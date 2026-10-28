"""Read archives without executing bundled code or requesting any dataset URL."""
import argparse
from collections import Counter,defaultdict
import csv
import hashlib
import io
import json
import re
from pathlib import Path
import unicodedata
import zipfile
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.neighbors import NearestNeighbors
from sklearn.model_selection import GroupShuffleSplit
from ml.training.validation import template
from backend.app.url_analysis import inspect_url

SEED=20261023
KNOWN_ARCHIVES={'0a639fd03aea6308c5b1c10c92aa23c2ce1505447a9137271865cd0badc9a59a','c2b5a89dd682ce4cd83d11c5f193d9f5f9d59a467f6e63d860fd38848396fb75'}
def sha(data):return hashlib.sha256(data).hexdigest()
def normalized(text):return ' '.join(unicodedata.normalize('NFKC',text).casefold().split())

def csv_members(path):
    with zipfile.ZipFile(path) as z:
        for name in z.namelist():
            if name.lower().endswith('.csv'):yield name,z.read(name)
            elif name.lower().endswith('.zip'):
                with zipfile.ZipFile(io.BytesIO(z.read(name))) as nested:
                    for child in nested.namelist():
                        if child.lower().endswith('.csv'):yield name+'!'+child,nested.read(child)

def split_rows(rows):
    groups=[r['group'] for r in rows]
    train,rest=next(GroupShuffleSplit(n_splits=1,test_size=.30,random_state=SEED).split(rows,groups=groups))
    validation,test=next(GroupShuffleSplit(n_splits=1,test_size=.50,random_state=SEED+1).split(rest,groups=[groups[i] for i in rest]))
    for indices,split in [(train,'train'),([rest[i] for i in validation],'validation'),([rest[i] for i in test],'test')]:
        for i in indices:rows[i]['split']=split
    assert len({r['group'] for r in rows if r['split']=='train'} & {r['group'] for r in rows if r['split']!='train'})==0
    return rows

def clean(rows,kind):
    buckets=defaultdict(list)
    for row in rows:buckets[normalized(row['text'])].append(row)
    conflicts=[key for key,values in buckets.items() if len({r['label'] for r in values})>1]
    kept=[values[0] for key,values in buckets.items() if key not in set(conflicts) and key]
    stats={'exact_duplicate_rows':sum(len(v)-1 for v in buckets.values()),'conflicting_text_groups':len(conflicts),'conflicting_record_ids':[r['id'] for key in conflicts for r in buckets[key]],'empty_text_rows':sum(not normalized(r['text']) for r in rows)}
    if kind=='text':
        # Connected components preserve transitive template families across splits.
        parent=list(range(len(kept)))
        def root(i):
            while parent[i]!=i:parent[i]=parent[parent[i]];i=parent[i]
            return i
        def union(i,j):parent[root(i)]=root(j)
        templates=[template(r['text']) or normalized(r['text']) for r in kept]
        matrix=TfidfVectorizer(analyzer='char',ngram_range=(3,5),min_df=1).fit_transform(templates)
        neighbors=NearestNeighbors(metric='cosine',algorithm='brute',radius=.15,n_jobs=2).fit(matrix)
        pairs=0
        for start in range(0,len(kept),128):
            for offset,adjacent in enumerate(neighbors.radius_neighbors(matrix[start:start+128],return_distance=False)):
                for j in adjacent:
                    if j>start+offset:union(start+offset,int(j));pairs+=1
        for i,r in enumerate(kept):r['group']='template-'+str(root(i))
        stats['near_template_pairs_cosine_at_least_085']=pairs
        stats['near_duplicate_policy']='Character 3-5 gram TF-IDF cosine >=0.85 connected components on entity/number-masked text, for grouping only; no classifier feature fitting uses this matrix.'
    else:
        invalid=0
        valid=[]
        for r in kept:
            d=inspect_url(r['text'])
            if not d['hostname']:invalid+=1;continue
            r['group']=d['registrable_domain'] or d['hostname'];valid.append(r)
        kept=valid;stats['invalid_url_rows']=invalid
        stats['near_duplicate_policy']='All shared registrable domains (private PSL included), or IP/unknown-suffix hostname, are one group; URL variants on that host cannot cross splits. Cross-domain lexical similarity is not assumed to establish a campaign.'
    split_rows(kept)
    stats['clean_rows']=len(kept);stats['groups']=len({r['group'] for r in kept})
    stats['splits']={s:dict(Counter(r['label'] for r in kept if r['split']==s)) for s in ['train','validation','test']}
    return kept,stats

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--input',type=Path,default=Path('ml/data'));parser.add_argument('--output',type=Path,default=Path('ml/prepared/v1'));args=parser.parse_args()
    if args.output.exists():raise SystemExit('Use a new output version; prepared data/manifests cannot be overwritten')
    inventory=[];datasets={}
    for path in sorted(args.input.rglob('*.zip')):
        if sha(path.read_bytes()) not in KNOWN_ARCHIVES:
            inventory.append({'path':str(path),'archive_sha256':sha(path.read_bytes()),'excluded':'Unreviewed archive provenance; schema alone cannot establish publisher or license'})
            continue
        for member,raw in csv_members(path):
            reader=csv.DictReader(io.StringIO(raw.decode('utf-8-sig')));data=list(reader);columns=reader.fieldnames
            if {'LABEL','TEXT'}<=set(columns):kind='text';label_key='LABEL';text_key='TEXT';mapping={'ham':'ham','spam':'spam','smishing':'smishing'};source='https://data.mendeley.com/datasets/f45bkkt8pr/1'
            elif {'URL','label','FILENAME'}<=set(columns):kind='url';label_key='label';text_key='URL';mapping={'1':'legitimate','0':'phishing'};source='https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset'
            else:inventory.append({'path':str(path),'member':member,'excluded':'Unrecognized schema/provenance; no inferred labels'});continue
            if kind in datasets:raise ValueError('Multiple datasets require explicit provenance/overlap review before combining')
            counts=Counter(r[label_key] for r in data)
            if any(label.casefold().strip() not in mapping for label in counts):raise ValueError('Unknown publisher label')
            item={'path':str(path),'archive_sha256':sha(path.read_bytes()),'member':member,'member_sha256':sha(raw),'rows':len(data),'columns':columns,'raw_labels':dict(counts),'missing_by_column':{c:sum(not (r.get(c) or '').strip() for r in data) for c in columns},'source':source,'license':'CC BY 4.0; publisher checked 2026-10-23','label_mapping':mapping,'language':'Predominantly English SMS with transliterated/mixed rows; not individually language-adjudicated' if kind=='text' else 'URL syntax only; no language claim','publisher_labels':'Not independently adjudicated; historical source benchmark, not representative production evaluation'}
            rows=[{'id':kind+'-'+str(i+2),'text':r[text_key].strip(),'label':mapping[r[label_key].casefold().strip()],'group':'','split':''} for i,r in enumerate(data)]
            kept,stats=clean(rows,kind);item['cleaning']=stats;inventory.append(item);datasets[kind]=kept
    args.output.mkdir(parents=True)
    url_values={normalized(r['text']) for r in datasets.get('url',[])}
    embedded=[(r['id'],u.rstrip('.,);')) for r in datasets.get('text',[]) for u in re.findall(r'https?://[^\s<>\"]+',r['text'],re.I)]
    overlap={'embedded_http_urls_in_sms':len(embedded),'exact_url_intersections':len({normalized(u) for _,u in embedded}&url_values),'sms_records_with_exact_url_overlap':[id for id,u in embedded if normalized(u) in url_values],'policy':'Datasets evaluated separately; no combined/multimodal accuracy. Before joint evaluation, union message/domain groups across both datasets.'}
    for kind,rows in datasets.items():
        target=args.output/(kind+'.csv')
        with target.open('w',encoding='utf-8',newline='') as f:
            writer=csv.DictWriter(f,fieldnames=['id','text','label','group','split']);writer.writeheader();writer.writerows(rows)
        test=[r for r in rows if r['split']=='test']
        (args.output/(kind+'-frozen.json')).write_text(json.dumps({'seed':SEED,'prepared_sha256':sha(target.read_bytes()),'test_sha256':sha(json.dumps(test,sort_keys=True).encode()),'test_ids':[r['id'] for r in test]},indent=2))
    (args.output/'inventory.json').write_text(json.dumps({'datasets':inventory,'cross_dataset_overlap':overlap,'screenshots':'No reviewed screenshot/transcription corpus located in supplied archives.'},indent=2))
    print(json.dumps({k:len(v) for k,v in datasets.items()}))

if __name__=='__main__':main()
