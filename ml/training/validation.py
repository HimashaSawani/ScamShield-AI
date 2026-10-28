"""Reject untraceable data and cross-split template/campaign leakage."""
import re
import unicodedata
from datetime import date
from difflib import SequenceMatcher

REQUIRED = {'record_id','text','language','label','scam_category','source','source_date','campaign_group','annotation_status','split','template_group','data_origin'}

def template(text):
    text=unicodedata.normalize('NFKC',text).casefold()
    text=re.sub(r'https?://\S+|[\w.+-]+@[\w.-]+', ' ENTITY ', text)
    text=re.sub(r'\d+', ' NUMBER ', text)
    return ' '.join(re.sub(r'[^\w\s]', ' ',text).split())

def validate(records, allow_synthetic_evaluation=False, *, labels=('Scam','Legitimate'), require_binary_splits=True):
    if not records:
        raise ValueError('Supply a consented annotated dataset; schema.csv is a header template only.')
    ids, exact, campaigns, templates, fingerprints, inverted = set(), {}, {}, {}, [], {}
    for index,row in enumerate(records):
        if REQUIRED-set(row) or any(not str(row.get(k,'')).strip() for k in REQUIRED):
            raise ValueError(f'Row {index+1}: missing required label, text or provenance fields')
        if row['record_id'] in ids:
            raise ValueError('Duplicate record ID')
        ids.add(row['record_id'])
        if row['split'] not in ['train','validation','test'] or row['label'] not in labels or row['annotation_status']!='adjudicated':
            raise ValueError('Every row must be adjudicated, use an accepted label, and have a frozen split')
        if row['data_origin'] not in ['observed','representative','synthetic']:
            raise ValueError('data_origin must identify observed, representative or synthetic data')
        if row['data_origin']=='synthetic' and row['split']!='train' and not allow_synthetic_evaluation:
            raise ValueError('Synthetic evaluation requires the explicit smoke-test flag; it cannot establish real-world accuracy')
        try:
            date.fromisoformat(row['source_date'])
        except ValueError:
            raise ValueError('source_date must be an ISO calendar date')
        normalized=' '.join(unicodedata.normalize('NFKC',row['text']).casefold().split())
        if normalized in exact:
            raise ValueError('Exact duplicate text: deduplicate before splitting')
        exact[normalized]=index
        fingerprint=template(row['text'])
        for mapping,key in [(campaigns,row['campaign_group']),(templates,row['template_group']),(templates,'fingerprint:'+fingerprint)]:
            if key in mapping and mapping[key]!=row['split']:
                raise ValueError('Cross-split campaign/template leakage detected')
            mapping[key]=row['split']
        grams={fingerprint[i:i+5] for i in range(max(1,len(fingerprint)-4))}
        candidates=set().union(*(inverted.get(g,set()) for g in grams))
        for other in candidates:
            if records[other]['split']!=row['split'] and SequenceMatcher(None,fingerprint,fingerprints[other],autojunk=False).ratio()>=0.90:
                raise ValueError('Cross-split near-duplicate template detected; group and re-split')
        for gram in grams:
            inverted.setdefault(gram,set()).add(index)
        fingerprints.append(fingerprint)
    for split in ['train','validation','test'] if require_binary_splits else []:
        if {r['label'] for r in records if r['split']==split}!={'Scam','Legitimate'}:
            raise ValueError('Each split must contain both labels')
    return {'records':len(records),'synthetic_evaluation':any(r['data_origin']=='synthetic' and r['split']!='train' for r in records),'near_duplicate_threshold':0.90}
