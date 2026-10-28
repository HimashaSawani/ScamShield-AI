import io
import zipfile
from ml.prepare import clean,csv_members

def test_nested_archive_reader_never_extracts_or_executes(tmp_path):
    nested=io.BytesIO()
    with zipfile.ZipFile(nested,'w') as z:z.writestr('Dataset.csv','LABEL,TEXT\nham,hello\n')
    path=tmp_path/'raw.zip'
    with zipfile.ZipFile(path,'w') as z:
        z.writestr('nested.zip',nested.getvalue());z.writestr('danger.py','raise RuntimeError("must never execute")');z.writestr('../outside.txt','ignored')
    before=path.read_bytes();members=list(csv_members(path))
    assert members==[('nested.zip!Dataset.csv',b'LABEL,TEXT\nham,hello\n')]
    assert path.read_bytes()==before and not (tmp_path/'danger.py').exists()

def test_conflicting_labels_excluded_and_template_groups_do_not_leak():
    texts=[('ham','same conflict'),('smishing','same conflict'),('spam','Sale offer number 123 expires today'),('spam','Sale offer number 456 expires today'),('ham','We meet for lunch tomorrow'),('smishing','Disclose your verification code'),('ham','I finished reading the novel'),('spam','A furniture discount this month')]
    rows=[{'id':str(i),'text':text,'label':label,'split':'','group':''} for i,(label,text) in enumerate(texts)]
    kept,stats=clean(rows,'text')
    assert stats['conflicting_text_groups']==1 and all(r['text']!='same conflict' for r in kept)
    sales=[r for r in kept if 'Sale offer' in r['text']]
    assert sales[0]['group']==sales[1]['group'] and sales[0]['split']==sales[1]['split']
    assert {r['label'] for r in kept}=={'ham','spam','smishing'}

def test_url_domains_share_split_without_network(monkeypatch):
    monkeypatch.setattr('requests.sessions.Session.send',lambda *_a,**_k:(_ for _ in ()).throw(AssertionError('network forbidden')))
    urls=['https://a.example.co.uk/a','http://b.example.co.uk/b','https://alice.github.io/','https://bob.github.io/','https://other.org/','https://third.com/','https://fourth.net/']
    rows=[{'id':str(i),'text':u,'label':'phishing' if i%2 else 'legitimate','group':'','split':''} for i,u in enumerate(urls)]
    kept,_=clean(rows,'url')
    assert kept[0]['group']==kept[1]['group']=='example.co.uk'
    assert kept[0]['split']==kept[1]['split']
    assert kept[2]['group']!=kept[3]['group']
