import copy
import csv
import json
import pytest
from backend.tests.test_dataset import rows
from ml.evaluation.evaluate_rules import load,freeze,verify_frozen,evaluate,summarize,compare_models

def fixtures():
    data=rows()
    for r in data:r.update(source_license='synthetic test fixture, not public data',source_record_id=r['record_id'])
    data.append(dict(data[-1],record_id='uncertain-fixture',text='An unexplained request with missing sender context',label='Uncertain',annotation_reason='Insufficient context in this synthetic fixture',campaign_group='unknown-campaign',template_group='unknown-template',source_record_id='uncertain-fixture'))
    return data

def write_dataset(tmp_path,data):
    path=tmp_path/'dataset.csv'
    keys=sorted(set().union(*(r.keys() for r in data)))
    with path.open('w',encoding='utf-8',newline='') as file:
        writer=csv.DictWriter(file,fieldnames=keys);writer.writeheader();writer.writerows(data)
    return path

def test_abstention_metrics_do_not_hide_missed_scams_or_uncertain_labels():
    inputs=[('tp','Scam','Scam'),('miss','Scam','Inconclusive'),('fp','Legitimate','Scam'),('noalert','Legitimate','Inconclusive'),('review','Uncertain','Scam')]
    report=summarize([{'record_id':id,'label':label,'prediction':prediction} for id,label,prediction in inputs])
    assert report['confusion_matrix']['values']==[[1,0,1],[1,0,1],[1,0,0]]
    assert report['flag_detection_metrics']['precision']==.5
    assert report['flag_detection_metrics']['recall']==.5
    assert report['flag_detection_metrics']['f1']==.5
    assert report['flag_detection_metrics']['known_label_count']==4
    assert report['inconclusive_rate']==.4 and report['decision_coverage']==.6
    assert report['false_positive_record_ids_first_100']==['fp']
    assert report['missed_scam_record_ids_first_100']==['miss']
    assert report['false_negatives_explicit_legitimate']==0

def test_zero_decisions_or_single_label_coverage_is_explicit():
    assert summarize([])['flag_detection_metrics']['precision'] is None
    report=summarize([{'record_id':'positive','label':'Scam','prediction':'Inconclusive'}])
    assert report['inconclusive_rate']==1 and report['decision_coverage']==0
    assert report['flag_detection_metrics']['precision'] is None
    assert report['flag_detection_metrics']['recall']==0
    assert 'insufficient evidence' in report['conclusion']

def test_freeze_preserves_test_records_and_refuses_overwrite_or_mutation(tmp_path):
    data=fixtures();path=tmp_path/'frozen.json'
    manifest=freeze(data,path)
    assert verify_frozen(data,path)==manifest
    with pytest.raises(FileExistsError):freeze(data,path)
    data[-1]['text']+=' changed after evaluation'
    with pytest.raises(ValueError,match='Frozen test set changed'):verify_frozen(data,path)

def test_loading_requires_reviewed_traceable_labels_and_synthetic_flag(tmp_path):
    data=fixtures();path=write_dataset(tmp_path,data)
    with pytest.raises(ValueError,match='Synthetic evaluation'):load(path)
    loaded,_=load(path,True);assert loaded[-1]['label']=='Uncertain'
    data[0]['source_license']='';path=write_dataset(tmp_path,data)
    with pytest.raises(ValueError,match='source_license'):load(path,True)
    data=fixtures();data[0]['annotation_status']='publisher-label-only';path=write_dataset(tmp_path,data)
    with pytest.raises(ValueError,match='adjudicated'):load(path,True)

def test_evaluator_retains_leakage_checks(tmp_path):
    data=fixtures();data[4]['text']=data[0]['text']+' now'
    with pytest.raises(ValueError,match='near-duplicate'):load(write_dataset(tmp_path,data),True)

def test_frozen_rules_output_contains_no_raw_messages_and_reports_language_counts(tmp_path):
    data=fixtures();manifest=freeze(data,tmp_path/'manifest.json');report=evaluate(data,manifest)
    assert report['rules']['overall']['count']==3
    assert report['rules']['languages']['Tamil']['count']==0
    assert 'SYNTHETIC' in report['evaluation_kind']
    assert report['latency_ms']['samples']==3
    assert all(row['text'] not in json.dumps(report) for row in data)

def test_comparison_fits_and_tunes_without_test_labels(tmp_path):
    data=fixtures();test=[r for r in data if r['split']=='test']
    rules=[dict(r,prediction='Inconclusive') for r in test]
    first=compare_models(data,test,rules)
    changed=copy.deepcopy(test)
    for r in changed:r['label']='Legitimate' if r['label']=='Scam' else 'Scam'
    second=compare_models(data,changed,rules)
    assert first['threshold']==second['threshold']
    assert first['train_count']==2 and first['validation_count']==2
    assert first['agreement_gate']['overall']['decision_coverage']==0
    assert 'not reported' in first['probabilities']
