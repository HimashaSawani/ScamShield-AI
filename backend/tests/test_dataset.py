import pytest
from ml.training.validation import validate

def rows():
    messages=['Request urgent verification of your private password','The garden club meets on Tuesday for refreshments','Investment scheme offers a guaranteed enormous fortune','Your appointment with the dentist is confirmed tomorrow','Transfer an advance payment to unlock this lottery award','The library has extended opening hours during exams']
    return [dict(record_id=str(i),text=t,language='English',label='Scam' if i%2==0 else 'Legitimate',scam_category='fixture',source='generated-unit-test',source_date='2026-10-23',campaign_group='campaign-'+str(i),template_group='template-'+str(i),annotation_status='adjudicated',split=['train','validation','test'][i//2],data_origin='synthetic') for i,t in enumerate(messages)]

def test_synthetic_evaluation_is_explicit():
    with pytest.raises(ValueError,match='Synthetic evaluation'):
        validate(rows())
    assert validate(rows(),True)['synthetic_evaluation']

@pytest.mark.parametrize('field',['label','source','source_date','text','data_origin'])
def test_missing_fields_rejected(field):
    data=rows();data[0][field]=''
    with pytest.raises(ValueError,match='missing'):
        validate(data,True)

def test_campaign_and_near_duplicate_leakage():
    data=rows();data[2]['campaign_group']=data[0]['campaign_group']
    with pytest.raises(ValueError,match='leakage'):
        validate(data,True)
    data=rows();data[2]['text']=data[0]['text']+' now'
    with pytest.raises(ValueError,match='near-duplicate'):
        validate(data,True)
