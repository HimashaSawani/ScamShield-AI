"""Functional examples only; these are not accuracy or language benchmarks."""
import pytest
from backend.app.detection import analyze, VERSION
from scripts.verify_detection_live import A, B

def codes(result):return {e['code'] for e in result['evidence']}

def test_reported_failure_and_protective_delivery():
    result=analyze(A)
    assert (result['assessment'],result['score'],result['version'])==('High',65,VERSION)
    assert {'credentials','urgency'}<=codes(result)
    assert 'not confirmed' in result['explanation']
    result=analyze(B)
    assert (result['assessment'],result['score'])==('Inconclusive',0)
    assert 'credentials' not in codes(result)
    assert result['coverage']['unavailable']

@pytest.mark.parametrize('text',[
    'Reply with your password and OTP.',
    'Send me your verification code.',
    'Tell our agent your one-time password.',
    'Share the login code to prevent account suspension.',
    'Please provide our support representative with your security code.',
    'Respond with the authentication code we just sent.',
    'Text your PIN to our representative.',
    'REPLY, with YOUR PASSWORD & OTP!',
    'Send\nme\tyour   verification\ncode.',
    '🙂 ＲＥＰＬＹ with your one‑time password.',
])
def test_disclosure_paraphrases_and_exact_original_offsets(text):
    result=analyze(text)
    assert 'credentials' in codes(result)
    expected=65 if 'account suspension' in text else 45
    assert result['score']==expected and result['assessment']==('High' if expected==65 else 'Medium')
    for item in result['evidence']:
        assert text[item['start']:item['end']]==item['quote']

@pytest.mark.parametrize('text',[
    'Never share your OTP.',
    'Our staff will never ask for your password.',
    'Please do not send your password to anyone.',
    "Don't reply with your verification code.",
    'You should not tell anyone your PIN.',
    'Your OTP is 123456. It expires in ten minutes.',
    'Your verification code is 123456.',
    'Enter the code in the app you opened to finish signing in.',
    'Enter your password in the official app you opened.',
    'To reset your password, open Settings and choose Reset password.',
    'Use the password-reset code in the app you opened.',
])
def test_protective_and_ordinary_signin_context(text):
    result=analyze(text)
    assert 'credentials' not in codes(result)
    assert result['assessment']=='Inconclusive'

@pytest.mark.parametrize('text',[
    'Never share your OTP with strangers. I am your bank agent. Reply with your OTP now.',
    'Never share your OTP with strangers; send me your password instead.',
    'Never share your OTP with strangers, but reply with your OTP to me.',
    'Our staff never ask for your password. However, send your OTP immediately.',
    'Scammers may ask you to send a password, but reply with your OTP to me.',
    'Scammers may ask for your password, reply with your OTP immediately.',
    'Beware of messages from strangers, reply with your OTP immediately.',
])
def test_warning_does_not_immunize_later_requests(text):
    assert 'credentials' in codes(analyze(text))

@pytest.mark.parametrize('text',[
    'Example of a scam: "Reply with your password and OTP immediately." Never follow that request.',
    'Scammers say “send me your verification code”. Never do this.',
    '"Tell our agent your one-time password" is a phishing example.',
    'A scammer may ask you to send your password. Do not comply.',
    'Beware of messages asking you to share your OTP.',
    'Watch out for messages that ask you to send your password and OTP.',
    'If a message says send your password, it is a scam.',
])
def test_educational_quotes_and_reported_warnings(text):
    result=analyze(text)
    assert 'credentials' not in codes(result)
    assert result['assessment']=='Inconclusive'
    assert result['context_notes']

def test_educational_quote_does_not_hide_directive_outside_quote():
    result=analyze('Scam example: "Never share an OTP." Reply with your password immediately.')
    assert {'credentials','urgency'}<=codes(result)
    assert result['assessment']=='High'
    result=analyze('Beware of messages asking you to share your OTP, but reply with your password immediately.')
    assert {'credentials','urgency'}<=codes(result)

def test_repetition_overlap_and_limited_coverage_policy():
    result=analyze('Reply with your OTP. Send me your password. Immediately!')
    assert result['score']==65
    assert len([e for e in result['evidence'] if e['code']=='credentials'])==2
    assert analyze('Your bank statement is available in the app.')['assessment']=='Inconclusive'
    assert analyze('This message is urgent.')['assessment']=='Inconclusive'
    assert analyze('https://fixture.example.test','url')['assessment']=='Inconclusive'
    assert 'not a probability' in result['score_type']

def test_disclosure_to_prevent_suspension_has_both_indicators():
    result=analyze('Reply with your password to prevent account suspension.')
    assert result['assessment']=='High' and result['score']==65
    assert {'credentials','urgency'}<=codes(result)
