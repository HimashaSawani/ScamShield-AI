"""Deterministic evidence; score is an indicator weight, never a probability."""
import ipaddress
import re
import unicodedata
from urllib.parse import urlsplit
from .url_analysis import inspect_url

VERSION = 'rules-1.2.0'
RULES = [
    ('urgency', r'\b(urgent|immediately|act now|within \d+ hours?|account.{0,12}(blocked|suspended|suspension|closure|deactivation))\b|වහාම|දැන්ම|உடனே|ikmanin', 20, 'Pressure to act quickly or prevent account restrictions'),
    ('payment', r'\b(pay|send|transfer|deposit).{0,30}\b(fee|money|payment|advance|cash)\b|මුදල්.{0,20}එවන්න|பணம்.{0,20}அனுப்பு|salli.{0,20}ewanna', 25, 'Payment or advance fee request'),
    ('reward', r'\b(won|winner|lottery|claim.{0,15}(prize|reward)|guaranteed.{0,15}(return|profit))\b|දිනුම්|ත්‍යාග|பரிசு|dinum', 25, 'Prize or guaranteed return language'),
]
URL_RE = re.compile(r'https?://[^\s<>"\u200b]+', re.I)

ACTION = re.compile(r'\b(reply|respond|send|share|tell|provide|give|disclose|forward|text|message|ask)\b')
CREDENTIAL = re.compile(r'\b(?:otp|one[ -]*time\s+(?:password|passcode|code)|verification\s+code|login\s+code|security\s+code|authentication\s+code|2fa\s+code|password|passcode|pin)\b')
NEGATION = re.compile(r"\b(?:never|not|don't|do not|mustn't|shouldn't|won't|cannot|can't|avoid)\b(?:\W+\w+){0,4}\W*$")
EDUCATION = re.compile(r'\b(?:example|educational|training|awareness|scammers?|phishing|fraudsters?|beware)\b')
REPORTED_WARNING = re.compile(r'\b(?:scammers?|fraudsters?)\s+(?:(?:may|might|often|sometimes|will|can)\s+)*(?:ask|say|request|tell|send)\b')

def matching_text(text):
    """Normalize for matching while retaining an exact original-character map."""
    chars, offsets = [], []
    for index, char in enumerate(text):
        expanded = unicodedata.normalize('NFKC', char).casefold()
        for value in expanded:
            value = {'’':"'", '‐':'-', '‑':'-', '–':'-', '—':'-'}.get(value,value)
            if value.isspace():
                if chars and chars[-1]==' ':
                    offsets[-1]=(offsets[-1][0],index+1)
                    continue
                value=' '
            chars.append(value);offsets.append((index,index+1))
    return ''.join(chars), offsets

def context_ranges(text):
    """Educational exclusions are scoped to quotes/reported clauses, never global."""
    ranges=[]
    for quote in re.finditer(r'"[^"\n]+"|“[^”\n]+”|(?<!\w)\'[^\'\n]+\'(?!\w)|‘[^’\n]+’',text):
        prefix=text[max(0,quote.start()-140):quote.start()]
        # An introductory label must immediately precede the quotation.
        prefix=re.split(r'[.!?;]',prefix)[-1]
        suffix=text[quote.end():quote.end()+90]
        if EDUCATION.search(prefix) or re.match(r'\s*(?:is|was)\s+(?:an?\s+)?(?:scam|phishing|educational|example)',suffix):
            ranges.append((quote.start(),quote.end()))
    for clause in re.finditer(r'[^.!?;]+',text):
        content=clause.group()
        protective=re.search(r"\b(?:beware of|watch out for|do not trust|don't trust)\b.{0,100}\b(?:messages?|requests?|anyone|people)\b",content)
        conditional=re.search(r'\bif\b.{0,50}\b(?:message|someone|agent)\b',content) if re.search(r'\b(?:is|may be)\s+(?:a\s+)?(?:scam|phishing)\b',content) else None
        marker=protective or conditional
        if marker:
            tail=content[marker.end():]
            credential=CREDENTIAL.search(tail)
            contrast=re.search(r'\b(?:but|however|instead)\b|,\s*(?:please\s+)?(?:reply|respond|send|share|tell|provide|give|disclose|forward|text|message)\b',tail)
            if credential and (not contrast or credential.end()<contrast.start()):
                end=marker.end()+credential.end()
                coordinated=re.match(r'\s*(?:and|or|&|/)\s*(?:your\s+)?'+CREDENTIAL.pattern,content[end:])
                if coordinated:end+=coordinated.end()
                ranges.append((clause.start()+marker.start(),clause.start()+end))
        for warning in REPORTED_WARNING.finditer(clause.group()):
            # Stop reported context at a contrasting directive, even in one sentence.
            tail=clause.group()[warning.start():]
            end=re.search(r'\b(?:but|however|instead|then)\b|,\s*(?:please\s+)?(?:reply|respond|send|share|tell|provide|give|disclose|forward|text|message)\b',tail)
            limit=end.start() if end else len(tail)
            credential=CREDENTIAL.search(tail[:limit])
            if credential:
                limit=credential.end()
                coordinated=re.match(r'\s*(?:and|or|&|/)\s*(?:your\s+)?'+CREDENTIAL.pattern,tail[limit:])
                if coordinated:limit+=coordinated.end()
            ranges.append((clause.start()+warning.start(),clause.start()+warning.start()+limit))
    return ranges

def contextual(start, end, ranges):
    return any(start>=left and end<=right for left,right in ranges)

def credential_requests(text, excluded):
    requests=[]
    for clause in re.finditer(r'[^.!?;]+',text):
        # Contrast clauses form a new context, so warnings cannot immunize a request.
        for part in re.finditer(r'.+?(?=\b(?:but|however|instead)\b|$)',clause.group()):
            segment=part.group();base=clause.start()+part.start()
            previous_end=0;previous_protected=False
            for action in ACTION.finditer(segment):
                prefix=segment[previous_end:action.start()]
                protected=bool(NEGATION.search(prefix))
                if previous_protected and re.fullmatch(r'\s+(?:(?:anyone|you|them|for|to)\s+)+',prefix):
                    protected=True
                previous_end=action.end();previous_protected=protected
                if protected:
                    continue
                tail=segment[action.end():action.end()+160]
                credential=CREDENTIAL.search(tail)
                if not credential or len(tail[:credential.start()].split())>20:
                    continue
                if action.group()=='ask' and not re.match(r'\s+(?:(?:you|me|us|anyone)\s+)?(?:for|to)\b',tail):
                    continue
                end=action.end()+credential.end()
                # Keep coordinated credentials in the evidence without charging twice.
                coordinated=re.match(r'\s*(?:and|or|&|/)\s*(?:your\s+)?'+CREDENTIAL.pattern,segment[end:])
                if coordinated:end+=coordinated.end()
                start=base+action.start();finish=base+end
                if not contextual(start,finish,excluded):
                    requests.append((start,finish))
    # Preserve existing experimental local-language action patterns, not bare keywords.
    local=re.compile(r'\botp.{0,20}\b(?:ewanna|denna)\b|(?:මුරපදය|otp).{0,20}(?:එවන්න|දෙන්න)|ரகசிய.{0,8}எண்.{0,20}அனுப்பு')
    for match in local.finditer(text):
        if not contextual(match.start(),match.end(),excluded):requests.append(match.span())
    return requests

def url_observations(url):
    details=inspect_url(url)
    return details['hostname'] or '', [(o['code'],o['description'],o['weight']) for o in details['observations']]

def analyze(text, kind='text'):
    evidence, entities, url_details = [], [], []
    normalized, offsets = matching_text(text)
    excluded=context_ranges(normalized)
    def add(code,description,weight,start,end):
        original_start,original_end=offsets[start][0],offsets[end-1][1]
        evidence.append(dict(code=code,description=description,weight=weight,start=original_start,end=original_end,quote=text[original_start:original_end]))
    for start,end in credential_requests(normalized,excluded):
        add('credentials','Request to disclose a password or verification code',45,start,end)
    for code, pattern, weight, message in RULES:
        for match in re.finditer(pattern, normalized, re.I):
            if not contextual(match.start(),match.end(),excluded):
                add(code,message,weight,match.start(),match.end())
                break
    urls = list(URL_RE.finditer(text))
    if kind == 'url' and not urls:
        raise ValueError('Enter a complete HTTP or HTTPS URL')
    for match in urls:
        url = match.group().rstrip('.,);')
        details=inspect_url(url)
        url_details.append(details)
        host=details['hostname']
        if kind == 'url' and not host:
            raise ValueError('Invalid URL')
        if host:
            entities.append(dict(type='domain', value=host))
        for observation in details['observations']:
            evidence.append(dict(**observation,start=match.start(),end=match.start()+len(url),quote=url))
    for phone in re.findall(r'(?<!\w)\+?\d[\d -]{7,14}\d(?!\w)', text):
        entities.append(dict(type='phone', value=re.sub(r'\D', '', phone)))
    score = min(100, sum({e['code']: e['weight'] for e in evidence}.values()))
    assessment = 'High' if score >= 60 else 'Medium' if score >= 25 else 'Inconclusive'
    missing = ['Sender identity verification', 'Live URL reputation and destination checks', 'Trained model inference']
    return dict(assessment=assessment, score=score, score_type='Rules indicator score; not a probability', version=VERSION,
                evidence=evidence, entities=entities, url_details=url_details, coverage={'completed': ['Text rules']+sorted({check for detail in url_details for check in detail['checks']['completed']}),'failed':sorted({check for detail in url_details for check in detail['checks']['failed']}), 'unavailable': missing+sorted({check for detail in url_details for check in detail['checks']['unavailable'] if check.startswith('Registrable domain:')})},
                explanation=('Strong credential-theft indicators: a credential disclosure request combined with pressure to act. Sender identity and fraud are not confirmed.' if {'credentials','urgency'}<=set(e['code'] for e in evidence) else ('; '.join(dict.fromkeys(e['description'] for e in evidence))+'. These observations do not verify sender identity or establish fraud.' if evidence else 'No configured indicators were established. Limited analysis cannot verify legitimacy or safety.')),
                context_notes=['Quoted or reported educational context was excluded from request indicators; intent remains unverified.'] if excluded else [],
                next_actions=['Do not share passwords or one-time codes.', 'Verify the request using an independently obtained official contact.', 'Avoid payment or links until the sender is verified.'] if score >= 25 else ['The result is inconclusive; sender identity and live reputation were not verified.', 'Verify unexpected requests independently before acting.', 'Keep passwords and one-time codes private.'],
                normalized=normalized)
