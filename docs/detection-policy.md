# Rules policy: rules-1.2.0

Rules 1.2 adds stored offline PSL URL details and nominal suspension/closure/deactivation pressure without changing weights. See [URL policy](url-analysis.md) and [evaluation guide](rules-evaluation.md).

This policy changes new scan assessments only. Stored historical results are not recalculated. These functional rules identify indicators, not verified sender identities, proven fraud, probabilities or measured detection accuracy.

## Credential requests and context

Matching normalizes Unicode compatibility characters and case, collapses whitespace, and recognizes common hyphen/apostrophe forms. Each normalized character maps back to original input positions so evidence spans and quotes retain original punctuation, whitespace and Unicode. Dashboard/native highlighting uses Unicode code points to match backend offsets.

English disclosure actions include reply, respond, send, share, tell, provide, give, disclose, forward, text, message and contextual ask-for/ask-to. A credential must occur within the same sentence/contrast clause, within 160 normalized characters and at most 20 intervening tokens. Credentials include password, OTP, one-time password/passcode/code, verification code, login code, security/authentication/2FA code and PIN. Coordinated credentials are retained in the quote. Bare credential words and ordinary enter/verify/confirm instructions are not sufficient for this disclosure rule.

Negation is checked near each action within its clause. It is not a message-wide exclusion. Sentence/semicolon and contrast boundaries reset context. Thus “Never share your OTP” does not suppress a later “Reply with your OTP.” Quoted requests with explicit educational/scam-example framing and scoped reported warnings are excluded as direct sender requests. Explicit beware/conditional warnings exclude their described credential request, not a later imperative outside that span. Remaining uncertainty is not resolved as safety.

This is bounded lexical context, not general language understanding. Pronoun-only requests, sarcasm, complex nested quotations, unusual punctuation and untested scripts can still fail. Local-language patterns remain experimental. Sender identity, conversation history, live URL reputation and trained-model inference are unavailable.

## Weights and mapping

| Indicator | Weight |
|---|---:|
| Explicit credential disclosure request | 45 |
| Urgency/account-blocking pressure | 20 |
| Payment/advance fee request | 25 |
| Prize/guaranteed return language | 25 |
| URL user-information section | 30 |
| IP-address hostname | 20 |
| Many subdomain levels | 15 |
| Internationalized/punycode hostname | 15 |
| Encoded URL characters | 10 |
| Unencrypted HTTP | 10 |
| Brand plus account-action words in hostname | 20 |

The score is the capped sum of **distinct indicator types**, maximum 100. Repeated matches, repeated URLs with the same structural signal, and overlapping evidence of the same type do not add weight. Evidence may display multiple request spans; “+45” describes that signal's weight, not an additive charge for each row. Different indicator types add even if their spans overlap; they are heuristic signals, not independent calibrated events.

- **High:** score ≥60. Credential disclosure (45) plus urgency/account-blocking pressure (20) yields 65, strong credential-theft indicators. Urgency's weight was not increased.
- **Medium:** score 25–59. An isolated explicit disclosure request scores 45; the presence of a credential word alone scores nothing.
- **Inconclusive:** score <25, including no matches. Limited negative findings cannot establish legitimacy or safety.
- **Low:** not assigned to new scans by this rules version. There is no implemented verified-safe evidence channel. Historical Low results retain their stored label, version, score and explanation.

Results disclose completed/unavailable components and label scores as indicator scores, never probabilities. High/Medium guidance says to keep credentials private, verify through independently obtained official contacts and avoid unverified payment/links. Inconclusive guidance emphasizes missing checks and independent verification, not safety.

## Reported examples

Input A scores **High, 65**: `Reply with your password and OTP` (45) and `account will be blocked` (20). Input B scores **Inconclusive, 0**: OTP delivery plus protective warnings does not match a disclosure request. Functional paraphrase/warning/quote tests are regression evidence only, not detection-accuracy evaluation.
