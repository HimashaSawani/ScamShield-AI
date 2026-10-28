# Static URL analysis

Rules 1.2.0 stores URL details for new assessments. Dashboard/mobile use plain text for suspicious URLs and separate assessment, processing, evidence title/span and weight. Historical assessments are not rewritten.

`https://bank.invalid@account-check.invalid/login` has hostname `account-check.invalid`; `bank.invalid` is user information before @. This can mislead but does not prove fraud. Reserved .invalid has no recognized public suffix, so no registrable domain is guessed. For `login.bank.example.co.uk`, the registrable domain is `example.co.uk`; preceding labels do not control it.

The parser uses IDNA and [tldextract](https://github.com/john-kurkowski/tldextract) 5.3.1 with its bundled [Public Suffix List](https://publicsuffix.org/list/), including private suffixes. Runtime suffix URLs/cache are disabled. Snapshot SHA256: `b69315c085d53972724b8f2df111ffc329b0c84fe0a47d62c8c91655cc774a38`. No DNS or destination fetch occurs. IP hosts have no registrable domain; invalid syntax records failed checks. Missing live/reputation checks are unavailable, never safe. HTTPS is not proof of safety.

Maintain the bounded snapshot through reviewed dependency/PSL updates: pin the version, record checksum, rerun URL tests and queued/browser checks. Unknown suffixes remain unavailable. No live registration/ownership claim is made. User-information passwords in parsed display are redacted; original sample text remains private history.

Static rules cannot establish sender identity, destination content, site compromise or homograph intent. Clause-context rules remain limited for indirect requests, unusual grammar, quotations and multi-message conversations. Educational/protective markers are heuristics, not semantic understanding. Indicator scores are not probabilities: High >=60, Medium >=25, otherwise Inconclusive; credential request 45, urgency/account restriction pressure 20, distinct weights summed and capped at 100. Urgency weight was not increased to fix the credential defect.
