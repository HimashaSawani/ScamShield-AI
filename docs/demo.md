# Demo and handover walkthrough

1. Start API and worker; register/verify a user. Show the empty dashboard.
2. Scan `Your bank statement is available in the official app. We never ask you to share security codes.` Show the Low result and missing identity/reputation checks; explain that Low is not guaranteed safe.
3. Scan `Urgent! Send your OTP immediately to claim your prize https://bank-login.example.com`. Inspect exact highlighted spans, rules score and next steps.
4. Check history, reopen the scan, submit a report with a reason.
5. Create an admin using the CLI, log in using an authenticator code, open Review queue, and record a decision. Return to the user account to show the separate reviewed outcome.
6. Submit another report containing the same domain, inspect the graph’s relationship evidence, and create a reviewed campaign. Explain that this does not establish common attacker identity.
7. Upload a PNG/JPEG screenshot. If Tesseract is present, review and correct extraction. If unavailable, show the Inconclusive fallback and enter text manually. Blurred images can also yield poor/empty extraction; always confirm text.
8. Inspect an unreachable URL. Static structure checks still run; coverage explicitly says live checks are unavailable. The scanner does not fetch the URL.
9. Register a second user and demonstrate API ownership rejection using the automated test suite. Demonstrate account/scan deletion and revoked sessions.
10. Show the model page and explain that language patterns are experimental, metrics are unavailable and a representative dataset is required.

Use the walkthrough to record your own demo video and slides after real-device validation. No video, presentation, production URL or signed Android build is included in this handover.
# Current local v1 demo

Open http://localhost:8015 and click Try demo. Use sample content only. Submit the credential/urgency example from the release report: show separate High and Completed badges, +45/+20 original-span evidence and rules version. Submit an ordinary OTP delivery with protective warnings: show Inconclusive and no request indicator. Submit `https://bank.invalid@account-check.invalid/login`: show the actual hostname, user information before @, unavailable registrable domain, and explicit missing live checks; do not click/visit destinations. Submit a named-domain sample URL and show its separate `scamshield-url-v1` prediction without treating it as verified safety. Upload a synthetic screenshot, correct the text and confirm it; explain OCR failure/manual fallback if Tesseract is absent. Open saved history to show versions remain unchanged. Explain explicit analyst-sharing consent and separate analyst decisions. Show [source-benchmark reports](model-workflow-v1.md); text model is disabled and no production/multilingual accuracy claim is made. Staff review uses separately enrolled MFA accounts, never demo privileges. Native device and external deployment remain unverified.

