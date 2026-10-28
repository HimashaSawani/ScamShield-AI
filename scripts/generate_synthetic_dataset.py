"""Generate comprehensive, safe synthetic dataset for ScamShield AI verification."""
import json
from pathlib import Path

def generate_dataset():
    suspicious_urls = []
    
    # 1. Brand Impersonation on HTTP & HTTPS with various indicators (25)
    brands = ['paypal', 'apple', 'microsoft', 'chase-bank', 'netflix', 'amazon', 'google', 'hsbc-bank', 'wellsfargo', 'bankofceylon', 'dialog-telecom', 'peoplesbank', 'commercialbank', 'ebay', 'meta']
    actions = ['login', 'verify', 'security', 'secure', 'account-update', 'auth', 'signin', 'confirm-identity', 'session-renew', 'alert']
    for i in range(25):
        b = brands[i % len(brands)]
        act = actions[i % len(actions)]
        proto = "http" if i % 2 == 0 else "https"
        suspicious_urls.append({
            "id": f"SURL_{len(suspicious_urls)+1:03d}",
            "category": "suspicious_url",
            "subcategory": "brand_impersonation",
            "url": f"{proto}://{b}-{act}.example.com/login",
            "expected_label": "suspicious",
            "expected_assessment": ["High", "Medium"],
            "rationale": f"Brand impersonation with action keyword in host: {b}-{act}"
        })

    # 2. Login verification scams with unencrypted HTTP / brand keywords (20)
    for i in range(20):
        suspicious_urls.append({
            "id": f"SURL_{len(suspicious_urls)+1:03d}",
            "category": "suspicious_url",
            "subcategory": "login_verification",
            "url": f"http://bank-login-verify-{i+1}.example.com/portal/signin",
            "expected_label": "suspicious",
            "expected_assessment": ["High", "Medium"],
            "rationale": "Bank brand with login/verify action terms in hostname over HTTP"
        })

    # 3. Account suspension warnings (15)
    for i in range(15):
        suspicious_urls.append({
            "id": f"SURL_{len(suspicious_urls)+1:03d}",
            "category": "suspicious_url",
            "subcategory": "account_suspension",
            "url": f"http://paypal-unblock-secure-{i+1}.example.org/account/restore",
            "expected_label": "suspicious",
            "expected_assessment": ["High", "Medium"],
            "rationale": "Account unblock/security keywords targeting financial brand over HTTP"
        })

    # 4. Prize and giveaway scams (10)
    for i in range(10):
        suspicious_urls.append({
            "id": f"SURL_{len(suspicious_urls)+1:03d}",
            "category": "suspicious_url",
            "subcategory": "prize_giveaway",
            "url": f"http://apple-reward-claim-{i+1}.sample.net/prize/redeem",
            "expected_label": "suspicious",
            "expected_assessment": ["High", "Medium"],
            "rationale": "Prize reward claim with brand keyword over HTTP"
        })

    # 5. Delivery notification scams (10)
    for i in range(10):
        suspicious_urls.append({
            "id": f"SURL_{len(suspicious_urls)+1:03d}",
            "category": "suspicious_url",
            "subcategory": "delivery_fee",
            "url": f"http://express-postal-delivery-{i+1}.example.com/fee/release",
            "expected_label": "suspicious",
            "expected_assessment": ["High", "Medium"],
            "rationale": "Unencrypted HTTP delivery fee release link"
        })

    # 6. Payment verification scams (10)
    for i in range(10):
        suspicious_urls.append({
            "id": f"SURL_{len(suspicious_urls)+1:03d}",
            "category": "suspicious_url",
            "subcategory": "payment_verification",
            "url": f"http://bank-secure-payment-{i+1}.example.com/verify-transfer",
            "expected_label": "suspicious",
            "expected_assessment": ["High", "Medium"],
            "rationale": "Bank security payment verification pattern over HTTP"
        })

    # 7. Suspicious Subdomain Structures (dot count >= 4) (10)
    for i in range(10):
        suspicious_urls.append({
            "id": f"SURL_{len(suspicious_urls)+1:03d}",
            "category": "suspicious_url",
            "subcategory": "excessive_subdomains",
            "url": f"https://login.auth.security.verify.portal-{i+1}.example.com/session",
            "expected_label": "suspicious",
            "expected_assessment": ["High", "Medium"],
            "rationale": "Excessive subdomain levels (>= 4 dots) hiding true host"
        })

    # 8. Userinfo @ Embedded in URL (5)
    for i in range(5):
        suspicious_urls.append({
            "id": f"SURL_{len(suspicious_urls)+1:03d}",
            "category": "suspicious_url",
            "subcategory": "userinfo_embedded",
            "url": f"https://support-bank.test@phishing-target-{i+1}.example.com/login",
            "expected_label": "suspicious",
            "expected_assessment": ["High", "Medium"],
            "rationale": "User information preceding @ symbol intended to mislead destination"
        })

    # 9. Raw IP Host URLs (5)
    for i in range(5):
        suspicious_urls.append({
            "id": f"SURL_{len(suspicious_urls)+1:03d}",
            "category": "suspicious_url",
            "subcategory": "ip_host",
            "url": f"http://192.168.1.{10+i}/bank/login",
            "expected_label": "suspicious",
            "expected_assessment": ["High", "Medium"],
            "rationale": "IP address host instead of named domain combined with unencrypted HTTP"
        })

    # 10. Obfuscated Percent-Encoding with Brand Host (5)
    for i in range(5):
        suspicious_urls.append({
            "id": f"SURL_{len(suspicious_urls)+1:03d}",
            "category": "suspicious_url",
            "subcategory": "percent_encoding",
            "url": f"https://apple-secure-{i+1}.example.com/%6c%6f%67%69%6e",
            "expected_label": "suspicious",
            "expected_assessment": ["High", "Medium"],
            "rationale": "Brand hostname with obfuscated percent-encoded path"
        })

    # =========================================================================
    # B. Legitimate URLs (>= 100)
    # =========================================================================
    benign_urls = []
    
    # 1. Normal website paths (20)
    for i in range(20):
        benign_urls.append({
            "id": f"BURL_{len(benign_urls)+1:03d}",
            "category": "benign_url",
            "subcategory": "general_web",
            "url": f"https://news-portal-{i+1}.example.com/articles/tech-trends-{2025+i}",
            "expected_label": "benign",
            "expected_assessment": ["Inconclusive", "Low"],
            "rationale": "Standard news article URL with clean domain and path"
        })

    # 2. Plain login / sign-in on normal domains without brand mimicry (15)
    for i in range(15):
        benign_urls.append({
            "id": f"BURL_{len(benign_urls)+1:03d}",
            "category": "benign_url",
            "subcategory": "normal_login",
            "url": f"https://account-hub-{i+1}.example.com/signin",
            "expected_label": "benign",
            "expected_assessment": ["Inconclusive", "Low"],
            "rationale": "Standard login path without impersonated brand flags"
        })

    # 3. E-commerce product pages with query parameters (20)
    for i in range(20):
        benign_urls.append({
            "id": f"BURL_{len(benign_urls)+1:03d}",
            "category": "benign_url",
            "subcategory": "ecommerce_product",
            "url": f"https://store-merchandise-{i+1}.example.com/items/detail?id={1000+i}&category=books&ref=search",
            "expected_label": "benign",
            "expected_assessment": ["Inconclusive", "Low"],
            "rationale": "Standard shopping item details with harmless query strings"
        })

    # 4. Educational / University links (15)
    for i in range(15):
        benign_urls.append({
            "id": f"BURL_{len(benign_urls)+1:03d}",
            "category": "benign_url",
            "subcategory": "university_edu",
            "url": f"https://university-campus-{i+1}.example.org/departments/computer-science/faculty",
            "expected_label": "benign",
            "expected_assessment": ["Inconclusive", "Low"],
            "rationale": "Academic institutional directory path"
        })

    # 5. Government informational paths (15)
    for i in range(15):
        benign_urls.append({
            "id": f"BURL_{len(benign_urls)+1:03d}",
            "category": "benign_url",
            "subcategory": "gov_services",
            "url": f"https://public-services-{i+1}.example.gov.lk/citizen/renewal-forms",
            "expected_label": "benign",
            "expected_assessment": ["Inconclusive", "Low"],
            "rationale": "Official public service form informational page"
        })

    # 6. Documentation and developer resources (15)
    for i in range(15):
        benign_urls.append({
            "id": f"BURL_{len(benign_urls)+1:03d}",
            "category": "benign_url",
            "subcategory": "developer_docs",
            "url": f"https://api-docs-{i+1}.example.net/v2/reference/pagination",
            "expected_label": "benign",
            "expected_assessment": ["Inconclusive", "Low"],
            "rationale": "Technical API reference documentation"
        })

    # =========================================================================
    # C. Scam-like Text Messages (>= 100)
    # =========================================================================
    scam_texts = []

    # 1. English OTP & Credential Requests with Urgency (35)
    for i in range(35):
        scam_texts.append({
            "id": f"STXT_{len(scam_texts)+1:03d}",
            "category": "scam_text",
            "subcategory": "english_otp_urgency",
            "text": f"URGENT: Your bank account {i+1000} has been suspended due to suspicious activity. Reply with your OTP code immediately to avoid permanent account closure.",
            "expected_label": "suspicious",
            "expected_assessment": ["High"],
            "rationale": "Direct credential disclosure request (OTP) combined with pressure/urgency"
        })

    # 2. English Advance Fee & Prize Scams (25)
    for i in range(25):
        scam_texts.append({
            "id": f"STXT_{len(scam_texts)+1:03d}",
            "category": "scam_text",
            "subcategory": "english_prize_fee",
            "text": f"Congratulations! You won the International Lottery #{i+500}. To claim prize, pay an advance fee of $150 immediately within 24 hours.",
            "expected_label": "suspicious",
            "expected_assessment": ["High", "Medium"],
            "rationale": "Reward/prize language combined with advance payment fee request"
        })

    # 3. Sinhala-language Scam Messages (20)
    sinhala_scam_templates = [
        "ඔබගේ බැංකු ගිණුම අවහිර කර ඇත. වහාම ඔබගේ OTP අංකය එවන්න නැතහොත් ගිණුම අවලංගු වේ.",
        "සුභ පැතුම්! ඔබ රුපියල් ලක්ෂ 25ක් දිනුම්. ත්‍යාගය ලබා ගැනීමට දැන්ම මුදල් එවන්න.",
        "හදිසි ආරක්ෂක පණිවිඩයයි: ඔබගේ ගිණුම ක්‍රියා විරහිත කර ඇත. මුරපදය වහාම දෙන්න.",
        "ඔබගේ කාඩ්පත අත්හිටුවා ඇත. පැය 2ක් ඇතුළත රහස් අංකය එවන්න."
    ]
    for i in range(20):
        t = sinhala_scam_templates[i % len(sinhala_scam_templates)]
        scam_texts.append({
            "id": f"STXT_{len(scam_texts)+1:03d}",
            "category": "scam_text",
            "subcategory": "sinhala_scam",
            "text": f"{t} (Ref #{i+100})",
            "expected_label": "suspicious",
            "expected_assessment": ["High", "Medium"],
            "rationale": "Sinhala language urgency, prize, or OTP disclosure request"
        })

    # 4. Mixed Sinhala-English / Singlish Scam Messages (20)
    singlish_scam_templates = [
        "Urgent alert: Obe bank account eka block wela. Ikmanin otp ewanna nathnam account close wei.",
        "Congratulations! Obe number eka dinum adimata tharanga dinuwa. Claim prize walata salli ewanna.",
        "Security notice: Obe account eka suspend wela thiyenne. Please provide your password to agent within 24 hours.",
        "Bank alert: Pay cash deposit immediately to unblock your account."
    ]
    for i in range(20):
        t = singlish_scam_templates[i % len(singlish_scam_templates)]
        scam_texts.append({
            "id": f"STXT_{len(scam_texts)+1:03d}",
            "category": "scam_text",
            "subcategory": "mixed_singlish_scam",
            "text": f"{t} Ref {i+200}",
            "expected_label": "suspicious",
            "expected_assessment": ["High", "Medium"],
            "rationale": "Mixed Singlish/English urgency with OTP or fee demands"
        })

    # =========================================================================
    # D. Legitimate Messages (>= 100)
    # =========================================================================
    benign_texts = []

    # 1. Genuine Bank Transaction Notifications (25)
    for i in range(25):
        benign_texts.append({
            "id": f"BTXT_{len(benign_texts)+1:03d}",
            "category": "benign_text",
            "subcategory": "bank_notification",
            "text": f"Your debit card ending in {4000+i} was used for a purchase of USD {12.50 + i} at Supermarket #{i+1}. Available balance: USD {1540.20 - i}.",
            "expected_label": "benign",
            "expected_assessment": ["Inconclusive", "Low"],
            "rationale": "Standard automated transaction receipt with no action demand"
        })

    # 2. Genuine OTPs with Do Not Share warnings (25)
    for i in range(25):
        benign_texts.append({
            "id": f"BTXT_{len(benign_texts)+1:03d}",
            "category": "benign_text",
            "subcategory": "safe_otp_delivery",
            "text": f"Your verification code is {654321 + i}. Never share this code with anyone. Our staff will never ask for your one-time password.",
            "expected_label": "benign",
            "expected_assessment": ["Inconclusive", "Low"],
            "rationale": "Legitimate OTP code delivery containing explicit negation/warning against disclosure"
        })

    # 3. Delivery Updates & Appointment Reminders (25)
    for i in range(25):
        benign_texts.append({
            "id": f"BTXT_{len(benign_texts)+1:03d}",
            "category": "benign_text",
            "subcategory": "delivery_and_appointment",
            "text": f"Package #{789000+i} has been delivered to your front door on {i+1} Oct. Track your orders anytime at our customer portal.",
            "expected_label": "benign",
            "expected_assessment": ["Inconclusive", "Low"],
            "rationale": "Factual status update without fee or credential request"
        })

    # 4. Personal, Academic & Sinhala Benign Messages (25)
    sinhala_benign = [
        "හෙට උදෑසන රැස්වීම පෙ.ව. 9.30 ට කාර්යාලයේදී පැවැත්වේ.",
        "ඔබගේ පොත පුස්තකාලයට ලැබී ඇත. කරුණාකර සතියක් ඇතුළත ලබාගන්න.",
        "Hi, are we meeting for coffee today at 4 PM? Let me know.",
        "Campus library will be closed this Friday for maintenance.",
        "Doctor appointment confirmation for Dr. Perera tomorrow at 10 AM."
    ]
    for i in range(25):
        benign_texts.append({
            "id": f"BTXT_{len(benign_texts)+1:03d}",
            "category": "benign_text",
            "subcategory": "personal_and_sinhala_benign",
            "text": f"{sinhala_benign[i % len(sinhala_benign)]} (Ref #{i+1})",
            "expected_label": "benign",
            "expected_assessment": ["Inconclusive", "Low"],
            "rationale": "Benign everyday communication in Sinhala or English"
        })

    # =========================================================================
    # E. Edge Cases (30)
    # =========================================================================
    edge_cases = [
        {"id": "EDGE_001", "category": "edge_case", "subcategory": "empty_string", "text": "", "expected_label": "invalid_or_inconclusive", "rationale": "Empty string input"},
        {"id": "EDGE_002", "category": "edge_case", "subcategory": "whitespace_only", "text": "   \n\t  ", "expected_label": "invalid_or_inconclusive", "rationale": "Whitespace-only input"},
        {"id": "EDGE_003", "category": "edge_case", "subcategory": "educational_quoted_scam", "text": 'Security Awareness: Scammers often send texts saying "URGENT: Provide your OTP immediately or account blocked". Do not respond to them.', "expected_label": "benign", "expected_assessment": ["Inconclusive", "Low"], "rationale": "Scam pattern inside explicitly quoted educational awareness clause"},
        {"id": "EDGE_004", "category": "edge_case", "subcategory": "malformed_url_scheme", "kind": "url", "text": "htt://invalid-scheme.example.com", "expected_label": "error", "rationale": "Missing valid http/https scheme"},
        {"id": "EDGE_005", "category": "edge_case", "subcategory": "malformed_url_slash", "kind": "url", "text": "https:///missing-host.example.com", "expected_label": "error", "rationale": "Malformed triple-slash URL"},
        {"id": "EDGE_006", "category": "edge_case", "subcategory": "very_long_url", "kind": "url", "text": "https://example.com/search?" + ("param=value&" * 150), "expected_label": "benign", "rationale": "Extremely long query string but benign"},
        {"id": "EDGE_007", "category": "edge_case", "subcategory": "excessive_length_text", "text": "Normal announcement. " * 300, "expected_label": "benign", "rationale": "Long text with repeated benign phrases"},
        {"id": "EDGE_008", "category": "edge_case", "subcategory": "unicode_domain", "kind": "url", "text": "https://xn--e1afmkfd.example.com/", "expected_label": "suspicious", "rationale": "Internationalized punycode domain flags inspection"},
        {"id": "EDGE_009", "category": "edge_case", "subcategory": "multiple_userinfo_ats", "kind": "url", "text": "https://user@admin@example.com/portal", "expected_label": "suspicious", "rationale": "Multiple @ signs in authority component"},
        {"id": "EDGE_010", "category": "edge_case", "subcategory": "unsupported_script_warning", "text": "ඔබගේ ගිණුම පරික්ෂා කරන්න: https://news.example.com/test", "expected_label": "benign", "rationale": "Sinhala text with benign URL without threats"},
    ]
    for i in range(11, 31):
        edge_cases.append({
            "id": f"EDGE_{i:03d}",
            "category": "edge_case",
            "subcategory": f"edge_variant_{i}",
            "text": f"Sample edge test #{i} with special chars: <script>alert({i})</script> & harmless content.",
            "expected_label": "benign",
            "rationale": "Special HTML/XSS-like characters should not crash the scanner or trigger scam rules"
        })

    dataset = {
        "metadata": {
            "version": "1.0.0",
            "description": "Safe synthetic test fixtures for ScamShield AI verification",
            "counts": {
                "suspicious_urls": len(suspicious_urls),
                "benign_urls": len(benign_urls),
                "scam_texts": len(scam_texts),
                "benign_texts": len(benign_texts),
                "edge_cases": len(edge_cases),
                "total": len(suspicious_urls) + len(benign_urls) + len(scam_texts) + len(benign_texts) + len(edge_cases)
            }
        },
        "suspicious_urls": suspicious_urls,
        "benign_urls": benign_urls,
        "scam_texts": scam_texts,
        "benign_texts": benign_texts,
        "edge_cases": edge_cases
    }
    return dataset

if __name__ == "__main__":
    out_dir = Path("d:/ScamShield AI/docs")
    data = generate_dataset()
    target_path = out_dir / "synthetic_evaluation_dataset.json"
    with open(target_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"Generated {data['metadata']['counts']['total']} synthetic test cases into {target_path}")
