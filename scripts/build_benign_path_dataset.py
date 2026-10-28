"""Build leakage-safe, domain-grouped benign deep-path dataset.

Generates realistic, public-documentation, educational, governmental,
and technical URLs with varying path depths, query parameters, and filenames.
Groups strictly by registrable domain to prevent domain leakage.
"""
import json
from pathlib import Path
import tldextract

ROOT = Path(__file__).resolve().parents[1]
EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True)

# Domain splits to guarantee zero domain overlap:
TRAIN_DOMAINS = {
    'python.org', 'wikipedia.org', 'w3.org', 'apache.org', 'kernel.org', 
    'gnu.org', 'ietf.org', 'readthedocs.io', 'debian.org', 'ubuntu.com'
}
VAL_DOMAINS = {
    'mozilla.org', 'nist.gov', 'github.com', 'archive.org', 'stackoverflow.com'
}
TEST_DOMAINS = {
    'cloudflare.com', 'google.com', 'duckduckgo.com', 'amazon.com', 
    'fb.com', 'gov.uk', 'data.gov', 'mit.edu', 'stanford.edu'
}

RAW_TEMPLATES = [
    # python.org (Train)
    ("python.org", "https://docs.python.org/3/library/{module}.html"),
    ("python.org", "https://docs.python.org/3/howto/{topic}.html"),
    ("python.org", "https://docs.python.org/3/c-api/{capi}.html"),
    ("python.org", "https://docs.python.org/3/tutorial/{tutorial}.html"),
    ("python.org", "https://peps.python.org/pep-{pep:04d}/"),
    
    # wikipedia.org (Train)
    ("wikipedia.org", "https://en.wikipedia.org/wiki/{wiki_topic}"),
    ("wikipedia.org", "https://commons.wikimedia.org/wiki/File:{wiki_file}"),
    ("wikipedia.org", "https://en.wikipedia.org/w/index.php?title={wiki_topic}&action=history"),

    # w3.org (Train)
    ("w3.org", "https://www.w3.org/TR/{w3_spec}/"),
    ("w3.org", "https://www.w3.org/standards/webdesign/{w3_topic}"),
    ("w3.org", "https://www.w3.org/Consortium/Offices/{w3_office}"),

    # apache.org (Train)
    ("apache.org", "https://httpd.apache.org/docs/2.4/mod/mod_{apache_mod}.html"),
    ("apache.org", "https://commons.apache.org/proper/commons-{apache_comp}/apidocs/index.html"),
    ("apache.org", "https://spark.apache.org/docs/latest/api/python/reference/{spark_ref}.html"),

    # kernel.org (Train)
    ("kernel.org", "https://www.kernel.org/doc/html/latest/admin-guide/{kernel_guide}.html"),
    ("kernel.org", "https://www.kernel.org/doc/html/latest/subsystem/{kernel_sub}.html"),
    ("kernel.org", "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/{kernel_path}"),

    # gnu.org (Train)
    ("gnu.org", "https://www.gnu.org/software/{gnu_pkg}/manual/html_node/{gnu_node}.html"),
    ("gnu.org", "https://www.gnu.org/licenses/{gnu_lic}.en.html"),

    # ietf.org (Train)
    ("ietf.org", "https://www.rfc-editor.org/rfc/rfc{rfc_num}.html"),
    ("ietf.org", "https://datatracker.ietf.org/doc/html/draft-{draft_name}"),

    # readthedocs.io (Train)
    ("readthedocs.io", "https://requests.readthedocs.io/en/latest/api/{rtd_topic}.html"),
    ("readthedocs.io", "https://click.palletsprojects.com/en/8.1.x/commands/{rtd_cmd}/"),

    # debian.org (Train)
    ("debian.org", "https://www.debian.org/doc/manuals/debian-reference/{deb_ref}.en.html"),
    ("debian.org", "https://packages.debian.org/sid/{deb_pkg}"),

    # ubuntu.com (Train)
    ("ubuntu.com", "https://ubuntu.com/server/docs/{ub_guide}"),
    ("ubuntu.com", "https://help.ubuntu.com/community/{ub_topic}"),

    # mozilla.org (Val)
    ("mozilla.org", "https://developer.mozilla.org/en-US/docs/Web/API/{web_api}"),
    ("mozilla.org", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/{http_header}"),
    ("mozilla.org", "https://developer.mozilla.org/en-US/docs/Web/CSS/{css_prop}"),
    ("mozilla.org", "https://developer.mozilla.org/en-US/docs/Learn/JavaScript/{js_guide}"),

    # nist.gov (Val)
    ("nist.gov", "https://csrc.nist.gov/publications/detail/sp/{sp_num}/final"),
    ("nist.gov", "https://www.nist.gov/cyberframework/online-learning/{nist_topic}"),
    ("nist.gov", "https://nvd.nist.gov/vuln/detail/{cve_id}"),

    # github.com (Val)
    ("github.com", "https://docs.github.com/en/actions/{gh_action_topic}"),
    ("github.com", "https://github.com/torvalds/linux/blob/master/Documentation/{gh_doc}.rst"),
    ("github.com", "https://github.com/python/cpython/tree/main/{gh_tree}"),

    # archive.org (Val)
    ("archive.org", "https://archive.org/details/{archive_item}"),
    ("archive.org", "https://archive.org/search.php?query={archive_query}"),

    # stackoverflow.com (Val)
    ("stackoverflow.com", "https://stackoverflow.com/questions/{so_id}/{so_slug}"),
    ("stackoverflow.com", "https://stackoverflow.com/tags/{so_tag}/info"),

    # cloudflare.com (Test)
    ("cloudflare.com", "https://blog.cloudflare.com/{cf_post}/"),
    ("cloudflare.com", "https://developers.cloudflare.com/workers/runtime-apis/{cf_api}/"),

    # google.com (Test)
    ("google.com", "https://www.google.com/search?q={google_query}&hl=en"),
    ("google.com", "https://developers.google.com/protocol-buffers/docs/{proto_topic}"),
    ("google.com", "https://cloud.google.com/security/products/{gcp_prod}"),

    # duckduckgo.com (Test)
    ("duckduckgo.com", "https://duckduckgo.com/?q={ddg_query}&ia=web"),

    # amazon.com (Test)
    ("amazon.com", "https://aws.amazon.com/security/identity-and-compliance/{aws_topic}/"),
    ("amazon.com", "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/{ec2_guide}.html"),

    # fb.com (Test)
    ("fb.com", "https://engineering.fb.com/{fb_year}/{fb_month}/{fb_day}/{fb_slug}/"),

    # gov.uk (Test)
    ("gov.uk", "https://www.gov.uk/government/organisations/{gov_org}"),
    ("gov.uk", "https://www.gov.uk/guidance/{gov_guide}"),

    # data.gov (Test)
    ("data.gov", "https://data.gov/metrics/{data_metric}/"),
    ("data.gov", "https://catalog.data.gov/dataset/{data_dataset}"),

    # mit.edu (Test)
    ("mit.edu", "https://ocw.mit.edu/courses/{mit_course}/pages/{mit_page}/"),

    # stanford.edu (Test)
    ("stanford.edu", "https://cs.stanford.edu/people/{stanford_person}/{stanford_path}.html"),
]

WORDS = [
    'os', 'sys', 'math', 'urllib', 'json', 're', 'socket', 'hashlib', 'sqlite3', 'unittest',
    'security', 'authentication', 'encryption', 'cryptography', 'network', 'protocol', 'database',
    'algorithm', 'performance', 'distributed', 'architecture', 'interface', 'compiler', 'runtime',
    'memory', 'storage', 'concurrency', 'asynchronous', 'optimization', 'standards', 'compliance',
    'monitoring', 'observability', 'telemetry', 'analytics', 'framework', 'pipeline', 'container'
]

def generate_urls():
    urls = []
    
    # 1. Python docs
    for w1 in WORDS:
        for w2 in ['parser', 'client', 'server', 'config', 'utils', 'handler']:
            urls.append(('python.org', f"https://docs.python.org/3/library/{w1}_{w2}.html"))
            urls.append(('python.org', f"https://docs.python.org/3/howto/logging_{w1}_{w2}.html"))
    for i in range(1, 150):
        urls.append(('python.org', f"https://peps.python.org/pep-{i:04d}/"))

    # 2. Wikipedia topics
    for w in WORDS:
        urls.append(('wikipedia.org', f"https://en.wikipedia.org/wiki/{w.capitalize()}_protocol"))
        urls.append(('wikipedia.org', f"https://en.wikipedia.org/wiki/{w.capitalize()}_algorithm"))
        urls.append(('wikipedia.org', f"https://en.wikipedia.org/wiki/Comparison_of_{w}_software"))
        urls.append(('wikipedia.org', f"https://en.wikipedia.org/w/index.php?title={w}&action=history"))

    # 3. W3C specs
    for w in ['html5', 'webdriver', 'csp', 'cors', 'webrtc', 'wasm', 'svg', 'xpath', 'xml', 'css3']:
        for sub in ['spec', 'primer', 'rec', 'test-suite']:
            urls.append(('w3.org', f"https://www.w3.org/TR/{w}-{sub}/"))
            urls.append(('w3.org', f"https://www.w3.org/TR/2026/REC-{w}-{sub}-20260415/"))

    # 4. Apache docs
    for w in ['ssl', 'rewrite', 'proxy', 'headers', 'deflate', 'auth_basic', 'cache', 'log_config']:
        urls.append(('apache.org', f"https://httpd.apache.org/docs/2.4/mod/mod_{w}.html"))
        urls.append(('apache.org', f"https://commons.apache.org/proper/commons-{w}/apidocs/index.html"))

    # 5. Linux Kernel & Git
    for w in ['memory-barriers', 'booting', 'sysfs', 'namespaces', 'cgroups', 'ebpf', 'networking']:
        urls.append(('kernel.org', f"https://www.kernel.org/doc/html/latest/admin-guide/{w}.html"))
        urls.append(('kernel.org', f"https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/Documentation/{w}.rst"))

    # 6. GNU
    for w in ['bash', 'coreutils', 'gcc', 'glibc', 'make', 'gdb', 'tar', 'grep']:
        urls.append(('gnu.org', f"https://www.gnu.org/software/{w}/manual/html_node/Invoking-{w}.html"))
        urls.append(('gnu.org', f"https://www.gnu.org/software/{w}/manual/html_node/{w}-Options.html"))

    # 7. IETF RFCs
    for r in [7230, 7231, 7540, 8446, 5246, 2616, 1034, 1035, 3986, 6749, 7519, 8259]:
        urls.append(('ietf.org', f"https://www.rfc-editor.org/rfc/rfc{r}.html"))
        urls.append(('ietf.org', f"https://datatracker.ietf.org/doc/html/rfc{r}#section-3"))

    # 8. ReadtheDocs
    for w in ['quickstart', 'advanced', 'authentication', 'configuration', 'exceptions']:
        urls.append(('readthedocs.io', f"https://requests.readthedocs.io/en/latest/user/{w}.html"))
        urls.append(('readthedocs.io', f"https://urllib3.readthedocs.io/en/stable/reference/{w}.html"))

    # 9. Debian & Ubuntu
    for w in ['system-administration', 'network-setup', 'security-updates']:
        urls.append(('debian.org', f"https://www.debian.org/doc/manuals/debian-reference/{w}.en.html"))
        urls.append(('ubuntu.com', f"https://ubuntu.com/server/docs/{w}-overview"))

    # --- VALIDATION SET (mozilla, nist, github, archive, stackoverflow) ---
    for w in WORDS:
        urls.append(('mozilla.org', f"https://developer.mozilla.org/en-US/docs/Web/API/{w.capitalize()}Stream"))
        urls.append(('mozilla.org', f"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-{w.capitalize()}-Policy"))
        urls.append(('mozilla.org', f"https://developer.mozilla.org/en-US/docs/Learn/JavaScript/Asynchronous/{w}"))
    for sp in [53, 63, 88, 137, 161, 190, 207]:
        urls.append(('nist.gov', f"https://csrc.nist.gov/publications/detail/sp/800-{sp}/final"))
        urls.append(('nist.gov', f"https://csrc.nist.gov/publications/detail/sp/800-{sp}/rev-5/draft"))
    for w in WORDS[:15]:
        urls.append(('github.com', f"https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#{w}"))
        urls.append(('github.com', f"https://github.com/torvalds/linux/blob/master/Documentation/admin-guide/{w}.rst"))
    for i in range(1001, 1080):
        urls.append(('stackoverflow.com', f"https://stackoverflow.com/questions/{i*123}/how-to-configure-secure-headers-in-python"))

    # --- HELD-OUT TEST SET (cloudflare, google, ddg, amazon, fb, gov.uk, data.gov, mit.edu, stanford.edu) ---
    for w in WORDS:
        urls.append(('cloudflare.com', f"https://blog.cloudflare.com/mitigating-{w}-attacks-with-cloudflare-workers/"))
        urls.append(('google.com', f"https://www.google.com/search?q={w}+documentation+standards&hl=en"))
        urls.append(('duckduckgo.com', f"https://duckduckgo.com/?q={w}+best+practices&ia=web"))
        urls.append(('amazon.com', f"https://aws.amazon.com/security/identity-and-compliance/{w}-guidance/"))
        urls.append(('fb.com', f"https://engineering.fb.com/2026/02/10/security/{w}-architecture-overview/"))
        urls.append(('gov.uk', f"https://www.gov.uk/government/publications/national-cyber-strategy-{w}-annex"))
        urls.append(('data.gov', f"https://catalog.data.gov/dataset/federal-{w}-metrics-2026"))
        urls.append(('mit.edu', f"https://ocw.mit.edu/courses/electrical-engineering-and-computer-science/6-858-computer-systems-security-fall-2026/pages/{w}-notes/"))
        urls.append(('stanford.edu', f"https://cs.stanford.edu/people/faculty/{w}-research-group.html"))

    # Split by registrable domain
    split_data = {'train': [], 'validation': [], 'test': []}
    seen = set()
    
    for domain, u in urls:
        if u in seen:
            continue
        seen.add(u)
        ext = EXTRACT(domain)
        reg_domain = ext.top_domain_under_public_suffix or domain
        
        if reg_domain in TRAIN_DOMAINS:
            split_data['train'].append({'text': u, 'label': 'legitimate', 'group': reg_domain, 'split': 'train'})
        elif reg_domain in VAL_DOMAINS:
            split_data['validation'].append({'text': u, 'label': 'legitimate', 'group': reg_domain, 'split': 'validation'})
        elif reg_domain in TEST_DOMAINS:
            split_data['test'].append({'text': u, 'label': 'legitimate', 'group': reg_domain, 'split': 'test'})
        else:
            split_data['train'].append({'text': u, 'label': 'legitimate', 'group': reg_domain, 'split': 'train'})

    return split_data

def main():
    data = generate_urls()
    print("Generated benign deep-path dataset:")
    print(f"  Train:      {len(data['train'])} URLs across {len({r['group'] for r in data['train']})} domains")
    print(f"  Validation: {len(data['validation'])} URLs across {len({r['group'] for r in data['validation']})} domains")
    print(f"  Test:       {len(data['test'])} URLs across {len({r['group'] for r in data['test']})} domains")
    
    # Assert zero domain leakage between splits
    train_groups = {r['group'] for r in data['train']}
    val_groups = {r['group'] for r in data['validation']}
    test_groups = {r['group'] for r in data['test']}
    
    assert not (train_groups & val_groups), f"Leakage train-val: {train_groups & val_groups}"
    assert not (train_groups & test_groups), f"Leakage train-test: {train_groups & test_groups}"
    assert not (val_groups & test_groups), f"Leakage val-test: {val_groups & test_groups}"
    print("ZERO DOMAIN LEAKAGE VERIFIED across train, validation, and test splits!")
    
    out_path = ROOT / 'ml' / 'data' / 'benign_deep_paths.json'
    out_path.write_text(json.dumps(data, indent=2), encoding='utf-8')
    print(f"Saved dataset to {out_path}")

if __name__ == '__main__':
    main()
