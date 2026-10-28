"""Build leakage-safe, domain-grouped benign deep-path dataset.

Generates realistic, diverse, non-duplicative URLs across documentation,
educational, governmental, news, and technical domains.
Partitioned strictly by registrable domain with ZERO domain overlap.
"""
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from backend.app.url_analysis import inspect_url

# Registrable domain splits to guarantee zero domain overlap:
TRAIN_DOMAINS = {
    'python.org', 'wikipedia.org', 'w3.org', 'apache.org', 'kernel.org', 
    'gnu.org', 'ietf.org', 'readthedocs.io', 'debian.org', 'ubuntu.com',
    'postgresql.org', 'rust-lang.org', 'sqlite.org', 'who.int', 'nasa.gov',
    'weather.gov', 'golang.org', 'curl.se'
}

VAL_DOMAINS = {
    'mozilla.org', 'nist.gov', 'github.com', 'archive.org', 'stackoverflow.com',
    'berkeley.edu', 'harvard.edu', 'reuters.com', 'arstechnica.com', 'gov.lk',
    'ox.ac.uk'
}

TEST_DOMAINS = {
    'cloudflare.com', 'google.com', 'duckduckgo.com', 'amazon.com', 'fb.com',
    'gov.uk', 'data.gov', 'mit.edu', 'stanford.edu', 'cam.ac.uk', 'cbsl.gov.lk',
    'theguardian.com', 'techcrunch.com'
}

def generate_benign_dataset():
    records = {'train': [], 'validation': [], 'test': []}
    
    # Vocabulary of diverse technical and general topics
    TOPICS = [
        'computer-security', 'cryptographic-hash', 'public-key-cryptography', 'transport-layer-security',
        'domain-name-system', 'ipv6-routing', 'border-gateway-protocol', 'operating-system-kernels',
        'relational-database-management', 'compiler-optimization', 'distributed-systems-consensus',
        'machine-learning-algorithms', 'random-forest-classification', 'logistic-regression-models',
        'virtual-machine-hypervisors', 'digital-signature-algorithms', 'zero-knowledge-proofs',
        'certificate-authority-trust', 'hypertext-transfer-protocol', 'oauth-authorization-framework',
        'multi-factor-authentication', 'single-sign-on-architecture', 'content-security-policy',
        'cross-origin-resource-sharing', 'webassembly-runtime-performance', 'asynchronous-event-loop',
        'garbage-collection-strategies', 'thread-synchronization-primitives', 'memory-allocator-internals',
        'sql-query-planner-optimization', 'tcp-congestion-control', 'packet-filtering-firewalls',
        'container-runtime-namespaces', 'microservices-observability', 'continuous-integration-pipelines',
        'version-control-internals', 'lexical-analysis-parsing', 'abstract-syntax-trees',
        'binary-search-tree-rotations', 'dynamic-programming-memoization', 'graph-shortest-path-algorithms'
    ]

    # --- TRAINING DOMAINS ---
    # 1. python.org
    for t in TOPICS[:30]:
        records['train'].append({'text': f"https://docs.python.org/3/library/{t.replace('-', '_')}.html", 'label': 'legitimate', 'group': 'python.org', 'split': 'train'})
        records['train'].append({'text': f"https://docs.python.org/3/howto/logging_{t.replace('-', '_')}.html", 'label': 'legitimate', 'group': 'python.org', 'split': 'train'})
        records['train'].append({'text': f"https://docs.python.org/3/c-api/{t.replace('-', '_')}.html", 'label': 'legitimate', 'group': 'python.org', 'split': 'train'})
        records['train'].append({'text': f"https://docs.python.org/3/tutorial/{t.replace('-', '_')}.html", 'label': 'legitimate', 'group': 'python.org', 'split': 'train'})
    for p in range(1, 120):
        records['train'].append({'text': f"https://peps.python.org/pep-{p:04d}/", 'label': 'legitimate', 'group': 'python.org', 'split': 'train'})

    # 2. wikipedia.org
    for t in TOPICS:
        slug = t.replace('-', '_').capitalize()
        records['train'].append({'text': f"https://en.wikipedia.org/wiki/{slug}", 'label': 'legitimate', 'group': 'wikipedia.org', 'split': 'train'})
        records['train'].append({'text': f"https://en.wikipedia.org/w/index.php?title={slug}&action=history", 'label': 'legitimate', 'group': 'wikipedia.org', 'split': 'train'})
        records['train'].append({'text': f"https://en.wikipedia.org/wiki/Talk:{slug}", 'label': 'legitimate', 'group': 'wikipedia.org', 'split': 'train'})
        records['train'].append({'text': f"https://en.wikipedia.org/wiki/Special:Search?search={t}&go=Go", 'label': 'legitimate', 'group': 'wikipedia.org', 'split': 'train'})

    # 3. w3.org
    for t in TOPICS[:25]:
        records['train'].append({'text': f"https://www.w3.org/TR/{t}/", 'label': 'legitimate', 'group': 'w3.org', 'split': 'train'})
        records['train'].append({'text': f"https://www.w3.org/standards/webdesign/{t}", 'label': 'legitimate', 'group': 'w3.org', 'split': 'train'})

    # 4. apache.org
    for t in TOPICS[:25]:
        records['train'].append({'text': f"https://httpd.apache.org/docs/2.4/mod/mod_{t.replace('-', '_')}.html", 'label': 'legitimate', 'group': 'apache.org', 'split': 'train'})
        records['train'].append({'text': f"https://commons.apache.org/proper/commons-{t}/apidocs/index.html", 'label': 'legitimate', 'group': 'apache.org', 'split': 'train'})

    # 5. kernel.org
    for t in TOPICS[:25]:
        records['train'].append({'text': f"https://www.kernel.org/doc/html/latest/admin-guide/{t}.html", 'label': 'legitimate', 'group': 'kernel.org', 'split': 'train'})
        records['train'].append({'text': f"https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/Documentation/{t}.rst", 'label': 'legitimate', 'group': 'kernel.org', 'split': 'train'})

    # 6. gnu.org
    for t in TOPICS[:25]:
        records['train'].append({'text': f"https://www.gnu.org/software/{t}/manual/html_node/Invoking.html", 'label': 'legitimate', 'group': 'gnu.org', 'split': 'train'})
        records['train'].append({'text': f"https://www.gnu.org/software/{t}/manual/html_node/Options.html", 'label': 'legitimate', 'group': 'gnu.org', 'split': 'train'})

    # 7. ietf.org
    for r in range(7000, 7060):
        records['train'].append({'text': f"https://www.rfc-editor.org/rfc/rfc{r}.html", 'label': 'legitimate', 'group': 'ietf.org', 'split': 'train'})
        records['train'].append({'text': f"https://datatracker.ietf.org/doc/html/rfc{r}#section-3", 'label': 'legitimate', 'group': 'ietf.org', 'split': 'train'})

    # 8. readthedocs.io
    for t in TOPICS[:25]:
        records['train'].append({'text': f"https://{t.replace('-', '')}.readthedocs.io/en/latest/user/quickstart.html", 'label': 'legitimate', 'group': 'readthedocs.io', 'split': 'train'})
        records['train'].append({'text': f"https://{t.replace('-', '')}.readthedocs.io/en/latest/api/reference.html", 'label': 'legitimate', 'group': 'readthedocs.io', 'split': 'train'})

    # 9. debian.org, ubuntu.com, postgresql.org, rust-lang.org, sqlite.org, who.int, nasa.gov, golang.org, curl.se
    for t in TOPICS[:20]:
        records['train'].append({'text': f"https://www.debian.org/doc/manuals/debian-reference/{t}.en.html", 'label': 'legitimate', 'group': 'debian.org', 'split': 'train'})
        records['train'].append({'text': f"https://ubuntu.com/server/docs/{t}-overview", 'label': 'legitimate', 'group': 'ubuntu.com', 'split': 'train'})
        records['train'].append({'text': f"https://www.postgresql.org/docs/current/{t}.html", 'label': 'legitimate', 'group': 'postgresql.org', 'split': 'train'})
        records['train'].append({'text': f"https://doc.rust-lang.org/std/{t.replace('-', '/')}/index.html", 'label': 'legitimate', 'group': 'rust-lang.org', 'split': 'train'})
        records['train'].append({'text': f"https://www.sqlite.org/{t.replace('-', '_')}.html", 'label': 'legitimate', 'group': 'sqlite.org', 'split': 'train'})
        records['train'].append({'text': f"https://pkg.go.dev/net/{t}", 'label': 'legitimate', 'group': 'golang.org', 'split': 'train'})
        records['train'].append({'text': f"https://curl.se/docs/{t}.html", 'label': 'legitimate', 'group': 'curl.se', 'split': 'train'})
        records['train'].append({'text': f"https://www.who.int/publications/i/item/{t}", 'label': 'legitimate', 'group': 'who.int', 'split': 'train'})
        records['train'].append({'text': f"https://www.nasa.gov/missions/{t}/", 'label': 'legitimate', 'group': 'nasa.gov', 'split': 'train'})

    # --- VALIDATION DOMAINS ---
    # 1. mozilla.org
    for t in TOPICS[:30]:
        slug = t.replace('-', '_').capitalize()
        records['validation'].append({'text': f"https://developer.mozilla.org/en-US/docs/Web/API/{slug}", 'label': 'legitimate', 'group': 'mozilla.org', 'split': 'validation'})
        records['validation'].append({'text': f"https://developer.mozilla.org/en-US/docs/Web/API/{slug}/Using_{slug}", 'label': 'legitimate', 'group': 'mozilla.org', 'split': 'validation'})
        records['validation'].append({'text': f"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/{slug}", 'label': 'legitimate', 'group': 'mozilla.org', 'split': 'validation'})
        records['validation'].append({'text': f"https://developer.mozilla.org/en-US/docs/Learn/JavaScript/{t}", 'label': 'legitimate', 'group': 'mozilla.org', 'split': 'validation'})

    # 2. nist.gov
    for n in range(50, 100):
        records['validation'].append({'text': f"https://csrc.nist.gov/publications/detail/sp/800-{n}/final", 'label': 'legitimate', 'group': 'nist.gov', 'split': 'validation'})
        records['validation'].append({'text': f"https://csrc.nist.gov/publications/detail/sp/800-{n}/rev-5/draft", 'label': 'legitimate', 'group': 'nist.gov', 'split': 'validation'})

    # 3. github.com
    for t in TOPICS[:30]:
        records['validation'].append({'text': f"https://github.com/torvalds/{t}/blob/main/README.md", 'label': 'legitimate', 'group': 'github.com', 'split': 'validation'})
        records['validation'].append({'text': f"https://github.com/torvalds/{t}/releases/tag/v2.0.0", 'label': 'legitimate', 'group': 'github.com', 'split': 'validation'})
        records['validation'].append({'text': f"https://github.com/torvalds/{t}/issues/1042", 'label': 'legitimate', 'group': 'github.com', 'split': 'validation'})
        records['validation'].append({'text': f"https://docs.github.com/en/actions/{t}", 'label': 'legitimate', 'group': 'github.com', 'split': 'validation'})

    # 4. stackoverflow.com (50 diverse, distinct questions across programming languages)
    SO_QUESTIONS = [
        'how-to-parse-json-in-python-safely', 'centering-a-div-horizontally-and-vertically-in-css',
        'docker-compose-expose-ports-vs-publish', 'git-rebase-vs-merge-best-practices',
        'regular-expression-to-match-ipv4-and-ipv6', 'fastapi-dependency-injection-with-yield',
        'postgresql-jsonb-indexing-with-gin', 'handling-concurrent-requests-in-node-js',
        'react-native-navigation-pass-props-between-screens', 'sqlite3-database-locked-workarounds-in-python',
        'rust-borrow-checker-cannot-borrow-as-mutable', 'golang-goroutine-channel-deadlock-prevention',
        'kubernetes-ingress-nginx-tls-termination', 'typescript-generic-type-inference-function-argument',
        'css-grid-template-areas-responsive-layout', 'webpack-code-splitting-dynamic-imports',
        'linux-systemd-service-auto-restart-policy', 'bash-script-read-file-line-by-line-safely',
        'nginx-reverse-proxy-websockets-configuration', 'redis-pub-sub-message-durability-alternatives',
        'python-multiprocessing-shared-memory-arrays', 'sqlalchemy-async-session-commit-rollback',
        'docker-multi-stage-build-minimal-alpine', 'git-submodule-update-init-recursive',
        'ssh-key-forwarding-agent-configuration-guide', 'curl-send-post-json-header-command-line',
        'pytest-fixture-scope-function-vs-session', 'javascript-event-delegation-performance',
        'html5-canvas-draw-image-aspect-ratio', 'pandas-dataframe-groupby-aggregate-named-columns',
        'django-rest-framework-nested-serializers', 'celery-task-retry-exponential-backoff',
        'tailwind-css-custom-breakpoint-theme-extend', 'mongodb-aggregation-pipeline-lookup-unwind',
        'git-stash-include-untracked-pop-conflict', 'ansible-playbook-run-once-per-host-group',
        'terraform-aws-security-group-rule-cidr', 'vim-search-replace-regex-capture-groups',
        'python-dataclass-field-default-factory', 'react-useEffect-cleanup-function-abort-controller',
        'flutter-stateful-widget-lifecycle-methods', 'aws-s3-presigned-url-expiration-policy',
        'google-cloud-run-container-concurrency-limits', 'graphql-schema-resolvers-query-mutation',
        'kafka-consumer-group-rebalance-protocol', 'elasticsearch-bool-query-must-should-filter',
        'c-sharp-async-await-configure-await-false', 'java-virtual-threads-project-loom-guide',
        'c-plus-plus-smart-pointers-unique-shared', 'ruby-on-rails-active-record-eager-loading'
    ]
    for i, slug in enumerate(SO_QUESTIONS):
        qid = 1000000 + i * 29381
        records['validation'].append({'text': f"https://stackoverflow.com/questions/{qid}/{slug}", 'label': 'legitimate', 'group': 'stackoverflow.com', 'split': 'validation'})
        records['validation'].append({'text': f"https://stackoverflow.com/questions/{qid}?answertab=votes", 'label': 'legitimate', 'group': 'stackoverflow.com', 'split': 'validation'})

    # 5. berkeley.edu, harvard.edu, ox.ac.uk, reuters.com, arstechnica.com, gov.lk
    for t in TOPICS[:20]:
        records['validation'].append({'text': f"https://eecs.berkeley.edu/academics/courses/{t}", 'label': 'legitimate', 'group': 'berkeley.edu', 'split': 'validation'})
        records['validation'].append({'text': f"https://cs50.harvard.edu/x/2026/weeks/{t}/", 'label': 'legitimate', 'group': 'harvard.edu', 'split': 'validation'})
        records['validation'].append({'text': f"https://www.ox.ac.uk/research/initiatives/{t}", 'label': 'legitimate', 'group': 'ox.ac.uk', 'split': 'validation'})
        records['validation'].append({'text': f"https://www.reuters.com/technology/{t}-market-outlook-2026/", 'label': 'legitimate', 'group': 'reuters.com', 'split': 'validation'})
        records['validation'].append({'text': f"https://arstechnica.com/information-technology/2026/02/{t}-deep-dive/", 'label': 'legitimate', 'group': 'arstechnica.com', 'split': 'validation'})
        records['validation'].append({'text': f"https://www.gov.lk/services/{t}-portal", 'label': 'legitimate', 'group': 'gov.lk', 'split': 'validation'})

    # --- HELD-OUT TEST DOMAINS ---
    # cloudflare, google, ddg, amazon, fb, gov.uk, data.gov, mit.edu, stanford.edu, cam.ac.uk, cbsl.gov.lk, theguardian.com, techcrunch.com
    for t in TOPICS[:30]:
        records['test'].append({'text': f"https://blog.cloudflare.com/{t}-architecture-and-defense/", 'label': 'legitimate', 'group': 'cloudflare.com', 'split': 'test'})
        records['test'].append({'text': f"https://developers.cloudflare.com/workers/runtime-apis/{t}/", 'label': 'legitimate', 'group': 'cloudflare.com', 'split': 'test'})
        records['test'].append({'text': f"https://www.google.com/search?q={t.replace('-', '+')}&hl=en", 'label': 'legitimate', 'group': 'google.com', 'split': 'test'})
        records['test'].append({'text': f"https://duckduckgo.com/?q={t.replace('-', '+')}&ia=web", 'label': 'legitimate', 'group': 'duckduckgo.com', 'split': 'test'})
        records['test'].append({'text': f"https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/{t}.html", 'label': 'legitimate', 'group': 'amazon.com', 'split': 'test'})
        records['test'].append({'text': f"https://aws.amazon.com/security/{t}-best-practices/", 'label': 'legitimate', 'group': 'amazon.com', 'split': 'test'})
        records['test'].append({'text': f"https://engineering.fb.com/2026/01/15/developer-tools/{t}/", 'label': 'legitimate', 'group': 'fb.com', 'split': 'test'})
        records['test'].append({'text': f"https://www.gov.uk/guidance/{t}-policy-framework", 'label': 'legitimate', 'group': 'gov.uk', 'split': 'test'})
        records['test'].append({'text': f"https://catalog.data.gov/dataset/{t}-metrics-report", 'label': 'legitimate', 'group': 'data.gov', 'split': 'test'})
        records['test'].append({'text': f"https://ocw.mit.edu/courses/{t}/pages/syllabus/", 'label': 'legitimate', 'group': 'mit.edu', 'split': 'test'})
        records['test'].append({'text': f"https://cs.stanford.edu/people/faculty/{t}-group.html", 'label': 'legitimate', 'group': 'stanford.edu', 'split': 'test'})
        records['test'].append({'text': f"https://www.cam.ac.uk/research/features/{t}", 'label': 'legitimate', 'group': 'cam.ac.uk', 'split': 'test'})
        records['test'].append({'text': f"https://www.cbsl.gov.lk/en/publications/{t}", 'label': 'legitimate', 'group': 'cbsl.gov.lk', 'split': 'test'})
        records['test'].append({'text': f"https://www.theguardian.com/technology/2026/mar/10/{t}", 'label': 'legitimate', 'group': 'theguardian.com', 'split': 'test'})
        records['test'].append({'text': f"https://techcrunch.com/2026/02/14/{t}-enterprise-overview/", 'label': 'legitimate', 'group': 'techcrunch.com', 'split': 'test'})

    # Verify zero leakage across splits:
    split_domains = {}
    for split in ['train', 'validation', 'test']:
        domains = set()
        for r in records[split]:
            info = inspect_url(r['text'])
            reg = info['registrable_domain']
            assert reg, f"Missing registrable domain for {r['text']}"
            domains.add(reg)
        split_domains[split] = domains
        
    s1 = split_domains['train']
    s2 = split_domains['validation']
    s3 = split_domains['test']
    
    assert len(s1.intersection(s2)) == 0, f"Train/Val domain leakage: {s1.intersection(s2)}"
    assert len(s1.intersection(s3)) == 0, f"Train/Test domain leakage: {s1.intersection(s3)}"
    assert len(s2.intersection(s3)) == 0, f"Val/Test domain leakage: {s2.intersection(s3)}"
    
    print("Zero domain leakage verified across all splits!")
    print(f"Train samples: {len(records['train'])} across {len(s1)} domains")
    print(f"Validation samples: {len(records['validation'])} across {len(s2)} domains")
    print(f"Test samples: {len(records['test'])} across {len(s3)} domains")
    
    out_file = ROOT / 'ml' / 'data' / 'benign_deep_paths.json'
    out_file.write_text(json.dumps(records, indent=2), encoding='utf-8')
    print(f"Saved benign deep paths to {out_file}")

if __name__ == '__main__':
    generate_benign_dataset()
