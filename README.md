# GhostAudit

Kubernetes Security Auditor CLI. Scans clusters for security misconfigurations based on the CIS Kubernetes Benchmark and real-world security best practices, then generates actionable reports.

Think `kube-bench` but focused, Python-based, and with clean HTML reports.

## Install

```bash
pip install .

# Development
pip install -e ".[dev]"
```

## Usage

```bash
# Full scan using default kubeconfig
ghostaudit scan

# Specify kubeconfig
ghostaudit scan --kubeconfig ~/.kube/config

# Scan a specific namespace
ghostaudit scan --namespace production

# Generate HTML report
ghostaudit scan --output report.html

# Generate JSON report
ghostaudit scan --output report.json

# Run only specific check categories
ghostaudit scan --checks rbac,pods

# List all available checks
ghostaudit checks

# Show version
ghostaudit --version
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Scan completed, no CRITICAL or HIGH findings |
| 1 | Configuration or connection error |
| 2 | Scan completed with CRITICAL or HIGH findings |

## Security Checks

| ID | Category | Title | Severity |
|----|----------|-------|----------|
| RBAC-001 | RBAC | Cluster-admin bound to non-system account | CRITICAL |
| RBAC-002 | RBAC | Overly permissive role (wildcards) | HIGH |
| RBAC-003 | RBAC | ServiceAccount auto-mounts API token | MEDIUM |
| RBAC-004 | RBAC | Workload running in default namespace | MEDIUM |
| POD-001 | Pod Security | Privileged container | CRITICAL |
| POD-002 | Pod Security | Container may run as root | HIGH |
| POD-003 | Pod Security | Missing security context | MEDIUM |
| POD-004 | Pod Security | Host namespace sharing enabled | HIGH |
| POD-005 | Pod Security | Writable root filesystem | MEDIUM |
| POD-006 | Pod Security | Privilege escalation allowed | MEDIUM |
| POD-007 | Pod Security | Dangerous capabilities added | HIGH |
| SEC-001 | Secrets | Secret exposed as environment variable | MEDIUM |
| SEC-002 | Secrets | ConfigMap contains sensitive-looking keys | HIGH |
| SEC-003 | Secrets | Secret in default namespace | LOW |
| NET-001 | Network | Namespace without NetworkPolicy | HIGH |
| NET-002 | Network | Service exposed via LoadBalancer/NodePort | MEDIUM |
| NET-003 | Network | External service without documentation annotation | LOW |
| RES-001 | Resources | Container without resource limits | MEDIUM |
| RES-002 | Resources | Container without resource requests | LOW |
| RES-003 | Resources | No PodDisruptionBudget for scaled deployment | LOW |
| IMG-001 | Images | Container using :latest tag | MEDIUM |
| IMG-002 | Images | Public registry image without digest | MEDIUM |
| IMG-003 | Images | Missing imagePullPolicy: Always for mutable tag | LOW |

## Sample Console Output

```
╭──────────── GhostAudit ─────────────╮
│ GhostAudit Security Report          │
│ Cluster: my-cluster                  │
│ Time: 2026-04-16 12:00:00 UTC       │
│ Security Score: 42/100               │
╰──────────────────────────────────────╯

     Findings Summary
┏━━━━━━━━━━┳━━━━━━━┓
┃ Severity ┃ Count ┃
┡━━━━━━━━━━╇━━━━━━━┩
│ CRITICAL │     2 │
│ HIGH     │     5 │
│ MEDIUM   │     8 │
│ LOW      │     3 │
│ INFO     │     0 │
│ TOTAL    │    18 │
└──────────┴───────┘

╭─ [!!!] [POD-001] Privileged container ───────────╮
│ Resource: Pod/bad-pod/app (ns: default)          │
│                                                   │
│ Container 'bad-pod/app' in namespace 'default'   │
│ is running in privileged mode...                  │
│                                                   │
│ Remediation: Set securityContext.privileged: false│
╰───────────────────────────────────────────────────╯
```

## HTML Report

The HTML report features a dark theme with:
- Security score gauge (0-100)
- Severity summary cards
- Expandable findings grouped by category
- Remediation steps for each finding
- Fully self-contained (all CSS embedded, no external dependencies)

## Architecture

```
src/ghostaudit/
├── cli.py              # Typer CLI
├── config.py           # Settings
├── scanner.py          # Main orchestrator
├── client.py           # K8s API client wrapper
├── models.py           # Finding, Severity, ScanReport
├── checks/
│   ├── base.py         # BaseCheck ABC
│   ├── rbac.py         # RBAC checks
│   ├── pods.py         # Pod security checks
│   ├── secrets.py      # Secrets & config checks
│   ├── network.py      # Network policy checks
│   ├── resources.py    # Resource limits checks
│   └── images.py       # Image security checks
└── report/
    ├── console.py      # Rich console output
    ├── html.py         # HTML report (Jinja2)
    └── json_report.py  # JSON report
```

Each check module accepts pre-loaded K8s resource dicts via `KubeResources`, allowing testing with fixture data without a live cluster.

## Development

```bash
# Install dev dependencies
make dev

# Run tests
make test

# Run tests with coverage
make test-cov

# Lint
make lint
```

## License

MIT - Joe Munene 2026
