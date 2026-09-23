# VAPT Auditor

A self-hosted tool that runs Vulnerability Assessment & Penetration Testing scans
against systems you're authorized to test, and produces a professional HTML + PDF
audit report.

It does not reimplement vulnerability scanning logic from scratch. It orchestrates
proven, industry-standard open-source scanners and normalizes their output into one
report:

| Target type | Tools used |
|---|---|
| Network host / IP / CIDR | Nmap (service/version detection, OS fingerprint, NSE `vuln` scripts) |
| Web application | Nuclei (templated vuln/exposure checks), Nikto (server misconfig), testssl.sh (TLS/cert issues, HTTPS only) |
| WordPress site | All of the above + WPScan (core/plugin/theme version + known-CVE lookup, username enumeration) |
| Mobile app (Android `.apk`) | Static analysis only (Androguard): manifest/permission review, exported components, cleartext traffic, hardcoded secrets |

**⚠️ Authorization is on you.** Only scan systems you own or have explicit written
permission to test. The web form requires checking an authorization confirmation
box before every scan, but that's a reminder, not a technical control — you are
responsible for scope.

**⚠️ Not a replacement for a licensed pentest.** This automates well-known tools and
flags what they find. It will produce false positives, and it will miss things a
skilled human tester wouldn't. Use it for continuous/internal hygiene checks and as
a head start — not as your only assurance activity if you have compliance
requirements (PCI-DSS, SOC 2, etc.) that mandate a licensed penetration test.

## What's covered today vs. not

- **Network + web + WordPress**: fully wired to real scanners with parsed,
  severity-ranked findings.
- **Mobile**: static analysis of an uploaded APK only. No dynamic/runtime testing
  (instrumentation, traffic interception, IPA/iOS support) — that needs a
  device/emulator farm and is a separate, larger build.
- **Cloud config, Active Directory, IoT/firmware, source code (SAST)**: not covered.
  Each is its own specialized toolchain; ask if you want one added next — the
  architecture (`app/scanners/*.py` + `app/orchestrator.py`) is built to add a new
  target type as one more scanner module.

## Access control

This is **not public**. Every route requires HTTP Basic Auth against a small local
user list (`data/users.json`, PBKDF2-hashed, never plaintext).

- On first boot, one admin account is seeded automatically — random password if you
  don't set one — and printed to the container logs plus saved to
  `data/INITIAL_CREDENTIALS.txt` (delete that file after you've copied the password out).
- Add more limited accounts:
  ```
  docker compose exec vapt-auditor python -m scripts.manage_users add alice <password>
  docker compose exec vapt-auditor python -m scripts.manage_users list
  docker compose exec vapt-auditor python -m scripts.manage_users remove alice
  ```
- The `docker-compose.yml` binds the port to `127.0.0.1` only, on purpose — reachable
  from the host but not the open internet. If your team needs remote access, put it
  behind your existing internal nginx (with TLS) or a VPN, not a public port mapping.

## Deploying to your private cloud

Prereqs: Docker + Docker Compose on the target host.

```bash
git clone <this repo>   # or scp the directory over
cd vapt-auditor
cp .env.example .env
# edit .env: optionally set VAPT_ADMIN_USER / VAPT_ADMIN_PASSWORD,
# and WPSCAN_API_TOKEN (free at https://wpscan.com/api) for CVE-level WordPress results
docker compose up -d --build
docker compose logs -f vapt-auditor   # first boot prints the admin password here
```

Then open `http://<host>:8000` from a machine that can reach `127.0.0.1` on that
host (SSH tunnel, internal network, or your reverse proxy).

First image build takes a while — it installs Nmap, Nikto, Ruby+WPScan, testssl.sh,
and downloads the full Nuclei template set (~thousands of templates) so the first
real scan isn't slow.

## Using it

1. Log in, pick a target type, enter the target (or upload an APK), check the
   authorization box, submit.
2. The scan runs in the background; the job page auto-refreshes until it's done.
3. Download the HTML or PDF report from the job page. Reports are also kept under
   `data/reports/<job-id>.{html,pdf}` on disk.

## Local development

```bash
python3.11 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Note: Nmap/Nikto/Nuclei/testssl.sh/WPScan aren't installed by `pip` — without them
on your dev machine, those scanners will report "not installed" per tool (the job
still completes and the report still generates; see `tests/test_report_pipeline.py`
for a fixture-based smoke test that doesn't depend on any of them). Install them
locally via Homebrew if you want to exercise a real scan outside Docker:
`brew install nmap nikto`.

## Architecture

```
app/
  models.py          Finding / ScanJob / Target schema shared by every module
  orchestrator.py     routes a target to the right scanner(s), aggregates findings
  scanners/           one module per tool family; each returns (findings, tool_run)
    network.py         nmap
    web.py              nuclei + nikto
    tls.py              testssl.sh
    wordpress.py        wpscan
    mobile.py           androguard static analysis
  report/
    generate.py         renders Jinja2 HTML, and PDF via WeasyPrint
    templates/report.html.j2
  auth.py              seeded admin + PBKDF2 user store, HTTP Basic Auth
  storage.py           JSON-file-per-job persistence (no DB needed at this scale)
  main.py              FastAPI app: web UI + scan submission + report download
scripts/manage_users.py  add/remove/list accounts
```

Adding a new target type = one new file in `app/scanners/`, one new
`TargetType` enum value, one branch in `orchestrator.py`.
