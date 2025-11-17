# Network Security Scanner & Firewall Visualizer

Prototype project: a simple local network port scanner and firewall rule visualizer.

Features
- FastAPI backend exposing scan and firewall endpoints
- Scanner uses python-nmap if available, falls back to a simple socket-based TCP scanner
- Firewall simulator with priority-based allow/deny rules
- Single-file frontend (`templates/index.html`) with JS that talks to the API and draws a small flow visualization

Assumptions
- This is a student project / prototype. Running full Nmap scans requires `nmap` installed on the host and optionally the `python-nmap` package.
- The fallback scanner is a basic TCP connect scanner and does not perform all features of Nmap (OS detection, versioning, advanced UDP scans).
- Firewall simulator is in-memory and meant for demonstration only.

Requirements
- Python 3.8+
- On Windows, run from PowerShell

Install
1. Create a virtual environment and activate it.

```powershell
python -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Run

```powershell
uvicorn main:app --reload
```

Open http://127.0.0.1:8000 in your browser.

Notes & next steps
- Add UDP scanning improvements (requires raw sockets / elevated privileges)
- Persist firewall rules, add authentication, and more advanced visualizations (e.g., D3)
- Add unit tests and CI
