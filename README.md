# Air-Gapped Security Remediator — Day 1 starter

This is a local learning prototype. It scans only the bundled `sample_app/` directory with Bandit, then optionally asks a local Ollama model to explain the findings.

## Safety boundaries

- The FastAPI server binds to `127.0.0.1` only.
- `/scan` and `/analyze` scan only the bundled demo directory; they do not accept arbitrary filesystem paths.
- Ollama is called at `http://127.0.0.1:11434` by default.
- The AI response is advice, not proof that a fix is correct. The starter defaults to the smaller `qwen2.5-coder:3b` model for easier local setup; you can switch to a larger model if your Mac has enough memory.
- Do not use this prototype with company source code or claim it is production-ready.
- Installing packages and downloading the model require network access. Air-gapped operation must be validated later with networking disabled and all dependencies already staged.

## Setup (macOS)

1. Install Ollama from https://ollama.com/download and open it.
2. In Terminal, from this project folder:

```bash
python3 --version
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
ollama pull qwen2.5-coder:3b
ollama list
```

3. Start the API in Terminal window 1:

```bash
source .venv/bin/activate
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

4. In Terminal window 2, check health and scanner findings:

```bash
curl -s http://127.0.0.1:8000/health
curl -s http://127.0.0.1:8000/scan
```

5. Ask the local model to explain the scanner-backed findings:

```bash
curl -s -X POST http://127.0.0.1:8000/analyze
```

You can also open http://127.0.0.1:8000/docs in your browser to use the local API UI.

## Expected result

Bandit should flag the `eval()` call in `sample_app/vulnerable.py` (commonly rule B307). The exact output depends on scanner version. `/analyze` returns the scanner report and a local model explanation.

## Day 1 limitations

This version does not edit files, create patches, open pull requests, scan arbitrary repositories, or verify remediation. Those are later milestones. The API has no authentication and is intended for localhost-only development.
