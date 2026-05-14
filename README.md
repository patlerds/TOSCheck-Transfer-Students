# TOSCheck: Legal Document Analyzer

Analyze Terms of Service, Privacy Policies, and organization bylaws with AI. Paste a URL, upload a file, paste raw text, or drop in raw HTML — TOSCheck sends it to Google Gemini and returns structured, citation-backed JSON.

---

## What Problem It Solves

Legal documents are long, dense, and written to protect the company — not the reader. Most people skip them entirely. TOSCheck reads them for you and surfaces:

- What the document actually covers
- What rights you give up
- What data is collected and how it's used
- Termination and liability clauses
- Dispute resolution and arbitration requirements
- For organization bylaws: whether transfer students or late joiners are structurally excluded from leadership

Every extracted field includes a direct quote from the original document so you can verify it yourself.

---

## What It Does

Four ways to feed a document in:
1. **URL** — App fetches and parses the page (SSRF-protected)
2. **PDF, DOCX, or TXT upload** — Text extracted automatically; upload on the batch page
3. **Raw HTML or plain text paste** — Paste directly into the main page; no network call
4. **Batch upload** — Drop up to 20 files at once on the `/batch` page

Two analysis modes:
- **Comprehensive Analysis** — 16 structured fields: product scope, key concerns, data protections, IP rights, termination clauses, dispute resolution, and 10 standard TOS concern checks (arbitration, warranty disclaimers, liability caps, etc.). Every field includes a verbatim citation.
- **Eligibility Check** — Targeted scan of organization bylaws for tenure requirements and transfer student barriers. Returns severity ratings (Mild / Moderate / Severe) with citations.

Results are cached by content hash. Identical documents return instantly on re-analysis.

---

## Architecture Overview

```
Browser (Vanilla JS + Tailwind + Marked.js)
    ↓ HTTP
Flask App (app.py)
    ├─ Routes → validate input, check cache, queue job
    ├─ ThreadPoolExecutor (5 workers) → run analysis in background
    │    ├─ Extract text (URL scrape / PDF / DOCX / TXT / HTML paste)
    │    ├─ Validate content (size, title keywords)
    │    ├─ Call Gemini API with JSON schema
    │    └─ Write results to cache directory
    └─ Filesystem cache (./cache/TOSCheck/)
         └─ {content_hash}/ → analysis.json, raw.txt, html.txt
    ↓
Google Gemini API (LLM with structured JSON output)
```

No database. All state is on disk. Job status is in-memory (lost on restart, mitigated by cache fallback).

---

## Tech Stack

| Layer | What |
|-------|------|
| Backend | Flask (Python 3.10+) |
| Frontend | Vanilla JS + Tailwind CSS (CDN) + Marked.js |
| LLM | Google Gemini API |
| PDF parsing | pdfplumber |
| DOCX parsing | python-docx |
| HTML parsing | BeautifulSoup4 |
| Async jobs | Python `ThreadPoolExecutor` (5 workers) |

---

## Folder Structure

```
TOSCheck/
├── app.py                  Main Flask app (~1,600 lines)
├── requirements.txt        Python dependencies
├── version.txt             Version schema reference
├── tos.wsgi                Gunicorn/WSGI entry point
├── pullcache.py            Utility: regenerate contracts.json from cache
│
├── templates/
│   ├── index.html          Main analyzer page (URL + paste)
│   ├── batch.html          Batch file upload (PDF, DOCX, TXT — up to 20 files)
│   ├── search.html         Search cached results
│   ├── about.html          About page
│   └── changelog.html      Version history
│
└── cache/TOSCheck/         Cache root (gitignored)
    ├── contracts.json       Metadata log of all analyses
    └── {content_hash}/
        ├── analysis.json    Full Gemini result + metadata
        ├── raw.txt          Preprocessed text sent to LLM
        ├── html.txt         Original HTML (empty for file uploads)
        └── eligibility.json Eligibility result (if requested)
```

---

## Data Flow

```
User Input (URL | PDF | DOCX | TXT | HTML paste | plain text paste)
       ↓
  Fetch & parse → plain text
  (URL: SSRF-checked before request)
       ↓
  sha256(content) → cache lookup
       ↓
  Cache hit → return analysis.json immediately
  Cache miss → submit background task
       ↓
  [Background] Validate size + title → send to Gemini with JSON schema
       ↓
  Save: analysis.json + raw.txt + html.txt
       ↓
  Client polls /status → fetches /result when done
```

---

## Setup

### Prerequisites
- Python 3.10+
- Google Gemini API key — get one free at https://aistudio.google.com/api-keys

### Install

```bash
git clone <repo>
cd TOSCheck
```

Create and activate a virtual environment:

**Windows (PowerShell)**
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

**Mac / Linux**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

Your prompt will show `(.venv)` when the environment is active. Then install dependencies:

```bash
pip install -r requirements.txt
```

> The `.venv` folder is gitignored — run the above steps once after cloning.

### Configure API key

Create a `.env` file in the project root:
```
GEMINI_API_KEY=your_key_here
```

> ⚠️ `.env` is gitignored. Never commit it. Use environment variables in production.

### Run locally

Make sure `.venv` is active (see above), then:

```bash
python app.py
```

Server starts at `http://127.0.0.1:5000`

---

## Development Workflow

### Test a URL

```bash
# Submit
curl -X POST http://localhost:5000/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com/privacy-policy"}'
# → { "job_id": "abc123", "status": "processing" }

# Poll
curl http://localhost:5000/status/abc123
# → { "status": "completed", "progress": 100 }

# Fetch
curl http://localhost:5000/result/abc123
```

### Test a file upload

```bash
curl -X POST http://localhost:5000/analyze/pdf \
  -F "pdf_file=@terms.pdf"
```

### Search cached results

```bash
curl "http://localhost:5000/search_cached?query=openai"
```

### View recent analyses

```bash
curl http://localhost:5000/recent_analyses
```

---

## Production Deployment

```bash
export GEMINI_API_KEY="your_key_here"
gunicorn -w 4 -b 0.0.0.0:5000 tos:application
```

See `tos.wsgi` for the WSGI entry point.

---

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `GEMINI_API_KEY` | Yes | API key from https://aistudio.google.com/api-keys |
| `__api_key__` | No | Alternative key var injected by Canvas/hosted platforms |

---

## API Reference

### Analysis

| Route | Method | Body | Returns |
|-------|--------|------|---------|
| `/analyze` | POST | `{ "url": "...", "raw_html_input": "...", "eligibility_only": false }` | `{ "job_id": "...", "status": "processing" }` |
| `/analyze/pdf` | POST | Multipart `pdf_file` field (PDF, DOCX, or TXT) | `{ "job_id": "..." }` or `{ "filename_conflict": true, ... }` |
| `/analyze/eligibility/<job_id>` | POST | — | Eligibility result JSON |
| `/status/<job_id>` | GET | — | `{ "status": "...", "progress": 0–100 }` |
| `/result/<job_id>` | GET | — | Full `analysis.json` |

### Cache / History

| Route | Method | Description |
|-------|--------|-------------|
| `/cache/<job_id>` | DELETE | Delete a cached result (unauthenticated) |
| `/recent_analyses` | GET | 5 most recent successful analyses |
| `/pdf_analyses` | GET | All successfully cached file uploads |
| `/search_cached` | GET | Search by URL, title, or company |
| `/version` | GET | `{ "version": "..." }` |

---

## Caching & Versioning

**Cache keys:**
- URL → `sha256(url)`
- HTML/text paste → `sha256(html)` (prefix: `html_`)
- PDF/DOCX/TXT → `sha256(file_bytes)` (prefix: `pdf_`)

**Version gating:** If a cached result is from an older app version, it's automatically re-analyzed. This propagates prompt improvements without manual cleanup.

**Version scheme:** `X.Y.Z[.x]`
- `X` — Major rewrite
- `Y` — New feature
- `Z` — Bug fix / patch
- `.x` suffix — Experimental / untested

---

## SSRF Protection

Before scraping any URL, the app resolves the hostname and rejects:
- Private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8)
- Link-local and loopback (169.254.0.0/16, ::1, fe80::/10)
- Cloud metadata service (169.254.169.254)
- Hardcoded bad hostnames (localhost, 0.0.0.0)

HTML paste, plain text paste, and file upload skip this check (no outbound network call).

---

## Gemini Model Fallback

Models are tried in order on 429 (rate limited) or 404 (model unavailable):
1. `gemini-3-flash-preview` (primary — update in `app.py` if unavailable on your key)
2. `gemini-2.5-flash` (fallback — confirmed working)

Each model gets up to 3 attempts with delays of 2s and 4s before moving to the next.

To find available model IDs for your API key: Google AI Studio → left sidebar → hover model name → copy API name.

---

## Known Issues & Technical Debt

| Issue | Status |
|-------|--------|
| JS-heavy pages fail to scrape (no browser renderer) | No fix planned; paste raw HTML or text as workaround |
| Job status lost on server restart | In-memory only; falls back to cache files gracefully |
| No per-user rate limiting | Any client can exhaust Gemini quota |
| Cache grows unbounded | No TTL or eviction policy |
| `DELETE /cache/<job_id>` is unauthenticated | Anyone with the job ID can delete a cached result |
| `contracts.json` has no deduplication | Same URL analyzed twice creates duplicate metadata entries |
| All logic in one ~1,600-line `app.py` | Makes testing and navigation hard; needs modularization |
| JSON schemas and prompts are hardcoded inline | Should be extracted to separate config files |

---

## Troubleshooting

**"Failed to extract main text content"**
URL was reachable but content couldn't be parsed. Try pasting the raw HTML or plain text instead.

**"Document title does not appear to be a legal policy"**
The page `<title>` doesn't match legal keywords. Either the URL points to the wrong page, or paste raw HTML directly.

**"Provided URL is not allowed. Potential security risk."**
URL resolves to a private or reserved IP (SSRF protection). Only public URLs are accepted.

**Cache growing too large**
No auto-cleanup exists. Delete via the UI (trash icon), via `DELETE /cache/<job_id>`, or manually from `cache/TOSCheck/`.

---

## Future Improvements

- Persistent job queue (Celery + Redis) so jobs survive server restart
- Cache TTL / disk quota enforcement
- Per-user rate limiting
- Authentication on cache deletion
- Break `app.py` into modules (routes, extractors, llm, cache)
- Move hardcoded prompts and JSON schemas to config files
- Structured logging (replace print statements)
- JavaScript rendering (Playwright) for SPA-based legal pages
- SQLite or PostgreSQL to replace filesystem cache at scale
