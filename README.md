# TOSCheck: Legal Document Analyzer

Analyze Terms of Service, Privacy Policies, and organization bylaws with AI. Paste a URL, upload a PDF, or drop in raw HTML — TOSCheck sends it to Google Gemini and returns structured, citation-backed JSON.

---

## What It Does

Three ways to feed a document in:
1. **URL** — App fetches and parses the page
2. **PDF upload** — Text extracted with pdfplumber
3. **Raw HTML paste** — Parsed locally, no network call

Two analysis modes:
- **Comprehensive Analysis** — 16 structured fields: product scope, key concerns, data protections, IP rights, termination clauses, dispute resolution, and 10 standard TOS concern checks (arbitration, warranty disclaimers, liability caps, etc.). Every field includes a verbatim citation.
- **Eligibility Check** — Targeted scan of organization bylaws for tenure requirements and transfer student barriers. Returns severity ratings (Mild / Moderate / Severe) with citations.

Results are cached by content hash. Identical documents return instantly on re-analysis.

---

## Tech Stack

| Layer | What |
|-------|------|
| Backend | Flask (Python) |
| Frontend | Vanilla JS + Tailwind CSS (CDN) + Marked.js |
| LLM | Google Gemini API |
| PDF parsing | pdfplumber |
| HTML parsing | BeautifulSoup4 |
| Async jobs | Python `ThreadPoolExecutor` (5 workers) |

---

## Folder Structure

```
TOSCheck/
├── app.py                  Main Flask app
├── requirements.txt        Python dependencies
├── version.txt             Version schema reference
├── tos.wsgi                Gunicorn/WSGI entry point
├── pullcache.py            Utility: regenerate contracts.json from cache
│
├── templates/
│   ├── index.html          Main analyzer page
│   ├── batch.html          Batch PDF upload (up to 20 files)
│   ├── search.html         Search cached results
│   ├── about.html          About page
│   └── changelog.html      Version history
│
└── cache/TOSCheck/         Cache root (gitignored)
    ├── contracts.json       Metadata log of all analyses
    └── {content_hash}/
        ├── analysis.json    Full Gemini result + metadata
        ├── raw.txt          Preprocessed text sent to LLM
        ├── html.txt         Original HTML (if URL-scraped)
        └── eligibility.json Eligibility result (if requested)
```

---

## Setup

### Prerequisites
- Python 3.8+
- Google Gemini API key — get one free at https://aistudio.google.com/api-keys

### Install

```bash
git clone <repo>
cd TOSCheck
pip install -r requirements.txt
```

### Configure API key

Create a `.env` file in the project root:
```
GEMINI_API_KEY=your_key_here
```

> ⚠️ `.env` is gitignored. Never commit it. Use environment variables in production.

### Run locally

```bash
python app.py
```

Server starts at `http://127.0.0.1:5000`

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
| `/analyze` | POST | `{ "url": "...", "eligibility_only": false }` | `{ "job_id": "...", "status": "processing" }` |
| `/analyze/pdf` | POST | Multipart `pdf_file` field | `{ "job_id": "..." }` or `{ "filename_conflict": true, ... }` |
| `/analyze/eligibility/<job_id>` | POST | — | Eligibility result JSON |
| `/status/<job_id>` | GET | — | `{ "status": "...", "progress": 0–100 }` |
| `/result/<job_id>` | GET | — | Full `analysis.json` |

### Cache / History

| Route | Method | Description |
|-------|--------|-------------|
| `/cache/<job_id>` | DELETE | Delete a cached result |
| `/recent_analyses` | GET | 5 most recent successful analyses |
| `/pdf_analyses` | GET | All successfully cached PDFs |
| `/search_cached` | GET | Search by URL, title, or company |
| `/version` | GET | `{ "version": "..." }` |

---

## Data Flow

```
User Input (URL | PDF | HTML)
       ↓
  Fetch & parse → plain text
  (URL: SSRF-checked before request)
       ↓
  sha256(content) → cache lookup
       ↓
  Cache hit → return analysis.json immediately
  Cache miss → submit background task
       ↓
  [Background] Send text to Gemini with JSON schema
       ↓
  Save: analysis.json + raw.txt + html.txt
       ↓
  Client polls /status → fetches /result when done
```

---

## Caching & Versioning

**Cache keys:**
- URL → `sha256(url)`
- HTML paste → `sha256(html)` (prefix: `html_`)
- PDF → `sha256(pdf_bytes)` (prefix: `pdf_`)

**Version gating:** If a cached result is from an older app version, it's automatically re-analyzed. This propagates prompt improvements without manual cleanup.

**Version scheme:** `X.Y.Z[.x]`
- `X` — Major rewrite
- `Y` — New feature
- `Z` — Bug fix / patch
- `.x` suffix — Experimental / untested feature

---

## SSRF Protection

Before scraping any URL, the app resolves the hostname and rejects:
- Private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8)
- Link-local and loopback (169.254.0.0/16, ::1, fe80::/10)
- Cloud metadata service (169.254.169.254)
- Hardcoded bad hostnames (localhost, 0.0.0.0)

HTML paste and PDF upload skip this check (no outbound network call).

---

## Gemini Model Fallback

Models are tried in order on 429 (rate limited) or 404 (model unavailable):
1. `gemini-3-flash-preview` (primary)
2. `gemini-2.5-flash` (fallback)

Each model gets up to 3 attempts with delays of 2s and 4s before moving to the next.

---

## Known Issues & Limitations

| Issue | Status |
|-------|--------|
| JS-heavy pages may fail to scrape (no browser renderer) | No fix planned; paste raw HTML as workaround |
| Job status lost on server restart | In-memory only; no persistent queue |
| No per-user rate limiting | Any client can exhaust Gemini quota |
| Cache grows unbounded | No TTL or eviction policy |
| PDF dedup by filename only — different content with same filename triggers conflict dialog but user may not know content differs | UX limitation; conflict dialog gives choice |

---

## Troubleshooting

**"Failed to extract main text content"**
URL was reachable but content couldn't be parsed. Try pasting raw HTML instead of a URL.

**"Document title does not appear to be a legal policy"**
The page `<title>` doesn't match legal keywords. Either the URL points to the wrong page, or try pasting raw HTML.

**"Provided URL is not allowed. Potential security risk."**
URL resolves to a private or reserved IP (SSRF protection). Only public URLs are accepted.

**Cache growing too large**
No auto-cleanup exists. Delete via the UI (trash icon), via `DELETE /cache/<job_id>`, or manually at `cache/TOSCheck/`.

---

## Future Improvements

- Persistent job queue (Celery + Redis) so jobs survive server restart
- Cache TTL / disk quota enforcement
- Per-user rate limiting
- Move hardcoded prompts to config files
- Structured logging (replace print statements)
- DOCX / TXT input support
