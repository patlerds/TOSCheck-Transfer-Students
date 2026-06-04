# TOSCheck: A Legal Document Analyzer

**PIC16B Honors Contract Submission, Patrick Lerdsuwanrut**

---

## What I Built
Video Demo: https://drive.google.com/file/d/15O32IGxO8A7LwaAqPzCODJBWYZv25gv_/view?usp=sharing

Legal documents are long, dense, and written to protect the organization that issued them,
not the person reading them. Most people skip them entirely. TOSCheck reads them instead.

TOSCheck is a Python web application built with Flask and Google Gemini. You feed it a
document (URL, file upload, or pasted HTML) and it returns a structured breakdown:
what the document covers, what rights you give up, what data is collected, how disputes are
handled, and more. Every extracted field includes a verbatim quote from the original
document so you can verify it yourself.

The original project was forked from a repository by Nishanth. I took over at v2.0 and
built everything described in this document from that point onward.

---

## The Product

TOSCheck has five pages:

- **Main analyzer** (`/`): URL input, HTML paste, or file upload; runs Comprehensive Analysis or Eligibility Check
- **Batch upload** (`/batch`): drop up to 20 files at once
- **Search** (`/search`): search cached results by title, URL, or company name
- **About** (`/about`): project background
- **Changelog** (`/changelog`): version history

### Two Analysis Modes

**Comprehensive Analysis** returns 16 structured fields: product scope, key concerns, data
protections, IP rights, termination clauses, dispute resolution, and 10 standard TOS concern
checks (arbitration, warranty disclaimers, liability caps, etc.). Every field includes a
verbatim citation from the document.

**Eligibility Check** is a targeted scan of organization bylaws for tenure requirements and
transfer student barriers. It returns severity ratings (Mild, Moderate, or Severe) with
citations for each finding.

### Demo: Analyzing Three Document Types

The app accepts PDF, DOCX, and TXT uploads through a single endpoint. Here is the extraction
logic that handles all three:

```python
ext = os.path.splitext(filename.lower())[1]

if ext == '.pdf':
    with pdfplumber.open(io.BytesIO(file_bytes)) as pdf:
        pages_text = [page.extract_text() or "" for page in pdf.pages]
    pdf_text = "\n\n".join(pages_text).strip()

elif ext == '.txt':
    pdf_text = file_bytes.decode('utf-8', errors='replace').strip()

elif ext == '.docx':
    doc = python_docx.Document(io.BytesIO(file_bytes))
    pdf_text = "\n".join(p.text for p in doc.paragraphs if p.text.strip())
```

Each branch extracts plain text, which then flows into the same analysis pipeline regardless
of the source format. Below are real results from three sample organization bylaws, pulled
directly from the app's cache.

---

**TXT: Open Horizons Service Club** (`open_horizons_service_club.txt`)

> *Inclusive student club prioritizing community service and equal leadership opportunities.*

| Field | Result |
|---|---|
| Transfer student impact | No barriers; transfer students receive full membership and voting rights immediately |
| Leadership eligibility | All members regardless of seniority may run for President or any officer role |
| Concerns flagged | None |

Key points extracted:
- The club maintains an open-door policy with no barriers like auditions or applications.
- Transfer and returning students are granted full membership status immediately upon joining.
- Membership status and voting rights are not dependent on how long a student has been at the university.
- All members, regardless of seniority, are eligible to run for leadership positions.

---

**DOCX: Heritage Honor Society** (`heritage_honor_society.docx`)

> *Society for long-term students preserving university traditions through restricted membership.*

| Field | Result |
|---|---|
| Transfer student impact | Permanently restricted to associate status (no voting rights, no officer eligibility) |
| Leadership eligibility | Reserved for students who enrolled as freshmen and completed four consecutive semesters |
| Concerns flagged | **Severe:** structural exclusion based solely on enrollment origin |

Key points extracted:
- Full membership is limited to students who enrolled as freshmen and completed four consecutive semesters.
- Transfer students and late enrollees are restricted to associate status with no voting or office-holding rights.
- Full membership requires 60 credit hours earned specifically at the university, excluding transfer credits.
- Leadership requires approval and nomination by current officers.

Concerns:
- Transfer students are permanently disenfranchised and cannot participate in the governance of the society.
- The organization enforces a strict seniority rule that excludes qualified students based solely on when they joined.
- There is a high barrier to leadership that depends on the approval and nomination of current officers.

---

**PDF: Riverside Debate Society** (`riverside_debate_society.pdf`)

> *The governing rules for membership and leadership within the society.*

| Field | Result |
|---|---|
| Transfer student impact | Membership granted on the same terms as continuing students |
| Leadership eligibility | Open, but spring joiners must wait until the following year for major roles |
| Concerns flagged | **Mild:** timing restriction and tie-breaking bias toward travel team members |

Key points extracted:
- Membership is inclusive and open to all students without the need for an audition.
- Transfer students are granted membership on the same terms as continuing students.
- Four officer roles established: President, Vice President, Treasurer, and Secretary.

Concerns:
- Students joining in the spring semester must wait until the following year to run for major leadership roles.
- In the event of a tie during elections, members with travel team experience are given priority.

---

## Challenge 1: Inheriting and Extending a Codebase

Taking over a codebase you didn't write means making a judgment call on nearly every file:
keep it, rewrite it, or build on top of it. At v2.0, I had to read through the existing
code and decide what to trust.

The core Flask routing structure and the basic idea of calling Gemini were solid enough to
keep. What I replaced or added from v2.0 onward:

- **No database.** All state lives on the filesystem. Each analysis gets a directory under
  `cache/TOSCheck/{content_hash}/`, containing the raw text, the original HTML, and the
  Gemini result. This was a deliberate choice: it made the system easy to inspect and
  debug without standing up a database, and it means the cache survives a server restart.

- **Background job execution.** Analysis calls can take 10-30 seconds. Running them
  synchronously would block every other request. I added a `ThreadPoolExecutor` with 5
  workers so analysis runs in the background while the client polls for status.

- **Eligibility Check mode.** The original only did generic TOS analysis. I added a second
  analysis mode specifically for scanning organization bylaws for transfer student barriers,
  which was the problem that motivated this fork in the first place.

- **Version gating.** If a cached result is from an older app version, it gets re-analyzed
  automatically. This lets prompt improvements propagate without manual cache cleanup.

Reading someone else's code forces you to slow down and understand the system before
changing it. I rewrote parts I didn't understand or that had grown beyond their original
scope. The parts I kept, I kept deliberately.

---

## Challenge 2: Working with the Gemini API

The Gemini API is not magic. It is an HTTP endpoint that accepts text and returns text.
Getting reliable, structured output out of it required engineering the interface carefully.

### Structured Output

The first version of the integration just asked Gemini to "return JSON." That produced
inconsistent output: sometimes valid JSON, sometimes JSON embedded in a markdown code
block, sometimes something that wasn't JSON at all. The fix was enforcing a strict response
schema by passing a `responseMimeType` and a `responseSchema` in every request. Gemini then
returns only values that match the schema, and parsing becomes trivial.

```python
payload = {
    "contents": [{"parts": [{"text": prompt + document_text}]}],
    "generationConfig": {
        "responseMimeType": "application/json",
        "responseSchema": schema
    }
}
```

### Model Fallback

API availability is not guaranteed. A model can be rate-limited (HTTP 429), unavailable on
a given key (HTTP 404), or temporarily down (5xx). Hardcoding a single model meant the app
failed completely when that model had an issue.

I built a fallback loop that tries each model in order, retrying transient failures with
delays of 2 and 4 seconds before moving to the next model:

```python
GEMINI_MODELS = ["gemini-3-flash-preview", "gemini-2.5-flash"]
RETRY_DELAYS = [2, 4]
TRANSIENT_STATUSES = {429, 500, 502, 503, 504}

for model in GEMINI_MODELS:
    for attempt in range(len(RETRY_DELAYS) + 1):
        if attempt > 0:
            time.sleep(RETRY_DELAYS[attempt - 1])
        response = requests.post(url, json=payload, timeout=300)

        if response.status_code == 404:
            break  # model unavailable, try next
        if response.status_code in TRANSIENT_STATUSES:
            if attempt < len(RETRY_DELAYS):
                continue  # retry same model
            break  # exhausted retries, try next model

        response.raise_for_status()
        return json.loads(
            response.json()["candidates"][0]["content"]["parts"][0]["text"]
        )
```

Working with an AI API is still engineering. The prompt, the schema, the retry logic, and
the error handling all have to be correct before the AI part becomes useful.

---

## Challenge 3: Building Things Manually

Some parts of the app had no library to call. I had to write them from scratch and
understand what they were actually doing.

### SSRF Protection

The app fetches arbitrary URLs submitted by users. Without protection, that is a vector for
Server-Side Request Forgery. An attacker could submit `http://169.254.169.254/` (the AWS
metadata service) and have the server make requests to internal infrastructure on their
behalf.

The fix: before making any outbound request, resolve the hostname to an IP address and
reject it if it falls in a private or reserved range.

```python
ip_addresses = [info[4][0] for info in socket.getaddrinfo(hostname, None)]
for ip_str in ip_addresses:
    ip_addr = ipaddress.ip_address(ip_str)
    for forbidden_range in FORBIDDEN_IP_RANGES:
        if ip_addr in forbidden_range:
            return False  # blocked
```

Writing this made me understand what SSRF actually is, not just that it exists as a
category of vulnerability.

### Content-Hash Caching

Caching by URL fails when the same document is accessible at multiple URLs, and it misses
file uploads entirely. I cache by content hash instead:

```python
# URL submission
url_hash = hashlib.sha256(url.encode()).hexdigest()

# File upload
url_hash = "pdf_" + hashlib.sha256(file_bytes).hexdigest()

# HTML paste
url_hash = "html_" + hashlib.sha256(raw_html.encode()).hexdigest()
```

Identical documents, regardless of how they were submitted, return the cached result
instantly. Cache hits avoid the 10-30 second Gemini call entirely.

### Background Job Polling

A Gemini call can take 10-30 seconds. Flask is synchronous by default. Running the analysis
on the request thread would block all other requests until it finished.

The solution: submit the analysis to a `ThreadPoolExecutor`, return a `job_id` immediately,
and have the client poll `/status/<job_id>` until done. Status updates are written to an
in-memory dictionary as the background task progresses through each stage.

```python
executor = concurrent.futures.ThreadPoolExecutor(max_workers=5)

# On submit:
executor.submit(analyze_document_task, url_hash, url, ...)
return jsonify({"job_id": url_hash, "status": "processing"})

# On poll:
return jsonify(job_statuses.get(url_hash, {"status": "unknown"}))
```

Building these by hand, rather than reaching for a task queue library, meant I had to
understand what each piece was actually doing and why it was necessary.

---

## Reflection

The biggest thing this project taught me is that AI is a tool with an interface, and the
interface has to be engineered like everything else. Writing the prompt, enforcing the
schema, handling rate limits, and building the fallback logic is real software work. The
model itself is just one part of the system.

Working in an inherited codebase taught me to read before I write. Understanding why
something was built the way it was, even when I disagreed with it, made my changes more
deliberate.

If I were starting over, I would separate the file parsing logic from the Flask route
handlers earlier. As the app grew, those functions became harder to test in isolation.

A natural next step would be deploying this on Vercel or a similar platform so it's
accessible without running a local server. The groundwork is already there.
