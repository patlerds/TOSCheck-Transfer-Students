# Web Deployment Plan

## Project

**Working name:** TOSCheck Transfer Student Bylaw Analyzer  
**Submission audience:** UCLA Transfer Center  
**Primary purpose:** Provide a web-based tool that helps identify whether student organization bylaws, constitutions, or related membership documents contain rules that may create barriers for transfer students or other late-entry students.

The tool should be presented as an organizational accessibility and transparency auditing tool. It is not a legal decision-maker, discrimination finding tool, or public ranking system. Its value is in helping staff and student leaders find evidence-backed policy language that may deserve review.

## Deployment Goals

- Make the analyzer available through a stable web URL for Transfer Center review and pilot use.
- Support URL analysis, PDF/DOCX/TXT upload, pasted text, pasted HTML, and batch uploads.
- Return structured, citation-backed findings so staff can verify every result against the source document.
- Provide a targeted Transfer Eligibility Check for tenure requirements and transfer student barriers.
- Keep the deployment low-risk, private, and easy to operate during the pilot phase.

## Recommended Deployment Model

### Phase 1: Private Pilot

Deploy the app behind restricted access for UCLA Transfer Center staff and selected reviewers.

Recommended access controls:

- Password-protected site, UCLA SSO, VPN, or another UCLA-approved access gate.
- No public search indexing.
- No public publishing of organization-level findings.
- Small reviewer group during initial validation.

### Phase 2: Staff-Facing Internal Tool

After pilot validation, expand access to approved UCLA staff and designated student governance partners.

Recommended usage:

- Internal review of bylaws and constitutions.
- Preparation of evidence-linked summaries for staff conversations.
- Support for student organization accessibility improvement, not punitive enforcement.

### Phase 3: Optional Broader Release

Only after privacy, accessibility, security, and governance review, consider a broader public or semi-public version.

Additional requirements before broader release:

- Authentication and user roles.
- Rate limiting.
- Cache retention policy.
- Abuse monitoring.
- Clear disclaimers and appeal/correction workflow.

## Hosting Options

### Preferred: UCLA-Managed Hosting

Best fit if UCLA wants direct control over data, access, logs, and institutional review.

Possible environment:

- Linux VM or container service.
- Python 3.10+ runtime.
- Gunicorn or another WSGI server.
- Nginx or equivalent reverse proxy.
- HTTPS via UCLA-managed certificate.
- Environment variables managed outside the repository.

### Alternative: Approved Cloud Hosting

If UCLA prefers a vendor-hosted deployment, use an approved hosting provider with:

- HTTPS by default.
- Secret management for API keys.
- Persistent disk for cache, or managed database/object storage.
- Access controls.
- Basic monitoring and log retention.

The deployment should not use free-tier public demos for official review unless UCLA confirms that the data handling model is acceptable.

## Runtime Architecture

Current application architecture:

```text
Browser
  -> Flask web app
  -> document extraction
  -> Gemini API request
  -> structured JSON result
  -> filesystem cache
  -> browser result display
```

Core components:

- Flask backend in `app.py`.
- Vanilla JavaScript and Tailwind templates in `templates/`.
- Gemini API for structured analysis.
- Filesystem cache under `cache/TOSCheck/`.
- Background work through Python `ThreadPoolExecutor`.

Production command shape:

```bash
gunicorn -w 4 -b 127.0.0.1:5000 tos:application
```

The app should sit behind a reverse proxy that terminates HTTPS and forwards requests to Gunicorn.

## Environment Configuration

Required environment variables:

| Variable | Purpose |
|----------|---------|
| `GEMINI_API_KEY` | API key for Google Gemini analysis |

Recommended environment variables to add before production:

| Variable | Purpose |
|----------|---------|
| `FLASK_ENV=production` | Avoid development behavior |
| `CACHE_DIR` | Move cache path outside the app source tree |
| `ALLOWED_ORIGINS` | Restrict browser origins |
| `APP_ACCESS_MODE` | Track whether deployment is pilot, internal, or public |

Secrets must not be committed to Git. API keys should be stored in UCLA-approved secret management or host-level environment variables.

## Data Handling And Privacy

### Data Processed

The app processes:

- Public URLs submitted by users.
- Uploaded PDF, DOCX, or TXT files.
- Pasted plain text or HTML.
- Generated analysis results.
- Direct citations from source documents.

The intended documents are student organization bylaws, constitutions, membership policies, recruitment materials, and similar governance documents. Users should be instructed not to submit student records, private advising notes, protected personal information, or confidential institutional documents unless UCLA has explicitly approved that use.

### Cache Behavior

Current behavior:

- Results are cached by content hash.
- Cached entries may include extracted raw text, source HTML, generated JSON analysis, and metadata.
- Cache persists on disk until manually deleted.

Required before production:

- Define cache retention period.
- Add scheduled cache cleanup or administrator cleanup process.
- Decide whether raw extracted text should be retained, encrypted, shortened, or deleted after analysis.
- Restrict cache deletion and cache browsing to authorized users.

### Third-Party Processing

The current app sends document text to the Gemini API for analysis. Before UCLA production use:

- Confirm that the chosen Gemini/API configuration is approved for the document types being processed.
- Confirm retention, logging, and data-use terms for the API provider.
- Avoid submitting documents that include protected student information unless UCLA privacy/security review approves it.

## Security Controls

Already present:

- SSRF checks block private IP ranges, localhost, loopback, link-local addresses, and common cloud metadata endpoints for URL scraping.
- File uploads are limited by type and size.
- Results are citation-backed so users can verify claims.

Required before pilot:

- HTTPS only.
- Restrict access to approved reviewers.
- Store API keys outside source control.
- Disable debug mode in production.
- Ensure cache directory is not web-served directly.
- Add a visible usage disclaimer.

Required before broader release:

- Authentication and authorization.
- Per-user or per-IP rate limiting.
- Authenticated cache deletion.
- Request size limits at the reverse proxy.
- Logging that avoids storing full submitted document text in application logs.
- Basic abuse monitoring.

## Accessibility And Usability

The web interface should be reviewed for:

- Keyboard navigation.
- Color contrast in light and dark mode.
- Screen-reader labels for buttons, toggles, and file inputs.
- Clear error messages.
- Plain-language disclaimers.
- Mobile and desktop layout.

Minimum pilot acceptance:

- Text remains readable in dark mode.
- All main workflows can be completed with keyboard and mouse.
- Uploaded documents and pasted text produce clear success or error states.
- Results include direct citations and do not rely on color alone to convey severity.

## Testing Plan

### Functional Tests

- Submit a public bylaw URL.
- Upload PDF, DOCX, and TXT samples.
- Paste raw text.
- Paste raw HTML.
- Run Transfer Eligibility Only.
- Run full analysis plus Transfer Eligibility Check.
- Batch upload multiple files.
- Load a previous result from History.
- Delete a cached result.

### Content Validation

Use a small UCLA-reviewed sample set:

- Transfer-friendly bylaws.
- Neutral bylaws.
- Bylaws with minimum-semester leadership requirements.
- Bylaws with freshman-only or early-entry pipelines.
- Bylaws with ambiguous membership or leadership language.

For each sample, reviewers should check:

- Whether the cited rule exists in the source.
- Whether the explanation is faithful to the citation.
- Whether severity labels are reasonable.
- Whether the output avoids unsupported accusations.

### Security/Operational Tests

- Confirm private IP and localhost URLs are blocked.
- Confirm unsupported file types are rejected.
- Confirm large files are rejected.
- Confirm cache is not directly browsable.
- Confirm API key is not exposed to the browser.
- Confirm server restart behavior is acceptable for pilot use.

## Rollout Timeline

### Week 1: Deployment Preparation

- Select hosting environment.
- Configure HTTPS.
- Configure API key through environment variables.
- Create protected pilot URL.
- Add or confirm usage disclaimer.
- Prepare sample document set.

### Week 2: Internal Technical Validation

- Run functional tests.
- Run SSRF and file upload checks.
- Confirm dark-mode/readability audit.
- Confirm cache location and deletion process.
- Document known limitations for reviewers.

### Weeks 3-4: Transfer Center Pilot

- Invite a small reviewer group.
- Analyze sample bylaws and selected real documents.
- Collect feedback on usefulness, false positives, unclear wording, and missing categories.
- Review whether results are appropriate for staff-facing use.

### Week 5: Pilot Review

- Summarize findings.
- Decide whether to continue, revise, or pause.
- Prioritize production hardening items.
- Prepare a revised deployment plan if broader access is requested.

## Maintenance Plan

Operational owner responsibilities:

- Keep dependencies updated.
- Rotate API keys if needed.
- Review logs for errors and abuse patterns.
- Monitor API usage and cost.
- Clear or expire cache according to UCLA-approved retention rules.
- Track prompt/schema changes through app versioning.

Recommended cadence:

- Weekly review during pilot.
- Monthly review after stable internal launch.
- Immediate review after any incident involving incorrect access, exposed cache, API key exposure, or unexpected data retention.

## Known Limitations

- The app uses AI analysis and may produce false positives or miss policy barriers.
- Results should be reviewed by a human before any action is taken.
- Current cache deletion is unauthenticated and should be protected before production.
- Current cache grows indefinitely without a TTL or quota.
- Current job status is in memory and can be lost on restart, though cached results can still be retrieved.
- JavaScript-heavy websites may not scrape correctly; paste text or upload files as a workaround.
- The current app is a single Flask file and should be modularized for long-term maintainability.

## Success Criteria

Pilot deployment is successful if:

- UCLA Transfer Center reviewers can access the site reliably.
- Reviewers can submit documents without developer assistance.
- Results provide useful, citation-backed evidence.
- The tool helps identify policy language that may affect transfer or late-entry student participation.
- Reviewers understand that the output is advisory and requires human review.
- No sensitive information is exposed through the browser, logs, cache, or repository.

## Submission Summary

This deployment is best framed as a limited, staff-facing pilot for organizational accessibility review. The tool can help UCLA Transfer Center staff identify bylaw language that may disadvantage transfer students, but it should remain evidence-linked, private, and human-reviewed. A broader launch should wait until UCLA has reviewed authentication, data retention, API provider terms, accessibility, and security controls.
