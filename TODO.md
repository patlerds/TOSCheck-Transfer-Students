# TODO

## Product Suggestions Worth Adding

These came from the `suggestions.md` audit. Completed portions stayed struck through there; the remaining items below are still worth adding.

### High Priority

- [ ] Broaden late-entry equity analysis beyond the current transfer/tenure check.
  - Detect freshman-year assumptions, pipeline locking, fall-only recruitment, and leadership timing barriers.
  - Add "realistic late-entry participation" and "realistic late-entry leadership" outputs.
  - Cover major changers, commuters, and re-entry students in addition to transfer students.
- [ ] Add a Transfer Inclusivity Audit.
  - Distinguish passive openness from active integration.
  - Consider a scale such as Hostile, Neutral, Friendly, Inclusive, and Empowering.
- [ ] Add joining accessibility / ease-of-entry analysis.
  - Detect auditions, applications, hidden prerequisites, drop-in participation, onboarding clarity, and beginner accessibility.
  - Answer whether a student can realistically start participating.
- [ ] Expand leadership accessibility analysis.
  - Current coverage catches time/tenure requirements.
  - Add prior board membership requirements, nomination dependencies, internal referrals, attendance thresholds, and legacy progression pipelines.
- [ ] Add a transparency score.
  - Check whether recruitment windows, time commitment, dues, eligibility, leadership pathways, audition requirements, and attendance expectations are clearly disclosed.

### Medium Priority

- [ ] Add hidden exclusivity signal flags.
  - Flag phrases like "family culture", "must demonstrate commitment", "selected internally", "active member in good standing", "board discretion", and "cultural fit".
  - Present these as evidence-linked ambiguity/gatekeeping risks, not accusations.
- [ ] Add exception justification detection.
  - Separate legitimate operational selectivity from unnecessary exclusion.
  - Example: auditions for a dance team may be reasonable, but freshman-only leadership pipelines are likely not.
- [ ] Add beginner accessibility analysis.
  - Detect prior-experience expectations, training availability, mentorship, novice pathways, and open workshops.
- [ ] Add combined cross-document organization analysis.
  - Batch upload currently analyzes files independently.
  - Combine bylaws, onboarding docs, FAQs, recruitment posts, and application forms into one organization-level audit.

### Lower Priority

- [ ] Add an organizational complexity / bureaucracy score.
  - Look for excessive rules, opaque governance, internal jargon, overformalization, newcomer friction, and institutional opacity.
- [ ] Tighten product positioning around "organizational accessibility and transparency auditing" rather than discrimination detection.

## Known Issues & Technical Debt

Moved from `README.md`.

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

## Future Improvements

Moved from `README.md`.

- [ ] Persistent job queue (Celery + Redis) so jobs survive server restart
- [ ] Cache TTL / disk quota enforcement
- [ ] Per-user rate limiting
- [ ] Authentication on cache deletion
- [ ] Break `app.py` into modules (routes, extractors, llm, cache)
- [ ] Move hardcoded prompts and JSON schemas to config files
- [ ] Structured logging (replace print statements)
- [ ] JavaScript rendering (Playwright) for SPA-based legal pages
- [ ] SQLite or PostgreSQL to replace filesystem cache at scale
- [ ] Support additional upload filetypes beyond the current URL / pasted text / PDF / DOCX / TXT (e.g. RTF, ODT, Markdown, EPUB, and image-based scans via OCR). Sample club constitutions for manual testing live in `sample_const/` (a transfer-friendly `.txt`, a mixed `.pdf`, and an anti-transfer `.docx`).
