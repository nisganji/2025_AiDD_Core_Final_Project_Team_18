AI Assistance Disclosure

Date: 2025-11-06

Summary
- An AI coding assistant (Codex CLI, terminal-based) was used to scan the repository, improve documentation, and perform targeted cleanup. Changes were reviewed in context before being applied.

Tools Used
- Codex CLI agent with local shell access
- ripgrep (rg) for code search and reference checks
- PowerShell for file operations on Windows
- apply_patch for atomic edits to repo files

Scope of AI Assistance
- Repository scanning and static analysis to understand data models, routes, and templates
- Removal of unused files and dead code after reference checks
- Clarification and consolidation of README setup/run instructions; verification of requirements.txt
- Documentation of AI assistance and change rationale (this file)

AI Contributions (This Session)
- Code review: verified data model relationships and feature usage via repository search (e.g., notification writes through notify() in booking/admin flows)
- Cleanup: removed clearly unused files and dead code after reference checks:
  - Deleted src/static/js/theme.js (not referenced by templates)
  - Deleted tmp_app.py (unreferenced duplicate of the app)
  - Removed src/__pycache__/ (runtime artifacts)
  - src/app.py: removed unused top-level MessageForm and require_admin() helper; the inline MessageForm in the messages route remains in use
- Documentation: rewrote README.md to clarify prerequisites, cross-platform setup/run, demo accounts, env vars, and API outline. Confirmed requirements.txt aligns with imports.

Rationale and Impact
- Deletions were conservative and preceded by repository-wide reference checks to avoid breaking runtime. Templates, routes, and active features remain intact.
- README now provides explicit Windows/macOS/Linux instructions and documents CLI tasks (flask db-init, flask make-admin).

Limitations and Notes
- A placeholder path /static/img/1.png is referenced by code but the file is not present; consider adding a small placeholder image.
- No end-to-end server run was executed here; the work relied on static analysis.
- No external network services or third-party APIs were used.

Human Oversight
- Each change was explained and applied incrementally. Maintainers should review diffs for alignment with team conventions.

Files Changed by AI (summary)
- README.md: clarified setup/run instructions and API notes
- requirements.txt: reviewed (no changes needed)
- src/app.py: removed two unused definitions (top-level MessageForm, require_admin())
- src/static/js/theme.js: removed (unused)
- tmp_app.py: removed (unused duplicate)
- src/__pycache__/: removed (runtime artifacts)

How AI Influenced Decisions
- Cleanup choices were guided by code search to ensure a file/class had zero references before removal.
- Documentation choices emphasized reproducibility and minimal setup friction.

Future Suggestions (not applied)
- UI polish: minor accessibility and navigation improvements (e.g., clearer active states, consistent button labels)
- My Bookings: add “Add to Google Calendar” convenience links alongside existing .ics export

Contact
- For questions about these AI-assisted changes, ping the maintainers in the repository discussion.


Prompts Consulted (development log)

Note: The following prompts were consulted during development to shape scope and implementation. In some cases, features were implemented differently or partially based on project constraints; these prompts are included for transparency.

"You are an expert full-stack engineer.

Goal:
Generate a Flask project called 'Campus Resource Hub' that satisfies ALL FINAL ASSIGNMENT RUBRIC REQUIREMENTS for AiDD Core 2025.

TECH STACK:
Flask + SQLAlchemy + Jinja2 + SQLite
bcrypt for password hashing
WTForms or Flask-WTF for forms + CSRF
no external frontend frameworks — pure HTML/CSS/JS

REQUIREMENTS (must all exist):

AUTH & USERS
• signup / login / logout
• hashed passwords
• roles: student / staff / admin
• admin approves accounts
• profile page with notification prefs + theme toggle

RESOURCES
• CRUD for resources
• fields: title, description, category, location, capacity, images (multiple), restriction (open|restricted)
• status: draft → published
• detail page shows images + average rating + reviews
• search by keyword, category, location, capacity, date availability
• sort by recent / most booked / top rated

BOOKINGS
• calendar based booking selector
• conflict detection (no overlapping bookings)
• automatic approval for open resources
• admin approval for restricted resources
• user “My bookings” page with statuses

REVIEWS
• users can review only completed bookings
• rating 0-5 stars + comment
• average rating displayed

MESSAGING
• WhatsApp-style threads
• admin has separate chat thread per user

ADMIN DASHBOARD
• manage users
• manage resources
• manage bookings
• moderate reviews
• usage analytics graph

SECURITY
• CSRF tokens on forms
• XSS protection (escape output)
• input sanitization

PROJECT STRUCTURE
• src/app.py
• src/templates/*.html
• src/static/css/theme.css
• src/static/js/theme.js
• requirements.txt
• README.md with run steps
• tests/test_smoke.py
• .prompt/dev_notes.md (document AI usage)

DELIVERY RULES:
• generate code in small incremental patches — never rewrite whole files unnecessarily
• keep naming consistent
• if you add a DB column, also add migration logic
• for every feature implemented, cite which rubric item it satisfies at top of the diff

Now begin by scaffolding the folder structure + base app.py + requirements.txt.
Wait for my approval before building templates."

"Next patch request:

Implement booking conflict detection + availability time slot filtering.

When user selects a date → show only free time slots.
If slot is taken → it cannot be selected.

Add code for:
• /api/check_slots?resource_id=xx&date=YYYY-MM-DD → returns JSON of available time intervals
• auto reject overlapping bookings at DB level
• reuse existing Booking model → do NOT create new models

Output unified diff only."

"Next patch request:

Upgrade messages to threaded chat like WhatsApp.

Rules:
• one thread per user → admin can open any thread
• messages auto append without refresh (AJAX)
• /api/messages/post → POST {thread_id, text}
• /api/messages/poll → GET → returns new messages since last_ts

Implement JS to poll every 2 seconds.

Output unified diff only."

"Next patch request:

Upgrade resource search page:

Add UI + backend filters for:
• keyword
• category
• location
• capacity
• availability date/time window

Also add SORT dropdown:
• recent
• most booked
• top rated

Important:
reuse existing Resource model fields.

Output unified diff only."

"Next patch request:

Add restriction that only users with COMPLETED bookings may review.

If no completed booking → hide review form.

Display review averages on all lists:
• home page top resources
• browse list
• resource detail

Output unified diff only."

"Next patch request:

Add analytics chart to admin dashboard using Chart.js.

Charts:
• bookings per resource over last 30 days
• average rating per resource

You can create /api/admin/stats endpoints returning JSON:
{labels:[], bookings:[], ratings:[]}

Output unified diff only."

"Next patch request:

Add:
• CSRF tokens to all forms
• escape all Jinja output
• use WTForms validation for all user input
• rate limit login attempts (3 fails → 10 min lock)

Output unified diff only."

"Next patch request:

Add 'Add to Calendar' button to booking detail → generates .ics file downloadable.

Use python-icalendar.
Route:
GET /booking/<id>/export_ical

Output unified diff only."

"Next patch request:

If time slot is full → allow user to join waitlist.

If slot becomes free → next in waitlist promoted → notify user.

Output unified diff only."

Implementation notes regarding prompts above
- Some items were implemented differently than described (e.g., admin analytics prepared server-side in the dashboard route instead of a separate /api/admin/stats endpoint; messages are page-driven without AJAX polling endpoints).
- Calendar export is implemented via an .ics route using the ics library and exposed on bookings.
- Availability filtering and conflict detection are implemented using helper functions and enforced at route-level logic.


Reflection (Appendix C)
Date: 2025-11-11

1) How did AI tools shape your design or coding decisions?
- Used AI to rapidly scaffold the Flask structure (blueprints, forms, models) and to surface security hardening items (global CSRF, Bleach sanitization, login rate limiting, CSP headers).
- Leveraged code search prompts to locate routing, validation, and upload paths quickly; then applied minimal, focused patches rather than broad refactors.
- Let AI propose options; final choices prioritized rubric alignment, testability, and maintainability over feature breadth (e.g., server-rendered messaging vs realtime).

2) What did you learn about verifying and improving AI‑generated outputs?
- Trust but verify: always run targeted tests and static checks. We rejected or revised suggestions that lacked grounding (e.g., raw SQL or unsafe template usage).
- Added server-side date range validation and adjusted forms after tests revealed edge cases; sanitized user content even when Jinja autoescape was present.
- Locked compatibility (SQLAlchemy for Python 3.13) and isolated pytest plugins to avoid environment flakiness when validating changes.

3) What ethical or managerial considerations emerged from using AI in your project?
- Attribution and transparency: documented AI involvement here; human review remained mandatory for all code and docs.
- Safety guardrails: avoided hallucinated content by grounding features in DB facts; minimized PII; enforced CSRF/XSS protections and upload constraints.
- Governance tradeoffs: chose simpler, auditable implementations (ORM-only, no realtime) to reduce risk under time constraints.

4) How might these tools change the role of a business technologist or product manager in the next five years?
- Shift toward specifying outcomes and constraints (prompts, acceptance criteria) and curating AI outputs rather than writing every line.
- Emphasis on verification, risk management, and ethics: PMs/BTs orchestrate guardrails, data grounding, and measurable success metrics.
- Faster iterations: more focus on integration, prioritization, and stakeholder alignment as AI accelerates routine implementation work.
