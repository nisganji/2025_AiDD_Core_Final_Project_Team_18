# Campus Resource Hub

Campus resource discovery and booking with roles, reviews, messages, and an admin dashboard.

Highlights:
- Messages: admin ↔ users chat threads (per-user threads)
- Roles: student, staff, admin; signups require admin approval
- Reviews: star ratings + sanitized comments
- Search: keyword, category, location, capacity, date/time; sort by recent/booked/rated
- Bookings: conflict detection, available slots only, auto-approve for open, waitlist, .ics export
- Notifications: stored in DB (in-app simulation)
- Admin: manage users/resources/bookings; analytics
- Security: CSRF, Jinja autoescape, validators, Bleach, login rate limiting, CSP headers
- API: session-auth endpoints for resources, reviews, bookings

## Requirements
- Python 3.11–3.13 supported
- SQLite (bundled; default via `campus.db` in project root)
- See `requirements.txt` for Python packages (SQLAlchemy >= 2.0.36 pinned for Python 3.13 compatibility)

## Setup
Install dependencies with a virtual environment.

Windows PowerShell
```powershell
python -m venv .venv
.\.venv\Scripts\Activate
pip install -r requirements.txt
```

macOS/Linux (bash/zsh)
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run
Set the Flask app and initialize the database (creates tables and seeds demo data).

Windows PowerShell
```powershell
$env:FLASK_APP = "src.app"
flask run               # http://127.0.0.1:5000
```

macOS/Linux (bash/zsh)
```bash
export FLASK_APP=src.app
flask run               # http://127.0.0.1:5000
```

Demo accounts
- admin@example.com / password
- staff@example.com / password
- student@example.com / password

Promote your user to admin
```bash
flask make-admin you@example.com
```

Optional environment variables
- `SECRET_KEY`: Flask secret (default: `dev-key`)
- `DATABASE_URL`: SQLAlchemy URL (default: SQLite file `campus.db`)
- `RATELIMIT_ENABLED`: Enable/disable rate limiting (default: `True`)
- `LIMITER_STORAGE_URI`: Rate limit backend (e.g., `redis://localhost:6379/0`; default: in-memory)

Security notes
- Configure a strong `SECRET_KEY` in production.
- Default rate limit applies to `/auth/login` (5/min per IP). Tune via environment if needed.
- A baseline Content Security Policy is set allowing self and jsDelivr for Bootstrap/Chart.js.

Uploads
- Images uploaded via the admin UI are written under `src/static/img/uploads` (created automatically).

## API (after logging in via browser)
- `GET /api/resources`
- `GET /api/resources/<id>`
- `GET /api/resources/<id>/reviews`
- `POST /api/bookings` JSON: `{ "resource_id": 1, "date": "YYYY-MM-DD", "slot": "HH:MM-HH:MM" }`
- `GET /api/bookings/my`

## Development
- Recreate schema/seed data during dev: `flask db-init --reset`
- The app registers blueprints for main, auth, resources, bookings, admin, users, messages, reports, and api.

## Architecture (MVC + DAL)
- Models: SQLAlchemy models are defined in `src/app.py` for now (User, Resource, Booking, Review, Message, Notification). These are exported via `src/__init__.py`.
- Views: Jinja templates live under `src/templates` (Flask default). A `src/views/` folder is present to document the view layer.
- Controllers: Flask blueprints live in `src/app.py` today; `src/controllers/` is scaffolded for future extraction of routes by domain.
- Data Access Layer (DAL): All raw SQL is encapsulated in `src/data_access/` and used by controllers. Controllers should not issue raw SQL directly.

Key DAL functions
- `get_distinct_locations_published(db)`
- `get_category_counts_published(db)`
- `get_booking_trend_counts(db, start_date, end_date)`
- `get_inbox_threads(db, user_id)`
- `get_hourly_bookings(db, day)`

This structure demonstrates separation of concerns while keeping changes minimal. Future refactors can move blueprints and models into `src/controllers` and `src/models` without changing URLs.

## AI First Context Pack
The repo includes folders to support AI-assisted workflows:
- `.prompt/dev_notes.md` – running log for AI interactions
- `docs/context/APA/` – Agility, Processes & Automation artifacts
- `docs/context/DT/` – Design Thinking artifacts
- `docs/context/PM/` – Product Management artifacts
- `docs/context/shared/` – shared personas, glossary, OKRs

These folders provide context to AI tools (Cursor, Copilot Agents) for better grounding and safer automation.

## AI Integration (Gemini Summary)
- Feature: an Auto‑Summary Reporter at `/reports/summary` (linked as “AI Summary” for staff/admin users) generates a weekly narrative of campus resource usage.
- Engine: when the `GEMINI_API_KEY` environment variable is set, the app calls Google Gemini 1.5 Flash (`generateContent` API) with structured booking/resource stats (no raw PII). If the key is missing or the call fails, a deterministic, rule‑based fallback summary is used instead.
- Grounding: only real data from the SQLite database is included in the JSON sent to Gemini (total bookings, top resources, quiet resources, date window). The prompt explicitly instructs Gemini not to invent resources or numbers.
- Configuration: set `GEMINI_API_KEY` in your local environment before running Flask; never commit keys to the repo. You may also run the app without the key, in which case the non‑AI fallback summary remains active.
- Ethics & review: AI usage and design choices are documented in `.prompt/dev_notes.md`. All Gemini‑generated summaries are short, internal‑facing, and should be spot‑checked by humans for demos or reports.

## Admin Moderation & Abuse Handling
- Users: admins/staff can approve or reject new registrations (`/admin` “Pending Users” list), edit user roles and departments (`/admin/users/<id>/edit`), grant admin to flagged accounts, and fully delete a user (`/admin/users/<id>/delete`), which also removes that user’s messages, bookings, reviews, and owned resources.
- Resources: admins/staff can create, edit, and delete resources, and use moderation actions (`/admin/resources/<id>/<action>`) to publish, hide (move to draft), or archive resources when there is misuse or outdated content.
- Reviews: only non‑flagged reviews are shown to end users; admins see flagged reviews in the dashboard and can either remove a review entirely or clear its flagged state via `/admin/reviews/<id>/<action>`.
- Messages: admins can start a thread with any user (`/messages/new`) and review message threads when needed; abusive users can be suspended or removed using the admin user management actions above, which also deletes their messages.
- Bookings: admins/staff can approve or reject bookings from the “Pending Bookings” section of the admin dashboard, including promoting waitlisted bookings when a slot is freed.

## Testing
- Install dev dependency: `pip install -r requirements.txt` (includes pytest)
 - Run with plugin isolation and clear cache:
   - Windows PowerShell
     - `setx PYTEST_DISABLE_PLUGIN_AUTOLOAD 1`
     - Open a new terminal
     - `python -m pytest -q --cache-clear`
   - macOS/Linux (bash/zsh)
     - `export PYTEST_DISABLE_PLUGIN_AUTOLOAD=1`
     - `pytest -q --cache-clear`
 - Save results: `python -m pytest -q | tee docs/pytest_results.txt`
 - Note: In TESTING mode, templates suppress `<script>` tags to simplify XSS assertions.
- What’s covered:
  - Unit: booking conflict detection and available-slot logic; status transitions for open vs restricted
  - DAL: CRUD operations via SQLAlchemy independent of routes
  - Integration: register → admin-approve (simulated in test) → login → protected route access
  - End-to-end: login → view resource → book slot → appears in My Bookings
  - Security: simple SQL injection resilience in search; template escaping/sanitization for reviews

## Accessibility
- Skip link, visible focus, ARIA labels

## Notes
- Calendar export is provided as `.ics` per booking (import into any calendar)
- Email delivery is simulated via `notifications` table
