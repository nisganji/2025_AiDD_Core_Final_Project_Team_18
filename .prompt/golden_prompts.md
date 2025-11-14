Golden Prompts — High‑Impact Requests and Responses

1) Project scaffolding to rubric
- Prompt: Scaffold a Flask project “Campus Resource Hub” meeting AiDD Core 2025 rubric (auth, roles, resources, bookings, reviews, messaging, admin, security, structure).
- Response summary: Created Flask app with SQLAlchemy models, blueprints, CSRF, seed data, templates, and static assets; aligned features to rubric categories.
- Key references:
  - Models: `src/app.py:40`, `src/app.py:55`, `src/app.py:75`, `src/app.py:87`, `src/app.py:99`, `src/app.py:107`
  - Blueprints register: `src/app.py:974`
  - CSRF setup: `src/app.py:16`, `src/app.py:26`

2) Booking conflict detection + availability slots
- Prompt: “Implement conflict detection and show only free time slots; add /api/check_slots; DB‑level overlap rejection.”
- Response summary: Implemented slot parsing and availability filtering via helpers; enforced conflicts in route logic. No dedicated `/api/check_slots` endpoint or DB constraint; availability shown on resource detail and enforced when booking.
- Key references:
  - Helpers: `src/app.py:176`, `src/app.py:184`, `src/app.py:196`
  - Use in browse/detail/booking: `src/app.py:323`, `src/app.py:335`, `src/app.py:374`, `src/app.py:409`

3) Threaded messaging
- Prompt: “Upgrade to WhatsApp‑style threads with AJAX poll/post endpoints.”
- Response summary: Implemented per‑user threads (admin can message any user) with server‑rendered pages and form posts. No AJAX polling or `/api/messages/post|poll` endpoints.
- Key references:
  - Inbox/thread routes: `src/app.py:833`, `src/app.py:855`
  - Message creation (sanitized): `src/app.py:861`
  - Templates: `src/templates/messages_inbox.html`, `src/templates/messages_thread.html`

4) Resource search + sorting
- Prompt: “Add filters (keyword/category/location/capacity/date/time) and sort (recent/most booked/top rated).”
- Response summary: Implemented filters and sorting in browse route and template UI.
- Key references:
  - Browse route: `src/app.py:300`, `src/app.py:362`
  - Browse template: `src/templates/resources_browse.html:15`, `src/templates/resources_browse.html:91`

5) Review gating + averages
- Prompt: “Only completed bookings may review; show averages on lists and detail.”
- Response summary: Enforced gating (approved booking with end < now) and display of averages.
- Key references:
  - Gate in route: `src/app.py:379`, `src/app.py:384`, `src/app.py:386`
  - Averages: `src/templates/home.html:39`, `src/templates/resources_browse.html:91`, `src/templates/resource_detail.html:55`

6) Admin dashboard analytics
- Prompt: “Add Chart.js analytics; optional /api/admin/stats.”
- Response summary: Implemented Chart.js charts using data prepared in the dashboard route (no separate stats API endpoint).
- Key references:
  - Dashboard route: `src/app.py:450`
  - Template with charts: `src/templates/admin_dashboard.html`

7) Security hardening
- Prompt: “CSRF on all forms, escape Jinja, sanitization, login rate limit.”
- Response summary: CSRF via Flask‑WTF global protect; Jinja autoescape; inputs validated; Bleach sanitization for reviews/messages. No login rate‑limiting implemented.
- Key references:
  - CSRF: `src/app.py:26`, `src/app.py:30`
  - Sanitization: reviews/messages `src/app.py:861`, `src/app.py:389`

8) Calendar export
- Prompt: “Add ‘Add to Calendar’ (.ics) and Google Calendar option.”
- Response summary: Implemented `.ics` export route and a Google Calendar link on “My Bookings”.
- Key references:
  - ICS export route: `src/app.py:434`
  - Google Calendar link: `src/templates/my_bookings.html:45`

9) Waitlist promotion + notifications
- Prompt: “Allow waitlist; promote next when freed; notify user.”
- Response summary: Implemented waitlist status, promotion on rejection approval path, and in‑app notifications persisted.
- Key references:
  - Waitlist set/validation: `src/app.py:413`
  - Promotion + notify: `src/app.py:498`, `src/app.py:513`
  - Notification helper/model: `src/app.py:201`, `src/app.py:107`

Notes
- Items explicitly not implemented: `/api/check_slots`, AJAX message poll/post endpoints, login rate limiting, separate `/api/admin/stats` endpoint.
- This log focuses on prompts that materially shaped architecture or user‑visible features and summarizes the resulting implementation paths.

