# AI Evaluation – Auto‑Summary Reporter

This note documents a simple manual validation flow for the Gemini‑powered weekly summary at `/reports/summary`.

## Goal
- Verify that the Auto‑Summary Reporter:
  - Responds successfully for staff/admin users.
  - Produces a narrative grounded strictly in real booking/resource data.
  - Behaves predictably with and without an AI key configured.

## Preconditions
- App installed and database initialized as described in `README.md`.
- At least one admin or staff account available (e.g., `admin@example.com`).

## Scenario A – Fallback (no Gemini)
1. Ensure the `GEMINI_API_KEY` environment variable is **not** set in your shell.
2. Run the app and log in as `admin@example.com`.
3. Navigate to `/reports/summary` via the “AI Summary” link.
4. Expected:
   - Page returns HTTP 200.
   - Narrative text matches the deterministic fallback behavior:
     - If there are no bookings in the last 7 days, it explains that there were no approved/completed bookings and suggests promoting resources.
     - If there are bookings, it mentions the total count, number of resources, a leading resource if any, and how many resources had no bookings.

## Scenario B – Gemini Active
1. Set a valid Gemini key in your environment:
   - On Windows PowerShell:
     ```powershell
     setx GEMINI_API_KEY "YOUR_KEY_HERE"
     ```
   - Open a new terminal so the variable is visible to Flask.
2. Run the app and log in as `admin@example.com`.
3. Navigate to `/reports/summary` again.
4. Expected:
   - Page returns HTTP 200.
   - Narrative is free‑form (Gemini generated) but:
     - Only references resources, counts, and time ranges that exist in the data.
     - Does not introduce new, fabricated resources or numbers.
5. Optional: confirm in Gemini AI Studio that requests are logged for the `gemini-1.5-flash:generateContent` model.

## Grounding Check
- Cross‑check the summary text against:
  - The underlying bookings in the last 7 days.
  - The “Top Resources This Week” and “Quiet Resources” tables on the same page.
- The summary should be a stylistic rewrite of those facts, not a source of new facts.

