# College Complaint Manager – Smart Campus Grievance Portal

Flask + SQLite + Bootstrap 5 + Chart.js. Students register, submit and track complaints; admins manage them and view analytics.

## Run locally
```bash
cd college-complaint-manager
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```
Open http://127.0.0.1:5000 . The SQLite database (`complaints.db`) is created on first run with demo data.
(Bootstrap, Chart.js and fonts load from CDNs, so internet access is needed in the browser.)

## Demo logins
| Role    | Email               | Password   |
|---------|---------------------|------------|
| Admin   | admin@college.edu   | Admin@123  |
| Student | student@college.edu | Student123 |

Change the admin password before any real deployment, and set `SECRET_KEY` as an environment variable.

## Structure
- `app.py` – routes, auth, validation, SQLite access, CSV export, analytics API
- `templates/` – Jinja pages (`base.html` is the shared layout
- `static/` – CSS, JS, and `uploads/` for complaint images

## Security
Salted password hashing, session auth with student/admin roles, CSRF tokens on all forms, parameterised SQL, login lockout (5 tries / 5 min), image-only uploads capped at 2 MB, security headers.
