# Security Header Auditor (Python)

Type in a website address and this tool checks the website's built-in safety settings (called "security headers"). It gives the site a grade from A to F and explains, in plain language, what each setting does and how to fix it.

This is the original Python version. The same tool also lives on my portfolio site, rebuilt in TypeScript, and both give the same grades.

## Run it

You need Python 3.11 or newer.

```bash
pip install -r requirements.txt
uvicorn app:app --reload
```

Then open <http://127.0.0.1:8000> in your browser.

## What's in the folder

| File | What it does |
|---|---|
| `app.py` | The web service: shows the page and answers audit requests |
| `audit_rules.py` | The eight checks, how much each is worth, and the grade |
| `safe_fetch.py` | Visits the website safely (see below) |
| `index.html` | The page you see in the browser |
| `test_audit.py` | Automatic checks. Run with `python test_audit.py` |

## The eight checks

HSTS, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, version leaks in the Server header, and cookie flags. They add up to a score out of 100.

## Why it can't be tricked into visiting the wrong place

A tool that visits any address a stranger types could be tricked into reaching private or internal systems (this is called server-side request forgery, or SSRF). To prevent that, the tool:

- accepts only normal web addresses (no files, no logins in the address, only the standard web ports);
- looks up the website's real IP address itself and refuses private, local and internal ones, including tricky disguises like `::ffff:127.0.0.1`;
- then connects to that exact checked address, so the lookup can't be swapped afterwards;
- re-checks every redirect, and limits time, redirects and requests per minute;
- only reads the website's headers, never its content, and saves nothing.

Only use it on websites you own or have permission to test. The grade is a quick guide, not a full security assessment.
