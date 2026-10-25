# secheaders

A fast, friendly audit of a website's **HTTP security headers, cookie flags and CORS policy** — with a score, a grade, and a plain explanation of every finding.

- Single file, **Python standard library only** (3.9+). No installs, no API keys.
- Polite: one GET per URL (plus one OPTIONS preflight with `--cors`). No scanning, no fuzzing, no auth.
- Useful in CI: `--fail-under` returns a non-zero exit code when a site drops below your bar.

> **Only test sites you own or are explicitly authorised to assess.** This tool makes ordinary requests, but permission is still yours to have.

## Quick start

```bash
git clone https://github.com/Zasnit1/secheaders.git
cd secheaders
python3 secheaders.py https://your-site.example --cors
```

```
https://shop.example  [HTTP 200]  score 79/100  grade C
  [PASS] HSTS: max-age=63072000, includeSubDomains
  [PASS] Content-Security-Policy: present with script/default-src and no unsafe-* keywords
  [PASS] X-Content-Type-Options: nosniff
  [PASS] Clickjacking protection: covered by CSP frame-ancestors
  [PASS] Referrer-Policy: strict-origin-when-cross-origin
  [WARN] Permissions-Policy: missing (lock down powerful features explicitly)
  [WARN] Server banner: discloses version: 'nginx/1.25.3'
  [WARN] Cookie 'sid' flags: missing Secure, HttpOnly, SameSite
```

*(Illustrative output. Run it against your own site for real numbers.)*

## What it checks

| Check | Points | Passes when |
|---|---|---|
| HTTPS | 20 | the URL is served over HTTPS |
| HSTS | 20 | `Strict-Transport-Security` has `max-age` of at least 180 days |
| Content-Security-Policy | 25 | a CSP defines `default-src`/`script-src` with no `unsafe-inline` / `unsafe-eval` |
| X-Content-Type-Options | 10 | set to `nosniff` |
| Clickjacking protection | 10 | `X-Frame-Options: DENY`/`SAMEORIGIN`, or CSP `frame-ancestors` |
| Referrer-Policy | 10 | a privacy-preserving policy is set |
| Permissions-Policy | 10 | present and non-empty |
| Server banner | 5 | no version number is disclosed |
| Cookie flags | 5 each | every `Set-Cookie` has `Secure`, `HttpOnly` and `SameSite` |
| CORS (`--cors`) | 10 | no `*` origin combined with credentials |

The score is the weighted percentage of points earned. Grades: A (90+), B (80+), C (70+), D (60+), F below.

## Usage

```bash
python3 secheaders.py URL [URL ...] [--cors] [--format text|markdown|json] [--fail-under N]
```

- `--cors` — also send an OPTIONS preflight and evaluate the CORS policy.
- `--format json` — machine-readable output for pipelines.
- `--fail-under 80` — exit code `1` if any site scores below 80 (handy in CI).

### CI example (GitHub Actions)

```yaml
- run: python3 secheaders.py https://staging.your-site.example --cors --fail-under 80
```

## Why these headers

Each header closes a specific door: HSTS stops protocol-downgrade and cookie-theft-over-HTTP, CSP is the strongest in-depth defence against XSS, `nosniff` stops MIME-confusion attacks, clickjacking protection stops UI redressing, and cookie flags keep session cookies out of JavaScript and off cross-site requests. A missing header is rarely a vulnerability on its own; together they are the difference between one bug and one breach.

## Tests

```bash
python3 -m pytest -q
```

## License

MIT, see [LICENSE](LICENSE).

Built by Ibrahim Maqtoush with AI assistance. Issues and pull requests welcome.
