# AGENTS.md — working agreement for subenum

## Project
Single-file recon tool `subenum.py` (~15k lines): subdomain discovery → port scan →
HTTP probes → evidence-based vulnerability checks → findings → `http://subenum`
dashboard (aiohttp, binds 127.0.0.1:80). Python 3.13, aiohttp only (plus dnspython).

## Non-negotiable rules
1. **Evidence-based detection only.** Every check needs positive evidence + a
   deny-phase/control negative. No "server header present ⇒ vuln".
2. **Every tag needs a `SEV` entry AND a `REMEDIATION` entry** in the two dicts.
   `check_sev.py` must stay green (SEV count == REMED count, no orphans).
3. **`check_opts.py` must stay green** (CLI flags in subenum.py == flags documented
   in the help/epilog).
4. **Finds print as `[TAG] text`**; severity from `SEV[tag]` only.
5. **Never modify the parallel local tools**: `authflow.py`, `bugaudit.py`,
   `cname.py`, `deep*.py`, `dnstls.py`, `methods.py`, `stack.py`, `vulcan_verify.py`.
6. **Never publish** scan outputs (`subdomains*`), state (`.subenum_history.json`),
   tests/scratch, or the parallel tools — enforced by `.gitignore`.
7. **Every check failure goes through `record_error()`/`note_check_error()`**
   (next to `FAILS` at the top of subenum.py) — never a bare
   `print(f"  [x] failed: ...")`. `CHECK_ERRORS` feeds the `/api/stats`
   `errors` count, the end-of-scan summary, and the smoke gate.
8. **Mutating dashboard routes need the session token**: any new route that
   changes state (POSTs, plus `GET /api/evidence` which re-probes URLs) must
   be listed in `_token_mw` inside `build_webapp()` and its JS fetch must
   send `X-Subenum-Token` (`SE_TOKEN`, injected by `index()`); read-only
   GETs stay open.

## Verification workflow (before declaring any change done)
1. `python -m py_compile subenum.py` + `python -m ruff check subenum.py
   --select E9,F63,F7,F82`
2. `check_sev.py` (273/273) + `check_opts.py` (ALL OK)
3. Affected `verify_waveNN.py` — live local mocks, expect `N ok, 0 FAIL`;
   `verify_golden.py` (precision ground truth: 10 cases, exact finding-set
   on positive + exact-zero on deny, expect `24 ok, 0 FAIL`)
4. Full `battery_w12.bat` (runs all verifiers + ruff + golden; **wave11 is
   manual**: `python verify_wave11.py` → 89/0)
5. `smoke_final.py` — real end-to-end; **rc must be 0 and the gate enforces
   zero `CHECK_ERRORS` and zero `failed:` lines** (any hit flips rc to 2 —
   mocks can't catch everything; this is the gate)
6. Restart dashboard: `cmd /c start "subenum" /min python subenum.py --web 80`
   (the `ChildProcess.kill` wrapper error is harmless), then hit `/`, `/api/stats`,
   `/api/history` — all must be 200; `POST /api/clear` **without**
   `X-Subenum-Token` must be 403, and `/` must contain a real token
   (no `__SE_TOKEN__` placeholder left in the served HTML).

Verifier scripts + battery live in `C:\Users\SATYA\AppData\Local\Temp\opencode\`
(kept out of the repo). `D:\Subenum\tests\` is the **maintained local backup**
(gitignored, never published) — re-copy the suite there after any verifier
change so a temp-dir loss doesn't take the suite with it.

## Verifier conventions
- One file per wave: `verify_waveNN.py`, unique mock port range per wave
  (w20: 9064+, w21: 9201+, w22: 9301+, w23: 9401, w24: 9410+, golden: 9501+).
- Import functions directly from `subenum.py`; spin `aiohttp` mock servers that
  produce the exact evidence pattern; assert findings contain the tag; assert
  deny-phase (clean server) produces nothing.
- **Mock contracts must match real protocol behavior**, not just our parser:
  aiohttp's server rejects TRACK/DEBUG → use raw `asyncio.start_server` TCP mocks
  for those verbs. Hidden contracts that bit the golden harness: TRACE marker
  header is `X-Sxe-Trace`; ratelimit baseline path is `/sxnrl-<rng>/login`
  (must 404, else catch-all suppression); backup canary is `/sxnbf-<rng>.bak`
  (must return the same fake body as candidates, else similarity never trips);
  session-fixation rotation is "Set-Cookie echoes the client-supplied value".
- Reuse **one `aiohttp.TCPConnector` per sequential batch** (`fresh_conn()`);
  an aiohttp session OWNS and CLOSES its connector on exit — a connector
  shared past the first `async with xsession(conn)` is dead (all later checks
  silently score 0).
- Parse HTTP headers **case-insensitively** — aiohttp returns a plain dict and
  `.get("allow")` misses server-cased `Allow`.

## Known landmines (all bit us before)
- `crawl_rows` is **tab-joined strings** `f"{h}\t{p}"` — consumers must
  `row.split("\t", 1)`, never tuple-unpack.
- Never `await` a `StreamReader`/`StreamWriter` object (`wr.write(); await wr.drain()`).
- `return_exceptions=True` hides failures → they land in `CHECK_ERRORS`; the
  smoke gate (rc=2) catches anything that slips past.
- State JSON: probe bodies capped at 8 KB (`_BODY_CAP`).
- Dedup via `class Findings` — append through it, not raw list.
- `SUBENUM_NO_NUCLEI=1` set in some shells (skips nuclei); unset for full runs.

## Shell quirks (Windows cmd)
- Multi-line `python -c` hangs → write a temp `.py` file and run it.
- `findstr` can't match `[` or most regex — use temp Python for content checks.
- Detached run: `cmd /c start "title" /min cmd /c script.bat` (kill error is harmless).
- Wait: `ping -n N 127.0.0.1 >nul`. PowerShell `->`/`$_` breaks in one-liners → temp `.ps1`.

## CI
`.github/workflows/ci.yml`: py_compile + ruff (`E9,F63,F7,F82` only — the
critical ruleset, not style) + `--help` on ubuntu+windows; runs
`tests/unit*.py` only if present (tests are gitignored/local-only).
