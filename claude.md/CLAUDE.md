# CLAUDE.md

Coding rules for any AI agent (Claude Code, Claude Desktop, Cursor, etc.)
working in this repository. Follow every time without exception.

## Module headers

Every Python module starts with:

\`\`\`
"""
Role: <one line, what this module is>
Description: <a few lines, what it does and important details>
Author: Bor
"""
\`\`\`

Do not change the Author field.

## Prose style

No em dashes anywhere. Not in code, comments, docstrings, log messages,
commit messages, or Markdown. Use a comma, a colon, or two sentences.

No semicolons in prose. Code semicolons follow Python rules.

Short scientific sentences. No throat-clearing. Forbidden filler:
"now", "let's", "we'll", "here we", "essentially", "basically",
"simply", "just". If a comment says "now do X", delete "now".

## Comments

Comments explain what is not obvious from the code. They never restate
the code in English.

No section dividers like `# ---- Auth ----` or `# ===== Fetch =====`.
Function names and module structure are the dividers.

No step narration like `# 1. authenticate`, `# 2. fetch`. The log lines
already announce these steps at runtime.

If a comment exists, it earns its space.

## Logging

Use `from spw_attrib.logger import get_logger; log = get_logger(__name__)`.

Never use `print()` in library or diag code. Logger only.

Format with `%s` placeholders, not f-strings, so the logger can
lazy-format and so structured log backends work.

`log.info` for milestones, `log.warning` for recoverable issues,
`log.error` for failures.

## Naming

Functions describe what they do, not how. `fetch_frames` not
`do_api_fetch`. `enrich_irbem` not `process_with_model`.

Private helpers prefix with `_`.

Constants in module scope are UPPER_SNAKE_CASE.

## Imports

Standard library, then third-party, then `spw_attrib.*`. Blank line
between groups. One import per line. No `from x import *`.

## Type hints

Modern syntax: `list[int]`, `dict[str, float]`, `int | None`.

Type all public function signatures. Internal helpers may skip when
types are obvious from a one-line body.

## Errors

Never silently swallow errors. Catch what you can act on, log the rest,
re-raise when in doubt.

Library code does not exit the process. Only entry-point scripts may
call `sys.exit`.

## Tests

Tests live in `tests/`, mirror the source layout. Plain `pytest`.

Test names describe behaviour, not the function:
`test_engine_attributes_saa_proton_as_environmental` rather than
`test_attribute`.

## Things never to do

- Emoji in code, comments, or commit messages.
- ASCII art banners.
- Unicode smart quotes or fancy bullets in code or docs.
- Placeholder TODOs without an attached GitLab issue number.
- Modify rule confidences in `attribution/engine.py` without re-running
  FLP validation against Noeldeke 2017.
- Modify the import order in `radiation/irene.py` (the order is
  load-bearing for the Fortran library).
- Modify the WGS84 conversion in `ephemeris/coords.py` without
  re-running the FLP onboard-truth check.

## Defaults and missing data

A silent default is a lie. If a value cannot be retrieved or computed, the
right behaviour is one of these, in this preference order:

1. Return `None` or `pd.NA` and let the caller decide.
2. Raise an explicit exception with a message naming the missing input.
3. Log a WARNING and return a sentinel only when the caller has documented
   that it accepts and handles the sentinel.

Never do any of these:

- Substitute a "reasonable" value (e.g. `Dst = 0`, `Bz = 0`, `Kp = 2`) when
  the real value is missing. Reasonable values mask gaps in input data and
  produce attribution verdicts that look defensible but are computed from
  fiction.
- Use `dict.get(key, fallback)` for scientific quantities. Use
  `dict.get(key)` and let `None` propagate, or check membership and raise.
- Wrap a computation in `try/except Exception: return default_value`.
  Catch only the specific error class you expect, and only when the
  recovery path is documented.
- Fill NaN columns with zero before a statistic. `df.fillna(0).mean()`
  hides missing data inside the mean. Use `df.mean(skipna=True)` and log
  the gap count, or `df.dropna()` and report `n_valid`.

There is one explicit exception: a function may have a "quiet baseline"
mode where defaults are used deliberately and named in the function
signature. `enrich_density` does this for the NRLMSIS quiet comparison.
The defaults are bound by an argument default or a documented module
constant, and the calling code is explicit about choosing the quiet mode.
Quiet defaults that exist only inside a fallback path do not qualify.

When you see a default that fails this test, raise an issue, do not fix
silently. The fix changes behaviour and needs an explicit review.

## When in doubt

Ask. Do not invent a convention. If a file in the repo contradicts
these rules, the file is wrong. Fix it, do not copy it.
