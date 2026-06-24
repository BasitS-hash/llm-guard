# Contributing to llm-guard

Thanks for your interest in improving `llm-guard`. Detection tooling lives or
dies by its precision/recall balance, so contributions that add **well-tested**
rules — with both positive and negative cases — are especially welcome.

## Development setup

```bash
git clone https://github.com/BasitS-hash/llm-guard.git
cd llm-guard
python3.11 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## The local quality gate

Run all of these before opening a pull request — CI runs the same set:

```bash
ruff check .                                   # lint
mypy                                           # type check (strict)
pytest --cov=llm_guard --cov-report=term-missing   # tests + coverage
bandit -c pyproject.toml -r src                # security lint
pip-audit                                       # dependency CVEs
```

## Adding or changing a detection rule

1. Add the rule to `rules_input.py` or `rules_output.py` with a stable
   `rule_id`, the correct `OwaspCategory`, a `Severity`, a `score` in `[0, 1]`,
   and a clear `description`.
2. **Add tests for both directions** in `tests/`:
   - a **positive** case proving the attack is caught, and
   - one or more **negative** cases proving benign text is *not* tripped.
3. Run the gate above. New code on detectors/scanners should keep coverage well
   above 85%.
4. If the rule changes red-team behaviour, sanity-check with
   `llm-guard redteam` and `llm-guard redteam --vulnerable`.

### Precision is the priority

Prefer patterns that target **adversarial framing** over bare keywords. A rule
that flags the word "system" in ordinary prose will get the whole tool turned
off. If you can't add a negative test that stays clean, the rule is probably too
broad.

## Coding standards

- Python 3.11+, fully type-annotated, `ruff`-clean, `mypy --strict`-clean.
- Keep modules focused and under ~400 lines.
- No secrets in code or tests; no network calls in the library or test suite.
- Immutable data where practical (`frozen` dataclasses / pydantic models).

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/):
`feat:`, `fix:`, `refactor:`, `docs:`, `test:`, `chore:`, `ci:`, `perf:`.

## Reporting issues

- **Security issues:** see [SECURITY.md](SECURITY.md) (report privately).
- **False positives / negatives:** open an issue with the exact input text and
  the observed vs. expected verdict.

By contributing you agree your contributions are licensed under the project's
[MIT License](LICENSE).
