# Contributing to Sigmwah

Thank you for helping. Sigmwah is a community converter. Keep the bar high: correct Wazuh XML or a motivated skip, never a “close enough” rule.

## Development setup

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
ruff check src tests
mypy src/sigmwah
pytest -m "not docker"
```

Python **3.11** or **3.12**. Optional Docker is only for `pytest -m docker` / `sigmwah validate --docker`.

## Rules of the road

- Do not copy code from sigmac, sigma2wazuh, cookiecutter-pySigma-backend, or other converters.
- Align the backend to the public pySigma API. If that API moves, update `tests/test_pysigma_contract.py` first.
- Do not vendor SigmaHQ rules in this repository.
- Windows EventChannel rules must use `if_sid` / `if_group`, not production `decoded_as json`.
- `--target wazuh5` must never emit 4.x XML.
- Golden YAML under `tests/golden/` must stay original (synthetic). Do not paste SigmaHQ detections.

## Pull requests

1. One concern per PR.
2. Add or update tests.
3. Run ruff, mypy, and `pytest -m "not docker"`.
4. If you change field mappings, document the Wazuh ruleset file you checked in `docs/mappings.md`.
