.PHONY: help venv fetch-sdk smoke test notebook submit clean

PY ?= python3
VENV ?= .venv
BIN := $(VENV)/bin
COMP := ai-agent-security-multi-step-tool-attacks

help:
	@echo "Targets:"
	@echo "  make venv       - create .venv and install dev deps (requirements.txt)"
	@echo "  make fetch-sdk  - download competition SDK+fixtures via Kaggle API (needs kaggle.json + accepted rules)"
	@echo "  make smoke      - run the local smoke test against attack.py (+ SDK if installed)"
	@echo "  make test       - run pytest"
	@echo "  make notebook   - build notebooks/submission.ipynb from notebooks/submission.py"
	@echo "  make submit      - submit the notebook (kaggle kernels push) — configure kernel-metadata.json first"
	@echo "  make clean      - remove caches / build artifacts"

venv:
	$(PY) -m venv $(VENV)
	$(BIN)/pip install --upgrade pip
	$(BIN)/pip install -r requirements.txt
	@echo "Activate with: source $(BIN)/activate"

fetch-sdk:
	bash scripts/fetch_sdk.sh

smoke:
	$(BIN)/python tests/smoke_test.py || $(PY) tests/smoke_test.py

test:
	$(BIN)/pytest -q || $(PY) -m pytest -q

notebook:
	$(BIN)/jupytext --to notebook notebooks/submission.py -o notebooks/submission.ipynb

clean:
	rm -rf **/__pycache__ .pytest_cache notebooks/submission.ipynb
