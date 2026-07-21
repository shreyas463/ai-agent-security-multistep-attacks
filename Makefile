.PHONY: help venv fetch-sdk smoke test local notebook push-kernel clean

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
	@echo "  make local      - scorer-equivalent local run (OptimalGuardrail + allow-all sanity)"
	@echo "  make notebook   - regenerate notebooks/submission.ipynb from src/attack.py"
	@echo "  make push-kernel - push the notebook to Kaggle (kaggle kernels push -p notebooks/)"
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

local:
	$(BIN)/python tests/run_local.py $(BUDGET)

notebook:
	$(BIN)/python scripts/build_notebook.py

push-kernel: notebook
	# This competition requires T4 (not the default P100). --accelerator overrides the metadata.
	$(BIN)/kaggle kernels push -p notebooks/ --accelerator NvidiaTeslaT4

clean:
	rm -rf **/__pycache__ .pytest_cache
