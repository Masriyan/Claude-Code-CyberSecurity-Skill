PYTHON ?= python3
.PHONY: check test lint
check: lint test
lint:
	$(PYTHON) -m ruff check .
	$(PYTHON) -m bandit -r cyberskill tools -ll
test:
	$(PYTHON) -m pytest -q
