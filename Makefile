.PHONY: install dev test lint format clean build scan checks

install:
	pip install .

dev:
	pip install -e ".[dev]"

test:
	pytest tests/ -v --tb=short

test-cov:
	pytest tests/ -v --cov=ghostaudit --cov-report=term-missing --cov-report=html

lint:
	ruff check src/ tests/

format:
	ruff format src/ tests/

clean:
	rm -rf dist/ build/ *.egg-info src/*.egg-info .pytest_cache htmlcov .coverage
	find . -type d -name __pycache__ -exec rm -rf {} +

build: clean
	python -m build

scan:
	ghostaudit scan

checks:
	ghostaudit checks
