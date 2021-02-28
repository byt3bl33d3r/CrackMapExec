.PHONY: tests

default: build

clean:
	rm -f -r build/
	rm -f -r bin/
	rm -f -r dist/
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '*.pyo' -exec rm -f {} +
	find . -name '*~' -exec rm -f  {} +
	find . -name '__pycache__' -exec rm -rf {} +
	find . -name '.pytest_cache' -exec rm -rf {} +

tests:
	flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics --exclude cme/data/*

requirements:
	poetry export --without-hashes -f requirements.txt -o requirements.txt
	poetry export --without-hashes --dev -f requirements.txt -o requirements-dev.txt