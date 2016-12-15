clean:
	rm --force --recursive build/
	rm --force --recursive dist/
	rm --force --recursive *.egg-info
	find . -name '*.pyc' -exec rm --force {} +
	find . -name '*.pyo' -exec rm --force {} +
	find . -name '*~' -exec rm --force  {} +