.PHONY: assess test report build
build:
	docker build -t security-assessment-scanner:1 .
assess:
	python scripts/assess.py --phase retest
test:
	python -m unittest discover -s tests -v
