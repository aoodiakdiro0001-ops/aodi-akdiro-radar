.PHONY: test demo cicheck clean

test:
	python3 -m unittest discover tests -v

demo:
	python3 -m nexus.cli demo

cicheck: test
	python3 -m py_compile nexus/*.py

clean:
	rm -rf __pycache__ nexus/__pycache__ tests/__pycache__ demo/out
