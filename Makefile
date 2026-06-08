.PHONY: install certs run-server run-client test clean

VENV := .venv
PYTHON := $(VENV)/bin/python
PIP := $(VENV)/bin/pip

HOST ?= localhost
PORT ?= 4433
SERVER ?= localhost

$(VENV):
	python3 -m venv $(VENV)

install: $(VENV)
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt

certs:
	bash certs/gen_cert.sh

run-server: install
	$(PYTHON) -m qcp.server --host $(HOST) --port $(PORT)

run-client: install
	$(PYTHON) -m qcp.client $(SERVER) --port $(PORT)

test: install
	$(PYTHON) -m pytest -q

clean:
	rm -rf $(VENV) certs/cert.pem certs/key.pem
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	find . -type d -name .pytest_cache -prune -exec rm -rf {} +
