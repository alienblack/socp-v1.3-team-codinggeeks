ENV_FILE := .socp.env
-include $(ENV_FILE)

SOCP_BACKDOORED ?= 0

.PHONY: run-server run-server-b run-client test fmt backdoored clean

run-server:
	SOCP_BACKDOORED=$(SOCP_BACKDOORED) python -m socp.cmd.server --config configs/server.yaml

run-server-b:
	SOCP_BACKDOORED=$(SOCP_BACKDOORED) python -m socp.cmd.server --config configs/server_b.yaml

run-client:
	python -m socp.cmd.client repl --server ws://127.0.0.1:7001 --user $$USER_ID --keys-dir ~/.socp

test:
	pytest -q

fmt:
	python -m pip install ruff
	ruff check --fix . || true

backdoored:
	@echo "SOCP_BACKDOORED=1" > $(ENV_FILE)
	@echo "Backdoored build toggled ON. Subsequent make run targets inherit SOCP_BACKDOORED=1."

clean:
	@echo "SOCP_BACKDOORED=0" > $(ENV_FILE)
	@echo "Clean build toggled. Backdoors disabled."
