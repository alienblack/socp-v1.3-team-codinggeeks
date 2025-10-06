
    .PHONY: run-server run-client test fmt
    run-server:
	python -m socp.cmd.server --config configs/server.yaml
    run-client:
	python -m socp.cmd.client --server ws://127.0.0.1:7001
    test:
	pytest -q
    fmt:
	python -m pip install ruff; ruff check --fix . || true
