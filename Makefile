.PHONY: check ci
check:
	python3 conformance/check_wasm_gas_envelope.py

ci:
	python3 conformance/check_wasm_gas_envelope.py --strict-ci
