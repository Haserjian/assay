.PHONY: assay-receipt-local test-assay-receipt-emitter verify-assay-receipt

ASSAY_PYTEST_COMMAND := PYTHONHASHSEED=0 pytest -q --maxfail=1 --tb=short --junitxml=results.xml
PYTHON ?= python3

assay-receipt-local:
	set +e; \
	$(ASSAY_PYTEST_COMMAND) > pytest.log 2>&1; \
	EC=$$?; \
	set -e; \
	echo "$$EC" > pytest-exit-code.txt; \
	ASSAY_PYTEST_COMMAND="$(ASSAY_PYTEST_COMMAND)" $(PYTHON) scripts/assay_emit_receipt.py \
		--pytest-exit-code "$$EC" \
		--out receipt.json \
		--artifact results.xml \
		--artifact pytest.log \
		--artifact pytest-exit-code.txt; \
	exit "$$EC"

test-assay-receipt-emitter:
	$(PYTHON) -m pytest tests/assay/test_assay_emit_receipt.py -q

verify-assay-receipt:
	test -f receipt.json
	test -f receipt.json.sigstore.json
	test -n "$$ASSAY_CERTIFICATE_IDENTITY"
	cosign verify-blob receipt.json \
		--bundle receipt.json.sigstore.json \
		--certificate-identity "$$ASSAY_CERTIFICATE_IDENTITY" \
		--certificate-oidc-issuer "https://token.actions.githubusercontent.com"
