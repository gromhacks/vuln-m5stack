# Convenience targets for building, testing, and flashing

CORES3_BASE ?= http://192.168.4.1

.PHONY: build flash monitor test test-device test-device-destructive

build:
	source .venv/bin/activate && pio run -e M5CoreS3

flash:
	source .venv/bin/activate && pio run -e M5CoreS3 -t upload

monitor:
	source .venv/bin/activate && pio device monitor -b 115200

test:
	SKIP_PIO_TESTS=1 python3 -u unittests/test_all_labs.py

test-device:
	SKIP_PIO_TESTS=1 CORES3_BASE=$(CORES3_BASE) python3 -u unittests/test_all_labs.py

test-device-destructive:
	SKIP_PIO_TESTS=1 CORES3_BASE=$(CORES3_BASE) CORES3_DESTRUCTIVE=1 python3 -u unittests/test_all_labs.py
