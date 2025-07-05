# Makefile for Layer 2 Packet Counter Kernel Module

# Module name
MODULE_NAME := l2packet_counter

# Kernel build directory (automatically detected)
KDIR ?= /lib/modules/$(shell uname -r)/build

# Build directory
PWD := $(shell pwd)

# Default target
all: build

# Build the module
build:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

# Clean build artifacts
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -rf Module.symvers modules.order

# Install module (requires root)
install: build
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install
	depmod -a

# Load the module
load: build
	sudo insmod $(MODULE_NAME).ko interface=$(INTERFACE)

# Unload the module
unload:
	sudo rmmod $(MODULE_NAME)

# Reload the module
reload: unload load

# Show module information
info:
	modinfo $(MODULE_NAME).ko

# Show kernel messages
dmesg:
	dmesg | tail -20

# Show statistics
stats:
	cat /proc/$(MODULE_NAME)

# Reset statistics manually
reset:
	echo "reset" | sudo tee /proc/$(MODULE_NAME)

# Check if module is loaded
status:
	lsmod | grep $(MODULE_NAME) || echo "Module not loaded"

# Run tests
test:
	@echo "Running tests requires root privileges."
	@echo "Please run: sudo ./run_tests.sh"
	@echo "Or run individual test scripts with sudo."

test-basic:
	@echo "Running basic tests requires root privileges."
	@echo "Please run: sudo ./run_tests.sh basic"

test-traffic:
	@echo "Running traffic tests requires root privileges."
	@echo "Please run: sudo ./run_tests.sh traffic"

test-stress:
	@echo "Running stress tests requires root privileges."
	@echo "Please run: sudo ./run_tests.sh stress"

# Help target
help:
	@echo "Available targets:"
	@echo "  build     - Build the kernel module"
	@echo "  clean     - Clean build artifacts"
	@echo "  install   - Install module to system (requires root)"
	@echo "  load      - Load module (use INTERFACE=ethX to specify interface)"
	@echo "  unload    - Unload module"
	@echo "  reload    - Unload and reload module"
	@echo "  info      - Show module information"
	@echo "  dmesg     - Show recent kernel messages"
	@echo "  stats     - Show current statistics"
	@echo "  reset     - Reset statistics manually"
	@echo "  status    - Check if module is loaded"
	@echo "  test      - Run all tests"
	@echo "  test-basic - Run basic tests only"
	@echo "  test-traffic - Run traffic tests only"
	@echo "  test-stress - Run stress tests only"
	@echo "  help      - Show this help"
	@echo ""
	@echo "Examples:"
	@echo "  make build"
	@echo "  make load INTERFACE=eth0"
	@echo "  make stats"
	@echo "  make reset"
	@echo "  make test"

# Default interface for loading
INTERFACE ?= eth0

.PHONY: all build clean install load unload reload info dmesg stats reset status test test-basic test-traffic test-stress help
