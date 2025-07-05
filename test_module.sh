#!/bin/bash

# Test Suite for L2 Packet Counter Kernel Module
# Author: Andrejs Glazkovs
# License: GPL-2.0

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
MODULE_NAME="l2packet_counter"
MODULE_FILE="${MODULE_NAME}.ko"
PROC_FILE="/proc/${MODULE_NAME}"
TEST_INTERFACE="${1:-eth0}"
TEST_LOG="/tmp/module_test.log"

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_TOTAL=0

# Helper functions
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$TEST_LOG"
}

print_status() {
    echo -e "${BLUE}[TEST]${NC} $1" | tee -a "$TEST_LOG"
}

print_success() {
    echo -e "${GREEN}[PASS]${NC} $1" | tee -a "$TEST_LOG"
    TESTS_PASSED=$((TESTS_PASSED + 1))
}

print_fail() {
    echo -e "${RED}[FAIL]${NC} $1" | tee -a "$TEST_LOG"
    TESTS_FAILED=$((TESTS_FAILED + 1))
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$TEST_LOG"
}

# Test execution wrapper
run_test() {
    local test_name="$1"
    local test_func="$2"
    
    print_status "Running test: $test_name"
    TESTS_TOTAL=$((TESTS_TOTAL + 1))
    
    if $test_func; then
        print_success "$test_name"
    else
        print_fail "$test_name"
    fi
}

# Cleanup function
cleanup() {
    print_status "Cleaning up..."
    
    # Unload module if loaded
    if lsmod | grep -q "$MODULE_NAME"; then
        sudo rmmod "$MODULE_NAME" 2>/dev/null || true
    fi
    
    # Remove test artifacts
    rm -f "$TEST_LOG" 2>/dev/null || true
}

# Signal handler
trap cleanup EXIT

# Test 1: Module file exists and is valid
test_module_file() {
    if [ ! -f "$MODULE_FILE" ]; then
        log "ERROR: Module file $MODULE_FILE not found"
        return 1
    fi
    
    if ! file "$MODULE_FILE" | grep -q "ELF.*relocatable"; then
        log "ERROR: Module file is not a valid ELF relocatable object"
        return 1
    fi
    
    log "Module file $MODULE_FILE is valid"
    return 0
}

# Test 2: Module info
test_module_info() {
    if ! modinfo "$MODULE_FILE" >/dev/null 2>&1; then
        log "ERROR: Cannot get module info"
        return 1
    fi
    
    local license=$(modinfo "$MODULE_FILE" | grep "license:" | awk '{print $2}')
    if [ "$license" != "GPL" ]; then
        log "ERROR: Module license is not GPL (found: $license)"
        return 1
    fi
    
    log "Module info is valid"
    return 0
}

# Test 3: Module loading
test_module_load() {
    # Ensure module is not loaded
    if lsmod | grep -q "$MODULE_NAME"; then
        sudo rmmod "$MODULE_NAME" || return 1
    fi
    
    # Load module
    if ! sudo insmod "$MODULE_FILE" interface="$TEST_INTERFACE" 2>/dev/null; then
        log "ERROR: Cannot load module"
        return 1
    fi
    
    # Verify module is loaded
    if ! lsmod | grep -q "$MODULE_NAME"; then
        log "ERROR: Module not found in lsmod after loading"
        return 1
    fi
    
    log "Module loaded successfully"
    return 0
}

# Test 4: Proc interface creation
test_proc_interface() {
    if [ ! -f "$PROC_FILE" ]; then
        log "ERROR: Proc file $PROC_FILE not created"
        return 1
    fi
    
    if [ ! -r "$PROC_FILE" ]; then
        log "ERROR: Proc file $PROC_FILE not readable"
        return 1
    fi
    
    if [ ! -w "$PROC_FILE" ]; then
        log "ERROR: Proc file $PROC_FILE not writable"
        return 1
    fi
    
    log "Proc interface created successfully"
    return 0
}

# Test 5: Proc interface content
test_proc_content() {
    local content=$(cat "$PROC_FILE" 2>/dev/null)
    
    if [ -z "$content" ]; then
        log "ERROR: Proc file content is empty"
        return 1
    fi
    
    if ! echo "$content" | grep -q "Interface:"; then
        log "ERROR: Proc file missing interface information"
        return 1
    fi
    
    if ! echo "$content" | grep -q "Total packets:"; then
        log "ERROR: Proc file missing total packets information"
        return 1
    fi
    
    if ! echo "$content" | grep -q "MAC Address Statistics:"; then
        log "ERROR: Proc file missing MAC address statistics"
        return 1
    fi
    
    log "Proc interface content is valid"
    return 0
}

# Test 6: Statistics reset functionality
test_stats_reset() {
    # Reset statistics
    if ! echo "reset" | sudo tee "$PROC_FILE" >/dev/null 2>&1; then
        log "ERROR: Cannot reset statistics"
        return 1
    fi
    
    # Verify reset worked (should show 0 packets)
    local content=$(cat "$PROC_FILE" 2>/dev/null)
    if ! echo "$content" | grep -q "Total packets: 0"; then
        log "ERROR: Statistics not reset properly"
        return 1
    fi
    
    log "Statistics reset functionality works"
    return 0
}

# Test 7: Invalid proc commands
test_invalid_proc_commands() {
    # Test invalid command
    if echo "invalid_command" | sudo tee "$PROC_FILE" >/dev/null 2>&1; then
        log "ERROR: Invalid command was accepted"
        return 1
    fi
    
    log "Invalid proc commands properly rejected"
    return 0
}

# Test 8: Module unloading
test_module_unload() {
    if ! sudo rmmod "$MODULE_NAME" 2>/dev/null; then
        log "ERROR: Cannot unload module"
        return 1
    fi
    
    # Verify module is unloaded
    if lsmod | grep -q "$MODULE_NAME"; then
        log "ERROR: Module still loaded after rmmod"
        return 1
    fi
    
    # Verify proc file is removed
    if [ -f "$PROC_FILE" ]; then
        log "ERROR: Proc file still exists after module unload"
        return 1
    fi
    
    log "Module unloaded successfully"
    return 0
}

# Test 9: Load with different interface
test_interface_parameter() {
    # Test with lo interface (should fail)
    if sudo insmod "$MODULE_FILE" interface="lo" 2>/dev/null; then
        log "ERROR: Module loaded with loopback interface (should fail)"
        sudo rmmod "$MODULE_NAME" 2>/dev/null || true
        return 1
    fi
    
    log "Interface parameter validation works"
    return 0
}

# Test 10: Multiple load/unload cycles
test_multiple_cycles() {
    for i in {1..3}; do
        # Load
        if ! sudo insmod "$MODULE_FILE" interface="$TEST_INTERFACE" 2>/dev/null; then
            log "ERROR: Cannot load module in cycle $i"
            return 1
        fi
        
        # Verify loaded
        if ! lsmod | grep -q "$MODULE_NAME"; then
            log "ERROR: Module not loaded in cycle $i"
            return 1
        fi
        
        # Unload
        if ! sudo rmmod "$MODULE_NAME" 2>/dev/null; then
            log "ERROR: Cannot unload module in cycle $i"
            return 1
        fi
        
        # Verify unloaded
        if lsmod | grep -q "$MODULE_NAME"; then
            log "ERROR: Module still loaded after unload in cycle $i"
            return 1
        fi
    done
    
    log "Multiple load/unload cycles successful"
    return 0
}

# Show usage
show_usage() {
    echo "Usage: $0 [INTERFACE] [--help]"
    echo "  INTERFACE   Network interface to test (default: eth0)"
    echo "  --help      Show this help message"
    echo
    echo "Examples:"
    echo "  sudo $0 eth0"
    echo "  sudo $0 enp0s3"
    exit 0
}

# Main test execution
main() {
    # Handle help option
    if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
        show_usage
    fi
    
    print_status "Starting L2 Packet Counter Module Test Suite"
    print_status "Testing with interface: $TEST_INTERFACE"
    log "Test started at $(date)"
    log "Using interface: $TEST_INTERFACE"
    
    # Check if running as root
    if [ "$EUID" -ne 0 ]; then
        print_fail "Tests must be run as root"
        exit 1
    fi
    
    # Check if interface exists
    if ! ip link show "$TEST_INTERFACE" >/dev/null 2>&1; then
        print_fail "Interface $TEST_INTERFACE not found"
        echo "Available interfaces:"
        ip link show | grep -E "^[0-9]+:" | awk -F': ' '{print "  " $2}'
        exit 1
    fi
    
    # Build module first
    print_status "Building module..."
    if ! make build >/dev/null 2>&1; then
        print_fail "Module build failed"
        exit 1
    fi
    
    # Run tests
    run_test "Module file validation" test_module_file
    run_test "Module info validation" test_module_info
    run_test "Module loading" test_module_load
    run_test "Proc interface creation" test_proc_interface
    run_test "Proc interface content" test_proc_content
    run_test "Statistics reset" test_stats_reset
    run_test "Invalid proc commands" test_invalid_proc_commands
    run_test "Module unloading" test_module_unload
    run_test "Interface parameter validation" test_interface_parameter
    run_test "Multiple load/unload cycles" test_multiple_cycles
    
    # Test summary
    echo
    print_status "Test Summary:"
    log "Tests passed: $TESTS_PASSED"
    log "Tests failed: $TESTS_FAILED"
    log "Tests total:  $TESTS_TOTAL"
    
    if [ $TESTS_FAILED -eq 0 ]; then
        print_success "All tests passed!"
        exit 0
    else
        print_fail "Some tests failed!"
        exit 1
    fi
}

# Run main function
main "$@"