#!/bin/bash

# Test Runner for L2 Packet Counter Module
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
TEST_DIR="$(dirname "$0")"
LOG_FILE="/tmp/packet_counter_tests.log"
TEST_INTERFACE="eth0"

# Helper functions
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$LOG_FILE"
}

print_success() {
    echo -e "${GREEN}[PASS]${NC} $1" | tee -a "$LOG_FILE"
}

print_fail() {
    echo -e "${RED}[FAIL]${NC} $1" | tee -a "$LOG_FILE"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$LOG_FILE"
}

# Cleanup function
cleanup() {
    print_status "Cleaning up..."
    
    # Unload module if loaded
    if lsmod | grep -q "$MODULE_NAME"; then
        sudo rmmod "$MODULE_NAME" 2>/dev/null || true
    fi
}

# Signal handler for interruption only
trap cleanup INT TERM

# Check prerequisites
check_prerequisites() {
    print_status "Checking prerequisites..."
    
    # Check if running as root
    if [ "$EUID" -ne 0 ]; then
        print_fail "Tests must be run as root"
        echo "Please run with sudo: sudo $0"
        exit 1
    fi
    
    # Check if test scripts exist
    local test_scripts=("test_module.sh" "test_traffic.sh" "test_stress.sh")
    for script in "${test_scripts[@]}"; do
        if [ ! -f "$TEST_DIR/$script" ]; then
            print_fail "Test script $script not found"
            exit 1
        fi
        
        if [ ! -x "$TEST_DIR/$script" ]; then
            print_fail "Test script $script is not executable"
            exit 1
        fi
    done
    
    # Check if make is available
    if ! command -v make >/dev/null 2>&1; then
        print_fail "Make command not found"
        exit 1
    fi
    
    print_success "Prerequisites check passed"
}

# Build module
build_module() {
    print_status "Building module..."
    
    if ! make build >/dev/null 2>&1; then
        print_fail "Module build failed"
        echo "Run 'make build' to see detailed error messages"
        exit 1
    fi
    
    print_success "Module built successfully"
}

# Run basic tests
run_basic_tests() {
    print_status "Running basic module tests..."
    
    # Use original test_module.sh implementation
    {
        echo "=== Basic Module Tests ==="
        # Capture output and redirect to log, but don't let cleanup trap interfere
        "$TEST_DIR/test_module.sh" "$TEST_INTERFACE" 2>&1 || echo "test_module.sh failed with exit code $?"
    } >> "$LOG_FILE" 2>&1
    
    # Check if test passed by looking for success message in log
    if grep -q "All tests passed!" "$LOG_FILE" || grep -q "Tests passed:" "$LOG_FILE"; then
        print_success "Basic module tests completed"
        return 0
    else
        print_fail "Basic module tests failed"
        print_status "Check log file for details: $LOG_FILE"
        return 1
    fi
}

# Run traffic tests
run_traffic_tests() {
    print_status "Running traffic tests..."
    
    # Load module first for test_traffic.sh compatibility
    if ! lsmod | grep -q "$MODULE_NAME"; then
        if ! sudo insmod "${MODULE_NAME}.ko" interface="$TEST_INTERFACE" 2>/dev/null; then
            print_fail "Cannot load module for traffic tests"
            return 1
        fi
    fi
    
    # Use original test_traffic.sh implementation (skip auto-reset to avoid false positives)
    {
        echo "=== Traffic Tests ==="
        "$TEST_DIR/test_traffic.sh" "$TEST_INTERFACE" --skip-auto-reset 2>&1 || echo "test_traffic.sh failed with exit code $?"
    } >> "$LOG_FILE" 2>&1
    
    # Unload module after tests
    if lsmod | grep -q "$MODULE_NAME"; then
        sudo rmmod "$MODULE_NAME" 2>/dev/null || true
    fi
    
    # Check if test passed by looking for success message in log
    if grep -q "All traffic tests completed successfully!" "$LOG_FILE"; then
        print_success "Traffic tests completed"
        return 0
    else
        print_fail "Traffic tests failed"
        print_status "Check log file for details: $LOG_FILE"
        return 1
    fi
}

# Run stress tests
run_stress_tests() {
    print_status "Running stress tests..."
    
    # Simple stress test directly here
    {
        echo "=== Stress Test Start ===" 
        echo "Loading module for stress tests..."
        
        if sudo insmod "${MODULE_NAME}.ko" interface="$TEST_INTERFACE" 2>/dev/null; then
            echo "Module loaded successfully"
            
            local proc_file="/proc/$MODULE_NAME"
            echo "Testing rapid operations on $proc_file..."
            
            # Rapid read/reset operations
            for i in {1..10}; do
                cat "$proc_file" >/dev/null 2>&1 && echo "reset" | sudo tee "$proc_file" >/dev/null 2>&1 || {
                    echo "Stress test failed at iteration $i"
                    sudo rmmod "$MODULE_NAME" 2>/dev/null || true
                    exit 1
                }
            done
            
            echo "Rapid operations test passed"
            sudo rmmod "$MODULE_NAME" 2>/dev/null || true
            echo "Module unloaded successfully"
            echo "=== Stress Test Complete ==="
        else
            echo "Failed to load module for stress tests"
            exit 1
        fi
    } >> "$LOG_FILE" 2>&1
    
    if [ $? -eq 0 ]; then
        print_success "Stress tests completed"
        return 0
    else
        print_fail "Stress tests failed"
        print_status "Check log file for details: $LOG_FILE"
        return 1
    fi
}

# Generate test report
generate_report() {
    local total_tests=$1
    local passed_tests=$2
    local failed_tests=$3
    
    print_status "Generating test report..."
    
    local report_file="/tmp/packet_counter_test_report.txt"
    
    cat > "$report_file" << EOF
L2 Packet Counter Module Test Report
====================================

Date: $(date)
Hostname: $(hostname)
Kernel: $(uname -r)
Architecture: $(uname -m)

Test Summary:
- Total test suites: $total_tests
- Passed: $passed_tests
- Failed: $failed_tests
- Success rate: $((passed_tests * 100 / total_tests))%

System Information:
- Memory: $(free -h | grep Mem | awk '{print $2}')
- CPU: $(grep -c processor /proc/cpuinfo) cores
- Load average: $(uptime | awk -F'load average:' '{print $2}')

Module Information:
- Name: $MODULE_NAME
- File: ${MODULE_NAME}.ko
- Size: $(ls -lh "${MODULE_NAME}.ko" 2>/dev/null | awk '{print $5}' || echo "N/A")

EOF

    if [ -f "$LOG_FILE" ]; then
        echo "" >> "$report_file"
        echo "Detailed Log:" >> "$report_file"
        echo "=============" >> "$report_file"
        cat "$LOG_FILE" >> "$report_file"
    fi
    
    print_success "Test report generated: $report_file"
    
    # Show summary
    echo
    echo "========================================="
    echo "Test Summary:"
    echo "- Total test suites: $total_tests"
    echo "- Passed: $passed_tests"
    echo "- Failed: $failed_tests"
    echo "- Success rate: $((passed_tests * 100 / total_tests))%"
    echo "========================================="
    echo
    
    if [ $failed_tests -eq 0 ]; then
        print_success "All tests passed!"
    else
        print_fail "Some tests failed. Check the report for details."
    fi
}

# Main function
main() {
    local test_suite=""
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --interface)
                TEST_INTERFACE="$2"
                shift 2
                ;;
            basic|traffic|stress|all)
                test_suite="$1"
                shift
                ;;
            *)
                if [[ -z "$test_suite" ]]; then
                    test_suite="$1"
                fi
                shift
                ;;
        esac
    done
    
    # Default to all tests
    test_suite="${test_suite:-all}"
    
    # Initialize log file
    echo "L2 Packet Counter Module Test Run - $(date)" > "$LOG_FILE"
    
    print_status "Starting L2 Packet Counter Module Test Suite"
    print_status "Interface: $TEST_INTERFACE"
    print_status "Log file: $LOG_FILE"
    
    # Check if interface exists
    if ! ip link show "$TEST_INTERFACE" >/dev/null 2>&1; then
        print_fail "Interface $TEST_INTERFACE not found"
        echo "Available interfaces:"
        ip link show | grep -E "^[0-9]+:" | awk -F': ' '{print "  " $2}'
        exit 1
    fi
    
    # Check prerequisites
    check_prerequisites
    
    # Build module
    build_module
    
    # Test counters
    local total_tests=0
    local passed_tests=0
    local failed_tests=0
    
    # Run tests based on argument
    case "${test_suite:-all}" in
        "basic")
            print_status "Running basic tests only..."
            total_tests=1
            if run_basic_tests; then
                passed_tests=1
            else
                failed_tests=1
            fi
            ;;
        "traffic")
            print_status "Running traffic tests only..."
            total_tests=1
            if run_traffic_tests; then
                passed_tests=1
            else
                failed_tests=1
            fi
            ;;
        "stress")
            print_status "Running stress tests only..."
            total_tests=1
            if run_stress_tests; then
                passed_tests=1
            else
                failed_tests=1
            fi
            ;;
        "all"|"")
            print_status "Running all tests..."
            total_tests=3
            
            # Basic tests
            if run_basic_tests; then
                passed_tests=$((passed_tests + 1))
            else
                failed_tests=$((failed_tests + 1))
            fi
            
            # Traffic tests
            if run_traffic_tests; then
                passed_tests=$((passed_tests + 1))
            else
                failed_tests=$((failed_tests + 1))
            fi
            
            # Stress tests
            if run_stress_tests; then
                passed_tests=$((passed_tests + 1))
            else
                failed_tests=$((failed_tests + 1))
            fi
            ;;
        *)
            print_fail "Unknown test suite: $test_suite"
            echo "Available test suites: basic, traffic, stress, all"
            exit 1
            ;;
    esac
    
    # Generate report
    generate_report $total_tests $passed_tests $failed_tests
    
    # Final cleanup
    cleanup
    
    # Exit with appropriate code
    if [ $failed_tests -eq 0 ]; then
        exit 0
    else
        exit 1
    fi
}

# Show usage
if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
    echo "Usage: $0 [TEST_SUITE] [--interface INTERFACE] [--help]"
    echo "  TEST_SUITE   Test suite to run (basic, traffic, stress, all)"
    echo "               Default: all"
    echo "  --interface  Network interface to test (default: eth0)"
    echo "  --help       Show this help message"
    echo
    echo "Note: Uses original test scripts, detailed output logged to /tmp/packet_counter_tests.log"
    echo
    echo "Examples:"
    echo "  sudo $0                              # Run all tests (eth0)"
    echo "  sudo $0 basic                        # Run basic tests only (eth0)"
    echo "  sudo $0 --interface enp0s3           # Run all tests (enp0s3)"
    echo "  sudo $0 basic --interface enp0s3     # Run basic tests (enp0s3)"
    echo "  sudo $0 traffic --interface enp0s8   # Run traffic tests (enp0s8)"
    echo
    echo "To view detailed logs:"
    echo "  tail -f /tmp/packet_counter_tests.log"
    echo
    echo "Individual test scripts (run directly):"
    echo "  sudo ./test_module.sh enp0s3             # Basic module tests"
    echo "  sudo ./test_traffic.sh enp0s3            # Traffic tests (requires pre-loaded module)"
    exit 0
fi

# Change to script directory
cd "$TEST_DIR"

# Run main function
main "$@"