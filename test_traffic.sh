#!/bin/bash

# Traffic Generation Test for L2 Packet Counter Module
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
PROC_FILE="/proc/${MODULE_NAME}"
TEST_INTERFACE="${1:-eth0}"
TEST_DURATION=10
PING_TARGET="8.8.8.8"

# Helper functions
print_status() {
    echo -e "${BLUE}[TEST]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

print_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# Check if module is loaded
check_module_loaded() {
    if ! lsmod | grep -q "$MODULE_NAME"; then
        print_fail "Module $MODULE_NAME is not loaded"
        echo "Load it first with: sudo make load"
        exit 1
    fi
}

# Generate network traffic
generate_traffic() {
    local duration=$1
    local target=$2
    
    print_status "Generating traffic for $duration seconds to $target..."
    
    # Generate various types of traffic
    {
        # ICMP traffic
        ping -c $((duration * 2)) "$target" >/dev/null 2>&1 &
        
        # DNS lookups
        for i in $(seq 1 $duration); do
            nslookup "test$i.example.com" >/dev/null 2>&1 &
            sleep 1
        done
        
        wait
    } || true
    
    print_status "Traffic generation completed"
}

# Test packet counting
test_packet_counting() {
    print_status "Testing packet counting functionality..."
    
    # Get initial statistics
    local initial_stats=$(cat "$PROC_FILE")
    local initial_count=$(echo "$initial_stats" | grep "Total packets:" | awk '{print $3}')
    
    print_status "Initial packet count: $initial_count"
    
    # Reset statistics
    echo "reset" | sudo tee "$PROC_FILE" >/dev/null
    
    # Verify reset
    local reset_stats=$(cat "$PROC_FILE")
    local reset_count=$(echo "$reset_stats" | grep "Total packets:" | awk '{print $3}')
    
    if [ "$reset_count" -ne 0 ]; then
        print_fail "Statistics not properly reset (count: $reset_count)"
        return 1
    fi
    
    print_success "Statistics reset successfully"
    
    # Generate traffic
    generate_traffic $TEST_DURATION "$PING_TARGET"
    
    # Get final statistics
    local final_stats=$(cat "$PROC_FILE")
    local final_count=$(echo "$final_stats" | grep "Total packets:" | awk '{print $3}')
    
    print_status "Final packet count: $final_count"
    
    # Verify packets were counted
    if [ "$final_count" -eq 0 ]; then
        print_fail "No packets were counted after traffic generation"
        return 1
    fi
    
    # Check for MAC address entries
    local mac_count=$(echo "$final_stats" | grep -E "^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}" | wc -l)
    
    if [ "$mac_count" -eq 0 ]; then
        print_warning "No MAC address entries found (might be normal depending on traffic)"
    else
        print_success "Found $mac_count MAC address entries"
    fi
    
    print_success "Packet counting test completed"
    return 0
}

# Test statistics display
test_stats_display() {
    print_status "Testing statistics display..."
    
    local stats=$(cat "$PROC_FILE")
    
    echo "Current statistics:"
    echo "$stats"
    echo
    
    # Verify required fields
    if ! echo "$stats" | grep -q "Interface:"; then
        print_fail "Missing interface information"
        return 1
    fi
    
    if ! echo "$stats" | grep -q "Total packets:"; then
        print_fail "Missing total packets information"
        return 1
    fi
    
    if ! echo "$stats" | grep -q "MAC Address Statistics:"; then
        print_fail "Missing MAC address statistics header"
        return 1
    fi
    
    print_success "Statistics display format is correct"
    return 0
}

# Test automatic reset functionality
test_auto_reset() {
    print_status "Testing automatic reset (waiting 25 seconds)..."
    
    # Generate some traffic
    generate_traffic 5 "$PING_TARGET"
    
    # Get packet count before reset
    local before_stats=$(cat "$PROC_FILE")
    local before_count=$(echo "$before_stats" | grep "Total packets:" | awk '{print $3}')
    
    if [ "$before_count" -eq 0 ]; then
        print_warning "No packets to test auto-reset with"
        return 0
    fi
    
    print_status "Packet count before auto-reset: $before_count"
    print_status "Waiting for automatic reset (20 second interval)..."
    
    # Wait for auto-reset (module resets every 20 seconds)
    sleep 25
    
    # Get packet count after reset
    local after_stats=$(cat "$PROC_FILE")
    local after_count=$(echo "$after_stats" | grep "Total packets:" | awk '{print $3}')
    
    print_status "Packet count after auto-reset: $after_count"
    
    if [ "$after_count" -eq 0 ]; then
        print_success "Automatic reset working correctly"
        return 0
    else
        print_warning "Automatic reset may not be working (count: $after_count)"
        return 1
    fi
}

# Test concurrent access
test_concurrent_access() {
    print_status "Testing concurrent access to proc interface..."
    
    # Start multiple readers
    for i in {1..5}; do
        (
            for j in {1..10}; do
                cat "$PROC_FILE" >/dev/null 2>&1
                sleep 0.1
            done
        ) &
    done
    
    # Start a writer
    (
        for i in {1..5}; do
            echo "reset" | sudo tee "$PROC_FILE" >/dev/null 2>&1
            sleep 0.5
        done
    ) &
    
    # Wait for all background jobs
    wait
    
    # Verify proc file still works
    if ! cat "$PROC_FILE" >/dev/null 2>&1; then
        print_fail "Proc interface corrupted after concurrent access"
        return 1
    fi
    
    print_success "Concurrent access test passed"
    return 0
}

# Main test execution
main() {
    print_status "Starting L2 Packet Counter Traffic Tests"
    
    # Check prerequisites
    check_module_loaded
    
    if [ ! -f "$PROC_FILE" ]; then
        print_fail "Proc file $PROC_FILE not found"
        exit 1
    fi
    
    # Run tests
    echo "=== Packet Counting Test ==="
    test_packet_counting
    echo
    
    echo "=== Statistics Display Test ==="
    test_stats_display
    echo
    
    echo "=== Concurrent Access Test ==="
    test_concurrent_access
    echo
    
    echo "=== Automatic Reset Test ==="
    if [ "${2:-}" = "--skip-auto-reset" ]; then
        print_warning "Skipping automatic reset test (--skip-auto-reset)"
    else
        test_auto_reset
    fi
    
    print_success "All traffic tests completed successfully!"
}

# Show usage
if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
    echo "Usage: $0 [INTERFACE] [--skip-auto-reset] [--help]"
    echo "  INTERFACE          Network interface to test (default: eth0)"
    echo "  --skip-auto-reset  Skip the automatic reset test (saves time)"
    echo "  --help             Show this help message"
    exit 0
fi

# Run main function
main "$@"