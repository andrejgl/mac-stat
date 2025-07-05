#!/bin/bash

# Stress Test for L2 Packet Counter Module
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
TEST_DURATION=30
STRESS_PROCESSES=10

# Helper functions
print_status() {
    echo -e "${BLUE}[STRESS]${NC} $1"
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

# Memory usage monitoring
monitor_memory() {
    local duration=$1
    local interval=5
    local count=$((duration / interval))
    
    print_status "Monitoring memory usage for $duration seconds..."
    
    for i in $(seq 1 $count); do
        local mem_info=$(grep -E "MemTotal|MemAvailable|Slab" /proc/meminfo)
        local timestamp=$(date '+%H:%M:%S')
        
        echo "[$timestamp] Memory info:"
        echo "$mem_info" | while read line; do
            echo "  $line"
        done
        echo
        
        sleep $interval
    done
}

# High-frequency proc reads
stress_proc_reads() {
    local duration=$1
    local process_id=$2
    
    local end_time=$(($(date +%s) + duration))
    local read_count=0
    
    while [ $(date +%s) -lt $end_time ]; do
        if cat "$PROC_FILE" >/dev/null 2>&1; then
            ((read_count++))
        else
            print_fail "Process $process_id: proc read failed at count $read_count"
            return 1
        fi
        
        # Small delay to prevent overwhelming the system
        sleep 0.01
    done
    
    echo "Process $process_id: completed $read_count reads"
    return 0
}

# High-frequency proc writes
stress_proc_writes() {
    local duration=$1
    local process_id=$2
    
    local end_time=$(($(date +%s) + duration))
    local write_count=0
    
    while [ $(date +%s) -lt $end_time ]; do
        if echo "reset" | sudo tee "$PROC_FILE" >/dev/null 2>&1; then
            ((write_count++))
        else
            print_fail "Process $process_id: proc write failed at count $write_count"
            return 1
        fi
        
        # Delay between writes
        sleep 0.1
    done
    
    echo "Process $process_id: completed $write_count writes"
    return 0
}

# Network traffic generation
generate_heavy_traffic() {
    local duration=$1
    
    print_status "Generating heavy network traffic for $duration seconds..."
    
    # Multiple ping processes
    for i in $(seq 1 5); do
        ping -f -c $((duration * 100)) "8.8.8.8" >/dev/null 2>&1 &
    done
    
    # DNS queries
    for i in $(seq 1 3); do
        (
            local end_time=$(($(date +%s) + duration))
            local query_count=0
            while [ $(date +%s) -lt $end_time ]; do
                nslookup "test$query_count.example.com" >/dev/null 2>&1 || true
                ((query_count++))
                sleep 0.1
            done
        ) &
    done
    
    wait
    print_status "Heavy traffic generation completed"
}

# Test rapid module load/unload
test_rapid_load_unload() {
    print_status "Testing rapid module load/unload cycles..."
    
    # First unload if loaded
    if lsmod | grep -q "$MODULE_NAME"; then
        sudo rmmod "$MODULE_NAME" || return 1
    fi
    
    local cycles=20
    for i in $(seq 1 $cycles); do
        print_status "Load/unload cycle $i/$cycles"
        
        # Load module
        if ! sudo insmod "${MODULE_NAME}.ko" interface="eth0" 2>/dev/null; then
            print_fail "Failed to load module in cycle $i"
            return 1
        fi
        
        # Brief operation
        if [ -f "$PROC_FILE" ]; then
            cat "$PROC_FILE" >/dev/null 2>&1 || true
        fi
        
        # Unload module
        if ! sudo rmmod "$MODULE_NAME" 2>/dev/null; then
            print_fail "Failed to unload module in cycle $i"
            return 1
        fi
        
        # Brief delay
        sleep 0.1
    done
    
    # Reload for other tests
    sudo insmod "${MODULE_NAME}.ko" interface="eth0" 2>/dev/null || return 1
    
    print_success "Rapid load/unload test completed"
    return 0
}

# Test concurrent proc access
test_concurrent_proc_access() {
    print_status "Testing concurrent proc file access..."
    
    # Start memory monitoring in background
    monitor_memory $TEST_DURATION &
    local monitor_pid=$!
    
    # Start multiple read processes
    for i in $(seq 1 $STRESS_PROCESSES); do
        stress_proc_reads $TEST_DURATION $i &
    done
    
    # Start fewer write processes (more expensive)
    for i in $(seq 1 $((STRESS_PROCESSES / 2))); do
        stress_proc_writes $TEST_DURATION $((i + 100)) &
    done
    
    # Generate network traffic
    generate_heavy_traffic $TEST_DURATION &
    
    # Wait for all processes
    wait
    
    # Stop memory monitoring
    kill $monitor_pid 2>/dev/null || true
    
    # Verify proc file still works
    if ! cat "$PROC_FILE" >/dev/null 2>&1; then
        print_fail "Proc file corrupted after stress test"
        return 1
    fi
    
    print_success "Concurrent proc access stress test passed"
    return 0
}

# Test large packet bursts
test_packet_burst() {
    print_status "Testing large packet burst handling..."
    
    # Reset statistics
    echo "reset" | sudo tee "$PROC_FILE" >/dev/null
    
    # Generate burst traffic
    print_status "Generating packet burst..."
    
    # Create multiple simultaneous connections
    for i in $(seq 1 20); do
        {
            # Fast ping
            ping -f -c 100 "8.8.8.8" >/dev/null 2>&1 || true
            
            # Multiple DNS queries
            for j in $(seq 1 50); do
                nslookup "burst$i-$j.example.com" >/dev/null 2>&1 || true
            done
        } &
    done
    
    wait
    
    # Check statistics
    local stats=$(cat "$PROC_FILE")
    local packet_count=$(echo "$stats" | grep "Total packets:" | awk '{print $3}')
    
    print_status "Packet count after burst: $packet_count"
    
    if [ "$packet_count" -eq 0 ]; then
        print_warning "No packets counted (might be normal depending on network setup)"
    else
        print_success "Packet burst test completed"
    fi
    
    return 0
}

# Test error conditions
test_error_conditions() {
    print_status "Testing error conditions..."
    
    # Test invalid interface (should fail gracefully)
    if lsmod | grep -q "$MODULE_NAME"; then
        sudo rmmod "$MODULE_NAME" || return 1
    fi
    
    # Try to load with invalid interface
    if sudo insmod "${MODULE_NAME}.ko" interface="invalid_interface" 2>/dev/null; then
        print_fail "Module loaded with invalid interface"
        sudo rmmod "$MODULE_NAME" 2>/dev/null || true
        return 1
    fi
    
    print_success "Invalid interface properly rejected"
    
    # Reload with valid interface
    sudo insmod "${MODULE_NAME}.ko" interface="eth0" 2>/dev/null || return 1
    
    # Test very long proc writes
    local long_string=$(printf 'a%.0s' {1..1000})
    if echo "$long_string" | sudo tee "$PROC_FILE" >/dev/null 2>&1; then
        print_warning "Very long proc write was accepted"
    else
        print_success "Very long proc write properly rejected"
    fi
    
    return 0
}

# System resource check
check_system_resources() {
    print_status "Checking system resources..."
    
    # Check available memory
    local mem_available=$(grep MemAvailable /proc/meminfo | awk '{print $2}')
    local mem_total=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    local mem_percent=$((mem_available * 100 / mem_total))
    
    print_status "Available memory: $mem_percent%"
    
    if [ $mem_percent -lt 10 ]; then
        print_warning "Low memory available ($mem_percent%)"
    fi
    
    # Check CPU load
    local load_avg=$(uptime | awk -F'load average:' '{print $2}' | awk '{print $1}' | tr -d ',')
    local cpu_count=$(nproc)
    
    print_status "Load average: $load_avg (CPUs: $cpu_count)"
    
    # Check disk space
    local disk_usage=$(df . | tail -1 | awk '{print $5}' | tr -d '%')
    print_status "Disk usage: $disk_usage%"
    
    if [ $disk_usage -gt 90 ]; then
        print_warning "High disk usage ($disk_usage%)"
    fi
}

# Main test execution
main() {
    print_status "Starting L2 Packet Counter Stress Tests"
    print_status "Test duration: $TEST_DURATION seconds"
    print_status "Stress processes: $STRESS_PROCESSES"
    
    # Check prerequisites
    check_module_loaded
    check_system_resources
    
    echo
    echo "=== Rapid Load/Unload Test ==="
    test_rapid_load_unload
    echo
    
    echo "=== Error Conditions Test ==="
    test_error_conditions
    echo
    
    echo "=== Packet Burst Test ==="
    test_packet_burst
    echo
    
    echo "=== Concurrent Access Stress Test ==="
    test_concurrent_proc_access
    echo
    
    check_system_resources
    
    print_success "All stress tests completed successfully!"
}

# Show usage
if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
    echo "Usage: $0 [--duration SECONDS] [--processes COUNT] [--help]"
    echo "  --duration SECONDS   Test duration in seconds (default: $TEST_DURATION)"
    echo "  --processes COUNT    Number of stress processes (default: $STRESS_PROCESSES)"
    echo "  --help               Show this help message"
    exit 0
fi

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --duration)
            TEST_DURATION="$2"
            shift 2
            ;;
        --processes)
            STRESS_PROCESSES="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Run main function
main "$@"