#!/bin/bash

# Installation script for Layer 2 Packet Counter Kernel Module
# Author: Andrejs Glazkovs
# License: GPL-2.0

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
MODULE_NAME="l2packet_counter"
DEFAULT_INTERFACE="eth0"

# Print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        print_warning "Running as root. This is required for module operations."
    else
        print_error "This script requires root privileges for module installation."
        echo "Please run with sudo: sudo $0"
        exit 1
    fi
}

# Check system requirements
check_requirements() {
    print_status "Checking system requirements..."
    
    # Check if kernel headers are installed
    KERNEL_VERSION=$(uname -r)
    HEADERS_PATH="/lib/modules/$KERNEL_VERSION/build"
    
    if [ ! -d "$HEADERS_PATH" ]; then
        print_error "Kernel headers not found at $HEADERS_PATH"
        echo "Please install kernel headers:"
        echo "  Ubuntu/Debian: sudo apt install linux-headers-\$(uname -r)"
        echo "  CentOS/RHEL:   sudo yum install kernel-devel-\$(uname -r)"
        echo "  Fedora:        sudo dnf install kernel-devel-\$(uname -r)"
        exit 1
    fi
    
    # Check for required tools
    for tool in gcc make; do
        if ! command -v $tool &> /dev/null; then
            print_error "$tool is not installed"
            echo "Please install build tools:"
            echo "  Ubuntu/Debian: sudo apt install build-essential"
            echo "  CentOS/RHEL:   sudo yum groupinstall 'Development Tools'"
            echo "  Fedora:        sudo dnf groupinstall 'Development Tools'"
            exit 1
        fi
    done
    
    print_success "All requirements satisfied"
}

# Detect available network interfaces
detect_interfaces() {
    print_status "Detecting available network interfaces..."
    
    # Get list of ethernet interfaces (excluding loopback)
    INTERFACES=$(ip -o link show | awk -F': ' '{print $2}' | grep -v lo | head -10)
    
    if [ -z "$INTERFACES" ]; then
        print_warning "No network interfaces detected"
        INTERFACE=$DEFAULT_INTERFACE
    else
        echo "Available interfaces:"
        echo "$INTERFACES" | nl -w2 -s') '
        echo
        read -p "Enter interface name (default: $DEFAULT_INTERFACE): " INTERFACE
        INTERFACE=${INTERFACE:-$DEFAULT_INTERFACE}
    fi
    
    print_status "Will monitor interface: $INTERFACE"
}

# Build the module
build_module() {
    print_status "Building kernel module..."
    
    if make clean &> /dev/null && make build &> /dev/null; then
        print_success "Module built successfully"
    else
        print_error "Failed to build module"
        echo "Run 'make build' manually to see detailed error messages"
        exit 1
    fi
}

# Install the module
install_module() {
    print_status "Installing kernel module..."
    
    # Check if module is already loaded
    if lsmod | grep -q "$MODULE_NAME"; then
        print_warning "Module already loaded, unloading first..."
        rmmod "$MODULE_NAME" || {
            print_error "Failed to unload existing module"
            exit 1
        }
    fi
    
    # Load the module
    if insmod "${MODULE_NAME}.ko" interface="$INTERFACE"; then
        print_success "Module loaded successfully"
        
        # Verify module is loaded
        if lsmod | grep -q "$MODULE_NAME"; then
            print_success "Module verification passed"
        else
            print_error "Module verification failed"
            exit 1
        fi
    else
        print_error "Failed to load module"
        echo "Check dmesg for error messages: dmesg | tail -10"
        exit 1
    fi
}

# Create systemd service for automatic loading
create_service() {
    read -p "Create systemd service for automatic loading? (y/N): " CREATE_SERVICE
    
    if [[ $CREATE_SERVICE =~ ^[Yy]$ ]]; then
        print_status "Creating systemd service..."
        
        SERVICE_FILE="/etc/systemd/system/${MODULE_NAME}.service"
        
        cat > "$SERVICE_FILE" << EOF
[Unit]
Description=Layer 2 Packet Counter Kernel Module
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/sbin/insmod $(pwd)/${MODULE_NAME}.ko interface=${INTERFACE}
ExecStop=/sbin/rmmod ${MODULE_NAME}

[Install]
WantedBy=multi-user.target
EOF

        # Enable and start the service
        systemctl daemon-reload
        systemctl enable "${MODULE_NAME}.service"
        
        print_success "Systemd service created and enabled"
        print_status "To start: systemctl start ${MODULE_NAME}"
        print_status "To stop:  systemctl stop ${MODULE_NAME}"
    else
        print_status "Skipping systemd service creation"
    fi
}

# Show usage information
show_usage() {
    print_success "L2 Packet Counter Module Installation Complete!"
    echo
    echo "Usage:"
    echo "  Monitor packets: cat /proc/${MODULE_NAME}"
    echo "  Reset stats:     echo 'reset' | sudo tee /proc/${MODULE_NAME}"
    echo "  Unload module:   sudo rmmod ${MODULE_NAME}"
    echo
    echo "Module is monitoring interface: ${INTERFACE}"
    echo "Statistics are automatically reset every 20 seconds."
}

# Main installation function
main() {
    echo "=================================="
    echo "L2 Packet Counter Module Installer"
    echo "=================================="
    echo
    
    check_root
    check_requirements
    detect_interfaces
    build_module
    install_module
    create_service
    show_usage
    
    print_success "Installation completed successfully!"
}

# Run main function
main "$@"
