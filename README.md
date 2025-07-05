# Layer 2 Packet Counter Kernel Module

A Linux kernel module that monitors network traffic and counts packets by source MAC address on a specified Ethernet interface.

## Features

- **Real-time packet counting**: Counts packets by source MAC address
- **RCU-based hash table**: Efficient, scalable data structure for high-performance packet processing
- **Atomic operations**: Thread-safe counters for SMP systems
- **Proc filesystem interface**: Easy-to-read statistics via `/proc/l2packet_counter`
- **Automatic statistics reset**: Configurable periodic reset (default: 20 seconds)
- **Manual reset capability**: Reset statistics on demand via proc interface
- **Configurable interface**: Specify which network interface to monitor
- **Filtering**: Skips multicast and broadcast frames for cleaner statistics

## Technical Details

### Architecture
- Uses RX handler registration to intercept packets at the network device level
- Implements a hash table with RCU (Read-Copy-Update) synchronization for scalability
- Atomic counters ensure thread-safety in SMP environments
- Kernel timer for periodic statistics reset

### Performance Optimizations
- Lock-free reads using RCU
- Minimal locking for writes (only during hash table modifications)
- GFP_ATOMIC allocations in packet processing path
- Efficient hash function using `jhash()`

## Prerequisites

- Linux kernel headers for your running kernel
- GCC compiler
- Make utility
- Root privileges for loading/unloading modules

### Installing Prerequisites

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install linux-headers-$(uname -r) build-essential
```

**CentOS/RHEL/Fedora:**
```bash
sudo yum install kernel-devel-$(uname -r) gcc make
# or for newer versions:
sudo dnf install kernel-devel-$(uname -r) gcc make
```

## Quick Start

### For Development/Testing
1. **Build the module:**
   ```bash
   make build
   ```

2. **Run automated tests:**
   ```bash
   sudo ./run_tests.sh --interface enp0s3
   ```

3. **Load module manually:**
   ```bash
   sudo insmod l2packet_counter.ko interface=enp0s3
   ```

4. **View statistics:**
   ```bash
   cat /proc/l2packet_counter
   ```

5. **Unload the module:**
   ```bash
   sudo rmmod l2packet_counter
   ```

### For Production Deployment
1. **Use the installer:**
   ```bash
   sudo ./install.sh
   ```

2. **The installer will automatically:**
   - Check system requirements
   - Build the module
   - Install and load the module
   - Optionally create systemd service

## Usage

### Building
```bash
# Build the kernel module
make build

# Clean build artifacts
make clean
```

### Module Management
```bash
# Load module with default interface (eth0)
make load

# Load module with specific interface
make load INTERFACE=enp0s3

# Unload module
make unload

# Reload module
make reload

# Check module status
make status
```

### Monitoring
```bash
# View current statistics
make stats
# or directly:
cat /proc/l2packet_counter

# Reset statistics manually
make reset
# or directly:
echo "reset" | sudo tee /proc/l2packet_counter

# Monitor kernel messages
make dmesg
```

### Manual Loading/Unloading
```bash
# Load with specific interface
sudo insmod l2packet_counter.ko interface=eth1

# Unload
sudo rmmod l2packet_counter

# Check loaded modules
lsmod | grep l2packet_counter
```

## Output Format

The module provides statistics via `/proc/l2packet_counter`:

```
Interface: eth0
Total packets: 1247
MAC Address Statistics:
MAC Address        Packet Count
------------------ ------------
aa:bb:cc:dd:ee:ff          523
11:22:33:44:55:66          724
```

## Configuration

### Module Parameters

- **interface**: Network interface to monitor (default: "eth0")
  ```bash
  sudo insmod l2packet_counter.ko interface=enp0s3
  ```

### Compile-time Constants

You can modify these in `packet-counter.c`:

- `HASH_TABLE_BITS`: Hash table size (default: 8, meaning 256 buckets)
- `RESET_INTERVAL_SEC`: Automatic reset interval in seconds (default: 20)

## Supported Interfaces

- Ethernet interfaces (eth0, eth1, enp0s3, etc.)
- Physical network adapters
- Virtual Ethernet interfaces

**Not supported:**
- Loopback interfaces (lo)
- Non-Ethernet devices
- Interfaces with ARPHRD_ETHER type

## Troubleshooting

### Common Issues

1. **Module fails to load:**
   ```bash
   # Check kernel messages
   dmesg | tail -10
   
   # Verify interface exists
   ip link show
   ```

2. **Permission denied:**
   ```bash
   # Ensure you have root privileges
   sudo make load
   ```

3. **Interface not found:**
   ```bash
   # List available interfaces
   ip link show
   
   # Load with correct interface name
   make load INTERFACE=your_interface_name
   ```

4. **Build errors:**
   ```bash
   # Ensure kernel headers are installed
   ls /lib/modules/$(uname -r)/build
   
   # Install missing headers (Ubuntu/Debian)
   sudo apt install linux-headers-$(uname -r)
   ```

### Debugging

Enable debug output:
```bash
# View kernel messages in real-time
sudo tail -f /var/log/kern.log

# Or use dmesg
dmesg -w
```

## File Structure

```
packet-counter/
├── packet-counter.c    # Main kernel module source code (377 lines)
├── Kbuild             # Kernel build configuration with debugging flags
├── Makefile           # Build configuration and targets
├── install.sh         # Production installation script with systemd support
├── run_tests.sh       # Master test runner with comprehensive reporting
├── test_module.sh     # Basic module functionality tests (10 test cases)
├── test_traffic.sh    # Traffic generation and packet counting tests
├── test_stress.sh     # Stress testing for rapid operations
└── README.md          # This documentation
```

## Development

### Code Style
- Linux kernel coding style
- Consistent naming with underscore suffixes for globals
- Comprehensive error handling
- RCU-safe data structures

### Testing

#### Automated Test Suite
```bash
# Run all tests with comprehensive reporting
sudo ./run_tests.sh --interface enp0s3

# Run specific test suites
sudo ./run_tests.sh --interface enp0s3 basic    # Module functionality
sudo ./run_tests.sh --interface enp0s3 traffic  # Traffic generation
sudo ./run_tests.sh --interface enp0s3 stress   # Stress testing

# View detailed test logs
cat /tmp/packet_counter_tests.log
cat /tmp/packet_counter_test_report.txt
```

#### Manual Testing
```bash
# Generate network traffic for testing
ping -c 10 google.com

# Monitor statistics
watch -n 1 'cat /proc/l2packet_counter'
```

#### Test Coverage
- **Basic Tests**: Module loading, proc interface validation, parameter checking
- **Traffic Tests**: Packet counting accuracy, statistics display, concurrent access
- **Stress Tests**: Rapid operations, edge cases, memory management

## Safety and Limitations

- **Root privileges required**: Module loading requires root access
- **Kernel version compatibility**: Tested on modern Linux kernels (5.x+)
- **Memory usage**: Grows with number of unique source MAC addresses
- **Performance impact**: Minimal due to efficient RCU implementation
- **Automatic cleanup**: Statistics reset every 20 seconds by default

## License

This module is licensed under the GNU General Public License v2 (GPL-2.0).

## Author

Andrejs Glazkovs

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## Changelog

### Version 1.1 (Current)
- Added comprehensive test suite (`run_tests.sh`, `test_module.sh`, `test_traffic.sh`, `test_stress.sh`)
- Added production installation script (`install.sh`) with systemd support
- Added debug build configuration (`Kbuild`)
- Enhanced error handling and parameter validation
- Fixed arithmetic expansion issues in test scripts
- Added detailed logging and reporting
- Updated documentation

### Version 1.0
- Initial release
- RCU-based hash table implementation
- Proc filesystem interface
- Automatic and manual statistics reset
- Configurable network interface monitoring
