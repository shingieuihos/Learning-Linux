# Linux System Information & Management Commands

A comprehensive reference for essential Linux system commands compatible with AWS Linux, Ubuntu, and other major distributions.

## Table of Contents
- [System Information](#system-information)
- [Hardware Information](#hardware-information)
- [Memory & CPU](#memory--cpu)
- [Disk & Storage](#disk--storage)
- [Network Information](#network-information)
- [Process Management](#process-management)
- [User & Permission Management](#user--permission-management)
- [Service Management](#service-management)
- [Log Management](#log-management)
- [System Monitoring](#system-monitoring)
- [Package Management](#package-management)

---

## System Information

### Basic System Details
```bash
# Display system information
uname -a                    # Complete system information (kernel, hostname, architecture)
hostnamectl                 # System hostname and related settings (systemd systems)
cat /etc/os-release         # OS version and distribution details
lsb_release -a             # Distribution-specific information (Ubuntu/Debian)
whoami                     # Current username
id                         # Current user ID and group memberships
uptime                     # System uptime and load averages
date                       # Current system date and time
timedatectl                # Date, time, and timezone information (systemd)
```

### Kernel & Architecture
```bash
uname -r                   # Kernel version
uname -m                   # Machine hardware architecture (x86_64, arm64, etc.)
arch                       # System architecture (alternative to uname -m)
cat /proc/version          # Detailed kernel version and compilation info
```

---

## Hardware Information

### CPU Information
```bash
lscpu                      # Detailed CPU information (cores, threads, cache, flags)
cat /proc/cpuinfo          # Raw CPU information from kernel
nproc                      # Number of processing units available
cat /proc/loadavg          # System load averages (1, 5, 15 minutes)
```

### Hardware Detection
```bash
lshw                       # Comprehensive hardware information (requires sudo)
lshw -short               # Condensed hardware summary
lspci                     # PCI devices (graphics cards, network adapters, etc.)
lsusb                     # USB devices connected to system
dmidecode                 # Hardware information from BIOS/UEFI (requires sudo)
```

### Block Devices & Storage Controllers
```bash
lsblk                     # Block devices in tree format (disks, partitions)
lsscsi                    # SCSI devices (hard drives, optical drives)
```

---

## Memory & CPU

### Memory Information
```bash
free -h                   # Memory usage in human-readable format
cat /proc/meminfo         # Detailed memory statistics
vmstat                    # Virtual memory statistics and system performance
vmstat 1 5               # Memory stats updated every 1 second, 5 times
```

### CPU Performance & Processes
```bash
top                       # Real-time process and CPU usage monitor
htop                      # Enhanced interactive process viewer (if installed)
ps aux                    # All running processes with detailed information
ps -ef                    # All processes in full format
pstree                    # Process tree showing parent-child relationships
```

---

## Disk & Storage

### Disk Usage & Space
```bash
df -h                     # Filesystem disk space usage in human-readable format
df -i                     # Inode usage for filesystems
du -h /path/to/directory  # Directory size in human-readable format
du -sh *                  # Size of all items in current directory
ncdu /                    # Interactive disk usage analyzer (if installed)
```

### Disk & Partition Information
```bash
fdisk -l                  # List all disk partitions (requires sudo)
parted -l                 # Partition information using parted (requires sudo)
blkid                     # Block device attributes (UUID, filesystem type)
mount                     # Currently mounted filesystems
cat /proc/mounts          # Kernel view of mounted filesystems
findmnt                   # Tree view of mounted filesystems
```

### Filesystem Operations
```bash
fsck /dev/sdX1            # Check filesystem integrity (requires sudo)
tune2fs -l /dev/sdX1      # Display ext2/3/4 filesystem parameters
```

---

## Network Information

### Network Configuration
```bash
ip addr show              # Network interfaces and IP addresses (modern)
ip a                      # Short form of ip addr show
ifconfig                  # Network interface configuration (legacy, may need net-tools)
hostname -I               # All IP addresses assigned to host
```

### Network Connectivity
```bash
ping -c 4 google.com      # Test network connectivity (4 packets)
traceroute google.com     # Trace network route to destination
netstat -tuln             # Active network connections and listening ports
ss -tuln                  # Socket statistics (modern replacement for netstat)
ss -tupln                 # Include process names for listening ports
```

### Network Routes & DNS
```bash
ip route show             # Routing table
route -n                  # Routing table in numeric format (legacy)
cat /etc/resolv.conf      # DNS resolver configuration
nslookup google.com       # DNS lookup for domain
dig google.com            # Detailed DNS information
```

---

## Process Management

### Process Control
```bash
jobs                      # Active jobs in current shell
ps aux | grep process_name # Find specific process
pgrep process_name        # Get PID of process by name
pkill process_name        # Kill processes by name
kill PID                  # Terminate process by PID
kill -9 PID              # Force kill process (SIGKILL)
killall process_name      # Kill all processes with given name
```

### Process Priorities
```bash
nice -n 10 command        # Run command with lower priority
renice 10 PID            # Change priority of running process
```

---

## User & Permission Management

### User Information
```bash
w                         # Currently logged-in users and their activities
who                       # Currently logged-in users (simple format)
last                      # Recent user login history
id username               # User ID and group information for specific user
groups username           # Groups that user belongs to
```

### File Permissions
```bash
ls -la                    # Detailed file listing with permissions
chmod 755 filename        # Change file permissions (rwxr-xr-x)
chown user:group filename # Change file ownership (requires sudo)
umask                     # Default permission mask for new files
```

---

## Service Management

### Systemd Services (Modern Linux)
```bash
systemctl status service_name     # Check service status
systemctl list-units --type=service # List all services
systemctl is-active service_name  # Check if service is running
systemctl is-enabled service_name # Check if service starts at boot
systemctl start service_name      # Start service (requires sudo)
systemctl stop service_name       # Stop service (requires sudo)
systemctl restart service_name    # Restart service (requires sudo)
systemctl enable service_name     # Enable service at boot (requires sudo)
systemctl disable service_name    # Disable service at boot (requires sudo)
```

### Legacy Init Systems
```bash
service service_name status       # Check service status (SysV init)
chkconfig --list                  # List services and runlevels (Red Hat/CentOS)
```

---

## Log Management

### System Logs
```bash
journalctl                        # View systemd journal logs
journalctl -f                     # Follow journal logs in real-time
journalctl -u service_name        # Logs for specific service
journalctl --since "2024-01-01"  # Logs since specific date
journalctl --until "1 hour ago"  # Logs until specific time
```

### Traditional Log Files
```bash
tail -f /var/log/syslog           # Follow system log in real-time (Debian/Ubuntu)
tail -f /var/log/messages         # Follow system log (Red Hat/CentOS)
less /var/log/auth.log            # Authentication logs (Debian/Ubuntu)
less /var/log/secure              # Authentication logs (Red Hat/CentOS)
dmesg                             # Kernel ring buffer messages
dmesg | tail -20                  # Last 20 kernel messages
```

---

## System Monitoring

### Real-time Monitoring
```bash
iostat                    # I/O statistics for devices and partitions
iostat -x 1              # Extended I/O stats updated every second
iotop                     # I/O usage by processes (requires sudo)
sar 1 5                  # System activity report (1 sec intervals, 5 times)
```

### System Resources
```bash
lsof                      # List open files and processes using them
lsof -i :80              # Show processes using port 80
fuser -v /path/to/file   # Show processes using specific file
```

---

## Package Management

### Ubuntu/Debian (APT)
```bash
apt list --installed      # List installed packages
apt search package_name   # Search for packages
apt show package_name     # Show package information
apt update               # Update package lists (requires sudo)
apt upgrade              # Upgrade installed packages (requires sudo)
dpkg -l                  # List installed packages (low-level)
dpkg -l | grep package   # Search installed packages
```

### Red Hat/CentOS/Amazon Linux (YUM/DNF)
```bash
yum list installed       # List installed packages
yum search package_name  # Search for packages
yum info package_name    # Show package information
yum update              # Update packages (requires sudo)
rpm -qa                 # List all installed RPM packages
rpm -qa | grep package  # Search installed RPM packages
```

### Amazon Linux 2023+ (DNF)
```bash
dnf list installed       # List installed packages
dnf search package_name  # Search for packages
dnf info package_name    # Show package information
dnf update              # Update packages (requires sudo)
```

---

## Useful Combinations & Tips

### Quick System Overview
```bash
# One-liner system summary
echo "=== System Info ===" && uname -a && echo "=== Memory ===" && free -h && echo "=== Disk Usage ===" && df -h && echo "=== Load Average ===" && uptime
```

### Find Large Files
```bash
find / -type f -size +100M 2>/dev/null    # Files larger than 100MB
du -ah / 2>/dev/null | sort -rh | head -20 # 20 largest files/directories
```

### Network Troubleshooting
```bash
# Check network connectivity and DNS
ping -c 3 8.8.8.8 && echo "Internet OK" || echo "No Internet"
nslookup google.com && echo "DNS OK" || echo "DNS Issues"
```

---

## Notes

- Commands marked with `(requires sudo)` need administrative privileges
- Some commands may require additional packages to be installed
- AWS Linux AMI may have slightly different default packages than standard distributions
- Always refer to `man command_name` for detailed documentation on any command
- Use `which command_name` to check if a command is available on your system

---

**Last Updated:** August 2025  
**Compatible with:** Ubuntu 18.04+, Amazon Linux 2/2023, CentOS 7+, RHEL 7+
