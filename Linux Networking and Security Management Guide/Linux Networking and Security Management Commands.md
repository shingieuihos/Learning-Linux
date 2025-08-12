# Linux Networking and Security Management Commands

A comprehensive reference guide for networking and security commands on Linux, AWS Linux, and Ubuntu systems.

## Table of Contents
- [Network Configuration](#network-configuration)
- [Network Diagnostics](#network-diagnostics)
- [Process and Port Management](#process-and-port-management)
- [Firewall Management](#firewall-management)
- [SSL/TLS and Certificates](#ssltls-and-certificates)
- [User and Permission Management](#user-and-permission-management)
- [System Security](#system-security)
- [Log Analysis](#log-analysis)
- [AWS-Specific Commands](#aws-specific-commands)

## Network Configuration

### Interface Management
```bash
# Display all network interfaces and their configuration
ip addr show
ip a                              # Short form

# Display specific interface
ip addr show eth0

# Enable/disable network interface
sudo ip link set eth0 up
sudo ip link set eth0 down

# Add IP address to interface
sudo ip addr add 192.168.1.100/24 dev eth0

# Remove IP address from interface
sudo ip addr del 192.168.1.100/24 dev eth0
```

### Routing
```bash
# Display routing table
ip route show
route -n                         # Traditional command (deprecated)

# Add default gateway
sudo ip route add default via 192.168.1.1

# Add specific route
sudo ip route add 10.0.0.0/8 via 192.168.1.1

# Delete route
sudo ip route del 10.0.0.0/8
```

### DNS Configuration
```bash
# View DNS configuration
cat /etc/resolv.conf

# Test DNS resolution
nslookup google.com
dig google.com
host google.com

# Flush DNS cache (Ubuntu)
sudo systemd-resolve --flush-caches
```

## Network Diagnostics

### Connectivity Testing
```bash
# Test connectivity to host
ping -c 4 google.com             # Send 4 packets
ping6 -c 4 ipv6.google.com       # IPv6 ping

# Trace route to destination
traceroute google.com
tracepath google.com             # Alternative without root privileges

# Test specific port connectivity
telnet google.com 80
nc -zv google.com 80             # Netcat port scan
```

### Network Analysis
```bash
# Display network connections and listening ports
netstat -tulpn                   # TCP/UDP, listening, process IDs, numeric
ss -tulpn                        # Modern replacement for netstat

# Display only listening ports
netstat -ln
ss -ln

# Display connections to specific port
netstat -an | grep :22
ss -an | grep :22

# Monitor network traffic
sudo tcpdump -i eth0             # Capture packets on eth0
sudo tcpdump -i any port 80      # Capture HTTP traffic on all interfaces

# Display network interface statistics
cat /proc/net/dev
ip -s link show                  # Interface statistics with ip command
```

### Bandwidth and Performance
```bash
# Test network speed between servers
iperf3 -s                        # Run as server
iperf3 -c server_ip              # Run as client

# Monitor network usage by process
sudo nethogs                     # Real-time per-process network usage

# Display network interface usage
ifstat                           # Interface statistics
nload                            # Network load monitor
```

## Process and Port Management

### Process Information
```bash
# List all running processes
ps aux
ps -ef

# Find process by name
pgrep nginx
pidof nginx

# Kill process by PID
kill 1234
kill -9 1234                     # Force kill

# Kill process by name
pkill nginx
killall nginx
```

### Port Management
```bash
# Find which process is using a port
sudo lsof -i :80
sudo fuser -n tcp 80

# List open files by process
lsof -p 1234

# Display listening processes
sudo lsof -i -P -n | grep LISTEN
```

## Firewall Management

### UFW (Ubuntu Firewall)
```bash
# Enable/disable firewall
sudo ufw enable
sudo ufw disable

# Check firewall status
sudo ufw status
sudo ufw status verbose

# Allow/deny ports
sudo ufw allow 22                # Allow SSH
sudo ufw allow 80/tcp            # Allow HTTP
sudo ufw deny 23                 # Deny Telnet

# Allow from specific IP
sudo ufw allow from 192.168.1.100

# Allow from subnet
sudo ufw allow from 192.168.1.0/24

# Delete rule
sudo ufw delete allow 80

# Reset firewall (remove all rules)
sudo ufw --force reset
```

### iptables
```bash
# List all rules
sudo iptables -L
sudo iptables -L -n              # Show numeric addresses
sudo iptables -L -v              # Verbose output

# Allow incoming SSH
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Allow incoming HTTP/HTTPS
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Block specific IP
sudo iptables -A INPUT -s 192.168.1.100 -j DROP

# Save iptables rules (Ubuntu/Debian)
sudo iptables-save > /etc/iptables/rules.v4

# Restore iptables rules
sudo iptables-restore < /etc/iptables/rules.v4

# Flush all rules
sudo iptables -F
```

### firewalld (CentOS/RHEL/Fedora)
```bash
# Start/enable firewalld
sudo systemctl start firewalld
sudo systemctl enable firewalld

# Check status
sudo firewall-cmd --state
sudo firewall-cmd --list-all

# Add service
sudo firewall-cmd --add-service=http --permanent
sudo firewall-cmd --reload

# Add port
sudo firewall-cmd --add-port=8080/tcp --permanent
sudo firewall-cmd --reload

# Remove service/port
sudo firewall-cmd --remove-service=http --permanent
sudo firewall-cmd --remove-port=8080/tcp --permanent
```

## SSL/TLS and Certificates

### Certificate Management
```bash
# Generate private key
openssl genrsa -out private.key 2048

# Generate certificate signing request (CSR)
openssl req -new -key private.key -out cert.csr

# Generate self-signed certificate
openssl req -x509 -newkey rsa:2048 -keyout private.key -out cert.crt -days 365

# View certificate details
openssl x509 -in cert.crt -text -noout

# Test SSL connection
openssl s_client -connect google.com:443

# Check certificate expiration
openssl x509 -in cert.crt -noout -dates
```

### Let's Encrypt with Certbot
```bash
# Install certificate for domain
sudo certbot --nginx -d example.com

# Renew certificates
sudo certbot renew

# List certificates
sudo certbot certificates

# Revoke certificate
sudo certbot revoke --cert-path /path/to/cert
```

## User and Permission Management

### User Management
```bash
# Add new user
sudo useradd -m username
sudo adduser username            # Interactive (Ubuntu/Debian)

# Set user password
sudo passwd username

# Add user to group
sudo usermod -aG sudo username   # Add to sudo group
sudo usermod -aG docker username # Add to docker group

# Delete user
sudo userdel username
sudo userdel -r username         # Remove home directory

# View user information
id username
getent passwd username
```

### Permission Management
```bash
# Change file permissions
chmod 755 file.txt               # rwxr-xr-x
chmod +x script.sh               # Add execute permission

# Change file ownership
sudo chown user:group file.txt
sudo chown -R user:group /path/  # Recursive

# View file permissions
ls -la
stat file.txt                    # Detailed file information

# Special permissions
chmod +s file                    # Set SUID bit
chmod +t directory               # Set sticky bit
```

### Sudo Configuration
```bash
# Edit sudo configuration
sudo visudo

# Run command as another user
sudo -u username command

# Check sudo privileges
sudo -l

# Run command without password prompt (if configured)
sudo -n command
```

## System Security

### System Updates
```bash
# Update package list (Ubuntu/Debian)
sudo apt update

# Upgrade packages
sudo apt upgrade
sudo apt full-upgrade            # Handle dependencies

# Update system (CentOS/RHEL/Amazon Linux)
sudo yum update
sudo dnf update                  # Fedora/newer RHEL

# Search for security updates only
sudo apt list --upgradable | grep -i security
```

### Security Scanning
```bash
# Check for rootkits
sudo rkhunter --check
sudo chkrootkit

# File integrity monitoring
sudo aide --init                 # Initialize database
sudo aide --check                # Check for changes

# Check for failed login attempts
sudo grep "Failed password" /var/log/auth.log

# Check for successful logins
sudo grep "Accepted" /var/log/auth.log
```

### System Hardening
```bash
# Disable unused services
sudo systemctl disable service_name
sudo systemctl stop service_name

# Check listening services
sudo ss -tulpn

# Set file permissions for sensitive files
sudo chmod 600 /etc/ssh/sshd_config
sudo chmod 644 /etc/passwd

# Enable automatic security updates (Ubuntu)
sudo dpkg-reconfigure -plow unattended-upgrades
```

## Log Analysis

### System Logs
```bash
# View system logs
journalctl                       # Systemd journal
journalctl -u ssh                # Specific service logs
journalctl -f                    # Follow logs in real-time

# Traditional log files
tail -f /var/log/syslog         # System log
tail -f /var/log/auth.log       # Authentication log
tail -f /var/log/kern.log       # Kernel log

# Search logs
grep "error" /var/log/syslog
journalctl --grep="error"
```

### Security Logs
```bash
# Failed SSH login attempts
sudo grep "Failed password" /var/log/auth.log

# Successful SSH logins
sudo grep "Accepted password" /var/log/auth.log

# Sudo usage
sudo grep "sudo" /var/log/auth.log

# Check for intrusion attempts
sudo fail2ban-client status      # If fail2ban is installed
```

## AWS-Specific Commands

### AWS CLI Security
```bash
# Configure AWS CLI
aws configure

# List security groups
aws ec2 describe-security-groups

# Create security group
aws ec2 create-security-group --group-name MySecGroup --description "My security group"

# Add rule to security group
aws ec2 authorize-security-group-ingress --group-id sg-12345678 --protocol tcp --port 22 --cidr 0.0.0.0/0

# List VPC information
aws ec2 describe-vpcs
aws ec2 describe-subnets
```

### Instance Metadata
```bash
# Get instance metadata (from within EC2 instance)
curl http://169.254.169.254/latest/meta-data/
curl http://169.254.169.254/latest/meta-data/instance-id
curl http://169.254.169.254/latest/meta-data/public-ipv4

# Get instance user data
curl http://169.254.169.254/latest/user-data
```

### CloudWatch Logs
```bash
# Install CloudWatch agent (Amazon Linux)
sudo yum install -y awslogs

# Configure CloudWatch logs
sudo vim /etc/awslogs/awslogs.conf

# Start CloudWatch logs service
sudo systemctl start awslogsd
sudo systemctl enable awslogsd
```

## Quick Reference Commands

### Emergency Network Troubleshooting
```bash
# Check if network is up
ip link show
ping -c 1 8.8.8.8

# Restart networking (be careful with remote connections!)
sudo systemctl restart networking      # Ubuntu/Debian
sudo systemctl restart network         # CentOS/RHEL

# Flush DNS
sudo systemd-resolve --flush-caches    # Ubuntu 18.04+
```

### Security Quick Checks
```bash
# Check for unauthorized users
cat /etc/passwd | grep "/bin/bash"

# Check for SUID files
find / -perm -4000 2>/dev/null

# Check for world-writable files
find / -type f -perm -002 2>/dev/null

# Check running processes
ps aux | grep -v "$(whoami)"
```

## Notes

- Always test firewall rules in a safe environment before applying to production
- Keep regular backups of configuration files before making changes
- Use `sudo` carefully and only when necessary
- Consider using configuration management tools (Ansible, Puppet, Chef) for managing multiple systems
- Regularly update systems and monitor security advisories
- Use strong passwords and consider implementing key-based authentication for SSH

## Additional Resources

- [Ubuntu Networking Documentation](https://ubuntu.com/server/docs/network-configuration)
- [AWS Security Best Practices](https://aws.amazon.com/security/security-resources/)
- [Linux Security HOWTO](https://tldp.org/HOWTO/Security-HOWTO/)
