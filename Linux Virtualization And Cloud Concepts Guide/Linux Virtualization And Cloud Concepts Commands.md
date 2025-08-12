# Linux Virtualization and Cloud Management Guide

A comprehensive guide to Linux virtualization and cloud concepts with essential management commands for Linux, AWS Linux, and Ubuntu systems.

## Table of Contents
- [System Information](#system-information)
- [Process Management](#process-management)
- [Network Management](#network-management)
- [Storage Management](#storage-management)
- [Virtualization with KVM/QEMU](#virtualization-with-kvmqemu)
- [Container Management (Docker)](#container-management-docker)
- [AWS CLI Commands](#aws-cli-commands)
- [Cloud-init and Metadata](#cloud-init-and-metadata)
- [System Monitoring and Performance](#system-monitoring-and-performance)
- [Security and Access Control](#security-and-access-control)

---

## System Information

### Basic System Commands
```bash
# Display system information
uname -a                    # Show kernel version, architecture, and system info
hostnamectl                 # Display hostname and system info (systemd systems)
lsb_release -a             # Show distribution information (Ubuntu/Debian)
cat /etc/os-release        # Display OS version and details

# Hardware information
lscpu                      # Display CPU architecture and details
lsmem                      # Show memory information
lsblk                      # List block devices (disks, partitions)
lspci                      # List PCI devices
lsusb                      # List USB devices
dmidecode                  # Display hardware information from DMI tables

# System uptime and load
uptime                     # Show system uptime and load averages
w                          # Show who is logged in and system load
who                        # Display currently logged users
```

### Practice Examples
```bash
# Check if system supports virtualization
egrep -c '(vmx|svm)' /proc/cpuinfo    # Returns >0 if virtualization supported
lscpu | grep Virtualization           # Shows virtualization technology

# Get detailed system specs for cloud instance sizing
echo "CPU Cores: $(nproc)"
echo "Memory: $(free -h | grep '^Mem:' | awk '{print $2}')"
echo "Disk: $(df -h / | tail -1 | awk '{print $2}')"
```

---

## Process Management

### Process Control Commands
```bash
# Process viewing and management
ps aux                     # Show all running processes
ps -ef                     # Show processes in full format
pstree                     # Display processes in tree format
top                        # Real-time process viewer
htop                       # Enhanced interactive process viewer
jobs                       # Show active jobs in current shell

# Process control
kill PID                   # Terminate process by PID
killall process_name       # Kill all processes with given name
pkill pattern             # Kill processes matching pattern
nohup command &           # Run command immune to hangups

# Background/foreground control
command &                 # Run command in background
bg                        # Put job in background
fg                        # Bring job to foreground
screen                    # Create detachable terminal sessions
tmux                      # Terminal multiplexer for session management
```

### Systemd Service Management
```bash
# Service control (systemd systems)
systemctl start service    # Start a service
systemctl stop service     # Stop a service
systemctl restart service  # Restart a service
systemctl reload service   # Reload service configuration
systemctl enable service   # Enable service at boot
systemctl disable service  # Disable service at boot
systemctl status service   # Show service status
systemctl list-units      # List all active units
```

### Practice Examples
```bash
# Monitor high CPU processes
ps aux --sort=-%cpu | head -10

# Find and kill memory-hungry processes
ps aux --sort=-%mem | head -5
# Kill specific process: sudo kill $(pgrep process_name)

# Create a persistent background service
sudo systemctl enable my-app.service
sudo systemctl start my-app.service
sudo systemctl status my-app.service
```

---

## Network Management

### Network Configuration
```bash
# Network interface management
ip addr show              # Display network interfaces and IP addresses
ip route show             # Show routing table
ip link show              # Show network interfaces
ifconfig                  # Legacy command to configure network interfaces

# Network connectivity
ping host                 # Test connectivity to host
traceroute host          # Show route packets take to host
nslookup domain          # DNS lookup for domain
dig domain               # Advanced DNS lookup tool
netstat -tuln            # Show listening ports and connections
ss -tuln                 # Modern replacement for netstat
```

### Firewall Management
```bash
# UFW (Uncomplicated Firewall - Ubuntu)
ufw status                # Show firewall status
ufw enable               # Enable firewall
ufw allow port           # Allow traffic on port
ufw deny port            # Deny traffic on port
ufw delete rule          # Delete firewall rule

# iptables (Advanced firewall)
iptables -L              # List firewall rules
iptables -A INPUT -p tcp --dport 80 -j ACCEPT  # Allow HTTP traffic
iptables-save            # Save current rules
```

### Practice Examples
```bash
# Check open ports and services
sudo netstat -tlnp | grep LISTEN
sudo ss -tlnp | grep LISTEN

# Test connectivity to cloud services
ping -c 4 8.8.8.8                    # Test internet connectivity
curl -I https://aws.amazon.com        # Test HTTP connectivity
nslookup ec2.amazonaws.com            # Test DNS resolution

# Configure basic firewall for web server
sudo ufw allow 22/tcp                 # SSH
sudo ufw allow 80/tcp                 # HTTP
sudo ufw allow 443/tcp                # HTTPS
sudo ufw --force enable
```

---

## Storage Management

### Disk and Filesystem Commands
```bash
# Disk usage and information
df -h                     # Show filesystem usage in human-readable format
du -sh directory         # Show directory size
lsblk                    # List block devices in tree format
fdisk -l                 # List partition tables
blkid                    # Display block device attributes

# Mounting and unmounting
mount device mountpoint   # Mount filesystem
umount mountpoint        # Unmount filesystem
mount -a                 # Mount all filesystems in /etc/fstab

# Filesystem operations
mkfs.ext4 device         # Create ext4 filesystem
fsck device              # Check and repair filesystem
resize2fs device         # Resize ext2/ext3/ext4 filesystem
```

### LVM (Logical Volume Management)
```bash
# Physical Volume management
pvcreate device          # Create physical volume
pvdisplay                # Show physical volume information

# Volume Group management
vgcreate vg_name pv      # Create volume group
vgdisplay                # Show volume group information
vgextend vg_name pv      # Extend volume group

# Logical Volume management
lvcreate -L size -n lv_name vg_name  # Create logical volume
lvdisplay                # Show logical volume information
lvextend -L +size lv_path            # Extend logical volume
```

### Practice Examples
```bash
# Monitor disk usage and find large files
df -h                                 # Check overall disk usage
du -sh /var/log/*                    # Check log file sizes
find / -type f -size +100M 2>/dev/null  # Find files larger than 100MB

# Add and configure new storage (AWS EBS example)
sudo fdisk -l                        # List available disks
sudo mkfs.ext4 /dev/xvdf             # Format new volume
sudo mkdir /mnt/data                 # Create mount point
sudo mount /dev/xvdf /mnt/data       # Mount volume
echo '/dev/xvdf /mnt/data ext4 defaults 0 0' | sudo tee -a /etc/fstab
```

---

## Virtualization with KVM/QEMU

### KVM Installation and Management
```bash
# Install KVM on Ubuntu
sudo apt update
sudo apt install qemu-kvm libvirt-daemon-system libvirt-clients bridge-utils

# Check KVM support
kvm-ok                   # Check if KVM acceleration is available
lsmod | grep kvm         # Check if KVM modules are loaded

# Libvirt management
virsh list --all         # List all virtual machines
virsh start vm_name      # Start virtual machine
virsh shutdown vm_name   # Shutdown virtual machine
virsh destroy vm_name    # Force stop virtual machine
virsh undefine vm_name   # Remove VM definition
```

### VM Creation and Management
```bash
# Create VM with virt-install
virt-install \
  --name test-vm \
  --ram 1024 \
  --disk path=/var/lib/libvirt/images/test-vm.img,size=10 \
  --vcpus 1 \
  --os-type linux \
  --os-variant ubuntu20.04 \
  --network bridge=virbr0 \
  --graphics none \
  --console pty,target_type=serial \
  --location 'http://archive.ubuntu.com/ubuntu/dists/focal/main/installer-amd64/' \
  --extra-args 'console=ttyS0,115200n8 serial'

# VM resource management
virsh setmem vm_name 2048M    # Set VM memory
virsh setvcpus vm_name 2      # Set VM CPU count
virsh dominfo vm_name         # Show VM information
```

### Practice Examples
```bash
# Set up KVM environment
sudo systemctl enable libvirtd
sudo systemctl start libvirtd
sudo usermod -aG libvirt $USER
sudo usermod -aG kvm $USER

# Create a simple test VM
virt-install --name test-vm --memory 512 --vcpus 1 \
  --disk size=5 --cdrom /path/to/ubuntu.iso \
  --os-variant ubuntu20.04

# Monitor VM performance
virsh domstats test-vm
virt-top                      # Top-like utility for VMs
```

---

## Container Management (Docker)

### Docker Installation and Basic Commands
```bash
# Install Docker (Ubuntu)
sudo apt update
sudo apt install docker.io
sudo systemctl start docker
sudo systemctl enable docker
sudo usermod -aG docker $USER

# Basic Docker commands
docker --version            # Show Docker version
docker info                # Display system-wide information
docker images              # List local images
docker ps                  # List running containers
docker ps -a               # List all containers
```

### Container Operations
```bash
# Container lifecycle
docker run image           # Run container from image
docker run -d image        # Run container in detached mode
docker run -it image bash  # Run interactive container
docker stop container_id   # Stop running container
docker start container_id  # Start stopped container
docker restart container_id # Restart container
docker rm container_id     # Remove container

# Image management
docker pull image          # Download image
docker build -t name .     # Build image from Dockerfile
docker push image          # Push image to registry
docker rmi image           # Remove image
```

### Docker Compose
```bash
# Docker Compose commands
docker-compose up          # Start services defined in docker-compose.yml
docker-compose up -d       # Start services in detached mode
docker-compose down        # Stop and remove containers
docker-compose ps          # List containers
docker-compose logs        # View logs
docker-compose build       # Build services
```

### Practice Examples
```bash
# Run a web server container
docker run -d -p 8080:80 nginx
curl http://localhost:8080

# Create a simple multi-container app
cat > docker-compose.yml << EOF
version: '3'
services:
  web:
    image: nginx
    ports:
      - "8080:80"
  redis:
    image: redis
EOF

docker-compose up -d
docker-compose ps
docker-compose down
```

---

## AWS CLI Commands

### AWS CLI Setup and Configuration
```bash
# Install AWS CLI
sudo apt update
sudo apt install awscli
# Or using pip: pip3 install awscli

# Configure AWS CLI
aws configure              # Set up credentials and region
aws configure list         # Show current configuration
aws sts get-caller-identity # Verify credentials
```

### EC2 Management
```bash
# EC2 instance operations
aws ec2 describe-instances                    # List all instances
aws ec2 start-instances --instance-ids i-xxx  # Start instance
aws ec2 stop-instances --instance-ids i-xxx   # Stop instance
aws ec2 reboot-instances --instance-ids i-xxx # Reboot instance
aws ec2 terminate-instances --instance-ids i-xxx # Terminate instance

# Security groups
aws ec2 describe-security-groups             # List security groups
aws ec2 authorize-security-group-ingress     # Add inbound rule
aws ec2 revoke-security-group-ingress        # Remove inbound rule
```

### S3 Operations
```bash
# S3 bucket and object operations
aws s3 ls                          # List buckets
aws s3 ls s3://bucket-name         # List objects in bucket
aws s3 cp file s3://bucket/key     # Copy file to S3
aws s3 cp s3://bucket/key file     # Copy file from S3
aws s3 sync directory s3://bucket  # Sync directory to S3
aws s3 rb s3://bucket --force      # Remove bucket and contents
```

### Practice Examples
```bash
# Launch and configure EC2 instance
aws ec2 run-instances --image-id ami-0abcdef1234567890 \
  --count 1 --instance-type t2.micro --key-name my-key \
  --security-group-ids sg-12345678 --subnet-id subnet-12345678

# Create S3 bucket and upload files
aws s3 mb s3://my-unique-bucket-name-123
aws s3 cp /var/log/syslog s3://my-unique-bucket-name-123/
aws s3 ls s3://my-unique-bucket-name-123/

# Set up CloudWatch monitoring
aws logs describe-log-groups
aws logs create-log-group --log-group-name /aws/ec2/my-app
```

---

## Cloud-init and Metadata

### Cloud-init Configuration
```bash
# Cloud-init commands
cloud-init status          # Check cloud-init status
cloud-init clean           # Clean cloud-init data
cloud-init init            # Run cloud-init initialization
sudo cloud-init logs       # View cloud-init logs

# Configuration files
/etc/cloud/cloud.cfg       # Main cloud-init configuration
/var/lib/cloud/instance/   # Instance-specific data
/var/log/cloud-init.log    # Cloud-init log file
```

### Instance Metadata (AWS)
```bash
# Retrieve instance metadata
curl http://169.254.169.254/latest/meta-data/          # List available metadata
curl http://169.254.169.254/latest/meta-data/instance-id    # Get instance ID
curl http://169.254.169.254/latest/meta-data/local-ipv4     # Get private IP
curl http://169.254.169.254/latest/meta-data/public-ipv4    # Get public IP
curl http://169.254.169.254/latest/user-data               # Get user data

# Using IMDSv2 (more secure)
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id
```

### Practice Examples
```bash
# Create cloud-init user data script
cat > user-data.sh << EOF
#!/bin/bash
yum update -y
yum install -y docker
systemctl start docker
systemctl enable docker
usermod -aG docker ec2-user
EOF

# Check cloud-init execution
sudo cloud-init status --wait  # Wait for cloud-init to complete
cat /var/log/cloud-init-output.log  # Check execution output

# Get instance information programmatically
INSTANCE_ID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)
REGION=$(curl -s http://169.254.169.254/latest/meta-data/placement/region)
echo "Instance $INSTANCE_ID running in $REGION"
```

---

## System Monitoring and Performance

### System Performance Commands
```bash
# CPU and memory monitoring
top                        # Real-time system monitor
htop                       # Enhanced interactive process viewer
iotop                      # I/O monitoring
vmstat                     # Virtual memory statistics
iostat                     # I/O statistics
sar                        # System activity reporter

# Memory analysis
free -h                    # Show memory usage
cat /proc/meminfo          # Detailed memory information
slabtop                    # Display kernel slab cache information

# Disk performance
iotop -o                   # Show only processes doing I/O
hdparm -tT /dev/sda        # Test disk performance
```

### Log Management
```bash
# System logs
journalctl                 # View systemd logs
journalctl -f              # Follow logs in real-time
journalctl -u service      # View logs for specific service
journalctl --since "1 hour ago"  # View recent logs

# Traditional log files
tail -f /var/log/syslog    # Follow system log
tail -f /var/log/auth.log  # Follow authentication log
grep ERROR /var/log/messages  # Search for errors
```

### Practice Examples
```bash
# Set up comprehensive monitoring
# Install monitoring tools
sudo apt install htop iotop sysstat

# Monitor system performance during load
stress --cpu 2 --timeout 60s &  # Generate CPU load
htop                             # Monitor in another terminal
iostat -x 1                      # Monitor I/O every second

# Check system health
uptime                           # System load
df -h                           # Disk usage
free -h                         # Memory usage
ps aux --sort=-%cpu | head -5   # Top CPU processes
```

---

## Security and Access Control

### User and Permission Management
```bash
# User management
useradd username           # Add new user
usermod -aG group user     # Add user to group
userdel username           # Delete user
passwd username            # Change user password
su - username              # Switch user
sudo command               # Execute command as root

# File permissions
chmod 755 file             # Set file permissions (rwxr-xr-x)
chmod u+x file             # Add execute permission for owner
chown user:group file      # Change file ownership
chgrp group file           # Change file group

# Access Control Lists (ACLs)
getfacl file               # Get file ACL
setfacl -m u:user:rwx file # Set ACL for user
```

### SSH and Key Management
```bash
# SSH operations
ssh-keygen -t rsa -b 4096  # Generate SSH key pair
ssh-copy-id user@host      # Copy public key to remote host
ssh -i keyfile user@host   # Connect using specific key
scp file user@host:/path   # Secure copy file
rsync -avz src/ user@host:dst/  # Synchronize directories

# SSH configuration
~/.ssh/config              # SSH client configuration
/etc/ssh/sshd_config       # SSH server configuration
sudo systemctl restart sshd  # Restart SSH service
```

### Practice Examples
```bash
# Set up secure user with sudo access
sudo useradd -m -s /bin/bash deploy
sudo usermod -aG sudo deploy
sudo passwd deploy

# Configure SSH key authentication
ssh-keygen -t ed25519 -C "your_email@example.com"
cat ~/.ssh/id_ed25519.pub  # Copy this to authorized_keys

# Harden SSH configuration (edit /etc/ssh/sshd_config)
sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sudo systemctl restart sshd

# Set up fail2ban for intrusion prevention
sudo apt install fail2ban
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
```

---

## Quick Reference Cheat Sheet

### Essential Commands for Cloud/Virtualization Management
```bash
# System Info
uname -a && lscpu && free -h && df -h

# Process Management
ps aux | grep process_name
sudo systemctl status service_name
top -p $(pgrep process_name)

# Network
ip addr show && ip route show
netstat -tlnp | grep :port
curl -I http://endpoint

# Storage
lsblk && df -h
sudo fdisk -l
mount | grep device

# Virtualization
virsh list --all
docker ps -a
kubectl get pods

# AWS
aws ec2 describe-instances --query 'Reservations[*].Instances[*].{ID:InstanceId,State:State.Name}'
aws s3 ls
curl http://169.254.169.254/latest/meta-data/instance-id

# Monitoring
htop
journalctl -f
tail -f /var/log/syslog
```

## Additional Resources

- **Documentation**: 
  - [Ubuntu Server Guide](https://ubuntu.com/server/docs)
  - [AWS CLI Documentation](https://docs.aws.amazon.com/cli/)
  - [Docker Documentation](https://docs.docker.com/)
  - [KVM Documentation](https://linux-kvm.org/page/Documents)

- **Best Practices**:
  - Always backup before making system changes
  - Use configuration management tools (Ansible, Puppet) for large deployments
  - Implement proper monitoring and alerting
  - Follow security best practices and keep systems updated
  - Use version control for configuration files

---

*This guide covers essential Linux commands for virtualization and cloud management. Commands may vary slightly between distributions. Always refer to man pages (`man command`) for detailed information.*
