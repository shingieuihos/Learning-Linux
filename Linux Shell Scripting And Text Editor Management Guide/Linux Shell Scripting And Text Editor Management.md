# Linux Shell Scripting & Text Editor Management Commands

A comprehensive reference guide for Linux, AWS Linux, and Ubuntu shell scripting and text editor management commands.

## Table of Contents
1. [Shell Scripting Basics](#shell-scripting-basics)
2. [File and Directory Operations](#file-and-directory-operations)
3. [Text Processing](#text-processing)
4. [System Information](#system-information)
5. [Process Management](#process-management)
6. [Text Editors](#text-editors)
7. [Package Management](#package-management)
8. [Network Commands](#network-commands)
9. [Permissions and Ownership](#permissions-and-ownership)
10. [Environment Variables](#environment-variables)

---

## Shell Scripting Basics

### Essential Commands

| Command | Description | Example |
|---------|-------------|---------|
| `bash script.sh` | Execute a bash script | `bash deploy.sh` |
| `chmod +x script.sh` | Make script executable | `chmod +x backup.sh` |
| `./script.sh` | Run executable script | `./monitor.sh` |
| `source script.sh` | Execute script in current shell | `source ~/.bashrc` |
| `. script.sh` | Shorthand for source | `. ./config.sh` |
| `bash -x script.sh` | Debug script execution | `bash -x test.sh` |
| `bash -n script.sh` | Check syntax without execution | `bash -n validate.sh` |

### Variables and Control Structures

| Command/Syntax | Description | Example |
|----------------|-------------|---------|
| `VAR="value"` | Set variable | `NAME="John"` |
| `$VAR` or `${VAR}` | Access variable | `echo $NAME` |
| `readonly VAR` | Make variable read-only | `readonly CONFIG_FILE` |
| `unset VAR` | Remove variable | `unset TEMP_VAR` |
| `if [ condition ]; then` | Conditional statement | `if [ -f "file.txt" ]; then` |
| `for i in list; do` | For loop | `for file in *.txt; do` |
| `while [ condition ]; do` | While loop | `while [ $count -lt 10 ]; do` |
| `case $var in` | Case statement | `case $option in "start")` |

### Practice Examples - Shell Scripting Basics

```bash
#!/bin/bash
# Example 1: Basic variable usage and conditional
NAME="DevOps Engineer"
if [ -n "$NAME" ]; then
    echo "Hello, $NAME!"
fi

# Example 2: Loop through files
for file in /var/log/*.log; do
    if [ -f "$file" ]; then
        echo "Processing: $(basename $file)"
        tail -5 "$file"
    fi
done

# Example 3: Function with parameters
backup_file() {
    local source_file=$1
    local backup_dir=$2
    
    if [ -f "$source_file" ]; then
        cp "$source_file" "$backup_dir/$(basename $source_file).backup"
        echo "Backed up: $source_file"
    else
        echo "File not found: $source_file"
        return 1
    fi
}

# Usage: backup_file "/etc/nginx/nginx.conf" "/backup"
```

---

## File and Directory Operations

### Basic File Commands

| Command | Description | Example |
|---------|-------------|---------|
| `ls -la` | List files with details | `ls -la /var/www/` |
| `find /path -name "pattern"` | Search for files | `find /var/log -name "*.log"` |
| `locate filename` | Quick file search | `locate nginx.conf` |
| `which command` | Find command location | `which python3` |
| `file filename` | Determine file type | `file script.sh` |
| `stat filename` | File detailed information | `stat /etc/passwd` |
| `du -sh directory` | Directory size | `du -sh /var/log` |
| `df -h` | Disk space usage | `df -h /` |

### File Operations

| Command | Description | Example |
|---------|-------------|---------|
| `cp source destination` | Copy files | `cp config.txt /backup/` |
| `mv source destination` | Move/rename files | `mv old.txt new.txt` |
| `rm -rf directory` | Remove recursively | `rm -rf temp/` |
| `mkdir -p path/to/dir` | Create directories | `mkdir -p /var/app/logs` |
| `rmdir directory` | Remove empty directory | `rmdir empty_folder` |
| `ln -s target linkname` | Create symbolic link | `ln -s /var/log/app.log current.log` |
| `tar -czf archive.tar.gz files` | Create compressed archive | `tar -czf backup.tar.gz /home/user/` |
| `tar -xzf archive.tar.gz` | Extract archive | `tar -xzf backup.tar.gz` |

### Practice Examples - File Operations

```bash
#!/bin/bash
# Example 1: Organize log files by date
organize_logs() {
    local log_dir="/var/log"
    local archive_dir="/var/log/archive"
    
    mkdir -p "$archive_dir"
    
    find "$log_dir" -name "*.log" -mtime +7 | while read logfile; do
        date_dir="$archive_dir/$(date -r "$logfile" +%Y-%m)"
        mkdir -p "$date_dir"
        mv "$logfile" "$date_dir/"
        echo "Archived: $(basename $logfile) to $date_dir"
    done
}

# Example 2: Backup with timestamp
create_backup() {
    local source_dir=$1
    local backup_base="/backups"
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local backup_name="backup_${timestamp}.tar.gz"
    
    tar -czf "${backup_base}/${backup_name}" "$source_dir"
    echo "Backup created: ${backup_base}/${backup_name}"
}

# Example 3: Clean temporary files older than 7 days
cleanup_temp() {
    find /tmp -type f -mtime +7 -delete
    find /var/tmp -type f -mtime +7 -delete
    echo "Cleanup completed"
}
```

---

## Text Processing

### Text Viewing and Editing

| Command | Description | Example |
|---------|-------------|---------|
| `cat filename` | Display file content | `cat /etc/hosts` |
| `less filename` | View file with pagination | `less /var/log/syslog` |
| `head -n 10 file` | Show first 10 lines | `head -20 error.log` |
| `tail -f file` | Follow file updates | `tail -f /var/log/nginx/access.log` |
| `wc -l file` | Count lines | `wc -l /etc/passwd` |
| `sort file` | Sort lines | `sort names.txt` |
| `uniq file` | Remove duplicate lines | `sort data.txt | uniq` |
| `cut -d: -f1 file` | Extract columns | `cut -d: -f1 /etc/passwd` |

### Text Search and Replace

| Command | Description | Example |
|---------|-------------|---------|
| `grep "pattern" file` | Search text | `grep "error" /var/log/app.log` |
| `grep -r "pattern" dir/` | Recursive search | `grep -r "TODO" /var/www/` |
| `grep -i "pattern" file` | Case-insensitive search | `grep -i "warning" logs/` |
| `awk '{print $1}' file` | Process columns | `awk '{print $1}' access.log` |
| `sed 's/old/new/g' file` | Replace text | `sed 's/localhost/127.0.0.1/g' config` |
| `tr 'a-z' 'A-Z'` | Transform characters | `echo "hello" | tr 'a-z' 'A-Z'` |
| `comm file1 file2` | Compare sorted files | `comm users1.txt users2.txt` |
| `diff file1 file2` | Compare files | `diff config.old config.new` |

### Practice Examples - Text Processing

```bash
#!/bin/bash
# Example 1: Log analysis script
analyze_access_log() {
    local log_file="/var/log/nginx/access.log"
    
    echo "=== Top 10 IP Addresses ==="
    awk '{print $1}' "$log_file" | sort | uniq -c | sort -nr | head -10
    
    echo -e "\n=== Top 10 Requested Pages ==="
    awk '{print $7}' "$log_file" | sort | uniq -c | sort -nr | head -10
    
    echo -e "\n=== 404 Errors ==="
    grep " 404 " "$log_file" | wc -l
}

# Example 2: Configuration file processor
update_config() {
    local config_file=$1
    local backup_file="${config_file}.backup.$(date +%Y%m%d)"
    
    # Create backup
    cp "$config_file" "$backup_file"
    
    # Update configuration
    sed -i 's/^#\s*\(ServerName\)/\1/' "$config_file"
    sed -i 's/Listen 80/Listen 8080/g' "$config_file"
    
    echo "Configuration updated. Backup: $backup_file"
}

# Example 3: Extract email addresses from text
extract_emails() {
    local source_file=$1
    grep -oE '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' "$source_file" | sort | uniq
}
```

---

## System Information

### Hardware and System Details

| Command | Description | Example |
|---------|-------------|---------|
| `uname -a` | System information | `uname -a` |
| `lscpu` | CPU information | `lscpu` |
| `free -h` | Memory usage | `free -h` |
| `lsblk` | Block devices | `lsblk` |
| `lspci` | PCI devices | `lspci | grep -i network` |
| `lsusb` | USB devices | `lsusb` |
| `dmidecode` | Hardware details | `sudo dmidecode -t memory` |
| `hdparm -I /dev/sda` | Hard disk info | `sudo hdparm -I /dev/sda` |

### System Status

| Command | Description | Example |
|---------|-------------|---------|
| `uptime` | System uptime and load | `uptime` |
| `whoami` | Current user | `whoami` |
| `id` | User and group IDs | `id` |
| `w` | Logged-in users | `w` |
| `last` | Login history | `last -10` |
| `history` | Command history | `history | tail -20` |
| `date` | Current date/time | `date "+%Y-%m-%d %H:%M:%S"` |
| `timedatectl` | Time and timezone info | `timedatectl status` |

### Practice Examples - System Information

```bash
#!/bin/bash
# Example 1: System health check
system_health_check() {
    echo "=== System Health Report - $(date) ==="
    
    echo -e "\n--- System Info ---"
    echo "Hostname: $(hostname)"
    echo "Uptime: $(uptime -p)"
    echo "Kernel: $(uname -r)"
    
    echo -e "\n--- Resource Usage ---"
    echo "Memory Usage:"
    free -h | grep -E "Mem|Swap"
    
    echo -e "\nDisk Usage:"
    df -h | grep -E "/$|/home|/var"
    
    echo -e "\nLoad Average:"
    uptime | awk -F'load average:' '{print $2}'
    
    echo -e "\n--- Network Status ---"
    ss -tulpn | grep :22 > /dev/null && echo "SSH: Running" || echo "SSH: Not running"
    ss -tulpn | grep :80 > /dev/null && echo "HTTP: Running" || echo "HTTP: Not running"
}

# Example 2: Performance monitoring
monitor_performance() {
    local duration=${1:-60}  # Default 60 seconds
    local interval=5
    local output_file="performance_$(date +%Y%m%d_%H%M%S).log"
    
    echo "Monitoring system for $duration seconds..."
    
    for ((i=0; i<duration; i+=interval)); do
        {
            echo "=== $(date) ==="
            echo "CPU: $(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d% -f1)"
            echo "Memory: $(free | grep Mem | awk '{printf "%.1f%%", $3/$2 * 100.0}')"
            echo "Load: $(uptime | awk -F'load average:' '{print $2}')"
            echo ""
        } >> "$output_file"
        sleep $interval
    done
    
    echo "Performance data saved to: $output_file"
}
```

---

## Process Management

### Process Control

| Command | Description | Example |
|---------|-------------|---------|
| `ps aux` | List all processes | `ps aux | grep nginx` |
| `pgrep process_name` | Find process ID | `pgrep ssh` |
| `pkill process_name` | Kill processes by name | `pkill -f "python app.py"` |
| `kill -9 PID` | Force kill process | `kill -9 12345` |
| `killall process_name` | Kill all instances | `killall firefox` |
| `nohup command &` | Run command in background | `nohup ./script.sh &` |
| `jobs` | List active jobs | `jobs -l` |
| `bg %1` | Move job to background | `bg %1` |
| `fg %1` | Bring job to foreground | `fg %1` |

### System Services

| Command | Description | Example |
|---------|-------------|---------|
| `systemctl status service` | Check service status | `systemctl status nginx` |
| `systemctl start service` | Start service | `systemctl start apache2` |
| `systemctl stop service` | Stop service | `systemctl stop mysql` |
| `systemctl restart service` | Restart service | `systemctl restart ssh` |
| `systemctl enable service` | Enable at boot | `systemctl enable docker` |
| `systemctl disable service` | Disable at boot | `systemctl disable apache2` |
| `service service_name status` | Service status (old way) | `service nginx status` |

### Practice Examples - Process Management

```bash
#!/bin/bash
# Example 1: Process monitor and restart
monitor_and_restart() {
    local service_name=$1
    local max_retries=3
    local retry_count=0
    
    while [ $retry_count -lt $max_retries ]; do
        if systemctl is-active --quiet "$service_name"; then
            echo "$(date): $service_name is running"
            break
        else
            echo "$(date): $service_name is not running. Attempting restart..."
            systemctl start "$service_name"
            sleep 10
            retry_count=$((retry_count + 1))
        fi
    done
    
    if [ $retry_count -eq $max_retries ]; then
        echo "$(date): Failed to start $service_name after $max_retries attempts"
        exit 1
    fi
}

# Example 2: Clean up old processes
cleanup_old_processes() {
    local process_pattern=$1
    local max_age_hours=${2:-24}
    
    echo "Cleaning up processes matching: $process_pattern"
    echo "Older than: $max_age_hours hours"
    
    # Find and kill old processes
    ps -eo pid,etime,cmd | grep "$process_pattern" | while read pid etime cmd; do
        # Convert etime to hours (simplified)
        if [[ $etime =~ ^[0-9]+-.*$ ]]; then  # Process running for days
            echo "Killing old process: $pid - $cmd"
            kill "$pid"
        fi
    done
}

# Example 3: Resource usage alert
check_resource_usage() {
    local cpu_threshold=80
    local mem_threshold=85
    local disk_threshold=90
    
    # Check CPU usage
    cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d% -f1 | cut -d. -f1)
    if [ "$cpu_usage" -gt "$cpu_threshold" ]; then
        echo "ALERT: CPU usage is ${cpu_usage}% (threshold: ${cpu_threshold}%)"
    fi
    
    # Check memory usage
    mem_usage=$(free | grep Mem | awk '{printf "%.0f", $3/$2 * 100.0}')
    if [ "$mem_usage" -gt "$mem_threshold" ]; then
        echo "ALERT: Memory usage is ${mem_usage}% (threshold: ${mem_threshold}%)"
    fi
    
    # Check disk usage
    disk_usage=$(df / | grep / | awk '{print $5}' | cut -d% -f1)
    if [ "$disk_usage" -gt "$disk_threshold" ]; then
        echo "ALERT: Disk usage is ${disk_usage}% (threshold: ${disk_threshold}%)"
    fi
}
```

---

## Text Editors

### Vim/Vi Commands

| Command | Description | Example |
|---------|-------------|---------|
| `vim filename` | Open file in vim | `vim /etc/nginx/nginx.conf` |
| `:w` | Save file | `:w` |
| `:q` | Quit vim | `:q` |
| `:wq` | Save and quit | `:wq` |
| `:q!` | Quit without saving | `:q!` |
| `/pattern` | Search forward | `/error` |
| `?pattern` | Search backward | `?config` |
| `:%s/old/new/g` | Replace all occurrences | `:%s/localhost/127.0.0.1/g` |
| `:set number` | Show line numbers | `:set number` |
| `dd` | Delete line | `dd` |
| `yy` | Copy line | `yy` |
| `p` | Paste | `p` |

### Nano Commands

| Command | Description | Example |
|---------|-------------|---------|
| `nano filename` | Open file in nano | `nano script.sh` |
| `Ctrl+O` | Save file | `Ctrl+O` |
| `Ctrl+X` | Exit nano | `Ctrl+X` |
| `Ctrl+W` | Search text | `Ctrl+W` |
| `Ctrl+\` | Find and replace | `Ctrl+\` |
| `Ctrl+G` | Show help | `Ctrl+G` |
| `Alt+U` | Undo | `Alt+U` |
| `Alt+E` | Redo | `Alt+E` |

### Practice Examples - Text Editors

```bash
#!/bin/bash
# Example 1: Automated vim editing
edit_config_vim() {
    local config_file=$1
    local backup_file="${config_file}.backup"
    
    # Create backup
    cp "$config_file" "$backup_file"
    
    # Use vim in batch mode to edit file
    vim -c ":%s/^#Port 22/Port 2222/g" -c ":wq" "$config_file"
    
    echo "Configuration updated using vim"
    echo "Backup saved as: $backup_file"
}

# Example 2: Interactive editor selection
choose_editor() {
    local file_to_edit=$1
    
    echo "Choose your editor:"
    echo "1) vim"
    echo "2) nano"
    echo "3) emacs"
    
    read -p "Enter choice (1-3): " choice
    
    case $choice in
        1) vim "$file_to_edit" ;;
        2) nano "$file_to_edit" ;;
        3) emacs "$file_to_edit" ;;
        *) echo "Invalid choice. Using nano as default."
           nano "$file_to_edit" ;;
    esac
}

# Example 3: Bulk file editing
bulk_edit_files() {
    local pattern=$1
    local old_text=$2
    local new_text=$3
    
    echo "Searching for files matching: $pattern"
    
    find . -name "$pattern" -type f | while read file; do
        if grep -q "$old_text" "$file"; then
            echo "Editing: $file"
            # Create backup
            cp "$file" "${file}.backup"
            # Replace text
            sed -i "s/$old_text/$new_text/g" "$file"
        fi
    done
    
    echo "Bulk editing completed"
}
```

---

## Package Management

### APT (Ubuntu/Debian)

| Command | Description | Example |
|---------|-------------|---------|
| `apt update` | Update package list | `sudo apt update` |
| `apt upgrade` | Upgrade packages | `sudo apt upgrade` |
| `apt install package` | Install package | `sudo apt install nginx` |
| `apt remove package` | Remove package | `sudo apt remove apache2` |
| `apt purge package` | Remove package and config | `sudo apt purge mysql-server` |
| `apt search pattern` | Search packages | `apt search python3` |
| `apt list --installed` | List installed packages | `apt list --installed | grep nginx` |
| `apt show package` | Package information | `apt show docker.io` |

### YUM (AWS Linux/CentOS/RHEL)

| Command | Description | Example |
|---------|-------------|---------|
| `yum update` | Update packages | `sudo yum update` |
| `yum install package` | Install package | `sudo yum install httpd` |
| `yum remove package` | Remove package | `sudo yum remove firefox` |
| `yum search pattern` | Search packages | `yum search mysql` |
| `yum list installed` | List installed packages | `yum list installed | grep kernel` |
| `yum info package` | Package information | `yum info git` |
| `yum clean all` | Clean cache | `sudo yum clean all` |

### Practice Examples - Package Management

```bash
#!/bin/bash
# Example 1: System update script
system_update() {
    echo "Starting system update..."
    
    # Detect package manager
    if command -v apt &> /dev/null; then
        echo "Using APT package manager"
        sudo apt update
        sudo apt upgrade -y
        sudo apt autoremove -y
        sudo apt autoclean
    elif command -v yum &> /dev/null; then
        echo "Using YUM package manager"
        sudo yum update -y
        sudo yum clean all
    else
        echo "No supported package manager found"
        exit 1
    fi
    
    echo "System update completed"
}

# Example 2: Install development tools
install_dev_tools() {
    local tools=("git" "curl" "wget" "vim" "htop" "tree")
    
    echo "Installing development tools..."
    
    if command -v apt &> /dev/null; then
        for tool in "${tools[@]}"; do
            if ! dpkg -l | grep -q "^ii  $tool "; then
                echo "Installing $tool..."
                sudo apt install -y "$tool"
            else
                echo "$tool is already installed"
            fi
        done
    elif command -v yum &> /dev/null; then
        for tool in "${tools[@]}"; do
            if ! yum list installed "$tool" &> /dev/null; then
                echo "Installing $tool..."
                sudo yum install -y "$tool"
            else
                echo "$tool is already installed"
            fi
        done
    fi
}

# Example 3: Package audit script
audit_packages() {
    local output_file="package_audit_$(date +%Y%m%d).txt"
    
    {
        echo "=== Package Audit Report - $(date) ==="
        echo ""
        
        if command -v apt &> /dev/null; then
            echo "=== Installed Packages (APT) ==="
            apt list --installed 2>/dev/null
            
            echo -e "\n=== Available Updates ==="
            apt list --upgradable 2>/dev/null
            
        elif command -v yum &> /dev/null; then
            echo "=== Installed Packages (YUM) ==="
            yum list installed
            
            echo -e "\n=== Available Updates ==="
            yum check-update
        fi
        
    } > "$output_file"
    
    echo "Package audit saved to: $output_file"
}
```

---

## Network Commands

### Network Information

| Command | Description | Example |
|---------|-------------|---------|
| `ip addr show` | Show IP addresses | `ip addr show eth0` |
| `ifconfig` | Network interface config | `ifconfig eth0` |
| `netstat -tulpn` | Show network connections | `netstat -tulpn | grep :80` |
| `ss -tulpn` | Modern netstat replacement | `ss -tulpn | grep :22` |
| `ping host` | Test connectivity | `ping google.com` |
| `traceroute host` | Trace route to host | `traceroute 8.8.8.8` |
| `nslookup domain` | DNS lookup | `nslookup example.com` |
| `dig domain` | Advanced DNS lookup | `dig example.com MX` |

### Network Tools

| Command | Description | Example |
|---------|-------------|---------|
| `wget url` | Download file | `wget https://example.com/file.tar.gz` |
| `curl url` | Transfer data | `curl -I https://example.com` |
| `scp file user@host:path` | Secure copy | `scp app.tar.gz user@server:/tmp/` |
| `rsync -av src/ dst/` | Sync directories | `rsync -av /home/user/ backup/` |
| `ssh user@host` | Secure shell | `ssh admin@192.168.1.10` |
| `ssh-keygen -t rsa` | Generate SSH key | `ssh-keygen -t rsa -b 2048` |
| `iptables -L` | Show firewall rules | `sudo iptables -L` |

### Practice Examples - Network Commands

```bash
#!/bin/bash
# Example 1: Network connectivity test
network_check() {
    local hosts=("google.com" "github.com" "stackoverflow.com")
    local failed_hosts=()
    
    echo "Testing network connectivity..."
    
    for host in "${hosts[@]}"; do
        if ping -c 3 "$host" &> /dev/null; then
            echo "✓ $host - Reachable"
        else
            echo "✗ $host - Unreachable"
            failed_hosts+=("$host")
        fi
    done
    
    if [ ${#failed_hosts[@]} -eq 0 ]; then
        echo "All hosts are reachable"
        return 0
    else
        echo "Failed to reach: ${failed_hosts[*]}"
        return 1
    fi
}

# Example 2: Port scanner
scan_ports() {
    local target_host=$1
    local ports=(22 23 25 53 80 110 443 993 995)
    
    echo "Scanning ports on $target_host..."
    
    for port in "${ports[@]}"; do
        if timeout 3 bash -c "</dev/tcp/$target_host/$port" 2>/dev/null; then
            echo "Port $port: Open"
        else
            echo "Port $port: Closed"
        fi
    done
}

# Example 3: Website monitoring
monitor_website() {
    local url=$1
    local log_file="website_monitor.log"
    local max_response_time=5
    
    while true; do
        timestamp=$(date "+%Y-%m-%d %H:%M:%S")
        
        # Test website response
        response_time=$(curl -o /dev/null -s -w "%{time_total}" "$url")
        http_code=$(curl -o /dev/null -s -w "%{http_code}" "$url")
        
        if [ "$http_code" = "200" ]; then
            if (( $(echo "$response_time > $max_response_time" | bc -l) )); then
                status="SLOW"
            else
                status="OK"
            fi
        else
            status="ERROR"
        fi
        
        echo "$timestamp - $url - HTTP: $http_code - Time: ${response_time}s - Status: $status" | tee -a "$log_file"
        
        sleep 60  # Check every minute
    done
}
```

---

## Permissions and Ownership

### File Permissions

| Command | Description | Example |
|---------|-------------|---------|
| `chmod 755 file` | Set permissions (rwxr-xr-x) | `chmod 755 script.sh` |
| `chmod +x file` | Add execute permission | `chmod +x deploy.sh` |
| `chmod -w file` | Remove write permission | `chmod -w config.conf` |
| `chmod u+rw,g+r,o-r file` | Complex permissions | `chmod u+rw,g+r,o-r data.txt` |
| `chown user:group file` | Change ownership | `sudo chown www-data:www-data index.html` |
| `chgrp group file` | Change group | `sudo chgrp developers project/` |
| `umask 022` | Set default permissions | `umask 022` |
| `getfacl file` | Get ACL permissions | `getfacl /var/www/html/` |
| `setfacl -m u:user:rwx file` | Set ACL permissions | `setfacl -m u:nginx:rx /var/log/` |

### Permission Numbers

| Number | Permission | Description |
|--------|------------|-------------|
| 0 | --- | No permissions |
| 1 | --x | Execute only |
| 2 | -w- | Write only |
| 3 | -wx | Write and execute |
| 4 | r-- | Read only |
| 5 | r-x | Read and execute |
| 6 | rw- | Read and write |
| 7 | rwx | Read, write, and execute |

### Practice Examples - Permissions and Ownership

```bash
#!/bin/bash
# Example 1: Secure file permissions setup
secure_permissions() {
    local app_dir=$1
    local web_user="www-data"
    local web_group="www-data"
    
    echo "Setting secure permissions for: $app_dir"
    
    # Set ownership
    sudo chown -R "$web_user:$web_group" "$app_dir"
    
    # Set directory permissions (755)
    find "$app_dir" -type d -exec chmod 755 {} \;
    
    # Set file permissions (644)
    find "$app_dir" -type f -exec chmod 644 {} \;
    
    # Make scripts executable
    find "$app_dir" -name "*.sh" -exec chmod +x {} \;
    
    # Secure sensitive files
    find "$app_dir" -name "*.conf" -exec chmod 600 {} \;
    find "$app_dir" -name "*.key" -exec chmod 600 {} \;
    
    echo "Permissions set successfully"
}

# Example 2: Permission audit
audit_permissions() {
    local target_dir=$1
    local report_file="permission_audit_$(date +%Y%m%d).txt"
    
    echo "Auditing permissions for: $target_dir"
    
    {
        echo "=== Permission Audit Report - $(date) ==="
        echo "Target Directory: $target_dir"
        echo ""
        
        echo "=== World-Writable Files ==="
        find "$target_dir" -type f -perm -002 2>/dev/null
        
        echo -e "\n=== SUID Files ==="
        find "$target_dir" -type f -perm -4000 2>/dev/null
        
        echo -e "\n=== SGID Files ==="
        find "$target_dir" -type f -perm -2000 2>/dev/null
        
        echo -e "\n=== Files without Owner ==="
        find "$target_dir" -nouser 2>/dev/null
        
        echo -e "\n=== Files without Group ==="
        find "$target_dir" -nogroup 2>/dev/null
        
        echo -e "\n=== Executable Files ==="
        find "$target_dir" -type f -executable 2>/dev/null
        
    } > "$report_file"
    
    echo "Audit report saved to: $report_file"
}

# Example 3: Fix common permission issues
fix_web_permissions() {
    local web_root="/var/www/html"
    local web_user="www-data"
    
    echo "Fixing web directory permissions..."
    
    # Backup current permissions
    getfacl -R "$web_root" > "web_permissions_backup_$(date +%Y%m%d).acl"
    
    # Set proper ownership
    sudo chown -R "$web_user:$web_user" "$web_root"
    
    # Directories: 755 (rwxr-xr-x)
    sudo find "$web_root" -type d -exec chmod 755 {} \;
    
    # Files: 644 (rw-r--r--)
    sudo find "$web_root" -type f -exec chmod 644 {} \;
    
    # Upload directories: 775 (rwxrwxr-x)
    sudo find "$web_root" -name "uploads" -type d -exec chmod 775 {} \;
    
    # Log directories: 750 (rwxr-x---)
    sudo find "$web_root" -name "logs" -type d -exec chmod 750 {} \;
    
    echo "Web permissions fixed"
}

---

## Environment Variables

### Environment Management

| Command | Description | Example |
|---------|-------------|---------|
| `env` | List all environment variables | `env | grep PATH` |
| `printenv VAR` | Print specific variable | `printenv HOME` |
| `export VAR="value"` | Set environment variable | `export JAVA_HOME="/usr/lib/jvm/java-8"` |
| `unset VAR` | Remove variable | `unset TEMP_VAR` |
| `echo $VAR` | Display variable value | `echo $PATH` |
| `set` | Show all shell variables | `set | grep USER` |
| `source ~/.bashrc` | Reload environment | `source ~/.bashrc` |
| `env -i command` | Run command with clean env | `env -i bash` |

### Common Environment Variables

| Variable | Description | Example Value |
|----------|-------------|---------------|
| `$PATH` | Executable search path | `/usr/local/bin:/usr/bin:/bin` |
| `$HOME` | User home directory | `/home/username` |
| `$USER` | Current username | `ubuntu` |
| `$PWD` | Current directory | `/var/www/html` |
| `$SHELL` | Default shell | `/bin/bash` |
| `$TERM` | Terminal type | `xterm-256color` |
| `$PS1` | Primary prompt | `\u@\h:\w\$ ` |
| `$LANG` | System language | `en_US.UTF-8` |

### Practice Examples - Environment Variables

```bash
#!/bin/bash
# Example 1: Development environment setup
setup_dev_environment() {
    local env_file="$HOME/.dev_env"
    
    echo "Setting up development environment..."
    
    # Create environment file
    cat > "$env_file" << EOF
# Development Environment Variables
export JAVA_HOME="/usr/lib/jvm/java-11-openjdk-amd64"
export MAVEN_HOME="/opt/maven"
export NODE_VERSION="16.20.0"
export PYTHON_PATH="/usr/local/lib/python3.9/site-packages"
export EDITOR="vim"
export BROWSER="firefox"

# Custom PATH
export PATH="\$JAVA_HOME/bin:\$MAVEN_HOME/bin:\$PATH"
export PATH="\$HOME/.local/bin:\$PATH"

# Development aliases
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'
alias ..='cd ..'
alias grep='grep --color=auto'

# Custom functions
function mkcd() {
    mkdir -p "\$1" && cd "\$1"
}

function backup() {
    cp "\$1" "\$1.backup.\$(date +%Y%m%d_%H%M%S)"
}
EOF

    # Add to .bashrc if not already there
    if ! grep -q "source $env_file" "$HOME/.bashrc"; then
        echo "source $env_file" >> "$HOME/.bashrc"
    fi
    
    echo "Development environment configured"
    echo "Run 'source ~/.bashrc' to apply changes"
}

# Example 2: Environment variable validator
validate_environment() {
    local required_vars=("JAVA_HOME" "PATH" "HOME" "USER")
    local missing_vars=()
    
    echo "Validating environment variables..."
    
    for var in "${required_vars[@]}"; do
        if [ -z "${!var}" ]; then
            missing_vars+=("$var")
            echo "✗ $var - Not set"
        else
            echo "✓ $var - ${!var}"
        fi
    done
    
    # Check PATH components
    echo -e "\n=== PATH Components ==="
    IFS=':' read -ra PATH_ARRAY <<< "$PATH"
    for path_component in "${PATH_ARRAY[@]}"; do
        if [ -d "$path_component" ]; then
            echo "✓ $path_component"
        else
            echo "✗ $path_component (directory not found)"
        fi
    done
    
    if [ ${#missing_vars[@]} -eq 0 ]; then
        echo -e "\nAll required variables are set"
        return 0
    else
        echo -e "\nMissing variables: ${missing_vars[*]}"
        return 1
    fi
}

# Example 3: Dynamic environment configuration
configure_app_environment() {
    local app_name=$1
    local env_type=${2:-development}  # development, staging, production
    local config_dir="/etc/$app_name"
    
    echo "Configuring environment for $app_name ($env_type)"
    
    # Create application-specific environment file
    local env_file="$config_dir/$app_name.env"
    sudo mkdir -p "$config_dir"
    
    case $env_type in
        "development")
            sudo tee "$env_file" > /dev/null << EOF
# Development Environment
APP_ENV=development
DEBUG=true
LOG_LEVEL=debug
DATABASE_URL=localhost:5432
CACHE_ENABLED=false
API_RATE_LIMIT=1000
EOF
            ;;
        "staging")
            sudo tee "$env_file" > /dev/null << EOF
# Staging Environment
APP_ENV=staging
DEBUG=false
LOG_LEVEL=info
DATABASE_URL=staging-db:5432
CACHE_ENABLED=true
API_RATE_LIMIT=500
EOF
            ;;
        "production")
            sudo tee "$env_file" > /dev/null << EOF
# Production Environment
APP_ENV=production
DEBUG=false
LOG_LEVEL=error
DATABASE_URL=prod-db:5432
CACHE_ENABLED=true
API_RATE_LIMIT=100
EOF
            ;;
    esac
    
    # Set secure permissions
    sudo chmod 600 "$env_file"
    sudo chown root:root "$env_file"
    
    echo "Environment file created: $env_file"
    echo "Load with: source $env_file"
}

---

## Advanced Shell Scripting Examples

### Complete Deployment Script
```bash
#!/bin/bash
# Complete application deployment script

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# Configuration
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly APP_NAME="myapp"
readonly DEPLOY_DIR="/opt/$APP_NAME"
readonly BACKUP_DIR="/backup/$APP_NAME"
readonly LOG_FILE="/var/log/${APP_NAME}_deploy.log"
readonly SERVICE_NAME="$APP_NAME"

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly NC='\033[0m' # No Color

# Logging function
log() {
    local level=$1
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${timestamp} [${level}] ${message}" | tee -a "$LOG_FILE"
}

# Error handling
error_exit() {
    log "ERROR" "$1"
    exit 1
}

# Pre-deployment checks
pre_deploy_checks() {
    log "INFO" "Running pre-deployment checks..."
    
    # Check if running as root
    if [[ $EUID -eq 0 ]]; then
        error_exit "This script should not be run as root"
    fi
    
    # Check disk space
    local available_space=$(df /opt | awk 'NR==2 {print $4}')
    if [[ $available_space -lt 1048576 ]]; then  # 1GB in KB
        error_exit "Insufficient disk space. Need at least 1GB free"
    fi
    
    # Check if service exists
    if systemctl list-unit-files | grep -q "$SERVICE_NAME"; then
        log "INFO" "Service $SERVICE_NAME found"
    else
        error_exit "Service $SERVICE_NAME not found"
    fi
    
    log "INFO" "Pre-deployment checks passed"
}

# Backup current version
backup_current_version() {
    log "INFO" "Creating backup of current version..."
    
    local backup_name="${APP_NAME}_$(date +%Y%m%d_%H%M%S)"
    local backup_path="$BACKUP_DIR/$backup_name"
    
    mkdir -p "$BACKUP_DIR"
    
    if [[ -d "$DEPLOY_DIR" ]]; then
        tar -czf "${backup_path}.tar.gz" -C "$(dirname "$DEPLOY_DIR")" "$(basename "$DEPLOY_DIR")"
        log "INFO" "Backup created: ${backup_path}.tar.gz"
    else
        log "WARN" "No existing installation found to backup"
    fi
}

# Deploy application
deploy_application() {
    log "INFO" "Deploying application..."
    
    # Stop service
    sudo systemctl stop "$SERVICE_NAME" || true
    
    # Create deployment directory
    sudo mkdir -p "$DEPLOY_DIR"
    
    # Copy application files
    sudo cp -r "$SCRIPT_DIR/../app/"* "$DEPLOY_DIR/"
    
    # Set permissions
    sudo chown -R "$USER:$USER" "$DEPLOY_DIR"
    sudo chmod +x "$DEPLOY_DIR/bin/"*
    
    # Install dependencies
    if [[ -f "$DEPLOY_DIR/requirements.txt" ]]; then
        pip3 install -r "$DEPLOY_DIR/requirements.txt"
    fi
    
    # Update configuration
    if [[ -f "$DEPLOY_DIR/config/app.conf.template" ]]; then
        envsubst < "$DEPLOY_DIR/config/app.conf.template" > "$DEPLOY_DIR/config/app.conf"
    fi
    
    log "INFO" "Application deployed successfully"
}

# Start services
start_services() {
    log "INFO" "Starting services..."
    
    sudo systemctl start "$SERVICE_NAME"
    sudo systemctl enable "$SERVICE_NAME"
    
    # Wait for service to start
    sleep 5
    
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        log "INFO" "Service $SERVICE_NAME started successfully"
    else
        error_exit "Failed to start service $SERVICE_NAME"
    fi
}

# Health check
health_check() {
    log "INFO" "Running health checks..."
    
    local max_attempts=30
    local attempt=1
    
    while [[ $attempt -le $max_attempts ]]; do
        if curl -s -o /dev/null -w "%{http_code}" "http://localhost:8080/health" | grep -q "200"; then
            log "INFO" "Health check passed"
            return 0
        fi
        
        log "WARN" "Health check attempt $attempt failed. Retrying in 10 seconds..."
        sleep 10
        ((attempt++))
    done
    
    error_exit "Health check failed after $max_attempts attempts"
}

# Main deployment function
main() {
    log "INFO" "Starting deployment of $APP_NAME"
    
    pre_deploy_checks
    backup_current_version
    deploy_application
    start_services
    health_check
    
    log "INFO" "Deployment completed successfully"
    echo -e "${GREEN}✓ Deployment completed successfully${NC}"
}

# Script execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
```

### System Maintenance Script
```bash
#!/bin/bash
# Comprehensive system maintenance script

# Configuration
readonly SCRIPT_NAME="$(basename "$0")"
readonly LOG_DIR="/var/log/maintenance"
readonly LOG_FILE="$LOG_DIR/maintenance_$(date +%Y%m%d).log"
readonly REPORT_FILE="$LOG_DIR/maintenance_report_$(date +%Y%m%d).txt"

# Create log directory
mkdir -p "$LOG_DIR"

# Logging function
log_action() {
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "$timestamp - $message" | tee -a "$LOG_FILE"
}

# System cleanup
system_cleanup() {
    log_action "Starting system cleanup..."
    
    # Clean package cache
    if command -v apt &> /dev/null; then
        sudo apt autoremove -y
        sudo apt autoclean
        log_action "APT cleanup completed"
    elif command -v yum &> /dev/null; then
        sudo yum clean all
        log_action "YUM cleanup completed"
    fi
    
    # Clean temporary files
    sudo find /tmp -type f -mtime +7 -delete 2>/dev/null || true
    sudo find /var/tmp -type f -mtime +7 -delete 2>/dev/null || true
    log_action "Temporary files cleaned"
    
    # Clean log files older than 30 days
    sudo find /var/log -name "*.log" -mtime +30 -exec gzip {} \; 2>/dev/null || true
    sudo find /var/log -name "*.gz" -mtime +90 -delete 2>/dev/null || true
    log_action "Log files rotated and cleaned"
    
    # Clean old kernels (Ubuntu/Debian)
    if command -v apt &> /dev/null; then
        local current_kernel=$(uname -r)
        local old_kernels=$(dpkg -l | grep linux-image | grep -v "$current_kernel" | awk '{print $2}' | head -n -1)
        
        if [[ -n "$old_kernels" ]]; then
            echo "$old_kernels" | xargs sudo apt remove -y
            log_action "Old kernels removed"
        fi
    fi
}

# Generate system report
generate_system_report() {
    log_action "Generating system report..."
    
    {
        echo "=== System Maintenance Report - $(date) ==="
        echo ""
        
        echo "=== System Information ==="
        echo "Hostname: $(hostname)"
        echo "Uptime: $(uptime -p)"
        echo "Kernel: $(uname -r)"
        echo "Architecture: $(uname -m)"
        echo ""
        
        echo "=== CPU Information ==="
        lscpu | grep -E "Model name|CPU\(s\)|Thread|Core"
        echo ""
        
        echo "=== Memory Usage ==="
        free -h
        echo ""
        
        echo "=== Disk Usage ==="
        df -h | grep -v tmpfs
        echo ""
        
        echo "=== Network Interfaces ==="
        ip addr show | grep -E "inet |inet6 " | grep -v "127.0.0.1\|::1"
        echo ""
        
        echo "=== Active Services ==="
        systemctl list-units --type=service --state=active --no-pager | head -20
        echo ""
        
        echo "=== Top 10 Processes by CPU ==="
        ps aux --sort=-%cpu | head -11
        echo ""
        
        echo "=== Top 10 Processes by Memory ==="
        ps aux --sort=-%mem | head -11
        echo ""
        
        echo "=== Recent System Logs ==="
        journalctl --since "1 hour ago" --no-pager | tail -20
        echo ""
        
        echo "=== Security Updates Available ==="
        if command -v apt &> /dev/null; then
            apt list --upgradable 2>/dev/null | grep -i security || echo "No security updates available"
        elif command -v yum &> /dev/null; then
            yum check-update --security 2>/dev/null || echo "No security updates available"
        fi
        
    } > "$REPORT_FILE"
    
    log_action "System report generated: $REPORT_FILE"
}

# Main maintenance routine
main() {
    log_action "Starting system maintenance"
    
    system_cleanup
    generate_system_report
    
    # Calculate script runtime
    local end_time=$(date +%s)
    local start_time=${start_time:-$end_time}
    local duration=$((end_time - start_time))
    
    log_action "System maintenance completed in ${duration}s"
    
    echo "Maintenance completed successfully!"
    echo "Log file: $LOG_FILE"
    echo "Report file: $REPORT_FILE"
}

# Set start time
start_time=$(date +%s)

# Execute main function
main "$@"
```

---

## Best Practices and Tips

### Shell Scripting Best Practices

1. **Always use `#!/bin/bash` shebang**
2. **Set strict error handling**: `set -euo pipefail`
3. **Use readonly for constants**: `readonly CONFIG_FILE="/etc/app.conf"`
4. **Quote variables**: `echo "$variable"` instead of `echo $variable`
5. **Use local variables in functions**: `local var_name="value"`
6. **Check command existence**: `command -v git &> /dev/null`
7. **Use meaningful variable names**: `user_count` instead of `uc`
8. **Add logging and error handling**
9. **Test scripts thoroughly before production use**
10. **Use version control for all scripts**

### Security Considerations

1. **Never store passwords in scripts**
2. **Use proper file permissions (600 for sensitive scripts)**
3. **Validate input parameters**
4. **Avoid using `eval` with user input**
5. **Use `sudo` instead of running as root**
6. **Sanitize file paths to prevent directory traversal**
7. **Log security-relevant actions**
8. **Use encrypted connections (SSH, HTTPS)**

### Performance Tips

1. **Use built-in commands when possible**
2. **Minimize subprocess creation**
3. **Use arrays for multiple values**
4. **Cache expensive operations**
5. **Use `grep -q` for boolean checks**
6. **Prefer `[[` over `[` for conditionals**
7. **Use `printf` instead of `echo` for formatted output**
8. **Background long-running processes when appropriate**

---

## Quick Reference Commands

### Most Used Commands Cheat Sheet

```bash
# File operations
ls -la                    # List files with details
find /path -name "*.txt"  # Find files by name
grep -r "pattern" /path   # Search text recursively
tail -f /var/log/app.log  # Follow log file

# System monitoring
ps aux | grep process     # Find processes
top -p PID               # Monitor specific process
df -h                    # Disk usage
free -h                  # Memory usage
netstat -tulpn           # Network connections

# Text editing shortcuts
# Vim: :wq (save & quit), :q! (quit without save)
# Nano: Ctrl+O (save), Ctrl+X (exit)

# Quick file editing
sed -i 's/old/new/g' file    # Replace text in file
awk '{print $1}' file        # Print first column
cut -d: -f1 /etc/passwd     # Extract usernames

# Package management
# Ubuntu/Debian
sudo apt update && sudo apt upgrade
sudo apt install package-name

# CentOS/RHEL/Amazon Linux
sudo yum update
sudo yum install package-name

# Service management
sudo systemctl status service-name
sudo systemctl start service-name
sudo systemctl restart service-name
```

---

This reference guide covers essential Linux commands for shell scripting and text editor management. Keep it handy for quick lookups and use the practice examples to improve your Linux administration skills.

**Remember**: Always test scripts in a safe environment before using them in production!
