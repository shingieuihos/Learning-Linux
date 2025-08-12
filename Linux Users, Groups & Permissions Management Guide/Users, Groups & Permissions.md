# Linux Users, Groups & Permissions Management Guide

A comprehensive reference for managing users, groups, and permissions on Linux systems (Ubuntu, AWS Linux, and other distributions).

## Table of Contents
- [User Management](#user-management)
- [Group Management](#group-management)
- [Permission Management](#permission-management)
- [File Ownership](#file-ownership)
- [Special Permissions](#special-permissions)
- [Practical Examples](#practical-examples)
- [Troubleshooting](#troubleshooting)

## User Management

### Creating Users

```bash
# Create a new user (basic account, no home directory)
sudo useradd username

# Create user with home directory (-m creates /home/username)
sudo useradd -m username

# Create user with specific shell (-s sets default shell)
sudo useradd -m -s /bin/bash username

# Create user with custom home directory (-d specifies directory path)
sudo useradd -m -d /custom/home/path username

# Create user and add to specific primary group (-g sets primary group)
sudo useradd -m -g groupname username

# Create user and add to multiple secondary groups (-G adds to groups)
sudo useradd -m -G group1,group2,group3 username
```

### User Information

```bash
# View user information (shows UID, GID, and group memberships)
id username
finger username              # Shows detailed user info including login time
getent passwd username       # Shows user entry from /etc/passwd

# List all users (shows all system accounts)
cat /etc/passwd
cut -d: -f1 /etc/passwd      # Extract only usernames from /etc/passwd

# View currently logged in users
who                          # Shows who is logged in with terminal info
w                           # Shows who is logged in with process info
users                       # Shows simple list of logged in users

# View user's groups (shows all groups user belongs to)
groups username
id -Gn username             # Shows group names only (not GIDs)
```

### Modifying Users

```bash
# Change user's primary group (-g changes main group membership)
sudo usermod -g newgroup username

# Add user to additional groups (-a appends, -G specifies secondary groups)
sudo usermod -a -G group1,group2 username

# Change user's shell (-s sets new login shell)
sudo usermod -s /bin/zsh username

# Change user's home directory (-d sets new home path)
sudo usermod -d /new/home/path username

# Lock a user account (prevents login but keeps account)
sudo usermod -L username     # Locks password in /etc/shadow
sudo passwd -l username      # Alternative method to lock password

# Unlock a user account (re-enables login capability)
sudo usermod -U username     # Unlocks password
sudo passwd -u username      # Alternative unlock method

# Set account expiration date (-e sets when account expires)
sudo usermod -e 2024-12-31 username
```

### Password Management

```bash
# Set password for user (prompts for new password input)
sudo passwd username

# Change your own password (current user password change)
passwd

# Force password change on next login (-e expires password immediately)
sudo passwd -e username

# View password status (-S shows password info and status)
sudo passwd -S username

# Remove password (makes account passwordless - security risk!)
sudo passwd -d username
```

### Deleting Users

```bash
# Delete user (removes account but keeps home directory and files)
sudo userdel username

# Delete user and home directory (-r removes home directory and mail spool)
sudo userdel -r username

# Delete user and all files owned by user (thorough cleanup)
sudo userdel -r username
sudo find / -user username -delete    # Find and delete remaining files
```

## Group Management

### Creating Groups

```bash
# Create a new group (creates group with next available GID)
sudo groupadd groupname

# Create group with specific GID (-g assigns specific group ID number)
sudo groupadd -g 1500 groupname

# Create system group (-r creates system group with low GID)
sudo groupadd -r groupname
```

### Group Information

```bash
# List all groups (shows all system groups with GIDs)
cat /etc/group
getent group                 # Alternative method using Name Service Switch

# View specific group information (shows group details and members)
getent group groupname

# List members of a group (extract member list from group entry)
getent group groupname | cut -d: -f4    # Extract 4th field (members)
members groupname           # Direct command to show group members
```

### Modifying Groups

```bash
# Add user to group (two methods for adding secondary group membership)
sudo usermod -a -G groupname username    # usermod method (-a appends)
sudo gpasswd -a username groupname       # gpasswd method (group admin)

# Remove user from group (removes user from specified secondary group)
sudo gpasswd -d username groupname

# Change group name (-n specifies new name for existing group)
sudo groupmod -n newname oldname

# Change group GID (-g changes the group ID number)
sudo groupmod -g 2000 groupname
```

### Deleting Groups

```bash
# Delete a group (removes group if no users have it as primary group)
sudo groupdel groupname

# Delete group and reassign files to another group (cleanup process)
sudo find / -group oldgroup -exec chgrp newgroup {} \;  # Find and reassign files
sudo groupdel oldgroup      # Then safely delete the group
```

## Permission Management

### Understanding Permissions

```
rwx rwx rwx
│   │   │
│   │   └── Others
│   └────── Group
└────────── Owner

r = read (4)
w = write (2)
x = execute (1)
```

### Viewing Permissions

```bash
# List files with permissions (shows detailed file information)
ls -l                        # Long format showing permissions, owner, group
ls -la                       # Include hidden files (starting with .)

# View permissions in octal format (shows numeric permission values)
stat -c "%a %n" filename     # %a=access rights in octal, %n=filename

# View detailed file information (comprehensive file metadata)
ls -la filename              # Detailed listing for specific file
stat filename                # Shows all file attributes and timestamps
```

### Changing Permissions (chmod)

```bash
# Using symbolic notation (letters: u=user, g=group, o=other, a=all)
chmod u+rwx filename      # Add read, write, execute for owner
chmod g+rw filename       # Add read, write for group
chmod o-rwx filename      # Remove all permissions for others
chmod a+r filename        # Add read permission for all (owner, group, other)

# Using octal notation (numbers: 4=read, 2=write, 1=execute)
chmod 755 filename        # rwxr-xr-x (owner: all, group/other: read+execute)
chmod 644 filename        # rw-r--r-- (owner: read+write, group/other: read)
chmod 600 filename        # rw------- (owner: read+write, group/other: none)
chmod 777 filename        # rwxrwxrwx (all permissions for everyone - risky!)

# Recursive permission changes (-R applies to all files/subdirectories)
chmod -R 755 directory/   # Apply 755 to directory and all contents
chmod -R u+x directory/   # Add execute permission for owner recursively
```

### Common Permission Combinations

```bash
# Files (typical permission patterns for regular files)
chmod 644 file.txt        # rw-r--r-- (owner: read/write, others: read-only)
chmod 600 file.txt        # rw------- (owner: read/write, others: no access)
chmod 755 script.sh       # rwxr-xr-x (owner: all, others: read/execute)

# Directories (directories need execute bit to be accessible)
chmod 755 directory/      # rwxr-xr-x (owner: all, others: read/execute)
chmod 750 directory/      # rwxr-x--- (owner: all, group: read/execute, other: none)
chmod 700 directory/      # rwx------ (owner: all, others: no access)
```

## File Ownership

### Changing Ownership (chown)

```bash
# Change owner (transfers file ownership to different user)
sudo chown newowner filename
sudo chown newowner directory/

# Change owner and group (changes both owner and group in one command)
sudo chown newowner:newgroup filename
sudo chown newowner. filename  # Uses newowner's primary group

# Change only group (alternative to chgrp command)
sudo chown :newgroup filename
sudo chgrp newgroup filename   # Dedicated command for group changes

# Recursive ownership change (-R applies to all subdirectories and files)
sudo chown -R newowner:newgroup directory/

# Change ownership based on reference file (copy ownership from another file)
sudo chown --reference=reffile targetfile
```

### Practical Ownership Examples

```bash
# Make user owner of their home directory (fix home directory ownership)
sudo chown -R username:username /home/username

# Change web directory ownership (web server file ownership)
sudo chown -R www-data:www-data /var/www/html

# Change ownership of log files (system log file ownership)
sudo chown root:adm /var/log/myapp.log
```

## Special Permissions

### Setuid, Setgid, and Sticky Bit

```bash
# Setuid (4000) - Execute with owner's permissions (run as file owner)
chmod 4755 filename       # -rwsr-xr-x (s replaces x for owner)
chmod u+s filename        # Add setuid bit using symbolic notation

# Setgid (2000) - Execute with group's permissions (run as file group)
chmod 2755 filename       # -rwxr-sr-x (s replaces x for group)
chmod g+s filename        # Add setgid bit using symbolic notation

# Sticky bit (1000) - Only owner can delete files (protection bit)
chmod 1755 directory/     # drwxr-xr-t (t replaces x for others)
chmod +t directory/       # Add sticky bit using symbolic notation

# Combined special permissions (multiple special bits together)
chmod 4755 filename       # setuid only
chmod 6755 filename       # setuid + setgid (4000 + 2000)
chmod 1777 /tmp/          # sticky bit with full permissions (like /tmp)
```

### Access Control Lists (ACL)

```bash
# View ACL (shows extended access control list permissions)
getfacl filename

# Set ACL permissions (grant specific permissions to users/groups)
setfacl -m u:username:rwx filename    # -m modifies ACL, u: specifies user
setfacl -m g:groupname:rw filename    # g: specifies group permissions
setfacl -m o::r filename              # o:: specifies other permissions

# Remove ACL (removes specific ACL entries)
setfacl -x u:username filename        # -x removes specific user ACL
setfacl -b filename                   # -b removes all ACL entries

# Default ACL for directories (inherited by new files/subdirectories)
setfacl -d -m u:username:rwx directory/  # -d sets default ACL
```

## Practical Examples

### Web Server Setup

```bash
# Create web user and group (dedicated web development account)
sudo groupadd webdev           # Create group for web developers
sudo useradd -m -g webdev -s /bin/bash webuser  # Create user with webdev as primary group

# Set up web directory permissions (proper web server file permissions)
sudo mkdir -p /var/www/mysite  # Create web directory structure
sudo chown -R webuser:webdev /var/www/mysite    # Set ownership recursively
sudo chmod -R 755 /var/www/mysite               # Set directory permissions
sudo chmod -R 664 /var/www/mysite/*.html        # Set file permissions for HTML files

# Allow group write access (enable collaborative editing)
sudo chmod g+w /var/www/mysite # Add group write permission to directory
```

### Shared Directory Setup

```bash
# Create shared group and directory (collaborative workspace setup)
sudo groupadd shared           # Create group for shared access
sudo mkdir /shared             # Create shared directory
sudo chown root:shared /shared # Set root as owner, shared as group
sudo chmod 2775 /shared        # setgid + group write (2000 + 775)

# Add users to shared group (grant access to shared resources)
sudo usermod -a -G shared user1  # Add user1 to shared group
sudo usermod -a -G shared user2  # Add user2 to shared group
```

### Secure File Handling

```bash
# Create private directory (user-only accessible directory)
mkdir ~/private
chmod 700 ~/private            # Only owner can read, write, or enter

# Create group-readable config file (shared configuration access)
touch config.conf
chmod 640 config.conf          # Owner: read/write, Group: read, Other: none
sudo chown root:admin config.conf  # Set appropriate ownership

# Secure sensitive files (SSH key security best practices)
chmod 600 ~/.ssh/id_rsa        # Private key: owner read/write only
chmod 644 ~/.ssh/id_rsa.pub    # Public key: owner read/write, others read
chmod 700 ~/.ssh/              # SSH directory: owner access only
```

## Troubleshooting

### Common Issues and Solutions

```bash
# Permission denied errors (diagnose and fix access issues)
ls -la filename          # Check current permissions and ownership
sudo chmod +x filename   # Add execute permission if missing
sudo chown $USER filename # Take ownership of file as current user

# User can't access directory (directory access requires execute bit)
chmod +x directory/      # Add execute permission to access directory contents
ls -la directory/        # Verify directory permissions are correct

# Group permissions not working (group membership troubleshooting)
groups username          # Check which groups user belongs to
newgrp groupname         # Switch to group temporarily in current session
# Note: User may need to log out/in for permanent group changes

# Find files with specific permissions (security auditing commands)
find /path -perm 777     # Find files with 777 permissions (security risk)
find /path -perm -u+s    # Find setuid files (potential security concern)
find /path -user username # Find all files owned by specific user

# Fix common permission problems (bulk permission corrections)
sudo chmod -R u+rX directory/  # Add read + conditional execute (X only for dirs)
sudo find directory/ -type f -exec chmod 644 {} \;  # Set all files to 644
sudo find directory/ -type d -exec chmod 755 {} \;  # Set all directories to 755
```

### Backup and Restore Permissions

```bash
# Backup permissions (save current permission settings)
getfacl -R directory/ > permissions_backup.txt  # Backup ACLs recursively

# Restore permissions (restore from backup file)
setfacl --restore=permissions_backup.txt        # Restore ACLs from backup

# Alternative method using find (backup standard permissions)
find directory/ -type f -printf '%m %p\n' > permissions_backup.txt  # Files
find directory/ -type d -printf '%m %p\n' >> permissions_backup.txt # Directories
```

## AWS Linux Specific Notes

### EC2 User Management

```bash
# Default users in AWS Linux (pre-configured system accounts)
# - ec2-user (Amazon Linux)
# - ubuntu (Ubuntu)
# - admin (Debian)

# Add user to sudo group (grant administrative privileges)
sudo usermod -a -G sudo username      # Ubuntu/Debian (sudo group)
sudo usermod -a -G wheel username     # Amazon Linux/RHEL/CentOS (wheel group)

# Configure SSH keys for new user (enable SSH access)
sudo mkdir /home/username/.ssh         # Create SSH directory
sudo cp ~/.ssh/authorized_keys /home/username/.ssh/  # Copy SSH keys
sudo chown -R username:username /home/username/.ssh  # Set ownership
sudo chmod 700 /home/username/.ssh     # Secure SSH directory
sudo chmod 600 /home/username/.ssh/authorized_keys   # Secure keys file
```mod -a -G wheel username     # Amazon Linux/RHEL/CentOS

# Configure SSH keys for new user
sudo mkdir /home/username/.ssh
sudo cp ~/.ssh/authorized_keys /home/username/.ssh/
sudo chown -R username:username /home/username/.ssh
sudo chmod 700 /home/username/.ssh
sudo chmod 600 /home/username/.ssh/authorized_keys
```

## Quick Reference

### Common Commands Summary

```bash
# User Management (account creation and modification commands)
useradd      # Add new user account
userdel      # Delete user account
usermod      # Modify existing user account
passwd       # Set or change user password
id           # Display user and group IDs
who          # Show who is currently logged in

# Group Management (group creation and membership commands)
groupadd     # Create new group
groupdel     # Delete group
groupmod     # Modify existing group
groups       # Display user's group memberships
gpasswd      # Administer group membership

# Permissions (file and directory access control commands)
chmod        # Change file permissions (read, write, execute)
chown        # Change file ownership (user and group)
chgrp        # Change group ownership only
umask        # Set default permissions for new files
getfacl      # Get Access Control List permissions
setfacl      # Set Access Control List permissions

# File Information (commands to view file attributes)
ls -la       # List files with detailed permissions
stat         # Display detailed file information
file         # Determine file type
find         # Search for files with specific attributes
```

### Permission Quick Reference

| Permission | Octal | Binary | Meaning |
|------------|-------|--------|---------|
| --- | 0 | 000 | No permissions |
| --x | 1 | 001 | Execute only |
| -w- | 2 | 010 | Write only |
| -wx | 3 | 011 | Write and execute |
| r-- | 4 | 100 | Read only |
| r-x | 5 | 101 | Read and execute |
| rw- | 6 | 110 | Read and write |
| rwx | 7 | 111 | Read, write, and execute |


**Note**: Always test permission changes in a safe environment first. Some commands require sudo privileges and can affect system security.

**Contributing**: Feel free to submit issues and enhancement requests!
