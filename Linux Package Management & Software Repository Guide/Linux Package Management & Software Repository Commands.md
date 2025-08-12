# Linux Package Management & Software Repository Commands

A comprehensive guide to package management and software repository commands for major Linux distributions including Ubuntu/Debian, CentOS/RHEL/Amazon Linux, and universal package managers.

## Table of Contents
- [APT (Ubuntu/Debian)](#apt-ubuntudebian)
- [YUM (CentOS/RHEL/Amazon Linux)](#yum-centosrhelamazon-linux)
- [DNF (Fedora/Modern RHEL)](#dnf-fedoramodern-rhel)
- [Snap (Universal)](#snap-universal)
- [Flatpak (Universal)](#flatpak-universal)
- [AppImage (Universal)](#appimage-universal)
- [Source Package Management](#source-package-management)

---

## APT (Ubuntu/Debian)

### Package Installation & Removal
```bash
sudo apt update
# Updates the local package index from all configured repositories

sudo apt upgrade
# Upgrades all installed packages to their latest available versions

sudo apt install package_name
# Installs a specific package and its dependencies

sudo apt install package1 package2
# Installs multiple packages at once

sudo apt remove package_name
# Removes a package but keeps configuration files

sudo apt purge package_name
# Completely removes a package including configuration files

sudo apt autoremove
# Removes packages that were installed as dependencies but are no longer needed
```

### Package Information & Search
```bash
apt search keyword
# Searches for packages containing the keyword in name or description

apt show package_name
# Displays detailed information about a specific package

apt list --installed
# Lists all currently installed packages

apt list --upgradable
# Shows packages that have available updates

dpkg -l
# Lists all installed packages with version information (low-level command)

dpkg -L package_name
# Lists all files installed by a specific package
```

### Repository Management
```bash
sudo add-apt-repository ppa:repository/name
# Adds a Personal Package Archive (PPA) to your system

sudo add-apt-repository --remove ppa:repository/name
# Removes a PPA from your system

sudo apt edit-sources
# Opens the sources.list file for editing repository configurations

cat /etc/apt/sources.list
# Displays the main repository configuration file

ls /etc/apt/sources.list.d/
# Lists additional repository configuration files
```

### Cache & Cleanup
```bash
sudo apt clean
# Removes all downloaded package files from the cache

sudo apt autoclean
# Removes only outdated downloaded package files

apt-cache policy package_name
# Shows available versions and current installation status of a package

sudo apt --fix-broken install
# Attempts to fix broken package dependencies
```

---

## YUM (CentOS/RHEL/Amazon Linux)

### Package Installation & Removal
```bash
sudo yum update
# Updates all installed packages to their latest versions

sudo yum install package_name
# Installs a specific package and its dependencies

sudo yum groupinstall "Group Name"
# Installs a predefined group of related packages

sudo yum remove package_name
# Removes a package but may leave dependencies

sudo yum autoremove
# Removes packages that were installed as dependencies but are no longer needed

sudo yum reinstall package_name
# Reinstalls a package (useful for fixing corrupted installations)
```

### Package Information & Search
```bash
yum search keyword
# Searches for packages containing the keyword

yum info package_name
# Displays detailed information about a specific package

yum list installed
# Lists all currently installed packages

yum list available
# Lists all packages available for installation

yum grouplist
# Lists available package groups

rpm -qa
# Lists all installed RPM packages (low-level command)

rpm -ql package_name
# Lists all files installed by a specific package
```

### Repository Management
```bash
sudo yum-config-manager --add-repo repository_url
# Adds a new repository to the system

sudo yum-config-manager --enable repository_name
# Enables a disabled repository

sudo yum-config-manager --disable repository_name
# Disables an active repository

yum repolist
# Lists all configured repositories and their status

cat /etc/yum.conf
# Displays the main YUM configuration file

ls /etc/yum.repos.d/
# Lists repository configuration files
```

### Cache & Cleanup
```bash
sudo yum clean all
# Cleans all cached data including packages and metadata

sudo yum clean packages
# Removes only cached packages

sudo yum makecache
# Downloads and caches metadata from all enabled repositories

yum history
# Shows a history of YUM transactions

sudo yum history undo ID
# Undoes a specific YUM transaction by ID
```

---

## DNF (Fedora/Modern RHEL)

### Package Installation & Removal
```bash
sudo dnf update
# Updates all installed packages (same as 'dnf upgrade')

sudo dnf install package_name
# Installs a specific package and its dependencies

sudo dnf group install "Group Name"
# Installs a predefined group of related packages

sudo dnf remove package_name
# Removes a package and unused dependencies automatically

sudo dnf autoremove
# Removes packages that were installed as dependencies but are no longer needed

sudo dnf reinstall package_name
# Reinstalls a package
```

### Package Information & Search
```bash
dnf search keyword
# Searches for packages containing the keyword

dnf info package_name
# Displays detailed information about a specific package

dnf list installed
# Lists all currently installed packages

dnf list available
# Lists all packages available for installation

dnf group list
# Lists available package groups

dnf provides */filename
# Finds which package provides a specific file
```

### Repository Management
```bash
sudo dnf config-manager --add-repo repository_url
# Adds a new repository to the system

sudo dnf config-manager --set-enabled repository_name
# Enables a disabled repository

sudo dnf config-manager --set-disabled repository_name
# Disables an active repository

dnf repolist
# Lists all configured repositories and their status
```

---

## Snap (Universal)

### Package Management
```bash
sudo snap install package_name
# Installs a snap package

sudo snap install package_name --classic
# Installs a snap with classic confinement (more system access)

sudo snap remove package_name
# Removes a snap package

sudo snap refresh
# Updates all installed snaps

sudo snap refresh package_name
# Updates a specific snap package
```

### Package Information
```bash
snap find keyword
# Searches for available snap packages

snap list
# Lists all installed snap packages

snap info package_name
# Shows detailed information about a snap package

snap version
# Shows the version of snapd and the core snap
```

---

## Flatpak (Universal)

### Package Management
```bash
flatpak install flathub app_id
# Installs a Flatpak application from Flathub repository

flatpak uninstall app_id
# Removes a Flatpak application

flatpak update
# Updates all installed Flatpak applications

flatpak run app_id
# Runs a specific Flatpak application
```

### Repository Management
```bash
flatpak remote-add --if-not-exists flathub https://flathub.org/repo/flathub.flatpakrepo
# Adds the Flathub repository

flatpak remote-list
# Lists all configured Flatpak repositories

flatpak search keyword
# Searches for available Flatpak applications
```

---

## AppImage (Universal)

### Usage
```bash
chmod +x application.AppImage
# Makes an AppImage executable

./application.AppImage
# Runs the AppImage application

./application.AppImage --appimage-extract
# Extracts the contents of an AppImage for inspection
```

---

## Source Package Management

### Building from Source
```bash
sudo apt build-dep package_name
# (Ubuntu/Debian) Installs build dependencies for a package

sudo yum-builddep package_name
# (RHEL/CentOS) Installs build dependencies for a package

./configure
# Configures the build system (typical for autotools-based projects)

make
# Compiles the source code

sudo make install
# Installs the compiled software system-wide

make uninstall
# Removes the installed software (if supported by the Makefile)
```

### Alternative Installation Prefix
```bash
./configure --prefix=/usr/local
# Installs to /usr/local instead of /usr (keeps system packages separate)

./configure --prefix=$HOME/local
# Installs to user's home directory (no sudo required)
```

---

## Useful Tips

### Security & Best Practices
- Always run `sudo apt update` before installing packages on Debian/Ubuntu systems
- Use `sudo yum update` regularly on RHEL-based systems to keep security patches current
- Prefer official repositories over third-party ones when possible
- Read package descriptions and check dependencies before installing unknown software

### Troubleshooting Common Issues
```bash
sudo dpkg --configure -a
# (Debian/Ubuntu) Fixes interrupted package installations

sudo apt --fix-broken install
# (Debian/Ubuntu) Attempts to fix dependency issues

sudo yum clean all && sudo yum update
# (RHEL/CentOS) Clears cache and updates to fix repository issues

sudo dnf distro-sync
# (Fedora) Synchronizes packages with the latest available versions
```

### System Information
```bash
lsb_release -a
# Shows Linux distribution information

uname -r
# Shows kernel version

cat /etc/os-release
# Displays OS identification information
```

---

*Last updated: August 2025*
*For the most current information, consult your distribution's official documentation.*
