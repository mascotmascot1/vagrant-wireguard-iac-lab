# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
	# Path to the main SSH daemon configuration file (Global due to extensive use).
	$sshdcfg_path = "/etc/ssh/sshd_config"
	# Set predefined credentials for the 'ubuntu' user (Global due to extensive use).
	$credentials = 'ubuntu:123456ubuntu'
	# Path to the directory containing SSH config overrides (Local Ruby variable).
	sshdcfg_dir = "/etc/ssh/sshd_config.d"

	# --- VM Settings ---
	# Define the base box for all VMs.
	config.vm.box = "ubuntu/jammy64"
	# Disable checking for box updates on 'vagrant up' for faster starts.
	config.vm.box_check_update = false
	# Disable the default synchronised folder.
	config.vm.synced_folder ".", "/vagrant", disabled: true

	# --- Global Provisioner: Base System & SSH Hardening ---
	# This script runs on ALL VMs first.
	config.vm.provision "shell", inline: <<-SHELL
	echo "--- [1] Updating package lists ---"
	apt-get update
	echo "--- [2] Upgrading all installed packages ---"
	apt-get upgrade -y

	echo "--- [3] Setting predefined password for 'ubuntu' user ---"
	echo #{$credentials} | chpasswd

	# This 'if' block makes the script more robust.
	echo "--- [4] Checking for cloud-init SSH override directory ---"
	if [ -d #{sshdcfg_dir} ]; then
		# This find command is safer than a simple 'rm', as it only removes
		# files with 'cloudimg' in the name from that specific directory.
		find #{sshdcfg_dir} -maxdepth 1 -type f -name '*cloudimg*.conf' -delete
	fi

	echo "--- [6] Applying security settings to #{$sshdcfg_path} ---"
	# Use 'sed' to find and replace (or uncomment) settings in the main SSH config.
	# Enforce modern SSH protocol.
	sed -i 's/^#*Protocol .*/Protocol 2/' #{$sshdcfg_path}
	# Set a short login grace time.
	sed -i 's/^#*LoginGraceTime .*/LoginGraceTime 10s/' #{$sshdcfg_path}
	# Limit failed authentication attempts.
	sed -i 's/^#*MaxAuthTries .*/MaxAuthTries 2/' #{$sshdcfg_path}
	# Limit concurrent sessions.
	sed -i 's/^#*MaxSessions .*/MaxSessions 2/' #{$sshdcfg_path}
	# Disallow empty passwords. 
	sed -i 's/^#*PermitEmptyPasswords .*/PermitEmptyPasswords no/' #{$sshdcfg_path}
	# Disable less secure host-based authentication.
	sed -i 's/^#*HostbasedAuthentication .*/HostbasedAuthentication no/' #{$sshdcfg_path}
 
	# IMPORTANT: Temporarily enable password auth.
	# This is required for vm1's provisioner (sshpass) to work.
	echo "--- [7] Temporarily enabling PasswordAuthentication ---"
	sed -i 's/^#*PasswordAuthentication .*/PasswordAuthentication yes/' #{$sshdcfg_path}
	
	# Ensure public key auth (our final goal) is enabled.
	sed -i 's/^#*PubkeyAuthentication .*/PubkeyAuthentication yes/' #{$sshdcfg_path}
	# Disable root login via SSH (security best practice).
	sed -i 's/^#*PermitRootLogin .*/PermitRootLogin no/' #{$sshdcfg_path}

	echo "--- [8] Restarting SSH daemon to apply changes ---"
	systemctl restart sshd
	
	echo "--- [9] End of Global Provisioner ---"
SHELL

	# ##########################################################################
	# ### VIRTUAL MACHINE DEFINITION: VM2 (WIREGUARD SERVER & DOCKER HOST) ###
	# ##########################################################################
	config.vm.define "vm2" do |vm2|
		# Set the static hostname.
		vm2.vm.hostname = "vm2"
		# Assign a static IP address for the private network interface.
		vm2.vm.network "private_network", ip: "192.168.56.101"

		# SECURITY NOTE: Bound to 127.0.0.1 on the host machine to protect unencrypted 
        # HTTP traffic used by wireguard-ui. This is a "Security by Design" approach 
        # for local laboratory environments.
		#
		# Forward localhost (due to unencrypted http protocol used by wg-ui) port 15000 to guest port 5000.
		# This exposes the WireGuard UI web interface to the host machine.
		vm2.vm.network "forwarded_port", guest: 6000, host: 16000, host_ip: "127.0.0.1"

		# Forward host port 51830 to guest port 51820 for Wireguard server.
		vm2.vm.network "forwarded_port", guest: 51820, host: 51820, protocol: "udp"
		
		# Provisioner for vm2.
		vm2.vm.provision "shell", inline: <<-'SHELL'
		# Set DEBIAN_FRONTEND to noninteractive to prevent apt from requiring
		# user interaction during package installations.
		export DEBIAN_FRONTEND=noninteractive

		# --- Docker Installation (Official Method) ---
		echo "--- [1] Installing Docker from official repository ---"
		apt-get install -y ca-certificates curl

		# Define variables for cleaner configuration (DRY Principle).
		KEYRINGS_DIR="/etc/apt/keyrings"
		DOCKER_GPG_KEY="${KEYRINGS_DIR}/docker.asc"

		# Create the directory for APT keyrings.
		install -m 0755 -d /etc/apt/keyrings
		# Download Docker's official GPG key.
		curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
		# Make the key readable by apt.
		chmod a+r /etc/apt/keyrings/docker.asc

		# Add the Docker repository to APT sources, using the architecture and distribution codename.
		echo \
			"deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
			$(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}") stable" | \
			tee /etc/apt/sources.list.d/docker.list > /dev/null
		apt-get update

		# Install the Docker engine, CLI, Containerd, and Compose Plugin.
		apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
		
		# --- WireGuard UI Installation ---
		echo "--- [2] Installing Wireguard Tools ---"
		# Install the core userspace tools (wg and wg-quick)
		apt-get install -y wireguard-tools

		# Ensure the default WireGuard configuration directory exists.
		mkdir -p /etc/wireguard

		echo "--- [3] Installing wireguard-ui ---"
		# Dynamically find the latest version tag for wireguard-ui from the GitHub API.
		LATEST_VERSION=$(curl -s "https://api.github.com/repos/ngoduykhanh/wireguard-ui/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
		echo "--- [4] Latest version found: ${LATEST_VERSION} ---"
		# Download the corresponding release binary to a temporary file.
		wget "https://github.com/ngoduykhanh/wireguard-ui/releases/download/${LATEST_VERSION}/wireguard-ui-${LATEST_VERSION}-linux-amd64.tar.gz" -O /tmp/wireguard-ui.tar.gz
		
		# Create the application directory in /opt, the standard location for optional software.
		mkdir -p /opt/wireguard-ui
		# Extract only the 'wireguard-ui' binary into the application directory.
		tar -xzf /tmp/wireguard-ui.tar.gz -C /opt/wireguard-ui/ wireguard-ui
		# Ensure the binary is executable.
		chmod +x /opt/wireguard-ui/wireguard-ui
		# Clean up the temporary archive file.
		rm /tmp/wireguard-ui.tar.gz

		# Create the .env file for the WireGuard UI service.
    # These environment variables are read by the wireguard-ui binary at launch,
    # as defined in its documentation (https://github.com/ngoduykhanh/wireguard-ui).
    echo "--- [5] Creating environment file (/etc/wireguard/wgui.env) ---"
		cat > /etc/wireguard/wgui.env <<-EOF
		WGUI_USERNAME=admin
		WGUI_PASSWORD=super_secret_password_123
		SESSION_SECRET=a_very_long_and_random_string_nobody_can_guess_12345
		BIND_ADDRESS=0.0.0.0:6000
		EOF

		# Define the systemd service to manage the wireguard-ui process.
    echo "--- [6] Creating systemd service file (wireguard-ui.service) ---"
		cat > /etc/systemd/system/wireguard-ui.service <<-EOF
		[Unit]
		Description=WireGuard UI
		# This ensures the service starts only after the network is ready.
		After=network.target

		[Service]
		Type=simple
		# Set the working directory to where the database (db/) and configs are expected.
		WorkingDirectory=/etc/wireguard
		# Load the credentials and port settings from the .env file.
		EnvironmentFile=/etc/wireguard/wgui.env
		# Define the full path to the executable to be run.
		ExecStart=/opt/wireguard-ui/wireguard-ui
		# Automatically restart the service if it crashes.
		Restart=always
		RestartSec=3

		[Install]
		# Enable the service to start at boot for the standard multi-user runlevel.
		WantedBy=multi-user.target
		EOF

		# Tell systemd to re-read its configuration files from disk.
		systemctl daemon-reload
		# Enable the service to start on boot and start it immediately.
		# This first run creates the database and the initial wg0.conf.
		echo "--- [7] Enabling and starting wireguard-ui.service ---"
		systemctl enable --now wireguard-ui.service

		# Enable and start the actual WireGuard tunnel (wg0).
		# This must run *after* wireguard-ui's first run, which creates the wg0.conf.
		echo "--- [8] Enabling and starting wg-quick@wg0.service ---"
		sleep 15
		systemctl enable --now wg-quick@wg0.service

		# Workaround for a known initialisation bug in some wireguard-ui versions.
		# A quick restart after the DB and tunnel are up resolves login issues.
		echo "--- [9] Restarting WireGuard UI to bypass login bug ---"
		systemctl restart wireguard-ui.service

		# --- Config Auto-Reload ---
    echo "--- [10] Setting up config auto-reload ---"
		cd /etc/systemd/system/

		# Create the .service unit (the 'executor') to be triggered.
    echo "---     Creating wg-auto-reload.service (the executor) ---"
		cat > wg-auto-reload.service <<-EOF
		[Unit]
		Description=Restart WireGuard
		After=network.target
		[Service]
		Type=oneshot
		ExecStart=/usr/bin/systemctl restart wg-quick@wg0.service
		[Install]
		# Create a hard dependency: this .service is 'RequiredBy' (enabled by) its .path unit.
		RequiredBy=wg-auto-reload.path
		EOF

		# Create the .path unit (the 'watchdog') to act as the trigger.
    echo "---     Creating wg-auto-reload.path (the watchdog) ---"
		cat > wg-auto-reload.path  <<-EOF
		[Unit]
		Description=Watch /etc/wireguard/wg0.conf for changes
		[Path]
		# Define the specific file to monitor for modifications.
		PathModified=/etc/wireguard/wg0.conf
		[Install]
		# Enable this watchdog to start at boot.
		WantedBy=multi-user.target
		EOF
		
		# Tell systemd to re-read the new .path and .service files.
    echo "--- [11] Reloading systemd daemon for auto-reload ---"
		systemctl daemon-reload

		# Enable the 'watchdog' (.path) to ensure it starts on VM boot.
    # Thanks to 'RequiredBy=' in the .service, the 'executor' (.service) will be enabled automatically.
    echo "--- [12] Enabling wg-auto-reload.path ---"
		systemctl enable wg-auto-reload.path 

		# Start the 'watchdog' (.path) immediately, without waiting for a reboot.
    # The 'executor' (.service) does NOT start; it waits for the 'watchdog' to trigger it.
    echo "--- [13] Starting wg-auto-reload.path ---"
		systemctl start wg-auto-reload.path

		echo "--- [14] Provisioning complete for vm2 ---"
	SHELL
	end

	# ##########################################################################
	# ### VIRTUAL MACHINE DEFINITION: VM3 (STANDARD USER & ACCESS CONTROL) ###
	# ##########################################################################
	config.vm.define "vm3" do |vm3|
		# Define a local Ruby variable for the user being created.
		vm3_user = "adam"
		
		# Set the static hostname.
		vm3.vm.hostname = "vm3"
		# Assign a static IP address for the private network interface.
		vm3.vm.network "private_network", ip: "192.168.56.102"

		# Provisioner for vm3.
		vm3.vm.provision "shell", inline: <<-SHELL
		echo "--- [1] Creating user '#{vm3_user}' ---"
		useradd -m -s /bin/bash -U #{vm3_user}

		echo "--- [2] Granting '#{vm3_user}' access to the 'sudo' group ---"
		usermod -aG sudo #{vm3_user}

		echo "--- [3] Configuring passwordless sudo for '#{vm3_user}' ---"
		# Create a new file in the sudoers drop-in directory.
		echo "#{vm3_user} ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/#{vm3_user}

		# Set the correct permissions for the sudoers file.
		# This is critical for security and for 'sudo' to accept the file.
		chmod 440 /etc/sudoers.d/#{vm3_user}
		echo "--- [4] Provisioning complete for vm3 ---"
		SHELL
	end

	# ########################################################################
	# ### VIRTUAL MACHINE DEFINITION: VM1 (DESKTOP & PROVISIONER JUMP HOST) ###
	# ########################################################################
	config.vm.define "vm1" do |vm1|
		# Set the static hostname.
		vm1.vm.hostname = "vm1"
		# Assign the primary IP for the private network.
		vm1.vm.network "private_network", ip: "192.168.56.100"
		# Forward RDP port 3389 (guest) to 13389 (host) for remote desktop access.
		vm1.vm.network "forwarded_port", guest: 3389, host: 13389

		# Provisioner for vm1.
		vm1.vm.provision "shell", inline: <<-SHELL
		# Prevent apt-get/dpkg from prompting for user input during installation.
		export DEBIAN_FRONTEND=noninteractive

		echo "--- [1] Installing Desktop Environment, XRDP, Snap-store and Tools ---"
		apt-get install -y ubuntu-desktop-minimal xrdp
		snap install snap-store
		snap install chromium
		# Install sshpass, required to automate password-based SSH login.
		apt-get install -y sshpass

		echo "--- [2] Configuring XRDP ---"
		# Add the 'xrdp' user to the 'ssl-cert' group.
		# This is a critical step, as XRDP needs to read SSL keys to function.
		adduser xrdp ssl-cert
		service xrdp restart

		echo "--- [3] Configuring internal DNS via /etc/hosts ---"
		# Add host entries for vm2 and vm3. This allows vm1 to resolve
		# them by name (e.g., 'ssh ubuntu@vm2').
		cat >> /etc/hosts <<-EOF
		192.168.56.101 vm2
		192.168.56.102 vm3
		EOF

		# --- SSH Key Provisioning Pipeline ---
		# This section turns vm1 into a 'jump host', enabling
		# passwordless SSH access to vm2 and vm3.
				
		echo "--- [4] Generating SSH key for 'ubuntu' user on vm1 ---"
		# Run as 'ubuntu' user. The [ -f ... ] || ... logic makes this
		# command idempotent (it only runs if the key is missing).
		runuser -l ubuntu -c 'mkdir -p ~/.ssh && chmod 700 ~/.ssh && [ -f ~/.ssh/id_ed25519 ] || ssh-keygen -t ed25519 -N "" -f ~/.ssh/id_ed25519'

		echo "--- [5] Scanning and adding host keys for vm2 & vm3 ---"
		# Run as 'ubuntu' to populate their known_hosts file.
		# This prevents interactive prompts on first connection.
		runuser -l ubuntu -c 'ssh-keyscan -H vm2 vm3 >> ~/.ssh/known_hosts'

		echo "--- [6] Copying 'ubuntu' public key to vm2 & vm3 via password ---"
		# Loop through the target hosts.
		for host in vm2 vm3; do
			# Run sshpass as the 'ubuntu' user.
			# We extract the username and password from the Ruby 'credentials' variable.
			# -o PreferredAuthentications=password: FORCES the client to use the password.
		runuser -l ubuntu -c "sshpass -p '#{$credentials.split(':')[1]}' ssh-copy-id \
			-i ~/.ssh/id_ed25519.pub \
			-o StrictHostKeyChecking=no \
			-o PreferredAuthentications=password \
			-o IdentitiesOnly=yes \
			#{$credentials.split(':')[0]}@${host}"
		done

		# --- Final Security Hardening ---
		# Now that keys are provisioned, we disable password login
		# everywhere for security.

		echo "--- [7] Remotely disabling PasswordAuthentication on vm2 & vm3 ---"
		# Loop again, this time connecting using the key.
		# The provisioner (root) runs 'ssh' but uses the '-i' flag
		# to specify the key belonging to the 'ubuntu' user.
		for host in vm2 vm3; do
			ssh -i /home/ubuntu/.ssh/id_ed25519 \
				-o StrictHostKeyChecking=no \
				-o IdentitiesOnly=yes \
				ubuntu@${host} \
				"sudo sed -i 's/^#*PasswordAuthentication .*/PasswordAuthentication no/' #{$sshdcfg_path} && sudo systemctl restart sshd"
		done

		echo "--- [8] Disabling PasswordAuthentication on vm1 (local) ---"
		# Finally, lock down the jump host itself.
		sed -i 's/^#*PasswordAuthentication .*/PasswordAuthentication no/' #{$sshdcfg_path} && systemctl restart sshd

		echo "--- [9] Provisioning complete for vm1 ---"
		SHELL
	end
end
