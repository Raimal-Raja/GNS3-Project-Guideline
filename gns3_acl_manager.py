"""
GNS3 ACL Manager - Remote SSH Control Application
Manages Access Control Lists for GNS3 Open vSwitch topology from host machine
Author: ACL Management System
Version: 2.0
"""

import paramiko
import sys
import os
import json
import time
from typing import List, Dict, Tuple
from getpass import getpass

class Colors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class SSHConnection:
    """Manages SSH connections to GNS3 devices"""
    
    def __init__(self, hostname: str, username: str, password: str, port: int = 22):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.port = port
        self.client = None
        self.connected = False
    
    def connect(self) -> bool:
        """Establish SSH connection"""
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.client.connect(
                hostname=self.hostname,
                port=self.port,
                username=self.username,
                password=self.password,
                timeout=10,
                allow_agent=False,
                look_for_keys=False
            )
            self.connected = True
            return True
        except paramiko.AuthenticationException:
            print(f"{Colors.RED}✗ Authentication failed for {self.hostname}{Colors.END}")
            return False
        except paramiko.SSHException as e:
            print(f"{Colors.RED}✗ SSH error: {str(e)}{Colors.END}")
            return False
        except Exception as e:
            print(f"{Colors.RED}✗ Connection error: {str(e)}{Colors.END}")
            return False
    
    def execute_command(self, command: str, timeout: int = 10) -> Tuple[int, str, str]:
        """Execute command on remote device"""
        if not self.connected:
            return -1, "", "Not connected"
        
        try:
            stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)
            exit_code = stdout.channel.recv_exit_status()
            output = stdout.read().decode('utf-8', errors='ignore')
            error = stderr.read().decode('utf-8', errors='ignore')
            return exit_code, output, error
        except Exception as e:
            return -1, "", str(e)
    
    def close(self):
        """Close SSH connection"""
        if self.client:
            self.client.close()
            self.connected = False

class GNS3Device:
    """Represents a GNS3 network device"""
    
    def __init__(self, name: str, mgmt_ip: str, device_ips: List[str], ssh_conn: SSHConnection):
        self.name = name
        self.mgmt_ip = mgmt_ip
        self.device_ips = device_ips
        self.ssh = ssh_conn
        self.is_reachable = False
    
    def test_connection(self) -> bool:
        """Test if device is reachable"""
        if self.ssh.connect():
            code, out, err = self.ssh.execute_command("echo 'connected'")
            self.is_reachable = (code == 0)
            return self.is_reachable
        return False
    
    def execute(self, command: str) -> Tuple[int, str, str]:
        """Execute command on this device"""
        if not self.is_reachable:
            if not self.test_connection():
                return -1, "", "Device not reachable"
        return self.ssh.execute_command(command)

class ACLManagerRemote:
    """Main ACL Manager for remote control"""
    
    def __init__(self):
        self.devices: Dict[str, GNS3Device] = {}
        self.config_file = "gns3_acl_config.json"
        self.current_device = None
        self.load_config()
    
    def load_config(self):
        """Load device configuration from file"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    data = json.load(f)
                    print(f"{Colors.GREEN}✓ Configuration loaded from {self.config_file}{Colors.END}")
                    return data
            except Exception as e:
                print(f"{Colors.YELLOW}⚠ Could not load config: {e}{Colors.END}")
        return None
    
    def save_config(self, config: dict):
        """Save device configuration to file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=4)
            print(f"{Colors.GREEN}✓ Configuration saved to {self.config_file}{Colors.END}")
        except Exception as e:
            print(f"{Colors.RED}✗ Could not save config: {e}{Colors.END}")
    
    def setup_devices(self):
        """Interactive device setup"""
        print(f"\n{Colors.BOLD}=== GNS3 Device Configuration ==={Colors.END}\n")
        print(f"{Colors.CYAN}Configure your GNS3 devices (OVS1-4){Colors.END}")
        print(f"{Colors.YELLOW}Note: You need SSH access to your GNS3 VM/devices{Colors.END}\n")
        
        config = {}
        
        # Get common credentials
        print(f"{Colors.BOLD}Common SSH Credentials:{Colors.END}")
        username = input("Enter SSH username (default: root): ") or "root"
        password = getpass("Enter SSH password: ")
        
        # Get GNS3 VM/Host info
        gns3_host = input("\nEnter GNS3 VM IP address (e.g., 192.168.122.1): ")
        base_port = int(input("Enter base SSH port for devices (default: 5000): ") or "5000")
        
        config['credentials'] = {
            'username': username,
            'password': password,
            'gns3_host': gns3_host,
            'base_port': base_port
        }
        
        # Define devices
        devices_info = [
            {'name': 'OVS1', 'eth0': '10.0.1.1', 'eth1': '10.0.2.1'},
            {'name': 'OVS2', 'eth0': '10.0.2.2', 'eth1': '10.0.3.1'},
            {'name': 'OVS3', 'eth0': '10.0.3.2', 'eth1': '10.0.4.1'},
            {'name': 'OVS4', 'eth0': '10.0.4.2', 'eth1': '10.0.5.1'}
        ]
        
        config['devices'] = []
        
        print(f"\n{Colors.CYAN}Testing connections to devices...{Colors.END}\n")
        
        for idx, dev_info in enumerate(devices_info):
            port = base_port + idx
            print(f"Configuring {dev_info['name']} (port {port})...")
            
            device_config = {
                'name': dev_info['name'],
                'mgmt_ip': gns3_host,
                'port': port,
                'device_ips': [dev_info['eth0'], dev_info['eth1']]
            }
            
            # Test connection
            ssh = SSHConnection(gns3_host, username, password, port)
            if ssh.connect():
                code, out, err = ssh.execute_command("hostname")
                if code == 0:
                    print(f"{Colors.GREEN}✓ {dev_info['name']} connected successfully{Colors.END}")
                    ssh.close()
                else:
                    print(f"{Colors.YELLOW}⚠ {dev_info['name']} connected but command failed{Colors.END}")
            else:
                print(f"{Colors.RED}✗ {dev_info['name']} connection failed (port {port}){Colors.END}")
            
            config['devices'].append(device_config)
        
        self.save_config(config)
        return config
    
    def connect_devices(self, config: dict):
        """Connect to all configured devices"""
        if not config:
            return False
        
        creds = config['credentials']
        
        for dev_config in config['devices']:
            ssh = SSHConnection(
                hostname=dev_config['mgmt_ip'],
                username=creds['username'],
                password=creds['password'],
                port=dev_config['port']
            )
            
            device = GNS3Device(
                name=dev_config['name'],
                mgmt_ip=dev_config['mgmt_ip'],
                device_ips=dev_config['device_ips'],
                ssh_conn=ssh
            )
            
            self.devices[dev_config['name']] = device
        
        return True
    
    def print_banner(self):
        """Print application banner"""
        banner = f"""
{Colors.CYAN}{'='*70}
    GNS3 ACL MANAGER - Remote SSH Control System
{'='*70}{Colors.END}
{Colors.YELLOW}Topology: VPC1 → OVS1 → OVS2 → OVS3 → OVS4 → VPC2{Colors.END}
{Colors.GREEN}Control your GNS3 network from your Ubuntu host machine{Colors.END}
"""
        print(banner)
    
    def show_main_menu(self):
        """Display main menu"""
        menu = f"""
{Colors.BOLD}Main Menu:{Colors.END}
{Colors.GREEN}[1]{Colors.END} Select Device
{Colors.GREEN}[2]{Colors.END} Add ACL Rule
{Colors.GREEN}[3]{Colors.END} Remove ACL Rule
{Colors.GREEN}[4]{Colors.END} View ACL Rules (Current Device)
{Colors.GREEN}[5]{Colors.END} View All Devices Status
{Colors.GREEN}[6]{Colors.END} Test Connectivity
{Colors.GREEN}[7]{Colors.END} ACL Templates (Quick Setup)
{Colors.GREEN}[8]{Colors.END} Batch Operations (All Devices)
{Colors.GREEN}[9]{Colors.END} Reconfigure Devices
{Colors.GREEN}[0]{Colors.END} Exit

{Colors.CYAN}Current Device: {self.current_device.name if self.current_device else 'None'}{Colors.END}

{Colors.CYAN}Choose an option:{Colors.END} """
        return input(menu)
    
    def select_device(self):
        """Device selection menu"""
        print(f"\n{Colors.BOLD}=== Select Device ==={Colors.END}\n")
        
        device_list = list(self.devices.keys())
        for idx, name in enumerate(device_list, 1):
            device = self.devices[name]
            status = f"{Colors.GREEN}●{Colors.END}" if device.is_reachable else f"{Colors.RED}●{Colors.END}"
            print(f"{status} {Colors.GREEN}[{idx}]{Colors.END} {name} - IPs: {', '.join(device.device_ips)}")
        
        print(f"{Colors.GREEN}[0]{Colors.END} Back to Main Menu")
        
        choice = input(f"\n{Colors.CYAN}Select device:{Colors.END} ")
        
        try:
            choice_idx = int(choice)
            if choice_idx == 0:
                return
            if 1 <= choice_idx <= len(device_list):
                device_name = device_list[choice_idx - 1]
                device = self.devices[device_name]
                
                print(f"\n{Colors.CYAN}Testing connection to {device_name}...{Colors.END}")
                if device.test_connection():
                    self.current_device = device
                    print(f"{Colors.GREEN}✓ Connected to {device_name}{Colors.END}")
                else:
                    print(f"{Colors.RED}✗ Failed to connect to {device_name}{Colors.END}")
                
                input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")
        except ValueError:
            print(f"{Colors.RED}Invalid input{Colors.END}")
    
    def add_acl_rule(self):
        """Add ACL rule menu"""
        if not self.current_device:
            print(f"\n{Colors.RED}✗ Please select a device first{Colors.END}")
            input(f"{Colors.CYAN}Press Enter to continue...{Colors.END}")
            return
        
        print(f"\n{Colors.BOLD}=== Add ACL Rule on {self.current_device.name} ==={Colors.END}\n")
        print(f"{Colors.GREEN}[1]{Colors.END} Blackhole Route (Block IP/Network)")
        print(f"{Colors.GREEN}[2]{Colors.END} ICMP Control (Enable/Disable Ping)")
        print(f"{Colors.GREEN}[3]{Colors.END} Interface Forwarding Control")
        print(f"{Colors.GREEN}[4]{Colors.END} Reverse Path Filtering")
        print(f"{Colors.GREEN}[5]{Colors.END} Rate Limiting")
        print(f"{Colors.GREEN}[0]{Colors.END} Back")
        
        choice = input(f"\n{Colors.CYAN}Choose ACL type:{Colors.END} ")
        
        if choice == '1':
            self.add_blackhole_route()
        elif choice == '2':
            self.control_icmp()
        elif choice == '3':
            self.control_interface_forwarding()
        elif choice == '4':
            self.control_rp_filter()
        elif choice == '5':
            self.set_rate_limiting()
    
    def add_blackhole_route(self):
        """Add blackhole route ACL"""
        print(f"\n{Colors.BOLD}=== Add Blackhole Route ==={Colors.END}")
        print(f"{Colors.YELLOW}Device: {self.current_device.name}{Colors.END}\n")
        
        source_ip = input("Enter source IP/Network (e.g., 10.0.1.2 or 10.0.1.0/24): ")
        dest_ip = input("Enter destination IP/Network to block (e.g., 10.0.5.2/32): ")
        table_num = input("Enter routing table number (100-252, default 100): ") or "100"
        priority = input("Enter rule priority (default 100): ") or "100"
        
        print(f"\n{Colors.CYAN}Executing commands on {self.current_device.name}...{Colors.END}")
        
        # Add blackhole route
        cmd1 = f"ip route add blackhole {dest_ip} table {table_num} 2>/dev/null || true"
        code1, out1, err1 = self.current_device.execute(cmd1)
        
        # Add routing rule
        cmd2 = f"ip rule add from {source_ip} table {table_num} priority {priority} 2>/dev/null || true"
        code2, out2, err2 = self.current_device.execute(cmd2)
        
        # Verify
        cmd3 = f"ip rule show | grep -E 'from {source_ip}|table {table_num}'"
        code3, out3, err3 = self.current_device.execute(cmd3)
        
        if code3 == 0 and out3:
            print(f"{Colors.GREEN}✓ Blackhole route added successfully!{Colors.END}")
            print(f"{Colors.BLUE}Source: {source_ip} → Destination: {dest_ip} (BLOCKED){Colors.END}")
            print(f"\n{Colors.CYAN}Verification:{Colors.END}")
            print(out3)
        else:
            print(f"{Colors.YELLOW}⚠ Rule may already exist or partially applied{Colors.END}")
        
        input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")
    
    def remove_acl_rule(self):
        """Remove ACL rule menu"""
        if not self.current_device:
            print(f"\n{Colors.RED}✗ Please select a device first{Colors.END}")
            input(f"{Colors.CYAN}Press Enter to continue...{Colors.END}")
            return
        
        print(f"\n{Colors.BOLD}=== Remove ACL Rule from {self.current_device.name} ==={Colors.END}\n")
        
        source_ip = input("Enter source IP/Network to remove: ")
        dest_ip = input("Enter destination IP/Network: ")
        table_num = input("Enter routing table number (default 100): ") or "100"
        
        print(f"\n{Colors.CYAN}Removing rules...{Colors.END}")
        
        # Remove routing rule
        cmd1 = f"ip rule del from {source_ip} table {table_num} 2>/dev/null || true"
        code1, out1, err1 = self.current_device.execute(cmd1)
        
        # Remove blackhole route
        cmd2 = f"ip route del blackhole {dest_ip} table {table_num} 2>/dev/null || true"
        code2, out2, err2 = self.current_device.execute(cmd2)
        
        print(f"{Colors.GREEN}✓ ACL rule removal attempted{Colors.END}")
        
        input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")
    
    def control_icmp(self):
        """Control ICMP on current device"""
        print(f"\n{Colors.BOLD}=== ICMP Control ==={Colors.END}")
        print(f"{Colors.YELLOW}Device: {self.current_device.name}{Colors.END}\n")
        
        action = input("Enable or Disable ICMP? (e/d): ").lower()
        
        value = "0" if action == 'e' else "1"
        cmd = f"echo {value} > /proc/sys/net/ipv4/icmp_echo_ignore_all"
        
        code, out, err = self.current_device.execute(cmd)
        
        if code == 0:
            status = "enabled" if value == "0" else "disabled"
            print(f"{Colors.GREEN}✓ ICMP {status} on {self.current_device.name}{Colors.END}")
        else:
            print(f"{Colors.RED}✗ Error: {err}{Colors.END}")
        
        # Verify
        code, out, err = self.current_device.execute("cat /proc/sys/net/ipv4/icmp_echo_ignore_all")
        if code == 0:
            status = "DISABLED" if out.strip() == "1" else "ENABLED"
            print(f"{Colors.BLUE}Current status: ICMP is {status}{Colors.END}")
        
        input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")
    
    def control_interface_forwarding(self):
        """Control interface forwarding"""
        print(f"\n{Colors.BOLD}=== Interface Forwarding Control ==={Colors.END}")
        print(f"{Colors.YELLOW}Device: {self.current_device.name}{Colors.END}\n")
        
        interface = input("Enter interface name (e.g., eth0, eth1): ")
        action = input("Enable or Disable forwarding? (e/d): ").lower()
        
        value = "1" if action == 'e' else "0"
        cmd = f"echo {value} > /proc/sys/net/ipv4/conf/{interface}/forwarding"
        
        code, out, err = self.current_device.execute(cmd)
        
        if code == 0:
            status = "enabled" if value == "1" else "disabled"
            print(f"{Colors.GREEN}✓ Forwarding {status} on {interface}{Colors.END}")
        else:
            print(f"{Colors.RED}✗ Error: {err}{Colors.END}")
        
        input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")
    
    def control_rp_filter(self):
        """Control reverse path filtering"""
        print(f"\n{Colors.BOLD}=== Reverse Path Filtering ==={Colors.END}")
        print(f"{Colors.YELLOW}Device: {self.current_device.name}{Colors.END}\n")
        
        action = input("Enable or Disable RP filter? (e/d): ").lower()
        
        value = "1" if action == 'e' else "0"
        cmd = f"echo {value} > /proc/sys/net/ipv4/conf/all/rp_filter"
        
        code, out, err = self.current_device.execute(cmd)
        
        if code == 0:
            status = "enabled" if value == "1" else "disabled"
            print(f"{Colors.GREEN}✓ RP filter {status}{Colors.END}")
        else:
            print(f"{Colors.RED}✗ Error: {err}{Colors.END}")
        
        input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")
    
    def set_rate_limiting(self):
        """Configure rate limiting"""
        print(f"\n{Colors.BOLD}=== Rate Limiting ==={Colors.END}")
        print(f"{Colors.YELLOW}Device: {self.current_device.name}{Colors.END}\n")
        
        print("1. ICMP Rate Limit")
        print("2. TCP SYN Backlog")
        choice = input("\nChoose option: ")
        
        if choice == '1':
            rate = input("Enter ICMP rate limit (packets/sec, default 10): ") or "10"
            cmd = f"echo {rate} > /proc/sys/net/ipv4/icmp_ratelimit"
        elif choice == '2':
            backlog = input("Enter TCP SYN backlog size (default 128): ") or "128"
            cmd = f"echo {backlog} > /proc/sys/net/ipv4/tcp_max_syn_backlog"
        else:
            print(f"{Colors.RED}Invalid choice{Colors.END}")
            return
        
        code, out, err = self.current_device.execute(cmd)
        
        if code == 0:
            print(f"{Colors.GREEN}✓ Rate limiting configured{Colors.END}")
        else:
            print(f"{Colors.RED}✗ Error: {err}{Colors.END}")
        
        input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")
    
    def view_acl_rules(self):
        """View ACL rules on current device"""
        if not self.current_device:
            print(f"\n{Colors.RED}✗ Please select a device first{Colors.END}")
            input(f"{Colors.CYAN}Press Enter to continue...{Colors.END}")
            return
        
        print(f"\n{Colors.BOLD}=== ACL Rules on {self.current_device.name} ==={Colors.END}\n")
        
        # IP Routing Rules
        print(f"{Colors.CYAN}IP Routing Rules:{Colors.END}")
        code, out, err = self.current_device.execute("ip rule show")
        if code == 0:
            print(out if out else "No custom rules")
        
        # Routing tables
        print(f"\n{Colors.CYAN}Custom Routing Tables:{Colors.END}")
        for table in range(100, 105):
            code, out, err = self.current_device.execute(f"ip route show table {table}")
            if code == 0 and out.strip():
                print(f"\n{Colors.YELLOW}Table {table}:{Colors.END}")
                print(out)
        
        # ICMP status
        print(f"\n{Colors.CYAN}ICMP Status:{Colors.END}")
        code, out, err = self.current_device.execute("cat /proc/sys/net/ipv4/icmp_echo_ignore_all")
        if code == 0:
            status = "DISABLED" if out.strip() == "1" else "ENABLED"
            print(f"ICMP Echo: {status}")
        
        # IP Forwarding
        print(f"\n{Colors.CYAN}IP Forwarding:{Colors.END}")
        code, out, err = self.current_device.execute("cat /proc/sys/net/ipv4/ip_forward")
        if code == 0:
            status = "ENABLED" if out.strip() == "1" else "DISABLED"
            print(f"Global: {status}")
        
        # Interface forwarding
        for iface in ['eth0', 'eth1']:
            code, out, err = self.current_device.execute(f"cat /proc/sys/net/ipv4/conf/{iface}/forwarding 2>/dev/null")
            if code == 0:
                status = "ENABLED" if out.strip() == "1" else "DISABLED"
                print(f"{iface}: {status}")
        
        # RP Filter
        print(f"\n{Colors.CYAN}Reverse Path Filter:{Colors.END}")
        code, out, err = self.current_device.execute("cat /proc/sys/net/ipv4/conf/all/rp_filter")
        if code == 0:
            status = "ENABLED" if out.strip() == "1" else "DISABLED"
            print(f"RP Filter: {status}")
        
        input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")
    
    def view_all_devices_status(self):
        """View status of all devices"""
        print(f"\n{Colors.BOLD}=== All Devices Status ==={Colors.END}\n")
        
        for name, device in self.devices.items():
            print(f"\n{Colors.CYAN}{'='*50}")
            print(f"Device: {name}")
            print(f"{'='*50}{Colors.END}")
            
            if not device.is_reachable:
                if not device.test_connection():
                    print(f"{Colors.RED}✗ Device not reachable{Colors.END}")
                    continue
            
            # Get basic info
            code, out, err = device.execute("ip addr show eth0 eth1 2>/dev/null | grep 'inet ' | awk '{print $2}'")
            if code == 0:
                print(f"{Colors.GREEN}IP Addresses:{Colors.END}")
                print(out)
            
            # Check for ACL rules
            code, out, err = device.execute("ip rule show | grep -v '^0:\\|^32766:\\|^32767:' | wc -l")
            if code == 0:
                rule_count = out.strip()
                print(f"{Colors.GREEN}Custom ACL Rules: {rule_count}{Colors.END}")
            
            # ICMP status
            code, out, err = device.execute("cat /proc/sys/net/ipv4/icmp_echo_ignore_all")
            if code == 0:
                status = "BLOCKED" if out.strip() == "1" else "ALLOWED"
                print(f"{Colors.GREEN}ICMP: {status}{Colors.END}")
        
        input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")
    
    def test_connectivity(self):
        """Test connectivity from VPC"""
        print(f"\n{Colors.BOLD}=== Connectivity Testing ==={Colors.END}\n")
        print(f"{Colors.YELLOW}Note: This tests from the current OVS device{Colors.END}")
        print(f"{Colors.YELLOW}For VPC testing, use GNS3 console directly{Colors.END}\n")
        
        if not self.current_device:
            print(f"{Colors.RED}✗ Please select a device first{Colors.END}")
            input(f"{Colors.CYAN}Press Enter to continue...{Colors.END}")
            return
        
        target = input("Enter target IP to ping: ")
        count = input("Number of pings (default 4): ") or "4"
        
        print(f"\n{Colors.CYAN}Testing from {self.current_device.name} to {target}...{Colors.END}\n")
        
        cmd = f"ping -c {count} -W 2 {target}"
        code, out, err = self.current_device.execute(cmd)
        
        print(out)
        
        if code == 0:
            print(f"\n{Colors.GREEN}✓ Connectivity test PASSED{Colors.END}")
        else:
            print(f"\n{Colors.RED}✗ Connectivity test FAILED{Colors.END}")
        
        input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")
    
    def show_templates_menu(self):
        """ACL templates menu"""
        if not self.current_device:
            print(f"\n{Colors.RED}✗ Please select a device first{Colors.END}")
            input(f"{Colors.CYAN}Press Enter to continue...{Colors.END}")
            return
        
        print(f"\n{Colors.BOLD}=== ACL Templates ==={Colors.END}")
        print(f"{Colors.YELLOW}Device: {self.current_device.name}{Colors.END}\n")
        
        print(f"{Colors.GREEN}[1]{Colors.END} Block VPC1 (10.0.1.2) from reaching VPC2 (10.0.5.2)")
        print(f"{Colors.GREEN}[2]{Colors.END} Block subnet 10.0.1.0/24 from 10.0.5.0/24")
        print(f"{Colors.GREEN}[3]{Colors.END} Disable all ICMP on this device")
        print(f"{Colors.GREEN}[4]{Colors.END} Enable full security (RP filter + Rate limit)")
        print(f"{Colors.GREEN}[0]{Colors.END} Back")
        
        choice = input(f"\n{Colors.CYAN}Choose template:{Colors.END} ")
        
        if choice == '1':
            self.template_block_vpc1_vpc2()
        elif choice == '2':
            self.template_block_subnet()
        elif choice == '3':
            self.template_disable_icmp()
        elif choice == '4':
            self.template_full_security()
    
    def template_block_vpc1_vpc2(self):
        """Template: Block VPC1 → VPC2"""
        print(f"\n{Colors.YELLOW}Applying: Block VPC1 → VPC2 on {self.current_device.name}{Colors.END}")
        
        commands = [
            ("ip route add blackhole 10.0.5.2/32 table 100 2>/dev/null || true", "Add blackhole route"),
            ("ip rule add from 10.0.1.2 table 100 priority 100 2>/dev/null || true", "Add routing rule")
        ]
        
        for cmd, desc in commands:
            code, out, err = self.current_device.execute(cmd)
            if code == 0:
                print(f"{Colors.GREEN}✓{Colors.END} {desc}")
            else:
                print(f"{Colors.YELLOW}⚠{Colors.END} {desc}")
        
        input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")
    
    def template_block_subnet(self):
        """Template: Block subnet"""
        print(f"\n{Colors.YELLOW}Applying: Block 10.0.1.0/24 → 10.0.5.0/24 on {self.current_device.name}{Colors.END}")
        
        commands = [
            ("ip route add blackhole 10.0.5.0/24 table 101 2>/dev/null || true", "Add blackhole route"),
            ("ip rule add from 10.0.1.0/24 table 101 priority 101 2>/dev/null || true", "Add routing rule")
        ]
        
        for cmd, desc in commands:
            code, out, err = self.current_device.execute(cmd)
            if code == 0:
                print(f"{Colors.GREEN}✓{Colors.END} {desc}")
            else:
                print(f"{Colors.YELLOW}⚠{Colors.END} {desc}")
        
        input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")
    
    def template_disable_icmp(self):
        """Template: Disable ICMP"""
        print(f"\n{Colors.YELLOW}Disabling ICMP on {self.current_device.name}{Colors.END}")
        
        cmd = "echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all"
        code, out, err = self.current_device.execute(cmd)
        
        if code == 0:
            print(f"{Colors.GREEN}✓ ICMP disabled{Colors.END}")
        else:
            print(f"{Colors.RED}✗ Error{Colors.END}")
        
        input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")
    
    def template_full_security(self):
        """Template: Full security"""
        print(f"\n{Colors.YELLOW}Applying full security on {self.current_device.name}{Colors.END}")
        
        commands = [
            ("echo 1 > /proc/sys/net/ipv4/conf/all/rp_filter", "Enable RP filter"),
            ("echo 10 > /proc/sys/net/ipv4/icmp_ratelimit", "Set ICMP rate limit"),
            ("echo 128 > /proc/sys/net/ipv4/tcp_max_syn_backlog", "Set TCP SYN backlog")
        ]
        
        for cmd, desc in commands:
            code, out, err = self.current_device.execute(cmd)
            if code == 0:
                print(f"{Colors.GREEN}✓{Colors.END} {desc}")
            else:
                print(f"{Colors.YELLOW}⚠{Colors.END} {desc}")
        
        input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")
    
    def batch_operations(self):
        """Batch operations on all devices"""
        print(f"\n{Colors.BOLD}=== Batch Operations ==={Colors.END}\n")
        
        print(f"{Colors.GREEN}[1]{Colors.END} Enable RP Filter on all devices")
        print(f"{Colors.GREEN}[2]{Colors.END} Disable ICMP on all devices")
        print(f"{Colors.GREEN}[3]{Colors.END} Enable ICMP on all devices")
        print(f"{Colors.GREEN}[4]{Colors.END} Show IP forwarding status on all")
        print(f"{Colors.GREEN}[5]{Colors.END} Custom command on all devices")
        print(f"{Colors.GREEN}[0]{Colors.END} Back")
        
        choice = input(f"\n{Colors.CYAN}Choose operation:{Colors.END} ")
        
        if choice == '1':
            self.batch_enable_rp_filter()
        elif choice == '2':
            self.batch_disable_icmp()
        elif choice == '3':
            self.batch_enable_icmp()
        elif choice == '4':
            self.batch_show_forwarding()
        elif choice == '5':
            self.batch_custom_command()
    
    def batch_enable_rp_filter(self):
        """Enable RP filter on all devices"""
        print(f"\n{Colors.CYAN}Enabling RP filter on all devices...{Colors.END}\n")
        
        cmd = "echo 1 > /proc/sys/net/ipv4/conf/all/rp_filter"
        
        for name, device in self.devices.items():
            if not device.is_reachable:
                device.test_connection()
            
            code, out, err = device.execute(cmd)
            if code == 0:
                print(f"{Colors.GREEN}✓{Colors.END} {name}: RP filter enabled")
            else:
                print(f"{Colors.RED}✗{Colors.END} {name}: Failed")
        
        input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")
    
    def batch_disable_icmp(self):
        """Disable ICMP on all devices"""
        print(f"\n{Colors.CYAN}Disabling ICMP on all devices...{Colors.END}\n")
        
        cmd = "echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all"
        
        for name, device in self.devices.items():
            if not device.is_reachable:
                device.test_connection()
            
            code, out, err = device.execute(cmd)
            if code == 0:
                print(f"{Colors.GREEN}✓{Colors.END} {name}: ICMP disabled")
            else:
                print(f"{Colors.RED}✗{Colors.END} {name}: Failed")
        
        input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")
    
    def batch_enable_icmp(self):
        """Enable ICMP on all devices"""
        print(f"\n{Colors.CYAN}Enabling ICMP on all devices...{Colors.END}\n")
        
        cmd = "echo 0 > /proc/sys/net/ipv4/icmp_echo_ignore_all"
        
        for name, device in self.devices.items():
            if not device.is_reachable:
                device.test_connection()
            
            code, out, err = device.execute(cmd)
            if code == 0:
                print(f"{Colors.GREEN}✓{Colors.END} {name}: ICMP enabled")
            else:
                print(f"{Colors.RED}✗{Colors.END} {name}: Failed")
        
        input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")
    
    def batch_show_forwarding(self):
        """Show forwarding status on all devices"""
        print(f"\n{Colors.CYAN}IP Forwarding Status:{Colors.END}\n")
        
        for name, device in self.devices.items():
            if not device.is_reachable:
                device.test_connection()
            
            print(f"{Colors.YELLOW}{name}:{Colors.END}")
            
            code, out, err = device.execute("cat /proc/sys/net/ipv4/ip_forward")
            if code == 0:
                status = "ENABLED" if out.strip() == "1" else "DISABLED"
                print(f"  Global: {status}")
            
            for iface in ['eth0', 'eth1']:
                code, out, err = device.execute(f"cat /proc/sys/net/ipv4/conf/{iface}/forwarding 2>/dev/null")
                if code == 0:
                    status = "ENABLED" if out.strip() == "1" else "DISABLED"
                    print(f"  {iface}: {status}")
            print()
        
        input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")
    
    def batch_custom_command(self):
        """Execute custom command on all devices"""
        print(f"\n{Colors.YELLOW}Warning: Be careful with custom commands!{Colors.END}")
        cmd = input("Enter command to execute on all devices: ")
        
        confirm = input(f"\n{Colors.RED}Execute '{cmd}' on all devices? (yes/no):{Colors.END} ")
        if confirm.lower() != 'yes':
            print("Cancelled")
            return
        
        print(f"\n{Colors.CYAN}Executing command...{Colors.END}\n")
        
        for name, device in self.devices.items():
            if not device.is_reachable:
                device.test_connection()
            
            print(f"{Colors.YELLOW}{name}:{Colors.END}")
            code, out, err = device.execute(cmd)
            if code == 0:
                print(f"{Colors.GREEN}Output:{Colors.END}")
                print(out if out else "(no output)")
            else:
                print(f"{Colors.RED}Error:{Colors.END}")
                print(err if err else "(unknown error)")
            print()
        
        input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")
    
    def cleanup_connections(self):
        """Close all SSH connections"""
        for device in self.devices.values():
            device.ssh.close()
    
    def run(self):
        """Main application loop"""
        config = self.load_config()
        
        if not config:
            print(f"{Colors.YELLOW}No configuration found. Starting setup...{Colors.END}")
            config = self.setup_devices()
        
        if not self.connect_devices(config):
            print(f"{Colors.RED}Failed to load device configuration{Colors.END}")
            return
        
        try:
            while True:
                os.system('clear' if os.name == 'posix' else 'cls')
                self.print_banner()
                
                choice = self.show_main_menu()
                
                if choice == '0':
                    print(f"\n{Colors.GREEN}Closing connections and exiting...{Colors.END}\n")
                    self.cleanup_connections()
                    sys.exit(0)
                elif choice == '1':
                    self.select_device()
                elif choice == '2':
                    self.add_acl_rule()
                elif choice == '3':
                    self.remove_acl_rule()
                elif choice == '4':
                    self.view_acl_rules()
                elif choice == '5':
                    self.view_all_devices_status()
                elif choice == '6':
                    self.test_connectivity()
                elif choice == '7':
                    self.show_templates_menu()
                elif choice == '8':
                    self.batch_operations()
                elif choice == '9':
                    config = self.setup_devices()
                    self.connect_devices(config)
                else:
                    print(f"{Colors.RED}Invalid choice{Colors.END}")
                    time.sleep(1)
        
        except KeyboardInterrupt:
            print(f"\n\n{Colors.YELLOW}Interrupted. Cleaning up...{Colors.END}\n")
            self.cleanup_connections()
            sys.exit(0)

def main():
    """Main entry point"""
    print(f"{Colors.CYAN}Checking requirements...{Colors.END}")
    
    try:
        import paramiko
    except ImportError:
        print(f"\n{Colors.RED}Error: paramiko library not found{Colors.END}")
        print(f"{Colors.YELLOW}Install it using:{Colors.END}")
        print(f"  sudo apt-get update")
        print(f"  sudo apt-get install python3-paramiko")
        print(f"  or")
        print(f"  pip3 install paramiko\n")
        sys.exit(1)
    
    manager = ACLManagerRemote()
    manager.run()

if __name__ == "__main__":
    main()