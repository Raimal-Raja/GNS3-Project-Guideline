"""
GNS3 ACL Manager - Python CLI Application
Manages Access Control Lists for GNS3 Open vSwitch topology
"""

import subprocess
import sys
import os
from typing import List, Dict, Optional

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

class ACLManager:
    """Main ACL Manager class"""
    
    def __init__(self):
        self.devices = {
            '1': {'name': 'OVS1', 'ip': '10.0.1.1'},
            '2': {'name': 'OVS2', 'ip': '10.0.2.2'},
            '3': {'name': 'OVS3', 'ip': '10.0.3.2'},
            '4': {'name': 'OVS4', 'ip': '10.0.4.2'}
        }
        
    def print_banner(self):
        """Print application banner"""
        banner = f"""
{Colors.CYAN}{'='*60}
   GNS3 ACL MANAGER - Access Control List Configuration
{'='*60}{Colors.END}
{Colors.YELLOW}Topology: VPC1 → OVS1 → OVS2 → OVS3 → OVS4 → VPC2{Colors.END}
"""
        print(banner)
    
    def run_command(self, command: str, shell: bool = True) -> tuple:
        """Execute shell command and return output"""
        try:
            result = subprocess.run(
                command,
                shell=shell,
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "Command timed out"
        except Exception as e:
            return -1, "", str(e)
    
    def show_main_menu(self):
        """Display main menu"""
        menu = f"""
{Colors.BOLD}Main Menu:{Colors.END}
{Colors.GREEN}[1]{Colors.END} Add ACL Rule
{Colors.GREEN}[2]{Colors.END} Remove ACL Rule
{Colors.GREEN}[3]{Colors.END} View ACL Rules
{Colors.GREEN}[4]{Colors.END} Test Connectivity
{Colors.GREEN}[5]{Colors.END} ACL Templates (Quick Setup)
{Colors.GREEN}[6]{Colors.END} Advanced ACL Options
{Colors.GREEN}[0]{Colors.END} Exit

{Colors.CYAN}Choose an option:{Colors.END} """
        return input(menu)
    
    def show_acl_types_menu(self):
        """Display ACL rule types menu"""
        menu = f"""
{Colors.BOLD}ACL Rule Types:{Colors.END}
{Colors.GREEN}[1]{Colors.END} Blackhole Route (Block specific IP/Network)
{Colors.GREEN}[2]{Colors.END} ICMP Control (Enable/Disable Ping)
{Colors.GREEN}[3]{Colors.END} Interface Forwarding Control
{Colors.GREEN}[4]{Colors.END} Reverse Path Filtering (Anti-spoofing)
{Colors.GREEN}[5]{Colors.END} Rate Limiting
{Colors.GREEN}[0]{Colors.END} Back to Main Menu

{Colors.CYAN}Choose ACL type:{Colors.END} """
        return input(menu)
    
    def add_blackhole_route(self):
        """Add blackhole route ACL"""
        print(f"\n{Colors.BOLD}=== Add Blackhole Route ==={Colors.END}")
        print(f"{Colors.YELLOW}This will drop all packets to specified destination{Colors.END}\n")
        
        source_ip = input("Enter source IP/Network (e.g., 10.0.1.2 or 10.0.1.0/24): ")
        dest_ip = input("Enter destination IP/Network to block (e.g., 10.0.5.2/32): ")
        table_num = input("Enter routing table number (100-252, default 100): ") or "100"
        priority = input("Enter rule priority (default 100): ") or "100"
        
        print(f"\n{Colors.CYAN}Executing commands...{Colors.END}")
        
        # Add blackhole route
        cmd1 = f"ip route add blackhole {dest_ip} table {table_num}"
        code1, out1, err1 = self.run_command(cmd1)
        
        # Add routing rule
        cmd2 = f"ip rule add from {source_ip} table {table_num} priority {priority}"
        code2, out2, err2 = self.run_command(cmd2)
        
        if code1 == 0 and code2 == 0:
            print(f"{Colors.GREEN}✓ Blackhole route added successfully!{Colors.END}")
            print(f"{Colors.BLUE}Source: {source_ip} → Destination: {dest_ip} (BLOCKED){Colors.END}")
        else:
            print(f"{Colors.RED}✗ Error adding rule:{Colors.END}")
            if err1: print(f"  Route: {err1}")
            if err2: print(f"  Rule: {err2}")
        
        input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")
    
    def remove_blackhole_route(self):
        """Remove blackhole route ACL"""
        print(f"\n{Colors.BOLD}=== Remove Blackhole Route ==={Colors.END}\n")
        
        source_ip = input("Enter source IP/Network to remove: ")
        dest_ip = input("Enter destination IP/Network: ")
        table_num = input("Enter routing table number (default 100): ") or "100"
        
        print(f"\n{Colors.CYAN}Executing commands...{Colors.END}")
        
        # Remove routing rule
        cmd1 = f"ip rule del from {source_ip} table {table_num}"
        code1, out1, err1 = self.run_command(cmd1)
        
        # Remove blackhole route
        cmd2 = f"ip route del blackhole {dest_ip} table {table_num}"
        code2, out2, err2 = self.run_command(cmd2)
        
        if code1 == 0 and code2 == 0:
            print(f"{Colors.GREEN}✓ Blackhole route removed successfully!{Colors.END}")
        else:
            print(f"{Colors.YELLOW}⚠ Partial removal or rule not found{Colors.END}")
        
        input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")
    
    def control_icmp(self):
        """Enable/Disable ICMP (ping) responses"""
        print(f"\n{Colors.BOLD}=== ICMP Control ==={Colors.END}\n")
        
        action = input("Enable or Disable ICMP? (e/d): ").lower()
        
        if action == 'd':
            cmd = "echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all"
            msg = "disabled"
        else:
            cmd = "echo 0 > /proc/sys/net/ipv4/icmp_echo_ignore_all"
            msg = "enabled"
        
        code, out, err = self.run_command(cmd)
        
        if code == 0:
            print(f"{Colors.GREEN}✓ ICMP (ping) {msg} successfully!{Colors.END}")
        else:
            print(f"{Colors.RED}✗ Error: {err}{Colors.END}")
        
        # Verify
        code, out, err = self.run_command("cat /proc/sys/net/ipv4/icmp_echo_ignore_all")
        if code == 0:
            status = "DISABLED" if out.strip() == "1" else "ENABLED"
            print(f"{Colors.BLUE}Current status: ICMP is {status}{Colors.END}")
        
        input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")
    
    def control_interface_forwarding(self):
        """Control IP forwarding on specific interface"""
        print(f"\n{Colors.BOLD}=== Interface Forwarding Control ==={Colors.END}\n")
        
        interface = input("Enter interface name (e.g., eth0, eth1): ")
        action = input("Enable or Disable forwarding? (e/d): ").lower()
        
        value = "1" if action == 'e' else "0"
        cmd = f"echo {value} > /proc/sys/net/ipv4/conf/{interface}/forwarding"
        
        code, out, err = self.run_command(cmd)
        
        if code == 0:
            status = "enabled" if value == "1" else "disabled"
            print(f"{Colors.GREEN}✓ IP forwarding {status} on {interface}!{Colors.END}")
        else:
            print(f"{Colors.RED}✗ Error: {err}{Colors.END}")
        
        input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")
    
    def control_rp_filter(self):
        """Control Reverse Path Filtering (anti-spoofing)"""
        print(f"\n{Colors.BOLD}=== Reverse Path Filtering ==={Colors.END}\n")
        print(f"{Colors.YELLOW}This enables anti-spoofing protection{Colors.END}\n")
        
        action = input("Enable or Disable RP filter? (e/d): ").lower()
        
        value = "1" if action == 'e' else "0"
        cmd1 = f"echo {value} > /proc/sys/net/ipv4/conf/all/rp_filter"
        cmd2 = f"sysctl -w net.ipv4.conf.all.rp_filter={value}"
        
        code1, out1, err1 = self.run_command(cmd1)
        code2, out2, err2 = self.run_command(cmd2)
        
        if code1 == 0:
            status = "enabled" if value == "1" else "disabled"
            print(f"{Colors.GREEN}✓ Reverse path filtering {status}!{Colors.END}")
        else:
            print(f"{Colors.RED}✗ Error: {err1}{Colors.END}")
        
        input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")
    
    def set_rate_limiting(self):
        """Configure rate limiting parameters"""
        print(f"\n{Colors.BOLD}=== Rate Limiting Configuration ==={Colors.END}\n")
        
        print("1. ICMP Rate Limit")
        print("2. TCP SYN Backlog")
        choice = input("\nChoose option: ")
        
        if choice == '1':
            rate = input("Enter ICMP rate limit (packets/sec, default 10): ") or "10"
            cmd = f"echo {rate} > /proc/sys/net/ipv4/icmp_ratelimit"
            param = "ICMP rate limit"
        elif choice == '2':
            backlog = input("Enter TCP SYN backlog size (default 128): ") or "128"
            cmd = f"echo {backlog} > /proc/sys/net/ipv4/tcp_max_syn_backlog"
            param = "TCP SYN backlog"
        else:
            print(f"{Colors.RED}Invalid choice{Colors.END}")
            return
        
        code, out, err = self.run_command(cmd)
        
        if code == 0:
            print(f"{Colors.GREEN}✓ {param} configured successfully!{Colors.END}")
        else:
            print(f"{Colors.RED}✗ Error: {err}{Colors.END}")
        
        input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")
    
    def view_acl_rules(self):
        """Display current ACL rules"""
        print(f"\n{Colors.BOLD}=== Current ACL Configuration ==={Colors.END}\n")
        
        # Show routing rules
        print(f"{Colors.CYAN}IP Routing Rules:{Colors.END}")
        code, out, err = self.run_command("ip rule show")
        if code == 0:
            print(out if out else "No custom rules found")
        
        # Show routing tables
        print(f"\n{Colors.CYAN}Custom Routing Tables (100-252):{Colors.END}")
        for table in range(100, 105):
            code, out, err = self.run_command(f"ip route show table {table}")
            if code == 0 and out.strip():
                print(f"\n{Colors.YELLOW}Table {table}:{Colors.END}")
                print(out)
        
        # Show ICMP status
        print(f"\n{Colors.CYAN}ICMP Status:{Colors.END}")
        code, out, err = self.run_command("cat /proc/sys/net/ipv4/icmp_echo_ignore_all")
        if code == 0:
            status = "DISABLED (blocked)" if out.strip() == "1" else "ENABLED"
            print(f"ICMP Echo: {status}")
        
        # Show IP forwarding status
        print(f"\n{Colors.CYAN}IP Forwarding Status:{Colors.END}")
        code, out, err = self.run_command("cat /proc/sys/net/ipv4/ip_forward")
        if code == 0:
            status = "ENABLED" if out.strip() == "1" else "DISABLED"
            print(f"Global IP Forwarding: {status}")
        
        # Show RP filter
        code, out, err = self.run_command("cat /proc/sys/net/ipv4/conf/all/rp_filter")
        if code == 0:
            status = "ENABLED" if out.strip() == "1" else "DISABLED"
            print(f"Reverse Path Filter: {status}")
        
        input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")
    
    def test_connectivity(self):
        """Test network connectivity"""
        print(f"\n{Colors.BOLD}=== Connectivity Testing ==={Colors.END}\n")
        
        target = input("Enter target IP to ping (e.g., 10.0.5.2): ")
        count = input("Number of pings (default 4): ") or "4"
        
        print(f"\n{Colors.CYAN}Testing connectivity to {target}...{Colors.END}\n")
        
        cmd = f"ping -c {count} {target}"
        code, out, err = self.run_command(cmd)
        
        print(out)
        
        if code == 0:
            print(f"\n{Colors.GREEN}✓ Connectivity test PASSED{Colors.END}")
        else:
            print(f"\n{Colors.RED}✗ Connectivity test FAILED{Colors.END}")
        
        input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")
    
    def show_templates_menu(self):
        """Show ACL template options"""
        print(f"\n{Colors.BOLD}=== ACL Templates (Quick Setup) ==={Colors.END}\n")
        print(f"{Colors.GREEN}[1]{Colors.END} Block VPC1 from reaching VPC2")
        print(f"{Colors.GREEN}[2]{Colors.END} Block subnet 10.0.1.0/24 from 10.0.5.0/24")
        print(f"{Colors.GREEN}[3]{Colors.END} Disable all ICMP on this device")
        print(f"{Colors.GREEN}[4]{Colors.END} Enable full security (RP filter + ICMP limit)")
        print(f"{Colors.GREEN}[0]{Colors.END} Back to Main Menu")
        
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
        """Template: Block VPC1 from reaching VPC2"""
        print(f"\n{Colors.YELLOW}Applying: Block VPC1 (10.0.1.2) → VPC2 (10.0.5.2){Colors.END}")
        
        commands = [
            "ip route add blackhole 10.0.5.2/32 table 100",
            "ip rule add from 10.0.1.2 table 100 priority 100"
        ]
        
        for cmd in commands:
            code, out, err = self.run_command(cmd)
            if code == 0:
                print(f"{Colors.GREEN}✓{Colors.END} {cmd}")
            else:
                print(f"{Colors.RED}✗{Colors.END} {cmd}: {err}")
        
        input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")
    
    def template_block_subnet(self):
        """Template: Block subnet access"""
        print(f"\n{Colors.YELLOW}Applying: Block 10.0.1.0/24 → 10.0.5.0/24{Colors.END}")
        
        commands = [
            "ip route add blackhole 10.0.5.0/24 table 101",
            "ip rule add from 10.0.1.0/24 table 101 priority 101"
        ]
        
        for cmd in commands:
            code, out, err = self.run_command(cmd)
            if code == 0:
                print(f"{Colors.GREEN}✓{Colors.END} {cmd}")
            else:
                print(f"{Colors.RED}✗{Colors.END} {cmd}: {err}")
        
        input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")
    
    def template_disable_icmp(self):
        """Template: Disable ICMP"""
        print(f"\n{Colors.YELLOW}Applying: Disable all ICMP responses{Colors.END}")
        
        cmd = "echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all"
        code, out, err = self.run_command(cmd)
        
        if code == 0:
            print(f"{Colors.GREEN}✓ ICMP disabled successfully{Colors.END}")
        else:
            print(f"{Colors.RED}✗ Error: {err}{Colors.END}")
        
        input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")
    
    def template_full_security(self):
        """Template: Enable full security"""
        print(f"\n{Colors.YELLOW}Applying: Full security configuration{Colors.END}")
        
        commands = [
            ("echo 1 > /proc/sys/net/ipv4/conf/all/rp_filter", "Enable RP filter"),
            ("echo 10 > /proc/sys/net/ipv4/icmp_ratelimit", "Set ICMP rate limit"),
            ("echo 128 > /proc/sys/net/ipv4/tcp_max_syn_backlog", "Set TCP SYN backlog")
        ]
        
        for cmd, desc in commands:
            code, out, err = self.run_command(cmd)
            if code == 0:
                print(f"{Colors.GREEN}✓{Colors.END} {desc}")
            else:
                print(f"{Colors.RED}✗{Colors.END} {desc}: {err}")
        
        input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")
    
    def run(self):
        """Main application loop"""
        # Check if running as root
        if os.geteuid() != 0:
            print(f"{Colors.RED}Error: This script must be run as root (sudo){Colors.END}")
            sys.exit(1)
        
        while True:
            os.system('clear' if os.name == 'posix' else 'cls')
            self.print_banner()
            
            choice = self.show_main_menu()
            
            if choice == '0':
                print(f"\n{Colors.GREEN}Exiting ACL Manager. Goodbye!{Colors.END}\n")
                sys.exit(0)
            elif choice == '1':
                acl_type = self.show_acl_types_menu()
                if acl_type == '1':
                    self.add_blackhole_route()
                elif acl_type == '2':
                    self.control_icmp()
                elif acl_type == '3':
                    self.control_interface_forwarding()
                elif acl_type == '4':
                    self.control_rp_filter()
                elif acl_type == '5':
                    self.set_rate_limiting()
            elif choice == '2':
                self.remove_blackhole_route()
            elif choice == '3':
                self.view_acl_rules()
            elif choice == '4':
                self.test_connectivity()
            elif choice == '5':
                self.show_templates_menu()
            elif choice == '6':
                print(f"\n{Colors.YELLOW}Advanced options coming soon...{Colors.END}")
                input(f"{Colors.CYAN}Press Enter to continue...{Colors.END}")
            else:
                print(f"{Colors.RED}Invalid choice. Please try again.{Colors.END}")
                input(f"{Colors.CYAN}Press Enter to continue...{Colors.END}")

if __name__ == "__main__":
    try:
        manager = ACLManager()
        manager.run()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}Interrupted by user. Exiting...{Colors.END}\n")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}Error: {str(e)}{Colors.END}\n")
        sys.exit(1)