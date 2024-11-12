from fastapi import FastAPI, WebSocket, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from scapy.all import sniff, IP, IPv6, DNS, DNSQR, Ether, UDP, TCP
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import json
import asyncio
from collections import defaultdict, deque
import re
from dataclasses import dataclass
from ipaddress import ip_address, IPv4Address, IPv6Address
from openai import OpenAI
import os
import dotenv
import logging
from pathlib import Path
dotenv.load_dotenv()

OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')

# Data classes for better type hints and organization
@dataclass
class DNSQuery:
    timestamp: datetime
    domain: str
    source_ip: str
    query_type: str
    alerts: List[str]
    category: str
    risk_score: float
    analysis: str

class DNSMonitor:
    def __init__(self, max_history: int = 1000):
        self.client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))
        self.queries = defaultdict(int)
        self.categories = defaultdict(int)
        self.security_alerts = deque(maxlen=max_history)
        self.recent_queries = deque(maxlen=max_history)
        self.blocked_ips = set()
        self.query_rate_limit = defaultdict(lambda: deque(maxlen=100))
        self.domain_cache = {}  # Cache for domain analysis
        
        # Enhanced security patterns
        self.suspicious_patterns = {
            'length': r'[a-zA-Z0-9]{25,}',
            'hex': r'[0-9a-f]{32}',
            'malicious_tld': r'\.pw$|\.top$|\.xyz$|\.cc$',
            'dga_like': r'[0-9a-f]{8,}|[bcdfghjklmnpqrstvwxz]{10,}',
            'ip_encoded': r'\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}',
        }

        # Store the main event loop
        self.loop = asyncio.get_event_loop()

        # Initialize cache with proper path
        self.cache_dir = Path("cache")
        self.cache_dir.mkdir(exist_ok=True)
        self.cache_file = self.cache_dir / "domain_cache.json"
        self.domain_cache = self.load_cache()

    def load_cache(self) -> dict:
        """Load domain analysis cache from JSON file"""
        try:
            if Path(self.cache_file).exists():
                with open(self.cache_file, 'r') as f:
                    cache_data = json.load(f)
                    logging.info(f"Loaded {len(cache_data)} entries from cache")
                    return cache_data
            logging.info("No existing cache file found, creating new cache")
            return {}
        except Exception as e:
            logging.error(f"Error loading cache: {e}")
            return {}
            
    def save_cache(self):
        """Save domain analysis cache to JSON file"""
        try:
            with open(self.cache_file, 'w') as f:
                json.dump(self.domain_cache, f)
                logging.info(f"Saved {len(self.domain_cache)} entries to cache")
        except Exception as e:
            logging.error(f"Error saving cache: {e}")

    async def analyze_domain_with_llm(self, domain: str) -> tuple[str, float, str]:
        """Analyze domain using GPT-4 for categorization and risk assessment"""
        # Check cache first
        if domain in self.domain_cache:
            logging.info(f"Cache hit for domain: {domain}")
            cached = self.domain_cache[domain]
            return cached['category'], cached['risk_score'], cached['analysis']

        logging.info(f"Cache miss for domain: {domain}, performing LLM analysis")
        
        try:
            prompt =  f"""Analyze the domain name '{domain}' and provide:
           1. Category (e.g., Social Media, Gaming, Business, Malicious)
           2. Risk score (0-1, where 1 is highest risk)
           3. Brief analysis explaining the categorization and risk assessment
            
           Format: 
           Provide exactly in this format with no extra text:
           category|0.5|analysis
            
           Where:
           - category is a single word
           - risk_score is just a decimal between 0-1 (e.g. 0.1, 0.5, 0.9)
           - analysis is your explanation"""
            
            response = await asyncio.to_thread(
                lambda: self.client.chat.completions.create(
                    model="gpt-4o-mini",
                    messages=[
                        {"role": "system", "content": "You are a domain analysis expert."},
                        {"role": "user", "content": prompt}
                    ],
                    max_tokens=150,
                    temperature=0.3
                )
            )

            result = response.choices[0].message.content.strip().split('|')
            if len(result) == 3:
                category, risk_score, analysis = result
                risk_score = float(risk_score)
                
                # Cache the results
                self.domain_cache[domain] = {
                    'category': category,
                    'risk_score': risk_score,
                    'analysis': analysis
                }
                self.save_cache()
                logging.info(f"Cached analysis for domain: {domain}")
                
                return category, risk_score, analysis
            
        except Exception as e:
            logging.error(f"LLM analysis error for domain {domain}: {e}")
        
        return "Unknown", 0.0, "Analysis failed"

    def check_rate_limiting(self, ip: str) -> Optional[str]:
        current_time = datetime.now()
        self.query_rate_limit[ip].append(current_time)
        
        recent_queries = [t for t in self.query_rate_limit[ip] 
                         if current_time - t < timedelta(seconds=10)]
        if len(recent_queries) > 50:
            self.blocked_ips.add(ip)
            return f"Rate limit exceeded for IP: {ip}"
        return None

    def detect_suspicious_domain(self, domain: str) -> List[str]:
        alerts = []
        for name, pattern in self.suspicious_patterns.items():
            if re.search(pattern, domain, re.IGNORECASE):
                alerts.append(f"Suspicious pattern detected: {name}")
        return alerts

    def packet_callback(self, packet):
        """Synchronous callback for Scapy sniffing"""
        try:
            if not (DNSQR in packet and packet.haslayer(DNS)):
                return

            # Extract basic information synchronously
            domain = packet[DNSQR].qname.decode('utf-8').rstrip('.')
            source_ip = packet[IP].src if IP in packet else packet[IPv6].src if IPv6 in packet else "N/A"
            query_type = packet[DNSQR].qtype

            # Schedule the async processing in the main event loop
            asyncio.run_coroutine_threadsafe(
                self.process_packet_async(domain, source_ip, query_type),
                self.loop
            )

        except Exception as e:
            print(f"Error in packet callback: {e}")

    async def process_packet_async(self, domain: str, source_ip: str, query_type: str):
        """Async packet processor"""
        try:
            # Skip if IP is blocked
            if source_ip in self.blocked_ips:
                return

            # Rate limiting check
            rate_limit_alert = self.check_rate_limiting(source_ip)
            if rate_limit_alert:
                self.security_alerts.append(rate_limit_alert)
                return

            # Enhanced analysis with LLM
            category, risk_score, analysis = await self.analyze_domain_with_llm(domain)
            
            # Update statistics
            self.queries[domain] += 1
            self.categories[category] += 1
            
            # Security checks
            alerts = self.detect_suspicious_domain(domain)
            if risk_score > 0.7:
                alerts.append(f"High risk domain detected: {analysis}")
            
            # Create query object
            query = DNSQuery(
                timestamp=datetime.now(),
                domain=domain,
                source_ip=source_ip,
                query_type=query_type,
                alerts=alerts,
                category=category,
                risk_score=risk_score,
                analysis=analysis
            )
            
            # Update recent queries and alerts
            self.recent_queries.append(query)
            if alerts:
                self.security_alerts.extend(alerts)

        except Exception as e:
            print(f"Error processing packet: {e}")

    def get_stats(self):
        return {
            "queries": dict(self.queries),
            "categories": dict(self.categories),
            "security_alerts": list(self.security_alerts)[-10:],
            "recent_queries": [
                {
                    "timestamp": q.timestamp.strftime("%H:%M:%S"),
                    "domain": q.domain,
                    "source_ip": q.source_ip,
                    "query_type": q.query_type,
                    "alerts": q.alerts,
                    "category": q.category,
                    "risk_score": q.risk_score,
                    "analysis": q.analysis
                }
                for q in list(self.recent_queries)[-10:]
            ],
            "blocked_ips": list(self.blocked_ips)
        }

# Initialize FastAPI and DNS Monitor
app = FastAPI(title="DNS Monitor", version="1.0.0")
dns_monitor = DNSMonitor()

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            await websocket.send_json(dns_monitor.get_stats())
            await asyncio.sleep(1)
    except Exception as e:
        print(f"WebSocket error: {e}")

async def start_sniffer(dns_monitor: DNSMonitor):
    """Start the DNS sniffer in a separate thread"""
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(
        None,
        lambda: sniff(
            prn=dns_monitor.packet_callback,
            filter="udp port 53 or tcp port 53",
            store=False
        )
    )

# Additional API endpoints for management
@app.post("/block_ip/{ip}")
async def block_ip(ip: str):
    try:
        ip_address(ip)  # Validate IP address
        dns_monitor.blocked_ips.add(ip)
        return {"message": f"IP {ip} blocked successfully"}
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address")

@app.delete("/unblock_ip/{ip}")
async def unblock_ip(ip: str):
    try:
        # Validate IP address format
        ip_address(ip)
        
        if ip in dns_monitor.blocked_ips:
            dns_monitor.blocked_ips.remove(ip)
            # Also clear rate limiting history for this IP
            if ip in dns_monitor.query_rate_limit:
                dns_monitor.query_rate_limit[ip].clear()
            return {"message": f"IP {ip} unblocked successfully", "status": "success"}
        else:
            raise HTTPException(
                status_code=404, 
                detail=f"IP {ip} not found in blocked list"
            )
    except ValueError:
        raise HTTPException(
            status_code=400, 
            detail="Invalid IP address format"
        )

@app.on_event("startup")
async def startup_event():
    dns_monitor.loop = asyncio.get_event_loop()
    asyncio.create_task(start_sniffer(dns_monitor))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

