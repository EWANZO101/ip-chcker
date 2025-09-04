from flask import Flask, render_template, request, jsonify, Response, send_file
from flask_socketio import SocketIO, emit
import requests
import os
import json
import sqlite3
import threading
import time
import socket
import struct
import psutil
import subprocess
import platform
import ipaddress
import dns.resolver
import geoip2.database
import geoip2.errors
from datetime import datetime, timedelta
from contextlib import contextmanager
from collections import defaultdict, deque
import statistics
import hashlib
import base64
import asyncio
import aiohttp
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import pandas as pd
import plotly.graph_objs as go
import plotly.utils
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import zipfile
import io
import csv
import re
import whois
from apscheduler.schedulers.background import BackgroundScheduler
import warnings
warnings.filterwarnings("ignore")

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Configuration
DATABASE_PATH = 'network_monitor.db'
GEOIP_DB_PATH = 'GeoLite2-City.mmdb'  # Download from MaxMind
PACKET_CAPTURE_ENABLED = True
DEEP_PACKET_INSPECTION_ENABLED = True
MACHINE_LEARNING_ENABLED = True
MAX_PACKET_BUFFER = 10000
ANOMALY_THRESHOLD = 0.1

# Global data structures for real-time monitoring
active_connections = {}
traffic_stats = defaultdict(lambda: defaultdict(int))
packet_buffer = deque(maxlen=MAX_PACKET_BUFFER)
bandwidth_monitor = defaultdict(lambda: deque(maxlen=1000))  # 1000 data points
connection_duration = {}
geo_cache = {}
threat_indicators = set()
ml_model = None
scaler = StandardScaler()

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('network_monitor.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class NetworkMonitor:
    def __init__(self):
        self.is_monitoring = False
        self.packet_count = 0
        self.start_time = time.time()
        self.scheduler = BackgroundScheduler()
        
    def start_monitoring(self):
        """Start comprehensive network monitoring"""
        if self.is_monitoring:
            return
            
        self.is_monitoring = True
        logger.info("Starting comprehensive network monitoring...")
        
        # Start packet capture in separate thread
        if PACKET_CAPTURE_ENABLED:
            threading.Thread(target=self.packet_capture_worker, daemon=True).start()
            
        # Start connection monitoring
        threading.Thread(target=self.connection_monitor_worker, daemon=True).start()
        
        # Start traffic analysis
        threading.Thread(target=self.traffic_analysis_worker, daemon=True).start()
        
        # Start threat detection
        threading.Thread(target=self.threat_detection_worker, daemon=True).start()
        
        # Start scheduled tasks
        self.scheduler.start()
        self.scheduler.add_job(
            func=self.analyze_patterns,
            trigger="interval",
            minutes=5,
            id='pattern_analysis'
        )
        
    def stop_monitoring(self):
        """Stop all monitoring processes"""
        self.is_monitoring = False
        if self.scheduler.running:
            self.scheduler.shutdown()
        logger.info("Network monitoring stopped")
        
    def packet_capture_worker(self):
        """Capture and analyze network packets"""
        def packet_handler(packet):
            if not self.is_monitoring:
                return
                
            self.packet_count += 1
            timestamp = time.time()
            
            try:
                if IP in packet:
                    ip_layer = packet[IP]
                    packet_data = {
                        'timestamp': timestamp,
                        'src_ip': ip_layer.src,
                        'dst_ip': ip_layer.dst,
                        'protocol': ip_layer.proto,
                        'length': len(packet),
                        'ttl': ip_layer.ttl
                    }
                    
                    # Transport layer analysis
                    if TCP in packet:
                        tcp_layer = packet[TCP]
                        packet_data.update({
                            'transport': 'TCP',
                            'src_port': tcp_layer.sport,
                            'dst_port': tcp_layer.dport,
                            'flags': tcp_layer.flags,
                            'seq': tcp_layer.seq,
                            'ack': tcp_layer.ack
                        })
                        
                        # Application layer detection
                        packet_data['application'] = self.detect_application_protocol(tcp_layer.dport)
                        
                    elif UDP in packet:
                        udp_layer = packet[UDP]
                        packet_data.update({
                            'transport': 'UDP',
                            'src_port': udp_layer.sport,
                            'dst_port': udp_layer.dport
                        })
                        
                        packet_data['application'] = self.detect_application_protocol(udp_layer.dport)
                        
                    # Deep packet inspection
                    if DEEP_PACKET_INSPECTION_ENABLED and Raw in packet:
                        packet_data['payload_analysis'] = self.analyze_payload(packet[Raw].load)
                    
                    # Geographic analysis
                    packet_data['src_geo'] = self.get_geolocation(ip_layer.src)
                    packet_data['dst_geo'] = self.get_geolocation(ip_layer.dst)
                    
                    # Add to buffer and process
                    packet_buffer.append(packet_data)
                    self.process_packet_realtime(packet_data)
                    
            except Exception as e:
                logger.error(f"Error processing packet: {e}")
        
        try:
            # Start packet capture (requires root/admin privileges)
            sniff(prn=packet_handler, store=0, filter="ip")
        except PermissionError:
            logger.warning("Packet capture requires root privileges. Using alternative monitoring...")
            self.alternative_monitoring()
        except Exception as e:
            logger.error(f"Packet capture error: {e}")
            
    def alternative_monitoring(self):
        """Alternative monitoring without packet capture"""
        while self.is_monitoring:
            try:
                # Monitor network connections using psutil
                connections = psutil.net_connections(kind='inet')
                for conn in connections:
                    if conn.status == 'ESTABLISHED':
                        connection_data = {
                            'local_ip': conn.laddr.ip if conn.laddr else 'unknown',
                            'local_port': conn.laddr.port if conn.laddr else 0,
                            'remote_ip': conn.raddr.ip if conn.raddr else 'unknown',
                            'remote_port': conn.raddr.port if conn.raddr else 0,
                            'pid': conn.pid,
                            'type': conn.type.name,
                            'family': conn.family.name,
                            'status': conn.status
                        }
                        self.process_connection(connection_data)
                
                time.sleep(1)  # Check every second
            except Exception as e:
                logger.error(f"Alternative monitoring error: {e}")
                time.sleep(5)
    
    def process_packet_realtime(self, packet_data):
        """Process packet in real-time for immediate analysis"""
        src_ip = packet_data['src_ip']
        dst_ip = packet_data['dst_ip']
        
        # Update traffic statistics
        traffic_stats[src_ip]['bytes_sent'] += packet_data['length']
        traffic_stats[dst_ip]['bytes_received'] += packet_data['length']
        traffic_stats[src_ip]['packets_sent'] += 1
        traffic_stats[dst_ip]['packets_received'] += 1
        
        # Update bandwidth monitoring
        current_time = time.time()
        bandwidth_monitor[src_ip].append((current_time, packet_data['length']))
        
        # Check for suspicious activity
        if self.is_suspicious_activity(packet_data):
            self.handle_threat_detection(packet_data)
        
        # Emit real-time data to frontend
        socketio.emit('packet_data', {
            'timestamp': packet_data['timestamp'],
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'protocol': packet_data.get('transport', 'Unknown'),
            'size': packet_data['length'],
            'src_country': packet_data.get('src_geo', {}).get('country', 'Unknown'),
            'dst_country': packet_data.get('dst_geo', {}).get('country', 'Unknown')
        })
    
   def detect_application_protocol(self, port):
    """Detect application protocol based on port number"""
    common_ports = {
        20: 'FTP-Data',
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        67: 'DHCP-Server',
        68: 'DHCP-Client',
        69: 'TFTP',
        80: 'HTTP',
        110: 'POP3',
        111: 'RPCBind',
        123: 'NTP',
        135: 'MS RPC',
        137: 'NetBIOS-NS',
        138: 'NetBIOS-DGM',
        139: 'NetBIOS-SSN',
        143: 'IMAP',
        161: 'SNMP',
        162: 'SNMP-Trap',
        194: 'IRC',
        389: 'LDAP',
        443: 'HTTPS',
        445: 'Microsoft-DS',
        465: 'SMTPS',
        500: 'ISAKMP',
        514: 'Syslog',
        546: 'DHCPv6-Client',
        547: 'DHCPv6-Server',
        587: 'SMTP-Submission',
        631: 'IPP',
        636: 'LDAPS',
        993: 'IMAPS',
        995: 'POP3S',
        1080: 'SOCKS',
        1194: 'OpenVPN',
        1433: 'MSSQL',
        1521: 'Oracle DB',
        1723: 'PPTP',
        2049: 'NFS',
        2082: 'cPanel',
        2083: 'cPanel SSL',
        2086: 'WHM',
        2087: 'WHM SSL',
        2095: 'Webmail',
        2096: 'Webmail SSL',
        2181: 'Zookeeper',
        2375: 'Docker',
        2376: 'Docker TLS',
        27017: 'MongoDB',
        28017: 'MongoDB Web',
        3306: 'MySQL',
        3389: 'RDP',
        4444: 'Metasploit',
        5432: 'PostgreSQL',
        5631: 'PCAnywhere',
        5900: 'VNC',
        6379: 'Redis',
        8000: 'HTTP-Alt',
        8080: 'HTTP-Alt',
        8443: 'HTTPS-Alt',
        8888: 'Web Proxy',
        9000: 'SonarQube',
        9090: 'Web Admin',
        10000: 'Webmin',
    }
    return common_ports.get(port, f'Unknown-{port}')

    
    def analyze_payload(self, payload):
        """Analyze packet payload for security threats"""
        try:
            payload_str = payload.decode('utf-8', errors='ignore')
            
            analysis = {
                'size': len(payload),
                'entropy': self.calculate_entropy(payload),
                'contains_strings': bool(re.search(r'[a-zA-Z]{4,}', payload_str)),
                'suspicious_patterns': []
            }
            
            # Check for suspicious patterns
            suspicious_patterns = [
                (r'(SELECT|INSERT|UPDATE|DELETE).*(FROM|INTO)', 'SQL Injection'),
                (r'<script.*?>', 'XSS Attack'),
                (r'(cmd|exec|system|eval)\s*\(', 'Code Injection'),
                (r'(password|passwd|pwd)[\s:=]', 'Password Exposure'),
                (r'\b\d{4}[-\s]\d{4}[-\s]\d{4}[-\s]\d{4}\b', 'Credit Card'),
                (r'BEGIN RSA PRIVATE KEY', 'Private Key')
            ]
            
            for pattern, threat_type in suspicious_patterns:
                if re.search(pattern, payload_str, re.IGNORECASE):
                    analysis['suspicious_patterns'].append(threat_type)
            
            return analysis
            
        except Exception as e:
            return {'error': str(e), 'size': len(payload)}
    
    def calculate_entropy(self, data):
        """Calculate Shannon entropy of data"""
        if not data:
            return 0
        
        entropy = 0
        for i in range(256):
            p = float(data.count(bytes([i]))) / len(data)
            if p > 0:
                entropy += - p * np.log2(p)
        return entropy
    
    def get_geolocation(self, ip):
        """Get geographic location of IP address"""
        if ip in geo_cache:
            return geo_cache[ip]
        
        if not self.is_public_ip(ip):
            geo_data = {'country': 'Private', 'city': 'Private', 'latitude': 0, 'longitude': 0}
        else:
            try:
                if os.path.exists(GEOIP_DB_PATH):
                    with geoip2.database.Reader(GEOIP_DB_PATH) as reader:
                        response = reader.city(ip)
                        geo_data = {
                            'country': response.country.name or 'Unknown',
                            'city': response.city.name or 'Unknown',
                            'latitude': float(response.location.latitude or 0),
                            'longitude': float(response.location.longitude or 0)
                        }
                else:
                    geo_data = {'country': 'Unknown', 'city': 'Unknown', 'latitude': 0, 'longitude': 0}
            except Exception as e:
                logger.debug(f"Geolocation error for {ip}: {e}")
                geo_data = {'country': 'Unknown', 'city': 'Unknown', 'latitude': 0, 'longitude': 0}
        
        geo_cache[ip] = geo_data
        return geo_data
    
    def is_public_ip(self, ip):
        """Check if IP address is public"""
        try:
            return ipaddress.ip_address(ip).is_global
        except:
            return False
    
    def connection_monitor_worker(self):
        """Monitor active network connections"""
        while self.is_monitoring:
            try:
                current_connections = {}
                connections = psutil.net_connections(kind='inet')
                
                for conn in connections:
                    if conn.status == 'ESTABLISHED' and conn.raddr:
                        key = f"{conn.laddr.ip}:{conn.laddr.port}-{conn.raddr.ip}:{conn.raddr.port}"
                        current_connections[key] = {
                            'local_ip': conn.laddr.ip,
                            'local_port': conn.laddr.port,
                            'remote_ip': conn.raddr.ip,
                            'remote_port': conn.raddr.port,
                            'pid': conn.pid,
                            'status': conn.status,
                            'timestamp': time.time()
                        }
                
                # Detect new connections
                for key, conn_data in current_connections.items():
                    if key not in active_connections:
                        self.handle_new_connection(conn_data)
                
                # Detect closed connections
                for key in list(active_connections.keys()):
                    if key not in current_connections:
                        self.handle_closed_connection(key)
                
                active_connections.update(current_connections)
                time.sleep(2)  # Check every 2 seconds
                
            except Exception as e:
                logger.error(f"Connection monitoring error: {e}")
                time.sleep(5)
    
    def handle_new_connection(self, conn_data):
        """Handle new connection detection"""
        remote_ip = conn_data['remote_ip']
        
        # Get additional information
        conn_data['geo'] = self.get_geolocation(remote_ip)
        conn_data['abuse_check'] = self.quick_abuse_check(remote_ip)
        conn_data['whois'] = self.get_whois_info(remote_ip)
        
        # Store in database
        self.save_connection_to_db(conn_data)
        
        # Emit to frontend
        socketio.emit('new_connection', conn_data)
        
        logger.info(f"New connection: {remote_ip}:{conn_data['remote_port']} from {conn_data['geo']['country']}")
    
    def handle_closed_connection(self, connection_key):
        """Handle connection closure"""
        if connection_key in active_connections:
            conn_data = active_connections[connection_key]
            duration = time.time() - conn_data['timestamp']
            
            # Update database with duration
            self.update_connection_duration(connection_key, duration)
            
            # Clean up
            del active_connections[connection_key]
            
            socketio.emit('connection_closed', {
                'key': connection_key,
                'duration': duration
            })
    
    def is_suspicious_activity(self, packet_data):
        """Detect suspicious network activity"""
        src_ip = packet_data['src_ip']
        
        # Port scanning detection
        if self.detect_port_scan(src_ip):
            return True
        
        # High frequency connection attempts
        if self.detect_high_frequency_connections(src_ip):
            return True
        
        # Suspicious payload patterns
        if packet_data.get('payload_analysis', {}).get('suspicious_patterns'):
            return True
        
        # Unusual traffic patterns (if ML is enabled)
        if MACHINE_LEARNING_ENABLED and self.detect_anomaly(packet_data):
            return True
        
        return False
    
    def detect_port_scan(self, src_ip, window_minutes=5, threshold=20):
        """Detect potential port scanning activity"""
        current_time = time.time()
        window_start = current_time - (window_minutes * 60)
        
        # Count unique destination ports from this IP in the time window
        unique_ports = set()
        for packet in packet_buffer:
            if (packet['src_ip'] == src_ip and 
                packet['timestamp'] >= window_start and
                'dst_port' in packet):
                unique_ports.add(packet['dst_port'])
        
        return len(unique_ports) > threshold
    
    def detect_high_frequency_connections(self, src_ip, window_seconds=60, threshold=50):
        """Detect high frequency connection attempts"""
        current_time = time.time()
        window_start = current_time - window_seconds
        
        connection_count = sum(1 for packet in packet_buffer 
                             if packet['src_ip'] == src_ip and 
                             packet['timestamp'] >= window_start)
        
        return connection_count > threshold
    
    def detect_anomaly(self, packet_data):
        """Use machine learning to detect network anomalies"""
        if not ml_model:
            return False
        
        try:
            # Feature extraction for ML model
            features = [
                packet_data['length'],
                packet_data.get('src_port', 0),
                packet_data.get('dst_port', 0),
                packet_data['protocol'],
                packet_data.get('ttl', 64)
            ]
            
            # Normalize features
            features_scaled = scaler.transform([features])
            
            # Predict anomaly
            anomaly_score = ml_model.decision_function(features_scaled)[0]
            
            return anomaly_score < -ANOMALY_THRESHOLD
            
        except Exception as e:
            logger.debug(f"ML anomaly detection error: {e}")
            return False
    
    def handle_threat_detection(self, packet_data):
        """Handle detected threats"""
        threat_data = {
            'timestamp': packet_data['timestamp'],
            'threat_type': 'Network Anomaly',
            'src_ip': packet_data['src_ip'],
            'dst_ip': packet_data['dst_ip'],
            'severity': 'HIGH',
            'details': packet_data
        }
        
        # Save threat to database
        self.save_threat_to_db(threat_data)
        
        # Send alert
        self.send_threat_alert(threat_data)
        
        # Emit to frontend
        socketio.emit('threat_detected', threat_data)
        
        logger.warning(f"Threat detected from {packet_data['src_ip']}")
    
    def traffic_analysis_worker(self):
        """Analyze traffic patterns and generate insights"""
        while self.is_monitoring:
            try:
                current_time = time.time()
                
                # Analyze bandwidth usage
                bandwidth_data = self.calculate_bandwidth_stats()
                
                # Analyze protocol distribution
                protocol_stats = self.analyze_protocol_distribution()
                
                # Analyze geographic distribution
                geo_stats = self.analyze_geographic_distribution()
                
                # Generate traffic report
                traffic_report = {
                    'timestamp': current_time,
                    'bandwidth': bandwidth_data,
                    'protocols': protocol_stats,
                    'geography': geo_stats,
                    'active_connections': len(active_connections),
                    'total_packets': self.packet_count
                }
                
                # Emit to frontend
                socketio.emit('traffic_analysis', traffic_report)
                
                # Sleep for analysis interval
                time.sleep(30)  # Analyze every 30 seconds
                
            except Exception as e:
                logger.error(f"Traffic analysis error: {e}")
                time.sleep(30)
    
    def calculate_bandwidth_stats(self):
        """Calculate bandwidth statistics"""
        stats = {}
        current_time = time.time()
        window = 300  # 5 minutes
        
        for ip, measurements in bandwidth_monitor.items():
            if not measurements:
                continue
                
            # Filter measurements within time window
            recent_measurements = [(ts, size) for ts, size in measurements 
                                 if current_time - ts <= window]
            
            if recent_measurements:
                total_bytes = sum(size for _, size in recent_measurements)
                time_span = max(ts for ts, _ in recent_measurements) - min(ts for ts, _ in recent_measurements)
                
                if time_span > 0:
                    bps = total_bytes / time_span
                    stats[ip] = {
                        'bytes_per_second': bps,
                        'total_bytes': total_bytes,
                        'packet_count': len(recent_measurements)
                    }
        
        return stats
    
    def analyze_protocol_distribution(self):
        """Analyze distribution of network protocols"""
        protocol_counts = defaultdict(int)
        
        for packet in packet_buffer:
            protocol = packet.get('transport', 'Unknown')
            protocol_counts[protocol] += 1
        
        return dict(protocol_counts)
    
    def analyze_geographic_distribution(self):
        """Analyze geographic distribution of traffic"""
        country_counts = defaultdict(int)
        
        for packet in packet_buffer:
            src_country = packet.get('src_geo', {}).get('country', 'Unknown')
            dst_country = packet.get('dst_geo', {}).get('country', 'Unknown')
            
            country_counts[src_country] += 1
            country_counts[dst_country] += 1
        
        return dict(country_counts)
    
    def threat_detection_worker(self):
        """Advanced threat detection worker"""
        while self.is_monitoring:
            try:
                # DDoS detection
                self.detect_ddos_attacks()
                
                # Brute force detection
                self.detect_brute_force_attacks()
                
                # Data exfiltration detection
                self.detect_data_exfiltration()
                
                # Botnet communication detection
                self.detect_botnet_communication()
                
                time.sleep(60)  # Check every minute
                
            except Exception as e:
                logger.error(f"Threat detection error: {e}")
                time.sleep(60)
    
    def detect_ddos_attacks(self):
        """Detect potential DDoS attacks"""
        current_time = time.time()
        window = 300  # 5 minutes
        threshold = 1000  # packets per 5 minutes per IP
        
        ip_packet_counts = defaultdict(int)
        
        for packet in packet_buffer:
            if current_time - packet['timestamp'] <= window:
                ip_packet_counts[packet['src_ip']] += 1
        
        for ip, count in ip_packet_counts.items():
            if count > threshold and self.is_public_ip(ip):
                threat_data = {
                    'timestamp': current_time,
                    'threat_type': 'DDoS Attack',
                    'src_ip': ip,
                    'severity': 'CRITICAL',
                    'details': {
                        'packet_count': count,
                        'time_window': window,
                        'threshold': threshold
                    }
                }
                self.handle_threat_detection({'timestamp': current_time, 'src_ip': ip, 'dst_ip': 'multiple'})
    
    def analyze_patterns(self):
        """Analyze traffic patterns periodically"""
        logger.info("Analyzing traffic patterns...")
        
        # Train/update ML model if enabled
        if MACHINE_LEARNING_ENABLED:
            self.update_ml_model()
        
        # Generate periodic reports
        self.generate_traffic_report()
    
    def update_ml_model(self):
        """Update machine learning model with recent data"""
        global ml_model, scaler
        
        try:
            if len(packet_buffer) < 100:  # Need minimum data
                return
            
            # Extract features from recent packets
            features = []
            for packet in list(packet_buffer)[-1000:]:  # Use last 1000 packets
                feature_row = [
                    packet['length'],
                    packet.get('src_port', 0),
                    packet.get('dst_port', 0),
                    packet['protocol'],
                    packet.get('ttl', 64)
                ]
                features.append(feature_row)
            
            # Train isolation forest for anomaly detection
            X = np.array(features)
            scaler.fit(X)
            X_scaled = scaler.transform(X)
            
            ml_model = IsolationForest(contamination=0.1, random_state=42)
            ml_model.fit(X_scaled)
            
            logger.info("ML model updated successfully")
            
        except Exception as e:
            logger.error(f"ML model update error: {e}")

# Initialize monitor
monitor = NetworkMonitor()

# Database functions
@contextmanager
def get_db_connection():
    """Database connection context manager"""
    conn = sqlite3.connect(DATABASE_PATH, timeout=30)
    try:
        yield conn
    finally:
        conn.close()

def init_database():
    """Initialize enhanced database schema"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        # Enhanced connections table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS connections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                local_ip TEXT NOT NULL,
                local_port INTEGER NOT NULL,
                remote_ip TEXT NOT NULL,
                remote_port INTEGER NOT NULL,
                protocol TEXT,
                pid INTEGER,
                process_name TEXT,
                duration REAL,
                bytes_sent INTEGER DEFAULT 0,
                bytes_received INTEGER DEFAULT 0,
                country TEXT,
                city TEXT,
                latitude REAL,
                longitude REAL,
                abuse_confidence REAL,
                threat_score REAL DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Traffic analysis table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS traffic_analysis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                src_ip TEXT NOT NULL,
                dst_ip TEXT NOT NULL,
                protocol TEXT,
                port INTEGER,
                packet_count INTEGER,
                bytes_total INTEGER,
                session_duration REAL,
                application_protocol TEXT,
                threat_indicators TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Threats table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                threat_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                src_ip TEXT NOT NULL,
                dst_ip TEXT,
                details TEXT,
                status TEXT DEFAULT 'active',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Bandwidth monitoring table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS bandwidth_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                ip_address TEXT NOT NULL,
                bytes_per_second REAL,
                packets_per_second REAL,
                protocol_distribution TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Geographic statistics
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS geo_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                country TEXT NOT NULL,
                connection_count INTEGER,
                bytes_total INTEGER,
                threat_count INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        logger.info("Enhanced database initialized")

# Flask routes
@app.route('/')
def dashboard():
    """Enhanced dashboard"""
    return render_template('enhanced_dashboard.html')

@app.route('/api/start-monitoring', methods=['POST'])
def start_monitoring():
    """Start network monitoring"""
    try:
        monitor.start_monitoring()
        return jsonify({'success': True, 'message': 'Network monitoring started'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/stop-monitoring', methods=['POST'])
def stop_monitoring():
    """Stop network monitoring"""
    try:
        monitor.stop_monitoring()
        return jsonify({'success': True, 'message': 'Network monitoring stopped'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/monitoring-status')
def monitoring_status():
    """Get current monitoring status"""
    return jsonify({
        'is_monitoring': monitor.is_monitoring,
        'packet_count': monitor.packet_count,
        'active_connections': len(active_connections),
        'uptime': time.time() - monitor.start_time,
        'buffer_size': len(packet_buffer)
    })

@app.route('/api/traffic-stats')
def get_traffic_stats():
    """Get comprehensive traffic statistics"""
    try:
        stats = {
            'bandwidth': monitor.calculate_bandwidth_stats(),
            'protocols': monitor.analyze_protocol_distribution(),
            'geography': monitor.analyze_geographic_distribution(),
            'active_connections': len(active_connections),
            'packet_count': monitor.packet_count,
            'threats_detected': len(threat_indicators)
        }
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/live-connections')
def get_live_connections():
    """Get current active connections with enhanced details"""
    connections = []
    for key, conn in active_connections.items():
        connections.append({
            'key': key,
            'local_ip': conn['local_ip'],
            'local_port': conn['local_port'],
            'remote_ip': conn['remote_ip'],
            'remote_port': conn['remote_port'],
            'duration': time.time() - conn['timestamp'],
            'country': conn.get('geo', {}).get('country', 'Unknown'),
            'city': conn.get('geo', {}).get('city', 'Unknown'),
            'abuse_confidence': conn.get('abuse_check', {}).get('confidence', 0),
            'threat_score': conn.get('threat_score', 0)
        })
    
    return jsonify(connections)

@app.route('/api/export-data')
def export_data():
    """Export comprehensive monitoring data"""
    try:
        # Create in-memory zip file
        memory_file = io.BytesIO()
        
        with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
            # Export connections
            with get_db_connection() as conn:
                cursor = conn.cursor()
                
                # Connections data
                cursor.execute('SELECT * FROM connections ORDER BY timestamp DESC LIMIT 10000')
                connections_data = cursor.fetchall()
                
                connections_csv = io.StringIO()
                writer = csv.writer(connections_csv)
                writer.writerow(['timestamp', 'local_ip', 'local_port', 'remote_ip', 'remote_port', 
                               'protocol', 'duration', 'country', 'abuse_confidence'])
                writer.writerows(connections_data)
                zf.writestr('connections.csv', connections_csv.getvalue())
                
                # Threats data
                cursor.execute('SELECT * FROM threats ORDER BY timestamp DESC LIMIT 1000')
                threats_data = cursor.fetchall()
                
                threats_csv = io.StringIO()
                writer = csv.writer(threats_csv)
                writer.writerow(['timestamp', 'threat_type', 'severity', 'src_ip', 'dst_ip', 'details'])
                writer.writerows(threats_data)
                zf.writestr('threats.csv', threats_csv.getvalue())
        
        memory_file.seek(0)
        
        return send_file(
            io.BytesIO(memory_file.read()),
            mimetype='application/zip',
            as_attachment=True,
            download_name=f'network_monitor_data_{datetime.now().strftime("%Y%m%d_%H%M%S")}.zip'
        )
        
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/threat-analysis')
def threat_analysis():
    """Get threat analysis dashboard data"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Recent threats
            cursor.execute('''
                SELECT threat_type, severity, src_ip, timestamp, details 
                FROM threats 
                ORDER BY timestamp DESC 
                LIMIT 100
            ''')
            recent_threats = cursor.fetchall()
            
            # Threat statistics
            cursor.execute('''
                SELECT threat_type, COUNT(*) as count, AVG(timestamp) as avg_time
                FROM threats 
                WHERE timestamp > ? 
                GROUP BY threat_type
            ''', (time.time() - 86400,))  # Last 24 hours
            
            threat_stats = cursor.fetchall()
            
            return jsonify({
                'recent_threats': recent_threats,
                'threat_statistics': threat_stats,
                'total_active_threats': len(threat_indicators)
            })
            
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/network-topology')
def network_topology():
    """Generate network topology data for visualization"""
    try:
        nodes = []
        edges = []
        
        # Add local machine as central node
        local_ips = set()
        for conn in active_connections.values():
            local_ips.add(conn['local_ip'])
        
        for local_ip in local_ips:
            nodes.append({
                'id': local_ip,
                'label': local_ip,
                'type': 'local',
                'color': '#4CAF50'
            })
        
        # Add remote connections
        for conn in active_connections.values():
            remote_ip = conn['remote_ip']
            if not any(node['id'] == remote_ip for node in nodes):
                nodes.append({
                    'id': remote_ip,
                    'label': remote_ip,
                    'type': 'remote',
                    'country': conn.get('geo', {}).get('country', 'Unknown'),
                    'color': '#2196F3' if conn.get('abuse_check', {}).get('confidence', 0) < 50 else '#FF5722'
                })
            
            edges.append({
                'from': conn['local_ip'],
                'to': remote_ip,
                'label': f":{conn['remote_port']}",
                'width': min(5, max(1, conn.get('bytes_sent', 0) / 1000))
            })
        
        return jsonify({
            'nodes': nodes,
            'edges': edges
        })
        
    except Exception as e:
        return jsonify({'error': str(e)})

# Socket.IO events
@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    emit('status', {'message': 'Connected to network monitor'})

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    logger.info('Client disconnected')

@socketio.on('request_update')
def handle_update_request():
    """Handle real-time update request"""
    emit('monitoring_status', {
        'is_monitoring': monitor.is_monitoring,
        'packet_count': monitor.packet_count,
        'active_connections': len(active_connections),
        'buffer_size': len(packet_buffer)
    })

if __name__ == '__main__':
    # Initialize database
    init_database()
    
    # Create data directory
    os.makedirs('data', exist_ok=True)
    
    logger.info("Starting Enhanced Network Traffic Analysis System...")
    logger.info(f"Packet capture: {'Enabled' if PACKET_CAPTURE_ENABLED else 'Disabled'}")
    logger.info(f"Deep packet inspection: {'Enabled' if DEEP_PACKET_INSPECTION_ENABLED else 'Disabled'}")
    logger.info(f"Machine learning: {'Enabled' if MACHINE_LEARNING_ENABLED else 'Disabled'}")
    
    # Start the application
    socketio.run(app, debug=False, host='0.0.0.0', port=5000)
