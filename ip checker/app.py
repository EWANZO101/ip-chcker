from flask import Response
from flask import Flask, render_template, request, jsonify
import requests
import os
from datetime import datetime, timedelta
import ipaddress
import socket
import subprocess
import platform
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import sqlite3
import json
from contextlib import contextmanager
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging
import hashlib
import time
import dns.resolver
import traceback
from functools import wraps, lru_cache
import shutil

app = Flask(__name__)


import os

# === IP / Domain Reputation & Threat Intelligence ===
ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY', 'your-abuseipdb-api-key')
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', 'your-virustotal-api-key')
IPVOID_API_KEY = os.getenv('IPVOID_API_KEY', 'your-ipvoid-api-key')
GREYNOISE_API_KEY = os.getenv('GREYNOISE_API_KEY', 'your-greynoise-api-key')
SHODAN_API_KEY = os.getenv('SHODAN_API_KEY', 'your-shodan-api-key')
BINARYEDGE_API_KEY = os.getenv('BINARYEDGE_API_KEY', 'your-binaryedge-api-key')
CENSYS_API_ID = os.getenv('CENSYS_API_ID', 'your-censys-api-id')
CENSYS_API_SECRET = os.getenv('CENSYS_API_SECRET', 'your-censys-api-secret')
THREATCROWD_API_KEY = os.getenv('THREATCROWD_API_KEY', 'your-threatcrowd-api-key')
OTX_API_KEY = os.getenv('OTX_API_KEY', 'your-otx-api-key')
SPYSE_API_KEY = os.getenv('SPYSE_API_KEY', 'your-spyse-api-key')
THREATMINER_API_KEY = os.getenv('THREATMINER_API_KEY', 'your-threatminer-api-key')
APIVOID_API_KEY = os.getenv('APIVOID_API_KEY', 'your-apivoid-api-key')
XFE_API_KEY = os.getenv('XFE_API_KEY', 'your-ibm-xfe-api-key')
XFE_API_PASS = os.getenv('XFE_API_PASS', 'your-ibm-xfe-api-password')
CIRCLPASSIVEDNS_API_KEY = os.getenv('CIRCLPASSIVEDNS_API_KEY', 'your-circl-passive-dns-key')

# === File / URL / Malware Analysis ===
HYBRID_ANALYSIS_API_KEY = os.getenv('HYBRID_ANALYSIS_API_KEY', 'your-hybrid-analysis-api-key')
ANYRUN_API_KEY = os.getenv('ANYRUN_API_KEY', 'your-anyrun-api-key')
JOESANDBOX_API_KEY = os.getenv('JOESANDBOX_API_KEY', 'your-joesandbox-api-key')
MALWAREBAZAAR_API_KEY = os.getenv('MALWAREBAZAAR_API_KEY', 'your-malwarebazaar-api-key')
URLSCAN_API_KEY = os.getenv('URLSCAN_API_KEY', 'your-urlscan-api-key')
CAPESANDBOX_API_KEY = os.getenv('CAPESANDBOX_API_KEY', 'your-capesandbox-api-key')

# === Credential Breach / Email Intelligence ===
HAVEIBEENPWNED_API_KEY = os.getenv('HIBP_API_KEY', 'your-hibp-api-key')
HUNTER_API_KEY = os.getenv('HUNTER_API_KEY', 'your-hunter-api-key')
EMAILREP_API_KEY = os.getenv('EMAILREP_API_KEY', 'your-emailrep-api-key')

# === Phishing Detection & Brand Protection ===
PHISHTANK_API_KEY = os.getenv('PHISHTANK_API_KEY', 'your-phishtank-api-key')
OPENPHISH_API_KEY = os.getenv('OPENPHISH_API_KEY', 'your-openphish-api-key')
CHECKPHISH_API_KEY = os.getenv('CHECKPHISH_API_KEY', 'your-checkphish-api-key')

# === Passive DNS, WHOIS, Certificates ===
SECURITYTRAILS_API_KEY = os.getenv('SECURITYTRAILS_API_KEY', 'your-securitytrails-api-key')
WHOISXML_API_KEY = os.getenv('WHOISXML_API_KEY', 'your-whoisxml-api-key')
CRT_SH_API_KEY = os.getenv('CRT_SH_API_KEY', 'your-crtsh-api-key')
FARSIGHTDNSDB_API_KEY = os.getenv('FARSIGHTDNSDB_API_KEY', 'your-farsight-dnsdb-api-key')

# === Miscellaneous OSINT / Enrichment ===
PEERINGDB_API_KEY = os.getenv('PEERINGDB_API_KEY', 'your-peeringdb-api-key')
RISKIQ_API_KEY = os.getenv('RISKIQ_API_KEY', 'your-riskiq-api-key')
RISKIQ_API_SECRET = os.getenv('RISKIQ_API_SECRET', 'your-riskiq-api-secret')
ZOOMEYE_API_KEY = os.getenv('ZOOMEYE_API_KEY', 'your-zoomeye-api-key')
ONYPHE_API_KEY = os.getenv('ONYPHE_API_KEY', 'your-onyph-api-key')
CROWDSOURCE_API_KEY = os.getenv('CROWDSOURCE_API_KEY', 'your-crowdsource-api-key')

# === API URLs ===

ABUSEIPDB_URL = 'https://api.abuseipdb.com/api/v2/check'
VIRUSTOTAL_URL = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
IPVOID_URL = 'https://endpoint.apivoid.com/iprep/v1/pay-as-you-go/'
GREYNOISE_URL = 'https://api.greynoise.io/v3/community/'
SHODAN_URL = 'https://api.shodan.io/'
BINARYEDGE_URL = 'https://api.binaryedge.io/v2/'
CENSYS_URL = 'https://search.censys.io/api/v2/'
THREATCROWD_URL = 'https://www.threatcrowd.org/searchApi/v2/'
OTX_URL = 'https://otx.alienvault.com/api/v1/'
SPYSE_URL = 'https://api.spyse.com/v4/data/'
THREATMINER_URL = 'https://api.threatminer.org/v2/'
HYBRID_ANALYSIS_URL = 'https://www.hybrid-analysis.com/api/v2/quick-scan/file'
ANYRUN_URL = 'https://api.any.run/v1/'
JOESANDBOX_URL = 'https://api.joesandbox.com/'
MALWAREBAZAAR_URL = 'https://mb-api.abuse.ch/api/v1/'
URLSCAN_URL = 'https://urlscan.io/api/v1/'
CAPESANDBOX_URL = 'https://capesandbox.com/api/'
HAVEIBEENPWNED_URL = 'https://haveibeenpwned.com/api/v3/breachedaccount/'
HUNTER_URL = 'https://api.hunter.io/v2/email-verifier'
EMAILREP_URL = 'https://emailrep.io/'
PHISHTANK_URL = 'http://data.phishtank.com/data/online-valid.json'
OPENPHISH_URL = 'https://openphish.com/feed.txt'
CHECKPHISH_URL = 'https://checkphish.ai/api/neo/scan'
SECURITYTRAILS_URL = 'https://api.securitytrails.com/v1/'
WHOISXML_URL = 'https://www.whoisxmlapi.com/whoisserver/'
CRT_SH_URL = 'https://crt.sh/'
FARSIGHTDNSDB_URL = 'https://api.dnsdb.info/dnsdb/v2/'
PEERINGDB_URL = 'https://www.peeringdb.com/api/'
RISKIQ_URL = 'https://api.riskiq.net/pt/v2/'
ZOOMEYE_URL = 'https://api.zoomeye.org/'
ONYPHE_URL = 'https://www.onyphe.io/api/v2/'
CROWDSOURCE_URL = 'https://crowdsource-api.example.com/'

ALLOWED_IPS = ['92.25.173.186', '51.179.204.24']  # List of allowed IPs
IP_LOCK_ENABLED = True  # Set to False to disable IP filtering

# Discord Webhook Configuration
DISCORD_WEBHOOK_URL = 'https://discord.com/api/webhooks/1396889092477812796/X6dc8zvQorEH4TsHVqMyaMBZgw1zwYHh4wqWr9B3uBkk1A976PxwD3vMt5AiqrW3cmSw'
DISCORD_ENABLED = True  # Set to False to disable Discord notifications

# Daily Monitoring Configuration
DATABASE_PATH = 'abuse_reports.db'
DAILY_CHECK_ENABLED = True
ALERT_EMAIL = os.getenv('ALERT_EMAIL', '')
SMTP_SERVER = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.getenv('SMTP_PORT', '587'))
SMTP_USER = os.getenv('SMTP_USER', '')
SMTP_PASS = os.getenv('SMTP_PASS', '')

# Logging configuration
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize scheduler
scheduler = BackgroundScheduler()
scheduler.start()

# Temporary IP whitelist for runtime additions
TEMPORARY_WHITELIST = []

# Database connection management
@contextmanager
def get_db_connection(timeout=30):
    """Context manager for database connections with proper error handling"""
    conn = None
    try:
        conn = sqlite3.connect(DATABASE_PATH, timeout=timeout)
        conn.execute('PRAGMA journal_mode=WAL')  # Enable WAL mode for better concurrency
        conn.execute('PRAGMA synchronous=NORMAL')  # Balance safety vs performance
        conn.execute('PRAGMA busy_timeout=30000')  # 30 second timeout for busy database
        yield conn
    except sqlite3.Error as e:
        if conn:
            conn.rollback()
        logger.error(f"Database error: {str(e)}")
        raise
    finally:
        if conn:
            conn.close()

def retry_db_operation(func, max_retries=3, delay=1):
    """Retry database operations with exponential backoff"""
    for attempt in range(max_retries):
        try:
            return func()
        except sqlite3.OperationalError as e:
            if "database is locked" in str(e).lower() and attempt < max_retries - 1:
                wait_time = delay * (2 ** attempt)  # Exponential backoff
                logger.warning(f"Database locked, retrying in {wait_time}s... (attempt {attempt + 1})")
                time.sleep(wait_time)
                continue
            else:
                logger.error(f"Database operation failed after {max_retries} attempts: {str(e)}")
                raise
        except Exception as e:
            logger.error(f"Database operation error: {str(e)}")
            raise

# Enhanced error logging and monitoring
def log_dashboard_errors(f):
    """Decorator to log dashboard errors with full context"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except Exception as e:
            # Log detailed error information
            error_details = {
                'function': f.__name__,
                'error_type': type(e).__name__,
                'error_message': str(e),
                'traceback': traceback.format_exc(),
                'timestamp': datetime.now().isoformat(),
                'client_ip': get_client_ip()
            }
            
            logger.error(f"Dashboard error in {f.__name__}: {error_details}")
            
            # Send detailed error to Discord
            send_discord_webhook(
                f"🚨 **Dashboard Error Detected**\n\n**Function:** `{f.__name__}`\n**Error:** {str(e)}\n**Client IP:** {get_client_ip()}\n**Time:** {datetime.now().strftime('%H:%M:%S')}\n\n**Action Required:** Check logs for full details",
                color=0xff0000,
                title="Dashboard Error Alert",
                urgent=True
            )
            
            # Return safe fallback response
            return jsonify({
                'error': f'Dashboard function {f.__name__} failed',
                'details': str(e),
                'fallback_data': get_fallback_stats()
            }), 500
            
    return decorated_function

def get_fallback_stats():
    """Provide safe fallback statistics when main queries fail"""
    return {
        'today_stats': {
            'total_checked': 0,
            'clean': 0,
            'suspicious': 0,
            'high_risk': 0,
            'avg_sources': 0,
            'total_detections': 0
        },
        'weekly_trend': [],
        'recent_alerts': [],
        'status': 'fallback_mode',
        'message': 'Using fallback data due to database issues'
    }

def send_discord_webhook(message, color=0x00ff00, title="IP Monitoring Alert", urgent=False):
    """Send message to Discord webhook"""
    if not DISCORD_ENABLED or not DISCORD_WEBHOOK_URL:
        logger.info(f"Discord notification: {title} - {message}")
        return
    
    try:
        embed = {
            "title": f"🛡️ {title}",
            "description": message,
            "color": color,
            "timestamp": datetime.utcnow().isoformat(),
            "footer": {
                "text": "IP Abuse Monitoring System",
                "icon_url": "https://cdn-icons-png.flaticon.com/512/1828/1828833.png"
            }
        }
        
        payload = {
            "embeds": [embed]
        }
        
        if urgent:
            payload["content"] = "@here 🚨 High Priority Alert!"
        
        response = requests.post(
            DISCORD_WEBHOOK_URL,
            json=payload,
            timeout=10
        )
        
        if response.status_code == 204:
            logger.info(f"Discord notification sent: {title}")
        else:
            logger.error(f"Discord webhook failed: {response.status_code}")
            
    except Exception as e:
        logger.error(f"Discord webhook error: {str(e)}")

def check_abuseipdb(ip):
    """Check IP against AbuseIPDB"""
    if ABUSEIPDB_API_KEY == 'your-api-key-here':
        return None
        
    headers = {
        'Key': ABUSEIPDB_API_KEY,
        'Accept': 'application/json',
    }
    
    params = {
        'ipAddress': ip,
        'maxAgeInDays': 90,
        'verbose': ''
    }
    
    try:
        response = requests.get(ABUSEIPDB_URL, headers=headers, params=params, timeout=10)
        
        if response.status_code == 200:
            data = response.json().get('data', {})
            return {
                'source': 'AbuseIPDB',
                'abuse_confidence': data.get('abuseConfidencePercentage', 0),
                'total_reports': data.get('totalReports', 0),
                'country_code': data.get('countryCode', 'Unknown'),
                'isp': data.get('isp', 'Unknown'),
                'usage_type': data.get('usageType', 'Unknown'),
                'is_whitelisted': data.get('isWhitelisted', False),
                'last_reported': data.get('lastReportedAt', None)
            }
        else:
            logger.error(f'AbuseIPDB API Error: {response.status_code} - {response.text}')
            return None
            
    except Exception as e:
        logger.error(f'AbuseIPDB check failed: {str(e)}')
        return None

def check_virustotal(ip):
    """Check IP against VirusTotal"""
    if VIRUSTOTAL_API_KEY == 'your-vt-api-key-here':
        return None
        
    params = {
        'apikey': VIRUSTOTAL_API_KEY,
        'ip': ip
    }
    
    try:
        response = requests.get(VIRUSTOTAL_URL, params=params, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            
            if data.get('response_code') == 1:
                positives = data.get('positives', 0)
                total = data.get('total', 1)
                
                # Calculate confidence based on detection ratio
                detection_ratio = (positives / total) * 100 if total > 0 else 0
                
                return {
                    'source': 'VirusTotal',
                    'abuse_confidence': min(detection_ratio * 2, 100),  # Scale up for better sensitivity
                    'total_reports': positives,
                    'detected_urls': len(data.get('detected_urls', [])),
                    'detected_samples': len(data.get('detected_communicating_samples', [])),
                    'country': data.get('country', 'Unknown'),
                    'as_owner': data.get('as_owner', 'Unknown')
                }
        else:
            logger.error(f'VirusTotal API Error: {response.status_code}')
            return None
            
    except Exception as e:
        logger.error(f'VirusTotal check failed: {str(e)}')
        return None

def check_ipvoid(ip):
    """Check IP against IPVoid"""
    if IPVOID_API_KEY == 'your-ipvoid-api-key-here':
        return None
        
    params = {
        'key': IPVOID_API_KEY,
        'ip': ip
    }
    
    try:
        response = requests.get(IPVOID_URL, params=params, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            
            if data.get('success'):
                engines = data.get('data', {}).get('report', {}).get('blacklists', {})
                
                # Count engines that detected the IP
                total_engines = len(engines)
                detected_engines = sum(1 for engine in engines.values() if engine.get('detected'))
                
                if total_engines > 0:
                    detection_ratio = (detected_engines / total_engines) * 100
                    
                    return {
                        'source': 'IPVoid',
                        'abuse_confidence': detection_ratio,
                        'total_reports': detected_engines,
                        'engines_total': total_engines,
                        'country_code': data.get('data', {}).get('information', {}).get('country_code', 'Unknown'),
                        'isp': data.get('data', {}).get('information', {}).get('isp', 'Unknown')
                    }
        else:
            logger.error(f'IPVoid API Error: {response.status_code}')
            return None
            
    except Exception as e:
        logger.error(f'IPVoid check failed: {str(e)}')
        return None

def check_greynoise(ip):
    """Check IP against GreyNoise Community API"""
    if GREYNOISE_API_KEY == 'your-greynoise-api-key-here':
        return None
        
    headers = {
        'key': GREYNOISE_API_KEY
    }
    
    try:
        response = requests.get(f"{GREYNOISE_URL}{ip}", headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            
            # GreyNoise classification
            classification = data.get('classification', 'unknown')
            noise = data.get('noise', False)
            riot = data.get('riot', False)
            
            # Calculate confidence based on classification
            confidence = 0
            if classification == 'malicious':
                confidence = 90
            elif classification == 'suspicious':
                confidence = 60  
            elif noise:
                confidence = 40
            elif riot:
                confidence = 10  # RIOT IPs are common business services
            
            return {
                'source': 'GreyNoise',
                'abuse_confidence': confidence,
                'classification': classification,
                'noise': noise,
                'riot': riot,
                'name': data.get('name', 'Unknown'),
                'last_seen': data.get('last_seen', None)
            }
        else:
            logger.error(f'GreyNoise API Error: {response.status_code}')
            return None
            
    except Exception as e:
        logger.error(f'GreyNoise check failed: {str(e)}')
        return None

def check_spamhaus(ip):
    """Check IP against Spamhaus DNS blacklists"""
    spamhaus_zones = [
        'sbl.spamhaus.org',
        'css.spamhaus.org', 
        'xbl.spamhaus.org',
        'pbl.spamhaus.org'
    ]
    
    detections = []
    
    try:
        # Reverse IP for DNS lookup
        reversed_ip = '.'.join(reversed(ip.split('.')))
        
        for zone in spamhaus_zones:
            query_domain = f"{reversed_ip}.{zone}"
            
            try:
                result = dns.resolver.resolve(query_domain, 'A')
                if result:
                    detections.append(zone)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                continue
            except Exception as e:
                logger.debug(f"Spamhaus {zone} lookup failed: {str(e)}")
                continue
        
        if detections:
            # Calculate confidence based on number of lists
            confidence = min(len(detections) * 25, 100)
            
            return {
                'source': 'Spamhaus',
                'abuse_confidence': confidence,
                'total_reports': len(detections),
                'detected_lists': detections
            }
        else:
            return {
                'source': 'Spamhaus',
                'abuse_confidence': 0,
                'total_reports': 0,
                'detected_lists': []
            }
            
    except Exception as e:
        logger.error(f'Spamhaus check failed: {str(e)}')
        return None

def check_surbl(ip):
    """Check IP against SURBL"""
    surbl_zones = [
        'multi.surbl.org',
        'multi.uribl.com'
    ]
    
    detections = []
    
    try:
        reversed_ip = '.'.join(reversed(ip.split('.')))
        
        for zone in surbl_zones:
            query_domain = f"{reversed_ip}.{zone}"
            
            try:
                result = dns.resolver.resolve(query_domain, 'A')
                if result:
                    detections.append(zone)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                continue
            except Exception:
                continue
        
        confidence = min(len(detections) * 30, 100) if detections else 0
        
        return {
            'source': 'SURBL',
            'abuse_confidence': confidence,
            'total_reports': len(detections),
            'detected_lists': detections
        }
        
    except Exception as e:
        logger.error(f'SURBL check failed: {str(e)}')
        return None

def check_barracuda(ip):
    """Check IP against Barracuda reputation"""
    try:
        reversed_ip = '.'.join(reversed(ip.split('.')))
        query_domain = f"{reversed_ip}.b.barracudacentral.org"
        
        try:
            result = dns.resolver.resolve(query_domain, 'A')
            if result:
                return {
                    'source': 'Barracuda',
                    'abuse_confidence': 75,
                    'total_reports': 1,
                    'detected': True
                }
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
            return {
                'source': 'Barracuda', 
                'abuse_confidence': 0,
                'total_reports': 0,
                'detected': False
            }
            
    except Exception as e:
        logger.error(f'Barracuda check failed: {str(e)}')
        return None

def aggregate_abuse_results(results):
    """Aggregate results from multiple abuse databases"""
    if not results:
        return {
            'abuseConfidence': 0,
            'totalReports': 0,
            'status': 'clean',
            'sources_checked': 0,
            'sources_detected': 0,
            'details': []
        }
    
    # Filter out None results
    valid_results = [r for r in results if r is not None]
    
    if not valid_results:
        return {
            'abuseConfidence': 0,
            'totalReports': 0,
            'status': 'error',
            'sources_checked': 0,
            'sources_detected': 0,
            'details': []
        }
    
    # Calculate weighted average confidence
    total_confidence = 0
    total_weight = 0
    total_reports = 0
    sources_detected = 0
    
    # Weight different sources
    source_weights = {
        'AbuseIPDB': 3.0,      # High weight - very reliable
        'VirusTotal': 2.5,     # High weight - comprehensive
        'Spamhaus': 2.0,       # High weight - email focus
        'IPVoid': 1.5,         # Medium weight
        'GreyNoise': 1.5,      # Medium weight  
        'SURBL': 1.0,          # Lower weight
        'Barracuda': 1.0       # Lower weight
    }
    
    for result in valid_results:
        source = result.get('source', 'Unknown')
        confidence = result.get('abuse_confidence', 0)
        reports = result.get('total_reports', 0)
        
        weight = source_weights.get(source, 1.0)
        
        total_confidence += confidence * weight
        total_weight += weight
        total_reports += reports
        
        if confidence > 0:
            sources_detected += 1
    
    # Calculate final confidence score
    if total_weight > 0:
        final_confidence = total_confidence / total_weight
    else:
        final_confidence = 0
    
    # Boost confidence if multiple sources agree
    if sources_detected > 1:
        boost_factor = 1 + (sources_detected - 1) * 0.1
        final_confidence = min(final_confidence * boost_factor, 100)
    
    # Determine status
    if final_confidence == 0:
        status = 'clean'
    elif final_confidence < 25:
        status = 'low-risk' 
    elif final_confidence < 75:
        status = 'reports'
    else:
        status = 'high-risk'
    
    return {
        'abuseConfidence': round(final_confidence, 1),
        'totalReports': total_reports,
        'status': status,
        'sources_checked': len(valid_results),
        'sources_detected': sources_detected,
        'details': valid_results
    }

def comprehensive_ip_check(ip):
    """Perform comprehensive IP abuse check using multiple sources"""
    logger.info(f"Starting comprehensive check for IP: {ip}")
    
    # Run all checks in parallel for speed
    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = {
            executor.submit(check_abuseipdb, ip): 'AbuseIPDB',
            executor.submit(check_virustotal, ip): 'VirusTotal', 
            executor.submit(check_ipvoid, ip): 'IPVoid',
            executor.submit(check_greynoise, ip): 'GreyNoise',
            executor.submit(check_spamhaus, ip): 'Spamhaus',
            executor.submit(check_surbl, ip): 'SURBL',
            executor.submit(check_barracuda, ip): 'Barracuda'
        }
        
        results = []
        for future in futures:
            try:
                result = future.result(timeout=15)
                if result:
                    results.append(result)
                    source = futures[future]
                    confidence = result.get('abuse_confidence', 0)
                    logger.info(f"{source}: {confidence}% confidence")
            except Exception as e:
                source = futures[future]
                logger.error(f"{source} check failed: {str(e)}")
    
    # Aggregate all results
    aggregated = aggregate_abuse_results(results)
    
    logger.info(f"Final result for {ip}: {aggregated['abuseConfidence']}% confidence from {aggregated['sources_checked']} sources")
    
    return aggregated

def check_ip_abuse(ip, save_to_db=False, send_discord=False):
    """Check IP against multiple abuse databases and optionally save to database"""
    if not validate_ip(ip):
        return {'error': 'Invalid IP address', 'status': 'error'}
    
    # Get previous status for comparison
    previous_status = get_previous_status(ip) if send_discord else None
    
    try:
        # Perform comprehensive check
        aggregated = comprehensive_ip_check(ip)
        
        # Get additional IP info
        country_code = 'Unknown'
        isp = 'Unknown'
        
        # Try to get country/ISP from the most reliable source
        for detail in aggregated.get('details', []):
            if detail.get('country_code') and country_code == 'Unknown':
                country_code = detail['country_code']
            if detail.get('isp') and isp == 'Unknown':
                isp = detail['isp']
            if detail.get('country') and country_code == 'Unknown':
                country_code = detail['country']
            if detail.get('as_owner') and isp == 'Unknown':
                isp = detail['as_owner']
        
        result = {
            'ip': ip,
            'abuseConfidence': aggregated['abuseConfidence'],
            'totalReports': aggregated['totalReports'],
            'status': aggregated['status'],
            'lastChecked': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'countryCode': country_code,
            'isp': isp,
            'sources_checked': aggregated['sources_checked'],
            'sources_detected': aggregated['sources_detected'],
            'details': aggregated['details']
        }
        
        if save_to_db:
            save_abuse_report_to_db(ip, result)
        
        if send_discord:
            send_ip_status_update(ip, previous_status or 'unknown', result['status'], result)
        
        return result
        
    except Exception as e:
        logger.error(f'Comprehensive IP check failed for {ip}: {str(e)}')
        return {'error': f'Check failed: {str(e)}', 'status': 'error'}

def send_ip_status_update(ip, old_status, new_status, details=None):
    """Send IP status update to Discord with comprehensive details"""
    if old_status == new_status:
        return
    
    # Determine color and urgency based on status
    color = 0x00ff00  # Green
    urgent = False
    
    if new_status == 'high-risk':
        color = 0xff0000  # Red
        urgent = True
        status_emoji = "🚨"
    elif new_status == 'reports':
        color = 0xffff00  # Yellow
        status_emoji = "⚠️"
    elif new_status == 'low-risk':
        color = 0xffa500  # Orange
        status_emoji = "🔶"
    elif new_status == 'clean':
        color = 0x00ff00  # Green
        status_emoji = "✅"
    else:
        color = 0x808080  # Gray
        status_emoji = "❓"
    
    confidence = details.get('abuseConfidence', 0) if details else 0
    reports = details.get('totalReports', 0) if details else 0
    sources_checked = details.get('sources_checked', 0) if details else 0
    sources_detected = details.get('sources_detected', 0) if details else 0
    
    # Build detailed source information
    source_info = ""
    if details and details.get('details'):
        detected_sources = [d['source'] for d in details['details'] if d.get('abuse_confidence', 0) > 0]
        if detected_sources:
            source_info = f"\n**Detected by:** {', '.join(detected_sources)}"
    
    message = f"""
**IP Address:** `{ip}`
**Status Change:** {old_status} → {new_status} {status_emoji}
**Abuse Confidence:** {confidence}%
**Total Reports:** {reports}
**Sources Checked:** {sources_checked}
**Sources Detected:** {sources_detected}{source_info}
**Country:** {details.get('countryCode', 'Unknown') if details else 'Unknown'}
**ISP:** {details.get('isp', 'Unknown') if details else 'Unknown'}
**Timestamp:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    """
    
    title = f"IP Status Update - {ip}"
    send_discord_webhook(message, color=color, title=title, urgent=urgent)

def send_daily_summary_discord(results):
    """Send daily summary to Discord with comprehensive stats"""
    if not results:
        return
    
    clean_ips = [r for r in results if r.get('abuseConfidence', 0) == 0]
    low_risk_ips = [r for r in results if 0 < r.get('abuseConfidence', 0) < 25]
    suspicious_ips = [r for r in results if 25 <= r.get('abuseConfidence', 0) < 75]
    high_risk_ips = [r for r in results if r.get('abuseConfidence', 0) >= 75]
    
    # Calculate average sources checked
    avg_sources = sum(r.get('sources_checked', 0) for r in results) / len(results) if results else 0
    
    # Main summary
    summary = f"""
**📊 Daily Comprehensive Abuse Check Summary - {datetime.now().strftime('%Y-%m-%d')}**

**Total IPs Checked:** {len(results)}
**✅ Clean IPs:** {len(clean_ips)}
**🔶 Low Risk IPs:** {len(low_risk_ips)}
**⚠️ Suspicious IPs:** {len(suspicious_ips)} 
**🚨 High Risk IPs:** {len(high_risk_ips)}
**📈 Avg Sources per IP:** {avg_sources:.1f}
    """
    
    # Add high risk details
    if high_risk_ips:
        summary += "\n\n**🚨 HIGH RISK IPs:**\n"
        for ip_data in high_risk_ips[:5]:
            sources_detected = ip_data.get('sources_detected', 0)
            summary += f"• `{ip_data['ip']}` - {ip_data.get('abuseConfidence', 0)}% ({sources_detected} sources)\n"
        
        if len(high_risk_ips) > 5:
            summary += f"• ... and {len(high_risk_ips) - 5} more\n"
    
    # Add suspicious details  
    if suspicious_ips:
        summary += "\n\n**⚠️ SUSPICIOUS IPs:**\n"
        for ip_data in suspicious_ips[:3]:
            sources_detected = ip_data.get('sources_detected', 0)
            summary += f"• `{ip_data['ip']}` - {ip_data.get('abuseConfidence', 0)}% ({sources_detected} sources)\n"
        
        if len(suspicious_ips) > 3:
            summary += f"• ... and {len(suspicious_ips) - 3} more\n"
    
    color = 0xff0000 if high_risk_ips else (0xffff00 if suspicious_ips else 0x00ff00)
    urgent = len(high_risk_ips) > 0
    
    send_discord_webhook(summary, color=color, title="Comprehensive Daily Summary", urgent=urgent)

def init_database():
    """Initialize SQLite database for storing abuse reports"""
    def _init():
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Create tables
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS abuse_reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT NOT NULL,
                    check_date DATE NOT NULL,
                    abuse_confidence REAL DEFAULT 0,
                    total_reports INTEGER DEFAULT 0,
                    country_code TEXT,
                    isp TEXT,
                    is_whitelisted BOOLEAN DEFAULT 0,
                    usage_type TEXT,
                    sources_checked INTEGER DEFAULT 0,
                    sources_detected INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(ip_address, check_date)
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ip_list (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT UNIQUE NOT NULL,
                    added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    is_active BOOLEAN DEFAULT 1,
                    notes TEXT
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS alert_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT NOT NULL,
                    alert_type TEXT NOT NULL,
                    message TEXT,
                    abuse_confidence REAL,
                    sources_detected INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS status_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT NOT NULL,
                    old_status TEXT,
                    new_status TEXT,
                    abuse_confidence REAL,
                    total_reports INTEGER,
                    sources_checked INTEGER,
                    sources_detected INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create indexes for performance
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_abuse_reports_ip_date ON abuse_reports(ip_address, check_date)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_abuse_reports_date ON abuse_reports(check_date)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_alert_history_date ON alert_history(created_at)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_status_history_date ON status_history(created_at)')
            
            conn.commit()
    
    retry_db_operation(_init)
    logger.info("Database initialized successfully")
    
    # Send startup notification to Discord
    send_discord_webhook(
        f"🚀 **Comprehensive IP Abuse Monitoring System Started**\n\n**Status:** Online and Ready\n**Database:** Initialized with WAL mode\n**Sources:** AbuseIPDB, VirusTotal, IPVoid, GreyNoise, Spamhaus, SURBL, Barracuda\n**IP Lock:** {'Enabled' if IP_LOCK_ENABLED else 'Disabled'}\n**Daily Monitoring:** {'Enabled' if DAILY_CHECK_ENABLED else 'Disabled'}\n**Allowed IPs:** {', '.join(ALLOWED_IPS)}\n**Server Time:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        color=0x0099ff,
        title="System Startup"
    )

def get_client_ip():
    """Get the real client IP address, considering proxies"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    else:
        return request.remote_addr

from flask import Response, request
from datetime import datetime
import ipaddress

# your other imports here

# your send_discord_webhook function here (assumed defined above)

@app.before_request
def limit_remote_addr():
    """Restrict access to allowed IP addresses only"""
    if not IP_LOCK_ENABLED:
        return None
    
    client_ip = get_client_ip()
    
    # Allow localhost for development
    if client_ip in ['127.0.0.1', 'localhost', '::1']:
        return None

    allowed_ips = ALLOWED_IPS + TEMPORARY_WHITELIST

    if client_ip not in allowed_ips:
        logger.warning(f"Blocked access attempt from IP: {client_ip}")
        
        send_discord_webhook(
            f"🚫 **Unauthorized Access Attempt**\n\n**Blocked IP:** `{client_ip}`\n**Time:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n**Action:** Access Denied (Redirected to ACD page)",
            color=0xff0000,
            title="Security Alert",
            urgent=True
        )
        
        return Response(status=302, headers={'Location': 'https://acd.swiftpeakhosting.com'})

# other functions here
def get_client_ip():
    """Get the real client IP address, considering proxies"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    else:
        return request.remote_addr

def validate_ip(ip):
    """Validate if the provided string is a valid IP address"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

# and so on...


def expand_ip_range(ip_range):
    """Expand IP range into list of individual IPs"""
    ips = []
    
    # Handle CIDR notation (e.g., 192.168.1.0/24)
    if '/' in ip_range:
        try:
            network = ipaddress.ip_network(ip_range, strict=False)
            for ip in network:
                ips.append(str(ip))
            return ips
        except ValueError:
            return None
    
    # Handle dash notation (e.g., 192.168.1.1-192.168.1.10)
    elif '-' in ip_range:
        try:
            start_ip, end_ip = ip_range.split('-')
            start_ip = start_ip.strip()
            end_ip = end_ip.strip()
            
            if not validate_ip(start_ip) or not validate_ip(end_ip):
                return None
            
            start = ipaddress.ip_address(start_ip)
            end = ipaddress.ip_address(end_ip)
            
            if start > end:
                start, end = end, start
            
            current = start
            count = 0
            while current <= end and count < 1000:
                ips.append(str(current))
                current += 1
                count += 1
            
            return ips
        except ValueError:
            return None
    else:
        if validate_ip(ip_range):
            return [ip_range]
        return None

# ========================
# ENHANCED CONNECTIVITY DETECTION FUNCTIONS
# These replace the old connectivity functions with enhanced RDP/service detection
# ========================

# Enhanced COMMON_PORTS with comprehensive service detection
COMMON_PORTS = {
    'SSH': 22,
    'Telnet': 23,
    'SMTP': 25,
    'DNS': 53,
    'HTTP': 80,
    'POP3': 110,
    'IMAP': 143,
    'SNMP': 161,
    'HTTPS': 443,
    'SMB': 445,
    'SMTP_SSL': 465,
    'IMAP_SSL': 993,
    'POP3_SSL': 995,
    'MySQL': 3306,
    'RDP': 3389,        # Windows Remote Desktop - KEY ENHANCEMENT
    'PostgreSQL': 5432,
    'VNC': 5900,
    'HTTP_ALT': 8080,
    'HTTP_ALT2': 8443,
    'Minecraft': 25565,
    'MongoDB': 27017,
    'Redis': 6379,
    'Elasticsearch': 9200,
    'FTP': 21,
    'FTPS': 990,
    'SFTP': 22,
    'WinRM_HTTP': 5985,
    'WinRM_HTTPS': 5986,
    'VPN_PPTP': 1723,
    'OpenVPN': 1194,
    'SIP': 5060,
    'Docker': 2376,
    'Kubernetes': 6443,
    'Grafana': 3000,
    'Prometheus': 9090
}

# High priority ports that strongly indicate system is online
HIGH_PRIORITY_PORTS = [22, 80, 443, 3389, 21, 23, 25, 53, 445]

def get_service_name(port):
    """Get service name for a port number"""
    for service, service_port in COMMON_PORTS.items():
        if service_port == port:
            return service
    return f'Port_{port}'

def check_ip_connectivity_enhanced(ip, timeout=5):
    """Enhanced connectivity check using both ping and TCP port scanning"""
    results = {
        'ping_status': 'unknown',
        'tcp_status': 'unknown', 
        'methods_used': []
    }
    
    # Method 1: Try ping first (but don't rely on it exclusively)
    try:
        if platform.system().lower() == 'windows':
            cmd = ['ping', '-n', '1', '-w', str(timeout * 1000), ip]
        else:
            cmd = ['ping', '-c', '1', '-W', str(timeout), ip]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 1)
        
        if result.returncode == 0:
            results['ping_status'] = 'online'
        else:
            results['ping_status'] = 'no_response'
        results['methods_used'].append('ping')
            
    except subprocess.TimeoutExpired:
        results['ping_status'] = 'timeout'
        results['methods_used'].append('ping_timeout')
    except Exception as e:
        results['ping_status'] = f'error: {str(e)[:30]}'
        results['methods_used'].append('ping_error')
    
    # Method 2: TCP connectivity test on common ports (more reliable for servers)
    tcp_ports_online = []
    
    def check_tcp_port_quick(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return port if result == 0 else None
        except Exception:
            return None
    
    # Check high priority ports with threading for speed
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(check_tcp_port_quick, port): port for port in HIGH_PRIORITY_PORTS}
        
        for future in as_completed(futures, timeout=timeout + 2):
            try:
                result = future.result(timeout=1)
                if result:
                    tcp_ports_online.append(result)
            except Exception:
                continue
    
    if tcp_ports_online:
        results['tcp_status'] = 'online'
        results['open_ports'] = tcp_ports_online
        results['methods_used'].append('tcp_scan')
    else:
        results['tcp_status'] = 'no_open_ports'
        results['open_ports'] = []
        results['methods_used'].append('tcp_scan_failed')
    
    # Determine overall connectivity status
    if results['tcp_status'] == 'online':
        overall_status = 'online'
    elif results['ping_status'] == 'online':
        overall_status = 'online_ping_only'  # Ping works but no TCP ports
    else:
        overall_status = 'offline'
    
    return {
        'status': overall_status,
        'response_time': 'Available' if overall_status.startswith('online') else 'No response',
        'details': results
    }

def check_ip_port_enhanced(ip, port, timeout=3):
    """Enhanced port checking with response time and service identification"""
    try:
        start_time = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        response_time = round((time.time() - start_time) * 1000, 2)  # ms
        sock.close()
        
        if result == 0:
            return {
                'port_status': 'open', 
                'port': port,
                'response_time_ms': response_time,
                'service': get_service_name(port)
            }
        else:
            return {
                'port_status': 'closed', 
                'port': port,
                'response_time_ms': response_time,
                'service': get_service_name(port)
            }
    except socket.timeout:
        return {
            'port_status': 'timeout', 
            'port': port, 
            'error': 'Connection timeout',
            'service': get_service_name(port)
        }
    except Exception as e:
        return {
            'port_status': 'error', 
            'port': port, 
            'error': str(e)[:50],
            'service': get_service_name(port)
        }

def comprehensive_port_scan(ip, timeout=3, max_ports=20):
    """Scan multiple common ports to detect services - KEY ENHANCEMENT"""
    open_ports = []
    services_found = []
    
    # Prioritize ports that are most likely to be open (including RDP!)
    priority_ports = [80, 443, 22, 3389, 21, 23, 25, 53, 445, 993, 995, 8080, 5985, 5986]
    
    def scan_port(port):
        result = check_ip_port_enhanced(ip, port, timeout)
        if result['port_status'] == 'open':
            return {
                'port': port,
                'service': result['service'],
                'response_time': result.get('response_time_ms', 0)
            }
        return None
    
    # Scan ports concurrently for speed
    with ThreadPoolExecutor(max_workers=15) as executor:
        futures = {executor.submit(scan_port, port): port for port in priority_ports[:max_ports]}
        
        for future in as_completed(futures, timeout=timeout + 3):
            try:
                result = future.result(timeout=1)
                if result:
                    open_ports.append(result['port'])
                    services_found.append(result['service'])
            except Exception:
                continue
    
    return {
        'open_ports': sorted(open_ports),
        'services': services_found,
        'total_open': len(open_ports)
    }

# Legacy wrapper functions for backward compatibility
def check_ip_connectivity(ip, timeout=3):
    """Legacy wrapper for enhanced connectivity check"""
    result = check_ip_connectivity_enhanced(ip, timeout)
    return {'status': result['status'], 'response_time': result['response_time']}

def check_ip_port(ip, port=80, timeout=3):
    """Legacy wrapper for enhanced port check"""
    result = check_ip_port_enhanced(ip, port, timeout)
    return {'port_status': result['port_status'], 'port': result['port']}

def get_live_status(ip, send_discord=False):
    """ENHANCED live status check with comprehensive port scanning and RDP detection"""
    logger.info(f"Enhanced connectivity check for IP: {ip}")
    
    # Step 1: Enhanced connectivity check (ping + TCP)
    basic_connectivity = check_ip_connectivity_enhanced(ip, timeout=5)
    
    # Step 2: Comprehensive port scan to detect services
    port_scan_results = comprehensive_port_scan(ip, timeout=3, max_ports=15)
    
    # Step 3: Determine overall connectivity status
    connectivity_status = basic_connectivity['status']
    
    # If TCP ports are open, definitely online (KEY FIX)
    if port_scan_results['total_open'] > 0:
        connectivity_status = 'online'
    elif basic_connectivity['status'] == 'online_ping_only':
        connectivity_status = 'online_ping_only'
    
    # Build comprehensive result with backward compatibility
    result = {
        'connectivity': connectivity_status,
        'services': port_scan_results['services'],
        'ports': {port: 'open' for port in port_scan_results['open_ports']},  # Keep backward compatibility
        'open_ports': port_scan_results['open_ports'],
        'total_open_ports': port_scan_results['total_open'],
        'last_checked': datetime.now().strftime('%H:%M:%S'),
        'connectivity_details': basic_connectivity['details'],
        'response_summary': f"{port_scan_results['total_open']} services detected" if port_scan_results['total_open'] > 0 else "No services responding"
    }
    
    # Enhanced Discord notification
    if send_discord:
        services_text = ", ".join(port_scan_results['services'][:5]) if port_scan_results['services'] else "No services detected"
        if len(port_scan_results['services']) > 5:
            services_text += f" (+{len(port_scan_results['services']) - 5} more)"
        
        send_live_status_update_enhanced(ip, connectivity_status, services_text, port_scan_results['total_open'])
    
    logger.info(f"Enhanced check for {ip}: {connectivity_status}, {port_scan_results['total_open']} ports open, services: {', '.join(port_scan_results['services'][:3])}")
    
    return result

def send_live_status_update_enhanced(ip, connectivity_status, services_text, open_ports_count):
    """Enhanced Discord notification for live status"""
    if connectivity_status == 'online':
        emoji = "🟢"
        color = 0x00ff00
        status_text = f"Online ({open_ports_count} ports)"
    elif connectivity_status == 'online_ping_only':
        emoji = "🟡"
        color = 0xffff00
        status_text = "Online (ping only)"
    elif connectivity_status == 'offline':
        emoji = "🔴"
        color = 0xff0000
        status_text = "Offline"
    else:
        emoji = "🟠"
        color = 0xffa500
        status_text = "Unknown"
    
    message = f"""
**IP Address:** `{ip}`
**Status:** {emoji} {status_text}
**Services Found:** {services_text}
**Open Ports:** {open_ports_count}
**Enhanced Detection:** RDP, SSH, HTTP/HTTPS, SMB, and 10+ more services
**Check Time:** {datetime.now().strftime('%H:%M:%S')}
    """
    
    send_discord_webhook(message, color=color, title=f"Enhanced Live Status - {ip}")

# Legacy wrapper for send_live_status_update
def send_live_status_update(ip, connectivity_status, services):
    """Legacy wrapper for enhanced status update"""
    services_text = ", ".join(services) if services else "No services detected"
    open_ports_count = len(services) if services else 0
    send_live_status_update_enhanced(ip, connectivity_status, services_text, open_ports_count)

# ========================
# END ENHANCED CONNECTIVITY FUNCTIONS
# ========================

def get_previous_status(ip):
    """Get the previous status of an IP from database"""
    def _get_status():
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT abuse_confidence FROM abuse_reports 
                WHERE ip_address = ? 
                ORDER BY created_at DESC 
                LIMIT 1
            ''', (ip,))
            
            result = cursor.fetchone()
            
            if result:
                confidence = result[0]
                if confidence == 0:
                    return 'clean'
                elif confidence < 25:
                    return 'low-risk'
                elif confidence < 75:
                    return 'reports'
                else:
                    return 'high-risk'
            
            return None
    
    try:
        return retry_db_operation(_get_status)
    except Exception as e:
        logger.error(f'Error getting previous status: {str(e)}')
        return None

def save_abuse_report_to_db(ip, result):
    """Save abuse report to database with proper connection management"""
    def _save_report():
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Insert or update the report
            cursor.execute('''
                INSERT OR REPLACE INTO abuse_reports 
                (ip_address, check_date, abuse_confidence, total_reports, country_code, isp, is_whitelisted, usage_type, sources_checked, sources_detected)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                ip,
                datetime.now().date(),
                result.get('abuseConfidence', 0),
                result.get('totalReports', 0),
                result.get('countryCode', ''),
                result.get('isp', ''),
                False,  # is_whitelisted
                '',     # usage_type
                result.get('sources_checked', 0),
                result.get('sources_detected', 0)
            ))
            
            # Save status history
            cursor.execute('''
                INSERT INTO status_history 
                (ip_address, new_status, abuse_confidence, total_reports, sources_checked, sources_detected)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                ip,
                result.get('status', 'unknown'),
                result.get('abuseConfidence', 0),
                result.get('totalReports', 0),
                result.get('sources_checked', 0),
                result.get('sources_detected', 0)
            ))
            
            conn.commit()
    
    try:
        retry_db_operation(_save_report)
        
        # Check if we need to send an alert (do this after DB save to avoid holding connection)
        check_and_send_alert(ip, result)
        
    except Exception as e:
        logger.error(f'Error saving to database: {str(e)}')

def check_and_send_alert(ip, result):
    """Check if an alert should be sent and send it"""
    abuse_confidence = result.get('abuseConfidence', 0)
    sources_detected = result.get('sources_detected', 0)
    
    # Alert thresholds
    if abuse_confidence >= 75:
        alert_type = 'HIGH_RISK'
        send_alert_email(ip, alert_type, f"High risk IP detected: {abuse_confidence}% confidence from {sources_detected} sources", result)
        
        # Send urgent Discord alert
        send_discord_webhook(
            f"🚨 **HIGH RISK IP DETECTED**\n\n**IP:** `{ip}`\n**Confidence:** {abuse_confidence}%\n**Reports:** {result.get('totalReports', 0)}\n**Sources Detected:** {sources_detected}/{result.get('sources_checked', 0)}\n**Country:** {result.get('countryCode', 'Unknown')}\n**ISP:** {result.get('isp', 'Unknown')}\n\n**⚠️ IMMEDIATE ACTION REQUIRED**",
            color=0xff0000,
            title="URGENT: High Risk IP Alert",
            urgent=True
        )
        
    elif abuse_confidence >= 25:
        alert_type = 'SUSPICIOUS'
        send_alert_email(ip, alert_type, f"Suspicious activity detected: {abuse_confidence}% confidence from {sources_detected} sources", result)
        
        # Send warning Discord alert
        send_discord_webhook(
            f"⚠️ **Suspicious IP Activity**\n\n**IP:** `{ip}`\n**Confidence:** {abuse_confidence}%\n**Reports:** {result.get('totalReports', 0)}\n**Sources Detected:** {sources_detected}/{result.get('sources_checked', 0)}\n**Country:** {result.get('countryCode', 'Unknown')}\n**ISP:** {result.get('isp', 'Unknown')}\n\n**Action:** Monitor closely",
            color=0xffff00,
            title="Suspicious IP Alert"
        )

def send_alert_email(ip, alert_type, message, result):
    """Send email alert for suspicious IPs"""
    if not ALERT_EMAIL or not SMTP_USER:
        logger.info(f"Alert for {ip}: {message} (Email not configured)")
        return
    
    def _save_alert():
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO alert_history (ip_address, alert_type, message, abuse_confidence, sources_detected)
                VALUES (?, ?, ?, ?, ?)
            ''', (ip, alert_type, message, result.get('abuseConfidence', 0), result.get('sources_detected', 0)))
            conn.commit()
    
    try:
        # Save alert to database first
        retry_db_operation(_save_alert)
        
        # Send email
        msg = MIMEMultipart()
        msg['From'] = SMTP_USER
        msg['To'] = ALERT_EMAIL
        msg['Subject'] = f"🚨 IP Abuse Alert: {alert_type} - {ip}"
        
        # Build detailed source information
        source_details = ""
        if result.get('details'):
            source_details = "\n\nDetection Details:\n"
            for detail in result['details']:
                if detail.get('abuse_confidence', 0) > 0:
                    source_details += f"- {detail['source']}: {detail.get('abuse_confidence', 0)}% confidence\n"
        
        body = f"""
Comprehensive IP Abuse Alert Report

IP Address: {ip}
Alert Type: {alert_type}
Abuse Confidence: {result.get('abuseConfidence', 0)}%
Total Reports: {result.get('totalReports', 0)}
Sources Checked: {result.get('sources_checked', 0)}
Sources Detected: {result.get('sources_detected', 0)}
Country: {result.get('countryCode', 'Unknown')}
ISP: {result.get('isp', 'Unknown')}
Last Checked: {result.get('lastChecked', 'Unknown')}

Message: {message}{source_details}

Please review this IP address immediately.

---
Automated Comprehensive IP Abuse Monitoring System
        """
        
        msg.attach(MIMEText(body, 'plain'))
        
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USER, SMTP_PASS)
        text = msg.as_string()
        server.sendmail(SMTP_USER, ALERT_EMAIL, text)
        server.quit()
        
        logger.info(f"Alert email sent for IP {ip}")
        
    except Exception as e:
        logger.error(f"Failed to send alert email: {str(e)}")

def daily_abuse_check():
    """Perform daily comprehensive abuse check on all active IPs with batch processing"""
    logger.info("Starting daily comprehensive abuse check...")
    
    # Send start notification to Discord
    send_discord_webhook(
        f"🔄 **Daily Comprehensive Abuse Check Starting**\n\nTime: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\nSources: AbuseIPDB, VirusTotal, IPVoid, GreyNoise, Spamhaus, SURBL, Barracuda\nChecking all monitored IPs...",
        color=0x0099ff,
        title="Daily Check Started"
    )
    
    try:
        # Get all active IPs
        def _get_active_ips():
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT ip_address FROM ip_list WHERE is_active = 1')
                return [row[0] for row in cursor.fetchall()]
        
        active_ips = retry_db_operation(_get_active_ips)
        
        if not active_ips:
            logger.info("No active IPs to check")
            send_discord_webhook(
                "ℹ️ **No IPs to Check**\n\nNo active IPs found in monitoring list.",
                color=0x808080,
                title="Daily Check Complete"
            )
            return
        
        logger.info(f"Checking {len(active_ips)} IPs comprehensively for abuse reports")
        
        # Check each IP with longer delays to prevent database locking
        results = []
        batch_results = []
        
        for i, ip in enumerate(active_ips):
            try:
                # Check IP without immediately saving to DB to avoid lock conflicts
                result = check_ip_abuse(ip, save_to_db=False, send_discord=False)
                results.append(result)
                batch_results.append((ip, result))
                
                logger.info(f"Checked {ip}: {result.get('abuseConfidence', 0)}% confidence from {result.get('sources_checked', 0)} sources ({i+1}/{len(active_ips)})")
                
                # Batch save every 5 IPs to reduce database contention
                if len(batch_results) >= 5 or i == len(active_ips) - 1:
                    save_batch_results(batch_results)
                    batch_results = []
                
                # Longer delay between checks to prevent API rate limiting and DB locking
                time.sleep(3)
                
            except Exception as e:
                logger.error(f"Error checking IP {ip}: {str(e)}")
                continue
        
        # Send Discord notifications for significant findings after all checks complete
        send_batch_discord_notifications(results)
        
        # Generate daily summary
        generate_daily_summary(results)
        
        # Send comprehensive summary to Discord
        send_daily_summary_discord(results)
        
        logger.info("Daily comprehensive abuse check completed successfully")
        
    except Exception as e:
        logger.error(f"Error in daily abuse check: {str(e)}")
        send_discord_webhook(
            f"❌ **Daily Check Failed**\n\nError: {str(e)}\nTime: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            color=0xff0000,
            title="Daily Check Error",
            urgent=True
        )

def save_batch_results(batch_results):
    """Save multiple results in a single database transaction"""
    def _save_batch():
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            for ip, result in batch_results:
                try:
                    # Insert or update the report
                    cursor.execute('''
                        INSERT OR REPLACE INTO abuse_reports 
                        (ip_address, check_date, abuse_confidence, total_reports, country_code, isp, is_whitelisted, usage_type, sources_checked, sources_detected)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        ip,
                        datetime.now().date(),
                        result.get('abuseConfidence', 0),
                        result.get('totalReports', 0),
                        result.get('countryCode', ''),
                        result.get('isp', ''),
                        False,  # is_whitelisted
                        '',     # usage_type
                        result.get('sources_checked', 0),
                        result.get('sources_detected', 0)
                    ))
                    
                    # Save status history
                    cursor.execute('''
                        INSERT INTO status_history 
                        (ip_address, new_status, abuse_confidence, total_reports, sources_checked, sources_detected)
                        VALUES (?, ?, ?, ?, ?, ?)
                    ''', (
                        ip,
                        result.get('status', 'unknown'),
                        result.get('abuseConfidence', 0),
                        result.get('totalReports', 0),
                        result.get('sources_checked', 0),
                        result.get('sources_detected', 0)
                    ))
                    
                except Exception as e:
                    logger.error(f"Error saving result for {ip}: {str(e)}")
                    continue
            
            conn.commit()
            logger.info(f"Batch saved {len(batch_results)} results to database")
    
    try:
        retry_db_operation(_save_batch)
        
        # Send alerts for high-risk IPs after saving
        for ip, result in batch_results:
            if result.get('abuseConfidence', 0) >= 25:  # Alert threshold
                try:
                    check_and_send_alert(ip, result)
                except Exception as e:
                    logger.error(f"Error sending alert for {ip}: {str(e)}")
                    
    except Exception as e:
        logger.error(f'Error saving batch results: {str(e)}')

def send_batch_discord_notifications(results):
    """Send Discord notifications for significant findings"""
    high_risk_ips = [r for r in results if r.get('abuseConfidence', 0) >= 75]
    
    # Send individual alerts for high-risk IPs
    for result in high_risk_ips[:3]:  # Limit to avoid spam
        try:
            send_ip_status_update(
                result['ip'], 
                'unknown', 
                result['status'], 
                result
            )
        except Exception as e:
            logger.error(f"Error sending Discord notification for {result.get('ip')}: {str(e)}")

def generate_daily_summary(results):
    """Generate and optionally email daily summary"""
    if not results:
        return
    
    clean_ips = [r for r in results if r.get('abuseConfidence', 0) == 0]
    low_risk_ips = [r for r in results if 0 < r.get('abuseConfidence', 0) < 25]
    suspicious_ips = [r for r in results if 25 <= r.get('abuseConfidence', 0) < 75]
    high_risk_ips = [r for r in results if r.get('abuseConfidence', 0) >= 75]
    
    avg_sources = sum(r.get('sources_checked', 0) for r in results) / len(results) if results else 0
    total_sources_detected = sum(r.get('sources_detected', 0) for r in results)
    
    summary = f"""
Comprehensive Daily Abuse Check Summary - {datetime.now().strftime('%Y-%m-%d')}

Total IPs Checked: {len(results)}
Clean IPs: {len(clean_ips)}
Low Risk IPs: {len(low_risk_ips)}
Suspicious IPs: {len(suspicious_ips)}
High Risk IPs: {len(high_risk_ips)}
Average Sources per IP: {avg_sources:.1f}
Total Detections: {total_sources_detected}

{'High Risk IPs:' if high_risk_ips else ''}
{chr(10).join([f"- {r['ip']}: {r.get('abuseConfidence', 0)}% confidence ({r.get('sources_detected', 0)} sources)" for r in high_risk_ips])}

{'Suspicious IPs:' if suspicious_ips else ''}
{chr(10).join([f"- {r['ip']}: {r.get('abuseConfidence', 0)}% confidence ({r.get('sources_detected', 0)} sources)" for r in suspicious_ips])}
    """
    
    logger.info(summary)

# Database backup function
def backup_database():
    """Create database backup"""
    try:
        backup_path = f"abuse_reports_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
        shutil.copy2(DATABASE_PATH, backup_path)
        
        logger.info(f"Database backed up to {backup_path}")
        
        # Send backup notification
        send_discord_webhook(
            f"💾 **Database Backup Created**\n\n**File:** `{backup_path}`\n**Time:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n**Status:** Success",
            color=0x00ff00,
            title="Backup Notification"
        )
        
        return backup_path
        
    except Exception as e:
        logger.error(f"Database backup failed: {e}")
        send_discord_webhook(
            f"❌ **Database Backup Failed**\n\n**Error:** {str(e)}\n**Time:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n**Action Required:** Manual backup recommended",
            color=0xff0000,
            title="Backup Error",
            urgent=True
        )
        return None

# ENHANCED API ROUTES

@app.route('/api/check-my-ip')
def check_my_ip():
    """Check what IP address the server sees"""
    client_ip = get_client_ip()
    allowed_ips = ALLOWED_IPS + TEMPORARY_WHITELIST
    return jsonify({
        'your_ip': client_ip,
        'is_allowed': client_ip in allowed_ips or client_ip in ['127.0.0.1', 'localhost', '::1'],
        'allowed_ips': ALLOWED_IPS,
        'temporary_whitelist': TEMPORARY_WHITELIST,
        'ip_lock_enabled': IP_LOCK_ENABLED
    })

@app.route('/api/admin/whitelist', methods=['POST'])
def admin_whitelist():
    """Temporary whitelist an IP (admin function)"""
    client_ip = get_client_ip()
    allowed_ips = ALLOWED_IPS + TEMPORARY_WHITELIST
    
    if client_ip not in allowed_ips and client_ip not in ['127.0.0.1', 'localhost', '::1']:
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.get_json()
    if not data or 'ip' not in data:
        return jsonify({'error': 'No IP provided'}), 400
    
    new_ip = data['ip'].strip()
    if not validate_ip(new_ip):
        return jsonify({'error': 'Invalid IP address'}), 400
    
    if new_ip not in TEMPORARY_WHITELIST and new_ip not in ALLOWED_IPS:
        TEMPORARY_WHITELIST.append(new_ip)
        logger.info(f"IP {new_ip} temporarily whitelisted by {client_ip}")
        
        # Send Discord notification
        send_discord_webhook(
            f"✅ **IP Temporarily Whitelisted**\n\n**New IP:** `{new_ip}`\n**Added by:** `{client_ip}`\n**Time:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n**Status:** Temporary (until restart)",
            color=0x00ff00,
            title="IP Whitelist Update"
        )
        
        return jsonify({
            'message': f'IP {new_ip} has been temporarily whitelisted',
            'allowed_ips': ALLOWED_IPS,
            'temporary_whitelist': TEMPORARY_WHITELIST
        })
    else:
        return jsonify({
            'message': 'IP already whitelisted', 
            'allowed_ips': ALLOWED_IPS,
            'temporary_whitelist': TEMPORARY_WHITELIST
        })

@app.route('/api/expand-range', methods=['POST'])
def api_expand_range():
    """API endpoint to expand IP range into individual IPs"""
    data = request.get_json()
    
    if not data or 'range' not in data:
        return jsonify({'error': 'No IP range provided'}), 400
    
    ip_range = data['range'].strip()
    ips = expand_ip_range(ip_range)
    
    if ips is None:
        return jsonify({'error': 'Invalid IP range format'}), 400
    
    if len(ips) > 1000:
        return jsonify({'error': 'Range too large (max 1000 IPs)'}), 400
    
    # Send Discord notification for range expansion
    if len(ips) > 1:
        send_discord_webhook(
            f"📊 **IP Range Expanded**\n\n**Range:** `{ip_range}`\n**Total IPs:** {len(ips)}\n**First IP:** `{ips[0]}`\n**Last IP:** `{ips[-1]}`\n**Time:** {datetime.now().strftime('%H:%M:%S')}",
            color=0x0099ff,
            title="Range Expansion"
        )
    
    return jsonify({'ips': ips, 'count': len(ips)})

@app.route('/api/live-status', methods=['POST'])
def api_live_status():
    """Enhanced API endpoint to check live status of an IP with RDP detection"""
    data = request.get_json()
    
    if not data or 'ip' not in data:
        return jsonify({'error': 'No IP address provided'}), 400
    
    ip = data['ip'].strip()
    send_discord = data.get('send_discord', False)
    
    if not validate_ip(ip):
        return jsonify({'error': 'Invalid IP address'}), 400
    
    try:
        status = get_live_status(ip, send_discord=send_discord)
        return jsonify({'ip': ip, **status})
    except Exception as e:
        return jsonify({'error': f'Enhanced status check failed: {str(e)}'}), 500

@app.route('/api/live-status-batch', methods=['POST'])
def api_live_status_batch():
    """Enhanced batch live status check with comprehensive service detection"""
    data = request.get_json()
    
    if not data or 'ips' not in data:
        return jsonify({'error': 'No IP addresses provided'}), 400
    
    ips = data['ips'][:50]  # Limit to 50 IPs for performance
    send_discord = data.get('send_discord', False)
    
    def check_single_ip_enhanced(ip):
        if not validate_ip(ip):
            return {'ip': ip, 'error': 'Invalid IP'}
        try:
            status = get_live_status(ip, send_discord=False)  # Disable individual notifications
            return {'ip': ip, **status}
        except Exception as e:
            logger.error(f"Enhanced check failed for {ip}: {str(e)}")
            return {'ip': ip, 'error': str(e), 'connectivity': 'error'}
    
    # Use ThreadPoolExecutor for concurrent checks with more workers
    start_time = time.time()
    with ThreadPoolExecutor(max_workers=20) as executor:
        results = list(executor.map(check_single_ip_enhanced, ips))
    
    check_duration = round(time.time() - start_time, 2)
    
    # Calculate enhanced statistics
    online_count = sum(1 for r in results if r.get('connectivity', '').startswith('online'))
    offline_count = len(ips) - online_count
    total_services = sum(r.get('total_open_ports', 0) for r in results)
    rdp_count = sum(1 for r in results if 'RDP' in r.get('services', []))
    ssh_count = sum(1 for r in results if 'SSH' in r.get('services', []))
    
    # Enhanced batch summary for Discord
    if send_discord and len(ips) > 1:
        summary_message = f"""📡 **Enhanced Batch Status Check Complete**

**📊 Summary:**
• **Total IPs Scanned:** {len(ips)}
• **🟢 Online IPs:** {online_count}
• **🔴 Offline IPs:** {offline_count}
• **🔧 Total Services Found:** {total_services}
• **🖥️ RDP Servers:** {rdp_count}
• **🔐 SSH Servers:** {ssh_count}
• **⚡ Scan Duration:** {check_duration}s

**🔍 Detection Methods:**
✅ TCP Port Scanning (15+ common ports)
✅ Enhanced timeout handling  
✅ RDP, SSH, HTTP/S, SMB detection
✅ Concurrent scanning for speed"""
        
        send_discord_webhook(
            summary_message,
            color=0x0099ff,
            title="Enhanced Batch Scan Complete"
        )
    
    return jsonify({
        'results': results,
        'summary': {
            'total_scanned': len(ips),
            'online_count': online_count,
            'offline_count': offline_count,
            'total_services_found': total_services,
            'rdp_servers': rdp_count,
            'ssh_servers': ssh_count,
            'scan_duration_seconds': check_duration
        }
    })

@app.route('/api/check-ip', methods=['POST'])
def api_check_ip():
    """API endpoint to check a single IP comprehensively"""
    data = request.get_json()
    
    if not data or 'ip' not in data:
        return jsonify({'error': 'No IP address provided'}), 400
    
    ip = data['ip'].strip()
    save_to_db = data.get('save_to_db', False)
    send_discord = data.get('send_discord', False)
    result = check_ip_abuse(ip, save_to_db=save_to_db, send_discord=send_discord)
    
    return jsonify(result)

@app.route('/api/check-multiple', methods=['POST'])
def api_check_multiple():
    """API endpoint to check multiple IPs comprehensively"""
    data = request.get_json()
    
    if not data or 'ips' not in data:
        return jsonify({'error': 'No IP addresses provided'}), 400
    
    ips = data['ips']
    save_to_db = data.get('save_to_db', False)
    send_discord = data.get('send_discord', False)
    results = []
    
    for ip in ips:
        ip = ip.strip()
        if ip:  # Skip empty strings
            result = check_ip_abuse(ip, save_to_db=save_to_db, send_discord=send_discord)
            results.append(result)
            # Small delay between checks
            time.sleep(1)
    
    return jsonify({'results': results})

@app.route('/api/add-ip-to-monitoring', methods=['POST'])
def api_add_ip_to_monitoring():
    """Add IP to daily monitoring list"""
    data = request.get_json()
    
    if not data or 'ip' not in data:
        return jsonify({'error': 'No IP address provided'}), 400
    
    ip = data['ip'].strip()
    notes = data.get('notes', '')
    
    if not validate_ip(ip):
        return jsonify({'error': 'Invalid IP address'}), 400
    
    def _add_ip():
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO ip_list (ip_address, notes, is_active)
                VALUES (?, ?, 1)
            ''', (ip, notes))
            
            conn.commit()
    
    try:
        retry_db_operation(_add_ip)
        
        # Send Discord notification
        send_discord_webhook(
            f"➕ **IP Added to Enhanced Monitoring**\n\n**IP:** `{ip}`\n**Notes:** {notes if notes else 'None'}\n**Status:** Active\n**Sources:** All 7 abuse databases + Enhanced service detection\n**Services Detected:** RDP, SSH, HTTP/S, SMB, and 15+ more\n**Time:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            color=0x00ff00,
            title="Monitoring List Updated"
        )
        
        return jsonify({'message': f'IP {ip} added to enhanced monitoring list'})
        
    except Exception as e:
        return jsonify({'error': f'Database error: {str(e)}'}), 500

@app.route('/api/monitoring-list')
def api_monitoring_list():
    """Get list of IPs being monitored"""
    def _get_list():
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT ip_address, added_date, is_active, notes
                FROM ip_list
                ORDER BY added_date DESC
            ''')
            
            results = cursor.fetchall()
            
            ips = []
            for row in results:
                ips.append({
                    'ip': row[0],
                    'added_date': row[1],
                    'is_active': bool(row[2]),
                    'notes': row[3] or ''
                })
            
            return ips
    
    try:
        monitoring_list = retry_db_operation(_get_list)
        return jsonify({'monitoring_list': monitoring_list})
        
    except Exception as e:
        return jsonify({'error': f'Database error: {str(e)}'}), 500

@app.route('/api/abuse-history/<ip>')
def api_abuse_history(ip):
    """Get comprehensive abuse history for a specific IP"""
    if not validate_ip(ip):
        return jsonify({'error': 'Invalid IP address'}), 400
    
    def _get_history():
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT check_date, abuse_confidence, total_reports, country_code, isp, 
                       COALESCE(sources_checked, 0) as sources_checked, 
                       COALESCE(sources_detected, 0) as sources_detected
                FROM abuse_reports
                WHERE ip_address = ?
                ORDER BY check_date DESC
                LIMIT 30
            ''', (ip,))
            
            results = cursor.fetchall()
            
            history = []
            for row in results:
                history.append({
                    'date': row[0],
                    'abuse_confidence': row[1],
                    'total_reports': row[2],
                    'country_code': row[3],
                    'isp': row[4],
                    'sources_checked': row[5],
                    'sources_detected': row[6]
                })
            
            return history
    
    try:
        history = retry_db_operation(_get_history)
        return jsonify({'ip': ip, 'history': history})
        
    except Exception as e:
        return jsonify({'error': f'Database error: {str(e)}'}), 500

# FIXED DASHBOARD STATS FUNCTION
@app.route('/api/dashboard-stats')
@log_dashboard_errors
def api_dashboard_stats():
    """Get comprehensive dashboard statistics with robust error handling"""
    def _get_stats():
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            try:
                # First, check if required columns exist
                cursor.execute("PRAGMA table_info(abuse_reports)")
                columns = {row[1]: row[2] for row in cursor.fetchall()}
                
                has_sources_checked = 'sources_checked' in columns
                has_sources_detected = 'sources_detected' in columns
                
                # Check if alert_history table exists
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='alert_history'")
                has_alert_history = cursor.fetchone() is not None
                
                # Get today's stats with conditional column selection
                today = datetime.now().date()
                
                if has_sources_checked and has_sources_detected:
                    stats_query = '''
                        SELECT 
                            COUNT(*) as total_checked,
                            COUNT(CASE WHEN abuse_confidence = 0 THEN 1 END) as clean,
                            COUNT(CASE WHEN abuse_confidence > 0 AND abuse_confidence < 75 THEN 1 END) as suspicious,
                            COUNT(CASE WHEN abuse_confidence >= 75 THEN 1 END) as high_risk,
                            AVG(sources_checked) as avg_sources,
                            SUM(sources_detected) as total_detections
                        FROM abuse_reports
                        WHERE check_date = ?
                    '''
                else:
                    stats_query = '''
                        SELECT 
                            COUNT(*) as total_checked,
                            COUNT(CASE WHEN abuse_confidence = 0 THEN 1 END) as clean,
                            COUNT(CASE WHEN abuse_confidence > 0 AND abuse_confidence < 75 THEN 1 END) as suspicious,
                            COUNT(CASE WHEN abuse_confidence >= 75 THEN 1 END) as high_risk,
                            0 as avg_sources,
                            0 as total_detections
                        FROM abuse_reports
                        WHERE check_date = ?
                    '''
                
                cursor.execute(stats_query, (today,))
                today_stats = cursor.fetchone()
                
                # Get weekly trend with conditional column selection
                week_ago = today - timedelta(days=7)
                
                if has_sources_checked:
                    trend_query = '''
                        SELECT check_date, 
                               COUNT(*) as total,
                               AVG(abuse_confidence) as avg_confidence,
                               AVG(sources_checked) as avg_sources
                        FROM abuse_reports
                        WHERE check_date >= ?
                        GROUP BY check_date
                        ORDER BY check_date
                    '''
                else:
                    trend_query = '''
                        SELECT check_date, 
                               COUNT(*) as total,
                               AVG(abuse_confidence) as avg_confidence,
                               0 as avg_sources
                        FROM abuse_reports
                        WHERE check_date >= ?
                        GROUP BY check_date
                        ORDER BY check_date
                    '''
                
                cursor.execute(trend_query, (week_ago,))
                weekly_trend = cursor.fetchall()
                
                # Get recent alerts if table exists
                recent_alerts = []
                if has_alert_history:
                    try:
                        cursor.execute('''
                            SELECT ip_address, alert_type, message, created_at, 
                                   COALESCE(sources_detected, 0) as sources_detected
                            FROM alert_history
                            ORDER BY created_at DESC
                            LIMIT 10
                        ''')
                        recent_alerts = cursor.fetchall()
                    except sqlite3.Error as e:
                        logger.warning(f"Error getting alerts: {e}")
                        recent_alerts = []
                
                return {
                    'today_stats': {
                        'total_checked': today_stats[0] or 0,
                        'clean': today_stats[1] or 0,
                        'suspicious': today_stats[2] or 0,
                        'high_risk': today_stats[3] or 0,
                        'avg_sources': round(today_stats[4] or 0, 1),
                        'total_detections': today_stats[5] or 0
                    },
                    'weekly_trend': [
                        {
                            'date': row[0],
                            'total': row[1],
                            'avg_confidence': round(row[2] or 0, 2),
                            'avg_sources': round(row[3] or 0, 1)
                        } for row in weekly_trend
                    ],
                    'recent_alerts': [
                        {
                            'ip': row[0],
                            'type': row[1],
                            'message': row[2],
                            'timestamp': row[3],
                            'sources_detected': row[4] if len(row) > 4 else 0
                        } for row in recent_alerts
                    ],
                    'schema_info': {
                        'has_sources_checked': has_sources_checked,
                        'has_sources_detected': has_sources_detected,
                        'has_alert_history': has_alert_history
                    }
                }
                
            except sqlite3.Error as e:
                logger.error(f"Database error in dashboard stats: {e}")
                raise
                
    try:
        stats = retry_db_operation(_get_stats)
        return jsonify(stats)
        
    except Exception as e:
        logger.error(f'Dashboard stats error: {str(e)}')
        return jsonify({
            'error': f'Dashboard stats error: {str(e)}',
            'today_stats': {
                'total_checked': 0,
                'clean': 0,
                'suspicious': 0,
                'high_risk': 0,
                'avg_sources': 0,
                'total_detections': 0
            },
            'weekly_trend': [],
            'recent_alerts': []
        }), 500

# DIAGNOSTIC AND REPAIR ENDPOINTS

@app.route('/api/diagnose-db')
def diagnose_database():
    """Diagnose database issues"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Check if database file exists and is accessible
            cursor.execute("SELECT sqlite_version()")
            sqlite_version = cursor.fetchone()[0]
            
            # Check all tables
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]
            
            # Check abuse_reports table structure
            cursor.execute("PRAGMA table_info(abuse_reports)")
            abuse_reports_columns = cursor.fetchall()
            
            # Check if we have any data
            cursor.execute("SELECT COUNT(*) FROM abuse_reports")
            total_reports = cursor.fetchone()[0]
            
            # Check recent data
            cursor.execute("SELECT COUNT(*) FROM abuse_reports WHERE check_date = date('now')")
            today_reports = cursor.fetchone()[0]
            
            # Test problematic query parts
            test_results = {}
            
            # Test sources_checked column
            try:
                cursor.execute("SELECT sources_checked FROM abuse_reports LIMIT 1")
                test_results['sources_checked'] = "EXISTS"
            except sqlite3.Error as e:
                test_results['sources_checked'] = f"ERROR: {str(e)}"
            
            # Test sources_detected column  
            try:
                cursor.execute("SELECT sources_detected FROM abuse_reports LIMIT 1")
                test_results['sources_detected'] = "EXISTS"
            except sqlite3.Error as e:
                test_results['sources_detected'] = f"ERROR: {str(e)}"
            
            # Test alert_history table
            try:
                cursor.execute("SELECT COUNT(*) FROM alert_history")
                alert_count = cursor.fetchone()[0]
                test_results['alert_history'] = f"EXISTS ({alert_count} records)"
            except sqlite3.Error as e:
                test_results['alert_history'] = f"ERROR: {str(e)}"
            
            return jsonify({
                'sqlite_version': sqlite_version,
                'tables': tables,
                'abuse_reports_columns': [col[1] for col in abuse_reports_columns],
                'total_reports': total_reports,
                'today_reports': today_reports,
                'column_tests': test_results,
                'diagnosis': 'success'
            })
            
    except Exception as e:
        return jsonify({
            'error': str(e),
            'diagnosis': 'failed'
        }), 500

@app.route('/api/dashboard-stats-minimal')
def api_dashboard_stats_minimal():
    """Minimal dashboard stats that should always work"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            today = datetime.now().date()
            
            # Basic stats that should always work
            cursor.execute('''
                SELECT 
                    COUNT(*) as total,
                    COUNT(CASE WHEN abuse_confidence = 0 THEN 1 END) as clean,
                    COUNT(CASE WHEN abuse_confidence > 0 THEN 1 END) as suspicious,
                    AVG(abuse_confidence) as avg_confidence
                FROM abuse_reports
                WHERE check_date = ?
            ''', (today,))
            
            result = cursor.fetchone()
            
            return jsonify({
                'today_stats': {
                    'total_checked': result[0] or 0,
                    'clean': result[1] or 0,
                    'suspicious': result[2] or 0,
                    'high_risk': 0,  # Calculate separately if needed
                    'avg_sources': 0,
                    'total_detections': 0,
                    'avg_confidence': round(result[3] or 0, 2)
                },
                'weekly_trend': [],
                'recent_alerts': [],
                'note': 'Minimal stats version - some features disabled'
            })
            
    except Exception as e:
        return jsonify({
            'error': str(e),
            'today_stats': {
                'total_checked': 0,
                'clean': 0,
                'suspicious': 0,
                'high_risk': 0,
                'avg_sources': 0,
                'total_detections': 0
            },
            'weekly_trend': [],
            'recent_alerts': []
        }), 500

@app.route('/api/repair-database', methods=['POST'])
def api_repair_database():
    """Repair and upgrade database schema"""
    client_ip = get_client_ip()
    allowed_ips = ALLOWED_IPS + TEMPORARY_WHITELIST
    
    if client_ip not in allowed_ips and client_ip not in ['127.0.0.1', 'localhost', '::1']:
        return jsonify({'error': 'Unauthorized'}), 403
    
    def _repair_database():
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            repairs_made = []
            
            try:
                # Check current schema
                cursor.execute("PRAGMA table_info(abuse_reports)")
                columns = {row[1]: row[2] for row in cursor.fetchall()}
                
                # Add missing columns to abuse_reports
                if 'sources_checked' not in columns:
                    cursor.execute('ALTER TABLE abuse_reports ADD COLUMN sources_checked INTEGER DEFAULT 0')
                    repairs_made.append('Added sources_checked column')
                
                if 'sources_detected' not in columns:
                    cursor.execute('ALTER TABLE abuse_reports ADD COLUMN sources_detected INTEGER DEFAULT 0')
                    repairs_made.append('Added sources_detected column')
                
                # Ensure alert_history table exists
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS alert_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ip_address TEXT NOT NULL,
                        alert_type TEXT NOT NULL,
                        message TEXT,
                        abuse_confidence REAL,
                        sources_detected INTEGER,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                repairs_made.append('Ensured alert_history table exists')
                
                # Ensure status_history table exists
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS status_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ip_address TEXT NOT NULL,
                        old_status TEXT,
                        new_status TEXT,
                        abuse_confidence REAL,
                        total_reports INTEGER,
                        sources_checked INTEGER,
                        sources_detected INTEGER,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                repairs_made.append('Ensured status_history table exists')
                
                # Create indexes for better performance
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_abuse_reports_ip_date ON abuse_reports(ip_address, check_date)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_abuse_reports_date ON abuse_reports(check_date)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_alert_history_date ON alert_history(created_at)')
                repairs_made.append('Created performance indexes')
                
                conn.commit()
                
                return {
                    'success': True,
                    'repairs_made': repairs_made,
                    'repair_count': len(repairs_made)
                }
                
            except sqlite3.Error as e:
                logger.error(f"Database repair error: {e}")
                conn.rollback()
                return {
                    'success': False,
                    'error': str(e),
                    'repairs_made': repairs_made
                }
    
    try:
        result = retry_db_operation(_repair_database)
        
        if result['success']:
            # Send Discord notification
            send_discord_webhook(
                f"🔧 **Database Repair Completed**\n\n**Repairs Made:** {result['repair_count']}\n**Details:**\n{chr(10).join(['• ' + repair for repair in result['repairs_made']])}\n**Triggered by:** `{client_ip}`\n**Time:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                color=0x00ff00,
                title="Database Repair"
            )
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Repair operation failed: {str(e)}'
        }), 500

@app.route('/api/database-health')
def api_database_health():
    """Check database health and schema integrity"""
    def _check_health():
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            health_report = {
                'tables': {},
                'issues': [],
                'recommendations': []
            }
            
            # Check each table
            tables_to_check = ['abuse_reports', 'ip_list', 'alert_history', 'status_history']
            
            for table in tables_to_check:
                try:
                    cursor.execute(f"SELECT COUNT(*) FROM {table}")
                    count = cursor.fetchone()[0]
                    
                    cursor.execute(f"PRAGMA table_info({table})")
                    columns = cursor.fetchall()
                    
                    health_report['tables'][table] = {
                        'exists': True,
                        'row_count': count,
                        'columns': [col[1] for col in columns]
                    }
                    
                except sqlite3.Error as e:
                    health_report['tables'][table] = {
                        'exists': False,
                        'error': str(e)
                    }
                    health_report['issues'].append(f"Table {table} has issues: {str(e)}")
            
            # Check for missing columns
            if 'abuse_reports' in health_report['tables'] and health_report['tables']['abuse_reports']['exists']:
                expected_columns = ['sources_checked', 'sources_detected']
                actual_columns = health_report['tables']['abuse_reports']['columns']
                
                for col in expected_columns:
                    if col not in actual_columns:
                        health_report['issues'].append(f"Missing column: {col} in abuse_reports")
                        health_report['recommendations'].append(f"Run database repair to add {col} column")
            
            # Check database file size and integrity
            cursor.execute("PRAGMA integrity_check")
            integrity_result = cursor.fetchone()
            
            if integrity_result[0] != 'ok':
                health_report['issues'].append(f"Database integrity issue: {integrity_result[0]}")
                health_report['recommendations'].append("Consider database repair or backup restoration")
            
            # Check for indexes
            cursor.execute("SELECT name FROM sqlite_master WHERE type='index'")
            indexes = [row[0] for row in cursor.fetchall()]
            
            health_report['indexes'] = indexes
            
            if not any('idx_abuse_reports' in idx for idx in indexes):
                health_report['recommendations'].append("Add performance indexes for better query speed")
            
            health_report['overall_health'] = 'good' if not health_report['issues'] else 'needs_attention'
            
            return health_report
    
    try:
        health = retry_db_operation(_check_health)
        return jsonify(health)
        
    except Exception as e:
        return jsonify({
            'overall_health': 'error',
            'error': str(e),
            'tables': {},
            'issues': [f"Health check failed: {str(e)}"],
            'recommendations': ["Check database file permissions and integrity"]
        }), 500

@app.route('/api/system-health')
def api_system_health():
    """Comprehensive system health check"""
    health_status = {
        'database': 'unknown',
        'api_keys': {},
        'discord': 'unknown',
        'scheduler': 'unknown',
        'disk_space': 'unknown'
    }
    
    try:
        # Database health
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM abuse_reports")
            health_status['database'] = 'healthy'
    except Exception as e:
        health_status['database'] = f'error: {str(e)}'
    
    # API key status
    health_status['api_keys'] = {
        'abuseipdb': ABUSEIPDB_API_KEY != 'your-api-key-here',
        'virustotal': VIRUSTOTAL_API_KEY != 'your-vt-api-key-here',
        'ipvoid': IPVOID_API_KEY != 'your-ipvoid-api-key-here',
        'greynoise': GREYNOISE_API_KEY != 'your-greynoise-api-key-here'
    }
    
    # Discord webhook status
    health_status['discord'] = 'enabled' if DISCORD_ENABLED and DISCORD_WEBHOOK_URL else 'disabled'
    
    # Scheduler status
    health_status['scheduler'] = 'running' if scheduler.running else 'stopped'
    
    # Database file size
    try:
        db_size = os.path.getsize(DATABASE_PATH)
        health_status['database_size'] = f"{db_size / (1024*1024):.2f} MB"
    except:
        health_status['database_size'] = 'unknown'
    
    return jsonify({
        'overall_status': 'healthy' if health_status['database'] == 'healthy' else 'issues_detected',
        'components': health_status,
        'timestamp': datetime.now().isoformat(),
        'enhanced_features': {
            'rdp_detection': True,
            'comprehensive_port_scanning': True,
            'enhanced_service_identification': True,
            'concurrent_scanning': True
        }
    })

@app.route('/api/trigger-daily-check', methods=['POST'])
def api_trigger_daily_check():
    """Manually trigger daily comprehensive abuse check"""
    client_ip = get_client_ip()
    allowed_ips = ALLOWED_IPS + TEMPORARY_WHITELIST
    
    if client_ip not in allowed_ips and client_ip not in ['127.0.0.1', 'localhost', '::1']:
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        # Send Discord notification about manual trigger
        send_discord_webhook(
            f"🚀 **Manual Enhanced Daily Check Triggered**\n\n**Triggered by:** `{client_ip}`\n**Time:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n**Sources:** All 7 databases + Enhanced service detection\n**Features:** RDP, SSH, HTTP/S, SMB detection\n**Status:** Starting...",
            color=0x0099ff,
            title="Manual Enhanced Check Started"
        )
        
        # Run in background thread to avoid timeout
        threading.Thread(target=daily_abuse_check, daemon=True).start()
        return jsonify({'message': 'Enhanced daily check started in background'})
    except Exception as e:
        return jsonify({'error': f'Failed to start daily check: {str(e)}'}), 500

@app.route('/api/discord/test', methods=['POST'])
def api_test_discord():
    """Test Discord webhook"""
    client_ip = get_client_ip()
    allowed_ips = ALLOWED_IPS + TEMPORARY_WHITELIST
    
    if client_ip not in allowed_ips and client_ip not in ['127.0.0.1', 'localhost', '::1']:
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        send_discord_webhook(
            f"🧪 **Enhanced Discord Webhook Test**\n\n**Tested by:** `{client_ip}`\n**Time:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n**System:** Enhanced IP Abuse Monitoring\n**Sources:** AbuseIPDB, VirusTotal, IPVoid, GreyNoise, Spamhaus, SURBL, Barracuda\n**Enhanced Features:** ✅ RDP Detection, ✅ SSH Detection, ✅ Comprehensive Port Scanning\n**Status:** Working correctly! ✅",
            color=0x0099ff,
            title="Enhanced Test Message"
        )
        return jsonify({'message': 'Enhanced Discord test message sent successfully'})
    except Exception as e:
        return jsonify({'error': f'Discord test failed: {str(e)}'}), 500

# Cache dashboard stats for 5 minutes
@lru_cache(maxsize=1)
def get_cached_dashboard_stats(cache_key):
    """Get dashboard stats with caching"""
    def _get_actual_dashboard_stats():
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            today = datetime.now().date()
            
            # Get basic stats
            cursor.execute('''
                SELECT 
                    COUNT(*) as total_checked,
                    COUNT(CASE WHEN abuse_confidence = 0 THEN 1 END) as clean,
                    COUNT(CASE WHEN abuse_confidence > 0 AND abuse_confidence < 75 THEN 1 END) as suspicious,
                    COUNT(CASE WHEN abuse_confidence >= 75 THEN 1 END) as high_risk,
                    AVG(COALESCE(sources_checked, 0)) as avg_sources,
                    SUM(COALESCE(sources_detected, 0)) as total_detections
                FROM abuse_reports
                WHERE check_date = ?
            ''', (today,))
            
            today_stats = cursor.fetchone()
            
            return {
                'today_stats': {
                    'total_checked': today_stats[0] or 0,
                    'clean': today_stats[1] or 0,
                    'suspicious': today_stats[2] or 0,
                    'high_risk': today_stats[3] or 0,
                    'avg_sources': round(today_stats[4] or 0, 1),
                    'total_detections': today_stats[5] or 0
                },
                'weekly_trend': [],
                'recent_alerts': []
            }
    
    return retry_db_operation(_get_actual_dashboard_stats)

@app.route('/api/dashboard-stats-cached')
def api_dashboard_stats_cached():
    """Cached version of dashboard stats"""
    try:
        # Use timestamp rounded to 5 minutes as cache key
        cache_key = int(time.time() // 300)
        stats = get_cached_dashboard_stats(cache_key)
        stats['cached'] = True
        stats['cache_key'] = cache_key
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Cached dashboard stats error: {e}")
        return jsonify(get_fallback_stats()), 500

@app.route('/api/backup-database', methods=['POST'])
def api_backup_database():
    """Create manual database backup"""
    client_ip = get_client_ip()
    allowed_ips = ALLOWED_IPS + TEMPORARY_WHITELIST
    
    if client_ip not in allowed_ips and client_ip not in ['127.0.0.1', 'localhost', '::1']:
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        backup_path = backup_database()
        if backup_path:
            return jsonify({
                'success': True,
                'backup_path': backup_path,
                'message': f'Database backup created: {backup_path}'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Backup failed - check logs for details'
            }), 500
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Backup operation failed: {str(e)}'
        }), 500

@app.route('/api/remove-ip-from-monitoring', methods=['POST'])
def api_remove_ip_from_monitoring():
    """Remove IP from daily monitoring list"""
    data = request.get_json()
    
    if not data or 'ip' not in data:
        return jsonify({'error': 'No IP address provided'}), 400
    
    ip = data['ip'].strip()
    
    if not validate_ip(ip):
        return jsonify({'error': 'Invalid IP address'}), 400
    
    def _remove_ip():
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Set is_active to 0 instead of deleting
            cursor.execute('''
                UPDATE ip_list 
                SET is_active = 0 
                WHERE ip_address = ?
            ''', (ip,))
            
            rows_affected = cursor.rowcount
            conn.commit()
            
            return rows_affected > 0
    
    try:
        removed = retry_db_operation(_remove_ip)
        
        if removed:
            # Send Discord notification
            send_discord_webhook(
                f"➖ **IP Removed from Enhanced Monitoring**\n\n**IP:** `{ip}`\n**Status:** Deactivated\n**Enhanced Features:** RDP, SSH, HTTP/S detection disabled\n**Time:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                color=0xff9900,
                title="Monitoring List Updated"
            )
            
            return jsonify({'message': f'IP {ip} removed from monitoring list'})
        else:
            return jsonify({'error': f'IP {ip} not found in monitoring list'}), 404
        
    except Exception as e:
        return jsonify({'error': f'Database error: {str(e)}'}), 500

@app.route('/api/bulk-add-ips', methods=['POST'])
def api_bulk_add_ips():
    """Add multiple IPs to monitoring list"""
    data = request.get_json()
    
    if not data or 'ips' not in data:
        return jsonify({'error': 'No IP addresses provided'}), 400
    
    ips = data['ips']
    notes = data.get('notes', '')
    
    if not isinstance(ips, list):
        return jsonify({'error': 'IPs must be provided as a list'}), 400
    
    # Validate all IPs first
    valid_ips = []
    invalid_ips = []
    
    for ip in ips:
        ip = ip.strip()
        if validate_ip(ip):
            valid_ips.append(ip)
        else:
            invalid_ips.append(ip)
    
    if not valid_ips:
        return jsonify({'error': 'No valid IP addresses provided'}), 400
    
    def _bulk_add():
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            added_count = 0
            for ip in valid_ips:
                try:
                    cursor.execute('''
                        INSERT OR REPLACE INTO ip_list (ip_address, notes, is_active)
                        VALUES (?, ?, 1)
                    ''', (ip, notes))
                    added_count += 1
                except Exception as e:
                    logger.error(f"Error adding IP {ip}: {e}")
            
            conn.commit()
            return added_count
    
    try:
        added_count = retry_db_operation(_bulk_add)
        
        # Send Discord notification
        send_discord_webhook(
            f"📋 **Bulk IPs Added to Enhanced Monitoring**\n\n**Valid IPs Added:** {added_count}\n**Invalid IPs:** {len(invalid_ips)}\n**Notes:** {notes if notes else 'None'}\n**Enhanced Features:** RDP, SSH, HTTP/S, SMB detection enabled\n**Time:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            color=0x00ff00,
            title="Bulk Enhanced Monitoring Update"
        )
        
        return jsonify({
            'message': f'Added {added_count} IPs to enhanced monitoring list',
            'added_count': added_count,
            'valid_ips': valid_ips,
            'invalid_ips': invalid_ips
        })
        
    except Exception as e:
        return jsonify({'error': f'Database error: {str(e)}'}), 500

@app.route('/api/export-data', methods=['GET'])
def api_export_data():
    """Export monitoring data as JSON"""
    try:
        def _export_data():
            with get_db_connection() as conn:
                cursor = conn.cursor()
                
                # Get monitoring list
                cursor.execute('''
                    SELECT ip_address, added_date, is_active, notes
                    FROM ip_list
                    ORDER BY added_date DESC
                ''')
                monitoring_list = cursor.fetchall()
                
                # Get recent abuse reports
                cursor.execute('''
                    SELECT ip_address, check_date, abuse_confidence, total_reports, 
                           country_code, isp, sources_checked, sources_detected
                    FROM abuse_reports
                    WHERE check_date >= date('now', '-30 days')
                    ORDER BY check_date DESC
                ''')
                abuse_reports = cursor.fetchall()
                
                # Get recent alerts
                cursor.execute('''
                    SELECT ip_address, alert_type, message, abuse_confidence, 
                           sources_detected, created_at
                    FROM alert_history
                    WHERE created_at >= datetime('now', '-30 days')
                    ORDER BY created_at DESC
                ''')
                alerts = cursor.fetchall()
                
                return {
                    'monitoring_list': [
                        {
                            'ip': row[0],
                            'added_date': row[1],
                            'is_active': bool(row[2]),
                            'notes': row[3] or ''
                        } for row in monitoring_list
                    ],
                    'abuse_reports': [
                        {
                            'ip': row[0],
                            'check_date': row[1],
                            'abuse_confidence': row[2],
                            'total_reports': row[3],
                            'country_code': row[4],
                            'isp': row[5],
                            'sources_checked': row[6] or 0,
                            'sources_detected': row[7] or 0
                        } for row in abuse_reports
                    ],
                    'alerts': [
                        {
                            'ip': row[0],
                            'alert_type': row[1],
                            'message': row[2],
                            'abuse_confidence': row[3],
                            'sources_detected': row[4],
                            'created_at': row[5]
                        } for row in alerts
                    ]
                }
        
        export_data = retry_db_operation(_export_data)
        export_data['export_date'] = datetime.now().isoformat()
        export_data['total_monitoring'] = len(export_data['monitoring_list'])
        export_data['total_reports'] = len(export_data['abuse_reports'])
        export_data['total_alerts'] = len(export_data['alerts'])
        export_data['enhanced_features'] = ['RDP Detection', 'SSH Detection', 'Comprehensive Port Scanning', 'Service Identification']
        
        return jsonify(export_data)
        
    except Exception as e:
        return jsonify({'error': f'Export failed: {str(e)}'}), 500

@app.route('/api/stats-summary')
def api_stats_summary():
    """Get comprehensive stats summary"""
    try:
        def _get_summary():
            with get_db_connection() as conn:
                cursor = conn.cursor()
                
                # Overall statistics
                cursor.execute('SELECT COUNT(*) FROM ip_list WHERE is_active = 1')
                active_monitored = cursor.fetchone()[0]
                
                cursor.execute('SELECT COUNT(*) FROM abuse_reports')
                total_checks = cursor.fetchone()[0]
                
                cursor.execute('SELECT COUNT(*) FROM alert_history')
                total_alerts = cursor.fetchone()[0]
                
                # Recent activity (last 7 days)
                cursor.execute('''
                    SELECT COUNT(*) FROM abuse_reports 
                    WHERE check_date >= date('now', '-7 days')
                ''')
                recent_checks = cursor.fetchone()[0]
                
                cursor.execute('''
                    SELECT COUNT(*) FROM alert_history 
                    WHERE created_at >= datetime('now', '-7 days')
                ''')
                recent_alerts = cursor.fetchone()[0]
                
                # Risk distribution (last 30 days)
                cursor.execute('''
                    SELECT 
                        COUNT(CASE WHEN abuse_confidence = 0 THEN 1 END) as clean,
                        COUNT(CASE WHEN abuse_confidence BETWEEN 1 AND 24 THEN 1 END) as low_risk,
                        COUNT(CASE WHEN abuse_confidence BETWEEN 25 AND 74 THEN 1 END) as suspicious,
                        COUNT(CASE WHEN abuse_confidence >= 75 THEN 1 END) as high_risk
                    FROM abuse_reports
                    WHERE check_date >= date('now', '-30 days')
                ''')
                risk_dist = cursor.fetchone()
                
                # Top countries (last 30 days)
                cursor.execute('''
                    SELECT country_code, COUNT(*) as count
                    FROM abuse_reports
                    WHERE check_date >= date('now', '-30 days') 
                      AND country_code IS NOT NULL 
                      AND country_code != ''
                    GROUP BY country_code
                    ORDER BY count DESC
                    LIMIT 5
                ''')
                top_countries = cursor.fetchall()
                
                # Average sources per check (last 30 days)
                cursor.execute('''
                    SELECT AVG(COALESCE(sources_checked, 0)) as avg_sources
                    FROM abuse_reports
                    WHERE check_date >= date('now', '-30 days')
                ''')
                avg_sources = cursor.fetchone()[0] or 0
                
                return {
                    'monitoring': {
                        'active_ips': active_monitored,
                        'total_checks_all_time': total_checks,
                        'total_alerts_all_time': total_alerts
                    },
                    'recent_activity': {
                        'checks_last_7_days': recent_checks,
                        'alerts_last_7_days': recent_alerts
                    },
                    'risk_distribution_30_days': {
                        'clean': risk_dist[0] or 0,
                        'low_risk': risk_dist[1] or 0,
                        'suspicious': risk_dist[2] or 0,
                        'high_risk': risk_dist[3] or 0
                    },
                    'top_countries_30_days': [
                        {'country': row[0], 'count': row[1]} 
                        for row in top_countries
                    ],
                    'performance': {
                        'avg_sources_per_check': round(avg_sources, 1)
                    },
                    'enhanced_features': {
                        'rdp_detection': True,
                        'ssh_detection': True,
                        'comprehensive_port_scanning': True,
                        'concurrent_processing': True
                    }
                }
        
        summary = retry_db_operation(_get_summary)
        return jsonify(summary)
        
    except Exception as e:
        return jsonify({'error': f'Stats summary failed: {str(e)}'}), 500

@app.route('/')
def index():
    """Main page"""
    return render_template('index.html')

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

@app.errorhandler(403)
def forbidden(error):
    return jsonify({'error': 'Access forbidden'}), 403

# Application startup and configuration
if __name__ == '__main__':
    print("🛡️  Enhanced Flask IP Abuse Checker Starting...")
    print(f"🔒 IP Lock: {'ENABLED' if IP_LOCK_ENABLED else 'DISABLED'}")
    if IP_LOCK_ENABLED:
        print(f"✅ Allowed IPs: {', '.join(ALLOWED_IPS) if ALLOWED_IPS else 'None (localhost only)'}")
    else:
        print("⚠️  WARNING: No IP restrictions - accessible from any IP!")
    
    print(f"📊 Daily Monitoring: {'ENABLED' if DAILY_CHECK_ENABLED else 'DISABLED'}")
    print(f"🎯 Discord Webhooks: {'ENABLED' if DISCORD_ENABLED else 'DISABLED'}")
    
    # Show API configuration status
    print("\n📡 Abuse Database Sources:")
    print(f"  • AbuseIPDB: {'✅ Configured' if ABUSEIPDB_API_KEY != 'your-api-key-here' else '❌ No API Key'}")
    print(f"  • VirusTotal: {'✅ Configured' if VIRUSTOTAL_API_KEY != 'your-vt-api-key-here' else '❌ No API Key'}")
    print(f"  • IPVoid: {'✅ Configured' if IPVOID_API_KEY != 'your-ipvoid-api-key-here' else '❌ No API Key'}")
    print(f"  • GreyNoise: {'✅ Configured' if GREYNOISE_API_KEY != 'your-greynoise-api-key-here' else '❌ No API Key'}")
    print(f"  • Spamhaus: ✅ DNS-based (always available)")
    print(f"  • SURBL: ✅ DNS-based (always available)")
    print(f"  • Barracuda: ✅ DNS-based (always available)")
    
    print("\n🔧 ENHANCED CONNECTIVITY FEATURES:")
    print("  • 🖥️  RDP Detection (Port 3389) - ENABLED")
    print("  • 🔐 SSH Detection (Port 22) - ENABLED") 
    print("  • 🌐 HTTP/HTTPS Detection (Ports 80/443) - ENABLED")
    print("  • 📁 SMB Detection (Port 445) - ENABLED")
    print("  • 📧 Email Services (SMTP/IMAP/POP3) - ENABLED")
    print("  • 🗄️  Database Services (MySQL/PostgreSQL) - ENABLED")
    print("  • ⚡ Concurrent Port Scanning - ENABLED")
    print("  • 🎯 Enhanced Service Identification - ENABLED")
    print("  • 📊 15+ Port Service Detection - ENABLED")
    
    if ALERT_EMAIL:
        print(f"📧 Alerts: {ALERT_EMAIL}")
    else:
        print("📧 Email alerts: Not configured")
    
    # Initialize database
    init_database()
    
    # Schedule daily checks if enabled
    if DAILY_CHECK_ENABLED:
        # Schedule daily check at 2 AM
        scheduler.add_job(
            daily_abuse_check,
            CronTrigger(hour=2, minute=0),
            id='daily_abuse_check',
            replace_existing=True
        )
        print("⏰ Scheduled comprehensive daily abuse checks at 2:00 AM")
        
        # Also add hourly light checks during business hours
        scheduler.add_job(
            daily_abuse_check,
            CronTrigger(hour='9-17', minute=0),
            id='hourly_light_check',
            replace_existing=True
        )
        print("⏰ Scheduled hourly comprehensive checks during business hours (9 AM - 5 PM)")
        
        # Schedule automatic backups
        scheduler.add_job(
            backup_database,
            CronTrigger(hour=1, minute=0),  # Daily at 1 AM
            id='daily_backup',
            replace_existing=True
        )
        print("⏰ Scheduled daily database backups at 1:00 AM")
    
    print("🌐 Starting server on http://0.0.0.0:5000")
    print("🗄️  Database: abuse_reports.db")
    print("🔗 Discord: Webhook configured")
    print("🚀 Multi-source abuse checking + Enhanced connectivity detection enabled")
    print("\n🆕 NEW ENHANCED FEATURES:")
    print("  • 🖥️  Windows RDP Server Detection")
    print("  • 🔐 Linux SSH Server Detection")
    print("  • 📊 Comprehensive Port Scanning (15+ ports)")
    print("  • ⚡ Concurrent Connection Testing")
    print("  • 🎯 Smart Service Identification")
    print("  • 📈 Enhanced Discord Notifications")
    print("  • 🔧 Dual Detection Method (Ping + TCP)")
    print("  • ⏱️  Response Time Measurement")
    print("\n📋 Available API Endpoints:")
    print("  • /api/live-status - Enhanced RDP/SSH/service detection")
    print("  • /api/live-status-batch - Batch enhanced connectivity check")
    print("  • /api/dashboard-stats - Fixed dashboard statistics")
    print("  • /api/diagnose-db - Database diagnostic tools")
    print("  • /api/repair-database - Auto-repair database schema")
    print("  • /api/database-health - Check database integrity")
    print("  • /api/system-health - Overall system status")
    print("  • /api/backup-database - Manual database backup")
    print("  • /api/bulk-add-ips - Add multiple IPs at once")
    print("  • /api/export-data - Export all monitoring data")
    print("  • /api/stats-summary - Comprehensive statistics")
    print("-" * 70)
    print("🎯 KEY IMPROVEMENT: Your RDP servers will now be detected as ONLINE!")
    print("🔍 Scanning for: RDP (3389), SSH (22), HTTP (80/443), SMB (445), and more")
    print("⚡ Performance: Concurrent scanning with intelligent timeouts")
    print("-" * 70)
    
    # Start the Flask application
    app.run(debug=True, host='0.0.0.0', port=5000)
