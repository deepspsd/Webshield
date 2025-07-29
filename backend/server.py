from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, Form, UploadFile, File, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader
from fastapi.responses import FileResponse, HTMLResponse
import mysql.connector
from mysql.connector import Error
from pydantic import BaseModel
from datetime import datetime
from dotenv import load_dotenv
import os
import asyncio
import aiohttp
import ssl
import socket
import re
import urllib.parse
import hashlib
import json
import base64
from typing import Optional, List, Dict, Any
import logging
import time
from uuid import uuid4
from passlib.hash import bcrypt
from fastapi import Request
# Jinja2 Template import moved to top of file

from fastapi.middleware.gzip import GZipMiddleware
from functools import lru_cache
from threading import Thread

# Import ML modules
import sys
sys.path.append('ml_models')
from ml_integration import get_ml_engine, integrate_ml_with_scan

load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="WebShield API", description="Real-time Fake Website & Malware Detection", version="1.0.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)

app.add_middleware(GZipMiddleware, minimum_size=1000)

def generate_scan_id():
    return str(uuid4())
# Serve the frontend index.html at root
@app.get("/", response_class=HTMLResponse)
async def serve_index():
    try:
        with open("frontend/index.html", "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        return HTMLResponse(content="<h1>WebShield Frontend Not Found</h1><p>Please ensure frontend/index.html exists.</p>", status_code=404)

    
# Removed duplicate route - keeping the more comprehensive one below

@app.get("/dashboard.html", response_class=HTMLResponse)
async def serve_dashboard_page():
    try:
        with open("frontend/dashboard.html", "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        return HTMLResponse(content="<h1>Dashboard Page Not Found</h1>", status_code=404)

@app.get("/how-to-install.html", response_class=HTMLResponse)
async def serve_how_to_install_page():
    try:
        with open("frontend/how-to-install.html", "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        return HTMLResponse(content="<h1>How to Install Page Not Found</h1>", status_code=404)

@app.get("/login.html", response_class=HTMLResponse)
async def serve_login_page():
    try:
        with open("frontend/login.html", "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        return HTMLResponse(content="<h1>Login Page Not Found</h1>", status_code=404)

@app.get("/register.html", response_class=HTMLResponse)

async def serve_register_page():
    try:
        with open("frontend/register.html", "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        return HTMLResponse(content="<h1>Register Page Not Found</h1>", status_code=404)


@app.get("/profile.html", response_class=HTMLResponse)
async def serve_profile():
    try:
        with open("frontend/profile.html", "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        return HTMLResponse(content="<h1>Profile Page Not Found</h1>", status_code=404)

@app.get("/debug_navigation.html", response_class=HTMLResponse)
async def serve_debug_navigation():
    try:
        with open("frontend/debug_navigation.html", "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        return HTMLResponse(content="<h1>Debug Navigation Page Not Found</h1>", status_code=404)

@app.get("/test_navigation.html", response_class=HTMLResponse)
async def serve_test_navigation():
    try:
        with open("frontend/test_navigation.html", "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        return HTMLResponse(content="<h1>Test Navigation Page Not Found</h1>", status_code=404)



@app.get("/scan_id.html", response_class=HTMLResponse)
async def serve_scan_id():
    try:
        with open("frontend/scan_id.html", "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        return HTMLResponse(content="<h1>Scan ID Page Not Found</h1><p>Please ensure frontend/scan_id.html exists.</p>", status_code=404)

# Serve scan_report.html
from jinja2 import Template

@app.get("/scan_report.html", response_class=HTMLResponse)
async def serve_scan_report(scan_id: str = None):
    """Serve scan report page with scan data"""
    try:
        # Read the template
        with open("frontend/scan_report.html", "r", encoding="utf-8") as f:
            template_content = f.read()
        
        # If no scan_id provided, return the template as-is (for JavaScript to handle)
        if not scan_id:
            return HTMLResponse(content=template_content)
            
        # Get scan data from database
        conn = get_mysql_connection()
        if conn:
            cursor = conn.cursor(dictionary=True)
            select_query = """
            SELECT scan_id, url, status, is_malicious, threat_level, malicious_count,
                   suspicious_count, total_engines, ssl_valid, domain_reputation,
                   detection_details, created_at, completed_at, scan_timestamp
            FROM scans WHERE scan_id = %s
            """
            cursor.execute(select_query, (scan_id,))
            scan = cursor.fetchone()
            cursor.close()
            
            if scan and scan['status'] == 'completed':
                # Convert detection_details from JSON string to dict
                if scan['detection_details']:
                    scan['detection_details'] = json.loads(scan['detection_details'])
                
                # Create ScanResult object for template
                result = ScanResult(
                    url=scan['url'],
                    is_malicious=scan.get('is_malicious', False),
                    threat_level=scan.get('threat_level', 'low'),
                    malicious_count=scan.get('malicious_count', 0),
                    suspicious_count=scan.get('suspicious_count', 0),
                    total_engines=scan.get('total_engines', 0),
                    detection_details=scan['detection_details'] if scan['detection_details'] else {},
                    ssl_valid=scan.get('ssl_valid', False),
                    domain_reputation=scan.get('domain_reputation', 'unknown'),
                    content_analysis=scan['detection_details'].get('content_analysis', {}) if scan['detection_details'] else {},
                    scan_timestamp=scan.get('scan_timestamp') or scan.get('completed_at')
                )
                
                # Render template with data
                template = Template(template_content)
                rendered_html = template.render(result=result)
                return HTMLResponse(content=rendered_html)
            else:
                # Scan not found or not completed, return template for JavaScript to handle
                return HTMLResponse(content=template_content)
        else:
            return HTMLResponse(content=template_content)
            
    except FileNotFoundError:
        return HTMLResponse(content="<h1>Scan Report Page Not Found</h1><p>Please ensure frontend/scan_report.html exists.</p>", status_code=404)
    except Exception as e:
        logger.error(f"Error rendering scan report: {e}")
        return HTMLResponse(content=f"<h1>Error Loading Scan Report</h1><p>{str(e)}</p>", status_code=500)

@app.get("/api/migrate-database")
async def migrate_database():
    """Manually run database migration"""
    try:
        conn = get_mysql_connection()
        if conn:
            cursor = conn.cursor()
            
            # Add user_email column to existing scans table if it doesn't exist
            try:
                cursor.execute("ALTER TABLE scans ADD COLUMN user_email VARCHAR(255)")
                conn.commit()
                logger.info("Successfully added user_email column to scans table")
                return {"success": True, "message": "Added user_email column"}
            except Error as e:
                if "Duplicate column name" in str(e):
                    logger.info("user_email column already exists in scans table")
                    return {"success": True, "message": "user_email column already exists"}
                else:
                    logger.error(f"Error adding user_email column: {e}")
                    return {"success": False, "error": str(e)}
            finally:
                cursor.close()
        else:
            return {"success": False, "error": "Database connection failed"}
    except Exception as e:
        return {"success": False, "error": str(e)}

@app.get("/api/debug/scan/{scan_id}")
async def debug_scan_result(scan_id: str):
    """Debug endpoint to check scan status"""
    try:
        conn = get_mysql_connection()
        if conn:
            cursor = conn.cursor(dictionary=True)
            
            # First, let's check what database we're connected to
            cursor.execute("SELECT DATABASE() as current_db")
            db_info = cursor.fetchone()
            
            # Check if the scans table exists
            cursor.execute("SHOW TABLES LIKE 'scans'")
            table_exists = cursor.fetchone()
            
            # Get all scans to see what's in the database
            cursor.execute("SELECT scan_id, url, status, created_at FROM scans ORDER BY created_at DESC LIMIT 5")
            all_scans = cursor.fetchall()
            
            # Now check for the specific scan
            select_query = """
            SELECT scan_id, url, status, is_malicious, threat_level, malicious_count,
                   suspicious_count, total_engines, ssl_valid, domain_reputation,
                   detection_details, created_at, completed_at, scan_timestamp, user_email
            FROM scans WHERE scan_id = %s
            """
            cursor.execute(select_query, (scan_id,))
            scan = cursor.fetchone()
            cursor.close()
            
            return {
                "found": scan is not None,
                "scan_id": scan_id,
                "database": db_info.get('current_db') if db_info else 'unknown',
                "table_exists": table_exists is not None,
                "all_scans": all_scans,
                "scan": scan,
                "message": "Scan not found in database" if scan is None else "Scan found"
            }
        else:
            return {
                "found": False,
                "error": "Database connection failed"
            }
    except Exception as e:
        return {
            "found": False,
            "error": str(e)
        }

load_dotenv()

# MySQL connection configuration
MYSQL_CONFIG = {
    'host': os.getenv('MYSQL_HOST', 'localhost'),
    'port': int(os.getenv('MYSQL_PORT', 3306)),
    'user': os.getenv('MYSQL_USER', 'root'),
    'password': os.getenv('MYSQL_PASSWORD', 'Deepak@1234'),
    'database': os.getenv('MYSQL_DATABASE', 'webshield'),
    'charset': 'utf8mb4',
    'autocommit': True,
    'use_unicode': True,
    'auth_plugin': 'mysql_native_password'
}

# Global database connection
mysql_connection = None

def create_database_and_tables():
    """Create database and tables if they don't exist"""
    try:
        # Connect without specifying database first
        config = MYSQL_CONFIG.copy()
        config['host'] = '127.0.0.1'
        del config['database']
        
        # Remove empty password to avoid authentication issues
        if not config['password']:
            del config['password']
        
        conn = mysql.connector.connect(**config)
        cursor = conn.cursor()
        
        # Create database if it doesn't exist
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {MYSQL_CONFIG['database']}")
        cursor.execute(f"USE {MYSQL_CONFIG['database']}")
        
        # Create users table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                email VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                name VARCHAR(255),
                profile_picture VARCHAR(255),
                email_notifications BOOLEAN DEFAULT TRUE,
                sms_notifications BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create scans table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INT AUTO_INCREMENT PRIMARY KEY,
                scan_id VARCHAR(255) UNIQUE NOT NULL,
                url TEXT NOT NULL,
                status ENUM('processing', 'completed', 'error') DEFAULT 'processing',
                is_malicious BOOLEAN DEFAULT FALSE,
                threat_level ENUM('low', 'medium', 'high') DEFAULT 'low',
                malicious_count INT DEFAULT 0,
                suspicious_count INT DEFAULT 0,
                total_engines INT DEFAULT 0,
                ssl_valid BOOLEAN DEFAULT FALSE,
                domain_reputation ENUM('clean', 'malicious', 'unknown') DEFAULT 'unknown',
                detection_details JSON,
                user_email VARCHAR(255),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP NULL,
                scan_timestamp TIMESTAMP NULL,
                INDEX idx_scan_id (scan_id),
                INDEX idx_user_email (user_email),
                INDEX idx_created_at (created_at)
            )
        """)
        
        # Add user_email column to existing scans table if it doesn't exist
        try:
            cursor.execute("ALTER TABLE scans ADD COLUMN user_email VARCHAR(255)")
            logger.info("Added user_email column to scans table")
        except Error as e:
            if "Duplicate column name" in str(e):
                logger.info("user_email column already exists in scans table")
            else:
                logger.error(f"Error adding user_email column: {e}")
        
        # Add indexes if they don't exist
        try:
            cursor.execute("CREATE INDEX idx_user_email ON scans(user_email)")
            logger.info("Added user_email index to scans table")
        except Error as e:
            if "Duplicate key name" in str(e):
                logger.info("user_email index already exists")
            else:
                logger.error(f"Error adding user_email index: {e}")
        
        conn.commit()
        cursor.close()
        conn.close()
        logger.info("Database and tables created successfully")
        
    except Error as e:
        logger.error(f"Failed to create database and tables: {e}")

def get_mysql_connection():
    """Get MySQL database connection"""
    global mysql_connection
    try:
        if mysql_connection is None or not mysql_connection.is_connected():
            # Try to connect with explicit TCP connection
            config = MYSQL_CONFIG.copy()
            if config['host'] == 'localhost':
                # Force TCP connection instead of named pipe on Windows
                config['host'] = '127.0.0.1'
            
            # Remove empty password to avoid authentication issues
            if not config['password']:
                del config['password']
            
            mysql_connection = mysql.connector.connect(**config)
            logger.info("Connected to MySQL successfully")
    except Error as e:
        logger.error(f"Failed to connect to MySQL: {e}")
        # Try alternative connection method
        try:
            config = MYSQL_CONFIG.copy()
            config['host'] = '127.0.0.1'
            config['port'] = 3306
            
            # Remove empty password to avoid authentication issues
            if not config['password']:
                del config['password']
            
            mysql_connection = mysql.connector.connect(**config)
            logger.info("Connected to MySQL using alternative method")
        except Error as e2:
            logger.error(f"Alternative MySQL connection also failed: {e2}")
            mysql_connection = None
    return mysql_connection

# VirusTotal API configuration
VT_API_KEY = os.getenv('VT_API_KEY')
VT_BASE_URL = "https://www.virustotal.com/api/v3"

# Data models
class URLScanRequest(BaseModel):
    url: str
    user_email: Optional[str] = None

class ScanResult(BaseModel):
    url: str
    is_malicious: bool
    threat_level: str  # 'low', 'medium', 'high'
    malicious_count: int
    suspicious_count: int
    total_engines: int
    detection_details: Dict[str, Any]
    ssl_valid: bool
    domain_reputation: str
    content_analysis: Dict[str, Any]
    scan_timestamp: datetime

class ThreatReport(BaseModel):
    scan_id: str
    url: str
    status: str
    results: Optional[ScanResult] = None

class RegisterRequest(BaseModel):
    email: str
    password: str
    name: str = ""

class LoginRequest(BaseModel):
    email: str
    password: str

class ReportRequest(BaseModel):
    url: str
    reason: Optional[str] = None
    added_by: Optional[str] = None

# Suspicious patterns for URL analysis
SUSPICIOUS_URL_PATTERNS = [
    r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',  # IP addresses
    r'[a-zA-Z0-9]+-[a-zA-Z0-9]+-[a-zA-Z0-9]+\.',  # Multiple hyphens
    r'[a-zA-Z0-9]{20,}',  # Very long domain names
    r'(bit\.ly|tinyurl|short|goo\.gl|t\.co)',  # URL shorteners
    r'(secure|login|bank|verify|update|confirm).*[0-9]+',  # Suspicious keywords with numbers
]

SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.info', '.click', '.download', '.stream']

PHISHING_KEYWORDS = {
    # Urgency / pressure
    'verify', 'suspend', 'suspended', 'limited', 'restriction', 'restricted',
    'confirm', 'update', 'unlock', 'locked', 'expire', 'expired', 'urgent',
    'immediately', 'immediate', 'alert',

    # High-value targets for spoofing
    'paypal', 'amazon', 'microsoft', 'outlook', 'google', 'gmail', 'apple',
    'icloud', 'netflix', 'ebay', 'wells fargo', 'bank of america', 'chase',
    'hsbc', 'citibank', 'usbank', 'barclays', 'lloyds', 'santander',

    # Common credential hooks
    'login', 'authentication', 'authenticate', 'password', 'credential'
}

class WebShieldDetector:
    def __init__(self):
        self.session = None
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    def analyze_url_patterns(self, url: str) -> Dict[str, Any]:
        """Analyze URL for suspicious patterns"""
        # Try ML analysis first
        try:
            ml_engine = get_ml_engine()
            ml_result = ml_engine.analyze_url_ml(url)
            
            if ml_result.get('ml_enabled', False):
                # Use ML results
                return {
                    'suspicious_score': int(ml_result['threat_probability'] * 100),
                    'detected_issues': ml_result.get('explanation', {}),
                    'domain': urllib.parse.urlparse(url).netloc.lower(),
                    'is_suspicious': ml_result['prediction'] == 1,
                    'ml_enabled': True,
                    'ml_confidence': ml_result['confidence'],
                    'ml_prediction': ml_result['prediction']
                }
        except Exception as ml_error:
            logger.warning(f"ML URL analysis failed, falling back to rule-based: {ml_error}")
        
        # Fallback to rule-based analysis
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.lower()
        
        suspicious_score = 0
        detected_issues = []
        
        # Check for IP address
        if re.match(r'^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$', domain):
            suspicious_score += 30
            detected_issues.append("Uses IP address instead of domain")
        
        # Check for suspicious patterns
        for pattern in SUSPICIOUS_URL_PATTERNS:
            if re.search(pattern, url):
                suspicious_score += 15
                detected_issues.append(f"Matches suspicious pattern: {pattern}")
        
        # Check for suspicious TLD
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                suspicious_score += 20
                detected_issues.append(f"Uses suspicious TLD: {tld}")
        
        # Check for excessive subdomains
        subdomain_count = len(domain.split('.')) - 2
        if subdomain_count > 3:
            suspicious_score += 10
            detected_issues.append(f"Excessive subdomains: {subdomain_count}")
        
        # Check for typosquatting patterns
        if self._check_typosquatting(domain):
            suspicious_score += 25
            detected_issues.append("Potential typosquatting detected")
        
        return {
            'suspicious_score': suspicious_score,
            'detected_issues': detected_issues,
            'domain': domain,
            'is_suspicious': suspicious_score > 20,
            'ml_enabled': False
        }
    
    def _check_typosquatting(self, domain: str) -> bool:
        """Check for common typosquatting patterns"""
        common_domains = [
            'google.com', 'facebook.com', 'amazon.com', 'microsoft.com',
            'apple.com', 'paypal.com', 'ebay.com', 'netflix.com'
        ]
        
        for legit_domain in common_domains:
            # Simple edit distance check
            if self._levenshtein_distance(domain, legit_domain) < 3 and domain != legit_domain:
                return True
        return False
    
    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """Calculate Levenshtein distance between two strings"""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        return previous_row[-1]
    
    async def analyze_ssl_certificate(self, url: str) -> Dict[str, Any]:
        """Analyze SSL certificate validity with improved error handling"""
        import ssl
        import socket
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        
        try:
            parsed = urllib.parse.urlparse(url)
            hostname = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            
            if parsed.scheme != 'https':
                return {
                    'valid': False,
                    'error': 'No HTTPS',
                    'details': 'Site does not use HTTPS encryption'
                }
            
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, port), timeout=5.0) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Try to get certificate in different ways
                    cert = ssock.getpeercert(binary_form=False)
                    if not cert:
                        # Fallback: try without binary_form parameter
                        cert = ssock.getpeercert()
                    
                    # Debug logging
                    import logging
                    logger = logging.getLogger("ssl")
                    logger.info(f"SSL Certificate for {hostname}: {cert}")
                    logger.info(f"Certificate type: {type(cert)}")
                    if cert:
                        logger.info(f"Certificate keys: {list(cert.keys())}")
                    
                    # Check if certificate is empty or None
                    if not cert:
                        # Try to get binary certificate and parse it
                        try:
                            cert_binary = ssock.getpeercert(binary_form=True)
                            if cert_binary:
                                # Parse the binary certificate
                                cert_obj = x509.load_der_x509_certificate(cert_binary, default_backend())
                                
                                # Extract issuer
                                issuer_name = cert_obj.issuer.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
                                issuer = issuer_name[0].value if issuer_name else "Unknown"
                                
                                # Extract expiry (use UTC to avoid deprecation warning)
                                expiry = cert_obj.not_valid_after_utc.strftime("%Y-%m-%d %H:%M:%S")
                                
                                return {
                                    'valid': True,
                                    'issuer': issuer,
                                    'expires': expiry,
                                    'serial_number': str(cert_obj.serial_number),
                                    'version': str(cert_obj.version.value)
                                }
                        except Exception as e:
                            logger.error(f"Failed to parse binary certificate: {e}")
                        
                        return {
                            'valid': False,
                            'error': 'No certificate data received',
                            'details': 'SSL handshake completed but no certificate information available'
                        }
                    
                    # Extract issuer information safely
                    issuer_info = {}
                    if 'issuer' in cert and cert['issuer']:
                        try:
                            # The issuer is a tuple of tuples, convert to dict properly
                            issuer_dict = {}
                            for item in cert['issuer']:
                                if len(item) >= 2:
                                    issuer_dict[item[0]] = item[1]
                            issuer_info = issuer_dict
                        except (KeyError, IndexError, TypeError):
                            issuer_info = {'commonName': 'Unknown'}
                    
                    # Extract subject information safely
                    subject_info = {}
                    if 'subject' in cert and cert['subject']:
                        try:
                            # The subject is a tuple of tuples, convert to dict properly
                            subject_dict = {}
                            for item in cert['subject']:
                                if len(item) >= 2:
                                    subject_dict[item[0]] = item[1]
                            subject_info = subject_dict
                        except (KeyError, IndexError, TypeError):
                            subject_info = {'commonName': hostname}
                    
                    # Format issuer name for display (string format for frontend)
                    issuer_name = 'Unknown'
                    if issuer_info:
                        if 'organizationName' in issuer_info:
                            issuer_name = issuer_info['organizationName']
                        elif 'commonName' in issuer_info:
                            issuer_name = issuer_info['commonName']
                        elif 'organizationalUnitName' in issuer_info:
                            issuer_name = issuer_info['organizationalUnitName']
                        elif 'countryName' in issuer_info:
                            issuer_name = f"CA ({issuer_info['countryName']})"
                    
                    # Format expiry date
                    expiry_date = 'Unknown'
                    if 'notAfter' in cert and cert['notAfter']:
                        try:
                            # Parse the date string and format it nicely
                            from datetime import datetime
                            expiry_str = cert['notAfter']
                            # Handle different date formats
                            if 'GMT' in expiry_str:
                                expiry_date = expiry_str.replace('GMT', '').strip()
                            else:
                                expiry_date = expiry_str
                        except:
                            expiry_date = cert['notAfter']
                    
                    return {
                        'valid': True,
                        'issuer': issuer_name,  # String format for frontend
                        'issuer_details': issuer_info,  # Keep full details
                        'subject': subject_info,
                        'expires': expiry_date,
                        'serial_number': cert.get('serialNumber', 'Unknown'),
                        'version': cert.get('version', 'Unknown')
                    }
        except socket.gaierror as e:
            return {
                'valid': False,
                'error': f'DNS resolution failed: {str(e)}',
                'details': 'Could not resolve domain name'
            }
        except socket.timeout as e:
            return {
                'valid': False,
                'error': f'Connection timeout: {str(e)}',
                'details': 'SSL connection timed out'
            }
        except ssl.SSLError as e:
            return {
                'valid': False,
                'error': f'SSL error: {str(e)}',
                'details': 'SSL certificate validation failed'
            }
        except Exception as e:
            return {
                'valid': False,
                'error': f'Connection error: {str(e)}',
                'details': 'SSL certificate validation failed'
            }
    
    async def analyze_content(self, url: str, max_bytes=200*1024) -> Dict[str, Any]:
        """Analyze webpage content for phishing indicators"""
        try:
            # Create a separate session for content analysis that bypasses SSL verification
            # This allows us to analyze content even from sites with expired/invalid certificates
            connector = aiohttp.TCPConnector(ssl=False)
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
            }
            async with aiohttp.ClientSession(connector=connector, headers=headers) as content_session:
                async with content_session.get(url, timeout=3.0) as response:
                    if response.status != 200:
                        error_msg = f'HTTP {response.status}'
                        if response.status == 403:
                            error_msg = 'Access forbidden (site may block automated requests)'
                        elif response.status == 404:
                            error_msg = 'Page not found'
                        elif response.status == 429:
                            error_msg = 'Too many requests (rate limited)'
                        elif response.status >= 500:
                            error_msg = f'Server error (HTTP {response.status})'
                        
                        return {
                            'error': error_msg, 
                            'phishing_score': 0,
                            'detected_indicators': [],
                            'is_suspicious': False,
                            'content_length': 0
                        }
                    
                    content = await response.content.read(max_bytes)
                    content = content.decode(errors='ignore')
                    
                    # Try ML analysis first
                    try:
                        ml_engine = get_ml_engine()
                        ml_result = ml_engine.analyze_content_ml(content)
                        
                        if ml_result.get('ml_enabled', False):
                            # Use ML results
                            return {
                                'phishing_score': int(ml_result['phishing_probability'] * 100),
                                'detected_indicators': ml_result.get('explanation', {}),
                                'is_suspicious': ml_result['prediction'] == 1,
                                'content_length': len(content),
                                'ml_enabled': True,
                                'ml_confidence': ml_result['confidence'],
                                'ml_prediction': ml_result['prediction']
                            }
                    except Exception as ml_error:
                        logger.warning(f"ML content analysis failed, falling back to rule-based: {ml_error}")
                    
                    # Fallback to rule-based analysis
                    phishing_score = 0
                    detected_indicators = []
                    
                    # Check for phishing keywords
                    content_lower = content.lower()
                    for keyword in PHISHING_KEYWORDS:
                        if keyword in content_lower:
                            phishing_score += 5
                            detected_indicators.append(f"Phishing keyword: {keyword}")
                    
                    # Check for suspicious forms
                    if re.search(r'<form[^>]*action\s*=\s*["\']?(?:https?://)?[^/"\']*["\']?', content):
                        if 'password' in content_lower or 'login' in content_lower:
                            phishing_score += 15
                            detected_indicators.append("Suspicious login form detected")
                    
                    # Check for fake security badges
                    if re.search(r'(norton|mcafee|verisign|ssl|secure)', content_lower):
                        phishing_score += 10
                        detected_indicators.append("Fake security badges detected")
                    
                    # Check for urgency indicators
                    urgency_patterns = [
                        r'act\s+now', r'urgent', r'immediate', r'expires?\s+(today|soon)',
                        r'limited\s+time', r'act\s+fast', r'don\'t\s+miss'
                    ]
                    
                    for pattern in urgency_patterns:
                        if re.search(pattern, content_lower):
                            phishing_score += 8
                            detected_indicators.append(f"Urgency indicator: {pattern}")
                    
                    return {
                        'phishing_score': phishing_score,
                        'detected_indicators': detected_indicators,
                        'is_suspicious': phishing_score > 20,
                        'content_length': len(content),
                        'ml_enabled': False
                    }
        except asyncio.TimeoutError:
            return {
                'error': 'Content analysis timed out',
                'phishing_score': 0,
                'detected_indicators': [],
                'is_suspicious': False,
                'content_length': 0
            }
        except Exception as e:
            logger.error(f"Content analysis failed for {url}: {str(e)}")
            return {
                'error': f'Content analysis failed: {str(e)}',
                'phishing_score': 0,
                'detected_indicators': [],
                'is_suspicious': False,
                'content_length': 0
            }
    
    async def check_virustotal(self, url: str) -> Dict[str, Any]:
        """Check URL against VirusTotal API with improved error handling"""
        # Check if VirusTotal API key is configured
        if not VT_API_KEY or VT_API_KEY == 'your_virustotal_api_key_here':
            return {'error': 'VirusTotal API key not configured. Using other security checks.'}
        
        try:
            # URL encode the URL for VirusTotal
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
            
            headers = {
                'x-apikey': VT_API_KEY,
                'Content-Type': 'application/json'
            }
            
            # Check if URL already exists in VirusTotal with shorter timeout
            check_url = f"{VT_BASE_URL}/urls/{url_id}"
            
            async with self.session.get(check_url, headers=headers, timeout=1.5) as response:
                if response.status == 200:
                    data = await response.json()
                    stats = data['data']['attributes']['last_analysis_stats']
                    
                    # Clean engines_results to ensure JSON serialization
                    engines_results = data['data']['attributes']['last_analysis_results']
                    cleaned_engines = {}
                    for engine, result in engines_results.items():
                        if isinstance(result, dict):
                            cleaned_result = {}
                            for key, value in result.items():
                                if isinstance(value, (str, int, float, bool)) or value is None:
                                    cleaned_result[key] = value
                            cleaned_engines[engine] = cleaned_result
                        else:
                            cleaned_engines[engine] = str(result) if result is not None else None
                    
                    return {
                        'malicious_count': stats.get('malicious', 0),
                        'suspicious_count': stats.get('suspicious', 0),
                        'harmless_count': stats.get('harmless', 0),
                        'undetected_count': stats.get('undetected', 0),
                        'total_engines': sum(stats.values()),
                        'engines_results': cleaned_engines,
                        'reputation': data['data']['attributes'].get('reputation', 0),
                        'cached': True
                    }
                elif response.status == 404:
                    # URL not found, submit for analysis
                    return await self._submit_url_to_virustotal(url)
                elif response.status == 429:
                    return {'error': 'VirusTotal rate limit exceeded. Using other security checks.'}
                elif response.status == 401:
                    return {'error': 'VirusTotal API key invalid. Using other security checks.'}
                else:
                    return {'error': f'VirusTotal API error: {response.status}. Using other security checks.'}
        except asyncio.TimeoutError:
            return {'error': 'VirusTotal request timed out. Using other security checks.'}
        except Exception as e:
            error_msg = str(e)
            # Clean up common serialization errors
            if 'Cannot serialize non-str key None' in error_msg:
                error_msg = 'VirusTotal API response contains invalid data. Using other security checks.'
            elif 'JSONDecodeError' in error_msg:
                error_msg = 'VirusTotal API returned invalid JSON. Using other security checks.'
            elif 'timeout' in error_msg.lower():
                error_msg = 'VirusTotal request timed out. Using other security checks.'
            else:
                error_msg = f'VirusTotal check failed: {error_msg}. Using other security checks.'
            return {'error': error_msg}
    
    async def _submit_url_to_virustotal(self, url: str) -> Dict[str, Any]:
        """Submit URL to VirusTotal for analysis with improved error handling"""
        try:
            headers = {
                'x-apikey': VT_API_KEY,
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            
            data = f'url={urllib.parse.quote(url)}'
            
            async with self.session.post(f"{VT_BASE_URL}/urls", 
                                       headers=headers, 
                                       data=data,
                                       timeout=2.0) as response:
                if response.status == 200:
                    result = await response.json()
                    analysis_id = result['data']['id']
                    
                    # Get results immediately (no sleep needed)
                    return await self._get_analysis_results(analysis_id)
                elif response.status == 429:
                    return {'error': 'VirusTotal rate limit exceeded. Using other security checks.'}
                elif response.status == 401:
                    return {'error': 'VirusTotal API key invalid. Using other security checks.'}
                else:
                    return {'error': f'URL submission failed: {response.status}. Using other security checks.'}
        except asyncio.TimeoutError:
            return {'error': 'VirusTotal submission timed out. Using other security checks.'}
        except Exception as e:
            error_msg = str(e)
            # Clean up common serialization errors
            if 'Cannot serialize non-str key None' in error_msg:
                error_msg = 'VirusTotal API response contains invalid data. Using other security checks.'
            elif 'JSONDecodeError' in error_msg:
                error_msg = 'VirusTotal API returned invalid JSON. Using other security checks.'
            elif 'timeout' in error_msg.lower():
                error_msg = 'VirusTotal request timed out. Using other security checks.'
            else:
                error_msg = f'URL submission error: {error_msg}. Using other security checks.'
            return {'error': error_msg}
    
    async def _get_analysis_results(self, analysis_id: str) -> Dict[str, Any]:
        """Get analysis results from VirusTotal with improved error handling"""
        try:
            headers = {'x-apikey': VT_API_KEY}
            
            async with self.session.get(f"{VT_BASE_URL}/analyses/{analysis_id}", 
                                      headers=headers,
                                      timeout=1.5) as response:
                if response.status == 200:
                    data = await response.json()
                    stats = data['data']['attributes']['stats']
                    
                    # Clean results to ensure JSON serialization
                    results = data['data']['attributes'].get('results', {})
                    cleaned_results = {}
                    for engine, result in results.items():
                        if isinstance(result, dict):
                            cleaned_result = {}
                            for key, value in result.items():
                                if isinstance(value, (str, int, float, bool)) or value is None:
                                    cleaned_result[key] = value
                            cleaned_results[engine] = cleaned_result
                        else:
                            cleaned_results[engine] = str(result) if result is not None else None
                    
                    return {
                        'malicious_count': stats.get('malicious', 0),
                        'suspicious_count': stats.get('suspicious', 0),
                        'harmless_count': stats.get('harmless', 0),
                        'undetected_count': stats.get('undetected', 0),
                        'total_engines': sum(stats.values()),
                        'engines_results': cleaned_results,
                        'status': data['data']['attributes']['status'],
                        'cached': False
                    }
                elif response.status == 429:
                    return {'error': 'VirusTotal rate limit exceeded. Using other security checks.'}
                elif response.status == 401:
                    return {'error': 'VirusTotal API key invalid. Using other security checks.'}
                else:
                    return {'error': f'Analysis retrieval failed: {response.status}. Using other security checks.'}
        except asyncio.TimeoutError:
            return {'error': 'VirusTotal analysis retrieval timed out. Using other security checks.'}
        except Exception as e:
            error_msg = str(e)
            # Clean up common serialization errors
            if 'Cannot serialize non-str key None' in error_msg:
                error_msg = 'VirusTotal API response contains invalid data. Using other security checks.'
            elif 'JSONDecodeError' in error_msg:
                error_msg = 'VirusTotal API returned invalid JSON. Using other security checks.'
            elif 'timeout' in error_msg.lower():
                error_msg = 'VirusTotal request timed out. Using other security checks.'
            else:
                error_msg = f'Analysis retrieval error: {error_msg}. Using other security checks.'
            return {'error': error_msg}

# Initialize detector
detector = WebShieldDetector()



# In-memory cache for scan results (simple dict with expiry)
SCAN_CACHE = {}
CACHE_TTL = 300  # 5 minutes (faster cache refresh)
SCAN_IN_PROGRESS = {}  # url: scan_id

def get_cached_scan(url):
    entry = SCAN_CACHE.get(url)
    if entry and time.time() - entry['ts'] < CACHE_TTL:
        return entry['result']
    return None

def set_cached_scan(url, result):
    SCAN_CACHE[url] = {'result': result, 'ts': time.time()}



@app.get("/api/get_user")
def get_user(email: str):
    conn = get_mysql_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database connection error")
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT email, name, profile_pic FROM users WHERE email = %s", (email,))
    user = cursor.fetchone()
    cursor.close()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@app.post("/api/register")
async def register_user(request: RegisterRequest):
    try:
        conn = get_mysql_connection()
        if not conn:
            raise HTTPException(status_code=500, detail="Database connection error")
        
        cursor = conn.cursor()
        
        # Check if user exists
        cursor.execute("SELECT id FROM users WHERE email = %s", (request.email,))
        if cursor.fetchone():
            cursor.close()
            conn.close()
            raise HTTPException(status_code=400, detail="Email already registered")
        
        # Hash password
        hashed_pw = bcrypt.hash(request.password)
        
        # Insert new user
        cursor.execute(
            "INSERT INTO users (email, password, name) VALUES (%s, %s, %s)",
            (request.email, hashed_pw, request.name)
        )
        conn.commit()
        cursor.close()
        conn.close()
        
        return {"success": True}
    except Exception as e:
        logger.error(f"Registration error: {e}")
        raise HTTPException(status_code=500, detail="Registration failed")

@app.post("/api/login")
def login_user(request: LoginRequest):
    try:
        conn = get_mysql_connection()
        if not conn:
            raise HTTPException(status_code=500, detail="Database connection error")
        
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE email = %s", (request.email,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if not user or not bcrypt.verify(request.password, user['password']):
            raise HTTPException(status_code=401, detail="Invalid email or password")
        
        return {"success": True, "name": user.get("name", ""), "email": user["email"]}
    except Exception as e:
        logger.error(f"Login error: {e}")
        raise HTTPException(status_code=500, detail="Login failed")

@app.post("/api/change_password")
def change_password(data: dict = Body(...)):
    email = data.get("email")
    old_password = data.get("old_password")
    new_password = data.get("new_password")
    if not email or not old_password or not new_password:
        raise HTTPException(status_code=400, detail="Missing required fields.")
    conn = get_mysql_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database connection error")
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT password FROM users WHERE email = %s", (email,))
    user = cursor.fetchone()
    if not user or not bcrypt.verify(old_password, user['password']):
        cursor.close()
        raise HTTPException(status_code=401, detail="Current password is incorrect.")
    hashed_pw = bcrypt.hash(new_password)
    cursor.execute("UPDATE users SET password = %s WHERE email = %s", (hashed_pw, email))
    conn.commit()
    cursor.close()
    return {"success": True}

@app.post("/api/update_profile")
def update_profile(data: dict = Body(...)):
    email = data.get("email")
    name = data.get("name")
    if not email or not name:
        raise HTTPException(status_code=400, detail="Missing required fields.")
    conn = get_mysql_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database connection error")
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET name = %s, email = %s WHERE email = %s", (name, email, email))
    conn.commit()
    cursor.close()
    return {"success": True}

@app.post("/api/notification_preferences")
def notification_preferences(data: dict = Body(...)):
    email = data.get("email")
    email_notifications = data.get("email_notifications", True)
    sms_notifications = data.get("sms_notifications", False)
    
    if not email:
        raise HTTPException(status_code=400, detail="Email is required")
    
    conn = get_mysql_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database connection error")
    
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE users SET 
        email_notifications = %s, 
        sms_notifications = %s 
        WHERE email = %s
    """, (email_notifications, sms_notifications, email))
    conn.commit()
    cursor.close()
    return {"success": True}

@app.post("/api/upload_profile_picture")
def upload_profile_picture(email: str = Form(...), file: UploadFile = File(...)):
    """Upload profile picture for user"""
    if not email:
        raise HTTPException(status_code=400, detail="Email is required")
    
    # Validate file type
    if not file.content_type.startswith('image/'):
        raise HTTPException(status_code=400, detail="File must be an image")
    
    # Create profile pictures directory
    profile_pics_dir = "profile_pics"
    os.makedirs(profile_pics_dir, exist_ok=True)
    
    # Generate filename
    file_extension = os.path.splitext(file.filename)[1]
    filename = f"{email.replace('@', '_at_')}{file_extension}"
    filepath = os.path.join(profile_pics_dir, filename)
    
    # Save file
    try:
        with open(filepath, "wb") as buffer:
            import shutil
            shutil.copyfileobj(file.file, buffer)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save file: {str(e)}")
    
    # Update database
    conn = get_mysql_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database connection error")
    
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET profile_picture = %s WHERE email = %s", (filename, email))
    conn.commit()
    cursor.close()
    
    return {"success": True, "filename": filename, "url": f"/profile_pics/{filename}"}

@app.get("/profile_pics/{filename}")
def get_profile_picture(filename: str):
    """Serve profile pictures"""
    filepath = os.path.join("profile_pics", filename)
    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail="Profile picture not found")
    return FileResponse(filepath)

@app.get("/config.js")
def serve_config_js():
    """Serve the config.js file"""
    try:
        with open("frontend/config.js", "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read(), media_type="application/javascript")
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Config file not found")

@app.delete("/api/remove_profile_picture")
def remove_profile_picture(data: dict = Body(...)):
    """Remove profile picture for user"""
    email = data.get("email")
    if not email:
        raise HTTPException(status_code=400, detail="Email is required")
    
    conn = get_mysql_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database connection error")
    
    # Get current profile picture
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT profile_picture FROM users WHERE email = %s", (email,))
    user = cursor.fetchone()
    
    if user and user['profile_picture']:
        # Delete file
        filepath = os.path.join("profile_pics", user['profile_picture'])
        if os.path.exists(filepath):
            os.remove(filepath)
        
        # Update database
        cursor.execute("UPDATE users SET profile_picture = NULL WHERE email = %s", (email,))
        conn.commit()
    
    cursor.close()
    return {"success": True}

@app.get("/api/user_scans")
def get_user_scans(email: str, limit: int = 20):
    """Get scan history for specific user"""
    if not email:
        raise HTTPException(status_code=400, detail="Email is required")
    
    conn = get_mysql_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database connection error")
    
    cursor = conn.cursor(dictionary=True)
    select_query = """
    SELECT scan_id, url, status, is_malicious, threat_level, malicious_count,
           suspicious_count, total_engines, created_at, completed_at
    FROM scans 
    WHERE user_email = %s
    ORDER BY created_at DESC 
    LIMIT %s
    """
    cursor.execute(select_query, (email, limit))
    scans = cursor.fetchall()
    cursor.close()
    
    # Format results for frontend
    formatted_scans = []
    for scan in scans:
        formatted_scan = dict(scan)
        if scan['status'] == 'completed':
            formatted_scan['results'] = {
                'is_malicious': scan['is_malicious'],
                'threat_level': scan['threat_level'],
                'malicious_count': scan['malicious_count'],
                'suspicious_count': scan['suspicious_count'],
                'total_engines': scan['total_engines']
            }
        formatted_scans.append(formatted_scan)
    
    return formatted_scans

async def _do_scan(url: str, scan_id: str):
    import logging
    logger = logging.getLogger("scan")
    start_time = time.time()
    try:
        async with WebShieldDetector() as detector_instance:
            async def with_timeout(coro, timeout, label):
                t0 = time.time()
                try:
                    result = await asyncio.wait_for(coro, timeout=timeout)
                    logger.info(f"{label} completed in {time.time()-t0:.2f}s")
                    return result
                except Exception as e:
                    logger.warning(f"{label} failed or timed out: {e}")
                    return {'error': str(e)}
            url_analysis_task = asyncio.to_thread(detector_instance.analyze_url_patterns, url)
            ssl_task = with_timeout(detector_instance.analyze_ssl_certificate(url), 3.0, 'SSL')
            content_task = with_timeout(detector_instance.analyze_content(url, max_bytes=10*1024), 3.0, 'Content')
            vt_task = with_timeout(detector_instance.check_virustotal(url), 2.0, 'VirusTotal')
            url_analysis, ssl_analysis, content_analysis, vt_analysis = await asyncio.gather(
                url_analysis_task, ssl_task, content_task, vt_task, return_exceptions=True
            )
            logger.info(f"Scan results for {url}: url_analysis={url_analysis}, ssl_analysis={ssl_analysis}, content_analysis={content_analysis}, vt_analysis={vt_analysis}")
            
            # Handle URL analysis with fallback
            if isinstance(url_analysis, Exception):
                logger.error(f"URL analysis failed with exception: {url_analysis}")
                url_analysis = {
                    'error': f'URL analysis failed: {str(url_analysis)}',
                    'suspicious_score': 0,
                    'detected_issues': [],
                    'domain': 'N/A',
                    'is_suspicious': False
                }
            elif not isinstance(url_analysis, dict):
                logger.error(f"URL analysis returned invalid type: {type(url_analysis)}")
                url_analysis = {
                    'error': 'URL analysis returned invalid data',
                    'suspicious_score': 0,
                    'detected_issues': [],
                    'domain': 'N/A',
                    'is_suspicious': False
                }
            
            # Handle content analysis with fallback
            if isinstance(content_analysis, Exception):
                logger.error(f"Content analysis failed with exception: {content_analysis}")
                content_analysis = {
                    'error': f'Content analysis failed: {str(content_analysis)}',
                    'phishing_score': 0,
                    'detected_indicators': [],
                    'is_suspicious': False,
                    'content_length': 0
                }
            elif not isinstance(content_analysis, dict):
                logger.error(f"Content analysis returned invalid type: {type(content_analysis)}")
                content_analysis = {
                    'error': 'Content analysis returned invalid data',
                    'phishing_score': 0,
                    'detected_indicators': [],
                    'is_suspicious': False,
                    'content_length': 0
                }
            
            # Handle VirusTotal analysis with fallback
            malicious_count = 0
            suspicious_count = 0
            total_engines = 0
            
            if isinstance(vt_analysis, dict) and 'error' not in vt_analysis:
                malicious_count = vt_analysis.get('malicious_count', 0)
                suspicious_count = vt_analysis.get('suspicious_count', 0)
                total_engines = vt_analysis.get('total_engines', 0)
            else:
                # VirusTotal failed, use other security checks
                logger.warning(f"VirusTotal analysis failed for {url}, using other security checks")
                # Set default values for display
                malicious_count = 0
                suspicious_count = 0
                total_engines = 0
            
            threat_score = 0
            if isinstance(url_analysis, dict):
                threat_score += url_analysis.get('suspicious_score', 0)
            if isinstance(content_analysis, dict):
                threat_score += content_analysis.get('phishing_score', 0)
            if isinstance(ssl_analysis, dict) and not ssl_analysis.get('valid', False):
                threat_score += 25
            
            # Add VirusTotal scores if available
            threat_score += malicious_count * 10 + suspicious_count * 5
            
            # Determine threat level based on available data
            if threat_score > 60 or malicious_count > 3:
                threat_level = 'high'
                is_malicious = True
            elif threat_score > 30 or suspicious_count > 2:
                threat_level = 'medium'
                is_malicious = True
            else:
                threat_level = 'low'
                is_malicious = False
            
            # Guarantee a valid ScanResult even if all checks are empty or error
            detection_details = {
                'url_analysis': url_analysis if isinstance(url_analysis, dict) else {'error': str(url_analysis)},
                'ssl_analysis': ssl_analysis if isinstance(ssl_analysis, dict) else {'error': str(ssl_analysis)},
                'content_analysis': content_analysis if isinstance(content_analysis, dict) else {'error': str(content_analysis)},
                'virustotal_analysis': vt_analysis if isinstance(vt_analysis, dict) else {'error': str(vt_analysis)},
                'database_health': {'database': 'connected' if get_mysql_connection() and get_mysql_connection().is_connected() else 'disconnected'}
            }
            
            # Ensure at least one field is always present in detection_details
            if not detection_details['url_analysis']:
                detection_details['url_analysis'] = {'info': 'No suspicious patterns found'}
            if not detection_details['ssl_analysis']:
                detection_details['ssl_analysis'] = {'info': 'No SSL issues found'}
            if not detection_details['content_analysis']:
                detection_details['content_analysis'] = {'info': 'No phishing indicators found'}
            if not detection_details['virustotal_analysis']:
                detection_details['virustotal_analysis'] = {'info': 'VirusTotal analysis unavailable - using other security checks'}
            result = ScanResult(
                url=url,
                is_malicious=is_malicious,
                threat_level=threat_level,
                malicious_count=malicious_count,
                suspicious_count=suspicious_count,
                total_engines=total_engines,
                detection_details=detection_details,
                ssl_valid=ssl_analysis.get('valid', False) if isinstance(ssl_analysis, dict) else False,
                domain_reputation='malicious' if is_malicious else 'clean',
                content_analysis=content_analysis if isinstance(content_analysis, dict) else {},
                scan_timestamp=datetime.now()
            )
            conn = get_mysql_connection()
            if conn:
                cursor = conn.cursor()
                logger.info(f"Updating scan {scan_id} status to completed")
                update_query = """
                UPDATE scans SET 
                    status = %s, 
                    is_malicious = %s,
                    threat_level = %s,
                    malicious_count = %s,
                    suspicious_count = %s,
                    total_engines = %s,
                    ssl_valid = %s,
                    domain_reputation = %s,
                    detection_details = %s,
                    completed_at = %s,
                    scan_timestamp = %s
                WHERE scan_id = %s
                """
                try:
                    cursor.execute(update_query, (
                        'completed', is_malicious, threat_level, malicious_count,
                        suspicious_count, total_engines, ssl_analysis.get('valid', False),
                        'malicious' if is_malicious else 'clean',
                        json.dumps(result.detection_details), datetime.now(),
                        result.scan_timestamp, scan_id
                    ))
                    conn.commit()
                    logger.info(f"Successfully updated scan {scan_id} to completed status")
                except Exception as e:
                    logger.error(f"Failed to update scan {scan_id}: {e}")
                    conn.rollback()
                finally:
                    cursor.close()
            else:
                logger.error(f"No database connection available for scan {scan_id} completion")
            logger.info(f"Total scan time: {time.time()-start_time:.2f}s")
            resp = ThreatReport(
                scan_id=scan_id,
                url=url,
                status='completed',
                results=result
            )
            set_cached_scan(url, resp)
    except Exception as e:
        logger.error(f"Scan error: {str(e)}")
        # Always store a completed scan result, even on error
        detection_details = {
            'url_analysis': {'error': 'Scan failed'},
            'ssl_analysis': {'error': 'Scan failed'},
            'content_analysis': {'error': 'Scan failed'},
            'virustotal_analysis': {'error': 'Scan failed'},
            'database_health': {'database': 'error'}
        }
        result = ScanResult(
            url=url,
            is_malicious=False,
            threat_level='low',
            malicious_count=0,
            suspicious_count=0,
            total_engines=0,
            detection_details=detection_details,
            ssl_valid=False,
            domain_reputation='unknown',
            content_analysis={},
            scan_timestamp=datetime.now()
        )
        conn = get_mysql_connection()
        if conn:
            cursor = conn.cursor()
            logger.info(f"Setting scan {scan_id} status to completed (error case)")
            update_query = """
            UPDATE scans SET status = %s, detection_details = %s, completed_at = %s, scan_timestamp = %s WHERE scan_id = %s
            """
            try:
                cursor.execute(update_query, ('completed', json.dumps(result.detection_details), datetime.now(), result.scan_timestamp, scan_id))
                conn.commit()
                logger.info(f"Successfully updated scan {scan_id} to completed status (error case)")
            except Exception as e:
                logger.error(f"Failed to update scan {scan_id} in error case: {e}")
                conn.rollback()
            finally:
                cursor.close()
        else:
            logger.error(f"No database connection available for scan {scan_id} error handling")
        resp = ThreatReport(
            scan_id=scan_id,
            url=url,
            status='completed',
            results=result
        )
        set_cached_scan(url, resp)
    finally:
        logger.info(f"Total scan time: {time.time()-start_time:.2f}s")
        SCAN_IN_PROGRESS.pop(url, None)

@app.post("/api/scan", response_model=ThreatReport)
async def scan_url(request: URLScanRequest):
    logger = logging.getLogger("scan")
    logger.info("Scanning URL: %s", request.url)
    url = request.url.strip()
    # Auto-prepend https:// if missing
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    # Validate URL format (basic check)
    url_pattern = re.compile(r'^https?://([\w.-]+)(:[0-9]+)?(/.*)?$')
    if not url_pattern.match(url):
        raise HTTPException(status_code=400, detail="Invalid or unsupported URL format. Please enter a valid http or https URL.")
    
    # Check cache first
    cached = get_cached_scan(url)
    if cached:
        logger.info(f"Cache hit for {url}")
        return cached
    
    # Check if URL is already being scanned
    if url in SCAN_IN_PROGRESS:
        scan_id = SCAN_IN_PROGRESS[url]
        logger.info(f"URL {url} already being scanned with ID: {scan_id}")
        return ThreatReport(scan_id=scan_id, url=url, status='processing', results=None)
    
    # Generate new scan ID
    scan_id = generate_scan_id()
    logger.info(f"Starting new scan for {url} with ID: {scan_id}")
    
    # Add to in-progress tracking
    SCAN_IN_PROGRESS[url] = scan_id
    
    # Insert processing status in DB
    conn = get_mysql_connection()
    if conn:
        cursor = conn.cursor()
        logger.info(f"Inserting scan into database: scan_id={scan_id}, url={url}, user_email={request.user_email}")
        insert_query = """
        INSERT INTO scans (scan_id, url, status, created_at, user_email)
        VALUES (%s, %s, %s, %s, %s)
        """
        try:
            cursor.execute(insert_query, (scan_id, url, 'processing', datetime.now(), request.user_email))
            conn.commit()
            logger.info(f"Successfully inserted scan {scan_id} into database")
        except Exception as e:
            logger.error(f"Failed to insert scan {scan_id}: {e}")
            conn.rollback()
            # Remove from in-progress if DB insert failed
            SCAN_IN_PROGRESS.pop(url, None)
            raise HTTPException(status_code=500, detail="Failed to start scan. Please try again.")
        finally:
            cursor.close()
    else:
        logger.error("No database connection available for scan insertion")
        # Remove from in-progress if no DB connection
        SCAN_IN_PROGRESS.pop(url, None)
        raise HTTPException(status_code=500, detail="Database connection error. Please try again.")
    
    def run_scan():
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(_do_scan(url, scan_id))
        except Exception as e:
            logger.error(f"Background scan error: {e}")
        finally:
            # Always clean up the in-progress tracking
            if url in SCAN_IN_PROGRESS and SCAN_IN_PROGRESS[url] == scan_id:
                SCAN_IN_PROGRESS.pop(url, None)
                logger.info(f"Cleaned up scan tracking for {url}")
    
    Thread(target=run_scan, daemon=True).start()
    return ThreatReport(scan_id=scan_id, url=url, status='processing', results=None)

@app.post("/api/report_blacklist")
def report_blacklist(request: ReportRequest):
    logger = logging.getLogger("report")
    logger.info("Reporting URL as malicious (blacklist): %s", request.url)
    conn = get_mysql_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database connection error")
    scan_id = hashlib.md5(f"{request.url}{datetime.now().isoformat()}".encode()).hexdigest()
    cursor = conn.cursor()
    insert_query = """
    INSERT INTO scans (scan_id, url, status, is_malicious, threat_level, malicious_count, suspicious_count, total_engines, ssl_valid, domain_reputation, detection_details, created_at, completed_at, scan_timestamp)
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """
    detection_details = json.dumps({"reason": request.reason or "User reported blacklist"})
    now = datetime.now()
    cursor.execute(insert_query, (
        scan_id, request.url, 'completed', True, 'high', 1, 0, 0, False, 'malicious', detection_details, now, now, now
    ))
    conn.commit()
    cursor.close()
    return {"success": True, "message": "URL reported as malicious (blacklist)."}

@app.post("/api/report_whitelist")
def report_whitelist(request: ReportRequest):
    logger = logging.getLogger("report")
    logger.info("Reporting URL as clean (whitelist): %s", request.url)
    conn = get_mysql_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database connection error")
    scan_id = hashlib.md5(f"{request.url}{datetime.now().isoformat()}".encode()).hexdigest()
    cursor = conn.cursor()
    insert_query = """
    INSERT INTO scans (scan_id, url, status, is_malicious, threat_level, malicious_count, suspicious_count, total_engines, ssl_valid, domain_reputation, detection_details, created_at, completed_at, scan_timestamp)
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """
    detection_details = json.dumps({"added_by": request.added_by or "User reported whitelist"})
    now = datetime.now()
    cursor.execute(insert_query, (
        scan_id, request.url, 'completed', False, 'low', 0, 0, 0, True, 'clean', detection_details, now, now, now
    ))
    conn.commit()
    cursor.close()
    return {"success": True, "message": "URL reported as clean (whitelist)."}

@app.get("/api/scan/{scan_id}")
async def get_scan_result(scan_id: str):
    """Get scan results by ID. Always return a valid 'results' object for completed scans."""
    try:
        logger = logging.getLogger("scan")
        logger.info("Getting scan result for ID: %s", scan_id)
        conn = get_mysql_connection()
        if conn:
            cursor = conn.cursor(dictionary=True)
            select_query = """
            SELECT scan_id, url, status, is_malicious, threat_level, malicious_count,
                   suspicious_count, total_engines, ssl_valid, domain_reputation,
                   detection_details, created_at, completed_at, scan_timestamp
            FROM scans WHERE scan_id = %s
            """
            cursor.execute(select_query, (scan_id,))
            scan = cursor.fetchone()
            cursor.close()
            
            # Debug logging
            logger.info(f"Looking for scan_id: {scan_id}")
            if scan:
                logger.info(f"Found scan: {scan['scan_id']}, status: {scan['status']}")
            else:
                logger.warning(f"Scan not found: {scan_id}")
            
            if scan:
                # Convert detection_details from JSON string to dict
                if scan['detection_details']:
                    scan['detection_details'] = json.loads(scan['detection_details'])
                # Always return a valid results object for completed scans
                if scan['status'] == 'completed':
                    # Fallback: if detection_details or results are missing, return a default clean result
                    detection_details = scan['detection_details'] if scan['detection_details'] else {
                        'url_analysis': {'info': 'No suspicious patterns found'},
                        'ssl_analysis': {'info': 'No SSL issues found'},
                        'content_analysis': {'info': 'No phishing indicators found'},
                        'virustotal_analysis': {'info': 'No VirusTotal data'},
                        'database_health': {'database': 'unknown'}
                    }
                    return {
                        'scan_id': scan['scan_id'],
                        'url': scan['url'],
                        'status': scan['status'],
                        'results': {
                            'url': scan['url'],
                            'is_malicious': scan.get('is_malicious', False),
                            'threat_level': scan.get('threat_level', 'low'),
                            'malicious_count': scan.get('malicious_count', 0),
                            'suspicious_count': scan.get('suspicious_count', 0),
                            'total_engines': scan.get('total_engines', 0),
                            'detection_details': detection_details,
                            'ssl_valid': scan.get('ssl_valid', False),
                            'domain_reputation': scan.get('domain_reputation', 'unknown'),
                            'content_analysis': detection_details.get('content_analysis', {}),
                            'scan_timestamp': scan.get('scan_timestamp') or scan.get('completed_at')
                        }
                    }
                else:
                    # Scan is processing or errored
                    return {
                        'scan_id': scan['scan_id'],
                        'url': scan['url'],
                        'status': scan['status'],
                        'results': None
                    }
            else:
                # Scan not found in database
                raise HTTPException(status_code=404, detail="Scan not found")
        else:
            # Database connection failed
            raise HTTPException(status_code=500, detail="Database connection failed")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving scan {scan_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error retrieving scan: {str(e)}")

@app.get("/api/history")
async def get_scan_history(limit: int = 50):
    """Get recent scan history"""
    try:
        logger = logging.getLogger("history")
        logger.info("Getting scan history with limit: %s", limit)
        conn = get_mysql_connection()
        if conn:
            cursor = conn.cursor(dictionary=True)
            select_query = """
            SELECT scan_id, url, status, is_malicious, threat_level, malicious_count,
                   suspicious_count, total_engines, created_at, completed_at
            FROM scans 
            ORDER BY created_at DESC 
            LIMIT %s
            """
            cursor.execute(select_query, (limit,))
            scans = cursor.fetchall()
            cursor.close()
            
            # Format results for frontend
            formatted_scans = []
            for scan in scans:
                formatted_scan = dict(scan)
                if scan['status'] == 'completed':
                    formatted_scan['results'] = {
                        'is_malicious': scan['is_malicious'],
                        'threat_level': scan['threat_level'],
                        'malicious_count': scan['malicious_count'],
                        'suspicious_count': scan['suspicious_count'],
                        'total_engines': scan['total_engines']
                    }
                formatted_scans.append(formatted_scan)
            
            return formatted_scans
        return []
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving history: {str(e)}")

@app.get("/api/stats")
async def get_statistics():
    """Get scanning statistics"""
    try:
        logger = logging.getLogger("stats")
        logger.info("Getting scanning statistics")
        conn = get_mysql_connection()
        if conn:
            cursor = conn.cursor(dictionary=True)
            
            # Get overall statistics
            total_query = "SELECT COUNT(*) as total_scans FROM scans"
            cursor.execute(total_query)
            total_result = cursor.fetchone()
            total_scans = total_result['total_scans'] if total_result else 0
            
            malicious_query = "SELECT COUNT(*) as malicious_scans FROM scans WHERE is_malicious = TRUE"
            cursor.execute(malicious_query)
            malicious_result = cursor.fetchone()
            malicious_scans = malicious_result['malicious_scans'] if malicious_result else 0
            
            today_query = "SELECT COUNT(*) as today_scans FROM scans WHERE DATE(created_at) = CURDATE()"
            cursor.execute(today_query)
            today_result = cursor.fetchone()
            today_scans = today_result['today_scans'] if today_result else 0
            
            cursor.close()
            
            clean_scans = total_scans - malicious_scans
            detection_rate = (malicious_scans / total_scans * 100) if total_scans > 0 else 0
            
            return {
                'total_scans': total_scans,
                'malicious_detected': malicious_scans,
                'clean_scans': clean_scans,
                'today_scans': today_scans,
                'detection_rate': round(detection_rate, 2)
            }
        
        return {
            'total_scans': 0,
            'malicious_detected': 0,
            'clean_scans': 0,
            'today_scans': 0,
            'detection_rate': 0
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving stats: {str(e)}")

@app.get("/api/dashboard-stats")
async def get_dashboard_statistics():
    """Get dashboard statistics including URLs scanned, threats blocked, and user count"""
    try:
        logger = logging.getLogger("dashboard")
        logger.info("Getting dashboard statistics")
        conn = get_mysql_connection()
        if conn:
            cursor = conn.cursor(dictionary=True)
            
            # Get total URLs scanned
            urls_query = "SELECT COUNT(*) as total_urls FROM scans WHERE status = 'completed'"
            cursor.execute(urls_query)
            urls_result = cursor.fetchone()
            urls_scanned = urls_result['total_urls'] if urls_result else 0
            
            # Get total threats blocked
            threats_query = "SELECT COUNT(*) as total_threats FROM scans WHERE is_malicious = TRUE AND status = 'completed'"
            cursor.execute(threats_query)
            threats_result = cursor.fetchone()
            threats_blocked = threats_result['total_threats'] if threats_result else 0
            
            # Get total users
            users_query = "SELECT COUNT(DISTINCT user_email) as total_users FROM scans WHERE user_email IS NOT NULL"
            cursor.execute(users_query)
            users_result = cursor.fetchone()
            users_count = users_result['total_users'] if users_result else 0
            
            cursor.close()
            
            return {
                'urls_scanned': urls_scanned,
                'threats_blocked': threats_blocked,
                'users': users_count,
                'uptime': '99.99 %'  # Always return 99.99%
            }
        
        return {
            'urls_scanned': 0,
            'threats_blocked': 0,
            'users': 0,
            'uptime': '99.99 %'
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving dashboard stats: {str(e)}")

@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    logger = logging.getLogger("health")
    logger.info("Running health check")
    conn = get_mysql_connection()
    database_status = "connected" if conn and conn.is_connected() else "disconnected"
    
    # Test database connection with a simple query
    db_test = "failed"
    if conn and conn.is_connected():
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT 1")
            cursor.fetchone()
            cursor.close()
            db_test = "passed"
        except Exception as e:
            db_test = f"failed: {str(e)}"
    
    # Check ML models status
    ml_status = "unknown"
    try:
        ml_engine = get_ml_engine()
        ml_status_info = ml_engine.get_model_status()
        ml_status = {
            "url_classifier_trained": ml_status_info['url_classifier_trained'],
            "content_detector_trained": ml_status_info['content_detector_trained'],
            "models_available": ml_status_info['url_classifier_trained'] or ml_status_info['content_detector_trained']
        }
    except Exception as e:
        ml_status = f"error: {str(e)}"
    
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "database": database_status,
        "database_test": db_test,
        "database_type": "MySQL",
        "database_config": {
            "host": MYSQL_CONFIG['host'],
            "port": MYSQL_CONFIG['port'],
            "database": MYSQL_CONFIG['database'],
            "user": MYSQL_CONFIG['user']
        },
        "virustotal": "configured" if VT_API_KEY else "not configured",
        "ml_models": ml_status
    }

def find_available_port(start_port=8000, max_attempts=100):
    """Find an available port starting from start_port"""
    import socket
    
    for port in range(start_port, start_port + max_attempts):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('127.0.0.1', port))
                return port
        except OSError:
            continue
    raise RuntimeError(f"No available ports found in range {start_port}-{start_port + max_attempts - 1}")

def kill_process_on_port(port):
    """Kill any process using the specified port"""
    import subprocess
    import platform
    
    try:
        if platform.system() == "Windows":
            # Find process using the port
            result = subprocess.run(['netstat', '-ano'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if f':{port}' in line and 'LISTENING' in line:
                    parts = line.split()
                    if len(parts) >= 5:
                        pid = parts[-1]
                        # Kill the process
                        subprocess.run(['taskkill', '/PID', pid, '/F'], 
                                     capture_output=True, check=False)
                        return True
        else:
            # For Unix-like systems
            result = subprocess.run(['lsof', '-ti', f':{port}'], 
                                 capture_output=True, text=True)
            if result.stdout.strip():
                pids = result.stdout.strip().split('\n')
                for pid in pids:
                    subprocess.run(['kill', '-9', pid], 
                                 capture_output=True, check=False)
                return True
    except Exception as e:
        print(f"Warning: Could not kill process on port {port}: {e}")
    return False

if __name__ == "__main__":
    import uvicorn
    import logging
    import socket
    import sys
    
    logger = logging.getLogger("server")
    logger.info("Starting server...")

    # Initialize database and tables
    try:
        logger.info("Initializing database and tables...")
        create_database_and_tables()
        logger.info("Database initialization completed successfully")
    except Exception as e:
        logger.warning(f"Database initialization failed: {e}")

    # Find available port
    preferred_port = 8000
    try:
        available_port = find_available_port(preferred_port)
        if available_port != preferred_port:
            logger.info(f"Port {preferred_port} is busy, using port {available_port}")
        else:
            logger.info(f"Using preferred port {preferred_port}")
    except RuntimeError as e:
        logger.error(f"Port allocation failed: {e}")
        sys.exit(1)

    logger.info(f"Starting uvicorn server on port {available_port}...")
    try:
        uvicorn.run(
            app, 
            host="127.0.0.1", 
            port=available_port,
            workers=1,
            access_log=False,
            log_level="warning"
        )
    except OSError as e:
        if "Address already in use" in str(e) or "10048" in str(e):
            logger.warning(f"Port {available_port} became busy, attempting to kill existing process...")
            if kill_process_on_port(available_port):
                logger.info("Killed existing process, retrying...")
                uvicorn.run(
                    app, 
                    host="127.0.0.1", 
                    port=available_port,
                    workers=1,
                    access_log=False,
                    log_level="warning"
                )
            else:
                logger.error(f"Could not free port {available_port}, trying next available port...")
                available_port = find_available_port(available_port + 1)
                logger.info(f"Retrying on port {available_port}")
                uvicorn.run(
                    app, 
                    host="127.0.0.1", 
                    port=available_port,
                    workers=1,
                    access_log=False,
                    log_level="warning"
                )
        else:
            raise

