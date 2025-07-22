from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, Form, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader
import mysql.connector
from mysql.connector import Error
from pydantic import BaseModel
from datetime import datetime
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
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from passlib.hash import bcrypt
from fastapi import Request
import shutil

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
)

# Optional: Serve index.html at root (for direct / access)
@app.get("/")
def read_index():
    return FileResponse("frontend/public/index.html")

# MySQL connection configuration
MYSQL_CONFIG = {
    'host': os.environ.get('MYSQL_HOST', 'localhost'),
    'port': int(os.environ.get('MYSQL_PORT', '3306')),
    'user': os.environ.get('MYSQL_USER', 'root'),
    'password': os.environ.get('MYSQL_PASSWORD', 'Deepak@1234'),
    'database': os.environ.get('MYSQL_DATABASE', 'webshield'),
    'charset': 'utf8mb4',
    'autocommit': True,
    'use_unicode': True
}

# Global database connection
mysql_connection = None

def get_mysql_connection():
    """Get MySQL database connection"""
    global mysql_connection
    try:
        if mysql_connection is None or not mysql_connection.is_connected():
            mysql_connection = mysql.connector.connect(**MYSQL_CONFIG)
            logger.info("Connected to MySQL successfully")
    except Error as e:
        logger.error(f"Failed to connect to MySQL: {e}")
        mysql_connection = None
    return mysql_connection

def init_database():
    """Initialize MySQL database tables"""
    try:
        conn = get_mysql_connection()
        if conn:
            cursor = conn.cursor()
            
            # Create scans table
            create_scans_table = """
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
                domain_reputation VARCHAR(50) DEFAULT 'unknown',
                detection_details JSON,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP NULL,
                scan_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
            
            cursor.execute(create_scans_table)
            
            # Create users table (add profile_pic if missing)
            create_users_table = """
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                email VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                name VARCHAR(255),
                profile_pic VARCHAR(255),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
            cursor.execute(create_users_table)
            
            # Create threat_reports table for detailed analysis
            create_reports_table = """
            CREATE TABLE IF NOT EXISTS threat_reports (
                id INT AUTO_INCREMENT PRIMARY KEY,
                scan_id VARCHAR(255) NOT NULL,
                url TEXT NOT NULL,
                threat_type VARCHAR(100),
                severity_score INT DEFAULT 0,
                details JSON,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
            )
            """
            
            cursor.execute(create_reports_table)
            
            # Create statistics table
            create_stats_table = """
            CREATE TABLE IF NOT EXISTS scan_statistics (
                id INT AUTO_INCREMENT PRIMARY KEY,
                date DATE DEFAULT (CURRENT_DATE),
                total_scans INT DEFAULT 0,
                malicious_detected INT DEFAULT 0,
                clean_scans INT DEFAULT 0,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                UNIQUE KEY unique_date (date)
            )
            """
            
            cursor.execute(create_stats_table)
            
            conn.commit()
            cursor.close()
            logger.info("Database tables initialized successfully")
    except Error as e:
        logger.error(f"Error initializing database: {e}")

# Initialize database on startup
init_database()

# VirusTotal API configuration
VT_API_KEY = "f356daa5ecedff26ce9a153be1c64bd88c4fa8ffc9aa9354924cc15f5c6e9c8f"
VT_BASE_URL = "https://www.virustotal.com/api/v3"

# Data models
class URLScanRequest(BaseModel):
    url: str

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

PHISHING_KEYWORDS = [
    'verify', 'suspend', 'limited', 'security', 'confirm', 'update', 'login',
    'account', 'bank', 'paypal', 'amazon', 'microsoft', 'google', 'apple',
    'urgent', 'immediate', 'expired', 'locked', 'restricted'
]

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
            'is_suspicious': suspicious_score > 20
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
        """Analyze SSL certificate validity"""
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
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    return {
                        'valid': True,
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'subject': dict(x[0] for x in cert['subject']),
                        'expires': cert['notAfter'],
                        'serial_number': cert['serialNumber']
                    }
        except Exception as e:
            return {
                'valid': False,
                'error': str(e),
                'details': 'SSL certificate validation failed'
            }
    
    async def analyze_content(self, url: str) -> Dict[str, Any]:
        """Analyze webpage content for phishing indicators"""
        try:
            async with self.session.get(url, timeout=10) as response:
                if response.status != 200:
                    return {'error': f'HTTP {response.status}', 'phishing_score': 0}
                
                content = await response.text()
                
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
                    'content_length': len(content)
                }
        except Exception as e:
            return {
                'error': str(e),
                'phishing_score': 0,
                'detected_indicators': [],
                'is_suspicious': False
            }
    
    async def check_virustotal(self, url: str) -> Dict[str, Any]:
        """Check URL against VirusTotal API"""
        try:
            # URL encode the URL for VirusTotal
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
            
            headers = {
                'x-apikey': VT_API_KEY,
                'Content-Type': 'application/json'
            }
            
            # Check if URL already exists in VirusTotal
            check_url = f"{VT_BASE_URL}/urls/{url_id}"
            
            async with self.session.get(check_url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    stats = data['data']['attributes']['last_analysis_stats']
                    
                    return {
                        'malicious_count': stats.get('malicious', 0),
                        'suspicious_count': stats.get('suspicious', 0),
                        'harmless_count': stats.get('harmless', 0),
                        'undetected_count': stats.get('undetected', 0),
                        'total_engines': sum(stats.values()),
                        'engines_results': data['data']['attributes']['last_analysis_results'],
                        'reputation': data['data']['attributes'].get('reputation', 0),
                        'cached': True
                    }
                elif response.status == 404:
                    # URL not found, submit for analysis
                    return await self._submit_url_to_virustotal(url)
                else:
                    return {'error': f'VirusTotal API error: {response.status}'}
        except Exception as e:
            return {'error': f'VirusTotal check failed: {str(e)}'}
    
    async def _submit_url_to_virustotal(self, url: str) -> Dict[str, Any]:
        """Submit URL to VirusTotal for analysis"""
        try:
            headers = {
                'x-apikey': VT_API_KEY,
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            
            data = f'url={urllib.parse.quote(url)}'
            
            async with self.session.post(f"{VT_BASE_URL}/urls", 
                                       headers=headers, 
                                       data=data) as response:
                if response.status == 200:
                    result = await response.json()
                    analysis_id = result['data']['id']
                    
                    # Wait a bit and try to get results
                    await asyncio.sleep(2)
                    return await self._get_analysis_results(analysis_id)
                else:
                    return {'error': f'URL submission failed: {response.status}'}
        except Exception as e:
            return {'error': f'URL submission error: {str(e)}'}
    
    async def _get_analysis_results(self, analysis_id: str) -> Dict[str, Any]:
        """Get analysis results from VirusTotal"""
        try:
            headers = {'x-apikey': VT_API_KEY}
            
            async with self.session.get(f"{VT_BASE_URL}/analyses/{analysis_id}", 
                                      headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    stats = data['data']['attributes']['stats']
                    
                    return {
                        'malicious_count': stats.get('malicious', 0),
                        'suspicious_count': stats.get('suspicious', 0),
                        'harmless_count': stats.get('harmless', 0),
                        'undetected_count': stats.get('undetected', 0),
                        'total_engines': sum(stats.values()),
                        'engines_results': data['data']['attributes'].get('results', {}),
                        'status': data['data']['attributes']['status'],
                        'cached': False
                    }
                else:
                    return {'error': f'Analysis retrieval failed: {response.status}'}
        except Exception as e:
            return {'error': f'Analysis retrieval error: {str(e)}'}

# Initialize detector
detector = WebShieldDetector()

PROFILE_PICS_DIR = "frontend/public/profile_pics"
os.makedirs(PROFILE_PICS_DIR, exist_ok=True)

@app.post("/api/upload_profile_photo")
def upload_profile_photo(email: str = Form(...), file: UploadFile = File(...)):
    conn = get_mysql_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database connection error")
    # Save file
    ext = os.path.splitext(file.filename)[1]
    filename = f"{email.replace('@','_at_')}{ext}"
    filepath = os.path.join(PROFILE_PICS_DIR, filename)
    with open(filepath, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    # Update user record
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET profile_pic = %s WHERE email = %s", (filename, email))
    conn.commit()
    cursor.close()
    return {"success": True, "filename": filename, "url": f"/profile_pics/{filename}"}

@app.get("/profile_pics/{filename}")
def get_profile_pic(filename: str):
    filepath = os.path.join(PROFILE_PICS_DIR, filename)
    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail="Profile picture not found")
    return FileResponse(filepath)

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
    conn = get_mysql_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database connection error")
    cursor = conn.cursor()
    # Check if user exists
    cursor.execute("SELECT id FROM users WHERE email = %s", (request.email,))
    if cursor.fetchone():
        cursor.close()
        raise HTTPException(status_code=400, detail="Email already registered")
    # Hash password
    hashed_pw = bcrypt.hash(request.password)
    cursor.execute(
        "INSERT INTO users (email, password, name) VALUES (%s, %s, %s)",
        (request.email, hashed_pw, request.name)
    )
    conn.commit()
    cursor.close()
    return {"success": True}

@app.post("/api/login")
def login_user(request: LoginRequest):
    conn = get_mysql_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database connection error")
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE email = %s", (request.email,))
    user = cursor.fetchone()
    cursor.close()
    if not user or not bcrypt.verify(request.password, user['password']):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    return {"success": True, "name": user.get("name", ""), "email": user["email"]}

@app.post("/api/scan", response_model=ThreatReport)
async def scan_url(request: URLScanRequest):
    """Comprehensive URL scanning endpoint"""
    try:
        url = request.url
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        scan_id = hashlib.md5(f"{url}{datetime.now().isoformat()}".encode()).hexdigest()
        # Store initial scan request in MySQL
        conn = get_mysql_connection()
        if conn:
            cursor = conn.cursor()
            print("Inserting status:", 'processing')
            insert_query = """
            INSERT INTO scans (scan_id, url, status, created_at)
            VALUES (%s, %s, %s, %s)
            """
            cursor.execute(insert_query, (scan_id, url, 'processing', datetime.now()))
            conn.commit()
            cursor.close()
        # Database health check
        db_health = {'database': 'connected' if conn and conn.is_connected() else 'disconnected'}
        # Start comprehensive analysis
        async with WebShieldDetector() as detector_instance:
            url_analysis, ssl_analysis, content_analysis, vt_analysis = await asyncio.gather(
                asyncio.create_task(asyncio.to_thread(detector_instance.analyze_url_patterns, url)),
                detector_instance.analyze_ssl_certificate(url),
                detector_instance.analyze_content(url),
                detector_instance.check_virustotal(url),
                return_exceptions=True
            )
            malicious_count = vt_analysis.get('malicious_count', 0) if isinstance(vt_analysis, dict) else 0
            suspicious_count = vt_analysis.get('suspicious_count', 0) if isinstance(vt_analysis, dict) else 0
            total_engines = vt_analysis.get('total_engines', 0) if isinstance(vt_analysis, dict) else 0
            threat_score = 0
            if isinstance(url_analysis, dict):
                threat_score += url_analysis.get('suspicious_score', 0)
            if isinstance(content_analysis, dict):
                threat_score += content_analysis.get('phishing_score', 0)
            if isinstance(ssl_analysis, dict) and not ssl_analysis.get('valid', False):
                threat_score += 25
            threat_score += malicious_count * 10 + suspicious_count * 5
            if threat_score > 60 or malicious_count > 3:
                threat_level = 'high'
                is_malicious = True
            elif threat_score > 30 or suspicious_count > 2:
                threat_level = 'medium'
                is_malicious = True
            else:
                threat_level = 'low'
                is_malicious = False
            detection_details = {
                'url_analysis': url_analysis if isinstance(url_analysis, dict) else {'error': str(url_analysis)},
                'ssl_analysis': ssl_analysis if isinstance(ssl_analysis, dict) else {'error': str(ssl_analysis)},
                'content_analysis': content_analysis if isinstance(content_analysis, dict) else {'error': str(content_analysis)},
                'virustotal_analysis': vt_analysis if isinstance(vt_analysis, dict) else {'error': str(vt_analysis)},
                'database_health': db_health
            }
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
            if conn:
                cursor = conn.cursor()
                print("Updating status:", 'completed')
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
                cursor.execute(update_query, (
                    'completed', is_malicious, threat_level, malicious_count,
                    suspicious_count, total_engines, ssl_analysis.get('valid', False),
                    'malicious' if is_malicious else 'clean',
                    json.dumps(result.detection_details), datetime.now(),
                    result.scan_timestamp, scan_id
                ))
                conn.commit()
                cursor.close()
                update_stats_query = """
                INSERT INTO scan_statistics (date, total_scans, malicious_detected, clean_scans)
                VALUES (CURDATE(), 1, %s, %s)
                ON DUPLICATE KEY UPDATE
                total_scans = total_scans + 1,
                malicious_detected = malicious_detected + %s,
                clean_scans = clean_scans + %s
                """
                cursor = conn.cursor()
                cursor.execute(update_stats_query, (
                    1 if is_malicious else 0,
                    0 if is_malicious else 1,
                    1 if is_malicious else 0,
                    0 if is_malicious else 1
                ))
                conn.commit()
                cursor.close()
            return ThreatReport(
                scan_id=scan_id,
                url=url,
                status='completed',
                results=result
            )
    except Exception as e:
        logger.error(f"Scan error: {str(e)}")
        # Set status to 'error' if possible
        conn = get_mysql_connection()
        if conn:
            cursor = conn.cursor()
            print("Setting status to error for scan_id:", scan_id)
            cursor.execute("UPDATE scans SET status = %s WHERE scan_id = %s", ('error', scan_id))
            conn.commit()
            cursor.close()
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

@app.post("/api/report_blacklist")
def report_blacklist(request: ReportRequest):
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
    """Get scan results by ID"""
    try:
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
            
            if scan:
                # Convert detection_details from JSON string to dict
                if scan['detection_details']:
                    scan['detection_details'] = json.loads(scan['detection_details'])
                
                return {
                    'scan_id': scan['scan_id'],
                    'url': scan['url'],
                    'status': scan['status'],
                    'results': {
                        'url': scan['url'],
                        'is_malicious': scan['is_malicious'],
                        'threat_level': scan['threat_level'],
                        'malicious_count': scan['malicious_count'],
                        'suspicious_count': scan['suspicious_count'],
                        'total_engines': scan['total_engines'],
                        'ssl_valid': scan['ssl_valid'],
                        'domain_reputation': scan['domain_reputation'],
                        'detection_details': scan['detection_details'],
                        'scan_timestamp': scan['scan_timestamp']
                    } if scan['status'] == 'completed' else None,
                    'created_at': scan['created_at'],
                    'completed_at': scan['completed_at']
                }
        
        raise HTTPException(status_code=404, detail="Scan not found")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving scan: {str(e)}")

@app.get("/api/history")
async def get_scan_history(limit: int = 50):
    """Get recent scan history"""
    try:
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

@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    conn = get_mysql_connection()
    database_status = "connected" if conn and conn.is_connected() else "disconnected"
    
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "database": database_status,
        "database_type": "MySQL",
        "virustotal": "configured" if VT_API_KEY else "not configured"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)

# Mount static files (frontend) at the end to avoid overriding API routes
app.mount("/", StaticFiles(directory="frontend/public", html=True), name="static")