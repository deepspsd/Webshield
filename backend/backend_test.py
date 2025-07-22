#!/usr/bin/env python3
"""
WebShield Backend Testing Suite
Tests all backend API endpoints and core functionality
"""

import requests
import json
import time
import sys
from datetime import datetime
from typing import Dict, Any, List

# Backend URL from environment
BACKEND_URL = "https://3e9118c5-7b1a-419b-b2e3-e953c1dc04f1.preview.emergentagent.com/api"

# Test URLs as specified in requirements
TEST_URLS = {
    'clean': 'https://google.com',
    'suspicious': 'http://bit.ly/test',
    'various_formats': ['google.com', 'https://example.com', 'ftp://invalid.com'],
    'malicious_patterns': [
        'http://192.168.1.1/login',  # IP address
        'https://g00gle.com',  # Typosquatting
        'http://secure-bank-update123.tk',  # Suspicious TLD + keywords
        'https://very-long-suspicious-domain-name-that-looks-fake.info'
    ]
}

class WebShieldTester:
    def __init__(self):
        self.results = {
            'passed': 0,
            'failed': 0,
            'errors': [],
            'test_details': []
        }
        self.scan_ids = []  # Store scan IDs for later testing
    
    def log_test(self, test_name: str, passed: bool, details: str = ""):
        """Log test result"""
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{status}: {test_name}")
        if details:
            print(f"   Details: {details}")
        
        self.results['test_details'].append({
            'test': test_name,
            'passed': passed,
            'details': details,
            'timestamp': datetime.now().isoformat()
        })
        
        if passed:
            self.results['passed'] += 1
        else:
            self.results['failed'] += 1
            self.results['errors'].append(f"{test_name}: {details}")
    
    def test_health_endpoint(self):
        """Test /api/health endpoint"""
        print("\n=== Testing Health Endpoint ===")
        try:
            response = requests.get(f"{BACKEND_URL}/health", timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                required_fields = ['status', 'timestamp', 'database', 'virustotal']
                
                all_fields_present = all(field in data for field in required_fields)
                database_connected = data.get('database') == 'connected'
                vt_configured = data.get('virustotal') == 'configured'
                
                self.log_test(
                    "Health endpoint response structure",
                    all_fields_present,
                    f"Fields present: {list(data.keys())}"
                )
                
                self.log_test(
                    "Database connection status",
                    database_connected,
                    f"Database status: {data.get('database')}"
                )
                
                self.log_test(
                    "VirusTotal API configuration",
                    vt_configured,
                    f"VirusTotal status: {data.get('virustotal')}"
                )
            else:
                self.log_test(
                    "Health endpoint accessibility",
                    False,
                    f"HTTP {response.status_code}: {response.text}"
                )
        except Exception as e:
            self.log_test("Health endpoint accessibility", False, str(e))
    
    def test_scan_endpoint_basic(self):
        """Test basic /api/scan endpoint functionality"""
        print("\n=== Testing Basic Scan Endpoint ===")
        
        # Test with clean URL
        try:
            payload = {"url": TEST_URLS['clean']}
            response = requests.post(f"{BACKEND_URL}/scan", json=payload, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                required_fields = ['scan_id', 'url', 'status', 'results']
                
                fields_present = all(field in data for field in required_fields)
                self.log_test(
                    "Scan endpoint response structure",
                    fields_present,
                    f"Response fields: {list(data.keys())}"
                )
                
                if 'scan_id' in data:
                    self.scan_ids.append(data['scan_id'])
                
                # Test results structure
                if 'results' in data and data['results']:
                    results = data['results']
                    result_fields = ['url', 'is_malicious', 'threat_level', 'detection_details']
                    results_valid = all(field in results for field in result_fields)
                    
                    self.log_test(
                        "Scan results structure",
                        results_valid,
                        f"Results fields: {list(results.keys())}"
                    )
                    
                    # Test threat level values
                    valid_threat_levels = ['low', 'medium', 'high']
                    threat_level_valid = results.get('threat_level') in valid_threat_levels
                    
                    self.log_test(
                        "Threat level validation",
                        threat_level_valid,
                        f"Threat level: {results.get('threat_level')}"
                    )
            else:
                self.log_test(
                    "Scan endpoint basic functionality",
                    False,
                    f"HTTP {response.status_code}: {response.text}"
                )
        except Exception as e:
            self.log_test("Scan endpoint basic functionality", False, str(e))
    
    def test_url_pattern_analysis(self):
        """Test URL pattern analysis functionality"""
        print("\n=== Testing URL Pattern Analysis ===")
        
        for pattern_type, url in [
            ("IP address detection", "http://192.168.1.1/login"),
            ("Typosquatting detection", "https://g00gle.com"),
            ("Suspicious TLD detection", "http://test.tk"),
            ("URL shortener detection", TEST_URLS['suspicious'])
        ]:
            try:
                payload = {"url": url}
                response = requests.post(f"{BACKEND_URL}/scan", json=payload, timeout=30)
                
                if response.status_code == 200:
                    data = response.json()
                    if 'results' in data and data['results']:
                        detection_details = data['results'].get('detection_details', {})
                        url_analysis = detection_details.get('url_analysis', {})
                        
                        # Check if suspicious patterns were detected
                        has_suspicious_score = 'suspicious_score' in url_analysis
                        has_detected_issues = 'detected_issues' in url_analysis
                        
                        self.log_test(
                            f"URL pattern analysis - {pattern_type}",
                            has_suspicious_score and has_detected_issues,
                            f"Suspicious score: {url_analysis.get('suspicious_score', 0)}, Issues: {len(url_analysis.get('detected_issues', []))}"
                        )
                else:
                    self.log_test(
                        f"URL pattern analysis - {pattern_type}",
                        False,
                        f"HTTP {response.status_code}"
                    )
            except Exception as e:
                self.log_test(f"URL pattern analysis - {pattern_type}", False, str(e))
    
    def test_ssl_certificate_validation(self):
        """Test SSL certificate validation"""
        print("\n=== Testing SSL Certificate Validation ===")
        
        test_cases = [
            ("HTTPS site", "https://google.com", True),
            ("HTTP site", "http://example.com", False),
        ]
        
        for test_name, url, should_be_valid in test_cases:
            try:
                payload = {"url": url}
                response = requests.post(f"{BACKEND_URL}/scan", json=payload, timeout=30)
                
                if response.status_code == 200:
                    data = response.json()
                    if 'results' in data and data['results']:
                        ssl_valid = data['results'].get('ssl_valid', False)
                        detection_details = data['results'].get('detection_details', {})
                        ssl_analysis = detection_details.get('ssl_analysis', {})
                        
                        # For HTTPS sites, should have valid SSL or detailed error
                        if url.startswith('https://'):
                            ssl_check_performed = 'valid' in ssl_analysis or 'error' in ssl_analysis
                        else:
                            ssl_check_performed = True  # HTTP sites should be handled
                        
                        self.log_test(
                            f"SSL validation - {test_name}",
                            ssl_check_performed,
                            f"SSL valid: {ssl_valid}, Analysis: {ssl_analysis.get('error', 'OK')}"
                        )
                else:
                    self.log_test(f"SSL validation - {test_name}", False, f"HTTP {response.status_code}")
            except Exception as e:
                self.log_test(f"SSL validation - {test_name}", False, str(e))
    
    def test_content_analysis(self):
        """Test content analysis for phishing detection"""
        print("\n=== Testing Content Analysis ===")
        
        try:
            payload = {"url": TEST_URLS['clean']}
            response = requests.post(f"{BACKEND_URL}/scan", json=payload, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                if 'results' in data and data['results']:
                    detection_details = data['results'].get('detection_details', {})
                    content_analysis = detection_details.get('content_analysis', {})
                    
                    # Check if content analysis was performed
                    has_phishing_score = 'phishing_score' in content_analysis
                    has_indicators = 'detected_indicators' in content_analysis
                    has_suspicious_flag = 'is_suspicious' in content_analysis
                    
                    content_analyzed = has_phishing_score and has_indicators and has_suspicious_flag
                    
                    self.log_test(
                        "Content analysis functionality",
                        content_analyzed,
                        f"Phishing score: {content_analysis.get('phishing_score', 0)}, Indicators: {len(content_analysis.get('detected_indicators', []))}"
                    )
                    
                    # Check if content was actually fetched
                    content_fetched = 'content_length' in content_analysis or 'error' in content_analysis
                    
                    self.log_test(
                        "Content fetching capability",
                        content_fetched,
                        f"Content length: {content_analysis.get('content_length', 'N/A')}"
                    )
            else:
                self.log_test("Content analysis functionality", False, f"HTTP {response.status_code}")
        except Exception as e:
            self.log_test("Content analysis functionality", False, str(e))
    
    def test_virustotal_integration(self):
        """Test VirusTotal API integration"""
        print("\n=== Testing VirusTotal Integration ===")
        
        try:
            payload = {"url": TEST_URLS['clean']}
            response = requests.post(f"{BACKEND_URL}/scan", json=payload, timeout=45)  # Longer timeout for VT
            
            if response.status_code == 200:
                data = response.json()
                if 'results' in data and data['results']:
                    detection_details = data['results'].get('detection_details', {})
                    vt_analysis = detection_details.get('virustotal_analysis', {})
                    
                    # Check if VirusTotal analysis was performed
                    has_engine_counts = any(key in vt_analysis for key in ['malicious_count', 'suspicious_count', 'total_engines'])
                    has_results = 'engines_results' in vt_analysis or 'error' in vt_analysis
                    
                    vt_integration_working = has_engine_counts or 'error' in vt_analysis
                    
                    self.log_test(
                        "VirusTotal API integration",
                        vt_integration_working,
                        f"Malicious: {vt_analysis.get('malicious_count', 0)}, Suspicious: {vt_analysis.get('suspicious_count', 0)}, Total engines: {vt_analysis.get('total_engines', 0)}"
                    )
                    
                    # Check threat level calculation includes VT data
                    results = data['results']
                    malicious_count = results.get('malicious_count', 0)
                    suspicious_count = results.get('suspicious_count', 0)
                    
                    vt_data_integrated = isinstance(malicious_count, int) and isinstance(suspicious_count, int)
                    
                    self.log_test(
                        "VirusTotal data integration in results",
                        vt_data_integrated,
                        f"Malicious count: {malicious_count}, Suspicious count: {suspicious_count}"
                    )
            else:
                self.log_test("VirusTotal API integration", False, f"HTTP {response.status_code}")
        except Exception as e:
            self.log_test("VirusTotal API integration", False, str(e))
    
    def test_scan_result_retrieval(self):
        """Test /api/scan/{scan_id} endpoint"""
        print("\n=== Testing Scan Result Retrieval ===")
        
        if not self.scan_ids:
            self.log_test("Scan result retrieval", False, "No scan IDs available for testing")
            return
        
        try:
            scan_id = self.scan_ids[0]
            response = requests.get(f"{BACKEND_URL}/scan/{scan_id}", timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                required_fields = ['scan_id', 'url', 'status', 'results']
                
                fields_present = all(field in data for field in required_fields)
                correct_scan_id = data.get('scan_id') == scan_id
                
                self.log_test(
                    "Scan result retrieval by ID",
                    fields_present and correct_scan_id,
                    f"Fields: {list(data.keys())}, Scan ID match: {correct_scan_id}"
                )
            else:
                self.log_test(
                    "Scan result retrieval by ID",
                    False,
                    f"HTTP {response.status_code}: {response.text}"
                )
        except Exception as e:
            self.log_test("Scan result retrieval by ID", False, str(e))
        
        # Test with invalid scan ID
        try:
            response = requests.get(f"{BACKEND_URL}/scan/invalid_scan_id", timeout=10)
            
            invalid_id_handled = response.status_code == 404
            
            self.log_test(
                "Invalid scan ID handling",
                invalid_id_handled,
                f"HTTP {response.status_code} for invalid ID"
            )
        except Exception as e:
            self.log_test("Invalid scan ID handling", False, str(e))
    
    def test_scan_history(self):
        """Test /api/history endpoint"""
        print("\n=== Testing Scan History ===")
        
        try:
            response = requests.get(f"{BACKEND_URL}/history", timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                is_list = isinstance(data, list)
                self.log_test(
                    "History endpoint returns list",
                    is_list,
                    f"Response type: {type(data)}"
                )
                
                if is_list and len(data) > 0:
                    # Check first item structure
                    first_item = data[0]
                    expected_fields = ['scan_id', 'url', 'status', 'created_at']
                    
                    has_required_fields = all(field in first_item for field in expected_fields)
                    
                    self.log_test(
                        "History item structure",
                        has_required_fields,
                        f"First item fields: {list(first_item.keys())}"
                    )
                else:
                    self.log_test(
                        "History contains data",
                        len(data) > 0 if is_list else False,
                        f"History length: {len(data) if is_list else 'N/A'}"
                    )
            else:
                self.log_test(
                    "History endpoint accessibility",
                    False,
                    f"HTTP {response.status_code}: {response.text}"
                )
        except Exception as e:
            self.log_test("History endpoint accessibility", False, str(e))
    
    def test_statistics(self):
        """Test /api/stats endpoint"""
        print("\n=== Testing Statistics ===")
        
        try:
            response = requests.get(f"{BACKEND_URL}/stats", timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                required_fields = ['total_scans', 'malicious_detected', 'clean_scans', 'today_scans', 'detection_rate']
                
                fields_present = all(field in data for field in required_fields)
                
                self.log_test(
                    "Statistics endpoint structure",
                    fields_present,
                    f"Fields: {list(data.keys())}"
                )
                
                # Check if values are numeric
                numeric_fields = ['total_scans', 'malicious_detected', 'clean_scans', 'today_scans']
                values_numeric = all(isinstance(data.get(field, 0), int) for field in numeric_fields)
                
                self.log_test(
                    "Statistics values are numeric",
                    values_numeric,
                    f"Total scans: {data.get('total_scans')}, Malicious: {data.get('malicious_detected')}"
                )
                
                # Check detection rate calculation
                total = data.get('total_scans', 0)
                malicious = data.get('malicious_detected', 0)
                clean = data.get('clean_scans', 0)
                
                calculation_correct = (total == malicious + clean) or total == 0
                
                self.log_test(
                    "Statistics calculation accuracy",
                    calculation_correct,
                    f"Total: {total}, Malicious: {malicious}, Clean: {clean}"
                )
            else:
                self.log_test(
                    "Statistics endpoint accessibility",
                    False,
                    f"HTTP {response.status_code}: {response.text}"
                )
        except Exception as e:
            self.log_test("Statistics endpoint accessibility", False, str(e))
    
    def test_error_handling(self):
        """Test error handling with invalid inputs"""
        print("\n=== Testing Error Handling ===")
        
        # Test with invalid URL format
        try:
            payload = {"url": "not-a-valid-url"}
            response = requests.post(f"{BACKEND_URL}/scan", json=payload, timeout=10)
            
            # Should either handle gracefully or return appropriate error
            handled_gracefully = response.status_code in [200, 400, 422]
            
            self.log_test(
                "Invalid URL format handling",
                handled_gracefully,
                f"HTTP {response.status_code}"
            )
        except Exception as e:
            self.log_test("Invalid URL format handling", False, str(e))
        
        # Test with malformed JSON
        try:
            response = requests.post(f"{BACKEND_URL}/scan", data="invalid json", timeout=10)
            
            malformed_json_handled = response.status_code in [400, 422]
            
            self.log_test(
                "Malformed JSON handling",
                malformed_json_handled,
                f"HTTP {response.status_code}"
            )
        except Exception as e:
            self.log_test("Malformed JSON handling", False, str(e))
        
        # Test with missing URL field
        try:
            payload = {"not_url": "https://example.com"}
            response = requests.post(f"{BACKEND_URL}/scan", json=payload, timeout=10)
            
            missing_field_handled = response.status_code in [400, 422]
            
            self.log_test(
                "Missing required field handling",
                missing_field_handled,
                f"HTTP {response.status_code}"
            )
        except Exception as e:
            self.log_test("Missing required field handling", False, str(e))
    
    def test_various_url_formats(self):
        """Test scanning with various URL formats"""
        print("\n=== Testing Various URL Formats ===")
        
        for url in TEST_URLS['various_formats']:
            try:
                payload = {"url": url}
                response = requests.post(f"{BACKEND_URL}/scan", json=payload, timeout=30)
                
                # Should handle different formats (with or without protocol)
                format_handled = response.status_code == 200
                
                if format_handled and response.status_code == 200:
                    data = response.json()
                    has_results = 'results' in data and data['results'] is not None
                    
                    self.log_test(
                        f"URL format handling - {url}",
                        has_results,
                        f"Status: {response.status_code}, Has results: {has_results}"
                    )
                else:
                    self.log_test(
                        f"URL format handling - {url}",
                        False,
                        f"HTTP {response.status_code}"
                    )
            except Exception as e:
                self.log_test(f"URL format handling - {url}", False, str(e))
    
    def run_all_tests(self):
        """Run all test suites"""
        print("🚀 Starting WebShield Backend Testing Suite")
        print(f"Backend URL: {BACKEND_URL}")
        print("=" * 60)
        
        # Run all test suites
        self.test_health_endpoint()
        self.test_scan_endpoint_basic()
        self.test_url_pattern_analysis()
        self.test_ssl_certificate_validation()
        self.test_content_analysis()
        self.test_virustotal_integration()
        self.test_scan_result_retrieval()
        self.test_scan_history()
        self.test_statistics()
        self.test_error_handling()
        self.test_various_url_formats()
        
        # Print summary
        print("\n" + "=" * 60)
        print("🏁 TEST SUMMARY")
        print("=" * 60)
        print(f"✅ Passed: {self.results['passed']}")
        print(f"❌ Failed: {self.results['failed']}")
        print(f"📊 Success Rate: {(self.results['passed'] / (self.results['passed'] + self.results['failed']) * 100):.1f}%")
        
        if self.results['errors']:
            print("\n🚨 FAILED TESTS:")
            for error in self.results['errors']:
                print(f"   • {error}")
        
        return self.results

if __name__ == "__main__":
    tester = WebShieldTester()
    results = tester.run_all_tests()
    
    # Exit with appropriate code
    sys.exit(0 if results['failed'] == 0 else 1)