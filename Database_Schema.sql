-- WebShield Project Database Schema

-- Table: scans
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
);

-- Table: users
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    name VARCHAR(255),
    profile_pic VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table: threat_reports
CREATE TABLE IF NOT EXISTS threat_reports (
    id INT AUTO_INCREMENT PRIMARY KEY,
    scan_id VARCHAR(255) NOT NULL,
    url TEXT NOT NULL,
    threat_type VARCHAR(100),
    severity_score INT DEFAULT 0,
    details JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
);

-- Table: scan_statistics
CREATE TABLE IF NOT EXISTS scan_statistics (
    id INT AUTO_INCREMENT PRIMARY KEY,
    date DATE DEFAULT (CURRENT_DATE),
    total_scans INT DEFAULT 0,
    malicious_detected INT DEFAULT 0,
    clean_scans INT DEFAULT 0,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY unique_date (date)
);

-- Indexes for performance
CREATE INDEX idx_scans_created_at ON scans(created_at);
CREATE INDEX idx_scans_scan_id ON scans(scan_id); 
