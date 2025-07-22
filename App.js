import React, { useState, useEffect } from 'react';
import './App.css';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL || 'http://localhost:8001';

function App() {
  const [url, setUrl] = useState('');
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [history, setHistory] = useState([]);
  const [stats, setStats] = useState(null);
  const [activeTab, setActiveTab] = useState('scan');

  useEffect(() => {
    loadStats();
    if (activeTab === 'history') {
      loadHistory();
    }
  }, [activeTab]);

  const loadStats = async () => {
    try {
      const response = await fetch(`${BACKEND_URL}/api/stats`);
      if (response.ok) {
        const data = await response.json();
        setStats(data);
      }
    } catch (error) {
      console.error('Error loading stats:', error);
    }
  };

  const loadHistory = async () => {
    try {
      const response = await fetch(`${BACKEND_URL}/api/history`);
      if (response.ok) {
        const data = await response.json();
        setHistory(data);
      }
    } catch (error) {
      console.error('Error loading history:', error);
    }
  };

  const handleScan = async () => {
    if (!url.trim()) {
      setError('Please enter a URL to scan');
      return;
    }

    setScanning(true);
    setError('');
    setResult(null);

    try {
      const response = await fetch(`${BACKEND_URL}/api/scan`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url: url.trim() }),
      });

      if (response.ok) {
        const data = await response.json();
        setResult(data);
        loadStats(); // Update stats after scan
      } else {
        const errorData = await response.json();
        setError(errorData.detail || 'Scan failed');
      }
    } catch (error) {
      setError('Network error. Please try again.');
      console.error('Scan error:', error);
    } finally {
      setScanning(false);
    }
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter') {
      handleScan();
    }
  };

  const getThreatLevelColor = (level) => {
    switch (level) {
      case 'high': return 'text-red-600 bg-red-100';
      case 'medium': return 'text-yellow-600 bg-yellow-100';
      case 'low': return 'text-green-600 bg-green-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  const getThreatIcon = (level) => {
    switch (level) {
      case 'high': return '🚨';
      case 'medium': return '⚠️';
      case 'low': return '✅';
      default: return '❓';
    }
  };

  const formatTimestamp = (timestamp) => {
    return new Date(timestamp).toLocaleString();
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100">
      {/* Header */}
      <header className="bg-white shadow-lg">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-6">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <h1 className="text-3xl font-bold text-gray-900">
                  🛡️ WebShield
                </h1>
              </div>
              <div className="ml-4">
                <p className="text-sm text-gray-600">
                  Real-time Fake Website & Malware Detection
                </p>
              </div>
            </div>
            
            {/* Stats Display */}
            {stats && (
              <div className="flex space-x-6 text-sm">
                <div className="text-center">
                  <div className="text-2xl font-bold text-blue-600">{stats.total_scans}</div>
                  <div className="text-gray-600">Total Scans</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-red-600">{stats.malicious_detected}</div>
                  <div className="text-gray-600">Threats Blocked</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-green-600">{stats.clean_scans}</div>
                  <div className="text-gray-600">Clean Sites</div>
                </div>
              </div>
            )}
          </div>
        </div>
      </header>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Navigation Tabs */}
        <div className="flex space-x-1 mb-8">
          <button
            onClick={() => setActiveTab('scan')}
            className={`px-4 py-2 rounded-lg font-medium transition-colors ${
              activeTab === 'scan'
                ? 'bg-blue-600 text-white'
                : 'bg-white text-gray-700 hover:bg-gray-50'
            }`}
          >
            🔍 URL Scanner
          </button>
          <button
            onClick={() => setActiveTab('history')}
            className={`px-4 py-2 rounded-lg font-medium transition-colors ${
              activeTab === 'history'
                ? 'bg-blue-600 text-white'
                : 'bg-white text-gray-700 hover:bg-gray-50'
            }`}
          >
            📊 Scan History
          </button>
        </div>

        {/* URL Scanner Tab */}
        {activeTab === 'scan' && (
          <div className="space-y-8">
            {/* Scanner Input */}
            <div className="bg-white rounded-xl shadow-lg p-8">
              <h2 className="text-2xl font-bold text-gray-900 mb-6">
                🔍 Scan URL for Threats
              </h2>
              
              <div className="flex space-x-4">
                <input
                  type="text"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  onKeyPress={handleKeyPress}
                  placeholder="Enter URL to scan (e.g., https://example.com)"
                  className="flex-1 px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  disabled={scanning}
                />
                <button
                  onClick={handleScan}
                  disabled={scanning}
                  className="px-8 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed font-medium transition-colors"
                >
                  {scanning ? (
                    <div className="flex items-center space-x-2">
                      <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white"></div>
                      <span>Scanning...</span>
                    </div>
                  ) : (
                    'Scan URL'
                  )}
                </button>
              </div>

              {error && (
                <div className="mt-4 p-4 bg-red-50 border border-red-200 rounded-lg">
                  <p className="text-red-800">{error}</p>
                </div>
              )}
            </div>

            {/* Scan Results */}
            {result && result.results && (
              <div className="bg-white rounded-xl shadow-lg p-8">
                <h3 className="text-2xl font-bold text-gray-900 mb-6">
                  📋 Scan Results
                </h3>
                
                {/* Overall Threat Level */}
                <div className="mb-8">
                  <div className={`inline-flex items-center px-6 py-3 rounded-full ${getThreatLevelColor(result.results.threat_level)}`}>
                    <span className="text-2xl mr-2">{getThreatIcon(result.results.threat_level)}</span>
                    <span className="text-lg font-bold capitalize">
                      {result.results.threat_level} Risk
                    </span>
                  </div>
                  
                  <div className="mt-4 text-gray-600">
                    <p>URL: <span className="font-mono bg-gray-100 px-2 py-1 rounded">{result.results.url}</span></p>
                    <p>Scanned: {formatTimestamp(result.results.scan_timestamp)}</p>
                  </div>
                </div>

                {/* Detection Summary */}
                <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
                  <div className="bg-red-50 p-4 rounded-lg">
                    <div className="text-2xl font-bold text-red-600">{result.results.malicious_count}</div>
                    <div className="text-sm text-red-800">Malicious Detections</div>
                  </div>
                  <div className="bg-yellow-50 p-4 rounded-lg">
                    <div className="text-2xl font-bold text-yellow-600">{result.results.suspicious_count}</div>
                    <div className="text-sm text-yellow-800">Suspicious Detections</div>
                  </div>
                  <div className="bg-blue-50 p-4 rounded-lg">
                    <div className="text-2xl font-bold text-blue-600">{result.results.total_engines}</div>
                    <div className="text-sm text-blue-800">Total Engines</div>
                  </div>
                  <div className="bg-green-50 p-4 rounded-lg">
                    <div className="text-2xl font-bold text-green-600">{result.results.ssl_valid ? 'Valid' : 'Invalid'}</div>
                    <div className="text-sm text-green-800">SSL Certificate</div>
                  </div>
                </div>

                {/* Detailed Analysis */}
                <div className="space-y-6">
                  {/* URL Analysis */}
                  {result.results.detection_details.url_analysis && (
                    <div className="border rounded-lg p-4">
                      <h4 className="font-bold text-lg mb-2">🔗 URL Analysis</h4>
                      <div className="text-sm space-y-2">
                        <p><strong>Domain:</strong> {result.results.detection_details.url_analysis.domain}</p>
                        <p><strong>Suspicious Score:</strong> {result.results.detection_details.url_analysis.suspicious_score}</p>
                        {result.results.detection_details.url_analysis.detected_issues && result.results.detection_details.url_analysis.detected_issues.length > 0 && (
                          <div>
                            <strong>Issues Detected:</strong>
                            <ul className="list-disc list-inside ml-4 mt-1">
                              {result.results.detection_details.url_analysis.detected_issues.map((issue, index) => (
                                <li key={index} className="text-red-600">{issue}</li>
                              ))}
                            </ul>
                          </div>
                        )}
                      </div>
                    </div>
                  )}

                  {/* Content Analysis */}
                  {result.results.detection_details.content_analysis && (
                    <div className="border rounded-lg p-4">
                      <h4 className="font-bold text-lg mb-2">📄 Content Analysis</h4>
                      <div className="text-sm space-y-2">
                        <p><strong>Phishing Score:</strong> {result.results.detection_details.content_analysis.phishing_score}</p>
                        <p><strong>Suspicious:</strong> {result.results.detection_details.content_analysis.is_suspicious ? 'Yes' : 'No'}</p>
                        {result.results.detection_details.content_analysis.detected_indicators && result.results.detection_details.content_analysis.detected_indicators.length > 0 && (
                          <div>
                            <strong>Indicators:</strong>
                            <ul className="list-disc list-inside ml-4 mt-1">
                              {result.results.detection_details.content_analysis.detected_indicators.map((indicator, index) => (
                                <li key={index} className="text-yellow-600">{indicator}</li>
                              ))}
                            </ul>
                          </div>
                        )}
                      </div>
                    </div>
                  )}

                  {/* SSL Analysis */}
                  {result.results.detection_details.ssl_analysis && (
                    <div className="border rounded-lg p-4">
                      <h4 className="font-bold text-lg mb-2">🔒 SSL Certificate</h4>
                      <div className="text-sm space-y-2">
                        <p><strong>Valid:</strong> {result.results.detection_details.ssl_analysis.valid ? 'Yes' : 'No'}</p>
                        {result.results.detection_details.ssl_analysis.issuer && (
                          <p><strong>Issuer:</strong> {result.results.detection_details.ssl_analysis.issuer.organizationName || 'Unknown'}</p>
                        )}
                        {result.results.detection_details.ssl_analysis.expires && (
                          <p><strong>Expires:</strong> {result.results.detection_details.ssl_analysis.expires}</p>
                        )}
                        {result.results.detection_details.ssl_analysis.error && (
                          <p className="text-red-600"><strong>Error:</strong> {result.results.detection_details.ssl_analysis.error}</p>
                        )}
                      </div>
                    </div>
                  )}

                  {/* VirusTotal Analysis */}
                  {result.results.detection_details.virustotal_analysis && (
                    <div className="border rounded-lg p-4">
                      <h4 className="font-bold text-lg mb-2">🦠 VirusTotal Analysis</h4>
                      <div className="text-sm space-y-2">
                        {result.results.detection_details.virustotal_analysis.engines_results && (
                          <div>
                            <strong>Engine Results:</strong>
                            <div className="mt-2 max-h-40 overflow-y-auto">
                              {Object.entries(result.results.detection_details.virustotal_analysis.engines_results).map(([engine, result]) => (
                                <div key={engine} className="flex justify-between py-1 px-2 hover:bg-gray-50">
                                  <span>{engine}</span>
                                  <span className={`font-medium ${
                                    result.category === 'malicious' ? 'text-red-600' : 
                                    result.category === 'suspicious' ? 'text-yellow-600' : 
                                    'text-green-600'
                                  }`}>
                                    {result.category}
                                  </span>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                        {result.results.detection_details.virustotal_analysis.error && (
                          <p className="text-red-600"><strong>Error:</strong> {result.results.detection_details.virustotal_analysis.error}</p>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        )}

        {/* History Tab */}
        {activeTab === 'history' && (
          <div className="bg-white rounded-xl shadow-lg p-8">
            <h2 className="text-2xl font-bold text-gray-900 mb-6">
              📊 Scan History
            </h2>
            
            {history.length === 0 ? (
              <p className="text-gray-500 text-center py-8">No scan history available</p>
            ) : (
              <div className="space-y-4">
                {history.map((scan, index) => (
                  <div key={index} className="border rounded-lg p-4 hover:bg-gray-50 transition-colors">
                    <div className="flex justify-between items-start">
                      <div className="flex-1">
                        <p className="font-mono text-sm text-gray-600 mb-1">{scan.url}</p>
                        <p className="text-xs text-gray-500">{formatTimestamp(scan.created_at)}</p>
                      </div>
                      <div className="ml-4">
                        {scan.results && (
                          <div className={`inline-flex items-center px-3 py-1 rounded-full text-sm ${getThreatLevelColor(scan.results.threat_level)}`}>
                            <span className="mr-1">{getThreatIcon(scan.results.threat_level)}</span>
                            <span className="capitalize">{scan.results.threat_level}</span>
                          </div>
                        )}
                        {scan.status === 'processing' && (
                          <div className="inline-flex items-center px-3 py-1 rounded-full text-sm bg-blue-100 text-blue-600">
                            <span className="mr-1">⏳</span>
                            <span>Processing</span>
                          </div>
                        )}
                      </div>
                    </div>
                    
                    {scan.results && (
                      <div className="mt-3 grid grid-cols-3 gap-4 text-sm">
                        <div>
                          <span className="text-gray-500">Malicious:</span>
                          <span className="ml-1 font-medium text-red-600">{scan.results.malicious_count}</span>
                        </div>
                        <div>
                          <span className="text-gray-500">Suspicious:</span>
                          <span className="ml-1 font-medium text-yellow-600">{scan.results.suspicious_count}</span>
                        </div>
                        <div>
                          <span className="text-gray-500">Engines:</span>
                          <span className="ml-1 font-medium text-blue-600">{scan.results.total_engines}</span>
                        </div>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Footer */}
      <footer className="bg-gray-800 text-white py-8 mt-12">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center">
            <h3 className="text-lg font-semibold mb-2">🛡️ WebShield</h3>
            <p className="text-gray-400">
              Protecting users from phishing, scam, and malware websites through real-time detection
            </p>
            <div className="mt-4 flex justify-center space-x-6 text-sm">
              <span>✅ URL Pattern Analysis</span>
              <span>✅ Content Analysis</span>
              <span>✅ SSL Validation</span>
              <span>✅ VirusTotal Integration</span>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default App;