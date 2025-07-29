import os
import logging
from typing import Dict, Any, Optional
import joblib
from pathlib import Path
import re # Added missing import for re

# Import our ML models
try:
    from .url_classifier import URLThreatClassifier
    from .content_analyzer import ContentPhishingDetector
except ImportError:
    # Fallback for direct imports
    from url_classifier import URLThreatClassifier
    from content_analyzer import ContentPhishingDetector

logger = logging.getLogger(__name__)

class MLSecurityEngine:
    """Main ML security engine that integrates all ML models"""
    
    def __init__(self, models_dir: str = "ml_models/saved_models"):
        self.models_dir = Path(models_dir)
        self.models_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize ML models
        self.url_classifier = URLThreatClassifier()
        self.content_detector = ContentPhishingDetector()
        
        # Load pre-trained models if available
        self._load_models()
        
        # ML confidence thresholds
        self.url_threshold = 0.6
        self.content_threshold = 0.7
        
    def _load_models(self):
        """Load pre-trained models from disk"""
        try:
            url_model_path = self.models_dir / "url_classifier.joblib"
            if url_model_path.exists():
                self.url_classifier.load_model(str(url_model_path))
                logger.info("Loaded pre-trained URL classifier")
            
            content_model_path = self.models_dir / "content_detector.joblib"
            if content_model_path.exists():
                self.content_detector.load_model(str(content_model_path))
                logger.info("Loaded pre-trained content detector")
                
        except Exception as e:
            logger.warning(f"Could not load pre-trained models: {e}")
            logger.info("Will use rule-based detection until models are trained")
    
    def analyze_url_ml(self, url: str) -> Dict[str, Any]:
        """Analyze URL using ML models"""
        try:
            if self.url_classifier.is_trained:
                url_result = self.url_classifier.predict(url)
                return {
                    'ml_enabled': True,
                    'threat_probability': url_result['threat_probability'],
                    'confidence': url_result['confidence'],
                    'prediction': url_result['prediction'],
                    'explanation': url_result['explanation'],
                    'features': url_result['features']
                }
            else:
                # Fallback to rule-based detection
                return self._rule_based_url_analysis(url)
        except Exception as e:
            logger.error(f"ML URL analysis failed: {e}")
            return self._rule_based_url_analysis(url)
    
    def analyze_content_ml(self, html_content: str) -> Dict[str, Any]:
        """Analyze HTML content using ML models"""
        try:
            if self.content_detector.is_trained:
                content_result = self.content_detector.predict(html_content, content_type='html')
                return {
                    'ml_enabled': True,
                    'phishing_probability': content_result['phishing_probability'],
                    'confidence': content_result['confidence'],
                    'prediction': content_result['prediction'],
                    'explanation': content_result['explanation'],
                    'features': content_result['features']
                }
            else:
                # Fallback to rule-based detection
                return self._rule_based_content_analysis(html_content)
        except Exception as e:
            logger.error(f"ML content analysis failed: {e}")
            return self._rule_based_content_analysis(html_content)
    
    def _rule_based_url_analysis(self, url: str) -> Dict[str, Any]:
        """Fallback rule-based URL analysis"""
        suspicious_score = 0
        detected_issues = []
        
        # Basic suspicious patterns
        suspicious_patterns = [
            (r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', 30, "Uses IP address"),
            (r'[a-zA-Z0-9]+-[a-zA-Z0-9]+-[a-zA-Z0-9]+\.', 15, "Multiple hyphens"),
            (r'(bit\.ly|tinyurl|short|goo\.gl|t\.co)', 20, "URL shortener"),
            (r'(secure|login|bank|verify|update|confirm).*[0-9]+', 25, "Suspicious keywords with numbers")
        ]
        
        for pattern, score, description in suspicious_patterns:
            if re.search(pattern, url):
                suspicious_score += score
                detected_issues.append(description)
        
        # Suspicious TLDs
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.info', '.click']
        for tld in suspicious_tlds:
            if tld in url.lower():
                suspicious_score += 20
                detected_issues.append(f"Uses suspicious TLD: {tld}")
        
        threat_probability = min(suspicious_score / 100.0, 1.0)
        
        return {
            'ml_enabled': False,
            'threat_probability': threat_probability,
            'confidence': 0.5,  # Lower confidence for rule-based
            'prediction': int(threat_probability > 0.5),
            'detected_issues': detected_issues,
            'suspicious_score': suspicious_score
        }
    
    def _rule_based_content_analysis(self, html_content: str) -> Dict[str, Any]:
        """Fallback rule-based content analysis"""
        content_lower = html_content.lower()
        phishing_score = 0
        detected_indicators = []
        
        # Phishing keywords
        phishing_keywords = [
            'verify', 'suspend', 'suspended', 'limited', 'restriction', 'restricted',
            'confirm', 'update', 'unlock', 'locked', 'expire', 'expired', 'urgent',
            'immediately', 'immediate', 'alert'
        ]
        
        for keyword in phishing_keywords:
            if keyword in content_lower:
                phishing_score += 5
                detected_indicators.append(f"Phishing keyword: {keyword}")
        
        # Suspicious forms
        if re.search(r'<form[^>]*action\s*=\s*["\']?(?:https?://)?[^/"\']*["\']?', html_content):
            if 'password' in content_lower or 'login' in content_lower:
                phishing_score += 15
                detected_indicators.append("Suspicious login form detected")
        
        # Fake security badges
        if re.search(r'(norton|mcafee|verisign|ssl|secure)', content_lower):
            phishing_score += 10
            detected_indicators.append("Fake security badges detected")
        
        phishing_probability = min(phishing_score / 50.0, 1.0)
        
        return {
            'ml_enabled': False,
            'phishing_probability': phishing_probability,
            'confidence': 0.5,  # Lower confidence for rule-based
            'prediction': int(phishing_probability > 0.5),
            'detected_indicators': detected_indicators,
            'phishing_score': phishing_score
        }
    
    def get_combined_threat_score(self, url_result: Dict[str, Any], content_result: Dict[str, Any]) -> Dict[str, Any]:
        """Combine URL and content analysis results"""
        # Weight the results (URL analysis is more reliable)
        url_weight = 0.6
        content_weight = 0.4
        
        # Calculate weighted threat probability
        url_threat = url_result.get('threat_probability', 0)
        content_threat = content_result.get('phishing_probability', 0)
        
        combined_threat = (url_threat * url_weight) + (content_threat * content_weight)
        
        # Determine overall threat level
        if combined_threat > 0.8:
            threat_level = 'high'
        elif combined_threat > 0.5:
            threat_level = 'medium'
        else:
            threat_level = 'low'
        
        # Calculate confidence (weighted average)
        url_confidence = url_result.get('confidence', 0.5)
        content_confidence = content_result.get('confidence', 0.5)
        combined_confidence = (url_confidence * url_weight) + (content_confidence * content_weight)
        
        return {
            'combined_threat_score': combined_threat,
            'threat_level': threat_level,
            'confidence': combined_confidence,
            'is_malicious': combined_threat > 0.5,
            'url_analysis': url_result,
            'content_analysis': content_result,
            'ml_enabled': url_result.get('ml_enabled', False) or content_result.get('ml_enabled', False)
        }
    
    def train_models(self, training_data: Dict[str, Any]):
        """Train ML models with provided data"""
        try:
            # Train URL classifier
            if 'urls' in training_data and 'url_labels' in training_data:
                logger.info("Training URL classifier...")
                self.url_classifier.train(training_data['urls'], training_data['url_labels'])
                self.url_classifier.save_model(str(self.models_dir / "url_classifier.joblib"))
            
            # Train content detector
            if 'content_samples' in training_data and 'content_labels' in training_data:
                logger.info("Training content detector...")
                self.content_detector.train(
                    training_data['content_samples'], 
                    training_data['content_labels'],
                    content_type='html'
                )
                self.content_detector.save_model(str(self.models_dir / "content_detector.joblib"))
            
            logger.info("ML models training completed successfully")
            return True
            
        except Exception as e:
            logger.error(f"ML models training failed: {e}")
            return False
    
    def get_model_status(self) -> Dict[str, Any]:
        """Get status of ML models"""
        return {
            'url_classifier_trained': self.url_classifier.is_trained,
            'content_detector_trained': self.content_detector.is_trained,
            'models_dir': str(self.models_dir),
            'url_model_path': str(self.models_dir / "url_classifier.joblib"),
            'content_model_path': str(self.models_dir / "content_detector.joblib")
        }


# Global ML engine instance
ml_engine = None

def get_ml_engine() -> MLSecurityEngine:
    """Get or create the global ML engine instance"""
    global ml_engine
    if ml_engine is None:
        ml_engine = MLSecurityEngine()
    return ml_engine


# Example usage and integration
def integrate_ml_with_scan(url: str, html_content: str = "") -> Dict[str, Any]:
    """Integrate ML analysis with existing scan functionality"""
    engine = get_ml_engine()
    
    # Analyze URL
    url_result = engine.analyze_url_ml(url)
    
    # Analyze content if available
    content_result = {}
    if html_content:
        content_result = engine.analyze_content_ml(html_content)
    
    # Combine results
    combined_result = engine.get_combined_threat_score(url_result, content_result)
    
    return {
        'url_analysis': url_result,
        'content_analysis': content_result,
        'combined_result': combined_result,
        'ml_enabled': combined_result['ml_enabled']
    }


if __name__ == "__main__":
    # Example usage
    engine = get_ml_engine()
    
    # Test with sample data
    test_url = "https://g00gle.com/verify"
    test_content = """
    <html>
    <body>
        <h1>URGENT: Account Suspended!</h1>
        <p>Your account has been suspended. Verify now!</p>
        <form action="http://fake-verify.com">
            <input type="password" placeholder="Password">
            <button>VERIFY</button>
        </form>
    </body>
    </html>
    """
    
    result = integrate_ml_with_scan(test_url, test_content)
    print("ML Analysis Result:")
    print(f"Combined threat score: {result['combined_result']['combined_threat_score']:.4f}")
    print(f"Threat level: {result['combined_result']['threat_level']}")
    print(f"ML enabled: {result['combined_result']['ml_enabled']}")
    print(f"Confidence: {result['combined_result']['confidence']:.4f}") 
