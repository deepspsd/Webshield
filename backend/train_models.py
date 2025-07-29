#!/usr/bin/env python3
"""
ML Models Training Script for WebShield
Trains URL and content classifiers with sample data
"""

import sys
import os
import logging
from pathlib import Path

# Add the ml_models directory to the path
sys.path.append(str(Path(__file__).parent))

from url_classifier import URLThreatClassifier, generate_training_data
from content_analyzer import ContentPhishingDetector, generate_content_training_data
from ml_integration import MLSecurityEngine

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def train_url_classifier():
    """Train the URL classifier with sample data"""
    logger.info("Training URL classifier...")
    
    # Generate training data
    urls, labels = generate_training_data()
    
    # Create and train classifier
    classifier = URLThreatClassifier()
    classifier.train(urls, labels)
    
    # Save the model
    models_dir = Path("ml_models/saved_models")
    models_dir.mkdir(parents=True, exist_ok=True)
    classifier.save_model(str(models_dir / "url_classifier.joblib"))
    
    logger.info("URL classifier training completed!")
    return classifier

def train_content_detector():
    """Train the content detector with sample data"""
    logger.info("Training content detector...")
    
    # Generate training data
    content_samples, labels = generate_content_training_data()
    
    # Create and train detector
    detector = ContentPhishingDetector()
    detector.train(content_samples, labels, content_type='html')
    
    # Save the model
    models_dir = Path("ml_models/saved_models")
    models_dir.mkdir(parents=True, exist_ok=True)
    detector.save_model(str(models_dir / "content_detector.joblib"))
    
    logger.info("Content detector training completed!")
    return detector

def test_models():
    """Test the trained models with sample URLs and content"""
    logger.info("Testing trained models...")
    
    # Test URLs
    test_urls = [
        "https://google.com",  # Safe
        "https://g00gle.com/verify",  # Malicious
        "https://facebook.com",  # Safe
        "http://192.168.1.1/login",  # Malicious
        "https://paypal-secure-verify.tk",  # Malicious
        "https://github.com",  # Safe
    ]
    
    # Test content
    test_content = [
        """
        <html>
        <body>
            <h1>Welcome to Google</h1>
            <p>Sign in to your Google account.</p>
            <form action="https://accounts.google.com">
                <input type="email" placeholder="Email">
                <button>Sign in</button>
            </form>
        </body>
        </html>
        """,  # Safe
        """
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
        """,  # Malicious
    ]
    
    # Test URL classifier
    url_classifier = URLThreatClassifier()
    url_classifier.load_model("ml_models/saved_models/url_classifier.joblib")
    
    print("\n=== URL Classifier Test Results ===")
    for url in test_urls:
        result = url_classifier.predict(url)
        print(f"URL: {url}")
        print(f"  Threat probability: {result['threat_probability']:.4f}")
        print(f"  Prediction: {'MALICIOUS' if result['prediction'] else 'SAFE'}")
        print(f"  Confidence: {result['confidence']:.4f}")
        print()
    
    # Test content detector
    content_detector = ContentPhishingDetector()
    content_detector.load_model("ml_models/saved_models/content_detector.joblib")
    
    print("\n=== Content Detector Test Results ===")
    for i, content in enumerate(test_content):
        result = content_detector.predict(content, content_type='html')
        print(f"Content {i+1}:")
        print(f"  Phishing probability: {result['phishing_probability']:.4f}")
        print(f"  Prediction: {'PHISHING' if result['prediction'] else 'LEGITIMATE'}")
        print(f"  Confidence: {result['confidence']:.4f}")
        print()

def main():
    """Main training function"""
    logger.info("Starting ML models training...")
    
    try:
        # Train URL classifier
        url_classifier = train_url_classifier()
        
        # Train content detector
        content_detector = train_content_detector()
        
        # Test the models
        test_models()
        
        # Test the integrated ML engine
        logger.info("Testing integrated ML engine...")
        engine = MLSecurityEngine()
        
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
        
        # Test integrated analysis
        result = engine.analyze_url_ml(test_url)
        print(f"\n=== Integrated ML Engine Test ===")
        print(f"URL: {test_url}")
        print(f"ML enabled: {result.get('ml_enabled', False)}")
        print(f"Threat probability: {result.get('threat_probability', 0):.4f}")
        print(f"Confidence: {result.get('confidence', 0):.4f}")
        
        content_result = engine.analyze_content_ml(test_content)
        print(f"\nContent analysis:")
        print(f"ML enabled: {content_result.get('ml_enabled', False)}")
        print(f"Phishing probability: {content_result.get('phishing_probability', 0):.4f}")
        print(f"Confidence: {content_result.get('confidence', 0):.4f}")
        
        # Test combined analysis
        combined = engine.get_combined_threat_score(result, content_result)
        print(f"\nCombined analysis:")
        print(f"Combined threat score: {combined['combined_threat_score']:.4f}")
        print(f"Threat level: {combined['threat_level']}")
        print(f"Overall confidence: {combined['confidence']:.4f}")
        print(f"ML enabled: {combined['ml_enabled']}")
        
        logger.info("ML models training and testing completed successfully!")
        
    except Exception as e:
        logger.error(f"Training failed: {e}")
        return False
    
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 
