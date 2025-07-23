# WebShield: Real-Time Malware & Phishing Detection

WebShield is a powerful web application designed to protect users from online threats by providing real-time detection of malicious websites, phishing scams, and malware. It offers a user-friendly interface for scanning URLs and provides detailed analysis reports to help users make informed decisions about their online safety.

## 🚀 Key Features

- **Real-Time URL Scanning**: Instantly scan any URL to check for potential threats
- **Comprehensive Threat Analysis**: Utilizes a multi-faceted approach for detection:
  - **VirusTotal Integration**: Leverages the power of over 90 antivirus scanners and URL/domain blocklisting services
  - **URL Pattern Analysis**: Detects suspicious patterns such as IP addresses in hostnames, URL shorteners, and typosquatting
  - **Content Analysis**: Scans webpage content for known phishing keywords and suspicious form structures
  - **SSL Certificate Validation**: Checks for valid HTTPS encryption
- **User Authentication**: Secure user registration and login system
- **User Profiles**: Allows users to view their profile, update their profile picture, and manage account settings
- **Scan History**: Keeps a record of all scans performed by the user
- **Dashboard**: Provides a central hub for scanning URLs and viewing a summary of recent activity
- **Statistical Overview**: Displays aggregate data on total scans, threats detected, and more
- **Extension Integration**: Direct link to install the WebShield Chrome extension for seamless browser protection

## ✨ Live Demo

While a live demo isn't available in this repository, the project is designed to be fully functional when deployed. The frontend is built with HTML and Tailwind CSS, and the backend is a robust FastAPI application.

## 🛠️ Technologies Used

### Backend
- **Python 3.10+**
- **FastAPI**: For building the high-performance API
- **MySQL**: As the primary database for storing user data, scan history, and reports
- **SQLAlchemy**: For interacting with the MySQL database
- **Aiohttp**: For making asynchronous HTTP requests to external APIs
- **Passlib & Bcrypt**: For password hashing and verification
- **Uvicorn**: As the ASGI server

### Frontend
- **HTML5**
- **Tailwind CSS**: For a modern and responsive user interface
- **JavaScript**: For dynamic content and interacting with the backend API
- **Chart.js**: For visualizing scan statistics

### Browser Extension
- **Extension**: Provides real-time protection while browsing
- 1. Account Management & Sync:
  Login/logout UI in popup.html/popup.js
  Store token in chrome.storage
  Sync scan history, stats, and settings via backend API
- 2. Real-Time URL Protection:
  content.js intercepts navigation, sends URL to background.js
  background.js checks URL with backend, blocks if malicious
  Shows warning overlay, updates extension icon, supports whitelist
- 3. Smart Notifications:
  background.js uses chrome.notifications for alerts, summaries, risk scores
  options.js allows user to set notification preferences
- 4. Quick Actions:
  Context menu for scanning/reporting URLs
  Popup for quick settings and emergency disable

### Services
- **VirusTotal API**: For comprehensive threat analysis

## 🚀 Getting Started

### Prerequisites
- Python 3.10 or higher
- MySQL Server
- A VirusTotal API Key

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-username/webshield.git
   cd webshield
   ```

2. **Create a virtual environment and activate it:**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
   ```

3. **Install the required Python packages:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set up the database:**
   - Create a MySQL database named `webshield`
   - Update the `MYSQL_CONFIG` in `server.py` with your MySQL credentials, or set the following environment variables:
     ```bash
     MYSQL_HOST='your_host'
     MYSQL_PORT='3306'
     MYSQL_USER='your_user'
     MYSQL_PASSWORD='your_password'
     MYSQL_DATABASE='webshield'
     ```

5. **Configure the VirusTotal API Key:**
   - In `server.py`, replace the placeholder for `VT_API_KEY` with your actual VirusTotal API key

### Running the Application

1. **Start the backend server:**
   ```bash
   uvicorn server:app --reload --port 8001
   ```

2. **Access the application:**
   - Open your web browser and navigate to the application URL
   - Use the "Add Extension" button to install the Chrome extension for enhanced protection

## 🧪 Running Tests

The project includes a comprehensive test suite for the backend API. To run the tests:

1. Ensure the backend server is running
2. In a new terminal, run the test script:
   ```bash
   python backend_test.py
   ```

## 📜 API Endpoints

The core of the application is the FastAPI backend. Here are the main API endpoints:

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/register` | Register a new user |
| POST | `/api/login` | Log in an existing user |
| POST | `/api/scan` | Submit a URL for scanning |
| GET | `/api/scan/{scan_id}` | Retrieve the results of a specific scan |
| GET | `/api/history` | Get the user's scan history |
| GET | `/api/stats` | Get overall scan statistics |
| GET | `/api/health` | Check the health of the API and its dependencies |
| POST | `/api/upload_profile_photo` | Upload a user profile picture |
| GET | `/api/get_user` | Get user details by email |

For detailed request and response models, please refer to the `server.py` file.

## 🤝 Contributing

Contributions are welcome! If you'd like to contribute, please follow these steps:

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a new Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Thanks to the developers of all the open-source libraries used in this project
- Special thanks to VirusTotal for their invaluable API

---

*Built with ❤️ for web security*
