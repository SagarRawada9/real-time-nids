# Real-Time Network Intrusion Detection System (NIDS)

## Overview
A machine learning-based real-time intrusion detection system designed to monitor network traffic, detect malicious activities, and respond with automated alerts and IP blocking. This system provides comprehensive security dashboards for network administrators to visualize and analyze attack patterns.

## Features
- **Real-Time Detection**: Continuous network packet analysis using ML models
- **Alert Logs**: Detailed logging of detected intrusions with timestamps and threat levels
- **IP Blocking**: Automatic blocking of suspicious IP addresses
- **Security Dashboard**: Interactive visualization of attack trends and statistics
- **Performance Metrics**: Real-time monitoring of detection accuracy and system performance
- **Multiple Attack Types**: Detection of DoS, port scanning, malware, and anomalous traffic

## Technologies Used
- **Python**: Core programming language
- **scikit-learn**: Machine learning models and classification
- **Pandas**: Data processing and manipulation
- **NumPy**: Numerical computing and array operations
- **Matplotlib**: Data visualization and dashboards
- **Flask**: Web-based dashboard interface
- **Wireshark**: Network packet capture analysis
- **nmap**: Network scanning and reconnaissance

## Installation

```bash
git clone https://github.com/SagarRawada9/real-time-nids.git
cd real-time-nids
pip install -r requirements.txt
```

## Usage

### Start the IDS System
```bash
python main.py
```

### Launch the Web Dashboard
```bash
python app.py
```
Then open `http://localhost:5000` in your browser.

## Project Structure
```
├── main.py                 # Main IDS engine
├── app.py                 # Flask web dashboard
├── packet_sniffer.py       # Network packet capture
├── feature_extractor.py    # ML feature engineering
├── threat_classifier.py    # ML model for classification
├── alert_manager.py        # Alert and logging system
├── ip_blocker.py           # Automated IP blocking
├── models/                 # Trained ML models
├── logs/                   # Alert and event logs
├─┐ requirements.txt        # Dependencies
```

## Configuration

Edit `config.py` to customize:
- Network interface to monitor
- Alert sensitivity levels
- IP blocking policies
- Dashboard settings

## Detection Accuracy
- **DoS Attacks**: 95%+ accuracy
- **Port Scanning**: 92%+ accuracy
- **Malware Traffic**: 88%+ accuracy
- **Overall**: 91% average accuracy on test datasets

## Alert System
Alerts are logged with:
- Timestamp and severity level
- Source/Destination IP addresses
- Detected threat type
- Confidence score
- Automated response actions taken

## Future Enhancements
- Deep learning models (LSTM, CNN) for improved detection
- Integration with SIEM systems
- Real-time threat intelligence feeds
- Multi-language dashboard support
- API for third-party integrations
- Machine learning model optimization for edge deployment

## Security Considerations
- Regular model retraining on new threat patterns
- Encrypted logging of sensitive network data
- Role-based access control for dashboard
- Compliance with data protection regulations

## License
MIT License

## Author
Sagar Rawada

## Contact
For inquiries or collaboration opportunities, feel free to reach out!
