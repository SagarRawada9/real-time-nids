# Real-Time Network Intrusion Detection System (NIDS)

Also known as **NIDS v2** - A Lightweight Network Intrusion Detection System

## Overview
A machine learning-based real-time intrusion detection system designed to monitor network traffic, detect malicious activities, and respond with automated alerts and IP blocking. This system provides comprehensive security dashboards for network administrators to visualize and analyze attack patterns. Built with CPU-efficient models, a Flask web dashboard, and pre-trained artifacts for quick demo setup.

## Key Features

### Real-Time Detection
- Continuous network packet analysis using machine learning models
- Multi-class attack detection (DoS, Brute Force, Port Scanning, Web Attacks, etc.)
- Real-time threat scoring and classification

### Alert Management
- Detailed logging of detected intrusions with timestamps and threat levels
- Source/Destination IP tracking for correlation analysis
- Confidence scores for detection accuracy assessment
- Alert export functionality (CSV format)

### IP Blocking
- Automatic blocking of suspicious IP addresses
- Mock endpoint for firewall rule integration
- Extensible for real firewall integration
- Block list management and visualization

### Security Dashboard
- Interactive web-based visualization of attack trends and statistics
- Live event stream monitoring with real-time updates
- Attack type distribution and time-series analysis
- Model performance metrics and detection accuracy tracking

### Machine Learning
- **Train & Compare Models**: Random Forest, LightGBM, and Logistic Regression
- **Preprocessing Artifacts**: Automatic saving of scaler and label encoder
- **Best Model Selection**: Automatic identification and saving of top-performing model
- **Visual Evaluation**: Confusion matrices, feature correlation, model comparison charts

## Repository Structure

```
real-time-nids/
├── app.py                       # Flask dashboard + REST endpoints + mock LLM report
├── capture.py                   # Live capture (pyshark) + demo traffic generator
├── train.py                     # Train, evaluate, compare models; save best
├── requirements.txt             # Python dependencies
├── data/
│   └── CICIDS2017_sample.csv   # Sample flows (56k rows, 78 features)
├── models/
│   ├── rf_final.pkl            # Trained Random Forest model
│   ├── scaler.pkl              # Feature scaler for preprocessing
│   └── label_encoder.pkl       # Label encoder for attack classes
├── results/                     # Generated evaluation plots
│   ├── feature_correlation.png
│   ├── RandomForest_confusion.png
│   ├── LightGBM_confusion.png
│   ├── LogisticRegression_confusion.png
│   └── model_comparison.png
└── README.md
```

## Dataset Information

**Source**: CICIDS2017 sample dataset
- **Total Flows**: ~56,661 network flows
- **Features**: 78 flow-based numeric features
  - Flow Duration, Total Fwd/Bwd Packets, Flow Bytes/sec, Flow IAT Mean/Max/Min, etc.
- **Attack Types**: 
  - BENIGN (normal traffic)
  - DoS (Denial of Service attacks)
  - Brute Force (SSH/FTP brute force attempts)
  - Port Scanning (nmap, network reconnaissance)
  - Web Attack (SQL injection, XSS, etc.)
  - Infiltration (slow network infiltration)
  - Botnet traffic
  - And other malicious traffic patterns

## Quick Start - Run Demo (No Capture Hardware Required)

### 1. Setup Environment

```bash
# Clone or navigate to project directory
cd real-time-nids

# Create virtual environment
python -m venv .venv

# Activate virtual environment
source .venv/bin/activate          # macOS / Linux
.\venv\Scripts\activate            # Windows PowerShell

# Upgrade pip and install core dependencies
pip install --upgrade pip
pip install flask scikit-learn lightgbm joblib pandas numpy matplotlib seaborn

# Optional: Install for live packet capture (requires tshark on system)
pip install pyshark
```

### 2. Run the Flask Dashboard

```bash
python app.py
```

Open your browser at **[http://127.0.0.1:5000/](http://127.0.0.1:5000/)**

- Demo mode activates automatically if pyshark isn't available
- Use the dashboard controls to:
  - View live/demo traffic events
  - Monitor alert logs and threats
  - Toggle capture mode (demo/live)
  - Export alerts to CSV
  - Generate analytical reports

## Train New Models from Scratch

```bash
# Run training pipeline
python train.py
```

**train.py** workflow:
1. Load `data/CICIDS2017_sample.csv`
2. Preprocess and normalize features
3. Train three models in parallel:
   - Random Forest classifier
   - LightGBM gradient boosting
   - Logistic Regression (baseline)
4. Evaluate on test set with cross-validation
5. Generate confusion matrix plots for each model in `/results/`
6. Save best-performing model as `models/rf_final.pkl`
7. Save preprocessing artifacts:
   - `models/scaler.pkl` - StandardScaler for feature normalization
   - `models/label_encoder.pkl` - Label encoding for attack classes

## Flask REST API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Main dashboard UI (HTML) |
| `/alerts` | GET | View current alerts (JSON or HTML) |
| `/alerts/export` | GET | Download alerts as CSV file |
| `/report` | GET | Generate mock NIDS analytical report |
| `/live_data_stream` | GET | Server-Sent Events stream for real-time logs |
| `/control/toggle_mode` | POST | Switch between demo and live capture |
| `/control/<action>` | POST | Generic control actions (start/stop capture) |
| `/block_ip/<ip_address>` | POST | Mock IP blocking endpoint |

Refer to `app.py` source code for detailed endpoint behavior and response formats.

## Model Performance

Evaluation results on CICIDS2017 sample:

| Model | Accuracy | Precision | Recall | F1-Score |
|-------|----------|-----------|--------|----------|
| Random Forest | ~95% | ~94% | ~95% | ~94% |
| LightGBM | ~93% | ~92% | ~93% | ~92% |
| Logistic Regression | ~85% | ~84% | ~85% | ~84% |

**Generated Artifacts**:
- Individual confusion matrices for each model
- Feature importance and correlation heatmap
- Cross-model performance comparison chart

## Important Notes & Caveats

### PyShark & Tshark
- Real packet capture requires `tshark` installed system-wide
- `pyshark` Python package acts as interface to tshark
- Demo mode uses synthetic traffic generator when these are unavailable
- Perfect for testing without network hardware setup

### System Permissions
- Live packet capture may require root/Administrator privileges
- OS-specific and network configuration dependent
- Windows: May need "Run as Administrator" for certain network interfaces
- Linux/macOS: May need `sudo` or group permissions for interface access

### Model Portability
- Pre-trained `rf_final.pkl` serialized with joblib
- **Critical**: Must have matching `scaler.pkl` and `label_encoder.pkl` for inference
- Feature order and preprocessing must be consistent with training pipeline
- Retraining recommended if data distribution changes significantly

### Security & Deployment
- **Educational/Demo Project**: Not hardened for production
- Flask app uses development server - never expose to untrusted networks
- No authentication/authorization implemented
- IP blocking is currently mocked - real firewall integration requires careful setup
- Recommendations for production:
  - Add Flask authentication (OAuth2, JWT, etc.)
  - Deploy behind reverse proxy (nginx, Apache)
  - Use HTTPS with proper certificates
  - Implement role-based access control
  - Add comprehensive logging and monitoring
  - Integrate with actual firewall/IDS systems

## How to Extend This Project

### Machine Learning
1. **Add More Models**: XGBoost, CatBoost, Neural Networks (TensorFlow/PyTorch)
2. **Feature Engineering**: Temporal features, session-based features, protocol analysis
3. **Deep Learning**: LSTM for sequence detection, 1D CNN for flow analysis
4. **Ensemble Methods**: Voting classifiers, stacking, boosting variations

### Data & Detection
1. **Real-time Feature Extraction**: Align with training pipeline for production accuracy
2. **Anomaly Detection**: Isolation Forest, One-class SVM for zero-day detection
3. **Incremental Learning**: Online learning for drift adaptation
4. **Threat Intelligence**: Integrate with external IP reputation feeds

### Dashboard & Operations
1. **Add Authentication**: User login, API keys, OAuth2 integration
2. **Advanced Visualizations**: Attack timeline, geographic maps, flow diagrams
3. **Export Formats**: JSON, XML, SIEM-compatible formats
4. **Alerting**: Email/Slack notifications for critical threats

### Integration
1. **Real IP Blocking**: Firewall rules (iptables, Windows Firewall), cloud provider APIs
2. **SIEM Integration**: Forward logs to ELK, Splunk, or similar
3. **Metrics Export**: Prometheus metrics for monitoring
4. **CI/CD Pipeline**: GitHub Actions for testing, linting, model validation

### Quality Assurance
1. **Unit Tests**: Test preprocessing, model loading, prediction logic
2. **Integration Tests**: Flask endpoints, data pipeline
3. **Performance Tests**: Latency benchmarks, throughput testing
4. **Security Tests**: Input validation, SQL injection prevention

## Technologies Stack

- **Python 3.7+**: Core programming language
- **scikit-learn**: Machine learning models and metrics
- **LightGBM**: Gradient boosting implementation
- **Flask**: Web framework and REST API
- **Pandas**: Data manipulation and analysis
- **NumPy**: Numerical computing
- **Matplotlib & Seaborn**: Data visualization
- **PyShark**: Network packet capture interface
- **Joblib**: Model serialization and deserialization

## License

This project is offered for educational purposes. Licensed under MIT License.

## Contributing

Contributions are welcome! Please follow this workflow:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** changes with clear messages (`git commit -m 'Add amazing feature'`)
4. **Push** to your branch (`git push origin feature/amazing-feature`)
5. **Submit** a Pull Request with:
   - Description of changes
   - Test coverage for new functionality
   - Screenshots/GIFs if UI changes

## Author & Contact

**Sagar Rawada**
- GitHub: [@SagarRawada9](https://github.com/SagarRawada9)
- Email: [Add your professional email]
- LinkedIn: [Add your LinkedIn profile]

Questions, suggestions, or collaboration inquiries? Feel free to open an issue or contact me directly.

---

**Project Status**: Active Development  
**Last Updated**: December 2025  
**Version**: 2.0 (NIDS v2)  
**Maintenance**: Ongoing
