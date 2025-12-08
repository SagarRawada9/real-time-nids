# Real-Time Network Intrusion Detection System (NIDS)

**Also known as NIDS v2** - A lightweight, CPU-efficient machine learning-based network intrusion detection system with Flask dashboard, live/demo traffic monitoring, and automated threat response.

## Overview

NIDS is a production-ready educational IDS that monitors network traffic in real-time, detects malicious activities using trained ML models, and responds with automated alerts and IP blocking. Built with Flask dashboard, three ML models (RF, LightGBM, LR), and pre-trained artifacts for quick deployment.

## Key Features

### Real-Time Detection & Response
- **Live packet capture** with PyShark (+ demo mode for testing)
- **Multi-class attack detection**: DoS, Brute Force, Port Scanning, Web Attacks, Botnet, Infiltration
- **Automated alerts** with timestamps, threat levels, and confidence scores
- **IP blocking** endpoint (mock + extensible for real firewall integration)

### Machine Learning
- **3 models**: Random Forest (~95% acc), LightGBM (~93%), Logistic Regression (~85%)
- **Training pipeline**: `train.py` evaluates and saves best model
- **Preprocessing artifacts**: Scaler & label encoder for consistent inference

### Web Dashboard
- **Flask UI** at `http://127.0.0.1:5000/` (demo mode by default)
- **Live event stream** with Server-Sent Events (SSE)
- **REST API endpoints** for alerts, reports, IP blocking, mode toggle
- **Alert export** (CSV format), mock LLM report generation

### Dataset
- **CICIDS2017 sample**: ~56,661 network flows, 78 features
- **Attack types**: BENIGN, DoS, Brute Force, Port Scan, Web Attack, Infiltration
- **Included**: `data/CICIDS2017_sample.csv` for training/testing

## Project Structure

```
real-time-nids/
├── app.py                     # Flask dashboard + REST API
├── capture.py                 # Live capture (PyShark) + demo mode
├── train.py                   # Train/evaluate models; save best
├── requirements.txt           # Python dependencies
├── data/
│   └── CICIDS2017_sample.csv  # Training dataset
├── models/
│   ├── rf_final.pkl           # Best model (Random Forest)
│   ├── scaler.pkl             # Feature normalization
│   └── label_encoder.pkl      # Class label mapping
├── results/                   # Generated plots
│   ├── feature_correlation.png
│   ├── RandomForest_confusion.png
│   ├── LightGBM_confusion.png
│   ├── LogisticRegression_confusion.png
│   └── model_comparison.png
└── README.md
```

## Quick Start (5 minutes)

### Setup
```bash
cd real-time-nids
python -m venv .venv
source .venv/bin/activate          # macOS/Linux
.\venv\Scripts\activate            # Windows

pip install -r requirements.txt
# Optional: pip install pyshark (for live capture)
```

### Run Dashboard (Demo Mode)
```bash
python app.py
# Open http://127.0.0.1:5000/ in browser
```

**Demo mode starts automatically** if PyShark unavailable. Use dashboard to:
- View live/demo attack events
- Monitor alert logs
- Toggle capture mode
- Export alerts (CSV)
- Generate analytical reports

### Train Models from Scratch
```bash
python train.py
```

Produces:
- Confusion matrix plots for each model in `/results/`
- Best model saved as `models/rf_final.pkl`
- Preprocessing artifacts: `scaler.pkl`, `label_encoder.pkl`

## REST API Endpoints

| Endpoint | Method | Purpose |
|----------|--------|----------|
| `/` | GET | Dashboard UI |
| `/alerts` | GET | View alerts (JSON/HTML) |
| `/alerts/export` | GET | Download alerts (CSV) |
| `/report` | GET | Generate NIDS report |
| `/live_data_stream` | GET | Real-time log stream (SSE) |
| `/control/toggle_mode` | POST | Toggle demo↔live |
| `/block_ip/<ip>` | POST | Block/mock-block IP |

See `app.py` for detailed payloads and responses.

## Model Performance (CICIDS2017 Sample)

| Model | Accuracy | Precision | Recall | F1 |
|-------|----------|-----------|--------|----|
| Random Forest | 95% | 94% | 95% | 94% |
| LightGBM | 93% | 92% | 93% | 92% |
| Logistic Regression | 85% | 84% | 85% | 84% |

## Technical Stack

- **Python 3.7+**, scikit-learn, LightGBM, Flask
- **Pandas/NumPy** for data processing
- **Matplotlib/Seaborn** for visualization
- **PyShark** for packet capture (optional)
- **Joblib** for model serialization

## Important Notes

### PyShark & Tshark
- Live capture requires `tshark` installed + `pyshark` pip package
- Demo mode works without any dependencies (best for testing)
- Falls back to synthetic traffic if unavailable

### Permissions
- Live capture may need **root/Administrator** privileges
- Windows: Run as Admin for certain network interfaces
- Linux/macOS: May need `sudo` or group permissions

### Model Artifacts
- **Must keep together**: `rf_final.pkl`, `scaler.pkl`, `label_encoder.pkl`
- Feature order & preprocessing must match training pipeline
- Retrain if data distribution changes significantly

### Security & Production Use
- **Educational demo** - not hardened for production
- **Never expose** Flask dev server to untrusted networks
- **No auth** implemented - add OAuth2/JWT before deployment
- IP blocking is **mocked** - integrate real firewall carefully

**Production checklist**:
- [ ] Add authentication (OAuth2/JWT)
- [ ] Deploy behind reverse proxy (nginx/Apache)
- [ ] Use HTTPS with valid certificates
- [ ] Add role-based access control
- [ ] Integrate with actual firewall/IDS
- [ ] Set up comprehensive logging & monitoring

## How to Extend

### Machine Learning
1. Add XGBoost, CatBoost, Neural Networks (TensorFlow/PyTorch)
2. Feature engineering: temporal, session-based, protocol analysis
3. Deep learning: LSTM for sequences, 1D CNN for flows
4. Ensemble methods: voting, stacking, boosting variants

### Detection & Integration
1. Anomaly detection: Isolation Forest, One-class SVM (zero-day)
2. Threat intelligence: IP reputation feeds, external APIs
3. SIEM integration: Forward logs to ELK, Splunk, etc.
4. Real IP blocking: iptables, Windows Firewall, cloud APIs
5. Metrics export: Prometheus for monitoring

### Dashboard & Operations
1. Add user authentication & role-based access
2. Advanced visualizations: attack timelines, geographic maps
3. Email/Slack notifications for critical threats
4. Export formats: JSON, XML, SIEM-compatible
5. CI/CD: GitHub Actions for testing & validation

## Requirements

Core:
```
flask==2.3.2
scikit-learn==1.3.0
lightgbm==4.0.0
joblib==1.3.1
pandas==2.0.3
numpy==1.24.3
matplotlib==3.7.2
seaborn==0.12.2
```

Optional (live capture):
```
pyshark==0.6  # Requires tshark installed system-wide
```

## Contributing

1. Fork the repository
2. Create feature branch: `git checkout -b feature/amazing-feature`
3. Commit changes: `git commit -m 'Add feature'`
4. Push: `git push origin feature/amazing-feature`
5. Submit PR with description, tests, screenshots

## License

MIT License - Educational/Research purposes

## Author & Contact

**Sagar Rawada**
- GitHub: [@SagarRawada9](https://github.com/SagarRawada9)
- Email: [Add your professional email]
- LinkedIn: [Add your LinkedIn]

Questions, suggestions, or collaboration? Open an issue or contact directly.

---

**Status**: Active Development | **Version**: 2.0 | **Last Updated**: December 2025
