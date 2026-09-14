# 🛡️ CloudGuard — AI-Powered Cloud Security Monitor

**CloudGuard** is an intelligent, end-to-end web-based system that continuously monitors your AWS account for security misconfigurations, analyzes them with AI (Google Gemini + Claude), and provides one-click auto-remediation.

## ✨ Features

- **🔍 7 AWS Scanners**: S3, IAM/MFA, Security Groups, RDS, CloudTrail, EBS, VPC
- **🤖 Dual AI Agent**: Gemini Flash for bulk analysis, Claude for deep-dive investigation
- **🎯 Hybrid Risk Scoring**: Deterministic base score + AI-adjusted contextual scoring (0-100)
- **🔧 One-Click Remediation**: Auto-fix misconfigurations with config snapshots for rollback
- **📊 Color-Coded Dashboard**: Red/Yellow/Green severity cards, risk gauge, trend charts
- **⚡ Real-Time Updates**: WebSocket-powered live scan progress and finding detection
- **⏰ Scheduled Scanning**: Automatic periodic scans with configurable intervals

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | **FastAPI** (Python) |
| AWS SDK | **Boto3** |
| AI (Primary) | **Google Gemini Flash** |
| AI (Secondary) | **Anthropic Claude** |
| Database | **SQLite + SQLAlchemy** |
| Frontend | **React + Vite** |
| Charts | **Recharts** |
| Animations | **Framer Motion** |
| Real-time | **WebSocket** |

## 🚀 Quick Start

### Prerequisites
- Python 3.10+
- Node.js 18+
- AWS account with credentials
- Google Gemini API key and/or Anthropic API key

### 1. Backend Setup

```bash
cd backend

# Create virtual environment
python -m venv venv
venv\Scripts\activate  # Windows
# source venv/bin/activate  # macOS/Linux

# Install dependencies
pip install -r requirements.txt

# Configure environment
copy .env.example .env
# Edit .env with your credentials

# Start server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### 2. Frontend Setup

```bash
cd frontend

# Install dependencies
npm install

# Start dev server
npm run dev
```

### 3. Open Dashboard
Visit **http://localhost:5173** in your browser.

## 📁 Project Structure

```
CloudGuard/
├── backend/
│   ├── app/
│   │   ├── main.py              # FastAPI entry point
│   │   ├── config.py            # Settings
│   │   ├── models.py            # Database models
│   │   ├── schemas.py           # API schemas
│   │   ├── scanners/            # 7 AWS service scanners
│   │   ├── ai_agent/            # Gemini + Claude AI integration
│   │   ├── remediation/         # Auto-fix engine
│   │   ├── routers/             # API endpoints
│   │   └── services/            # AWS service & scheduler
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── pages/               # Dashboard, Findings, History, Settings
│   │   ├── components/          # Sidebar, Header, Layout
│   │   ├── hooks/               # WebSocket hook
│   │   └── api/                 # API client
│   └── package.json
└── README.md
```

## 🔐 AWS IAM Setup

Create an IAM user with the **SecurityAudit** managed policy for scanning. For auto-remediation, add an inline policy with specific write permissions for S3, EC2, and IAM.

## 📝 API Documentation

Once the backend is running, visit:
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

## 👥 Authors

Built as a college project + real-world deployment tool.

## 📄 License

MIT License
