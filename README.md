# RevCopilot: AI-Powered Reverse Engineering Assistant

![RevCopilot](https://img.shields.io/badge/RevCopilot-AI%20Reverse%20Engineering-blue)
![Python](https://img.shields.io/badge/Python-3.8+-green)
![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-brightgreen)
![Dartmouth AI](https://img.shields.io/badge/Dartmouth%20AI-Integrated-purple)

RevCopilot is an advanced AI-powered reverse engineering platform designed to help students, CTF players, and security researchers analyze binary files with intelligent assistance.

## ✨ Features

### 🤖 **AI-Powered Analysis**
- **Auto Mode**: Symbolic execution with angr for automatic solution finding
- **AI Mode**: Dartmouth AI integration for deep binary analysis and insights
- **Tutor Mode**: Educational hints and step-by-step guidance

### 🔍 **AI-Assisted Disassembler**
- Real-time function extraction and disassembly
- Interactive assembly code viewing with syntax highlighting
- AI-powered code explanation and vulnerability scanning
- Live Q&A about disassembled code

### 🚀 **Key Capabilities**
- **Binary Analysis**: Static analysis, symbolic execution, and pattern recognition
- **AI Chat Assistant**: Interactive conversation about binary analysis
- **Vulnerability Detection**: AI-powered security flaw identification
- **Educational Hints**: Progressive learning guidance for reverse engineering
- **Multi-mode Support**: Auto, AI, and Tutor modes for different use cases

## 📦 Installation

### Prerequisites
- Python 3.8+
- Docker (optional)
- Dartmouth API credentials (for AI features)

### Backend Setup
```bash
# Clone repository
git clone <your-repo-url>
cd revcopilot

# Create and activate virtual environment
python -m venv .venv_revcopilot
source .venv_revcopilot/bin/activate

# Install dependencies
pip install -r backend/requirements.txt

# Set up environment variables
cp backend/.env.example backend/.env
# Edit backend/.env with your Dartmouth API credentials

# Run backend server
cd backend
python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### Frontend Setup
```bash
cd frontend
npm install
npm run dev
```

### Docker Setup
```bash
# Build and run with Docker Compose
docker-compose up --build
```

## 🎯 Quick Start

Start the backend:
```bash
cd backend
python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

Access the web interface at http://localhost:8000

Upload a binary (try medium.bin from test_data)

Enter Dartmouth API credentials for AI features

Select analysis mode:
	- Auto: For automatic solution finding
	- AI: For deep AI-powered analysis
	- Tutor: For educational guidance

Use the disassembler to explore functions and get AI explanations

## 🧪 Testing

Test with provided binaries
```bash
cd backend
# Test the API
python test_api.py

# Comprehensive test
python final_test.py

# Test with medium.bin
curl -X POST http://localhost:8000/api/analyze -F "file=@tests/test_data/medium.bin"
```

### Sample Analysis Flow
1. Upload medium.bin
2. Select "AI" mode
3. Click "Start Analysis"
4. Explore functions in the disassembler
5. Click "Analyze main()" for AI-powered disassembly
6. Ask questions about the code in the AI chat

## 🏗️ Architecture

### Backend (backend/)

backend/
├── main.py              # FastAPI server with AI integration
├── analysis_service.py  # Core analysis logic
├── simple_solver.py     # Hardcoded solver for known binaries
├── requirements.txt     # Python dependencies
├── tests/              # Test binaries and scripts
└── static/             # Web interface assets

### Frontend (frontend/)

frontend/
├── src/app/page.tsx    # Main React page
├── src/components/     # UI components
├── public/             # Static assets
└── package.json        # Node.js dependencies

## 🔧 Configuration

### Environment Variables
```bash
# Backend .env file
DARTMOUTH_CHAT_API_KEY=your_api_key_here
DARTMOUTH_CHAT_URL=https://chat.dartmouth.edu/api
DARTMOUTH_CHAT_MODEL=openai.gpt-4.1-mini-2025-04-14
PORT=8000
```

### Dependencies
See backend/requirements.txt and frontend/package.json for complete dependency lists.

## 🧰 macOS GDB Dynamic Analysis Setup (Required for GDB Attach)

macOS blocks GDB from attaching unless developer mode is enabled and GDB is signed.

### 1) Enable Developer Tools Security
```bash
sudo DevToolsSecurity -enable
sudo dseditgroup -o edit -a "$USER" -t user _developer
```

### 2) Ad-hoc sign GDB (recommended)
```bash
sudo codesign --force --sign - "/usr/local/Cellar/gdb/17.1/bin/gdb"
sudo killall taskgated
```

### 3) Reboot
Reboot your Mac, then retry the dynamic analysis.

## 📚 Usage Examples

### 1. Basic Binary Analysis
```python
# Using the API directly
import requests

response = requests.post(
		"http://localhost:8000/api/analyze",
		files={"file": open("binary.exe", "rb")},
		params={"mode": "auto"}
)
```

### 2. AI-Powered Disassembly
1. Upload any binary
2. Click on functions in the disassembler panel
3. Get real-time AI analysis of assembly code
4. Ask specific questions about the code

### 3. Educational Mode
Perfect for learning reverse engineering
- Progressive hints without spoilers
- Step-by-step guidance through complex binaries

## 🎓 Educational Value

RevCopilot is designed as a learning tool for:
- CTF Players: Quick analysis of crackme binaries
- Students: Learn reverse engineering with AI guidance
- Security Researchers: AI-assisted vulnerability discovery
- Beginners: Gentle introduction to binary analysis

## ⚠️ Limitations & Best Practices

### Known Limitations
- Complex Binaries: Heavily obfuscated or packed binaries may require manual analysis
- AI Dependence: Advanced features require Dartmouth API access
- Performance: Large binaries (>10MB) may have processing delays

### Best Practices
- Start with simple CTF-style binaries
- Use Auto mode for quick solutions
- Use AI/Tutor modes for learning and deep analysis
- Combine with traditional tools (Ghidra, IDA, radare2)

## 🔍 Testing with Sample Binaries

The repository includes test binaries in backend/tests/test_data/:
- medium.bin: Classic crackme with XOR+ROL transformations
- Other CTF-style binaries for practice

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

### Development Guidelines
- Follow PEP 8 for Python code
- Use TypeScript for frontend components
- Document new features thoroughly
- Add tests for new functionality

## 📄 License

This project is for educational purposes only. Use only on software you own or have permission to analyze.

## 🙏 Acknowledgments

- Dartmouth College for AI API access
- The angr team for symbolic execution framework
- FastAPI and Next.js communities
- All contributors and testers

## 🚨 Disclaimer

FOR EDUCATIONAL USE ONLY

This tool is intended for:
- Educational purposes
- CTF competitions
- Authorized security testing
- Learning reverse engineering

Do not use this tool on software you don't own or have explicit permission to analyze.

Made with ❤️ for the reverse engineering community