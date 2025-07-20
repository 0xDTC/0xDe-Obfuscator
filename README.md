# 🛡️ 0xDe-Obfuscator

**Advanced Code Deobfuscation & Secret Detection Tool for Penetration Testing & CTF**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js Version](https://img.shields.io/badge/node-%3E%3D16.0.0-brightgreen)](https://nodejs.org/)
[![Security](https://img.shields.io/badge/Security-Focused-red)](https://github.com/yourusername/0xDe-Obfuscator)

A comprehensive, professional-grade deobfuscation tool designed for **defensive security analysis**, penetration testing, and CTF competitions. Features a modern web interface with real-time processing capabilities.

## 🚀 Quick Start

### Prerequisites
- **Node.js** >= 16.0.0
- **npm** >= 8.0.0

### Installation & Setup

1. **Clone the repository:**
```bash
git clone https://github.com/yourusername/0xDe-Obfuscator.git
cd 0xDe-Obfuscator
```

2. **Install dependencies:**
```bash
npm install
```

3. **Start the server:**
```bash
# Option 1: Development mode with auto-restart (recommended)
npm run dev

# Option 2: Simple server (direct)
node simple-server.js

# Option 3: Production mode
npm start
```

4. **Open your browser:**
```
http://localhost:3000
```

## 📖 How to Use

### 🔧 **Deobfuscation Mode**
1. **Navigate to the Deobfuscate tab**
2. **Paste your obfuscated code** in the input area
3. **Select encoding type** (or use Auto-detect)
4. **Click "Analyze"** to process the code
5. **View results** in the output panel with risk assessment

### 🕸️ **Web Crawler Mode**
1. **Switch to Web Crawler tab**
2. **Enter target URL** (e.g., `https://example.com`)
3. **Configure crawler options:**
   - External JavaScript files
   - Inline scripts
   - Deep crawl (follow links)
   - Max files/depth limits
4. **Click "Start Crawl"** to begin scanning
5. **Monitor progress** and view discovered files

### 🔍 **Secret Scanner Mode**
1. **Go to Secret Scanner tab**
2. **Paste code or content** to scan
3. **Click "Scan for Secrets"**
4. **Review detected secrets** by severity level
5. **Export results** if needed

### 🛡️ **Malware Analysis Mode**
1. **Select Malware Analysis tab**
2. **Input suspicious code** for analysis
3. **Click "Analyze"** for comprehensive security assessment
4. **Review threat analysis** and risk indicators

### 📦 **Batch Processing Mode**
1. **Switch to Batch Process tab**
2. **Enter multiple items** (one per line)
3. **Select operation type** (Deobfuscate/Secrets/Analysis)
4. **Click "Start Batch"** to process all items
5. **Monitor progress** and download results

## 🎯 Supported Techniques

### **Core Encoding Methods**
- **Basic Encodings:** Base64, Hex, URL, HTML entities, Unicode
- **Cryptographic:** XOR, Caesar cipher, ROT13
- **JavaScript Obfuscation:** JSFuck, JJEncode, AAEncode
- **Compression:** GZIP, DEFLATE
- **Binary Formats:** Binary, Octal, Decimal

### **Secret Detection Patterns**
- **AWS Keys:** Access keys, Secret keys
- **API Tokens:** GitHub, GitLab, Slack, Discord
- **Certificates:** Private keys, JWT tokens
- **Database URLs:** MongoDB, MySQL, PostgreSQL
- **Sensitive Data:** Email addresses, phone numbers, credit cards

### **Security Analysis Features**
- **Code Injection:** eval(), Function(), setTimeout()
- **DOM Manipulation:** innerHTML, document.write
- **Network Requests:** XMLHttpRequest, fetch(), axios
- **Crypto Operations:** CryptoJS, atob/btoa
- **System Commands:** exec(), spawn(), child_process

## 🛠️ API Reference

### **Deobfuscation**
```bash
curl -X POST http://localhost:3000/api/deobfuscate \
  -H "Content-Type: application/json" \
  -d '{
    "input": "ZXZhbCgiYWxlcnQoSGVsbG8pIik=",
    "options": {
      "maxIterations": 10
    }
  }'
```

### **Secret Detection**
```bash
curl -X POST http://localhost:3000/api/secrets \
  -H "Content-Type: application/json" \
  -d '{
    "input": "const apiKey = \"sk-1234567890abcdef\";"
  }'
```

### **Code Analysis**
```bash
curl -X POST http://localhost:3000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "input": "eval(atob(\"YWxlcnQoIkhlbGxvIik=\"));"
  }'
```

### **Code Beautification**
```bash
curl -X POST http://localhost:3000/api/beautify \
  -H "Content-Type: application/json" \
  -d '{
    "input": "function test(){console.log(\"hello\");}",
    "type": "javascript"
  }'
```

## 📁 Project Structure

```
0xDe-Obfuscator/
├── 📄 simple-server.js     # Main server file
├── 📂 client/              # Web interface
│   ├── 📄 index.html       # Main HTML page
│   ├── 📄 style.css        # Modern CSS styling
│   └── 📄 app.js           # Frontend JavaScript
├── 📂 lib/                 # Core libraries
│   └── 📄 encoders.js      # Encoding/decoding engine
├── 📄 package.json         # Project configuration
├── 📄 .gitignore          # Git ignore rules
└── 📄 README.md           # This file
```

## 🔒 Security & Ethics

### **✅ Intended Use Cases**
- **Penetration Testing** (authorized engagements)
- **CTF Competitions** and security challenges
- **Malware Analysis** (defensive research)
- **Security Education** and training
- **Code Review** and auditing

### **❌ Prohibited Uses**
- Creating or improving malicious code
- Unauthorized access attempts
- Bypassing security controls
- Any illegal activities

### **🛡️ Safety Features**
- **No code execution** - analysis only
- **Input validation** and sanitization
- **Safe pattern matching** without eval()
- **Local processing** - no data sent externally
- **Rate limiting** built into server

## 🚨 Important Notes

1. **This tool is for defensive security purposes only**
2. **Always use on authorized systems and code**
3. **Be cautious with suspicious/unknown code**
4. **The tool identifies patterns but doesn't execute code**
5. **Results should be manually verified**

## 🛠️ Troubleshooting

### **Server won't start:**
```bash
# Check if port 3000 is in use
netstat -ano | findstr :3000

# Use different port
PORT=8080 node simple-server.js
```

### **Dependencies issues:**
```bash
# Clear npm cache
npm cache clean --force

# Remove node_modules and reinstall
rm -rf node_modules
npm install
```

### **API not responding:**
- Check that server is running on correct port
- Verify CORS headers are enabled
- Test with curl commands from API section

## 🤝 Contributing

1. **Fork the repository**
2. **Create feature branch:** `git checkout -b feature/new-decoder`
3. **Commit changes:** `git commit -m 'Add new decoder'`
4. **Push to branch:** `git push origin feature/new-decoder`
5. **Open Pull Request**

### **Adding New Decoders**
1. Add pattern to `initializePatterns()` in `lib/encoders.js`
2. Implement decoder function
3. Add to `initializeDecoders()` mapping
4. Test with sample inputs
5. Update documentation

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Security Community** for sharing knowledge
- **Node.js Ecosystem** for excellent libraries
- **Open Source Contributors** worldwide
- **CTF Platforms** for providing challenges
