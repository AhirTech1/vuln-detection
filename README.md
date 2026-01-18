# AI Code Vulnerability Detector

A VS Code extension that detects security vulnerabilities in AI-generated code and provides secure patch recommendations.

## Features

- 🔍 **Pattern-based vulnerability detection** for Python and JavaScript
- ⚠️ **Clear severity levels** (Critical, High, Medium, Low)
- 📖 **Detailed explanations** of why code is vulnerable
- 🔧 **Secure patch suggestions** with code examples

### Detected Vulnerabilities

**Python:**
- Code Injection (`eval()`, `exec()`)
- SQL Injection
- Command Injection (`subprocess` with `shell=True`)
- Insecure Deserialization (`pickle`)
- Hardcoded Credentials

**JavaScript:**
- Code Injection (`eval()`)
- Cross-Site Scripting (`innerHTML`, `document.write`)
- SQL Injection
- Command Injection (`child_process.exec`)
- Hardcoded Credentials

## Prerequisites

- **VS Code** 1.60.0 or higher
- **Python 3.x** installed and available in PATH

## How to Run (Debug Mode)

1. Open this folder in VS Code:
   ```
   code "d:\New Project\vuln-detection"
   ```

2. Press **F5** to launch the Extension Development Host

3. A new VS Code window will open with the extension loaded

## How to Use

1. Open a Python (`.py`) or JavaScript (`.js`) file

2. **Select** the code you want to analyze

3. **Right-click** and choose **"Analyze Code Security"**

4. View the results in the side panel showing:
   - Vulnerability name
   - Severity level
   - Explanation of the issue
   - Recommended secure patch

## Example Usage

Try analyzing this vulnerable Python code:

```python
user_input = input("Enter expression: ")
result = eval(user_input)  # Vulnerable!
print(result)
```

Or this vulnerable JavaScript code:

```javascript
const userInput = document.getElementById('input').value;
document.getElementById('output').innerHTML = userInput;  // XSS!
```

## Project Structure

```
vuln-detection/
├── extension.js      # VS Code extension main logic
├── detector.py       # Python vulnerability detector
├── package.json      # Extension manifest
├── README.md         # This file
└── .vscode/
    └── launch.json   # Debug configuration
```

## Demo Notes

- This is a hackathon demo, not production software
- Detection is pattern-based and may not catch all vulnerabilities
- Focus is on clarity and educational value

---

*Built for AI-Generated Code Vulnerability Detection Hackathon*
