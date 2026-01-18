#!/usr/bin/env python3
"""
AI-Generated Code Vulnerability Detection
A simple pattern-based vulnerability detector for Python and JavaScript code.
"""

import sys
import json
import re


def detect_vulnerabilities(code: str, language: str) -> dict:
    """
    Analyze code for common security vulnerabilities.
    
    Args:
        code: The source code to analyze
        language: Programming language ('python' or 'javascript')
    
    Returns:
        dict with vulnerability, severity, explanation, and patch
    """
    language = language.lower()
    
    # Define vulnerability patterns for each language
    patterns = {
        'python': [
            {
                'pattern': r'\beval\s*\(',
                'vulnerability': 'Code Injection (eval)',
                'severity': 'High',
                'explanation': 'The eval() function executes arbitrary Python code from a string. If user input is passed to eval(), an attacker can execute malicious code, potentially gaining full control of the system.',
                'patch': '''# Instead of eval(), use safer alternatives:
# For mathematical expressions:
import ast
result = ast.literal_eval(user_input)  # Only evaluates literals

# For JSON data:
import json
result = json.loads(user_input)

# For simple calculations, use a dedicated parser or whitelist allowed operations'''
            },
            {
                'pattern': r'\bexec\s*\(',
                'vulnerability': 'Code Injection (exec)',
                'severity': 'High',
                'explanation': 'The exec() function executes arbitrary Python statements. This is extremely dangerous when combined with user input as it allows complete code execution.',
                'patch': '''# Avoid exec() entirely when possible
# If you need to run dynamic code, consider:
# 1. Using a configuration file instead of dynamic code
# 2. Implementing a restricted DSL (Domain Specific Language)
# 3. Using subprocess with strict input validation for external scripts'''
            },
            {
                'pattern': r'\.execute\s*\(\s*["\'].*%|\.execute\s*\(\s*.*\+|\.execute\s*\(\s*f["\']',
                'vulnerability': 'SQL Injection',
                'severity': 'Critical',
                'explanation': 'Building SQL queries by concatenating or formatting user input allows attackers to inject malicious SQL commands, potentially accessing, modifying, or deleting database data.',
                'patch': '''# Use parameterized queries instead:
# BAD:  cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
# GOOD: cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))

# Or use an ORM like SQLAlchemy:
# user = session.query(User).filter(User.id == user_id).first()'''
            },
            {
                'pattern': r'pickle\.loads?\s*\(',
                'vulnerability': 'Insecure Deserialization',
                'severity': 'Critical',
                'explanation': 'Pickle can deserialize arbitrary Python objects, including malicious ones. Unpickling untrusted data can lead to remote code execution.',
                'patch': '''# Use safer serialization formats:
import json
data = json.loads(user_data)  # For JSON data

# If you must use pickle, only load from trusted sources
# and consider using hmac to verify data integrity'''
            },
            {
                'pattern': r'(password|secret|api_key|token)\s*=\s*["\'][^"\']+["\']',
                'vulnerability': 'Hardcoded Credentials',
                'severity': 'High',
                'explanation': 'Storing passwords, API keys, or secrets directly in source code exposes them to anyone with access to the codebase and makes rotation difficult.',
                'patch': '''# Use environment variables:
import os
password = os.environ.get('DB_PASSWORD')
api_key = os.environ.get('API_KEY')

# Or use a secrets management service like:
# - AWS Secrets Manager
# - HashiCorp Vault
# - Azure Key Vault'''
            },
            {
                'pattern': r'subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True',
                'vulnerability': 'Command Injection',
                'severity': 'Critical',
                'explanation': 'Using shell=True with subprocess allows shell injection attacks. User input can include shell metacharacters to execute arbitrary commands.',
                'patch': '''# Avoid shell=True and pass arguments as a list:
# BAD:  subprocess.run(f"ls {user_dir}", shell=True)
# GOOD: subprocess.run(["ls", user_dir])

# If shell features are needed, validate and sanitize input:
import shlex
safe_input = shlex.quote(user_input)'''
            }
        ],
        'javascript': [
            {
                'pattern': r'\beval\s*\(',
                'vulnerability': 'Code Injection (eval)',
                'severity': 'High',
                'explanation': 'The eval() function executes arbitrary JavaScript code. If user input reaches eval(), attackers can execute malicious scripts in the browser or server context.',
                'patch': '''// Instead of eval(), use safer alternatives:
// For JSON parsing:
const data = JSON.parse(userInput);

// For dynamic property access:
const value = obj[propertyName];

// For mathematical expressions, use a safe parser library like math.js'''
            },
            {
                'pattern': r'\.innerHTML\s*=',
                'vulnerability': 'Cross-Site Scripting (XSS)',
                'severity': 'High',
                'explanation': 'Setting innerHTML with user-controlled content allows attackers to inject malicious scripts that execute in victims\' browsers, stealing cookies, sessions, or performing actions on their behalf.',
                'patch': '''// Use textContent for plain text:
element.textContent = userInput;

// Or use DOM methods to create elements safely:
const div = document.createElement('div');
div.textContent = userInput;
container.appendChild(div);

// If HTML is needed, sanitize with DOMPurify:
element.innerHTML = DOMPurify.sanitize(userInput);'''
            },
            {
                'pattern': r'(query|execute)\s*\(\s*[`"\'].*\$\{|\.query\s*\(\s*.*\+',
                'vulnerability': 'SQL Injection',
                'severity': 'Critical',
                'explanation': 'Building SQL queries by concatenating or interpolating user input allows attackers to inject malicious SQL commands.',
                'patch': '''// Use parameterized queries:
// BAD:  db.query(`SELECT * FROM users WHERE id = ${userId}`)
// GOOD: db.query('SELECT * FROM users WHERE id = ?', [userId])

// Or use an ORM like Sequelize or Prisma:
const user = await User.findByPk(userId);'''
            },
            {
                'pattern': r'child_process\.(exec|execSync)\s*\(',
                'vulnerability': 'Command Injection',
                'severity': 'Critical',
                'explanation': 'The exec functions run shell commands. If user input is included, attackers can inject additional commands using shell metacharacters.',
                'patch': '''// Use execFile or spawn instead of exec:
const { execFile } = require('child_process');
execFile('ls', [userDir], (error, stdout) => {
  // handle output
});

// Always validate and sanitize user input before use'''
            },
            {
                'pattern': r'(password|secret|apiKey|token)\s*[:=]\s*["\'][^"\']+["\']',
                'vulnerability': 'Hardcoded Credentials',
                'severity': 'High',
                'explanation': 'Storing secrets in source code exposes them in version control and client-side bundles.',
                'patch': '''// Use environment variables:
const apiKey = process.env.API_KEY;

// For frontend apps, use build-time injection:
const apiKey = process.env.REACT_APP_API_KEY;

// Never commit .env files - add to .gitignore'''
            },
            {
                'pattern': r'document\.write\s*\(',
                'vulnerability': 'DOM-based XSS',
                'severity': 'Medium',
                'explanation': 'document.write() can introduce XSS vulnerabilities and causes performance issues by blocking parsing.',
                'patch': '''// Use modern DOM manipulation instead:
const container = document.getElementById('output');
container.textContent = userContent;

// Or create elements:
const p = document.createElement('p');
p.textContent = userContent;
document.body.appendChild(p);'''
            }
        ]
    }
    
    # Check if language is supported
    if language not in patterns:
        return {
            'vulnerability': 'Unsupported Language',
            'severity': 'N/A',
            'explanation': f'Language "{language}" is not supported. Currently supported: Python, JavaScript.',
            'patch': 'N/A'
        }
    
    # Check each pattern
    for vuln in patterns[language]:
        if re.search(vuln['pattern'], code, re.IGNORECASE):
            return {
                'vulnerability': vuln['vulnerability'],
                'severity': vuln['severity'],
                'explanation': vuln['explanation'],
                'patch': vuln['patch']
            }
    
    # No vulnerabilities found
    return {
        'vulnerability': 'None Detected',
        'severity': 'Safe',
        'explanation': 'No common vulnerability patterns were detected in this code snippet. Note: This is a pattern-based analysis and may not catch all security issues. Always follow secure coding practices and conduct thorough security reviews.',
        'patch': 'N/A - No changes needed'
    }


def main():
    """Main entry point - reads JSON from stdin and outputs result."""
    try:
        # Read input from stdin
        input_data = sys.stdin.read()
        request = json.loads(input_data)
        
        code = request.get('code', '')
        language = request.get('language', '')
        
        if not code:
            result = {
                'vulnerability': 'Error',
                'severity': 'N/A',
                'explanation': 'No code provided for analysis.',
                'patch': 'N/A'
            }
        else:
            result = detect_vulnerabilities(code, language)
        
        # Output JSON result
        print(json.dumps(result, indent=2))
        
    except json.JSONDecodeError as e:
        error_result = {
            'vulnerability': 'Error',
            'severity': 'N/A',
            'explanation': f'Invalid JSON input: {str(e)}',
            'patch': 'N/A'
        }
        print(json.dumps(error_result, indent=2))
    except Exception as e:
        error_result = {
            'vulnerability': 'Error',
            'severity': 'N/A',
            'explanation': f'Analysis failed: {str(e)}',
            'patch': 'N/A'
        }
        print(json.dumps(error_result, indent=2))


if __name__ == '__main__':
    main()
