const vscode = require('vscode');
const { spawn } = require('child_process');
const path = require('path');

/**
 * @param {vscode.ExtensionContext} context
 */
function activate(context) {
    console.log('AI Code Vulnerability Detector is now active!');

    let disposable = vscode.commands.registerCommand('vulnDetection.analyze', async function () {
        const editor = vscode.window.activeTextEditor;

        if (!editor) {
            vscode.window.showErrorMessage('No active editor found.');
            return;
        }

        const selection = editor.selection;
        const selectedText = editor.document.getText(selection);

        if (!selectedText || selectedText.trim() === '') {
            vscode.window.showErrorMessage('Please select some code to analyze.');
            return;
        }

        // Get the language of the current file
        const languageId = editor.document.languageId;

        // Map VS Code language IDs to our detector's expected values
        const languageMap = {
            'python': 'python',
            'javascript': 'javascript',
            'javascriptreact': 'javascript',
            'typescript': 'javascript',
            'typescriptreact': 'javascript'
        };

        const language = languageMap[languageId];

        if (!language) {
            vscode.window.showWarningMessage(`Language "${languageId}" is not supported. Only Python and JavaScript are currently supported.`);
            return;
        }

        // Show progress indicator
        vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: "Analyzing code for vulnerabilities...",
            cancellable: false
        }, async () => {
            try {
                const result = await analyzeCode(selectedText, language, context);
                showResultsPanel(result, context);
            } catch (error) {
                vscode.window.showErrorMessage(`Analysis failed: ${error.message}`);
            }
        });
    });

    context.subscriptions.push(disposable);
}

/**
 * Analyze code by calling the Python detector
 * @param {string} code - The code to analyze
 * @param {string} language - The programming language
 * @param {vscode.ExtensionContext} context - Extension context
 * @returns {Promise<object>} Analysis result
 */
function analyzeCode(code, language, context) {
    return new Promise((resolve, reject) => {
        const detectorPath = path.join(context.extensionPath, 'detector.py');

        // Try python3 first, then python
        const pythonCommands = ['python', 'python3', 'py'];

        tryPythonCommand(pythonCommands, 0, detectorPath, code, language, resolve, reject);
    });
}

/**
 * Try different Python commands until one works
 */
function tryPythonCommand(commands, index, detectorPath, code, language, resolve, reject) {
    if (index >= commands.length) {
        reject(new Error('Python is not installed or not in PATH. Please install Python 3.x.'));
        return;
    }

    const pythonCmd = commands[index];
    const pythonProcess = spawn(pythonCmd, [detectorPath]);

    let stdout = '';
    let stderr = '';

    pythonProcess.stdout.on('data', (data) => {
        stdout += data.toString();
    });

    pythonProcess.stderr.on('data', (data) => {
        stderr += data.toString();
    });

    pythonProcess.on('error', () => {
        // Try next Python command
        tryPythonCommand(commands, index + 1, detectorPath, code, language, resolve, reject);
    });

    pythonProcess.on('close', (exitCode) => {
        if (exitCode === 0) {
            try {
                const result = JSON.parse(stdout);
                resolve(result);
            } catch (e) {
                reject(new Error(`Failed to parse detector output: ${stdout}`));
            }
        } else {
            reject(new Error(`Detector exited with code ${exitCode}: ${stderr}`));
        }
    });

    // Send input to the Python process
    const input = JSON.stringify({ code, language });
    pythonProcess.stdin.write(input);
    pythonProcess.stdin.end();
}

/**
 * Show the analysis results in a webview panel
 * @param {object} result - The analysis result
 * @param {vscode.ExtensionContext} context - Extension context
 */
function showResultsPanel(result, context) {
    const panel = vscode.window.createWebviewPanel(
        'vulnDetectionResults',
        'Security Analysis Results',
        vscode.ViewColumn.Beside,
        {
            enableScripts: false
        }
    );

    panel.webview.html = getResultsHtml(result);
}

/**
 * Generate HTML for the results panel
 * @param {object} result - The analysis result
 * @returns {string} HTML content
 */
function getResultsHtml(result) {
    const severityColors = {
        'Critical': '#dc2626',
        'High': '#ea580c',
        'Medium': '#ca8a04',
        'Low': '#16a34a',
        'Safe': '#22c55e',
        'N/A': '#6b7280'
    };

    const severityColor = severityColors[result.severity] || '#6b7280';
    const isVulnerable = result.vulnerability !== 'None Detected' && result.vulnerability !== 'Error';

    // Escape HTML to prevent XSS in our own panel
    const escapeHtml = (str) => {
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    };

    const statusIcon = isVulnerable ? '⚠️' : (result.vulnerability === 'Error' ? '❌' : '✅');
    const statusText = isVulnerable ? 'Vulnerability Detected' : (result.vulnerability === 'Error' ? 'Analysis Error' : 'Code Appears Safe');

    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Analysis Results</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            padding: 20px;
            background: var(--vscode-editor-background);
            color: var(--vscode-editor-foreground);
            line-height: 1.6;
        }
        .header {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 24px;
            padding-bottom: 16px;
            border-bottom: 1px solid var(--vscode-panel-border);
        }
        .header-icon {
            font-size: 32px;
        }
        .header-text h1 {
            font-size: 18px;
            font-weight: 600;
        }
        .header-text .status {
            font-size: 14px;
            color: var(--vscode-descriptionForeground);
        }
        .card {
            background: var(--vscode-input-background);
            border: 1px solid var(--vscode-panel-border);
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 16px;
        }
        .card-title {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--vscode-descriptionForeground);
            margin-bottom: 8px;
        }
        .vulnerability-name {
            font-size: 16px;
            font-weight: 600;
            color: ${severityColor};
        }
        .severity-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
            background: ${severityColor}22;
            color: ${severityColor};
            border: 1px solid ${severityColor}44;
        }
        .explanation {
            font-size: 14px;
            line-height: 1.7;
        }
        .patch-code {
            background: var(--vscode-textCodeBlock-background);
            border: 1px solid var(--vscode-panel-border);
            border-radius: 4px;
            padding: 12px;
            font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
            font-size: 13px;
            white-space: pre-wrap;
            overflow-x: auto;
        }
        .footer {
            margin-top: 24px;
            padding-top: 16px;
            border-top: 1px solid var(--vscode-panel-border);
            font-size: 12px;
            color: var(--vscode-descriptionForeground);
        }
    </style>
</head>
<body>
    <div class="header">
        <span class="header-icon">${statusIcon}</span>
        <div class="header-text">
            <h1>Security Analysis Results</h1>
            <div class="status">${statusText}</div>
        </div>
    </div>

    <div class="card">
        <div class="card-title">Vulnerability</div>
        <div class="vulnerability-name">${escapeHtml(result.vulnerability)}</div>
    </div>

    <div class="card">
        <div class="card-title">Severity Level</div>
        <span class="severity-badge">${escapeHtml(result.severity)}</span>
    </div>

    <div class="card">
        <div class="card-title">Explanation</div>
        <p class="explanation">${escapeHtml(result.explanation)}</p>
    </div>

    <div class="card">
        <div class="card-title">Recommended Fix</div>
        <pre class="patch-code">${escapeHtml(result.patch)}</pre>
    </div>

    <div class="footer">
        <p>🔒 AI Code Vulnerability Detector • Pattern-based security analysis</p>
        <p>Note: This tool uses pattern matching and may not detect all vulnerabilities. Always conduct thorough security reviews.</p>
    </div>
</body>
</html>`;
}

function deactivate() { }

module.exports = {
    activate,
    deactivate
};
