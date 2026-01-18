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
 * @param {object} result - The analysis result with language and results array
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

    // Escape HTML to prevent XSS in our own panel
    const escapeHtml = (str) => {
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    };

    const results = result.results || [];
    const vulnCount = results.length;
    const hasVulnerabilities = vulnCount > 0 && results[0].vulnerability !== 'Error';
    const isError = vulnCount > 0 && results[0].vulnerability === 'Error';

    // Determine header info
    let statusIcon, statusText, headerColor;
    if (isError) {
        statusIcon = '❌';
        statusText = 'Analysis Error';
        headerColor = '#6b7280';
    } else if (hasVulnerabilities) {
        statusIcon = '⚠️';
        statusText = `${vulnCount} ${vulnCount === 1 ? 'vulnerability' : 'vulnerabilities'} detected`;
        headerColor = '#ea580c';
    } else {
        statusIcon = '✅';
        statusText = 'No vulnerabilities detected';
        headerColor = '#22c55e';
    }

    // Generate cards for each vulnerability
    let cardsHtml = '';

    if (hasVulnerabilities || isError) {
        results.forEach((vuln, index) => {
            const severityColor = severityColors[vuln.severity] || '#6b7280';
            const lines = vuln.lines || [];
            const lineText = lines.length === 1
                ? `Line ${lines[0]}`
                : lines.length > 1
                    ? `Lines ${lines.join(', ')}`
                    : '';
            cardsHtml += `
            <div class="vuln-section" style="margin-bottom: 24px; padding-bottom: 24px; border-bottom: 1px solid var(--vscode-panel-border);">
                ${vulnCount > 1 ? `<div class="vuln-number" style="font-size: 11px; color: var(--vscode-descriptionForeground); margin-bottom: 8px;">Issue ${index + 1} of ${vulnCount}</div>` : ''}
                
                <div class="card">
                    <div class="card-title">Vulnerability</div>
                    <div class="vulnerability-name" style="color: ${severityColor};">${escapeHtml(vuln.vulnerability)}</div>
                </div>

                <div class="card">
                    <div class="card-title">Location & Severity</div>
                    <div style="display: flex; gap: 8px; align-items: center; flex-wrap: wrap;">
                        ${lineText ? `<span class="location-badge" style="display: inline-flex; align-items: center; gap: 4px; padding: 4px 10px; border-radius: 4px; font-size: 12px; font-weight: 500; background: #3b82f622; color: #3b82f6; border: 1px solid #3b82f644;">
                            <span style="font-size: 14px;">📍</span> ${escapeHtml(lineText)}
                        </span>` : ''}
                        <span class="severity-badge" style="background: ${severityColor}22; color: ${severityColor}; border: 1px solid ${severityColor}44;">${escapeHtml(vuln.severity)}</span>
                    </div>
                </div>

                <div class="card">
                    <div class="card-title">Explanation</div>
                    <p class="explanation">${escapeHtml(vuln.explanation)}</p>
                </div>

                <div class="card">
                    <div class="card-title">Recommended Fix</div>
                    <pre class="patch-code">${escapeHtml(vuln.patch)}</pre>
                </div>
            </div>`;
        });
    } else {
        // No vulnerabilities - show safe message
        cardsHtml = `
        <div class="safe-message" style="text-align: center; padding: 40px 20px;">
            <div style="font-size: 48px; margin-bottom: 16px;">✅</div>
            <h2 style="font-size: 18px; font-weight: 600; margin-bottom: 12px; color: #22c55e;">Code Appears Safe</h2>
            <p style="color: var(--vscode-descriptionForeground); max-width: 400px; margin: 0 auto;">
                No common vulnerability patterns were detected in this code snippet. 
                Note: This is a pattern-based analysis and may not catch all security issues. 
                Always follow secure coding practices and conduct thorough security reviews.
            </p>
        </div>`;
    }

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
            color: ${headerColor};
            font-weight: 500;
        }
        .card {
            background: var(--vscode-input-background);
            border: 1px solid var(--vscode-panel-border);
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 12px;
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
        }
        .severity-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
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

    ${cardsHtml}

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
