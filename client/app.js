/**
 * 0xDe-Obfuscator Frontend Application
 * Modern, responsive interface for advanced security analysis
 */

class DeobfuscatorApp {
    constructor() {
        this.currentMode = 'deobfuscate';
        this.apiBaseUrl = window.location.origin + '/api';
        this.stats = {
            totalAnalyzes: 0,
            secretsFound: 0
        };
        
        this.init();
    }

    async init() {
        this.setupEventListeners();
        this.initializeInterface();
        await this.checkApiConnection();
        this.loadStats();
    }

    setupEventListeners() {
        // Navigation tabs
        document.querySelectorAll('.nav-tab').forEach(tab => {
            tab.addEventListener('click', (e) => this.switchMode(e.target.dataset.mode));
        });

        // Action buttons
        document.getElementById('clearAllBtn').addEventListener('click', () => this.clearAll());
        document.getElementById('exportBtn').addEventListener('click', () => this.exportResults());
        document.getElementById('settingsBtn').addEventListener('click', () => this.openSettings());

        // Deobfuscation mode
        document.getElementById('deobfuscateBtn').addEventListener('click', () => this.performDeobfuscation());
        document.getElementById('pasteBtn').addEventListener('click', () => this.pasteFromClipboard());
        document.getElementById('copyResultBtn').addEventListener('click', () => this.copyResults());
        document.getElementById('beautifyBtn').addEventListener('click', () => this.beautifyCode());
        document.getElementById('downloadBtn').addEventListener('click', () => this.downloadResult());

        // File upload
        document.getElementById('fileUpload').addEventListener('change', (e) => this.handleFileUpload(e));

        // Web crawler mode
        document.getElementById('startCrawlBtn').addEventListener('click', () => this.startWebCrawl());
        document.getElementById('stopCrawlBtn').addEventListener('click', () => this.stopWebCrawl());
        
        // Real-time input monitoring for deobfuscator
        document.getElementById('codeInput').addEventListener('input', () => this.onInputChange());

        // Secret scanner mode
        document.getElementById('scanSecretsBtn').addEventListener('click', () => this.scanSecrets());

        // Malware analysis mode
        document.getElementById('analyzeMalwareBtn').addEventListener('click', () => this.analyzeMalware());

        // Batch processing mode
        document.getElementById('startBatchBtn').addEventListener('click', () => this.startBatchProcessing());

        // Settings modal
        document.getElementById('closeSettingsModal').addEventListener('click', () => this.closeSettings());

        // Drag and drop
        this.setupDragAndDrop();

        // Auto-resize textareas
        this.setupAutoResize();

        // Keyboard shortcuts
        this.setupKeyboardShortcuts();
    }

    initializeInterface() {
        this.updateStatus('Ready', 'success');
        this.switchMode('deobfuscate');
        
        // Initialize Prism.js for syntax highlighting
        if (window.Prism) {
            Prism.highlightAll();
        }
    }

    async checkApiConnection() {
        try {
            const response = await fetch(`${this.apiBaseUrl}/health`);
            if (response.ok) {
                this.updateApiStatus('Connected', 'success');
            } else {
                this.updateApiStatus('Error', 'error');
            }
        } catch (error) {
            this.updateApiStatus('Offline', 'error');
            this.showNotification('API connection failed. Running in offline mode.', 'warning');
        }
    }

    loadStats() {
        const savedStats = localStorage.getItem('deobfuscator-stats');
        if (savedStats) {
            this.stats = JSON.parse(savedStats);
            this.updateStatsDisplay();
        }
    }

    saveStats() {
        localStorage.setItem('deobfuscator-stats', JSON.stringify(this.stats));
        this.updateStatsDisplay();
    }

    updateStatsDisplay() {
        document.getElementById('totalAnalyzes').textContent = this.stats.totalAnalyzes;
        document.getElementById('secretsFound').textContent = this.stats.secretsFound;
    }

    switchMode(mode) {
        if (mode === this.currentMode) return;

        // Update navigation
        document.querySelectorAll('.nav-tab').forEach(tab => {
            tab.classList.toggle('active', tab.dataset.mode === mode);
        });

        // Update panels
        document.querySelectorAll('.mode-panel').forEach(panel => {
            panel.classList.toggle('active', panel.id === `${mode}-panel`);
        });

        this.currentMode = mode;
        this.updateStatus(`Switched to ${this.getModeDisplayName(mode)} mode`, 'info');
    }

    getModeDisplayName(mode) {
        const names = {
            deobfuscate: 'Deobfuscation',
            crawler: 'Web Crawler',
            secrets: 'Secret Scanner',
            analyzer: 'Malware Analysis',
            batch: 'Batch Processing'
        };
        return names[mode] || mode;
    }

    async performDeobfuscation() {
        const input = document.getElementById('codeInput').value.trim();
        if (!input) {
            this.showNotification('Please enter code to deobfuscate', 'warning');
            return;
        }

        const language = document.getElementById('languageSelect').value;
        const encoding = document.getElementById('encodingSelect').value;

        this.updateStatus('Analyzing code...', 'processing');
        this.showLoading('deobfuscateBtn');

        try {
            const response = await fetch(`${this.apiBaseUrl}/deobfuscate`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    input,
                    options: {
                        language: language !== 'auto' ? language : undefined,
                        encoding: encoding !== 'auto' ? encoding : undefined,
                        maxIterations: this.getSettings().maxIterations || 10
                    }
                })
            });

            const result = await response.json();

            if (result.success) {
                this.displayDeobfuscationResult(result.result);
                this.stats.totalAnalyzes++;
                this.saveStats();
                this.updateStatus('Deobfuscation completed successfully', 'success');
            } else {
                throw new Error(result.message || 'Deobfuscation failed');
            }

        } catch (error) {
            this.showNotification(`Error: ${error.message}`, 'error');
            this.updateStatus('Deobfuscation failed', 'error');
        } finally {
            this.hideLoading('deobfuscateBtn');
        }
    }

    displayDeobfuscationResult(result) {
        const outputElement = document.getElementById('codeOutput');
        outputElement.textContent = result.finalOutput;

        // Update syntax highlighting
        if (window.Prism) {
            Prism.highlightElement(outputElement);
        }

        // Show analysis summary
        const summaryElement = document.getElementById('analysisSummary');
        if (result.steps && result.steps.length > 0) {
            const lastStep = result.steps[result.steps.length - 1];
            document.getElementById('detectedEncoding').textContent = lastStep.encoding || 'Multiple';
            document.getElementById('iterationCount').textContent = result.iterations || result.steps.length;
            
            const originalSize = result.originalLength || 0;
            const finalSize = result.finalOutput.length;
            const reduction = originalSize > 0 ? ((originalSize - finalSize) / originalSize * 100).toFixed(1) : 0;
            document.getElementById('sizeReduction').textContent = `${reduction}%`;
            
            // Risk assessment based on content
            const riskLevel = this.assessRiskLevel(result.finalOutput);
            const riskElement = document.getElementById('riskLevel');
            riskElement.textContent = riskLevel.toUpperCase();
            riskElement.className = `summary-value risk-indicator ${riskLevel}`;
            
            summaryElement.style.display = 'block';
        } else {
            summaryElement.style.display = 'none';
        }
    }

    assessRiskLevel(content) {
        const highRiskPatterns = [
            /eval\s*\(/gi,
            /Function\s*\(/gi,
            /document\.write/gi,
            /innerHTML\s*=/gi,
            /XMLHttpRequest/gi,
            /fetch\s*\(/gi
        ];

        const mediumRiskPatterns = [
            /atob\s*\(/gi,
            /btoa\s*\(/gi,
            /String\.fromCharCode/gi,
            /unescape/gi,
            /decodeURIComponent/gi
        ];

        let riskScore = 0;
        highRiskPatterns.forEach(pattern => {
            if (pattern.test(content)) riskScore += 3;
        });
        
        mediumRiskPatterns.forEach(pattern => {
            if (pattern.test(content)) riskScore += 1;
        });

        if (riskScore >= 6) return 'high';
        if (riskScore >= 3) return 'medium';
        return 'low';
    }

    async startWebCrawl() {
        const url = document.getElementById('crawlUrl').value.trim();
        if (!url) {
            this.showNotification('Please enter a URL to crawl', 'warning');
            return;
        }

        // Validate URL
        try {
            new URL(url);
        } catch {
            this.showNotification('Please enter a valid URL', 'error');
            return;
        }

        const options = {
            includeExternalJS: document.getElementById('includeExternal').checked,
            includeInlineJS: document.getElementById('includeInline').checked,
            deepCrawl: document.getElementById('deepCrawl').checked,
            maxFiles: parseInt(document.getElementById('maxFiles').value) || 50,
            maxDepth: parseInt(document.getElementById('maxDepth').value) || 2
        };

        this.updateStatus('Starting web crawl...', 'processing');
        this.showCrawlProgress(true);
        this.updateCrawlProgress(0, 'Initializing crawler...');

        try {
            const response = await fetch(`${this.apiBaseUrl}/crawl`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ url, options })
            });

            const result = await response.json();

            if (result.status === 'success') {
                this.displayCrawlResults(result);
                this.updateStatus(`Crawl completed - ${result.stats.totalScripts} scripts found, ${result.stats.secretsFound} secrets detected`, 'success');
                this.updateSecretsCount(result.stats.secretsFound);
            } else {
                throw new Error(result.error || 'Crawl failed');
            }

        } catch (error) {
            this.showNotification(`Crawl error: ${error.message}`, 'error');
            this.updateStatus('Crawl failed', 'error');
        } finally {
            this.showCrawlProgress(false);
        }
    }

    displayCrawlResults(results) {
        const container = document.getElementById('discoveredFiles');
        
        if (!results.scripts || results.scripts.length === 0) {
            container.innerHTML = `
                <div class="empty-state">
                    <i class="fas fa-spider"></i>
                    <p>No JavaScript files found on this website</p>
                </div>
            `;
            return;
        }

        const scriptsHtml = results.scripts.map((script, index) => `
            <div class="file-item ${script.riskLevel}" data-index="${index}">
                <div class="file-header">
                    <div class="file-info">
                        <span class="file-type ${script.type}">${script.type}</span>
                        <span class="file-url" title="${script.url}">${this.truncateUrl(script.url)}</span>
                        <span class="file-size">${this.formatFileSize(script.size)}</span>
                    </div>
                    <div class="file-indicators">
                        ${script.content.includes('eval(') ? '<span class="indicator obfuscated" title="Potentially Obfuscated"><i class="fas fa-eye-slash"></i></span>' : ''}
                        ${script.secrets && script.secrets.secrets && script.secrets.secrets.length > 0 ? '<span class="indicator secrets" title="Contains Secrets"><i class="fas fa-key"></i></span>' : ''}
                        <span class="risk-badge ${script.riskLevel}">${script.riskLevel}</span>
                    </div>
                </div>
                <div class="file-stats">
                    ${script.secrets && script.secrets.secrets ? `<span class="stat-badge">🔑 ${script.secrets.secrets.length} secrets</span>` : ''}
                    <span class="stat-badge">📏 ${script.size} bytes</span>
                </div>
                <div class="file-actions">
                    <button class="btn-small" onclick="app.analyzeScript(${index})">
                        <i class="fas fa-search"></i> Analyze
                    </button>
                    <button class="btn-small" onclick="app.viewScriptContent(${index})">
                        <i class="fas fa-eye"></i> View
                    </button>
                    ${script.secrets && script.secrets.secrets && script.secrets.secrets.length > 0 ? `
                    <button class="btn-small" onclick="app.viewScriptSecrets(${index})">
                        <i class="fas fa-key"></i> Secrets
                    </button>` : ''}
                </div>
            </div>
        `).join('');

        container.innerHTML = scriptsHtml;
        this.crawlResults = results;
        
        // Update crawl stats
        document.getElementById('pagesCount').textContent = '1';
        document.getElementById('filesCount').textContent = results.stats.totalScripts;
        document.getElementById('crawlSecretsCount').textContent = results.stats.secretsFound;
    }

    analyzeFile(fileIndex) {
        if (!this.crawlResults || !this.crawlResults.files[fileIndex]) return;
        
        const file = this.crawlResults.files[fileIndex];
        
        // Switch to deobfuscation mode and populate input
        this.switchMode('deobfuscate');
        document.getElementById('codeInput').value = `// Source: ${file.url}\n// Type: ${file.type}\n// Risk: ${file.riskLevel}\n\n${file.content}`;
        
        // Auto-trigger analysis
        setTimeout(() => this.performDeobfuscation(), 100);
    }

    viewFileContent(fileIndex) {
        if (!this.crawlResults || !this.crawlResults.files[fileIndex]) return;
        
        const file = this.crawlResults.files[fileIndex];
        
        // Create and show modal with file content
        const modal = document.createElement('div');
        modal.className = 'modal';
        modal.innerHTML = `
            <div class="modal-content" style="max-width: 90%; max-height: 90%;">
                <div class="modal-header">
                    <h3><i class="fas fa-file-code"></i> ${this.truncateUrl(file.url)}</h3>
                    <button class="modal-close" onclick="this.closest('.modal').remove()">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
                <div class="modal-body">
                    <div class="file-meta" style="margin-bottom: 1rem; padding: 1rem; background: var(--bg-tertiary); border-radius: var(--radius-md);">
                        <p><strong>URL:</strong> ${file.url}</p>
                        <p><strong>Type:</strong> ${file.type} | <strong>Size:</strong> ${this.formatFileSize(file.size)} | <strong>Risk:</strong> ${file.riskLevel}</p>
                        <p><strong>Obfuscated:</strong> ${file.isObfuscated ? 'Yes' : 'No'} | <strong>Has Secrets:</strong> ${file.hasSecrets ? 'Yes' : 'No'}</p>
                    </div>
                    <pre><code class="language-javascript" style="max-height: 60vh; overflow: auto;">${this.escapeHtml(file.content)}</code></pre>
                </div>
            </div>
        `;
        
        document.body.appendChild(modal);
        
        // Highlight syntax
        if (window.Prism) {
            Prism.highlightAllUnder(modal);
        }
    }

    async scanSecrets() {
        const input = document.getElementById('secretsInput').value.trim();
        if (!input) {
            this.showNotification('Please enter code to scan for secrets', 'warning');
            return;
        }

        this.updateStatus('Scanning for secrets...', 'processing');
        this.showLoading('scanSecretsBtn');

        try {
            const response = await fetch(`${this.apiBaseUrl}/secrets`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    input,
                    options: {
                        includeContext: true
                    }
                })
            });

            const result = await response.json();

            if (result.success) {
                this.displaySecretsResults(result.secrets, result.report);
                this.stats.secretsFound += result.secrets.length;
                this.saveStats();
                this.updateStatus(`Secret scan completed - ${result.secrets.length} secrets found`, 'success');
            } else {
                throw new Error(result.message || 'Secret scanning failed');
            }

        } catch (error) {
            this.showNotification(`Error: ${error.message}`, 'error');
            this.updateStatus('Secret scanning failed', 'error');
        } finally {
            this.hideLoading('scanSecretsBtn');
        }
    }

    displaySecretsResults(secrets, report) {
        // Update stats
        const statsElements = {
            critical: document.getElementById('criticalSecrets'),
            high: document.getElementById('highSecrets'),
            medium: document.getElementById('mediumSecrets'),
            low: document.getElementById('lowSecrets')
        };

        Object.keys(statsElements).forEach(severity => {
            const count = report.breakdown.bySeverity[severity] || 0;
            statsElements[severity].textContent = `${count} ${severity.charAt(0).toUpperCase() + severity.slice(1)}`;
        });

        // Display secrets
        const container = document.getElementById('secretsResults');
        
        if (secrets.length === 0) {
            container.innerHTML = `
                <div class="empty-state">
                    <i class="fas fa-key"></i>
                    <p>No secrets detected. Code appears clean!</p>
                </div>
            `;
            return;
        }

        const secretsHtml = secrets.map((secret, index) => `
            <div class="secret-item ${secret.severity}" data-index="${index}">
                <div class="secret-header">
                    <div class="secret-type">
                        <i class="fas fa-key"></i>
                        ${secret.type}
                    </div>
                    <div class="secret-indicators">
                        <span class="confidence-badge ${secret.confidence}">${secret.confidence}</span>
                        <span class="severity-badge ${secret.severity}">${secret.severity}</span>
                    </div>
                </div>
                <div class="secret-value">${this.maskSecret(secret.value)}</div>
                <div class="secret-meta">
                    <p><strong>Line:</strong> ${secret.line}</p>
                    <p><strong>Description:</strong> ${secret.description}</p>
                    <p><strong>Remediation:</strong> ${secret.remediation}</p>
                </div>
            </div>
        `).join('');

        container.innerHTML = secretsHtml;
    }

    maskSecret(value) {
        if (value.length <= 8) return '*'.repeat(value.length);
        const start = value.substring(0, 4);
        const end = value.substring(value.length - 4);
        const middle = '*'.repeat(value.length - 8);
        return start + middle + end;
    }

    async analyzeMalware() {
        const input = document.getElementById('malwareInput').value.trim();
        if (!input) {
            this.showNotification('Please enter code to analyze', 'warning');
            return;
        }

        this.updateStatus('Performing malware analysis...', 'processing');
        this.showLoading('analyzeMalwareBtn');

        try {
            const response = await fetch(`${this.apiBaseUrl}/analyze`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    input,
                    options: {}
                })
            });

            const result = await response.json();

            if (result.success) {
                this.displayMalwareResults(result.analysis);
                this.stats.totalAnalyzes++;
                this.saveStats();
                this.updateStatus('Malware analysis completed', 'success');
            } else {
                throw new Error(result.message || 'Malware analysis failed');
            }

        } catch (error) {
            this.showNotification(`Error: ${error.message}`, 'error');
            this.updateStatus('Malware analysis failed', 'error');
        } finally {
            this.hideLoading('analyzeMalwareBtn');
        }
    }

    displayMalwareResults(analysis) {
        const container = document.getElementById('malwareResults');
        
        const resultsHtml = `
            <div class="analysis-overview">
                <div class="risk-score ${analysis.summary.riskLevel.toLowerCase()}">
                    <h3>Risk Score: ${analysis.summary.riskScore}/100</h3>
                    <p>Risk Level: ${analysis.summary.riskLevel}</p>
                </div>
                <div class="detection-summary">
                    <p><strong>Total Detections:</strong> ${analysis.summary.totalDetections}</p>
                    <p><strong>Analysis Time:</strong> ${new Date(analysis.summary.analysisTime).toLocaleTimeString()}</p>
                </div>
            </div>
            
            <div class="analysis-sections">
                ${this.renderAnalysisSection('Packers Detected', analysis.details.detections.packers)}
                ${this.renderAnalysisSection('Anti-Debug Techniques', analysis.details.detections.antiDebug)}
                ${this.renderAnalysisSection('VM Evasion', analysis.details.detections.vmEvasion)}
                ${this.renderAnalysisSection('Malware Patterns', analysis.details.detections.malware)}
                ${this.renderAnalysisSection('Obfuscation Techniques', analysis.details.detections.obfuscation)}
            </div>
            
            <div class="recommendations">
                <h4><i class="fas fa-lightbulb"></i> Recommendations</h4>
                <ul>
                    ${analysis.mitigations.map(rec => `<li>${rec}</li>`).join('')}
                </ul>
            </div>
            
            <div class="iocs">
                <h4><i class="fas fa-search"></i> Indicators of Compromise</h4>
                ${this.renderIOCs(analysis.iocs)}
            </div>
        `;
        
        container.innerHTML = resultsHtml;
    }

    renderAnalysisSection(title, data) {
        if (!data || (Array.isArray(data) && data.length === 0) || (typeof data === 'object' && Object.keys(data).length === 0)) {
            return '';
        }

        let content = '';
        if (Array.isArray(data)) {
            content = data.map(item => `<li>${item.description || item.name || JSON.stringify(item)}</li>`).join('');
        } else if (typeof data === 'object') {
            content = Object.keys(data).map(key => {
                const value = data[key];
                return `<li><strong>${key}:</strong> ${value.count || value.length || JSON.stringify(value)}</li>`;
            }).join('');
        }

        return `
            <div class="analysis-section">
                <h4><i class="fas fa-exclamation-triangle"></i> ${title}</h4>
                <ul>${content}</ul>
            </div>
        `;
    }

    renderIOCs(iocs) {
        const sections = [];
        
        if (iocs.urls && iocs.urls.length > 0) {
            sections.push(`<div class="ioc-section"><strong>URLs:</strong><ul>${iocs.urls.map(url => `<li>${url}</li>`).join('')}</ul></div>`);
        }
        
        if (iocs.ips && iocs.ips.length > 0) {
            sections.push(`<div class="ioc-section"><strong>IP Addresses:</strong><ul>${iocs.ips.map(ip => `<li>${ip}</li>`).join('')}</ul></div>`);
        }
        
        if (iocs.domains && iocs.domains.length > 0) {
            sections.push(`<div class="ioc-section"><strong>Domains:</strong><ul>${iocs.domains.map(domain => `<li>${domain}</li>`).join('')}</ul></div>`);
        }

        return sections.length > 0 ? sections.join('') : '<p>No IOCs detected</p>';
    }

    async startBatchProcessing() {
        const input = document.getElementById('batchInput').value.trim();
        if (!input) {
            this.showNotification('Please enter items for batch processing', 'warning');
            return;
        }

        const operation = document.getElementById('batchOperation').value;
        const items = input.split('\n').filter(item => item.trim());

        if (items.length === 0) {
            this.showNotification('No valid items found for processing', 'warning');
            return;
        }

        this.updateStatus('Starting batch processing...', 'processing');
        this.showBatchProgress(true);

        try {
            const response = await fetch(`${this.apiBaseUrl}/batch`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    inputs: items,
                    operation,
                    options: {}
                })
            });

            const result = await response.json();

            if (result.success) {
                this.displayBatchResults(result.results);
                this.updateStatus(`Batch processing completed - ${result.results.length} items processed`, 'success');
            } else {
                throw new Error(result.message || 'Batch processing failed');
            }

        } catch (error) {
            this.showNotification(`Error: ${error.message}`, 'error');
            this.updateStatus('Batch processing failed', 'error');
        } finally {
            this.showBatchProgress(false);
        }
    }

    displayBatchResults(results) {
        const container = document.getElementById('batchResults');
        
        const resultsHtml = results.map((result, index) => `
            <div class="batch-result-item ${result.success ? 'success' : 'error'}">
                <div class="result-header">
                    <span class="result-index">#${index + 1}</span>
                    <span class="result-status ${result.success ? 'success' : 'error'}">
                        <i class="fas fa-${result.success ? 'check' : 'times'}"></i>
                        ${result.success ? 'Success' : 'Failed'}
                    </span>
                </div>
                <div class="result-content">
                    ${result.success ? 
                        `<pre><code>${this.escapeHtml(JSON.stringify(result.result, null, 2))}</code></pre>` :
                        `<p class="error-message">${result.error}</p>`
                    }
                </div>
            </div>
        `).join('');
        
        container.innerHTML = resultsHtml;
    }

    // Utility functions
    async pasteFromClipboard() {
        try {
            const text = await navigator.clipboard.readText();
            const activeTextarea = document.querySelector(`#${this.currentMode}-panel textarea`);
            if (activeTextarea) {
                activeTextarea.value = text;
                this.showNotification('Content pasted from clipboard', 'success');
            }
        } catch (error) {
            this.showNotification('Could not read from clipboard', 'error');
        }
    }

    async copyResults() {
        const output = document.getElementById('codeOutput').textContent;
        try {
            await navigator.clipboard.writeText(output);
            this.showNotification('Results copied to clipboard', 'success');
        } catch (error) {
            this.showNotification('Could not copy to clipboard', 'error');
        }
    }

    beautifyCode() {
        const output = document.getElementById('codeOutput');
        const code = output.textContent;
        
        try {
            // Simple beautification - would use a proper library in production
            const beautified = code
                .replace(/;/g, ';\n')
                .replace(/{/g, '{\n')
                .replace(/}/g, '}\n')
                .replace(/,/g, ',\n');
            
            output.textContent = beautified;
            if (window.Prism) {
                Prism.highlightElement(output);
            }
            this.showNotification('Code beautified', 'success');
        } catch (error) {
            this.showNotification('Could not beautify code', 'error');
        }
    }

    downloadResult() {
        const output = document.getElementById('codeOutput').textContent;
        const blob = new Blob([output], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        
        const a = document.createElement('a');
        a.href = url;
        a.download = `deobfuscated-${Date.now()}.txt`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        
        this.showNotification('Result downloaded', 'success');
    }

    async handleFileUpload(event) {
        const files = Array.from(event.target.files);
        if (files.length === 0) return;

        this.updateStatus('Loading files...', 'processing');

        try {
            const results = await Promise.all(files.map(file => this.readFile(file)));
            const combinedContent = results.map((content, index) => 
                `// File: ${files[index].name}\n${content}`
            ).join('\n\n' + '='.repeat(50) + '\n\n');

            const activeTextarea = document.querySelector(`#${this.currentMode}-panel textarea`);
            if (activeTextarea) {
                activeTextarea.value = combinedContent;
                this.showNotification(`${files.length} file(s) loaded successfully`, 'success');
            }
        } catch (error) {
            this.showNotification(`Error loading files: ${error.message}`, 'error');
        }

        // Reset file input
        event.target.value = '';
    }

    readFile(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = () => resolve(reader.result);
            reader.onerror = () => reject(new Error(`Failed to read ${file.name}`));
            reader.readAsText(file);
        });
    }

    setupDragAndDrop() {
        const textareas = document.querySelectorAll('textarea');
        
        textareas.forEach(textarea => {
            textarea.addEventListener('dragover', (e) => {
                e.preventDefault();
                textarea.classList.add('drag-over');
            });
            
            textarea.addEventListener('dragleave', () => {
                textarea.classList.remove('drag-over');
            });
            
            textarea.addEventListener('drop', async (e) => {
                e.preventDefault();
                textarea.classList.remove('drag-over');
                
                const files = Array.from(e.dataTransfer.files);
                if (files.length > 0) {
                    try {
                        const results = await Promise.all(files.map(file => this.readFile(file)));
                        const combinedContent = results.map((content, index) => 
                            `// File: ${files[index].name}\n${content}`
                        ).join('\n\n' + '='.repeat(50) + '\n\n');
                        
                        textarea.value = combinedContent;
                        this.showNotification(`${files.length} file(s) loaded via drag & drop`, 'success');
                    } catch (error) {
                        this.showNotification(`Error loading files: ${error.message}`, 'error');
                    }
                }
            });
        });
    }

    setupAutoResize() {
        const textareas = document.querySelectorAll('textarea');
        
        textareas.forEach(textarea => {
            textarea.addEventListener('input', () => {
                textarea.style.height = 'auto';
                textarea.style.height = Math.max(textarea.scrollHeight, 400) + 'px';
            });
        });
    }

    setupKeyboardShortcuts() {
        document.addEventListener('keydown', (e) => {
            // Ctrl/Cmd + Enter to process
            if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
                e.preventDefault();
                switch (this.currentMode) {
                    case 'deobfuscate':
                        this.performDeobfuscation();
                        break;
                    case 'secrets':
                        this.scanSecrets();
                        break;
                    case 'analyzer':
                        this.analyzeMalware();
                        break;
                    case 'batch':
                        this.startBatchProcessing();
                        break;
                }
            }
            
            // Ctrl/Cmd + K to clear
            if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
                e.preventDefault();
                this.clearAll();
            }
        });
    }

    showCrawlProgress(show) {
        const progressElement = document.getElementById('crawlProgress');
        progressElement.style.display = show ? 'block' : 'none';
    }

    updateCrawlProgress(percentage, text) {
        document.getElementById('progressFill').style.width = `${percentage}%`;
        document.getElementById('progressText').textContent = text;
    }

    showBatchProgress(show) {
        const progressElement = document.getElementById('batchProgress');
        progressElement.style.display = show ? 'block' : 'none';
    }

    updateBatchProgress(percentage, text) {
        document.getElementById('batchProgressFill').style.width = `${percentage}%`;
        document.getElementById('batchProgressText').textContent = text;
    }

    showLoading(buttonId) {
        const button = document.getElementById(buttonId);
        const icon = button.querySelector('i');
        if (icon) {
            icon.className = 'fas fa-spinner loading';
        }
        button.disabled = true;
    }

    hideLoading(buttonId) {
        const button = document.getElementById(buttonId);
        const icon = button.querySelector('i');
        if (icon) {
            icon.className = icon.dataset.originalClass || 'fas fa-play';
        }
        button.disabled = false;
    }

    updateStatus(message, type = 'info') {
        const statusText = document.getElementById('statusText');
        const statusIndicator = document.getElementById('statusIndicator');
        
        statusText.textContent = message;
        statusIndicator.className = `status-indicator ${type}`;
        
        // Auto-hide non-error messages after 3 seconds
        if (type !== 'error') {
            setTimeout(() => {
                if (statusText.textContent === message) {
                    this.updateStatus('Ready', 'success');
                }
            }, 3000);
        }
    }

    updateApiStatus(status, type) {
        const apiStatus = document.getElementById('apiStatus');
        apiStatus.textContent = `API: ${status}`;
        apiStatus.className = `api-status ${type}`;
    }

    showNotification(message, type = 'info') {
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        notification.innerHTML = `
            <i class="fas fa-${this.getNotificationIcon(type)}"></i>
            <span>${message}</span>
            <button onclick="this.parentElement.remove()">
                <i class="fas fa-times"></i>
            </button>
        `;
        
        document.body.appendChild(notification);
        
        // Auto-remove after 5 seconds
        setTimeout(() => {
            if (notification.parentElement) {
                notification.remove();
            }
        }, 5000);
    }

    getNotificationIcon(type) {
        const icons = {
            success: 'check-circle',
            error: 'exclamation-circle',
            warning: 'exclamation-triangle',
            info: 'info-circle'
        };
        return icons[type] || 'info-circle';
    }

    clearAll() {
        // Clear all textareas
        document.querySelectorAll('textarea').forEach(textarea => {
            textarea.value = '';
        });
        
        // Clear results
        document.getElementById('codeOutput').textContent = '';
        document.getElementById('analysisSummary').style.display = 'none';
        
        // Clear other result containers
        ['discoveredFiles', 'secretsResults', 'malwareResults', 'batchResults'].forEach(id => {
            const container = document.getElementById(id);
            if (container) {
                container.innerHTML = `
                    <div class="empty-state">
                        <i class="fas fa-${this.getEmptyStateIcon(id)}"></i>
                        <p>${this.getEmptyStateMessage(id)}</p>
                    </div>
                `;
            }
        });
        
        this.updateStatus('All data cleared', 'info');
    }

    getEmptyStateIcon(containerId) {
        const icons = {
            discoveredFiles: 'spider',
            secretsResults: 'key',
            malwareResults: 'virus',
            batchResults: 'layer-group'
        };
        return icons[containerId] || 'circle';
    }

    getEmptyStateMessage(containerId) {
        const messages = {
            discoveredFiles: 'Start crawling a website to discover JavaScript files',
            secretsResults: 'No secrets detected. Paste code above to start scanning.',
            malwareResults: 'Upload suspicious code for comprehensive security analysis',
            batchResults: 'Configure batch processing options and start analysis'
        };
        return messages[containerId] || 'No data available';
    }

    async exportResults() {
        const data = {
            timestamp: new Date().toISOString(),
            mode: this.currentMode,
            stats: this.stats,
            results: {
                deobfuscated: document.getElementById('codeOutput').textContent,
                crawlResults: this.crawlResults,
                // Add other results as needed
            }
        };

        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        
        const a = document.createElement('a');
        a.href = url;
        a.download = `0xde-obfuscator-export-${Date.now()}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        
        this.showNotification('Results exported successfully', 'success');
    }

    openSettings() {
        document.getElementById('settingsModal').style.display = 'flex';
    }

    closeSettings() {
        document.getElementById('settingsModal').style.display = 'none';
    }

    getSettings() {
        return {
            autoAnalyze: document.getElementById('autoAnalyze')?.checked ?? true,
            realTimeSecrets: document.getElementById('realTimeSecrets')?.checked ?? false,
            maxIterations: parseInt(document.getElementById('maxIterations')?.value) || 10,
            analysisTimeout: parseInt(document.getElementById('analysisTimeout')?.value) || 30
        };
    }

    // Utility functions
    truncateUrl(url) {
        return url.length > 60 ? url.substring(0, 57) + '...' : url;
    }

    formatFileSize(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

// Initialize the application
const app = new DeobfuscatorApp();

// Add notification styles
const notificationStyles = `
    .notification {
        position: fixed;
        top: 20px;
        right: 20px;
        background: var(--bg-secondary);
        border: 1px solid var(--border-secondary);
        border-radius: var(--radius-md);
        padding: var(--spacing-md) var(--spacing-lg);
        display: flex;
        align-items: center;
        gap: var(--spacing-sm);
        z-index: 10000;
        max-width: 400px;
        box-shadow: var(--shadow-lg);
        animation: slideInRight 0.3s ease;
    }
    
    .notification.success {
        border-color: var(--accent-success);
        color: var(--accent-success);
    }
    
    .notification.error {
        border-color: var(--accent-danger);
        color: var(--accent-danger);
    }
    
    .notification.warning {
        border-color: var(--accent-warning);
        color: var(--accent-warning);
    }
    
    .notification.info {
        border-color: var(--accent-primary);
        color: var(--accent-primary);
    }
    
    .notification button {
        background: none;
        border: none;
        color: inherit;
        cursor: pointer;
        padding: var(--spacing-xs);
        margin-left: auto;
    }
    
    @keyframes slideInRight {
        from {
            transform: translateX(100%);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }
    
    .drag-over {
        border-color: var(--accent-primary) !important;
        background: rgba(6, 182, 212, 0.1) !important;
    }
`;

    // Real-time secret scanning for deobfuscator
    onInputChange() {
        const input = document.getElementById('codeInput').value;
        if (input.length > 10) { // Only scan if there's meaningful input
            this.performRealtimeSecretScan(input);
        } else {
            this.hideSecretsRealtime();
        }
    }

    async performRealtimeSecretScan(content) {
        try {
            const response = await fetch(`${this.apiBaseUrl}/secrets`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ input: content })
            });

            const result = await response.json();
            
            if (result.secrets && result.secrets.length > 0) {
                this.displayRealtimeSecrets(result);
            } else {
                this.hideSecretsRealtime();
            }
        } catch (error) {
            console.log('Real-time secret scan error:', error);
        }
    }

    displayRealtimeSecrets(secretsResult) {
        const container = document.getElementById('secretsRealtime');
        const listContainer = document.getElementById('secretsList');
        
        // Update stats
        document.getElementById('realtimeCritical').textContent = `${secretsResult.summary.critical} Critical`;
        document.getElementById('realtimeHigh').textContent = `${secretsResult.summary.high} High`;
        document.getElementById('realtimeMedium').textContent = `${secretsResult.summary.medium} Medium`;
        document.getElementById('realtimeLow').textContent = `${secretsResult.summary.low} Low`;
        
        // Display secrets
        const secretsHtml = secretsResult.secrets.map(secret => `
            <div class="secret-item ${secret.severity}">
                <div class="secret-header">
                    <span class="secret-type">${secret.type}</span>
                    <span class="severity-badge ${secret.severity}">${secret.severity}</span>
                </div>
                <div class="secret-value">${this.maskSensitiveValue(secret.value)}</div>
                <div class="secret-position">Position: ${secret.position}</div>
            </div>
        `).join('');
        
        listContainer.innerHTML = secretsHtml;
        container.style.display = 'block';
    }

    hideSecretsRealtime() {
        const container = document.getElementById('secretsRealtime');
        container.style.display = 'none';
    }

    maskSensitiveValue(value) {
        if (value.length <= 8) return '*'.repeat(value.length);
        return value.substring(0, 4) + '*'.repeat(Math.min(value.length - 8, 20)) + value.substring(value.length - 4);
    }

    updateSecretsCount(count) {
        const element = document.getElementById('secretsFound');
        if (element) {
            element.textContent = count;
            this.stats.secretsFound = count;
        }
    }

    // New web crawler functions
    analyzeScript(scriptIndex) {
        if (!this.crawlResults || !this.crawlResults.scripts[scriptIndex]) return;
        
        const script = this.crawlResults.scripts[scriptIndex];
        
        // Switch to deobfuscator mode and load the script content
        this.switchMode('deobfuscate');
        document.getElementById('codeInput').value = script.content;
        
        // Trigger analysis
        this.performDeobfuscation();
    }

    viewScriptContent(scriptIndex) {
        if (!this.crawlResults || !this.crawlResults.scripts[scriptIndex]) return;
        
        const script = this.crawlResults.scripts[scriptIndex];
        
        // Create modal to view content
        this.showContentModal(script.url, script.content);
    }

    viewScriptSecrets(scriptIndex) {
        if (!this.crawlResults || !this.crawlResults.scripts[scriptIndex]) return;
        
        const script = this.crawlResults.scripts[scriptIndex];
        
        if (script.secrets && script.secrets.secrets) {
            this.showSecretsModal(script.url, script.secrets);
        }
    }

    showContentModal(title, content) {
        const modal = document.createElement('div');
        modal.className = 'modal';
        modal.innerHTML = `
            <div class="modal-content" style="max-width: 90%; max-height: 90%;">
                <div class="modal-header">
                    <h3><i class="fas fa-code"></i> ${this.truncateUrl(title)}</h3>
                    <button class="modal-close" onclick="this.closest('.modal').remove()">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
                <div class="modal-body">
                    <pre style="max-height: 60vh; overflow: auto; background: var(--bg-primary); padding: 1rem; border-radius: 0.5rem;"><code>${this.escapeHtml(content)}</code></pre>
                </div>
            </div>
        `;
        
        document.body.appendChild(modal);
        
        // Close on backdrop click
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                modal.remove();
            }
        });
    }

    showSecretsModal(title, secretsResult) {
        const modal = document.createElement('div');
        modal.className = 'modal';
        
        const secretsHtml = secretsResult.secrets.map(secret => `
            <div class="secret-item ${secret.severity}" style="margin-bottom: 1rem; padding: 1rem; background: var(--bg-tertiary); border-radius: 0.5rem;">
                <div style="display: flex; justify-content: space-between; margin-bottom: 0.5rem;">
                    <strong>${secret.type}</strong>
                    <span class="severity-badge ${secret.severity}">${secret.severity}</span>
                </div>
                <div style="font-family: var(--font-mono); font-size: 0.875rem; background: var(--bg-primary); padding: 0.5rem; border-radius: 0.25rem;">
                    ${this.escapeHtml(secret.value)}
                </div>
                <div style="font-size: 0.75rem; color: var(--text-muted); margin-top: 0.5rem;">
                    Position: ${secret.position}
                </div>
            </div>
        `).join('');

        modal.innerHTML = `
            <div class="modal-content">
                <div class="modal-header">
                    <h3><i class="fas fa-key"></i> Secrets Found - ${this.truncateUrl(title)}</h3>
                    <button class="modal-close" onclick="this.closest('.modal').remove()">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
                <div class="modal-body" style="max-height: 60vh; overflow-y: auto;">
                    ${secretsHtml}
                </div>
            </div>
        `;
        
        document.body.appendChild(modal);
        
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                modal.remove();
            }
        });
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

// Initialize the application
const app = new DeobfuscatorApp();

// Inject notification styles
const styleSheet = document.createElement('style');
styleSheet.textContent = notificationStyles;
document.head.appendChild(styleSheet);