/**
 * Deobfuscator Module - Dedicated Code Analysis
 */

class DeobfuscatorModule {
    constructor() {
        this.apiBaseUrl = window.location.origin + '/api';
        this.stats = {
            totalAnalyzes: 0,
            secretsFound: 0,
            iterations: 0
        };
        
        this.init();
    }

    async init() {
        this.setupEventListeners();
        await this.checkApiConnection();
        this.loadStats();
    }

    setupEventListeners() {
        // Main functionality
        document.getElementById('deobfuscateBtn').addEventListener('click', () => this.performDeobfuscation());
        document.getElementById('pasteBtn').addEventListener('click', () => this.pasteFromClipboard());
        document.getElementById('copyResultBtn').addEventListener('click', () => this.copyResults());
        document.getElementById('beautifyBtn').addEventListener('click', () => this.beautifyCode());
        document.getElementById('downloadBtn').addEventListener('click', () => this.downloadResult());
        document.getElementById('clearAllBtn').addEventListener('click', () => this.clearAll());
        document.getElementById('exportBtn').addEventListener('click', () => this.exportResults());

        // File upload
        document.getElementById('fileUpload').addEventListener('change', (e) => this.handleFileUpload(e));

        // Real-time input monitoring
        document.getElementById('codeInput').addEventListener('input', () => this.onInputChange());

        // Drag and drop
        this.setupDragAndDrop();
    }

    setupDragAndDrop() {
        const inputArea = document.getElementById('codeInput');
        
        inputArea.addEventListener('dragover', (e) => {
            e.preventDefault();
            inputArea.classList.add('drag-over');
        });

        inputArea.addEventListener('dragleave', () => {
            inputArea.classList.remove('drag-over');
        });

        inputArea.addEventListener('drop', (e) => {
            e.preventDefault();
            inputArea.classList.remove('drag-over');
            
            const files = e.dataTransfer.files;
            if (files.length > 0) {
                this.processDroppedFiles(files);
            }
        });
    }

    async processDroppedFiles(files) {
        for (const file of files) {
            if (file.size > 10 * 1024 * 1024) { // 10MB limit
                this.showNotification('File too large. Maximum size is 10MB.', 'warning');
                continue;
            }
            
            try {
                const content = await this.readFile(file);
                document.getElementById('codeInput').value = content;
                this.showNotification(`Loaded ${file.name}`, 'success');
                break; // Only load first file
            } catch (error) {
                this.showNotification(`Error reading ${file.name}: ${error.message}`, 'error');
            }
        }
    }

    readFile(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = (e) => resolve(e.target.result);
            reader.onerror = reject;
            reader.readAsText(file);
        });
    }

    async performDeobfuscation() {
        const input = document.getElementById('codeInput').value.trim();
        if (!input) {
            this.showNotification('Please enter code to analyze', 'warning');
            return;
        }

        const options = {
            language: document.getElementById('languageSelect').value,
            encoding: document.getElementById('encodingSelect').value,
            maxIterations: 10
        };

        this.updateStatus('Analyzing code...', 'processing');
        
        try {
            const response = await fetch(`${this.apiBaseUrl}/deobfuscate`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ input, options })
            });

            const result = await response.json();
            
            if (response.ok) {
                this.displayResults(result);
                this.updateStats();
                this.updateStatus('Analysis complete', 'success');
            } else {
                throw new Error(result.error || 'Analysis failed');
            }

        } catch (error) {
            this.showNotification(`Analysis error: ${error.message}`, 'error');
            this.updateStatus('Analysis failed', 'error');
        }
    }

    displayResults(result) {
        const outputElement = document.getElementById('codeOutput');
        outputElement.textContent = result.processed;
        
        // Update syntax highlighting
        Prism.highlightElement(outputElement);
        
        // Show analysis summary
        const summaryElement = document.getElementById('analysisSummary');
        document.getElementById('detectedEncoding').textContent = result.detectedEncodings.join(', ') || 'None';
        document.getElementById('iterationCount').textContent = result.iterations;
        document.getElementById('secretsCount').textContent = result.secrets?.secrets?.length || 0;
        
        const sizeReduction = ((result.size.original - result.size.final) / result.size.original * 100).toFixed(1);
        document.getElementById('sizeReduction').textContent = `${sizeReduction}%`;
        
        const riskElement = document.getElementById('riskLevel');
        riskElement.textContent = result.riskLevel;
        riskElement.className = `summary-value risk-indicator ${result.riskLevel}`;
        
        summaryElement.style.display = 'grid';

        // Display secrets if found
        if (result.secrets && result.secrets.secrets && result.secrets.secrets.length > 0) {
            this.displayRealtimeSecrets(result.secrets);
            this.updateSecretsCount(result.secrets.secrets.length);
        } else {
            this.hideSecretsRealtime();
        }

        // Update header stats
        document.getElementById('iterations').textContent = result.iterations;
    }

    // Real-time secret scanning
    onInputChange() {
        const input = document.getElementById('codeInput').value;
        if (input.length > 10) {
            clearTimeout(this.scanTimeout);
            this.scanTimeout = setTimeout(() => {
                this.performRealtimeSecretScan(input);
            }, 500); // Debounce
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

    async pasteFromClipboard() {
        try {
            const text = await navigator.clipboard.readText();
            document.getElementById('codeInput').value = text;
            this.showNotification('Code pasted from clipboard', 'success');
        } catch (error) {
            this.showNotification('Failed to paste from clipboard', 'error');
        }
    }

    async copyResults() {
        const output = document.getElementById('codeOutput').textContent;
        if (!output) {
            this.showNotification('No results to copy', 'warning');
            return;
        }

        try {
            await navigator.clipboard.writeText(output);
            this.showNotification('Results copied to clipboard', 'success');
        } catch (error) {
            this.showNotification('Failed to copy results', 'error');
        }
    }

    async beautifyCode() {
        const output = document.getElementById('codeOutput').textContent;
        if (!output) {
            this.showNotification('No code to beautify', 'warning');
            return;
        }

        try {
            const response = await fetch(`${this.apiBaseUrl}/beautify`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ 
                    input: output, 
                    type: document.getElementById('languageSelect').value 
                })
            });

            const result = await response.json();
            
            if (response.ok) {
                document.getElementById('codeOutput').textContent = result.beautified;
                Prism.highlightElement(document.getElementById('codeOutput'));
                this.showNotification('Code beautified', 'success');
            } else {
                throw new Error(result.error || 'Beautification failed');
            }

        } catch (error) {
            this.showNotification(`Beautification error: ${error.message}`, 'error');
        }
    }

    downloadResult() {
        const output = document.getElementById('codeOutput').textContent;
        if (!output) {
            this.showNotification('No results to download', 'warning');
            return;
        }

        const blob = new Blob([output], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `deobfuscated_${Date.now()}.txt`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        
        this.showNotification('Results downloaded', 'success');
    }

    handleFileUpload(event) {
        const files = event.target.files;
        if (files.length > 0) {
            this.processDroppedFiles(files);
        }
    }

    clearAll() {
        document.getElementById('codeInput').value = '';
        document.getElementById('codeOutput').textContent = '';
        document.getElementById('analysisSummary').style.display = 'none';
        document.getElementById('secretsRealtime').style.display = 'none';
        this.updateStatus('Cleared', 'success');
    }

    exportResults() {
        const input = document.getElementById('codeInput').value;
        const output = document.getElementById('codeOutput').textContent;
        
        if (!output) {
            this.showNotification('No results to export', 'warning');
            return;
        }

        const exportData = {
            timestamp: new Date().toISOString(),
            input: input,
            output: output,
            analysis: {
                encoding: document.getElementById('detectedEncoding').textContent,
                iterations: document.getElementById('iterationCount').textContent,
                riskLevel: document.getElementById('riskLevel').textContent,
                secretsFound: document.getElementById('secretsCount').textContent
            }
        };

        const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `analysis_report_${Date.now()}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        
        this.showNotification('Analysis report exported', 'success');
    }

    updateStats() {
        this.stats.totalAnalyzes++;
        document.getElementById('totalAnalyzes').textContent = this.stats.totalAnalyzes;
        
        // Save to localStorage
        localStorage.setItem('deobfuscator_stats', JSON.stringify(this.stats));
    }

    loadStats() {
        const savedStats = localStorage.getItem('deobfuscator_stats');
        if (savedStats) {
            this.stats = JSON.parse(savedStats);
            document.getElementById('totalAnalyzes').textContent = this.stats.totalAnalyzes;
            document.getElementById('secretsFound').textContent = this.stats.secretsFound;
        }
    }

    async checkApiConnection() {
        try {
            const response = await fetch(`${this.apiBaseUrl}/status`);
            const data = await response.json();
            this.updateStatus('Connected', 'success');
            document.getElementById('apiStatus').textContent = `API: Online (${data.techniques} techniques)`;
        } catch (error) {
            this.updateStatus('Connection failed', 'error');
            document.getElementById('apiStatus').textContent = 'API: Offline';
        }
    }

    updateStatus(text, type = 'info') {
        const statusElement = document.getElementById('statusText');
        const indicatorElement = document.getElementById('statusIndicator');
        
        statusElement.textContent = text;
        
        // Update indicator color
        const colors = {
            success: 'var(--accent-success)',
            error: 'var(--accent-danger)',
            warning: 'var(--accent-warning)',
            processing: 'var(--accent-primary)',
            info: 'var(--accent-secondary)'
        };
        
        indicatorElement.style.background = colors[type] || colors.info;
    }

    showNotification(message, type = 'info') {
        // Create notification element
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        notification.innerHTML = `
            <div class="notification-content">
                <i class="fas fa-${this.getNotificationIcon(type)}"></i>
                <span>${message}</span>
            </div>
            <button class="notification-close" onclick="this.parentElement.remove()">
                <i class="fas fa-times"></i>
            </button>
        `;
        
        // Add to page
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
}

// Notification styles
const notificationStyles = `
    .notification {
        position: fixed;
        top: 20px;
        right: 20px;
        background: var(--bg-secondary);
        border: 1px solid var(--border-primary);
        border-radius: var(--radius-lg);
        padding: var(--spacing-lg);
        box-shadow: var(--shadow-xl);
        z-index: 1000;
        display: flex;
        align-items: center;
        gap: var(--spacing-md);
        min-width: 300px;
        animation: slideIn 0.3s ease-out;
    }

    .notification.success {
        border-left: 4px solid var(--accent-success);
    }

    .notification.error {
        border-left: 4px solid var(--accent-danger);
    }

    .notification.warning {
        border-left: 4px solid var(--accent-warning);
    }

    .notification.info {
        border-left: 4px solid var(--accent-primary);
    }

    .notification-content {
        display: flex;
        align-items: center;
        gap: var(--spacing-sm);
        flex: 1;
        color: var(--text-primary);
    }

    .notification-close {
        background: none;
        border: none;
        color: var(--text-muted);
        cursor: pointer;
        padding: var(--spacing-xs);
        border-radius: var(--radius-sm);
        transition: var(--transition-normal);
    }

    .notification-close:hover {
        background: var(--bg-hover);
        color: var(--text-primary);
    }

    @keyframes slideIn {
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

// Inject styles
const styleSheet = document.createElement('style');
styleSheet.textContent = notificationStyles;
document.head.appendChild(styleSheet);

// Initialize the deobfuscator module
const deobfuscator = new DeobfuscatorModule();