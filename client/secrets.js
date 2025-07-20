/**
 * Secret Scanner Module - Dedicated Secret Detection
 */

class SecretScannerModule {
    constructor() {
        this.apiBaseUrl = window.location.origin + '/api';
        this.currentSecrets = null;
        this.stats = {
            totalScans: 0,
            secretsFound: 0,
            criticalSecrets: 0
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
        document.getElementById('scanSecretsBtn').addEventListener('click', () => this.performSecretScan());
        document.getElementById('pasteSecretsBtn').addEventListener('click', () => this.pasteFromClipboard());
        document.getElementById('clearSecretsBtn').addEventListener('click', () => this.clearResults());
        document.getElementById('exportSecretsBtn').addEventListener('click', () => this.exportSecrets());

        // File upload
        document.getElementById('secretFileUpload').addEventListener('change', (e) => this.handleFileUpload(e));

        // Real-time scanning
        document.getElementById('secretsInput').addEventListener('input', () => this.onInputChange());

        // Severity filters
        document.querySelectorAll('.severity-filter').forEach(filter => {
            filter.addEventListener('click', (e) => this.applySeverityFilter(e.target.dataset.severity));
        });

        // Pattern filters
        document.querySelectorAll('.filter-grid input[type="checkbox"]').forEach(checkbox => {
            checkbox.addEventListener('change', () => this.updatePatternFilters());
        });

        // Drag and drop
        this.setupDragAndDrop();
    }

    setupDragAndDrop() {
        const inputArea = document.getElementById('secretsInput');
        
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
            if (file.size > 50 * 1024 * 1024) { // 50MB limit
                this.showNotification('File too large. Maximum size is 50MB.', 'warning');
                continue;
            }
            
            try {
                const content = await this.readFile(file);
                document.getElementById('secretsInput').value = content;
                this.showNotification(`Loaded ${file.name}`, 'success');
                
                // Auto-scan after loading
                if (document.getElementById('scanMode').value === 'full') {
                    setTimeout(() => this.performSecretScan(), 500);
                }
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

    async performSecretScan() {
        const input = document.getElementById('secretsInput').value.trim();
        if (!input) {
            this.showNotification('Please enter content to scan for secrets', 'warning');
            return;
        }

        const options = {
            mode: document.getElementById('scanMode').value,
            sensitivity: document.getElementById('sensitivityLevel').value,
            patterns: this.getSelectedPatterns()
        };

        this.updateStatus('Scanning for secrets...', 'processing');
        
        try {
            const response = await fetch(`${this.apiBaseUrl}/secrets`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ input, options })
            });

            const result = await response.json();
            
            if (response.ok) {
                this.displaySecrets(result);
                this.updateStats(result);
                this.updateStatus(`Scan complete - ${result.secrets?.length || 0} secrets found`, 'success');
            } else {
                throw new Error(result.error || 'Secret scan failed');
            }

        } catch (error) {
            this.showNotification(`Scan error: ${error.message}`, 'error');
            this.updateStatus('Scan failed', 'error');
        }
    }

    getSelectedPatterns() {
        const patterns = [];
        if (document.getElementById('filterAPIs').checked) patterns.push('api');
        if (document.getElementById('filterCreds').checked) patterns.push('credentials');
        if (document.getElementById('filterCrypto').checked) patterns.push('crypto');
        if (document.getElementById('filterURLs').checked) patterns.push('urls');
        if (document.getElementById('filterPersonal').checked) patterns.push('personal');
        if (document.getElementById('filterCustom').checked) patterns.push('custom');
        return patterns;
    }

    displaySecrets(result) {
        const container = document.getElementById('secretsContainer');
        const summaryElement = document.getElementById('secretsSummary');
        
        if (!result.secrets || result.secrets.length === 0) {
            container.innerHTML = `
                <div class="empty-state">
                    <i class="fas fa-shield-alt"></i>
                    <p>No secrets detected in the provided content</p>
                    <p class="muted">This is good! Your content appears to be clean.</p>
                </div>
            `;
            summaryElement.style.display = 'none';
            return;
        }

        // Update summary stats
        document.getElementById('criticalCount').textContent = result.summary.critical || 0;
        document.getElementById('highCount').textContent = result.summary.high || 0;
        document.getElementById('mediumCount').textContent = result.summary.medium || 0;
        document.getElementById('lowCount').textContent = result.summary.low || 0;
        summaryElement.style.display = 'flex';

        // Display secrets
        const secretsHtml = result.secrets.map((secret, index) => `
            <div class="secret-item ${secret.severity}" data-severity="${secret.severity}" data-index="${index}">
                <div class="secret-header">
                    <div class="secret-type-info">
                        <span class="secret-type">${secret.type}</span>
                        <span class="secret-pattern">${secret.pattern || 'Custom'}</span>
                    </div>
                    <div class="secret-meta">
                        <span class="severity-badge ${secret.severity}">${secret.severity}</span>
                        <span class="confidence-score">${secret.confidence || 100}%</span>
                    </div>
                </div>
                <div class="secret-content">
                    <div class="secret-value">
                        <span class="value-label">Value:</span>
                        <code class="secret-code">${this.maskSensitiveValue(secret.value)}</code>
                        <button class="reveal-btn" onclick="secretScanner.toggleSecretVisibility(${index})">
                            <i class="fas fa-eye"></i>
                        </button>
                    </div>
                    <div class="secret-context">
                        <span class="context-label">Context:</span>
                        <pre class="context-preview">${this.getContextPreview(secret.context, secret.position)}</pre>
                    </div>
                </div>
                <div class="secret-actions">
                    <button class="btn-small" onclick="secretScanner.copySecret(${index})">
                        <i class="fas fa-copy"></i> Copy
                    </button>
                    <button class="btn-small" onclick="secretScanner.markFalsePositive(${index})">
                        <i class="fas fa-times-circle"></i> False Positive
                    </button>
                    <button class="btn-small" onclick="secretScanner.viewFullContext(${index})">
                        <i class="fas fa-search-plus"></i> Full Context
                    </button>
                </div>
            </div>
        `).join('');

        container.innerHTML = secretsHtml;
        this.currentSecrets = result;
    }

    getContextPreview(context, position) {
        if (!context) return 'No context available';
        
        const start = Math.max(0, position - 50);
        const end = Math.min(context.length, position + 50);
        let preview = context.substring(start, end);
        
        if (start > 0) preview = '...' + preview;
        if (end < context.length) preview = preview + '...';
        
        return this.escapeHtml(preview);
    }

    maskSensitiveValue(value) {
        if (value.length <= 8) return '*'.repeat(value.length);
        return value.substring(0, 3) + '*'.repeat(Math.min(value.length - 6, 15)) + value.substring(value.length - 3);
    }

    toggleSecretVisibility(secretIndex) {
        if (!this.currentSecrets || !this.currentSecrets.secrets[secretIndex]) return;
        
        const secret = this.currentSecrets.secrets[secretIndex];
        const codeElement = document.querySelector(`[data-index="${secretIndex}"] .secret-code`);
        const buttonElement = document.querySelector(`[data-index="${secretIndex}"] .reveal-btn i`);
        
        if (codeElement.dataset.revealed === 'true') {
            codeElement.textContent = this.maskSensitiveValue(secret.value);
            codeElement.dataset.revealed = 'false';
            buttonElement.className = 'fas fa-eye';
        } else {
            codeElement.textContent = secret.value;
            codeElement.dataset.revealed = 'true';
            buttonElement.className = 'fas fa-eye-slash';
        }
    }

    applySeverityFilter(severity) {
        // Update active filter button
        document.querySelectorAll('.severity-filter').forEach(btn => btn.classList.remove('active'));
        document.querySelector(`[data-severity="${severity}"]`).classList.add('active');
        
        // Filter secrets
        const secretItems = document.querySelectorAll('.secret-item');
        let visibleCount = 0;
        
        secretItems.forEach(item => {
            const itemSeverity = item.dataset.severity;
            if (severity === 'all' || itemSeverity === severity) {
                item.style.display = 'block';
                visibleCount++;
            } else {
                item.style.display = 'none';
            }
        });
        
        this.updateStatus(`Showing ${visibleCount} secrets (${severity} filter)`, 'info');
    }

    copySecret(secretIndex) {
        if (!this.currentSecrets || !this.currentSecrets.secrets[secretIndex]) return;
        
        const secret = this.currentSecrets.secrets[secretIndex];
        navigator.clipboard.writeText(secret.value).then(() => {
            this.showNotification('Secret copied to clipboard', 'success');
        }).catch(() => {
            this.showNotification('Failed to copy secret', 'error');
        });
    }

    markFalsePositive(secretIndex) {
        const secretItem = document.querySelector(`[data-index="${secretIndex}"]`);
        if (secretItem) {
            secretItem.style.opacity = '0.5';
            secretItem.classList.add('false-positive');
            this.showNotification('Marked as false positive', 'info');
        }
    }

    viewFullContext(secretIndex) {
        if (!this.currentSecrets || !this.currentSecrets.secrets[secretIndex]) return;
        
        const secret = this.currentSecrets.secrets[secretIndex];
        this.showContextModal(secret);
    }

    showContextModal(secret) {
        const modal = document.createElement('div');
        modal.className = 'modal';
        modal.innerHTML = `
            <div class="modal-content" style="max-width: 80%; max-height: 80%;">
                <div class="modal-header">
                    <h3><i class="fas fa-search-plus"></i> Full Context - ${secret.type}</h3>
                    <button class="modal-close" onclick="this.closest('.modal').remove()">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
                <div class="modal-body">
                    <div class="context-details">
                        <p><strong>Type:</strong> ${secret.type}</p>
                        <p><strong>Severity:</strong> <span class="severity-badge ${secret.severity}">${secret.severity}</span></p>
                        <p><strong>Position:</strong> ${secret.position}</p>
                        <p><strong>Confidence:</strong> ${secret.confidence || 100}%</p>
                    </div>
                    <div class="full-context">
                        <h4>Full Context:</h4>
                        <pre class="context-code">${this.escapeHtml(secret.context || 'No context available')}</pre>
                    </div>
                    <div class="modal-actions">
                        <button class="btn-primary" onclick="secretScanner.copyFullSecret('${this.escapeHtml(secret.value)}')">
                            <i class="fas fa-copy"></i> Copy Secret
                        </button>
                        <button class="btn-secondary" onclick="secretScanner.copyFullContext('${this.escapeHtml(secret.context || '')}')">
                            <i class="fas fa-clipboard"></i> Copy Context
                        </button>
                    </div>
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

    copyFullSecret(value) {
        navigator.clipboard.writeText(value).then(() => {
            this.showNotification('Secret copied to clipboard', 'success');
        }).catch(() => {
            this.showNotification('Failed to copy secret', 'error');
        });
    }

    copyFullContext(context) {
        navigator.clipboard.writeText(context).then(() => {
            this.showNotification('Context copied to clipboard', 'success');
        }).catch(() => {
            this.showNotification('Failed to copy context', 'error');
        });
    }

    // Real-time scanning
    onInputChange() {
        const input = document.getElementById('secretsInput').value;
        if (input.length > 50) {
            clearTimeout(this.scanTimeout);
            this.scanTimeout = setTimeout(() => {
                if (document.getElementById('scanMode').value === 'fast') {
                    this.performQuickScan(input);
                }
            }, 1000); // Longer debounce for secret scanning
        }
    }

    async performQuickScan(content) {
        try {
            const response = await fetch(`${this.apiBaseUrl}/secrets`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ 
                    input: content,
                    options: { mode: 'fast', quick: true }
                })
            });

            const result = await response.json();
            
            if (result.secrets && result.secrets.length > 0) {
                this.updateStatus(`${result.secrets.length} potential secrets detected`, 'warning');
            } else {
                this.updateStatus('No secrets detected', 'success');
            }
        } catch (error) {
            console.log('Quick scan error:', error);
        }
    }

    async pasteFromClipboard() {
        try {
            const text = await navigator.clipboard.readText();
            document.getElementById('secretsInput').value = text;
            this.showNotification('Content pasted from clipboard', 'success');
        } catch (error) {
            this.showNotification('Failed to paste from clipboard', 'error');
        }
    }

    clearResults() {
        document.getElementById('secretsInput').value = '';
        document.getElementById('secretsContainer').innerHTML = `
            <div class="empty-state">
                <i class="fas fa-key"></i>
                <p>No secrets detected yet</p>
                <p class="muted">Paste or upload content to scan for sensitive information</p>
            </div>
        `;
        document.getElementById('secretsSummary').style.display = 'none';
        this.currentSecrets = null;
        this.updateStatus('Cleared', 'success');
    }

    exportSecrets() {
        if (!this.currentSecrets || !this.currentSecrets.secrets || this.currentSecrets.secrets.length === 0) {
            this.showNotification('No secrets to export', 'warning');
            return;
        }

        const exportData = {
            timestamp: new Date().toISOString(),
            summary: this.currentSecrets.summary,
            totalSecrets: this.currentSecrets.secrets.length,
            secrets: this.currentSecrets.secrets.map(secret => ({
                type: secret.type,
                severity: secret.severity,
                pattern: secret.pattern,
                position: secret.position,
                confidence: secret.confidence,
                value: secret.value, // Include full value in export
                contextPreview: this.getContextPreview(secret.context, secret.position)
            }))
        };

        const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `secrets_report_${Date.now()}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        
        this.showNotification('Secrets report exported', 'success');
    }

    handleFileUpload(event) {
        const files = event.target.files;
        if (files.length > 0) {
            this.processDroppedFiles(files);
        }
    }

    updateStats(result) {
        this.stats.totalScans++;
        this.stats.secretsFound = result.secrets?.length || 0;
        this.stats.criticalSecrets = result.summary?.critical || 0;
        
        document.getElementById('totalScans').textContent = this.stats.totalScans;
        document.getElementById('secretsFound').textContent = this.stats.secretsFound;
        document.getElementById('criticalSecrets').textContent = this.stats.criticalSecrets;
        
        // Save to localStorage
        localStorage.setItem('secret_scanner_stats', JSON.stringify(this.stats));
    }

    loadStats() {
        const savedStats = localStorage.getItem('secret_scanner_stats');
        if (savedStats) {
            this.stats = JSON.parse(savedStats);
            document.getElementById('totalScans').textContent = this.stats.totalScans;
            document.getElementById('secretsFound').textContent = this.stats.secretsFound;
            document.getElementById('criticalSecrets').textContent = this.stats.criticalSecrets;
        }
    }

    updatePatternFilters() {
        // Update scan when filters change
        const input = document.getElementById('secretsInput').value.trim();
        if (input && this.currentSecrets) {
            this.performSecretScan();
        }
    }

    async checkApiConnection() {
        try {
            const response = await fetch(`${this.apiBaseUrl}/status`);
            const data = await response.json();
            this.updateStatus('Ready to scan', 'success');
            document.getElementById('apiStatus').textContent = `API: Online`;
            document.getElementById('performanceInfo').textContent = 'Scanner: Ready';
        } catch (error) {
            this.updateStatus('API connection failed', 'error');
            document.getElementById('apiStatus').textContent = 'API: Offline';
        }
    }

    updateStatus(text, type = 'info') {
        const statusElement = document.getElementById('statusText');
        const indicatorElement = document.getElementById('statusIndicator');
        
        statusElement.textContent = text;
        
        const colors = {
            success: 'var(--accent-success)',
            error: 'var(--accent-danger)',
            warning: 'var(--accent-warning)',
            processing: 'var(--accent-primary)',
            info: 'var(--accent-secondary)'
        };
        
        indicatorElement.style.background = colors[type] || colors.info;
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    showNotification(message, type = 'info') {
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
        
        document.body.appendChild(notification);
        
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

    .notification.success { border-left: 4px solid var(--accent-success); }
    .notification.error { border-left: 4px solid var(--accent-danger); }
    .notification.warning { border-left: 4px solid var(--accent-warning); }
    .notification.info { border-left: 4px solid var(--accent-primary); }

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
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
    }

    .drag-over {
        border-color: var(--accent-primary) !important;
        background: rgba(6, 182, 212, 0.1) !important;
    }

    .false-positive {
        opacity: 0.5 !important;
        text-decoration: line-through;
    }

    .context-code {
        background: var(--bg-primary);
        padding: 1rem;
        border-radius: var(--radius-md);
        font-family: var(--font-mono);
        font-size: 0.875rem;
        line-height: 1.5;
        white-space: pre-wrap;
        word-break: break-all;
        max-height: 400px;
        overflow-y: auto;
    }

    .context-details {
        background: var(--bg-tertiary);
        padding: 1rem;
        border-radius: var(--radius-md);
        margin-bottom: 1rem;
    }

    .context-details p {
        margin: 0.5rem 0;
    }

    .reveal-btn {
        background: none;
        border: none;
        color: var(--text-muted);
        cursor: pointer;
        margin-left: 0.5rem;
        padding: 0.25rem;
        border-radius: var(--radius-sm);
        transition: var(--transition-normal);
    }

    .reveal-btn:hover {
        background: var(--bg-hover);
        color: var(--text-primary);
    }
`;

// Inject styles
const styleSheet = document.createElement('style');
styleSheet.textContent = notificationStyles;
document.head.appendChild(styleSheet);

// Initialize the secret scanner module
const secretScanner = new SecretScannerModule();