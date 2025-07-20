/**
 * Web Crawler Module - Website JavaScript Discovery
 */

class WebCrawlerModule {
    constructor() {
        this.apiBaseUrl = window.location.origin + '/api';
        this.crawlResults = null;
        this.isScanning = false;
        
        this.init();
    }

    async init() {
        this.setupEventListeners();
        await this.checkApiConnection();
    }

    setupEventListeners() {
        // Main functionality
        document.getElementById('startCrawlBtn').addEventListener('click', () => this.startWebCrawl());
        document.getElementById('stopCrawlBtn').addEventListener('click', () => this.stopWebCrawl());
        document.getElementById('clearResultsBtn').addEventListener('click', () => this.clearResults());
        document.getElementById('exportCrawlBtn').addEventListener('click', () => this.exportResults());

        // Filters
        document.getElementById('riskFilter').addEventListener('change', () => this.applyFilters());
        document.getElementById('typeFilter').addEventListener('change', () => this.applyFilters());

        // URL input
        document.getElementById('crawlUrl').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                this.startWebCrawl();
            }
        });
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

        if (this.isScanning) {
            this.showNotification('Crawl already in progress', 'warning');
            return;
        }

        const options = {
            includeExternalJS: document.getElementById('includeExternal').checked,
            includeInlineJS: document.getElementById('includeInline').checked,
            maxFiles: parseInt(document.getElementById('maxFiles').value) || 20,
            timeout: parseInt(document.getElementById('timeout').value) || 10
        };

        this.isScanning = true;
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

            if (response.ok && result.status === 'success') {
                this.displayCrawlResults(result);
                this.updateStatus(`Crawl completed - ${result.stats.totalScripts} scripts found, ${result.stats.secretsFound} secrets detected`, 'success');
                this.updateSecretsCount(result.stats.secretsFound);
                
                // Auto-analyze if enabled
                if (document.getElementById('autoAnalyze').checked) {
                    this.autoAnalyzeScripts(result.scripts);
                }
            } else {
                throw new Error(result.error || 'Crawl failed');
            }

        } catch (error) {
            this.showNotification(`Crawl error: ${error.message}`, 'error');
            this.updateStatus('Crawl failed', 'error');
        } finally {
            this.isScanning = false;
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
                    <p class="muted">Try a different URL or check the crawl options</p>
                </div>
            `;
            return;
        }

        const scriptsHtml = results.scripts.map((script, index) => `
            <div class="file-item ${script.riskLevel}" data-index="${index}" data-risk="${script.riskLevel}" data-type="${script.type}">
                <div class="file-header">
                    <div class="file-info">
                        <span class="file-type ${script.type}">${script.type}</span>
                        <span class="file-url" title="${script.url}">${this.truncateUrl(script.url)}</span>
                        <span class="file-size">${this.formatFileSize(script.size)}</span>
                    </div>
                    <div class="file-indicators">
                        ${script.content && script.content.includes('eval(') ? '<span class="indicator obfuscated" title="Potentially Obfuscated"><i class="fas fa-eye-slash"></i></span>' : ''}
                        ${script.secrets && script.secrets.secrets && script.secrets.secrets.length > 0 ? '<span class="indicator secrets" title="Contains Secrets"><i class="fas fa-key"></i></span>' : ''}
                        <span class="risk-badge ${script.riskLevel}">${script.riskLevel}</span>
                    </div>
                </div>
                <div class="file-stats">
                    ${script.secrets && script.secrets.secrets && script.secrets.secrets.length > 0 ? `<span class="stat-badge">🔑 ${script.secrets.secrets.length} secrets</span>` : ''}
                    <span class="stat-badge">📏 ${script.size || 0} bytes</span>
                    ${script.riskLevel === 'error' ? '<span class="stat-badge error">❌ Failed to fetch</span>' : ''}
                </div>
                <div class="file-actions">
                    <button class="btn-small" onclick="crawler.analyzeScript(${index})" ${!script.content || script.content.includes('Error fetching') ? 'disabled' : ''}>
                        <i class="fas fa-search"></i> Analyze
                    </button>
                    <button class="btn-small" onclick="crawler.viewScriptContent(${index})" ${!script.content || script.content.includes('Error fetching') ? 'disabled' : ''}>
                        <i class="fas fa-eye"></i> View
                    </button>
                    ${script.secrets && script.secrets.secrets && script.secrets.secrets.length > 0 ? `
                    <button class="btn-small" onclick="crawler.viewScriptSecrets(${index})">
                        <i class="fas fa-key"></i> Secrets
                    </button>` : ''}
                </div>
            </div>
        `).join('');

        container.innerHTML = scriptsHtml;
        this.crawlResults = results;
        
        // Update stats
        document.getElementById('pagesCount').textContent = '1';
        document.getElementById('filesCount').textContent = results.stats.totalScripts;
        document.getElementById('crawlSecretsCount').textContent = results.stats.secretsFound;
    }

    applyFilters() {
        if (!this.crawlResults) return;

        const riskFilter = document.getElementById('riskFilter').value;
        const typeFilter = document.getElementById('typeFilter').value;
        
        const fileItems = document.querySelectorAll('.file-item');
        let visibleCount = 0;

        fileItems.forEach(item => {
            const risk = item.dataset.risk;
            const type = item.dataset.type;
            
            const showRisk = riskFilter === 'all' || risk === riskFilter;
            const showType = typeFilter === 'all' || type === typeFilter;
            
            if (showRisk && showType) {
                item.style.display = 'block';
                visibleCount++;
            } else {
                item.style.display = 'none';
            }
        });

        this.updateStatus(`Showing ${visibleCount} of ${this.crawlResults.scripts.length} scripts`, 'info');
    }

    async autoAnalyzeScripts(scripts) {
        const highRiskScripts = scripts.filter(script => 
            script.riskLevel === 'high' && script.content && !script.content.includes('Error fetching')
        );

        if (highRiskScripts.length === 0) return;

        this.showNotification(`Auto-analyzing ${highRiskScripts.length} high-risk scripts...`, 'info');

        for (const script of highRiskScripts.slice(0, 3)) { // Limit to first 3
            try {
                await this.analyzeScriptInBackground(script);
            } catch (error) {
                console.log('Auto-analysis error:', error);
            }
        }

        this.showNotification('Auto-analysis completed', 'success');
    }

    async analyzeScriptInBackground(script) {
        // Silently analyze script without switching pages
        const response = await fetch(`${this.apiBaseUrl}/deobfuscate`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ 
                input: script.content,
                options: { maxIterations: 5 }
            })
        });

        const result = await response.json();
        return result;
    }

    analyzeScript(scriptIndex) {
        if (!this.crawlResults || !this.crawlResults.scripts[scriptIndex]) return;
        
        const script = this.crawlResults.scripts[scriptIndex];
        
        if (!script.content || script.content.includes('Error fetching')) {
            this.showNotification('Script content not available for analysis', 'warning');
            return;
        }
        
        // Store script content in session storage for deobfuscator
        sessionStorage.setItem('crawled_script', JSON.stringify({
            url: script.url,
            content: script.content,
            type: script.type
        }));
        
        // Navigate to deobfuscator
        window.location.href = 'deobfuscator.html?from=crawler';
    }

    viewScriptContent(scriptIndex) {
        if (!this.crawlResults || !this.crawlResults.scripts[scriptIndex]) return;
        
        const script = this.crawlResults.scripts[scriptIndex];
        
        if (!script.content || script.content.includes('Error fetching')) {
            this.showNotification('Script content not available', 'warning');
            return;
        }
        
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
                    <div class="code-preview">
                        <pre><code>${this.escapeHtml(content.substring(0, 5000))}${content.length > 5000 ? '\n\n... (truncated)' : ''}</code></pre>
                    </div>
                    <div class="modal-actions">
                        <button class="btn-primary" onclick="crawler.copyScriptContent('${this.escapeHtml(content)}')">
                            <i class="fas fa-copy"></i> Copy
                        </button>
                        <button class="btn-secondary" onclick="crawler.downloadScript('${title}', '${this.escapeHtml(content)}')">
                            <i class="fas fa-download"></i> Download
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

    showSecretsModal(title, secretsResult) {
        const modal = document.createElement('div');
        modal.className = 'modal';
        
        const secretsHtml = secretsResult.secrets.map(secret => `
            <div class="secret-item ${secret.severity}" style="margin-bottom: 1rem; padding: 1rem; background: var(--bg-tertiary); border-radius: 0.5rem;">
                <div style="display: flex; justify-content: space-between; margin-bottom: 0.5rem;">
                    <strong>${secret.type}</strong>
                    <span class="severity-badge ${secret.severity}">${secret.severity}</span>
                </div>
                <div style="font-family: var(--font-mono); font-size: 0.875rem; background: var(--bg-primary); padding: 0.5rem; border-radius: 0.25rem; word-break: break-all;">
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
                    <div class="modal-actions">
                        <button class="btn-primary" onclick="crawler.exportSecrets('${title}', ${JSON.stringify(secretsResult).replace(/"/g, '&quot;')})">
                            <i class="fas fa-download"></i> Export Secrets
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

    copyScriptContent(content) {
        navigator.clipboard.writeText(content).then(() => {
            this.showNotification('Script copied to clipboard', 'success');
        }).catch(() => {
            this.showNotification('Failed to copy script', 'error');
        });
    }

    downloadScript(title, content) {
        const filename = this.getFilenameFromUrl(title) || 'script.js';
        const blob = new Blob([content], { type: 'text/javascript' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        
        this.showNotification('Script downloaded', 'success');
    }

    exportSecrets(title, secretsData) {
        const exportData = {
            url: title,
            timestamp: new Date().toISOString(),
            secrets: secretsData
        };

        const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `secrets_${this.getFilenameFromUrl(title) || 'export'}_${Date.now()}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        
        this.showNotification('Secrets exported', 'success');
    }

    stopWebCrawl() {
        this.isScanning = false;
        this.showCrawlProgress(false);
        this.updateStatus('Crawl stopped', 'warning');
    }

    clearResults() {
        document.getElementById('discoveredFiles').innerHTML = `
            <div class="empty-state">
                <i class="fas fa-spider"></i>
                <p>Start crawling a website to discover JavaScript files</p>
            </div>
        `;
        
        this.crawlResults = null;
        document.getElementById('pagesCount').textContent = '0';
        document.getElementById('filesCount').textContent = '0';
        document.getElementById('crawlSecretsCount').textContent = '0';
        
        this.updateStatus('Results cleared', 'info');
    }

    exportResults() {
        if (!this.crawlResults) {
            this.showNotification('No results to export', 'warning');
            return;
        }

        const exportData = {
            crawl: {
                url: this.crawlResults.url,
                timestamp: this.crawlResults.timestamp,
                stats: this.crawlResults.stats
            },
            scripts: this.crawlResults.scripts.map(script => ({
                url: script.url,
                type: script.type,
                size: script.size,
                riskLevel: script.riskLevel,
                secretsCount: script.secrets?.secrets?.length || 0,
                hasObfuscation: script.content?.includes('eval(') || false
            })),
            secrets: this.crawlResults.secrets
        };

        const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `crawl_report_${Date.now()}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        
        this.showNotification('Crawl report exported', 'success');
    }

    showCrawlProgress(show) {
        const progressElement = document.getElementById('crawlProgress');
        progressElement.style.display = show ? 'block' : 'none';
        
        if (show) {
            document.getElementById('liveScriptCount').textContent = '0';
            document.getElementById('liveSecretCount').textContent = '0';
            document.getElementById('errorCount').textContent = '0';
        }
    }

    updateCrawlProgress(percent, text) {
        document.getElementById('progressFill').style.width = `${percent}%`;
        document.getElementById('progressText').textContent = text;
    }

    // Utility functions
    truncateUrl(url) {
        if (url.length <= 50) return url;
        return url.substring(0, 30) + '...' + url.substring(url.length - 15);
    }

    formatFileSize(bytes) {
        if (!bytes) return '0 B';
        const sizes = ['B', 'KB', 'MB'];
        const i = Math.floor(Math.log(bytes) / Math.log(1024));
        return `${(bytes / Math.pow(1024, i)).toFixed(1)} ${sizes[i]}`;
    }

    getFilenameFromUrl(url) {
        try {
            const pathname = new URL(url).pathname;
            return pathname.split('/').pop() || 'script.js';
        } catch {
            return 'script.js';
        }
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    updateSecretsCount(count) {
        const element = document.getElementById('crawlSecretsCount');
        if (element) {
            element.textContent = count;
        }
    }

    async checkApiConnection() {
        try {
            const response = await fetch(`${this.apiBaseUrl}/status`);
            const data = await response.json();
            this.updateStatus('Ready to crawl', 'success');
            document.getElementById('apiStatus').textContent = `API: Online`;
            document.getElementById('performanceInfo').textContent = 'Crawler: Ready';
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

// Example URL loader
function loadExample(url) {
    document.getElementById('crawlUrl').value = url;
    crawler.showNotification(`Loaded example: ${url}`, 'info');
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

    .example-urls {
        margin-top: 1rem;
        text-align: center;
    }

    .example-urls p {
        color: var(--text-muted);
        margin-bottom: 0.5rem;
    }

    .example-btn {
        background: var(--bg-quaternary);
        border: 1px solid var(--border-secondary);
        color: var(--text-primary);
        padding: 0.5rem 1rem;
        margin: 0.25rem;
        border-radius: var(--radius-md);
        cursor: pointer;
        transition: var(--transition-normal);
    }

    .example-btn:hover {
        background: var(--bg-hover);
        border-color: var(--border-accent);
    }

    .code-preview {
        background: var(--bg-primary);
        border-radius: var(--radius-md);
        padding: 1rem;
        margin-bottom: 1rem;
        max-height: 400px;
        overflow-y: auto;
    }

    .code-preview pre {
        margin: 0;
        font-family: var(--font-mono);
        font-size: 0.875rem;
        line-height: 1.5;
        color: var(--text-primary);
    }

    .modal-actions {
        display: flex;
        gap: 0.5rem;
        justify-content: flex-end;
        padding-top: 1rem;
        border-top: 1px solid var(--border-primary);
    }
`;

// Inject styles
const styleSheet = document.createElement('style');
styleSheet.textContent = notificationStyles;
document.head.appendChild(styleSheet);

// Initialize the crawler module
const crawler = new WebCrawlerModule();