/**
 * 0xDe-Obfuscator - Simple Web Server
 * Direct static file serving for testing
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');
const axios = require('axios');
const cheerio = require('cheerio');

// Import our encoding engine
const EncodingEngine = require('./lib/encoders');

const PORT = process.env.PORT || 3000;
const encoder = new EncodingEngine();

// MIME types
const mimeTypes = {
    '.html': 'text/html',
    '.css': 'text/css',
    '.js': 'application/javascript',
    '.json': 'application/json',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.gif': 'image/gif',
    '.ico': 'image/x-icon'
};

const server = http.createServer(async (req, res) => {
    const parsedUrl = url.parse(req.url, true);
    const pathname = parsedUrl.pathname;

    // Enable CORS for all requests
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

    // Handle OPTIONS preflight requests
    if (req.method === 'OPTIONS') {
        res.writeHead(200);
        res.end();
        return;
    }

    // Handle favicon request
    if (pathname === '/favicon.ico') {
        res.writeHead(204);
        res.end();
        return;
    }

    // API Routes
    if (pathname.startsWith('/api/')) {
        await handleAPI(req, res, pathname);
        return;
    }

    // Serve static files
    let filePath = path.join(__dirname, 'client', pathname === '/' ? 'index.html' : pathname);
    
    fs.readFile(filePath, (err, data) => {
        if (err) {
            res.writeHead(404);
            res.end('File not found');
            return;
        }

        const ext = path.extname(filePath);
        const contentType = mimeTypes[ext] || 'text/plain';
        
        res.writeHead(200, { 'Content-Type': contentType });
        res.end(data);
    });
});

async function handleAPI(req, res, pathname) {
    // Allow GET for some endpoints, POST for others
    const allowedMethods = ['GET', 'POST'];
    if (!allowedMethods.includes(req.method)) {
        res.writeHead(405, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Method not allowed' }));
        return;
    }

    // Handle GET requests for status/info endpoints
    if (req.method === 'GET') {
        let result = {};
        
        switch (pathname) {
            case '/api/status':
                result = {
                    status: 'online',
                    techniques: encoder.getTechniqueCount(),
                    version: '2.0.0'
                };
                break;
            case '/api/techniques':
                result = encoder.getTechniqueInfo();
                break;
            default:
                res.writeHead(404, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'Endpoint not found' }));
                return;
        }
        
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(result));
        return;
    }

    // Handle POST requests
    if (req.method !== 'POST') {
        res.writeHead(405, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'POST method required for this endpoint' }));
        return;
    }

    let body = '';
    req.on('data', chunk => {
        body += chunk.toString();
    });

    req.on('end', async () => {
        try {
            const data = JSON.parse(body);
            let result = {};

            switch (pathname) {
                case '/api/deobfuscate':
                    result = await encoder.processInput(data.input, data.options);
                    // Add real-time secret scanning
                    result.secrets = detectSecrets(result.processed);
                    break;

                case '/api/secrets':
                    result = detectSecrets(data.input);
                    break;

                case '/api/crawl':
                    result = await crawlWebsite(data.url, data.options);
                    break;

                case '/api/beautify':
                    result = {
                        beautified: encoder.beautifyCode(data.input, data.type || 'javascript')
                    };
                    break;

                default:
                    res.writeHead(404);
                    res.end('API endpoint not found');
                    return;
            }

            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(result));
        } catch (error) {
            res.writeHead(500);
            res.end(JSON.stringify({ error: error.message }));
        }
    });
}

function detectSecrets(input) {
    const secrets = [];
    const seenSecrets = new Set(); // Duplicate detection
    
    const patterns = {
        'AWS Access Key ID': {
            pattern: /\b((A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})\b/g,
            confidence: 99
        },
        'AWS Secret Access Key': {
            pattern: /(?:aws[_-]?secret[_-]?access[_-]?key|secret[_-]?access[_-]?key|aws[_-]?secret)['":\s=]+['"]*([A-Za-z0-9/+=]{40})["']*/gi,
            confidence: 95
        },
        'AWS Session Token': {
            pattern: /(?:aws[_-]?session[_-]?token|session[_-]?token)['":\s=]+['"]*([A-Za-z0-9/+=]{100,500})["']*/gi,
            confidence: 90
        },
        'AWS Account ID': {
            pattern: /(?:aws[_-]?account[_-]?id|account[_-]?id)['":\s=]+['"]*([0-9]{4}-?[0-9]{4}-?[0-9]{4})["']*/gi,
            confidence: 85
        },
        'AWS MWS Auth Token': {
            pattern: /\b(amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b/g,
            confidence: 98
        },
        'GitHub Personal Access Token': {
            pattern: /\b(ghp_[A-Za-z0-9]{36})\b/g,
            confidence: 99
        },
        'GitHub Fine-grained Token': {
            pattern: /\b(github_pat_[A-Za-z0-9_]{82})\b/g,
            confidence: 99
        },
        'GitHub OAuth Token': {
            pattern: /\b(gho_[A-Za-z0-9]{36})\b/g,
            confidence: 99
        },
        'GitHub App Token': {
            pattern: /\b(ghs_[A-Za-z0-9]{36})\b/g,
            confidence: 99
        },
        'GitHub Refresh Token': {
            pattern: /\b(ghr_[A-Za-z0-9]{76})\b/g,
            confidence: 99
        },
        'GitHub Generic Token': {
            pattern: /(?:github|git)['":\s=]+['"]*([0-9a-zA-Z]{35,40})["']*/gi,
            confidence: 75
        },
        'GitLab Personal Access Token': {
            pattern: /\b(glpat-[A-Za-z0-9_-]{20})\b/g,
            confidence: 98
        },
        'Slack Bot Token': {
            pattern: /\b(xoxb-[0-9]{11,13}-[0-9]{11,13}-[A-Za-z0-9]{24})\b/g,
            confidence: 99
        },
        'Slack User Token': {
            pattern: /\b(xoxp-[0-9]{11,13}-[0-9]{11,13}-[0-9]{11,13}-[A-Za-z0-9]{32})\b/g,
            confidence: 99
        },
        'Slack Generic Token': {
            pattern: /\b(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})\b/g,
            confidence: 95
        },
        'Slack Webhook URL': {
            pattern: /https:\/\/hooks\.slack\.com\/services\/[A-Z0-9]{9}\/[A-Z0-9]{9}\/[A-Za-z0-9]{24}/g,
            confidence: 98
        },
        'Discord Bot Token': {
            pattern: /\b([MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27})\b/g,
            confidence: 97
        },
        'Discord Webhook': {
            pattern: /https:\/\/discord(?:app)?\.com\/api\/webhooks\/[0-9]{17,19}\/[A-Za-z0-9\-_]{68}/g,
            confidence: 98
        },
        'Discord Client Secret': {
            pattern: /(?:discord[_-]?client[_-]?secret|client[_-]?secret)['":\s=]+['"]*([A-Za-z0-9_-]{32})["']*/gi,
            confidence: 90
        },
        'JWT Bearer Token': {
            pattern: /\b(eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*)\b/g,
            confidence: 88
        },
        'Google API Key': {
            pattern: /\b(AIza[0-9A-Za-z-_]{35})\b/g,
            confidence: 98
        },
        'Google OAuth Client ID': {
            pattern: /[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com/g,
            confidence: 97
        },
        'Google OAuth Client Secret': {
            pattern: /(?:client[_-]?secret)['":\s=]+['"]*([0-9A-Za-z_-]{24})["']*/gi,
            confidence: 85
        },
        'Facebook Access Token': {
            pattern: /\b(EAA[A-Za-z0-9]{90,200})\b/g,
            confidence: 95
        },
        'Twitter API Key': {
            pattern: /(?:twitter[_-]?api[_-]?key|consumer[_-]?key)['":\s=]+['"]*([A-Za-z0-9]{25})["']*/gi,
            confidence: 85
        },
        'Twitter API Secret': {
            pattern: /(?:twitter[_-]?api[_-]?secret|consumer[_-]?secret)['":\s=]+['"]*([A-Za-z0-9]{50})["']*/gi,
            confidence: 85
        },
        'Twitter Bearer Token': {
            pattern: /\b(AAAAAAAAAAAAAAAAAAA[A-Za-z0-9%]{60,80})\b/g,
            confidence: 95
        },
        'Stripe API Key': {
            pattern: /\b(sk_live_[0-9a-zA-Z]{24})\b/g,
            confidence: 99
        },
        'Stripe Test Key': {
            pattern: /\b(sk_test_[0-9a-zA-Z]{24})\b/g,
            confidence: 99
        },
        'PayPal Client ID': {
            pattern: /\b(A[A-Za-z0-9_-]{80})\b/g,
            confidence: 85
        },
        'Twilio Account SID': {
            pattern: /\b(AC[a-fA-F0-9]{32})\b/g,
            confidence: 98
        },
        'Twilio Auth Token': {
            pattern: /\b([a-fA-F0-9]{32})\b/g,
            confidence: 75
        },
        'SendGrid API Key': {
            pattern: /\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b/g,
            confidence: 99
        },
        'Mailgun API Key': {
            pattern: /\b(key-[a-fA-F0-9]{32})\b/g,
            confidence: 95
        },
        'MongoDB Connection String': {
            pattern: /mongodb(?:\+srv)?:\/\/[^\s'";)]*[a-zA-Z0-9]/g,
            confidence: 92
        },
        'PostgreSQL Connection String': {
            pattern: /postgres(?:ql)?:\/\/[^\s'";)]*[a-zA-Z0-9]/g,
            confidence: 92
        },
        'MySQL Connection String': {
            pattern: /mysql:\/\/[^\s'";)]*[a-zA-Z0-9]/g,
            confidence: 92
        },
        'Redis Connection String': {
            pattern: /redis:\/\/[^\s'";)]*[a-zA-Z0-9]/g,
            confidence: 92
        },
        'RSA Private Key': {
            pattern: /-----BEGIN RSA PRIVATE KEY-----[\s\S]*?-----END RSA PRIVATE KEY-----/g,
            confidence: 99
        },
        'ECDSA Private Key': {
            pattern: /-----BEGIN EC PRIVATE KEY-----[\s\S]*?-----END EC PRIVATE KEY-----/g,
            confidence: 99
        },
        'DSA Private Key': {
            pattern: /-----BEGIN DSA PRIVATE KEY-----[\s\S]*?-----END DSA PRIVATE KEY-----/g,
            confidence: 99
        },
        'PGP Private Key': {
            pattern: /-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]*?-----END PGP PRIVATE KEY BLOCK-----/g,
            confidence: 99
        },
        'SSH Private Key': {
            pattern: /-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]*?-----END OPENSSH PRIVATE KEY-----/g,
            confidence: 99
        },
        'Generic Private Key': {
            pattern: /-----BEGIN[A-Z\s]*PRIVATE KEY-----[\s\S]*?-----END[A-Z\s]*PRIVATE KEY-----/g,
            confidence: 95
        },
        'API Key (Generic)': {
            pattern: /(?:api[_-]?key|apikey|api_token|access[_-]?token)['":\s=]+['"]*([A-Za-z0-9_-]{20,128})["']*/gi,
            confidence: 75
        },
        'Bearer Token': {
            pattern: /(?:bearer[_-]?token|authorization['":\s=]+bearer)['":\s=]+['"]*([A-Za-z0-9_.-]{20,500})["']*/gi,
            confidence: 80
        },
        'OAuth Token': {
            pattern: /(?:oauth[_-]?token|access[_-]?token)['":\s=]+['"]*([A-Za-z0-9_.-]{20,200})["']*/gi,
            confidence: 75
        },
        'Password (Suspicious)': {
            pattern: /(?:password|passwd|pwd)['":\s=]+['"]*([A-Za-z0-9!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]{8,50})["']*/gi,
            confidence: 65
        },
        'Email Address': {
            pattern: /\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b/g,
            confidence: 90
        },
        'IP Address (Private)': {
            pattern: /\b((?:10\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))|(?:172\.(?:1[6-9]|2[0-9]|3[0-1])\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))|(?:192\.168\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)))\b/g,
            confidence: 85
        },
        'URL with Credentials': {
            pattern: /https?:\/\/[a-zA-Z0-9._-]+:[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+/g,
            confidence: 95
        },
        'Docker Registry Token': {
            pattern: /(?:docker[_-]?token|registry[_-]?token)['":\s=]+['"]*([A-Za-z0-9._-]{20,200})["']*/gi,
            confidence: 85
        },
        'Kubernetes Service Token': {
            pattern: /(?:k8s[_-]?token|kubernetes[_-]?token|service[_-]?account[_-]?token)['":\s=]+['"]*([A-Za-z0-9._-]{20,200})["']*/gi,
            confidence: 85
        },
        'Azure Client Secret': {
            pattern: /(?:azure[_-]?client[_-]?secret|client[_-]?secret)['":\s=]+['"]*([A-Za-z0-9._~-]{34,40})["']*/gi,
            confidence: 90
        },
        'Heroku API Key': {
            pattern: /(?:heroku[_-]?api[_-]?key|heroku)['":\s=]+['"]*([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})["']*/gi,
            confidence: 92
        },
        'Firebase API Key': {
            pattern: /\b(AIza[0-9A-Za-z_-]{35})\b/g,
            confidence: 95
        },
        'Shopify Access Token': {
            pattern: /shpat_[a-fA-F0-9]{32}/g,
            confidence: 98
        },
        'Square Access Token': {
            pattern: /\b(sq0atp-[0-9A-Za-z\-_]{22})\b/g,
            confidence: 98
        },
        'Square Application Secret': {
            pattern: /\b(sq0csp-[0-9A-Za-z\-_]{43})\b/g,
            confidence: 98
        },
        'Auth0 Client ID': {
            pattern: /(?:auth0[_-]?client[_-]?id|client[_-]?id)['":\s=]+['"]*([A-Za-z0-9]{32})["']*/gi,
            confidence: 92
        },
        'Auth0 Client Secret': {
            pattern: /(?:auth0[_-]?client[_-]?secret|client[_-]?secret)['":\s=]+['"]*([A-Za-z0-9_-]{64})["']*/gi,
            confidence: 95
        },
        'Auth0 Domain': {
            pattern: /(?:auth0[_-]?domain|domain)['":\s=]+['"]*([a-zA-Z0-9.-]+\.auth0\.com)["']*/gi,
            confidence: 90
        },
        'Generic API Key (High Entropy)': {
            pattern: /(?:api[_-]?key|apikey|token|secret)['":\s=]+['"]*([A-Za-z0-9_-]{32,128})["']*/gi,
            confidence: 70
        },
        'Generic Client ID (32 chars)': {
            pattern: /\b([A-Za-z0-9]{32})\b/g,
            confidence: 60
        },
        'Telegram Bot Token': {
            pattern: /\b([0-9]{9,10}:[A-Za-z0-9_-]{35})\b/g,
            confidence: 95
        },
        'DigitalOcean Token': {
            pattern: /\b(doo_[A-Za-z0-9]{64})\b/g,
            confidence: 98
        },
        'DigitalOcean Spaces Key': {
            pattern: /\b((?:AKIA|ASIA)[A-Z0-9]{16})\b/g,
            confidence: 95
        },
        'Base64 Encoded Token': {
            pattern: /(?:token|key|secret|auth)['":\s=]+['"]*([A-Za-z0-9+/]{40,}={0,2})["']*/gi,
            confidence: 70
        },
        'UUID/GUID': {
            pattern: /\b([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\b/g,
            confidence: 80
        },
        'JWT Secret Key (Contextual)': {
            pattern: /(?:jwt[_-]?secret[_-]?key|secret[_-]?key|jwt[_-]?secret)['":\s=]+['"]*([A-Za-z0-9_.-]{16,})["']*/gi,
            confidence: 95
        },
        'JWT Secret Key (SHA256 Hash)': {
            pattern: /\b([a-f0-9]{64})\b/g,
            confidence: 88
        },
        'JWT Secret Key (Long Hex)': {
            pattern: /\b([a-f0-9]{40,128})\b/g,
            confidence: 75
        }
    };

    for (const [type, config] of Object.entries(patterns)) {
        let match;
        const regex = new RegExp(config.pattern);
        
        while ((match = regex.exec(input)) !== null) {
            let secretValue = match[1] || match[0];
            
            // Filter out obvious false positives
            if (isLikelyFalsePositive(secretValue, type)) {
                continue;
            }
            
            // Enhanced duplicate detection - check for same value across all types
            const valueKey = secretValue.toLowerCase();
            if (seenSecrets.has(valueKey)) {
                continue;
            }
            seenSecrets.add(valueKey);
            
            const position = match.index;
            const context = getContext(input, position, 100);
            
            secrets.push({
                type,
                value: secretValue,
                severity: getSeverity(type),
                confidence: config.confidence,
                position,
                context,
                pattern: config.pattern.source
            });
        }
    }

    return {
        secrets,
        summary: {
            total: secrets.length,
            critical: secrets.filter(s => s.severity === 'critical').length,
            high: secrets.filter(s => s.severity === 'high').length,
            medium: secrets.filter(s => s.severity === 'medium').length,
            low: secrets.filter(s => s.severity === 'low').length
        }
    };
}

function isLikelyFalsePositive(value, type) {
    const falsePositives = {
        'Password (Suspicious)': [
            'password', 'PASSWORD', '123456', 'example', 'test', 'demo', 'null', 'undefined',
            'placeholder', 'your_password', 'enter_password', 'change_me', 'admin', 'root',
            'guest', 'user', 'default', 'secret', 'qwerty', 'asdfgh', 'zxcvbn'
        ],
        'API Key (Generic)': [
            'your_api_key', 'api_key_here', 'enter_api_key', 'example_key', 'test_key',
            'placeholder', 'key123', 'abc123', 'null', 'undefined', 'YOUR_API_KEY',
            'INSERT_API_KEY_HERE', 'REPLACE_WITH_API_KEY'
        ],
        'Bearer Token': [
            'bearer_token_here', 'your_bearer_token', 'INSERT_TOKEN', 'example_token',
            'test_token', 'placeholder_token', 'BEARER_TOKEN_HERE'
        ],
        'OAuth Token': [
            'oauth_token_here', 'your_oauth_token', 'access_token_here', 'example_oauth',
            'test_oauth', 'placeholder_oauth'
        ],
        'JWT Bearer Token': [
            'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
            // This is the most common example JWT from jwt.io
        ],
        'Email Address': [
            'example@example.com', 'test@test.com', 'user@domain.com', 'admin@admin.com',
            'foo@bar.com', 'john@doe.com', 'jane@doe.com', 'noreply@example.com'
        ],
        'Auth0 Client ID': [
            'your_auth0_client_id', 'AUTH0_CLIENT_ID', 'client_id_here', 'example_client_id'
        ],
        'Generic Client ID (32 chars)': [
            'abcdefghijklmnopqrstuvwxyz123456', '12345678901234567890123456789012',
            'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
        ],
        'Base64 Encoded Token': [
            'VGhpcyBpcyBhIHRlc3QgdG9rZW4gZm9yIGV4YW1wbGU',
            'dGVzdA==', 'ZXhhbXBsZQ==', 'cGxhY2Vob2xkZXI='
        ]
    };
    
    const typeSpecific = falsePositives[type] || [];
    
    // Common false positives for all types
    const common = [
        'example', 'test', 'demo', 'placeholder', 'dummy', 'fake', 'sample',
        'null', 'undefined', 'none', 'empty', 'default', 'change_me', 'replace_me',
        'insert_here', 'your_', 'enter_', 'add_your', 'put_your', 'lorem', 'ipsum',
        'EXAMPLE', 'TEST', 'DEMO', 'PLACEHOLDER', 'DUMMY', 'FAKE', 'SAMPLE'
    ];
    
    const allFalsePositives = [...typeSpecific, ...common];
    
    // Skip false positive check for high-confidence patterns with specific formats
    const highConfidenceTypes = [
        'AWS Access Key ID', 'AWS MWS Auth Token', 'GitHub Personal Access Token', 'GitHub Fine-grained Token',
        'GitHub OAuth Token', 'GitHub App Token', 'GitHub Refresh Token', 'GitLab Personal Access Token',
        'Slack Bot Token', 'Slack User Token', 'Slack Generic Token', 'Discord Bot Token', 'Google API Key',
        'Stripe API Key', 'Stripe Test Key', 'SendGrid API Key', 'RSA Private Key',
        'ECDSA Private Key', 'DSA Private Key', 'PGP Private Key', 'SSH Private Key',
        'Shopify Access Token', 'Square Access Token', 'Square Application Secret',
        'Auth0 Client ID', 'Auth0 Client Secret', 'JWT Secret Key (Contextual)',
        'JWT Secret Key (SHA256 Hash)', 'JWT Secret Key (Long Hex)', 'Telegram Bot Token',
        'DigitalOcean Token', 'DigitalOcean Spaces Key', 'Firebase API Key'
    ];
    
    const lowConfidenceTypes = [
        'Generic Client ID (32 chars)', 'Base64 Encoded Token', 
        'UUID/GUID', 'Email Address', 'IP Address (Private)'
    ];
    
    if (highConfidenceTypes.includes(type)) {
        // Only check for very obvious false positives in high-confidence patterns
        return allFalsePositives.some(fp => value.toLowerCase() === fp.toLowerCase());
    }
    
    if (lowConfidenceTypes.includes(type)) {
        // More aggressive filtering for low-confidence patterns
        if (value.length < 16) return true;
        if (allFalsePositives.some(fp => value.toLowerCase().includes(fp.toLowerCase()))) return true;
        
        // Additional checks for generic patterns
        if (type === 'Generic Client ID (32 chars)') {
            // Skip if it's a simple repetitive pattern
            if (/^(.)\1{31}$/.test(value)) return true; // All same character
            if (/^(..)\1{15}$/.test(value)) return true; // Repeating 2-char pattern
            if (/^[0-9]{32}$/.test(value)) return true; // All numbers
            if (/^[a-f0-9]{32}$/i.test(value) && !/[g-z]/i.test(value)) return true; // Looks like hash but too short
        }
        
        if (type === 'Base64 Encoded Token') {
            // Skip very short base64 or obvious examples
            if (value.length < 20) return true;
            if (value === btoa('test') || value === btoa('example')) return true;
            // Skip if it looks like a hash or random hex string
            if (/^[a-f0-9]{40,}$/i.test(value)) return true;
        }
        
        
        return false;
    }
    
    // Standard false positive checks for medium confidence patterns
    if (value.length < 8) return true;
    if (allFalsePositives.some(fp => value.toLowerCase().includes(fp.toLowerCase()))) return true;
    
    // Pattern-specific checks
    if (type.includes('Email')) {
        // Allow valid email formats, but exclude obvious examples
        return typeSpecific.includes(value.toLowerCase());
    }
    
    if (type.includes('Password')) {
        // Reject obvious passwords and short values
        if (value.length < 8) return true;
        if (/^[a-z]+$/.test(value.toLowerCase()) && value.length < 12) return true;
        if (/^[0-9]+$/.test(value)) return true;
        if (/^[a-f0-9]+$/i.test(value) && value.length < 16) return true;
        // Reject JavaScript code snippets
        if (value.includes('!0,') || value.includes(';}') || value.includes('for(')) return true;
        if (value.includes('pseudos') || value.includes('image:')) return true;
    }
    
    if (type.includes('API Key') || type.includes('Token')) {
        // Reject simple patterns for API keys
        if (/^[a-z]+$/.test(value.toLowerCase()) && value.length < 20) return true;
        if (/^[0-9]+$/.test(value)) return true;
        if (value.length < 16 && !/[A-Z]/.test(value) && !/[0-9]/.test(value)) return true;
    }
    
    return false;
}

function getContext(input, position, length = 100) {
    const start = Math.max(0, position - length);
    const end = Math.min(input.length, position + length);
    return input.substring(start, end);
}

function getSeverity(type) {
    const severityMap = {
        // Critical - Cloud provider access keys and private keys
        'AWS Access Key ID': 'critical',
        'AWS Secret Access Key': 'critical',
        'AWS Session Token': 'critical',
        'AWS Account ID': 'medium',
        'AWS MWS Auth Token': 'high',
        'RSA Private Key': 'critical',
        'ECDSA Private Key': 'critical',
        'DSA Private Key': 'critical',
        'PGP Private Key': 'critical',
        'SSH Private Key': 'critical',
        'Generic Private Key': 'critical',
        'Azure Client Secret': 'critical',
        
        // High - Service tokens and API keys
        'GitHub Personal Access Token': 'high',
        'GitHub Fine-grained Token': 'high',
        'GitHub OAuth Token': 'high',
        'GitHub App Token': 'high',
        'GitHub Refresh Token': 'high',
        'GitHub Generic Token': 'medium',
        'GitLab Personal Access Token': 'high',
        'Slack Bot Token': 'high',
        'Slack User Token': 'high',
        'Slack Generic Token': 'high',
        'Discord Bot Token': 'high',
        'Discord Client Secret': 'high',
        'Google API Key': 'high',
        'Firebase API Key': 'high',
        'Stripe API Key': 'high',
        'Stripe Test Key': 'high',
        'SendGrid API Key': 'high',
        'Mailgun API Key': 'high',
        'Twilio Account SID': 'high',
        'Facebook Access Token': 'high',
        'Twitter Bearer Token': 'high',
        'Shopify Access Token': 'high',
        'Square Access Token': 'high',
        'Square Application Secret': 'high',
        'JWT Bearer Token': 'high',
        'Bearer Token': 'high',
        'OAuth Token': 'high',
        
        // Medium - Database connections and webhooks
        'MongoDB Connection String': 'medium',
        'PostgreSQL Connection String': 'medium',
        'MySQL Connection String': 'medium',
        'Redis Connection String': 'medium',
        'Slack Webhook URL': 'medium',
        'Discord Webhook': 'medium',
        'URL with Credentials': 'medium',
        'Google OAuth Client ID': 'medium',
        'Google OAuth Client Secret': 'medium',
        'PayPal Client ID': 'medium',
        'Twilio Auth Token': 'medium',
        'Twitter API Key': 'medium',
        'Twitter API Secret': 'medium',
        'Docker Registry Token': 'medium',
        'Kubernetes Service Token': 'medium',
        'Heroku API Key': 'high',
        'Telegram Bot Token': 'high',
        'DigitalOcean Token': 'high',
        'DigitalOcean Spaces Key': 'high',
        'API Key (Generic)': 'medium',
        'Generic API Key (High Entropy)': 'medium',
        
        // Medium - Authentication and client credentials
        'Auth0 Client ID': 'medium',
        'Auth0 Client Secret': 'high',
        'Auth0 Domain': 'low',
        'JWT Secret Key (Contextual)': 'critical',
        'JWT Secret Key (SHA256 Hash)': 'high',
        'JWT Secret Key (Long Hex)': 'high',
        'UUID/GUID': 'low',
        'Generic Client ID (32 chars)': 'low',
        'Base64 Encoded Token': 'low',
        
        // Low - Less sensitive information
        'Email Address': 'low',
        'IP Address (Private)': 'low',
        'Password (Suspicious)': 'medium' // Passwords can be medium risk depending on context
    };
    
    return severityMap[type] || 'medium';
}

async function crawlWebsite(targetUrl, options = {}) {
    try {
        console.log(`🕷️ Starting crawl of: ${targetUrl}`);
        
        const results = {
            url: targetUrl,
            timestamp: new Date().toISOString(),
            scripts: [],
            secrets: [],
            status: 'success',
            stats: {
                totalScripts: 0,
                inlineScripts: 0,
                externalScripts: 0,
                secretsFound: 0,
                errors: 0
            }
        };

        // Check if URL is directly a JavaScript file
        if (targetUrl.match(/\.js(\?.*)?$/i)) {
            console.log(`📜 Direct JS file detected: ${targetUrl}`);
            return await crawlDirectJSFile(targetUrl, results);
        }

        // Fetch the main page
        const response = await axios.get(targetUrl, {
            timeout: 15000,
            maxRedirects: 5,
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate, br',
                'DNT': '1',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1'
            }
        });

        const $ = cheerio.load(response.data);
        
        // Extract inline scripts
        $('script').each((index, element) => {
            const $script = $(element);
            const src = $script.attr('src');
            const content = $script.html();

            if (src) {
                // External script
                let fullUrl = src;
                if (src.startsWith('//')) {
                    fullUrl = 'https:' + src;
                } else if (src.startsWith('/')) {
                    const baseUrl = new URL(targetUrl);
                    fullUrl = baseUrl.origin + src;
                } else if (!src.startsWith('http')) {
                    const baseUrl = new URL(targetUrl);
                    fullUrl = new URL(src, baseUrl).href;
                }

                results.scripts.push({
                    type: 'external',
                    url: fullUrl,
                    size: 0,
                    content: '',
                    secrets: { secrets: [], summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0 } },
                    riskLevel: 'unknown'
                });
                results.stats.externalScripts++;
            } else if (content && content.trim()) {
                // Inline script
                const scriptSecrets = detectSecrets(content.trim());
                const scriptData = {
                    type: 'inline',
                    url: targetUrl,
                    size: content.length,
                    content: content.trim(),
                    secrets: scriptSecrets,
                    riskLevel: 'low'
                };

                // Assess risk level
                if (scriptSecrets.secrets.length > 0) {
                    scriptData.riskLevel = 'high';
                } else if (content.includes('eval(') || content.includes('Function(')) {
                    scriptData.riskLevel = 'medium';
                }

                results.scripts.push(scriptData);
                results.stats.inlineScripts++;
                
                // Add secrets to main results
                if (scriptSecrets.secrets.length > 0) {
                    results.secrets.push(...scriptSecrets.secrets);
                    results.stats.secretsFound += scriptSecrets.secrets.length;
                }
            }
        });

        // Fetch external scripts (limited to prevent abuse)
        const maxExternalScripts = options.maxFiles || 20;
        let fetchedCount = 0;

        for (const script of results.scripts) {
            if (script.type === 'external' && fetchedCount < maxExternalScripts) {
                try {
                    console.log(`📜 Fetching: ${script.url}`);
                    const scriptResponse = await axios.get(script.url, {
                        timeout: 10000,
                        maxRedirects: 3,
                        headers: {
                            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                            'Accept': 'application/javascript, text/javascript, */*',
                            'Referer': targetUrl
                        }
                    });

                    script.content = scriptResponse.data;
                    script.size = scriptResponse.data.length;
                    script.secrets = detectSecrets(scriptResponse.data);
                    
                    // Assess risk level
                    if (script.secrets.secrets.length > 0) {
                        script.riskLevel = 'high';
                        results.secrets.push(...script.secrets.secrets);
                        results.stats.secretsFound += script.secrets.secrets.length;
                    } else if (scriptResponse.data.includes('eval(') || scriptResponse.data.includes('Function(')) {
                        script.riskLevel = 'medium';
                    } else {
                        script.riskLevel = 'low';
                    }

                    fetchedCount++;
                } catch (error) {
                    console.log(`❌ Failed to fetch ${script.url}: ${error.message}`);
                    script.content = `Error fetching script: ${error.message}`;
                    script.riskLevel = 'error';
                    script.secrets = { secrets: [], summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0 } };
                    results.stats.errors++;
                }
            }
        }

        results.stats.totalScripts = results.scripts.length;
        
        console.log(`✅ Crawl completed: ${results.stats.totalScripts} scripts, ${results.stats.secretsFound} secrets found`);
        
        return results;

    } catch (error) {
        console.log(`❌ Crawl failed: ${error.message}`);
        return {
            url: targetUrl,
            timestamp: new Date().toISOString(),
            status: 'error',
            error: error.message,
            scripts: [],
            secrets: [],
            stats: {
                totalScripts: 0,
                inlineScripts: 0,
                externalScripts: 0,
                secretsFound: 0,
                errors: 1
            }
        };
    }
}

async function crawlDirectJSFile(jsUrl, results) {
    try {
        console.log(`📜 Fetching direct JS file: ${jsUrl}`);
        
        const response = await axios.get(jsUrl, {
            timeout: 15000,
            maxRedirects: 5,
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'application/javascript, text/javascript, */*'
            }
        });

        const content = response.data;
        const secrets = detectSecrets(content);
        
        const scriptData = {
            type: 'direct',
            url: jsUrl,
            size: content.length,
            content: content,
            secrets: secrets,
            riskLevel: 'low'
        };

        // Assess risk level
        if (secrets.secrets.length > 0) {
            scriptData.riskLevel = 'high';
            results.secrets.push(...secrets.secrets);
            results.stats.secretsFound += secrets.secrets.length;
        } else if (content.includes('eval(') || content.includes('Function(')) {
            scriptData.riskLevel = 'medium';
        }

        results.scripts.push(scriptData);
        results.stats.totalScripts = 1;
        results.stats.externalScripts = 1;

        console.log(`✅ Direct JS scan completed: ${content.length} chars, ${secrets.secrets.length} secrets found`);
        
        return results;

    } catch (error) {
        console.log(`❌ Direct JS fetch failed: ${error.message}`);
        results.status = 'error';
        results.error = error.message;
        results.stats.errors = 1;
        return results;
    }
}

function analyzeCode(input) {
    const analysis = {
        riskLevel: 'low',
        threats: [],
        patterns: [],
        statistics: {
            lines: input.split('\n').length,
            characters: input.length,
            functions: (input.match(/function\s+\w+/g) || []).length,
            variables: (input.match(/var\s+\w+|let\s+\w+|const\s+\w+/g) || []).length
        }
    };

    // Threat patterns
    const threatPatterns = {
        'Code Injection': /eval\s*\(|Function\s*\(|setTimeout\s*\(/g,
        'DOM Manipulation': /document\.write|innerHTML|outerHTML/g,
        'Network Requests': /XMLHttpRequest|fetch\s*\(|axios\.|ajax/g,
        'Crypto Operations': /crypto\.|CryptoJS|forge\.|atob|btoa/g,
        'File Operations': /readFile|writeFile|fs\./g,
        'System Commands': /exec\s*\(|spawn\s*\(|child_process/g
    };

    let riskScore = 0;

    for (const [threat, pattern] of Object.entries(threatPatterns)) {
        const matches = input.match(pattern);
        if (matches) {
            analysis.threats.push({
                type: threat,
                count: matches.length,
                severity: getThreatSeverity(threat)
            });
            riskScore += matches.length * getThreatScore(threat);
        }
    }

    // Determine overall risk level
    if (riskScore >= 20) analysis.riskLevel = 'high';
    else if (riskScore >= 10) analysis.riskLevel = 'medium';

    return analysis;
}

function getThreatSeverity(threat) {
    const severityMap = {
        'Code Injection': 'critical',
        'System Commands': 'critical',
        'File Operations': 'high',
        'DOM Manipulation': 'medium',
        'Network Requests': 'medium',
        'Crypto Operations': 'low'
    };
    return severityMap[threat] || 'low';
}

function getThreatScore(threat) {
    const scoreMap = {
        'Code Injection': 8,
        'System Commands': 8,
        'File Operations': 5,
        'DOM Manipulation': 3,
        'Network Requests': 2,
        'Crypto Operations': 1
    };
    return scoreMap[threat] || 1;
}

server.listen(PORT, () => {
    console.log(`
🛡️  0xDe-Obfuscator Server Started
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📍 Server running at: http://localhost:${PORT}
🚀 Techniques available: ${encoder.getTechniqueCount()}
🔧 Environment: ${process.env.NODE_ENV || 'development'}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
`);
});

process.on('SIGINT', () => {
    console.log('\n🛑 Server shutting down gracefully...');
    server.close(() => {
        console.log('✅ Server closed');
        process.exit(0);
    });
});

module.exports = server;