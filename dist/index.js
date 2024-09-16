import * as fs from 'fs';
class Firewall {
    constructor() {
        this.allowlist = ['192.168.1.1'];
        this.blocklist = new Set();
        this.blocklistTimestamps = new Map();
        this.actionsLog = [];
        this.allowedMethods = new Set(['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']);
        // private blockedRoutes: Set<string> = new Set(['/home']);
        this.lastRequestTimes = new Map();
        this.flaggedIps = new Set();
    }
    blockAndLogRequest(request, reason) {
        this.addToBlocklist(request.clientIP, request.edgeStartTimestamp);
        this.actionsLog.push(`Request blocked due to ${reason}: ${JSON.stringify(request)}`);
    }
    isAllowed(request) {
        this.removeOldBlockedIps();
        if (this.isInAllowlist(request)) {
            return true;
        }
        const reasons = [
            { check: () => this.isMethodNotAllowed(request), reason: 'method not allowed' },
            // { check: () => this.isRouteNotAllowed(request), reason: 'route not allowed' },
            { check: () => this.isTooFast(request), reason: 'too many requests' },
            { check: () => this.isSqlInjection(request), reason: 'SQL injection detected' },
            { check: () => this.isXssAttack(request), reason: 'XSS attack detected' },
            { check: () => this.isDotSlashAttack(request), reason: 'dot-slash attack detected' },
            { check: () => this.isPathDiscrepancy(request), reason: 'path discrepancy detected' },
            { check: () => this.isNonStandardPort(request), reason: 'non-standard source port' }
        ];
        for (const { check, reason } of reasons) {
            if (check()) {
                if (!this.flaggedIps.has(request.clientIP)) {
                    this.blockAndLogRequest(request, reason);
                    this.flaggedIps.add(request.clientIP);
                    this.actionsLog.push(`IP flagged: ${request.clientIP}`);
                }
                return false;
            }
        }
        if (this.isIpBlocked(request)) {
            return false;
        }
        this.allowlist.push(request.clientIP);
        this.logAllowedRequest(request);
        this.lastRequestTimes.set(request.clientIP, request.edgeStartTimestamp);
        return true;
    }
    removeOldBlockedIps() {
        const now = new Date();
        for (const [ip, blockedSince] of this.blocklistTimestamps.entries()) {
            const twelveHoursLater = new Date(blockedSince.getTime() + 12 * 60 * 60 * 1000);
            if (now >= twelveHoursLater) {
                this.removeFromBlocklist(ip);
            }
        }
    }
    isPathDiscrepancy(request) {
        return request.clientRequestURI !== request.clientRequestPath;
    }
    isNonStandardPort(request) {
        return request.clientSrcPort < 49152 || request.clientSrcPort > 65535;
    }
    isSqlInjection(request) {
        const sqlInjectionPattern = /(\b(SELECT|DELETE|UPDATE|INSERT)\b|\bWHERE\b|=|--|\bOR\b)/i;
        return sqlInjectionPattern.test(request.clientRequestPath);
    }
    isXssAttack(request) {
        const xssPattern = /(<\s*script\b)|(\balert\s*\()|(<\s*img\b)|(<\s*a\b)|(<\s*body\b)|(<\s*iframe\b)|(<\s*input\b)|(<\s*form\b)|(<\s*div\b)/i;
        return xssPattern.test(request.clientRequestPath);
    }
    isDotSlashAttack(request) {
        return request.clientRequestPath.includes('/../');
    }
    isTooFast(request) {
        const lastRequestTime = this.lastRequestTimes[request.clientIP];
        if (lastRequestTime) {
            const timeDifference = request.edgeStartTimestamp.getTime() - lastRequestTime.getTime();
            return timeDifference < 1000; // 1 second, adjust as needed
        }
        return false;
    }
    isInAllowlist(request) {
        const allowed = this.allowlist.includes(request.clientIP);
        if (allowed) {
            this.logAllowedRequest(request);
        }
        return allowed;
    }
    isMethodNotAllowed(request) {
        return !this.allowedMethods.has(request.clientRequestMethod);
    }
    // private isRouteNotAllowed(request: Request): boolean {
    //    return !this.blockedRoutes.has(request.clientRequestPath);
    // }
    isIpBlocked(request) {
        const blockedSince = this.blocklistTimestamps[request.clientIP];
        if (blockedSince) {
            const twelveHoursLater = new Date(blockedSince.getTime() + 12 * 60 * 60 * 1000);
            if (request.edgeStartTimestamp < twelveHoursLater) {
                this.logBlockedRequest(request);
                return true;
            }
            else {
                this.removeFromBlocklist(request.clientIP);
            }
        }
        return false;
    }
    logAllowedRequest(request) {
        this.actionsLog.push(`Request allowed: ${JSON.stringify(request)}`);
    }
    logBlockedRequest(request) {
        this.actionsLog.push(`Request blocked: ${JSON.stringify(request)}`);
    }
    addToBlocklist(ip, timestamp) {
        this.blocklist.add(ip);
        this.blocklistTimestamps.set(ip, timestamp);
        this.actionsLog.push(`IP added to blocklist: ${ip}`);
    }
    removeFromBlocklist(ip) {
        if (this.blocklist.has(ip)) {
            this.blocklist.delete(ip);
            this.blocklistTimestamps.delete(ip);
            this.actionsLog.push(`IP removed from blocklist: ${ip}`);
        }
    }
    printActionsLog() {
        const logData = this.actionsLog.join('\n');
        console.log(logData);
        fs.appendFile('firewall.log', logData + '\n', err => {
            if (err) {
                console.error(err);
            }
            else {
                console.log('Logs written to firewall.log');
            }
        });
    }
}
const firewall = new Firewall();
fs.readFile('./datasets/dataset.csv', 'utf8', (err, data) => {
    if (err) {
        console.error(err);
        return;
    }
    const lines = data.split('\n');
    for (let i = 1; i < lines.length; i++) {
        const request = createRequestFromLine(lines[i]);
        firewall.isAllowed(request);
    }
    firewall.printActionsLog();
});
function createRequestFromLine(line) {
    const parts = line.split(',');
    return {
        clientIP: parts[0],
        clientRequestHost: parts[1],
        clientRequestMethod: parts[2],
        clientRequestURI: parts[3],
        edgeStartTimestamp: new Date(parts[4]),
        zoneName: parts[5],
        clientASN: parseInt(parts[6]),
        clientCountry: parts[7],
        clientDeviceType: parts[8],
        clientSrcPort: parseInt(parts[9]),
        clientRequestBytes: parseInt(parts[10]),
        clientRequestPath: parts[11],
        clientRequestReferer: parts[12],
        clientRequestScheme: parts[13],
        clientRequestUserAgent: parts[14]
    };
}
//# sourceMappingURL=index.js.map