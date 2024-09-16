import * as fs from 'fs';
import * as readline from 'readline';
class Firewall {
    constructor() {
        // private allowlist: string[] = ['192.168.1.1'];
        this.allowlist = new Set(['192.168.1.1']);
        this.flaggedIps = new Set();
        this.blocklist = new Set();
        this.blocklistTimestamps = new Map(); // Timestamps to check when to allow ips after 12 hours
        this.actionsLog = [];
        this.allowedMethods = new Set(['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']);
        this.blockedRoutes = new Set(['/etc/passwd', '/console', '/aux', '/storage']);
        this.lastRequestTimes = new Map();
        this.requestCounters = new Map();
        this.blockedReqCount = 0;
        this.allowedReqCount = 0;
        this.requestCount = 0;
    }
    isAllowed(request) {
        this.requestCount++;
        this.removeOldBlockedIps(request.edgeStartTimestamp);
        if (this.isIpBlocked(request)) {
            return false;
        }
        const reasons = [
            { check: () => this.isInjectionAttack(request), reason: 'Injection attack detected' },
            { check: () => this.isMethodNotAllowed(request), reason: 'method not allowed' },
            { check: () => this.isRouteNotAllowed(request), reason: 'route not allowed' },
            { check: () => this.isDDoSAttack(request), reason: 'too many requests' },
            { check: () => this.isDotSlashAttack(request), reason: 'dot-slash attack detected' },
            { check: () => this.isPathDiscrepancy(request), reason: 'path discrepancy detected' },
            { check: () => this.isNonStandardPort(request), reason: 'non-standard source port' }
        ];
        for (const { check, reason } of reasons) {
            if (check()) {
                if (!this.flaggedIps.has(request.clientIP)) {
                    this.blockAndLogRequest(request, reason);
                    this.flaggedIps.add(request.clientIP);
                }
                return false;
            }
        }
        if (this.isInAllowlist(request)) {
            return true;
        }
        this.addToAllowlist(request.clientIP);
        this.logAllowedRequest(request);
        this.lastRequestTimes.set(request.clientIP, request.edgeStartTimestamp);
        return true;
    }
    blockAndLogRequest(request, reason) {
        this.blockedReqCount++;
        if (this.allowlist.has(request.clientIP)) {
            // If the IP is in the allowlist, just flag it and remove it from the allowlist
            this.flaggedIps.add(request.clientIP);
            this.allowlist.delete(request.clientIP);
            this.actionsLog.push(`IP flagged: ${request.clientIP}`);
        }
        else {
            // If the IP is not in the allowlist, block it
            this.addToBlocklist(request.clientIP, request.edgeStartTimestamp);
        }
        this.actionsLog.push(`Request blocked due to ${reason}: ${JSON.stringify(request, null, 2)}`);
    }
    isInjectionAttack(request) {
        const sqlInjectionPattern = /(\bSELECT\b|\bDELETE\b|\bUPDATE\b|\bINSERT\b|\bWHERE\b|=|--|\bOR\b)/i;
        const xssInjectionPattern = /(<\s*script\b|\balert\s*\(|<\s*img\b|<\s*a\b|<\s*body\b|<\s*iframe\b|<\s*input\b|<\s*form\b|<\s*div\b|\bonerror\b)/i;
        return sqlInjectionPattern.test(request.clientRequestPath) || xssInjectionPattern.test(request.clientRequestPath);
    }
    removeOldBlockedIps(currentTime) {
        for (const [ip, blockedSince] of this.blocklistTimestamps.entries()) {
            const twelveHoursLater = new Date(blockedSince.getTime() + 12 * 60 * 60 * 1000);
            if (currentTime >= twelveHoursLater) {
                this.removeFromBlocklist(ip);
                this.flaggedIps.delete(ip);
                this.actionsLog.push(`IP unblocked and unflagged after 12 hours: ${ip} || Time it was blocked: ${blockedSince} - Current Time: ${currentTime} `);
            }
        }
    }
    isPathDiscrepancy(request) {
        const uriPath = request.clientRequestURI.split('?')[0];
        return uriPath !== request.clientRequestPath;
    }
    isNonStandardPort(request) {
        return request.clientSrcPort < 49152 || request.clientSrcPort > 65535;
    }
    isDotSlashAttack(request) {
        return request.clientRequestPath.includes('/../');
    }
    isRouteNotAllowed(request) {
        return this.blockedRoutes.has(request.clientRequestPath);
    }
    isDDoSAttack(request) {
        const count = this.requestCounters.get(request.clientIP) || 0;
        this.requestCounters.set(request.clientIP, count + 1);
        if (count > 1000) {
            // Reset the counter
            this.requestCounters.set(request.clientIP, 0);
            return true;
        }
        return false;
    }
    isMethodNotAllowed(request) {
        return !this.allowedMethods.has(request.clientRequestMethod);
    }
    isInAllowlist(request) {
        const allowed = this.allowlist.has(request.clientIP);
        if (allowed) {
            this.logAllowedRequest(request);
        }
        return allowed;
    }
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
        this.allowedReqCount++;
        this.actionsLog.push(`Request allowed: ${JSON.stringify(request, null, 2)}`);
    }
    logBlockedRequest(request) {
        this.blockedReqCount++;
        this.actionsLog.push(`Request blocked: ${JSON.stringify(request, null, 2)} due to IP is still being in blocklist.`);
    }
    addToBlocklist(ip, timestamp) {
        this.blocklist.add(ip);
        this.blocklistTimestamps.set(ip, timestamp);
        this.actionsLog.push(`IP added to blocklist: ${ip}`);
        this.allowlist.delete(ip);
    }
    addToAllowlist(ip) {
        this.allowlist.add(ip);
        this.actionsLog.push(`IP added to Allow List: ${ip}`);
    }
    removeFromBlocklist(ip) {
        if (this.blocklist.has(ip)) {
            this.blocklist.delete(ip);
            this.blocklistTimestamps.delete(ip);
            this.actionsLog.push(`IP removed from blocklist: ${ip}`);
        }
    }
    printActionsLog() {
        const summary = `Total requests: ${this.requestCount}\n` +
            `Requests Blocked: ${this.blockedReqCount}\n` +
            `Requests Allowed: ${this.allowedReqCount}\n - - - - - - - - - - - - - - - - - - - - - - - - - -\n`;
        const logData = summary + this.actionsLog.join('\n');
        console.log(logData);
        fs.writeFile('firewall.log', logData + '\n', err => {
            if (err) {
                console.error(err);
            }
            else {
                console.log('Logs written to firewall.log');
            }
        });
    }
    printBlocklist() {
        console.log('Blocklist:', Array.from(this.blocklist));
    }
    printAllowlist() {
        console.log('Allowlist:', this.allowlist);
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
    // Start listening for user commands
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout
    });
    rl.on('line', (input) => {
        const [command, arg] = input.split(' ');
        switch (command) {
            case 'blocklist':
                firewall.printBlocklist();
                break;
            case 'allowlist':
                firewall.printAllowlist();
                break;
            case 'block':
                firewall.addToBlocklist(arg, new Date());
                break;
            case 'unblock':
                firewall.removeFromBlocklist(arg);
                break;
            case 'allow':
                firewall.addToAllowlist(arg);
                break;
            default:
                console.log('Unknown command:', command);
        }
    });
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