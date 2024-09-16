import * as fs from 'fs';
class Firewall {
    constructor() {
        this.allowlist = ['192.168.1.1'];
        this.blocklist = [];
        this.blocklistTimestamps = {};
        this.actionsLog = [];
        this.allowedMethods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS  '];
        this.blockedPorts = [22, 23, 3389];
        this.allowedRoutes = ['/home', '/about', '/contact'];
        this.lastRequestTimes = {};
    }
    isAllowed(request) {
        if (this.isInAllowlist(request) || this.isFromBrazil(request)) {
            return true;
        }
        if (this.isPortBlocked(request) || this.isMethodNotAllowed(request) || this.isRouteNotAllowed(request) || this.isGetRequest(request) || this.isTooFast(request)) {
            this.blockAndLogRequest(request);
            return false;
        }
        if (this.isIpBlocked(request)) {
            return false;
        }
        this.logAllowedRequest(request);
        this.lastRequestTimes[request.clientIP] = request.edgeStartTimestamp;
        return true;
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
    isFromBrazil(request) {
        const allowed = request.clientCountry === 'br';
        if (allowed) {
            this.logAllowedRequest(request);
        }
        return allowed;
    }
    isPortBlocked(request) {
        return this.blockedPorts.includes(request.clientSrcPort);
    }
    isMethodNotAllowed(request) {
        return !this.allowedMethods.includes(request.clientRequestMethod);
    }
    isRouteNotAllowed(request) {
        return !this.allowedRoutes.includes(request.clientRequestPath);
    }
    isGetRequest(request) {
        return request.clientRequestMethod === 'GET';
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
    blockAndLogRequest(request) {
        this.addToBlocklist(request.clientIP, request.edgeStartTimestamp);
        this.logBlockedRequest(request);
    }
    logAllowedRequest(request) {
        this.actionsLog.push(`Request allowed: ${JSON.stringify(request)}`);
    }
    logBlockedRequest(request) {
        this.actionsLog.push(`Request blocked: ${JSON.stringify(request)}`);
    }
    addToBlocklist(ip, timestamp) {
        this.blocklist.push(ip);
        this.blocklistTimestamps[ip] = timestamp;
        this.actionsLog.push(`IP added to blocklist: ${ip}`);
    }
    removeFromBlocklist(ip) {
        const index = this.blocklist.indexOf(ip);
        if (index > -1) {
            this.blocklist.splice(index, 1);
            delete this.blocklistTimestamps[ip];
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
fs.readFile('./datasets/sampleDataset1.csv', 'utf8', (err, data) => {
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