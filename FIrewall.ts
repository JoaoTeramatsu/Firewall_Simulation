import * as fs from 'fs';

interface Request {
   clientIP: string;
   clientRequestHost: string;
   clientRequestMethod: string;
   clientRequestURI: string;
   edgeStartTimestamp: Date;
   zoneName: string;
   clientASN: number;
   clientCountry: string;
   clientDeviceType: string;
   clientSrcPort: number;
   clientRequestBytes: number;
   clientRequestPath: string;
   clientRequestReferer: string;
   clientRequestScheme: string;
   clientRequestUserAgent: string;
}
class Firewall {
   private allowlist: string[] = ['192.168.1.1'];
   private blocklist: string[] = [];
   private blocklistTimestamps: { [ip: string]: Date } = {};
   private actionsLog: string[] = [];

   private allowedMethods: string[] = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS  '];
   private blockedPorts: number[] = [22, 23, 3389];
   private allowedRoutes: string[] = ['/home', '/about', '/contact'];

   private lastRequestTimes: { [ip: string]: Date } = {};

   public isAllowed(request: Request): boolean {
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

   private isTooFast(request: Request): boolean {
      const lastRequestTime = this.lastRequestTimes[request.clientIP];
      if (lastRequestTime) {
         const timeDifference = request.edgeStartTimestamp.getTime() - lastRequestTime.getTime();
         return timeDifference < 1000; // 1 second, adjust as needed
      }
      return false;
   }


   private isInAllowlist(request: Request): boolean {
      const allowed = this.allowlist.includes(request.clientIP);
      if (allowed) {
         this.logAllowedRequest(request);
      }
      return allowed;
   }

   private isFromBrazil(request: Request): boolean {
      const allowed = request.clientCountry === 'br';
      if (allowed) {
         this.logAllowedRequest(request);
      }
      return allowed;
   }

   private isPortBlocked(request: Request): boolean {
      return this.blockedPorts.includes(request.clientSrcPort);
   }

   private isMethodNotAllowed(request: Request): boolean {
      return !this.allowedMethods.includes(request.clientRequestMethod);
   }

   private isRouteNotAllowed(request: Request): boolean {
      return !this.allowedRoutes.includes(request.clientRequestPath);
   }

   private isGetRequest(request: Request): boolean {
      return request.clientRequestMethod === 'GET';
   }

   private isIpBlocked(request: Request): boolean {
      const blockedSince = this.blocklistTimestamps[request.clientIP];
      if (blockedSince) {
         const twelveHoursLater = new Date(blockedSince.getTime() + 12 * 60 * 60 * 1000);
         if (request.edgeStartTimestamp < twelveHoursLater) {
            this.logBlockedRequest(request);
            return true;
         } else {
            this.removeFromBlocklist(request.clientIP);
         }
      }
      return false;
   }

   private blockAndLogRequest(request: Request): void {
      this.addToBlocklist(request.clientIP, request.edgeStartTimestamp);
      this.logBlockedRequest(request);
   }

   private logAllowedRequest(request: Request): void {
      this.actionsLog.push(`Request allowed: ${JSON.stringify(request)}`);
   }

   private logBlockedRequest(request: Request): void {
      this.actionsLog.push(`Request blocked: ${JSON.stringify(request)}`);
   }

   public addToBlocklist(ip: string, timestamp: Date): void {
      this.blocklist.push(ip);
      this.blocklistTimestamps[ip] = timestamp;
      this.actionsLog.push(`IP added to blocklist: ${ip}`);
   }

   public removeFromBlocklist(ip: string): void {
      const index = this.blocklist.indexOf(ip);
      if (index > -1) {
         this.blocklist.splice(index, 1);
         delete this.blocklistTimestamps[ip];
         this.actionsLog.push(`IP removed from blocklist: ${ip}`);
      }
   }

   public printActionsLog(): void {
      const logData = this.actionsLog.join('\n');
      console.log(logData);

      fs.appendFile('firewall.log', logData + '\n', err => {
         if (err) {
            console.error(err);
         } else {
            console.log('Logs written to firewall.log');
         }
      });
   }
}

const firewall = new Firewall();

fs.readFile('networkTraffic.txt', 'utf8', (err, data) => {
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

function createRequestFromLine(line: string): Request {
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