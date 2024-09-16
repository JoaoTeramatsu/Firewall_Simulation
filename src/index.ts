   import * as fs from 'fs';
   import * as readline from 'readline';

   /*Creating a Request interface for extract data from each line of csv*/
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
      // private allowlist: string[] = ['192.168.1.1'];
      private allowlist: Set<string> = new Set(['192.168.1.1']);
      private flaggedIps: Set<string> = new Set();
      private blocklist: Set<string> = new Set();
      private blocklistTimestamps: Map<string, Date> = new Map(); // Timestamps to check when to allow ips after 12 hours
      private actionsLog: string[] = [];
      private allowedMethods: Set<string> = new Set(['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']);
      private blockedRoutes: Set<string> = new Set(['/etc/passwd', '/console', '/aux', '/storage']);
      private lastRequestTimes: Map<string, Date> = new Map();
      private requestCounters: Map<string, number> = new Map();

      public blockedReqCount = 0;
      public allowedReqCount = 0;
      private requestCount = 0;
      

      public isAllowed(request: Request): boolean {
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
                  this.flaggedIps.add(request.clientIP);
                  if(this.checkFlaggedIP(request, reason)){return true}
               }
               return false;
            }
         }
      
         if (this.isInAllowlist(request)) {
            return true;
         }
      
         this.addToAllowlist(request.clientIP);
         this.logAllowedRequest(request); // Only handle the allowed count here
         this.lastRequestTimes.set(request.clientIP, request.edgeStartTimestamp);
         return true;
      }

      private checkFlaggedIP(request: Request, reason: string): boolean {
         if (this.allowlist.has(request.clientIP)) {
            this.flaggedIps.add(request.clientIP);
            this.allowlist.delete(request.clientIP);
            this.actionsLog.push(`IP flagged: ${request.clientIP}`);
            this.actionsLog.push(`Request allowed: ${JSON.stringify(request, null, 2)}\n But the IP ${request.clientIP} has been removed from the allowlist.`);
            return true;
         } else {
            this.addToBlocklist(request.clientIP, request.edgeStartTimestamp);
            this.actionsLog.push(`Request blocked due to ${reason}: ${JSON.stringify(request, null, 2)}`);
            return false;
         }
      }

      private logAllowedRequest(request: Request): void {
         this.actionsLog.push(`Request allowed: ${JSON.stringify(request, null, 2)}`);
      }
   

      private isInjectionAttack(request: Request): boolean {
         const sqlInjectionPattern = /(\bSELECT\b|\bDELETE\b|\bUPDATE\b|\bINSERT\b|\bWHERE\b|=|--|\bOR\b)/i;
         const xssInjectionPattern = /(<\s*script\b|\balert\s*\(|<\s*img\b|<\s*a\b|<\s*body\b|<\s*iframe\b|<\s*input\b|<\s*form\b|<\s*div\b|\bonerror\b)/i;
         return sqlInjectionPattern.test(request.clientRequestPath) || xssInjectionPattern.test(request.clientRequestPath);
      }

      private removeOldBlockedIps(currentTime: Date): void {
         for (const [ip, blockedSince] of this.blocklistTimestamps.entries()) {
            const twelveHoursLater = new Date(blockedSince.getTime() + 12 * 60 * 60 * 1000);
            if (currentTime >= twelveHoursLater) {
               this.removeFromBlocklist(ip);
               this.flaggedIps.delete(ip);
               this.actionsLog.push(`IP unblocked and unflagged after 12 hours: ${ip} || Time it was blocked: ${blockedSince} - Current Time: ${currentTime} `);
            }
         }
      }

      private isPathDiscrepancy(request: Request): boolean {
         const uriPath = request.clientRequestURI.split('?')[0];
         return uriPath !== request.clientRequestPath;
      }

      private isNonStandardPort(request: Request): boolean {
         return request.clientSrcPort < 49152 || request.clientSrcPort > 65535;
      }

      private isDotSlashAttack(request: Request): boolean {
         return request.clientRequestPath.includes('/../');
      }

      private isRouteNotAllowed(request: Request): boolean {
         return this.blockedRoutes.has(request.clientRequestPath);
      }

      private isDDoSAttack(request: Request): boolean {
         const count = this.requestCounters.get(request.clientIP) || 0;
         this.requestCounters.set(request.clientIP, count + 1);

         if (count > 1000) {
            // Reset the counter
            this.requestCounters.set(request.clientIP, 0);
            return true;
         }

         return false;
      }

      private isMethodNotAllowed(request: Request): boolean {
         return !this.allowedMethods.has(request.clientRequestMethod);
      }

      private isInAllowlist(request: Request): boolean {
         const allowed = this.allowlist.has(request.clientIP);
         if (allowed) {
            this.logAllowedRequest(request);
         }
         return allowed;
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

      private logBlockedRequest(request: Request): void {
         this.actionsLog.push(`Request blocked: ${JSON.stringify(request, null, 2)} due to IP is still being in blocklist.`);
      }

      public addToBlocklist(ip: string, timestamp: Date): void {
         this.blocklist.add(ip);
         this.blocklistTimestamps.set(ip, timestamp);
         this.actionsLog.push(`IP added to blocklist: ${ip}`);
         this.allowlist.delete(ip)
      }

      public addToAllowlist(ip: string): void {
         this.allowlist.add(ip);
         this.actionsLog.push(`IP added to Allow List: ${ip}`);
      }

      public removeFromBlocklist(ip: string): void {
         if (this.blocklist.has(ip)) {
            this.blocklist.delete(ip);
            this.blocklistTimestamps.delete(ip);
            this.actionsLog.push(`IP removed from blocklist: ${ip}`);
         }
      }

      public printActionsLog(): void {
         const summary = `Total requests: ${this.requestCount}\n` +
            `Requests Blocked: ${this.blockedReqCount}\n` +
            `Requests Allowed: ${this.allowedReqCount}\n - - - - - - - - - - - - - - - - - - - - - - - - - -\n`;
         const logData = summary + this.actionsLog.join('\n');
         console.log(logData);

         fs.writeFile('firewall.log', logData + '\n', err => {
            if (err) {
               console.error(err);
            } else {
               console.log('Logs written to firewall.log');
            }
         });
      }

      public printBlocklist(): void {
         console.log('Blocklist:', Array.from(this.blocklist));
      }

      public printAllowlist(): void {
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
         let isAllowed = firewall.isAllowed(request);
         if(isAllowed){
            firewall.allowedReqCount++;
         }else{firewall.blockedReqCount++;}
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