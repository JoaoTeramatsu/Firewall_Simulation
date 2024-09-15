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

   public isAllowed(request: Request): boolean {
      if (this.allowlist.includes(request.clientIP)) {
         this.actionsLog.push(`Request allowed: ${JSON.stringify(request)}`);
         return true;
      }

      const blockedSince = this.blocklistTimestamps[request.clientIP];
      if (blockedSince) {
         const twelveHoursLater = new Date(blockedSince.getTime() + 12 * 60 * 60 * 1000);
         if (request.edgeStartTimestamp < twelveHoursLater) {
            this.actionsLog.push(`Request blocked: ${JSON.stringify(request)}`);
            return false;
         } else {
            // Remove IP from blocklist after 12 hours
            this.removeFromBlocklist(request.clientIP);
         }
      }

      // Exemplo de regra adicional: bloquear todas as solicitações GET
      if (request.clientRequestMethod === 'GET') {
         this.addToBlocklist(request.clientIP, request.edgeStartTimestamp);
         this.actionsLog.push(`Request blocked: ${JSON.stringify(request)}`);
         return false;
      }

      // Exemplo de regra adicional: permitir todas as solicitações do país 'br'
      if (request.clientCountry === 'br') {
         this.actionsLog.push(`Request allowed: ${JSON.stringify(request)}`);
         return true;
      }

      this.actionsLog.push(`Request allowed: ${JSON.stringify(request)}`);
      return true;
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

// Simulando a leitura do arquivo de log
fs.readFile('networkTraffic.txt', 'utf8', (err, data) => {
   if (err) {
      console.error(err);
      return;
   }

   const lines = data.split('\n');

   // Ignorar a primeira linha (cabeçalho)
   for (let i = 1; i < lines.length; i++) {
      const parts = lines[i].split(','); // Agora os dados são separados por vírgulas
      const request: Request = {
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

      firewall.isAllowed(request);
   }

   firewall.printActionsLog();
});
