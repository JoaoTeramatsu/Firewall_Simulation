# Firewall Simulation

This project simulates the functions of a firewall, assessing and filtering network traffic based on a set of rules.

## Implementation Details

   The firewall works by checking network traffic from an input file. It looks at each IP address and uses a set of rules to decide if it's safe or not. This includes looking for signs of threats like DDoS attacks or SQL/XSS injections.
   
   It keeps two lists: one for safe IP addresses (allowlist) and one for unsafe ones (blocklist). If an IP makes a good request, it goes on the allowlist. But if it makes a malicious request, it goes on the blocklist and we stop its requests. If an IP that is in the allowlist starts making bad requests, we flag it, take it off the allowlist, and deal with its request.
   
   Everything is logged so we can track what's happening, such as allowed requests, blocked requests, unblocked ips after 12 hours etc. Also, we automatically unblock IPs and remove their flags after 12 hours.
   
   After analyzing the data, I realized we needed to stop attack attempts like SQL injection, XSS attacks, dot-slash attacks, verb tampering, DDoS, non-standard source ports, and possible malicious requests when looking at the ClientRequestURI and the ClientRequestPath. So, I made sure our firewall could handle these threats. This thought process was crucial in shaping our security policy and ensuring robust protection against various types of cyber threats.

## Prerequisites

- Node.js
- TypeScript

## Installation

1. Clone this repository to your local machine using `git clone`.
2. Navigate into the project folder using `cd /src`.
3. Install the necessary dependencies using `npm install`.

## Execution

1. Transpile the TypeScript code to JavaScript using `npx tsc`.
2. Run the generated JavaScript script using `node ./dist/index.js` in your terminal.

## Features

- Management of an allowlist and blocklist.
- Logging of all actions for traceability.
- Processing of a stream of "network traffic" from an input file.
- Identification of patterns and implementation of a comprehensive security policy.
- Additional features like DDoS attack prevention and SQL/XSS injection detection.
- Automatic unblocking of IP addresses and removal of flags after 12 hours.

## Command Line Interface

After processing the CSV file, you can interact with the firewall through a command line interface. The following commands are available:

- `blocklist`: Displays the current blocklist.
- `allowlist`: Displays the current allowlist.
- `block`: Adds a new IP address to the blocklist. The current date and time are logged along with the IP address.
- `unblock`: Removes an IP address from the blocklist.
- `allow`: Adds a new IP address to the allowlist.

If an unknown command is entered, the program will display an error message: 'Unknown command:' followed by the unknown command.

Example of use:

```bash
> block 192.168.0.1
> allow 192.168.0.2
> blocklist
> allowlist