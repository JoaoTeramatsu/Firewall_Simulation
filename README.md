# Firewall Simulation

This project simulates the functions of a firewall, assessing and filtering network traffic based on a set of rules.

## Prerequisites

- Node.js
- TypeScript

## Installation

1. Clone this repository to your local machine using `git clone`.
2. Navigate into the project folder using `cd /src`.
4. Install the necessary dependencies using `npm install`.

## Execution

1. Transpile the TypeScript code to JavaScript using `npx tsc`.
2. Run the generated JavaScript script using `node ./dist/index.js` in your terminal.

## Features

- The firewall is capable of managing an allowlist and blocklist.
- It logs all actions for traceability.
- It processes a stream of "network traffic" from an input file.
- It identifies patterns and implements a comprehensive security policy.
- It includes additional features like DDoS attack prevention and SQL/XSS injection detection.

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

Feel free to explore the code and contribute!
