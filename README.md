# Mobile Web Security Scanner

A small, mobile-friendly scanner for basic HTTP response security checks.

## Requirements
- Node.js 20 or newer
- A browser such as Safari

## Run locally
1. Unzip the project.
2. Run `npm start` in the project directory.
3. Open `http://localhost:3000`.

An iPad cannot normally run this Node.js server directly. Use a cloud host such as Railway and open its public URL. Before making this public for general use, add authentication and rate limiting.

## Checks included
- HTTPS usage and common security response headers
- Server / technology banners
- Cookie flags (Secure, HttpOnly, SameSite)
- Basic HTML checks for password fields on HTTP and forms posting to HTTP
- Redirect chain and HTTP status

## Limitations
This is a heuristic first-pass scanner, not a full penetration test. It only makes GET requests and does not submit forms, brute-force, exploit endpoints, or crawl an entire site. Results can be false positives or false negatives.

## Network protections
The server blocks localhost, private/reserved IP ranges, internal hostnames, and hostnames that resolve to private addresses. It rechecks redirect destinations and limits redirects, response size, and request duration. Scan only sites you own or have permission to test.
