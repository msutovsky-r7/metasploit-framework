## Vulnerable Application

This module checks for accessible WordPress pingback functionality.

Pingback is an XML-RPC feature in WordPress that allows blogs to notify each other of references. If enabled, it can be abused for:

- DDoS amplification attacks
- Internal network scanning
- Information disclosure

To test this module:

1. Set up a WordPress instance (any version with XML-RPC enabled)
2. Ensure `/xmlrpc.php` is accessible
3. Pingback functionality should not be disabled

## Verification Steps

1. Start Metasploit:
   `msfconsole`

2. Load the module:
   `use auxiliary/scanner/http/wordpress_pingback_access`

3. Set the target:
   `set RHOSTS example.com`

4. Run the module:
   `run`

If vulnerable, the module will indicate that pingback access is enabled.

## Options

### RHOSTS
Target address or range of addresses.

### RPORT
Target port (default: 80 or 443 depending on SSL).

### THREADS
Number of concurrent threads.

## Scenarios

Example run:

```bash
msfconsole
use auxiliary/scanner/http/wordpress_pingback_access
set RHOSTS example.com
run
```

```
[*] Checking pingback access on example.com
[+] Pingback is enabled and accessible at /xmlrpc.php
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
