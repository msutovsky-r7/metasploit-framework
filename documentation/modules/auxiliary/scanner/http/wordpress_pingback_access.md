# WordPress Pingback Access Scanner

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

---

## Verification Steps

1. Start Metasploit:
`msfconsole`
2. Load the module:
`use auxiliary/scanner/http/wordpress_pingback_access`
3. Set the target:
`set RHOSTS <target_ip_or_domain>`
4. Run the module:
`run`

5. If vulnerable, the module will indicate that pingback access is enabled.

---

## Options

### RHOSTS
Target address or range of addresses.

### RPORT
Target port (default: 80 or 443 depending on SSL).

### THREADS
Number of concurrent threads.

---

## Scenarios

This module can be used in:

- Security assessments to identify exposed XML-RPC endpoints
- Detecting potential DDoS amplification vectors
- Enumerating WordPress misconfigurations

---

## Version and OS

Tested on:
- WordPress 5.x / 6.x
- Kali Linux
