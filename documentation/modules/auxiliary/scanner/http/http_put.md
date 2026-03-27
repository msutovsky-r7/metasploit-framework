# HTTP PUT File Upload Scanner

## Vulnerable Application

This module targets web servers that allow HTTP PUT and DELETE methods without proper restrictions.

Improper configuration of HTTP PUT can allow attackers to upload arbitrary files to the server. If executable files are uploaded, this may lead to:

- Arbitrary file upload
- Remote code execution
- Website defacement
- Unauthorized content modification

DELETE method misuse can allow attackers to remove existing files from the server.

To test this module:

1. Set up a web server (Apache, Nginx, IIS, etc.)
2. Ensure HTTP PUT/DELETE methods are enabled
3. Confirm lack of authentication or access control

---

## Description

This module abuses misconfigured web servers to upload and delete web content via HTTP PUT and DELETE requests.

---

## Verification Steps

1. Start Metasploit:
   ```bash
   msfconsole
   ```

2. Load the module:
   ```bash
   use auxiliary/scanner/http/http_put
   ```

3. Set required options:
   ```bash
   set RHOSTS [IP]
   set RPORT [PORT]
   set PATH [PATH]
   set FILENAME [FILENAME]
   set FILEDATA [PATH]
   ```

4. Run the module:
   ```bash
   run
   ```

5. If vulnerable, the module will confirm successful upload or deletion.
