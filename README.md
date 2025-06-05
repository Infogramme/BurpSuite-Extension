# BurpSuite-Extension
**Burp Suite Extension for Security Headers**

### Description
This Burp Suite extension enhances your web security assessments by detecting missing or misconfigured security headers.

### Features
- Passive scan for security headers in HTTP responses
- Flags missing headers like:
  - `Content-Security-Policy`
  - `Strict-Transport-Security`
  - `X-Content-Type-Options`
  - `X-Frame-Options`
  - `Referrer-Policy`

### How to Use the Extension Correctly
Install Jython:

Download the standalone Jython JAR: http://www.jython.org

Configure Burp:

Go to Extender > Options > Python Environment

Add the path to your jython-standalone-x.x.x.jar

Load the Extension:

Go to Extender > Extensions > Add

Set Type to "Python"

Select the .py file containing your extension

Run Scans:

Browse or scan a site.

Look for results in the Scanner or Alerts tab.


### Usage
1. Open Burp Suite
2. Go to `Extender > Add`
3. Load `burp_security_headers.py`
4. View findings in the Scanner tab

---

## 🧰 Requirements
- Python 3
- No external dependencies


## 🤝 Contributing

Pull requests and suggestions are welcome!

---

## 🙏 Acknowledgements

Inspired by real-world cybersecurity needs and audit tasks.
