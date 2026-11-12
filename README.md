# PhishRadar 📡

A lightweight, dependency-free Python CLI for **heuristic phishing URL checks**.

> This tool flags suspicious URL patterns. It does not prove that a URL is safe, and it does not use a trained AI model.

## Features
- Detects suspicious URL patterns (IP-host URLs, HTTP, punycode, excessive subdomains, misleading @ signs, long URLs)
- Clear risk score and reasons
- No external requests: checks the URL text locally
- JSON output for automation
- Python standard library only

## Usage

```bash
python main.py "http://192.0.2.5/login@account.example"
python -m unittest discover -s tests -v
```

## Responsible use
Do not enter passwords or personal information into suspicious websites. This scanner is an educational aid, not a substitute for browser protections and threat-intelligence services.

## License
MIT
