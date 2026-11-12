"""Command-line interface for PhishRadar."""
import argparse
import json
from scanner import scan_url

def main() -> None:
    parser = argparse.ArgumentParser(description="PhishRadar — offline URL phishing risk checker")
    parser.add_argument("url", help="HTTP(S) URL to check")
    args = parser.parse_args()
    try:
        print(json.dumps(scan_url(args.url), indent=2, ensure_ascii=False))
    except ValueError as exc:
        parser.error(str(exc))

if __name__ == "__main__":
    main()
