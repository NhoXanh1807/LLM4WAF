import argparse
from pathlib import Path
import sys

# Allow import from gui/backend
sys.path.append(str(Path(__file__).resolve().parents[1] / "gui" / "backend"))
from src.cli.waf_detector import detect_waf

def main():

    parser = argparse.ArgumentParser(description="WAF Detector using wafw00f")
    parser.add_argument("-d", "--domain", required=True, help="Domain to detect")
    args = parser.parse_args()

    result = detect_waf(args.domain)

    if result["status"] == "success":
        print(f"\n[+] Detection successful for {result['domain']}\n")
        print(result["output"])
    else:
        print(f"\n[!] Error: {result.get('message', 'Unknown error')}")
        if "stderr" in result:
            print(result["stderr"])

if __name__ == "__main__":
    main()