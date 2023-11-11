import re
import urllib3
import argparse
import requests
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style, init

banner = r"""
            WebStrings - Sensitive String Enumeration | By Derezzed
                     https://github.com/wxor/webstrings
"""

def search_webpage(url, regex_list):
    try:
        response = requests.get(url, verify=False)
        response.raise_for_status()

        content = response.text
        matches_found = False
        for regex, comment in regex_list:
            matches = re.findall(regex, content, flags=re.IGNORECASE)
            if matches:
                matches_found = True
                for match in matches:
                    print(f"{Fore.GREEN}{comment} found on {url}: {match}{Style.RESET_ALL}")

        if not matches_found:
            print(f"No matches on {url}")

    except requests.RequestException as e:
        print(f"Error accessing {url}: {e}")

def should_ignore_url(url, ignore_keywords):
    for keyword in ignore_keywords:
        if keyword.lower() in url.lower():
            return True
    return False

def process_line(line, status_codes, regex_list, ignore_keywords):
    parts = line.split()
    
    if len(parts) == 6 and int(parts[0]) in status_codes:
        try:
            url = parts[-1]
            if not should_ignore_url(url, ignore_keywords):
                print(f"Searching {url}")
                search_webpage(url, regex_list)
            else:
                print(f"{Fore.RED}Ignoring {url}{Style.RESET_ALL}")
        except Exception as e:
            print(e, " Invalid file format")

def main():
    parser = argparse.ArgumentParser(description="Takes an output file from feroxbuster and searches for potentially sensitive strings in found files")
    parser.add_argument("-f", "--file", help="Specify the file to read from.")
    parser.add_argument("-c", "--status-codes", nargs="+", type=int, help="Specify status codes to search for.", default=[200])
    parser.add_argument("-i", "--ignore-keywords", nargs="+", help="Specify keywords to ignore in URLs.", default=[""])
    parser.add_argument("-t", "--threads", type=int, help="Specify the number of threads.", default=2)

    args = parser.parse_args()

    status_codes = set(args.status_codes)
    regex_list = [
        # Sensitive strings
        (r"(passw.*[=,:].+)", "Sensitive string"),
        (r"(cred.*[=,:].+)", "Sensitive string"),
        (r"(datab.*[=,:].+)", "Sensitive string"),
        (r"(server.*[=,:].+)", "Sensitive string"),
        (r"(DB_.*)", "Sensitive string"),
        (r"(PRIVATE.*[ ].+)", "Sensitive string"),

        #bcrypt
        (r"(\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}([./A-Za-z0-9]{31})?\b)", "bcrypt"),

        # MD5
        (r"(\b[a-fA-F0-9]{32}\b)", "MD5"),

        # SHA-1
        (r"(\b[a-fA-F0-9]{40}\b)", "SHA-1"),

        #scrypt
        (r"\$scrypt\$\b.+", "scrypt"),

        # Email Addresses
        (r"(\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b)", "Email")    
    ]
    try:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        with open(args.file, "r") as file:
            with ThreadPoolExecutor(max_workers=args.threads) as executor:
                futures = [executor.submit(process_line, line, status_codes, regex_list, args.ignore_keywords) for line in file]

                for future in futures:
                    future.result()
    except Exception as e:
        print(f"Cannot find {args.file}")
if __name__ == "__main__":
    print(banner)
    main()
