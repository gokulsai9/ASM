import json
import concurrent.futures
import time
import os
import sys
import requests
import re

EXCLUDE_HEADERS = [
    "Cache-Control",
    "Content-Length",
    "Content-Type",
    "Expires",
    "Last-Modified",
    "ETag",
    "Connection",
    "Content-Language",
    "Vary",
    "Accept-Ranges",
    "Pragma",
    "etag",
    "accept-ranges",
    "Content-Script-Type",
    "Content-Style-Type",
    "Content-Encoding",
    "Date",
    "X-Amz-Cf-*",
    "Via"
]

# Convert EXCLUDE_HEADERS to regex patterns
##done
EXCLUDE_HEADERS_REGEX = [re.compile(header.replace('*', '.*'), re.IGNORECASE) for header in EXCLUDE_HEADERS]
EXCLUDE_HEADERS_REGEX += [re.compile(header, re.IGNORECASE) for header in EXCLUDE_HEADERS]  # Added exact match patterns

# Function to check if a header should be excluded
def should_exclude_header(header):
    return any(header_pattern.fullmatch(header) for header_pattern in EXCLUDE_HEADERS_REGEX)

# Function to get domain fingerprint
def get_domain_fingerprint(url):
    fingerprint = {"url": url}

    try:
        with requests.head(url, timeout=5, allow_redirects=True) as response:
            fingerprint["headers"] = {
                key: value
                for key, value in response.headers.items()
                if not should_exclude_header(key)
            }
            fingerprint["status_code"] = response.status_code
            fingerprint["server"] = response.headers.get("Server", "")
    except requests.RequestException as e:
        fingerprint["error"] = str(e)

    return fingerprint if "headers" in fingerprint else None

# Function to get fingerprints for all subdomains
def get_fingerprint(subdomains):
    fingerprint_data = {}
    num_cpus = os.cpu_count()
    num_threads = num_cpus * 16

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = {executor.submit(get_domain_fingerprint, url): url for url in subdomains}
        for future in concurrent.futures.as_completed(futures):
            url = futures[future]
            result = future.result()
            if result is not None:
                fingerprint_data[url] = result

    return fingerprint_data

def save_to_json(fingerprint_data, output_file):
    filtered_data = [
        {
            "url": data["url"],
            "headers": data.get("headers", {}),
            "status_code": data.get("status_code", None),
            "server": data.get("server", ""),
            "new_headers": {}
        }
        for url, data in fingerprint_data.items()
        if "error" not in data
    ]

    with open(output_file, 'w') as json_file:
        json.dump(filtered_data, json_file, indent=2)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python app.py subdomains_file.txt")
        sys.exit(1)

    output_file = "fingerprint_output.json"  # Replace with your desired output file

    with open(sys.argv[1], 'r') as file:
        subdomains = [line.strip() for line in file.readlines()]

    start_time = time.time()
    fingerprint_data = get_fingerprint(subdomains)
    end_time = time.time()
    elapsed_time = end_time - start_time

    print(f"Process completed in {elapsed_time:.2f} seconds.")
    save_to_json(fingerprint_data, output_file)