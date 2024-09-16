#!/usr/bin/env python3
from multiprocessing.pool import ThreadPool
from urllib.request import urlopen
import mmh3
import codecs
import sys
import ssl
import argparse
import json
import os
import errno
from os import path

# Function to create or update data.json with provided data
def update_data_json(data):
    try:
        with open("data.json", "w") as json_file:
            json.dump(data, json_file, indent=4)
    except Exception as e:
        pass  # Handle exceptions silently

def main():
    urls = []
    a = {}
    for line in sys.stdin:
        if line.strip()[-1] == "/":
            urls.append(line.strip() + "favicon.ico")
        else:
            urls.append(line.strip() + "/favicon.ico")

    def fetch_url(url):
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            response = urlopen(url, timeout=5, context=ctx)
            favicon = codecs.encode(response.read(), "base64")
            hash_val = mmh3.hash(favicon)
            a.setdefault(hash_val, [])
            a[hash_val].append(url)
            return url, hash_val, None
        except Exception as e:
            return url, None, e

    results = ThreadPool(20).imap_unordered(fetch_url, urls)
    for url, hash_val, error in results:
        pass  # Handle each result silently

    return a, urls

if __name__ == "__main__":
    try:
        parser = argparse.ArgumentParser(description='FavFreak - a Favicon Hash based asset mapper')
        parser.add_argument('-o', '--output', help='Output file name')
        parser.add_argument('--shodan', help='Prints Shodan Dorks', action='store_true')
        parser.add_argument('--fingerprint_file', '-fp', help='Path to the fingerprint JSON file', required=True)

        args = parser.parse_args()

        a, urls = main()

        # Check if data.json exists
        if not os.path.exists("data.json"):
            update_data_json([])  # Initialize with empty list if doesn't exist

        # Load the fingerprint file
        with open(args.fingerprint_file, "r") as json_data:
            fingerprint = json.load(json_data)

        json_data_list = []
        for i in a.keys():
            if str(i) in fingerprint.keys():
                for k in a[i]:
                    json_data_list.append({
                        "fingerprint": fingerprint[str(i)],
                        "hash": str(i),
                        "count": str(len(a[int(i)])),
                        "url": k[:-12]
                    })

        # Update data.json with the accumulated data
        update_data_json(json_data_list)

        if args.output:
            for i in a.keys():
                filename = args.output + "/" + str(i) + ".txt"
                if path.exists(filename):
                    os.remove(filename)
                if not os.path.exists(os.path.dirname(filename)):
                    try:
                        os.makedirs(os.path.dirname(filename))
                    except OSError as exc:
                        if exc.errno != errno.EEXIST:
                            raise

                with open(filename, "a") as f:
                    f.write('\n'.join(a[i]))
                    f.write("\n")
    except KeyboardInterrupt:
        pass  # Handle keyboard interrupt silently
    except Exception as ex:
        pass  # Handle all other exceptions silently
