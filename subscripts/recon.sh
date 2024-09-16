#!/bin/bash

subsfile=$1

outputfile="/workspaces/ASM/subscripts/files/recon.json"

httpxrunner(){
    while IFS= read -r subdomain; do
        httpx -asn -td -json "$subdomain" | jq -c '{ "status_code": ."status_code", "cnames": .cname, "a": .a, "port": .port, "url": .url, "title": .title,"cdn": .cdn_name, "host": .host, "csp": .csp, "asn": .asn, "technologies": .tech, "input": .input, "Server": .webserver}' >> "$outputfile"
    done < "$subsfile"
}

httpxrunner