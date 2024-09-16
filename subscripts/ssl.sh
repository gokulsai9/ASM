#!/bin/bash

filepath="/workspaces/ASM/subscripts/"

function RunHTTP() {
    # Remove the existing ssl.json file if it exists to avoid conflicts
    if [ -f "${filepath}files/ssl.json" ]; then
        rm "${filepath}files/ssl.json"
        echo "Existing ssl.json file removed."
    fi

    # Run the testssl.sh command with the desired options
    ${filepath}/testssl.sh/testssl.sh --connect-timeout 1 --openssl-timeout 1 --file=${filepath}files/final.txt -U --jsonfile=${filepath}files/ssl.json

    if [ $? -eq 0 ]; then
        echo "SSL scan completed successfully."
    else
        echo "SSL scan failed."
        exit 1
    fi
}

function main() {
    RunHTTP  # Call the RunHTTP function correctly
}

main
