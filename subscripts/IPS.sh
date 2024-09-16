#!/bin/bash

function DigCommand() {
    local filename="$1"
    local subdomains="$2"
    
    # Create a temporary file for the output
    local temp_file="${filename}.tmp"
    
    # Process each line in the subdomains file
    while read -r line; do
        dig +short "$line" | grep '^[.0-9]*$' >> "$temp_file"
    done < "$subdomains"
    
    # Sort and deduplicate the results
    sort -u "$temp_file" > "$filename"
    
    # Remove the temporary file
    rm "$temp_file"
}

function RunShodan() {
    local domain="$1"
    shodan domain "$domain" > "${filename}.shodan"
}

function Main() {
    local filename="$1"
    local subdomains="$2"
    local domain="$3"
    
    # Ensure the subdomains file exists
    if [ ! -f "$subdomains" ]; then
        echo "Subdomains file not found: $subdomains"
        exit 1
    fi
    
    DigCommand "$filename" "$subdomains"
    RunShodan "$domain"
}

# Run the Main function with the provided arguments
Main "$1" "$2" "$3"
