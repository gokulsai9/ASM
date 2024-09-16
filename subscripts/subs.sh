#!/bin/bash

domain=$1
scan_type=$2

path="/workspaces/ASM/subscripts"
bwordlist="$path/files/subs.txt"
public="$path/files/public.txt"
words="$path/files/words.txt"

output_path="$path/files"

check_and_create_dir() {
    [ ! -d "$output_path" ] && mkdir -p "$output_path"
}

filter_domains() {
    local input_file=$1
    local output_file=$2
    awk -v domain="$domain" '$0 ~ "\\."domain"$"' $input_file | sort -u > $output_file
    rm $input_file
}

assetfinderfun() {
    assetfinder $domain | sort -u | tee "$output_path/af.txt"
    filter_domains "$output_path/af.txt" "$output_path/af_filtered.txt"
}

subfinderfun() {
    subfinder -d $domain | sort -u | tee "$output_path/sf.txt"
    filter_domains "$output_path/sf.txt" "$output_path/sf_filtered.txt"
    echo "subfinder done"
}

bruteforce() {
    if [ ! -x "$(command -v massdns)" ]; then
        echo "massdns is not installed or not in PATH"
        exit 1
    fi
    puredns bruteforce $bwordlist $domain --resolvers $public -t 5000 --skip-wildcard-filter | tee "$output_path/bsub.txt"
    filter_domains "$output_path/bsub.txt" "$output_path/bsub_filtered.txt"
    echo "bruteforce done"
}

alt_dns() {
    if [ ! -f "$words" ]; then
        echo "Wordlist file not found: $words"
        exit 1
    fi
    altdns --input "$output_path/asb.txt" -o "$output_path/alt.txt" -w $words -t 500
    filter_domains "$output_path/alt.txt" "$output_path/alt_filtered.txt"
    echo "alt_dns done"
}

shufflednsfun() {
    shuffledns -l "$output_path/alt_filtered.txt" -r $public -o "$output_path/fin.txt" -sw -t 20000 -mode resolve
    filter_domains "$output_path/fin.txt" "$output_path/fin_filtered.txt"
}

deletefiles() {
    if [ -f "$output_path/af_filtered.txt" ] && [ -f "$output_path/sf_filtered.txt" ] && [ -f "$output_path/bsub_filtered.txt" ] && [ -f "$output_path/alt_filtered.txt" ]; then
        rm "$output_path/af_filtered.txt" "$output_path/sf_filtered.txt" "$output_path/bsub_filtered.txt" "$output_path/alt_filtered.txt"
        if [ -f "$output_path/asb.txt" ] && [ -f "$output_path/fin_filtered.txt" ]; then
            cat "$output_path/asb.txt" "$output_path/fin_filtered.txt" | sort -u | tee "$output_path/fin2.txt"
            filter_domains "$output_path/fin2.txt" "$output_path/final.txt"
            rm "$output_path/asb.txt" "$output_path/fin_filtered.txt" "$output_path/fin2.txt"
            echo "final.txt is written to: $output_path/final.txt"
        fi
    fi
}

activereadfiles() {
    if [ -f "$output_path/af_filtered.txt" ] && [ -f "$output_path/sf_filtered.txt" ] && [ -f "$output_path/bsub_filtered.txt" ]; then
        cat "$output_path/af_filtered.txt" "$output_path/sf_filtered.txt" "$output_path/bsub_filtered.txt" | sort -u | tee "$output_path/asb.txt"
        echo "active_file done"
    else
        echo "One or more required files for activereadfiles are missing"
    fi
}

passivereadfiles() {
    if [ -f "$output_path/af_filtered.txt" ] && [ -f "$output_path/sf_filtered.txt" ]; then
        cat "$output_path/af_filtered.txt" "$output_path/sf_filtered.txt" | sort -u | tee "$output_path/passive.txt"
        rm "$output_path/af_filtered.txt" "$output_path/sf_filtered.txt"
    else
        echo "One or more required files for passivereadfiles are missing"
    fi
}

main() {
    if [ -z "$domain" ]; then
        echo "No domain provided. Usage: suball domain.com [active/passive]"
        exit 1
    fi
    
    check_and_create_dir
    
    case "$scan_type" in
        active)
            assetfinderfun
            subfinderfun
            bruteforce
            activereadfiles
            alt_dns
            shufflednsfun
            deletefiles
        ;;
        passive)
            assetfinderfun
            subfinderfun
            passivereadfiles
        ;;
        *)
            echo "Invalid scan type. Usage: suball domain.com [active/passive]"
            exit 1
        ;;
    esac
}

main
