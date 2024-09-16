#!/bin/bash

install_dependencies() {
    # Function to check if a command is installed
    check_command() {
        command -v "$1" >/dev/null 2>&1
    }

    # List of commands to check and install
    commands=("python3" "node" "npm")

    # Loop through the commands and install if not present
    for cmd in "${commands[@]}"; do
        if ! check_command "$cmd"; then
            echo "Installing $cmd..."
            sudo apt-get update
            sudo apt-get install -y "$cmd"
        else
            echo "$cmd is already installed."
        fi
    done
}
install_dependencies

export_gopath() {
    sudo snap install go --classic
    echo "exporting GOPATH"
    echo 'export GOPATH=$HOME/go' >> ~/.bashrc
    export PATH=$PATH:$HOME/go/bin >> ~/.bashrc
    source ~/.bashrc
    echo "DONE exporting"
    echo $GOPATH
}

export_gopath

installpkg() {
    echo "Installing massdns..."
    git clone https://github.com/blechschmidt/massdns.git
    cd massdns || exit
    make
    sudo cp bin/massdns /usr/bin/
    cd ..

    # Install DNS-related tools
    echo "Installing DNS-related tools..."
    go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
    go install github.com/hakluke/hakoriginfinder@latest
    go install github.com/hakluke/hakrevdns@latest
    go install github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest
    go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest

    # Install HTTP-related tools
    echo "Installing HTTP-related tools..."
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest
    go install github.com/ffuf/ffuf/v2@latest
    go install github.com/tomnomnom/waybackurls@latest
    go install github.com/tomnomnom/assetfinder@latest

    # Install subdomain discovery tools
    echo "Installing subdomain discovery tools..."
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

    # Install other tools
    echo "Installing other tools..."
    go install github.com/tomnomnom/gf@latest
    go install github.com/d3mondev/puredns/v2@latest
    go install github.com/projectdiscovery/katana/cmd/katana@latest

    # Install Python tools
    echo "Installing Python tools..."
    sudo apt-get install -y python3-pip
   sudo pip3 install py-altdns==1.0.2
   sudo pip3 install dirsearch
   sudo pip3 install shodan
   sudo pip3 install mmh3
   sudo pip3 install dnspython==1.16.0

    echo "Installation complete."
}

# Call the function
installpkg