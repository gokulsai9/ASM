#!/bin/bash

subsfile=$1

SCRIPT_DIR="/workspaces/ASM/subscripts"
pythonpath=$SCRIPT_DIR/app.py


httpxRun(){
    cat $subsfile | httpx -silent | tee $SCRIPT_DIR/files/urls
}

AppFunc(){
    python3 $pythonpath $SCRIPT_DIR/files/urls
}

RunMain(){
    httpxRun &
    wait $!
    AppFunc
}

RunMain