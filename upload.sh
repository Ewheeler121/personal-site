#!/bin/bash

cargo build --release

rsync -avz --delete -e "ssh -i server_key.pem" target/release/website admin@unpaidrust.dev:~ 
rsync -avz --delete -e "ssh -i server_key.pem" run.sh admin@unpaidrust.dev:~ 
rsync -ravz --delete -e "ssh -i server_key.pem" static admin@unpaidrust.dev:~ 
rsync -ravz --delete -e "ssh -i server_key.pem" entries admin@unpaidrust.dev:~ 
