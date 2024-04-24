#!/bin/bash
cargo build --release
rsync -avz --delete -e "ssh -i server_key.pem" target/release/website admin@ec2-3-19-120-57.us-east-2.compute.amazonaws.com:~ 
rsync -avz --delete -e "ssh -i server_key.pem" run.sh admin@ec2-3-19-120-57.us-east-2.compute.amazonaws.com:~ 
rsync -avz --delete -e "ssh -i server_key.pem" static/* admin@ec2-3-19-120-57.us-east-2.compute.amazonaws.com:~ 
rsync -avz --delete -e "ssh -i server_key.pem" entries/* admin@ec2-3-19-120-57.us-east-2.compute.amazonaws.com:~ 
