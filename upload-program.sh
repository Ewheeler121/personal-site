#!/bin/bash
cargo build --release
scp -i "server_key.pem" target/release/website admin@ec2-3-19-120-57.us-east-2.compute.amazonaws.com:~
