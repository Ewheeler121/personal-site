#!/bin/bash
scp -r -i "server_key.pem" static/* admin@ec2-3-19-120-57.us-east-2.compute.amazonaws.com:~/static/
scp -r -i "server_key.pem" entries/* admin@ec2-3-19-120-57.us-east-2.compute.amazonaws.com:~/entries/
