#!/usr/bin/bash

date_changed() {
    new_date=$(date +"%d-%m-%Y")
    [[ "$current_date" != "$new_date" ]]
}

restart_program() {
    kill -SIGTERM $program_pid
    wait $program_pid
    sleep 10

    current_date=$(date +"%d-%m-%Y")
    log_file="logs/$current_date.log"
    sudo nohup ./website >> "$log_file" 2>&1 &
    program_pid=$!
}

mkdir -p logs
current_date=$(date +"%d-%m-%Y")
log_file="logs/$current_date.log"

sudo nohup ./website >> "$log_file" 2>&1 &
program_pid=$!

while true; do
    if date_changed; then
        restart_program
    fi
    sleep 10
done

