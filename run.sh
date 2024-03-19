#!/usr/bin/bash

date_changed() {
    new_date=$(date +"%Y-%m-%d")
    [[ "$current_date" != "$new_date" ]]
}

restart_program() {
    kill -SIGTERM $program_pid
    wait $program_pid
    program_pid=$(nohup ./website > "$log_file" 2>&1 & echo $!)
}

current_date=$(date +"%Y-%m-%d")
log_file="$current_date.log"

nohup ./website > "$log_file" 2>&1 &
program_pid=$!

while true; do
    if date_changed; then
        restart_program
    fi
    sleep 10
done

