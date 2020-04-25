#!/bin/bash
# Default-Start:  2 3 4 5
# Default-Stop: 0 1 6

cd /opt/observer

python3 manage.py runscript start_service  --script-args core >> /opt/observer/logs/core.log 2>&1 &
PIDS[0]=$!
python3 manage.py runscript start_service --script-args helper >> /opt/observer/logs/helper.log 2>&1 &
PIDS[1]=$!
python3 manage.py runscript start_service --script-args pastebin >> /opt/observer/logs/batch.log 2>&1 &
PIDS[2]=$!

trap "kill ${PIDS[*]}" SIGINT

wait
