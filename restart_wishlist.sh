#!/usr/bin/env bash

go build
sudo setcap 'cap_net_bind_service=+ep' wishlist

kill -9 $(cat save_pid.txt) 
rm save_pid.txt

nohup ./wishlist &
echo $! > save_pid.txt
