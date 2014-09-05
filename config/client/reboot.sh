#!/usr/bin/expect -f

set timeout 30
spawn ssh root@10.1.242.1
expect "password:"
send "reboot\r"
interact