#!/usr/bin/expect -f

set timeout 30
spawn screen
send "\r"
send "ssh -CfNg -L 3389:172.16.136.136:3389 root@10.1.242.2\r"
expect "password:"
send "6351806\r"
send "ssh -CfNg -L 80:127.0.0.1:80 root@10.1.242.2\r"
expect "password:"
send "6351806\r"
expect "windpro:~#"
send "exit\r"
interact