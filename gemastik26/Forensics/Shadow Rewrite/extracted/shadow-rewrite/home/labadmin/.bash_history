ls
pwd
journalctl -n 25
sudo grep -E '^(labadmin|operator|forest|maint):' /etc/shadow
sudo tail -n 20 /var/log/auth.log
sudo tail -n 20 /var/log/auth.log.1
exit
