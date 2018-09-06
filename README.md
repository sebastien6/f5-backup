# f5-backup

The python script is using the F5 iControlRest API to authenticate with remote authentication (Active directory, RADIUS,...) to obtain a token, create a timestamp UCS backup file, download the file locally and delete it from the F5 appliance.

Provide a way to backup F5 bigIP configuration and arhive the backup files on a remote location.

Usage:

python3 f5-backup.py --hostname <fqdn_f5_appliance>
