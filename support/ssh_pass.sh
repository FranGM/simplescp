#!/bin/sh

# Simple script to be used to send passwords to scp.
# It's used like this:
#   SIMPLESCP_TESTPASS="hunter2"  # Password to send to scp
#   SSH_ASKPASS="/path/to/ssh_pass.sh"
#   DISPLAY=dummystring
#   setsid -w scp ...

echo ${SIMPLESCP_TESTPASS} < /dev/null
