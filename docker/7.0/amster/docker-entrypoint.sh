#!/usr/bin/env bash
#
# Copyright (c) 2016-2017 ForgeRock AS. All rights reserved.
#

set -x

echo $1

exit_script() {
    echo "Got signal. Killing child processes"
    trap - SIGINT SIGTERM # clear the trap
    kill -- -$$ # Sends SIGTERM to child/sub processes
    echo "Exiting"
    exit 0
}

trap exit_script SIGINT SIGTERM SIGUSR1 EXIT



pause() {
    echo "Args are $# "

    echo "Container will now pause. You can exec into the container using kubectl exec to run export.sh"
    # Sleep forever, waiting for someone to exec into the container.
    while true
    do
        sleep 1000000 & wait
    done
}

# Extract amster version for commons parameter to modify configs
echo "Extracting amster version"
VER=$(./amster --version)
[[ "$VER" =~ ([0-9].[0-9].[0-9](\.[0-9]*)?-([a-zA-Z][0-9]+|SNAPSHOT|RC[0-9]+)|[0-9].[0-9].[0-9](\.[0-9]*)?) ]]
VERSION=${BASH_REMATCH[1]}
echo "Amster version is: '${VERSION}'"
export VERSION

case $ACTION  in
pause)
    pause
    ;;
export)
    # TO DO - export dynamic config
    ./export.sh
    sleep infinity
    ;;
import)
    # Without this chmod, Docker does not know the file is executable on Windows
    chmod +x import.sh
    # invoke amster install.
    ./import.sh
    ;;
*)
   exec "$@"
esac