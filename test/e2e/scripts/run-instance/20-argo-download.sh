#!/bin/bash

printf '=%.0s' {0..79} ; echo
set -x

cd "$(dirname $0)"

sha512sum -c argo.sha512sum && {
    chmod +x ./argo
    exit 0
}

set -e
curl -sLf https://github.com/argoproj/argo/releases/download/v2.11.1/argo-linux-amd64.gz -o argo.gz
gunzip argo.gz
sha512sum -c argo.sha512sum
chmod +x ./argo
./argo version
