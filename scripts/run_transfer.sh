#!/bin/bash
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 RECIPIENT_ADDRESS AMOUNT"
    exit 1
fi

RECIPIENT_ADDRESS=$1
AMOUNT=$2

aptos move run --function-id default::secure_transfer::secure_transfer --args address:$RECIPIENT_ADDRESS u64:$AMOUNT
