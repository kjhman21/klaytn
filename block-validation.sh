#!/bin/bash
NODE_URL=${NODE_URL:="http://cypress_archive:8551"}
echo "connecting to $NODE_URL"
BLOCK_NUMBER_IN_HEX=$(curl -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"klay_blockNumber","params":[],"id":1}' $NODE_URL | jq -r .result)
BLOCK_NUMBER_IN_DEC=$(printf "%d" $BLOCK_NUMBER_IN_HEX)

echo "block number $BLOCK_NUMBER_IN_DEC"

COUNCIL=$(curl -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"klay_getCouncil","params":[],"id":1}' $NODE_URL | jq .result)
RESULT=$(curl -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"klay_getBlockWithConsensusInfoByNumber","params":["'$BLOCK_NUMBER_IN_HEX'"],"id":1}' $NODE_URL | jq .result | jq ". +{council:$COUNCIL}" )
echo $RESULT | ./build/bin/block-validation
