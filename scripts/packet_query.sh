#!/usr/bin/env bash

# Run this script to verify packets were indexed into Elasticsearch

if [[ $# -ne 1 ]] ; then
    echo "usage: packet_query.sh node"
    exit
fi

curl -XGET 'http://'$1'/packets-*/_search?pretty' -d '
{
    "size": 200,
    "sort": [
       {
          "timestamp": {
             "order": "asc"
          }
       }
    ]
}'  | less
