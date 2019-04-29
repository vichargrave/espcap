#!/usr/bin/env bash

# Run this script before you do anything else with espcap
# to make sure all dates are properly mapped to date types
# in Elasticsearch.

if [[ $# -ne 1 ]] ; then
    echo "usage: template.sh node"
    exit
fi

curl -H 'Content-Type: application/json' -XPUT 'http://'$1'/_template/packets' -d '
{
  "template": "packets-*",
  "mappings": {
    "_doc": {
      "dynamic": "false",
      "properties": {
        "timestamp": {
          "type": "date"
        },
        "layers": {
          "properties": {
            "frame": {
              "properties": {
                "frame_interface_id_frame_interface_name": {
                  "type": "keyword"
                },
                "frame_frame_protocols": {
                  "type": "text",
                  "analyzer": "simple"
                }
              }
            },
            "ip": {
              "properties": {
                "ip_ip_src": {
                  "type": "ip"
                },
                "ip_ip_dst": {
                  "type": "ip"
                },
                "ip_ip_version": {
                  "type": "integer"
                }
              }
            },
            "udp": {
              "properties": {
                "udp_udp_srcport": {
                  "type": "integer"
                },
                "udp_udp_dstport": {
                  "type": "integer"
                }
              }
            },
            "tcp": {
              "properties": {
                "tcp_tcp_srcport": {
                  "type": "integer"
                },
                "tcp_tcp_dstport": {
                  "type": "integer"
                },
                "tcp_flags_tcp_flags_str": {
                  "type": "keyword"
                },
                "tcp_flags_tcp_flags_urg": {
                  "type": "integer"
                },
                "tcp_flags_tcp_flags_ack": {
                  "type": "integer"
                },
                "tcp_flags_tcp_flags_push": {
                  "type": "integer"
                },
                "tcp_flags_tcp_flags_reset": {
                  "type": "integer"
                },
                "tcp_flags_tcp_flags_syn": {
                  "type": "integer"
                },
                "tcp_flags_tcp_flags_fin": {
                  "type": "integer"
                },
                "tcp_tcp_seq": {
                  "type": "integer"
                },
                "tcp_tcp_ack": {
                  "type": "integer"
                },
                "tcp_tcp_window_size": {
                  "type": "integer"
                }
              }
            }
          }
        }
      }
    }
  }
}'

echo

