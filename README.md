#  Espcap

__Espcap__ is a program that uses __tshark__ to capture packets from a pcap file or live from a network interface and index them with Elasticsearch.  __Espcap__ runs only on Python 3.x.  For those of you who used my previous version of this application, I completed deleted the previous version since I moved awy from using Pyshark and did not want to support that version. This version of **Espcap** is lighter weight since is has far fewer module dependencies. 

## Requirements

1. Python 3.x (Python 2.7.x not supported)
2. tshark (included in Wireshark)
3. Elasticsearch client for Python
4. Elasticsearch 6.x or greater

## Installation

1. Install Wireshark for your OS.
2. Clone the __Espcap__ repo then cd into the `espcap` directory. 
3. Install the required Python modules:
   ```
   pip install -r requirements.txt
   ```

4. Create the packet index template by running `scripts|templates.sh` as follows specifying the node IP address and TCP port of your Elasticsearch instance (localhost:9200 in this example):
   ```
   scripts|template.sh localhost:9200
   ```
   If you are using Elasticsearch 6.x, run `template-6.x.sh` instead.

5. Set the `tshark_path` variable in the `config|espcap.yml` file.  You can locate `espcap.yml` in one of 3 places:
   - Use the file directly from `config|`
   - Copy it to the same directory as `espcap.py` and its related files
   - Create the `|etc|espcap` directory and copy it there
   
6. cd into the `src` directory.
7. Run `espcap.py` to index some packet data in Elasticsearch:
    ```
    espcap.py --file=test_pcaps|test_http.pcap --node=localhost:9200
    ```
    
8. Run `packet_query.sh` as follows to check that the packet data resides in your Elasticsearch instance:
    ```
    scripts|packet_query.sh localhost:9200
    ```

## Running Examples

+ Display the following help message:
  ```
  espcap.py --help
  Usage: espcap.py [OPTIONS]

  Options:
    --node TEXT      Elasticsearch IP and port (default=None, dump packets to
                     stdout)
    --nic TEXT       Network interface for live capture (default=None, if file
                     or dir specified)
    --file TEXT      PCAP file for file capture (default=None, if nic specified)
    --dir TEXT       PCAP directory for multiple file capture (default=None, if
                     nic specified)
    --bpf TEXT       Packet filter for live capture (default=all packets)
    --chunk INTEGER  Number of packets to bulk index (default=1000)
    --count INTEGER  Number of packets to capture during live capture
                     (default=0, capture indefinitely)
    --list           List the network interfaces
    --help           Show this message and exit.
  ```

+ Load the test packet capture files and index the packets in the Elasticsearch cluster running at 10.0.0.1:9200, assuming your present working directory is `espcap|src`:
  ```
  espcap.py --dir=..|test_pcaps --node=10.0.0.1:9200
  ```

+ Same as the previous except load the `test_pcaps|test_http.pcap` file:
  ```
  espcap.py --file=..|test_pcaps|test_http.pcap --node=10.0.0.1:9200
  ```

+ Do a live capture from the network interface `eth0`, get all packets and index them in the Elasticsearch cluster running at 10.0.0.1:9200:
  ```
  espcap.py --nic=eth0 --node=10.0.0.1:9200
  ```

+ Same as the previous except dump the packets to `stdout`:
  ```
  espcap.py --nic=eth0
  ```

+ Do a live capture of TCP packets with source port or destination port == 80 and index in Elasticsearch running at 10.0.0.1:9200:
  ```
  espcap.py --nic=eth0 --bpf="tcp port 443" --node=10.0.0.1:9200
  ```

+ List the network interfaces
  ```
  espcap.py --list
  ```

## Packet Indexing

### Time Series Indexing

When indexing packets in Elasticsearch, a new index is created for each day. The index naming format is _packets-yyyy-mm-dd_. The index type is `_doc` for both live and file capture. Index `_id` is automatically assigned by Elasticsearch.

### Packet Index Structure

Packets from *tshark* are indexed just as they are received.  Packet payloads are contained in `layers` objects with each protocol, `frame`, `eth`, `ip`, `tcp`, etc., contained in a sub-object with the corresponding protocol fields.   Here is an example of a DNS packet:


```
      {
        "_index" : "packets-2015-08-14",
        "_type" : "_doc",
        "_id" : "yjgVamoBqD8GDhvGePoE",
        "_score" : 0.004597709,
        "_source" : {
          "timestamp" : "1439587239879",
          "layers" : {
            "frame" : {
              "frame_frame_interface_id" : "0",
              "frame_interface_id_frame_interface_name" : "en0",
              "frame_frame_encap_type" : "1",
              "frame_frame_time" : "Aug 14, 2015 14:20:39.879373000 PDT",
              "frame_frame_offset_shift" : "0.000000000",
              "frame_frame_time_epoch" : "1439587239.879373000",
              "frame_frame_time_delta" : "0.000217000",
              "frame_frame_time_delta_displayed" : "0.000217000",
              "frame_frame_time_relative" : "0.963427000",
              "frame_frame_number" : "9",
              "frame_frame_len" : "71",
              "frame_frame_cap_len" : "71",
              "frame_frame_marked" : "0",
              "frame_frame_ignored" : "0",
              "frame_frame_protocols" : "eth:ethertype:ip:udp:dns"
            },
            "eth" : {
              "eth_eth_dst" : "58:23:8c:b4:42:56",
              "eth_dst_eth_dst_resolved" : "Technico_b4:42:56",
              "eth_dst_eth_addr" : "58:23:8c:b4:42:56",
              "eth_dst_eth_addr_resolved" : "Technico_b4:42:56",
              "eth_dst_eth_lg" : "0",
              "eth_dst_eth_ig" : "0",
              "eth_eth_src" : "60:f8:1d:cb:43:84",
              "eth_src_eth_src_resolved" : "Apple_cb:43:84",
              "eth_src_eth_addr" : "60:f8:1d:cb:43:84",
              "eth_src_eth_addr_resolved" : "Apple_cb:43:84",
              "eth_src_eth_lg" : "0",
              "eth_src_eth_ig" : "0",
              "eth_eth_type" : "0x00000800"
            },
            "ip" : {
              "ip_ip_version" : "4",
              "ip_ip_hdr_len" : "20",
              "ip_ip_dsfield" : "0x00000000",
              "ip_dsfield_ip_dsfield_dscp" : "0",
              "ip_dsfield_ip_dsfield_ecn" : "0",
              "ip_ip_len" : "57",
              "ip_ip_id" : "0x0000a7f9",
              "ip_ip_flags" : "0x00000000",
              "ip_flags_ip_flags_rb" : "0",
              "ip_flags_ip_flags_df" : "0",
              "ip_flags_ip_flags_mf" : "0",
              "ip_flags_ip_frag_offset" : "0",
              "ip_ip_ttl" : "64",
              "ip_ip_proto" : "17",
              "ip_ip_checksum" : "0x00003122",
              "ip_ip_checksum_status" : "2",
              "ip_ip_src" : "10.0.0.2",
              "ip_ip_addr" : [
                "10.0.0.2",
                "75.75.76.76"
              ],
              "ip_ip_src_host" : "10.0.0.2",
              "ip_ip_host" : [
                "10.0.0.2",
                "75.75.76.76"
              ],
              "ip_ip_dst" : "75.75.76.76",
              "ip_ip_dst_host" : "75.75.76.76"
            },
            "udp" : {
              "udp_udp_srcport" : "33967",
              "udp_udp_dstport" : "53",
              "udp_udp_port" : [
                "33967",
                "53"
              ],
              "udp_udp_length" : "37",
              "udp_udp_checksum" : "0x0000aab3",
              "udp_udp_checksum_status" : "2",
              "udp_udp_stream" : "6",
              "udp_text" : "Timestamps",
              "text_udp_time_relative" : "0.000000000",
              "text_udp_time_delta" : "0.000000000"
            },
            "dns" : {
              "dns_dns_id" : "0x0000cfe4",
              "dns_dns_flags" : "0x00000100",
              "dns_flags_dns_flags_response" : "0",
              "dns_flags_dns_flags_opcode" : "0",
              "dns_flags_dns_flags_truncated" : "0",
              "dns_flags_dns_flags_recdesired" : "1",
              "dns_flags_dns_flags_z" : "0",
              "dns_flags_dns_flags_checkdisable" : "0",
              "dns_dns_count_queries" : "1",
              "dns_dns_count_answers" : "0",
              "dns_dns_count_auth_rr" : "0",
              "dns_dns_count_add_rr" : "0",
              "dns_text" : "Queries",
              "text_text" : "s.ytimg.com: type A, class IN",
              "text_dns_qry_name" : "s.ytimg.com",
              "text_dns_qry_name_len" : "11",
              "text_dns_count_labels" : "3",
              "text_dns_qry_type" : "1",
              "text_dns_qry_class" : "0x00000001"
            }
          }
        }
      }
```

There are a considerable number of fields in each, mnpot all of which can be indexed efficiently in Elasticsearch.  The fields that are indexed are given in the *template.sh* and *template-6.x.sh* scripts discussed in the next section. To get UDP packets for a given index from most recent to least recently captured, you could use a query like this:

```
GET packets-2019-04-01|_search
{
    "query": {
        "match": {
            "layers.udp.udp_udp_dstport": 53
        }
    },
    "sort": [
    {
        "timestamp": {
            "order": "desc"
        }
    }
  ]
}
```

### Packet Index Mapping

Trying to index all the possible packet fields can slow Elasticsearch down, so a limited number of core fields are mapped. Index mapping is set by two scripts, *packet_template.sh* and *packet_template-6.x.xh*. Use the latter script for versions of Elasticsearch prior to 7.x. These scripts set the mappings for the fields shown in the table below. Dynamic mapping is disabled so only these fields will be mapped.

| Protocol | Field                                   | Mapping                
|----------|-----------------------------------------|------------------------
| frame    | frame_interface_id_frame_interface_name | keyword
| frame    | frame_frame_protocols                   | simple
| ip       | ip_ip_src                               | ip
| ip       | ip_ip_dst                               | ip
| ip       | ip_ip_version                           | integer
| udp      | udp_udp_srcport                         | integer
| udp      | udp_udp_dstport                         | integer
| tcp      | tcp_tcp_srcport                         | integer
| tcp      | tcp_tcp_dstport                         | integer
| tcp      | tcp_flags_tcp_flags_str                 | keyword
| tcp      | tcp_flags_tcp_flags_urg                 | integer
| tcp      | tcp_flags_tcp_flags_ack                 | integer
| tcp      | tcp_flags_tcp_flags_push                | integer
| tcp      | tcp_flags_tcp_flags_syn                 | integer
| tcp      | tcp_flags_tcp_flags_fin                 | integer
| tcp      | tcp_tcp_seq                             | integer
| tcp      | tcp_tcp_ack                             | integer
| tcp      | tcp_tcp_window_size                     | integer

The mapping for `frame_frame_protocols` enables you to search for a given top level protocol. For example if you want to revise the query used before to find DNS, you could query with the `dns` string like this:

```
GET packets-2019-04-01|_search
{
    "query": {
        "match": {
            "layers.frame.frame_frame_protocols": "dns"
        }
    },
    "sort": [
    {
        "timestamp": {
            "order": "desc"
        }
    }
  ]
}
```

If you want to change the mappings for your packets, just revise the packet template scripts to your liking. You will have to delete your existing packet indexing template, if any, before creating a new one. You should keep dynamic indexing turned off so Elasticsearch does not create new mappings as new packet protocols and fields are encountered.