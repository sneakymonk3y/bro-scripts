# FOXHOUND-IDS 

RaspberryPi 3 IDS System based on [Bro](https://www.bro.org). Suitable for a home 'blackbox' deployment.

### Descriptions
* [dns-hunt] - Query velocity, length and counts of DNS queries.
* [exfil] - Data exfiltration ICMP/FTP/LargeTX/SSH.
* [file-extract] - Extract 'interesting' files.
* [geoip] - Geolocation added to the conn.log
* [human] - Makes bro data human readable.
* [notice-ext] - Adds more detail to the notice email alerts.
* [ssl-ext-san] - Adds x509 Subject Alternative Names attributes to SSL:Info.
* [useragent-hunt] - Creates a count of HTTP User-Agent length and vector of HTTP User-Agent variables.

### local.bro
```bro
# Evernote scripts
@load bro-scripts/human
@load bro-scripts/ssl-ext-san
@load bro-scripts/exfil
@load bro-scripts/notice-ext

# Exfiltration
redef Exfiltration::file_of_whitelisted_hostnames = "/opt/bro/share/bro/site/input/whitelists/hostnames.whitelist";
redef Exfiltration::file_of_whitelisted_subnets = "/opt/bro/share/bro/site/input/whitelists/subnets.whitelist";
# DNS zones to whitelist
# define here instead of using the input framework becuase we can't reliably load a table before bro_init completes
# and converting this to a regex requires bro_init.
redef Exfiltration::common_zones = {
    #".zombo.com", # Welcome to zombocom
}

# Flow
# single conn Tx bytes over which we want to alert on immediately
redef Exfiltration::flow_bytes_tx_to_notice= 20000000;
# destination hosts to record if over this many bytes
redef Exfiltration::flow_bytes_tx_to_log_and_track= 1000000;
# number of large uploads per IP before an email is generated for that IP
redef Exfiltration::count_of_tracked_flows_to_notice = 13;
# how long to suppress re-notices
redef Exfiltration::flow_suppression_interval = 480mins;
# flow producer consumer ratio floor
redef Exfiltration::min_flow_producer_consumer_ratio = 0.4;

# DNS
redef Exfiltration::query_interval = 1min;
redef Exfiltration::queries_per_query_interval = 800.0;
redef Exfiltration::query_length_sum_per_interval = 10000.0;
redef Exfiltration::txt_answer_types_per_interval = 5.0;
redef Exfiltration::null_answer_types_per_interval = 1.0;
redef Exfiltration::frequent_queriers = {
    # A cool host
    10.0.0.1/32,
    # A cool net
    192.168.1.0/24,
    };


# ICMP
redef Exfiltration::icmp_interval = 1min;
redef Exfiltration::icmp_per_query_interval = 60.0;
redef Exfiltration::frequent_icmp_senders = {
    # A cool host
    10.0.0.1/32,
    # A cool net
    192.168.1.0/24,
};

# Notices

# Use notice_ext for emailed alert types
redef Notice::ext_emailed_types = {
    Exfiltration::Large_Flow,
    Exfiltration::DNS_Excessive_Query_Velocity,
    Exfiltration::DNS_Excessive_Query_Length,
    Exfiltration::DNS_too_many_TXT_Answers,
    Exfiltration::DNS_too_many_NULL_Answers,
    Exfiltration::FTP_Upload,
    Exfiltration::ICMP_Velocity,
    Exfiltration::SSH,
};
```

# Deployment
```
broctl check
broctl deploy
```

## Script Authors
* [CrowdStrike](https://github.com/CrowdStrike/cs-bro)
* [EverNote](https://github.com/evernote/bro-scripts)
* [Security Onion](https://github.com/Security-Onion-Solutions/securityonion-bro-scripts)
