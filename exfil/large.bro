##! This script alerts on any large uploads to the Internet
##! and emails alerts on sufficiently large uploads if enabled.
##! 
##! Based on https://github.com/sooshie/bro-scripts/blob/master/2.4-scripts/largeUpload.bro
##! by Brian Kellogg
##!
##! And http://resources.sei.cmu.edu/asset_files/Presentation/2014_017_001_90063.pdf

@load base/frameworks/notice
@load bro-scripts/human

module Exfiltration;
export {
	# Notice large flows
	redef enum Notice::Type += {
		Flow,
		Large_Flow,
		Multiple_Flows,
	};

	# Redefine flow limits appropriate for your environment
	const flow_bytes_tx_to_notice = 20000000 &redef; # single conn Tx bytes over which we want to alert on immediately: 20MB
	const flow_bytes_tx_to_log_and_track = 1000000 &redef;	# destination hosts to record if over this many bytes
	const count_of_tracked_flows_to_notice = 13 &redef; # number of large uploads per IP for an exception
	const flow_suppression_interval = 8hrs &redef; # how long to suppress notices
	const min_flow_producer_consumer_ratio = -0.4 &redef; # disregard flows by ratio of up to down
}

# table indexed by source IP of hosts that have triggered notices and/or emails
# if the number of large uploads exceed maxNumup then generate email
# expire table's entry for IP if older than 1 days
global large_flow_count_by_sender: table[addr] of count &default=0 &create_expire=1days;

# table indexed by dest IP of hosts that have had large uploads to them
# if the number of large uploads exceed maxNumup then generate email
# expire table's entry for IP if older than 1 days
global large_flow_count_by_receiver: table[addr] of count &default=0 &create_expire=1days;

function connection_producer_consumer_ratio(c: connection): double
	{
	# calculate our own floww PCR as described in http://resources.sei.cmu.edu/asset_files/Presentation/2014_017_001_90063.pdf
	local flow_pcr: double = ((c$orig$num_bytes_ip + 0.0) - (c$resp$num_bytes_ip + 0.0)) / ((c$orig$num_bytes_ip + 0.0) + (c$resp$num_bytes_ip + 0.0));
	return flow_pcr;
	}

function handle_flow_exception(c: connection, reverse_lookup_hostname: string)
	{
	# Calculate when the connection ended
	local conn_end_time = c$start_time + c$duration;

	# Represent data as human redable data in Notices
	local start_time = Human::time_to_rfc3339(c$start_time);
	local end_time = Human::time_to_rfc3339(conn_end_time);
	local duration = Human::interval_to_human_string(c$duration);
	local bytes_sent = Human::bytes_to_human_string(c$orig$num_bytes_ip);
	local bytes_received = Human::bytes_to_human_string(c$resp$num_bytes_ip);

	# Calculate the PCR for this flow
	local flow_pcr = connection_producer_consumer_ratio(c);
	local sub_message = "\n";
	sub_message = string_cat(fmt("Flows started: %s, Flows ended: %s\nFlow Producer-Consumer Ratio: %s\n",
						 start_time, end_time, fmt("%s", flow_pcr)));

	# Transport securtiy details
	if (c?$ssl && c$ssl?$server_name)
		{
		sub_message = string_cat(sub_message, fmt("Transport Security Server Name: %s\n", c$ssl$server_name));
		}
	if (c?$ssl && c$ssl?$subject)
		{
		sub_message = string_cat(sub_message, fmt("Transport Security Subject Extracted CN: %s\n", x509_subject_common_name(c$ssl$subject)));
		sub_message = string_cat(sub_message, fmt("Transport Security Subject: %s\n", c$ssl$subject));
		}
	if (c?$ssl && c$ssl?$san_dns)
		{
		sub_message = string_cat(sub_message, fmt("Subject Alternative Names: %s\n", c$ssl$san_dns));
		}
	if (c?$ssl)
		{
		if (c$ssl?$validation_status)
			{
			sub_message = string_cat(sub_message, fmt("Transport Security Certificate Validation: %s\n", c$ssl$validation_status));
			}
		else
			sub_message = string_cat(sub_message, fmt("Transport Security Certificate Validation: Inconclusive."));
		}

	# HTTP parameters
	if (c?$http && c$http?$host && c$http?$method && c$http?$uri)
		{
		sub_message = string_cat(sub_message, fmt("HTTP Request: %s %s%s\n", c$http$method, c$http$host, c$http$uri));
		}
	 if (c?$http && c$http?$user_agent)
		{
		sub_message = string_cat(sub_message, fmt("HTTP User-Agent: %s\n", c$http$user_agent));
		}

	# Count how many large uploads were sent to this host
	large_flow_count_by_receiver[c$id$resp_h]+=1;
	# Alert for large flows, notice the rest 
	if (large_flow_count_by_receiver[c$id$resp_h] >= count_of_tracked_flows_to_notice)
		{
		NOTICE([$note=Multiple_Flows,
		        $msg=fmt("%s has received %s uploads greater than %s from internal hosts over the past %s.",
		                  c$id$resp_h, large_flow_count_by_receiver[c$id$resp_h], bytes_sent, duration),
		        $sub=sub_message,
		        $conn=c,
		        $suppress_for=flow_suppression_interval,
		        $identifier=cat(c$id$resp_h)]);
		}

	# Count how many large uploads originated from this host
	large_flow_count_by_sender[c$id$orig_h]+=1;
	# Alert for large flows, notice the rest 
	if (large_flow_count_by_sender[c$id$orig_h] >= count_of_tracked_flows_to_notice)
		{
		NOTICE([$note=Multiple_Flows,
		        $msg=fmt("%s has sent %s uploads greater than %s over the past %s",
		                  c$id$orig_h, large_flow_count_by_sender[c$id$orig_h], bytes_sent, duration),
		        $sub=sub_message,
		        $conn=c,
		        $suppress_for=flow_suppression_interval,
		        $identifier=cat(c$id$orig_h)]);
		}

	# if num_bytes sent over threshold
	# and flow pcr is noteworthy
	# then send an email alert, else just raise a notice log entry
	if (c$orig$num_bytes_ip > flow_bytes_tx_to_notice && flow_pcr > min_flow_producer_consumer_ratio)
		{
		NOTICE([$note=Large_Flow,
		        $msg=fmt("%s:%s sent %s to %s (%s:%s) over %s in %s, while receiving %s.",
		                  c$id$orig_h, c$id$orig_p, bytes_sent, reverse_lookup_hostname, c$id$resp_h, c$id$resp_p, duration, c$uid, bytes_received),
		        $sub=sub_message,
		        $conn=c,
		        $suppress_for=480min,
		        $identifier=cat(c$id$orig_h, " -> ", c$id$resp_h, ":", c$id$resp_p)]);
		}
	else
		{
		# raise notice msg and format the time stamp for the sub message so that it is human readable
		NOTICE([$note=Flow,
		        $msg=fmt("%s:%s sent %s to %s (%s:%s) over %s in %s, while receiving %s.",
		                  c$id$orig_h, c$id$orig_p, bytes_sent, reverse_lookup_hostname, c$id$resp_h, c$id$resp_p, duration, c$uid, bytes_received),
		        $sub=sub_message,
		        $conn=c,
		        $suppress_for=480min,
		        $identifier=cat(c$id$orig_h, ":", c$id$orig_p, " -> ", c$id$resp_h, ":", c$id$resp_p)]);
		}
	}

event connection_state_remove(c: connection) &priority=10
	{
	if (c$id$resp_h in 255.255.255.255/32) return;

	if (c$orig$num_bytes_ip < flow_bytes_tx_to_log_and_track) return;

	if (c$id$orig_h !in Site::local_nets) return;

	if (c$id$resp_h in Site::local_nets) return;

	if (whitelisted_connection_in_cache(c)) return;

	if (whitelisted_connection_by_subnet(c)) return;

	if (c?$http && c$http?$host)
		{
		if (whitelisted_connection_by_hostname(c, c$http$host))
			{
			add_to_whitelist_cache(c$id$resp_h, c$uid, c$http$host);
			return;
			}
		if (whitelisted_connection_by_hostname_zone(c, c$http$host))
			{
			add_to_whitelist_cache(c$id$resp_h, c$uid, c$http$host);
			return;
			}
		}

	if (c?$ssl && c$ssl?$subject && c$ssl?$validation_status && c$ssl$validation_status == "ok")
		{
		if (whitelisted_connection_by_hostname_zone(c, x509_subject_common_name(c$ssl$subject)))
			{
			add_to_whitelist_cache(c$id$resp_h, c$uid, c$ssl$subject);
			return;
			}
		}

	if (c?$ssl && c$ssl?$server_name && c$ssl?$validation_status)
		{
		if (c$ssl$validation_status != "ok") return;
		if (whitelisted_connection_by_hostname(c, c$ssl$server_name) || whitelisted_connection_by_hostname_zone(c, c$ssl$server_name))
			{
			add_to_whitelist_cache(c$id$resp_h, c$uid, c$ssl$server_name);
			return;
			}
		}

	if (c?$ssl && c$ssl?$san_dns && c$ssl?$validation_status && c$ssl$validation_status == "ok")
		{
		for (dns in c$ssl$san_dns)
			{
			if (whitelisted_connection_by_hostname(c, c$ssl$san_dns[dns]) || whitelisted_connection_by_hostname_zone(c, c$ssl$san_dns[dns]))
				{
				add_to_whitelist_cache(c$id$resp_h, c$uid, c$ssl$san_dns[dns]);
				return;
				}
			}
		}

	when (local reverse_lookup_hostname = lookup_addr(c$id$resp_h))
		{
		if (whitelisted_connection_by_hostname(c, reverse_lookup_hostname)|| whitelisted_connection_by_hostname_zone(c, reverse_lookup_hostname))
			{
			add_to_whitelist_cache(c$id$resp_h, c$uid, reverse_lookup_hostname);
			return;
			}
		else
			{
			handle_flow_exception(c, reverse_lookup_hostname);
			}
		}
	}
