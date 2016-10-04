##! This script will generate a notice if a host exceeds threshold
##! configurable velocities, length, or counts of DNS queries.
##! 
##! Future massive improvement opportunities: 
##! 	"Practical Comprehensive Bounds on Surreptitious Communication Over DNS"
##! 	http://www.icir.org/vern/papers/covert-dns-usec13.pdf

@load base/frameworks/sumstats
@load base/protocols/dns
@load bro-scripts/human

module Exfil;

export {
	# Notice DNS strangeness
	redef enum Notice::Type += {
		DNS_Excessive_Query_Velocity,
		DNS_Excessive_Query_Length,
		DNS_too_many_TXT_Answers,
		DNS_too_many_NULL_Answers,
	};

	# configurable options to be added to local.bro
	const frequent_queriers: set[subnet] &redef;
	const query_interval = 2min &redef;
	const queries_per_query_interval = 800.0 &redef;
	const query_length_sum_per_interval = 500.0 &redef;
	const txt_answer_types_per_interval = 20.0 &redef;
	const null_answer_types_per_interval = 20.0 &redef;
}

event DNS::connection_state_remove(c: connection) &priority=5
	{
	# Ignore frequent queriers
	if (c$id$orig_h in frequent_queriers)
		return;

	# Ignore non-standard ports
	if (c$id$resp_p == 53/udp || c$id$resp_p == 53/tcp)
		return;

	# Ignore PTR lookups
	if (c$dns?$qtype_name && c$dns$qtype_name == "PTR")
		return;

	# Ignore failed lookups
	if (c$dns?$rcode_name && c$dns$rcode_name != "NOERROR")
		return;

	# Ignore local bare-word lookups like WPAD that are typically local
	if ("." !in c$dns$query)
		return;
	
	# Ignore Service Discovery
	if ("_dns-sd_" in c$dns$query)
		return;

	# Ignore responses without answers
	if (!c$dns?$answers)
		return;

	# Ignore PTR lookups
	if (c$dns?$qtype_name && c$dns$qtype_name == "PTR")
		return;
	
	# Ignore our own zones
	if (whitelisted_zones_regex in c$dns$query)
		{
		return;
		}

	# Sumstat all queries per origin
	SumStats::observe("Queries",
	                   SumStats::Key($host=c$id$orig_h),
	                   SumStats::Observation($str=c$dns$query));

	# Sumstat all query lengths per origin
	SumStats::observe("Query Length",
	                   SumStats::Key($host=c$id$orig_h),
	                   SumStats::Observation($num=|c$dns$query|));

	# Sumstat TXT query answers by origin
	if (c$dns$qtype_name == "TXT")
		{
		SumStats::observe("TXT Answers",
		                   SumStats::Key($host=c$id$orig_h),
		                   SumStats::Observation($str=join_string_vec(c$dns$answers, "\t\t")));
		}

	# Sumstat NULL query answers by origin
	if (c$dns$qtype_name == "NULL")
		{
		SumStats::observe("NULL Answers",
		                   SumStats::Key($host=c$id$orig_h),
		                   SumStats::Observation($str=join_string_vec(c$dns$answers, "\t\t")));
		}
	}

event bro_init()
	{
	# For all queries, only keep unique ones
	local queries_reducer = SumStats::Reducer($stream="Queries", $apply=set(SumStats::UNIQUE));
	local txt_reducer = SumStats::Reducer($stream="TXT Answers", $apply=set(SumStats::UNIQUE));
	local null_reducer = SumStats::Reducer($stream="NULL Answers", $apply=set(SumStats::UNIQUE));
	# Count the amount of data that could be in a stream of queries and answers by length
	local query_length_reducer = SumStats::Reducer($stream="Query Length", $apply=set(SumStats::SUM));

	# Notice too many unique queries
	SumStats::create([$name = "queries",
	                  $epoch = query_interval,
	                  $reducers = set(queries_reducer),
	                  $threshold = queries_per_query_interval,
	                  $threshold_val(key: SumStats::Key, result: SumStats::Result) =
		                {
		                return result["Queries"]$sum;
		                },
	                  $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
		                {
		                local dur = Human::interval_to_human_string(query_interval);
		                Reporter::info(fmt("%s sent %d DNS queries in %s", key$host, result["Queries"]$sum, dur));
		                NOTICE([$note=DNS_Excessive_Query_Velocity,
		                        $src=key$host,
		                        $msg=fmt("%s sent %d DNS queries in %s", key$host, result["Queries"]$sum, dur),
		                        $suppress_for=1mins,
		                        $identifier=cat(key$host)]);
		                }
	                ]);

	# Notice too much data stuffed into queries
	SumStats::create([$name = "query_length",
	                  $epoch = query_interval,
	                  $reducers = set(query_length_reducer),
	                  $threshold = query_length_sum_per_interval,
	                  $threshold_val(key: SumStats::Key, result: SumStats::Result) =
		                {
		                return result["Query Length"]$sum;
		                },
	                  $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
		                {
		                local dur = Human::interval_to_human_string(query_interval);
		                Reporter::info(fmt("%s sent %f characters of DNS queries in %s", key$host, result["Query Length"]$sum, dur));
		                NOTICE([$note=DNS_Excessive_Query_Length,
		                        $src=key$host,
		                        $msg=fmt("%s sent %f characters of DNS queries in %s", key$host, result["Query Length"]$sum, dur),
		                        $suppress_for=1mins,
		                        $identifier=cat(key$host)]);
		                }
	                ]);

	# Notice too many TXT queries
	SumStats::create([$name = "txt",
	                  $epoch = query_interval,
	                  $reducers = set(txt_reducer),
	                  $threshold = txt_answer_types_per_interval,
	                  $threshold_val(key: SumStats::Key, result: SumStats::Result) =
		                {
		                return result["TXT Answers"]$unique+0.0;
		                },
	                  $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
		                {
		                local dur = Human::interval_to_human_string(query_interval);
		                Reporter::info(fmt("%s received %d unique TXT answers to DNS queries against zones we don't whitelist in %s",
		                                    key$host,result["TXT Answers"]$unique, dur));
		                NOTICE([$note=DNS_too_many_TXT_Answers,
		                        $src=key$host,
		                        $msg=fmt("%s received %d unique TXT answers to DNS queries against zones we don't whitelist in %s",
		                                  key$host, result["TXT Answers"]$unique, dur),
		                        $suppress_for=1mins,
		                        $identifier=cat(key$host)]);
		                }
	                ]);

	# Notice too many NULL queries
	SumStats::create([$name = "null",
	                  $epoch = query_interval,
	                  $reducers = set(null_reducer),
	                  $threshold = null_answer_types_per_interval,
	                  $threshold_val(key: SumStats::Key, result: SumStats::Result) =
		                {
		                return result["NULL Answers"]$unique+0.0;
		                },
	                  $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
		                {
		                local dur = Human::interval_to_human_string(query_interval);
		                Reporter::info(fmt("%s received %d unique NULL answers to DNS queries against zones we don't whitelist in %s",
		                                    key$host, result["NULL Answers"]$unique, dur));
		                NOTICE([$note=DNS_too_many_NULL_Answers,
		                        $src=key$host,
		                        $msg=fmt("%s received %d unique NULL answers to DNS queries against zones we don't whitelist in %s",
		                                  key$host, result["NULL Answers"]$unique, dur),
		                        $suppress_for=1mins,
		                        $identifier=cat(key$host)]);
		                }
	                ]);
