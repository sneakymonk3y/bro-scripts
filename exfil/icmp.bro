##! This script will generate a notice if a host exceeds a threshold
##! count of ICMP payloads or those payloads have interesting entropy.

@load base/frameworks/sumstats
@load base/frameworks/notice
@load evernote/human

module Exfiltration;

export {
	# Use unique and descriptive names for each notice
	redef enum Notice::Type += {
	ICMP_Velocity,
	};

	# configurable options to be added to local.bro
	const frequent_icmp_senders: set[subnet] &redef;
	const icmp_interval = 2min &redef;
	const icmp_per_query_interval = 120.0 &redef;
}

function check_icmp(c:connection)
	{
	if (c$id$orig_h in frequent_icmp_senders) return;
	if (c$id$orig_h !in Site::local_nets) return;
	if (c$id$resp_h in Site::local_nets) return;

	SumStats::observe("Messages",
	                  SumStats::Key($host=c$id$orig_h),
	                  SumStats::Observation($num=1));
	}

event icmp_sent(c: connection, icmp: icmp_conn)
	{
	check_icmp(c);
	}

event icmp_echo_request(c: connection, icmp: icmp_conn, id: count, seq: count, payload: string)
	{
	if(icmp$len > 110) check_icmp(c);
	}

event icmp_echo_reply(c: connection, icmp: icmp_conn, id: count, seq: count, payload: string)
	{
	check_icmp(c);
	}

event icmp_error_message(c: connection, icmp: icmp_conn, code: count, context: icmp_context)
	{
	check_icmp(c);
	}

event icmp_neighbor_advertisement(c: connection, icmp: icmp_conn, router: bool, solicited: bool, override: bool, tgt: addr, options: icmp6_nd_options)
	{
	check_icmp(c);
	}

event icmp_neighbor_solicitation(c: connection, icmp: icmp_conn, tgt: addr, options: icmp6_nd_options)
	{
	check_icmp(c);
	}

event icmp_packet_too_big(c: connection, icmp: icmp_conn, code: count, context: icmp_context)
	{
	check_icmp(c);
	}

event icmp_parameter_problem(c: connection, icmp: icmp_conn, code: count, context: icmp_context)
	{
	check_icmp(c);
	}

event icmp_redirect(c: connection, icmp: icmp_conn, tgt: addr, dest: addr, options: icmp6_nd_options)
	{
	check_icmp(c);
	}

event icmp_router_advertisement(c: connection, icmp: icmp_conn, cur_hop_limit: count, managed: bool, other: bool, home_agent: bool, pref: count, proxy: bool, rsv: count, router_lifetime: interval, reachable_time: interval, retrans_timer: interval, options: icmp6_nd_options)
	{
	check_icmp(c);
	}

event icmp_router_solicitation(c: connection, icmp: icmp_conn, options: icmp6_nd_options)
	{
	check_icmp(c);
	}

event icmp_time_exceeded(c: connection, icmp: icmp_conn, code: count, context: icmp_context)
	{
	check_icmp(c);
	}

# icmp_unreachable causes frequent false positives when video conferences end with
# our side hanging up first and the flood of UDP to a closed socket is sent
# the unreachables, so only track absurdly large responses
# normal icmp_unreachables tend to be ~36
 event icmp_unreachable(c: connection, icmp: icmp_conn, code: count, context: icmp_context)
	{
	if(icmp$len > 50) check_icmp(c);
	}

event bro_init()
	{
	local messages_reducer = SumStats::Reducer($stream="Messages",
	                                           $apply=set(SumStats::SUM));

	SumStats::create([$name = "messages",
	                 $epoch = icmp_interval,
	                 $reducers = set(messages_reducer),
	                 $threshold = icmp_per_query_interval,
	                 $threshold_val(key: SumStats::Key, result: SumStats::Result) =
		                 {
		                 return result["Messages"]$sum;
		                 },
	                 $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
		                 {
		                 local dur = Human::interval_to_human_string(query_interval);
		                 NOTICE([$note=ICMP_Velocity,
		                         $src=key$host,
		                         $msg=fmt("%s sent %s/%s ICMP messages in %s", key$host, result["Messages"]$sum, icmp_per_query_interval, dur),
		                         $suppress_for=30mins,
		                         $identifier=cat(key$host)]);
		                 }
	                ]);
	}
