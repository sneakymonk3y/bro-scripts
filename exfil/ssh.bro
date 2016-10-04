##! This script will generate a notice if an apparent SSH login originates
##! or heads to a host that is not whitelisted.

@load base/protocols/ssh
@load base/frameworks/notice

module Exfil;
export {
	redef enum Notice::Type += {
		SSH,
	};
}

function handle_ssh_execption(c: connection)
	{
	local sub_message : string = "\n";

	if (!c?$ssh)
		{
		return;
		}

	if (c$ssh?$client)
		{
		sub_message = string_cat(sub_message, fmt("Client: %s\n", c$ssh$client));
		}

	if (c$ssh?$server)
		{
		sub_message = string_cat(sub_message, fmt("Server: %s\n", c$ssh$server));
		}

	when (local reverse_lookup_hostname = lookup_addr(c$id$resp_h))
		{
		NOTICE([$note=SSH,
		        $msg=fmt("%s has connected to %s:%s (%s) using SSH",
		                  c$id$orig_h, c$id$resp_h, c$id$resp_p, reverse_lookup_hostname),
		        $conn=c,
		        $sub=sub_message,
		        $suppress_for=1day,
		        $identifier=cat(c$id$orig_h, " -> ", c$id$resp_h, ":", c$id$resp_p)]);
		}
	}

function evaluate_ssh_for_exception(c:connection)
	{
	if (c$id$orig_h !in Site::local_nets) return;

	if (c$id$resp_h in Site::local_nets) return;

	if (whitelisted_connection_in_cache(c)) return;

	if (whitelisted_connection_by_subnet(c)) return;

	when (local name = lookup_addr(c$id$resp_h))
		{
		if (whitelisted_connection_by_hostname(c, name))
			{
			add_to_whitelist_cache(c$id$resp_h, c$uid, name);
			return;
			}
		else if (whitelisted_connection_by_hostname_zone(c, name))
			{
			add_to_whitelist_cache(c$id$resp_h, c$uid, name);
			return;
			}
		else
			{
			handle_ssh_execption(c);
			}
		}
	}

# Evaluate immediately if auth is successful
event ssh_auth_successful(c: connection, auth_method_none: bool)
	{
	evaluate_ssh_for_exception(c);
	}

# Consider even if we eventually log that it wasn't successful, for short lived connections
event ssh_auth_failed(c: connection)
	{
	evaluate_ssh_for_exception(c);
	}
