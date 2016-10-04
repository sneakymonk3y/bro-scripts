##! This script will generate a notice if a host succesfully uploads
##! data to an FTP server.

@load base/frameworks/notice
@load base/protocols/ftp

module Exfil;

export {
	redef enum Notice::Type += {
		FTP_Upload,
	};
}

function handle_ftp_exception(c: connection)
	{
	when (local reverse_lookup_hostname = lookup_addr(c$id$resp_h))
		{
		NOTICE([$note=FTP_Upload,
		        $msg=fmt("%s has used FTP to send files to %s (%s:%s)",
		                  c$id$orig_h, reverse_lookup_hostname, c$id$resp_h, c$id$resp_p),
		        $conn=c,
		        $suppress_for=4hr,
		        $identifier=cat(c$id$orig_h," -> ", c$id$resp_h)]);
		}
	}

event ftp_reply(c: connection, code: count, msg: string, cont_resp: bool )
	{

	local response_xyz = FTP::parse_ftp_reply_code(code);

	# Ignore failed and missing commands
	if (response_xyz$x != 2) return;

	if (!c$ftp?$command) return;

	# Only monitor for STOR (store) and STOU (store uniquely) uploads
	if (/[Ss[Tt][Oo]/ !in c$ftp$command) return;

	# Handle but consider for exception
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
			handle_ftp_exception(c);
			}
		}
	}
