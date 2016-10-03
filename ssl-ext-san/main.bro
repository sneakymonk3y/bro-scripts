# Add X509 Subject Alternative Name attributes to SSL::Info
#
# Grant Stavely gstavely@evernote.com

@load base/protocols/ssl
@load base/utils/conn-ids
@load base/frameworks/files
@load base/files/x509

module SSL;


export {
	redef record Info += {
		## List of DNS entries in SAN
		san_dns: vector of string &log &optional;

		## List of URI entries in SAN
		san_uri: vector of string &log &optional;

		## List of email entries in SAN
		san_email: vector of string &log &optional;

		## List of ip entries in SAN
		san_ip: vector of addr &log &optional;
		
	};
}

event ssl_established(c: connection) &priority=10
	{
	# update subject and issuer information
	if ( c$ssl?$cert_chain && |c$ssl$cert_chain| > 0 &&
		 c$ssl$cert_chain[0]?$x509 && c$ssl$cert_chain[0]$x509?$san)
		{
		if (c$ssl$cert_chain[0]$x509$san?$dns)
				c$ssl$san_dns = c$ssl$cert_chain[0]$x509$san$dns;

		if (c$ssl$cert_chain[0]$x509$san?$uri)
				c$ssl$san_uri = c$ssl$cert_chain[0]$x509$san$uri;

		if (c$ssl$cert_chain[0]$x509$san?$email)
				c$ssl$san_email = c$ssl$cert_chain[0]$x509$san$email;

		if (c$ssl$cert_chain[0]$x509$san?$ip)
				c$ssl$san_ip = c$ssl$cert_chain[0]$x509$san$ip;
		}

	}
