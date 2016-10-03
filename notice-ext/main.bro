##! This script will provide an alternate way of emailing Notices so 
##! that you can provide more details in the subject and body.

@load base/frameworks/notice
@load bro-scripts/human

module Notice;

export {
	redef enum Action += {
		## add our extended email action to Notice's list
		ACTION_EMAIL_EXT,
	};

	## Extend existing Notice::Info records with other connection records
	## so that tickets created directly from notices can be more actionable
	redef record Info+= {
		email_subject: string &optional;
	};

	## Constructs mail headers to which an email body can be appended for
	## sending with sendmail.
	##
	## subject_notice: the name of the notice that bro normally uses for the email subject
	##
	## subject_desc: the text we are adding to the subject in this module
	##
	## dest: recipient string to use for the mail.
	##
	## Returns: a string of mail headers to which an email body can be appended
	global email_headers_ext: function(subject_notice: string, subject_desc: string, dest: string): string;

	## Call this function to send a notice in an email with a custom and additional body content
	##
	## n: The record of notice data to email.
	##
	## dest: The intended recipient of the notice email.
	##
	## extend: Whether to extend the email using the ``email_body_sections`` field of *n*.
	global email_notice_to_ext: function(n: Notice::Info, dest: string, extend: bool);

	## Emailed notice types.
	const ext_emailed_types: set[Notice::Type] = {} &redef;

}


function email_headers_ext(subject_notice: string, subject_desc: string, dest: string): string
	{
	local header_text = string_cat(
		"From: ", mail_from, "\n",
		"Subject: ", mail_subject_prefix, ":", subject_notice, ": ", subject_desc, "\n",
		"To: ", dest, "\n",
		"User-Agent: Bro-IDS/", bro_version(), "\n");
	if ( reply_to != "" )
		header_text = string_cat(header_text, "Reply-To: ", reply_to, "\n");
	return header_text;
	}

function email_notice_to_ext(n: Notice::Info, dest: string, extend: bool)
	{
	if ( reading_traces() || dest == "" )
		return;

	if ( extend )
		{
		if ( |n$email_delay_tokens| > 0 )
			{
			# If we still are within the max_email_delay, keep delaying.
			if ( n$ts + max_email_delay > network_time() )
				{
				schedule 1sec { delay_sending_email(n, dest, extend) };
				return;
				}
			else
				{
				Reporter::info(fmt("Notice email delay tokens weren't released in time (%s).", n$email_delay_tokens));
				}
			}
		}

		local email_subject: string &redef;

	if (n?$email_subject)
		{
		email_subject = n$email_subject;
		}
	else if(n?$msg)
		{
		email_subject = n$msg;
		}

	local email_text = email_headers_ext(fmt("%s", n$note), email_subject, dest);

	# First off, finish the headers and include the human readable messages
	# then leave a blank line after the message.
	email_text = string_cat(email_text, "\n", n$msg, "\n");

	if ( n?$sub )
		email_text = string_cat(email_text, n$sub, " ");

	email_text = string_cat(email_text, "\n");

	# Add information about the file if it exists.
	if ( n?$file_desc )
		email_text = string_cat(email_text, "File Description: ", n$file_desc, "\n");

	if ( n?$file_mime_type )
		email_text = string_cat(email_text, "File MIME Type: ", n$file_mime_type, "\n");

	if ( n?$file_desc || n?$file_mime_type )
		email_text = string_cat(email_text, "\n");

	# Next, add information about the connection if it exists.
	if ( n?$id )
		{
		email_text = string_cat(email_text, "Connection: ",
			fmt("%s", n$id$orig_h), ":", fmt("%d", n$id$orig_p), " -> ",
			fmt("%s", n$id$resp_h), ":", fmt("%d/%s", n$id$resp_p, n$proto), "\n");
		if ( n?$uid )
			email_text = string_cat(email_text, "Connection uid: ", n$uid, "\n");
		}
	else if ( n?$src )
		email_text = string_cat(email_text, "Address: ", fmt("%s", n$src), "\n");

	# Add details about when the notice was generated
	if ( n?$ts )
		{
		local timeformat = "%F %H:%M:%S %Z";
		email_text = string_cat(email_text, "Notice time: ", strftime(timeformat, n$ts), " ", "(", cat(n$ts), ")\n");
		}

	# Detail this notices suppression information
	if ( n?$suppress_for && n?$identifier )
		{
		email_text = string_cat(email_text, fmt("\n%s will not be noticed by %s again for %s.\n", n$identifier, n$note, Human::interval_to_human_string(n$suppress_for)));
		}

	# Add the extended information if it's requested and contains anything
	if ( extend && |n$email_body_sections| > 0)
		{
		email_text = string_cat(email_text, "\n*Context*\n----\n");
		for ( i in n$email_body_sections )
			{
			email_text = string_cat(email_text, n$email_body_sections[i], "\n");
			}
		}
	piped_exec(fmt("%s -t -oi", sendmail), email_text);
	}

hook policy(n: Notice::Info)
	{
	if ( n$note in ext_emailed_types )
		add n$actions[ACTION_EMAIL_EXT];
	}

hook notice(n: Notice::Info)
	{
	if ( ACTION_EMAIL_EXT in n$actions )
		email_notice_to_ext(n, mail_dest, T);
	}
