##! A bro module to use in notices where values should be formated for human understanding
module Human;

export {
	global bytes_to_human_string: function(size: double, multiple: count &default=1000) : string;
	global interval_to_human_string: function(i: interval) : string;
	global time_to_rfc3339: function(t: time) : string;
	global x509_subject_common_name: function(distinguished_name: string): string;
}

function bytes_to_human_string(size: double, multiple: count &default=1000) : string {
	local suffixes: table[count] of vector of string = {
	[1000] = vector("KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"),
	[1024] = vector("KiB", "MiB", "GiB", "TiB", "PiB", "EiB", "ZiB", "YiB"),
	};

	if (size < multiple)
		{
		return fmt("%.0f Bytes", size);
		}
	else
		{
		for (suffix in suffixes[multiple])
			{
			size = size / multiple;
			if (size < multiple)
				return fmt("%.2f %s", size, suffixes[multiple][suffix]);
			}
		}
}

function interval_to_human_string(i: interval) : string {
	local human_interval: string = " ";
	local total_seconds = double_to_count(interval_to_double(i));
	local seconds = total_seconds % 60;
	local minutes = total_seconds / 60 % 60;
	local hours = total_seconds / 60 / 60 % 60 %24;
	local days = total_seconds / 60 / 60 / 24;

	if (days > 0)
		{
		human_interval = fmt(" %d day", days);
			{
			if (days > 1) human_interval = string_cat(human_interval, "s");
			}
		}
	if (hours > 0)
		{
		human_interval = string_cat(human_interval, fmt(" %d hour", hours));
			{
			if (hours > 1) human_interval = string_cat(human_interval, "s");
			}
		}
	if (minutes > 0)
		{
		human_interval = string_cat(human_interval, fmt(" %d minute", minutes));
			{
			if (minutes > 1) human_interval = string_cat(human_interval, "s");
			}
		}
	if (seconds > 0)
		{
		human_interval = string_cat(human_interval, fmt(" %d second", seconds));
			{
			if (seconds > 1) human_interval = string_cat(human_interval, "s");
			}
		}
	
	return strip(human_interval);
}

function time_to_rfc3339(t: time) : string {
	local strftime_like_rfc3339 = strftime("%FT%H:%M:%S%z", t);
	local fix_rfc339_zone_offset: pattern = /(..)$/;
	return gsub(strftime_like_rfc3339, fix_rfc339_zone_offset, ":00");
}

function x509_subject_common_name(distinguished_name: string): string
	{
	const match_common_name: pattern = /CN=(.*?),/;
	local extracted_common_name = match_pattern(distinguished_name, match_common_name);
	if (extracted_common_name$matched)
		{
		const extract_common_name: pattern = /\.[^,]*/;
		local extracted_common_name_domain = match_pattern(extracted_common_name$str, extract_common_name);
		if (extracted_common_name_domain$matched)
			return extracted_common_name_domain$str;
		}
	else
		return "no_match";
	}
