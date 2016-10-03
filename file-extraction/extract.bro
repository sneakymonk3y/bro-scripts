global ext_map: table[string] of string = {
    ["application/x-dosexec"] = "exe",
    ["application/octet-stream"] = "bin",
    ["text/plain"] = "txt",
    ["image/jpeg"] = "jpg",
    ["image/png"] = "png",
} &default ="";

event file_new(f: fa_file)
{
        local am_i_orig: bool;
        local ext = "";

        for (cid in f$conns) {
                if (Site::is_local_addr(cid$orig_h)) {
                        am_i_orig = T;
                        break;
                }
        }

        if (!f?$mime_type)
                f$mime_type = "application/octet-stream";
        if ( f?$mime_type && f$mime_type in ext_map)
                ext = ext_map[f$mime_type];

        local fname = fmt("/opt/bro/extracted/%s-%s.%s", f$source, f$id, ext);
        Files::add_analyzer(f, Files::ANALYZER_EXTRACT, [$extract_filename=fname]);
}
