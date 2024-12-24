use std::path::PathBuf;

use grammartec::{context::Context, tree::TreeLike};
use libafl::{
    generators::NautilusContext,
    inputs::{Input, NautilusInput},
};
use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};

/// Given a rule name it will generate a tree and unparse the input
/// It will return false if the input is too big for the bound specified
pub fn unparse_bounded_from_rule(
    context: &NautilusContext,
    input: &NautilusInput,
    output_vec: &mut Vec<u8>,
    max_len: usize,
    rule: &str,
) -> bool {
    // Get the rule non-terminal
    let ntid = context.ctx.nt_id(rule);
    // Search for the node corresponding to the the non-terminal
    let id = input
        .tree
        .rules
        .iter()
        .enumerate()
        .position(|(index, _r)| input.tree.get_nonterm_id(index.into(), &context.ctx) == ntid);
    assert!(id.is_some(), "{rule} rule not found in tree!");
    // Unparse the tree in the input, starting from the rule
    input
        .tree
        .unparse(id.unwrap().into(), &context.ctx, output_vec);
    let old_len = output_vec.len();
    let new_len = std::cmp::min(old_len, max_len);
    output_vec.resize(new_len + 1, 0u8);
    old_len <= max_len
}

/// Takes an output directory, unparses all the crashes and stores them in a directory.
pub fn create_concrete_outputs(context: &NautilusContext, crash_dir: PathBuf) {
    let crashes = std::fs::read_dir(crash_dir.clone()).expect("Failed to read crashes");
    let out_dir = crash_dir.join("concrete");
    let mut tmp = vec![];
    for path in crashes {
        tmp.clear();
        let path = path.unwrap().path();
        if path.is_dir() {
            continue;
        }
        let ext = path.extension().unwrap_or_else(|| std::ffi::OsStr::new(""));
        if ext == "lafl_lock" || ext == "metadata" {
            continue;
        }
        // Check if this file was already converted.
        let out_file = out_dir.join(path.file_name().unwrap());
        if !out_file.exists() {
            let input = NautilusInput::from_file(path).expect("Failed to create NautilusInput");
            input.unparse(context, &mut tmp);
            // Remove null terminator before writing to disk
            tmp.pop();
            std::fs::write(&out_file, &tmp).expect("Failed to write file contents");
            println!("Converted {:?}", &out_file);
        }
    }
}

// ref:
// CGI RFC
// https://www.rfc-editor.org/rfc/rfc3875
// mini_httpd implementation
// https://sources.debian.org/src/mini-httpd/1.30-2/mini_httpd.c/

pub fn get_cgi_context(tree_depth: usize, bin_name: String) -> NautilusContext {
    println!("Building grammar, please wait\nIf this takes too long, it might make sense to reduce the number of ints generated");
    // ref:
    // https://url.spec.whatwg.org/#fragment-percent-encode-set
    const FRAGMENT: &AsciiSet = &CONTROLS
        .add(b' ')
        .add(b'"')
        .add(b'<')
        .add(b'>')
        .add(b'`')
        .add(b':');

    // Imitate https://github.com/AFLplusplus/LibAF L/blob/7fd9ac095241da7e65c418eeb69e058e71377f54/libafl/src/generators/nautilus.rs#L30
    // to not use grammar string
    let mut ctx = Context::new();

    // This is needed for the fuzzer to save the input that caused the crash
    // FUZZTERMINATE is needed to differentiate between the ENVs and the BODY when reproducing
    ctx.add_rule("START", b"{ENV}\nFUZZTERM\n{BODY}");

    // POST body
    // [TODO] This doesn't handle multipart, and other types of input (JSON, etc..)
    ctx.add_rule("BODY", b"{BODY_PAIR}");
    ctx.add_rule("BODY", b"{BODY}&{BODY_PAIR}");

    ctx.add_rule("BODY_PAIR", b"{PARAM}%3D{URLENCODED_STRING}");
    // [APPLICATION SPECIFIC] In the application webproc, there are similarities in use between fields and parames, therefore:
    ctx.add_rule("BODY_PAIR", b"{FIELD}%3D{URLENCODED_STRING}");

    for param in include_str!("grammar_data/post_params.list").lines() {
        ctx.add_rule(
            "PARAM",
            utf8_percent_encode(param, FRAGMENT).to_string().as_bytes(),
        );
    }

    // ENV
    // [APPLICATION SPECIFIC] For optimization purposes, we should generate only env variables used by the binary
    ctx.add_rule(
        "ENV",
        b"REMOTE_ADDR={REMOTE_ADDR}\0HTTP_HOST={HTTP_HOST}\0REQUEST_METHOD={REQUEST_METHOD}\0SCRIPT_NAME={SCRIPT_NAME}\0CONTENT_LENGTH={CONTENT_LENGTH}\0CONTENT_TYPE={CONTENT_TYPE}\0QUERY_STRING={QUERY_STRING}\0HTTP_COOKIE={HTTP_COOKIE}",
    );

    // REMOTE_ADDRD
    // I wanted to use a regex for this, but it's too expensive for the final result
    for ip in [
        "192.168.0.1",
        "192.168.1.1",
        "127.0.0.1",
        "0.0.0.0",
        "0:0:0:0:0:0:0:1",
        "::1",
        "10.11.12.13",
        "10.0.0.1",
        "10.1.1.1",
        "121.131.141.151",
    ] {
        ctx.add_rule("REMOTE_ADDR", ip.as_bytes());
    }

    // HTTP_HOST
    ctx.add_rule("HTTP_HOST", b"{STRING}:{PORT}");

    // REQUEST_METHOD
    // reduced for performance reasons
    for elem in [
        "GET", "POST",
    ] {
        ctx.add_rule("REQUEST_METHOD", elem.as_bytes());
    }

    // SCRIPT_NAME
    // I'm assuming that every script is in CGI-bin
    // SCRIPT_NAME could allow a path traversal vulnerability (minihttpd already prevents this tho)
    // ref: https://www.rfc-editor.org/rfc/rfc3875#section-8.2
    ctx.add_rule("SCRIPT_NAME", format!("/cgi-bin/{bin_name}").as_bytes());

    // CONTENT_LENGTH
    ctx.add_rule("CONTENT_LENGTH", b"{INT}");

    // CONTENT_TYPE
    // https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-all-content-types.txt
    for line in include_str!("grammar_data/web-all-content-types.list").lines() {
        ctx.add_rule("CONTENT_TYPE", line.as_bytes());
    }

    // QUERY_STRING
    ctx.add_rule("QUERY_STRING", b"{QUERY_PAIR}");
    // %3D is '&'
    ctx.add_rule("QUERY_STRING", b"{QUERY_STRING}&{QUERY_PAIR}");
    // %3D is '='
    ctx.add_rule("QUERY_PAIR", b"{FIELD}%3D{URLENCODED_STRING}");
    // [APPLICATION SPECIFIC] In the application webproc, there are similarities in use between fields and parames, therefore:
    ctx.add_rule("QUERY_PAIR", b"{PARAM}%3D{URLENCODED_STRING}");

    for field in include_str!("grammar_data/get_fields.list").lines() {
        ctx.add_rule(
            "FIELD",
            utf8_percent_encode(field, FRAGMENT).to_string().as_bytes(),
        );
    }

    // HTTP_COOKIE
    // [APPLICATION SPECIFIC] These are the cookies used by webproc
    ctx.add_rule(
        "HTTP_COOKIE",
        b"sessionid={STRING};language={STRING};sys_UserName={STRING};",
    );

    // ----Base types----
    // On my laptop it takes a long time to create the grammar with u32
    // On the server it might be worth to wait those few minutes on a long campaign
    // Overrall I don't think fuzzing for all possible grammar possibilities is useful
    // It might be better to just choose meaningful ints and use those 
    for i in 0..u16::MAX {
        ctx.add_rule("POS_INT", format!("{i}").as_bytes());
    }

    ctx.add_rule("INT", b"{POS_INT}");
    ctx.add_rule("INT", b"-{POS_INT}");

    // This goes way beyond the allowed port number, do we care?
    ctx.add_rule("PORT", b"{INT}");

    ctx.add_rule("STRING", b"{STRING}{STRING}");
    ctx.add_rule("STRING", b"{NAUGHTY_STRING}");

    ctx.add_rule(
        "URLENCODED_STRING",
        b"{URLENCODED_STRING}{URLENCODED_STRING}",
    );
    ctx.add_rule("URLENCODED_STRING", b"{URLENCODED_NAUGHTY}");

    // Strings taken directly form the binary with `strings`
    for bin_string in include_str!("grammar_data/bin_strings.list").lines() {
        ctx.add_rule("STRING", bin_string.as_bytes());
        // What happens if it's not utf8?
        ctx.add_rule(
            "URLENCODED_STRING",
            utf8_percent_encode(bin_string, FRAGMENT)
                .to_string()
                .as_bytes(),
        );
    }

    // Some naughty strings, some taken from https://github.com/andreafioraldi/libafl_quickjs_fuzzing/blob/master/grammar.json
    for naughty_string in include_str!("grammar_data/naughty_strings.list").lines() {
        ctx.add_rule("NAUGHTY_STRING", naughty_string.as_bytes());
        // What happens if it's not utf8?
        ctx.add_rule(
            "URLENCODED_NAUGHTY",
            utf8_percent_encode(naughty_string, FRAGMENT)
                .to_string()
                .as_bytes(),
        );
    }
    // ----Base types----

    ctx.initialize(tree_depth);
    NautilusContext { ctx }
}
