//! Exercises the C ABI exactly as the Qt/C++ frontend does: through the exported `extern "C"`
//! functions, raw pointers, and manual string freeing.

use std::ffi::{CStr, CString};
use std::os::raw::c_char;

use aero_core::ffi::*;

fn cstr(s: &str) -> CString {
    CString::new(s).unwrap()
}

unsafe fn take(s: *mut c_char) -> String {
    assert!(!s.is_null(), "unexpected NULL string from FFI");
    let out = CStr::from_ptr(s).to_str().unwrap().to_string();
    aero_string_free(s);
    out
}

#[test]
fn version_is_reported() {
    unsafe {
        let v = take(aero_version());
        assert!(!v.is_empty());
    }
}

#[test]
fn restore_and_derive_over_abi() {
    unsafe {
        let mnemonic = cstr("test test test test test test test test test test test junk");
        let w = aero_wallet_restore(mnemonic.as_ptr());
        assert!(!w.is_null());

        let addr = take(aero_wallet_address(w, 0));
        assert_eq!(
            addr.to_lowercase(),
            "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
        );
        assert_eq!(aero_wallet_account_count(w), 1);
        assert_eq!(aero_wallet_add_account(w), 1);
        assert_eq!(aero_wallet_account_count(w), 2);

        aero_wallet_free(w);
    }
}

#[test]
fn create_save_open_roundtrip_over_abi() {
    unsafe {
        let w = aero_wallet_create_new(24);
        assert!(!w.is_null());
        let seed = take(aero_wallet_mnemonic(w));
        assert_eq!(seed.split_whitespace().count(), 24);
        let addr0 = take(aero_wallet_address(w, 0));

        // track a token, then persist
        let usdt = cstr("0xdAC17F958D2ee523a2206206994597C13D831ec7");
        let sym = cstr("USDT");
        assert_eq!(aero_wallet_add_token(w, usdt.as_ptr(), sym.as_ptr(), 6), 0);

        let dir = std::env::temp_dir().join(format!("aero_test_{}.aero", std::process::id()));
        let path = cstr(dir.to_str().unwrap());
        let pw = cstr("s3cret");
        assert_eq!(aero_wallet_save(w, path.as_ptr(), pw.as_ptr()), 0);
        aero_wallet_free(w);

        // reopen with correct password
        let w2 = aero_wallet_open(path.as_ptr(), pw.as_ptr());
        assert!(!w2.is_null());
        assert_eq!(take(aero_wallet_address(w2, 0)), addr0);
        let tokens = take(aero_wallet_tokens(w2));
        assert!(tokens.contains("USDT"));
        aero_wallet_free(w2);

        // wrong password fails and sets last_error
        let bad = cstr("nope");
        let w3 = aero_wallet_open(path.as_ptr(), bad.as_ptr());
        assert!(w3.is_null());
        let err = take(aero_last_error());
        assert!(err.to_lowercase().contains("password") || !err.is_empty());

        let _ = std::fs::remove_file(dir);
    }
}

#[test]
fn parse_units_over_abi() {
    unsafe {
        let amt = cstr("1.5");
        let wei = take(aero_parse_units(amt.as_ptr(), 18));
        assert_eq!(wei, "1500000000000000000");
    }
}

#[test]
fn set_provider_rejects_remote_without_tor() {
    unsafe {
        let w = aero_wallet_create_new(12);
        let endpoints = cstr("[\"https://example.com/rpc\"]");
        // NULL socks proxy + remote endpoint + allow_clearnet=false must be refused (no IP leak).
        let rc = aero_wallet_set_provider(w, 1, endpoints.as_ptr(), std::ptr::null(), false, 30);
        assert_eq!(rc, -1);
        let err = take(aero_last_error());
        assert!(err.contains("Tor") || err.contains("proxy"));
        aero_wallet_free(w);
    }
}
