//! Test-only one-shot fault at the real Argon2 FFI boundary. No crypto is implemented here.
#![cfg_attr(not(test), no_std)]
use core::{
    ffi::{c_int, c_uchar, c_ulonglong},
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};
static ARMED: AtomicBool = AtomicBool::new(false);
static HITS: AtomicU64 = AtomicU64::new(0);
static BAD_PARAMETERS: AtomicU64 = AtomicU64::new(0);
#[cfg(not(test))]
extern "C" {
    #[link_name = "__real_cardano_crypto_wallet_argon2id"]
    fn real_argon(
        out: *mut c_uchar,
        password: *const c_uchar,
        password_len: c_ulonglong,
        salt: *const c_uchar,
        time_cost: c_ulonglong,
        memory_bytes: usize,
    ) -> c_int;
}
#[no_mangle]
pub extern "C" fn conformance_arm_argon2_failure() {
    HITS.store(0, Ordering::SeqCst);
    BAD_PARAMETERS.store(0, Ordering::SeqCst);
    ARMED.store(true, Ordering::SeqCst);
}
#[no_mangle]
pub extern "C" fn conformance_argon2_failures() -> u64 {
    HITS.load(Ordering::SeqCst)
}
#[no_mangle]
pub extern "C" fn conformance_argon2_bad_parameters() -> u64 {
    BAD_PARAMETERS.load(Ordering::SeqCst)
}
/// # Safety
/// Arguments and lifetimes are exactly those of the original C Argon2 function.
#[no_mangle]
pub unsafe extern "C" fn __wrap_cardano_crypto_wallet_argon2id(
    out: *mut c_uchar,
    password: *const c_uchar,
    password_len: c_ulonglong,
    salt: *const c_uchar,
    time_cost: c_ulonglong,
    memory_bytes: usize,
) -> c_int {
    if time_cost != 3 || memory_bytes != 131_072 * 1024 {
        BAD_PARAMETERS.fetch_add(1, Ordering::SeqCst);
    }
    if ARMED.swap(false, Ordering::SeqCst) {
        HITS.fetch_add(1, Ordering::SeqCst);
        return 1;
    }
    // SAFETY: This wrapper changes no arguments and the original caller owns them.
    unsafe { real_argon(out, password, password_len, salt, time_cost, memory_bytes) }
}
#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
#[cfg(test)]
unsafe fn real_argon(
    _out: *mut c_uchar,
    _password: *const c_uchar,
    _password_len: c_ulonglong,
    _salt: *const c_uchar,
    _time_cost: c_ulonglong,
    _memory_bytes: usize,
) -> c_int {
    17
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_one_call_fails_then_delegation_and_parameter_checks_resume() {
        conformance_arm_argon2_failure();
        let call = |time, memory| unsafe {
            __wrap_cardano_crypto_wallet_argon2id(
                core::ptr::null_mut(),
                core::ptr::null(),
                0,
                core::ptr::null(),
                time,
                memory,
            )
        };
        assert_eq!(call(3, 131_072 * 1024), 1);
        assert_eq!(conformance_argon2_failures(), 1);
        assert_eq!(call(3, 131_072 * 1024), 17);
        assert_eq!(conformance_argon2_failures(), 1);
        assert_eq!(conformance_argon2_bad_parameters(), 0);
        assert_eq!(call(1, 1024), 17);
        assert_eq!(conformance_argon2_bad_parameters(), 1);
    }
}
