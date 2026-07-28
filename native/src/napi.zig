//! The slice of Node-API this addon uses, transcribed from the public headers.
//!
//! Node ships no headers in a version-manager install, and making the build
//! depend on downloading them is worse than transcribing an ABI that is
//! explicitly frozen: Node-API is versioned and additive, which is the whole
//! point of it. So this file is the same kind of artifact as
//! `src/fuse/constants.ts` — copied by hand from the source of truth, with the
//! source named, and never guessed.
//!
//! Source: `js_native_api.h` and `js_native_api_types.h`, Node v24.18.0
//! (`https://github.com/nodejs/node/blob/v24.18.0/src/js_native_api.h`).
//! Everything here is Node-API version 1, supported by every Node since 8.12.

/// `napi_env` — opaque; only ever passed back to the functions below.
pub const Env = *opaque {};
/// `napi_value` — opaque handle to a JS value, valid for the current scope.
pub const Value = *opaque {};
/// `napi_callback_info` — opaque; unpacked by `napi_get_cb_info`.
pub const CallbackInfo = *opaque {};

/// `napi_status`. Only `ok` is ever branched on; the rest are here to make a
/// non-zero return readable in a debugger.
pub const Status = enum(c_uint) {
    ok = 0,
    invalid_arg = 1,
    object_expected = 2,
    string_expected = 3,
    name_expected = 4,
    function_expected = 5,
    number_expected = 6,
    boolean_expected = 7,
    array_expected = 8,
    generic_failure = 9,
    pending_exception = 10,
    _,
};

/// `napi_callback`.
pub const Callback = *const fn (env: Env, info: CallbackInfo) callconv(.c) Value;

/// `NAPI_AUTO_LENGTH` — "this string is NUL-terminated, measure it yourself".
pub const AUTO_LENGTH: usize = @import("std").math.maxInt(usize);

pub extern fn napi_get_undefined(env: Env, result: *Value) Status;
pub extern fn napi_create_int32(env: Env, value: i32, result: *Value) Status;
pub extern fn napi_get_value_int32(env: Env, value: Value, result: *i32) Status;
pub extern fn napi_create_string_utf8(env: Env, str: [*]const u8, length: usize, result: *Value) Status;
pub extern fn napi_create_error(env: Env, code: ?Value, msg: Value, result: *Value) Status;
pub extern fn napi_throw(env: Env, err: Value) Status;
pub extern fn napi_set_named_property(env: Env, object: Value, utf8name: [*:0]const u8, value: Value) Status;
pub extern fn napi_create_function(
    env: Env,
    utf8name: [*:0]const u8,
    length: usize,
    cb: Callback,
    data: ?*anyopaque,
    result: *Value,
) Status;
pub extern fn napi_get_cb_info(
    env: Env,
    cbinfo: CallbackInfo,
    argc: *usize,
    argv: ?[*]Value,
    this_arg: ?*Value,
    data: ?*?*anyopaque,
) Status;
pub extern fn napi_create_array_with_length(env: Env, length: usize, result: *Value) Status;
pub extern fn napi_set_element(env: Env, object: Value, index: u32, value: Value) Status;
