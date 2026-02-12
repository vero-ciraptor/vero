const std = @import("std");

fn writeError(err_ptr: [*]u8, err_len: usize, msg: []const u8) void {
    if (err_len == 0) return;

    const copy_len = @min(msg.len, err_len - 1);
    @memcpy(err_ptr[0..copy_len], msg[0..copy_len]);
    err_ptr[copy_len] = 0;
}

// Returns 0 on success, non-zero on error.
// ABI contract:
// - input_ptr/input_len: input bytes
// - out_ptr: must point to 32 writable bytes
// - err_ptr/err_len: optional error buffer for UTF-8, null-terminated
pub export fn vero_attestation_data_root_from_ssz(
    input_ptr: [*]const u8,
    input_len: usize,
    out_ptr: [*]u8,
    err_ptr: [*]u8,
    err_len: usize,
) c_int {
    _ = input_ptr;
    _ = input_len;
    _ = out_ptr;

    writeError(err_ptr, err_len, "not implemented");
    return 1;
}

pub export fn vero_attestation_data_root_from_response_json(
    input_ptr: [*]const u8,
    input_len: usize,
    out_ptr: [*]u8,
    err_ptr: [*]u8,
    err_len: usize,
) c_int {
    _ = input_ptr;
    _ = input_len;
    _ = out_ptr;

    writeError(err_ptr, err_len, "not implemented");
    return 1;
}
