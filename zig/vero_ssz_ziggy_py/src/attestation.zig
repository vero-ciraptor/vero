const py = @import("pydust");

const root = @This();

pub const ZigAttestationData = py.class(struct {
    const Self = @This();

    pub fn __init__(self: *Self) void {
        _ = self;
    }
});

pub fn zig_attestation_data_from_ssz_bytes() !*ZigAttestationData.definition {
    return try py.init(root, ZigAttestationData.definition, .{});
}

pub fn zig_attestation_data_from_response_json_bytes() !*ZigAttestationData.definition {
    return try py.init(root, ZigAttestationData.definition, .{});
}

comptime {
    py.rootmodule(root);
}
