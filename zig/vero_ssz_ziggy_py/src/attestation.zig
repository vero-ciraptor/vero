const py = @import("pydust");

const root = @This();

pub const ZigAttestationData = py.class(struct {
    const Self = @This();

    payload: py.PyBytes,
    is_json: bool,

    pub fn __init__(self: *Self, args: struct { payload: py.PyBytes, is_json: bool = false }) void {
        args.payload.obj.incref();
        self.* = .{
            .payload = args.payload,
            .is_json = args.is_json,
        };
    }

    pub fn payload_bytes(self: *const Self) py.PyBytes {
        self.payload.obj.incref();
        return self.payload;
    }

    pub fn payload_kind(self: *const Self) py.PyString {
        return if (self.is_json) py.PyString.create("response_json") catch unreachable else py.PyString.create("ssz") catch unreachable;
    }

    pub fn __del__(self: *Self) void {
        self.payload.obj.decref();
    }
});

pub fn zig_attestation_data_from_ssz_bytes(args: struct { payload: py.PyBytes }) !*ZigAttestationData.definition {
    return try py.init(root, ZigAttestationData.definition, .{
        .payload = args.payload,
        .is_json = false,
    });
}

pub fn zig_attestation_data_from_response_json_bytes(args: struct { payload: py.PyBytes }) !*ZigAttestationData.definition {
    return try py.init(root, ZigAttestationData.definition, .{
        .payload = args.payload,
        .is_json = true,
    });
}

comptime {
    py.rootmodule(root);
}
