const std = @import("std");
const py = @import("pydust");

const root = @This();
const ssz = @import("lodestar_ssz/root.zig");
const electra = @import("consensus_types/electra.zig");

const Root = ssz.ByteVectorType(32);
const Uint64 = ssz.UintType(64);
const Checkpoint = ssz.FixedContainerType(struct {
    epoch: Uint64,
    root: Root,
});
const AttestationDataSsz = ssz.FixedContainerType(struct {
    slot: Uint64,
    index: Uint64,
    beacon_block_root: Root,
    source: Checkpoint,
    target: Checkpoint,
});

fn decodeHexRoot(hex: []const u8) ![32]u8 {
    if (hex.len != 66 or hex[0] != '0' or hex[1] != 'x') return error.InvalidHex;
    var out: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&out, hex[2..]);
    return out;
}

fn parseU64String(v: []const u8) !u64 {
    return try std.fmt.parseUnsigned(u64, v, 10);
}

const JsonCheckpoint = struct {
    epoch: []const u8,
    root: []const u8,
};

const JsonAttestationData = struct {
    slot: []const u8,
    index: []const u8,
    beacon_block_root: []const u8,
    source: JsonCheckpoint,
    target: JsonCheckpoint,
};

const JsonEnvelope = struct {
    data: JsonAttestationData,
};

fn attestationFromJsonBytes(allocator: std.mem.Allocator, payload: []const u8) !AttestationDataSsz.Type {
    const parsed = try std.json.parseFromSlice(JsonEnvelope, allocator, payload, .{});
    defer parsed.deinit();

    return .{
        .slot = try parseU64String(parsed.value.data.slot),
        .index = try parseU64String(parsed.value.data.index),
        .beacon_block_root = try decodeHexRoot(parsed.value.data.beacon_block_root),
        .source = .{
            .epoch = try parseU64String(parsed.value.data.source.epoch),
            .root = try decodeHexRoot(parsed.value.data.source.root),
        },
        .target = .{
            .epoch = try parseU64String(parsed.value.data.target.epoch),
            .root = try decodeHexRoot(parsed.value.data.target.root),
        },
    };
}

pub const ZigAttestationData = py.class(struct {
    const Self = @This();

    root_bytes: [32]u8 = [_]u8{0} ** 32,

    pub fn __init__(self: *Self) void {
        _ = self;
    }

    pub fn hash_tree_root_hex(self: *const Self) !py.PyObject(root) {
        var hex_buf: [66]u8 = undefined;
        hex_buf[0] = '0';
        hex_buf[1] = 'x';
        _ = std.fmt.bufPrint(hex_buf[2..], "{s}", .{std.fmt.fmtSliceHexLower(&self.root_bytes)}) catch unreachable;
        const s = try py.PyString(root).create(hex_buf[0..]);
        return s.obj;
    }
});

pub fn zig_attestation_data_from_ssz_bytes(args: struct { payload: py.PyObject(root) }) !*ZigAttestationData.definition {
    const view = try args.payload.getBuffer(py.PyBuffer(root).Flags.SIMPLE);
    defer view.release();

    var root_out: [32]u8 = undefined;
    try AttestationDataSsz.serialized.hashTreeRoot(view.asSlice(u8), &root_out);

    const obj = try py.init(root, ZigAttestationData.definition, .{});
    obj.root_bytes = root_out;
    return obj;
}

pub fn zig_attestation_data_from_response_json_bytes(args: struct { payload: py.PyObject(root) }) !*ZigAttestationData.definition {
    const view = try args.payload.getBuffer(py.PyBuffer(root).Flags.SIMPLE);
    defer view.release();

    const value = try attestationFromJsonBytes(py.allocator, view.asSlice(u8));

    var root_out: [32]u8 = undefined;
    try AttestationDataSsz.hashTreeRoot(&value, &root_out);

    const obj = try py.init(root, ZigAttestationData.definition, .{});
    obj.root_bytes = root_out;
    return obj;
}

pub fn zig_beacon_block_body_root_from_ssz_bytes(args: struct { payload: py.PyObject(root) }) !py.PyObject(root) {
    const view = try args.payload.getBuffer(py.PyBuffer(root).Flags.SIMPLE);
    defer view.release();

    const data = view.asSlice(u8);
    const ranges = try electra.BeaconBlock.readFieldRanges(data);
    const body_range = ranges[4];
    const body_bytes = data[body_range[0]..body_range[1]];

    var root_out: [32]u8 = undefined;
    try electra.BeaconBlockBody.serialized.hashTreeRoot(py.allocator, body_bytes, &root_out);

    var hex_buf: [66]u8 = undefined;
    hex_buf[0] = '0';
    hex_buf[1] = 'x';
    _ = std.fmt.bufPrint(hex_buf[2..], "{s}", .{std.fmt.fmtSliceHexLower(&root_out)}) catch unreachable;
    const s = try py.PyString(root).create(hex_buf[0..]);
    return s.obj;
}

comptime {
    py.rootmodule(root);
}
