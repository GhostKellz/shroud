const std = @import("std");

pub const ZQuicConfig = extern struct {
    port: u16,
    max_connections: u32,
    connection_timeout_ms: u32,
    enable_ipv6: u8,
    tls_verify: u8,
    reserved: [16]u8,
};

export fn zquic_init(config: [*c]const ZQuicConfig) ?*opaque {
    _ = config;
    return @ptrFromInt(0x1);
}

export fn zquic_destroy(handle: ?*opaque) void {
    _ = handle;
}

export fn zquic_create_server(handle: ?*opaque) c_int {
    _ = handle;
    return 0;
}

export fn zquic_start_server(handle: ?*opaque) c_int {
    _ = handle;
    return 0;
}

export fn zquic_stop_server(handle: ?*opaque) void {
    _ = handle;
}

export fn zquic_create_connection(handle: ?*opaque, endpoint: [*c]const u8) ?*opaque {
    _ = handle;
    _ = endpoint;
    return @ptrFromInt(0x2);
}

export fn zquic_close_connection(conn: ?*opaque) void {
    _ = conn;
}

export fn zquic_send_data(conn: ?*opaque, data: [*c]const u8, data_len: usize) isize {
    _ = conn;
    _ = data;
    return @intCast(data_len);
}

export fn zquic_receive_data(conn: ?*opaque, buffer: [*c]u8, buffer_len: usize) isize {
    _ = conn;
    _ = buffer;
    _ = buffer_len;
    return 0;
}