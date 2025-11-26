const std = @import("std");
const posix = std.posix;
const types = @import("types.zig");
const Config = types.Config;
const Job = types.Job;

const c = @cImport({
    @cInclude("netdb.h");
    @cInclude("sys/socket.h");
    @cInclude("netinet/in.h");
    @cInclude("arpa/inet.h");
    @cInclude("fcntl.h");
    @cInclude("unistd.h");
    @cInclude("net/if.h");
    @cInclude("sys/ioctl.h");
});

pub const NetError = error{
    InvalidSpec,
    DnsLookupFailed,
    SocketError,
    BindError,
    ConnectError,
};

/// Parse a UDP spec like "udp://127.0.0.1:5555[@eth2]"
pub fn parseSpec(spec: []const u8) !struct { addr: u32, port: u16, iface: ?[]const u8 } {
    // Check protocol prefix
    if (!std.mem.startsWith(u8, spec, "udp://")) {
        return NetError.InvalidSpec;
    }

    const after_proto = spec[6..];

    // Find the last colon for port
    const colon_pos = std.mem.lastIndexOfScalar(u8, after_proto, ':') orelse return NetError.InvalidSpec;

    // Check for @ for interface
    var port_end = after_proto.len;
    var iface: ?[]const u8 = null;
    if (std.mem.lastIndexOfScalar(u8, after_proto, '@')) |at_pos| {
        if (at_pos > colon_pos) {
            port_end = at_pos;
            iface = after_proto[at_pos + 1 ..];
        }
    }

    const host = after_proto[0..colon_pos];
    const port_str = after_proto[colon_pos + 1 .. port_end];

    // Parse port
    const port = std.fmt.parseInt(u16, port_str, 10) catch return NetError.InvalidSpec;

    // Resolve hostname
    const addr = try resolveHost(host);

    return .{ .addr = addr, .port = port, .iface = iface };
}

/// Resolve a hostname to an IPv4 address
fn resolveHost(host: []const u8) !u32 {
    // First try to parse as a numeric IP
    var buf: [16]u8 = undefined;
    const host_z = std.fmt.bufPrint(&buf, "{s}", .{host}) catch return NetError.InvalidSpec;
    buf[host.len] = 0;

    var addr: c.struct_in_addr = undefined;
    if (c.inet_aton(@ptrCast(host_z.ptr), &addr) != 0) {
        return @bitCast(addr.s_addr);
    }

    // Try DNS lookup
    const he = c.gethostbyname(@ptrCast(host_z.ptr));
    if (he == null) {
        return NetError.DnsLookupFailed;
    }

    const addr_ptr: *c.struct_in_addr = @ptrCast(@alignCast(he.*.h_addr_list[0]));
    return @bitCast(addr_ptr.s_addr);
}

/// Set up a UDP listener socket
pub fn setupListener(addr: u32, port: u16) !posix.fd_t {
    const fd = posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0) catch return NetError.SocketError;
    errdefer posix.close(fd);

    // Set close-on-exec
    const flags = posix.fcntl(fd, posix.F.GETFD) catch return NetError.SocketError;
    _ = posix.fcntl(fd, posix.F.SETFD, @as(u32, @bitCast(flags)) | posix.FD_CLOEXEC) catch return NetError.SocketError;

    // Bind
    var sin: posix.sockaddr.in = .{
        .family = posix.AF.INET,
        .port = std.mem.nativeToBig(u16, port),
        .addr = addr,
        .zero = [_]u8{0} ** 8,
    };

    posix.bind(fd, @ptrCast(&sin), @sizeOf(posix.sockaddr.in)) catch return NetError.BindError;

    // Enable SIGIO and non-blocking
    const fl = posix.fcntl(fd, posix.F.GETFL) catch return NetError.SocketError;
    _ = posix.fcntl(fd, posix.F.SETFL, @as(u32, @bitCast(fl)) | @as(u32, @bitCast(posix.O{ .ASYNC = true, .NONBLOCK = true }))) catch return NetError.SocketError;
    _ = posix.fcntl(fd, posix.F.SETOWN, @as(i32, @intCast(c.getpid()))) catch return NetError.SocketError;

    return fd;
}

/// Set up a UDP reporter socket (connected to destination)
pub fn setupReporter(addr: u32, port: u16) !posix.fd_t {
    const fd = posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0) catch return NetError.SocketError;
    errdefer posix.close(fd);

    // Set close-on-exec
    const flags = posix.fcntl(fd, posix.F.GETFD) catch return NetError.SocketError;
    _ = posix.fcntl(fd, posix.F.SETFD, @as(u32, @bitCast(flags)) | posix.FD_CLOEXEC) catch return NetError.SocketError;

    // Connect (for UDP, this just sets default destination)
    var sin: posix.sockaddr.in = .{
        .family = posix.AF.INET,
        .port = std.mem.nativeToBig(u16, port),
        .addr = addr,
        .zero = [_]u8{0} ** 8,
    };

    posix.connect(fd, @ptrCast(&sin), @sizeOf(posix.sockaddr.in)) catch return NetError.ConnectError;

    return fd;
}

/// Close all UDP sockets
pub fn closeSockets(config: *Config) void {
    for (config.listen.items) |sock| {
        posix.close(sock.fd);
    }
    for (config.report.items) |sock| {
        posix.close(sock.fd);
    }
    config.listen.clearRetainingCapacity();
    config.report.clearRetainingCapacity();
}

/// Service incoming UDP datagrams
pub fn serviceSocket(config: *Config) void {
    if (config.listen.items.len == 0) return;

    var buf: [2001]u8 = undefined;
    const fd = config.listen.items[0].fd;

    while (true) {
        const n = posix.read(fd, &buf) catch break;
        if (n == 0) break;
        decodeMessage(config, buf[0..n]);
    }
}

/// Decode a control message like "enable job1 job2" or "disable job1"
fn decodeMessage(config: *Config, buf: []const u8) void {
    const Mode = enum { err, enable, disable };
    var mode: Mode = .err;

    var it = std.mem.tokenizeAny(u8, buf, " \t\n\r");
    while (it.next()) |word| {
        if (std.mem.eql(u8, word, "enable")) {
            mode = .enable;
            continue;
        } else if (std.mem.eql(u8, word, "disable")) {
            mode = .disable;
            continue;
        }

        if (mode == .err) {
            std.log.err("invalid control message", .{});
            return;
        }

        // Find job by name
        if (config.getJobByName(word)) |job| {
            switch (mode) {
                .enable => {
                    if (job.disabled) {
                        std.log.info("enabling {s}", .{word});
                        job.disabled = false;
                    }
                },
                .disable => {
                    if (!job.disabled) {
                        std.log.info("disabling {s}", .{word});
                        job.disabled = true;
                        if (job.pid != 0 and job.terminate == 0) {
                            job.terminate = 1;
                        }
                    }
                },
                .err => {},
            }
        } else {
            std.log.info("control message for unknown job {s}", .{word});
        }
    }
}

/// Report status to all configured destinations
pub fn reportStatus(config: *Config, allocator: std.mem.Allocator) !void {
    if (config.report.items.len == 0) return;

    const now = std.time.timestamp();

    var msg = std.ArrayList(u8).init(allocator);
    defer msg.deinit();

    // Get report_id as string
    const id_end = std.mem.indexOfScalar(u8, &config.report_id, 0) orelse config.report_id.len;
    const report_id = config.report_id[0..id_end];

    try msg.writer().print("report {s}\n", .{report_id});

    for (config.jobs.items) |job| {
        if (!job.respawn) continue; // Don't report one-time jobs

        const name = job.name orelse "unknown";
        const status: u8 = if (job.disabled) 'd' else 'e';
        const elapsed = now - job.start_ts;
        const cmd = if (job.cmdv.items.len > 0) job.cmdv.items[0] else "?";

        try msg.writer().print("{s} {c} {d} {d} {s}\n", .{ name, status, elapsed, job.pid, cmd });
    }

    // Send to all destinations
    for (config.report.items) |sock| {
        _ = posix.write(sock.fd, msg.items) catch |err| {
            if (err != error.ConnectionRefused) {
                std.log.info("write error: {}", .{err});
            }
        };
    }
}

test "parse spec - simple" {
    const result = try parseSpec("udp://127.0.0.1:5555");
    try std.testing.expectEqual(@as(u16, 5555), result.port);
    try std.testing.expectEqual(@as(?[]const u8, null), result.iface);
}

test "parse spec - with interface" {
    const result = try parseSpec("udp://192.168.1.1:6666@eth0");
    try std.testing.expectEqual(@as(u16, 6666), result.port);
    try std.testing.expectEqualStrings("eth0", result.iface.?);
}

test "parse spec - invalid protocol" {
    const result = parseSpec("tcp://127.0.0.1:5555");
    try std.testing.expectError(NetError.InvalidSpec, result);
}
