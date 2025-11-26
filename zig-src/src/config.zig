const std = @import("std");
const types = @import("types.zig");
const tokenizer = @import("tokenizer.zig");

const Job = types.Job;
const Config = types.Config;
const RlimitType = types.RlimitType;
const ResourceRlimit = types.ResourceRlimit;
const Token = tokenizer.Token;
const TokenType = tokenizer.TokenType;
const Tokenizer = tokenizer.Tokenizer;
const rlimit_labels = types.rlimit_labels;

pub const ParseError = error{
    SyntaxError,
    InvalidValue,
    DuplicateField,
    MissingField,
    OutOfMemory,
    FileNotFound,
    IoError,
};

/// Parser for pmtr configuration files
pub const Parser = struct {
    allocator: std.mem.Allocator,
    tok: Tokenizer,
    current_job: ?*Job = null,
    config: *Config,
    error_message: std.ArrayList(u8),

    pub fn init(allocator: std.mem.Allocator, source: []const u8, config: *Config) Parser {
        return .{
            .allocator = allocator,
            .tok = Tokenizer.init(source),
            .config = config,
            .error_message = std.ArrayList(u8).init(allocator),
        };
    }

    pub fn deinit(self: *Parser) void {
        self.error_message.deinit();
    }

    fn setError(self: *Parser, comptime fmt: []const u8, args: anytype) void {
        self.error_message.clearRetainingCapacity();
        std.fmt.format(self.error_message.writer(), fmt, args) catch {};
    }

    fn expect(self: *Parser, expected: TokenType) ParseError!Token {
        const tok = self.tok.next();
        if (tok.type != expected) {
            self.setError("expected {s}, got {s} at line {d}", .{
                @tagName(expected),
                @tagName(tok.type),
                tok.line,
            });
            return ParseError.SyntaxError;
        }
        return tok;
    }

    /// Parse the entire configuration file
    pub fn parse(self: *Parser) ParseError!void {
        while (true) {
            const tok = self.tok.next();
            switch (tok.type) {
                .eof => break,
                .job => try self.parseJob(),
                .report => try self.parseReport(),
                .listen => try self.parseListen(),
                else => {
                    self.setError("unexpected token {s} at line {d}", .{ @tagName(tok.type), tok.line });
                    return ParseError.SyntaxError;
                },
            }
        }

        // Sort jobs by order
        std.mem.sort(Job, self.config.jobs.items, {}, struct {
            fn lessThan(_: void, a: Job, b: Job) bool {
                return a.order < b.order;
            }
        }.lessThan);
    }

    fn parseJob(self: *Parser) ParseError!void {
        _ = try self.expect(.lcurly);

        var job = Job.init(self.allocator);
        errdefer job.deinit();

        while (true) {
            const tok = self.tok.next();
            switch (tok.type) {
                .rcurly => break,
                .name => {
                    const val = try self.expect(.str);
                    if (job.name != null) {
                        self.setError("name respecified at line {d}", .{val.line});
                        return ParseError.DuplicateField;
                    }
                    job.name = try self.allocator.dupe(u8, val.value);
                },
                .cmd => try self.parseCmd(&job),
                .dir => {
                    const val = try self.expectPath();
                    if (job.dir != null) {
                        self.setError("dir respecified at line {d}", .{val.line});
                        return ParseError.DuplicateField;
                    }
                    job.dir = try self.allocator.dupe(u8, val.value);
                },
                .out => {
                    const val = try self.expectPath();
                    if (job.out != null) {
                        self.setError("out respecified at line {d}", .{val.line});
                        return ParseError.DuplicateField;
                    }
                    job.out = try self.allocator.dupe(u8, val.value);
                },
                .err => {
                    const val = try self.expectPath();
                    if (job.err != null) {
                        self.setError("err respecified at line {d}", .{val.line});
                        return ParseError.DuplicateField;
                    }
                    job.err = try self.allocator.dupe(u8, val.value);
                },
                .in => {
                    const val = try self.expectPath();
                    if (job.in != null) {
                        self.setError("in respecified at line {d}", .{val.line});
                        return ParseError.DuplicateField;
                    }
                    job.in = try self.allocator.dupe(u8, val.value);
                },
                .user => {
                    const val = try self.expect(.str);
                    if (val.value.len >= types.PMTR_MAX_USER) {
                        self.setError("user name too long at line {d}", .{val.line});
                        return ParseError.InvalidValue;
                    }
                    @memcpy(job.user[0..val.value.len], val.value);
                    job.user[val.value.len] = 0;
                },
                .order => {
                    const val = try self.expect(.str);
                    job.order = std.fmt.parseInt(i32, val.value, 10) catch {
                        self.setError("invalid order value at line {d}", .{val.line});
                        return ParseError.InvalidValue;
                    };
                },
                .env => {
                    const val = try self.expect(.str);
                    if (std.mem.indexOfScalar(u8, val.value, '=') == null) {
                        self.setError("environment string must be VAR=VALUE at line {d}", .{val.line});
                        return ParseError.InvalidValue;
                    }
                    try job.envv.append(try self.allocator.dupe(u8, val.value));
                },
                .ulimit => try self.parseUlimit(&job),
                .disabled => job.disabled = true,
                .wait => job.wait = true,
                .once => {
                    job.once = true;
                    job.respawn = false;
                },
                .nice => {
                    const val = try self.expect(.str);
                    job.nice = std.fmt.parseInt(i32, val.value, 10) catch {
                        self.setError("invalid nice value at line {d}", .{val.line});
                        return ParseError.InvalidValue;
                    };
                    if (job.nice < -20 or job.nice > 19) {
                        self.setError("nice out of range -20 to 19 at line {d}", .{val.line});
                        return ParseError.InvalidValue;
                    }
                },
                .bounce => try self.parseBounce(&job),
                .depends => try self.parseDepends(&job),
                .cpuset => {
                    const val = try self.expect(.str);
                    try self.parseCpuSet(&job.cpuset, val.value, val.line);
                },
                else => {
                    self.setError("unexpected token {s} in job at line {d}", .{ @tagName(tok.type), tok.line });
                    return ParseError.SyntaxError;
                },
            }
        }

        // Validate job has required fields
        if (job.name == null) {
            self.setError("job has no name", .{});
            return ParseError.MissingField;
        }

        try self.config.jobs.append(job);
    }

    fn parseCmd(self: *Parser, job: *Job) ParseError!void {
        // First get the path
        const path = try self.expectPath();
        try job.cmdv.insert(0, try self.allocator.dupe(u8, path.value));

        // Then get any additional arguments
        while (true) {
            const peek = self.tok.peek();
            if (peek.type == .str or peek.type == .quotedstr) {
                const arg = self.tok.next();
                const value = if (arg.type == .quotedstr) tokenizer.unquote(arg.value) else arg.value;
                try job.cmdv.append(try self.allocator.dupe(u8, value));
            } else {
                break;
            }
        }
    }

    fn expectPath(self: *Parser) ParseError!Token {
        const tok = self.tok.next();
        if (tok.type != .str and tok.type != .quotedstr) {
            self.setError("expected path, got {s} at line {d}", .{ @tagName(tok.type), tok.line });
            return ParseError.SyntaxError;
        }
        return tok;
    }

    fn parseUlimit(self: *Parser, job: *Job) ParseError!void {
        const peek = self.tok.peek();
        if (peek.type == .lcurly) {
            // Block form: ulimit { -n 1024 -m 2048 }
            _ = self.tok.next(); // consume {
            while (true) {
                const tok = self.tok.peek();
                if (tok.type == .rcurly) {
                    _ = self.tok.next();
                    break;
                }
                const rname = try self.expect(.str);
                const rval = try self.expect(.str);
                try self.addUlimit(job, rname.value, rval.value, rname.line);
            }
        } else {
            // Single form: ulimit -n 1024
            const rname = try self.expect(.str);
            const rval = try self.expect(.str);
            try self.addUlimit(job, rname.value, rval.value, rname.line);
        }
    }

    fn addUlimit(self: *Parser, job: *Job, rname: []const u8, value_str: []const u8, line: usize) ParseError!void {
        // Parse the value
        var rval: u64 = undefined;
        if (std.mem.eql(u8, value_str, "infinity") or std.mem.eql(u8, value_str, "unlimited")) {
            rval = std.math.maxInt(u64); // RLIM_INFINITY
        } else {
            rval = std.fmt.parseInt(u64, value_str, 10) catch {
                self.setError("non-numeric ulimit value at line {d}", .{line});
                return ParseError.InvalidValue;
            };
        }

        // Find the resource type
        for (rlimit_labels) |label| {
            if (std.mem.eql(u8, rname, label.flag) or std.mem.eql(u8, rname, label.name)) {
                // Prevent ulimit -n infinity
                if (label.id == .nofile and rval == std.math.maxInt(u64)) {
                    self.setError("ulimit -n must be finite at line {d}", .{line});
                    return ParseError.InvalidValue;
                }
                try job.rlim.append(.{
                    .id = label.id,
                    .rlim_cur = rval,
                    .rlim_max = rval,
                });
                return;
            }
        }

        self.setError("unknown ulimit resource {s} at line {d}", .{ rname, line });
        return ParseError.InvalidValue;
    }

    fn parseBounce(self: *Parser, job: *Job) ParseError!void {
        _ = try self.expect(.every);
        const val = try self.expect(.str);

        if (val.value.len == 0) {
            self.setError("invalid time interval in 'bounce every' at line {d}", .{val.line});
            return ParseError.InvalidValue;
        }

        const unit = val.value[val.value.len - 1];
        const num_str = val.value[0 .. val.value.len - 1];

        var interval = std.fmt.parseInt(u32, num_str, 10) catch {
            self.setError("invalid time interval in 'bounce every' at line {d}", .{val.line});
            return ParseError.InvalidValue;
        };

        switch (unit) {
            's' => {},
            'm' => interval *= 60,
            'h' => interval *= 60 * 60,
            'd' => interval *= 60 * 60 * 24,
            else => {
                self.setError("invalid time unit in 'bounce every' at line {d}", .{val.line});
                return ParseError.InvalidValue;
            },
        }

        job.bounce_interval = interval;
    }

    fn parseDepends(self: *Parser, job: *Job) ParseError!void {
        _ = try self.expect(.lcurly);

        while (true) {
            const tok = self.tok.peek();
            if (tok.type == .rcurly) {
                _ = self.tok.next();
                break;
            }
            const path = try self.expectPath();
            try job.depv.append(try self.allocator.dupe(u8, path.value));
        }
    }

    fn parseCpuSet(self: *Parser, cpuset: *types.CpuSet, spec: []const u8, line: usize) ParseError!void {
        // Parse 0xABC form
        if (spec.len > 2 and std.mem.eql(u8, spec[0..2], "0x")) {
            const hex = spec[2..];
            if (hex.len == 0) {
                self.setError("parse error in cpuset at line {d}", .{line});
                return ParseError.InvalidValue;
            }

            for (0..hex.len) |i| {
                const c = hex[hex.len - 1 - i];
                const d: u4 = switch (c) {
                    '0'...'9' => @intCast(c - '0'),
                    'a'...'f' => @intCast(c - 'a' + 10),
                    'A'...'F' => @intCast(c - 'A' + 10),
                    else => {
                        self.setError("invalid hex in cpuset at line {d}", .{line});
                        return ParseError.InvalidValue;
                    },
                };
                for (0..4) |bit| {
                    if ((d & (@as(u4, 1) << @intCast(bit))) != 0) {
                        cpuset.set(i * 4 + bit);
                    }
                }
            }
            return;
        }

        // Parse numbers and ranges: "12,14-17"
        var i: usize = 0;
        while (i < spec.len) {
            // Parse a number
            var num: usize = 0;
            var num_len: usize = 0;
            while (i < spec.len and spec[i] >= '0' and spec[i] <= '9') {
                num = num * 10 + (spec[i] - '0');
                num_len += 1;
                i += 1;
            }

            if (num_len == 0) {
                self.setError("syntax error in cpuset at line {d}", .{line});
                return ParseError.InvalidValue;
            }

            // Check for range
            if (i < spec.len and spec[i] == '-') {
                i += 1;
                var end: usize = 0;
                var end_len: usize = 0;
                while (i < spec.len and spec[i] >= '0' and spec[i] <= '9') {
                    end = end * 10 + (spec[i] - '0');
                    end_len += 1;
                    i += 1;
                }
                if (end_len == 0 or end <= num) {
                    self.setError("syntax error in cpuset at line {d}", .{line});
                    return ParseError.InvalidValue;
                }
                var cpu = num;
                while (cpu <= end) : (cpu += 1) {
                    cpuset.set(cpu);
                }
            } else {
                cpuset.set(num);
            }

            // Skip comma if present
            if (i < spec.len and spec[i] == ',') {
                i += 1;
            }
        }
    }

    fn parseReport(self: *Parser) ParseError!void {
        _ = try self.expect(.to);
        const addr = try self.expect(.str);
        // In test mode, just validate syntax
        if (!self.config.test_only) {
            // TODO: actually set up the socket
            _ = addr;
        }
    }

    fn parseListen(self: *Parser) ParseError!void {
        _ = try self.expect(.on);
        const addr = try self.expect(.str);
        // In test mode, just validate syntax
        if (!self.config.test_only) {
            // TODO: actually set up the socket
            _ = addr;
        }
    }

    pub fn getErrorMessage(self: *Parser) []const u8 {
        return self.error_message.items;
    }
};

/// Read a file and parse it
pub fn parseFile(allocator: std.mem.Allocator, path: []const u8, config: *Config) !void {
    const file = std.fs.cwd().openFile(path, .{}) catch |err| {
        std.log.err("can't open {s}: {}", .{ path, err });
        return ParseError.FileNotFound;
    };
    defer file.close();

    const source = file.readToEndAlloc(allocator, 1024 * 1024) catch |err| {
        std.log.err("can't read {s}: {}", .{ path, err });
        return ParseError.IoError;
    };
    defer allocator.free(source);

    var parser = Parser.init(allocator, source, config);
    defer parser.deinit();

    parser.parse() catch |err| {
        std.log.err("parse error in {s}: {s}", .{ path, parser.getErrorMessage() });
        return err;
    };
}

// Tests
test "parse simple job" {
    const allocator = std.testing.allocator;
    var config = Config.init(allocator, "/etc/pmtr.conf");
    defer config.deinit();

    const source =
        \\job {
        \\  name test-job
        \\  cmd /bin/sleep 10
        \\}
    ;

    var parser = Parser.init(allocator, source, &config);
    defer parser.deinit();

    try parser.parse();

    try std.testing.expectEqual(@as(usize, 1), config.jobs.items.len);
    try std.testing.expectEqualStrings("test-job", config.jobs.items[0].name.?);
    try std.testing.expectEqual(@as(usize, 2), config.jobs.items[0].cmdv.items.len);
    try std.testing.expectEqualStrings("/bin/sleep", config.jobs.items[0].cmdv.items[0]);
    try std.testing.expectEqualStrings("10", config.jobs.items[0].cmdv.items[1]);
}

test "parse job with all options" {
    const allocator = std.testing.allocator;
    var config = Config.init(allocator, "/etc/pmtr.conf");
    defer config.deinit();

    const source =
        \\job {
        \\  name full-job
        \\  cmd /usr/bin/server --port 8080
        \\  dir /var/lib/server
        \\  user www-data
        \\  env PATH=/usr/bin
        \\  env HOME=/var/lib/server
        \\  nice 5
        \\  order 10
        \\  ulimit -n 1024
        \\  cpu 0,1,2-4
        \\  bounce every 1h
        \\  out /var/log/server.log
        \\  err /var/log/server.err
        \\}
    ;

    var parser = Parser.init(allocator, source, &config);
    defer parser.deinit();

    try parser.parse();

    try std.testing.expectEqual(@as(usize, 1), config.jobs.items.len);
    const job = &config.jobs.items[0];
    try std.testing.expectEqualStrings("full-job", job.name.?);
    try std.testing.expectEqualStrings("/var/lib/server", job.dir.?);
    try std.testing.expectEqual(@as(i32, 5), job.nice);
    try std.testing.expectEqual(@as(i32, 10), job.order);
    try std.testing.expectEqual(@as(u32, 3600), job.bounce_interval);
    try std.testing.expectEqual(@as(usize, 2), job.envv.items.len);
    try std.testing.expectEqual(@as(usize, 1), job.rlim.items.len);
    try std.testing.expect(job.cpuset.isSet(0));
    try std.testing.expect(job.cpuset.isSet(1));
    try std.testing.expect(job.cpuset.isSet(2));
    try std.testing.expect(job.cpuset.isSet(3));
    try std.testing.expect(job.cpuset.isSet(4));
    try std.testing.expect(!job.cpuset.isSet(5));
}

test "parse multiple jobs with ordering" {
    const allocator = std.testing.allocator;
    var config = Config.init(allocator, "/etc/pmtr.conf");
    defer config.deinit();

    const source =
        \\job {
        \\  name second
        \\  cmd /bin/b
        \\  order 2
        \\}
        \\job {
        \\  name first
        \\  cmd /bin/a
        \\  order 1
        \\}
    ;

    var parser = Parser.init(allocator, source, &config);
    defer parser.deinit();

    try parser.parse();

    try std.testing.expectEqual(@as(usize, 2), config.jobs.items.len);
    // Jobs should be sorted by order
    try std.testing.expectEqualStrings("first", config.jobs.items[0].name.?);
    try std.testing.expectEqualStrings("second", config.jobs.items[1].name.?);
}

test "parse disabled and once jobs" {
    const allocator = std.testing.allocator;
    var config = Config.init(allocator, "/etc/pmtr.conf");
    defer config.deinit();

    const source =
        \\job {
        \\  name disabled-job
        \\  cmd /bin/test
        \\  disable
        \\}
        \\job {
        \\  name once-job
        \\  cmd /bin/init
        \\  once
        \\  wait
        \\}
    ;

    var parser = Parser.init(allocator, source, &config);
    defer parser.deinit();

    try parser.parse();

    try std.testing.expectEqual(@as(usize, 2), config.jobs.items.len);
    try std.testing.expect(config.jobs.items[0].disabled);
    try std.testing.expect(config.jobs.items[1].once);
    try std.testing.expect(config.jobs.items[1].wait);
    try std.testing.expect(!config.jobs.items[1].respawn);
}

test "parse depends" {
    const allocator = std.testing.allocator;
    var config = Config.init(allocator, "/etc/pmtr.conf");
    defer config.deinit();

    const source =
        \\job {
        \\  name dep-job
        \\  cmd /bin/app
        \\  depends { config.json data.db
        \\  }
        \\}
    ;

    var parser = Parser.init(allocator, source, &config);
    defer parser.deinit();

    try parser.parse();

    try std.testing.expectEqual(@as(usize, 1), config.jobs.items.len);
    try std.testing.expectEqual(@as(usize, 2), config.jobs.items[0].depv.items.len);
    try std.testing.expectEqualStrings("config.json", config.jobs.items[0].depv.items[0]);
    try std.testing.expectEqualStrings("data.db", config.jobs.items[0].depv.items[1]);
}

test "parse ulimit block" {
    const allocator = std.testing.allocator;
    var config = Config.init(allocator, "/etc/pmtr.conf");
    defer config.deinit();

    const source =
        \\job {
        \\  name ulimit-job
        \\  cmd /bin/app
        \\  ulimit { -n 1024 -m 2048
        \\  }
        \\}
    ;

    var parser = Parser.init(allocator, source, &config);
    defer parser.deinit();

    try parser.parse();

    try std.testing.expectEqual(@as(usize, 1), config.jobs.items.len);
    try std.testing.expectEqual(@as(usize, 2), config.jobs.items[0].rlim.items.len);
}

test "parse cpu hex mask" {
    const allocator = std.testing.allocator;
    var config = Config.init(allocator, "/etc/pmtr.conf");
    defer config.deinit();

    const source =
        \\job {
        \\  name cpu-job
        \\  cmd /bin/app
        \\  cpu 0xff
        \\}
    ;

    var parser = Parser.init(allocator, source, &config);
    defer parser.deinit();

    try parser.parse();

    try std.testing.expectEqual(@as(usize, 1), config.jobs.items.len);
    const cpuset = &config.jobs.items[0].cpuset;
    for (0..8) |i| {
        try std.testing.expect(cpuset.isSet(i));
    }
    try std.testing.expect(!cpuset.isSet(8));
}

test "error on missing job name" {
    const allocator = std.testing.allocator;
    var config = Config.init(allocator, "/etc/pmtr.conf");
    defer config.deinit();

    const source =
        \\job {
        \\  cmd /bin/test
        \\}
    ;

    var parser = Parser.init(allocator, source, &config);
    defer parser.deinit();

    const result = parser.parse();
    try std.testing.expectError(ParseError.MissingField, result);
}

test "error on invalid nice value" {
    const allocator = std.testing.allocator;
    var config = Config.init(allocator, "/etc/pmtr.conf");
    defer config.deinit();

    const source =
        \\job {
        \\  name bad-nice
        \\  cmd /bin/test
        \\  nice 25
        \\}
    ;

    var parser = Parser.init(allocator, source, &config);
    defer parser.deinit();

    const result = parser.parse();
    try std.testing.expectError(ParseError.InvalidValue, result);
}
