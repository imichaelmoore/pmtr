const std = @import("std");

/// Token types used in pmtr configuration files
pub const TokenType = enum(u8) {
    report = 1,
    to = 2,
    str = 3,
    listen = 4,
    on = 5,
    job = 6,
    lcurly = 7,
    rcurly = 8,
    name = 9,
    cmd = 10,
    dir = 11,
    out = 12,
    in = 13,
    err = 14,
    user = 15,
    order = 16,
    env = 17,
    ulimit = 18,
    disabled = 19,
    wait = 20,
    once = 21,
    nice = 22,
    bounce = 23,
    every = 24,
    depends = 25,
    cpuset = 26,
    quotedstr = 27,
    eof = 0,
    invalid = 255,
};

/// A token with its type and value
pub const Token = struct {
    type: TokenType,
    value: []const u8,
    line: usize,
};

/// Keyword definition
const Keyword = struct {
    str: []const u8,
    id: TokenType,
};

/// List of keywords recognized by the tokenizer
const keywords = [_]Keyword{
    .{ .str = "job", .id = .job },
    .{ .str = "name", .id = .name },
    .{ .str = "user", .id = .user },
    .{ .str = "cmd", .id = .cmd },
    .{ .str = "env", .id = .env },
    .{ .str = "dir", .id = .dir },
    .{ .str = "out", .id = .out },
    .{ .str = "err", .id = .err },
    .{ .str = "in", .id = .in },
    .{ .str = "order", .id = .order },
    .{ .str = "disable", .id = .disabled },
    .{ .str = "wait", .id = .wait },
    .{ .str = "once", .id = .once },
    .{ .str = "{", .id = .lcurly },
    .{ .str = "}", .id = .rcurly },
    .{ .str = "listen", .id = .listen },
    .{ .str = "on", .id = .on },
    .{ .str = "report", .id = .report },
    .{ .str = "to", .id = .to },
    .{ .str = "bounce", .id = .bounce },
    .{ .str = "every", .id = .every },
    .{ .str = "depends", .id = .depends },
    .{ .str = "ulimit", .id = .ulimit },
    .{ .str = "nice", .id = .nice },
    .{ .str = "cpu", .id = .cpuset },
};

fn isWhitespace(c: u8) bool {
    return c == ' ' or c == '\t' or c == '\r' or c == '\n';
}

/// Tokenizer for pmtr configuration files
pub const Tokenizer = struct {
    source: []const u8,
    pos: usize = 0,
    line: usize = 1,
    last_newline_pos: usize = 0,

    pub fn init(source: []const u8) Tokenizer {
        return .{ .source = source };
    }

    /// Skip whitespace and update line count
    fn skipWhitespace(self: *Tokenizer) void {
        while (self.pos < self.source.len and isWhitespace(self.source[self.pos])) {
            if (self.source[self.pos] == '\n') {
                self.line += 1;
                self.last_newline_pos = self.pos;
            }
            self.pos += 1;
        }
    }

    /// Skip a comment (from # to end of line)
    fn skipComment(self: *Tokenizer) void {
        while (self.pos < self.source.len and self.source[self.pos] != '\n') {
            self.pos += 1;
        }
    }

    /// Check if the character before position (after last newline) is only whitespace
    fn isPrecededByNewlineOrStart(self: *const Tokenizer, start_pos: usize) bool {
        if (start_pos == 0) return true;

        // Look backwards from start_pos to find if there's any non-whitespace before on this line
        var p = start_pos;
        while (p > 0) {
            p -= 1;
            const c = self.source[p];
            if (c == '\n') return true;
            if (!isWhitespace(c)) return false;
        }
        return true; // reached start of buffer
    }

    /// Get the next token
    pub fn next(self: *Tokenizer) Token {
        while (true) {
            self.skipWhitespace();

            if (self.pos >= self.source.len) {
                return .{ .type = .eof, .value = "", .line = self.line };
            }

            // Skip comments
            if (self.source[self.pos] == '#') {
                self.skipComment();
                continue;
            }

            const start_pos = self.pos;
            const start_line = self.line;

            // Try to match a keyword
            for (keywords) |kw| {
                if (self.pos + kw.str.len <= self.source.len) {
                    if (std.mem.eql(u8, self.source[self.pos .. self.pos + kw.str.len], kw.str)) {
                        // Check if followed by whitespace or end of buffer
                        const end_pos = self.pos + kw.str.len;
                        const followed_by_ws = end_pos >= self.source.len or isWhitespace(self.source[end_pos]);

                        if (followed_by_ws) {
                            // Special rules: most keywords must be preceded by newline or start
                            // Exception: { on to every
                            const needs_newline = kw.id != .lcurly and kw.id != .on and kw.id != .to and kw.id != .every;

                            if (!needs_newline or self.isPrecededByNewlineOrStart(start_pos)) {
                                self.pos = end_pos;
                                return .{ .type = kw.id, .value = kw.str, .line = start_line };
                            }
                        }
                    }
                }
            }

            // Try to match a quoted string
            if (self.source[self.pos] == '"') {
                self.pos += 1;
                while (self.pos < self.source.len) {
                    if (self.source[self.pos] == '"') {
                        const value = self.source[start_pos .. self.pos + 1]; // include quotes
                        self.pos += 1;
                        return .{ .type = .quotedstr, .value = value, .line = start_line };
                    }
                    if (self.source[self.pos] == '\n') {
                        // Unterminated quote - error
                        return .{ .type = .invalid, .value = self.source[start_pos..self.pos], .line = start_line };
                    }
                    self.pos += 1;
                }
                // End of buffer without closing quote
                return .{ .type = .invalid, .value = self.source[start_pos..], .line = start_line };
            }

            // Otherwise it's a plain string
            while (self.pos < self.source.len and !isWhitespace(self.source[self.pos])) {
                self.pos += 1;
            }

            if (self.pos > start_pos) {
                return .{ .type = .str, .value = self.source[start_pos..self.pos], .line = start_line };
            }

            // Shouldn't reach here
            return .{ .type = .invalid, .value = "", .line = start_line };
        }
    }

    /// Peek at the next token without consuming it
    pub fn peek(self: *Tokenizer) Token {
        const saved_pos = self.pos;
        const saved_line = self.line;
        const saved_last_newline = self.last_newline_pos;

        const tok = self.next();

        self.pos = saved_pos;
        self.line = saved_line;
        self.last_newline_pos = saved_last_newline;

        return tok;
    }
};

/// Unquote a quoted string (remove surrounding quotes)
pub fn unquote(str: []const u8) []const u8 {
    if (str.len >= 2 and str[0] == '"' and str[str.len - 1] == '"') {
        return str[1 .. str.len - 1];
    }
    return str;
}

// Tests
test "empty input" {
    var tokenizer = Tokenizer.init("");
    const tok = tokenizer.next();
    try std.testing.expectEqual(TokenType.eof, tok.type);
}

test "whitespace only" {
    var tokenizer = Tokenizer.init("   \t\n  ");
    const tok = tokenizer.next();
    try std.testing.expectEqual(TokenType.eof, tok.type);
}

test "comment only" {
    var tokenizer = Tokenizer.init("# this is a comment\n");
    const tok = tokenizer.next();
    try std.testing.expectEqual(TokenType.eof, tok.type);
}

test "job keyword" {
    var tokenizer = Tokenizer.init("job {\n}");
    const tok1 = tokenizer.next();
    try std.testing.expectEqual(TokenType.job, tok1.type);
    const tok2 = tokenizer.next();
    try std.testing.expectEqual(TokenType.lcurly, tok2.type);
    const tok3 = tokenizer.next();
    try std.testing.expectEqual(TokenType.rcurly, tok3.type);
}

test "name keyword" {
    var tokenizer = Tokenizer.init("name test-job");
    const tok1 = tokenizer.next();
    try std.testing.expectEqual(TokenType.name, tok1.type);
    const tok2 = tokenizer.next();
    try std.testing.expectEqual(TokenType.str, tok2.type);
    try std.testing.expectEqualStrings("test-job", tok2.value);
}

test "cmd keyword" {
    var tokenizer = Tokenizer.init("cmd /bin/sleep 10");
    const tok1 = tokenizer.next();
    try std.testing.expectEqual(TokenType.cmd, tok1.type);
    const tok2 = tokenizer.next();
    try std.testing.expectEqual(TokenType.str, tok2.type);
    const tok3 = tokenizer.next();
    try std.testing.expectEqual(TokenType.str, tok3.type);
}

test "quoted string" {
    var tokenizer = Tokenizer.init("cmd /bin/echo \"hello world\"");
    _ = tokenizer.next(); // cmd
    _ = tokenizer.next(); // /bin/echo
    const tok = tokenizer.next();
    try std.testing.expectEqual(TokenType.quotedstr, tok.type);
    try std.testing.expectEqualStrings("hello world", unquote(tok.value));
}

test "listen on" {
    var tokenizer = Tokenizer.init("listen on udp://127.0.0.1:5555");
    const tok1 = tokenizer.next();
    try std.testing.expectEqual(TokenType.listen, tok1.type);
    const tok2 = tokenizer.next();
    try std.testing.expectEqual(TokenType.on, tok2.type);
    const tok3 = tokenizer.next();
    try std.testing.expectEqual(TokenType.str, tok3.type);
}

test "report to" {
    var tokenizer = Tokenizer.init("report to udp://192.168.1.1:6666");
    const tok1 = tokenizer.next();
    try std.testing.expectEqual(TokenType.report, tok1.type);
    const tok2 = tokenizer.next();
    try std.testing.expectEqual(TokenType.to, tok2.type);
    const tok3 = tokenizer.next();
    try std.testing.expectEqual(TokenType.str, tok3.type);
}

test "disabled" {
    var tokenizer = Tokenizer.init("disable");
    const tok = tokenizer.next();
    try std.testing.expectEqual(TokenType.disabled, tok.type);
}

test "wait once" {
    var tokenizer = Tokenizer.init("wait\nonce");
    const tok1 = tokenizer.next();
    try std.testing.expectEqual(TokenType.wait, tok1.type);
    const tok2 = tokenizer.next();
    try std.testing.expectEqual(TokenType.once, tok2.type);
}

test "env var" {
    var tokenizer = Tokenizer.init("env FOO=bar");
    const tok1 = tokenizer.next();
    try std.testing.expectEqual(TokenType.env, tok1.type);
    const tok2 = tokenizer.next();
    try std.testing.expectEqual(TokenType.str, tok2.type);
    try std.testing.expectEqualStrings("FOO=bar", tok2.value);
}

test "ulimit" {
    var tokenizer = Tokenizer.init("ulimit -n 1024");
    const tok1 = tokenizer.next();
    try std.testing.expectEqual(TokenType.ulimit, tok1.type);
    const tok2 = tokenizer.next();
    try std.testing.expectEqual(TokenType.str, tok2.type);
    const tok3 = tokenizer.next();
    try std.testing.expectEqual(TokenType.str, tok3.type);
}

test "nice" {
    var tokenizer = Tokenizer.init("nice -5");
    const tok1 = tokenizer.next();
    try std.testing.expectEqual(TokenType.nice, tok1.type);
    const tok2 = tokenizer.next();
    try std.testing.expectEqual(TokenType.str, tok2.type);
}

test "cpu" {
    var tokenizer = Tokenizer.init("cpu 0x0f");
    const tok1 = tokenizer.next();
    try std.testing.expectEqual(TokenType.cpuset, tok1.type);
    const tok2 = tokenizer.next();
    try std.testing.expectEqual(TokenType.str, tok2.type);
}

test "bounce every" {
    var tokenizer = Tokenizer.init("bounce every 1h");
    const tok1 = tokenizer.next();
    try std.testing.expectEqual(TokenType.bounce, tok1.type);
    const tok2 = tokenizer.next();
    try std.testing.expectEqual(TokenType.every, tok2.type);
    const tok3 = tokenizer.next();
    try std.testing.expectEqual(TokenType.str, tok3.type);
}

test "depends" {
    var tokenizer = Tokenizer.init("depends { file1.txt file2.txt\n}");
    const tok1 = tokenizer.next();
    try std.testing.expectEqual(TokenType.depends, tok1.type);
    const tok2 = tokenizer.next();
    try std.testing.expectEqual(TokenType.lcurly, tok2.type);
    const tok3 = tokenizer.next();
    try std.testing.expectEqual(TokenType.str, tok3.type);
    const tok4 = tokenizer.next();
    try std.testing.expectEqual(TokenType.str, tok4.type);
    const tok5 = tokenizer.next();
    try std.testing.expectEqual(TokenType.rcurly, tok5.type);
}

test "full job" {
    const config =
        \\job {
        \\  name test-service
        \\  cmd /usr/bin/sleep 3600
        \\  dir /tmp
        \\  user nobody
        \\  env PATH=/usr/bin
        \\  nice 5
        \\}
    ;
    var tokenizer = Tokenizer.init(config);

    const tok1 = tokenizer.next();
    try std.testing.expectEqual(TokenType.job, tok1.type);
    const tok2 = tokenizer.next();
    try std.testing.expectEqual(TokenType.lcurly, tok2.type);
    const tok3 = tokenizer.next();
    try std.testing.expectEqual(TokenType.name, tok3.type);
}

test "multiple jobs" {
    const config =
        \\job {
        \\  name job1
        \\  cmd /bin/true
        \\}
        \\job {
        \\  name job2
        \\  cmd /bin/false
        \\}
    ;
    var tokenizer = Tokenizer.init(config);

    var job_count: usize = 0;
    while (true) {
        const tok = tokenizer.next();
        if (tok.type == .eof) break;
        if (tok.type == .job) job_count += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), job_count);
}

test "line counting" {
    var tokenizer = Tokenizer.init("job\n\n\nname");

    const tok1 = tokenizer.next();
    try std.testing.expectEqual(TokenType.job, tok1.type);
    try std.testing.expectEqual(@as(usize, 1), tok1.line);

    const tok2 = tokenizer.next();
    try std.testing.expectEqual(TokenType.name, tok2.type);
    try std.testing.expectEqual(@as(usize, 4), tok2.line);
}
