const std = @import("std");
const os = std.os;
const posix = std.posix;

/// Exit status that a job can use to indicate it does not want to be respawned
pub const PMTR_NO_RESTART: u8 = 33;

/// Maximum username length
pub const PMTR_MAX_USER: usize = 100;

/// Short delay for restart rate limiting (seconds)
pub const SHORT_DELAY: u32 = 10;

/// Default config file path
pub const DEFAULT_PMTR_CONFIG = "/etc/pmtr.conf";

/// Resource limit types that can be set
pub const RlimitType = enum(c_int) {
    core = 4, // RLIMIT_CORE
    data = 2, // RLIMIT_DATA
    nice = 13, // RLIMIT_NICE
    fsize = 1, // RLIMIT_FSIZE
    sigpending = 11, // RLIMIT_SIGPENDING
    memlock = 8, // RLIMIT_MEMLOCK
    rss = 5, // RLIMIT_RSS
    nofile = 7, // RLIMIT_NOFILE
    msgqueue = 12, // RLIMIT_MSGQUEUE
    rtprio = 14, // RLIMIT_RTPRIO
    stack = 3, // RLIMIT_STACK
    cpu = 0, // RLIMIT_CPU
    nproc = 6, // RLIMIT_NPROC
    as = 9, // RLIMIT_AS
};

/// Resource limit with ID and values
pub const ResourceRlimit = struct {
    id: RlimitType,
    rlim_cur: u64,
    rlim_max: u64,
};

/// Mapping of ulimit flags/names to resource types
pub const RlimitLabel = struct {
    flag: []const u8,
    name: []const u8,
    id: RlimitType,
};

pub const rlimit_labels = [_]RlimitLabel{
    .{ .flag = "-c", .name = "RLIMIT_CORE", .id = .core },
    .{ .flag = "-d", .name = "RLIMIT_DATA", .id = .data },
    .{ .flag = "-e", .name = "RLIMIT_NICE", .id = .nice },
    .{ .flag = "-f", .name = "RLIMIT_FSIZE", .id = .fsize },
    .{ .flag = "-i", .name = "RLIMIT_SIGPENDING", .id = .sigpending },
    .{ .flag = "-l", .name = "RLIMIT_MEMLOCK", .id = .memlock },
    .{ .flag = "-m", .name = "RLIMIT_RSS", .id = .rss },
    .{ .flag = "-n", .name = "RLIMIT_NOFILE", .id = .nofile },
    .{ .flag = "-q", .name = "RLIMIT_MSGQUEUE", .id = .msgqueue },
    .{ .flag = "-r", .name = "RLIMIT_RTPRIO", .id = .rtprio },
    .{ .flag = "-s", .name = "RLIMIT_STACK", .id = .stack },
    .{ .flag = "-t", .name = "RLIMIT_CPU", .id = .cpu },
    .{ .flag = "-u", .name = "RLIMIT_NPROC", .id = .nproc },
    .{ .flag = "-v", .name = "RLIMIT_AS", .id = .as },
};

/// CPU set for affinity
pub const CpuSet = struct {
    bits: [16]u64 = [_]u64{0} ** 16, // Up to 1024 CPUs

    pub fn set(self: *CpuSet, cpu: usize) void {
        if (cpu < 1024) {
            self.bits[cpu / 64] |= @as(u64, 1) << @intCast(cpu % 64);
        }
    }

    pub fn isSet(self: *const CpuSet, cpu: usize) bool {
        if (cpu >= 1024) return false;
        return (self.bits[cpu / 64] & (@as(u64, 1) << @intCast(cpu % 64))) != 0;
    }

    pub fn count(self: *const CpuSet) usize {
        var c: usize = 0;
        for (self.bits) |word| {
            c += @popCount(word);
        }
        return c;
    }

    pub fn eql(self: *const CpuSet, other: *const CpuSet) bool {
        return std.mem.eql(u64, &self.bits, &other.bits);
    }
};

/// Job definition - represents a managed process
pub const Job = struct {
    allocator: std.mem.Allocator,
    name: ?[]const u8 = null,
    cmdv: std.ArrayList([]const u8),
    envv: std.ArrayList([]const u8),
    depv: std.ArrayList([]const u8),
    rlim: std.ArrayList(ResourceRlimit),
    deps_hash: i32 = 0,
    dir: ?[]const u8 = null,
    out: ?[]const u8 = null,
    err: ?[]const u8 = null,
    in: ?[]const u8 = null,
    pid: posix.pid_t = 0,
    start_ts: i64 = 0, // last start time
    start_at: i64 = 0, // desired next start
    terminate: i64 = 0, // non-zero if termination requested
    user: [PMTR_MAX_USER]u8 = [_]u8{0} ** PMTR_MAX_USER,
    respawn: bool = true,
    delete_when_collected: bool = false,
    order: i32 = 0,
    nice: i32 = 0,
    disabled: bool = false,
    wait: bool = false,
    once: bool = false,
    bounce_interval: u32 = 0,
    cpuset: CpuSet = .{},

    pub fn init(allocator: std.mem.Allocator) Job {
        return .{
            .allocator = allocator,
            .cmdv = std.ArrayList([]const u8).init(allocator),
            .envv = std.ArrayList([]const u8).init(allocator),
            .depv = std.ArrayList([]const u8).init(allocator),
            .rlim = std.ArrayList(ResourceRlimit).init(allocator),
        };
    }

    pub fn deinit(self: *Job) void {
        if (self.name) |n| self.allocator.free(n);
        if (self.dir) |d| self.allocator.free(d);
        if (self.out) |o| self.allocator.free(o);
        if (self.err) |e| self.allocator.free(e);
        if (self.in) |i| self.allocator.free(i);
        for (self.cmdv.items) |s| self.allocator.free(s);
        self.cmdv.deinit();
        for (self.envv.items) |s| self.allocator.free(s);
        self.envv.deinit();
        for (self.depv.items) |s| self.allocator.free(s);
        self.depv.deinit();
        self.rlim.deinit();
    }

    pub fn clone(self: *const Job, allocator: std.mem.Allocator) !Job {
        var new_job = Job.init(allocator);

        if (self.name) |n| new_job.name = try allocator.dupe(u8, n);
        if (self.dir) |d| new_job.dir = try allocator.dupe(u8, d);
        if (self.out) |o| new_job.out = try allocator.dupe(u8, o);
        if (self.err) |e| new_job.err = try allocator.dupe(u8, e);
        if (self.in) |i| new_job.in = try allocator.dupe(u8, i);

        for (self.cmdv.items) |s| {
            try new_job.cmdv.append(try allocator.dupe(u8, s));
        }
        for (self.envv.items) |s| {
            try new_job.envv.append(try allocator.dupe(u8, s));
        }
        for (self.depv.items) |s| {
            try new_job.depv.append(try allocator.dupe(u8, s));
        }
        for (self.rlim.items) |r| {
            try new_job.rlim.append(r);
        }

        new_job.deps_hash = self.deps_hash;
        new_job.pid = self.pid;
        new_job.start_ts = self.start_ts;
        new_job.start_at = self.start_at;
        new_job.terminate = self.terminate;
        new_job.delete_when_collected = self.delete_when_collected;
        new_job.respawn = self.respawn;
        new_job.order = self.order;
        new_job.nice = self.nice;
        new_job.disabled = self.disabled;
        new_job.wait = self.wait;
        new_job.once = self.once;
        new_job.bounce_interval = self.bounce_interval;
        new_job.cpuset = self.cpuset;
        @memcpy(&new_job.user, &self.user);

        return new_job;
    }

    pub fn getUserName(self: *const Job) ?[]const u8 {
        const end = std.mem.indexOfScalar(u8, &self.user, 0) orelse self.user.len;
        if (end == 0) return null;
        return self.user[0..end];
    }

    /// Compare two job definitions for equality (used when rescanning config)
    pub fn eql(self: *const Job, other: *const Job) bool {
        // Compare name
        const name_eq = if (self.name) |sn| (if (other.name) |on| std.mem.eql(u8, sn, on) else false) else other.name == null;
        if (!name_eq) return false;

        // Compare cmdv
        if (self.cmdv.items.len != other.cmdv.items.len) return false;
        for (self.cmdv.items, other.cmdv.items) |a, b| {
            if (!std.mem.eql(u8, a, b)) return false;
        }

        // Compare envv
        if (self.envv.items.len != other.envv.items.len) return false;
        for (self.envv.items, other.envv.items) |a, b| {
            if (!std.mem.eql(u8, a, b)) return false;
        }

        // Compare rlim
        if (self.rlim.items.len != other.rlim.items.len) return false;
        for (self.rlim.items, other.rlim.items) |a, b| {
            if (a.id != b.id or a.rlim_cur != b.rlim_cur or a.rlim_max != b.rlim_max) return false;
        }

        // Compare depv and hash
        if (self.depv.items.len != other.depv.items.len) return false;
        for (self.depv.items, other.depv.items) |a, b| {
            if (!std.mem.eql(u8, a, b)) return false;
        }
        if (self.deps_hash != other.deps_hash) return false;

        // Compare optional strings
        const dir_eq = if (self.dir) |sd| (if (other.dir) |od| std.mem.eql(u8, sd, od) else false) else other.dir == null;
        if (!dir_eq) return false;

        const out_eq = if (self.out) |so| (if (other.out) |oo| std.mem.eql(u8, so, oo) else false) else other.out == null;
        if (!out_eq) return false;

        const err_eq = if (self.err) |se| (if (other.err) |oe| std.mem.eql(u8, se, oe) else false) else other.err == null;
        if (!err_eq) return false;

        const in_eq = if (self.in) |si| (if (other.in) |oi| std.mem.eql(u8, si, oi) else false) else other.in == null;
        if (!in_eq) return false;

        // Compare other fields
        if (!std.mem.eql(u8, &self.user, &other.user)) return false;
        if (self.order != other.order) return false;
        if (self.disabled != other.disabled) return false;
        if (self.wait != other.wait) return false;
        if (self.once != other.once) return false;
        if (self.bounce_interval != other.bounce_interval) return false;
        if (!self.cpuset.eql(&other.cpuset)) return false;

        return true;
    }
};

/// Socket info for UDP listeners/reporters
pub const SocketInfo = struct {
    fd: posix.fd_t,
    addr: u32,
    port: u16,
};

/// Global pmtr configuration
pub const Config = struct {
    allocator: std.mem.Allocator,
    file: []const u8,
    pidfile: ?[]const u8 = null,
    verbose: u32 = 0,
    foreground: bool = false,
    test_only: bool = false,
    echo_syslog_to_stderr: bool = true,
    dm_pid: posix.pid_t = 0, // dependency monitor subprocess pid
    jobs: std.ArrayList(Job),
    next_alarm: i64 = 0,
    listen: std.ArrayList(SocketInfo),
    report: std.ArrayList(SocketInfo),
    report_id: [100]u8 = [_]u8{0} ** 100,
    logger_pid: posix.pid_t = 0,
    logger_fd: posix.fd_t = -1,
    logger_socket: [10]u8 = [_]u8{0} ** 10,
    logger_namelen: usize = 0,

    pub fn init(allocator: std.mem.Allocator, file: []const u8) Config {
        return .{
            .allocator = allocator,
            .file = file,
            .jobs = std.ArrayList(Job).init(allocator),
            .listen = std.ArrayList(SocketInfo).init(allocator),
            .report = std.ArrayList(SocketInfo).init(allocator),
        };
    }

    pub fn deinit(self: *Config) void {
        for (self.jobs.items) |*job| {
            job.deinit();
        }
        self.jobs.deinit();
        self.listen.deinit();
        self.report.deinit();
        if (self.pidfile) |pf| self.allocator.free(pf);
    }

    pub fn getJobByPid(self: *Config, pid: posix.pid_t) ?*Job {
        for (self.jobs.items) |*job| {
            if (job.pid == pid) return job;
        }
        return null;
    }

    pub fn getJobByName(self: *Config, name: []const u8) ?*Job {
        for (self.jobs.items) |*job| {
            if (job.name) |n| {
                if (std.mem.eql(u8, n, name)) return job;
            }
        }
        return null;
    }
};

test "CpuSet operations" {
    var set = CpuSet{};

    set.set(0);
    set.set(3);
    set.set(64);

    try std.testing.expect(set.isSet(0));
    try std.testing.expect(!set.isSet(1));
    try std.testing.expect(set.isSet(3));
    try std.testing.expect(set.isSet(64));
    try std.testing.expectEqual(@as(usize, 3), set.count());
}

test "Job initialization and cleanup" {
    const allocator = std.testing.allocator;
    var job = Job.init(allocator);
    defer job.deinit();

    job.name = try allocator.dupe(u8, "test-job");
    try job.cmdv.append(try allocator.dupe(u8, "/bin/sleep"));
    try job.cmdv.append(try allocator.dupe(u8, "10"));

    try std.testing.expectEqualStrings("test-job", job.name.?);
    try std.testing.expectEqual(@as(usize, 2), job.cmdv.items.len);
}
