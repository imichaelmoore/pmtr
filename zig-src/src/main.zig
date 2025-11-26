const std = @import("std");
const posix = std.posix;
const types = @import("types.zig");
const config_parser = @import("config.zig");
const job_mgmt = @import("job.zig");
const net = @import("net.zig");
pub const tokenizer = @import("tokenizer.zig");

const Config = types.Config;
const Job = types.Job;

const c = @cImport({
    @cInclude("signal.h");
    @cInclude("setjmp.h");
    @cInclude("syslog.h");
    @cInclude("sys/socket.h");
    @cInclude("sys/un.h");
    @cInclude("sys/epoll.h");
    @cInclude("sys/prctl.h");
    @cInclude("sys/types.h");
    @cInclude("sys/stat.h");
    @cInclude("unistd.h");
    @cInclude("fcntl.h");
    @cInclude("time.h");
    @cInclude("errno.h");
    @cInclude("stdio.h");
    @cInclude("stdlib.h");
});

// Global state needed for signal handling
var global_jmp: c.sigjmp_buf = undefined;
var global_config: ?*Config = null;
var gpa = std.heap.GeneralPurposeAllocator(.{}){};

fn usage(prog: []const u8) noreturn {
    const stderr = std.io.getStdErr().writer();
    stderr.print(
        \\usage: {s} [options]
        \\
        \\  options:
        \\    -v           (verbose)
        \\    -c <file>    (config file)
        \\    -p <file>    (make pidfile)
        \\    -F           (stay in foreground)
        \\    -t           (just test config file)
        \\
        \\  Default config: {s}
        \\
    , .{ prog, types.DEFAULT_PMTR_CONFIG }) catch {};
    c.exit(255);
}

fn sighandler(signo: c_int) callconv(.C) void {
    c.siglongjmp(&global_jmp, signo);
}

/// Set up logger socket (parent side)
fn setupLogger(config: *Config) !void {
    const fd = c.socket(c.AF_UNIX, c.SOCK_STREAM, 0);
    if (fd < 0) {
        std.log.err("socket: {s}", .{c.strerror(c.__errno_location().*)});
        return error.SocketError;
    }

    var addr: c.struct_sockaddr_un = undefined;
    @memset(@as([*]u8, @ptrCast(&addr))[0..@sizeOf(c.struct_sockaddr_un)], 0);
    addr.sun_family = c.AF_UNIX;

    // Autobind - kernel chooses unique socket name
    const want_autobind: c.socklen_t = @sizeOf(c.sa_family_t);
    if (c.bind(fd, @ptrCast(&addr), want_autobind) < 0) {
        std.log.err("bind: {s}", .{c.strerror(c.__errno_location().*)});
        _ = c.close(fd);
        return error.BindError;
    }

    // Get assigned name
    var tmp: c.struct_sockaddr_un = undefined;
    var addrlen: c.socklen_t = @sizeOf(c.struct_sockaddr_un);
    if (c.getsockname(fd, @ptrCast(&tmp), &addrlen) < 0) {
        std.log.err("getsockname: {s}", .{c.strerror(c.__errno_location().*)});
        _ = c.close(fd);
        return error.SocketError;
    }

    config.logger_namelen = addrlen - @sizeOf(c.sa_family_t);
    @memcpy(config.logger_socket[0..config.logger_namelen], tmp.sun_path[0..config.logger_namelen]);

    if (c.listen(fd, 5) == -1) {
        std.log.err("listen: {s}", .{c.strerror(c.__errno_location().*)});
        _ = c.close(fd);
        return error.ListenError;
    }

    config.logger_fd = fd;
}

/// Start logger subprocess
fn startLogger(config: *Config) !posix.pid_t {
    const pid = c.fork();

    if (pid == -1) {
        std.log.err("fork: {s}", .{c.strerror(c.__errno_location().*)});
        return error.ForkError;
    }

    // Parent closes logger socket
    if (pid > 0) {
        if (config.logger_fd != -1) {
            _ = c.close(config.logger_fd);
            config.logger_fd = -1;
        }
        return pid;
    }

    // Child
    _ = c.prctl(c.PR_SET_NAME, "pmtr-log", @as(c_ulong, 0), @as(c_ulong, 0), @as(c_ulong, 0));

    // Close sockets
    for (config.listen.items) |sock| {
        posix.close(sock.fd);
    }
    for (config.report.items) |sock| {
        posix.close(sock.fd);
    }

    // Request HUP on parent exit
    _ = c.signal(c.SIGHUP, c.SIG_DFL);
    _ = c.prctl(c.PR_SET_PDEATHSIG, c.SIGHUP, @as(c_ulong, 0), @as(c_ulong, 0), @as(c_ulong, 0));

    var hup: c.sigset_t = undefined;
    _ = c.sigemptyset(&hup);
    _ = c.sigaddset(&hup, c.SIGHUP);
    _ = c.sigprocmask(c.SIG_UNBLOCK, &hup, null);

    // Set up epoll
    const epoll_fd = c.epoll_create(1);
    if (epoll_fd == -1) {
        std.log.err("epoll: {s}", .{c.strerror(c.__errno_location().*)});
        c.exit(255);
    }

    // Add logger socket to epoll
    var ev: c.struct_epoll_event = undefined;
    ev.events = c.EPOLLIN;
    ev.data.fd = config.logger_fd;
    if (c.epoll_ctl(epoll_fd, c.EPOLL_CTL_ADD, config.logger_fd, &ev) < 0) {
        std.log.err("epoll_ctl: {s}", .{c.strerror(c.__errno_location().*)});
        c.exit(255);
    }

    // Logger event loop
    var buf: [1000]u8 = undefined;
    while (c.epoll_wait(epoll_fd, &ev, 1, -1) > 0) {
        if (ev.data.fd == config.logger_fd) {
            // New client connect
            const fd = c.accept(config.logger_fd, null, null);
            if (fd < 0) {
                std.log.err("accept: {s}", .{c.strerror(c.__errno_location().*)});
                c.exit(255);
            }

            ev.events = c.EPOLLIN;
            ev.data.fd = fd;
            if (c.epoll_ctl(epoll_fd, c.EPOLL_CTL_ADD, fd, &ev) < 0) {
                std.log.err("epoll_ctl: {s}", .{c.strerror(c.__errno_location().*)});
                c.exit(255);
            }
        } else {
            // Handle input from connected client
            const nr = c.read(ev.data.fd, &buf, buf.len);
            if (nr < 0) {
                std.log.err("read: {s}", .{c.strerror(c.__errno_location().*)});
                c.exit(255);
            } else if (nr == 0) {
                _ = c.close(ev.data.fd);
            } else {
                // Log the output
                const data = buf[0..@intCast(nr)];
                var lines = std.mem.splitAny(u8, data, "\n");
                while (lines.next()) |line| {
                    if (line.len > 0) {
                        c.syslog(c.LOG_DAEMON | c.LOG_INFO, "%.*s", @as(c_int, @intCast(line.len)), line.ptr);
                    }
                }
            }
        }
    }

    std.log.err("pmtr-log: error, terminating", .{});
    c.exit(255);
}

/// Rescan configuration file
fn rescanConfig(config: *Config, allocator: std.mem.Allocator) void {
    std.log.info("rescanning job configuration", .{});

    // Save previous jobs
    const previous_jobs = config.jobs;
    config.jobs = std.ArrayList(Job).init(allocator);

    // Close and reopen sockets
    net.closeSockets(config);

    // Parse new config
    config_parser.parseFile(allocator, config.file, config) catch |err| {
        std.log.err("FAILED to parse {s}: {}", .{ config.file, err });
        std.log.err("NOTE: using PREVIOUS job config", .{});

        // Restore previous jobs
        for (config.jobs.items) |*j| j.deinit();
        config.jobs.deinit();
        config.jobs = previous_jobs;
        return;
    };

    // Diff new jobs vs existing
    for (config.jobs.items) |*new_job| {
        for (previous_jobs.items) |*old| {
            if (new_job.name != null and old.name != null and std.mem.eql(u8, new_job.name.?, old.name.?)) {
                if (new_job.eql(old)) {
                    // Identical - copy runtime state
                    new_job.deinit();
                    new_job.* = old.clone(allocator) catch continue;
                } else {
                    // Changed - keep pid but mark for restart
                    new_job.start_ts = old.start_ts;
                    new_job.pid = old.pid;
                    if (new_job.pid != 0) new_job.terminate = 1;
                }
                break;
            }
        }
    }

    // Jobs removed from config
    for (previous_jobs.items) |*old| {
        var found = false;
        for (config.jobs.items) |*new_job| {
            if (new_job.name != null and old.name != null and std.mem.eql(u8, new_job.name.?, old.name.?)) {
                found = true;
                break;
            }
        }
        if (!found and old.pid != 0) {
            // Keep old job until it exits
            old.terminate = 1;
            old.respawn = false;
            old.delete_when_collected = true;
            config.jobs.append(old.clone(allocator) catch continue) catch continue;
        }
    }

    // Clean up previous jobs
    for (previous_jobs.items) |*j| j.deinit();
    var prev_jobs = previous_jobs;
    prev_jobs.deinit();
}

/// Create pidfile
fn makePidfile(config: *Config) !void {
    const pidfile = config.pidfile orelse return;

    const file = std.fs.cwd().createFile(pidfile, .{ .mode = 0o644 }) catch |err| {
        std.log.err("can't open {s}: {}", .{ pidfile, err });
        return err;
    };
    defer file.close();

    const pid = c.getpid();
    file.writer().print("{d}\n", .{pid}) catch |err| {
        std.log.err("can't write to {s}: {}", .{ pidfile, err });
        std.fs.cwd().deleteFile(pidfile) catch {};
        return err;
    };
}

/// Ensure config file exists (create empty if not)
fn instantiateCfgFile(config: *Config) !void {
    std.fs.cwd().access(config.file, .{}) catch |err| {
        if (err == error.FileNotFound) {
            std.log.info("creating empty {s}", .{config.file});
            const file = std.fs.cwd().createFile(config.file, .{ .mode = 0o600 }) catch |e| {
                std.log.err("can't create {s}: {}", .{ config.file, e });
                return e;
            };
            file.close();
            return;
        }
        return err;
    };
}

pub fn main() !void {
    const allocator = gpa.allocator();

    var config_file: []const u8 = types.DEFAULT_PMTR_CONFIG;
    var pidfile: ?[]const u8 = null;
    var verbose: u32 = 0;
    var foreground = false;
    var test_only = false;

    // Parse command line arguments
    var args = std.process.args();
    const prog = args.next() orelse "pmtr";

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "-v")) {
            verbose += 1;
        } else if (std.mem.eql(u8, arg, "-F")) {
            foreground = true;
        } else if (std.mem.eql(u8, arg, "-t")) {
            test_only = true;
            foreground = true;
        } else if (std.mem.eql(u8, arg, "-c")) {
            config_file = args.next() orelse usage(prog);
        } else if (std.mem.eql(u8, arg, "-p")) {
            pidfile = args.next() orelse usage(prog);
        } else if (std.mem.eql(u8, arg, "-h")) {
            usage(prog);
        } else {
            usage(prog);
        }
    }

    // As container main process, stay in foreground
    if (c.getpid() == 1) foreground = true;

    // Open syslog
    var log_opt: c_int = c.LOG_PID;
    if (c.isatty(c.STDERR_FILENO) != 0) log_opt |= c.LOG_PERROR;
    c.openlog("pmtr", log_opt, c.LOG_LOCAL0);

    // Daemonize if not foreground
    if (!foreground) {
        const pid = c.fork();
        if (pid != 0) c._exit(0);
        _ = c.setsid();
        _ = c.close(c.STDIN_FILENO);
        _ = c.close(c.STDOUT_FILENO);
        _ = c.close(c.STDERR_FILENO);
    }

    // Block all signals
    var all: c.sigset_t = undefined;
    _ = c.sigfillset(&all);
    _ = c.sigprocmask(c.SIG_SETMASK, &all, null);

    // Initialize config
    var config = Config.init(allocator, config_file);
    defer config.deinit();
    config.verbose = verbose;
    config.foreground = foreground;
    config.test_only = test_only;
    if (pidfile) |pf| {
        config.pidfile = try allocator.dupe(u8, pf);
    }

    global_config = &config;

    // Create pidfile
    try makePidfile(&config);
    _ = c.umask(0);

    // Ensure config file exists
    try instantiateCfgFile(&config);

    // Parse config
    config_parser.parseFile(allocator, config.file, &config) catch |err| {
        std.log.err("parse failed: {}", .{err});
        return;
    };

    if (test_only) return;

    std.log.info("pmtr: starting", .{});

    // Set up signal mask for sigsuspend
    var ss: c.sigset_t = undefined;
    _ = c.sigfillset(&ss);
    for (job_mgmt.handled_signals) |sig| {
        _ = c.sigdelset(&ss, sig);
    }

    // Set up signal handlers
    var sa: c.struct_sigaction = undefined;
    sa.__sigaction_handler.sa_handler = sighandler;
    sa.sa_flags = 0;
    _ = c.sigfillset(&sa.sa_mask);
    for (job_mgmt.handled_signals) |sig| {
        _ = c.sigaction(sig, &sa, null);
    }

    // Main event loop - sigsetjmp returns here on signal
    const signo = c.sigsetjmp(&global_jmp, 1);

    switch (signo) {
        0 => {
            // Initial setup
            setupLogger(&config) catch return;
            config.logger_pid = startLogger(&config) catch return;
            job_mgmt.doJobs(&config, allocator) catch {};
            config.dm_pid = job_mgmt.depMonitor(&config, allocator) catch 0;
            net.reportStatus(&config, allocator) catch {};
            job_mgmt.alarmWithin(&config, types.SHORT_DELAY);
        },
        c.SIGHUP => {
            rescanConfig(&config, allocator);
            job_mgmt.doJobs(&config, allocator) catch {};
        },
        c.SIGCHLD => {
            job_mgmt.collectJobs(&config, allocator);
            job_mgmt.doJobs(&config, allocator) catch {};
        },
        c.SIGALRM => {
            job_mgmt.doJobs(&config, allocator) catch {};
            net.reportStatus(&config, allocator) catch {};
            job_mgmt.alarmWithin(&config, types.SHORT_DELAY);
        },
        c.SIGIO => {
            net.serviceSocket(&config);
            job_mgmt.doJobs(&config, allocator) catch {};
        },
        else => {
            std.log.info("pmtr: exiting on signal {d}", .{signo});
            // Graceful shutdown
            job_mgmt.termJobs(&config);
            job_mgmt.doJobs(&config, allocator) catch {};
            std.time.sleep(500 * std.time.ns_per_ms);
            job_mgmt.collectJobs(&config, allocator);
            net.closeSockets(&config);
            if (config.pidfile) |pf| {
                std.fs.cwd().deleteFile(pf) catch {};
            }
            return;
        },
    }

    // Wait for signals
    _ = c.sigsuspend(&ss);

    // Should never reach here (siglongjmp jumps back to sigsetjmp)
    unreachable;
}

// Re-export tests from submodules
test {
    _ = @import("types.zig");
    _ = @import("tokenizer.zig");
    _ = @import("config.zig");
}
