const std = @import("std");
const posix = std.posix;
const types = @import("types.zig");
const Config = types.Config;
const Job = types.Job;

const c = @cImport({
    // Define _GNU_SOURCE to get sched_setaffinity and cpu_set_t
    @cDefine("_GNU_SOURCE", {});
    @cInclude("sys/resource.h");
    @cInclude("sys/prctl.h");
    @cInclude("sys/socket.h");
    @cInclude("sys/un.h");
    @cInclude("sys/inotify.h");
    @cInclude("sys/wait.h");
    @cInclude("pwd.h");
    @cInclude("grp.h");
    @cInclude("sched.h");
    @cInclude("syslog.h");
    @cInclude("unistd.h");
    @cInclude("signal.h");
    @cInclude("fcntl.h");
    @cInclude("errno.h");
    @cInclude("string.h");
    @cInclude("stdlib.h");
});

/// Signals that we handle
pub const handled_signals = [_]u6{
    posix.SIG.HUP,
    posix.SIG.CHLD,
    posix.SIG.TERM,
    posix.SIG.INT,
    posix.SIG.QUIT,
    posix.SIG.ALRM,
    posix.SIG.USR1,
    posix.SIG.IO,
};

/// Run jobs - start any that should be running, signal any that should terminate
pub fn doJobs(config: *Config, allocator: std.mem.Allocator) !void {
    const now = std.time.timestamp();

    for (config.jobs.items) |*job| {
        // Handle bounce interval - force restart if running too long
        if (job.bounce_interval > 0 and job.pid != 0) {
            const elapsed = now - job.start_ts;
            if (elapsed >= job.bounce_interval) {
                if (job.terminate == 0) job.terminate = 1;
            }
        }

        // Signal jobs that need to terminate
        if (job.terminate != 0) {
            try signalJob(job);
            continue;
        }

        // Skip disabled jobs
        if (job.disabled) continue;

        // Skip jobs already running
        if (job.pid != 0) continue;

        // Skip jobs that shouldn't respawn
        if (!job.respawn) continue;

        // Check if we should delay the start
        if (job.start_at > now) {
            alarmWithin(config, @intCast(job.start_at - now));
            continue;
        }

        // Fork and start the job
        try forkJob(config, job, allocator);
    }
}

fn signalJob(job: *Job) !void {
    const now = std.time.timestamp();

    if (job.pid == 0) return;

    switch (job.terminate) {
        0 => {}, // Should not be here
        1 => {
            // Initial termination request - send SIGTERM
            std.log.info("sending SIGTERM to job {?s} [{d}]", .{ job.name, job.pid });
            _ = c.kill(job.pid, c.SIGTERM);
            job.terminate = now + types.SHORT_DELAY; // Time to wait before SIGKILL
        },
        else => {
            // Job didn't exit, use stronger signal if time has elapsed
            if (job.terminate > now) return;
            std.log.info("sending SIGKILL to job {?s} [{d}]", .{ job.name, job.pid });
            _ = c.kill(job.pid, c.SIGKILL);
            job.terminate = 0; // Don't repeatedly signal
        },
    }
}

fn forkJob(config: *Config, job: *Job, allocator: std.mem.Allocator) !void {
    const pid = c.fork();

    if (pid == -1) {
        std.log.err("fork error", .{});
        _ = c.kill(c.getpid(), 15); // Induce graceful shutdown
        return error.ForkFailed;
    }

    if (pid > 0) {
        // Parent
        job.pid = pid;
        job.start_ts = std.time.timestamp();
        std.log.info("started job {?s} [{d}]", .{ job.name, job.pid });

        // Support the 'wait' feature which blocks for a job to finish
        if (job.wait) {
            std.log.info("pausing for job {?s} to finish", .{job.name});
            var status: c_int = 0;
            _ = c.waitpid(job.pid, &status, 0);
            std.log.info("job {?s} finished", .{job.name});

            if (c.WIFEXITED(status)) {
                const exit_status = c.WEXITSTATUS(status);
                if (exit_status == types.PMTR_NO_RESTART) {
                    job.respawn = false;
                }
            }
            if (job.once) job.respawn = false;
            job.pid = 0;
        }
        return;
    }

    // Child process
    childProcess(config, job, allocator);
}

fn childProcess(config: *Config, job: *Job, allocator: std.mem.Allocator) noreturn {
    var rc: i32 = 0;

    // Setup working directory
    if (job.dir) |dir| {
        const dir_z = allocator.dupeZ(u8, dir) catch {
            rc = -1;
            exitWithError(rc, job);
        };
        if (c.chdir(dir_z.ptr) == -1) {
            rc = -1;
            exitWithError(rc, job);
        }
    }

    // Close syslog
    c.closelog();

    // Set environment variables
    for (job.envv.items) |env| {
        const env_z = allocator.dupeZ(u8, env) catch continue;
        _ = c.putenv(@ptrCast(env_z.ptr));
    }

    // Set process priority / nice
    if (c.setpriority(c.PRIO_PROCESS, 0, job.nice) < 0) {
        rc = -5;
        exitWithError(rc, job);
    }

    // Set CPU affinity
    if (job.cpuset.count() > 0) {
        var cpu_set: c.cpu_set_t = undefined;
        // Zero the cpu_set manually (CPU_ZERO_S equivalent)
        @memset(@as([*]u8, @ptrCast(&cpu_set))[0..@sizeOf(c.cpu_set_t)], 0);
        // Set bits for each CPU (CPU_SET_S equivalent)
        for (0..1024) |cpu| {
            if (job.cpuset.isSet(cpu)) {
                const word_idx = cpu / @bitSizeOf(c_ulong);
                const bit_idx: u6 = @intCast(cpu % @bitSizeOf(c_ulong));
                cpu_set.__bits[word_idx] |= @as(c_ulong, 1) << bit_idx;
            }
        }
        if (c.sched_setaffinity(0, @sizeOf(c.cpu_set_t), &cpu_set) != 0) {
            rc = -12;
            exitWithError(rc, job);
        }
    }

    // Set resource limits
    for (job.rlim.items) |rlim| {
        var new_limit: c.struct_rlimit = .{
            .rlim_cur = rlim.rlim_cur,
            .rlim_max = rlim.rlim_max,
        };
        if (c.setrlimit(@as(c_uint, @intCast(@intFromEnum(rlim.id))), &new_limit) != 0) {
            rc = -6;
            exitWithError(rc, job);
        }
    }

    // Restore default signal handlers
    for (handled_signals) |sig| {
        _ = c.signal(sig, c.SIG_DFL);
    }
    var none: c.sigset_t = undefined;
    _ = c.sigemptyset(&none);
    _ = c.sigprocmask(c.SIG_SETMASK, &none, null);

    // Change user if specified
    if (job.getUserName()) |username| {
        const username_z = allocator.dupeZ(u8, username) catch {
            rc = -7;
            exitWithError(rc, job);
        };
        const pw = c.getpwnam(username_z.ptr);
        if (pw == null) {
            rc = -7;
            exitWithError(rc, job);
        }
        if (c.setgid(pw.*.pw_gid) == -1) {
            rc = -8;
            exitWithError(rc, job);
        }
        if (c.initgroups(username_z.ptr, pw.*.pw_gid) == -1) {
            rc = -9;
            exitWithError(rc, job);
        }
        if (c.setuid(pw.*.pw_uid) == -1) {
            rc = -10;
            exitWithError(rc, job);
        }
    }

    // Set up redirections
    const in_file = job.in orelse "/dev/null";
    const out_file = job.out orelse "syslog";
    const err_file = job.err orelse "syslog";

    if (redirect(config, 0, in_file, c.O_RDONLY, 0, allocator) < 0) {
        rc = -2;
        exitWithError(rc, job);
    }
    if (redirect(config, 1, out_file, c.O_WRONLY | c.O_CREAT | c.O_APPEND, 0o644, allocator) < 0) {
        rc = -3;
        exitWithError(rc, job);
    }
    if (redirect(config, 2, err_file, c.O_WRONLY | c.O_CREAT | c.O_APPEND, 0o644, allocator) < 0) {
        rc = -4;
        exitWithError(rc, job);
    }

    // Build argv for execv
    if (job.cmdv.items.len == 0) {
        rc = -11;
        exitWithError(rc, job);
    }

    // Create null-terminated argv array
    var argv: [256:null]?[*:0]const u8 = undefined;
    for (job.cmdv.items, 0..) |arg, i| {
        if (i >= 255) break;
        argv[i] = (allocator.dupeZ(u8, arg) catch {
            rc = -11;
            exitWithError(rc, job);
        }).ptr;
    }
    argv[job.cmdv.items.len] = null;

    // Execute
    const pathname = argv[0].?;
    _ = c.execv(pathname, @ptrCast(&argv));

    // If we get here, exec failed
    rc = -11;
    exitWithError(rc, job);
}

fn redirect(config: *Config, fileno: c_int, filename: []const u8, flags: c_int, mode: c_uint, allocator: std.mem.Allocator) c_int {
    // Handle syslog redirect
    if (std.mem.eql(u8, filename, "syslog")) {
        return loggerOn(config, fileno);
    }

    // Regular file
    const filename_z = allocator.dupeZ(u8, filename) catch return -1;
    const fd = c.open(filename_z.ptr, flags, mode);
    if (fd < 0) return -1;

    if (fd != fileno) {
        if (c.dup2(fd, fileno) < 0) {
            _ = c.close(fd);
            return -1;
        }
        _ = c.close(fd);
    }

    return 0;
}

fn loggerOn(config: *Config, dst_fd: c_int) c_int {
    const fd = c.socket(c.AF_UNIX, c.SOCK_STREAM, 0);
    if (fd == -1) return -1;

    var addr: c.struct_sockaddr_un = undefined;
    @memset(@as([*]u8, @ptrCast(&addr))[0..@sizeOf(c.struct_sockaddr_un)], 0);
    addr.sun_family = c.AF_UNIX;

    if (config.logger_namelen == 0) return -1;
    @memcpy(addr.sun_path[0..config.logger_namelen], config.logger_socket[0..config.logger_namelen]);

    const len = @sizeOf(c.sa_family_t) + config.logger_namelen;
    const sockaddr_arg: c.__CONST_SOCKADDR_ARG = .{ .__sockaddr__ = @ptrCast(&addr) };
    if (c.connect(fd, sockaddr_arg, @intCast(len)) == -1) {
        _ = c.close(fd);
        return -1;
    }

    if (fd != dst_fd) {
        if (c.dup2(fd, dst_fd) < 0) {
            _ = c.close(fd);
            return -1;
        }
        _ = c.close(fd);
    }

    return 0;
}

fn exitWithError(rc: i32, job: *Job) noreturn {
    const err_msg = switch (rc) {
        -1 => "can't chdir",
        -2 => "can't open/dup stdin",
        -3 => "can't open/dup stdout",
        -4 => "can't open/dup stderr",
        -5 => "can't setpriority",
        -6 => "can't setrlimit",
        -7 => "unknown user",
        -8 => "can't setgid",
        -9 => "can't initgroups",
        -10 => "can't setuid",
        -11 => "can't exec",
        -12 => "can't set cpu affinity",
        else => "unknown error",
    };
    std.log.err("{s}: {?s}", .{ err_msg, job.name });
    c.exit(255);
}

/// Collect exited child processes
pub fn collectJobs(config: *Config, allocator: std.mem.Allocator) void {
    while (true) {
        var status: c_int = 0;
        const pid = c.waitpid(-1, &status, c.WNOHANG);

        if (pid <= 0) break;

        // Check if it's the dependency monitor
        if (pid == config.dm_pid) {
            if (c.WIFEXITED(status)) {
                const exit_status = c.WEXITSTATUS(status);
                if (exit_status == types.PMTR_NO_RESTART) {
                    std.log.info("inotify-based dependency monitoring disabled", .{});
                    config.dm_pid = 0;
                    continue;
                }
            }
            // Respawn dependency monitor
            config.dm_pid = depMonitor(config, allocator) catch 0;
            continue;
        }

        // Check if it's the logger subprocess
        if (pid == config.logger_pid) {
            _ = c.kill(c.getpid(), 15); // Induce graceful shutdown
            continue;
        }

        // Find the job
        const job = config.getJobByPid(pid) orelse {
            std.log.err("sigchld for unknown pid {d}", .{pid});
            continue;
        };

        // Reset job state
        job.pid = 0;
        job.terminate = 0;

        const now = std.time.timestamp();
        const elapsed = now - job.start_ts;

        // Rate limit restarts
        job.start_at = if (elapsed < types.SHORT_DELAY) (now + types.SHORT_DELAY) else now;

        if (job.once) job.respawn = false;

        // Log exit info
        if (c.WIFSIGNALED(status)) {
            std.log.info("job {?s} [{d}] exited after {d} sec: signal {d}", .{ job.name, pid, elapsed, c.WTERMSIG(status) });
        }
        if (c.WIFEXITED(status)) {
            const exit_status = c.WEXITSTATUS(status);
            if (exit_status == types.PMTR_NO_RESTART) job.respawn = false;
            std.log.info("job {?s} [{d}] exited after {d} sec: exit status {d}", .{ job.name, pid, elapsed, exit_status });
        }

        // Delete job if it was removed from config
        if (job.delete_when_collected) {
            // Find and remove from jobs list
            for (config.jobs.items, 0..) |*j, i| {
                if (j.pid == 0 and j.delete_when_collected and std.mem.eql(u8, j.name orelse "", job.name orelse "")) {
                    j.deinit();
                    _ = config.jobs.orderedRemove(i);
                    break;
                }
            }
        }
    }
}

/// Set termination flags on all jobs
pub fn termJobs(config: *Config) void {
    for (config.jobs.items) |*job| {
        if (job.pid == 0) continue;
        if (job.terminate == 0) job.terminate = 1;
    }
}

/// Schedule an alarm within the specified number of seconds
pub fn alarmWithin(config: *Config, sec: i64) void {
    const now = std.time.timestamp();
    var reset = false;

    if (config.next_alarm == 0) reset = true;
    if (config.next_alarm <= now) reset = true;
    if (config.next_alarm > now + sec) reset = true;

    if (!reset) {
        _ = c.alarm(@intCast(config.next_alarm - now));
        return;
    }

    const sec_u: c_uint = if (sec == 0) 1 else @intCast(sec);
    config.next_alarm = now + sec;
    _ = c.alarm(sec_u);
}

/// Fork a dependency monitor subprocess
pub fn depMonitor(config: *Config, allocator: std.mem.Allocator) !posix.pid_t {
    _ = allocator;
    const pid = c.fork();

    if (pid == -1) {
        std.log.err("fork: {s}", .{c.strerror(c.__errno_location().*)});
        return error.ForkFailed;
    }

    if (pid > 0) return pid;

    // Child process
    _ = c.prctl(c.PR_SET_NAME, "pmtr-dep", @as(c_ulong, 0), @as(c_ulong, 0), @as(c_ulong, 0));

    // Close sockets
    for (config.listen.items) |sock| {
        posix.close(sock.fd);
    }
    for (config.report.items) |sock| {
        posix.close(sock.fd);
    }

    // Set up inotify
    const ifd = c.inotify_init();
    if (ifd == -1) {
        std.log.err("inotify_init: {s}", .{c.strerror(c.__errno_location().*)});
        // Log if any jobs have dependencies
        for (config.jobs.items) |*job| {
            if (!job.disabled and job.depv.items.len > 0) {
                std.log.err("job {?s}: dependency watching disabled", .{job.name});
            }
        }
        c.exit(types.PMTR_NO_RESTART);
    }

    // Watch config file
    const file_z = std.heap.c_allocator.dupeZ(u8, config.file) catch c.exit(255);
    const wd = c.inotify_add_watch(ifd, file_z, c.IN_CLOSE_WRITE);
    if (wd == -1) {
        std.log.err("can't watch {s}: {s}", .{ config.file, c.strerror(c.__errno_location().*) });
        std.time.sleep(@as(u64, types.SHORT_DELAY) * std.time.ns_per_s);
        c.exit(255);
    }

    // Watch job dependencies
    for (config.jobs.items) |*job| {
        if (job.disabled) continue;
        for (job.depv.items) |dep| {
            const dep_z = std.heap.c_allocator.dupeZ(u8, dep) catch continue;
            const dwd = c.inotify_add_watch(ifd, dep_z, c.IN_CLOSE_WRITE);
            if (dwd == -1) {
                std.log.err("can't watch {s}: {s}", .{ dep, c.strerror(c.__errno_location().*) });
            }
        }
    }

    // Request HUP on parent exit
    _ = c.signal(c.SIGHUP, c.SIG_DFL);
    _ = c.prctl(c.PR_SET_PDEATHSIG, c.SIGHUP, @as(c_ulong, 0), @as(c_ulong, 0), @as(c_ulong, 0));

    var hup: c.sigset_t = undefined;
    _ = c.sigemptyset(&hup);
    _ = c.sigaddset(&hup, c.SIGHUP);
    _ = c.sigprocmask(c.SIG_UNBLOCK, &hup, null);

    // Wait for inotify event
    var buf: [4096]u8 = undefined;
    _ = posix.read(@intCast(ifd), &buf) catch {};

    // Small delay then signal parent
    std.time.sleep(500 * std.time.ns_per_ms);
    _ = c.kill(c.getppid(), c.SIGHUP);

    c.exit(0);
}

/// Hash the contents of dependency files
pub fn hashDeps(config: *Config, allocator: std.mem.Allocator) void {
    for (config.jobs.items) |*job| {
        job.deps_hash = 0;

        for (job.depv.items) |dep| {
            const path = fpath(job, dep, allocator) orelse continue;
            const file = std.fs.cwd().openFile(path, .{}) catch {
                std.log.err("job {?s}: can't open dependency {s}", .{ job.name, dep });
                job.disabled = true;
                if (job.pid != 0) job.terminate = 1;
                continue;
            };
            defer file.close();

            const content = file.readToEndAlloc(allocator, 10 * 1024 * 1024) catch continue;
            defer allocator.free(content);

            for (content) |byte| {
                job.deps_hash = job.deps_hash *% 33 +% @as(i32, byte);
            }
        }
    }
}

/// Resolve a relative path using job's working directory
fn fpath(job: *Job, file: []const u8, allocator: std.mem.Allocator) ?[]const u8 {
    if (file.len > 0 and file[0] == '/') return file;
    const dir = job.dir orelse return file;

    return std.fmt.allocPrint(allocator, "{s}/{s}", .{ dir, file }) catch null;
}
