//! onconnect - Accept TCP connections and fork a subprocess to handle each one
//!
//! This utility monitors for new client connections using epoll. When a client
//! connects, it accepts the connection and forks a subprocess to handle it.
//! The subprocess receives the connection on file descriptor 3.

const std = @import("std");
const posix = std.posix;

const c = @cImport({
    @cInclude("sys/signalfd.h");
    @cInclude("sys/socket.h");
    @cInclude("sys/epoll.h");
    @cInclude("sys/wait.h");
    @cInclude("netinet/in.h");
    @cInclude("arpa/inet.h");
    @cInclude("signal.h");
    @cInclude("unistd.h");
    @cInclude("fcntl.h");
    @cInclude("errno.h");
    @cInclude("string.h");
    @cInclude("stdio.h");
    @cInclude("stdlib.h");
});

const Config = struct {
    addr: u32 = c.INADDR_ANY,
    port: u16 = 0,
    listener_fd: posix.fd_t = -1,
    signal_fd: posix.fd_t = -1,
    epoll_fd: posix.fd_t = -1,
    verbose: bool = false,
    ticks: u32 = 0,
    subprocess_argv: []const [:0]const u8 = &.{},
};

var cfg: Config = .{};

fn usage(prog: []const u8) noreturn {
    const stderr = std.io.getStdErr().writer();
    stderr.print("usage: {s} [-v] [-a <ip>] -p <port> -- <command> [args...]\n", .{prog}) catch {};
    c.exit(255);
}

fn addEpoll(events: u32, fd: posix.fd_t) !void {
    var ev: c.struct_epoll_event = undefined;
    ev.events = events;
    ev.data.fd = fd;
    if (cfg.verbose) {
        std.debug.print("adding fd {d} to epoll\n", .{fd});
    }
    if (c.epoll_ctl(cfg.epoll_fd, c.EPOLL_CTL_ADD, fd, &ev) == -1) {
        std.debug.print("epoll_ctl: {s}\n", .{c.strerror(c.__errno_location().*)});
        return error.EpollError;
    }
}

fn setupListener() !void {
    const fd = c.socket(c.AF_INET, c.SOCK_STREAM, 0);
    if (fd == -1) {
        std.debug.print("socket: {s}\n", .{c.strerror(c.__errno_location().*)});
        return error.SocketError;
    }

    var sin: c.struct_sockaddr_in = undefined;
    sin.sin_family = c.AF_INET;
    sin.sin_addr.s_addr = cfg.addr;
    sin.sin_port = c.htons(cfg.port);

    var one: c_int = 1;
    _ = c.setsockopt(fd, c.SOL_SOCKET, c.SO_REUSEADDR, &one, @sizeOf(c_int));

    if (c.bind(fd, @ptrCast(&sin), @sizeOf(c.struct_sockaddr_in)) == -1) {
        std.debug.print("bind: {s}\n", .{c.strerror(c.__errno_location().*)});
        _ = c.close(fd);
        return error.BindError;
    }

    if (c.listen(fd, 1) == -1) {
        std.debug.print("listen: {s}\n", .{c.strerror(c.__errno_location().*)});
        _ = c.close(fd);
        return error.ListenError;
    }

    cfg.listener_fd = fd;
}

fn acceptClient(allocator: std.mem.Allocator) !void {
    var sin: c.struct_sockaddr_in = undefined;
    var sz: c.socklen_t = @sizeOf(c.struct_sockaddr_in);

    const fd = c.accept(cfg.listener_fd, @ptrCast(&sin), &sz);
    if (fd == -1) {
        std.debug.print("accept: {s}\n", .{c.strerror(c.__errno_location().*)});
        return error.AcceptError;
    }

    if (cfg.verbose and sz == @sizeOf(c.struct_sockaddr_in)) {
        var addr_buf: [c.INET_ADDRSTRLEN]u8 = undefined;
        const addr_str = c.inet_ntop(c.AF_INET, &sin.sin_addr, &addr_buf, c.INET_ADDRSTRLEN);
        const addr_slice = if (addr_str) |ptr| std.mem.span(ptr) else "unknown";
        std.debug.print("connection fd {d} from {s}:{d}\n", .{
            fd,
            addr_slice,
            c.ntohs(sin.sin_port),
        });
    }

    // Fork subprocess
    const pid = c.fork();

    if (pid == -1) {
        std.debug.print("fork: {s}\n", .{c.strerror(c.__errno_location().*)});
        _ = c.close(fd);
        return error.ForkError;
    }

    if (pid > 0) {
        // Parent
        _ = c.close(fd);
        std.debug.print("forked pid {d}\n", .{pid});
        return;
    }

    // Child
    _ = c.close(cfg.listener_fd);
    _ = c.close(cfg.signal_fd);
    _ = c.close(cfg.epoll_fd);

    // Make the new connection fd 3
    if (fd != c.STDERR_FILENO + 1) {
        if (c.dup2(fd, c.STDERR_FILENO + 1) < 0) {
            std.debug.print("dup2: {s}\n", .{c.strerror(c.__errno_location().*)});
            c.exit(255);
        }
        _ = c.close(fd);
    }

    // Restore default signal handlers
    const sigs = [_]c_int{ c.SIGIO, c.SIGHUP, c.SIGTERM, c.SIGINT, c.SIGQUIT, c.SIGALRM, c.SIGCHLD };
    for (sigs) |sig| {
        _ = c.signal(sig, c.SIG_DFL);
    }

    var none: c.sigset_t = undefined;
    _ = c.sigemptyset(&none);
    _ = c.sigprocmask(c.SIG_SETMASK, &none, null);

    // Build argv for execv
    if (cfg.subprocess_argv.len == 0) {
        std.debug.print("no subprocess specified\n", .{});
        c.exit(255);
    }

    var argv: [256:null]?[*:0]const u8 = undefined;
    for (cfg.subprocess_argv, 0..) |arg, i| {
        if (i >= 255) break;
        argv[i] = arg.ptr;
    }
    argv[cfg.subprocess_argv.len] = null;

    _ = c.execv(argv[0].?, @ptrCast(&argv));
    std.debug.print("execv: {s}\n", .{c.strerror(c.__errno_location().*)});
    c.exit(255);

    _ = allocator;
}

fn handleSignal() !void {
    var info: c.struct_signalfd_siginfo = undefined;

    const nr = c.read(cfg.signal_fd, &info, @sizeOf(c.struct_signalfd_siginfo));
    if (nr != @sizeOf(c.struct_signalfd_siginfo)) {
        std.debug.print("failed to read signal fd buffer\n", .{});
        return error.SignalError;
    }

    switch (info.ssi_signo) {
        c.SIGALRM => {
            cfg.ticks += 1;
            if (cfg.ticks % 10 == 0 and cfg.verbose) {
                std.debug.print("up {d} seconds\n", .{cfg.ticks});
            }
            _ = c.alarm(1);
        },
        c.SIGCHLD => {
            // Collect children to avoid zombies
            while (true) {
                var es: c_int = 0;
                const pid = c.waitpid(-1, &es, c.WNOHANG);
                if (pid <= 0) break;

                if (c.WIFSIGNALED(es)) {
                    std.debug.print("pid {d} exited: signal {d}\n", .{ pid, c.WTERMSIG(es) });
                }
                if (c.WIFEXITED(es)) {
                    std.debug.print("pid {d} exited: status {d}\n", .{ pid, c.WEXITSTATUS(es) });
                }
            }
        },
        else => {
            std.debug.print("got signal {d}\n", .{info.ssi_signo});
            return error.SignalExit;
        },
    }
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    var args = std.process.args();
    const prog = args.next() orelse "onconnect";

    var subprocess_args = std.ArrayList([:0]const u8).init(allocator);
    defer subprocess_args.deinit();

    var parsing_subprocess = false;

    while (args.next()) |arg| {
        if (parsing_subprocess) {
            const arg_z = try allocator.dupeZ(u8, arg);
            try subprocess_args.append(arg_z);
        } else if (std.mem.eql(u8, arg, "-v")) {
            cfg.verbose = true;
        } else if (std.mem.eql(u8, arg, "-p")) {
            const port_str = args.next() orelse usage(prog);
            cfg.port = std.fmt.parseInt(u16, port_str, 10) catch usage(prog);
        } else if (std.mem.eql(u8, arg, "-a")) {
            const addr_str = args.next() orelse usage(prog);
            const addr_z = try allocator.dupeZ(u8, addr_str);
            cfg.addr = c.inet_addr(addr_z.ptr);
        } else if (std.mem.eql(u8, arg, "--")) {
            parsing_subprocess = true;
        } else if (std.mem.eql(u8, arg, "-h")) {
            usage(prog);
        } else {
            usage(prog);
        }
    }

    if (cfg.addr == c.INADDR_NONE) usage(prog);
    if (cfg.port == 0) usage(prog);

    cfg.subprocess_argv = subprocess_args.items;

    if (cfg.verbose) {
        for (cfg.subprocess_argv, 0..) |arg, i| {
            std.debug.print("subprocess: argv[{d}]: {s}\n", .{ i, arg });
        }
    }

    // Block all signals
    var all: c.sigset_t = undefined;
    _ = c.sigfillset(&all);
    _ = c.sigprocmask(c.SIG_SETMASK, &all, null);

    // Signals we'll accept via signalfd
    var sw: c.sigset_t = undefined;
    _ = c.sigemptyset(&sw);
    const sigs = [_]c_int{ c.SIGIO, c.SIGHUP, c.SIGTERM, c.SIGINT, c.SIGQUIT, c.SIGALRM, c.SIGCHLD };
    for (sigs) |sig| {
        _ = c.sigaddset(&sw, sig);
    }

    try setupListener();

    // Create signalfd
    cfg.signal_fd = c.signalfd(-1, &sw, 0);
    if (cfg.signal_fd == -1) {
        std.debug.print("signalfd: {s}\n", .{c.strerror(c.__errno_location().*)});
        return error.SignalfdError;
    }

    // Set up epoll
    cfg.epoll_fd = c.epoll_create(1);
    if (cfg.epoll_fd == -1) {
        std.debug.print("epoll: {s}\n", .{c.strerror(c.__errno_location().*)});
        return error.EpollError;
    }

    try addEpoll(c.EPOLLIN, cfg.listener_fd);
    try addEpoll(c.EPOLLIN, cfg.signal_fd);

    // Main loop
    _ = c.alarm(1);
    var ev: c.struct_epoll_event = undefined;

    while (c.epoll_wait(cfg.epoll_fd, &ev, 1, -1) > 0) {
        if (ev.data.fd == cfg.signal_fd) {
            handleSignal() catch |err| {
                if (err == error.SignalExit) break;
                return err;
            };
        } else if (ev.data.fd == cfg.listener_fd) {
            acceptClient(allocator) catch {};
        } else {
            std.debug.print("Unexpected file descriptor from epoll\n", .{});
            break;
        }
    }

    // Cleanup
    if (cfg.listener_fd != -1) _ = c.close(cfg.listener_fd);
    if (cfg.epoll_fd != -1) _ = c.close(cfg.epoll_fd);
    if (cfg.signal_fd != -1) _ = c.close(cfg.signal_fd);
}
