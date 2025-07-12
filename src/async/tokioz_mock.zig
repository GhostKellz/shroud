//! Mock TokioZ implementation for SHROUD async integration
//! This provides the interface that SHROUD expects from TokioZ v1.0.1
//! until the real TokioZ implementation is available

const std = @import("std");

/// Mock Runtime for TokioZ compatibility
pub const Runtime = struct {
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) !*Runtime {
        const runtime = try allocator.create(Runtime);
        runtime.* = Runtime{
            .allocator = allocator,
        };
        return runtime;
    }

    pub fn deinit(self: *Runtime) void {
        self.allocator.destroy(self);
    }

    pub fn run(self: *Runtime, main_task: anytype) !void {
        _ = self;
        try main_task();
    }
};

/// Mock Task for async operations
pub fn Task(comptime T: type) type {
    return struct {
        const Self = @This();

        result: T,

        pub fn await(self: *Self) !T {
            return self.result;
        }
    };
}

/// Mock spawn function
pub fn spawn(task: anytype) !Task(@TypeOf(task).ReturnType) {
    const result = try task();
    return Task(@TypeOf(task).ReturnType){
        .result = result,
    };
}

/// Mock Timer
pub const Timer = struct {
    duration: std.time.Duration,

    pub fn sleep(duration: std.time.Duration) Timer {
        return Timer{ .duration = duration };
    }
};

/// Mock time utilities
pub const time = struct {
    pub fn sleep(duration: std.time.Duration) Timer {
        std.time.sleep(@intCast(duration.nanos));
        return Timer{ .duration = duration };
    }

    pub fn interval(duration: std.time.Duration) Interval {
        return Interval{ .duration = duration };
    }

    pub const Interval = struct {
        duration: std.time.Duration,

        pub fn tick(self: *Interval) void {
            std.time.sleep(@intCast(self.duration.nanos));
        }
    };
};

/// Mock select for future racing
pub fn select(futures: anytype) !@TypeOf(futures[0]) {
    // Just return the first future for now
    return futures[0];
}

/// Mock Sender/Receiver for channels
pub fn Sender(comptime T: type) type {
    return struct {
        const Self = @This();

        pub fn send(self: *Self, value: T) !void {
            _ = self;
            _ = value;
            // Mock implementation
        }

        pub fn close(self: *Self) void {
            _ = self;
        }
    };
}

pub fn Receiver(comptime T: type) type {
    return struct {
        const Self = @This();

        pub fn recv(self: *Self) !T {
            _ = self;
            return error.MockNotImplemented;
        }

        pub fn tryRecv(self: *Self) ?T {
            _ = self;
            return null;
        }
    };
}

/// Mock Channel
pub fn Channel(comptime T: type) type {
    return struct {
        const Self = @This();

        sender_impl: Sender(T),
        receiver_impl: Receiver(T),

        pub fn init(allocator: std.mem.Allocator, capacity: usize) !Self {
            _ = allocator;
            _ = capacity;
            return Self{
                .sender_impl = Sender(T){},
                .receiver_impl = Receiver(T){},
            };
        }

        pub fn sender(self: *Self) Sender(T) {
            return self.sender_impl;
        }

        pub fn receiver(self: *Self) Receiver(T) {
            return self.receiver_impl;
        }
    };
}

/// Mock networking
pub const net = struct {
    pub const TcpStream = struct {
        pub fn connect(address: []const u8, port: u16) !TcpStream {
            _ = address;
            _ = port;
            return TcpStream{};
        }

        pub fn read(self: *TcpStream, buffer: []u8) !usize {
            _ = self;
            _ = buffer;
            return 0;
        }

        pub fn write(self: *TcpStream, data: []const u8) !usize {
            _ = self;
            return data.len;
        }

        pub fn close(self: *TcpStream) void {
            _ = self;
        }
    };

    pub const TcpListener = struct {
        pub fn bind(address: []const u8, port: u16) !TcpListener {
            _ = address;
            _ = port;
            return TcpListener{};
        }

        pub fn accept(self: *TcpListener) !TcpStream {
            _ = self;
            return TcpStream{};
        }
    };

    pub const UdpSocket = struct {
        pub fn bind(address: []const u8, port: u16) !UdpSocket {
            _ = address;
            _ = port;
            return UdpSocket{};
        }

        pub fn sendTo(self: *UdpSocket, data: []const u8, address: std.net.Address) !void {
            _ = self;
            _ = data;
            _ = address;
        }

        pub fn recvFrom(self: *UdpSocket, buffer: []u8) !struct { usize, std.net.Address } {
            _ = self;
            _ = buffer;
            return error.MockNotImplemented;
        }
    };
};
