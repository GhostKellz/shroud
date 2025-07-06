const std = @import("std");

/// Log levels
pub const Level = enum {
    debug,
    info,
    warn,
    err,
    
    pub fn toString(self: Level) []const u8 {
        return switch (self) {
            .debug => "DEBUG",
            .info => "INFO",
            .warn => "WARN",
            .err => "ERROR",
        };
    }
};

/// Simple logger for production use
pub const Logger = struct {
    level: Level,
    writer: std.fs.File.Writer,
    
    pub fn init(level: Level) Logger {
        return Logger{
            .level = level,
            .writer = std.io.getStdErr().writer(),
        };
    }
    
    pub fn log(self: Logger, level: Level, comptime format: []const u8, args: anytype) void {
        if (@intFromEnum(level) < @intFromEnum(self.level)) {
            return;
        }
        
        const timestamp = std.time.timestamp();
        const level_str = level.toString();
        
        self.writer.print("[{d}] {s} ", .{ timestamp, level_str }) catch return;
        self.writer.print(format, args) catch return;
        self.writer.print("\n", .{}) catch return;
    }
    
    pub fn debug(self: Logger, comptime format: []const u8, args: anytype) void {
        self.log(.debug, format, args);
    }
    
    pub fn info(self: Logger, comptime format: []const u8, args: anytype) void {
        self.log(.info, format, args);
    }
    
    pub fn warn(self: Logger, comptime format: []const u8, args: anytype) void {
        self.log(.warn, format, args);
    }
    
    pub fn err(self: Logger, comptime format: []const u8, args: anytype) void {
        self.log(.err, format, args);
    }
};