const std = @import("std");

pub const GuardianError = error{
    RuleValidationFailed,
    PolicyViolation,
    AccessDenied,
};

pub fn version() []const u8 {
    return "1.0.0-placeholder";
}

test "guardian tests" {
    std.testing.refAllDecls(@This());
}