const std = @import("std");

pub const CovenantError = error{
    ContractExecutionFailed,
    InvalidParameters,
    StateMismatch,
};

pub fn version() []const u8 {
    return "1.0.0-placeholder";
}

test "covenant tests" {
    std.testing.refAllDecls(@This());
}