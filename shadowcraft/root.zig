const std = @import("std");

pub const ShadowcraftError = error{
    AnonymizationFailed,
    PrivacyBreach,
    ObfuscationError,
};

pub fn version() []const u8 {
    return "1.0.0-placeholder";
}

test "shadowcraft tests" {
    std.testing.refAllDecls(@This());
}