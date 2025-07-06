//! By convention, root.zig is the root source file when making a library.
//! This file exports the zsig module for use as a library dependency.

const zsig = @import("zsig.zig");

// Re-export everything from zsig module
pub usingnamespace zsig;

// Include tests from zsig module
test {
    @import("std").testing.refAllDecls(@This());
}
