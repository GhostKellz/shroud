const std = @import("std");
pub fn main() void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var map = std.ArrayHashMap(u64, i32, std.array_hash_map.AutoContext(u64), false).init(gpa.allocator());
    defer map.deinit();
}
