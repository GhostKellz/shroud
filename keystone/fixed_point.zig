const std = @import("std");

pub const DECIMAL_PLACES: u8 = 8;
pub const SCALE_FACTOR: i64 = 100_000_000;

pub const FixedPoint = struct {
    value: i64,

    pub fn fromInt(int_value: i64) FixedPoint {
        return FixedPoint{ .value = int_value * SCALE_FACTOR };
    }

    pub fn fromFloat(float_value: f64) FixedPoint {
        return FixedPoint{ .value = @intFromFloat(float_value * @as(f64, @floatFromInt(SCALE_FACTOR))) };
    }

    pub fn fromString(allocator: std.mem.Allocator, str: []const u8) !FixedPoint {
        _ = allocator;
        
        if (std.mem.indexOf(u8, str, ".")) |dot_index| {
            const integer_part = str[0..dot_index];
            const decimal_part = str[dot_index + 1 ..];
            
            const int_value = try std.fmt.parseInt(i64, integer_part, 10);
            
            var decimal_value: i64 = 0;
            if (decimal_part.len > 0) {
                var padded_decimal: [DECIMAL_PLACES]u8 = [_]u8{'0'} ** DECIMAL_PLACES;
                const copy_len = @min(decimal_part.len, DECIMAL_PLACES);
                @memcpy(padded_decimal[0..copy_len], decimal_part[0..copy_len]);
                
                decimal_value = try std.fmt.parseInt(i64, &padded_decimal, 10);
            }
            
            const sign: i64 = if (int_value < 0 or (int_value == 0 and str[0] == '-')) -1 else 1;
            return FixedPoint{ .value = (int_value * SCALE_FACTOR) + (sign * decimal_value) };
        } else {
            const int_value = try std.fmt.parseInt(i64, str, 10);
            return fromInt(int_value);
        }
    }

    pub fn toInt(self: FixedPoint) i64 {
        return @divTrunc(self.value, SCALE_FACTOR);
    }

    pub fn toFloat(self: FixedPoint) f64 {
        return @as(f64, @floatFromInt(self.value)) / @as(f64, @floatFromInt(SCALE_FACTOR));
    }

    pub fn toString(self: FixedPoint, allocator: std.mem.Allocator) ![]u8 {
        const integer_part = @divTrunc(self.value, SCALE_FACTOR);
        const decimal_part = @rem(@abs(self.value), SCALE_FACTOR);
        
        if (decimal_part == 0) {
            return try std.fmt.allocPrint(allocator, "{d}", .{integer_part});
        }
        
        var decimal_str: [DECIMAL_PLACES]u8 = undefined;
        _ = try std.fmt.bufPrint(&decimal_str, "{:0>8}", .{decimal_part});
        
        var end_idx: usize = DECIMAL_PLACES;
        while (end_idx > 0 and decimal_str[end_idx - 1] == '0') {
            end_idx -= 1;
        }
        
        return try std.fmt.allocPrint(allocator, "{d}.{s}", .{ integer_part, decimal_str[0..end_idx] });
    }

    pub fn add(self: FixedPoint, other: FixedPoint) FixedPoint {
        return FixedPoint{ .value = self.value + other.value };
    }

    pub fn sub(self: FixedPoint, other: FixedPoint) FixedPoint {
        return FixedPoint{ .value = self.value - other.value };
    }

    pub fn mul(self: FixedPoint, other: FixedPoint) FixedPoint {
        const result = (@as(i128, self.value) * @as(i128, other.value)) / @as(i128, SCALE_FACTOR);
        return FixedPoint{ .value = @intCast(result) };
    }

    pub fn div(self: FixedPoint, other: FixedPoint) !FixedPoint {
        if (other.value == 0) return error.DivisionByZero;
        
        const result = (@as(i128, self.value) * @as(i128, SCALE_FACTOR)) / @as(i128, other.value);
        return FixedPoint{ .value = @intCast(result) };
    }

    pub fn eq(self: FixedPoint, other: FixedPoint) bool {
        return self.value == other.value;
    }

    pub fn lt(self: FixedPoint, other: FixedPoint) bool {
        return self.value < other.value;
    }

    pub fn gt(self: FixedPoint, other: FixedPoint) bool {
        return self.value > other.value;
    }

    pub fn lte(self: FixedPoint, other: FixedPoint) bool {
        return self.value <= other.value;
    }

    pub fn gte(self: FixedPoint, other: FixedPoint) bool {
        return self.value >= other.value;
    }

    pub fn abs(self: FixedPoint) FixedPoint {
        return FixedPoint{ .value = @abs(self.value) };
    }

    pub fn neg(self: FixedPoint) FixedPoint {
        return FixedPoint{ .value = -self.value };
    }

    pub fn round(self: FixedPoint, decimal_places: u8) FixedPoint {
        if (decimal_places >= DECIMAL_PLACES) return self;
        
        const divisor = std.math.pow(i64, 10, DECIMAL_PLACES - decimal_places);
        const remainder = @rem(self.value, divisor);
        
        var rounded_value = self.value - remainder;
        if (@abs(remainder) >= @divTrunc(divisor, 2)) {
            if (self.value >= 0) {
                rounded_value += divisor;
            } else {
                rounded_value -= divisor;
            }
        }
        
        return FixedPoint{ .value = rounded_value };
    }
};

pub fn convertAmountToFixedPoint(amount_cents: i64) FixedPoint {
    return FixedPoint{ .value = amount_cents * (SCALE_FACTOR / 100) };
}

pub fn convertFixedPointToAmount(fp: FixedPoint) i64 {
    return @divTrunc(fp.value, (SCALE_FACTOR / 100));
}

test "fixed point basic operations" {
    const a = FixedPoint.fromFloat(10.5);
    const b = FixedPoint.fromFloat(2.25);
    
    const sum = a.add(b);
    const diff = a.sub(b);
    const product = a.mul(b);
    const quotient = try a.div(b);
    
    try std.testing.expectApproxEqAbs(sum.toFloat(), 12.75, 0.000001);
    try std.testing.expectApproxEqAbs(diff.toFloat(), 8.25, 0.000001);
    try std.testing.expectApproxEqAbs(product.toFloat(), 23.625, 0.000001);
    try std.testing.expectApproxEqAbs(quotient.toFloat(), 4.666666666666667, 0.000001);
}

test "fixed point string conversion" {
    const allocator = std.testing.allocator;
    
    const fp1 = try FixedPoint.fromString(allocator, "123.456789");
    const str1 = try fp1.toString(allocator);
    defer allocator.free(str1);
    try std.testing.expectEqualStrings("123.456789", str1);
    
    const fp2 = try FixedPoint.fromString(allocator, "100");
    const str2 = try fp2.toString(allocator);
    defer allocator.free(str2);
    try std.testing.expectEqualStrings("100", str2);
    
    const fp3 = try FixedPoint.fromString(allocator, "-50.25");
    const str3 = try fp3.toString(allocator);
    defer allocator.free(str3);
    try std.testing.expectEqualStrings("-50.25", str3);
}

test "fixed point precision" {
    const a = FixedPoint.fromFloat(0.1);
    const b = FixedPoint.fromFloat(0.2);
    const sum = a.add(b);
    
    try std.testing.expectApproxEqAbs(sum.toFloat(), 0.3, 0.000000001);
    try std.testing.expect(sum.eq(FixedPoint.fromFloat(0.3)));
}

test "fixed point rounding" {
    const allocator = std.testing.allocator;
    
    const fp = try FixedPoint.fromString(allocator, "123.456789");
    
    const rounded2 = fp.round(2);
    const str2 = try rounded2.toString(allocator);
    defer allocator.free(str2);
    try std.testing.expectEqualStrings("123.46", str2);
    
    const rounded0 = fp.round(0);
    const str0 = try rounded0.toString(allocator);
    defer allocator.free(str0);
    try std.testing.expectEqualStrings("123", str0);
}

test "amount conversion" {
    const amount_cents: i64 = 150000;
    const fp = convertAmountToFixedPoint(amount_cents);
    const converted_back = convertFixedPointToAmount(fp);
    
    try std.testing.expectEqual(amount_cents, converted_back);
    try std.testing.expectApproxEqAbs(fp.toFloat(), 1500.0, 0.000001);
}