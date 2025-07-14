# zsync Library Bugs and Issues

## Bug #1: RingBuffer.init() API Mismatch - **RESOLVED** ✅

**Status:** Fixed in zsync v0.2.1  
**File:** `zsync/src/channel.zig:60`  
**Error:** `expected 2 argument(s), found 1`

**Details:**
The zsync library was calling `std.RingBuffer.init(raw_buffer)` with only one argument, but Zig 0.15's `std.RingBuffer.init()` requires two arguments: `(allocator, capacity)`.

**Resolution:**
This bug has been fixed by the zsync maintainers in version 0.2.1. SHROUD now uses the corrected version.

**Impact:**
- Prevents compilation when using zsync channels
- Affects `zsync.bounded()` and `zsync.unbounded()` functions
- Critical bug that breaks channel functionality

**Fix Applied:**
Updated all RingBuffer.init() calls in src/channel.zig to use the new Zig 0.15 API that requires `(allocator, capacity)` instead of just a buffer.

## Status

- **Reported:** July 13, 2025
- **Fixed:** July 14, 2025  
- **Severity:** Critical (breaks compilation) - ✅ RESOLVED
- **Components Affected:** Channel system, bounded/unbounded functions
- **Fix Applied:** Updated RingBuffer.init() calls to use new Zig 0.15 API

## Technical Details

**Changes Made:**
1. Updated `std.RingBuffer.init(raw_buffer)` to `std.RingBuffer.init(allocator, total_capacity)` on lines 59, 140, 145
2. Updated `deinit()` method to call `buffer.deinit(allocator)` instead of `allocator.free(raw_buffer)`
3. Fixed capacity checks to use `buffer.data.len` instead of non-existent `buffer.capacity()` method
4. Updated `readFirst()` calls to include length parameter as required by new API

**Testing:**
- All 4 channel tests pass
- Full project compiles successfully
- Channel functionality preserved
