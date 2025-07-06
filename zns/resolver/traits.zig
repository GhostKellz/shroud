const std = @import("std");
const types = @import("types.zig");

/// Generic name service resolver interface (trait-like pattern)
pub const NameServiceResolver = struct {
    /// Function pointer types for the vtable
    const ResolveFn = *const fn (ptr: *anyopaque, domain: []const u8) anyerror!types.CryptoAddress;
    const ResolveAllFn = *const fn (ptr: *anyopaque, domain: []const u8) anyerror![]types.CryptoAddress;
    const SupportsFn = *const fn (domain: []const u8) bool;
    const GetMetadataFn = *const fn (ptr: *anyopaque, domain: []const u8) anyerror![]const u8;
    const DeinitFn = *const fn (ptr: *anyopaque) void;
    
    /// Virtual function table
    ptr: *anyopaque,
    resolveFn: ResolveFn,
    resolveAllFn: ResolveAllFn,
    supportsFn: SupportsFn,
    getMetadataFn: GetMetadataFn,
    deinitFn: DeinitFn,
    name: []const u8,
    
    /// Public interface methods
    pub fn resolve(self: NameServiceResolver, domain: []const u8) !types.CryptoAddress {
        return self.resolveFn(self.ptr, domain);
    }
    
    pub fn resolveAll(self: NameServiceResolver, domain: []const u8) ![]types.CryptoAddress {
        return self.resolveAllFn(self.ptr, domain);
    }
    
    pub fn supports(self: NameServiceResolver, domain: []const u8) bool {
        return self.supportsFn(domain);
    }
    
    pub fn getMetadata(self: NameServiceResolver, domain: []const u8) ![]const u8 {
        return self.getMetadataFn(self.ptr, domain);
    }
    
    pub fn deinit(self: NameServiceResolver) void {
        self.deinitFn(self.ptr);
    }
    
    /// Helper to create resolver from concrete type
    pub fn from(comptime T: type, instance: *T) NameServiceResolver {
        const gen = struct {
            fn resolve(ptr: *anyopaque, domain: []const u8) anyerror!types.CryptoAddress {
                const self: *T = @ptrCast(@alignCast(ptr));
                return self.resolve(domain);
            }
            
            fn resolveAll(ptr: *anyopaque, domain: []const u8) anyerror![]types.CryptoAddress {
                const self: *T = @ptrCast(@alignCast(ptr));
                return self.resolveAll(domain);
            }
            
            fn supports(domain: []const u8) bool {
                return T.supports(domain);
            }
            
            fn getMetadata(ptr: *anyopaque, domain: []const u8) anyerror![]const u8 {
                const self: *T = @ptrCast(@alignCast(ptr));
                return self.getMetadata(domain);
            }
            
            fn deinitFn(ptr: *anyopaque) void {
                const self: *T = @ptrCast(@alignCast(ptr));
                if (@hasDecl(T, "deinit")) {
                    self.deinit();
                }
            }
        };
        
        return NameServiceResolver{
            .ptr = instance,
            .resolveFn = gen.resolve,
            .resolveAllFn = gen.resolveAll,
            .supportsFn = gen.supports,
            .getMetadataFn = gen.getMetadata,
            .deinitFn = gen.deinitFn,
            .name = @typeName(T),
        };
    }
};

/// Registry for managing multiple name service resolvers
pub const ResolverRegistry = struct {
    allocator: std.mem.Allocator,
    resolvers: std.ArrayList(NameServiceResolver),
    
    pub fn init(allocator: std.mem.Allocator) ResolverRegistry {
        return ResolverRegistry{
            .allocator = allocator,
            .resolvers = std.ArrayList(NameServiceResolver).init(allocator),
        };
    }
    
    pub fn deinit(self: *ResolverRegistry) void {
        // Deinitialize all resolvers
        for (self.resolvers.items) |resolver| {
            resolver.deinit();
        }
        self.resolvers.deinit();
    }
    
    /// Register a new resolver
    pub fn register(self: *ResolverRegistry, resolver: NameServiceResolver) !void {
        try self.resolvers.append(resolver);
    }
    
    /// Find the appropriate resolver for a domain
    pub fn findResolver(self: *ResolverRegistry, domain: []const u8) ?NameServiceResolver {
        for (self.resolvers.items) |resolver| {
            if (resolver.supports(domain)) {
                return resolver;
            }
        }
        return null;
    }
    
    /// Resolve using the appropriate resolver
    pub fn resolve(self: *ResolverRegistry, domain: []const u8) !types.CryptoAddress {
        const resolver = self.findResolver(domain) orelse return error.UnsupportedDomain;
        return resolver.resolve(domain);
    }
    
    /// Resolve all addresses using the appropriate resolver
    pub fn resolveAll(self: *ResolverRegistry, domain: []const u8) ![]types.CryptoAddress {
        const resolver = self.findResolver(domain) orelse return error.UnsupportedDomain;
        return resolver.resolveAll(domain);
    }
    
    /// Get metadata using the appropriate resolver
    pub fn getMetadata(self: *ResolverRegistry, domain: []const u8) ![]const u8 {
        const resolver = self.findResolver(domain) orelse return error.UnsupportedDomain;
        return resolver.getMetadata(domain);
    }
    
    /// List all supported TLDs
    pub fn getSupportedTlds(self: *ResolverRegistry) ![][]const u8 {
        var tlds = std.ArrayList([]const u8).init(self.allocator);
        defer tlds.deinit();
        
        // Common TLDs for each resolver type
        const known_tlds = [_]struct { name: []const u8, tlds: []const []const u8 }{
            .{ .name = "ENS", .tlds = &[_][]const u8{".eth"} },
            .{ .name = "Unstoppable", .tlds = &[_][]const u8{ ".crypto", ".nft", ".x", ".wallet", ".bitcoin", ".dao" } },
            .{ .name = "Ghost", .tlds = &[_][]const u8{ ".ghost", ".bc", ".kz", ".zkellz" } },
        };
        
        for (known_tlds) |tld_group| {
            for (tld_group.tlds) |tld| {
                // Test if any resolver supports this TLD
                const test_domain = try std.fmt.allocPrint(self.allocator, "test{s}", .{tld});
                defer self.allocator.free(test_domain);
                
                if (self.findResolver(test_domain)) |_| {
                    try tlds.append(try self.allocator.dupe(u8, tld));
                }
            }
        }
        
        return tlds.toOwnedSlice();
    }
};

/// Lookup function type definitions for modular design
pub const LookupFn = *const fn (domain: []const u8, allocator: std.mem.Allocator) anyerror!types.CryptoAddress;

/// Module-specific lookup functions
pub const Lookups = struct {
    /// ENS lookup function
    pub fn ens_lookup(domain: []const u8, allocator: std.mem.Allocator) !types.CryptoAddress {
        const ens = @import("ens.zig");
        var resolver = ens.ENSResolver.init(allocator, "https://eth-mainnet.alchemyapi.io/v2/demo");
        return resolver.resolve(domain);
    }
    
    /// Unstoppable Domains lookup function  
    pub fn ud_lookup(domain: []const u8, allocator: std.mem.Allocator) !types.CryptoAddress {
        const ud = @import("unstoppable.zig");
        var resolver = ud.UnstoppableResolver.init(allocator, null);
        return resolver.resolve(domain);
    }
    
    /// GhostChain native lookup function
    pub fn zns_lookup(domain: []const u8, allocator: std.mem.Allocator) !types.CryptoAddress {
        const ghost = @import("ghost.zig");
        var resolver = ghost.GhostResolver.init(allocator, "http://localhost:9090");
        return resolver.resolve(domain);
    }
};

/// Utility for dynamic resolver loading
pub const DynamicResolver = struct {
    name: []const u8,
    lookup_fn: LookupFn,
    supports_fn: *const fn (domain: []const u8) bool,
    
    pub fn resolve(self: DynamicResolver, domain: []const u8, allocator: std.mem.Allocator) !types.CryptoAddress {
        return self.lookup_fn(domain, allocator);
    }
    
    pub fn supports(self: DynamicResolver, domain: []const u8) bool {
        return self.supports_fn(domain);
    }
};