const std = @import("std");

/// ZNS configuration
pub const Config = struct {
    /// Ethereum RPC endpoint
    ethereum_rpc: []const u8 = "https://eth-mainnet.alchemyapi.io/v2/demo",
    
    /// GhostBridge endpoint
    ghostbridge_endpoint: []const u8 = "http://localhost:9090",
    
    /// Unstoppable Domains API key (optional)
    unstoppable_api_key: ?[]const u8 = null,
    
    /// Cache settings
    cache_size: usize = 1000,
    cache_ttl: u64 = 300, // 5 minutes default
    
    /// Network timeouts
    timeout_ms: u32 = 30000, // 30 seconds
    
    /// Log level
    log_level: []const u8 = "info",
    
    /// Load configuration from environment variables
    pub fn fromEnv(allocator: std.mem.Allocator) !Config {
        var config = Config{};
        
        // Load Ethereum RPC
        if (std.process.getEnvVarOwned(allocator, "ZNS_ETHEREUM_RPC")) |value| {
            config.ethereum_rpc = value;
        } else |_| {}
        
        // Load GhostBridge endpoint
        if (std.process.getEnvVarOwned(allocator, "ZNS_GHOSTBRIDGE_ENDPOINT")) |value| {
            config.ghostbridge_endpoint = value;
        } else |_| {}
        
        // Load Unstoppable API key
        if (std.process.getEnvVarOwned(allocator, "ZNS_UNSTOPPABLE_API_KEY")) |value| {
            config.unstoppable_api_key = value;
        } else |_| {}
        
        // Load cache size
        if (std.process.getEnvVarOwned(allocator, "ZNS_CACHE_SIZE")) |value| {
            defer allocator.free(value);
            config.cache_size = try std.fmt.parseInt(usize, value, 10);
        } else |_| {}
        
        // Load timeout
        if (std.process.getEnvVarOwned(allocator, "ZNS_TIMEOUT_MS")) |value| {
            defer allocator.free(value);
            config.timeout_ms = try std.fmt.parseInt(u32, value, 10);
        } else |_| {}
        
        // Load log level
        if (std.process.getEnvVarOwned(allocator, "ZNS_LOG_LEVEL")) |value| {
            config.log_level = value;
        } else |_| {}
        
        return config;
    }
    
    /// Load configuration from JSON file
    pub fn fromFile(allocator: std.mem.Allocator, path: []const u8) !Config {
        const file = try std.fs.cwd().openFile(path, .{});
        defer file.close();
        
        const contents = try file.readToEndAlloc(allocator, 1024 * 1024); // 1MB max
        defer allocator.free(contents);
        
        // Simple JSON parsing without complex types
        var config = Config{};
        
        // Parse ethereum_rpc
        if (std.mem.indexOf(u8, contents, "\"ethereum_rpc\":")) |pos| {
            const start = std.mem.indexOf(u8, contents[pos..], "\"") orelse return config;
            const end = std.mem.indexOf(u8, contents[pos + start + 1..], "\"") orelse return config;
            config.ethereum_rpc = try allocator.dupe(u8, contents[pos + start + 1..pos + start + 1 + end]);
        }
        
        return config;
    }
};