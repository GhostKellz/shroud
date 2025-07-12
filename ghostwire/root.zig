//! Ghostwire: Complete networking stack for Shroud v1.0
//! QUIC, HTTP/1.1, HTTP/2, HTTP/3, gRPC, IPv6, WebSockets, Reverse Proxy
//! Now with async support for massive performance improvements
const std = @import("std");

// Async core - Local async implementation
pub const async_local = @import("async_local.zig");
pub const async_core = @import("async_core.zig");
pub const async_server = @import("async_unified_server.zig");

// Async types and components
pub const AsyncRuntime = async_local.AsyncRuntime;
pub const AsyncServerCore = async_core.AsyncServerCore;
pub const AsyncUnifiedServer = async_server.AsyncUnifiedServer;
pub const AsyncServerBuilder = async_server.AsyncServerBuilder;
pub const AsyncHttpRequest = async_server.AsyncHttpRequest;
pub const AsyncHttpResponse = async_server.AsyncHttpResponse;
pub const AsyncRequestHandler = async_server.AsyncRequestHandler;
pub const AsyncMiddleware = async_server.AsyncMiddleware;

// Async connections
pub const AsyncConnection = async_local.AsyncConnection;
pub const AsyncHttpConnection = async_core.AsyncHttpConnection;

// Core protocol implementations
pub const zquic = @import("zquic/root.zig");
pub const http1 = @import("http1/server.zig");
pub const http2 = @import("http2/server.zig");
pub const http3 = zquic; // HTTP/3 is part of QUIC

// WebSocket implementation
pub const websocket = struct {
    pub const server = @import("websocket/server.zig");
    pub const client = @import("websocket/client.zig");
    pub const frame = @import("websocket/frame.zig");
    pub const handshake = @import("websocket/handshake.zig");

    // Convenience exports
    pub const WebSocketServer = server.WebSocketServer;
    pub const WebSocketClient = client.WebSocketClient;
    pub const WebSocketFrame = frame.WebSocketFrame;
    pub const WebSocketOpcode = frame.WebSocketOpcode;
    pub const WebSocketCloseCode = frame.WebSocketCloseCode;
    pub const WebSocketHandshake = handshake.WebSocketHandshake;
};

// gRPC implementation
pub const grpc = struct {
    pub const server = @import("grpc/server.zig");
    pub const grpc_client = @import("grpc/client.zig");

    // Convenience exports
    pub const GrpcServer = server.GrpcServer;
    pub const GrpcClient = grpc_client.GrpcClient;
    pub const GrpcMessage = server.GrpcMessage;
    pub const GrpcStatus = server.GrpcStatus;
    pub const EchoService = server.EchoService;
    pub const GrpcConnection = server.GrpcConnection;
    pub const GrpcMethod = server.GrpcMethod;
    pub const GrpcResponseInternal = server.GrpcResponseInternal;
    pub const GrpcStream = server.GrpcStream;
    pub const ServiceType = server.ServiceType;
    pub const HealthStatus = server.HealthStatus;
    pub const RegisteredService = server.RegisteredService;
    pub const GrpcConfig = server.GrpcConfig;
};

// IPv6 networking stack
pub const ipv6 = struct {
    pub const core = @import("ipv6/core.zig");
    pub const discovery = @import("ipv6/discovery.zig");

    // Convenience exports
    pub const IPv6Address = core.IPv6Address;
    pub const IPv6Subnet = core.IPv6Subnet;
    pub const IPv6Stack = core.IPv6Stack;
    pub const IPv6Discovery = discovery.IPv6Discovery;
    pub const MulticastDiscovery = discovery.MulticastDiscovery;
    pub const WellKnownAddresses = core.WellKnownAddresses;
};

// HTTP client
pub const http_client = @import("client/http_client.zig");

// Infrastructure
pub const proxy = @import("proxy/reverse_proxy.zig");
pub const unified = @import("unified_server.zig");

// Convenience exports
pub const HttpClient = http_client.HttpClient;
pub const ReverseProxy = proxy.ReverseProxy;
pub const UnifiedServer = unified.UnifiedServer;
pub const Http1Server = http1.Http1Server;
pub const Http2Server = http2.Http2Server;

// Unified types
pub const UnifiedRequest = unified.UnifiedRequest;
pub const UnifiedResponse = unified.UnifiedResponse;
pub const HandlerFn = unified.HandlerFn;
pub const MiddlewareFn = unified.MiddlewareFn;

pub const TransportError = error{
    ConnectionFailed,
    HandshakeFailed,
    StreamError,
    NetworkError,
    ProxyError,
    ClientError,
    GrpcError,
    IPv6Error,
};

pub const NetworkProtocol = enum {
    http1_1,
    http2,
    http3,
    quic,
    grpc,
    websocket,
    ipv6,
    icmpv6,
};

pub const GhostwireCapabilities = struct {
    http1_1: bool = true,
    http2: bool = true,
    http3: bool = true,
    grpc: bool = true,
    ipv6: bool = true,
    websocket: bool = true,
    reverse_proxy: bool = true,
    multicast_discovery: bool = true,
    zero_config_ipv6: bool = true,
    dual_stack: bool = true,
};

pub fn version() []const u8 {
    return "1.0.0";
}

pub fn capabilities() GhostwireCapabilities {
    return GhostwireCapabilities{};
}

// Integration helpers
pub fn createUnifiedServer(allocator: std.mem.Allocator, config: unified.UnifiedServerConfig) !UnifiedServer {
    return UnifiedServer.init(allocator, config);
}

pub fn createGrpcServer(allocator: std.mem.Allocator, config: grpc.server.GrpcConfig) !grpc.GrpcServer {
    return grpc.GrpcServer.init(allocator, config);
}

pub fn createIPv6Stack(allocator: std.mem.Allocator, config: ipv6.core.IPv6Config) ipv6.IPv6Stack {
    return ipv6.IPv6Stack.init(allocator, config);
}

pub fn createReverseProxy(allocator: std.mem.Allocator, config: proxy.ProxyConfig) !ReverseProxy {
    return ReverseProxy.init(allocator, config);
}

pub fn createWebSocketServer(allocator: std.mem.Allocator, config: websocket.server.WebSocketServerConfig) !websocket.WebSocketServer {
    return websocket.WebSocketServer.init(allocator, config);
}

pub fn createWebSocketClient(allocator: std.mem.Allocator, url: []const u8, config: websocket.client.WebSocketClientConfig) !websocket.WebSocketClient {
    return websocket.WebSocketClient.init(allocator, url, config);
}

pub fn createAsyncUnifiedServer(allocator: std.mem.Allocator, runtime: *AsyncRuntime, config: async_server.AsyncUnifiedServerConfig) !*AsyncUnifiedServer {
    return AsyncUnifiedServer.init(allocator, runtime, config);
}

pub fn createAsyncServerBuilder(allocator: std.mem.Allocator, runtime: *AsyncRuntime) AsyncServerBuilder {
    return AsyncServerBuilder.init(allocator, runtime);
}

test "ghostwire tests" {
    std.testing.refAllDecls(@This());
}
