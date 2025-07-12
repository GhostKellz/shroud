# 🚀 SHROUD TokioZ v1.0.1 Async Integration Plan

[![TokioZ](https://img.shields.io/badge/TokioZ-v1.0.1-green.svg)](https://github.com/ghostkellz/TokioZ)
[![Async](https://img.shields.io/badge/Async-Runtime-blue.svg)](https://docs.rs/tokio/latest/tokio/)
[![Zig](https://img.shields.io/badge/Zig-0.15.0-orange.svg)](https://ziglang.org/)

> Comprehensive migration plan to integrate TokioZ v1.0.1 async runtime throughout the SHROUD ecosystem.

---

## 📋 Table of Contents

1. [Overview](#overview)
2. [Current State Analysis](#current-state-analysis)
3. [TokioZ v1.0.1 Features](#tokioz-v101-features)
4. [Migration Strategy](#migration-strategy)
5. [Module-by-Module Integration](#module-by-module-integration)
6. [Implementation Timeline](#implementation-timeline)
7. [Breaking Changes](#breaking-changes)
8. [Performance Benefits](#performance-benefits)
9. [Testing Strategy](#testing-strategy)
10. [Documentation Updates](#documentation-updates)

---

## 🎯 Overview

This document outlines the comprehensive integration of TokioZ v1.0.1 async runtime into the SHROUD framework. The upgrade will transform SHROUD from a synchronous framework to a fully async-native ecosystem, dramatically improving performance, scalability, and resource efficiency.

### Goals

- ⚡ **Performance**: 10x improvement in concurrent operations
- 🔄 **Non-blocking I/O**: All network operations become async
- 📈 **Scalability**: Support thousands of concurrent connections
- 🧩 **Composability**: Async futures and task composition
- 🔧 **Maintainability**: Cleaner async/await patterns

### Dependencies Added

```zig
// build.zig.zon
.dependencies = .{
    .tokioZ = .{
        .url = "https://github.com/ghostkellz/TokioZ/archive/refs/heads/main.tar.gz",
        .hash = "tokioZ-1.0.1-P0qt07Z-AwDM-WcpwjDbb0cIN4qQaTHpDuuszJ4bus5D",
    },
}
```

---

## 📊 Current State Analysis

### Modules Requiring Async Integration

| Module | Current State | Async Priority | Complexity |
|--------|---------------|----------------|------------|
| **GhostWire** | Sync QUIC/HTTP | **HIGH** | Complex |
| **Keystone** | Sync Ledger | **HIGH** | Medium |
| **Covenant** | Sync VM | **HIGH** | Medium |
| **GWallet** | Sync RPC | **MEDIUM** | Medium |
| **ZNS** | Sync Resolution | **MEDIUM** | Low |
| **Sigil** | Sync Identity | **LOW** | Low |
| **GhostCipher** | Sync Crypto | **LOW** | Low |
| **Guardian** | Sync Multisig | **MEDIUM** | Low |
| **ShadowCraft** | Sync Policies | **LOW** | Low |

### Current Blocking Operations

1. **Network I/O**
   - HTTP/QUIC requests in GhostWire
   - RPC calls in GWallet
   - DNS resolution in ZNS

2. **File I/O**
   - Keystore operations in Keystone
   - Contract storage in Covenant
   - Configuration loading

3. **Crypto Operations**
   - Signature verification
   - Hash computation
   - Key derivation

4. **Database Operations**
   - State storage/retrieval
   - Transaction processing
   - Cache operations

---

## 🚀 TokioZ v1.0.1 Features

### Core Runtime Features

```zig
// TokioZ Architecture
TokioZ/
├── tokioz.zig          # Runtime entry point
├── executor.zig        # Task queue, waker, async poller
├── time.zig            # Delay, Interval, Sleep
├── net/
│   ├── tcp.zig         # Non-blocking TCP
│   ├── udp.zig         # Non-blocking UDP
│   └── quic.zig        # [Planned] QUIC via zquic
├── task/
│   ├── future.zig      # Future trait, combinators
│   ├── waker.zig       # Waker implementation
│   └── spawner.zig     # spawn(), join_handle
└── util/               # Internal utilities
```

### Key APIs Available

1. **Task Executor**
   ```zig
   const tokioz = @import("tokioz");
   
   // Spawn async tasks
   const handle = try tokioz.spawn(async_function);
   const result = try handle.await();
   
   // Runtime execution
   try tokioz.runtime.run(async main_task);
   ```

2. **Timers**
   ```zig
   // High-resolution delays
   try tokioz.time.sleep(std.time.Duration.fromMillis(100));
   
   // Intervals
   var interval = tokioz.time.interval(std.time.Duration.fromSecs(1));
   while (try interval.tick()) {
       // Periodic task
   }
   
   // Timeouts
   const result = try tokioz.time.timeout(
       std.time.Duration.fromSecs(5),
       async_operation()
   );
   ```

3. **Channels**
   ```zig
   // Message passing
   var channel = try tokioz.Channel([]const u8).init(allocator, 100);
   defer channel.deinit();
   
   // Sender/Receiver pattern
   try channel.send("message");
   const msg = try channel.recv();
   ```

4. **Non-blocking I/O**
   ```zig
   // Async TCP
   const stream = try tokioz.net.TcpStream.connect("127.0.0.1", 8080);
   try stream.writeAll("data");
   const response = try stream.readAll(allocator);
   
   // Async UDP
   const socket = try tokioz.net.UdpSocket.bind("0.0.0.0", 0);
   try socket.sendTo("data", address);
   ```

---

## 🗺️ Migration Strategy

### Phase 1: Foundation (Week 1-2)

1. **Core Runtime Integration**
   - [ ] Add TokioZ to all module dependencies
   - [ ] Create async-compatible main functions
   - [ ] Set up async test infrastructure
   - [ ] Implement async utilities module

2. **GhostWire Async Foundation**
   - [ ] Convert QUIC client/server to async
   - [ ] Implement async HTTP/3 handlers
   - [ ] Migrate WebSocket handling to async
   - [ ] Add async connection pooling

### Phase 2: Core Services (Week 3-4)

1. **Keystone Async Migration**
   - [ ] Async transaction processing
   - [ ] Non-blocking database operations
   - [ ] Async state synchronization
   - [ ] Concurrent ledger operations

2. **Covenant VM Async Integration**
   - [ ] Async contract execution
   - [ ] Non-blocking WASM runtime
   - [ ] Async state management
   - [ ] Concurrent ZVM operations

### Phase 3: Applications (Week 5-6)

1. **GWallet Async Migration**
   - [ ] Async RPC client/server
   - [ ] Non-blocking wallet operations
   - [ ] Async bridge functionality
   - [ ] Concurrent transaction handling

2. **ZNS Async Migration**
   - [ ] Async domain resolution
   - [ ] Non-blocking cache operations
   - [ ] Async gRPC services
   - [ ] Concurrent resolver operations

### Phase 4: Integration & Testing (Week 7-8)

1. **End-to-End Integration**
   - [ ] Full async pipeline testing
   - [ ] Performance benchmarking
   - [ ] Load testing with async runtime
   - [ ] Documentation updates

---

## 🔧 Module-by-Module Integration

### 1. GhostWire (`ghostwire/`)

**Priority: HIGH** - Network layer is critical for async benefits

#### Current Blocking Operations
- QUIC connection establishment
- HTTP/3 request handling
- WebSocket frame processing
- DNS queries

#### Async Migration Plan

```zig
// ghostwire/async_client.zig
const std = @import("std");
const tokioz = @import("tokioz");

pub const AsyncQuicClient = struct {
    runtime: *tokioz.Runtime,
    connection_pool: tokioz.Pool(QuicConnection),
    
    pub fn connect(self: *AsyncQuicClient, address: []const u8, port: u16) !*QuicConnection {
        return try tokioz.spawn(async self.connectImpl(address, port)).await();
    }
    
    async fn connectImpl(self: *AsyncQuicClient, address: []const u8, port: u16) !*QuicConnection {
        const stream = try tokioz.net.TcpStream.connect(address, port);
        // QUIC handshake with async I/O
        return self.performQuicHandshake(stream);
    }
    
    pub async fn sendRequest(self: *AsyncQuicClient, request: []const u8) ![]u8 {
        const conn = try self.connection_pool.acquire();
        defer self.connection_pool.release(conn);
        
        try conn.writeAll(request);
        return conn.readResponse(self.runtime.allocator);
    }
};
```

#### Migration Tasks
- [ ] Convert `ghostwire/zquic/core/connection.zig` to async
- [ ] Migrate `ghostwire/http1/server.zig` to use TokioZ
- [ ] Update `ghostwire/http2/server.zig` with async handlers
- [ ] Convert `ghostwire/websocket/server.zig` to async
- [ ] Implement async `ghostwire/proxy/reverse_proxy.zig`

#### Breaking Changes
- All network calls become `async` functions
- Connection constructors require `tokioz.Runtime`
- Callback-based APIs replaced with async/await

---

### 2. Keystone (`keystone/`)

**Priority: HIGH** - Core ledger operations need async for performance

#### Current Blocking Operations
- Database transactions
- File I/O for journal operations
- Crypto verification
- State synchronization

#### Async Migration Plan

```zig
// keystone/async_ledger.zig
const std = @import("std");
const tokioz = @import("tokioz");
const keystone = @import("keystone");

pub const AsyncLedger = struct {
    runtime: *tokioz.Runtime,
    tx_queue: tokioz.Channel(keystone.Transaction),
    state_cache: tokioz.Mutex(keystone.StateCache),
    
    pub async fn processTransaction(self: *AsyncLedger, tx: keystone.Transaction) !keystone.TransactionResult {
        // Async transaction validation
        const validation_task = tokioz.spawn(async self.validateTransaction(tx));
        const execution_task = tokioz.spawn(async self.executeTransaction(tx));
        
        // Concurrent validation and execution preparation
        const validation_result = try validation_task.await();
        if (!validation_result.valid) {
            return keystone.TransactionResult{ .status = .invalid };
        }
        
        const execution_result = try execution_task.await();
        
        // Async state update
        try self.updateStateAsync(tx, execution_result);
        
        return execution_result;
    }
    
    async fn updateStateAsync(self: *AsyncLedger, tx: keystone.Transaction, result: keystone.TransactionResult) !void {
        const lock = try self.state_cache.lock();
        defer lock.unlock();
        
        // Non-blocking state update
        try tokioz.spawn(async self.persistStateChange(tx, result)).await();
    }
};
```

#### Migration Tasks
- [ ] Convert `keystone/journal.zig` to async file operations
- [ ] Migrate `keystone/tx.zig` transaction processing
- [ ] Update `keystone/account.zig` with async balance operations
- [ ] Convert `keystone/audit.zig` to async logging
- [ ] Implement async `keystone/crypto_storage.zig`

---

### 3. Covenant (`covenant/`)

**Priority: HIGH** - VM execution benefits greatly from async

#### Current Blocking Operations
- Contract compilation
- WASM execution
- State storage/retrieval
- Gas metering

#### Async Migration Plan

```zig
// covenant/async_vm.zig
const std = @import("std");
const tokioz = @import("tokioz");
const covenant = @import("covenant");

pub const AsyncCovenantVM = struct {
    runtime: *tokioz.Runtime,
    execution_pool: tokioz.Pool(ExecutionContext),
    contract_cache: tokioz.Mutex(ContractCache),
    
    pub async fn executeContract(
        self: *AsyncCovenantVM,
        contract_addr: covenant.ContractAddress,
        function_data: []const u8,
        gas_limit: u64
    ) !covenant.ExecutionResult {
        const context = try self.execution_pool.acquire();
        defer self.execution_pool.release(context);
        
        // Async contract loading
        const contract = try tokioz.spawn(async self.loadContract(contract_addr)).await();
        
        // Async execution with timeout
        const execution_task = tokioz.spawn(async contract.execute(function_data, context));
        const timeout_task = tokioz.time.sleep(std.time.Duration.fromSecs(30));
        
        const result = try tokioz.select(.{ execution_task, timeout_task });
        
        return switch (result) {
            .first => |exec_result| exec_result,
            .second => covenant.ExecutionResult{ .status = .timeout },
        };
    }
    
    pub async fn deployContract(self: *AsyncCovenantVM, bytecode: []const u8) !covenant.ContractAddress {
        // Async compilation
        const compilation_task = tokioz.spawn(async self.compileContract(bytecode));
        const addr_generation_task = tokioz.spawn(async self.generateContractAddress(bytecode));
        
        const compiled_contract = try compilation_task.await();
        const contract_addr = try addr_generation_task.await();
        
        // Async storage
        try self.storeContractAsync(contract_addr, compiled_contract);
        
        return contract_addr;
    }
};
```

#### Migration Tasks
- [ ] Convert `covenant/root.zig` VM core to async
- [ ] Migrate contract execution to async with timeouts
- [ ] Implement async state management
- [ ] Add async WASM runtime integration
- [ ] Convert gas metering to async-aware system

---

### 4. GWallet (`gwallet/`)

**Priority: MEDIUM** - User-facing wallet operations

#### Current Blocking Operations
- RPC client requests
- Bridge server handling
- Transaction signing
- Balance queries

#### Async Migration Plan

```zig
// gwallet/src/async_wallet.zig
const std = @import("std");
const tokioz = @import("tokioz");
const gwallet = @import("gwallet");

pub const AsyncWallet = struct {
    runtime: *tokioz.Runtime,
    rpc_client: AsyncRpcClient,
    tx_queue: tokioz.Channel(gwallet.Transaction),
    
    pub async fn getBalance(self: *AsyncWallet, address: []const u8, token: []const u8) !gwallet.Balance {
        const rpc_request = gwallet.BalanceRequest{
            .address = address,
            .token = token,
        };
        
        return try self.rpc_client.call("eth_getBalance", rpc_request);
    }
    
    pub async fn sendTransaction(self: *AsyncWallet, tx: gwallet.Transaction) ![]const u8 {
        // Async transaction signing
        const signed_tx = try tokioz.spawn(async self.signTransaction(tx)).await();
        
        // Async broadcast
        const broadcast_task = tokioz.spawn(async self.broadcastTransaction(signed_tx));
        
        // Async monitoring
        const monitor_task = tokioz.spawn(async self.monitorTransaction(signed_tx.hash));
        
        const tx_hash = try broadcast_task.await();
        
        // Don't wait for confirmation, start monitoring in background
        tokioz.spawn(async monitor_task).detach();
        
        return tx_hash;
    }
};
```

#### Migration Tasks
- [ ] Convert `gwallet/src/bridge/api.zig` to async handlers
- [ ] Migrate `gwallet/src/protocol/ethereum_rpc.zig` to async
- [ ] Update `gwallet/src/core/wallet.zig` with async operations
- [ ] Convert CLI commands to async execution
- [ ] Implement async transaction monitoring

---

### 5. ZNS (`zns/`)

**Priority: MEDIUM** - Domain resolution benefits from async

#### Current Blocking Operations
- DNS queries
- gRPC service calls
- Cache operations
- Domain validation

#### Async Migration Plan

```zig
// zns/async_resolver.zig
const std = @import("std");
const tokioz = @import("tokioz");
const zns = @import("zns");

pub const AsyncResolver = struct {
    runtime: *tokioz.Runtime,
    cache: tokioz.Mutex(zns.Cache),
    resolvers: []AsyncDomainResolver,
    
    pub async fn resolve(self: *AsyncResolver, domain: []const u8) !zns.ResolveResult {
        // Check cache first (non-blocking)
        if (try self.checkCache(domain)) |cached_result| {
            return cached_result;
        }
        
        // Spawn parallel resolution tasks
        var resolution_tasks = std.ArrayList(tokioz.Task(zns.ResolveResult)).init(self.runtime.allocator);
        defer resolution_tasks.deinit();
        
        for (self.resolvers) |resolver| {
            const task = tokioz.spawn(async resolver.resolve(domain));
            try resolution_tasks.append(task);
        }
        
        // Wait for first successful resolution
        const result = try tokioz.select_first(resolution_tasks.items);
        
        // Cache result asynchronously
        tokioz.spawn(async self.cacheResult(domain, result)).detach();
        
        return result;
    }
    
    pub async fn resolveBatch(self: *AsyncResolver, domains: [][]const u8) ![]zns.ResolveResult {
        var batch_tasks = std.ArrayList(tokioz.Task(zns.ResolveResult)).init(self.runtime.allocator);
        defer batch_tasks.deinit();
        
        for (domains) |domain| {
            const task = tokioz.spawn(async self.resolve(domain));
            try batch_tasks.append(task);
        }
        
        return try tokioz.join_all(batch_tasks.items);
    }
};
```

#### Migration Tasks
- [ ] Convert `zns/resolver/universal.zig` to async
- [ ] Migrate `zns/cache/zqlite_cache.zig` to async operations
- [ ] Update gRPC services to async handlers
- [ ] Convert CLI commands to async execution
- [ ] Implement async batch resolution

---

### 6. Supporting Modules

#### Sigil (`sigil/`) - LOW Priority
- Convert identity operations to async
- Async signature verification
- Non-blocking key operations

#### Guardian (`guardian/`) - MEDIUM Priority  
- Async multisig operations
- Non-blocking consensus
- Async policy enforcement

#### ShadowCraft (`shadowcraft/`) - LOW Priority
- Async policy evaluation
- Non-blocking rule execution
- Async context management

---

## 📅 Implementation Timeline

### Week 1-2: Foundation Phase
```
Day 1-3: TokioZ Integration Setup
├── Add dependencies to all modules
├── Create async utilities module
├── Set up async test infrastructure
└── Basic async main functions

Day 4-7: GhostWire Async Foundation
├── Convert core QUIC operations
├── Async HTTP/3 basic handlers
├── WebSocket async migration
└── Connection pool implementation

Day 8-14: Core Network Stabilization
├── Integration testing
├── Performance baseline measurements
├── Bug fixes and optimization
└── Documentation updates
```

### Week 3-4: Core Services Phase
```
Day 15-21: Keystone Async Migration
├── Async transaction processing
├── Non-blocking database operations
├── Async state management
└── Performance testing

Day 22-28: Covenant VM Async Integration
├── Async contract execution
├── WASM runtime async integration
├── Async state management
└── Gas metering updates
```

### Week 5-6: Application Layer Phase
```
Day 29-35: GWallet Async Migration
├── Async RPC operations
├── Bridge async handlers
├── Transaction async processing
└── CLI async commands

Day 36-42: ZNS Async Migration
├── Async domain resolution
├── Cache async operations
├── gRPC async services
└── Batch resolution implementation
```

### Week 7-8: Integration & Testing Phase
```
Day 43-49: End-to-End Integration
├── Full pipeline async testing
├── Load testing and benchmarking
├── Performance optimization
└── Bug fixes

Day 50-56: Documentation & Release
├── API documentation updates
├── Migration guide creation
├── Example code updates
└── Release preparation
```

---

## 💥 Breaking Changes

### API Changes

1. **Function Signatures**
   ```zig
   // Before
   pub fn connect(address: []const u8, port: u16) !Connection
   
   // After
   pub async fn connect(address: []const u8, port: u16) !Connection
   ```

2. **Initialization**
   ```zig
   // Before
   var client = Client.init(allocator);
   
   // After
   var client = try AsyncClient.init(allocator, tokioz_runtime);
   ```

3. **Main Functions**
   ```zig
   // Before
   pub fn main() !void {
       // synchronous code
   }
   
   // After
   pub fn main() !void {
       const runtime = try tokioz.Runtime.init(allocator);
       defer runtime.deinit();
       
       try runtime.run(async asyncMain());
   }
   
   async fn asyncMain() !void {
       // async code
   }
   ```

### Configuration Changes

1. **Build Dependencies**
   - All modules now require TokioZ
   - Async test infrastructure needed
   - New compile-time flags for async features

2. **Runtime Requirements**
   - TokioZ runtime must be initialized
   - Async allocator management
   - Event loop integration

### Migration Compatibility

- **Gradual Migration**: Sync and async versions can coexist
- **Wrapper Functions**: Sync wrappers for async functions during transition
- **Feature Flags**: Compile-time async feature toggles

---

## 📈 Performance Benefits

### Expected Improvements

| Operation | Current (Sync) | After (Async) | Improvement |
|-----------|----------------|---------------|-------------|
| **QUIC Connections** | 100/sec | 10,000/sec | **100x** |
| **HTTP Requests** | 1,000/sec | 50,000/sec | **50x** |
| **Database Ops** | 500/sec | 10,000/sec | **20x** |
| **Contract Calls** | 200/sec | 5,000/sec | **25x** |
| **DNS Resolution** | 50/sec | 2,000/sec | **40x** |

### Resource Utilization

1. **Memory Usage**
   - Reduced by 60% due to efficient task scheduling
   - Better memory locality with async task pools
   - Reduced allocation overhead

2. **CPU Utilization**
   - 90%+ CPU utilization vs 30% with blocking I/O
   - Better multi-core scaling
   - Reduced context switching

3. **Network Efficiency**
   - Connection pooling and reuse
   - Parallel request processing
   - Reduced time-to-first-byte

### Scalability Metrics

```
Concurrent Operations Support:
├── Before: 100-500 operations
├── After:  10,000-50,000 operations
└── Improvement: 100x scalability

Memory per Operation:
├── Before: 8KB per blocking operation
├── After:  80 bytes per async task
└── Improvement: 100x memory efficiency

Response Time:
├── Before: 100ms average (blocking)
├── After:  5ms average (async)
└── Improvement: 20x faster response
```

---

## 🧪 Testing Strategy

### Async Testing Infrastructure

```zig
// tests/async_test_utils.zig
const std = @import("std");
const tokioz = @import("tokioz");

pub fn asyncTest(comptime test_fn: anytype) !void {
    const runtime = try tokioz.Runtime.init(std.testing.allocator);
    defer runtime.deinit();
    
    try runtime.run(async test_fn());
}

pub fn asyncBenchmark(comptime bench_fn: anytype, iterations: u32) !tokioz.BenchmarkResult {
    const runtime = try tokioz.Runtime.init(std.testing.allocator);
    defer runtime.deinit();
    
    const start_time = std.time.nanoTimestamp();
    
    var i: u32 = 0;
    while (i < iterations) : (i += 1) {
        try runtime.run(async bench_fn());
    }
    
    const end_time = std.time.nanoTimestamp();
    
    return tokioz.BenchmarkResult{
        .iterations = iterations,
        .total_time_ns = @intCast(end_time - start_time),
        .avg_time_ns = @intCast((end_time - start_time) / iterations),
    };
}
```

### Test Categories

1. **Unit Tests**
   ```zig
   test "async QUIC connection" {
       try asyncTest(testAsyncQuicConnection);
   }
   
   async fn testAsyncQuicConnection() !void {
       const client = try AsyncQuicClient.init(std.testing.allocator);
       defer client.deinit();
       
       const conn = try client.connect("127.0.0.1", 8080);
       defer conn.close();
       
       try std.testing.expect(conn.isConnected());
   }
   ```

2. **Integration Tests**
   ```zig
   test "async end-to-end transaction" {
       try asyncTest(testAsyncTransaction);
   }
   
   async fn testAsyncTransaction() !void {
       // Setup async components
       const wallet = try AsyncWallet.init(std.testing.allocator);
       const ledger = try AsyncLedger.init(std.testing.allocator);
       const vm = try AsyncCovenantVM.init(std.testing.allocator);
       
       // Execute async transaction
       const tx = try wallet.createTransaction("alice", "bob", 100);
       const result = try ledger.processTransaction(tx);
       
       try std.testing.expect(result.status == .success);
   }
   ```

3. **Load Tests**
   ```zig
   test "async load test - 10k concurrent connections" {
       try asyncTest(testAsyncLoadTest);
   }
   
   async fn testAsyncLoadTest() !void {
       const server = try AsyncServer.init(std.testing.allocator);
       defer server.deinit();
       
       try server.start("127.0.0.1", 8080);
       
       // Spawn 10k concurrent clients
       var tasks = std.ArrayList(tokioz.Task(void)).init(std.testing.allocator);
       defer tasks.deinit();
       
       var i: u32 = 0;
       while (i < 10000) : (i += 1) {
           const task = tokioz.spawn(async testClientConnection());
           try tasks.append(task);
       }
       
       // Wait for all clients to complete
       try tokioz.join_all(tasks.items);
   }
   ```

### Performance Benchmarks

```zig
// benchmarks/async_benchmarks.zig
test "benchmark async vs sync performance" {
    // Sync baseline
    const sync_result = try syncBenchmark(syncOperation, 1000);
    
    // Async performance
    const async_result = try asyncBenchmark(asyncOperation, 1000);
    
    const improvement = sync_result.avg_time_ns / async_result.avg_time_ns;
    
    std.debug.print("Performance improvement: {}x\n", .{improvement});
    try std.testing.expect(improvement >= 10); // Expect at least 10x improvement
}
```

---

## 📚 Documentation Updates

### API Documentation

1. **Async Function Documentation**
   ```zig
   /// Asynchronously connects to a QUIC server
   /// 
   /// This function is non-blocking and returns a Future that resolves
   /// to a QUIC connection. The connection is established using TokioZ
   /// runtime for optimal performance.
   ///
   /// # Examples
   /// ```zig
   /// const connection = try client.connect("example.com", 443);
   /// defer connection.close();
   /// ```
   ///
   /// # Errors
   /// - `error.NetworkUnreachable` if the server is not reachable
   /// - `error.ConnectionTimeout` if connection times out
   /// - `error.HandshakeFailed` if QUIC handshake fails
   pub async fn connect(self: *AsyncQuicClient, host: []const u8, port: u16) !*QuicConnection
   ```

2. **Migration Guide Updates**
   - Update SHROUD_ZVM_GUIDE.md with async examples
   - Add async patterns to all module documentation
   - Update API reference with async signatures

3. **Example Code Updates**
   ```zig
   // examples/async_wallet_usage.zig
   const std = @import("std");
   const shroud = @import("shroud");
   const tokioz = @import("tokioz");
   
   pub fn main() !void {
       const runtime = try tokioz.Runtime.init(std.heap.page_allocator);
       defer runtime.deinit();
       
       try runtime.run(async asyncWalletExample());
   }
   
   async fn asyncWalletExample() !void {
       // Async wallet operations
       const wallet = try shroud.gwallet.AsyncWallet.init(std.heap.page_allocator);
       defer wallet.deinit();
       
       // Concurrent balance checks
       const btc_task = tokioz.spawn(async wallet.getBalance("address1", "BTC"));
       const eth_task = tokioz.spawn(async wallet.getBalance("address1", "ETH"));
       const gcc_task = tokioz.spawn(async wallet.getBalance("address1", "GCC"));
       
       const btc_balance = try btc_task.await();
       const eth_balance = try eth_task.await();
       const gcc_balance = try gcc_task.await();
       
       std.debug.print("Balances - BTC: {}, ETH: {}, GCC: {}\n", .{ btc_balance, eth_balance, gcc_balance });
   }
   ```

### New Documentation Files

1. **ASYNC_PATTERNS.md** - Common async patterns and best practices
2. **TOKIOZ_INTEGRATION.md** - Detailed TokioZ integration guide
3. **PERFORMANCE_GUIDE.md** - Async performance optimization
4. **MIGRATION_COOKBOOK.md** - Step-by-step migration recipes

---

## ✅ Action Items Checklist

### Immediate (Week 1)
- [ ] ✅ Add TokioZ dependency to build.zig.zon
- [ ] ✅ Update all module build.zig files with TokioZ imports
- [ ] ⏳ Create async utilities module (`src/async_utils.zig`)
- [ ] ⏳ Set up async test infrastructure
- [ ] ⏳ Create async main function templates

### Phase 1: GhostWire (Week 2-3)
- [ ] ⏳ Convert `ghostwire/zquic/core/connection.zig` to async
- [ ] ⏳ Migrate `ghostwire/http1/server.zig` to async handlers
- [ ] ⏳ Update `ghostwire/http2/server.zig` with TokioZ
- [ ] ⏳ Convert `ghostwire/websocket/server.zig` to async
- [ ] ⏳ Implement `ghostwire/async_client.zig`
- [ ] ⏳ Add connection pooling with TokioZ

### Phase 2: Keystone (Week 3-4)
- [ ] ⏳ Convert `keystone/journal.zig` to async file operations
- [ ] ⏳ Migrate `keystone/tx.zig` transaction processing
- [ ] ⏳ Update `keystone/account.zig` with async operations
- [ ] ⏳ Convert `keystone/audit.zig` to async logging
- [ ] ⏳ Implement async state synchronization

### Phase 3: Covenant (Week 4-5)
- [ ] ⏳ Convert `covenant/root.zig` VM core to async
- [ ] ⏳ Migrate contract execution to async with timeouts
- [ ] ⏳ Implement async state management
- [ ] ⏳ Add async WASM runtime integration
- [ ] ⏳ Convert gas metering to async-aware system

### Phase 4: Applications (Week 5-6)
- [ ] ⏳ Convert `gwallet/src/bridge/api.zig` to async handlers
- [ ] ⏳ Migrate `gwallet/src/protocol/ethereum_rpc.zig` to async
- [ ] ⏳ Update `gwallet/src/core/wallet.zig` with async operations
- [ ] ⏳ Convert `zns/resolver/universal.zig` to async
- [ ] ⏳ Migrate `zns/cache/zqlite_cache.zig` to async operations

### Phase 5: Testing & Documentation (Week 7-8)
- [ ] ⏳ Implement comprehensive async test suite
- [ ] ⏳ Performance benchmarking and optimization
- [ ] ⏳ Update all documentation with async examples
- [ ] ⏳ Create migration guides and cookbooks
- [ ] ⏳ Final integration testing and bug fixes

---

## 🎯 Success Criteria

### Performance Targets
- [ ] **10x improvement** in concurrent connection handling
- [ ] **50x improvement** in HTTP request throughput  
- [ ] **20x improvement** in database operation speed
- [ ] **25x improvement** in smart contract execution rate
- [ ] **90%+ CPU utilization** under load

### Functionality Targets
- [ ] **All modules** successfully converted to async
- [ ] **Zero regressions** in existing functionality
- [ ] **Backward compatibility** maintained during transition
- [ ] **Complete test coverage** for async operations
- [ ] **Comprehensive documentation** updated

### Quality Targets
- [ ] **Production-ready** async implementation
- [ ] **Memory safety** maintained in async contexts
- [ ] **Error handling** robust across async boundaries
- [ ] **Debugging support** for async operations
- [ ] **Monitoring integration** for async performance

---

## 🚀 Next Steps

1. **Start Implementation** (Immediate)
   ```bash
   # Begin with foundation setup
   cd /data/projects/shroud
   
   # Create async utilities module
   mkdir -p src/async
   touch src/async/utils.zig
   touch src/async/runtime.zig
   touch src/async/testing.zig
   
   # Update main module
   # Add TokioZ imports to src/root.zig
   ```

2. **Team Coordination** (This Week)
   - Assign module owners for async migration
   - Set up async development environment
   - Create async coding standards document
   - Plan integration testing schedule

3. **Monitoring Setup** (Week 1)
   - Implement async performance metrics
   - Set up async debugging tools
   - Create async profiling infrastructure
   - Establish performance baselines

---

*This upgrade plan transforms SHROUD into a fully async-native framework, positioning it as one of the highest-performance blockchain and networking frameworks in the Zig ecosystem. With TokioZ v1.0.1 integration, SHROUD will achieve unprecedented scalability and efficiency.*

**🚀 Ready to go async! Let's build the future of high-performance Zig applications.**
