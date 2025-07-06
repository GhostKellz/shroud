const std = @import("std");

pub const CovenantError = error{
    ContractExecutionFailed,
    InvalidParameters,
    StateMismatch,
    CompilationFailed,
    InsufficientGas,
    AccessDenied,
    StateCorrupted,
    InvalidOpcode,
    StackOverflow,
    StackUnderflow,
    OutOfMemory,
};

pub const GasLimit = u64;
pub const ContractAddress = [20]u8;
pub const StateHash = [32]u8;

pub const ContractState = struct {
    storage: std.HashMap([32]u8, [32]u8, std.hash_map.HashMap([32]u8, [32]u8).Context, std.hash_map.default_max_load_percentage),
    balance: u256,
    nonce: u64,
    code_hash: [32]u8,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) ContractState {
        return ContractState{
            .storage = std.HashMap([32]u8, [32]u8, std.hash_map.HashMap([32]u8, [32]u8).Context, std.hash_map.default_max_load_percentage).init(allocator),
            .balance = 0,
            .nonce = 0,
            .code_hash = std.mem.zeroes([32]u8),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *ContractState) void {
        self.storage.deinit();
    }

    pub fn get(self: *const ContractState, key: [32]u8) ?[32]u8 {
        return self.storage.get(key);
    }

    pub fn set(self: *ContractState, key: [32]u8, value: [32]u8) !void {
        try self.storage.put(key, value);
    }
};

pub const ExecutionContext = struct {
    sender: ContractAddress,
    origin: ContractAddress,
    gas_limit: GasLimit,
    gas_used: GasLimit,
    value: u256,
    data: []const u8,
    block_number: u64,
    timestamp: u64,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, sender: ContractAddress, gas_limit: GasLimit) ExecutionContext {
        return ExecutionContext{
            .sender = sender,
            .origin = sender,
            .gas_limit = gas_limit,
            .gas_used = 0,
            .value = 0,
            .data = &.{},
            .block_number = 0,
            .timestamp = @intCast(std.time.timestamp()),
            .allocator = allocator,
        };
    }

    pub fn consumeGas(self: *ExecutionContext, amount: GasLimit) CovenantError!void {
        if (self.gas_used + amount > self.gas_limit) {
            return CovenantError.InsufficientGas;
        }
        self.gas_used += amount;
    }
};

pub const Contract = struct {
    address: ContractAddress,
    code: []const u8,
    state: ContractState,
    owner: ContractAddress,
    is_active: bool,

    pub fn init(allocator: std.mem.Allocator, address: ContractAddress, code: []const u8, owner: ContractAddress) Contract {
        return Contract{
            .address = address,
            .code = code,
            .state = ContractState.init(allocator),
            .owner = owner,
            .is_active = true,
        };
    }

    pub fn deinit(self: *Contract) void {
        self.state.deinit();
    }

    pub fn execute(self: *Contract, context: *ExecutionContext, function_sig: [4]u8, params: []const u8) CovenantError![]u8 {
        if (!self.is_active) {
            return CovenantError.AccessDenied;
        }

        try context.consumeGas(21000);

        return switch (std.mem.readIntBig(u32, &function_sig)) {
            0x70a08231 => self.balanceOf(context, params),
            0xa9059cbb => self.transfer(context, params),  
            0x095ea7b3 => self.approve(context, params),   
            0x23b872dd => self.transferFrom(context, params),
            else => CovenantError.InvalidOpcode,
        };
    }

    fn balanceOf(self: *Contract, context: *ExecutionContext, params: []const u8) CovenantError![]u8 {
        try context.consumeGas(400);
        
        if (params.len != 32) return CovenantError.InvalidParameters;
        
        const addr_key = params[0..32].*;
        const balance = self.state.get(addr_key) orelse std.mem.zeroes([32]u8);
        
        const result = try context.allocator.alloc(u8, 32);
        @memcpy(result, &balance);
        return result;
    }

    fn transfer(self: *Contract, context: *ExecutionContext, params: []const u8) CovenantError![]u8 {
        try context.consumeGas(5000);
        
        if (params.len != 64) return CovenantError.InvalidParameters;
        
        const to_addr = params[12..32].*;
        const amount = params[32..64].*;
        
        var sender_key: [32]u8 = undefined;
        @memcpy(sender_key[12..], &context.sender);
        
        const sender_balance = self.state.get(sender_key) orelse std.mem.zeroes([32]u8);
        const receiver_balance = self.state.get(to_addr) orelse std.mem.zeroes([32]u8);
        
        const sender_val = std.mem.readIntBig(u256, &sender_balance);
        const amount_val = std.mem.readIntBig(u256, &amount);
        const receiver_val = std.mem.readIntBig(u256, &receiver_balance);
        
        if (sender_val < amount_val) {
            return CovenantError.InvalidParameters;
        }
        
        var new_sender_balance: [32]u8 = undefined;
        var new_receiver_balance: [32]u8 = undefined;
        std.mem.writeIntBig(u256, &new_sender_balance, sender_val - amount_val);
        std.mem.writeIntBig(u256, &new_receiver_balance, receiver_val + amount_val);
        
        try self.state.set(sender_key, new_sender_balance);
        try self.state.set(to_addr, new_receiver_balance);
        
        const result = try context.allocator.alloc(u8, 32);
        std.mem.writeIntBig(u256, result[0..32], 1);
        return result;
    }

    fn approve(self: *Contract, context: *ExecutionContext, params: []const u8) CovenantError![]u8 {
        try context.consumeGas(5000);
        
        if (params.len != 64) return CovenantError.InvalidParameters;
        
        var allowance_key: [32]u8 = undefined;
        @memcpy(allowance_key[0..12], context.sender[0..12]);
        @memcpy(allowance_key[12..32], params[12..32]);
        
        const amount = params[32..64].*;
        try self.state.set(allowance_key, amount);
        
        const result = try context.allocator.alloc(u8, 32);
        std.mem.writeIntBig(u256, result[0..32], 1);
        return result;
    }

    fn transferFrom(self: *Contract, context: *ExecutionContext, params: []const u8) CovenantError![]u8 {
        _ = self;
        try context.consumeGas(7000);
        
        if (params.len != 96) return CovenantError.InvalidParameters;
        
        const result = try context.allocator.alloc(u8, 32);
        std.mem.writeIntBig(u256, result[0..32], 1);
        return result;
    }
};

pub const CovenantVM = struct {
    contracts: std.HashMap(ContractAddress, Contract, std.hash_map.HashMap(ContractAddress, Contract).Context, std.hash_map.default_max_load_percentage),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) CovenantVM {
        return CovenantVM{
            .contracts = std.HashMap(ContractAddress, Contract, std.hash_map.HashMap(ContractAddress, Contract).Context, std.hash_map.default_max_load_percentage).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *CovenantVM) void {
        var iterator = self.contracts.iterator();
        while (iterator.next()) |entry| {
            entry.value_ptr.deinit();
        }
        self.contracts.deinit();
    }

    pub fn deployContract(self: *CovenantVM, code: []const u8, constructor_params: []const u8, deployer: ContractAddress) !ContractAddress {
        _ = constructor_params;
        var address: ContractAddress = undefined;
        std.crypto.hash.Blake3.hash(code, address[0..], .{});
        
        const contract_instance = Contract.init(self.allocator, address, code, deployer);
        try self.contracts.put(address, contract_instance);
        
        return address;
    }

    pub fn call(self: *CovenantVM, target: ContractAddress, context: *ExecutionContext, function_sig: [4]u8, params: []const u8) ![]u8 {
        var contract_instance = self.contracts.getPtr(target) orelse return CovenantError.InvalidParameters;
        return contract_instance.execute(context, function_sig, params);
    }

    pub fn getContract(self: *const CovenantVM, address: ContractAddress) ?*const Contract {
        return self.contracts.getPtr(address);
    }
};

pub fn version() []const u8 {
    return "0.3.0";
}

pub fn createVM(allocator: std.mem.Allocator) CovenantVM {
    return CovenantVM.init(allocator);
}

// ZVM Native Contract Interface
pub fn zigContract(comptime name: []const u8) type {
    return struct {
        const Self = @This();
        
        state: ContractState,
        allocator: std.mem.Allocator,
        
        pub fn init(allocator: std.mem.Allocator, constructor_params: []const u8) !Self {
            _ = constructor_params;
            return Self{
                .state = ContractState.init(allocator),
                .allocator = allocator,
            };
        }
        
        pub fn deinit(self: *Self) void {
            self.state.deinit();
        }
        
        pub fn call(self: *Self, method: []const u8, params: []const u8, context: *ExecutionContext) CovenantError![]u8 {
            const method_hash = std.hash_map.hashString(method);
            
            return switch (method_hash) {
                std.hash_map.hashString("balance_of") => self.balanceOf(params, context),
                std.hash_map.hashString("transfer") => self.transfer(params, context),
                std.hash_map.hashString("get_info") => self.getInfo(params, context),
                else => CovenantError.InvalidOpcode,
            };
        }
        
        pub fn balanceOf(self: *Self, params: []const u8, context: *ExecutionContext) CovenantError![]u8 {
            try context.consumeGas(400);
            
            if (params.len != 32) return CovenantError.InvalidParameters;
            
            const addr_key = params[0..32].*;
            const balance = self.state.get(addr_key) orelse std.mem.zeroes([32]u8);
            
            const result = try context.allocator.alloc(u8, 32);
            @memcpy(result, &balance);
            return result;
        }
        
        pub fn transfer(self: *Self, params: []const u8, context: *ExecutionContext) CovenantError![]u8 {
            _ = self;
            try context.consumeGas(5000);
            
            if (params.len != 64) return CovenantError.InvalidParameters;
            
            const result = try context.allocator.alloc(u8, 32);
            std.mem.writeIntBig(u256, result[0..32], 1);
            return result;
        }
        
        pub fn getInfo(self: *Self, params: []const u8, context: *ExecutionContext) CovenantError![]u8 {
            _ = self;
            _ = params;
            try context.consumeGas(200);
            
            const result = try context.allocator.alloc(u8, name.len);
            @memcpy(result, name);
            return result;
        }
    };
}

pub const SimpleToken = zigContract("SimpleToken");

pub const ZVMRuntime = struct {
    contract_registry: std.HashMap([]const u8, ContractDefinition, std.hash_map.HashMap([]const u8, ContractDefinition).Context, std.hash_map.default_max_load_percentage),
    allocator: std.mem.Allocator,
    
    const ContractDefinition = struct {
        source_hash: [32]u8,
        bytecode: []const u8,
        abi: []const u8,
        created_at: u64,
    };
    
    pub fn init(allocator: std.mem.Allocator) ZVMRuntime {
        return ZVMRuntime{
            .contract_registry = std.HashMap([]const u8, ContractDefinition, std.hash_map.HashMap([]const u8, ContractDefinition).Context, std.hash_map.default_max_load_percentage).init(allocator),
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *ZVMRuntime) void {
        var iter = self.contract_registry.iterator();
        while (iter.next()) |entry| {
            self.allocator.free(entry.value_ptr.bytecode);
            self.allocator.free(entry.value_ptr.abi);
        }
        self.contract_registry.deinit();
    }
    
    pub fn compileContract(self: *ZVMRuntime, name: []const u8, source: []const u8) !ContractAddress {
        var source_hash: [32]u8 = undefined;
        std.crypto.hash.Blake3.hash(source, source_hash[0..], .{});
        
        const bytecode = try self.allocator.dupe(u8, source);
        const abi = try std.fmt.allocPrint(self.allocator, "{{\"name\":\"{s}\",\"methods\":[\"balance_of\",\"transfer\"]}}", .{name});
        
        const definition = ContractDefinition{
            .source_hash = source_hash,
            .bytecode = bytecode,
            .abi = abi,
            .created_at = @intCast(std.time.timestamp()),
        };
        
        try self.contract_registry.put(name, definition);
        
        var address: ContractAddress = undefined;
        @memcpy(&address, source_hash[0..20]);
        return address;
    }
    
    pub fn executeContract(self: *ZVMRuntime, name: []const u8, method: []const u8, params: []const u8, context: *ExecutionContext) ![]u8 {
        _ = self.contract_registry.get(name) orelse return CovenantError.InvalidParameters;
        
        var token = try SimpleToken.init(context.allocator, "");
        defer token.deinit();
        
        return token.call(method, params, context);
    }
};

pub fn deployZigContract(vm: *CovenantVM, runtime: *ZVMRuntime, name: []const u8, contract_source: []const u8, deployer: ContractAddress) !ContractAddress {
    const contract_addr = try runtime.compileContract(name, contract_source);
    
    const contract_instance = Contract.init(vm.allocator, contract_addr, contract_source, deployer);
    try vm.contracts.put(contract_addr, contract_instance);
    
    return contract_addr;
}

test "covenant vm creation" {
    var vm = createVM(std.testing.allocator);
    defer vm.deinit();
    
    var runtime = ZVMRuntime.init(std.testing.allocator);
    defer runtime.deinit();
    
    const deployer = std.mem.zeroes(ContractAddress);
    _ = try deployZigContract(&vm, &runtime, "TestToken", "contract TestToken {}", deployer);
}

test "contract execution" {
    var vm = createVM(std.testing.allocator);
    defer vm.deinit();
    
    var runtime = ZVMRuntime.init(std.testing.allocator);
    defer runtime.deinit();
    
    const deployer = std.mem.zeroes(ContractAddress);
    _ = try deployZigContract(&vm, &runtime, "TestToken", "contract TestToken {}", deployer);
    
    var context = ExecutionContext.init(std.testing.allocator, deployer, 100000);
    
    const result = try runtime.executeContract("TestToken", "get_info", "", &context);
    defer std.testing.allocator.free(result);
    
    try std.testing.expect(result.len > 0);
}