
### **Performance Impact**
- **Abstraction Overhead**: Shroud wrapper adds 20-30% latency
- **Limited Control**: Cannot optimize connection pooling, flow control
- **Missing Features**: No zero-copy networking, custom congestion control
- **Scalability**: Current implementation caps at ~1K connections vs 10K+ target

find a way around this if possible. 

Possibly build zquic further so there is no performance hit so it can be native zquic hooked into shroud? not sure? ideas? ... 
