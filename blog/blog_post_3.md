# HFT Architecture Deep Dive: POD Types, Threading Models, and Resource Management

Earlier conversations today touched on fundamental C++ patterns that appear repeatedly in high-frequency trading systems. Let's connect the dots between template metaprogramming, data layout, object lifetimes, and thread safety in the context of market data handlers.

## The Template Streaming Operator

Consider the `SystemEventMessage` struct in a typical ITCH handler:

```cpp
struct SystemEventMessage {
    char Type;
    uint16_t StockLocate;
    uint16_t TrackingNumber;
    uint64_t Timestamp;
    char EventCode;

    template <class TOutputStream>
    friend TOutputStream& operator<<(TOutputStream& stream, const SystemEventMessage& message);
};
```

The `template <class TOutputStream>` declaration often confuses developers coming from languages with runtime polymorphism. This is **compile-time polymorphism**, not runtime. The template parameter `TOutputStream` doesn't mean the struct can have "any member class decided at runtime." It means the streaming operator works with **any type that supports the `<<` operation**—`std::cout`, `std::stringstream`, `std::ofstream`, or custom logging classes.

**Why this matters for HFT:**
- Zero virtual dispatch overhead—resolved at compile time
- Same binary layout as a C struct—safe for direct memory mapping from network buffers
- Works with your logging infrastructure without inheritance or virtual functions

The implementation typically looks like:

```cpp
template <class TOutputStream>
inline TOutputStream& operator<<(TOutputStream& stream, const SystemEventMessage& msg) {
    stream << "SystemEventMessage(Type=" << WriteChar(msg.Type)
           << "; StockLocate=" << msg.StockLocate
           << "; Timestamp=" << msg.Timestamp << ")";
    return stream;
}
```

## POD Types: Struct vs Class

A common misconception: "structs are POD, classes are not." This is wrong.

In C++, `struct` and `class` differ only in **default access**: `struct` defaults to public, `class` to private. What determines POD (Plain Old Data) status—or in modern C++, "standard-layout and trivial"—is the internal structure:

| Property | POD Required | Why It Matters for HFT |
|----------|--------------|------------------------|
| No virtual functions | Yes | No vtable pointer overhead |
| No virtual base classes | Yes | Predictable memory layout |
| No user-defined constructors | Yes | Compiler can trivially construct |
| Uniform access control | Yes | All public or all private |
| Trivial destructor | Yes | No cleanup code to run |

**POD example (class keyword):**
```cpp
class PriceLevel {  // class, not struct
public:             // explicit public section
    uint64_t price;
    uint32_t quantity;
    Side side;      // enum: Buy or Sell
};
// sizeof(PriceLevel) == 16 bytes, no padding surprises
```

**Not POD (despite struct keyword):**
```cpp
struct NotPod {
    virtual void update() {}  // Virtual function = not POD
    uint64_t price;
};
// Contains hidden vtable pointer, breaks binary serialization
```

**HFT implication:** ITCH protocol messages are parsed via direct memory casting. POD guarantees the binary layout matches the wire format exactly—no hidden members, no padding surprises.

```cpp
// Safe: SystemEventMessage is POD
SystemEventMessage* msg = reinterpret_cast<SystemEventMessage*>(network_buffer);
```

## Constructor Taxonomy in Resource Management

HFT systems manage resources: network buffers, file handles, memory-mapped files, order book state. Understanding constructor types is essential for correct resource semantics.

### 1. Default Constructor
```cpp
OrderBook book;  // Default-constructed
```
Creates an object without parameters. Often `= default` for POD types, or initializes empty state.

### 2. Parameterized Constructor
```cpp
OrderBook book(symbol_id, max_depth);
```
Initializes with specific values. In HFT, these often take primitive parameters (not strings) to avoid heap allocations in hot paths.

### 3. Copy Constructor
```cpp
OrderBook book2 = book1;  // Copy
```
Duplicates an object. **Critical for HFT:** If your class manages heap memory (order buffers, price levels), you must implement or delete the copy constructor. The compiler-generated version does shallow copies—dangling pointers and double-free bugs.

### 4. Move Constructor (C++11)
```cpp
OrderBook book2 = std::move(book1);  // Transfer ownership
```
Steals resources instead of copying. Essential for returning large objects from functions without allocation overhead.

### 5. Rule of Five

If you define any of these five special member functions, you probably need to define or delete all of them:

1. Destructor
2. Copy constructor
3. Copy assignment
4. Move constructor
5. Move assignment

**HFT example—RAII for network buffers:**

```cpp
class NetworkBuffer {
    uint8_t* _data;
    size_t _size;
    
public:
    explicit NetworkBuffer(size_t size) 
        : _data(new uint8_t[size]), _size(size) {}
    
    ~NetworkBuffer() { delete[] _data; }
    
    // Copy: duplicate memory (expensive but safe)
    NetworkBuffer(const NetworkBuffer& other)
        : _data(new uint8_t[other._size]), _size(other._size) {
        std::memcpy(_data, other._data, _size);
    }
    
    NetworkBuffer& operator=(const NetworkBuffer& other) {
        if (this != &other) {
            delete[] _data;
            _data = new uint8_t[other._size];
            _size = other._size;
            std::memcpy(_data, other._data, _size);
        }
        return *this;
    }
    
    // Move: steal pointer (cheap)
    NetworkBuffer(NetworkBuffer&& other) noexcept
        : _data(other._data), _size(other._size) {
        other._data = nullptr;  // Leave moved-from object valid
        other._size = 0;
    }
    
    NetworkBuffer& operator=(NetworkBuffer&& other) noexcept {
        if (this != &other) {
            delete[] _data;
            _data = other._data;
            _size = other._size;
            other._data = nullptr;
        }
        return *this;
    }
};
```

**Destructor note:** In HFT, destructors run on hot paths when objects leave scope. Keep them `noexcept` and minimal—no logging, no network calls, no exceptions.

## Thread Safety: Compatible vs. Safe

The `ITCHHandler` class header contains this warning:

```cpp
/*!
    \brief NASDAQ ITCH handler
    
    Not thread-safe.
*/
```

This doesn't mean "cannot be used in multi-threaded programs." It means **instances cannot be shared between threads simultaneously**.

### Why ITCHHandler Is Not Thread-Safe

Looking at the implementation:

```cpp
class ITCHHandler {
private:
    size_t _size;                    // Current message size being parsed
    std::vector<uint8_t> _cache;     // Partial message buffer
};
```

These members track parsing state across `Process()` calls. Consider two threads sharing one handler:

```cpp
// Thread A starts processing a message
_size = 0;
_cache.push_back(byte_from_message_A);  // A's data

// Context switch to Thread B
if (_size == 0) {  // True—A hasn't set it yet
    _cache.push_back(byte_from_message_B);  // B's data mixed with A's!
}
```

**Race conditions:**
- `_size` read/write: Thread A reads stale value after Thread B modifies it
- `_cache.insert()`: Vector reallocation invalidates pointers; interleaved inserts corrupt data
- `_cache.clear()`: Thread A clears data Thread B just inserted

### Thread-Compatible: The HFT Pattern

`ITCHHandler` is **thread-compatible**, not thread-safe. This is intentional. In HFT architecture:

```cpp
// One handler per thread (thread-compatible)
void market_data_worker(int core_id, NetworkFeed feed) {
    pin_thread_to_core(core_id);  // Dedicate CPU
    
    ITCHHandler handler;  // Local instance—no sharing
    
    while (feed.is_connected()) {
        Packet packet = feed.read();
        handler.Process(packet.data, packet.size);  // Safe—only this thread touches handler
    }
}

// Launch 4 threads, each with dedicated handler
std::vector<std::thread> threads;
for (int i = 0; i < 4; ++i) {
    threads.emplace_back(market_data_worker, i, feeds[i]);
}
```

**Architecture benefits:**
- No mutex contention (locks are microseconds—death in HFT)
- No cache coherency overhead between cores
- Linear scalability with core count
- NUMA-aware: each core's handler stays in local memory

### What Can Be Shared

Read-only data after initialization is safe to share:

```cpp
// Loaded at startup, never modified
const std::unordered_map<uint16_t, SymbolInfo> symbol_directory;

// Each thread has own handler, reads shared const data
class MyHandler : public ITCHHandler {
    bool onMessage(const AddOrderMessage& msg) override {
        const SymbolInfo& symbol = symbol_directory.at(msg.StockLocate);
        // Safe: read-only access to shared data
        return process_order(symbol, msg);
    }
};
```

**Thread-safety summary:**

| Pattern | Shareable? | HFT Usage |
|---------|-----------|-----------|
| One handler, multiple threads | No | Never |
| One handler per thread | Yes (by design) | Standard practice |
| Read-only lookup tables | Yes | Symbol directories, config |
| Lock-free queues (SPSC) | Yes | Inter-thread communication |

## Putting It All Together: A Minimal HFT Data Handler

Here's how these concepts compose in practice:

```cpp
// 1. POD message struct for binary protocol parsing
struct MarketDataMessage {
    uint64_t timestamp;
    uint32_t symbol_id;
    uint64_t order_id;
    uint32_t price;
    uint32_t quantity;
    char side;  // 'B' or 'S'
};
static_assert(sizeof(MarketDataMessage) == 29, "Unexpected padding");

// 2. RAII buffer with Rule of Five
class AlignedBuffer {
    uint8_t* _data;
    size_t _size;
    
public:
    explicit AlignedBuffer(size_t size) 
        : _data(static_cast<uint8_t*>(aligned_alloc(64, size))), _size(size) {}
    
    ~AlignedBuffer() { free(_data); }
    
    // Deleted copy (expensive, avoid in HFT)
    AlignedBuffer(const AlignedBuffer&) = delete;
    AlignedBuffer& operator=(const AlignedBuffer&) = delete;
    
    // Implemented move (cheap)
    AlignedBuffer(AlignedBuffer&& other) noexcept 
        : _data(other._data), _size(other._size) {
        other._data = nullptr;
    }
    
    uint8_t* data() const noexcept { return _data; }
    size_t size() const noexcept { return _size; }
};

// 3. Thread-compatible handler (not thread-safe)
class MarketDataHandler {
    OrderBook _local_book;           // Per-thread order book
    alignas(64) Stats _stats{};      // Cache-line aligned stats
    
public:
    void process(const MarketDataMessage& msg) noexcept {
        // No locks—this handler is owned by one thread
        switch (msg.side) {
            case 'B': _local_book.add_bid(msg.price, msg.quantity); break;
            case 'S': _local_book.add_ask(msg.price, msg.quantity); break;
        }
        _stats.messages_processed++;
    }
    
    const OrderBook& book() const noexcept { return _local_book; }
};

// 4. Thread-per-core architecture
void trading_worker(int cpu_id, NetworkInterface& nic) {
    pin_to_cpu(cpu_id);
    
    AlignedBuffer buffer(4096);      // Per-thread buffer (RAII)
    MarketDataHandler handler;        // Per-thread handler (thread-compatible)
    
    while (running) {
        size_t len = nic.receive(buffer.data(), buffer.size());
        const MarketDataMessage* msg = 
            reinterpret_cast<const MarketDataMessage*>(buffer.data());
        
        handler.process(*msg);  // No contention, no locks
    }
}
```

## Key Takeaways

1. **Templates enable compile-time polymorphism**—flexible streaming without runtime overhead
2. **POD is about layout, not keywords**—`class` can be POD, `struct` can contain vtables
3. **Rule of Five governs resource management**—if you manage memory, implement or delete all five special members
4. **Destructors must be `noexcept` and minimal** in hot paths
5. **Thread-compatible ≠ thread-safe**—HFT scales via dedicated instances per thread, not shared state
6. **Parallel is fine, sharing is the problem**—one handler per thread eliminates synchronization overhead

The CppTrader codebase demonstrates these principles: POD message structs for wire-format compatibility, explicit resource management in constructors/destructors, and thread-compatible handlers designed for single-threaded execution with linear scalability.

---

*In HFT, the winning architecture is often the one that avoids sharing entirely.*
