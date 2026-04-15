# C++ Fundamentals: Struct vs Class and Deleted Operations

Two questions came up that deserve deeper exploration: the technical difference between `struct` and `class`, and what happens when you delete copy operations. These fundamentals underpin the safety patterns in CppTrader.

## Question 1: `struct` vs `class`

They're nearly identical in C++—only two technical differences exist.

### Default Access

```cpp
struct S {
    int x;  // public by default
};

class C {
    int x;  // private by default
};

S s;
s.x = 42;   // OK - public

C c;
c.x = 42;   // ERROR - private
```

### Default Inheritance

```cpp
struct Base { };

struct SDerived : Base { };   // public inheritance
class CDerived : Base { };    // private inheritance

SDerived s;
Base* sb = &s;   // OK - public inheritance

CDerived c;
Base* cb = &c;   // ERROR - private inheritance
```

### Convention Over Rules

The C++ community uses convention to differentiate them:

```cpp
// struct: Plain Old Data (POD), no invariants
struct PriceLevel {
    uint64_t Price;
    uint64_t TotalVolume;
};

// class: Encapsulated state with behavior, maintains invariants
class OrderBook {
    std::map<uint64_t, LevelNode*> _bids;
    std::map<uint64_t, LevelNode*> _asks;
    
public:
    void AddOrder(const Order& o);
    LevelUpdate DeleteOrder(OrderNode* order);
    
    // Invariant: best bid < best ask (no crossed market)
    bool IsValid() const noexcept;
};
```

**Key insight:** Use `struct` when all members can be public without breaking anything. Use `class` when you need to protect internal state and enforce constraints.

### In CppTrader

Looking at the actual codebase:

```cpp
// include/trader/matching/order.h (lines 127-213)
struct Order
{
    uint64_t Id;
    uint32_t SymbolId;
    OrderType Type;
    OrderSide Side;
    uint64_t Price;
    uint64_t StopPrice;
    uint64_t Quantity;
    uint64_t ExecutedQuantity;
    uint64_t LeavesQuantity;
    OrderTimeInForce TimeInForce;
    uint64_t MaxVisibleQuantity;
    uint64_t Slippage;
    int64_t TrailingDistance;
    int64_t TrailingStep;

    Order() noexcept = default;
    Order(uint64_t id, uint32_t symbol, OrderType type, OrderSide side, 
          uint64_t price, uint64_t stop_price, uint64_t quantity,
          OrderTimeInForce tif = OrderTimeInForce::GTC, ...) noexcept;
    Order(const Order&) noexcept = default;
    Order(Order&&) noexcept = default;
    ~Order() noexcept = default;

    bool IsMarket() const noexcept { return Type == OrderType::MARKET; }
    bool IsBuy() const noexcept { return Side == OrderSide::BUY; }
    bool IsHidden() const noexcept { return MaxVisibleQuantity == 0; }
    // ...
};
```

`Order` is a simple data carrier with all public members—`struct` makes sense. It has no invariants to protect; any combination of values is valid.

Compare to:

```cpp
// include/trader/matching/order_book.h (lines 28-43)
class OrderBook
{
    friend class MarketManager;

public:
    OrderBook(MarketManager& manager, const Symbol& symbol);
    OrderBook(const OrderBook&) = delete;
    OrderBook(OrderBook&&) = delete;
    ~OrderBook();

    OrderBook& operator=(const OrderBook&) = delete;
    OrderBook& operator=(OrderBook&&) = delete;

    explicit operator bool() const noexcept { return !empty(); }
    bool empty() const noexcept { return size() == 0; }
    // ...

private:
    MarketManager& _manager;  // Reference to parent - must be valid
    Symbol _symbol;           // Owned copy
    LevelNode* _best_bid;   // Pointer to best bid level
    LevelNode* _best_ask;   // Pointer to best ask level
    Levels _bids;
    Levels _asks;
    // ... internal state for stop orders, trailing stops, etc.
};
```

`OrderBook` maintains complex internal state with invariants (best bid < best ask, consistent price levels). It's a `class` with private members and deleted copy operations—encapsulation is critical.

---

## Question 2: Deleted Copy Operations

Two related but distinct deletions:

| Declaration | What It Deletes | Prevents |
|-------------|-----------------|----------|
| `MarketManager(const MarketManager&) = delete;` | Copy constructor | `MarketManager b = a;` <br> `MarketManager b(a);` |
| `MarketManager& operator=(const MarketManager&) = delete;` | Copy assignment | `b = a;` |

### Why Delete Both?

From `include/trader/matching/market_manager.h` (lines 52-57):

```cpp
class MarketManager
{
public:
    MarketManager();
    MarketManager(MarketHandler& market_handler);
    MarketManager(const MarketManager&) = delete;      // No copying
    MarketManager(MarketManager&&) = delete;           // No moving
    ~MarketManager();

    MarketManager& operator=(const MarketManager&) = delete;  // No copy assign
    MarketManager& operator=(MarketManager&&) = delete;       // No move assign
    // ...
};
```

**Why delete all four?** `MarketManager` owns `OrderBook*` pointers and maintains a `MarketHandler&` reference. Copying would duplicate pointer ownership; moving would invalidate the reference. Both are catastrophic.

### The Reference Member Problem

```cpp
// include/trader/matching/market_manager.h (line 276)
class MarketManager
{
    // ...
private:
    MarketHandler* _market_handler;  // Optional handler pointer
    // OR
    MarketHandler& _market_handler;  // Required handler reference
};
```

If `MarketManager` stores `MarketHandler& _market_handler`:
- **Cannot reseat:** References must be initialized and never changed
- **Cannot copy:** What would the new object's reference point to?
- **Cannot move:** The reference still can't be reseated

This forces deletion of all four operations.

### Why MarketHandler Is Deleted

```cpp
// include/trader/matching/market_handler.h (lines 32-43)
class MarketHandler
{
    friend class MarketManager;

public:
    MarketHandler() = default;
    MarketHandler(const MarketHandler&) = delete;
    MarketHandler(MarketHandler&&) = delete;
    virtual ~MarketHandler() = default;

    MarketHandler& operator=(const MarketHandler&) = delete;
    MarketHandler& operator=(MarketHandler&&) = delete;

protected:
    virtual void onAddOrder(const Order& order) {}
    virtual void onExecuteOrder(const Order& order, uint64_t price, uint64_t quantity) {}
    // ...
};
```

`MarketHandler` is a **polymorphic base class**. Copying would slice the derived object. The virtual destructor already deletes copies; these declarations make the intent explicit.

### The Rule of Five in CppTrader

Let's trace the special members for `Order` (a value type):

```cpp
// include/trader/matching/order.h (lines 200-212)
struct Order
{
    Order() noexcept = default;
    Order(uint64_t id, ...) noexcept;           // User-defined ctor
    Order(const Order&) noexcept = default;     // Copyable
    Order(Order&&) noexcept = default;          // Movable
    ~Order() noexcept = default;                // Trivial dtor

    Order& operator=(const Order&) noexcept = default;  // Copy assignable
    Order& operator=(Order&&) noexcept = default;       // Move assignable
};
```

`Order` is fully copyable/movable—it's just data. All members are value types (integers), so the compiler-generated operations work fine.

Now `OrderNode` (extends Order for linked list storage):

```cpp
// include/trader/matching/order.h (lines 301-313)
struct OrderNode : public Order, public CppCommon::List<OrderNode>::Node
{
    LevelNode* Level;  // Pointer to parent level

    OrderNode(const Order& order) noexcept;
    OrderNode(const OrderNode&) noexcept = default;
    OrderNode(OrderNode&&) noexcept = default;
    ~OrderNode() noexcept = default;

    OrderNode& operator=(const Order& order) noexcept;
    OrderNode& operator=(const OrderNode&) noexcept = default;
    OrderNode& operator=(OrderNode&&) noexcept = default;
};
```

Interesting: `OrderNode` defaults copies despite the `LevelNode*` pointer. This is safe because:
1. `Level` is set to `nullptr` in the constructor (line 218: `Level(nullptr)`)
2. The list node base class manages its own linkage
3. Copying an `OrderNode` doesn't duplicate it in the list—just copies the data

### Compiler-Generated Matrix

| Member | Generated When | Deleted When |
|--------|---------------|--------------|
| Destructor | Default | User-declared destructor (even `=default`) |
| Copy ctor | Default | User-declared move operation, destructor, or copy assignment |
| Copy assign | Default | User-declared move operation, destructor, or copy ctor |
| Move ctor | Default | User-declared copy operation, destructor, or assignment |
| Move assign | Default | User-declared copy operation, destructor, or copy ctor |

**Key insight:** From `MarketHandler`:
- Virtual destructor declared (`~MarketHandler() = default`)
- This alone deletes the move operations!
- Explicit deletions make intent clear

### Summary Table: CppTrader Types

| Type | struct/class | Copies | Moves | Why |
|------|--------------|--------|-------|-----|
| `Order` | struct | ✅ default | ✅ default | Pure data |
| `Level` | struct | ✅ default | ✅ default | Pure data |
| `Symbol` | struct | ✅ default | ✅ default | Pure data |
| `OrderNode` | struct | ✅ default | ✅ default | List manages linkage |
| `LevelNode` | struct | ✅ default | ✅ default | Tree manages linkage |
| `OrderBook` | class | ❌ delete | ❌ delete | Reference member `_manager` |
| `MarketManager` | class | ❌ delete | ❌ delete | Manages `OrderBook*` pointers |
| `MarketHandler` | class | ❌ delete | ❌ delete | Polymorphic base |

---

## Summary

1. **`struct` vs `class`** — Only differences are default access (`public` vs `private`) and inheritance. CppTrader uses `struct` for `Order`, `Level`, `Symbol` (data carriers) and `class` for `OrderBook`, `MarketManager` (stateful managers).

2. **Deleted operations** — Copy constructor and copy assignment are distinct. CppTrader deletes both (and moves) for types with reference members or polymorphic bases.

3. **Reference members** — Force deletion of all operations. `OrderBook` has `MarketManager& _manager`; `MarketManager` optionally has `MarketHandler& _market_handler`.

4. **Rule of Five** — `Order` is a value type with all defaults. `MarketHandler` deletes everything because it's a polymorphic base with virtual functions.

These aren't just style preferences—they're contracts with the compiler that prevent slicing, double-free, and dangling reference bugs.
