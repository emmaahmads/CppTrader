# Pushing C++ to the Edge: Modern Techniques for HFT Security Wrappers

This post explores how we can take a production security wrapper (`SafeITCHHandler`) and push it toward bleeding-edge C++. We're trading backwards compatibility for performance, safety, and expressiveness. This is the code you write when nanoseconds matter and you control your toolchain.

## The Starting Point

Our current `SafeITCHHandler` is solid but conservative:

```cpp
bool SafeProcess(void* buffer, size_t size) {
    auto result = Validator::ValidateITCHMessageSize(size);
    if (!result) {
        _last_error = result.error_message;
        return false;
    }
    // ... validation logic with raw pointers
    return _handler.Process(buffer, size);
}
```

The TODOs in the codebase hint at where we want to go. Let's explore the edgier alternatives.

## 1. `std::span` - Death to Pointer+Size Pairs

**Current:** `void* buffer, size_t size` - Two parameters, no bounds safety

**Edgier:** `std::span<const std::byte>` - Single parameter, bounds-checked, type-safe

```cpp
// Old school - prone to mismatched buffer/size
bool SafeProcess(void* buffer, size_t size);

// Modern - span carries both, is bounds-safe
#include <span>

bool SafeProcess(std::span<const std::byte> data) {
    // data.size() is always correct
    // data subspan: auto header = data.subspan(0, 2);
    // Bounds checking on every access
    
    if (data.size() < 2) {
        return false;
    }
    
    uint8_t msg_size = std::to_integer<uint8_t>(data[0]);
    // msg_size is now type-safe, not raw byte arithmetic
}
```

**Why this is edgy:**
- Requires C++20
- `std::byte` forces you to think about raw memory (no accidental char arithmetic)
- `.subspan()` is bounds-checked in debug, fast in release
- Single parameter eliminates mismatch bugs

**The HFT angle:** In optimized builds, `std::span` compiles down to pointer+size. Zero overhead abstraction.

## 2. `[[nodiscard]] - Make the Compiler Your Enforcement Agent

Current code can silently ignore return values:

```cpp
safe_handler.GetStats();  // Forgot to capture - no warning
safe_handler.ResetStats();  // Called but return value ignored... wait, it returns void
```

**Edgier:** Force the caller to acknowledge the result:

```cpp
class SafeITCHHandler {
public:
    [[nodiscard]] bool SafeProcess(std::span<const std::byte> data);
    
    [[nodiscard]] Stats GetStats() const;
    
    // Error message might be null - make caller think about it
    [[nodiscard]] std::optional<std::string_view> GetLastError() const;
    
    void ResetStats() noexcept;  // Void is fine - noexcept for HFT path
};
```

Now these are compile-time errors:

```cpp
safe_handler.SafeProcess(data);  // ERROR: ignoring nodiscard return
safe_handler.GetStats();          // ERROR: not using the stats

// Must explicitly acknowledge:
[[maybe_unused]] auto stats = safe_handler.GetStats();
if (!safe_handler.SafeProcess(data)) { /* handle error */ }
```

**Why this is edgy:** It turns runtime bugs into compile-time failures. In HFT, an unchecked error can cost millions.

## 3. `noexcept` - The HFT Performance Contract

Exceptions are death in the hot path. They break optimization, add branching, and can trigger stack unwinding.

**Current:** Implicitly throwing

**Edgier:** Explicitly non-throwing

```cpp
class SafeITCHHandler {
public:
    // Hot path - must not throw
    [[nodiscard]] bool SafeProcess(std::span<const std::byte> data) noexcept;
    
    // Stats never allocate - also noexcept
    [[nodiscard]] Stats GetStats() const noexcept;
    
    void ResetStats() noexcept {
        _stats = {0, 0, 0, 0};  // std::array is noexcept assignable
    }
};
```

**Critical insight:** `noexcept` on virtual functions or callbacks allows the compiler to omit exception handling code entirely. In HFT, this is free performance.

**But what about errors?** Validation failures are **expected**, not exceptional. Return `bool` or use `std::optional`/`std::expected`. Don't throw.

## 4. `std::expected` (C++23) - Structured Error Handling Without Exceptions

**Current:** Return `bool` + side-channel error message

**Edgier:** Return value OR error, enforced by the type system

```cpp
#include <expected>  // C++23

enum class ErrorCode {
    BUFFER_TOO_SMALL,
    INVALID_MESSAGE_TYPE,
    SIZE_MISMATCH,
    NULL_BUFFER
};

// Returns bool on success, ErrorCode on failure
[[nodiscard]] std::expected<bool, ErrorCode> SafeProcess(std::span<const std::byte> data) noexcept {
    if (data.empty()) {
        return std::unexpected(ErrorCode::BUFFER_TOO_SMALL);
    }
    
    // ... validation ...
    
    return _handler.Process(data);  // Return true on success
}

// Usage - must handle both cases:
auto result = handler.SafeProcess(data);
if (!result) {
    switch (result.error()) {
        case ErrorCode::BUFFER_TOO_SMALL: Log("Buffer issue"); break;
        // Exhaustive handling enforced by compiler
    }
}
```

**Why this is edgy:**
- No exceptions (performance)
- No side-channel error state (thread safety)
- Exhaustive error handling enforced by type system
- Composable with monadic operations (C++23)

## 5. `std::optional` + `std::string_view` - Zero-Allocation Error Messages

**Current:** `const char*` to error string - lifetime issues, heap allocations

**Edgier:** `std::optional<std::string_view>` - borrow semantics, no allocations

```cpp
class SafeITCHHandler {
    // Static error messages - compile-time constants
    static constexpr std::string_view ERR_BUFFER_NULL = "Buffer cannot be null";
    static constexpr std::string_view ERR_SIZE_MISMATCH = "ITCH message size mismatch";
    
    // Current: const char* - who owns this? Where does it point?
    const char* _last_error = nullptr;  // Dangling pointer risk
    
    // Edgier: optional string_view - no ownership, no allocation
    std::optional<std::string_view> _last_error;
    
public:
    [[nodiscard]] std::optional<std::string_view> GetLastError() const noexcept {
        return _last_error;
    }
};

// Usage - zero heap allocations:
if (auto err = handler.GetLastError(); err.has_value()) {
    std::cerr << *err << std::endl;  // Just pointer+length, no copy
}
```

**Why this is edgy:**
- `std::string_view` is `{const char*, size_t}` - never allocates
- `std::optional` is zero-overhead over the value itself
- Thread-safe: no shared mutable state (unlike `const char*` globals)

## 6. `std::array` for Cache-Line-Friendly Layout

**Current:** `Stats` struct with 4 uint64_t members

**Edgier:** Guarantee cache-line alignment for atomic operations

```cpp
#include <array>
#include <atomic>

class SafeITCHHandler {
    // Current - struct might have padding, not cache-line aligned
    struct Stats {
        uint64_t total_messages;
        uint64_t rejected_messages;
        uint64_t size_violations;
        uint64_t type_violations;
    };
    
    // Edgier - cache-line aligned, enables atomic operations
    alignas(64) std::array<std::atomic<uint64_t>, 4> _stats{};
    
public:
    [[nodiscard]] Stats GetStats() const noexcept {
        return {
            _stats[0].load(std::memory_order_relaxed),
            _stats[1].load(std::memory_order_relaxed),
            _stats[2].load(std::memory_order_relaxed),
            _stats[3].load(std::memory_order_relaxed)
        };
    }
    
    void RecordRejection() noexcept {
        _stats[1].fetch_add(1, std::memory_order_relaxed);  // Lock-free
    }
};
```

**Why this is edgy:**
- `alignas(64)` - cache line size on x86_64
- `std::atomic` with `memory_order_relaxed` - thread-safe, zero contention
- Lock-free statistics in multithreaded HFT paths

## Putting It All Together: The Edgy SafeITCHHandler

```cpp
#include <span>
#include <expected>
#include <optional>
#include <string_view>
#include <array>
#include <atomic>
#include <cstdint>

namespace CppTrader::Secure {

enum class ITCHError {
    BUFFER_TOO_SMALL,
    SIZE_MISMATCH,
    INVALID_TYPE,
    NULL_BUFFER
};

class SafeITCHHandler {
    ITCH::ITCHHandler& _handler;
    std::optional<std::string_view> _last_error;
    alignas(64) std::array<std::atomic<uint64_t>, 4> _stats{};
    
    static constexpr std::string_view ERR_NULL = "Buffer null";
    static constexpr std::string_view ERR_SIZE = "Size mismatch";
    
public:
    explicit SafeITCHHandler(ITCH::ITCHHandler& handler) noexcept 
        : _handler(handler) {}
    
    [[nodiscard]] std::expected<bool, ITCHError> SafeProcess(
        std::span<const std::byte> data
    ) noexcept {
        if (data.empty()) {
            _last_error = ERR_SIZE;
            return std::unexpected(ITCHError::BUFFER_TOO_SMALL);
        }
        
        if (!ValidateMessageBuffer(data)) {
            return std::unexpected(ITCHError::SIZE_MISMATCH);
        }
        
        _stats[0].fetch_add(1, std::memory_order_relaxed);
        return _handler.Process(data);
    }
    
    [[nodiscard]] std::optional<std::string_view> GetLastError() const noexcept {
        return _last_error;
    }
    
    struct Stats {
        uint64_t total, rejected, size_violations, type_violations;
    };
    
    [[nodiscard]] Stats GetStats() const noexcept {
        return {
            _stats[0].load(std::memory_order_relaxed),
            _stats[1].load(std::memory_order_relaxed),
            _stats[2].load(std::memory_order_relaxed),
            _stats[3].load(std::memory_order_relaxed)
        };
    }
    
    void ResetStats() noexcept {
        for (auto& s : _stats) {
            s.store(0, std::memory_order_relaxed);
        }
    }
    
private:
    [[nodiscard]] bool ValidateMessageBuffer(std::span<const std::byte> data) noexcept;
};

} // namespace CppTrader::Secure
```

## What We Gained

| Aspect | Old | Edgy |
|--------|-----|------|
| Type safety | `void*` + size | `std::span<std::byte>` |
| Error handling | Side-channel `const char*` | `std::expected` + `std::optional` |
| Performance | Potentially throwing | `noexcept` everywhere |
| Thread safety | None | Lock-free atomics |
| Memory safety | Raw pointers | Bounds-checked span |
| Compile-time enforcement | None | `[[nodiscard]]` |

## Trade-offs

This is **edgier** C++, meaning:
- Requires C++23 (`std::expected`)
- Less portable (GCC 13+, Clang 17+, MSVC 2022+)
- Steeper learning curve for the team
- Longer compile times with modules/concepts

But for HFT where you control the toolchain and every nanosecond matters? This is the sweet spot.

## The Philosophy

Modern C++ isn't about writing "C with classes." It's about:
1. **Type safety** - Let the compiler catch bugs
2. **Zero-cost abstractions** - Don't pay for what you don't use
3. **Explicit contracts** - `noexcept`, `[[nodiscard]]`, `const` correctness
4. **Composability** - `std::expected`, `std::optional`, `std::span`

The TODOs in the original codebase were breadcrumbs. Follow them, and you arrive at a system that's simultaneously safer and faster.

---

*Write code that the compiler can reason about. The optimizer will thank you.*
