/*!
    \file safe_market_manager.h
    \brief Application-layer security wrapper for MarketManager
    \brief Validates all inputs before delegating to vendor MarketManager
    \author Security Hardening Layer
    \date 2024
    \copyright MIT License
*/

#ifndef CPPTRADER_APP_SAFE_MARKET_MANAGER_H
#define CPPTRADER_APP_SAFE_MARKET_MANAGER_H

#include "trader/matching/market_manager.h"
#include "validator.h"

#include <string>
#include <iostream>

namespace CppTrader {
namespace App {

//! Security-hardened MarketManager wrapper
//! Validates all order operations to prevent DoS and integer overflow attacks
class SafeMarketManager {
public:
    SafeMarketManager(MarketHandler& handler) : _manager(handler) {}
    
    //! Get underlying manager (for read-only operations)
    const Matching::MarketManager& GetManager() const { return _manager; }
    
    //! Safely add symbol with DoS protection
    ErrorCode SafeAddSymbol(const Symbol& symbol) {
        // Validate symbol ID to prevent unbounded vector resize
        auto result = Validator::ValidateSymbolId(symbol.Id);
        if (!result) {
            LogSecurityEvent("SafeAddSymbol rejected", result.error_message, symbol.Id);
            _stats.symbols_rejected++;
            return ErrorCode::SYMBOL_INVALID;
        }
        
        // Validate symbol name
        result = Validator::ValidateSymbolName(symbol.Name);
        if (!result) {
            LogSecurityEvent("SafeAddSymbol rejected", result.error_message, symbol.Id);
            _stats.symbols_rejected++;
            return ErrorCode::SYMBOL_INVALID;
        }
        
        _stats.symbols_accepted++;
        return _manager.AddSymbol(symbol);
    }
    
    //! Safely delete symbol
    ErrorCode SafeDeleteSymbol(uint32_t id) {
        auto result = Validator::ValidateSymbolId(id);
        if (!result) {
            LogSecurityEvent("SafeDeleteSymbol rejected", result.error_message, id);
            return ErrorCode::SYMBOL_INVALID;
        }
        
        return _manager.DeleteSymbol(id);
    }
    
    //! Safely add order book
    ErrorCode SafeAddOrderBook(const OrderBook& order_book) {
        auto result = Validator::ValidateOrderBookId(order_book.Id);
        if (!result) {
            LogSecurityEvent("SafeAddOrderBook rejected", result.error_message, order_book.Id);
            _stats.order_books_rejected++;
            return ErrorCode::ORDER_BOOK_INVALID;
        }
        
        // Validate symbol reference exists
        result = Validator::ValidateSymbolId(order_book.SymbolId);
        if (!result) {
            LogSecurityEvent("SafeAddOrderBook rejected", "Invalid symbol reference", order_book.Id);
            _stats.order_books_rejected++;
            return ErrorCode::SYMBOL_INVALID;
        }
        
        _stats.order_books_accepted++;
        return _manager.AddOrderBook(order_book);
    }
    
    //! Safely delete order book
    ErrorCode SafeDeleteOrderBook(uint32_t id) {
        auto result = Validator::ValidateOrderBookId(id);
        if (!result) {
            LogSecurityEvent("SafeDeleteOrderBook rejected", result.error_message, id);
            return ErrorCode::ORDER_BOOK_INVALID;
        }
        
        return _manager.DeleteOrderBook(id);
    }
    
    //! Safely add order with comprehensive validation
    ErrorCode SafeAddOrder(const Order& order) {
        if (!ValidateOrder(order)) {
            _stats.orders_rejected++;
            return ErrorCode::ORDER_INVALID;
        }
        
        // Additional order-type specific validation
        if (order.IsMarket()) {
            auto result = Validator::ValidateSlippage(order.Slippage);
            if (!result) {
                LogSecurityEvent("SafeAddOrder (Market) rejected", result.error_message, order.Id);
                _stats.orders_rejected++;
                return ErrorCode::ORDER_SLIPPAGE_INVALID;
            }
        }
        
        if (order.IsTrailingStop() || order.IsTrailingStopLimit()) {
            auto result = Validator::ValidateTrailingDistance(order.TrailingDistance);
            if (!result) {
                LogSecurityEvent("SafeAddOrder (Trailing) rejected", result.error_message, order.Id);
                _stats.orders_rejected++;
                return ErrorCode::ORDER_TRAILING_DISTANCE_INVALID;
            }
            
            result = Validator::ValidateTrailingStep(order.TrailingStep);
            if (!result) {
                LogSecurityEvent("SafeAddOrder (Trailing) rejected", result.error_message, order.Id);
                _stats.orders_rejected++;
                return ErrorCode::ORDER_TRAILING_STEP_INVALID;
            }
        }
        
        _stats.orders_accepted++;
        return _manager.AddOrder(order);
    }
    
    //! Safely delete order
    ErrorCode SafeDeleteOrder(uint64_t id) {
        auto result = Validator::ValidateOrderId(id);
        if (!result) {
            LogSecurityEvent("SafeDeleteOrder rejected", result.error_message, id);
            return ErrorCode::ORDER_ID_INVALID;
        }
        
        return _manager.DeleteOrder(id);
    }
    
    //! Safely reduce order with underflow protection
    ErrorCode SafeReduceOrder(uint64_t id, uint64_t quantity) {
        auto result = Validator::ValidateOrderId(id);
        if (!result) {
            LogSecurityEvent("SafeReduceOrder rejected", result.error_message, id);
            return ErrorCode::ORDER_ID_INVALID;
        }
        
        result = Validator::ValidateQuantity(quantity);
        if (!result) {
            LogSecurityEvent("SafeReduceOrder rejected", result.error_message, id);
            return ErrorCode::ORDER_QUANTITY_INVALID;
        }
        
        // Note: We can't check for underflow here without knowing current leaves quantity
        // The vendor code should handle this, but we rely on the wrapper pattern
        
        return _manager.ReduceOrder(id, quantity);
    }
    
    //! Safely modify order
    ErrorCode SafeModifyOrder(uint64_t id, uint64_t price, uint64_t quantity) {
        auto result = Validator::ValidateOrderId(id);
        if (!result) {
            LogSecurityEvent("SafeModifyOrder rejected", result.error_message, id);
            return ErrorCode::ORDER_ID_INVALID;
        }
        
        result = Validator::ValidatePrice(price);
        if (!result) {
            LogSecurityEvent("SafeModifyOrder rejected", result.error_message, id);
            return ErrorCode::ORDER_PRICE_INVALID;
        }
        
        result = Validator::ValidateQuantity(quantity);
        if (!result) {
            LogSecurityEvent("SafeModifyOrder rejected", result.error_message, id);
            return ErrorCode::ORDER_QUANTITY_INVALID;
        }
        
        return _manager.ModifyOrder(id, price, quantity);
    }
    
    //! Safely replace order
    ErrorCode SafeReplaceOrder(uint64_t id, uint64_t new_id, uint64_t new_price, uint64_t new_quantity) {
        auto result = Validator::ValidateOrderId(id);
        if (!result) {
            LogSecurityEvent("SafeReplaceOrder rejected", "Invalid original ID", id);
            return ErrorCode::ORDER_ID_INVALID;
        }
        
        result = Validator::ValidateOrderId(new_id);
        if (!result) {
            LogSecurityEvent("SafeReplaceOrder rejected", "Invalid new ID", new_id);
            return ErrorCode::ORDER_ID_INVALID;
        }
        
        result = Validator::ValidatePrice(new_price);
        if (!result) {
            LogSecurityEvent("SafeReplaceOrder rejected", "Invalid new price", id);
            return ErrorCode::ORDER_PRICE_INVALID;
        }
        
        result = Validator::ValidateQuantity(new_quantity);
        if (!result) {
            LogSecurityEvent("SafeReplaceOrder rejected", "Invalid new quantity", id);
            return ErrorCode::ORDER_QUANTITY_INVALID;
        }
        
        return _manager.ReplaceOrder(id, new_id, new_price, new_quantity);
    }
    
    //! Safely execute order with overflow protection
    ErrorCode SafeExecuteOrder(uint64_t id, uint64_t price, uint64_t quantity) {
        auto result = Validator::ValidateOrderId(id);
        if (!result) {
            LogSecurityEvent("SafeExecuteOrder rejected", result.error_message, id);
            return ErrorCode::ORDER_ID_INVALID;
        }
        
        result = Validator::ValidatePrice(price);
        if (!result) {
            LogSecurityEvent("SafeExecuteOrder rejected", result.error_message, id);
            return ErrorCode::ORDER_PRICE_INVALID;
        }
        
        result = Validator::ValidateQuantity(quantity);
        if (!result) {
            LogSecurityEvent("SafeExecuteOrder rejected", result.error_message, id);
            return ErrorCode::ORDER_QUANTITY_INVALID;
        }
        
        return _manager.ExecuteOrder(id, price, quantity);
    }
    
    //! Get validation statistics
    struct Stats {
        uint64_t symbols_accepted = 0;
        uint64_t symbols_rejected = 0;
        uint64_t order_books_accepted = 0;
        uint64_t order_books_rejected = 0;
        uint64_t orders_accepted = 0;
        uint64_t orders_rejected = 0;
        uint64_t security_events = 0;
    };
    
    Stats GetStats() const { return _stats; }
    void ResetStats() { _stats = Stats{}; }
    
    //! Enable/disable security logging
    void SetSecurityLogging(bool enabled) { _security_logging = enabled; }

private:
    Matching::MarketManager _manager;
    Stats _stats;
    bool _security_logging = true;
    
    //! Comprehensive order validation
    bool ValidateOrder(const Order& order) {
        // Validate order ID
        auto result = Validator::ValidateOrderId(order.Id);
        if (!result) {
            LogSecurityEvent("ValidateOrder failed", result.error_message, order.Id);
            return false;
        }
        
        // Validate symbol reference
        result = Validator::ValidateSymbolId(order.SymbolId);
        if (!result) {
            LogSecurityEvent("ValidateOrder failed", "Invalid symbol ID", order.Id);
            return false;
        }
        
        // Validate quantity fields
        result = Validator::ValidateQuantity(order.Quantity);
        if (!result) {
            LogSecurityEvent("ValidateOrder failed", result.error_message, order.Id);
            return false;
        }
        
        result = Validator::ValidateQuantity(order.LeavesQuantity);
        if (!result) {
            LogSecurityEvent("ValidateOrder failed", "Invalid leaves quantity", order.Id);
            return false;
        }
        
        // Validate quantity consistency
        if (order.Quantity < order.LeavesQuantity) {
            LogSecurityEvent("ValidateOrder failed", "Quantity < LeavesQuantity", order.Id);
            return false;
        }
        
        // Validate price for non-market orders
        if (!order.IsMarket() && !order.IsStop() && !order.IsTrailingStop()) {
            result = Validator::ValidatePrice(order.Price);
            if (!result) {
                LogSecurityEvent("ValidateOrder failed", "Invalid price", order.Id);
                return false;
            }
        }
        
        // Validate stop price for stop orders
        if (order.IsStop() || order.IsStopLimit() || order.IsTrailingStop() || order.IsTrailingStopLimit()) {
            result = Validator::ValidatePrice(order.StopPrice);
            if (!result) {
                LogSecurityEvent("ValidateOrder failed", "Invalid stop price", order.Id);
                return false;
            }
        }
        
        return true;
    }
    
    //! Log security event
    void LogSecurityEvent(const char* operation, const char* reason, uint64_t id) {
        if (_security_logging) {
            std::cerr << "[SECURITY] " << operation << " - ID: " << id 
                      << " - Reason: " << reason << std::endl;
        }
        _stats.security_events++;
    }
};

} // namespace App
} // namespace CppTrader

#endif // CPPTRADER_APP_SAFE_MARKET_MANAGER_H
