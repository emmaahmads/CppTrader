/*!
    \file safe_itch_handler.h
    \brief Application-layer security wrapper for NASDAQ ITCH handler
    \brief Validates ITCH messages before processing to prevent buffer overflows
    \author Security Hardening Layer
    \date 2024
    \copyright MIT License
*/

#ifndef CPPTRADER_APP_SAFE_ITCH_HANDLER_H
#define CPPTRADER_APP_SAFE_ITCH_HANDLER_H

#include "trader/providers/nasdaq/itch_handler.h"
#include "validator.h"

#include <cstdint>
#include <cstring>

namespace CppTrader {
namespace App {

//! ITCH message type constants with expected sizes for validation
namespace ITCHMessageSizes {
    constexpr size_t SYSTEM_EVENT_MIN = 12;
    constexpr size_t SYSTEM_EVENT_MAX = 12;
    constexpr size_t STOCK_DIRECTORY_MIN = 39;
    constexpr size_t STOCK_DIRECTORY_MAX = 39;
    constexpr size_t STOCK_TRADING_ACTION_MIN = 26;
    constexpr size_t STOCK_TRADING_ACTION_MAX = 26;
    constexpr size_t REG_SHO_MIN = 20;
    constexpr size_t REG_SHO_MAX = 20;
    constexpr size_t MARKET_PARTICIPANT_POSITION_MIN = 26;
    constexpr size_t MARKET_PARTICIPANT_POSITION_MAX = 26;
    constexpr size_t MWCB_DECLINE_MIN = 36;
    constexpr size_t MWCB_DECLINE_MAX = 36;
    constexpr size_t MWCB_STATUS_MIN = 13;
    constexpr size_t MWCB_STATUS_MAX = 13;
    constexpr size_t IPO_QUOTING_MIN = 28;
    constexpr size_t IPO_QUOTING_MAX = 28;
    constexpr size_t ADD_ORDER_MIN = 36;
    constexpr size_t ADD_ORDER_MAX = 36;
    constexpr size_t ADD_ORDER_MPID_MIN = 37;
    constexpr size_t ADD_ORDER_MPID_MAX = 37;
    constexpr size_t ORDER_EXECUTED_MIN = 31;
    constexpr size_t ORDER_EXECUTED_MAX = 31;
    constexpr size_t ORDER_EXECUTED_WITH_PRICE_MIN = 36;
    constexpr size_t ORDER_EXECUTED_WITH_PRICE_MAX = 36;
    constexpr size_t ORDER_CANCEL_MIN = 23;
    constexpr size_t ORDER_CANCEL_MAX = 23;
    constexpr size_t ORDER_DELETE_MIN = 19;
    constexpr size_t ORDER_DELETE_MAX = 19;
    constexpr size_t ORDER_REPLACE_MIN = 35;
    constexpr size_t ORDER_REPLACE_MAX = 35;
    constexpr size_t TRADE_MIN = 44;
    constexpr size_t TRADE_MAX = 44;
    constexpr size_t CROSS_TRADE_MIN = 40;
    constexpr size_t CROSS_TRADE_MAX = 40;
    constexpr size_t BROKEN_TRADE_MIN = 19;
    constexpr size_t BROKEN_TRADE_MAX = 19;
    constexpr size_t NOII_MIN = 50;
    constexpr size_t NOII_MAX = 50;
    constexpr size_t RPII_MIN = 20;
    constexpr size_t RPII_MAX = 20;
    constexpr size_t LULD_AUCTION_COLLAR_MIN = 35;
    constexpr size_t LULD_AUCTION_COLLAR_MAX = 35;
}

//! ITCH message type identifiers
namespace ITCHMessageTypes {
    constexpr char SYSTEM_EVENT = 'S';
    constexpr char STOCK_DIRECTORY = 'R';
    constexpr char STOCK_TRADING_ACTION = 'H';
    constexpr char REG_SHO = 'Y';
    constexpr char MARKET_PARTICIPANT_POSITION = 'L';
    constexpr char MWCB_DECLINE = 'V';
    constexpr char MWCB_STATUS = 'W';
    constexpr char IPO_QUOTING = 'K';
    constexpr char ADD_ORDER = 'A';
    constexpr char ADD_ORDER_MPID = 'F';
    constexpr char ORDER_EXECUTED = 'E';
    constexpr char ORDER_EXECUTED_WITH_PRICE = 'C';
    constexpr char ORDER_CANCEL = 'X';
    constexpr char ORDER_DELETE = 'D';
    constexpr char ORDER_REPLACE = 'U';
    constexpr char TRADE = 'P';
    constexpr char CROSS_TRADE = 'Q';
    constexpr char BROKEN_TRADE = 'B';
    constexpr char NOII = 'I';
    constexpr char RPII = 'N';
    constexpr char LULD_AUCTION_COLLAR = 'J';
}

//! Security-hardened ITCH handler wrapper
//! Validates message sizes before delegating to vendor ITCHHandler
class SafeITCHHandler {
public:
    SafeITCHHandler(ITCH::ITCHHandler& handler) : _handler(handler) {}
    
    //! Safely process ITCH buffer with comprehensive validation
    bool SafeProcess(void* buffer, size_t size) {
        // Validate overall buffer size
        auto result = Validator::ValidateITCHMessageSize(size);
        if (!result) {
            _last_error = result.error_message;
            return false;
        }
        
        // Ensure buffer is not null
        if (buffer == nullptr) {
            _last_error = "Buffer cannot be null";
            return false;
        }
        
        // Validate individual message sizes in the buffer
        if (!ValidateMessageBuffer(buffer, size)) {
            return false;
        }
        
        // All validations passed - delegate to vendor handler
        return _handler.Process(buffer, size);
    }
    
    //! Safely process a single ITCH message
    bool SafeProcessMessage(void* buffer, size_t size) {
        auto result = Validator::ValidateITCHMessageSize(size);
        if (!result) {
            _last_error = result.error_message;
            return false;
        }
        
        if (buffer == nullptr) {
            _last_error = "Buffer cannot be null";
            return false;
        }
        
        if (!ValidateSingleMessage(buffer, size)) {
            return false;
        }
        
        return _handler.ProcessMessage(buffer, size);
    }
    
    //! Get last error message
    const char* GetLastError() const {
        return _last_error;
    }
    
    //! Get detailed validation statistics
    struct Stats {
        uint64_t total_messages;
        uint64_t rejected_messages;
        uint64_t size_violations;
        uint64_t type_violations;
    };
    
    Stats GetStats() const {
        return _stats;
    }
    
    //! Reset statistics
    void ResetStats() {
        _stats = {0, 0, 0, 0};
    }

private:
    ITCH::ITCHHandler& _handler;
    const char* _last_error = nullptr;
    Stats _stats{0, 0, 0, 0};
    
    //! Validate message buffer - check each message
    bool ValidateMessageBuffer(void* buffer, size_t size) {
        const uint8_t* data = static_cast<const uint8_t*>(buffer);
        size_t remaining = size;
        
        while (remaining > 0) {
            // Need at least 2 bytes: message size (1 byte) + message type (1 byte)
            if (remaining < 2) {
                _last_error = "Insufficient data for message header";
                _stats.rejected_messages++;
                _stats.size_violations++;
                return false;
            }
            
            // ITCH message format: 1 byte size + message data
            uint8_t msg_size = data[0];
            char msg_type = static_cast<char>(data[1]);
            
            _stats.total_messages++;
            
            // Check if message fits in remaining buffer
            // msg_size includes the size byte itself
            if (msg_size == 0 || msg_size > remaining) {
                _last_error = "Message size exceeds buffer";
                _stats.rejected_messages++;
                _stats.size_violations++;
                return false;
            }
            
            // Validate specific message type and size
            if (!ValidateMessageTypeAndSize(msg_type, msg_size)) {
                _stats.rejected_messages++;
                _stats.type_violations++;
                return false;
            }
            
            // Advance to next message
            data += msg_size;
            remaining -= msg_size;
        }
        
        return true;
    }
    
    //! Validate a single message
    bool ValidateSingleMessage(void* buffer, size_t size) {
        const uint8_t* data = static_cast<const uint8_t*>(buffer);
        
        if (size < 1) {
            _last_error = "Message too small for type byte";
            _stats.rejected_messages++;
            _stats.size_violations++;
            return false;
        }
        
        char msg_type = static_cast<char>(data[0]);
        _stats.total_messages++;
        
        if (!ValidateMessageTypeAndSize(msg_type, size)) {
            _stats.rejected_messages++;
            return false;
        }
        
        return true;
    }
    
    //! Validate message type has correct size
    bool ValidateMessageTypeAndSize(char type, size_t size) {
        using namespace ITCHMessageSizes;
        using namespace ITCHMessageTypes;
        
        size_t expected_min = 0;
        size_t expected_max = 0;
        
        switch (type) {
            case SYSTEM_EVENT:
                expected_min = SYSTEM_EVENT_MIN;
                expected_max = SYSTEM_EVENT_MAX;
                break;
            case STOCK_DIRECTORY:
                expected_min = STOCK_DIRECTORY_MIN;
                expected_max = STOCK_DIRECTORY_MAX;
                break;
            case STOCK_TRADING_ACTION:
                expected_min = STOCK_TRADING_ACTION_MIN;
                expected_max = STOCK_TRADING_ACTION_MAX;
                break;
            case REG_SHO:
                expected_min = REG_SHO_MIN;
                expected_max = REG_SHO_MAX;
                break;
            case MARKET_PARTICIPANT_POSITION:
                expected_min = MARKET_PARTICIPANT_POSITION_MIN;
                expected_max = MARKET_PARTICIPANT_POSITION_MAX;
                break;
            case MWCB_DECLINE:
                expected_min = MWCB_DECLINE_MIN;
                expected_max = MWCB_DECLINE_MAX;
                break;
            case MWCB_STATUS:
                expected_min = MWCB_STATUS_MIN;
                expected_max = MWCB_STATUS_MAX;
                break;
            case IPO_QUOTING:
                expected_min = IPO_QUOTING_MIN;
                expected_max = IPO_QUOTING_MAX;
                break;
            case ADD_ORDER:
                expected_min = ADD_ORDER_MIN;
                expected_max = ADD_ORDER_MAX;
                break;
            case ADD_ORDER_MPID:
                expected_min = ADD_ORDER_MPID_MIN;
                expected_max = ADD_ORDER_MPID_MAX;
                break;
            case ORDER_EXECUTED:
                expected_min = ORDER_EXECUTED_MIN;
                expected_max = ORDER_EXECUTED_MAX;
                break;
            case ORDER_EXECUTED_WITH_PRICE:
                expected_min = ORDER_EXECUTED_WITH_PRICE_MIN;
                expected_max = ORDER_EXECUTED_WITH_PRICE_MAX;
                break;
            case ORDER_CANCEL:
                expected_min = ORDER_CANCEL_MIN;
                expected_max = ORDER_CANCEL_MAX;
                break;
            case ORDER_DELETE:
                expected_min = ORDER_DELETE_MIN;
                expected_max = ORDER_DELETE_MAX;
                break;
            case ORDER_REPLACE:
                expected_min = ORDER_REPLACE_MIN;
                expected_max = ORDER_REPLACE_MAX;
                break;
            case TRADE:
                expected_min = TRADE_MIN;
                expected_max = TRADE_MAX;
                break;
            case CROSS_TRADE:
                expected_min = CROSS_TRADE_MIN;
                expected_max = CROSS_TRADE_MAX;
                break;
            case BROKEN_TRADE:
                expected_min = BROKEN_TRADE_MIN;
                expected_max = BROKEN_TRADE_MAX;
                break;
            case NOII:
                expected_min = NOII_MIN;
                expected_max = NOII_MAX;
                break;
            case RPII:
                expected_min = RPII_MIN;
                expected_max = RPII_MAX;
                break;
            case LULD_AUCTION_COLLAR:
                expected_min = LULD_AUCTION_COLLAR_MIN;
                expected_max = LULD_AUCTION_COLLAR_MAX;
                break;
            default:
                // Unknown message type - could be new ITCH version or attack
                _last_error = "Unknown ITCH message type";
                _stats.type_violations++;
                return false;
        }
        
        // Strict size checking - reject if not exact match
        if (size < expected_min || size > expected_max) {
            _last_error = "ITCH message size mismatch";
            return false;
        }
        
        return true;
    }
};

} // namespace App
} // namespace CppTrader

#endif // CPPTRADER_APP_SAFE_ITCH_HANDLER_H
