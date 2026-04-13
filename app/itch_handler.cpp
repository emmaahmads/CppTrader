/*!
    \file itch_handler.cpp
    \brief NASDAQ ITCH handler example with security hardening
    \author Ivan Shynkarenka
    \date 23.07.2017
    \copyright MIT License
*/

#include "trader/providers/nasdaq/itch_handler.h"
#include "common/safe_itch_handler.h"
#include "common/validator.h"

#include "system/stream.h"

#include <iostream>

using namespace CppTrader::ITCH;
using namespace CppTrader::App;

class MyITCHHandler : public ITCHHandler
{
protected:
    bool onMessage(const SystemEventMessage& message) override { return OutputMessage(message); }
    bool onMessage(const StockDirectoryMessage& message) override { return OutputMessage(message); }
    bool onMessage(const StockTradingActionMessage& message) override { return OutputMessage(message); }
    bool onMessage(const RegSHOMessage& message) override { return OutputMessage(message); }
    bool onMessage(const MarketParticipantPositionMessage& message) override { return OutputMessage(message); }
    bool onMessage(const MWCBDeclineMessage& message) override { return OutputMessage(message); }
    bool onMessage(const MWCBStatusMessage& message) override { return OutputMessage(message); }
    bool onMessage(const IPOQuotingMessage& message) override { return OutputMessage(message); }
    bool onMessage(const AddOrderMessage& message) override { return OutputMessage(message); }
    bool onMessage(const AddOrderMPIDMessage& message) override { return OutputMessage(message); }
    bool onMessage(const OrderExecutedMessage& message) override { return OutputMessage(message); }
    bool onMessage(const OrderExecutedWithPriceMessage& message) override { return OutputMessage(message); }
    bool onMessage(const OrderCancelMessage& message) override { return OutputMessage(message); }
    bool onMessage(const OrderDeleteMessage& message) override { return OutputMessage(message); }
    bool onMessage(const OrderReplaceMessage& message) override { return OutputMessage(message); }
    bool onMessage(const TradeMessage& message) override { return OutputMessage(message); }
    bool onMessage(const CrossTradeMessage& message) override { return OutputMessage(message); }
    bool onMessage(const BrokenTradeMessage& message) override { return OutputMessage(message); }
    bool onMessage(const NOIIMessage& message) override { return OutputMessage(message); }
    bool onMessage(const RPIIMessage& message) override { return OutputMessage(message); }
    bool onMessage(const LULDAuctionCollarMessage& message) override { return OutputMessage(message); }
    bool onMessage(const UnknownMessage& message) override { 
        // Reject unknown message types for security
        std::cerr << "[SECURITY] Unknown message type rejected: " << message.Type << std::endl;
        return false; 
    }

private:
    template <class TMessage>
    static bool OutputMessage(const TMessage& message)
    {
        std::cout << message << std::endl;
        return true;
    }
};

int main(int argc, char** argv)
{
    std::cout << "=== CppTrader ITCH Handler (Security Hardened) ===" << std::endl;
    std::cout << "Processing ITCH messages with bounds validation..." << std::endl;
    std::cout << std::endl;

    MyITCHHandler itch_handler;
    SafeITCHHandler safe_handler(itch_handler);

    // Perform input with security validation
    size_t size;
    uint8_t buffer[8192];
    CppCommon::StdInput input;
    uint64_t total_processed = 0;
    uint64_t total_rejected = 0;

    while ((size = input.Read(buffer, sizeof(buffer))) > 0)
    {
        // Validate buffer size before processing
        auto result = Validator::ValidateITCHMessageSize(size);
        if (!result) {
            std::cerr << "[SECURITY] Buffer rejected: " << result.error_message << std::endl;
            total_rejected++;
            continue;
        }

        // Process the buffer with safe handler
        if (!safe_handler.SafeProcess(buffer, size)) {
            const char* error = safe_handler.GetLastError();
            std::cerr << "[SECURITY] ITCH processing failed: " << (error ? error : "unknown error") << std::endl;
            total_rejected++;
        } else {
            total_processed++;
        }
    }

    // Print security statistics
    auto stats = safe_handler.GetStats();
    std::cout << std::endl;
    std::cout << "=== Security Validation Statistics ===" << std::endl;
    std::cout << "Total messages processed: " << stats.total_messages << std::endl;
    std::cout << "Rejected messages: " << stats.rejected_messages << std::endl;
    std::cout << "Size violations: " << stats.size_violations << std::endl;
    std::cout << "Type violations: " << stats.type_violations << std::endl;
    
    if (stats.security_events > 0 || total_rejected > 0) {
        std::cout << std::endl;
        std::cout << "[SECURITY] Total security events detected: " << (stats.rejected_messages + total_rejected) << std::endl;
    }

    return 0;
}
