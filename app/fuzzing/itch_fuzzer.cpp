/*!
    \file itch_fuzzer.cpp
    \brief Fuzzing harness for ITCH handler security testing
    \brief Generates malformed ITCH messages to test buffer overflow protections
    \author Security Hardening Layer
    \date 2024
    \copyright MIT License
*/

#include "trader/providers/nasdaq/itch_handler.h"
#include "../common/safe_itch_handler.h"
#include "../common/validator.h"

#include "system/stream.h"

#include <iostream>
#include <cstring>
#include <random>
#include <vector>
#include <chrono>

using namespace CppTrader;
using namespace CppTrader::App;

//! Simple ITCH handler for testing
class TestITCHHandler : public ITCH::ITCHHandler {
protected:
    bool onMessage(const ITCH::SystemEventMessage& message) override { 
        (void)message;
        return true; 
    }
    bool onMessage(const ITCH::StockDirectoryMessage& message) override { 
        (void)message;
        return true; 
    }
    bool onMessage(const ITCH::StockTradingActionMessage& message) override { 
        (void)message;
        return true; 
    }
    bool onMessage(const ITCH::RegSHOMessage& message) override { 
        (void)message;
        return true; 
    }
    bool onMessage(const ITCH::MarketParticipantPositionMessage& message) override { 
        (void)message;
        return true; 
    }
    bool onMessage(const ITCH::MWCBDeclineMessage& message) override { 
        (void)message;
        return true; 
    }
    bool onMessage(const ITCH::MWCBStatusMessage& message) override { 
        (void)message;
        return true; 
    }
    bool onMessage(const ITCH::IPOQuotingMessage& message) override { 
        (void)message;
        return true; 
    }
    bool onMessage(const ITCH::AddOrderMessage& message) override { 
        (void)message;
        return true; 
    }
    bool onMessage(const ITCH::AddOrderMPIDMessage& message) override { 
        (void)message;
        return true; 
    }
    bool onMessage(const ITCH::OrderExecutedMessage& message) override { 
        (void)message;
        return true; 
    }
    bool onMessage(const ITCH::OrderExecutedWithPriceMessage& message) override { 
        (void)message;
        return true; 
    }
    bool onMessage(const ITCH::OrderCancelMessage& message) override { 
        (void)message;
        return true; 
    }
    bool onMessage(const ITCH::OrderDeleteMessage& message) override { 
        (void)message;
        return true; 
    }
    bool onMessage(const ITCH::OrderReplaceMessage& message) override { 
        (void)message;
        return true; 
    }
    bool onMessage(const ITCH::TradeMessage& message) override { 
        (void)message;
        return true; 
    }
    bool onMessage(const ITCH::CrossTradeMessage& message) override { 
        (void)message;
        return true; 
    }
    bool onMessage(const ITCH::BrokenTradeMessage& message) override { 
        (void)message;
        return true; 
    }
    bool onMessage(const ITCH::NOIIMessage& message) override { 
        (void)message;
        return true; 
    }
    bool onMessage(const ITCH::RPIIMessage& message) override { 
        (void)message;
        return true; 
    }
    bool onMessage(const ITCH::LULDAuctionCollarMessage& message) override { 
        (void)message;
        return true; 
    }
    bool onMessage(const ITCH::UnknownMessage& message) override { 
        (void)message;
        return true; 
    }
};

//! Fuzzing test cases
namespace FuzzTests {
    
    //! Test 1: Oversized message
    void TestOversizedMessage(SafeITCHHandler& safe_handler) {
        std::vector<uint8_t> buffer(2048, 'A');  // Larger than MAX_ITCH_MESSAGE_SIZE
        buffer[0] = 200;  // Message size field
        buffer[1] = 'S';  // Message type
        
        bool result = safe_handler.SafeProcess(buffer.data(), buffer.size());
        std::cout << "Oversized message test: " << (result ? "PASSED (rejected)" : "FAILED (accepted)") << std::endl;
    }
    
    //! Test 2: Mismatched message size
    void TestMismatchedSize(SafeITCHHandler& safe_handler) {
        std::vector<uint8_t> buffer(50, 0);
        buffer[0] = 39;  // Claimed size (Stock Directory)
        buffer[1] = 'R'; // Stock Directory type
        // But actual buffer is 50 bytes
        
        bool result = safe_handler.SafeProcess(buffer.data(), buffer.size());
        std::cout << "Mismatched size test: " << (result ? "PASSED (rejected)" : "FAILED (accepted)") << std::endl;
    }
    
    //! Test 3: Truncated message
    void TestTruncatedMessage(SafeITCHHandler& safe_handler) {
        std::vector<uint8_t> buffer(5, 0);
        buffer[0] = 39;  // Claimed size (Stock Directory)
        buffer[1] = 'R'; // Stock Directory type
        // But only 5 bytes provided
        
        bool result = safe_handler.SafeProcess(buffer.data(), buffer.size());
        std::cout << "Truncated message test: " << (result ? "PASSED (rejected)" : "FAILED (accepted)") << std::endl;
    }
    
    //! Test 4: Unknown message type
    void TestUnknownType(SafeITCHHandler& safe_handler) {
        std::vector<uint8_t> buffer(20, 0);
        buffer[0] = 20;  // Size
        buffer[1] = 'Z'; // Unknown type
        
        bool result = safe_handler.SafeProcess(buffer.data(), buffer.size());
        std::cout << "Unknown type test: " << (result ? "FAILED (accepted)" : "PASSED (rejected)") << std::endl;
    }
    
    //! Test 5: Zero-sized message
    void TestZeroSize(SafeITCHHandler& safe_handler) {
        std::vector<uint8_t> buffer(10, 0);
        buffer[0] = 0;   // Zero size
        buffer[1] = 'S'; // Any type
        
        bool result = safe_handler.SafeProcess(buffer.data(), buffer.size());
        std::cout << "Zero size test: " << (result ? "FAILED (accepted)" : "PASSED (rejected)") << std::endl;
    }
    
    //! Test 6: Valid message (should pass)
    void TestValidMessage(SafeITCHHandler& safe_handler) {
        std::vector<uint8_t> buffer(12, 0);
        buffer[0] = 12;  // Size
        buffer[1] = 'S'; // System Event type
        // Remaining bytes can be anything for this test
        
        bool result = safe_handler.SafeProcess(buffer.data(), buffer.size());
        std::cout << "Valid message test: " << (result ? "PASSED (accepted)" : "FAILED (rejected)") << std::endl;
    }
    
    //! Test 7: Random fuzzing
    void TestRandomFuzzing(SafeITCHHandler& safe_handler, int iterations = 1000) {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<size_t> size_dist(1, 100);
        std::uniform_int_distribution<uint8_t> byte_dist(0, 255);
        
        int accepted = 0;
        int rejected = 0;
        
        for (int i = 0; i < iterations; ++i) {
            size_t size = size_dist(gen);
            std::vector<uint8_t> buffer(size);
            
            for (size_t j = 0; j < size; ++j) {
                buffer[j] = byte_dist(gen);
            }
            
            bool result = safe_handler.SafeProcess(buffer.data(), buffer.size());
            if (result) {
                accepted++;
            } else {
                rejected++;
            }
        }
        
        std::cout << "Random fuzzing (" << iterations << " iterations): " 
                  << accepted << " accepted, " << rejected << " rejected" << std::endl;
    }
    
    //! Test 8: Boundary values
    void TestBoundaryValues(SafeITCHHandler& safe_handler) {
        // Test exact size match
        {
            std::vector<uint8_t> buffer(39, 0);
            buffer[0] = 39;  // Exact Stock Directory size
            buffer[1] = 'R'; // Stock Directory type
            
            bool result = safe_handler.SafeProcess(buffer.data(), buffer.size());
            std::cout << "Exact size boundary test: " << (result ? "PASSED (accepted)" : "FAILED (rejected)") << std::endl;
        }
        
        // Test size - 1
        {
            std::vector<uint8_t> buffer(38, 0);
            buffer[0] = 38;  // Wrong size
            buffer[1] = 'R'; // Stock Directory type
            
            bool result = safe_handler.SafeProcess(buffer.data(), buffer.size());
            std::cout << "Size-1 boundary test: " << (result ? "FAILED (accepted)" : "PASSED (rejected)") << std::endl;
        }
        
        // Test size + 1
        {
            std::vector<uint8_t> buffer(40, 0);
            buffer[0] = 40;  // Wrong size
            buffer[1] = 'R'; // Stock Directory type
            
            bool result = safe_handler.SafeProcess(buffer.data(), buffer.size());
            std::cout << "Size+1 boundary test: " << (result ? "FAILED (accepted)" : "PASSED (rejected)") << std::endl;
        }
    }
}

int main(int argc, char** argv) {
    std::cout << "=== CppTrader ITCH Handler Security Fuzzer ===" << std::endl;
    std::cout << std::endl;
    
    TestITCHHandler handler;
    SafeITCHHandler safe_handler(handler);
    
    std::cout << "Running security fuzz tests..." << std::endl;
    std::cout << std::endl;
    
    FuzzTests::TestOversizedMessage(safe_handler);
    FuzzTests::TestMismatchedSize(safe_handler);
    FuzzTests::TestTruncatedMessage(safe_handler);
    FuzzTests::TestUnknownType(safe_handler);
    FuzzTests::TestZeroSize(safe_handler);
    FuzzTests::TestValidMessage(safe_handler);
    FuzzTests::TestBoundaryValues(safe_handler);
    
    std::cout << std::endl;
    FuzzTests::TestRandomFuzzing(safe_handler, 10000);
    
    std::cout << std::endl;
    std::cout << "=== Fuzz Test Summary ===" << std::endl;
    auto stats = safe_handler.GetStats();
    std::cout << "Total messages processed: " << stats.total_messages << std::endl;
    std::cout << "Rejected messages: " << stats.rejected_messages << std::endl;
    std::cout << "Size violations: " << stats.size_violations << std::endl;
    std::cout << "Type violations: " << stats.type_violations << std::endl;
    
    std::cout << std::endl;
    std::cout << "Fuzz testing complete." << std::endl;
    
    return 0;
}
