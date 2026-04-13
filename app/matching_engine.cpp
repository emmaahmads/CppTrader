/*!
    \file matching_engine.cpp
    \brief Matching engine example with security hardening
    \author Ivan Shynkarenka
    \date 16.08.2017
    \copyright MIT License
*/

#include "trader/matching/market_manager.h"
#include "common/safe_market_manager.h"
#include "common/validator.h"

#include "system/stream.h"

#include <iostream>
#include <regex>
#include <string>

using namespace CppTrader::Matching;
using namespace CppTrader::App;

class MyMarketHandler : public MarketHandler
{
protected:
    void onAddSymbol(const Symbol& symbol) override
    { std::cout << "Add symbol: " << symbol << std::endl; }
    void onDeleteSymbol(const Symbol& symbol) override
    { std::cout << "Delete symbol: " << symbol << std::endl; }

    void onAddOrderBook(const OrderBook& order_book) override
    { std::cout << "Add order book: " << order_book << std::endl; }
    void onUpdateOrderBook(const OrderBook& order_book, bool top) override
    { std::cout << "Update order book: " << order_book << (top ? " - Top of the book!" : "") << std::endl; }
    void onDeleteOrderBook(const OrderBook& order_book) override
    { std::cout << "Delete order book: " << order_book << std::endl; }

    void onAddLevel(const OrderBook& order_book, const Level& level, bool top) override
    { std::cout << "Add level: " << level << (top ? " - Top of the book!" : "") << std::endl; }
    void onUpdateLevel(const OrderBook& order_book, const Level& level, bool top) override
    { std::cout << "Update level: " << level << (top ? " - Top of the book!" : "") << std::endl; }
    void onDeleteLevel(const OrderBook& order_book, const Level& level, bool top) override
    { std::cout << "Delete level: " << level << (top ? " - Top of the book!" : "") << std::endl; }

    void onAddOrder(const Order& order) override
    { std::cout << "Add order: " << order << std::endl; }
    void onUpdateOrder(const Order& order) override
    { std::cout << "Update order: " << order << std::endl; }
    void onDeleteOrder(const Order& order) override
    { std::cout << "Delete order: " << order << std::endl; }

    void onExecuteOrder(const Order& order, uint64_t price, uint64_t quantity) override
    { std::cout << "Execute order: " << order << " with price " << price << " and quantity " << quantity << std::endl; }
};

void AddSymbol(SafeMarketManager& market, const std::string& command)
{
    static std::regex pattern("^add symbol (\\d+) (.+)$");
    std::smatch match;

    if (std::regex_search(command, match, pattern))
    {
        try {
            // Validate and parse symbol ID with bounds checking
            long long id_ll = std::stoll(match[1]);
            if (id_ll < 0 || id_ll > static_cast<long long>(Validator::MAX_SYMBOL_ID)) {
                std::cerr << "[SECURITY] Symbol ID out of allowed range: " << id_ll << std::endl;
                return;
            }
            uint32_t id = static_cast<uint32_t>(id_ll);

            // Validate input line length
            std::string sname = match[2];
            if (sname.length() > 8) {
                std::cerr << "[SECURITY] Symbol name exceeds maximum length (8 characters)" << std::endl;
                return;
            }

            char name[8];
            std::memcpy(name, sname.data(), sname.size());
            // Pad remaining bytes with spaces for safety
            if (sname.size() < 8) {
                std::memset(name + sname.size(), ' ', 8 - sname.size());
            }

            Symbol symbol(id, name);

            ErrorCode result = market.SafeAddSymbol(symbol);
            if (result != ErrorCode::OK)
                std::cerr << "Failed 'add symbol' command: " << result << std::endl;

        } catch (const std::out_of_range&) {
            std::cerr << "[SECURITY] Symbol ID value out of range" << std::endl;
        } catch (const std::invalid_argument&) {
            std::cerr << "Invalid 'add symbol' command format" << std::endl;
        }
        return;
    }

    std::cerr << "Invalid 'add symbol' command: " << command << std::endl;
}

void DeleteSymbol(SafeMarketManager& market, const std::string& command)
{
    static std::regex pattern("^delete symbol (\\d+)$");
    std::smatch match;

    if (std::regex_search(command, match, pattern))
    {
        try {
            long long id_ll = std::stoll(match[1]);
            if (id_ll < 0 || id_ll > static_cast<long long>(Validator::MAX_SYMBOL_ID)) {
                std::cerr << "[SECURITY] Symbol ID out of allowed range: " << id_ll << std::endl;
                return;
            }
            uint32_t id = static_cast<uint32_t>(id_ll);

            ErrorCode result = market.SafeDeleteSymbol(id);
            if (result != ErrorCode::OK)
                std::cerr << "Failed 'delete symbol' command: " << result << std::endl;

        } catch (const std::out_of_range&) {
            std::cerr << "[SECURITY] Symbol ID value out of range" << std::endl;
        } catch (const std::invalid_argument&) {
            std::cerr << "Invalid 'delete symbol' command format" << std::endl;
        }
        return;
    }

    std::cerr << "Invalid 'delete symbol' command: " << command << std::endl;
}

void AddOrderBook(SafeMarketManager& market, const std::string& command)
{
    static std::regex pattern("^add book (\\d+)$");
    std::smatch match;

    if (std::regex_search(command, match, pattern))
    {
        try {
            long long id_ll = std::stoll(match[1]);
            if (id_ll < 0 || id_ll > static_cast<long long>(Validator::MAX_ORDER_BOOK_ID)) {
                std::cerr << "[SECURITY] Order book ID out of allowed range: " << id_ll << std::endl;
                return;
            }
            uint32_t id = static_cast<uint32_t>(id_ll);

            char name[8];
            std::memset(name, ' ', sizeof(name));  // Pad with spaces

            OrderBook order_book(id, id);  // Using id as symbol_id for simplicity

            ErrorCode result = market.SafeAddOrderBook(order_book);
            if (result != ErrorCode::OK)
                std::cerr << "Failed 'add book' command: " << result << std::endl;

        } catch (const std::out_of_range&) {
            std::cerr << "[SECURITY] Order book ID value out of range" << std::endl;
        } catch (const std::invalid_argument&) {
            std::cerr << "Invalid 'add book' command format" << std::endl;
        }
        return;
    }

    std::cerr << "Invalid 'add book' command: " << command << std::endl;
}

void DeleteOrderBook(SafeMarketManager& market, const std::string& command)
{
    static std::regex pattern("^delete book (\\d+)$");
    std::smatch match;

    if (std::regex_search(command, match, pattern))
    {
        try {
            long long id_ll = std::stoll(match[1]);
            if (id_ll < 0 || id_ll > static_cast<long long>(Validator::MAX_ORDER_BOOK_ID)) {
                std::cerr << "[SECURITY] Order book ID out of allowed range: " << id_ll << std::endl;
                return;
            }
            uint32_t id = static_cast<uint32_t>(id_ll);

            ErrorCode result = market.SafeDeleteOrderBook(id);
            if (result != ErrorCode::OK)
                std::cerr << "Failed 'delete book' command: " << result << std::endl;

        } catch (const std::out_of_range&) {
            std::cerr << "[SECURITY] Order book ID value out of range" << std::endl;
        } catch (const std::invalid_argument&) {
            std::cerr << "Invalid 'delete book' command format" << std::endl;
        }
        return;
    }

    std::cerr << "Invalid 'delete book' command: " << command << std::endl;
}

void AddMarketOrder(SafeMarketManager& market, const std::string& command)
{
    static std::regex pattern("^add market (buy|sell) (\\d+) (\\d+) (\\d+)$");
    std::smatch match;

    if (std::regex_search(command, match, pattern))
    {
        try {
            uint64_t id = std::stoull(match[2]);
            uint32_t symbol_id = std::stoul(match[3]);
            uint64_t quantity = std::stoull(match[4]);

            // Validate inputs
            auto result = Validator::ValidateOrderId(id);
            if (!result) { std::cerr << "[SECURITY] Invalid order ID: " << id << std::endl; return; }
            
            result = Validator::ValidateSymbolId(symbol_id);
            if (!result) { std::cerr << "[SECURITY] Invalid symbol ID: " << symbol_id << std::endl; return; }
            
            result = Validator::ValidateQuantity(quantity);
            if (!result) { std::cerr << "[SECURITY] Invalid quantity: " << quantity << std::endl; return; }

            Order order;
            if (match[1] == "buy")
                order = Order::BuyMarket(id, symbol_id, quantity);
            else if (match[1] == "sell")
                order = Order::SellMarket(id, symbol_id, quantity);
            else
            {
                std::cerr << "Invalid market order side: " << match[1] << std::endl;
                return;
            }

            ErrorCode ec = market.SafeAddOrder(order);
            if (ec != ErrorCode::OK)
                std::cerr << "Failed 'add market' command: " << ec << std::endl;

        } catch (const std::out_of_range&) {
            std::cerr << "[SECURITY] Order parameter value out of range" << std::endl;
        } catch (const std::invalid_argument&) {
            std::cerr << "Invalid 'add market' command format" << std::endl;
        }
        return;
    }

    std::cerr << "Invalid 'add market' command: " << command << std::endl;
}

void AddSlippageMarketOrder(SafeMarketManager& market, const std::string& command)
{
    static std::regex pattern("^add slippage market (buy|sell) (\\d+) (\\d+) (\\d+) (\\d+)$");
    std::smatch match;

    if (std::regex_search(command, match, pattern))
    {
        try {
            uint64_t id = std::stoull(match[2]);
            uint32_t symbol_id = std::stoul(match[3]);
            uint64_t quantity = std::stoull(match[4]);
            uint64_t slippage = std::stoull(match[5]);

            // Validate inputs
            auto result = Validator::ValidateOrderId(id);
            if (!result) { std::cerr << "[SECURITY] Invalid order ID: " << id << std::endl; return; }
            
            result = Validator::ValidateSymbolId(symbol_id);
            if (!result) { std::cerr << "[SECURITY] Invalid symbol ID: " << symbol_id << std::endl; return; }
            
            result = Validator::ValidateQuantity(quantity);
            if (!result) { std::cerr << "[SECURITY] Invalid quantity: " << quantity << std::endl; return; }
            
            result = Validator::ValidateSlippage(slippage);
            if (!result) { std::cerr << "[SECURITY] Invalid slippage: " << slippage << std::endl; return; }

            Order order;
            if (match[1] == "buy")
                order = Order::BuyMarket(id, symbol_id, quantity, slippage);
            else if (match[1] == "sell")
                order = Order::SellMarket(id, symbol_id, quantity, slippage);
            else
            {
                std::cerr << "Invalid market order side: " << match[1] << std::endl;
                return;
            }

            ErrorCode ec = market.SafeAddOrder(order);
            if (ec != ErrorCode::OK)
                std::cerr << "Failed 'add slippage market' command: " << ec << std::endl;

        } catch (const std::out_of_range&) {
            std::cerr << "[SECURITY] Order parameter value out of range" << std::endl;
        } catch (const std::invalid_argument&) {
            std::cerr << "Invalid 'add slippage market' command format" << std::endl;
        }
        return;
    }

    std::cerr << "Invalid 'add slippage market' command: " << command << std::endl;
}

void AddLimitOrder(SafeMarketManager& market, const std::string& command)
{
    static std::regex pattern("^add limit (buy|sell) (\\d+) (\\d+) (\\d+) (\\d+)$");
    std::smatch match;

    if (std::regex_search(command, match, pattern))
    {
        try {
            uint64_t id = std::stoull(match[2]);
            uint32_t symbol_id = std::stoul(match[3]);
            uint64_t price = std::stoull(match[4]);
            uint64_t quantity = std::stoull(match[5]);

            // Validate inputs
            auto result = Validator::ValidateOrderId(id);
            if (!result) { std::cerr << "[SECURITY] Invalid order ID: " << id << std::endl; return; }
            
            result = Validator::ValidateSymbolId(symbol_id);
            if (!result) { std::cerr << "[SECURITY] Invalid symbol ID: " << symbol_id << std::endl; return; }
            
            result = Validator::ValidatePrice(price);
            if (!result) { std::cerr << "[SECURITY] Invalid price: " << price << std::endl; return; }
            
            result = Validator::ValidateQuantity(quantity);
            if (!result) { std::cerr << "[SECURITY] Invalid quantity: " << quantity << std::endl; return; }

            Order order;
            if (match[1] == "buy")
                order = Order::BuyLimit(id, symbol_id, price, quantity);
            else if (match[1] == "sell")
                order = Order::SellLimit(id, symbol_id, price, quantity);
            else
            {
                std::cerr << "Invalid limit order side: " << match[1] << std::endl;
                return;
            }

            ErrorCode ec = market.SafeAddOrder(order);
            if (ec != ErrorCode::OK)
                std::cerr << "Failed 'add limit' command: " << ec << std::endl;

        } catch (const std::out_of_range&) {
            std::cerr << "[SECURITY] Order parameter value out of range" << std::endl;
        } catch (const std::invalid_argument&) {
            std::cerr << "Invalid 'add limit' command format" << std::endl;
        }
        return;
    }

    std::cerr << "Invalid 'add limit' command: " << command << std::endl;
}

void AddIOCLimitOrder(SafeMarketManager& market, const std::string& command)
{
    static std::regex pattern("^add ioc limit (buy|sell) (\\d+) (\\d+) (\\d+) (\\d+)$");
    std::smatch match;

    if (std::regex_search(command, match, pattern))
    {
        try {
            uint64_t id = std::stoull(match[2]);
            uint32_t symbol_id = std::stoul(match[3]);
            uint64_t price = std::stoull(match[4]);
            uint64_t quantity = std::stoull(match[5]);

            // Validate inputs
            auto result = Validator::ValidateOrderId(id);
            if (!result) { std::cerr << "[SECURITY] Invalid order ID: " << id << std::endl; return; }
            
            result = Validator::ValidateSymbolId(symbol_id);
            if (!result) { std::cerr << "[SECURITY] Invalid symbol ID: " << symbol_id << std::endl; return; }
            
            result = Validator::ValidatePrice(price);
            if (!result) { std::cerr << "[SECURITY] Invalid price: " << price << std::endl; return; }
            
            result = Validator::ValidateQuantity(quantity);
            if (!result) { std::cerr << "[SECURITY] Invalid quantity: " << quantity << std::endl; return; }

            Order order;
            if (match[1] == "buy")
                order = Order::BuyLimit(id, symbol_id, price, quantity, OrderTimeInForce::IOC);
            else if (match[1] == "sell")
                order = Order::SellLimit(id, symbol_id, price, quantity, OrderTimeInForce::IOC);
            else
            {
                std::cerr << "Invalid limit order side: " << match[1] << std::endl;
                return;
            }

            ErrorCode ec = market.SafeAddOrder(order);
            if (ec != ErrorCode::OK)
                std::cerr << "Failed 'add ioc limit' command: " << ec << std::endl;

        } catch (const std::out_of_range&) {
            std::cerr << "[SECURITY] Order parameter value out of range" << std::endl;
        } catch (const std::invalid_argument&) {
            std::cerr << "Invalid 'add ioc limit' command format" << std::endl;
        }
        return;
    }

    std::cerr << "Invalid 'add ioc limit' command: " << command << std::endl;
}

void AddFOKLimitOrder(SafeMarketManager& market, const std::string& command)
{
    static std::regex pattern("^add fok limit (buy|sell) (\\d+) (\\d+) (\\d+) (\\d+)$");
    std::smatch match;

    if (std::regex_search(command, match, pattern))
    {
        try {
            uint64_t id = std::stoull(match[2]);
            uint32_t symbol_id = std::stoul(match[3]);
            uint64_t price = std::stoull(match[4]);
            uint64_t quantity = std::stoull(match[5]);

            // Validate inputs
            auto result = Validator::ValidateOrderId(id);
            if (!result) { std::cerr << "[SECURITY] Invalid order ID: " << id << std::endl; return; }
            
            result = Validator::ValidateSymbolId(symbol_id);
            if (!result) { std::cerr << "[SECURITY] Invalid symbol ID: " << symbol_id << std::endl; return; }
            
            result = Validator::ValidatePrice(price);
            if (!result) { std::cerr << "[SECURITY] Invalid price: " << price << std::endl; return; }
            
            result = Validator::ValidateQuantity(quantity);
            if (!result) { std::cerr << "[SECURITY] Invalid quantity: " << quantity << std::endl; return; }

            Order order;
            if (match[1] == "buy")
                order = Order::BuyLimit(id, symbol_id, price, quantity, OrderTimeInForce::FOK);
            else if (match[1] == "sell")
                order = Order::SellLimit(id, symbol_id, price, quantity, OrderTimeInForce::FOK);
            else
            {
                std::cerr << "Invalid limit order side: " << match[1] << std::endl;
                return;
            }

            ErrorCode ec = market.SafeAddOrder(order);
            if (ec != ErrorCode::OK)
                std::cerr << "Failed 'add fok limit' command: " << ec << std::endl;

        } catch (const std::out_of_range&) {
            std::cerr << "[SECURITY] Order parameter value out of range" << std::endl;
        } catch (const std::invalid_argument&) {
            std::cerr << "Invalid 'add fok limit' command format" << std::endl;
        }
        return;
    }

    std::cerr << "Invalid 'add fok limit' command: " << command << std::endl;
}

void AddAONLimitOrder(SafeMarketManager& market, const std::string& command)
{
    static std::regex pattern("^add aon limit (buy|sell) (\\d+) (\\d+) (\\d+) (\\d+)$");
    std::smatch match;

    if (std::regex_search(command, match, pattern))
    {
        try {
            uint64_t id = std::stoull(match[2]);
            uint32_t symbol_id = std::stoul(match[3]);
            uint64_t price = std::stoull(match[4]);
            uint64_t quantity = std::stoull(match[5]);

            // Validate inputs
            auto result = Validator::ValidateOrderId(id);
            if (!result) { std::cerr << "[SECURITY] Invalid order ID: " << id << std::endl; return; }
            
            result = Validator::ValidateSymbolId(symbol_id);
            if (!result) { std::cerr << "[SECURITY] Invalid symbol ID: " << symbol_id << std::endl; return; }
            
            result = Validator::ValidatePrice(price);
            if (!result) { std::cerr << "[SECURITY] Invalid price: " << price << std::endl; return; }
            
            result = Validator::ValidateQuantity(quantity);
            if (!result) { std::cerr << "[SECURITY] Invalid quantity: " << quantity << std::endl; return; }

            Order order;
            if (match[1] == "buy")
                order = Order::BuyLimit(id, symbol_id, price, quantity, OrderTimeInForce::AON);
            else if (match[1] == "sell")
                order = Order::SellLimit(id, symbol_id, price, quantity, OrderTimeInForce::AON);
            else
            {
                std::cerr << "Invalid limit order side: " << match[1] << std::endl;
                return;
            }

            ErrorCode ec = market.SafeAddOrder(order);
            if (ec != ErrorCode::OK)
                std::cerr << "Failed 'add aon limit' command: " << ec << std::endl;

        } catch (const std::out_of_range&) {
            std::cerr << "[SECURITY] Order parameter value out of range" << std::endl;
        } catch (const std::invalid_argument&) {
            std::cerr << "Invalid 'add aon limit' command format" << std::endl;
        }
        return;
    }

    std::cerr << "Invalid 'add aon limit' command: " << command << std::endl;
}

void AddStopOrder(SafeMarketManager& market, const std::string& command)
{
    static std::regex pattern("^add stop (buy|sell) (\\d+) (\\d+) (\\d+) (\\d+)$");
    std::smatch match;

    if (std::regex_search(command, match, pattern))
    {
        try {
            uint64_t id = std::stoull(match[2]);
            uint32_t symbol_id = std::stoul(match[3]);
            uint64_t stop_price = std::stoull(match[4]);
            uint64_t quantity = std::stoull(match[5]);

            // Validate inputs
            auto result = Validator::ValidateOrderId(id);
            if (!result) { std::cerr << "[SECURITY] Invalid order ID: " << id << std::endl; return; }
            
            result = Validator::ValidateSymbolId(symbol_id);
            if (!result) { std::cerr << "[SECURITY] Invalid symbol ID: " << symbol_id << std::endl; return; }
            
            result = Validator::ValidatePrice(stop_price);
            if (!result) { std::cerr << "[SECURITY] Invalid stop price: " << stop_price << std::endl; return; }
            
            result = Validator::ValidateQuantity(quantity);
            if (!result) { std::cerr << "[SECURITY] Invalid quantity: " << quantity << std::endl; return; }

            Order order;
            if (match[1] == "buy")
                order = Order::BuyStop(id, symbol_id, stop_price, quantity);
            else if (match[1] == "sell")
                order = Order::SellStop(id, symbol_id, stop_price, quantity);
            else
            {
                std::cerr << "Invalid stop order side: " << match[1] << std::endl;
                return;
            }

            ErrorCode ec = market.SafeAddOrder(order);
            if (ec != ErrorCode::OK)
                std::cerr << "Failed 'add stop' command: " << ec << std::endl;

        } catch (const std::out_of_range&) {
            std::cerr << "[SECURITY] Order parameter value out of range" << std::endl;
        } catch (const std::invalid_argument&) {
            std::cerr << "Invalid 'add stop' command format" << std::endl;
        }
        return;
    }

    std::cerr << "Invalid 'add stop' command: " << command << std::endl;
}

void AddStopLimitOrder(SafeMarketManager& market, const std::string& command)
{
    static std::regex pattern("^add stop-limit (buy|sell) (\\d+) (\\d+) (\\d+) (\\d+) (\\d+)$");
    std::smatch match;

    if (std::regex_search(command, match, pattern))
    {
        try {
            uint64_t id = std::stoull(match[2]);
            uint32_t symbol_id = std::stoul(match[3]);
            uint64_t stop_price = std::stoull(match[4]);
            uint64_t price = std::stoull(match[5]);
            uint64_t quantity = std::stoull(match[6]);

            // Validate inputs
            auto result = Validator::ValidateOrderId(id);
            if (!result) { std::cerr << "[SECURITY] Invalid order ID: " << id << std::endl; return; }
            
            result = Validator::ValidateSymbolId(symbol_id);
            if (!result) { std::cerr << "[SECURITY] Invalid symbol ID: " << symbol_id << std::endl; return; }
            
            result = Validator::ValidatePrice(stop_price);
            if (!result) { std::cerr << "[SECURITY] Invalid stop price: " << stop_price << std::endl; return; }
            
            result = Validator::ValidatePrice(price);
            if (!result) { std::cerr << "[SECURITY] Invalid price: " << price << std::endl; return; }
            
            result = Validator::ValidateQuantity(quantity);
            if (!result) { std::cerr << "[SECURITY] Invalid quantity: " << quantity << std::endl; return; }

            Order order;
            if (match[1] == "buy")
                order = Order::BuyStopLimit(id, symbol_id, stop_price, price, quantity);
            else if (match[1] == "sell")
                order = Order::SellStopLimit(id, symbol_id, stop_price, price, quantity);
            else
            {
                std::cerr << "Invalid stop-limit order side: " << match[1] << std::endl;
                return;
            }

            ErrorCode ec = market.SafeAddOrder(order);
            if (ec != ErrorCode::OK)
                std::cerr << "Failed 'add stop-limit' command: " << ec << std::endl;

        } catch (const std::out_of_range&) {
            std::cerr << "[SECURITY] Order parameter value out of range" << std::endl;
        } catch (const std::invalid_argument&) {
            std::cerr << "Invalid 'add stop-limit' command format" << std::endl;
        }
        return;
    }

    std::cerr << "Invalid 'add stop-limit' command: " << command << std::endl;
}

void AddTrailingStopOrder(SafeMarketManager& market, const std::string& command)
{
    static std::regex pattern("^add trailing stop (buy|sell) (\\d+) (\\d+) (\\d+) (\\d+) ([\\d-]+) ([\\d-]+)$");
    std::smatch match;

    if (std::regex_search(command, match, pattern))
    {
        try {
            uint64_t id = std::stoull(match[2]);
            uint32_t symbol_id = std::stoul(match[3]);
            uint64_t stop_price = std::stoull(match[4]);
            uint64_t quantity = std::stoull(match[5]);
            int64_t trailing_distance = std::stoll(match[6]);
            int64_t trailing_step = std::stoll(match[7]);

            // Validate inputs
            auto result = Validator::ValidateOrderId(id);
            if (!result) { std::cerr << "[SECURITY] Invalid order ID: " << id << std::endl; return; }
            
            result = Validator::ValidateSymbolId(symbol_id);
            if (!result) { std::cerr << "[SECURITY] Invalid symbol ID: " << symbol_id << std::endl; return; }
            
            result = Validator::ValidatePrice(stop_price);
            if (!result) { std::cerr << "[SECURITY] Invalid stop price: " << stop_price << std::endl; return; }
            
            result = Validator::ValidateQuantity(quantity);
            if (!result) { std::cerr << "[SECURITY] Invalid quantity: " << quantity << std::endl; return; }
            
            result = Validator::ValidateTrailingDistance(trailing_distance);
            if (!result) { std::cerr << "[SECURITY] Invalid trailing distance: " << trailing_distance << std::endl; return; }
            
            result = Validator::ValidateTrailingStep(trailing_step);
            if (!result) { std::cerr << "[SECURITY] Invalid trailing step: " << trailing_step << std::endl; return; }

            Order order;
            if (match[1] == "buy")
                order = Order::TrailingBuyStop(id, symbol_id, stop_price, quantity, trailing_distance, trailing_step);
            else if (match[1] == "sell")
                order = Order::TrailingSellStop(id, symbol_id, stop_price, quantity, trailing_distance, trailing_step);
            else
            {
                std::cerr << "Invalid stop order side: " << match[1] << std::endl;
                return;
            }

            ErrorCode ec = market.SafeAddOrder(order);
            if (ec != ErrorCode::OK)
                std::cerr << "Failed 'add trailing stop' command: " << ec << std::endl;

        } catch (const std::out_of_range&) {
            std::cerr << "[SECURITY] Order parameter value out of range" << std::endl;
        } catch (const std::invalid_argument&) {
            std::cerr << "Invalid 'add trailing stop' command format" << std::endl;
        }
        return;
    }

    std::cerr << "Invalid 'add trailing stop' command: " << command << std::endl;
}

void AddTrailingStopLimitOrder(SafeMarketManager& market, const std::string& command)
{
    static std::regex pattern("^add trailing stop-limit (buy|sell) (\\d+) (\\d+) (\\d+) (\\d+) (\\d+) ([\\d-]+) ([\\d-]+)$");
    std::smatch match;

    if (std::regex_search(command, match, pattern))
    {
        try {
            uint64_t id = std::stoull(match[2]);
            uint32_t symbol_id = std::stoul(match[3]);
            uint64_t stop_price = std::stoull(match[4]);
            uint64_t price = std::stoull(match[5]);
            uint64_t quantity = std::stoull(match[6]);
            int64_t trailing_distance = std::stoll(match[7]);
            int64_t trailing_step = std::stoll(match[8]);

            // Validate inputs
            auto result = Validator::ValidateOrderId(id);
            if (!result) { std::cerr << "[SECURITY] Invalid order ID: " << id << std::endl; return; }
            
            result = Validator::ValidateSymbolId(symbol_id);
            if (!result) { std::cerr << "[SECURITY] Invalid symbol ID: " << symbol_id << std::endl; return; }
            
            result = Validator::ValidatePrice(stop_price);
            if (!result) { std::cerr << "[SECURITY] Invalid stop price: " << stop_price << std::endl; return; }
            
            result = Validator::ValidatePrice(price);
            if (!result) { std::cerr << "[SECURITY] Invalid price: " << price << std::endl; return; }
            
            result = Validator::ValidateQuantity(quantity);
            if (!result) { std::cerr << "[SECURITY] Invalid quantity: " << quantity << std::endl; return; }
            
            result = Validator::ValidateTrailingDistance(trailing_distance);
            if (!result) { std::cerr << "[SECURITY] Invalid trailing distance: " << trailing_distance << std::endl; return; }
            
            result = Validator::ValidateTrailingStep(trailing_step);
            if (!result) { std::cerr << "[SECURITY] Invalid trailing step: " << trailing_step << std::endl; return; }

            Order order;
            if (match[1] == "buy")
                order = Order::TrailingBuyStopLimit(id, symbol_id, stop_price, price, quantity, trailing_distance, trailing_step);
            else if (match[1] == "sell")
                order = Order::TrailingSellStopLimit(id, symbol_id, stop_price, price, quantity, trailing_distance, trailing_step);
            else
            {
                std::cerr << "Invalid stop-limit order side: " << match[1] << std::endl;
                return;
            }

            ErrorCode ec = market.SafeAddOrder(order);
            if (ec != ErrorCode::OK)
                std::cerr << "Failed 'add trailing stop-limit' command: " << ec << std::endl;

        } catch (const std::out_of_range&) {
            std::cerr << "[SECURITY] Order parameter value out of range" << std::endl;
        } catch (const std::invalid_argument&) {
            std::cerr << "Invalid 'add trailing stop-limit' command format" << std::endl;
        }
        return;
    }

    std::cerr << "Invalid 'add trailing stop-limit' command: " << command << std::endl;
}

void ReduceOrder(SafeMarketManager& market, const std::string& command)
{
    static std::regex pattern("^reduce order (\\d+) (\\d+)$");
    std::smatch match;

    if (std::regex_search(command, match, pattern))
    {
        try {
            uint64_t id = std::stoull(match[1]);
            uint64_t quantity = std::stoull(match[2]);

            // Validate inputs
            auto result = Validator::ValidateOrderId(id);
            if (!result) { std::cerr << "[SECURITY] Invalid order ID: " << id << std::endl; return; }
            
            result = Validator::ValidateQuantity(quantity);
            if (!result) { std::cerr << "[SECURITY] Invalid quantity: " << quantity << std::endl; return; }

            ErrorCode ec = market.SafeReduceOrder(id, quantity);
            if (ec != ErrorCode::OK)
                std::cerr << "Failed 'reduce order' command: " << ec << std::endl;

        } catch (const std::out_of_range&) {
            std::cerr << "[SECURITY] Order parameter value out of range" << std::endl;
        } catch (const std::invalid_argument&) {
            std::cerr << "Invalid 'reduce order' command format" << std::endl;
        }
        return;
    }

    std::cerr << "Invalid 'reduce order' command: " << command << std::endl;
}

void ModifyOrder(SafeMarketManager& market, const std::string& command)
{
    static std::regex pattern("^modify order (\\d+) (\\d+) (\\d+)$");
    std::smatch match;

    if (std::regex_search(command, match, pattern))
    {
        try {
            uint64_t id = std::stoull(match[1]);
            uint64_t new_price = std::stoull(match[2]);
            uint64_t new_quantity = std::stoull(match[3]);

            // Validate inputs
            auto result = Validator::ValidateOrderId(id);
            if (!result) { std::cerr << "[SECURITY] Invalid order ID: " << id << std::endl; return; }
            
            result = Validator::ValidatePrice(new_price);
            if (!result) { std::cerr << "[SECURITY] Invalid price: " << new_price << std::endl; return; }
            
            result = Validator::ValidateQuantity(new_quantity);
            if (!result) { std::cerr << "[SECURITY] Invalid quantity: " << new_quantity << std::endl; return; }

            ErrorCode ec = market.SafeModifyOrder(id, new_price, new_quantity);
            if (ec != ErrorCode::OK)
                std::cerr << "Failed 'modify order' command: " << ec << std::endl;

        } catch (const std::out_of_range&) {
            std::cerr << "[SECURITY] Order parameter value out of range" << std::endl;
        } catch (const std::invalid_argument&) {
            std::cerr << "Invalid 'modify order' command format" << std::endl;
        }
        return;
    }

    std::cerr << "Invalid 'modify order' command: " << command << std::endl;
}

void MitigateOrder(SafeMarketManager& market, const std::string& command)
{
    static std::regex pattern("^mitigate order (\\d+) (\\d+) (\\d+)$");
    std::smatch match;

    if (std::regex_search(command, match, pattern))
    {
        try {
            uint64_t id = std::stoull(match[1]);
            uint64_t new_price = std::stoull(match[2]);
            uint64_t new_quantity = std::stoull(match[3]);

            // Validate inputs
            auto result = Validator::ValidateOrderId(id);
            if (!result) { std::cerr << "[SECURITY] Invalid order ID: " << id << std::endl; return; }
            
            result = Validator::ValidatePrice(new_price);
            if (!result) { std::cerr << "[SECURITY] Invalid price: " << new_price << std::endl; return; }
            
            result = Validator::ValidateQuantity(new_quantity);
            if (!result) { std::cerr << "[SECURITY] Invalid quantity: " << new_quantity << std::endl; return; }

            ErrorCode ec = market.SafeModifyOrder(id, new_price, new_quantity);
            if (ec != ErrorCode::OK)
                std::cerr << "Failed 'mitigate order' command: " << ec << std::endl;

        } catch (const std::out_of_range&) {
            std::cerr << "[SECURITY] Order parameter value out of range" << std::endl;
        } catch (const std::invalid_argument&) {
            std::cerr << "Invalid 'mitigate order' command format" << std::endl;
        }
        return;
    }

    std::cerr << "Invalid 'mitigate order' command: " << command << std::endl;
}

void ReplaceOrder(SafeMarketManager& market, const std::string& command)
{
    static std::regex pattern("^replace order (\\d+) (\\d+) (\\d+) (\\d+)$");
    std::smatch match;

    if (std::regex_search(command, match, pattern))
    {
        try {
            uint64_t id = std::stoull(match[1]);
            uint64_t new_id = std::stoull(match[2]);
            uint64_t new_price = std::stoull(match[3]);
            uint64_t new_quantity = std::stoull(match[4]);

            // Validate inputs
            auto result = Validator::ValidateOrderId(id);
            if (!result) { std::cerr << "[SECURITY] Invalid order ID: " << id << std::endl; return; }
            
            result = Validator::ValidateOrderId(new_id);
            if (!result) { std::cerr << "[SECURITY] Invalid new order ID: " << new_id << std::endl; return; }
            
            result = Validator::ValidatePrice(new_price);
            if (!result) { std::cerr << "[SECURITY] Invalid price: " << new_price << std::endl; return; }
            
            result = Validator::ValidateQuantity(new_quantity);
            if (!result) { std::cerr << "[SECURITY] Invalid quantity: " << new_quantity << std::endl; return; }

            ErrorCode ec = market.SafeReplaceOrder(id, new_id, new_price, new_quantity);
            if (ec != ErrorCode::OK)
                std::cerr << "Failed 'replace order' command: " << ec << std::endl;

        } catch (const std::out_of_range&) {
            std::cerr << "[SECURITY] Order parameter value out of range" << std::endl;
        } catch (const std::invalid_argument&) {
            std::cerr << "Invalid 'replace order' command format" << std::endl;
        }
        return;
    }

    std::cerr << "Invalid 'replace order' command: " << command << std::endl;
}

void DeleteOrder(SafeMarketManager& market, const std::string& command)
{
    static std::regex pattern("^delete order (\\d+)$");
    std::smatch match;

    if (std::regex_search(command, match, pattern))
    {
        try {
            uint64_t id = std::stoull(match[1]);

            // Validate inputs
            auto result = Validator::ValidateOrderId(id);
            if (!result) { std::cerr << "[SECURITY] Invalid order ID: " << id << std::endl; return; }

            ErrorCode ec = market.SafeDeleteOrder(id);
            if (ec != ErrorCode::OK)
                std::cerr << "Failed 'delete order' command: " << ec << std::endl;

        } catch (const std::out_of_range&) {
            std::cerr << "[SECURITY] Order ID value out of range" << std::endl;
        } catch (const std::invalid_argument&) {
            std::cerr << "Invalid 'delete order' command format" << std::endl;
        }
        return;
    }

    std::cerr << "Invalid 'delete order' command: " << command << std::endl;
}

void ExecuteOrder(SafeMarketManager& market, const std::string& command)
{
    static std::regex pattern("^execute order (\\d+) (\\d+) (\\d+)$");
    std::smatch match;

    if (std::regex_search(command, match, pattern))
    {
        try {
            uint64_t id = std::stoull(match[1]);
            uint64_t price = std::stoull(match[2]);
            uint64_t quantity = std::stoull(match[3]);

            // Validate inputs
            auto result = Validator::ValidateOrderId(id);
            if (!result) { std::cerr << "[SECURITY] Invalid order ID: " << id << std::endl; return; }
            
            result = Validator::ValidatePrice(price);
            if (!result) { std::cerr << "[SECURITY] Invalid price: " << price << std::endl; return; }
            
            result = Validator::ValidateQuantity(quantity);
            if (!result) { std::cerr << "[SECURITY] Invalid quantity: " << quantity << std::endl; return; }

            ErrorCode ec = (price == 0) ? market.GetManager().ExecuteOrder(id, quantity) : market.SafeExecuteOrder(id, price, quantity);
            if (ec != ErrorCode::OK)
                std::cerr << "Failed 'execute order' command: " << ec << std::endl;

        } catch (const std::out_of_range&) {
            std::cerr << "[SECURITY] Order parameter value out of range" << std::endl;
        } catch (const std::invalid_argument&) {
            std::cerr << "Invalid 'execute order' command format" << std::endl;
        }
        return;
    }

    std::cerr << "Invalid 'execute order' command: " << command << std::endl;
}

int main(int argc, char** argv)
{
    MyMarketHandler market_handler;
    SafeMarketManager market(market_handler);
    
    std::cout << "=== CppTrader Matching Engine (Security Hardened) ===" << std::endl;
    std::cout << "Type 'help' for commands, 'exit' to quit" << std::endl;
    std::cout << std::endl;

    // Perform text input
    std::string line;
    while (getline(std::cin, line))
    {
        // Validate input line length
        auto result = Validator::ValidateInputLine(line.c_str(), line.length());
        if (!result) {
            std::cerr << "[SECURITY] Input rejected: " << result.error_message << std::endl;
            continue;
        }

        if (line == "help")
        {
            std::cout << "Supported commands: " << std::endl;
            std::cout << "add symbol {Id} {Name} - Add a new symbol with {Id} and {Name}" << std::endl;
            std::cout << "delete symbol {Id} - Delete the symbol with {Id}" << std::endl;
            std::cout << "add book {Id} - Add a new order book for the symbol with {Id}" << std::endl;
            std::cout << "delete book {Id} - Delete the order book with {Id}" << std::endl;
            std::cout << "add market {Side} {Id} {SymbolId} {Quantity} - Add a new market order of {Type} (buy/sell) with {Id}, {SymbolId} and {Quantity}" << std::endl;
            std::cout << "add slippage market {Side} {Id} {SymbolId} {Quantity} {Slippage} - Add a new slippage market order of {Type} (buy/sell) with {Id}, {SymbolId}, {Quantity} and {Slippage}" << std::endl;
            std::cout << "add limit {Side} {Id} {SymbolId} {Price} {Quantity} - Add a new limit order of {Type} (buy/sell) with {Id}, {SymbolId}, {Price} and {Quantity}" << std::endl;
            std::cout << "add ioc limit {Side} {Id} {SymbolId} {Price} {Quantity} - Add a new 'Immediate-Or-Cancel' limit order of {Type} (buy/sell) with {Id}, {SymbolId}, {Price} and {Quantity}" << std::endl;
            std::cout << "add fok limit {Side} {Id} {SymbolId} {Price} {Quantity} - Add a new 'Fill-Or-Kill' limit order of {Type} (buy/sell) with {Id}, {SymbolId}, {Price} and {Quantity}" << std::endl;
            std::cout << "add aon limit {Side} {Id} {SymbolId} {Price} {Quantity} - Add a new 'All-Or-None' limit order of {Type} (buy/sell) with {Id}, {SymbolId}, {Price} and {Quantity}" << std::endl;
            std::cout << "add stop {Side} {Id} {SymbolId} {StopPrice} {Quantity} - Add a new stop order of {Type} (buy/sell) with {Id}, {SymbolId}, {StopPrice} and {Quantity}" << std::endl;
            std::cout << "add stop-limit {Side} {Id} {SymbolId} {StopPrice} {Price} {Quantity} - Add a new stop-limit order of {Type} (buy/sell) with {Id}, {SymbolId}, {StopPrice}, {Price} and {Quantity}" << std::endl;
            std::cout << "add trailing stop {Side} {Id} {SymbolId} {StopPrice} {Quantity} {TrailingDistance} {TrailingStep} - Add a new trailing stop order of {Type} (buy/sell) with {Id}, {SymbolId}, {StopPrice}, {Quantity}, {TrailingDistance} and {TrailingStep}" << std::endl;
            std::cout << "add trailing stop-limit {Side} {Id} {SymbolId} {StopPrice} {Price} {Quantity} {TrailingDistance} {TrailingStep} - Add a new trailing stop-limit order of {Type} (buy/sell) with {Id}, {SymbolId}, {StopPrice}, {Price}, {Quantity}, {TrailingDistance} and {TrailingStep}" << std::endl;
            std::cout << "reduce order {Id} {Quantity} - Reduce the order with {Id} by the given {Quantity}" << std::endl;
            std::cout << "modify order {Id} {NewPrice} {NewQuantity} - Modify the order with {Id} and set {NewPrice} and {NewQuantity}" << std::endl;
            std::cout << "mitigate order {Id} {NewPrice} {NewQuantity} - Mitigate the order with {Id} and set {NewPrice} and {NewQuantity}" << std::endl;
            std::cout << "replace order {Id} {NewId} {NewPrice} {NewQuantity} - Replace the order with {Id} and set {NewId}, {NewPrice} and {NewQuantity}" << std::endl;
            std::cout << "delete order {Id} - Delete the order with {Id}" << std::endl;
            std::cout << "exit/quit - Exit the program" << std::endl;
        }
        else if ((line == "exit") || (line == "quit"))
            break;
        else if ((line.find("#") == 0) || (line == ""))
            continue;
        else if (line == "enable matching")
            market.GetManager().EnableMatching();
        else if (line == "disable matching")
            market.GetManager().DisableMatching();
        else if (line == "stats")
        {
            auto stats = market.GetStats();
            std::cout << "=== Security Validation Statistics ===" << std::endl;
            std::cout << "Symbols accepted/rejected: " << stats.symbols_accepted << "/" << stats.symbols_rejected << std::endl;
            std::cout << "Order books accepted/rejected: " << stats.order_books_accepted << "/" << stats.order_books_rejected << std::endl;
            std::cout << "Orders accepted/rejected: " << stats.orders_accepted << "/" << stats.orders_rejected << std::endl;
            std::cout << "Security events: " << stats.security_events << std::endl;
        }
        else if (line.find("add symbol") != std::string::npos)
            AddSymbol(market, line);
        else if (line.find("delete symbol") != std::string::npos)
            DeleteSymbol(market, line);
        else if (line.find("add book") != std::string::npos)
            AddOrderBook(market, line);
        else if (line.find("delete book") != std::string::npos)
            DeleteOrderBook(market, line);
        else if (line.find("add market") != std::string::npos)
            AddMarketOrder(market, line);
        else if (line.find("add slippage market") != std::string::npos)
            AddSlippageMarketOrder(market, line);
        else if (line.find("add limit") != std::string::npos)
            AddLimitOrder(market, line);
        else if (line.find("add ioc limit") != std::string::npos)
            AddIOCLimitOrder(market, line);
        else if (line.find("add fok limit") != std::string::npos)
            AddFOKLimitOrder(market, line);
        else if (line.find("add aon limit") != std::string::npos)
            AddAONLimitOrder(market, line);
        else if (line.find("add stop-limit") != std::string::npos)
            AddStopLimitOrder(market, line);
        else if (line.find("add stop") != std::string::npos)
            AddStopOrder(market, line);
        else if (line.find("add trailing stop-limit") != std::string::npos)
            AddTrailingStopLimitOrder(market, line);
        else if (line.find("add trailing stop") != std::string::npos)
            AddTrailingStopOrder(market, line);
        else if (line.find("reduce order") != std::string::npos)
            ReduceOrder(market, line);
        else if (line.find("modify order") != std::string::npos)
            ModifyOrder(market, line);
        else if (line.find("mitigate order") != std::string::npos)
            MitigateOrder(market, line);
        else if (line.find("replace order") != std::string::npos)
            ReplaceOrder(market, line);
        else if (line.find("delete order") != std::string::npos)
            DeleteOrder(market, line);
        else if (line.find("execute order") != std::string::npos)
            ExecuteOrder(market, line);
        else
            std::cerr << "Unknown command: "  << line << std::endl;
    }

    // Print final statistics
    auto stats = market.GetStats();
    if (stats.security_events > 0) {
        std::cout << std::endl;
        std::cout << "[SECURITY] Total security events detected: " << stats.security_events << std::endl;
    }

    return 0;
}
