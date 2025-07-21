/*
 * Copyright (c) 2023, Alibaba Group Holding Limited;
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <iostream>
#include <thread>
#include <chrono>
#include "ylt/coro_http/coro_http_server.hpp"
#include "ylt/coro_http/coro_http_client.hpp"

using namespace coro_http;

void print_usage() {
    std::cout << "HTTP Server IP Whitelist Example\n";
    std::cout << "================================\n\n";
    std::cout << "This example demonstrates:\n";
    std::cout << "  - Basic IP whitelist configuration\n";
    std::cout << "  - Using set_ip_whitelist() method (copy and move versions)\n";
    std::cout << "  - Dynamic whitelist management\n";
    std::cout << "  - HTTP endpoint protection with IP filtering\n\n";
}

int main() {
    print_usage();
    
    // 创建HTTP服务器
    coro_http_server server(1, 8080);

    // 方法1：传统方式配置IP白名单
    std::cout << "=== Method 1: Traditional Configuration ===\n";
    auto& whitelist = server.get_ip_whitelist();
    
    // 添加本地IP到白名单
    whitelist.add_ip("127.0.0.1");
    whitelist.add_ip("::1");  // IPv6本地地址
    
    // 添加私有网络段
    whitelist.add_cidr("192.168.0.0/16");
    whitelist.add_cidr("10.0.0.0/8");
    whitelist.add_cidr("172.16.0.0/12");
    
    std::cout << "HTTP Server IP whitelist configured with:\n";
    std::cout << "- localhost (127.0.0.1, ::1)\n";
    std::cout << "- Private networks (192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12)\n";
    std::cout << "Total entries: " << whitelist.size() << "\n\n";
    
    // 方法2：使用set_ip_whitelist方法（copy版本）
    std::cout << "=== Method 2: Using set_ip_whitelist (copy) ===\n";
    
    // 创建一个预配置的IP白名单
    coro_io::ip_whitelist predefined_whitelist;
    predefined_whitelist.add_ip("127.0.0.1");
    predefined_whitelist.add_ip("::1");
    predefined_whitelist.add_cidr("203.0.113.0/24");  // TEST-NET-3 (RFC 5737)
    predefined_whitelist.add_regex_pattern(R"(192\.168\.100\.\d+)");  // 特定子网
    
    std::cout << "Created predefined whitelist with test networks\n";
    std::cout << "Setting whitelist using copy method...\n";
    server.set_ip_whitelist(predefined_whitelist);
    
    std::cout << "Whitelist updated! New size: " << server.get_ip_whitelist().size() << "\n";
    std::cout << "Testing new configuration:\n";
    
    // 测试新的配置
    std::vector<std::string> test_ips = {
        "127.0.0.1",           // 应该被允许
        "203.0.113.50",        // 应该被允许 (TEST-NET-3)
        "192.168.100.200",     // 应该被允许 (regex匹配)
        "192.168.1.50",        // 应该被拒绝 (不在新配置中)
        "8.8.8.8"              // 应该被拒绝
    };
    
    for (const auto& ip : test_ips) {
        bool allowed = server.get_ip_whitelist().is_allowed(ip);
        std::cout << "  " << ip << ": " << (allowed ? "ALLOWED" : "BLOCKED") << "\n";
    }
    std::cout << "\n";
    
    // 方法3：使用set_ip_whitelist方法（move版本）
    std::cout << "=== Method 3: Using set_ip_whitelist (move) ===\n";
    
    // 创建生产环境的白名单配置
    coro_io::ip_whitelist production_whitelist;
    production_whitelist.add_ip("127.0.0.1");
    production_whitelist.add_ip("::1");
    production_whitelist.add_cidr("192.168.0.0/16");    // 私有网络
    production_whitelist.add_cidr("10.0.0.0/8");        // 私有网络
    production_whitelist.add_cidr("172.16.0.0/12");     // 私有网络
    production_whitelist.add_ip("203.0.113.100");       // 特定的外部IP
    
    std::cout << "Created production whitelist configuration\n";
    std::cout << "Setting whitelist using move method...\n";
    server.set_ip_whitelist(std::move(production_whitelist));
    
    std::cout << "Production whitelist set! Final size: " << server.get_ip_whitelist().size() << "\n\n";
    
    // 启用IP白名单
    server.enable_ip_whitelist(true);
    std::cout << "IP whitelist enabled\n\n";

    // 设置HTTP处理器
    std::cout << "=== Setting Up HTTP Endpoints ===\n";
    
    server.set_http_handler<GET>("/", [](coro_http_request& req, coro_http_response& resp) {
        resp.set_status_and_content(status_type::ok,
            "Hello from HTTP server with IP whitelist!\n"
            "Your connection passed the IP whitelist check.");
    });
    
    server.set_http_handler<GET>("/test", [](coro_http_request& req, coro_http_response& resp) {
        resp.set_status_and_content(status_type::ok,
            "Test endpoint accessed successfully!\n"
            "This endpoint is protected by IP whitelist.");
    });
    
    server.set_http_handler<GET>("/whitelist/status", [&server](coro_http_request& req, coro_http_response& resp) {
        std::string status = server.is_ip_whitelist_enabled() ? "enabled" : "disabled";
        std::string response = "IP Whitelist Status: " + status + "\n";
        response += "Total whitelist entries: " + std::to_string(server.get_ip_whitelist().size());
        resp.set_status_and_content(status_type::ok, response);
    });
    
    server.set_http_handler<GET>("/api/info", [](coro_http_request& req, coro_http_response& resp) {
        resp.set_status_and_content(status_type::ok,
            "{"
            "\"service\":\"HTTP Server with IP Whitelist\","
            "\"version\":\"1.0\","
            "\"framework\":\"yalantinglibs\","
            "\"protection\":\"IP Whitelist Active\""
            "}");
        resp.add_header("Content-Type", "application/json");
    });

    std::cout << "HTTP endpoints configured:\n";
    std::cout << "  GET /                - Welcome message\n";
    std::cout << "  GET /test           - Test endpoint\n";
    std::cout << "  GET /whitelist/status - Whitelist status\n";
    std::cout << "  GET /api/info       - API information (JSON)\n\n";

    // 启动服务器
    std::cout << "=== Starting HTTP Server ===\n";
    std::cout << "Starting HTTP server on port 8080...\n";
    std::cout << "Server will only accept connections from whitelisted IPs:\n";
    std::cout << "  - localhost (127.0.0.1, ::1)\n";
    std::cout << "  - Private networks (192.168.x.x, 10.x.x.x, 172.16-31.x.x)\n";
    std::cout << "  - Specific IP: 203.0.113.100\n\n";
    
    std::cout << "Test the server with:\n";
    std::cout << "  curl http://localhost:8080/\n";
    std::cout << "  curl http://localhost:8080/test\n";
    std::cout << "  curl http://localhost:8080/whitelist/status\n";
    std::cout << "  curl http://localhost:8080/api/info\n\n";
    
    std::cout << "Press Ctrl+C to stop the server.\n\n";
    
    auto result = server.sync_start();
    if (result) {
        std::cerr << "Failed to start server: " << result.message() << std::endl;
        return -1;
    }
    
    return 0;
}