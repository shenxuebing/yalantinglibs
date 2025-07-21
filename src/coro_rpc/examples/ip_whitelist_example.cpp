/*
 * Copyright (c) 2025, Alibaba Group Holding Limited;
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
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include "ylt/coro_rpc/coro_rpc_server.hpp"
#include "ylt/coro_rpc/coro_rpc_client.hpp"
#include "ylt/coro_io/ip_whitelist.hpp"

using namespace coro_rpc;
using namespace coro_io;
using namespace std::chrono_literals;

// 示例RPC函数
std::string echo(const std::string& message) {
    return "Echo: " + message;
}

int add(int a, int b) {
    return a + b;
}

std::string get_server_info() {
    return "YLT RPC Server with IP Whitelist v1.0";
}

void print_usage() {
    std::cout << "IP Whitelist Example Usage:\n"
              << "  This example demonstrates how to use IP whitelist functionality\n"
              << "  in yalantinglibs RPC server.\n\n"
              << "Features demonstrated:\n"
              << "  - Adding individual IP addresses to whitelist\n"
              << "  - Adding CIDR network ranges to whitelist\n"
              << "  - Adding IP address ranges to whitelist\n"
              << "  - Enabling/disabling whitelist checking\n"
              << "  - Testing connections from allowed/blocked IPs\n\n";
}

int main() {
    print_usage();
    
    // 创建RPC服务器
    coro_rpc_server server{1, 9001};
    
    // 注册RPC函数
    server.register_handler<echo, add, get_server_info>();
    
    // 获取服务器的IP白名单引用
    auto& whitelist = server.get_ip_whitelist();
    
    // 配置IP白名单
    std::cout << "=== Configuring IP Whitelist ===\n";
    
    // 1. 添加单个IP地址
    std::cout << "Adding individual IP addresses:\n";
    whitelist.add_ip("127.0.0.1");        // 本地回环地址
    whitelist.add_ip("::1");               // IPv6本地回环地址
    std::cout << "  - Added 127.0.0.1 (IPv4 localhost)\n";
    std::cout << "  - Added ::1 (IPv6 localhost)\n";
    
    // 2. 添加CIDR网段
    std::cout << "\nAdding CIDR network ranges:\n";
    whitelist.add_cidr("192.168.1.0/24");  // 私有网络段
    whitelist.add_cidr("10.0.0.0/8");      // 私有网络段
    std::cout << "  - Added 192.168.1.0/24 (Class C private network)\n";
    std::cout << "  - Added 10.0.0.0/8 (Class A private network)\n";
    
    // 3. 添加IP地址范围
    std::cout << "\nAdding IP address ranges:\n";
    whitelist.add_ip_range("172.16.0.1", "172.16.0.100");
    std::cout << "  - Added range 172.16.0.1 - 172.16.0.100\n";
    
    // 4. 添加正则表达式模式
    std::cout << "\nAdding regex patterns:\n";
    whitelist.add_regex_pattern(R"(192\.168\.100\.\d+)");
    std::cout << "  - Added regex pattern for 192.168.100.x\n";
    
    std::cout << "\nTotal whitelist entries: " << whitelist.size() << "\n";
    
    // 启用IP白名单
    server.enable_ip_whitelist(true);
    std::cout << "\nIP whitelist enabled: " << (server.is_ip_whitelist_enabled() ? "Yes" : "No") << "\n";
    
    // 测试一些IP地址
    std::cout << "\n=== Testing IP Address Validation ===\n";
    std::vector<std::string> test_ips = {
        "127.0.0.1",           // 应该被允许
        "192.168.1.50",        // 应该被允许（CIDR范围内）
        "10.10.10.10",         // 应该被允许（CIDR范围内）
        "172.16.0.50",         // 应该被允许（IP范围内）
        "192.168.100.200",     // 应该被允许（正则匹配）
        "8.8.8.8",             // 应该被拒绝
        "192.168.2.1",         // 应该被拒绝
        "172.16.0.200"         // 应该被拒绝（超出范围）
    };
    
    for (const auto& ip : test_ips) {
        bool allowed = whitelist.is_allowed(ip);
        std::cout << "  IP " << ip << ": " << (allowed ? "ALLOWED" : "BLOCKED") << "\n";
    }
    
    // 启动服务器
    std::cout << "\n=== Starting RPC Server ===\n";
    std::cout << "Server starting on port 9001...\n";
    std::cout << "Only connections from whitelisted IPs will be accepted.\n";
    
    std::thread server_thread([&server]() {
        auto result = server.start();
        if (result) {
            std::cerr << "Server start failed: " << result.message() << std::endl;
        }
    });
    
    // 等待服务器启动
    std::this_thread::sleep_for(500ms);
    
    // 测试客户端连接
    std::cout << "\n=== Testing Client Connections ===\n";
    
    // 测试从本地连接（应该成功）
    std::cout << "Testing connection from localhost (127.0.0.1):\n";
    try {
        coro_rpc_client client;
        auto connect_result = syncAwait(client.connect("127.0.0.1", "9001"));
        
        if (!connect_result) {
            std::cout << "  ✓ Connection successful!\n";
            
            // 测试RPC调用
            auto echo_result = syncAwait(client.call<echo>("Hello from whitelisted client!"));
            if (echo_result.has_value()) {
                std::cout << "  ✓ RPC call successful: " << echo_result.value() << "\n";
            }
            
            auto add_result = syncAwait(client.call<add>(10, 20));
            if (add_result.has_value()) {
                std::cout << "  ✓ Add function result: " << add_result.value() << "\n";
            }
            
            auto info_result = syncAwait(client.call<get_server_info>());
            if (info_result.has_value()) {
                std::cout << "  ✓ Server info: " << info_result.value() << "\n";
            }
        } else {
            std::cout << "  ✗ Connection failed: " << connect_result.message() << "\n";
        }
    } catch (const std::exception& e) {
        std::cout << "  ✗ Connection exception: " << e.what() << "\n";
    }
    
    // 演示如何动态修改白名单
    std::cout << "\n=== Dynamic Whitelist Management ===\n";
    
    // 添加新的IP
    std::cout << "Adding new IP 192.168.50.100 to whitelist...\n";
    whitelist.add_ip("192.168.50.100");
    
    // 移除IP
    std::cout << "Removing IP 192.168.1.0/24 from whitelist...\n";
    // 注意：当前实现不支持移除CIDR，只能移除单个IP
    
    // 演示set_ip_whitelist方法
    std::cout << "\n=== Demonstrating set_ip_whitelist Method ===\n";
    
    // 创建一个新的白名单配置
    std::cout << "Creating a new whitelist configuration...\n";
    coro_io::ip_whitelist new_whitelist;
    new_whitelist.add_ip("127.0.0.1");
    new_whitelist.add_ip("::1");
    new_whitelist.add_cidr("192.168.0.0/16");  // 更大的私有网络范围
    new_whitelist.add_regex_pattern(R"(10\.0\.1\.\d+)");  // 特定子网的正则匹配
    
    std::cout << "New whitelist contains:\n";
    std::cout << "  - 127.0.0.1 (localhost)\n";
    std::cout << "  - ::1 (IPv6 localhost)\n";
    std::cout << "  - 192.168.0.0/16 (Private Class B network)\n";
    std::cout << "  - Regex pattern: 10.0.1.x\n";
    
    // 使用copy版本设置白名单
    std::cout << "\nSetting whitelist using copy method...\n";
    server.set_ip_whitelist(new_whitelist);
    std::cout << "Whitelist updated! New size: " << server.get_ip_whitelist().size() << "\n";
    
    // 验证新的白名单配置
    std::vector<std::string> new_test_ips = {
        "127.0.0.1",        // 应该被允许
        "192.168.10.50",    // 应该被允许（新CIDR范围内）
        "10.0.1.100",       // 应该被允许（正则匹配）
        "192.168.1.50",     // 应该被允许（CIDR范围内，之前是单独的/24）
        "10.0.2.100",       // 应该被拒绝（正则不匹配）
        "172.16.0.50"       // 应该被拒绝（不在新白名单中）
    };
    
    std::cout << "\nTesting new whitelist configuration:\n";
    for (const auto& ip : new_test_ips) {
        bool allowed = server.get_ip_whitelist().is_allowed(ip);
        std::cout << "  IP " << ip << ": " << (allowed ? "ALLOWED" : "BLOCKED") << "\n";
    }
    
    // 演示move版本
    std::cout << "\nDemonstrating move version of set_ip_whitelist...\n";
    coro_io::ip_whitelist move_whitelist;
    move_whitelist.add_ip("127.0.0.1");
    move_whitelist.add_ip("::1");
    move_whitelist.add_ip("203.0.113.0");  // TEST-NET-3 (RFC 5737)
    
    server.set_ip_whitelist(std::move(move_whitelist));
    std::cout << "Whitelist replaced using move semantics.\n";
    std::cout << "New whitelist size: " << server.get_ip_whitelist().size() << "\n";
    
    // 临时禁用白名单
    std::cout << "\nTemporarily disabling IP whitelist...\n";
    server.enable_ip_whitelist(false);
    std::cout << "IP whitelist disabled. All connections will be accepted.\n";
    
    // 重新启用白名单
    std::this_thread::sleep_for(2s);
    std::cout << "Re-enabling IP whitelist...\n";
    server.enable_ip_whitelist(true);
    
    // 最终配置：重新设置为基本的本地访问白名单
    std::cout << "\nFinal configuration: Setting basic localhost whitelist...\n";
    coro_io::ip_whitelist final_whitelist;
    final_whitelist.add_ip("127.0.0.1");
    final_whitelist.add_ip("::1");
    server.set_ip_whitelist(std::move(final_whitelist));
    std::cout << "Final whitelist set with localhost access only.\n";
    
    std::cout << "\n=== Server Running ===\n";
    std::cout << "Server is running with IP whitelist protection.\n";
    std::cout << "Press Ctrl+C to stop the server.\n";
    std::cout << "\nYou can test the server using:\n";
    std::cout << "  - Allowed IPs: 127.0.0.1, ::1\n";
    std::cout << "  - RPC functions: echo, add, get_server_info\n";
    std::cout << "\nExample client test:\n";
    std::cout << "  coro_rpc_client client;\n";
    std::cout << "  client.connect(\"127.0.0.1\", \"9001\");\n";
    std::cout << "  auto result = client.call<echo>(\"Hello World\");\n";
    
    // 等待用户中断
    if (server_thread.joinable()) {
        server_thread.join();
    }
    
    return 0;
}