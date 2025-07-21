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
#include <doctest.h>
#include "ylt/coro_http/coro_http_server.hpp"
#include "ylt/coro_http/coro_http_client.hpp"
#include <thread>
#include <chrono>

using namespace coro_http;

TEST_CASE("test http ip whitelist basic functionality") {
    coro_http_server server(1, 0);  // 使用随机端口
    
    // 设置测试处理器
    server.set_http_handler<GET>("/test", [](coro_http_request& req, coro_http_response& resp) {
        resp.set_status_and_content(status_type::ok, "Success");
    });
    
    // 配置白名单
    auto& whitelist = server.get_ip_whitelist();
    whitelist.add_ip("127.0.0.1");
    
    // 验证白名单配置
    CHECK(whitelist.is_allowed("127.0.0.1"));
    CHECK_FALSE(whitelist.is_allowed("192.168.1.100"));
    
    // 启用白名单
    server.enable_ip_whitelist(true);
    CHECK(server.is_ip_whitelist_enabled());
    
    // 禁用白名单
    server.enable_ip_whitelist(false);
    CHECK_FALSE(server.is_ip_whitelist_enabled());
}

TEST_CASE("test http ip whitelist cidr network support") {
    coro_http_server server(1, 0);
    auto& whitelist = server.get_ip_whitelist();
    
    // 添加CIDR网段
    whitelist.add_cidr("192.168.1.0/24");
    
    // 测试网段内的IP
    CHECK(whitelist.is_allowed("192.168.1.1"));
    CHECK(whitelist.is_allowed("192.168.1.100"));
    CHECK(whitelist.is_allowed("192.168.1.254"));
    
    // 测试网段外的IP
    CHECK_FALSE(whitelist.is_allowed("192.168.2.1"));
    CHECK_FALSE(whitelist.is_allowed("10.0.0.1"));
}

TEST_CASE("test http ip whitelist ip range support") {
    coro_http_server server(1, 0);
    auto& whitelist = server.get_ip_whitelist();
    
    // 添加IP范围
    whitelist.add_ip_range("10.0.0.10", "10.0.0.20");
    
    // 测试范围内的IP
    CHECK(whitelist.is_allowed("10.0.0.10"));
    CHECK(whitelist.is_allowed("10.0.0.15"));
    CHECK(whitelist.is_allowed("10.0.0.20"));
    
    // 测试范围外的IP
    CHECK_FALSE(whitelist.is_allowed("10.0.0.9"));
    CHECK_FALSE(whitelist.is_allowed("10.0.0.21"));
}

TEST_CASE("test http ip whitelist regex pattern support") {
    coro_http_server server(1, 0);
    auto& whitelist = server.get_ip_whitelist();
    
    // 添加正则表达式模式
    whitelist.add_regex_pattern("192\\.168\\.1\\.\\d+");
    
    // 测试匹配的IP
    CHECK(whitelist.is_allowed("192.168.1.1"));
    CHECK(whitelist.is_allowed("192.168.1.255"));
    
    // 测试不匹配的IP
    CHECK_FALSE(whitelist.is_allowed("192.168.2.1"));
    CHECK_FALSE(whitelist.is_allowed("10.0.0.1"));
}

TEST_CASE("test http ip whitelist ipv6 support") {
    coro_http_server server(1, 0);
    auto& whitelist = server.get_ip_whitelist();
    
    // 添加IPv6地址
    whitelist.add_ip("::1");
    whitelist.add_ip("2001:db8::1");
    
    // 测试IPv6地址
    CHECK(whitelist.is_allowed("::1"));
    CHECK(whitelist.is_allowed("2001:db8::1"));
    
    // 测试未在白名单中的IPv6地址
    CHECK_FALSE(whitelist.is_allowed("2001:db8::2"));
}

TEST_CASE("test http ip whitelist batch operations") {
    coro_http_server server(1, 0);
    auto& whitelist = server.get_ip_whitelist();
    
    // 批量添加IP
    std::vector<std::string> ips = {"192.168.1.1", "192.168.1.2", "192.168.1.3"};
    whitelist.add_ips(ips);
    
    // 验证批量添加
    for (const auto& ip : ips) {
        CHECK(whitelist.is_allowed(ip));
    }
    
    // 批量添加CIDR
    std::vector<std::string> cidrs = {"10.0.0.0/8", "172.16.0.0/12"};
    whitelist.add_cidrs(cidrs);
    
    // 验证CIDR批量添加
    CHECK(whitelist.is_allowed("10.1.1.1"));
    CHECK(whitelist.is_allowed("172.16.1.1"));
}

TEST_CASE("test http ip whitelist management") {
    coro_http_server server(1, 0);
    auto& whitelist = server.get_ip_whitelist();
    
    // 添加IP
    whitelist.add_ip("192.168.1.1");
    CHECK(whitelist.is_allowed("192.168.1.1"));
    
    // 移除IP
    whitelist.remove_ip("192.168.1.1");
    CHECK_FALSE(whitelist.is_allowed("192.168.1.1"));
    
    // 添加多个IP后清空
    whitelist.add_ip("192.168.1.1");
    whitelist.add_ip("192.168.1.2");
    whitelist.clear();
    
    CHECK_FALSE(whitelist.is_allowed("192.168.1.1"));
    CHECK_FALSE(whitelist.is_allowed("192.168.1.2"));
}

TEST_CASE("test http ip whitelist thread safety") {
    coro_http_server server(1, 0);
    auto& whitelist = server.get_ip_whitelist();
    
    const int num_threads = 10;
    const int operations_per_thread = 100;
    
    std::vector<std::thread> threads;
    std::atomic<int> success_count(0);
    
    // 启动多个线程同时进行白名单操作
    for (int i = 0; i < num_threads; ++i) {
        threads.emplace_back([&whitelist, &success_count, operations_per_thread, i]() {
            for (int j = 0; j < operations_per_thread; ++j) {
                std::string ip = "192.168." + std::to_string(i) + "." + std::to_string(j);
                whitelist.add_ip(ip);
                
                if (whitelist.is_allowed(ip)) {
                    success_count++;
                }
                
                whitelist.remove_ip(ip);
            }
        });
    }
    
    // 等待所有线程完成
    for (auto& thread : threads) {
        thread.join();
    }
    
    // 验证线程安全性
    CHECK(success_count.load() == num_threads * operations_per_thread);
}

// 集成测试 - 测试服务器启动和基本连接
TEST_CASE("test http server integration with whitelist") {
    coro_http_server server(1, 0);  // 使用随机端口
    
    // 设置测试处理器
    server.set_http_handler<GET>("/test", [](coro_http_request& req, coro_http_response& resp) {
        resp.set_status_and_content(status_type::ok, "Success");
    });
    
    // 配置白名单只允许本地连接
    auto& whitelist = server.get_ip_whitelist();
    whitelist.add_ip("127.0.0.1");
    whitelist.add_ip("::1");
    
    server.enable_ip_whitelist(true);
    
    // 启动服务器
    std::thread server_thread([&server]() {
        server.sync_start();
    });
    
    // 等待服务器启动
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    // 获取服务器端口
    uint16_t port = server.port();
    CHECK(port > 0);
    
    // 测试连接 - 注意：这个测试可能需要根据实际的客户端实现调整
    // 在实际环境中，白名单会在连接层面生效
    
    server.stop();
    if (server_thread.joinable()) {
        server_thread.join();
    }
}
TEST_CASE("test http server set_ip_whitelist method") {
    // 测试set_ip_whitelist方法
    coro_http_server server(1, 0);  // 使用随机端口
    
    // 设置测试处理器
    server.set_http_handler<GET>("/test", [](coro_http_request& req, coro_http_response& resp) {
        resp.set_status_and_content(status_type::ok, "Success");
    });
    
    // 创建一个新的IP白名单
    coro_io::ip_whitelist new_whitelist;
    new_whitelist.add_ip("127.0.0.1");
    new_whitelist.add_ip("192.168.1.100");
    new_whitelist.add_cidr("10.0.0.0/8");
    
    // 使用copy版本设置IP白名单
    server.set_ip_whitelist(new_whitelist);
    server.enable_ip_whitelist(true);
    
    // 验证白名单设置是否生效
    auto& whitelist = server.get_ip_whitelist();
    CHECK(whitelist.is_allowed("127.0.0.1"));
    CHECK(whitelist.is_allowed("192.168.1.100"));
    CHECK(whitelist.is_allowed("10.1.2.3"));  // CIDR范围内
    CHECK_FALSE(whitelist.is_allowed("8.8.8.8"));   // 不在白名单中
    
    // 测试move版本
    coro_io::ip_whitelist another_whitelist;
    another_whitelist.add_ip("172.16.0.1");
    another_whitelist.add_regex_pattern(R"(192\.168\.1\.\d+)");
    
    server.set_ip_whitelist(std::move(another_whitelist));
    
    // 验证新的白名单设置
    CHECK(whitelist.is_allowed("172.16.0.1"));
    CHECK(whitelist.is_allowed("192.168.1.50"));  // regex匹配
    CHECK_FALSE(whitelist.is_allowed("127.0.0.1"));    // 之前的规则应该被替换
}