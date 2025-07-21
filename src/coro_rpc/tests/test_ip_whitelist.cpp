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

#include <thread>
#include <chrono>
#include <async_simple/coro/SyncAwait.h>
#include "doctest.h"
#include "ylt/coro_io/ip_whitelist.hpp"
#include "ylt/coro_rpc/coro_rpc_server.hpp"
#include "ylt/coro_rpc/coro_rpc_client.hpp"

using namespace coro_io;
using namespace coro_rpc;
using namespace std::chrono_literals;

// 测试用的RPC函数
std::string echo(const std::string& msg) {
    return "echo: " + msg;
}

// 测试IP白名单基本功能
TEST_CASE("IP whitelist basic functionality") {
    ip_whitelist whitelist;
    
    // 测试添加单个IP
    CHECK(whitelist.add_ip("127.0.0.1"));
    CHECK(whitelist.add_ip("192.168.1.100"));
    CHECK(whitelist.add_ip("::1"));  // IPv6 localhost
    
    // 测试格式错误的IP
    CHECK_FALSE(whitelist.add_ip("invalid_ip"));
    CHECK_FALSE(whitelist.add_ip("256.256.256.256"));
    
    // 测试IP检查
    CHECK(whitelist.is_allowed("127.0.0.1"));
    CHECK(whitelist.is_allowed("192.168.1.100"));
    CHECK(whitelist.is_allowed("::1"));
    CHECK_FALSE(whitelist.is_allowed("192.168.1.101"));
    CHECK_FALSE(whitelist.is_allowed("10.0.0.1"));
    
    // 测试大小和清空
    CHECK_EQ(whitelist.size(), 3);
    CHECK_FALSE(whitelist.empty());
    
    whitelist.clear();
    CHECK_EQ(whitelist.size(), 0);
    CHECK(whitelist.empty());
}

// 测试CIDR网段功能
TEST_CASE("IP whitelist CIDR network functionality") {
    ip_whitelist whitelist;
    
    // 添加CIDR网段
    CHECK(whitelist.add_cidr("192.168.1.0/24"));
    CHECK(whitelist.add_cidr("10.0.0.0/8"));
    CHECK(whitelist.add_cidr("2001:db8::/32"));  // IPv6 CIDR
    
    // 测试格式错误的CIDR
    CHECK_FALSE(whitelist.add_cidr("192.168.1.0"));  // 缺少前缀
    CHECK_FALSE(whitelist.add_cidr("192.168.1.0/"));  // 前缀为空
    CHECK_FALSE(whitelist.add_cidr("192.168.1.0/33")); // 前缀超范围
    
    // 测试CIDR范围内的IP
    CHECK(whitelist.is_allowed("192.168.1.1"));
    CHECK(whitelist.is_allowed("192.168.1.254"));
    CHECK(whitelist.is_allowed("10.10.10.10"));
    CHECK(whitelist.is_allowed("10.255.255.255"));
    
    // 测试CIDR范围外的IP
    CHECK_FALSE(whitelist.is_allowed("192.168.2.1"));
    CHECK_FALSE(whitelist.is_allowed("11.0.0.1"));
    CHECK_FALSE(whitelist.is_allowed("127.0.0.1"));
}

// 测试IP范围功能
TEST_CASE("IP whitelist IP range functionality") {
    ip_whitelist whitelist;
    
    // 添加IP范围
    CHECK(whitelist.add_ip_range("192.168.1.10", "192.168.1.20"));
    CHECK(whitelist.add_ip_range("10.0.0.1", "10.0.0.100"));
    
    // 测试版本不匹配的范围
    CHECK_FALSE(whitelist.add_ip_range("192.168.1.1", "::1"));
    
    // 测试范围内的IP
    CHECK(whitelist.is_allowed("192.168.1.10"));
    CHECK(whitelist.is_allowed("192.168.1.15"));
    CHECK(whitelist.is_allowed("192.168.1.20"));
    CHECK(whitelist.is_allowed("10.0.0.50"));
    
    // 测试范围外的IP
    CHECK_FALSE(whitelist.is_allowed("192.168.1.9"));
    CHECK_FALSE(whitelist.is_allowed("192.168.1.21"));
    CHECK_FALSE(whitelist.is_allowed("10.0.0.101"));
}

// 测试正则表达式功能
TEST_CASE("IP whitelist regex pattern functionality") {
    ip_whitelist whitelist;
    
    // 添加正则表达式模式
    CHECK(whitelist.add_regex_pattern(R"(192\.168\.1\.\d+)"));
    CHECK(whitelist.add_regex_pattern(R"(127\.0\.0\.[1-5])"));
    
    // 测试匹配的IP
    CHECK(whitelist.is_allowed("192.168.1.1"));
    CHECK(whitelist.is_allowed("192.168.1.255"));
    CHECK(whitelist.is_allowed("127.0.0.1"));
    CHECK(whitelist.is_allowed("127.0.0.5"));
    
    // 测试不匹配的IP
    CHECK_FALSE(whitelist.is_allowed("192.168.2.1"));
    CHECK_FALSE(whitelist.is_allowed("127.0.0.6"));
    CHECK_FALSE(whitelist.is_allowed("10.0.0.1"));
}

// 测试批量操作
TEST_CASE("IP whitelist batch operations") {
    ip_whitelist whitelist;
    
    std::vector<std::string> ips = {
        "127.0.0.1",
        "192.168.1.1",
        "invalid_ip",
        "10.0.0.1"
    };
    
    std::vector<std::string> cidrs = {
        "192.168.0.0/16",
        "invalid_cidr",
        "10.0.0.0/8"
    };
    
    // 测试批量添加IP，应该成功添加3个有效IP
    CHECK_EQ(whitelist.add_ips(ips), 3);
    
    // 测试批量添加CIDR，应该成功添加2个有效CIDR
    CHECK_EQ(whitelist.add_cidrs(cidrs), 2);
    
    // 验证添加的IP和CIDR是否生效
    CHECK(whitelist.is_allowed("127.0.0.1"));
    CHECK(whitelist.is_allowed("192.168.1.1"));
    CHECK(whitelist.is_allowed("10.0.0.1"));
    CHECK(whitelist.is_allowed("192.168.100.100")); // CIDR范围内
    CHECK(whitelist.is_allowed("10.255.255.255"));  // CIDR范围内
}

// 测试RPC服务器集成IP白名单
TEST_CASE("RPC server IP whitelist integration") {
    coro_rpc_server server(1, 9001);
    server.register_handler<echo>();
    
    // 配置IP白名单，只允许本地连接
    auto& whitelist = server.get_ip_whitelist();
    whitelist.add_ip("127.0.0.1");
    whitelist.add_ip("::1");
    server.enable_ip_whitelist(true);
    
    CHECK(server.is_ip_whitelist_enabled());
    
    // 启动服务器
    std::thread server_thread([&server]() {
        auto result = server.start();
    });
    
    // 等待服务器启动
    std::this_thread::sleep_for(100ms);
    
    // 测试允许的客户端连接
    {
        coro_rpc_client client;
        auto result = syncAwait(client.connect("127.0.0.1", "9001"));
        CHECK(!result);
        
        if (!result) {
            auto echo_result = syncAwait(client.call<echo>("hello"));
            CHECK(echo_result.has_value());
            if (echo_result.has_value()) {
                CHECK_EQ(echo_result.value(), "echo: hello");
            }
        }
    }
    
    // 停止服务器
    server.stop();
    if (server_thread.joinable()) {
        server_thread.join();
    }
    
    // 注意：由于测试环境限制，我们无法轻易测试从其他IP地址的连接
    // 在实际环境中，可以通过网络配置来测试被拒绝的连接
}

// 测试移除IP功能
TEST_CASE("IP whitelist remove IP functionality") {
    ip_whitelist whitelist;
    
    // 添加一些IP
    whitelist.add_ip("127.0.0.1");
    whitelist.add_ip("192.168.1.1");
    whitelist.add_ip("10.0.0.1");
    
    CHECK_EQ(whitelist.size(), 3);
    CHECK(whitelist.is_allowed("127.0.0.1"));
    
    // 移除IP
    CHECK(whitelist.remove_ip("127.0.0.1"));
    CHECK_FALSE(whitelist.is_allowed("127.0.0.1"));
    CHECK_EQ(whitelist.size(), 2);
    
    // 尝试移除不存在的IP
    CHECK_FALSE(whitelist.remove_ip("127.0.0.1"));
    CHECK_EQ(whitelist.size(), 2);
    
    // 尝试移除格式错误的IP
    CHECK_FALSE(whitelist.remove_ip("invalid_ip"));
    CHECK_EQ(whitelist.size(), 2);
}
// 测试RPC服务器set_ip_whitelist方法
TEST_CASE("RPC server set_ip_whitelist method") {
    // 测试set_ip_whitelist方法
    coro_rpc_server server(1, 9002);
    server.register_handler<echo>();
    
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