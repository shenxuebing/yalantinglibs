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

#include <gtest/gtest.h>
#include <thread>
#include <chrono>
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

class IPWhitelistTest : public ::testing::Test {
protected:
    void SetUp() override {
        // 注册测试用的RPC函数
        server_.register_handler<echo>();
    }

    void TearDown() override {
        if (server_thread_.joinable()) {
            server_.stop();
            server_thread_.join();
        }
    }

    void StartServer(uint16_t port = 9001) {
        server_thread_ = std::thread([this, port]() {
            auto result = server_.start();
            if (result) {
                std::cerr << "Server start failed: " << result.message() << std::endl;
            }
        });
        
        // 等待服务器启动
        std::this_thread::sleep_for(100ms);
    }

    coro_rpc_server server_{1, 9001};
    std::thread server_thread_;
};

// 测试IP白名单基本功能
TEST_F(IPWhitelistTest, BasicIPWhitelistTest) {
    ip_whitelist whitelist;
    
    // 测试添加单个IP
    EXPECT_TRUE(whitelist.add_ip("127.0.0.1"));
    EXPECT_TRUE(whitelist.add_ip("192.168.1.100"));
    EXPECT_TRUE(whitelist.add_ip("::1"));  // IPv6 localhost
    
    // 测试格式错误的IP
    EXPECT_FALSE(whitelist.add_ip("invalid_ip"));
    EXPECT_FALSE(whitelist.add_ip("256.256.256.256"));
    
    // 测试IP检查
    EXPECT_TRUE(whitelist.is_allowed("127.0.0.1"));
    EXPECT_TRUE(whitelist.is_allowed("192.168.1.100"));
    EXPECT_TRUE(whitelist.is_allowed("::1"));
    EXPECT_FALSE(whitelist.is_allowed("192.168.1.101"));
    EXPECT_FALSE(whitelist.is_allowed("10.0.0.1"));
    
    // 测试大小和清空
    EXPECT_EQ(whitelist.size(), 3);
    EXPECT_FALSE(whitelist.empty());
    
    whitelist.clear();
    EXPECT_EQ(whitelist.size(), 0);
    EXPECT_TRUE(whitelist.empty());
}

// 测试CIDR网段功能
TEST_F(IPWhitelistTest, CIDRNetworkTest) {
    ip_whitelist whitelist;
    
    // 添加CIDR网段
    EXPECT_TRUE(whitelist.add_cidr("192.168.1.0/24"));
    EXPECT_TRUE(whitelist.add_cidr("10.0.0.0/8"));
    EXPECT_TRUE(whitelist.add_cidr("2001:db8::/32"));  // IPv6 CIDR
    
    // 测试格式错误的CIDR
    EXPECT_FALSE(whitelist.add_cidr("192.168.1.0"));  // 缺少前缀
    EXPECT_FALSE(whitelist.add_cidr("192.168.1.0/"));  // 前缀为空
    EXPECT_FALSE(whitelist.add_cidr("192.168.1.0/33")); // 前缀超范围
    
    // 测试CIDR范围内的IP
    EXPECT_TRUE(whitelist.is_allowed("192.168.1.1"));
    EXPECT_TRUE(whitelist.is_allowed("192.168.1.254"));
    EXPECT_TRUE(whitelist.is_allowed("10.10.10.10"));
    EXPECT_TRUE(whitelist.is_allowed("10.255.255.255"));
    
    // 测试CIDR范围外的IP
    EXPECT_FALSE(whitelist.is_allowed("192.168.2.1"));
    EXPECT_FALSE(whitelist.is_allowed("11.0.0.1"));
    EXPECT_FALSE(whitelist.is_allowed("127.0.0.1"));
}

// 测试IP范围功能
TEST_F(IPWhitelistTest, IPRangeTest) {
    ip_whitelist whitelist;
    
    // 添加IP范围
    EXPECT_TRUE(whitelist.add_ip_range("192.168.1.10", "192.168.1.20"));
    EXPECT_TRUE(whitelist.add_ip_range("10.0.0.1", "10.0.0.100"));
    
    // 测试版本不匹配的范围
    EXPECT_FALSE(whitelist.add_ip_range("192.168.1.1", "::1"));
    
    // 测试范围内的IP
    EXPECT_TRUE(whitelist.is_allowed("192.168.1.10"));
    EXPECT_TRUE(whitelist.is_allowed("192.168.1.15"));
    EXPECT_TRUE(whitelist.is_allowed("192.168.1.20"));
    EXPECT_TRUE(whitelist.is_allowed("10.0.0.50"));
    
    // 测试范围外的IP
    EXPECT_FALSE(whitelist.is_allowed("192.168.1.9"));
    EXPECT_FALSE(whitelist.is_allowed("192.168.1.21"));
    EXPECT_FALSE(whitelist.is_allowed("10.0.0.101"));
}

// 测试正则表达式功能
TEST_F(IPWhitelistTest, RegexPatternTest) {
    ip_whitelist whitelist;
    
    // 添加正则表达式模式
    EXPECT_TRUE(whitelist.add_regex_pattern(R"(192\.168\.1\.\d+)"));
    EXPECT_TRUE(whitelist.add_regex_pattern(R"(127\.0\.0\.[1-5])"));
    
    // 测试匹配的IP
    EXPECT_TRUE(whitelist.is_allowed("192.168.1.1"));
    EXPECT_TRUE(whitelist.is_allowed("192.168.1.255"));
    EXPECT_TRUE(whitelist.is_allowed("127.0.0.1"));
    EXPECT_TRUE(whitelist.is_allowed("127.0.0.5"));
    
    // 测试不匹配的IP
    EXPECT_FALSE(whitelist.is_allowed("192.168.2.1"));
    EXPECT_FALSE(whitelist.is_allowed("127.0.0.6"));
    EXPECT_FALSE(whitelist.is_allowed("10.0.0.1"));
}

// 测试批量操作
TEST_F(IPWhitelistTest, BatchOperationsTest) {
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
    EXPECT_EQ(whitelist.add_ips(ips), 3);
    
    // 测试批量添加CIDR，应该成功添加2个有效CIDR
    EXPECT_EQ(whitelist.add_cidrs(cidrs), 2);
    
    // 验证添加的IP和CIDR是否生效
    EXPECT_TRUE(whitelist.is_allowed("127.0.0.1"));
    EXPECT_TRUE(whitelist.is_allowed("192.168.1.1"));
    EXPECT_TRUE(whitelist.is_allowed("10.0.0.1"));
    EXPECT_TRUE(whitelist.is_allowed("192.168.100.100")); // CIDR范围内
    EXPECT_TRUE(whitelist.is_allowed("10.255.255.255"));  // CIDR范围内
}

// 测试RPC服务器集成IP白名单
TEST_F(IPWhitelistTest, ServerIntegrationTest) {
    // 配置IP白名单，只允许本地连接
    auto& whitelist = server_.get_ip_whitelist();
    whitelist.add_ip("127.0.0.1");
    whitelist.add_ip("::1");
    server_.enable_ip_whitelist(true);
    
    EXPECT_TRUE(server_.is_ip_whitelist_enabled());
    
    // 启动服务器
    StartServer();
    
    // 测试允许的客户端连接
    {
        coro_rpc_client client;
        auto result = syncAwait(client.connect("127.0.0.1", "9001"));
        EXPECT_TRUE(result.has_value());
        
        if (result.has_value()) {
            auto echo_result = syncAwait(client.call<echo>("hello"));
            EXPECT_TRUE(echo_result.has_value());
            if (echo_result.has_value()) {
                EXPECT_EQ(echo_result.value(), "echo: hello");
            }
        }
    }
    
    // 注意：由于测试环境限制，我们无法轻易测试从其他IP地址的连接
    // 在实际环境中，可以通过网络配置来测试被拒绝的连接
}

// 测试全局IP白名单
TEST_F(IPWhitelistTest, GlobalWhitelistTest) {
    auto& global_whitelist = global_ip_whitelist();
    
    // 清空全局白名单
    global_whitelist.clear();
    EXPECT_TRUE(global_whitelist.empty());
    
    // 添加一些IP到全局白名单
    global_whitelist.add_ip("127.0.0.1");
    global_whitelist.add_cidr("192.168.0.0/16");
    
    EXPECT_FALSE(global_whitelist.empty());
    EXPECT_TRUE(global_whitelist.is_allowed("127.0.0.1"));
    EXPECT_TRUE(global_whitelist.is_allowed("192.168.1.100"));
    EXPECT_FALSE(global_whitelist.is_allowed("10.0.0.1"));
    
    // 清理
    global_whitelist.clear();
}

// 测试移除IP功能
TEST_F(IPWhitelistTest, RemoveIPTest) {
    ip_whitelist whitelist;
    
    // 添加一些IP
    whitelist.add_ip("127.0.0.1");
    whitelist.add_ip("192.168.1.1");
    whitelist.add_ip("10.0.0.1");
    
    EXPECT_EQ(whitelist.size(), 3);
    EXPECT_TRUE(whitelist.is_allowed("127.0.0.1"));
    
    // 移除IP
    EXPECT_TRUE(whitelist.remove_ip("127.0.0.1"));
    EXPECT_FALSE(whitelist.is_allowed("127.0.0.1"));
    EXPECT_EQ(whitelist.size(), 2);
    
    // 尝试移除不存在的IP
    EXPECT_FALSE(whitelist.remove_ip("127.0.0.1"));
    EXPECT_EQ(whitelist.size(), 2);
    
    // 尝试移除格式错误的IP
    EXPECT_FALSE(whitelist.remove_ip("invalid_ip"));
    EXPECT_EQ(whitelist.size(), 2);
}