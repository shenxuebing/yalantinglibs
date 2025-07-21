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

int main() {
    // 创建HTTP服务器
    coro_http_server server(1, 8080);

    // 配置IP白名单
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
    
    // 启用IP白名单
    server.enable_ip_whitelist(true);
    std::cout << "IP whitelist enabled\n";

    // 设置简单的HTTP处理器
    server.set_http_handler<GET>("/", [](coro_http_request& req, coro_http_response& resp) {
        resp.set_status_and_content(status_type::ok, "Hello from HTTP server with IP whitelist!");
    });
    
    server.set_http_handler<GET>("/test", [](coro_http_request& req, coro_http_response& resp) {
        resp.set_status_and_content(status_type::ok, "Test endpoint accessed successfully!");
    });
    
    server.set_http_handler<GET>("/whitelist/status", [&server](coro_http_request& req, coro_http_response& resp) {
        std::string status = server.is_ip_whitelist_enabled() ? "enabled" : "disabled";
        resp.set_status_and_content(status_type::ok, "IP Whitelist status: " + status);
    });

    // 启动服务器
    std::cout << "Starting HTTP server on port 8080...\n";
    auto result = server.sync_start();
    if (result) {
        std::cerr << "Failed to start server: " << result.message() << std::endl;
        return -1;
    }
    
    return 0;
}