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
#pragma once

#include "asio/ip/address.hpp"
#include "asio/ip/network_v4.hpp"
#include "asio/ip/network_v6.hpp"
#include <shared_mutex>
#include <string>
#include <unordered_set>
#include <vector>
#include <regex>
#include <cstring>
#include <sstream>
#include "ylt/easylog.hpp"

namespace coro_io {

/**
 * @brief IP白名单管理器
 * 
 * 提供IP白名单的管理功能，支持：
 * - 单个IP地址
 * - CIDR网段
 * - IP地址范围
 * - 正则表达式匹配
 */
class ip_whitelist {
public:
    /**
     * @brief 默认构造函数，创建空白名单
     */
    ip_whitelist() = default;
    
    /**
     * @brief 拷贝构造函数
     * @param other 要拷贝的源对象
     */
    ip_whitelist(const ip_whitelist& other) {
        std::shared_lock<std::shared_mutex> lock(other.mutex_);
        single_ips_ = other.single_ips_;
        cidr_v4_networks_ = other.cidr_v4_networks_;
        cidr_v6_networks_ = other.cidr_v6_networks_;
        ip_ranges_ = other.ip_ranges_;
        regex_patterns_ = other.regex_patterns_;
    }
    
    /**
     * @brief 拷贝赋值运算符
     * @param other 要拷贝的源对象
     * @return 当前对象的引用
     */
    ip_whitelist& operator=(const ip_whitelist& other) {
        if (this != &other) {
            std::shared_lock<std::shared_mutex> other_lock(other.mutex_);
            std::unique_lock<std::shared_mutex> this_lock(mutex_);
            
            single_ips_ = other.single_ips_;
            cidr_v4_networks_ = other.cidr_v4_networks_;
            cidr_v6_networks_ = other.cidr_v6_networks_;
            ip_ranges_ = other.ip_ranges_;
            regex_patterns_ = other.regex_patterns_;
        }
        return *this;
    }
    
    /**
     * @brief 移动构造函数
     * @param other 要移动的源对象
     */
    ip_whitelist(ip_whitelist&& other) noexcept {
        std::unique_lock<std::shared_mutex> lock(other.mutex_);
        single_ips_ = std::move(other.single_ips_);
        cidr_v4_networks_ = std::move(other.cidr_v4_networks_);
        cidr_v6_networks_ = std::move(other.cidr_v6_networks_);
        ip_ranges_ = std::move(other.ip_ranges_);
        regex_patterns_ = std::move(other.regex_patterns_);
    }
    
    /**
     * @brief 移动赋值运算符
     * @param other 要移动的源对象
     * @return 当前对象的引用
     */
    ip_whitelist& operator=(ip_whitelist&& other) noexcept {
        if (this != &other) {
            std::unique_lock<std::shared_mutex> other_lock(other.mutex_);
            std::unique_lock<std::shared_mutex> this_lock(mutex_);
            
            single_ips_ = std::move(other.single_ips_);
            cidr_v4_networks_ = std::move(other.cidr_v4_networks_);
            cidr_v6_networks_ = std::move(other.cidr_v6_networks_);
            ip_ranges_ = std::move(other.ip_ranges_);
            regex_patterns_ = std::move(other.regex_patterns_);
        }
        return *this;
    }
    
    /**
     * @brief 构造函数，使用IP地址列表初始化
     * @param ips IP地址列表
     */
    explicit ip_whitelist(const std::vector<std::string>& ips) {
        for (const auto& ip : ips) {
            add_ip(ip);
        }
    }

    /**
     * @brief 添加单个IP地址到白名单
     * @param ip_str IP地址字符串，支持IPv4/IPv6
     * @return 添加成功返回true，格式错误返回false
     */
    bool add_ip(const std::string& ip_str) {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        try {
            auto addr = asio::ip::address::from_string(ip_str);
            single_ips_.insert(addr);
            ELOG_INFO << "Added IP to whitelist: " << ip_str;
            return true;
        } catch (const std::exception& e) {
            ELOG_ERROR << "Failed to add IP to whitelist: " << ip_str 
                      << ", error: " << e.what();
            return false;
        }
    }

    /**
     * @brief 添加CIDR网段到白名单
     * @param cidr_str CIDR网段字符串，如 "192.168.1.0/24"
     * @return 添加成功返回true，格式错误返回false
     */
    bool add_cidr(const std::string& cidr_str) {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        try {
            // 分离IP和前缀长度
            size_t slash_pos = cidr_str.find('/');
            if (slash_pos == std::string::npos) {
                return false;
            }
            
            std::string ip_part = cidr_str.substr(0, slash_pos);
            std::string prefix_part = cidr_str.substr(slash_pos + 1);
            
            auto addr = asio::ip::address::from_string(ip_part);
            int prefix_length = std::stoi(prefix_part);
            
            if (addr.is_v4()) {
                auto network = asio::ip::make_network_v4(cidr_str);
                cidr_v4_networks_.push_back(network);
            } else {
                auto network = asio::ip::make_network_v6(cidr_str);
                cidr_v6_networks_.push_back(network);
            }
            
            ELOG_INFO << "Added CIDR to whitelist: " << cidr_str;
            return true;
        } catch (const std::exception& e) {
            ELOG_ERROR << "Failed to add CIDR to whitelist: " << cidr_str 
                      << ", error: " << e.what();
            return false;
        }
    }

    /**
     * @brief 添加IP地址范围到白名单
     * @param start_ip 起始IP地址
     * @param end_ip 结束IP地址
     * @return 添加成功返回true，格式错误返回false
     */
    bool add_ip_range(const std::string& start_ip, const std::string& end_ip) {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        try {
            auto start_addr = asio::ip::address::from_string(start_ip);
            auto end_addr = asio::ip::address::from_string(end_ip);
            
            if (start_addr.is_v4() != end_addr.is_v4()) {
                ELOG_ERROR << "IP version mismatch in range: " << start_ip << " - " << end_ip;
                return false;
            }
            
            ip_ranges_.emplace_back(start_addr, end_addr);
            ELOG_INFO << "Added IP range to whitelist: " << start_ip << " - " << end_ip;
            return true;
        } catch (const std::exception& e) {
            ELOG_ERROR << "Failed to add IP range to whitelist: " << start_ip 
                      << " - " << end_ip << ", error: " << e.what();
            return false;
        }
    }

    /**
     * @brief 添加正则表达式模式到白名单
     * @param pattern 正则表达式模式字符串
     * @return 添加成功返回true，格式错误返回false
     */
    bool add_regex_pattern(const std::string& pattern) {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        try {
            regex_patterns_.emplace_back(pattern);
            ELOG_INFO << "Added regex pattern to whitelist: " << pattern;
            return true;
        } catch (const std::exception& e) {
            ELOG_ERROR << "Failed to add regex pattern to whitelist: " << pattern 
                      << ", error: " << e.what();
            return false;
        }
    }

    /**
     * @brief 移除IP地址从白名单
     * @param ip_str IP地址字符串
     * @return 移除成功返回true
     */
    bool remove_ip(const std::string& ip_str) {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        try {
            auto addr = asio::ip::address::from_string(ip_str);
            auto count = single_ips_.erase(addr);
            if (count > 0) {
                ELOG_INFO << "Removed IP from whitelist: " << ip_str;
                return true;
            }
            return false;
        } catch (const std::exception& e) {
            ELOG_ERROR << "Failed to remove IP from whitelist: " << ip_str 
                      << ", error: " << e.what();
            return false;
        }
    }

    /**
     * @brief 清空白名单
     */
    void clear() {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        single_ips_.clear();
        cidr_v4_networks_.clear();
        cidr_v6_networks_.clear();
        ip_ranges_.clear();
        regex_patterns_.clear();
        ELOG_INFO << "Cleared IP whitelist";
    }

    /**
     * @brief 检查IP地址是否在白名单中
     * @param ip_addr IP地址对象
     * @return 在白名单中返回true，否则返回false
     */
    bool is_allowed(const asio::ip::address& ip_addr) const {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        
        // 检查单个IP
        if (single_ips_.find(ip_addr) != single_ips_.end()) {
            return true;
        }

        // 检查CIDR网段
        if (ip_addr.is_v4()) {
            auto v4_addr = ip_addr.to_v4();
            for (const auto& network : cidr_v4_networks_) {
                if (network.hosts().find(v4_addr) != network.hosts().end()) {
                    return true;
                }
            }
        } else {
            auto v6_addr = ip_addr.to_v6();
            for (const auto& network : cidr_v6_networks_) {
                if (network.hosts().find(v6_addr) != network.hosts().end()) {
                    return true;
                }
            }
        }

        // 检查IP范围
        for (const auto& range : ip_ranges_) {
            if (is_ip_in_range(ip_addr, range.first, range.second)) {
                return true;
            }
        }

        // 检查正则表达式
        std::string ip_str = ip_addr.to_string();
        for (const auto& pattern : regex_patterns_) {
            if (std::regex_match(ip_str, pattern)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @brief 检查IP地址字符串是否在白名单中
     * @param ip_str IP地址字符串
     * @return 在白名单中返回true，格式错误或不在白名单中返回false
     */
    bool is_allowed(const std::string& ip_str) const {
        try {
            auto addr = asio::ip::address::from_string(ip_str);
            return is_allowed(addr);
        } catch (const std::exception& e) {
            ELOG_ERROR << "Invalid IP address format: " << ip_str 
                      << ", error: " << e.what();
            return false;
        }
    }

    /**
     * @brief 获取白名单大小
     * @return 白名单中条目数量
     */
    size_t size() const {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        return single_ips_.size() + cidr_v4_networks_.size() + 
               cidr_v6_networks_.size() + ip_ranges_.size() + regex_patterns_.size();
    }

    /**
     * @brief 检查白名单是否为空
     * @return 空返回true，否则返回false
     */
    bool empty() const {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        return single_ips_.empty() && cidr_v4_networks_.empty() && 
               cidr_v6_networks_.empty() && ip_ranges_.empty() && regex_patterns_.empty();
    }

    /**
     * @brief 批量添加IP地址到白名单
     * @param ips IP地址列表
     * @return 成功添加的数量
     */
    size_t add_ips(const std::vector<std::string>& ips) {
        size_t count = 0;
        for (const auto& ip : ips) {
            if (add_ip(ip)) {
                ++count;
            }
        }
        return count;
    }

    /**
     * @brief 批量添加CIDR网段到白名单
     * @param cidrs CIDR网段列表
     * @return 成功添加的数量
     */
    size_t add_cidrs(const std::vector<std::string>& cidrs) {
        size_t count = 0;
        for (const auto& cidr : cidrs) {
            if (add_cidr(cidr)) {
                ++count;
            }
        }
        return count;
    }

    /**
     * @brief 获取白名单的详细信息
     * @return 包含所有白名单条目的字符串
     */
    std::string to_string() const {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        std::ostringstream oss;
        
        // 单个IP地址
        if (!single_ips_.empty()) {
            oss << "Single IPs (" << single_ips_.size() << "):\n";
            for (const auto& ip : single_ips_) {
                oss << "  - " << ip.to_string() << "\n";
            }
        }
        
        // IPv4 CIDR网段
        if (!cidr_v4_networks_.empty()) {
            oss << "IPv4 CIDR Networks (" << cidr_v4_networks_.size() << "):\n";
            for (const auto& network : cidr_v4_networks_) {
                oss << "  - " << network.network().to_string()
                    << "/" << network.prefix_length() << "\n";
            }
        }
        
        // IPv6 CIDR网段
        if (!cidr_v6_networks_.empty()) {
            oss << "IPv6 CIDR Networks (" << cidr_v6_networks_.size() << "):\n";
            for (const auto& network : cidr_v6_networks_) {
                oss << "  - " << network.network().to_string()
                    << "/" << network.prefix_length() << "\n";
            }
        }
        
        // IP范围
        if (!ip_ranges_.empty()) {
            oss << "IP Ranges (" << ip_ranges_.size() << "):\n";
            for (const auto& range : ip_ranges_) {
                oss << "  - " << range.first.to_string()
                    << " - " << range.second.to_string() << "\n";
            }
        }
        
        // 正则表达式模式
        if (!regex_patterns_.empty()) {
            oss << "Regex Patterns (" << regex_patterns_.size() << "):\n";
            for (size_t i = 0; i < regex_patterns_.size(); ++i) {
                oss << "  - Pattern " << (i + 1) << ": (regex pattern)\n";
            }
        }
        
        if (empty()) {
            oss << "Whitelist is empty.\n";
        }
        
        return oss.str();
    }
    
    /**
     * @brief 获取单个IP地址列表
     * @return 包含所有单个IP地址的字符串向量
     */
    std::vector<std::string> get_single_ips() const {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        std::vector<std::string> result;
        result.reserve(single_ips_.size());
        
        for (const auto& ip : single_ips_) {
            result.push_back(ip.to_string());
        }
        
        return result;
    }
    
    /**
     * @brief 获取CIDR网段列表
     * @return 包含所有CIDR网段的字符串向量
     */
    std::vector<std::string> get_cidr_networks() const {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        std::vector<std::string> result;
        result.reserve(cidr_v4_networks_.size() + cidr_v6_networks_.size());
        
        for (const auto& network : cidr_v4_networks_) {
            result.push_back(network.network().to_string() + "/" +
                           std::to_string(network.prefix_length()));
        }
        
        for (const auto& network : cidr_v6_networks_) {
            result.push_back(network.network().to_string() + "/" +
                           std::to_string(network.prefix_length()));
        }
        
        return result;
    }
    
    /**
     * @brief 获取IP范围列表
     * @return 包含所有IP范围的字符串向量，格式为"start_ip - end_ip"
     */
    std::vector<std::string> get_ip_ranges() const {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        std::vector<std::string> result;
        result.reserve(ip_ranges_.size());
        
        for (const auto& range : ip_ranges_) {
            result.push_back(range.first.to_string() + " - " + range.second.to_string());
        }
        
        return result;
    }
    
    /**
     * @brief 获取正则表达式模式数量
     * @return 正则表达式模式的数量
     */
    size_t get_regex_pattern_count() const {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        return regex_patterns_.size();
    }

private:
    /**
     * @brief 检查IP是否在指定范围内
     * @param ip 要检查的IP地址
     * @param start 范围起始IP
     * @param end 范围结束IP
     * @return 在范围内返回true
     */
    bool is_ip_in_range(const asio::ip::address& ip, 
                       const asio::ip::address& start, 
                       const asio::ip::address& end) const {
        if (ip.is_v4() && start.is_v4() && end.is_v4()) {
            auto ip_v4 = ip.to_v4().to_uint();
            auto start_v4 = start.to_v4().to_uint();
            auto end_v4 = end.to_v4().to_uint();
            return ip_v4 >= start_v4 && ip_v4 <= end_v4;
        } else if (ip.is_v6() && start.is_v6() && end.is_v6()) {
            auto ip_bytes = ip.to_v6().to_bytes();
            auto start_bytes = start.to_v6().to_bytes();
            auto end_bytes = end.to_v6().to_bytes();
            return std::memcmp(ip_bytes.data(), start_bytes.data(), 16) >= 0 &&
                   std::memcmp(ip_bytes.data(), end_bytes.data(), 16) <= 0;
        }
        return false;
    }

    mutable std::shared_mutex mutex_;
    std::unordered_set<asio::ip::address> single_ips_;
    std::vector<asio::ip::network_v4> cidr_v4_networks_;
    std::vector<asio::ip::network_v6> cidr_v6_networks_;
    std::vector<std::pair<asio::ip::address, asio::ip::address>> ip_ranges_;
    std::vector<std::regex> regex_patterns_;
};


} // namespace coro_io