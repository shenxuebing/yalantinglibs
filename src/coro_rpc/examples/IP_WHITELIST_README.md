# YLT RPC Server IP 白名单功能

## 概述

本功能为阿里巴巴 yalantinglibs 库的 coro_rpc 模块添加了IP白名单支持，允许用户在socket连接时进行IP地址过滤，实现网络访问控制。

## 功能特性

- **单个IP地址过滤**: 支持IPv4和IPv6地址
- **CIDR网段过滤**: 支持网络段过滤，如 `192.168.1.0/24`
- **IP地址范围过滤**: 支持IP地址范围，如 `192.168.1.10-192.168.1.20`
- **正则表达式过滤**: 支持复杂的IP地址模式匹配
- **动态管理**: 支持运行时添加/删除IP白名单条目
- **高性能**: 使用读写锁实现线程安全，读操作可并发
- **批量操作**: 支持批量添加IP地址和网段

## 文件结构

```
include/ylt/coro_io/ip_whitelist.hpp           # IP白名单核心实现
include/ylt/coro_rpc/impl/coro_rpc_server.hpp  # RPC服务器集成修改
src/coro_rpc/tests/test_ip_whitelist.cpp       # 单元测试
src/coro_rpc/examples/ip_whitelist_example.cpp # 使用示例
```

## 基本使用方法

### 1. 创建服务器并配置IP白名单

```cpp
#include "ylt/coro_rpc/coro_rpc_server.hpp"
#include "ylt/coro_io/ip_whitelist.hpp"

// 创建RPC服务器
coro_rpc_server server{1, 9001};

// 获取IP白名单引用
auto& whitelist = server.get_ip_whitelist();

// 添加允许的IP地址
whitelist.add_ip("127.0.0.1");       // 本地回环
whitelist.add_ip("192.168.1.100");   // 特定IP
whitelist.add_ip("::1");              // IPv6本地回环

// 添加网段
whitelist.add_cidr("192.168.1.0/24");  // 整个子网
whitelist.add_cidr("10.0.0.0/8");      // 大型私有网络

// 添加IP范围
whitelist.add_ip_range("172.16.0.1", "172.16.0.100");

// 启用IP白名单
server.enable_ip_whitelist(true);

// 启动服务器
server.start();
```

### 2. 独立使用IP白名单

```cpp
#include "ylt/coro_io/ip_whitelist.hpp"

using namespace coro_io;

// 创建IP白名单实例
ip_whitelist whitelist;

// 添加IP地址
whitelist.add_ip("192.168.1.100");
whitelist.add_cidr("10.0.0.0/8");
whitelist.add_ip_range("172.16.0.1", "172.16.0.100");

// 检查IP是否被允许
bool allowed = whitelist.is_allowed("192.168.1.100");  // true
bool blocked = whitelist.is_allowed("8.8.8.8");        // false

// 批量添加
std::vector<std::string> ips = {"127.0.0.1", "192.168.1.1", "10.0.0.1"};
whitelist.add_ips(ips);

// 获取白名单大小
size_t size = whitelist.size();

// 清空白名单
whitelist.clear();
```

### 3. 使用全局白名单

```cpp
#include "ylt/coro_io/ip_whitelist.hpp"

// 获取全局白名单实例
auto& global_whitelist = coro_io::global_ip_whitelist();

// 配置全局白名单
global_whitelist.add_ip("127.0.0.1");
global_whitelist.add_cidr("192.168.0.0/16");

// 检查IP
bool allowed = global_whitelist.is_allowed("192.168.1.100");
```

## 高级用法

### 1. 正则表达式过滤

```cpp
ip_whitelist whitelist;

// 添加正则表达式模式
whitelist.add_regex_pattern(R"(192\.168\.1\.\d+)");        // 192.168.1.x
whitelist.add_regex_pattern(R"(10\.0\.0\.[1-9]\d?)");      // 10.0.0.1-99
whitelist.add_regex_pattern(R"(172\.1[6-9]\.\d+\.\d+)");   // 172.16-19.x.x

// 测试匹配
bool match1 = whitelist.is_allowed("192.168.1.50");   // true
bool match2 = whitelist.is_allowed("10.0.0.25");      // true
bool match3 = whitelist.is_allowed("172.17.1.100");   // true
bool match4 = whitelist.is_allowed("192.168.2.1");    // false
```

### 2. 动态管理

```cpp
coro_rpc_server server{1, 9001};
auto& whitelist = server.get_ip_whitelist();

// 运行时添加IP
whitelist.add_ip("192.168.1.200");

// 运行时移除IP
whitelist.remove_ip("192.168.1.100");

// 临时禁用白名单
server.enable_ip_whitelist(false);  // 允许所有连接

// 重新启用白名单
server.enable_ip_whitelist(true);   // 恢复白名单检查

// 检查白名单状态
bool enabled = server.is_ip_whitelist_enabled();
```

### 3. 批量操作

```cpp
ip_whitelist whitelist;

// 批量添加IP
std::vector<std::string> ips = {
    "127.0.0.1",
    "192.168.1.100",
    "10.0.0.1",
    "invalid_ip"  // 会被跳过
};
size_t added = whitelist.add_ips(ips);  // 返回3（成功添加的数量）

// 批量添加CIDR
std::vector<std::string> cidrs = {
    "192.168.0.0/16",
    "10.0.0.0/8",
    "172.16.0.0/12"
};
size_t added_cidrs = whitelist.add_cidrs(cidrs);  // 返回3
```

## 性能优化

### 1. 线程安全

IP白名单使用读写锁（`std::shared_mutex`）实现线程安全：
- 读操作（`is_allowed`）可以并发执行
- 写操作（`add_ip`, `remove_ip`等）需要独占锁
- 适合读多写少的场景

### 2. 查找效率

- 单个IP查找：O(1) 哈希表查找
- CIDR匹配：O(n) 遍历网段列表
- IP范围匹配：O(n) 遍历范围列表
- 正则匹配：O(n*m) 遍历模式列表并匹配

### 3. 内存使用

- 单个IP：每个IP约32字节（IPv4）或128字节（IPv6）
- CIDR网段：每个网段约40字节
- IP范围：每个范围约64字节
- 正则表达式：根据模式复杂度变化

## 安全考虑

### 1. 默认拒绝策略

```cpp
// 白名单为空时，所有连接都会被拒绝
ip_whitelist whitelist;  // 空白名单
server.enable_ip_whitelist(true);  // 启用后拒绝所有连接

// 确保至少添加必要的IP
whitelist.add_ip("127.0.0.1");  // 允许本地访问
```

### 2. 避免过于宽松的规则

```cpp
// 不推荐：过于宽松的CIDR
whitelist.add_cidr("0.0.0.0/0");  // 允许所有IPv4地址

// 推荐：具体的网段
whitelist.add_cidr("192.168.1.0/24");  // 只允许特定子网
```

### 3. 正则表达式验证

```cpp
// 确保正则表达式正确
try {
    whitelist.add_regex_pattern(R"(192\.168\.1\.\d+)");
} catch (const std::exception& e) {
    std::cerr << "Invalid regex pattern: " << e.what() << std::endl;
}
```

## 错误处理

```cpp
ip_whitelist whitelist;

// 检查添加结果
if (!whitelist.add_ip("invalid_ip")) {
    std::cerr << "Failed to add invalid IP address" << std::endl;
}

if (!whitelist.add_cidr("192.168.1.0/33")) {  // 无效的前缀长度
    std::cerr << "Failed to add invalid CIDR" << std::endl;
}

// 异常处理
try {
    bool allowed = whitelist.is_allowed("some_ip");
} catch (const std::exception& e) {
    std::cerr << "Error checking IP: " << e.what() << std::endl;
}
```

## 测试和调试

### 1. 运行测试

```bash
# 编译并运行测试
cd build
make test_ip_whitelist
./test_ip_whitelist
```

### 2. 运行示例

```bash
# 编译并运行示例
cd build
make ip_whitelist_example
./ip_whitelist_example
```

### 3. 日志调试

IP白名单功能会输出详细的日志信息：

```cpp
// 查看日志输出
ELOG_INFO << "Added IP to whitelist: " << ip;
ELOG_WARN << "Connection from " << ip << " rejected by IP whitelist";
ELOG_ERROR << "Error checking IP whitelist: " << e.what();
```

## API 参考

### ip_whitelist 类

#### 构造函数
- `ip_whitelist()` - 创建空白名单
- `ip_whitelist(const std::vector<std::string>& ips)` - 使用IP列表初始化

#### 添加方法
- `bool add_ip(const std::string& ip_str)` - 添加单个IP
- `bool add_cidr(const std::string& cidr_str)` - 添加CIDR网段
- `bool add_ip_range(const std::string& start_ip, const std::string& end_ip)` - 添加IP范围
- `bool add_regex_pattern(const std::string& pattern)` - 添加正则模式
- `size_t add_ips(const std::vector<std::string>& ips)` - 批量添加IP
- `size_t add_cidrs(const std::vector<std::string>& cidrs)` - 批量添加CIDR

#### 查询方法
- `bool is_allowed(const asio::ip::address& ip_addr)` - 检查IP地址对象
- `bool is_allowed(const std::string& ip_str)` - 检查IP地址字符串
- `size_t size()` - 获取白名单大小
- `bool empty()` - 检查是否为空

#### 管理方法
- `bool remove_ip(const std::string& ip_str)` - 移除IP地址
- `void clear()` - 清空白名单

### coro_rpc_server 扩展方法

- `coro_io::ip_whitelist& get_ip_whitelist()` - 获取IP白名单引用
- `void enable_ip_whitelist(bool enable = true)` - 启用/禁用IP白名单
- `bool is_ip_whitelist_enabled()` - 检查IP白名单是否启用

## 常见问题

### Q: 如何允许所有本地连接？
```cpp
whitelist.add_ip("127.0.0.1");    // IPv4本地回环
whitelist.add_ip("::1");           // IPv6本地回环
whitelist.add_cidr("127.0.0.0/8"); // 整个127.x.x.x段
```

### Q: 如何允许私有网络？
```cpp
whitelist.add_cidr("10.0.0.0/8");      // Class A私有网络
whitelist.add_cidr("172.16.0.0/12");   // Class B私有网络
whitelist.add_cidr("192.168.0.0/16");  // Class C私有网络
```

### Q: 性能影响如何？
IP白名单检查在接受连接后立即进行，对已建立连接的性能影响很小。检查耗时主要取决于白名单规则数量和复杂度。

### Q: 是否支持域名？
目前不支持域名，只支持IP地址。如需域名支持，需要在应用层进行DNS解析。

## 贡献

欢迎提交Issue和Pull Request来改进此功能。

## 许可证

此功能遵循Apache License 2.0许可证。