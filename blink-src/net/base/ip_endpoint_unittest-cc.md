Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Understand the Goal:** The primary goal is to analyze the provided C++ source code (`ip_endpoint_unittest.cc`) and explain its purpose, its relationship to JavaScript (if any), its logic through examples, potential user/programmer errors, and how a user might trigger this code.

2. **Identify the Core Functionality:** The filename `ip_endpoint_unittest.cc` immediately suggests this file contains unit tests. The `#include "net/base/ip_endpoint.h"` line confirms that the tests are for the `IPEndPoint` class. This class likely represents an IP address and a port number, a fundamental concept in networking.

3. **Scan for Key Concepts and Patterns:** Look for repeating elements and core functionalities being tested. Keywords like `TEST_F`, `EXPECT_EQ`, `EXPECT_TRUE`, `EXPECT_FALSE`, `DCHECK_DEATH` are indicative of unit testing using Google Test. The code iterates through a `tests` array, which holds sample IP addresses and their normalized forms. This suggests the tests cover various valid IP address formats.

4. **Analyze Individual Tests:** Go through each `TEST_F` function and understand what it's testing:
    * `Constructor`: Tests basic instantiation of `IPEndPoint`.
    * `Assignment`: Tests the assignment operator.
    * `Copy`: Tests the copy constructor.
    * `ToFromSockAddr`: Tests converting between `IPEndPoint` and the low-level `sockaddr` structure. This is crucial for interacting with the operating system's networking APIs.
    * `ToSockAddrBufTooSmall`, `FromSockAddrBufTooSmall`: Test error handling for insufficient buffer sizes when converting to/from `sockaddr`.
    * **Windows Bluetooth Specific Tests:** The `#if BUILDFLAG(IS_WIN)` block introduces Bluetooth-specific tests, indicated by `SOCKADDR_BTH`. These tests focus on comparisons and handling of Bluetooth addresses within `IPEndPoint`. They also highlight scenarios where methods designed for IPv4/IPv6 may not be applicable to Bluetooth addresses (using `EXPECT_DCHECK_DEATH`).
    * `Equality`, `LessThan`: Test the overloaded equality and less-than operators for `IPEndPoint` objects. This is important for using `IPEndPoint` in containers and for sorting.
    * `ToString`: Tests the string representation of an `IPEndPoint`.
    * `RoundtripThroughValue`, `FromGarbageValue`, `FromMalformedValues`: Tests serialization and deserialization of `IPEndPoint` using `base::Value`, often used for configuration or inter-process communication. These tests specifically check for robustness against invalid or malformed input.

5. **Identify Connections to JavaScript (if any):** Think about where IP addresses and ports are relevant in a web browser context, which is where Chromium is used. JavaScript running in a browser interacts with networks. Key areas include:
    * **`fetch()` API:** JavaScript uses `fetch()` to make network requests. The URL provided to `fetch()` contains the hostname and port.
    * **WebSockets:** WebSockets establish persistent connections, requiring an IP address and port.
    * **WebRTC:**  Peer-to-peer communication in WebRTC relies on IP addresses and ports for signaling and data transfer.
    * **Network APIs:**  While direct manipulation of `IPEndPoint` isn't done in JavaScript, the *concepts* are exposed through browser APIs.

6. **Illustrate with Examples (Hypothetical Inputs and Outputs):**  For core functionalities like `ToSockAddr` and `FromSockAddr`, provide concrete examples of how the data structures would be populated. For comparisons, show how different IP addresses and ports lead to different comparison results.

7. **Consider User/Programmer Errors:** Think about common mistakes when dealing with networking:
    * **Incorrect port numbers:**  Trying to connect to a port where no service is listening.
    * **Incorrect IP addresses:** Typos, using private IP addresses incorrectly.
    * **Buffer overflows:**  The `ToSockAddrBufTooSmall` and `FromSockAddrBufTooSmall` tests directly address this.
    * **Platform-specific issues:** The Bluetooth tests highlight the need to handle different address families correctly.

8. **Trace User Actions (Debugging Context):** Imagine how a user's actions could lead to this code being executed. Focus on network-related actions in a browser:
    * Typing a URL in the address bar.
    * Clicking a link.
    * Using a web application that utilizes WebSockets or WebRTC.
    * Browser extensions making network requests.

9. **Structure the Explanation:**  Organize the findings into logical sections as requested: functionality, relationship to JavaScript, logical reasoning (with examples), common errors, and debugging context. Use clear and concise language.

10. **Refine and Review:**  Read through the explanation to ensure accuracy, clarity, and completeness. Check for any missed points or areas that could be explained better. For instance, initially, the focus might be solely on the C++ code. The review process helps to connect it more explicitly to the user's interaction with a web browser and the underlying network stack.

This systematic approach allows for a thorough understanding of the code and its context within a larger system like Chromium.
这个文件 `net/base/ip_endpoint_unittest.cc` 是 Chromium 网络栈的一部分，它的主要功能是**测试 `net::IPEndPoint` 类的功能**。 `IPEndPoint` 类用于表示一个 IP 地址（IPv4 或 IPv6）和一个端口号的组合，这是网络编程中一个非常基础且重要的概念。

下面详细列举一下它的功能，并根据你的要求进行说明：

**1. 功能列表:**

* **构造函数测试:** 测试 `IPEndPoint` 类的各种构造函数，例如默认构造函数、使用 `IPAddress` 和端口号的构造函数。
* **赋值和拷贝测试:** 测试 `IPEndPoint` 对象的赋值运算符和拷贝构造函数，确保对象能够正确地复制和赋值。
* **与 `sockaddr` 结构体的相互转换测试:** `sockaddr` 结构体是操作系统网络 API 中用于表示网络地址的标准结构。这部分测试验证了 `IPEndPoint` 对象能够正确地转换为 `sockaddr` 结构体，以及从 `sockaddr` 结构体正确地创建 `IPEndPoint` 对象。这对于与底层网络 API 交互至关重要。
* **转换到 `sockaddr` 时的缓冲区大小检查:** 测试了在将 `IPEndPoint` 转换为 `sockaddr` 结构体时，提供的缓冲区大小不足的情况，确保代码能够正确处理这种情况并返回错误。
* **从 `sockaddr` 创建时的缓冲区大小检查:** 测试了在从 `sockaddr` 结构体创建 `IPEndPoint` 对象时，提供的缓冲区大小不足的情况，确保代码能够正确处理这种情况并返回错误。
* **Windows 平台下的 Bluetooth 地址支持测试:** 在 Windows 平台下，`IPEndPoint` 可以表示 Bluetooth 地址。这部分测试专门针对 Bluetooth 地址的创建、比较等操作进行了测试。
* **相等性测试:** 测试了 `IPEndPoint` 对象的相等性比较运算符 (`==`)，确保两个 `IPEndPoint` 对象在 IP 地址和端口号都相同时被认为是相等的。
* **小于比较测试:** 测试了 `IPEndPoint` 对象的小于比较运算符 (`<`)，定义了 `IPEndPoint` 对象之间的大小关系，通常是先比较 IP 地址，再比较端口号。
* **转换为字符串测试:** 测试了将 `IPEndPoint` 对象转换为字符串表示的功能 (`ToString`)，例如 "127.0.0.1:80" 或 "[::1]:80"。
* **通过 `base::Value` 的序列化和反序列化测试:** `base::Value` 是 Chromium 中用于表示通用值的类。这部分测试验证了 `IPEndPoint` 对象可以被序列化为 `base::Value` 对象，并且可以从 `base::Value` 对象反序列化回 `IPEndPoint` 对象。这对于配置管理或进程间通信很有用。
* **从错误的 `base::Value` 反序列化测试:** 测试了当提供的 `base::Value` 对象格式不正确时，`IPEndPoint::FromValue` 方法的健壮性，确保它能够正确处理错误情况。

**2. 与 JavaScript 功能的关系及举例:**

虽然这个 C++ 文件本身不包含 JavaScript 代码，但 `IPEndPoint` 类所代表的概念在 JavaScript 中有重要的体现，尤其是在浏览器环境中：

* **`fetch()` API:** 当 JavaScript 使用 `fetch()` API 发起网络请求时，需要指定请求的目标 URL。URL 中包含了主机名（最终会被解析为 IP 地址）和端口号。浏览器内部的网络栈（包括这里的 C++ 代码）会处理这个 URL，并使用 `IPEndPoint` 或类似的数据结构来表示请求的目标地址。

   **举例:**
   ```javascript
   fetch('http://www.example.com:8080/data.json')
       .then(response => response.json())
       .then(data => console.log(data));
   ```
   在这个例子中，JavaScript 代码指定了目标主机 `www.example.com` 和端口 `8080`。浏览器内部会将 `www.example.com` 解析为 IP 地址，然后与端口 `8080` 组合成一个 `IPEndPoint` 对象（或类似概念的内部表示），用于建立连接和发送请求。

* **WebSockets:**  WebSockets 建立持久的双向通信连接，也需要指定服务器的 IP 地址和端口。

   **举例:**
   ```javascript
   const websocket = new WebSocket('ws://192.168.1.100:8000');

   websocket.onopen = function(event) {
     console.log("WebSocket connection opened");
     websocket.send("Hello from client!");
   };
   ```
   在这个例子中，JavaScript 代码创建了一个连接到 IP 地址 `192.168.1.100` 和端口 `8000` 的 WebSocket 连接。浏览器内部会使用 `IPEndPoint` 的概念来表示这个连接的服务器端点。

* **WebRTC:** WebRTC 用于浏览器之间的实时通信，涉及 ICE (Interactive Connectivity Establishment) 协议，该协议会交换候选项 (candidates)，其中包含了 IP 地址和端口信息。

   **举例 (简化):**
   当 WebRTC 连接建立时，浏览器会收集本地的网络接口信息，包括 IP 地址和端口号，并将这些信息作为 ICE 候选项发送给对方。 这些候选项在内部也会以 `IPEndPoint` 的形式或类似的形式表示。

**3. 逻辑推理 (假设输入与输出):**

假设我们运行 `ToFromSockAddr` 测试中的一个用例：

**假设输入:**

* `test.ip_address`:  `IPAddress` 对象，其值为 IPv4 地址 "192.168.1.1"。
* `port`: 80 (uint16_t)。
* `ip_endpoint`:  一个使用 `test.ip_address` 和 `port` 构造的 `IPEndPoint` 对象。
* `storage`: 一个 `SockaddrStorage` 对象，用于存储转换后的 `sockaddr`。

**步骤:**

1. `ip_endpoint.ToSockAddr(storage.addr, &storage.addr_len)` 被调用。
2. 由于 `ip_endpoint` 的 IP 地址是 IPv4，代码会填充 `storage.addr` 指向的 `sockaddr_in` 结构体。
3. `storage.addr.sin_family` 将被设置为 `AF_INET`.
4. `storage.addr.sin_addr` 将被设置为 `192.168.1.1` 的网络字节序表示。
5. `storage.addr.sin_port` 将被设置为 80 的网络字节序表示。
6. `storage.addr_len` 将被设置为 `sizeof(sockaddr_in)`.

**预期输出:**

* `ip_endpoint.ToSockAddr` 返回 `true`。
* `storage.addr` 中的内容：
    * `sa_family`: `AF_INET` (通常是 2)
    * `sin_port`:  网络字节序的 80 (例如，对于小端系统可能是 `0x5000`)
    * `sin_addr`:  网络字节序的 `192.168.1.1` (例如，对于小端系统可能是 `0x0101A8C0`)
* `storage.addr_len`: `16` (在 Linux 等系统上，`sizeof(sockaddr_in)` 为 16)。

然后，`ip_endpoint2.FromSockAddr(storage.addr, storage.addr_len)` 被调用，预期会从 `storage.addr` 中正确解析出 IP 地址 "192.168.1.1" 和端口号 80，并赋值给 `ip_endpoint2`。

**4. 涉及用户或编程常见的使用错误及举例:**

* **端口号超出范围:** 用户或程序员可能尝试使用超出 0-65535 范围的端口号。 `IPEndPoint` 的构造函数或设置端口的方法应该能够处理这种情况（虽然测试中没有明确展示错误处理，但实际代码应该有）。

   **举例:**
   ```c++
   IPEndPoint endpoint(IPAddress::IPv4Localhost(), 70000); // 70000 超出范围
   ```
   如果代码没有进行校验，可能会导致未定义的行为或者在转换为 `sockaddr` 时发生错误。

* **IP 地址格式错误:** 用户或程序员可能提供格式不正确的 IP 地址字符串。

   **举例:**
   ```c++
   std::string invalid_ip = "192.168.1.256"; // 256 超出 IPv4 地址范围
   IPAddress address;
   address.AssignFromIPLiteral(invalid_ip); // 应该返回 false
   IPEndPoint endpoint(address, 80); // 使用无效的 IPAddress
   ```
   虽然 `IPAddress` 类会处理 IP 地址的解析，但如果 `IPEndPoint` 接收到一个无效的 `IPAddress` 对象，其行为可能会变得不可预测。测试中的 `ToString` 方法针对无效地址的情况做了处理，返回空字符串。

* **`ToSockAddr` 缓冲区过小:** 程序员可能在调用 `ToSockAddr` 时提供的缓冲区大小不足以容纳 `sockaddr` 结构体。这个错误在 `ToSockAddrBufTooSmall` 测试中被覆盖。

   **举例:**
   ```c++
   IPEndPoint endpoint(IPAddress::IPv4Localhost(), 80);
   char buffer[8]; // 缓冲区太小
   socklen_t buffer_len = sizeof(buffer);
   bool success = endpoint.ToSockAddr(reinterpret_cast<sockaddr*>(buffer), &buffer_len);
   EXPECT_FALSE(success); // 预期返回 false
   ```

* **`FromSockAddr` 缓冲区过小:** 程序员可能在调用 `FromSockAddr` 时提供的缓冲区大小不足以表示 `sockaddr` 结构体。这个错误在 `FromSockAddrBufTooSmall` 测试中被覆盖。

   **举例:**
   ```c++
   sockaddr_in addr;
   memset(&addr, 0, sizeof(addr));
   addr.sin_family = AF_INET;
   IPEndPoint endpoint;
   bool success = endpoint.FromSockAddr(reinterpret_cast<sockaddr*>(&addr), sizeof(addr) - 1);
   EXPECT_FALSE(success); // 预期返回 false
   ```

**5. 说明用户操作是如何一步步到达这里，作为调试线索:**

假设用户在浏览器中尝试访问一个网页 `http://example.com:8080`，并且遇到了连接问题，开发者可能需要调试网络栈的这部分代码。以下是用户操作如何一步步触发到 `IPEndPoint` 相关的代码：

1. **用户在地址栏输入 `http://example.com:8080` 并按下回车。**
2. **浏览器解析 URL:** 浏览器会解析输入的 URL，提取出协议 (http)、主机名 (example.com) 和端口号 (8080)。
3. **DNS 解析:** 浏览器会发起 DNS 查询，将主机名 `example.com` 解析为 IP 地址。这个过程涉及到网络栈中的 DNS 解析器。
4. **创建 `IPEndPoint` 对象:**  一旦获取到 IP 地址和端口号，浏览器内部的网络代码会创建一个 `IPEndPoint` 对象（或类似的数据结构）来表示连接的目标端点。这个过程会使用到 `net/base/ip_endpoint.h` 中定义的 `IPEndPoint` 类。
5. **建立 TCP 连接:** 浏览器会尝试与目标服务器建立 TCP 连接。这涉及到调用操作系统的 socket API，例如 `connect()`. 在调用 `connect()` 之前，需要将 `IPEndPoint` 对象转换为 `sockaddr_in` 或 `sockaddr_in6` 结构体，这会触发 `IPEndPoint::ToSockAddr` 方法。
6. **数据传输:** 如果连接建立成功，浏览器会发送 HTTP 请求。在底层的 socket 操作中，数据包的目标地址和端口号会使用 `IPEndPoint` 中存储的信息。

**作为调试线索:**

当用户遇到连接问题时，开发者可能会：

* **检查 DNS 解析是否成功:** 如果 DNS 解析失败，就不会创建有效的 `IPEndPoint` 对象。
* **检查创建的 `IPEndPoint` 对象是否正确:** 调试器可以用来查看 `IPEndPoint` 对象中的 IP 地址和端口号是否与预期一致。
* **单步执行 `ToSockAddr` 方法:** 如果怀疑 `IPEndPoint` 到 `sockaddr` 的转换有问题，可以单步执行 `ToSockAddr` 方法，查看 `sockaddr` 结构体的填充情况。
* **查看 socket API 的调用:** 检查 `connect()` 等 socket API 的参数，确认传递的目标地址信息是否正确。

总之，`net/base/ip_endpoint_unittest.cc` 文件通过各种测试用例，确保了 `net::IPEndPoint` 类的功能正确可靠，这是 Chromium 网络栈正常运行的基础。用户在浏览器中的每一次网络操作，从简单的网页访问到复杂的实时通信，都离不开 `IPEndPoint` 这样的底层网络概念和数据结构。

Prompt: 
```
这是目录为net/base/ip_endpoint_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/base/ip_endpoint.h"

#include <string.h>

#include <optional>
#include <string>
#include <tuple>

#include "base/check_op.h"
#include "base/notreached.h"
#include "base/numerics/safe_conversions.h"
#include "base/strings/string_number_conversions.h"
#include "base/sys_byteorder.h"
#include "base/values.h"
#include "build/build_config.h"
#include "net/base/ip_address.h"
#include "net/base/sockaddr_storage.h"
#include "net/base/sys_addrinfo.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "testing/platform_test.h"

#if BUILDFLAG(IS_WIN)
#include <winsock2.h>

#include <ws2bth.h>

#include "base/test/gtest_util.h"   // For EXPECT_DCHECK_DEATH
#include "net/base/winsock_util.h"  // For kBluetoothAddressSize
#elif BUILDFLAG(IS_POSIX)
#include <netinet/in.h>
#endif

using testing::Optional;

namespace net {

namespace {

// Retuns the port field of the |sockaddr|.
const uint16_t* GetPortFieldFromSockaddr(const struct sockaddr* address,
                                         socklen_t address_len) {
  if (address->sa_family == AF_INET) {
    DCHECK_LE(sizeof(sockaddr_in), static_cast<size_t>(address_len));
    const struct sockaddr_in* sockaddr =
        reinterpret_cast<const struct sockaddr_in*>(address);
    return &sockaddr->sin_port;
  } else if (address->sa_family == AF_INET6) {
    DCHECK_LE(sizeof(sockaddr_in6), static_cast<size_t>(address_len));
    const struct sockaddr_in6* sockaddr =
        reinterpret_cast<const struct sockaddr_in6*>(address);
    return &sockaddr->sin6_port;
  } else {
    NOTREACHED();
  }
}

// Returns the value of port in |sockaddr| (in host byte ordering).
int GetPortFromSockaddr(const struct sockaddr* address, socklen_t address_len) {
  const uint16_t* port_field = GetPortFieldFromSockaddr(address, address_len);
  if (!port_field)
    return -1;
  return base::NetToHost16(*port_field);
}

struct TestData {
  std::string host;
  std::string host_normalized;
  bool ipv6;
  IPAddress ip_address;
} tests[] = {
    {"127.0.00.1", "127.0.0.1", false},
    {"192.168.1.1", "192.168.1.1", false},
    {"::1", "[::1]", true},
    {"2001:db8:0::42", "[2001:db8::42]", true},
};

class IPEndPointTest : public PlatformTest {
 public:
  void SetUp() override {
    // This is where we populate the TestData.
    for (auto& test : tests) {
      EXPECT_TRUE(test.ip_address.AssignFromIPLiteral(test.host));
    }
  }
};

TEST_F(IPEndPointTest, Constructor) {
  {
    IPEndPoint endpoint;
    EXPECT_EQ(0, endpoint.port());
  }

  for (const auto& test : tests) {
    IPEndPoint endpoint(test.ip_address, 80);
    EXPECT_EQ(80, endpoint.port());
    EXPECT_EQ(test.ip_address, endpoint.address());
  }
}

TEST_F(IPEndPointTest, Assignment) {
  uint16_t port = 0;
  for (const auto& test : tests) {
    IPEndPoint src(test.ip_address, ++port);
    IPEndPoint dest = src;

    EXPECT_EQ(src.port(), dest.port());
    EXPECT_EQ(src.address(), dest.address());
  }
}

TEST_F(IPEndPointTest, Copy) {
  uint16_t port = 0;
  for (const auto& test : tests) {
    IPEndPoint src(test.ip_address, ++port);
    IPEndPoint dest(src);

    EXPECT_EQ(src.port(), dest.port());
    EXPECT_EQ(src.address(), dest.address());
  }
}

TEST_F(IPEndPointTest, ToFromSockAddr) {
  uint16_t port = 0;
  for (const auto& test : tests) {
    IPEndPoint ip_endpoint(test.ip_address, ++port);

    // Convert to a sockaddr.
    SockaddrStorage storage;
    EXPECT_TRUE(ip_endpoint.ToSockAddr(storage.addr, &storage.addr_len));

    // Basic verification.
    socklen_t expected_size =
        test.ipv6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
    EXPECT_EQ(expected_size, storage.addr_len);
    EXPECT_EQ(ip_endpoint.port(),
              GetPortFromSockaddr(storage.addr, storage.addr_len));
    // And convert back to an IPEndPoint.
    IPEndPoint ip_endpoint2;
    EXPECT_TRUE(ip_endpoint2.FromSockAddr(storage.addr, storage.addr_len));
    EXPECT_EQ(ip_endpoint.port(), ip_endpoint2.port());
    EXPECT_EQ(ip_endpoint.address(), ip_endpoint2.address());
  }
}

TEST_F(IPEndPointTest, ToSockAddrBufTooSmall) {
  uint16_t port = 0;
  for (const auto& test : tests) {
    IPEndPoint ip_endpoint(test.ip_address, port);

    SockaddrStorage storage;
    storage.addr_len = 3;  // size is too small!
    EXPECT_FALSE(ip_endpoint.ToSockAddr(storage.addr, &storage.addr_len));
  }
}

TEST_F(IPEndPointTest, FromSockAddrBufTooSmall) {
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  IPEndPoint ip_endpoint;
  struct sockaddr* sockaddr = reinterpret_cast<struct sockaddr*>(&addr);
  EXPECT_FALSE(ip_endpoint.FromSockAddr(sockaddr, sizeof(addr) - 1));
}

#if BUILDFLAG(IS_WIN)

namespace {
constexpr uint8_t kBluetoothAddrBytes[kBluetoothAddressSize] = {1, 2, 3,
                                                                4, 5, 6};
constexpr uint8_t kBluetoothAddrBytes2[kBluetoothAddressSize] = {1, 2, 3,
                                                                 4, 5, 7};
const IPAddress kBluetoothAddress(kBluetoothAddrBytes);
const IPAddress kBluetoothAddress2(kBluetoothAddrBytes2);

// Select a Bluetooth port that does not fit in a uint16_t.
constexpr uint32_t kBluetoothPort = std::numeric_limits<uint16_t>::max() + 1;

SOCKADDR_BTH BuildBluetoothSockAddr(const IPAddress& ip_address,
                                    uint32_t port) {
  SOCKADDR_BTH addr = {};
  addr.addressFamily = AF_BTH;
  DCHECK_LE(ip_address.bytes().size(), sizeof(addr.btAddr));
  memcpy(&addr.btAddr, ip_address.bytes().data(), ip_address.bytes().size());
  addr.port = port;
  return addr;
}
}  // namespace

TEST_F(IPEndPointTest, WinBluetoothSockAddrCompareWithSelf) {
  IPEndPoint bt_endpoint;
  SOCKADDR_BTH addr = BuildBluetoothSockAddr(kBluetoothAddress, kBluetoothPort);
  EXPECT_TRUE(bt_endpoint.FromSockAddr(
      reinterpret_cast<const struct sockaddr*>(&addr), sizeof(addr)));
  EXPECT_EQ(bt_endpoint.address(), kBluetoothAddress);
  EXPECT_EQ(bt_endpoint.GetFamily(), AddressFamily::ADDRESS_FAMILY_UNSPECIFIED);
  EXPECT_EQ(bt_endpoint.GetSockAddrFamily(), AF_BTH);
  // Comparison functions should agree that `bt_endpoint` equals itself.
  EXPECT_FALSE(bt_endpoint < bt_endpoint);
  EXPECT_FALSE(bt_endpoint != bt_endpoint);
  EXPECT_TRUE(bt_endpoint == bt_endpoint);
  // Test that IPv4/IPv6-only methods crash.
  EXPECT_DCHECK_DEATH(bt_endpoint.port());
  SockaddrStorage storage;
  EXPECT_DCHECK_DEATH(
      std::ignore = bt_endpoint.ToSockAddr(storage.addr, &storage.addr_len));
  EXPECT_DCHECK_DEATH(bt_endpoint.ToString());
  EXPECT_DCHECK_DEATH(bt_endpoint.ToStringWithoutPort());
}

TEST_F(IPEndPointTest, WinBluetoothSockAddrCompareWithNonBluetooth) {
  IPEndPoint bt_endpoint;
  SOCKADDR_BTH addr = BuildBluetoothSockAddr(kBluetoothAddress, kBluetoothPort);
  EXPECT_TRUE(bt_endpoint.FromSockAddr(
      reinterpret_cast<const struct sockaddr*>(&addr), sizeof(addr)));

  // Compare `bt_endpoint` with non-Bluetooth endpoints.
  for (const auto& test : tests) {
    IPEndPoint endpoint(test.ip_address, 80);
    if (test.ip_address.IsIPv4()) {
      EXPECT_FALSE(bt_endpoint < endpoint);
    } else {
      EXPECT_TRUE(test.ip_address.IsIPv6());
      EXPECT_TRUE(bt_endpoint < endpoint);
    }
    EXPECT_TRUE(bt_endpoint != endpoint);
    EXPECT_FALSE(bt_endpoint == endpoint);
  }
}

TEST_F(IPEndPointTest, WinBluetoothSockAddrCompareWithCopy) {
  IPEndPoint bt_endpoint;
  SOCKADDR_BTH addr = BuildBluetoothSockAddr(kBluetoothAddress, kBluetoothPort);
  EXPECT_TRUE(bt_endpoint.FromSockAddr(
      reinterpret_cast<const struct sockaddr*>(&addr), sizeof(addr)));

  // Verify that a copy's accessors return the same values as the original's.
  IPEndPoint bt_endpoint_other(bt_endpoint);
  EXPECT_EQ(bt_endpoint.address(), bt_endpoint_other.address());
  EXPECT_EQ(bt_endpoint.GetFamily(), bt_endpoint_other.GetFamily());
  EXPECT_EQ(bt_endpoint.GetSockAddrFamily(),
            bt_endpoint_other.GetSockAddrFamily());
  // Comparison functions should agree that the endpoints are equal.
  EXPECT_FALSE(bt_endpoint < bt_endpoint_other);
  EXPECT_FALSE(bt_endpoint != bt_endpoint_other);
  EXPECT_TRUE(bt_endpoint == bt_endpoint_other);
  // Test that IPv4/IPv6-only methods crash.
  EXPECT_DCHECK_DEATH(bt_endpoint_other.port());
  SockaddrStorage storage;
  EXPECT_DCHECK_DEATH(std::ignore = bt_endpoint_other.ToSockAddr(
                          storage.addr, &storage.addr_len));
  EXPECT_DCHECK_DEATH(bt_endpoint_other.ToString());
  EXPECT_DCHECK_DEATH(bt_endpoint_other.ToStringWithoutPort());
}

TEST_F(IPEndPointTest, WinBluetoothSockAddrCompareWithDifferentPort) {
  IPEndPoint bt_endpoint;
  SOCKADDR_BTH addr = BuildBluetoothSockAddr(kBluetoothAddress, kBluetoothPort);
  EXPECT_TRUE(bt_endpoint.FromSockAddr(
      reinterpret_cast<const struct sockaddr*>(&addr), sizeof(addr)));

  // Compare with another IPEndPoint that has a different port.
  IPEndPoint bt_endpoint_other;
  SOCKADDR_BTH addr2 =
      BuildBluetoothSockAddr(kBluetoothAddress, kBluetoothPort + 1);
  EXPECT_TRUE(bt_endpoint_other.FromSockAddr(
      reinterpret_cast<const struct sockaddr*>(&addr2), sizeof(addr2)));
  EXPECT_EQ(bt_endpoint.address(), bt_endpoint_other.address());
  EXPECT_EQ(bt_endpoint.GetFamily(), bt_endpoint_other.GetFamily());
  EXPECT_EQ(bt_endpoint.GetSockAddrFamily(),
            bt_endpoint_other.GetSockAddrFamily());
  // Comparison functions should agree that `bt_endpoint == bt_endpoint_other`
  // because they have the same address and Bluetooth ports are not considered
  // by comparison functions.
  EXPECT_FALSE(bt_endpoint < bt_endpoint_other);
  EXPECT_FALSE(bt_endpoint != bt_endpoint_other);
  EXPECT_TRUE(bt_endpoint == bt_endpoint_other);
  // Test that IPv4/IPv6-only methods crash.
  EXPECT_DCHECK_DEATH(bt_endpoint_other.port());
  SockaddrStorage storage;
  EXPECT_DCHECK_DEATH(std::ignore = bt_endpoint_other.ToSockAddr(
                          storage.addr, &storage.addr_len));
  EXPECT_DCHECK_DEATH(bt_endpoint_other.ToString());
  EXPECT_DCHECK_DEATH(bt_endpoint_other.ToStringWithoutPort());
}

TEST_F(IPEndPointTest, WinBluetoothSockAddrCompareWithDifferentAddress) {
  IPEndPoint bt_endpoint;
  SOCKADDR_BTH addr = BuildBluetoothSockAddr(kBluetoothAddress, kBluetoothPort);
  EXPECT_TRUE(bt_endpoint.FromSockAddr(
      reinterpret_cast<const struct sockaddr*>(&addr), sizeof(addr)));

  // Compare with another IPEndPoint that has a different address.
  IPEndPoint bt_endpoint_other;
  SOCKADDR_BTH addr2 =
      BuildBluetoothSockAddr(kBluetoothAddress2, kBluetoothPort);
  EXPECT_TRUE(bt_endpoint_other.FromSockAddr(
      reinterpret_cast<const struct sockaddr*>(&addr2), sizeof(addr2)));
  EXPECT_LT(bt_endpoint.address(), bt_endpoint_other.address());
  EXPECT_EQ(bt_endpoint.GetFamily(), bt_endpoint_other.GetFamily());
  EXPECT_EQ(bt_endpoint.GetSockAddrFamily(),
            bt_endpoint_other.GetSockAddrFamily());
  // Comparison functions should agree that `bt_endpoint < bt_endpoint_other`
  // due to lexicographic comparison of the address bytes.
  EXPECT_TRUE(bt_endpoint < bt_endpoint_other);
  EXPECT_TRUE(bt_endpoint != bt_endpoint_other);
  EXPECT_FALSE(bt_endpoint == bt_endpoint_other);
  // Test that IPv4/IPv6-only methods crash.
  EXPECT_DCHECK_DEATH(bt_endpoint_other.port());
  SockaddrStorage storage;
  EXPECT_DCHECK_DEATH(std::ignore = bt_endpoint_other.ToSockAddr(
                          storage.addr, &storage.addr_len));
  EXPECT_DCHECK_DEATH(bt_endpoint_other.ToString());
  EXPECT_DCHECK_DEATH(bt_endpoint_other.ToStringWithoutPort());
}
#endif

TEST_F(IPEndPointTest, Equality) {
  uint16_t port = 0;
  for (const auto& test : tests) {
    IPEndPoint src(test.ip_address, ++port);
    IPEndPoint dest(src);
    EXPECT_TRUE(src == dest);
  }
}

TEST_F(IPEndPointTest, LessThan) {
  // Vary by port.
  IPEndPoint ip_endpoint1(tests[0].ip_address, 100);
  IPEndPoint ip_endpoint2(tests[0].ip_address, 1000);
  EXPECT_TRUE(ip_endpoint1 < ip_endpoint2);
  EXPECT_FALSE(ip_endpoint2 < ip_endpoint1);

  // IPv4 vs IPv6
  ip_endpoint1 = IPEndPoint(tests[0].ip_address, 81);
  ip_endpoint2 = IPEndPoint(tests[2].ip_address, 80);
  EXPECT_TRUE(ip_endpoint1 < ip_endpoint2);
  EXPECT_FALSE(ip_endpoint2 < ip_endpoint1);

  // IPv4 vs IPv4
  ip_endpoint1 = IPEndPoint(tests[0].ip_address, 81);
  ip_endpoint2 = IPEndPoint(tests[1].ip_address, 80);
  EXPECT_TRUE(ip_endpoint1 < ip_endpoint2);
  EXPECT_FALSE(ip_endpoint2 < ip_endpoint1);

  // IPv6 vs IPv6
  ip_endpoint1 = IPEndPoint(tests[2].ip_address, 81);
  ip_endpoint2 = IPEndPoint(tests[3].ip_address, 80);
  EXPECT_TRUE(ip_endpoint1 < ip_endpoint2);
  EXPECT_FALSE(ip_endpoint2 < ip_endpoint1);

  // Compare equivalent endpoints.
  ip_endpoint1 = IPEndPoint(tests[0].ip_address, 80);
  ip_endpoint2 = IPEndPoint(tests[0].ip_address, 80);
  EXPECT_FALSE(ip_endpoint1 < ip_endpoint2);
  EXPECT_FALSE(ip_endpoint2 < ip_endpoint1);
}

TEST_F(IPEndPointTest, ToString) {
  {
    IPEndPoint endpoint;
    EXPECT_EQ(0, endpoint.port());
  }

  uint16_t port = 100;
  for (const auto& test : tests) {
    ++port;
    IPEndPoint endpoint(test.ip_address, port);
    const std::string result = endpoint.ToString();
    EXPECT_EQ(test.host_normalized + ":" + base::NumberToString(port), result);
  }

  // ToString() shouldn't crash on invalid addresses.
  IPAddress invalid_address;
  IPEndPoint invalid_endpoint(invalid_address, 8080);
  EXPECT_EQ("", invalid_endpoint.ToString());
  EXPECT_EQ("", invalid_endpoint.ToStringWithoutPort());
}

TEST_F(IPEndPointTest, RoundtripThroughValue) {
  for (const auto& test : tests) {
    IPEndPoint endpoint(test.ip_address, 1645);
    base::Value value = endpoint.ToValue();

    EXPECT_THAT(IPEndPoint::FromValue(value), Optional(endpoint));
  }
}

TEST_F(IPEndPointTest, FromGarbageValue) {
  base::Value value(123);
  EXPECT_FALSE(IPEndPoint::FromValue(value).has_value());
}

TEST_F(IPEndPointTest, FromMalformedValues) {
  for (const auto& test : tests) {
    base::Value valid_value = IPEndPoint(test.ip_address, 1111).ToValue();
    ASSERT_TRUE(IPEndPoint::FromValue(valid_value).has_value());

    base::Value missing_address = valid_value.Clone();
    ASSERT_TRUE(missing_address.GetDict().Remove("address"));
    EXPECT_FALSE(IPEndPoint::FromValue(missing_address).has_value());

    base::Value missing_port = valid_value.Clone();
    ASSERT_TRUE(missing_port.GetDict().Remove("port"));
    EXPECT_FALSE(IPEndPoint::FromValue(missing_port).has_value());

    base::Value invalid_address = valid_value.Clone();
    *invalid_address.GetDict().Find("address") = base::Value("1.2.3.4.5");
    EXPECT_FALSE(IPEndPoint::FromValue(invalid_address).has_value());

    base::Value negative_port = valid_value.Clone();
    *negative_port.GetDict().Find("port") = base::Value(-1);
    EXPECT_FALSE(IPEndPoint::FromValue(negative_port).has_value());

    base::Value large_port = valid_value.Clone();
    *large_port.GetDict().Find("port") = base::Value(66000);
    EXPECT_FALSE(IPEndPoint::FromValue(large_port).has_value());
  }
}

}  // namespace

}  // namespace net

"""

```