Response:
My thought process to address the prompt about `net/base/ip_address_unittest.cc` involves several steps:

1. **Understand the Core Purpose:** The file name itself, `ip_address_unittest.cc`, is a strong indicator. It's a unit test file for code related to IP addresses. This immediately tells me its primary function is *testing*.

2. **Identify Key Concepts:** I scan the code for important terms and patterns:
    * `#include "net/base/ip_address.h"`: This is the header file being tested. The core functionality revolves around the `IPAddress` class.
    * `TEST(...)`:  These are the GTest macros defining individual test cases.
    * `EXPECT_EQ`, `EXPECT_TRUE`, `EXPECT_FALSE`, `ASSERT_EQ`: These are GTest assertions used to verify expected behavior.
    * `IPAddressBytes`, `IPAddress`: The main classes/structures being tested.
    * `IPv4`, `IPv6`: Indications of the IP address versions being handled.
    * `ToString()`, `AssignFromIPLiteral()`, `IsPubliclyRoutable()`, `IsZero()`, `IsIPv4MappedIPv6()`, etc.: These are methods of the `IPAddress` class, and the tests verify their functionality.
    * Reserved IP ranges, link-local addresses, unique local addresses: These are specific IP address concepts that the tests cover.
    * CIDR notation, IPv4-mapped IPv6, IPv4-embedded IPv6: More advanced IP address related concepts being tested.

3. **Group Tests by Functionality:** I categorize the tests based on what aspect of `IPAddress` they are verifying. This leads to groupings like:
    * Construction and basic properties (`ConstructEmpty`, `ConstructIPv4`, `ConstructIPv6`, `Assign`, `IsIPVersion`, `IsValid`, `IsZero`)
    * String conversion (`ToString`, `IPAddressToStringWithPort`, `IPAddressToPackedString`)
    * Parsing from string literals (`AssignFromIPLiteral`, `ParseURLHostnameToAddress`, `ParseCIDRBlock`)
    * Comparison (`IsEqual`, `LessThan`)
    * IP address type checks (`IsIPv4Mapped`)
    * Reserved address checks (`IsPubliclyRoutableIPv4`, `IsPubliclyRoutableIPv6`)
    * Address manipulation and conversion (`ConvertIPv4ToIPv4MappedIPv6`, `ConvertIPv4MappedIPv6ToIPv4`, `ConvertIPv4ToIPv4EmbeddedIPv6`, `ExtractPref64FromIpv4onlyArpaAAAA`)
    * Prefix matching (`IPAddressMatchesPrefix`, `IPAddressStartsWith`)
    * Special address types (`IsLinkLocal`, `IsUniqueLocalIPv6`)

4. **Analyze for JavaScript Relevance:** I consider how IP addresses are used in web contexts and how JavaScript might interact with them. The most obvious connection is through network requests (fetching resources, WebSocket connections, etc.). JavaScript uses URLs, which contain hostnames that resolve to IP addresses. Therefore, the parsing functions (`AssignFromIPLiteral`, `ParseURLHostnameToAddress`, `ParseCIDRBlock`) are relevant.

5. **Create Hypothetical Scenarios and Examples:** Based on the identified functionalities and JavaScript relevance, I construct examples to illustrate how these functions might be used and what the expected inputs and outputs would be. This involves thinking about:
    * Valid and invalid IP address strings.
    * Different IP address formats (IPv4, IPv6, with and without brackets).
    * CIDR notation.
    * How JavaScript might pass these strings (e.g., from `window.location.hostname`, user input).

6. **Consider Potential Errors:**  I think about common mistakes developers or users might make when dealing with IP addresses. This leads to examples of:
    * Invalid IP address formats.
    * Incorrect CIDR notation.
    * Mixing up IPv4 and IPv6.
    * Assuming a string is a valid IP address without validation.

7. **Trace User Actions (Debugging Context):**  I consider how a user action in a browser could lead to the execution of this IP address handling code. This usually involves:
    * Typing a URL in the address bar.
    * Clicking a link.
    * JavaScript making a network request.
    * Browser settings (proxy, DNS).

8. **Synthesize and Summarize:** Finally, I organize the findings into a clear and concise summary that addresses all parts of the prompt:
    * Main functions of the file.
    * Relationship to JavaScript with concrete examples.
    * Logical reasoning with input/output examples.
    * Common usage errors.
    * Debugging context and user actions.
    * Overall summary of the file's purpose.

This structured approach ensures that I cover all aspects of the prompt, provide relevant details, and connect the C++ unit test code to higher-level concepts and user interactions within a web browser. It involves understanding the code's purpose, identifying key elements, making connections to other technologies, and illustrating with practical examples.
这是对 Chromium 网络栈中 `net/base/ip_address_unittest.cc` 文件（第一部分）的功能进行分析和归纳。

**文件功能归纳:**

这个 `ip_address_unittest.cc` 文件的主要功能是 **对 `net/base/ip_address.h` 中定义的 `IPAddress` 类及其相关辅助函数进行单元测试**。  它通过编写一系列独立的测试用例，来验证 `IPAddress` 类的各种功能是否按照预期工作，包括：

* **IP 地址的创建和初始化:** 测试使用不同的方法创建 `IPAddress` 对象，包括从字节数组、独立的字节、以及预定义的常量（如本地环回地址）。
* **IP 地址的属性判断:** 测试判断 IP 地址版本 (IPv4/IPv6)、有效性、是否为零地址、是否为 IPv4 映射的 IPv6 地址等。
* **IP 地址的字符串转换:** 测试将 `IPAddress` 对象转换为不同格式的字符串，包括点分十进制 IPv4 地址、冒号分隔的十六进制 IPv6 地址，以及带端口号的字符串表示。
* **IP 地址的字符串解析:** 测试从字符串字面量解析 IP 地址，包括 IPv4 和 IPv6 格式，以及处理错误输入的情况。
* **IP 地址的比较:** 测试 IP 地址之间的相等性和大小比较。
* **IP 地址的转换:** 测试 IPv4 和 IPv6 地址之间的转换，包括将 IPv4 地址转换为 IPv4 映射的 IPv6 地址，以及反向转换。
* **IP 地址的范围判断:** 测试判断 IP 地址是否属于特定的保留地址范围或公共可路由地址范围。
* **IP 地址的前缀匹配:** 测试判断一个 IP 地址是否以给定的前缀开始。
* **CIDR 表示法的解析:** 测试解析 CIDR (Classless Inter-Domain Routing) 表示法的 IP 地址和前缀长度。
* **URL 主机名到 IP 地址的解析:** 测试从 URL 主机名（可能是 IP 地址或带方括号的 IPv6 地址）解析 IP 地址。
* **特殊 IP 地址的判断:** 测试判断 IP 地址是否为本地链路地址或唯一本地 IPv6 地址。
* **NAT64 相关功能测试:** 测试从 IPv4-only 的 `.arpa` 域名的 AAAA 记录中提取 NAT64 前缀，以及将 IPv4 地址嵌入到 IPv6 地址中。

**与 JavaScript 功能的关系 (举例说明):**

虽然此文件是 C++ 代码，直接在 JavaScript 环境中无法运行，但其测试的功能与 JavaScript 的网络编程密切相关。JavaScript 中处理网络请求时，经常会涉及到 IP 地址。

* **`ParseURLHostnameToAddress` 的功能与 JavaScript 的 `URL` API 和网络请求 API (如 `fetch`) 相关:**
    * **假设输入:**  JavaScript 代码中使用 `new URL("http://[2001:db8::1]")` 创建一个 URL 对象，然后浏览器需要解析这个 URL 中的主机名 `[2001:db8::1]`。
    * **输出:**  `ParseURLHostnameToAddress` 函数（在 C++ 的网络栈中）会被调用，将 `"[2001:db8::1]"` 解析为 `IPAddress` 对象，其字节表示为 `0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01`。

* **`ToString` 的功能与在 JavaScript 中展示 IP 地址相关:**
    * **假设输入:**  一个 C++ 的网络组件获取到一个 `IPAddress` 对象，其值为 IPv4 地址 `192.168.1.1`。
    * **输出:** 调用 `ToString()` 方法会返回字符串 `"192.168.1.1"`。这个字符串可能会被传递到渲染进程，最终在 JavaScript 中显示给用户，例如在开发者工具的网络面板中。

* **`IsPubliclyRoutableIPv4` / `IsPubliclyRoutableIPv6` 的功能与 JavaScript 进行网络策略判断相关:**
    * **假设输入:** JavaScript 发起一个连接请求到一个特定的 IP 地址。
    * **输出:**  在 C++ 的网络栈中，会使用 `IsPubliclyRoutable` 来判断目标 IP 地址是否为公共可路由的地址。这会影响到路由选择、安全策略等方面，虽然 JavaScript 本身不直接调用此函数，但其行为会受到这些底层判断的影响。例如，如果目标地址是私有地址，可能需要通过特定的代理或 VPN 连接。

**逻辑推理的假设输入与输出:**

* **测试 `IsIPv4`:**
    * **假设输入:** 一个 `IPAddress` 对象使用 IPv4 地址 `10.0.0.1` 初始化。
    * **预期输出:** `IsIPv4()` 方法返回 `true`，`IsIPv6()` 方法返回 `false`。

* **测试 `AssignFromIPLiteral` (成功解析 IPv6):**
    * **假设输入:** 字符串字面量 `"2001:db8::1"`。
    * **预期输出:** `AssignFromIPLiteral()` 方法返回 `true`，并且 `IPAddress` 对象的值被设置为对应的 IPv6 地址。

* **测试 `AssignFromIPLiteral` (解析失败):**
    * **假设输入:** 字符串字面量 `"invalid-ip-address"`。
    * **预期输出:** `AssignFromIPLiteral()` 方法返回 `false`，并且 `IPAddress` 对象的值被重置为空。

* **测试 `ConvertIPv4ToIPv4MappedIPv6`:**
    * **假设输入:** 一个 `IPAddress` 对象代表 IPv4 地址 `8.8.8.8`。
    * **预期输出:** `ConvertIPv4ToIPv4MappedIPv6()` 方法返回一个新的 `IPAddress` 对象，其值为 IPv4 映射的 IPv6 地址 `::ffff:8.8.8.8`，字符串表示为 `"::ffff:808:808"`。

**用户或编程常见的使用错误 (举例说明):**

* **错误地将带端口号的字符串传递给 `AssignFromIPLiteral`:**
    * **错误代码 (C++ 模拟):** `IPAddress address; address.AssignFromIPLiteral("192.168.1.1:80");`
    * **后果:**  `AssignFromIPLiteral` 会返回 `false`，因为带端口号的字符串不是合法的 IP 地址字面量。正确的做法是先解析 IP 地址，再单独处理端口号。

* **在需要 IPv6 地址的地方传入 IPv4 地址，反之亦然 (虽然 `IPAddress` 类可以处理两种类型，但某些特定操作可能有限制):**
    * **错误代码 (C++ 模拟):**  某个需要 IPv6 地址的函数接收到一个只包含 IPv4 地址的 `IPAddress` 对象。
    * **后果:**  如果该函数没有正确处理这种情况，可能会导致错误或不期望的行为。例如，在 NAT64 的场景下，可能需要的是 IPv6 地址，如果传入 IPv4 地址则无法进行转换。

* **忘记验证 `AssignFromIPLiteral` 的返回值，直接使用解析后的 `IPAddress` 对象:**
    * **错误代码 (C++ 模拟):**
    ```c++
    IPAddress address;
    address.AssignFromIPLiteral(userInput); // 用户输入可能不是合法的 IP 地址
    std::string ip_string = address.ToString(); // 如果解析失败，ToString() 可能返回空字符串或导致未定义行为
    ```
    * **后果:** 如果用户输入了无效的 IP 地址，`address` 对象可能处于无效状态，后续操作可能会出错。应该先检查 `AssignFromIPLiteral` 的返回值。

**用户操作如何一步步的到达这里 (作为调试线索):**

1. **用户在浏览器地址栏输入一个 URL 或点击一个链接。** 例如，输入 `http://[2001:db8::1]:8080/index.html`。
2. **浏览器解析 URL。**  浏览器需要识别主机名部分 `[2001:db8::1]`。
3. **DNS 解析 (如果主机名不是 IP 地址)。**  如果输入的是域名，浏览器会发起 DNS 查询，将域名解析为 IP 地址。对于直接输入的 IP 地址，则跳过此步骤。
4. **连接建立。**  浏览器（更具体地说，是其网络栈）尝试与目标 IP 地址建立连接。
5. **`ParseURLHostnameToAddress` 被调用。**  在建立连接之前，网络栈需要验证和解析主机名。如果主机名是 IP 地址字面量（包括带方括号的 IPv6 地址），则会调用 `ParseURLHostnameToAddress` 将字符串转换为 `IPAddress` 对象。
6. **后续的网络操作。** 一旦 `IPAddress` 对象被创建，它将被用于后续的网络操作，例如创建 socket 连接、发送 HTTP 请求等。

在调试网络相关问题时，如果怀疑 IP 地址解析有问题，可以在 Chromium 的网络栈代码中设置断点，查看 `ParseURLHostnameToAddress` 函数的输入和输出，以及 `IPAddress` 对象的值，从而定位问题。

**总结 (针对第一部分):**

`net/base/ip_address_unittest.cc` 的第一部分主要涵盖了 `IPAddress` 类的基础功能测试，包括创建、属性判断、字符串转换和解析、比较、基本类型转换以及公共可路由性判断。 这些测试用例确保了 `IPAddress` 类能够正确地表示和处理 IP 地址，为 Chromium 网络栈的稳定运行提供了保障。它也揭示了 IP 地址在网络编程中的核心地位，以及在 URL 解析和连接建立等关键环节的作用。

Prompt: 
```
这是目录为net/base/ip_address_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/base/ip_address.h"

#include <optional>
#include <vector>

#include "base/format_macros.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/stringprintf.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using testing::Optional;

namespace net {

namespace {

// Helper to stringize an IP address (used to define expectations).
std::string DumpIPAddress(const IPAddress& v) {
  std::string out;
  for (size_t i = 0; i < v.bytes().size(); ++i) {
    if (i != 0)
      out.append(",");
    out.append(base::NumberToString(v.bytes()[i]));
  }
  return out;
}

TEST(IPAddressBytesTest, ConstructEmpty) {
  IPAddressBytes bytes;
  ASSERT_EQ(0u, bytes.size());
}

TEST(IPAddressBytesTest, ConstructIPv4) {
  uint8_t data[] = {192, 168, 1, 1};
  IPAddressBytes bytes(data);
  ASSERT_EQ(std::size(data), bytes.size());
  size_t i = 0;
  for (uint8_t byte : bytes)
    EXPECT_EQ(data[i++], byte);
  ASSERT_EQ(std::size(data), i);
}

TEST(IPAddressBytesTest, ConstructIPv6) {
  uint8_t data[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
  IPAddressBytes bytes(data);
  ASSERT_EQ(std::size(data), bytes.size());
  size_t i = 0;
  for (uint8_t byte : bytes)
    EXPECT_EQ(data[i++], byte);
  ASSERT_EQ(std::size(data), i);
}

TEST(IPAddressBytesTest, Assign) {
  uint8_t data[] = {192, 168, 1, 1};
  IPAddressBytes copy;
  copy.Assign(data);
  EXPECT_EQ(IPAddressBytes(data), copy);
}

TEST(IPAddressTest, ConstructIPv4) {
  EXPECT_EQ("127.0.0.1", IPAddress::IPv4Localhost().ToString());

  IPAddress ipv4_ctor(192, 168, 1, 1);
  EXPECT_EQ("192.168.1.1", ipv4_ctor.ToString());
}

TEST(IPAddressTest, IsIPVersion) {
  uint8_t addr1[4] = {192, 168, 0, 1};
  IPAddress ip_address1(addr1);
  EXPECT_TRUE(ip_address1.IsIPv4());
  EXPECT_FALSE(ip_address1.IsIPv6());

  uint8_t addr2[16] = {0xFE, 0xDC, 0xBA, 0x98};
  IPAddress ip_address2(addr2);
  EXPECT_TRUE(ip_address2.IsIPv6());
  EXPECT_FALSE(ip_address2.IsIPv4());

  IPAddress ip_address3;
  EXPECT_FALSE(ip_address3.IsIPv6());
  EXPECT_FALSE(ip_address3.IsIPv4());
}

TEST(IPAddressTest, IsValid) {
  uint8_t addr1[4] = {192, 168, 0, 1};
  IPAddress ip_address1(addr1);
  EXPECT_TRUE(ip_address1.IsValid());
  EXPECT_FALSE(ip_address1.empty());

  uint8_t addr2[16] = {0xFE, 0xDC, 0xBA, 0x98};
  IPAddress ip_address2(addr2);
  EXPECT_TRUE(ip_address2.IsValid());
  EXPECT_FALSE(ip_address2.empty());

  uint8_t addr3[5] = {0xFE, 0xDC, 0xBA, 0x98};
  IPAddress ip_address3(addr3);
  EXPECT_FALSE(ip_address3.IsValid());
  EXPECT_FALSE(ip_address3.empty());

  IPAddress ip_address4;
  EXPECT_FALSE(ip_address4.IsValid());
  EXPECT_TRUE(ip_address4.empty());
}

enum IPAddressReservedResult : bool { NOT_RESERVED = false, RESERVED = true };

// Tests for the reserved IPv4 ranges and the (unreserved) blocks in between.
// The reserved ranges are tested by checking the first and last address of each
// range. The unreserved blocks are tested similarly. These tests cover the
// entire IPv4 address range, as well as this range mapped to IPv6.
TEST(IPAddressTest, IsPubliclyRoutableIPv4) {
  struct {
    const char* const address;
    IPAddressReservedResult is_reserved;
  } tests[] = {// 0.0.0.0/8
               {"0.0.0.0", RESERVED},
               {"0.255.255.255", RESERVED},
               // Unreserved block(s)
               {"1.0.0.0", NOT_RESERVED},
               {"9.255.255.255", NOT_RESERVED},
               // 10.0.0.0/8
               {"10.0.0.0", RESERVED},
               {"10.255.255.255", RESERVED},
               // Unreserved block(s)
               {"11.0.0.0", NOT_RESERVED},
               {"100.63.255.255", NOT_RESERVED},
               // 100.64.0.0/10
               {"100.64.0.0", RESERVED},
               {"100.127.255.255", RESERVED},
               // Unreserved block(s)
               {"100.128.0.0", NOT_RESERVED},
               {"126.255.255.255", NOT_RESERVED},
               // 127.0.0.0/8
               {"127.0.0.0", RESERVED},
               {"127.255.255.255", RESERVED},
               // Unreserved block(s)
               {"128.0.0.0", NOT_RESERVED},
               {"169.253.255.255", NOT_RESERVED},
               // 169.254.0.0/16
               {"169.254.0.0", RESERVED},
               {"169.254.255.255", RESERVED},
               // Unreserved block(s)
               {"169.255.0.0", NOT_RESERVED},
               {"172.15.255.255", NOT_RESERVED},
               // 172.16.0.0/12
               {"172.16.0.0", RESERVED},
               {"172.31.255.255", RESERVED},
               // Unreserved block(s)
               {"172.32.0.0", NOT_RESERVED},
               {"191.255.255.255", NOT_RESERVED},
               // 192.0.0.0/24 (including sub ranges)
               {"192.0.0.0", RESERVED},
               {"192.0.0.255", RESERVED},
               // Unreserved block(s)
               {"192.0.1.0", NOT_RESERVED},
               {"192.0.1.255", NOT_RESERVED},
               // 192.0.2.0/24
               {"192.0.2.0", RESERVED},
               {"192.0.2.255", RESERVED},
               // Unreserved block(s)
               {"192.0.3.0", NOT_RESERVED},
               {"192.31.195.255", NOT_RESERVED},
               // 192.31.196.0/24
               {"192.31.196.0", NOT_RESERVED},
               {"192.31.196.255", NOT_RESERVED},
               // Unreserved block(s)
               {"192.32.197.0", NOT_RESERVED},
               {"192.52.192.255", NOT_RESERVED},
               // 192.52.193.0/24
               {"192.52.193.0", NOT_RESERVED},
               {"192.52.193.255", NOT_RESERVED},
               // Unreserved block(s)
               {"192.52.194.0", NOT_RESERVED},
               {"192.88.98.255", NOT_RESERVED},
               // 192.88.99.0/24
               {"192.88.99.0", RESERVED},
               {"192.88.99.255", RESERVED},
               // Unreserved block(s)
               {"192.88.100.0", NOT_RESERVED},
               {"192.167.255.255", NOT_RESERVED},
               // 192.168.0.0/16
               {"192.168.0.0", RESERVED},
               {"192.168.255.255", RESERVED},
               // Unreserved block(s)
               {"192.169.0.0", NOT_RESERVED},
               {"192.175.47.255", NOT_RESERVED},
               // 192.175.48.0/24
               {"192.175.48.0", NOT_RESERVED},
               {"192.175.48.255", NOT_RESERVED},
               // Unreserved block(s)
               {"192.175.49.0", NOT_RESERVED},
               {"198.17.255.255", NOT_RESERVED},
               // 198.18.0.0/15
               {"198.18.0.0", RESERVED},
               {"198.19.255.255", RESERVED},
               // Unreserved block(s)
               {"198.20.0.0", NOT_RESERVED},
               {"198.51.99.255", NOT_RESERVED},
               // 198.51.100.0/24
               {"198.51.100.0", RESERVED},
               {"198.51.100.255", RESERVED},
               // Unreserved block(s)
               {"198.51.101.0", NOT_RESERVED},
               {"203.0.112.255", NOT_RESERVED},
               // 203.0.113.0/24
               {"203.0.113.0", RESERVED},
               {"203.0.113.255", RESERVED},
               // Unreserved block(s)
               {"203.0.114.0", NOT_RESERVED},
               {"223.255.255.255", NOT_RESERVED},
               // 224.0.0.0/8 - 255.0.0.0/8
               {"224.0.0.0", RESERVED},
               {"255.255.255.255", RESERVED}};

  for (const auto& test : tests) {
    IPAddress address;
    EXPECT_TRUE(address.AssignFromIPLiteral(test.address));
    ASSERT_TRUE(address.IsValid());
    EXPECT_EQ(!test.is_reserved, address.IsPubliclyRoutable());

    // Check these IPv4 addresses when mapped to IPv6. This verifies we're
    // properly unpacking mapped addresses.
    IPAddress mapped_address = ConvertIPv4ToIPv4MappedIPv6(address);
    EXPECT_EQ(!test.is_reserved, mapped_address.IsPubliclyRoutable());
  }
}

// Tests for the reserved IPv6 ranges and the (unreserved) blocks in between.
// The reserved ranges are tested by checking the first and last address of each
// range. The unreserved blocks are tested similarly. These tests cover the
// entire IPv6 address range.
TEST(IPAddressTest, IsPubliclyRoutableIPv6) {
  struct {
    const char* const address;
    IPAddressReservedResult is_reserved;
  } tests[] = {// 0000::/8.
               // Skip testing ::ffff:/96 explicitly since it was tested
               // in IsPubliclyRoutableIPv4
               {"0:0:0:0:0:0:0:0", RESERVED},
               {"ff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", RESERVED},
               // 0100::/8
               {"100:0:0:0:0:0:0:0", RESERVED},
               {"1ff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", RESERVED},
               // 0200::/7
               {"200:0:0:0:0:0:0:0", RESERVED},
               {"3ff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", RESERVED},
               // 0400::/6
               {"400:0:0:0:0:0:0:0", RESERVED},
               {"7ff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", RESERVED},
               // 0800::/5
               {"800:0:0:0:0:0:0:0", RESERVED},
               {"fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", RESERVED},
               // 1000::/4
               {"1000:0:0:0:0:0:0:0", RESERVED},
               {"1fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", RESERVED},
               // 2000::/3 (Global Unicast)
               {"2000:0:0:0:0:0:0:0", NOT_RESERVED},
               {"3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", NOT_RESERVED},
               // 4000::/3
               {"4000:0:0:0:0:0:0:0", RESERVED},
               {"5fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", RESERVED},
               // 6000::/3
               {"6000:0:0:0:0:0:0:0", RESERVED},
               {"7fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", RESERVED},
               // 8000::/3
               {"8000:0:0:0:0:0:0:0", RESERVED},
               {"9fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", RESERVED},
               // c000::/3
               {"c000:0:0:0:0:0:0:0", RESERVED},
               {"dfff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", RESERVED},
               // e000::/4
               {"e000:0:0:0:0:0:0:0", RESERVED},
               {"efff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", RESERVED},
               // f000::/5
               {"f000:0:0:0:0:0:0:0", RESERVED},
               {"f7ff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", RESERVED},
               // f800::/6
               {"f800:0:0:0:0:0:0:0", RESERVED},
               {"fbff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", RESERVED},
               // fc00::/7
               {"fc00:0:0:0:0:0:0:0", RESERVED},
               {"fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", RESERVED},
               // fe00::/9
               {"fe00:0:0:0:0:0:0:0", RESERVED},
               {"fe7f:ffff:ffff:ffff:ffff:ffff:ffff:ffff", RESERVED},
               // fe80::/10
               {"fe80:0:0:0:0:0:0:0", RESERVED},
               {"febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff", RESERVED},
               // fec0::/10
               {"fec0:0:0:0:0:0:0:0", RESERVED},
               {"feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", RESERVED},
               // ff00::/8 (Multicast)
               {"ff00:0:0:0:0:0:0:0", NOT_RESERVED},
               {"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", NOT_RESERVED}};

  IPAddress address;
  for (const auto& test : tests) {
    EXPECT_TRUE(address.AssignFromIPLiteral(test.address));
    EXPECT_EQ(!test.is_reserved, address.IsPubliclyRoutable());
  }
}

TEST(IPAddressTest, IsZero) {
  uint8_t address1[4] = {};
  IPAddress zero_ipv4_address(address1);
  EXPECT_TRUE(zero_ipv4_address.IsZero());

  uint8_t address2[4] = {10};
  IPAddress non_zero_ipv4_address(address2);
  EXPECT_FALSE(non_zero_ipv4_address.IsZero());

  uint8_t address3[16] = {};
  IPAddress zero_ipv6_address(address3);
  EXPECT_TRUE(zero_ipv6_address.IsZero());

  uint8_t address4[16] = {10};
  IPAddress non_zero_ipv6_address(address4);
  EXPECT_FALSE(non_zero_ipv6_address.IsZero());

  IPAddress empty_address;
  EXPECT_FALSE(empty_address.IsZero());
}

TEST(IPAddressTest, IsIPv4Mapped) {
  IPAddress ipv4_address(192, 168, 0, 1);
  EXPECT_FALSE(ipv4_address.IsIPv4MappedIPv6());
  IPAddress ipv6_address(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1);
  EXPECT_FALSE(ipv6_address.IsIPv4MappedIPv6());
  IPAddress mapped_address(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 1, 1, 0, 1);
  EXPECT_TRUE(mapped_address.IsIPv4MappedIPv6());
}

TEST(IPAddressTest, AllZeros) {
  EXPECT_TRUE(IPAddress::AllZeros(0).empty());

  EXPECT_EQ(3u, IPAddress::AllZeros(3).size());
  EXPECT_TRUE(IPAddress::AllZeros(3).IsZero());

  EXPECT_EQ("0.0.0.0", IPAddress::IPv4AllZeros().ToString());
  EXPECT_EQ("::", IPAddress::IPv6AllZeros().ToString());
}

TEST(IPAddressTest, ToString) {
  EXPECT_EQ("0.0.0.0", IPAddress::IPv4AllZeros().ToString());

  IPAddress address(192, 168, 0, 1);
  EXPECT_EQ("192.168.0.1", address.ToString());

  IPAddress address2(0xFE, 0xDC, 0xBA, 0x98, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                     0);
  EXPECT_EQ("fedc:ba98::", address2.ToString());

  // ToString() shouldn't crash on invalid addresses.
  uint8_t addr4[2];
  IPAddress address4(addr4);
  EXPECT_EQ("", address4.ToString());

  IPAddress address5;
  EXPECT_EQ("", address5.ToString());
}

TEST(IPAddressTest, IPAddressToStringWithPort) {
  EXPECT_EQ("0.0.0.0:3",
            IPAddressToStringWithPort(IPAddress::IPv4AllZeros(), 3));

  IPAddress address1(192, 168, 0, 1);
  EXPECT_EQ("192.168.0.1:99", IPAddressToStringWithPort(address1, 99));

  IPAddress address2(0xFE, 0xDC, 0xBA, 0x98, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                     0);
  EXPECT_EQ("[fedc:ba98::]:8080", IPAddressToStringWithPort(address2, 8080));

  // IPAddressToStringWithPort() shouldn't crash on invalid addresses.
  uint8_t addr3[2];
  EXPECT_EQ("", IPAddressToStringWithPort(IPAddress(addr3), 8080));
}

TEST(IPAddressTest, IPAddressToPackedString) {
  IPAddress ipv4_address;
  EXPECT_TRUE(ipv4_address.AssignFromIPLiteral("4.31.198.44"));
  std::string expected_ipv4_address("\x04\x1f\xc6\x2c", 4);
  EXPECT_EQ(expected_ipv4_address, IPAddressToPackedString(ipv4_address));

  IPAddress ipv6_address;
  EXPECT_TRUE(ipv6_address.AssignFromIPLiteral("2001:0700:0300:1800::000f"));
  std::string expected_ipv6_address(
      "\x20\x01\x07\x00\x03\x00\x18\x00"
      "\x00\x00\x00\x00\x00\x00\x00\x0f",
      16);
  EXPECT_EQ(expected_ipv6_address, IPAddressToPackedString(ipv6_address));
}

// Test that invalid IP literals fail to parse.
TEST(IPAddressTest, AssignFromIPLiteral_FailParse) {
  IPAddress address;

  EXPECT_FALSE(address.AssignFromIPLiteral("bad value"));
  EXPECT_FALSE(address.AssignFromIPLiteral("bad:value"));
  EXPECT_FALSE(address.AssignFromIPLiteral(std::string()));
  EXPECT_FALSE(address.AssignFromIPLiteral("192.168.0.1:30"));
  EXPECT_FALSE(address.AssignFromIPLiteral("  192.168.0.1  "));
  EXPECT_FALSE(address.AssignFromIPLiteral("[::1]"));
}

// Test that a failure calling AssignFromIPLiteral() has the sideffect of
// clearing the current value.
TEST(IPAddressTest, AssignFromIPLiteral_ResetOnFailure) {
  IPAddress address = IPAddress::IPv6Localhost();

  EXPECT_TRUE(address.IsValid());
  EXPECT_FALSE(address.empty());

  EXPECT_FALSE(address.AssignFromIPLiteral("bad value"));

  EXPECT_FALSE(address.IsValid());
  EXPECT_TRUE(address.empty());
}

// Test parsing an IPv4 literal.
TEST(IPAddressTest, AssignFromIPLiteral_IPv4) {
  IPAddress address;
  EXPECT_TRUE(address.AssignFromIPLiteral("192.168.0.1"));
  EXPECT_EQ("192,168,0,1", DumpIPAddress(address));
  EXPECT_EQ("192.168.0.1", address.ToString());
}

// Test parsing an IPv6 literal.
TEST(IPAddressTest, AssignFromIPLiteral_IPv6) {
  IPAddress address;
  EXPECT_TRUE(address.AssignFromIPLiteral("1:abcd::3:4:ff"));
  EXPECT_EQ("0,1,171,205,0,0,0,0,0,0,0,3,0,4,0,255", DumpIPAddress(address));
  EXPECT_EQ("1:abcd::3:4:ff", address.ToString());
}

TEST(IPAddressTest, IsIPv4MappedIPv6) {
  IPAddress ipv4_address(192, 168, 0, 1);
  EXPECT_FALSE(ipv4_address.IsIPv4MappedIPv6());
  IPAddress ipv6_address = IPAddress::IPv6Localhost();
  EXPECT_FALSE(ipv6_address.IsIPv4MappedIPv6());
  IPAddress mapped_address(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 1, 1, 0, 1);
  EXPECT_TRUE(mapped_address.IsIPv4MappedIPv6());
}

TEST(IPAddressTest, IsEqual) {
  IPAddress ip_address1;
  EXPECT_TRUE(ip_address1.AssignFromIPLiteral("127.0.0.1"));
  IPAddress ip_address2;
  EXPECT_TRUE(ip_address2.AssignFromIPLiteral("2001:db8:0::42"));
  IPAddress ip_address3;
  EXPECT_TRUE(ip_address3.AssignFromIPLiteral("127.0.0.1"));

  EXPECT_FALSE(ip_address1 == ip_address2);
  EXPECT_TRUE(ip_address1 == ip_address3);
}

TEST(IPAddressTest, LessThan) {
  // IPv4 vs IPv6
  IPAddress ip_address1;
  EXPECT_TRUE(ip_address1.AssignFromIPLiteral("127.0.0.1"));
  IPAddress ip_address2;
  EXPECT_TRUE(ip_address2.AssignFromIPLiteral("2001:db8:0::42"));
  EXPECT_TRUE(ip_address1 < ip_address2);
  EXPECT_FALSE(ip_address2 < ip_address1);

  // Compare equivalent addresses.
  IPAddress ip_address3;
  EXPECT_TRUE(ip_address3.AssignFromIPLiteral("127.0.0.1"));
  EXPECT_FALSE(ip_address1 < ip_address3);
  EXPECT_FALSE(ip_address3 < ip_address1);

  IPAddress ip_address4;
  EXPECT_TRUE(ip_address4.AssignFromIPLiteral("128.0.0.0"));
  EXPECT_TRUE(ip_address1 < ip_address4);
  EXPECT_FALSE(ip_address4 < ip_address1);
}

// Test mapping an IPv4 address to an IPv6 address.
TEST(IPAddressTest, ConvertIPv4ToIPv4MappedIPv6) {
  IPAddress ipv4_address(192, 168, 0, 1);
  IPAddress ipv6_address = ConvertIPv4ToIPv4MappedIPv6(ipv4_address);

  // ::ffff:192.168.0.1
  EXPECT_EQ("0,0,0,0,0,0,0,0,0,0,255,255,192,168,0,1",
            DumpIPAddress(ipv6_address));
  EXPECT_EQ("::ffff:c0a8:1", ipv6_address.ToString());
}

// Test reversal of a IPv6 address mapping.
TEST(IPAddressTest, ConvertIPv4MappedIPv6ToIPv4) {
  IPAddress ipv4mapped_address;
  EXPECT_TRUE(ipv4mapped_address.AssignFromIPLiteral("::ffff:c0a8:1"));

  IPAddress expected(192, 168, 0, 1);

  IPAddress result = ConvertIPv4MappedIPv6ToIPv4(ipv4mapped_address);
  EXPECT_EQ(expected, result);
}

TEST(IPAddressTest, IPAddressMatchesPrefix) {
  struct {
    const char* const cidr_literal;
    size_t prefix_length_in_bits;
    const char* const ip_literal;
    bool expected_to_match;
  } tests[] = {
      // IPv4 prefix with IPv4 inputs.
      {"10.10.1.32", 27, "10.10.1.44", true},
      {"10.10.1.32", 27, "10.10.1.90", false},
      {"10.10.1.32", 27, "10.10.1.90", false},

      // IPv6 prefix with IPv6 inputs.
      {"2001:db8::", 32, "2001:DB8:3:4::5", true},
      {"2001:db8::", 32, "2001:c8::", false},

      // IPv6 prefix with IPv4 inputs.
      {"2001:db8::", 33, "192.168.0.1", false},
      {"::ffff:192.168.0.1", 112, "192.168.33.77", true},

      // IPv4 prefix with IPv6 inputs.
      {"10.11.33.44", 16, "::ffff:0a0b:89", true},
      {"10.11.33.44", 16, "::ffff:10.12.33.44", false},
  };
  for (const auto& test : tests) {
    SCOPED_TRACE(
        base::StringPrintf("%s, %s", test.cidr_literal, test.ip_literal));

    IPAddress ip_address;
    EXPECT_TRUE(ip_address.AssignFromIPLiteral(test.ip_literal));

    IPAddress ip_prefix;
    EXPECT_TRUE(ip_prefix.AssignFromIPLiteral(test.cidr_literal));

    EXPECT_EQ(test.expected_to_match,
              IPAddressMatchesPrefix(ip_address, ip_prefix,
                                     test.prefix_length_in_bits));
  }
}

// Test parsing invalid CIDR notation literals.
TEST(IPAddressTest, ParseCIDRBlock_Invalid) {
  const char* const bad_literals[] = {"foobar",
                                      "",
                                      "192.168.0.1",
                                      "::1",
                                      "/",
                                      "/1",
                                      "1",
                                      "192.168.1.1/-1",
                                      "192.168.1.1/33",
                                      "::1/-3",
                                      "a::3/129",
                                      "::1/x",
                                      "192.168.0.1//11",
                                      "192.168.1.1/+1",
                                      "192.168.1.1/ +1",
                                      "192.168.1.1/"};

  for (auto* bad_literal : bad_literals) {
    IPAddress ip_address;
    size_t prefix_length_in_bits;

    EXPECT_FALSE(
        ParseCIDRBlock(bad_literal, &ip_address, &prefix_length_in_bits));
  }
}

// Test parsing a valid CIDR notation literal.
TEST(IPAddressTest, ParseCIDRBlock_Valid) {
  IPAddress ip_address;
  size_t prefix_length_in_bits;

  EXPECT_TRUE(
      ParseCIDRBlock("192.168.0.1/11", &ip_address, &prefix_length_in_bits));

  EXPECT_EQ("192,168,0,1", DumpIPAddress(ip_address));
  EXPECT_EQ(11u, prefix_length_in_bits);

  EXPECT_TRUE(ParseCIDRBlock("::ffff:192.168.0.1/112", &ip_address,
                             &prefix_length_in_bits));

  EXPECT_EQ("0,0,0,0,0,0,0,0,0,0,255,255,192,168,0,1",
            DumpIPAddress(ip_address));
  EXPECT_EQ(112u, prefix_length_in_bits);
}

TEST(IPAddressTest, ParseURLHostnameToAddress_FailParse) {
  IPAddress address;
  EXPECT_FALSE(ParseURLHostnameToAddress("bad value", &address));
  EXPECT_FALSE(ParseURLHostnameToAddress("bad:value", &address));
  EXPECT_FALSE(ParseURLHostnameToAddress(std::string(), &address));
  EXPECT_FALSE(ParseURLHostnameToAddress("192.168.0.1:30", &address));
  EXPECT_FALSE(ParseURLHostnameToAddress("  192.168.0.1  ", &address));
  EXPECT_FALSE(ParseURLHostnameToAddress("::1", &address));
  EXPECT_FALSE(ParseURLHostnameToAddress("[192.169.0.1]", &address));
}

TEST(IPAddressTest, ParseURLHostnameToAddress_IPv4) {
  IPAddress address;
  EXPECT_TRUE(ParseURLHostnameToAddress("192.168.0.1", &address));
  EXPECT_EQ("192,168,0,1", DumpIPAddress(address));
  EXPECT_EQ("192.168.0.1", address.ToString());
}

TEST(IPAddressTest, ParseURLHostnameToAddress_IPv6) {
  IPAddress address;
  EXPECT_TRUE(ParseURLHostnameToAddress("[1:abcd::3:4:ff]", &address));
  EXPECT_EQ("0,1,171,205,0,0,0,0,0,0,0,3,0,4,0,255", DumpIPAddress(address));
  EXPECT_EQ("1:abcd::3:4:ff", address.ToString());
}

TEST(IPAddressTest, IPAddressStartsWith) {
  IPAddress ipv4_address(192, 168, 10, 5);

  uint8_t ipv4_prefix1[] = {192, 168, 10};
  EXPECT_TRUE(IPAddressStartsWith(ipv4_address, ipv4_prefix1));

  uint8_t ipv4_prefix3[] = {192, 168, 10, 5};
  EXPECT_TRUE(IPAddressStartsWith(ipv4_address, ipv4_prefix3));

  uint8_t ipv4_prefix2[] = {192, 168, 10, 10};
  EXPECT_FALSE(IPAddressStartsWith(ipv4_address, ipv4_prefix2));

  // Prefix is longer than the address.
  uint8_t ipv4_prefix4[] = {192, 168, 10, 10, 0};
  EXPECT_FALSE(IPAddressStartsWith(ipv4_address, ipv4_prefix4));

  IPAddress ipv6_address;
  EXPECT_TRUE(ipv6_address.AssignFromIPLiteral("2a00:1450:400c:c09::64"));

  uint8_t ipv6_prefix1[] = {42, 0, 20, 80, 64, 12, 12, 9};
  EXPECT_TRUE(IPAddressStartsWith(ipv6_address, ipv6_prefix1));

  uint8_t ipv6_prefix2[] = {41, 0, 20, 80, 64, 12, 12, 9,
                            0,  0, 0,  0,  0,  0,  100};
  EXPECT_FALSE(IPAddressStartsWith(ipv6_address, ipv6_prefix2));

  uint8_t ipv6_prefix3[] = {42, 0, 20, 80, 64, 12, 12, 9,
                            0,  0, 0,  0,  0,  0,  0,  100};
  EXPECT_TRUE(IPAddressStartsWith(ipv6_address, ipv6_prefix3));

  uint8_t ipv6_prefix4[] = {42, 0, 20, 80, 64, 12, 12, 9,
                            0,  0, 0,  0,  0,  0,  0,  0};
  EXPECT_FALSE(IPAddressStartsWith(ipv6_address, ipv6_prefix4));

  // Prefix is longer than the address.
  uint8_t ipv6_prefix5[] = {42, 0, 20, 80, 64, 12, 12, 9, 0,
                            0,  0, 0,  0,  0,  0,  0,  10};
  EXPECT_FALSE(IPAddressStartsWith(ipv6_address, ipv6_prefix5));
}

TEST(IPAddressTest, IsLinkLocal) {
  const char* kPositive[] = {
      "169.254.0.0",
      "169.254.100.1",
      "169.254.100.1",
      "::ffff:169.254.0.0",
      "::ffff:169.254.100.1",
      "fe80::1",
      "fe81::1",
  };

  for (const char* literal : kPositive) {
    IPAddress ip_address;
    ASSERT_TRUE(ip_address.AssignFromIPLiteral(literal));
    EXPECT_TRUE(ip_address.IsLinkLocal()) << literal;
  }

  const char* kNegative[] = {
      "170.254.0.0",        "169.255.0.0",        "::169.254.0.0",
      "::fffe:169.254.0.0", "::ffff:169.255.0.0", "fec0::1",
  };

  for (const char* literal : kNegative) {
    IPAddress ip_address;
    ASSERT_TRUE(ip_address.AssignFromIPLiteral(literal));
    EXPECT_FALSE(ip_address.IsLinkLocal()) << literal;
  }
}

TEST(IPAddressTest, IsUniqueLocalIPv6) {
  const char* kPositive[] = {
      "fc00::1",
      "fc80::1",
      "fd00::1",
  };

  for (const char* literal : kPositive) {
    IPAddress ip_address;
    ASSERT_TRUE(ip_address.AssignFromIPLiteral(literal));
    EXPECT_TRUE(ip_address.IsUniqueLocalIPv6()) << literal;
  }

  const char* kNegative[] = {
      "fe00::1",
      "ff00::1",
      "252.0.0.1",
  };

  for (const char* literal : kNegative) {
    IPAddress ip_address;
    ASSERT_TRUE(ip_address.AssignFromIPLiteral(literal));
    EXPECT_FALSE(ip_address.IsUniqueLocalIPv6()) << literal;
  }
}

// Tests extraction of the NAT64 translation prefix.
TEST(IPAddressTest, ExtractPref64FromIpv4onlyArpaAAAA) {
  // Well Known Prefix 64:ff9b::/96.
  IPAddress ipv6_address_WKP_0(0, 100, 255, 155, 0, 0, 0, 0, 0, 0, 0, 0, 192, 0,
                               0, 170);
  IPAddress ipv6_address_WKP_1(0, 100, 255, 155, 0, 0, 0, 0, 0, 0, 0, 0, 192, 0,
                               0, 171);
  Dns64PrefixLength pref64_length_WKP_0 =
      ExtractPref64FromIpv4onlyArpaAAAA(ipv6_address_WKP_0);
  Dns64PrefixLength pref64_length_WKP_1 =
      ExtractPref64FromIpv4onlyArpaAAAA(ipv6_address_WKP_1);
  EXPECT_EQ(Dns64PrefixLength::k96bit, pref64_length_WKP_0);
  EXPECT_EQ(Dns64PrefixLength::k96bit, pref64_length_WKP_1);

  // Prefix length 96
  IPAddress ipv6_address_96_0(32, 1, 13, 184, 1, 34, 3, 68, 0, 0, 0, 0, 192, 0,
                              0, 170);
  IPAddress ipv6_address_96_1(32, 1, 13, 184, 1, 34, 3, 68, 0, 0, 0, 0, 192, 0,
                              0, 171);
  Dns64PrefixLength pref64_length_96_0 =
      ExtractPref64FromIpv4onlyArpaAAAA(ipv6_address_96_0);
  Dns64PrefixLength pref64_length_96_1 =
      ExtractPref64FromIpv4onlyArpaAAAA(ipv6_address_96_1);
  EXPECT_EQ(Dns64PrefixLength::k96bit, pref64_length_96_0);
  EXPECT_EQ(Dns64PrefixLength::k96bit, pref64_length_96_1);

  // Prefix length 64
  IPAddress ipv6_address_64_0(32, 1, 13, 184, 1, 34, 3, 68, 0, 192, 0, 0, 170,
                              0, 0, 0);
  IPAddress ipv6_address_64_1(32, 1, 13, 184, 1, 34, 3, 68, 0, 192, 0, 0, 171,
                              0, 0, 0);
  Dns64PrefixLength pref64_length_64_0 =
      ExtractPref64FromIpv4onlyArpaAAAA(ipv6_address_64_0);
  Dns64PrefixLength pref64_length_64_1 =
      ExtractPref64FromIpv4onlyArpaAAAA(ipv6_address_64_1);
  EXPECT_EQ(Dns64PrefixLength::k64bit, pref64_length_64_0);
  EXPECT_EQ(Dns64PrefixLength::k64bit, pref64_length_64_1);

  // Prefix length 56
  IPAddress ipv6_address_56_0(32, 1, 13, 184, 1, 34, 3, 192, 0, 0, 0, 170, 0, 0,
                              0, 0);
  IPAddress ipv6_address_56_1(32, 1, 13, 184, 1, 34, 3, 192, 0, 0, 0, 171, 0, 0,
                              0, 0);
  Dns64PrefixLength pref64_length_56_0 =
      ExtractPref64FromIpv4onlyArpaAAAA(ipv6_address_56_0);
  Dns64PrefixLength pref64_length_56_1 =
      ExtractPref64FromIpv4onlyArpaAAAA(ipv6_address_56_1);
  EXPECT_EQ(Dns64PrefixLength::k56bit, pref64_length_56_0);
  EXPECT_EQ(Dns64PrefixLength::k56bit, pref64_length_56_1);

  // Prefix length 48
  IPAddress ipv6_address_48_0(32, 1, 13, 184, 1, 34, 192, 0, 0, 0, 170, 0, 0, 0,
                              0, 0);
  IPAddress ipv6_address_48_1(32, 1, 13, 184, 1, 34, 192, 0, 0, 0, 171, 0, 0, 0,
                              0, 0);
  Dns64PrefixLength pref64_length_48_0 =
      ExtractPref64FromIpv4onlyArpaAAAA(ipv6_address_48_0);
  Dns64PrefixLength pref64_length_48_1 =
      ExtractPref64FromIpv4onlyArpaAAAA(ipv6_address_48_1);
  EXPECT_EQ(Dns64PrefixLength::k48bit, pref64_length_48_0);
  EXPECT_EQ(Dns64PrefixLength::k48bit, pref64_length_48_1);

  // Prefix length 40
  IPAddress ipv6_address_40_0(32, 1, 13, 184, 1, 192, 0, 0, 0, 170, 0, 0, 0, 0,
                              0, 0);
  IPAddress ipv6_address_40_1(32, 1, 13, 184, 1, 192, 0, 0, 0, 171, 0, 0, 0, 0,
                              0, 0);
  Dns64PrefixLength pref64_length_40_0 =
      ExtractPref64FromIpv4onlyArpaAAAA(ipv6_address_40_0);
  Dns64PrefixLength pref64_length_40_1 =
      ExtractPref64FromIpv4onlyArpaAAAA(ipv6_address_40_1);
  EXPECT_EQ(Dns64PrefixLength::k40bit, pref64_length_40_0);
  EXPECT_EQ(Dns64PrefixLength::k40bit, pref64_length_40_1);

  // Prefix length 32
  IPAddress ipv6_address_32_0(32, 1, 13, 184, 192, 0, 0, 170, 0, 0, 0, 0, 0, 0,
                              0, 0);
  IPAddress ipv6_address_32_1(32, 1, 13, 184, 192, 0, 0, 171, 0, 0, 0, 0, 0, 0,
                              0, 0);
  Dns64PrefixLength pref64_length_32_0 =
      ExtractPref64FromIpv4onlyArpaAAAA(ipv6_address_32_0);
  Dns64PrefixLength pref64_length_32_1 =
      ExtractPref64FromIpv4onlyArpaAAAA(ipv6_address_32_1);
  EXPECT_EQ(Dns64PrefixLength::k32bit, pref64_length_32_0);
  EXPECT_EQ(Dns64PrefixLength::k32bit, pref64_length_32_1);
}

// Tests mapping an IPv4 address to an IPv6 address.
TEST(IPAddressTest, ConvertIPv4ToIPv4EmbeddedIPv6) {
  IPAddress ipv4_address(192, 0, 2, 33);

  // Well Known Prefix 64:ff9b::/96.
  IPAddress ipv6_address_WKP(0, 100, 255, 155, 0, 0, 0, 0, 0, 0, 0, 0, 192, 0,
                             0, 170);
  IPAddress converted_ipv6_address_WKP = ConvertIPv4ToIPv4EmbeddedIPv6(
      ipv4_address, ipv6_address_WKP, Dns64PrefixLength::k96bit);
  EXPECT_EQ("0,100,255,155,0,0,0,0,0,0,0,0,192,0,2,33",
            DumpIPAddress(converted_ipv6_address_WKP));
  EXPECT_EQ("64:ff9b::c000:221", converted_ipv6_address_WKP.ToString());

  // Prefix length 96
  IPAddress ipv6_address_96(32, 1, 13, 184, 1, 34, 3, 68, 0, 0, 0, 0, 0, 0, 0,
                            0);
  IPAddress converted_ipv6_address_96 = ConvertIPv4ToIPv4EmbeddedIPv6(
      ipv4_address, ipv6_address_96, Dns64PrefixLength::k96bit);
  EXPECT_EQ("32,1,13,184,1,34,3,68,0,0,0,0,192,0,2,33",
            DumpIPAddress(converted_ipv6_address_96));
  EXPECT_EQ("2001:db8:122:344::c000:221", converted_ipv6_address_96.ToString());

  // Prefix length 64
  IPAddress ipv6_address_64(32, 1, 13, 184, 1, 34, 3, 68, 0, 0, 0, 0, 0, 0, 0,
                            0);
  IPAddress converted_ipv6_address_64 = ConvertIPv4ToIPv4EmbeddedIPv6(
      ipv4_address, ipv6_address_64, Dns64PrefixLength::k64bit);
  EXPECT_EQ("32,1,13,184,1,34,3,68,0,192,0,2,33,0,0,0",
            DumpIPAddress(converted_ipv6_address_64));
  EXPECT_EQ("2001:db8:122:344:c0:2:2100:0",
            converted_ipv6_address_64.ToString());

  // Prefix length 56
  IPAddress ipv6_address_56(32, 1, 13, 184, 1, 34, 3, 0, 0, 0, 0, 0, 0, 0, 0,
                            0);
  IPAddress converted_ipv6_address_56 = ConvertIPv4ToIPv4EmbeddedIPv6(
      ipv4_address, ipv6_address_56, Dns64PrefixLength::k56bit);
  EXPECT_EQ("32,1,13,184,1,34,3,192,0,0,2,33,0,0,0,0",
            DumpIPAddress(converted_ipv6_address_56));
  EXPECT_EQ("2001:db8:122:3c0:0:221::", converted_ipv6_address_56.ToString());

  // Prefix length 48
  IPAddress ipv6_address_48(32, 1, 13, 184, 1, 34, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                            0);
  IPAddress converted_ipv6_address_48 = ConvertIPv4ToIPv4EmbeddedIPv6(
      ipv4_address, ipv6_address_48, Dns64PrefixLength::k48bit);
  EXPECT_EQ("32,1,13,184,1,34,192,0,0,2,33,0,0,0,0,0",
            DumpIPAddress(converted_ipv6_address_48));
  EXPECT_EQ("2001:db8:122:c000:2:2100::", converted_ipv6_address_48.ToString());

  // Prefix length 40
  IPAddress ipv6_address_40(32, 1, 13, 184, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
  IPAddress converted_ipv6_address_40 = ConvertIPv4ToIPv4EmbeddedIPv6(
      ipv4_address, ipv6_address_40, Dns64PrefixLength::k40bit);
  EXPECT_EQ("32,1,13,184,1,192,0,2,0,33,0,0,0,0,0,0",
            DumpIPAddress(converted_ipv6_address_40));
  EXPECT_EQ("2001:db8:1c0:2:21::", converted_ipv6_address_40.ToString());

  // Prefix length 32
  IPAddress ipv6_address_32(32, 1, 13, 184, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
  IPAddress converted_ipv6_address_32 = ConvertIPv4ToIPv4EmbeddedIPv6(
      ipv4_address, ipv6_address_32, Dns64PrefixLength::k32bit);
  EXPECT_EQ("32,1,13,184,192,0,2,33,0,0,0,0,0,0,0,0",
            DumpIPAddress(conv
"""


```