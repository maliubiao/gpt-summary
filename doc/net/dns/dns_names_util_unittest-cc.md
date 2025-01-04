Response:
Let's break down the thought process for analyzing this C++ unittest file.

1. **Identify the Core Purpose:** The filename `dns_names_util_unittest.cc` immediately tells us this file contains unit tests. The `dns_names_util` part suggests it's testing utilities related to DNS names.

2. **Scan the Includes:**  The included headers provide clues about the functionality being tested:
    * `net/dns/dns_names_util.h`: This is the primary header, containing the definitions of the functions being tested.
    * Standard C++ headers (`<climits>`, `<cstdint>`, `<cstring>`, etc.): Indicate basic data type and memory manipulation.
    * `base/containers/span_reader.h`: Suggests the code deals with reading data from contiguous memory regions.
    * `base/numerics/safe_conversions.h`:  Implies attention to potential overflow or truncation issues.
    * `net/dns/dns_util.h` and `net/dns/public/dns_protocol.h`:  Confirms the focus on DNS-related operations and understanding DNS structure.
    * `testing/gmock/include/gmock/gmock.h` and `testing/gtest/include/gtest/gtest.h`:  Explicitly confirms this is a unit test file using Google Test and Google Mock frameworks.

3. **Analyze the Namespaces:** The code is within the `net::dns_names_util` namespace, further solidifying the area of functionality.

4. **Examine Helper Functions:** The `ToBytes` function is a small helper. Recognizing its role in converting C-style strings to `std::vector<uint8_t>` is crucial for understanding the test inputs and expected outputs. The inclusion of the null terminator is important.

5. **Focus on the Test Cases (Using `TEST()`):** This is where the core logic lies. Group the tests based on the function being tested:
    * **`DottedNameToNetwork` and `DottedNameToNetworkWithValidation`:**  These tests clearly focus on converting human-readable dotted DNS names (like "google.com") into the network byte format. The "WithValidation" suffix indicates a version that performs extra checks. Pay attention to the different scenarios tested: valid names, empty labels, long names, too-long names, and restricted characters. Note the use of `EXPECT_THAT` with `Optional` and `ToBytes`, indicating that the functions return an optional value and the expected output is in the byte format.
    * **`NetworkToDottedName`:** These tests cover the reverse operation: converting the network byte format back to a human-readable dotted name. Observe tests for simple names, empty input, handling of completeness, rejection of compression, handling excess input, rejecting truncated names, and tests for maximum length labels and names.
    * **`IsValidDnsName` and `IsValidDnsRecordName`:** These tests verify functions that check the validity of DNS names, with `IsValidDnsRecordName` having stricter rules (e.g., not allowing "localhost" or IP addresses).
    * **`UrlCanonicalizeNameIfAble`:** This test focuses on canonicalizing DNS names for URL usage (e.g., converting to lowercase, handling Punycode for internationalized domain names).
    * **`ReadU8LengthPrefixed` and `ReadU16LengthPrefixed`:** These tests are about reading length-prefixed data from a byte stream, a common pattern in network protocols.

6. **Identify Key Functionality:** Based on the test cases, extract the core functionalities of `dns_names_util`:
    * Converting dotted DNS names to network byte format.
    * Converting network byte format back to dotted DNS names.
    * Validating the format of DNS names.
    * Canonicalizing DNS names for URLs.
    * Reading length-prefixed data from byte streams.

7. **Analyze JavaScript Relevance (If Any):**  Think about where DNS name manipulation is relevant in a web browser context:
    * **URL parsing:**  When a user types a URL, the browser needs to resolve the hostname.
    * **Fetching resources:**  Making network requests involves DNS resolution.
    * **WebSockets and other network APIs:**  These often rely on hostnames.
    * **Security features (like CORS):**  Domain names play a crucial role.

8. **Illustrate with JavaScript Examples:**  Create concrete examples of how the C++ functionality relates to JavaScript. Focus on the observable behavior in JavaScript, even if the underlying implementation is in C++.

9. **Infer Logic and Create Example Inputs/Outputs:** For each major function, create hypothetical inputs and the corresponding expected outputs based on the test cases. This demonstrates an understanding of the transformations being performed.

10. **Identify Potential User/Programming Errors:**  Think about common mistakes developers might make when dealing with DNS names or byte streams:
    * Incorrectly formatting DNS names.
    * Providing too-long names.
    * Not handling the network byte format correctly.
    * Misunderstanding the validation rules.

11. **Trace User Actions (Debugging Perspective):**  Consider how a user action in the browser might lead to this code being executed. This provides debugging context. Start with a user action (typing a URL) and follow the chain of events.

12. **Structure the Output:** Organize the findings logically, using clear headings and bullet points. Start with a high-level overview and then delve into specifics.

13. **Refine and Review:** Read through the analysis to ensure accuracy, clarity, and completeness. Check for any inconsistencies or areas where further explanation is needed. For example, double-check the assumptions about JavaScript and the connections between C++ and browser behavior. Ensure the examples are clear and easy to understand.

By following these steps, you can systematically analyze a C++ source file and understand its functionality, its relevance to other technologies (like JavaScript), and potential usage scenarios and pitfalls.
这个文件 `net/dns/dns_names_util_unittest.cc` 是 Chromium 网络栈中关于 DNS 名称实用工具函数的**单元测试文件**。它的主要功能是**测试 `net/dns/dns_names_util.h` 中定义的 DNS 名称处理相关函数的正确性**。

具体来说，它测试了以下几个方面的功能：

1. **`DottedNameToNetwork` 和 `DottedNameToNetworkWithValidation`**:
   - **功能:** 将点分格式的域名 (例如 "google.com") 转换为网络字节流格式 (用于 DNS 查询)。
   - **区别:** `DottedNameToNetworkWithValidation` 会进行更严格的域名格式验证，例如检查是否包含非法字符。
   - **假设输入与输出:**
     - **输入:** `"www.example.com"`，`require_valid_internet_hostname=true`
     - **输出:** `Optional(ToBytes("\003www\007example\003com"))` (一个包含网络字节流的 `std::vector<uint8_t>`，其中每个域名前有一个表示长度的字节)
     - **输入:** `"www..example.com"`，`require_valid_internet_hostname=true`
     - **输出:** `std::nullopt` (因为包含连续的点，域名格式无效)
   - **与 JavaScript 的关系:** JavaScript 本身不直接处理 DNS 网络字节流。但是，当 JavaScript 代码（例如通过 `fetch` API 或 `XMLHttpRequest`）发起网络请求时，浏览器底层会使用这些函数将域名转换为网络格式进行 DNS 查询。

2. **`NetworkToDottedName`**:
   - **功能:** 将网络字节流格式的域名转换回点分格式的域名。
   - **假设输入与输出:**
     - **输入:**  `base::as_byte_span("\003www\007example\003com\0")`
     - **输出:** `Optional(Eq("www.example.com"))`
     - **输入:** `base::as_byte_span("\003www\007example")` (缺少结尾的 `\0`)， `require_complete=true`
     - **输出:** `std::nullopt` (因为要求完整，但输入未以 `\0` 结尾)
   - **与 JavaScript 的关系:** 同样，JavaScript 不直接操作网络字节流，但浏览器在接收到 DNS 响应后，可能使用类似的逻辑将网络格式的域名转换回 JavaScript 可以处理的字符串格式。

3. **`IsValidDnsName` 和 `IsValidDnsRecordName`**:
   - **功能:** 检查给定的字符串是否是有效的 DNS 名称或 DNS 记录名称。`IsValidDnsRecordName` 的限制更严格，例如不允许包含下划线 `_` 或百分号 `%`。
   - **假设输入与输出:**
     - **输入:** `"example.com"`
     - **输出:** `true` (对于 `IsValidDnsName` 和 `IsValidDnsRecordName`)
     - **输入:** `"_example.com"`
     - **输出:** `true` (对于 `IsValidDnsName`)，`false` (对于 `IsValidDnsRecordName`)
   - **与 JavaScript 的关系:** 当 JavaScript 代码需要验证用户输入的域名或从 API 获取的域名时，可以使用正则表达式或其他字符串处理方法进行验证，其背后的逻辑与这些 C++ 函数类似。例如，判断一个字符串是否符合域名规范。

4. **`UrlCanonicalizeNameIfAble`**:
   - **功能:** 将域名规范化，例如转换为小写，处理国际化域名 (IDN) 到 Punycode 的转换。
   - **假设输入与输出:**
     - **输入:** `"GOOGLE.com"`
     - **输出:** `"google.com"`
     - **输入:** `"göogle.com"` (包含 Unicode 字符)
     - **输出:** `"xn--oogle-zwa.com"` (Punycode 编码)
   - **与 JavaScript 的关系:** JavaScript 的 `URL` API 或一些字符串处理库也提供了域名规范化的功能。例如，`new URL('HTTP://GOOGLE.com').hostname` 会返回 `"google.com"`。

5. **`ReadU8LengthPrefixed` 和 `ReadU16LengthPrefixed`**:
   - **功能:** 从字节流中读取长度前缀的数据。这是一种常见的网络协议数据解析方式。
   - **假设输入与输出:**
     - **输入:** 字节数组 `{'b', '4', 3, 'a', 'b', 'c', 'd'}`，使用 `ReadU8LengthPrefixed` 从索引 2 开始读取。
     - **输出:** 读取到长度为 3 的数据 `{'a', 'b', 'c'}`。
   - **与 JavaScript 的关系:** 在 JavaScript 中处理二进制数据（例如通过 `ArrayBuffer` 和 `DataView`）时，也需要类似的逻辑来解析长度前缀的数据。

**用户或编程常见的使用错误举例:**

1. **在 C++ 中使用 `DottedNameToNetworkWithValidation` 但传入了包含非法字符的域名:**
   - **假设输入:** `"my_domain.com"`
   - **预期结果:** `DottedNameToNetworkWithValidation` 返回 `std::nullopt`，因为下划线 `_` 在严格的互联网主机名中是不允许的。
   - **错误后果:**  如果代码没有正确处理 `std::nullopt` 的情况，可能会导致程序崩溃或产生意想不到的行为。

2. **在 C++ 中使用 `NetworkToDottedName` 处理不完整的网络字节流:**
   - **假设输入:** `base::as_byte_span("\003www\007example")` (缺少结尾的 `\0`)
   - **预期结果:** 如果 `require_complete` 为 `true`，`NetworkToDottedName` 返回 `std::nullopt`。
   - **错误后果:** 如果代码期望返回一个有效的域名字符串，但实际得到 `std::nullopt`，可能会导致程序逻辑错误。

3. **在 JavaScript 中错误地认为包含下划线的域名总是无效的:**
   - **用户操作:** 用户在网页表单中输入了域名 `my_domain.com`。
   - **JavaScript 验证:** 一些过于严格的 JavaScript 验证逻辑可能会错误地将 `my_domain.com` 标记为无效，因为它包含下划线。
   - **与 C++ 的联系:**  尽管 `IsValidDnsRecordName` 会认为包含下划线的域名无效，但 `IsValidDnsName` 认为有效。这说明域名验证的严格程度取决于具体的应用场景。

**用户操作如何一步步到达这里，作为调试线索:**

假设用户在 Chrome 浏览器中访问 `http://my_domain.com`：

1. **用户输入 URL:** 用户在浏览器的地址栏中输入 `http://my_domain.com` 并按下回车键。
2. **URL 解析:** 浏览器解析输入的 URL，提取出主机名 `my_domain.com`。
3. **DNS 查询:**
   - 浏览器需要将主机名 `my_domain.com` 解析为 IP 地址。
   - 这涉及到 DNS 查询过程。
   - **在 Chromium 的网络栈中，`net/dns/dns_names_util.cc` 中的 `DottedNameToNetwork` 或 `DottedNameToNetworkWithValidation` 函数可能会被调用，将 `my_domain.com` 转换为网络字节流格式，以便发送 DNS 查询请求。**
4. **发送 DNS 请求:** 构造 DNS 查询数据包并发送到 DNS 服务器。
5. **接收 DNS 响应:** 从 DNS 服务器接收到包含 IP 地址的响应。
6. **连接服务器:** 浏览器使用解析得到的 IP 地址与服务器建立 TCP 连接。
7. **发送 HTTP 请求:** 浏览器发送 HTTP 请求到服务器。
8. **接收 HTTP 响应:** 服务器返回 HTTP 响应，浏览器渲染页面。

**作为调试线索，如果出现 DNS 解析相关的问题，例如无法解析域名或解析错误，开发者可能会查看以下内容:**

- **检查用户输入的域名是否有效:** 可以使用 `IsValidDnsName` 或 `IsValidDnsRecordName` 的逻辑来验证。
- **查看域名到网络字节流的转换过程:**  如果怀疑 `DottedNameToNetwork` 存在问题，可以断点调试该函数，查看输入和输出是否符合预期。
- **查看网络字节流到域名的转换过程:** 如果怀疑 DNS 响应处理存在问题，可以断点调试 `NetworkToDottedName` 函数。
- **检查域名规范化过程:** 如果涉及国际化域名，可以查看 `UrlCanonicalizeNameIfAble` 的行为。

总而言之，`net/dns/dns_names_util_unittest.cc` 这个文件通过一系列的单元测试，确保了 Chromium 网络栈中 DNS 名称处理工具函数的正确性和健壮性，这些函数在浏览器进行网络请求时扮演着至关重要的角色。

Prompt: 
```
这是目录为net/dns/dns_names_util_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/dns/dns_names_util.h"

#include <climits>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "base/containers/span_reader.h"
#include "base/numerics/safe_conversions.h"
#include "net/dns/dns_util.h"
#include "net/dns/public/dns_protocol.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net::dns_names_util {
namespace {

using ::testing::Eq;
using ::testing::Optional;

// ToBytes converts a char* to a std::vector<uint8_t> and includes the
// terminating NUL in the result.
std::vector<uint8_t> ToBytes(const char* in) {
  size_t size = strlen(in) + 1;
  std::vector<uint8_t> out(size, 0);
  memcpy(out.data(), in, size);
  return out;
}

TEST(DnsNamesUtilTest, DottedNameToNetworkWithValidation) {
  EXPECT_THAT(
      DottedNameToNetwork("com", /*require_valid_internet_hostname=*/true),
      Optional(ToBytes("\003com")));
  EXPECT_THAT(DottedNameToNetwork("google.com",
                                  /*require_valid_internet_hostname=*/true),
              Optional(ToBytes("\x006google\003com")));
  EXPECT_THAT(DottedNameToNetwork("www.google.com",
                                  /*require_valid_internet_hostname=*/true),
              Optional(ToBytes("\003www\006google\003com")));
}

TEST(DnsNamesUtilTest, DottedNameToNetwork) {
  EXPECT_THAT(
      DottedNameToNetwork("com", /*require_valid_internet_hostname=*/false),
      Optional(ToBytes("\003com")));
  EXPECT_THAT(DottedNameToNetwork("google.com",
                                  /*require_valid_internet_hostname=*/false),
              Optional(ToBytes("\x006google\003com")));
  EXPECT_THAT(DottedNameToNetwork("www.google.com",
                                  /*require_valid_internet_hostname=*/false),
              Optional(ToBytes("\003www\006google\003com")));
}

TEST(DnsNamesUtilTest, DottedNameToNetworkWithValidationRejectsEmptyLabels) {
  EXPECT_FALSE(DottedNameToNetwork("", /*require_valid_internet_hostname=*/true)
                   .has_value());
  EXPECT_FALSE(
      DottedNameToNetwork(".", /*require_valid_internet_hostname=*/true)
          .has_value());
  EXPECT_FALSE(
      DottedNameToNetwork("..", /*require_valid_internet_hostname=*/true)
          .has_value());
  EXPECT_FALSE(DottedNameToNetwork(".google.com",
                                   /*require_valid_internet_hostname=*/true)
                   .has_value());
  EXPECT_FALSE(DottedNameToNetwork("www..google.com",
                                   /*require_valid_internet_hostname=*/true)
                   .has_value());
}

TEST(DnsNamesUtilTest, DottedNameToNetworkRejectsEmptyLabels) {
  EXPECT_FALSE(
      DottedNameToNetwork("", /*require_valid_internet_hostname=*/false)
          .has_value());
  EXPECT_FALSE(
      DottedNameToNetwork(".", /*require_valid_internet_hostname=*/false)
          .has_value());
  EXPECT_FALSE(
      DottedNameToNetwork("..", /*require_valid_internet_hostname=*/false)
          .has_value());
  EXPECT_FALSE(DottedNameToNetwork(".google.com",
                                   /*require_valid_internet_hostname=*/false)
                   .has_value());
  EXPECT_FALSE(DottedNameToNetwork("www..google.com",
                                   /*require_valid_internet_hostname=*/false)
                   .has_value());
}

TEST(DnsNamesUtilTest,
     DottedNameToNetworkWithValidationAcceptsEmptyLabelAtEnd) {
  EXPECT_THAT(DottedNameToNetwork("www.google.com.",
                                  /*require_valid_internet_hostname=*/true),
              Optional(ToBytes("\003www\006google\003com")));
}

TEST(DnsNamesUtilTest, DottedNameToNetworkAcceptsEmptyLabelAtEnd) {
  EXPECT_THAT(DottedNameToNetwork("www.google.com.",
                                  /*require_valid_internet_hostname=*/false),
              Optional(ToBytes("\003www\006google\003com")));
}

TEST(DnsNamesUtilTest, DottedNameToNetworkWithValidationAllowsLongNames) {
  // Label is 63 chars: still valid
  EXPECT_THAT(
      DottedNameToNetwork(
          "z23456789a123456789a123456789a123456789a123456789a123456789a123",
          /*require_valid_internet_hostname=*/true),
      Optional(ToBytes("\077z23456789a123456789a123456789a123456789a123456"
                       "789a123456789a123")));
  EXPECT_THAT(
      DottedNameToNetwork(
          "z23456789a123456789a123456789a123456789a123456789a123456789a123.",
          /*require_valid_internet_hostname=*/true),
      Optional(ToBytes("\077z23456789a123456789a123456789a123456789a123456"
                       "789a123456789a123")));

  // 253 characters in the name: still valid
  EXPECT_THAT(
      DottedNameToNetwork(
          "abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi."
          "abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi."
          "abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi."
          "abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi."
          "abcdefghi.abc",
          /*require_valid_internet_hostname=*/true),
      Optional(ToBytes("\011abcdefghi\011abcdefghi\011abcdefghi\011abcdefghi"
                       "\011abcdefghi\011abcdefghi\011abcdefghi\011abcdefghi"
                       "\011abcdefghi\011abcdefghi\011abcdefghi\011abcdefghi"
                       "\011abcdefghi\011abcdefghi\011abcdefghi\011abcdefghi"
                       "\011abcdefghi\011abcdefghi\011abcdefghi\011abcdefghi"
                       "\011abcdefghi\011abcdefghi\011abcdefghi\011abcdefghi"
                       "\011abcdefghi\003abc")));

  // 253 characters in the name plus final dot: still valid
  EXPECT_THAT(
      DottedNameToNetwork(
          "abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi."
          "abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi."
          "abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi."
          "abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi."
          "abcdefghi.abc.",
          /*require_valid_internet_hostname=*/true),
      Optional(ToBytes("\011abcdefghi\011abcdefghi\011abcdefghi\011abcdefghi"
                       "\011abcdefghi\011abcdefghi\011abcdefghi\011abcdefghi"
                       "\011abcdefghi\011abcdefghi\011abcdefghi\011abcdefghi"
                       "\011abcdefghi\011abcdefghi\011abcdefghi\011abcdefghi"
                       "\011abcdefghi\011abcdefghi\011abcdefghi\011abcdefghi"
                       "\011abcdefghi\011abcdefghi\011abcdefghi\011abcdefghi"
                       "\011abcdefghi\003abc")));
}

TEST(DnsNamesUtilTest, DottedNameToNetworkAllowsLongNames) {
  // Label is 63 chars: still valid
  EXPECT_THAT(
      DottedNameToNetwork(
          "z23456789a123456789a123456789a123456789a123456789a123456789a123",
          /*require_valid_internet_hostname=*/false),
      Optional(ToBytes("\077z23456789a123456789a123456789a123456789a123456"
                       "789a123456789a123")));
  // Label is 63 chars: still valid
  EXPECT_THAT(
      DottedNameToNetwork(
          "z23456789a123456789a123456789a123456789a123456789a123456789a123.",
          /*require_valid_internet_hostname=*/false),
      Optional(ToBytes("\077z23456789a123456789a123456789a123456789a123456"
                       "789a123456789a123")));

  // 253 characters in the name: still valid
  EXPECT_THAT(
      DottedNameToNetwork(
          "abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi."
          "abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi."
          "abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi."
          "abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi."
          "abcdefghi.abc",
          /*require_valid_internet_hostname=*/false),
      Optional(ToBytes("\011abcdefghi\011abcdefghi\011abcdefghi\011abcdefghi"
                       "\011abcdefghi\011abcdefghi\011abcdefghi\011abcdefghi"
                       "\011abcdefghi\011abcdefghi\011abcdefghi\011abcdefghi"
                       "\011abcdefghi\011abcdefghi\011abcdefghi\011abcdefghi"
                       "\011abcdefghi\011abcdefghi\011abcdefghi\011abcdefghi"
                       "\011abcdefghi\011abcdefghi\011abcdefghi\011abcdefghi"
                       "\011abcdefghi\003abc")));

  // 253 characters in the name plus final dot: still valid
  EXPECT_THAT(
      DottedNameToNetwork(
          "abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi."
          "abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi."
          "abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi."
          "abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi."
          "abcdefghi.abc.",
          /*require_valid_internet_hostname=*/false),
      Optional(ToBytes("\011abcdefghi\011abcdefghi\011abcdefghi\011abcdefghi"
                       "\011abcdefghi\011abcdefghi\011abcdefghi\011abcdefghi"
                       "\011abcdefghi\011abcdefghi\011abcdefghi\011abcdefghi"
                       "\011abcdefghi\011abcdefghi\011abcdefghi\011abcdefghi"
                       "\011abcdefghi\011abcdefghi\011abcdefghi\011abcdefghi"
                       "\011abcdefghi\011abcdefghi\011abcdefghi\011abcdefghi"
                       "\011abcdefghi\003abc")));
}

TEST(DnsNamesUtilTest, DottedNameToNetworkWithValidationRejectsTooLongNames) {
  // Label is too long: invalid
  EXPECT_FALSE(
      DottedNameToNetwork(
          "123456789a123456789a123456789a123456789a123456789a123456789a1234",
          /*require_valid_internet_hostname=*/true)
          .has_value());
  EXPECT_FALSE(
      DottedNameToNetwork(
          "123456789a123456789a123456789a123456789a123456789a123456789a1234.",
          /*require_valid_internet_hostname=*/true)
          .has_value());

  // 254 characters in the name: invalid
  EXPECT_FALSE(
      DottedNameToNetwork(
          "123456789.123456789.123456789.123456789.123456789.123456789."
          "123456789.123456789.123456789.123456789.123456789.123456789."
          "123456789.123456789.123456789.123456789.123456789.123456789."
          "123456789.123456789.123456789.123456789.123456789.123456789."
          "123456789.1234",
          /*require_valid_internet_hostname=*/true)
          .has_value());
  EXPECT_FALSE(
      DottedNameToNetwork(
          "123456789.123456789.123456789.123456789.123456789.123456789."
          "123456789.123456789.123456789.123456789.123456789.123456789."
          "123456789.123456789.123456789.123456789.123456789.123456789."
          "123456789.123456789.123456789.123456789.123456789.123456789."
          "123456789.1234.",
          /*require_valid_internet_hostname=*/true)
          .has_value());

  // 255 characters in the name: invalid before even trying to add a final
  // zero-length termination
  EXPECT_FALSE(
      DottedNameToNetwork(
          "123456789.123456789.123456789.123456789.123456789.123456789."
          "123456789.123456789.123456789.123456789.123456789.123456789."
          "123456789.123456789.123456789.123456789.123456789.123456789."
          "123456789.123456789.123456789.123456789.123456789.123456789."
          "123456789.12345",
          /*require_valid_internet_hostname=*/true)
          .has_value());
  EXPECT_FALSE(
      DottedNameToNetwork(
          "123456789.123456789.123456789.123456789.123456789.123456789."
          "123456789.123456789.123456789.123456789.123456789.123456789."
          "123456789.123456789.123456789.123456789.123456789.123456789."
          "123456789.123456789.123456789.123456789.123456789.123456789."
          "123456789.12345.",
          /*require_valid_internet_hostname=*/true)
          .has_value());
}

TEST(DnsNamesUtilTest, DottedNameToNetworkRejectsTooLongNames) {
  // Label is too long: invalid
  EXPECT_FALSE(
      DottedNameToNetwork(
          "123456789a123456789a123456789a123456789a123456789a123456789a1234",
          /*require_valid_internet_hostname=*/false)
          .has_value());
  EXPECT_FALSE(
      DottedNameToNetwork(
          "123456789a123456789a123456789a123456789a123456789a123456789a1234.",
          /*require_valid_internet_hostname=*/false)
          .has_value());

  // 254 characters in the name: invalid
  EXPECT_FALSE(
      DottedNameToNetwork(
          "123456789.123456789.123456789.123456789.123456789.123456789."
          "123456789.123456789.123456789.123456789.123456789.123456789."
          "123456789.123456789.123456789.123456789.123456789.123456789."
          "123456789.123456789.123456789.123456789.123456789.123456789."
          "123456789.1234",
          /*require_valid_internet_hostname=*/false)
          .has_value());
  EXPECT_FALSE(
      DottedNameToNetwork(
          "123456789.123456789.123456789.123456789.123456789.123456789."
          "123456789.123456789.123456789.123456789.123456789.123456789."
          "123456789.123456789.123456789.123456789.123456789.123456789."
          "123456789.123456789.123456789.123456789.123456789.123456789."
          "123456789.1234.",
          /*require_valid_internet_hostname=*/false)
          .has_value());

  // 255 characters in the name: invalid before even trying to add a final
  // zero-length termination
  EXPECT_FALSE(
      DottedNameToNetwork(
          "123456789.123456789.123456789.123456789.123456789.123456789."
          "123456789.123456789.123456789.123456789.123456789.123456789."
          "123456789.123456789.123456789.123456789.123456789.123456789."
          "123456789.123456789.123456789.123456789.123456789.123456789."
          "123456789.12345",
          /*require_valid_internet_hostname=*/false)
          .has_value());
  EXPECT_FALSE(
      DottedNameToNetwork(
          "123456789.123456789.123456789.123456789.123456789.123456789."
          "123456789.123456789.123456789.123456789.123456789.123456789."
          "123456789.123456789.123456789.123456789.123456789.123456789."
          "123456789.123456789.123456789.123456789.123456789.123456789."
          "123456789.12345.",
          /*require_valid_internet_hostname=*/false)
          .has_value());
}

TEST(DnsNamesUtilTest,
     DottedNameToNetworkWithValidationRejectsRestrictedCharacters) {
  EXPECT_FALSE(DottedNameToNetwork("foo,bar.com",
                                   /*require_valid_internet_hostname=*/true)
                   .has_value());
  EXPECT_FALSE(DottedNameToNetwork("_ipp._tcp.local.foo printer (bar)",
                                   /*require_valid_internet_hostname=*/true)
                   .has_value());
}

TEST(DnsNamesUtilTest, DottedNameToNetworkAcceptsRestrictedCharacters) {
  EXPECT_THAT(DottedNameToNetwork("foo,bar.com",
                                  /*require_valid_internet_hostname=*/false),
              Optional(ToBytes("\007foo,bar\003com")));

  EXPECT_THAT(
      DottedNameToNetwork("_ipp._tcp.local.foo printer (bar)",
                          /*require_valid_internet_hostname=*/false),
      Optional(ToBytes("\004_ipp\004_tcp\005local\021foo printer (bar)")));
}

TEST(DnsNamesUtilTest, NetworkToDottedNameAdvancesReader) {
  {
    auto reader = base::SpanReader(base::byte_span_from_cstring("\003com"));
    EXPECT_THAT(NetworkToDottedName(reader), Optional(Eq("com")));
    EXPECT_EQ(reader.remaining(), 0u);
  }
  {
    auto reader =
        base::SpanReader(base::byte_span_from_cstring("\003com\0ZZZ"));
    EXPECT_THAT(NetworkToDottedName(reader), Optional(Eq("com")));
    EXPECT_EQ(reader.remaining(), 3u);
  }
}

TEST(DnsNamesUtilTest, NetworkToDottedNameShouldHandleSimpleNames) {
  std::string dns_name = "\003foo";
  EXPECT_THAT(NetworkToDottedName(base::as_byte_span(dns_name)),
              Optional(Eq("foo")));

  dns_name += "\003bar";
  EXPECT_THAT(NetworkToDottedName(base::as_byte_span(dns_name)),
              Optional(Eq("foo.bar")));

  dns_name += "\002uk";
  EXPECT_THAT(NetworkToDottedName(base::as_byte_span(dns_name)),
              Optional(Eq("foo.bar.uk")));

  dns_name += '\0';
  EXPECT_THAT(NetworkToDottedName(base::as_byte_span(dns_name)),
              Optional(Eq("foo.bar.uk")));
}

TEST(DnsNamesUtilTest, NetworkToDottedNameShouldHandleEmpty) {
  std::string dns_name;

  EXPECT_THAT(NetworkToDottedName(base::as_byte_span(dns_name)),
              Optional(Eq("")));

  dns_name += '\0';
  EXPECT_THAT(NetworkToDottedName(base::as_byte_span(dns_name)),
              Optional(Eq("")));
}

TEST(DnsNamesUtilTest, NetworkToDottedNameShouldRejectEmptyIncomplete) {
  std::string dns_name;

  EXPECT_THAT(NetworkToDottedName(base::as_byte_span(dns_name),
                                  false /* require_complete */),
              Optional(Eq("")));

  EXPECT_EQ(NetworkToDottedName(base::as_byte_span(dns_name),
                                true /* require_complete */),
            std::nullopt);
}

// Test `require_complete` functionality given an input with terminating zero-
// length label.
TEST(DnsNamesUtilTest, NetworkToDottedNameComplete) {
  std::string dns_name("\003foo\004test");
  dns_name += '\0';

  EXPECT_THAT(NetworkToDottedName(base::as_byte_span(dns_name),
                                  false /* require_complete */),
              Optional(Eq("foo.test")));

  EXPECT_THAT(NetworkToDottedName(base::as_byte_span(dns_name),
                                  true /* require_complete */),
              Optional(Eq("foo.test")));
}

// Test `require_complete` functionality given an input without terminating
// zero-length label.
TEST(DnsNamesUtilTest, NetworkToDottedNameNotComplete) {
  std::string dns_name("\003boo\004test");

  EXPECT_THAT(NetworkToDottedName(base::as_byte_span(dns_name),
                                  false /* require_complete */),
              Optional(Eq("boo.test")));

  EXPECT_EQ(NetworkToDottedName(base::as_byte_span(dns_name),
                                true /* require_complete */),
            std::nullopt);
}

TEST(DnsNamesUtilTest,
     NetworkToDottedNameShouldRejectEmptyWhenRequiringComplete) {
  std::string dns_name;

  EXPECT_THAT(NetworkToDottedName(base::as_byte_span(dns_name),
                                  false /* require_complete */),
              Optional(Eq("")));

  EXPECT_EQ(NetworkToDottedName(base::as_byte_span(dns_name),
                                true /* require_complete */),
            std::nullopt);

  dns_name += '\0';
  EXPECT_THAT(NetworkToDottedName(base::as_byte_span(dns_name),
                                  true /* require_complete */),
              Optional(Eq("")));
}

TEST(DnsNamesUtilTest, NetworkToDottedNameShouldRejectCompression) {
  std::string dns_name = CreateNamePointer(152);

  EXPECT_EQ(NetworkToDottedName(base::as_byte_span(dns_name)), std::nullopt);

  dns_name = "\005hello";
  dns_name += CreateNamePointer(152);

  EXPECT_EQ(NetworkToDottedName(base::as_byte_span(dns_name)), std::nullopt);
}

// Test that extra input past the terminating zero-length label are ignored.
TEST(DnsNamesUtilTest, NetworkToDottedNameShouldHandleExcessInput) {
  std::string dns_name("\004cool\004name\004test");
  dns_name += '\0';
  dns_name += "blargh!";

  EXPECT_THAT(NetworkToDottedName(base::as_byte_span(dns_name)),
              Optional(Eq("cool.name.test")));

  dns_name = "\002hi";
  dns_name += '\0';
  dns_name += "goodbye";

  EXPECT_THAT(NetworkToDottedName(base::as_byte_span(dns_name)),
              Optional(Eq("hi")));
}

// Test that input is malformed if it ends mid label.
TEST(DnsNamesUtilTest, NetworkToDottedNameShouldRejectTruncatedNames) {
  std::string dns_name = "\07cheese";
  EXPECT_EQ(NetworkToDottedName(base::as_byte_span(dns_name)), std::nullopt);

  dns_name = "\006cheesy\05test";
  EXPECT_EQ(NetworkToDottedName(base::as_byte_span(dns_name)), std::nullopt);
}

TEST(DnsNamesUtilTest, NetworkToDottedNameShouldHandleLongSingleLabel) {
  std::string dns_name(1, static_cast<char>(dns_protocol::kMaxLabelLength));
  for (int i = 0; i < dns_protocol::kMaxLabelLength; ++i) {
    dns_name += 'a';
  }

  EXPECT_NE(NetworkToDottedName(base::as_byte_span(dns_name)), std::nullopt);
}

TEST(DnsNamesUtilTest, NetworkToDottedNameShouldHandleLongSecondLabel) {
  std::string dns_name("\003foo");
  dns_name += static_cast<char>(dns_protocol::kMaxLabelLength);
  for (int i = 0; i < dns_protocol::kMaxLabelLength; ++i) {
    dns_name += 'a';
  }

  EXPECT_NE(NetworkToDottedName(base::as_byte_span(dns_name)), std::nullopt);
}

TEST(DnsNamesUtilTest, NetworkToDottedNameShouldRejectTooLongSingleLabel) {
  std::string dns_name(1, static_cast<char>(dns_protocol::kMaxLabelLength));
  for (int i = 0; i < dns_protocol::kMaxLabelLength + 1; ++i) {
    dns_name += 'a';
  }

  EXPECT_EQ(NetworkToDottedName(base::as_byte_span(dns_name)), std::nullopt);
}

TEST(DnsNamesUtilTest, NetworkToDottedNameShouldRejectTooLongSecondLabel) {
  std::string dns_name("\003foo");
  dns_name += static_cast<char>(dns_protocol::kMaxLabelLength);
  for (int i = 0; i < dns_protocol::kMaxLabelLength + 1; ++i) {
    dns_name += 'a';
  }

  EXPECT_EQ(NetworkToDottedName(base::as_byte_span(dns_name)), std::nullopt);
}

#if CHAR_MIN < 0
TEST(DnsNamesUtilTest, NetworkToDottedNameShouldRejectCharMinLabels) {
  ASSERT_GT(static_cast<uint8_t>(CHAR_MIN), dns_protocol::kMaxLabelLength);

  std::string dns_name;
  dns_name += base::checked_cast<char>(CHAR_MIN);

  // Wherever possible, make the name otherwise valid.
  if (static_cast<uint8_t>(CHAR_MIN) < UINT8_MAX) {
    for (uint8_t i = 0; i < static_cast<uint8_t>(CHAR_MIN); ++i) {
      dns_name += 'a';
    }
  }

  EXPECT_EQ(NetworkToDottedName(base::as_byte_span(dns_name)), std::nullopt);
}
#endif  // if CHAR_MIN < 0

TEST(DnsNamesUtilTest, NetworkToDottedNameShouldHandleLongName) {
  std::string dns_name;
  for (int i = 0; i < dns_protocol::kMaxNameLength;
       i += (dns_protocol::kMaxLabelLength + 1)) {
    int label_size = std::min(dns_protocol::kMaxNameLength - 1 - i,
                              dns_protocol::kMaxLabelLength);
    dns_name += static_cast<char>(label_size);
    for (int j = 0; j < label_size; ++j) {
      dns_name += 'a';
    }
  }
  ASSERT_EQ(dns_name.size(), static_cast<size_t>(dns_protocol::kMaxNameLength));

  EXPECT_NE(NetworkToDottedName(base::as_byte_span(dns_name)), std::nullopt);
}

TEST(DnsNamesUtilTest, NetworkToDottedNameShouldRejectTooLongName) {
  std::string dns_name;
  for (int i = 0; i < dns_protocol::kMaxNameLength + 1;
       i += (dns_protocol::kMaxLabelLength + 1)) {
    int label_size = std::min(dns_protocol::kMaxNameLength - i,
                              dns_protocol::kMaxLabelLength);
    dns_name += static_cast<char>(label_size);
    for (int j = 0; j < label_size; ++j) {
      dns_name += 'a';
    }
  }
  ASSERT_EQ(dns_name.size(),
            static_cast<size_t>(dns_protocol::kMaxNameLength + 1));

  EXPECT_EQ(NetworkToDottedName(base::as_byte_span(dns_name)), std::nullopt);
}

TEST(DnsNamesUtilTest, NetworkToDottedNameShouldHandleLongCompleteName) {
  std::string dns_name;
  for (int i = 0; i < dns_protocol::kMaxNameLength;
       i += (dns_protocol::kMaxLabelLength + 1)) {
    int label_size = std::min(dns_protocol::kMaxNameLength - 1 - i,
                              dns_protocol::kMaxLabelLength);
    dns_name += static_cast<char>(label_size);
    for (int j = 0; j < label_size; ++j) {
      dns_name += 'a';
    }
  }
  dns_name += '\0';
  ASSERT_EQ(dns_name.size(),
            static_cast<size_t>(dns_protocol::kMaxNameLength + 1));

  EXPECT_NE(NetworkToDottedName(base::as_byte_span(dns_name)), std::nullopt);
}

TEST(DnsNamesUtilTest, NetworkToDottedNameShouldRejectTooLongCompleteName) {
  std::string dns_name;
  for (int i = 0; i < dns_protocol::kMaxNameLength + 1;
       i += (dns_protocol::kMaxLabelLength + 1)) {
    int label_size = std::min(dns_protocol::kMaxNameLength - i,
                              dns_protocol::kMaxLabelLength);
    dns_name += static_cast<char>(label_size);
    for (int j = 0; j < label_size; ++j) {
      dns_name += 'a';
    }
  }
  dns_name += '\0';
  ASSERT_EQ(dns_name.size(),
            static_cast<size_t>(dns_protocol::kMaxNameLength + 2));

  EXPECT_EQ(NetworkToDottedName(base::as_byte_span(dns_name)), std::nullopt);
}

TEST(DnsNamesUtilTest, ValidDnsNames) {
  constexpr std::string_view kGoodHostnames[] = {
      "www.noodles.blorg",   "1www.noodles.blorg",    "www.2noodles.blorg",
      "www.n--oodles.blorg", "www.noodl_es.blorg",    "www.no-_odles.blorg",
      "www_.noodles.blorg",  "www.noodles.blorg.",    "_privet._tcp.local",
      "%20%20noodles.blorg", "noo dles.blorg ",       "noo dles_ipp._tcp.local",
      "www.nood(les).blorg", "noo dl(es)._tcp.local",
  };

  for (std::string_view good_hostname : kGoodHostnames) {
    EXPECT_TRUE(IsValidDnsName(good_hostname));
    EXPECT_TRUE(IsValidDnsRecordName(good_hostname));
  }
}

TEST(DnsNamesUtilTest, EmptyNotValidDnsName) {
  EXPECT_FALSE(IsValidDnsName(""));
  EXPECT_FALSE(IsValidDnsRecordName(""));
}

TEST(DnsNamesUtilTest, EmptyLabelNotValidDnsName) {
  EXPECT_FALSE(IsValidDnsName("www..test"));
  EXPECT_FALSE(IsValidDnsName(".foo.test"));

  EXPECT_FALSE(IsValidDnsRecordName("www..test"));
  EXPECT_FALSE(IsValidDnsRecordName(".foo.test"));
}

TEST(DnsNameUtilTest, LongLabelsInValidDnsNames) {
  EXPECT_TRUE(IsValidDnsName(
      "z23456789a123456789a123456789a123456789a123456789a123456789a123"));
  EXPECT_TRUE(IsValidDnsName(
      "z23456789a123456789a123456789a123456789a123456789a123456789a123."));

  EXPECT_TRUE(IsValidDnsRecordName(
      "z23456789a123456789a123456789a123456789a123456789a123456789a123"));
  EXPECT_TRUE(IsValidDnsRecordName(
      "z23456789a123456789a123456789a123456789a123456789a123456789a123."));
}

TEST(DnsNameUtilTest, TooLongLabelsInInvalidDnsNames) {
  EXPECT_FALSE(IsValidDnsName(
      "123456789a123456789a123456789a123456789a123456789a123456789a1234"));
  EXPECT_FALSE(IsValidDnsName(
      "z23456789a123456789a123456789a123456789a123456789a123456789a1234."));

  EXPECT_FALSE(IsValidDnsRecordName(
      "z23456789a123456789a123456789a123456789a123456789a123456789a1234"));
  EXPECT_FALSE(IsValidDnsRecordName(
      "z23456789a123456789a123456789a123456789a123456789a123456789a1234."));
}

TEST(DnsNameUtilTest, LongValidDnsNames) {
  EXPECT_TRUE(IsValidDnsName(
      "abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi."
      "abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi."
      "abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi."
      "abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi."
      "abcdefghi.abc"));
  EXPECT_TRUE(IsValidDnsName(
      "abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi."
      "abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi."
      "abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi."
      "abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi."
      "abcdefghi.abc."));

  EXPECT_TRUE(IsValidDnsRecordName(
      "abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi."
      "abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi."
      "abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi."
      "abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi."
      "abcdefghi.abc"));
  EXPECT_TRUE(IsValidDnsRecordName(
      "abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi."
      "abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi."
      "abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi."
      "abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi."
      "abcdefghi.abc."));
}

TEST(DnsNameUtilTest, TooLongInalidDnsNames) {
  EXPECT_FALSE(IsValidDnsName(
      "abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi."
      "abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi."
      "abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi."
      "abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi."
      "abcdefghi.abcd"));
  EXPECT_FALSE(IsValidDnsName(
      "abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi."
      "abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi."
      "abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi."
      "abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi."
      "abcdefghi.abcd."));

  EXPECT_FALSE(IsValidDnsRecordName(
      "abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi."
      "abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi."
      "abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi."
      "abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi."
      "abcdefghi.abcd"));
  EXPECT_FALSE(IsValidDnsRecordName(
      "abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi."
      "abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi."
      "abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi."
      "abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi."
      "abcdefghi.abcd."));
}

TEST(DnsNameUtilTest, LocalhostNotValidDnsRecordName) {
  EXPECT_TRUE(IsValidDnsName("localhost"));
  EXPECT_FALSE(IsValidDnsRecordName("localhost"));
}

TEST(DnsNameUtilTest, IpAddressNotValidDnsRecordName) {
  EXPECT_TRUE(IsValidDnsName("1.2.3.4"));
  EXPECT_FALSE(IsValidDnsRecordName("1.2.3.4"));

  EXPECT_TRUE(IsValidDnsName("[2001:4860:4860::8888]"));
  EXPECT_FALSE(IsValidDnsRecordName("[2001:4860:4860::8888]"));

  EXPECT_TRUE(IsValidDnsName("2001:4860:4860::8888"));
  EXPECT_FALSE(IsValidDnsRecordName("2001:4860:4860::8888"));
}

TEST(DnsUtilTest, CanonicalizeNames) {
  EXPECT_EQ(UrlCanonicalizeNameIfAble("GOOGLE.test"), "google.test");

  EXPECT_EQ(UrlCanonicalizeNameIfAble("g{oo}gle.test"), "g{oo}gle.test");
  EXPECT_EQ(UrlCanonicalizeNameIfAble("G{OO}GLE.test"), "g{oo}gle.test");

  // g�gle.test
  EXPECT_EQ(UrlCanonicalizeNameIfAble("g\u00FCgle.test"), "xn--ggle-0ra.test");
  EXPECT_EQ(UrlCanonicalizeNameIfAble("G\u00fcGLE.test"), "xn--ggle-0ra.test");
}

TEST(DnsUtilTest, IgnoreUncanonicalizeableNames) {
  EXPECT_EQ(UrlCanonicalizeNameIfAble(""), "");

  // Forbidden domain code point.
  // https://url.spec.whatwg.org/#forbidden-domain-code-point
  EXPECT_EQ(UrlCanonicalizeNameIfAble("g<oo>gle.test"), "g<oo>gle.test");
  EXPECT_EQ(UrlCanonicalizeNameIfAble("G<OO>GLE.test"), "G<OO>GLE.test");

  // Invalid UTF8 character.
  EXPECT_EQ(UrlCanonicalizeNameIfAble("g\x00FCgle.test"), "g\x00fcgle.test");
  EXPECT_EQ(UrlCanonicalizeNameIfAble("G\x00fcGLE.test"), "G\x00fcGLE.test");

  // Disallowed ASCII character.
  EXPECT_EQ(UrlCanonicalizeNameIfAble("google\n.test"), "google\n.test");
  EXPECT_EQ(UrlCanonicalizeNameIfAble("GOOGLE\n.test"), "GOOGLE\n.test");
}

TEST(DnsNamesUtilTest, ReadU8LengthPrefixed) {
  const uint8_t kArray[] = {'b', '4', 3, 'a', 'b', 'c', 'd'};
  auto reader = base::SpanReader(base::span(kArray));
  EXPECT_TRUE(reader.Skip(2u));
  EXPECT_EQ(reader.remaining(), 5u);
  EXPECT_EQ(reader.num_read(), 2u);
  base::span<const uint8_t> s;
  EXPECT_TRUE(ReadU8LengthPrefixed(reader, &s));
  EXPECT_EQ(s, base::span(kArray).subspan(3u, 3u));
  EXPECT_EQ(reader.remaining(), 1u);
  EXPECT_EQ(reader.num_read(), 6u);
}

TEST(DnsNamesUtilTest, ReadU16LengthPrefixed) {
  const uint8_t kArray[] = {'b', '4', 0, 3, 'a', 'b', 'c', 'd'};
  auto reader = base::SpanReader(base::span(kArray));
  EXPECT_TRUE(reader.Skip(2u));
  EXPECT_EQ(reader.remaining(), 6u);
  EXPECT_EQ(reader.num_read(), 2u);
  base::span<const uint8_t> s;
  EXPECT_TRUE(ReadU16LengthPrefixed(reader, &s));
  EXPECT_EQ(s, base::span(kArray).subspan(4u, 3u));
  EXPECT_EQ(reader.remaining(), 1u);
  EXPECT_EQ(reader.num_read(), 7u);
}

}  // namespace
}  // namespace net::dns_names_util

"""

```