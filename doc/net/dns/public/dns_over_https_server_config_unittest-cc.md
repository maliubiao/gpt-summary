Response:
Let's break down the thought process for analyzing the provided C++ unittest file.

1. **Understand the Goal:** The request asks for the functionality of the given C++ file, its relation to JavaScript (if any), examples of logical reasoning, common usage errors, and how a user might end up triggering this code.

2. **Identify the Core Subject:** The file name `dns_over_https_server_config_unittest.cc` immediately tells us this code is related to testing the `DnsOverHttpsServerConfig` class. The `unittest.cc` suffix is a strong indicator of a unit test file.

3. **Scan for Key Elements:** Look for important keywords and patterns within the code:
    * `#include`:  Lists the dependencies. `DnsOverHttpsServerConfig.h` is the key header, revealing the class being tested. `gtest/gtest.h` and `gmock/gmock.h` confirm it's a Google Test-based unit test. `base/json/json_reader.h` suggests JSON parsing is involved.
    * `namespace net { namespace { ... } }`:  Indicates the code is within the `net` namespace and an anonymous namespace for internal linkage.
    * `TEST(...)`:  Identifies individual test cases. The first argument is the test suite name (`DnsOverHttpsServerConfigTest`), and the second is the specific test case name (e.g., `ValidWithGet`).
    * `EXPECT_...`:  These are Google Test macros used for assertions. `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_THAT`, `EXPECT_EQ` are crucial for understanding the test logic. `testing::Optional` and `testing::Property` suggest more complex assertions about the structure of the `DnsOverHttpsServerConfig` object.
    * `DnsOverHttpsServerConfig::FromString(...)`:  This function is clearly being tested. It takes a string and returns a `DnsOverHttpsServerConfig` object (or an empty optional if parsing fails).
    * `DnsOverHttpsServerConfig::ToValue()`: This function likely converts a `DnsOverHttpsServerConfig` object to a `base::Value` (which often represents JSON).
    * `DnsOverHttpsServerConfig::FromValue(...)`: This function likely does the reverse, creating a `DnsOverHttpsServerConfig` object from a `base::Value`.
    * IP address constants (`ip1`, `ip2`, etc.):  These are used in tests involving server endpoints.
    * JSON string literals (e.g., `R"( ... )"`):  These are used for testing JSON serialization and deserialization.

4. **Analyze Test Case Functionality:** Go through each `TEST` function and understand what it's verifying:
    * `ValidWithGet`: Checks if valid DOH templates using HTTP GET are parsed correctly. It specifically verifies the `use_post` flag is `false`.
    * `ValidWithPost`: Checks if valid DOH templates that imply HTTP POST are parsed correctly. It verifies `use_post` is `true`.
    * `Invalid`: Tests various invalid DOH template formats, ensuring `FromString` returns an empty optional (or `false`). This highlights common errors in specifying DOH templates.
    * `Empty`: Tests parsing an empty string.
    * `Simple`: Checks if a simple DOH template is correctly identified as simple (likely meaning it doesn't have explicit endpoint IPs).
    * `ToValueSimple`: Tests converting a simple `DnsOverHttpsServerConfig` object to its JSON representation.
    * `ToValueWithEndpoints`: Tests converting a `DnsOverHttpsServerConfig` object with specific endpoint IPs to its JSON representation.
    * `FromValueSimple`: Tests creating a `DnsOverHttpsServerConfig` object from a simple JSON representation.
    * `FromValueWithEndpoints`: Tests creating a `DnsOverHttpsServerConfig` object from a JSON representation including endpoint IPs.
    * `FromValueWithUnknownKey`: Tests that extra, unexpected keys in the JSON are ignored during parsing.
    * `FromValueInvalid`: Tests various invalid JSON inputs for creating `DnsOverHttpsServerConfig` objects, covering incorrect template formats, wrong data types, and invalid IP addresses.

5. **Infer Overall Functionality:** Based on the test cases, the `DnsOverHttpsServerConfig` class seems to be responsible for:
    * Parsing DOH server configurations from strings (templates).
    * Representing whether to use HTTP GET or POST for DOH requests.
    * Handling optional specific IP addresses for the DOH server.
    * Converting between its internal representation and JSON format.
    * Validating the format of DOH templates and JSON configurations.

6. **Consider JavaScript Relationship:**  The presence of JSON handling is the primary connection to JavaScript. Web browsers often use JSON to store and exchange configuration data. Therefore, this C++ code likely plays a role in how the Chrome browser handles DOH settings, which might be configured through user settings or policies expressed in a JSON-like format that interacts with JavaScript in the browser's UI or internal settings management.

7. **Develop Examples and Scenarios:**
    * **Logical Reasoning:**  Choose a test case that demonstrates conditional logic (like checking for the presence of `?query` for POST). Provide a clear input and expected output based on the code's behavior.
    * **User/Programming Errors:** Focus on the `Invalid` and `FromValueInvalid` test cases. These directly illustrate common mistakes users or developers might make when configuring DOH.
    * **User Journey/Debugging:** Think about how a user would interact with DOH settings in Chrome. This involves going through browser settings, potentially importing/exporting configurations, or encountering errors that might lead a developer to investigate this code.

8. **Structure the Answer:** Organize the findings into clear sections as requested: Functionality, JavaScript relation, logical reasoning, usage errors, and debugging clues. Use clear and concise language. For code examples in the "Logical Reasoning" section, directly relate them to the relevant test case.

9. **Review and Refine:** Read through the answer to ensure accuracy, clarity, and completeness. Check for any inconsistencies or areas that need further explanation. For instance, initially, I might have missed the explicit check for HTTPS, but reviewing the `Invalid` tests would highlight this detail.

This methodical approach, starting with identifying the core purpose and then dissecting the code's components and test cases, allows for a comprehensive understanding and the ability to address all aspects of the request.
这个文件 `net/dns/public/dns_over_https_server_config_unittest.cc` 是 Chromium 网络栈的一部分，专门用于测试 `net/dns/public/dns_over_https_server_config.h` 中定义的 `DnsOverHttpsServerConfig` 类的功能。 单元测试的目标是验证代码的各个独立部分是否按预期工作。

以下是该文件的功能分解：

**核心功能：测试 `DnsOverHttpsServerConfig` 类的各种方法。**

`DnsOverHttpsServerConfig` 类很可能负责：

* **解析 DOH 服务器配置字符串:**  将用户提供的 DOH 服务器 URL 模板（例如 `"https://dnsserver.example.net/dns-query{?dns}"`）解析成内部数据结构。
* **判断请求方法 (GET/POST):**  根据 URL 模板中的占位符判断 DOH 请求应该使用 HTTP GET 还是 POST 方法。
* **管理服务器端点 IP 地址:**  存储与 DOH 服务器关联的 IP 地址列表。
* **序列化和反序列化配置:** 将 `DnsOverHttpsServerConfig` 对象转换为 JSON 格式，以及从 JSON 格式恢复。

**该测试文件具体测试了以下方面：**

1. **有效的 GET 请求配置解析:**
   - 测试使用 `FromString` 方法解析各种有效的、暗示使用 HTTP GET 请求的 DOH 服务器 URL 模板。
   - 验证解析后的 `DnsOverHttpsServerConfig` 对象的 `use_post` 属性是否为 `false`。
   - **假设输入:** `"https://dnsserver.example.net/dns-query{?dns}"`
   - **预期输出:** 解析成功，且 `use_post` 为 `false`。

2. **有效的 POST 请求配置解析:**
   - 测试使用 `FromString` 方法解析各种有效的、暗示使用 HTTP POST 请求的 DOH 服务器 URL 模板。
   - 验证解析后的 `DnsOverHttpsServerConfig` 对象的 `use_post` 属性是否为 `true`。
   - **假设输入:** `"https://dnsserver.example.net/dns-query{?query}"`
   - **预期输出:** 解析成功，且 `use_post` 为 `true`。

3. **无效的配置解析:**
   - 测试使用 `FromString` 方法解析各种无效的 DOH 服务器 URL 模板。
   - 验证 `FromString` 方法返回 `false` 或一个空的 `Optional`。
   - **假设输入:** `"http://dnsserver.example.net/dns-query"` (非 HTTPS)
   - **预期输出:** 解析失败。

4. **空字符串解析:**
   - 测试解析空字符串的情况。
   - 验证 `FromString` 方法返回 `false`。

5. **简单配置的识别:**
   - 测试识别不包含特定端点 IP 地址的简单 DOH 配置。
   - 验证 `IsSimple` 方法返回 `true`。
   - **假设输入:** `"https://dnsserver.example.net/dns-query{?dns}"`
   - **预期输出:** `IsSimple` 为 `true`。

6. **序列化为 JSON (简单配置):**
   - 测试将简单的 `DnsOverHttpsServerConfig` 对象转换为 JSON 格式。
   - 验证生成的 JSON 字符串是否符合预期。
   - **假设输入:** 一个通过 `FromString("https://dnsserver.example.net/dns-query{?dns}")` 创建的对象。
   - **预期输出:** `{"template": "https://dnsserver.example.net/dns-query{?dns}"}`

7. **序列化为 JSON (包含端点):**
   - 测试将包含端点 IP 地址的 `DnsOverHttpsServerConfig` 对象转换为 JSON 格式。
   - 验证生成的 JSON 字符串是否包含正确的 `endpoints` 数组。
   - **假设输入:** 一个通过 `FromString("https://dnsserver.example.net/dns-query{?dns}", endpoints)` 创建的对象。
   - **预期输出:**  包含 `template` 和 `endpoints` 信息的 JSON。

8. **从 JSON 反序列化 (简单配置):**
   - 测试从 JSON 字符串反序列化为 `DnsOverHttpsServerConfig` 对象。
   - 验证反序列化后的对象与通过 `FromString` 创建的对象相等。
   - **假设输入:** `{"template": "https://dnsserver.example.net/dns-query{?dns}"}`
   - **预期输出:**  成功创建一个 `DnsOverHttpsServerConfig` 对象，其属性与输入 JSON 匹配。

9. **从 JSON 反序列化 (包含端点):**
   - 测试从包含端点信息的 JSON 字符串反序列化为 `DnsOverHttpsServerConfig` 对象。
   - 验证反序列化后的对象与通过 `FromString` 和 IP 地址列表创建的对象相等。
   - **假设输入:** 包含 `template` 和 `endpoints` 信息的 JSON。
   - **预期输出:**  成功创建一个包含端点信息的 `DnsOverHttpsServerConfig` 对象.

10. **从 JSON 反序列化 (包含未知键):**
    - 测试从包含额外未知键的 JSON 字符串反序列化。
    - 验证未知键被忽略，反序列化仍然成功。
    - **假设输入:** `{"template": "...", "unknown key": "value"}`
    - **预期输出:**  成功反序列化，但 "unknown key" 被忽略。

11. **从 JSON 反序列化 (无效输入):**
    - 测试从各种无效的 JSON 格式反序列化。
    - 验证 `FromValue` 方法返回 `false`。
    - **假设输入:** `{"template": "http://..."}` (非 HTTPS) 或 `{"endpoints": {"ips": [...]}}` (错误的 endpoints 类型)。
    - **预期输出:** 反序列化失败。

**与 JavaScript 的关系：**

虽然这个 C++ 文件本身不包含 JavaScript 代码，但它所测试的功能与 Chromium 浏览器中处理 DNS over HTTPS 设置的方式密切相关，而这些设置可能会受到 JavaScript 代码的影响。

* **用户配置:** 用户在浏览器的设置界面中配置 DOH 服务器时，JavaScript 代码负责接收用户的输入，并将其转换为某种内部表示形式。最终，这个配置信息可能需要被传递给 C++ 网络栈进行处理。`DnsOverHttpsServerConfig` 类就负责解析这些配置字符串。
* **策略管理:** 企业或系统管理员可以通过策略来强制使用特定的 DOH 服务器。这些策略通常以 JSON 格式定义，JavaScript 代码可能会读取和处理这些策略，并将相关的 DOH 服务器配置传递给 C++ 代码。
* **实验性功能:**  Chrome 中的一些实验性 DOH 功能可能通过 JavaScript API 进行控制，这些 API 会间接地影响 `DnsOverHttpsServerConfig` 的使用。

**举例说明 (与 JavaScript 的关系):**

假设用户在 Chrome 的设置中输入了一个 DOH 服务器地址：`"https://doh.example/dns-query{?dns}"`。

1. **JavaScript 接收输入:**  浏览器设置页面的 JavaScript 代码捕获用户的输入。
2. **JavaScript 可能进行初步验证:**  JavaScript 代码可能会进行一些基本的格式验证，例如确保是以 `"https://"` 开头。
3. **将配置传递给 C++:**  JavaScript 代码最终会将这个字符串传递给 Chromium 的 C++ 网络栈。
4. **C++ 解析配置:**  `DnsOverHttpsServerConfig::FromString` 方法会被调用，使用这个字符串作为输入，创建 `DnsOverHttpsServerConfig` 对象。
5. **C++ 使用配置:**  网络栈的其他部分会使用这个 `DnsOverHttpsServerConfig` 对象来执行 DNS over HTTPS 查询。

**用户或编程常见的使用错误举例说明：**

1. **错误的 URL 模板格式:** 用户可能会输入错误的 URL 模板，例如缺少 `{?dns}` 占位符，或者使用了错误的占位符。测试用例 `Invalid` 就覆盖了这种情况。
   - **用户操作:** 在浏览器设置中手动输入 DOH 服务器地址时，拼写错误或使用了不支持的语法，例如输入 `"https://doh.example/dns-query"` (缺少 GET 请求参数指示)。
   - **结果:**  C++ 代码解析失败，DOH 功能可能无法正常工作，或者回退到传统的 DNS 查询。

2. **使用 HTTP 而不是 HTTPS:** DOH 必须使用 HTTPS 进行加密通信。如果用户错误地输入了以 `"http://"` 开头的地址，`FromString` 方法应该拒绝它。测试用例 `Invalid` 中包含了这种情况。
   - **用户操作:**  在设置中输入 `"http://doh.example/dns-query"`。
   - **结果:** C++ 代码解析失败，因为安全连接是 DOH 的基本要求。

3. **在 JSON 配置中提供无效的数据类型:**  如果 DOH 配置是通过 JSON 文件或策略提供的，可能会出现数据类型错误，例如将 IP 地址表示为数字而不是字符串。测试用例 `FromValueInvalid` 就测试了这种情况。
   - **用户操作 (或编程错误):**  在配置文件中错误地将 IP 地址写成数字，例如 `"ips": ["2001:db8::1", 192021]` 而不是 `"ips": ["2001:db8::1", "192.0.2.1"]`。
   - **结果:** C++ 代码在尝试从 JSON 反序列化时会失败。

**用户操作如何一步步到达这里，作为调试线索：**

1. **用户想要启用或配置 DNS over HTTPS:** 用户可能出于隐私或安全考虑，希望使用 DOH。
2. **用户打开浏览器的设置界面:**  用户导航到 Chrome 的设置页面，通常是 `chrome://settings/security` 或类似的地址。
3. **用户找到 DNS 设置:** 在安全或隐私设置部分，用户会找到与 DNS 相关的选项，例如 "使用安全连接查找网络地址" 或 "自定义"。
4. **用户选择自定义 DNS 提供商:** 用户选择手动配置 DNS 服务器。
5. **用户输入 DOH 服务器地址:** 用户在提供的文本框中输入 DOH 服务器的 URL 模板，例如 `"https://cloudflare-dns.com/dns-query{?dns}"`。
6. **浏览器验证并保存设置:** 当用户点击保存或应用按钮时，浏览器会将用户输入的字符串传递给底层的 C++ 网络栈进行处理。
7. **C++ 代码调用 `DnsOverHttpsServerConfig::FromString`:**  网络栈接收到配置字符串后，会调用 `DnsOverHttpsServerConfig::FromString` 方法尝试解析这个字符串。
8. **如果解析失败:** 如果用户输入的格式不正确，`FromString` 方法会返回错误。这可能会导致浏览器显示错误消息，或者回退到默认的 DNS 设置。
9. **调试线索:** 如果 DOH 功能出现问题，开发者可能会查看网络日志或使用调试工具来跟踪配置的解析过程。断点可能会设置在 `DnsOverHttpsServerConfig::FromString` 方法内部，以检查输入的字符串以及解析过程中发生的情况。 单元测试的存在也为开发者提供了一种验证 `DnsOverHttpsServerConfig` 类行为的方式。

总而言之，`dns_over_https_server_config_unittest.cc` 文件对于确保 Chromium 网络栈正确处理 DNS over HTTPS 服务器配置至关重要。它通过详尽的测试用例覆盖了各种有效和无效的配置场景，帮助开发者避免潜在的错误，并保证 DOH 功能的稳定性和可靠性。 虽然与 JavaScript 没有直接的代码关联，但它所测试的功能是浏览器中 DOH 特性不可或缺的一部分，并且与用户通过 JavaScript 驱动的界面进行的配置操作紧密相关。

### 提示词
```
这是目录为net/dns/public/dns_over_https_server_config_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/dns/public/dns_over_https_server_config.h"

#include <string>
#include <string_view>

#include "base/json/json_reader.h"
#include "net/base/ip_address.h"
#include "net/dns/public/dns_over_https_config.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {
namespace {

const IPAddress ip1(192, 0, 2, 1);
const IPAddress ip2(0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1);
const IPAddress ip3(192, 0, 2, 2);
const IPAddress ip4(0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2);
const DnsOverHttpsServerConfig::Endpoints endpoints{{ip1, ip2}, {ip3, ip4}};

TEST(DnsOverHttpsServerConfigTest, ValidWithGet) {
  auto parsed = DnsOverHttpsServerConfig::FromString(
      "https://dnsserver.example.net/dns-query{?dns}");
  EXPECT_THAT(parsed, testing::Optional(testing::Property(
                          &DnsOverHttpsServerConfig::use_post, false)));

  parsed = DnsOverHttpsServerConfig::FromString(
      "https://dnsserver.example.net/dns-query{?dns,extra}");
  EXPECT_THAT(parsed, testing::Optional(testing::Property(
                          &DnsOverHttpsServerConfig::use_post, false)));

  parsed = DnsOverHttpsServerConfig::FromString(
      "https://query:{dns}@dnsserver.example.net");
  EXPECT_THAT(parsed, testing::Optional(testing::Property(
                          &DnsOverHttpsServerConfig::use_post, false)));

  parsed = DnsOverHttpsServerConfig::FromString(
      "https://dnsserver.example.net{/dns}");
  EXPECT_THAT(parsed, testing::Optional(testing::Property(
                          &DnsOverHttpsServerConfig::use_post, false)));
}

TEST(DnsOverHttpsServerConfigTest, ValidWithPost) {
  auto parsed = DnsOverHttpsServerConfig::FromString(
      "https://dnsserver.example.net/dns-query{?query}");
  EXPECT_THAT(parsed, testing::Optional(testing::Property(
                          &DnsOverHttpsServerConfig::use_post, true)));

  parsed = DnsOverHttpsServerConfig::FromString(
      "https://dnsserver.example.net/dns-query");
  EXPECT_THAT(parsed, testing::Optional(testing::Property(
                          &DnsOverHttpsServerConfig::use_post, true)));
}

TEST(DnsOverHttpsServerConfigTest, Invalid) {
  // Invalid template format
  EXPECT_FALSE(DnsOverHttpsServerConfig::FromString(
      "https://dnsserver.example.net/dns-query{{?dns}}"));
  // Must be HTTPS
  EXPECT_FALSE(DnsOverHttpsServerConfig::FromString(
      "http://dnsserver.example.net/dns-query"));
  EXPECT_FALSE(DnsOverHttpsServerConfig::FromString(
      "http://dnsserver.example.net/dns-query{?dns}"));
  // Template must expand to a valid URL
  EXPECT_FALSE(DnsOverHttpsServerConfig::FromString("https://{?dns}"));
  // The hostname must not contain the dns variable
  EXPECT_FALSE(
      DnsOverHttpsServerConfig::FromString("https://{dns}.dnsserver.net"));
}

TEST(DnsOverHttpsServerConfigTest, Empty) {
  EXPECT_FALSE(net::DnsOverHttpsServerConfig::FromString(""));
}

TEST(DnsOverHttpsServerConfigTest, Simple) {
  auto parsed = DnsOverHttpsServerConfig::FromString(
      "https://dnsserver.example.net/dns-query{?dns}");
  EXPECT_THAT(parsed, testing::Optional(testing::Property(
                          &DnsOverHttpsServerConfig::IsSimple, true)));
}

TEST(DnsOverHttpsServerConfigTest, ToValueSimple) {
  auto parsed = DnsOverHttpsServerConfig::FromString(
      "https://dnsserver.example.net/dns-query{?dns}");
  ASSERT_TRUE(parsed);

  base::Value expected = *base::JSONReader::Read(R"(
    {
      "template": "https://dnsserver.example.net/dns-query{?dns}"
    }
  )");
  EXPECT_EQ(expected.GetDict(), parsed->ToValue());
}

TEST(DnsOverHttpsServerConfigTest, ToValueWithEndpoints) {
  auto parsed = DnsOverHttpsServerConfig::FromString(
      "https://dnsserver.example.net/dns-query{?dns}", endpoints);
  ASSERT_TRUE(parsed);

  EXPECT_THAT(parsed, testing::Optional(testing::Property(
                          &DnsOverHttpsServerConfig::IsSimple, false)));
  EXPECT_THAT(parsed, testing::Optional(testing::Property(
                          &DnsOverHttpsServerConfig::endpoints, endpoints)));

  base::Value expected = *base::JSONReader::Read(
      R"({
        "template": "https://dnsserver.example.net/dns-query{?dns}",
        "endpoints": [{
          "ips": ["192.0.2.1", "2001:db8::1"]
        }, {
          "ips": ["192.0.2.2", "2001:db8::2"]
        }]
      })");
  EXPECT_EQ(expected.GetDict(), parsed->ToValue());
}

TEST(DnsOverHttpsServerConfigTest, FromValueSimple) {
  base::Value input = *base::JSONReader::Read(R"(
    {
      "template": "https://dnsserver.example.net/dns-query{?dns}"
    }
  )");

  auto parsed =
      DnsOverHttpsServerConfig::FromValue(std::move(input).TakeDict());

  auto expected = DnsOverHttpsServerConfig::FromString(
      "https://dnsserver.example.net/dns-query{?dns}");
  EXPECT_EQ(expected, parsed);
}

TEST(DnsOverHttpsServerConfigTest, FromValueWithEndpoints) {
  base::Value input = *base::JSONReader::Read(R"(
    {
      "template": "https://dnsserver.example.net/dns-query{?dns}",
      "endpoints": [{
        "ips": ["192.0.2.1", "2001:db8::1"]
      }, {
        "ips": ["192.0.2.2", "2001:db8::2"]
      }]
    }
  )");

  auto parsed =
      DnsOverHttpsServerConfig::FromValue(std::move(input).TakeDict());

  auto expected = DnsOverHttpsServerConfig::FromString(
      "https://dnsserver.example.net/dns-query{?dns}", endpoints);
  EXPECT_EQ(expected, parsed);
}

TEST(DnsOverHttpsServerConfigTest, FromValueWithUnknownKey) {
  base::Value input = *base::JSONReader::Read(R"(
    {
      "template": "https://dnsserver.example.net/dns-query{?dns}",
      "unknown key": "value is ignored"
    }
  )");

  auto parsed =
      DnsOverHttpsServerConfig::FromValue(std::move(input).TakeDict());

  auto expected = DnsOverHttpsServerConfig::FromString(
      "https://dnsserver.example.net/dns-query{?dns}");
  EXPECT_EQ(expected, parsed);
}

TEST(DnsOverHttpsServerConfigTest, FromValueInvalid) {
  // Empty dict
  EXPECT_FALSE(DnsOverHttpsServerConfig::FromValue(base::Value::Dict()));

  // Wrong scheme
  std::string_view input = R"(
    {
      "template": "http://dnsserver.example.net/dns-query{?dns}"
    }
  )";
  EXPECT_FALSE(DnsOverHttpsServerConfig::FromValue(
      std::move(base::JSONReader::Read(input)->GetDict())));

  // Wrong template type
  input = R"({"template": 12345})";
  EXPECT_FALSE(DnsOverHttpsServerConfig::FromValue(
      std::move(base::JSONReader::Read(input)->GetDict())));

  // Wrong endpoints type
  input = R"(
    {
      "template": "https://dnsserver.example.net/dns-query{?dns}",
      "endpoints": {
         "ips": ["192.0.2.1", "2001:db8::1"]
      }
    }
  )";
  EXPECT_FALSE(DnsOverHttpsServerConfig::FromValue(
      std::move(base::JSONReader::Read(input)->GetDict())));

  // Wrong "ips" type
  input = R"(
    {
      "template": "https://dnsserver.example.net/dns-query{?dns}",
      "endpoints": [{
        "ips": "192.0.2.1"
      }]
    }
  )";
  EXPECT_FALSE(DnsOverHttpsServerConfig::FromValue(
      std::move(base::JSONReader::Read(input)->GetDict())));

  // Wrong IP type
  input = R"(
    {
      "template": "https://dnsserver.example.net/dns-query{?dns}",
      "endpoints": [{
        "ips": ["2001:db8::1", 192.021]
      }]
    }
  )";
  EXPECT_FALSE(DnsOverHttpsServerConfig::FromValue(
      std::move(base::JSONReader::Read(input)->GetDict())));

  // Bad IP address
  input = R"(
    {
      "template": "https://dnsserver.example.net/dns-query{?dns}",
     "endpoints": [{
        "ips": ["2001:db8::1", "256.257.258.259"]
      }]
    }
  )";
  EXPECT_FALSE(DnsOverHttpsServerConfig::FromValue(
      std::move(base::JSONReader::Read(input)->GetDict())));
}

}  // namespace
}  // namespace net
```