Response:
Let's break down the thought process for analyzing this C++ unittest file for Chromium's network stack.

1. **Identify the Core Purpose:** The filename `proxy_string_util_unittest.cc` immediately suggests this file tests the utility functions related to handling proxy strings. The presence of `#include "net/base/proxy_string_util.h"` confirms this.

2. **Recognize the Testing Framework:** The inclusion of `#include "testing/gtest/include/gtest/gtest.h"` indicates the use of Google Test (gtest) framework for writing these unit tests. This means we should look for `TEST()` macros.

3. **Examine the `TEST()` Cases:**  Go through each `TEST()` block and try to understand what aspect of `proxy_string_util.h` is being tested. Look at the test names and the logic inside each test. Here's a breakdown of the individual test cases and what they reveal:

    * **`ProxyUriToProxyServer`:** Focuses on converting a string representation of a proxy URI into a `ProxyServer` object. It tests various schemes (HTTP, SOCKS, HTTPS, QUIC), formats (with and without ports, IPv6 addresses), and hostname canonicalization.

    * **`ProxyUriToProxyServerBuildFlagEnabledQuicDisallowedIsInvalid` and `ProxyUriToProxyServerBuildFlagDisabledQuicAllowedIsInvalid`:** These tests are conditional based on the `ENABLE_QUIC_PROXY_SUPPORT` build flag. They verify that QUIC proxy parsing behaves correctly depending on whether QUIC proxy support is enabled in the build.

    * **`DirectProxyUriToProxyChain`:** Specifically tests the parsing of the special "direct://" URI, which signifies no proxy. It checks for correct parsing of valid "direct://" and rejection of invalid forms (e.g., "direct://xyz").

    * **`ProxyUriToProxyChainWithBracketsInvalid`:** This test checks that inputs intended for *multi-proxy chains* (using brackets) are *not* valid input for the single-proxy `ProxyUriToProxyChain` function.

    * **`InvalidProxyUriToProxyServer`:** Tests various invalid proxy URI strings to ensure the parsing function correctly identifies and rejects them.

    * **`WhitespaceProxyUriToProxyServer`:**  Verifies that leading and trailing whitespace around proxy URIs are correctly ignored.

    * **`PacResultElementToProxyServer`:**  Tests the conversion of proxy information obtained from a PAC (Proxy Auto-Config) file into `ProxyServer` objects. It handles various PAC formats (PROXY, SOCKS, HTTPS) and whitespace.

    * **`InvalidPacResultElementToProxyServer`:**  Tests invalid PAC result strings to ensure they are correctly rejected.

    * **`MultiProxyUrisToProxyChainMultiProxyDirectIsInvalid` and `MultiProxyUrisToProxyChainSingleDirectIsValid`:** These tests (conditional on `ENABLE_BRACKETED_PROXY_URIS`) focus on how multi-proxy chains handle the "direct://" directive. A multi-proxy chain with `direct://` should be invalid, but a single `direct://` is valid.

    * **`MultiProxyUrisToProxyChainValid`:**  Tests the successful parsing of valid multi-proxy chain strings (with and without brackets, multiple proxies).

    * **`MultiProxyUrisToProxyChainValidQuic` and `MultiProxyUrisToProxyChainInvalidQuicCombo`:** These tests (conditional on `ENABLE_BRACKETED_PROXY_URIS` and `ENABLE_QUIC_PROXY_SUPPORT`) focus on the correct handling of QUIC proxies within multi-proxy chains, including valid and invalid combinations.

    * **`MultiProxyUrisToProxyChainInvalidFormatReturnsInvalidProxyChain`:** Tests various invalid formats for multi-proxy chain strings to ensure they are correctly rejected.

4. **Identify the Tested Functions:**  From the `TEST()` calls and the included header file, we can determine the primary functions being tested:

    * `ProxyUriToProxyServer()`
    * `ProxyServerToProxyUri()`
    * `ProxyServerToPacResultElement()`
    * `PacResultElementToProxyServer()`
    * `PacResultElementToProxyChain()`
    * `ProxyUriToProxyChain()`
    * `MultiProxyUrisToProxyChain()`

5. **Analyze Functionality and Potential Issues:** Based on the tests, deduce the functionality of the utility functions. Look for patterns in the test cases that indicate common usage scenarios and potential pitfalls. For example, the tests for invalid URIs and PAC strings highlight potential user input errors.

6. **Consider JavaScript Relevance:** Think about where proxy settings are configured in a browser. JavaScript in web pages or browser extensions often interacts with proxy settings. PAC scripts, written in JavaScript, are a prime example. This connects the C++ code to the JavaScript realm.

7. **Infer User Actions and Debugging:**  Imagine a user encountering proxy-related issues. How might they configure their proxy settings?  Where might those settings be stored? How could a developer debug proxy problems?  This helps connect the low-level C++ code to user-facing scenarios.

8. **Structure the Explanation:** Organize the findings into logical sections: file function, JavaScript relevance, logical reasoning (with examples), common errors, and debugging. Use clear and concise language.

9. **Review and Refine:**  Read through the explanation to ensure accuracy and completeness. Check for any logical gaps or areas that could be clearer. For example, initially, I might not have explicitly linked PAC scripts to JavaScript. Reviewing the functionality would prompt me to make that connection. Similarly, ensuring example inputs and outputs are provided for logical reasoning adds clarity.
这个文件 `net/base/proxy_string_util_unittest.cc` 是 Chromium 网络栈的一部分，它的主要功能是**测试 `net/base/proxy_string_util.h` 中定义的与代理字符串处理相关的工具函数**。 换句话说，它验证了各种用于解析、格式化和操作代理服务器字符串表示的函数的正确性。

下面详细列举一下它的功能点，并根据您的要求进行说明：

**1. 功能列举:**

* **`ProxyUriToProxyServer()` 测试:**
    * 将各种格式的代理 URI 字符串 (例如 "foopy:10", "http://foopy:80", "socks5://foopy") 转换为 `ProxyServer` 对象。
    * 验证转换后的 `ProxyServer` 对象的各个属性是否正确，包括代理协议 (scheme)、主机名 (host)、端口号 (port) 等。
    * 测试了不同协议的代理 URI，如 HTTP, SOCKS4, SOCKS5, HTTPS，以及条件编译的 QUIC 代理。
    * 测试了 IPv6 地址的代理 URI。
    * 测试了主机名的规范化，例如将 Punycode 编码的域名转换为 IDN 域名。
    * 验证了在启用/禁用 QUIC 代理支持的编译配置下，QUIC 代理 URI 的解析行为。
* **`ProxyServerToProxyUri()` 测试:**
    * 将 `ProxyServer` 对象转换回其字符串表示形式。这与 `ProxyUriToProxyServer()` 形成互补的测试。
* **`ProxyServerToPacResultElement()` 测试:**
    * 将 `ProxyServer` 对象转换为 PAC (Proxy Auto-Config) 文件中使用的字符串格式 (例如 "PROXY foopy:80", "SOCKS5 foopy:1080")。
* **`PacResultElementToProxyServer()` 测试:**
    * 将 PAC 文件中的代理字符串转换为 `ProxyServer` 对象。
* **`PacResultElementToProxyChain()` 测试:**
    * 将 PAC 文件中的代理字符串转换为 `ProxyChain` 对象。
* **`DirectProxyUriToProxyChain()` 测试:**
    * 测试解析特殊的 "direct://" URI，它表示不使用代理。
    * 验证 "direct://" URI 可以正确转换为表示直接连接的 `ProxyChain` 对象。
* **`ProxyUriToProxyChain()` 测试:**
    * 测试将单个代理服务器 URI 字符串转换为 `ProxyChain` 对象。
    * 验证对于多代理 URI 字符串（例如 "[https://...] [https://...]")，此函数会返回无效的 `ProxyChain`。
* **`MultiProxyUrisToProxyChain()` 测试 (在 `ENABLE_BRACKETED_PROXY_URIS` 宏定义启用的情况下):**
    * 将包含多个代理 URI 的字符串（例如 "[https://foopy:443 https://hoopy:443]") 转换为 `ProxyChain` 对象。
    * 验证转换后的 `ProxyChain` 对象包含正确的代理服务器列表。
    * 测试了 QUIC 代理在多代理链中的使用情况。
    * 验证了包含 "direct://" 的多代理链会被视为无效。
* **无效输入的测试:**
    * 测试了各种无效的代理 URI 和 PAC 字符串，确保相关的解析函数能够正确识别并处理这些错误情况。
* **空白字符处理测试:**
    * 验证解析函数能够忽略代理 URI 字符串两端的空白字符。

**2. 与 JavaScript 的关系 (举例说明):**

该文件直接测试的是 C++ 代码，与 JavaScript 没有直接的运行时交互。但是，它所测试的功能与 JavaScript 在浏览器环境中的代理配置息息相关。

* **PAC (Proxy Auto-Config) 文件:** PAC 文件是用 JavaScript 编写的脚本，浏览器会执行这些脚本来确定特定 URL 是否应该使用代理以及使用哪个代理。`PacResultElementToProxyServer()` 和 `PacResultElementToProxyChain()` 测试了如何解析 PAC 文件中返回的代理服务器信息。
    * **假设输入:** PAC 文件中包含一行 `return "PROXY myproxy.com:8080";`
    * **对应 JavaScript 功能:** 浏览器在执行 PAC 脚本时，如果脚本返回了 `"PROXY myproxy.com:8080"`，浏览器会调用底层的网络栈代码（即此文件测试的代码）来解析这个字符串，以便连接到 `myproxy.com:8080` 这个代理服务器。
* **浏览器代理设置:** 用户在浏览器设置中配置代理服务器时，通常会输入代理服务器的地址和端口，例如 "http://myproxy.com:8080" 或 "socks5://anotherproxy.net:1080"。浏览器会将这些用户输入的字符串传递给底层的网络栈代码进行解析和处理。
    * **假设输入:** 用户在浏览器设置中输入 "socks5://my-socks-proxy:1080"。
    * **对应 JavaScript 功能:**  虽然用户界面是用 HTML/CSS/JavaScript 构建的，但当用户点击“保存”或应用设置时，浏览器会将这个字符串传递给 C++ 网络栈，`ProxyUriToProxyServer()` 函数（或类似的函数）会被调用来解析这个字符串。

**3. 逻辑推理 (假设输入与输出):**

* **假设输入 (针对 `ProxyUriToProxyServer()`):** `"https://secure-proxy:443"`
* **输出:** 一个 `ProxyServer` 对象，其属性为:
    * `scheme()`: `ProxyServer::SCHEME_HTTPS`
    * `host_port_pair().host()`: `"secure-proxy"`
    * `host_port_pair().port()`: `443`
    * `is_valid()`: `true`

* **假设输入 (针对 `PacResultElementToProxyServer()`):** `"SOCKS5 internal-socks:1080"`
* **输出:** 一个 `ProxyServer` 对象，其属性为:
    * `scheme()`: `ProxyServer::SCHEME_SOCKS5`
    * `host_port_pair().host()`: `"internal-socks"`
    * `host_port_pair().port()`: `1080`
    * `is_valid()`: `true`

* **假设输入 (针对 `MultiProxyUrisToProxyChain()` 且 `ENABLE_BRACKETED_PROXY_URIS` 启用):** `"[https://proxy1:443 socks5://proxy2:1080]"`
* **输出:** 一个 `ProxyChain` 对象，包含两个 `ProxyServer` 对象:
    * 第一个 `ProxyServer`: `scheme()` 为 `ProxyServer::SCHEME_HTTPS`, host 为 "proxy1", port 为 443
    * 第二个 `ProxyServer`: `scheme()` 为 `ProxyServer::SCHEME_SOCKS5`, host 为 "proxy2", port 为 1080
    * `IsValid()`: `true`

**4. 涉及用户或者编程常见的使用错误 (举例说明):**

* **错误的代理 URI 格式:** 用户可能在配置代理时输入了格式错误的 URI。
    * **错误示例:** `"http//myproxy:80"` (缺少冒号), `"myproxy"` (缺少端口或协议)。
    * **此文件中的测试:** `InvalidProxyUriToProxyServer` 测试了各种此类错误格式，确保解析函数能正确识别并拒绝它们。
* **PAC 文件中使用了错误的代理字符串格式:** PAC 脚本编写者可能会在 `return` 语句中使用错误的代理字符串格式。
    * **错误示例:** `"HTTP myproxy:80"` (应该使用 "PROXY"), `"SOCKS myproxy"` (缺少协议版本)。
    * **此文件中的测试:** `InvalidPacResultElementToProxyServer` 测试了这些情况。
* **在不支持多代理的情况下使用了多代理字符串:** 在某些情况下，系统可能不支持配置多级代理链，但用户或程序可能尝试使用类似 "[proxy1 proxy2]" 的格式。
    * **此文件中的测试:** `ProxyUriToProxyChainWithBracketsInvalid` 验证了在不支持多代理的上下文中，这种格式会被拒绝。
* **QUIC 代理配置不当:**  用户或程序可能在未启用 QUIC 代理支持的情况下尝试配置 QUIC 代理。
    * **此文件中的测试:** `ProxyUriToProxyServerBuildFlagEnabledQuicDisallowedIsInvalid` 和 `ProxyUriToProxyServerBuildFlagDisabledQuicAllowedIsInvalid` 验证了在这种情况下 QUIC 代理的解析行为。

**5. 用户操作如何一步步的到达这里，作为调试线索:**

当用户在使用 Chromium 浏览器时遇到与代理相关的问题，例如无法通过代理连接到网站，开发人员可能会需要调试网络栈的代码，而这个单元测试文件可以提供一些线索：

1. **用户报告代理问题:** 用户反馈无法通过配置的代理访问特定网站。
2. **检查浏览器代理设置:** 开发者首先会检查用户的浏览器代理设置，查看用户配置的代理服务器地址。
3. **分析网络请求日志:** 开发者可能会抓取网络请求日志，查看浏览器尝试连接代理服务器的详细信息。
4. **定位到代理处理代码:** 如果怀疑是代理配置解析的问题，开发者可能会深入到 Chromium 的网络栈代码中，查找处理代理设置的模块。
5. **查看 `proxy_string_util.h` 和 `proxy_string_util_unittest.cc`:**  开发者可能会查看 `net/base/proxy_string_util.h` 中定义的函数，了解如何解析和处理代理字符串。同时，会查看 `proxy_string_util_unittest.cc` 中的测试用例，了解这些函数应该如何工作以及各种边界情况。
6. **重现问题并调试:** 开发者可能会尝试使用用户报告的代理配置信息，运行相关的代码，并使用调试器逐步执行，查看 `ProxyUriToProxyServer()` 等函数的执行过程，判断是否是代理字符串解析错误导致的问题。
7. **单元测试作为参考:**  单元测试文件可以作为“黄金标准”，帮助开发者理解代码的预期行为。如果实际运行的代码行为与单元测试不符，则很可能存在 bug。例如，如果用户配置了一个格式正确的代理 URI，但 `ProxyUriToProxyServer()` 却返回了无效的 `ProxyServer` 对象，那么就需要进一步调查代码中的错误。

总而言之，`net/base/proxy_string_util_unittest.cc` 是一个关键的测试文件，用于确保 Chromium 网络栈能够正确地解析和处理各种格式的代理服务器字符串，这对于保证浏览器的代理功能正常工作至关重要。 它可以帮助开发者理解代码的功能，发现潜在的 bug，并作为调试代理相关问题的起点。

Prompt: 
```
这是目录为net/base/proxy_string_util_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/base/proxy_string_util.h"

#include <string>
#include <vector>

#include "build/buildflag.h"
#include "net/base/proxy_chain.h"
#include "net/base/proxy_server.h"
#include "net/net_buildflags.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {
namespace {

// Test the creation of ProxyServer using ProxyUriToProxyServer, which parses
// inputs of the form [<scheme>"://"]<host>[":"<port>]. Verify that each part
// was labelled correctly, and the accessors all give the right data.
TEST(ProxySpecificationUtilTest, ProxyUriToProxyServer) {
  const struct {
    const char* const input_uri;
    const char* const expected_uri;
    ProxyServer::Scheme expected_scheme;
    const char* const expected_host;
    int expected_port;
    const char* const expected_pac_string;
  } tests[] = {
      // HTTP proxy URIs:
      {"foopy:10",  // No scheme.
       "foopy:10", ProxyServer::SCHEME_HTTP, "foopy", 10, "PROXY foopy:10"},
      {"http://foopy",  // No port.
       "foopy:80", ProxyServer::SCHEME_HTTP, "foopy", 80, "PROXY foopy:80"},
      {"http://foopy:10", "foopy:10", ProxyServer::SCHEME_HTTP, "foopy", 10,
       "PROXY foopy:10"},

      // IPv6 HTTP proxy URIs:
      {"[fedc:ba98:7654:3210:fedc:ba98:7654:3210]:10",  // No scheme.
       "[fedc:ba98:7654:3210:fedc:ba98:7654:3210]:10", ProxyServer::SCHEME_HTTP,
       "fedc:ba98:7654:3210:fedc:ba98:7654:3210", 10,
       "PROXY [fedc:ba98:7654:3210:fedc:ba98:7654:3210]:10"},
      {"http://[3ffe:2a00:100:7031::1]",  // No port.
       "[3ffe:2a00:100:7031::1]:80", ProxyServer::SCHEME_HTTP,
       "3ffe:2a00:100:7031::1", 80, "PROXY [3ffe:2a00:100:7031::1]:80"},

      // SOCKS4 proxy URIs:
      {"socks4://foopy",  // No port.
       "socks4://foopy:1080", ProxyServer::SCHEME_SOCKS4, "foopy", 1080,
       "SOCKS foopy:1080"},
      {"socks4://foopy:10", "socks4://foopy:10", ProxyServer::SCHEME_SOCKS4,
       "foopy", 10, "SOCKS foopy:10"},

      // SOCKS5 proxy URIs:
      {"socks5://foopy",  // No port.
       "socks5://foopy:1080", ProxyServer::SCHEME_SOCKS5, "foopy", 1080,
       "SOCKS5 foopy:1080"},
      {"socks5://foopy:10", "socks5://foopy:10", ProxyServer::SCHEME_SOCKS5,
       "foopy", 10, "SOCKS5 foopy:10"},

      // SOCKS proxy URIs (should default to SOCKS5)
      {"socks://foopy",  // No port.
       "socks5://foopy:1080", ProxyServer::SCHEME_SOCKS5, "foopy", 1080,
       "SOCKS5 foopy:1080"},
      {"socks://foopy:10", "socks5://foopy:10", ProxyServer::SCHEME_SOCKS5,
       "foopy", 10, "SOCKS5 foopy:10"},

      // HTTPS proxy URIs:
      {"https://foopy",  // No port
       "https://foopy:443", ProxyServer::SCHEME_HTTPS, "foopy", 443,
       "HTTPS foopy:443"},
      {"https://foopy:10",  // Non-standard port
       "https://foopy:10", ProxyServer::SCHEME_HTTPS, "foopy", 10,
       "HTTPS foopy:10"},
      {"https://1.2.3.4:10",  // IP Address
       "https://1.2.3.4:10", ProxyServer::SCHEME_HTTPS, "1.2.3.4", 10,
       "HTTPS 1.2.3.4:10"},

#if BUILDFLAG(ENABLE_QUIC_PROXY_SUPPORT)
      // QUIC proxy URIs:
      {"quic://foopy",  // no port
       "quic://foopy:443", ProxyServer::SCHEME_QUIC, "foopy", 443,
       "QUIC foopy:443"},
      {"quic://foopy:80", "quic://foopy:80", ProxyServer::SCHEME_QUIC, "foopy",
       80, "QUIC foopy:80"},
#endif  // BUILDFLAG(ENABLE_QUIC_PROXY_SUPPORT)

      // Hostname canonicalization:
      {"[FEDC:BA98:7654:3210:FEDC:BA98:7654:3210]:10",  // No scheme.
       "[fedc:ba98:7654:3210:fedc:ba98:7654:3210]:10", ProxyServer::SCHEME_HTTP,
       "fedc:ba98:7654:3210:fedc:ba98:7654:3210", 10,
       "PROXY [fedc:ba98:7654:3210:fedc:ba98:7654:3210]:10"},
      {"http://[::192.9.5.5]", "[::c009:505]:80", ProxyServer::SCHEME_HTTP,
       "::c009:505", 80, "PROXY [::c009:505]:80"},
      {"http://[::FFFF:129.144.52.38]:80", "[::ffff:8190:3426]:80",
       ProxyServer::SCHEME_HTTP, "::ffff:8190:3426", 80,
       "PROXY [::ffff:8190:3426]:80"},
      {"http://f\u00fcpy:85", "xn--fpy-hoa:85", ProxyServer::SCHEME_HTTP,
       "xn--fpy-hoa", 85, "PROXY xn--fpy-hoa:85"},
      {"https://0xA.020.3.4:443", "https://10.16.3.4:443",
       ProxyServer::SCHEME_HTTPS, "10.16.3.4", 443, "HTTPS 10.16.3.4:443"},
      {"http://FoO.tEsT:80", "foo.test:80", ProxyServer::SCHEME_HTTP,
       "foo.test", 80, "PROXY foo.test:80"},
  };

  for (const auto& test : tests) {
    ProxyServer uri = ProxyUriToProxyServer(
        test.input_uri, ProxyServer::SCHEME_HTTP, /*is_quic_allowed=*/true);
    EXPECT_TRUE(uri.is_valid());
    EXPECT_EQ(test.expected_uri, ProxyServerToProxyUri(uri));
    EXPECT_EQ(test.expected_scheme, uri.scheme());
    EXPECT_EQ(test.expected_host, uri.host_port_pair().host());
    EXPECT_EQ(test.expected_port, uri.host_port_pair().port());
    EXPECT_EQ(test.expected_pac_string, ProxyServerToPacResultElement(uri));
  }
}

#if BUILDFLAG(ENABLE_QUIC_PROXY_SUPPORT)
// In a build where the quic proxy support build flag is enabled, if the
// boolean for allowing quic proxy support is false, it will be considered in an
// invalid scheme as QUIC should not be parsed.
TEST(ProxySpecificationUtilTest,
     ProxyUriToProxyServerBuildFlagEnabledQuicDisallowedIsInvalid) {
  ProxyServer proxy_server = ProxyUriToProxyServer(
      "quic://foopy:443", ProxyServer::SCHEME_HTTP, /*is_quic_allowed=*/false);
  EXPECT_FALSE(proxy_server.is_valid());
  EXPECT_EQ(ProxyServer::SCHEME_INVALID, proxy_server.scheme());
}
#else
// In a build where the quic proxy support build flag is disabled, if the
// boolean for allowing quic proxy support is true, it will be considered in an
// invalid scheme as QUIC is not allowed in this type of build.
TEST(ProxySpecificationUtilTest,
     ProxyUriToProxyServerBuildFlagDisabledQuicAllowedIsInvalid) {
  ProxyServer proxy_server = ProxyUriToProxyServer(
      "quic://foopy:443", ProxyServer::SCHEME_HTTP, /*is_quic_allowed=*/true);
  EXPECT_FALSE(proxy_server.is_valid());
  EXPECT_EQ(ProxyServer::SCHEME_INVALID, proxy_server.scheme());
}
#endif  // BUILDFLAG(ENABLE_QUIC_PROXY_SUPPORT)

// Test parsing of the special URI form "direct://".
TEST(ProxySpecificationUtilTest, DirectProxyUriToProxyChain) {
  const char* const uris[] = {
      "direct://",
      "DIRECT://",
      "DiReCt://",
  };

  for (const char* uri : uris) {
    ProxyChain valid_uri = ProxyUriToProxyChain(uri, ProxyServer::SCHEME_HTTP);
    EXPECT_TRUE(valid_uri.IsValid());
    EXPECT_TRUE(valid_uri.is_direct());
  }

  // Direct is not allowed a host/port.
  ProxyChain invalid_uri =
      ProxyUriToProxyChain("direct://xyz", ProxyServer::SCHEME_HTTP);
  EXPECT_FALSE(invalid_uri.IsValid());
  EXPECT_FALSE(invalid_uri.is_direct());
}

// A multi-proxy string containing URIs is not acceptable input for the
// ProxyUriToProxyChain function and should return an invalid `ProxyChain()`.
TEST(ProxySpecificationUtilTest, ProxyUriToProxyChainWithBracketsInvalid) {
  // Release builds should return an invalid proxy chain for multi-proxy chains.
  const char* const invalid_multi_proxy_uris[] = {
      "[]",
      "[direct://]",
      "[https://foopy]",
      "[https://foopy https://hoopy]",
  };

  for (const char* uri : invalid_multi_proxy_uris) {
    ProxyChain multi_proxy_uri =
        ProxyUriToProxyChain(uri, ProxyServer::SCHEME_HTTP);
    EXPECT_FALSE(multi_proxy_uri.IsValid());
    EXPECT_FALSE(multi_proxy_uri.is_direct());
  }
}

// Test parsing some invalid inputs.
TEST(ProxySpecificationUtilTest, InvalidProxyUriToProxyServer) {
  const char* const tests[] = {
      "",
      "   ",
      "dddf:",         // not a valid port
      "dddd:d",        // not a valid port
      "http://",       // not a valid host/port.
      "direct://",     // direct is not a valid proxy server.
      "http:/",        // ambiguous, but will fail because of bad port.
      "http:",         // ambiguous, but will fail because of bad port.
      "foopy.111",     // Interpreted as invalid IPv4 address.
      "foo.test/"      // Paths disallowed.
      "foo.test:123/"  // Paths disallowed.
      "foo.test/foo"   // Paths disallowed.
  };

  for (const char* test : tests) {
    SCOPED_TRACE(test);
    ProxyServer uri = ProxyUriToProxyServer(test, ProxyServer::SCHEME_HTTP);
    EXPECT_FALSE(uri.is_valid());
    EXPECT_FALSE(uri.is_http());
    EXPECT_FALSE(uri.is_socks());
  }
}

// Test that LWS (SP | HT) is disregarded from the ends.
TEST(ProxySpecificationUtilTest, WhitespaceProxyUriToProxyServer) {
  const char* const tests[] = {
      "  foopy:80",
      "foopy:80   \t",
      "  \tfoopy:80  ",
  };

  for (const char* test : tests) {
    ProxyServer uri = ProxyUriToProxyServer(test, ProxyServer::SCHEME_HTTP);
    EXPECT_EQ("foopy:80", ProxyServerToProxyUri(uri));
  }
}

// Test parsing a ProxyServer from a PAC representation.
TEST(ProxySpecificationUtilTest, PacResultElementToProxyServer) {
  const struct {
    const char* const input_pac;
    const char* const expected_uri;
  } tests[] = {
      {
          "PROXY foopy:10",
          "foopy:10",
      },
      {
          "   PROXY    foopy:10   ",
          "foopy:10",
      },
      {
          "pRoXy foopy:10",
          "foopy:10",
      },
      {
          "PROXY foopy",  // No port.
          "foopy:80",
      },
      {
          "socks foopy",
          "socks4://foopy:1080",
      },
      {
          "socks4 foopy",
          "socks4://foopy:1080",
      },
      {
          "socks5 foopy",
          "socks5://foopy:1080",
      },
      {
          "socks5 foopy:11",
          "socks5://foopy:11",
      },
      {
          "https foopy",
          "https://foopy:443",
      },
      {
          "https foopy:10",
          "https://foopy:10",
      },
      {"PROXY [FEDC:BA98:7654:3210:FEDC:BA98:7654:3210]:10",
       "[fedc:ba98:7654:3210:fedc:ba98:7654:3210]:10"},
      {"PROXY f\u00fcpy:85", "xn--fpy-hoa:85"},
  };

  for (const auto& test : tests) {
    SCOPED_TRACE(test.input_pac);
    ProxyServer server = PacResultElementToProxyServer(test.input_pac);
    EXPECT_TRUE(server.is_valid());
    EXPECT_EQ(test.expected_uri, ProxyServerToProxyUri(server));

    ProxyChain chain = PacResultElementToProxyChain(test.input_pac);
    EXPECT_TRUE(chain.IsValid());
    if (!chain.is_direct()) {
      EXPECT_EQ(test.expected_uri, ProxyServerToProxyUri(chain.First()));
    }
  }
}

// Test parsing a ProxyServer from an invalid PAC representation.
TEST(ProxySpecificationUtilTest, InvalidPacResultElementToProxyServer) {
  const char* const tests[] = {
      "PROXY",                   // missing host/port.
      "HTTPS",                   // missing host/port.
      "SOCKS",                   // missing host/port.
      "DIRECT foopy:10",         // direct cannot have host/port.
      "INVALIDSCHEME",           // unrecognized scheme.
      "INVALIDSCHEME foopy:10",  // unrecognized scheme.
      "HTTP foopy:10",           // http scheme should be "PROXY"
  };

  for (const char* test : tests) {
    SCOPED_TRACE(test);
    ProxyServer server = PacResultElementToProxyServer(test);
    EXPECT_FALSE(server.is_valid());

    ProxyChain chain = PacResultElementToProxyChain(test);
    EXPECT_FALSE(chain.IsValid());
  }
}

#if BUILDFLAG(ENABLE_BRACKETED_PROXY_URIS)
// A multi-proxy chain that contains any mention of direct will be considered an
// invalid `ProxyChain()`.
TEST(ProxySpecificationUtilTest,
     MultiProxyUrisToProxyChainMultiProxyDirectIsInvalid) {
  const char* const invalid_multi_proxy_uris[] = {
      "[direct://xyz]",             // direct with ports
      "[direct:// direct://]",      // Two directs in chain
      "[direct:// https://foopy]",  // direct first in chain
      "[https://foopy direct://]",  // direct later in chain
  };

  for (const char* uri : invalid_multi_proxy_uris) {
    ProxyChain multi_proxy_uri =
        MultiProxyUrisToProxyChain(uri, ProxyServer::SCHEME_HTTPS);
    EXPECT_FALSE(multi_proxy_uri.IsValid());
    EXPECT_FALSE(multi_proxy_uri.is_direct());
  }
}

// A input containing a single uri of direct will be valid.
TEST(ProxySpecificationUtilTest,
     MultiProxyUrisToProxyChainSingleDirectIsValid) {
  const char* const valid_direct_uris[] = {
      "direct://",    // non-bracketed direct
      "[direct://]",  // bracketed direct
  };

  for (const char* uri : valid_direct_uris) {
    ProxyChain multi_proxy_uri =
        MultiProxyUrisToProxyChain(uri, ProxyServer::SCHEME_HTTPS);
    EXPECT_TRUE(multi_proxy_uri.IsValid());
    EXPECT_TRUE(multi_proxy_uri.is_direct());
  }
}

TEST(ProxySpecificationUtilTest, MultiProxyUrisToProxyChainValid) {
  const struct {
    const char* const input_uri;
    const std::vector<std::string> expected_uris;
    ProxyServer::Scheme expected_scheme;
  } tests[] = {
      // 1 Proxy (w/ and w/o brackets):
      {"[https://foopy:443]", {"https://foopy:443"}, ProxyServer::SCHEME_HTTPS},
      {"https://foopy:443", {"https://foopy:443"}, ProxyServer::SCHEME_HTTPS},

      // 2 Proxies:
      {"[https://foopy:443 https://hoopy:443]",
       {"https://foopy:443", "https://hoopy:443"},
       ProxyServer::SCHEME_HTTPS},

      // Extra padding in uris string ignored:
      {" [https://foopy:443 https://hoopy:443] ",
       {"https://foopy:443", "https://hoopy:443"},
       ProxyServer::SCHEME_HTTPS},
      {"[\thttps://foopy:443 https://hoopy:443\t       ] ",
       {"https://foopy:443", "https://hoopy:443"},
       ProxyServer::SCHEME_HTTPS},
      {"     \t[       https://foopy:443 https://hoopy:443\t        ]",
       {"https://foopy:443", "https://hoopy:443"},
       ProxyServer::SCHEME_HTTPS},
      {"[https://foopy:443  https://hoopy:443]",
       {"https://foopy:443", "https://hoopy:443"},
       ProxyServer::SCHEME_HTTPS},  // Delimiter is two spaces.
      {"[https://foopy \thttps://hoopy]",
       {"https://foopy:443", "https://hoopy:443"},
       ProxyServer::SCHEME_HTTPS},  // Delimiter is followed by tab.

      // 3 Proxies:
      {"[https://foopy:443 https://hoopy:443 https://loopy:443]",
       {"https://foopy:443", "https://hoopy:443", "https://loopy:443"},
       ProxyServer::SCHEME_HTTPS},
  };

  for (const auto& test : tests) {
    ProxyChain proxy_chain =
        MultiProxyUrisToProxyChain(test.input_uri, test.expected_scheme);

    EXPECT_TRUE(proxy_chain.IsValid());
    EXPECT_EQ(proxy_chain.length(), test.expected_uris.size());

    std::vector<ProxyServer> proxies = proxy_chain.proxy_servers();
    for (size_t i = 0; i < proxies.size(); i++) {
      const ProxyServer& proxy = proxies[i];
      EXPECT_TRUE(proxy.is_valid());
      EXPECT_EQ(test.expected_uris[i], ProxyServerToProxyUri(proxy));
    }
  }
}

#if BUILDFLAG(ENABLE_QUIC_PROXY_SUPPORT)
// Quic proxy schemes are parsed properly
TEST(ProxySpecificationUtilTest, MultiProxyUrisToProxyChainValidQuic) {
  const struct {
    const char* const input_uri;
    const std::vector<std::string> expected_uris;
    ProxyServer::Scheme default_scheme;
    const std::vector<ProxyServer::Scheme> expected_schemes;
  } tests[] = {
      // single quic proxy scheme (unbracketed)
      {"quic://foopy",  // missing port number
       {"quic://foopy:443"},
       ProxyServer::SCHEME_HTTP,
       {ProxyServer::SCHEME_QUIC}},
      {"quic://foopy:80",
       {"quic://foopy:80"},
       ProxyServer::SCHEME_HTTP,
       {ProxyServer::SCHEME_QUIC}},

      // single quic proxy scheme (bracketed)
      {"[quic://foopy:80]",
       {"quic://foopy:80"},
       ProxyServer::SCHEME_HTTP,
       {ProxyServer::SCHEME_QUIC}},

      // multi-proxy chain
      // 2 quic schemes in a row
      {"[quic://foopy:80 quic://loopy:80]",
       {"quic://foopy:80", "quic://loopy:80"},
       ProxyServer::SCHEME_HTTP,
       {ProxyServer::SCHEME_QUIC, ProxyServer::SCHEME_QUIC}},
      // Quic scheme followed by HTTPS in a row
      {"[quic://foopy:80 https://loopy:80]",
       {"quic://foopy:80", "https://loopy:80"},
       ProxyServer::SCHEME_HTTP,
       {ProxyServer::SCHEME_QUIC, ProxyServer::SCHEME_HTTPS}},
  };

  for (const auto& test : tests) {
    ProxyChain proxy_chain = MultiProxyUrisToProxyChain(
        test.input_uri, test.default_scheme, /*is_quic_allowed=*/true);

    EXPECT_TRUE(proxy_chain.IsValid());
    EXPECT_EQ(proxy_chain.length(), test.expected_uris.size());

    std::vector<ProxyServer> proxies = proxy_chain.proxy_servers();
    for (size_t i = 0; i < proxies.size(); i++) {
      const ProxyServer& proxy = proxies[i];
      EXPECT_TRUE(proxy.is_valid());
      EXPECT_EQ(test.expected_uris[i], ProxyServerToProxyUri(proxy));
      EXPECT_EQ(test.expected_schemes[i], proxy.scheme());
    }
  }
}

// If a multi-proxy chain contains a quic scheme proxy, it must only be followed
// by another quic or https proxy. This ensures this logic still applies.
TEST(ProxySpecificationUtilTest, MultiProxyUrisToProxyChainInvalidQuicCombo) {
  ProxyChain proxy_chain = MultiProxyUrisToProxyChain(
      "[https://loopy:80 quic://foopy:80]", ProxyServer::SCHEME_HTTP);

  EXPECT_FALSE(proxy_chain.IsValid());
}

#endif  // BUILDFLAG(ENABLE_QUIC_PROXY_SUPPORT)

// If the input URIs is invalid, an invalid `ProxyChain()` will be returned.
TEST(ProxySpecificationUtilTest,
     MultiProxyUrisToProxyChainInvalidFormatReturnsInvalidProxyChain) {
  const char* const invalid_multi_proxy_uris[] = {
      "",                                 // Empty string
      "   ",                              // String with only spaces
      "[]",                               // No proxies within brackets
      "https://foopy https://hoopy",      // Missing brackets
      "[https://foopy https://hoopy",     // Missing bracket
      "https://foopy https://hoopy]",     // Missing bracket
      "https://foopy \t   https://hoopy"  // Missing brackets and bad delimiter
  };

  for (const char* uri : invalid_multi_proxy_uris) {
    ProxyChain multi_proxy_uri =
        MultiProxyUrisToProxyChain(uri, ProxyServer::SCHEME_HTTPS);
    EXPECT_FALSE(multi_proxy_uri.IsValid());
    EXPECT_FALSE(multi_proxy_uri.is_direct());
  }
}
#endif  // BUILDFLAG(ENABLE_BRACKETED_PROXY_URIS)
}  // namespace
}  // namespace net

"""

```