Response:
Let's break down the thought process for analyzing the C++ unittest file `proxy_list_unittest.cc`.

1. **Understand the Goal:** The primary goal is to understand the functionality tested in this file. Since it's a unittest, the code will directly exercise the methods of a specific class or related classes. The filename `proxy_list_unittest.cc` strongly suggests it's testing the `ProxyList` class.

2. **Identify the Target Class:**  Scanning the `#include` directives confirms this: `#include "net/proxy_resolution/proxy_list.h"`. This is the core class under scrutiny.

3. **Examine the Test Structure:** Unit tests in C++ often use a framework like Google Test (gtest). Look for macros like `TEST(TestSuiteName, TestName)`. This helps identify individual test cases.

4. **Analyze Individual Test Cases:** Go through each `TEST` block and determine its purpose. Focus on:
    * **Setup:** What data or objects are created before the main action?
    * **Action:** Which methods of the `ProxyList` class are being called?
    * **Assertions:** What are the `EXPECT_EQ`, `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_DEATH_IF_SUPPORTED`, etc., checking?  These assertions reveal the expected behavior of the method being tested.

5. **Group Functionality by Test:**  As you analyze the tests, you'll notice patterns and repeated calls to certain `ProxyList` methods. This helps group the tests by the functionality they exercise. For example:
    * Tests with "SetFromPacString" are testing parsing PAC strings.
    * Tests with "RemoveProxiesWithoutScheme" are testing filtering by scheme.
    * Tests with "DeprioritizeBadProxyChains" are testing the logic for reordering based on retry information.
    * Tests with "UpdateRetryInfoOnFallback" are testing how retry info is updated.
    * Tests with "ToPacString", "ToDebugString", and "ToValue" are testing different string representations of the `ProxyList`.

6. **Consider Edge Cases and Error Handling:** Unit tests often explicitly test how the code handles invalid input or error conditions. Look for tests that use "invalid inputs" or that check for specific error conditions. The `EXPECT_DEATH_IF_SUPPORTED` macro is a clear indicator of testing for expected program termination under certain conditions.

7. **Look for Conditional Compilation:** Pay attention to preprocessor directives like `#if BUILDFLAG(...)`. These indicate that certain tests or behaviors might be specific to certain build configurations. In this case, `ENABLE_BRACKETED_PROXY_URIS` enables testing of multi-proxy chains outside of IP Protection.

8. **Relate to Javascript (if applicable):**  Consider how the functionality being tested might be relevant to the browser's interaction with proxy settings, which are often configured or retrieved via Javascript. Think about:
    * How does the browser interpret PAC scripts? The `SetFromPacString` test is directly related to this.
    * How does the browser store and manage proxy configurations?  The different string representations might be used for displaying or serializing this data.
    * How does the browser handle proxy failures and retries? The tests involving `ProxyRetryInfoMap` are relevant here.

9. **Infer Logic and Assumptions:** Based on the test cases, try to infer the underlying logic of the `ProxyList` class. What are the assumptions it makes about proxy configurations? How does it handle different proxy schemes (HTTP, SOCKS, DIRECT)?

10. **Think About User Errors:** Consider how a user's misconfiguration or a programmer's incorrect usage of the `ProxyList` class might lead to issues. The tests with "invalid inputs" provide some clues.

11. **Trace User Actions (Debugging Clues):**  Imagine a user encountering a proxy-related problem. How would their actions lead to the execution of the code being tested?  Think about:
    * User manually configuring proxy settings in the browser.
    * The browser automatically detecting proxy settings (WPAD).
    * Javascript code using the Chrome API to fetch or apply proxy settings.
    * Network requests triggering proxy resolution logic.

12. **Structure the Answer:** Organize the findings into logical sections:
    * **Functionality:** A high-level summary of what the file tests.
    * **Relationship to Javascript:** Explain how the tested functionality connects to browser behavior and potential Javascript interactions.
    * **Logical Reasoning (Input/Output):** Provide concrete examples of how the methods work with specific inputs.
    * **User/Programming Errors:** Illustrate common mistakes.
    * **Debugging Clues (User Operations):** Describe the steps a user might take that lead to this code being executed.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This file just tests parsing proxy strings."  **Correction:**  While parsing is a part of it, the file also tests filtering, prioritization based on retry info, and different string representations.
* **Initial thought:** "The Javascript connection is weak." **Refinement:** Realize that while the C++ code is not directly Javascript, it underlies the browser's proxy handling, which *is* influenced by Javascript (e.g., PAC scripts).
* **Stuck on a particular test:** If a test is unclear, reread the surrounding code, the method being called, and the assertion carefully. Look for comments within the test case.
* **Missing a key concept:** If a group of tests revolves around an unfamiliar term (like "IP Protection"), research that term in the context of Chromium's proxy implementation.
这个文件 `net/proxy_resolution/proxy_list_unittest.cc` 是 Chromium 网络栈中用于测试 `ProxyList` 类的单元测试文件。 `ProxyList` 类负责管理和操作代理服务器列表。

**主要功能:**

该文件主要测试 `ProxyList` 类的以下功能：

1. **解析 PAC (Proxy Auto-Config) 字符串:**
   - 测试 `SetFromPacString()` 方法，该方法用于从 PAC 字符串解析代理服务器列表。
   - 验证不同格式的 PAC 字符串（包括 `PROXY`, `DIRECT`, `SOCKS`, `SOCKS5` 等指令）是否能被正确解析成 `ProxyList` 对象。
   - 测试解析过程中对空格、分隔符的处理。
   - 测试解析过程中对无效或无法识别的代理指令的处理（会被忽略并回退到 `DIRECT`）。

2. **移除特定类型的代理服务器:**
   - 测试 `RemoveProxiesWithoutScheme()` 方法，该方法用于移除不属于指定协议类型的代理服务器。
   - 可以根据代理服务器的 scheme (例如 `SCHEME_HTTP`, `SCHEME_SOCKS5`) 进行过滤。
   - 同时也测试了在代理链 (`ProxyChain`) 的情况下，如何根据 scheme 进行移除。

3. **根据重试信息调整代理服务器优先级:**
   - 测试 `DeprioritizeBadProxyChains()` 方法，该方法根据 `ProxyRetryInfoMap` 中记录的代理服务器重试信息，将标记为“坏”的代理服务器排到列表末尾。
   - 模拟不同的重试状态（例如，标记为坏但允许重试，标记为坏且不允许重试）来验证排序逻辑。
   - 测试当所有代理都被标记为坏的情况。

4. **根据回退事件更新重试信息:**
   - 测试 `UpdateRetryInfoOnFallback()` 方法，该方法在连接代理失败时更新 `ProxyRetryInfoMap`。
   - 验证在回退到下一个代理时，会将失败的代理信息添加到重试列表中，并设置相应的重试延迟和错误信息。
   - 测试当回退到 `DIRECT` 连接时，是否不会添加重试信息。
   - 测试当代理已经存在于重试列表时，如何更新重试信息（保留较长的重试时间）。

5. **生成不同格式的字符串表示:**
   - 测试 `ToPacString()` 方法，该方法将 `ProxyList` 转换为 PAC 格式的字符串。
   - 测试 `ToDebugString()` 方法，该方法生成更易于调试的字符串表示，包含代理服务器的 scheme、主机和端口。
   - 测试 `ToValue()` 方法，该方法生成 `base::Value` 类型的表示，用于序列化和日志记录。

**与 Javascript 的关系:**

该文件测试的功能与 Javascript 在以下方面存在关系：

1. **PAC 脚本:**  `SetFromPacString()` 方法直接关联到浏览器对 PAC 脚本的解析。当用户配置了 PAC URL 或嵌入式的 PAC 脚本时，浏览器会下载或执行该脚本，并将其返回的代理字符串传递给类似 `ProxyList` 这样的 C++ 类进行解析。

   **举例说明:**
   假设一个 PAC 脚本返回字符串 `"PROXY proxy1.example.com:8080; SOCKS5 socks.example.com:1080; DIRECT"`。浏览器在获取到这个字符串后，会调用 C++ 代码（通过内部接口）将这个字符串传递给 `ProxyList::SetFromPacString()`，这个测试文件中的 `TEST(ProxyListTest, SetFromPacString)` 就是在验证这种解析过程的正确性。

2. **Chrome 扩展 API (chrome.proxy):**  Chrome 扩展程序可以使用 `chrome.proxy` API 来动态配置浏览器的代理设置。这些设置最终也会被转换为 `ProxyList` 对象。

   **举例说明:**
   一个 Chrome 扩展程序可以使用以下 Javascript 代码来设置代理：

   ```javascript
   chrome.proxy.settings.set({
       value: {
           mode: "fixed_servers",
           rules: {
               proxyRules: "proxy1.example.com:8080,socks5://socks.example.com:1080"
           }
       },
       scope: 'regular'
   }, function() {
       console.log("Proxy settings applied.");
   });
   ```

   在幕后，Chromium 会将这个 Javascript 配置转换为一个 `ProxyList` 对象，并应用到网络请求中。虽然 Javascript 不直接调用 `ProxyList` 的方法，但它控制着代理配置的来源，而 `ProxyList` 负责处理这些配置。

**逻辑推理 (假设输入与输出):**

**假设输入 (PAC 字符串):** `"PROXY webproxy:80; SOCKS my.socks.server:1080"`

**预期输出 (`ToDebugString()`):** `"PROXY webproxy:80;SOCKS my.socks.server:1080"`

**假设输入 (初始 `ProxyList`):**  包含 `PROXY badproxy:80`, `PROXY goodproxy:80` 两个代理。
**假设输入 (`ProxyRetryInfoMap`):**  标记 `badproxy:80` 为连接失败。

**预期输出 (`DeprioritizeBadProxyChains()` 后的 `ToDebugString()`):** `"PROXY goodproxy:80;PROXY badproxy:80"` (坏的代理被排到后面)

**涉及用户或编程常见的使用错误:**

1. **错误的 PAC 字符串格式:** 用户或程序生成的 PAC 字符串格式不正确，例如缺少分隔符、代理类型拼写错误等。
   **例子:** `"PROXY webproxy:80 SOCKS my.socks.server:1080"` (缺少分号分隔符)。`ProxyList` 会尽力解析，但可能会忽略错误的部分或回退到 `DIRECT`。

2. **指定不支持的代理类型:** PAC 字符串中使用了 Chromium 不支持的代理类型。
   **例子:** `"HTTP webproxy:80"` (Chromium 中通常使用 `PROXY` 表示 HTTP 代理)。`ProxyList` 会忽略这种无法识别的类型。

3. **编程时错误地假设 `ToPacString()` 可以处理所有类型的 `ProxyList`:**  `ToPacString()` 不能表示复杂的代理链 (`ProxyChain`)，尝试对包含代理链的 `ProxyList` 调用 `ToPacString()` 会导致断言失败（在非 release 版本）。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户手动配置代理:**
   - 用户打开 Chromium 的设置。
   - 找到 "网络" 或 "代理" 设置。
   - 选择 "手动配置代理服务器"。
   - 输入代理服务器地址和端口（可能包括多个代理，用分号分隔）。
   - 用户点击 "保存"。
   - Chromium 会将用户输入的字符串传递给 `ProxyList::SetFromPacString()` 或类似的函数进行解析。

2. **用户配置 PAC URL:**
   - 用户在代理设置中选择 "自动检测代理设置" 或 "使用代理自动配置脚本"。
   - 输入 PAC 文件的 URL。
   - Chromium 会下载 PAC 文件。
   - 当需要解析代理时，Chromium 会执行 PAC 脚本，并将其返回的代理字符串传递给 `ProxyList` 进行处理。

3. **Chrome 扩展程序修改代理设置:**
   - 用户安装了一个可以管理代理设置的 Chrome 扩展程序。
   - 扩展程序使用 `chrome.proxy` API 来设置代理。
   - Chromium 会将扩展程序提供的配置转换为 `ProxyList` 对象。

4. **WPAD (Web Proxy Auto-Discovery):**
   - 在某些网络环境中，Chromium 会尝试自动发现 PAC 文件。
   - 一旦找到 PAC 文件并下载，其解析过程与用户配置 PAC URL 类似。

当网络请求发生，并且需要确定使用哪个代理服务器时，Chromium 会使用 `ProxyList` 对象中存储的代理信息。如果连接代理失败，就会调用 `ProxyList::UpdateRetryInfoOnFallback()` 来更新重试信息。后续的网络请求可能会调用 `ProxyList::DeprioritizeBadProxyChains()` 来调整代理服务器的尝试顺序。

因此，`proxy_list_unittest.cc` 中测试的 `ProxyList` 类的功能是网络栈中处理代理配置的核心部分，涉及到用户通过各种方式配置代理，以及 Chromium 如何根据这些配置选择和重试代理服务器。

### 提示词
```
这是目录为net/proxy_resolution/proxy_list_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2006-2008 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/proxy_resolution/proxy_list.h"

#include <vector>

#include "base/logging.h"
#include "build/buildflag.h"
#include "net/base/net_errors.h"
#include "net/base/proxy_server.h"
#include "net/base/proxy_string_util.h"
#include "net/log/net_log_with_source.h"
#include "net/net_buildflags.h"
#include "net/proxy_resolution/proxy_retry_info.h"
#include "net/test/gtest_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using net::test::IsOk;

namespace net {

namespace {

// Test parsing from a PAC string.
TEST(ProxyListTest, SetFromPacString) {
  const struct {
    const char* pac_input;
    const char* debug_output;
  } tests[] = {
      // Valid inputs:
      {
          "PROXY foopy:10",
          "PROXY foopy:10",
      },
      {
          " DIRECT",  // leading space.
          "DIRECT",
      },
      {
          "PROXY foopy1 ; proxy foopy2;\t DIRECT",
          "PROXY foopy1:80;PROXY foopy2:80;DIRECT",
      },
      {
          "proxy foopy1 ; SOCKS foopy2",
          "PROXY foopy1:80;SOCKS foopy2:1080",
      },
      // Try putting DIRECT first.
      {
          "DIRECT ; proxy foopy1 ; DIRECT ; SOCKS5 foopy2;DIRECT ",
          "DIRECT;PROXY foopy1:80;DIRECT;SOCKS5 foopy2:1080;DIRECT",
      },
      // Try putting DIRECT consecutively.
      {
          "DIRECT ; proxy foopy1:80; DIRECT ; DIRECT",
          "DIRECT;PROXY foopy1:80;DIRECT;DIRECT",
      },

      // Invalid inputs (parts which aren't understood get
      // silently discarded):
      //
      // If the proxy list string parsed to empty, automatically fall-back to
      // DIRECT.
      {
          "PROXY-foopy:10",
          "DIRECT",
      },
      {
          "PROXY",
          "DIRECT",
      },
      {
          "PROXY foopy1 ; JUNK ; JUNK ; SOCKS5 foopy2 ; ;",
          "PROXY foopy1:80;SOCKS5 foopy2:1080",
      },
  };

  for (const auto& test : tests) {
    ProxyList list;
    list.SetFromPacString(test.pac_input);
    EXPECT_EQ(test.debug_output, list.ToDebugString());
    EXPECT_FALSE(list.IsEmpty());
  }
}

TEST(ProxyListTest, RemoveProxiesWithoutScheme) {
  const struct {
    const char* pac_input;
    int filter;
    const char* filtered_debug_output;
  } tests[] = {
      {
          "PROXY foopy:10 ; SOCKS5 foopy2 ; SOCKS foopy11 ; PROXY foopy3 ; "
          "DIRECT",
          // Remove anything that isn't HTTP.
          ProxyServer::SCHEME_HTTP,
          "PROXY foopy:10;PROXY foopy3:80;DIRECT",
      },
      {
          "PROXY foopy:10 ; SOCKS5 foopy2",
          // Remove anything that isn't HTTP or SOCKS5.
          ProxyServer::SCHEME_SOCKS4,
          "",
      },
  };

  for (const auto& test : tests) {
    ProxyList list;
    list.SetFromPacString(test.pac_input);
    list.RemoveProxiesWithoutScheme(test.filter);
    EXPECT_EQ(test.filtered_debug_output, list.ToDebugString());
  }
}

TEST(ProxyListTest, RemoveProxiesWithoutSchemeWithProxyChains) {
  const auto kProxyChainFooHttps = ProxyChain::ForIpProtection({
      ProxyServer::FromSchemeHostAndPort(ProxyServer::Scheme::SCHEME_HTTPS,
                                         "foo-a", 443),
      ProxyServer::FromSchemeHostAndPort(ProxyServer::Scheme::SCHEME_HTTPS,
                                         "foo-b", 443),
  });
  const auto kProxyChainBarMixed = ProxyChain::ForIpProtection({
      ProxyServer::FromSchemeHostAndPort(ProxyServer::Scheme::SCHEME_QUIC,
                                         "bar-a", 443),
      ProxyServer::FromSchemeHostAndPort(ProxyServer::Scheme::SCHEME_HTTPS,
                                         "bar-b", 443),
  });
  const ProxyChain kProxyChainGraultSocks = ProxyChain::FromSchemeHostAndPort(
      ProxyServer::Scheme::SCHEME_SOCKS4, "grault", 443);

  ProxyList list;
  list.AddProxyChain(kProxyChainFooHttps);
  list.AddProxyChain(kProxyChainBarMixed);
  list.AddProxyChain(kProxyChainGraultSocks);
  list.AddProxyChain(ProxyChain::Direct());

  // Remove anything that isn't entirely HTTPS.
  list.RemoveProxiesWithoutScheme(ProxyServer::SCHEME_HTTPS);

  std::vector<net::ProxyChain> expected = {
      kProxyChainFooHttps,
      ProxyChain::Direct(),
  };
  EXPECT_EQ(list.AllChains(), expected);
}

TEST(ProxyListTest, DeprioritizeBadProxyChains) {
  // Retry info that marks a proxy as being bad for a *very* long time (to avoid
  // the test depending on the current time.)
  ProxyRetryInfo proxy_retry_info;
  proxy_retry_info.bad_until = base::TimeTicks::Now() + base::Days(1);

  // Call DeprioritizeBadProxyChains with an empty map -- should have no effect.
  {
    ProxyList list;
    list.SetFromPacString("PROXY foopy1:80;PROXY foopy2:80;PROXY foopy3:80");

    ProxyRetryInfoMap retry_info_map;
    list.DeprioritizeBadProxyChains(retry_info_map);
    EXPECT_EQ("PROXY foopy1:80;PROXY foopy2:80;PROXY foopy3:80",
              list.ToDebugString());
  }

  // Call DeprioritizeBadProxyChains with 2 of the three chains marked as bad.
  // These proxies should be retried last.
  {
    ProxyList list;
    list.SetFromPacString("PROXY foopy1:80;PROXY foopy2:80;PROXY foopy3:80");

    ProxyRetryInfoMap retry_info_map;
    retry_info_map[ProxyUriToProxyChain(
        "foopy1:80", ProxyServer::SCHEME_HTTP)] = proxy_retry_info;
    retry_info_map[ProxyUriToProxyChain(
        "foopy3:80", ProxyServer::SCHEME_HTTP)] = proxy_retry_info;
    retry_info_map[ProxyUriToProxyChain("socks5://localhost:1080",
                                        ProxyServer::SCHEME_HTTP)] =
        proxy_retry_info;

    list.DeprioritizeBadProxyChains(retry_info_map);

    EXPECT_EQ("PROXY foopy2:80;PROXY foopy1:80;PROXY foopy3:80",
              list.ToDebugString());
  }

  // Call DeprioritizeBadProxyChains where ALL of the chains are marked as bad.
  // This should have no effect on the order.
  {
    ProxyList list;
    list.SetFromPacString("PROXY foopy1:80;PROXY foopy2:80;PROXY foopy3:80");

    ProxyRetryInfoMap retry_info_map;
    retry_info_map[ProxyUriToProxyChain(
        "foopy1:80", ProxyServer::SCHEME_HTTP)] = proxy_retry_info;
    retry_info_map[ProxyUriToProxyChain(
        "foopy2:80", ProxyServer::SCHEME_HTTP)] = proxy_retry_info;
    retry_info_map[ProxyUriToProxyChain(
        "foopy3:80", ProxyServer::SCHEME_HTTP)] = proxy_retry_info;

    list.DeprioritizeBadProxyChains(retry_info_map);

    EXPECT_EQ("PROXY foopy1:80;PROXY foopy2:80;PROXY foopy3:80",
              list.ToDebugString());
  }

  // Call DeprioritizeBadProxyChains with 2 of the three chains marked as bad.
  // Of the 2 bad proxies, one is to be reconsidered and should be retried last.
  // The other is not to be reconsidered and should be removed from the list.
  {
    ProxyList list;
    list.SetFromPacString("PROXY foopy1:80;PROXY foopy2:80;PROXY foopy3:80");

    ProxyRetryInfoMap retry_info_map;
    // |proxy_retry_info.reconsider defaults to true.
    retry_info_map[ProxyUriToProxyChain(
        "foopy1:80", ProxyServer::SCHEME_HTTP)] = proxy_retry_info;
    proxy_retry_info.try_while_bad = false;
    retry_info_map[ProxyUriToProxyChain(
        "foopy3:80", ProxyServer::SCHEME_HTTP)] = proxy_retry_info;
    proxy_retry_info.try_while_bad = true;
    retry_info_map[ProxyUriToProxyChain("socks5://localhost:1080",
                                        ProxyServer::SCHEME_SOCKS5)] =
        proxy_retry_info;

    list.DeprioritizeBadProxyChains(retry_info_map);

    EXPECT_EQ("PROXY foopy2:80;PROXY foopy1:80", list.ToDebugString());
  }
}

TEST(ProxyListTest, UpdateRetryInfoOnFallback) {
  // Retrying should put the first proxy on the retry list.
  {
    ProxyList list;
    ProxyRetryInfoMap retry_info_map;
    NetLogWithSource net_log;
    ProxyChain proxy_chain(
        ProxyUriToProxyChain("foopy1:80", ProxyServer::SCHEME_HTTP));
    std::vector<ProxyChain> bad_proxies;
    bad_proxies.push_back(proxy_chain);
    list.SetFromPacString("PROXY foopy1:80;PROXY foopy2:80;PROXY foopy3:80");
    list.UpdateRetryInfoOnFallback(&retry_info_map, base::Seconds(60), true,
                                   bad_proxies, ERR_PROXY_CONNECTION_FAILED,
                                   net_log);
    EXPECT_TRUE(retry_info_map.end() != retry_info_map.find(proxy_chain));
    EXPECT_EQ(ERR_PROXY_CONNECTION_FAILED,
              retry_info_map[proxy_chain].net_error);
    EXPECT_TRUE(retry_info_map.end() ==
                retry_info_map.find(ProxyUriToProxyChain(
                    "foopy2:80", ProxyServer::SCHEME_HTTP)));
    EXPECT_TRUE(retry_info_map.end() ==
                retry_info_map.find(ProxyUriToProxyChain(
                    "foopy3:80", ProxyServer::SCHEME_HTTP)));
  }
  // Retrying should put the first proxy on the retry list, even if there
  // was no network error.
  {
    ProxyList list;
    ProxyRetryInfoMap retry_info_map;
    NetLogWithSource net_log;
    ProxyChain proxy_chain(
        ProxyUriToProxyChain("foopy1:80", ProxyServer::SCHEME_HTTP));
    std::vector<ProxyChain> bad_proxies;
    bad_proxies.push_back(proxy_chain);
    list.SetFromPacString("PROXY foopy1:80;PROXY foopy2:80;PROXY foopy3:80");
    list.UpdateRetryInfoOnFallback(&retry_info_map, base::Seconds(60), true,
                                   bad_proxies, OK, net_log);
    EXPECT_TRUE(retry_info_map.end() != retry_info_map.find(proxy_chain));
    EXPECT_THAT(retry_info_map[proxy_chain].net_error, IsOk());
    EXPECT_TRUE(retry_info_map.end() ==
                retry_info_map.find(ProxyUriToProxyChain(
                    "foopy2:80", ProxyServer::SCHEME_HTTP)));
    EXPECT_TRUE(retry_info_map.end() ==
                retry_info_map.find(ProxyUriToProxyChain(
                    "foopy3:80", ProxyServer::SCHEME_HTTP)));
  }
  // Including another bad proxy should put both the first and the specified
  // proxy on the retry list.
  {
    ProxyList list;
    ProxyRetryInfoMap retry_info_map;
    NetLogWithSource net_log;
    ProxyChain proxy_chain(
        ProxyUriToProxyChain("foopy3:80", ProxyServer::SCHEME_HTTP));
    std::vector<ProxyChain> bad_proxies;
    bad_proxies.push_back(proxy_chain);
    list.SetFromPacString("PROXY foopy1:80;PROXY foopy2:80;PROXY foopy3:80");
    list.UpdateRetryInfoOnFallback(&retry_info_map, base::Seconds(60), true,
                                   bad_proxies, ERR_NAME_RESOLUTION_FAILED,
                                   net_log);
    EXPECT_TRUE(retry_info_map.end() !=
                retry_info_map.find(ProxyUriToProxyChain(
                    "foopy1:80", ProxyServer::SCHEME_HTTP)));
    EXPECT_EQ(ERR_NAME_RESOLUTION_FAILED,
              retry_info_map[proxy_chain].net_error);
    EXPECT_TRUE(retry_info_map.end() ==
                retry_info_map.find(ProxyUriToProxyChain(
                    "foopy2:80", ProxyServer::SCHEME_HTTP)));
    EXPECT_TRUE(retry_info_map.end() != retry_info_map.find(proxy_chain));
  }
  // If the first proxy is DIRECT, nothing is added to the retry list, even
  // if another bad proxy is specified.
  {
    ProxyList list;
    ProxyRetryInfoMap retry_info_map;
    NetLogWithSource net_log;
    ProxyChain proxy_chain(
        ProxyUriToProxyChain("foopy2:80", ProxyServer::SCHEME_HTTP));
    std::vector<ProxyChain> bad_proxies;
    bad_proxies.push_back(proxy_chain);
    list.SetFromPacString("DIRECT;PROXY foopy2:80;PROXY foopy3:80");
    list.UpdateRetryInfoOnFallback(&retry_info_map, base::Seconds(60), true,
                                   bad_proxies, OK, net_log);
    EXPECT_TRUE(retry_info_map.end() == retry_info_map.find(proxy_chain));
    EXPECT_TRUE(retry_info_map.end() ==
                retry_info_map.find(ProxyUriToProxyChain(
                    "foopy3:80", ProxyServer::SCHEME_HTTP)));
  }
  // If the bad proxy is already on the retry list, and the old retry info would
  // cause the proxy to be retried later than the newly specified retry info,
  // then the old retry info should be kept.
  {
    ProxyList list;
    ProxyRetryInfoMap retry_info_map;
    NetLogWithSource net_log;
    list.SetFromPacString("PROXY foopy1:80;PROXY foopy2:80;PROXY foopy3:80");

    // First, mark the proxy as bad for 60 seconds.
    list.UpdateRetryInfoOnFallback(&retry_info_map, base::Seconds(60), true,
                                   std::vector<ProxyChain>(),
                                   ERR_PROXY_CONNECTION_FAILED, net_log);
    // Next, mark the same proxy as bad for 1 second. This call should have no
    // effect, since this would cause the bad proxy to be retried sooner than
    // the existing retry info.
    list.UpdateRetryInfoOnFallback(&retry_info_map, base::Seconds(1), false,
                                   std::vector<ProxyChain>(), OK, net_log);
    ProxyChain proxy_chain(
        ProxyUriToProxyChain("foopy1:80", ProxyServer::SCHEME_HTTP));
    EXPECT_TRUE(retry_info_map.end() != retry_info_map.find(proxy_chain));
    EXPECT_EQ(ERR_PROXY_CONNECTION_FAILED,
              retry_info_map[proxy_chain].net_error);
    EXPECT_TRUE(retry_info_map[proxy_chain].try_while_bad);
    EXPECT_EQ(base::Seconds(60), retry_info_map[proxy_chain].current_delay);
    EXPECT_GT(retry_info_map[proxy_chain].bad_until,
              base::TimeTicks::Now() + base::Seconds(30));
    EXPECT_TRUE(retry_info_map.end() ==
                retry_info_map.find(ProxyUriToProxyChain(
                    "foopy2:80", ProxyServer::SCHEME_HTTP)));
    EXPECT_TRUE(retry_info_map.end() ==
                retry_info_map.find(ProxyUriToProxyChain(
                    "foopy3:80", ProxyServer::SCHEME_HTTP)));
  }
  // If the bad proxy is already on the retry list, and the newly specified
  // retry info would cause the proxy to be retried later than the old retry
  // info, then the old retry info should be replaced with the new retry info.
  {
    ProxyList list;
    ProxyRetryInfoMap retry_info_map;
    NetLogWithSource net_log;
    list.SetFromPacString("PROXY foopy1:80;PROXY foopy2:80;PROXY foopy3:80");

    // First, mark the proxy as bad for 1 second.
    list.UpdateRetryInfoOnFallback(&retry_info_map, base::Seconds(1), false,
                                   std::vector<ProxyChain>(), OK, net_log);
    // Next, mark the same proxy as bad for 60 seconds. This call should replace
    // the existing retry info with the new 60 second retry info.
    list.UpdateRetryInfoOnFallback(&retry_info_map, base::Seconds(60), true,
                                   std::vector<ProxyChain>(),
                                   ERR_PROXY_CONNECTION_FAILED, net_log);
    ProxyChain proxy_chain(
        ProxyUriToProxyChain("foopy1:80", ProxyServer::SCHEME_HTTP));
    EXPECT_TRUE(retry_info_map.end() != retry_info_map.find(proxy_chain));
    EXPECT_EQ(ERR_PROXY_CONNECTION_FAILED,
              retry_info_map[proxy_chain].net_error);
    EXPECT_TRUE(retry_info_map[proxy_chain].try_while_bad);
    EXPECT_EQ(base::Seconds(60), retry_info_map[proxy_chain].current_delay);
    EXPECT_GT(retry_info_map[proxy_chain].bad_until,
              base::TimeTicks::Now() + base::Seconds(30));
    EXPECT_TRUE(retry_info_map.end() ==
                retry_info_map.find(ProxyUriToProxyChain(
                    "foopy2:80", ProxyServer::SCHEME_HTTP)));
    EXPECT_TRUE(retry_info_map.end() ==
                retry_info_map.find(ProxyUriToProxyChain(
                    "foopy3:80", ProxyServer::SCHEME_HTTP)));
  }
}

TEST(ProxyListTest, ToPacString) {
  ProxyList list;
  list.AddProxyChain(ProxyChain::FromSchemeHostAndPort(
      ProxyServer::Scheme::SCHEME_HTTPS, "foo", 443));
  EXPECT_EQ(list.ToPacString(), "HTTPS foo:443");
  // ToPacString should fail for proxy chains.
  list.AddProxyChain(ProxyChain::ForIpProtection({
      ProxyServer::FromSchemeHostAndPort(ProxyServer::Scheme::SCHEME_HTTPS,
                                         "foo-a", 443),
      ProxyServer::FromSchemeHostAndPort(ProxyServer::Scheme::SCHEME_HTTPS,
                                         "foo-b", 443),
  }));
  EXPECT_DEATH_IF_SUPPORTED(list.ToPacString(), "");
}

TEST(ProxyListTest, ToDebugString) {
  ProxyList list;
  list.AddProxyChain(ProxyChain::FromSchemeHostAndPort(
      ProxyServer::Scheme::SCHEME_HTTPS, "foo", 443));
  list.AddProxyChain(ProxyChain::ForIpProtection({
      ProxyServer::FromSchemeHostAndPort(ProxyServer::Scheme::SCHEME_HTTPS,
                                         "foo-a", 443),
      ProxyServer::FromSchemeHostAndPort(ProxyServer::Scheme::SCHEME_HTTPS,
                                         "foo-b", 443),
  }));

  EXPECT_EQ(
      list.ToDebugString(),
      "HTTPS foo:443;[https://foo-a:443, https://foo-b:443] (IP Protection)");
}

TEST(ProxyListTest, ToValue) {
  ProxyList list;
  list.AddProxyChain(ProxyChain::FromSchemeHostAndPort(
      ProxyServer::Scheme::SCHEME_HTTPS, "foo", 443));
  list.AddProxyChain(ProxyChain::ForIpProtection({
      ProxyServer::FromSchemeHostAndPort(ProxyServer::Scheme::SCHEME_HTTPS,
                                         "foo-a", 443),
      ProxyServer::FromSchemeHostAndPort(ProxyServer::Scheme::SCHEME_HTTPS,
                                         "foo-b", 443),
  }));

  base::Value expected(base::Value::Type::LIST);
  base::Value::List& exp_list = expected.GetList();
  exp_list.Append("[https://foo:443]");
  exp_list.Append("[https://foo-a:443, https://foo-b:443] (IP Protection)");

  EXPECT_EQ(list.ToValue(), expected);
}

#if BUILDFLAG(ENABLE_BRACKETED_PROXY_URIS)
// The following tests are for non-release builds where multi-proxy chains are
// permitted outside of Ip Protection.

TEST(ProxyListTest,
     NonIpProtectionMultiProxyChainRemoveProxiesWithoutSchemeWithProxyChains) {
  const ProxyChain kProxyChainFooHttps({
      ProxyServer::FromSchemeHostAndPort(ProxyServer::Scheme::SCHEME_HTTPS,
                                         "foo-a", 443),
      ProxyServer::FromSchemeHostAndPort(ProxyServer::Scheme::SCHEME_HTTPS,
                                         "foo-b", 443),
  });
  const ProxyChain kProxyChainBarMixed({
      ProxyServer::FromSchemeHostAndPort(ProxyServer::Scheme::SCHEME_QUIC,
                                         "bar-a", 443),
      ProxyServer::FromSchemeHostAndPort(ProxyServer::Scheme::SCHEME_HTTPS,
                                         "bar-b", 443),
  });
  const ProxyChain kProxyChainGraultSocks = ProxyChain::FromSchemeHostAndPort(
      ProxyServer::Scheme::SCHEME_SOCKS4, "grault", 443);

  ProxyList list;
  list.AddProxyChain(kProxyChainFooHttps);
  list.AddProxyChain(kProxyChainBarMixed);
  list.AddProxyChain(kProxyChainGraultSocks);
  list.AddProxyChain(ProxyChain::Direct());

  // Remove anything that isn't entirely HTTPS.
  list.RemoveProxiesWithoutScheme(ProxyServer::SCHEME_HTTPS);

  std::vector<net::ProxyChain> expected = {
      kProxyChainFooHttps,
      ProxyChain::Direct(),
  };
  EXPECT_EQ(list.AllChains(), expected);
}

// `ToPacString` should only be called if the list contains no multi-proxy
// chains, as those cannot be represented in PAC syntax. This is not an issue in
// release builds because a `ProxyChain` constructed with multiple proxy servers
// would automatically default to an empty, invalid
// `ProxyChain` (unless for Ip Protection); however, in non-release builds,
// multi-proxy chains are permitted which means they must be CHECKED when this
// function is called.
TEST(ProxyListTest, NonIpProtectionMultiProxyChainToPacString) {
  ProxyList list;
  list.AddProxyChain(ProxyChain::FromSchemeHostAndPort(
      ProxyServer::Scheme::SCHEME_HTTPS, "foo", 443));
  EXPECT_EQ(list.ToPacString(), "HTTPS foo:443");
  // ToPacString should fail for proxy chains.
  list.AddProxyChain(ProxyChain({
      ProxyServer::FromSchemeHostAndPort(ProxyServer::Scheme::SCHEME_HTTPS,
                                         "foo-a", 443),
      ProxyServer::FromSchemeHostAndPort(ProxyServer::Scheme::SCHEME_HTTPS,
                                         "foo-b", 443),
  }));
  EXPECT_DEATH_IF_SUPPORTED(list.ToPacString(), "");
}

TEST(ProxyListTest, NonIpProtectionMultiProxyChainToDebugString) {
  ProxyList list;
  list.AddProxyChain(ProxyChain::FromSchemeHostAndPort(
      ProxyServer::Scheme::SCHEME_HTTPS, "foo", 443));
  list.AddProxyChain(ProxyChain({
      ProxyServer::FromSchemeHostAndPort(ProxyServer::Scheme::SCHEME_HTTPS,
                                         "foo-a", 443),
      ProxyServer::FromSchemeHostAndPort(ProxyServer::Scheme::SCHEME_HTTPS,
                                         "foo-b", 443),
  }));

  EXPECT_EQ(list.ToDebugString(),
            "HTTPS foo:443;[https://foo-a:443, https://foo-b:443]");
}

TEST(ProxyListTest, NonIpProtectionMultiProxyChainToValue) {
  ProxyList list;
  list.AddProxyChain(ProxyChain::FromSchemeHostAndPort(
      ProxyServer::Scheme::SCHEME_HTTPS, "foo", 443));
  list.AddProxyChain(ProxyChain({
      ProxyServer::FromSchemeHostAndPort(ProxyServer::Scheme::SCHEME_HTTPS,
                                         "foo-a", 443),
      ProxyServer::FromSchemeHostAndPort(ProxyServer::Scheme::SCHEME_HTTPS,
                                         "foo-b", 443),
  }));

  base::Value expected(base::Value::Type::LIST);
  base::Value::List& exp_list = expected.GetList();
  exp_list.Append("[https://foo:443]");
  exp_list.Append("[https://foo-a:443, https://foo-b:443]");

  EXPECT_EQ(list.ToValue(), expected);
}
#endif  // BUILDFLAG(ENABLE_BRACKETED_PROXY_URIS)

}  // anonymous namespace

}  // namespace net
```