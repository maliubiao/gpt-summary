Response:
Let's break down the thought process for analyzing this `proxy_config.cc` file.

1. **Understand the Goal:** The request asks for a functional overview, connection to JavaScript, logic examples, common errors, and debugging tips related to this specific C++ file within the Chromium network stack.

2. **Initial Scan and Keyword Identification:**  Quickly read through the code, looking for key terms and patterns:
    * `ProxyConfig`, `ProxyRules`, `ProxyList`, `ProxyServer`, `ProxyInfo`, `ProxyBypassRules` - These clearly indicate the core functionality revolves around proxy configuration.
    * `ParseFromString`, `Apply`, `Equals`, `ToValue` - These suggest methods for setting, using, comparing, and representing proxy configurations.
    * `GURL`, `std::string`, `base::Value` - These indicate data types used for handling URLs, strings, and structured data (likely for serialization or inter-process communication).
    * `auto_detect`, `pac_url`, `pac_mandatory` - These are common proxy settings.
    * Comments like "// Copyright...", "// If |proxies| is non-empty...",  "// Reset." - These provide hints about the code's purpose.
    * `#include` directives -  These tell us about dependencies and related concepts (e.g., `net/base/proxy_server.h`).

3. **Identify Core Classes and Their Roles:**
    * **`ProxyConfig`:**  Represents the overall proxy configuration, including automatic detection settings (WPAD), PAC file URL, and manual proxy rules.
    * **`ProxyRules`:**  Encapsulates the manual proxy settings, allowing different proxy servers for different protocols (HTTP, HTTPS, FTP) and fallback proxies. It also handles bypass rules.
    * **`ProxyList`:** A container for one or more proxy servers to try in order.
    * **`ProxyServer`:** Represents a single proxy server (address, port, scheme).
    * **`ProxyInfo`:**  Used to store the resulting proxy information for a particular URL after applying the `ProxyRules`.
    * **`ProxyBypassRules`:** Manages the rules for bypassing proxies for certain URLs or hosts.

4. **Analyze Key Methods and Their Logic:**
    * **`ProxyRules::ParseFromString()`:**  This is crucial for understanding how manual proxy strings (like those entered by a user) are converted into the internal representation. Pay attention to how it handles different formats (single proxy, per-scheme proxies, fallback proxies).
    * **`ProxyRules::Apply()`:** This method determines which proxy (or direct connection) should be used for a given URL based on the configured rules. This is the core decision-making logic.
    * **`ProxyConfig::ToValue()`:**  This method serializes the `ProxyConfig` into a `base::Value`, which is a generic data structure used for inter-process communication and storage in Chromium. This is the most likely point of interaction with JavaScript (through Chromium's APIs).

5. **Identify Potential Connections to JavaScript:**
    * The `ToValue()` method strongly suggests a connection. Chromium uses `base::Value` extensively for communicating configuration and state between the browser's UI (often implemented with web technologies like JavaScript) and the underlying C++ networking stack.
    *  Consider where proxy settings are configured in the browser UI. This is usually done through settings pages built with HTML, CSS, and JavaScript. When the user changes proxy settings, this JavaScript code needs to communicate the new configuration to the C++ backend.

6. **Develop Examples and Scenarios:**
    * **JavaScript Interaction:** Imagine a user setting "Use a proxy server" and entering `http://proxy.example.com:8080`. Trace how this information might be passed to the C++ side and how `ParseFromString()` would process it.
    * **Logic Examples:** Create simple input URLs and proxy configurations to illustrate how `Apply()` works for different scenarios (direct connection, single proxy, per-scheme proxies, bypass rules).
    * **Common Errors:** Think about what mistakes users might make when entering proxy settings (typos, incorrect formats, missing ports). Also consider common programming errors in handling these configurations.

7. **Consider Debugging and User Actions:**
    * How would a developer investigate a proxy configuration issue?  Looking at the output of `ToValue()` could be very helpful.
    * How does a user arrive at a state where `proxy_config.cc` is relevant?  They explicitly configure proxy settings in the browser's UI.

8. **Structure the Answer:** Organize the information logically, covering each aspect of the request:
    * Functionality overview.
    * JavaScript relationship with examples.
    * Logic examples with input/output.
    * Common user/programming errors.
    * User actions leading to this code (debugging context).

9. **Refine and Elaborate:**  Review the initial draft and add more details and explanations where necessary. For example, explain *why* `ToValue()` is likely the JavaScript interface. Provide more concrete examples of user errors.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "Maybe JavaScript directly calls functions in `proxy_config.cc`."  **Correction:** This is unlikely due to the C++/JavaScript boundary and the need for a structured communication mechanism. `base::Value` and IPC are more probable.
* **Considering `ParseFromString`:**  Realize the importance of understanding the supported proxy string formats. Refer back to the code to confirm how it handles different delimiters and scheme specifications.
* **Thinking about errors:** Initially focus on code errors. **Broaden the scope:** Also consider user errors in *configuring* the proxy settings.
* **Debugging:**  Initially think about code debugging. **Expand:** Consider how a *user* might troubleshoot proxy issues (e.g., looking at browser developer tools). Connecting this back to the underlying C++ implementation adds value.

By following these steps, the comprehensive answer addressing all aspects of the request can be constructed. The key is to move from a general understanding of the file's purpose to a more detailed analysis of its components and interactions.
好的，我们来详细分析一下 `net/proxy_resolution/proxy_config.cc` 这个 Chromium 网络栈的源代码文件。

**文件功能概述:**

`proxy_config.cc` 文件定义了用于表示和操作代理配置的类和方法。 它的主要功能是：

1. **表示代理配置：** 定义了 `ProxyConfig` 类，用于存储各种代理配置信息，包括：
    * **自动代理检测 (Auto Detect):**  是否启用自动检测代理设置 (通常通过 WPAD 协议)。
    * **PAC 文件 URL (PAC URL):**  用于指定 PAC (Proxy Auto-Config) 脚本的 URL。
    * **PAC 强制 (PAC Mandatory):**  指示是否必须使用 PAC 文件，如果下载失败则不允许网络连接。
    * **从系统获取 (From System):**  指示是否使用操作系统的代理设置。
    * **代理规则 (Proxy Rules):**  一个 `ProxyRules` 对象，包含更详细的代理规则，例如手动指定的代理服务器列表、按协议指定的代理、以及绕过规则。

2. **管理代理规则：** 定义了嵌套类 `ProxyConfig::ProxyRules`，用于管理更细粒度的代理设置：
    * **代理类型 (Type):**  指示代理规则的类型，例如：
        * `EMPTY`: 没有配置代理。
        * `PROXY_LIST`: 使用单个代理服务器列表。
        * `PROXY_LIST_PER_SCHEME`:  为不同的协议 (http, https, ftp) 配置不同的代理服务器列表。
    * **代理服务器列表 (Proxy Lists):**  存储不同类型的代理服务器列表，例如 `single_proxies` (单个列表), `proxies_for_http`, `proxies_for_https`, `proxies_for_ftp`, `fallback_proxies`。
    * **绕过规则 (Bypass Rules):**  一个 `ProxyBypassRules` 对象，用于指定哪些主机或 URL 应该绕过代理直接连接。
    * **反向绕过 (Reverse Bypass):**  指示绕过规则的含义是“匹配的走代理”，而不是“匹配的直连”。

3. **解析代理规则字符串：**  `ProxyRules::ParseFromString()` 方法负责将用户提供的代理规则字符串（例如 "proxy.example.com:8080", "http=http_proxy:3128;https=https_proxy:3129"）解析成内部的 `ProxyRules` 对象。

4. **应用代理规则：** `ProxyRules::Apply()` 方法根据配置的规则和给定的 URL，决定应该使用哪个代理服务器（或直接连接）。

5. **比较代理配置：**  提供了 `Equals()` 方法用于比较两个 `ProxyConfig` 或 `ProxyRules` 对象是否相等。

6. **序列化代理配置：** `ProxyConfig::ToValue()` 方法将 `ProxyConfig` 对象转换为 `base::Value` 对象，这是一种用于在 Chromium 中进行进程间通信和数据存储的通用数据结构。

**与 JavaScript 的关系：**

`proxy_config.cc` 本身是用 C++ 编写的，因此不直接包含 JavaScript 代码。然而，它与 JavaScript 的功能有密切关系，主要体现在以下几点：

1. **用户界面交互：**  Chromium 的用户界面（例如设置页面）通常使用 HTML、CSS 和 JavaScript 构建。用户在这些界面上配置代理设置（例如输入代理服务器地址、PAC 文件 URL 等）。当用户提交这些设置时，JavaScript 代码会读取这些配置，并将它们传递给 Chromium 的 C++ 后端。

2. **数据传递：**  JavaScript 代码会将用户输入的代理配置信息，可能以字符串或其他数据结构的形式，通过 Chromium 提供的 API 传递给 C++ 代码。 `ProxyRules::ParseFromString()` 方法就是用来解析这些字符串的。

3. **配置同步和持久化：**  当代理配置发生变化时，C++ 代码可能会使用 `ProxyConfig::ToValue()` 将配置序列化为 `base::Value` 对象，然后将此对象传递给 JavaScript 或其他组件进行存储（例如，存储到本地存储或同步到云端）。反之，加载已保存的配置时，也可能涉及将 `base::Value` 对象转换回 `ProxyConfig` 对象。

**举例说明 JavaScript 交互：**

假设用户在 Chromium 的设置页面中手动配置代理服务器为 `http://myproxy.com:8080`。

1. **用户操作：** 用户在设置页面输入 "myproxy.com:8080" 并选择 HTTP 协议。
2. **JavaScript 处理：**  JavaScript 代码会监听用户的输入和提交事件。当用户提交配置时，JavaScript 代码会构建一个表示代理配置的数据结构或字符串，例如：`"myproxy.com:8080"`。
3. **API 调用：** JavaScript 代码会调用 Chromium 提供的 C++ API (可能通过消息传递或绑定机制)，将这个字符串传递给网络栈的某个组件。
4. **C++ 处理：** 接收到配置信息的 C++ 组件可能会调用 `ProxyConfig::ProxyRules::ParseFromString()` 方法，将字符串 `"myproxy.com:8080"` 解析到 `ProxyRules` 对象的 `single_proxies` 成员中。

**逻辑推理、假设输入与输出：**

**场景 1：简单的 HTTP 代理**

* **假设输入 (用户配置)：** 手动代理服务器设置为 `proxy.example.com:8080`。
* **`ProxyRules::ParseFromString()` 输入：**  `"proxy.example.com:8080"`
* **`ProxyRules::ParseFromString()` 处理：**  `type` 被设置为 `ProxyRules::Type::PROXY_LIST`，`single_proxies` 包含一个 `ProxyServer` 对象，其 scheme 为 `SCHEME_HTTP`，主机为 `proxy.example.com`，端口为 8080。
* **假设输入 (URL)：**  `http://www.example.com`
* **`ProxyRules::Apply()` 处理：**  因为 `type` 是 `PROXY_LIST`，`Apply()` 方法会调用 `result->UseProxyList(single_proxies)`，指示使用 `proxy.example.com:8080` 作为代理。
* **输出 (ProxyInfo)：**  `result` 对象会包含一个 `ProxyList`，其中包含 `proxy.example.com:8080`。

**场景 2：按协议指定代理**

* **假设输入 (用户配置)：**  HTTP 代理设置为 `http_proxy:3128`，HTTPS 代理设置为 `https_proxy:3129`。
* **`ProxyRules::ParseFromString()` 输入：** `"http=http_proxy:3128;https=https_proxy:3129"`
* **`ProxyRules::ParseFromString()` 处理：** `type` 被设置为 `ProxyRules::Type::PROXY_LIST_PER_SCHEME`，`proxies_for_http` 包含 `http_proxy:3128`，`proxies_for_https` 包含 `https_proxy:3129`。
* **假设输入 (URL 1)：** `http://www.example.com`
* **`ProxyRules::Apply()` 处理：** `MapUrlSchemeToProxyList("http")` 返回 `proxies_for_http`，`Apply()` 调用 `result->UseProxyList(proxies_for_http)`。
* **输出 (ProxyInfo 1)：** `result` 对象包含 `http_proxy:3128`。
* **假设输入 (URL 2)：** `https://www.example.com`
* **`ProxyRules::Apply()` 处理：** `MapUrlSchemeToProxyList("https")` 返回 `proxies_for_https`，`Apply()` 调用 `result->UseProxyList(proxies_for_https)`。
* **输出 (ProxyInfo 2)：** `result` 对象包含 `https_proxy:3129`。

**用户或编程常见的使用错误：**

1. **用户输入错误的代理格式：**
   * **错误示例：** 用户输入 "proxy.example.com" (缺少端口号) 或 "http://proxy.example.com" (缺少端口号)。
   * **结果：** `ParseFromString()` 可能无法正确解析，导致代理设置无效或者使用默认的直接连接。
   * **调试线索：**  检查网络请求是否使用了预期的代理。查看 Chromium 的网络日志 (chrome://net-internals/#events) 可以帮助诊断。

2. **用户忘记配置特定协议的代理：**
   * **错误示例：** 用户只配置了 HTTP 代理，但访问 HTTPS 网站。
   * **结果：** 如果没有配置 fallback 代理，HTTPS 请求可能会直接连接。
   * **调试线索：**  检查 `chrome://net-internals/#proxy` 查看当前生效的代理配置。

3. **用户配置了错误的 PAC 文件 URL：**
   * **错误示例：** PAC 文件 URL 拼写错误或指向不存在的文件。
   * **结果：** 代理自动配置失败，可能导致无法连接网络。
   * **调试线索：**  Chromium 会在控制台输出 PAC 文件下载或执行错误。查看 `chrome://net-internals/#events` 中与 PAC 相关的事件。

4. **编程错误 - 错误地调用 `ParseFromString()`：**
   * **错误示例：**  在调用 `ParseFromString()` 之前没有正确初始化 `ProxyRules` 对象，或者传递了错误的输入字符串。
   * **结果：**  代理配置可能不符合预期。
   * **调试线索：**  使用调试器单步执行 `ParseFromString()`，检查内部状态和变量值。

5. **编程错误 -  在多线程环境下不正确地访问 `ProxyConfig` 对象：**
   * **错误示例：**  多个线程同时修改同一个 `ProxyConfig` 对象而没有适当的同步机制。
   * **结果：**  可能导致数据竞争和未定义的行为。
   * **调试线索：**  使用线程分析工具来检测数据竞争。

**用户操作如何一步步到达这里，作为调试线索：**

要理解用户操作如何影响 `proxy_config.cc` 中的代码执行，可以考虑以下步骤：

1. **用户打开 Chromium 的设置页面。**
2. **用户导航到代理设置部分（通常在“高级”设置中）。**
3. **用户选择手动配置代理，或者选择使用 PAC 文件，或者选择自动检测。**
4. **如果用户选择手动配置：**
   * 用户输入代理服务器地址和端口号，可能为不同的协议分别输入。
   * JavaScript 代码会捕获这些输入，并构建一个表示代理规则的字符串。
   * JavaScript 代码调用 Chromium 提供的 API，将这个字符串传递给 C++ 后端。
   * C++ 后端接收到字符串后，会创建一个 `ProxyConfig` 对象，并调用其 `proxy_rules_.ParseFromString()` 方法来解析字符串。
5. **如果用户选择使用 PAC 文件：**
   * 用户输入 PAC 文件的 URL。
   * JavaScript 代码会将 PAC URL 传递给 C++ 后端。
   * C++ 后端会设置 `ProxyConfig` 对象的 `pac_url_` 成员。
6. **如果用户选择自动检测：**
   * JavaScript 代码会将自动检测的选项传递给 C++ 后端。
   * C++ 后端会设置 `ProxyConfig` 对象的 `auto_detect_` 成员为 `true`。

**调试线索：**

* **检查 `chrome://net-internals/#proxy`：**  这个页面显示了当前 Chromium 进程生效的代理配置，包括配置来源、手动代理设置、PAC 文件 URL 等。这可以帮助确定 `ProxyConfig` 对象的状态。
* **检查 `chrome://net-internals/#events`：**  这个页面记录了网络相关的事件，包括代理解析和查找过程。可以搜索与 "proxy" 相关的事件，查看 PAC 文件是否下载成功，以及使用了哪个代理服务器。
* **使用 `--proxy-server` 命令行参数启动 Chromium：**  可以通过命令行直接指定代理服务器，这可以绕过用户界面设置，用于测试特定的代理配置。
* **在 C++ 代码中添加日志：**  在 `proxy_config.cc` 中的关键方法（如 `ParseFromString()` 和 `Apply()`）添加 `LOG` 语句，可以输出中间状态和变量值，帮助理解代码的执行流程。
* **使用调试器：**  如果可以构建和运行 Chromium，可以使用 GDB 或 LLDB 等调试器来单步执行代码，查看 `ProxyConfig` 和 `ProxyRules` 对象的内容。

总而言之，`net/proxy_resolution/proxy_config.cc` 是 Chromium 网络栈中负责管理代理配置的核心文件。它定义了表示代理配置的数据结构和操作方法，并与 JavaScript 用户界面紧密合作，处理用户的代理设置，并最终决定网络请求是否以及如何通过代理服务器发送。 理解这个文件的功能和内部逻辑对于调试网络问题至关重要。

### 提示词
```
这是目录为net/proxy_resolution/proxy_config.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/proxy_resolution/proxy_config.h"

#include <memory>
#include <utility>

#include "base/check.h"
#include "base/check_op.h"
#include "base/notreached.h"
#include "base/strings/string_tokenizer.h"
#include "base/strings/string_util.h"
#include "base/values.h"
#include "build/buildflag.h"
#include "net/base/proxy_server.h"
#include "net/base/proxy_string_util.h"
#include "net/net_buildflags.h"
#include "net/proxy_resolution/proxy_info.h"

namespace net {

namespace {

// If |proxies| is non-empty, sets it in |dict| under the key |name|.
void AddProxyListToValue(const char* name,
                         const ProxyList& proxies,
                         base::Value::Dict* dict) {
  if (!proxies.IsEmpty()) {
    dict->Set(name, proxies.ToValue());
  }
}

// Split the |uri_list| on commas and add each entry to |proxy_list| in turn.
void AddProxyURIListToProxyList(std::string uri_list,
                                ProxyList* proxy_list,
                                ProxyServer::Scheme default_scheme,
                                bool allow_bracketed_proxy_chains,
                                bool is_quic_allowed) {
  base::StringTokenizer proxy_uri_list(uri_list, ",");
  while (proxy_uri_list.GetNext()) {
    proxy_list->AddProxyChain(
        allow_bracketed_proxy_chains
            ? MultiProxyUrisToProxyChain(proxy_uri_list.token(), default_scheme,
                                         is_quic_allowed)
            : ProxyUriToProxyChain(proxy_uri_list.token(), default_scheme,
                                   is_quic_allowed));
  }
}

}  // namespace

ProxyConfig::ProxyRules::ProxyRules() = default;

ProxyConfig::ProxyRules::ProxyRules(const ProxyRules& other) = default;

ProxyConfig::ProxyRules::~ProxyRules() = default;

void ProxyConfig::ProxyRules::Apply(const GURL& url, ProxyInfo* result) const {
  if (empty()) {
    result->UseDirect();
    return;
  }

  if (bypass_rules.Matches(url, reverse_bypass)) {
    result->UseDirectWithBypassedProxy();
    return;
  }

  switch (type) {
    case ProxyRules::Type::PROXY_LIST: {
      result->UseProxyList(single_proxies);
      return;
    }
    case ProxyRules::Type::PROXY_LIST_PER_SCHEME: {
      const ProxyList* entry = MapUrlSchemeToProxyList(url.scheme());
      if (entry) {
        result->UseProxyList(*entry);
      } else {
        // We failed to find a matching proxy server for the current URL
        // scheme. Default to direct.
        result->UseDirect();
      }
      return;
    }
    default: {
      NOTREACHED();
    }
  }
}

void ProxyConfig::ProxyRules::ParseFromString(const std::string& proxy_rules,
                                              bool allow_bracketed_proxy_chains,
                                              bool is_quic_allowed) {
  // Reset.
  type = Type::EMPTY;
  single_proxies = ProxyList();
  proxies_for_http = ProxyList();
  proxies_for_https = ProxyList();
  proxies_for_ftp = ProxyList();
  fallback_proxies = ProxyList();

#if !BUILDFLAG(ENABLE_BRACKETED_PROXY_URIS)
  // `allow_multi_proxy_chains` can only be true in non-release builds;
  CHECK(!allow_bracketed_proxy_chains);
#endif  // !BUILDFLAG(ENABLE_BRACKETED_PROXY_URIS)

#if !BUILDFLAG(ENABLE_QUIC_PROXY_SUPPORT)
  CHECK(!is_quic_allowed);
#endif  // BUILDFLAG(ENABLE_QUIC_PROXY_SUPPORT)

  base::StringTokenizer proxy_server_list(proxy_rules, ";");
  while (proxy_server_list.GetNext()) {
    base::StringTokenizer proxy_server_for_scheme(
        proxy_server_list.token_begin(), proxy_server_list.token_end(), "=");

    while (proxy_server_for_scheme.GetNext()) {
      std::string url_scheme = proxy_server_for_scheme.token();

      // If we fail to get the proxy server here, it means that
      // this is a regular proxy server configuration, i.e. proxies
      // are not configured per protocol.
      if (!proxy_server_for_scheme.GetNext()) {
        if (type == Type::PROXY_LIST_PER_SCHEME) {
          continue;  // Unexpected.
        }
        AddProxyURIListToProxyList(
            std::move(url_scheme), &single_proxies, ProxyServer::SCHEME_HTTP,
            allow_bracketed_proxy_chains, is_quic_allowed);
        type = Type::PROXY_LIST;
        return;
      }

      // Trim whitespace off the url scheme.
      base::TrimWhitespaceASCII(url_scheme, base::TRIM_ALL, &url_scheme);

      // Add it to the per-scheme mappings (if supported scheme).
      type = Type::PROXY_LIST_PER_SCHEME;
      ProxyList* entry = MapUrlSchemeToProxyListNoFallback(url_scheme);
      ProxyServer::Scheme default_scheme = ProxyServer::SCHEME_HTTP;

      // socks=XXX is inconsistent with the other formats, since "socks"
      // is not a URL scheme. Rather this means "for everything else, send
      // it to the SOCKS proxy server XXX".
      if (url_scheme == "socks") {
        DCHECK(!entry);
        entry = &fallback_proxies;
        // Note that here 'socks' is understood to be SOCKS4, even though
        // 'socks' maps to SOCKS5 in ProxyServer::GetSchemeFromURIInternal.
        default_scheme = ProxyServer::SCHEME_SOCKS4;
      }

      if (entry) {
        AddProxyURIListToProxyList(proxy_server_for_scheme.token(), entry,
                                   default_scheme, allow_bracketed_proxy_chains,
                                   is_quic_allowed);
      }
    }
  }
}

const ProxyList* ProxyConfig::ProxyRules::MapUrlSchemeToProxyList(
    const std::string& url_scheme) const {
  const ProxyList* proxy_server_list =
      const_cast<ProxyRules*>(this)->MapUrlSchemeToProxyListNoFallback(
          url_scheme);
  if (proxy_server_list && !proxy_server_list->IsEmpty()) {
    return proxy_server_list;
  }
  if (url_scheme == "ws" || url_scheme == "wss") {
    return GetProxyListForWebSocketScheme();
  }
  if (!fallback_proxies.IsEmpty()) {
    return &fallback_proxies;
  }
  return nullptr;  // No mapping for this scheme. Use direct.
}

bool ProxyConfig::ProxyRules::Equals(const ProxyRules& other) const {
  return type == other.type && single_proxies.Equals(other.single_proxies) &&
         proxies_for_http.Equals(other.proxies_for_http) &&
         proxies_for_https.Equals(other.proxies_for_https) &&
         proxies_for_ftp.Equals(other.proxies_for_ftp) &&
         fallback_proxies.Equals(other.fallback_proxies) &&
         bypass_rules == other.bypass_rules &&
         reverse_bypass == other.reverse_bypass;
}

ProxyList* ProxyConfig::ProxyRules::MapUrlSchemeToProxyListNoFallback(
    const std::string& scheme) {
  DCHECK_EQ(Type::PROXY_LIST_PER_SCHEME, type);
  if (scheme == "http") {
    return &proxies_for_http;
  }
  if (scheme == "https") {
    return &proxies_for_https;
  }
  if (scheme == "ftp") {
    return &proxies_for_ftp;
  }
  return nullptr;  // No mapping for this scheme.
}

const ProxyList* ProxyConfig::ProxyRules::GetProxyListForWebSocketScheme()
    const {
  // Follow the recommendation from RFC 6455 section 4.1.3:
  //
  //       NOTE: Implementations that do not expose explicit UI for
  //       selecting a proxy for WebSocket connections separate from other
  //       proxies are encouraged to use a SOCKS5 [RFC1928] proxy for
  //       WebSocket connections, if available, or failing that, to prefer
  //       the proxy configured for HTTPS connections over the proxy
  //       configured for HTTP connections.
  //
  // This interpretation is a bit different from the RFC, in
  // that it favors both SOCKSv4 and SOCKSv5.
  //
  // When the net::ProxyRules came from system proxy settings,
  // "fallback_proxies" will be empty, or a a single SOCKS
  // proxy, making this ordering match the RFC.
  //
  // However for other configurations it is possible for
  // "fallback_proxies" to be a list of any ProxyServer,
  // including non-SOCKS. In this case "fallback_proxies" is
  // still prioritized over proxies_for_http and
  // proxies_for_https.
  if (!fallback_proxies.IsEmpty()) {
    return &fallback_proxies;
  }
  if (!proxies_for_https.IsEmpty()) {
    return &proxies_for_https;
  }
  if (!proxies_for_http.IsEmpty()) {
    return &proxies_for_http;
  }
  return nullptr;
}

ProxyConfig::ProxyConfig() = default;

ProxyConfig::ProxyConfig(const ProxyConfig& config) = default;

ProxyConfig::ProxyConfig(ProxyConfig&& config) = default;

ProxyConfig& ProxyConfig::operator=(const ProxyConfig& config) = default;

ProxyConfig& ProxyConfig::operator=(ProxyConfig&& config) = default;

ProxyConfig::~ProxyConfig() = default;

bool ProxyConfig::Equals(const ProxyConfig& other) const {
  return auto_detect_ == other.auto_detect_ && pac_url_ == other.pac_url_ &&
         pac_mandatory_ == other.pac_mandatory_ &&
         from_system_ == other.from_system_ &&
         proxy_rules_.Equals(other.proxy_rules());
}

bool ProxyConfig::HasAutomaticSettings() const {
  return auto_detect_ || has_pac_url();
}

void ProxyConfig::ClearAutomaticSettings() {
  auto_detect_ = false;
  pac_url_ = GURL();
}

base::Value ProxyConfig::ToValue() const {
  base::Value::Dict dict;

  // Output the automatic settings.
  if (auto_detect_) {
    dict.Set("auto_detect", auto_detect_);
  }
  if (has_pac_url()) {
    dict.Set("pac_url", pac_url_.possibly_invalid_spec());
    if (pac_mandatory_) {
      dict.Set("pac_mandatory", pac_mandatory_);
    }
  }
  if (from_system_) {
    dict.Set("from_system", from_system_);
  }

  // Output the manual settings.
  if (proxy_rules_.type != ProxyRules::Type::EMPTY) {
    switch (proxy_rules_.type) {
      case ProxyRules::Type::PROXY_LIST:
        AddProxyListToValue("single_proxy", proxy_rules_.single_proxies, &dict);
        break;
      case ProxyRules::Type::PROXY_LIST_PER_SCHEME: {
        base::Value::Dict dict2;
        AddProxyListToValue("http", proxy_rules_.proxies_for_http, &dict2);
        AddProxyListToValue("https", proxy_rules_.proxies_for_https, &dict2);
        AddProxyListToValue("ftp", proxy_rules_.proxies_for_ftp, &dict2);
        AddProxyListToValue("fallback", proxy_rules_.fallback_proxies, &dict2);
        dict.Set("proxy_per_scheme", std::move(dict2));
        break;
      }
      default:
        NOTREACHED();
    }

    // Output the bypass rules.
    const ProxyBypassRules& bypass = proxy_rules_.bypass_rules;
    if (!bypass.rules().empty()) {
      if (proxy_rules_.reverse_bypass) {
        dict.Set("reverse_bypass", true);
      }

      base::Value::List list;

      for (const auto& bypass_rule : bypass.rules()) {
        list.Append(bypass_rule->ToString());
      }

      dict.Set("bypass_list", std::move(list));
    }
  }

  return base::Value(std::move(dict));
}

}  // namespace net
```