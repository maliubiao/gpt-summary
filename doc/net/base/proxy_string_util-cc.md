Response:
Let's break down the thought process for analyzing this C++ code and generating the explanation.

1. **Understanding the Goal:** The primary goal is to explain the functionality of `proxy_string_util.cc`, especially its relation to JavaScript, input/output behavior, common errors, and how a user might reach this code.

2. **Initial Code Scan (Skimming):**  A quick read-through reveals several key aspects:
    * **Namespace:**  It's within the `net` namespace, suggesting it deals with networking concepts.
    * **Includes:** Headers like `string`, `vector`, `base/strings/...`, `net/base/proxy_server.h`, `net/base/url_util.h`, `net/http/http_util.h`, and `url/third_party/mozilla/url_parse.h`  hint at string manipulation, data structures, proxy server representation, URL parsing, and HTTP utilities.
    * **Function Names:**  Function names like `GetSchemeFromPacTypeInternal`, `PacResultElementToProxyChain`, `ProxyUriToProxyServer`, `ProxyServerToPacResultElement`, etc., clearly indicate a focus on converting between different string representations of proxy configurations and internal `ProxyServer` objects. The presence of "PAC" suggests handling Proxy Auto-Configuration scripts.
    * **String Operations:**  There's heavy use of `std::string_view`, `base::EqualsCaseInsensitiveASCII`, `base::StrCat`, `base::SplitStringPiece`, and trimming functions, indicating a lot of string parsing and manipulation.

3. **Categorizing Functionality:** Based on the function names and initial scan, we can group the functionalities:
    * **PAC String Handling:**  Functions like `GetSchemeFromPacTypeInternal`, `PacResultElementToProxyChain`, and `PacResultElementToProxyServer` deal with parsing strings returned by PAC scripts. `ProxyServerToPacResultElement` does the reverse.
    * **Proxy URI Handling:** Functions like `ProxyUriToProxyChain`, `ProxyUriToProxyServer`, and `ProxyServerToProxyUri` handle proxy URIs (e.g., `http://proxy.example.com:8080`).
    * **Internal Conversion:**  `ProxySchemeHostAndPortToProxyServer` converts a scheme and host/port string into a `ProxyServer` object.
    * **Scheme Extraction:** `GetSchemeFromUriScheme` extracts the proxy scheme from a URI string.
    * **Multi-Proxy URI Handling:** `MultiProxyUrisToProxyChain` deals with comma-separated (or space-separated within brackets) lists of proxy URIs.
    * **Utility Functions:** `ConstructHostPortString` builds a host:port string.

4. **JavaScript Relationship Analysis:** This requires understanding where proxy settings might interact with JavaScript. The primary connection is through the **PAC script**. Browsers execute PAC scripts (written in JavaScript) to determine the appropriate proxy server for a given URL. The *output* of the PAC script is a string that this C++ code parses. Therefore, the relationship is indirect but crucial.

5. **Input/Output Examples:** For each main function category, think of plausible inputs and the expected outputs. This helps illustrate the logic.
    * **PAC:**  Input: `"PROXY myproxy:80"`, Output: `ProxyServer` object representing an HTTP proxy at `myproxy:80`.
    * **URI:** Input: `"socks5://anotherproxy:1080"`, Output: `ProxyServer` for SOCKS5 at `anotherproxy:1080`.
    * **Multi-Proxy:** Input: `"[http://p1:8080 socks5://p2:1080]"`, Output: `ProxyChain` with two proxies.

6. **Common Errors:** Consider how users or programmers might misuse these functions or provide invalid input.
    * **Incorrect PAC syntax:**  Missing spaces, invalid schemes.
    * **Malformed URIs:**  Missing colons, invalid port numbers.
    * **Mixing direct with other proxies (in `MultiProxyUrisToProxyChain` without brackets).**

7. **Debugging Scenario:** Think about a user-visible problem related to proxies and how it might lead to this code. A common scenario is a website failing to load due to incorrect proxy settings. The browser would then need to parse the configured proxy information, which involves this code. Tracing the steps involves user configuration, network requests, and the system's proxy resolution mechanisms.

8. **Structuring the Explanation:** Organize the information logically. Start with a general overview of the file's purpose. Then, detail each function's functionality. Address the JavaScript relationship, provide input/output examples, discuss common errors, and finally, outline a debugging scenario.

9. **Refinement and Clarity:** Review the explanation for clarity and accuracy. Ensure the language is easy to understand, even for someone not deeply familiar with the Chromium codebase. Use bullet points, code formatting, and clear headings to improve readability. Double-check the input/output examples for correctness. Make sure the connection to JavaScript is clearly explained.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Focus heavily on the C++ details of each function.
* **Correction:** Realize the prompt asks for a broader understanding, including the JavaScript connection and user-level impact. Shift focus to the *purpose* of the code in the larger context.
* **Initial thought:** List all functions with brief descriptions.
* **Correction:** Group functions by their main purpose (PAC, URI, etc.) for better organization.
* **Initial thought:** Provide very technical input/output examples.
* **Correction:** Simplify the examples to be more illustrative and less bogged down in edge cases.
* **Initial thought:** Focus only on programmer errors.
* **Correction:** Include user-facing errors in proxy configuration as well.

By following this kind of structured approach, combining code analysis with an understanding of the broader context, one can generate a comprehensive and informative explanation of the given C++ source file.
好的，我们来分析一下 `net/base/proxy_string_util.cc` 这个文件。

**文件功能概述:**

这个 C++ 文件 `proxy_string_util.cc` 位于 Chromium 的网络栈中，它的主要功能是提供 **代理服务器字符串和内部 `ProxyServer` 对象之间的转换**，以及处理与代理相关的字符串解析和格式化。  它处理以下几种主要的代理字符串格式：

1. **PAC (Proxy Auto-Configuration) 结果字符串:**  这是 PAC 脚本返回的字符串，用于指定要使用的代理服务器。例如 `"PROXY myproxy:80"` 或 `"DIRECT"`。
2. **代理 URI 字符串:**  这是以特定协议开头的代理服务器地址，例如 `"http://proxy.example.com:8080"` 或 `"socks5://anotherproxy:1080"`。
3. **多代理 URI 字符串:**  一种特殊的格式，允许指定一个代理链，例如 `"[http://p1:8080 socks5://p2:1080]"`。

**具体功能分解:**

* **解析 PAC 结果字符串:**
    * `GetSchemeFromPacTypeInternal`: 从 PAC 字符串中解析代理类型 (例如 "PROXY", "SOCKS") 并转换为 `ProxyServer::Scheme` 枚举值。
    * `PacResultElementToProxyChain`: 将单个 PAC 结果元素转换为 `ProxyChain` 对象。PAC 字符串不支持代理链，所以这里实际上是转换成包含单个代理服务器的链。
    * `PacResultElementToProxyServer`: 将单个 PAC 结果元素转换为 `ProxyServer` 对象。

* **格式化为 PAC 结果字符串:**
    * `ProxyServerToPacResultElement`: 将 `ProxyServer` 对象转换为 PAC 结果字符串。

* **解析代理 URI 字符串:**
    * `ProxyUriToProxyChain`: 将代理 URI 字符串转换为 `ProxyChain` 对象。
    * `ProxyUriToProxyServer`: 将代理 URI 字符串转换为 `ProxyServer` 对象。
    * `GetSchemeFromUriScheme`: 从代理 URI 的 scheme 部分 (例如 "http", "socks5") 解析出 `ProxyServer::Scheme`。

* **格式化为代理 URI 字符串:**
    * `ProxyServerToProxyUri`: 将 `ProxyServer` 对象转换为代理 URI 字符串。

* **内部转换:**
    * `ProxySchemeHostAndPortToProxyServer`:  根据提供的 `ProxyServer::Scheme` 和主机端口字符串，创建一个 `ProxyServer` 对象。
    * `ConstructHostPortString`:  将主机名和端口号组合成 "host:port" 格式的字符串，并处理 IPv6 地址的方括号。

* **解析多代理 URI 字符串:**
    * `MultiProxyUrisToProxyChain`:  将包含多个代理 URI 的字符串（例如 `"[...]"`）解析为 `ProxyChain` 对象。这个功能通常在非发布版本中启用。

**与 JavaScript 的关系:**

这个文件与 JavaScript 的主要联系在于 **PAC (Proxy Auto-Configuration)** 脚本。

1. **PAC 脚本执行:** 当浏览器需要确定给定 URL 的代理服务器时，它可以配置为执行一个 PAC 脚本。这个脚本是用 JavaScript 编写的。
2. **PAC 脚本的返回值:** PAC 脚本的 `FindProxyForURL(url, host)` 函数会返回一个字符串，这个字符串描述了应该使用的代理服务器（或 `DIRECT` 表示不使用代理）。这个返回的字符串就是这里处理的 **PAC 结果字符串**。
3. **`proxy_string_util.cc` 的作用:**  Chromium 的网络栈会调用 `proxy_string_util.cc` 中的函数（例如 `PacResultElementToProxyChain` 或 `PacResultElementToProxyServer`）来解析 PAC 脚本返回的字符串，并将其转换为内部的 `ProxyServer` 或 `ProxyChain` 对象，以便后续的网络请求可以使用正确的代理。

**JavaScript 举例说明:**

假设一个 PAC 脚本返回以下字符串：

```javascript
"PROXY my-proxy.example.com:8080; SOCKS5 another-proxy.example.com:1080; DIRECT"
```

Chromium 的网络栈会逐个解析这些元素：

* `"PROXY my-proxy.example.com:8080"` 会被 `PacResultElementToProxyServer` 解析为一个 `ProxyServer` 对象，其 scheme 为 `SCHEME_HTTP`，host 为 `my-proxy.example.com`，port 为 `8080`。
* `"SOCKS5 another-proxy.example.com:1080"` 会被解析为一个 `ProxyServer` 对象，其 scheme 为 `SCHEME_SOCKS5`，host 为 `another-proxy.example.com`，port 为 `1080`。
* `"DIRECT"` 会被解析为 `ProxyChain::Direct()`，表示不使用代理。

**逻辑推理的假设输入与输出:**

**假设输入 1 (PAC 结果字符串):**

```
输入: "HTTPS secure-proxy:443"
```

**逻辑推理:**

1. `PacResultElementToSchemeAndHostPort` 会将输入分解为 type: "HTTPS", host_and_port: "secure-proxy:443"。
2. `GetSchemeFromPacTypeInternal`("HTTPS") 返回 `ProxyServer::SCHEME_HTTPS`。
3. `ProxySchemeHostAndPortToProxyServer`(SCHEME_HTTPS, "secure-proxy:443") 会创建一个 `ProxyServer` 对象，其 scheme 为 `SCHEME_HTTPS`，host 为 "secure-proxy"，port 为 443。

**输出:**  一个 `ProxyServer` 对象，表示 HTTPS 代理服务器 `secure-proxy:443`。

**假设输入 2 (代理 URI 字符串):**

```
输入: "socks://my-socks-proxy:1080"
```

**逻辑推理:**

1. `ProxyUriToProxyServer` 会识别出 scheme 为 "socks"。
2. `GetSchemeFromUriScheme`("socks", ...) 返回 `ProxyServer::SCHEME_SOCKS5` (因为代码中 "socks" 映射到 SOCKS5)。
3. `ProxySchemeHostAndPortToProxyServer`(SCHEME_SOCKS5, "my-socks-proxy:1080") 会创建一个 `ProxyServer` 对象，其 scheme 为 `SCHEME_SOCKS5`，host 为 "my-socks-proxy"，port 为 1080。

**输出:** 一个 `ProxyServer` 对象，表示 SOCKS5 代理服务器 `my-socks-proxy:1080`。

**用户或编程常见的使用错误:**

1. **PAC 脚本返回格式错误:** PAC 脚本返回的字符串格式不符合预期，例如缺少空格、类型拼写错误等。
   * **例子:** PAC 脚本返回 `"PROXYmyproxy:80"` (缺少类型和主机之间的空格)。`PacResultElementToProxyServer` 可能会解析失败，导致无法使用代理。
2. **代理 URI 格式错误:** 手动配置代理服务器时，输入的 URI 格式错误。
   * **例子:** 用户在代理设置中输入 `"http//proxy.example.com:80"` (缺少一个 `/`)。`ProxyUriToProxyServer` 会解析失败，导致连接错误。
3. **多代理 URI 格式错误:**  使用多代理 URI 时，格式不正确。
   * **例子:**  用户输入 `"http://p1:8080 socks5://p2:1080"` (缺少方括号)。在非调试模式下，`MultiProxyUrisToProxyChain` 会断言失败或返回无效的 `ProxyChain`。
4. **指定了无效的代理 Scheme:**  使用了代码不支持的代理协议。
   * **例子:** 用户尝试配置一个 "ftp://proxy:21" 代理。`GetSchemeFromUriScheme` 将返回 `SCHEME_INVALID`，导致无法识别该代理。
5. **在 `MultiProxyUrisToProxyChain` 中错误地混合 `DIRECT` 和其他代理:**  `DIRECT` 必须是唯一的 URI，否则会被认为是无效的。
   * **例子:**  输入 `"[DIRECT http://proxy:80]"` 是无效的。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户配置代理设置:** 用户在操作系统或浏览器的设置中配置了代理服务器。这可能涉及：
   * **手动配置代理服务器地址和端口。**
   * **配置使用 PAC 脚本，并提供了 PAC 脚本的 URL 或本地文件路径。**
   * **配置自动检测代理设置。**

2. **浏览器发起网络请求:** 当用户尝试访问一个网页或其他网络资源时，浏览器需要确定是否应该使用代理。

3. **代理设置生效:**
   * **如果配置了 PAC 脚本:** 浏览器会下载并执行 PAC 脚本。PAC 脚本的 `FindProxyForURL` 函数会被调用，并返回一个描述代理的字符串。这个字符串会被传递给 `proxy_string_util.cc` 中的函数进行解析。
   * **如果手动配置了代理:** 用户提供的代理 URI 字符串会被传递给 `proxy_string_util.cc` 中的函数进行解析。
   * **如果配置了自动检测:** 系统可能会尝试通过 WPAD (Web Proxy Auto-Discovery Protocol) 等方式自动发现 PAC 脚本，然后流程与使用 PAC 脚本的情况类似。

4. **`proxy_string_util.cc` 中的函数被调用:**  根据代理配置的方式和返回的字符串格式，Chromium 的网络栈会调用 `proxy_string_util.cc` 中相应的函数，例如：
   * 如果 PAC 脚本返回 `"PROXY myproxy:80"`，则会调用 `PacResultElementToProxyServer`。
   * 如果用户手动配置了 `"socks5://anotherproxy:1080"`，则会调用 `ProxyUriToProxyServer`。
   * 如果配置了多代理 `"[http://p1:8080 socks5://p2:1080]"`，则会调用 `MultiProxyUrisToProxyChain`。

5. **解析结果用于网络连接:** 解析得到的 `ProxyServer` 或 `ProxyChain` 对象会被网络栈用于建立到目标服务器的连接，可能会通过指定的代理服务器进行连接。

**调试线索:**

如果在网络连接中遇到代理相关的问题，可以从以下方面入手进行调试，并可能涉及到 `proxy_string_util.cc`：

* **检查代理配置:**  确认用户配置的代理设置是否正确，包括代理服务器地址、端口、协议以及 PAC 脚本的 URL 等。
* **查看 PAC 脚本执行结果:** 如果使用了 PAC 脚本，可以查看浏览器开发者工具的网络面板或相关日志，确认 PAC 脚本是否执行成功，以及返回的代理字符串是什么。
* **网络日志:** Chromium 提供了详细的网络日志，可以查看代理解析和连接的详细过程。 启用网络日志可以帮助确定 `proxy_string_util.cc` 中的哪个函数被调用，以及解析的结果是什么。
* **断点调试:** 如果有 Chromium 的调试构建，可以在 `proxy_string_util.cc` 中设置断点，查看不同函数的输入和输出，分析解析过程中的问题。例如，可以在 `PacResultElementToProxyServer` 或 `ProxyUriToProxyServer` 中设置断点，查看传入的字符串和解析后的 `ProxyServer` 对象。

总而言之，`net/base/proxy_string_util.cc` 是 Chromium 网络栈中负责处理代理服务器字符串的关键组件，它将各种格式的代理描述转换为内部表示，以便网络连接模块可以使用正确的代理进行通信。 理解这个文件的功能对于调试代理相关的问题至关重要。

Prompt: 
```
这是目录为net/base/proxy_string_util.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
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
#include <string_view>
#include <vector>

#include "base/check.h"
#include "base/notreached.h"
#include "base/strings/strcat.h"
#include "base/strings/string_split.h"
#include "base/strings/string_util.h"
#include "build/buildflag.h"
#include "net/base/proxy_server.h"
#include "net/base/url_util.h"
#include "net/http/http_util.h"
#include "net/net_buildflags.h"
#include "url/third_party/mozilla/url_parse.h"

namespace net {

namespace {

// Parses the proxy type from a PAC string, to a ProxyServer::Scheme.
// This mapping is case-insensitive. If no type could be matched
// returns SCHEME_INVALID.
ProxyServer::Scheme GetSchemeFromPacTypeInternal(std::string_view type) {
  if (base::EqualsCaseInsensitiveASCII(type, "proxy")) {
    return ProxyServer::SCHEME_HTTP;
  }
  if (base::EqualsCaseInsensitiveASCII(type, "socks")) {
    // Default to v4 for compatibility. This is because the SOCKS4 vs SOCKS5
    // notation didn't originally exist, so if a client returns SOCKS they
    // really meant SOCKS4.
    return ProxyServer::SCHEME_SOCKS4;
  }
  if (base::EqualsCaseInsensitiveASCII(type, "socks4")) {
    return ProxyServer::SCHEME_SOCKS4;
  }
  if (base::EqualsCaseInsensitiveASCII(type, "socks5")) {
    return ProxyServer::SCHEME_SOCKS5;
  }
  if (base::EqualsCaseInsensitiveASCII(type, "https")) {
    return ProxyServer::SCHEME_HTTPS;
  }

  return ProxyServer::SCHEME_INVALID;
}

std::string ConstructHostPortString(std::string_view hostname, uint16_t port) {
  DCHECK(!hostname.empty());
  DCHECK((hostname.front() == '[' && hostname.back() == ']') ||
         hostname.find(":") == std::string_view::npos);

  return base::StrCat({hostname, ":", base::NumberToString(port)});
}

std::tuple<std::string_view, std::string_view>
PacResultElementToSchemeAndHostPort(std::string_view pac_result_element) {
  // Trim the leading/trailing whitespace.
  pac_result_element = HttpUtil::TrimLWS(pac_result_element);

  // Input should match:
  // ( <type> 1*(LWS) <host-and-port> )

  // Start by finding the first space (if any).
  size_t space = 0;
  for (; space < pac_result_element.size(); space++) {
    if (HttpUtil::IsLWS(pac_result_element[space])) {
      break;
    }
  }
  // Everything to the left of the space is the scheme.
  std::string_view scheme = pac_result_element.substr(0, space);

  // And everything to the right of the space is the
  // <host>[":" <port>].
  std::string_view host_and_port = pac_result_element.substr(space);
  return std::make_tuple(scheme, host_and_port);
}

}  // namespace

ProxyChain PacResultElementToProxyChain(std::string_view pac_result_element) {
  // Proxy chains are not supported in PAC strings, so this is just parsed
  // as a single server.
  auto [type, host_and_port] =
      PacResultElementToSchemeAndHostPort(pac_result_element);
  if (base::EqualsCaseInsensitiveASCII(type, "direct") &&
      host_and_port.empty()) {
    return ProxyChain::Direct();
  }
  return ProxyChain(PacResultElementToProxyServer(pac_result_element));
}

ProxyServer PacResultElementToProxyServer(std::string_view pac_result_element) {
  auto [type, host_and_port] =
      PacResultElementToSchemeAndHostPort(pac_result_element);
  ProxyServer::Scheme scheme = GetSchemeFromPacTypeInternal(type);
  return ProxySchemeHostAndPortToProxyServer(scheme, host_and_port);
}

std::string ProxyServerToPacResultElement(const ProxyServer& proxy_server) {
  switch (proxy_server.scheme()) {
    case ProxyServer::SCHEME_HTTP:
      return std::string("PROXY ") +
             ConstructHostPortString(proxy_server.GetHost(),
                                     proxy_server.GetPort());
    case ProxyServer::SCHEME_SOCKS4:
      // For compatibility send SOCKS instead of SOCKS4.
      return std::string("SOCKS ") +
             ConstructHostPortString(proxy_server.GetHost(),
                                     proxy_server.GetPort());
    case ProxyServer::SCHEME_SOCKS5:
      return std::string("SOCKS5 ") +
             ConstructHostPortString(proxy_server.GetHost(),
                                     proxy_server.GetPort());
    case ProxyServer::SCHEME_HTTPS:
      return std::string("HTTPS ") +
             ConstructHostPortString(proxy_server.GetHost(),
                                     proxy_server.GetPort());
    case ProxyServer::SCHEME_QUIC:
      return std::string("QUIC ") +
             ConstructHostPortString(proxy_server.GetHost(),
                                     proxy_server.GetPort());
    default:
      // Got called with an invalid scheme.
      NOTREACHED();
  }
}

ProxyChain ProxyUriToProxyChain(std::string_view uri,
                                ProxyServer::Scheme default_scheme,
                                bool is_quic_allowed) {
  // If uri is direct, return direct proxy chain.
  uri = HttpUtil::TrimLWS(uri);
  size_t colon = uri.find("://");
  if (colon != std::string_view::npos &&
      base::EqualsCaseInsensitiveASCII(uri.substr(0, colon), "direct")) {
    if (!uri.substr(colon + 3).empty()) {
      return ProxyChain();  // Invalid -- Direct chain cannot have a host/port.
    }
    return ProxyChain::Direct();
  }
  return ProxyChain(
      ProxyUriToProxyServer(uri, default_scheme, is_quic_allowed));
}

ProxyServer ProxyUriToProxyServer(std::string_view uri,
                                  ProxyServer::Scheme default_scheme,
                                  bool is_quic_allowed) {
  // We will default to |default_scheme| if no scheme specifier was given.
  ProxyServer::Scheme scheme = default_scheme;

  // Trim the leading/trailing whitespace.
  uri = HttpUtil::TrimLWS(uri);

  // Check for [<scheme> "://"]
  size_t colon = uri.find(':');
  if (colon != std::string_view::npos && uri.size() - colon >= 3 &&
      uri[colon + 1] == '/' && uri[colon + 2] == '/') {
    scheme = GetSchemeFromUriScheme(uri.substr(0, colon), is_quic_allowed);
    uri = uri.substr(colon + 3);  // Skip past the "://"
  }

  // Now parse the <host>[":"<port>].
  return ProxySchemeHostAndPortToProxyServer(scheme, uri);
}

std::string ProxyServerToProxyUri(const ProxyServer& proxy_server) {
  switch (proxy_server.scheme()) {
    case ProxyServer::SCHEME_HTTP:
      // Leave off "http://" since it is our default scheme.
      return ConstructHostPortString(proxy_server.GetHost(),
                                     proxy_server.GetPort());
    case ProxyServer::SCHEME_SOCKS4:
      return std::string("socks4://") +
             ConstructHostPortString(proxy_server.GetHost(),
                                     proxy_server.GetPort());
    case ProxyServer::SCHEME_SOCKS5:
      return std::string("socks5://") +
             ConstructHostPortString(proxy_server.GetHost(),
                                     proxy_server.GetPort());
    case ProxyServer::SCHEME_HTTPS:
      return std::string("https://") +
             ConstructHostPortString(proxy_server.GetHost(),
                                     proxy_server.GetPort());
    case ProxyServer::SCHEME_QUIC:
      return std::string("quic://") +
             ConstructHostPortString(proxy_server.GetHost(),
                                     proxy_server.GetPort());
    default:
      // Got called with an invalid scheme.
      NOTREACHED();
  }
}

ProxyServer ProxySchemeHostAndPortToProxyServer(
    ProxyServer::Scheme scheme,
    std::string_view host_and_port) {
  // Trim leading/trailing space.
  host_and_port = HttpUtil::TrimLWS(host_and_port);

  if (scheme == ProxyServer::SCHEME_INVALID) {
    return ProxyServer();
  }

  url::Component username_component;
  url::Component password_component;
  url::Component hostname_component;
  url::Component port_component;
  url::ParseAuthority(host_and_port.data(),
                      url::Component(0, host_and_port.size()),
                      &username_component, &password_component,
                      &hostname_component, &port_component);
  if (username_component.is_valid() || password_component.is_valid() ||
      hostname_component.is_empty()) {
    return ProxyServer();
  }

  std::string_view hostname =
      host_and_port.substr(hostname_component.begin, hostname_component.len);

  // Reject inputs like "foo:". /url parsing and canonicalization code generally
  // allows it and treats it the same as a URL without a specified port, but
  // Chrome has traditionally disallowed it in proxy specifications.
  if (port_component.is_valid() && port_component.is_empty()) {
    return ProxyServer();
  }
  std::string_view port =
      port_component.is_nonempty()
          ? host_and_port.substr(port_component.begin, port_component.len)
          : "";

  return ProxyServer::FromSchemeHostAndPort(scheme, hostname, port);
}

ProxyServer::Scheme GetSchemeFromUriScheme(std::string_view scheme,
                                           bool is_quic_allowed) {
  if (base::EqualsCaseInsensitiveASCII(scheme, "http")) {
    return ProxyServer::SCHEME_HTTP;
  }
  if (base::EqualsCaseInsensitiveASCII(scheme, "socks4")) {
    return ProxyServer::SCHEME_SOCKS4;
  }
  if (base::EqualsCaseInsensitiveASCII(scheme, "socks")) {
    return ProxyServer::SCHEME_SOCKS5;
  }
  if (base::EqualsCaseInsensitiveASCII(scheme, "socks5")) {
    return ProxyServer::SCHEME_SOCKS5;
  }
  if (base::EqualsCaseInsensitiveASCII(scheme, "https")) {
    return ProxyServer::SCHEME_HTTPS;
  }
#if BUILDFLAG(ENABLE_QUIC_PROXY_SUPPORT)
  if (is_quic_allowed && base::EqualsCaseInsensitiveASCII(scheme, "quic")) {
    return ProxyServer::SCHEME_QUIC;
  }
#endif  // BUILDFLAG(ENABLE_QUIC_PROXY_SUPPORT)
  return ProxyServer::SCHEME_INVALID;
}

ProxyChain MultiProxyUrisToProxyChain(std::string_view uris,
                                      ProxyServer::Scheme default_scheme,
                                      bool is_quic_allowed) {
#if !BUILDFLAG(ENABLE_BRACKETED_PROXY_URIS)
  // This function should not be called in non-debug modes.
  CHECK(false);
#endif  // !BUILDFLAG(ENABLE_BRACKETED_PROXY_URIS)

  uris = HttpUtil::TrimLWS(uris);
  if (uris.empty()) {
    return ProxyChain();
  }

  bool has_multi_proxy_brackets = uris.front() == '[' && uris.back() == ']';
  // Remove `[]` if present
  if (has_multi_proxy_brackets) {
    uris = HttpUtil::TrimLWS(uris.substr(1, uris.size() - 2));
  }

  std::vector<ProxyServer> proxy_server_list;
  std::vector<std::string_view> uris_list = base::SplitStringPiece(
      uris, " ", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);
  size_t number_of_proxy_uris = uris_list.size();
  bool has_invalid_format =
      number_of_proxy_uris > 1 && !has_multi_proxy_brackets;

  // If uris list is empty or has invalid formatting for multi-proxy chains, an
  // invalid `ProxyChain` should be returned.
  if (uris_list.empty() || has_invalid_format) {
    return ProxyChain();
  }

  for (const auto& uri : uris_list) {
    // If direct is found, it MUST be the only uri in the list. Otherwise, it is
    // an invalid `ProxyChain()`.
    if (base::EqualsCaseInsensitiveASCII(uri, "direct://")) {
      return number_of_proxy_uris > 1 ? ProxyChain() : ProxyChain::Direct();
    }

    proxy_server_list.push_back(
        ProxyUriToProxyServer(uri, default_scheme, is_quic_allowed));
  }

  return ProxyChain(std::move(proxy_server_list));
}
}  // namespace net

"""

```