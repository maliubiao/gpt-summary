Response:
Let's break down the thought process for analyzing this C++ code and answering the prompt's questions.

**1. Understanding the Goal:**

The core purpose of this file is to define rules for matching URLs based on their scheme, host, and port. The classes within this file represent different types of these matching rules. The prompt asks for functionality, relation to JavaScript, examples, error scenarios, and debugging context.

**2. Initial Code Scan and Class Identification:**

The first step is to quickly scan the code and identify the key classes and their relationships. I see:

* `SchemeHostPortMatcherRule`: This is the base class, suggesting polymorphism. It has a static factory method `FromUntrimmedRawString`.
* `SchemeHostPortMatcherHostnamePatternRule`:  Derived from the base class, deals with matching hostnames using patterns (like wildcards).
* `SchemeHostPortMatcherIPHostRule`:  Derived from the base class, matches specific IP addresses and optional ports.
* `SchemeHostPortMatcherIPBlockRule`: Derived from the base class, matches IP addresses within a specified CIDR block.

This structure suggests a design pattern where you can create different matching rules and evaluate them against a URL.

**3. Analyzing `FromUntrimmedRawString`:**

This static method is crucial. It takes a raw string as input and parses it to create a specific rule object. I need to analyze the parsing logic:

* **Trimming:**  Whitespace is removed.
* **Scheme Extraction:**  Looks for `://` to identify and extract the scheme.
* **CIDR Check:** Checks for `/` to determine if it's an IP block rule. Uses `ParseCIDRBlock`.
* **IP Address/Port Check:**  Uses `ParseHostAndPort` and `AssignFromIPLiteral` to see if it's a specific IP address.
* **Hostname Pattern:** If none of the above, assumes it's a hostname pattern with an optional port. Handles leading dots (`.`) as wildcard indicators.

**4. Analyzing Individual Rule Classes:**

For each derived class, I focus on:

* **Constructor:** How is it initialized? What parameters does it take?
* **`Evaluate` Method:** This is the core matching logic. How does it compare the rule against a given `GURL`?  Pay attention to case sensitivity (using `base::ToLowerASCII`).
* **`ToString` Method:** How is the rule represented as a string? Useful for debugging and logging.
* **`IsHostnamePatternRule`:** A simple type check.
* **`GenerateSuffixMatchingRule` (for `HostnamePatternRule`):** This looks interesting. It seems to create a more general rule by adding a wildcard prefix.
* **`EstimateMemoryUsage`:**  Relevant for performance analysis, but not central to the core functionality for the prompt.

**5. Answering the Prompt's Questions:**

Now that I understand the code, I can address each part of the prompt:

* **Functionality:** Summarize the purpose of each class and the overall goal of matching URLs based on patterns and specific values.
* **Relation to JavaScript:** This requires careful consideration. While this C++ code itself doesn't directly interact with JavaScript *within the same process*, its functionality can influence JavaScript behavior in the browser. Think about network requests initiated by JavaScript. Features like proxy settings, Content Security Policy, and extension-based blocking often rely on this kind of URL matching logic. This is where the examples come in.
* **Logical Reasoning (Input/Output):**  Choose different input strings for `FromUntrimmedRawString` and trace the code's execution to determine which rule type is created and how the `Evaluate` method would work for example URLs. This reinforces the understanding of the parsing logic.
* **User/Programming Errors:** Consider common mistakes developers might make when providing the rule strings. Incorrect syntax, invalid ports, and misunderstanding wildcard behavior are good examples.
* **User Operation to Reach Here (Debugging):**  Think about the browser's network stack. Where would these rules be used?  Proxy configuration, extension settings, and network interception are good candidates. Describe the user actions that might lead to the evaluation of these rules.

**6. Iteration and Refinement:**

As I draft the answers, I might revisit the code to clarify details or ensure accuracy. For example, I double-checked the wildcard handling in `HostnamePatternRule` and the port handling in `IPHostRule`. I also considered the potential for internationalized domain names (IDNs), although the code doesn't explicitly handle them in a special way (it relies on `GURL`).

**Self-Correction Example During the Process:**

Initially, I might have focused too much on the low-level C++ details. However, the prompt specifically asks about the *relationship* with JavaScript. I'd then realize that I need to shift my focus to how this C++ code affects the browser's behavior regarding network requests initiated by JavaScript, even if there's no direct C++/JavaScript interop in this specific file. This leads to the examples involving proxy settings and content blocking.

By following these steps, combining code analysis with a broader understanding of the browser's architecture, I can provide a comprehensive and accurate answer to the prompt.
好的，让我们来分析一下 `net/base/scheme_host_port_matcher_rule.cc` 这个 Chromium 网络栈的源代码文件。

**功能概述**

这个文件定义了一系列类，用于根据 URL 的 scheme（协议），host（主机名或 IP 地址），以及 port（端口号）来匹配 URL。这些匹配规则可以用于各种网络相关的策略和配置，例如：

* **阻止或允许特定来源的请求：** 例如，阻止来自特定域名的图片加载。
* **配置代理服务器：**  为特定的 host 或 scheme 使用不同的代理服务器。
* **Content Security Policy (CSP)：**  限制可以加载的资源来源。
* **HSTS (HTTP Strict Transport Security)：**  指定哪些域名必须通过 HTTPS 访问。
* **扩展程序 API：** 允许扩展程序根据 URL 匹配规则执行操作。

**核心类和功能分解**

1. **`SchemeHostPortMatcherRule` (抽象基类)**
   - 定义了匹配规则的通用接口。
   - 提供了一个静态工厂方法 `FromUntrimmedRawString`，用于从字符串解析并创建具体的规则对象。这个方法是入口点，负责识别字符串的格式并创建合适的子类实例。
   - 提供了虚函数 `Evaluate`，用于判断给定的 URL 是否匹配规则。
   - 提供了虚函数 `ToString`，用于将规则转换为字符串表示。
   - 提供了虚函数 `IsHostnamePatternRule`，用于判断是否是主机名模式匹配规则。
   - 提供了虚函数 `EstimateMemoryUsage` (非 CRONET 构建)，用于估计规则对象占用的内存大小。

2. **`SchemeHostPortMatcherHostnamePatternRule` (派生类)**
   - 用于匹配主机名模式，支持通配符（`*`）。
   - 可以指定可选的 scheme 和 port。
   - `Evaluate` 方法使用 `base::MatchPattern` 来进行主机名匹配（大小写不敏感）。
   - `GenerateSuffixMatchingRule` 方法可以生成一个后缀匹配规则，例如将 `google.com` 转换为 `*.google.com`。

3. **`SchemeHostPortMatcherIPHostRule` (派生类)**
   - 用于匹配特定的 IP 地址和可选的端口。
   - 可以指定可选的 scheme。
   - `Evaluate` 方法直接比较 URL 的 host 和端口。

4. **`SchemeHostPortMatcherIPBlockRule` (派生类)**
   - 用于匹配一个 IP 地址段（使用 CIDR 表示法）。
   - 可以指定可选的 scheme。
   - `Evaluate` 方法使用 `IPAddressMatchesPrefix` 函数来判断 URL 的 IP 地址是否属于指定的地址段。

**与 JavaScript 的关系**

这个 C++ 代码本身并不直接包含 JavaScript 代码，但它的功能深深地影响着 JavaScript 在浏览器中的行为。当 JavaScript 发起网络请求时，浏览器会使用这些匹配规则来决定如何处理这些请求。以下是一些例子：

* **代理设置:** JavaScript 发起一个 `fetch` 请求时，浏览器可能会根据 `SchemeHostPortMatcherRule` 的配置，决定是否需要通过代理服务器发送请求。例如，可以设置规则 "example.com" 使用特定的代理。

   ```javascript
   // 假设浏览器配置了 "example.com" 需要使用代理
   fetch('https://example.com/data')
     .then(response => response.json())
     .then(data => console.log(data));
   ```
   在这个例子中，当 `fetch` 发起请求到 `https://example.com/data` 时，浏览器网络栈会使用 `SchemeHostPortMatcherRule` 来判断是否需要使用代理服务器。

* **内容安全策略 (CSP):**  CSP 使用类似的规则来限制 JavaScript 可以加载的资源来源。例如，CSP 指令 `img-src 'self' data:` 允许加载来自同源和 data URI 的图片。这背后会使用类似于 `SchemeHostPortMatcherRule` 的机制来匹配资源的 URL。

   ```html
   <!-- 假设网页的 CSP 头包含 img-src 'self' data: -->
   <img src="/images/logo.png">  <!-- 允许 (同源) -->
   <img src="data:image/png;base64,..."> <!-- 允许 (data URI) -->
   <img src="https://otherdomain.com/image.jpg"> <!-- 可能被阻止 -->
   ```
   当浏览器尝试加载这些图片时，CSP 机制会使用类似的 URL 匹配逻辑来决定是否允许加载。

* **扩展程序 API:** Chrome 扩展程序可以使用 `chrome.webRequest` API 来拦截和修改网络请求。这些 API 允许扩展程序定义 URL 匹配规则，以便在满足条件时执行特定操作，例如阻止请求或修改请求头。

   ```javascript
   // 扩展程序代码，拦截对 *.example.com 的请求
   chrome.webRequest.onBeforeRequest.addListener(
     function(details) {
       console.log("拦截到请求:", details.url);
       return {cancel: true}; // 阻止请求
     },
     {urls: ["*://*.example.com/*"]}
   );
   ```
   这里的 `urls` 属性就使用了类似 `SchemeHostPortMatcherRule` 的匹配模式。

**逻辑推理 (假设输入与输出)**

假设我们调用 `SchemeHostPortMatcherRule::FromUntrimmedRawString` 方法：

**假设输入 1:** `"https://example.com:8080"`

* **处理过程:**
    1. 去除空格 (无)。
    2. 找到 `://`，提取 scheme 为 `"https"`。
    3. 剩余部分 `"example.com:8080"` 不包含 `/`，不是 IP 块规则。
    4. 使用 `ParseHostAndPort` 解析 `"example.com:8080"`，得到 host `"example.com"`，port `8080`。
    5. `"example.com"` 不是 IP 地址。
    6. 创建 `SchemeHostPortMatcherHostnamePatternRule` 对象，scheme 为 `"https"`，hostname_pattern 为 `"example.com"`，port 为 `8080`。
* **输出:**  一个指向 `SchemeHostPortMatcherHostnamePatternRule` 对象的 `std::unique_ptr`。

**假设输入 2:** `"192.168.1.0/24"`

* **处理过程:**
    1. 去除空格 (无)。
    2. 未找到 `://`，scheme 为空。
    3. 找到 `/`，判断为 IP 块规则。
    4. 使用 `ParseCIDRBlock` 解析 `"192.168.1.0/24"`，得到 ip_prefix 为 `192.168.1.0`，prefix_length_in_bits 为 `24`。
    5. 创建 `SchemeHostPortMatcherIPBlockRule` 对象，description 为 `"192.168.1.0/24"`，scheme 为空，ip_prefix 为 `192.168.1.0`，prefix_length_in_bits 为 `24`。
* **输出:** 一个指向 `SchemeHostPortMatcherIPBlockRule` 对象的 `std::unique_ptr`。

**假设输入 3:** `"*.google.com"`

* **处理过程:**
    1. 去除空格 (无)。
    2. 未找到 `://`，scheme 为空。
    3. 不包含 `/`，不是 IP 块规则。
    4. 使用 `ParseHostAndPort` 解析 `"*.google.com"`，无法解析出有效的 IP 地址。
    5. 识别为 hostname pattern。
    6. 开头是 `*`，hostname_pattern 为 `"*.google.com"`。
    7. 创建 `SchemeHostPortMatcherHostnamePatternRule` 对象，scheme 为空，hostname_pattern 为 `"*.google.com"`，port 为 `-1`。
* **输出:** 一个指向 `SchemeHostPortMatcherHostnamePatternRule` 对象的 `std::unique_ptr`。

**用户或编程常见的使用错误**

1. **错误的语法格式:**  用户在配置规则时，可能会输入错误的字符串格式，导致解析失败。例如，缺少 `://`，或者端口号不是数字。
   * **例子:** `"example.com:abc"` (端口号错误)，`"http//example.com"` (缺少一个 `/`)。

2. **通配符使用不当:**  对于 `SchemeHostPortMatcherHostnamePatternRule`，用户可能不理解通配符 `*` 的作用范围。
   * **例子:**  配置了 `".example.com"`，实际上会被转换为 `"*.example.com"`，匹配所有以 `.example.com` 结尾的域名，可能超出预期。

3. **IP 地址和主机名混淆:**  用户可能期望主机名规则也能匹配 IP 地址，反之亦然。
   * **例子:** 配置了 `"example.com"`，但期望它能阻止访问 `192.0.2.1` (假设 `example.com` 解析到这个 IP)。实际上，需要分别配置主机名规则和 IP 地址规则。

4. **端口号范围错误:**  端口号必须是 0 到 65535 的整数。
   * **例子:** 配置了 `"example.com:70000"`，端口号超出范围。

5. **Scheme 的大小写:** 虽然代码中将 scheme 转换为小写进行比较，但用户在配置时可能会混淆大小写。建议统一使用小写。

**用户操作如何一步步到达这里 (调试线索)**

作为调试线索，以下用户操作可能会触发对 `SchemeHostPortMatcherRule` 的使用：

1. **配置代理服务器:**
   - 用户打开浏览器设置，找到代理服务器配置。
   - 用户手动输入代理服务器地址和端口，并可能配置“不使用代理的地址”列表。
   - “不使用代理的地址”列表中的条目会被解析成 `SchemeHostPortMatcherRule` 对象。

2. **安装或配置浏览器扩展程序:**
   - 用户安装了一个可以拦截或修改网络请求的扩展程序。
   - 扩展程序使用 `chrome.webRequest` API，并定义了 URL 匹配规则。
   - 这些规则会被转换为 `SchemeHostPortMatcherRule` 对象。

3. **浏览器加载网页并遇到 CSP 策略:**
   - 网站的 HTTP 响应头中包含了 `Content-Security-Policy` 字段。
   - 浏览器解析 CSP 策略，其中的指令（例如 `img-src`, `script-src`）包含了 URL 匹配模式。
   - 这些模式会间接地通过浏览器的内部机制与 `SchemeHostPortMatcherRule` 的功能类似的方式进行处理。

4. **浏览器处理 HSTS 信息:**
   - 浏览器访问了一个启用了 HSTS 的网站，或者本地存储了 HSTS 信息。
   - HSTS 信息包含了必须使用 HTTPS 访问的域名，这可以看作是一种特殊的 scheme 匹配规则。

5. **用户通过命令行或其他方式设置 Chromium 的网络配置:**
   - Chromium 支持通过命令行参数或配置文件来设置网络策略，例如阻止特定类型的请求。
   - 这些配置可能会使用类似于 `SchemeHostPortMatcherRule` 的机制。

**调试示例:**

假设用户报告某个网站的图片无法加载。作为开发者，你可以：

1. **检查网络请求:** 使用 Chrome 的开发者工具 (Network 面板) 查看该图片的请求是否被阻止，以及是否有相关的错误信息。
2. **检查 CSP 策略:** 查看网页的响应头，确认是否存在阻止图片加载的 CSP 策略。
3. **检查代理设置:**  如果配置了代理，尝试禁用代理查看问题是否依旧存在。
4. **检查扩展程序:** 禁用可疑的扩展程序，看是否是扩展程序阻止了请求。
5. **查看 Chromium 内部的网络配置:**  可以通过 `chrome://net-internals/#events` 查看更底层的网络事件，搜索与该域名相关的事件，可能会看到 `SchemeHostPortMatcherRule` 相关的日志或匹配信息。

总结来说，`net/base/scheme_host_port_matcher_rule.cc` 定义了 Chromium 网络栈中用于 URL 匹配的核心机制，它在浏览器的各种网络功能中扮演着重要的角色，并且直接影响着 JavaScript 发起的网络请求的行为。理解其工作原理对于调试网络相关的问题至关重要。

Prompt: 
```
这是目录为net/base/scheme_host_port_matcher_rule.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/base/scheme_host_port_matcher_rule.h"

#include "base/strings/pattern.h"
#include "base/strings/strcat.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/trace_event/memory_usage_estimator.h"
#include "net/base/host_port_pair.h"
#include "net/base/parse_number.h"
#include "net/base/url_util.h"
#include "url/url_util.h"

namespace net {

namespace {

std::string AddBracketsIfIPv6(const IPAddress& ip_address) {
  std::string ip_host = ip_address.ToString();
  if (ip_address.IsIPv6())
    return base::StringPrintf("[%s]", ip_host.c_str());
  return ip_host;
}

}  // namespace

// static
std::unique_ptr<SchemeHostPortMatcherRule>
SchemeHostPortMatcherRule::FromUntrimmedRawString(
    std::string_view raw_untrimmed) {
  std::string_view raw =
      base::TrimWhitespaceASCII(raw_untrimmed, base::TRIM_ALL);

  // Extract any scheme-restriction.
  std::string::size_type scheme_pos = raw.find("://");
  std::string scheme;
  if (scheme_pos != std::string::npos) {
    scheme = std::string(raw.substr(0, scheme_pos));
    raw = raw.substr(scheme_pos + 3);
    if (scheme.empty())
      return nullptr;
  }

  if (raw.empty())
    return nullptr;

  // If there is a forward slash in the input, it is probably a CIDR style
  // mask.
  if (raw.find('/') != std::string::npos) {
    IPAddress ip_prefix;
    size_t prefix_length_in_bits;

    if (!ParseCIDRBlock(raw, &ip_prefix, &prefix_length_in_bits))
      return nullptr;

    return std::make_unique<SchemeHostPortMatcherIPBlockRule>(
        std::string(raw), scheme, ip_prefix, prefix_length_in_bits);
  }

  // Check if we have an <ip-address>[:port] input. We need to treat this
  // separately since the IP literal may not be in a canonical form.
  std::string host;
  int port;
  if (ParseHostAndPort(raw, &host, &port)) {
    IPAddress ip_address;
    if (ip_address.AssignFromIPLiteral(host)) {
      // Instead of -1, 0 is invalid for IPEndPoint.
      int adjusted_port = port == -1 ? 0 : port;
      return std::make_unique<SchemeHostPortMatcherIPHostRule>(
          scheme, IPEndPoint(ip_address, adjusted_port));
    }
  }

  // Otherwise assume we have <hostname-pattern>[:port].
  std::string::size_type pos_colon = raw.rfind(':');
  port = -1;
  if (pos_colon != std::string::npos) {
    if (!ParseInt32(
            base::MakeStringPiece(raw.begin() + pos_colon + 1, raw.end()),
            ParseIntFormat::NON_NEGATIVE, &port) ||
        port > 0xFFFF) {
      return nullptr;  // Port was invalid.
    }
    raw = raw.substr(0, pos_colon);
  }

  // Special-case hostnames that begin with a period.
  // For example, we remap ".google.com" --> "*.google.com".
  std::string hostname_pattern;
  if (raw.starts_with(".")) {
    hostname_pattern = base::StrCat({"*", raw});
  } else {
    hostname_pattern = std::string(raw);
  }

  return std::make_unique<SchemeHostPortMatcherHostnamePatternRule>(
      scheme, hostname_pattern, port);
}

bool SchemeHostPortMatcherRule::IsHostnamePatternRule() const {
  return false;
}

#if !BUILDFLAG(CRONET_BUILD)
size_t SchemeHostPortMatcherRule::EstimateMemoryUsage() const {
  return 0;
}
#endif  // !BUILDFLAG(CRONET_BUILD)

SchemeHostPortMatcherHostnamePatternRule::
    SchemeHostPortMatcherHostnamePatternRule(
        const std::string& optional_scheme,
        const std::string& hostname_pattern,
        int optional_port)
    : optional_scheme_(base::ToLowerASCII(optional_scheme)),
      hostname_pattern_(base::ToLowerASCII(hostname_pattern)),
      optional_port_(optional_port) {
  // |hostname_pattern| shouldn't be an IP address.
  DCHECK(!url::HostIsIPAddress(hostname_pattern));
}

SchemeHostPortMatcherResult SchemeHostPortMatcherHostnamePatternRule::Evaluate(
    const GURL& url) const {
  if (optional_port_ != -1 && url.EffectiveIntPort() != optional_port_) {
    // Didn't match port expectation.
    return SchemeHostPortMatcherResult::kNoMatch;
  }

  if (!optional_scheme_.empty() && url.scheme() != optional_scheme_) {
    // Didn't match scheme expectation.
    return SchemeHostPortMatcherResult::kNoMatch;
  }

  // Note it is necessary to lower-case the host, since GURL uses capital
  // letters for percent-escaped characters.
  return base::MatchPattern(url.host(), hostname_pattern_)
             ? SchemeHostPortMatcherResult::kInclude
             : SchemeHostPortMatcherResult::kNoMatch;
}

std::string SchemeHostPortMatcherHostnamePatternRule::ToString() const {
  std::string str;
  if (!optional_scheme_.empty())
    base::StringAppendF(&str, "%s://", optional_scheme_.c_str());
  str += hostname_pattern_;
  if (optional_port_ != -1)
    base::StringAppendF(&str, ":%d", optional_port_);
  return str;
}

bool SchemeHostPortMatcherHostnamePatternRule::IsHostnamePatternRule() const {
  return true;
}

std::unique_ptr<SchemeHostPortMatcherHostnamePatternRule>
SchemeHostPortMatcherHostnamePatternRule::GenerateSuffixMatchingRule() const {
  if (!hostname_pattern_.starts_with("*")) {
    return std::make_unique<SchemeHostPortMatcherHostnamePatternRule>(
        optional_scheme_, "*" + hostname_pattern_, optional_port_);
  }
  // return a new SchemeHostPortMatcherHostNamePatternRule with the same data.
  return std::make_unique<SchemeHostPortMatcherHostnamePatternRule>(
      optional_scheme_, hostname_pattern_, optional_port_);
}

#if !BUILDFLAG(CRONET_BUILD)
size_t SchemeHostPortMatcherHostnamePatternRule::EstimateMemoryUsage() const {
  return base::trace_event::EstimateMemoryUsage(optional_scheme_) +
         base::trace_event::EstimateMemoryUsage(hostname_pattern_);
}
#endif  // !BUILDFLAG(CRONET_BUILD)

SchemeHostPortMatcherIPHostRule::SchemeHostPortMatcherIPHostRule(
    const std::string& optional_scheme,
    const IPEndPoint& ip_end_point)
    : optional_scheme_(base::ToLowerASCII(optional_scheme)),
      ip_host_(AddBracketsIfIPv6(ip_end_point.address())),
      optional_port_(ip_end_point.port()) {}

SchemeHostPortMatcherResult SchemeHostPortMatcherIPHostRule::Evaluate(
    const GURL& url) const {
  if (optional_port_ != 0 && url.EffectiveIntPort() != optional_port_) {
    // Didn't match port expectation.
    return SchemeHostPortMatcherResult::kNoMatch;
  }

  if (!optional_scheme_.empty() && url.scheme() != optional_scheme_) {
    // Didn't match scheme expectation.
    return SchemeHostPortMatcherResult::kNoMatch;
  }

  // Note it is necessary to lower-case the host, since GURL uses capital
  // letters for percent-escaped characters.
  return base::MatchPattern(url.host(), ip_host_)
             ? SchemeHostPortMatcherResult::kInclude
             : SchemeHostPortMatcherResult::kNoMatch;
}

std::string SchemeHostPortMatcherIPHostRule::ToString() const {
  std::string str;
  if (!optional_scheme_.empty())
    base::StringAppendF(&str, "%s://", optional_scheme_.c_str());
  str += ip_host_;
  if (optional_port_ != 0)
    base::StringAppendF(&str, ":%d", optional_port_);
  return str;
}

#if !BUILDFLAG(CRONET_BUILD)
size_t SchemeHostPortMatcherIPHostRule::EstimateMemoryUsage() const {
  return base::trace_event::EstimateMemoryUsage(optional_scheme_) +
         base::trace_event::EstimateMemoryUsage(ip_host_);
}
#endif  // !BUILDFLAG(CRONET_BUILD)

SchemeHostPortMatcherIPBlockRule::SchemeHostPortMatcherIPBlockRule(
    const std::string& description,
    const std::string& optional_scheme,
    const IPAddress& ip_prefix,
    size_t prefix_length_in_bits)
    : description_(description),
      optional_scheme_(optional_scheme),
      ip_prefix_(ip_prefix),
      prefix_length_in_bits_(prefix_length_in_bits) {}

SchemeHostPortMatcherResult SchemeHostPortMatcherIPBlockRule::Evaluate(
    const GURL& url) const {
  if (!url.HostIsIPAddress())
    return SchemeHostPortMatcherResult::kNoMatch;

  if (!optional_scheme_.empty() && url.scheme() != optional_scheme_) {
    // Didn't match scheme expectation.
    return SchemeHostPortMatcherResult::kNoMatch;
  }

  // Parse the input IP literal to a number.
  IPAddress ip_address;
  if (!ip_address.AssignFromIPLiteral(url.HostNoBracketsPiece()))
    return SchemeHostPortMatcherResult::kNoMatch;

  // Test if it has the expected prefix.
  return IPAddressMatchesPrefix(ip_address, ip_prefix_, prefix_length_in_bits_)
             ? SchemeHostPortMatcherResult::kInclude
             : SchemeHostPortMatcherResult::kNoMatch;
}

std::string SchemeHostPortMatcherIPBlockRule::ToString() const {
  return description_;
}

#if !BUILDFLAG(CRONET_BUILD)
size_t SchemeHostPortMatcherIPBlockRule::EstimateMemoryUsage() const {
  return base::trace_event::EstimateMemoryUsage(description_) +
         base::trace_event::EstimateMemoryUsage(optional_scheme_) +
         base::trace_event::EstimateMemoryUsage(ip_prefix_);
}
#endif  // !BUILDFLAG(CRONET_BUILD)

}  // namespace net

"""

```