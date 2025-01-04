Response:
Let's break down the thought process for analyzing this C++ code and generating the explanation.

1. **Understand the Goal:** The primary request is to explain the functionality of `csp_source.cc` within the Chromium Blink rendering engine, focusing on its relationship to JavaScript, HTML, and CSS, providing examples, and highlighting potential usage errors.

2. **Initial Code Scan and Keyword Identification:**  I start by quickly scanning the code, looking for keywords and patterns. Things that jump out are:
    * `CSPSource`: This is clearly the core concept.
    * `SchemeMatches`, `HostMatches`, `PortMatches`, `PathMatches`: These are likely the fundamental matching functions.
    * `kMatchingExact`, `kMatchingUpgrade`, `kMatchingWildcard`, `kNotMatching`: These are the results of the matching functions, indicating different levels of agreement.
    * `network::mojom::blink::CSPSource`: This suggests interaction with a network-related component and likely represents the data structure holding the CSP source information.
    * `KURL`: This is Chromium's URL class, indicating the code deals with URLs.
    * `self_protocol`:  This hints at the context of the current document or resource.
    * `redirect_status`: This indicates handling of redirects.
    * `CSPSourceMatches`, `CSPSourceMatchesAsSelf`:  These are the main public functions, implementing the overall matching logic.
    * Comments like "// host-part = \"*\"" and "// host-part = \"*.\" 1*host-char *( \".\" 1*host-char )" provide valuable clues about the matching rules.

3. **Decipher the Core Logic:** I focus on the individual matching functions:
    * **`SchemeMatches`**:  This checks if the protocol of a URL matches the allowed source's protocol, including allowing upgrades (HTTP to HTTPS, WS to WSS). The `self_protocol` argument is interesting – it suggests a context-dependent check.
    * **`HostMatches`**: This handles exact hostname matching and wildcard matching (`*.example.com`). The comment about non-special URLs and `url.IsStandard()` is a crucial detail.
    * **`PathMatches`**: This compares the path of a URL against the allowed source's path, including handling of trailing slashes.
    * **`PortMatches`**: This is more complex, handling exact port matches, wildcard ports (implicit), and upgrades (HTTP/80 to HTTPS/443). The handling of default ports is significant.

4. **Understand `CSPSourceMatches` and `CSPSourceMatchesAsSelf`:**
    * **`CSPSourceMatches`**: This appears to be the primary function for checking if a given URL is allowed by a CSP source directive. It combines the individual matching functions, considering redirects and ensuring consistent upgrades of both scheme and port.
    * **`CSPSourceMatchesAsSelf`**: This seems to handle the specific case of the `self` keyword in CSP, which has special rules, including handling of `file:` URLs.

5. **Relate to Web Technologies:** Now, I connect the C++ code to the web technologies mentioned in the prompt:
    * **JavaScript:** CSP directly impacts JavaScript execution. If a script source doesn't match the CSP, the browser will block its execution.
    * **HTML:**  `<script>`, `<img>`, `<link>`, etc., tags load resources. CSP controls which sources these resources can be loaded from. Inline scripts and styles are also affected.
    * **CSS:**  CSP can control the sources of stylesheets loaded via `<link>` and `@import`. Inline styles can also be restricted.

6. **Construct Examples:**  For each function and the main logic, I create concrete examples. These examples should illustrate the different matching scenarios (exact, wildcard, upgrade, mismatch) and the impact on JavaScript, HTML, and CSS. I try to include examples that are easy to understand and clearly demonstrate the function's purpose.

7. **Identify Potential Usage Errors:**  I consider common mistakes developers might make when defining CSP rules. This includes:
    * Incorrectly using wildcards.
    * Forgetting about port numbers or default ports.
    * Not understanding scheme upgrades.
    * Issues with `file:` URLs and the `self` keyword.
    * Errors related to redirects.

8. **Structure the Explanation:** I organize the explanation logically, starting with an overview, then detailing each function, providing examples, and finally discussing usage errors. Using headings and bullet points makes the explanation easier to read.

9. **Refine and Review:**  I reread the code and my explanation to ensure accuracy, clarity, and completeness. I check if all parts of the prompt have been addressed. I ensure the examples are correct and the explanations are easy to understand for someone with a basic understanding of web security and CSP. For instance, I initially might not have emphasized the redirect handling as much and would go back to add that detail. Similarly, making the connection to how these blocks manifest in the developer console is important.

This iterative process of understanding the code, connecting it to web concepts, generating examples, and refining the explanation leads to a comprehensive and helpful answer. The key is to break down the complex code into smaller, understandable parts and then build back up to the overall functionality and its implications.```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/frame/csp/csp_source.h"

#include "services/network/public/mojom/content_security_policy.mojom-blink.h"
#include "third_party/blink/renderer/platform/weborigin/known_ports.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

namespace {

enum class SchemeMatchingResult {
  kNotMatching,
  kMatchingUpgrade,
  kMatchingExact
};

enum class PortMatchingResult {
  kNotMatching,
  kMatchingWildcard,
  kMatchingUpgrade,
  kMatchingExact
};

SchemeMatchingResult SchemeMatches(
    const network::mojom::blink::CSPSource& source,
    const String& protocol,
    const String& self_protocol) {
  DCHECK_EQ(protocol, protocol.DeprecatedLower());
  const String& scheme =
      (source.scheme.empty() ? self_protocol : source.scheme);

  if (scheme == protocol)
    return SchemeMatchingResult::kMatchingExact;

  if ((scheme == "http" && protocol == "https") ||
      (scheme == "ws" && protocol == "wss")) {
    return SchemeMatchingResult::kMatchingUpgrade;
  }

  return SchemeMatchingResult::kNotMatching;
}

bool HostMatches(const network::mojom::blink::CSPSource& source,
                 const StringView& host) {
  if (source.is_host_wildcard) {
    if (source.host.empty()) {
      // host-part = "*"
      return true;
    }
    if (host.ToString().EndsWith(String("." + source.host))) {
      // host-part = "*." 1*host-char *( "." 1*host-char )
      return true;
    }
    return false;
  }
  return source.host == host;
}

bool HostMatches(const network::mojom::blink::CSPSource& source,
                 const KURL& url) {
  // Chromium currently has an issue handling non-special URLs. The url.Host()
  // function returns an empty string for them. See
  // crbug.com/40063064 for details.
  //
  // In the future, once non-special URLs are fully supported, we might consider
  // checking the host information for them too.
  //
  // For now, we check `url.IsStandard()` to maintain consistent behavior
  // regardless of the url::StandardCompliantNonSpecialSchemeURLParsing feature
  // state.
  if (!url.IsStandard()) {
    return HostMatches(source, "");
  }
  return HostMatches(source, url.Host());
}

bool PathMatches(const network::mojom::blink::CSPSource& source,
                 const StringView& url_path) {
  if (source.path.empty() || (source.path == "/" && url_path.empty()))
    return true;

  String path =
      DecodeURLEscapeSequences(url_path, DecodeURLMode::kUTF8OrIsomorphic);

  if (source.path.EndsWith("/"))
    return path.StartsWith(source.path);

  return path == source.path;
}

PortMatchingResult PortMatches(const network::mojom::blink::CSPSource& source,
                               const String& self_protocol,
                               int port,
                               const String& protocol) {
  if (source.is_port_wildcard)
    return PortMatchingResult::kMatchingWildcard;

  if (port == source.port) {
    if (port == url::PORT_UNSPECIFIED)
      return PortMatchingResult::kMatchingWildcard;
    return PortMatchingResult::kMatchingExact;
  }

  bool is_scheme_http;  // needed for detecting an upgrade when the port is 0
  is_scheme_http = source.scheme.empty()
                       ? "http" == self_protocol
                       : "http" == source.scheme;

  if ((source.port == 80 ||
       ((source.port == url::PORT_UNSPECIFIED || source.port == 443) &&
        is_scheme_http)) &&
      (port == 443 || (port == url::PORT_UNSPECIFIED &&
                       DefaultPortForProtocol(protocol) == 443))) {
    return PortMatchingResult::kMatchingUpgrade;
  }

  if (port == url::PORT_UNSPECIFIED) {
    if (IsDefaultPortForProtocol(source.port, protocol))
      return PortMatchingResult::kMatchingExact;
    return PortMatchingResult::kNotMatching;
  }

  if (source.port == url::PORT_UNSPECIFIED) {
    if (IsDefaultPortForProtocol(port, protocol))
      return PortMatchingResult::kMatchingExact;
    return PortMatchingResult::kNotMatching;
  }

  return PortMatchingResult::kNotMatching;
}

// Helper inline functions for Port and Scheme MatchingResult enums
bool inline RequiresUpgrade(const PortMatchingResult result) {
  return result == PortMatchingResult::kMatchingUpgrade;
}
bool inline RequiresUpgrade(const SchemeMatchingResult result) {
  return result == SchemeMatchingResult::kMatchingUpgrade;
}

bool inline CanUpgrade(const PortMatchingResult result) {
  return result == PortMatchingResult::kMatchingUpgrade ||
         result == PortMatchingResult::kMatchingWildcard;
}

bool inline CanUpgrade(const SchemeMatchingResult result) {
  return result == SchemeMatchingResult::kMatchingUpgrade;
}

}  // namespace

bool CSPSourceMatches(const network::mojom::blink::CSPSource& source,
                      const String& self_protocol,
                      const KURL& url,
                      ResourceRequest::RedirectStatus redirect_status) {
  SchemeMatchingResult schemes_match =
      SchemeMatches(source, url.Protocol(), self_protocol);
  if (schemes_match == SchemeMatchingResult::kNotMatching)
    return false;
  if (CSPSourceIsSchemeOnly(source))
    return true;
  bool paths_match =
      (redirect_status == ResourceRequest::RedirectStatus::kFollowedRedirect) ||
      PathMatches(source, url.GetPath());
  PortMatchingResult ports_match = PortMatches(
      source, self_protocol, url.HasPort() ? url.Port() : url::PORT_UNSPECIFIED,
      url.Protocol());

  // if either the scheme or the port would require an upgrade (e.g. from http
  // to https) then check that both of them can upgrade to ensure that we don't
  // run into situations where we only upgrade the port but not the scheme or
  // viceversa
  if ((RequiresUpgrade(schemes_match) || (RequiresUpgrade(ports_match))) &&
      (!CanUpgrade(schemes_match) || !CanUpgrade(ports_match))) {
    return false;
  }

  return HostMatches(source, url) &&
         ports_match != PortMatchingResult::kNotMatching && paths_match;
}

bool CSPSourceMatchesAsSelf(const network::mojom::blink::CSPSource& source,
                            const KURL& url) {
  // https://w3c.github.io/webappsec-csp/#match-url-to-source-expression
  // Step 4.
  SchemeMatchingResult schemes_match =
      SchemeMatches(source, url.Protocol(), source.scheme);

  if (url.Protocol() == "file" &&
      schemes_match == SchemeMatchingResult::kMatchingExact) {
    // Determining the origin of a file URL is left as an exercise to the reader
    // https://url.spec.whatwg.org/#concept-url-origin. Let's always match file
    // URLs against 'self' delivered from a file. This avoids inconsistencies
    // between file:/// and file://localhost/.
    return true;
  }

  bool hosts_match = HostMatches(source, url);
  PortMatchingResult ports_match = PortMatches(
      source, source.scheme, url.HasPort() ? url.Port() : url::PORT_UNSPECIFIED,
      url.Protocol());

  // check if the origin is exactly matching
  if (schemes_match == SchemeMatchingResult::kMatchingExact && hosts_match &&
      (ports_match == PortMatchingResult::kMatchingExact ||
       ports_match == PortMatchingResult::kMatchingWildcard)) {
    return true;
  }

  bool ports_match_or_defaults =
      (ports_match == PortMatchingResult::kMatchingExact ||
       ((IsDefaultPortForProtocol(source.port, source.scheme) ||
         source.port == url::PORT_UNSPECIFIED) &&
        (!url.HasPort() ||
         IsDefaultPortForProtocol(url.Port(), url.Protocol()))));

  return hosts_match && ports_match_or_defaults &&
         (url.Protocol() == "https" || url.Protocol() == "wss" ||
          source.scheme == "http");
}

bool CSPSourceIsSchemeOnly(const network::mojom::blink::CSPSource& source) {
  return source.host.empty() && (!source.is_host_wildcard);
}

}  // namespace blink
```

### 功能列表

`blink/renderer/core/frame/csp/csp_source.cc` 文件的主要功能是：

1. **实现内容安全策略 (CSP) 中 `source-list` 的匹配逻辑**:  该文件定义了各种函数来判断一个给定的 URL 是否与 CSP 指令中允许的源 (source) 相匹配。 这是 CSP 核心功能的一部分，用于限制浏览器加载和执行资源的来源，从而提高网页安全性。

2. **`SchemeMatches`**:  比较 URL 的协议 (scheme) 与 CSP 源的协议。它支持精确匹配以及协议升级（例如，允许从 `http:` 加载资源到 `https:`）。

3. **`HostMatches`**:  比较 URL 的主机名 (hostname) 与 CSP 源的主机名。 它支持精确匹配和通配符匹配 (例如 `*.example.com`)。

4. **`PathMatches`**: 比较 URL 的路径 (path) 与 CSP 源的路径。

5. **`PortMatches`**: 比较 URL 的端口号 (port) 与 CSP 源的端口号。 它支持精确匹配、通配符（表示任意端口）以及默认端口的匹配和升级（例如，`http:` 的默认端口 `80` 可以匹配 `https:` 的默认端口 `443`）。

6. **`CSPSourceMatches`**:  这是核心函数，它接收一个 CSP 源、当前页面的协议、一个 URL 以及重定向状态，并根据协议、主机、端口和路径的匹配情况，判断该 URL 是否被允许。 它还处理协议和端口升级的情况。

7. **`CSPSourceMatchesAsSelf`**:  专门用于处理 CSP 中的 `self` 关键字。`self` 指的是与受保护文档相同的来源。 这个函数实现了 `self` 关键字的特殊匹配规则。

8. **`CSPSourceIsSchemeOnly`**: 检查一个 CSP 源是否只指定了协议，而没有指定主机或端口。 例如，`https:` 就是一个 scheme-only 的源。

### 与 JavaScript, HTML, CSS 的关系及举例说明

该文件中的逻辑直接影响浏览器如何加载和执行 JavaScript、HTML 和 CSS 资源，因为 CSP 的主要目标就是控制这些资源的来源。

**JavaScript:**

* **功能关系:** CSP 可以限制浏览器加载和执行外部 JavaScript 文件的来源，以及是否允许执行内联的 `<script>` 标签中的 JavaScript 代码。
* **举例说明:**
    * 假设 CSP 指令中包含 `script-src 'self' https://example.com;`。
    * 如果一个 HTML 文件尝试加载 `<script src="https://malicious.com/evil.js"></script>`，`CSPSourceMatches` 将会被调用来判断 `https://malicious.com` 是否被允许。 由于它不在 `'self'` 或 `https://example.com` 中，该脚本的加载将被阻止。
    * 如果尝试执行内联脚本 `<script>alert('hello');</script>`，并且 CSP 中没有 `'unsafe-inline'` 关键字，CSP 也会阻止执行。

**HTML:**

* **功能关系:** CSP 可以限制 HTML 文件中可以加载的各种资源，例如图片 (`<img>`)、样式表 (`<link rel="stylesheet">`)、iframe (`<iframe>`)、媒体文件 (`<video>`, `<audio>`) 等的来源。
* **举例说明:**
    * 假设 CSP 指令中包含 `img-src https://cdn.example.com;`。
    * 如果 HTML 中有 `<img src="https://another-cdn.com/image.png">`，`CSPSourceMatches` 会被调用来检查 `https://another-cdn.com` 是否被允许。 如果不允许，图片将无法加载。

**CSS:**

* **功能关系:** CSP 可以限制加载外部 CSS 样式表的来源，以及是否允许使用内联的 `<style>` 标签和 HTML 元素的 `style` 属性。
* **举例说明:**
    * 假设 CSP 指令中包含 `style-src 'self';`。
    * 如果 HTML 中有 `<link rel="stylesheet" href="https://external.styles.com/style.css">`，`CSPSourceMatches` 会判断 `https://external.styles.com` 是否被允许。 因为它不是 `'self'`，样式表将不会被加载。
    * 同样，如果尝试使用内联样式 `<div style="color: red;"></div>`，并且 CSP 中没有 `'unsafe-inline'` 关键字，CSP 可能会阻止样式的应用（取决于具体的 CSP 指令）。

### 逻辑推理、假设输入与输出

**假设输入 1:**

* `source`:  一个 `network::mojom::blink::CSPSource` 对象，表示 CSP 指令中的一个源，例如 `{scheme: "https", host: "example.com", is_host_wildcard: false, port: 443, is_port_wildcard: false, path: "/"}`
* `self_protocol`:  "https"
* `url`:  `KURL("https://example.com/index.html")`
* `redirect_status`: `ResourceRequest::RedirectStatus::kNoRedirect`

**逻辑推理:**

1. `SchemeMatches`("https", "https", "https") 返回 `kMatchingExact`。
2. `HostMatches`(source, url) 比较 "example.com" 和 "example.com"，返回 `true`。
3. `PortMatches`(source, "https", 443, "https") 返回 `kMatchingExact`。
4. `PathMatches`(source, "/index.html") 比较 "/" 和 "/index.html"，返回 `false`。
5. 由于 `redirect_status` 不是 `kFollowedRedirect`，路径需要匹配。

**输出:** `CSPSourceMatches` 返回 `false`。

**假设输入 2:**

* `source`:  一个 `network::mojom::blink::CSPSource` 对象，表示 CSP 指令中的一个源，例如 `{scheme: "http", host: "example.com", is_host_wildcard: false, port: 80, is_port_wildcard: false, path: "/"}`
* `self_protocol`:  "https"
* `url`:  `KURL("https://example.com/")`
* `redirect_status`: `ResourceRequest::RedirectStatus::kNoRedirect`

**逻辑推理:**

1. `SchemeMatches`("http", "https", "https") 返回 `kMatchingUpgrade`。
2. `HostMatches`(source, url) 比较 "example.com" 和 "example.com"，返回 `true`。
3. `PortMatches`(source, "https", 443, "https") 返回 `kMatchingUpgrade`。
4. `PathMatches`(source, "/") 比较 "/" 和 "/"，返回 `true`。
5. 协议和端口都需要升级，且两者都可以升级。

**输出:** `CSPSourceMatches` 返回 `true`。

### 用户或编程常见的使用错误

1. **忘记包含协议**:
   * **错误:** 在 CSP 中只写主机名，例如 `script-src example.com;`。
   * **后果:** 这不会匹配任何 HTTPS 资源，因为默认情况下浏览器会认为应该使用与当前页面相同的协议。 用户可能会意外阻止了他们想要加载的资源。

2. **通配符使用不当**:
   * **错误:** 使用 `script-src *.example.com;`，期望匹配所有子域名，但可能忘记也需要显式允许 `example.com` 本身。
   * **后果:**  直接在 `example.com` 上的脚本会被阻止。

3. **端口号混淆**:
   * **错误:** 假设 `https://example.com:8080/` 会被 `script-src 'self'` 允许。
   * **后果:**  由于端口号不同，这会被 CSP 阻止。 需要显式指定端口号，例如 `script-src 'self' https://example.com:8080;`。

4. **对协议升级理解不足**:
   * **错误:**  期望 `script-src http://example.com;` 会自动允许 `https://example.com` 上的资源。
   * **后果:**  CSP 策略默认不进行降级匹配。需要显式地允许 `https://example.com`。 然而，从 `http` 升级到 `https` 是允许的，反之则不然。

5. **`'self'` 关键字的误用**:
   * **错误:** 认为 `'self'` 会允许来自任何子域名的资源。
   * **后果:** `'self'` 只匹配与受保护文档完全相同的来源（协议、域名和端口）。

6. **内联资源的处理不当**:
   * **错误:**  忘记添加 `'unsafe-inline'` 或使用 nonce/hash 来允许内联脚本或样式。
   * **后果:**  内联的 `<script>` 和 `<style>` 标签中的代码将被阻止执行/应用。

7. **重定向处理疏忽**:
   * **错误:** CSP 策略没有考虑到资源可能会发生重定向。
   * **后果:**  如果一个允许的资源重定向到一个不被允许的来源，加载可能会失败。 `CSPSourceMatches` 函数的 `redirect_status` 参数就是用来处理这种情况的。

理解 `csp_source.cc` 中的匹配逻辑对于正确配置和调试 CSP 至关重要，以确保网页安全性的同时不会意外阻止合法资源的加载。

Prompt: 
```
这是目录为blink/renderer/core/frame/csp/csp_source.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/frame/csp/csp_source.h"

#include "services/network/public/mojom/content_security_policy.mojom-blink.h"
#include "third_party/blink/renderer/platform/weborigin/known_ports.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

namespace {

enum class SchemeMatchingResult {
  kNotMatching,
  kMatchingUpgrade,
  kMatchingExact
};

enum class PortMatchingResult {
  kNotMatching,
  kMatchingWildcard,
  kMatchingUpgrade,
  kMatchingExact
};

SchemeMatchingResult SchemeMatches(
    const network::mojom::blink::CSPSource& source,
    const String& protocol,
    const String& self_protocol) {
  DCHECK_EQ(protocol, protocol.DeprecatedLower());
  const String& scheme =
      (source.scheme.empty() ? self_protocol : source.scheme);

  if (scheme == protocol)
    return SchemeMatchingResult::kMatchingExact;

  if ((scheme == "http" && protocol == "https") ||
      (scheme == "ws" && protocol == "wss")) {
    return SchemeMatchingResult::kMatchingUpgrade;
  }

  return SchemeMatchingResult::kNotMatching;
}

bool HostMatches(const network::mojom::blink::CSPSource& source,
                 const StringView& host) {
  if (source.is_host_wildcard) {
    if (source.host.empty()) {
      // host-part = "*"
      return true;
    }
    if (host.ToString().EndsWith(String("." + source.host))) {
      // host-part = "*." 1*host-char *( "." 1*host-char )
      return true;
    }
    return false;
  }
  return source.host == host;
}

bool HostMatches(const network::mojom::blink::CSPSource& source,
                 const KURL& url) {
  // Chromium currently has an issue handling non-special URLs. The url.Host()
  // function returns an empty string for them. See
  // crbug.com/40063064 for details.
  //
  // In the future, once non-special URLs are fully supported, we might consider
  // checking the host information for them too.
  //
  // For now, we check `url.IsStandard()` to maintain consistent behavior
  // regardless of the url::StandardCompliantNonSpecialSchemeURLParsing feature
  // state.
  if (!url.IsStandard()) {
    return HostMatches(source, "");
  }
  return HostMatches(source, url.Host());
}

bool PathMatches(const network::mojom::blink::CSPSource& source,
                 const StringView& url_path) {
  if (source.path.empty() || (source.path == "/" && url_path.empty()))
    return true;

  String path =
      DecodeURLEscapeSequences(url_path, DecodeURLMode::kUTF8OrIsomorphic);

  if (source.path.EndsWith("/"))
    return path.StartsWith(source.path);

  return path == source.path;
}

PortMatchingResult PortMatches(const network::mojom::blink::CSPSource& source,
                               const String& self_protocol,
                               int port,
                               const String& protocol) {
  if (source.is_port_wildcard)
    return PortMatchingResult::kMatchingWildcard;

  if (port == source.port) {
    if (port == url::PORT_UNSPECIFIED)
      return PortMatchingResult::kMatchingWildcard;
    return PortMatchingResult::kMatchingExact;
  }

  bool is_scheme_http;  // needed for detecting an upgrade when the port is 0
  is_scheme_http = source.scheme.empty()
                       ? "http" == self_protocol
                       : "http" == source.scheme;

  if ((source.port == 80 ||
       ((source.port == url::PORT_UNSPECIFIED || source.port == 443) &&
        is_scheme_http)) &&
      (port == 443 || (port == url::PORT_UNSPECIFIED &&
                       DefaultPortForProtocol(protocol) == 443))) {
    return PortMatchingResult::kMatchingUpgrade;
  }

  if (port == url::PORT_UNSPECIFIED) {
    if (IsDefaultPortForProtocol(source.port, protocol))
      return PortMatchingResult::kMatchingExact;
    return PortMatchingResult::kNotMatching;
  }

  if (source.port == url::PORT_UNSPECIFIED) {
    if (IsDefaultPortForProtocol(port, protocol))
      return PortMatchingResult::kMatchingExact;
    return PortMatchingResult::kNotMatching;
  }

  return PortMatchingResult::kNotMatching;
}

// Helper inline functions for Port and Scheme MatchingResult enums
bool inline RequiresUpgrade(const PortMatchingResult result) {
  return result == PortMatchingResult::kMatchingUpgrade;
}
bool inline RequiresUpgrade(const SchemeMatchingResult result) {
  return result == SchemeMatchingResult::kMatchingUpgrade;
}

bool inline CanUpgrade(const PortMatchingResult result) {
  return result == PortMatchingResult::kMatchingUpgrade ||
         result == PortMatchingResult::kMatchingWildcard;
}

bool inline CanUpgrade(const SchemeMatchingResult result) {
  return result == SchemeMatchingResult::kMatchingUpgrade;
}

}  // namespace

bool CSPSourceMatches(const network::mojom::blink::CSPSource& source,
                      const String& self_protocol,
                      const KURL& url,
                      ResourceRequest::RedirectStatus redirect_status) {
  SchemeMatchingResult schemes_match =
      SchemeMatches(source, url.Protocol(), self_protocol);
  if (schemes_match == SchemeMatchingResult::kNotMatching)
    return false;
  if (CSPSourceIsSchemeOnly(source))
    return true;
  bool paths_match =
      (redirect_status == ResourceRequest::RedirectStatus::kFollowedRedirect) ||
      PathMatches(source, url.GetPath());
  PortMatchingResult ports_match = PortMatches(
      source, self_protocol, url.HasPort() ? url.Port() : url::PORT_UNSPECIFIED,
      url.Protocol());

  // if either the scheme or the port would require an upgrade (e.g. from http
  // to https) then check that both of them can upgrade to ensure that we don't
  // run into situations where we only upgrade the port but not the scheme or
  // viceversa
  if ((RequiresUpgrade(schemes_match) || (RequiresUpgrade(ports_match))) &&
      (!CanUpgrade(schemes_match) || !CanUpgrade(ports_match))) {
    return false;
  }

  return HostMatches(source, url) &&
         ports_match != PortMatchingResult::kNotMatching && paths_match;
}

bool CSPSourceMatchesAsSelf(const network::mojom::blink::CSPSource& source,
                            const KURL& url) {
  // https://w3c.github.io/webappsec-csp/#match-url-to-source-expression
  // Step 4.
  SchemeMatchingResult schemes_match =
      SchemeMatches(source, url.Protocol(), source.scheme);

  if (url.Protocol() == "file" &&
      schemes_match == SchemeMatchingResult::kMatchingExact) {
    // Determining the origin of a file URL is left as an exercise to the reader
    // https://url.spec.whatwg.org/#concept-url-origin. Let's always match file
    // URLs against 'self' delivered from a file. This avoids inconsistencies
    // between file:/// and file://localhost/.
    return true;
  }

  bool hosts_match = HostMatches(source, url);
  PortMatchingResult ports_match = PortMatches(
      source, source.scheme, url.HasPort() ? url.Port() : url::PORT_UNSPECIFIED,
      url.Protocol());

  // check if the origin is exactly matching
  if (schemes_match == SchemeMatchingResult::kMatchingExact && hosts_match &&
      (ports_match == PortMatchingResult::kMatchingExact ||
       ports_match == PortMatchingResult::kMatchingWildcard)) {
    return true;
  }

  bool ports_match_or_defaults =
      (ports_match == PortMatchingResult::kMatchingExact ||
       ((IsDefaultPortForProtocol(source.port, source.scheme) ||
         source.port == url::PORT_UNSPECIFIED) &&
        (!url.HasPort() ||
         IsDefaultPortForProtocol(url.Port(), url.Protocol()))));

  return hosts_match && ports_match_or_defaults &&
         (url.Protocol() == "https" || url.Protocol() == "wss" ||
          source.scheme == "http");
}

bool CSPSourceIsSchemeOnly(const network::mojom::blink::CSPSource& source) {
  return source.host.empty() && (!source.is_host_wildcard);
}

}  // namespace blink

"""

```