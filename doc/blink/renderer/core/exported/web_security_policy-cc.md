Response:
Let's break down the thought process for analyzing the `web_security_policy.cc` file.

**1. Initial Understanding - The File's Purpose:**

The first thing to notice is the file path: `blink/renderer/core/exported/web_security_policy.cc`. The keywords "security policy" immediately suggest this file is related to managing and enforcing web security within the Blink rendering engine. The `exported` directory hints that this is an interface intended for use by other parts of Chromium, likely the higher-level browser process.

**2. Analyzing the Includes:**

Looking at the `#include` directives provides crucial context:

* **`third_party/blink/public/web/web_security_policy.h`**: This is the corresponding header file, defining the public interface of the class. It confirms this is a publicly accessible class.
* **`services/network/public/mojom/referrer_policy.mojom-blink.h`**:  This indicates interaction with the network service and specifically with referrer policies.
* **`third_party/blink/public/common/scheme_registry.h`**:  This is a key clue. "Scheme Registry" implies managing different URL schemes (like `http`, `https`, `file`, etc.) and their security properties.
* **`third_party/blink/public/platform/web_security_origin.h`, `third_party/blink/public/platform/web_string.h`, `third_party/blink/public/platform/web_url.h`**: These are fundamental types for representing origins, strings, and URLs within Blink. The `public/platform` suggests a lower-level platform abstraction.
* **`third_party/blink/renderer/core/loader/frame_loader.h`**: This connects the security policy to the loading of web pages (frames).
* **`third_party/blink/renderer/platform/weborigin/scheme_registry.h`, `third_party/blink/renderer/platform/weborigin/security_origin.h`, `third_party/blink/renderer/platform/weborigin/security_policy.h`**: These are internal Blink implementations for scheme registration, security origins, and security policies. This confirms the file acts as a bridge between the public API and the internal implementation.

**3. Examining the Function Definitions:**

Now, go through each function definition and understand its purpose:

* **`RegisterURLSchemeAs...` functions:**  These are clearly about registering URL schemes and associating specific security behaviors with them. The names themselves are quite descriptive (e.g., `RegisterURLSchemeAsDisplayIsolated`, `RegisterURLSchemeAsAllowingServiceWorkers`).
* **`AddOriginAccessAllowListEntry`, `AddOriginAccessBlockListEntry`, `ClearOriginAccessListForOrigin`, `ClearOriginAccessList`:** These functions deal with managing Cross-Origin Resource Sharing (CORS) by defining allow and block lists based on origins, protocols, hosts, and ports.
* **`AddSchemeToSecureContextSafelist`:** This relates to the concept of secure contexts (like HTTPS) and allows certain schemes to bypass those requirements.
* **`GenerateReferrerHeader`:**  This function is responsible for generating the `Referer` header based on the specified referrer policy.
* **`RegisterURLSchemeAsNotAllowingJavascriptURLs`:**  This prevents JavaScript execution within URLs of a specific scheme.
* **`RegisterURLSchemeAsAllowedForReferrer`:**  This controls whether a scheme's URLs can be sent in the `Referer` header.
* **`RegisterURLSchemeAsError`:**  Treats a scheme as an error, likely causing navigation failures.
* **`RegisterURLSchemeAsExtension`:**  Marks a scheme as a browser extension scheme.
* **`RegisterURLSchemeAsWebUI`:**  Identifies a scheme used for internal browser UI.
* **`RegisterURLSchemeAsCodeCacheWithHashing`:** This is likely related to caching and security for code downloaded under specific schemes.

**4. Identifying Relationships with Web Technologies (JavaScript, HTML, CSS):**

With the function purposes understood, we can connect them to web technologies:

* **JavaScript:** Functions like `RegisterURLSchemeAsAllowingWasmEvalCSP`, `RegisterURLSchemeAsAllowingServiceWorkers`, `RegisterURLSchemeAsNotAllowingJavascriptURLs`, and features like CORS directly impact JavaScript's capabilities and security.
* **HTML:** CORS settings and the `Referer` header influence how resources are loaded and displayed, affecting HTML rendering. The concept of secure contexts also influences what features are available in a given HTML document.
* **CSS:** While not as direct as with JavaScript, CORS can affect loading of CSS resources from different origins.

**5. Developing Examples and Scenarios:**

Based on the functions, we can create concrete examples:

* **CORS:**  Demonstrate how `AddOriginAccessAllowListEntry` would allow a specific origin to access resources.
* **`RegisterURLSchemeAsNotAllowingJavascriptURLs`:** Show how this would prevent `javascript:` URLs from executing.
* **`GenerateReferrerHeader`:** Illustrate how different referrer policies result in different `Referer` header values.
* **Secure Contexts:** Explain how `AddSchemeToSecureContextSafelist` could allow a non-HTTPS page to use features typically restricted to secure contexts.

**6. Considering User/Developer Errors:**

Think about common mistakes developers might make:

* **Misconfiguring CORS:**  Incorrectly setting up allow/block lists can lead to either security vulnerabilities or broken functionality.
* **Assuming `javascript:` URLs will always work:**  Not realizing that certain schemes might block them.
* **Not understanding referrer policies:**  Leading to unexpected information being sent in the `Referer` header.

**7. Tracing User Actions (Debugging Clues):**

Imagine a user experiencing a security-related issue. How might they end up interacting with this code?

* **Visiting a website with CORS issues:** The browser would check the origin access lists defined by this code.
* **Trying to execute a `javascript:` URL on a page with a restricted scheme:** This code would enforce the restriction.
* **Navigating between pages with different referrer policies:** This code would be involved in generating the `Referer` header.

**8. Structuring the Answer:**

Finally, organize the information logically:

* **Start with a summary of the file's overall purpose.**
* **List the key functionalities, explaining each one concisely.**
* **Provide concrete examples for JavaScript, HTML, and CSS.**
* **Include example input/output scenarios for logical functions.**
* **Describe common user/developer errors.**
* **Outline user actions that might lead to this code being executed (debugging clues).**

This systematic approach allows for a comprehensive understanding and explanation of the `web_security_policy.cc` file's role within the Blink rendering engine. It combines code analysis, knowledge of web technologies, and logical reasoning to provide a thorough and insightful answer.
这个文件 `blink/renderer/core/exported/web_security_policy.cc` 是 Chromium Blink 引擎中 **Web 安全策略** 的一个实现细节的导出层。 它的主要功能是 **提供了一组供外部（通常是 Chromium 的更高层）调用的接口，用于配置和管理 Blink 渲染引擎的各种安全策略相关的行为**。

更具体地说，它封装了 Blink 内部 `third_party/blink/renderer/platform/weborigin/security_policy.h` 和 `third_party/blink/renderer/platform/weborigin/scheme_registry.h` 中定义的安全策略功能，并以 `WebSecurityPolicy` 类的静态方法的形式暴露出来。  这个类定义在 `third_party/blink/public/web/web_security_policy.h` 中，作为 Blink 的公共 API 的一部分。

**以下是 `web_security_policy.cc` 的主要功能列表:**

1. **注册具有特殊安全属性的 URL Scheme:**
   - `RegisterURLSchemeAsDisplayIsolated(const WebString& scheme)`:  将某个 URL scheme 注册为“显示隔离”。这意味着来自该 scheme 的内容将与来自其他 scheme 的内容严格隔离，防止潜在的跨源信息泄露。
   - `RegisterURLSchemeAsAllowingServiceWorkers(const WebString& scheme)`: 允许特定的 URL scheme 启动和运行 Service Workers。
   - `RegisterURLSchemeAsAllowingWasmEvalCSP(const WebString& scheme)`: 允许来自该 scheme 的内容使用 `eval()` 或类似机制执行 WebAssembly 代码，即使内容安全策略 (CSP) 通常会阻止这种行为。
   - `RegisterURLSchemeAsSupportingFetchAPI(const WebString& scheme)`: 允许该 scheme 的 URL 使用 Fetch API 进行网络请求。
   - `RegisterURLSchemeAsFirstPartyWhenTopLevel(const WebString& scheme)`:  当该 scheme 的 URL 作为顶级文档加载时，将其视为第一方。
   - `RegisterURLSchemeAsFirstPartyWhenTopLevelEmbeddingSecure(const WebString& scheme)`: 当该 scheme 的 URL 作为顶级文档加载，并且嵌入它的页面是安全的 (HTTPS) 时，将其视为第一方。
   - `RegisterURLSchemeAsAllowingSharedArrayBuffers(const WebString& scheme)`: 允许来自该 scheme 的内容使用 SharedArrayBuffers。
   - `RegisterURLSchemeAsNotAllowingJavascriptURLs(const WebString& scheme)`:  禁止在该 scheme 的 URL 中执行 `javascript:` URL。
   - `RegisterURLSchemeAsAllowedForReferrer(const WebString& scheme)`: 允许将该 scheme 的 URL 作为 Referrer 发送。
   - `RegisterURLSchemeAsError(const WebString& scheme)`: 将该 scheme 视为错误，尝试导航到该 scheme 的 URL 将会失败。
   - `RegisterURLSchemeAsExtension(const WebString& scheme)`: 将该 scheme 标记为浏览器扩展使用的 scheme。
   - `RegisterURLSchemeAsWebUI(const WebString& scheme)`: 将该 scheme 标记为 Chrome 内部 WebUI 使用的 scheme。
   - `RegisterURLSchemeAsCodeCacheWithHashing(const WebString& scheme)`: 表明该 scheme 的资源可以被安全地缓存并带有哈希值。

2. **管理跨域资源共享 (CORS) 访问控制列表:**
   - `AddOriginAccessAllowListEntry(...)`:  添加一个允许特定源访问的条目到允许列表中。
   - `AddOriginAccessBlockListEntry(...)`: 添加一个阻止特定源访问的条目到阻止列表中。
   - `ClearOriginAccessListForOrigin(const WebURL& source_origin)`: 清除特定源的访问控制列表。
   - `ClearOriginAccessList()`: 清除全局的访问控制列表。

3. **管理安全上下文豁免列表:**
   - `AddSchemeToSecureContextSafelist(const WebString& scheme)`: 将一个 scheme 添加到安全上下文豁免列表。这意味着即使在非安全上下文（例如 HTTP 页面）下，来自该 scheme 的资源也可以访问某些通常只在安全上下文下可用的功能。

4. **生成 Referrer Header:**
   - `GenerateReferrerHeader(...)`: 根据指定的 Referrer 策略、目标 URL 和当前的 Referrer 生成 Referrer HTTP 头的值。

**与 JavaScript, HTML, CSS 的关系举例:**

* **JavaScript 和 `RegisterURLSchemeAsNotAllowingJavascriptURLs`:**
    * **场景:**  假设 Chromium 将 `chrome-extension://` scheme 注册为不允许执行 `javascript:` URL。
    * **用户操作:** 用户在浏览器地址栏输入 `chrome-extension://some-extension/page.html`，这个页面可能包含一个链接 `<a href="javascript:alert('Hello')">Click Me</a>`。
    * **结果:**  由于 `chrome-extension://` 不允许 `javascript:` URL，点击这个链接将不会执行 `alert('Hello')`。这增强了扩展的安全性，防止恶意扩展通过 `javascript:` URL 注入代码。

* **JavaScript 和 `AddOriginAccessAllowListEntry` (CORS):**
    * **场景:**  一个运行在 `https://example.com` 的网页需要从 `https://api.another-domain.com` 获取数据。但默认情况下，浏览器会阻止这种跨域请求。
    * **配置:** Chromium 可以通过某种机制（例如命令行参数或配置文件）调用 `WebSecurityPolicy::AddOriginAccessAllowListEntry` 来允许 `https://example.com` 访问 `https://api.another-domain.com`。
    * **用户操作:** 用户访问 `https://example.com`，网页上的 JavaScript 代码使用 `fetch` 或 `XMLHttpRequest` 向 `https://api.another-domain.com` 发起请求。
    * **结果:**  由于配置了允许列表，浏览器允许这次跨域请求，JavaScript 代码可以成功获取数据。

* **HTML 和 `RegisterURLSchemeAsDisplayIsolated`:**
    * **场景:** Chromium 将 `file://` scheme 注册为显示隔离。
    * **用户操作:** 用户打开本地 HTML 文件 `file:///path/to/my.html`，该文件通过 `<iframe>` 嵌入了另一个 `file:///path/to/another.html` 文件。
    * **结果:**  由于 `file://` 是显示隔离的，这两个 `file://` 来源的文档将被严格隔离，它们之间无法通过 JavaScript 进行跨源通信，即使它们都来自于本地文件系统。

* **CSS 和 `AddOriginAccessAllowListEntry` (CORS):**
    * **场景:**  一个运行在 `https://website.com` 的网页需要在 CSS 中使用来自 `https://cdn.assets.com` 的字体。
    * **配置:** 如果 `https://cdn.assets.com` 没有设置正确的 CORS 头部，浏览器会阻止字体加载。可以通过 `WebSecurityPolicy::AddOriginAccessAllowListEntry` 允许 `https://website.com` 访问 `https://cdn.assets.com`。
    * **用户操作:** 用户访问 `https://website.com`，浏览器尝试加载 CSS 文件，其中包含类似 `@font-face { src: url('https://cdn.assets.com/myfont.woff2'); }` 的规则。
    * **结果:**  如果允许列表配置正确，字体资源可以成功加载并应用到网页样式。

**逻辑推理的假设输入与输出:**

大多数方法是副作用操作，修改全局状态（例如，注册 scheme 或修改访问列表）。对于 `GenerateReferrerHeader` 方法，我们可以进行逻辑推理：

* **假设输入:**
    * `referrer_policy`: `network::mojom::ReferrerPolicy::kNoReferrerWhenDowngrade`
    * `url`: `https://example.com/page.html`
    * `referrer`: `http://attacker.com/evil.html`
* **逻辑:**  由于策略是 `kNoReferrerWhenDowngrade`，并且目标 URL 是 HTTPS，当前 Referrer 是 HTTP（降级），所以不应该发送 Referrer。
* **输出:**  生成的 Referrer 头为空字符串 `""`。

* **假设输入:**
    * `referrer_policy`: `network::mojom::ReferrerPolicy::kOrigin`
    * `url`: `https://example.com/sub/page.html`
    * `referrer`: `https://example.com/other.html`
* **逻辑:**  策略是 `kOrigin`，所以只发送来源。
* **输出:** 生成的 Referrer 头为 `https://example.com/`。

**用户或编程常见的使用错误:**

* **错误地配置 CORS 允许列表:**  允许了不应该允许的源，可能导致安全漏洞。例如，允许 `*` 作为源，意味着任何网站都可以访问受保护的资源。
* **忘记注册自定义 scheme 的安全属性:**  如果开发者引入了一个新的 URL scheme，但没有通过 `WebSecurityPolicy` 注册其安全属性，可能会导致意外的安全行为或功能缺失（例如，Service Worker 无法在该 scheme 上运行）。
* **不理解 Referrer 策略的影响:**  错误地选择 Referrer 策略可能导致敏感信息泄露或者破坏某些依赖 Referrer 的功能。
* **在不应该使用的地方绕过安全上下文检查:**  过度使用 `AddSchemeToSecureContextSafelist` 可能会降低安全性，因为它允许在非安全的环境中使用本应受限的功能。

**用户操作如何一步步的到达这里 (作为调试线索):**

1. **用户在浏览器中输入或点击一个 URL:**  这会触发导航过程，涉及到加载页面资源。
2. **浏览器解析 URL，确定其 scheme:**  例如，`https://...`, `http://...`, `file://...`.
3. **Blink 渲染引擎在加载资源时，会检查与该 URL scheme 相关的安全策略:**  这会调用 `web_security_policy.cc` 中注册的 scheme 属性。
4. **如果涉及到跨域请求 (例如，通过 `<img>`, `<script>`, `fetch` 等):**  Blink 会检查 CORS 策略，这会涉及到 `AddOriginAccessAllowListEntry` 和 `AddOriginAccessBlockListEntry` 配置的规则。
5. **如果页面尝试执行 `javascript:` URL:**  Blink 会检查该 URL 的 scheme 是否允许执行 `javascript:` URL，这与 `RegisterURLSchemeAsNotAllowingJavascriptURLs` 的配置有关。
6. **当浏览器需要发送 HTTP 请求时，会根据 Referrer 策略生成 Referrer 头:**  这会调用 `GenerateReferrerHeader`。

**例如，调试一个 CORS 问题:**

1. 用户访问 `https://user.com`，该页面尝试加载 `https://api.provider.com/data.json`。
2. 开发者工具显示 CORS 错误，表明 `https://api.provider.com` 没有允许 `https://user.com` 的访问。
3. 作为调试，开发者可能会尝试通过命令行参数或修改 Chromium 源代码，调用 `WebSecurityPolicy::AddOriginAccessAllowListEntry` 来临时允许 `https://user.com` 访问 `https://api.provider.com`。
4. 重新运行浏览器，再次访问 `https://user.com`，如果配置正确，CORS 错误消失，数据加载成功。这表明问题确实是 CORS 配置导致的。

总而言之，`blink/renderer/core/exported/web_security_policy.cc` 是 Blink 引擎安全策略配置的核心入口点，它通过公开一系列接口，允许 Chromium 的其他部分来灵活地管理和定制各种安全相关的行为，从而确保 Web 内容在浏览器中的安全执行。

### 提示词
```
这是目录为blink/renderer/core/exported/web_security_policy.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2009 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/public/web/web_security_policy.h"

#include "services/network/public/mojom/referrer_policy.mojom-blink.h"
#include "third_party/blink/public/common/scheme_registry.h"
#include "third_party/blink/public/platform/web_security_origin.h"
#include "third_party/blink/public/platform/web_string.h"
#include "third_party/blink/public/platform/web_url.h"
#include "third_party/blink/renderer/core/loader/frame_loader.h"
#include "third_party/blink/renderer/platform/weborigin/scheme_registry.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/weborigin/security_policy.h"

namespace blink {

void WebSecurityPolicy::RegisterURLSchemeAsDisplayIsolated(
    const WebString& scheme) {
  SchemeRegistry::RegisterURLSchemeAsDisplayIsolated(scheme);
}

void WebSecurityPolicy::RegisterURLSchemeAsAllowingServiceWorkers(
    const WebString& scheme) {
  SchemeRegistry::RegisterURLSchemeAsAllowingServiceWorkers(scheme);
}

void WebSecurityPolicy::RegisterURLSchemeAsAllowingWasmEvalCSP(
    const WebString& scheme) {
  SchemeRegistry::RegisterURLSchemeAsAllowingWasmEvalCSP(scheme);
}

void WebSecurityPolicy::RegisterURLSchemeAsSupportingFetchAPI(
    const WebString& scheme) {
  SchemeRegistry::RegisterURLSchemeAsSupportingFetchAPI(scheme);
}

void WebSecurityPolicy::RegisterURLSchemeAsFirstPartyWhenTopLevel(
    const WebString& scheme) {
  SchemeRegistry::RegisterURLSchemeAsFirstPartyWhenTopLevel(scheme);
}

void WebSecurityPolicy::
    RegisterURLSchemeAsFirstPartyWhenTopLevelEmbeddingSecure(
        const WebString& scheme) {
  SchemeRegistry::RegisterURLSchemeAsFirstPartyWhenTopLevelEmbeddingSecure(
      scheme);
}

void WebSecurityPolicy::RegisterURLSchemeAsAllowingSharedArrayBuffers(
    const WebString& scheme) {
  SchemeRegistry::RegisterURLSchemeAsAllowingSharedArrayBuffers(scheme);
}

void WebSecurityPolicy::AddOriginAccessAllowListEntry(
    const WebURL& source_origin,
    const WebString& destination_protocol,
    const WebString& destination_host,
    const uint16_t destination_port,
    const network::mojom::CorsDomainMatchMode domain_match_mode,
    const network::mojom::CorsPortMatchMode port_match_mode,
    const network::mojom::CorsOriginAccessMatchPriority priority) {
  SecurityPolicy::AddOriginAccessAllowListEntry(
      *SecurityOrigin::Create(source_origin), destination_protocol,
      destination_host, destination_port, domain_match_mode, port_match_mode,
      priority);
}

void WebSecurityPolicy::AddOriginAccessBlockListEntry(
    const WebURL& source_origin,
    const WebString& destination_protocol,
    const WebString& destination_host,
    const uint16_t destination_port,
    const network::mojom::CorsDomainMatchMode domain_match_mode,
    const network::mojom::CorsPortMatchMode port_match_mode,
    const network::mojom::CorsOriginAccessMatchPriority priority) {
  SecurityPolicy::AddOriginAccessBlockListEntry(
      *SecurityOrigin::Create(source_origin), destination_protocol,
      destination_host, destination_port, domain_match_mode, port_match_mode,
      priority);
}

void WebSecurityPolicy::ClearOriginAccessListForOrigin(
    const WebURL& source_origin) {
  scoped_refptr<SecurityOrigin> security_origin =
      SecurityOrigin::Create(source_origin);
  SecurityPolicy::ClearOriginAccessListForOrigin(*security_origin);
}

void WebSecurityPolicy::ClearOriginAccessList() {
  SecurityPolicy::ClearOriginAccessList();
}

void WebSecurityPolicy::AddSchemeToSecureContextSafelist(
    const WebString& scheme) {
  SchemeRegistry::RegisterURLSchemeBypassingSecureContextCheck(scheme);
}

WebString WebSecurityPolicy::GenerateReferrerHeader(
    network::mojom::ReferrerPolicy referrer_policy,
    const WebURL& url,
    const WebString& referrer) {
  return SecurityPolicy::GenerateReferrer(referrer_policy, url, referrer)
      .referrer;
}

void WebSecurityPolicy::RegisterURLSchemeAsNotAllowingJavascriptURLs(
    const WebString& scheme) {
  SchemeRegistry::RegisterURLSchemeAsNotAllowingJavascriptURLs(scheme);
}

void WebSecurityPolicy::RegisterURLSchemeAsAllowedForReferrer(
    const WebString& scheme) {
  SchemeRegistry::RegisterURLSchemeAsAllowedForReferrer(scheme);
}

void WebSecurityPolicy::RegisterURLSchemeAsError(const WebString& scheme) {
  SchemeRegistry::RegisterURLSchemeAsError(scheme);
}

void WebSecurityPolicy::RegisterURLSchemeAsExtension(const WebString& scheme) {
  CommonSchemeRegistry::RegisterURLSchemeAsExtension(scheme.Ascii());
}

void WebSecurityPolicy::RegisterURLSchemeAsWebUI(const WebString& scheme) {
  SchemeRegistry::RegisterURLSchemeAsWebUI(scheme);
}

void WebSecurityPolicy::RegisterURLSchemeAsCodeCacheWithHashing(
    const WebString& scheme) {
  SchemeRegistry::RegisterURLSchemeAsCodeCacheWithHashing(scheme);
}

}  // namespace blink
```