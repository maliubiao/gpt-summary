Response:
Let's break down the thought process for analyzing this C++ code and generating the response.

1. **Understanding the Goal:** The primary goal is to explain the functionality of `scheme_registry.cc` and its relation to web technologies (JavaScript, HTML, CSS). The request also asks for examples, logical deductions, and potential errors.

2. **Initial Code Scan (High-Level):**  First, quickly scan the code for keywords and patterns. Notice:
    * Includes: `blink.h`, `url_util.h` - suggesting interaction with URLs and the broader Blink/Chromium environment.
    * Namespaces: `blink` - confirms this is Blink code.
    * Class `SchemeRegistry`: The core entity.
    * `URLSchemesRegistry`: A nested class holding sets and maps of URL schemes.
    * Lots of `RegisterURLSchemeAs...` and `ShouldTreatURLSchemeAs...` functions. This strongly indicates the purpose is to define and check properties of URL schemes.
    * Sets and Maps:  `URLSchemesSet`, `URLSchemesMap`. These likely store different categories of URL schemes.
    * Thread safety mechanisms: `DEFINE_THREAD_SAFE_STATIC_LOCAL`, comments about thread safety. This is important for a multi-threaded rendering engine.

3. **Identifying Key Functionality Areas:** Based on the function names, group the functionalities into logical areas:
    * **Scheme Registration:**  Functions starting with `RegisterURLSchemeAs...` are clearly for adding schemes to different categories.
    * **Scheme Checking:** Functions starting with `ShouldTreatURLSchemeAs...` and `Is...Scheme` are for querying the properties of a given scheme.
    * **Domain Relaxation:**  Functions related to `DomainRelaxation`.
    * **Content Security Policy (CSP):** Functions involving `BypassingContentSecurityPolicy`.
    * **Secure Context:** Functions involving `BypassingSecureContextCheck`.
    * **Service Workers and Fetch API:** Functions related to these web platform features.
    * **Referrer Policy:** Functions related to `AllowedForReferrer`.
    * **Web UI:** Functions related to `WebUI`.
    * **WASM:** Functions related to `WasmEvalCSP`.
    * **Code Cache:** Functions related to `CodeCacheWithHashing`.
    * **Display Isolation:** Functions related to `DisplayIsolated`.
    * **Empty Documents:** Functions related to `EmptyDocument`.
    * **JavaScript URLs:** Functions related to `NotAllowingJavascriptURLs`.
    * **CORS:** Functions related to `CorsEnabled`.
    * **Usage Metrics:**  `ShouldTrackUsageMetricsForScheme`.
    * **First-Party:** Functions related to `FirstPartyWhenTopLevel`.
    * **Error Schemes:** Functions related to `Error`.
    * **Shared Array Buffers:** Functions related to `AllowingSharedArrayBuffers`.

4. **Analyzing Individual Functions:** For each function, determine:
    * **Purpose:** What does this function do?
    * **Input:** What arguments does it take? (Usually a `String` representing the scheme).
    * **Output:** What does it return? (Usually a `bool`).
    * **Side effects:** Does it modify any internal state? (Likely for `RegisterURLSchemeAs...`).
    * **Relevance to Web Technologies:** How does this functionality relate to JavaScript, HTML, or CSS?  This is the crucial linking step.

5. **Connecting to Web Technologies (Examples):** For each functional area, think of concrete examples in JavaScript, HTML, or CSS where the scheme plays a role.
    * **JavaScript:** `fetch()`, `XMLHttpRequest`, `import()`, `new Worker('...')`, `<iframe>` with different `src` schemes, `<a>` tags, `<script src="...">`.
    * **HTML:** `<img>`, `<iframe>`, `<link>`, `<form action="...">`, `<a>`.
    * **CSS:** `url()` in stylesheets, `@import`.
    * **CSP:**  `Content-Security-Policy` header directives.
    * **Service Workers:** Registering a service worker with a specific scope.

6. **Logical Deductions (Assumptions and Outputs):**  Choose a few interesting functions and demonstrate how they would work with example inputs. Focus on the conditional logic within the functions. For example, the `ShouldTreatURLSchemeAsCorsEnabled` function directly checks against a set.

7. **Common Usage Errors:** Think about how developers might misuse or misunderstand the behavior controlled by this code. This often involves security implications or unexpected behavior due to scheme restrictions.

8. **Structuring the Response:** Organize the information logically:
    * Start with a concise summary of the file's purpose.
    * Detail the functionalities in categories.
    * Provide clear examples for each category, linking to JavaScript, HTML, and CSS.
    * Present logical deductions with clear input/output examples.
    * Explain common usage errors with illustrative scenarios.
    * Use clear and concise language.

9. **Refinement and Review:**  Read through the generated response to ensure accuracy, clarity, and completeness. Check for any inconsistencies or areas that could be explained better. For instance, initially, I might not have explicitly linked the "Empty Document Schemes" to the behavior of certain URLs resolving to blank pages, so reviewing helps to make these connections clearer. Also, ensuring the assumptions and outputs in the logical deduction section are sensible and easy to follow.

**Self-Correction Example during the process:**

Initially, I might have just said "Registers schemes for Service Workers."  However, by thinking more deeply and looking at the code comments, I'd realize the nuance:  "Registers schemes *allowing* Service Workers, and notes that HTTP is initially required for `localhost` scenarios due to security considerations." This adds more valuable detail. Similarly, for CSP, instead of just saying "Handles CSP bypassing," it's better to explain *how* it handles it (through a map with policy areas).
这个文件 `blink/renderer/platform/weborigin/scheme_registry.cc` 在 Chromium 的 Blink 渲染引擎中扮演着至关重要的角色，它**负责管理和维护各种 URL scheme (协议) 的属性和行为规则**。简单来说，它定义了 Blink 引擎如何理解和处理不同的 URL 前缀，例如 `http://`, `https://`, `file://`, `data:`, `blob:`, 等等。

以下是它的主要功能以及与 JavaScript、HTML 和 CSS 的关系：

**主要功能:**

1. **注册和管理 URL Scheme 的属性:**  `SchemeRegistry` 维护着一系列的集合和映射，用于存储不同 URL scheme 的特定属性。这些属性决定了这些 scheme 在浏览器中的行为。例如：
    * **是否需要安全上下文 (Secure Context):**  例如 `https://` 需要安全上下文，而 `http://` 在某些情况下不需要。
    * **是否允许 Service Workers:**  只有特定的 scheme (例如 `https://`) 才允许注册和运行 Service Workers。
    * **是否支持 Fetch API:**  哪些 scheme 可以使用 `fetch()` API 发起网络请求。
    * **是否禁用域名放松 (Domain Relaxation):**  控制同源策略的放松程度。
    * **是否被视为 CORS 启用 (CORS Enabled):**  决定是否需要执行跨域资源共享 (CORS) 检查。
    * **是否绕过内容安全策略 (CSP):**  一些内部或特殊的 scheme 可以绕过 CSP 的限制。
    * **是否被视为 Web UI Scheme:**  用于浏览器内部页面的特殊 scheme。
    * **是否允许 `javascript:` URL:**  控制是否允许执行 `javascript:` URL 中的代码。

2. **提供查询接口:**  `SchemeRegistry` 提供了大量的静态方法，用于查询特定 scheme 的属性。例如：
    * `SchemeRegistry::ShouldTreatURLSchemeAsSecureContext()`
    * `SchemeRegistry::ShouldTreatURLSchemeAsAllowingServiceWorkers()`
    * `SchemeRegistry::ShouldTreatURLSchemeAsCorsEnabled()`

3. **影响核心 Web 平台功能:**  `SchemeRegistry` 的配置直接影响到浏览器如何处理各种 Web 平台的特性，包括安全、网络请求、同源策略等等。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`SchemeRegistry` 的功能直接影响 JavaScript, HTML 和 CSS 的行为，因为它决定了浏览器如何解释和执行与 URL 相关的操作。

**1. JavaScript:**

* **`fetch()` API 和 `XMLHttpRequest`:**  `SchemeRegistry::ShouldTreatURLSchemeAsSupportingFetchAPI()` 决定了 JavaScript 中的 `fetch()` API 和 `XMLHttpRequest` 是否可以向特定 scheme 的 URL 发起请求。
    * **假设输入:** JavaScript 代码 `fetch('file:///path/to/local/file.txt')`
    * **逻辑推理:** `SchemeRegistry` 可能配置为 `file://` 不支持 `fetch()` API。
    * **输出:** `fetch()` 请求失败，可能会抛出网络错误或者安全错误，具体取决于浏览器的实现。
* **Service Workers:**  `SchemeRegistry::ShouldTreatURLSchemeAsAllowingServiceWorkers()` 决定了哪些 scheme 可以注册 Service Workers。通常只有 `https://` 才能注册生产环境的 Service Workers。
    * **假设输入:** JavaScript 代码尝试在 `http://example.com` 上注册 Service Worker。
    * **逻辑推理:**  `SchemeRegistry` 配置为 `http://` 不允许注册 Service Workers。
    * **输出:** Service Worker 注册失败。
* **`javascript:` URL:** `SchemeRegistry::ShouldTreatURLSchemeAsNotAllowingJavascriptURLs()` 控制是否允许执行 `javascript:` URL 中的代码。
    * **假设输入:**  HTML `<a href="javascript:alert('hello')">Click Me</a>`
    * **逻辑推理:**  如果某个 scheme 被注册为不允许 `javascript:` URL，则点击链接不会执行 JavaScript 代码。
    * **输出:** 点击链接没有反应，或者浏览器可能会阻止执行并显示安全警告。
* **WebSockets:** WebSockets 连接的建立 ( `ws://` 和 `wss://` ) 也受到 `SchemeRegistry` 的影响，例如是否需要安全上下文。
* **`import()` 动态导入:**  动态导入模块的 URL Scheme 也可能受到 `SchemeRegistry` 的限制。

**2. HTML:**

* **`<script src="...">`:**  `SchemeRegistry` 影响 `<script>` 标签加载外部脚本的行为。例如，如果某个 scheme 不允许被当作资源加载，那么加载该 scheme 的脚本将会失败。
* **`<link rel="stylesheet" href="...">`:**  加载外部 CSS 样式表的行为与 `<script>` 类似，也受到 `SchemeRegistry` 的控制。
* **`<img>`, `<video>`, `<audio>` 等媒体标签的 `src` 属性:**  `SchemeRegistry` 决定了这些标签是否可以加载特定 scheme 的资源。
* **`<iframe>` 的 `src` 属性:**  嵌入的 iframe 的 URL scheme 受到 `SchemeRegistry` 的限制，这关系到安全性和同源策略。
    * **假设输入:** HTML `<iframe src="data:text/html,<h1>Hello</h1>"></iframe>`
    * **逻辑推理:** `SchemeRegistry` 配置为允许 `data:` scheme 作为 iframe 的 `src`。
    * **输出:**  iframe 中会渲染出 "Hello"。
* **表单的 `action` 属性:**  表单提交的目标 URL 的 scheme 也受到 `SchemeRegistry` 的约束。
* **`<a>` 标签的 `href` 属性:**  点击链接的行为受到 `SchemeRegistry` 的影响，例如 `javascript:` URL 的处理。

**3. CSS:**

* **`url()` 函数:**  在 CSS 中使用 `url()` 函数引用外部资源 (例如背景图片、字体) 时，资源的 URL scheme 受到 `SchemeRegistry` 的限制。
    * **假设输入:** CSS 规则 `body { background-image: url('file:///path/to/image.png'); }`
    * **逻辑推理:**  如果 `file://` scheme 被 `SchemeRegistry` 配置为不允许用作背景图片，或者有安全限制。
    * **输出:** 背景图片加载失败。
* **`@import` 规则:**  导入外部 CSS 文件的 URL scheme 也受到 `SchemeRegistry` 的控制。

**逻辑推理的假设输入与输出:**

* **假设输入:** 调用 `SchemeRegistry::ShouldTreatURLSchemeAsSecureContext("http")`
* **逻辑推理:**  `SchemeRegistry` 通常会将 "http" scheme 视为非安全上下文。
* **输出:** `false`

* **假设输入:** 调用 `SchemeRegistry::ShouldTreatURLSchemeAsAllowingServiceWorkers("https")`
* **逻辑推理:** `SchemeRegistry` 通常会将 "https" scheme 视为允许 Service Workers。
* **输出:** `true`

**用户或编程常见的使用错误:**

1. **假设所有 scheme 行为一致:**  开发者可能会错误地认为所有 URL scheme 的行为都是相同的，而忽略了 `SchemeRegistry` 定义的差异。例如，在 `http://` 页面上尝试注册 Service Worker，却不知道只有 `https://` 才允许。
2. **混淆内部和外部 scheme:**  一些 scheme (例如 `chrome://`, `devtools://`) 是浏览器内部使用的，不应该在普通的 Web 页面中使用或假设其行为。
3. **安全漏洞:**  不恰当的 `SchemeRegistry` 配置可能导致安全漏洞。例如，如果一个不应该绕过 CSP 的 scheme 被错误地配置为可以绕过，那么可能会引入跨站脚本攻击 (XSS) 的风险。
4. **CORS 问题:**  没有意识到某些 scheme 默认是启用 CORS 的，可能会导致跨域请求被阻止。
5. **referrer policy 错误:**  没有理解哪些 scheme 允许作为 referrer，可能会导致 referrer 信息丢失或泄露。

**总结:**

`blink/renderer/platform/weborigin/scheme_registry.cc` 是 Blink 引擎中一个核心的配置中心，它定义了 URL scheme 的各种属性和行为规则，直接影响着 JavaScript, HTML 和 CSS 的运行和安全。理解 `SchemeRegistry` 的作用对于理解浏览器的行为和避免潜在的错误至关重要。开发者在处理不同 URL scheme 时，需要意识到这些潜在的差异，并遵循浏览器的安全和功能限制。

Prompt: 
```
这是目录为blink/renderer/platform/weborigin/scheme_registry.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
/*
 * Copyright (C) 2010 Apple Inc. All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE, INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL APPLE COMPUTER, INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "third_party/blink/renderer/platform/weborigin/scheme_registry.h"

#include <algorithm>

#include "third_party/blink/public/platform/web_string.h"
#include "third_party/blink/public/web/blink.h"
#include "third_party/blink/renderer/platform/wtf/allocator/allocator.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/thread_specific.h"
#include "third_party/blink/renderer/platform/wtf/threading.h"
#include "url/url_util.h"

namespace blink {

// Function defined in third_party/blink/public/web/blink.h.
void SetDomainRelaxationForbiddenForTest(bool forbidden,
                                         const WebString& scheme) {
  SchemeRegistry::SetDomainRelaxationForbiddenForURLSchemeForTest(
      forbidden, String(scheme));
}

// Function defined in third_party/blink/public/web/blink.h.
void ResetDomainRelaxationForTest() {
  SchemeRegistry::ResetDomainRelaxationForTest();
}

namespace {

struct PolicyAreasHashTraits : HashTraits<SchemeRegistry::PolicyAreas> {
  static const bool kEmptyValueIsZero = true;
  static SchemeRegistry::PolicyAreas EmptyValue() {
    return SchemeRegistry::kPolicyAreaNone;
  }
};

class URLSchemesRegistry final {
  USING_FAST_MALLOC(URLSchemesRegistry);

 public:
  URLSchemesRegistry()
      :  // For ServiceWorker schemes: HTTP is required because http://localhost
         // is considered secure. Additional checks are performed to ensure that
         // other http pages are filtered out.
        service_worker_schemes({"http", "https"}),
        fetch_api_schemes({"http", "https"}),
        allowed_in_referrer_schemes({"http", "https"}) {
    for (auto& scheme : url::GetCorsEnabledSchemes())
      cors_enabled_schemes.insert(scheme.c_str());
    for (auto& scheme : url::GetCSPBypassingSchemes()) {
      content_security_policy_bypassing_schemes.insert(
          scheme.c_str(), SchemeRegistry::kPolicyAreaAll);
    }
    for (auto& scheme : url::GetEmptyDocumentSchemes())
      empty_document_schemes.insert(scheme.c_str());
  }
  ~URLSchemesRegistry() = default;

  // As URLSchemesRegistry is accessed from multiple threads, be very careful to
  // ensure that
  // - URLSchemesRegistry is initialized/modified through
  //   GetMutableURLSchemesRegistry() before threads can be created, and
  // - The URLSchemesRegistry members below aren't modified when accessed after
  //   initialization.
  URLSchemesSet display_isolated_url_schemes;
  URLSchemesSet empty_document_schemes;
  URLSchemesSet schemes_forbidden_from_domain_relaxation;
  URLSchemesSet not_allowing_javascript_urls_schemes;
  URLSchemesSet cors_enabled_schemes;
  URLSchemesSet service_worker_schemes;
  URLSchemesSet fetch_api_schemes;
  URLSchemesSet first_party_when_top_level_schemes;
  URLSchemesSet first_party_when_top_level_with_secure_embedded_schemes;
  URLSchemesMap<SchemeRegistry::PolicyAreas, PolicyAreasHashTraits>
      content_security_policy_bypassing_schemes;
  URLSchemesSet secure_context_bypassing_schemes;
  URLSchemesSet allowed_in_referrer_schemes;
  URLSchemesSet error_schemes;
  URLSchemesSet wasm_eval_csp_schemes;
  URLSchemesSet allowing_shared_array_buffer_schemes;
  URLSchemesSet web_ui_schemes;
  URLSchemesSet code_cache_with_hashing_schemes;

 private:
  friend const URLSchemesRegistry& GetURLSchemesRegistry();
  friend URLSchemesRegistry& GetMutableURLSchemesRegistry();
  friend URLSchemesRegistry& GetMutableURLSchemesRegistryForTest();

  static URLSchemesRegistry& GetInstance() {
    DEFINE_THREAD_SAFE_STATIC_LOCAL(URLSchemesRegistry, schemes, ());
    return schemes;
  }
};

const URLSchemesRegistry& GetURLSchemesRegistry() {
  return URLSchemesRegistry::GetInstance();
}

URLSchemesRegistry& GetMutableURLSchemesRegistry() {
#if DCHECK_IS_ON()
  DCHECK(WTF::IsBeforeThreadCreated());
#endif
  return URLSchemesRegistry::GetInstance();
}

URLSchemesRegistry& GetMutableURLSchemesRegistryForTest() {
  // Bypasses thread check. This is used when TestRunner tries to mutate
  // schemes_forbidden_from_domain_relaxation during a test or on resetting
  // its internal states.
  return URLSchemesRegistry::GetInstance();
}

}  // namespace

void SchemeRegistry::RegisterURLSchemeAsDisplayIsolated(const String& scheme) {
  DCHECK_EQ(scheme, scheme.LowerASCII());
  GetMutableURLSchemesRegistry().display_isolated_url_schemes.insert(scheme);
}

bool SchemeRegistry::ShouldTreatURLSchemeAsDisplayIsolated(
    const String& scheme) {
  DCHECK_EQ(scheme, scheme.LowerASCII());
  if (scheme.empty())
    return false;
  return GetURLSchemesRegistry().display_isolated_url_schemes.Contains(scheme);
}

bool SchemeRegistry::ShouldTreatURLSchemeAsRestrictingMixedContent(
    const String& scheme) {
  DCHECK_EQ(scheme, scheme.LowerASCII());
  return scheme == "https";
}

bool SchemeRegistry::ShouldLoadURLSchemeAsEmptyDocument(const String& scheme) {
  DCHECK_EQ(scheme, scheme.LowerASCII());
  if (scheme.empty())
    return false;
  return GetURLSchemesRegistry().empty_document_schemes.Contains(scheme);
}

void SchemeRegistry::SetDomainRelaxationForbiddenForURLSchemeForTest(
    bool forbidden,
    const String& scheme) {
  DCHECK_EQ(scheme, scheme.LowerASCII());
  if (scheme.empty())
    return;

  if (forbidden) {
    GetMutableURLSchemesRegistryForTest()
        .schemes_forbidden_from_domain_relaxation.insert(scheme);
  } else {
    GetMutableURLSchemesRegistryForTest()
        .schemes_forbidden_from_domain_relaxation.erase(scheme);
  }
}

void SchemeRegistry::ResetDomainRelaxationForTest() {
  GetMutableURLSchemesRegistryForTest()
      .schemes_forbidden_from_domain_relaxation.clear();
}

bool SchemeRegistry::IsDomainRelaxationForbiddenForURLScheme(
    const String& scheme) {
  DCHECK_EQ(scheme, scheme.LowerASCII());
  if (scheme.empty())
    return false;
  return GetURLSchemesRegistry()
      .schemes_forbidden_from_domain_relaxation.Contains(scheme);
}

bool SchemeRegistry::CanDisplayOnlyIfCanRequest(const String& scheme) {
  DCHECK_EQ(scheme, scheme.LowerASCII());
  return scheme == "blob" || scheme == "filesystem";
}

void SchemeRegistry::RegisterURLSchemeAsNotAllowingJavascriptURLs(
    const String& scheme) {
  DCHECK_EQ(scheme, scheme.LowerASCII());
  GetMutableURLSchemesRegistry().not_allowing_javascript_urls_schemes.insert(
      scheme);
}

void SchemeRegistry::RemoveURLSchemeAsNotAllowingJavascriptURLs(
    const String& scheme) {
  GetMutableURLSchemesRegistry().not_allowing_javascript_urls_schemes.erase(
      scheme);
}

bool SchemeRegistry::ShouldTreatURLSchemeAsNotAllowingJavascriptURLs(
    const String& scheme) {
  DCHECK_EQ(scheme, scheme.LowerASCII());
  if (scheme.empty())
    return false;
  return GetURLSchemesRegistry().not_allowing_javascript_urls_schemes.Contains(
      scheme);
}

bool SchemeRegistry::ShouldTreatURLSchemeAsCorsEnabled(const String& scheme) {
  DCHECK_EQ(scheme, scheme.LowerASCII());
  if (scheme.empty())
    return false;
  return GetURLSchemesRegistry().cors_enabled_schemes.Contains(scheme);
}

String SchemeRegistry::ListOfCorsEnabledURLSchemes() {
  Vector<String> sorted_schemes(GetURLSchemesRegistry().cors_enabled_schemes);
  std::sort(sorted_schemes.begin(), sorted_schemes.end(),
            [](const String& a, const String& b) {
              return CodeUnitCompareLessThan(a, b);
            });

  StringBuilder builder;
  bool add_separator = false;
  for (const auto& scheme : sorted_schemes) {
    if (add_separator)
      builder.Append(", ");
    else
      add_separator = true;

    builder.Append(scheme);
  }
  return builder.ToString();
}

bool SchemeRegistry::ShouldTrackUsageMetricsForScheme(const String& scheme) {
  // This SchemeRegistry is primarily used by Blink UseCounter, which aims to
  // match the tracking policy of page_load_metrics (see
  // pageTrackDecider::ShouldTrack() for more details).
  // The scheme represents content which likely cannot be easily updated.
  // Specifically this includes internal pages such as about, devtools,
  // etc.
  // "chrome-extension" is not included because they have a single deployment
  // point (the webstore) and are designed specifically for Chrome.
  // "data" is not included because real sites shouldn't be using it for
  // top-level pages and Chrome does use it internally (eg. PluginPlaceholder).
  // "file" is not included because file:// navigations have different loading
  // behaviors.
  return scheme == "http" || scheme == "https";
}

void SchemeRegistry::RegisterURLSchemeAsAllowingServiceWorkers(
    const String& scheme) {
  DCHECK_EQ(scheme, scheme.LowerASCII());
  GetMutableURLSchemesRegistry().service_worker_schemes.insert(scheme);
}

bool SchemeRegistry::ShouldTreatURLSchemeAsAllowingServiceWorkers(
    const String& scheme) {
  DCHECK_EQ(scheme, scheme.LowerASCII());
  if (scheme.empty())
    return false;
  return GetURLSchemesRegistry().service_worker_schemes.Contains(scheme);
}

void SchemeRegistry::RegisterURLSchemeAsSupportingFetchAPI(
    const String& scheme) {
  DCHECK_EQ(scheme, scheme.LowerASCII());
  GetMutableURLSchemesRegistry().fetch_api_schemes.insert(scheme);
}

bool SchemeRegistry::ShouldTreatURLSchemeAsSupportingFetchAPI(
    const String& scheme) {
  DCHECK_EQ(scheme, scheme.LowerASCII());
  if (scheme.empty())
    return false;
  return GetURLSchemesRegistry().fetch_api_schemes.Contains(scheme);
}

// https://url.spec.whatwg.org/#special-scheme
bool SchemeRegistry::IsSpecialScheme(const String& scheme) {
  DCHECK_EQ(scheme, scheme.LowerASCII());
  return scheme == "ftp" || scheme == "file" || scheme == "http" ||
         scheme == "https" || scheme == "ws" || scheme == "wss";
}

void SchemeRegistry::RegisterURLSchemeAsFirstPartyWhenTopLevel(
    const String& scheme) {
  DCHECK_EQ(scheme, scheme.LowerASCII());
  GetMutableURLSchemesRegistry().first_party_when_top_level_schemes.insert(
      scheme);
}

void SchemeRegistry::RemoveURLSchemeAsFirstPartyWhenTopLevel(
    const String& scheme) {
  DCHECK_EQ(scheme, scheme.LowerASCII());
  GetMutableURLSchemesRegistry().first_party_when_top_level_schemes.erase(
      scheme);
}

bool SchemeRegistry::ShouldTreatURLSchemeAsFirstPartyWhenTopLevel(
    const String& scheme) {
  DCHECK_EQ(scheme, scheme.LowerASCII());
  if (scheme.empty())
    return false;
  return GetURLSchemesRegistry().first_party_when_top_level_schemes.Contains(
      scheme);
}

void SchemeRegistry::RegisterURLSchemeAsFirstPartyWhenTopLevelEmbeddingSecure(
    const String& scheme) {
  DCHECK_EQ(scheme, scheme.LowerASCII());
  GetMutableURLSchemesRegistry()
      .first_party_when_top_level_with_secure_embedded_schemes.insert(scheme);
}

bool SchemeRegistry::
    ShouldTreatURLSchemeAsFirstPartyWhenTopLevelEmbeddingSecure(
        const String& top_level_scheme,
        const String& child_scheme) {
  DCHECK_EQ(top_level_scheme, top_level_scheme.LowerASCII());
  DCHECK_EQ(child_scheme, child_scheme.LowerASCII());
  // Matches GURL::SchemeIsCryptographic used by
  // RenderFrameHostImpl::ComputeIsolationInfoInternal
  if (child_scheme != "https" && child_scheme != "wss")
    return false;
  if (top_level_scheme.empty())
    return false;
  return GetURLSchemesRegistry()
      .first_party_when_top_level_with_secure_embedded_schemes.Contains(
          top_level_scheme);
}

void SchemeRegistry::RegisterURLSchemeAsAllowedForReferrer(
    const String& scheme) {
  DCHECK_EQ(scheme, scheme.LowerASCII());
  GetMutableURLSchemesRegistry().allowed_in_referrer_schemes.insert(scheme);
}

void SchemeRegistry::RemoveURLSchemeAsAllowedForReferrer(const String& scheme) {
  GetMutableURLSchemesRegistry().allowed_in_referrer_schemes.erase(scheme);
}

bool SchemeRegistry::ShouldTreatURLSchemeAsAllowedForReferrer(
    const String& scheme) {
  DCHECK_EQ(scheme, scheme.LowerASCII());
  if (scheme.empty())
    return false;
  return GetURLSchemesRegistry().allowed_in_referrer_schemes.Contains(scheme);
}

void SchemeRegistry::RegisterURLSchemeAsError(const String& scheme) {
  DCHECK_EQ(scheme, scheme.LowerASCII());
  GetMutableURLSchemesRegistry().error_schemes.insert(scheme);
}

bool SchemeRegistry::ShouldTreatURLSchemeAsError(const String& scheme) {
  DCHECK_EQ(scheme, scheme.LowerASCII());
  if (scheme.empty())
    return false;
  return GetURLSchemesRegistry().error_schemes.Contains(scheme);
}

void SchemeRegistry::RegisterURLSchemeAsAllowingSharedArrayBuffers(
    const String& scheme) {
  DCHECK_EQ(scheme, scheme.LowerASCII());
  GetMutableURLSchemesRegistry().allowing_shared_array_buffer_schemes.insert(
      scheme);
}

bool SchemeRegistry::ShouldTreatURLSchemeAsAllowingSharedArrayBuffers(
    const String& scheme) {
  DCHECK_EQ(scheme, scheme.LowerASCII());
  if (scheme.empty())
    return false;
  return GetURLSchemesRegistry().allowing_shared_array_buffer_schemes.Contains(
      scheme);
}

void SchemeRegistry::RegisterURLSchemeAsBypassingContentSecurityPolicy(
    const String& scheme,
    PolicyAreas policy_areas) {
  DCHECK_EQ(scheme, scheme.LowerASCII());
  GetMutableURLSchemesRegistry()
      .content_security_policy_bypassing_schemes.insert(scheme, policy_areas);
}

void SchemeRegistry::RemoveURLSchemeRegisteredAsBypassingContentSecurityPolicy(
    const String& scheme) {
  DCHECK_EQ(scheme, scheme.LowerASCII());
  GetMutableURLSchemesRegistry()
      .content_security_policy_bypassing_schemes.erase(scheme);
}

bool SchemeRegistry::SchemeShouldBypassContentSecurityPolicy(
    const String& scheme,
    PolicyAreas policy_areas) {
  DCHECK_NE(policy_areas, kPolicyAreaNone);
  if (scheme.empty() || policy_areas == kPolicyAreaNone)
    return false;

  const auto& bypassing_schemes =
      GetURLSchemesRegistry().content_security_policy_bypassing_schemes;
  const auto it = bypassing_schemes.find(scheme);
  if (it == bypassing_schemes.end())
    return false;
  return (it->value & policy_areas) == policy_areas;
}

void SchemeRegistry::RegisterURLSchemeBypassingSecureContextCheck(
    const String& scheme) {
  DCHECK_EQ(scheme, scheme.LowerASCII());
  GetMutableURLSchemesRegistry().secure_context_bypassing_schemes.insert(
      scheme);
}

bool SchemeRegistry::SchemeShouldBypassSecureContextCheck(
    const String& scheme) {
  if (scheme.empty())
    return false;
  DCHECK_EQ(scheme, scheme.LowerASCII());
  return GetURLSchemesRegistry().secure_context_bypassing_schemes.Contains(
      scheme);
}

void SchemeRegistry::RegisterURLSchemeAsAllowingWasmEvalCSP(
    const String& scheme) {
  DCHECK_EQ(scheme, scheme.LowerASCII());
  GetMutableURLSchemesRegistry().wasm_eval_csp_schemes.insert(scheme);
}

bool SchemeRegistry::SchemeSupportsWasmEvalCSP(const String& scheme) {
  if (scheme.empty())
    return false;
  DCHECK_EQ(scheme, scheme.LowerASCII());
  return GetURLSchemesRegistry().wasm_eval_csp_schemes.Contains(scheme);
}

void SchemeRegistry::RegisterURLSchemeAsWebUI(const String& scheme) {
  DCHECK_EQ(scheme, scheme.LowerASCII());
  GetMutableURLSchemesRegistry().web_ui_schemes.insert(scheme);
}

void SchemeRegistry::RemoveURLSchemeAsWebUI(const String& scheme) {
  GetMutableURLSchemesRegistry().web_ui_schemes.erase(scheme);
}

bool SchemeRegistry::IsWebUIScheme(const String& scheme) {
  if (scheme.empty())
    return false;
  DCHECK_EQ(scheme, scheme.LowerASCII());
  return GetURLSchemesRegistry().web_ui_schemes.Contains(scheme);
}

void SchemeRegistry::RegisterURLSchemeAsWebUIForTest(const String& scheme) {
  DCHECK_EQ(scheme, scheme.LowerASCII());
  GetMutableURLSchemesRegistryForTest().web_ui_schemes.insert(scheme);
}

void SchemeRegistry::RemoveURLSchemeAsWebUIForTest(const String& scheme) {
  GetMutableURLSchemesRegistryForTest().web_ui_schemes.erase(scheme);
}

void SchemeRegistry::RegisterURLSchemeAsCodeCacheWithHashing(
    const String& scheme) {
  DCHECK_EQ(scheme, scheme.LowerASCII());
  GetMutableURLSchemesRegistry().code_cache_with_hashing_schemes.insert(scheme);
}

void SchemeRegistry::RemoveURLSchemeAsCodeCacheWithHashing(
    const String& scheme) {
  GetMutableURLSchemesRegistry().code_cache_with_hashing_schemes.erase(scheme);
}

bool SchemeRegistry::SchemeSupportsCodeCacheWithHashing(const String& scheme) {
  if (scheme.empty())
    return false;
  DCHECK_EQ(scheme, scheme.LowerASCII());
  return GetURLSchemesRegistry().code_cache_with_hashing_schemes.Contains(
      scheme);
}

}  // namespace blink

"""

```