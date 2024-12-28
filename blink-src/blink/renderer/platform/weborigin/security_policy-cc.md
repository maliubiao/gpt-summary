Response:
Let's break down the thought process to analyze the given `security_policy.cc` file.

1. **Understand the Goal:** The request asks for the functionality of the file, its relationship to web technologies (JavaScript, HTML, CSS), logical reasoning examples, and common user/programming errors.

2. **Initial Skim for Keywords and Structure:** I'd quickly scan the code for prominent terms. "SecurityPolicy", "Referrer", "Origin", "Access", "Allowed", "Block", "CORS", "HTTPS", etc., immediately stand out. The `#include` directives also give clues about dependencies like `KURL`, `SecurityOrigin`, and network-related components. The namespace `blink` confirms this is part of the Blink rendering engine.

3. **Identify Core Functionality Areas:**  Based on the keywords, I can start grouping the functions into logical areas:

    * **Referrer Policy:**  The functions `ShouldHideReferrer`, `GenerateReferrer`, `ReferrerPolicyFromString`, `ReferrerPolicyAsString`, and `ReferrerPolicyFromHeaderValue` clearly deal with managing the `Referrer` header.

    * **Origin Access Control (CORS-related):**  Functions like `IsOriginAccessAllowed`, `IsOriginAccessToURLAllowed`, `AddOriginAccessAllowListEntry`, `AddOriginAccessBlockListEntry`, `ClearOriginAccessListForOrigin`, and `ClearOriginAccessList` are related to Cross-Origin Resource Sharing (CORS) and controlling access between different origins.

    * **SharedArrayBuffer:** The function `IsSharedArrayBufferAlwaysAllowedForOrigin` indicates functionality related to the `SharedArrayBuffer` feature and its security implications.

4. **Analyze Each Function/Area in Detail:**

    * **Referrer Policy:**
        * **`ShouldHideReferrer`:** Focus on the logic: HTTPS to HTTP hides the referrer. Note the `SchemeRegistry` usage.
        * **`GenerateReferrer`:** This is more complex. Notice the `ReferrerPolicy` enum and the `switch` statement. Trace the different policy options and how they manipulate the referrer URL. Pay attention to the 4096 character limit.
        * **`ReferrerPolicyFromString`:**  Simple mapping from string values to the `ReferrerPolicy` enum.
        * **`ReferrerPolicyAsString`:**  The reverse mapping.
        * **`ReferrerPolicyFromHeaderValue`:**  Parsing a potentially comma-separated list of referrer policy directives from an HTTP header. The validation logic (checking for non-alphanumeric/hyphen characters) is important.

    * **Origin Access Control:**
        * **`IsOriginAccessAllowed` and `IsOriginAccessToURLAllowed`:**  These are essentially checks against an allow/block list managed by `network::cors::OriginAccessList`.
        * **`AddOriginAccessAllowListEntry`, `AddOriginAccessBlockListEntry`, `ClearOriginAccessListForOrigin`, `ClearOriginAccessList`:**  These functions modify the aforementioned allow/block list. The parameters clearly indicate how specific rules can be added based on origin, protocol, domain, and port.

    * **SharedArrayBuffer:**
        * **`IsSharedArrayBufferAlwaysAllowedForOrigin`:** This seems to have platform-specific logic (Fuchsia). The command-line switch and hardcoded allowed origins are key.

5. **Connect to Web Technologies (JavaScript, HTML, CSS):**

    * **Referrer Policy:**  Think about how these policies are set in HTML (`<meta name="referrer">`, `referrerpolicy` attribute on links/iframes/scripts) and how JavaScript can trigger navigations or fetch requests.
    * **Origin Access Control:** This directly relates to CORS, which affects JavaScript's ability to make cross-origin requests using `fetch` or `XMLHttpRequest`. HTML elements like `<img>` or `<link>` can also be subject to CORS.
    * **SharedArrayBuffer:** This is a JavaScript feature. The security policy directly controls when it can be used.

6. **Generate Examples and Scenarios:**

    * **Referrer Policy:** Create scenarios with different `referrerpolicy` values and observe the resulting referrer in outgoing requests. Consider secure vs. insecure contexts.
    * **Origin Access Control:**  Imagine a JavaScript on `a.com` trying to fetch data from `b.com`. Illustrate how allow/block list entries affect this.
    * **SharedArrayBuffer:** Show how the command-line switch on Fuchsia would enable its use.

7. **Identify Potential Errors:**

    * **Referrer Policy:** Typographical errors in policy strings, misunderstanding the nuances of each policy.
    * **Origin Access Control:** Incorrectly configuring allow/block lists (e.g., typos in domain names, wrong port numbers, using the wrong match mode).
    * **SharedArrayBuffer:**  Trying to use it when it's not allowed.

8. **Organize the Information:**  Structure the analysis into clear sections (Functionality, Relationship to Web Technologies, Logical Reasoning, Common Errors). Use bullet points and code examples where appropriate.

9. **Refine and Review:**  Read through the analysis to ensure clarity, accuracy, and completeness. Check for any logical gaps or misunderstandings. For example, double-check the exact behavior of each referrer policy. Ensure the examples are clear and illustrative. Make sure the user error examples are practical and understandable.

By following these steps, a comprehensive analysis of the `security_policy.cc` file can be produced, covering its functionality and its interactions with web technologies.
好的，让我们来分析一下 `blink/renderer/platform/weborigin/security_policy.cc` 这个文件。

**文件功能概要:**

`security_policy.cc` 文件在 Chromium 的 Blink 渲染引擎中，主要负责实现与 Web 安全策略相关的各种功能。 它的核心职责是执行和管理与以下方面相关的安全决策：

1. **Referrer Policy (引用策略):**  控制在浏览器发送请求时，`Referer` HTTP 头信息如何生成和发送。这包括根据不同的策略设置，决定是否发送 Referer，以及发送哪些信息 (例如，只发送源，还是完整 URL)。

2. **Origin Access Control (源访问控制):**  管理跨域资源共享 (CORS) 相关的策略。它维护一个允许和阻止列表，用于决定一个源是否可以访问来自另一个源的资源。

3. **SharedArrayBuffer 访问控制:**  在特定平台上（如 Fuchsia），允许根据配置允许某些源始终使用 `SharedArrayBuffer`。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这个文件中的功能直接影响到 JavaScript, HTML, 和 CSS 的行为，因为它们都可能触发网络请求，并受到安全策略的约束。

**1. Referrer Policy:**

* **关系:**
    * **HTML:**  通过 `<meta name="referrer">` 标签可以设置页面的默认引用策略。链接 (`<a>`)、图片 (`<img>`)、脚本 (`<script>`)、样式表 (`<link rel="stylesheet">`) 等元素可以通过 `referrerpolicy` 属性覆盖默认策略。
    * **JavaScript:**  通过 JavaScript 发起的网络请求 (例如 `fetch`, `XMLHttpRequest`) 会受到当前文档或发起请求元素的引用策略影响。
    * **CSS:**  CSS 中引用的资源 (例如，背景图片 `background-image: url(...)`) 的加载也会受到引用策略的影响。

* **举例说明:**

    * **HTML:**
        ```html
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta name="referrer" content="origin-when-cross-origin">
            <title>Referrer Policy Example</title>
        </head>
        <body>
            <a href="https://example.com" referrerpolicy="no-referrer-when-downgrade">Visit Example</a>
            <img src="https://other-domain.com/image.jpg" referrerpolicy="origin">
            <script src="https://another-domain.com/script.js"></script>
        </body>
        </html>
        ```
        在这个例子中：
        * 整个页面的默认引用策略是 `origin-when-cross-origin`。
        * 链接到 `https://example.com` 的请求，由于设置了 `referrerpolicy="no-referrer-when-downgrade"`，如果当前页面是 HTTPS，则会发送 Referer，否则不发送。
        * 加载 `https://other-domain.com/image.jpg` 的请求只会发送目标源作为 Referer。
        * 加载 `https://another-domain.com/script.js` 的请求会遵循页面的默认引用策略。

    * **JavaScript:**
        ```javascript
        fetch('https://api.example.com', {
          referrerPolicy: 'same-origin'
        })
        .then(response => response.json())
        .then(data => console.log(data));
        ```
        这个 `fetch` 请求显式设置了 `referrerPolicy` 为 `same-origin`，意味着只有当请求源和目标源相同时才会发送 Referer。

**2. Origin Access Control (CORS):**

* **关系:**
    * **JavaScript:** 当 JavaScript 代码尝试从与当前文档不同源的 URL 获取资源时（例如，使用 `fetch` 或 `XMLHttpRequest`），浏览器会进行 CORS 检查。`security_policy.cc` 中的代码会检查是否允许该跨域访问。
    * **HTML:**  `<img>`, `<video>`, `<audio>`, `<link>` 等标签在加载跨域资源时也会受到 CORS 的限制。
    * **CSS:**  `@font-face` 规则加载跨域字体，以及 `background-image: url(...)` 加载跨域图片时，同样会触发 CORS 检查。

* **举例说明:**

    * **假设输入:** 一个运行在 `http://example.com` 的网页中的 JavaScript 代码尝试使用 `fetch` 获取 `http://api.another-domain.com/data` 的数据。

    * **逻辑推理:** `SecurityPolicy::IsOriginAccessToURLAllowed` 会被调用，传入 `http://example.com` 的安全源和目标 URL `http://api.another-domain.com/data`。

    * **假设输出:**
        * 如果 `security_policy.cc` 中维护的源访问列表中，`http://example.com` 被允许访问 `http://api.another-domain.com` (可能通过 `AddOriginAccessAllowListEntry` 添加)，则 `IsOriginAccessToURLAllowed` 返回 `true`，浏览器会发送带有 `Origin: http://example.com` 的请求，并根据服务器的 `Access-Control-Allow-Origin` 等响应头决定是否允许访问。
        * 如果没有相应的允许规则，则 `IsOriginAccessToURLAllowed` 返回 `false`，浏览器会阻止该跨域请求，JavaScript 代码会收到一个网络错误。

**3. SharedArrayBuffer 访问控制:**

* **关系:**
    * **JavaScript:**  `SharedArrayBuffer` 是一个允许在多个 worker 之间共享内存的 JavaScript 对象。由于其强大的功能，也存在安全风险。`security_policy.cc` 中的 `IsSharedArrayBufferAlwaysAllowedForOrigin` 用于控制在特定情况下是否允许使用。

* **举例说明 (基于 Fuchsia 平台):**

    * **假设输入:**  一个运行在 `https://trusted.example.com` 的网页尝试创建 `SharedArrayBuffer`。 假设启动 Chromium 时使用了 `--shared-array-buffer-allowed-origins=https://trusted.example.com`。

    * **逻辑推理:** 当 JavaScript 代码尝试创建 `SharedArrayBuffer` 时，`SecurityPolicy::IsSharedArrayBufferAlwaysAllowedForOrigin` 会被调用，传入 `https://trusted.example.com` 的安全源。

    * **假设输出:** 由于启动参数中允许了 `https://trusted.example.com`，`IsSharedArrayBufferAlwaysAllowedForOrigin` 返回 `true`，允许创建 `SharedArrayBuffer`。 如果没有在启动参数中指定该源，则会返回 `false`，创建 `SharedArrayBuffer` 将失败。

**逻辑推理举例 (Referrer Policy):**

* **假设输入:**
    * 当前页面 URL: `https://secure.example.com/page.html`
    * 触发请求的 URL: `http://insecure.other.com/api`
    * 当前页面的引用策略: `strict-origin-when-cross-origin`

* **逻辑推理:**  `SecurityPolicy::GenerateReferrer` 函数会被调用，传入策略、目标 URL 和当前页面 URL。 由于目标 URL 的协议是 HTTP (不安全)，而当前页面是 HTTPS (安全)，属于降级的情况。 并且策略是 `strict-origin-when-cross-origin`，在跨域且降级的情况下，不会发送 Referer。

* **假设输出:** `GenerateReferrer` 函数会返回一个 `Referrer` 对象，其 Referrer URL 为空 (或表示不发送 Referer)。

**用户或编程常见的使用错误:**

1. **Referrer Policy 设置错误:**
    * **错误:** 在 HTML 中拼写错误的 `referrerpolicy` 属性值，例如 `referepolicy`。
    * **后果:** 浏览器可能无法识别该策略，会使用默认的引用策略，导致与预期不符的 Referer 信息被发送或不发送。
    * **例子:** `<a href="..." referepolicy="origin">`

2. **CORS 配置错误:**
    * **错误:**  服务器端没有正确配置 CORS 响应头 (`Access-Control-Allow-Origin` 等)。
    * **后果:**  即使客户端代码尝试发起跨域请求，也会被浏览器阻止，导致 JavaScript 代码报错。
    * **例子:**  JavaScript 代码尝试从 `http://api.example.com` 获取数据，但服务器端没有设置 `Access-Control-Allow-Origin: *` 或 `Access-Control-Allow-Origin: http://client.example.com`。

3. **误解 Referrer Policy 的行为:**
    * **错误:**  认为设置了 `no-referrer` 就绝对不会发送任何 Referer 信息。
    * **后果:**  虽然 `no-referrer` 会阻止发送 Referer HTTP 头，但在某些情况下，浏览器或插件可能会使用其他机制来传递引用信息。
    * **例子:**  用户期望使用 `no-referrer` 来完全隐藏来源，但某些浏览器插件可能会通过其他方式记录或传递来源信息。

4. **SharedArrayBuffer 使用限制:**
    * **错误 (在非 Fuchsia 平台):**  尝试在没有正确配置 COOP/COEP 头的情况下使用 `SharedArrayBuffer`。
    * **后果:**  `SharedArrayBuffer` 的构造函数会抛出异常，因为安全上下文不满足要求。
    * **例子:**  在没有设置 `Cross-Origin-Opener-Policy: same-origin` 和 `Cross-Origin-Embedder-Policy: require-corp` 响应头的情况下尝试创建 `SharedArrayBuffer`。

5. **源访问列表配置错误:**
    * **错误:** 在使用 `AddOriginAccessAllowListEntry` 或 `AddOriginAccessBlockListEntry` 时，错误地指定了协议、域名或端口。
    * **后果:**  可能导致本应允许的跨域请求被阻止，或者本应阻止的请求被允许，从而产生安全风险或功能异常。
    * **例子:**  错误地将端口设置为字符串而不是数字，或者在域名中出现拼写错误。

总而言之，`security_policy.cc` 是 Blink 渲染引擎中一个至关重要的文件，它通过执行各种安全策略来保护用户的安全和隐私，并确保 Web 平台的稳定性和可靠性。理解其功能对于 Web 开发者来说非常重要，以便正确地构建安全可靠的 Web 应用。

Prompt: 
```
这是目录为blink/renderer/platform/weborigin/security_policy.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
/*
 * Copyright (C) 2011 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1.  Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 * 3.  Neither the name of Google, Inc. ("Google") nor the names of
 *     its contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY GOOGLE AND ITS CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL APPLE OR ITS CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/platform/weborigin/security_policy.h"

#include <memory>

#include "base/command_line.h"
#include "base/no_destructor.h"
#include "base/strings/pattern.h"
#include "base/strings/string_split.h"
#include "base/synchronization/lock.h"
#include "build/build_config.h"
#include "services/network/public/cpp/cors/origin_access_list.h"
#include "services/network/public/mojom/referrer_policy.mojom-blink.h"
#include "third_party/blink/public/common/loader/referrer_utils.h"
#include "third_party/blink/public/common/switches.h"
#include "third_party/blink/public/platform/web_string.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/weborigin/scheme_registry.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/wtf/hash_set.h"
#include "third_party/blink/renderer/platform/wtf/std_lib_extras.h"
#include "third_party/blink/renderer/platform/wtf/text/parsing_utilities.h"
#include "third_party/blink/renderer/platform/wtf/text/string_utf8_adaptor.h"
#include "third_party/blink/renderer/platform/wtf/threading.h"
#include "third_party/blink/renderer/platform/wtf/wtf.h"
#include "url/gurl.h"

namespace blink {

static base::Lock& GetLock() {
  DEFINE_THREAD_SAFE_STATIC_LOCAL(base::Lock, lock, ());
  return lock;
}

static network::cors::OriginAccessList& GetOriginAccessList() {
  DEFINE_THREAD_SAFE_STATIC_LOCAL(network::cors::OriginAccessList,
                                  origin_access_list, ());
  return origin_access_list;
}

bool SecurityPolicy::ShouldHideReferrer(const KURL& url, const KURL& referrer) {
  bool referrer_is_secure_url = referrer.ProtocolIs("https");
  bool scheme_is_allowed =
      SchemeRegistry::ShouldTreatURLSchemeAsAllowedForReferrer(
          referrer.Protocol());

  if (!scheme_is_allowed)
    return true;

  if (!referrer_is_secure_url)
    return false;

  bool url_is_secure_url = url.ProtocolIs("https");

  return !url_is_secure_url;
}

Referrer SecurityPolicy::GenerateReferrer(
    network::mojom::ReferrerPolicy referrer_policy,
    const KURL& url,
    const String& referrer) {
  network::mojom::ReferrerPolicy referrer_policy_no_default =
      ReferrerUtils::MojoReferrerPolicyResolveDefault(referrer_policy);
  // Empty (a possible input) and default (the value of `Referrer::NoReferrer`)
  // strings are not equivalent.
  if (referrer == Referrer::NoReferrer() || referrer.empty())
    return Referrer(Referrer::NoReferrer(), referrer_policy_no_default);

  KURL referrer_url = KURL(NullURL(), referrer).UrlStrippedForUseAsReferrer();

  if (!referrer_url.IsValid())
    return Referrer(Referrer::NoReferrer(), referrer_policy_no_default);

  // 5. Let referrerOrigin be the result of stripping referrerSource for use as
  // a referrer, with the origin-only flag set to true.
  KURL referrer_origin = referrer_url;
  referrer_origin.SetPath(String());
  referrer_origin.SetQuery(String());

  // 6. If the result of serializing referrerURL is a string whose length is
  // greater than 4096, set referrerURL to referrerOrigin.
  if (referrer_url.GetString().length() > 4096)
    referrer_url = referrer_origin;

  switch (referrer_policy_no_default) {
    case network::mojom::ReferrerPolicy::kNever:
      return Referrer(Referrer::NoReferrer(), referrer_policy_no_default);
    case network::mojom::ReferrerPolicy::kAlways:
      return Referrer(referrer_url, referrer_policy_no_default);
    case network::mojom::ReferrerPolicy::kOrigin: {
      return Referrer(referrer_origin, referrer_policy_no_default);
    }
    case network::mojom::ReferrerPolicy::kOriginWhenCrossOrigin: {
      if (!SecurityOrigin::AreSameOrigin(referrer_url, url)) {
        return Referrer(referrer_origin, referrer_policy_no_default);
      }
      break;
    }
    case network::mojom::ReferrerPolicy::kSameOrigin: {
      if (!SecurityOrigin::AreSameOrigin(referrer_url, url)) {
        return Referrer(Referrer::NoReferrer(), referrer_policy_no_default);
      }
      return Referrer(referrer_url, referrer_policy_no_default);
    }
    case network::mojom::ReferrerPolicy::kStrictOrigin: {
      return Referrer(ShouldHideReferrer(url, referrer_url)
                          ? Referrer::NoReferrer()
                          : referrer_origin,
                      referrer_policy_no_default);
    }
    case network::mojom::ReferrerPolicy::kStrictOriginWhenCrossOrigin: {
      if (!SecurityOrigin::AreSameOrigin(referrer_url, url)) {
        return Referrer(ShouldHideReferrer(url, referrer_url)
                            ? Referrer::NoReferrer()
                            : referrer_origin,
                        referrer_policy_no_default);
      }
      break;
    }
    case network::mojom::ReferrerPolicy::kNoReferrerWhenDowngrade:
      break;
    case network::mojom::ReferrerPolicy::kDefault:
      NOTREACHED();
  }

  return Referrer(ShouldHideReferrer(url, referrer_url) ? Referrer::NoReferrer()
                                                        : referrer_url,
                  referrer_policy_no_default);
}

bool SecurityPolicy::IsOriginAccessAllowed(
    const SecurityOrigin* active_origin,
    const SecurityOrigin* target_origin) {
  base::AutoLock locker(GetLock());
  return GetOriginAccessList().CheckAccessState(
             active_origin->ToUrlOrigin(),
             target_origin->ToUrlOrigin().GetURL()) ==
         network::cors::OriginAccessList::AccessState::kAllowed;
}

bool SecurityPolicy::IsOriginAccessToURLAllowed(
    const SecurityOrigin* active_origin,
    const KURL& url) {
  base::AutoLock locker(GetLock());
  return GetOriginAccessList().CheckAccessState(active_origin->ToUrlOrigin(),
                                                GURL(url)) ==
         network::cors::OriginAccessList::AccessState::kAllowed;
}

void SecurityPolicy::AddOriginAccessAllowListEntry(
    const SecurityOrigin& source_origin,
    const String& destination_protocol,
    const String& destination_domain,
    const uint16_t port,
    const network::mojom::CorsDomainMatchMode domain_match_mode,
    const network::mojom::CorsPortMatchMode port_match_mode,
    const network::mojom::CorsOriginAccessMatchPriority priority) {
  base::AutoLock locker(GetLock());
  GetOriginAccessList().AddAllowListEntryForOrigin(
      source_origin.ToUrlOrigin(), destination_protocol.Utf8(),
      destination_domain.Utf8(), port, domain_match_mode, port_match_mode,
      priority);
}

void SecurityPolicy::AddOriginAccessBlockListEntry(
    const SecurityOrigin& source_origin,
    const String& destination_protocol,
    const String& destination_domain,
    const uint16_t port,
    const network::mojom::CorsDomainMatchMode domain_match_mode,
    const network::mojom::CorsPortMatchMode port_match_mode,
    const network::mojom::CorsOriginAccessMatchPriority priority) {
  base::AutoLock locker(GetLock());
  GetOriginAccessList().AddBlockListEntryForOrigin(
      source_origin.ToUrlOrigin(), destination_protocol.Utf8(),
      destination_domain.Utf8(), port, domain_match_mode, port_match_mode,
      priority);
}

void SecurityPolicy::ClearOriginAccessListForOrigin(
    const SecurityOrigin& source_origin) {
  base::AutoLock locker(GetLock());
  GetOriginAccessList().ClearForOrigin(source_origin.ToUrlOrigin());
}

void SecurityPolicy::ClearOriginAccessList() {
  base::AutoLock locker(GetLock());
  GetOriginAccessList().Clear();
}

bool SecurityPolicy::ReferrerPolicyFromString(
    const String& policy,
    ReferrerPolicyLegacyKeywordsSupport legacy_keywords_support,
    network::mojom::ReferrerPolicy* result) {
  DCHECK(!policy.IsNull());
  bool support_legacy_keywords =
      (legacy_keywords_support == kSupportReferrerPolicyLegacyKeywords);

  if (EqualIgnoringASCIICase(policy, "no-referrer") ||
      (support_legacy_keywords && (EqualIgnoringASCIICase(policy, "never") ||
                                   EqualIgnoringASCIICase(policy, "none")))) {
    *result = network::mojom::ReferrerPolicy::kNever;
    return true;
  }
  if (EqualIgnoringASCIICase(policy, "unsafe-url") ||
      (support_legacy_keywords && EqualIgnoringASCIICase(policy, "always"))) {
    *result = network::mojom::ReferrerPolicy::kAlways;
    return true;
  }
  if (EqualIgnoringASCIICase(policy, "origin")) {
    *result = network::mojom::ReferrerPolicy::kOrigin;
    return true;
  }
  if (EqualIgnoringASCIICase(policy, "origin-when-cross-origin") ||
      (support_legacy_keywords &&
       EqualIgnoringASCIICase(policy, "origin-when-crossorigin"))) {
    *result = network::mojom::ReferrerPolicy::kOriginWhenCrossOrigin;
    return true;
  }
  if (EqualIgnoringASCIICase(policy, "same-origin")) {
    *result = network::mojom::ReferrerPolicy::kSameOrigin;
    return true;
  }
  if (EqualIgnoringASCIICase(policy, "strict-origin")) {
    *result = network::mojom::ReferrerPolicy::kStrictOrigin;
    return true;
  }
  if (EqualIgnoringASCIICase(policy, "strict-origin-when-cross-origin")) {
    *result = network::mojom::ReferrerPolicy::kStrictOriginWhenCrossOrigin;
    return true;
  }
  if (EqualIgnoringASCIICase(policy, "no-referrer-when-downgrade")) {
    *result = network::mojom::ReferrerPolicy::kNoReferrerWhenDowngrade;
    return true;
  }
  if (support_legacy_keywords && EqualIgnoringASCIICase(policy, "default")) {
    *result = ReferrerUtils::NetToMojoReferrerPolicy(
        ReferrerUtils::GetDefaultNetReferrerPolicy());
    return true;
  }
  return false;
}

String SecurityPolicy::ReferrerPolicyAsString(
    network::mojom::ReferrerPolicy policy) {
  switch (policy) {
    case network::mojom::ReferrerPolicy::kAlways:
      return "unsafe-url";
    case network::mojom::ReferrerPolicy::kDefault:
      return "";
    case network::mojom::ReferrerPolicy::kNoReferrerWhenDowngrade:
      return "no-referrer-when-downgrade";
    case network::mojom::ReferrerPolicy::kNever:
      return "no-referrer";
    case network::mojom::ReferrerPolicy::kOrigin:
      return "origin";
    case network::mojom::ReferrerPolicy::kOriginWhenCrossOrigin:
      return "origin-when-cross-origin";
    case network::mojom::ReferrerPolicy::kSameOrigin:
      return "same-origin";
    case network::mojom::ReferrerPolicy::kStrictOrigin:
      return "strict-origin";
    case network::mojom::ReferrerPolicy::kStrictOriginWhenCrossOrigin:
      return "strict-origin-when-cross-origin";
  }
  NOTREACHED();
}

namespace {

template <typename CharType>
inline bool IsASCIIAlphaOrHyphen(CharType c) {
  return IsASCIIAlpha(c) || c == '-';
}

}  // namespace

bool SecurityPolicy::ReferrerPolicyFromHeaderValue(
    const String& header_value,
    ReferrerPolicyLegacyKeywordsSupport legacy_keywords_support,
    network::mojom::ReferrerPolicy* result) {
  network::mojom::ReferrerPolicy referrer_policy =
      network::mojom::ReferrerPolicy::kDefault;

  Vector<String> tokens;
  header_value.Split(',', true, tokens);
  for (const auto& token : tokens) {
    network::mojom::ReferrerPolicy current_result;
    auto stripped_token = token.StripWhiteSpace();
    if (SecurityPolicy::ReferrerPolicyFromString(token.StripWhiteSpace(),
                                                 legacy_keywords_support,
                                                 &current_result)) {
      referrer_policy = current_result;
    } else {
      Vector<UChar> characters;
      stripped_token.AppendTo(characters);
      const UChar* position = characters.data();
      UChar* end = characters.data() + characters.size();
      SkipWhile<UChar, IsASCIIAlphaOrHyphen>(position, end);
      if (position != end)
        return false;
    }
  }

  if (referrer_policy == network::mojom::ReferrerPolicy::kDefault)
    return false;

  *result = referrer_policy;
  return true;
}

#if BUILDFLAG(IS_FUCHSIA)
namespace {
std::vector<url::Origin> GetSharedArrayBufferOrigins() {
  std::string switch_value =
      base::CommandLine::ForCurrentProcess()->GetSwitchValueASCII(
          switches::kSharedArrayBufferAllowedOrigins);
  std::vector<std::string> list =
      SplitString(switch_value, ",", base::WhitespaceHandling::TRIM_WHITESPACE,
                  base::SplitResult::SPLIT_WANT_NONEMPTY);
  std::vector<url::Origin> result;
  for (auto& origin : list) {
    GURL url(origin);
    if (!url.is_valid() || url.scheme() != url::kHttpsScheme) {
      LOG(FATAL) << "Invalid --" << switches::kSharedArrayBufferAllowedOrigins
                 << " specified: " << switch_value;
    }
    result.push_back(url::Origin::Create(url));
  }
  return result;
}
}  // namespace
#endif  // BUILDFLAG(IS_FUCHSIA)

// static
bool SecurityPolicy::IsSharedArrayBufferAlwaysAllowedForOrigin(
    const SecurityOrigin* security_origin) {
#if BUILDFLAG(IS_FUCHSIA)
  static base::NoDestructor<std::vector<url::Origin>> allowed_origins(
      GetSharedArrayBufferOrigins());
  url::Origin origin = security_origin->ToUrlOrigin();
  for (const url::Origin& allowed_origin : *allowed_origins) {
    if (origin.scheme() == allowed_origin.scheme() &&
        origin.DomainIs(allowed_origin.host()) &&
        origin.port() == allowed_origin.port()) {
      return true;
    }
  }
#endif
  return false;
}

}  // namespace blink

"""

```