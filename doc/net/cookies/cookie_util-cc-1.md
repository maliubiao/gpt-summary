Response:
Let's break down the thought process for analyzing this code snippet.

**1. Understanding the Request:**

The request asks for the functionalities of `net/cookies/cookie_util.cc`, its relation to JavaScript, examples with input/output, common user errors, debugging steps, and a summary. It's also flagged as part 2 of 2, implying the first part provided some context, though we need to proceed as if this is the only context available for now.

**2. Initial Skim and Keyword Identification:**

I'd first read through the code, looking for recognizable keywords and patterns related to cookies and network requests. Terms like `SameSite`, `CookieOptions`, `ComputeSameSiteContext`, `ScriptGet`, `ScriptSet`, `Response`, `Subresource`, `FirstPartySet`, and `StorageAccessApi` immediately stand out. These suggest the file's primary concern is managing cookie behavior based on different contexts and security considerations.

**3. Functional Grouping:**

Next, I'd try to group related functions together to understand their purpose. I see several functions starting with `ComputeSameSiteContextFor...`. This strongly suggests a core function for determining the "SameSite" context of a cookie operation, with specialized variations for different scenarios (script access, responses, subresources).

*   **`ComputeSameSiteContext` variants:** These seem to handle the logic for determining if a cookie access is same-site, cross-site, or something in between. They take parameters like URLs, `SiteForCookies`, and initiators.
*   **Helper functions:**  Functions like `HttpMethodStringToEnum`, `IsPortBoundCookiesEnabled`, `IsSchemefulSameSiteEnabled` provide supporting information or utilities.
*   **Functions related to First-Party Sets:** `ComputeFirstPartySetMetadataMaybeAsync` deals with the concept of grouping related sites.
*   **Utility functions:** `StripAccessResults`, `RecordCookiePortOmniboxHistograms`, `DCheckIncludedAndExcludedCookieLists` perform specific tasks related to cookie data and debugging.
*   **Functions related to partitioning and overrides:** `IsForceThirdPartyCookieBlockingEnabled`, `PartitionedCookiesDisabledByCommandLine`, `AddOrRemoveStorageAccessApiOverride` deal with more advanced cookie settings.

**4. Inferring Functionality from Function Names and Logic:**

Now, I'd go deeper into individual functions:

*   **`ComputeSameSiteContextFor...`:** The core logic involves comparing the URLs, `SiteForCookies`, and initiators, both schemefully (including protocol) and schemelessly (ignoring protocol). The `SameSite` context determines how a browser handles cookies based on the relationship between the requesting site and the cookie's origin. The logic includes checks for redirects and HTTP method safety.
*   **`ComputeSameSiteContextForScriptGet` and `ComputeSameSiteContextForScriptSet`:** These are specifically for JavaScript's interaction with cookies. The code explicitly mentions that the redirect chain is not considered in these cases, only the current URL.
*   **`ComputeSameSiteContextForResponse`:** This function seems focused on the server setting cookies, considering main frame navigations and `site_for_cookies`.
*   **`ComputeSameSiteContextForSubresource`:** This handles cookie access for resources loaded by a page (images, scripts, etc.). The same-site check is based on `site_for_cookies`.

**5. Identifying JavaScript Relevance:**

The functions with "ScriptGet" and "ScriptSet" in their names clearly indicate interaction with JavaScript. JavaScript uses methods like `document.cookie` to access and set cookies. The parameters of these functions (like `url`) align with the information JavaScript would have in these scenarios.

**6. Constructing Examples (Hypothetical Input/Output):**

For the JavaScript interactions, I considered typical use cases:

*   **`ComputeSameSiteContextForScriptGet`:**  A script on `https://example.com` trying to read a cookie for `https://other.com`. The output would likely be `CROSS_SITE`.
*   **`ComputeSameSiteContextForScriptSet`:** A script on `https://example.com` setting a cookie for `https://example.com`. The output would be `SAME_SITE`.

For the main frame navigation (`ComputeSameSiteContextForResponse`), a navigation from `https://initial.com` to `https://final.com` (potentially through redirects) is a good example.

**7. Considering User Errors and Debugging:**

I thought about common mistakes developers make when working with cookies:

*   Incorrectly setting `SameSite` attributes.
*   Assuming cookies will be sent in all contexts.
*   Not understanding the implications of different `SameSite` values (Strict, Lax, None).

For debugging, I considered how a developer might end up in this code:

*   Setting breakpoints in the cookie handling logic within the Chromium DevTools.
*   Examining network requests and responses to understand cookie behavior.

**8. Summarizing the Functionality:**

Finally, I summarized the core purpose of the file as managing cookie access and setting based on the SameSite attribute, considering various contexts like script interaction, navigation, and subresource loading. I emphasized its role in implementing modern cookie security features.

**Self-Correction/Refinement during the Process:**

*   Initially, I might have focused too much on individual functions. I realized the importance of grouping them by purpose (SameSite computation, JavaScript interaction, etc.).
*   I ensured the examples were clear and illustrated the core concepts of same-site and cross-site contexts.
*   I made sure to explicitly link the JavaScript examples to the corresponding `ComputeSameSiteContextForScript...` functions.
*   I reviewed the code for any mentions of user errors or debugging hints within the comments or logic. The `DCHECK` statements are a good example of internal debugging checks.

By following this structured approach, I could systematically analyze the code and address all aspects of the request effectively.
好的，这是对`net/cookies/cookie_util.cc`文件功能的归纳总结：

**功能归纳：**

`net/cookies/cookie_util.cc` 文件是 Chromium 网络栈中专门负责处理 Cookie 相关实用功能的代码。其核心职责是确定在不同场景下，Cookie 的 "SameSite" 上下文，并提供其他辅助性的 Cookie 处理工具函数。

主要功能可以概括为以下几点：

1. **计算 SameSite Cookie 上下文 (核心功能):**
    *   该文件包含多个 `ComputeSameSiteContextFor...` 函数，用于根据不同的请求类型和上下文（例如，HTTP 请求、JavaScript 脚本访问、资源加载、主框架导航等）以及相关的 URL、站点信息 (SiteForCookies)、发起者 (initiator) 等信息，来计算出 Cookie 的 SameSite 上下文。
    *   SameSite 上下文决定了浏览器是否应该在跨站请求中发送 Cookie，这是现代 Web 安全的重要组成部分。
    *   它会区分 schemeful (包括协议) 和 schemeless (忽略协议) 的 SameSite 判断。

2. **处理不同来源的 Cookie 访问请求：**
    *   针对 HTTP 请求 (`ComputeSameSiteContextForRequest`)：考虑请求方法 (GET, POST 等) 和重定向链。
    *   针对 JavaScript 脚本 (`ComputeSameSiteContextForScriptGet`, `ComputeSameSiteContextForScriptSet`)：专门处理 JavaScript 通过 `document.cookie` 访问 Cookie 的情况，不考虑重定向链。
    *   针对 HTTP 响应 (`ComputeSameSiteContextForResponse`)：处理服务器设置 Cookie 的场景，特别关注主框架导航。
    *   针对子资源请求 (`ComputeSameSiteContextForSubresource`)：处理页面加载的图片、脚本等资源的 Cookie 访问。

3. **提供 Cookie 相关的配置和特性检测：**
    *   提供函数来检查某些 Cookie 特性是否启用，例如端口绑定 Cookie (`IsPortBoundCookiesEnabled`)、Scheme 绑定 Cookie (`IsSchemeBoundCookiesEnabled`)、Schemeful SameSite (`IsSchemefulSameSiteEnabled`)、以及第三方 Cookie 强制拦截等。

4. **处理 First-Party Sets (FPS)：**
    *   提供 `ComputeFirstPartySetMetadataMaybeAsync` 函数，用于异步计算与 First-Party Sets 相关的元数据。FPS 允许将一组相关域名声明为一个 "集合"，以便在某些 Cookie 处理场景中被视为同一方。

5. **提供 Cookie 访问结果和列表处理的工具函数：**
    *   `IsCookieAccessResultInclude` 判断 Cookie 访问结果是否为包含 (允许访问)。
    *   `StripAccessResults` 从带有访问结果的 Cookie 列表中提取出纯粹的 Cookie 列表。

6. **记录 Cookie 相关的统计信息：**
    *   `RecordCookiePortOmniboxHistograms` 记录通过地址栏导航访问带有特定端口的 URL 的统计信息。

7. **提供调试和断言功能：**
    *   `DCheckIncludedAndExcludedCookieLists` 用于在调试版本中检查包含和排除的 Cookie 列表是否符合预期。

8. **处理存储访问 API (Storage Access API) 的覆盖：**
    *   `AddOrRemoveStorageAccessApiOverride` 函数用于根据存储访问 API 的状态来添加或移除 Cookie 设置的覆盖。

**与 JavaScript 的关系举例：**

`ComputeSameSiteContextForScriptGet` 和 `ComputeSameSiteContextForScriptSet` 函数直接关联到 JavaScript 的 Cookie 操作。

**举例说明：**

假设一个网页 `https://example.com` 上的 JavaScript 代码尝试读取或设置 Cookie。

*   **读取 Cookie (ScriptGet):**  当 JavaScript 执行 `document.cookie` 尝试读取 Cookie 时，浏览器网络栈会调用 `ComputeSameSiteContextForScriptGet` 函数。
    *   **假设输入：**
        *   `url`: `https://otherwebsite.com` (假设尝试读取目标站点的 Cookie)
        *   `site_for_cookies`:  `SiteForCookies("https://example.com")` (当前页面的站点信息)
        *   `initiator`: `url::Origin::Create(GURL("https://example.com"))` (发起脚本的来源)
        *   `force_ignore_site_for_cookies`: `false`
    *   **逻辑推理：** 函数会比较 `url` 和 `site_for_cookies`，如果两者不是同源或同站（根据 SameSite 的定义），则会判断为跨站。
    *   **可能的输出：** `CookieOptions::SameSiteCookieContext(ContextType::CROSS_SITE, ContextType::CROSS_SITE)` (表示跨站上下文，默认情况下浏览器可能不会发送 SameSite=Strict 或 Lax 的 Cookie)。

*   **设置 Cookie (ScriptSet):** 当 JavaScript 执行 `document.cookie = "name=value"` 尝试设置 Cookie 时，浏览器网络栈会调用 `ComputeSameSiteContextForScriptSet` 函数。
    *   **假设输入：**
        *   `url`: `https://example.com` (要设置 Cookie 的域名)
        *   `site_for_cookies`: `SiteForCookies("https://example.com")`
        *   `force_ignore_site_for_cookies`: `false`
    *   **逻辑推理：** 函数会比较 `url` 和 `site_for_cookies`。由于两者相同，会判断为同站。
    *   **可能的输出：** `CookieOptions::SameSiteCookieContext`，其内部的 `ContextType` 将根据其他因素（如是否启用 Schemeful SameSite）而定，但很可能是表示同站的某种类型。

**用户或编程常见的使用错误：**

1. **未正确设置或理解 `SameSite` 属性：**
    *   **错误示例：** 开发者可能错误地认为所有 Cookie 都会在所有跨站请求中发送，而没有正确设置 `SameSite=None; Secure` 来允许跨站发送。这会导致在某些场景下 Cookie 被阻止发送。
    *   **用户操作：** 用户访问一个网站，该网站依赖于在跨站请求中发送的 Cookie 来维持登录状态或其他功能。如果开发者未正确配置 `SameSite` 属性，用户可能会发现某些功能无法正常工作，例如登录状态丢失。

2. **在不安全的上下文中设置 `Secure` 属性的 Cookie：**
    *   **错误示例：** 开发者尝试在一个非 HTTPS 的页面上设置带有 `Secure` 属性的 Cookie。
    *   **后果：** 浏览器会阻止这种 Cookie 的设置，因为 `Secure` 属性要求 Cookie 只能通过 HTTPS 连接传输。

3. **对 `SiteForCookies` 的理解不足：**
    *   **错误示例：**  在某些复杂的场景下，例如涉及嵌入式内容或不同的域名结构，开发者可能对应该使用哪个 `SiteForCookies` 产生误解，导致 SameSite 上下文计算错误。

**用户操作如何一步步到达这里 (作为调试线索)：**

假设用户在访问 `https://example.com` 时遇到了 Cookie 相关的问题，开发者可能会进行以下调试：

1. **用户访问 `https://example.com`。**
2. **网站上的 JavaScript 代码尝试读取或设置 Cookie (例如，通过 `document.cookie`)。**
3. **浏览器接收到 JavaScript 的 Cookie 操作请求。**
4. **浏览器网络栈开始处理该 Cookie 操作。**
5. **根据是读取还是设置 Cookie，以及当前的页面 URL 和其他上下文信息，网络栈内部会调用 `cookie_util.cc` 中的相应 `ComputeSameSiteContextForScriptGet` 或 `ComputeSameSiteContextForScriptSet` 函数。**
6. **在这些函数内部，会进行一系列的逻辑判断，比较 URL、站点信息、发起者等，来确定 SameSite 上下文。**
7. **开发者可能会在这些 `ComputeSameSiteContextFor...` 函数中设置断点，查看传入的参数值，例如 `url`、`site_for_cookies`、`initiator` 等，来理解浏览器是如何判断 SameSite 上下文的。**
8. **开发者还可以检查 Cookie 的 `SameSite` 属性，以及网络请求的 Header 信息，来验证浏览器的行为是否符合预期。**

总而言之，`net/cookies/cookie_util.cc` 是 Chromium 中处理 Cookie 安全性和行为的关键组成部分，特别是关于 SameSite 策略的实现。它提供了丰富的函数来在各种场景下精确地计算和管理 Cookie 的上下文。

Prompt: 
```
这是目录为net/cookies/cookie_util.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
uests initiated by extensions,
  //   which need to behave as though they are made by the document itself,
  //   but appear like cross-site ones.
  //
  // * Otherwise, do not include same-site cookies.

  if (force_ignore_site_for_cookies)
    return CookieOptions::SameSiteCookieContext::MakeInclusive();

  ComputeSameSiteContextResult result = ComputeSameSiteContext(
      url_chain, site_for_cookies, initiator, true /* is_http */,
      is_main_frame_navigation, false /* compute_schemefully */);
  ComputeSameSiteContextResult schemeful_result = ComputeSameSiteContext(
      url_chain, site_for_cookies, initiator, true /* is_http */,
      is_main_frame_navigation, true /* compute_schemefully */);

  // If the method is safe, the context is Lax. Otherwise, make a note that
  // the method is unsafe.
  if (!net::HttpUtil::IsMethodSafe(http_method)) {
    if (result.context_type == ContextType::SAME_SITE_LAX)
      result.context_type = ContextType::SAME_SITE_LAX_METHOD_UNSAFE;
    if (schemeful_result.context_type == ContextType::SAME_SITE_LAX)
      schemeful_result.context_type = ContextType::SAME_SITE_LAX_METHOD_UNSAFE;
  }

  ContextMetadata::HttpMethod http_method_enum =
      HttpMethodStringToEnum(http_method);

  if (result.metadata.cross_site_redirect_downgrade !=
      ContextMetadata::ContextDowngradeType::kNoDowngrade) {
    result.metadata.http_method_bug_1221316 = http_method_enum;
  }

  if (schemeful_result.metadata.cross_site_redirect_downgrade !=
      ContextMetadata::ContextDowngradeType::kNoDowngrade) {
    schemeful_result.metadata.http_method_bug_1221316 = http_method_enum;
  }

  return MakeSameSiteCookieContext(result, schemeful_result);
}

NET_EXPORT CookieOptions::SameSiteCookieContext
ComputeSameSiteContextForScriptGet(const GURL& url,
                                   const SiteForCookies& site_for_cookies,
                                   const std::optional<url::Origin>& initiator,
                                   bool force_ignore_site_for_cookies) {
  if (force_ignore_site_for_cookies)
    return CookieOptions::SameSiteCookieContext::MakeInclusive();

  // We don't check the redirect chain for script access to cookies (only the
  // URL itself).
  ComputeSameSiteContextResult result = ComputeSameSiteContext(
      {url}, site_for_cookies, initiator, false /* is_http */,
      false /* is_main_frame_navigation */, false /* compute_schemefully */);
  ComputeSameSiteContextResult schemeful_result = ComputeSameSiteContext(
      {url}, site_for_cookies, initiator, false /* is_http */,
      false /* is_main_frame_navigation */, true /* compute_schemefully */);

  return MakeSameSiteCookieContext(result, schemeful_result);
}

CookieOptions::SameSiteCookieContext ComputeSameSiteContextForResponse(
    const std::vector<GURL>& url_chain,
    const SiteForCookies& site_for_cookies,
    const std::optional<url::Origin>& initiator,
    bool is_main_frame_navigation,
    bool force_ignore_site_for_cookies) {
  if (force_ignore_site_for_cookies)
    return CookieOptions::SameSiteCookieContext::MakeInclusiveForSet();

  DCHECK(!url_chain.empty());
  if (is_main_frame_navigation && !site_for_cookies.IsNull()) {
    // If the request is a main frame navigation, site_for_cookies must either
    // be null (for opaque origins, e.g., data: origins) or same-site with the
    // request URL (both schemefully and schemelessly), and the URL cannot be
    // ws/wss (these schemes are not navigable).
    DCHECK(
        site_for_cookies.IsFirstPartyWithSchemefulMode(url_chain.back(), true));
    DCHECK(!url_chain.back().SchemeIsWSOrWSS());
    CookieOptions::SameSiteCookieContext result =
        CookieOptions::SameSiteCookieContext::MakeInclusiveForSet();

    const GURL& request_url = url_chain.back();

    for (bool compute_schemefully : {false, true}) {
      bool same_site_initiator =
          !initiator ||
          SiteForCookies::FromOrigin(initiator.value())
              .IsFirstPartyWithSchemefulMode(request_url, compute_schemefully);

      const auto is_same_site_with_site_for_cookies =
          [&site_for_cookies, compute_schemefully](const GURL& url) {
            return site_for_cookies.IsFirstPartyWithSchemefulMode(
                url, compute_schemefully);
          };

      bool same_site_redirect_chain =
          url_chain.size() == 1u ||
          base::ranges::all_of(url_chain, is_same_site_with_site_for_cookies);

      CookieOptions::SameSiteCookieContext::ContextMetadata& result_metadata =
          compute_schemefully ? result.schemeful_metadata() : result.metadata();

      result_metadata.redirect_type_bug_1221316 =
          ComputeContextRedirectTypeBug1221316(
              url_chain.size() == 1u, same_site_initiator,
              true /* site_for_cookies_is_same_site */,
              same_site_redirect_chain);
    }
    return result;
  }

  return ComputeSameSiteContextForSet(url_chain, site_for_cookies, initiator,
                                      true /* is_http */,
                                      is_main_frame_navigation);
}

CookieOptions::SameSiteCookieContext ComputeSameSiteContextForScriptSet(
    const GURL& url,
    const SiteForCookies& site_for_cookies,
    bool force_ignore_site_for_cookies) {
  if (force_ignore_site_for_cookies)
    return CookieOptions::SameSiteCookieContext::MakeInclusiveForSet();

  // It doesn't matter what initiator origin we pass here. Either way, the
  // context will be considered same-site iff the site_for_cookies is same-site
  // with the url. We don't check the redirect chain for script access to
  // cookies (only the URL itself).
  return ComputeSameSiteContextForSet(
      {url}, site_for_cookies, std::nullopt /* initiator */,
      false /* is_http */, false /* is_main_frame_navigation */);
}

CookieOptions::SameSiteCookieContext ComputeSameSiteContextForSubresource(
    const GURL& url,
    const SiteForCookies& site_for_cookies,
    bool force_ignore_site_for_cookies) {
  if (force_ignore_site_for_cookies)
    return CookieOptions::SameSiteCookieContext::MakeInclusive();

  // If the URL is same-site as site_for_cookies it's same-site as all frames
  // in the tree from the initiator frame up --- including the initiator frame.

  // Schemeless check
  if (!site_for_cookies.IsFirstPartyWithSchemefulMode(url, false)) {
    return CookieOptions::SameSiteCookieContext(ContextType::CROSS_SITE,
                                                ContextType::CROSS_SITE);
  }

  // Schemeful check
  if (!site_for_cookies.IsFirstPartyWithSchemefulMode(url, true)) {
    return CookieOptions::SameSiteCookieContext(ContextType::SAME_SITE_STRICT,
                                                ContextType::CROSS_SITE);
  }

  return CookieOptions::SameSiteCookieContext::MakeInclusive();
}

bool IsPortBoundCookiesEnabled() {
  return base::FeatureList::IsEnabled(features::kEnablePortBoundCookies);
}

bool IsSchemeBoundCookiesEnabled() {
  return base::FeatureList::IsEnabled(features::kEnableSchemeBoundCookies);
}

bool IsOriginBoundCookiesPartiallyEnabled() {
  return IsPortBoundCookiesEnabled() || IsSchemeBoundCookiesEnabled();
}

bool IsTimeLimitedInsecureCookiesEnabled() {
  return IsSchemeBoundCookiesEnabled() &&
         base::FeatureList::IsEnabled(features::kTimeLimitedInsecureCookies);
}

bool IsSchemefulSameSiteEnabled() {
  return base::FeatureList::IsEnabled(features::kSchemefulSameSite);
}

std::optional<
    std::pair<FirstPartySetMetadata, FirstPartySetsCacheFilter::MatchInfo>>
ComputeFirstPartySetMetadataMaybeAsync(
    const SchemefulSite& request_site,
    const IsolationInfo& isolation_info,
    const CookieAccessDelegate* cookie_access_delegate,
    base::OnceCallback<void(FirstPartySetMetadata,
                            FirstPartySetsCacheFilter::MatchInfo)> callback) {
  if (cookie_access_delegate) {
    return cookie_access_delegate->ComputeFirstPartySetMetadataMaybeAsync(
        request_site,
        base::OptionalToPtr(
            isolation_info.network_isolation_key().GetTopFrameSite()),
        std::move(callback));
  }

  return std::pair(FirstPartySetMetadata(),
                   FirstPartySetsCacheFilter::MatchInfo());
}

CookieOptions::SameSiteCookieContext::ContextMetadata::HttpMethod
HttpMethodStringToEnum(const std::string& in) {
  using HttpMethod =
      CookieOptions::SameSiteCookieContext::ContextMetadata::HttpMethod;
  if (in == "GET")
    return HttpMethod::kGet;
  if (in == "HEAD")
    return HttpMethod::kHead;
  if (in == "POST")
    return HttpMethod::kPost;
  if (in == "PUT")
    return HttpMethod::KPut;
  if (in == "DELETE")
    return HttpMethod::kDelete;
  if (in == "CONNECT")
    return HttpMethod::kConnect;
  if (in == "OPTIONS")
    return HttpMethod::kOptions;
  if (in == "TRACE")
    return HttpMethod::kTrace;
  if (in == "PATCH")
    return HttpMethod::kPatch;

  return HttpMethod::kUnknown;
}

bool IsCookieAccessResultInclude(CookieAccessResult cookie_access_result) {
  return cookie_access_result.status.IsInclude();
}

CookieList StripAccessResults(
    const CookieAccessResultList& cookie_access_results_list) {
  CookieList cookies;
  for (const CookieWithAccessResult& cookie_with_access_result :
       cookie_access_results_list) {
    cookies.push_back(cookie_with_access_result.cookie);
  }
  return cookies;
}

NET_EXPORT void RecordCookiePortOmniboxHistograms(const GURL& url) {
  int port = url.EffectiveIntPort();

  if (port == url::PORT_UNSPECIFIED)
    return;

  if (IsLocalhost(url)) {
    UMA_HISTOGRAM_ENUMERATION("Cookie.Port.OmniboxURLNavigation.Localhost",
                              ReducePortRangeForCookieHistogram(port));
  } else {
    UMA_HISTOGRAM_ENUMERATION("Cookie.Port.OmniboxURLNavigation.RemoteHost",
                              ReducePortRangeForCookieHistogram(port));
  }
}

NET_EXPORT void DCheckIncludedAndExcludedCookieLists(
    const CookieAccessResultList& included_cookies,
    const CookieAccessResultList& excluded_cookies) {
  // Check that all elements of `included_cookies` really should be included,
  // and that all elements of `excluded_cookies` really should be excluded.
  DCHECK(base::ranges::all_of(included_cookies,
                              [](const net::CookieWithAccessResult& cookie) {
                                return cookie.access_result.status.IsInclude();
                              }));
  DCHECK(base::ranges::none_of(excluded_cookies,
                               [](const net::CookieWithAccessResult& cookie) {
                                 return cookie.access_result.status.IsInclude();
                               }));

  // Check that the included cookies are still in the correct order.
  DCHECK(
      base::ranges::is_sorted(included_cookies, CookieWithAccessResultSorter));
}

NET_EXPORT bool IsForceThirdPartyCookieBlockingEnabled() {
  return base::FeatureList::IsEnabled(
             features::kForceThirdPartyCookieBlocking) &&
         base::FeatureList::IsEnabled(features::kThirdPartyStoragePartitioning);
}

bool PartitionedCookiesDisabledByCommandLine() {
  const base::CommandLine* command_line =
      base::CommandLine::ForCurrentProcess();
  if (!command_line) {
    return false;
  }
  return command_line->HasSwitch(kDisablePartitionedCookiesSwitch);
}

void AddOrRemoveStorageAccessApiOverride(
    const GURL& url,
    StorageAccessApiStatus api_status,
    base::optional_ref<const url::Origin> request_initiator,
    CookieSettingOverrides& overrides) {
  overrides.PutOrRemove(
      CookieSettingOverride::kStorageAccessGrantEligible,
      api_status == StorageAccessApiStatus::kAccessViaAPI &&
          request_initiator.has_value() &&
          IsSameSiteIgnoringWebSocketProtocol(request_initiator.value(), url));
}

}  // namespace net::cookie_util

"""


```