Response:
The user is asking for a summary of the functionality of the provided C++ code snippet from `document_loader.cc`. I need to identify the key actions and responsibilities of the `DocumentLoader` class based on the given code. Specifically, I should look for interactions with JavaScript, HTML, and CSS, logical reasoning within the code, potential user errors, and steps leading to this code execution.

**Part 4 Summary Plan:**

1. **Identify Core Functions:**  Analyze the code to pinpoint the main actions performed in this segment. Keywords like `CommitLoad`, `CalculateOwnerFrame`, `CalculateOrigin`, `InitializeWindow`, `CommitNavigation` are strong indicators.
2. **Relate to Web Technologies:** Look for connections to JavaScript, HTML, and CSS. This might involve observing how the code handles security origins, policies (like CSP), and interacts with the DOM (`Frame`, `Document`, `LocalDOMWindow`).
3. **Analyze Logic and Reasoning:** Examine conditional statements and algorithms. Look for assumptions and the relationship between inputs and outputs.
4. **Identify Potential User Errors:**  Consider how incorrect user actions or website configurations could lead to issues handled by this code (e.g., cache control headers, security policy violations).
5. **Trace User Actions:**  Infer the sequence of user interactions that might result in the execution of this specific part of the `DocumentLoader`'s logic (e.g., navigating to a new page, reloading).
6. **Summarize Functionality (Part 4 Specific):**  Focus on the actions happening within the provided code block, especially around committing the navigation, calculating the owner frame, determining the security origin, initializing the window, and the initial steps of committing the navigation.
这是 `blink/renderer/core/loader/document_loader.cc` 文件的第四部分，主要涵盖了 `DocumentLoader` 在完成资源加载后，提交导航以及初始化新文档和窗口的关键步骤。以下是其功能的归纳：

**主要功能归纳:**

* **`CommitLoad()`:**  在资源加载完成后被调用，执行提交加载的关键步骤。
    * **处理缓存控制指令:** 检查响应头中的 `Cache-Control: no-cache` 和 `Cache-Control: no-store`，并向 `FrameScheduler` 注册相应的粘性特性，以禁用后退/前进缓存。这与 **HTTP 缓存机制** 有关。
    * **重置字体性能计数器:** 如果是主框架且文档需要标记字体性能，则重置全局的字体性能计数器。这涉及到 **浏览器性能监控**。
    * **恢复子资源加载:**  通知框架恢复子资源的加载。这与 **HTML 中引用的图片、CSS、JavaScript 等资源的加载** 有关。
    * **设置交互检测器起始时间:**  如果存在交互检测器，则设置其导航开始时间。这与 **用户交互和页面加载性能监控** 有关。
    * **触发 DevTools 时间线事件:** 发送 "CommitLoad" 事件到开发者工具，用于性能分析。这与 **浏览器开发者工具** 有关。
    * **调用探针和页面提交加载方法:** 通知探针和页面加载已提交。这涉及到 **Chromium 内部的监控和钩子机制**。

* **`CalculateOwnerFrame()`:** 计算当前文档的所有者框架。这主要用于确定诸如 `about:blank` 和 `about:srcdoc` 这类特殊 URL 的上下文。
    * **`about:srcdoc`:** 所有者是父框架。
    * **`about:blank` 和初始空文档:**  所有者是父框架或打开它的框架 (opener)。
    * **`about:blank` 的特殊处理:**  需要额外的检查来确保所有者是实际的导航发起者，特别是需要验证发起者的源 ( `requestor_origin_` ) 与潜在所有者的源是否相同。 这与 **HTML 的跨域安全模型** 有关，特别是 `about:blank` 页面的源继承规则。
    * **假设输入与输出:**
        * **输入:**  `url_` 为 "about:blank"，当前框架有父框架且父框架的源与 `requestor_origin_` 相同。
        * **输出:** 父框架指针。
        * **输入:** `url_` 为 "about:blank"，但 `requestor_origin_` 为空（浏览器发起的导航）。
        * **输出:** `nullptr`。

* **`CalculateOrigin()`:** 计算新文档的安全源 (SecurityOrigin)。这是浏览器安全模型的核心部分，决定了脚本的权限和跨域访问策略。
    * **处理 Web 测试中的弹窗:**  在 LayoutTests 中，确保弹窗使用其所有者的安全源，以便测试可以访问。
    * **优先从所有者文档获取:** 如果存在所有者文档，则优先从其获取安全源，这样可以正确继承和别名 `document.domain`。这与 **JavaScript 的 `document.domain` 属性和跨域访问控制** 有关。
    * **使用 `origin_to_commit_`:** 如果浏览器进程指定了要提交的源，则直接使用该源。
    * **根据 URL 创建:**  否则，根据当前 URL 和请求者的源 ( `requestor_origin_` ) 创建新的安全源。
    * **处理沙箱 (Sandbox) 属性:** 如果文档需要沙箱化，则创建一个新的不透明源。这与 **HTML 的 `<iframe>` 标签的 `sandbox` 属性** 有关。
    * **处理特殊权限:** 根据设置（例如禁用 Web 安全、允许文件 URL 的通用访问），授予安全源额外的权限。
    * **假设输入与输出:**
        * **假设输入:**  `url_` 为 "https://example.com/page.html"，没有 `owner_document`，没有 `origin_to_commit_`，`requestor_origin_` 为 "https://another.com"。
        * **输出:**  一个表示 "https://example.com" 的安全源对象。
        * **假设输入:** `url_` 为 "about:blank"，`owner_document` 指向一个源为 "https://parent.com" 的文档。
        * **输出:** 指向 "https://parent.com" 安全源的指针（可能会是别名）。

* **`ShouldReuseDOMWindow()`:** 决定是否可以重用现有的 `LocalDOMWindow` 对象。
    * **匿名性匹配:** 只有当窗口的匿名性 (credentialless) 与新的策略容器匹配时才能重用。
    * **初始空文档:** 只有从初始空文档发起的导航才能重用窗口。
    * **源匹配:** 新的源必须能够访问初始空文档的源。 这与 **浏览器窗口的生命周期管理和安全上下文切换** 有关。

* **`InitializeWindow()`:** 初始化或重用 `LocalDOMWindow` 对象。
    * **处理策略容器 (PolicyContainer):**  获取或继承策略容器，每个窗口都必须有一个策略容器。策略容器包含了 CSP、Feature Policy 等安全策略信息。这与 **浏览器安全策略** 有关，包括 **Content Security Policy (CSP)** 和 **Feature Policy**。
    * **创建内容安全策略 (CSP) 对象:**  为新文档创建 `ContentSecurityPolicy` 对象。
    * **计算安全源:** 调用 `CalculateOrigin()` 来确定新窗口的安全源。
    * **获取或创建 WindowAgent:**  根据安全源和是否启用 Origin-keyed Agent Clusters (OAC) 获取或创建一个 `WindowAgent`。 `WindowAgent` 负责管理特定源的全局 JavaScript 执行环境。
    * **设置 `LocalDOMWindow` 的属性:**  设置窗口的 `StorageAccessApiStatus`，关联策略容器和内容安全策略。
    * **设置存储键 (StorageKey):**  根据安全源设置窗口的存储键，用于隔离不同源的存储。
    * **设置安全上下文 (SecurityContext):**  将计算出的安全源设置到窗口的安全上下文中。
    * **处理 Origin Trials:** 从响应头中提取 Origin Trial token 并添加到窗口中。这与 **浏览器实验性特性支持** 有关。
    * **继承不安全请求策略:** 从父框架继承不安全请求策略。
    * **处理 `Referrer-Policy` 头:** 解析并设置 `Referrer-Policy` 头。这与 **HTTP Referer 头部的隐私和安全控制** 有关。

* **`CommitNavigation()` (第二部分):**  提交导航的后续步骤。
    * **应用运行时特性覆盖:**  应用从浏览器进程传递过来的运行时特性覆盖设置。这与 **浏览器配置和实验性功能** 有关。
    * **重置相同文档导航任务:**  重置与之前相同文档导航相关的任务。
    * **可能在后台开始加载 Body:**  如果适用，启动在后台加载文档 Body 的过程。这与 **页面加载优化** 有关。
    * **记录非安全私有地址空间导航:**  如果是最外层主框架，且导航到一个非安全的私有 IP 地址，则记录该行为。
    * **初始化安全上下文:** 使用 `SecurityContextInit` 对象初始化安全上下文，例如应用权限策略 (Permissions Policy) 和文档策略 (Document Policy)。 这与 **浏览器安全策略** 有关。
    * **处理 JavaScript URL、XSLT 提交和丢弃的文档:**  这些情况下，会从之前的窗口继承权限策略和文档策略，因为 `response_` 中不再包含相应的头信息。这与 **JavaScript 执行、XSLT 处理以及浏览器内部的文档管理** 有关。
    * **应用权限策略和文档策略:**  解析响应头中的 `Permissions-Policy` 和 `Document-Policy` 并应用到安全上下文中。这与 **浏览器安全策略** 有关。

**与 JavaScript, HTML, CSS 的关系举例:**

* **JavaScript:**
    * `CalculateOrigin()` 决定了 JavaScript 代码的执行权限和跨域访问能力。例如，如果两个页面源不同，浏览器会阻止一个页面中的 JavaScript 代码访问另一个页面的 `document` 对象，这与 `CalculateOrigin()` 的计算结果密切相关。
    * `InitializeWindow()` 中设置的 `ContentSecurityPolicy` 会限制页面中 JavaScript 的执行方式，例如禁止执行内联脚本或只允许加载特定来源的脚本。
* **HTML:**
    * `CalculateOwnerFrame()` 影响 `<iframe>` 标签的上下文，特别是对于 `about:blank` 和 `about:srcdoc` 这样的特殊页面。
    * `InitializeWindow()` 处理的策略容器和安全源与 HTML 中定义的安全策略（如 `<meta>` 标签中的 CSP）以及 `<iframe>` 标签的 `sandbox` 属性有关。
* **CSS:**
    * `CommitLoad()` 中处理的 `Cache-Control` 头会影响浏览器对 CSS 文件的缓存行为。
    * `InitializeWindow()` 中设置的 `ContentSecurityPolicy` 可能会限制 CSS 的加载来源或禁止使用某些 CSS 特性。

**用户或编程常见的使用错误举例:**

* **缓存配置错误:** 网站开发者可能错误地配置了 `Cache-Control` 头，导致浏览器过度缓存或不缓存资源，影响用户体验。例如，错误地设置了 `Cache-Control: no-cache` 或 `Cache-Control: no-store` 可能会导致每次访问都重新请求资源。
* **CSP 配置错误:**  开发者可能配置了过于严格或错误的 CSP，导致页面中的 JavaScript 或 CSS 无法正常加载或执行，从而破坏页面功能。例如，忘记允许加载 CDN 上的 JavaScript 库。
* **`document.domain` 使用不当:**  在跨域场景下，不正确地使用 `document.domain` 可能会导致安全漏洞或跨域访问失败。`CalculateOrigin()` 中对源的计算直接影响了 `document.domain` 的行为。
* **`<iframe>` 沙箱属性配置错误:**  开发者可能没有正确地配置 `<iframe>` 标签的 `sandbox` 属性，导致安全风险或功能受限。`CalculateOrigin()` 中会考虑沙箱属性来创建安全源。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在浏览器地址栏输入 URL 或点击链接:** 这会触发一次导航。
2. **浏览器进程发起网络请求:**  浏览器会根据 URL 创建网络请求。
3. **接收到响应头:**  服务器返回响应头，其中可能包含 `Cache-Control`, `Referrer-Policy`, `Permissions-Policy`, `Document-Policy` 等信息。
4. **Blink 渲染引擎创建 `DocumentLoader`:**  当需要加载新的文档时，渲染引擎会创建 `DocumentLoader` 对象来处理加载过程。
5. **资源加载完成:**  `DocumentLoader` 负责下载 HTML 资源。
6. **调用 `CommitLoad()`:**  在 HTML 资源加载完成后，`CommitLoad()` 方法被调用，开始提交加载过程。
7. **根据 URL 类型 (如 `about:blank`) 或上下文调用 `CalculateOwnerFrame()`:**  确定所有者框架。
8. **根据各种因素 (如所有者框架、策略容器等) 调用 `CalculateOrigin()`:** 计算新文档的安全源。
9. **调用 `InitializeWindow()`:**  初始化或重用 `LocalDOMWindow` 对象，并设置安全策略等。
10. **调用 `CommitNavigation()`:**  执行提交导航的剩余步骤，包括应用安全策略等。

总而言之，这段代码是 Chromium Blink 引擎中处理页面导航和文档初始化的核心部分，它负责确保页面的安全性和正确加载，并与浏览器的缓存机制、安全策略以及 JavaScript、HTML、CSS 等技术紧密相关。

### 提示词
```
这是目录为blink/renderer/core/loader/document_loader.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
FrameScheduler::NavigationType::kReload
          : FrameScheduler::NavigationType::kOther,
      {previous_document_unreported_task_time});

  if (response_.CacheControlContainsNoCache()) {
    GetFrame()->GetFrameScheduler()->RegisterStickyFeature(
        SchedulingPolicy::Feature::kMainResourceHasCacheControlNoCache,
        {SchedulingPolicy::DisableBackForwardCache()});
  }
  if (response_.CacheControlContainsNoStore()) {
    GetFrame()->GetFrameScheduler()->RegisterStickyFeature(
        SchedulingPolicy::Feature::kMainResourceHasCacheControlNoStore,
        {SchedulingPolicy::DisableBackForwardCache()});
  }

  // Reset the global |FontPerformance| counter.
  if (GetFrame()->IsMainFrame() &&
      GetFrame()->GetDocument()->ShouldMarkFontPerformance())
    FontPerformance::Reset();

  // When a new navigation commits in the frame, subresource loading should be
  // resumed.
  frame_->ResumeSubresourceLoading();

  Document* document = frame_->GetDocument();
  InteractiveDetector* interactive_detector =
      InteractiveDetector::From(*document);
  if (interactive_detector)
    interactive_detector->SetNavigationStartTime(GetTiming().NavigationStart());

  DEVTOOLS_TIMELINE_TRACE_EVENT("CommitLoad", inspector_commit_load_event::Data,
                                frame_);

  // Needs to run before dispatching preloads, as it may evict the memory cache.
  probe::DidCommitLoad(frame_, this);

  frame_->GetPage()->DidCommitLoad(frame_);
}

Frame* DocumentLoader::CalculateOwnerFrame() {
  // For "about:srcdoc", the parent is the owner frame.
  if (url_.IsAboutSrcdocURL())
    return frame_->Tree().Parent();

  // Consider the parent or the opener for 1) about:blank" (including
  // "about:mumble" - see https://crbug.com/1220186) and 2) the initial empty
  // document (with an empty `url_`)..
  DCHECK(url_.ProtocolIsAbout() || url_.IsEmpty()) << "url_ = " << url_;
  Frame* owner_frame = frame_->Tree().Parent();
  if (!owner_frame)
    owner_frame = frame_->Opener();

  // No other checks are needed for the initial empty document.
  if (url_.IsEmpty())
    return owner_frame;

  // For about:blank the owner frame should be the actual initiator/requestor of
  // the navigation - see:
  // https://html.spec.whatwg.org/multipage/browsers.html#determining-the-origin
  //
  // This requires a few extra checks below.
  DCHECK(url_.ProtocolIsAbout()) << "url_ = " << url_;

  // Browser-initiated navigations to about:blank should always commit with an
  // opaque origin (i.e. they should not inherit the origin and other properties
  // of the `owner_frame`).
  if (!requestor_origin_)
    return nullptr;

  // The parent-or-owner heuristic above might not find the actual initiator of
  // the navigation (e.g. see the SameSiteSiblingToAboutBlank_CrossSiteTop
  // testcase).  To limit (but not eliminate :-/) incorrect cases we require
  // that `owner_frame`'s origin is same origin with `requestor_origin_`.
  //
  // TODO(https://crbug.com/1176291): Improve heuristics for finding the
  // correct initiator, to properly inherit/alias `document.domain` in more
  // cases.
  if (owner_frame &&
      owner_frame->GetSecurityContext()->GetSecurityOrigin()->IsSameOriginWith(
          requestor_origin_.get())) {
    return owner_frame;
  } else {
    return nullptr;
  }
}

scoped_refptr<SecurityOrigin> DocumentLoader::CalculateOrigin(
    Document* owner_document) {
  scoped_refptr<SecurityOrigin> origin;
  StringBuilder debug_info_builder;
  // Whether the origin is newly created within this call, instead of copied
  // from an existing document's origin or from `origin_to_commit_`. If this is
  // true, we won't try to compare the nonce of this origin (if it's opaque) to
  // the browser-calculated origin later on.
  bool origin_is_newly_created = false;
  if (IsPagePopupRunningInWebTest(frame_)) {
    // If we are a page popup in LayoutTests ensure we use the popup
    // owner's security origin so the tests can possibly access the
    // document via internals API.
    auto* owner_context = frame_->PagePopupOwner()->GetExecutionContext();
    origin = owner_context->GetSecurityOrigin()->IsolatedCopy();
    debug_info_builder.Append("use_popup_owner_origin");
  } else if (owner_document && owner_document->domWindow()) {
    // Prefer taking `origin` from `owner_document` if one is available - this
    // will correctly inherit/alias `SecurityOrigin::domain_` from the
    // `owner_document` (note that the
    // `SecurityOrigin::CreateWithReferenceOrigin` fallback below A) doesn't
    // preserve `domain_` via `url::Origin` and B) doesn't alias the origin /
    // `domain_` - changes in the "about:blank" document do not affect the
    // initiator document).
    //
    // TODO(dcheng): if we're aliasing an origin, do we need to go through any
    // of the other checks below? This seems like it could have potentially
    // surprising side effects: for example, if the web security setting toggle
    // is disabled, this will affect the owner document's origin too...
    //
    // TODO(dcheng): maybe FrameLoader::Init() should specify origin_to_commit_?
    // But origin_to_commit_ is currently cloned with IsolatedCopy() which
    // breaks aliasing...
    origin = owner_document->domWindow()->GetMutableSecurityOrigin();
    debug_info_builder.Append("use_owner_document_origin(");
    // Add debug information about the owner document too.
    if (owner_document->GetFrame() == frame_->Tree().Parent()) {
      debug_info_builder.Append("parent");
    } else {
      debug_info_builder.Append("opener");
    }
    debug_info_builder.Append(":");
    debug_info_builder.Append(
        owner_document->Loader()->origin_calculation_debug_info_);
    debug_info_builder.Append(", url=");
    debug_info_builder.Append(owner_document->Url().BaseAsString());
    debug_info_builder.Append(")");
  } else if (origin_to_commit_) {
    // Origin to commit is specified by the browser process, it must be taken
    // and used directly. An exception is when the owner origin should be
    // inherited in the cases above, since we want to also inherit renderer-only
    // information such as document.domain value. This is OK because the
    // non-renderer only origin bits will be the same, which will be asserted at
    // the end of this function.
    origin = origin_to_commit_;
    debug_info_builder.Append("use_origin_to_commit");
  } else {
    debug_info_builder.Append("use_url_with_precursor");
    // Otherwise, create an origin that propagates precursor information
    // as needed. For non-opaque origins, this creates a standard tuple
    // origin, but for opaque origins, it creates an origin with the
    // initiator origin as the precursor.
    origin = SecurityOrigin::CreateWithReferenceOrigin(url_,
                                                       requestor_origin_.get());
    origin_is_newly_created = true;
  }

  if ((policy_container_->GetPolicies().sandbox_flags &
       network::mojom::blink::WebSandboxFlags::kOrigin) !=
      network::mojom::blink::WebSandboxFlags::kNone) {
    debug_info_builder.Append(", add_sandbox[new_origin_precursor=");
    // If `origin_to_commit_` is set, don't create a new opaque origin, but just
    // use `origin_to_commit_`, which is already opaque.
    auto sandbox_origin =
        origin_to_commit_ ? origin_to_commit_ : origin->DeriveNewOpaqueOrigin();
    CHECK(sandbox_origin->IsOpaque());
    debug_info_builder.Append(
        sandbox_origin->GetOriginOrPrecursorOriginIfOpaque()->ToString());
    debug_info_builder.Append("]");

    // If we're supposed to inherit our security origin from our
    // owner, but we're also sandboxed, the only things we inherit are
    // the origin's potential trustworthiness and the ability to
    // load local resources. The latter lets about:blank iframes in
    // file:// URL documents load images and other resources from
    // the file system.
    //
    // Note: Sandboxed about:srcdoc iframe without "allow-same-origin" aren't
    // allowed to load user's file, even if its parent can.
    if (url_.IsAboutSrcdocURL()) {
      // We should only have a sandboxed, srcdoc frame without an owner
      // document if isolated-sandboxed-iframes is enabled. Only cases that
      // would normally inherit the origin need to be handled here, and a
      // sandboxed about:blank document won't be moved out of process. Also,
      // data: urls don't get secure contexts, so needn't be considered here.
      CHECK(owner_document ||
            base::FeatureList::IsEnabled(features::kIsolateSandboxedIframes));

      bool is_potentially_trustworthy =
          origin->GetOriginOrPrecursorOriginIfOpaque()
              ->IsPotentiallyTrustworthy();
      if (is_potentially_trustworthy) {
        sandbox_origin->SetOpaqueOriginIsPotentiallyTrustworthy(true);
        debug_info_builder.Append(", _potentially_trustworthy");
      }
    } else if (owner_document) {
      if (origin->IsPotentiallyTrustworthy()) {
        sandbox_origin->SetOpaqueOriginIsPotentiallyTrustworthy(true);
        debug_info_builder.Append(", _potentially_trustworthy");
      }
      if (origin->CanLoadLocalResources()) {
        sandbox_origin->GrantLoadLocalResources();
        debug_info_builder.Append(", _load_local");
      }
    }
    origin = sandbox_origin;
    origin_is_newly_created = !origin_to_commit_;
  }

  if (commit_reason_ == CommitReason::kInitialization &&
      frame_->GetSettings()->GetShouldReuseGlobalForUnownedMainFrame() &&
      !frame_->Parent() && !frame_->Opener()) {
    // For legacy reasons, grant universal access to a top-level initial empty
    // Document in Android WebView. This allows the WebView embedder to inject
    // arbitrary script into about:blank and have it persist when the frame is
    // navigated.
    CHECK(origin->IsOpaque());
    origin->GrantUniversalAccess();
    debug_info_builder.Append(", universal_access_webview");
  } else if (!frame_->GetSettings()->GetWebSecurityEnabled()) {
    // Web security is turned off. We should let this document access
    // every other document. This is used primary by testing harnesses for
    // web sites.
    origin->GrantUniversalAccess();
    debug_info_builder.Append(", universal_access_no_web_security");
  } else if (origin->IsLocal()) {
    if (frame_->GetSettings()->GetAllowUniversalAccessFromFileURLs()) {
      // Some clients want local URLs to have universal access, but that
      // setting is dangerous for other clients.
      origin->GrantUniversalAccess();
      debug_info_builder.Append(", universal_access_allow_file");
    } else if (!frame_->GetSettings()->GetAllowFileAccessFromFileURLs()) {
      // Some clients do not want local URLs to have access to other local
      // URLs.
      origin->BlockLocalAccessFromLocalOrigin();
      if (origin_to_commit_) {
        // This information does not exist on `origin_to_commit_` as it comes
        // from the browser side. To make sure the `IsSameOriginWith()` check
        // at the end of the function will pass, also block access for
        // `origin_to_commit_`.
        origin_to_commit_->BlockLocalAccessFromLocalOrigin();
      }
      debug_info_builder.Append(", universal_access_block_file");
    }
  }

  if (grant_load_local_resources_) {
    origin->GrantLoadLocalResources();
    debug_info_builder.Append(", grant_load_local_resources");
  }

  if (origin->IsOpaque()) {
    KURL url = url_.IsEmpty() ? BlankURL() : url_;
    if (SecurityOrigin::Create(url)->IsPotentiallyTrustworthy()) {
      origin->SetOpaqueOriginIsPotentiallyTrustworthy(true);
      debug_info_builder.Append(", is_potentially_trustworthy");
    }
  }
  if (origin_is_newly_created) {
    // This information will be used by the browser side to figure out if it can
    // do browser vs renderer calculated origin equality check. Note that this
    // information must be the last part of the debug info string.
    // TODO(https://crbug.com/888079): Consider adding a separate boolean that
    // tracks this instead of piggybacking `origin_calculation_debug_info_`.
    debug_info_builder.Append(", is_newly_created");
  }
  origin_calculation_debug_info_ = debug_info_builder.ToAtomicString();
  if (origin_to_commit_) {
    SCOPED_CRASH_KEY_STRING256("OriginCalc", "debug_info",
                               origin_calculation_debug_info_.Ascii());
    SCOPED_CRASH_KEY_STRING256("OriginCalc", "url_stripped",
                               url_.StrippedForUseAsReferrer().Ascii());
    SCOPED_CRASH_KEY_BOOL("OriginCalc", "same_ptr",
                          origin == origin_to_commit_);
    SCOPED_CRASH_KEY_STRING256("OriginCalc", "origin",
                               origin->ToString().Ascii());
    SCOPED_CRASH_KEY_STRING256("OriginCalc", "origin_to_commit",
                               origin_to_commit_->ToString().Ascii());
    SCOPED_CRASH_KEY_BOOL("OriginCalc", "origin_local", origin->IsLocal());
    SCOPED_CRASH_KEY_BOOL("OriginCalc", "origin_to_commit_local",
                          origin_to_commit_->IsLocal());
    SCOPED_CRASH_KEY_BOOL("OriginCalc", "origin_opaque", origin->IsOpaque());
    SCOPED_CRASH_KEY_BOOL("OriginCalc", "origin_to_commit_opaque",
                          origin_to_commit_->IsOpaque());
    SCOPED_CRASH_KEY_BOOL("OriginCalc", "origin_block",
                          origin->block_local_access_from_local_origin());
    SCOPED_CRASH_KEY_BOOL(
        "OriginCalc", "origin_to_commit_block",
        origin_to_commit_->block_local_access_from_local_origin());
    if (origin->IsLocal() && !origin->IsOpaque() &&
        origin->block_local_access_from_local_origin() &&
        origin != origin_to_commit_) {
      // For local non-opaque origins that block local access, we can't use the
      // IsSameOrigin check directly if the ptr is not the same (e.g. when the
      // origin is inherited from the owner, instead of using
      // `origin_to_commit_`), since the blocking will apply within that check.
      // Instead, check that all the important properties are the same.
      CHECK(owner_document && owner_document->domWindow());
      CHECK(origin_to_commit_->IsLocal());
      CHECK(!origin_to_commit_->IsOpaque());
      CHECK(origin_to_commit_->block_local_access_from_local_origin());
      CHECK_EQ(origin->Protocol(), origin_to_commit_->Protocol());
      CHECK_EQ(origin->Host(), origin_to_commit_->Host());
      CHECK_EQ(origin->Domain(), origin_to_commit_->Domain());
    } else {
      CHECK(origin->IsSameOriginWith(origin_to_commit_.get()));
    }
  }
  return origin;
}

bool ShouldReuseDOMWindow(LocalDOMWindow* window,
                          SecurityOrigin* security_origin,
                          bool window_anonymous_matching) {
  if (!window) {
    return false;
  }

  // Anonymous is tracked per-Window, so if it does not match, do not reuse it.
  if (!window_anonymous_matching) {
    return false;
  }

  // Only navigations from the initial empty document can reuse the window.
  if (!window->document()->IsInitialEmptyDocument()) {
    return false;
  }

  // The new origin must match the origin of the initial empty document.
  return window->GetSecurityOrigin()->CanAccess(security_origin);
}

namespace {

bool HasPotentialUniversalAccessPrivilege(LocalFrame* frame) {
  return !frame->GetSettings()->GetWebSecurityEnabled() ||
         frame->GetSettings()->GetAllowUniversalAccessFromFileURLs();
}

}  // namespace

WindowAgent* GetWindowAgentForOrigin(
    LocalFrame* frame,
    SecurityOrigin* origin,
    bool is_origin_agent_cluster,
    bool origin_agent_cluster_left_as_default) {
  // TODO(keishi): Also check if AllowUniversalAccessFromFileURLs might
  // dynamically change.
  return frame->window_agent_factory().GetAgentForOrigin(
      HasPotentialUniversalAccessPrivilege(frame), origin,
      is_origin_agent_cluster, origin_agent_cluster_left_as_default);
}

// Inheriting cases use their agent's "is origin-keyed" value, which is set
// by whatever they're inheriting from.
//
// javascript: URLs use the calling page as their Url() value, so we need to
// include them explicitly.
//
// Discarded pages retain their Url() value so must be included explicitly.
bool ShouldInheritExplicitOriginKeying(const KURL& url, CommitReason reason) {
  return Document::ShouldInheritSecurityOriginFromOwner(url) ||
         reason == CommitReason::kJavascriptUrl ||
         reason == CommitReason::kDiscard;
}

bool DocumentLoader::IsSameOriginInitiator() const {
  return requestor_origin_ &&
         requestor_origin_->IsSameOriginWith(
             SecurityOrigin::Create(Url()).get()) &&
         Url().ProtocolIsInHTTPFamily();
}

void DocumentLoader::InitializeWindow(Document* owner_document) {
  TRACE_EVENT_WITH_FLOW0("loading", "DocumentLoader::InitializeWindow",
                         TRACE_ID_LOCAL(this),
                         TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT);
  // Javascript URLs, XSLT committed document and discarded documents must not
  // pass a new policy_container_, since they must keep the previous document
  // one.
  DCHECK((!IsJavaScriptURLOrXSLTCommitOrDiscard()) || !policy_container_);

  bool did_have_policy_container = (policy_container_ != nullptr);

  // The old window's PolicyContainer must be accessed before being potentially
  // extracted below.
  const bool old_window_is_credentialless =
      frame_->DomWindow() && frame_->DomWindow()
                                 ->GetPolicyContainer()
                                 ->GetPolicies()
                                 .is_credentialless;

  // DocumentLoader::InitializeWindow is called either on FrameLoader::Init or
  // on FrameLoader::CommitNavigation. FrameLoader::Init always initializes a
  // non null |policy_container_|. If |policy_container_| is null, this is
  // committing a navigation without a policy container. This can happen in a
  // few circumstances:
  // 1. for a javascript or a xslt document,
  // 2. when loading html in a page for testing,
  // 3. this is the synchronous navigation to 'about:blank'.
  // (On the other side notice that all navigations committed by the browser
  // have a non null |policy_container_|). In all the cases 1-3 above, we should
  // keep the PolicyContainer of the previous document (since the browser does
  // not know about this and is not changing the RenderFrameHost's
  // PolicyContainerHost).
  if (frame_->DomWindow() && !policy_container_) {
    policy_container_ = frame_->DomWindow()->TakePolicyContainer();
  }

  // Every window must have a policy container.
  DCHECK(policy_container_);

  const bool window_anonymous_matching =
      old_window_is_credentialless ==
      policy_container_->GetPolicies().is_credentialless;

  ContentSecurityPolicy* csp = CreateCSP();

  scoped_refptr<SecurityOrigin> security_origin;
  if (frame_->IsProvisional()) {
    // Provisional frames shouldn't be doing anything other than act as a
    // placeholder. Enforce a strict sandbox and ensure a unique opaque origin.
    // TODO(dcheng): Actually enforce strict sandbox flags for provisional
    // frame. For some reason, doing so breaks some random devtools tests.
    security_origin = SecurityOrigin::CreateUniqueOpaque();
  } else if (IsJavaScriptURLOrXSLTCommitOrDiscard()) {
    // For javascript: URL, XSLT commits and discarded documents which don't go
    // through the browser process and reuses the same DocumentLoader, reuse the
    // previous origin.
    // TODO(dcheng): Is it a problem that the previous origin is copied with
    // isolated copy? This probably has observable side effects (e.g. executing
    // a javascript: URL in an about:blank frame that inherited an origin will
    // cause the origin to no longer be aliased).
    security_origin = frame_->DomWindow()->GetSecurityOrigin()->IsolatedCopy();
  } else {
    security_origin = CalculateOrigin(owner_document);
  }

  bool origin_agent_cluster = origin_agent_cluster_;
  // Note: this code must be kept in sync with
  // WindowAgentFactory::GetAgentForOrigin(), as the two conditions below hand
  // out universal WindowAgent objects, and thus override OAC.
  if (HasPotentialUniversalAccessPrivilege(frame_.Get()) ||
      security_origin->IsLocal()) {
    // In this case we either have AllowUniversalAccessFromFileURLs enabled, or
    // WebSecurity is disabled, or it's a local scheme such as file://; any of
    // these cases forces us to use a common WindowAgent for all origins, so
    // don't attempt to use OriginAgentCluster. Note:
    // AllowUniversalAccessFromFileURLs is deprecated as of Android R, so
    // eventually this use case will diminish.
    origin_agent_cluster = false;
  } else if (ShouldInheritExplicitOriginKeying(Url(), commit_reason_) &&
             owner_document && owner_document->domWindow()) {
    // Since we're inheriting the owner document's origin, we should also use
    // its OriginAgentCluster (OAC) in determining which WindowAgent to use,
    // overriding the OAC value sent in the commit params. For example, when
    // about:blank is loaded, it has OAC = false, but if we have an owner, then
    // we are using the owner's SecurityOrigin, we should match the OAC value
    // also. JavaScript URLs also use their owner's SecurityOrigins, and don't
    // set OAC as part of their commit params.
    // TODO(wjmaclean,domenic): we're currently verifying that the OAC
    // inheritance is correct for both XSLT documents and non-initial
    // about:blank cases. Given the relationship between OAC, SecurityOrigin,
    // and COOP/COEP, a single inheritance pathway would make sense; this work
    // is being tracked in https://crbug.com/1183935.
    origin_agent_cluster =
        owner_document->domWindow()->GetAgent()->IsOriginKeyedForInheritance();
  }

  bool inherited_has_storage_access = false;
  // In some rare cases, we'll re-use a LocalDOMWindow for a new Document. For
  // example, when a script calls window.open("..."), the browser gives
  // JavaScript a window synchronously but kicks off the load in the window
  // asynchronously. Web sites expect that modifications that they make to the
  // window object synchronously won't be blown away when the network load
  // commits. To make that happen, we "securely transition" the existing
  // LocalDOMWindow to the Document that results from the network load. See also
  // Document::IsSecureTransitionTo.
  if (!ShouldReuseDOMWindow(frame_->DomWindow(), security_origin.get(),
                            window_anonymous_matching)) {
    auto* agent = GetWindowAgentForOrigin(
        frame_.Get(), security_origin.get(), origin_agent_cluster,
        origin_agent_cluster_left_as_default_);
    frame_->SetDOMWindow(MakeGarbageCollected<LocalDOMWindow>(*frame_, agent));

    // TODO(https://crbug.com/1111897): This call is likely to happen happen
    // multiple times per agent, since navigations can happen multiple times per
    // agent. This is subpar.
    if (!ShouldInheritExplicitOriginKeying(Url(), commit_reason_) &&
        origin_agent_cluster) {
      agent->ForceOriginKeyedBecauseOfInheritance();
    }

    frame_->DomWindow()->SetStorageAccessApiStatus(storage_access_api_status_);
    inherited_has_storage_access = [this]() -> bool {
      switch (storage_access_api_status_) {
        case net::StorageAccessApiStatus::kNone:
          return false;
        case net::StorageAccessApiStatus::kAccessViaAPI:
          return true;
      }
      NOTREACHED();
    }();
  } else {
    if (frame_->GetSettings()->GetShouldReuseGlobalForUnownedMainFrame() &&
        frame_->IsMainFrame()) {
      // When GetShouldReuseGlobalForUnownedMainFrame() causes a main frame's
      // window to be reused, we should not inherit the initial empty document's
      // Agent, which was a universal access Agent.
      // This happens only in android webview.
      frame_->DomWindow()->ResetWindowAgent(GetWindowAgentForOrigin(
          frame_.Get(), security_origin.get(), origin_agent_cluster,
          origin_agent_cluster_left_as_default_));
    }
    frame_->DomWindow()->ClearForReuse();

    // If one of the two following things is true:
    // 1. JS called window.open(), Blink created a new auxiliary browsing
    //    context, and the target URL is resolved to 'about:blank'.
    // 2. A new iframe is attached, and the target URL is resolved to
    //    'about:blank'.
    // then Blink immediately synchronously navigates to about:blank after
    // creating the new browsing context and has initialized it with the initial
    // empty document. In those cases, we must not pass a PolicyContainer, as
    // this does not trigger a corresponding browser-side navigation, and we
    // must reuse the PolicyContainer.
    //
    // TODO(antoniosartori): Improve this DCHECK to match exactly the condition
    // above.
    DCHECK(did_have_policy_container || WillLoadUrlAsEmpty(Url()));
  }

  if (initial_permission_statuses_ &&
      RuntimeEnabledFeatures::PermissionElementEnabled(
          frame_->DomWindow()->GetExecutionContext())) {
    CachedPermissionStatus::From(frame_->DomWindow())
        ->SetPermissionStatusMap(
            std::move(initial_permission_statuses_).value());
  }

  content_security_notifier_ =
      HeapMojoRemote<mojom::blink::ContentSecurityNotifier>(
          frame_->DomWindow());

  base::UmaHistogramBoolean("API.StorageAccess.DocumentLoadedWithStorageAccess",
                            [this]() -> bool {
                              switch (storage_access_api_status_) {
                                case net::StorageAccessApiStatus::kNone:
                                  return false;
                                case net::StorageAccessApiStatus::kAccessViaAPI:
                                  return true;
                              }
                              NOTREACHED();
                            }());
  base::UmaHistogramBoolean("API.StorageAccess.DocumentInheritedStorageAccess",
                            inherited_has_storage_access);

  frame_->DomWindow()->SetPolicyContainer(std::move(policy_container_));
  frame_->DomWindow()->SetContentSecurityPolicy(csp);

  BlinkStorageKey storage_key(storage_key_);
  // TODO(crbug.com/1199077): For some reason `storage_key_` is occasionally
  // null. If that's the case this will create one based on the
  // `security_origin`.
  // TODO(crbug.com/1199077): Some tests (potentially other code?) rely on an
  // opaque origin + nonce. Investigate whether this combination should be
  // disallowed.
  if (storage_key.GetSecurityOrigin()->IsOpaque() && !storage_key.GetNonce()) {
    storage_key = BlinkStorageKey::CreateFirstParty(security_origin);
  }

  // Now that we have the final window and Agent, ensure the security origin has
  // the appropriate agent cluster id. This may derive a new security origin.
  security_origin = security_origin->GetOriginForAgentCluster(
      frame_->DomWindow()->GetAgent()->cluster_id());

  // TODO(https://crbug.com/888079): Just use the storage key sent by the
  // browser once the browser will be able to compute the origin in all cases.
  frame_->DomWindow()->SetStorageKey(storage_key.WithOrigin(security_origin));

  // Conceptually, SecurityOrigin doesn't have to be initialized after sandbox
  // flags are applied, but there's a UseCounter in SetSecurityOrigin() that
  // wants to inspect sandbox flags.
  SecurityContext& security_context = frame_->DomWindow()->GetSecurityContext();
  security_context.SetSecurityOrigin(std::move(security_origin));
  // Requires SecurityOrigin to be initialized.
  OriginTrialContext::AddTokensFromHeader(
      frame_->DomWindow(), response_.HttpHeaderField(http_names::kOriginTrial));

  if (auto* parent = frame_->Tree().Parent()) {
    const SecurityContext* parent_context = parent->GetSecurityContext();
    security_context.SetInsecureRequestPolicy(
        parent_context->GetInsecureRequestPolicy());
    for (auto to_upgrade : parent_context->InsecureNavigationsToUpgrade())
      security_context.AddInsecureNavigationUpgrade(to_upgrade);
  }

  String referrer_policy_header =
      response_.HttpHeaderField(http_names::kReferrerPolicy);
  if (!referrer_policy_header.IsNull()) {
    CountUse(WebFeature::kReferrerPolicyHeader);
    frame_->DomWindow()->ParseAndSetReferrerPolicy(referrer_policy_header,
                                                   kPolicySourceHttpHeader);
  }
}

void DocumentLoader::CommitNavigation() {
  TRACE_EVENT_WITH_FLOW0("loading", "DocumentLoader::CommitNavigation",
                         TRACE_ID_LOCAL(this),
                         TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT);
  base::ScopedUmaHistogramTimer histogram_timer(
      "Navigation.DocumentLoader.CommitNavigation");
  base::ElapsedTimer timer;
  DCHECK_LT(state_, kCommitted);
  DCHECK(frame_->GetPage());
  DCHECK(!frame_->GetDocument() || !frame_->GetDocument()->IsActive());
  DCHECK_EQ(frame_->Tree().ChildCount(), 0u);
  DCHECK(!frame_->GetDocument() ||
         frame_->GetDocument()->ConnectedSubframeCount() == 0);
  state_ = kCommitted;

  // Prepare a DocumentInit before clearing the frame, because it may need to
  // inherit an aliased security context.
  Document* owner_document = nullptr;

  // Calculate `owner_document` from which the committing navigation should
  // inherit the cookie URL and inherit/alias the SecurityOrigin.
  if (Document::ShouldInheritSecurityOriginFromOwner(Url())) {
    Frame* owner_frame = CalculateOwnerFrame();
    if (auto* owner_local_frame = DynamicTo<LocalFrame>(owner_frame))
      owner_document = owner_local_frame->GetDocument();
  }

  LocalDOMWindow* previous_window = frame_->DomWindow();
  InitializeWindow(owner_document);

  frame_->DomWindow()
      ->GetRuntimeFeatureStateOverrideContext()
      ->ApplyOverrideValuesFromParams(modified_runtime_features_);

  // Previous same-document navigation tasks are not relevant once a
  // cross-document navigation has happened.
  if (auto* tracker = scheduler::TaskAttributionTracker::From(
          frame_->DomWindow()->GetIsolate())) {
    tracker->ResetSameDocumentNavigationTasks();
  }

  MaybeStartLoadingBodyInBackground(body_loader_.get(), frame_, url_,
                                    response_);

  // Record if we have navigated to a non-secure page served from a IP address
  // in the private address space.
  //
  // Use response_.AddressSpace() instead of frame_->DomWindow()->AddressSpace()
  // since the latter isn't populated in unit tests.
  if (frame_->IsOutermostMainFrame()) {
    auto address_space = response_.AddressSpace();
    if ((address_space == network::mojom::blink::IPAddressSpace::kPrivate ||
         address_space == network::mojom::blink::IPAddressSpace::kLocal) &&
        !frame_->DomWindow()->IsSecureContext()) {
      CountUse(WebFeature::kMainFrameNonSecurePrivateAddressSpace);
    }
  }

  SecurityContextInit security_init(frame_->DomWindow());

  // The document constructed by XSLTProcessor and ScriptController should
  // inherit Permissions Policy and Document Policy from the previous Document.
  // Note: In XSLT commit, JavaScript commit and discard commit, |response_| no
  // longer holds header fields. Going through regular initialization will cause
  // empty policy even if there is header on xml document.
  if (IsJavaScriptURLOrXSLTCommitOrDiscard()) {
    DCHECK(response_.HttpHeaderField(http_names::kFeaturePolicy).empty());
    DCHECK(response_.HttpHeaderField(http_names::kPermissionsPolicy).empty());
    DCHECK(response_.HttpHeaderField(http_names::kDocumentPolicy).empty());
    security_init.InitPermissionsPolicyFrom(
        previous_window->GetSecurityContext());
    security_init.InitDocumentPolicyFrom(previous_window->GetSecurityContext());
  } else {
    // PermissionsPolicy and DocumentPolicy require SecurityOrigin and origin
    // trials to be initialized.
    // TODO(iclelland): Add Permissions-Policy-Report-Only to Origin Policy.
    security_init.ApplyPermissionsPolicy(
        *frame_.Get(), response_, frame_policy_, initial_permissions_policy_,
        FencedFrameProperties());

    // |document_policy_| is parsed in document loader because it is
    // compared with |frame_policy.required_document_policy| to decide
    // whether to block the document load or not.
    // |report_only_document_policy| does not block the page load. Its
    // initialization is delayed to
    // SecurityContextInit::InitializeDocumentPolicy(), similar to
    // |report_only_permissions_policy|.
    security_init.ApplyDocumentPolicy(
        document_policy_,
        response_.HttpHeaderField(http_names::k
```