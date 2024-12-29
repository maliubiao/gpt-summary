Response:
My thought process for analyzing the provided code snippet and generating the response goes through these stages:

1. **Understanding the Goal:** The primary goal is to analyze the functionality of the given C++ code snippet from Chromium's Blink rendering engine, specifically the `FrameLoader::BeginNavigation` and `FrameLoader::CommitNavigation` methods, and relate it to web technologies (JavaScript, HTML, CSS). The request also asks for examples, error scenarios, debugging tips, and a summary.

2. **Initial Code Scan and Keyword Identification:** I quickly scanned the code for important keywords and function calls. Things that jumped out were:
    * `BeginNavigation`, `CommitNavigation` - These are clearly central to the navigation process.
    * `ResourceRequest`, `WebNavigationParams` -  Represent data associated with navigation.
    * `URL`, `KURL` - Obvious connection to web addresses.
    * `javascript:`, `ProcessJavaScriptUrl` - Directly relates to JavaScript.
    * `DocumentLoader` - Manages the loading of documents.
    * `SecurityOrigin`, `CSP` (Content Security Policy) - Security-related aspects.
    * `Frame`, `LocalFrame` - Indicate the context of the code (frame management).
    * `NavigationPolicy`, `NavigationType` - Different ways a navigation can occur.
    * `HTMLFrameOwnerElement` -  Specifically about iframe elements.
    * `DispatchNavigateEvent` - Event handling related to navigation.
    * `V8DOMActivityLogger` -  Debugging and logging related to V8 (JavaScript engine).
    * `MHTMLArchive` - Handling of archived web pages.
    * `PluginData` - Dealing with browser plugins.
    * `HistoryItem` - Browser history management.
    * `ScrollPosition`, `ViewState` - Managing scroll and view state during navigation.

3. **Focusing on Key Methods:** I recognized `BeginNavigation` and `CommitNavigation` as the core methods being examined in this code portion. I decided to analyze each separately first.

4. **Deconstructing `BeginNavigation`:** I stepped through the `BeginNavigation` code, commenting mentally on what each part does:
    * Setting up `ResourceRequest`:  This involves gathering information about the request like the URL, HTTP method, headers, and navigation type.
    * Handling `javascript:` URLs:  A special case for executing JavaScript directly within the page. This immediately flags a connection to JavaScript.
    * Dispatching `NavigateEvent`:  Newer API for handling navigation events in JavaScript.
    * Logging and instrumentation: Using `V8DOMActivityLogger` and `probe::FrameRequestedNavigation` for debugging and monitoring.
    * Security checks: Involving CSP and IDNA deviation warnings.
    * Calling `Client()->BeginNavigation()`: The final step, initiating the navigation process with the browser.

5. **Deconstructing `CommitNavigation`:** I repeated the process for `CommitNavigation`:
    * Early exit conditions: Checking if navigation is allowed.
    * Starting body loading (potentially):  Handling how the page content is loaded.
    * Canceling provisional loaders: Managing concurrent navigation attempts.
    * Handling static responses (e.g., from MHTML archives or `about:blank`):  Special cases for pre-rendered or simple content.
    * Assertions:  Checks to ensure the navigation is valid.
    * Detaching the old document: Cleaning up the previous page.
    * Swapping in the new frame (if it's provisional).
    * Creating and committing the `DocumentLoader`: The core action of loading the new document.
    * Restoring scroll position and view state.

6. **Identifying Relationships with Web Technologies:** As I analyzed each step, I specifically looked for connections to JavaScript, HTML, and CSS:
    * **JavaScript:** Obvious with `javascript:` URLs, `ProcessJavaScriptUrl`, `DispatchNavigateEvent`, `V8DOMActivityLogger`, and the mentions of script execution being forbidden in certain scenarios.
    * **HTML:** Implied by the entire navigation process, but specifically mentioned with `HTMLFrameOwnerElement` (iframes), the handling of `about:srcdoc`, and the default HTML content provided for error cases.
    * **CSS:** Less direct in this specific snippet, but I recognized that navigation ultimately leads to rendering and styling, thus CSS is implicitly involved. The restoration of `ViewState` can include scroll positions which are influenced by layout and thus indirectly by CSS.

7. **Generating Examples and Scenarios:** Based on my understanding, I devised examples for:
    * JavaScript navigation (`javascript:alert('hello')`).
    * HTML navigation (clicking a link, submitting a form).
    * CSS (less direct, but considered how layout affects scroll restoration).
    * User errors (incorrect URLs, CSP violations).
    * Debugging (logging, breakpoints).

8. **Structuring the Output:** I organized the information into the requested categories: main functionalities, relationships with web technologies (with examples), logical inferences, common user errors, debugging clues, and a summary. I used clear headings and bullet points for readability.

9. **Refining and Reviewing:** I reread my analysis and examples to ensure accuracy, clarity, and completeness. I made sure the examples were concise and illustrative. I checked that the summary accurately captured the essence of the code's function. I made sure to address all parts of the prompt.

This iterative process of scanning, focusing, deconstructing, connecting, and structuring allowed me to create a comprehensive and informative response to the request. The key was breaking down the code into smaller, understandable parts and then building up the connections to the broader web technology landscape.
这是提供的 `blink/renderer/core/loader/frame_loader.cc` 文件代码的第二部分，主要涵盖了 `FrameLoader::BeginNavigation` 和 `FrameLoader::CommitNavigation` 两个核心方法以及一些辅助方法。

**功能归纳:**

这部分代码主要负责处理 **导航的开始和提交** 过程。  具体来说，它：

* **`BeginNavigation`:**  处理启动一个新的导航请求。它会收集导航所需的信息，进行各种检查（例如 JavaScript URL），并最终调用底层的浏览器接口来真正开始加载。
* **`CommitNavigation`:** 当浏览器告知渲染器可以提交导航时被调用。它负责实际的页面切换，包括卸载旧文档，加载新文档，并更新浏览器历史记录。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

1. **JavaScript:**

   * **功能关系:**  `BeginNavigation` 中会专门处理 `javascript:` 协议的 URL。它会检查安全性和执行上下文，并在合适的时机调用 `frame_->GetDocument()->ProcessJavaScriptUrl()` 来执行 JavaScript 代码。
   * **举例:**
      * **假设输入:** 用户在地址栏输入 `javascript:alert('Hello from JavaScript!')` 并回车。
      * **处理过程:** `BeginNavigation` 会识别出 `javascript:` 协议，检查当前帧是否允许执行脚本，然后调用 JavaScript 引擎执行 `alert('Hello from JavaScript!')`。
      * **用户操作:** 用户直接在地址栏输入或点击一个 `href="javascript:..."` 的链接。

   * **功能关系:**  `BeginNavigation` 中会处理 `NavigateEvent` 的派发。这是一个新的 Web API，允许 JavaScript 代码拦截和自定义导航行为。
   * **举例:**
      * **假设输入:** 页面中有一个 JavaScript 监听了 `navigate` 事件，并且调用了 `event.preventDefault()`。
      * **处理过程:** 当用户点击一个链接时，`BeginNavigation` 会创建并派发 `NavigateEvent`。如果事件被阻止，`BeginNavigation` 会提前返回，取消导航。
      * **用户操作:** 用户点击了一个链接，但页面上的 JavaScript 代码阻止了默认的导航行为。

2. **HTML:**

   * **功能关系:** `BeginNavigation` 中会处理包含换行符的 URL。虽然这种做法不推荐，但代码会检测并记录这种用法。
   * **举例:**
      * **假设输入:** HTML 中存在一个链接 `<a href="http://example.com/page
        with
        newline">Link</a>`。
      * **处理过程:** 当用户点击这个链接时，`BeginNavigation` 会检测到 URL 中包含换行符，并记录一个废弃警告。
      * **用户操作:**  开发者在 HTML 中使用了包含换行符的 URL。

   * **功能关系:** `CommitNavigation` 会处理 `about:srcdoc` 类型的 URL，这种 URL 的内容直接来源于 iframe 的 `srcdoc` 属性。
   * **举例:**
      * **假设输入:** HTML 中有一个 iframe `<iframe srcdoc="<h1>Hello from srcdoc!</h1>"></iframe>`。
      * **处理过程:** 当浏览器请求加载这个 iframe 时，`CommitNavigation` 会使用 `srcdoc` 属性的内容来创建文档。
      * **用户操作:** 开发者在 HTML 中使用了 `srcdoc` 属性来定义 iframe 的内容。

   * **功能关系:** `CommitNavigation` 中会处理 MHTML 归档文件，允许从归档文件中加载资源。
   * **举例:**
      * **假设输入:** 页面加载了一个 MHTML 归档文件，其中包含了其他 HTML 页面和资源。
      * **处理过程:** 当页面尝试导航到归档文件中的一个内部 URL 时，`CommitNavigation` 会从归档文件中提取相应的资源并加载。
      * **用户操作:** 用户加载了一个包含其他网页的 MHTML 文件，并点击了文件内部的链接。

3. **CSS:**

   * **功能关系:** 虽然这段代码没有直接处理 CSS 的解析或应用，但 `CommitNavigation` 中涉及到 `RestoreScrollPositionAndViewState()`，这与页面的滚动位置和视图状态有关，而这些状态最终会受到 CSS 的影响。
   * **举例:**
      * **假设输入:** 用户浏览了一个页面并滚动到页面的底部，然后点击了一个链接返回到该页面。
      * **处理过程:** `CommitNavigation` 中的 `RestoreScrollPositionAndViewState()` 会尝试恢复用户之前的滚动位置。这个滚动位置是基于之前页面的布局和 CSS 样式计算出来的。
      * **用户操作:** 用户在浏览器中进行前进/后退操作，或者通过历史记录导航。

**逻辑推理的假设输入与输出:**

* **假设输入 (针对 `BeginNavigation` 中的 JavaScript URL 处理):**
    * `url`:  `KURL("javascript:void(0)")`
    * `request.GetNavigationPolicy()`: `kNavigationPolicyCurrentTab`
    * `origin_window->CanExecuteScripts(kAboutToExecuteScript)`: `true`
* **输出:**
    * 调用 `frame_->GetDocument()->ProcessJavaScriptUrl(url, request.JavascriptWorld())`。

* **假设输入 (针对 `BeginNavigation` 中的 `NavigateEvent` 处理):**
    * `request.GetNavigationPolicy()`: `kNavigationPolicyCurrentTab`
    * `origin_window` 的文档中存在一个 `navigate` 事件监听器，并且该监听器返回 `NavigationApi::DispatchResult::kContinue`。
* **输出:**
    * 继续执行 `BeginNavigation` 的后续流程。

**涉及用户或者编程常见的使用错误及举例说明:**

1. **用户错误：在 URL 中输入未转义的换行符。**
   * **举例:** 用户尝试复制粘贴包含换行符的 URL 到地址栏。
   * **后果:**  虽然代码会尝试处理，但这通常不是预期的行为，并且可能会导致 URL 解析错误或安全问题。浏览器可能会尝试自动修复 URL，但也可能导致加载失败。

2. **编程错误：在 JavaScript 中使用 `javascript:` URL 进行跨帧导航，但目标帧的安全上下文不允许执行脚本。**
   * **举例:** 一个页面中的 iframe 的 `sandbox` 属性禁止了脚本执行，而父页面尝试通过 `location.href = 'javascript:...';` 来操作 iframe。
   * **后果:** `BeginNavigation` 会检查目标帧的脚本执行权限，如果被禁止，JavaScript 代码将不会被执行，导航可能不会发生或行为不符合预期。

3. **编程错误：依赖于在 unload 事件处理程序中启动新的导航。**
   * **举例:** 在一个页面的 `window.onunload` 函数中，尝试修改 `window.location.href` 来跳转到另一个页面。
   * **后果:** 代码中使用了 `FrameNavigationDisabler` 来阻止在卸载过程中启动新的导航，以避免潜在的问题和不确定性。这种尝试启动的导航可能会被忽略或导致意外行为。

**用户操作如何一步步的到达这里，作为调试线索:**

* **到达 `BeginNavigation` 的步骤:**
    1. **用户在地址栏输入 URL 并回车。**
    2. **用户点击页面上的一个链接 (`<a>` 标签)。**
    3. **用户提交一个表单 (`<form>`)。**
    4. **页面上的 JavaScript 代码执行了 `window.location.href = '...'` 或类似的操作。**
    5. **浏览器处理书签或历史记录导航。**
    6. **iframe 中的页面尝试导航。**

* **到达 `CommitNavigation` 的步骤:**
    1. **以上 `BeginNavigation` 的步骤之一发生。**
    2. **浏览器进程接收到渲染器进程发送的导航请求。**
    3. **浏览器进程进行必要的处理（例如，网络请求，安全检查）。**
    4. **浏览器进程确定可以提交导航，并向渲染器进程发送提交导航的指令。**
    5. **渲染器进程接收到提交指令，并调用 `CommitNavigation`。**

**调试线索:**

* **在 `BeginNavigation` 的入口处设置断点，** 可以查看导航请求的 URL、导航类型、发起者等信息，判断导航是否按预期启动。
* **检查 `request.GetNavigationPolicy()` 的值，** 了解导航是如何被触发的（例如，用户点击、脚本触发等）。
* **查看 `url.ProtocolIsJavaScript()` 的结果，** 判断是否是 JavaScript URL 导航。
* **在 `CommitNavigation` 的入口处设置断点，** 可以查看 `navigation_params` 中的响应信息，判断网络请求是否成功。
* **检查 `commit_reason` 的值，** 了解导航提交的原因（例如，常规导航、JavaScript URL、XSLT 等）。
* **利用 Chromium 的 tracing 工具 (chrome://tracing)** 可以查看更详细的导航过程，包括 `FrameLoader::BeginNavigation` 和 `FrameLoader::CommitNavigation` 的调用时机和相关参数。

总而言之，这段代码是 Blink 渲染引擎中处理页面导航的核心部分，它连接了用户操作、网络请求、安全策略以及 JavaScript 和 HTML 等 Web 技术，确保页面能够正确地加载和切换。

Prompt: 
```
这是目录为blink/renderer/core/loader/frame_loader.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能

"""
umentLoader()->ConsumeTextFragmentToken();

  resource_request.SetHasTextFragmentToken(text_fragment_token);

  WebNavigationType navigation_type = DetermineNavigationType(
      frame_load_type, resource_request.HttpBody() || request.Form(),
      request.GetTriggeringEventInfo() !=
          mojom::blink::TriggeringEventInfo::kNotFromEvent);
  mojom::blink::RequestContextType request_context_type =
      DetermineRequestContextFromNavigationType(navigation_type);

  // TODO(lyf): handle `frame` context type. https://crbug.com/1019716
  if (mojom::blink::RequestContextType::LOCATION == request_context_type &&
      !frame_->IsMainFrame()) {
    request_context_type = mojom::blink::RequestContextType::IFRAME;
  }
  resource_request.SetRequestContext(request_context_type);
  resource_request.SetRequestDestination(
      DetermineRequestDestinationFromNavigationType(navigation_type));
  request.SetFrameType(frame_->IsMainFrame()
                           ? mojom::RequestContextFrameType::kTopLevel
                           : mojom::RequestContextFrameType::kNested);

  // TODO(arthursonzogni): 'frame-src' check is disabled on the
  // renderer side, but is enforced on the browser side.
  // See http://crbug.com/692595 for understanding why it
  // can't be enforced on both sides instead.

  // 'form-action' check in the frame that is navigating is disabled on the
  // renderer side, but is enforced on the browser side instead.
  // N.B. check in the frame that initiates the navigation stills occurs in
  // blink and is not enforced on the browser-side.
  // TODO(arthursonzogni) The 'form-action' check should be fully disabled
  // in blink, except when the form submission doesn't trigger a navigation
  // (i.e. javascript urls). Please see https://crbug.com/701749.

  // Report-only CSP headers are checked in browser.
  const FetchClientSettingsObject* fetch_client_settings_object = nullptr;
  if (origin_window) {
    fetch_client_settings_object = &origin_window->Fetcher()
                                        ->GetProperties()
                                        .GetFetchClientSettingsObject();
  }
  ModifyRequestForCSP(resource_request, fetch_client_settings_object,
                      origin_window, request.GetFrameType());

  DCHECK(Client()->HasWebView());
  // Check for non-escaped new lines in the url.
  if (url.PotentiallyDanglingMarkup() && url.ProtocolIsInHTTPFamily()) {
    Deprecation::CountDeprecation(
        origin_window, WebFeature::kCanRequestURLHTTPContainingNewline);
    return;
  }

  if (url.ProtocolIsJavaScript()) {
    // If the navigation policy does not target the current frame (for example,
    // a navigation initiated by Ctrl/Cmd+Click on an anchor element),
    // `FindOrCreateFrameForNavigation()` returns the initiator frame, expecting
    // the navigation to end up in the browser process so the browser process
    // can handle the navigation policy accordingly.
    //
    // However, before this navigation is sent to the browser process, Blink
    // checks if it's a javascript: URL, since that is always supposed to be
    // handled internally in the renderer. It is certainly not correct to
    // evaluate the javascript: URL in the initiator frame if the navigation is
    // not targeting the current frame.
    if (request.GetNavigationPolicy() == kNavigationPolicyCurrentTab) {
      if (!origin_window ||
          origin_window->CanExecuteScripts(kAboutToExecuteScript)) {
        if (origin_window &&
            request.GetFrameType() ==
                mojom::blink::RequestContextFrameType::kNested) {
          LogJavaScriptUrlHistogram(origin_window, url.GetPath());
        }

        frame_->GetDocument()->ProcessJavaScriptUrl(url,
                                                    request.JavascriptWorld());
      } else {
        // Any possible navigation policy that ends up creating a new browsing
        // context will create a browsing context with no opener relation. The
        // new browsing context will always be cross-origin because the new
        // window starts at the initial empty document—and since it does have an
        // opener, it will not inherit an origin and will have a new unique
        // opaque origin. It would be incorrect to execute the javascript: URL
        // in a cross-origin context, so intentionally do nothing.
      }
    }
    return;
  }
  // If kStandardCompliantNonSpecialSchemeURLParsing feature is enabled,
  // "javascript:" scheme URL can be a invalid URL. e.g. "javascript://a b".
  //
  // We shouldn't navigate to such an invalid "javascript:" scheme URL.
  //
  // See wpt/url/javascript-urls.window.js test for the standard compliant
  // behaviors.
  if (url::IsUsingStandardCompliantNonSpecialSchemeURLParsing() &&
      ProtocolIsJavaScript(url.GetString())) {
    DCHECK(!url.IsValid());
    return;
  }

  if (request.GetNavigationPolicy() == kNavigationPolicyCurrentTab &&
      (!origin_window || origin_window->GetSecurityOrigin()->CanAccess(
                             frame_->DomWindow()->GetSecurityOrigin()))) {
    auto* params = MakeGarbageCollected<NavigateEventDispatchParams>(
        url, NavigateEventType::kCrossDocument, frame_load_type);
    params->source_element = request.GetSourceElement();
    if (request.GetTriggeringEventInfo() ==
        mojom::blink::TriggeringEventInfo::kFromTrustedEvent) {
      params->involvement = UserNavigationInvolvement::kActivation;
    }
    if (frame_->DomWindow()->navigation()->DispatchNavigateEvent(params) !=
        NavigationApi::DispatchResult::kContinue) {
      return;
    }
  }

  if (frame_->IsMainFrame())
    LocalFrame::ConsumeTransientUserActivation(frame_);

  // The main resource request gets logged here, because V8DOMActivityLogger
  // is looked up based on the current v8::Context. When the request actually
  // begins, the v8::Context may no longer be on the stack.
  if (V8DOMActivityLogger* activity_logger =
          V8DOMActivityLogger::CurrentActivityLoggerIfIsolatedWorld(
              frame_->DomWindow()->GetIsolate())) {
    if (!DocumentLoader::WillLoadUrlAsEmpty(url)) {
      Vector<String> argv;
      argv.push_back("Main resource");
      argv.push_back(url.GetString());
      activity_logger->LogEvent(frame_->DomWindow(), "blinkRequestResource",
                                argv);
    }
  }

  probe::FrameRequestedNavigation(frame_.Get(), frame_.Get(), url,
                                  request.GetClientNavigationReason(),
                                  request.GetNavigationPolicy());

  // TODO(crbug.com/896041): Instead of just bypassing the CSP for navigations
  // from isolated world, ideally we should enforce the isolated world CSP by
  // plumbing the correct CSP to the browser.
  using CSPDisposition = network::mojom::CSPDisposition;
  CSPDisposition should_check_main_world_csp =
      ContentSecurityPolicy::ShouldBypassMainWorldDeprecated(
          request.JavascriptWorld())
          ? CSPDisposition::DO_NOT_CHECK
          : CSPDisposition::CHECK;

  // Warn if the resource URL's hostname contains IDNA deviation characters.
  // Only warn if the resource URL's origin is different than its requestor
  // (we don't want to warn for <img src="faß.de/image.img"> on faß.de).
  // TODO(crbug.com/1396475): Remove once Non-Transitional mode is shipped.
  if (url.HasIDNA2008DeviationCharacter() &&
      resource_request.RequestorOrigin() &&
      !resource_request.RequestorOrigin()->IsSameOriginWith(
          SecurityOrigin::Create(url).get())) {
    String message = GetConsoleWarningForIDNADeviationCharacters(url);
    if (!message.empty()) {
      request.GetOriginWindow()->AddConsoleMessage(
          MakeGarbageCollected<ConsoleMessage>(
              mojom::ConsoleMessageSource::kSecurity,
              mojom::ConsoleMessageLevel::kWarning, message));
      origin_window->CountUse(
          WebFeature::kIDNA2008DeviationCharacterInHostnameOfIFrame);
    }
  }

  Client()->BeginNavigation(
      resource_request, request.GetRequestorBaseURL(), request.GetFrameType(),
      origin_window, nullptr /* document_loader */, navigation_type,
      request.GetNavigationPolicy(), frame_load_type,
      request.ForceHistoryPush(),
      CalculateClientRedirectPolicy(
          request.GetClientNavigationReason(), frame_load_type,
          IsOnInitialEmptyDocument()) == ClientRedirectPolicy::kClientRedirect,
      request.IsUnfencedTopNavigation(), request.GetTriggeringEventInfo(),
      request.Form(), should_check_main_world_csp, request.GetBlobURLToken(),
      request.GetInputStartTime(), request.HrefTranslate().GetString(),
      request.Impression(), request.GetInitiatorFrameToken(),
      request.TakeSourceLocation(),
      request.TakeInitiatorNavigationStateKeepAliveHandle(),
      request.IsContainerInitiated(),
      request.GetWindowFeatures().explicit_opener);
}

static void FillStaticResponseIfNeeded(WebNavigationParams* params,
                                       LocalFrame* frame) {
  if (params->is_static_data)
    return;

  const KURL& url = params->url;
  // See WebNavigationParams for special case explanations.
  if (url.IsAboutSrcdocURL()) {
    CHECK(params->body_loader);
    // Originally, this branch was responsible for retrieving the value of the
    // srcdoc attribute and turning it into a body loader when committing a
    // navigation to about:srcdoc. To support out-of-process sandboxed iframes,
    // the value of the srcdoc attribute is now sent to the browser in
    // BeginNavigation, and the body loader should have already been created
    // by the time the browser asks the renderer to commit, like other
    // standard navigations.
    return;
  }

  MHTMLArchive* archive = nullptr;
  if (auto* parent = DynamicTo<LocalFrame>(frame->Tree().Parent()))
    archive = parent->Loader().GetDocumentLoader()->Archive();
  if (archive && !url.ProtocolIsData()) {
    // If we have an archive loaded in some ancestor frame, we should
    // retrieve document content from that archive. This is different from
    // loading an archive into this frame, which will be handled separately
    // once we load the body and parse it as an archive.
    params->body_loader.reset();
    ArchiveResource* archive_resource = archive->SubresourceForURL(url);
    if (archive_resource) {
      WebNavigationParams::FillStaticResponse(
          params, archive_resource->MimeType(),
          archive_resource->TextEncoding(), archive_resource->Data());
    } else {
      // The requested archive resource does not exist. In an ideal world, this
      // would commit as a failed navigation, but the browser doesn't know
      // anything about what resources are available in the archive. Just
      // synthesize an empty document so that something commits still.
      // TODO(https://crbug.com/1112965): remove these special cases by adding
      // an URLLoaderFactory implementation for MHTML archives.
      WebNavigationParams::FillStaticResponse(
          params, "text/html", "UTF-8",
          base::span_from_cstring(
              "<html><body>"
              "<!-- failed to find resource in MHTML archive -->"
              "</body></html>"));
    }
  }

  // Checking whether a URL would load as empty (e.g. about:blank) must be done
  // after checking for content with the corresponding URL in the MHTML archive,
  // since MHTML archives can define custom content to load for about:blank...
  //
  // Note that no static response needs to be filled here; instead, this is
  // synthesised later by `DocumentLoader::InitializeEmptyResponse()`.
  if (DocumentLoader::WillLoadUrlAsEmpty(params->url))
    return;

  const String& mime_type = params->response.MimeType();
  if (MIMETypeRegistry::IsSupportedMIMEType(mime_type))
    return;

  PluginData* plugin_data = frame->GetPluginData();
  if (!mime_type.empty() && plugin_data &&
      plugin_data->SupportsMimeType(mime_type)) {
    return;
  }

  // Typically, PlzNavigate checks that the MIME type can be handled on the
  // browser side before sending it to the renderer. However, there are rare
  // scenarios where it's possible for the renderer to send a commit request
  // with a MIME type the renderer cannot handle:
  //
  // - (hypothetical) some sort of race between enabling/disabling plugins
  //   and when it's checked by the navigation URL loader / handled in the
  //   renderer.
  // - mobile emulation disables plugins on the renderer side, but the browser
  //   navigation code is not aware of this.
  //
  // Similar to the missing archive resource case above, synthesise a resource
  // to commit.
  //
  // WebNavigationParams::FillStaticResponse() fills the response of |params|
  // using |params|'s |url| which is the initial URL even after redirections. So
  // updates the URL to the current URL before calling FillStaticResponse().
  params->url = params->response.CurrentRequestUrl();
  WebNavigationParams::FillStaticResponse(
      params, "text/html", "UTF-8",
      base::span_from_cstring(
          "<html><body>"
          "<!-- no enabled plugin supports this MIME type -->"
          "</body></html>"));
}

// The browser navigation code should never send a `CommitNavigation()` request
// that fails this check.
static void AssertCanNavigate(WebNavigationParams* params, LocalFrame* frame) {
  if (params->is_static_data)
    return;

  if (DocumentLoader::WillLoadUrlAsEmpty(params->url))
    return;

  int status_code = params->response.HttpStatusCode();
  // If the server sends 204 or 205, this means the server does not want to
  // replace the page contents. However, PlzNavigate should have handled it
  // browser-side and never sent a commit request to the renderer.
  if (status_code == 204 || status_code == 205)
    CHECK(false);

  // If the server attached a Content-Disposition indicating that the resource
  // is an attachment, this is actually a download. However, PlzNavigate should
  // have handled it browser-side and never sent a commit request to the
  // renderer.
  if (IsContentDispositionAttachment(
          params->response.HttpHeaderField(http_names::kContentDisposition))) {
    CHECK(false);
  }
}

void FrameLoader::CommitNavigation(
    std::unique_ptr<WebNavigationParams> navigation_params,
    std::unique_ptr<WebDocumentLoader::ExtraData> extra_data,
    CommitReason commit_reason) {
  TRACE_EVENT0("navigation", "FrameLoader::CommitNavigation");
  base::ScopedUmaHistogramTimer histogram_timer(
      "Navigation.FrameLoader.CommitNavigation");
  DCHECK(document_loader_);
  DCHECK(frame_->GetDocument());
  DCHECK(Client()->HasWebView());

  if (!frame_->IsNavigationAllowed() ||
      frame_->GetDocument()->PageDismissalEventBeingDispatched() !=
          Document::kNoDismissal) {
    // Any of the checks above should not be necessary.
    // Unfortunately, in the case of sync IPCs like print() there might be
    // reentrancy and, for example, frame detach happening.
    // See fast/loader/detach-while-printing.html for a repro.
    // TODO(https://crbug.com/862088): we should probably ignore print()
    // call in this case instead.
    return;
  }

  // The encoding may be inherited from the parent frame if the security context
  // allows it, but we don't have the frame's security context set up yet. In
  // this case avoid starting the body load since it requires the correct
  // encoding. We'll try again after the security context is set up in
  // DocumentLoader::CommitNavigation().
  const ResourceResponse& response =
      navigation_params->response.ToResourceResponse();
  if (!response.TextEncodingName().empty() ||
      !IsA<LocalFrame>(frame_->Tree().Parent())) {
    DocumentLoader::MaybeStartLoadingBodyInBackground(
        navigation_params->body_loader.get(), frame_.Get(),
        navigation_params->url, response);
  }

  // TODO(dgozman): figure out the better place for this check
  // to cancel lazy load both on start and commit. Perhaps
  // CancelProvisionalLoaderForNewNavigation() is a good one.
  HTMLFrameOwnerElement* frame_owner = frame_->DeprecatedLocalOwner();
  if (frame_owner)
    frame_owner->CancelPendingLazyLoad();

  // Note: we might actually classify this navigation as same document
  // right here in the following circumstances:
  // - the loader has already committed a navigation and notified the browser
  //   process which did not receive a message about that just yet;
  // - meanwhile, the browser process sent us a command to commit this new
  //   "cross-document" navigation, while it's actually same-document
  //   with regards to the last commit.
  // In this rare case, we intentionally proceed as cross-document.

  if (!CancelProvisionalLoaderForNewNavigation())
    return;

  FillStaticResponseIfNeeded(navigation_params.get(), frame_);
  AssertCanNavigate(navigation_params.get(), frame_);

  // If this is a javascript: URL, XSLT commit or discard we must copy the
  // ExtraData from the previous DocumentLoader to ensure the new DocumentLoader
  // behaves the same way as the previous one.
  if (commit_reason == CommitReason::kXSLT ||
      commit_reason == CommitReason::kJavascriptUrl ||
      commit_reason == CommitReason::kDiscard) {
    // It is important to clone the previous loader's ExtraData instead of
    // extracting it since it may be needed to handle operations in the
    // document's unload handler (such as same-site navigation, see
    // crbug.com/361658816).
    DCHECK(!extra_data);
    extra_data = document_loader_->CloneExtraData();
  }

  // Create the OldDocumentInfoForCommit for the old document (that might be in
  // another FrameLoader) and save it in ScopedOldDocumentInfoForCommitCapturer,
  // so that the old document can access it and fill in the information as it
  // is being unloaded/swapped out.
  auto url_origin = SecurityOrigin::Create(navigation_params->url);
  ScopedOldDocumentInfoForCommitCapturer scoped_old_document_info(
      MakeGarbageCollected<OldDocumentInfoForCommit>(url_origin));

  FrameSwapScope frame_swap_scope(frame_owner);
  {
    base::AutoReset<bool> scoped_committing(&committing_navigation_, true);

    progress_tracker_->ProgressStarted();
    // In DocumentLoader, the matching DidCommitLoad messages are only called
    // for kRegular commits. Skip them here, too, to ensure we match
    // start/commit message pairs.
    if (commit_reason == CommitReason::kRegular) {
      frame_->GetFrameScheduler()->DidStartProvisionalLoad();
      probe::DidStartProvisionalLoad(frame_.Get());
    }

    DCHECK(Client()->HasWebView());

    // If `frame_` is provisional, `DetachDocument()` is largely a no-op other
    // than cleaning up the initial (and unused) empty document. Otherwise, this
    // unloads the previous Document and detaches subframes. If
    // `DetachDocument()` returns false, JS caused `frame_` to be removed, so
    // just return.
    const bool is_provisional = frame_->IsProvisional();
    // For an XSLT document, set SentDidFinishLoad now to prevent the
    // DocumentLoader from reporting an error when detaching the pre-XSLT
    // document.
    if (commit_reason == CommitReason::kXSLT && document_loader_)
      document_loader_->SetSentDidFinishLoad();
    if (!DetachDocument()) {
      DCHECK(!is_provisional);
      return;
    }

    // If the frame is provisional, swap it in now. However, if `SwapIn()`
    // returns false, JS caused `frame_` to be removed, so just return. In case
    // this triggers a local RenderFrame swap, it might trigger the unloading
    // of the old RenderFrame's document, updating the contents of the
    // OldDocumentInfoForCommit set in `scoped_old_document_info` above.
    // NOTE: it's important that SwapIn() happens before DetachDocument(),
    // because this ensures that the unload timing info generated by detaching
    // the provisional frame's document isn't the one that gets used.
    if (is_provisional && !frame_->SwapIn())
      return;
  }

  tls_version_warning_origins_.clear();

  if (!navigation_params->is_synchronous_commit_for_bug_778318 ||
      (!navigation_params->url.IsEmpty() &&
       !KURL(navigation_params->url).IsAboutBlankURL())) {
    // The new document is not the synchronously committed about:blank document,
    // so lose the initial empty document status.
    // Note 1: The actual initial empty document commit (with commit_reason set
    // to CommitReason::kInitialization) won't go through this path since it
    // immediately commits the DocumentLoader, so we only check for the
    // synchronous about:blank commit here.
    // Note 2: Even if the navigation is a synchronous one, it might be a
    // non-about:blank/empty URL commit that is accidentally got caught by the
    // synchronous about:blank path but can't easily be removed due to failing
    // tests/compatibility risk (e.g. about:mumble).
    // TODO(https://crbug.com/1215096): Tighten the conditions in
    // RenderFrameImpl::BeginNavigation() for a navigation to enter the
    // synchronous commit path to only accept about:blank or an empty URL which
    // defaults to about:blank, per the spec:
    // https://html.spec.whatwg.org/multipage/iframe-embed-object.html#the-iframe-element:about:blank
    DCHECK_NE(commit_reason, CommitReason::kInitialization);
    SetIsNotOnInitialEmptyDocument();
  }

  // TODO(dgozman): navigation type should probably be passed by the caller.
  // It seems incorrect to pass |false| for |have_event| and then use
  // determined navigation type to update resource request.
  WebNavigationType navigation_type = DetermineNavigationType(
      navigation_params->frame_load_type,
      !navigation_params->http_body.IsNull(), false /* have_event */);

  std::unique_ptr<PolicyContainer> policy_container;
  if (navigation_params->policy_container) {
    // Javascript and xslt documents should not change the PolicyContainer.
    DCHECK(commit_reason == CommitReason::kRegular);

    policy_container = PolicyContainer::CreateFromWebPolicyContainer(
        std::move(navigation_params->policy_container));
  }

  // TODO(dgozman): get rid of provisional document loader and most of the code
  // below. We should probably call DocumentLoader::CommitNavigation directly.
  DocumentLoader* new_document_loader = MakeGarbageCollected<DocumentLoader>(
      frame_, navigation_type, std::move(navigation_params),
      std::move(policy_container), std::move(extra_data));

  CommitDocumentLoader(
      new_document_loader,
      ScopedOldDocumentInfoForCommitCapturer::CurrentInfo()->history_item.Get(),
      commit_reason);

  RestoreScrollPositionAndViewState();

  TakeObjectSnapshot();
}

bool FrameLoader::WillStartNavigation(const WebNavigationInfo& info) {
  if (!CancelProvisionalLoaderForNewNavigation())
    return false;

  progress_tracker_->ProgressStarted();
  client_navigation_ = std::make_unique<ClientNavigationState>();
  client_navigation_->url = info.url_request.Url();
  frame_->GetFrameScheduler()->DidStartProvisionalLoad();
  probe::DidStartProvisionalLoad(frame_.Get());
  virtual_time_pauser_.PauseVirtualTime();
  TakeObjectSnapshot();
  return true;
}

void FrameLoader::StopAllLoaders(bool abort_client) {
  if (!frame_->IsNavigationAllowed() ||
      frame_->GetDocument()->PageDismissalEventBeingDispatched() !=
          Document::kNoDismissal) {
    return;
  }

  // This method could be called from within this method, e.g. through plugin
  // detach. Avoid infinite recursion by disabling navigations.
  FrameNavigationDisabler navigation_disabler(*frame_);

  for (Frame* child = frame_->Tree().FirstChild(); child;
       child = child->Tree().NextSibling()) {
    if (auto* child_local_frame = DynamicTo<LocalFrame>(child))
      child_local_frame->Loader().StopAllLoaders(abort_client);
  }

  frame_->GetDocument()->CancelParsing();

  // `abort_client` is false only when we are stopping all loading in
  // preparation for a frame swap. When a swap occurs, we're stopping all
  // loading in this particular LocalFrame, but the conceptual frame is
  // committing and continuing loading. We shouldn't treat this as a navigation
  // cancellation in web-observable ways, so the navigation API should not do
  // its cancelled navigation steps (e.g., firing a navigateerror event).
  if (abort_client) {
    frame_->DomWindow()->navigation()->InformAboutCanceledNavigation();
  }

  if (document_loader_)
    document_loader_->StopLoading();
  if (abort_client)
    CancelClientNavigation();
  else
    ClearClientNavigation();
  frame_->CancelFormSubmission();
  DidFinishNavigation(FrameLoader::NavigationFinishState::kSuccess);

  TakeObjectSnapshot();
}

void FrameLoader::DidAccessInitialDocument() {
  if (frame_->IsMainFrame() && !has_accessed_initial_document_) {
    has_accessed_initial_document_ = true;
    // Forbid script execution to prevent re-entering V8, since this is called
    // from a binding security check.
    ScriptForbiddenScope forbid_scripts;
    frame_->GetPage()->GetChromeClient().DidAccessInitialMainDocument();
  }
}

bool FrameLoader::DetachDocument() {
  TRACE_EVENT0("navigation", "FrameLoader::DetachDocument");
  base::ScopedUmaHistogramTimer histogram_timer(
      "Navigation.FrameLoader.DetachDocument");
  DCHECK(frame_->GetDocument());
  DCHECK(document_loader_);

  PluginScriptForbiddenScope forbid_plugin_destructor_scripting;
  ClientNavigationState* client_navigation = client_navigation_.get();

  // Don't allow this frame to navigate anymore. This line is needed for
  // navigation triggered from children's unload handlers. Blocking navigations
  // triggered from this frame's unload handler is already covered in
  // DispatchUnloadEventAndFillOldDocumentInfoIfNeeded().
  FrameNavigationDisabler navigation_disabler(*frame_);
  // Don't allow any new child frames to load in this frame: attaching a new
  // child frame during or after detaching children results in an attached frame
  // on a detached DOM tree, which is bad.
  SubframeLoadingDisabler disabler(frame_->GetDocument());
  // https://html.spec.whatwg.org/C/browsing-the-web.html#unload-a-document
  // The ignore-opens-during-unload counter of a Document must be incremented
  // both when unloading itself and when unloading its descendants.
  IgnoreOpensDuringUnloadCountIncrementer ignore_opens_during_unload(
      frame_->GetDocument());
  DispatchUnloadEventAndFillOldDocumentInfoIfNeeded(
      true /* will_commit_new_document_in_this_frame */);
  frame_->DetachChildren();
  // The previous calls to DispatchUnloadEventAndFillOldDocumentInfoIfNeeded()
  // and detachChildren() can execute arbitrary script via things like unload
  // events. If the executed script causes the current frame to be detached, we
  // need to abandon the current load.
  if (!frame_->Client())
    return false;
  // FrameNavigationDisabler should prevent another load from starting.
  DCHECK_EQ(client_navigation_.get(), client_navigation);
  // Detaching the document loader will abort XHRs that haven't completed, which
  // can trigger event listeners for 'abort'. These event listeners might call
  // window.stop(), which will in turn detach the provisional document loader.
  // At this point, the provisional document loader should not detach, because
  // then the FrameLoader would not have any attached DocumentLoaders. This is
  // guaranteed by FrameNavigationDisabler above.
  DetachDocumentLoader(document_loader_, true);
  // 'abort' listeners can also detach the frame.
  if (!frame_->Client())
    return false;
  // FrameNavigationDisabler should prevent another load from starting.
  DCHECK_EQ(client_navigation_.get(), client_navigation);

  // No more events will be dispatched so detach the Document.
  // TODO(dcheng): Why is this a conditional check?
  // TODO(yoav): Should we also be nullifying domWindow's document (or
  // domWindow) since the doc is now detached?
  frame_->GetDocument()->Shutdown();
  document_loader_ = nullptr;

  return true;
}

void FrameLoader::CommitDocumentLoader(DocumentLoader* document_loader,
                                       HistoryItem* previous_history_item,
                                       CommitReason commit_reason) {
  TRACE_EVENT0("navigation", "FrameLoader::CommitDocumentLoader");
  base::ScopedUmaHistogramTimer histogram_timer(
      "Navigation.FrameLoader.CommitDocumentLoader");
  base::ElapsedTimer timer;
  document_loader_ = document_loader;
  CHECK(document_loader_);

  document_loader_->SetCommitReason(commit_reason);
  document_loader_->StartLoading();

  if (commit_reason != CommitReason::kInitialization) {
    // Following the call to StartLoading, the DocumentLoader state has taken
    // into account all redirects that happened during navigation. Its
    // HistoryItem can be properly updated for the commit, using the HistoryItem
    // of the previous Document.
    document_loader_->SetHistoryItemStateForCommit(
        previous_history_item, document_loader_->LoadType(),
        DocumentLoader::HistoryNavigationType::kDifferentDocument,
        commit_reason);
  }

  // Update the DocumentLoadTiming with the timings from the previous document
  // unload event.
  OldDocumentInfoForCommit* old_document_info =
      ScopedOldDocumentInfoForCommitCapturer::CurrentInfo();
  if (old_document_info &&
      old_document_info->unload_timing_info.unload_timing.has_value()) {
    document_loader_->GetTiming().SetCanRequestFromPreviousDocument(
        old_document_info->unload_timing_info.unload_timing->can_request);
    document_loader_->GetTiming().SetUnloadEventStart(
        old_document_info->unload_timing_info.unload_timing
            ->unload_event_start);
    document_loader_->GetTiming().SetUnloadEventEnd(
        old_document_info->unload_timing_info.unload_timing->unload_event_end);
    document_loader_->GetTiming().MarkCommitNavigationEnd();
  }

  TakeObjectSnapshot();

  Client()->TransitionToCommittedForNewPage();

  document_loader_->CommitNavigation();

  base::UmaHistogramTimes("Blink.CommitDocumentLoaderTime", timer.Elapsed());
  ukm::builders::Blink_FrameLoader(frame_->GetDocument()->UkmSourceID())
      .SetCommitDocumentLoaderTime(ukm::GetExponentialBucketMinForUserTiming(
          timer.Elapsed().InMicroseconds()))
      .Record(frame_->GetDocument()->UkmRecorder());
}

void FrameLoader::RestoreScrollPositionAndViewState() {
  if (!frame_->GetPage() || !GetDocumentLoader() ||
      !GetDocumentLoader()->GetHistoryItem() ||
      !GetDocumentLoader()->GetHistoryItem()->GetViewState() ||
      !GetDocumentLoader()->NavigationScrollAllowed()) {
    return;
  }

  // We need to suppress scroll restoration animations for navigations with
  // visual transitions for the same-document case only. This is done in
  // ProcessScrollForSameDocumentNavigation.
  //
  // For cross-document navigations (which take this path) the animation is
  // suppressed by default.
  RestoreScrollPositionAndViewState(
      GetDocumentLoader()->LoadType(),
      *GetDocumentLoader()->GetHistoryItem()->GetViewState(),
      GetDocumentLoader()->GetHistoryItem()->ScrollRestorationType(),
      mojom::blink::ScrollBehavior::kAuto);
}

void FrameLoader::RestoreScrollPositionAndViewState(
    WebFrameLoadType load_type,
    const HistoryItem::ViewState& view_state,
    mojom::blink::ScrollRestorationType scroll_restoration_type,
    mojom::blink::ScrollBehavior scroll_behavior) {
  LocalFrameView* view = frame_->View();
  if (!view || !view->LayoutViewport() || !frame_->IsAttached() ||
      frame_->GetDocument()->IsInitialEmptyDocument()) {
    return;
  }
  if (!NeedsHistoryItemRestore(load_type))
    return;

  view->LayoutViewport()->SetPendingHistoryRestoreScrollOffset(
      view_state,
      scroll_restoration_type != mojom::blink::ScrollRestorationType::kManual,
      scroll_behavior);
  view->GetScrollableArea()->SetPendingHistoryRestoreScrollOffset(
      view_state,
      scroll_restoration_type != mojom::blink::ScrollRestorationType::kManual,
      scroll_behavior);

  view->ScheduleAnimation();
}

String FrameLoader::ApplyUserAgentOverride(const String& user_agent) const {
  String user_agent_override;
  probe::ApplyUserAgentOverride(probe::ToCoreProbeSink(frame_->GetDocument()),
                                &user_agent_override);

  if (Client()->UserAgentOverride().empty() && user_agent_override.empty()) {
    return user_agent;
  }

  if (user_agent_override.empty()) {
    user_agent_override = user_agent;
  }

  return user_agent_override;
}

String FrameLoader::UserAgent() const {
  return ApplyUserAgentOverride(Client()->UserAgent());
}

std::optional<blink::UserAgentMetadata> Frame
"""


```