Response:
My thinking process to answer the request goes through these steps:

1. **Understand the Goal:** The request asks for a summary of the `DocumentLoader`'s functionality based on a code snippet, focusing on its relationship with JavaScript, HTML, CSS, providing examples, explaining common errors, outlining user interaction, and fitting it into a larger six-part context.

2. **Initial Code Scan (High-Level):**  I first read through the provided code to get a general idea of what the `DocumentLoader` is doing. I notice keywords like "loading," "navigation," "redirect," "parser," "commit," "data," "JavaScript," "HTML," "CSS," and functions dealing with states (kCommitted, kFinishedLoading, etc.). This tells me it's central to the process of fetching and processing web page content.

3. **Identify Key Responsibilities:** I start breaking down the code into functional units. I see:
    * **Navigation Management:** Handling redirects (`HandleRedirect`), same-document navigations (`CommitSameDocumentNavigation`, `CommitSameDocumentNavigationInternal`).
    * **Resource Loading:** Fetching data (`StartLoading`, `StartLoadingInternal`, `StartLoadingResponse`), handling responses (`HandleResponse`), processing data chunks (`CommitData`, `ProcessDataBuffer`).
    * **Parsing:** Interacting with a parser (`parser_`, `Finish()`, `CommitData`), handling parser blocking.
    * **Document State:** Managing the loading state (`state_`), committing the document (`DidCommitNavigation`).
    * **Error Handling:**  Logging console errors (`ConsoleError`), handling blocked loads.
    * **Integration with other Blink Components:** Interacting with `Frame`, `DomWindow`, `FrameLoader`, `Fetcher`, `HistoryItem`, `Console`, `DocumentPolicy`.
    * **MHTML Handling:** Special logic for loading MHTML archives.
    * **Empty Document Handling:** Handling navigation to `about:` URLs and potentially creating empty documents.
    * **Security:** Checking document policy, handling cross-origin navigations.
    * **Events:** Dispatching `hashchange` and `navigate` events.

4. **Relate to Core Web Technologies (HTML, CSS, JavaScript):**  Now I think about how these responsibilities connect to the core web technologies:
    * **HTML:** The parser (`parser_`) is directly responsible for interpreting HTML. The `DocumentLoader` feeds the HTML data to the parser. The final output is a `Document` object, which represents the HTML structure.
    * **CSS:** While the code doesn't directly show CSS parsing, I know that once the HTML structure is built, the browser will start fetching and applying CSS. The `DocumentLoader` is responsible for getting the initial HTML that triggers this process. The mention of `PreloadHelper::LoadLinksFromHeader` suggests it handles preloading of various resources, including CSS.
    * **JavaScript:** The code explicitly mentions dispatching events (like `navigate`) which are crucial for JavaScript interaction. The `DomWindow` interaction points to the JavaScript execution environment. The handling of same-document navigations is often triggered by JavaScript (e.g., `history.pushState`).

5. **Construct Examples:** Based on the identified responsibilities, I create simple examples to illustrate the concepts:
    * **JavaScript:**  `window.location.hash = 'section1'` for same-document navigation, or `window.open('new_page.html')` for a new navigation.
    * **HTML:**  A basic HTML structure, a link, or an iframe to demonstrate different loading scenarios.
    * **CSS:** A simple CSS rule to show how it would be applied to the loaded HTML.

6. **Identify Potential User/Programming Errors:**  I consider common issues developers might face related to document loading:
    * **Navigation away during loading:**  The code has checks for `!frame_` which suggests this is a possibility.
    * **Mismatched URLs:**  The same-document navigation logic has checks for URL consistency.
    * **Document Policy Blocking:** The code explicitly handles cases where document policy blocks loading.
    * **Incorrect MHTML formatting:** The code handles malformed MHTML archives.

7. **Trace User Interaction:** I try to map typical user actions to the `DocumentLoader`'s involvement:
    * Typing a URL and pressing Enter.
    * Clicking a link.
    * Using the browser's back/forward buttons.
    * JavaScript-initiated navigation.

8. **Infer Context (Part 3 of 6):**  Knowing this is part 3 of 6 suggests that earlier parts likely deal with the initial request and setup, while later parts might cover rendering, post-load processing, or cleanup. I focus on the functionalities apparent in *this* snippet, which seems to be the core loading and initial processing phase.

9. **Structure the Answer:** I organize my findings into the requested categories: Functionality, Relationship with Web Technologies (with examples), Logical Reasoning (assumptions and outputs), Common Errors, User Interaction (Debugging), and overall Function Summary.

10. **Refine and Review:** I go back through my answer, ensuring clarity, accuracy, and completeness based on the provided code. I make sure the examples are relevant and the explanations are easy to understand. I also ensure that I address each part of the original prompt. For instance, I explicitly state the assumptions for the logical reasoning (e.g., a redirect occurring).

By following this systematic approach, I can dissect the code snippet, understand its purpose, and generate a comprehensive answer that addresses all aspects of the request. The key is to move from a high-level understanding to specific details, making connections to relevant concepts and providing concrete examples.
好的，让我们来分析一下 `blink/renderer/core/loader/document_loader.cc` 文件（提供的代码片段是该文件的一部分）的功能。

**基于提供的代码片段，`DocumentLoader` 的主要功能可以归纳如下：**

1. **管理文档的加载生命周期:**  `DocumentLoader` 负责从开始到结束管理一个文档的加载过程，包括：
    * **初始化加载:** (`StartLoadingInternal`) 设置加载状态，处理 URL，初始化资源请求等。
    * **处理重定向:** (`HandleRedirect`)  当发生 HTTP 重定向时，更新 URL、请求方法、Referrer 等信息。
    * **接收和处理数据:** (`CommitData`, `ProcessDataBuffer`)  接收从网络或其他来源获取的文档数据，并将数据传递给解析器。
    * **完成加载:** (`FinishedLoading`) 在文档数据加载完成后执行清理工作，标记加载完成。
    * **停止加载:** (`StopLoading`)  取消当前的加载操作。
    * **处理错误:** (`LoadFailed`)  在加载失败时进行处理。

2. **与解析器交互:** `DocumentLoader` 与 HTML 解析器 (`parser_`) 紧密合作，将接收到的 HTML 数据传递给解析器进行解析。它还处理解析器阻塞的情况 (`parser_blocked_count_`)。

3. **处理不同类型的导航:**
    * **正常的跨文档导航:**  通过加载新的资源来替换当前文档。
    * **相同的文档导航 (Same-document navigation):** (`CommitSameDocumentNavigation`, `CommitSameDocumentNavigationInternal`)  在不卸载当前文档的情况下，更新 URL 的片段标识符（hash），或通过 JavaScript API（如 `history.pushState`）进行状态更新。

4. **处理 MHTML 档案:**  `DocumentLoader` 能够识别和加载 MHTML (MIME HTML) 格式的文档，这是一种将 HTML 页面及其资源打包成单个文件的格式。

5. **管理文档策略 (Document Policy):** (`CreateDocumentPolicy`)  解析和应用文档策略，这是一种允许页面声明其期望的安全策略的机制。

6. **处理空的或特殊的 URL:**  能够加载 `about:` 协议的 URL 或空 URL，通常会创建空的文档。

7. **与 Frame 和 DomWindow 交互:** `DocumentLoader` 与其所属的 `Frame` 和 `DomWindow` 对象进行通信，更新它们的状态，并触发相应的事件。

8. **处理客户端重定向:** 能够识别并处理客户端发起的重定向。

**与 JavaScript, HTML, CSS 的功能关系及举例说明:**

* **HTML:**
    * `DocumentLoader` 接收到的主要数据是 HTML。它将这些 HTML 数据传递给解析器 (`parser_->CommitData`)，解析器负责构建 DOM 树。
    * **例子:** 当用户访问一个网页时，`DocumentLoader` 会下载 HTML 内容，并将其交给 HTML 解析器，最终浏览器会渲染出网页结构。
    * **例子:**  `DocumentLoader` 处理 `<meta>` 标签中定义的字符编码，确保 HTML 内容被正确解析。

* **JavaScript:**
    * `DocumentLoader` 负责触发与导航相关的 JavaScript 事件，例如 `hashchange` 和 `navigate` 事件。
    * **例子:** 当 JavaScript 代码执行 `window.location.hash = '#section1'` 时，`DocumentLoader` 的 `CommitSameDocumentNavigationInternal` 方法会被调用，并触发 `hashchange` 事件。
    * **例子:**  当使用 Navigation API (`navigation.navigate()`) 进行导航时，`DocumentLoader` 会负责协调 `navigate` 事件的派发。
    * `DocumentLoader` 的状态和行为会影响 JavaScript 的执行。例如，当解析器被阻塞时，某些 JavaScript 的执行可能会被延迟。

* **CSS:**
    * 虽然 `DocumentLoader` 不直接解析 CSS，但它是加载 HTML 的关键部分，而 HTML 中会引用 CSS 文件。
    * **例子:**  HTML 中的 `<link rel="stylesheet" href="style.css">` 标签指示浏览器加载 CSS 文件。`DocumentLoader` 负责加载包含这个标签的 HTML 文件，从而触发 CSS 文件的加载。
    * `DocumentLoader` 中的 `PreloadHelper::LoadLinksFromHeader` 函数可以处理 HTTP 头部中的 `Link` 信息，这些信息可能包含 CSS 资源的预加载指示。

**逻辑推理 (假设输入与输出):**

**假设输入:**

1. 用户在地址栏输入 `https://example.com/page.html` 并回车。
2. 服务器返回一个 HTTP 响应，包含以下头部和 HTML 内容：
   ```
   HTTP/1.1 200 OK
   Content-Type: text/html; charset=utf-8
   Link: <style.css>; rel=preload; as=style

   <!DOCTYPE html>
   <html>
   <head>
       <title>Example Page</title>
       <link rel="stylesheet" href="style.css">
   </head>
   <body>
       <h1>Hello World</h1>
       <a href="#section2">Go to Section 2</a>
       <div id="section2">This is section 2.</div>
       <script>
           console.log("Page loaded");
       </script>
   </body>
   </html>
   ```

**输出 (DocumentLoader 的部分行为):**

1. `DocumentLoader` 的 `StartLoadingInternal` 被调用，开始加载 `https://example.com/page.html`。
2. `HandleResponse` 处理 HTTP 响应，获取 Content-Type 和字符编码等信息。
3. `PreloadHelper::LoadLinksFromHeader` 被调用，解析 `Link` 头部，可能触发 `style.css` 的预加载。
4. `CreateParserPostCommit` 创建 HTML 解析器。
5. `ProcessDataBuffer` 被调用多次，接收 HTML 内容的各个部分。
6. `parser_->CommitData` 被调用，将 HTML 数据传递给解析器。
7. 解析器开始构建 DOM 树。
8. 当解析到 `<link rel="stylesheet" href="style.css">` 时，浏览器会开始加载 `style.css`。
9. 当解析到 `<script>` 标签时，如果脚本不是异步或延迟加载，解析器可能会暂停解析，直到脚本加载和执行完毕。
10. 当用户点击 "Go to Section 2" 链接时，`CommitSameDocumentNavigationInternal` 被调用，更新 URL 的 hash，并触发 `hashchange` 事件。

**用户或编程常见的使用错误:**

1. **在文档加载过程中尝试操作未完全加载的 DOM 元素:**
   * **场景:**  JavaScript 代码在 `<head>` 部分执行，试图访问 `<body>` 中的元素。由于 `<body>` 尚未被解析，操作会失败或导致错误。
   * **调试线索:** 检查控制台的错误信息，查看 JavaScript 代码的执行时机，确认是否在 `DOMContentLoaded` 或 `load` 事件触发后执行。

2. **错误的 MHTML 格式:**
   * **场景:**  尝试加载一个格式错误的 MHTML 文件。
   * **`DocumentLoader` 行为:**  代码中有 `loading_main_document_from_mhtml_archive_` 的判断，并且会检查 `archive_->LoadResult()`，如果加载失败，会输出控制台错误信息 (`Malformed multipart archive`)。
   * **调试线索:** 检查控制台是否有 "Malformed multipart archive" 相关的错误信息。验证 MHTML 文件的格式是否正确。

3. **文档策略阻止加载:**
   * **场景:**  服务器发送了严格的文档策略头部，阻止了某些不符合策略的资源加载或行为。
   * **`DocumentLoader` 行为:**  `CreateDocumentPolicy` 方法会解析文档策略，如果策略不兼容，`was_blocked_by_document_policy_` 会被设置为 true。
   * **调试线索:**  检查 Network 面板的 Response Headers 中是否有 `Document-Policy` 或 `Require-Document-Policy` 头部。检查控制台是否有与文档策略相关的警告或错误信息。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在地址栏输入 URL 并回车:**  这会触发浏览器的导航过程，浏览器进程会向渲染器进程发送请求加载该 URL 的消息。渲染器进程会创建 `DocumentLoader` 对象来处理这次加载。
2. **用户点击页面上的链接:**  点击链接同样会触发导航，浏览器会根据链接的 URL 创建新的加载请求，并可能创建新的 `DocumentLoader` 对象，或者重用现有的。
3. **用户使用浏览器的前进/后退按钮:**  这会触发历史导航，浏览器会从历史记录中恢复页面的状态，`DocumentLoader` 会根据历史记录的信息进行加载。
4. **JavaScript 代码执行 `window.location.href` 的修改或使用 Navigation API:**  这些操作会直接触发相同文档或跨文档的导航，`DocumentLoader` 会根据不同的情况执行相应的加载逻辑。
5. **页面中包含 `<iframe>` 或 `<frame>` 元素:**  每个 frame 都会有自己的 `DocumentLoader` 实例来加载其内容。

**调试线索:**

* **Network 面板:**  查看网络请求的状态、头部信息、响应内容，可以帮助判断资源是否加载成功，以及服务器返回的策略信息。
* **Console 面板:**  查看 JavaScript 错误、警告信息，以及 `DocumentLoader` 输出的与 MHTML 或文档策略相关的错误信息。
* **Sources 面板:**  可以设置断点在 `DocumentLoader` 的关键方法中，例如 `StartLoadingInternal`、`HandleRedirect`、`CommitData` 等，来跟踪加载过程。
* **Performance 面板:**  可以分析页面加载的性能瓶颈，例如资源加载时间、解析时间等。

**总结 `DocumentLoader` 的功能 (基于提供的代码片段):**

`DocumentLoader` 是 Chromium Blink 引擎中负责管理文档加载的核心组件。它处理从接收初始请求到完成文档加载的整个生命周期，包括处理重定向、接收和处理 HTML 数据、与 HTML 解析器交互、处理相同文档导航、管理文档策略以及处理特定类型的文档（如 MHTML）。它在幕后协调各种操作，最终将从网络获取的 HTML、CSS 和 JavaScript 转化为用户可见的网页。 这段代码片段主要展示了 `DocumentLoader` 在加载过程中的数据接收、解析处理、以及与导航机制的交互。

### 提示词
```
这是目录为blink/renderer/core/loader/document_loader.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
r::Instance(frame_->DomWindow()->GetIsolate())
             ->IsPaused());

  if (loading_main_document_from_mhtml_archive_ && state_ < kCommitted) {
    // The browser process should block any navigation to an MHTML archive
    // inside iframes. See NavigationRequest::OnResponseStarted().
    CHECK(frame_->IsMainFrame());

    archive_ = MHTMLArchive::Create(url_, std::move(data_buffer_));
  }

  // We should not call FinishedLoading before committing navigation,
  // except for the mhtml case. When loading an MHTML archive, the whole archive
  // has to be validated before committing the navigation. The validation
  // process loads the entire body of the archive, which will move the state to
  // FinishedLoading.
  if (!loading_main_document_from_mhtml_archive_)
    DCHECK_GE(state_, kCommitted);

  base::TimeTicks response_end_time = finish_time;
  if (response_end_time.is_null())
    response_end_time = time_of_last_data_received_;
  if (response_end_time.is_null())
    response_end_time = clock_->NowTicks();
  GetTiming().SetResponseEnd(response_end_time);

  if (!frame_)
    return;

  if (parser_) {
    if (parser_blocked_count_) {
      finish_loading_when_parser_resumed_ = true;
    } else {
      parser_->Finish();
      parser_.Clear();
    }
  }
}

void DocumentLoader::HandleRedirect(
    const WebNavigationParams::RedirectInfo& redirect) {
  const ResourceResponse& redirect_response =
      redirect.redirect_response.ToResourceResponse();
  const KURL& url_before_redirect = redirect_response.CurrentRequestUrl();
  url_ = redirect.new_url;
  const KURL& url_after_redirect = url_;

  // Update the HTTP method of this document to the method used by the redirect.
  AtomicString new_http_method = redirect.new_http_method;
  if (http_method_ != new_http_method) {
    http_body_ = nullptr;
    http_content_type_ = g_null_atom;
    http_method_ = new_http_method;
  }

  referrer_ = redirect.new_referrer;

  probe::WillSendNavigationRequest(
      probe::ToCoreProbeSink(GetFrame()), main_resource_identifier_, this,
      url_after_redirect, http_method_, http_body_.get());

  DCHECK(!GetTiming().FetchStart().is_null());
  GetTiming().AddRedirect(url_before_redirect, url_after_redirect);
}

void DocumentLoader::ConsoleError(const String& message) {
  auto* console_message = MakeGarbageCollected<ConsoleMessage>(
      mojom::ConsoleMessageSource::kSecurity,
      mojom::ConsoleMessageLevel::kError, message,
      response_.CurrentRequestUrl(), this, MainResourceIdentifier());
  frame_->DomWindow()->AddConsoleMessage(console_message);
}

void DocumentLoader::ReplaceWithEmptyDocument() {
  DCHECK(params_);
  KURL blocked_url = SecurityOrigin::UrlWithUniqueOpaqueOrigin();
  url_ = blocked_url;
  params_->url = blocked_url;
  WebNavigationParams::FillStaticResponse(params_.get(), "text/html", "UTF-8",
                                          base::span_from_cstring(""));
}

DocumentPolicy::ParsedDocumentPolicy DocumentLoader::CreateDocumentPolicy() {
  // For URLs referring to local content to parent frame, they have no way to
  // specify the document policy they use. If the parent frame requires a
  // document policy on them, use the required policy as effective policy.
  if (url_.IsEmpty() || url_.ProtocolIsAbout() || url_.ProtocolIsData() ||
      url_.ProtocolIs("blob") || url_.ProtocolIs("filesystem"))
    return {frame_policy_.required_document_policy, {} /* endpoint_map */};

  PolicyParserMessageBuffer header_logger("Document-Policy HTTP header: ");
  PolicyParserMessageBuffer require_header_logger(
      "Require-Document-Policy HTTP header: ");

  // Filtering out features that are disabled by origin trial is done
  // in SecurityContextInit when origin trial context is available.
  auto parsed_policy =
      DocumentPolicyParser::Parse(
          response_.HttpHeaderField(http_names::kDocumentPolicy), header_logger)
          .value_or(DocumentPolicy::ParsedDocumentPolicy{});

  // |parsed_policy| can have policies that are disabled by origin trial,
  // but |frame_policy_.required_document_policy| cannot.
  // It is safe to call |IsPolicyCompatible| as long as required policy is
  // checked against origin trial.
  if (!DocumentPolicy::IsPolicyCompatible(
          frame_policy_.required_document_policy,
          parsed_policy.feature_state)) {
    was_blocked_by_document_policy_ = true;
    // When header policy is less strict than required policy, use required
    // policy to initialize document policy for the document.
    parsed_policy = {frame_policy_.required_document_policy,
                     {} /* endpoint_map */};
  }

  // Initialize required document policy for subtree.
  //
  // If the document is blocked by document policy, there won't be content
  // in the sub-frametree, thus no need to initialize required_policy for
  // subtree.
  if (!was_blocked_by_document_policy_) {
    // Require-Document-Policy header only affects subtree of current document,
    // but not the current document.
    const DocumentPolicyFeatureState header_required_policy =
        DocumentPolicyParser::Parse(
            response_.HttpHeaderField(http_names::kRequireDocumentPolicy),
            require_header_logger)
            .value_or(DocumentPolicy::ParsedDocumentPolicy{})
            .feature_state;
    frame_->SetRequiredDocumentPolicy(DocumentPolicy::MergeFeatureState(
        header_required_policy, frame_policy_.required_document_policy));
  }

  document_policy_parsing_messages_.AppendVector(header_logger.GetMessages());
  document_policy_parsing_messages_.AppendVector(
      require_header_logger.GetMessages());

  return parsed_policy;
}

void DocumentLoader::HandleResponse() {
  DCHECK(frame_);

  if (response_.IsHTTP() &&
      !network::IsSuccessfulStatus(response_.HttpStatusCode())) {
    DCHECK(!IsA<HTMLObjectElement>(frame_->Owner()));
  }
}

void DocumentLoader::CommitData(BodyData& data) {
  TRACE_EVENT_WITH_FLOW1("loading", "DocumentLoader::CommitData",
                         TRACE_ID_LOCAL(this),
                         TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT,
                         "length", data.EncodedData().size());

  // This can happen if document.close() is called by an event handler while
  // there's still pending incoming data.
  // TODO(dgozman): we should stop body loader when stopping the parser to
  // avoid unnecessary work. This may happen, for example, when we abort current
  // committed document which is still loading when initiating a new navigation.
  if (!frame_ || !frame_->GetDocument()->Parsing() || !parser_)
    return;

  base::AutoReset<bool> reentrancy_protector(&in_commit_data_, true);
  if (data.EncodedData().size())
    data_received_ = true;
  data.AppendToParser(this);
}

mojom::CommitResult DocumentLoader::CommitSameDocumentNavigation(
    const KURL& url,
    WebFrameLoadType frame_load_type,
    HistoryItem* history_item,
    ClientRedirectPolicy client_redirect_policy,
    bool has_transient_user_activation,
    const SecurityOrigin* initiator_origin,
    bool is_synchronously_committed,
    Element* source_element,
    mojom::blink::TriggeringEventInfo triggering_event_info,
    bool is_browser_initiated,
    bool has_ua_visual_transition,
    std::optional<scheduler::TaskAttributionId>
        soft_navigation_heuristics_task_id) {
  DCHECK(!IsReloadLoadType(frame_load_type));
  DCHECK(frame_->GetDocument());
  DCHECK(!is_browser_initiated || !is_synchronously_committed);
  CHECK(frame_->IsNavigationAllowed());

  if (Page* page = frame_->GetPage())
    page->HistoryNavigationVirtualTimePauser().UnpauseVirtualTime();

  if (frame_->GetDocument()->IsFrameSet()) {
    // Navigations in a frameset are always cross-document. Renderer-initiated
    // navigations in a frameset will be deferred to the browser, and all
    // renderer-initiated navigations are treated as cross-document. So this one
    // must have been browser-initiated, where it was not aware that the
    // document is a frameset. In that case we just restart the navigation,
    // making it cross-document. This gives a consistent outcome for all
    // navigations in a frameset.
    return mojom::blink::CommitResult::RestartCrossDocument;
  }

  if (!IsBackForwardOrRestore(frame_load_type)) {
    // For the browser to send a same-document navigation, it will always have a
    // fragment. When no fragment is present, the browser loads a new document.
    CHECK(url.HasFragmentIdentifier());
    if (!EqualIgnoringFragmentIdentifier(frame_->GetDocument()->Url(), url)) {
      // A race condition has occurred! The renderer has changed the current
      // document's URL through history.pushState(). This change was performed
      // as a synchronous same-document navigation in the renderer process,
      // though the URL of that document is changed as a result. The browser
      // will hear about this and update its current URL too, but there's a time
      // window before it hears about it. During that time, it may try to
      // perform a same-document navigation based on the old URL. That would
      // arrive here. There are effectively 2 incompatible navigations in flight
      // at the moment, and the history.pushState() one was already performed.
      // We will reorder the incoming navigation from the browser to be
      // performed after the history.pushState() by bouncing it back through the
      // browser. The way we do that is by sending RestartCrossDocument, which
      // is not strictly what we want. We just want the browser to restart the
      // navigation. However, since the document address has changed, the
      // restarted navigation will probably be cross-document, and this prevents
      // a resulting same-document navigation from getting bounced and restarted
      // yet again by a renderer performing another history.pushState(). See
      // https://crbug.com/1209772.
      return mojom::blink::CommitResult::RestartCrossDocument;
    }
  }

  // If the item sequence number didn't change, there's no need to trigger
  // the navigate event. It's possible to get a same-document navigation
  // to a same ISN when a history navigation targets a frame that no longer
  // exists (https://crbug.com/705550).
  bool same_item_sequence_number =
      history_item_ && history_item &&
      history_item_->ItemSequenceNumber() == history_item->ItemSequenceNumber();
  if (!same_item_sequence_number) {
    auto* params = MakeGarbageCollected<NavigateEventDispatchParams>(
        url, NavigateEventType::kFragment, frame_load_type);
    if (is_browser_initiated) {
      params->involvement = UserNavigationInvolvement::kBrowserUI;
    } else if (triggering_event_info ==
               mojom::blink::TriggeringEventInfo::kFromTrustedEvent) {
      params->involvement = UserNavigationInvolvement::kActivation;
    }
    params->source_element = source_element;
    params->destination_item = history_item;
    params->is_browser_initiated = is_browser_initiated;
    params->has_ua_visual_transition = has_ua_visual_transition;
    params->is_synchronously_committed_same_document =
        is_synchronously_committed;
    params->soft_navigation_heuristics_task_id =
        soft_navigation_heuristics_task_id;
    auto dispatch_result =
        frame_->DomWindow()->navigation()->DispatchNavigateEvent(params);
    if (dispatch_result == NavigationApi::DispatchResult::kAbort) {
      return mojom::blink::CommitResult::Aborted;
    } else if (dispatch_result == NavigationApi::DispatchResult::kIntercept) {
      return mojom::blink::CommitResult::Ok;
    }
  }

  mojom::blink::SameDocumentNavigationType same_document_navigation_type =
      mojom::blink::SameDocumentNavigationType::kFragment;
  // If the requesting document is cross-origin, perform the navigation
  // asynchronously to minimize the navigator's ability to execute timing
  // attacks. If |is_synchronously_committed| is false, the navigation is
  // already asynchronous since it's coming from the browser so there's no need
  // to post it again.
  if (is_synchronously_committed && initiator_origin &&
      !initiator_origin->CanAccess(frame_->DomWindow()->GetSecurityOrigin())) {
    frame_->GetTaskRunner(TaskType::kInternalLoading)
        ->PostTask(
            FROM_HERE,
            WTF::BindOnce(
                &DocumentLoader::CommitSameDocumentNavigationInternal,
                WrapWeakPersistent(this), url, frame_load_type,
                WrapPersistent(history_item), same_document_navigation_type,
                client_redirect_policy, has_transient_user_activation,
                WTF::RetainedRef(initiator_origin), is_browser_initiated,
                is_synchronously_committed, triggering_event_info,
                soft_navigation_heuristics_task_id, has_ua_visual_transition));
  } else {
    CommitSameDocumentNavigationInternal(
        url, frame_load_type, history_item, same_document_navigation_type,
        client_redirect_policy, has_transient_user_activation, initiator_origin,
        is_browser_initiated, is_synchronously_committed, triggering_event_info,
        soft_navigation_heuristics_task_id, has_ua_visual_transition);
  }
  return mojom::CommitResult::Ok;
}

void DocumentLoader::CommitSameDocumentNavigationInternal(
    const KURL& url,
    WebFrameLoadType frame_load_type,
    HistoryItem* history_item,
    mojom::blink::SameDocumentNavigationType same_document_navigation_type,
    ClientRedirectPolicy client_redirect,
    bool has_transient_user_activation,
    const SecurityOrigin* initiator_origin,
    bool is_browser_initiated,
    bool is_synchronously_committed,
    mojom::blink::TriggeringEventInfo triggering_event_info,
    std::optional<scheduler::TaskAttributionId>
        soft_navigation_heuristics_task_id,
    bool has_ua_visual_transition) {
  // If this function was scheduled to run asynchronously, this DocumentLoader
  // might have been detached before the task ran.
  if (!frame_)
    return;

  if (!IsBackForwardOrRestore(frame_load_type)) {
    SetNavigationType(triggering_event_info !=
                              mojom::blink::TriggeringEventInfo::kNotFromEvent
                          ? kWebNavigationTypeLinkClicked
                          : kWebNavigationTypeOther);
  }

  // If we have a client navigation for a different document, a fragment
  // scroll should cancel it.
  // Note: see fragment-change-does-not-cancel-pending-navigation, where
  // this does not actually happen.
  GetFrameLoader().DidFinishNavigation(
      FrameLoader::NavigationFinishState::kSuccess);

  // GetFrameLoader().DidFinishNavigation can lead to DetachFromFrame so need
  // to check again if frame_ is null.
  if (!frame_ || !frame_->GetPage())
    return;
  GetFrameLoader().SaveScrollState();

  KURL old_url = frame_->GetDocument()->Url();
  bool hash_change = EqualIgnoringFragmentIdentifier(url, old_url) &&
                     url.FragmentIdentifier() != old_url.FragmentIdentifier();
  if (hash_change) {
    // If we were in the autoscroll/middleClickAutoscroll mode we want to stop
    // it before following the link to the anchor
    frame_->GetEventHandler().StopAutoscroll();
    frame_->DomWindow()->EnqueueHashchangeEvent(old_url, url);
  }
  is_client_redirect_ =
      client_redirect == ClientRedirectPolicy::kClientRedirect;

  last_navigation_had_transient_user_activation_ =
      has_transient_user_activation;

  // Events fired in UpdateForSameDocumentNavigation() might change view state,
  // so stash for later restore.
  std::optional<HistoryItem::ViewState> view_state;
  mojom::blink::ScrollRestorationType scroll_restoration_type =
      mojom::blink::ScrollRestorationType::kAuto;
  if (history_item) {
    view_state = history_item->GetViewState();
    scroll_restoration_type = history_item->ScrollRestorationType();
  }

  UpdateForSameDocumentNavigation(
      url, history_item, same_document_navigation_type, nullptr,
      frame_load_type, FirePopstate::kYes, initiator_origin,
      is_browser_initiated, is_synchronously_committed,
      soft_navigation_heuristics_task_id);
  if (!frame_)
    return;

  if (!frame_->GetDocument()->LoadEventStillNeeded() && frame_->Owner() &&
      initiator_origin &&
      !initiator_origin->CanAccess(frame_->DomWindow()->GetSecurityOrigin()) &&
      frame_->Tree().Parent()->GetSecurityContext()->GetSecurityOrigin()) {
    // If this same-document navigation was initiated by a cross-origin iframe
    // and is cross-origin to its parent, fire onload on the owner iframe.
    // Normally, the owner iframe's onload fires if and only if the window's
    // onload fires (i.e., when a navigation to a different document completes).
    // However, a cross-origin initiator can use the presence or absence of a
    // load event to detect whether the navigation was same- or cross-document,
    // and can therefore try to guess the url of a cross-origin iframe. Fire the
    // iframe's onload to prevent this technique. https://crbug.com/1248444
    frame_->Owner()->DispatchLoad();
  }

  auto scroll_behavior = has_ua_visual_transition
                             ? mojom::blink::ScrollBehavior::kInstant
                             : mojom::blink::ScrollBehavior::kAuto;
  GetFrameLoader().ProcessScrollForSameDocumentNavigation(
      url, frame_load_type, view_state, scroll_restoration_type,
      scroll_behavior);
}

void DocumentLoader::ProcessDataBuffer(BodyData* data) {
  DCHECK_GE(state_, kCommitted);
  if (parser_blocked_count_ || in_commit_data_) {
    // 1) If parser is blocked, we buffer data and process it upon resume.
    // 2) If this function is reentered, we defer processing of the additional
    //    data to the top-level invocation. Reentrant calls can occur because
    //    of web platform (mis-)features that require running a nested run loop:
    //    - alert(), confirm(), prompt()
    //    - Detach of plugin elements.
    //    - Synchronous XMLHTTPRequest
    if (data)
      data->Buffer(this);
    return;
  }

  if (data)
    CommitData(*data);

  // Process data received in reentrant invocations. Note that the invocations
  // of CommitData() may queue more data in reentrant invocations, so iterate
  // until it's empty.
  DCHECK(data_buffer_->empty() || decoded_data_buffer_.empty());
  for (const auto& span : *data_buffer_) {
    EncodedBodyData body_data(span);
    CommitData(body_data);
  }
  for (auto& decoded_data : decoded_data_buffer_)
    CommitData(decoded_data);

  // All data has been consumed, so flush the buffer.
  data_buffer_->Clear();
  decoded_data_buffer_.clear();
}

void DocumentLoader::StopLoading() {
  if (frame_ && GetFrameLoader().GetDocumentLoader() == this)
    frame_->GetDocument()->Fetcher()->StopFetching();
  body_loader_.reset();
  virtual_time_pauser_.UnpauseVirtualTime();
  if (!SentDidFinishLoad())
    LoadFailed(ResourceError::CancelledError(Url()));
}

void DocumentLoader::SetDefersLoading(LoaderFreezeMode mode) {
  freeze_mode_ = mode;
  if (body_loader_)
    body_loader_->SetDefersLoading(mode);
}

void DocumentLoader::DetachFromFrame(bool flush_microtask_queue) {
  DCHECK(frame_);
  StopLoading();
  DCHECK(!body_loader_);

  // `frame_` may become null because this method can get re-entered. If it
  // is null we've already run the code below so just return early.
  if (!frame_)
    return;

  if (flush_microtask_queue) {
    // Flush microtask queue so that they all run on pre-navigation context.
    // TODO(dcheng): This is a temporary hack that should be removed. This is
    // only here because it's currently not possible to drop the microtasks
    // queued for a Document when the Document is navigated away; instead, the
    // entire microtask queue needs to be flushed. Unfortunately, running the
    // microtasks any later results in violating internal invariants, since
    // Blink does not expect the DocumentLoader for a not-yet-detached Document
    // to be null. It is also not possible to flush microtasks any earlier,
    // since flushing microtasks can only be done after any other JS (which can
    // queue additional microtasks) has run. Once it is possible to associate
    // microtasks with a v8::Context, remove this hack.
    frame_->GetDocument()
        ->GetAgent()
        .event_loop()
        ->PerformMicrotaskCheckpoint();
  }
  ScriptForbiddenScope forbid_scripts;
  // If that load cancellation triggered another detach, leave.
  // (fast/frames/detach-frame-nested-no-crash.html is an example of this.)
  if (!frame_)
    return;

  extra_data_.reset();
  service_worker_network_provider_ = nullptr;
  WeakIdentifierMap<DocumentLoader>::NotifyObjectDestroyed(this);
  frame_ = nullptr;
}

const KURL& DocumentLoader::UnreachableURL() const {
  return unreachable_url_;
}

const std::optional<blink::mojom::FetchCacheMode>&
DocumentLoader::ForceFetchCacheMode() const {
  return force_fetch_cache_mode_;
}

bool DocumentLoader::WillLoadUrlAsEmpty(const KURL& url) {
  if (url.IsEmpty())
    return true;
  // Usually, we load urls with about: scheme as empty.
  // However, about:srcdoc is only used as a marker for non-existent
  // url of iframes with srcdoc attribute, which have possibly non-empty
  // content of the srcdoc attribute used as document's html.
  if (url.IsAboutSrcdocURL())
    return false;
  return SchemeRegistry::ShouldLoadURLSchemeAsEmptyDocument(url.Protocol());
}

bool WebDocumentLoader::WillLoadUrlAsEmpty(const WebURL& url) {
  return DocumentLoader::WillLoadUrlAsEmpty(url);
}

void DocumentLoader::InitializeEmptyResponse() {
  response_ = ResourceResponse(url_);
  response_.SetMimeType(AtomicString("text/html"));
  response_.SetTextEncodingName(AtomicString("utf-8"));
}

void DocumentLoader::StartLoading() {
  probe::LifecycleEvent(frame_, this, "init",
                        base::TimeTicks::Now().since_origin().InSecondsF());
  StartLoadingInternal();
  params_ = nullptr;
}

void DocumentLoader::StartLoadingInternal() {
  GetTiming().MarkNavigationStart();
  DCHECK_EQ(state_, kNotStarted);
  DCHECK(params_);
  state_ = kProvisional;

  if (url_.IsEmpty() && commit_reason_ != CommitReason::kInitialization)
    url_ = BlankURL();

  if (loading_url_as_empty_document_) {
    InitializeEmptyResponse();
    return;
  }

  body_loader_ = std::move(params_->body_loader);
  DCHECK(body_loader_);
  DCHECK(!GetTiming().NavigationStart().is_null());
  // The fetch has already started in the browser,
  // so we don't MarkFetchStart here.
  main_resource_identifier_ = CreateUniqueIdentifier();

  virtual_time_pauser_ =
      frame_->GetFrameScheduler()->CreateWebScopedVirtualTimePauser(
          url_.GetString(),
          WebScopedVirtualTimePauser::VirtualTaskDuration::kNonInstant);
  virtual_time_pauser_.PauseVirtualTime();

  // Many parties are interested in resource loading, so we will notify
  // them through various DispatchXXX methods on FrameFetchContext.

  GetFrameLoader().Progress().WillStartLoading(main_resource_identifier_,
                                               ResourceLoadPriority::kVeryHigh);
  probe::WillSendNavigationRequest(probe::ToCoreProbeSink(GetFrame()),
                                   main_resource_identifier_, this, url_,
                                   http_method_, http_body_.get());

  for (const WebNavigationParams::RedirectInfo& redirect : params_->redirects) {
    HandleRedirect(redirect);
  }

  ApplyClientHintsConfig(params_->enabled_client_hints);
  PreloadHelper::LoadLinksFromHeader(
      response_.HttpHeaderField(http_names::kLink),
      response_.CurrentRequestUrl(), *GetFrame(), nullptr,
      PreloadHelper::LoadLinksFromHeaderMode::kDocumentBeforeCommit,
      nullptr /* viewport_description */, nullptr /* alternate_resource_info */,
      nullptr /* recursive_prefetch_token */);
  GetFrameLoader().Progress().IncrementProgress(main_resource_identifier_,
                                                response_);
  probe::DidReceiveResourceResponse(probe::ToCoreProbeSink(GetFrame()),
                                    main_resource_identifier_, this, response_,
                                    nullptr /* resource */);

  HandleResponse();

  loading_main_document_from_mhtml_archive_ =
      EqualIgnoringASCIICase("multipart/related", response_.MimeType()) ||
      EqualIgnoringASCIICase("message/rfc822", response_.MimeType());
  if (loading_main_document_from_mhtml_archive_) {
    // The browser process should block any navigation to an MHTML archive
    // inside iframes. See NavigationRequest::OnResponseStarted().
    CHECK(frame_->IsMainFrame());

    // To commit an mhtml archive synchronously we have to load the whole body
    // synchronously and parse it, and it's already loaded in a buffer usually.
    // This means we should not defer, and we'll finish loading synchronously
    // from StartLoadingBody().
    body_loader_->StartLoadingBody(this);
    return;
  }

  InitializePrefetchedSignedExchangeManager();

  body_loader_->SetDefersLoading(freeze_mode_);
}

void DocumentLoader::StartLoadingResponse() {
  TRACE_EVENT_WITH_FLOW0("loading", "DocumentLoader::StartLoadingResponse",
                         TRACE_ID_LOCAL(this),
                         TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT);
  // TODO(dcheng): Clean up the null checks in this helper.
  if (!frame_)
    return;

  // TODO(crbug.com/332706093): See if this optimization can be enabled for
  // non-main frames after fixing failing tests.
  if (base::FeatureList::IsEnabled(features::kStreamlineRendererInit) &&
      frame_->IsMainFrame() && loading_url_as_empty_document_ &&
      commit_reason_ == CommitReason::kInitialization) {
    // We know this is an empty document, so explicitly set empty content
    // without going through the parser, which has a lot of overhead.
    Document* document = frame_->GetDocument();
    auto* html = MakeGarbageCollected<HTMLHtmlElement>(*document);
    html->AppendChild(MakeGarbageCollected<HTMLHeadElement>(*document));
    document->AppendChild(html);
    html->AppendChild(MakeGarbageCollected<HTMLBodyElement>(*document));

    FinishedLoading(base::TimeTicks::Now());
    return;
  }

  CHECK_GE(state_, kCommitted);

  CreateParserPostCommit();

  // The main document from an MHTML archive is not loaded from its HTTP
  // response, but from the main resource within the archive (in the response).
  if (loading_main_document_from_mhtml_archive_) {
    // If the `archive_` contains a main resource, load the main document from
    // the archive, else it will remain empty.
    if (ArchiveResource* resource = archive_->MainResource()) {
      DCHECK_EQ(archive_->LoadResult(),
                mojom::blink::MHTMLLoadResult::kSuccess);

      data_buffer_ = resource->Data();
      ProcessDataBuffer();
      FinishedLoading(base::TimeTicks::Now());
      return;
    }

    // Log attempts loading a malformed archive.
    DCHECK_NE(archive_->LoadResult(), mojom::blink::MHTMLLoadResult::kSuccess);
    frame_->Console().AddMessage(MakeGarbageCollected<ConsoleMessage>(
        mojom::blink::ConsoleMessageSource::kJavaScript,
        mojom::blink::ConsoleMessageLevel::kError,
        "Malformed multipart archive: " + url_.GetString()));
    FinishedLoading(base::TimeTicks::Now());
    return;
  }

  // Empty documents are empty by definition. Nothing to load.
  if (loading_url_as_empty_document_) {
    FinishedLoading(base::TimeTicks::Now());
    return;
  }

  // Implements "Then, the user agent must act as if it had stopped parsing."
  // from https://html.spec.whatwg.org/C/browsing-the-web.html#read-media
  //
  // This is an oddity of navigating to a media resource: the original request
  // for the media resource—which resulted in a committed navigation—is simply
  // discarded, while the media element created inside the MediaDocument then
  // makes *another new* request for the same media resource.
  //
  // TODO(dcheng): Barring something really strange and unusual, there should
  // always be a frame here.
  if (frame_ && frame_->GetDocument()->IsMediaDocument()) {
    parser_->Finish();
    StopLoading();
    return;
  }

  // Committing can run unload handlers, which can detach this frame or
  // stop this loader.
  if (!frame_ || !body_loader_)
    return;

  if (!url_.ProtocolIsInHTTPFamily()) {
    body_loader_->StartLoadingBody(this);
    return;
  }

  if (parser_->IsPreloading()) {
    // If we were waiting for the document loader, the body has already
    // started loading and it is safe to continue parsing.
    parser_->CommitPreloadedData();
  } else {
    body_loader_->StartLoadingBody(this);
  }
}

void DocumentLoader::DidInstallNewDocument(Document* document) {
  TRACE_EVENT_WITH_FLOW0("loading", "DocumentLoader::DidInstallNewDocument",
                         TRACE_ID_LOCAL(this),
                         TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT);
  // This was called already during `InitializeWindow`, but it could be that we
  // didn't have a Document then (which happens when `InitializeWindow` reuses
  // the window and calls `LocalDOMWindow::ClearForReuse()`). This is
  // idempotent, so it is safe to do it again (in fact, it will be called again
  // also when parsing origin trials delivered in meta tags).
  frame_->DomWindow()->GetOriginTrialContext()->InitializePendingFeatures();

  frame_->DomWindow()->BindContentSecurityPolicy();

  if (history_item_ && IsBackForwardOrRestore(load_type_)) {
    document->SetStateForNewControls(history_item_->GetDocumentState());
  }

  DCHECK(document->GetFrame());
  // TODO(dgozman): modify frame's client hints directly once we commit
  // synchronously.
  document->GetFrame()->GetClientHintsPreferences().UpdateFrom(
      client_hints_preferences_);

  document->GetFrame()->SetReducedAcceptLanguage(reduced_accept_language_);

  const AtomicString& dns_prefetch_control =
      response_.HttpHeaderField(http_names::kXDNSPrefetchControl);
  if (!dns_prefetch_control.empty())
    document->ParseDNSPrefetchControlHeader(dns_prefetch_control);

  String header_content_language =
      response_.HttpHeaderField(http_names::kContentLanguage);
  if (!header_content_language.empty()) {
    wtf_size_t comma_index = header_content_language.find(',');
    // kNotFound == -1 == don't truncate
    header_content_language.Truncate(comma_index);
    header_content_language =
        header_content_language.StripWhiteSpace(IsHTMLSpace<UChar>);
    if (!header_content_language.empty())
      document->SetContentLanguage(AtomicString(header_content_language));
  }

  for (const auto& message : document_policy_parsing_messages_) {
    document->AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        mojom::blink::ConsoleMessageSource::kOther, message.level,
        message.content));
  }
  document_policy_parsing_messages_.clear();

  WarnIfSandboxIneffective(document->domWindow());

  StartViewTransitionIfNeeded(*document);

  // This also enqueues the event for a Document that's loading while
  // prerendered; however, the event still fires at the correct time (first
  // render opportunity after activation) since the event is fired as part of
  // updating the rendering which is suppressed until the prerender is
  // activated.
  if (RuntimeEnabledFeatures::PageRevealEventEnabled()) {
    document->EnqueuePageRevealEvent();
  }
}

void DocumentLoader::WillCommitNavigation() {
  if (commit_reason_ != CommitReason::kRegular)
    return;
  probe::WillCommitLoad(frame_, this);
  frame_->GetIdlenessDetector()->WillCommitLoad();
}

void DocumentLoader::DidCommitNavigation() {
  TRACE_EVENT0("loading", "DocumentLoader::DidCommitNavigation");
  base::ScopedUmaHistogramTimer histogram_timer(
      "Navigation.DocumentLoader.DidCommitNavigation");
  if (commit_reason_ != CommitReason::kRegular)
    return;

  // When committing a new document, the FrameScheduler might need to carry over
  // the previous document's FrameScheduler's `UnreportedTaskTime()`, as that
  // value should be aggregated across all documents that ever committed in the
  // same frame.
  base::TimeDelta previous_document_unreported_task_time =
      frame_->GetFrameScheduler()->UnreportedTaskTime();
  if (OldDocumentInfoForCommit* old_document_info =
          ScopedOldDocumentInfoForCommitCapturer::CurrentInfo()) {
    previous_document_unreported_task_time =
        old_document_info->frame_scheduler_unreported_task_time;
  }
  WebHistoryCommitType commit_type = LoadTypeToCommitType(load_type_);
  frame_->GetFrameScheduler()->DidCommitProvisionalLoad(
      commit_type == kWebHistoryInertCommit,
      load_type_ == WebFrameLoadType::kReload
          ?
```