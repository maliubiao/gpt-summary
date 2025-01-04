Response:
The user wants a summary of the functionality of the provided C++ code snippet from `blink/renderer/core/dom/document.cc`. I need to analyze the code and identify its key responsibilities. The request also asks for connections to JavaScript, HTML, and CSS, examples of logical reasoning with input/output, common user/programming errors, and how user actions might lead to this code being executed.

Here's a breakdown of the code's functionalities based on the provided snippet:

1. **Accessibility:**  Manages an `AXObjectCache` for accessibility purposes. This includes creating, disposing, and refreshing the accessibility tree.
2. **Canvas Font Cache:** Provides access to a `CanvasFontCache`.
3. **Document Parsing:** Creates and manages `DocumentParser` instances, particularly `HTMLDocumentParser` and `XMLDocumentParser`. Handles document opening, closing, and cancellation of parsing.
4. **Frame Handling:** Detects if the document is a frameset and handles changes in `display: none` for frames.
5. **Printing:**  Manages the document's printing state, including triggering style and layout updates for printing, and handling image loading for printing.
6. **`document.open()`:** Implements the behavior of the JavaScript `document.open()` method, including security checks, parser management, and URL updates. It also manages sandbox flags inheritance (though this is being deprecated).
7. **`document.close()`:** Implements the behavior of the JavaScript `document.close()` method, signaling the end of parsing.
8. **Load Event Handling:** Manages the document's loading state, dispatching load start and complete events, and checking for document completion.
9. **Body and Head Element Access:** Provides methods to get the `body` and `head` elements of the document.
10. **Viewport Handling:** Determines the viewport-defining element based on overflow properties and containment.
11. **`beforeunload` Event:**  Dispatches the `beforeunload` event and handles its outcome.

Now, let's address the specific points in the request:

*   **Functionality Summary:** I'll list the core functionalities identified above.
*   **Relationship with JavaScript, HTML, CSS:** I'll provide examples of how these functionalities are linked to web technologies.
*   **Logical Reasoning:** I'll try to infer the logic based on the code and provide a simple scenario with assumed input and output.
*   **User/Programming Errors:** I'll identify common mistakes related to these functionalities.
*   **User Action to Execution:** I'll describe how a user's interaction can lead to this code being executed.
这是 `blink/renderer/core/dom/document.cc` 文件的第五部分，主要涉及 `Document` 类的以下功能：

**核心功能归纳：**

*   **管理辅助功能对象缓存 (AXObjectCache):**  创建、销毁、获取和刷新文档的辅助功能树。
*   **管理 Canvas 字体缓存 (CanvasFontCache):**  获取文档的 Canvas 字体缓存实例。
*   **创建和管理文档解析器 (DocumentParser):**  根据文档类型创建 HTML 或 XML 解析器，并处理解析的开始、取消和完成。
*   **处理框架集 (FrameSet):**  判断文档是否为框架集。
*   **管理脚本可控的文档解析器 (ScriptableDocumentParser):** 获取文档的脚本可控解析器。
*   **处理 `display: none` 属性对框架的影响:** 当 iframe 的 `display: none` 状态改变时，触发样式重算。
*   **处理打印 (Printing):**  管理文档的打印状态，包括加载所有图片和 iframe，调整媒体类型，更新样式和布局。
*   **实现 `document.open()` 方法:**  处理 JavaScript 中 `document.open()` 的调用，包括安全检查、URL 更新、以及与窗口的关联。
*   **实现 `document.close()` 方法:**  处理 JavaScript 中 `document.close()` 的调用，结束文档解析。
*   **处理文档加载事件:**  分发加载开始和加载完成事件。
*   **提供访问文档 body 和 head 元素的方法:**  方便地获取文档的 `body` 和 `head` 元素。
*   **确定视口定义元素 (ViewportDefiningElement):**  根据 CSS 属性判断哪个元素定义了视口。
*   **分发 `beforeunload` 事件:**  处理页面卸载前的提示。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

1. **JavaScript 和 `document.open()`:**
    *   **功能关系:**  这段代码实现了 JavaScript 中 `document.open()` 方法的具体逻辑。
    *   **举例说明:**  在 JavaScript 中调用 `document.open()` 会触发 `Document::open()` 函数的执行。例如，`document.open()` 可以清空当前文档并准备写入新的内容。
    *   **假设输入与输出:**
        *   **假设输入:** JavaScript 代码 `document.open(); document.write('<h1>Hello</h1>'); document.close();` 在浏览器中执行。
        *   **输出:** `Document::open()` 会被调用，清空当前文档，创建一个新的 HTML 解析器。随后 `document.write()` 会将 '<h1>Hello</h1>' 写入解析器。`document.close()` 调用会触发 `Document::close()`，结束解析过程，最终浏览器会显示 "Hello"。

2. **JavaScript 和 `document.close()`:**
    *   **功能关系:**  这段代码实现了 JavaScript 中 `document.close()` 方法的具体逻辑。
    *   **举例说明:**  在 JavaScript 中调用 `document.close()` 会通知文档解析器停止解析。
    *   **假设输入与输出:**
        *   **假设输入:**  在通过 `document.open()` 打开的文档中，JavaScript 代码执行 `document.close()`.
        *   **输出:** `Document::close()` 被调用，如果存在脚本创建的解析器，则会调用解析器的 `Finish()` 方法，表示解析结束。

3. **HTML 和文档解析器:**
    *   **功能关系:**  代码中的 `CreateParser()` 方法会根据文档类型（HTML 或 XML）创建相应的解析器。HTML 解析器负责将 HTML 标记转换为 DOM 树。
    *   **举例说明:**  当浏览器加载一个 HTML 页面时，Blink 引擎会创建一个 `HTMLDocumentParser` 对象（由 `Document::CreateParser()` 返回），该对象负责解析 HTML 文件的内容。

4. **CSS 和打印:**
    *   **功能关系:**  `Document::SetPrinting()` 和 `Document::InitiateStyleOrLayoutDependentLoadForPrint()` 方法与 CSS 的媒体查询 `@media print` 有关。它们会调整样式以适应打印。
    *   **举例说明:**  当用户点击浏览器的打印按钮时，会触发 `Document::SetPrinting(kPrinting)`。这会导致引擎重新计算样式，应用 `@media print` 中定义的样式，并进行布局以生成打印预览。

5. **CSS 和 `display: none`:**
    *   **功能关系:**  `Document::DisplayNoneChangedForFrame()` 方法处理 iframe 的 `display: none` 属性变化，这会影响布局树的生成。
    *   **举例说明:**  如果一个 iframe 的初始 CSS 样式是 `display: none;`，那么它的内容可能不会立即渲染到布局树中。当 JavaScript 动态地将该 iframe 的 `display` 属性改为 `block` 时，`DisplayNoneChangedForFrame()` 会被调用，触发样式重算，使得 iframe 的内容能够被渲染。

6. **HTML 和 `body` 及 `head` 元素:**
    *   **功能关系:**  `Document::body()` 和 `Document::head()` 方法提供了访问 HTML 文档中 `<body>` 和 `<head>` 元素的接口。
    *   **举例说明:**  JavaScript 代码可以通过 `document.body` 访问 `<body>` 元素，而 Blink 引擎内部的实现就是通过调用 `Document::body()` 来获取该元素的。

**用户或编程常见的使用错误举例说明：**

1. **在自定义元素构造函数中使用 `document.open()`:**
    *   **错误:** 在自定义元素的构造函数中调用 `document.open()` 会导致 `throw_on_dynamic_markup_insertion_count_` 大于 0，从而在 `Document::open()` 中抛出 `InvalidStateError` 异常。
    *   **用户操作:**  开发者错误地在自定义元素的 `constructor` 中编写了类似 `this.attachShadow({mode: 'open'}).innerHTML = '...'; document.open(); document.write('...'); document.close();` 的代码。
    *   **调试线索:** 浏览器控制台会显示 "InvalidStateError: Custom Element constructor should not use open()." 错误信息。

2. **在 XML 文档上调用 `document.open()` 或 `document.close()`:**
    *   **错误:** `Document::open()` 和 `Document::close()` 都会检查文档类型，如果不是 HTML 文档，则会抛出 `InvalidStateError` 异常。
    *   **用户操作:**  开发者尝试在一个 XML 文档上调用 `document.open()`，例如通过 AJAX 加载了一个 XML 文件后执行 `xmlDoc.open()`。
    *   **调试线索:** 浏览器控制台会显示 "InvalidStateError: Only HTML documents support open()." 或 "InvalidStateError: Only HTML documents support close()." 错误信息。

3. **在页面卸载过程中调用 `document.open()`:**
    *   **错误:**  在 `beforeunload` 或 `unload` 事件处理程序中调用 `document.open()` 可能会被浏览器忽略或导致不可预测的行为，因为此时文档状态正在变化。
    *   **用户操作:**  开发者在 `window.addEventListener('beforeunload', function() { document.open(); ... });` 中尝试打开一个新的文档。
    *   **调试线索:**  这种错误可能不会立即抛出异常，但新的文档可能无法正确加载或替换当前页面。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **加载 HTML 页面:** 用户在浏览器地址栏输入网址或点击链接，浏览器开始加载 HTML 文档。
    *   **调试线索:** 可以在网络面板查看请求，确认 HTML 文档被成功下载。

2. **解析 HTML 内容:**  Blink 引擎会创建 `HTMLDocumentParser` 并开始解析下载的 HTML 内容。
    *   **调试线索:**  可以在 Performance 面板或 Tracing 工具中看到 "Parse HTML" 的活动。

3. **执行 JavaScript 代码:**  HTML 中嵌入的 `<script>` 标签或外部 JavaScript 文件被加载和执行。
    *   **调试线索:**  可以在 Sources 面板设置断点，观察 JavaScript 代码的执行流程。

4. **调用 `document.open()` 或 `document.close()`:**  JavaScript 代码中可能调用了 `document.open()` 来清空文档并写入新的内容，或者调用 `document.close()` 来结束解析过程。
    *   **调试线索:**  在 Sources 面板中，可以单步执行 JavaScript 代码，观察 `document.open()` 或 `document.close()` 的调用。同时可以在 Console 面板输出相关信息。

5. **触发打印:** 用户点击浏览器的打印按钮或调用 `window.print()` 方法。
    *   **调试线索:**  可以在 Performance 面板或 Tracing 工具中看到与 "Print" 相关的活动。

6. **iframe 的 `display` 属性变化:**  JavaScript 代码可能会动态修改 iframe 的 `display` 属性。
    *   **调试线索:**  可以在 Elements 面板中观察 iframe 元素的样式变化，或者在 JavaScript 代码中设置断点。

7. **页面卸载:** 用户关闭标签页、点击后退按钮或输入新的网址导航到其他页面。
    *   **调试线索:**  可以在 Sources 面板中设置 `beforeunload` 或 `unload` 事件的断点，观察事件处理函数的执行。

通过以上调试线索，可以逐步跟踪用户操作和代码执行流程，定位到 `blink/renderer/core/dom/document.cc` 文件中相关功能的执行。例如，如果在控制台中看到 `InvalidStateError` 并提示与 `document.open()` 相关，可以检查导致 `document.open()` 调用的 JavaScript 代码，确认是否在不合适的时机或对非 HTML 文档进行了调用。

Prompt: 
```
这是目录为blink/renderer/core/dom/document.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共11部分，请归纳一下它的功能

"""
XObjectCacheOwner(), this);

  DCHECK_EQ(ax_contexts_.size(), 0U);

  // Clear the cache member variable before calling delete because attempts
  // are made to access it during destruction.
  if (ax_object_cache_) {
    ax_object_cache_->Dispose();
    ax_object_cache_.Clear();
    DCHECK_NE(g_ax_object_cache_count, 0u);
    g_ax_object_cache_count--;
  }
}

AXObjectCache* Document::ExistingAXObjectCache() const {
  DCHECK(IsMainThread());
  if (g_ax_object_cache_count == 0) {
    return nullptr;
  }

  auto& cache_owner = AXObjectCacheOwner();

  // If the LayoutView is gone then we are in the process of destruction.
  if (!cache_owner.GetLayoutView())
    return nullptr;

  return cache_owner.ax_object_cache_.Get();
}

void Document::RefreshAccessibilityTree() const {
  if (AXObjectCache* cache = ExistingAXObjectCache()) {
    cache->MarkDocumentDirty();
  }
}

CanvasFontCache* Document::GetCanvasFontCache() {
  if (!canvas_font_cache_)
    canvas_font_cache_ = MakeGarbageCollected<CanvasFontCache>(*this);

  return canvas_font_cache_.Get();
}

DocumentParser* Document::CreateParser() {
  if (auto* html_document = DynamicTo<HTMLDocument>(this)) {
    return MakeGarbageCollected<HTMLDocumentParser>(*html_document,
                                                    parser_sync_policy_);
  }
  // FIXME: this should probably pass the frame instead
  return MakeGarbageCollected<XMLDocumentParser>(*this, View());
}

bool Document::IsFrameSet() const {
  if (!IsA<HTMLDocument>(this))
    return false;
  return IsA<HTMLFrameSetElement>(body());
}

ScriptableDocumentParser* Document::GetScriptableDocumentParser() const {
  return Parser() ? Parser()->AsScriptableDocumentParser() : nullptr;
}

void Document::DisplayNoneChangedForFrame() {
  if (!documentElement())
    return;
  // LayoutView()::CanHaveChildren(), hence the existence of style and
  // layout tree, depends on the owner being display:none or not. Trigger
  // detaching or attaching the style/layout-tree as a result of that
  // changing.
  documentElement()->SetNeedsStyleRecalc(
      kLocalStyleChange,
      StyleChangeReasonForTracing::Create(style_change_reason::kFrame));
}

bool Document::WillPrintSoon() {
  loading_for_print_ = LazyImageHelper::LoadAllImagesAndBlockLoadEvent(*this);

  if (auto* view = View()) {
    loading_for_print_ = loading_for_print_ || view->LoadAllLazyLoadedIframes();
  }

  loading_for_print_ =
      loading_for_print_ || InitiateStyleOrLayoutDependentLoadForPrint();

  return loading_for_print_;
}

bool Document::InitiateStyleOrLayoutDependentLoadForPrint() {
  if (auto* view = View()) {
    view->AdjustMediaTypeForPrinting(true);
    GetStyleEngine().UpdateViewportSize();
    UpdateStyleAndLayout(DocumentUpdateReason::kPrinting);
    GetStyleResolver().LoadPaginationResources();
    view->FlushAnyPendingPostLayoutTasks();

    view->AdjustMediaTypeForPrinting(false);
    GetStyleEngine().UpdateViewportSize();
    UpdateStyleAndLayout(DocumentUpdateReason::kPrinting);

    return fetcher_->BlockingRequestCount() > 0;
  }

  return false;
}

void Document::SetPrinting(PrintingState state) {
  bool was_printing = Printing();
  printing_ = state;
  bool is_printing = Printing();

  if (was_printing != is_printing) {
    GetDisplayLockDocumentState().NotifyPrintingOrPreviewChanged();

    // We force the color-scheme to light for printing.
    ColorSchemeChanged();
    // StyleResolver::InitialStyleForElement uses different zoom for printing.
    GetStyleEngine().MarkViewportStyleDirty();
    // Separate UA sheet for printing.
    GetStyleEngine().MarkAllElementsForStyleRecalc(
        StyleChangeReasonForTracing::Create(style_change_reason::kPrinting));

    if (documentElement() && GetFrame() && !GetFrame()->IsMainFrame() &&
        GetFrame()->Owner() && GetFrame()->Owner()->IsDisplayNone()) {
      // In non-printing mode we do not generate style or layout objects for
      // display:none iframes, yet we do when printing (see
      // LayoutView::CanHaveChildren). Trigger a style recalc on the root
      // element to create a layout tree for printing.
      DisplayNoneChangedForFrame();
    }
  }
}

// https://html.spec.whatwg.org/C/dynamic-markup-insertion.html#document-open-steps
void Document::open(LocalDOMWindow* entered_window,
                    ExceptionState& exception_state) {
  // If |document| is an XML document, then throw an "InvalidStateError"
  // DOMException exception.
  if (!IsA<HTMLDocument>(this)) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "Only HTML documents support open().");
    return;
  }

  // If |document|'s throw-on-dynamic-markup-insertion counter is greater than
  // 0, then throw an "InvalidStateError" DOMException.
  if (throw_on_dynamic_markup_insertion_count_) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "Custom Element constructor should not use open().");
    return;
  }

  if (entered_window && !entered_window->GetFrame())
    return;

  // If |document|'s origin is not same origin to the origin of the responsible
  // document specified by the entry settings object, then throw a
  // "SecurityError" DOMException.
  if (entered_window && GetExecutionContext() &&
      !GetExecutionContext()->GetSecurityOrigin()->IsSameOriginWith(
          entered_window->GetSecurityOrigin())) {
    exception_state.ThrowSecurityError(
        "Can only call open() on same-origin documents.");
    return;
  }

  // If |document| has an active parser whose script nesting level is greater
  // than 0, then return |document|.
  if (ScriptableDocumentParser* parser = GetScriptableDocumentParser()) {
    if (parser->IsParsing() && parser->IsExecutingScript())
      return;
  }

  // Similarly, if |document|'s ignore-opens-during-unload counter is greater
  // than 0, then return |document|.
  if (ignore_opens_during_unload_count_)
    return;

  // If |document|'s active parser was aborted is true, then return |document|.
  if (ignore_opens_and_writes_for_abort_)
    return;

  if (cookie_jar_) {
    // open() can affect security context which can change cookie values. Make
    // sure cached values are thrown out. see
    // third_party/blink/web_tests/http/tests/security/aboutBlank/.
    cookie_jar_->InvalidateCache();
  }

  // If this document is fully active, then update the URL
  // for this document with the entered window's url.
  if (dom_window_ && entered_window) {
    KURL new_url = entered_window->Url();
    if (new_url.IsAboutBlankURL()) {
      // When updating the URL to about:blank due to a document.open() call,
      // the opened document should also end up with the same base URL as the
      // opener about:blank document. Propagate the fallback information here
      // so that SetURL() below will take it into account.
      fallback_base_url_ = entered_window->BaseURL();
    }
    // Clear the hash fragment from the inherited URL to prevent a
    // scroll-into-view for any document.open()'d frame.
    if (dom_window_ != entered_window) {
      new_url.SetFragmentIdentifier(String());
    }
    // If an about:srcdoc frame .open()s another frame, then we don't set the
    // url, and we leave the value of `is_srcdoc_document` untouched. Otherwise
    // we should reset `is_srcdoc_document_`.
    if (!new_url.IsAboutSrcdocURL()) {
      is_srcdoc_document_ = false;
      SetURL(new_url);
    }
    if (Loader())
      Loader()->DidOpenDocumentInputStream(new_url);

    if (dom_window_ != entered_window) {
      // 2023-03-28: Page use is 0.1%. Too much for a removal.
      // https://chromestatus.com/metrics/feature/timeline/popularity/4374
      CountUse(WebFeature::kDocumentOpenDifferentWindow);

      if ((dom_window_->GetSecurityContext().GetSandboxFlags() |
           entered_window->GetSandboxFlags()) !=
          dom_window_->GetSecurityContext().GetSandboxFlags()) {
        // 2023-03-28. Page use is 0.000005%. Most of the days, it is not even
        //             recorded. Ready for removal!
        // https://chromestatus.com/metrics/feature/timeline/popularity/4375
        CountUse(WebFeature::kDocumentOpenMutateSandbox);
      }

      if (!RuntimeEnabledFeatures::
              DocumentOpenSandboxInheritanceRemovalEnabled()) {
        // We inherit the sandbox flags of the entered document, so mask on
        // the ones contained in the CSP. The operator| is a bitwise operation
        // on the sandbox flags bits. It makes the sandbox policy stricter (or
        // as strict) as both policy.
        //
        // TODO(arthursonzogni): Why merging sandbox flags?
        // This doesn't look great at many levels:
        // - The browser process won't be notified of the update.
        // - The origin won't be made opaque, despite the new flags.
        // - The sandbox flags of the document can't be considered to be an
        //   immutable property anymore.
        //
        // Ideally:
        // - javascript-url document.
        // - XSLT document.
        // - document.open.
        // should not mutate the security properties of the current document.
        // From the browser process point of view, all of those operations are
        // not considered to produce new documents. No IPCs are sent, it is as
        // if it was a no-op.
        //
        // TODO(https://crbug.com/1360795) Remove this. Only Chrome implements
        // it. Safari/Firefox do not.
        dom_window_->GetSecurityContext().SetSandboxFlags(
            dom_window_->GetSecurityContext().GetSandboxFlags() |
            entered_window->GetSandboxFlags());
      }

      // We would like to remove this block. See:
      // https://docs.google.com/document/d/1_89X4cNUab-PZE0iBDTKIftaQZsFbk7SbFmHbqY54os
      //
      // This is not specified. Only Webkit/Blink implement it. Gecko doesn't.
      //
      // 2023-06-02: Removal would impact 0.02% page load.
      // https://chromestatus.com/metrics/feature/timeline/popularity/4535
      // We hope the document.domain deprecation is going to drive this number
      // down quickly:
      // https://developer.chrome.com/blog/document-domain-setter-deprecation/
      if (!RuntimeEnabledFeatures::DocumentOpenOriginAliasRemovalEnabled()) {
        dom_window_->GetSecurityContext().SetSecurityOrigin(
            entered_window->GetMutableSecurityOrigin());

        // The SecurityOrigin is now shared in between two different window. It
        // means mutating one can have side effect on the other.
        entered_window->GetMutableSecurityOrigin()
            ->set_aliased_by_document_open();
      }

      // Question: Should we remove the inheritance of the CookieURL via
      // document.open?
      //
      // Arguments in favor of maintaining this behavior include the fact that
      // document.open can be used to alter the document's URL. According to
      // prior talks, this is necessary for web compatibility. It looks nicer if
      // all URL variations change uniformly and simultaneously.
      //
      // Arguments in favor of eliminating this behavior include the fact that
      // cookie URLs are extremely particular pieces of state that resemble the
      // origin more than they do actual URLs. The less we inherit via
      // document.open, the better.
      cookie_url_ = entered_window->document()->CookieURL();
    }
  }

  open();
}

// https://html.spec.whatwg.org/C/dynamic-markup-insertion.html#document-open-steps
void Document::open() {
  DCHECK(!ignore_opens_during_unload_count_);
  if (ScriptableDocumentParser* parser = GetScriptableDocumentParser())
    DCHECK(!parser->IsParsing() || !parser->IsExecutingScript());

  // If |document| has a browsing context and there is an existing attempt to
  // navigate |document|'s browsing context, then stop document loading given
  // |document|.
  //
  // As noted in the spec and https://github.com/whatwg/html/issues/3975, we
  // want to treat ongoing navigation and queued navigation the same way.
  // However, we don't want to consider navigations scheduled too much into the
  // future through Refresh headers or a <meta> refresh pragma to be a current
  // navigation. Thus, we cut it off with
  // IsHttpRefreshScheduledWithin(base::TimeDelta()).
  //
  // This also prevents window.open(url) -- eg window.open("about:blank") --
  // from blowing away results from a subsequent window.document.open /
  // window.document.write call.
  if (GetFrame() && (GetFrame()->Loader().HasProvisionalNavigation() ||
                     IsHttpRefreshScheduledWithin(base::TimeDelta()))) {
    GetFrame()->Loader().StopAllLoaders(/*abort_client=*/true);
  }
  CancelPendingJavaScriptUrls();

  // TODO(crbug.com/1085514): Consider making HasProvisionalNavigation() return
  // true when form submission task is active, in which case we can delete this
  // redundant attempt to cancel it.
  if (GetFrame())
    GetFrame()->CancelFormSubmission();

  // For each shadow-including inclusive descendant |node| of |document|, erase
  // all event listeners and handlers given |node|.
  //
  // Erase all event listeners and handlers given |window|.
  //
  // NB: Document::RemoveAllEventListeners() (called by
  // RemoveAllEventListenersRecursively()) erases event listeners from the
  // Window object as well.
  RemoveAllEventListenersRecursively();

  // Create a new HTML parser and associate it with |document|.
  //
  // Set the current document readiness of |document| to "loading".
  ImplicitOpen(kForceSynchronousParsing);

  // This is a script-created parser.
  if (ScriptableDocumentParser* parser = GetScriptableDocumentParser())
    parser->SetWasCreatedByScript(true);

  // Calling document.open counts as committing the first real document load.
  is_initial_empty_document_ = false;
  if (GetFrame())
    GetFrame()->Loader().DidExplicitOpen();
}

void Document::DetachParser() {
  if (!parser_)
    return;
  parser_->Detach();
  parser_.Clear();
  DocumentParserTiming::From(*this).MarkParserDetached();
}

void Document::CancelParsing() {
  TRACE_EVENT_WITH_FLOW0("blink", "Document::CancelParsing",
                         TRACE_ID_LOCAL(this),
                         TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT);
  // There appears to be an unspecced assumption that a document.open()
  // or document.write() immediately after a navigation start won't cancel
  // the navigation. Firefox avoids cancelling the navigation by ignoring an
  // open() or write() after an active parser is aborted. See
  // https://github.com/whatwg/html/issues/4723 for discussion about
  // standardizing this behavior.
  if (parser_ && parser_->IsParsing()) {
    ignore_opens_and_writes_for_abort_ = true;
    if (GetFrame()) {
      // Only register the sticky feature when the parser was parsing and then
      // was cancelled.
      GetFrame()->GetFrameScheduler()->RegisterStickyFeature(
          SchedulingPolicy::Feature::kParserAborted,
          {SchedulingPolicy::DisableBackForwardCache()});
    }
  }
  DetachParser();
  SetParsingState(kFinishedParsing);
  SetReadyState(kComplete);
  if (!LoadEventFinished())
    load_event_progress_ = kLoadEventCompleted;
  CancelPendingJavaScriptUrls();
  http_refresh_scheduler_->Cancel();
}

DocumentParser* Document::OpenForNavigation(
    ParserSynchronizationPolicy parser_sync_policy,
    const AtomicString& mime_type,
    const AtomicString& encoding) {
  TRACE_EVENT_WITH_FLOW0("blink", "Document::OpenForNavigation",
                         TRACE_ID_LOCAL(this),
                         TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT);
  DocumentParser* parser = ImplicitOpen(parser_sync_policy);
  if (parser->NeedsDecoder()) {
    parser->SetDecoder(
        BuildTextResourceDecoder(GetFrame(), Url(), mime_type, encoding));
  }
  if (!GetFrame()->IsProvisional()) {
    anchor_element_interaction_tracker_ =
        MakeGarbageCollected<AnchorElementInteractionTracker>(*this);
  }
  return parser;
}

DocumentParser* Document::ImplicitOpen(
    ParserSynchronizationPolicy parser_sync_policy) {
  RemoveChildren();
  DCHECK(!focused_element_);

  SetCompatibilityMode(kNoQuirksMode);

  bool force_sync_policy = false;
  // Give inspector a chance to force sync parsing when virtual time is on.
  probe::WillCreateDocumentParser(this, force_sync_policy);
  // Prefetch must be synchronous.
  force_sync_policy |= ForceSynchronousParsingForTesting() || IsPrefetchOnly();
  if (force_sync_policy)
    parser_sync_policy = kForceSynchronousParsing;
  DetachParser();
  parser_sync_policy_ = parser_sync_policy;
  parser_ = CreateParser();
  DocumentParserTiming::From(*this).MarkParserStart();
  SetParsingState(kParsing);
  SetReadyState(kLoading);
  if (load_event_progress_ != kLoadEventInProgress &&
      PageDismissalEventBeingDispatched() == kNoDismissal) {
    load_event_progress_ = kLoadEventNotRun;
  }
  DispatchHandleLoadStart();
  return parser_.Get();
}

void Document::DispatchHandleLoadStart() {
  if (AXObjectCache* cache = ExistingAXObjectCache())
    cache->HandleLoadStart(this);
}

void Document::DispatchHandleLoadComplete() {
  if (AXObjectCache* cache = ExistingAXObjectCache())
    cache->HandleLoadComplete(this);
}

HTMLElement* Document::body() const {
  if (!IsA<HTMLHtmlElement>(documentElement()))
    return nullptr;

  for (HTMLElement* child =
           Traversal<HTMLElement>::FirstChild(*documentElement());
       child; child = Traversal<HTMLElement>::NextSibling(*child)) {
    if (IsA<HTMLFrameSetElement>(*child) || IsA<HTMLBodyElement>(*child))
      return child;
  }

  return nullptr;
}

HTMLBodyElement* Document::FirstBodyElement() const {
  if (!IsA<HTMLHtmlElement>(documentElement()))
    return nullptr;

  for (HTMLElement* child =
           Traversal<HTMLElement>::FirstChild(*documentElement());
       child; child = Traversal<HTMLElement>::NextSibling(*child)) {
    if (auto* body = DynamicTo<HTMLBodyElement>(*child))
      return body;
  }

  return nullptr;
}

void Document::setBody(HTMLElement* prp_new_body,
                       ExceptionState& exception_state) {
  HTMLElement* new_body = prp_new_body;

  if (!new_body) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kHierarchyRequestError,
        ExceptionMessages::ArgumentNullOrIncorrectType(1, "HTMLElement"));
    return;
  }
  if (!documentElement()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kHierarchyRequestError,
                                      "No document element exists.");
    return;
  }

  if (!IsA<HTMLBodyElement>(*new_body) &&
      !IsA<HTMLFrameSetElement>(*new_body)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kHierarchyRequestError,
        "The new body element is of type '" + new_body->tagName() +
            "'. It must be either a 'BODY' or 'FRAMESET' element.");
    return;
  }

  HTMLElement* old_body = body();
  if (old_body == new_body)
    return;

  if (old_body)
    documentElement()->ReplaceChild(new_body, old_body, exception_state);
  else
    documentElement()->AppendChild(new_body, exception_state);
}

void Document::WillInsertBody() {
  if (Loader())
    fetcher_->LoosenLoadThrottlingPolicy();

  if (auto* supplement = ViewTransitionSupplement::FromIfExists(*this)) {
    supplement->WillInsertBody();
  }

  if (render_blocking_resource_manager_) {
    render_blocking_resource_manager_->WillInsertDocumentBody();
  }

  // If we get to the <body> try to resume commits since we should have content
  // to paint now.
  // TODO(esprehn): Is this really optimal? We might start producing frames
  // for very little content, should we wait for some heuristic like
  // isVisuallyNonEmpty() ?
  BeginLifecycleUpdatesIfRenderingReady();
}

HTMLHeadElement* Document::head() const {
  Node* de = documentElement();
  if (!de)
    return nullptr;

  return Traversal<HTMLHeadElement>::FirstChild(*de);
}

Element* Document::ViewportDefiningElement() const {
  // If a BODY element sets non-visible overflow, it is to be propagated to the
  // viewport, as long as the following conditions are all met:
  // (1) The root element is HTML.
  // (2) It is the primary BODY element.
  // (3) The root element has visible overflow.
  // (4) The root or BODY elements do not apply any containment.
  // Otherwise it's the root element's properties that are to be propagated.

  // This method is called in the middle of a lifecycle update, for instance
  // from a LayoutObject which is created but not yet inserted into the box
  // tree, which is why we have to do the decision based on the ComputedStyle
  // and not the LayoutObject style and the containment checks below also.

  Element* root_element = documentElement();
  if (!root_element)
    return nullptr;
  const ComputedStyle* root_style = root_element->GetComputedStyle();
  if (!root_style || root_style->IsEnsuredInDisplayNone())
    return nullptr;
  if (!root_style->IsOverflowVisibleAlongBothAxes())
    return root_element;
  HTMLBodyElement* body_element = FirstBodyElement();
  if (!body_element)
    return root_element;
  const ComputedStyle* body_style = body_element->GetComputedStyle();
  if (!body_style || body_style->IsEnsuredInDisplayNone())
    return root_element;
  if (root_style->ShouldApplyAnyContainment(*root_element) ||
      body_style->ShouldApplyAnyContainment(*body_element)) {
    return root_element;
  }
  return body_element;
}

Document* Document::open(v8::Isolate* isolate,
                         const AtomicString& type,
                         const AtomicString& replace,
                         ExceptionState& exception_state) {
  if (replace == "replace") {
    CountUse(WebFeature::kDocumentOpenTwoArgsWithReplace);
  }
  open(EnteredDOMWindow(isolate), exception_state);
  return this;
}

DOMWindow* Document::open(v8::Isolate* isolate,
                          const String& url_string,
                          const AtomicString& name,
                          const AtomicString& features,
                          ExceptionState& exception_state) {
  if (!domWindow()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidAccessError,
                                      "The document has no window associated.");
    return nullptr;
  }

  return domWindow()->open(isolate, url_string, name, features,
                           exception_state);
}

// https://html.spec.whatwg.org/C/dynamic-markup-insertion.html#dom-document-close
void Document::close(ExceptionState& exception_state) {
  // If the Document object is an XML document, then throw an
  // "InvalidStateError" DOMException.
  if (!IsA<HTMLDocument>(this)) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "Only HTML documents support close().");
    return;
  }

  // If the Document object's throw-on-dynamic-markup-insertion counter is
  // greater than zero, then throw an "InvalidStateError" DOMException.
  if (throw_on_dynamic_markup_insertion_count_) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "Custom Element constructor should not use close().");
    return;
  }

  close();
}

// https://html.spec.whatwg.org/C/dynamic-markup-insertion.html#dom-document-close
void Document::close() {
  // If there is no script-created parser associated with the document, then
  // return.
  if (!GetScriptableDocumentParser() ||
      !GetScriptableDocumentParser()->WasCreatedByScript() ||
      !GetScriptableDocumentParser()->IsParsing())
    return;

  // Insert an explicit "EOF" character at the end of the parser's input
  // stream.
  parser_->Finish();

  // TODO(timothygu): We should follow the specification more closely.
  if (!parser_ || !parser_->IsParsing())
    SetReadyState(kComplete);
  CheckCompleted();
}

void Document::ImplicitClose() {
  DCHECK(!InStyleRecalc());

  load_event_progress_ = kLoadEventInProgress;

  // We have to clear the parser, in case someone document.write()s from the
  // onLoad event handler, as in Radar 3206524.
  DetachParser();

  // JS running below could remove the frame or destroy the LayoutView so we
  // call those two functions repeatedly and don't save them on the stack.

  // To align the HTML load event and the SVGLoad event for the outermost <svg>
  // element, fire it from here, instead of doing it from
  // SVGElement::finishedParsingChildren.
  if (SvgExtensions())
    AccessSVGExtensions().DispatchSVGLoadEventToOutermostSVGElements();

  if (domWindow())
    domWindow()->DocumentWasClosed();

  if (GetFrame() && GetFrame()->IsMainFrame())
    GetFrame()->GetLocalFrameHostRemote().DocumentOnLoadCompleted();

  if (GetFrame()) {
    GetFrame()->Client()->DispatchDidHandleOnloadEvents();
  }

  if (!GetFrame()) {
    load_event_progress_ = kLoadEventCompleted;
    return;
  }

  if (GetFrame()->Loader().HasProvisionalNavigation() &&
      start_time_.Elapsed() < kCLayoutScheduleThreshold) {
    // Just bail out. Before or during the onload we were shifted to another
    // page.  The old i-Bench suite does this. When this happens don't bother
    // painting or laying out.
    load_event_progress_ = kLoadEventCompleted;
    return;
  }

  if (HaveRenderBlockingStylesheetsLoaded()) {
    // The initial empty document might be loaded synchronously.
    // When this occurs and we also synchronously update the style and layout
    // here, which is needed for things like autofill, it creates a chain
    // reaction where inserting iframes without a src to a document causes
    // expensive layout thrashing of the embedding document. Since this is a
    // common scenario, special-casing it here, and avoiding that layout if
    // this is an initial-empty document in a subframe.
    if (!base::FeatureList::IsEnabled(
            features::kAvoidForcedLayoutOnInitialEmptyDocumentInSubframe) ||
        Loader()->HasLoadedNonInitialEmptyDocument() ||
        GetFrame()->IsMainFrame()) {
      UpdateStyleAndLayout(DocumentUpdateReason::kUnknown);
    }
  }

  load_event_progress_ = kLoadEventCompleted;

  if (GetFrame() && GetLayoutView()) {
    DispatchHandleLoadComplete();
    FontFaceSetDocument::DidLayout(*this);
  }

  if (SvgExtensions())
    AccessSVGExtensions().StartAnimations();
}

static bool AllDescendantsAreComplete(Document* document) {
  Frame* frame = document->GetFrame();
  if (!frame)
    return true;

  for (Frame* child = frame->Tree().FirstChild(); child;
       child = child->Tree().TraverseNext(frame)) {
    if (child->IsLoading())
      return false;
  }

  return true;
}

bool Document::ShouldComplete() {
  return parsing_state_ == kFinishedParsing &&
         !fetcher_->BlockingRequestCount() && !IsDelayingLoadEvent() &&
         !javascript_url_task_handle_.IsActive() &&
         load_event_progress_ != kLoadEventInProgress &&
         AllDescendantsAreComplete(this) && !Fetcher()->IsInRequestResource();
}

void Document::Abort() {
  CancelParsing();
  CheckCompletedInternal();
}

void Document::CheckCompleted() {
  if (CheckCompletedInternal()) {
    CHECK(GetFrame());
    GetFrame()->Loader().DidFinishNavigation(
        FrameLoader::NavigationFinishState::kSuccess);
  }
}

void Document::FetchDictionaryFromLinkHeader() {
  if (!CompressionDictionaryTransportFullyEnabled(GetExecutionContext()) ||
      !Loader()) {
    return;
  }
  Loader()->DispatchLinkHeaderPreloads(
      nullptr /* viewport */,
      PreloadHelper::LoadLinksFromHeaderMode::kDocumentAfterLoadCompleted);
}

bool Document::CheckCompletedInternal() {
  if (!ShouldComplete())
    return false;

  if (GetFrame() && !UnloadStarted()) {
    GetFrame()->Client()->RunScriptsAtDocumentIdle();

    // Injected scripts may have disconnected this frame.
    if (!GetFrame())
      return false;

    // Check again, because runScriptsAtDocumentIdle() may have delayed the load
    // event.
    if (!ShouldComplete())
      return false;
  }

  // OK, completed. Fire load completion events as needed.
  SetReadyState(kComplete);
  const bool load_event_needed = LoadEventStillNeeded();
  if (load_event_needed) {
    ImplicitClose();
  }

  DCHECK(fetcher_);

  fetcher_->ScheduleWarnUnusedPreloads(
      WTF::BindOnce(&Document::OnWarnUnusedPreloads, WrapWeakPersistent(this)));

  // The readystatechanged or load event may have disconnected this frame.
  if (!GetFrame() || !GetFrame()->IsAttached())
    return false;
  http_refresh_scheduler_->MaybeStartTimer();
  View()->HandleLoadCompleted();
  // The document itself is complete, but if a child frame was restarted due to
  // an event, this document is still considered to be in progress.
  if (!AllDescendantsAreComplete(this))
    return false;

  // No need to repeat if we've already notified this load as finished.
  if (!Loader()->SentDidFinishLoad()) {
    if (GetFrame()->IsOutermostMainFrame()) {
      GetViewportData().GetViewportDescription().ReportMobilePageStats(
          GetFrame());
    }
    Loader()->SetSentDidFinishLoad();
    GetFrame()->Client()->DispatchDidFinishLoad();
    // RenderFrameObservers may execute script, which could detach this frame.
    if (!GetFrame())
      return false;
    GetFrame()->GetLocalFrameHostRemote().DidFinishLoad(Loader()->Url());

    GetFrame()->GetFrameScheduler()->RegisterStickyFeature(
        SchedulingPolicy::Feature::kDocumentLoaded,
        {SchedulingPolicy::DisableBackForwardCache()});

    DetectJavascriptFrameworksOnLoad(*this);
    // Only load the dictionary after the full document load completes.
    // The compression dictionary is of low priority and shall be only loaded
    // when the browser is idle.
    FetchDictionaryFromLinkHeader();
  } else if (loading_for_print_) {
    loading_for_print_ = false;
    GetFrame()->Client()->DispatchDidFinishLoadForPrinting();
    // Refresh the page when the print preview pops up.
    // DispatchDidFinishLoadForPrinting could detach this frame
    if (!GetFrame()) {
      return false;
    }
  }

  if (auto* view = View()) {
    if (view->GetFragmentAnchor()) {
      // Schedule an animation frame to process fragment anchors. The frame
      // can't be scheduled when the fragment anchor is set because, per spec,
      // we must wait for the document to be loaded before invoking fragment
      // anchors.
      View()->ScheduleAnimation();
    }
  }

  if (load_event_needed) {
    if (LCPCriticalPathPredictor* lcpp = GetFrame()->GetLCPP()) {
      lcpp->OnOutermostMainFrameDocumentLoad();
      fetcher_->MaybeRecordLCPPSubresourceMetrics(Url());
    }
  }

  return true;
}

namespace {

enum class BeforeUnloadUse {
  kNoDialogNoText,
  kNoDialogNoUserGesture,
  kNoDialogMultipleConfirmationForNavigation,
  kShowDialog,
  kNoDialogAutoCancelTrue,
  kNotSupportedInDocumentPictureInPicture,
  kMaxValue = kNotSupportedInDocumentPictureInPicture,
};

void RecordBeforeUnloadUse(BeforeUnloadUse metric) {
  base::UmaHistogramEnumeration("Document.BeforeUnloadDialog", metric);
}

}  // namespace

bool Document::DispatchBeforeUnloadEvent(ChromeClient* chrome_client,
                                         bool is_reload,
                                         bool& did_allow_navigation) {
  TRACE_EVENT_WITH_FLOW0("blink", "Document::DispatchBeforeUnloadEvent",
                         TRACE_ID_LOCAL(this),
                         TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT);
  if (!dom_window_)
    return true;

  if (!body())
    return true;

  if (ProcessingBeforeUnload())
    return false;

  if (dom_window_->IsPictureInPictureWindow()) {
    RecordBeforeUnloadUse(
        BeforeUnloadUse::kNotSupportedInDocumentPictureInPicture);
    return true;
  }

  // Since we do not allow registering the beforeunload event handlers in
  // fenced frames, it should not be fired by fencedframes.
  DCHECK(!GetFrame() || !GetFrame()->IsInFencedFrameTree() ||
         !GetEventTargetData() ||
         !GetEventTargetData()->event_listener_map.Contains(
             event_type_names::kBeforeunload));

  PageDismissalScope in_page_dismissal;
  auto& before_unload_event = *MakeGarbageCollected<BeforeUnloadEvent>();
  before_unload_event.initEvent(event_type_names::kBeforeunload, false, true);

  {
    // We want to avoid progressing to kBeforeUnloadEventHandled if the page
    // cancels the unload. Because a subframe may cancel unload on our behalf,
    // only the caller, which makes this call over the frame subtree, can know
    // whether or not  we'll unload so the caller is responsible for advancing
    // to kBeforeUnloadEventHandled. Here, we'll reset back to our prior value
    // once the handler 
"""


```