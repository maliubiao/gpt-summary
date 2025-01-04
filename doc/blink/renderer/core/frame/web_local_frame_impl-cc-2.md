Response:
The user wants a summary of the functionality of the provided C++ code snippet from `web_local_frame_impl.cc`.

The code primarily deals with:
1. **Input Method Editor (IME) handling:**  Functions for managing IME text spans (underlines, etc.) during text composition.
2. **Selection manipulation:** Extending and deleting selections.
3. **Text replacement and deletion:**  Functions for deleting and replacing text around the current selection point.
4. **Printing:** Functions to initiate and control the printing process, including handling plugins and dispatching print events.
5. **Paint Preview:** Functionality for capturing a paint preview of the frame's content.
6. **Testing utilities:** Methods for getting selection bounds, viewport position, and spooling sizes for testing purposes.

The request also asks for connections to JavaScript, HTML, and CSS, logical reasoning examples, and common user errors.

**Plan:**
1. Summarize each function's purpose.
2. Identify connections to web technologies (JavaScript, HTML, CSS).
3. Create examples for logical reasoning (input/output).
4. Provide examples of common user/programming errors.
这是 `blink/renderer/core/frame/web_local_frame_impl.cc` 文件的第三部分，主要负责以下功能：

**1. 输入法编辑器 (IME) 处理:**

*   **`AddImeTextSpansToExistingText`:**  向已存在的文本添加 IME 文本范围 (text spans)。这些范围通常用于在用户输入过程中高亮显示或标记候选字符。
    *   **与 JavaScript 关系:**  网页可以通过 JavaScript 调用相关的 API 来影响 IME 的行为，例如设置光标位置，从而影响 `text_start` 和 `text_end`。
    *   **与 HTML 关系:**  IME 的效果会渲染在 HTML 元素中的文本上。例如，一个 `<input>` 元素正在接受 IME 输入。
    *   **与 CSS 关系:**  IME 文本范围的样式可以通过 CSS 来定义，例如下划线的颜色和样式。
    *   **假设输入与输出:**
        *   **假设输入:**  用户在 `<input>` 框中输入中文 "你好"，IME 提供了两个候选词。
        *   **输出:** `AddImeTextSpansToExistingText` 会被调用，可能添加一个下划线到 "你" 和 "好" 上，表示这些是待确定的输入。
*   **`ClearImeTextSpansByType`:**  清除指定类型的 IME 文本范围。例如，清除所有候选词的标记。
    *   **与 JavaScript 关系:**  JavaScript 可以触发清除 IME 状态的操作。
    *   **与 HTML 关系:** 清除操作会影响 HTML 元素中显示的文本的视觉效果。
    *   **与 CSS 关系:** 清除操作会移除通过 CSS 设置的与 IME 相关的样式。
    *   **假设输入与输出:**
        *   **假设输入:** 用户选择了正确的候选词，完成了输入。
        *   **输出:** `ClearImeTextSpansByType` 会被调用，移除之前用于标记候选词的下划线。
*   **`SetCompositionFromExistingText`:**  从已存在的文本中设置组合 (composition)。这通常用于在用户输入过程中选中部分文本作为输入法的输入源。
    *   **与 JavaScript 关系:** JavaScript 可以通过编程方式选中部分文本，然后触发输入法的组合操作。
    *   **与 HTML 关系:** 组合操作会影响 HTML 元素中选中文本的状态。
    *   **假设输入与输出:**
        *   **假设输入:** 用户选中了 `<p>` 标签中的 "世界" 两个字，然后调用了输入法。
        *   **输出:** `SetCompositionFromExistingText` 会被调用，将 "世界" 标记为输入法的组合文本。

**2. 文本选择和编辑:**

*   **`ExtendSelectionAndDelete`:**  扩展当前的选择并删除选中的内容。
    *   **与 JavaScript 关系:** JavaScript 可以通过 `Selection` API 获取和修改文本选择。
    *   **与 HTML 关系:**  操作会直接修改 HTML 元素中的文本内容。
    *   **常见使用错误:**  JavaScript 代码中计算 `before` 和 `after` 参数时出现错误，导致删除了错误的文本范围。 例如，计算长度时没有考虑 Unicode 字符的长度。
*   **`ExtendSelectionAndReplace`:**  扩展当前的选择并用新的文本替换选中的内容。
    *   **与 JavaScript 关系:**  JavaScript 可以控制文本选择和替换操作。
    *   **与 HTML 关系:**  操作会直接修改 HTML 元素中的文本内容。
    *   **常见使用错误:**  提供的 `replacement_text` 可能包含不合法的字符，或者与周围的 HTML 结构不兼容，导致页面渲染错误或脚本错误。
*   **`DeleteSurroundingText`:**  删除光标周围指定数量的字符。
    *   **与 JavaScript 关系:** JavaScript 可以控制光标的位置，从而影响删除的位置。
    *   **与 HTML 关系:** 操作会直接修改 HTML 元素中的文本内容。
    *   **假设输入与输出:**
        *   **假设输入:** 光标在文本 "这是一个例子" 的 "个" 字后面，`before` 为 1，`after` 为 1。
        *   **输出:**  "这是例子"。
*   **`DeleteSurroundingTextInCodePoints`:**  删除光标周围指定数量的 Unicode 代码点的字符。与 `DeleteSurroundingText` 的区别在于它处理 Unicode 代码点，这对于处理如 emoji 等多代码点字符很重要。
    *   **与 JavaScript 关系:** JavaScript 可以控制光标位置。
    *   **与 HTML 关系:** 操作会直接修改 HTML 元素中的文本内容。
    *   **假设输入与输出:**
        *   **假设输入:** 光标在一个 emoji 表情 😃 后面，`before` 为 1，`after` 为 0。
        *   **输出:** emoji 表情被删除。

**3. 打印功能:**

*   **`DispatchBeforePrintEvent`:**  分发 "beforeprint" 事件。这是一个标准的 Web API，允许网页在打印前执行一些操作。
    *   **与 JavaScript 关系:** JavaScript 可以监听 "beforeprint" 事件，并在打印前修改页面样式、内容或取消打印。
    *   **与 HTML 关系:**  该事件触发时，浏览器会对 HTML 结构进行分析，准备打印布局。
    *   **与 CSS 关系:**  JavaScript 通常会修改 CSS 样式来优化打印效果，例如隐藏不需要打印的元素。
    *   **常见使用错误:**  在 "beforeprint" 事件处理函数中执行耗时的同步操作，可能会导致打印延迟或界面冻结。
*   **`DispatchAfterPrintEvent`:** 分发 "afterprint" 事件。允许网页在打印完成后执行一些清理工作。
    *   **与 JavaScript 关系:** JavaScript 可以监听 "afterprint" 事件，恢复打印前的页面状态。
    *   **与 HTML 关系:**  事件在打印完成或取消后触发。
*   **`DispatchPrintEventRecursively`:**  递归地向所有子 Frame 分发打印事件。
*   **`FocusedPluginIfInputMethodSupported`:**  如果焦点在支持输入法的插件上，则返回该插件。
*   **`GetPluginToPrintHelper`:**  获取用于打印的插件容器。
*   **`GetPluginToPrint`:**  获取用于打印的插件。
*   **`WillPrintSoon`:**  检查文档是否即将打印。
*   **`PrintBegin`:**  开始打印过程，初始化打印上下文。
    *   **与 HTML 关系:** 浏览器会根据 HTML 结构生成打印布局。
    *   **与 CSS 关系:**  浏览器会应用打印相关的 CSS 样式（例如 `@media print`）。
*   **`PrintPage`:**  打印指定索引的页面到画布上。
*   **`PrintEnd`:**  结束打印过程，清理打印上下文。
*   **`GetPrintPresetOptionsForPlugin`:**  获取插件的打印预设选项。

**4. 捕获 Paint Preview:**

*   **`CapturePaintPreview`:**  捕获当前 Frame 的绘制预览。这通常用于生成页面的静态快照，用于性能分析或离线查看。
    *   **与 HTML 关系:**  捕获的是 HTML 渲染后的内容。
    *   **与 CSS 关系:**  CSS 样式会影响捕获到的预览效果。
    *   **假设输入与输出:**
        *   **假设输入:** 调用 `CapturePaintPreview` 函数。
        *   **输出:** `canvas` 上会绘制出当前 Frame 的渲染结果。

**5. 获取页面描述信息:**

*   **`GetPageDescription`:**  获取指定页面的描述信息，例如尺寸和方向。这通常在打印过程中使用。

**6. 测试辅助功能:**

*   **`SpoolSizeInPixelsForTesting`:**  计算用于测试的假脱机大小（像素）。
*   **`PrintPagesForTesting`:**  用于测试目的打印页面。
*   **`GetSelectionBoundsRectForTesting`:**  获取当前选择的边界矩形（用于测试）。
*   **`GetPositionInViewportForTesting`:**  获取当前 Frame 在视口中的位置（用于测试）。

**总结本部分的功能:**

这部分 `WebLocalFrameImpl` 的代码主要负责处理 **文本输入和编辑** (特别是 IME 输入)，以及 **页面打印** 和 **绘制预览** 相关的功能。它提供了底层的实现，与浏览器进程和渲染引擎的其他部分进行交互，同时暴露了一些接口供上层的 Web API (如 JavaScript) 使用。此外，还包含了一些用于测试目的的辅助功能。

Prompt: 
```
这是目录为blink/renderer/core/frame/web_local_frame_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第3部分，共5部分，请归纳一下它的功能

"""
dateStyleAndLayout
  // needs to be audited.  See http://crbug.com/590369 for more details.
  GetFrame()->GetDocument()->UpdateStyleAndLayout(
      DocumentUpdateReason::kEditing);

  input_method_controller.AddImeTextSpansToExistingText(
      ImeTextSpanVectorBuilder::Build(ime_text_spans), text_start, text_end);

  return true;
}
bool WebLocalFrameImpl::ClearImeTextSpansByType(ui::ImeTextSpan::Type type,
                                                unsigned text_start,
                                                unsigned text_end) {
  TRACE_EVENT0("blink", "WebLocalFrameImpl::ClearImeTextSpansByType");

  if (!GetFrame()->GetEditor().CanEdit())
    return false;

  InputMethodController& input_method_controller =
      GetFrame()->GetInputMethodController();

  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited.  See http://crbug.com/590369 for more details.
  GetFrame()->GetDocument()->UpdateStyleAndLayout(
      DocumentUpdateReason::kEditing);

  input_method_controller.ClearImeTextSpansByType(ConvertUiTypeToType(type),
                                                  text_start, text_end);

  return true;
}

bool WebLocalFrameImpl::SetCompositionFromExistingText(
    int composition_start,
    int composition_end,
    const WebVector<ui::ImeTextSpan>& ime_text_spans) {
  TRACE_EVENT0("blink", "WebLocalFrameImpl::setCompositionFromExistingText");
  if (EditContext* edit_context =
          GetFrame()->GetInputMethodController().GetActiveEditContext()) {
    return edit_context->SetCompositionFromExistingText(
        composition_start, composition_end, ime_text_spans);
  }

  if (!GetFrame()->GetEditor().CanEdit())
    return false;

  InputMethodController& input_method_controller =
      GetFrame()->GetInputMethodController();

  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited.  See http://crbug.com/590369 for more details.
  GetFrame()->GetDocument()->UpdateStyleAndLayout(
      DocumentUpdateReason::kEditing);

  input_method_controller.SetCompositionFromExistingText(
      ImeTextSpanVectorBuilder::Build(ime_text_spans), composition_start,
      composition_end);

  return true;
}

void WebLocalFrameImpl::ExtendSelectionAndDelete(int before, int after) {
  TRACE_EVENT0("blink", "WebLocalFrameImpl::extendSelectionAndDelete");
  if (EditContext* edit_context =
          GetFrame()->GetInputMethodController().GetActiveEditContext()) {
    edit_context->ExtendSelectionAndDelete(before, after);
    return;
  }

  if (WebPlugin* plugin = FocusedPluginIfInputMethodSupported()) {
    plugin->ExtendSelectionAndDelete(before, after);
    return;
  }

  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited.  See http://crbug.com/590369 for more details.
  GetFrame()->GetDocument()->UpdateStyleAndLayout(
      DocumentUpdateReason::kSelection);

  GetFrame()->GetInputMethodController().ExtendSelectionAndDelete(before,
                                                                  after);
}

void WebLocalFrameImpl::ExtendSelectionAndReplace(
    int before,
    int after,
    const WebString& replacement_text) {
  TRACE_EVENT0("blink", "WebLocalFrameImpl::extendSelectionAndReplace");

  // EditContext and WebPlugin do not support atomic replacement.
  if (EditContext* edit_context =
          GetFrame()->GetInputMethodController().GetActiveEditContext()) {
    edit_context->ExtendSelectionAndDelete(before, after);
    edit_context->CommitText(replacement_text, std::vector<ui::ImeTextSpan>(),
                             blink::WebRange(), 0);
    return;
  }

  if (WebPlugin* plugin = FocusedPluginIfInputMethodSupported()) {
    plugin->ExtendSelectionAndDelete(before, after);
    plugin->CommitText(replacement_text, std::vector<ui::ImeTextSpan>(),
                       blink::WebRange(), 0);
    return;
  }

  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited.  See http://crbug.com/590369 for more details.
  GetFrame()->GetDocument()->UpdateStyleAndLayout(
      DocumentUpdateReason::kSelection);

  GetFrame()->GetInputMethodController().ExtendSelectionAndReplace(
      before, after, replacement_text);
}

void WebLocalFrameImpl::DeleteSurroundingText(int before, int after) {
  TRACE_EVENT0("blink", "WebLocalFrameImpl::deleteSurroundingText");

  if (EditContext* edit_context =
          GetFrame()->GetInputMethodController().GetActiveEditContext()) {
    edit_context->DeleteSurroundingText(before, after);
    return;
  }

  if (WebPlugin* plugin = FocusedPluginIfInputMethodSupported()) {
    plugin->DeleteSurroundingText(before, after);
    return;
  }

  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited.  See http://crbug.com/590369 for more details.
  GetFrame()->GetDocument()->UpdateStyleAndLayout(
      DocumentUpdateReason::kEditing);

  GetFrame()->GetInputMethodController().DeleteSurroundingText(before, after);
}

void WebLocalFrameImpl::DeleteSurroundingTextInCodePoints(int before,
                                                          int after) {
  TRACE_EVENT0("blink", "WebLocalFrameImpl::deleteSurroundingTextInCodePoints");
  if (WebPlugin* plugin = FocusedPluginIfInputMethodSupported()) {
    plugin->DeleteSurroundingTextInCodePoints(before, after);
    return;
  }

  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited.  See http://crbug.com/590369 for more details.
  GetFrame()->GetDocument()->UpdateStyleAndLayout(
      DocumentUpdateReason::kEditing);

  GetFrame()->GetInputMethodController().DeleteSurroundingTextInCodePoints(
      before, after);
}

WebPlugin* WebLocalFrameImpl::FocusedPluginIfInputMethodSupported() {
  WebPluginContainerImpl* container = GetFrame()->GetWebPluginContainer();
  if (container && container->SupportsInputMethod())
    return container->Plugin();
  return nullptr;
}

void WebLocalFrameImpl::DispatchBeforePrintEvent(
    base::WeakPtr<WebPrintClient> print_client) {
#if DCHECK_IS_ON()
  DCHECK(!is_in_printing_) << "DispatchAfterPrintEvent() should have been "
                              "called after the previous "
                              "DispatchBeforePrintEvent() call.";
  is_in_printing_ = true;
#endif

  print_client_ = print_client;

  // Disable BackForwardCache when printing API is used for now. When the page
  // navigates with BackForwardCache, we currently do not close the printing
  // popup properly.
  GetFrame()->GetFrameScheduler()->RegisterStickyFeature(
      blink::SchedulingPolicy::Feature::kPrinting,
      {blink::SchedulingPolicy::DisableBackForwardCache()});

  GetFrame()->GetDocument()->SetPrinting(Document::kBeforePrinting);
  DispatchPrintEventRecursively(event_type_names::kBeforeprint);
  // In case the printing or print preview aborts for any reason, it is
  // important not to leave the document in the kBeforePrinting state.
  // See: crbug.com/1309595
  if (GetFrame())
    GetFrame()->GetDocument()->SetPrinting(Document::kNotPrinting);
}

void WebLocalFrameImpl::DispatchAfterPrintEvent() {
#if DCHECK_IS_ON()
  DCHECK(is_in_printing_) << "DispatchBeforePrintEvent() should be called "
                             "before DispatchAfterPrintEvent().";
  is_in_printing_ = false;
#endif

  print_client_.reset();

  if (View())
    DispatchPrintEventRecursively(event_type_names::kAfterprint);
}

void WebLocalFrameImpl::DispatchPrintEventRecursively(
    const AtomicString& event_type) {
  DCHECK(event_type == event_type_names::kBeforeprint ||
         event_type == event_type_names::kAfterprint);

  HeapVector<Member<Frame>> frames;
  for (Frame* frame = frame_; frame; frame = frame->Tree().TraverseNext(frame_))
    frames.push_back(frame);

  for (auto& frame : frames) {
    if (frame->IsRemoteFrame()) {
      // TODO(tkent): Support remote frames. crbug.com/455764.
      continue;
    }
    if (!frame->Tree().IsDescendantOf(frame_))
      continue;
    Event* event =
        event_type == event_type_names::kBeforeprint
            ? static_cast<Event*>(MakeGarbageCollected<BeforePrintEvent>())
            : static_cast<Event*>(MakeGarbageCollected<AfterPrintEvent>());
    To<LocalFrame>(frame.Get())->DomWindow()->DispatchEvent(*event);
  }
}

WebPluginContainerImpl* WebLocalFrameImpl::GetPluginToPrintHelper(
    const WebNode& constrain_to_node) {
  if (constrain_to_node.IsNull()) {
    // If this is a plugin document, check if the plugin supports its own
    // printing. If it does, we will delegate all printing to that.
    return GetFrame()->GetWebPluginContainer();
  }

  // We only support printing plugin nodes for now.
  return To<WebPluginContainerImpl>(constrain_to_node.PluginContainer());
}

WebPlugin* WebLocalFrameImpl::GetPluginToPrint(
    const WebNode& constrain_to_node) {
  WebPluginContainerImpl* plugin_container =
      GetPluginToPrintHelper(constrain_to_node);
  return plugin_container ? plugin_container->Plugin() : nullptr;
}

bool WebLocalFrameImpl::WillPrintSoon() {
  return GetFrame()->GetDocument()->WillPrintSoon();
}

uint32_t WebLocalFrameImpl::PrintBegin(const WebPrintParams& print_params,
                                       const WebNode& constrain_to_node) {
  WebPluginContainerImpl* plugin_container =
      GetPluginToPrintHelper(constrain_to_node);
  if (plugin_container && plugin_container->SupportsPaginatedPrint()) {
    print_context_ = MakeGarbageCollected<ChromePluginPrintContext>(
        GetFrame(), plugin_container);
  } else {
    print_context_ = MakeGarbageCollected<ChromePrintContext>(GetFrame());
  }

  print_context_->BeginPrintMode(print_params);

  return print_context_->PageCount();
}

void WebLocalFrameImpl::PrintPage(uint32_t page_index,
                                  cc::PaintCanvas* canvas) {
  DCHECK(print_context_);
  DCHECK(GetFrame());
  DCHECK(GetFrame()->GetDocument());

  print_context_->SpoolSinglePage(canvas, page_index);
}

void WebLocalFrameImpl::PrintEnd() {
  DCHECK(print_context_);
  print_context_->EndPrintMode();
  print_context_.Clear();
}

bool WebLocalFrameImpl::GetPrintPresetOptionsForPlugin(
    const WebNode& node,
    WebPrintPresetOptions* preset_options) {
  WebPluginContainerImpl* plugin_container = GetPluginToPrintHelper(node);
  if (!plugin_container || !plugin_container->SupportsPaginatedPrint())
    return false;

  return plugin_container->GetPrintPresetOptionsFromDocument(preset_options);
}

bool WebLocalFrameImpl::CapturePaintPreview(const gfx::Rect& bounds,
                                            cc::PaintCanvas* canvas,
                                            bool include_linked_destinations,
                                            bool skip_accelerated_content) {
  bool success = false;
  {
    // Ignore paint timing while capturing a paint preview as it can change LCP
    // see crbug.com/1323073.
    IgnorePaintTimingScope scope;
    IgnorePaintTimingScope::IncrementIgnoreDepth();

    Document::PaintPreviewScope paint_preview(
        *GetFrame()->GetDocument(),
        skip_accelerated_content
            ? Document::kPaintingPreviewSkipAcceleratedContent
            : Document::kPaintingPreview);
    GetFrame()->StartPaintPreview();
    PaintPreviewContext* paint_preview_context =
        MakeGarbageCollected<PaintPreviewContext>(GetFrame());
    success = paint_preview_context->Capture(canvas, bounds,
                                             include_linked_destinations);
    GetFrame()->EndPaintPreview();
  }
  return success;
}

WebPrintPageDescription WebLocalFrameImpl::GetPageDescription(
    uint32_t page_index) {
  if (page_index >= print_context_->PageCount()) {
    // TODO(crbug.com/452672): The number of pages may change after layout for
    // pagination. Very bad, but let's avoid crashing. The GetPageDescription()
    // API has no way of reporting failure, and the API user should be able to
    // trust that the numbers of pages reported when generating print layout
    // anyway. Due to Blink bugs, this isn't always the case, though. Get the
    // description of the first page.
    page_index = 0;
  }
  return print_context_->GetPageDescription(page_index);
}

gfx::Size WebLocalFrameImpl::SpoolSizeInPixelsForTesting(
    const WebVector<uint32_t>& pages) {
  int spool_width = 0;
  int spool_height = 0;

  for (uint32_t page_index : pages) {
    // Make room for the 1px tall page separator.
    if (page_index != pages.front())
      spool_height++;

    WebPrintPageDescription description =
        GetFrame()->GetDocument()->GetPageDescription(page_index);
    gfx::Size page_size = gfx::ToCeiledSize(description.size);
    if (description.orientation == PageOrientation::kUpright) {
      spool_width = std::max(spool_width, page_size.width());
      spool_height += page_size.height();
    } else {
      spool_height += page_size.width();
      spool_width = std::max(spool_width, page_size.height());
    }
  }
  return gfx::Size(spool_width, spool_height);
}

gfx::Size WebLocalFrameImpl::SpoolSizeInPixelsForTesting(uint32_t page_count) {
  WebVector<uint32_t> pages(page_count);
  std::iota(pages.begin(), pages.end(), 0);
  return SpoolSizeInPixelsForTesting(pages);
}

void WebLocalFrameImpl::PrintPagesForTesting(
    cc::PaintCanvas* canvas,
    const gfx::Size& spool_size_in_pixels,
    const WebVector<uint32_t>* pages) {
  DCHECK(print_context_);

  print_context_->SpoolPagesWithBoundariesForTesting(
      canvas, spool_size_in_pixels, pages);
}

gfx::Rect WebLocalFrameImpl::GetSelectionBoundsRectForTesting() const {
  DCHECK(GetFrame());  // Not valid after the Frame is detached.
  GetFrame()->View()->UpdateLifecycleToLayoutClean(
      DocumentUpdateReason::kSelection);
  return HasSelection() ? ToPixelSnappedRect(
                              GetFrame()->Selection().AbsoluteUnclippedBounds())
                        : gfx::Rect();
}

gfx::Point WebLocalFrameImpl::GetPositionInViewportForTesting() const {
  DCHECK(GetFrame());  // Not valid after the Frame is detached.
  LocalFrameView* view = GetFrameView();
  return view->ConvertToRootFrame(gfx::Point());
}

// WebLocalFrameImpl public --------------------------------------------------

WebLocalFrame* WebLocalFrame::CreateMainFrame(
    WebView* web_view,
    WebLocalFrameClient* client,
    InterfaceRegistry* interface_registry,
    CrossVariantMojoRemote<mojom::BrowserInterfaceBrokerInterfaceBase>
        interface_broker,
    const LocalFrameToken& frame_token,
    const DocumentToken& document_token,
    std::unique_ptr<WebPolicyContainer> policy_container,
    WebFrame* opener,
    const WebString& name,
    network::mojom::blink::WebSandboxFlags sandbox_flags,
    const WebURL& creator_base_url) {
  return WebLocalFrameImpl::CreateMainFrame(
      web_view, client, interface_registry, std::move(interface_broker),
      frame_token, opener, name, sandbox_flags, document_token,
      std::move(policy_container), creator_base_url);
}

WebLocalFrame* WebLocalFrame::CreateProvisional(
    WebLocalFrameClient* client,
    InterfaceRegistry* interface_registry,
    CrossVariantMojoRemote<mojom::BrowserInterfaceBrokerInterfaceBase>
        interface_broker,
    const LocalFrameToken& frame_token,
    WebFrame* previous_frame,
    const FramePolicy& frame_policy,
    const WebString& name,
    WebView* web_view) {
  return WebLocalFrameImpl::CreateProvisional(
      client, interface_registry, std::move(interface_broker), frame_token,
      previous_frame, frame_policy, name, web_view);
}

WebLocalFrameImpl* WebLocalFrameImpl::CreateMainFrame(
    WebView* web_view,
    WebLocalFrameClient* client,
    InterfaceRegistry* interface_registry,
    mojo::PendingRemote<mojom::blink::BrowserInterfaceBroker> interface_broker,
    const LocalFrameToken& frame_token,
    WebFrame* opener,
    const WebString& name,
    network::mojom::blink::WebSandboxFlags sandbox_flags,
    const DocumentToken& document_token,
    std::unique_ptr<WebPolicyContainer> policy_container,
    const WebURL& creator_base_url) {
  auto* frame = MakeGarbageCollected<WebLocalFrameImpl>(
      base::PassKey<WebLocalFrameImpl>(),
      mojom::blink::TreeScopeType::kDocument, client, interface_registry,
      frame_token);
  Page& page = *To<WebViewImpl>(web_view)->GetPage();
  DCHECK(!page.MainFrame());

  // TODO(https://crbug.com/1355751): From the browser process, plumb the
  // correct StorageKey for window in main frame. This is not an issue here,
  // because the FrameLoader is able to recover a correct StorageKey from the
  // origin of the document only.
  StorageKey storage_key;

  frame->InitializeCoreFrame(
      page, nullptr, nullptr, nullptr, FrameInsertType::kInsertInConstructor,
      name, opener ? &ToCoreFrame(*opener)->window_agent_factory() : nullptr,
      opener, document_token, std::move(interface_broker),
      std::move(policy_container), storage_key, creator_base_url,
      sandbox_flags);
  return frame;
}

WebLocalFrameImpl* WebLocalFrameImpl::CreateProvisional(
    WebLocalFrameClient* client,
    blink::InterfaceRegistry* interface_registry,
    mojo::PendingRemote<mojom::blink::BrowserInterfaceBroker> interface_broker,
    const LocalFrameToken& frame_token,
    WebFrame* previous_web_frame,
    const FramePolicy& frame_policy,
    const WebString& name,
    WebView* web_view) {
  DCHECK(client);
  Frame* previous_frame = ToCoreFrame(*previous_web_frame);
  DCHECK(name.IsEmpty() || name.Equals(previous_frame->Tree().GetName()));
  auto* web_frame = MakeGarbageCollected<WebLocalFrameImpl>(
      base::PassKey<WebLocalFrameImpl>(),
      previous_web_frame->GetTreeScopeType(), client, interface_registry,
      frame_token);
  network::mojom::blink::WebSandboxFlags sandbox_flags =
      network::mojom::blink::WebSandboxFlags::kNone;
  PermissionsPolicyFeatureState feature_state;
  if (!previous_frame->Owner() || previous_frame->IsFencedFrameRoot()) {
    // Provisional main frames need to force sandbox flags.  This is necessary
    // to inherit sandbox flags when a sandboxed frame does a window.open()
    // which triggers a cross-process navigation.
    // Fenced frames also need to force special initial sandbox flags that are
    // passed via frame_policy.
    sandbox_flags = frame_policy.sandbox_flags;
  }

  // Note: this *always* temporarily sets a frame owner, even for main frames!
  // When a core Frame is created with no owner, it attempts to set itself as
  // the main frame of the Page. However, this is a provisional frame, and may
  // disappear, so Page::m_mainFrame can't be updated just yet.
  // Note 2: Becuase the dummy owner is still the owner when the initial empty
  // document is created, the initial empty document will not inherit the
  // correct sandbox flags. However, since the provisional frame is inivisible
  // to the rest of the page, the initial document is also invisible and
  // unscriptable. Once the provisional frame gets properly attached and is
  // observable, it will have the real FrameOwner, and any subsequent real
  // documents will correctly inherit sandbox flags from the owner.
  //
  // Note: this intentionally initializes the initial document of the
  // provisional frame with a random DocumentToken rather than plumbing it
  // through from //content. The fact that provisional frames have an initial
  // document is a weird implementation detail and this is an attempt to
  // minimize its visibility/usefulness.
  Page* page_for_provisional_frame = To<WebViewImpl>(web_view)->GetPage();
  web_frame->InitializeCoreFrame(
      *page_for_provisional_frame, MakeGarbageCollected<DummyFrameOwner>(),
      previous_web_frame->Parent(), nullptr, FrameInsertType::kInsertLater,
      name, &ToCoreFrame(*previous_web_frame)->window_agent_factory(),
      previous_web_frame->Opener(), DocumentToken(),
      std::move(interface_broker),
      /*policy_container=*/nullptr, StorageKey(),
      /*creator_base_url=*/KURL(), sandbox_flags);

  LocalFrame* new_frame = web_frame->GetFrame();

  if (previous_frame->GetPage() != page_for_provisional_frame) {
    // The previous frame's Page is different from the new frame's page. This
    // can only be true when creating a provisional LocalFrame that will do a
    // local main frame swap when its navigation commits. To be able to do the
    // swap, the provisional frame must have a pointer to the previous Page's
    // local main frame, and also be set as the provisional frame of the
    // placeholder RemoteFrame of the new Page.
    // Note that the new provisional frame is not set as the provisional frame
    // of the previous Page's main frame, to avoid triggering the deletion of
    // the new Page's provisional frame if/when the previous Page's main frame
    // gets deleted. With that, the new Page's provisional main frame's deletion
    // can only be triggered by deleting the new Page (when its WebView gets
    // deleted).
    CHECK(!previous_web_frame->Parent());
    CHECK(previous_web_frame->IsWebLocalFrame());
    CHECK(page_for_provisional_frame->MainFrame()->IsRemoteFrame());
    CHECK(!DynamicTo<RemoteFrame>(page_for_provisional_frame->MainFrame())
               ->IsRemoteFrameHostRemoteBound());
    page_for_provisional_frame->SetPreviousMainFrameForLocalSwap(
        DynamicTo<LocalFrame>(ToCoreFrame(*previous_web_frame)));
    page_for_provisional_frame->MainFrame()->SetProvisionalFrame(new_frame);
  } else {
    // This is a normal provisional frame, which will either replace a
    // RemoteFrame or a non-main-frame LocalFrame. This makes it possible to
    // find the provisional owner frame (the previous frame) when swapping in
    // the new frame. This also ensures that detaching the previous frame also
    // disposes of the provisional frame.
    previous_frame->SetProvisionalFrame(new_frame);
  }

  new_frame->SetOwner(previous_frame->Owner());
  if (auto* remote_frame_owner =
          DynamicTo<RemoteFrameOwner>(new_frame->Owner())) {
    remote_frame_owner->SetFramePolicy(frame_policy);
  }

  return web_frame;
}

WebLocalFrameImpl* WebLocalFrameImpl::CreateLocalChild(
    mojom::blink::TreeScopeType scope,
    WebLocalFrameClient* client,
    blink::InterfaceRegistry* interface_registry,
    const LocalFrameToken& frame_token) {
  auto* frame = MakeGarbageCollected<WebLocalFrameImpl>(
      base::PassKey<WebLocalFrameImpl>(), scope, client, interface_registry,
      frame_token);
  return frame;
}

WebLocalFrameImpl::WebLocalFrameImpl(
    base::PassKey<WebLocalFrameImpl>,
    mojom::blink::TreeScopeType scope,
    WebLocalFrameClient* client,
    blink::InterfaceRegistry* interface_registry,
    const LocalFrameToken& frame_token)
    : WebNavigationControl(scope, frame_token),
      client_(client),
      local_frame_client_(MakeGarbageCollected<LocalFrameClientImpl>(this)),
      autofill_client_(nullptr),
      find_in_page_(
          MakeGarbageCollected<FindInPage>(*this, interface_registry)),
      interface_registry_(interface_registry),
      input_method_controller_(*this),
      spell_check_panel_host_client_(nullptr),
      not_restored_reasons_(
          mojom::BackForwardCacheNotRestoredReasonsPtr(nullptr)) {
  CHECK(client_);
  g_frame_count++;
  client_->BindToFrame(this);
}

WebLocalFrameImpl::WebLocalFrameImpl(base::PassKey<WebRemoteFrameImpl>,
                                     mojom::blink::TreeScopeType scope,
                                     WebLocalFrameClient* client,
                                     InterfaceRegistry* interface_registry,
                                     const LocalFrameToken& frame_token)
    : WebLocalFrameImpl(base::PassKey<WebLocalFrameImpl>(),
                        scope,
                        client,
                        interface_registry,
                        frame_token) {}

WebLocalFrameImpl::~WebLocalFrameImpl() {
  // The widget for the frame, if any, must have already been closed.
  DCHECK(!frame_widget_);
  g_frame_count--;
}

void WebLocalFrameImpl::Trace(Visitor* visitor) const {
  visitor->Trace(local_frame_client_);
  visitor->Trace(find_in_page_);
  visitor->Trace(frame_);
  visitor->Trace(dev_tools_agent_);
  visitor->Trace(frame_widget_);
  visitor->Trace(print_context_);
  visitor->Trace(input_method_controller_);
  visitor->Trace(current_history_item_);
}

void WebLocalFrameImpl::SetCoreFrame(LocalFrame* frame) {
  frame_ = frame;
}

void WebLocalFrameImpl::InitializeCoreFrame(
    Page& page,
    FrameOwner* owner,
    WebFrame* parent,
    WebFrame* previous_sibling,
    FrameInsertType insert_type,
    const AtomicString& name,
    WindowAgentFactory* window_agent_factory,
    WebFrame* opener,
    const DocumentToken& document_token,
    mojo::PendingRemote<mojom::blink::BrowserInterfaceBroker> interface_broker,
    std::unique_ptr<blink::WebPolicyContainer> policy_container,
    const StorageKey& storage_key,
    const KURL& creator_base_url,
    network::mojom::blink::WebSandboxFlags sandbox_flags) {
  InitializeCoreFrameInternal(
      page, owner, parent, previous_sibling, insert_type, name,
      window_agent_factory, opener, document_token, std::move(interface_broker),
      PolicyContainer::CreateFromWebPolicyContainer(
          std::move(policy_container)),
      storage_key, ukm::kInvalidSourceId, creator_base_url, sandbox_flags);
}

void WebLocalFrameImpl::InitializeCoreFrameInternal(
    Page& page,
    FrameOwner* owner,
    WebFrame* parent,
    WebFrame* previous_sibling,
    FrameInsertType insert_type,
    const AtomicString& name,
    WindowAgentFactory* window_agent_factory,
    WebFrame* opener,
    const DocumentToken& document_token,
    mojo::PendingRemote<mojom::blink::BrowserInterfaceBroker> interface_broker,
    std::unique_ptr<PolicyContainer> policy_container,
    const StorageKey& storage_key,
    ukm::SourceId document_ukm_source_id,
    const KURL& creator_base_url,
    network::mojom::blink::WebSandboxFlags sandbox_flags) {
  Frame* parent_frame = parent ? ToCoreFrame(*parent) : nullptr;
  Frame* previous_sibling_frame =
      previous_sibling ? ToCoreFrame(*previous_sibling) : nullptr;
  SetCoreFrame(MakeGarbageCollected<LocalFrame>(
      local_frame_client_.Get(), page, owner, parent_frame,
      previous_sibling_frame, insert_type, GetLocalFrameToken(),
      window_agent_factory, interface_registry_, std::move(interface_broker)));
  frame_->Tree().SetName(name);

  // See sandbox inheritance: content/browser/renderer_host/sandbox_flags.md
  //
  // New documents are either:
  // 1. The initial empty document:
  //   a. In a new iframe.
  //   b. In a new fencedframe.
  //   c. In a new popup.
  // 2. A document replacing the previous, one via a navigation.
  //
  // 1.b. will get the special sandbox flags. See:
  // https://docs.google.com/document/d/1RO4NkQk_XaEE7vuysM9LJilZYsoOhydfh93sOvrPQxU/edit
  // For 1.c., this is used to define sandbox flags for
  // the initial empty document in a new popup.
  if (frame_->IsMainFrame()) {
    DCHECK(!frame_->IsInFencedFrameTree() ||
           ((sandbox_flags & blink::kFencedFrameForcedSandboxFlags) ==
            blink::kFencedFrameForcedSandboxFlags))
        << "An MPArch fencedframe must be configured with its forced sandbox "
        << "flags:" << sandbox_flags;
    frame_->SetOpenerSandboxFlags(sandbox_flags);
  }

  Frame* opener_frame = opener ? ToCoreFrame(*opener) : nullptr;

  // We must call init() after frame_ is assigned because it is referenced
  // during init().
  frame_->Init(opener_frame, document_token, std::move(policy_container),
               storage_key, document_ukm_source_id, creator_base_url);

  if (!owner) {
    // This trace event is needed to detect the main frame of the
    // renderer in telemetry metrics. See crbug.com/692112#c11.
    TRACE_EVENT_INSTANT1("loading", "markAsMainFrame", TRACE_EVENT_SCOPE_THREAD,
                         "frame", GetFrameIdForTracing(frame_));
  }
}

LocalFrame* WebLocalFrameImpl::CreateChildFrame(
    const AtomicString& name,
    HTMLFrameOwnerElement* owner_element) {
  DCHECK(client_);
  TRACE_EVENT0("blink", "WebLocalFrameImpl::createChildframe");
  mojom::blink::TreeScopeType scope =
      GetFrame()->GetDocument() == owner_element->GetTreeScope()
          ? mojom::blink::TreeScopeType::kDocument
          : mojom::blink::TreeScopeType::kShadow;
  WebFrameOwnerProperties owner_properties(
      owner_element->BrowsingContextContainerName(),
      owner_element->ScrollbarMode(), owner_element->MarginWidth(),
      owner_element->MarginHeight(), owner_element->AllowFullscreen(),
      owner_element->AllowPaymentRequest(), owner_element->IsDisplayNone(),
      owner_element->GetColorScheme(),
      owner_element->GetPreferredColorScheme());

  mojo::PendingAssociatedRemote<mojom::blink::PolicyContainerHost>
      policy_container_remote;
  mojo::PendingAssociatedReceiver<mojom::blink::PolicyContainerHost>
      policy_container_receiver =
          policy_container_remote.InitWithNewEndpointAndPassReceiver();

  FramePolicy frame_policy = owner_element->GetFramePolicy();

  // The initial empty document's policy container is inherited from its parent.
  mojom::blink::PolicyContainerPoliciesPtr policy_container_data =
      GetFrame()->DomWindow()->GetPolicyContainer()->GetPolicies().Clone();

  // The frame sandbox flags and the initial empty document's sandbox flags
  // are restricted by the parent document's sandbox flags and the iframe's
  // sandbox attribute. It is the union of:
  //  - The parent's sandbox flags which are contained in
  //    policy_container_data and were cloned from the parent's document policy
  //    container above.
  //  - The iframe's sandbox attribute which is contained in frame_policy, from
  //    the owner element's frame policy.
  policy_container_data->sandbox_flags |= frame_policy.sandbox_flags;
  frame_policy.sandbox_flags = policy_container_data->sandbox_flags;

  // No URL is associated with this frame, but we can still assign UKM events to
  // this identifier.
  ukm::SourceId document_ukm_source_id = ukm::NoURLSourceId();

  auto complete_initialization =
      [this, owner_element, &policy_container_remote, &policy_container_data,
       &name, document_ukm_source_id](
          WebLocalFrame* new_child_frame, const DocumentToken& document_token,
          CrossVariantMojoRemote<mojom::BrowserInterfaceBrokerInterfaceBase>
              interface_broker) {
        // The initial empty document's credentialless bit is the union of:
        // - its parent's credentialless bit.
        // - its frame's credentialless attribute.
        policy_container_data->is_credentialless |=
            owner_element->Credentialless();

        std::unique_ptr<PolicyContainer> policy_container =
            std::make_unique<PolicyContainer>(
                std::move(policy_container_remote),
                std::move(policy_container_data));

        KURL creator_base_url(owner_element->GetDocument().BaseURL());
        To<WebLocalFrameImpl>(new_child_frame)
            ->InitializeCoreFrameInternal(
                *GetFrame()->GetPage(), owner_element, this, LastChild(),
                FrameInsertType::kInsertInConstructor, name,
                &GetFrame()->window_agent_factory(), nullptr, document_token,
                std::move(interface_broker), std::move(policy_container),
                GetFrame()->DomWindow()->GetStorageKey(),
                document_ukm_source_id, creator_base_url);
      };

  // FIXME: Using subResourceAttributeName as fallback is not a perfect
  // solution. subResourceAttributeName returns just one attribute name. The
  // element might not have the attribute, and there might be other attributes
  // which can identify the element.
  WebLocalFrameImpl* webframe_child =
      To<WebLocalFrameImpl>(client_->CreateChildFrame(
          scope, name,
          owner_element->getAttribute(
              owner_element->SubResourceAttributeName()),
          std::move(frame_policy), owner_properties, owner_element->OwnerType(),
          WebPolicyContainerBindParams{std::move(policy_container_receiver)},
          document_ukm_source_id, complete_initialization));
  if (!webframe_child)
    return nullptr;

  DCHECK(webframe_child->Parent());
  // If the lambda to complete initialization is not called, this will fail.
  DCHECK(webframe_child->GetFrame());
  return webframe_child->GetFrame();
}

RemoteFrame* WebLocalFrameImpl::CreateFencedFrame(
    HTMLFencedFrameElement* fenced_frame,
    mojo::PendingAssociatedReceiver<mojom::blink::FencedFrameOwnerHost>
        receiver) {
  mojom::blink::FrameReplicationStatePtr initial_replicated_state =
      mojom::blink::FrameReplicationState::New();
  initial
"""


```