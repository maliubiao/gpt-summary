Response:
The user wants a summary of the functionality of the provided C++ code snippet from the Chromium Blink engine. They are interested in how this code relates to Javascript, HTML, and CSS, including examples. They also want to know about potential user/programming errors. Finally, they specified that this is part 6 of 7 and want a summary of the functions in *this* part specifically.

**Plan:**

1. **Identify the core functionality:**  The provided code snippet largely deals with text editing, input method interaction (IME), selection manipulation, and some aspects of viewport and screen management.
2. **Categorize the functions:** Group the functions based on their related actions (e.g., IME related, selection related, edit commands).
3. **Explain the relationship to web technologies:** For each category, explain how it connects to Javascript, HTML, and CSS concepts.
4. **Provide examples:** Illustrate the connection with concrete examples of how these functions might be triggered or how they affect the rendering.
5. **Consider potential errors:** Think about common mistakes developers or users might make that would involve these functions.
6. **Address the "part 6" constraint:**  Focus the summary on the functions present *in this specific snippet*.
7. **Formulate assumptions and outputs (where applicable):** For functions that perform transformations or calculations, consider hypothetical inputs and their expected outputs.
这是 `blink/renderer/core/frame/web_frame_widget_impl.cc` 源代码文件的第 6 部分，主要包含以下功能，集中在**文本编辑、输入法支持、选择操作以及一些窗口和屏幕属性管理**：

**主要功能归纳:**

* **输入法 (IME) 支持:**
    * 获取指定范围内输入法文本 span 的信息 (`GetImeTextSpanInfo`)。
    * 清除指定范围内特定类型的输入法文本 span (`ClearImeTextSpansByType`)。
    * 从现有文本设置输入法组合 (`SetCompositionFromExistingText`)。
* **文本选择和编辑:**
    * 扩展选择并删除 (`ExtendSelectionAndDelete`)。
    * 扩展选择并替换 (`ExtendSelectionAndReplace`)。
    * 删除周围文本（字符或代码点） (`DeleteSurroundingText`, `DeleteSurroundingTextInCodePoints`)。
    * 设置可编辑区域的选择偏移量 (`SetEditableSelectionOffsets`)。
* **执行编辑命令:**
    * 执行预定义的编辑命令，如撤销、重做、剪切、复制、粘贴、删除、全选等 (`ExecuteEditCommand`, `Undo`, `Redo`, `Cut`, `Copy`, `Paste`, `PasteAndMatchStyle`, `Delete`, `SelectAll`)。
    * 将选中文本复制到查找剪贴板（仅限 Mac） (`CopyToFindPboard`)。
    * 使选中文本居中显示 (`CenterSelection`)。
    * 折叠当前选择 (`CollapseSelection`)。
    * 替换当前选中的内容 (`Replace`)。
    * 替换拼写错误的文本 (`ReplaceMisspelling`)。
* **精确选择操作:**
    * 根据屏幕坐标选择范围 (`SelectRange`)。
    * 通过字符偏移调整选择 (`AdjustSelectionByCharacterOffset`)。
    * 移动范围选择的终点 (`MoveRangeSelectionExtent`)。
* **滚动操作:**
    * 将焦点可编辑节点滚动到视图中 (`ScrollFocusedEditableNodeIntoView`)。
* **测试辅助功能:**
    * 等待页面缩放动画完成（仅用于测试） (`WaitForPageScaleAnimationForTesting`)。
* **查找功能辅助:**
    * 缩放到页面内查找的矩形区域 (`ZoomToFindInPageRect`)。
* **光标操作:**
    * 将光标移动到指定的屏幕坐标 (`MoveCaret`)。
    * 在光标周围选择文本（按字符、单词等粒度） (`SelectAroundCaret`)。
* **管理子 Frame:**
    * 遍历由该 Widget 控制的远程 Frame (`ForEachRemoteFrameControlledByWidget`)。
* **计算选择边界:**
    * 计算选择锚点和焦点的屏幕坐标 (`CalculateSelectionBounds`)。
* **图层树访问:**
    * 获取底层的 LayerTreeHost (`LayerTreeHost`, `LayerTreeHostForTesting`)。
* **设备模拟:**
    * 获取设备模拟器 (`DeviceEmulator`)。
    * 查询是否处于自动调整大小模式 (`AutoResizeMode`)。
    * 设置屏幕指标模拟参数 (`SetScreenMetricsEmulationParameters`)。
    * 设置屏幕信息和 Widget 大小 (`SetScreenInfoAndSize`)。
* **合成缩放因子:**
    * 获取合成缩放因子 (`GetCompositingScaleFactor`)。
    * 获取和设置图层树调试状态 (`GetLayerTreeDebugState`, `SetLayerTreeDebugState`)。
    * 通知合成缩放因子已更改 (`NotifyCompositingScaleFactorChanged`)。
* **页面缩放因子:**
    * 通知页面缩放因子已更改 (`NotifyPageScaleFactorChanged`)。
    * 设置页面缩放状态和限制 (`SetPageScaleStateAndLimits`)。
* **视口描述:**
    * 更新视口描述信息 (`UpdateViewportDescription`)。
* **屏幕矩形:**
    * 更新屏幕矩形信息，并检测窗口移动 (`UpdateScreenRects`, `EnqueueMoveEvent`)。
* **Windows 特有功能:**
    * 计算光标附近字符的边界（用于手写输入等） (`ComputeProximateCharacterBounds`)。
* **屏幕方向:**
    * 通知屏幕方向已更改 (`OrientationChanged`)。
* **Surface 和屏幕更新:**
    * 处理 Surface 和屏幕信息的更新，包括设备像素比变化 (`DidUpdateSurfaceAndScreen`)。
* **视口可见区域:**
    * 获取视口可见区域 (`ViewportVisibleRect`)。
* **屏幕方向覆盖:**
    * 获取屏幕方向覆盖 (`ScreenOrientationOverride`)。
* **可见性:**
    * 处理 Widget 被隐藏和显示的事件 (`WasHidden`, `WasShown`)。
* **性能测试:**
    * 运行绘制性能基准测试 (`RunPaintBenchmark`)。
* **通知输入观察者:**
    * 通知输入事件观察者 (`NotifyInputObservers`)。
* **焦点管理:**
    * 获取焦点 CoreFrame 和 Element (`FocusedCoreFrame`, `FocusedElement`)。
* **命中测试:**
    * 在根 Frame 坐标系中执行命中测试 (`HitTestResultForRootFramePos`)。
* **调试信息:**
    * 获取用于调试跟踪的 URL (`GetURLForDebugTrace`)。
* **测试 Hook:**
    * 获取测试用的设备像素比覆盖值 (`GetTestingDeviceScaleFactorOverride`)。
    * 释放鼠标锁定和指针捕获（用于测试） (`ReleaseMouseLockAndPointerCaptureForTesting`)。
    * 获取 FrameSinkId (`GetFrameSinkId`)。
    * 在指定点进行命中测试 (`HitTestResultAt`)。
    * 设置和重置测试用的缩放级别 (`SetZoomLevelForTesting`, `ResetZoomLevelForTesting`)。
    * 设置测试用的设备像素比 (`SetDeviceScaleFactorForTesting`)。
    * 获取 FrameWidget 测试助手 (`GetFrameWidgetTestHelperForTesting`)。
    * 为最终生命周期更新做准备（用于测试） (`PrepareForFinalLifecyclUpdateForTesting`)。
    * 应用本地 Surface ID 更新 (`ApplyLocalSurfaceIdUpdate`)。
    * 设置是否允许在未绘制帧时节流 (`SetMayThrottleIfUndrawnFrames`)。
    * 获取虚拟键盘调整高度 (`GetVirtualKeyboardResizeHeight`)。
    * 设置虚拟键盘调整高度（用于测试） (`SetVirtualKeyboardResizeHeightForTesting`)。
    * 获取是否允许在未绘制帧时节流（用于测试） (`GetMayThrottleIfUndrawnFramesForTesting`)。
* **插件容器:**
    * 获取焦点插件容器 (`GetFocusedPluginContainer`)。

**与 Javascript, HTML, CSS 的关系及举例说明:**

许多功能都直接或间接地与 Javascript、HTML 和 CSS 的交互有关：

* **文本编辑和选择:**
    * **Javascript:** Javascript 可以通过 `document.execCommand()` API 调用许多相同的编辑命令（如 `cut`, `copy`, `paste`, `selectAll`, `undo`, `redo`）。例如，一个按钮的 `onclick` 事件可以触发 `document.execCommand('copy')`。
    * **HTML:**  用户在 `<textarea>` 或设置了 `contenteditable` 属性的 HTML 元素中进行文本选择和编辑，会触发这里的方法。
    * **CSS:** CSS 影响文本的显示样式，例如字体、颜色、行高等，这些样式会在渲染输入法候选词和选中文本时被考虑。

* **输入法 (IME) 支持:**
    * **Javascript:** Javascript 的 `compositionstart`, `compositionupdate`, `compositionend` 事件用于监听输入法的状态变化，这些事件的处理最终会调用到这里的 IME 相关方法。例如，用户输入拼音时会触发 `compositionupdate` 事件。
    * **HTML:** 输入法主要作用于可编辑的 HTML 元素。
    * **CSS:**  输入法候选词的显示样式会受到 CSS 的影响。

* **选择操作 (SelectRange, AdjustSelectionByCharacterOffset 等):**
    * **Javascript:** Javascript 可以通过 `window.getSelection()` API 获取和操作选择范围。例如，可以使用 `Selection.collapse()` 折叠选择，这会对应调用到 `CollapseSelection`。
    * **HTML:** 用户通过鼠标拖拽或键盘快捷键（如 Shift + 方向键）进行选择，会触发这些操作。
    * **CSS:** `::selection` 伪元素允许开发者自定义选中文本的样式。

* **滚动操作 (ScrollFocusedEditableNodeIntoView):**
    * **Javascript:** Javascript 可以使用 `element.scrollIntoView()` 方法将元素滚动到可见区域，这可能会触发 `ScrollFocusedEditableNodeIntoView`。
    * **HTML:** 当焦点移动到一个不在当前视口内的可编辑元素时，浏览器可能会自动滚动。
    * **CSS:** CSS 的 `overflow` 属性决定了元素是否可以滚动。

* **屏幕和视口管理 (SetScreenInfoAndSize, UpdateViewportDescription 等):**
    * **Javascript:** Javascript 可以通过 `window.innerWidth`, `window.innerHeight`, `screen.width`, `screen.height` 等属性获取屏幕和视口的信息。`window.resize` 事件会触发相关更新。
    * **HTML:**  `<meta name="viewport">` 标签用于配置视口属性，这些属性会影响这里的方法调用。
    * **CSS:** CSS 的媒体查询 (`@media`) 允许开发者根据屏幕尺寸和分辨率应用不同的样式。

**逻辑推理的假设输入与输出举例:**

* **假设输入 (GetImeTextSpanInfo):**
    * `start`: 10
    * `end`: 20
    * `ime_text_spans`: 一个包含多个 `ui::ImeTextSpan` 对象的 Vector，这些对象描述了文本中特定位置的输入法高亮、下划线等信息。
    * `rect`:  一个 `gfx::Rect` 对象，表示文本所在区域的屏幕坐标。
* **输出 (GetImeTextSpanInfo):** 一个 `Vector<mojom::blink::ImeTextSpanInfoPtr>`，其中包含了根据输入 `ime_text_spans` 和 `rect` 创建的 `ImeTextSpanInfo` 对象。每个 `ImeTextSpanInfo` 包含了原始的 `ImeTextSpan` 数据以及相对于 Widget 的转换后的矩形坐标。

* **假设输入 (AdjustSelectionByCharacterOffset):**
    * 当前选择范围从字符 5 到 10。
    * `start`: 2 (将选择起始位置向后移动 2 个字符)
    * `end`: -1 (将选择结束位置向前移动 1 个字符)
* **输出 (AdjustSelectionByCharacterOffset):**  新的选择范围将变为从字符 5 + 2 = 7 到 10 - 1 = 9。

**用户或编程常见的使用错误举例:**

* **错误地假设 `FocusedWebLocalFrameInWidget()` 始终返回有效指针:**  如果在没有焦点 Frame 的情况下调用这些方法，会导致空指针解引用。例如，在页面加载完成前或焦点移出页面时调用编辑命令。
* **传递无效的偏移量或范围:**  例如，在 `ExtendSelectionAndReplace` 中，如果 `before` 或 `after` 的值超出了文本的范围，可能会导致崩溃或不可预测的行为。
* **在不适用的元素上调用编辑命令:**  例如，尝试在非 `contenteditable` 的 `<div>` 元素上执行 `Paste` 命令将不会有任何效果。
* **在测试代码中忘记重置测试用的设备像素比或缩放级别:**  这可能导致后续测试受到之前测试的影响，产生错误的测试结果。

**本部分功能归纳:**

总而言之，这部分代码主要负责处理用户在网页上进行的文本编辑和选择操作，并为输入法提供底层支持。它将用户的意图（例如，按下 `Ctrl+C` 复制，或者通过输入法输入文字）转化为 Blink 引擎内部对 DOM 树的修改和渲染更新。同时，也包含了一些与窗口和屏幕属性管理以及测试相关的辅助功能。

Prompt: 
```
这是目录为blink/renderer/core/frame/web_frame_widget_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第6部分，共7部分，请归纳一下它的功能

"""
m::blink::ImeTextSpanInfo::New(
        ime_text_span, widget_base_->BlinkSpaceToEnclosedDIPs(rect)));
  }
  return ime_text_spans_info;
}

void WebFrameWidgetImpl::ClearImeTextSpansByType(uint32_t start,
                                                 uint32_t end,
                                                 ui::ImeTextSpan::Type type) {
  WebLocalFrame* focused_frame = FocusedWebLocalFrameInWidget();
  if (!focused_frame)
    return;
  focused_frame->ClearImeTextSpansByType(type, start, end);
}

void WebFrameWidgetImpl::SetCompositionFromExistingText(
    int32_t start,
    int32_t end,
    const Vector<ui::ImeTextSpan>& ime_text_spans) {
  WebLocalFrame* focused_frame = FocusedWebLocalFrameInWidget();
  if (!focused_frame)
    return;
  focused_frame->SetCompositionFromExistingText(start, end, ime_text_spans);
}

void WebFrameWidgetImpl::ExtendSelectionAndDelete(int32_t before,
                                                  int32_t after) {
  WebLocalFrame* focused_frame = FocusedWebLocalFrameInWidget();
  if (!focused_frame)
    return;
  focused_frame->ExtendSelectionAndDelete(before, after);
}

void WebFrameWidgetImpl::ExtendSelectionAndReplace(
    uint32_t before,
    uint32_t after,
    const String& replacement_text) {
  WebLocalFrame* focused_frame = FocusedWebLocalFrameInWidget();
  if (!focused_frame) {
    return;
  }
  focused_frame->ExtendSelectionAndReplace(base::checked_cast<int>(before),
                                           base::checked_cast<int>(after),
                                           replacement_text);
}

void WebFrameWidgetImpl::DeleteSurroundingText(int32_t before, int32_t after) {
  WebLocalFrame* focused_frame = FocusedWebLocalFrameInWidget();
  if (!focused_frame)
    return;
  focused_frame->DeleteSurroundingText(before, after);
}

void WebFrameWidgetImpl::DeleteSurroundingTextInCodePoints(int32_t before,
                                                           int32_t after) {
  WebLocalFrame* focused_frame = FocusedWebLocalFrameInWidget();
  if (!focused_frame)
    return;
  focused_frame->DeleteSurroundingTextInCodePoints(before, after);
}

void WebFrameWidgetImpl::SetEditableSelectionOffsets(int32_t start,
                                                     int32_t end) {
  WebLocalFrame* focused_frame = FocusedWebLocalFrameInWidget();
  if (!focused_frame)
    return;
  focused_frame->SetEditableSelectionOffsets(start, end);
}

void WebFrameWidgetImpl::ExecuteEditCommand(const String& command,
                                            const String& value) {
  WebLocalFrame* focused_frame = FocusedWebLocalFrameInWidget();
  if (!focused_frame)
    return;
  focused_frame->ExecuteCommand(command, value);
}

void WebFrameWidgetImpl::Undo() {
  WebLocalFrame* focused_frame = FocusedWebLocalFrameInWidget();
  if (!focused_frame)
    return;
  focused_frame->ExecuteCommand(WebString::FromLatin1("Undo"));
}

void WebFrameWidgetImpl::Redo() {
  WebLocalFrame* focused_frame = FocusedWebLocalFrameInWidget();
  if (!focused_frame)
    return;
  focused_frame->ExecuteCommand(WebString::FromLatin1("Redo"));
}

void WebFrameWidgetImpl::Cut() {
  WebLocalFrame* focused_frame = FocusedWebLocalFrameInWidget();
  if (!focused_frame)
    return;
  focused_frame->ExecuteCommand(WebString::FromLatin1("Cut"));
}

void WebFrameWidgetImpl::Copy() {
  WebLocalFrame* focused_frame = FocusedWebLocalFrameInWidget();
  if (!focused_frame)
    return;
  focused_frame->ExecuteCommand(WebString::FromLatin1("Copy"));
}

void WebFrameWidgetImpl::CopyToFindPboard() {
#if BUILDFLAG(IS_MAC)
  WebLocalFrame* focused_frame = FocusedWebLocalFrameInWidget();
  if (!focused_frame)
    return;
  To<WebLocalFrameImpl>(focused_frame)->CopyToFindPboard();
#endif
}

void WebFrameWidgetImpl::CenterSelection() {
  WebLocalFrame* focused_frame = FocusedWebLocalFrameInWidget();
  if (!focused_frame) {
    return;
  }
  To<WebLocalFrameImpl>(focused_frame)->CenterSelection();
}

void WebFrameWidgetImpl::Paste() {
  WebLocalFrame* focused_frame = FocusedWebLocalFrameInWidget();
  if (!focused_frame)
    return;
  focused_frame->ExecuteCommand(WebString::FromLatin1("Paste"));
}

void WebFrameWidgetImpl::PasteAndMatchStyle() {
  WebLocalFrame* focused_frame = FocusedWebLocalFrameInWidget();
  if (!focused_frame)
    return;
  focused_frame->ExecuteCommand(WebString::FromLatin1("PasteAndMatchStyle"));
}

void WebFrameWidgetImpl::Delete() {
  WebLocalFrame* focused_frame = FocusedWebLocalFrameInWidget();
  if (!focused_frame)
    return;
  focused_frame->ExecuteCommand(WebString::FromLatin1("Delete"));
}

void WebFrameWidgetImpl::SelectAll() {
  WebLocalFrame* focused_frame = FocusedWebLocalFrameInWidget();
  if (!focused_frame)
    return;
  focused_frame->ExecuteCommand(WebString::FromLatin1("SelectAll"));
}

void WebFrameWidgetImpl::CollapseSelection() {
  WebLocalFrame* focused_frame = FocusedWebLocalFrameInWidget();
  if (!focused_frame)
    return;
  const blink::WebRange& range =
      focused_frame->GetInputMethodController()->GetSelectionOffsets();
  if (range.IsNull())
    return;

  focused_frame->SelectRange(blink::WebRange(range.EndOffset(), 0),
                             blink::WebLocalFrame::kHideSelectionHandle,
                             mojom::blink::SelectionMenuBehavior::kHide,
                             blink::WebLocalFrame::kSelectionDoNotSetFocus);
}

void WebFrameWidgetImpl::Replace(const String& word) {
  auto* focused_frame = FocusedWebLocalFrameInWidget();
  if (!focused_frame)
    return;
  if (!focused_frame->HasSelection()) {
    focused_frame->SelectAroundCaret(mojom::blink::SelectionGranularity::kWord,
                                     /*should_show_handle=*/false,
                                     /*should_show_context_menu=*/false);
  }
  focused_frame->ReplaceSelection(word);
  // If the resulting selection is not actually a change in selection, we do not
  // need to explicitly notify about the selection change.
  focused_frame->Client()->SyncSelectionIfRequired(
      blink::SyncCondition::kNotForced);
}

void WebFrameWidgetImpl::ReplaceMisspelling(const String& word) {
  WebLocalFrame* focused_frame = FocusedWebLocalFrameInWidget();
  if (!focused_frame)
    return;
  if (!focused_frame->HasSelection())
    return;
  focused_frame->ReplaceMisspelledRange(word);
}

void WebFrameWidgetImpl::SelectRange(const gfx::Point& base_in_dips,
                                     const gfx::Point& extent_in_dips) {
  WebLocalFrame* focused_frame = FocusedWebLocalFrameInWidget();
  if (!focused_frame)
    return;
  focused_frame->SelectRange(
      widget_base_->DIPsToRoundedBlinkSpace(base_in_dips),
      widget_base_->DIPsToRoundedBlinkSpace(extent_in_dips));
}

void WebFrameWidgetImpl::AdjustSelectionByCharacterOffset(
    int32_t start,
    int32_t end,
    mojom::blink::SelectionMenuBehavior selection_menu_behavior) {
  WebLocalFrame* focused_frame = FocusedWebLocalFrameInWidget();
  if (!focused_frame)
    return;
  blink::WebRange range =
      focused_frame->GetInputMethodController()->GetSelectionOffsets();
  if (range.IsNull())
    return;

  // Sanity checks to disallow empty and out of range selections.
  if (start - end > range.length() || range.StartOffset() + start < 0)
    return;

  // A negative adjust amount moves the selection towards the beginning of
  // the document, a positive amount moves the selection towards the end of
  // the document.
  focused_frame->SelectRange(blink::WebRange(range.StartOffset() + start,
                                             range.length() + end - start),
                             blink::WebLocalFrame::kPreserveHandleVisibility,
                             selection_menu_behavior,
                             blink::WebLocalFrame::kSelectionSetFocus);
}

void WebFrameWidgetImpl::MoveRangeSelectionExtent(
    const gfx::Point& extent_in_dips) {
  WebLocalFrame* focused_frame = FocusedWebLocalFrameInWidget();
  if (!focused_frame)
    return;
  focused_frame->MoveRangeSelectionExtent(
      widget_base_->DIPsToRoundedBlinkSpace(extent_in_dips));
}

void WebFrameWidgetImpl::ScrollFocusedEditableNodeIntoView() {
  WebLocalFrameImpl* local_frame = FocusedWebLocalFrameInWidget();
  if (!local_frame)
    return;

  // OnSynchronizeVisualProperties does not call DidChangeVisibleViewport
  // on OOPIFs. Since we are starting a new scroll operation now, call
  // DidChangeVisibleViewport to ensure that we don't assume the element
  // is already in view and ignore the scroll.
  local_frame->ResetHasScrolledFocusedEditableIntoView();
  local_frame->ScrollFocusedEditableElementIntoView();
}

void WebFrameWidgetImpl::WaitForPageScaleAnimationForTesting(
    WaitForPageScaleAnimationForTestingCallback callback) {
  DCHECK(ForMainFrame());
  DCHECK(LocalRootImpl()->GetFrame()->IsOutermostMainFrame());
  page_scale_animation_for_testing_callback_ = std::move(callback);
}

void WebFrameWidgetImpl::ZoomToFindInPageRect(
    const gfx::Rect& rect_in_root_frame) {
  if (ForMainFrame()) {
    View()->ZoomToFindInPageRect(rect_in_root_frame);
  } else {
    GetAssociatedFrameWidgetHost()->ZoomToFindInPageRectInMainFrame(
        rect_in_root_frame);
  }
}

void WebFrameWidgetImpl::MoveCaret(const gfx::Point& point_in_dips) {
  WebLocalFrame* focused_frame = FocusedWebLocalFrameInWidget();
  if (!focused_frame)
    return;
  focused_frame->MoveCaretSelection(
      widget_base_->DIPsToRoundedBlinkSpace(point_in_dips));
}

void WebFrameWidgetImpl::SelectAroundCaret(
    mojom::blink::SelectionGranularity granularity,
    bool should_show_handle,
    bool should_show_context_menu,
    SelectAroundCaretCallback callback) {
  auto* focused_frame = FocusedWebLocalFrameInWidget();
  if (!focused_frame) {
    std::move(callback).Run(std::move(nullptr));
    return;
  }

  int extended_start_adjust = 0;
  int extended_end_adjust = 0;
  int word_start_adjust = 0;
  int word_end_adjust = 0;
  blink::WebRange initial_range = focused_frame->SelectionRange();
  SetHandlingInputEvent(true);

  if (initial_range.IsNull()) {
    std::move(callback).Run(std::move(nullptr));
    return;
  }

  // If the requested granularity is not word, still calculate the hypothetical
  // word selection offsets. This is needed for contextual search to support
  // legacy semantics for the word that was tapped.
  blink::WebRange word_range;
  if (granularity != mojom::blink::SelectionGranularity::kWord) {
    word_range = focused_frame->GetWordSelectionRangeAroundCaret();
  }

  // Select around the caret at the specified |granularity|.
  if (!focused_frame->SelectAroundCaret(granularity, should_show_handle,
                                        should_show_context_menu)) {
    std::move(callback).Run(std::move(nullptr));
    return;
  }

  blink::WebRange extended_range = focused_frame->SelectionRange();
  DCHECK(!extended_range.IsNull());
  extended_start_adjust =
      extended_range.StartOffset() - initial_range.StartOffset();
  extended_end_adjust = extended_range.EndOffset() - initial_range.EndOffset();

  if (granularity == mojom::blink::SelectionGranularity::kWord) {
    // Since the requested granularity was word, simply set the word offset
    // to be the same as the extended offset values.
    word_start_adjust = extended_start_adjust;
    word_end_adjust = extended_end_adjust;
  } else {
    // Calculate the word offset compared to the initial selection (caret).
    DCHECK(!word_range.IsNull());
    word_start_adjust = word_range.StartOffset() - initial_range.StartOffset();
    word_end_adjust = word_range.EndOffset() - initial_range.EndOffset();
  }

  SetHandlingInputEvent(false);
  auto result = mojom::blink::SelectAroundCaretResult::New();
  result->extended_start_adjust = extended_start_adjust;
  result->extended_end_adjust = extended_end_adjust;
  result->word_start_adjust = word_start_adjust;
  result->word_end_adjust = word_end_adjust;
  std::move(callback).Run(std::move(result));
}

void WebFrameWidgetImpl::ForEachRemoteFrameControlledByWidget(
    base::FunctionRef<void(RemoteFrame*)> callback) {
  ForEachRemoteFrameChildrenControlledByWidget(local_root_->GetFrame(),
                                               callback);
}

void WebFrameWidgetImpl::CalculateSelectionBounds(gfx::Rect& anchor_root_frame,
                                                  gfx::Rect& focus_root_frame) {
  CalculateSelectionBounds(anchor_root_frame, focus_root_frame, nullptr);
}

void WebFrameWidgetImpl::CalculateSelectionBounds(
    gfx::Rect& anchor_root_frame,
    gfx::Rect& focus_root_frame,
    gfx::Rect* bounding_box_in_root_frame) {
  const LocalFrame* local_frame = FocusedLocalFrameInWidget();
  if (!local_frame)
    return;

  gfx::Rect anchor;
  gfx::Rect focus;
  auto& selection = local_frame->Selection();
  if (!selection.ComputeAbsoluteBounds(anchor, focus))
    return;

  // Apply the visual viewport for main frames this will apply the page scale.
  // For subframes it will just be a 1:1 transformation and the browser
  // will then apply later transformations to these rects.
  VisualViewport& visual_viewport = GetPage()->GetVisualViewport();
  anchor_root_frame = visual_viewport.RootFrameToViewport(
      local_frame->View()->ConvertToRootFrame(anchor));
  focus_root_frame = visual_viewport.RootFrameToViewport(
      local_frame->View()->ConvertToRootFrame(focus));

  // Calculate the bounding box of the selection area.
  if (bounding_box_in_root_frame) {
    Range* range =
        CreateRange(selection.GetSelectionInDOMTree().ComputeRange());
    const gfx::Rect bounding_box = ToEnclosingRect(range->BoundingRect());
    range->Dispose();
    *bounding_box_in_root_frame = visual_viewport.RootFrameToViewport(
        local_frame->View()->ConvertToRootFrame(bounding_box));
  }
}

const viz::LocalSurfaceId& WebFrameWidgetImpl::LocalSurfaceIdFromParent() {
  return widget_base_->local_surface_id_from_parent();
}

cc::LayerTreeHost* WebFrameWidgetImpl::LayerTreeHost() {
  return widget_base_->LayerTreeHost();
}

cc::LayerTreeHost* WebFrameWidgetImpl::LayerTreeHostForTesting() const {
  return widget_base_->LayerTreeHost();
}

ScreenMetricsEmulator* WebFrameWidgetImpl::DeviceEmulator() {
  return device_emulator_.Get();
}

bool WebFrameWidgetImpl::AutoResizeMode() {
  return View()->AutoResizeMode();
}

void WebFrameWidgetImpl::SetScreenMetricsEmulationParameters(
    bool enabled,
    const DeviceEmulationParams& params) {
  if (enabled)
    View()->ActivateDevToolsTransform(params);
  else
    View()->DeactivateDevToolsTransform();
}

void WebFrameWidgetImpl::SetScreenInfoAndSize(
    const display::ScreenInfos& screen_infos,
    const gfx::Size& widget_size_in_dips,
    const gfx::Size& visible_viewport_size_in_dips) {
  // Emulation happens on regular main frames which don't use auto-resize mode.
  DCHECK(!AutoResizeMode());

  UpdateScreenInfo(screen_infos);
  widget_base_->SetVisibleViewportSizeInDIPs(visible_viewport_size_in_dips);
  Resize(widget_base_->DIPsToCeiledBlinkSpace(widget_size_in_dips));
}

float WebFrameWidgetImpl::GetCompositingScaleFactor() {
  return compositing_scale_factor_;
}

const cc::LayerTreeDebugState* WebFrameWidgetImpl::GetLayerTreeDebugState() {
  if (!View()->does_composite()) {
    return nullptr;
  }
  return &widget_base_->LayerTreeHost()->GetDebugState();
}

void WebFrameWidgetImpl::SetLayerTreeDebugState(
    const cc::LayerTreeDebugState& state) {
  if (!View()->does_composite()) {
    return;
  }
  widget_base_->LayerTreeHost()->SetDebugState(state);
}

void WebFrameWidgetImpl::NotifyCompositingScaleFactorChanged(
    float compositing_scale_factor) {
  compositing_scale_factor_ = compositing_scale_factor;

  // Update the scale factor for remote frames which in turn depends on the
  // compositing scale factor set in the widget.
  ForEachRemoteFrameControlledByWidget([](RemoteFrame* remote_frame) {
    // Only RemoteFrames with a local parent frame participate in compositing
    // (and thus have a view).
    if (remote_frame->View())
      remote_frame->View()->UpdateCompositingScaleFactor();
  });
}

void WebFrameWidgetImpl::NotifyPageScaleFactorChanged(
    float page_scale_factor,
    bool is_pinch_gesture_active) {
  // Store the value to give to any new RemoteFrame that will be created as a
  // descendant of this widget.
  page_scale_factor_in_mainframe_ = page_scale_factor;
  is_pinch_gesture_active_in_mainframe_ = is_pinch_gesture_active;
  // Push the page scale factor down to any child RemoteFrames.
  // TODO(danakj): This ends up setting the page scale factor in the
  // RenderWidgetHost of the child WebFrameWidgetImpl, so that it can bounce
  // the value down to its WebFrameWidgetImpl. Since this is essentially a
  // global value per-page, we could instead store it once in the browser
  // (such as in RenderViewHost) and distribute it to each WebFrameWidgetImpl
  // from there.
  ForEachRemoteFrameControlledByWidget(
      [page_scale_factor, is_pinch_gesture_active](RemoteFrame* remote_frame) {
        remote_frame->PageScaleFactorChanged(page_scale_factor,
                                             is_pinch_gesture_active);
      });
}

void WebFrameWidgetImpl::SetPageScaleStateAndLimits(
    float page_scale_factor,
    bool is_pinch_gesture_active,
    float minimum,
    float maximum) {
  widget_base_->LayerTreeHost()->SetPageScaleFactorAndLimits(page_scale_factor,
                                                             minimum, maximum);

  // Only propagate page scale from the main frame.
  if (ForMainFrame()) {
    // If page scale hasn't changed, then just return without notifying
    // the remote frames.
    if (page_scale_factor == page_scale_factor_in_mainframe_ &&
        is_pinch_gesture_active == is_pinch_gesture_active_in_mainframe_) {
      return;
    }

    NotifyPageScaleFactorChanged(page_scale_factor, is_pinch_gesture_active);
  }
}

void WebFrameWidgetImpl::UpdateViewportDescription(
    const ViewportDescription& viewport) {
  bool is_device_width = viewport.max_width.IsDeviceWidth();
  bool is_zoom_at_least_one = viewport.zoom >= 1.0 || viewport.min_zoom >= 1;
  widget_base_->LayerTreeHost()->UpdateViewportIsMobileOptimized(
      (is_device_width && is_zoom_at_least_one) ||
      (is_device_width && !viewport.zoom_is_explicit) ||
      (viewport.max_width.IsAuto() && is_zoom_at_least_one));
}

bool WebFrameWidgetImpl::UpdateScreenRects(
    const gfx::Rect& widget_screen_rect,
    const gfx::Rect& window_screen_rect) {

  if (device_emulator_) {
    device_emulator_->OnUpdateScreenRects(widget_screen_rect,
                                          window_screen_rect);
  }

  // Check movement from the committed `WindowScreenRect()`, not `WindowRect()`,
  // which may include pending updates from renderer-initiated moveTo|By calls.
  if (widget_base_->WindowScreenRect().origin() !=
      window_screen_rect.origin()) {
    EnqueueMoveEvent();
  }

  return device_emulator_ != nullptr;
}

void WebFrameWidgetImpl::EnqueueMoveEvent() {
  if (!RuntimeEnabledFeatures::WindowOnMoveEventEnabled()) {
    return;
  }

  if (!local_root_ || !local_root_->GetFrame() || !ForTopMostMainFrame()) {
    return;
  }

  Document* document = local_root_->GetFrame()->GetDocument();
  if (!document || !document->IsActive()) {
    return;
  }

  document->EnqueueMoveEvent();
}

#if BUILDFLAG(IS_WIN)
mojom::blink::ProximateCharacterRangeBoundsPtr
WebFrameWidgetImpl::ComputeProximateCharacterBounds(
    const PositionWithAffinity& pivot_position) const {
  TRACE_EVENT("ime", "WebFrameWidgetImpl::ComputeProximateCharacterBounds");
  if (pivot_position.IsNull() ||
      !stylus_handwriting::win::IsStylusHandwritingWinEnabled()) {
    return nullptr;
  }
  // The amount of text to collect in each direction relative to the character
  // offset pivot position `x` derived by `point_in_widget`. Collects character
  // bounds for offsets [x - half_limit, x + half_limit).
  const wtf_size_t half_limit =
      stylus_handwriting::win::ProximateBoundsCollectionHalfLimit();
  if (!half_limit) {
    return nullptr;
  }
  Element* root_editable_element =
      RootEditableElement(*pivot_position.AnchorNode());
  if (!root_editable_element) {
    return nullptr;
  }

  // `CreateVisiblePosition` and `FirstRectForRange` requires clean layout.
  root_editable_element->GetDocument().UpdateStyleAndLayout(
      DocumentUpdateReason::kEditing);

  // Compute a PlainTextRange for a subset of text around `pivot_position`.
  const PlainTextRange text_range = ShellHandwritingProximateTextRange(
      *root_editable_element, pivot_position.GetPosition(), half_limit);
  if (text_range.IsNull()) {
    return nullptr;
  }

  // Compute the DIP space bounding box for each character in `text_range`
  // relative to the root editable Element containing `pivot_position`.
  WTF::Vector<gfx::Rect> character_bounds;
  character_bounds.reserve(text_range.length());
  for (wtf_size_t i = text_range.Start(); i < text_range.End(); ++i) {
    gfx::Rect rect = FirstRectForRange(
        PlainTextRange(i, i + 1U).CreateRange(*root_editable_element));
    // Convert rect coordinates to be relative to the root editable frame.
    LocalFrame* editable_frame =
        root_editable_element->GetDocument().GetFrame();
    rect = editable_frame->View()->ConvertToRootFrame(rect);
    rect = gfx::ScaleToRoundedRect(
        rect, editable_frame->GetPage()->PageScaleFactor());
    character_bounds.emplace_back(widget_base_->BlinkSpaceToEnclosedDIPs(rect));
  }

  return mojom::blink::ProximateCharacterRangeBounds::New(
      gfx::Range(text_range.Start(), text_range.End()),
      std::move(character_bounds));
}
#endif  // BUILDFLAG(IS_WIN)

void WebFrameWidgetImpl::OrientationChanged() {
  local_root_->SendOrientationChangeEvent();
}

void WebFrameWidgetImpl::DidUpdateSurfaceAndScreen(
    const display::ScreenInfos& previous_original_screen_infos) {
  display::ScreenInfo screen_info = widget_base_->GetScreenInfo();
  View()->SetZoomFactorForDeviceScaleFactor(screen_info.device_scale_factor);

  if (ShouldAutoDetermineCompositingToLCDTextSetting()) {
    // This causes compositing state to be modified which dirties the
    // document lifecycle. Android Webview relies on the document
    // lifecycle being clean after the RenderWidget is initialized, in
    // order to send IPCs that query and change compositing state. So
    // WebFrameWidgetImpl::Resize() must come after this call, as it runs the
    // entire document lifecycle.
    View()->GetSettings()->SetLCDTextPreference(
        widget_base_->ComputeLCDTextPreference());
  }

  // When the device scale changes, the size and position of the popup would
  // need to be adjusted, which we can't do. Just close the popup, which is
  // also consistent with page zoom and resize behavior.
  display::ScreenInfos original_screen_infos = GetOriginalScreenInfos();
  if (previous_original_screen_infos.current().device_scale_factor !=
      original_screen_infos.current().device_scale_factor) {
    View()->CancelPagePopup();
  }

  const bool window_screen_has_changed =
      !Screen::AreWebExposedScreenPropertiesEqual(
          previous_original_screen_infos.current(),
          original_screen_infos.current());

  // Update Screens interface data before firing any events. The API is designed
  // to offer synchronous access to the most up-to-date cached screen
  // information when a change event is fired.  It is not required but it
  // is convenient to have all ScreenDetailed objects be up to date when any
  // window.screen events are fired as well.
  ForEachLocalFrameControlledByWidget(
      LocalRootImpl()->GetFrame(),
      [&original_screen_infos,
       window_screen_has_changed](WebLocalFrameImpl* local_frame) {
        auto* screen = local_frame->GetFrame()->DomWindow()->screen();
        screen->UpdateDisplayId(original_screen_infos.current().display_id);
        CoreInitializer::GetInstance().DidUpdateScreens(
            *local_frame->GetFrame(), original_screen_infos);
        if (window_screen_has_changed)
          screen->DispatchEvent(*Event::Create(event_type_names::kChange));
      });

  if (previous_original_screen_infos != original_screen_infos) {
    // Propagate changes down to child local root RenderWidgets and
    // BrowserPlugins in other frame trees/processes.
    ForEachRemoteFrameControlledByWidget(
        [&original_screen_infos](RemoteFrame* remote_frame) {
          remote_frame->DidChangeScreenInfos(original_screen_infos);
        });
  }
}

gfx::Rect WebFrameWidgetImpl::ViewportVisibleRect() {
  if (ForMainFrame()) {
    return widget_base_->CompositorViewportRect();
  } else {
    return child_data().compositor_visible_rect;
  }
}

std::optional<display::mojom::blink::ScreenOrientation>
WebFrameWidgetImpl::ScreenOrientationOverride() {
  return View()->ScreenOrientationOverride();
}

void WebFrameWidgetImpl::WasHidden() {
  ForEachLocalFrameControlledByWidget(local_root_->GetFrame(),
                                      [](WebLocalFrameImpl* local_frame) {
                                        local_frame->Client()->WasHidden();
                                      });

  if (animation_frame_timing_monitor_) {
    animation_frame_timing_monitor_->Shutdown();
    animation_frame_timing_monitor_.Clear();
  }
}

void WebFrameWidgetImpl::WasShown(bool was_evicted) {
  ForEachLocalFrameControlledByWidget(local_root_->GetFrame(),
                                      [](WebLocalFrameImpl* local_frame) {
                                        local_frame->Client()->WasShown();
                                      });
  if (was_evicted) {
    ForEachRemoteFrameControlledByWidget(
        // On eviction, the last SurfaceId is invalidated. We need to
        // allocate a new id.
        &RemoteFrame::ResendVisualProperties);
  }

  CHECK(local_root_ && local_root_->GetFrame());
  if (!animation_frame_timing_monitor_) {
    animation_frame_timing_monitor_ =
        MakeGarbageCollected<AnimationFrameTimingMonitor>(
            *this, local_root_->GetFrame()->GetProbeSink());
  }
}

void WebFrameWidgetImpl::RunPaintBenchmark(int repeat_count,
                                           cc::PaintBenchmarkResult& result) {
  if (!ForMainFrame())
    return;
  if (auto* frame_view = LocalRootImpl()->GetFrameView())
    frame_view->RunPaintBenchmark(repeat_count, result);
}

void WebFrameWidgetImpl::NotifyInputObservers(
    const WebCoalescedInputEvent& coalesced_event) {
  LocalFrame* frame = FocusedLocalFrameInWidget();
  if (!frame)
    return;

  LocalFrameView* frame_view = frame->View();
  if (!frame_view)
    return;

  const WebInputEvent& input_event = coalesced_event.Event();
  auto& paint_timing_detector = frame_view->GetPaintTimingDetector();

  if (paint_timing_detector.NeedToNotifyInputOrScroll())
    paint_timing_detector.NotifyInputEvent(input_event.GetType());
}

Frame* WebFrameWidgetImpl::FocusedCoreFrame() const {
  return GetPage() ? GetPage()->GetFocusController().FocusedOrMainFrame()
                   : nullptr;
}

Element* WebFrameWidgetImpl::FocusedElement() const {
  LocalFrame* frame = GetPage()->GetFocusController().FocusedFrame();
  if (!frame)
    return nullptr;

  Document* document = frame->GetDocument();
  if (!document)
    return nullptr;

  return document->FocusedElement();
}

HitTestResult WebFrameWidgetImpl::HitTestResultForRootFramePos(
    const gfx::PointF& pos_in_root_frame) {
  gfx::PointF doc_point =
      LocalRootImpl()->GetFrame()->View()->ConvertFromRootFrame(
          pos_in_root_frame);
  HitTestLocation location(doc_point);
  HitTestResult result =
      LocalRootImpl()->GetFrame()->View()->HitTestWithThrottlingAllowed(
          location, HitTestRequest::kReadOnly | HitTestRequest::kActive);
  return result;
}

KURL WebFrameWidgetImpl::GetURLForDebugTrace() {
  WebFrame* main_frame = View()->MainFrame();
  if (main_frame->IsWebLocalFrame())
    return main_frame->ToWebLocalFrame()->GetDocument().Url();
  return {};
}

float WebFrameWidgetImpl::GetTestingDeviceScaleFactorOverride() {
  return device_scale_factor_for_testing_;
}

void WebFrameWidgetImpl::ReleaseMouseLockAndPointerCaptureForTesting() {
  GetPage()->GetPointerLockController().ExitPointerLock();
  MouseCaptureLost();
}

const viz::FrameSinkId& WebFrameWidgetImpl::GetFrameSinkId() {
  // It is valid to create a WebFrameWidget with an invalid frame sink id for
  // printing and placeholders. But if we go to use it, it should be valid.
  DCHECK(frame_sink_id_.is_valid());
  return frame_sink_id_;
}

WebHitTestResult WebFrameWidgetImpl::HitTestResultAt(const gfx::PointF& point) {
  return CoreHitTestResultAt(point);
}

void WebFrameWidgetImpl::SetZoomLevelForTesting(double zoom_level) {
  DCHECK(ForMainFrame());
  DCHECK_NE(zoom_level, -INFINITY);
  zoom_level_for_testing_ = zoom_level;
  SetZoomLevel(zoom_level);
}

void WebFrameWidgetImpl::ResetZoomLevelForTesting() {
  DCHECK(ForMainFrame());
  zoom_level_for_testing_ = -INFINITY;
  SetZoomLevel(0);
}

void WebFrameWidgetImpl::SetDeviceScaleFactorForTesting(float factor) {
  DCHECK(ForMainFrame());
  DCHECK_GE(factor, 0.f);

  // Stash the window size before we adjust the scale factor, as subsequent
  // calls to convert will use the new scale factor.
  gfx::Size size_in_dips = widget_base_->BlinkSpaceToFlooredDIPs(Size());
  device_scale_factor_for_testing_ = factor;

  // Receiving a 0 is used to reset between tests, it removes the override in
  // order to listen to the browser for the next test.
  if (!factor)
    return;

  // We are changing the device scale factor from the renderer, so allocate a
  // new viz::LocalSurfaceId to avoid surface invariants violations in tests.
  widget_base_->LayerTreeHost()->RequestNewLocalSurfaceId();

  display::ScreenInfos screen_infos = widget_base_->screen_infos();
  screen_infos.mutable_current().device_scale_factor = factor;
  gfx::Size size_with_dsf = gfx::ScaleToCeiledSize(size_in_dips, factor);
  widget_base_->UpdateCompositorViewportAndScreenInfo(gfx::Rect(size_with_dsf),
                                                      screen_infos);
  if (!AutoResizeMode()) {
    // This picks up the new device scale factor as
    // `UpdateCompositorViewportAndScreenInfo()` has applied a new value.
    Resize(widget_base_->DIPsToCeiledBlinkSpace(size_in_dips));
  }
}

FrameWidgetTestHelper*
WebFrameWidgetImpl::GetFrameWidgetTestHelperForTesting() {
  return nullptr;
}

void WebFrameWidgetImpl::PrepareForFinalLifecyclUpdateForTesting() {
  ForEachLocalFrameControlledByWidget(
      LocalRootImpl()->GetFrame(), [](WebLocalFrameImpl* local_frame) {
        LocalFrame* core_frame = local_frame->GetFrame();
        // A frame in the frame tree is fully attached and must always have a
        // core frame.
        DCHECK(core_frame);
        Document* document = core_frame->GetDocument();
        // Similarly, a fully attached frame must always have a document.
        DCHECK(document);

        // In a web test, a rendering update may not have occurred before the
        // test finishes so ensure the transition moves out of rendering
        // blocked state.
        if (RuntimeEnabledFeatures::ViewTransitionOnNavigationEnabled()) {
          if (ViewTransition* transition =
                  ViewTransitionUtils::GetTransition(*document);
              transition && transition->IsForNavigationOnNewDocument()) {
            transition->ActivateFromSnapshot();
          }
        }
      });
}

void WebFrameWidgetImpl::ApplyLocalSurfaceIdUpdate(
    const viz::LocalSurfaceId& id) {
  if (!View()->does_composite()) {
    return;
  }
  widget_base_->LayerTreeHost()->SetLocalSurfaceIdFromParent(id);
}

void WebFrameWidgetImpl::SetMayThrottleIfUndrawnFrames(
    bool may_throttle_if_undrawn_frames) {
  if (!View()->does_composite())
    return;
  widget_base_->LayerTreeHost()->SetMayThrottleIfUndrawnFrames(
      may_throttle_if_undrawn_frames);
}

int WebFrameWidgetImpl::GetVirtualKeyboardResizeHeight() const {
  DCHECK(!virtual_keyboard_resize_height_physical_px_ || ForTopMostMainFrame());
  return virtual_keyboard_resize_height_physical_px_;
}

void WebFrameWidgetImpl::SetVirtualKeyboardResizeHeightForTesting(int height) {
  virtual_keyboard_resize_height_physical_px_ = height;
}

bool WebFrameWidgetImpl::GetMayThrottleIfUndrawnFramesForTesting() {
  return widget_base_->LayerTreeHost()
      ->GetMayThrottleIfUndrawnFramesForTesting();
}

WebPlugin* WebFrameWidgetImpl::GetFocusedPluginContainer() {
  LocalFrame* focused_frame = FocusedLocalFrameInWidget();
  if (!focused_frame)
    return nullptr;
  if (auto* container = focused_frame->GetWebPluginContainer())
    return cont
"""


```