Response:
The user wants to understand the functionality of the provided C++ code snippet from `chrome_client_impl.cc`. This is the second part of the file, so I need to summarize the functionality covered in this section.

My plan is to go through the code, function by function, and:
1. **Identify the core purpose of each function.**
2. **Check for connections to JavaScript, HTML, and CSS.**
3. **Look for logical reasoning and create example inputs/outputs if present.**
4. **Identify potential user or programming errors.**
5. **Infer how user actions might lead to these functions being called.**
6. **Finally, synthesize a concise summary of the functionality.**

Let's go through the functions:

- `DidCompleteFileChooser`:  Handles the completion of a file selection process. It manages a queue of file choosers.
- `LastSetCursorForTesting`:  A testing function to retrieve the last set cursor.
- `SetCursor`, `SetCursorInternal`, `SetCursorForPlugin`, `SetCursorOverridden`: Functions related to setting the mouse cursor, considering overrides and plugin contexts.
- `AutoscrollStart`, `AutoscrollFling`, `AutoscrollEnd`: Functions related to initiating and managing autoscrolling.
- `AcceptLanguages`: Retrieves the accepted languages from the web view preferences.
- `AttachRootLayer`:  Attaches the compositor root layer to the frame widget.
- `GetCompositorAnimationHost`, `GetScrollAnimationTimeline`: Retrieves animation-related objects from the frame widget.
- `EnterFullscreen`, `ExitFullscreen`, `FullscreenElementChanged`: Functions to manage fullscreen requests and state changes.
- `AnimateDoubleTapZoom`:  Initiates an animation for double-tap zooming.
- `HasOpenedPopup`: Checks if a popup window is open.
- `OpenPopupMenu`: Opens a popup menu, potentially an external or internal one.
- `OpenPagePopup`, `ClosePagePopup`, `PagePopupWindowForTesting`: Functions for managing page popups.
- `SetBrowserControlsState`, `SetBrowserControlsShownRatio`: Functions to control the state and visibility of browser controls.
- `ShouldOpenUIElementDuringPageDismissal`:  Determines if a UI element should be opened during page dismissal, logging errors if blocked.
- `GetFrameSinkId`: Retrieves the frame sink ID.
- `RequestDecode`: Requests image decoding.
- `NotifyPresentationTime`:  Notifies about presentation time.
- `RequestBeginMainFrameNotExpected`: Signals whether a main frame update is expected.
- `GetLayerTreeId`: Retrieves the layer tree ID.
- `SetEventListenerProperties`: Sets properties for event listeners on the compositor thread.
- `BeginLifecycleUpdates`: Signals the start of lifecycle updates.
- `RegisterForCommitObservation`, `UnregisterFromCommitObservation`, `WillCommitCompositorFrame`:  Manages observers for compositor frame commits.
- `PauseRendering`: Pauses rendering for a frame.
- `GetMaxRenderBufferBounds`: Retrieves the maximum render buffer bounds.
- `StartDeferringCommits`, `StopDeferringCommits`: Functions to control commit deferral.
- `SetHasScrollEventHandlers`:  Indicates if a frame has scroll event handlers.
- `SetNeedsLowLatencyInput`, `SetNeedsUnbufferedInputForDebugger`, `RequestUnbufferedInputEvents`: Functions to manage input event handling behavior.
- `SetTouchAction`, `SetPanAction`: Sets touch and pan actions for a frame.
- `DidChangeFormRelatedElementDynamically`:  Notifies about dynamic changes to form elements, used by Autofill.
- `ShowVirtualKeyboardOnElementFocus`:  Triggers the virtual keyboard on element focus.
- `OnMouseDown`, `HandleKeyboardEventOnTextField`, `DidChangeValueInTextField`, `DidClearValueInTextField`, `DidUserChangeContentEditableContent`, `DidEndEditingOnTextField`, `OpenTextDataListChooser`, `TextFieldDataListChanged`, `DidChangeSelectionInSelectControl`, `SelectFieldOptionsChanged`, `AjaxSucceeded`, `JavaScriptChangedValue`: Functions related to handling user interactions and changes within form elements, heavily involved with Autofill functionality.
- `GetDeviceEmulationTransform`: Retrieves the device emulation transform.
- `DidUpdateBrowserControls`:  Notifies about updates to browser controls.
- `RegisterPopupOpeningObserver`, `UnregisterPopupOpeningObserver`, `NotifyPopupOpeningObservers`:  Manages observers for popup openings.
- `ElasticOverscroll`: Retrieves the elastic overscroll amount.
- `AutofillClientFromFrame`: Helper function to get the Autofill client for a frame.
- `DidUpdateTextAutosizerPageInfo`:  Notifies about text autosizer page information changes.
- `DocumentDetached`:  Handles document detachment, disconnecting file choosers.
- `UserZoomFactor`: Retrieves the user zoom factor.
- `SetDelegatedInkMetadata`: Sets metadata for delegated ink input.
- `FormElementReset`, `PasswordFieldReset`: Functions to handle form and password field resets, relevant to Autofill.
- `ZoomFactorForViewportLayout`: Retrieves the zoom factor for viewport layout.
- `AdjustWindowRectForMinimum`, `AdjustWindowRectForDisplay`: Functions to adjust window rectangles based on minimum size and display constraints.
- `OnFirstContentfulPaint`: Notifies when the first contentful paint occurs.

**Summary of Functionality:** This part of `ChromeClientImpl` focuses on several key areas:

- **User Interaction Handling:**  Managing mouse cursor changes, autoscrolling, keyboard events, and touch/pan gestures.
- **Fullscreen API:**  Handling requests to enter and exit fullscreen mode.
- **Popup Management:** Opening and closing various types of popups (select menus, page popups).
- **Browser Controls:**  Controlling the visibility and layout of browser UI elements.
- **Compositor Integration:**  Managing the compositor layer tree, animations, and event listener properties.
- **Lifecycle Management:** Handling frame lifecycle events like commits and rendering pauses.
- **Input Event Handling:** Managing low-latency and unbuffered input for performance and debugging.
- **Autofill Integration:**  A significant portion of the code deals with integrating with the Autofill system, responding to user interactions with form elements and notifying the Autofill client.
- **Zoom and Display:** Managing user zoom levels and adjusting window sizes based on display information.
- **Performance Monitoring:** Tracking metrics like first contentful paint.
这是 `blink/renderer/core/page/chrome_client_impl.cc` 文件的第二部分，延续了第一部分的功能，主要负责实现 Chromium 特定的浏览器行为和与渲染引擎的交互。

**归纳其功能，本部分主要集中在以下方面：**

1. **文件选择（File Chooser）：**
   - `DidCompleteFileChooser`: 处理文件选择器完成后的逻辑，维护一个文件选择器的队列，确保只有一个文件选择器在活动。

2. **光标控制（Cursor Control）：**
   - `LastSetCursorForTesting`: 用于测试，获取最后一次设置的光标。
   - `SetCursor`, `SetCursorInternal`: 设置鼠标光标的样式。
   - `SetCursorForPlugin`: 为插件设置光标。
   - `SetCursorOverridden`: 设置光标是否被覆盖。

3. **自动滚动（Autoscroll）：**
   - `AutoscrollStart`, `AutoscrollFling`, `AutoscrollEnd`:  处理自动滚动的开始、惯性滑动和结束。

4. **语言设置（Language Settings）：**
   - `AcceptLanguages`: 获取浏览器接受的语言设置。

5. **图层管理（Layer Management）：**
   - `AttachRootLayer`: 将合成器的根图层附加到 `LocalFrame`。
   - `GetCompositorAnimationHost`: 获取合成器动画主机。
   - `GetScrollAnimationTimeline`: 获取滚动动画时间线。

6. **全屏处理（Fullscreen）：**
   - `EnterFullscreen`, `ExitFullscreen`: 处理进入和退出全屏的请求。
   - `FullscreenElementChanged`:  当全屏元素改变时通知。
   - `AnimateDoubleTapZoom`: 处理双击缩放动画。

7. **弹出窗口管理（Popup Management）：**
   - `HasOpenedPopup`: 检查是否有弹出窗口打开。
   - `OpenPopupMenu`: 打开下拉菜单（例如 `<select>` 元素）。
   - `OpenPagePopup`, `ClosePagePopup`, `PagePopupWindowForTesting`: 管理页面级别的弹出窗口。

8. **浏览器控件（Browser Controls）：**
   - `SetBrowserControlsState`: 设置浏览器控件的状态（例如，顶部和底部栏的高度）。
   - `SetBrowserControlsShownRatio`: 设置浏览器控件的显示比例。

9. **页面关闭时的 UI 元素显示控制：**
   - `ShouldOpenUIElementDuringPageDismissal`:  决定在页面即将关闭时是否应该显示某些 UI 元素（例如，警告对话框），并记录错误信息。

10. **合成器集成（Compositor Integration）：**
    - `GetFrameSinkId`: 获取帧接收器 ID。
    - `RequestDecode`: 请求解码图像。
    - `NotifyPresentationTime`: 通知呈现时间。
    - `RequestBeginMainFrameNotExpected`: 通知是否期望主帧更新。
    - `GetLayerTreeId`: 获取图层树 ID。
    - `SetEventListenerProperties`: 设置事件监听器的属性。
    - `BeginLifecycleUpdates`: 标记生命周期更新的开始。
    - `RegisterForCommitObservation`, `UnregisterFromCommitObservation`, `WillCommitCompositorFrame`: 管理合成器帧提交的观察者。
    - `PauseRendering`: 暂停渲染。
    - `GetMaxRenderBufferBounds`: 获取最大渲染缓冲区边界。
    - `StartDeferringCommits`, `StopDeferringCommits`: 控制提交的延迟。

11. **输入事件处理（Input Event Handling）：**
    - `SetHasScrollEventHandlers`:  设置是否有滚动事件处理器。
    - `SetNeedsLowLatencyInput`: 设置是否需要低延迟输入。
    - `SetNeedsUnbufferedInputForDebugger`: 设置调试器是否需要非缓冲输入。
    - `RequestUnbufferedInputEvents`: 请求非缓冲输入事件。
    - `SetTouchAction`, `SetPanAction`: 设置触摸和拖拽行为。

12. **表单和自动填充集成（Form and Autofill Integration）：**
    - `DidChangeFormRelatedElementDynamically`: 通知表单相关元素的动态变化。
    - `ShowVirtualKeyboardOnElementFocus`: 在元素获得焦点时显示虚拟键盘。
    - `OnMouseDown`: 处理鼠标按下事件。
    - `HandleKeyboardEventOnTextField`: 处理文本字段上的键盘事件。
    - `DidChangeValueInTextField`, `DidClearValueInTextField`: 通知文本字段值的改变和清除。
    - `DidUserChangeContentEditableContent`: 通知可编辑内容的变化。
    - `DidEndEditingOnTextField`: 通知文本字段编辑结束。
    - `OpenTextDataListChooser`: 打开文本数据列表选择器（`<datalist>`）。
    - `TextFieldDataListChanged`: 通知文本字段的数据列表发生变化。
    - `DidChangeSelectionInSelectControl`: 通知下拉选择框的选择发生变化。
    - `SelectFieldOptionsChanged`: 通知下拉选择框的选项发生变化。
    - `AjaxSucceeded`: 通知 Ajax 请求成功。
    - `JavaScriptChangedValue`: 通知 JavaScript 修改了表单元素的值。

13. **设备模拟（Device Emulation）：**
    - `GetDeviceEmulationTransform`: 获取设备模拟的变换矩阵。

14. **浏览器控件更新通知：**
    - `DidUpdateBrowserControls`: 通知浏览器控件已更新。

15. **弹出窗口打开观察者（Popup Opening Observer）：**
    - `RegisterPopupOpeningObserver`, `UnregisterPopupOpeningObserver`, `NotifyPopupOpeningObservers`: 管理监听弹出窗口打开的观察者。

16. **弹性拉伸（Elastic Overscroll）：**
    - `ElasticOverscroll`: 获取弹性拉伸的距离。

17. **自动填充客户端辅助函数：**
    - `AutofillClientFromFrame`: 从 `LocalFrame` 获取 `WebAutofillClient`。

18. **文本自动调整大小（Text Autosizer）：**
    - `DidUpdateTextAutosizerPageInfo`: 通知文本自动调整大小的页面信息已更新。

19. **文档分离处理：**
    - `DocumentDetached`: 处理文档从帧中分离的情况，断开文件选择器的连接。

20. **用户缩放（User Zoom）：**
    - `UserZoomFactor`: 获取用户的缩放因子。

21. **委托墨迹元数据（Delegated Ink Metadata）：**
    - `SetDelegatedInkMetadata`: 设置委托墨迹的元数据。

22. **表单元素重置（Form Element Reset）：**
    - `FormElementReset`, `PasswordFieldReset`: 处理表单元素和密码字段的重置事件，与自动填充相关。

23. **视口布局缩放（Viewport Layout Zoom）：**
    - `ZoomFactorForViewportLayout`: 获取视口布局的缩放因子。

24. **窗口尺寸调整（Window Rect Adjustment）：**
    - `AdjustWindowRectForMinimum`, `AdjustWindowRectForDisplay`:  根据最小尺寸和显示器信息调整窗口矩形。

25. **首次内容绘制通知（First Contentful Paint）：**
    - `OnFirstContentfulPaint`: 通知首次内容绘制事件。

**与 JavaScript, HTML, CSS 的关系举例说明：**

* **JavaScript:**
    * `OpenPopupMenu`: 当 JavaScript 代码触发 `<select>` 元素的点击事件，需要显示下拉菜单时，会调用此函数。
    * `SetCursor`: 当 JavaScript 代码监听 `mousemove` 事件，并根据鼠标位置动态改变光标样式时，会调用此函数。例如，当鼠标悬停在一个可拖拽的元素上时，JavaScript 可以设置光标为 `move`。
    * `EnterFullscreen`, `ExitFullscreen`: JavaScript 的 `element.requestFullscreen()` 和 `document.exitFullscreen()` 方法最终会调用到这些 C++ 函数。
    * `DidChangeValueInTextField`: 当用户在 `<input>` 元素中输入内容，或者 JavaScript 代码通过 `element.value = ...` 修改其值时，会触发此函数，通知 Chromium 进行自动填充等处理。
* **HTML:**
    * `OpenPopupMenu`:  对应 HTML 中的 `<select>` 元素。
    * `EnterFullscreen`:  对应 HTML 全屏 API，通常由用户或 JavaScript 触发，作用于特定的 HTML 元素。
    * `DidChangeValueInTextField`: 对应 HTML 的 `<input>` 和 `<textarea>` 等表单元素。
    * `SetTouchAction`:  对应 CSS 中的 `touch-action` 属性，用于指定元素如何响应触摸事件。Blink 需要根据 CSS 的设置来调用此函数。
* **CSS:**
    * `SetCursor`: CSS 的 `cursor` 属性决定了鼠标悬停在元素上时的光标样式。渲染引擎会根据 CSS 的设置调用此函数。
    * `SetBrowserControlsState`:  虽然不直接关联到 CSS 属性，但 CSS 的布局可能会受到浏览器控件状态的影响，例如，当浏览器工具栏隐藏时，内容区域可能会扩大。
    * `ZoomFactorForViewportLayout`: CSS 的 `@viewport` 规则可以影响视口的缩放行为，从而影响此函数的返回值。

**逻辑推理举例：**

**假设输入：** 用户点击了一个 `<select>` 元素。

**输出：** `OpenPopupMenu` 函数被调用，创建一个 `PopupMenu` 对象并返回。

**推理：**  当用户与一个需要弹出菜单的 HTML 元素交互时，Blink 引擎需要创建一个对应的原生 UI 控件来显示菜单项。`OpenPopupMenu` 负责根据平台和配置创建合适的菜单实现。

**常见的使用错误举例：**

* **编程错误：** 在 JavaScript 中错误地多次调用 `element.requestFullscreen()` 而没有相应的错误处理，可能会导致 Blink 内部状态混乱，虽然 `ChromeClientImpl` 自身会做一些检查，但过度的调用仍然可能产生问题。
* **用户操作错误：**  用户在页面加载过程中，快速地多次点击文件上传按钮（`<input type="file">`），可能会导致多个文件选择器请求被放入队列，虽然 `DidCompleteFileChooser` 有处理队列的逻辑，但过快的操作仍然可能导致意外行为。

**用户操作到达此处的调试线索：**

要调试为什么 `ChromeClientImpl` 的某个特定函数被调用，通常需要从以下用户操作入手：

1. **页面加载和渲染：**  `AttachRootLayer`, `GetCompositorAnimationHost`, `GetScrollAnimationTimeline`, `OnFirstContentfulPaint` 等函数会在页面加载和渲染过程中被调用。
2. **鼠标交互：**  鼠标移动会触发 `SetCursor`，鼠标按下会触发 `OnMouseDown`。
3. **键盘输入：**  在文本字段中输入会触发 `HandleKeyboardEventOnTextField`, `DidChangeValueInTextField` 等。
4. **表单操作：**  与 `<input>`, `<select>`, `<textarea>` 等表单元素的交互会触发一系列与自动填充相关的函数。
5. **触摸操作：**  在支持触摸的设备上进行触摸和拖拽操作会触发 `SetTouchAction`, `SetPanAction`, `AutoscrollStart` 等。
6. **全屏操作：**  用户点击全屏按钮或者 JavaScript 调用全屏 API 会触发 `EnterFullscreen`, `ExitFullscreen`。
7. **弹出窗口操作：**  点击 `<select>` 元素或者使用 JavaScript 打开新窗口会触发 `OpenPopupMenu`, `OpenPagePopup`。
8. **文件选择：**  点击 `<input type="file">` 会触发文件选择流程，最终调用 `DidCompleteFileChooser`。

通过在这些可能的入口点设置断点，可以追踪用户操作是如何一步步地触发到 `ChromeClientImpl` 中的特定函数的。

总而言之，`ChromeClientImpl` 的这部分代码是 Blink 渲染引擎与 Chromium 浏览器进行深度集成的关键桥梁，它处理了大量的浏览器行为，并将这些行为与底层的渲染机制连接起来。

Prompt: 
```
这是目录为blink/renderer/core/page/chrome_client_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
hooser(FileChooser& chooser) {
  if (!file_chooser_queue_.empty() &&
      file_chooser_queue_.front().get() != &chooser) {
    // This function is called even if |chooser| wasn't stored in
    // file_chooser_queue_.
    return;
  }
  file_chooser_queue_.EraseAt(0);
  if (file_chooser_queue_.empty())
    return;
  FileChooser* next_chooser = file_chooser_queue_.front().get();
  if (next_chooser->OpenFileChooser(*this))
    return;
  // Choosing failed, so try the next chooser.
  DidCompleteFileChooser(*next_chooser);
}

ui::Cursor ChromeClientImpl::LastSetCursorForTesting() const {
  return last_set_mouse_cursor_for_testing_;
}

void ChromeClientImpl::SetCursor(const ui::Cursor& cursor,
                                 LocalFrame* local_frame) {
  last_set_mouse_cursor_for_testing_ = cursor;
  SetCursorInternal(cursor, local_frame);
}

void ChromeClientImpl::SetCursorInternal(const ui::Cursor& cursor,
                                         LocalFrame* local_frame) {
  if (cursor_overridden_)
    return;

#if BUILDFLAG(IS_MAC)
  DCHECK(web_view_);
  // On Mac the mousemove event propagates to both the popup and main window.
  // If a popup is open we don't want the main window to change the cursor.
  if (web_view_->HasOpenedPopup())
    return;
#endif

  // TODO(dcheng): Why is this null check necessary?
  if (FrameWidget* widget = local_frame->GetWidgetForLocalRoot())
    widget->DidChangeCursor(cursor);
}

void ChromeClientImpl::SetCursorForPlugin(const ui::Cursor& cursor,
                                          LocalFrame* local_frame) {
  SetCursorInternal(cursor, local_frame);
}

void ChromeClientImpl::SetCursorOverridden(bool overridden) {
  cursor_overridden_ = overridden;
}

void ChromeClientImpl::AutoscrollStart(const gfx::PointF& viewport_point,
                                       LocalFrame* local_frame) {
  // TODO(dcheng): Why is this null check necessary?
  if (WebFrameWidgetImpl* widget =
          WebLocalFrameImpl::FromFrame(local_frame)->LocalRootFrameWidget())
    widget->AutoscrollStart(viewport_point);
}

void ChromeClientImpl::AutoscrollFling(const gfx::Vector2dF& velocity,
                                       LocalFrame* local_frame) {
  // TODO(dcheng): Why is this null check necessary?
  if (WebFrameWidgetImpl* widget =
          WebLocalFrameImpl::FromFrame(local_frame)->LocalRootFrameWidget())
    widget->AutoscrollFling(velocity);
}

void ChromeClientImpl::AutoscrollEnd(LocalFrame* local_frame) {
  // TODO(dcheng): Why is this null check necessary?
  if (WebFrameWidgetImpl* widget =
          WebLocalFrameImpl::FromFrame(local_frame)->LocalRootFrameWidget())
    widget->AutoscrollEnd();
}

String ChromeClientImpl::AcceptLanguages() {
  DCHECK(web_view_);
  return String::FromUTF8(web_view_->GetRendererPreferences().accept_languages);
}

void ChromeClientImpl::AttachRootLayer(scoped_refptr<cc::Layer> root_layer,
                                       LocalFrame* local_frame) {
  DCHECK(local_frame->IsLocalRoot());

  // This method is called during Document::Shutdown with a null |root_layer|,
  // but a widget may have never been created in some tests, so it would also
  // be null (we don't call here with a valid |root_layer| in those tests).
  FrameWidget* widget = local_frame->GetWidgetForLocalRoot();
  DCHECK(widget || !root_layer);
  if (widget)
    widget->SetRootLayer(std::move(root_layer));
}

cc::AnimationHost* ChromeClientImpl::GetCompositorAnimationHost(
    LocalFrame& local_frame) const {
  WebLocalFrameImpl* web_frame = WebLocalFrameImpl::FromFrame(local_frame);
  if (!web_frame || web_frame->IsProvisional()) {
    return nullptr;
  }
  FrameWidget* widget = local_frame.GetWidgetForLocalRoot();
  DCHECK(widget);
  return widget->AnimationHost();
}

cc::AnimationTimeline* ChromeClientImpl::GetScrollAnimationTimeline(
    LocalFrame& local_frame) const {
  FrameWidget* widget = local_frame.GetWidgetForLocalRoot();
  DCHECK(widget);
  return widget->ScrollAnimationTimeline();
}

void ChromeClientImpl::EnterFullscreen(LocalFrame& frame,
                                       const FullscreenOptions* options,
                                       FullscreenRequestType request_type) {
  DCHECK(web_view_);
  web_view_->EnterFullscreen(frame, options, request_type);
}

void ChromeClientImpl::ExitFullscreen(LocalFrame& frame) {
  DCHECK(web_view_);
  web_view_->ExitFullscreen(frame);
}

void ChromeClientImpl::FullscreenElementChanged(
    Element* old_element,
    Element* new_element,
    const FullscreenOptions* options,
    FullscreenRequestType request_type) {
  DCHECK(web_view_);
  web_view_->FullscreenElementChanged(old_element, new_element, options,
                                      request_type);
}

void ChromeClientImpl::AnimateDoubleTapZoom(const gfx::Point& point,
                                            const gfx::Rect& rect) {
  DCHECK(web_view_);
  web_view_->AnimateDoubleTapZoom(point, rect);
}

bool ChromeClientImpl::HasOpenedPopup() const {
  DCHECK(web_view_);
  return web_view_->HasOpenedPopup();
}

PopupMenu* ChromeClientImpl::OpenPopupMenu(LocalFrame& frame,
                                           HTMLSelectElement& select) {
  NotifyPopupOpeningObservers();

  if (WebViewImpl::UseExternalPopupMenus()) {
    return MakeGarbageCollected<ExternalPopupMenu>(frame, select);
  }

  DCHECK(RuntimeEnabledFeatures::PagePopupEnabled());
  return MakeGarbageCollected<InternalPopupMenu>(this, select);
}

PagePopup* ChromeClientImpl::OpenPagePopup(PagePopupClient* client) {
  DCHECK(web_view_);
  return web_view_->OpenPagePopup(client);
}

void ChromeClientImpl::ClosePagePopup(PagePopup* popup) {
  DCHECK(web_view_);
  web_view_->ClosePagePopup(popup);
}

DOMWindow* ChromeClientImpl::PagePopupWindowForTesting() const {
  DCHECK(web_view_);
  return web_view_->PagePopupWindow();
}

void ChromeClientImpl::SetBrowserControlsState(float top_height,
                                               float bottom_height,
                                               bool shrinks_layout) {
  DCHECK(web_view_);
  DCHECK(web_view_->MainFrameWidget());
  gfx::Size size = web_view_->MainFrameWidget()->Size();
  if (shrinks_layout)
    size -= gfx::Size(0, top_height + bottom_height);

  web_view_->ResizeWithBrowserControls(size, top_height, bottom_height,
                                       shrinks_layout);
}

void ChromeClientImpl::SetBrowserControlsShownRatio(float top_ratio,
                                                    float bottom_ratio) {
  DCHECK(web_view_);
  web_view_->GetBrowserControls().SetShownRatio(top_ratio, bottom_ratio);
}

bool ChromeClientImpl::ShouldOpenUIElementDuringPageDismissal(
    LocalFrame& frame,
    UIElementType ui_element_type,
    const String& dialog_message,
    Document::PageDismissalType dismissal_type) const {
  StringBuilder builder;
  builder.Append("Blocked ");
  builder.Append(UIElementTypeToString(ui_element_type));
  if (dialog_message.length()) {
    builder.Append("('");
    builder.Append(dialog_message);
    builder.Append("')");
  }
  builder.Append(" during ");
  builder.Append(DismissalTypeToString(dismissal_type));
  builder.Append(".");

  WebLocalFrameImpl::FromFrame(frame)->AddMessageToConsole(WebConsoleMessage(
      mojom::ConsoleMessageLevel::kError, builder.ToString()));

  return false;
}

viz::FrameSinkId ChromeClientImpl::GetFrameSinkId(LocalFrame* frame) {
  return frame->GetWidgetForLocalRoot()->GetFrameSinkId();
}

void ChromeClientImpl::RequestDecode(LocalFrame* frame,
                                     const PaintImage& image,
                                     base::OnceCallback<void(bool)> callback) {
  FrameWidget* widget = frame->GetWidgetForLocalRoot();
  widget->RequestDecode(image, std::move(callback));
}

void ChromeClientImpl::NotifyPresentationTime(LocalFrame& frame,
                                              ReportTimeCallback callback) {
  FrameWidget* widget = frame.GetWidgetForLocalRoot();
  if (!widget)
    return;
  widget->NotifyPresentationTimeInBlink(
      ConvertToBaseOnceCallback(std::move(callback)));
}

void ChromeClientImpl::RequestBeginMainFrameNotExpected(LocalFrame& frame,
                                                        bool request) {
  frame.GetWidgetForLocalRoot()->RequestBeginMainFrameNotExpected(request);
}

int ChromeClientImpl::GetLayerTreeId(LocalFrame& frame) {
  return frame.GetWidgetForLocalRoot()->GetLayerTreeId();
}

void ChromeClientImpl::SetEventListenerProperties(
    LocalFrame* frame,
    cc::EventListenerClass event_class,
    cc::EventListenerProperties properties) {
  DCHECK(web_view_);
  // This method is only useful when compositing is enabled.
  if (!web_view_->does_composite())
    return;

  // |frame| might be null if called via TreeScopeAdopter::
  // moveNodeToNewDocument() and the new document has no frame attached.
  // Since a document without a frame cannot attach one later, it is safe to
  // exit early.
  if (!frame)
    return;

  FrameWidget* widget = frame->GetWidgetForLocalRoot();
  // TODO(https://crbug.com/820787): When creating a local root, the widget
  // won't be set yet. While notifications in this case are technically
  // redundant, it adds an awkward special case.
  if (!widget) {
    WebLocalFrameImpl* web_frame = WebLocalFrameImpl::FromFrame(frame);
    if (web_frame->IsProvisional()) {
      // If we hit a provisional frame, we expect it to be during initialization
      // in which case the |properties| should be 'nothing'.
      DCHECK(properties == cc::EventListenerProperties::kNone);
    }
    return;
  }

  widget->SetEventListenerProperties(event_class, properties);
}

void ChromeClientImpl::BeginLifecycleUpdates(LocalFrame& main_frame) {
  DCHECK(main_frame.IsMainFrame());
  DCHECK(web_view_);
  web_view_->StopDeferringMainFrameUpdate();
}

void ChromeClientImpl::RegisterForCommitObservation(CommitObserver* observer) {
  commit_observers_.insert(observer);
}

void ChromeClientImpl::UnregisterFromCommitObservation(
    CommitObserver* observer) {
  commit_observers_.erase(observer);
}

void ChromeClientImpl::WillCommitCompositorFrame() {
  // Make a copy since callbacks may modify the set as we're iterating it.
  auto observers = commit_observers_;
  for (auto& observer : observers)
    observer->WillCommitCompositorFrame();
}

std::unique_ptr<cc::ScopedPauseRendering> ChromeClientImpl::PauseRendering(
    LocalFrame& frame) {
  // If |frame| corresponds to an iframe this implies a transition in an iframe
  // will pause rendering for the all ancestor frames (including the main frame)
  // hosted in this process.
  DCHECK(frame.IsLocalRoot());
  return WebLocalFrameImpl::FromFrame(frame)
      ->FrameWidgetImpl()
      ->PauseRendering();
}

std::optional<int> ChromeClientImpl::GetMaxRenderBufferBounds(
    LocalFrame& frame) const {
  return WebLocalFrameImpl::FromFrame(frame)
      ->LocalRootFrameWidget()
      ->GetMaxRenderBufferBounds();
}

bool ChromeClientImpl::StartDeferringCommits(LocalFrame& main_frame,
                                             base::TimeDelta timeout,
                                             cc::PaintHoldingReason reason) {
  DCHECK(main_frame.IsLocalRoot());
  return WebLocalFrameImpl::FromFrame(main_frame)
      ->FrameWidgetImpl()
      ->StartDeferringCommits(timeout, reason);
}

void ChromeClientImpl::StopDeferringCommits(
    LocalFrame& main_frame,
    cc::PaintHoldingCommitTrigger trigger) {
  DCHECK(main_frame.IsLocalRoot());
  WebLocalFrameImpl::FromFrame(main_frame)
      ->FrameWidgetImpl()
      ->StopDeferringCommits(trigger);
}

void ChromeClientImpl::SetHasScrollEventHandlers(LocalFrame* frame,
                                                 bool has_event_handlers) {
  // |frame| might be null if called via
  // TreeScopeAdopter::MoveNodeToNewDocument() and the new document has no frame
  // attached. Since a document without a frame cannot attach one later, it is
  // safe to exit early.
  if (!frame)
    return;

  WebLocalFrameImpl::FromFrame(frame)
      ->LocalRootFrameWidget()
      ->SetHaveScrollEventHandlers(has_event_handlers);
}

void ChromeClientImpl::SetNeedsLowLatencyInput(LocalFrame* frame,
                                               bool needs_low_latency) {
  DCHECK(frame);
  WebLocalFrameImpl* web_frame = WebLocalFrameImpl::FromFrame(frame);
  WebFrameWidgetImpl* widget = web_frame->LocalRootFrameWidget();
  if (!widget)
    return;

  widget->SetNeedsLowLatencyInput(needs_low_latency);
}

void ChromeClientImpl::SetNeedsUnbufferedInputForDebugger(LocalFrame* frame,
                                                          bool unbuffered) {
  DCHECK(frame);
  WebLocalFrameImpl* web_frame = WebLocalFrameImpl::FromFrame(frame);
  WebFrameWidgetImpl* widget = web_frame->LocalRootFrameWidget();
  if (!widget)
    return;

  widget->SetNeedsUnbufferedInputForDebugger(unbuffered);
}

void ChromeClientImpl::RequestUnbufferedInputEvents(LocalFrame* frame) {
  DCHECK(frame);
  WebLocalFrameImpl* web_frame = WebLocalFrameImpl::FromFrame(frame);
  WebFrameWidgetImpl* widget = web_frame->LocalRootFrameWidget();
  if (!widget)
    return;

  widget->RequestUnbufferedInputEvents();
}

void ChromeClientImpl::SetTouchAction(LocalFrame* frame,
                                      TouchAction touch_action) {
  DCHECK(frame);
  WebLocalFrameImpl* web_frame = WebLocalFrameImpl::FromFrame(frame);
  WebFrameWidgetImpl* widget = web_frame->LocalRootFrameWidget();
  if (!widget)
    return;

  widget->ProcessTouchAction(touch_action);
}

void ChromeClientImpl::SetPanAction(LocalFrame* frame,
                                    mojom::blink::PanAction pan_action) {
  DCHECK(frame);
  WebLocalFrameImpl* web_frame = WebLocalFrameImpl::FromFrame(frame);
  WebFrameWidgetImpl* widget = web_frame->LocalRootFrameWidget();
  if (!widget)
    return;

  widget->SetPanAction(pan_action);
}

void ChromeClientImpl::DidChangeFormRelatedElementDynamically(
    LocalFrame* frame,
    HTMLElement* element,
    WebFormRelatedChangeType form_related_change) {
  if (auto* fill_client = AutofillClientFromFrame(frame)) {
    fill_client->DidChangeFormRelatedElementDynamically(element,
                                                        form_related_change);
  }
}

void ChromeClientImpl::ShowVirtualKeyboardOnElementFocus(LocalFrame& frame) {
  WebLocalFrameImpl::FromFrame(frame)
      ->LocalRootFrameWidget()
      ->ShowVirtualKeyboardOnElementFocus();
}

void ChromeClientImpl::OnMouseDown(Node& mouse_down_node) {
  if (auto* fill_client =
          AutofillClientFromFrame(mouse_down_node.GetDocument().GetFrame())) {
    fill_client->DidReceiveLeftMouseDownOrGestureTapInNode(
        WebNode(&mouse_down_node));
  }
}

void ChromeClientImpl::HandleKeyboardEventOnTextField(
    HTMLInputElement& input_element,
    KeyboardEvent& event) {
  if (auto* fill_client =
          AutofillClientFromFrame(input_element.GetDocument().GetFrame())) {
    fill_client->TextFieldDidReceiveKeyDown(WebInputElement(&input_element),
                                            WebKeyboardEventBuilder(event));
  }
}

void ChromeClientImpl::DidChangeValueInTextField(
    HTMLFormControlElement& element) {
  Document& doc = element.GetDocument();
  if (auto* fill_client = AutofillClientFromFrame(doc.GetFrame()))
    fill_client->TextFieldDidChange(WebFormControlElement(&element));

  // Value changes caused by |document.execCommand| calls should not be
  // interpreted as a user action. See https://crbug.com/764760.
  if (!doc.IsRunningExecCommand()) {
    UseCounter::Count(doc, doc.GetExecutionContext()->IsSecureContext()
                               ? WebFeature::kFieldEditInSecureContext
                               : WebFeature::kFieldEditInNonSecureContext);
    // The resource coordinator is not available in some tests.
    if (auto* rc = doc.GetResourceCoordinator())
      rc->SetHadFormInteraction();
  }
}

void ChromeClientImpl::DidClearValueInTextField(
    HTMLFormControlElement& element) {
  Document& doc = element.GetDocument();
  if (auto* fill_client = AutofillClientFromFrame(doc.GetFrame())) {
    fill_client->TextFieldCleared(WebFormControlElement(&element));
  }
}

void ChromeClientImpl::DidUserChangeContentEditableContent(Element& element) {
  Document& doc = element.GetDocument();
  // Selecting the focused element as we are only interested in changes made by
  // the user. We assume the user must focus the field to type into it.
  WebElement focused_element = doc.FocusedElement();
  // If element argument is not the focused element we can assume the user
  // was not typing (this covers cases like element.innerText = 'foo').
  // Value changes caused by |document.execCommand| calls should not be
  // interpreted as a user action. See https://crbug.com/764760.
  if (!element.IsFocusedElementInDocument() || doc.IsRunningExecCommand()) {
    return;
  }
  if (auto* fill_client = AutofillClientFromFrame(doc.GetFrame())) {
    fill_client->ContentEditableDidChange(focused_element);
  }
}

void ChromeClientImpl::DidEndEditingOnTextField(
    HTMLInputElement& input_element) {
  if (auto* fill_client =
          AutofillClientFromFrame(input_element.GetDocument().GetFrame())) {
    fill_client->TextFieldDidEndEditing(WebInputElement(&input_element));
  }
}

void ChromeClientImpl::OpenTextDataListChooser(HTMLInputElement& input) {
  NotifyPopupOpeningObservers();
  if (auto* fill_client =
          AutofillClientFromFrame(input.GetDocument().GetFrame())) {
    fill_client->OpenTextDataListChooser(WebInputElement(&input));
  }
}

void ChromeClientImpl::TextFieldDataListChanged(HTMLInputElement& input) {
  if (auto* fill_client =
          AutofillClientFromFrame(input.GetDocument().GetFrame())) {
    fill_client->DataListOptionsChanged(WebInputElement(&input));
  }
}

void ChromeClientImpl::DidChangeSelectionInSelectControl(
    HTMLFormControlElement& element) {
  Document& doc = element.GetDocument();
  if (auto* fill_client = AutofillClientFromFrame(doc.GetFrame()))
    fill_client->SelectControlDidChange(WebFormControlElement(&element));
}

void ChromeClientImpl::SelectFieldOptionsChanged(
    HTMLFormControlElement& element) {
  Document& doc = element.GetDocument();
  if (auto* fill_client = AutofillClientFromFrame(doc.GetFrame())) {
    fill_client->SelectFieldOptionsChanged(WebFormControlElement(&element));
  }
}

void ChromeClientImpl::AjaxSucceeded(LocalFrame* frame) {
  if (auto* fill_client = AutofillClientFromFrame(frame))
    fill_client->AjaxSucceeded();
}

void ChromeClientImpl::JavaScriptChangedValue(HTMLFormControlElement& element,
                                              const String& old_value,
                                              bool was_autofilled) {
  Document& doc = element.GetDocument();
  if (auto* fill_client = AutofillClientFromFrame(doc.GetFrame())) {
    fill_client->JavaScriptChangedValue(WebFormControlElement(&element),
                                        old_value, was_autofilled);
  }
}

gfx::Transform ChromeClientImpl::GetDeviceEmulationTransform() const {
  DCHECK(web_view_);
  return web_view_->GetDeviceEmulationTransform();
}

void ChromeClientImpl::DidUpdateBrowserControls() const {
  DCHECK(web_view_);
  web_view_->DidUpdateBrowserControls();
}

void ChromeClientImpl::RegisterPopupOpeningObserver(
    PopupOpeningObserver* observer) {
  DCHECK(observer);
  popup_opening_observers_.insert(observer);
}

void ChromeClientImpl::UnregisterPopupOpeningObserver(
    PopupOpeningObserver* observer) {
  DCHECK(popup_opening_observers_.Contains(observer));
  popup_opening_observers_.erase(observer);
}

void ChromeClientImpl::NotifyPopupOpeningObservers() const {
  const HeapHashSet<WeakMember<PopupOpeningObserver>> observers(
      popup_opening_observers_);
  for (const auto& observer : observers)
    observer->WillOpenPopup();
}

gfx::Vector2dF ChromeClientImpl::ElasticOverscroll() const {
  DCHECK(web_view_);
  return web_view_->ElasticOverscroll();
}

WebAutofillClient* ChromeClientImpl::AutofillClientFromFrame(
    LocalFrame* frame) {
  if (!frame) {
    // It is possible to pass nullptr to this method. For instance the call from
    // OnMouseDown might be nullptr. See https://crbug.com/739199.
    return nullptr;
  }

  return WebLocalFrameImpl::FromFrame(frame)->AutofillClient();
}

void ChromeClientImpl::DidUpdateTextAutosizerPageInfo(
    const mojom::blink::TextAutosizerPageInfo& page_info) {
  DCHECK(web_view_);
  web_view_->TextAutosizerPageInfoChanged(page_info);
}

void ChromeClientImpl::DocumentDetached(Document& document) {
  for (auto& it : file_chooser_queue_) {
    if (it->FrameOrNull() == document.GetFrame())
      it->DisconnectClient();
  }
}

double ChromeClientImpl::UserZoomFactor(LocalFrame* frame) const {
  DCHECK(web_view_);
  return ZoomLevelToZoomFactor(
      WebLocalFrameImpl::FromFrame(frame->LocalFrameRoot())
          ->FrameWidgetImpl()
          ->GetZoomLevel());
}

void ChromeClientImpl::SetDelegatedInkMetadata(
    LocalFrame* frame,
    std::unique_ptr<gfx::DelegatedInkMetadata> metadata) {
  frame->GetWidgetForLocalRoot()->SetDelegatedInkMetadata(std::move(metadata));
}

void ChromeClientImpl::FormElementReset(HTMLFormElement& element) {
  Document& doc = element.GetDocument();
  if (auto* fill_client = AutofillClientFromFrame(doc.GetFrame()))
    fill_client->FormElementReset(WebFormElement(&element));
}

void ChromeClientImpl::PasswordFieldReset(HTMLInputElement& element) {
  if (auto* fill_client =
          AutofillClientFromFrame(element.GetDocument().GetFrame())) {
    fill_client->PasswordFieldReset(WebInputElement(&element));
  }
}

float ChromeClientImpl::ZoomFactorForViewportLayout() {
  DCHECK(web_view_);
  return web_view_->ZoomFactorForViewportLayout();
}

gfx::Rect ChromeClientImpl::AdjustWindowRectForMinimum(
    const gfx::Rect& pending_rect,
    int minimum_size) {
  gfx::Rect window = pending_rect;

  // Let size 0 pass through, since that indicates default size, not minimum
  // size.
  if (window.width()) {
    window.set_width(std::max(minimum_size, window.width()));
  }
  if (window.height()) {
    window.set_height(std::max(minimum_size, window.height()));
  }
  return window;
}

gfx::Rect ChromeClientImpl::AdjustWindowRectForDisplay(
    const gfx::Rect& pending_rect,
    LocalFrame& frame,
    int minimum_size) {
  DCHECK_EQ(pending_rect,
            AdjustWindowRectForMinimum(pending_rect, minimum_size))
      << "Make sure to first use AdjustWindowRectForMinimum to adjust "
         "pending_rect for minimum.";
  gfx::Rect screen = GetScreenInfo(frame).available_rect;
  gfx::Rect window = pending_rect;

  gfx::Size size_for_constraining_move = MinimumWindowSize();
  // Let size 0 pass through, since that indicates default size, not minimum
  // size.
  if (window.width()) {
    window.set_width(std::min(window.width(), screen.width()));
    size_for_constraining_move.set_width(window.width());
  }
  if (window.height()) {
    window.set_height(std::min(window.height(), screen.height()));
    size_for_constraining_move.set_height(window.height());
  }

  // Constrain the window position within the valid screen area.
  window.set_x(
      std::max(screen.x(),
               std::min(window.x(),
                        screen.right() - size_for_constraining_move.width())));
  window.set_y(std::max(
      screen.y(),
      std::min(window.y(),
               screen.bottom() - size_for_constraining_move.height())));

  // Coarsely measure whether coordinates may be requesting another screen.
  if (!screen.Contains(window)) {
    UseCounter::Count(frame.DomWindow(),
                      WebFeature::kDOMWindowSetWindowRectCrossScreen);
  }

  return window;
}

void ChromeClientImpl::OnFirstContentfulPaint() {
  web_view_->OnFirstContentfulPaint();
}

}  // namespace blink

"""


```