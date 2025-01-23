Response:
The user wants to understand the functionality of the provided C++ code snippet from `web_view_impl.cc`, which is part of the Chromium Blink rendering engine. Specifically, I need to:

1. **List the functionalities** present in the code.
2. **Identify connections to web technologies (JavaScript, HTML, CSS)** and provide examples.
3. **Analyze logical inferences** and illustrate with input/output examples.
4. **Point out common user/programming errors** related to the code.
5. **Describe the user actions** that could lead to this code being executed (debugging clues).
6. **Summarize the overall function** of this specific code section as part 2 of 6.

Let's break down the code section by section to address these points:

* **`StartPageScaleAnimation` and related functions (`EnableFakePageScaleAnimationForTesting`)**:  These functions deal with animating the page zoom level. They are triggered programmatically or via user interaction.
* **`AcceptLanguagesChanged`**: This function updates the font cache and notifies the page about changes in accepted languages, impacting how text is rendered.
* **`WidenRectWithinPageBounds`**:  This utility function calculates a wider rectangle while staying within the document bounds, likely used for zooming or highlighting.
* **`MaximumLegiblePageScale`**: This determines the maximum zoom level for readability, considering accessibility settings.
* **`ComputeScaleAndScrollForBlockRect`**: This is a core function for calculating the appropriate zoom level and scroll position to bring a specific block of content into view, used for features like double-tap zoom and find-in-page.
* **`FindLinkHighlightAncestor` and `BestTapNode`**: These functions identify the most appropriate DOM node to highlight when a user taps on a link, considering factors like cursor styles and editable content.
* **`EnableTapHighlightAtPoint`**:  This function triggers the visual highlighting of a tapped link.
* **`AnimateDoubleTapZoom`**:  This orchestrates the zoom animation triggered by a double-tap gesture.
* **`ZoomToFindInPageRect`**: This function handles zooming to the result of a find-in-page operation.
* **`SendContextMenuEvent`**: This function triggers the display of the context menu (right-click menu).
* **`OpenPagePopup`, `CancelPagePopup`, `ClosePagePopup`, `CleanupPagePopup`, `UpdatePagePopup`, `EnablePopupMouseWheelEventListener`, `DisablePopupMouseWheelEventListener`, `PagePopupWindow`**: These functions manage the lifecycle of popup windows within the web view.
* **`FocusedCoreFrame`**: Returns the currently focused frame within the page.
* **`Close`**: Handles the destruction of the `WebViewImpl` object and its associated resources.
* **`Size`, `ResizeVisualViewport`**: Functions related to the size and resizing of the viewport.
* **`DidFirstVisuallyNonEmptyPaint`, `OnFirstContentfulPaint`**: Lifecycle notifications about the painting process.
* **`UpdateICBAndResizeViewport`**: Manages the resizing of the viewport, taking into account browser controls.
* **`UpdateBrowserControlsConstraint`, `DidUpdateBrowserControls`, `GetBrowserControls`**: Functions related to the management and state of browser controls (like the address bar).
* **`ResizeViewWhileAnchored`**: Handles resizing while maintaining an anchor point, often related to browser control visibility changes.
* **`ResizeWithBrowserControls` (multiple overloads)**: Functions responsible for resizing the web view, considering browser controls.
* **`Resize`**: A simpler resize function.
* **`SetScreenOrientationOverrideForTesting`, `SetWindowRectSynchronouslyForTesting`, `ScreenOrientationOverride`**: Testing-related functions.
* **`DidEnterFullscreen`, `DidExitFullscreen`**: Notifications for entering and exiting fullscreen mode.
* **`SetMainFrameViewWidget`**: Sets the widget associated with the main frame.
* **`SetMouseOverURL`, `SetKeyboardFocusURL`, `MainFrameViewWidget`**: Functions related to tracking URLs and the main frame widget.
* **`PaintContent`**: Handles painting the content of the WebView when compositing is disabled.
* **`ApplyWebPreferences`**: Applies various web preferences to the WebView.
这是 `blink/renderer/core/exported/web_view_impl.cc` 文件代码片段的第 2 部分，主要负责处理以下功能：

**核心功能归纳:**

* **页面缩放动画和控制:**  这部分代码详细处理了页面缩放的启动、动画以及相关的计算。包括用户手势触发的缩放（例如双击缩放）和程序控制的缩放（例如“查找页面”功能）。
* **语言设置:** 响应语言设置的更改，并更新字体缓存和通知页面。
* **辅助功能相关的缩放:**  计算最大可读的缩放比例，考虑了辅助功能字体缩放因子。
* **点击高亮:**  实现了用户点击链接时的高亮显示功能。
* **上下文菜单:**  处理上下文菜单的显示。
* **弹出窗口管理:**  管理页面内的弹出窗口（PagePopup）的创建、取消、关闭和更新。
* **焦点管理:**  获取当前聚焦的 Frame。
* **WebView生命周期管理 (Close):** 处理 `WebViewImpl` 对象的销毁。
* **尺寸调整和布局更新:**  处理 `WebView` 尺寸的变化，包括考虑浏览器控件的影响。
* **全屏管理:**  通知全屏状态的进入和退出。
* **URL追踪:**  记录鼠标悬停和键盘焦点所在的 URL。
* **非合成模式下的绘制:**  在非合成模式下，负责绘制 WebView 的内容。
* **WebPreferences 应用:**  应用 Web 偏好设置。

**与 JavaScript, HTML, CSS 的关系及举例:**

1. **页面缩放 (JavaScript/CSS):**
   * **功能:** `StartPageScaleAnimation` 函数会最终影响页面的渲染比例，这直接反映在 CSS 的 `zoom` 属性或者更底层的渲染机制上。JavaScript 可以通过 `window.scrollTo()` 或其他方式触发 programmatic 的缩放，从而间接调用到这里的代码。
   * **假设输入与输出:**
      * **假设输入:** 用户双击页面上的某个区域 (触发 `AnimateDoubleTapZoom`)，该区域的 `block_rect_in_root_frame` 为 `gfx::Rect(100, 100, 200, 100)`，当前 `PageScaleFactor()` 为 1.0。
      * **输出:**  `ComputeScaleAndScrollForBlockRect` 会计算出一个新的 `scale` (可能大于 1.0) 和 `scroll` 值，使得双击区域放大并居中显示。`StartPageScaleAnimation` 会启动一个动画，平滑地将页面缩放到新的比例和位置。

2. **语言设置 (HTML/CSS):**
   * **功能:** `AcceptLanguagesChanged` 接收浏览器设置的偏好语言，并更新 `FontCache`。这影响浏览器如何选择合适的字体来渲染 HTML 内容，特别是当 HTML 中使用了语言相关的字体族 (e.g., `font-family: sans-serif`)。
   * **举例说明:**  用户在浏览器设置中将首选语言设置为 "zh-CN"。浏览器通知 Blink 引擎，`AcceptLanguagesChanged` 被调用，`FontCache` 会更新，以便在渲染中文页面时选择合适的无衬线字体。

3. **点击高亮 (HTML/CSS):**
   * **功能:** `BestTapNode` 会检查被点击的元素及其祖先节点的 CSS `cursor` 属性，特别是 `cursor: pointer`。如果找到这样的节点，且该节点不是可编辑的，`EnableTapHighlightAtPoint` 会在该节点上显示高亮效果，这通常通过添加特定的 CSS 类或伪类来实现。
   * **举例说明:** 用户点击一个带有 `<a href="...">` 标签的链接。该链接的 CSS 规则可能包含 `cursor: pointer;`。`BestTapNode` 会找到这个 `<a>` 元素，`EnableTapHighlightAtPoint` 会在该链接上短暂显示一个高亮效果，提示用户点击已生效。

4. **上下文菜单 (HTML):**
   * **功能:** `SendContextMenuEvent` 的调用通常由用户右键点击页面触发。浏览器会将这个事件传递给渲染引擎，渲染引擎会根据用户点击的位置和上下文，决定是否显示浏览器的默认上下文菜单，或者由页面上的 JavaScript 代码自定义的上下文菜单 (通过监听 `contextmenu` 事件)。
   * **用户操作:** 用户在网页的某个元素上点击鼠标右键。

5. **弹出窗口 (JavaScript):**
   * **功能:** `OpenPagePopup` 等函数与 JavaScript 的 `window.open()` 方法创建的弹出窗口相关。当 JavaScript 代码尝试打开一个新的弹出窗口时，会调用到这些 Blink 引擎的函数来创建和管理该窗口。
   * **假设输入与输出:**
      * **假设输入:** JavaScript 代码执行 `window.open('popup.html', '_blank', 'width=400,height=300')`。
      * **输出:** `OpenPagePopup` 会被调用，创建一个 `WebPagePopupImpl` 对象，并与浏览器进程通信，创建一个新的渲染进程和窗口来加载 `popup.html`。

**用户或编程常见的使用错误及举例说明:**

1. **不正确的缩放参数:** 开发者在 JavaScript 中使用 `window.scrollTo()` 或其他 API 进行页面滚动或缩放时，如果提供的参数超出范围或不合理，可能会导致 `StartPageScaleAnimation` 或相关的计算函数产生意料之外的结果，例如页面缩放过大或过小，或者滚动位置错误。
   * **举例:**  开发者尝试将页面缩放到一个非常小的比例，例如 0.01，这可能导致页面内容几乎不可见。

2. **弹出窗口管理不当:**  开发者在 JavaScript 中创建了弹出窗口后，没有正确地关闭或管理这些窗口，可能导致资源泄漏或用户体验问题。Blink 引擎的弹出窗口管理机制可以帮助避免一些问题，但最终还是依赖开发者的正确使用。
   * **举例:** 开发者使用 `window.open()` 创建了一个弹出窗口，但在主窗口关闭时忘记关闭该弹出窗口，导致弹出窗口仍然存在。

**用户操作如何一步步到达这里 (调试线索):**

1. **页面缩放:**
   * 用户使用鼠标滚轮配合 Ctrl 键进行缩放。
   * 用户使用触摸板或触摸屏进行捏合缩放。
   * 用户双击页面上的某个区域。
   * 网页上的 JavaScript 代码调用 `window.scrollTo()` 或其他相关 API。

2. **语言设置:**
   * 用户在浏览器的设置中更改了首选语言。

3. **点击高亮:**
   * 用户在触摸屏设备上点击一个链接。

4. **上下文菜单:**
   * 用户在网页元素上点击鼠标右键。
   * 在某些平台上，用户按下特定的键盘组合键 (虽然此代码片段中 Mac 平台的情况被排除)。

5. **弹出窗口:**
   * 网页上的 JavaScript 代码调用 `window.open()`。

**作为调试线索:**

* 如果页面缩放出现异常，可以在 `StartPageScaleAnimation` 和 `ComputeScaleAndScrollForBlockRect` 中设置断点，查看缩放目标位置、比例等参数的计算过程。
* 如果点击高亮效果不正确，可以在 `BestTapNode` 中设置断点，查看哪个 DOM 节点被选中，以及 CSS `cursor` 属性是否正确。
* 如果弹出窗口行为异常，可以在 `OpenPagePopup`、`CancelPagePopup` 等函数中设置断点，追踪弹出窗口的创建和销毁过程。

**第 2 部分功能归纳:**

总的来说，这个代码片段是 `WebViewImpl` 中处理用户交互和程序控制的页面显示特性（如缩放、高亮）、管理页面行为（如弹出窗口）以及响应环境变化（如语言设置）的关键部分。它连接了浏览器提供的用户界面事件和偏好设置与 Blink 引擎的渲染和布局逻辑。

### 提示词
```
这是目录为blink/renderer/core/exported/web_view_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
ScrollType::kProgrammatic);
      }

      return false;
    }
  }
  if (use_anchor && new_scale == PageScaleFactor())
    return false;

  if (enable_fake_page_scale_animation_for_testing_) {
    fake_page_scale_animation_target_position_ = target_position;
    fake_page_scale_animation_use_anchor_ = use_anchor;
    fake_page_scale_animation_page_scale_factor_ = new_scale;
  } else {
    MainFrameImpl()->FrameWidgetImpl()->StartPageScaleAnimation(
        target_position, use_anchor, new_scale, duration);
  }
  return true;
}

void WebViewImpl::EnableFakePageScaleAnimationForTesting(bool enable) {
  enable_fake_page_scale_animation_for_testing_ = enable;
  fake_page_scale_animation_target_position_ = gfx::Point();
  fake_page_scale_animation_use_anchor_ = false;
  fake_page_scale_animation_page_scale_factor_ = 0;
}

void WebViewImpl::AcceptLanguagesChanged() {
  FontCache::AcceptLanguagesChanged(
      String::FromUTF8(renderer_preferences_.accept_languages));

  if (!GetPage())
    return;

  GetPage()->AcceptLanguagesChanged();
}

gfx::Rect WebViewImpl::WidenRectWithinPageBounds(const gfx::Rect& source,
                                                 int target_margin,
                                                 int minimum_margin) {
  // Caller should guarantee that the main frame exists and is local.
  DCHECK(MainFrame());
  DCHECK(MainFrame()->IsWebLocalFrame());
  gfx::Size max_size = MainFrame()->ToWebLocalFrame()->DocumentSize();
  gfx::PointF scroll_offset = MainFrame()->ToWebLocalFrame()->GetScrollOffset();

  int left_margin = target_margin;
  int right_margin = target_margin;

  const int absolute_source_x = source.x() + scroll_offset.x();
  if (left_margin > absolute_source_x) {
    left_margin = absolute_source_x;
    right_margin = std::max(left_margin, minimum_margin);
  }

  const int maximum_right_margin =
      max_size.width() - (source.width() + absolute_source_x);
  if (right_margin > maximum_right_margin) {
    right_margin = maximum_right_margin;
    left_margin = std::min(left_margin, std::max(right_margin, minimum_margin));
  }

  const int new_width = source.width() + left_margin + right_margin;
  const int new_x = source.x() - left_margin;

  DCHECK_GE(new_width, 0);
  DCHECK_LE(scroll_offset.x() + new_x + new_width, max_size.width());

  return gfx::Rect(new_x, source.y(), new_width, source.height());
}

float WebViewImpl::MaximumLegiblePageScale() const {
  // Pages should be as legible as on desktop when at dpi scale, so no
  // need to zoom in further when automatically determining zoom level
  // (after double tap, find in page, etc), though the user should still
  // be allowed to manually pinch zoom in further if they desire.
  if (GetPage()) {
    return maximum_legible_scale_ *
           GetPage()->GetSettings().GetAccessibilityFontScaleFactor();
  }
  return maximum_legible_scale_;
}

void WebViewImpl::ComputeScaleAndScrollForBlockRect(
    const gfx::Point& hit_point_in_root_frame,
    const gfx::Rect& block_rect_in_root_frame,
    float padding,
    float default_scale_when_already_legible,
    float& scale,
    gfx::Point& scroll) {
  DCHECK(GetPage()->GetVisualViewport().IsActiveViewport());
  scale = PageScaleFactor();
  scroll = gfx::Point();

  gfx::Rect rect = block_rect_in_root_frame;

  if (!rect.IsEmpty()) {
    float default_margin = doubleTapZoomContentDefaultMargin;
    float minimum_margin = doubleTapZoomContentMinimumMargin;
    // We want the margins to have the same physical size, which means we
    // need to express them in post-scale size. To do that we'd need to know
    // the scale we're scaling to, but that depends on the margins. Instead
    // we express them as a fraction of the target rectangle: this will be
    // correct if we end up fully zooming to it, and won't matter if we
    // don't.
    rect = WidenRectWithinPageBounds(
        rect, static_cast<int>(default_margin * rect.width() / size_.width()),
        static_cast<int>(minimum_margin * rect.width() / size_.width()));
    // Fit block to screen, respecting limits.
    scale = static_cast<float>(size_.width()) / rect.width();
    scale = std::min(scale, MaximumLegiblePageScale());
    if (PageScaleFactor() < default_scale_when_already_legible)
      scale = std::max(scale, default_scale_when_already_legible);
    scale = ClampPageScaleFactorToLimits(scale);
  }

  // FIXME: If this is being called for auto zoom during find in page,
  // then if the user manually zooms in it'd be nice to preserve the
  // relative increase in zoom they caused (if they zoom out then it's ok
  // to zoom them back in again). This isn't compatible with our current
  // double-tap zoom strategy (fitting the containing block to the screen)
  // though.

  float screen_width = size_.width() / scale;
  float screen_height = size_.height() / scale;

  // Scroll to vertically align the block.
  if (rect.height() < screen_height) {
    // Vertically center short blocks.
    rect.Offset(0, -0.5 * (screen_height - rect.height()));
  } else {
    // Ensure position we're zooming to (+ padding) isn't off the bottom of
    // the screen.
    rect.set_y(std::max<float>(
        rect.y(), hit_point_in_root_frame.y() + padding - screen_height));
  }  // Otherwise top align the block.

  // Do the same thing for horizontal alignment.
  if (rect.width() < screen_width) {
    rect.Offset(-0.5 * (screen_width - rect.width()), 0);
  } else {
    rect.set_x(std::max<float>(
        rect.x(), hit_point_in_root_frame.x() + padding - screen_width));
  }
  scroll.set_x(rect.x());
  scroll.set_y(rect.y());

  scale = ClampPageScaleFactorToLimits(scale);
  scroll = MainFrameImpl()->GetFrameView()->RootFrameToDocument(scroll);
  scroll =
      GetPage()->GetVisualViewport().ClampDocumentOffsetAtScale(scroll, scale);
}

static Node* FindLinkHighlightAncestor(Node* node) {
  // Go up the tree to find the node that defines a mouse cursor style
  while (node) {
    const LinkHighlightCandidate type = node->IsLinkHighlightCandidate();
    if (type == LinkHighlightCandidate::kYes)
      return node;
    if (type == LinkHighlightCandidate::kNo)
      return nullptr;
    node = LayoutTreeBuilderTraversal::Parent(*node);
  }
  return nullptr;
}

// This is for tap (link) highlight and is tested in
// link_highlight_impl_test.cc.
Node* WebViewImpl::BestTapNode(
    const GestureEventWithHitTestResults& targeted_tap_event) {
  TRACE_EVENT0("input", "WebViewImpl::bestTapNode");

  Page* page = page_.Get();
  if (!page || !page->MainFrame())
    return nullptr;

  Node* best_touch_node = targeted_tap_event.GetHitTestResult().InnerNode();
  if (!best_touch_node)
    return nullptr;

  // We might hit something like an image map that has no layoutObject on it
  // Walk up the tree until we have a node with an attached layoutObject
  while (!best_touch_node->GetLayoutObject()) {
    best_touch_node = LayoutTreeBuilderTraversal::Parent(*best_touch_node);
    if (!best_touch_node)
      return nullptr;
  }

  // Editable nodes should not be highlighted (e.g., <input>)
  if (IsEditable(*best_touch_node))
    return nullptr;

  Node* hand_cursor_ancestor = FindLinkHighlightAncestor(best_touch_node);
  // We show a highlight on tap only when the current node shows a hand cursor
  if (!hand_cursor_ancestor) {
    return nullptr;
  }

  // We should pick the largest enclosing node with hand cursor set. We do this
  // by first jumping up to the closest ancestor with hand cursor set. Then we
  // locate the next ancestor up in the the tree and repeat the jumps as long as
  // the node has hand cursor set.
  do {
    best_touch_node = hand_cursor_ancestor;
    hand_cursor_ancestor = FindLinkHighlightAncestor(
        LayoutTreeBuilderTraversal::Parent(*best_touch_node));
  } while (hand_cursor_ancestor);

  // This happens in cases like:
  // <div style="display: contents; cursor: pointer">Text</div>.
  // The text node inherits cursor: pointer and the div doesn't have a
  // LayoutObject, so |best_touch_node| is the text node here. We should not
  // return the text node because it can't have touch actions.
  if (best_touch_node->IsTextNode())
    return nullptr;

  return best_touch_node;
}

void WebViewImpl::EnableTapHighlightAtPoint(
    const GestureEventWithHitTestResults& targeted_tap_event) {
  DCHECK(MainFrameImpl());
  Node* touch_node = BestTapNode(targeted_tap_event);
  GetPage()->GetLinkHighlight().SetTapHighlight(touch_node);
  MainFrameWidget()->UpdateLifecycle(WebLifecycleUpdate::kAll,
                                     DocumentUpdateReason::kTapHighlight);
}

void WebViewImpl::AnimateDoubleTapZoom(const gfx::Point& point_in_root_frame,
                                       const gfx::Rect& rect_to_zoom) {
  DCHECK(MainFrameImpl());

  float scale;
  gfx::Point scroll;

  ComputeScaleAndScrollForBlockRect(
      point_in_root_frame, rect_to_zoom, touchPointPadding,
      MinimumPageScaleFactor() * doubleTapZoomAlreadyLegibleRatio, scale,
      scroll);

  bool still_at_previous_double_tap_scale =
      (PageScaleFactor() == double_tap_zoom_page_scale_factor_ &&
       double_tap_zoom_page_scale_factor_ != MinimumPageScaleFactor()) ||
      double_tap_zoom_pending_;

  bool scale_unchanged = fabs(PageScaleFactor() - scale) < minScaleDifference;
  bool should_zoom_out = rect_to_zoom.IsEmpty() || scale_unchanged ||
                         still_at_previous_double_tap_scale;

  bool is_animating;

  if (should_zoom_out) {
    scale = MinimumPageScaleFactor();
    gfx::Point target_position =
        MainFrameImpl()->GetFrameView()->RootFrameToDocument(
            gfx::Point(point_in_root_frame.x(), point_in_root_frame.y()));
    is_animating = StartPageScaleAnimation(target_position, true, scale,
                                           kDoubleTapZoomAnimationDuration);
  } else {
    is_animating = StartPageScaleAnimation(scroll, false, scale,
                                           kDoubleTapZoomAnimationDuration);
  }

  // TODO(dglazkov): The only reason why we're using isAnimating and not just
  // checking for layer_tree_view_->HasPendingPageScaleAnimation() is because of
  // fake page scale animation plumbing for testing, which doesn't actually
  // initiate a page scale animation.
  if (is_animating) {
    double_tap_zoom_page_scale_factor_ = scale;
    double_tap_zoom_pending_ = true;
  }
}

void WebViewImpl::ZoomToFindInPageRect(const gfx::Rect& rect_in_root_frame) {
  DCHECK(MainFrameImpl());

  gfx::Rect block_bounds =
      MainFrameImpl()->FrameWidgetImpl()->ComputeBlockBound(
          gfx::Point(rect_in_root_frame.x() + rect_in_root_frame.width() / 2,
                     rect_in_root_frame.y() + rect_in_root_frame.height() / 2),
          true);

  if (block_bounds.IsEmpty()) {
    // Keep current scale (no need to scroll as x,y will normally already
    // be visible). FIXME: Revisit this if it isn't always true.
    return;
  }

  float scale;
  gfx::Point scroll;

  ComputeScaleAndScrollForBlockRect(rect_in_root_frame.origin(), block_bounds,
                                    nonUserInitiatedPointPadding,
                                    MinimumPageScaleFactor(), scale, scroll);

  StartPageScaleAnimation(scroll, false, scale, kFindInPageAnimationDuration);
}

#if !BUILDFLAG(IS_MAC)
// Mac has no way to open a context menu based on a keyboard event.
WebInputEventResult WebViewImpl::SendContextMenuEvent() {
  // The contextMenuController() holds onto the last context menu that was
  // popped up on the page until a new one is created. We need to clear
  // this menu before propagating the event through the DOM so that we can
  // detect if we create a new menu for this event, since we won't create
  // a new menu if the DOM swallows the event and the defaultEventHandler does
  // not run.
  GetPage()->GetContextMenuController().ClearContextMenu();

  {
    ContextMenuAllowedScope scope;
    Frame* focused_frame = GetPage()->GetFocusController().FocusedOrMainFrame();
    auto* focused_local_frame = DynamicTo<LocalFrame>(focused_frame);
    if (!focused_local_frame)
      return WebInputEventResult::kNotHandled;
    // Firefox reveal focus based on "keydown" event but not "contextmenu"
    // event, we match FF.
    if (Element* focused_element =
            focused_local_frame->GetDocument()->FocusedElement())
      focused_element->scrollIntoViewIfNeeded();
    return focused_local_frame->GetEventHandler().ShowNonLocatedContextMenu(
        nullptr, kMenuSourceKeyboard);
  }
}
#else
WebInputEventResult WebViewImpl::SendContextMenuEvent() {
  return WebInputEventResult::kNotHandled;
}
#endif

WebPagePopupImpl* WebViewImpl::OpenPagePopup(PagePopupClient* client) {
  DCHECK(client);

  // This guarantees there is never more than 1 PagePopup active at a time.
  CancelPagePopup();
  DCHECK(!page_popup_);

  LocalFrame* opener_frame = client->OwnerElement().GetDocument().GetFrame();
  WebLocalFrameImpl* web_opener_frame =
      WebLocalFrameImpl::FromFrame(opener_frame);

  mojo::PendingAssociatedRemote<mojom::blink::Widget> widget;
  mojo::PendingAssociatedReceiver<mojom::blink::Widget> widget_receiver =
      widget.InitWithNewEndpointAndPassReceiver();

  mojo::PendingAssociatedRemote<mojom::blink::WidgetHost> widget_host;
  mojo::PendingAssociatedReceiver<mojom::blink::WidgetHost>
      widget_host_receiver = widget_host.InitWithNewEndpointAndPassReceiver();

  mojo::PendingAssociatedRemote<mojom::blink::PopupWidgetHost>
      popup_widget_host;
  mojo::PendingAssociatedReceiver<mojom::blink::PopupWidgetHost>
      popup_widget_host_receiver =
          popup_widget_host.InitWithNewEndpointAndPassReceiver();

  opener_frame->GetLocalFrameHostRemote().CreateNewPopupWidget(
      std::move(popup_widget_host_receiver), std::move(widget_host_receiver),
      std::move(widget));
  WebFrameWidgetImpl* opener_widget = web_opener_frame->LocalRootFrameWidget();

  AgentGroupScheduler& agent_group_scheduler =
      opener_frame->GetPage()->GetPageScheduler()->GetAgentGroupScheduler();
  // The returned WebPagePopup is self-referencing, so the pointer here is not
  // an owning pointer. It is de-referenced by the PopupWidgetHost disconnecting
  // and calling Close().
  page_popup_ = WebPagePopupImpl::Create(
      std::move(popup_widget_host), std::move(widget_host),
      std::move(widget_receiver), this, agent_group_scheduler,
      opener_widget->GetOriginalScreenInfos(), client);
  EnablePopupMouseWheelEventListener(web_opener_frame->LocalRoot());
  return page_popup_.get();
}

void WebViewImpl::CancelPagePopup() {
  if (page_popup_)
    page_popup_->Cancel();
}

void WebViewImpl::ClosePagePopup(PagePopup* popup) {
  DCHECK(popup);
  auto* popup_impl = To<WebPagePopupImpl>(popup);
  DCHECK_EQ(page_popup_.get(), popup_impl);
  if (page_popup_.get() != popup_impl)
    return;
  page_popup_->ClosePopup();
}

void WebViewImpl::CleanupPagePopup() {
  page_popup_ = nullptr;
  DisablePopupMouseWheelEventListener();
}

void WebViewImpl::UpdatePagePopup() {
  if (page_popup_)
    page_popup_->Update();
}

void WebViewImpl::EnablePopupMouseWheelEventListener(
    WebLocalFrameImpl* local_root) {
  DCHECK(!popup_mouse_wheel_event_listener_);
  Document* document = local_root->GetDocument();
  DCHECK(document);
  // We register an empty event listener, EmptyEventListener, so that mouse
  // wheel events get sent to the WebView.
  popup_mouse_wheel_event_listener_ =
      MakeGarbageCollected<EmptyEventListener>();
  document->addEventListener(event_type_names::kMousewheel,
                             popup_mouse_wheel_event_listener_, false);
  local_root_with_empty_mouse_wheel_listener_ = local_root;
}

void WebViewImpl::DisablePopupMouseWheelEventListener() {
  // TODO(kenrb): Concerns the same as in enablePopupMouseWheelEventListener.
  // See https://crbug.com/566130
  DCHECK(popup_mouse_wheel_event_listener_);
  Document* document =
      local_root_with_empty_mouse_wheel_listener_->GetDocument();
  DCHECK(document);
  // Document may have already removed the event listener, for instance, due
  // to a navigation, but remove it anyway.
  document->removeEventListener(event_type_names::kMousewheel,
                                popup_mouse_wheel_event_listener_.Release(),
                                false);
  local_root_with_empty_mouse_wheel_listener_ = nullptr;
}

LocalDOMWindow* WebViewImpl::PagePopupWindow() const {
  return page_popup_ ? page_popup_->Window() : nullptr;
}

Frame* WebViewImpl::FocusedCoreFrame() const {
  Page* page = page_.Get();
  return page ? page->GetFocusController().FocusedOrMainFrame() : nullptr;
}

// WebWidget ------------------------------------------------------------------

void WebViewImpl::Close() {
#if !(BUILDFLAG(IS_ANDROID) || \
      (BUILDFLAG(IS_CHROMEOS) && defined(ARCH_CPU_ARM64)))
  auto close_task_trace = close_task_posted_stack_trace_;
  base::debug::Alias(&close_task_trace);
  auto prev_close_trace = close_called_stack_trace_;
  base::debug::Alias(&prev_close_trace);
  close_called_stack_trace_.emplace();
  auto cur_close_trace = close_called_stack_trace_;
  base::debug::Alias(&cur_close_trace);
  auto close_window_trace = close_window_called_stack_trace_;
  base::debug::Alias(&close_window_trace);
#endif
  SCOPED_CRASH_KEY_BOOL("Bug1499519", "page_exists", !!page_);

  // Closership is a single relationship, so only 1 call to Close() should
  // occur.
  CHECK(page_);
  DCHECK(AllInstances().Contains(this));
  AllInstances().erase(this);

  // Ensure if we have a page popup we cancel it immediately as we do not
  // want page popups to re-enter WebViewImpl during our shutdown.
  CancelPagePopup();

  receiver_.reset();

  dev_tools_emulator_->Shutdown();

  // Initiate shutdown for the entire frameset.  This will cause a lot of
  // notifications to be sent. This will detach all frames in this WebView's
  // frame tree.
  page_->WillBeDestroyed();
  page_.Clear();

  if (web_view_client_)
    web_view_client_->OnDestruct();

  // Reset the delegate to prevent notifications being sent as we're being
  // deleted.
  web_view_client_ = nullptr;

  for (auto& observer : observers_)
    observer.WebViewDestroyed();

  delete this;
}

gfx::Size WebViewImpl::Size() {
  return size_;
}

void WebViewImpl::ResizeVisualViewport(const gfx::Size& new_size) {
  GetPage()->GetVisualViewport().SetSize(new_size);
  GetPage()->GetVisualViewport().ClampToBoundaries();
}

void WebViewImpl::DidFirstVisuallyNonEmptyPaint() {
  DCHECK(MainFrameImpl());
  local_main_frame_host_remote_->DidFirstVisuallyNonEmptyPaint();
}

void WebViewImpl::OnFirstContentfulPaint() {
  local_main_frame_host_remote_->OnFirstContentfulPaint();
}

void WebViewImpl::UpdateICBAndResizeViewport(
    const gfx::Size& visible_viewport_size) {
  // We'll keep the initial containing block size from changing when the top
  // controls hide so that the ICB will always be the same size as the
  // viewport with the browser controls shown.
  gfx::Size icb_size = size_;
  if (GetBrowserControls().PermittedState() ==
          cc::BrowserControlsState::kBoth &&
      !GetBrowserControls().ShrinkViewport()) {
    icb_size.Enlarge(0, -(GetBrowserControls().TotalHeight() -
                          GetBrowserControls().TotalMinHeight()));
  }

  GetPageScaleConstraintsSet().DidChangeInitialContainingBlockSize(icb_size);

  UpdatePageDefinedViewportConstraints(MainFrameImpl()
                                           ->GetFrame()
                                           ->GetDocument()
                                           ->GetViewportData()
                                           .GetViewportDescription());
  UpdateMainFrameLayoutSize();

  GetPage()->GetVisualViewport().SetSize(visible_viewport_size);

  if (MainFrameImpl()->GetFrameView()) {
    if (!MainFrameImpl()->GetFrameView()->NeedsLayout())
      resize_viewport_anchor_->ResizeFrameView(MainFrameSize());
  }

  // The boundaries are not properly established until after the frame view is
  // also resized, as demonstrated by
  // VisualViewportTest.TestBrowserControlsAdjustmentAndResize.
  GetPage()->GetVisualViewport().ClampToBoundaries();
}

void WebViewImpl::UpdateBrowserControlsConstraint(
    cc::BrowserControlsState constraint) {
  cc::BrowserControlsState old_permitted_state =
      GetBrowserControls().PermittedState();

  GetBrowserControls().UpdateConstraintsAndState(
      constraint, cc::BrowserControlsState::kBoth);

  // If the controls are going from a locked hidden to unlocked state, or vice
  // versa, the ICB size needs to change but we can't rely on getting a
  // WebViewImpl::resize since the top controls shown state may not have
  // changed.
  if ((old_permitted_state == cc::BrowserControlsState::kHidden &&
       constraint == cc::BrowserControlsState::kBoth) ||
      (old_permitted_state == cc::BrowserControlsState::kBoth &&
       constraint == cc::BrowserControlsState::kHidden)) {
    UpdateICBAndResizeViewport(GetPage()->GetVisualViewport().Size());
  }
}

void WebViewImpl::DidUpdateBrowserControls() {
  // BrowserControls are a feature whereby the browser can introduce an
  // interactable element [e.g. search box] that grows/shrinks in height as the
  // user scrolls the web contents.
  //
  // This method is called by the BrowserControls class to let the compositor
  // know that the browser controls have been updated. This is only relevant if
  // the main frame is local because BrowserControls only affects the main
  // frame's viewport, and are only affected by main frame scrolling.
  //
  // The relevant state is stored on the BrowserControls object even if the main
  // frame is remote. If the main frame becomes local, the state will be
  // restored by the first commit, since the state is checked in every call to
  // ApplyScrollAndScale().
  WebLocalFrameImpl* main_frame = MainFrameImpl();
  if (!main_frame || !main_frame->IsOutermostMainFrame())
    return;

  WebFrameWidgetImpl* widget = main_frame->LocalRootFrameWidget();
  widget->SetBrowserControlsShownRatio(GetBrowserControls().TopShownRatio(),
                                       GetBrowserControls().BottomShownRatio());
  widget->SetBrowserControlsParams(GetBrowserControls().Params());

  VisualViewport& visual_viewport = GetPage()->GetVisualViewport();
  DCHECK(visual_viewport.IsActiveViewport());

  {
    // This object will save the current visual viewport offset w.r.t. the
    // document and restore it when the object goes out of scope. It's
    // needed since the browser controls adjustment will change the maximum
    // scroll offset and we may need to reposition them to keep the user's
    // apparent position unchanged.
    ResizeViewportAnchor::ResizeScope resize_scope(*resize_viewport_anchor_);

    visual_viewport.SetBrowserControlsAdjustment(
        GetBrowserControls().UnreportedSizeAdjustment());
  }

  if (GetPage()->GetSettings().GetDynamicSafeAreaInsetsEnabled() &&
      RuntimeEnabledFeatures::DynamicSafeAreaInsetsOnScrollEnabled()) {
    GetPage()->UpdateSafeAreaInsetWithBrowserControls(GetBrowserControls());
  }
}

BrowserControls& WebViewImpl::GetBrowserControls() {
  return GetPage()->GetBrowserControls();
}

void WebViewImpl::ResizeViewWhileAnchored(
    cc::BrowserControlsParams params,
    const gfx::Size& visible_viewport_size) {
  DCHECK(MainFrameImpl());

  bool old_viewport_shrink = GetBrowserControls().ShrinkViewport();

  GetBrowserControls().SetParams(params);

  if (old_viewport_shrink != GetBrowserControls().ShrinkViewport())
    MainFrameImpl()->GetFrameView()->DynamicViewportUnitsChanged();

  if (GetPage()->GetSettings().GetDynamicSafeAreaInsetsEnabled()) {
    GetPage()->UpdateSafeAreaInsetWithBrowserControls(GetBrowserControls(),
                                                      /* force_update= */ true);
  }

  {
    // Avoids unnecessary invalidations while various bits of state in
    // TextAutosizer are updated.
    TextAutosizer::DeferUpdatePageInfo defer_update_page_info(GetPage());
    LocalFrameView* frame_view = MainFrameImpl()->GetFrameView();
    gfx::Size old_size = frame_view->Size();
    UpdateICBAndResizeViewport(visible_viewport_size);
    if (old_size != frame_view->Size()) {
      frame_view->InvalidateLayoutForViewportConstrainedObjects();
    }
  }

  fullscreen_controller_->UpdateSize();

  if (!scoped_defer_main_frame_update_) {
    // Page scale constraints may need to be updated; running layout now will
    // do that.
    MainFrameWidget()->UpdateLifecycle(WebLifecycleUpdate::kLayout,
                                       DocumentUpdateReason::kSizeChange);
  }
}

void WebViewImpl::ResizeWithBrowserControls(
    const gfx::Size& new_size,
    float top_controls_height,
    float bottom_controls_height,
    bool browser_controls_shrink_layout) {
  ResizeWithBrowserControls(
      new_size, new_size,
      {top_controls_height, GetBrowserControls().TopMinHeight(),
       bottom_controls_height, GetBrowserControls().BottomMinHeight(),
       GetBrowserControls().AnimateHeightChanges(),
       browser_controls_shrink_layout});
}

void WebViewImpl::ResizeWithBrowserControls(
    const gfx::Size& main_frame_widget_size,
    const gfx::Size& visible_viewport_size,
    cc::BrowserControlsParams browser_controls_params) {
  if (should_auto_resize_) {
    // When auto-resizing only the viewport size comes from the browser, while
    // the widget size is determined in the renderer.
    ResizeVisualViewport(visible_viewport_size);
    return;
  }

  if (size_ == main_frame_widget_size &&
      GetPage()->GetVisualViewport().Size() == visible_viewport_size &&
      GetBrowserControls().Params() == browser_controls_params)
    return;

  if (GetPage()->MainFrame() && !GetPage()->MainFrame()->IsLocalFrame()) {
    // Viewport resize for a remote main frame does not require any
    // particular action, but the state needs to reflect the correct size
    // so that it can be used for initialization if the main frame gets
    // swapped to a LocalFrame at a later time.
    size_ = main_frame_widget_size;
    GetPageScaleConstraintsSet().DidChangeInitialContainingBlockSize(size_);
    GetPage()->GetVisualViewport().SetSize(size_);
    GetPage()->GetBrowserControls().SetParams(browser_controls_params);
    return;
  }

  WebLocalFrameImpl* main_frame = MainFrameImpl();
  if (!main_frame)
    return;

  LocalFrameView* view = main_frame->GetFrameView();
  if (!view)
    return;

  VisualViewport& visual_viewport = GetPage()->GetVisualViewport();

  bool is_rotation =
      GetPage()->GetSettings().GetMainFrameResizesAreOrientationChanges() &&
      size_.width() && ContentsSize().width() &&
      main_frame_widget_size.width() != size_.width() &&
      !fullscreen_controller_->IsFullscreenOrTransitioning();
  size_ = main_frame_widget_size;

  if (!main_frame->IsOutermostMainFrame()) {
    // Anchoring should not be performed from embedded frames as anchoring
    // should only be performed when the size/orientation is user controlled.
    ResizeViewWhileAnchored(browser_controls_params, visible_viewport_size);
  } else if (is_rotation) {
    gfx::PointF viewport_anchor_coords(viewportAnchorCoordX,
                                       viewportAnchorCoordY);
    RotationViewportAnchor anchor(*view, visual_viewport,
                                  viewport_anchor_coords,
                                  GetPageScaleConstraintsSet());
    ResizeViewWhileAnchored(browser_controls_params, visible_viewport_size);
  } else {
    DCHECK(visual_viewport.IsActiveViewport());
    ResizeViewportAnchor::ResizeScope resize_scope(*resize_viewport_anchor_);
    ResizeViewWhileAnchored(browser_controls_params, visible_viewport_size);
  }

  // TODO(bokan): This will send a resize event even if the innerHeight on the
  // page didn't change (e.g. virtual keyboard causes resize of only visual
  // viewport). Lets remove this and have the frame send this event when its
  // frame rect is resized (as noted by the ancient FIXME inside this method).
  // https://crbug.com/1353728.
  SendResizeEventForMainFrame();
}

void WebViewImpl::Resize(const gfx::Size& new_size) {
  if (should_auto_resize_ || size_ == new_size)
    return;

  ResizeWithBrowserControls(new_size, GetBrowserControls().TopHeight(),
                            GetBrowserControls().BottomHeight(),
                            GetBrowserControls().ShrinkViewport());
}

void WebViewImpl::SetScreenOrientationOverrideForTesting(
    std::optional<display::mojom::blink::ScreenOrientation> orientation) {
  screen_orientation_override_ = orientation;

  // Since we updated the override value, notify all widgets.
  for (WebFrame* frame = MainFrame(); frame; frame = frame->TraverseNext()) {
    if (frame->IsWebLocalFrame()) {
      if (WebFrameWidgetImpl* widget = static_cast<WebFrameWidgetImpl*>(
              frame->ToWebLocalFrame()->FrameWidget())) {
        widget->UpdateScreenInfo(widget->GetScreenInfos());
      }
    }
  }
}

void WebViewImpl::SetWindowRectSynchronouslyForTesting(
    const gfx::Rect& new_window_rect) {
  // We need to call UpdateScreenRects to ensure the 'move' event is enqueued.
  // TODO(jfernandez): Ideally updating the window rect should do that
  // automatically.
  web_widget_->UpdateScreenRects(new_window_rect, new_window_rect);
  web_widget_->SetWindowRectSynchronouslyForTesting(new_window_rect);
}

std::optional<display::mojom::blink::ScreenOrientation>
WebViewImpl::ScreenOrientationOverride() {
  return screen_orientation_override_;
}

void WebViewImpl::DidEnterFullscreen() {
  fullscreen_controller_->DidEnterFullscreen();
}

void WebViewImpl::DidExitFullscreen() {
  fullscreen_controller_->DidExitFullscreen();
}

void WebViewImpl::SetMainFrameViewWidget(WebFrameWidgetImpl* widget) {
  DCHECK(!widget || widget->ForMainFrame());
  web_widget_ = widget;
}

void WebViewImpl::SetMouseOverURL(const KURL& url) {
  mouse_over_url_ = url;
  UpdateTargetURL(mouse_over_url_, focus_url_);
}

void WebViewImpl::SetKeyboardFocusURL(const KURL& url) {
  focus_url_ = url;
  UpdateTargetURL(focus_url_, mouse_over_url_);
}

WebFrameWidgetImpl* WebViewImpl::MainFrameViewWidget() {
  return web_widget_;
}

void WebViewImpl::PaintContent(cc::PaintCanvas* canvas, const gfx::Rect& rect) {
  // This should only be used when compositing is not being used for this
  // WebView, and it is painting into the recording of its parent.
  DCHECK(!does_composite_);
  // Non-composited WebViews always have a local main frame.
  DCHECK(MainFrameImpl());

  if (rect.IsEmpty())
    return;

  LocalFrameView& main_view = *MainFrameImpl()->GetFrame()->View();
  // TODO(crbug.com/1442088): Investigate the reason.
  if (!main_view.GetLayoutView()
           ->FirstFragment()
           .HasLocalBorderBoxProperties()) {
    return;
  }
  DCHECK_EQ(main_view.GetLayoutView()->GetDocument().Lifecycle().GetState(),
            DocumentLifecycle::kPaintClean);

  PaintRecordBuilder builder;
  main_view.PaintOutsideOfLifecycleWithThrottlingAllowed(
      builder.Context(), PaintFlag::kNoFlag, CullRect(rect));
  // Don't bother to save/restore here as the caller is expecting the canvas
  // to be modified and take care of it.
  canvas->clipRect(gfx::RectToSkRect(rect));
  builder.EndRecording(*canvas, main_view.GetLayoutView()
                                    ->FirstFragment()
                                    .LocalBorderBoxProperties()
                                    .Unalias());
}

// static
void WebView::ApplyWebPreferences(const web_pref::WebPreferences& prefs,
                                  WebView* web_view) {
  WebViewImpl* web_view_impl = To<WebViewImpl>(web_view);
  WebSettings* settings = web_view->GetSettings();
  ApplyFontsFromMap(prefs.standard_font_family_map,
                    SetStandardFontFamilyWrapper, settings);
  ApplyFontsFromMap(prefs.fixed_font_family_map, SetFixedFontFamilyWrapper,
                    settings);
  ApplyFontsFromMap(prefs.serif_font_family_map, SetSerifFontFamilyWrapper,
                    settings);
  ApplyFontsFromMap(prefs.sans_serif_font_family_map,
                    SetSansSerifFontFamilyWrapper, settings);
  ApplyFontsFromMap(prefs.cursive_font_family_map, SetCursiveFontFamilyWrapper,
                    settings);
  ApplyFontsFromMap(prefs.fantasy_font_family_map, SetFantasyFontFamilyWrapper,
                    settings);
  ApplyFontsFromMap(prefs.math_font_family_map, SetMathFontFamilyWrapper,
                    settings);
  settings->SetDefaultFontSize(prefs.default_font_size);
  settings->SetDefaultFixedFontSize(prefs.default_fixed_font_size);
  settings->SetMinimumFontSize(prefs.minimum_font_size);
  settings->SetMinimumLogicalFont
```