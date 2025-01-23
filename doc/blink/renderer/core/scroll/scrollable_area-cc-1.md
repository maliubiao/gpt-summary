Response:
The user is asking for a summary of the functionality of the provided C++ code snippet from the `scrollable_area.cc` file in the Chromium Blink engine. This is the second part of a two-part request, indicating that the previous part contained the initial section of the file. I need to analyze the code, identify the main features and responsibilities of the `ScrollableArea` class based on this snippet, and relate them to web technologies (JavaScript, HTML, CSS) where applicable. I also need to consider potential user errors and how they might lead to this code being executed, as well as provide debugging insights.

Here's a breakdown of the code's functionalities:

1. **Scrollbar Management:**  This section deals with managing the visibility, painting, and animation of scrollbars (both native and overlay).
2. **Overlay Scrollbar Customization:**  The code handles setting and recalculating the color scheme of overlay scrollbars based on the background color.
3. **Compositor Integration:**  It interacts with the compositor to manage scrollbar layers and trigger repaints on the compositor thread.
4. **Scroll Animation:** The code manages both programmatic and user-initiated scroll animations.
5. **Overlay Scrollbar Fading:**  It implements the logic for fading out overlay scrollbars after a period of inactivity.
6. **Scroll Snapping:**  The code includes logic for snapping to scroll targets after scrolling, both initiated by the user and programmatically.
7. **Event Handling:** It enqueues scroll-related events like `scrollend`, `scrollsnapchange`, and `scrollsnapchanging`.
8. **Coordinate Conversion:** It provides methods for converting between local and visible content coordinates.
9. **Scroll Offset Manipulation:**  It clamps and sets scroll offsets, taking into account minimum and maximum values.
10. **Step Calculation:** It calculates step sizes for scrolling by line, page, and document.
11. **Integration with Chromium Infrastructure:** It uses `ChromeClient` and interacts with the compositor task runner.

Now I need to connect these functionalities to web technologies, user errors, and debugging scenarios.根据您提供的代码片段，`ScrollableArea` 类的主要功能集中在以下几个方面：

**1. 滚动条管理 (Scrollbar Management):**

* **控制滚动条的移除和更新:** `WillRemoveScrollbar` 方法在滚动条被移除前执行特定的动画逻辑（针对 Mac 平台）。`ContentsResized` 方法通知滚动条内容大小已改变，以便更新滚动条的状态。
* **判断是否使用 Overlay 滚动条:** `HasOverlayScrollbars` 方法检查是否同时存在垂直和水平的 Overlay 滚动条。
* **设置 Overlay 滚动条的颜色方案:** `SetOverlayScrollbarColorScheme` 方法允许设置 Overlay 滚动条的主题颜色。这与 CSS 的 `scrollbar-color` 属性有一定的关联，尽管这里的实现更底层。
* **自动计算 Overlay 滚动条的颜色方案:** `RecalculateOverlayScrollbarColorScheme` 方法会根据元素的背景色动态调整 Overlay 滚动条的主题，以保证对比度。

   **与 CSS 的关系举例:**  如果一个 HTML 元素的 CSS 设置了 `background-color: black;`， 那么 `RecalculateOverlayScrollbarColorScheme` 方法可能会将 Overlay 滚动条的主题设置为 "light"，以便在黑色背景上清晰可见。

* **标记滚动条需要重绘:** `SetScrollbarNeedsPaintInvalidation` 方法通知系统需要重新绘制滚动条。它还会尝试直接更新 Compositor 层的滚动条外观（如果滚动条已合成）。

   **与 CSS 的关系举例:** 当 CSS 的 `:hover` 状态改变了滚动条的颜色时，或者当滚动条的 `visibility` 属性发生变化时，可能会调用此方法来触发滚动条的重绘。

* **标记滚动角需要重绘:** `SetScrollCornerNeedsPaintInvalidation` 方法通知系统需要重新绘制滚动角的区域。

* **标记滚动控件需要完全重绘:** `SetScrollControlsNeedFullPaintInvalidation` 方法会强制水平和垂直滚动条以及滚动角进行完全重绘。

* **判断滚动条 Layer 是否存在:** `HasLayerForHorizontalScrollbar`, `HasLayerForVerticalScrollbar`, `HasLayerForScrollCorner` 方法用于判断滚动条和滚动角是否已经创建了独立的 Compositor Layer。这与浏览器的渲染优化有关，可以实现滚动条的独立合成和动画。

**2. 滚动动画管理 (Scroll Animation Management):**

* **驱动滚动动画:** `ServiceScrollAnimations` 方法会在每一帧被调用，用于更新和驱动各种类型的滚动动画，包括平滑滚动和程序化滚动。
* **更新 Compositor 滚动动画:** `UpdateCompositorScrollAnimations` 方法将当前的滚动动画状态同步到 Compositor 层。
* **取消滚动动画:** `CancelScrollAnimation` 和 `CancelProgrammaticScrollAnimation` 方法分别用于取消用户发起的平滑滚动动画和程序控制的滚动动画。

   **与 JavaScript 的关系举例:**  JavaScript 可以使用 `scrollTo()` 或 `scrollBy()` 方法触发平滑滚动。`CancelProgrammaticScrollAnimation` 可以用于停止这些 JavaScript 发起的滚动动画。

**3. Overlay 滚动条的显示和隐藏 (Overlay Scrollbar Visibility):**

* **判断 Overlay 滚动条是否在指定条件下隐藏:** `ScrollbarsHiddenIfOverlay` 方法返回是否因为是 Overlay 滚动条并且设置了隐藏而导致滚动条不可见。
* **设置 Overlay 滚动条的隐藏状态 (用于测试):** `SetScrollbarsHiddenForTesting` 方法允许在测试中强制设置 Overlay 滚动条的隐藏状态。
* **从外部动画设置 Overlay 滚动条的隐藏状态:** `SetScrollbarsHiddenFromExternalAnimator` 方法用于处理来自外部动画的 Overlay 滚动条隐藏请求。
* **设置 Overlay 滚动条的隐藏状态:** `SetScrollbarsHiddenIfOverlay` 方法根据配置设置 Overlay 滚动条的隐藏状态。
* **内部设置 Overlay 滚动条的隐藏状态:** `SetScrollbarsHiddenIfOverlayInternal` 方法是实际执行 Overlay 滚动条隐藏/显示逻辑的内部方法。
* **Overlay 滚动条淡出定时器:** `FadeOverlayScrollbarsTimerFired` 方法是定时器回调，用于在一段时间不活动后隐藏 Overlay 滚动条。
* **显示非 Mac 平台的 Overlay 滚动条:** `ShowNonMacOverlayScrollbars` 方法负责在非 Mac 平台上显示 Overlay 滚动条，并启动一个定时器用于后续的自动隐藏。

   **与 JavaScript 的关系举例:**  JavaScript 事件监听器 (例如 `mouseover` 或 `touchstart`) 可以触发 `ShowNonMacOverlayScrollbars` 方法来显示 Overlay 滚动条。

**4. 事件目标节点获取 (Event Target Node):**

* **获取事件目标节点:** `EventTargetNode` 方法尝试找到与当前 `ScrollableArea` 关联的 DOM 节点，通常用于事件分发。

   **与 HTML 的关系举例:**  当用户在一个可滚动的 `<div>` 元素上滚动鼠标滚轮时，`EventTargetNode` 方法会返回这个 `<div>` 元素对应的节点。

**5. 文档对象获取 (Document Object):**

* **获取关联的文档对象:** `GetDocument` 方法返回与当前 `ScrollableArea` 关联的 `Document` 对象。

**6. 滚动偏移量限制 (Scroll Offset Clamping):**

* **限制滚动偏移量 (浮点数和整数):** `ClampScrollOffset` 方法确保滚动偏移量不会超出允许的最小值和最大值。

**7. 滚动步长计算 (Scroll Step Calculation):**

* **计算行步长、页步长、文档步长和像素步长:** `LineStep`, `PageStep`, `DocumentStep`, `PixelStep` 方法用于计算不同粒度的滚动步长，用于响应用户的滚动操作。

   **与用户操作的关系:** 当用户点击滚动条的箭头按钮（行步长）、点击滚动条的空白区域（页步长）或者拖动滚动条滑块（文档步长）时，这些方法会被调用以确定滚动的距离。

**8. 滚动条宽度和高度获取 (Scrollbar Width and Height):**

* **获取垂直和水平滚动条的宽度和高度:** `VerticalScrollbarWidth` 和 `HorizontalScrollbarHeight` 方法返回滚动条的尺寸，会考虑 Overlay 滚动条的情况。

**9. 坐标转换 (Coordinate Conversion):**

* **本地坐标到可视内容坐标的转换:** `LocalToVisibleContentQuad` 方法将本地坐标系下的四边形转换为可视内容坐标系下的四边形，用于计算元素在滚动后的位置。

**10. 排除滚动条的尺寸计算 (Excluding Scrollbars from Size):**

* **从尺寸中排除滚动条:** `ExcludeScrollbars` 方法从给定的尺寸中减去滚动条的尺寸，常用于布局计算。

**11. Compositor 滚动完成处理 (Compositor Scroll Completion):**

* **处理 Compositor 滚动完成事件:** `DidCompositorScroll` 方法在 Compositor 层完成滚动后被调用，用于更新 Blink 层的滚动状态。

**12. 获取滚动条对象 (Get Scrollbar Object):**

* **根据方向获取滚动条对象:** `GetScrollbar` 方法根据水平或垂直方向返回对应的滚动条对象。

**13. 获取滚动条的 Compositor Element ID:**

* **获取滚动条的 Compositor 元素 ID:** `GetScrollbarElementId` 方法用于获取 Compositor 层的滚动条元素的唯一标识符。

**14. 滚动结束处理 (Scroll Finished Handling):**

* **处理滚动完成事件:** `OnScrollFinished` 方法在滚动动画结束后被调用，用于执行一些清理工作，例如重置平滑滚动类型、更新滚动捕捉状态和触发 `scrollend` 事件。

   **与 JavaScript 的关系举例:**  `OnScrollFinished` 方法的执行可能导致 JavaScript 中监听的 `scrollend` 事件被触发。

**15. 滚动捕捉 (Scroll Snapping):**

* **滚动条滚动后的捕捉:** `SnapAfterScrollbarScrolling` 方法在用户通过滚动条进行滚动后触发滚动捕捉。
* **捕捉到当前位置:** `SnapAtCurrentPosition` 方法将当前滚动位置捕捉到最近的捕捉点。
* **捕捉到指定结束位置:** `SnapForEndPosition` 方法将滚动位置捕捉到指定的结束位置。
* **根据滚动方向进行捕捉:** `SnapForDirection` 方法根据滚动的方向进行捕捉。
* **根据结束位置和方向进行捕捉:** `SnapForEndAndDirection` 方法根据结束位置和滚动方向进行捕捉。
* **布局后的捕捉:** `SnapAfterLayout` 方法在布局完成后执行滚动捕捉。
* **执行滚动捕捉:** `PerformSnapping` 方法是实际执行滚动捕捉逻辑的核心方法。

   **与 CSS 和 JavaScript 的关系举例:**  这些方法与 CSS 的 `scroll-snap-type`, `scroll-snap-align`, `scroll-padding` 等属性以及 JavaScript 中用于控制滚动捕捉的行为有关。

**16. 滚动条手势滚动注入 (Inject Scrollbar Gesture Scroll):**

* **注入滚动条手势滚动事件:** `InjectScrollbarGestureScroll` 方法用于模拟滚动条的手势滚动事件，通常用于测试或特定的交互场景。

   **与用户操作的关系:** 虽然是注入，但它模拟的是用户通过触摸或者鼠标拖动滚动条进行滚动的操作。

**17. 获取用于滚动的 ScrollableArea (Get ScrollableArea for Scrolling):**

* **获取用于滚动的 ScrollableArea:** `GetForScrolling` 方法根据给定的 `LayoutBox` 获取负责滚动的 `ScrollableArea` 对象。

**18. DPI 缩放比例获取 (Scale from DIP):**

* **获取设备独立像素到物理像素的缩放比例:** `ScaleFromDIP` 方法用于获取屏幕的 DPI 缩放比例。

**19. 判断滚动偏移量是否为 No-op (Scroll Offset Is Noop):**

* **判断给定的滚动偏移量是否与当前偏移量相同:** `ScrollOffsetIsNoop` 方法用于判断设置新的滚动偏移量是否会实际改变滚动位置。

**20. 触发滚动捕捉事件 (Enqueue Scroll Snap Events):**

* **触发 `scrollsnapchange` 事件:** `EnqueueScrollSnapChangeEvent` 方法用于在滚动捕捉状态改变时触发 `scrollsnapchange` 事件。
* **触发 `scrollsnapchanging` 事件:** `EnqueueScrollSnapChangingEvent` 方法用于在滚动捕捉状态即将改变时触发 `scrollsnapchanging` 事件。

   **与 JavaScript 的关系举例:**  JavaScript 可以监听这些事件来响应滚动捕捉状态的变化。

**21. 获取 Web 可见的滚动偏移量 (Get Web Exposed Scroll Offset):**

* **获取 Web API 可以访问的滚动偏移量:** `GetWebExposedScrollOffset` 方法返回经过处理的滚动偏移量，该偏移量会转换为物理像素，并确保在禁用浮点滚动偏移的情况下是整数值。

**用户操作如何一步步的到达这里 (调试线索):**

假设用户在一个网页上进行以下操作，可能会逐步触发 `scrollable_area.cc` 中的代码：

1. **页面加载和渲染:**  当浏览器加载 HTML、解析 CSS 并创建渲染树时，如果页面内容超出视口，`ScrollableArea` 对象会被创建并与可滚动的元素关联。
2. **鼠标滚轮滚动:** 用户使用鼠标滚轮向上或向下滚动页面。这会触发浏览器的底层滚动事件，最终传递到 Blink 引擎，`ScrollableArea` 中的方法会被调用来更新滚动位置。如果启用了平滑滚动，`ServiceScrollAnimations` 和 `UpdateCompositorScrollAnimations` 会被调用。
3. **拖动滚动条滑块:** 用户点击并拖动滚动条的滑块。这会直接操作滚动条，`SetScrollOffset` 方法会被调用来设置新的滚动偏移量。滚动完成后，`OnScrollFinished` 和可能的滚动捕捉相关方法会被执行。
4. **点击滚动条箭头或空白区域:** 用户点击滚动条的箭头按钮（触发 `LineStep` 计算）或空白区域（触发 `PageStep` 计算），导致页面滚动。
5. **使用触摸手势滚动:** 在触摸设备上，用户滑动屏幕进行滚动，这也会触发 `ScrollableArea` 中的滚动处理逻辑。
6. **JavaScript 控制滚动:** 网页上的 JavaScript 代码使用 `window.scrollTo()` 或元素的 `scrollIntoView()` 方法来滚动页面。这会调用 `ScrollableArea` 中的 `SetScrollOffset` 方法，并可能触发滚动动画。
7. **元素尺寸改变:** 当页面元素的尺寸发生变化，导致可滚动区域大小改变时，`ContentsResized` 方法会被调用，以更新滚动条的状态。
8. **悬停在可滚动元素上 (Overlay 滚动条):** 如果启用了 Overlay 滚动条，当鼠标悬停在可滚动元素上时，`ShowNonMacOverlayScrollbars` 方法可能会被调用来显示滚动条。一段时间不活动后，`FadeOverlayScrollbarsTimerFired` 会被调用来隐藏滚动条。
9. **CSS 样式更新:** 当 CSS 样式发生变化，例如改变了元素的 `background-color`，`RecalculateOverlayScrollbarColorScheme` 可能会被调用来调整 Overlay 滚动条的颜色方案。
10. **滚动捕捉交互:** 用户滚动到一个设置了 `scroll-snap-type` 的容器时，滚动停止后，`SnapAfterScrollbarScrolling` 或 `SnapAtCurrentPosition` 等方法会被调用来执行滚动捕捉。

**常见的用户或编程错误举例:**

1. **错误的滚动边界判断:** 开发者在 JavaScript 中手动控制滚动时，如果没有正确判断滚动边界（最小值和最大值），可能导致设置的滚动偏移量超出范围，最终 `ClampScrollOffset` 方法会进行修正。
   * **假设输入:** JavaScript 代码尝试将滚动偏移量设置为超出最大值的值，例如 `element.scrollTo(0, 10000)`，而实际最大滚动高度只有 5000px。
   * **输出:** `ClampScrollOffset` 方法会将偏移量修正为 5000px。

2. **频繁的滚动操作导致性能问题:**  如果在 JavaScript 中编写了频繁触发滚动操作的代码，可能会导致 `ServiceScrollAnimations` 和相关方法被频繁调用，消耗大量计算资源，影响页面性能。

3. **Overlay 滚动条显示/隐藏逻辑错误:**  开发者可能错误地控制了 Overlay 滚动条的显示和隐藏，导致滚动条出现异常的显示状态。

4. **滚动捕捉配置错误:**  CSS 的滚动捕捉属性配置不当，例如缺少必要的父容器设置或捕捉点定义不清晰，可能导致滚动捕捉行为不符合预期，而 `PerformSnapping` 方法的逻辑可能因此无法正确执行。

**总结 `ScrollableArea` 的功能:**

`ScrollableArea` 类是 Chromium Blink 引擎中负责管理可滚动区域的核心组件。它封装了滚动条的创建、更新、绘制和动画逻辑，处理用户和程序触发的滚动操作，并集成了滚动捕捉功能。它还负责处理 Overlay 滚动条的显示和隐藏，并与 Compositor 层进行交互以实现高效的渲染和动画。该类在 Web 浏览器的滚动功能中扮演着至关重要的角色，确保用户能够流畅地浏览超出视口的内容。

### 提示词
```
这是目录为blink/renderer/core/scroll/scrollable_area.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
eVerticalScrollbar(scrollbar);
    else
      mac_scrollbar_animator_->WillRemoveHorizontalScrollbar(scrollbar);
  }
}

void ScrollableArea::ContentsResized() {
  if (mac_scrollbar_animator_)
    mac_scrollbar_animator_->ContentsResized();
}

bool ScrollableArea::HasOverlayScrollbars() const {
  Scrollbar* v_scrollbar = VerticalScrollbar();
  if (v_scrollbar && v_scrollbar->IsOverlayScrollbar())
    return true;
  Scrollbar* h_scrollbar = HorizontalScrollbar();
  return h_scrollbar && h_scrollbar->IsOverlayScrollbar();
}

void ScrollableArea::SetOverlayScrollbarColorScheme(
    mojom::blink::ColorScheme overlay_theme) {
  overlay_scrollbar_color_scheme__ = static_cast<unsigned>(overlay_theme);

  if (Scrollbar* scrollbar = HorizontalScrollbar()) {
    scrollbar->SetNeedsPaintInvalidation(kAllParts);
  }

  if (Scrollbar* scrollbar = VerticalScrollbar()) {
    scrollbar->SetNeedsPaintInvalidation(kAllParts);
  }
}

void ScrollableArea::RecalculateOverlayScrollbarColorScheme() {
  mojom::blink::ColorScheme old_overlay_theme =
      GetOverlayScrollbarColorScheme();

  // Start with a scrollbar overlay theme based on the used color scheme.
  mojom::blink::ColorScheme overlay_theme = UsedColorSchemeScrollbars();

  // If there is a background color set on the scroller, use the lightness of
  // the background color for the scrollbar overlay color theme.
  if (GetLayoutBox()) {
    Color background_color = GetLayoutBox()->StyleRef().VisitedDependentColor(
        GetCSSPropertyBackgroundColor());
    if (!background_color.IsFullyTransparent()) {
      double hue, saturation, lightness;
      background_color.GetHSL(hue, saturation, lightness);
      overlay_theme = lightness <= 0.5 ? mojom::blink::ColorScheme::kDark
                                       : mojom::blink::ColorScheme::kLight;
    }
  }

  if (old_overlay_theme != overlay_theme) {
    SetOverlayScrollbarColorScheme(overlay_theme);
  }
}

void ScrollableArea::SetScrollbarNeedsPaintInvalidation(
    ScrollbarOrientation orientation) {
  if (orientation == kHorizontalScrollbar)
    horizontal_scrollbar_needs_paint_invalidation_ = true;
  else
    vertical_scrollbar_needs_paint_invalidation_ = true;

  // Invalidate the scrollbar directly if it's already composited.
  // GetLayoutBox() may be null in some unit tests.
  if (auto* box = GetLayoutBox()) {
    if (auto* scrollbar = GetScrollbar(orientation)) {
      if (auto* compositor =
              box->GetFrameView()->GetPaintArtifactCompositor()) {
        CompositorElementId element_id = GetScrollbarElementId(orientation);
        if (scrollbar->IsSolidColor()) {
          // This will call SetNeedsDisplay() if the color changes (which is
          // the only reason for a SolidColorScrollbarLayer to update display).
          if (compositor->SetScrollbarSolidColor(
                  element_id, scrollbar->GetTheme().ThumbColor(*scrollbar))) {
            scrollbar->ClearNeedsUpdateDisplay();
          }
        } else if (compositor->SetScrollbarNeedsDisplay(element_id)) {
          scrollbar->ClearNeedsUpdateDisplay();
        }
      }
    }
  }

  // TODO(crbug.com/1505560): we don't need to invalidate paint of scrollbar
  // for changes inside of the scrollbar. We'll invalidate raster if needed
  // after paint. We can remove some of paint invalidation code in this class,
  // and move remaining paint invalidation code into
  // PaintLayerScrollableArea and Scrollbar.
  ScrollControlWasSetNeedsPaintInvalidation();
}

void ScrollableArea::SetScrollCornerNeedsPaintInvalidation() {
  if (cc::Layer* layer = LayerForScrollCorner())
    layer->SetNeedsDisplay();
  scroll_corner_needs_paint_invalidation_ = true;
  ScrollControlWasSetNeedsPaintInvalidation();
}

void ScrollableArea::SetScrollControlsNeedFullPaintInvalidation() {
  if (auto* horizontal_scrollbar = HorizontalScrollbar())
    horizontal_scrollbar->SetNeedsPaintInvalidation(kAllParts);
  if (auto* vertical_scrollbar = VerticalScrollbar())
    vertical_scrollbar->SetNeedsPaintInvalidation(kAllParts);
  SetScrollCornerNeedsPaintInvalidation();
}

bool ScrollableArea::HasLayerForHorizontalScrollbar() const {
  return LayerForHorizontalScrollbar();
}

bool ScrollableArea::HasLayerForVerticalScrollbar() const {
  return LayerForVerticalScrollbar();
}

bool ScrollableArea::HasLayerForScrollCorner() const {
  return LayerForScrollCorner();
}

void ScrollableArea::ServiceScrollAnimations(double monotonic_time) {
  bool requires_animation_service = false;
  if (ScrollAnimatorBase* scroll_animator = ExistingScrollAnimator()) {
    scroll_animator->TickAnimation(base::Seconds(monotonic_time) +
                                   base::TimeTicks());
    if (scroll_animator->HasAnimationThatRequiresService())
      requires_animation_service = true;
  }
  if (ProgrammaticScrollAnimator* programmatic_scroll_animator =
          ExistingProgrammaticScrollAnimator()) {
    programmatic_scroll_animator->TickAnimation(base::Seconds(monotonic_time) +
                                                base::TimeTicks());
    if (programmatic_scroll_animator->HasAnimationThatRequiresService())
      requires_animation_service = true;
  }
  if (!requires_animation_service)
    DeregisterForAnimation();
}

void ScrollableArea::UpdateCompositorScrollAnimations() {
  if (ProgrammaticScrollAnimator* programmatic_scroll_animator =
          ExistingProgrammaticScrollAnimator())
    programmatic_scroll_animator->UpdateCompositorAnimations();

  if (ScrollAnimatorBase* scroll_animator = ExistingScrollAnimator())
    scroll_animator->UpdateCompositorAnimations();
}

void ScrollableArea::CancelScrollAnimation() {
  if (ScrollAnimatorBase* scroll_animator = ExistingScrollAnimator())
    scroll_animator->CancelAnimation();
}

void ScrollableArea::CancelProgrammaticScrollAnimation() {
  if (ProgrammaticScrollAnimator* programmatic_scroll_animator =
          ExistingProgrammaticScrollAnimator())
    programmatic_scroll_animator->CancelAnimation();
}

bool ScrollableArea::ScrollbarsHiddenIfOverlay() const {
  return HasOverlayScrollbars() && scrollbars_hidden_if_overlay_;
}

void ScrollableArea::SetScrollbarsHiddenForTesting(bool hidden) {
  // If scrollable area has been disposed, we can not get the page scrollbar
  // theme setting. Should early return here.
  if (HasBeenDisposed())
    return;

  SetScrollbarsHiddenIfOverlayInternal(hidden);
}

void ScrollableArea::SetScrollbarsHiddenFromExternalAnimator(bool hidden) {
  // If scrollable area has been disposed, we can not get the page scrollbar
  // theme setting. Should early return here.
  if (HasBeenDisposed())
    return;

  DCHECK(!GetPageScrollbarTheme().BlinkControlsOverlayVisibility());
  SetScrollbarsHiddenIfOverlayInternal(hidden);
}

void ScrollableArea::SetScrollbarsHiddenIfOverlay(bool hidden) {
  // If scrollable area has been disposed, we can not get the page scrollbar
  // theme setting. Should early return here.
  if (HasBeenDisposed())
    return;

  DCHECK(GetPageScrollbarTheme().BlinkControlsOverlayVisibility());
  SetScrollbarsHiddenIfOverlayInternal(hidden);
}

void ScrollableArea::SetScrollbarsHiddenIfOverlayInternal(bool hidden) {
  if (!GetPageScrollbarTheme().UsesOverlayScrollbars())
    return;

  if (scrollbars_hidden_if_overlay_ == static_cast<unsigned>(hidden))
    return;

  scrollbars_hidden_if_overlay_ = hidden;
  ScrollbarVisibilityChanged();
}

void ScrollableArea::FadeOverlayScrollbarsTimerFired(TimerBase*) {
  // Scrollbars can become composited in the time it takes the timer set in
  // ShowNonMacOverlayScrollbars to be fired.
  if (RuntimeEnabledFeatures::RasterInducingScrollEnabled() ||
      UsesCompositedScrolling()) {
    return;
  }
  SetScrollbarsHiddenIfOverlay(true);
}

void ScrollableArea::ShowNonMacOverlayScrollbars() {
  if (!GetPageScrollbarTheme().UsesOverlayScrollbars() ||
      !GetPageScrollbarTheme().BlinkControlsOverlayVisibility())
    return;

  // Don't do this for composited scrollbars. These scrollbars are handled
  // by separate code in cc::ScrollbarAnimationController.
  // TODO(crbug.com/1229864): We may want to always composite overlay
  // scrollbars to avoid the bug and the duplicated code for composited and
  // non-composited overlay scrollbars.
  if (RuntimeEnabledFeatures::RasterInducingScrollEnabled() ||
      UsesCompositedScrolling()) {
    return;
  }

  SetScrollbarsHiddenIfOverlay(false);

  const base::TimeDelta time_until_disable =
      GetPageScrollbarTheme().OverlayScrollbarFadeOutDelay() +
      GetPageScrollbarTheme().OverlayScrollbarFadeOutDuration();

  // If the overlay scrollbars don't fade out, don't do anything. This is the
  // case for the mock overlays used in tests (and also Mac but its scrollbars
  // are animated by OS APIs and so we've already early-out'ed above).  We also
  // don't fade out overlay scrollbar for popup since we don't create
  // compositor for popup and thus they don't appear on hover so users without
  // a wheel can't scroll if they fade out.
  if (time_until_disable.is_zero() || GetChromeClient()->IsPopup())
    return;

  if (!fade_overlay_scrollbars_timer_) {
    fade_overlay_scrollbars_timer_ = MakeGarbageCollected<
        DisallowNewWrapper<HeapTaskRunnerTimer<ScrollableArea>>>(
        GetCompositorTaskRunner(), this,
        &ScrollableArea::FadeOverlayScrollbarsTimerFired);
  }

  if (!scrollbar_captured_ && !mouse_over_scrollbar_) {
    fade_overlay_scrollbars_timer_->Value().StartOneShot(time_until_disable,
                                                         FROM_HERE);
  }
}

scoped_refptr<base::SingleThreadTaskRunner>
ScrollableArea::GetCompositorTaskRunner() {
  return compositor_task_runner_;
}

Node* ScrollableArea::EventTargetNode() const {
  const LayoutBox* box = GetLayoutBox();
  Node* node = box->GetNode();
  if (!node && box->Parent() && box->Parent()->IsFieldset()) {
    node = box->Parent()->GetNode();
  }
  if (auto* element = DynamicTo<Element>(node)) {
    const LayoutBox* layout_box_for_scrolling =
        element->GetLayoutBoxForScrolling();
    if (layout_box_for_scrolling)
      DCHECK_EQ(box, layout_box_for_scrolling);
    else
      return nullptr;
  }
  return node;
}

const Document* ScrollableArea::GetDocument() const {
  if (auto* box = GetLayoutBox())
    return &box->GetDocument();
  return nullptr;
}

gfx::Vector2d ScrollableArea::ClampScrollOffset(
    const gfx::Vector2d& scroll_offset) const {
  gfx::Vector2d result = scroll_offset;
  result.SetToMin(MaximumScrollOffsetInt());
  result.SetToMax(MinimumScrollOffsetInt());
  return result;
}

ScrollOffset ScrollableArea::ClampScrollOffset(
    const ScrollOffset& scroll_offset) const {
  ScrollOffset result = scroll_offset;
  result.SetToMin(MaximumScrollOffset());
  result.SetToMax(MinimumScrollOffset());
  return result;
}

int ScrollableArea::LineStep(ScrollbarOrientation) const {
  return PixelsPerLineStep(GetLayoutBox()->GetFrame());
}

int ScrollableArea::PageStep(ScrollbarOrientation orientation) const {
  // Paging scroll operations should take scroll-padding into account [1]. So we
  // use the snapport rect to calculate the page step instead of the visible
  // rect.
  // [1] https://drafts.csswg.org/css-scroll-snap/#scroll-padding
  gfx::Size snapport_size =
      VisibleScrollSnapportRect(kExcludeScrollbars).PixelSnappedSize();
  int length = (orientation == kHorizontalScrollbar) ? snapport_size.width()
                                                     : snapport_size.height();
  int min_page_step =
      static_cast<float>(length) * MinFractionToStepWhenPaging();
  int page_step = std::max(min_page_step, length - MaxOverlapBetweenPages());

  return std::max(page_step, 1);
}

int ScrollableArea::DocumentStep(ScrollbarOrientation orientation) const {
  return ScrollSize(orientation);
}

float ScrollableArea::PixelStep(ScrollbarOrientation) const {
  return 1;
}

float ScrollableArea::PercentageStep(ScrollbarOrientation orientation) const {
  int percent_basis =
      (orientation == ScrollbarOrientation::kHorizontalScrollbar)
          ? VisibleWidth()
          : VisibleHeight();
  return static_cast<float>(percent_basis);
}

int ScrollableArea::VerticalScrollbarWidth(
    OverlayScrollbarClipBehavior behavior) const {
  DCHECK_EQ(behavior, kIgnoreOverlayScrollbarSize);
  if (Scrollbar* vertical_bar = VerticalScrollbar())
    return !vertical_bar->IsOverlayScrollbar() ? vertical_bar->Width() : 0;
  return 0;
}

int ScrollableArea::HorizontalScrollbarHeight(
    OverlayScrollbarClipBehavior behavior) const {
  DCHECK_EQ(behavior, kIgnoreOverlayScrollbarSize);
  if (Scrollbar* horizontal_bar = HorizontalScrollbar())
    return !horizontal_bar->IsOverlayScrollbar() ? horizontal_bar->Height() : 0;
  return 0;
}

gfx::QuadF ScrollableArea::LocalToVisibleContentQuad(const gfx::QuadF& quad,
                                                     const LayoutObject*,
                                                     unsigned) const {
  return quad - GetScrollOffset();
}

gfx::Size ScrollableArea::ExcludeScrollbars(const gfx::Size& size) const {
  return gfx::Size(std::max(0, size.width() - VerticalScrollbarWidth()),
                   std::max(0, size.height() - HorizontalScrollbarHeight()));
}

void ScrollableArea::DidCompositorScroll(const gfx::PointF& position) {
  ScrollOffset new_offset(ScrollPositionToOffset(position));
  SetScrollOffset(new_offset, mojom::blink::ScrollType::kCompositor);
}

Scrollbar* ScrollableArea::GetScrollbar(
    ScrollbarOrientation orientation) const {
  return orientation == kHorizontalScrollbar ? HorizontalScrollbar()
                                             : VerticalScrollbar();
}

CompositorElementId ScrollableArea::GetScrollbarElementId(
    ScrollbarOrientation orientation) {
  CompositorElementId scrollable_element_id = GetScrollElementId();
  DCHECK(scrollable_element_id);
  CompositorElementIdNamespace element_id_namespace =
      orientation == kHorizontalScrollbar
          ? CompositorElementIdNamespace::kHorizontalScrollbar
          : CompositorElementIdNamespace::kVerticalScrollbar;
  return CompositorElementIdWithNamespace(scrollable_element_id,
                                          element_id_namespace);
}

void ScrollableArea::OnScrollFinished(bool scroll_did_end) {
  if (GetLayoutBox()) {
    if (scroll_did_end) {
      active_smooth_scroll_type_.reset();
      UpdateSnappedTargetsAndEnqueueScrollSnapChange();
      if (Node* node = EventTargetNode()) {
        if (auto* viewport_position_tracker =
                AnchorElementViewportPositionTracker::MaybeGetOrCreateFor(
                    node->GetDocument())) {
          viewport_position_tracker->OnScrollEnd();
        }
        if (RuntimeEnabledFeatures::ScrollEndEventsEnabled()) {
          node->GetDocument().EnqueueScrollEndEventForNode(node);
        }
      }
    }
    GetLayoutBox()
        ->GetFrame()
        ->LocalFrameRoot()
        .GetEventHandler()
        .MarkHoverStateDirty();
  }
}

void ScrollableArea::SnapAfterScrollbarScrolling(
    ScrollbarOrientation orientation) {
  SnapAtCurrentPosition(orientation == kHorizontalScrollbar,
                        orientation == kVerticalScrollbar);
}

bool ScrollableArea::SnapAtCurrentPosition(
    bool scrolled_x,
    bool scrolled_y,
    base::ScopedClosureRunner on_finish) {
  DCHECK(IsRootFrameViewport() || !GetLayoutBox()->IsGlobalRootScroller());
  gfx::PointF current_position = ScrollPosition();
  return SnapForEndPosition(current_position, scrolled_x, scrolled_y,
                            std::move(on_finish));
}

bool ScrollableArea::SnapForEndPosition(const gfx::PointF& end_position,
                                        bool scrolled_x,
                                        bool scrolled_y,
                                        base::ScopedClosureRunner on_finish) {
  DCHECK(IsRootFrameViewport() || !GetLayoutBox()->IsGlobalRootScroller());
  std::unique_ptr<cc::SnapSelectionStrategy> strategy =
      cc::SnapSelectionStrategy::CreateForEndPosition(end_position, scrolled_x,
                                                      scrolled_y);
  return PerformSnapping(*strategy, mojom::blink::ScrollBehavior::kSmooth,
                         std::move(on_finish));
}

bool ScrollableArea::SnapForDirection(const ScrollOffset& delta,
                                      base::ScopedClosureRunner on_finish) {
  DCHECK(IsRootFrameViewport() || !GetLayoutBox()->IsGlobalRootScroller());
  gfx::PointF current_position = ScrollPosition();
  std::unique_ptr<cc::SnapSelectionStrategy> strategy =
      cc::SnapSelectionStrategy::CreateForDirection(
          current_position, delta,
          RuntimeEnabledFeatures::FractionalScrollOffsetsEnabled());
  return PerformSnapping(*strategy, mojom::blink::ScrollBehavior::kSmooth,
                         std::move(on_finish));
}

bool ScrollableArea::SnapForEndAndDirection(const ScrollOffset& delta) {
  DCHECK(IsRootFrameViewport() || !GetLayoutBox()->IsGlobalRootScroller());
  gfx::PointF current_position = ScrollPosition();
  std::unique_ptr<cc::SnapSelectionStrategy> strategy =
      cc::SnapSelectionStrategy::CreateForEndAndDirection(
          current_position, delta,
          RuntimeEnabledFeatures::FractionalScrollOffsetsEnabled());
  return PerformSnapping(*strategy);
}

void ScrollableArea::SnapAfterLayout() {
  const cc::SnapContainerData* container_data = GetSnapContainerData();
  if (!container_data || !container_data->size()) {
    UpdateSnappedTargetsAndEnqueueScrollSnapChange();
    return;
  }

  gfx::PointF current_position = ScrollPosition();
  std::unique_ptr<cc::SnapSelectionStrategy> strategy =
      cc::SnapSelectionStrategy::CreateForTargetElement(current_position);
  PerformSnapping(*strategy, mojom::blink::ScrollBehavior::kInstant);
}

bool ScrollableArea::PerformSnapping(
    const cc::SnapSelectionStrategy& strategy,
    mojom::blink::ScrollBehavior scroll_behavior,
    base::ScopedClosureRunner on_finish) {
  std::optional<gfx::PointF> snap_point = GetSnapPositionAndSetTarget(strategy);
  if (!snap_point) {
    UpdateSnappedTargetsAndEnqueueScrollSnapChange();
    return false;
  }

  // We should set the scrollsnapchanging targets of a snap container the first
  // time it is laid out to avoid a spurious scrollsnapchanging event firing the
  // first time the scroller is scrolled.
  if (!GetScrollsnapchangingTargetIds()) {
    SetScrollsnapchangingTargetIds(
        GetSnapContainerData()->GetTargetSnapAreaElementIds());
  }

  CancelScrollAnimation();
  CancelProgrammaticScrollAnimation();
  if (!SetScrollOffset(ScrollPositionToOffset(snap_point.value()),
                       mojom::blink::ScrollType::kProgrammatic, scroll_behavior,
                       IgnoreArgs<ScrollableArea::ScrollCompletionMode>(
                           on_finish.Release()))) {
    // If no scroll happens, e.g. we got here because of a layout change, we
    // need to re-compute snapped targets and fire scrollsnapchange if
    // necessary.
    UpdateSnappedTargetsAndEnqueueScrollSnapChange();
  }
  return true;
}

void ScrollableArea::Trace(Visitor* visitor) const {
  visitor->Trace(scroll_animator_);
  visitor->Trace(mac_scrollbar_animator_);
  visitor->Trace(programmatic_scroll_animator_);
  visitor->Trace(fade_overlay_scrollbars_timer_);
}

void ScrollableArea::InjectScrollbarGestureScroll(
    ScrollOffset delta,
    ui::ScrollGranularity granularity,
    WebInputEvent::Type gesture_type) const {
  // All ScrollableArea's have a layout box, except for the VisualViewport.
  // We shouldn't be injecting scrolls for the visual viewport scrollbar, since
  // it is not hit-testable.
  DCHECK(GetLayoutBox());

  // Speculative fix for crash reports (crbug.com/1307510).
  if (!GetLayoutBox() || !GetLayoutBox()->GetFrame())
    return;

  if (granularity == ui::ScrollGranularity::kScrollByPrecisePixel ||
      granularity == ui::ScrollGranularity::kScrollByPixel) {
    // Pixel-based deltas need to be scaled up by the input event scale factor,
    // since the GSUs will be scaled down by that factor when being handled.
    float scale = 1;
    LocalFrameView* root_view =
        GetLayoutBox()->GetFrame()->LocalFrameRoot().View();
    if (root_view)
      scale = root_view->InputEventsScaleFactor();
    delta.Scale(scale);
  }

  GetChromeClient()->InjectScrollbarGestureScroll(
      *GetLayoutBox()->GetFrame(), delta, granularity, GetScrollElementId(),
      gesture_type);
}

ScrollableArea* ScrollableArea::GetForScrolling(const LayoutBox* layout_box) {
  if (!layout_box)
    return nullptr;

  if (!layout_box->IsGlobalRootScroller()) {
    if (const auto* element = DynamicTo<Element>(layout_box->GetNode())) {
      if (auto* scrolling_box = element->GetLayoutBoxForScrolling())
        return scrolling_box->GetScrollableArea();
    }
    return layout_box->GetScrollableArea();
  }

  // The global root scroller should be scrolled by the root frame view's
  // ScrollableArea.
  LocalFrame& root_frame = layout_box->GetFrame()->LocalFrameRoot();
  return root_frame.View()->GetScrollableArea();
}

float ScrollableArea::ScaleFromDIP() const {
  auto* client = GetChromeClient();
  auto* document = GetDocument();
  if (client && document)
    return client->WindowToViewportScalar(document->GetFrame(), 1.0f);
  return 1.0f;
}

bool ScrollableArea::ScrollOffsetIsNoop(const ScrollOffset& offset) const {
  return GetScrollOffset() ==
         (ShouldUseIntegerScrollOffset()
              ? ScrollOffset(gfx::ToFlooredVector2d(offset))
              : offset);
}

void ScrollableArea::EnqueueScrollSnapChangeEvent() const {
  DCHECK(RuntimeEnabledFeatures::CSSScrollSnapChangeEventEnabled());
  Node* target_node = EventTargetNode();
  if (!target_node) {
    return;
  }
  Member<Node> block_target = GetSnapEventTargetAlongAxis(
      event_type_names::kScrollsnapchange, cc::SnapAxis::kBlock);
  Member<Node> inline_target = GetSnapEventTargetAlongAxis(
      event_type_names::kScrollsnapchange, cc::SnapAxis::kInline);
  target_node->GetDocument().EnqueueScrollSnapChangeEvent(
      target_node, block_target, inline_target);
}

void ScrollableArea::EnqueueScrollSnapChangingEvent() const {
  DCHECK(RuntimeEnabledFeatures::CSSScrollSnapChangingEventEnabled());
  Node* target_node = EventTargetNode();
  if (!target_node) {
    return;
  }
  Member<Node> block_target = GetSnapEventTargetAlongAxis(
      event_type_names::kScrollsnapchanging, cc::SnapAxis::kBlock);
  Member<Node> inline_target = GetSnapEventTargetAlongAxis(
      event_type_names::kScrollsnapchanging, cc::SnapAxis::kInline);
  target_node->GetDocument().EnqueueScrollSnapChangingEvent(
      target_node, block_target, inline_target);
}

ScrollOffset ScrollableArea::GetWebExposedScrollOffset() const {
  ScrollOffset scroll_offset =
      SnapScrollOffsetToPhysicalPixels(GetScrollOffset());

  // Ensure that, if fractional scroll offsets are not enabled, the scroll
  // offset is an floored value.
  CHECK_EQ(gfx::ToFlooredVector2d(scroll_offset), scroll_offset);
  return scroll_offset;
}

}  // namespace blink
```