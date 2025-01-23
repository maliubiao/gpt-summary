Response:
The user wants a summary of the functionalities of the provided C++ code snippet from `visual_viewport.cc`. They are particularly interested in:

1. **Listing functionalities**: A comprehensive list of what the code does.
2. **Relationship to web technologies**:  Connections and examples related to JavaScript, HTML, and CSS.
3. **Logical reasoning**: Identifying sections with clear input and output relationships and providing examples.
4. **Common errors**: Pointing out typical mistakes developers might make when using or interacting with this component.
5. **Overall function**: A concise summary of the file's purpose, as this is part 2 of a 2-part analysis.

Let's break down the code section by section to identify its functionalities and connections to web technologies.

**Code Breakdown and Functionalities:**

* **`pDocumentOffsetAtScale`**: Calculates the clamped document offset at a given scale. It takes an offset and a scale as input and returns a clamped point.
* **`SetBrowserControlsAdjustment`**: Sets the adjustment for browser controls (like the address bar). It affects the available viewport size.
* **`BrowserControlsAdjustment`**: Returns the current browser controls adjustment.
* **`UserInputScrollable`**: Determines if the visual viewport can be scrolled by user input. It considers fullscreen elements.
* **`ContentsSize`**: Returns the size of the content within the viewport.
* **`VisibleContentRect`**: Returns the visible content rectangle, optionally including scrollbars.
* **`GetTimerTaskRunner`**: Returns a task runner for internal timers.
* **`UsedColorSchemeScrollbars`**: Returns the color scheme used for scrollbars based on the document's style.
* **`UpdateScrollOffset`**: Updates the scroll offset and notifies the root frame viewport.
* **`LayerForScrolling`, `LayerForHorizontalScrollbar`, `LayerForVerticalScrollbar`**: Return the compositing layers associated with scrolling and scrollbars.
* **`GetRootFrameViewport`**: Returns the root frame viewport object.
* **`IsActiveViewport`**: Checks if this is the active visual viewport (only the outermost main frame has one).
* **`LocalMainFrame`**: Returns a reference to the local main frame.
* **`ExcludeScrollbars`**: Calculates the size excluding scrollbar dimensions.
* **`ScheduleAnimation`**: Schedules a visual animation.
* **`ClampToBoundaries`**: Clamps the viewport's location to its boundaries.
* **`ViewportToRootFrame` and `RootFrameToViewport` (various overloads)**:  Methods for converting coordinates between the visual viewport and the root frame. These are crucial for understanding element positioning across different coordinate systems.
* **`ShouldDisableDesktopWorkarounds`**: Determines if desktop-specific workarounds should be disabled based on viewport meta tag settings.
* **`GetCompositorAnimationHost` and `GetCompositorAnimationTimeline`**: Access the compositor's animation infrastructure.
* **`NotifyRootFrameViewport`**: Informs the root frame viewport about visual viewport updates.
* **`GetPageScrollbarTheme`**: Returns the scrollbar theme for the page.
* **`GetPaintArtifactCompositor`**: Returns the paint artifact compositor.
* **`ViewportToTracedValue`**: Creates a TracedValue representation of the viewport for debugging and performance monitoring.
* **`DisposeImpl`**: Cleans up resources.
* **`Paint`**: Records display items for rendering the viewport and scrollbars using compositing layers.
* **`UsedColorSchemeChanged`**: Reacts to changes in the document's color scheme to update scrollbar appearance.
* **`ScrollbarColorChanged`**:  Handles changes to the scrollbar color.
* **`UpdateScrollbarColor`**: Updates the color of a given scrollbar layer.

**Connections to Web Technologies:**

* **JavaScript**:  JavaScript can interact with the visual viewport through APIs like `window.visualViewport`. This code likely implements the backend logic for those APIs.
* **HTML**: The `<meta name="viewport">` tag in HTML influences the visual viewport's behavior, particularly its size, zoom constraints, and whether desktop workarounds are applied.
* **CSS**: CSS properties like `overflow`, `width`, `height`, and scrollbar styling directly affect the visual viewport's dimensions, scrollability, and appearance. The `prefers-color-scheme` media query influences the scrollbar color scheme.

**Logical Reasoning Examples:**

* **`pDocumentOffsetAtScale`**:
    * **Input:** `offset` = `{100, 100}`, `scale` = `2.0`
    * **Assumption:** The visual viewport size and content size allow for this offset at the given scale.
    * **Output:** A `gfx::Point` representing the clamped offset. The clamping logic ensures the offset remains within valid bounds.

* **`UserInputScrollable`**:
    * **Input (Scenario 1):** No fullscreen element.
    * **Output:** `true` (scrolling is allowed).
    * **Input (Scenario 2):** A non-root fullscreen element exists.
    * **Output:** `false` (scrolling is blocked).

**Common Usage Errors:**

* **Incorrectly assuming visual viewport size:** Developers might assume the visual viewport size is constant, but it can change due to browser controls, zooming, and viewport meta tags.
* **Not accounting for coordinate system differences:**  Directly manipulating coordinates without converting between viewport and document/root frame spaces can lead to incorrect positioning.
* **Misunderstanding the impact of viewport meta tags:**  Incorrectly configured viewport meta tags can lead to unexpected zooming or layout behavior.

**Overall Function (Part 2):**

This part of the `visual_viewport.cc` file focuses on the **state management, coordinate transformations, rendering, and user interaction aspects of the visual viewport**. It handles:

* **Positioning and scaling**: Calculating and managing the viewport's position and zoom level relative to the document.
* **Clipping and boundaries**: Ensuring the viewport stays within valid bounds.
* **Scrollability**: Determining and controlling whether the user can scroll the viewport.
* **Coordinate transformations**: Providing utilities to convert between different coordinate spaces (viewport, root frame).
* **Rendering**:  Contributing to the rendering pipeline by managing compositing layers for the viewport and scrollbars.
* **Integration with browser features**: Interacting with browser controls and fullscreen mode.
* **Responsiveness**: Adapting to different screen sizes and orientations, potentially disabling desktop workarounds based on the website's configuration.
* **Theming**: Handling scrollbar theming based on the document's color scheme.

In essence, it's responsible for the dynamic and interactive aspects of the visual viewport, building upon the foundation likely laid out in the first part of the file. It ensures the user sees the correct portion of the web page at the appropriate zoom level and can interact with it through scrolling.
好的，让我们来归纳一下这段 `blink/renderer/core/frame/visual_viewport.cc` 代码的功能。

**功能归纳:**

这段代码主要负责实现 Chromium Blink 引擎中 **视觉视口 (Visual Viewport)** 的相关功能。视觉视口是用户在屏幕上实际看到的内容区域，它会受到缩放、滚动、浏览器控件（如地址栏）的影响。

具体来说，这段代码的功能包括：

1. **管理视觉视口的位置和缩放:**
   - 提供方法来获取和设置视觉视口的偏移量 (`offset_`) 和缩放比例 (`scale_`)。
   - `pDocumentOffsetAtScale` 方法用于计算在特定缩放比例下，给定的偏移量在文档中的实际位置，并进行边界 clamping。
   - `SetLocation` 方法用于设置视觉视口的位置，并进行边界限制。
   - `SetScale` 方法用于设置视觉视口的缩放比例，并处理相关的事件通知。
   - 维护 `is_pinch_gesture_active_` 标志，表示当前是否是捏合缩放手势。

2. **处理浏览器控件的调整:**
   - `SetBrowserControlsAdjustment` 方法允许调整因浏览器控件（例如，移动设备上的地址栏显示/隐藏）而引起的视觉视口大小变化。
   - `BrowserControlsAdjustment` 方法返回当前的浏览器控件调整值。

3. **控制用户输入滚动:**
   - `UserInputScrollable` 方法判断当前视觉视口是否允许用户通过输入进行滚动。当存在非根全屏元素时，会阻止视觉视口的滚动。

4. **获取内容和可见区域大小:**
   - `ContentsSize` 方法返回文档内容的完整大小。
   - `VisibleRect` 和 `VisibleContentRect` 方法返回当前视觉视口可见的矩形区域，可以选择是否包含滚动条。

5. **管理与渲染相关的层:**
   - 提供访问与滚动 (`scroll_layer_`) 和滚动条 (`scrollbar_layer_horizontal_`, `scrollbar_layer_vertical_`) 相关的合成层的方法。
   - `Paint` 方法负责在渲染过程中记录这些层的绘制信息。

6. **坐标转换:**
   - 提供了一系列 `ViewportToRootFrame` 和 `RootFrameToViewport` 方法，用于在视觉视口坐标系和根框架坐标系之间进行坐标转换（点和矩形）。

7. **判断是否禁用桌面端适配的 workaround:**
   - `ShouldDisableDesktopWorkarounds` 方法根据页面设置（例如，`viewport` meta 标签）判断是否应该禁用针对桌面端的一些兼容性处理。

8. **处理动画:**
   - `ScheduleAnimation` 方法用于调度动画。
   - `GetCompositorAnimationHost` 和 `GetCompositorAnimationTimeline` 方法用于获取合成器的动画主机和时间线。

9. **通知父级框架:**
   - `NotifyRootFrameViewport` 方法用于通知根框架视口视觉视口发生了更新。

10. **处理滚动条主题和颜色:**
    - `UsedColorSchemeScrollbars` 方法获取当前使用的颜色方案，用于确定滚动条的样式。
    - `UsedColorSchemeChanged` 和 `ScrollbarColorChanged` 方法处理颜色方案和滚动条颜色的变化，并更新滚动条的显示。
    - `UpdateScrollbarColor` 方法用于更新滚动条图层的颜色。

11. **生命周期管理:**
    - `IsActiveViewport` 方法判断当前视觉视口是否处于激活状态（只有最外层的主框架才有激活的视觉视口）。
    - `DisposeImpl` 方法用于清理资源。

12. **调试信息:**
    - `ViewportToTracedValue` 方法将视觉视口的信息转换为可追踪的值，用于调试和性能分析。

**与 JavaScript, HTML, CSS 的关系:**

* **JavaScript:** JavaScript 可以通过 `window.visualViewport` API 来访问和操作视觉视口的信息，例如获取其大小、偏移量和缩放比例，以及监听其变化事件。这段 C++ 代码实现了这些 API 背后的核心逻辑。
    * **举例:** JavaScript 可以使用 `visualViewport.offsetLeft` 和 `visualViewport.offsetTop` 来获取视觉视口的偏移量，这对应于 C++ 代码中的 `offset_`。
    * **举例:** JavaScript 可以监听 `visualviewportresize` 和 `visualviewportscroll` 事件，这些事件的触发可能与 C++ 代码中设置 `scale_` 或 `offset_` 以及调用 `EnqueueResizeEvent()` 或通知父框架有关。

* **HTML:** HTML 中的 `<meta name="viewport">` 标签会影响视觉视口的初始状态和行为，例如初始缩放比例、最小/最大缩放比例、宽度等。
    * **举例:**  HTML 中设置 `<meta name="viewport" content="width=device-width, initial-scale=1.0">` 会影响 `VisualViewport` 对象的初始大小和缩放比例。`ShouldDisableDesktopWorkarounds` 方法的判断就与 `viewport` meta 标签的设置有关。

* **CSS:** CSS 属性如 `zoom`、`overflow`、滚动条相关的伪元素 (`::-webkit-scrollbar`) 和媒体查询 (`@media (prefers-color-scheme: dark)`) 都会影响视觉视口的渲染和行为。
    * **举例:**  如果 CSS 中设置了 `body { overflow: auto; }`，当内容超出视觉视口大小时，会出现滚动条，而 `VisualViewport` 代码负责管理这些滚动条的显示和交互。
    * **举例:**  `UsedColorSchemeScrollbars` 和相关的 `UsedColorSchemeChanged` 方法与 CSS 的 `@media (prefers-color-scheme)` 媒体查询有关，用于根据用户选择的颜色模式调整滚动条的颜色。

**逻辑推理的假设输入与输出:**

* **假设输入:** `pDocumentOffsetAtScale` 方法接收 `offset` 为 `{50, 50}`，`scale` 为 `2.0`。当前视觉视口的大小为 `{300, 400}`，内容大小为 `{600, 800}`。
* **输出:**  该方法会计算在缩放 `2.0` 的情况下，视觉视口有效的大小为 `{150, 200}`。然后，它会根据内容大小和有效视口大小计算出允许的最大偏移量。假设计算出的最大偏移量为 `{450, 600}`，最小偏移量为 `{0, 0}`。由于输入的 `offset` 在缩放前是 `{50, 50}`，缩放后对应的内容偏移量也是 `{50, 50}`，这个值在允许的范围内，所以输出的 clamped 后的点很可能仍然是与缩放前的偏移量对应的点，但具体数值取决于内部的计算逻辑，需要考虑缩放中心等因素。一个简化的理解是，输出会是一个在允许滚动范围内的点。

* **假设输入:** `UserInputScrollable` 方法被调用，并且当前页面中有一个使用全屏 API 进入全屏模式的 `<div>` 元素。
* **输出:**  `UserInputScrollable` 方法会返回 `false`，阻止用户通过视觉视口进行滚动，因为存在一个非根全屏元素。

**涉及的用户或编程常见的使用错误:**

* **错误地假设视觉视口的大小是固定的:** 开发者可能会在计算布局或坐标时，错误地假设视觉视口的大小始终等于屏幕大小，而忽略了缩放、浏览器控件的影响。
* **在没有考虑坐标系转换的情况下进行坐标计算:** 当需要在视觉视口坐标系和文档坐标系之间进行转换时，如果没有使用 `ViewportToRootFrame` 或 `RootFrameToViewport` 等方法，可能会导致元素定位错误。
* **不理解 `viewport` meta 标签的影响:**  开发者可能会错误地配置 `viewport` meta 标签，导致页面在不同设备上显示异常，例如缩放级别不正确或无法正常缩放。
* **过度依赖 JavaScript 操作视觉视口:**  在某些情况下，过度使用 JavaScript 来操作视觉视口可能会导致性能问题或与浏览器的默认行为冲突。应该尽可能利用 CSS 和浏览器自身的优化。

**总结:**

这段 `visual_viewport.cc` 代码是 Chromium Blink 引擎中实现视觉视口功能的核心部分，它负责管理视觉视口的位置、大小、缩放，处理用户输入和渲染，并与浏览器的其他组件（如渲染引擎、合成器）以及 Web 技术（JavaScript, HTML, CSS）进行交互，以确保用户能够正确地查看和操作网页内容。它是构建响应式和跨设备兼容网页的关键组成部分。

### 提示词
```
这是目录为blink/renderer/core/frame/visual_viewport.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
pDocumentOffsetAtScale(const gfx::Point& offset,
                                                      float scale) {
  DCHECK(IsActiveViewport());

  LocalFrameView* view = LocalMainFrame().View();
  if (!view)
    return gfx::Point();

  gfx::SizeF scaled_size(ExcludeScrollbars(size_));
  scaled_size.Scale(1 / scale);

  gfx::Size visual_viewport_max =
      gfx::ToFlooredSize(gfx::SizeF(ContentsSize()) - scaled_size);
  gfx::Vector2d max =
      view->LayoutViewport()->MaximumScrollOffsetInt() +
      gfx::Vector2d(visual_viewport_max.width(), visual_viewport_max.height());
  gfx::Vector2d min =
      view->LayoutViewport()
          ->MinimumScrollOffsetInt();  // VisualViewportMin should be (0, 0)

  gfx::Point clamped = offset;
  clamped.SetToMin(gfx::PointAtOffsetFromOrigin(max));
  clamped.SetToMax(gfx::PointAtOffsetFromOrigin(min));
  return clamped;
}

void VisualViewport::SetBrowserControlsAdjustment(float adjustment) {
  DCHECK(IsActiveViewport());
  DCHECK(LocalMainFrame().IsOutermostMainFrame());

  if (browser_controls_adjustment_ == adjustment)
    return;

  browser_controls_adjustment_ = adjustment;
  EnqueueResizeEvent();
}

float VisualViewport::BrowserControlsAdjustment() const {
  DCHECK(!browser_controls_adjustment_ || IsActiveViewport());
  return browser_controls_adjustment_;
}

bool VisualViewport::UserInputScrollable(ScrollbarOrientation) const {
  // User input scrollable is used to block scrolling from the visual viewport.
  // If the viewport isn't active we don't have to do anything special.
  if (!IsActiveViewport())
    return true;

  // If there is a non-root fullscreen element, prevent the viewport from
  // scrolling.
  if (Document* main_document = LocalMainFrame().GetDocument()) {
    Element* fullscreen_element =
        Fullscreen::FullscreenElementFrom(*main_document);
    if (fullscreen_element)
      return false;
  }
  return true;
}

gfx::Size VisualViewport::ContentsSize() const {
  if (!IsActiveViewport())
    return gfx::Size();

  LocalFrameView* frame_view = LocalMainFrame().View();
  if (!frame_view)
    return gfx::Size();

  return frame_view->Size();
}

gfx::Rect VisualViewport::VisibleContentRect(
    IncludeScrollbarsInRect scrollbar_inclusion) const {
  return ToEnclosingRect(VisibleRect(scrollbar_inclusion));
}

scoped_refptr<base::SingleThreadTaskRunner> VisualViewport::GetTimerTaskRunner()
    const {
  DCHECK(IsActiveViewport());
  return LocalMainFrame().GetTaskRunner(TaskType::kInternalDefault);
}

mojom::blink::ColorScheme VisualViewport::UsedColorSchemeScrollbars() const {
  DCHECK(IsActiveViewport());
  if (Document* main_document = LocalMainFrame().GetDocument())
    return main_document->GetLayoutView()->StyleRef().UsedColorScheme();

  return mojom::blink::ColorScheme::kLight;
}

void VisualViewport::UpdateScrollOffset(const ScrollOffset& position,
                                        mojom::blink::ScrollType scroll_type) {
  if (!DidSetScaleOrLocation(scale_, is_pinch_gesture_active_,
                             gfx::PointAtOffsetFromOrigin(position))) {
    return;
  }
  if (IsExplicitScrollType(scroll_type))
    NotifyRootFrameViewport();
}

cc::Layer* VisualViewport::LayerForScrolling() const {
  DCHECK(!scroll_layer_ || IsActiveViewport());
  return scroll_layer_.get();
}

cc::Layer* VisualViewport::LayerForHorizontalScrollbar() const {
  DCHECK(!scrollbar_layer_horizontal_ || IsActiveViewport());
  return scrollbar_layer_horizontal_.get();
}

cc::Layer* VisualViewport::LayerForVerticalScrollbar() const {
  DCHECK(!scrollbar_layer_vertical_ || IsActiveViewport());
  return scrollbar_layer_vertical_.get();
}

RootFrameViewport* VisualViewport::GetRootFrameViewport() const {
  if (!IsActiveViewport())
    return nullptr;

  LocalFrameView* frame_view = LocalMainFrame().View();
  if (!frame_view)
    return nullptr;

  return frame_view->GetRootFrameViewport();
}

bool VisualViewport::IsActiveViewport() const {
  Frame* main_frame = GetPage().MainFrame();
  if (!main_frame)
    return false;

  // If the main frame is remote, we're inside a remote subframe which
  // shouldn't have an active visual viewport.
  if (!main_frame->IsLocalFrame())
    return false;

  // Only the outermost main frame should have an active viewport.
  return main_frame->IsOutermostMainFrame();
}

LocalFrame& VisualViewport::LocalMainFrame() const {
  DCHECK(IsActiveViewport());
  return *To<LocalFrame>(GetPage().MainFrame());
}

gfx::Size VisualViewport::ExcludeScrollbars(const gfx::Size& size) const {
  if (!IsActiveViewport())
    return size;

  gfx::Size excluded_size = size;
  if (RootFrameViewport* root_frame_viewport = GetRootFrameViewport()) {
    excluded_size.Enlarge(-root_frame_viewport->VerticalScrollbarWidth(),
                          -root_frame_viewport->HorizontalScrollbarHeight());
  }
  return excluded_size;
}

bool VisualViewport::ScheduleAnimation() {
  DCHECK(IsActiveViewport());

  LocalFrameView* frame_view = LocalMainFrame().View();
  DCHECK(frame_view);
  GetPage().GetChromeClient().ScheduleAnimation(frame_view);
  return true;
}

void VisualViewport::ClampToBoundaries() {
  SetLocation(gfx::PointAtOffsetFromOrigin(offset_));
}

gfx::RectF VisualViewport::ViewportToRootFrame(
    const gfx::RectF& rect_in_viewport) const {
  gfx::RectF rect_in_root_frame = rect_in_viewport;
  rect_in_root_frame.Scale(1 / Scale());
  rect_in_root_frame.Offset(GetScrollOffset());
  return rect_in_root_frame;
}

gfx::Rect VisualViewport::ViewportToRootFrame(
    const gfx::Rect& rect_in_viewport) const {
  // FIXME: How to snap to pixels?
  return ToEnclosingRect(ViewportToRootFrame(gfx::RectF(rect_in_viewport)));
}

gfx::RectF VisualViewport::RootFrameToViewport(
    const gfx::RectF& rect_in_root_frame) const {
  gfx::RectF rect_in_viewport = rect_in_root_frame;
  rect_in_viewport.Offset(-GetScrollOffset());
  rect_in_viewport.Scale(Scale());
  return rect_in_viewport;
}

gfx::Rect VisualViewport::RootFrameToViewport(
    const gfx::Rect& rect_in_root_frame) const {
  // FIXME: How to snap to pixels?
  return ToEnclosingRect(RootFrameToViewport(gfx::RectF(rect_in_root_frame)));
}

gfx::PointF VisualViewport::ViewportToRootFrame(
    const gfx::PointF& point_in_viewport) const {
  gfx::PointF point_in_root_frame = point_in_viewport;
  point_in_root_frame.Scale(1 / Scale());
  point_in_root_frame += GetScrollOffset();
  return point_in_root_frame;
}

gfx::PointF VisualViewport::RootFrameToViewport(
    const gfx::PointF& point_in_root_frame) const {
  gfx::PointF point_in_viewport = point_in_root_frame;
  point_in_viewport -= GetScrollOffset();
  point_in_viewport.Scale(Scale());
  return point_in_viewport;
}

gfx::Point VisualViewport::ViewportToRootFrame(
    const gfx::Point& point_in_viewport) const {
  // FIXME: How to snap to pixels?
  return gfx::ToFlooredPoint(
      ViewportToRootFrame(gfx::PointF(point_in_viewport)));
}

gfx::Point VisualViewport::RootFrameToViewport(
    const gfx::Point& point_in_root_frame) const {
  // FIXME: How to snap to pixels?
  return gfx::ToFlooredPoint(
      RootFrameToViewport(gfx::PointF(point_in_root_frame)));
}

bool VisualViewport::ShouldDisableDesktopWorkarounds() const {
  DCHECK(IsActiveViewport());

  LocalFrameView* frame_view = LocalMainFrame().View();
  if (!frame_view)
    return false;

  if (!LocalMainFrame().GetSettings()->GetViewportEnabled())
    return false;

  // A document is considered adapted to small screen UAs if one of these holds:
  // 1. The author specified viewport has a constrained width that is equal to
  //    the initial viewport width.
  // 2. The author has disabled viewport zoom.
  const PageScaleConstraints& constraints =
      GetPage().GetPageScaleConstraintsSet().PageDefinedConstraints();

  return frame_view->GetLayoutSize().width() == size_.width() ||
         (constraints.minimum_scale == constraints.maximum_scale &&
          constraints.minimum_scale != -1);
}

cc::AnimationHost* VisualViewport::GetCompositorAnimationHost() const {
  DCHECK(IsActiveViewport());
  DCHECK(GetChromeClient());
  return GetChromeClient()->GetCompositorAnimationHost(LocalMainFrame());
}

cc::AnimationTimeline* VisualViewport::GetCompositorAnimationTimeline() const {
  DCHECK(IsActiveViewport());
  DCHECK(GetChromeClient());
  return GetChromeClient()->GetScrollAnimationTimeline(LocalMainFrame());
}

void VisualViewport::NotifyRootFrameViewport() const {
  DCHECK(IsActiveViewport());

  if (!GetRootFrameViewport())
    return;

  GetRootFrameViewport()->DidUpdateVisualViewport();
}

ScrollbarTheme& VisualViewport::GetPageScrollbarTheme() const {
  return GetPage().GetScrollbarTheme();
}

PaintArtifactCompositor* VisualViewport::GetPaintArtifactCompositor() const {
  DCHECK(IsActiveViewport());

  LocalFrameView* frame_view = LocalMainFrame().View();
  if (!frame_view)
    return nullptr;

  return frame_view->GetPaintArtifactCompositor();
}

std::unique_ptr<TracedValue> VisualViewport::ViewportToTracedValue() const {
  auto value = std::make_unique<TracedValue>();
  gfx::Rect viewport = VisibleContentRect();
  value->SetInteger("x", ClampTo<int>(roundf(viewport.x())));
  value->SetInteger("y", ClampTo<int>(roundf(viewport.y())));
  value->SetInteger("width", ClampTo<int>(roundf(viewport.width())));
  value->SetInteger("height", ClampTo<int>(roundf(viewport.height())));
  value->SetString("frameID",
                   IdentifiersFactory::FrameId(GetPage().MainFrame()));
  value->SetBoolean("isActive", IsActiveViewport());
  return value;
}

void VisualViewport::DisposeImpl() {
  scroll_layer_.reset();
  scrollbar_layer_horizontal_.reset();
  scrollbar_layer_vertical_.reset();
  device_emulation_transform_node_ = nullptr;
  overscroll_elasticity_transform_node_ = nullptr;
  page_scale_node_ = nullptr;
  scroll_translation_node_ = nullptr;
  scroll_node_ = nullptr;
  horizontal_scrollbar_effect_node_ = nullptr;
  vertical_scrollbar_effect_node_ = nullptr;
}

void VisualViewport::Paint(GraphicsContext& context) const {
  if (!IsActiveViewport())
    return;

  // TODO(crbug.com/1015625): Avoid scroll_layer_.
  if (scroll_layer_) {
    PropertyTreeStateOrAlias state(parent_property_tree_state_);
    state.SetTransform(*scroll_translation_node_);
    DEFINE_STATIC_DISPLAY_ITEM_CLIENT(client, "Inner Viewport Scroll Layer");
    RecordForeignLayer(context, *client,
                       DisplayItem::kForeignLayerViewportScroll, scroll_layer_,
                       gfx::Point(), &state);
  }

  if (scrollbar_layer_horizontal_) {
    PropertyTreeStateOrAlias state(parent_property_tree_state_);
    state.SetEffect(*horizontal_scrollbar_effect_node_);
    DEFINE_STATIC_DISPLAY_ITEM_CLIENT(client,
                                      "Inner Viewport Horizontal Scrollbar");
    RecordForeignLayer(
        context, *client, DisplayItem::kForeignLayerViewportScrollbar,
        scrollbar_layer_horizontal_,
        gfx::Point(0, size_.height() - ScrollbarThickness()), &state);
  }

  if (scrollbar_layer_vertical_) {
    PropertyTreeStateOrAlias state(parent_property_tree_state_);
    state.SetEffect(*vertical_scrollbar_effect_node_);
    DEFINE_STATIC_DISPLAY_ITEM_CLIENT(client,
                                      "Inner Viewport Vertical Scrollbar");
    RecordForeignLayer(
        context, *client, DisplayItem::kForeignLayerViewportScrollbar,
        scrollbar_layer_vertical_,
        gfx::Point(size_.width() - ScrollbarThickness(), 0), &state);
  }
}

void VisualViewport::UsedColorSchemeChanged() {
  DCHECK(IsActiveViewport());
  // The scrollbar overlay color theme depends on the used color scheme.
  RecalculateOverlayScrollbarColorScheme();
}

void VisualViewport::ScrollbarColorChanged() {
  DCHECK(IsActiveViewport());
  if (scrollbar_layer_horizontal_) {
    DCHECK(scrollbar_layer_vertical_);
    UpdateScrollbarColor(*scrollbar_layer_horizontal_);
    UpdateScrollbarColor(*scrollbar_layer_vertical_);
  }
}

void VisualViewport::UpdateScrollbarColor(cc::SolidColorScrollbarLayer& layer) {
  auto& theme = ScrollbarThemeOverlayMobile::GetInstance();
  layer.SetColor(
      CSSScrollbarThumbColor().value_or(theme.DefaultColor()).toSkColor4f());
}

}  // namespace blink
```