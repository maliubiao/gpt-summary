Response:
The user wants a summary of the functionality of the provided C++ code snippet from `blink/renderer/core/dom/element.cc`. I need to analyze the code and identify the purpose of each function. Furthermore, I need to connect these functionalities to concepts in JavaScript, HTML, and CSS, providing examples. I also need to consider potential user errors and how they might lead to this code being executed. Finally, I need to provide a concise summary of the overall functionality of this specific part of the `Element.cc` file, remembering that this is part 3 of 13.

Here's a breakdown of the code's functions and their implications:

1. **`offsetParent()`**:  Determines the offset parent of an element, used for calculating offsets. Relates to JavaScript's `element.offsetParent`.
2. **`clientLeft()`/`clientTop()`**: Get the border widths on the left/top. Relates to JavaScript's `element.clientLeft`/`element.clientTop`. These trigger layout updates.
3. **`ClientLeftNoLayout()`/`ClientTopNoLayout()`**: Get the client left/top without triggering layout.
4. **`LastRememberedSizeChanged()`**: Handles updates to the last remembered size of an element, likely for `ResizeObserver`.
5. **`ShouldUpdateLastRememberedBlockSize()`/`ShouldUpdateLastRememberedInlineSize()`**: Determine if the last remembered block/inline size should be updated, considering `contain-intrinsic-size` CSS property.
6. **`SetLastRememberedInlineSize()`/`SetLastRememberedBlockSize()`**: Set the last remembered inline/block size.
7. **`LastRememberedInlineSize()`/`LastRememberedBlockSize()`**: Get the last remembered inline/block size.
8. **`IsViewportScrollElement()`**: Checks if the element is the viewport scrolling element (document or body in quirks mode).
9. **`RecordScrollbarSizeForStudy()`**: Records scrollbar sizes for metrics, considering overlay scrollbars.
10. **`clientWidth()`/`clientHeight()`**: Get the inner width/height of an element, excluding borders and scrollbars. Relates to JavaScript's `element.clientWidth`/`element.clientHeight`. Handles special cases for the viewport and triggers layout updates.
11. **`currentCSSZoom()`**: Gets the current CSS zoom level. Relates to the CSS `zoom` property.
12. **`GetLayoutBoxForScrolling()`**:  Gets the layout box for scrolling.
13. **`scrollLeft()`/`scrollTop()`**: Get the current horizontal/vertical scroll position. Relates to JavaScript's `element.scrollLeft`/`element.scrollTop`.
14. **`setScrollLeft()`/`setScrollTop()`**: Set the horizontal/vertical scroll position. Relates to JavaScript's `element.scrollLeft = value`/`element.scrollTop = value`. Triggers layout updates.
15. **`scrollWidth()`/`scrollHeight()`**: Get the total width/height of the scrollable content. Relates to JavaScript's `element.scrollWidth`/`element.scrollHeight`. Triggers layout updates.
16. **`scrollBy()`**: Scrolls the element by a specified amount. Relates to JavaScript's `element.scrollBy()`. Triggers layout updates.
17. **`scrollTo()`**: Scrolls the element to a specific position. Relates to JavaScript's `element.scrollTo()`. Triggers layout updates.
18. **`ScrollLayoutBoxBy()`/`ScrollLayoutBoxTo()`**:  Internal methods for scrolling layout boxes.
19. **`ScrollFrameBy()`/`ScrollFrameTo()`**: Internal methods for scrolling the frame.
20. **`BoundsInWidget()`**: Gets the element's bounding box in the browser window coordinates.
21. **`OutlineRectsInWidget()`**: Gets the rectangles representing the element's outline in widget coordinates.
22. **`VisibleBoundsInLocalRoot()`**: Gets the visible bounds of the element within the local root.
23. **`ClientQuads()`**: Gets the client quads of the element, which are rectangles representing its content.
24. **`getClientRects()`**:  Gets a list of DOMRects representing the client rectangles. Relates to JavaScript's `element.getClientRects()`. Triggers layout updates.
25. **`GetBoundingClientRectNoLifecycleUpdateNoAdjustment()`**: Gets the bounding client rectangle without triggering a full lifecycle update or adjustments.

Based on the functions, this section of `element.cc` primarily deals with **element geometry and scrolling**. It provides the underlying implementation for various JavaScript properties and methods related to an element's position, size, and scrolling behavior.
这是 `blink/renderer/core/dom/element.cc` 文件的第 3 部分，主要负责实现 `Element` 类中关于 **元素几何属性和滚动** 的相关功能。具体来说，它涵盖了以下几个方面的功能：

**1. 获取元素的偏移属性 (Offset Properties):**

*   **`offsetParent()`**:  确定元素的偏移父元素。
    *   **与 JavaScript 的关系:**  对应 JavaScript 中 `element.offsetParent` 属性。
    *   **举例说明:**
        *   **HTML:**
            ```html
            <div style="position: relative;">
              <div id="child" style="position: absolute;"></div>
            </div>
            ```
        *   **JavaScript:**
            ```javascript
            const child = document.getElementById('child');
            console.log(child.offsetParent); // 输出外层的 div 元素
            ```
    *   **假设输入与输出:**
        *   **假设输入:** 一个设置了 `position: absolute` 的子元素。
        *   **输出:**  该子元素最近的设置了 `position: relative`, `position: absolute` 或 `position: fixed` 的祖先元素。

**2. 获取元素的客户端区域 (Client Region):**

*   **`clientLeft()` 和 `clientTop()`**: 获取元素左边框和上边框的宽度。
    *   **与 JavaScript 的关系:** 对应 JavaScript 中 `element.clientLeft` 和 `element.clientTop` 属性。
    *   **举例说明:**
        *   **HTML:**
            ```html
            <div id="box" style="border: 5px solid black;">内容</div>
            ```
        *   **JavaScript:**
            ```javascript
            const box = document.getElementById('box');
            console.log(box.clientLeft); // 输出 5
            console.log(box.clientTop);  // 输出 5
            ```
    *   **假设输入与输出:**
        *   **假设输入:** 一个设置了边框的 div 元素。
        *   **输出:**  左边框和上边框的像素宽度。
*   **`ClientLeftNoLayout()` 和 `ClientTopNoLayout()`**:  在不强制布局的情况下，获取元素的左边距和上边距（实际上是左边框和上边框）。这些方法通常在已经完成布局的情况下使用，避免重复布局计算。

**3. 记住元素的大小 (Remembered Size):**

*   **`LastRememberedSizeChanged(ResizeObserverSize* size)`**:  当观察到元素大小改变时，更新最后记住的块大小和内联大小。这与 `ResizeObserver` API 相关。
    *   **与 JavaScript 的关系:**  与 JavaScript 的 `ResizeObserver` API 的回调函数相关。
    *   **举例说明:**  当使用 `ResizeObserver` 监听元素大小变化时，浏览器引擎内部会调用此方法来更新记录的尺寸。
*   **`ShouldUpdateLastRememberedBlockSize()` 和 `ShouldUpdateLastRememberedInlineSize()`**:  判断是否应该更新最后记住的块大小和内联大小。这与 CSS 的 `contain-intrinsic-size` 属性有关，当该属性设置为 `auto` 时，可能需要记住元素的大小。
    *   **与 CSS 的关系:**  与 CSS 的 `contain-intrinsic-size` 属性相关。
    *   **假设输入与输出:**
        *   **假设输入:** 一个元素的样式包含 `contain-intrinsic-size: auto;`。
        *   **输出:**  如果写入模式是水平的，`ShouldUpdateLastRememberedHeight()` 返回 `true`，否则 `ShouldUpdateLastRememberedWidth()` 返回 `true`。
*   **`SetLastRememberedInlineSize(std::optional<LayoutUnit> size)` 和 `SetLastRememberedBlockSize(std::optional<LayoutUnit> size)`**:  设置最后记住的内联大小和块大小。
*   **`LastRememberedInlineSize()` 和 `LastRememberedBlockSize()`**:  获取最后记住的内联大小和块大小。

**4. 判断是否为视口滚动元素 (Viewport Scroll Element):**

*   **`IsViewportScrollElement()`**:  判断当前元素是否是视口的滚动元素（通常是 `<html>` 元素，在 Quirks 模式下可能是 `<body>` 元素）。
    *   **与 HTML 的关系:**  与 HTML 文档的结构和是否处于 Quirks 模式有关。
    *   **假设输入与输出:**
        *   **假设输入:**  当前的元素是 `<html>` 元素，且文档处于标准模式。
        *   **输出:** `true`。
        *   **假设输入:**  当前的元素是 `<body>` 元素，且文档处于 Quirks 模式。
        *   **输出:** `true`。

**5. 记录滚动条大小 (Record Scrollbar Size):**

*   **`RecordScrollbarSizeForStudy(int measurement, bool is_width, bool is_offset)`**:  用于收集滚动条大小的统计数据，用于研究和优化。
    *   **用户操作是如何一步步的到达这里 (调试线索):** 用户可能正在访问一个包含滚动条的网页。当浏览器渲染页面并计算布局时，如果启用了相关的实验性特性或统计功能，就会触发此代码的执行。`measurement` 参数可能来自于 `offsetWidth`/`offsetHeight` 或 `clientWidth`/`clientHeight` 的计算。

**6. 获取元素的客户端宽度和高度 (Client Width and Height):**

*   **`clientWidth()` 和 `clientHeight()`**: 获取元素的内部宽度和高度，不包括边框和滚动条。
    *   **与 JavaScript 的关系:** 对应 JavaScript 中 `element.clientWidth` 和 `element.clientHeight` 属性。
    *   **举例说明:**
        *   **HTML:**
            ```html
            <div id="content" style="width: 200px; height: 100px; padding: 10px; border: 5px solid black;">内容</div>
            ```
        *   **JavaScript:**
            ```javascript
            const content = document.getElementById('content');
            console.log(content.clientWidth);  // 输出 210 (200 + 10 + 10)
            console.log(content.clientHeight); // 输出 110 (100 + 10 + 10)
            ```
    *   **假设输入与输出:**
        *   **假设输入:** 一个设置了宽度、高度、内边距和边框的 div 元素。
        *   **输出:**  不包含边框的内部宽度和高度。

**7. 获取元素的当前 CSS 缩放 (Current CSS Zoom):**

*   **`currentCSSZoom()`**: 获取应用于元素的当前 CSS 缩放级别。
    *   **与 CSS 的关系:**  与 CSS 的 `zoom` 属性相关。
    *   **与 JavaScript 的关系:**  虽然没有直接对应的 JavaScript 属性，但可以通过计算间接获得。

**8. 获取用于滚动的布局盒子 (Layout Box for Scrolling):**

*   **`GetLayoutBoxForScrolling()`**: 获取用于滚动的布局盒子对象。

**9. 获取和设置元素的滚动位置 (Scroll Position):**

*   **`scrollLeft()` 和 `scrollTop()`**: 获取元素的水平和垂直滚动位置。
    *   **与 JavaScript 的关系:** 对应 JavaScript 中 `element.scrollLeft` 和 `element.scrollTop` 属性。
    *   **举例说明:**
        *   **HTML:**
            ```html
            <div id="scrollable" style="width: 100px; height: 100px; overflow: scroll;">
              <div style="width: 200px; height: 200px;">内容很长</div>
            </div>
            ```
        *   **JavaScript:**
            ```javascript
            const scrollable = document.getElementById('scrollable');
            scrollable.scrollLeft = 50;
            console.log(scrollable.scrollLeft); // 输出 50
            ```
    *   **用户或编程常见的使用错误:**  尝试在没有 `overflow: scroll` 或 `overflow: auto` 样式的元素上设置滚动位置是无效的。
*   **`setScrollLeft(double new_left)` 和 `setScrollTop(double new_top)`**: 设置元素的水平和垂直滚动位置。
    *   **与 JavaScript 的关系:** 对应 JavaScript 中 `element.scrollLeft = value` 和 `element.scrollTop = value`。

**10. 获取元素的滚动宽度和高度 (Scroll Width and Height):**

*   **`scrollWidth()` 和 `scrollHeight()`**: 获取元素的总滚动宽度和高度，包括不可见的部分。
    *   **与 JavaScript 的关系:** 对应 JavaScript 中 `element.scrollWidth` 和 `element.scrollHeight` 属性。
    *   **举例说明:**  在上一个滚动示例中，`scrollable.scrollWidth` 将输出 200，`scrollable.scrollHeight` 将输出 200。

**11. 滚动元素 (Scroll Element):**

*   **`scrollBy(double x, double y)` 和 `scrollBy(const ScrollToOptions* scroll_to_options)`**:  相对于当前滚动位置滚动元素。
    *   **与 JavaScript 的关系:** 对应 JavaScript 中 `element.scrollBy()` 方法。
    *   **举例说明:**
        ```javascript
        scrollable.scrollBy({ left: 10, top: -5, behavior: 'smooth' });
        ```
*   **`scrollTo(double x, double y)` 和 `scrollTo(const ScrollToOptions* scroll_to_options)`**:  滚动元素到指定的绝对位置。
    *   **与 JavaScript 的关系:** 对应 JavaScript 中 `element.scrollTo()` 方法。
    *   **举例说明:**
        ```javascript
        scrollable.scrollTo({ top: 100, left: 0 });
        ```
*   **`ScrollLayoutBoxBy(const ScrollToOptions* scroll_to_options)` 和 `ScrollLayoutBoxTo(const ScrollToOptions* scroll_to_options)`**:  内部方法，用于滚动布局盒子。
*   **`ScrollFrameBy(const ScrollToOptions* scroll_to_options)` 和 `ScrollFrameTo(const ScrollToOptions* scroll_to_options)`**: 内部方法，用于滚动框架（Frame）。

**12. 获取元素在视口中的边界 (Bounds in Widget):**

*   **`BoundsInWidget()`**: 获取元素在浏览器窗口坐标系中的边界矩形。
    *   **与 JavaScript 的关系:**  可以用于实现一些需要元素在视口中位置的功能。

**13. 获取元素的外轮廓矩形 (Outline Rects in Widget):**

*   **`OutlineRectsInWidget(DocumentUpdateReason reason)`**: 获取元素外轮廓在浏览器窗口坐标系中的矩形。这与 CSS 的 `outline` 属性相关。
    *   **与 CSS 的关系:** 与 CSS 的 `outline` 属性相关。

**14. 获取元素在本地根的可见边界 (Visible Bounds in Local Root):**

*   **`VisibleBoundsInLocalRoot()`**: 获取元素在本地根（通常是文档的根元素）的可见边界。

**15. 获取元素的客户端四边形 (Client Quads):**

*   **`ClientQuads(Vector<gfx::QuadF>& quads)`**: 获取元素的客户端四边形，用于描述元素内容区域的形状。

**16. 获取元素的客户端矩形列表 (Client Rects):**

*   **`getClientRects()`**: 获取一个 `DOMRectList` 对象，其中包含描述元素所有内容框的矩形集合。
    *   **与 JavaScript 的关系:** 对应 JavaScript 中 `element.getClientRects()` 方法。
    *   **举例说明:**
        ```javascript
        const rects = element.getClientRects();
        for (let i = 0; i < rects.length; i++) {
          console.log(rects[i].top, rects[i].right, rects[i].bottom, rects[i].left);
        }
        ```

**17. 获取元素的边界客户端矩形 (Bounding Client Rect):**

*   **`GetBoundingClientRectNoLifecycleUpdateNoAdjustment()`**:  获取元素的边界客户端矩形，但不执行完整的生命周期更新或调整。这个方法通常用于性能敏感的场景。

**用户或编程常见的使用错误举例:**

*   **在没有滚动条的元素上设置 `scrollLeft` 或 `scrollTop`:**  如果元素的 `overflow` 属性不是 `scroll` 或 `auto`，设置这些属性通常不会有效果。
*   **在布局尚未完成时访问几何属性:**  在某些情况下，如果 JavaScript 代码在布局计算完成之前尝试访问如 `offsetWidth`、`clientHeight` 等属性，可能会得到不正确的值。Blink 引擎会尝试在访问这些属性时触发布局，但这可能会影响性能。
*   **不理解 `offsetParent` 的工作原理:**  `offsetParent` 并不总是元素的直接父元素，它取决于元素的 `position` 属性以及其祖先元素的 `position` 属性。

**归纳一下它的功能:**

这部分 `element.cc` 代码主要负责实现 `Element` 类的核心几何属性和滚动相关的底层逻辑。它提供了获取和设置元素的位置、大小、边框、滚动位置和滚动范围的方法，并与相应的 JavaScript 属性和方法相对应。此外，它还涉及一些与布局和渲染相关的内部机制，例如记住元素大小和记录滚动条大小。 这些功能是构建和操作网页元素的基础，直接影响着网页的布局、渲染和用户交互体验。

### 提示词
```
这是目录为blink/renderer/core/dom/element.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共13部分，请归纳一下它的功能
```

### 源代码
```cpp
eReason::kJavaScript);

  LayoutObject* layout_object = GetLayoutObject();
  return layout_object ? layout_object->OffsetParent() : nullptr;
}

int Element::clientLeft() {
  GetDocument().UpdateStyleAndLayoutForNode(this,
                                            DocumentUpdateReason::kJavaScript);
  return ClientLeftNoLayout();
}

int Element::clientTop() {
  GetDocument().UpdateStyleAndLayoutForNode(this,
                                            DocumentUpdateReason::kJavaScript);
  return ClientTopNoLayout();
}

int Element::ClientLeftNoLayout() const {
  if (const auto* layout_object = GetLayoutBox()) {
    return AdjustForAbsoluteZoom::AdjustLayoutUnit(layout_object->ClientLeft(),
                                                   layout_object->StyleRef())
        .Round();
  }
  return 0;
}

int Element::ClientTopNoLayout() const {
  if (const auto* layout_object = GetLayoutBox()) {
    return AdjustForAbsoluteZoom::AdjustLayoutUnit(layout_object->ClientTop(),
                                                   layout_object->StyleRef())
        .Round();
  }
  return 0;
}

void Element::LastRememberedSizeChanged(ResizeObserverSize* size) {
  if (ShouldUpdateLastRememberedBlockSize()) {
    SetLastRememberedBlockSize(LayoutUnit(size->blockSize()));
  }
  if (ShouldUpdateLastRememberedInlineSize()) {
    SetLastRememberedInlineSize(LayoutUnit(size->inlineSize()));
  }
}

bool Element::ShouldUpdateLastRememberedBlockSize() const {
  const auto* style = GetComputedStyle();
  if (!style) {
    return false;
  }

  return style->IsHorizontalWritingMode()
             ? style->ContainIntrinsicHeight().HasAuto()
             : style->ContainIntrinsicWidth().HasAuto();
}

bool Element::ShouldUpdateLastRememberedInlineSize() const {
  const auto* style = GetComputedStyle();
  if (!style) {
    return false;
  }

  return style->IsHorizontalWritingMode()
             ? style->ContainIntrinsicWidth().HasAuto()
             : style->ContainIntrinsicHeight().HasAuto();
}

void Element::SetLastRememberedInlineSize(std::optional<LayoutUnit> size) {
  if (ElementRareDataVector* data = GetElementRareData()) {
    data->SetLastRememberedInlineSize(size);
  } else if (size) {
    EnsureElementRareData().SetLastRememberedInlineSize(size);
  }
}

void Element::SetLastRememberedBlockSize(std::optional<LayoutUnit> size) {
  if (ElementRareDataVector* data = GetElementRareData()) {
    data->SetLastRememberedBlockSize(size);
  } else if (size) {
    EnsureElementRareData().SetLastRememberedBlockSize(size);
  }
}

std::optional<LayoutUnit> Element::LastRememberedInlineSize() const {
  if (const ElementRareDataVector* data = GetElementRareData()) {
    return data->LastRememberedInlineSize();
  }
  return std::nullopt;
}

std::optional<LayoutUnit> Element::LastRememberedBlockSize() const {
  if (const ElementRareDataVector* data = GetElementRareData()) {
    return data->LastRememberedBlockSize();
  }
  return std::nullopt;
}

bool Element::IsViewportScrollElement() {
  auto& document = GetDocument();
  bool quirks_mode = document.InQuirksMode();
  return (!quirks_mode && document.documentElement() == this) ||
         (quirks_mode && IsHTMLElement() && document.body() == this);
}

void Element::RecordScrollbarSizeForStudy(int measurement,
                                          bool is_width,
                                          bool is_offset) {
  if (!IdentifiabilityStudySettings::Get()->ShouldSampleType(
          IdentifiableSurface::Type::kScrollbarSize) ||
      (!is_offset && !IsViewportScrollElement())) {
    return;
  }

  // Check for presence of a scrollbar.
  PaintLayerScrollableArea* area;
  if (IsViewportScrollElement()) {
    auto* view = GetDocument().View();
    if (!view) {
      return;
    }
    area = view->LayoutViewport();
  } else {
    auto* layout = GetLayoutBox();
    if (!layout) {
      return;
    }
    area = layout->GetScrollableArea();
  }
  if (!area || area->HasOverlayOverflowControls()) {
    return;
  }

  Scrollbar* scrollbar =
      is_width ? area->VerticalScrollbar() : area->HorizontalScrollbar();
  // We intentionally exclude platform overlay scrollbars since their size
  // cannot be detected in JavaScript using the methods below.
  if (!scrollbar) {
    return;
  }

  IdentifiableSurface::ScrollbarSurface surface;
  int scrollbar_size;

  // There are two common ways to detect the size of a scrollbar in a DOM
  // window. They are:
  // 1. Compute the difference of the window.inner[Width|Height] and the
  //    corresponding document.scrollingElement.offset[Width|Height].
  // 2. Any HTML element that insets the layout to fit a scrollbar, so it is
  //    measurable by a JavaScript program on a site.
  if (IsViewportScrollElement()) {
    LocalDOMWindow* dom_window = GetDocument().domWindow();
    scrollbar_size =
        (is_width ? dom_window->innerWidth() : dom_window->innerHeight()) -
        measurement;
    surface =
        is_width
            ? IdentifiableSurface::ScrollbarSurface::kScrollingElementWidth
            : IdentifiableSurface::ScrollbarSurface::kScrollingElementHeight;
  } else {
    scrollbar_size = measurement - (is_width ? clientWidth() : clientHeight());
    surface = is_width
                  ? IdentifiableSurface::ScrollbarSurface::kElemScrollbarWidth
                  : IdentifiableSurface::ScrollbarSurface::kElemScrollbarHeight;
  }

  blink::IdentifiabilityMetricBuilder(GetDocument().UkmSourceID())
      .Add(blink::IdentifiableSurface::FromTypeAndToken(
               blink::IdentifiableSurface::Type::kScrollbarSize, surface),
           scrollbar_size)
      .Record(GetDocument().UkmRecorder());
}

int Element::clientWidth() {
  // When in strict mode, clientWidth for the document element should return the
  // width of the containing frame.
  // When in quirks mode, clientWidth for the body element should return the
  // width of the containing frame.
  if (IsViewportScrollElement()) {
    auto* layout_view = GetDocument().GetLayoutView();
    if (layout_view) {
      // TODO(crbug.com/740879): Use per-page overlay scrollbar settings.
      if (!ScrollbarThemeSettings::OverlayScrollbarsEnabled() ||
          !GetDocument().GetFrame()->IsLocalRoot()) {
        GetDocument().UpdateStyleAndLayoutForNode(
            this, DocumentUpdateReason::kJavaScript);
      }
      if (GetDocument().GetPage()->GetSettings().GetForceZeroLayoutHeight()) {
        // OverflowClipRect() may return infinite along a particular axis if
        // |layout_view| is not a scroll-container.
        DCHECK(layout_view->IsScrollContainer());
        int result =
            AdjustForAbsoluteZoom::AdjustLayoutUnit(
                layout_view->OverflowClipRect(PhysicalOffset()).Width(),
                layout_view->StyleRef())
                .Round();
        RecordScrollbarSizeForStudy(result, /* is_width= */ true,
                                    /* is_offset= */ false);
        return result;
      }
      int result = AdjustForAbsoluteZoom::AdjustInt(
          layout_view->GetLayoutSize().width(), layout_view->StyleRef());
      RecordScrollbarSizeForStudy(result, /* is_width= */ true,
                                  /* is_offset= */ false);
      return result;
    }
  }

  GetDocument().UpdateStyleAndLayoutForNode(this,
                                            DocumentUpdateReason::kJavaScript);

  int result = 0;
  if (const auto* layout_object = GetLayoutBox()) {
    result = AdjustForAbsoluteZoom::AdjustLayoutUnit(
                 layout_object->ClientWidthWithTableSpecialBehavior(),
                 layout_object->StyleRef())
                 .Round();
    RecordScrollbarSizeForStudy(result, /* is_width= */ true,
                                /* is_offset= */ false);
  }
  return result;
}

int Element::clientHeight() {
  // When in strict mode, clientHeight for the document element should return
  // the height of the containing frame.
  // When in quirks mode, clientHeight for the body element should return the
  // height of the containing frame.
  if (IsViewportScrollElement()) {
    auto* layout_view = GetDocument().GetLayoutView();
    if (layout_view) {
      // TODO(crbug.com/740879): Use per-page overlay scrollbar settings.
      if (!ScrollbarThemeSettings::OverlayScrollbarsEnabled() ||
          !GetDocument().GetFrame()->IsLocalRoot()) {
        GetDocument().UpdateStyleAndLayoutForNode(
            this, DocumentUpdateReason::kJavaScript);
      }
      if (GetDocument().GetPage()->GetSettings().GetForceZeroLayoutHeight()) {
        // OverflowClipRect() may return infinite along a particular axis if
        // |layout_view| is not a scroll-container.
        DCHECK(layout_view->IsScrollContainer());
        int result =
            AdjustForAbsoluteZoom::AdjustLayoutUnit(
                layout_view->OverflowClipRect(PhysicalOffset()).Height(),
                layout_view->StyleRef())
                .Round();
        RecordScrollbarSizeForStudy(result, /* is_width= */ false,
                                    /* is_offset= */ false);
        return result;
      }
      int result = AdjustForAbsoluteZoom::AdjustInt(
          layout_view->GetLayoutSize().height(), layout_view->StyleRef());
      RecordScrollbarSizeForStudy(result, /* is_width= */ false,
                                  /* is_offset= */ false);
      return result;
    }
  }

  GetDocument().UpdateStyleAndLayoutForNode(this,
                                            DocumentUpdateReason::kJavaScript);

  int result = 0;
  if (const auto* layout_object = GetLayoutBox()) {
    result = AdjustForAbsoluteZoom::AdjustLayoutUnit(
                 layout_object->ClientHeightWithTableSpecialBehavior(),
                 layout_object->StyleRef())
                 .Round();
    RecordScrollbarSizeForStudy(result, /* is_width= */ false,
                                /* is_offset= */ false);
  }
  return result;
}

double Element::currentCSSZoom() {
  GetDocument().UpdateStyleAndLayoutTreeForElement(
      this, DocumentUpdateReason::kComputedStyle);
  if (const auto* layout_object = GetLayoutObject()) {
    return layout_object->StyleRef().EffectiveZoom() /
           GetDocument().GetStyleEngine().GetStyleResolver().InitialZoom();
  }
  return 1.0;
}

LayoutBox* Element::GetLayoutBoxForScrolling() const {
  LayoutBox* box = GetLayoutBox();
  if (!box || !box->IsScrollContainer()) {
    return nullptr;
  }
  return box;
}

double Element::scrollLeft() {
  if (!InActiveDocument()) {
    return 0;
  }

  // TODO(crbug.com/1499981): This should be removed once synchronized scrolling
  // impact is understood.
  SyncScrollAttemptHeuristic::DidAccessScrollOffset();

  GetDocument().UpdateStyleAndLayoutForNode(this,
                                            DocumentUpdateReason::kJavaScript);

  if (GetDocument().ScrollingElementNoLayout() == this) {
    if (GetDocument().domWindow()) {
      return GetDocument().domWindow()->scrollX();
    }
    return 0;
  }

  LayoutBox* box = GetLayoutBoxForScrolling();
  if (!box) {
    return 0;
  }
  if (PaintLayerScrollableArea* scrollable_area = box->GetScrollableArea()) {
    DCHECK(GetLayoutBox());

    if (HasLeftwardDirection(*this)) {
      UseCounter::Count(
          GetDocument(),
          WebFeature::
              kElementWithLeftwardOrUpwardOverflowDirection_ScrollLeftOrTop);
    }

    return AdjustForAbsoluteZoom::AdjustScroll(
        scrollable_area->GetWebExposedScrollOffset().x(), *GetLayoutBox());
  }

  return 0;
}

double Element::scrollTop() {
  if (!InActiveDocument()) {
    return 0;
  }

  // TODO(crbug.com/1499981): This should be removed once synchronized scrolling
  // impact is understood.
  SyncScrollAttemptHeuristic::DidAccessScrollOffset();

  GetDocument().UpdateStyleAndLayoutForNode(this,
                                            DocumentUpdateReason::kJavaScript);

  if (GetDocument().ScrollingElementNoLayout() == this) {
    if (GetDocument().domWindow()) {
      return GetDocument().domWindow()->scrollY();
    }
    return 0;
  }

  // Don't disclose scroll position in preview state. See crbug.com/1261689.
  auto* select_element = DynamicTo<HTMLSelectElement>(this);
  if (select_element && !select_element->UsesMenuList() &&
      select_element->IsPreviewed()) {
    return 0;
  }

  LayoutBox* box = GetLayoutBoxForScrolling();
  if (!box) {
    return 0;
  }
  if (PaintLayerScrollableArea* scrollable_area = box->GetScrollableArea()) {
    DCHECK(GetLayoutBox());

    if (HasUpwardDirection(*this)) {
      UseCounter::Count(
          GetDocument(),
          WebFeature::
              kElementWithLeftwardOrUpwardOverflowDirection_ScrollLeftOrTop);
    }

    return AdjustForAbsoluteZoom::AdjustScroll(
        scrollable_area->GetWebExposedScrollOffset().y(), *GetLayoutBox());
  }

  return 0;
}

void Element::setScrollLeft(double new_left) {
  if (!InActiveDocument()) {
    return;
  }

  // TODO(crbug.com/1499981): This should be removed once synchronized scrolling
  // impact is understood.
  SyncScrollAttemptHeuristic::DidSetScrollOffset();

  GetDocument().UpdateStyleAndLayoutForNode(this,
                                            DocumentUpdateReason::kJavaScript);

  new_left = ScrollableArea::NormalizeNonFiniteScroll(new_left);

  if (GetDocument().ScrollingElementNoLayout() == this) {
    if (LocalDOMWindow* window = GetDocument().domWindow()) {
      ScrollToOptions* options = ScrollToOptions::Create();
      options->setLeft(new_left);
      window->scrollTo(options);
    }
    return;
  }

  LayoutBox* box = GetLayoutBoxForScrolling();
  if (!box) {
    return;
  }
  if (PaintLayerScrollableArea* scrollable_area = box->GetScrollableArea()) {
    if (HasLeftwardDirection(*this)) {
      UseCounter::Count(
          GetDocument(),
          WebFeature::
              kElementWithLeftwardOrUpwardOverflowDirection_ScrollLeftOrTop);
      if (new_left > 0) {
        UseCounter::Count(
            GetDocument(),
            WebFeature::
                kElementWithLeftwardOrUpwardOverflowDirection_ScrollLeftOrTopSetPositive);
      }
    }

    ScrollOffset end_offset(new_left * box->Style()->EffectiveZoom(),
                            scrollable_area->GetScrollOffset().y());
    std::unique_ptr<cc::SnapSelectionStrategy> strategy =
        cc::SnapSelectionStrategy::CreateForEndPosition(
            scrollable_area->ScrollOffsetToPosition(end_offset), true, false);
    std::optional<gfx::PointF> snap_point =
        scrollable_area->GetSnapPositionAndSetTarget(*strategy);
    if (snap_point.has_value()) {
      end_offset = scrollable_area->ScrollPositionToOffset(snap_point.value());
    }
    scrollable_area->SetScrollOffset(end_offset,
                                     mojom::blink::ScrollType::kProgrammatic,
                                     mojom::blink::ScrollBehavior::kAuto);
  }
}

void Element::setScrollTop(double new_top) {
  if (!InActiveDocument()) {
    return;
  }

  // TODO(crbug.com/1499981): This should be removed once synchronized scrolling
  // impact is understood.
  SyncScrollAttemptHeuristic::DidSetScrollOffset();

  GetDocument().UpdateStyleAndLayoutForNode(this,
                                            DocumentUpdateReason::kJavaScript);

  new_top = ScrollableArea::NormalizeNonFiniteScroll(new_top);

  if (GetDocument().ScrollingElementNoLayout() == this) {
    if (LocalDOMWindow* window = GetDocument().domWindow()) {
      ScrollToOptions* options = ScrollToOptions::Create();
      options->setTop(new_top);
      window->scrollTo(options);
    }
    return;
  }

  LayoutBox* box = GetLayoutBoxForScrolling();
  if (!box) {
    return;
  }
  if (PaintLayerScrollableArea* scrollable_area = box->GetScrollableArea()) {
    if (HasUpwardDirection(*this)) {
      UseCounter::Count(
          GetDocument(),
          WebFeature::
              kElementWithLeftwardOrUpwardOverflowDirection_ScrollLeftOrTop);
      if (new_top > 0) {
        UseCounter::Count(
            GetDocument(),
            WebFeature::
                kElementWithLeftwardOrUpwardOverflowDirection_ScrollLeftOrTopSetPositive);
      }
    }

    ScrollOffset end_offset(scrollable_area->GetScrollOffset().x(),
                            new_top * box->Style()->EffectiveZoom());
    std::unique_ptr<cc::SnapSelectionStrategy> strategy =
        cc::SnapSelectionStrategy::CreateForEndPosition(
            scrollable_area->ScrollOffsetToPosition(end_offset), false, true);
    std::optional<gfx::PointF> snap_point =
        scrollable_area->GetSnapPositionAndSetTarget(*strategy);
    if (snap_point.has_value()) {
      end_offset = scrollable_area->ScrollPositionToOffset(snap_point.value());
    }

    scrollable_area->SetScrollOffset(end_offset,
                                     mojom::blink::ScrollType::kProgrammatic,
                                     mojom::blink::ScrollBehavior::kAuto);
  }
}

int Element::scrollWidth() {
  if (!InActiveDocument()) {
    return 0;
  }

  GetDocument().UpdateStyleAndLayoutForNode(this,
                                            DocumentUpdateReason::kJavaScript);

  if (GetDocument().ScrollingElementNoLayout() == this) {
    if (GetDocument().View()) {
      return AdjustForAbsoluteZoom::AdjustInt(
          GetDocument().View()->LayoutViewport()->ContentsSize().width(),
          GetDocument().GetFrame()->LayoutZoomFactor());
    }
    return 0;
  }

  if (LayoutBox* box = GetLayoutBox()) {
    return AdjustForAbsoluteZoom::AdjustLayoutUnit(box->ScrollWidth(), *box)
        .Round();
  }
  return 0;
}

int Element::scrollHeight() {
  if (!InActiveDocument()) {
    return 0;
  }

  GetDocument().UpdateStyleAndLayoutForNode(this,
                                            DocumentUpdateReason::kJavaScript);

  if (GetDocument().ScrollingElementNoLayout() == this) {
    if (GetDocument().View()) {
      return AdjustForAbsoluteZoom::AdjustInt(
          GetDocument().View()->LayoutViewport()->ContentsSize().height(),
          GetDocument().GetFrame()->LayoutZoomFactor());
    }
    return 0;
  }

  if (LayoutBox* box = GetLayoutBox()) {
    return AdjustForAbsoluteZoom::AdjustLayoutUnit(box->ScrollHeight(), *box)
        .Round();
  }
  return 0;
}

void Element::scrollBy(double x, double y) {
  ScrollToOptions* scroll_to_options = ScrollToOptions::Create();
  scroll_to_options->setLeft(x);
  scroll_to_options->setTop(y);
  scrollBy(scroll_to_options);
}

void Element::scrollBy(const ScrollToOptions* scroll_to_options) {
  if (!InActiveDocument()) {
    return;
  }

  // TODO(crbug.com/1499981): This should be removed once synchronized scrolling
  // impact is understood.
  SyncScrollAttemptHeuristic::DidSetScrollOffset();

  // FIXME: This should be removed once scroll updates are processed only after
  // the compositing update. See http://crbug.com/420741.
  GetDocument().UpdateStyleAndLayoutForNode(this,
                                            DocumentUpdateReason::kJavaScript);

  if (GetDocument().ScrollingElementNoLayout() == this) {
    ScrollFrameBy(scroll_to_options);
  } else {
    ScrollLayoutBoxBy(scroll_to_options);
  }
}

void Element::scrollTo(double x, double y) {
  ScrollToOptions* scroll_to_options = ScrollToOptions::Create();
  scroll_to_options->setLeft(x);
  scroll_to_options->setTop(y);
  scrollTo(scroll_to_options);
}

void Element::scrollTo(const ScrollToOptions* scroll_to_options) {
  if (!InActiveDocument()) {
    return;
  }

  // TODO(crbug.com/1499981): This should be removed once synchronized scrolling
  // impact is understood.
  SyncScrollAttemptHeuristic::DidSetScrollOffset();

  // FIXME: This should be removed once scroll updates are processed only after
  // the compositing update. See http://crbug.com/420741.
  GetDocument().UpdateStyleAndLayoutForNode(this,
                                            DocumentUpdateReason::kJavaScript);

  if (GetDocument().ScrollingElementNoLayout() == this) {
    ScrollFrameTo(scroll_to_options);
  } else {
    ScrollLayoutBoxTo(scroll_to_options);
  }
}

void Element::ScrollLayoutBoxBy(const ScrollToOptions* scroll_to_options) {
  gfx::Vector2dF displacement;
  if (scroll_to_options->hasLeft()) {
    displacement.set_x(
        ScrollableArea::NormalizeNonFiniteScroll(scroll_to_options->left()));
  }
  if (scroll_to_options->hasTop()) {
    displacement.set_y(
        ScrollableArea::NormalizeNonFiniteScroll(scroll_to_options->top()));
  }

  mojom::blink::ScrollBehavior scroll_behavior =
      ScrollableArea::V8EnumToScrollBehavior(
          scroll_to_options->behavior().AsEnum());
  LayoutBox* box = GetLayoutBoxForScrolling();
  if (!box) {
    return;
  }
  if (PaintLayerScrollableArea* scrollable_area = box->GetScrollableArea()) {
    DCHECK(box);
    gfx::PointF current_position(scrollable_area->ScrollPosition().x(),
                                 scrollable_area->ScrollPosition().y());
    displacement.Scale(box->Style()->EffectiveZoom());
    gfx::PointF new_position = current_position + displacement;

    std::unique_ptr<cc::SnapSelectionStrategy> strategy =
        cc::SnapSelectionStrategy::CreateForEndAndDirection(
            current_position, displacement,
            RuntimeEnabledFeatures::FractionalScrollOffsetsEnabled());
    new_position =
        scrollable_area->GetSnapPositionAndSetTarget(*strategy).value_or(
            new_position);
    scrollable_area->ScrollToAbsolutePosition(new_position, scroll_behavior);
  }
}

void Element::ScrollLayoutBoxTo(const ScrollToOptions* scroll_to_options) {
  mojom::blink::ScrollBehavior scroll_behavior =
      ScrollableArea::V8EnumToScrollBehavior(
          scroll_to_options->behavior().AsEnum());

  LayoutBox* box = GetLayoutBoxForScrolling();
  if (!box) {
    return;
  }
  if (PaintLayerScrollableArea* scrollable_area = box->GetScrollableArea()) {
    if (scroll_to_options->hasLeft() && HasLeftwardDirection(*this)) {
      UseCounter::Count(
          GetDocument(),
          WebFeature::
              kElementWithLeftwardOrUpwardOverflowDirection_ScrollLeftOrTop);
      if (scroll_to_options->left() > 0) {
        UseCounter::Count(
            GetDocument(),
            WebFeature::
                kElementWithLeftwardOrUpwardOverflowDirection_ScrollLeftOrTopSetPositive);
      }
    }
    if (scroll_to_options->hasTop() && HasUpwardDirection(*this)) {
      UseCounter::Count(
          GetDocument(),
          WebFeature::
              kElementWithLeftwardOrUpwardOverflowDirection_ScrollLeftOrTop);
      if (scroll_to_options->top() > 0) {
        UseCounter::Count(
            GetDocument(),
            WebFeature::
                kElementWithLeftwardOrUpwardOverflowDirection_ScrollLeftOrTopSetPositive);
      }
    }

    ScrollOffset new_offset = scrollable_area->GetScrollOffset();
    if (scroll_to_options->hasLeft()) {
      new_offset.set_x(
          ScrollableArea::NormalizeNonFiniteScroll(scroll_to_options->left()) *
          box->Style()->EffectiveZoom());
    }
    if (scroll_to_options->hasTop()) {
      new_offset.set_y(
          ScrollableArea::NormalizeNonFiniteScroll(scroll_to_options->top()) *
          box->Style()->EffectiveZoom());
    }

    new_offset = SnapScrollOffsetToPhysicalPixels(new_offset);
    std::unique_ptr<cc::SnapSelectionStrategy> strategy =
        cc::SnapSelectionStrategy::CreateForEndPosition(
            scrollable_area->ScrollOffsetToPosition(new_offset),
            scroll_to_options->hasLeft(), scroll_to_options->hasTop());
    std::optional<gfx::PointF> snap_point =
        scrollable_area->GetSnapPositionAndSetTarget(*strategy);
    if (snap_point.has_value()) {
      new_offset = scrollable_area->ScrollPositionToOffset(snap_point.value());
    }

    scrollable_area->SetScrollOffset(
        new_offset, mojom::blink::ScrollType::kProgrammatic, scroll_behavior);
  }
}

void Element::ScrollFrameBy(const ScrollToOptions* scroll_to_options) {
  gfx::Vector2dF displacement;
  if (scroll_to_options->hasLeft()) {
    displacement.set_x(
        ScrollableArea::NormalizeNonFiniteScroll(scroll_to_options->left()));
  }
  if (scroll_to_options->hasTop()) {
    displacement.set_y(
        ScrollableArea::NormalizeNonFiniteScroll(scroll_to_options->top()));
  }

  mojom::blink::ScrollBehavior scroll_behavior =
      ScrollableArea::V8EnumToScrollBehavior(
          scroll_to_options->behavior().AsEnum());
  LocalFrame* frame = GetDocument().GetFrame();
  if (!frame || !frame->View() || !GetDocument().GetPage()) {
    return;
  }

  ScrollableArea* viewport = frame->View()->LayoutViewport();
  if (!viewport) {
    return;
  }

  displacement.Scale(frame->LayoutZoomFactor());
  gfx::PointF new_position = viewport->ScrollPosition() + displacement;
  gfx::PointF current_position = viewport->ScrollPosition();
  std::unique_ptr<cc::SnapSelectionStrategy> strategy =
      cc::SnapSelectionStrategy::CreateForEndAndDirection(
          current_position, displacement,
          RuntimeEnabledFeatures::FractionalScrollOffsetsEnabled());
  new_position =
      viewport->GetSnapPositionAndSetTarget(*strategy).value_or(new_position);
  viewport->SetScrollOffset(viewport->ScrollPositionToOffset(new_position),
                            mojom::blink::ScrollType::kProgrammatic,
                            scroll_behavior);
}

void Element::ScrollFrameTo(const ScrollToOptions* scroll_to_options) {
  mojom::blink::ScrollBehavior scroll_behavior =
      ScrollableArea::V8EnumToScrollBehavior(
          scroll_to_options->behavior().AsEnum());
  LocalFrame* frame = GetDocument().GetFrame();
  if (!frame || !frame->View() || !GetDocument().GetPage()) {
    return;
  }

  ScrollableArea* viewport = frame->View()->LayoutViewport();
  if (!viewport) {
    return;
  }

  ScrollOffset new_offset = viewport->GetScrollOffset();
  if (scroll_to_options->hasLeft()) {
    new_offset.set_x(
        ScrollableArea::NormalizeNonFiniteScroll(scroll_to_options->left()) *
        frame->LayoutZoomFactor());
  }
  if (scroll_to_options->hasTop()) {
    new_offset.set_y(
        ScrollableArea::NormalizeNonFiniteScroll(scroll_to_options->top()) *
        frame->LayoutZoomFactor());
  }

  gfx::PointF new_position = viewport->ScrollOffsetToPosition(
      SnapScrollOffsetToPhysicalPixels(new_offset));
  std::unique_ptr<cc::SnapSelectionStrategy> strategy =
      cc::SnapSelectionStrategy::CreateForEndPosition(
          new_position, scroll_to_options->hasLeft(),
          scroll_to_options->hasTop());
  new_position =
      viewport->GetSnapPositionAndSetTarget(*strategy).value_or(new_position);
  new_offset = viewport->ScrollPositionToOffset(new_position);
  viewport->SetScrollOffset(new_offset, mojom::blink::ScrollType::kProgrammatic,
                            scroll_behavior);
}

gfx::Rect Element::BoundsInWidget() const {
  GetDocument().EnsurePaintLocationDataValidForNode(
      this, DocumentUpdateReason::kUnknown);

  LocalFrameView* view = GetDocument().View();
  if (!view) {
    return gfx::Rect();
  }

  Vector<gfx::QuadF> quads;

  // TODO(pdr): Unify the quad/bounds code with Element::ClientQuads.

  // Foreign objects need to convert between SVG and HTML coordinate spaces and
  // cannot use LocalToAbsoluteQuad directly with ObjectBoundingBox which is
  // SVG coordinates and not HTML coordinates. Instead, use the AbsoluteQuads
  // codepath below.
  auto* svg_element = DynamicTo<SVGElement>(this);
  if (svg_element && GetLayoutObject() &&
      !GetLayoutObject()->IsSVGForeignObject()) {
    // Get the bounding rectangle from the SVG model.
    // TODO(pdr): This should include stroke.
    if (IsA<SVGGraphicsElement>(svg_element)) {
      quads.push_back(GetLayoutObject()->LocalToAbsoluteQuad(
          gfx::QuadF(GetLayoutObject()->ObjectBoundingBox())));
    }
  } else {
    // Get the bounding rectangle from the box model.
    if (GetLayoutBoxModelObject()) {
      GetLayoutBoxModelObject()->AbsoluteQuads(quads);
    }
  }

  if (quads.empty()) {
    return gfx::Rect();
  }

  gfx::RectF result;
  for (auto& quad : quads) {
    result.Union(quad.BoundingBox());
  }

  return view->FrameToViewport(gfx::ToEnclosingRect(result));
}

Vector<gfx::Rect> Element::OutlineRectsInWidget(
    DocumentUpdateReason reason) const {
  Vector<gfx::Rect> rects;

  LocalFrameView* view = GetDocument().View();
  if (!view) {
    return rects;
  }

  GetDocument().EnsurePaintLocationDataValidForNode(this, reason);

  LayoutBoxModelObject* layout_object = GetLayoutBoxModelObject();
  if (!layout_object) {
    return rects;
  }

  Vector<PhysicalRect> outline_rects = layout_object->OutlineRects(
      nullptr, PhysicalOffset(),
      layout_object->StyleRef().OutlineRectsShouldIncludeBlockInkOverflow());
  for (auto& r : outline_rects) {
    PhysicalRect physical_rect = layout_object->LocalToAbsoluteRect(r);
    gfx::Rect absolute_rect =
        view->FrameToViewport(ToPixelSnappedRect(physical_rect));
    rects.push_back(absolute_rect);
  }

  return rects;
}

gfx::Rect Element::VisibleBoundsInLocalRoot() const {
  if (!GetLayoutObject() || !GetDocument().GetPage() ||
      !GetDocument().GetFrame()) {
    return gfx::Rect();
  }

  // We don't use absoluteBoundingBoxRect() because it can return an gfx::Rect
  // larger the actual size by 1px. crbug.com/470503
  PhysicalRect rect(
      gfx::ToRoundedRect(GetLayoutObject()->AbsoluteBoundingBoxRectF()));
  PhysicalRect frame_clip_rect =
      GetDocument().View()->GetLayoutView()->ClippingRect(PhysicalOffset());
  rect.Intersect(frame_clip_rect);

  // MapToVisualRectInAncestorSpace, called with a null ancestor argument,
  // returns the root-frame-visible rect in the root frame's coordinate space.
  // TODO(bokan): When the root is remote this appears to be document space,
  // rather than frame.
  // MapToVisualRectInAncestorSpace applies ancestors' frame's clipping but does
  // not apply (overflow) element clipping.
  GetDocument().View()->GetLayoutView()->MapToVisualRectInAncestorSpace(nullptr,
                                                                        rect);

  rect = GetDocument()
             .GetFrame()
             ->LocalFrameRoot()
             .ContentLayoutObject()
             ->AbsoluteToLocalRect(rect, kTraverseDocumentBoundaries |
                                             kApplyRemoteMainFrameTransform);

  return ToPixelSnappedRect(rect);
}

void Element::ClientQuads(Vector<gfx::QuadF>& quads) const {
  LayoutObject* element_layout_object = GetLayoutObject();
  if (!element_layout_object) {
    return;
  }

  // Foreign objects need to convert between SVG and HTML coordinate spaces and
  // cannot use LocalToAbsoluteQuad directly with ObjectBoundingBox which is
  // SVG coordinates and not HTML coordinates. Instead, use the AbsoluteQuads
  // codepath below.
  const auto* svg_element = DynamicTo<SVGElement>(this);
  if (svg_element && !element_layout_object->IsSVGRoot() &&
      !element_layout_object->IsSVGForeignObject()) {
    // Get the bounding rectangle from the SVG model.
    // TODO(pdr): ObjectBoundingBox does not include stroke and the spec is not
    // clear (see: https://github.com/w3c/svgwg/issues/339, crbug.com/529734).
    // If stroke is desired, we can update this to use AbsoluteQuads, below.
    if (IsA<SVGGraphicsElement>(svg_element)) {
      quads.push_back(element_layout_object->LocalToAbsoluteQuad(
          gfx::QuadF(element_layout_object->ObjectBoundingBox())));
    }
    return;
  }

  // FIXME: Handle table/inline-table with a caption.
  if (element_layout_object->IsBoxModelObject() ||
      element_layout_object->IsBR()) {
    element_layout_object->AbsoluteQuads(quads);
  }
}

DOMRectList* Element::getClientRects() {
  // TODO(crbug.com/1499981): This should be removed once synchronized scrolling
  // impact is understood.
  SyncScrollAttemptHeuristic::DidAccessScrollOffset();
  GetDocument().EnsurePaintLocationDataValidForNode(
      this, DocumentUpdateReason::kJavaScript);
  Vector<gfx::QuadF> quads;
  ClientQuads(quads);
  if (quads.empty()) {
    return MakeGarbageCollected<DOMRectList>();
  }

  LayoutObject* element_layout_object = GetLayoutObject();
  DCHECK(element_layout_object);
  GetDocument().AdjustQuadsForScrollAndAbsoluteZoom(quads,
                                                    *element_layout_object);
  return MakeGarbageCollected<DOMRectList>(quads);
}

gfx::RectF Element::GetBoundingClientRectNoLifecycleUpdateNoAdjustment() const {
  Vector<gfx::QuadF> quads;
  ClientQuads(quads);
  if (quads.empty()) {
    return gfx::RectF();
  }

  gfx::RectF result;
  for (auto& quad : quads) {
    result.Union(quad.BoundingBox());
  }
  return result;
}

gfx::RectF Element::GetBoundingClientRectNoLife
```