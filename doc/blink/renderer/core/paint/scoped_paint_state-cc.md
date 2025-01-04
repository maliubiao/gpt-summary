Response:
Let's break down the request and the provided code to construct a comprehensive answer.

**1. Understanding the Goal:**

The core request is to analyze the `scoped_paint_state.cc` file in Chromium's Blink rendering engine and explain its functionality, relating it to web technologies (JavaScript, HTML, CSS) and common developer errors. The request also asks for logical reasoning examples, user operation tracing, and hints for debugging.

**2. Deconstructing the Code:**

I'll go through the code section by section, noting key functionalities and potential connections to web concepts:

* **Includes:**  `layout_replaced.h`, `layout_view.h`, `physical_fragment.h`, `box_model_object_painter.h`, `paint_layer.h`, `paint_layer_painter.h`. These headers suggest the file deals with the layout and painting process of elements on a webpage. "Replaced" likely refers to elements like `<img>` or `<video>`. "Paint Layer" is a crucial concept for understanding compositing and optimizations.

* **`ScopedPaintState` Constructor:**
    * Takes a `LayoutObject`, `PaintInfo`, and `FragmentData`. This immediately tells us it's involved in the painting of individual layout objects within specific fragments (likely parts of a larger element).
    * `fragment_to_paint_`:  Determines if the object needs painting in the current fragment. If not, it sets `paint_offset_` to a very large value, indicating nothing to paint.
    * `paint_offset_`: The starting position for drawing the element.
    * The `if` condition checks for overlay overflow controls and self-painting layers. This suggests optimization or special handling for these cases where the offset might already be accounted for.
    * `AdjustForPaintProperties(object)`: This is a key function and will need further examination.

* **`AdjustForPaintProperties`:**
    * Handles paint properties (like transforms, effects) that might affect how an element is painted.
    * `object.IsSVGChild()`: SVG elements have their own rendering pipeline.
    * `fragment_to_paint_->PaintProperties()`:  Retrieves the paint properties associated with the current fragment.
    * The code then checks for different types of paint properties: `PaintOffsetTranslation`, `Transform`, `Effect`.
    * **`PaintOffsetTranslation`:** This seems to handle cases where an element's painting needs to be shifted. The comment about table row backgrounds is a good concrete example. It also shows the distinction between applying the translation via paint chunk properties (for most cases) and as a direct drawing operation (in specific scenarios like table row backgrounds).
    * **`Transform`:** Handles non-layer transforms (where a full paint layer isn't created).
    * **`Effect`:** Handles visual effects that don't require a dedicated layer.
    * The creation of `chunk_properties_` suggests grouping painting operations for optimization.

* **`FinishPaintOffsetTranslationAsDrawing`:** Cleans up the drawing context if a direct drawing translation was applied.

* **`ScopedBoxContentsPaintState`:** A derived class likely specifically for painting the content area of boxes.
    * `AdjustForBoxContents`:
        * Focuses on painting the "contents" part of a box (excluding borders, margins, etc.).
        * Handles `ContentsProperties`.
        * **Scroll Translation:** Adjusts the paint offset based on scroll position. This is crucial for displaying scrolled content correctly.
        * **Culling:**  Optimizes painting by only painting what's visible within the cull rect.
        * **Mobile Friendliness Checker:**  This is an interesting aspect. It detects potentially problematic horizontal scrolling areas, likely for improving the mobile user experience.

**3. Connecting to Web Technologies:**

Now, I'll link these code features to JavaScript, HTML, and CSS:

* **HTML:** The structure of the HTML document dictates the `LayoutObject` tree. Each HTML element will have a corresponding `LayoutObject`.
* **CSS:** CSS properties directly influence the paint properties. `transform`, `opacity`, `filter`, `overflow`, `position: fixed`, and scrolling behavior are all relevant here.
* **JavaScript:** JavaScript can dynamically modify the DOM and CSS, triggering repaints and thus involving this code. Animations and interactive elements heavily rely on the rendering pipeline.

**4. Logical Reasoning Examples:**

I'll create scenarios with inputs and outputs to illustrate the code's behavior:

* **Scenario 1 (Paint Offset Translation):**
    * **Input:** A `<div>` with `transform: translateX(10px);`
    * **Expected Output:** The `AdjustForPaintProperties` function will detect the `PaintOffsetTranslation` and adjust the `paint_offset_` accordingly, ensuring the content is drawn 10 pixels to the right.

* **Scenario 2 (Culling):**
    * **Input:** A large `<div>` with `overflow: hidden;` and only a small portion visible in the viewport.
    * **Expected Output:** `AdjustForBoxContents` will set the `CullRect` to the visible area. Subsequent painting operations will be clipped to this rect, improving performance.

**5. Common User/Programming Errors:**

I'll consider situations where developers might unintentionally trigger this code in unexpected ways:

* **Excessive Use of Transforms:** Animating many elements with complex transforms can lead to frequent repaints and performance issues. This code would be involved in each repaint.
* **Incorrect `overflow` Settings:**  Not setting `overflow: hidden;` on a scrollable container might cause unexpected painting of off-screen content. The mobile friendliness checker logic is directly related to this.
* **Z-Index Issues:** While not directly in this file, incorrect `z-index` values can lead to complex paint order calculations and might indirectly involve this code.

**6. User Operation Tracing:**

I'll simulate a user action and how it leads to this code being executed:

1. **User Action:**  User scrolls down a webpage.
2. **Browser Event:** The browser detects the scroll event.
3. **Layout Update:** The browser recalculates the layout of the page to determine which parts are now visible.
4. **Paint Invalidation:** The browser marks the areas that need to be repainted.
5. **Paint Tree Traversal:** The rendering engine walks through the paint tree.
6. **`Paint()` Call:** The `Paint()` method is called on relevant `LayoutObject`s.
7. **`ScopedPaintState` Instantiation:** Inside the `Paint()` method, a `ScopedPaintState` object is created to manage the painting context for the current object and paint phase.
8. **`AdjustForPaintProperties` and `AdjustForBoxContents` Execution:**  These methods are called to prepare the painting state based on the object's properties and the current fragment.
9. **Drawing Operations:** The actual drawing commands are issued based on the prepared state.

**7. Debugging Hints:**

I'll provide tips for developers debugging paint-related issues:

* **Chromium DevTools Layers Panel:** This panel visualizes paint layers and can help identify unexpected layer creation or compositing issues.
* **"Show Paint Rects" and "Show Composited Layer Borders" in DevTools:** These flags highlight the areas being repainted and the boundaries of composited layers.
* **Performance Profiling:** Use the DevTools performance profiler to identify expensive paint operations.
* **Understanding Paint Phases:** Knowing the different paint phases (`Background`, `Border`, `Foreground`, etc.) can help narrow down where a painting issue might be occurring. The `PaintInfo::phase` in the code is key here.
* **Examining Paint Properties:** Inspect the computed styles of an element to understand how CSS properties are affecting its rendering.

By following this structured approach, I can ensure the answer is detailed, accurate, and addresses all aspects of the request. The key is to connect the low-level C++ code to the higher-level concepts of web development.
好的，我们来详细分析一下 `blink/renderer/core/paint/scoped_paint_state.cc` 这个文件的功能。

**功能概述:**

`ScopedPaintState` 类及其相关的 `ScopedBoxContentsPaintState` 类的主要功能是**管理在 Blink 渲染引擎的绘制过程中的状态**。它就像一个作用域管理器，在对一个特定的 `LayoutObject` 进行绘制时，负责设置和维护必要的绘制上下文信息。

更具体地说，它的功能包括：

1. **跟踪当前的绘制片段 (Fragment):**  确定当前正在绘制的是 `LayoutObject` 的哪个物理片段 (PhysicalFragment)。一个 `LayoutObject` 可能因为分栏、分页等原因被分割成多个片段。
2. **管理绘制偏移 (Paint Offset):** 记录当前片段的绘制起始位置。这个偏移量考虑了父元素的滚动、变换等因素。
3. **调整绘制属性 (Paint Properties):** 根据元素的 CSS 属性（如 `transform`, `opacity`, `filter` 等），调整绘制上下文，以便正确地渲染元素。这包括但不限于：
    * **平移 (Translation):** 应用 `transform: translate()` 效果。
    * **变换 (Transform):** 应用更复杂的 `transform` 效果。
    * **效果 (Effect):** 应用 `opacity`, `filter` 等视觉效果。
4. **管理绘制块属性 (Paint Chunk Properties):**  为了优化绘制，Blink 会将绘制操作组织成不同的 "绘制块"。`ScopedPaintState` 负责管理与当前绘制块相关的属性。
5. **处理滚动偏移 (Scroll Offset):**  对于可滚动的元素，需要考虑其滚动位置对子元素绘制的影响。
6. **进行裁剪 (Culling):**  优化绘制性能，避免绘制不可见的内容。`ScopedPaintState` 可以根据裁剪区域调整绘制信息。
7. **处理移动端友好性检查 (Mobile Friendliness Check):**  在绘制前景阶段，会检查是否存在可能导致移动端用户体验不佳的水平滚动内容。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`ScopedPaintState` 位于渲染引擎的核心部分，直接参与将 HTML 结构、CSS 样式转化为屏幕上可见像素的过程。

* **HTML:** HTML 结构定义了 `LayoutObject` 的树形结构。`ScopedPaintState` 的构造函数接收一个 `LayoutObject`，这意味着它处理的是页面上的具体元素（例如 `<div>`, `<p>`, `<img>` 等）。

   **举例:** 当浏览器渲染一个 `<div>` 元素时，会创建一个对应的 `LayoutBox` 对象。在绘制这个 `LayoutBox` 时，会创建 `ScopedPaintState` 的实例来管理其绘制状态。

* **CSS:** CSS 样式规则决定了元素的视觉表现，包括布局、颜色、大小、变换等。这些样式信息会被转换成绘制属性，并在 `AdjustForPaintProperties` 中被应用。

   **举例:**
    * 如果一个元素设置了 `transform: translateX(10px);`，`AdjustForPaintProperties` 会检测到这个变换，并更新绘制偏移，使得元素在绘制时向右平移 10 像素。
    * 如果一个元素设置了 `opacity: 0.5;`，`AdjustForPaintProperties` 会应用相应的透明度效果。
    * `overflow: hidden;` 会影响裁剪区域的计算，从而影响 `ScopedPaintState` 如何进行裁剪优化。

* **JavaScript:** JavaScript 可以动态地修改 HTML 结构和 CSS 样式。这些修改会触发重新布局和重绘，从而再次调用到 `ScopedPaintState` 相关的代码。

   **举例:**
    * 当 JavaScript 使用 `element.style.transform = 'rotate(45deg)';` 修改元素的变换时，会导致该元素及其可能受影响的祖先元素进行重绘。在绘制该元素时，`ScopedPaintState` 会处理新的旋转变换。
    * JavaScript 创建或删除 DOM 元素也会触发布局和绘制的更新。

**逻辑推理的假设输入与输出:**

假设我们有一个简单的 HTML 结构和 CSS 样式：

**HTML:**

```html
<div id="container" style="width: 200px; height: 100px; overflow: auto;">
  <div id="content" style="width: 300px; height: 150px; background-color: red;"></div>
</div>
```

**假设输入 (在绘制 `#content` 元素时):**

* `object`: 指向 `#content` 元素的 `LayoutBox` 对象。
* `paint_info`: 包含了当前绘制阶段的信息，例如是绘制背景还是前景。
* `fragment_data`: 指向 `#content` 元素在 `#container` 中的物理片段信息。由于 `#content` 的尺寸大于 `#container`，并且 `overflow` 设置为 `auto`，因此可能会存在滚动条。

**逻辑推理 (部分 `ScopedPaintState` 的执行过程):**

1. **构造函数:** `ScopedPaintState` 被创建，接收 `#content` 的 `LayoutBox` 对象和相关的 `PaintInfo` 和 `FragmentData`。
2. **`paint_offset_` 计算:** 由于 `#content` 位于可滚动的容器中，`paint_offset_` 会考虑 `#container` 的滚动位置。例如，如果用户向左滚动了 50 像素，那么 `#content` 的绘制起始位置的 X 坐标会加上 50 像素（相对于 `#container` 的内容区域）。
3. **`AdjustForPaintProperties`:**  由于 `#content` 没有设置 `transform` 或其他复杂的绘制属性，这个函数可能不会执行太多操作。
4. **`ScopedBoxContentsPaintState::AdjustForBoxContents`:** (假设当前是绘制盒子内容阶段)
    * **滚动偏移处理:**  `paint_offset_` 可能会进一步调整，加上 `#container` 的 `ScrollOrigin()`。
    * **裁剪:** 由于 `#container` 设置了 `overflow: auto;`, 会计算出一个裁剪矩形，限制 `#content` 的绘制范围在 `#container` 的可见区域内。只有位于可见区域内的部分 `#content` 才会被绘制。
    * **移动端友好性检查:**  由于 `#content` 的宽度大于 `#container`，可能会触发移动端友好性检查，因为这可能导致水平滚动。

**假设输出:**

* `paint_offset_`:  包含了 `#container` 的滚动偏移。
* 绘制操作会被限制在 `#container` 的裁剪区域内。
* 可能会记录水平滚动信息用于移动端友好性分析。

**涉及用户或者编程常见的使用错误及举例说明:**

1. **过度使用复杂的 `transform` 或 `filter`:**  过多的复杂绘制属性会导致频繁的重绘和性能问题。`ScopedPaintState` 会参与这些重绘过程，但如果性能瓶颈出现在这里，通常意味着需要优化 CSS 或动画实现。

   **例子:**  在一个包含大量元素的列表上使用复杂的 CSS 动画，每个元素的动画都涉及到 `transform` 或 `filter` 的改变，会导致 `ScopedPaintState` 被频繁调用，占用大量 CPU 资源。

2. **不必要的重绘区域:**  当 JavaScript 修改 DOM 或样式时，可能会导致不必要的较大区域被标记为需要重绘。虽然 `ScopedPaintState` 负责管理单个元素的绘制状态，但如果重绘范围过大，也会影响整体性能。

   **例子:**  使用 JavaScript 修改一个位于页面顶部的元素的样式，可能会导致整个页面进行重绘，即使只有顶部元素发生了变化。

3. **忘记设置 `overflow: hidden` 或 `overflow: auto`:**  对于需要裁剪内容的容器，如果没有正确设置 `overflow` 属性，可能会导致内容溢出并被绘制出来，即使这些内容在视觉上应该被隐藏。`ScopedPaintState` 会根据 `overflow` 属性来决定是否进行裁剪。

   **例子:**  一个模态对话框没有设置 `overflow: hidden;`，其内容可能会溢出到视口之外，即使这些溢出的部分不应该显示。

**用户操作是如何一步步的到达这里，作为调试线索:**

假设用户在浏览网页时触发了一个动画效果：

1. **用户操作:** 用户鼠标悬停在一个按钮上，触发了一个 CSS `transition` 动画，该动画改变了按钮的 `transform` 属性（例如 `scale`）。
2. **浏览器事件:** 浏览器捕获到 `mouseover` 事件。
3. **样式计算:** 浏览器根据 CSS 规则和 `transition` 定义，计算出按钮新的 `transform` 值。
4. **布局（可能）：** 如果 `transform` 影响了按钮的尺寸或位置，可能会触发轻微的布局更新。
5. **标记为需要绘制:** 按钮元素被标记为需要重绘，因为它视觉外观发生了变化。
6. **进入绘制流程:**  渲染引擎开始执行绘制操作。
7. **遍历绘制树:** 渲染引擎遍历绘制树，找到需要绘制的元素，包括这个按钮。
8. **调用 `Paint()` 方法:**  按钮对应的 `LayoutObject` 的 `Paint()` 方法被调用。
9. **创建 `ScopedPaintState`:** 在 `Paint()` 方法内部，会创建 `ScopedPaintState` 对象，传入按钮的 `LayoutObject` 和当前的 `PaintInfo`。
10. **`AdjustForPaintProperties` 执行:** `ScopedPaintState::AdjustForPaintProperties` 方法会被调用，它会读取按钮的 `transform` 属性，并将其应用到绘制上下文中。这可能涉及到更新绘制偏移、设置变换矩阵等操作。
11. **实际绘制:**  后续的绘制代码会利用 `ScopedPaintState` 中设置的绘制状态，将按钮以缩放后的状态绘制到屏幕上。

**调试线索:**

* **性能分析工具:**  使用 Chrome DevTools 的 Performance 面板可以记录页面运行时的性能信息，包括绘制调用的堆栈。如果发现某个动画或交互导致了大量的绘制操作，并且调用栈中出现了 `ScopedPaintState` 相关的函数，则可以定位到这里。
* **Layers 面板:**  DevTools 的 Layers 面板可以显示页面的分层情况。如果动画涉及到层合成 (compositing)，可以观察层的创建和更新，这与 `ScopedPaintState` 处理的绘制属性有关。
* **Paint flashing:**  在 DevTools 的 Rendering 设置中开启 "Show paint rectangles"，可以高亮显示页面上正在重绘的区域。如果发现不必要的重绘，可以进一步分析是什么操作触发了这些重绘。
* **断点调试:**  在 `scoped_paint_state.cc` 文件中设置断点，可以跟踪代码的执行流程，查看 `paint_offset_`、绘制属性等是如何被计算和应用的。这需要编译 Chromium 源码。

总而言之，`blink/renderer/core/paint/scoped_paint_state.cc` 是 Blink 渲染引擎中负责管理元素绘制状态的关键组件，它连接了 HTML 结构、CSS 样式和最终的屏幕渲染。理解它的功能有助于理解浏览器的渲染过程，并为性能优化和问题排查提供线索。

Prompt: 
```
这是目录为blink/renderer/core/paint/scoped_paint_state.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/paint/scoped_paint_state.h"

#include "third_party/blink/renderer/core/layout/layout_replaced.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/layout/physical_fragment.h"
#include "third_party/blink/renderer/core/paint/box_model_object_painter.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/paint/paint_layer_painter.h"

namespace blink {

ScopedPaintState::ScopedPaintState(const LayoutObject& object,
                                   const PaintInfo& paint_info,
                                   const FragmentData* fragment_data)
    : fragment_to_paint_(fragment_data), input_paint_info_(paint_info) {
  if (!fragment_to_paint_) {
    // The object has nothing to paint in the current fragment.
    // TODO(wangxianzhu): Use DCHECK(fragment_to_paint_) in PaintOffset()
    // when all painters check FragmentToPaint() before painting.
    paint_offset_ =
        PhysicalOffset(LayoutUnit::NearlyMax(), LayoutUnit::NearlyMax());
    return;
  }

  paint_offset_ = fragment_to_paint_->PaintOffset();
  if (paint_info.phase == PaintPhase::kOverlayOverflowControls ||
      (object.HasLayer() &&
       To<LayoutBoxModelObject>(object).HasSelfPaintingLayer())) {
    // PaintLayerPainter already adjusted for PaintOffsetTranslation for
    // PaintContainer.
    return;
  }

  AdjustForPaintProperties(object);
}

void ScopedPaintState::AdjustForPaintProperties(const LayoutObject& object) {
  // Paint properties of SVG children are handled in SVG code paths.
  if (object.IsSVGChild())
    return;

  const auto* properties = fragment_to_paint_->PaintProperties();
  if (!properties)
    return;

  if (!object.Parent() && !object.HasLayer()) {
#if DCHECK_IS_ON()
    DCHECK(object.IsInDetachedNonDomTree());
    DCHECK(object.IsBox());
    DCHECK_EQ(To<LayoutBox>(object).GetPhysicalFragment(0)->GetBoxType(),
              PhysicalFragment::kPageBorderBox);
#endif

    // The page border box fragment paints @page borders and other decorations,
    // in addition to the document background (the one typically defined on the
    // BODY or HTML element). Therefore, this is in the coordinate system of the
    // document, which may have a different scale factor than the page
    // container, which is fitted to the paper size, if any.
    chunk_properties_.emplace(
        input_paint_info_.context.GetPaintController(),
        fragment_to_paint_->LocalBorderBoxProperties(), object,
        DisplayItem::PaintPhaseToDrawingType(input_paint_info_.phase));
    return;
  }

  auto new_chunk_properties = input_paint_info_.context.GetPaintController()
                                  .CurrentPaintChunkProperties();
  bool needs_new_chunk_properties = false;

  if (const auto* paint_offset_translation =
          properties->PaintOffsetTranslation()) {
    adjusted_paint_info_.emplace(input_paint_info_);
    adjusted_paint_info_->TransformCullRect(*paint_offset_translation);
    new_chunk_properties.SetTransform(*paint_offset_translation);
    needs_new_chunk_properties = true;

    if (input_paint_info_.context.InDrawingRecorder()) {
      // If we are recording drawings, we should issue the translation as a raw
      // paint operation instead of paint chunk properties. One case is that we
      // are painting table row background behind a cell having paint offset
      // translation.
      input_paint_info_.context.Save();
      gfx::Vector2dF translation = paint_offset_translation->Get2dTranslation();
      input_paint_info_.context.Translate(translation.x(), translation.y());
      paint_offset_translation_as_drawing_ = true;
    }
  }

  if (input_paint_info_.context.InDrawingRecorder())
    return;

  if (const auto* transform = properties->Transform()) {
    // This transform node stores some transform-related information for a
    // non-stacked object without real transform (otherwise PaintLayerPainter
    // should have handled the transform node for painting).
    DCHECK(transform->IsIdentity());
    new_chunk_properties.SetTransform(*transform);
    needs_new_chunk_properties = true;
  }
  DCHECK(!properties->Translate());
  DCHECK(!properties->Rotate());
  DCHECK(!properties->Scale());
  DCHECK(!properties->Offset());
  if (const auto* effect = properties->Effect()) {
    // Similar to the above.
    DCHECK(!effect->HasRealEffects());
    new_chunk_properties.SetEffect(*effect);
    needs_new_chunk_properties = true;
  }

  if (needs_new_chunk_properties) {
    chunk_properties_.emplace(
        input_paint_info_.context.GetPaintController(), new_chunk_properties,
        object, DisplayItem::PaintPhaseToDrawingType(input_paint_info_.phase));
  }
}

void ScopedPaintState::FinishPaintOffsetTranslationAsDrawing() {
  // This scope should not interlace with scopes of DrawingRecorders.
  DCHECK(paint_offset_translation_as_drawing_);
  DCHECK(input_paint_info_.context.InDrawingRecorder());
  input_paint_info_.context.Restore();
}

void ScopedBoxContentsPaintState::AdjustForBoxContents(const LayoutBox& box) {
  DCHECK(input_paint_info_.phase != PaintPhase::kSelfOutlineOnly &&
         input_paint_info_.phase != PaintPhase::kMask);

  if (!fragment_to_paint_ || !fragment_to_paint_->HasLocalBorderBoxProperties())
    return;

  DCHECK_EQ(paint_offset_, fragment_to_paint_->PaintOffset());

  chunk_properties_.emplace(input_paint_info_.context.GetPaintController(),
                            fragment_to_paint_->ContentsProperties(), box,
                            input_paint_info_.DisplayItemTypeForClipping());

  if (const auto* properties = fragment_to_paint_->PaintProperties()) {
    // See comments for ScrollTranslation in object_paint_properties.h
    // for the reason of adding ScrollOrigin(). The paint offset will
    // be used only for the scrolling contents that are not painted through
    // descendant objects' Paint() method, e.g. inline boxes.
    if (properties->ScrollTranslation())
      paint_offset_ += PhysicalOffset(box.ScrollOrigin());
  }

  // We calculated cull rects for PaintLayers only.
  if (!box.HasLayer())
    return;
  adjusted_paint_info_.emplace(input_paint_info_);
  adjusted_paint_info_->SetCullRect(fragment_to_paint_->GetContentsCullRect());
  if (box.Layer()->PreviousPaintResult() == kFullyPainted) {
    PhysicalRect contents_visual_rect =
        PaintLayerPainter::ContentsVisualRect(*fragment_to_paint_, box);
    if (!PhysicalRect(fragment_to_paint_->GetContentsCullRect().Rect())
             .Contains(contents_visual_rect)) {
      box.Layer()->SetPreviousPaintResult(kMayBeClippedByCullRect);
    }
  }

  if (input_paint_info_.phase == PaintPhase::kForeground) {
    // We treat horizontal-scrollable scrollers like replaced objects.
    if (auto* mf_checker = MobileFriendlinessChecker::From(box.GetDocument())) {
      if (!box.IsLayoutView()) {
        if (auto* scrollable_area = box.GetScrollableArea()) {
          if (scrollable_area->MaximumScrollOffset().x() != 0) {
            PhysicalRect content_rect = box.OverflowClipRect(paint_offset_);
            content_rect.Intersect(
                PhysicalRect(input_paint_info_.GetCullRect().Rect()));
            mf_checker->NotifyPaintReplaced(
                content_rect, input_paint_info_.context.GetPaintController()
                                  .CurrentPaintChunkProperties()
                                  .Transform());
            mf_ignore_scope_.emplace(*mf_checker);
          }
        }
        // Don't check mobile friendliness for beyond viewport in position:fixed
        // boxes because they don't scroll in the viewport.
        if (const auto* properties = fragment_to_paint_->PaintProperties()) {
          if (const auto* translation = properties->PaintOffsetTranslation()) {
            if (translation->ScrollTranslationForFixed())
              mf_ignore_scope_.emplace(*mf_checker);
          }
        }
      }
    }
  }
}

}  // namespace blink

"""

```