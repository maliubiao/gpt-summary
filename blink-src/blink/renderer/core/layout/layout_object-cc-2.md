Response:
The user wants a summary of the functionality of the provided C++ code snippet from `layout_object.cc`. I need to identify the core purposes of the methods within this snippet and explain their relation to web technologies (JavaScript, HTML, CSS). Specifically, I should look for examples of how these methods are used in rendering and layout, and any potential user or programming errors that might arise.

Here's a breakdown of the methods and their potential functions:

- **`CanContainFixedPositionObjects`**: Determines if the layout object can contain fixed-position elements. This relates to CSS positioning.
- **`ContainingBlockForAbsolutePosition`**: Finds the containing block for absolutely positioned elements. Directly related to CSS absolute positioning.
- **`ContainingBlockForFixedPosition`**: Finds the containing block for fixed-position elements. Directly related to CSS fixed positioning.
- **`InclusiveContainingBlock`**:  Returns the layout block that contains the current object.
- **`ContainingScrollContainerLayer`**:  Finds the paint layer that acts as a scroll container. Relates to CSS `overflow` and scrolling.
- **`ContainingScrollContainer`**: Finds the layout box that acts as a scroll container. Relates to CSS `overflow` and scrolling.
- **`NearestAncestorForElement`**: Finds the closest non-anonymous ancestor. This is likely used for DOM tree traversal and style inheritance.
- **`ComputeIsFixedContainer`**: Determines if the layout object acts as a container for fixed-position elements based on CSS properties like `transform`, `filter`, `backdrop-filter`, `contain`, and element types like `LayoutView`, `SVGForeignObject`, and text controls.
- **`ComputeIsAbsoluteContainer`**: Determines if the layout object acts as a container for absolutely positioned elements, often based on `ComputeIsFixedContainer` and the `contain` property.
- **`FindFirstStickyContainer`**: Finds the nearest ancestor with `position: sticky`. Directly related to CSS sticky positioning.
- **`AbsoluteBoundingBoxRectF` / `AbsoluteBoundingBoxRect`**: Calculates the object's bounding box in the viewport coordinates, considering transforms. This is crucial for rendering and hit-testing.
- **`AbsoluteBoundingBoxRectHandlingEmptyInline`**: Similar to the above, but with specific handling for empty inline elements.
- **`AbsoluteBoundingBoxRectForScrollIntoView`**: Calculates the bounding box for scrolling elements into view, potentially ignoring sticky offsets. Related to browser scrolling behavior and JavaScript's `scrollIntoView()` method.
- **`AddAbsoluteRectForLayer`**: Accumulates the bounding boxes of elements within a layer.
- **`AbsoluteBoundingBoxRectIncludingDescendants`**: Calculates the bounding box including all descendants.
- **`Paint`**:  A virtual method intended for subclasses to perform actual painting. Relates to the rendering pipeline.
- **`RecalcScrollableOverflow`**: Recalculates the scrollable overflow area. Related to CSS `overflow` and scrollbars.
- **`RecalcVisualOverflow`**: Recalculates the visual overflow area. Related to how content exceeding the bounds of an element is handled.
- **`RecalcNormalFlowChildVisualOverflowIfNeeded`**:  Recalculates visual overflow specifically for normal flow children.
- **`InvalidateVisualOverflow`**: Marks the visual overflow as needing recalculation, potentially triggering a repaint.
- **`InvalidateVisualOverflowForDCheck`**:  A debug-only function to invalidate visual overflow.
- **`HasDistortingVisualEffects`**:  Checks if the object has visual effects (filters, blends, transforms) that might distort its appearance.
- **`HasNonZeroEffectiveOpacity`**: Checks if the object has an opacity greater than zero.
- **`DecoratedName`**:  Creates a human-readable name for debugging.
- **`ToString`**: Returns a string representation of the object, useful for debugging.
- **`DebugName`**: Similar to `ToString`, used for debugging.
- **`OwnerNodeId`**: Returns the DOM node ID associated with the layout object. Connects the layout tree to the DOM tree.
- **`InvalidateDisplayItemClients`**: Marks the object for repaint.
- **`AbsoluteSelectionRect`**: Calculates the absolute position of the text selection within the object. Related to text selection and user interaction.
- **`InvalidatePaint`**:  Marks the object for repaint, taking context into account.
- **`MapToVisualRectInAncestorSpaceInternalFastPath` / `MapToVisualRectInAncestorSpace` / `MapToVisualRectInAncestorSpaceInternal`**:  Methods to convert coordinates from the object's local space to an ancestor's space, considering transforms and other visual properties. This is essential for hit-testing and event handling.
- **`GetPropertyContainer`**: Finds the nearest ancestor that establishes a new property tree state (e.g., containing transforms or clips).
- **`HitTestForOcclusion`**: Performs a hit test to check if the object is occluded by other elements. Used for optimization and visibility checks.
- **`operator<<`**:  Overloads the output stream operator for easier debugging output.
- **`ShowTreeForThis` / `ShowLayoutTreeForThis` / `ShowLayoutObject`**: Debugging functions to print the layout tree.
- **`DumpLayoutObject` / `DumpLayoutTreeAndMark`**:  More detailed debugging functions to inspect the layout object and its tree structure.
- **`IsSelected`**: Checks if the object is part of the current selection.
- **`IsSelectable`**: Checks if the object can be selected.
- **`SlowEffectiveStyle`**: Returns the computed style, potentially considering pseudo-elements.
- **`HandleDynamicFloatPositionChange`**: Handles changes in the floating or positioned status of an object, updating the layout tree accordingly.
- **`AdjustStyleDifference`**:  Adjusts the style difference to potentially optimize layout and paint invalidation.
- **`SetPseudoElementStyle`**:  Sets the style for a pseudo-element based on its owner element's style.

**Hypotheses for Input and Output (where logical reasoning is involved):**

- **`CanContainFixedPositionObjects`**:
    - Input: A `LayoutObject` representing a `<div>` element.
    - Output: `true` (assuming default styles).
    - Input: A `LayoutObject` representing a `<span>` element with `display: inline`.
    - Output: `false`.
- **`ComputeIsFixedContainer`**:
    - Input: A `LayoutObject` for a `<div>` with `transform: translateZ(0)`.
    - Output: `true`.
    - Input: A `LayoutObject` for a `<span>` with `filter: blur(5px)`.
    - Output: `true`.
- **`ComputeIsAbsoluteContainer`**:
    - Input: A `LayoutObject` for a `<div>` with `contain: layout`.
    - Output: `true`.
    - Input: A `LayoutObject` for a `<span>` with no special CSS.
    - Output: `false`.
- **`FindFirstStickyContainer`**:
    - Input: A `LayoutObject` representing a `<p>` element nested inside a `<div>` with `position: sticky`.
    - Output: The `LayoutObject` of the `<div>`.
    - Input: A `LayoutObject` representing a `<h1>` element with no sticky ancestors.
    - Output: `nullptr`.
- **`AbsoluteBoundingBoxRectF`**:
    - Input: A `LayoutObject` for a 100x100 `<div>` at position (50, 50).
    - Output: A `gfx::RectF` representing the rectangle (50, 50, 100, 100).
    - Input: The same `LayoutObject` with `transform: rotate(45deg)`.
    - Output: A `gfx::RectF` representing the bounding box of the rotated square.

**Common User or Programming Errors:**

- **Incorrectly assuming a containing block:**  Developers might incorrectly assume an element is the containing block for absolute or fixed positioning, leading to unexpected placement of elements. For example, assuming a parent `<div>` with no explicit `position` set is a containing block.
- **Forgetting about transform and filter effects:** Developers might not realize that CSS `transform` or `filter` properties on ancestor elements can create new containing blocks, affecting the behavior of absolutely or fixed positioned children.
- **Misunderstanding sticky positioning:** Developers might expect `position: sticky` to work relative to any ancestor, but it works relative to the nearest scrolling ancestor.
- **Over-invalidation:**  Incorrectly invalidating paint or layout can lead to performance issues. For instance, unnecessarily calling `InvalidatePaint` on a large portion of the document.
- **Z-index issues:** Incorrectly assuming the stacking context of elements, particularly when transforms or other properties create new stacking contexts.

**Summary of Functionality:**

This section of `layout_object.cc` focuses on **determining the spatial relationships and rendering properties of layout objects within the Blink rendering engine**. It provides the core logic for:

- **Establishing containing blocks for positioned elements (absolute, fixed, sticky).**
- **Identifying scroll containers.**
- **Calculating bounding boxes in various coordinate spaces, taking into account transforms.**
- **Managing visual and scrollable overflow.**
- **Invalidating layout and paint when necessary.**
- **Performing hit-testing for occlusion.**
- **Providing debugging utilities to inspect the layout tree.**
- **Handling style updates and their impact on layout.**

Essentially, these methods are crucial for correctly positioning, sizing, drawing, and handling interactions with elements on a web page, reflecting the core principles of CSS layout and rendering.
这是 `blink/renderer/core/layout/layout_object.cc` 源代码文件的第 3 部分，主要关注 `LayoutObject` 的功能，特别是与定位、包含块、滚动容器、视觉效果、绘画失效、坐标映射以及调试相关的操作。

以下是该部分代码功能的归纳：

**核心功能：确定元素在页面中的位置和渲染方式**

1. **包含块的确定 (Containing Block Determination):**
   - `CanContainFixedPositionObjects()`: 判断该 `LayoutObject` 是否可以作为固定定位元素的包含块。
   - `ContainingBlockForAbsolutePosition()`: 查找绝对定位元素的包含块。
   - `ContainingBlockForFixedPosition()`: 查找固定定位元素的包含块。
   - `InclusiveContainingBlock()`: 返回包含该 `LayoutObject` 的最近的 `LayoutBlock`。
   - 这些功能直接关系到 **CSS 定位机制**，特别是 `position: absolute` 和 `position: fixed` 的工作原理。

   **举例说明 (CSS 关系):**
   ```html
   <div style="position: relative;">
     <div style="position: absolute; top: 10px; left: 10px;"></div>
   </div>
   ```
   对于内部的绝对定位 `div`，`ContainingBlockForAbsolutePosition()` 会返回外部的相对定位 `div` 的 `LayoutObject`。

   **假设输入与输出:**
   - **假设输入:** 一个表示绝对定位 `div` 的 `LayoutObject`。
   - **输出:**  包含该 `LayoutObject` 的相对定位祖先元素的 `LayoutBlock` 指针。

2. **滚动容器的查找 (Scroll Container Identification):**
   - `ContainingScrollContainerLayer()`: 查找包含该 `LayoutObject` 的滚动容器的 `PaintLayer`。
   - `ContainingScrollContainer()`: 查找包含该 `LayoutObject` 的滚动容器的 `LayoutBox`。
   - 这些功能与 **CSS 的 `overflow` 属性** 以及页面滚动行为息息相关。

   **举例说明 (CSS 关系):**
   ```html
   <div style="overflow: auto; height: 100px;">
     <p style="height: 200px;">Content that overflows.</p>
   </div>
   ```
   对于 `<p>` 元素的 `LayoutObject`，`ContainingScrollContainer()` 会返回外部 `div` 的 `LayoutBox`。

3. **固定和绝对定位容器的判断 (Fixed and Absolute Container Determination):**
   - `ComputeIsFixedContainer()`:  根据 CSS 属性 (如 `transform`, `filter`, `backdrop-filter`, `contain`) 和元素类型 (如 `LayoutView`, `SVGForeignObject`) 判断该 `LayoutObject` 是否是固定定位元素的容器。
   - `ComputeIsAbsoluteContainer()`:  根据 CSS 属性和 `ComputeIsFixedContainer()` 的结果判断该 `LayoutObject` 是否是绝对定位元素的容器。
   - 这部分逻辑深入解析了 **CSS 中创建新的包含块的各种情况**。

   **举例说明 (CSS 关系):**
   ```html
   <div style="transform: translateZ(0);">
     <div style="position: fixed;"></div>
   </div>
   ```
   对于 `position: fixed` 的内部 `div`，由于外部 `div` 应用了 `transform`，`ComputeIsFixedContainer()` 会返回 `true`。

   **假设输入与输出:**
   - **假设输入:** 一个表示应用了 `transform` 的 `div` 元素的 `LayoutObject`。
   - **输出:** `true` (因为 `transform` 会创建一个新的固定定位容器)。

4. **粘性定位容器的查找 (Sticky Container Identification):**
   - `FindFirstStickyContainer()`: 查找该 `LayoutObject` 最近的粘性定位祖先元素。
   - 直接关联 **CSS 的 `position: sticky` 属性**。

   **举例说明 (CSS 关系):**
   ```html
   <div style="overflow: auto; height: 200px;">
     <div style="position: sticky; top: 0;">Sticky Header</div>
     <p>Some content...</p>
   </div>
   ```
   对于 `<p>` 元素的 `LayoutObject`，`FindFirstStickyContainer()` 会返回 "Sticky Header" `div` 的 `LayoutBoxModelObject`。

5. **边界框的计算 (Bounding Box Calculation):**
   - `AbsoluteBoundingBoxRectF()` / `AbsoluteBoundingBoxRect()`: 计算该 `LayoutObject` 在视口坐标系中的绝对边界框，考虑了变换。
   - `AbsoluteBoundingBoxRectHandlingEmptyInline()`:  处理空行内元素的边界框计算。
   - `AbsoluteBoundingBoxRectForScrollIntoView()`:  为滚动到视图中计算边界框，可能忽略粘性定位的偏移。
   - 这些功能是 **浏览器渲染引擎的核心部分**，用于确定元素在屏幕上的实际位置和大小。

   **举例说明 (JavaScript 关系):**
   JavaScript 的 `getBoundingClientRect()` 方法最终会调用类似的底层机制来获取元素的边界框。

   **假设输入与输出:**
   - **假设输入:** 一个表示 100x100 像素 `div` 的 `LayoutObject`。
   - **输出:** 一个 `gfx::RectF` 对象，表示该 `div` 在视口中的矩形位置和大小。

6. **视觉溢出和滚动溢出的处理 (Visual and Scrollable Overflow Handling):**
   - `RecalcScrollableOverflow()`: 重新计算可滚动溢出区域。
   - `RecalcVisualOverflow()`: 重新计算视觉溢出区域。
   - `RecalcNormalFlowChildVisualOverflowIfNeeded()`:  必要时重新计算正常流子元素的视觉溢出。
   - `InvalidateVisualOverflow()`: 使视觉溢出失效，触发重新计算。
   - 这些功能与 **CSS 的 `overflow` 属性**，以及浏览器如何处理超出元素边界的内容有关。

7. **视觉效果的判断 (Visual Effects Detection):**
   - `HasDistortingVisualEffects()`: 判断该 `LayoutObject` 是否具有扭曲视觉效果 (如 `filter`, `blend-mode`, 透明度小于 1)。
   - `HasNonZeroEffectiveOpacity()`: 判断该 `LayoutObject` 的有效透明度是否大于零。
   - 这些用于优化渲染，例如判断是否需要创建合成层。

8. **坐标映射 (Coordinate Mapping):**
   - `MapToVisualRectInAncestorSpaceInternalFastPath()`, `MapToVisualRectInAncestorSpace()`, `MapToVisualRectInAncestorSpaceInternal()`: 将该 `LayoutObject` 局部坐标系中的矩形映射到祖先元素的视觉坐标系中，考虑了变换等因素。
   - 这对于 **事件处理 (例如点击事件的命中测试)** 和其他需要了解元素在屏幕上位置的操作至关重要。

   **举例说明 (JavaScript 关系):**
   当用户点击屏幕时，浏览器需要将点击的屏幕坐标映射到具体的 DOM 元素，这个过程中会用到类似的坐标映射功能。

9. **命中测试 (Hit Testing):**
   - `HitTestForOcclusion()`: 执行命中测试，判断该 `LayoutObject` 是否被其他元素遮挡。

10. **调试辅助 (Debugging Utilities):**
    - `DecoratedName()`, `ToString()`, `DebugName()`:  生成 `LayoutObject` 的调试信息。
    - `ShowTreeForThis()`, `ShowLayoutTreeForThis()`, `ShowLayoutObject()`:  打印布局树结构用于调试。
    - `DumpLayoutObject()`, `DumpLayoutTreeAndMark()`: 更详细地输出 `LayoutObject` 的信息。

11. **绘画失效 (Paint Invalidation):**
    - `InvalidatePaint()`:  使该 `LayoutObject` 需要重新绘制。
    - `InvalidateDisplayItemClients()`: 使显示项客户端失效。
    - 这些功能用于优化渲染，只在必要时重新绘制屏幕上的部分内容。

12. **选择状态 (Selection State):**
    - `IsSelected()`: 判断该 `LayoutObject` 是否被选中。
    - `IsSelectable()`: 判断该 `LayoutObject` 是否可以被选中。
    - `AbsoluteSelectionRect()`: 获取选中文本的绝对位置。

13. **样式处理 (Style Handling):**
    - `SlowEffectiveStyle()`: 获取该 `LayoutObject` 的最终样式，包括伪元素样式。
    - `AdjustStyleDifference()`:  根据样式差异调整布局和绘制的需求，进行优化。
    - `SetPseudoElementStyle()`: 设置伪元素的样式。

14. **动态浮动和定位变化的处理 (Handling Dynamic Float and Position Changes):**
    - `HandleDynamicFloatPositionChange()`:  当一个浮动或定位元素变为正常流元素时，调整布局树。

**用户或编程常见的使用错误举例:**

- **错误地假设包含块:**  开发者可能错误地认为某个元素是绝对定位或固定定位子元素的包含块，导致元素位置错误。例如，忘记给父元素设置 `position: relative`。
- **忽略 `transform` 或 `filter` 创建的包含块:** 开发者可能没有意识到父元素的 `transform` 或 `filter` 属性会创建新的包含块，导致子元素的绝对定位或固定定位行为不符合预期。
- **粘性定位的误用:** 开发者可能认为 `position: sticky` 可以相对于任何祖先元素进行粘性定位，而实际上它是相对于最近的可滚动祖先元素。

**总结:**

这部分代码定义了 `LayoutObject` 中负责管理元素定位、包含关系、滚动、视觉效果以及渲染失效的关键功能。它体现了浏览器渲染引擎在处理 CSS 布局和渲染方面的核心逻辑，并且与 JavaScript 和 HTML 的功能有着紧密的联系。这些功能确保了网页元素能够按照 CSS 规则正确地显示在屏幕上，并响应用户的交互。

Prompt: 
```
这是目录为blink/renderer/core/layout/layout_object.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第3部分，共6部分，请归纳一下它的功能

"""
t* candidate) {
    return candidate->CanContainFixedPositionObjects();
  });
}

LayoutBlock* LayoutObject::ContainingBlockForAbsolutePosition(
    AncestorSkipInfo* skip_info) const {
  NOT_DESTROYED();
  auto* container = ContainerForAbsolutePosition(skip_info);
  return container ? container->InclusiveContainingBlock(skip_info) : nullptr;
}

LayoutBlock* LayoutObject::ContainingBlockForFixedPosition(
    AncestorSkipInfo* skip_info) const {
  NOT_DESTROYED();
  auto* container = ContainerForFixedPosition(skip_info);
  return container ? container->InclusiveContainingBlock(skip_info) : nullptr;
}

LayoutBlock* LayoutObject::InclusiveContainingBlock(
    AncestorSkipInfo* skip_info) {
  NOT_DESTROYED();
  auto* layout_block = DynamicTo<LayoutBlock>(this);
  return layout_block ? layout_block : ContainingBlock(skip_info);
}

const PaintLayer* LayoutObject::ContainingScrollContainerLayer(
    bool ignore_layout_view_for_fixed_pos) const {
  NOT_DESTROYED();
  const PaintLayer* layer = EnclosingLayer();
  if (!layer) {
    return nullptr;
  }
  if (auto* box = layer->GetLayoutBox()) {
    if (box != this && box->IsScrollContainer()) {
      return layer;
    }
  }
  bool is_fixed_to_view = false;
  if (auto* scroll_container_layer =
          layer->ContainingScrollContainerLayer(&is_fixed_to_view)) {
    if (!is_fixed_to_view || !ignore_layout_view_for_fixed_pos) {
      return scroll_container_layer;
    }
  }
  return nullptr;
}

const LayoutBox* LayoutObject::ContainingScrollContainer(
    bool ignore_layout_view_for_fixed_pos) const {
  NOT_DESTROYED();
  if (const PaintLayer* scroll_container_layer =
          ContainingScrollContainerLayer(ignore_layout_view_for_fixed_pos)) {
    return scroll_container_layer->GetLayoutBox();
  }
  return nullptr;
}

LayoutObject* LayoutObject::NearestAncestorForElement() const {
  NOT_DESTROYED();
  LayoutObject* ancestor = Parent();
  while (ancestor && ancestor->IsAnonymous()) {
    ancestor = ancestor->Parent();
  }
  return ancestor;
}

bool LayoutObject::ComputeIsFixedContainer(const ComputedStyle* style) const {
  NOT_DESTROYED();
  if (!style)
    return false;
  if (IsViewTransitionRoot()) {
    return true;
  }
  bool is_document_element = IsDocumentElement();
  // https://www.w3.org/TR/filter-effects-1/#FilterProperty
  if (!is_document_element && style->HasNonInitialFilter())
    return true;
  // Backdrop-filter creates a containing block for fixed and absolute
  // positioned elements:
  // https://drafts.fxtf.org/filter-effects-2/#backdrop-filter-operation
  if (!is_document_element && style->HasNonInitialBackdropFilter())
    return true;
  // The LayoutView is always a container of fixed positioned descendants. In
  // addition, SVG foreignObjects become such containers, so that descendants
  // of a foreignObject cannot escape it. Similarly, text controls let authors
  // select elements inside that are created by user agent shadow DOM, and we
  // have (C++) code that assumes that the elements are indeed contained by the
  // text control. So just make sure this is the case.
  if (IsA<LayoutView>(this) || IsSVGForeignObject() || IsTextControl()) {
    return true;
  }

  // crbug.com/1153042: If <fieldset> is a fixed container, its anonymous
  // content box should be a fixed container.
  if (IsAnonymous() && Parent() && Parent()->IsFieldset() &&
      Parent()->CanContainFixedPositionObjects()) {
    return true;
  }

  // https://www.w3.org/TR/css-transforms-1/#containing-block-for-all-descendants

  // For transform-style specifically, we want to consider the computed
  // value rather than the used value.
  if (style->HasTransformRelatedProperty() ||
      style->TransformStyle3D() == ETransformStyle3D::kPreserve3d) {
    if (!IsInline() || IsAtomicInlineLevel())
      return true;
  }
  // https://www.w3.org/TR/css-contain-1/#containment-layout
  if (IsEligibleForPaintOrLayoutContainment() &&
      (ShouldApplyPaintContainment(*style) ||
       ShouldApplyLayoutContainment(*style) ||
       style->WillChangeProperties().Contains(CSSPropertyID::kContain)))
    return true;

  return false;
}

bool LayoutObject::ComputeIsAbsoluteContainer(
    const ComputedStyle* style) const {
  NOT_DESTROYED();
  if (!style)
    return false;
  return style->CanContainAbsolutePositionObjects() ||
         ComputeIsFixedContainer(style) ||
         // crbug.com/1153042: If <fieldset> is an absolute container, its
         // anonymous content box should be an absolute container.
         (IsAnonymous() && Parent() && Parent()->IsFieldset() &&
          Parent()->StyleRef().CanContainAbsolutePositionObjects());
}

const LayoutBoxModelObject* LayoutObject::FindFirstStickyContainer(
    const LayoutBox* below) const {
  const LayoutObject* maybe_sticky_ancestor = this;
  while (maybe_sticky_ancestor && maybe_sticky_ancestor != below) {
    if (maybe_sticky_ancestor->StyleRef().HasStickyConstrainedPosition()) {
      return To<LayoutBoxModelObject>(maybe_sticky_ancestor);
    }

    // We use LocationContainer here to find the nearest sticky ancestor which
    // shifts the given element's position so that the sticky positioning code
    // is aware ancestor sticky position shifts.
    maybe_sticky_ancestor =
        maybe_sticky_ancestor->IsLayoutInline()
            ? maybe_sticky_ancestor->Container()
            : To<LayoutBox>(maybe_sticky_ancestor)->LocationContainer();
  }
  return nullptr;
}

gfx::RectF LayoutObject::AbsoluteBoundingBoxRectF(
    MapCoordinatesFlags flags) const {
  NOT_DESTROYED();
  DCHECK(!(flags & kIgnoreTransforms));
  Vector<gfx::QuadF> quads;
  AbsoluteQuads(quads, flags);

  wtf_size_t n = quads.size();
  if (n == 0)
    return gfx::RectF();

  gfx::RectF result = quads[0].BoundingBox();
  for (wtf_size_t i = 1; i < n; ++i)
    result.Union(quads[i].BoundingBox());
  return result;
}

gfx::Rect LayoutObject::AbsoluteBoundingBoxRect(
    MapCoordinatesFlags flags) const {
  NOT_DESTROYED();
  DCHECK(!(flags & kIgnoreTransforms));
  Vector<gfx::QuadF> quads;
  AbsoluteQuads(quads, flags);

  wtf_size_t n = quads.size();
  if (!n)
    return gfx::Rect();

  gfx::RectF result;
  for (auto& quad : quads)
    result.Union(quad.BoundingBox());
  return gfx::ToEnclosingRect(result);
}

PhysicalRect LayoutObject::AbsoluteBoundingBoxRectHandlingEmptyInline(
    MapCoordinatesFlags flags) const {
  NOT_DESTROYED();
  return PhysicalRect::EnclosingRect(AbsoluteBoundingBoxRectF(flags));
}

PhysicalRect LayoutObject::AbsoluteBoundingBoxRectForScrollIntoView() const {
  NOT_DESTROYED();
  // Ignore sticky position offsets for the purposes of scrolling elements into
  // view. See https://www.w3.org/TR/css-position-3/#stickypos-scroll for
  // details

  const MapCoordinatesFlags flag =
      (RuntimeEnabledFeatures::CSSPositionStickyStaticScrollPositionEnabled())
          ? kIgnoreStickyOffset
          : 0;

  if (const auto* scroll_marker =
          DynamicTo<ScrollMarkerPseudoElement>(GetNode())) {
    // Scroll markers are reparented into a scroll marker group. We want the
    // rectangle of the originating element (or column).
    const Element* originating_element =
        scroll_marker->UltimateOriginatingElement();
    const auto* originating_object = originating_element->GetLayoutObject();
    const auto* column_pseudo =
        DynamicTo<ColumnPseudoElement>(scroll_marker->parentNode());
    if (!column_pseudo) {
      return originating_object->AbsoluteBoundingBoxRectForScrollIntoView();
    }
    // This is a ::column::scroll-marker
    const auto* scroller = originating_element->GetLayoutBoxForScrolling();
    PhysicalRect bounds = column_pseudo->ColumnRect();
    bounds.offset -= PhysicalOffset::FromVector2dFRound(
        scroller->GetScrollableArea()->GetScrollOffset());
    return scroller->LocalToAbsoluteRect(bounds, flag);
  }

  return AbsoluteBoundingBoxRectHandlingEmptyInline(flag);
}

void LayoutObject::AddAbsoluteRectForLayer(gfx::Rect& result) {
  NOT_DESTROYED();
  if (HasLayer())
    result.Union(AbsoluteBoundingBoxRect());
  for (LayoutObject* current = SlowFirstChild(); current;
       current = current->NextSibling())
    current->AddAbsoluteRectForLayer(result);
}

gfx::Rect LayoutObject::AbsoluteBoundingBoxRectIncludingDescendants() const {
  NOT_DESTROYED();
  gfx::Rect result = AbsoluteBoundingBoxRect();
  for (LayoutObject* current = SlowFirstChild(); current;
       current = current->NextSibling())
    current->AddAbsoluteRectForLayer(result);
  return result;
}

void LayoutObject::Paint(const PaintInfo&) const {
  NOT_DESTROYED();
}

RecalcScrollableOverflowResult LayoutObject::RecalcScrollableOverflow() {
  NOT_DESTROYED();
  ClearSelfNeedsScrollableOverflowRecalc();
  if (!ChildNeedsScrollableOverflowRecalc()) {
    return RecalcScrollableOverflowResult();
  }

  ClearChildNeedsScrollableOverflowRecalc();
  bool children_scrollable_overflow_changed = false;
  for (LayoutObject* current = SlowFirstChild(); current;
       current = current->NextSibling()) {
    children_scrollable_overflow_changed |=
        current->RecalcScrollableOverflow().scrollable_overflow_changed;
  }
  return {children_scrollable_overflow_changed,
          /* rebuild_fragment_tree */ false};
}

void LayoutObject::RecalcVisualOverflow() {
  NOT_DESTROYED();
  for (LayoutObject* current = SlowFirstChild(); current;
       current = current->NextSibling()) {
    if (current->HasLayer() &&
        To<LayoutBoxModelObject>(current)->HasSelfPaintingLayer())
      continue;
    current->RecalcVisualOverflow();
  }
}

void LayoutObject::RecalcNormalFlowChildVisualOverflowIfNeeded() {
  NOT_DESTROYED();
  if (IsOutOfFlowPositioned() ||
      (HasLayer() && To<LayoutBoxModelObject>(this)->HasSelfPaintingLayer()))
    return;
  RecalcVisualOverflow();
}

void LayoutObject::InvalidateVisualOverflow() {
  if (!IsInLayoutNGInlineFormattingContext() && !IsLayoutNGObject() &&
      !IsLayoutBlock() && !NeedsLayout()) {
    // TODO(crbug.com/1128199): This is still needed because
    // RecalcVisualOverflow() does not actually compute the visual overflow
    // for inline elements (legacy layout). However in LayoutNG
    // RecalcInlineChildrenInkOverflow() is called and visual overflow is
    // recomputed properly so we don't need this (see crbug.com/1043927).
    SetNeedsLayoutAndIntrinsicWidthsRecalc(
        layout_invalidation_reason::kStyleChange);
  } else {
    if (IsInLayoutNGInlineFormattingContext() && !NeedsLayout()) {
      if (auto* text = DynamicTo<LayoutText>(this)) {
        text->InvalidateVisualOverflow();
      }
    }
    PaintingLayer()->SetNeedsVisualOverflowRecalc();
    // TODO(crbug.com/1385848): This looks like an over-invalidation.
    // visual overflow change should not require checking for layout change.
    SetShouldCheckForPaintInvalidation();
  }
}

#if DCHECK_IS_ON()
void LayoutObject::InvalidateVisualOverflowForDCheck() {
  if (auto* box = DynamicTo<LayoutBox>(this)) {
    for (const PhysicalBoxFragment& fragment : box->PhysicalFragments()) {
      fragment.GetMutableForPainting().InvalidateInkOverflow();
    }
  }
  // For now, we can only check |LayoutBox| laid out by NG.
}
#endif

bool LayoutObject::HasDistortingVisualEffects() const {
  NOT_DESTROYED();
  // TODO(szager): Check occlusion information propagated from out-of-process
  // parent frame.

  auto& first_fragment = EnclosingLayer()->GetLayoutObject().FirstFragment();
  // This can happen for an iframe element which is outside the viewport and has
  // therefore never been painted. In that case, we do the safe thing -- report
  // it as having distorting visual effects.
  if (!first_fragment.HasLocalBorderBoxProperties())
    return true;
  auto paint_properties = first_fragment.LocalBorderBoxProperties();

  // No filters, no blends, no opacity < 100%.
  for (const auto* effect = &paint_properties.Effect().Unalias(); effect;
       effect = effect->UnaliasedParent()) {
    if (effect->HasRealEffects())
      return true;
  }

  auto& local_frame_root = GetDocument().GetFrame()->LocalFrameRoot();
  auto& root_fragment = local_frame_root.ContentLayoutObject()->FirstFragment();
  CHECK(root_fragment.HasLocalBorderBoxProperties());
  const auto& root_properties = root_fragment.LocalBorderBoxProperties();

  // The only allowed transforms are 2D translation and proportional up-scaling.
  gfx::Transform projection = GeometryMapper::SourceToDestinationProjection(
      paint_properties.Transform(), root_properties.Transform());
  if (!projection.Is2dProportionalUpscaleAndOr2dTranslation())
    return true;

  return false;
}

bool LayoutObject::HasNonZeroEffectiveOpacity() const {
  NOT_DESTROYED();
  const FragmentData& fragment =
      EnclosingLayer()->GetLayoutObject().FirstFragment();

  // This can happen for an iframe element which is outside the viewport and has
  // therefore never been painted. In that case, we do the safe thing -- report
  // it as having non-zero opacity -- since this method is used by
  // IntersectionObserver to detect occlusion.
  if (!fragment.HasLocalBorderBoxProperties())
    return true;

  const auto& paint_properties = fragment.LocalBorderBoxProperties();

  for (const auto* effect = &paint_properties.Effect().Unalias(); effect;
       effect = effect->UnaliasedParent()) {
    if (effect->Opacity() == 0.0)
      return false;
  }
  return true;
}

String LayoutObject::DecoratedName() const {
  NOT_DESTROYED();
  StringBuilder name;
  name.Append(GetName());

  Vector<const char*> attributes;
  if (IsAnonymous()) {
    attributes.push_back("anonymous");
  }
  // FIXME: Remove the special case for LayoutView here (requires rebaseline of
  // all tests).
  if (IsOutOfFlowPositioned() && !IsA<LayoutView>(this)) {
    attributes.push_back("positioned");
  }
  if (IsRelPositioned()) {
    attributes.push_back("relative positioned");
  }
  if (IsStickyPositioned()) {
    attributes.push_back("sticky positioned");
  }
  if (IsFloating()) {
    attributes.push_back("floating");
  }
  if (SpannerPlaceholder()) {
    attributes.push_back("column spanner");
  }
  if (IsLayoutBlock() && IsInline()) {
    attributes.push_back("inline");
  }
  if (IsLayoutReplaced() && !IsInline()) {
    attributes.push_back("block");
  }
  if (IsLayoutBlockFlow() && ChildrenInline() && SlowFirstChild()) {
    attributes.push_back("children-inline");
  }
  if (!attributes.empty()) {
    name.Append(" (");
    name.Append(attributes[0]);
    for (wtf_size_t i = 1; i < attributes.size(); ++i) {
      name.Append(", ");
      name.Append(attributes[i]);
    }
    name.Append(")");
  }

  return name.ToString();
}

String LayoutObject::ToString() const {
  StringBuilder builder;
  builder.Append(DecoratedName());
  if (const Node* node = GetNode()) {
    builder.Append(' ');
    builder.Append(node->ToString());
  }
  return builder.ToString();
}

String LayoutObject::DebugName() const {
  NOT_DESTROYED();
  StringBuilder name;
  name.Append(DecoratedName());

  if (const Node* node = GetNode()) {
    name.Append(' ');
    name.Append(node->DebugName());
  }
  return name.ToString();
}

DOMNodeId LayoutObject::OwnerNodeId() const {
  NOT_DESTROYED();
  return GetNode() ? GetNode()->GetDomNodeId() : kInvalidDOMNodeId;
}

void LayoutObject::InvalidateDisplayItemClients(
    PaintInvalidationReason reason) const {
  NOT_DESTROYED();
  // This default implementation invalidates only the object itself as a
  // DisplayItemClient.
  ObjectPaintInvalidator(*this).InvalidateDisplayItemClient(*this, reason);
}

PhysicalRect LayoutObject::AbsoluteSelectionRect() const {
  NOT_DESTROYED();
  PhysicalRect selection_rect = LocalSelectionVisualRect();
  if (!selection_rect.IsEmpty())
    MapToVisualRectInAncestorSpace(View(), selection_rect);

  if (LocalFrameView* frame_view = GetFrameView())
    return frame_view->DocumentToFrame(selection_rect);

  return selection_rect;
}

DISABLE_CFI_PERF
void LayoutObject::InvalidatePaint(
    const PaintInvalidatorContext& context) const {
  NOT_DESTROYED();
  ObjectPaintInvalidatorWithContext(*this, context).InvalidatePaint();
}

bool LayoutObject::MapToVisualRectInAncestorSpaceInternalFastPath(
    const LayoutBoxModelObject* ancestor,
    gfx::RectF& rect,
    VisualRectFlags visual_rect_flags,
    bool& intersects) const {
  NOT_DESTROYED();
  intersects = true;
  if (!(visual_rect_flags & kUseGeometryMapper) || !ancestor ||
      !ancestor->FirstFragment().HasLocalBorderBoxProperties())
    return false;

  if (ancestor == this)
    return true;

  AncestorSkipInfo skip_info(ancestor);
  PropertyTreeState container_properties(PropertyTreeState::kUninitialized);
  const LayoutObject* property_container = GetPropertyContainer(
      &skip_info, &container_properties, visual_rect_flags);
  if (!property_container)
    return false;

  // This works because it's not possible to have any intervening clips,
  // effects, transforms between |this| and |property_container|, and therefore
  // FirstFragment().PaintOffset() is relative to the transform space defined by
  // FirstFragment().LocalBorderBoxProperties() (if this == property_container)
  // or property_container->FirstFragment().ContentsProperties().
  rect.Offset(gfx::Vector2dF(FirstFragment().PaintOffset()));
  if (property_container != ancestor) {
    FloatClipRect clip_rect(rect);
    intersects = GeometryMapper::LocalToAncestorVisualRect(
        container_properties, ancestor->FirstFragment().ContentsProperties(),
        clip_rect, kIgnoreOverlayScrollbarSize, visual_rect_flags);
    rect = clip_rect.Rect();
  }
  rect.Offset(-gfx::Vector2dF(ancestor->FirstFragment().PaintOffset()));
  return true;
}

bool LayoutObject::MapToVisualRectInAncestorSpace(
    const LayoutBoxModelObject* ancestor,
    PhysicalRect& rect,
    VisualRectFlags visual_rect_flags) const {
  NOT_DESTROYED();
  gfx::RectF float_rect(rect);

  bool intersects = true;
  if (MapToVisualRectInAncestorSpaceInternalFastPath(
          ancestor, float_rect, visual_rect_flags, intersects)) {
    rect = PhysicalRect::EnclosingRect(float_rect);
    return intersects;
  }
  TransformState transform_state(TransformState::kApplyTransformDirection,
                                 gfx::QuadF(float_rect));
  intersects = MapToVisualRectInAncestorSpaceInternal(ancestor, transform_state,
                                                      visual_rect_flags);
  transform_state.Flatten();
  rect = PhysicalRect::EnclosingRect(
      transform_state.LastPlanarQuad().BoundingBox());
  return intersects;
}

bool LayoutObject::MapToVisualRectInAncestorSpace(
    const LayoutBoxModelObject* ancestor,
    gfx::RectF& rect,
    VisualRectFlags visual_rect_flags) const {
  NOT_DESTROYED();
  bool intersects = true;
  if (MapToVisualRectInAncestorSpaceInternalFastPath(
          ancestor, rect, visual_rect_flags, intersects)) {
    return intersects;
  }

  TransformState transform_state(TransformState::kApplyTransformDirection,
                                 gfx::QuadF(rect));
  intersects = MapToVisualRectInAncestorSpaceInternal(ancestor, transform_state,
                                                      visual_rect_flags);
  transform_state.Flatten();
  rect = transform_state.LastPlanarQuad().BoundingBox();
  return intersects;
}

bool LayoutObject::MapToVisualRectInAncestorSpaceInternal(
    const LayoutBoxModelObject* ancestor,
    TransformState& transform_state,
    VisualRectFlags visual_rect_flags) const {
  NOT_DESTROYED();
  // For any layout object that doesn't override this method (the main example
  // is LayoutText), the rect is assumed to be in the parent's coordinate space,
  // except for container flip.

  if (ancestor == this)
    return true;

  if (LayoutObject* parent = Parent()) {
    if (parent->IsBox()) {
      bool preserve3d = parent->StyleRef().Preserves3D() && !parent->IsText();
      TransformState::TransformAccumulation accumulation =
          preserve3d ? TransformState::kAccumulateTransform
                     : TransformState::kFlattenTransform;

      if (parent != ancestor &&
          !To<LayoutBox>(parent)->MapContentsRectToBoxSpace(
              transform_state, accumulation, *this, visual_rect_flags))
        return false;
    }
    return parent->MapToVisualRectInAncestorSpaceInternal(
        ancestor, transform_state, visual_rect_flags);
  }
  return true;
}

const LayoutObject* LayoutObject::GetPropertyContainer(
    AncestorSkipInfo* skip_info,
    PropertyTreeStateOrAlias* container_properties,
    VisualRectFlags visual_rect_flags) const {
  NOT_DESTROYED();
  const LayoutObject* property_container = this;
  while (!property_container->FirstFragment().HasLocalBorderBoxProperties()) {
    property_container = property_container->Container(skip_info);
    if (!property_container || (skip_info && skip_info->AncestorSkipped()) ||
        property_container->IsFragmented()) {
      return nullptr;
    }
  }
  if (container_properties) {
    if (property_container == this) {
      *container_properties = FirstFragment().LocalBorderBoxProperties();

      if (visual_rect_flags & kIgnoreLocalClipPath) {
        if (auto* properties =
                property_container->FirstFragment().PaintProperties()) {
          if (auto* clip_path_clip = properties->ClipPathClip()) {
            container_properties->SetClip(*clip_path_clip->Parent());
          }
        }
      }
    } else {
      *container_properties =
          property_container->FirstFragment().ContentsProperties();
    }
  }

  return property_container;
}

HitTestResult LayoutObject::HitTestForOcclusion(
    const PhysicalRect& hit_rect) const {
  NOT_DESTROYED();
  LocalFrame* frame = GetDocument().GetFrame();
  DCHECK(!frame->View()->NeedsLayout());
  HitTestRequest::HitTestRequestType hit_type =
      HitTestRequest::kIgnorePointerEventsNone | HitTestRequest::kReadOnly |
      HitTestRequest::kIgnoreClipping |
      HitTestRequest::kIgnoreZeroOpacityObjects |
      HitTestRequest::kHitTestVisualOverflow;
  HitTestLocation location(hit_rect);
  return frame->GetEventHandler().HitTestResultAtLocation(location, hit_type,
                                                          this, true);
}

std::ostream& operator<<(std::ostream& out, const LayoutObject& object) {
  String info;
#if DCHECK_IS_ON()
  StringBuilder string_builder;
  object.DumpLayoutObject(string_builder, false, 0);
  info = string_builder.ToString();
#else
  info = object.DebugName();
#endif
  return out << static_cast<const void*>(&object) << ":" << info.Utf8();
}

std::ostream& operator<<(std::ostream& out, const LayoutObject* object) {
  if (!object)
    return out << "<null>";
  return out << *object;
}

#if DCHECK_IS_ON()

void LayoutObject::ShowTreeForThis() const {
  NOT_DESTROYED();
  if (GetNode())
    ::ShowTree(GetNode());
}

void LayoutObject::ShowLayoutTreeForThis() const {
  NOT_DESTROYED();
  ShowLayoutTree(this, nullptr);
}

void LayoutObject::ShowLayoutObject() const {
  NOT_DESTROYED();

  if (getenv("RUNNING_UNDER_RR")) {
    // Printing timestamps requires an IPC to get the local time, which
    // does not work in an rr replay session. Just disable timestamp printing
    // globally, since we don't need them. Affecting global state isn't a
    // problem because invoking this from a rr session creates a temporary
    // program environment that will be destroyed as soon as the invocation
    // completes.
    logging::SetLogItems(true, true, false, false);
  }

  StringBuilder string_builder;
  DumpLayoutObject(string_builder, true, kShowTreeCharacterOffset);
  DLOG(INFO) << "\n" << string_builder.ToString().Utf8();
}

void LayoutObject::DumpLayoutObject(StringBuilder& string_builder,
                                    bool dump_address,
                                    unsigned show_tree_character_offset) const {
  // This function doesn't call `NOT_DESTROYED()` to aid debugging.
#if DCHECK_IS_ON()
  std::optional<base::AutoReset<bool>> is_destroyed;
  if (is_destroyed_) {
    string_builder.Append("[DESTROYED] ");

    // Temporarily reset `is_destroyed_` to make dumping possible. Code and
    // functions in this function must be safe to call for a destroyed object.
    is_destroyed.emplace(const_cast<bool*>(&is_destroyed_), false);
  }
#endif  // DCHECK_IS_ON()

  string_builder.Append(DecoratedName());

  if (dump_address)
    string_builder.AppendFormat(" %p", this);

  if (IsText() && To<LayoutText>(this)->IsTextFragment()) {
    string_builder.AppendFormat(
        " \"%s\" ", To<LayoutText>(this)->TransformedText().Ascii().c_str());
  }

  if (GetNode()) {
    while (string_builder.length() < show_tree_character_offset)
      string_builder.Append(' ');
    string_builder.Append('\t');
    string_builder.Append(GetNode()->ToString());
  }
  if (ChildLayoutBlockedByDisplayLock())
    string_builder.Append(" (display-locked)");
}

void LayoutObject::DumpLayoutTreeAndMark(StringBuilder& string_builder,
                                         const LayoutObject* marked_object1,
                                         const char* marked_label1,
                                         const LayoutObject* marked_object2,
                                         const char* marked_label2,
                                         unsigned depth) const {
  NOT_DESTROYED();
  StringBuilder object_info;
  if (marked_object1 == this && marked_label1)
    object_info.Append(marked_label1);
  if (marked_object2 == this && marked_label2)
    object_info.Append(marked_label2);
  while (object_info.length() < depth * 2)
    object_info.Append(' ');

  DumpLayoutObject(object_info, true, kShowTreeCharacterOffset);
  string_builder.Append(object_info);

  if (!ChildLayoutBlockedByDisplayLock()) {
    for (const LayoutObject* child = SlowFirstChild(); child;
         child = child->NextSibling()) {
      string_builder.Append('\n');
      child->DumpLayoutTreeAndMark(string_builder, marked_object1,
                                   marked_label1, marked_object2, marked_label2,
                                   depth + 1);
    }
  }
}

#endif  // DCHECK_IS_ON()

bool LayoutObject::IsSelected() const {
  NOT_DESTROYED();
  // Keep this fast and small, used in very hot functions to skip computing
  // selection when this is not selected. This function may be inlined in
  // link-optimized builds, but keeping fast and small helps running perf
  // tests.
  return GetSelectionState() != SelectionState::kNone ||
         // TODO(kojii): Can't we set SelectionState() properly to
         // LayoutTextFragment too?
         (IsA<LayoutTextFragment>(*this) && LayoutSelection::IsSelected(*this));
}

bool LayoutObject::IsSelectable() const {
  NOT_DESTROYED();
  return StyleRef().IsSelectable();
}

const ComputedStyle& LayoutObject::SlowEffectiveStyle(
    StyleVariant style_variant) const {
  NOT_DESTROYED();
  switch (style_variant) {
    case StyleVariant::kStandard:
      return StyleRef();
    case StyleVariant::kFirstLine:
      if (IsInline() && IsAtomicInlineLevel())
        return StyleRef();
      return FirstLineStyleRef();
    case StyleVariant::kStandardEllipsis:
      // The ellipsis is styled according to the line style.
      // https://www.w3.org/TR/css-overflow-3/#ellipsing-details
      DCHECK(IsInline());
      if (const LayoutObject* block = ContainingBlock()) {
        return block->StyleRef();
      }
      return StyleRef();
    case StyleVariant::kFirstLineEllipsis:
      DCHECK(IsInline());
      if (const LayoutObject* block = ContainingBlock()) {
        return block->FirstLineStyleRef();
      }
      return FirstLineStyleRef();
  }
  NOTREACHED();
}

// Called when an object that was floating or positioned becomes a normal flow
// object again. We have to make sure the layout tree updates as needed to
// accommodate the new normal flow object.
static inline void HandleDynamicFloatPositionChange(LayoutObject* object) {
  // We have gone from not affecting the inline status of the parent flow to
  // suddenly having an impact.  See if there is a mismatch between the parent
  // flow's childrenInline() state and our state.
  object->SetInline(object->StyleRef().IsDisplayInlineType());
  if (object->IsInline() != object->Parent()->ChildrenInline()) {
    if (!object->IsInline()) {
      To<LayoutBoxModelObject>(object->Parent())->ChildBecameNonInline(object);
    } else {
      // An anonymous block must be made to wrap this inline.
      LayoutBlock* block =
          To<LayoutBlock>(object->Parent())->CreateAnonymousBlock();
      LayoutObjectChildList* childlist = object->Parent()->VirtualChildren();
      childlist->InsertChildNode(object->Parent(), block, object);
      block->Children()->AppendChildNode(
          block, childlist->RemoveChildNode(object->Parent(), object));
    }
  }
}

StyleDifference LayoutObject::AdjustStyleDifference(
    StyleDifference diff) const {
  NOT_DESTROYED();
  if (diff.TransformChanged() && IsSVG()) {
    // Skip a full layout for transforms at the html/svg boundary which do not
    // affect sizes inside SVG.
    if (!IsSVGRoot())
      diff.SetNeedsFullLayout();
  }

  // Optimization: for decoration/color property changes, invalidation is only
  // needed if we have style or text affected by these properties.
  if (diff.TextDecorationOrColorChanged() &&
      !diff.NeedsNormalPaintInvalidation() &&
      !diff.NeedsSimplePaintInvalidation()) {
    if (StyleRef().HasOutlineWithCurrentColor() ||
        StyleRef().HasBackgroundRelatedColorReferencingCurrentColor() ||
        // Skip any text nodes that do not contain text boxes. Whitespace cannot
        // be skipped or we will miss invalidating decorations (e.g.,
        // underlines). MathML elements are not skipped either as some of them
        // do special painting (e.g. fraction bar).
        (IsText() && !IsBR() && To<LayoutText>(this)->HasInlineFragments()) ||
        (IsSVG() && StyleRef().IsFillColorCurrentColor()) ||
        (IsSVG() && StyleRef().IsStrokeColorCurrentColor()) || IsMathML()) {
      diff.SetNeedsSimplePaintInvalidation();
    }
  }

  // TODO(1088373): Pixel_WebGLHighToLowPower fails without this. This isn't the
  // right way to ensure GPU switching. Investigate and do it in the right way.
  if (!diff.NeedsNormalPaintInvalidation() && IsLayoutView() && Style() &&
      !Style()->GetFont().IsFallbackValid()) {
    diff.SetNeedsNormalPaintInvalidation();
  }

  // The answer to layerTypeRequired() for plugins, iframes, and canvas can
  // change without the actual style changing, since it depends on whether we
  // decide to composite these elements. When the/ layer status of one of these
  // elements changes, we need to force a layout.
  if (!diff.NeedsFullLayout() && Style() && IsBoxModelObject()) {
    bool requires_layer =
        To<LayoutBoxModelObject>(this)->LayerTypeRequired() != kNoPaintLayer;
    if (HasLayer() != requires_layer)
      diff.SetNeedsFullLayout();
  }

  return diff;
}

void LayoutObject::SetPseudoElementStyle(const LayoutObject& owner,
                                         bool match_parent_size) {
  NOT_DESTROYED();
  const ComputedStyle* pseudo_style = owner.Style();
  DCHECK(pseudo_style->StyleType() == kPseudoIdCheck ||
         pseudo_style->StyleType() == kPseudoIdBefore ||
         pseudo_style->StyleType() == kPseudoIdAfter ||
         pseudo_style->StyleType() == kPseudoIdSelectArrow ||
         pseudo_style->StyleType() == kPseudoIdMarker ||
         pseudo_style->StyleType() == kPseudoIdFirstLetter ||
         pseudo_style->StyleType() == kPseudoIdScrollMarkerGroup ||
         pseudo_style->IsPageMarginBox() ||
         pseudo_style->StyleType() == kPseudoIdScrollMarker ||
         pseudo_style->StyleType() == kPseudoIdScrollNextButton ||
         pseudo_style->StyleType() == kPseudoIdScrollPrevButton);

  InheritIsInDetachedNonDomTree(owner);

  // FIXME: We should consider just making all pseudo items use an inherited
  // style.

  // Images are special and must inherit the pseudoStyle so the width and height
  // of the pseudo element doesn't change the size of the image. In all other
  // cases we can just share the style.
  //
  // Quotes are also LayoutInline, so we need to create an inherited style to
  // avoid getting an inline with positioning or an invalid display.
  //
  if (IsImage() || IsQuote()) {
    ComputedStyleBuilder builder =
        GetDocument()
            .GetStyleResolver()
            .CreateComputedStyleBuilderInheritingFrom(*pseudo_style);
    if (match_parent_size) {
      DCHECK(IsImage());
      builder.SetWidth(Length::Percent(100));
      builder.SetHeight(Length::Percent(100));
    }
    SetStyle(builder.TakeStyle());
    return;
  }
"""


```