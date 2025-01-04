Response:
My thinking process to answer the request goes like this:

1. **Understand the Goal:** The request asks for a breakdown of the `BoxBackgroundPaintContext` class in the Chromium Blink rendering engine. This includes its purpose, relationships to web technologies, logic, potential errors, and how a user might trigger its use.

2. **Initial Scan for Keywords and Concepts:** I quickly scan the code for key terms and concepts that stand out. These include:
    * `paint`, `background`, `border`, `padding`, `fragment`, `layout`, `style`, `viewport`, `fixed`, `image`, `table`, `page`, `offset`, `positioning`.
    * Class names like `LayoutView`, `LayoutBox`, `LayoutTableCell`, `PhysicalBoxFragment`, `ComputedStyle`, `PaintInfo`.
    * The namespace `blink`.

3. **Identify Core Functionality:** Based on the keywords, the class's name, and the included headers, I deduce the primary function: managing the painting of backgrounds and related decorations (borders, padding) for HTML elements. The "context" part suggests it provides the necessary information and settings for this painting process.

4. **Analyze Constructors:** The constructors reveal how `BoxBackgroundPaintContext` is instantiated and for what types of elements:
    * `LayoutView`: Painting the root element's background.
    * `LayoutBoxModelObject`: General case for most elements.
    * `LayoutTableCell`: Special handling for table cell backgrounds.
    * `PhysicalBoxFragment`:  Crucial for handling fragmented content (like multi-page layouts or elements split across lines).

5. **Examine Key Methods:** I then look at the important methods to understand their roles:
    * `BorderOutsets`, `PaddingOutsets`, `VisualOverflowOutsets`: These clearly deal with calculating the dimensions of borders, padding, and overflow.
    * `ComputePositioningArea`, `NormalPositioningArea`, `FixedAttachmentPositioningArea`:  These manage how the background image is positioned, particularly the difference between `fixed` and `scroll` attachment.
    * `ShouldUseFixedAttachment`, `HasBackgroundFixedToViewport`, `CanCompositeBackgroundAttachmentFixed`: These methods determine if and how `background-attachment: fixed` is handled.
    * `OffsetInBackground`:  Calculates the starting offset for background images, important for tiled or fragmented backgrounds.
    * Methods dealing with borders (`InnerBorderOutsets`, `ObscuredBorderOutsets`): Handle situations where borders might cover the background.

6. **Connect to Web Technologies (HTML, CSS, JavaScript):**
    * **HTML:** The class operates on the rendered representation of HTML elements (represented by `LayoutBox`, `LayoutTableCell`, etc.).
    * **CSS:**  The class heavily relies on `ComputedStyle` to access CSS properties like `background-image`, `background-color`, `background-repeat`, `background-position`, `background-attachment`, `border-*`, `padding-*`, and `box-decoration-break`. I make explicit connections to specific CSS properties in my answer.
    * **JavaScript:** While this C++ code doesn't directly *execute* JavaScript, JavaScript can manipulate the DOM and CSS styles, which in turn triggers the layout and painting processes that use this class. I explain how JS interactions can indirectly lead to this code being executed.

7. **Identify Logic and Assumptions:** I look for conditional logic (`if` statements) and any calculations that indicate specific scenarios being handled. The handling of fragmented content, `background-attachment: fixed`, and table backgrounds are good examples. I try to create simple "input/output" scenarios to illustrate this logic.

8. **Consider Potential Errors:** I think about what could go wrong. Common web development mistakes related to backgrounds and borders come to mind:
    * Incorrect use of `background-attachment: fixed` in transformed elements.
    * Misunderstanding how `box-decoration-break` affects background painting across fragments.
    * Overlapping borders obscuring backgrounds.

9. **Trace User Actions (Debugging Context):** I work backward from the functionality. If this code paints backgrounds, what user actions lead to backgrounds being displayed?  Loading a page, scrolling, resizing the window, and JavaScript-driven style changes are all relevant. I outline a step-by-step scenario for debugging.

10. **Structure the Answer:** I organize my findings into logical categories based on the request's prompts:
    * Functionality.
    * Relationship to web technologies (with examples).
    * Logical inference (with hypothetical inputs/outputs).
    * Common user errors.
    * Debugging context.

11. **Refine and Clarify:**  I review my answer for clarity, accuracy, and completeness. I ensure the language is understandable and the examples are helpful. I try to avoid overly technical jargon where possible, or explain it when necessary. I make sure to explicitly address each part of the original request.

By following this process, I can effectively dissect the C++ code and provide a comprehensive explanation of its role in the browser's rendering engine and its relationship to web technologies.
这个C++源代码文件 `box_background_paint_context.cc` 定义了 `BoxBackgroundPaintContext` 类，该类在 Chromium Blink 渲染引擎中负责处理 HTML 元素的背景和边框的绘制过程。它提供了一个上下文环境，包含了绘制背景和边框所需的信息和方法。

以下是 `BoxBackgroundPaintContext` 的主要功能：

**1. 管理背景和边框绘制所需的上下文信息:**

* **关联 LayoutObject:**  它与一个 `LayoutBoxModelObject` 或其子类（如 `LayoutView`, `LayoutBox`, `LayoutTableCell`）关联，表示要绘制背景的元素。
* **处理 Fragmented 内容:**  对于被分割成多个片段的元素（例如，跨多页打印的元素，或使用 `box-decoration-break: slice` 的元素），它能正确计算每个片段的背景偏移和尺寸。
* **处理 `background-attachment: fixed`:**  它能正确处理背景固定到视口的情况，并考虑祖先元素的 transform 属性对固定背景的影响。
* **处理表格背景:**  对于表格单元格，它可以处理单元格自身以及容器（表格的某个部分）的背景绘制。
* **提供边框和内边距信息:** 它计算元素的边框宽度、内边距大小，以及视觉溢出的大小，这些信息用于精确绘制背景和边框。

**2. 计算背景的定位区域 (Positioning Area):**

* **普通定位区域:**  默认情况下，背景的定位区域是元素的内容框 (content box)。
* **固定定位区域:** 对于 `background-attachment: fixed` 的元素，定位区域是视口 (viewport)。
* **处理 Fragmented 内容的定位区域:**  对于被分割的元素，它会计算出一个虚拟的、缝合在一起的区域，用于背景的定位。

**3. 提供用于绘制的辅助方法:**

* **`BorderOutsets()` 和 `PaddingOutsets()`:** 返回边框和内边距的大小。
* **`VisualOverflowOutsets()`:** 返回视觉溢出的大小。
* **`InnerBorderOutsets()`:** 计算内边框的偏移量。
* **`ObscuredBorderOutsets()`:**  计算可能会遮挡背景的边框的偏移量。
* **`ComputePositioningArea()`:** 根据不同的情况计算背景的定位区域。
* **`OffsetInBackground()`:** 计算背景图像的起始偏移量。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`BoxBackgroundPaintContext` 直接服务于 CSS 样式的渲染，最终影响用户在 HTML 页面上看到的效果。JavaScript 可以动态修改 HTML 结构和 CSS 样式，从而间接地影响 `BoxBackgroundPaintContext` 的行为。

* **HTML:**  HTML 结构定义了元素的层级关系和类型，`BoxBackgroundPaintContext` 需要根据元素的类型（例如，`<div>`, `<table>`, `<td>`）进行不同的处理。
    * **例：** 当 HTML 中有一个 `<div>` 元素时，渲染引擎会为其创建一个 `LayoutBox` 对象，`BoxBackgroundPaintContext` 可能被用来绘制该 `<div>` 的背景。

* **CSS:**  CSS 样式规则（例如 `background-color`, `background-image`, `border`, `padding`, `background-attachment`, `box-decoration-break`) 直接决定了 `BoxBackgroundPaintContext` 如何绘制背景和边框。
    * **例：**
        * **`background-color: red;`:**  `BoxBackgroundPaintContext` 会使用红色填充元素的背景区域。
        * **`background-image: url(image.png);`:** `BoxBackgroundPaintContext` 会加载并绘制指定的背景图片。
        * **`border: 1px solid black;`:** `BoxBackgroundPaintContext` 会绘制黑色的边框。
        * **`padding: 10px;`:** `BoxBackgroundPaintContext` 在计算背景区域时会考虑到内边距。
        * **`background-attachment: fixed;`:** `BoxBackgroundPaintContext` 会将背景固定到视口，即使页面滚动背景也不会移动。
        * **`box-decoration-break: clone;` 或 `slice;`:**  这会影响在元素被分割成多个片段时背景和边框的绘制方式，`BoxBackgroundPaintContext` 会根据此属性计算每个片段的背景偏移。

* **JavaScript:** JavaScript 可以通过 DOM API 修改元素的样式，从而触发重新布局和重绘，其中就可能包括 `BoxBackgroundPaintContext` 的使用。
    * **例：**
        ```javascript
        const divElement = document.getElementById('myDiv');
        divElement.style.backgroundColor = 'blue'; // 修改背景颜色
        divElement.style.border = '2px dashed green'; // 修改边框
        ```
        这段 JavaScript 代码会修改元素的背景色和边框，导致渲染引擎重新调用相关的绘制逻辑，包括使用 `BoxBackgroundPaintContext` 来绘制新的背景和边框。

**逻辑推理与假设输入输出:**

**假设输入:**

* 一个 `LayoutBox` 对象，表示一个 `<div>` 元素。
* 该元素的 CSS 样式为：`background-color: yellow; border: 2px solid black; padding: 5px;`
* 元素的布局信息（位置和大小）。

**逻辑推理:**

1. `BoxBackgroundPaintContext` 被创建并与该 `LayoutBox` 对象关联。
2. `BorderOutsets()` 方法会返回 `PhysicalBoxStrut(2, 2, 2, 2)` (假设所有边框宽度相同)。
3. `PaddingOutsets()` 方法会返回 `PhysicalBoxStrut(5, 5, 5, 5)`。
4. 在绘制背景时，`BoxBackgroundPaintContext` 会使用黄色填充元素的内边距区域。
5. 在绘制边框时，`BoxBackgroundPaintContext` 会在内边距之外绘制黑色的实线边框。

**假设输出:**

最终渲染结果是，该 `<div>` 元素会有一个黄色的背景，周围是黑色的 2px 实线边框，内容与边框之间有 5px 的内边距。

**用户或编程常见的使用错误:**

* **错误地假设 `background-attachment: fixed` 在所有情况下都相对于视口:**  当元素有 `transform` 属性时，`background-attachment: fixed` 的行为会变为 `scroll`。开发者可能会误认为背景会固定在视口上，但实际上会随着元素滚动。
    * **例：** 一个设置了 `transform: translateZ(0)` 的 `div` 元素，其子元素的 `background-attachment: fixed` 将不会固定到视口。
* **混淆 `box-decoration-break: clone` 和 `slice` 的效果:** 开发者可能不理解这两个属性在元素被分割时的区别，导致背景和边框的渲染效果不符合预期。
    * **例：**  在一个跨页打印的 `<div>` 元素上，如果设置了 `box-decoration-break: clone;`，每一页都会重复绘制完整的背景和边框。如果设置了 `box-decoration-break: slice;`，背景和边框会被分割开，仿佛从连续的背景和边框上切下来一块。
* **忘记考虑祖先元素的 `overflow` 属性对固定背景的影响:** 如果祖先元素设置了 `overflow: hidden` 或其他非 `visible` 的值，固定背景可能会被裁剪。

**用户操作如何一步步到达这里 (作为调试线索):**

假设用户在浏览器中访问了一个包含以下 HTML 和 CSS 的网页：

**HTML:**

```html
<!DOCTYPE html>
<html>
<head>
<style>
  #myDiv {
    width: 200px;
    height: 100px;
    background-color: lightblue;
    border: 1px solid black;
    padding: 10px;
  }
</style>
</head>
<body>
  <div id="myDiv">This is a div.</div>
</body>
</html>
```

**用户操作步骤 (调试线索):**

1. **浏览器加载 HTML 文档:**  浏览器开始解析 HTML 结构，创建 DOM 树。
2. **CSS 解析和样式计算:** 浏览器解析 CSS 样式，并为每个 DOM 元素计算出最终的样式（Computed Style）。对于 `#myDiv` 元素，计算出 `background-color`, `border`, `padding` 等属性的值。
3. **布局 (Layout):**  根据 DOM 树和计算出的样式，浏览器进行布局计算，确定每个元素在页面上的位置和大小。对于 `#myDiv`，会计算出其具体的坐标和尺寸。
4. **绘制 (Paint):**  布局完成后，浏览器开始进行绘制。对于 `#myDiv` 元素的背景和边框绘制，会涉及到 `BoxBackgroundPaintContext`。
    * **创建 `BoxBackgroundPaintContext`:**  渲染引擎会创建一个 `BoxBackgroundPaintContext` 对象，关联到表示 `#myDiv` 的 `LayoutBox` 对象。
    * **调用绘制方法:**  `BoxBackgroundPaintContext` 的相关方法会被调用，例如用于绘制背景的逻辑会读取 `#myDiv` 的 `background-color` 属性（lightblue），并填充相应的区域。绘制边框的逻辑会读取 `border` 属性，并绘制黑色的 1px 边框。绘制逻辑还会考虑 `padding` 属性，确保背景和边框绘制在正确的区域。
5. **合成 (Composite):**  绘制的结果会被上传到 GPU 进行合成，最终显示在用户的屏幕上。

**调试线索:**

如果在 `#myDiv` 的背景或边框渲染上出现问题，例如颜色不正确、边框缺失或位置错误，开发者可以通过以下步骤进行调试，可能会涉及到查看 `BoxBackgroundPaintContext` 的行为：

1. **检查 CSS 样式:**  确认 CSS 样式是否正确，例如 `background-color` 和 `border` 属性的值是否符合预期。
2. **检查布局信息:**  确认元素的布局是否正确，例如元素的位置和大小是否符合预期。可以使用浏览器的开发者工具查看元素的布局信息。
3. **断点调试渲染代码:**  对于 Chromium 开发者，可以在 `box_background_paint_context.cc` 中设置断点，查看 `BoxBackgroundPaintContext` 对象的状态和方法的调用过程，例如查看 `BorderOutsets()` 和 `PaddingOutsets()` 的返回值，以及背景绘制逻辑的具体实现。
4. **查看渲染流水线:**  使用浏览器的渲染调试工具（例如 Chrome 的 `chrome://tracing`）可以查看渲染流水线的各个阶段，包括绘制阶段，从而更深入地了解背景和边框的绘制过程。

总而言之，`BoxBackgroundPaintContext` 是 Blink 渲染引擎中一个核心的组件，负责处理元素背景和边框的绘制，它与 HTML 结构和 CSS 样式紧密相关，并受到 JavaScript 动态修改的影响。理解其功能有助于开发者更好地理解浏览器如何渲染网页，并排查相关的渲染问题。

Prompt: 
```
这是目录为blink/renderer/core/paint/box_background_paint_context.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2023 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/paint/box_background_paint_context.h"

#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/pagination_state.h"
#include "third_party/blink/renderer/core/layout/fragmentation_utils.h"
#include "third_party/blink/renderer/core/layout/layout_box.h"
#include "third_party/blink/renderer/core/layout/layout_box_model_object.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/layout/pagination_utils.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"
#include "third_party/blink/renderer/core/layout/table/layout_table_cell.h"
#include "third_party/blink/renderer/core/paint/paint_info.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/paint/rounded_border_geometry.h"
#include "third_party/blink/renderer/core/style/border_edge.h"
#include "third_party/blink/renderer/platform/graphics/paint/geometry_mapper.h"
#include "third_party/blink/renderer/platform/graphics/paint/paint_controller.h"

namespace blink {

namespace {

// Computes the offset into the stitched table-grid for the current fragment,
// and the total size of the stitched grid rectangle.
PhysicalOffset OffsetInStitchedTableGrid(const PhysicalBoxFragment& fragment,
                                         PhysicalSize* stitched_grid_size) {
  const auto writing_direction = fragment.Style().GetWritingDirection();
  LogicalRect table_grid_rect;
  LogicalRect fragment_local_grid_rect;
  LayoutUnit stitched_block_size;

  for (const PhysicalBoxFragment& walker :
       To<LayoutBox>(fragment.GetLayoutObject())->PhysicalFragments()) {
    LogicalRect local_grid_rect = walker.TableGridRect();
    local_grid_rect.offset.block_offset += stitched_block_size;
    if (table_grid_rect.IsEmpty()) {
      table_grid_rect = local_grid_rect;
    } else {
      table_grid_rect.Unite(local_grid_rect);
    }

    if (&walker == &fragment) {
      fragment_local_grid_rect = local_grid_rect;
    }

    stitched_block_size +=
        LogicalFragment(writing_direction, walker).BlockSize();
  }

  // Make the rect relative to the table grid.
  fragment_local_grid_rect.offset -= table_grid_rect.offset;

  WritingModeConverter converter(writing_direction, table_grid_rect.size);
  *stitched_grid_size = converter.ToPhysical(table_grid_rect.size);
  return converter.ToPhysical(fragment_local_grid_rect).offset;
}

}  // Anonymous namespace

BoxBackgroundPaintContext::BoxBackgroundPaintContext(
    const LayoutView& view,
    const PhysicalBoxFragment* box_fragment,
    const PhysicalOffset& element_positioning_area_offset)
    : box_(&view) {
  if (box_fragment &&
      box_fragment->GetBoxType() == PhysicalFragment::kPageContainer) {
    // @page backgrounds are painted on the page container, but borders and
    // padding outsets are part of the page border box child fragment.
    positioning_box_ =
        To<LayoutBox>(GetPageBorderBox(*box_fragment).GetLayoutObject());
  } else {
    positioning_box_ = &view.RootBox();
  }

  has_background_fixed_to_viewport_ = view.IsBackgroundAttachmentFixedObject();
  painting_view_ = true;
  // The background of the box generated by the root element covers the
  // entire canvas and will be painted by the view object, but the we should
  // still use the root element box for positioning.
  positioning_size_override_ = view.RootBox().Size();
  // The background image should paint from the root element's coordinate space.
  element_positioning_area_offset_ = element_positioning_area_offset;
}

BoxBackgroundPaintContext::BoxBackgroundPaintContext(
    const LayoutBoxModelObject& obj)
    : BoxBackgroundPaintContext(&obj, &obj) {}

// TablesNG background painting.
BoxBackgroundPaintContext::BoxBackgroundPaintContext(
    const LayoutTableCell& cell,
    PhysicalOffset cell_offset,
    const LayoutBox& table_part,
    PhysicalSize table_part_size)
    : BoxBackgroundPaintContext(&cell, &table_part) {
  painting_table_cell_ = true;
  cell_using_container_background_ = true;
  element_positioning_area_offset_ = cell_offset;
  positioning_size_override_ = table_part_size;
}

BoxBackgroundPaintContext::BoxBackgroundPaintContext(
    const PhysicalBoxFragment& fragment)
    : BoxBackgroundPaintContext(
          To<LayoutBoxModelObject>(fragment.GetLayoutObject()),
          To<LayoutBoxModelObject>(fragment.GetLayoutObject())) {
  DCHECK(box_->IsBox());
  box_fragment_ = &fragment;

  if (fragment.GetBoxType() == PhysicalFragment::kPageBorderBox) {
    // The page border box paints the document canvas, in which case it's the
    // LayoutView that has been used as image client.
    painting_view_ = true;
    const LayoutView* view = fragment.GetDocument().GetLayoutView();
    box_ = view;
    positioning_size_override_ = view->RootBox().Size();

    // Calculate the offset into the background image for the current page.
    wtf_size_t page_index =
        view->GetFrameView()->GetPaginationState()->CurrentPageIndex();
    element_positioning_area_offset_ =
        StitchedPageContentRect(*view, page_index).offset;
  } else {
    PhysicalOffset offset;
    if (fragment.IsTable()) {
      offset = OffsetInStitchedTableGrid(fragment, &positioning_size_override_);
    } else if (!fragment.IsOnlyForNode()) {
      // The element is block-fragmented. We need to calculate the correct
      // background offset within an imaginary box where all the fragments have
      // been stitched together.
      offset = OffsetInStitchedFragments(fragment, &positioning_size_override_);
    }
    // Set the start offset into the background image if box decorations are
    // sliced (default), so that one fragment will resume where the previous one
    // left off. Otherwise (if they are to be cloned, the offset will remain the
    // same for every fragment).
    if (fragment.Style().BoxDecorationBreak() == EBoxDecorationBreak::kSlice) {
      element_positioning_area_offset_ = offset;
    }
    box_has_multiple_fragments_ = !fragment.IsOnlyForNode();
  }
}

BoxBackgroundPaintContext::BoxBackgroundPaintContext(
    const LayoutBoxModelObject* box,
    const LayoutBoxModelObject* positioning_box)
    : box_(box),
      positioning_box_(positioning_box),
      has_background_fixed_to_viewport_(
          HasBackgroundFixedToViewport(*positioning_box)) {
  // Specialized constructor should be used for LayoutView.
  DCHECK(!IsA<LayoutView>(box));
  DCHECK(box);
  DCHECK(positioning_box);
}

PhysicalBoxStrut BoxBackgroundPaintContext::BorderOutsets() const {
  if (box_fragment_) {
    return box_fragment_->Borders();
  }
  return positioning_box_->BorderOutsets();
}

PhysicalBoxStrut BoxBackgroundPaintContext::PaddingOutsets() const {
  if (box_fragment_) {
    return box_fragment_->Padding();
  }
  return positioning_box_->PaddingOutsets();
}

PhysicalBoxStrut BoxBackgroundPaintContext::VisualOverflowOutsets() const {
  PhysicalRect border_box;
  if (positioning_box_->IsBox()) {
    border_box = To<LayoutBox>(positioning_box_)->PhysicalBorderBoxRect();
  } else {
    border_box = To<LayoutInline>(positioning_box_)->PhysicalLinesBoundingBox();
  }
  PhysicalRect visual_overflow =
      positioning_box_->Layer()
          ->LocalBoundingBoxIncludingSelfPaintingDescendants();
  return PhysicalBoxStrut(visual_overflow.Y() - border_box.Y(),
                          border_box.Right() - visual_overflow.Right(),
                          border_box.Bottom() - visual_overflow.Bottom(),
                          visual_overflow.X() - border_box.X());
}

PhysicalBoxStrut BoxBackgroundPaintContext::InnerBorderOutsets(
    const PhysicalRect& dest_rect,
    const PhysicalRect& positioning_area) const {
  gfx::RectF inner_border_rect =
      RoundedBorderGeometry::PixelSnappedRoundedInnerBorder(
          positioning_box_->StyleRef(), positioning_area)
          .Rect();
  PhysicalBoxStrut outset;
  // TODO(rendering-core) The LayoutUnit(float) constructor always rounds
  // down. We should FromFloatFloor or FromFloatCeil to move toward the border.
  outset.left = LayoutUnit(inner_border_rect.x()) - dest_rect.X();
  outset.top = LayoutUnit(inner_border_rect.y()) - dest_rect.Y();
  outset.right = dest_rect.Right() - LayoutUnit(inner_border_rect.right());
  outset.bottom = dest_rect.Bottom() - LayoutUnit(inner_border_rect.bottom());
  return outset;
}

SnappedAndUnsnappedOutsets BoxBackgroundPaintContext::ObscuredBorderOutsets(
    const PhysicalRect& dest_rect,
    const PhysicalRect& positioning_area) const {
  const ComputedStyle& style = positioning_box_->StyleRef();
  gfx::RectF inner_border_rect =
      RoundedBorderGeometry::PixelSnappedRoundedInnerBorder(style,
                                                            positioning_area)
          .Rect();

  BorderEdgeArray edges;
  style.GetBorderEdgeInfo(edges);
  const PhysicalBoxStrut box_outsets = BorderOutsets();
  SnappedAndUnsnappedOutsets adjust;
  if (edges[static_cast<unsigned>(BoxSide::kTop)].ObscuresBackground()) {
    adjust.snapped.top = LayoutUnit(inner_border_rect.y()) - dest_rect.Y();
    adjust.unsnapped.top = box_outsets.top;
  }
  if (edges[static_cast<unsigned>(BoxSide::kRight)].ObscuresBackground()) {
    adjust.snapped.right =
        dest_rect.Right() - LayoutUnit(inner_border_rect.right());
    adjust.unsnapped.right = box_outsets.right;
  }
  if (edges[static_cast<unsigned>(BoxSide::kBottom)].ObscuresBackground()) {
    adjust.snapped.bottom =
        dest_rect.Bottom() - LayoutUnit(inner_border_rect.bottom());
    adjust.unsnapped.bottom = box_outsets.bottom;
  }
  if (edges[static_cast<unsigned>(BoxSide::kLeft)].ObscuresBackground()) {
    adjust.snapped.left = LayoutUnit(inner_border_rect.x()) - dest_rect.X();
    adjust.unsnapped.left = box_outsets.left;
  }
  return adjust;
}

PhysicalRect BoxBackgroundPaintContext::ComputePositioningArea(
    const PaintInfo& paint_info,
    const FillLayer& fill_layer,
    const PhysicalRect& paint_rect) const {
  if (ShouldUseFixedAttachment(fill_layer)) {
    return FixedAttachmentPositioningArea(paint_info);
  }
  return NormalPositioningArea(paint_rect);
}

PhysicalRect BoxBackgroundPaintContext::NormalPositioningArea(
    const PhysicalRect& paint_rect) const {
  if (painting_view_ || cell_using_container_background_ ||
      box_has_multiple_fragments_) {
    return {PhysicalOffset(), positioning_size_override_};
  }
  return paint_rect;
}

bool BoxBackgroundPaintContext::DisallowBorderDerivedAdjustment() const {
  return painting_view_ || painting_table_cell_ ||
         box_has_multiple_fragments_ ||
         positioning_box_->StyleRef().BorderImage().GetImage() ||
         positioning_box_->StyleRef().BorderCollapse() ==
             EBorderCollapse::kCollapse;
}

bool BoxBackgroundPaintContext::CanCompositeBackgroundAttachmentFixed() const {
  return !painting_view_ && has_background_fixed_to_viewport_ &&
         positioning_box_->CanCompositeBackgroundAttachmentFixed();
}

bool BoxBackgroundPaintContext::ShouldUseFixedAttachment(
    const FillLayer& fill_layer) const {
  // Only backgrounds fixed to viewport should be treated as fixed attachment.
  // See comments in the private constructor.
  return has_background_fixed_to_viewport_ &&
         // Solid color background should use default attachment.
         fill_layer.GetImage() &&
         fill_layer.Attachment() == EFillAttachment::kFixed;
}

bool BoxBackgroundPaintContext::HasBackgroundFixedToViewport(
    const LayoutBoxModelObject& object) {
  if (!object.IsBackgroundAttachmentFixedObject()) {
    return false;
  }
  // https://www.w3.org/TR/css-transforms-1/#transform-rendering
  // Fixed backgrounds on the root element are affected by any transform
  // specified for that element. For all other elements that are effected
  // by a transform, a value of fixed for the background-attachment property
  // is treated as if it had a value of scroll.
  for (const PaintLayer* layer = object.EnclosingLayer();
       layer && !layer->IsRootLayer(); layer = layer->Parent()) {
    // Check LayoutObject::HasTransformRelatedProperty() first to exclude
    // non-applicable transforms and will-change: transform.
    LayoutObject& ancestor = layer->GetLayoutObject();
    if (ancestor.HasTransformRelatedProperty() &&
        (layer->Transform() ||
         ancestor.StyleRef().HasWillChangeHintForAnyTransformProperty())) {
      return false;
    }
  }
  return true;
}

PhysicalRect BoxBackgroundPaintContext::FixedAttachmentPositioningArea(
    const PaintInfo& paint_info) const {
  const ScrollableArea* layout_viewport =
      box_->GetFrameView()->LayoutViewport();
  DCHECK(layout_viewport);
  PhysicalSize size(layout_viewport->VisibleContentRect().size());
  if (CanCompositeBackgroundAttachmentFixed()) {
    // The caller should have adjusted paint chunk properties to be in the
    // viewport space.
    return PhysicalRect(PhysicalOffset(), size);
  }
  gfx::PointF viewport_origin_in_local_space =
      GeometryMapper::SourceToDestinationProjection(
          box_->View()->FirstFragment().LocalBorderBoxProperties().Transform(),
          paint_info.context.GetPaintController()
              .CurrentPaintChunkProperties()
              .Transform())
          .MapPoint(gfx::PointF());
  return PhysicalRect(
      PhysicalOffset::FromPointFRound(viewport_origin_in_local_space),
      PhysicalSize(layout_viewport->VisibleContentRect().size()));
}

const ComputedStyle& BoxBackgroundPaintContext::Style() const {
  return box_->StyleRef();
}

const ImageResourceObserver& BoxBackgroundPaintContext::ImageClient() const {
  return *(painting_view_ ? box_ : positioning_box_);
}

const ComputedStyle& BoxBackgroundPaintContext::ImageStyle(
    const ComputedStyle& fragment_style) const {
  if (painting_view_ || cell_using_container_background_) {
    return positioning_box_->StyleRef();
  }
  return fragment_style;
}

bool BoxBackgroundPaintContext::ShouldSkipBackgroundIfWhite() const {
  // Leave a transparent background if white, assuming the paper or the PDF
  // viewer background is white by default. This allows further customization of
  // the background, e.g. in the case of https://crbug.com/498892.
  return box_fragment_ &&
         box_fragment_->GetBoxType() == PhysicalFragment::kPageBorderBox;
}

PhysicalOffset BoxBackgroundPaintContext::OffsetInBackground(
    const FillLayer& fill_layer) const {
  if (ShouldUseFixedAttachment(fill_layer)) {
    return PhysicalOffset();
  }
  return element_positioning_area_offset_;
}

}  // namespace blink

"""

```