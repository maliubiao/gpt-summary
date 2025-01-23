Response:
Let's break down the thought process for analyzing this `LayoutSVGText.cc` file.

1. **Understand the Goal:** The request is to analyze the functionality of this specific Chromium Blink engine source code file. This involves identifying its purpose, connections to web technologies (HTML, CSS, JavaScript), any internal logic, and potential usage errors.

2. **Initial Scan for Keywords and Structure:**  A quick glance reveals key terms like `LayoutSVGText`, `SVGTextElement`, `paint`, `layout`, `transform`, `bounding box`, `font`, `style`, and mentions of child elements. The `#include` directives give a high-level overview of dependencies on other Blink components. The namespace `blink` confirms it's part of the Blink rendering engine.

3. **Identify the Core Class:** The central class is `LayoutSVGText`. The constructor takes an `Element*`, specifically an `SVGTextElement*`. This immediately tells us the file is responsible for the *layout* of `<text>` elements within an SVG context. The inheritance from `LayoutSVGBlock` suggests it handles block-level layout principles within the SVG framework.

4. **Decipher Function Names and Parameters:** Analyze the methods one by one, focusing on their names and parameters.

    * `StyleDidChange`: This clearly relates to CSS styling changes affecting the text element. The `StyleDifference` parameter points to optimization for incremental updates.
    * `WillBeDestroyed`, `InsertedIntoTree`, `WillBeRemovedFromTree`: These are lifecycle methods indicating how the layout object interacts with the rendering tree. The logic within these (adding/removing itself from `LayoutSVGRoot` or `LayoutBlock` ancestors) reveals how SVG text is tracked in the rendering tree hierarchy.
    * `CreatesNewFormattingContext`: This signifies that the `LayoutSVGText` establishes its own layout boundaries for its children.
    * `IsChildAllowed`:  Defines what types of elements can be children of an SVG text element (inline SVG elements and layoutable text nodes). This connects to the structure of SVG documents.
    * `AddChild`, `RemoveChild`: Standard methods for managing child layout objects.
    * `SubtreeStructureChanged`:  Indicates that changes in the children of the text element require a re-evaluation of layout and potentially invalidation of cached resources.
    * `UpdateFont`, `UpdateTransformAffectsVectorEffect`: These methods deal with specific rendering properties related to fonts and transformations, respectively. `VectorEffect` ties into SVG's non-scaling stroke behavior.
    * `Paint`: A crucial rendering method. The logic here shows it uses `ScopedSVGTransformState` and `SVGModelObjectPainter`, indicating it handles transformations and delegates the actual drawing.
    * `UpdateSVGLayout`: This is a core layout method. It involves creating `ConstraintSpaceBuilder` and calling `BlockNode::Layout`, highlighting the use of a constraint-based layout system. It also manages updates to the bounding box and triggers further layout updates if needed.
    * `IsObjectBoundingBoxValid`, `ObjectBoundingBox`, `StrokeBoundingBox`, `DecoratedBoundingBox`, `VisualRectInLocalSVGCoordinates`: These are all about calculating the dimensions and visual extents of the text, with distinctions for different purposes (e.g., including stroke, visual representation).
    * `QuadsInAncestorInternal`, `LocalBoundingBoxRectForAccessibility`:  Methods related to providing geometry information for rendering and accessibility features.
    * `NodeAtPoint`:  Handles hit-testing, determining if a given point intersects with the text element.
    * `PositionForPoint`:  Converts a point within the text element to a text cursor position, useful for text selection and editing.
    * `SetNeedsPositioningValuesUpdate`, `SetNeedsTextMetricsUpdate`, `NeedsTextMetricsUpdate`: Methods for managing the invalidation of cached layout information when properties that affect text positioning or metrics change.
    * `LocateLayoutSVGTextAncestor`, `NotifySubtreeStructureChanged`: Utility methods for traversing the layout tree and triggering updates.

5. **Identify Connections to Web Technologies:**

    * **HTML:** The class handles the layout of SVG `<text>` elements, which are embedded within HTML.
    * **CSS:**  The `StyleDidChange` method and the use of `ComputedStyle` directly link to CSS styling. Properties like `font-size`, `fill`, `stroke`, `transform`, and `vector-effect` are relevant.
    * **JavaScript:** While the C++ code itself doesn't directly execute JavaScript, changes made via JavaScript that affect the style or structure of the SVG text will trigger these layout methods. For instance, setting the `textContent` of the `<text>` element or modifying its attributes via JavaScript will lead to layout recalculations.

6. **Analyze Logic and Infer Behavior:**  Look for conditional statements, loops, and calculations. For example:

    * The logic in `InsertedIntoTree` and `WillBeRemovedFromTree` shows how the `LayoutSVGText` object registers and unregisters itself with its SVG root and block ancestors. This likely helps with efficient updates and event handling.
    * The `UpdateSVGLayout` method's steps indicate a multi-stage layout process: updating metrics based on transforms, performing block layout, and then updating transforms after the layout.
    * The bounding box calculations show the need to iterate through child inline text elements to determine the overall bounds.

7. **Consider Potential Usage Errors:**  Think about how developers might misuse SVG text or how the browser might handle invalid input.

    * **Incorrect Child Elements:**  The `IsChildAllowed` method hints at a potential error if developers try to nest non-allowed elements directly within a `<text>` element.
    * **Performance Issues:**  While not a direct coding error, excessive changes to the text content or styling of a complex SVG text element could lead to performance problems as the layout engine needs to recompute.
    * **Transformations:** Misunderstanding how transformations are applied in SVG (e.g., the `transform-origin`) could lead to unexpected visual results.

8. **Formulate Examples:**  For each connection to web technologies and potential errors, create concrete examples using HTML, CSS, and JavaScript code snippets. This makes the explanation clearer and more practical.

9. **Structure the Output:**  Organize the findings into logical categories (functionality, connections to web technologies, logic/reasoning, common errors). Use clear and concise language.

10. **Review and Refine:** After drafting the analysis, review it for accuracy, completeness, and clarity. Ensure the examples are correct and illustrative. For instance, double-check the assumptions made during logical reasoning.

This systematic approach, combining code reading with knowledge of web technologies and potential pitfalls, allows for a comprehensive understanding of the `LayoutSVGText.cc` file's role within the Blink rendering engine.
这个文件 `blink/renderer/core/layout/svg/layout_svg_text.cc` 是 Chromium Blink 渲染引擎中负责 **SVG `<text>` 元素布局** 的核心代码。它继承自 `LayoutSVGBlock`，表明它在布局上会被视为一个块级元素，但专门处理 SVG 文本相关的布局逻辑。

以下是它的主要功能及其与 JavaScript, HTML, CSS 的关系，以及逻辑推理和常见使用错误：

**功能列举：**

1. **创建和管理 SVG 文本的布局对象:** `LayoutSVGText` 类负责为 HTML 中的 `<text>` SVG 元素创建对应的布局对象。
2. **处理文本内容的布局:** 它确定文本在 SVG 画布上的位置、大小和排列方式。
3. **处理 SVG 文本特有的属性:**  例如，`x`, `y`, `dx`, `dy`, `textLength`, `lengthAdjust` 等属性会影响文本的布局。
4. **管理子元素:** SVG `<text>` 元素可以包含 `<tspan>`, `<tref>`, `<a>` 等子元素，`LayoutSVGText` 需要处理这些子元素的布局。
5. **计算文本的边界框 (bounding box):**  提供 `ObjectBoundingBox()`, `StrokeBoundingBox()`, `DecoratedBoundingBox()` 等方法来计算文本的各种边界框，这对于渲染、点击测试和计算元素尺寸至关重要。
6. **处理文本的变换 (transform):**  支持 CSS `transform` 属性应用于 SVG 文本，并更新文本的布局。
7. **处理 `vector-effect` 属性:**  特别是 `non-scaling-stroke`，确保描边在缩放时保持固定宽度。
8. **处理点击测试 (hit testing):**  `NodeAtPoint()` 方法用于判断给定坐标是否落在 SVG 文本的渲染区域内。
9. **处理文本光标定位:**  `PositionForPoint()` 方法用于将画布上的点转换为文本中的光标位置，这对于文本编辑功能很重要。
10. **处理文本指标更新:**  当字体、字号或其他影响文本尺寸的属性发生变化时，会触发文本指标的更新。
11. **集成到渲染树:**  管理自身在渲染树中的插入和移除，并通知父元素关于 SVG 文本子树的变化。
12. **处理 SVG 资源:**  与 `SVGResources` 类协同工作，处理与文本相关的 SVG 资源（例如，填充、描边等）。
13. **支持无障碍功能 (Accessibility):**  提供 `LocalBoundingBoxRectForAccessibility()` 方法，为辅助技术提供文本的边界信息。

**与 JavaScript, HTML, CSS 的关系：**

* **HTML:**
    * `LayoutSVGText` 对象对应于 HTML 中的 `<svg>` 元素下的 `<text>` 元素。当浏览器解析 HTML 时遇到 `<text>` 标签，Blink 引擎会创建 `LayoutSVGText` 对象来负责其布局。
    * **示例:**
      ```html
      <svg width="200" height="100">
        <text x="10" y="30" fill="black">Hello, SVG!</text>
      </svg>
      ```
      在这个例子中，`LayoutSVGText` 对象会处理 "Hello, SVG!" 这段文本的布局，包括它的起始位置 (x, y) 和填充颜色。

* **CSS:**
    * CSS 样式会影响 `LayoutSVGText` 对象的布局和渲染。例如，`fill`, `stroke`, `font-size`, `font-family`, `transform` 等 CSS 属性都会被 `LayoutSVGText` 考虑在内。
    * `StyleDidChange()` 方法会在元素的 CSS 样式发生变化时被调用，并根据新的样式重新计算布局。
    * **示例:**
      ```css
      text {
        font-size: 20px;
        font-family: sans-serif;
        transform: rotate(15deg);
      }
      ```
      这段 CSS 会影响所有 `<text>` 元素的字体大小、字体族和旋转角度，`LayoutSVGText` 对象会根据这些样式来布局文本。

* **JavaScript:**
    * JavaScript 可以动态地修改 SVG `<text>` 元素的属性和样式，这些修改会触发 `LayoutSVGText` 对象的更新和重新布局。
    * 例如，使用 JavaScript 修改 `text.textContent` 会导致文本内容改变，从而需要重新计算布局。
    * **示例:**
      ```javascript
      const textElement = document.querySelector('text');
      textElement.textContent = 'New Text!'; // 修改文本内容
      textElement.setAttribute('x', 50);    // 修改 x 坐标
      textElement.style.fill = 'red';      // 修改填充颜色
      ```
      这些 JavaScript 操作会触发 `LayoutSVGText` 对象重新计算文本的位置和外观。

**逻辑推理 (假设输入与输出):**

假设有以下 SVG 代码：

```html
<svg width="100" height="50">
  <text x="10" y="20" font-size="16">Test</text>
</svg>
```

**假设输入:**

* `LayoutSVGText` 对象关联到 `<text>` 元素。
* `x` 属性值为 10，`y` 属性值为 20，`font-size` 属性值为 16。
* 渲染上下文的坐标系统原点在 (0, 0)。

**逻辑推理过程 (简化):**

1. `LayoutSVGText` 会解析 `<text>` 元素的属性，获取 `x`, `y`, `font-size` 等值。
2. 根据 `font-size` 计算文本的尺寸（高度）。
3. 将文本的起始位置设置为 (10, 20)。
4. 计算文本的边界框，例如，如果字体高度是 16px，"Test" 的宽度是 30px，则边界框可能为 (10, 4, 40, 16)  (y 坐标是 20 减去字体基线之上部分)。
5. 如果存在 `transform` 属性，则应用相应的变换。

**假设输出 (部分):**

* `ObjectBoundingBox()` 返回的矩形可能类似于 `gfx::RectF(10, 4, 30, 16)`。
* 在渲染时，文本 "Test" 会被绘制在画布的 (10, 20) 附近。

**常见的使用错误举例：**

1. **尝试在 `<text>` 元素内放置非法的子元素:**
   ```html
   <svg>
     <text>
       <div>This is invalid</div>
       Hello
     </text>
   </svg>
   ```
   `LayoutSVGText::IsChildAllowed()` 会拒绝 `<div>` 这样的非 SVG 内联元素，可能导致渲染错误或布局异常。

2. **错误地理解 `x` 和 `y` 属性的含义:**  `x` 和 `y` 属性定义的是文本基线起始点的坐标，而不是文本边界框的左上角。初学者可能会误解这一点。

3. **过度依赖像素值而忽略相对单位:** 在 SVG 中使用相对单位（如 `em`）可以使文本在不同上下文中更具适应性。过度依赖像素值可能导致在不同缩放级别或视口大小下显示不一致。

4. **在循环中频繁修改文本内容或属性:** 大量修改 SVG 文本的内容或属性会导致频繁的布局和重绘，可能影响性能。应该尽量批量更新或使用更高效的方式。

5. **忘记处理文本溢出:** 如果文本内容超出了预期的区域，可能会发生溢出。需要使用适当的 CSS 属性（如 `overflow`, `text-overflow`）或 SVG 提供的文本裁剪机制来处理。

6. **在 JavaScript 中直接操作 `LayoutSVGText` 对象:**  `LayoutSVGText` 是 Blink 内部的 C++ 类，开发者不应该直接在 JavaScript 中操作它。应该通过 DOM API（例如，`element.setAttribute()`, `element.style`) 来修改 SVG 元素。

总而言之，`layout_svg_text.cc` 是 Blink 引擎中一个至关重要的文件，它负责将 SVG `<text>` 元素及其相关的属性和样式转化为浏览器可以渲染的布局信息，并与 HTML, CSS 和 JavaScript 紧密协作，共同呈现网页上的 SVG 文本内容。

### 提示词
```
这是目录为blink/renderer/core/layout/svg/layout_svg_text.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/svg/layout_svg_text.h"

#include <limits>

#include "third_party/blink/renderer/core/editing/position_with_affinity.h"
#include "third_party/blink/renderer/core/layout/block_node.h"
#include "third_party/blink/renderer/core/layout/constraint_space_builder.h"
#include "third_party/blink/renderer/core/layout/inline/fragment_item.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_inline_text.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_resource_container.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_root.h"
#include "third_party/blink/renderer/core/layout/svg/svg_layout_info.h"
#include "third_party/blink/renderer/core/layout/svg/svg_layout_support.h"
#include "third_party/blink/renderer/core/layout/svg/svg_resources.h"
#include "third_party/blink/renderer/core/layout/svg/transform_helper.h"
#include "third_party/blink/renderer/core/layout/svg/transformed_hit_test_location.h"
#include "third_party/blink/renderer/core/paint/clip_path_clipper.h"
#include "third_party/blink/renderer/core/paint/paint_info.h"
#include "third_party/blink/renderer/core/paint/scoped_svg_paint_state.h"
#include "third_party/blink/renderer/core/paint/svg_model_object_painter.h"
#include "third_party/blink/renderer/core/svg/svg_text_element.h"

namespace blink {

namespace {

const LayoutSVGText* FindTextRoot(const LayoutObject* start) {
  DCHECK(start);
  for (; start; start = start->Parent()) {
    if (const auto* ng_text = DynamicTo<LayoutSVGText>(start)) {
      return ng_text;
    }
  }
  return nullptr;
}

}  // namespace

LayoutSVGText::LayoutSVGText(Element* element)
    : LayoutSVGBlock(element),
      needs_update_bounding_box_(true),
      needs_text_metrics_update_(true) {
  DCHECK(IsA<SVGTextElement>(element));
}

void LayoutSVGText::StyleDidChange(StyleDifference diff,
                                   const ComputedStyle* old_style) {
  NOT_DESTROYED();
  if (needs_text_metrics_update_ && diff.HasDifference() && old_style) {
    diff.SetNeedsFullLayout();
  }
  LayoutSVGBlock::StyleDidChange(diff, old_style);
  SVGResources::UpdatePaints(*this, old_style, StyleRef());

  if (old_style) {
    const ComputedStyle& style = StyleRef();
    if (transform_uses_reference_box_ && !needs_transform_update_) {
      if (TransformHelper::CheckReferenceBoxDependencies(*old_style, style)) {
        SetNeedsTransformUpdate();
        SetNeedsPaintPropertyUpdate();
      }
    }
  }
}

void LayoutSVGText::WillBeDestroyed() {
  NOT_DESTROYED();
  SVGResources::ClearPaints(*this, Style());
  LayoutSVGBlock::WillBeDestroyed();
}

const char* LayoutSVGText::GetName() const {
  NOT_DESTROYED();
  return "LayoutSVGText";
}

bool LayoutSVGText::CreatesNewFormattingContext() const {
  NOT_DESTROYED();
  return true;
}

void LayoutSVGText::UpdateFromStyle() {
  NOT_DESTROYED();
  LayoutSVGBlock::UpdateFromStyle();
  SetHasNonVisibleOverflow(false);
}

bool LayoutSVGText::IsChildAllowed(LayoutObject* child,
                                   const ComputedStyle&) const {
  NOT_DESTROYED();
  return child->IsSVGInline() ||
         (child->IsText() && SVGLayoutSupport::IsLayoutableTextNode(child));
}

void LayoutSVGText::AddChild(LayoutObject* child, LayoutObject* before_child) {
  NOT_DESTROYED();
  LayoutSVGBlock::AddChild(child, before_child);
  SubtreeStructureChanged(layout_invalidation_reason::kChildChanged);
}

void LayoutSVGText::RemoveChild(LayoutObject* child) {
  NOT_DESTROYED();
  SubtreeStructureChanged(layout_invalidation_reason::kChildChanged);
  LayoutSVGBlock::RemoveChild(child);
}

void LayoutSVGText::InsertedIntoTree() {
  NOT_DESTROYED();
  LayoutSVGBlock::InsertedIntoTree();
  bool seen_svg_root = false;
  for (auto* ancestor = Parent(); ancestor; ancestor = ancestor->Parent()) {
    auto* root = DynamicTo<LayoutSVGRoot>(ancestor);
    if (!seen_svg_root && root) {
      root->AddSvgTextDescendant(*this);
      seen_svg_root = true;
    } else if (auto* block = DynamicTo<LayoutBlock>(ancestor)) {
      block->AddSvgTextDescendant(*this);
    }
  }
}

void LayoutSVGText::WillBeRemovedFromTree() {
  NOT_DESTROYED();
  bool seen_svg_root = false;
  for (auto* ancestor = Parent(); ancestor; ancestor = ancestor->Parent()) {
    auto* root = DynamicTo<LayoutSVGRoot>(ancestor);
    if (!seen_svg_root && root) {
      root->RemoveSvgTextDescendant(*this);
      seen_svg_root = true;
    } else if (auto* block = DynamicTo<LayoutBlock>(ancestor)) {
      block->RemoveSvgTextDescendant(*this);
    }
  }
  LayoutSVGBlock::WillBeRemovedFromTree();
}

void LayoutSVGText::SubtreeStructureChanged(
    LayoutInvalidationReasonForTracing) {
  NOT_DESTROYED();
  if (BeingDestroyed() || !EverHadLayout()) {
    return;
  }
  if (DocumentBeingDestroyed()) {
    return;
  }

  SetNeedsTextMetricsUpdate();
  LayoutSVGResourceContainer::MarkForLayoutAndParentResourceInvalidation(*this);
}

void LayoutSVGText::UpdateFont() {
  for (LayoutObject* descendant = FirstChild(); descendant;
       descendant = descendant->NextInPreOrder(this)) {
    if (auto* text = DynamicTo<LayoutSVGInlineText>(descendant)) {
      text->UpdateScaledFont();
    }
  }
}

void LayoutSVGText::UpdateTransformAffectsVectorEffect() {
  if (StyleRef().VectorEffect() == EVectorEffect::kNonScalingStroke) {
    SetTransformAffectsVectorEffect(true);
    return;
  }

  SetTransformAffectsVectorEffect(false);
  for (LayoutObject* descendant = FirstChild(); descendant;
       descendant = descendant->NextInPreOrder(this)) {
    if (descendant->IsSVGInline() && descendant->StyleRef().VectorEffect() ==
                                         EVectorEffect::kNonScalingStroke) {
      SetTransformAffectsVectorEffect(true);
      break;
    }
  }
}

void LayoutSVGText::Paint(const PaintInfo& paint_info) const {
  if (paint_info.phase != PaintPhase::kForeground &&
      paint_info.phase != PaintPhase::kForcedColorsModeBackplate &&
      paint_info.phase != PaintPhase::kSelectionDragImage) {
    return;
  }

  ScopedSVGTransformState transform_state(paint_info, *this);
  PaintInfo& block_info = transform_state.ContentPaintInfo();
  if (const auto* properties = FirstFragment().PaintProperties()) {
    // TODO(https://crbug.com/1278452): Also consider Translate, Rotate,
    // Scale, and Offset, probably via a single transform operation to
    // FirstFragment().PreTransform().
    if (const auto* transform = properties->Transform()) {
      block_info.TransformCullRect(*transform);
    }
  }

  if (block_info.phase == PaintPhase::kForeground) {
    SVGModelObjectPainter::RecordHitTestData(*this, block_info);
    SVGModelObjectPainter::RecordRegionCaptureData(*this, block_info);
  }
  LayoutSVGBlock::Paint(block_info);

  // Svg doesn't follow HTML PaintPhases, but is implemented with HTML classes.
  // The nearest self-painting layer is the containing <svg> element which is
  // painted using ReplacedPainter and ignores kDescendantOutlinesOnly.
  // Begin a fake kOutline to paint outlines, if any.
  if (paint_info.phase == PaintPhase::kForeground) {
    block_info.phase = PaintPhase::kOutline;
    LayoutSVGBlock::Paint(block_info);
  }
}

SVGLayoutResult LayoutSVGText::UpdateSVGLayout(
    const SVGLayoutInfo& layout_info) {
  NOT_DESTROYED();

  // If the root layout size changed (eg. window size changes), or the screen
  // scale factor has changed, then recompute the on-screen font size. Since
  // the computation of layout attributes uses the text metrics, we need to
  // update them before updating the layout attributes.
  if (needs_text_metrics_update_ || needs_transform_update_) {
    // Recompute the transform before updating font and corresponding
    // metrics. At this point our bounding box may be incorrect, so
    // any box relative transforms will be incorrect. Since the scaled
    // font size only needs the scaling components to be correct, this
    // should be fine. We update the transform again after computing
    // the bounding box below, and after that we clear the
    // |needs_transform_update_| flag.
    UpdateTransformBeforeLayout();
    UpdateFont();
    SetNeedsCollectInlines(true);
    needs_text_metrics_update_ = false;
  }

  const gfx::RectF old_boundaries = ObjectBoundingBox();

  const ComputedStyle& style = StyleRef();
  ConstraintSpaceBuilder builder(
      style.GetWritingMode(), style.GetWritingDirection(),
      /* is_new_fc */ true, /* adjust_inline_size_if_needed */ false);
  builder.SetAvailableSize(LogicalSize());
  BlockNode(this).Layout(builder.ToConstraintSpace());

  needs_update_bounding_box_ = true;

  const gfx::RectF boundaries = ObjectBoundingBox();
  const bool bounds_changed = old_boundaries != boundaries;

  SVGLayoutResult result;
  if (bounds_changed) {
    result.bounds_changed = true;
  }
  if (UpdateAfterSVGLayout(layout_info, bounds_changed)) {
    result.bounds_changed = true;
  }
  return result;
}

bool LayoutSVGText::UpdateAfterSVGLayout(const SVGLayoutInfo& layout_info,
                                         bool bounds_changed) {
  if (bounds_changed) {
    // Invalidate all resources of this client if our reference box changed.
    SVGResourceInvalidator resource_invalidator(*this);
    resource_invalidator.InvalidateEffects();
    resource_invalidator.InvalidatePaints();
  }

  UpdateTransformAffectsVectorEffect();
  return UpdateTransformAfterLayout(layout_info, bounds_changed);
}

bool LayoutSVGText::IsObjectBoundingBoxValid() const {
  NOT_DESTROYED();
  return PhysicalFragments().HasFragmentItems();
}

gfx::RectF LayoutSVGText::ObjectBoundingBox() const {
  NOT_DESTROYED();
  if (needs_update_bounding_box_) {
    // Compute a box containing repositioned text in the non-scaled coordinate.
    // We don't need to take into account of ink overflow here. We should
    // return a union of "advance x EM height".
    // https://svgwg.org/svg2-draft/coords.html#BoundingBoxes
    gfx::RectF bbox;
    DCHECK_LE(PhysicalFragmentCount(), 1u);
    for (const auto& fragment : PhysicalFragments()) {
      if (!fragment.Items()) {
        continue;
      }
      for (const auto& item : fragment.Items()->Items()) {
        if (item.IsSvgText()) {
          // Do not use item.RectInContainerFragment() in order to avoid
          // precision loss.
          bbox.Union(item.ObjectBoundingBox(*fragment.Items()));
        }
      }
    }
    bounding_box_ = bbox;
    needs_update_bounding_box_ = false;
  }
  return bounding_box_;
}

gfx::RectF LayoutSVGText::StrokeBoundingBox() const {
  NOT_DESTROYED();
  gfx::RectF box = ObjectBoundingBox();
  if (box.IsEmpty()) {
    return gfx::RectF();
  }
  return SVGLayoutSupport::ExtendTextBBoxWithStroke(*this, box);
}

gfx::RectF LayoutSVGText::DecoratedBoundingBox() const {
  NOT_DESTROYED();
  return StrokeBoundingBox();
}

gfx::RectF LayoutSVGText::VisualRectInLocalSVGCoordinates() const {
  NOT_DESTROYED();
  // TODO(crbug.com/1179585): Just use ink overflow?
  gfx::RectF box = ObjectBoundingBox();
  if (box.IsEmpty()) {
    return gfx::RectF();
  }
  return SVGLayoutSupport::ComputeVisualRectForText(*this, box);
}

void LayoutSVGText::QuadsInAncestorInternal(
    Vector<gfx::QuadF>& quads,
    const LayoutBoxModelObject* ancestor,
    MapCoordinatesFlags mode) const {
  NOT_DESTROYED();
  quads.push_back(
      LocalToAncestorQuad(gfx::QuadF(DecoratedBoundingBox()), ancestor, mode));
}

gfx::RectF LayoutSVGText::LocalBoundingBoxRectForAccessibility() const {
  NOT_DESTROYED();
  return DecoratedBoundingBox();
}

bool LayoutSVGText::NodeAtPoint(HitTestResult& result,
                                const HitTestLocation& hit_test_location,
                                const PhysicalOffset& accumulated_offset,
                                HitTestPhase phase) {
  TransformedHitTestLocation local_location(hit_test_location,
                                            LocalToSVGParentTransform());
  if (!local_location) {
    return false;
  }

  if (HasClipPath() && !ClipPathClipper::HitTest(*this, *local_location)) {
    return false;
  }

  return LayoutSVGBlock::NodeAtPoint(result, *local_location,
                                     accumulated_offset, phase);
}

PositionWithAffinity LayoutSVGText::PositionForPoint(
    const PhysicalOffset& point_in_contents) const {
  NOT_DESTROYED();
  gfx::PointF point(point_in_contents.left, point_in_contents.top);
  float min_distance = std::numeric_limits<float>::max();
  const LayoutSVGInlineText* closest_inline_text = nullptr;
  for (const LayoutObject* descendant = FirstChild(); descendant;
       descendant = descendant->NextInPreOrder(this)) {
    const auto* text = DynamicTo<LayoutSVGInlineText>(descendant);
    if (!text) {
      continue;
    }
    float distance =
        (descendant->ObjectBoundingBox().ClosestPoint(point) - point)
            .LengthSquared();
    if (distance >= min_distance) {
      continue;
    }
    min_distance = distance;
    closest_inline_text = text;
  }
  if (!closest_inline_text) {
    return CreatePositionWithAffinity(0);
  }
  return closest_inline_text->PositionForPoint(point_in_contents);
}

void LayoutSVGText::SetNeedsPositioningValuesUpdate() {
  NOT_DESTROYED();
  // We resolve text layout attributes in CollectInlines().
  // Do not use SetNeedsCollectInlines() without arguments.
  SetNeedsCollectInlines(true);
}

void LayoutSVGText::SetNeedsTextMetricsUpdate() {
  NOT_DESTROYED();
  needs_text_metrics_update_ = true;
  // We need to re-shape text.
  SetNeedsCollectInlines(true);
}

bool LayoutSVGText::NeedsTextMetricsUpdate() const {
  NOT_DESTROYED();
  return needs_text_metrics_update_;
}

LayoutSVGText* LayoutSVGText::LocateLayoutSVGTextAncestor(LayoutObject* start) {
  return const_cast<LayoutSVGText*>(FindTextRoot(start));
}

const LayoutSVGText* LayoutSVGText::LocateLayoutSVGTextAncestor(
    const LayoutObject* start) {
  return FindTextRoot(start);
}

// static
void LayoutSVGText::NotifySubtreeStructureChanged(
    LayoutObject* object,
    LayoutInvalidationReasonForTracing reason) {
  if (auto* ng_text = LocateLayoutSVGTextAncestor(object)) {
    ng_text->SubtreeStructureChanged(reason);
  }
}

}  // namespace blink
```