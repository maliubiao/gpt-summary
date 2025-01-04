Response:
Let's break down the thought process for analyzing the `layout_inline.cc` file and generating the summary.

1. **Understand the Request:** The goal is to analyze a specific Chromium Blink source file (`layout_inline.cc`) and describe its functionality, its relationship with web technologies (HTML, CSS, JavaScript), and potential user/developer errors. The request also emphasizes summarizing the file's purpose in this first part of a two-part analysis.

2. **Initial Scan for Keywords and Structure:** Quickly read through the code, looking for familiar terms and structural elements. This involves noticing:
    * Copyright information (indicates the file's age and licensing).
    * `#include` directives (reveal dependencies on other Blink components). Pay special attention to headers related to layout, CSS, DOM, and painting.
    * Class definition: `class LayoutInline : public LayoutBoxModelObject`. This immediately tells us the core entity this file is about.
    * Method names: `Paint`, `HitTest`, `AddChild`, `UpdateFromStyle`, `QuadsForSelfInternal`, etc. These are strong indicators of the file's responsibilities.
    * Namespaces: `blink`. This confirms it's a Blink-specific file.
    * Assertions and checks (`DCHECK`, `CHECK`, `NOTREACHED`): These are internal development aids but can offer hints about expected conditions and error handling.

3. **Identify the Core Functionality:** Based on the keywords and class name, it's clear this file deals with the layout of *inline* elements. The inheritance from `LayoutBoxModelObject` suggests it handles box model properties (margins, padding, borders) for inline elements.

4. **Analyze Key Methods and Their Implications:**  Go back through the code and examine the purpose of the most important methods:
    * **`LayoutInline::LayoutInline(Element* element)` and `CreateAnonymous`:**  Construction and creation of `LayoutInline` objects, including anonymous ones. This points to the file's role in representing inline elements in the layout tree.
    * **`UpdateFromStyle` and `StyleDidChange`:** Handling style changes and updating the layout object accordingly. This connects the file to CSS.
    * **`Paint`:** While marked `NOTREACHED`, its presence signifies that inline elements *can* be involved in the painting process, even if this specific class might delegate it. Other paint-related includes (`BoxFragmentPainter`, `ObjectPainter`) are also significant.
    * **`HitTest` and `NodeAtPoint`:** Determining if a point on the screen intersects with this layout object. This is crucial for user interaction and event handling.
    * **`AddChild` and `AddChildIgnoringContinuation`:** Managing the addition of child elements, including handling cases where block elements are nested within inline elements (leading to the creation of anonymous block wrappers).
    * **`QuadsForSelfInternal`:**  Calculating the geometric representation (quads) of the inline element, important for rendering and hit testing.
    * **`LocalCaretRect`:** Determining the position of the text cursor within the inline element, relevant for text editing.
    * **Methods related to fragments (`HasInlineFragments`, `SetFirstInlineFragmentItemIndex`):**  These suggest the file interacts with the concept of layout fragments, which are part of the more modern LayoutNG engine.
    * **Methods related to bounding boxes (`PhysicalLinesBoundingBox`, `VisualOverflowRect`):** Calculating the dimensions and overflow characteristics of the inline element.

5. **Connect to Web Technologies (HTML, CSS, JavaScript):**
    * **HTML:**  `LayoutInline` represents inline HTML elements like `<span>`, `<a>`, `<em>`, `<strong>`, etc. The creation of anonymous inline elements is also related to how the browser handles inline text outside explicit HTML tags.
    * **CSS:**  The `UpdateFromStyle` and `StyleDidChange` methods directly relate to how CSS properties (like `display: inline`, `margin`, `padding`, `background-color`, etc.) affect the layout of inline elements. The code also references specific CSS concepts like pseudo-elements (`::before`, `::after`, `::first-letter`).
    * **JavaScript:** While the file doesn't directly execute JavaScript, its functionality is essential for how JavaScript interacts with the DOM and CSS. For instance, JavaScript can modify styles, which then triggers the logic in `layout_inline.cc` to update the layout. JavaScript can also perform hit testing, which relies on the calculations done in this file.

6. **Consider Logical Reasoning (Input/Output):**  Think about scenarios and predict the behavior of the code:
    * **Input:** A `<span>` element with `padding: 10px;`. **Output:** The `LayoutInline` object will have its dimensions adjusted to include the padding.
    * **Input:** A `<div>` (block) nested inside a `<span>` (inline). **Output:** The `LayoutInline` will create an anonymous `LayoutBlockFlow` to wrap the `<div>`.
    * **Input:** A mouse click at coordinates (x, y). **Output:** The `HitTest` methods will determine if those coordinates fall within the boundaries of the `LayoutInline` object.

7. **Identify Potential User/Programming Errors:** Consider common mistakes developers might make:
    * **Assuming Block-Level Behavior:** A common error is expecting inline elements to behave like block elements (e.g., setting fixed widths/heights without understanding how inline elements expand).
    * **Incorrectly Nesting Block Elements:**  Nesting block elements directly inside inline elements can lead to unexpected layout results due to the creation of anonymous block wrappers.
    * **Over-reliance on Inline Margins/Padding:**  Understanding that vertical margins and padding on inline elements don't affect the line height in the same way as block elements is crucial.

8. **Structure the Summary:** Organize the findings into logical sections as requested:
    * **Functionality:** Start with a high-level description and then detail specific responsibilities.
    * **Relationship with Web Technologies:** Provide concrete examples linking the code to HTML, CSS, and JavaScript.
    * **Logical Reasoning (Input/Output):**  Illustrate the code's behavior with simple scenarios.
    * **User/Programming Errors:** Highlight common pitfalls.
    * **Summary (for Part 1):**  Reiterate the main purpose of the file.

9. **Refine and Elaborate:** Review the generated summary, adding more detail and clarity where needed. Ensure the language is precise and avoids jargon where possible.

By following this structured approach, we can systematically analyze the source code and generate a comprehensive and informative summary that addresses all aspects of the request. The process involves code reading, understanding the underlying web technologies, logical deduction, and consideration of practical usage scenarios.
这是对 `blink/renderer/core/layout/layout_inline.cc` 源代码文件（第一部分）的功能归纳：

**核心功能:**

`layout_inline.cc` 文件定义了 `LayoutInline` 类，这个类是 Blink 渲染引擎中负责 **行内级别元素（inline-level elements）** 布局的核心。它的主要职责是处理和计算行内元素的尺寸、位置、以及与其他元素之间的关系，最终确定它们在页面上的渲染方式。

**具体功能细分:**

1. **表示行内元素:** `LayoutInline` 类作为 `LayoutObject` 的子类，专门用于表示 HTML 中的行内元素，例如 `<span>`、`<a>`、`<em>`、`<strong>` 等。也包括一些匿名行内元素。

2. **处理样式和属性:**
   - `UpdateFromStyle()`:  根据元素的 CSS 样式（`ComputedStyle`）更新 `LayoutInline` 对象的状态，例如设置是否为行内元素。
   - `StyleDidChange()`:  当元素的样式发生变化时，更新 `LayoutInline` 对象并触发必要的重排和重绘。

3. **管理子元素:**
   - `AddChild()` 和 `AddChildIgnoringContinuation()`:  处理向 `LayoutInline` 对象添加子元素。一个关键的逻辑是处理当行内元素包含块级子元素时，会创建匿名的 `LayoutBlockFlow` 对象来包裹这些块级子元素，维护正确的布局结构。
   - `BlockInInlineBecameFloatingOrOutOfFlow()`:  处理当行内元素中的块级子元素变为浮动或脱离文档流时的情况，可能会移除不再需要的匿名块级容器。
   - `ChildBecameNonInline()`: 当一个原本是行内的子元素变为非行内时，进行相应的处理，例如将其移动到一个匿名的块级容器中。

4. **计算尺寸和位置:**
   - `LocalCaretRect()`: 计算行内元素内部光标的局部矩形位置，用于文本编辑。
   - `OffsetLeft()`, `OffsetTop()`, `OffsetWidth()`, `OffsetHeight()`: 提供获取行内元素相对于其父元素或包含块的偏移和尺寸的方法。
   - `MarginLeft()`, `MarginRight()`, `MarginTop()`, `MarginBottom()`: 获取行内元素的 margin 值。
   - `PhysicalLinesBoundingBox()`: 计算行内元素所有行框（line box）的物理边界框。
   - `LinesVisualOverflowBoundingBox()`: 计算行内元素的视觉溢出边界框。
   - `VisualOverflowRect()`: 计算行内元素的总视觉溢出矩形，包括轮廓（outline）等。
   - `AnchorPhysicalLocation()`: 获取行内元素锚点的物理位置。

5. **处理坐标转换:**
   - `QuadsForSelfInternal()` 和 `QuadsInAncestorInternal()`:  计算行内元素在自身坐标系以及相对于祖先元素的坐标系中的四边形（quads），用于渲染和命中测试。
   - `LocalToAbsoluteRect()`: 将局部坐标转换为绝对坐标。
   - `OffsetFromContainerInternal()`: 计算相对于容器的偏移。

6. **命中测试 (Hit Testing):**
   - `NodeAtPoint()`: 判断给定的屏幕坐标是否落在该行内元素内部，用于事件处理。
   - `HitTestCulledInline()`:  处理被裁剪（culled）的行内元素的命中测试。
   - `UpdateHitTestResult()`: 更新命中测试的结果。

7. **与 LayoutNG 的集成:** 代码中多处出现了 `IsInLayoutNGInlineFormattingContext()` 的判断，表明 `LayoutInline` 已经适配了 Blink 的下一代布局引擎 LayoutNG，并针对 LayoutNG 的特性进行了相应的处理，例如使用了 `FragmentItem` 和 `InlineCursor` 等与分片相关的概念。

8. **处理匿名块级容器:**  `CreateAnonymousContainerForBlockChildren()` 和相关逻辑负责在行内元素内部需要放置块级元素时创建必要的匿名 `LayoutBlockFlow` 容器。

9. **处理盒模型属性:**  继承自 `LayoutBoxModelObject`，负责处理 margin、padding、border 等盒模型属性。

10. **支持伪元素:**  `CanBeHitTestTargetPseudoNodeStyle()` 函数判断伪元素（例如 `::before`, `::after`, `::first-letter`）是否可以作为命中测试的目标。

**与 JavaScript, HTML, CSS 的关系举例:**

* **HTML:** 当浏览器解析到 HTML 中的 `<span>` 标签时，渲染引擎会创建一个对应的 `LayoutInline` 对象来表示它。
* **CSS:**
    * 如果 CSS 规则设置了 `span { display: inline; background-color: red; }`，`LayoutInline::UpdateFromStyle()` 会读取这些样式信息，并将背景色等属性应用到该 `LayoutInline` 对象上。
    * 如果 CSS 设置了 `span::before { content: "前缀"; }`，`LayoutInline` 在布局和渲染过程中会考虑这个伪元素，并且 `CanBeHitTestTargetPseudoNodeStyle()` 可能会返回 `true`，使得该伪元素可以被点击。
* **JavaScript:**
    * JavaScript 可以通过 DOM API 获取到 `<span>` 元素，然后通过 `getBoundingClientRect()` 等方法获取其在页面上的位置和尺寸。这些方法最终会调用 `LayoutInline` 中计算尺寸和位置的相关函数。
    * JavaScript 可以修改 `<span>` 元素的 CSS 样式，例如 `element.style.marginLeft = '10px'`，这会触发 `LayoutInline::StyleDidChange()`，导致重新布局和渲染。

**逻辑推理举例:**

假设输入一个 HTML 片段：

```html
<div>
  <span>This is an <em>inline</em> element.</span>
</div>
```

**假设输入:**  渲染引擎开始处理上述 HTML，遇到了 `<span>` 标签。

**逻辑推理:**

1. 创建一个 `LayoutInline` 对象来表示 `<span>` 元素。
2. 读取 `<span>` 元素的 CSS 样式（如果没有显式样式，则使用默认样式）。
3. 遍历 `<span>` 的子节点，包括文本节点 "This is an "，`<em>` 元素，以及文本节点 " element."。
4. 对于 `<em>` 元素，会创建另一个 `LayoutInline` 对象。
5. 计算 `<span>` 中每个部分（文本节点和 `<em>` 元素）的宽度和高度。
6. 将这些部分排列在同一行上，考虑到可能的换行情况（如果 `<span>` 的内容超出其父容器的宽度）。
7. 最终确定 `<span>` 及其子元素在页面上的精确位置和尺寸。

**假设输出:**  `LayoutInline` 对象计算出自身的宽度、高度，以及其子元素 `<em>` 相对于自身的偏移量。 这些信息将被用于后续的渲染过程。

**用户或编程常见的使用错误举例:**

* **错误地假设行内元素的 margin 和 padding 行为与块级元素相同:** 用户可能会认为给一个 `<span>` 设置 `margin-top` 和 `margin-bottom` 会像 `<div>` 一样增加其上下的空间，但实际上，行内元素的垂直 margin 并不会直接影响行高，可能会导致意想不到的布局问题。
* **在行内元素内部错误地嵌套块级元素:**  虽然浏览器会容错处理，并在内部创建匿名块级容器，但这种做法不符合 HTML 规范，可能会导致布局上的困惑和兼容性问题。例如，直接在 `<span>` 内部放置 `<div>`。
* **过度依赖行内元素的尺寸来布局:**  由于行内元素的尺寸是由其内容决定的，尝试使用 CSS 来精确控制行内元素的宽度和高度可能会遇到困难，特别是当内容动态变化时。

**功能归纳 (第 1 部分):**

总而言之，`layout_inline.cc` (第一部分) 的核心在于定义了 `LayoutInline` 类，该类负责 **行内级别元素的布局计算和管理**。它处理了行内元素的样式应用、子元素管理（包括匿名块级容器的创建）、尺寸和位置计算、坐标转换、以及命中测试等关键任务。该文件是 Blink 渲染引擎中处理行内元素显示的核心组件，并已部分集成了 LayoutNG 的相关特性。它直接关联着 HTML 中行内元素的呈现方式和 CSS 样式的应用效果。

Prompt: 
```
这是目录为blink/renderer/core/layout/layout_inline.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 1999 Lars Knoll (knoll@kde.org)
 *           (C) 1999 Antti Koivisto (koivisto@kde.org)
 * Copyright (C) 2003, 2004, 2005, 2006, 2007, 2008, 2009 Apple Inc.
 *               All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public License
 * along with this library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 *
 */

#include "third_party/blink/renderer/core/layout/layout_inline.h"

#include "cc/base/region.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/editing/position_with_affinity.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/fullscreen/fullscreen.h"
#include "third_party/blink/renderer/core/layout/geometry/transform_state.h"
#include "third_party/blink/renderer/core/layout/hit_test_location.h"
#include "third_party/blink/renderer/core/layout/hit_test_result.h"
#include "third_party/blink/renderer/core/layout/inline/fragment_item.h"
#include "third_party/blink/renderer/core/layout/inline/inline_cursor.h"
#include "third_party/blink/renderer/core/layout/layout_block.h"
#include "third_party/blink/renderer/core/layout/layout_block_flow.h"
#include "third_party/blink/renderer/core/layout/layout_object_inlines.h"
#include "third_party/blink/renderer/core/layout/layout_theme.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/layout/outline_utils.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"
#include "third_party/blink/renderer/core/layout/text_autosizer.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/paint/box_fragment_painter.h"
#include "third_party/blink/renderer/core/paint/box_painter.h"
#include "third_party/blink/renderer/core/paint/object_paint_invalidator.h"
#include "third_party/blink/renderer/core/paint/object_painter.h"
#include "third_party/blink/renderer/core/paint/outline_painter.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/platform/wtf/size_assertions.h"
#include "ui/gfx/geometry/quad_f.h"

namespace blink {

namespace {

// TODO(xiaochengh): Deduplicate with a similar function in ng_paint_fragment.cc
// ::before, ::after and ::first-letter can be hit test targets.
bool CanBeHitTestTargetPseudoNodeStyle(const ComputedStyle& style) {
  switch (style.StyleType()) {
    case kPseudoIdBefore:
    case kPseudoIdCheck:
    case kPseudoIdAfter:
    case kPseudoIdSelectArrow:
    case kPseudoIdFirstLetter:
      return true;
    default:
      return false;
  }
}

bool IsInChildRubyText(const LayoutInline& start_object,
                       const LayoutObject* target) {
  if (!target || !start_object.IsInlineRuby() || &start_object == target) {
    return false;
  }
  const LayoutObject* start_child = target;
  while (start_child->Parent() != &start_object) {
    start_child = start_child->Parent();
  }
  return start_child->IsInlineRubyText();
}

}  // anonymous namespace

struct SameSizeAsLayoutInline : public LayoutBoxModelObject {
  ~SameSizeAsLayoutInline() override = default;
  LayoutObjectChildList children_;
  wtf_size_t first_fragment_item_index_;
};

ASSERT_SIZE(LayoutInline, SameSizeAsLayoutInline);

LayoutInline::LayoutInline(Element* element) : LayoutBoxModelObject(element) {
  SetChildrenInline(true);
}

void LayoutInline::Trace(Visitor* visitor) const {
  visitor->Trace(children_);
  LayoutBoxModelObject::Trace(visitor);
}

LayoutInline* LayoutInline::CreateAnonymous(Document* document) {
  LayoutInline* layout_inline = MakeGarbageCollected<LayoutInline>(nullptr);
  layout_inline->SetDocumentForAnonymous(document);
  return layout_inline;
}

void LayoutInline::WillBeDestroyed() {
  NOT_DESTROYED();
  // Make sure to destroy anonymous children first while they are still
  // connected to the rest of the tree, so that they will properly dirty line
  // boxes that they are removed from. Effects that do :before/:after only on
  // hover could crash otherwise.
  Children()->DestroyLeftoverChildren();

  if (TextAutosizer* text_autosizer = GetDocument().GetTextAutosizer())
    text_autosizer->Destroy(this);

  if (!DocumentBeingDestroyed()) {
    if (Parent()) {
      Parent()->DirtyLinesFromChangedChild(this);
    }
    if (FirstInlineFragmentItemIndex()) {
      FragmentItems::LayoutObjectWillBeDestroyed(*this);
      ClearFirstInlineFragmentItemIndex();
    }
  }

  LayoutBoxModelObject::WillBeDestroyed();
}

void LayoutInline::ClearFirstInlineFragmentItemIndex() {
  NOT_DESTROYED();
  CHECK(IsInLayoutNGInlineFormattingContext()) << *this;
  first_fragment_item_index_ = 0u;
}

void LayoutInline::SetFirstInlineFragmentItemIndex(wtf_size_t index) {
  NOT_DESTROYED();
  CHECK(IsInLayoutNGInlineFormattingContext()) << *this;
  DCHECK_NE(index, 0u);
  first_fragment_item_index_ = index;
}

bool LayoutInline::HasInlineFragments() const {
  NOT_DESTROYED();
  return first_fragment_item_index_;
}

void LayoutInline::InLayoutNGInlineFormattingContextWillChange(bool new_value) {
  NOT_DESTROYED();
  if (IsInLayoutNGInlineFormattingContext())
    ClearFirstInlineFragmentItemIndex();
}

void LayoutInline::UpdateFromStyle() {
  NOT_DESTROYED();
  LayoutBoxModelObject::UpdateFromStyle();

  // This is needed (at a minimum) for LayoutSVGInline, which (including
  // subclasses) is constructed for svg:a, svg:textPath, and svg:tspan,
  // regardless of CSS 'display'.
  SetInline(true);

  // FIXME: Support transforms and reflections on inline flows someday.
  SetHasTransformRelatedProperty(false);
  SetHasReflection(false);
}

void LayoutInline::StyleDidChange(StyleDifference diff,
                                  const ComputedStyle* old_style) {
  NOT_DESTROYED();
  LayoutBoxModelObject::StyleDidChange(diff, old_style);

  const ComputedStyle& new_style = StyleRef();
  if (!IsInLayoutNGInlineFormattingContext()) {
    if (!AlwaysCreateLineBoxes()) {
      bool always_create_line_boxes_new =
          HasSelfPaintingLayer() || HasBoxDecorationBackground() ||
          new_style.MayHavePadding() || new_style.MayHaveMargin() ||
          new_style.HasOutline();
      if (old_style && always_create_line_boxes_new) {
        SetNeedsLayoutAndFullPaintInvalidation(
            layout_invalidation_reason::kStyleChange);
      }
      SetAlwaysCreateLineBoxes(always_create_line_boxes_new);
    }
  } else {
    if (!ShouldCreateBoxFragment()) {
      UpdateShouldCreateBoxFragment();
    }
    if (diff.NeedsReshape()) {
      SetNeedsCollectInlines();
    }
  }

  PropagateStyleToAnonymousChildren();
}

bool LayoutInline::ComputeInitialShouldCreateBoxFragment(
    const ComputedStyle& style) const {
  NOT_DESTROYED();

  // We'd like to use ScopedSVGPaintState in
  // InlineBoxFragmentPainter::Paint().
  // TODO(layout-dev): Improve the below condition so that we a create box
  // fragment only if this requires ScopedSVGPaintState, instead of
  // creating box fragments for all LayoutSVGInlines.
  if (IsSVGInline())
    return true;

  if (style.HasBoxDecorationBackground() || style.MayHavePadding() ||
      style.MayHaveMargin())
    return true;

  if (style.AnchorName())
    return true;

  if (const Element* element = DynamicTo<Element>(GetNode())) {
    if (element->HasImplicitlyAnchoredElement()) {
      return true;
    }
  }

  return ComputeIsAbsoluteContainer(&style) ||
         HasPaintedOutline(style, GetNode()) ||
         CanBeHitTestTargetPseudoNodeStyle(style);
}

bool LayoutInline::ComputeInitialShouldCreateBoxFragment() const {
  NOT_DESTROYED();
  const ComputedStyle& style = StyleRef();
  if (HasSelfPaintingLayer() || ComputeInitialShouldCreateBoxFragment(style) ||
      ShouldApplyPaintContainment() || ShouldApplyLayoutContainment())
    return true;

  const ComputedStyle& first_line_style = FirstLineStyleRef();
  if (&style != &first_line_style &&
      ComputeInitialShouldCreateBoxFragment(first_line_style)) [[unlikely]] {
    return true;
  }

  return false;
}

void LayoutInline::UpdateShouldCreateBoxFragment() {
  NOT_DESTROYED();
  // Once we have been tainted once, just assume it will happen again. This way
  // effects like hover highlighting that change the background color will only
  // cause a layout on the first rollover.
  if (IsInLayoutNGInlineFormattingContext()) {
    if (ShouldCreateBoxFragment())
      return;
  } else {
    SetIsInLayoutNGInlineFormattingContext(true);
    SetShouldCreateBoxFragment(false);
  }

  if (ComputeInitialShouldCreateBoxFragment()) {
    SetShouldCreateBoxFragment();
    SetNeedsLayoutAndFullPaintInvalidation(
        layout_invalidation_reason::kStyleChange);
  }
}

PhysicalRect LayoutInline::LocalCaretRect(int) const {
  NOT_DESTROYED();
  if (FirstChild()) {
    // This condition is possible if the LayoutInline is at an editing boundary,
    // i.e. the VisiblePosition is:
    //   <LayoutInline editingBoundary=true>|<LayoutText>
    //   </LayoutText></LayoutInline>
    // FIXME: need to figure out how to make this return a valid rect, note that
    // there are no line boxes created in the above case.
    return PhysicalRect();
  }

  LogicalRect logical_caret_rect =
      LocalCaretRectForEmptyElement(BorderAndPaddingInlineSize(), LayoutUnit());

  if (IsInLayoutNGInlineFormattingContext()) {
    InlineCursor cursor;
    cursor.MoveTo(*this);
    if (cursor) {
      PhysicalRect caret_rect =
          WritingModeConverter(
              {StyleRef().GetWritingMode(), TextDirection::kLtr},
              cursor.CurrentItem()->Size())
              .ToPhysical(logical_caret_rect);
      caret_rect.Move(cursor.Current().OffsetInContainerFragment());
      return caret_rect;
    }
  }

  return PhysicalRect(logical_caret_rect.offset.inline_offset,
                      logical_caret_rect.offset.block_offset,
                      logical_caret_rect.size.inline_size,
                      logical_caret_rect.size.block_size);
}

void LayoutInline::AddChild(LayoutObject* new_child,
                            LayoutObject* before_child) {
  NOT_DESTROYED();
  // Any table-part dom child of an inline element has anonymous wrappers in the
  // layout tree so we need to climb up to the enclosing anonymous table wrapper
  // and add the new child before that.
  // TODO(rhogan): If newChild is a table part we want to insert it into the
  // same table as beforeChild.
  while (before_child && before_child->IsTablePart())
    before_child = before_child->Parent();
  return AddChildIgnoringContinuation(new_child, before_child);
}

void LayoutInline::BlockInInlineBecameFloatingOrOutOfFlow(
    LayoutBlockFlow* anonymous_block_child) {
  NOT_DESTROYED();
  // Look for in-flow children. Any in-flow child will prevent the wrapper from
  // being deleted.
  for (const LayoutObject* grandchild = anonymous_block_child->FirstChild();
       grandchild; grandchild = grandchild->NextSibling()) {
    if (!grandchild->IsFloating() && !grandchild->IsOutOfFlowPositioned()) {
      return;
    }
  }
  // There are no longer any in-flow children inside the anonymous block wrapper
  // child. Get rid of it.
  anonymous_block_child->MoveAllChildrenTo(this, anonymous_block_child);
  anonymous_block_child->Destroy();
}

void LayoutInline::AddChildIgnoringContinuation(LayoutObject* new_child,
                                                LayoutObject* before_child) {
  NOT_DESTROYED();
  // Make sure we don't append things after :after-generated content if we have
  // it.
  if (!before_child && IsAfterContent(LastChild()))
    before_child = LastChild();

  if (!new_child->IsInline() && !new_child->IsFloatingOrOutOfFlowPositioned() &&
      // Table parts can be either inline or block. When creating its table
      // wrapper, |CreateAnonymousTableWithParent| creates an inline table if
      // the parent is |LayoutInline|.
      !new_child->IsTablePart()) {
    AddChildAsBlockInInline(new_child, before_child);
    return;
  }

  // If inserting an inline child before a block-in-inline, change
  // |before_child| to the anonymous block. The anonymous block may need to be
  // split if |before_child| is not the first child.
  if (before_child && before_child->Parent() != this) {
    DCHECK(before_child->Parent()->IsBlockInInline());
    DCHECK(IsA<LayoutBlockFlow>(before_child->Parent()));
    DCHECK_EQ(before_child->Parent()->Parent(), this);
    before_child = SplitAnonymousBoxesAroundChild(before_child);
  }

  LayoutBoxModelObject::AddChild(new_child, before_child);

  new_child->SetNeedsLayoutAndIntrinsicWidthsRecalcAndFullPaintInvalidation(
      layout_invalidation_reason::kChildChanged);
}

void LayoutInline::AddChildAsBlockInInline(LayoutObject* new_child,
                                           LayoutObject* before_child) {
  DCHECK(!new_child->IsInline());
  LayoutBlockFlow* anonymous_box;
  if (!before_child) {
    anonymous_box = DynamicTo<LayoutBlockFlow>(LastChild());
  } else if (before_child->IsInline() ||
             before_child->IsFloatingOrOutOfFlowPositioned()) {
    anonymous_box = DynamicTo<LayoutBlockFlow>(before_child->PreviousSibling());
  } else {
    // If |before_child| is not inline, it should have been added to the
    // anonymous block.
    anonymous_box = DynamicTo<LayoutBlockFlow>(before_child->Parent());
    DCHECK(anonymous_box);
    DCHECK(anonymous_box->IsBlockInInline());
    anonymous_box->AddChild(new_child, before_child);
    return;
  }
  if (!anonymous_box || !anonymous_box->IsBlockInInline()) {
    anonymous_box = CreateAnonymousContainerForBlockChildren();
    LayoutBoxModelObject::AddChild(anonymous_box, before_child);
  }
  DCHECK(anonymous_box->IsBlockInInline());
  anonymous_box->AddChild(new_child);
}

LayoutBlockFlow* LayoutInline::CreateAnonymousContainerForBlockChildren()
    const {
  NOT_DESTROYED();
  // TODO(1229581): Determine if we actually need to set the direction for
  // block-in-inline.

  // We are placing a block inside an inline. We have to perform a split of this
  // inline into continuations. This involves creating an anonymous block box to
  // hold |newChild|. We then make that block box a continuation of this
  // inline. We take all of the children after |beforeChild| and put them in a
  // clone of this object.
  ComputedStyleBuilder new_style_builder =
      GetDocument().GetStyleResolver().CreateAnonymousStyleBuilderWithDisplay(
          StyleRef(), EDisplay::kBlock);
  const LayoutBlock* containing_block = ContainingBlock();
  // The anon block we create here doesn't exist in the CSS spec, so we need to
  // ensure that any blocks it contains inherit properly from its true
  // parent. This means they must use the direction set by the anon block's
  // containing block, so we need to prevent the anon block from inheriting
  // direction from the inline. If there are any other inheritable properties
  // that apply to block and inline elements but only affect the layout of
  // children we will want to special-case them here too. Writing-mode would be
  // one if it didn't create a formatting context of its own, removing the need
  // for continuations.
  new_style_builder.SetDirection(containing_block->StyleRef().Direction());

  return LayoutBlockFlow::CreateAnonymous(&GetDocument(),
                                          new_style_builder.TakeStyle());
}

LayoutBox* LayoutInline::CreateAnonymousBoxToSplit(
    const LayoutBox* box_to_split) const {
  NOT_DESTROYED();
  DCHECK(box_to_split->IsBlockInInline());
  DCHECK(IsA<LayoutBlockFlow>(box_to_split));
  return CreateAnonymousContainerForBlockChildren();
}

void LayoutInline::Paint(const PaintInfo& paint_info) const {
  NOT_DESTROYED();
  NOTREACHED();
}

template <typename PhysicalRectCollector>
void LayoutInline::CollectLineBoxRects(
    const PhysicalRectCollector& yield) const {
  NOT_DESTROYED();
  if (!IsInLayoutNGInlineFormattingContext()) {
    // InlineCursor::MoveToIncludingCulledInline() below would fail DCHECKs in
    // this situation, so just bail. This is most likely not a good situation to
    // be in, though. See crbug.com/1448357
    return;
  }
  InlineCursor cursor;
  cursor.MoveToIncludingCulledInline(*this);
  for (; cursor; cursor.MoveToNextForSameLayoutObject()) {
    if (!IsInChildRubyText(*this, cursor.Current().GetLayoutObject())) {
      yield(cursor.CurrentRectInBlockFlow());
    }
  }
}

bool LayoutInline::AbsoluteTransformDependsOnPoint(
    const LayoutObject& object) const {
  const LayoutObject* current = &object;
  const LayoutObject* container = object.Container();
  while (container) {
    if (current->OffsetForContainerDependsOnPoint(container))
      return true;
    current = container;
    container = container->Container();
  }
  return false;
}

void LayoutInline::QuadsInAncestorInternal(Vector<gfx::QuadF>& quads,
                                           const LayoutBoxModelObject* ancestor,
                                           MapCoordinatesFlags mode) const {
  QuadsForSelfInternal(quads, ancestor, mode, true);
}

void LayoutInline::QuadsForSelfInternal(Vector<gfx::QuadF>& quads,
                                        const LayoutBoxModelObject* ancestor,
                                        MapCoordinatesFlags mode,
                                        bool map_to_ancestor) const {
  NOT_DESTROYED();
  std::optional<gfx::Transform> mapping_to_ancestor;
  // Set to true if the transform to absolute space depends on the point
  // being mapped (in which case we can't use LocalToAncestorTransform).
  bool transform_depends_on_point = false;
  bool transform_depends_on_point_computed = false;
  auto PushAncestorQuad = [&transform_depends_on_point,
                           &transform_depends_on_point_computed,
                           &mapping_to_ancestor, &quads, ancestor, mode,
                           this](const PhysicalRect& rect) {
    if (!transform_depends_on_point_computed) {
      transform_depends_on_point_computed = true;
      transform_depends_on_point = AbsoluteTransformDependsOnPoint(*this);
      if (!transform_depends_on_point)
        mapping_to_ancestor.emplace(LocalToAncestorTransform(ancestor, mode));
    }
    if (transform_depends_on_point) {
      quads.push_back(
          LocalToAncestorQuad(gfx::QuadF(gfx::RectF(rect)), ancestor, mode));
    } else {
      quads.push_back(
          mapping_to_ancestor->MapQuad(gfx::QuadF(gfx::RectF(rect))));
    }
  };

  CollectLineBoxRects(
      [&PushAncestorQuad, &map_to_ancestor, &quads](const PhysicalRect& rect) {
        if (map_to_ancestor) {
          PushAncestorQuad(rect);
        } else {
          quads.push_back(gfx::QuadF(gfx::RectF(rect)));
        }
      });
  if (quads.empty()) {
    if (map_to_ancestor) {
      PushAncestorQuad(PhysicalRect());
    } else {
      quads.push_back(gfx::QuadF());
    }
  }
}

std::optional<PhysicalOffset> LayoutInline::FirstLineBoxTopLeftInternal()
    const {
  NOT_DESTROYED();
  if (IsInLayoutNGInlineFormattingContext()) {
    InlineCursor cursor;
    cursor.MoveToIncludingCulledInline(*this);
    if (!cursor)
      return std::nullopt;
    return cursor.CurrentOffsetInBlockFlow();
  }
  return std::nullopt;
}

PhysicalOffset LayoutInline::AnchorPhysicalLocation() const {
  NOT_DESTROYED();
  if (const auto& location = FirstLineBoxTopLeftInternal())
    return *location;
  // This object doesn't have fragment/line box, probably because it's an empty
  // and at the beginning/end of a line. Query sibling or parent.
  // TODO(crbug.com/953479): We won't need this if we always create line box
  // for empty inline elements. The following algorithm works in most cases for
  // anchor elements, though may be inaccurate in some corner cases (e.g. if the
  // sibling is not in the same line).
  if (const auto* sibling = NextSibling()) {
    if (sibling->IsLayoutInline())
      return To<LayoutInline>(sibling)->AnchorPhysicalLocation();
    if (sibling->IsText())
      return To<LayoutText>(sibling)->FirstLineBoxTopLeft();
    if (sibling->IsBox())
      return To<LayoutBox>(sibling)->PhysicalLocation();
  }
  if (Parent()->IsLayoutInline())
    return To<LayoutInline>(Parent())->AnchorPhysicalLocation();
  return PhysicalOffset();
}

PhysicalRect LayoutInline::AbsoluteBoundingBoxRectHandlingEmptyInline(
    MapCoordinatesFlags flags) const {
  NOT_DESTROYED();
  Vector<PhysicalRect> rects = OutlineRects(
      nullptr, PhysicalOffset(), OutlineType::kIncludeBlockInkOverflow);
  PhysicalRect rect = UnionRect(rects);
  // When empty LayoutInline is not culled, |rect| is empty but |rects| is not.
  if (rect.IsEmpty())
    rect.offset = AnchorPhysicalLocation();
  return LocalToAbsoluteRect(rect);
}

LayoutUnit LayoutInline::OffsetLeft(const Element* parent) const {
  NOT_DESTROYED();
  return AdjustedPositionRelativeTo(FirstLineBoxTopLeft(), parent).left;
}

LayoutUnit LayoutInline::OffsetTop(const Element* parent) const {
  NOT_DESTROYED();
  return AdjustedPositionRelativeTo(FirstLineBoxTopLeft(), parent).top;
}

LayoutUnit LayoutInline::OffsetWidth() const {
  NOT_DESTROYED();
  return PhysicalLinesBoundingBox().Width();
}

LayoutUnit LayoutInline::OffsetHeight() const {
  NOT_DESTROYED();
  return PhysicalLinesBoundingBox().Height();
}

static LayoutUnit ComputeMargin(const LayoutInline* layout_object,
                                const Length& margin) {
  if (margin.IsFixed())
    return LayoutUnit(margin.Value());
  if (margin.IsPercent() || margin.IsCalculated()) {
    return MinimumValueForLength(
        margin,
        std::max(LayoutUnit(),
                 layout_object->ContainingBlock()->AvailableLogicalWidth()));
  }
  return LayoutUnit();
}

LayoutUnit LayoutInline::MarginLeft() const {
  NOT_DESTROYED();
  return ComputeMargin(this, StyleRef().MarginLeft());
}

LayoutUnit LayoutInline::MarginRight() const {
  NOT_DESTROYED();
  return ComputeMargin(this, StyleRef().MarginRight());
}

LayoutUnit LayoutInline::MarginTop() const {
  NOT_DESTROYED();
  return ComputeMargin(this, StyleRef().MarginTop());
}

LayoutUnit LayoutInline::MarginBottom() const {
  NOT_DESTROYED();
  return ComputeMargin(this, StyleRef().MarginBottom());
}

bool LayoutInline::NodeAtPoint(HitTestResult& result,
                               const HitTestLocation& hit_test_location,
                               const PhysicalOffset& accumulated_offset,
                               HitTestPhase phase) {
  NOT_DESTROYED();
  if (IsInLayoutNGInlineFormattingContext()) {
    // TODO(crbug.com/965976): We should fix the root cause of the missed
    // layout.
    if (NeedsLayout()) [[unlikely]] {
      DUMP_WILL_BE_NOTREACHED();
      return false;
    }

    // In LayoutNG, we reach here only when called from
    // PaintLayer::HitTestContents() without going through any ancestor, in
    // which case the element must have self painting layer.
    DCHECK(HasSelfPaintingLayer());
    InlineCursor cursor;
    cursor.MoveTo(*this);
    if (!cursor)
      return false;
    int target_fragment_idx = hit_test_location.FragmentIndex();
    // Fragment traversal requires a target fragment to be specified,
    // unless there's only one.
    DCHECK(!CanTraversePhysicalFragments() || target_fragment_idx >= 0 ||
           !IsFragmented());
    // Convert from inline fragment index to container fragment index, as the
    // inline may not start in the first fragment generated for the inline
    // formatting context.
    if (target_fragment_idx != -1)
      target_fragment_idx += cursor.ContainerFragmentIndex();

    for (; cursor; cursor.MoveToNextForSameLayoutObject()) {
      if (target_fragment_idx != -1 &&
          wtf_size_t(target_fragment_idx) != cursor.ContainerFragmentIndex())
        continue;
      DCHECK(cursor.Current().Item());
      const FragmentItem& item = *cursor.Current().Item();
      const PhysicalBoxFragment* box_fragment = item.BoxFragment();
      DCHECK(box_fragment);
      // BoxFragmentPainter::NodeAtPoint() takes an offset that is accumulated
      // up to the fragment itself. Compute this offset.
      const PhysicalOffset child_offset =
          accumulated_offset + item.OffsetInContainerFragment();
      InlinePaintContext inline_context;
      if (BoxFragmentPainter(cursor, item, *box_fragment, &inline_context)
              .NodeAtPoint(result, hit_test_location, child_offset,
                           accumulated_offset, phase)) {
        return true;
      }
    }
    return false;
  }

  NOTREACHED();
}

bool LayoutInline::HitTestCulledInline(HitTestResult& result,
                                       const HitTestLocation& hit_test_location,
                                       const PhysicalOffset& accumulated_offset,
                                       const InlineCursor& parent_cursor) {
  NOT_DESTROYED();
  if (!VisibleToHitTestRequest(result.GetHitTestRequest()))
    return false;

  HitTestLocation adjusted_location(hit_test_location, -accumulated_offset);
  cc::Region region_result;
  bool intersected = false;

  // NG generates purely physical rectangles here.

  // Iterate fragments for |this|, including culled inline, but only that are
  // descendants of |parent_cursor|.
  DCHECK(IsDescendantOf(parent_cursor.GetLayoutBlockFlow()));
  InlineCursor cursor(parent_cursor);
  cursor.MoveToIncludingCulledInline(*this);
  for (; cursor; cursor.MoveToNextForSameLayoutObject()) {
    // Block-in-inline is inline in the box tree, and may appear as a child of
    // a culled inline, but it should be painted and hit-tested as block
    // painting-order-wise. Don't include it as part of the culled inline
    // region. https://www.w3.org/TR/CSS22/zindex.html#painting-order
    if (const auto* fragment = cursor.Current().BoxFragment()) {
      if (fragment->IsOpaque()) [[unlikely]] {
        continue;
      }
    }
    PhysicalRect rect = cursor.Current().RectInContainerFragment();
    if (adjusted_location.Intersects(rect)) {
      intersected = true;
      region_result.Union(ToEnclosingRect(rect));
    }
  }

  if (intersected) {
    UpdateHitTestResult(result, adjusted_location.Point());
    if (result.AddNodeToListBasedTestResult(GetNode(), adjusted_location,
                                            region_result) == kStopHitTesting)
      return true;
  }
  return false;
}

PositionWithAffinity LayoutInline::PositionForPoint(
    const PhysicalOffset& point) const {
  NOT_DESTROYED();
  // FIXME: Does not deal with relative positioned inlines (should it?)

  if (const LayoutBlockFlow* ng_block_flow = FragmentItemsContainer())
    return ng_block_flow->PositionForPoint(point);

  return LayoutBoxModelObject::PositionForPoint(point);
}

PhysicalRect LayoutInline::PhysicalLinesBoundingBox() const {
  NOT_DESTROYED();

  if (IsInLayoutNGInlineFormattingContext()) {
    InlineCursor cursor;
    cursor.MoveToIncludingCulledInline(*this);
    PhysicalRect bounding_box;
    for (; cursor; cursor.MoveToNextForSameLayoutObject())
      bounding_box.UniteIfNonZero(cursor.Current().RectInContainerFragment());
    return bounding_box;
  }
  return PhysicalRect();
}

PhysicalRect LayoutInline::LinesVisualOverflowBoundingBox() const {
  NOT_DESTROYED();
  if (IsInLayoutNGInlineFormattingContext()) {
    PhysicalRect result;
    InlineCursor cursor;
    cursor.MoveToIncludingCulledInline(*this);
    for (; cursor; cursor.MoveToNextForSameLayoutObject()) {
      PhysicalRect child_rect = cursor.Current().InkOverflowRect();
      child_rect.offset += cursor.Current().OffsetInContainerFragment();
      result.Unite(child_rect);
    }
    return result;
  }
  return PhysicalRect();
}

PhysicalRect LayoutInline::VisualOverflowRect() const {
  NOT_DESTROYED();
  PhysicalRect overflow_rect = LinesVisualOverflowBoundingBox();
  const ComputedStyle& style = StyleRef();
  LayoutUnit outline_outset(OutlinePainter::OutlineOutsetExtent(
      style, OutlineInfo::GetFromStyle(style)));
  if (outline_outset) {
    UnionOutlineRectCollector collector;
    if (GetDocument().InNoQuirksMode()) {
      // We have already included outline extents of line boxes in
      // linesVisualOverflowBoundingBox(), so the following just add outline
      // rects for children and continuations.
      AddOutlineRectsForNormalChildren(
          collector, PhysicalOffset(),
          style.OutlineRectsShouldIncludeBlockInkOverflow());
    } else {
      // In non-standard mode, because the difference in
      // LayoutBlock::minLineHeightForReplacedObject(),
      // linesVisualOverflowBoundingBox() may not cover outline rects of lines
      // containing replaced objects.
      AddOutlineRects(collector, nullptr, PhysicalOffset(),
                      style.OutlineRectsShouldIncludeBlockInkOverflow());
    }
    if (!collector.Rect().IsEmpty()) {
      PhysicalRect outline_rect = collector.Rect();
      outline_rect.Inflate(outline_outset);
      overflow_rect.Unite(outline_rect);
    }
  }
  // TODO(rendering-core): Add in Text Decoration overflow rect.
  return overflow_rect;
}

bool LayoutInline::MapToVisualRectInAncestorSpaceInternal(
    const LayoutBoxModelObject* ancestor,
    TransformState& transform_state,
    VisualRectFlags visual_rect_flags) const {
  NOT_DESTROYED();
  if (ancestor == this)
    return true;

  LayoutObject* container = Container();
  DCHECK_EQ(container, Parent());
  if (!container)
    return true;

  bool preserve3d = container->StyleRef().Preserves3D();

  TransformState::TransformAccumulation accumulation =
      preserve3d ? TransformState::kAccumulateTransform
                 : TransformState::kFlattenTransform;

  if (IsStickyPositioned()) {
    transform_state.Move(StickyPositionOffset(), accumulation);
  }

  LayoutBox* container_box = DynamicTo<LayoutBox>(container);
  if (container_box && container != ancestor &&
      !container_box->MapContentsRectToBoxSpace(transform_state, accumulation,
                                                *this, visual_rect_flags))
    return false;

  return container->MapToVisualRectInAncestorSpaceInternal(
      ancestor, transform_state, visual_rect_flags);
}

PhysicalOffset LayoutInline::OffsetFromContainerInternal(
    const LayoutObject* container,
    MapCoordinatesFlags mode) const {
  NOT_DESTROYED();
  DCHECK_EQ(container, Container());

  PhysicalOffset offset;
  if (IsStickyPositioned() && !(mode & kIgnoreStickyOffset)) {
    offset += StickyPositionOffset();
  }

  if (container->IsScrollContainer()) {
    offset +=
        OffsetFromScrollableContainer(container, mode & kIgnoreScrollOffset);
  }

  return offset;
}

PaintLayerType LayoutInline::LayerTypeRequired() const {
  NOT_DESTROYED();
  return IsRelPositioned() || IsStickyPositioned() || CreatesGroup() ||
                 StyleRef().ShouldCompositeForCurrentAnimations() ||
                 ShouldApplyPaintContainment()
             ? kNormalPaintLayer
             : kNoPaintLayer;
}

void LayoutInline::ChildBecameNonInline(LayoutObject* child) {
  NOT_DESTROYED();
  DCHECK(!child->IsInline());
  // Following tests reach here.
  //  * external/wpt/css/CSS2/positioning/toogle-abspos-on-relpos-inline-child.html
  //  * fast/block/float/float-originating-line-deleted-crash.html
  //  * paint/stacking/layer-stacking-change-under-inline.html
  auto* const anonymous_box = CreateAnonymousContainerForBlockChildren();
  LayoutBoxModelObject::AddChild(anonymous_box, child);
  Children()->RemoveChildNode(this, child);
  anonymous_box->AddChild(child);
}

void LayoutInline::UpdateHitTestResult(HitTestResult& result,
                                       const PhysicalOffset& point) const {
  NOT_DESTROYED();
  if (result.InnerNode())
    return;

  PhysicalOffset local_point = point;
  if (Node* n = GetNode()) {
    result.SetNodeAndPosition(n, local_point);
  }
}

void LayoutInline::DirtyLinesFromChangedChild(LayoutObject* child) {
  NOT_DESTROYED();
  if (IsInL
"""


```