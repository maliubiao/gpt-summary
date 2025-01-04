Response:
My thinking process to answer the request goes like this:

1. **Understand the Core Request:** The request asks for the functionality of `layout_block.cc`, its relation to web technologies (HTML, CSS, JavaScript), examples, and common usage errors.

2. **Identify the Class's Role:** The filename `layout_block.cc` and the class name `LayoutBlock` strongly suggest this class is responsible for handling the layout of block-level elements in the Blink rendering engine. This immediately connects it to the CSS `display: block` property.

3. **Analyze the Includes:** The included header files provide valuable clues about the class's responsibilities:
    * **CSS & Styling:** `style_resolver.h`, `style_engine.h`, `computed_style.h` point to handling CSS styles.
    * **DOM & Structure:** `document.h`, `element.h`, `html_names.h` indicate interaction with the HTML structure.
    * **Layout Specifics:** `layout_block_flow.h`, `layout_inline.h`, `flex/layout_flexible_box.h`, `grid/layout_grid.h` suggest managing different layout models.
    * **Painting & Rendering:** `paint/block_paint_invalidator.h`, `paint/box_fragment_painter.h`, `paint/paint_layer.h` relate to the visual presentation.
    * **Editing & Selection:** `editing/drag_caret.h`, `editing/frame_selection.h`, `editing/ime/input_method_controller.h` show involvement in text editing and selection.
    * **Hit Testing:** `hit_test_location.h`, `hit_test_result.h` point to determining what's under the mouse cursor.

4. **Scan the Class Members and Methods:** A quick skim through the methods reveals key functionalities:
    * **Construction/Destruction:** `LayoutBlock()`, `WillBeDestroyed()`, `RemoveFromGlobalMaps()` - managing the object's lifecycle.
    * **Style Management:** `StyleWillChange()`, `StyleDidChange()` - reacting to CSS style changes.
    * **Child Management:** `AddChild()`, `AddChildBeforeDescendant()`, `RemoveLeftoverAnonymousBlock()` - handling the hierarchy of layout objects.
    * **Painting:** `Paint()`, `InvalidatePaint()` - responsible for drawing the element.
    * **Hit Testing:** `NodeAtPoint()`, `HitTestChildren()` - determining if a point is within the element.
    * **Positioning:** `RemovePositionedObjects()`, `PositionForPoint()` - handling element positioning.
    * **Scrolling:** `RecalcScrollableOverflow()` - managing scrollable content.
    * **Anonymous Blocks:** `CreateAnonymousBlock()`, `CreateAnonymousBoxWithSameTypeAs()` - creating anonymous wrapper elements.
    * **SVG Text:** `AddSvgTextDescendant()`, `RemoveSvgTextDescendant()` - specific handling for SVG text elements.
    * **Text Indent:** `TextIndentOffset()` - handling text indentation.
    * **First Line Styling:** `FirstLineHeight()`, `NearestInnerBlockWithFirstLine()` - specific logic for the `::first-line` pseudo-element.

5. **Connect to Web Technologies and Provide Examples:** Now, link the identified functionalities to HTML, CSS, and JavaScript.

    * **HTML:**  `LayoutBlock` directly corresponds to HTML elements that have a `display: block` characteristic (e.g., `<div>`, `<p>`, `<h1>`-`<h6>`). The methods for adding and removing children directly relate to the HTML DOM tree structure.
    * **CSS:**  The class is heavily influenced by CSS properties. Examples include:
        * `display: block`, `display: flex`, `display: grid`: Directly control the type of `LayoutBlock` created.
        * `position: absolute`, `position: fixed`: Handled by `RemovePositionedObjects()`.
        * `overflow: scroll`, `overflow: auto`: Managed by `RecalcScrollableOverflow()`.
        * `text-indent`: Calculated in `TextIndentOffset()`.
        * `::first-line`: Logic in `FirstLineHeight()` and related methods.
        * `transform`: Handling in `StyleDidChange()` and its impact on SVG text.
    * **JavaScript:** While `layout_block.cc` is C++, it interacts with JavaScript indirectly. JavaScript can manipulate the DOM (adding/removing elements, changing attributes) and CSS styles. These changes trigger layout recalculations, which involve the `LayoutBlock` class. JavaScript can also trigger scrolling, which uses the logic within this class.

6. **Develop Logical Reasoning Examples:**  For functions like `AddChildBeforeDescendant` and the anonymous block handling, create scenarios with input and expected output. This clarifies the more complex logic.

7. **Identify Potential Usage Errors:** Think about common mistakes developers make that could relate to layout:

    * Incorrectly assuming inline elements behave like block elements.
    * Forgetting about the existence and behavior of anonymous blocks.
    * Misunderstanding the impact of `position: absolute` or `position: fixed` on the layout flow.
    * Issues related to z-index and stacking contexts (though not directly in this file, it's related to positioned elements).

8. **Structure the Answer:** Organize the information logically with clear headings and bullet points. Start with a general overview of the file's purpose and then delve into specific functionalities with examples.

9. **Refine and Review:**  Read through the answer to ensure clarity, accuracy, and completeness. Check for any inconsistencies or missing information. For instance, initially, I might have focused too much on basic block layout. Reviewing the file reminds me of the SVG text handling and the intricacies of anonymous blocks.

By following these steps, I can generate a comprehensive and accurate answer that addresses all aspects of the user's request. The key is to start broad, analyze the code for specific clues, connect those clues to web technologies, and then illustrate the concepts with concrete examples.
这是 `blink/renderer/core/layout/layout_block.cc` 文件的功能列表，并解释了它与 JavaScript、HTML 和 CSS 的关系，以及一些逻辑推理示例和常见使用错误：

**主要功能:**

`LayoutBlock` 类是 Blink 渲染引擎中用于表示 **块级布局对象 (Block-level Layout Objects)** 的核心类。它负责管理和计算这些块级元素的大小、位置以及与其他元素的关系。  简单来说，它定义了诸如 `<div>`、`<p>`、`<h1>` 等 HTML 元素如何在页面上排列和渲染。

**详细功能分解:**

1. **表示块级元素:**
   - `LayoutBlock` 类的实例对应于 DOM 树中的一个节点，并且该节点在 CSS 样式计算后被确定为块级元素 (例如，`display: block`, `display: flex`, `display: grid` 等)。
   - 它继承自 `LayoutBox`，后者提供了更通用的布局盒子的基础功能。

2. **管理子元素:**
   - 维护一个子 `LayoutObject` 列表 (`children_`)，表示该块级元素包含的其他布局对象。
   - 提供了添加 (`AddChild`, `AddChildBeforeDescendant`) 和移除子元素的方法。
   - 能够处理匿名块级盒子的创建和管理，这些盒子是渲染引擎为了满足特定布局需求而自动创建的。

3. **处理样式变化:**
   - `StyleWillChange` 和 `StyleDidChange` 方法响应 CSS 样式的变化，并根据新的样式调整布局。
   - 例如，当元素的 `display` 属性从 `inline` 变为 `block` 时，会创建一个新的 `LayoutBlock` 对象。
   - 当 `transform` 属性改变时，会影响其包含的 SVG 文本的渲染。

4. **执行布局计算:**
   - 虽然具体的布局算法在其他类中实现（如 `LayoutBlockFlow`, `LayoutFlexibleBox`, `LayoutGrid`），但 `LayoutBlock` 是这些布局过程的基础。
   - 参与计算元素的内容宽度、高度、边距、内边距和边框。
   - 参与处理浮动元素和绝对定位元素的布局。

5. **负责绘制 (Painting):**
   - `Paint` 方法指示如何绘制这个块级元素，包括其背景、边框和内容。
   - `InvalidatePaint` 方法用于标记需要重新绘制的区域。

6. **处理点击测试 (Hit Testing):**
   - `NodeAtPoint` 和 `HitTestChildren` 方法用于确定鼠标点击位置落在哪个元素上。

7. **处理滚动 (Scrolling):**
   - `RecalcScrollableOverflow` 方法计算元素的滚动溢出区域，并确定是否需要显示滚动条。

8. **处理选择 (Selection):**
   - 与文本选择功能集成，例如 `PositionForPoint` 方法用于确定鼠标点击位置对应的文本位置。

9. **处理 SVG 文本:**
   - 包含针对包含 SVG 文本元素的特殊处理逻辑 (`AddSvgTextDescendant`, `RemoveSvgTextDescendant`)，以确保 SVG 文本在变换等情况下正确渲染。

10. **处理 `::first-line` 伪元素:**
    - 包含与 `::first-line` 伪元素样式相关的逻辑 (`FirstLineHeight`, `NearestInnerBlockWithFirstLine`)。

**与 JavaScript, HTML, CSS 的关系:**

* **HTML:**  `LayoutBlock` 对象直接对应于 HTML 元素。当浏览器解析 HTML 时，会为具有块级特性的元素创建相应的 `LayoutBlock` 对象。
    * **举例:** 对于以下 HTML 代码：
      ```html
      <div>这是一个块级元素</div>
      ```
      Blink 引擎会创建一个 `LayoutBlock` 对象来表示这个 `<div>` 元素。

* **CSS:** CSS 样式规则决定了 `LayoutBlock` 对象的属性和行为。`LayoutBlock` 的各种方法会读取和应用 CSS 样式。
    * **举例:**
        * CSS `display: block;` 会导致创建一个 `LayoutBlock` 的实例（通常是 `LayoutBlockFlow`）。
        * CSS `width: 100px; height: 50px;` 会影响 `LayoutBlock` 的尺寸计算。
        * CSS `position: absolute;` 会触发 `LayoutBlock` 中处理绝对定位的逻辑。
        * CSS `overflow: auto;` 会调用 `RecalcScrollableOverflow` 来决定是否显示滚动条。
        * CSS `text-indent: 2em;` 会被 `TextIndentOffset()` 方法读取并影响文本缩进的计算。
        * CSS `transform: rotate(45deg);` 的改变会触发 `StyleDidChange`，并可能影响包含的 SVG 文本的渲染。

* **JavaScript:** JavaScript 可以通过 DOM API 操作 HTML 结构和 CSS 样式。这些操作可能会导致 Blink 引擎重新布局和重绘页面，从而涉及到 `LayoutBlock` 对象的创建、更新和销毁。
    * **举例:**
        * JavaScript 使用 `document.createElement('div')` 创建一个新的 `div` 元素，Blink 引擎会为其创建一个 `LayoutBlock` 对象。
        * JavaScript 使用 `element.style.width = '200px'` 修改元素的宽度，会触发 `LayoutBlock` 的布局计算更新。
        * JavaScript 使用 `element.classList.add('hidden')` 添加一个设置了 `display: none` 的 CSS 类，会导致与该元素关联的 `LayoutBlock` 对象不再参与布局和渲染。

**逻辑推理示例:**

**假设输入:**

1. 一个 `<div>` 元素，其 CSS 样式为 `width: 100px; height: 50px; padding: 10px; border: 5px solid black;`。
2. 该 `<div>` 元素没有子元素。

**输出 (通过 `LayoutBlock` 的相关方法计算):**

* **内容宽度 (Content Logical Width):** 100px
* **内容高度 (Logical Height):** 50px
* **总宽度 (Width including padding and border):** 100px + 10px * 2 + 5px * 2 = 130px
* **总高度 (Height including padding and border):** 50px + 10px * 2 + 5px * 2 = 80px
* **文本缩进偏移量 (TextIndentOffset):** 如果 `text-indent` 属性未设置，则为 0。

**假设输入 (匿名块级盒子):**

1. 一个 `<div>` 元素，其 CSS 样式为 `display: inline-block;`。
2. 该 `<div>` 元素包含一些文本内容。

**推理:**

由于 `inline-block` 元素内部的内容需要进行块级布局，Blink 引擎可能会创建一个匿名的 `LayoutBlockFlow` 对象来包含这些文本内容，即使该 `<div>` 本身是 inline-block 级别的。

**常见的使用错误 (开发者角度，间接影响 `LayoutBlock` 的行为):**

这些错误通常发生在开发者编写 HTML, CSS 或 JavaScript 代码时，导致浏览器布局引擎出现意外行为。

1. **错误地假设内联元素的行为:** 开发者可能认为修改一个 `<span>` 元素的 `width` 和 `height` 会像修改 `<div>` 一样生效，但内联元素默认不会接受这些尺寸属性。理解块级和内联元素的区别对于避免布局问题至关重要。

2. **忘记考虑匿名块级盒子:**  当内联内容出现在块级容器中时，浏览器会自动创建匿名块级盒子来包裹这些内容。不理解这一点可能会导致对元素层叠和定位的误解。
    * **举例:** 在一个 `<div>` 中直接放置文本，渲染引擎会创建一个匿名的块级盒子来包含这些文本。

3. **过度使用绝对定位:** 大量使用 `position: absolute` 可能导致布局难以维护和理解，因为绝对定位的元素会脱离正常的文档流，影响其他元素的布局。

4. **不理解 `overflow` 属性的影响:**  错误地使用 `overflow: hidden`, `overflow: scroll` 或 `overflow: auto` 可能导致内容被裁剪或意外出现滚动条。

5. **不理解 `z-index` 的工作原理:** `z-index` 属性只对定位元素（`position: relative`, `absolute`, `fixed`, 或 `sticky`）有效。在非定位元素上设置 `z-index` 不会产生预期的层叠效果。

6. **修改样式导致频繁的重排 (Reflow/Layout):**  在 JavaScript 中频繁地修改元素的样式，特别是影响布局的属性（如 `width`, `height`, `position`），会导致浏览器频繁地进行布局计算，影响性能。

**总结:**

`layout_block.cc` 文件中的 `LayoutBlock` 类是 Blink 渲染引擎中一个至关重要的组件，它负责表示和管理块级布局对象，并与 CSS 样式紧密相关。理解其功能有助于深入理解浏览器如何将 HTML、CSS 和 JavaScript 代码转化为用户可见的网页。开发者虽然不直接操作 `LayoutBlock` 对象，但他们编写的代码会直接影响这些对象的创建、属性和行为。

Prompt: 
```
这是目录为blink/renderer/core/layout/layout_block.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
/*
 * Copyright (C) 1999 Lars Knoll (knoll@kde.org)
 *           (C) 1999 Antti Koivisto (koivisto@kde.org)
 *           (C) 2007 David Smith (catfish.man@gmail.com)
 * Copyright (C) 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2011 Apple Inc.
 *               All rights reserved.
 * Copyright (C) Research In Motion Limited 2010. All rights reserved.
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
 */

#include "third_party/blink/renderer/core/layout/layout_block.h"

#include <algorithm>
#include <memory>
#include <utility>

#include "base/memory/ptr_util.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/display_lock/display_lock_utilities.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/editing/drag_caret.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/ime/input_method_controller.h"
#include "third_party/blink/renderer/core/editing/text_affinity.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/html/html_marquee_element.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/layout/constraint_space.h"
#include "third_party/blink/renderer/core/layout/disable_layout_side_effects_scope.h"
#include "third_party/blink/renderer/core/layout/flex/layout_flexible_box.h"
#include "third_party/blink/renderer/core/layout/grid/layout_grid.h"
#include "third_party/blink/renderer/core/layout/hit_test_location.h"
#include "third_party/blink/renderer/core/layout/hit_test_result.h"
#include "third_party/blink/renderer/core/layout/layout_block_flow.h"
#include "third_party/blink/renderer/core/layout/layout_inline.h"
#include "third_party/blink/renderer/core/layout/layout_object_inlines.h"
#include "third_party/blink/renderer/core/layout/layout_theme.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/layout/legacy_layout_tree_walking.h"
#include "third_party/blink/renderer/core/layout/length_utils.h"
#include "third_party/blink/renderer/core/layout/mathml/layout_mathml_block.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_text.h"
#include "third_party/blink/renderer/core/layout/text_autosizer.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/page/scrolling/root_scroller_controller.h"
#include "third_party/blink/renderer/core/paint/block_paint_invalidator.h"
#include "third_party/blink/renderer/core/paint/box_fragment_painter.h"
#include "third_party/blink/renderer/core/paint/object_paint_invalidator.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/platform/wtf/size_assertions.h"
#include "third_party/blink/renderer/platform/wtf/std_lib_extras.h"

namespace blink {

struct SameSizeAsLayoutBlock : public LayoutBox {
  LayoutObjectChildList children;
  uint32_t bitfields;
};

ASSERT_SIZE(LayoutBlock, SameSizeAsLayoutBlock);

LayoutBlock::LayoutBlock(ContainerNode* node)
    : LayoutBox(node), has_svg_text_descendants_(false) {
  // LayoutBlockFlow calls setChildrenInline(true).
  // By default, subclasses do not have inline children.
}

void LayoutBlock::Trace(Visitor* visitor) const {
  visitor->Trace(children_);
  LayoutBox::Trace(visitor);
}

bool LayoutBlock::IsLayoutNGObject() const {
  NOT_DESTROYED();
  return true;
}

void LayoutBlock::RemoveFromGlobalMaps() {
  NOT_DESTROYED();
  if (has_svg_text_descendants_) {
    View()->SvgTextDescendantsMap().erase(this);
    has_svg_text_descendants_ = false;
  }
}

void LayoutBlock::WillBeDestroyed() {
  NOT_DESTROYED();
  if (!DocumentBeingDestroyed() && Parent())
    Parent()->DirtyLinesFromChangedChild(this);

  if (LocalFrame* frame = GetFrame()) {
    frame->Selection().LayoutBlockWillBeDestroyed(*this);
    frame->GetPage()->GetDragCaret().LayoutBlockWillBeDestroyed(*this);
  }

  if (TextAutosizer* text_autosizer = GetDocument().GetTextAutosizer())
    text_autosizer->Destroy(this);

  RemoveFromGlobalMaps();

  LayoutBox::WillBeDestroyed();
}

void LayoutBlock::StyleWillChange(StyleDifference diff,
                                  const ComputedStyle& new_style) {
  NOT_DESTROYED();
  SetIsAtomicInlineLevel(ShouldBeHandledAsInline(new_style));
  LayoutBox::StyleWillChange(diff, new_style);
}

// Compute a local version of the "font size scale factor" used by SVG
// <text>. Squared to avoid computing the square root. See
// SVGLayoutSupport::CalculateScreenFontSizeScalingFactor().
static double ComputeSquaredLocalFontSizeScalingFactor(
    const gfx::Transform* transform) {
  if (!transform)
    return 1;
  const auto affine = AffineTransform::FromTransform(*transform);
  return affine.XScaleSquared() + affine.YScaleSquared();
}

void LayoutBlock::StyleDidChange(StyleDifference diff,
                                 const ComputedStyle* old_style) {
  NOT_DESTROYED();
  // Computes old scaling factor before PaintLayer::UpdateTransform()
  // updates Layer()->Transform().
  double old_squared_scale = 1;
  if (Layer() && diff.TransformChanged() && has_svg_text_descendants_) {
    old_squared_scale =
        ComputeSquaredLocalFontSizeScalingFactor(Layer()->Transform());
  }

  LayoutBox::StyleDidChange(diff, old_style);

  const ComputedStyle& new_style = StyleRef();

  if (old_style && Parent()) {
    if (old_style->GetPosition() != new_style.GetPosition() &&
        new_style.GetPosition() != EPosition::kStatic) {
      // In LayoutObject::styleWillChange() we already removed ourself from our
      // old containing block's positioned descendant list, and we will be
      // inserted to the new containing block's list during layout. However the
      // positioned descendant layout logic assumes layout objects to obey
      // parent-child order in the list. Remove our descendants here so they
      // will be re-inserted after us.
      if (LayoutBlock* cb = ContainingBlock()) {
        cb->RemovePositionedObjects(this);
      }
    }
  }

  if (TextAutosizer* text_autosizer = GetDocument().GetTextAutosizer())
    text_autosizer->Record(this);

  PropagateStyleToAnonymousChildren();

  if (diff.TransformChanged() && has_svg_text_descendants_) {
    const double new_squared_scale = ComputeSquaredLocalFontSizeScalingFactor(
        Layer() ? Layer()->Transform() : nullptr);
    // Compare local scale before and after.
    if (old_squared_scale != new_squared_scale) {
      bool stacking_context_changed =
          old_style &&
          (IsStackingContext(*old_style) != IsStackingContext(new_style));
      for (LayoutBox* box : *View()->SvgTextDescendantsMap().at(this)) {
        To<LayoutSVGText>(box)->SetNeedsTextMetricsUpdate();
        if (GetNode() == GetDocument().documentElement() ||
            stacking_context_changed) {
          box->SetNeedsLayout(layout_invalidation_reason::kStyleChange);
        }
      }
    }
  }
}

bool LayoutBlock::RespectsCSSOverflow() const {
  NOT_DESTROYED();
  // If overflow has been propagated to the viewport, it has no effect here.
  return GetNode() != GetDocument().ViewportDefiningElement();
}

void LayoutBlock::AddChildBeforeDescendant(LayoutObject* new_child,
                                           LayoutObject* before_descendant) {
  NOT_DESTROYED();
  DCHECK_NE(before_descendant->Parent(), this);
  LayoutObject* before_descendant_container = before_descendant->Parent();
  while (before_descendant_container->Parent() != this)
    before_descendant_container = before_descendant_container->Parent();
  DCHECK(before_descendant_container);

  // We really can't go on if what we have found isn't anonymous. We're not
  // supposed to use some random non-anonymous object and put the child there.
  // That's a recipe for security issues.
  CHECK(before_descendant_container->IsAnonymous());

  // If the requested insertion point is not one of our children, then this is
  // because there is an anonymous container within this object that contains
  // the beforeDescendant.
  if (before_descendant_container->IsAnonymousBlock()) {
    // Insert the child into the anonymous block box instead of here. Note that
    // a LayoutOutsideListMarker is out-of-flow for tree building purposes, and
    // that is not inline level, although IsInline() is true.
    if ((new_child->IsInline() && !new_child->IsLayoutOutsideListMarker()) ||
        (new_child->IsFloatingOrOutOfFlowPositioned() &&
         (StyleRef().IsDeprecatedFlexboxUsingFlexLayout() ||
          (!IsFlexibleBox() && !IsLayoutGrid()))) ||
        before_descendant->Parent()->SlowFirstChild() != before_descendant) {
      before_descendant_container->AddChild(new_child, before_descendant);
    } else {
      AddChild(new_child, before_descendant->Parent());
    }
    return;
  }

  DCHECK(before_descendant_container->IsTable());
  if (new_child->IsTablePart()) {
    // Insert into the anonymous table.
    before_descendant_container->AddChild(new_child, before_descendant);
    return;
  }

  LayoutObject* before_child =
      SplitAnonymousBoxesAroundChild(before_descendant);

  DCHECK_EQ(before_child->Parent(), this);
  if (before_child->Parent() != this) {
    // We should never reach here. If we do, we need to use the
    // safe fallback to use the topmost beforeChild container.
    before_child = before_descendant_container;
  }

  AddChild(new_child, before_child);
}

void LayoutBlock::AddChild(LayoutObject* new_child,
                           LayoutObject* before_child) {
  NOT_DESTROYED();
  if (before_child && before_child->Parent() != this) {
    AddChildBeforeDescendant(new_child, before_child);
    return;
  }

  // Only LayoutBlockFlow should have inline children, and then we shouldn't be
  // here.
  DCHECK(!ChildrenInline());

  if (new_child->IsInline() ||
      (new_child->IsFloatingOrOutOfFlowPositioned() &&
       (StyleRef().IsDeprecatedFlexboxUsingFlexLayout() ||
        (!IsFlexibleBox() && !IsLayoutGrid())))) {
    // If we're inserting an inline child but all of our children are blocks,
    // then we have to make sure it is put into an anomyous block box. We try to
    // use an existing anonymous box if possible, otherwise a new one is created
    // and inserted into our list of children in the appropriate position.
    LayoutObject* after_child =
        before_child ? before_child->PreviousSibling() : LastChild();

    if (after_child && after_child->IsAnonymousBlock()) {
      after_child->AddChild(new_child);
      return;
    }

    if (new_child->IsInline()) {
      // No suitable existing anonymous box - create a new one.
      LayoutBlock* new_box = CreateAnonymousBlock();
      LayoutBox::AddChild(new_box, before_child);
      new_box->AddChild(new_child);
      return;
    }
  }

  LayoutBox::AddChild(new_child, before_child);
}

void LayoutBlock::RemoveLeftoverAnonymousBlock(LayoutBlock* child) {
  NOT_DESTROYED();
  DCHECK(child->IsAnonymousBlock());
  DCHECK(!child->ChildrenInline());
  DCHECK_EQ(child->Parent(), this);

  // Promote all the leftover anonymous block's children (to become children of
  // this block instead). We still want to keep the leftover block in the tree
  // for a moment, for notification purposes done further below (flow threads
  // and grids).
  child->MoveAllChildrenTo(this, child->NextSibling());

  // Remove all the information in the flow thread associated with the leftover
  // anonymous block.
  child->RemoveFromLayoutFlowThread();

  // Now remove the leftover anonymous block from the tree, and destroy it.
  // We'll rip it out manually from the tree before destroying it, because we
  // don't want to trigger any tree adjustments with regards to anonymous blocks
  // (or any other kind of undesired chain-reaction).
  Children()->RemoveChildNode(this, child, false);
  child->Destroy();
}

void LayoutBlock::Paint(const PaintInfo& paint_info) const {
  NOT_DESTROYED();

  // When |this| is NG block fragmented, the painter should traverse fragments
  // instead of |LayoutObject|, because this function cannot handle block
  // fragmented objects. We can come here only when |this| cannot traverse
  // fragments, or the parent is legacy.
  DCHECK(IsMonolithic() || !CanTraversePhysicalFragments() ||
         !Parent()->CanTraversePhysicalFragments());
  // We may get here in multiple-fragment cases if the object is repeated
  // (inside table headers and footers, for instance).
  DCHECK(PhysicalFragmentCount() <= 1u ||
         GetPhysicalFragment(0)->GetBreakToken()->IsRepeated());

  // Avoid painting dirty objects because descendants maybe already destroyed.
  if (NeedsLayout() && !ChildLayoutBlockedByDisplayLock()) [[unlikely]] {
    DUMP_WILL_BE_NOTREACHED();
    return;
  }

  if (PhysicalFragmentCount()) {
    const PhysicalBoxFragment* fragment = GetPhysicalFragment(0);
    DCHECK(fragment);
    BoxFragmentPainter(*fragment).Paint(paint_info);
    return;
  }

  NOTREACHED();
}

void LayoutBlock::InvalidatePaint(
    const PaintInvalidatorContext& context) const {
  NOT_DESTROYED();
  BlockPaintInvalidator(*this).InvalidatePaint(context);
}

void LayoutBlock::ImageChanged(WrappedImagePtr image,
                               CanDeferInvalidation defer) {
  NOT_DESTROYED();
  LayoutBox::ImageChanged(image, defer);

  if (!StyleRef().HasPseudoElementStyle(kPseudoIdFirstLine))
    return;

  const auto* first_line_style =
      StyleRef().GetCachedPseudoElementStyle(kPseudoIdFirstLine);
  if (!first_line_style)
    return;
  if (auto* first_line_container = NearestInnerBlockWithFirstLine()) {
    for (const auto* layer = &first_line_style->BackgroundLayers(); layer;
         layer = layer->Next()) {
      if (layer->GetImage() && image == layer->GetImage()->Data()) {
        first_line_container->SetShouldDoFullPaintInvalidationForFirstLine();
        break;
      }
    }
  }
}

void LayoutBlock::RemovePositionedObjects(LayoutObject* stay_within) {
  NOT_DESTROYED();

  auto ProcessPositionedObjectRemoval = [&](LayoutObject* positioned_object) {
    if (stay_within && (!positioned_object->IsDescendantOf(stay_within) ||
                        stay_within == positioned_object)) {
      return false;
    }

    positioned_object->SetChildNeedsLayout(kMarkOnlyThis);

    // It is parent blocks job to add positioned child to positioned objects
    // list of its containing block.
    // Parent layout needs to be invalidated to ensure this happens.
    positioned_object->MarkParentForSpannerOrOutOfFlowPositionedChange();
    return true;
  };

  bool has_positioned_children_in_fragment_tree = false;

  // PositionedObjects() is populated in legacy, and in NG when inside a
  // fragmentation context root. But in other NG cases it's empty as an
  // optimization, since we can just look at the children in the fragment tree.
  for (const PhysicalBoxFragment& fragment : PhysicalFragments()) {
    if (!fragment.HasOutOfFlowFragmentChild()) {
      continue;
    }
    for (const PhysicalFragmentLink& fragment_child : fragment.Children()) {
      if (!fragment_child->IsOutOfFlowPositioned()) {
        continue;
      }
      if (LayoutObject* child = fragment_child->GetMutableLayoutObject()) {
        if (ProcessPositionedObjectRemoval(child)) {
          has_positioned_children_in_fragment_tree = true;
        }
      }
    }
  }

  // Invalidate the nearest OOF container to ensure it is marked for layout.
  // Fixed containing blocks are always absolute containing blocks too,
  // so we only need to look for absolute containing blocks.
  if (has_positioned_children_in_fragment_tree) {
    if (LayoutBlock* containing_block = ContainingBlockForAbsolutePosition())
      containing_block->SetChildNeedsLayout(kMarkContainerChain);
  }
}

void LayoutBlock::AddSvgTextDescendant(LayoutBox& svg_text) {
  NOT_DESTROYED();
  DCHECK(IsA<LayoutSVGText>(svg_text));
  auto result = View()->SvgTextDescendantsMap().insert(this, nullptr);
  if (result.is_new_entry) {
    result.stored_value->value =
        MakeGarbageCollected<TrackedLayoutBoxLinkedHashSet>();
  }
  result.stored_value->value->insert(&svg_text);
  has_svg_text_descendants_ = true;
}

void LayoutBlock::RemoveSvgTextDescendant(LayoutBox& svg_text) {
  NOT_DESTROYED();
  DCHECK(IsA<LayoutSVGText>(svg_text));
  TrackedDescendantsMap& map = View()->SvgTextDescendantsMap();
  auto it = map.find(this);
  if (it == map.end())
    return;
  TrackedLayoutBoxLinkedHashSet* descendants = &*it->value;
  descendants->erase(&svg_text);
  if (descendants->empty()) {
    map.erase(this);
    has_svg_text_descendants_ = false;
  }
}

LayoutUnit LayoutBlock::TextIndentOffset() const {
  NOT_DESTROYED();
  LayoutUnit cw;
  if (StyleRef().TextIndent().HasPercent()) {
    cw = ContentLogicalWidth();
  }
  return MinimumValueForLength(StyleRef().TextIndent(), cw);
}

bool LayoutBlock::NodeAtPoint(HitTestResult& result,
                              const HitTestLocation& hit_test_location,
                              const PhysicalOffset& accumulated_offset,
                              HitTestPhase phase) {
  NOT_DESTROYED();

  // We may get here in multiple-fragment cases if the object is repeated
  // (inside table headers and footers, for instance).
  DCHECK(PhysicalFragmentCount() <= 1u ||
         GetPhysicalFragment(0)->GetBreakToken()->IsRepeated());

  if (!MayIntersect(result, hit_test_location, accumulated_offset)) {
    return false;
  }

  if (PhysicalFragmentCount()) {
    const PhysicalBoxFragment* fragment = GetPhysicalFragment(0);
    DCHECK(fragment);
    return BoxFragmentPainter(*fragment).NodeAtPoint(result, hit_test_location,
                                                     accumulated_offset, phase);
  }

  return false;
}

bool LayoutBlock::HitTestChildren(HitTestResult& result,
                                  const HitTestLocation& hit_test_location,
                                  const PhysicalOffset& accumulated_offset,
                                  HitTestPhase phase) {
  NOT_DESTROYED();
  DCHECK(!ChildrenInline());

  if (PhysicalFragmentCount() && CanTraversePhysicalFragments()) {
    DCHECK(!Parent()->CanTraversePhysicalFragments());
    DCHECK_LE(PhysicalFragmentCount(), 1u);
    const PhysicalBoxFragment* fragment = GetPhysicalFragment(0);
    DCHECK(fragment);
    DCHECK(!fragment->HasItems());
    return BoxFragmentPainter(*fragment).NodeAtPoint(result, hit_test_location,
                                                     accumulated_offset, phase);
  }

  PhysicalOffset scrolled_offset = accumulated_offset;
  if (IsScrollContainer())
    scrolled_offset -= PhysicalOffset(PixelSnappedScrolledContentOffset());
  HitTestPhase child_hit_test = phase;
  if (phase == HitTestPhase::kDescendantBlockBackgrounds)
    child_hit_test = HitTestPhase::kSelfBlockBackground;
  for (LayoutBox* child = LastChildBox(); child;
       child = child->PreviousSiblingBox()) {
    if (child->HasSelfPaintingLayer() || child->IsColumnSpanAll())
      continue;

    PhysicalOffset child_accumulated_offset =
        scrolled_offset + child->PhysicalLocation(this);
    bool did_hit;
    if (child->IsFloating()) {
      if (phase != HitTestPhase::kFloat || !IsLayoutNGObject())
        continue;
      // Hit-test the floats in regular tree order if this is LayoutNG. Only
      // legacy layout uses the FloatingObjects list.
      did_hit = child->HitTestAllPhases(result, hit_test_location,
                                        child_accumulated_offset);
    } else {
      did_hit = child->NodeAtPoint(result, hit_test_location,
                                   child_accumulated_offset, child_hit_test);
    }
    if (did_hit) {
      UpdateHitTestResult(result,
                          hit_test_location.Point() - accumulated_offset);
      return true;
    }
  }

  return false;
}

PositionWithAffinity LayoutBlock::PositionForPointIfOutsideAtomicInlineLevel(
    const PhysicalOffset& point) const {
  NOT_DESTROYED();
  DCHECK(IsAtomicInlineLevel());
  LogicalOffset logical_offset =
      point.ConvertToLogical({StyleRef().GetWritingMode(), ResolvedDirection()},
                             PhysicalSize(Size()), PhysicalSize());
  if (logical_offset.inline_offset < 0)
    return FirstPositionInOrBeforeThis();
  if (logical_offset.inline_offset >= LogicalWidth())
    return LastPositionInOrAfterThis();
  if (logical_offset.block_offset < 0)
    return FirstPositionInOrBeforeThis();
  if (logical_offset.block_offset >= LogicalHeight())
    return LastPositionInOrAfterThis();
  return PositionWithAffinity();
}

PositionWithAffinity LayoutBlock::PositionForPoint(
    const PhysicalOffset& point) const {
  NOT_DESTROYED();
  // NG codepath requires |kPrePaintClean|.
  // |SelectionModifier| calls this only in legacy codepath.
  DCHECK(!IsLayoutNGObject() || GetDocument().Lifecycle().GetState() >=
                                    DocumentLifecycle::kPrePaintClean);

  if (IsAtomicInlineLevel()) {
    PositionWithAffinity position =
        PositionForPointIfOutsideAtomicInlineLevel(point);
    if (!position.IsNull())
      return position;
  }

  if (PhysicalFragmentCount()) {
    return PositionForPointInFragments(point);
  }

  return LayoutBox::PositionForPoint(point);
}

bool LayoutBlock::HasLineIfEmpty() const {
  NOT_DESTROYED();
  if (GetNode()) {
    if (IsRootEditableElement(*GetNode()))
      return true;
  }
  return FirstLineStyleRef().HasLineIfEmpty();
}

// This function should return the distance from the block-start, not from
// the line-over.
std::optional<LayoutUnit> LayoutBlock::BaselineForEmptyLine() const {
  NOT_DESTROYED();
  const ComputedStyle* style = FirstLineStyle();
  const SimpleFontData* font_data = style->GetFont().PrimaryFont();
  if (!font_data)
    return std::nullopt;
  const auto& font_metrics = font_data->GetFontMetrics();
  const auto baseline_type = style->GetFontBaseline();
  const LayoutUnit line_height = FirstLineHeight();
  if (RuntimeEnabledFeatures::SidewaysWritingModesEnabled()) {
    int ascent_or_descent = IsFlippedLinesWritingMode(style->GetWritingMode())
                                ? font_metrics.Descent(baseline_type)
                                : font_metrics.Ascent(baseline_type);
    return LayoutUnit((ascent_or_descent +
                       (line_height - font_metrics.Height()) / 2 +
                       BorderAndPaddingBlockStart())
                          .ToInt());
  }
  const LayoutUnit border_padding = style->IsHorizontalWritingMode()
                                        ? BorderTop() + PaddingTop()
                                        : BorderRight() + PaddingRight();
  return LayoutUnit((font_metrics.Ascent(baseline_type) +
                     (line_height - font_metrics.Height()) / 2 + border_padding)
                        .ToInt());
}

LayoutUnit LayoutBlock::FirstLineHeight() const {
  NOT_DESTROYED();
  return LayoutUnit(FirstLineStyle()->ComputedLineHeight());
}

const LayoutBlock* LayoutBlock::FirstLineStyleParentBlock() const {
  NOT_DESTROYED();
  const LayoutBlock* first_line_block = this;
  // Inline blocks do not get ::first-line style from its containing blocks.
  if (IsAtomicInlineLevel())
    return nullptr;
  // Floats and out of flow blocks do not get ::first-line style from its
  // containing blocks.
  if (IsFloatingOrOutOfFlowPositioned())
    return nullptr;

  LayoutObject* parent_block = first_line_block->Parent();
  if (!parent_block || !parent_block->BehavesLikeBlockContainer())
    return nullptr;

  const LayoutBlock* parent_layout_block = To<LayoutBlock>(parent_block);

  // If we are not the first in-flow child of our parent, we cannot get
  // ::first-line style from our ancestors.
  const LayoutObject* first_child = parent_layout_block->FirstChild();
  while (first_child->IsFloatingOrOutOfFlowPositioned())
    first_child = first_child->NextSibling();
  if (first_child != first_line_block)
    return nullptr;

  return parent_layout_block;
}

LayoutBlockFlow* LayoutBlock::NearestInnerBlockWithFirstLine() {
  NOT_DESTROYED();
  if (ChildrenInline())
    return To<LayoutBlockFlow>(this);
  for (LayoutObject* child = FirstChild();
       child && !child->IsFloatingOrOutOfFlowPositioned() &&
       child->IsLayoutBlockFlow();
       child = To<LayoutBlock>(child)->FirstChild()) {
    if (child->ChildrenInline())
      return To<LayoutBlockFlow>(child);
  }
  return nullptr;
}

// An inline-block uses its inlineBox as the inlineBoxWrapper,
// so the firstChild() is nullptr if the only child is an empty inline-block.
inline bool LayoutBlock::IsInlineBoxWrapperActuallyChild() const {
  NOT_DESTROYED();
  return IsInline() && IsAtomicInlineLevel() && !Size().IsEmpty() &&
         GetNode() && EditingIgnoresContent(*GetNode());
}

PhysicalRect LayoutBlock::LocalCaretRect(int caret_offset) const {
  NOT_DESTROYED();
  // Do the normal calculation in most cases.
  if ((FirstChild() && !FirstChild()->IsPseudoElement()) ||
      IsInlineBoxWrapperActuallyChild()) {
    return LayoutBox::LocalCaretRect(caret_offset);
  }

  const ComputedStyle& style = StyleRef();
  const bool is_horizontal = style.IsHorizontalWritingMode();

  LayoutUnit inline_size = is_horizontal ? Size().width : Size().height;
  LogicalRect caret_rect =
      LocalCaretRectForEmptyElement(inline_size, TextIndentOffset());
  return CreateWritingModeConverter().ToPhysical(caret_rect);
}

void LayoutBlock::AddOutlineRects(OutlineRectCollector& collector,
                                  OutlineInfo* info,
                                  const PhysicalOffset& additional_offset,
                                  OutlineType include_block_overflows) const {
  NOT_DESTROYED();
#if DCHECK_IS_ON()
  // TODO(crbug.com/987836): enable this DCHECK universally.
  Page* page = GetDocument().GetPage();
  if (page && !page->GetSettings().GetSpatialNavigationEnabled()) {
    DCHECK_GE(GetDocument().Lifecycle().GetState(),
              DocumentLifecycle::kAfterPerformLayout);
  }
#endif  // DCHECK_IS_ON()

  // For anonymous blocks, the children add outline rects.
  if (!IsAnonymous()) {
    collector.AddRect(PhysicalRect(additional_offset, Size()));
  }

  if (ShouldIncludeBlockInkOverflow(include_block_overflows) &&
      !HasNonVisibleOverflow() && !HasControlClip()) {
    AddOutlineRectsForNormalChildren(collector, additional_offset,
                                     include_block_overflows);
  }
  if (info)
    *info = OutlineInfo::GetFromStyle(StyleRef());
}

LayoutBox* LayoutBlock::CreateAnonymousBoxWithSameTypeAs(
    const LayoutObject* parent) const {
  NOT_DESTROYED();
  return CreateAnonymousWithParentAndDisplay(parent, StyleRef().Display());
}

const char* LayoutBlock::GetName() const {
  NOT_DESTROYED();
  NOTREACHED();
}

LayoutBlock* LayoutBlock::CreateAnonymousWithParentAndDisplay(
    const LayoutObject* parent,
    EDisplay display) {
  // TODO(layout-dev): Do we need to convert all our inline displays to block
  // type in the anonymous logic?
  EDisplay new_display;
  switch (display) {
    case EDisplay::kFlex:
    case EDisplay::kInlineFlex:
      new_display = EDisplay::kFlex;
      break;
    case EDisplay::kGrid:
    case EDisplay::kInlineGrid:
      new_display = EDisplay::kGrid;
      break;
    case EDisplay::kFlowRoot:
      new_display = EDisplay::kFlowRoot;
      break;
    case EDisplay::kBlockMath:
      new_display = EDisplay::kBlockMath;
      break;
    default:
      new_display = EDisplay::kBlock;
      break;
  }
  ComputedStyleBuilder new_style_builder =
      parent->GetDocument()
          .GetStyleResolver()
          .CreateAnonymousStyleBuilderWithDisplay(parent->StyleRef(),
                                                  new_display);

  parent->UpdateAnonymousChildStyle(nullptr, new_style_builder);
  const ComputedStyle* new_style = new_style_builder.TakeStyle();

  LayoutBlock* layout_block;
  if (new_display == EDisplay::kFlex) {
    layout_block =
        MakeGarbageCollected<LayoutFlexibleBox>(/* element */ nullptr);
  } else if (new_display == EDisplay::kGrid) {
    layout_block = MakeGarbageCollected<LayoutGrid>(/* element */ nullptr);
  } else if (new_display == EDisplay::kBlockMath) {
    layout_block =
        MakeGarbageCollected<LayoutMathMLBlock>(/* element */ nullptr);
  } else {
    DCHECK(new_display == EDisplay::kBlock ||
           new_display == EDisplay::kFlowRoot);
    layout_block = MakeGarbageCollected<LayoutBlockFlow>(nullptr);
  }
  layout_block->SetDocumentForAnonymous(&parent->GetDocument());
  layout_block->SetStyle(new_style);
  return layout_block;
}

RecalcScrollableOverflowResult LayoutBlock::RecalcScrollableOverflow() {
  NOT_DESTROYED();
  DCHECK(!DisableLayoutSideEffectsScope::IsDisabled());
  return RecalcScrollableOverflowNG();
}

void LayoutBlock::RecalcVisualOverflow() {
  NOT_DESTROYED();
  if (!PhysicalFragmentCount()) {
    ClearVisualOverflow();
    return;
  }

  DCHECK(CanUseFragmentsForVisualOverflow());
  DCHECK(!DisplayLockUtilities::LockedAncestorPreventingPrePaint(*this));
  for (const PhysicalBoxFragment& fragment : PhysicalFragments()) {
    DCHECK(fragment.CanUseFragmentsForInkOverflow());
    fragment.GetMutableForPainting().RecalcInkOverflow();
  }
}

}  // namespace blink

"""

```