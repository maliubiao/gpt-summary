Response:
My thinking process to analyze the code and fulfill the request goes like this:

1. **Understand the Goal:** The primary goal is to understand the functionality of `box_fragment_painter.cc` within the Chromium Blink rendering engine. The request specifically asks for connections to web technologies (HTML, CSS, JavaScript), logical inferences with input/output examples, common usage errors, debugging clues, and a summary of its function.

2. **Initial Code Scan (Headers and Namespace):** I start by looking at the included headers. These immediately give clues about the file's responsibilities. I see headers related to:
    * **Paint:**  `box_background_paint_context.h`, `box_border_painter.h`, `fragment_painter.h`, `inline_box_fragment_painter.h`, `paint_info.h`, etc. This strongly suggests the file is involved in the painting process.
    * **Layout:** `layout/`, `geometry/box_strut.h`, `layout_inline.h`, `layout_block.h`, etc. This indicates a connection to the layout engine, managing the structure and position of elements.
    * **Editing:** `editing/drag_caret.h`, `editing/frame_selection.h`. This hints at handling text selection and drag-and-drop related visuals.
    * **Frame/Page:** `frame/local_frame.h`, `frame/pagination_state.h`, `page/page.h`. This points to interactions with the overall document structure and pagination.
    * **CSS:** `css/style_engine.h`. This is a direct link to CSS styling.
    * **Graphics:** `platform/graphics/`. This confirms the rendering aspect, dealing with the actual drawing.
    * **Other:**  Utilities like `<algorithm>`, `<numeric>`, `<vector>`, and Chromium base libraries (`base/`) suggest general programming logic.

3. **Identify Key Classes and Functions:**  The class name itself, `BoxFragmentPainter`, is a major clue. The `Paint()` method is the most obvious entry point for its core functionality. I'd then look for other methods like `HitTestAllPhases()`, `NodeAtPoint()`, `PaintObject()`, `PaintLineBoxes()`, etc. These names suggest specific aspects of rendering and interaction handling.

4. **Analyze Core Functionality - Painting:** The `Paint()` and `PaintInternal()` methods are crucial. I see logic for:
    * **Visibility checks:** `IsVisibleToPaint()`.
    * **Different paint phases:**  `PaintPhase` enum and conditional logic based on it (e.g., background, foreground, outlines).
    * **Handling different box types:**  Inline, block, replaced elements, tables, etc. The code uses `DynamicTo<>` for type casting.
    * **Calling other painters:** `BoxBackgroundPaintContext`, `BoxBorderPainter`, `InlineBoxFragmentPainter`, `TextFragmentPainter`, etc. This shows a delegation of responsibilities.
    * **Handling text-combine:** Special logic for vertical text rendering.
    * **Painting carets:**  `PaintCaretsIfNeeded()`.
    * **Painting scrollbars:** `PaintOverflowControls()`.
    * **View Transitions:** Checking `ShouldDelegatePaintingToViewTransition()`.

5. **Analyze Hit Testing:** The presence of `HitTestAllPhases()`, `NodeAtPoint()`, and related helper functions indicates responsibility for determining which element is clicked or hovered. I note the handling of:
    * **Visibility for hit testing:** `IsVisibleToHitTest()`.
    * **Pointer events:**  Checking `style.UsedPointerEvents()`.
    * **Culled inline ancestors:** `HitTestCulledInlineAncestors()`. This is a more complex scenario where inline elements don't have their own box fragments.

6. **Connect to Web Technologies:** Based on the identified functionalities, I can make connections to HTML, CSS, and JavaScript:
    * **HTML:** The code renders elements defined in HTML. The concept of "box fragments" relates to how HTML elements are broken down for layout and rendering.
    * **CSS:** The code directly interacts with `ComputedStyle`. CSS properties like `background-color`, `border`, `visibility`, `pointer-events`, `text-combine-upright`, etc., directly influence the painting and hit-testing logic.
    * **JavaScript:** While this file is C++, its actions are triggered by the browser's rendering pipeline, which is often initiated or manipulated by JavaScript (e.g., changing styles, adding/removing elements, scrolling).

7. **Logical Inferences and Examples:**  I try to think about scenarios and what the input/output would be. For example:
    * **Input:** A `div` element with a red background. **Output:** The `PaintObject()` method would call `PaintBoxDecorationBackground()` with the red color to draw the background.
    * **Input:**  A `span` element inside a `p` element is clicked. **Output:** The `HitTestAllPhases()` or `NodeAtPoint()` functions would traverse the fragment tree to identify the `span` as the target.

8. **Common Usage Errors:**  I consider what developers might do that could lead to issues this code handles or reveals:
    * Incorrect or missing CSS styling.
    * Overlapping elements causing unexpected hit-testing behavior.
    * Performance issues with complex layouts or excessive repaints.

9. **Debugging Clues:** I think about how a developer might end up in this code during debugging:
    * Using browser developer tools to inspect elements and their rendering properties.
    * Setting breakpoints in the Blink rendering code to understand the paint flow.
    * Investigating issues related to visual glitches, incorrect hit testing, or performance.

10. **Summarize the Functionality:** Finally, I synthesize all the information into a concise summary, focusing on the core responsibilities of the `BoxFragmentPainter`.

11. **Structure the Output:**  I organize the information according to the specific questions in the request, ensuring clarity and providing relevant code snippets or examples where necessary. I also pay attention to the "Part 1 of 4" instruction and focus on summarizing the overall functionality in this part.

By following this structured approach, I can systematically analyze the code and extract the necessary information to answer the prompt effectively. The key is to connect the low-level C++ code to the high-level concepts of web development.
好的，让我们来分析一下 `blink/renderer/core/paint/box_fragment_painter.cc` 文件的功能。

**文件功能归纳（第1部分）:**

`box_fragment_painter.cc` 文件的主要职责是**负责绘制代表HTML元素的“盒模型片段”（Box Fragments）**。  更具体地说，它处理以下核心功能：

* **盒模型片段的绘制协调:**  它是一个中心类，协调各种与盒模型片段绘制相关的操作。
* **不同绘制阶段的处理:**  它根据不同的绘制阶段（例如：背景、前景、轮廓）来执行相应的绘制逻辑。
* **委托给更细粒度的绘制器:**  它将具体的绘制任务委托给其他专门的绘制器，例如 `BoxBackgroundPaintContext` (绘制背景), `BoxBorderPainter` (绘制边框), `InlineBoxFragmentPainter` (绘制行内盒模型片段) 等。
* **处理不同类型的盒模型片段:**  它可以处理不同类型的盒模型片段，例如块级元素、行内元素、表格、浮动元素等。
* **处理文本相关的绘制:**  包括文本的背景、装饰线以及光标的绘制。
* **处理滚动条:**  负责绘制元素的滚动条。
* **处理命中测试:**  参与确定用户点击或悬停在哪个元素上。
* **处理视图过渡:**  在视图过渡动画期间，可能会将部分绘制工作委托给视图过渡相关的机制。

**与 Javascript, HTML, CSS 的关系及举例说明:**

`box_fragment_painter.cc` 位于渲染引擎的核心部分，直接参与将 HTML 结构和 CSS 样式转化为用户可见的像素。

* **HTML:**  HTML 定义了页面的结构，每个 HTML 元素都会对应一个或多个盒模型片段。`box_fragment_painter.cc` 的输入是这些盒模型片段，它负责将这些片段渲染到屏幕上。
    * **例子:**  一个简单的 `<div>` 元素在 HTML 中定义，渲染引擎会为其创建一个对应的盒模型片段，`box_fragment_painter.cc` 将会根据 CSS 样式来绘制这个 `<div>` 的背景、边框等。
* **CSS:** CSS 决定了盒模型片段的样式，例如背景颜色、边框样式、字体颜色等等。`box_fragment_painter.cc` 会读取元素的 `ComputedStyle` (计算后的样式)，并根据这些样式来执行绘制操作。
    * **例子:** 如果 CSS 中设置了 `div { background-color: blue; border: 1px solid black; }`，那么 `box_fragment_painter.cc` 在绘制该 `div` 对应的盒模型片段时，会调用 `BoxBackgroundPaintContext` 绘制蓝色背景，并调用 `BoxBorderPainter` 绘制黑色边框。
* **Javascript:**  虽然 `box_fragment_painter.cc` 本身是 C++ 代码，但 Javascript 可以通过修改 DOM 结构或 CSS 样式来间接影响其行为。例如，Javascript 动态修改元素的样式，会导致重新布局和重绘，进而触发 `box_fragment_painter.cc` 的工作。
    * **例子:**  Javascript 代码 `document.getElementById('myDiv').style.backgroundColor = 'red';` 会修改 id 为 `myDiv` 的元素的背景色。这会导致渲染引擎重新绘制该元素，`box_fragment_painter.cc` 会在新的绘制过程中使用红色来绘制背景。

**逻辑推理、假设输入与输出:**

假设我们有一个简单的 HTML 结构：

```html
<div style="width: 100px; height: 50px; background-color: lightblue;">Hello</div>
```

**假设输入:**

* 一个代表该 `<div>` 元素的 `PhysicalBoxFragment` 对象，包含了其位置、尺寸、层叠上下文等信息。
* 该元素的计算样式 `ComputedStyle`，包含 `background-color: lightblue` 等属性。
* 当前的 `PaintInfo` 对象，指定了当前的绘制阶段 (例如 `PaintPhase::kBlockBackground`) 和绘制上下文。

**逻辑推理:**

1. `BoxFragmentPainter::Paint()` 方法会被调用，传入上述的 `PhysicalBoxFragment` 和 `PaintInfo`。
2. 如果 `PaintInfo` 的 `phase` 是 `PaintPhase::kBlockBackground`，则会进入绘制背景的逻辑。
3. `PaintInternal()` 方法会被调用，并创建一个 `ScopedPaintState` 来管理绘制状态。
4. `ShouldPaintSelfBlockBackground()` 会返回 true。
5. `PaintObject()` 方法会被调用。
6. 在 `PaintObject()` 中，会调用 `PaintBoxDecorationBackground()` 方法。
7. `PaintBoxDecorationBackground()` 内部会使用 `BoxBackgroundPaintContext` 来在指定的区域绘制浅蓝色背景。

**假设输出:**

* 在屏幕上，该 `<div>` 元素会被渲染成一个 100px 宽，50px 高，背景色为浅蓝色的矩形。
* 在渲染过程中，相关的图形绘制命令会被添加到当前的绘制上下文中。

**用户或编程常见的使用错误:**

* **CSS 样式冲突导致意外的渲染结果:** 用户可能定义了相互冲突的 CSS 样式，导致 `box_fragment_painter.cc` 使用的计算样式与预期不符，从而产生错误的渲染。
    * **例子:**  同时设置了 `background-color: red;` 和 `background-image: url(...)`，可能导致只显示背景图片而看不到背景颜色。
* **Z-index 使用不当导致元素遮挡:**  如果元素的 `z-index` 属性设置不当，可能会导致某些元素被错误地遮挡或显示在错误的层叠顺序上。虽然 `box_fragment_painter.cc` 本身不直接处理 `z-index`，但它绘制的结果会受到层叠上下文的影响。
* **修改了影响布局的 CSS 属性后未触发重绘:**  在某些情况下，开发者可能通过 Javascript 修改了影响元素布局的 CSS 属性，但浏览器可能没有立即触发重绘，导致页面显示不一致。这可能需要手动触发重绘操作。

**用户操作如何一步步到达这里，作为调试线索:**

1. **用户访问网页:**  用户在浏览器中输入网址或点击链接，浏览器开始加载网页的 HTML、CSS 和 Javascript 资源。
2. **HTML 解析和 DOM 树构建:**  浏览器解析 HTML 代码，构建 DOM (Document Object Model) 树，表示页面的结构。
3. **CSS 解析和样式计算:**  浏览器解析 CSS 样式表，计算每个元素的最终样式 (ComputedStyle)。
4. **布局计算 (Layout):**  渲染引擎根据 DOM 树和计算后的样式，计算每个元素在页面上的位置和尺寸，生成布局树。
5. **构建渲染树 (Render Tree) 和分片 (Fragmentation):**  渲染树是只包含需要渲染的元素的树。对于复杂的布局，元素可能会被分割成多个片段 (fragments) 进行渲染，例如长文本会被分割成多行。 `PhysicalBoxFragment` 就是布局计算的产物。
6. **构建绘制列表 (Paint List):**  渲染引擎遍历渲染树，为每个需要绘制的元素和片段生成绘制指令，形成绘制列表。 `box_fragment_painter.cc` 的调用通常在这个阶段。
7. **执行绘制 (Painting):**  浏览器按照绘制列表中的指令，调用相应的绘制器 (例如 `box_fragment_painter.cc`) 将内容绘制到屏幕上。

**调试线索:**

* **在开发者工具的 "Elements" 面板中检查元素的样式:**  查看元素的 "Computed" 标签，可以了解元素最终的计算样式，确认 CSS 是否按预期生效。
* **使用开发者工具的 "Rendering" 标签:**  可以开启 "Paint flashing" 或 "Layout Shift Regions" 等功能，帮助识别哪些区域发生了重绘或布局偏移。
* **在 Blink 源代码中设置断点:**  对于 Chromium 的开发者，可以在 `box_fragment_painter.cc` 的关键方法 (例如 `Paint`, `PaintInternal`, `PaintObject`) 设置断点，查看代码执行流程和相关变量的值，了解绘制过程中的具体细节。
* **查看 Layer 树:** 开发者工具的 "Layers" 面板可以展示页面的 Layer 结构，了解元素的层叠关系，有助于排查 z-index 相关的问题。

希望以上分析对您有所帮助！ 如果有其他问题，请随时提出。

### 提示词
```
这是目录为blink/renderer/core/paint/box_fragment_painter.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/paint/box_fragment_painter.h"

#include <algorithm>
#include <numeric>
#include <vector>

#include "base/containers/adapters.h"
#include "base/ranges/algorithm.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/editing/drag_caret.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/pagination_state.h"
#include "third_party/blink/renderer/core/layout/background_bleed_avoidance.h"
#include "third_party/blink/renderer/core/layout/block_break_token.h"
#include "third_party/blink/renderer/core/layout/fragmentation_utils.h"
#include "third_party/blink/renderer/core/layout/geometry/box_strut.h"
#include "third_party/blink/renderer/core/layout/hit_test_location.h"
#include "third_party/blink/renderer/core/layout/hit_test_result.h"
#include "third_party/blink/renderer/core/layout/inline/fragment_items.h"
#include "third_party/blink/renderer/core/layout/inline/inline_cursor.h"
#include "third_party/blink/renderer/core/layout/inline/physical_line_box_fragment.h"
#include "third_party/blink/renderer/core/layout/layout_inline.h"
#include "third_party/blink/renderer/core/layout/layout_text_combine.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/layout/outline_utils.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"
#include "third_party/blink/renderer/core/layout/pointer_events_hit_rules.h"
#include "third_party/blink/renderer/core/layout/table/layout_table.h"
#include "third_party/blink/renderer/core/layout/table/layout_table_cell.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/paint/box_background_paint_context.h"
#include "third_party/blink/renderer/core/paint/box_border_painter.h"
#include "third_party/blink/renderer/core/paint/box_decoration_data.h"
#include "third_party/blink/renderer/core/paint/box_painter.h"
#include "third_party/blink/renderer/core/paint/fieldset_painter.h"
#include "third_party/blink/renderer/core/paint/fragment_painter.h"
#include "third_party/blink/renderer/core/paint/frame_set_painter.h"
#include "third_party/blink/renderer/core/paint/inline_box_fragment_painter.h"
#include "third_party/blink/renderer/core/paint/mathml_painter.h"
#include "third_party/blink/renderer/core/paint/object_painter.h"
#include "third_party/blink/renderer/core/paint/paint_auto_dark_mode.h"
#include "third_party/blink/renderer/core/paint/paint_info.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/paint/paint_phase.h"
#include "third_party/blink/renderer/core/paint/rounded_border_geometry.h"
#include "third_party/blink/renderer/core/paint/scoped_paint_state.h"
#include "third_party/blink/renderer/core/paint/scoped_svg_paint_state.h"
#include "third_party/blink/renderer/core/paint/scrollable_area_painter.h"
#include "third_party/blink/renderer/core/paint/table_painters.h"
#include "third_party/blink/renderer/core/paint/text_combine_painter.h"
#include "third_party/blink/renderer/core/paint/text_fragment_painter.h"
#include "third_party/blink/renderer/core/paint/theme_painter.h"
#include "third_party/blink/renderer/core/paint/timing/paint_timing.h"
#include "third_party/blink/renderer/core/paint/timing/paint_timing_detector.h"
#include "third_party/blink/renderer/core/paint/url_metadata_utils.h"
#include "third_party/blink/renderer/core/paint/view_painter.h"
#include "third_party/blink/renderer/core/scroll/scroll_types.h"
#include "third_party/blink/renderer/core/view_transition/view_transition_utils.h"
#include "third_party/blink/renderer/platform/graphics/graphics_context_state_saver.h"
#include "third_party/blink/renderer/platform/graphics/paint/display_item_cache_skipper.h"
#include "third_party/blink/renderer/platform/graphics/paint/drawing_recorder.h"
#include "third_party/blink/renderer/platform/graphics/paint/scoped_display_item_fragment.h"

namespace blink {

namespace {

inline bool HasSelection(const LayoutObject* layout_object) {
  return layout_object->GetSelectionState() != SelectionState::kNone;
}

inline bool IsVisibleToPaint(const PhysicalFragment& fragment,
                             const ComputedStyle& style) {
  if (fragment.IsHiddenForPaint())
    return false;
  if (style.Visibility() != EVisibility::kVisible) {
    auto display = style.Display();
    // Hidden section/row backgrounds still paint into cells.
    if (display != EDisplay::kTableRowGroup && display != EDisplay::kTableRow &&
        display != EDisplay::kTableColumn &&
        display != EDisplay::kTableColumnGroup) {
      return false;
    }
  }

  // When |LineTruncator| sets |IsHiddenForPaint|, it sets to the fragment in
  // the line. However, when it has self-painting layer, the fragment stored in
  // |LayoutBlockFlow| will be painted. Check |IsHiddenForPaint| of the fragment
  // in the inline formatting context.
  if (fragment.IsAtomicInline() && fragment.HasSelfPaintingLayer())
      [[unlikely]] {
    const LayoutObject* layout_object = fragment.GetLayoutObject();
    if (layout_object->IsInLayoutNGInlineFormattingContext()) {
      InlineCursor cursor;
      cursor.MoveTo(*layout_object);
      if (cursor && cursor.Current().IsHiddenForPaint())
        return false;
    }
  }

  return true;
}

inline bool IsVisibleToPaint(const FragmentItem& item,
                             const ComputedStyle& style) {
  return !item.IsHiddenForPaint() &&
         style.Visibility() == EVisibility::kVisible;
}

inline bool IsVisibleToHitTest(const ComputedStyle& style,
                               const HitTestRequest& request) {
  return request.IgnorePointerEventsNone() ||
         style.UsedPointerEvents() != EPointerEvents::kNone;
}

inline bool IsVisibleToHitTest(const FragmentItem& item,
                               const HitTestRequest& request) {
  const ComputedStyle& style = item.Style();
  if (!item.IsSvgText()) {
    return IsVisibleToPaint(item, style) && IsVisibleToHitTest(style, request);
  }

  if (item.IsHiddenForPaint())
    return false;
  PointerEventsHitRules hit_rules(PointerEventsHitRules::kSvgTextHitTesting,
                                  request, style.UsedPointerEvents());
  if (hit_rules.require_visible &&
      style.Visibility() != EVisibility::kVisible) {
    return false;
  }
  if (hit_rules.can_hit_bounding_box ||
      (hit_rules.can_hit_stroke &&
       (style.HasStroke() || !hit_rules.require_stroke)) ||
      (hit_rules.can_hit_fill && (style.HasFill() || !hit_rules.require_fill)))
    return IsVisibleToHitTest(style, request);
  return false;
}

inline bool IsVisibleToHitTest(const PhysicalFragment& fragment,
                               const HitTestRequest& request) {
  const ComputedStyle& style = fragment.Style();
  return IsVisibleToPaint(fragment, style) &&
         IsVisibleToHitTest(style, request);
}

// Hit tests inline ancestor elements of |fragment| who do not have their own
// box fragments.
// @param physical_offset Physical offset of |fragment| in the paint layer.
bool HitTestCulledInlineAncestors(
    HitTestResult& result,
    const InlineCursor& parent_cursor,
    const LayoutObject* current,
    const LayoutObject* limit,
    const InlineCursorPosition& previous_sibling,
    const HitTestLocation& hit_test_location,
    const PhysicalOffset fallback_accumulated_offset) {
  DCHECK(current != limit && current->IsDescendantOf(limit));

  // Check ancestors only when |current| is the first fragment in this line.
  if (previous_sibling && current == previous_sibling.GetLayoutObject())
    return false;

  for (LayoutObject* parent = current->Parent(); parent && parent != limit;
       current = parent, parent = parent->Parent()) {
    // |culled_parent| is a culled inline element to be hit tested, since it's
    // "between" |fragment| and |fragment->Parent()| but doesn't have its own
    // box fragment.
    // To ensure the correct hit test ordering, |culled_parent| must be hit
    // tested only once after all of its descendants are hit tested:
    // - Shortcut: when |current_layout_object| is the only child (of
    // |culled_parent|), since it's just hit tested, we can safely hit test its
    // parent;
    // - General case: we hit test |culled_parent| only when it is not an
    // ancestor of |previous_sibling|; otherwise, |previous_sibling| has to be
    // hit tested first.
    // TODO(crbug.com/849331): It's wrong for bidi inline fragmentation. Fix it.
    const bool has_sibling =
        current->PreviousSibling() || current->NextSibling();
    if (has_sibling && previous_sibling &&
        previous_sibling.GetLayoutObject()->IsDescendantOf(parent))
      break;

    if (auto* parent_layout_inline = DynamicTo<LayoutInline>(parent)) {
      if (parent_layout_inline->HitTestCulledInline(result, hit_test_location,
                                                    fallback_accumulated_offset,
                                                    parent_cursor)) {
        return true;
      }
    }
  }

  return false;
}

bool HitTestCulledInlineAncestors(HitTestResult& result,
                                  const PhysicalBoxFragment& container,
                                  const InlineCursor& parent_cursor,
                                  const FragmentItem& item,
                                  const InlineCursorPosition& previous_sibling,
                                  const HitTestLocation& hit_test_location,
                                  const PhysicalOffset& physical_offset) {
  // Ellipsis can appear under a different parent from the ellipsized object
  // that it can confuse culled inline logic.
  if (item.IsEllipsis()) [[unlikely]] {
    return false;
  }
  // To be passed as |accumulated_offset| to LayoutInline::HitTestCulledInline,
  // where it equals the physical offset of the containing block in paint layer.
  const PhysicalOffset fallback_accumulated_offset =
      physical_offset - item.OffsetInContainerFragment();
  return HitTestCulledInlineAncestors(
      result, parent_cursor, item.GetLayoutObject(),
      // Limit the traversal up to the container fragment, or its container if
      // the fragment is not a CSSBox.
      container.GetSelfOrContainerLayoutObject(), previous_sibling,
      hit_test_location, fallback_accumulated_offset);
}

// Returns a vector of backplates that surround the paragraphs of text within
// line_boxes.
//
// This function traverses descendants of an inline formatting context in
// pre-order DFS and build up backplates behind inline text boxes, each split at
// the paragraph level. Store the results in paragraph_backplates.
Vector<PhysicalRect> BuildBackplate(InlineCursor* descendants,
                                    const PhysicalOffset& paint_offset) {
  // The number of consecutive forced breaks that split the backplate by
  // paragraph.
  static constexpr int kMaxConsecutiveLineBreaks = 2;

  struct Backplates {
    STACK_ALLOCATED();

   public:
    void AddTextRect(const PhysicalRect& box_rect) {
      if (consecutive_line_breaks >= kMaxConsecutiveLineBreaks) {
        // This is a paragraph point.
        paragraph_backplates.push_back(current_backplate);
        current_backplate = PhysicalRect();
      }
      consecutive_line_breaks = 0;

      current_backplate.Unite(box_rect);
    }

    void AddLineBreak() { consecutive_line_breaks++; }

    Vector<PhysicalRect> paragraph_backplates;
    PhysicalRect current_backplate;
    int consecutive_line_breaks = 0;
  } backplates;

  // Build up and paint backplates of all child inline text boxes. We are not
  // able to simply use the linebox rect to compute the backplate because the
  // backplate should only be painted for inline text and not for atomic
  // inlines.
  for (; *descendants; descendants->MoveToNext()) {
    if (const FragmentItem* child_item = descendants->CurrentItem()) {
      if (child_item->IsHiddenForPaint())
        continue;
      if (child_item->IsText()) {
        if (child_item->IsLineBreak()) {
          backplates.AddLineBreak();
          continue;
        }

        PhysicalRect box_rect(
            child_item->OffsetInContainerFragment() + paint_offset,
            child_item->Size());
        backplates.AddTextRect(box_rect);
      }
      continue;
    }
    NOTREACHED();
  }

  if (!backplates.current_backplate.IsEmpty())
    backplates.paragraph_backplates.push_back(backplates.current_backplate);
  return backplates.paragraph_backplates;
}

bool HitTestAllPhasesInFragment(const PhysicalBoxFragment& fragment,
                                const HitTestLocation& hit_test_location,
                                PhysicalOffset accumulated_offset,
                                HitTestResult* result) {
  // Hit test all phases of inline blocks, inline tables, replaced elements and
  // non-positioned floats as if they created their own (pseudo- [1]) stacking
  // context. https://www.w3.org/TR/CSS22/zindex.html#painting-order
  //
  // [1] As if it creates a new stacking context, but any positioned descendants
  // and descendants which actually create a new stacking context should be
  // considered part of the parent stacking context, not this new one.

  if (!fragment.CanTraverse()) {
    if (!fragment.IsFirstForNode() && !CanPaintMultipleFragments(fragment))
      return false;
    return fragment.GetMutableLayoutObject()->HitTestAllPhases(
        *result, hit_test_location, accumulated_offset);
  }

  if (!fragment.MayIntersect(*result, hit_test_location, accumulated_offset))
    return false;

  return BoxFragmentPainter(To<PhysicalBoxFragment>(fragment))
      .HitTestAllPhases(*result, hit_test_location, accumulated_offset);
}

bool NodeAtPointInFragment(const PhysicalBoxFragment& fragment,
                           const HitTestLocation& hit_test_location,
                           PhysicalOffset accumulated_offset,
                           HitTestPhase phase,
                           HitTestResult* result) {
  if (!fragment.CanTraverse()) {
    if (!fragment.IsFirstForNode() && !CanPaintMultipleFragments(fragment))
      return false;
    return fragment.GetMutableLayoutObject()->NodeAtPoint(
        *result, hit_test_location, accumulated_offset, phase);
  }

  if (!fragment.MayIntersect(*result, hit_test_location, accumulated_offset))
    return false;

  return BoxFragmentPainter(fragment).NodeAtPoint(*result, hit_test_location,
                                                  accumulated_offset, phase);
}

// Return an ID for this fragmentainer, which is unique within the fragmentation
// context. We need to provide this ID when block-fragmenting, so that we can
// cache the painting of each individual fragment.
unsigned FragmentainerUniqueIdentifier(const PhysicalBoxFragment& fragment) {
  if (const auto* break_token = fragment.GetBreakToken()) {
    return break_token->SequenceNumber() + 1;
  }
  return 0;
}

bool ShouldPaintCursorCaret(const PhysicalBoxFragment& fragment) {
  return fragment.GetLayoutObject()->GetFrame()->Selection().ShouldPaintCaret(
      fragment);
}

bool ShouldPaintDragCaret(const PhysicalBoxFragment& fragment) {
  return fragment.GetLayoutObject()
      ->GetFrame()
      ->GetPage()
      ->GetDragCaret()
      .ShouldPaintCaret(fragment);
}

bool ShouldPaintCarets(const PhysicalBoxFragment& fragment) {
  return ShouldPaintCursorCaret(fragment) || ShouldPaintDragCaret(fragment);
}

PaintInfo FloatPaintInfo(const PaintInfo& paint_info) {
  PaintInfo float_paint_info(paint_info);
  if (paint_info.phase == PaintPhase::kFloat)
    float_paint_info.phase = PaintPhase::kForeground;
  return float_paint_info;
}

// Helper function for painting a child fragment, when there's any likelihood
// that we need legacy fallback. If it's guaranteed that legacy fallback won't
// be necessary, on the other hand, there's no need to call this function. In
// such cases, call sites may just as well invoke BoxFragmentPainter::Paint()
// on their own.
void PaintFragment(const PhysicalBoxFragment& fragment,
                   const PaintInfo& paint_info) {
  if (fragment.CanTraverse()) {
    BoxFragmentPainter(fragment).Paint(paint_info);
    return;
  }

  if (fragment.IsHiddenForPaint() ||
      (!fragment.IsFirstForNode() && !CanPaintMultipleFragments(fragment))) {
    return;
  }

  // We are about to enter legacy paint code. This means that the node is
  // monolithic. However, that doesn't necessarily mean that it only has one
  // fragment. Repeated table headers / footers may cause multiple fragments,
  // for instance. Set the FragmentData, to use the right paint offset.
  PaintInfo modified_paint_info(paint_info);
  modified_paint_info.SetFragmentDataOverride(fragment.GetFragmentData());

  auto* layout_object = fragment.GetLayoutObject();
  DCHECK(layout_object);
  if (fragment.IsPaintedAtomically() && layout_object->IsLayoutReplaced()) {
    ObjectPainter(*layout_object).PaintAllPhasesAtomically(modified_paint_info);
  } else {
    layout_object->Paint(modified_paint_info);
  }
}

bool ShouldDelegatePaintingToViewTransition(const PhysicalBoxFragment& fragment,
                                            PaintPhase paint_phase) {
  if (!fragment.GetLayoutObject()) {
    return false;
  }

  switch (paint_phase) {
    case PaintPhase::kSelfBlockBackgroundOnly:
    case PaintPhase::kSelfOutlineOnly:
      return ViewTransitionUtils::
          ShouldDelegateEffectsAndBoxDecorationsToViewTransitionGroup(
              *fragment.GetLayoutObject());
    case PaintPhase::kBlockBackground:
    case PaintPhase::kDescendantBlockBackgroundsOnly:
    case PaintPhase::kForcedColorsModeBackplate:
    case PaintPhase::kFloat:
    case PaintPhase::kForeground:
    case PaintPhase::kOutline:
    case PaintPhase::kDescendantOutlinesOnly:
    case PaintPhase::kOverlayOverflowControls:
    case PaintPhase::kSelectionDragImage:
    case PaintPhase::kTextClip:
    case PaintPhase::kMask:
      return false;
  }
}

}  // anonymous namespace

PhysicalRect BoxFragmentPainter::InkOverflowIncludingFilters() const {
  if (box_item_)
    return box_item_->SelfInkOverflowRect();
  const auto& fragment = GetPhysicalFragment();
  DCHECK(!fragment.IsInlineBox());
  return To<LayoutBox>(fragment.GetLayoutObject())
      ->VisualOverflowRectIncludingFilters();
}

InlinePaintContext& BoxFragmentPainter::EnsureInlineContext() {
  if (!inline_context_)
    inline_context_ = &inline_context_storage_.emplace();
  return *inline_context_;
}

void BoxFragmentPainter::Paint(const PaintInfo& paint_info) {
  if (GetPhysicalFragment().IsHiddenForPaint()) {
    return;
  }
  auto* layout_object = box_fragment_.GetLayoutObject();
  if (GetPhysicalFragment().IsPaintedAtomically() &&
      !box_fragment_.HasSelfPaintingLayer() &&
      paint_info.phase != PaintPhase::kOverlayOverflowControls) {
    PaintAllPhasesAtomically(paint_info);
  } else if (layout_object && layout_object->IsSVGForeignObject()) {
    ScopedSVGPaintState paint_state(*layout_object, paint_info);
    PaintTiming::From(layout_object->GetDocument()).MarkFirstContentfulPaint();
    PaintInternal(paint_info);
  } else {
    PaintInternal(paint_info);
  }
}

void BoxFragmentPainter::PaintInternal(const PaintInfo& paint_info) {
  // Avoid initialization of Optional ScopedPaintState::chunk_properties_
  // and ScopedPaintState::adjusted_paint_info_.
  STACK_UNINITIALIZED ScopedPaintState paint_state(box_fragment_, paint_info);
  if (!ShouldPaint(paint_state))
    return;

  if (!box_fragment_.IsFirstForNode() &&
      !CanPaintMultipleFragments(box_fragment_))
    return;

  PaintInfo& info = paint_state.MutablePaintInfo();
  const PhysicalOffset paint_offset = paint_state.PaintOffset();
  const PaintPhase original_phase = info.phase;
  bool painted_overflow_controls = false;

  // For text-combine-upright:all, we need to realize canvas here for scaling
  // to fit text content in 1em and shear for "font-style: oblique -15deg".
  std::optional<DrawingRecorder> recorder;
  std::optional<GraphicsContextStateSaver> graphics_context_state_saver;
  const auto* const text_combine =
      DynamicTo<LayoutTextCombine>(box_fragment_.GetLayoutObject());
  if (text_combine) [[unlikely]] {
    if (text_combine->NeedsAffineTransformInPaint()) {
      if (original_phase == PaintPhase::kForeground)
        PaintCaretsIfNeeded(paint_state, paint_info, paint_offset);
      if (!paint_info.context.InDrawingRecorder()) {
        if (DrawingRecorder::UseCachedDrawingIfPossible(
                paint_info.context, GetDisplayItemClient(), paint_info.phase))
          return;
        recorder.emplace(paint_info.context, GetDisplayItemClient(),
                         paint_info.phase,
                         text_combine->VisualRectForPaint(paint_offset));
      }
      graphics_context_state_saver.emplace(paint_info.context);
      paint_info.context.ConcatCTM(
          text_combine->ComputeAffineTransformForPaint(paint_offset));
    }
  }

  ScopedPaintTimingDetectorBlockPaintHook
      scoped_paint_timing_detector_block_paint_hook;
  if (original_phase == PaintPhase::kForeground &&
      box_fragment_.GetLayoutObject()->IsBox()) {
    scoped_paint_timing_detector_block_paint_hook.EmplaceIfNeeded(
        To<LayoutBox>(*box_fragment_.GetLayoutObject()),
        paint_info.context.GetPaintController().CurrentPaintChunkProperties());
  }

  if (original_phase == PaintPhase::kOutline) {
    info.phase = PaintPhase::kDescendantOutlinesOnly;
  } else if (ShouldPaintSelfBlockBackground(original_phase)) {
    info.phase = PaintPhase::kSelfBlockBackgroundOnly;
    // We need to call PaintObject twice: one for painting background in the
    // border box space, and the other for painting background in the scrolling
    // contents space.
    const LayoutBox& box = To<LayoutBox>(*box_fragment_.GetLayoutObject());
    auto paint_location = box.GetBackgroundPaintLocation();
    if (!(paint_location & kBackgroundPaintInBorderBoxSpace))
      info.SetSkipsBackground(true);
    PaintObject(info, paint_offset);
    info.SetSkipsBackground(false);

    if ((RuntimeEnabledFeatures::HitTestOpaquenessEnabled() &&
         // We need to record hit test data for the scrolling contents.
         box.ScrollsOverflow()) ||
        (paint_location & kBackgroundPaintInContentsSpace)) {
      if (!(paint_location & kBackgroundPaintInContentsSpace)) {
        DCHECK(RuntimeEnabledFeatures::HitTestOpaquenessEnabled());
        info.SetSkipsBackground(true);
      }
      // If possible, paint overflow controls before scrolling background to
      // make it easier to merge scrolling background and scrolling contents
      // into the same layer. The function checks if it's appropriate to paint
      // overflow controls now.
      painted_overflow_controls = PaintOverflowControls(info, paint_offset);

      info.SetIsPaintingBackgroundInContentsSpace(true);
      PaintObject(info, paint_offset);
      info.SetIsPaintingBackgroundInContentsSpace(false);
      info.SetSkipsBackground(false);
    }

    if (ShouldPaintDescendantBlockBackgrounds(original_phase))
      info.phase = PaintPhase::kDescendantBlockBackgroundsOnly;
  }

  if (original_phase != PaintPhase::kSelfBlockBackgroundOnly &&
      original_phase != PaintPhase::kSelfOutlineOnly &&
      // kOverlayOverflowControls is for the current object itself, so we don't
      // need to traverse descendants here.
      original_phase != PaintPhase::kOverlayOverflowControls) {
    if (original_phase == PaintPhase::kMask ||
        !box_fragment_.GetLayoutObject()->IsBox()) {
      PaintObject(info, paint_offset);
    } else {
      ScopedBoxContentsPaintState contents_paint_state(
          paint_state, To<LayoutBox>(*box_fragment_.GetLayoutObject()));
      PaintObject(contents_paint_state.GetPaintInfo(),
                  contents_paint_state.PaintOffset());
    }
  }

  // If the caret's node's fragment's containing block is this block, and
  // the paint action is PaintPhaseForeground, then paint the caret.
  if (original_phase == PaintPhase::kForeground) {
    if (!recorder) [[likely]] {
      DCHECK(!text_combine || !text_combine->NeedsAffineTransformInPaint());
      PaintCaretsIfNeeded(paint_state, paint_info, paint_offset);
    }
  }

  if (ShouldPaintSelfOutline(original_phase)) {
    info.phase = PaintPhase::kSelfOutlineOnly;
    PaintObject(info, paint_offset);
  }

  if (text_combine && TextCombinePainter::ShouldPaint(*text_combine))
      [[unlikely]] {
    if (recorder) {
      // Paint text decorations and emphasis marks without scaling and share.
      DCHECK(text_combine->NeedsAffineTransformInPaint());
      graphics_context_state_saver->Restore();
    } else if (!paint_info.context.InDrawingRecorder()) {
      if (DrawingRecorder::UseCachedDrawingIfPossible(
              paint_info.context, GetDisplayItemClient(), paint_info.phase))
        return;
      recorder.emplace(paint_info.context, GetDisplayItemClient(),
                       paint_info.phase,
                       text_combine->VisualRectForPaint(paint_offset));
    }
    TextCombinePainter::Paint(info, paint_offset, *text_combine);
  }

  // If we haven't painted overflow controls, paint scrollbars after we painted
  // the other things, so that the scrollbars will sit above them.
  if (!painted_overflow_controls) {
    info.phase = original_phase;
    PaintOverflowControls(info, paint_offset);
  }
}

bool BoxFragmentPainter::PaintOverflowControls(
    const PaintInfo& paint_info,
    const PhysicalOffset& paint_offset) {
  if (!box_fragment_.IsScrollContainer())
    return false;

  return ScrollableAreaPainter(
             *GetPhysicalFragment().Layer()->GetScrollableArea())
      .PaintOverflowControls(paint_info, paint_offset,
                             box_fragment_.GetFragmentData());
}

void BoxFragmentPainter::RecordScrollHitTestData(
    const PaintInfo& paint_info,
    const DisplayItemClient& background_client) {
  if (!box_fragment_.GetLayoutObject()->IsBox())
    return;
  BoxPainter(To<LayoutBox>(*box_fragment_.GetLayoutObject()))
      .RecordScrollHitTestData(paint_info, background_client,
                               box_fragment_.GetFragmentData());
}

bool BoxFragmentPainter::ShouldRecordHitTestData(const PaintInfo& paint_info) {
  // Some conditions are checked in ObjectPainter::RecordHitTestData().
  // Table rows/sections do not participate in hit testing.
  return !GetPhysicalFragment().IsTableRow() &&
         !GetPhysicalFragment().IsTableSection();
}

void BoxFragmentPainter::PaintObject(const PaintInfo& paint_info,
                                     const PhysicalOffset& paint_offset,
                                     bool suppress_box_decoration_background) {
  const PaintPhase paint_phase = paint_info.phase;
  const PhysicalBoxFragment& fragment = GetPhysicalFragment();

  if (ShouldDelegatePaintingToViewTransition(fragment, paint_phase)) {
    return;
  }

  if (fragment.IsFrameSet()) {
    FrameSetPainter(fragment, display_item_client_)
        .PaintObject(paint_info, paint_offset);
    return;
  }
  const ComputedStyle& style = fragment.Style();
  const bool is_visible = IsVisibleToPaint(fragment, style);
  if (ShouldPaintSelfBlockBackground(paint_phase)) {
    if (is_visible) {
      PaintBoxDecorationBackground(paint_info, paint_offset,
                                   suppress_box_decoration_background);
    }
    // We're done. We don't bother painting any children.
    if (paint_phase == PaintPhase::kSelfBlockBackgroundOnly)
      return;
  }

  if (paint_phase == PaintPhase::kMask && is_visible) {
    PaintMask(paint_info, paint_offset);
    return;
  }

  if (paint_phase == PaintPhase::kForeground) {
    // PaintLineBoxes() calls AddURLRectsForInlineChildrenRecursively(). So we
    // don't need to call AddURLRectIfNeeded() for LayoutInline.
    if (paint_info.ShouldAddUrlMetadata()) {
      const auto* layout_object = fragment.GetLayoutObject();
      if (layout_object && !layout_object->IsLayoutInline()) {
        FragmentPainter(fragment, GetDisplayItemClient())
            .AddURLRectIfNeeded(paint_info, paint_offset);
      }
    }
    if (is_visible && fragment.HasExtraMathMLPainting())
      MathMLPainter(fragment).Paint(paint_info, paint_offset);
  }

  // Paint children.
  if (paint_phase != PaintPhase::kSelfOutlineOnly &&
      (!fragment.Children().empty() || fragment.HasItems() ||
       inline_box_cursor_) &&
      !paint_info.DescendantPaintingBlocked()) {
    if (paint_phase == PaintPhase::kDescendantBlockBackgroundsOnly &&
        is_visible && fragment.IsCSSBox() && style.HasColumnRule())
        [[unlikely]] {
      PaintColumnRules(paint_info, paint_offset);
    }

    if (paint_phase != PaintPhase::kFloat) {
      if (inline_box_cursor_) [[unlikely]] {
        // Use the descendants cursor for this painter if it is given.
        // Self-painting inline box paints only parts of the container block.
        // Adjust |paint_offset| because it is the offset of the inline box, but
        // |descendants_| has offsets to the contaiing block.
        DCHECK(box_item_);
        InlineCursor descendants = inline_box_cursor_->CursorForDescendants();
        const PhysicalOffset paint_offset_to_inline_formatting_context =
            paint_offset - box_item_->OffsetInContainerFragment();
        PaintInlineItems(paint_info.ForDescendants(),
                         paint_offset_to_inline_formatting_context,
                         box_item_->OffsetInContainerFragment(), &descendants);
      } else if (items_) {
        DCHECK(fragment.IsBlockFlow());
        PaintLineBoxes(paint_info, paint_offset);
      } else if (fragment.IsPaginatedRoot()) {
        PaintCurrentPageContainer(paint_info);
      } else if (!fragment.IsInlineFormattingContext()) {
        PaintBlockChildren(paint_info, paint_offset);
      }
    }

    if (paint_phase == PaintPhase::kFloat ||
        paint_phase == PaintPhase::kSelectionDragImage ||
        paint_phase == PaintPhase::kTextClip) {
      if (fragment.HasFloatingDescendantsForPaint())
        PaintFloats(paint_info);
    }
  }

  if (!is_visible)
    return;

  // Collapsed borders paint *after* children have painted their backgrounds.
  if (box_fragment_.IsTable() &&
      paint_phase == PaintPhase::kDescendantBlockBackgroundsOnly) {
    TablePainter(box_fragment_)
        .PaintCollapsedBorders(paint_info, paint_offset,
                               VisualRect(paint_offset));
  }

  if (ShouldPaintSelfOutline(paint_phase)) {
    if (HasPaintedOutline(style, fragment.GetNode())) {
      FragmentPainter(fragment, GetDisplayItemClient())
          .PaintOutline(paint_info, paint_offset, style);
    }
  }
}

void BoxFragmentPainter::PaintCaretsIfNeeded(
    const ScopedPaintState& paint_state,
    const PaintInfo& paint_info,
    const PhysicalOffset& paint_offset) {
  if (!ShouldPaintCarets(box_fragment_))
    return;

  // Apply overflow clip if needed.
  // reveal-caret-of-multiline-contenteditable.html needs this.
  std::optional<ScopedPaintChunkProperties> paint_chunk_properties;
  if (const auto* fragment = paint_state.FragmentToPaint()) {
    if (const auto* properties = fragment->PaintProperties()) {
      if (const auto* overflow_clip = properties->OverflowClip()) {
        paint_chunk_properties.emplace(
            paint_info.context.GetPaintController(), *overflow_clip,
            *box_fragment_.GetLayoutObject(), DisplayItem::kCaret);
      }
    }
  }

  LocalFrame* frame = box_fragment_.GetLayoutObject()->GetFrame();
  if (ShouldPaintCursorCaret(box_fragment_))
    frame->Selection().PaintCaret(paint_info.context, paint_offset);

  if (ShouldPaintDragCaret(box_fragment_)) {
    frame->GetPage()->GetDragCaret().PaintDragCaret(frame, paint_info.context,
                                                    paint_offset);
  }
}

void BoxFragmentPainter::PaintLineBoxes(const PaintInfo& paint_info,
                                        const PhysicalOffset& paint_offset) {
  const LayoutObject* layout_object = box_fragment_.GetLayoutObject();
  DCHECK(layout_object);
  DCHECK(layout_object->IsLayoutBlock());
  DCHECK(box_fragment_.IsInlineFormattingContext());

  // When the layout-tree gets into a bad state, we can end up trying to paint
  // a fra
```