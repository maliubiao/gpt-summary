Response:
Let's break down the thought process for analyzing the `text_fragment_painter.cc` file.

1. **Initial Skim and Keyword Recognition:**

   - The filename itself, "text_fragment_painter," immediately suggests its core function: painting portions of text.
   - Scanning the `#include` directives reveals interactions with various Blink components related to:
     - **Editing:** `editor.h`, `frame_selection.h`, `markers/...` (composition, document, text match). This hints at handling things like cursor, selections, and inline editing.
     - **Layout:** `geometry/...`, `inline/...`, `layout_counter.h`, `layout_text_combine.h`, `list_marker.h`, `physical_box_fragment.h`, `layout_svg_inline_text.h`, `text_decoration_offset.h`. This strongly indicates the painter works with the output of the layout process, knowing the geometric arrangement of text.
     - **Painting:** `box_model_object_painter.h`, `highlight_painter.h`, `inline_paint_context.h`, `line_relative_rect.h`, `object_painter.h`, `paint_auto_dark_mode.h`, `paint_info.h`, `selection_bounds_recorder.h`, `text_decoration_painter.h`, `text_painter.h`. This confirms its role in the painting pipeline.
     - **Styling:** `applied_text_decoration.h`, `computed_style.h`. The painter needs to consider CSS styles.
     - **SVG:** `svg_element.h`, `layout_svg_inline_text.h`. Handles text within SVG.
     - **Platform Graphics:** `character_range.h`, `text_fragment_paint_info.h`, `dom_node_id.h`, `graphics_context_state_saver.h`, `drawing_recorder.h`, `gfx/...`. Interacts with the underlying graphics system.

2. **High-Level Function Identification:**

   - The `Paint()` method is the most obvious entry point for the painting process.
   - The `PaintSymbol()` method suggests it also handles painting list markers.
   - The presence of `HighlightPainter` and `SelectionPaintState` indicates involvement in rendering text selections and other highlights (e.g., find-in-page, composition).

3. **Detailed Analysis of Key Functions and Code Blocks:**

   - **`Paint()`:**
     - Checks for visibility (`style.Visibility() != EVisibility::kVisible`).
     - Handles cases where text shaping hasn't occurred.
     - Determines if the text is selected.
     - Deals with writing mode and potential rotation.
     - Uses `DrawingRecorder` for potential caching of paint operations.
     - Calls `PaintSymbol()` for list markers.
     - Gets text colors based on style and selection.
     - Sets the font.
     - Creates `TextPainter`, `TextDecorationPainter`, and `HighlightPainter` instances, indicating a delegation of responsibilities.
     - Handles painting of document marker backgrounds and foregrounds.
     - Has different code paths based on `HighlightPainter::PaintCase()`:
       - `kNoHighlights`: Simple text and decoration painting.
       - `kFastSpellingGrammar`: Adds spelling/grammar highlighting.
       - `kFastSelection`: Optimized selection painting.
       - `kOverlay`: Handles more complex highlighting scenarios, including shadows and pseudo-elements.
       - `kSelectionOnly`: Paints only the selection.
     - Includes logic for SVG text painting.
     - Interacts with `MobileFriendlinessChecker`.

   - **`PaintSymbol()`:**
     - Paints different list marker types (disc, circle, square, disclosure triangles).
     - Uses `GraphicsContext` for drawing.
     - Considers dark mode.

   - **Helper Functions (within the anonymous namespace):**
     - `AsDisplayItemClient`: Gets the display item client for painting, handling selection cases.
     - `PhysicalBoxRect`: Calculates the physical rectangle for the text fragment, considering SVG and text combine.
     - `InlineCursorForBlockFlow`: Expands the inline cursor to the containing block.
     - `ShouldPaintEmphasisMark`: Determines if emphasis marks should be painted based on style and ruby annotations.
     - `GetDisclosureOrientation`: Gets the orientation of the disclosure triangle.
     - `CreatePath`, `GetCanonicalDisclosurePath`:  Creates the paths for the disclosure triangle shapes.

4. **Relating to Web Technologies (JavaScript, HTML, CSS):**

   - **HTML:** The text being painted comes from the HTML structure of the page. The presence of list markers relates to the `<ol>` and `<ul>` elements. SVG text is within `<svg>` elements.
   - **CSS:**  The `ComputedStyle` object is central. Properties like `color`, `font-family`, `font-size`, `text-decoration`, `text-emphasis`, `list-style-type`, `visibility`, `writing-mode`, and highlight-related pseudo-elements (`::selection`, `::spelling-error`, `::grammar-error`) are all relevant.
   - **JavaScript:** While this file doesn't directly interact with JavaScript, JavaScript actions (like user input, DOM manipulation) can trigger layout changes that eventually lead to this painter being called. JavaScript can also modify styles that influence the painting. The editing components suggest interaction with contenteditable elements.

5. **Inferring Logic and Examples:**

   - **Assumption:**  When a user types text in a `contenteditable` element, the editing logic updates the document, triggers layout, and eventually calls this painter to render the new text.
   - **Input:** A text node with the word "hello" and the CSS style `color: blue; text-decoration: underline;`.
   - **Output:** The word "hello" painted in blue with an underline.
   - **Assumption:** The user selects the word "hello".
   - **Input:** The same text node and style, plus a selection range covering "hello". The browser's default selection background color (e.g., light blue) and text color (e.g., white) for selections.
   - **Output:** The word "hello" painted with a light blue background and white text, with the underline still present.

6. **Identifying Potential User/Programming Errors:**

   - **Incorrect CSS:** Setting `visibility: hidden` will prevent the text from being painted, even if other styles are set.
   - **Conflicting styles:**  Setting both `text-decoration: underline` and `text-decoration: none` might lead to unexpected results depending on CSS specificity.
   - **SVG-specific errors:** Incorrectly specifying SVG `x`, `y`, `dx`, `dy` attributes could lead to the text not being rendered where expected.

7. **Tracing User Actions (Debugging):**

   - **Scenario:** A user reports that text is not appearing correctly on the page.
   - **Debugging Steps:**
     1. **Inspect the element:** Use browser developer tools to examine the HTML structure and applied CSS styles.
     2. **Check for visibility:** Ensure the element and its ancestors are not hidden using CSS (`visibility`, `display`).
     3. **Examine text properties:** Verify `color`, `font-size`, etc., are set correctly.
     4. **Look for overlapping content:** See if other elements are positioned on top of the text.
     5. **Set breakpoints:** Place breakpoints in `TextFragmentPainter::Paint()` to see if it's being called for the problematic text.
     6. **Step through the code:**  Inspect the values of `paint_info`, `style`, `physical_box`, and the results of `TextPainter::Paint()` to pinpoint where the painting process might be going wrong. For example, check if `text_item.TextLength()` is zero or if `text_item.TextShapeResult()` is null, which would cause the painter to skip. Examine the `HighlightPainter::PaintCase()` to understand which highlighting path is being taken.

This systematic approach, moving from a broad overview to specific code details and then relating it back to user-facing web technologies and debugging scenarios, allows for a comprehensive understanding of the `text_fragment_painter.cc` file's purpose and functionality.
好的，让我们来分析一下 `blink/renderer/core/paint/text_fragment_painter.cc` 这个文件。

**功能概要**

`TextFragmentPainter` 类的主要职责是在 Blink 渲染引擎中绘制文本片段。它负责处理文本内容的渲染，包括：

1. **基本的文本绘制:**  使用 `TextPainter` 类来实际绘制文本字符。
2. **处理文本装饰:**  使用 `TextDecorationPainter` 类来绘制下划线、删除线等文本装饰。
3. **处理文本高亮:** 使用 `HighlightPainter` 类来绘制文本的选择高亮、搜索匹配高亮、拼写/语法错误高亮以及 composition 区域的高亮。
4. **处理列表符号:** 当遇到列表项的符号时，调用 `PaintSymbol` 来绘制项目符号（如圆点、圆圈、方块等）。
5. **处理 SVG 文本:**  专门处理 SVG 元素中的文本渲染。
6. **考虑书写模式:**  处理水平和垂直书写模式下的文本绘制。
7. **优化绘制:** 使用 `DrawingRecorder` 来缓存绘制操作，提高性能。
8. **处理暗黑模式:**  根据样式应用暗黑模式的颜色调整。
9. **记录选择边界:**  使用 `SelectionBoundsRecorder` 来记录选择区域的边界。
10. **与移动端友好性检查器交互:**  通知 `MobileFriendlinessChecker` 文本片段的绘制信息。

**与 JavaScript, HTML, CSS 的关系**

`TextFragmentPainter` 的工作是最终将 HTML 结构和 CSS 样式转化为屏幕上的像素，因此它与这三者都有密切关系：

* **HTML:**  `TextFragmentPainter` 接收来自布局阶段的信息，这些信息对应于 HTML 文档中的文本节点。例如，如果 HTML 中有 `<p>Hello World</p>`，那么 "Hello World" 这个文本内容会被传递给 `TextFragmentPainter` 进行绘制。
* **CSS:**  `TextFragmentPainter` 严重依赖 CSS 样式信息（通过 `ComputedStyle` 对象获取）。CSS 属性如 `color`、`font-family`、`font-size`、`text-decoration`、`text-emphasis`、`list-style-type`、`visibility`、`writing-mode` 以及与高亮相关的伪元素（如 `::selection`、`::spelling-error`、`::grammar-error`）都会影响 `TextFragmentPainter` 的绘制行为。
* **JavaScript:**  JavaScript 可以动态地修改 HTML 结构和 CSS 样式。这些修改会导致重新布局和重绘，最终会再次调用 `TextFragmentPainter` 来更新屏幕上的显示。例如，JavaScript 可以通过修改元素的 `textContent` 来改变文本内容，或者通过修改元素的 `style` 属性来改变文本颜色。

**举例说明**

1. **CSS 文本颜色:**
   - **HTML:** `<p id="myText">This is some text.</p>`
   - **CSS:** `#myText { color: red; }`
   - **功能:** `TextFragmentPainter` 在绘制 "This is some text." 时，会读取 `#myText` 元素的 `ComputedStyle`，发现 `color` 属性为 `red`，因此会将文本绘制成红色。

2. **HTML 文本选择高亮:**
   - **用户操作:** 用户使用鼠标选中 "some text" 这部分内容。
   - **功能:**  `TextFragmentPainter` 在绘制被选中的文本时，会通过 `HighlightPainter` 检测到这是一个选择区域，并根据浏览器的默认选择样式或自定义的 `::selection` 伪元素样式来绘制高亮背景和文字颜色。

3. **JavaScript 修改文本内容:**
   - **HTML:** `<p id="dynamicText">Initial Text</p>`
   - **JavaScript:** `document.getElementById('dynamicText').textContent = 'Updated Text';`
   - **功能:** 当 JavaScript 执行后，DOM 树发生变化，触发布局和重绘。`TextFragmentPainter` 会被调用来绘制新的文本内容 "Updated Text"。

4. **CSS 列表样式:**
   - **HTML:** `<ul><li>Item 1</li></ul>`
   - **CSS:** `ul { list-style-type: square; }`
   - **功能:** `TextFragmentPainter` 在绘制列表项 "Item 1" 前，会调用 `PaintSymbol` 并根据 `list-style-type: square` 的设置，绘制一个方形的项目符号。

**逻辑推理 (假设输入与输出)**

假设我们有一个简单的文本片段需要绘制：

* **假设输入:**
    * 文本内容: "Example"
    * CSS 样式: `color: blue; font-weight: bold;`
    * 绘制位置 (paint_offset): `{10, 20}`
* **逻辑推理过程:**
    1. `TextFragmentPainter::Paint` 方法被调用。
    2. 获取文本内容的 `ComputedStyle`，得到颜色为蓝色，字体加粗。
    3. 创建 `TextPainter` 对象，配置字体和颜色。
    4. 调用 `TextPainter::Paint` 方法，传入文本内容和绘制位置。
* **预期输出:**
    * 在屏幕上坐标 (10, 20) 的位置，绘制出蓝色的、加粗的 "Example" 文本。

**用户或编程常见的使用错误**

1. **CSS `visibility: hidden` 或 `display: none`:**  如果文本所在的元素或其祖先元素设置了这些属性，`TextFragmentPainter` 会跳过绘制，导致文本不可见。这是用户可能误操作或开发者错误设置 CSS 导致的。

   ```html
   <div style="visibility: hidden;"><p>This text won't be painted.</p></div>
   ```

2. **颜色与背景色冲突:** 如果文本颜色和背景色相同，文本将不可见。

   ```css
   #invisibleText { color: white; background-color: white; }
   ```

3. **错误的 SVG 属性:** 在 SVG 文本中，如果 `x`、`y` 等属性设置不当，可能导致文本绘制在不可见的区域。

   ```html
   <svg><text x="-100" y="-100">Invisible SVG Text</text></svg>
   ```

4. **Z-index 问题:**  文本可能被其他元素遮挡，即使 `TextFragmentPainter` 正常绘制了文本。

**用户操作如何一步步到达这里 (调试线索)**

假设用户反馈页面上的某个文本没有正确显示：

1. **用户加载页面:** 浏览器开始解析 HTML、CSS，构建 DOM 树和渲染树。
2. **布局阶段:**  渲染树中的每个元素都会被赋予具体的尺寸和位置信息。对于文本节点，布局阶段会确定每个文本片段的位置和尺寸。
3. **绘制阶段:**
   - **遍历渲染树:** 浏览器会遍历渲染树，决定哪些内容需要绘制。
   - **定位文本节点:** 当遍历到需要绘制的文本节点时，会创建或获取对应的 `LayoutText` 对象。
   - **创建 TextFragmentPainter:**  对于 `LayoutText` 对象中的每个文本片段（`TextFragment`），会创建一个 `TextFragmentPainter` 对象。
   - **调用 Paint 方法:**  调用 `TextFragmentPainter::Paint` 方法，传入相关的绘制信息 (如 `PaintInfo` 和 `paint_offset`)。
   - **执行绘制:** `TextFragmentPainter` 内部会调用 `TextPainter`、`TextDecorationPainter`、`HighlightPainter` 等来完成具体的绘制操作，最终调用底层的图形库将像素渲染到屏幕上。

**调试线索:**

* **使用浏览器开发者工具:**
    * **检查元素:** 查看文本元素的 HTML 结构和应用的 CSS 样式，确认是否有影响显示的 CSS 属性。
    * **Computed 样式:** 查看最终计算出的样式，确认颜色、字体、可见性等属性是否符合预期。
    * **Layout 面板:** 查看元素的布局信息，确认文本片段的位置是否在可视区域内。
    * **Rendering 面板:** 可以强制启用绘制边界，查看文本片段的绘制区域。
* **设置断点:** 在 `TextFragmentPainter::Paint` 方法中设置断点，可以追踪文本绘制的流程，查看 `paint_info`、`style`、`physical_box` 等参数的值，判断哪个环节出了问题。
* **查看调用堆栈:**  如果断点触发，可以查看调用堆栈，了解 `TextFragmentPainter::Paint` 是从哪里被调用的，有助于理解整个渲染流程。
* **逐步调试:**  单步执行 `TextFragmentPainter::Paint` 方法的内部代码，观察变量的变化，例如文本颜色、绘制位置等。

总而言之，`TextFragmentPainter` 是 Blink 渲染引擎中负责文本最终绘制的关键组件，它将布局信息和样式信息转化为用户在屏幕上看到的文本。理解其功能和与 Web 技术的关系，对于调试和理解页面渲染过程至关重要。

### 提示词
```
这是目录为blink/renderer/core/paint/text_fragment_painter.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/paint/text_fragment_painter.h"

#include "third_party/blink/renderer/core/editing/editor.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/markers/composition_marker.h"
#include "third_party/blink/renderer/core/editing/markers/document_marker_controller.h"
#include "third_party/blink/renderer/core/editing/markers/text_match_marker.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/layout/geometry/logical_rect.h"
#include "third_party/blink/renderer/core/layout/inline/inline_cursor.h"
#include "third_party/blink/renderer/core/layout/inline/offset_mapping.h"
#include "third_party/blink/renderer/core/layout/layout_counter.h"
#include "third_party/blink/renderer/core/layout/layout_text_combine.h"
#include "third_party/blink/renderer/core/layout/list/list_marker.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_inline_text.h"
#include "third_party/blink/renderer/core/layout/text_decoration_offset.h"
#include "third_party/blink/renderer/core/mobile_metrics/mobile_friendliness_checker.h"
#include "third_party/blink/renderer/core/paint/box_model_object_painter.h"
#include "third_party/blink/renderer/core/paint/highlight_painter.h"
#include "third_party/blink/renderer/core/paint/inline_paint_context.h"
#include "third_party/blink/renderer/core/paint/line_relative_rect.h"
#include "third_party/blink/renderer/core/paint/object_painter.h"
#include "third_party/blink/renderer/core/paint/paint_auto_dark_mode.h"
#include "third_party/blink/renderer/core/paint/paint_info.h"
#include "third_party/blink/renderer/core/paint/selection_bounds_recorder.h"
#include "third_party/blink/renderer/core/paint/text_decoration_painter.h"
#include "third_party/blink/renderer/core/paint/text_painter.h"
#include "third_party/blink/renderer/core/style/applied_text_decoration.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/core/svg/svg_element.h"
#include "third_party/blink/renderer/platform/fonts/character_range.h"
#include "third_party/blink/renderer/platform/fonts/text_fragment_paint_info.h"
#include "third_party/blink/renderer/platform/graphics/dom_node_id.h"
#include "third_party/blink/renderer/platform/graphics/graphics_context_state_saver.h"
#include "third_party/blink/renderer/platform/graphics/paint/drawing_recorder.h"
#include "ui/gfx/geometry/rect_conversions.h"

namespace blink {

namespace {

inline const DisplayItemClient& AsDisplayItemClient(const InlineCursor& cursor,
                                                    bool for_selection) {
  if (for_selection) [[unlikely]] {
    if (const auto* selection_client =
            cursor.Current().GetSelectionDisplayItemClient())
      return *selection_client;
  }
  return *cursor.Current().GetDisplayItemClient();
}

inline PhysicalRect PhysicalBoxRect(const InlineCursor& cursor,
                                    const PhysicalOffset& paint_offset,
                                    const PhysicalOffset& parent_offset,
                                    const LayoutTextCombine* text_combine) {
  PhysicalRect box_rect;
  if (const auto* svg_data = cursor.CurrentItem()->GetSvgFragmentData()) {
    box_rect = PhysicalRect::FastAndLossyFromRectF(svg_data->rect);
    const float scale = svg_data->length_adjust_scale;
    if (scale != 1.0f) {
      if (cursor.CurrentItem()->IsHorizontal())
        box_rect.SetWidth(LayoutUnit(svg_data->rect.width() / scale));
      else
        box_rect.SetHeight(LayoutUnit(svg_data->rect.height() / scale));
    }
  } else {
    box_rect = cursor.CurrentItem()->RectInContainerFragment();
  }
  box_rect.offset.left += paint_offset.left;
  // We round the y-axis to ensure consistent line heights.
  box_rect.offset.top =
      LayoutUnit((paint_offset.top + parent_offset.top).Round()) +
      (box_rect.offset.top - parent_offset.top);
  if (text_combine) {
    box_rect.offset.left =
        text_combine->AdjustTextLeftForPaint(box_rect.offset.left);
  }
  return box_rect;
}

inline const InlineCursor& InlineCursorForBlockFlow(
    const InlineCursor& cursor,
    std::optional<InlineCursor>* storage) {
  if (*storage)
    return **storage;
  *storage = cursor;
  (*storage)->ExpandRootToContainingBlock();
  return **storage;
}

// Check if text-emphasis and ruby annotation text are on different sides.
//
// TODO(layout-dev): The current behavior is compatible with the legacy layout.
// However, the specification asks to draw emphasis marks over ruby annotation
// text.
// https://drafts.csswg.org/css-text-decor-4/#text-emphasis-position-property
// > If emphasis marks are applied to characters for which ruby is drawn in the
// > same position as the emphasis mark, the emphasis marks are placed outside
// > the ruby.
bool ShouldPaintEmphasisMark(const ComputedStyle& style,
                             const LayoutObject& layout_object,
                             const FragmentItem& text_item) {
  if (style.GetTextEmphasisMark() == TextEmphasisMark::kNone)
    return false;
  // Note: We set text-emphasis-style:none for combined text and we paint
  // emphasis mark at left/right side of |LayoutTextCombine|.
  DCHECK(!IsA<LayoutTextCombine>(layout_object.Parent()));

  if (style.GetTextEmphasisLineLogicalSide() == LineLogicalSide::kOver) {
    return !text_item.HasOverAnnotation();
  }
  return !text_item.HasUnderAnnotation();
}

PhysicalDirection GetDisclosureOrientation(const ComputedStyle& style,
                                           bool is_open) {
  const auto direction_mode = style.GetWritingDirection();
  return is_open ? direction_mode.BlockEnd() : direction_mode.InlineEnd();
}

Path CreatePath(base::span<const gfx::PointF, 4> path) {
  Path result;
  result.MoveTo(path[0]);
  for (size_t i = 1; i < 4; ++i) {
    result.AddLineTo(path[i]);
  }
  return result;
}

Path GetCanonicalDisclosurePath(const ComputedStyle& style, bool is_open) {
  constexpr gfx::PointF kLeftPoints[4] = {
      {1.0f, 0.0f}, {0.14f, 0.5f}, {1.0f, 1.0f}, {1.0f, 0.0f}};
  constexpr gfx::PointF kRightPoints[4] = {
      {0.0f, 0.0f}, {0.86f, 0.5f}, {0.0f, 1.0f}, {0.0f, 0.0f}};
  constexpr gfx::PointF kUpPoints[4] = {
      {0.0f, 0.93f}, {0.5f, 0.07f}, {1.0f, 0.93f}, {0.0f, 0.93f}};
  constexpr gfx::PointF kDownPoints[4] = {
      {0.0f, 0.07f}, {0.5f, 0.93f}, {1.0f, 0.07f}, {0.0f, 0.07f}};

  switch (GetDisclosureOrientation(style, is_open)) {
    case PhysicalDirection::kLeft:
      return CreatePath(kLeftPoints);
    case PhysicalDirection::kRight:
      return CreatePath(kRightPoints);
    case PhysicalDirection::kUp:
      return CreatePath(kUpPoints);
    case PhysicalDirection::kDown:
      return CreatePath(kDownPoints);
  }

  return Path();
}

}  // namespace

void TextFragmentPainter::PaintSymbol(const LayoutObject* layout_object,
                                      const ComputedStyle& style,
                                      const PhysicalSize box_size,
                                      const PaintInfo& paint_info,
                                      const PhysicalOffset& paint_offset) {
  const AtomicString& type = LayoutCounter::ListStyle(layout_object, style);
  PhysicalRect marker_rect(
      ListMarker::RelativeSymbolMarkerRect(style, type, box_size.width));
  marker_rect.Move(paint_offset);

  DCHECK(layout_object);
#if DCHECK_IS_ON()
  if (layout_object->IsCounter()) {
    DCHECK(To<LayoutCounter>(layout_object)->IsDirectionalSymbolMarker());
  } else {
    DCHECK(style.ListStyleType());
    DCHECK(style.ListStyleType()->IsCounterStyle());
  }
#endif
  GraphicsContext& context = paint_info.context;
  Color color(layout_object->ResolveColor(GetCSSPropertyColor()));
  if (BoxModelObjectPainter::ShouldForceWhiteBackgroundForPrintEconomy(
          layout_object->GetDocument(), style)) {
    color = TextPainter::TextColorForWhiteBackground(color);
  }
  // Apply the color to the list marker text.
  context.SetFillColor(color);
  context.SetStrokeColor(color);
  const gfx::Rect snapped_rect = ToPixelSnappedRect(marker_rect);
  AutoDarkMode auto_dark_mode(
      PaintAutoDarkMode(style, DarkModeFilter::ElementRole::kListSymbol));
  if (type == keywords::kDisc) {
    context.FillEllipse(gfx::RectF(snapped_rect), auto_dark_mode);
  } else if (type == keywords::kCircle) {
    context.SetStrokeThickness(1.0f);
    context.StrokeEllipse(gfx::RectF(snapped_rect), auto_dark_mode);
  } else if (type == keywords::kSquare) {
    context.FillRect(snapped_rect, color, auto_dark_mode);
  } else if (type == keywords::kDisclosureOpen ||
             type == keywords::kDisclosureClosed) {
    Path path =
        GetCanonicalDisclosurePath(style, type == keywords::kDisclosureOpen);
    path.Transform(AffineTransform::MakeScaleNonUniform(marker_rect.Width(),
                                                        marker_rect.Height()));
    path.Translate(gfx::Vector2dF(marker_rect.X(), marker_rect.Y()));
    context.FillPath(path, auto_dark_mode);
  } else {
    NOTREACHED();
  }
}

void TextFragmentPainter::Paint(const PaintInfo& paint_info,
                                const PhysicalOffset& paint_offset) {
  const auto& text_item = *cursor_.CurrentItem();
  // We can skip painting if the fragment (including selection) is invisible.
  if (!text_item.TextLength())
    return;

  if (!text_item.TextShapeResult() &&
      // A line break's selection tint is still visible.
      !text_item.IsLineBreak())
    return;

  const ComputedStyle& style = text_item.Style();
  if (style.Visibility() != EVisibility::kVisible) {
    return;
  }

  const TextFragmentPaintInfo& fragment_paint_info =
      cursor_.Current()->TextPaintInfo(cursor_.Items());
  const LayoutObject* layout_object = text_item.GetLayoutObject();
  const Document& document = layout_object->GetDocument();
  const bool is_printing = document.Printing();
  // Don't paint selections when rendering a mask, clip-path (as a mask),
  // pattern or feImage (element reference.)
  const bool is_rendering_resource = paint_info.IsRenderingResourceSubtree();
  const auto* const text_combine =
      DynamicTo<LayoutTextCombine>(layout_object->Parent());
  const PhysicalRect physical_box =
      PhysicalBoxRect(cursor_, paint_offset, parent_offset_, text_combine);
#if DCHECK_IS_ON()
  if (text_combine) [[unlikely]] {
    LayoutTextCombine::AssertStyleIsValid(style);
  }
#endif

  ObjectPainter object_painter(*layout_object);
  if (object_painter.ShouldRecordSpecialHitTestData(paint_info)) {
    object_painter.RecordHitTestData(paint_info,
                                     ToPixelSnappedRect(physical_box),
                                     *text_item.GetDisplayItemClient());
  }

  // Determine whether or not we’ll need a writing-mode rotation, but don’t
  // actually rotate until we reach the steps that need it.
  std::optional<AffineTransform> rotation;
  const WritingMode writing_mode = style.GetWritingMode();
  const bool is_horizontal = IsHorizontalWritingMode(writing_mode);
  const LineRelativeRect rotated_box =
      LineRelativeRect::CreateFromLineBox(physical_box, is_horizontal);
  if (!is_horizontal) {
    rotation.emplace(
        rotated_box.ComputeRelativeToPhysicalTransform(writing_mode));
  }

  // Determine whether or not we're selected.
  HighlightPainter::SelectionPaintState* selection = nullptr;
  std::optional<HighlightPainter::SelectionPaintState>
      selection_for_bounds_recording;
  if (!is_printing && !is_rendering_resource &&
      paint_info.phase != PaintPhase::kTextClip && layout_object->IsSelected())
      [[unlikely]] {
    const InlineCursor& root_inline_cursor =
        InlineCursorForBlockFlow(cursor_, &inline_cursor_for_block_flow_);

    // Empty selections might be the boundary of the document selection, and
    // thus need to get recorded. We only need to paint the selection if it
    // has a valid range.
    selection_for_bounds_recording.emplace(root_inline_cursor,
                                           physical_box.offset, rotation);
    if (selection_for_bounds_recording->Status().HasValidRange())
      selection = &selection_for_bounds_recording.value();
  }
  if (!selection) {
    // When only painting the selection drag image, don't bother to paint if
    // there is none.
    if (paint_info.phase == PaintPhase::kSelectionDragImage)
      return;

    // Flow controls (line break, tab, <wbr>) need only selection painting.
    if (text_item.IsFlowControl())
      return;
  }

  gfx::Rect visual_rect;
  const auto* const svg_inline_text =
      DynamicTo<LayoutSVGInlineText>(layout_object);
  float scaling_factor = 1.0f;
  if (svg_inline_text) [[unlikely]] {
    DCHECK(text_item.IsSvgText());
    scaling_factor = svg_inline_text->ScalingFactor();
    DCHECK_NE(scaling_factor, 0.0f);
    visual_rect = gfx::ToEnclosingRect(
        svg_inline_text->Parent()->VisualRectInLocalSVGCoordinates());
  } else {
    DCHECK(!text_item.IsSvgText());
    PhysicalRect ink_overflow = text_item.SelfInkOverflowRect();
    ink_overflow.Move(physical_box.offset);
    visual_rect = ToEnclosingRect(ink_overflow);
  }

  // Ensure the selection bounds are recorded on the paint chunk regardless of
  // whether the display item that contains the actual selection painting is
  // reused.
  std::optional<SelectionBoundsRecorder> selection_recorder;
  if (selection_for_bounds_recording &&
      paint_info.phase == PaintPhase::kForeground && !is_printing)
      [[unlikely]] {
    if (SelectionBoundsRecorder::ShouldRecordSelection(
            cursor_.Current().GetLayoutObject()->GetFrame()->Selection(),
            selection_for_bounds_recording->State())) {
      selection_recorder.emplace(
          selection_for_bounds_recording->State(),
          selection_for_bounds_recording->PhysicalSelectionRect(),
          paint_info.context.GetPaintController(),
          cursor_.Current().ResolvedDirection(), style.GetWritingMode(),
          *cursor_.Current().GetLayoutObject());
    }
  }

  // This is declared after selection_recorder so that this will be destructed
  // before selection_recorder to ensure the selection is painted before
  // selection_recorder records the selection bounds.
  std::optional<DrawingRecorder> recorder;
  const auto& display_item_client =
      AsDisplayItemClient(cursor_, selection != nullptr);
  // Text clips are initiated only in BoxPainterBase::PaintFillLayer, which is
  // already within a DrawingRecorder.
  if (paint_info.phase != PaintPhase::kTextClip) {
    if (!paint_info.context.InDrawingRecorder()) [[likely]] {
      if (DrawingRecorder::UseCachedDrawingIfPossible(
              paint_info.context, display_item_client, paint_info.phase)) {
        return;
      }
      recorder.emplace(paint_info.context, display_item_client,
                       paint_info.phase, visual_rect);
    }
  }

  if (text_item.IsSymbolMarker()) [[unlikely]] {
    PaintSymbol(layout_object, style, physical_box.size, paint_info,
                physical_box.offset);
    return;
  }

  GraphicsContext& context = paint_info.context;

  // Determine text colors.

  Node* node = layout_object->GetNode();
  TextPaintStyle text_style =
      TextPainter::TextPaintingStyle(document, style, paint_info);
  if (selection) [[unlikely]] {
    selection->ComputeSelectionStyle(document, style, node, paint_info,
                                     text_style);
  }

  // Set our font.
  const Font* font;
  if (text_combine && text_combine->CompressedFont()) [[unlikely]] {
    font = text_combine->CompressedFont();
  } else {
    font = &text_item.ScaledFont();
  }
  const SimpleFontData* font_data = font->PrimaryFont();
  DCHECK(font_data);

  GraphicsContextStateSaver state_saver(context, /*save_and_restore=*/false);
  const int ascent = font_data ? font_data->GetFontMetrics().Ascent() : 0;
  LineRelativeOffset text_origin{physical_box.offset.left,
                                 physical_box.offset.top + ascent};
  if (text_combine) [[unlikely]] {
    text_origin.line_over =
        text_combine->AdjustTextTopForPaint(physical_box.offset.top);
  }

  TextPainter text_painter(context, paint_info.GetSvgContextPaints(), *font,
                           visual_rect, text_origin, is_horizontal);
  TextDecorationPainter decoration_painter(text_painter, inline_context_,
                                           paint_info, style, text_style,
                                           rotated_box, selection);
  HighlightPainter highlight_painter(
      fragment_paint_info, text_painter, decoration_painter, paint_info,
      cursor_, text_item, physical_box.offset, style, text_style, selection);
  if (paint_info.phase == PaintPhase::kForeground) {
    if (auto* mf_checker = MobileFriendlinessChecker::From(document)) {
      if (auto* text = DynamicTo<LayoutText>(*layout_object)) {
        PhysicalRect clipped_rect = PhysicalRect(visual_rect);
        clipped_rect.Intersect(PhysicalRect(paint_info.GetCullRect().Rect()));
        mf_checker->NotifyPaintTextFragment(
            clipped_rect, text->StyleRef().FontSize(),
            paint_info.context.GetPaintController()
                .CurrentPaintChunkProperties()
                .Transform());
      }
    }
  }

  if (svg_inline_text) {
    TextPainter::SvgTextPaintState& svg_state = text_painter.SetSvgState(
        *svg_inline_text, style, text_item.GetStyleVariant(),
        paint_info.GetPaintFlags());

    if (scaling_factor != 1.0f) {
      state_saver.SaveIfNeeded();
      context.Scale(1 / scaling_factor, 1 / scaling_factor);
      svg_state.EnsureShaderTransform().Scale(scaling_factor);
    }
    if (text_item.HasSvgTransformForPaint()) {
      state_saver.SaveIfNeeded();
      const auto fragment_transform = text_item.BuildSvgTransformForPaint();
      context.ConcatCTM(fragment_transform);
      DCHECK(fragment_transform.IsInvertible());
      svg_state.EnsureShaderTransform().PostConcat(
          fragment_transform.Inverse());
    }
  }

  const bool paint_marker_backgrounds =
      paint_info.phase != PaintPhase::kSelectionDragImage &&
      paint_info.phase != PaintPhase::kTextClip && !is_printing;

  // 1. Paint backgrounds for document markers that don’t participate in the CSS
  // highlight overlay system, such as composition highlights. They use physical
  // coordinates, so are painted before GraphicsContext rotation.
  if (paint_marker_backgrounds) {
    highlight_painter.PaintNonCssMarkers(HighlightPainter::kBackground);
  }

  if (rotation) {
    state_saver.SaveIfNeeded();
    context.ConcatCTM(*rotation);
    if (TextPainter::SvgTextPaintState* state = text_painter.GetSvgState()) {
      DCHECK(rotation->IsInvertible());
      state->EnsureShaderTransform().PostConcat(rotation->Inverse());
    }
  }

  if (highlight_painter.Selection()) [[unlikely]] {
    PhysicalRect physical_selection =
        highlight_painter.Selection()->PhysicalSelectionRect();
    if (scaling_factor != 1.0f) {
      physical_selection.offset.Scale(1 / scaling_factor);
      physical_selection.size.Scale(1 / scaling_factor);
    }

    // We need to use physical coordinates when invalidating.
    if (paint_marker_backgrounds && recorder) {
      recorder->UniteVisualRect(ToEnclosingRect(physical_selection));
    }
  }

  // 2. Now paint the foreground, including text and decorations.
  // TODO(dazabani@igalia.com): suppress text proper where one or more highlight
  // overlays are active, but paint shadows in full <https://crbug.com/1147859>
  if (ShouldPaintEmphasisMark(style, *layout_object, text_item)) {
    text_painter.SetEmphasisMark(style.TextEmphasisMarkString(),
                                 style.GetTextEmphasisPosition());
  }

  DOMNodeId node_id = kInvalidDOMNodeId;
  if (node) {
    if (auto* layout_text = DynamicTo<LayoutText>(node->GetLayoutObject()))
      node_id = layout_text->EnsureNodeId();
  }
  InlinePaintContext::ScopedPaintOffset scoped_paint_offset(paint_offset,
                                                            inline_context_);

  AutoDarkMode auto_dark_mode(
      PaintAutoDarkMode(style, DarkModeFilter::ElementRole::kForeground));

  HighlightPainter::Case highlight_case = highlight_painter.PaintCase();
  switch (highlight_case) {
    case HighlightPainter::kNoHighlights:
      // Fast path: just paint the text, including its decorations.
      decoration_painter.Begin(text_item, TextDecorationPainter::kOriginating);
      decoration_painter.PaintExceptLineThrough(fragment_paint_info);
      text_painter.Paint(fragment_paint_info, text_style, node_id,
                         auto_dark_mode);
      decoration_painter.PaintOnlyLineThrough();
      break;
    case HighlightPainter::kFastSpellingGrammar:
      decoration_painter.Begin(text_item, TextDecorationPainter::kOriginating);
      decoration_painter.PaintExceptLineThrough(fragment_paint_info);
      text_painter.Paint(fragment_paint_info, text_style, node_id,
                         auto_dark_mode);
      decoration_painter.PaintOnlyLineThrough();
      highlight_painter.FastPaintSpellingGrammarDecorations();
      break;
    case HighlightPainter::kFastSelection:
      highlight_painter.Selection()->PaintSuppressingTextProperWhereSelected(
          text_painter, fragment_paint_info, text_style, node_id,
          auto_dark_mode);
      break;
    case HighlightPainter::kOverlay:
      // Paint originating shadows at the bottom, below all highlight pseudos.
      highlight_painter.PaintOriginatingShadow(text_style, node_id);
      // Paint each highlight overlay, including originating and selection.
      highlight_painter.PaintHighlightOverlays(
          text_style, node_id, paint_marker_backgrounds, rotation);
      break;
    case HighlightPainter::kSelectionOnly:
      // Do nothing, and paint the selection later.
      break;
  }

  // Paint ::selection background.
  if (highlight_painter.Selection() && paint_marker_backgrounds) [[unlikely]] {
    if (highlight_case == HighlightPainter::kFastSelection) {
      highlight_painter.Selection()->PaintSelectionBackground(
          context, node, document, style, rotation);
    }
  }

  // Paint foregrounds for document markers that don’t participate in the CSS
  // highlight overlay system, such as composition highlights.
  if (paint_info.phase == PaintPhase::kForeground) {
    highlight_painter.PaintNonCssMarkers(HighlightPainter::kForeground);
  }

  // Paint ::selection foreground only.
  if (highlight_painter.Selection()) [[unlikely]] {
    switch (highlight_case) {
      case HighlightPainter::kFastSelection:
        highlight_painter.Selection()->PaintSelectedText(
            text_painter, fragment_paint_info, text_style, node_id,
            auto_dark_mode);
        break;
      case HighlightPainter::kSelectionOnly:
        decoration_painter.Begin(text_item, TextDecorationPainter::kSelection);
        decoration_painter.PaintExceptLineThrough(fragment_paint_info);
        highlight_painter.Selection()->PaintSelectedText(
            text_painter, fragment_paint_info, text_style, node_id,
            auto_dark_mode);
        decoration_painter.PaintOnlyLineThrough();
        break;
      case HighlightPainter::kOverlay:
        // Do nothing, because PaintHighlightOverlays already painted it.
        break;
      case HighlightPainter::kFastSpellingGrammar:
      case HighlightPainter::kNoHighlights:
        NOTREACHED();
    }
  }
}

}  // namespace blink
```