Response:
The user wants a summary of the functionality of the `box_fragment_painter.cc` file in the Chromium Blink rendering engine. I need to extract the core responsibilities of this class and explain how it relates to web technologies like JavaScript, HTML, and CSS. I also need to consider debugging aspects and common usage errors (although these might be more related to the underlying rendering logic than direct user action). Since this is part 3 of a 4-part request, I should focus on summarizing the functions within this specific code snippet, assuming the prior parts covered broader aspects of the file.

**Plan:**

1. **Identify Key Functions:** Go through the provided code and list the main methods and their purposes.
2. **Relate to Web Technologies:** For each key function, determine if and how it relates to HTML elements, CSS styles, or JavaScript interactions.
3. **Logical Reasoning (Input/Output):**  Where applicable, think of simple scenarios and how these functions would process them.
4. **User/Programming Errors:** Consider common mistakes developers might make that would lead to this code being executed or reveal issues within it.
5. **User Operations (Debugging):** Trace back how user interactions in a browser might lead to the execution of this code.
6. **Summarize Functionality:** Combine the above points into a concise summary of the file's purpose within the rendering pipeline.
这是`blink/renderer/core/paint/box_fragment_painter.cc`文件的第3部分，主要负责以下功能：

**核心功能： 绘制盒模型片段的各个部分，尤其是处理内联内容和复杂的布局情况。**

这是对前一部分功能的延续，继续实现了`BoxFragmentPainter`类的各种绘制方法，专注于处理更细粒度的渲染任务。

**具体功能点：**

1. **绘制列规则 (PaintColumnRules):**
   - **功能:** 绘制多列布局中列之间的分隔线。
   - **与 CSS 的关系:**  与 CSS 的 `column-rule-width`, `column-rule-style`, `column-rule-color` 属性相关。
   - **逻辑推理:**
     - **假设输入:** 一个多列布局的 `LayoutBoxFragment`，包含多个列的尺寸和偏移信息，以及列规则的样式属性。
     - **输出:** 在指定上下文中绘制出符合样式定义的列分隔线。分隔线的位置和长度根据相邻列的布局计算得出。
   - **用户操作与调试:** 当用户浏览一个使用了 CSS 多列布局的网页时，如果定义了列规则样式，渲染引擎会调用此函数来绘制分隔线。在调试时，可以检查元素的样式计算结果和布局信息，确认列规则属性是否正确应用，以及列的尺寸和偏移是否符合预期。

2. **绘制背景 (PaintBackground):**
   - **功能:** 绘制盒模型片段的背景颜色和背景图像。特殊处理了页面边框盒的背景绘制，会使用文档根元素的样式。
   - **与 HTML 和 CSS 的关系:** 与 HTML 元素的背景色（`background-color`）和背景图像（`background-image` 等 `background-*` 属性）相关。页面边框盒对应于整个文档的背景。
   - **编程常见的使用错误:**  开发者可能错误地认为修改某个元素的背景会影响到页面边框盒的背景，而实际上页面边框盒的背景是由文档根元素的样式控制的。
   - **用户操作与调试:** 当用户浏览网页时，元素的背景显示依赖于此函数的正确执行。在调试背景显示问题时，需要检查目标元素及其祖先元素的背景样式，特别是对于页面级别的背景，需要检查 `<html>` 元素的样式。

3. **原子性地绘制所有阶段 (PaintAllPhasesAtomically):**
   - **功能:**  在一个操作中按顺序绘制盒模型片段的不同渲染阶段，例如背景、浮动元素、前景、轮廓等。这主要用于非自绘图层的情况。
   - **与渲染流程的关系:**  此函数体现了渲染引擎的绘制流程，按照特定的顺序进行绘制以保证正确的视觉效果。
   - **逻辑推理:**  此函数通过设置 `paint_info.phase` 来控制绘制的阶段，并依次调用 `PaintInternal` 函数。
   - **用户操作与调试:**  当页面元素的内容和样式发生变化时，渲染引擎会触发重绘，并可能调用此函数来更新元素的显示。调试时，可以通过渲染流程相关的工具观察不同阶段的绘制情况。

4. **绘制内联元素 (PaintInlineItems):**
   - **功能:** 递归地绘制内联盒模型片段中的子元素，包括文本和嵌套的内联盒子。
   - **与 HTML 和 CSS 的关系:**  处理 HTML 中的内联元素（如 `<span>`, `<a>` 等）以及受 CSS 影响的文本内容。
   - **逻辑推理:**  此函数使用 `InlineCursor` 遍历内联元素的片段项，并根据项的类型调用相应的绘制函数（如 `PaintTextItem`, `PaintBoxItem`）。
   - **编程常见的使用错误:**  在处理复杂的内联布局时，可能会出现元素重叠或错位的问题，这可能与内联元素的盒模型属性（如 `line-height`, `vertical-align` 等）设置不当有关。
   - **用户操作与调试:** 当用户浏览包含复杂内联布局的网页时，元素的排列和显示依赖于此函数的正确执行。可以使用浏览器的开发者工具查看元素的盒模型和布局信息，以及检查相关的 CSS 属性。

5. **绘制行盒 (PaintLineBox):**
   - **功能:** 绘制内联布局中的行盒，并记录行盒的命中测试数据。还会绘制 `::first-line` 伪元素的背景。
   - **与 HTML 和 CSS 的关系:**  与内联元素的行布局以及 CSS 的 `::first-line` 伪元素相关。
   - **逻辑推理:**  此函数首先判断是否需要绘制命中测试数据，然后针对 `::first-line` 伪元素调用相应的绘制函数。
   - **用户操作与调试:**  当用户与网页中的文本进行交互（如点击、选择）时，需要进行命中测试以确定用户操作的目标。此函数参与了行盒的命中测试数据的记录。

6. **绘制行盒的子元素 (PaintLineBoxChildItems):**
   - **功能:** 遍历并绘制行盒中的子元素，跳过浮动元素。
   - **与 HTML 和 CSS 的关系:**  处理行盒中包含的各种类型的内联内容。
   - **逻辑推理:**  此函数根据子元素的类型（例如，内联盒子、文本、行盒等）调用相应的绘制函数。
   - **用户操作与调试:**  当用户浏览包含多行文本或嵌套内联元素的网页时，此函数负责渲染每一行中的内容。

7. **绘制背板 (PaintBackplate):**
   - **功能:** 在强制颜色模式下，为文本绘制背板颜色，以提高可读性。
   - **与 CSS 的关系:** 与 CSS 的 `forced-color-adjust` 属性以及强制颜色模式相关。
   - **逻辑推理:**  仅在 `forced-color-adjust` 为 `auto` 且元素可见时绘制背板。
   - **用户操作与调试:**  当用户在操作系统层面启用了高对比度或强制颜色模式时，此函数会影响文本的显示效果。

8. **绘制文本项 (PaintTextItem):**
   - **功能:** 绘制内联布局中的文本内容。
   - **与 HTML 和 CSS 的关系:**  处理 HTML 文本节点以及受 CSS 样式影响的文本显示，如颜色、字体等。
   - **逻辑推理:**  仅在前景、选择或裁剪阶段进行绘制，并会进行裁剪测试以提高性能。
   - **用户操作与调试:** 网页上显示的文本内容主要由此函数渲染。调试文本显示问题时，需要检查文本节点的样式和布局信息。

9. **绘制盒模型项 (PaintBoxItem):**
   - **功能:** 绘制内联布局中嵌套的盒子元素，区分不同的盒子类型（例如，原子内联、列表标记、内联盒子、块级元素内联）。
   - **与 HTML 和 CSS 的关系:**  处理内联布局中包含的各种类型的 HTML 元素。
   - **逻辑推理:**  根据子盒子的类型选择不同的绘制策略。
   - **用户操作与调试:** 当用户浏览包含嵌套的内联块级元素或具有特殊类型的内联元素时，此函数负责渲染这些元素。

10. **判断是否需要绘制 (ShouldPaint):**
    - **功能:**  根据裁剪区域判断当前盒模型片段是否需要进行绘制。对于分页根元素，总是返回 true。
    - **与渲染性能的关系:**  通过避免绘制不可见的元素来提高渲染性能。
    - **逻辑推理:**  检查盒模型片段的墨水溢出区域是否与当前的裁剪区域相交。

11. **绘制文本裁剪遮罩 (PaintTextClipMask):**
    - **功能:**  为文本裁剪效果绘制遮罩。
    - **与 CSS 的关系:**  与 CSS 的 `text-overflow: ellipsis` 等属性相关。
    - **逻辑推理:**  根据盒装饰打断属性 (`box-decoration-break`) 选择不同的绘制策略。

12. **调整滚动内容的矩形 (AdjustRectForScrolledContent):**
    - **功能:**  当内容发生滚动时，调整绘制矩形以反映滚动偏移。
    - **与滚动条的关系:**  与带有滚动条的容器的渲染相关。
    - **逻辑推理:**  将绘制矩形裁剪到溢出区域，并根据滚动偏移调整绘制位置和大小。

13. **获取填充图层信息 (GetFillLayerInfo):**
    - **功能:**  获取用于绘制背景填充层的信息。
    - **与背景绘制的关系:**  辅助 `PaintBackground` 函数进行背景绘制。

14. **命中测试相关函数 (HitTestContext, AddNodeToResult, NodeAtPoint 等):**
    - **功能:**  实现命中测试逻辑，判断鼠标点击等事件发生在哪个元素上。
    - **与用户交互的关系:**  是浏览器处理用户交互事件的关键部分。
    - **逻辑推理:**  这些函数递归地检查盒模型片段及其子元素，判断点击位置是否在元素的边界内。不同的阶段 (foreground, float, background 等) 会进行不同的命中测试。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户加载网页:** 当用户在浏览器中输入网址或点击链接时，浏览器开始解析 HTML、CSS 和 JavaScript。
2. **布局计算:** Blink 引擎会根据 HTML 结构和 CSS 样式计算出页面的布局，生成布局树和相应的盒模型片段。
3. **进入绘制阶段:** 当需要渲染页面或更新页面显示时，Blink 引擎会遍历布局树，并为每个盒模型片段创建一个 `BoxFragmentPainter` 对象（或其他类型的 painter）。
4. **触发绘制函数:** 根据盒模型片段的类型和需要绘制的阶段，会调用 `BoxFragmentPainter` 对象的相应绘制函数，例如 `PaintBackground`、`PaintInlineItems`、`PaintTextItem` 等。
5. **`PaintColumnRules` 示例:** 如果用户浏览的网页使用了 `column-count` 或 `columns` 属性创建了多列布局，并且定义了 `column-rule-*` 属性，那么在绘制阶段会调用 `PaintColumnRules` 来绘制列之间的分隔线。
6. **`PaintBackground` 示例:**  所有可见的 HTML 元素都需要绘制背景，因此当渲染引擎处理到某个元素的 `LayoutBoxFragment` 时，会调用 `PaintBackground` 来绘制其背景。
7. **`PaintInlineItems` 示例:** 当渲染引擎遇到包含内联内容的 `LayoutBoxFragment` 时，会调用 `PaintInlineItems` 来递归地绘制其中的文本和嵌套的内联元素。
8. **用户交互触发重绘:** 当用户与网页进行交互，例如滚动页面、鼠标悬停、点击元素导致样式变化等，可能会触发页面的重绘。在重绘过程中，会再次执行上述绘制流程，并可能再次调用 `BoxFragmentPainter` 的相关函数。
9. **调试线索:**  当遇到渲染问题时，可以通过浏览器的开发者工具（例如，Elements 面板、Layers 面板、Performance 面板）来观察元素的布局、样式和绘制情况。设置断点在 `BoxFragmentPainter` 的相关函数中，可以追踪渲染流程，查看传入的参数（例如，`paint_info`，盒模型片段的尺寸和位置等），从而定位问题所在。

**总结第3部分的功能：**

`BoxFragmentPainter` 的第 3 部分主要关注**内联内容的绘制、多列布局的渲染以及更细粒度的绘制任务处理**。它包含了绘制列规则、背景、内联元素及其子元素、行盒以及处理强制颜色模式下的背板绘制等关键功能。 此外，还涉及到了命中测试的初步处理，为用户交互提供基础。 这部分的代码深入到了文本和内联元素的渲染细节，是 Blink 渲染引擎中负责页面视觉呈现的重要组成部分。

### 提示词
```
这是目录为blink/renderer/core/paint/box_fragment_painter.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
->ComputeLogicalScrollbars()
                                                  .block_end;
          rule_length = column_box_right - previous_column.offset.left;
        } else {
          // Vertical-rl or sideways-rl writing-mode
          const LayoutUnit column_box_left = box_fragment_.ContentOffset().left;
          rule_length = previous_column.Width() +
                        (previous_column.offset.left - column_box_left);
          rule_left = column_box_left;
        }

        // TODO(layout-dev): Get rid of this clamping, and fix any underlying
        // issues
        rule_length = std::max(rule_length, previous_column.Width());
        rule_left = std::min(rule_left, previous_column.offset.left);
      } else {
        rule_length = previous_column.Width();
      }

      DCHECK_GE(rule_length, current_column.Width());
      rule.offset.left = rule_left;
      rule.size.width = rule_length;
      rule.offset.top = center - rule_thickness / 2;
      rule.size.height = rule_thickness;
    }

    rule.Move(paint_offset);
    gfx::Rect snapped_rule = ToPixelSnappedRect(rule);
    BoxBorderPainter::DrawBoxSide(paint_info.context, snapped_rule, box_side,
                                  rule_color, rule_style, auto_dark_mode);
    recorder.UniteVisualRect(snapped_rule);

    previous_column = current_column;
  }
}

// TODO(kojii): This logic is kept in sync with BoxPainter. Not much efforts to
// eliminate LayoutObject dependency were done yet.
void BoxFragmentPainter::PaintBackground(
    const PaintInfo& paint_info,
    const PhysicalRect& paint_rect,
    const Color& background_color,
    BackgroundBleedAvoidance bleed_avoidance) {
  const auto& layout_box = To<LayoutBox>(*box_fragment_.GetLayoutObject());
  if (layout_box.BackgroundTransfersToView())
    return;
  if (layout_box.BackgroundIsKnownToBeObscured())
    return;

  const ComputedStyle* style_to_use = &box_fragment_.Style();
  Color background_color_to_use = background_color;
  if (box_fragment_.GetBoxType() == PhysicalFragment::kPageBorderBox) {
    // The page border box fragment paints the document background.
    // See https://drafts.csswg.org/css-page-3/#painting
    const Document& document = box_fragment_.GetDocument();
    const Element* root = document.documentElement();
    if (!root || !root->GetLayoutObject()) {
      // We're going to need a document element, and it needs to have a box.
      // If there's no such thing, we have nothing to paint.
      return;
    }
    style_to_use = document.GetLayoutView()->Style();
    background_color_to_use =
        style_to_use->VisitedDependentColor(GetCSSPropertyBackgroundColor());
  }

  BoxBackgroundPaintContext bg_paint_context(box_fragment_);
  PaintFillLayers(paint_info, background_color_to_use,
                  style_to_use->BackgroundLayers(), paint_rect,
                  bg_paint_context, bleed_avoidance);
}

void BoxFragmentPainter::PaintAllPhasesAtomically(const PaintInfo& paint_info) {
  // Self-painting AtomicInlines should go to normal paint logic.
  DCHECK(!(GetPhysicalFragment().IsPaintedAtomically() &&
           box_fragment_.HasSelfPaintingLayer()));

  // Pass PaintPhaseSelection and PaintPhaseTextClip is handled by the regular
  // foreground paint implementation. We don't need complete painting for these
  // phases.
  PaintPhase phase = paint_info.phase;
  if (phase == PaintPhase::kSelectionDragImage ||
      phase == PaintPhase::kTextClip)
    return PaintInternal(paint_info);

  if (phase != PaintPhase::kForeground)
    return;

  PaintInfo local_paint_info(paint_info);
  local_paint_info.phase = PaintPhase::kBlockBackground;
  PaintInternal(local_paint_info);

  local_paint_info.phase = PaintPhase::kForcedColorsModeBackplate;
  PaintInternal(local_paint_info);

  local_paint_info.phase = PaintPhase::kFloat;
  PaintInternal(local_paint_info);

  local_paint_info.phase = PaintPhase::kForeground;
  PaintInternal(local_paint_info);

  local_paint_info.phase = PaintPhase::kOutline;
  PaintInternal(local_paint_info);
}

void BoxFragmentPainter::PaintInlineItems(const PaintInfo& paint_info,
                                          const PhysicalOffset& paint_offset,
                                          const PhysicalOffset& parent_offset,
                                          InlineCursor* cursor) {
  while (*cursor) {
    const FragmentItem* item = cursor->CurrentItem();
    DCHECK(item);
    if (item->IsLayoutObjectDestroyedOrMoved()) [[unlikely]] {
      // TODO(crbug.com/1099613): This should not happen, as long as it is
      // really layout-clean.
      NOTREACHED();
    }
    switch (item->Type()) {
      case FragmentItem::kText:
      case FragmentItem::kGeneratedText:
        if (!item->IsHiddenForPaint())
          PaintTextItem(*cursor, paint_info, paint_offset, parent_offset);
        cursor->MoveToNext();
        break;
      case FragmentItem::kBox:
        if (!item->IsHiddenForPaint())
          PaintBoxItem(*item, *cursor, paint_info, paint_offset, parent_offset);
        cursor->MoveToNextSkippingChildren();
        break;
      case FragmentItem::kLine: {
        // Nested kLine items are used for ruby annotations.
        InlineCursor line_box_cursor = cursor->CursorForDescendants();
        PaintInlineItems(paint_info, paint_offset, parent_offset,
                         &line_box_cursor);
        cursor->MoveToNextSkippingChildren();
        break;
      }
      case FragmentItem::kInvalid:
        NOTREACHED();
    }
  }
}

// Paint a line box. This function records hit test data of the line box in
// case the line box overflows the container or the line box is in a different
// chunk from the hit test data recorded for the container box's background.
// It also paints the backgrounds of the `::first-line` line box. Other line
// boxes don't have their own background.
inline void BoxFragmentPainter::PaintLineBox(
    const PhysicalFragment& line_box_fragment,
    const DisplayItemClient& display_item_client,
    const FragmentItem& line_box_item,
    const PaintInfo& paint_info,
    const PhysicalOffset& child_offset) {
  if (paint_info.phase != PaintPhase::kForeground)
    return;

  PhysicalRect border_box = line_box_fragment.LocalRect();
  border_box.offset += child_offset;
  const wtf_size_t line_fragment_id = line_box_item.FragmentId();
  DCHECK_GE(line_fragment_id, FragmentItem::kInitialLineFragmentId);
  ScopedDisplayItemFragment display_item_fragment(paint_info.context,
                                                  line_fragment_id);

  bool paints_hit_test_data =
      !RuntimeEnabledFeatures::HitTestOpaquenessEnabled() ||
      !RuntimeEnabledFeatures::HitTestOpaquenessOmitLineBoxEnabled();
  if (paints_hit_test_data && ShouldRecordHitTestData(paint_info)) {
    ObjectPainter(*GetPhysicalFragment().GetLayoutObject())
        .RecordHitTestData(paint_info, ToPixelSnappedRect(border_box),
                           display_item_client);
  }

  Element* element = DynamicTo<Element>(line_box_fragment.GetNode());
  if (element && element->GetRegionCaptureCropId()) {
    paint_info.context.GetPaintController().RecordRegionCaptureData(
        display_item_client, *(element->GetRegionCaptureCropId()),
        ToPixelSnappedRect(border_box));
  }

  // Paint the background of the `::first-line` line box.
  if (LineBoxFragmentPainter::NeedsPaint(line_box_fragment)) {
    LineBoxFragmentPainter line_box_painter(line_box_fragment, line_box_item,
                                            GetPhysicalFragment());
    line_box_painter.PaintBackgroundBorderShadow(paint_info, child_offset);
  }
}

void BoxFragmentPainter::PaintLineBoxChildItems(
    InlineCursor* children,
    const PaintInfo& paint_info,
    const PhysicalOffset& paint_offset) {
  const bool is_horizontal = box_fragment_.Style().IsHorizontalWritingMode();
  for (; *children; children->MoveToNextSkippingChildren()) {
    const FragmentItem* child_item = children->CurrentItem();
    DCHECK(child_item);
    if (child_item->IsFloating())
      continue;

    // Check if CullRect intersects with this child, only in block direction
    // because soft-wrap and <br> needs to paint outside of InkOverflow() in
    // inline direction.
    const PhysicalOffset& child_offset =
        paint_offset + child_item->OffsetInContainerFragment();
    const PhysicalRect child_rect = child_item->InkOverflowRect();
    if (is_horizontal) {
      LayoutUnit y = child_rect.offset.top + child_offset.top;
      if (!paint_info.GetCullRect().IntersectsVerticalRange(
              y, y + child_rect.size.height))
        continue;
    } else {
      LayoutUnit x = child_rect.offset.left + child_offset.left;
      if (!paint_info.GetCullRect().IntersectsHorizontalRange(
              x, x + child_rect.size.width))
        continue;
    }

    if (child_item->Type() == FragmentItem::kLine) {
      const PhysicalLineBoxFragment* line_box_fragment =
          child_item->LineBoxFragment();
      DCHECK(line_box_fragment);
      PaintLineBox(*line_box_fragment, *child_item->GetDisplayItemClient(),
                   *child_item, paint_info, child_offset);
      InlinePaintContext::ScopedLineBox scoped_line_box(*children,
                                                        inline_context_);
      InlineCursor line_box_cursor = children->CursorForDescendants();
      PaintInlineItems(paint_info, paint_offset,
                       child_item->OffsetInContainerFragment(),
                       &line_box_cursor);
      continue;
    }

    if (const PhysicalBoxFragment* child_fragment = child_item->BoxFragment()) {
      DCHECK(!child_fragment->IsOutOfFlowPositioned());
      if (child_fragment->IsListMarker()) {
        PaintBoxItem(*child_item, *child_fragment, *children, paint_info,
                     paint_offset);
        continue;
      }
    }

    NOTREACHED();
  }
}

void BoxFragmentPainter::PaintBackplate(InlineCursor* line_boxes,
                                        const PaintInfo& paint_info,
                                        const PhysicalOffset& paint_offset) {
  if (paint_info.phase != PaintPhase::kForcedColorsModeBackplate)
    return;

  // Only paint backplates behind text when forced-color-adjust is auto and the
  // element is visible.
  const ComputedStyle& style = GetPhysicalFragment().Style();
  if (style.ForcedColorAdjust() != EForcedColorAdjust::kAuto ||
      style.Visibility() != EVisibility::kVisible) {
    return;
  }

  if (DrawingRecorder::UseCachedDrawingIfPossible(
          paint_info.context, GetDisplayItemClient(),
          DisplayItem::kForcedColorsModeBackplate))
    return;

  Color backplate_color = GetPhysicalFragment()
                              .GetLayoutObject()
                              ->GetDocument()
                              .GetStyleEngine()
                              .ForcedBackgroundColor();
  const auto& backplates = BuildBackplate(line_boxes, paint_offset);
  DrawingRecorder recorder(paint_info.context, GetDisplayItemClient(),
                           DisplayItem::kForcedColorsModeBackplate,
                           ToEnclosingRect(UnionRect(backplates)));
  for (const auto backplate : backplates) {
    paint_info.context.FillRect(
        gfx::RectF(backplate), backplate_color,
        PaintAutoDarkMode(style, DarkModeFilter::ElementRole::kBackground));
  }
}

void BoxFragmentPainter::PaintTextItem(const InlineCursor& cursor,
                                       const PaintInfo& paint_info,
                                       const PhysicalOffset& paint_offset,
                                       const PhysicalOffset& parent_offset) {
  DCHECK(cursor.CurrentItem());
  const FragmentItem& item = *cursor.CurrentItem();
  DCHECK(item.IsText()) << item;

  // Only paint during the foreground/selection phases.
  if (paint_info.phase != PaintPhase::kForeground &&
      paint_info.phase != PaintPhase::kSelectionDragImage &&
      paint_info.phase != PaintPhase::kTextClip &&
      paint_info.phase != PaintPhase::kMask)
    return;

  // Skip if this child does not intersect with CullRect.
  if (!paint_info.IntersectsCullRect(
          item.InkOverflowRect(),
          paint_offset + item.OffsetInContainerFragment()) &&
      // Don't skip <br>, it doesn't have ink but need to paint selection.
      !(item.IsLineBreak() && HasSelection(item.GetLayoutObject()))) {
    return;
  }

  ScopedDisplayItemFragment display_item_fragment(paint_info.context,
                                                  item.FragmentId());
  DCHECK(inline_context_);
  InlinePaintContext::ScopedInlineItem scoped_item(item, inline_context_);
  TextFragmentPainter text_painter(cursor, parent_offset, inline_context_);
  text_painter.Paint(paint_info, paint_offset);
}

// Paint non-culled box item.
void BoxFragmentPainter::PaintBoxItem(const FragmentItem& item,
                                      const PhysicalBoxFragment& child_fragment,
                                      const InlineCursor& cursor,
                                      const PaintInfo& paint_info,
                                      const PhysicalOffset& paint_offset) {
  DCHECK_EQ(item.Type(), FragmentItem::kBox);
  DCHECK_EQ(&item, cursor.Current().Item());
  DCHECK_EQ(item.PostLayoutBoxFragment(), &child_fragment);
  DCHECK(!child_fragment.IsHiddenForPaint());
  if (child_fragment.HasSelfPaintingLayer() || child_fragment.IsFloating())
    return;

  // Skip if this child does not intersect with CullRect.
  if (!paint_info.IntersectsCullRect(
          child_fragment.InkOverflowRect(),
          paint_offset + item.OffsetInContainerFragment())) {
    return;
  }

  if (child_fragment.IsAtomicInline() || child_fragment.IsListMarker()) {
    // Establish a display item fragment scope here, in case there are multiple
    // fragment items for the same layout object. This is unusual for atomic
    // inlines, but might happen e.g. if an text-overflow ellipsis is associated
    // with the layout object.
    ScopedDisplayItemFragment display_item_fragment(paint_info.context,
                                                    item.FragmentId());
    PaintFragment(child_fragment, paint_info);
    return;
  }

  if (child_fragment.IsInlineBox()) {
    DCHECK(inline_context_);
    InlineBoxFragmentPainter(cursor, item, child_fragment, inline_context_)
        .Paint(paint_info, paint_offset);
    return;
  }

  // Block-in-inline
  DCHECK(!child_fragment.GetLayoutObject()->IsInline());
  PaintInfo paint_info_for_descendants = paint_info.ForDescendants();
  PaintBlockChild({&child_fragment, item.OffsetInContainerFragment()},
                  paint_info, paint_info_for_descendants, paint_offset);
}

void BoxFragmentPainter::PaintBoxItem(const FragmentItem& item,
                                      const InlineCursor& cursor,
                                      const PaintInfo& paint_info,
                                      const PhysicalOffset& paint_offset,
                                      const PhysicalOffset& parent_offset) {
  DCHECK_EQ(item.Type(), FragmentItem::kBox);
  DCHECK_EQ(&item, cursor.Current().Item());

  if (const PhysicalBoxFragment* child_fragment = item.BoxFragment()) {
    child_fragment = child_fragment->PostLayout();
    if (child_fragment)
      PaintBoxItem(item, *child_fragment, cursor, paint_info, paint_offset);
    return;
  }

  // Skip if this child does not intersect with CullRect.
  if (!paint_info.IntersectsCullRect(
          item.InkOverflowRect(),
          paint_offset + item.OffsetInContainerFragment())) {
    return;
  }

  // This |item| is a culled inline box.
  DCHECK(item.GetLayoutObject()->IsLayoutInline());
  InlineCursor children = cursor.CursorForDescendants();
  // Pass the given |parent_offset| because culled inline boxes do not affect
  // the sub-pixel snapping behavior. TODO(kojii): This is for the
  // compatibility, we may want to revisit in future.
  PaintInlineItems(paint_info, paint_offset, parent_offset, &children);
}

bool BoxFragmentPainter::ShouldPaint(
    const ScopedPaintState& paint_state) const {
  DCHECK(!box_fragment_.IsInlineBox());
  // When printing, the root fragment's background (i.e. the document's
  // background) should extend onto every page, regardless of the overflow
  // rectangle.
  if (box_fragment_.IsPaginatedRoot())
    return true;
  return paint_state.LocalRectIntersectsCullRect(
      box_fragment_.InkOverflowRect());
}

void BoxFragmentPainter::PaintTextClipMask(const PaintInfo& paint_info,
                                           const gfx::Rect& mask_rect,
                                           const PhysicalOffset& paint_offset,
                                           bool object_has_multiple_boxes) {
  PaintInfo mask_paint_info(paint_info.context, CullRect(mask_rect),
                            PaintPhase::kTextClip,
                            paint_info.DescendantPaintingBlocked());
  if (!object_has_multiple_boxes) {
    PaintObject(mask_paint_info, paint_offset);
    return;
  }

  DCHECK(inline_box_cursor_);
  DCHECK(box_item_);
  DCHECK(inline_context_);
  InlineBoxFragmentPainter inline_box_painter(*inline_box_cursor_, *box_item_,
                                              inline_context_);
  PaintTextClipMask(mask_paint_info,
                    paint_offset - box_item_->OffsetInContainerFragment(),
                    &inline_box_painter);
}

void BoxFragmentPainter::PaintTextClipMask(
    const PaintInfo& paint_info,
    PhysicalOffset paint_offset,
    InlineBoxFragmentPainter* inline_box_painter) {
  const ComputedStyle& style = box_fragment_.Style();
  if (style.BoxDecorationBreak() == EBoxDecorationBreak::kSlice) {
    LayoutUnit offset_on_line;
    LayoutUnit total_width;
    inline_box_painter->ComputeFragmentOffsetOnLine(
        style.Direction(), &offset_on_line, &total_width);
    if (style.IsHorizontalWritingMode())
      paint_offset.left += offset_on_line;
    else
      paint_offset.top += offset_on_line;
  }
  inline_box_painter->Paint(paint_info, paint_offset);
}

PhysicalRect BoxFragmentPainter::AdjustRectForScrolledContent(
    GraphicsContext& context,
    const PhysicalBoxStrut& borders,
    const PhysicalRect& rect) const {
  const PhysicalBoxFragment& physical = GetPhysicalFragment();

  // Clip to the overflow area.
  context.Clip(gfx::RectF(physical.OverflowClipRect(rect.offset)));

  PhysicalRect scrolled_paint_rect = rect;
  // Adjust the paint rect to reflect a scrolled content box with borders at
  // the ends.
  scrolled_paint_rect.offset -=
      PhysicalOffset(physical.PixelSnappedScrolledContentOffset());
  scrolled_paint_rect.size =
      physical.ScrollSize() +
      PhysicalSize(borders.HorizontalSum(), borders.VerticalSum());
  return scrolled_paint_rect;
}

BoxPainterBase::FillLayerInfo BoxFragmentPainter::GetFillLayerInfo(
    const Color& color,
    const FillLayer& bg_layer,
    BackgroundBleedAvoidance bleed_avoidance,
    bool is_painting_background_in_contents_space) const {
  const PhysicalBoxFragment& fragment = GetPhysicalFragment();
  return BoxPainterBase::FillLayerInfo(
      fragment.GetLayoutObject()->GetDocument(), fragment.Style(),
      fragment.IsScrollContainer(), color, bg_layer, bleed_avoidance,
      box_fragment_.SidesToInclude(),
      fragment.GetLayoutObject()->IsLayoutInline(),
      is_painting_background_in_contents_space);
}

template <typename T>
bool BoxFragmentPainter::HitTestContext::AddNodeToResult(
    Node* node,
    const PhysicalBoxFragment* box_fragment,
    const T& bounds_rect,
    const PhysicalOffset& offset) const {
  if (node && !result->InnerNode())
    result->SetNodeAndPosition(node, box_fragment, location.Point() - offset);
  return result->AddNodeToListBasedTestResult(node, location, bounds_rect) ==
         kStopHitTesting;
}

template <typename T>
bool BoxFragmentPainter::HitTestContext::AddNodeToResultWithContentOffset(
    Node* node,
    const PhysicalBoxFragment& container,
    const T& bounds_rect,
    PhysicalOffset offset) const {
  if (container.IsScrollContainer())
    offset += PhysicalOffset(container.PixelSnappedScrolledContentOffset());
  return AddNodeToResult(node, &container, bounds_rect, offset);
}

bool BoxFragmentPainter::NodeAtPoint(HitTestResult& result,
                                     const HitTestLocation& hit_test_location,
                                     const PhysicalOffset& physical_offset,
                                     HitTestPhase phase) {
  HitTestContext hit_test{phase, hit_test_location, physical_offset, &result};
  return NodeAtPoint(hit_test, physical_offset);
}

bool BoxFragmentPainter::NodeAtPoint(HitTestResult& result,
                                     const HitTestLocation& hit_test_location,
                                     const PhysicalOffset& physical_offset,
                                     const PhysicalOffset& inline_root_offset,
                                     HitTestPhase phase) {
  HitTestContext hit_test{phase, hit_test_location, inline_root_offset,
                          &result};
  return NodeAtPoint(hit_test, physical_offset);
}

bool BoxFragmentPainter::NodeAtPoint(const HitTestContext& hit_test,
                                     const PhysicalOffset& physical_offset) {
  const PhysicalBoxFragment& fragment = GetPhysicalFragment();
  // Creating a BoxFragmentPainter is a significant cost, especially in broad
  // trees. Should check before getting here, whether the fragment might
  // intersect or not.
  DCHECK(fragment.MayIntersect(*hit_test.result, hit_test.location,
                               physical_offset));

  if (!fragment.IsFirstForNode() && !CanPaintMultipleFragments(fragment))
    return false;

  if (hit_test.phase == HitTestPhase::kForeground &&
      !box_fragment_.HasSelfPaintingLayer() &&
      HitTestOverflowControl(hit_test, physical_offset))
    return true;

  const PhysicalSize& size = fragment.Size();
  const ComputedStyle& style = fragment.Style();
  const LayoutObject* layout_object = fragment.GetLayoutObject();
  bool skip_children =
      layout_object &&
      (layout_object == hit_test.result->GetHitTestRequest().GetStopNode() ||
       layout_object->ChildPaintBlockedByDisplayLock());
  if (!skip_children && box_fragment_.ShouldClipOverflowAlongEitherAxis()) {
    // PaintLayer::HitTestFragmentsWithPhase() checked the fragments'
    // foreground rect for intersection if a layer is self painting,
    // so only do the overflow clip check here for non-self-painting layers.
    if (!box_fragment_.HasSelfPaintingLayer() &&
        !hit_test.location.Intersects(GetPhysicalFragment().OverflowClipRect(
            physical_offset, kExcludeOverlayScrollbarSizeForHitTesting))) {
      skip_children = true;
    }
    if (!skip_children && style.HasBorderRadius()) {
      PhysicalRect bounds_rect(physical_offset, size);
      skip_children = !hit_test.location.Intersects(
          RoundedBorderGeometry::PixelSnappedRoundedInnerBorder(style,
                                                                bounds_rect));
    }
  }

  if (!skip_children) {
    if (!box_fragment_.IsScrollContainer()) {
      if (HitTestChildren(hit_test, physical_offset))
        return true;
    } else {
      const PhysicalOffset scrolled_offset =
          physical_offset -
          PhysicalOffset(
              GetPhysicalFragment().PixelSnappedScrolledContentOffset());
      HitTestContext adjusted_hit_test{hit_test.phase, hit_test.location,
                                       scrolled_offset, hit_test.result};
      if (HitTestChildren(adjusted_hit_test, scrolled_offset))
        return true;
    }
  }

  if (style.HasBorderRadius() &&
      HitTestClippedOutByBorder(hit_test.location, physical_offset))
    return false;

  bool pointer_events_bounding_box = false;
  bool hit_test_self = fragment.IsInSelfHitTestingPhase(hit_test.phase);
  if (hit_test_self) {
    // Table row and table section are never a hit target.
    // SVG <text> is not a hit target except if 'pointer-events: bounding-box'.
    if (GetPhysicalFragment().IsTableRow() ||
        GetPhysicalFragment().IsTableSection()) {
      hit_test_self = false;
    } else if (fragment.IsSvgText()) {
      pointer_events_bounding_box =
          fragment.Style().UsedPointerEvents() == EPointerEvents::kBoundingBox;
      hit_test_self = pointer_events_bounding_box;
    }
  }

  // Now hit test ourselves.
  if (hit_test_self) {
    if (!IsVisibleToHitTest(fragment, hit_test.result->GetHitTestRequest()))
        [[unlikely]] {
      return false;
    }
    if (fragment.IsOpaque()) [[unlikely]] {
      return false;
    }
  } else if (fragment.IsOpaque() && hit_test.result->HasListBasedResult() &&
             IsVisibleToHitTest(fragment, hit_test.result->GetHitTestRequest()))
      [[unlikely]] {
    // Opaque fragments should not hit, but they are still ancestors in the DOM
    // tree. They should be added to the list-based result as ancestors if
    // descendants hit.
    hit_test_self = true;
  }
  if (hit_test_self) {
    PhysicalRect bounds_rect(physical_offset, size);
    if (hit_test.result->GetHitTestRequest().IsHitTestVisualOverflow())
        [[unlikely]] {
      // We'll include overflow from children here (in addition to self-overflow
      // caused by filters), because we want to record a match if we hit the
      // overflow of a child below the stop node. This matches legacy behavior
      // in LayoutBox::NodeAtPoint(); see call to
      // PhysicalVisualOverflowRectIncludingFilters().
      bounds_rect = InkOverflowIncludingFilters();
      bounds_rect.Move(physical_offset);
    }
    if (pointer_events_bounding_box) [[unlikely]] {
      bounds_rect = PhysicalRect::EnclosingRect(
          GetPhysicalFragment().GetLayoutObject()->ObjectBoundingBox());
    }
    // TODO(kojii): Don't have good explanation why only inline box needs to
    // snap, but matches to legacy and fixes crbug.com/976606.
    if (fragment.IsInlineBox())
      bounds_rect = PhysicalRect(ToPixelSnappedRect(bounds_rect));
    if (hit_test.location.Intersects(bounds_rect)) {
      // We set offset in container block instead of offset in |fragment| like
      // |BoxFragmentPainter::HitTestTextFragment()|.
      // See http://crbug.com/1043471
      DCHECK(!box_item_ || box_item_->BoxFragment() == &fragment);
      if (box_item_ && box_item_->IsInlineBox()) {
        DCHECK(inline_box_cursor_);
        if (hit_test.AddNodeToResultWithContentOffset(
                fragment.NodeForHitTest(),
                inline_box_cursor_->ContainerFragment(), bounds_rect,
                physical_offset - box_item_->OffsetInContainerFragment()))
          return true;
      } else {
        if (UpdateHitTestResultForView(bounds_rect, hit_test))
          return true;
        if (hit_test.AddNodeToResult(fragment.NodeForHitTest(), &box_fragment_,
                                     bounds_rect, physical_offset))
          return true;
      }
    }
  }

  return false;
}

bool BoxFragmentPainter::UpdateHitTestResultForView(
    const PhysicalRect& bounds_rect,
    const HitTestContext& hit_test) const {
  const LayoutObject* layout_object = GetPhysicalFragment().GetLayoutObject();
  if (!layout_object || !layout_object->IsLayoutView() ||
      hit_test.result->InnerNode()) {
    return false;
  }
  auto* element = layout_object->GetDocument().documentElement();
  if (!element)
    return false;
  const auto children = GetPhysicalFragment().Children();
  auto it = base::ranges::find(children, element, &PhysicalFragment::GetNode);
  if (it == children.end())
    return false;
  return hit_test.AddNodeToResultWithContentOffset(
      element, To<PhysicalBoxFragment>(**it), bounds_rect, it->Offset());
}

bool BoxFragmentPainter::HitTestAllPhases(
    HitTestResult& result,
    const HitTestLocation& hit_test_location,
    const PhysicalOffset& accumulated_offset) {
  // Logic taken from LayoutObject::HitTestAllPhases().
  if (NodeAtPoint(result, hit_test_location, accumulated_offset,
                  HitTestPhase::kForeground)) {
    return true;
  }
  if (NodeAtPoint(result, hit_test_location, accumulated_offset,
                  HitTestPhase::kFloat)) {
    return true;
  }
  if (NodeAtPoint(result, hit_test_location, accumulated_offset,
                  HitTestPhase::kDescendantBlockBackgrounds)) {
    return true;
  }
  if (NodeAtPoint(result, hit_test_location, accumulated_offset,
                  HitTestPhase::kSelfBlockBackground)) {
    return true;
  }
  return false;
}

bool BoxFragmentPainter::HitTestTextItem(const HitTestContext& hit_test,
                                         const FragmentItem& text_item,
                                         const InlineBackwardCursor& cursor) {
  DCHECK(text_item.IsText());

  if (hit_test.phase != HitTestPhase::kForeground) {
    return false;
  }
  if (!IsVisibleToHitTest(text_item, hit_test.result->GetHitTestRequest())) {
    return false;
  }

  if (text_item.IsSvgText() && text_item.HasSvgTransformForBoundingBox()) {
    const gfx::QuadF quad = text_item.SvgUnscaledQuad();
    if (!hit_test.location.Intersects(quad)) {
      return false;
    }
    return hit_test.AddNodeToResultWithContentOffset(
        text_item.NodeForHitTest(), cursor.ContainerFragment(), quad,
        hit_test.inline_root_offset);
  }

  const auto* const text_combine =
      DynamicTo<LayoutTextCombine>(box_fragment_.GetLayoutObject());

  // TODO(layout-dev): Clip to line-top/bottom.
  PhysicalRect rect;
  if (text_combine) [[unlikely]] {
    rect = text_combine->ComputeTextBoundsRectForHitTest(
        text_item, hit_test.inline_root_offset);
  } else {
    rect = text_item.ComputeTextBoundsRectForHitTest(
        hit_test.inline_root_offset,
        hit_test.result->GetHitTestRequest().IsHitTestVisualOverflow());
  }
  if (!hit_test.location.Intersects(rect))
    return false;

  return hit_test.AddNodeToResultWithContentOffset(
      text_item.NodeForHitTest(), cursor.ContainerFragment(), rect,
      hit_test.inline_root_offset);
}

bool BoxFragmentPainter::HitTestLineBoxFragment(
    const HitTestContext& hit_test,
    const PhysicalLineBoxFragment& fragment,
    const InlineBackwardCursor& cursor,
    const PhysicalOffset& physical_offset) {
  DCHECK_EQ(cursor.Current()->LineBoxFragment(), &fragment);
  PhysicalRect overflow_rect = cursor.Current().InkOverflowRect();
  overflow_rect.Move(physical_offset);
  if (!hit_test.location.Intersects(overflow_rect))
    return false;

  if (HitTestChildren(hit_test, GetPhysicalFragment(),
                      cursor.CursorForDescendants(), physical_offset)) {
    return true;
  }

  if (hit_test.phase != HitTestPhase::kForeground)
    return false;

  if (!IsVisibleToHitTest(box_fragment_, hit_test.result->GetHitTestRequest()))
    return false;

  const PhysicalOffset overflow_location =
      cursor.Current().SelfInkOverflowRect().offset + physical_offset;
  if (HitTestClippedOutByBorder(hit_test.location, overflow_location))
    return false;

  const PhysicalRect bounds_rect(physical_offset, fragment.Size());
  const ComputedStyle& containing_box_style = box_fragment_.Style();
  if (containing_box_style.HasBorderRadius() &&
      !hit_test.location.Intersects(
          RoundedBorderGeometry::PixelSnappedRoundedBorder(containing_box_style,
                                                           bounds_rect)))
    return false;

  if (cursor.ContainerFragment().IsSvgText())
    return false;

  // Now hit test ourselves.
  if (!hit_test.location.Intersects(bounds_rect))
    return false;

  // Floats will be hit-tested in |kHitTestFloat| phase, but
  // |LayoutObject::HitTestAllPhases| does not try it if |kHitTestForeground|
  // succeeds. Pretend the location is not in this linebox if it hits floating
  // descendants. TODO(kojii): Computing this is redundant, consider
  // restructuring. Changing the caller logic isn't easy because currently
  // floats are in the bounds of line boxes only in NG.
  if (fragment.HasFloatingDescendantsForPaint()) {
    DCHECK_NE(hit_test.phase, HitTestPhase::kFloat);
    HitTestResult result;
    HitTestContext hit_test_float{HitTestPhase::kFloat, hit_test.location,
                                  hit_test.inline_root_offset, &result};
    if (HitTestChildren(hit_test_float, GetPhysicalFragment(),
                        cursor.CursorForDescendants(), physical_offset)) {
      return false;
    }
  }

  // |physical_offset| is inside line, but
  //  * Outside of children
  //  * In child without no foreground descendant, e.g. block with size.
  if (cursor.Current()->LineBoxFragment()->
```