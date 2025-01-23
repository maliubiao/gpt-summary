Response:
My thinking process to analyze the given C++ code and fulfill the request goes like this:

1. **Understand the Core Request:** The primary goal is to understand the functionality of `inline_box_state.cc` within the Chromium Blink rendering engine. This involves identifying its purpose, its relationship to web technologies (HTML, CSS, JavaScript), potential logical inferences, common errors, and summarizing its overall function (as part 2 of a larger file).

2. **Initial Code Scan and Keyword Identification:** I start by quickly scanning the code for prominent keywords and patterns. I see terms like `InlineLayoutStateStack`, `InlineBoxState`, `BoxData`, `LogicalLineItems`, `LayoutUnit`, `LayoutResult`, `FragmentGeometry`, `vertical-align`, `baseline-shift`, `ruby`, and function names like `MoveBoxData`, `ApplyRelativePositioning`, `CreateBoxFragments`, `ApplyBaselineShift`, etc. These keywords provide initial clues about the file's purpose.

3. **Focus on Key Classes:**  I identify the central classes: `InlineLayoutStateStack` and `InlineBoxState`. These likely represent the core data structures and logic for managing the layout of inline elements.

4. **Analyze `InlineLayoutStateStack`:** I examine the methods within this class.
    * `MoveBoxDataInBlockDirection`, `MoveBoxDataInInlineDirection`: Suggests manipulation of box positions along vertical and horizontal axes.
    * `ApplyRelativePositioning`:  Indicates handling of relative positioning for inline elements. The comments mentioning `<span>` reinforce this.
    * `CreateBoxFragments`: Points towards the creation of layout fragments, essential for rendering.
    * `ApplyBaselineShift`: Clearly deals with the `vertical-align` and `baseline-shift` CSS properties.
    * `CreateRubyColumn`: Indicates support for ruby annotations.

5. **Analyze `InlineBoxState`:**  I look at the members and methods of this class.
    * Members like `rect`, `metrics`, `text_metrics`, `margins`, `borders`, `padding` represent properties relevant to the size and positioning of inline boxes.
    * The `CreateBoxFragment` method is crucial for generating the actual layout fragment.
    * `pending_descendants` suggests a mechanism for handling `vertical-align` dependencies.

6. **Connect to Web Technologies:** Based on the identified functionalities, I start making connections to HTML, CSS, and JavaScript:
    * **HTML:**  The comments explicitly mention `<span>`, indicating a direct relationship to inline HTML elements. The presence of ruby-related code links to the `<ruby>` tag.
    * **CSS:**  Properties like `vertical-align`, `baseline-shift`, `margin`, `border`, `padding`, `position: relative` are directly handled by the code. The logic within `ApplyBaselineShift` directly implements the behavior of `vertical-align`.
    * **JavaScript:** While the C++ code itself doesn't directly interact with JavaScript, the layout calculations it performs are crucial for the visual rendering of web pages, which is often dynamically manipulated by JavaScript. For example, JavaScript changes to CSS properties affecting inline layout would trigger recalculations in this C++ code.

7. **Infer Logical Reasoning (Hypothetical Input/Output):** I consider how the code might behave with specific inputs. For example, for `ApplyRelativePositioning`:
    * **Input:** A `LogicalLineItems` object representing a line of text, and a `BoxData` object for a `<span>` element with `position: relative; top: 10px; left: 5px;`.
    * **Output:** The `rect.offset` of the items within the `<span>` in the `LogicalLineItems` would be adjusted by `(5px, 10px)`.

8. **Identify Potential Usage Errors:** I think about common mistakes developers make with inline elements and how this code might be affected:
    * **Incorrect `vertical-align`:**  Using `vertical-align` on elements that are not inline or table-cell might not have the intended effect. The code handles various `vertical-align` values, but the layout context is important.
    * **Confusing relative and absolute positioning:**  Misunderstanding how `position: relative` affects inline elements and their descendants is a common error. The code correctly applies relative offsets.
    * **Forgetting about margins/padding on inline elements:** Developers might forget that horizontal margins and padding apply to inline elements, affecting their spacing. The code explicitly considers margins and padding.

9. **Address Part 2 Summary:**  I focus on summarizing the overall function of the provided code snippet. Since it's part 2, I assume part 1 dealt with the initial setup or data structures. Part 2 seems to focus on the *manipulation* and *finalization* of inline box layout – moving boxes, applying relative positioning, creating fragments, and handling baseline shifts.

10. **Structure the Answer:** Finally, I organize the information into the requested categories: functionality, relationships to web technologies (with examples), logical inferences, common errors, and the summary for part 2. I use clear and concise language, referencing specific code elements where appropriate. I ensure the examples are concrete and easy to understand.

By following these steps, I can systematically analyze the C++ code and provide a comprehensive answer that addresses all aspects of the user's request. The process involves understanding the code's structure and logic, connecting it to the broader context of web rendering, and anticipating potential user interactions and errors.
这是 `blink/renderer/core/layout/inline/inline_box_state.cc` 文件的第二部分，其主要功能是继续处理和完成内联盒子的布局。 基于第一部分已经创建和初始化的一些状态和数据，第二部分着重于最终确定内联盒子的位置、创建布局片段以及处理基线对齐等。

**以下是第二部分代码的功能归纳：**

1. **调整内联盒子的尺寸和位置 (AdjustInlineBoxRect):**
   - 该函数负责根据其包含的内容和周围的上下文来最终确定内联盒子的矩形区域 (`rect`)。
   - 它会考虑盒子的内边距、边框和外边距，以及相邻盒子的位置。
   - **与 CSS 关系:** 这直接关系到 CSS 中影响内联元素尺寸和定位的属性，例如 `width`, `height` (在特定情况下), `margin`, `padding`, `border`。
   - **逻辑推理 (假设输入与输出):**
     - **假设输入:** 一个内联盒子包含文本 "Hello"，其 `margin-left` 为 `5px`，`padding-left` 为 `3px`，前一个内联盒子的右边界位于 `100px`。
     - **输出:**  `box_data.rect.offset.inline_offset` 将被计算为 `100px + 5px + 3px` 加上前一个盒子的宽度， `box_data.rect.size.inline_size` 将是 "Hello" 的文本宽度加上左右内边距。

2. **在块方向和内联方向移动盒子数据 (MoveBoxDataInBlockDirection, MoveBoxDataInInlineDirection):**
   - 这两个函数用于在布局过程中调整所有已存储的盒子数据的位置。
   - 这在处理相对定位或调整行框时非常有用。
   - **与 CSS 关系:** 与 CSS 中的 `top`, `bottom`, `left`, `right` 属性（特别是对于相对定位的元素）有关。
   - **逻辑推理 (假设输入与输出):**
     - **假设输入:** 调用 `MoveBoxDataInBlockDirection(10px)`。
     - **输出:** 所有 `box_data_list_` 中的 `box_data.rect.offset.block_offset` 都将增加 `10px`。

3. **应用相对定位 (ApplyRelativePositioning):**
   - 此函数处理内联元素的相对定位。
   - 它会计算相对于其正常位置的偏移量，并将该偏移量应用到盒子的位置上。
   - **与 CSS 关系:** 直接对应于 CSS 中的 `position: relative` 属性以及 `top`, `bottom`, `left`, `right` 属性的值。
   - **逻辑推理 (假设输入与输出):**
     - **假设输入:** 一个 `<span>` 元素设置了 `position: relative; top: 5px; left: 10px;`。
     - **输出:** 该 `<span>` 元素及其包含的文本片段的最终位置将相对于其原本的位置向下偏移 `5px`，向右偏移 `10px`。

4. **创建盒子片段 (CreateBoxFragments):**
   - 这是内联布局的关键步骤。它将逻辑上的内联盒子信息转换为实际的布局片段 (`LayoutResult`)，这些片段可以用于后续的绘制。
   - 它会考虑盒子的边框、内边距和是否透明等因素。
   - **与 CSS 关系:** 涉及到所有影响盒子外观的 CSS 属性，包括 `border`, `padding`, `background-color` (决定是否为 opaque)。
   - **逻辑推理 (假设输入与输出):**
     - **假设输入:** 一个 `<strong>` 标签包含了文本 "Bold"，并且设置了 `border: 1px solid black; padding: 2px;`。
     - **输出:**  会创建一个 `LayoutResult` 对象，其中包含了该 `<strong>` 标签的边框和内边距信息，以及文本 "Bold" 的布局信息。

5. **处理基线偏移 (ApplyBaselineShift):**
   - 此函数处理内联元素的 `vertical-align` 属性，用于调整元素相对于其基线的垂直位置。
   - 它支持不同的 `vertical-align` 值，如 `top`, `bottom`, `middle`, `sub`, `super` 等。
   - **与 CSS 关系:** 直接对应于 CSS 的 `vertical-align` 属性。
   - **逻辑推理 (假设输入与输出):**
     - **假设输入:** 一个 `<sub>` 标签（表示下标）。
     - **输出:** 该标签内的文本片段的基线将被向下移动，使其看起来像下标。
     - **用户或编程常见的使用错误:**  在非内联元素上使用 `vertical-align`，例如在 `<div>` 上设置 `vertical-align: middle;` 通常不会有预期的效果，因为 `vertical-align` 只对内联元素、表格单元格和匿名内联表格单元格有效。

6. **计算对齐基线偏移 (ComputeAlignmentBaselineShift):**
   - 辅助 `ApplyBaselineShift` 函数，用于计算更精细的基线调整，特别是对于 SVG 文本元素。

7. **计算用于顶部和底部对齐的度量 (MetricsForTopAndBottomAlign):**
   - 辅助 `ApplyBaselineShift` 函数，用于计算 `vertical-align: top` 和 `vertical-align: bottom` 所需的度量信息。

8. **创建 Ruby 列 (CreateRubyColumn):**
   - 支持 Ruby 注释的布局，用于创建 Ruby 文本的列。
   - **与 HTML/CSS 关系:** 与 HTML 的 `<ruby>` 标签以及相关的 CSS 属性有关。

**与 JavaScript, HTML, CSS 的关系举例说明:**

* **HTML:** 当浏览器解析包含 `<span>` 或 `<strong>` 等内联元素的 HTML 时，会创建相应的布局对象。`InlineLayoutStateStack` 和 `InlineBoxState` 类用于管理这些内联元素的布局信息。
* **CSS:** CSS 样式（如 `font-size`, `line-height`, `vertical-align`, `margin`, `padding`, `border`, `position: relative`）的值会被读取并用于计算内联盒子的尺寸、位置和基线偏移。例如，当 CSS 中设置 `vertical-align: middle;` 时，`ApplyBaselineShift` 函数会根据元素的字体大小和行高来调整其垂直位置。
* **JavaScript:** JavaScript 可以动态地修改元素的 CSS 样式。当 JavaScript 更改了影响内联布局的 CSS 属性时，Blink 引擎会重新计算布局，包括调用 `InlineLayoutStateStack` 和 `InlineBoxState` 中的相关方法来更新内联盒子的布局信息。

**用户或编程常见的使用错误举例说明:**

* **错误地在块级元素上使用 `vertical-align`:**  例如，用户可能会尝试在 `<div>` 元素上设置 `vertical-align: middle;` 来使其内容垂直居中。然而，`vertical-align` 属性只对内联元素、表格单元格以及匿名内联表格单元格起作用。正确的做法是使用 Flexbox 或 Grid 布局来实现块级元素的垂直居中。
* **忘记考虑内联元素的边距和内边距:** 开发者可能会忽略内联元素的水平边距和内边距会影响其在行内的水平空间占用，导致布局上的意外。

**总结:**

`inline_box_state.cc` 的第二部分专注于内联盒子布局的最终处理阶段，包括：

- **确定内联盒子的精确尺寸和位置。**
- **应用相对定位带来的偏移。**
- **将逻辑上的盒子信息转换为可以用于渲染的布局片段。**
- **根据 `vertical-align` 属性调整元素的基线。**
- **支持更复杂的内联布局，如 Ruby 注释。**

它与 HTML 结构和 CSS 样式紧密相关，是 Blink 引擎渲染内联内容的关键组成部分。理解这部分代码的功能有助于深入了解浏览器如何将 HTML 和 CSS 转化为用户可见的网页。

### 提示词
```
这是目录为blink/renderer/core/layout/inline/inline_box_state.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
st];
    LayoutUnit line_right_offset = last_child.rect.offset.inline_offset -
                                   last_child.margin_line_left +
                                   last_child.inline_size;
    LinePadding& last_padding = accumulated_padding[last];

    if (!ignore_box_margin_border_padding) {
      start_padding.line_left += box_data.margin_border_padding_line_left;
      last_padding.line_right += box_data.margin_border_padding_line_right;
      line_left_offset += box_data.margin_line_left;
      line_right_offset -= box_data.margin_line_right;
    }

    line_left_offset -= start_padding.line_left;
    line_right_offset += last_padding.line_right;

    box_data.rect.offset.inline_offset = line_left_offset;
    box_data.rect.size.inline_size = line_right_offset - line_left_offset;
  }

  return position;
}

void InlineLayoutStateStack::MoveBoxDataInBlockDirection(LayoutUnit diff) {
  for (BoxData& box_data : box_data_list_) {
    box_data.rect.offset.block_offset += diff;
  }
}

void InlineLayoutStateStack::MoveBoxDataInInlineDirection(LayoutUnit diff) {
  for (BoxData& box_data : box_data_list_) {
    box_data.rect.offset.inline_offset += diff;
  }
}

void InlineLayoutStateStack::ApplyRelativePositioning(
    const ConstraintSpace& space,
    LogicalLineItems* line_box,
    const LogicalOffset* parent_offset) {
  if (box_data_list_.empty() && ruby_column_list_.empty() && !parent_offset) {
    return;
  }

  // The final position of any inline boxes, (<span>, etc) are stored on
  // |BoxData::rect|. As we don't have a mapping from |LogicalLineItem| to
  // |BoxData| we store the accumulated relative offsets, and then apply the
  // final adjustment at the end of this function.
  Vector<LogicalOffset, 32> accumulated_offsets(line_box->size());

  if (parent_offset) {
    for (unsigned index = 0; index < line_box->size(); ++index) {
      (*line_box)[index].rect.offset += *parent_offset;
      accumulated_offsets[index] = *parent_offset;
    }
  }

  for (BoxData& box_data : box_data_list_) {
    unsigned start = box_data.fragment_start;
    unsigned end = box_data.fragment_end;
    const LogicalOffset relative_offset =
        ComputeRelativeOffsetForInline(space, *box_data.item->Style());

    // Move all children for this box.
    for (unsigned index = start; index < end; index++) {
      auto& child = (*line_box)[index];
      child.rect.offset += relative_offset;
      accumulated_offsets[index] += relative_offset;
    }
  }

  // Apply the final accumulated relative position offset for each box.
  for (BoxData& box_data : box_data_list_)
    box_data.rect.offset += accumulated_offsets[box_data.fragment_start];

  for (auto& logical_column : ruby_column_list_) {
    logical_column->state_stack.ApplyRelativePositioning(
        space, logical_column->annotation_items,
        &accumulated_offsets[logical_column->start_index]);
  }
}

void InlineLayoutStateStack::CreateBoxFragments(const ConstraintSpace& space,
                                                LogicalLineItems* line_box,
                                                bool is_opaque) {
  for (auto& logical_column : ruby_column_list_) {
    logical_column->state_stack.CreateBoxFragments(
        space, logical_column->annotation_items, /* is_opaque */ false);
  }

  if (!HasBoxFragments()) {
    return;
  }

  for (BoxData& box_data : box_data_list_) {
    unsigned start = box_data.fragment_start;
    unsigned end = box_data.fragment_end;
    DCHECK_GT(end, start);
    LogicalLineItem* child = &(*line_box)[start];
    DCHECK(box_data.item->ShouldCreateBoxFragment());
    const LayoutResult* box_fragment =
        box_data.CreateBoxFragment(space, line_box, is_opaque);
    if (child->IsPlaceholder()) {
      child->layout_result = std::move(box_fragment);
      child->rect = box_data.rect;
      child->children_count = end - start;
      continue;
    }

    // |AddBoxFragmentPlaceholder| adds a placeholder at |fragment_start|, but
    // bidi reordering may move it. Insert in such case.
    line_box->InsertChild(start, std::move(box_fragment), box_data.rect,
                          end - start + 1);
    ChildInserted(start + 1);
  }

  box_data_list_.clear();
}

const LayoutResult* InlineLayoutStateStack::BoxData::CreateBoxFragment(
    const ConstraintSpace& space,
    LogicalLineItems* line_box,
    bool is_opaque) {
  DCHECK(item);
  DCHECK(item->Style());
  const ComputedStyle& style = *item->Style();

  FragmentGeometry fragment_geometry;
  fragment_geometry.border_box_size = {
      rect.size.inline_size.ClampNegativeToZero(), rect.size.block_size};
  fragment_geometry.border =
      BoxStrut(borders, IsFlippedLinesWritingMode(style.GetWritingMode()));
  fragment_geometry.padding =
      BoxStrut(padding, IsFlippedLinesWritingMode(style.GetWritingMode()));

  // Because children are already in the visual order, use LTR for the
  // fragment builder so that it should not transform the coordinates for RTL.
  BoxFragmentBuilder box(item->GetLayoutObject(), &style, space,
                         {style.GetWritingMode(), TextDirection::kLtr});
  box.SetInitialFragmentGeometry(fragment_geometry);
  box.SetBoxType(PhysicalFragment::kInlineBox);
  box.SetStyleVariant(item->GetStyleVariant());

  if (is_opaque) [[unlikely]] {
    box.SetIsOpaque();
    box.SetSidesToInclude({false, false, false, false});
  } else {
    // Inline boxes have block start/end borders, even when its containing block
    // was fragmented. Fragmenting a line box in block direction is not
    // supported today.
    box.SetSidesToInclude(
        {true, has_line_right_edge, true, has_line_left_edge});
  }

  auto handle_box_child = [&](LogicalLineItem& child) {
    if (child.out_of_flow_positioned_box) {
      DCHECK(item->GetLayoutObject()->IsLayoutInline());
      BlockNode oof_box(To<LayoutBox>(child.out_of_flow_positioned_box.Get()));

      // child.offset is the static position wrt. the linebox. As we are adding
      // this as a child of an inline level fragment, we adjust the static
      // position to be relative to this fragment.
      LogicalOffset static_offset = child.rect.offset - rect.offset;

      box.AddOutOfFlowInlineChildCandidate(oof_box, static_offset,
                                           child.container_direction,
                                           child.is_hidden_for_paint);
      child.out_of_flow_positioned_box = nullptr;
      return;
    }

    // Propagate any OOF-positioned descendants from any atomic-inlines, etc.
    if (child.layout_result) {
      const ComputedStyle& child_style = child.GetPhysicalFragment()->Style();
      box.PropagateFromLayoutResultAndFragment(
          *child.layout_result,
          child.rect.offset - rect.offset -
              ComputeRelativeOffsetForInline(space, child_style),
          ComputeRelativeOffsetForOOFInInline(space, child_style));
    }
  };

  for (unsigned i = fragment_start; i < fragment_end; i++) {
    LogicalLineItem& child = (*line_box)[i];

    // If |child| has a fragment created by previous |CreateBoxFragment|, skip
    // children that were already added to |child|.
    if (child.children_count) {
      i += child.children_count - 1;
    }

    handle_box_child(child);

    // |FragmentItems| has a flat list of all descendants, except
    // OOF-positioned descendants. We still create a |PhysicalBoxFragment|,
    // but don't add children to it and keep them in the flat list.
  }
  if (ruby_column_list) {
    for (auto& logical_column : *ruby_column_list) {
      auto& annotation_items = *logical_column->annotation_items;
      if (annotation_items.WasPropagated()) {
        continue;
      }
      for (unsigned i = 0; i < annotation_items.size(); ++i) {
        LogicalLineItem& child = annotation_items[i];
        if (child.children_count) {
          i += child.children_count - 1;
        }
        handle_box_child(child);
      }
      annotation_items.SetPropagated();
    }
    ruby_column_list.Clear();
  }

  // Inline boxes that produce DisplayItemClient should do full paint
  // invalidations.
  item->GetLayoutObject()->SetShouldDoFullPaintInvalidation();

  box.MoveOutOfFlowDescendantCandidatesToDescendants();
  return box.ToInlineBoxFragment();
}

void InlineLayoutStateStack::BoxData::Trace(Visitor* visitor) const {
  visitor->Trace(ruby_column_list);
}

InlineLayoutStateStack::PositionPending
InlineLayoutStateStack::ApplyBaselineShift(InlineBoxState* box,
                                           LogicalLineItems* line_box,
                                           FontBaseline baseline_type) {
  // The `vertical-align` property should not apply to the line wrapper for
  // block-in-inline.
  if (has_block_in_inline_) [[unlikely]] {
    DCHECK(box->pending_descendants.empty());
    return kPositionNotPending;
  }

  // Some 'vertical-align' values require the size of their parents. Align all
  // such descendant boxes that require the size of this box; they are queued in
  // |pending_descendants|.
  LayoutUnit baseline_shift;
  if (!box->pending_descendants.empty()) {
    bool has_top_or_bottom = false;
    for (PendingPositions& child : box->pending_descendants) {
      // In quirks mode, metrics is empty if no content.
      if (child.metrics.IsEmpty())
        child.metrics = FontHeight();
      switch (child.vertical_align) {
        case EVerticalAlign::kTextTop:
          baseline_shift = child.metrics.ascent + box->TextTop(baseline_type);
          break;
        case EVerticalAlign::kTextBottom:
          if (const SimpleFontData* font_data = box->font->PrimaryFont()) {
            LayoutUnit text_bottom =
                font_data->GetFontMetrics().FixedDescent(baseline_type);
            baseline_shift = text_bottom - child.metrics.descent;
            break;
          }
          DUMP_WILL_BE_NOTREACHED();
          break;
        case EVerticalAlign::kTop:
        case EVerticalAlign::kBottom:
          has_top_or_bottom = true;
          continue;
        default:
          NOTREACHED();
      }
      child.metrics.Move(baseline_shift);
      box->metrics.Unite(child.metrics);
      line_box->MoveInBlockDirection(baseline_shift, child.fragment_start,
                                     child.fragment_end);
    }
    // `top` and `bottom` need to be applied after all other values are applied,
    // because they align to the maximum metrics, but the maximum metrics may
    // depend on other pending descendants for this box.
    if (has_top_or_bottom) {
      FontHeight max = MetricsForTopAndBottomAlign(*box, *line_box);
      for (PendingPositions& child : box->pending_descendants) {
        switch (child.vertical_align) {
          case EVerticalAlign::kTop:
            baseline_shift = child.metrics.ascent - max.ascent;
            break;
          case EVerticalAlign::kBottom:
            baseline_shift = max.descent - child.metrics.descent;
            break;
          case EVerticalAlign::kTextTop:
          case EVerticalAlign::kTextBottom:
            continue;
          default:
            NOTREACHED();
        }
        child.metrics.Move(baseline_shift);
        box->metrics.Unite(child.metrics);
        line_box->MoveInBlockDirection(baseline_shift, child.fragment_start,
                                       child.fragment_end);
      }
    }
    box->pending_descendants.clear();
  }

  const ComputedStyle& style = *box->style;
  EVerticalAlign vertical_align = style.VerticalAlign();
  if (!is_svg_text_ && vertical_align == EVerticalAlign::kBaseline)
    return kPositionNotPending;

  if (box->item && IsA<LayoutTextCombine>(box->item->GetLayoutObject()))
      [[unlikely]] {
    // Text content in text-combine-upright:all is layout in horizontally, so
    // we don't need to move text combine box.
    // See "text-combine-shrink-to-fit.html".
    return kPositionNotPending;
  }

  // Check if there are any fragments to move.
  unsigned fragment_end = line_box->size();
  if (box->fragment_start == fragment_end)
    return kPositionNotPending;

  // SVG <text> supports not |vertical-align| but |baseline-shift|.
  // https://drafts.csswg.org/css-inline/#propdef-vertical-align says
  // |vertical-align| is a shorthand property of |baseline-shift| and
  // |alignment-baseline|. However major browsers have never supported
  // |vertical-align| in SVG <text>. Also, the shift amount computation
  // for |baseline-shift| is not same as one for |vertical-align|.
  // For now we follow the legacy behavior. If we'd like to follow the
  // standard, first we should add a UseCounter for non-zero
  // |baseline-shift|.
  if (is_svg_text_) {
    switch (style.BaselineShiftType()) {
      case EBaselineShiftType::kLength: {
        const Length& length = style.BaselineShift();
        // ValueForLength() should be called with unscaled values.
        const float computed_font_size =
            box->font->GetFontDescription().ComputedPixelSize() /
            box->scaling_factor;
        baseline_shift =
            LayoutUnit(-ValueForLength(length, style, computed_font_size) *
                       box->scaling_factor);
        break;
      }
      case EBaselineShiftType::kSub:
        if (const auto* font_data = box->font->PrimaryFont()) {
          baseline_shift =
              LayoutUnit(font_data->GetFontMetrics().FloatHeight() / 2);
        }
        break;
      case EBaselineShiftType::kSuper:
        if (const auto* font_data = box->font->PrimaryFont()) {
          baseline_shift =
              LayoutUnit(-font_data->GetFontMetrics().FloatHeight() / 2);
        }
        break;
    }
    baseline_shift += ComputeAlignmentBaselineShift(box);
    if (!box->metrics.IsEmpty())
      box->metrics.Move(baseline_shift);
    line_box->MoveInBlockDirection(baseline_shift, box->fragment_start,
                                   fragment_end);
    return kPositionNotPending;
  }

  // 'vertical-align' aligns boxes relative to themselves, to their parent
  // boxes, or to the line box, depends on the value.
  // Because |box| is an item in |stack_|, |box[-1]| is its parent box.
  // If this box doesn't have a parent; i.e., this box is a line box,
  // 'vertical-align' has no effect.
  DCHECK(box >= stack_.data() && box < stack_.data() + stack_.size());
  if (box == stack_.data()) {
    return kPositionNotPending;
  }
  InlineBoxState& parent_box = box[-1];

  switch (vertical_align) {
    case EVerticalAlign::kSub:
      baseline_shift = parent_box.style->ComputedFontSizeAsFixed() / 5 + 1;
      break;
    case EVerticalAlign::kSuper:
      baseline_shift = -(parent_box.style->ComputedFontSizeAsFixed() / 3 + 1);
      break;
    case EVerticalAlign::kLength: {
      // 'Percentages: refer to the 'line-height' of the element itself'.
      // https://www.w3.org/TR/CSS22/visudet.html#propdef-vertical-align
      const Length& length = style.GetVerticalAlignLength();
      LayoutUnit line_height = length.HasPercent()
                                   ? style.ComputedLineHeightAsFixed()
                                   : box->text_metrics.LineHeight();
      baseline_shift = -ValueForLength(length, line_height);
      break;
    }
    case EVerticalAlign::kMiddle:
      baseline_shift = (box->metrics.ascent - box->metrics.descent) / 2;
      if (const SimpleFontData* parent_font_data =
              parent_box.style->GetFont().PrimaryFont()) {
        baseline_shift -= LayoutUnit::FromFloatRound(
            parent_font_data->GetFontMetrics().XHeight() / 2);
      }
      break;
    case EVerticalAlign::kBaselineMiddle:
      baseline_shift = (box->metrics.ascent - box->metrics.descent) / 2;
      break;
    case EVerticalAlign::kTop:
    case EVerticalAlign::kBottom: {
      // 'top' and 'bottom' require the layout size of the nearest ancestor that
      // has 'top' or 'bottom', or the line box if none.
      InlineBoxState* ancestor = &parent_box;
      for (; ancestor != stack_.data(); --ancestor) {
        if (ancestor->style->VerticalAlign() == EVerticalAlign::kTop ||
            ancestor->style->VerticalAlign() == EVerticalAlign::kBottom)
          break;
      }
      ancestor->pending_descendants.push_back(PendingPositions{
          box->fragment_start, fragment_end, box->metrics, vertical_align});
      return kPositionPending;
    }
    default:
      // Other values require the layout size of the parent box.
      parent_box.pending_descendants.push_back(PendingPositions{
          box->fragment_start, fragment_end, box->metrics, vertical_align});
      return kPositionPending;
  }
  if (!box->metrics.IsEmpty())
    box->metrics.Move(baseline_shift);
  line_box->MoveInBlockDirection(baseline_shift, box->fragment_start,
                                 fragment_end);
  return kPositionNotPending;
}

LayoutUnit InlineLayoutStateStack::ComputeAlignmentBaselineShift(
    const InlineBoxState* box) {
  LayoutUnit result;
  if (const auto* font_data = box->font->PrimaryFont()) {
    const FontMetrics& metrics = font_data->GetFontMetrics();
    result = metrics.FixedAscent(box->style->GetFontBaseline()) -
             metrics.FixedAscent(box->alignment_type);
  }

  if (box == stack_.data()) {
    return result;
  }
  if (const auto* font_data = box[-1].font->PrimaryFont()) {
    const FontMetrics& parent_metrics = font_data->GetFontMetrics();
    result -= parent_metrics.FixedAscent(box[-1].style->GetFontBaseline()) -
              parent_metrics.FixedAscent(box[-1].alignment_type);
  }

  return result;
}

FontHeight InlineLayoutStateStack::MetricsForTopAndBottomAlign(
    const InlineBoxState& box,
    const LogicalLineItems& line_box) const {
  DCHECK(!box.pending_descendants.empty());

  // |metrics| is the bounds of "aligned subtree", that is, bounds of
  // descendants that are not 'vertical-align: top' nor 'bottom'.
  // https://drafts.csswg.org/css2/visudet.html#propdef-vertical-align
  FontHeight metrics = box.metrics;

  // BoxData contains inline boxes to be created later. Take them into account.
  for (const BoxData& box_data : box_data_list_) {
    // Except when the box has `vertical-align: top` or `bottom`.
    DCHECK(box_data.item->Style());
    const ComputedStyle& style = *box_data.item->Style();
    EVerticalAlign vertical_align = style.VerticalAlign();
    if (vertical_align == EVerticalAlign::kTop ||
        vertical_align == EVerticalAlign::kBottom)
      continue;

    // |block_offset| is the top position when the baseline is at 0.
    const LogicalLineItem& placeholder = line_box[box_data.fragment_start];
    DCHECK(placeholder.IsPlaceholder());
    LayoutUnit box_ascent = -placeholder.rect.offset.block_offset;
    FontHeight box_metrics(box_ascent,
                           box_data.rect.size.block_size - box_ascent);
    // The top/bottom of inline boxes should not include their paddings.
    box_metrics.ascent -= box_data.padding.line_over;
    box_metrics.descent -= box_data.padding.line_under;
    // Include the line-height property. The inline box has the height of the
    // font metrics without the line-height included.
    FontHeight leading_space =
        CalculateLeadingSpace(style.ComputedLineHeightAsFixed(), box_metrics);
    box_metrics.AddLeading(leading_space);
    metrics.Unite(box_metrics);
  }

  // In quirks mode, metrics is empty if no content.
  if (metrics.IsEmpty())
    metrics = FontHeight();

  // If the height of a box that has 'vertical-align: top' or 'bottom' exceeds
  // the height of the "aligned subtree", align the edge to the "aligned
  // subtree" and extend the other edge.
  FontHeight max = metrics;
  for (const PendingPositions& child : box.pending_descendants) {
    if ((child.vertical_align == EVerticalAlign::kTop ||
         child.vertical_align == EVerticalAlign::kBottom) &&
        child.metrics.LineHeight() > max.LineHeight()) {
      if (child.vertical_align == EVerticalAlign::kTop) {
        max = FontHeight(metrics.ascent,
                         child.metrics.LineHeight() - metrics.ascent);
      } else if (child.vertical_align == EVerticalAlign::kBottom) {
        max = FontHeight(child.metrics.LineHeight() - metrics.descent,
                         metrics.descent);
      }
    }
  }
  return max;
}

LogicalRubyColumn& InlineLayoutStateStack::CreateRubyColumn() {
  ruby_column_list_.push_back(MakeGarbageCollected<LogicalRubyColumn>());
  return *ruby_column_list_.back();
}

#if DCHECK_IS_ON()
void InlineLayoutStateStack::CheckSame(
    const InlineLayoutStateStack& other) const {
  // At the beginning of each line, box_data_list_ should be empty.
  DCHECK_EQ(box_data_list_.size(), 0u);
  DCHECK_EQ(other.box_data_list_.size(), 0u);

  DCHECK_EQ(stack_.size(), other.stack_.size());
  for (unsigned i = 0; i < stack_.size(); i++) {
    stack_[i].CheckSame(other.stack_[i]);
  }
}

void InlineBoxState::CheckSame(const InlineBoxState& other) const {
  DCHECK_EQ(fragment_start, other.fragment_start);
  DCHECK_EQ(item, other.item);
  DCHECK_EQ(style, other.style);

  DCHECK_EQ(metrics, other.metrics);
  DCHECK_EQ(text_metrics, other.text_metrics);
  DCHECK_EQ(text_top, other.text_top);
  DCHECK_EQ(text_height, other.text_height);
  if (!text_metrics.IsEmpty()) {
    // |include_used_fonts| will be computed when computing |text_metrics|.
    DCHECK_EQ(include_used_fonts, other.include_used_fonts);
  }

  DCHECK_EQ(needs_box_fragment, other.needs_box_fragment);

  DCHECK_EQ(has_start_edge, other.has_start_edge);
  // |has_end_edge| may not match because it will be computed in |OnCloseTag|.

  DCHECK_EQ(margins, other.margins);
  DCHECK_EQ(borders, other.borders);
  DCHECK_EQ(padding, other.padding);

  // At the beginning of each line, box_data_list_pending_descendants should be
  // empty.
  DCHECK_EQ(pending_descendants.size(), 0u);
  DCHECK_EQ(other.pending_descendants.size(), 0u);
}
#endif

}  // namespace blink
```