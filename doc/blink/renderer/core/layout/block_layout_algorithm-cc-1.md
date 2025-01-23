Response:
The user wants to understand the functionality of the provided C++ code snippet from `block_layout_algorithm.cc`. This is part 2 of a 6-part code section. I need to:

1. **Summarize the main purpose of this code section.**
2. **Identify its relation to JavaScript, HTML, and CSS.**
3. **Illustrate logical reasoning with input/output examples (if applicable).**
4. **Point out common user or programming errors.**

**Code Analysis:**

This code primarily focuses on iterating through the children of a block-level element during the layout process. It handles different types of children (out-of-flow, floats, list markers, column spanners, regular inflow content) and determines how they should be laid out within the current fragment. It also deals with line clamping, breaks, and margin collapsing.

**Relation to Web Technologies:**

*   **HTML:** The code directly operates on the structure of the HTML document, represented by `Node()` and its children.
*   **CSS:**  The code heavily relies on CSS properties (e.g., `line-clamp`, `break-inside`, `float`, `display: none`) to determine layout behavior. `Style()` provides access to these properties.
*   **JavaScript:** While this code is in C++, its actions directly affect the visual rendering that JavaScript might interact with or manipulate. For instance, JavaScript might query the layout of elements whose positioning is determined by this code.

**Logical Reasoning (Examples):**

*   **Input (CSS):** `div { line-clamp: 3; }`
    **Processing:** The code in the `else if (Style().HasLineClamp())` block will be executed, calculating the number of lines to display.
*   **Input (HTML):** `<div><p style="float: left;">Float</p>Content</div>`
    **Processing:** The `else if (child.IsFloating())` block will be executed for the `<p>` element, handling its placement according to float rules.

**Common Errors:**

*   **CSS:** Incorrectly using `-webkit-line-clamp` without `-webkit-box-orient: vertical` and `display: -webkit-box`. The code has a check for this: `if (Style().WebkitLineClamp() != 0) { UseCounter::Count(...) }`.
*   **JavaScript:** Making assumptions about the precise pixel positions of elements before the layout process is complete, as this code is part of that process.
这段代码是 `blink/renderer/core/layout/block_layout_algorithm.cc` 文件的 **`Layout` 函数** 的一部分，它主要负责 **遍历和布局块级容器的子元素**。这是块级布局算法的核心部分，用于确定容器内每个子元素的位置和尺寸，并处理各种复杂的布局情况，例如浮动、溢出、分页符、列布局等。

**具体功能归纳如下:**

1. **处理行钳制 (Line Clamp):**
    *   检查并更新行钳制相关的数据，包括从 CSS 样式中读取行数限制，以及计算由于行钳制产生的偏移量。
    *   区分新的 CSS `line-clamp` 属性和旧的 `-webkit-line-clamp` 属性，并对旧属性的错误使用进行计数。
    *   当使用基于 BFC 偏移量的行钳制时，会考虑元素的 margin 来进行精确计算。

2. **处理分页符 (Break Tokens):**
    *   检查是否存在分页符，并根据分页符的状态（例如，是否强制分页、是否由列跨越元素引起）来调整布局行为，例如是否需要丢弃 margin。
    *   处理由前一页的整体溢出推送的情况。

3. **处理 margin 折叠 (Margin Collapsing):**
    *   判断在哪些情况下父子元素之间的 margin 不应该折叠，例如存在 border/padding、是新的格式化上下文或者正在从分页符处恢复布局。
    *   在满足条件时，会解析 BFC 块偏移 (BFC block offset)。

4. **处理 Quirks 模式下的容器:**
    *   如果当前容器处于 Quirks 模式，并且是 table cell 或 body 元素，会设置 margin strut 的模式，使其仅考虑非 Quirks 的 margin。

5. **迭代子元素:**
    *   使用 `BlockChildIterator` 遍历当前块级容器的所有子元素。
    *   针对 `display: contents` 的元素，会跳过其自身的布局。
    *   如果子元素的布局被 display-lock 阻止，则会跳过这些子元素的布局。

6. **处理不同类型的子元素:**
    *   **绝对定位元素 (Out-of-flow):** 调用 `HandleOutOfFlowPositioned` 进行处理。
    *   **浮动元素 (Float):** 调用 `HandleFloat` 进行处理。
    *   **列表标记 (List Marker):**  对于不占据整行的外部列表标记，会被忽略，因为它们已经在构造函数中被设置为 `container_builder_.UnpositionedListMarker`。占据整行的列表标记会被视为普通子元素。
    *   **列跨越元素 (Column Span All):**  当处于多列布局 (Column BFC) 中时，会检查是否需要结束当前分段器 (fragmentainer) 并中止，以便列布局算法处理列跨越元素。会建立 `ColumnSpannerPath` 来追踪列跨越元素的布局信息。
    *   **文本输入框占位符 (Text Control Placeholder):**  会将占位符子元素存储在 `placeholder_child` 变量中。
    *   **普通 In-flow 子元素:**
        *   如果存在需要提前分页的情况 (`early_break_`)，并且当前子元素是分页目标，则会执行分页并结束布局。
        *   如果子元素创建新的格式化上下文 (New Formatting Context)，则调用 `HandleNewFormattingContext` 进行处理。
        *   否则，调用 `HandleInflow` 处理 In-flow 子元素的布局。
        *   如果子元素内部发生分页 (`container_builder_.HasInflowChildBreakInside()`)，则会结束当前分段器的布局。

7. **处理文本输入框占位符:**
    *   在遍历完所有子元素后，如果存在占位符子元素，则调用 `HandleTextControlPlaceholder` 进行布局。

8. **标记已遍历所有子元素:**
    *   当所有子元素都处理完毕后，会设置 `container_builder_.SetHasSeenAllChildren()`，表示已经遍历了所有子元素。

9. **设置初始的 intrinsic block size:**
    *   将 intrinsic block size 初始化为内容边缘的偏移量 `content_edge`。

10. **调用 `FinishLayout` 完成布局:**
    *   最后，调用 `FinishLayout` 函数来完成剩余的布局步骤。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

*   **HTML:** 代码直接操作 HTML 元素，通过 `Node()` 获取当前容器的 HTML 节点，并通过 `Node().FirstChild()` 和 `child_iterator` 遍历其子元素。例如，如果 HTML 结构是 `<div><p>Hello</p><span>World</span></div>`，这段代码会遍历 `<p>` 和 `<span>` 元素。
*   **CSS:** 代码大量使用 CSS 样式属性来决定布局行为。
    *   **`line-clamp` / `-webkit-line-clamp`:**  决定了文本在溢出时是否需要被截断并显示省略号。例如，CSS `div { line-clamp: 2; overflow: hidden; }` 会使 `<div>` 中的文本最多显示两行。
    *   **`break-inside`:**  控制元素内部是否允许分页。例如，CSS `div { break-inside: avoid; }` 会尽量避免在 `<div>` 内部进行分页。
    *   **`float`:**  决定元素是否浮动及其浮动方向。例如，CSS `img { float: left; }` 会使图片向左浮动，周围的文本会环绕它。
    *   **`display: none` (通过 `Node().ChildLayoutBlockedByDisplayLock()` 判断):**  如果子元素设置了 `display: none`，那么这段代码会跳过对其的布局。
*   **JavaScript:** 虽然这段代码是 C++，但它生成的布局结果会被 JavaScript 所使用。例如，JavaScript 可以通过 `getBoundingClientRect()` 获取元素的位置和尺寸，而这些位置和尺寸正是由这段 C++ 代码计算出来的。又或者，JavaScript 可以动态修改元素的 CSS 属性（例如通过 `element.style.lineClamp = 3`），从而间接地影响这段 C++ 代码的执行逻辑。

**逻辑推理的假设输入与输出举例:**

**假设输入 (CSS):**

```css
.container {
  width: 200px;
}
.item {
  height: 50px;
  margin-bottom: 10px;
}
```

**假设输入 (HTML):**

```html
<div class="container">
  <div class="item">Item 1</div>
  <div class="item">Item 2</div>
</div>
```

**处理过程 (部分逻辑):**

1. `BlockLayoutAlgorithm` 开始处理 `.container` 元素的布局。
2. 遍历第一个子元素 `.item`。
3. `HandleInflow` 函数会被调用来布局 `.item`。
4. 计算 `.item` 的位置和尺寸，其高度为 50px，marginBottom 为 10px。
5. `previous_inflow_position.logical_block_offset` 会被更新为 50px + 10px = 60px。
6. 遍历第二个子元素 `.item`。
7. `HandleInflow` 函数会被调用来布局第二个 `.item`。
8. 计算第二个 `.item` 的位置和尺寸，其起始位置会基于前一个元素的偏移量，即 `previous_inflow_position.logical_block_offset` (60px)。
9. 第二个 `.item` 的起始位置大概会在 60px 的位置。

**假设输出 (简化):**

```
Item 1 的布局信息: { top: 0px, height: 50px }
Item 2 的布局信息: { top: 60px, height: 50px }
```

**用户或编程常见的使用错误举例:**

1. **CSS 中错误地使用了 `-webkit-line-clamp` 但没有设置 `-webkit-box-orient` 和 `display: -webkit-box`。** 这段代码中会通过 `UseCounter::Count` 来记录这种错误用法，提醒开发者正确使用。

    ```css
    /* 错误用法 */
    .text {
      -webkit-line-clamp: 3;
      overflow: hidden;
    }

    /* 正确用法 */
    .text {
      display: -webkit-box;
      -webkit-line-orient: vertical;
      -webkit-line-clamp: 3;
      overflow: hidden;
    }
    ```

2. **在 JavaScript 中过早地访问尚未完成布局的元素的位置和尺寸。** 由于布局是逐步进行的，如果在 JavaScript 执行时布局尚未完成，获取到的尺寸信息可能是不准确的。

3. **在 CSS 中设置了冲突的属性，导致布局行为不符合预期。** 例如，同时设置了 `float: left` 和 `display: flex` 在某些情况下可能会导致意想不到的布局结果。

**总结这段代码的功能:**

这段代码的主要功能是 **遍历和布局块级容器的子元素**，它根据 HTML 结构和 CSS 样式规则，确定每个子元素在容器内的位置和尺寸。它处理了行钳制、分页符、margin 折叠等复杂的布局情况，并为不同类型的子元素（如浮动元素、绝对定位元素、列跨越元素等）提供了相应的处理逻辑。这是浏览器引擎渲染网页内容的关键步骤。

### 提示词
```
这是目录为blink/renderer/core/layout/block_layout_algorithm.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
zes.max_size - BorderScrollbarPadding().block_end)
                  .ClampNegativeToZero();
        }
      } else {
        clamp_bfc_offset =
            (BorderScrollbarPadding().block_start + clamp_bfc_offset)
                .ClampNegativeToZero();
      }
      line_clamp_data_.UpdateClampOffsetFromStyle(
          clamp_bfc_offset, BorderScrollbarPadding().block_start);
    }
  } else if (Style().HasLineClamp()) {
    if (!line_clamp_data_.data.IsLineClampContext()) {
      line_clamp_data_.UpdateLinesFromStyle(Style().LineClamp());
    }
  } else {
    if (Style().WebkitLineClamp() != 0) {
      UseCounter::Count(Node().GetDocument(),
                        WebFeature::kWebkitLineClampWithoutWebkitBox);
    }

    // If we're clamping by BFC offset, we need to subtract the bottom bmp to
    // leave room for it. This doesn't apply if we're relaying out to fix the
    // offset, because that already accounts for the bmp.
    if (line_clamp_data_.data.state ==
        LineClampData::kMeasureLinesUntilBfcOffset) {
      MarginStrut end_margin_strut = constraint_space.LineClampEndMarginStrut();
      end_margin_strut.Append(
          ComputeMarginsForSelf(constraint_space, Style()).block_end,
          /* is_quirky */ false);

      // `constraint_space.LineClampEndMarginStrut().Sum()` is the margin
      // contribution from our ancestor boxes, which has already been taken
      // into account for the clamp BFC offset that we have. We only need to
      // add any additional margin contribution from this box's margin.
      line_clamp_data_.data.clamp_bfc_offset -=
          BorderScrollbarPadding().block_end +
          (end_margin_strut.Sum() -
           constraint_space.LineClampEndMarginStrut().Sum());

      // The presence of borders and padding blocks margin propagation.
      if (!BorderScrollbarPadding().block_end) {
        line_clamp_data_.end_margin_strut = end_margin_strut;
      }
    }
  }

  LayoutUnit content_edge = BorderScrollbarPadding().block_start;

  PreviousInflowPosition previous_inflow_position = {
      LayoutUnit(), constraint_space.GetMarginStrut(),
      is_resuming_ ? LayoutUnit() : container_builder_.Padding().block_start,
      /* self_collapsing_child_had_clearance */ false};

  if (GetBreakToken()) {
    if (IsBreakInside(GetBreakToken()) && !GetBreakToken()->IsForcedBreak() &&
        !GetBreakToken()->IsCausedByColumnSpanner()) {
      // If the block container is being resumed after an unforced break,
      // margins inside may be adjoining with the fragmentainer boundary.
      previous_inflow_position.margin_strut.discard_margins = true;
    }

    if (GetBreakToken()->MonolithicOverflow()) {
      // If we have been pushed by monolithic overflow that started on a
      // previous page, we'll behave as if there's a valid breakpoint before the
      // first child here, and that it has perfect break appeal. This isn't
      // always strictly correct (the monolithic content in question may have
      // break-after:avoid, for instance), but should be a reasonable approach,
      // unless we want to make a bigger effort.
      has_break_opportunity_before_next_child_ = true;
    }
  }

  // Do not collapse margins between parent and its child if:
  //
  // A: There is border/padding between them.
  // B: This is a new formatting context
  // C: We're resuming layout from a break token. Margin struts cannot pass from
  //    one fragment to another if they are generated by the same block; they
  //    must be dealt with at the first fragment.
  //
  // In all those cases we can and must resolve the BFC block offset now.
  if (content_edge || is_resuming_ ||
      constraint_space.IsNewFormattingContext()) {
    bool discard_subsequent_margins =
        previous_inflow_position.margin_strut.discard_margins && !content_edge;
    if (!ResolveBfcBlockOffset(&previous_inflow_position)) {
      // There should be no preceding content that depends on the BFC block
      // offset of a new formatting context block, and likewise when resuming
      // from a break token.
      DCHECK(!constraint_space.IsNewFormattingContext());
      DCHECK(!is_resuming_);
      return container_builder_.Abort(LayoutResult::kBfcBlockOffsetResolved);
    }
    // Move to the content edge. This is where the first child should be placed.
    previous_inflow_position.logical_block_offset = content_edge;

    // If we resolved the BFC block offset now, the margin strut has been
    // reset. If margins are to be discarded, and this box would otherwise have
    // adjoining margins between its own margin and those subsequent content,
    // we need to make sure subsequent content discard theirs.
    if (discard_subsequent_margins)
      previous_inflow_position.margin_strut.discard_margins = true;
  }

#if DCHECK_IS_ON()
  // If this is a new formatting context, we should definitely be at the origin
  // here. If we're resuming from a break token (for a block that doesn't
  // establish a new formatting context), that may not be the case,
  // though. There may e.g. be clearance involved, or inline-start margins.
  if (constraint_space.IsNewFormattingContext()) {
    DCHECK_EQ(*container_builder_.BfcBlockOffset(), LayoutUnit());
  }
  // If this is a new formatting context, or if we're resuming from a break
  // token, no margin strut must be lingering around at this point.
  if (constraint_space.IsNewFormattingContext() || is_resuming_) {
    DCHECK(constraint_space.GetMarginStrut().IsEmpty());
  }

  if (!container_builder_.BfcBlockOffset()) {
    // New formatting-contexts, and when we have a self-collapsing child
    // affected by clearance must already have their BFC block-offset resolved.
    DCHECK(!previous_inflow_position.self_collapsing_child_had_clearance);
    DCHECK(!constraint_space.IsNewFormattingContext());
  }
#endif

  // If this node is a quirky container, (we are in quirks mode and either a
  // table cell or body), we set our margin strut to a mode where it only
  // considers non-quirky margins. E.g.
  // <body>
  //   <p></p>
  //   <div style="margin-top: 10px"></div>
  //   <h1>Hello</h1>
  // </body>
  // In the above example <p>'s & <h1>'s margins are ignored as they are
  // quirky, and we only consider <div>'s 10px margin.
  if (node_.IsQuirkyContainer())
    previous_inflow_position.margin_strut.is_quirky_container_start = true;

  // Try to reuse line box fragments from cached fragments if possible.
  // When possible, this adds fragments to |container_builder_| and update
  // |previous_inflow_position| and |BreakToken()|.
  const InlineBreakToken* previous_inline_break_token = nullptr;

  BlockChildIterator child_iterator(Node().FirstChild(), GetBreakToken());

  // If this layout is blocked by a display-lock, then we pretend this node has
  // no children and that there are no break tokens. Due to this, we skip layout
  // on these children.
  if (Node().ChildLayoutBlockedByDisplayLock())
    child_iterator = BlockChildIterator(BlockNode(nullptr), nullptr);

  BlockNode placeholder_child(nullptr);
  BlockChildIterator::Entry entry;
  for (entry = child_iterator.NextChild(); LayoutInputNode child = entry.node;
       entry = child_iterator.NextChild(previous_inline_break_token)) {
    const BreakToken* child_break_token = entry.token;

    if (child.IsOutOfFlowPositioned()) {
      // Out-of-flow fragmentation is a special step that takes place after
      // regular layout, so we should never resume anything here. However, we
      // may have break-before tokens, when a column spanner is directly
      // followed by an OOF.
      DCHECK(!child_break_token ||
             (child_break_token->IsBlockType() &&
              To<BlockBreakToken>(child_break_token)->IsBreakBefore()));
      HandleOutOfFlowPositioned(previous_inflow_position, To<BlockNode>(child));
    } else if (child.IsFloating()) {
      HandleFloat(previous_inflow_position, To<BlockNode>(child),
                  To<BlockBreakToken>(child_break_token));
    } else if (child.IsListMarker() && !child.ListMarkerOccupiesWholeLine()) {
      // Ignore outside list markers because they are already set to
      // |container_builder_.UnpositionedListMarker| in the constructor, unless
      // |ListMarkerOccupiesWholeLine|, which is handled like a regular child.
    } else if (child.IsColumnSpanAll() && constraint_space.IsInColumnBfc() &&
               constraint_space.HasBlockFragmentation()) {
      // The child is a column spanner. If we have no breaks inside (in parallel
      // flows), we now need to finish this fragmentainer, then abort and let
      // the column layout algorithm handle the spanner as a child. The
      // HasBlockFragmentation() check above may seem redundant, but this is
      // important if we're overflowing a clipped container. In such cases, we
      // won't treat the spanner as one, since we shouldn't insert any breaks in
      // that mode.
      DCHECK(!container_builder_.DidBreakSelf());
      DCHECK(!container_builder_.FoundColumnSpanner());
      DCHECK(!IsBreakInside(To<BlockBreakToken>(child_break_token)));

      if (constraint_space.IsPastBreak() ||
          container_builder_.HasInsertedChildBreak()) {
        // Something broke inside (typically in a parallel flow, or we wouldn't
        // be here). Before we can handle the spanner, we need to finish what
        // comes before it.
        container_builder_.AddBreakBeforeChild(child, kBreakAppealPerfect,
                                               /* is_forced_break */ true);

        // We're not ready to go back and lay out the spanner yet (see above),
        // so we don't set a spanner path, but since we did find a spanner, make
        // a note of it. This will make sure that we resolve our BFC block-
        // offset, so that we don't incorrectly appear to be self-collapsing.
        container_builder_.SetHasColumnSpanner(true);
        break;
      }

      // Establish a column spanner path. The innermost node will be the spanner
      // itself, wrapped inside the container handled by this layout algorithm.
      const auto* child_spanner_path =
          MakeGarbageCollected<ColumnSpannerPath>(To<BlockNode>(child));
      const auto* container_spanner_path =
          MakeGarbageCollected<ColumnSpannerPath>(Node(), child_spanner_path);
      container_builder_.SetColumnSpannerPath(container_spanner_path);

      // In order to properly collapse column spanner margins, we need to know
      // if the column spanner's parent was empty, for example, in the case that
      // the only child content of the parent since the last spanner is an OOF
      // that will get positioned outside the multicol.
      container_builder_.SetIsEmptySpannerParent(
          container_builder_.Children().empty() && is_resuming_);
      // After the spanner(s), we are going to resume inside this block. If
      // there's a subsequent sibling that's not a spanner, we're resume right
      // in front of that one. Otherwise we'll just resume after all the
      // children.
      for (entry = child_iterator.NextChild();
           LayoutInputNode sibling = entry.node;
           entry = child_iterator.NextChild()) {
        DCHECK(!entry.token);
        if (sibling.IsColumnSpanAll())
          continue;
        container_builder_.AddBreakBeforeChild(sibling, kBreakAppealPerfect,
                                               /* is_forced_break */ true);
        break;
      }
      break;
    } else if (child.IsTextControlPlaceholder()) {
      placeholder_child = To<BlockNode>(child);
    } else {
      // If this is the child we had previously determined to break before, do
      // so now and finish layout.
      if (early_break_ && IsEarlyBreakTarget(*early_break_, container_builder_,
                                             child)) [[unlikely]] {
        if (!ResolveBfcBlockOffset(&previous_inflow_position)) {
          // However, the predetermined breakpoint may be exactly where the BFC
          // block-offset gets resolved. If that hasn't yet happened, we need to
          // do that first and re-layout at the right BFC block-offset, and THEN
          // break.
          return container_builder_.Abort(
              LayoutResult::kBfcBlockOffsetResolved);
        }
        container_builder_.AddBreakBeforeChild(child, kBreakAppealPerfect,
                                               /* is_forced_break */ false);
        ConsumeRemainingFragmentainerSpace(&previous_inflow_position);
        break;
      }

      LayoutResult::EStatus status;
      if (child.CreatesNewFormattingContext()) {
        status = HandleNewFormattingContext(
            child, To<BlockBreakToken>(child_break_token),
            &previous_inflow_position);
        previous_inline_break_token = nullptr;
      } else {
        status = HandleInflow(
            child, child_break_token, &previous_inflow_position,
            inline_child_layout_context, &previous_inline_break_token);
      }

      if (status != LayoutResult::kSuccess) {
        // We need to abort the layout. No fragment will be generated.
        return container_builder_.Abort(status);
      }
      if (constraint_space.HasBlockFragmentation()) {
        // A child break in a parallel flow doesn't affect whether we should
        // break here or not.
        if (container_builder_.HasInflowChildBreakInside()) {
          // But if the break happened in the same flow, we'll now just finish
          // layout of the fragment. No more siblings should be processed.
          break;
        }
      }
    }
  }

#if DCHECK_IS_ON()
  // Assert that we have made actual progress. Breaking before we're done with
  // all parallel flows from incoming break tokens means that we'll never get
  // the opportunity to handle them again. We don't repropagate unhandled
  // incoming break tokens, and there should be no need to.
  if (auto* inline_token = DynamicTo<InlineBreakToken>(entry.token)) {
    DCHECK(!inline_token->IsInParallelBlockFlow());
  } else if (auto* block_token = DynamicTo<BlockBreakToken>(entry.token)) {
    // A column spanner forces all content preceding it to stay in the same
    // flow, so we can (and must) skip the check. Even if IsAtBlockEnd() is true
    // in such cases, it doesn't mean that a parallel flow is established.
    if (!container_builder_.FoundColumnSpanner() &&
        !container_builder_.ShouldForceSameFragmentationFlow()) {
      DCHECK(!block_token->IsAtBlockEnd());
    }
  }
#endif

  if (placeholder_child) {
    previous_inflow_position.logical_block_offset =
        HandleTextControlPlaceholder(placeholder_child,
                                     previous_inflow_position);
  }

  if (!child_iterator.NextChild(previous_inline_break_token).node) {
    // We've gone through all the children. This doesn't necessarily mean that
    // we're done fragmenting, as there may be parallel flows [1] (visible
    // overflow) still needing more space than what the current fragmentainer
    // can provide. It does mean, though, that, for any future fragmentainers,
    // we'll just be looking at the break tokens, if any, and *not* start laying
    // out any nodes from scratch, since we have started/finished all the
    // children, or at least created break tokens for them.
    //
    // [1] https://drafts.csswg.org/css-break/#parallel-flows
    container_builder_.SetHasSeenAllChildren();
  }

  // The intrinsic block size is not allowed to be less than the content edge
  // offset, as that could give us a negative content box size.
  intrinsic_block_size_ = content_edge;

  // To save space of the stack when we recurse into children, the rest of this
  // function is continued within |FinishLayout|. However it should be read as
  // one function.
  return FinishLayout(&previous_inflow_position, inline_child_layout_context);
}

const LayoutResult* BlockLayoutAlgorithm::FinishLayout(
    PreviousInflowPosition* previous_inflow_position,
    InlineChildLayoutContext* inline_child_layout_context) {
  const auto& constraint_space = GetConstraintSpace();
  if (constraint_space.IsNewFormattingContext() &&
      line_clamp_data_.ShouldRelayoutWithNoForcedTruncate()) [[unlikely]] {
    // Truncation of the last line was forced, but there are no lines after the
    // truncated line. Rerun layout without forcing truncation. This is only
    // done if line-clamp was specified on the element as the element containing
    // the node may have subsequent lines. If there aren't, the containing
    // element will relayout.
    return container_builder_.Abort(LayoutResult::kNeedsLineClampRelayout);
  }

  if (ShouldTextBoxTrimEnd() && last_non_empty_inflow_child_ &&
      !line_clamp_data_.previous_inflow_position_when_clamped.has_value())
      [[unlikely]] {
    // The `text-box-trim: trim-end` should apply to the last inflow child, but
    // which child this was isn't always something we can tell up-front, e.g. if
    // the last formatted line is inside a block-in-inline, and we moved past it
    // with no trimming.
    // We ignore this if we have line-clamped, because the trim-end would have
    // applied to the last line before clamp regardless.
    return container_builder_.Abort(LayoutResult::kTextBoxTrimEndDidNotApply);
  }

  // With CSSLineClamp enabled, if we line-clamped inside this box, its size
  // must be set exactly as if there were no layout boxes after the clamp point.
  // We therefore use the previous inflow position that we saved at the clamp
  // point.
  if (RuntimeEnabledFeatures::CSSLineClampEnabled() &&
      line_clamp_data_.previous_inflow_position_when_clamped.has_value())
      [[unlikely]] {
    previous_inflow_position =
        &*line_clamp_data_.previous_inflow_position_when_clamped;
  }

  LogicalSize border_box_size = container_builder_.InitialBorderBoxSize();
  MarginStrut end_margin_strut = previous_inflow_position->margin_strut;

  // Add line height for empty content editable or button with empty label, e.g.
  // <div contenteditable></div>, <input type="button" value="">
  if (container_builder_.HasSeenAllChildren() &&
      HasLineEvenIfEmpty(Node().GetLayoutBox())) {
    intrinsic_block_size_ = std::max(
        intrinsic_block_size_, BorderScrollbarPadding().block_start +
                                   Node().EmptyLineBlockSize(GetBreakToken()));
    if (container_builder_.IsInitialColumnBalancingPass()) {
      container_builder_.PropagateTallestUnbreakableBlockSize(
          intrinsic_block_size_);
    }
    // Test [1][2] require baseline offset for empty editable.
    // [1] css3/flexbox/baseline-for-empty-line.html
    // [2] inline-block/contenteditable-baseline.html
    const LayoutBlock* const layout_block =
        To<LayoutBlock>(Node().GetLayoutBox());
    if (auto baseline_offset = layout_block->BaselineForEmptyLine()) {
      container_builder_.SetBaselines(*baseline_offset);
    }
  }

  // Collapse annotation overflow and padding.
  // logical_block_offset already contains block-end annotation overflow.
  // However, if the container has non-zero block-end padding, the annotation
  // can extend on the padding. So we decrease logical_block_offset by
  // shareable part of the annotation overflow and the padding.
  if (previous_inflow_position->block_end_annotation_space < LayoutUnit()) {
    const LayoutUnit annotation_overflow =
        -previous_inflow_position->block_end_annotation_space;
    previous_inflow_position->logical_block_offset -=
        std::min(container_builder_.Padding().block_end, annotation_overflow);
  }

  // If line clamping occurred, and we're using the legacy behavior, the
  // intrinsic block-size comes from the intrinsic block-size at the time of the
  // clamp, without taking margins, clearance, etc. into account.
  if (!RuntimeEnabledFeatures::CSSLineClampEnabled() &&
      line_clamp_data_.previous_inflow_position_when_clamped) {
    DCHECK(container_builder_.BfcBlockOffset());
    intrinsic_block_size_ =
        line_clamp_data_.previous_inflow_position_when_clamped
            ->logical_block_offset +
        BorderScrollbarPadding().block_end;
    end_margin_strut = MarginStrut();
  } else if (BorderScrollbarPadding().block_end ||
             previous_inflow_position->self_collapsing_child_had_clearance ||
             constraint_space.IsNewFormattingContext()) {
    // The end margin strut of an in-flow fragment contributes to the size of
    // the current fragment if:
    //  - There is block-end border/scrollbar/padding.
    //  - There was a self-collapsing child affected by clearance.
    //  - We are a new formatting context.
    // Additionally this fragment produces no end margin strut.

    // If the current layout is a new formatting context, we need to encapsulate
    // all of our floats, except for those that were hidden because of
    // line-clamp.
    if (constraint_space.IsNewFormattingContext()) {
      LayoutUnit clearance =
          GetExclusionSpace().NonHiddenClearanceOffsetIncludingInitialLetter();
#ifdef DCHECK_ALWAYS_ON
      if (!RuntimeEnabledFeatures::CSSLineClampEnabled() ||
          !line_clamp_data_.previous_inflow_position_when_clamped) {
        DCHECK_EQ(clearance,
                  GetExclusionSpace().ClearanceOffsetIncludingInitialLetter(
                      EClear::kBoth));
      }
#endif
      intrinsic_block_size_ = std::max(intrinsic_block_size_, clearance);
    }

    if (!container_builder_.BfcBlockOffset()) {
      // If we have collapsed through the block start and all children (if any),
      // now is the time to determine the BFC block offset, because finally we
      // have found something solid to hang on to (like clearance or a bottom
      // border, for instance). If we're a new formatting context, though, we
      // shouldn't be here, because then the offset should already have been
      // determined.
      DCHECK(!constraint_space.IsNewFormattingContext());
      if (!ResolveBfcBlockOffset(previous_inflow_position)) {
        return container_builder_.Abort(LayoutResult::kBfcBlockOffsetResolved);
      }
      DCHECK(container_builder_.BfcBlockOffset());
    } else {
      // If we are a quirky container, we ignore any quirky margins and just
      // consider normal margins to extend our size.  Other UAs perform this
      // calculation differently, e.g. by just ignoring the *last* quirky
      // margin.
      LayoutUnit margin_strut_sum = node_.IsQuirkyContainer()
                                        ? end_margin_strut.QuirkyContainerSum()
                                        : end_margin_strut.Sum();

      if (constraint_space.HasKnownFragmentainerBlockSize()) {
        LayoutUnit new_margin_strut_sum = AdjustedMarginAfterFinalChildFragment(
            container_builder_, previous_inflow_position->logical_block_offset,
            margin_strut_sum);
        if (new_margin_strut_sum != margin_strut_sum) {
          container_builder_.SetIsTruncatedByFragmentationLine();
          margin_strut_sum = new_margin_strut_sum;
        }
      }

      // The trailing margin strut will be part of our intrinsic block size, but
      // only if there is something that separates the end margin strut from the
      // input margin strut (typically child content, block start
      // border/padding, or this being a new BFC). If the margin strut from a
      // previous sibling or ancestor managed to collapse through all our
      // children (if any at all, that is), it means that the resulting end
      // margin strut actually pushes us down, and it should obviously not be
      // doubly accounted for as our block size.
      intrinsic_block_size_ = std::max(
          intrinsic_block_size_,
          previous_inflow_position->logical_block_offset + margin_strut_sum);
    }

    if (!ShouldIncludeBlockEndBorderPadding(container_builder_)) {
      // The block-end edge isn't in this fragment. We either haven't got there
      // yet, or we're past it (and are overflowing). So don't add trailing
      // border/padding.
      container_builder_.ClearBorderScrollbarPaddingBlockEnd();
    }
    intrinsic_block_size_ += BorderScrollbarPadding().block_end;
    end_margin_strut = MarginStrut();
  } else {
    // Update our intrinsic block size to be just past the block-end border edge
    // of the last in-flow child. The pending margin is to be propagated to our
    // container, so ignore it.
    intrinsic_block_size_ = std::max(
        intrinsic_block_size_, previous_inflow_position->logical_block_offset);
  }

  LayoutUnit unconstrained_intrinsic_block_size = intrinsic_block_size_;
  intrinsic_block_size_ = ClampIntrinsicBlockSize(
      constraint_space, Node(), GetBreakToken(), BorderScrollbarPadding(),
      intrinsic_block_size_,
      CalculateQuirkyBodyMarginBlockSum(end_margin_strut));

  // In order to calculate the block-size for the fragment, we need to compare
  // the combined intrinsic block-size of all fragments to e.g. specified
  // block-size. We'll skip this part if this is a fragmentainer.
  // Fragmentainers never have a specified block-size anyway, but, more
  // importantly, adding consumed block-size, and then subtracting it again
  // later (when setting the final fragment size) would produce incorrect
  // results if the sum becomes "infinity", i.e. LayoutUnit::Max(). Skipping
  // this will allow the total block-size of all the fragmentainers to become
  // greater than LayoutUnit::Max(). This is important for column balancing, or
  // we'd fail to finish very tall child content properly, ending up with too
  // many fragmentainers, since the fragmentainers produced would be too short
  // to fit as much as necessary. Basically: don't mess up (clamp) the measument
  // we've already done.
  LayoutUnit previously_consumed_block_size;
  if (GetBreakToken() && !container_builder_.IsFragmentainerBoxType())
      [[unlikely]] {
    previously_consumed_block_size = GetBreakToken()->ConsumedBlockSize();
  }

  // Recompute the block-axis size now that we know our content size.
  border_box_size.block_size = ComputeBlockSizeForFragment(
      constraint_space, Node(), BorderPadding(),
      previously_consumed_block_size + intrinsic_block_size_,
      border_box_size.inline_size);
  container_builder_.SetFragmentsTotalBlockSize(border_box_size.block_size);

  // If our BFC block-offset is still unknown, we check:
  //  - If we have a non-zero block-size (margins don't collapse through us).
  //  - If we have a break token. (Even if we are self-collapsing we position
  //    ourselves at the very start of the fragmentainer).
  //  - We got interrupted by a column spanner.
  if (!container_builder_.BfcBlockOffset() &&
      (border_box_size.block_size || GetBreakToken() ||
       container_builder_.FoundColumnSpanner())) {
    if (!ResolveBfcBlockOffset(previous_inflow_position))
      return container_builder_.Abort(LayoutResult::kBfcBlockOffsetResolved);
    DCHECK(container_builder_.BfcBlockOffset());
  }

  if (container_builder_.BfcBlockOffset()) {
    // Do not collapse margins between the last in-flow child and bottom margin
    // of its parent if:
    //  - The block-size differs from the intrinsic size.
    //  - The parent has a definite initial block-size.
    const LayoutUnit initial_block_size = ComputeInitialBlockSizeForFragment(
        constraint_space, Node(), BorderPadding(), kIndefiniteSize,
        border_box_size.inline_size);
    if (border_box_size.block_size != intrinsic_block_size_ ||
        initial_block_size != kIndefiniteSize) {
      end_margin_strut = MarginStrut();
    }
  }

  // List markers should have been positioned if we had line boxes, or boxes
  // that have line boxes. If there were no line boxes, position without line
  // boxes.
  if (container_builder_.GetUnpositionedListMarker() &&
      ShouldPlaceUnpositionedListMarker() &&
      // If the list-item is block-fragmented, leave it unpositioned and expect
      // following fragments have a line box.
      !container_builder_.HasInflowChildBreakInside()) {
    if (!PositionListMarkerWithoutLineBoxes(previous_inflow_position))
      return container_builder_.Abort(LayoutResult::kBfcBlockOffsetResolved);
  }

  container_builder_.SetEndMarginStrut(end_margin_strut);
  container_builder_.SetIntrinsicBlockSize(intrinsic_block_size_);

  if (container_builder_.BfcBlockOffset()) {
    // If we know our BFC block-offset we should have correctly placed all
    // adjoining objects, and shouldn't propagate this information to siblings.
    container_builder_.ResetAdjoiningObjectTypes();
  } else {
    // If we don't know our BFC block-offset yet, we know that for
    // margin-collapsing purposes we are self-collapsing.
    container_builder_.SetIsSelfCollapsing();

    // If we've been forced at a particular BFC block-offset, (either from
    // clearance past adjoining floats, or a re-layout), we can safely set our
    // BFC block-offset now.
    if (constraint_space.ForcedBfcBlockOffset()) {
      container_builder_.SetBfcBlockOffset(
          *constraint_space.ForcedBfcBlockOffset());

      // Also make sure that this is treated as a valid class C breakpoint (if
      // it is one).
      if (constraint_space.IsPushedByFloats()) {
        container_builder_.SetIsPushedByFloats();
      }
    }
  }

  if (InvolvedInBlockFragmentation(container_builder_)) [[unlikely]] {
    BreakStatus status = FinalizeForFragmentation();
    if (status != BreakStatus::kContinue) {
      if (status == BreakStatus::kNeedsEarlierBreak) {
        return container_builder_.Abort(LayoutResult::kNeedsEarlierBreak);
      }
      DCHECK_EQ(status, BreakStatus::kDisableFragmentation);
      return container_builder_.Abort(LayoutResult::kDisableFragmentation);
    }

    // Read the intrinsic block-size back, since it may have been reduced due to
    // fragmentation.
    intrinsic_block_size_ = container_builder_.IntrinsicBlockSize();
  } else {
#if DCHECK_IS_ON()
  // If we're not participating in a fragmentation context, no block
  // fragmentation related fields should have been set.
  container_builder_.CheckNoBlockFragmentation();
#endif
  }

  // At this point, perform any final table-cell adjustments needed.
  if (constraint_space.IsTableCell()) {
    FinalizeTableCellLayout(intrinsic_block_size_, &container_builder_);
  } else {
    AlignBlockContent(Style(), GetBreakToken(),
                      unconstrained_intrinsic_block_size, container_builder_);
  }

  container_builder_.HandleOofsAndSpecialDescendants();

  if (constraint_space.GetBaselineAlgorithmType() ==
      BaselineAlgorithmType::kInlineBlock) {
    container_builder_.SetUseLastBaselineForInlineBaseline();
  }

  // An exclusion space is confined to nodes within the same formatting context.
  if (constraint_space.IsNewFormattingContext()) {
    container_builder_.SetExclusionSpace(ExclusionSpace());
  } else {
    container_builder_.SetLinesUntilClamp(
        line_clamp_data_.data.LinesUntilClamp(/*show_measured_lines*/ true));
  }

  if (constraint_space.UseFirstLineStyle()) {
    container_builder_.SetStyleVariant(StyleVariant::kFirstLine);
  }

  return container_builder_.ToBoxFragment();
}

bool BlockLayoutAlgorithm::TryReuseFragmentsFromCache(
    InlineNode inline_node,
    PreviousInflowPosition* previous_inflow_position,
    const InlineBreakToken** inline_break_token_out) {
  DCHECK(previous_result_);

  // No lines are reusable if this block uses paragraph-level line breakers such
  // as `ParagraphLineBreaker` or `ScoreLineBreaker`.
  if (!Style().ShouldWrapLineGreedy()) {
    return false;
  }

  const auto& previous_fragment =
      To<PhysicalBoxFragment>(previous_result_->GetPhysicalFragment());
  const FragmentItems* previous_items = previous_fragment.Items();
  DCHECK(previous_items);

  // Find reusable lines. Fail if no items are reusable.
  // TODO(kojii): |DirtyLinesFromNeedsLayout| is needed only once for a
  // |LayoutBlockFlow|, not for every fragment.
  FragmentItems::DirtyLinesFromNeedsLayout(*inline_node.GetLayoutBlockFlow());
  const FragmentItem* end_item =
      previous_items->EndOfReusableItems(previous_fragment);
  DCHECK(end_item);
  if (!end_item || end_item == &previous_items->front())
    return false;

  wtf_size_t max_lines = 0;
  if (std::optional<int> lines_until_clamp =
          line_clamp_data_.LinesUntilClamp()) {
    // There is an additional logic for the last clamped line. Reuse only up to
    // before that to use the same logic.
    if (*lines_until_clamp <= 1) {
      return false;
    }
    max_lines = *lines_until_clamp - 1;
  }

  const auto& children = container_builder_.Children();
  const
```