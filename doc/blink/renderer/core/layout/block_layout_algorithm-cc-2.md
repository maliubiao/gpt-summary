Response:
My thinking process to arrive at the summary of `block_layout_algorithm.cc` goes through these stages:

1. **Understanding the Context:** I start by acknowledging the provided information: the file path (`blink/renderer/core/layout/block_layout_algorithm.cc`) within the Chromium Blink engine. This immediately tells me the file is responsible for the layout of block-level elements. The "cc" extension indicates C++ code.

2. **Deconstructing the Code Snippets:** I carefully examine the code snippets provided. I look for keywords, function names, and patterns that reveal the file's operations. Key observations from the snippets:
    * **`AddPreviousItems`:** Deals with handling previously laid-out content, likely for multi-fragment scenarios (like pagination or columns).
    * **`ResolveBfcBlockOffset`:**  Indicates the file is involved in resolving the block offset of the Block Formatting Context (BFC). This is crucial for positioning elements correctly.
    * **`HandleOutOfFlowPositioned`, `HandleFloat`:**  These function names clearly point to the handling of absolutely positioned and floated elements, respectively. These are key aspects of CSS layout.
    * **`HandleNewFormattingContext`:**  Suggests the file manages the creation and layout of elements that establish new formatting contexts (like flexbox or grid containers).
    * **`LayoutNewFormattingContext`:**  Likely the actual function performing the layout of these new formatting contexts.
    * **`HandleInflow`:** Deals with the layout of regular, in-flow block and inline elements.
    * **`FragmentItemsBuilder`, `container_builder_`:** These suggest the file builds and manages fragments (parts of the layout) and the overall container's layout information.
    * **`ConstraintSpace`, `ExclusionSpace`:**  These terms relate to the constraints under which layout occurs (available space, fragmentation) and the areas occupied by floats or other exclusions.
    * **`LineClampData`:** Indicates support for CSS's `-webkit-line-clamp` property.
    * **`BreakToken`:** Points to the handling of page breaks or column breaks.

3. **Identifying Core Responsibilities:** Based on the code snippets and my understanding of CSS layout, I start to identify the core responsibilities of this file:
    * **Block-level layout:**  The file name and the presence of functions like `HandleInflow` and `HandleNewFormattingContext` strongly suggest this.
    * **Handling different element types:** The distinct `Handle` functions for out-of-flow, floated, and in-flow elements confirm this.
    * **BFC management:** `ResolveBfcBlockOffset` is a key indicator.
    * **Fragmentation:** The use of `BreakToken` and discussions of multi-fragment scenarios are significant.
    * **Exclusion handling:**  The `ExclusionSpace` and the logic within `HandleFloat` and `HandleNewFormattingContext` are evidence.
    * **Line clamping:**  The `LineClampData` structure directly points to this functionality.

4. **Connecting to Web Technologies (HTML, CSS, JavaScript):** I then consider how these responsibilities relate to the core web technologies:
    * **HTML:** The layout algorithms determine how the structure defined in HTML is rendered visually.
    * **CSS:** The file directly implements CSS layout rules, like positioning (absolute, fixed, relative), floats, margins, padding, and line clamping. The way it handles `ConstraintSpace` reflects the influence of CSS properties on available space. The handling of breaks relates to CSS break properties.
    * **JavaScript:** While this C++ file doesn't directly *execute* JavaScript, its output (the computed layout) is used by the rendering engine to display the web page, including elements manipulated by JavaScript. If JavaScript changes the DOM or CSS, this layout algorithm will be re-run.

5. **Inferring Logic and Scenarios:** I try to infer the underlying logic and consider potential scenarios:
    * **Multi-fragment layout:** The handling of `previous_fragment` and `previous_items` suggests it can lay out content across multiple pages or columns.
    * **Float interaction:** The complex logic in `HandleFloat` and `HandleNewFormattingContext` around `ExclusionSpace` illustrates how floats influence the positioning of other elements.
    * **Margin collapsing:** The mentions of `MarginStrut` suggest the file deals with CSS margin collapsing rules.
    * **Line clamping:** The `LineClampData` and its update logic point to how the engine limits the number of visible lines of text.

6. **Identifying Potential Errors:** Based on my understanding of layout complexities, I consider common errors:
    * **Incorrect float clearing:** Misunderstanding how to clear floats can lead to layout issues.
    * **Conflicting positioning:** Using absolute positioning without careful consideration can cause elements to overlap unexpectedly.
    * **Incorrect use of line-clamp:**  Applying line clamp to elements where it doesn't make sense or not providing sufficient fallback content.

7. **Structuring the Summary:** Finally, I organize my findings into a clear and concise summary, covering the key functionalities and their relationships to web technologies, along with examples and potential errors. I ensure the summary directly addresses the prompt's requirements. I also pay attention to the "Part 3 of 6" instruction and frame the summary as an overview of the file's main purpose.

By following these steps, I can effectively analyze the code snippets and generate a comprehensive summary of the `block_layout_algorithm.cc` file's role in the Chromium Blink rendering engine.
这是 `blink/renderer/core/layout/block_layout_algorithm.cc` 文件代码片段的第三部分，它主要关注于处理块级盒子的布局，特别是涉及到以下几个关键方面：

**归纳其功能:**

总的来说，这段代码片段的核心功能是**在块级布局过程中，处理和放置各种类型的子元素，并维护布局状态，以便后续的布局操作能够正确进行。**  它负责将子元素添加到布局结果中，并考虑了分页、浮动、绝对定位以及新格式化上下文等因素。

**具体功能分解和与 Web 技术的关系:**

1. **处理之前的布局片段 (`AddPreviousItems`):**
   - **功能:** 当进行分片布局（例如，在分页或多列布局中）时，此函数负责将之前布局片段中的项目添加到当前片段中。它会考虑最大行数限制 (`max_lines`)，并更新行数计数器。
   - **与 Web 技术的关系:**
     - **CSS:**  与 `break-before`, `break-after`, `break-inside` 等分页属性相关。当一个块元素由于分页符被分割成多个片段时，这个函数确保之前的片段内容能够正确延续到当前片段。
     - **CSS:** 与 `-webkit-line-clamp` 属性相关。如果设置了最大行数，此函数会追踪剩余可用的行数。
   - **逻辑推理（假设输入与输出）:**
     - **假设输入:** `previous_fragment` 代表前一个布局片段的信息， `previous_items` 是前一个片段中的布局项列表， `max_lines` 是当前片段的最大行数限制。
     - **预期输出:** 如果成功，新的布局项会被添加到 `container_builder_` 中，`result.line_count` 会更新已添加的行数，`previous_inflow_position` 的 `logical_block_offset` 会增加已使用的块大小。
   - **用户或编程常见的使用错误:**
     - **错误地配置分页属性:**  例如，在一个不应该分页的元素上设置了 `break-after: always;`，可能会导致意外的布局中断。
     - **`-webkit-line-clamp` 使用不当:**  例如，没有设置 `-webkit-box-orient: vertical;` 和 `display: -webkit-box;`，导致 `-webkit-line-clamp` 无效。

2. **解析 BFC 块偏移 (`ResolveBfcBlockOffset`):**
   - **功能:** 确定当前块格式化上下文 (BFC) 的块起始偏移量。这对于正确放置 BFC 内的元素至关重要。
   - **与 Web 技术的关系:**
     - **CSS:**  BFC 是 CSS 布局的核心概念。它影响着块级盒子的布局和相互作用，包括外边距折叠、浮动元素的包含等。
   - **逻辑推理:**
     - **假设输入:** `previous_inflow_position` 提供之前的流入位置信息。
     - **预期输出:** `container_builder_.BfcBlockOffset()` 将被设置为一个有效的值。

3. **处理绝对定位元素 (`HandleOutOfFlowPositioned`):**
   - **功能:**  负责放置绝对定位（`position: absolute` 或 `position: fixed`）的子元素。它会计算静态位置，并考虑外边距和浮动元素的影响。
   - **与 Web 技术的关系:**
     - **CSS:**  直接对应于 `position: absolute` 和 `position: fixed` 属性。
   - **逻辑推理:**
     - **假设输入:** `previous_inflow_position` 提供之前的流入位置信息， `child` 是要布局的绝对定位元素。
     - **预期输出:** 绝对定位元素的布局信息会被添加到 `container_builder_` 中，包括其静态偏移量。
   - **用户或编程常见的使用错误:**
     - **忘记设置定位父元素:** 绝对定位元素的偏移量相对于最近的已定位祖先元素，如果没有已定位的祖先元素，则相对于初始包含块（通常是 `<html>` 元素）。
     - **不理解 `top`, `right`, `bottom`, `left` 的工作方式:** 这些属性定义了元素边缘相对于包含块边缘的偏移。

4. **处理浮动元素 (`HandleFloat`):**
   - **功能:**  负责放置浮动 (`float: left` 或 `float: right`) 的子元素。它需要考虑浮动元素对周围内容的影响，并可能导致后续内容环绕浮动元素。
   - **与 Web 技术的关系:**
     - **CSS:**  直接对应于 `float: left` 和 `float: right` 属性。
   - **逻辑推理:**
     - **假设输入:** `previous_inflow_position`， `child` 是要布局的浮动元素， `child_break_token` 是可能的断点信息。
     - **预期输出:** 浮动元素的布局信息会被添加到 `container_builder_` 中，并且 `GetExclusionSpace()` 会被更新以反映浮动元素占据的空间。
   - **用户或编程常见的使用错误:**
     - **忘记清除浮动:** 浮动元素会脱离正常的文档流，可能导致父元素高度塌陷或后续元素布局错乱。常见的清除浮动方法包括使用 `clear: both;` 或 BFC。
     - **不理解浮动元素的相互作用:**  多个浮动元素可能会并排排列，直到空间不足。

5. **处理创建新的格式化上下文的元素 (`HandleNewFormattingContext` 和 `LayoutNewFormattingContext`):**
   - **功能:**  处理那些创建新的格式化上下文的块级子元素，例如 flex 容器、grid 容器等。这需要为这些子元素建立独立的布局流程。
   - **与 Web 技术的关系:**
     - **CSS:**  与 `display: flex`, `display: grid`, `display: flow-root` 等属性相关，这些属性会创建新的格式化上下文。
   - **逻辑推理:**
     - **假设输入:** `child` 是创建新格式化上下文的元素， `child_break_token`， `previous_inflow_position`。
     - **预期输出:**  调用 `LayoutNewFormattingContext` 为子元素执行独立的布局，并将布局结果添加到 `container_builder_` 中。
   - **用户或编程常见的使用错误:**
     - **不理解格式化上下文的概念:** 格式化上下文决定了元素的布局方式，理解不同格式化上下文的特性对于编写复杂的布局至关重要。
     - **混淆不同格式化上下文的布局规则:** 例如，尝试将 flexbox 的属性应用于非 flex 容器。

6. **处理普通的流入元素 (`HandleInflow`):**
   - **功能:**  负责布局正常的、按文档流顺序排列的子元素。
   - **与 Web 技术的关系:**
     - **HTML:**  反映了 HTML 元素的默认布局方式。
     - **CSS:**  受到各种 CSS 属性的影响，如 `margin`, `padding`, `width`, `height` 等。
   - **逻辑推理:**
     - **假设输入:** `child` 是要布局的流入元素， `child_break_token`， `previous_inflow_position`。
     - **预期输出:**  子元素的布局信息会被添加到 `container_builder_` 中。

**总结这段代码片段的功能:**

这段代码片段是 `BlockLayoutAlgorithm` 类的一部分，专注于处理块级元素的布局。它负责：

- **管理分片布局**:  将之前的布局片段合并到当前片段。
- **确定 BFC 块偏移**:  为后续元素定位打下基础。
- **放置不同类型的子元素**:  包括绝对定位、浮动和普通的流入元素。
- **处理新的格式化上下文**:  为 flex 和 grid 等容器创建独立的布局流程。
- **维护布局状态**:  更新流入位置、行数等信息，以便后续布局操作能够正确进行。

这段代码是浏览器渲染引擎核心功能的一部分，确保网页能够按照 CSS 规则正确地呈现给用户。 它的正确性直接影响到用户看到的网页布局是否符合预期。

### 提示词
```
这是目录为blink/renderer/core/layout/block_layout_algorithm.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第3部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
wtf_size_t children_before = children.size();
  FragmentItemsBuilder* items_builder = container_builder_.ItemsBuilder();
  const auto& space = GetConstraintSpace();
  DCHECK_EQ(items_builder->GetWritingDirection(), space.GetWritingDirection());
  const auto result =
      items_builder->AddPreviousItems(previous_fragment, *previous_items,
                                      &container_builder_, end_item, max_lines);
  if (!result.succeeded) [[unlikely]] {
    DCHECK_EQ(children.size(), children_before);
    DCHECK(!result.used_block_size);
    DCHECK(!result.inline_break_token);
    return false;
  }

  // To reach here we mustn't have any adjoining objects, and the first line
  // must have content. Resolving the BFC block-offset here should never fail.
  DCHECK(!abort_when_bfc_block_offset_updated_);
  bool success = ResolveBfcBlockOffset(previous_inflow_position);
  DCHECK(success);
  DCHECK(container_builder_.BfcBlockOffset());

  DCHECK_GT(result.line_count, 0u);
  if (max_lines) {
    DCHECK(result.line_count <= max_lines);
    DCHECK_EQ(line_clamp_data_.data.state, LineClampData::kClampByLines);
    line_clamp_data_.data.lines_until_clamp -= result.line_count;
  } else if (line_clamp_data_.data.state ==
             LineClampData::kMeasureLinesUntilBfcOffset) {
    line_clamp_data_.data.lines_until_clamp += result.line_count;
  }

  // |AddPreviousItems| may have added more than one lines. Propagate baselines
  // from them.
  for (const auto& child : base::make_span(children).subspan(children_before)) {
    DCHECK(child.fragment->IsLineBox());
    PropagateBaselineFromLineBox(*child.fragment, child.offset.block_offset);
  }

  previous_inflow_position->logical_block_offset += result.used_block_size;
  *inline_break_token_out = result.inline_break_token;
  return true;
}

void BlockLayoutAlgorithm::HandleOutOfFlowPositioned(
    const PreviousInflowPosition& previous_inflow_position,
    BlockNode child) {
  if (GetConstraintSpace().HasBlockFragmentation()) {
    // Forced breaks cannot be specified directly on out-of-flow positioned
    // elements, but if the preceding block has a forced break after, we need to
    // break before it. Note that we really only need to do this if block-start
    // offset is auto (but it's harmless to do it also when it's non-auto).
    EBreakBetween break_between =
        container_builder_.JoinedBreakBetweenValue(EBreakBetween::kAuto);
    if (IsForcedBreakValue(GetConstraintSpace(), break_between)) {
      container_builder_.AddBreakBeforeChild(child, kBreakAppealPerfect,
                                             /* is_forced_break*/ true);
      return;
    }
  }

  DCHECK(child.IsOutOfFlowPositioned());
  LogicalOffset static_offset = {BorderScrollbarPadding().inline_start,
                                 previous_inflow_position.logical_block_offset};

  // We only include the margin strut in the OOF static-position if we know we
  // aren't going to be a zero-block-size fragment.
  if (container_builder_.BfcBlockOffset())
    static_offset.block_offset += previous_inflow_position.margin_strut.Sum();

  if (child.Style().IsOriginalDisplayInlineType()) {
    // The static-position of inline-level OOF-positioned nodes depends on
    // previous floats (if any).
    //
    // Due to this we need to mark this node as having adjoining objects, and
    // perform a re-layout if our position shifts.
    if (!container_builder_.BfcBlockOffset()) {
      container_builder_.AddAdjoiningObjectTypes(kAdjoiningInlineOutOfFlow);
      abort_when_bfc_block_offset_updated_ = true;
    }

    LayoutUnit origin_bfc_block_offset =
        container_builder_.BfcBlockOffset().value_or(
            GetConstraintSpace().ExpectedBfcBlockOffset()) +
        static_offset.block_offset;

    BfcOffset origin_bfc_offset = {
        GetConstraintSpace().GetBfcOffset().line_offset +
            BorderScrollbarPadding().LineLeft(Style().Direction()),
        origin_bfc_block_offset};

    static_offset.inline_offset += CalculateOutOfFlowStaticInlineLevelOffset(
        Style(), origin_bfc_offset, GetExclusionSpace(),
        ChildAvailableSize().inline_size);
  }

  container_builder_.AddOutOfFlowChildCandidate(
      child, static_offset, LogicalStaticPosition::kInlineStart,
      LogicalStaticPosition::kBlockStart,
      line_clamp_data_.ShouldHideForPaint());
}

void BlockLayoutAlgorithm::HandleFloat(
    const PreviousInflowPosition& previous_inflow_position,
    BlockNode child,
    const BlockBreakToken* child_break_token) {
  // If we're resuming layout, we must always know our position in the BFC.
  DCHECK(!IsBreakInside(child_break_token) ||
         container_builder_.BfcBlockOffset());
  const auto& constraint_space = GetConstraintSpace();

  // If we don't have a BFC block-offset yet, the "expected" BFC block-offset
  // is used to optimistically place floats.
  BfcOffset origin_bfc_offset = {
      constraint_space.GetBfcOffset().line_offset +
          BorderScrollbarPadding().LineLeft(constraint_space.Direction()),
      container_builder_.BfcBlockOffset()
          ? NextBorderEdge(previous_inflow_position)
          : constraint_space.ExpectedBfcBlockOffset()};

  if (child_break_token) {
    // If there's monolithic content inside the float from a previous page
    // overflowing into this one, move past it. And subtract any such overflow
    // from the parent flow, as floats establish a parallel flow.
    origin_bfc_offset.block_offset += child_break_token->MonolithicOverflow() -
                                      GetBreakToken()->MonolithicOverflow();
  }

  if (GetConstraintSpace().HasBlockFragmentation()) {
    // Forced breaks cannot be specified directly on floats, but if the
    // preceding block has a forced break after, we need to break before this
    // float.
    EBreakBetween break_between =
        container_builder_.JoinedBreakBetweenValue(EBreakBetween::kAuto);
    if (IsForcedBreakValue(constraint_space, break_between)) {
      container_builder_.AddBreakBeforeChild(child, kBreakAppealPerfect,
                                             /* is_forced_break*/ true);
      return;
    }
  }

  UnpositionedFloat unpositioned_float(
      child, child_break_token, ChildAvailableSize(), child_percentage_size_,
      replaced_child_percentage_size_, origin_bfc_offset, constraint_space,
      Style(), FragmentainerCapacityForChildren(),
      FragmentainerOffsetForChildren(), line_clamp_data_.ShouldHideForPaint());

  if (!container_builder_.BfcBlockOffset()) {
    container_builder_.AddAdjoiningObjectTypes(
        unpositioned_float.IsLineLeft(constraint_space.Direction())
            ? kAdjoiningFloatLeft
            : kAdjoiningFloatRight);
    // If we don't have a forced BFC block-offset yet, we'll optimistically
    // place floats at the "expected" BFC block-offset. If this differs from
    // our final BFC block-offset we'll need to re-layout.
    if (!constraint_space.ForcedBfcBlockOffset()) {
      abort_when_bfc_block_offset_updated_ = true;
    }
  }

  PositionedFloat positioned_float =
      PositionFloat(&unpositioned_float, &GetExclusionSpace());

  if (positioned_float.minimum_space_shortage > LayoutUnit()) {
    container_builder_.PropagateSpaceShortage(
        positioned_float.minimum_space_shortage);
  }

  if (positioned_float.break_before_token) {
    DCHECK(constraint_space.HasBlockFragmentation());
    container_builder_.AddBreakToken(positioned_float.break_before_token,
                                     /* is_in_parallel_flow */ true);
    // After breaking before the float, carry on with layout of this
    // container. The float constitutes a parallel flow, and there may be
    // siblings that could still fit in the current fragmentainer.
    return;
  }

  DCHECK_EQ(positioned_float.layout_result->Status(), LayoutResult::kSuccess);

  // TODO(mstensho): There should be a class A breakpoint between a float and
  // another float, and also between a float and an in-flow block.

  const PhysicalFragment& physical_fragment =
      positioned_float.layout_result->GetPhysicalFragment();
  LayoutUnit float_inline_size =
      LogicalFragment(constraint_space.GetWritingDirection(), physical_fragment)
          .InlineSize();

  BfcOffset bfc_offset = {constraint_space.GetBfcOffset().line_offset,
                          container_builder_.BfcBlockOffset().value_or(
                              constraint_space.ExpectedBfcBlockOffset())};

  LogicalOffset logical_offset = LogicalFromBfcOffsets(
      positioned_float.bfc_offset, bfc_offset, float_inline_size,
      container_builder_.InlineSize(), constraint_space.Direction());

  container_builder_.AddResult(*positioned_float.layout_result, logical_offset);
}

LayoutResult::EStatus BlockLayoutAlgorithm::HandleNewFormattingContext(
    LayoutInputNode child,
    const BlockBreakToken* child_break_token,
    PreviousInflowPosition* previous_inflow_position) {
  DCHECK(child);
  DCHECK(!child.IsFloating());
  DCHECK(!child.IsOutOfFlowPositioned());
  DCHECK(child.CreatesNewFormattingContext());
  DCHECK(child.IsBlock());

  const auto& constraint_space = GetConstraintSpace();
  const ComputedStyle& child_style = child.Style();
  const TextDirection direction = constraint_space.Direction();
  InflowChildData child_data =
      ComputeChildData(*previous_inflow_position, child, child_break_token,
                       /* is_new_fc */ true);

  LayoutUnit child_origin_line_offset =
      constraint_space.GetBfcOffset().line_offset +
      BorderScrollbarPadding().LineLeft(direction);

  // If the child has a block-start margin, and the BFC block offset is still
  // unresolved, and we have preceding adjoining floats, things get complicated
  // here. Depending on whether the child fits beside the floats, the margin may
  // or may not be adjoining with the current margin strut. This affects the
  // position of the preceding adjoining floats. We may have to resolve the BFC
  // block offset once with the child's margin tentatively adjoining, then
  // realize that the child isn't going to fit beside the floats at the current
  // position, and therefore re-resolve the BFC block offset with the child's
  // margin non-adjoining. This is akin to clearance.
  MarginStrut adjoining_margin_strut(previous_inflow_position->margin_strut);
  adjoining_margin_strut.Append(child_data.margins.block_start,
                                child_style.HasMarginBlockStartQuirk());
  LayoutUnit adjoining_bfc_offset_estimate =
      child_data.bfc_offset_estimate.block_offset +
      adjoining_margin_strut.Sum();
  LayoutUnit non_adjoining_bfc_offset_estimate =
      child_data.bfc_offset_estimate.block_offset +
      previous_inflow_position->margin_strut.Sum();
  LayoutUnit child_bfc_offset_estimate = adjoining_bfc_offset_estimate;
  bool bfc_offset_already_resolved = false;
  bool child_determined_bfc_offset = false;
  bool child_margin_got_separated = false;
  bool has_adjoining_floats = false;

  if (!container_builder_.BfcBlockOffset()) {
    has_adjoining_floats =
        container_builder_.GetAdjoiningObjectTypes() & kAdjoiningFloatBoth;

    // If this node, or an arbitrary ancestor had clearance past adjoining
    // floats, we consider the margin "separated". We should *never* attempt to
    // re-resolve the BFC block-offset in this case.
    bool has_clearance_past_adjoining_floats =
        constraint_space.AncestorHasClearancePastAdjoiningFloats() ||
        HasClearancePastAdjoiningFloats(
            container_builder_.GetAdjoiningObjectTypes(), child_style, Style());

    if (has_clearance_past_adjoining_floats) {
      child_bfc_offset_estimate = NextBorderEdge(*previous_inflow_position);
      child_margin_got_separated = true;
    } else if (constraint_space.ForcedBfcBlockOffset()) {
      // This is not the first time we're here. We already have a suggested BFC
      // block offset.
      bfc_offset_already_resolved = true;
      child_bfc_offset_estimate = *constraint_space.ForcedBfcBlockOffset();
      // We require that the BFC block offset be the one we'd get with margins
      // adjoining, margins separated, or if clearance was applied to either of
      // these. Anything else is a bug.
      DCHECK(child_bfc_offset_estimate == adjoining_bfc_offset_estimate ||
             child_bfc_offset_estimate == non_adjoining_bfc_offset_estimate ||
             child_bfc_offset_estimate == constraint_space.ClearanceOffset());
      // Figure out if the child margin has already got separated from the
      // margin strut or not.
      //
      // TODO(mstensho): We get false positives here, if the container was
      // cleared by floats (but the child wasn't). See
      // wpt/css/css-break/class-c-breakpoint-after-float-004.html
      child_margin_got_separated =
          child_bfc_offset_estimate != adjoining_bfc_offset_estimate;
    }

    // The BFC block offset of this container gets resolved because of this
    // child.
    child_determined_bfc_offset = true;

    // The block-start margin of the child will only affect the parent's
    // position if it is adjoining.
    if (!child_margin_got_separated) {
      SetSubtreeModifiedMarginStrutIfNeeded(
          &child_style.MarginBlockStartUsing(Style()));
    }

    if (!ResolveBfcBlockOffset(previous_inflow_position,
                               child_bfc_offset_estimate)) {
      // If we need to abort here, it means that we had preceding unpositioned
      // floats. This is only expected if we're here for the first time.
      DCHECK(!bfc_offset_already_resolved);
      return LayoutResult::kBfcBlockOffsetResolved;
    }

    // We reset the block offset here as it may have been affected by clearance.
    child_bfc_offset_estimate = ContainerBfcOffset().block_offset;
  }

  // If the child has a non-zero block-start margin, our initial estimate will
  // be that any pending floats will be flush (block-start-wise) with this
  // child, since they are affected by margin collapsing. Furthermore, this
  // child's margin may also pull parent blocks downwards. However, this is only
  // the case if the child fits beside the floats at the current block
  // offset. If it doesn't (or if it gets clearance), the child needs to be
  // pushed down. In this case, the child's margin no longer collapses with the
  // previous margin strut, so the pending floats and parent blocks need to
  // ignore this margin, which may cause them to end up at completely different
  // positions than initially estimated. In other words, we'll need another
  // layout pass if this happens.
  bool abort_if_cleared = child_data.margins.block_start != LayoutUnit() &&
                          !child_margin_got_separated &&
                          child_determined_bfc_offset;
  BfcOffset child_bfc_offset;
  BoxStrut resolved_margins;
  const LayoutResult* layout_result = LayoutNewFormattingContext(
      child, child_break_token, child_data,
      {child_origin_line_offset, child_bfc_offset_estimate}, abort_if_cleared,
      &child_bfc_offset, &resolved_margins);

  if (!layout_result) {
    DCHECK(abort_if_cleared);
    // Layout got aborted, because the child got pushed down by floats, and we
    // may have had pending floats that we tentatively positioned incorrectly
    // (since the child's margin shouldn't have affected them). Try again
    // without the child's margin. So, we need another layout pass. Figure out
    // if we can do it right away from here, or if we have to roll back and
    // reposition floats first.
    if (child_determined_bfc_offset) {
      // The BFC block offset was calculated when we got to this child, with
      // the child's margin adjoining. Since that turned out to be wrong,
      // re-resolve the BFC block offset without the child's margin.
      LayoutUnit old_offset = *container_builder_.BfcBlockOffset();
      container_builder_.ResetBfcBlockOffset();

      // Re-resolving the BFC block-offset with a different "forced" BFC
      // block-offset is only safe if an ancestor *never* had clearance past
      // adjoining floats.
      DCHECK(!constraint_space.AncestorHasClearancePastAdjoiningFloats());
      ResolveBfcBlockOffset(previous_inflow_position,
                            non_adjoining_bfc_offset_estimate,
                            /* forced_bfc_block_offset */ std::nullopt);

      if ((bfc_offset_already_resolved || has_adjoining_floats) &&
          old_offset != *container_builder_.BfcBlockOffset()) {
        // The first BFC block offset resolution turned out to be wrong, and we
        // positioned preceding adjacent floats based on that. Now we have to
        // roll back and position them at the correct offset. The only expected
        // incorrect estimate is with the child's margin adjoining. Any other
        // incorrect estimate will result in failed layout.
        DCHECK_EQ(old_offset, adjoining_bfc_offset_estimate);
        return LayoutResult::kBfcBlockOffsetResolved;
      }
    }

    child_bfc_offset_estimate = non_adjoining_bfc_offset_estimate;
    child_margin_got_separated = true;

    // We can re-layout the child right away. This re-layout *must* produce a
    // fragment which fits within the exclusion space.
    layout_result = LayoutNewFormattingContext(
        child, child_break_token, child_data,
        {child_origin_line_offset, child_bfc_offset_estimate},
        /* abort_if_cleared */ false, &child_bfc_offset, &resolved_margins);
  }

  if (constraint_space.HasBlockFragmentation()) {
    bool has_container_separation =
        has_break_opportunity_before_next_child_ ||
        child_bfc_offset.block_offset > child_bfc_offset_estimate ||
        layout_result->IsPushedByFloats();
    BreakStatus break_status = BreakBeforeChildIfNeeded(
        child, *layout_result, previous_inflow_position,
        child_bfc_offset.block_offset, has_container_separation);
    if (break_status == BreakStatus::kBrokeBefore) {
      return LayoutResult::kSuccess;
    }
    if (break_status == BreakStatus::kNeedsEarlierBreak) {
      return LayoutResult::kNeedsEarlierBreak;
    }

    // If the child aborted layout, we cannot continue.
    DCHECK_EQ(layout_result->Status(), LayoutResult::kSuccess);
  }

  const auto& physical_fragment = layout_result->GetPhysicalFragment();
  LogicalFragment fragment(constraint_space.GetWritingDirection(),
                           physical_fragment);

  LogicalOffset logical_offset = LogicalFromBfcOffsets(
      child_bfc_offset, ContainerBfcOffset(), fragment.InlineSize(),
      container_builder_.InlineSize(), constraint_space.Direction());

  if (!PositionOrPropagateListMarker(*layout_result, &logical_offset,
                                     previous_inflow_position))
    return LayoutResult::kBfcBlockOffsetResolved;

  PropagateBaselineFromBlockChild(physical_fragment, resolved_margins,
                                  logical_offset.block_offset);

  container_builder_.AddResult(*layout_result, logical_offset,
                               resolved_margins);

  if (!child_break_token || !child_break_token->IsInParallelFlow()) {
    *previous_inflow_position = ComputeInflowPosition(
        *previous_inflow_position, child, child_data,
        child_bfc_offset.block_offset, logical_offset, *layout_result, fragment,
        /* self_collapsing_child_had_clearance */ false);
  }

  // Update line-clamp data, and abort if needed
  if (!line_clamp_data_.UpdateAfterLayout(
          layout_result, *container_builder_.BfcBlockOffset(),
          *previous_inflow_position, Padding().block_end)) {
    container_builder_.SetLinesUntilClamp(
        line_clamp_data_.LinesUntilClamp(/*show_measured_lines*/ true));
    return LayoutResult::kNeedsLineClampRelayout;
  }

  if (constraint_space.HasBlockFragmentation() &&
      !has_break_opportunity_before_next_child_) {
    has_break_opportunity_before_next_child_ =
        HasBreakOpportunityBeforeNextChild(physical_fragment,
                                           child_break_token);
  }

  return LayoutResult::kSuccess;
}

const LayoutResult* BlockLayoutAlgorithm::LayoutNewFormattingContext(
    LayoutInputNode child,
    const BlockBreakToken* child_break_token,
    const InflowChildData& child_data,
    BfcOffset origin_offset,
    bool abort_if_cleared,
    BfcOffset* out_child_bfc_offset,
    BoxStrut* out_resolved_margins) {
  const auto& style = Style();
  const auto& child_style = child.Style();
  const TextDirection direction = GetConstraintSpace().Direction();
  const auto writing_direction = GetConstraintSpace().GetWritingDirection();

  if (!IsBreakInside(child_break_token)) {
    // The origin offset is where we should start looking for layout
    // opportunities. It needs to be adjusted by the child's clearance.
    AdjustToClearance(GetExclusionSpace().ClearanceOffsetIncludingInitialLetter(
                          child_style.Clear(style)),
                      &origin_offset);
  }
  DCHECK(container_builder_.BfcBlockOffset());

  LayoutOpportunityVector opportunities =
      GetExclusionSpace().AllLayoutOpportunities(
          origin_offset, ChildAvailableSize().inline_size);
  ClearCollectionScope scope(&opportunities);

  // We should always have at least one opportunity.
  DCHECK_GT(opportunities.size(), 0u);

  // Now we lay out. This will give us a child fragment and thus its size, which
  // means that we can find out if it's actually going to fit. If it doesn't
  // fit where it was laid out, and is pushed downwards, we'll lay out over
  // again, since a new BFC block offset could result in a new fragment size,
  // e.g. when inline size is auto, or if we're block-fragmented.
  for (const auto& opportunity : opportunities) {
    if (abort_if_cleared &&
        origin_offset.block_offset < opportunity.rect.BlockStartOffset()) {
      // Abort if we got pushed downwards. We need to adjust
      // origin_offset.block_offset, reposition any floats affected by that, and
      // try again.
      return nullptr;
    }

    // Determine which sides of the opportunity have floats we should avoid.
    // We can detect this when the opportunity-rect sides match the
    // available-rect sides.
    bool has_floats_on_line_left =
        opportunity.rect.LineStartOffset() != origin_offset.line_offset;
    bool has_floats_on_line_right =
        opportunity.rect.LineEndOffset() !=
        (origin_offset.line_offset + ChildAvailableSize().inline_size);
    bool can_expand_outside_opportunity =
        !has_floats_on_line_left && !has_floats_on_line_right;

    const LayoutUnit line_left_margin = child_data.margins.LineLeft(direction);
    const LayoutUnit line_right_margin =
        child_data.margins.LineRight(direction);

    // Find the available inline-size which should be given to the child.
    LayoutUnit line_left_offset = opportunity.rect.LineStartOffset();
    LayoutUnit line_right_offset = opportunity.rect.LineEndOffset();

    if (can_expand_outside_opportunity) {
      // No floats have affected the available inline-size, adjust the
      // available inline-size by the margins.
      DCHECK_EQ(line_left_offset, origin_offset.line_offset);
      DCHECK_EQ(line_right_offset,
                origin_offset.line_offset + ChildAvailableSize().inline_size);
      line_left_offset += line_left_margin;
      line_right_offset -= line_right_margin;
    } else {
      // Margins are applied from the content-box, not the layout opportunity
      // area. Instead of adjusting by the size of the margins, we "shrink" the
      // available inline-size if required.
      line_left_offset = std::max(
          line_left_offset,
          origin_offset.line_offset + line_left_margin.ClampNegativeToZero());
      line_right_offset = std::min(line_right_offset,
                                   origin_offset.line_offset +
                                       ChildAvailableSize().inline_size -
                                       line_right_margin.ClampNegativeToZero());
    }
    LayoutUnit opportunity_size =
        (line_right_offset - line_left_offset).ClampNegativeToZero();

    // The available inline size in the child constraint space needs to include
    // inline margins, since layout algorithms (both legacy and NG) will resolve
    // auto inline size by subtracting the inline margins from available inline
    // size. We have calculated a layout opportunity without margins in mind,
    // since they overlap with adjacent floats. Now we need to add them.
    LayoutUnit child_available_inline_size =
        (opportunity_size + child_data.margins.InlineSum())
            .ClampNegativeToZero();

    ConstraintSpace child_space = CreateConstraintSpaceForChild(
        child, child_break_token, child_data,
        {child_available_inline_size, ChildAvailableSize().block_size},
        /* is_new_fc */ true, opportunity.rect.start_offset.block_offset);

    // All formatting context roots (like this child) should start with an empty
    // exclusion space.
    DCHECK(child_space.GetExclusionSpace().IsEmpty());

    const LayoutResult* layout_result = LayoutBlockChild(
        child_space, child_break_token, early_break_,
        /* column_spanner_path */ nullptr, &To<BlockNode>(child));

    // Since this child establishes a new formatting context, no exclusion space
    // should be returned.
    DCHECK(layout_result->GetExclusionSpace().IsEmpty());

    DCHECK_EQ(layout_result->Status(), LayoutResult::kSuccess);

    // Check if we can fit in the opportunity block direction.
    LogicalFragment fragment(writing_direction,
                             layout_result->GetPhysicalFragment());
    if (fragment.BlockSize() > opportunity.rect.BlockSize())
      continue;

    // Now find the fragment's (final) position calculating the auto margins.
    BoxStrut auto_margins = child_data.margins;
    LayoutUnit text_align_offset;
    bool has_auto_margins = false;
    if (child.IsListMarker()) {
      // Deal with marker's margin. It happens only when marker needs to occupy
      // the whole line.
      DCHECK(child.ListMarkerOccupiesWholeLine());
      // Because the marker is laid out as a normal block child, its inline
      // size is extended to fill up the space. Compute the regular marker size
      // from the first child.
      const auto& marker_fragment = layout_result->GetPhysicalFragment();
      LayoutUnit marker_inline_size;
      if (!marker_fragment.Children().empty()) {
        marker_inline_size =
            LogicalFragment(writing_direction,
                            *marker_fragment.Children().front())
                .InlineSize();
      }
      auto_margins.inline_start = UnpositionedListMarker(To<BlockNode>(child))
                                      .InlineOffset(marker_inline_size);
      auto_margins.inline_end = opportunity.rect.InlineSize() -
                                fragment.InlineSize() -
                                auto_margins.inline_start;
    } else {
      if (child_style.MarginInlineStartUsing(style).IsAuto() ||
          child_style.MarginInlineEndUsing(style).IsAuto()) {
        has_auto_margins = true;
        ResolveInlineAutoMargins(child_style, style,
                                 child_available_inline_size,
                                 fragment.InlineSize(), &auto_margins);
      } else {
        // Handle -webkit- values for text-align.
        text_align_offset = WebkitTextAlignAndJustifySelfOffset(
            child_style, style, opportunity.rect.InlineSize(),
            child_data.margins, [&]() { return fragment.InlineSize(); });
      }
    }

    // Determine our final BFC offset.
    //
    // NOTE: |auto_margins| are initialized as a copy of the child's initial
    // margins. To determine the effect of the auto-margins we apply only the
    // difference.
    BfcOffset child_bfc_offset = {LayoutUnit(),
                                  opportunity.rect.BlockStartOffset()};
    if (direction == TextDirection::kLtr) {
      LayoutUnit auto_margin_line_left =
          auto_margins.LineLeft(direction) - line_left_margin;
      child_bfc_offset.line_offset =
          line_left_offset + auto_margin_line_left + text_align_offset;
    } else {
      LayoutUnit auto_margin_line_right =
          auto_margins.LineRight(direction) - line_right_margin;
      child_bfc_offset.line_offset = line_right_offset - text_align_offset -
                                     auto_margin_line_right -
                                     fragment.InlineSize();
    }

    // Check if we'll intersect any floats on our line-left/line-right.
    if (has_floats_on_line_left &&
        child_bfc_offset.line_offset < opportunity.rect.LineStartOffset())
      continue;
    if (has_floats_on_line_right &&
        child_bfc_offset.line_offset + fragment.InlineSize() >
            opportunity.rect.LineEndOffset())
      continue;

    // If we can't expand outside our opportunity, check if we fit in the
    // inline direction.
    if (!can_expand_outside_opportunity &&
        fragment.InlineSize() > opportunity.rect.InlineSize())
      continue;

    // auto-margins are "fun". To ensure round tripping from getComputedStyle
    // the used values are relative to the content-box edge, rather than the
    // opportunity edge.
    BoxStrut resolved_margins = child_data.margins;
    if (has_auto_margins) {
      LayoutUnit inline_offset =
          LogicalFromBfcLineOffset(child_bfc_offset.line_offset,
                                   container_builder_.BfcLineOffset(),
                                   fragment.InlineSize(),
                                   container_builder_.InlineSize(), direction) -
          BorderScrollbarPadding().inline_start;
      if (child_style.MarginInlineStartUsing(style).IsAuto()) {
        resolved_margins.inline_start = inline_offset;
      }
      if (child_style.MarginInlineEndUsing(style).IsAuto()) {
        resolved_margins.inline_end = ChildAvailableSize().inline_size -
                                      inline_offset - fragment.InlineSize();
      }
    }

    *out_child_bfc_offset = child_bfc_offset;
    *out_resolved_margins = resolved_margins;
    return layout_result;
  }

  NOTREACHED();
}

LayoutResult::EStatus BlockLayoutAlgorithm::HandleInflow(
    LayoutInputNode child,
    const BreakToken* child_break_token,
    PreviousInflowPosition* previous_inflow_position,
    InlineChildLayoutContext* inline_child_layout_context,
    const InlineBreakToken** previous_inline_break_token) {
  DCHECK(child);
  DCHECK(!child.IsFloating());
  DCHECK(!child.IsOutOfFlowPositioned());
  DCHECK(!child.CreatesNewFormattingContext());

  auto* child_inline_node = DynamicTo<InlineNode>(child);
  if (child_inline_node) {
    // Add reusable line boxes from |previous_result_| if any.
    if (!abort_when_bfc_block_offset_updated_ && !child_break_token &&
        previous_result_) {
      DCHECK(!*previous_inline_break_token);
      if (TryReuseFragmentsFromCache(*child_inline_node,
                                     previous_inflow_position,
                                     previous_inline_break_token))
        return LayoutResult::kSuccess;
    }
  }

  bool has_clearance_past_adjoining_floats =
      !container_builder_.BfcBlockOffset() && child.IsBlock() &&
      HasClearancePastAdjoiningFloats(
          container_builder_.GetAdjoiningObjectTypes(), child.Style(), Style());

  std::optional<LayoutUnit> forced_bfc_block_offset;
  bool is_pushed_by_floats = false;

  // If we can separate the previous margin strut from what is to follow, do
  // that. Then we're able to resolve *our* BFC block offset and position any
  // pending floats. There are two situations where this is necessary:
  //  1. If the child is to be cleared by adjoining floats.
  //  2. If the child is a non-empty inline.
  //
  // Note this logic is copied to TryReuseFragmentsFromCache(), they need to
  // keep in sync.
  if (has_clearance_past_adjoining_floats) {
    if (!ResolveBfcBlockOffset(previous_inflow_position))
      return LayoutResult::kBfcBlockOffsetResolved;

    // If we had clearance past any adjoining floats, we already know where the
    // child is going to be (the child's margins won't have any effect).
    //
    // Set the forced BFC block-offset to the appropriate clearance offset to
    // force this placement of this child.
    forced_bfc_block_offset =
        GetExclusionSpace().ClearanceOffset(child.Style().Clear(Style()));
    is_pushed_by_floats = true;
  }

  // Perform layout on the child.
  InflowChildData child_data =
      ComputeChildData(*previous_inflow_position, child, child_break_token,
                       /*
```