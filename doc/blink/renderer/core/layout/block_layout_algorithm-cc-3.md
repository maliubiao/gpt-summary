Response:
The user wants a summary of the functionality of the `block_layout_algorithm.cc` file in the Chromium Blink rendering engine. Specifically, they are interested in:

1. **General functionality:** What does this code do?
2. **Relationship to web technologies:** How does it connect to JavaScript, HTML, and CSS?
3. **Logical reasoning:** If there are algorithmic steps, what are the inputs and outputs?
4. **Common errors:** What mistakes do users or developers make related to this code?
5. **Context within the larger file:** This is part 4 of 6, so what's the focus of this section?

Let's break down the provided code snippets to address these points:

**Code Analysis:**

* **`LayoutInflow`:** This function appears to be the core of laying out an "in-flow" child element within a block formatting context. It takes a child node, constraint information, and break tokens as input. It recursively calls the layout process for the child.
* **`FinishInflow`:** This function seems to handle the post-layout processing of an in-flow child. It deals with:
    * **Line clamping:** Propagating line clamp requirements.
    * **BFC block offset resolution:** Handling cases where the child determines its block offset.
    * **Clearance:**  Adjusting for elements that need to be placed below floats.
    * **Margin collapsing:**  Managing how margins of adjacent elements interact.
    * **Relayouting:**  Deciding if a child needs to be laid out again.
    * **Fragmentation:** Handling how content breaks across page or column boundaries.
    * **Exclusion spaces and adjoining objects:**  Dealing with floats and other positioned elements.
    * **Positioning:**  Calculating the final position of the child.
    * **Baseline propagation:**  Ensuring baselines of text align correctly.
    * **Text box trimming:** Applying the `text-box-trim` CSS property.
* **`ComputeChildData`:**  This function calculates data needed for laying out a child, such as margins and initial offsets. It considers fragmentation and new formatting contexts.
* **`ComputeInflowPosition`:** This function determines the block offset and margin strut for the *next* element based on the layout of the current child. It handles margin collapsing, clearance, and annotation spaces.
* **`PositionSelfCollapsingChildWithParentBfc`:** This function specifically handles the positioning of self-collapsing elements (elements with zero height) within their parent's block formatting context, considering clearance.
* **`ConsumeRemainingFragmentainerSpace`:** This function seems to deal with how leftover space in a fragmented container is handled.

**Connecting to the Request:**

1. **Functionality:** This section of `block_layout_algorithm.cc` focuses on the core logic for laying out individual block-level and inline-level elements within a block formatting context. It handles the complex interplay of margins, floats, clearance, fragmentation, and line clamping to determine the position and size of elements.

2. **Web Technologies:**
    * **HTML:** The input to these functions are representations of HTML elements (`LayoutInputNode`, `child`). The structure of the HTML document directly influences the order in which elements are laid out.
    * **CSS:** CSS properties like `margin`, `padding`, `clear`, `float`, `break-before`, `break-after`, `text-box-trim`, and `line-clamp` are critical inputs to these algorithms. The code calculates sizes and positions based on these styles.
        * **Example (CSS & Output):** If a CSS rule `div { margin-bottom: 20px; }` is applied to an HTML `<div>`, the `CalculateMargins` and `ComputeInflowPosition` functions will use this value to determine the spacing between this `div` and the next element. The `margin_strut` will store this information.
    * **JavaScript:** While this code is C++, JavaScript can indirectly influence it. Dynamic changes to the DOM (adding/removing elements) or CSS styles via JavaScript will trigger a relayout process, which will call these functions.

3. **Logical Reasoning:**
    * **`LayoutInflow` (Hypothetical Input & Output):**
        * **Input:** A `LayoutInputNode` representing a `<div>` element, a `ConstraintSpace` indicating available width, and no preceding floats.
        * **Output:** A `LayoutResult` containing the final position and size of the `<div>`, potentially information about how its children were laid out, and if it was pushed by floats.
    * **`FinishInflow` (Hypothetical Input & Output):**
        * **Input:** The `LayoutInputNode` of a child `<span>`, the `LayoutResult` from its layout, and information about preceding elements.
        * **Output:**  Potentially an updated `LayoutResult` for the parent container, indicating whether the parent's BFC block offset was resolved or if there are line clamping requirements.

4. **Common Errors:**
    * **CSS `clear` property issues:** Developers often misuse the `clear` property, leading to unexpected spacing or layout shifts. For example, applying `clear: both` to an element without understanding the context of surrounding floats can lead to large gaps. This code handles the logic for `clear`, so errors in its implementation could manifest as incorrect placement of cleared elements.
    * **Margin collapsing misunderstandings:** The rules for margin collapsing are complex. Developers might expect margins to always add up, but they collapse in certain situations. This code implements those rules, and bugs here could lead to incorrect vertical spacing between elements.
    * **Fragmentation issues:**  Incorrectly using `break-before` or `break-after` CSS properties can lead to content being split unexpectedly across pages or columns. This code handles the logic for these properties, and errors could cause incorrect fragmentation.
    * **Line clamping problems:**  Incorrectly setting or expecting `line-clamp` behavior can lead to text being truncated unexpectedly. This code manages the measurement and application of line clamping.

5. **Part 4 Focus:** Based on the function names and the flow of control, this section seems to be focused on the **core iteration of laying out individual child elements** within a block formatting context. It handles the initial layout and the finalization steps after a child has been laid out. It manages the complex interactions between elements as they are positioned sequentially.

**Summary of Functionality (Part 4):**

This section of `block_layout_algorithm.cc` details the primary logic for **laying out individual child elements within a block formatting context**. It iteratively processes each child, calculating its position and size while considering factors like margins, floats, clearance, and fragmentation. Key responsibilities include: initiating the layout of a child (`LayoutInflow`), finalizing the layout and handling post-processing steps like BFC block offset resolution and margin collapsing (`FinishInflow`), calculating initial layout data for a child (`ComputeChildData`), determining the position for the next element based on the current child's layout (`ComputeInflowPosition`), and handling the specific case of positioning self-collapsing elements (`PositionSelfCollapsingChildWithParentBfc`). It also includes logic for handling leftover space in fragmented containers (`ConsumeRemainingFragmentainerSpace`). This part of the code directly translates CSS layout rules into concrete positioning and sizing of HTML elements on the rendered page.

这是`blink/renderer/core/layout/block_layout_algorithm.cc`文件的第4部分，主要关注于**在块级格式化上下文（BFC）中布局子元素的核心迭代过程以及完成子元素布局后的处理工作**。

以下是该部分功能的详细归纳：

**核心功能：迭代布局子元素并完成布局**

1. **`LayoutInflow` 函数:**
   - **功能:**  负责启动对一个**in-flow（正常流）**的子元素的布局过程。
   - **过程:**
     - 计算子元素的布局约束空间 (`ConstraintSpace`)，这包括可用的尺寸、是否为新的格式化上下文、以及是否需要考虑浮动元素的影响等。
     - 调用更底层的布局函数 (`LayoutInflow` 的递归调用或者其他布局算法) 来实际布局子元素。
     - 将布局结果传递给 `FinishInflow` 函数进行后续处理。
   - **与 Web 技术的关系:**
     - **HTML:**  接收代表 HTML 元素的 `LayoutInputNode` 作为输入。
     - **CSS:**  布局约束空间 (`ConstraintSpace`) 的创建会考虑到元素的 CSS 属性，例如 `display`、`float`、`clear` 等。
   - **逻辑推理（假设输入与输出）:**
     - **假设输入:** 一个 `<div>` 元素作为子元素，父元素没有浮动，可用宽度为 100px。
     - **输出:** 调用 `LayoutInflow` 后，会创建一个针对该 `<div>` 的 `ConstraintSpace`，指示其可用的宽度为 100px，并且没有受到浮动的影响。然后会调用相应的布局逻辑来计算 `<div>` 的最终尺寸和位置。

2. **`FinishInflow` 函数:**
   - **功能:**  处理完成 **in-flow** 子元素布局后的各种后续操作。
   - **过程:**
     - **处理非成功的布局结果:**  检查布局是否需要行裁剪重排 (`kNeedsLineClampRelayout`)，并向上冒泡该状态。
     - **处理 BFC 块偏移量:**  如果子元素解析了自己的 BFC 块偏移量，则尝试更新父元素的 BFC 块偏移量。
     - **处理浮动清除:**  检查子元素是否需要清除浮动，并根据情况更新父元素的 BFC 块偏移量。
     - **处理边距折叠:**  根据子元素是否被浮动推下以及是否是自折叠元素来判断是否需要解析父元素的 BFC 块偏移量，以分隔折叠的边距。
     - **处理自折叠子元素:**  如果子元素是自折叠的（高度为 0），则需要特殊处理其定位，可能需要重新布局。
     - **处理分片:**  在分片上下文中，考虑是否需要在子元素之前进行分片。
     - **更新排除空间和邻接对象:**  根据子元素的布局结果更新父元素的排除空间（用于处理浮动）和邻接对象信息。
     - **定位子元素:**  计算子元素的最终逻辑偏移量，并调用 `container_builder_.AddResult` 将其添加到布局结果中。
     - **更新后续元素的流入位置:**  调用 `ComputeInflowPosition` 计算下一个子元素的起始位置。
     - **处理行裁剪:**  根据子元素的布局结果更新行裁剪数据，并可能触发重排。
     - **处理文本框裁剪 (`text-box-trim`)：** 如果需要，处理文本框的裁剪逻辑。
   - **与 Web 技术的关系:**
     - **CSS:**  `FinishInflow` 的逻辑直接对应了 CSS 中关于浮动、清除、边距折叠、分片和文本框裁剪的规则。
   - **逻辑推理（假设输入与输出）:**
     - **假设输入:** 一个子 `<span>` 元素的 `LayoutResult`，指示其宽度为 50px，没有被浮动影响。
     - **输出:** `FinishInflow` 会根据这个结果，更新父元素的布局信息，例如增加父元素的总高度，并计算下一个子元素的起始位置。如果 `<span>` 元素有 `clear: left;` 属性，则父元素的 BFC 块偏移量可能会被更新。

3. **`ComputeChildData` 函数:**
   - **功能:**  计算布局子元素所需的初始数据，例如边距、初始偏移量等。
   - **过程:**
     - 计算子元素在父元素书写模式下的边距。
     - 将子元素的块起始边距添加到当前的边距支柱 (`MarginStrut`) 中，用于处理边距折叠。
     - 计算子元素的 BFC 偏移量。
   - **与 Web 技术的关系:**
     - **CSS:**  直接读取子元素的 CSS 边距属性。
     - **HTML:**  接收代表 HTML 元素的 `LayoutInputNode` 作为输入。
   - **逻辑推理（假设输入与输出）:**
     - **假设输入:** 一个 `<div>` 子元素，CSS 样式为 `margin-top: 10px;`。
     - **输出:**  `ComputeChildData` 会计算出该 `<div>` 的顶部边距为 10px，并将其添加到 `MarginStrut` 中。

4. **`ComputeInflowPosition` 函数:**
   - **功能:**  计算下一个 **in-flow** 子元素的起始位置和边距支柱。
   - **过程:**
     - 根据当前子元素的布局结果（尺寸、偏移量、边距等）来确定下一个子元素的块偏移量。
     - 处理浮动清除对后续元素位置的影响。
     - 处理自折叠元素在清除浮动时的特殊情况。
     - 更新边距支柱，用于处理后续元素的边距折叠。
     - 处理文本框裁剪对后续元素位置的影响。
     - 处理 annotation 的空间。
   - **与 Web 技术的关系:**
     - **CSS:**  该函数的逻辑体现了 CSS 中关于盒子模型、浮动、清除和边距折叠的规则。
   - **逻辑推理（假设输入与输出）:**
     - **假设输入:** 一个已布局的 `<div>` 子元素，高度为 20px，底部边距为 5px。
     - **输出:**  `ComputeInflowPosition` 会计算出下一个子元素的起始块偏移量为当前 `<div>` 的结束位置加上底部边距，即 20px + 5px = 25px。

5. **`PositionSelfCollapsingChildWithParentBfc` 函数:**
   - **功能:**  专门用于定位自折叠（高度为 0）的子元素在其父元素的 BFC 中。
   - **过程:**
     - 使用子元素的结束边距支柱来确定其 BFC 块偏移量。
     - 应用浮动清除。
   - **与 Web 技术的关系:**
     - **CSS:**  处理高度为 0 的元素的定位，这在 CSS 布局中是一个特殊情况。

6. **`ConsumeRemainingFragmentainerSpace` 函数:**
    - **功能:**  处理分片容器中剩余的空间。
    - **过程:**  如果分片容器有已知的块大小，则剩余空间仍然会被当前容器占据。
    - **与 Web 技术的关系:**
        - **CSS:** 与 CSS 分页和分列属性相关。

**常见的使用错误 (用户或编程):**

- **误用 `clear` 属性:**  开发者可能不理解 `clear` 属性的作用域和影响，导致元素没有按照预期清除浮动。例如，在一个没有浮动元素的父元素上使用 `clear` 是无效的。
- **对边距折叠的误解:**  开发者可能期望相邻元素的边距总是会累加，而忽略了边距折叠的规则。这会导致元素之间的垂直间距与预期不符。
- **不理解自折叠元素的行为:**  自折叠元素（例如，空的块级元素没有内容，并且没有设置最小高度）在布局中表现特殊，可能导致开发者混淆其定位和尺寸。
- **在分片上下文中对布局的错误假设:**  在多列布局或分页中，元素的布局可能会受到分片的影响，开发者需要理解这些影响才能正确布局元素。
- **对 `text-box-trim` 属性理解不足:**  `text-box-trim` 属性会影响行盒的尺寸，开发者需要仔细考虑其对布局的影响，特别是与其他属性（如 `line-clamp`）结合使用时。

**总结（第 4 部分的功能）：**

`block_layout_algorithm.cc` 文件的第 4 部分是块级布局算法的核心，它负责**迭代地布局 BFC 中的每个子元素**，并完成布局后的关键处理步骤。它涵盖了计算子元素的初始布局数据、启动子元素的布局过程、处理布局结果（包括浮动清除、边距折叠、BFC 块偏移量解析、分片处理、行裁剪和文本框裁剪）、以及计算下一个子元素的起始位置。这部分代码直接实现了 CSS 布局规范中关于块级元素布局的核心逻辑，是 Blink 渲染引擎中至关重要的组成部分。

Prompt: 
```
这是目录为blink/renderer/core/layout/block_layout_algorithm.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第4部分，共6部分，请归纳一下它的功能

"""
 is_new_fc */ false);
  child_data.is_pushed_by_floats = is_pushed_by_floats;
  ConstraintSpace child_space = CreateConstraintSpaceForChild(
      child, child_break_token, child_data, ChildAvailableSize(),
      /* is_new_fc */ false, forced_bfc_block_offset,
      has_clearance_past_adjoining_floats,
      previous_inflow_position->block_end_annotation_space);
  const LayoutResult* layout_result =
      LayoutInflow(child_space, child_break_token, early_break_,
                   column_spanner_path_, &child, inline_child_layout_context);

  // To save space of the stack when we recurse into |BlockNode::Layout|
  // above, the rest of this function is continued within |FinishInflow|.
  // However it should be read as one function.
  return FinishInflow(child, child_break_token, child_space,
                      has_clearance_past_adjoining_floats,
                      std::move(layout_result), &child_data,
                      previous_inflow_position, inline_child_layout_context,
                      previous_inline_break_token);
}

LayoutResult::EStatus BlockLayoutAlgorithm::FinishInflow(
    LayoutInputNode child,
    const BreakToken* child_break_token,
    const ConstraintSpace& child_space,
    bool has_clearance_past_adjoining_floats,
    const LayoutResult* layout_result,
    InflowChildData* child_data,
    PreviousInflowPosition* previous_inflow_position,
    InlineChildLayoutContext* inline_child_layout_context,
    const InlineBreakToken** previous_inline_break_token) {
  // If a kNeedsLineClampRelayout layout result was not handled in
  // HandleNonSuccessfulLayoutResult, it needs to be propagated upwards until
  // the BFC root.
  if (layout_result->Status() == LayoutResult::kNeedsLineClampRelayout) {
    DCHECK_EQ(line_clamp_data_.data.state,
              LineClampData::kMeasureLinesUntilBfcOffset);
    container_builder_.SetLinesUntilClamp(layout_result->LinesUntilClamp());
    return LayoutResult::kNeedsLineClampRelayout;
  }

  std::optional<LayoutUnit> child_bfc_block_offset =
      layout_result->BfcBlockOffset();

  bool is_self_collapsing = layout_result->IsSelfCollapsing();

  // "Normal child" here means non-self-collapsing. Even self-collapsing
  // children may be cleared by floats, if they have a forced BFC block-offset.
  bool normal_child_had_clearance =
      layout_result->IsPushedByFloats() && !is_self_collapsing;

  // A child may have aborted its layout if it resolved its BFC block-offset.
  // If we don't have a BFC block-offset yet, we need to propagate the abort
  // signal up to our parent.
  if (layout_result->Status() == LayoutResult::kBfcBlockOffsetResolved &&
      !container_builder_.BfcBlockOffset()) {
    // There's no need to do anything apart from resolving the BFC block-offset
    // here, so make sure that it aborts before trying to position floats or
    // anything like that, which would just be waste of time.
    //
    // This is simply propagating an abort up to a node which is able to
    // restart the layout (a node that has resolved its BFC block-offset).
    DCHECK(child_bfc_block_offset);
    abort_when_bfc_block_offset_updated_ = true;

    LayoutUnit bfc_block_offset = *child_bfc_block_offset;

    if (normal_child_had_clearance) {
      // If the child has the same clearance-offset as ourselves it means that
      // we should *also* resolve ourselves at that offset, (and we also have
      // been pushed by floats).
      if (GetConstraintSpace().ClearanceOffset() ==
          child_space.ClearanceOffset()) {
        container_builder_.SetIsPushedByFloats();
      } else {
        bfc_block_offset = NextBorderEdge(*previous_inflow_position);
      }
    }

    // A new formatting-context may have previously tried to resolve the BFC
    // block-offset. In this case we'll have a "forced" BFC block-offset
    // present, but we shouldn't apply it (instead preferring the child's new
    // BFC block-offset).
    DCHECK(!GetConstraintSpace().AncestorHasClearancePastAdjoiningFloats());

    if (!ResolveBfcBlockOffset(previous_inflow_position, bfc_block_offset,
                               /* forced_bfc_block_offset */ std::nullopt)) {
      return LayoutResult::kBfcBlockOffsetResolved;
    }
  }

  // We have special behavior for a self-collapsing child which gets pushed
  // down due to clearance, see comment inside |ComputeInflowPosition|.
  bool self_collapsing_child_had_clearance =
      is_self_collapsing && has_clearance_past_adjoining_floats;

  // We try and position the child within the block formatting-context. This
  // may cause our BFC block-offset to be resolved, in which case we should
  // abort our layout if needed.
  if (!child_bfc_block_offset) {
    DCHECK(is_self_collapsing);
    if (child_space.HasClearanceOffset() && child.Style().HasClear()) {
      // This is a self-collapsing child that we collapsed through, so we have
      // to detect clearance manually. See if the child's hypothetical border
      // edge is past the relevant floats. If it's not, we need to apply
      // clearance before it.
      LayoutUnit child_block_offset_estimate =
          BfcBlockOffset() + layout_result->EndMarginStrut().Sum();
      if (child_block_offset_estimate < child_space.ClearanceOffset())
        self_collapsing_child_had_clearance = true;
    }
  }

  bool child_had_clearance =
      self_collapsing_child_had_clearance || normal_child_had_clearance;
  if (child_had_clearance) {
    // The child has clearance. Clearance inhibits margin collapsing and acts as
    // spacing before the block-start margin of the child. Our BFC block offset
    // is therefore resolvable, and if it hasn't already been resolved, we'll
    // do it now to separate the child's collapsed margin from this container.
    if (!ResolveBfcBlockOffset(previous_inflow_position))
      return LayoutResult::kBfcBlockOffsetResolved;
  } else if (layout_result->SubtreeModifiedMarginStrut()) {
    // The child doesn't have clearance, and modified its incoming
    // margin-strut. Propagate this information up to our parent if needed.
    SetSubtreeModifiedMarginStrutIfNeeded();
  }

  bool self_collapsing_child_needs_relayout = false;
  if (!child_bfc_block_offset) {
    // Layout wasn't able to determine the BFC block-offset of the child. This
    // has to mean that the child is self-collapsing.
    DCHECK(is_self_collapsing);

    if (container_builder_.BfcBlockOffset() &&
        layout_result->Status() == LayoutResult::kSuccess) {
      // Since we know our own BFC block-offset, though, we can calculate that
      // of the child as well.
      child_bfc_block_offset = PositionSelfCollapsingChildWithParentBfc(
          child, child_space, *child_data, *layout_result);

      // We may need to relayout this child if it had any (adjoining) objects
      // which were positioned in the incorrect place.
      if (layout_result->GetPhysicalFragment()
              .HasAdjoiningObjectDescendants() &&
          *child_bfc_block_offset != child_space.ExpectedBfcBlockOffset()) {
        self_collapsing_child_needs_relayout = true;
      }
    }
  } else if (!child_had_clearance && !is_self_collapsing) {
    // Only non self-collapsing children are allowed resolve their parent's BFC
    // block-offset. We check the BFC block-offset at the end of layout
    // determine if this fragment is self-collapsing.
    //
    // The child's BFC block-offset is known, and since there's no clearance,
    // this container will get the same offset, unless it has already been
    // resolved.
    if (!ResolveBfcBlockOffset(previous_inflow_position,
                               *child_bfc_block_offset))
      return LayoutResult::kBfcBlockOffsetResolved;
  }

  // We need to re-layout a self-collapsing child if it was affected by
  // clearance in order to produce a new margin strut. For example:
  // <div style="margin-bottom: 50px;"></div>
  // <div id="float" style="height: 50px;"></div>
  // <div id="zero" style="clear: left; margin-top: -20px;">
  //   <div id="zero-inner" style="margin-top: 40px; margin-bottom: -30px;">
  // </div>
  //
  // The end margin strut for #zero will be {50, -30}. #zero will be affected
  // by clearance (as 50 > {50, -30}).
  //
  // As #zero doesn't touch the incoming margin strut now we need to perform a
  // relayout with an empty incoming margin strut.
  //
  // The resulting margin strut in the above example will be {40, -30}. See
  // |ComputeInflowPosition| for how this end margin strut is used.
  if (self_collapsing_child_had_clearance) {
    MarginStrut margin_strut;
    margin_strut.Append(child_data->margins.block_start,
                        child.Style().HasMarginBlockStartQuirk());

    // We only need to relayout if the new margin strut is different to the
    // previous one.
    if (child_data->margin_strut != margin_strut) {
      child_data->margin_strut = margin_strut;
      self_collapsing_child_needs_relayout = true;
    }
  }

  // We need to layout a child if we know its BFC block offset and:
  //  - It aborted its layout as it resolved its BFC block offset.
  //  - It has some unpositioned floats.
  //  - It was affected by clearance.
  if ((layout_result->Status() == LayoutResult::kBfcBlockOffsetResolved ||
       self_collapsing_child_needs_relayout) &&
      child_bfc_block_offset) {
    // Assert that any clearance previously detected isn't lost.
    DCHECK(!child_data->is_pushed_by_floats ||
           layout_result->IsPushedByFloats());
    // If the child got pushed down by floats (normally because of clearance),
    // we need to carry over this state to the next layout pass, as clearance
    // won't automatically be detected then, since the BFC block-offset will
    // already be past the relevant floats.
    child_data->is_pushed_by_floats = layout_result->IsPushedByFloats();

    ConstraintSpace new_child_space = CreateConstraintSpaceForChild(
        child, child_break_token, *child_data, ChildAvailableSize(),
        /* is_new_fc */ false, child_bfc_block_offset);
    layout_result =
        LayoutInflow(new_child_space, child_break_token, early_break_,
                     column_spanner_path_, &child, inline_child_layout_context);

    if (layout_result->Status() == LayoutResult::kBfcBlockOffsetResolved) {
      // Even a second layout pass may abort, if the BFC block offset initially
      // calculated turned out to be wrong. This happens when we discover that
      // an in-flow block-level descendant that establishes a new formatting
      // context doesn't fit beside the floats at its initial position. Allow
      // one more pass.
      child_bfc_block_offset = layout_result->BfcBlockOffset();
      DCHECK(child_bfc_block_offset);

      // We don't expect clearance to be detected at this point. Any clearance
      // should already have been detected above.
      DCHECK(child_data->is_pushed_by_floats ||
             !layout_result->IsPushedByFloats());

      new_child_space = CreateConstraintSpaceForChild(
          child, child_break_token, *child_data, ChildAvailableSize(),
          /* is_new_fc */ false, child_bfc_block_offset);
      layout_result = LayoutInflow(new_child_space, child_break_token,
                                   early_break_, column_spanner_path_, &child,
                                   inline_child_layout_context);
    }

    DCHECK_EQ(layout_result->Status(), LayoutResult::kSuccess);

    // We stored this in a local variable, so it better not have changed.
    DCHECK_EQ(layout_result->IsSelfCollapsing(), is_self_collapsing);
  }

  const std::optional<LayoutUnit> line_box_bfc_block_offset =
      layout_result->LineBoxBfcBlockOffset();

  if (GetConstraintSpace().HasBlockFragmentation()) {
    // If the BFC block-offset is known both for this container and for the
    // child, breaking before may be possible, unless this is a resumed inline
    // formatting context in a parallel block flow. There are situations where
    // such parallel flows cannot be resumed, due to a float (that got pushed
    // from a previous fragmentainer) taking up all the available space in the
    // current fragmentainer, for instance. In such cases we'll just repropagate
    // the break tokens, by obtaining them from inline_child_layout_context
    // below.
    bool consider_breaking_before =
        container_builder_.BfcBlockOffset() && child_bfc_block_offset &&
        (!child.IsInline() || !child_break_token ||
         !To<InlineBreakToken>(child_break_token)->IsInParallelBlockFlow());

    if (consider_breaking_before) {
      bool is_line_box_pushed_by_floats =
          line_box_bfc_block_offset &&
          *line_box_bfc_block_offset > *child_bfc_block_offset;

      // Floats only cause container separation for the outermost block child
      // that gets pushed down (the container and the child may have adjoining
      // block-start margins).
      bool has_container_separation =
          has_break_opportunity_before_next_child_ ||
          (!container_builder_.IsPushedByFloats() &&
           (layout_result->IsPushedByFloats() || is_line_box_pushed_by_floats));

      // If this is a line with a block-in-inline, use the result for the
      // block-in-inline instead of that for the line. That's where we find the
      // relevant info for block fragmentation considerations, including the
      // block break token, if any.
      const LayoutResult& layout_result_to_use =
          container_builder_.LayoutResultForPropagation(*layout_result);

      BreakStatus break_status = BreakBeforeChildIfNeeded(
          child, layout_result_to_use, previous_inflow_position,
          line_box_bfc_block_offset.value_or(*child_bfc_block_offset),
          has_container_separation);

      if (child_space.ShouldForceTextBoxTrimEnd()) {
        // This is the line that we decided to come back to and trim, as an
        // attempt to fit it in the fragmentainer. This may or may not have
        // succeeded, but in any case, we can stop looking for a place to trim.
        ClearShouldTextBoxTrimEnd();
      }

      if (break_status == BreakStatus::kBrokeBefore) {
        // The line didn't fit, but if trimming is enabled, try again by
        // trimming the block-end side of the line box. It might fit
        // then. Otherwise we'll get here again and break before it.
        if (should_text_box_trim_fragmentainer_end_ && child.IsInline() &&
            !child_space.ShouldForceTextBoxTrimEnd()) {
          last_non_empty_inflow_child_ = To<InlineNode>(child);
          last_non_empty_break_token_ = child_break_token;
          return LayoutResult::kTextBoxTrimEndDidNotApply;
        } else {
          ClearShouldTextBoxTrimEnd();
        }
        return LayoutResult::kSuccess;
      }

      if (break_status == BreakStatus::kNeedsEarlierBreak) {
        return LayoutResult::kNeedsEarlierBreak;
      }
    }

    if (inline_child_layout_context) {
      for (auto token :
           inline_child_layout_context->ParallelFlowBreakTokens()) {
        container_builder_.AddBreakToken(std::move(token),
                                         /* is_in_parallel_flow */ true);
      }
    }
  }

  // It is now safe to update our version of the exclusion space, and any
  // propagated adjoining floats.
  container_builder_.SetExclusionSpace(layout_result->GetExclusionSpace());

  // Only self-collapsing children should have adjoining objects.
  DCHECK(!layout_result->GetAdjoiningObjectTypes() || is_self_collapsing);
  container_builder_.SetAdjoiningObjectTypes(
      layout_result->GetAdjoiningObjectTypes());

  // If we don't know our BFC block-offset yet, and the child stumbled into
  // something that needs it (unable to position floats yet), we need abort
  // layout, and trigger a re-layout once we manage to resolve it.
  //
  // NOTE: This check is performed after the optional second layout pass above,
  // since we may have been able to resolve our BFC block-offset (e.g. due to
  // clearance) and position any descendant floats in the second pass.
  // In particular, when it comes to clearance of self-collapsing children, if
  // we just applied it and resolved the BFC block-offset to separate the
  // margins before and after clearance, we cannot abort and re-layout this
  // child, or clearance would be lost.
  //
  // If we are a new formatting context, the child will get re-laid out once it
  // has been positioned.
  if (!container_builder_.BfcBlockOffset()) {
    abort_when_bfc_block_offset_updated_ |=
        layout_result->GetAdjoiningObjectTypes();
    // If our BFC block offset is unknown, and the child got pushed down by
    // floats, so will we.
    if (layout_result->IsPushedByFloats())
      container_builder_.SetIsPushedByFloats();
  }

  const auto& physical_fragment = layout_result->GetPhysicalFragment();
  LogicalFragment fragment(GetConstraintSpace().GetWritingDirection(),
                           physical_fragment);

  if (line_box_bfc_block_offset)
    child_bfc_block_offset = line_box_bfc_block_offset;

  LogicalOffset logical_offset = CalculateLogicalOffset(
      fragment, layout_result->BfcLineOffset(), child_bfc_block_offset);
  if (child.IsSliderThumb()) [[unlikely]] {
    logical_offset = AdjustSliderThumbInlineOffset(fragment, logical_offset);
  }

  if (!PositionOrPropagateListMarker(*layout_result, &logical_offset,
                                     previous_inflow_position))
    return LayoutResult::kBfcBlockOffsetResolved;

  if (physical_fragment.IsLineBox()) {
    PropagateBaselineFromLineBox(physical_fragment,
                                 logical_offset.block_offset);
  } else {
    PropagateBaselineFromBlockChild(physical_fragment, child_data->margins,
                                    logical_offset.block_offset);
  }

  if (IsA<BlockNode>(child)) {
    container_builder_.AddResult(*layout_result, logical_offset,
                                 child_data->margins);
  } else {
    container_builder_.AddResult(*layout_result, logical_offset);
  }

  if (!child_break_token || !child_break_token->IsInParallelFlow()) {
    *previous_inflow_position = ComputeInflowPosition(
        *previous_inflow_position, child, *child_data, child_bfc_block_offset,
        logical_offset, *layout_result, fragment,
        self_collapsing_child_had_clearance);
  }

  const InlineBreakToken* outgoing_inline_break_token = nullptr;
  if (child.IsInline()) {
    outgoing_inline_break_token =
        To<InlineBreakToken>(physical_fragment.GetBreakToken());
  }
  *previous_inline_break_token = outgoing_inline_break_token;

  // Update |line_clamp_data_| from the LayoutResult, and abort if needed.
  // If the BFC block offset hasn't been resolved, the child we just laid out
  // must be empty (no lines and zero block size), so we can skip the update.
  if (auto bfc_block_offset = container_builder_.BfcBlockOffset()) {
    if (!line_clamp_data_.UpdateAfterLayout(layout_result, *bfc_block_offset,
                                            *previous_inflow_position,
                                            Padding().block_end)) {
      container_builder_.SetLinesUntilClamp(
          line_clamp_data_.LinesUntilClamp(/*show_measured_lines*/ true));
      return LayoutResult::kNeedsLineClampRelayout;
    }
  }

  if (ShouldTextBoxTrim()) [[unlikely]] {
    should_text_box_trim_fragmentainer_start_ = false;
    // Update `should_text_box_trim_{start,end}_` if the child `layout_result`
    // has applied `text-box-trim`, or was meant to apply it.
    if (should_text_box_trim_node_start_) {
      if (!child.IsInline() || !outgoing_inline_break_token ||
          outgoing_inline_break_token->IsPastFirstFormattedLine()) {
        should_text_box_trim_node_start_ = false;
      }
    }
    if (should_text_box_trim_node_end_) {
      if (line_clamp_data_.data.state ==
              LineClampData::kMeasureLinesUntilBfcOffset &&
          layout_result->TrimBlockEndBy() &&
          layout_result->GetPhysicalFragment().GetBreakToken()) {
        // If we trimmed the end only because we're in the first layout of a
        // line-clamp: auto context, and we might not trim in the relayout, then
        // we don't reset should_text_box_trim_node_end_, and we add the trim
        // length to the logical block offset so next lines are set in the right
        // position.
        previous_inflow_position->logical_block_offset +=
            *layout_result->TrimBlockEndBy();
      } else if (layout_result->IsBlockEndTrimmableLine() ||
                 (child.IsBlock() &&
                  IsLastInflowChild(*child.GetLayoutBox()))) {
        ClearShouldTextBoxTrimEnd();
      } else if (!layout_result->IsSelfCollapsing() && child.IsInline() &&
                 !override_text_box_trim_end_child_) {
        // Keep the last non-empty child for `RelayoutForTextBoxTrimEnd`.
        last_non_empty_inflow_child_ = To<InlineNode>(child);
        last_non_empty_break_token_ = child_break_token;
      }
    }
  }

  if (GetConstraintSpace().HasBlockFragmentation() &&
      !has_break_opportunity_before_next_child_) {
    has_break_opportunity_before_next_child_ =
        HasBreakOpportunityBeforeNextChild(physical_fragment,
                                           child_break_token);
  }

  return LayoutResult::kSuccess;
}

InflowChildData BlockLayoutAlgorithm::ComputeChildData(
    const PreviousInflowPosition& previous_inflow_position,
    LayoutInputNode child,
    const BreakToken* child_break_token,
    bool is_new_fc) {
  DCHECK(child);
  DCHECK(!child.IsFloating());
  DCHECK_EQ(is_new_fc, child.CreatesNewFormattingContext());

  // Calculate margins in parent's writing mode.
  LayoutUnit additional_line_offset;
  BoxStrut margins =
      CalculateMargins(child, is_new_fc, &additional_line_offset);

  // Append the current margin strut with child's block start margin.
  // Non empty border/padding, and new formatting-context use cases are handled
  // inside of the child's layout
  MarginStrut margin_strut = previous_inflow_position.margin_strut;

  LayoutUnit logical_block_offset =
      previous_inflow_position.logical_block_offset;

  const auto* child_block_break_token =
      DynamicTo<BlockBreakToken>(child_break_token);
  if (child_block_break_token) [[unlikely]] {
    AdjustMarginsForFragmentation(child_block_break_token, &margins);
    if (child_block_break_token->IsForcedBreak()) {
      // After a forced fragmentainer break we need to reset the margin strut,
      // in case it was set to discard all margins (which is the default at
      // breaks). Margins after a forced break should be retained.
      margin_strut = MarginStrut();
    }

    if (child_block_break_token->MonolithicOverflow() &&
        (Node().IsPaginatedRoot() || !GetBreakToken()->MonolithicOverflow())) {
      // Every container that needs to be pushed to steer clear of monolithic
      // overflow on a previous page will have this stored in its break token.
      // So we'll only add the additional offset here if the child is the
      // outermost container with monolithic overflow recorded.
      logical_block_offset += child_block_break_token->MonolithicOverflow();
    }
  }

  margin_strut.Append(margins.block_start,
                      child.Style().HasMarginBlockStartQuirk());
  if (child.IsBlock())
    SetSubtreeModifiedMarginStrutIfNeeded(&child.Style().MarginBlockStart());

  TextDirection direction = GetConstraintSpace().Direction();
  BfcOffset child_bfc_offset = {
      GetConstraintSpace().GetBfcOffset().line_offset +
          BorderScrollbarPadding().LineLeft(direction) +
          additional_line_offset + margins.LineLeft(direction),
      BfcBlockOffset() + logical_block_offset};

  return InflowChildData(child_bfc_offset, margin_strut, margins);
}

PreviousInflowPosition BlockLayoutAlgorithm::ComputeInflowPosition(
    const PreviousInflowPosition& previous_inflow_position,
    const LayoutInputNode child,
    const InflowChildData& child_data,
    const std::optional<LayoutUnit>& child_bfc_block_offset,
    const LogicalOffset& logical_offset,
    const LayoutResult& layout_result,
    const LogicalFragment& fragment,
    bool self_collapsing_child_had_clearance) {
  // Determine the child's end logical offset, for the next child to use.
  LayoutUnit logical_block_offset;
  std::optional<LayoutUnit> clearance_after_line;
  std::optional<LayoutUnit> trim_block_end_by;

  const bool is_self_collapsing = layout_result.IsSelfCollapsing();
  if (is_self_collapsing) {
    // The default behavior for self-collapsing children is they just pass
    // through the previous inflow position.
    logical_block_offset = previous_inflow_position.logical_block_offset;

    if (self_collapsing_child_had_clearance) {
      // If there's clearance, we must have applied that by now and thus
      // resolved our BFC block-offset.
      DCHECK(container_builder_.BfcBlockOffset());
      DCHECK(child_bfc_block_offset.has_value());

      // If a self-collapsing child was affected by clearance (that is it got
      // pushed down past a float), we need to do something slightly bizarre.
      //
      // Instead of just passing through the previous inflow position, we make
      // the inflow position our new position (which was affected by the
      // float), minus what the margin strut which the self-collapsing child
      // produced.
      //
      // Another way of thinking about this is that when you *add* back the
      // margin strut, you end up with the same position as you started with.
      //
      // This is essentially what the spec refers to as clearance [1], and,
      // while we normally don't have to calculate it directly, in the case of
      // a self-collapsing cleared child like here, we actually have to.
      //
      // We have to calculate clearance for self-collapsing cleared children,
      // because we need the margin that's between the clearance and this block
      // to collapse correctly with subsequent content. This is something that
      // needs to take place after the margin strut preceding and following the
      // clearance have been separated. Clearance may be positive, negative or
      // zero, depending on what it takes to (hypothetically) place this child
      // just below the last relevant float. Since the margins before and after
      // the clearance have been separated, we may have to pull the child back,
      // and that's an example of negative clearance.
      //
      // (In the other case, when a cleared child is non self-collapsing (i.e.
      // when we don't end up here), we don't need to explicitly calculate
      // clearance, because then we just place its border edge where it should
      // be and we're done with it.)
      //
      // [1] https://www.w3.org/TR/CSS22/visuren.html#flow-control

      // First move past the margin that is to precede the clearance. It will
      // not participate in any subsequent margin collapsing.
      LayoutUnit margin_before_clearance =
          previous_inflow_position.margin_strut.Sum();
      logical_block_offset += margin_before_clearance;

      // Calculate and apply actual clearance.
      LayoutUnit clearance = *child_bfc_block_offset -
                             layout_result.EndMarginStrut().Sum() -
                             NextBorderEdge(previous_inflow_position);
      logical_block_offset += clearance;
    }
    if (!container_builder_.BfcBlockOffset())
      DCHECK_EQ(logical_block_offset, LayoutUnit());
  } else {
    logical_block_offset = logical_offset.block_offset + fragment.BlockSize();

    clearance_after_line = layout_result.ClearanceAfterLine();
    trim_block_end_by = layout_result.TrimBlockEndBy();
    if (trim_block_end_by) {
      // Trim the space to respect the `text-box-trim` property here. Objects
      // that pushes following boxes down (e.g., Ruby annotations) are also
      // trimmed.
      logical_block_offset -= *trim_block_end_by;

      if (clearance_after_line) {
        // `<br>` with clearance is an exception. It still pushes down, after
        // all other objects are trimmed. See `AddAnyClearanceAfterLine()`.
        logical_block_offset += *clearance_after_line;
      }
    } else {
      // We add the greater of AnnotationOverflow and ClearanceAfterLine here.
      // Then, we cancel the AnnotationOverflow part if
      //  - The next line box has block-start annotation space, or
      //  - There are no following child boxes and this container has block-end
      //    padding.
      //
      // See InlineLayoutAlgorithm::CreateLine() and
      // BlockLayoutAlgorithm::Layout().
      logical_block_offset +=
          std::max(layout_result.AnnotationOverflow(),
                   clearance_after_line.value_or(LayoutUnit()));
    }
  }

  MarginStrut margin_strut = layout_result.EndMarginStrut();

  // Self collapsing child's end margin can "inherit" quirkiness from its start
  // margin. E.g.
  // <ol style="margin-bottom: 20px"></ol>
  bool is_quirky =
      (is_self_collapsing && child.Style().HasMarginBlockStartQuirk()) ||
      child.Style().HasMarginBlockEndQuirk();
  margin_strut.Append(child_data.margins.block_end, is_quirky);
  if (child.IsBlock())
    SetSubtreeModifiedMarginStrutIfNeeded(&child.Style().MarginBlockEnd());

  if (GetConstraintSpace().HasBlockFragmentation()) [[unlikely]] {
    // If the child broke inside, don't apply any trailing margin, since it's
    // only to be applied to the last fragment that's not in a parallel flow
    // (due to overflow). While trailing margins are normally truncated at
    // fragmentainer boundaries, so that whether or not we add such margins
    // doesn't really make much of a difference, this isn't the case in the
    // initial column balancing pass.
    if (const auto* physical_fragment = DynamicTo<PhysicalBoxFragment>(
            &layout_result.GetPhysicalFragment())) {
      if (const BlockBreakToken* token = physical_fragment->GetBreakToken()) {
        // TODO(mstensho): Don't apply the margin to all overflowing fragments
        // (if any). It should only be applied after the fragment where we
        // reached the block-end of the node.
        if (!token->IsAtBlockEnd())
          margin_strut = MarginStrut();
      }
    }
  }

  // This flag is subtle, but in order to determine our size correctly we need
  // to check if our last child is self-collapsing, and it was affected by
  // clearance *or* an adjoining self-collapsing sibling was affected by
  // clearance. E.g.
  // <div id="container">
  //   <div id="float"></div>
  //   <div id="zero-with-clearance"></div>
  //   <div id="another-zero"></div>
  // </div>
  // In the above case #container's size will depend on the end margin strut of
  // #another-zero, even though usually it wouldn't.
  bool self_or_sibling_self_collapsing_child_had_clearance =
      self_collapsing_child_had_clearance ||
      (previous_inflow_position.self_collapsing_child_had_clearance &&
       is_self_collapsing);

  LayoutUnit annotation_space;
  if (!is_self_collapsing && !trim_block_end_by) {
    annotation_space = layout_result.BlockEndAnnotationSpace();
    if (layout_result.AnnotationOverflow() > LayoutUnit()) {
      DCHECK(!annotation_space);
      // Allow the portion of the annotation overflow that isn't also part of
      // clearance to overlap with certain types of subsequent content.
      annotation_space = -std::max(
          LayoutUnit(), layout_result.AnnotationOverflow() -
                            clearance_after_line.value_or(LayoutUnit()));
    }
  }

  return {logical_block_offset, margin_strut, annotation_space,
          self_or_sibling_self_collapsing_child_had_clearance};
}

LayoutUnit BlockLayoutAlgorithm::PositionSelfCollapsingChildWithParentBfc(
    const LayoutInputNode& child,
    const ConstraintSpace& child_space,
    const InflowChildData& child_data,
    const LayoutResult& layout_result) const {
  DCHECK(layout_result.IsSelfCollapsing());

  // The child must be an in-flow zero-block-size fragment, use its end margin
  // strut for positioning.
  LayoutUnit child_bfc_block_offset =
      child_data.bfc_offset_estimate.block_offset +
      layout_result.EndMarginStrut().Sum();

  ApplyClearance(child_space, &child_bfc_block_offset);

  return child_bfc_block_offset;
}

void BlockLayoutAlgorithm::ConsumeRemainingFragmentainerSpace(
    PreviousInflowPosition* previous_inflow_position) {
  if (GetConstraintSpace().HasKnownFragmentainerBlockSize()) {
    // The remaining part of the fragmentainer (the unusable space for child
    // content, due to the break) should still be occupied by this
    // container
"""


```