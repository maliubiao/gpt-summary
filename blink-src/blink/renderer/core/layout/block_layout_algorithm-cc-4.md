Response:
My thinking process for summarizing the provided code snippet went through these stages:

1. **Initial Scan and Identification of Key Class:** The first step was to confirm the file name and the core class being discussed: `BlockLayoutAlgorithm`. This immediately tells me the code deals with the layout of block-level elements.

2. **Decomposition by Function/Method:**  I then scanned through the code, paying attention to individual functions or methods. I looked for keywords like `void`, `BreakStatus`, `bool`, etc., to identify function boundaries. I noted down the names of the functions that appeared frequently or seemed significant. Examples include `FinalizeForFragmentation`, `BreakBeforeChildIfNeeded`, `UpdateEarlyBreakBetweenLines`, `CalculateMargins`, `CreateConstraintSpaceForChild`, `PropagateBaselineFromLineBox`, `ResolveBfcBlockOffset`.

3. **Understanding Individual Function Purpose (High-Level):**  For each identified function, I tried to grasp its main objective based on its name and the code within it. I focused on the "what" rather than the "how" at this stage. For instance:
    * `FinalizeForFragmentation`: Seemed related to handling how content is split across pages or columns.
    * `BreakBeforeChildIfNeeded`: Likely determines if a break is needed before a child element.
    * `CalculateMargins`:  Deals with calculating the margins of elements.
    * `CreateConstraintSpaceForChild`:  Focuses on setting up the constraints for laying out child elements.
    * `PropagateBaselineFromLineBox`: Related to establishing the baseline for text alignment.
    * `ResolveBfcBlockOffset`:  Deals with determining the vertical position of a block formatting context.

4. **Identifying Relationships and Dependencies:** I looked for connections between the functions. For example, `BreakBeforeChildIfNeeded` calls `CalculateBreakAppealBefore`, suggesting a decision-making process for breaking. The frequent use of `container_builder_` indicated it's a central object for managing the layout process. The presence of `BreakStatus` as a return type in several functions highlighted the importance of the fragmentation/breaking logic.

5. **Inferring Overall Functionality:** By combining the understanding of individual functions and their relationships, I started to infer the overall functionality of the `BlockLayoutAlgorithm`. It became clear that it's responsible for:
    * **Block Layout Core:**  The fundamental task of positioning block-level elements.
    * **Fragmentation/Pagination:**  Handling how content is broken across multiple fragments (like pages or columns).
    * **Margin Handling:**  Calculating and applying margins.
    * **Baseline Alignment:**  Ensuring proper vertical alignment of text.
    * **Constraint Management:**  Setting up the constraints and environment for laying out child elements.
    * **Break Logic:** Determining where and how to break content.

6. **Connecting to Web Technologies (HTML, CSS, JavaScript):** I considered how the functions relate to the core web technologies:
    * **CSS:**  Margin calculations directly relate to CSS margin properties. Break properties like `page-break-before`, `page-break-after`, `orphans`, and `widows` are handled by the fragmentation logic. `text-align` influences margin calculations.
    * **HTML:** The structure of the HTML document (parent-child relationships) is crucial for the layout process. Specific HTML elements like `table`, list items, and the `body` are handled differently.
    * **JavaScript:** While the provided code is C++, the layout engine's results directly impact how JavaScript interacts with the DOM and how elements are visually rendered. JavaScript can trigger relayouts through DOM manipulation or style changes.

7. **Identifying Potential User/Developer Errors:**  I considered scenarios where incorrect CSS or DOM manipulation could lead to issues:
    * Incorrect or conflicting break properties.
    *  Issues with `orphans` and `widows` leading to unexpected breaking.
    *  Problems with margin collapsing.
    *  Unexpected behavior with floated elements and clearance.

8. **Focusing on the Specific Snippet:** I paid close attention to the details within the provided code extract, particularly the logic within the `FinalizeForFragmentation` and `BreakBeforeChildIfNeeded` functions, as they seemed to be central to the snippet's purpose. The handling of `orphans` and `widows`, the `EarlyBreak` mechanism, and the interaction with `container_builder_` were key takeaways.

9. **Structuring the Summary:** Finally, I organized my understanding into a coherent summary, covering the key functions, their relationships to web technologies, examples, and potential errors. I made sure to address the "part 5 of 6" instruction by providing a summarizing statement.

**Self-Correction/Refinement during the process:**

* Initially, I might have focused too much on the low-level implementation details. I had to step back and focus on the high-level purpose of each function.
* I initially overlooked the significance of the `container_builder_`. Recognizing its role as a central data structure was crucial.
* I realized the importance of explicitly connecting the code functions to specific CSS properties and HTML elements to make the explanation more concrete.
* I made sure to provide concrete examples for the relationships with HTML, CSS, and JavaScript and for common errors.

By following these steps, I could analyze the C++ code snippet and provide a comprehensive summary of its functionality, its connections to web technologies, and potential issues.
这是 `blink/renderer/core/layout/block_layout_algorithm.cc` 文件的第五部分，主要关注于**块级盒子的布局算法中与分片（fragmentation）和基线（baseline）相关的逻辑**。

综合前后的代码，这一部分的核心功能可以归纳为：

**1. 分片完成和断点决策 (FinalizeForFragmentation, BreakBeforeChildIfNeeded, UpdateEarlyBreakBetweenLines):**

* **`FinalizeForFragmentation()`:**  这是在块级盒子的内容布局完成后，为进行分片做最终处理的函数。
    * **防止表格单元格断裂:**  针对表格单元格，阻止在尾部装饰（边框、内边距）之前断裂，避免影响表格行的拉伸机制。
    * **处理行内格式化上下文根元素 (Inline Formatting Context Root):**  如果当前节点是行内格式化上下文的根元素，并且存在块级分片，则会检查是否需要提前断裂。
        * **检查内部子元素是否需要断裂:** 如果子元素内部需要断裂 (`HasInflowChildBreakInside()`) 或者已经出现溢出行 (`first_overflowing_line_`)，则可能需要提前断裂。
        * **处理孤儿寡妇 (Orphans and Widows):** 如果所有行都能放入当前分片容器，但为了满足 `orphans` 和 `widows` 属性的要求，可能需要在两行之间找到最佳的断裂位置。
        * **设置提前断裂点:**  创建一个 `EarlyBreak` 对象，指示需要在哪个行号提前断裂。
    * **完成分片容器的处理:** 如果当前节点是分片容器，调用 `FinishFragmentationForFragmentainer`。
    * **完成普通分片:** 否则，调用 `FinishFragmentation`。
* **`BreakBeforeChildIfNeeded()`:** 决定是否需要在子元素之前断裂以适应分片容器的剩余空间。
    * **检查是否强制断裂:** 根据子元素的 `break-before` 或父元素的 `break-inside` 属性判断是否需要强制断裂。
    * **计算断裂吸引力 (Break Appeal):**  计算在子元素之前断裂的吸引力程度。
    * **移动过断点并评估:** 尝试跳过断点，如果可以跳过，则评估在该点断裂的吸引力。
    * **处理软断裂:** 如果不能跳过断点，尝试插入一个软断裂。这会考虑孤儿寡妇规则，并可能需要在更早的兄弟元素处断裂。
    * **处理行盒:**  针对行盒（inline 内容），处理空间不足的情况，并尝试遵守孤儿寡妇规则。
* **`UpdateEarlyBreakBetweenLines()`:**  如果没有确定断裂点，则计算在两行之间断裂的最佳位置和吸引力，以满足 `orphans` 和 `widows` 属性。

**2. 计算和处理边距 (CalculateMargins):**

* **`CalculateMargins()`:** 计算子元素的边距。
    * **区分块级和行内元素:** 对块级和行内元素进行不同的处理。
    * **处理 auto 边距:**  解析 `margin-inline-start: auto` 和 `margin-inline-end: auto` 的情况。
    * **处理 `-webkit-text-align` 和 `justify-self` 的偏移:** 计算由于这些属性产生的偏移。

**3. 创建子元素的约束空间 (CreateConstraintSpaceForChild):**

* **`CreateConstraintSpaceForChild()`:**  为子元素创建布局约束空间 `ConstraintSpace`，这是布局算法的关键输入。
    * **继承父元素的约束:**  从父元素的约束空间继承属性。
    * **处理书写模式 (Writing Mode):**  考虑父子元素的书写模式是否平行。
    * **处理 auto 尺寸:**  根据 `justify-self` 属性和是否是块级容器的子元素来设置 `inline-auto` 的行为。
    * **处理表格单元格子元素:** 特殊处理表格单元格的子元素，例如强制 shrink-to-fit。
    * **传递 BFC 偏移:**  传递块级格式化上下文 (BFC) 的偏移信息。
    * **处理浮动清除 (Clearance):** 传递清除浮动所需的偏移量。
    * **处理基线对齐方式 (Baseline Algorithm Type):** 传递基线对齐方式。
    * **传递文本框裁剪 (Text Box Trim) 信息:** 传递 `text-box-trim` 和 `text-box-edge` 相关的信息。
    * **处理分片相关信息:**  传递分片容器的偏移信息，以及是否处于列布局或需要强制断裂等信息。

**4. 传播基线信息 (PropagateBaselineFromLineBox, PropagateBaselineFromBlockChild):**

* **`PropagateBaselineFromLineBox()`:** 从行盒中提取基线信息并传播给父元素。
* **`PropagateBaselineFromBlockChild()`:** 从块级子元素中提取基线信息并传播给父元素。
    * **处理 inline-block 和 table 的基线:**  针对 `inline-block` 元素和表格元素的基线传播进行特殊处理。

**5. 解析 BFC 块偏移 (ResolveBfcBlockOffset):**

* **`ResolveBfcBlockOffset()`:** 解析块级格式化上下文 (BFC) 的块偏移量。
    * **应用清除浮动的影响:**  考虑清除浮动对 BFC 偏移的影响。
    * **设置 BFC 块偏移:**  设置容器构建器 (`container_builder_`) 的 BFC 块偏移。
    * **处理 BFC 偏移变化导致的重新布局:** 如果 BFC 偏移与预期不同，并且需要中止布局，则返回 `false`。

**6. 其他辅助功能:**

* **`NeedsAbortOnBfcBlockOffsetChange()`:**  检查是否需要因为 BFC 块偏移的改变而中止布局。
* **`CalculateQuirkyBodyMarginBlockSum()`:**  针对 Quirks 模式下的 `<body>` 元素计算特殊的边距总和。
* **`PositionOrPropagateListMarker()`:**  定位或向上级传播未定位的列表标记。

**与 JavaScript, HTML, CSS 的关系：**

* **CSS:**
    * **分片属性:**  `page-break-before`, `page-break-after`, `break-inside`, `orphans`, `widows`, `column-span` 等 CSS 属性直接影响 `FinalizeForFragmentation` 和 `BreakBeforeChildIfNeeded` 的逻辑。
        * **例子:**  如果 CSS 设置了 `break-inside: avoid;`，`BreakBeforeChildIfNeeded` 会尽量避免在该元素内部断裂。
    * **边距属性:** `margin-top`, `margin-bottom`, `margin-left`, `margin-right`, 以及逻辑属性 `margin-inline-start`, `margin-inline-end` 等，直接由 `CalculateMargins` 处理。
        * **例子:**  `margin-left: auto; margin-right: auto;` 会导致块级元素水平居中，`CalculateMargins` 中的 `ResolveInlineAutoMargins` 会处理这种情况。
    * **文本对齐属性:** `text-align` (特别是 `-webkit-text-align`) 和 `justify-self` 影响 `CalculateMargins` 中边距的计算。
        * **例子:**  `text-align: center;` 可能会影响子元素的起始位置。
    * **基线对齐属性:** `vertical-align: baseline;` 等属性会影响基线的计算和传播，与 `PropagateBaselineFromLineBox` 和 `PropagateBaselineFromBlockChild` 相关。
        * **例子:**  行内元素的基线对齐方式会影响它们在行盒中的垂直位置。
    * **列表属性:** `list-style-type`, `list-style-position` 等属性影响 `PositionOrPropagateListMarker` 的行为。
        * **例子:**  `list-style-position: inside;` 会将列表标记放置在内容区域内部。
    * **文本框裁剪属性:** `text-box-trim`, `text-box-edge` 等属性会影响 `CreateConstraintSpaceForChild` 中相关信息的传递。
        * **例子:**  `text-box-trim: both;` 会裁剪文本框的顶部和底部空白。
* **HTML:**
    * **元素类型:** 代码中会判断元素的类型，例如 `Node().IsTableCell()`, `Node().IsInlineFormattingContextRoot()`, `child.IsInline()`, `child.IsBlock()`, `Node().IsBody()` 等，不同的 HTML 元素类型有不同的布局规则。
        * **例子:**  表格单元格的断裂处理方式与普通块级元素不同。
    * **DOM 结构:** 父子元素的关系对于布局至关重要，例如在 `BreakBeforeChildIfNeeded` 中判断是否需要在子元素前断裂。
* **JavaScript:**
    * JavaScript 可以动态修改元素的样式和 DOM 结构，这些修改会触发布局的重新计算，包括 `BlockLayoutAlgorithm` 的执行。
        * **例子:**  使用 JavaScript 修改元素的 `margin` 属性会导致重新调用 `CalculateMargins`。
        * **例子:**  使用 JavaScript 插入或删除元素会触发布局更新，并可能导致重新进行分片计算。

**逻辑推理的假设输入与输出：**

**假设输入 (针对 `BreakBeforeChildIfNeeded`)：**

* 当前分片容器剩余空间有限。
* 正在布局一个块级子元素，该子元素具有 `break-before: always;` 的 CSS 属性。
* `fragmentainer_block_offset`：当前分片容器的块偏移量。
* `FragmentainerCapacityForChildren()`：当前分片容器剩余的可用空间。

**输出：**

* `BreakStatus::kBrokeBefore`：表示在子元素之前发生了断裂。
* 调用 `BreakBeforeChild()` 函数，将子元素放到新的分片中。
* `ConsumeRemainingFragmentainerSpace(previous_inflow_position)` 被调用，表示当前分片容器的剩余空间已被消耗。

**常见的使用错误举例：**

1. **不合理的 `orphans` 和 `widows` 设置:**  设置过大的 `orphans` 或 `widows` 值，可能导致即使有足够的空间，也无法将内容放在一个分片中，或者产生过多的空白。
    * **例子:** 设置 `orphans: 10;`，但每个分片只能容纳 5 行文本，会导致一直尝试寻找更早的断点，可能造成性能问题。
2. **强制断裂属性冲突:**  在父元素和子元素上设置冲突的断裂属性，例如父元素 `break-inside: avoid;`，子元素 `break-before: always;`，可能会导致意想不到的布局结果。
3. **过度依赖 `auto` 边距而不理解其行为:**  不理解 `auto` 边距在不同情况下的计算方式，可能导致元素没有按照预期进行居中或对齐。
4. **错误地假设分片总是发生在元素边界:**  行内元素也可能被分片，尤其是在空间不足的情况下。

**功能归纳 (第 5 部分):**

这部分 `BlockLayoutAlgorithm` 的代码主要负责**处理块级盒子在分片场景下的最终调整和断点决策**，以及**计算和传播影响布局的边距和基线信息**。它确保了内容能够正确地分割到不同的分片容器中，并保证了文本的垂直对齐。同时，它也负责为子元素的布局准备必要的约束条件，是块级盒子布局算法中至关重要的一个环节，与 CSS 的分片、边距、文本和列表等属性紧密相关。

Prompt: 
```
这是目录为blink/renderer/core/layout/block_layout_algorithm.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第5部分，共6部分，请归纳一下它的功能

"""
. Also encompass fragmentainer overflow (may be caused by
    // monolithic content).
    previous_inflow_position->logical_block_offset =
        std::max(previous_inflow_position->logical_block_offset,
                 FragmentainerSpaceLeftForChildren());
  }
}

BreakStatus BlockLayoutAlgorithm::FinalizeForFragmentation() {
  if (Node().IsTableCell()) {
    // For table cells, prevent breaking before trailing box decorations, as
    // that might disturb the row stretching machinery, causing an infinite
    // loop. We'd add the stretch amount to the block-size to the content box of
    // the table cell, even though we're past it.
    container_builder_.SetShouldPreventBreakBeforeBlockEndDecorations(true);
  }

  if (Node().IsInlineFormattingContextRoot() && !early_break_ &&
      GetConstraintSpace().HasBlockFragmentation()) {
    if (container_builder_.HasInflowChildBreakInside() ||
        first_overflowing_line_) {
      if (first_overflowing_line_ &&
          first_overflowing_line_ < container_builder_.LineCount()) {
        int line_number;
        if (fit_all_lines_) {
          line_number = first_overflowing_line_;
        } else {
          // We managed to finish layout of all the lines for the node, which
          // means that we won't have enough widows, unless we break earlier
          // than where we overflowed.
          int line_count = container_builder_.LineCount();
          line_number = std::max(line_count - Style().Widows(),
                                 std::min(line_count, int(Style().Orphans())));
        }
        // We need to layout again, and stop at the right line number.
        const auto* breakpoint =
            MakeGarbageCollected<EarlyBreak>(line_number, kBreakAppealPerfect);
        container_builder_.SetEarlyBreak(breakpoint);
        return BreakStatus::kNeedsEarlierBreak;
      }
    } else {
      // Everything could fit in the current fragmentainer, but, depending on
      // what comes after, the best location to break at may be between two of
      // our lines.
      UpdateEarlyBreakBetweenLines();
    }
  }

  if (container_builder_.IsFragmentainerBoxType()) {
    return FinishFragmentationForFragmentainer(&container_builder_);
  }

  return FinishFragmentation(&container_builder_);
}

BreakStatus BlockLayoutAlgorithm::BreakBeforeChildIfNeeded(
    LayoutInputNode child,
    const LayoutResult& layout_result,
    PreviousInflowPosition* previous_inflow_position,
    LayoutUnit bfc_block_offset,
    bool has_container_separation) {
  DCHECK(GetConstraintSpace().HasBlockFragmentation());

  // If the BFC offset is unknown, there's nowhere to break, since there's no
  // non-empty child content yet (as that would have resolved the BFC offset).
  DCHECK(container_builder_.BfcBlockOffset());

  LayoutUnit fragmentainer_block_offset =
      FragmentainerOffsetAtBfc(container_builder_) + bfc_block_offset -
      layout_result.AnnotationBlockOffsetAdjustment();

  if (has_container_separation) {
    EBreakBetween break_between =
        CalculateBreakBetweenValue(child, layout_result, container_builder_);
    if (IsForcedBreakValue(GetConstraintSpace(), break_between)) {
      BreakBeforeChild(GetConstraintSpace(), child, &layout_result,
                       fragmentainer_block_offset,
                       FragmentainerCapacityForChildren(), kBreakAppealPerfect,
                       /* is_forced_break */ true, &container_builder_);
      ConsumeRemainingFragmentainerSpace(previous_inflow_position);
      return BreakStatus::kBrokeBefore;
    }
  }

  BreakAppeal appeal_before =
      CalculateBreakAppealBefore(GetConstraintSpace(), child, layout_result,
                                 container_builder_, has_container_separation);

  // Attempt to move past the break point, and if we can do that, also assess
  // the appeal of breaking there, even if we didn't.
  if (MovePastBreakpoint(child, layout_result, fragmentainer_block_offset,
                         appeal_before)) {
    return BreakStatus::kContinue;
  }

  // Figure out where to insert a soft break. It will either be before this
  // child, or before an earlier sibling, if there's a more appealing breakpoint
  // there.

  // Handle line boxes - propagate space shortage and attempt to honor orphans
  // and widows (or detect violations). Skip this part if we didn't produce a
  // fragment (status != kSuccess). The latter happens with BR clear=all if we
  // need to push it to a later fragmentainer to get past floats. BR clear="all"
  // adds clearance *after* the contents (the line), unlike regular CSS
  // clearance, which adds clearance *before* the contents). To handle this
  // corner-case as simply as possible, we'll break (line-wise AND block-wise)
  // before a BR clear=all element, and add it in the fragmentainer where the
  // relevant floats end. This means that we might get an additional line box
  // (to simply hold the BR clear=all), that should be ignored as far as orphans
  // and widows are concerned. Just give up instead, and break before it.
  //
  // Orphans and widows affect column balancing, and if we get imperfect breaks
  // (such as widows / orphans violations), we'll attempt to stretch the
  // columns, and without this exception for BR clear=all, we'd end up
  // stretching to fit the entire float(s) (that could otherwise be broken
  // nicely into fragments) in a single column.
  if (child.IsInline() && layout_result.Status() == LayoutResult::kSuccess) {
    if (!first_overflowing_line_) {
      // We're at the first overflowing line. This is the space shortage that
      // we are going to report. We do this in spite of not yet knowing
      // whether breaking here would violate orphans and widows requests. This
      // approach may result in a lower space shortage than what's actually
      // true, which leads to more layout passes than we'd otherwise
      // need. However, getting this optimal for orphans and widows would
      // require an additional piece of machinery. This case should be rare
      // enough (to worry about performance), so let's focus on code
      // simplicity instead.
      PropagateSpaceShortage(
          GetConstraintSpace(), &layout_result, fragmentainer_block_offset,
          FragmentainerCapacityForChildren(), &container_builder_);
    }
    // Attempt to honor orphans and widows requests.
    if (int line_count = container_builder_.LineCount()) {
      if (!first_overflowing_line_)
        first_overflowing_line_ = line_count;
      bool is_first_fragment = !GetBreakToken();
      // Figure out how many lines we need before the break. That entails to
      // attempt to honor the orphans request.
      int minimum_line_count = Style().Orphans();
      if (!is_first_fragment) {
        // If this isn't the first fragment, it means that there's a break both
        // before and after this fragment. So what was seen as trailing widows
        // in the previous fragment is essentially orphans for us now.
        minimum_line_count =
            std::max(minimum_line_count, static_cast<int>(Style().Widows()));
      }
      if (line_count < minimum_line_count) {
        // Not enough orphans. Our only hope is if we can break before the start
        // of this block to improve on the situation. That's not something we
        // can determine at this point though. Permit the break, but mark it as
        // undesirable.
        if (appeal_before > kBreakAppealViolatingOrphansAndWidows)
          appeal_before = kBreakAppealViolatingOrphansAndWidows;
      } else {
        // There are enough lines before the break. Try to make sure that
        // there'll be enough lines after the break as well. Attempt to honor
        // the widows request.
        DCHECK_GE(line_count, first_overflowing_line_);
        int widows_found = line_count - first_overflowing_line_ + 1;
        if (widows_found < Style().Widows()) {
          // Although we're out of space, we have to continue layout to figure
          // out exactly where to break in order to honor the widows
          // request. We'll make sure that we're going to leave at least as many
          // lines as specified by the 'widows' property for the next fragment
          // (if at all possible), which means that lines that could fit in the
          // current fragment (that we have already laid out) may have to be
          // saved for the next fragment.
          //
          // However, any text box block-end trimming must take place before
          // calculating widows, since we might fit an additional line by
          // trimming.
          if (!should_text_box_trim_fragmentainer_end_ ||
              override_text_box_trim_end_child_) {
            return BreakStatus::kContinue;
          }
        }

        // We have determined that there are plenty of lines for the next
        // fragment, so we can just break exactly where we ran out of space,
        // rather than pushing some of the line boxes over to the next fragment.
      }
      fit_all_lines_ = true;
    }
  }

  if (!AttemptSoftBreak(GetConstraintSpace(), child, &layout_result,
                        fragmentainer_block_offset,
                        FragmentainerCapacityForChildren(), appeal_before,
                        &container_builder_)) {
    return BreakStatus::kNeedsEarlierBreak;
  }

  ConsumeRemainingFragmentainerSpace(previous_inflow_position);
  return BreakStatus::kBrokeBefore;
}

void BlockLayoutAlgorithm::UpdateEarlyBreakBetweenLines() {
  // We shouldn't be here if we already know where to break.
  DCHECK(!early_break_);

  // If something in this flow already broke, it's a little too late to look for
  // breakpoints.
  DCHECK(!container_builder_.HasInflowChildBreakInside());

  int line_count = container_builder_.LineCount();
  if (line_count < 2)
    return;
  // We can break between two of the lines if we have to. Calculate the best
  // line number to break before, and the appeal of such a breakpoint.
  int line_number =
      std::max(line_count - Style().Widows(),
               std::min(line_count - 1, static_cast<int>(Style().Orphans())));
  BreakAppeal appeal = kBreakAppealPerfect;
  if (line_number < Style().Orphans() ||
      line_count - line_number < Style().Widows()) {
    // Not enough lines in this container to satisfy the orphans and/or widows
    // requirement. If we break before the last line (i.e. the last possible
    // class B breakpoint), we'll fit as much as possible, and that's the best
    // we can do.
    line_number = line_count - 1;
    appeal = kBreakAppealViolatingOrphansAndWidows;
  }
  if (container_builder_.HasEarlyBreak() &&
      container_builder_.GetEarlyBreak().GetBreakAppeal() > appeal) {
    return;
  }
  const auto* breakpoint =
      MakeGarbageCollected<EarlyBreak>(line_number, appeal);
  container_builder_.SetEarlyBreak(breakpoint);
}

BoxStrut BlockLayoutAlgorithm::CalculateMargins(
    LayoutInputNode child,
    bool is_new_fc,
    LayoutUnit* additional_line_offset) {
  DCHECK(child);
  if (child.IsInline())
    return {};

  const ComputedStyle& child_style = child.Style();
  BoxStrut margins =
      ComputeMarginsFor(child_style, child_percentage_size_.inline_size,
                        GetConstraintSpace().GetWritingDirection());
  if (is_new_fc) {
    return margins;
  }

  std::optional<LayoutUnit> child_inline_size;
  auto ChildInlineSize = [&]() -> LayoutUnit {
    if (!child_inline_size) {
      ConstraintSpaceBuilder builder(GetConstraintSpace(),
                                     child_style.GetWritingDirection(),
                                     /* is_new_fc */ false);
      builder.SetAvailableSize(ChildAvailableSize());
      builder.SetPercentageResolutionSize(child_percentage_size_);

      const bool has_auto_margins =
          child_style.MarginInlineStartUsing(Style()).IsAuto() ||
          child_style.MarginInlineEndUsing(Style()).IsAuto();

      const bool justify_self_affects_sizing =
          RuntimeEnabledFeatures::LayoutJustifySelfForBlocksEnabled() &&
          !has_auto_margins;

      const ItemPosition justify_self =
          child_style
              .ResolvedJustifySelf(
                  {ItemPosition::kNormal, OverflowAlignment::kDefault},
                  &Style())
              .GetPosition();

      if (justify_self_affects_sizing &&
          justify_self == ItemPosition::kStretch) {
        builder.SetInlineAutoBehavior(AutoSizeBehavior::kStretchExplicit);
      } else if (justify_self_affects_sizing &&
                 justify_self != ItemPosition::kNormal) {
        builder.SetInlineAutoBehavior(AutoSizeBehavior::kFitContent);
      } else {
        builder.SetInlineAutoBehavior(AutoSizeBehavior::kStretchImplicit);
      }
      ConstraintSpace space = builder.ToConstraintSpace();

      const auto block_child = To<BlockNode>(child);
      BoxStrut child_border_padding = ComputeBorders(space, block_child) +
                                      ComputePadding(space, child_style);
      child_inline_size = ComputeInlineSizeForFragment(space, block_child,
                                                       child_border_padding);
    }
    return *child_inline_size;
  };

  const auto& style = Style();
  const bool is_rtl = IsRtl(style.Direction());
  const LayoutUnit available_space = ChildAvailableSize().inline_size;

  LayoutUnit text_align_offset;
  if (child_style.MarginInlineStartUsing(style).IsAuto() ||
      child_style.MarginInlineEndUsing(style).IsAuto()) {
    // Resolve auto-margins.
    ResolveInlineAutoMargins(child_style, style, available_space,
                             ChildInlineSize(), &margins);
  } else {
    // Handle -webkit- values for text-align.
    text_align_offset = WebkitTextAlignAndJustifySelfOffset(
        child_style, style, available_space, margins, ChildInlineSize);
  }

  if (is_rtl) {
    *additional_line_offset = ChildAvailableSize().inline_size -
                              text_align_offset - ChildInlineSize() -
                              margins.InlineSum();
  } else {
    *additional_line_offset = text_align_offset;
  }

  return margins;
}

ConstraintSpace BlockLayoutAlgorithm::CreateConstraintSpaceForChild(
    const LayoutInputNode child,
    const BreakToken* child_break_token,
    const InflowChildData& child_data,
    const LogicalSize child_available_size,
    bool is_new_fc,
    const std::optional<LayoutUnit> child_bfc_block_offset,
    bool has_clearance_past_adjoining_floats,
    LayoutUnit block_start_annotation_space) {
  const ComputedStyle& child_style = child.Style();
  const auto child_writing_direction = child_style.GetWritingDirection();
  const auto& constraint_space = GetConstraintSpace();
  ConstraintSpaceBuilder builder(constraint_space, child_writing_direction,
                                 is_new_fc);

  const bool is_in_parallel_flow =
      IsParallelWritingMode(constraint_space.GetWritingMode(),
                            child_writing_direction.GetWritingMode());
  if (!is_in_parallel_flow) [[unlikely]] {
    SetOrthogonalFallbackInlineSize(Style(), child, &builder);
  }

  if (child.IsInline()) {
    if (is_in_parallel_flow) {
      builder.SetInlineAutoBehavior(AutoSizeBehavior::kStretchImplicit);
    }
  } else {
    const bool has_auto_margins =
        child_style.MarginInlineStartUsing(Style()).IsAuto() ||
        child_style.MarginInlineEndUsing(Style()).IsAuto();

    const bool justify_self_affects_sizing =
        RuntimeEnabledFeatures::LayoutJustifySelfForBlocksEnabled() &&
        !has_auto_margins;

    const ItemPosition justify_self =
        child_style
            .ResolvedJustifySelf(
                {ItemPosition::kNormal, OverflowAlignment::kDefault}, &Style())
            .GetPosition();

    if (justify_self_affects_sizing && justify_self == ItemPosition::kStretch) {
      builder.SetInlineAutoBehavior(AutoSizeBehavior::kStretchExplicit);
    } else if (justify_self_affects_sizing &&
               justify_self != ItemPosition::kNormal) {
      builder.SetInlineAutoBehavior(AutoSizeBehavior::kFitContent);
    } else if (is_in_parallel_flow &&
               ShouldBlockContainerChildStretchAutoInlineSize(
                   To<BlockNode>(child))) {
      builder.SetInlineAutoBehavior(AutoSizeBehavior::kStretchImplicit);
    }
  }

  if (line_clamp_data_.ShouldHideForPaint()) [[unlikely]] {
    builder.SetIsHiddenForPaint(true);
  }

  builder.SetAvailableSize(child_available_size);
  builder.SetPercentageResolutionSize(child_percentage_size_);
  builder.SetReplacedPercentageResolutionSize(replaced_child_percentage_size_);

  if (constraint_space.IsTableCell()) {
    builder.SetIsTableCellChild(true);

    // Always shrink-to-fit children within a <mtd> element.
    if (Node().GetDOMNode() &&
        IsA<MathMLTableCellElement>(Node().GetDOMNode())) {
      builder.SetInlineAutoBehavior(AutoSizeBehavior::kFitContent);
    }

    // Some scrollable percentage-sized children of table-cells use their
    // min-size (instead of sizing normally).
    //
    // We only apply this rule if the block size of the containing table cell
    // is considered to be "restricted". Otherwise, especially if this is the
    // only child of the cell, and that is the only cell in the row, we'd end
    // up with zero block size.
    if (constraint_space.IsRestrictedBlockSizeTableCell() &&
        child_percentage_size_.block_size == kIndefiniteSize &&
        !child.ShouldBeConsideredAsReplaced() &&
        child_style.LogicalHeight().HasPercent() &&
        (child_style.OverflowBlockDirection() == EOverflow::kAuto ||
         child_style.OverflowBlockDirection() == EOverflow::kScroll)) {
      builder.SetIsRestrictedBlockSizeTableCellChild();
    }
  }

  bool has_bfc_block_offset = container_builder_.BfcBlockOffset().has_value();

  // Propagate the |ConstraintSpace::ForcedBfcBlockOffset| down to our
  // children.
  if (!has_bfc_block_offset && constraint_space.ForcedBfcBlockOffset()) {
    builder.SetForcedBfcBlockOffset(*constraint_space.ForcedBfcBlockOffset());
  }
  if (child_bfc_block_offset && !is_new_fc)
    builder.SetForcedBfcBlockOffset(*child_bfc_block_offset);

  if (has_bfc_block_offset) {
    // Typically we aren't allowed to look at the previous layout result within
    // a layout algorithm. However this is fine (honest), as it is just a hint
    // to the child algorithm for where floats should be placed. If it doesn't
    // have this flag, or gets this estimate wrong, it'll relayout with the
    // appropriate "forced" BFC block-offset.
    if (child.IsBlock()) {
      if (const LayoutResult* cached_result =
              child.GetLayoutBox()->GetCachedLayoutResult(
                  To<BlockBreakToken>(child_break_token))) {
        const auto& prev_space = cached_result->GetConstraintSpaceForCaching();

        // To increase the hit-rate we adjust the previous "optimistic"/"forced"
        // BFC block-offset by how much the child has shifted from the previous
        // layout.
        LayoutUnit bfc_block_delta =
            child_data.bfc_offset_estimate.block_offset -
            prev_space.GetBfcOffset().block_offset;
        if (prev_space.ForcedBfcBlockOffset()) {
          builder.SetOptimisticBfcBlockOffset(
              *prev_space.ForcedBfcBlockOffset() + bfc_block_delta);
        } else if (prev_space.OptimisticBfcBlockOffset()) {
          builder.SetOptimisticBfcBlockOffset(
              *prev_space.OptimisticBfcBlockOffset() + bfc_block_delta);
        }
      }
    }
  } else if (constraint_space.OptimisticBfcBlockOffset()) {
    // Propagate the |ConstraintSpace::OptimisticBfcBlockOffset| down to our
    // children.
    builder.SetOptimisticBfcBlockOffset(
        *constraint_space.OptimisticBfcBlockOffset());
  }

  // Propagate the |ConstraintSpace::AncestorHasClearancePastAdjoiningFloats|
  // flag down to our children.
  if (!has_bfc_block_offset &&
      constraint_space.AncestorHasClearancePastAdjoiningFloats()) {
    builder.SetAncestorHasClearancePastAdjoiningFloats();
  }
  if (has_clearance_past_adjoining_floats)
    builder.SetAncestorHasClearancePastAdjoiningFloats();

  LayoutUnit clearance_offset = LayoutUnit::Min();
  if (!IsBreakInside(DynamicTo<BlockBreakToken>(child_break_token))) {
    if (!constraint_space.IsNewFormattingContext()) {
      clearance_offset = constraint_space.ClearanceOffset();
    }
    if (child.IsBlock()) {
      LayoutUnit child_clearance_offset =
          GetExclusionSpace().ClearanceOffset(child_style.Clear(Style()));
      clearance_offset = std::max(clearance_offset, child_clearance_offset);
    }
  }
  builder.SetClearanceOffset(clearance_offset);
  builder.SetBaselineAlgorithmType(constraint_space.GetBaselineAlgorithmType());

  if (child_data.is_pushed_by_floats) {
    // Clearance has been applied, but it won't be automatically detected when
    // laying out the child, since the BFC block-offset has already been updated
    // to be past the relevant floats. We therefore need a flag.
    builder.SetIsPushedByFloats();
  }

  if (!is_new_fc) {
    builder.SetMarginStrut(child_data.margin_strut);
    builder.SetBfcOffset(child_data.bfc_offset_estimate);
    builder.SetExclusionSpace(GetExclusionSpace());
    if (!has_bfc_block_offset) {
      builder.SetAdjoiningObjectTypes(
          container_builder_.GetAdjoiningObjectTypes());
    }
    builder.SetLineClampData(line_clamp_data_.data);
    builder.SetLineClampEndMarginStrut(line_clamp_data_.end_margin_strut);
    builder.SetLineClampEndPadding(Padding().block_end);
    builder.SetShouldTextBoxTrimInsideWhenLineClamp(
        line_clamp_data_.data.IsLineClampContext() &&
        (constraint_space.ShouldTextBoxTrimInsideWhenLineClamp() ||
         should_text_box_trim_node_end_));
  }
  builder.SetBlockStartAnnotationSpace(block_start_annotation_space);

  // Propagate `text-box-trim` only for in-flow children.
  if (ShouldTextBoxTrim() && !child.IsFloatingOrOutOfFlowPositioned())
      [[unlikely]] {
    builder.SetShouldTextBoxTrimNodeStart(should_text_box_trim_node_start_);
    builder.SetShouldTextBoxTrimFragmentainerStart(
        should_text_box_trim_fragmentainer_start_);
    builder.SetShouldTextBoxTrimFragmentainerEnd(
        should_text_box_trim_fragmentainer_end_);
    if (ShouldTextBoxTrimEnd()) {
      // For an inline child, always set the flag for the child if it's set on
      // `this`. The `InlineLayoutAlgorithm` can determine if it's the last line
      // or not rather quickly in most cases. If it fails to apply end trimming
      // (happens for block-in-inline), this is handled by
      // `RelayoutForTextBoxTrimEnd()`.
      builder.SetShouldTextBoxTrimNodeEnd(
          should_text_box_trim_node_end_ &&
          (child.IsInline() || IsLastInflowChild(*child.GetLayoutBox())));

      if (child.IsInline() && child == override_text_box_trim_end_child_ &&
          InlineBreakToken::IsStartEqual(
              To<InlineBreakToken>(override_text_box_trim_end_break_token_),
              To<InlineBreakToken>(child_break_token))) {
        builder.SetShouldForceTextBoxTrimEnd();
      }
    }

    // Propagate `text-box-edge` if this box has non-initial `text-box-trim`.
    const ComputedStyle& style = Node().Style();
    builder.SetEffectiveTextBoxEdge(
        style.TextBoxTrim() != ETextBoxTrim::kNone
            ? style.GetTextBoxEdge()
            : constraint_space.EffectiveTextBoxEdge());
  }

  if (constraint_space.HasBlockFragmentation()) {
    LayoutUnit fragmentainer_offset_delta;
    // We need to keep track of our block-offset within the fragmentation
    // context, to be able to tell where the fragmentation line is (i.e. where
    // to break).
    if (is_new_fc) {
      fragmentainer_offset_delta =
          *child_bfc_block_offset - constraint_space.ExpectedBfcBlockOffset();
    } else {
      fragmentainer_offset_delta = builder.ExpectedBfcBlockOffset() -
                                   constraint_space.ExpectedBfcBlockOffset();
    }
    SetupSpaceBuilderForFragmentation(container_builder_, child,
                                      fragmentainer_offset_delta, &builder);

    if (!is_new_fc && GetConstraintSpace().IsInColumnBfc()) {
      // Need to keep track of whether we're in the same formatting context as a
      // column, in order to determine whether column-span:all applies on a
      // descendant.
      builder.SetIsInColumnBfc();
    }

    // If there's a child break inside (typically in a parallel flow, or we
    // would have finished layout by now), we need to produce more
    // fragmentainers, before we can insert any column spanners, so that
    // everything that is supposed to come before the spanner actually ends up
    // there.
    if (constraint_space.IsPastBreak() ||
        container_builder_.HasInsertedChildBreak()) {
      builder.SetIsPastBreak();
    }
  }

  return builder.ToConstraintSpace();
}

void BlockLayoutAlgorithm::PropagateBaselineFromLineBox(
    const PhysicalFragment& child,
    LayoutUnit block_offset) {
  const auto& line_box = To<PhysicalLineBoxFragment>(child);

  // Skip over a line-box which is empty. These don't have any baselines
  // which should be added.
  if (line_box.IsEmptyLineBox())
    return;

  // Skip over the line-box if we are past our clamp point.
  if (line_clamp_data_.IsPastClampPoint()) {
    return;
  }

  if (line_box.IsBlockInInline()) [[unlikely]] {
    // Block-in-inline may have different first/last baselines.
    DCHECK(container_builder_.ItemsBuilder());
    const auto& items =
        container_builder_.ItemsBuilder()->GetLogicalLineItems(line_box);
    const LayoutResult* result = items.BlockInInlineLayoutResult();
    DCHECK(result);
    PropagateBaselineFromBlockChild(result->GetPhysicalFragment(),
                                    /* margins */ BoxStrut(), block_offset);
    return;
  }

  FontHeight metrics = line_box.BaselineMetrics();
  DCHECK(!metrics.IsEmpty());
  LayoutUnit baseline =
      block_offset +
      (Style().IsFlippedLinesWritingMode() ? metrics.descent : metrics.ascent);

  if (!container_builder_.FirstBaseline())
    container_builder_.SetFirstBaseline(baseline);
  container_builder_.SetLastBaseline(baseline);
}

void BlockLayoutAlgorithm::PropagateBaselineFromBlockChild(
    const PhysicalFragment& child,
    const BoxStrut& margins,
    LayoutUnit block_offset) {
  DCHECK(child.IsBox());
  const auto baseline_algorithm =
      GetConstraintSpace().GetBaselineAlgorithmType();

  // When computing baselines for an inline-block, table's don't contribute any
  // baselines.
  if (child.IsTable() &&
      baseline_algorithm == BaselineAlgorithmType::kInlineBlock) {
    return;
  }

  // Skip over the block if we are past our clamp point.
  if (line_clamp_data_.IsPastClampPoint()) {
    return;
  }

  const auto& physical_fragment = To<PhysicalBoxFragment>(child);
  LogicalBoxFragment fragment(GetConstraintSpace().GetWritingDirection(),
                              physical_fragment);

  if (!container_builder_.FirstBaseline()) {
    if (auto first_baseline = fragment.FirstBaseline())
      container_builder_.SetFirstBaseline(block_offset + *first_baseline);
  }

  // Counter-intuitively, when computing baselines for an inline-block, some
  // fragments use their first-baseline for the container's last-baseline.
  bool use_last_baseline =
      baseline_algorithm == BaselineAlgorithmType::kDefault ||
      physical_fragment.UseLastBaselineForInlineBaseline();

  auto last_baseline =
      use_last_baseline ? fragment.LastBaseline() : fragment.FirstBaseline();

  // When computing baselines for an inline-block, some block-boxes (e.g. with
  // "overflow: hidden") will force the baseline to the block-end margin edge.
  if (baseline_algorithm == BaselineAlgorithmType::kInlineBlock &&
      physical_fragment.ForceInlineBaselineSynthesis() &&
      fragment.IsWritingModeEqual()) {
    last_baseline = fragment.BlockSize() + margins.block_end;
  }

  if (last_baseline)
    container_builder_.SetLastBaseline(block_offset + *last_baseline);
}

bool BlockLayoutAlgorithm::ResolveBfcBlockOffset(
    PreviousInflowPosition* previous_inflow_position,
    LayoutUnit bfc_block_offset,
    std::optional<LayoutUnit> forced_bfc_block_offset) {
  // Clearance may have been resolved (along with BFC block-offset) in a
  // previous layout pass, so check the constraint space for pre-applied
  // clearance. This is important in order to identify possible class C break
  // points.
  if (GetConstraintSpace().IsPushedByFloats()) {
    container_builder_.SetIsPushedByFloats();
  }

  if (container_builder_.BfcBlockOffset())
    return true;

  bfc_block_offset = forced_bfc_block_offset.value_or(bfc_block_offset);

  if (ApplyClearance(GetConstraintSpace(), &bfc_block_offset)) {
    container_builder_.SetIsPushedByFloats();
  }

  container_builder_.SetBfcBlockOffset(bfc_block_offset);

  if (NeedsAbortOnBfcBlockOffsetChange()) {
    // A formatting context root should always be able to resolve its
    // whereabouts before layout, so there should never be any incorrect
    // estimates that we need to go back and fix.
    DCHECK(!GetConstraintSpace().IsNewFormattingContext());

    return false;
  }

  // Set the offset to our block-start border edge. We'll now end up at the
  // block-start border edge. If the BFC block offset was resolved due to a
  // block-start border or padding, that must be added by the caller, for
  // subsequent layout to continue at the right position. Whether we need to add
  // border+padding or not isn't something we should determine here, so it must
  // be dealt with as part of initializing the layout algorithm.
  previous_inflow_position->logical_block_offset = LayoutUnit();

  // Resolving the BFC offset normally means that we have finished collapsing
  // adjoining margins, so that we can reset the margin strut. One exception
  // here is if we're resuming after a break, in which case we know that we can
  // resolve the BFC offset to the block-start of the fragmentainer
  // (block-offset 0). But keep the margin strut, since we're essentially still
  // collapsing with the fragmentainer boundary, which will eat / discard all
  // adjoining margins - unless this is at a forced break. DCHECK that the strut
  // is empty (note that a strut that's set up to eat all margins will also be
  // considered to be empty).
  if (!is_resuming_)
    previous_inflow_position->margin_strut = MarginStrut();
  else
    DCHECK(previous_inflow_position->margin_strut.IsEmpty());

  return true;
}

bool BlockLayoutAlgorithm::NeedsAbortOnBfcBlockOffsetChange() const {
  DCHECK(container_builder_.BfcBlockOffset());
  if (!abort_when_bfc_block_offset_updated_)
    return false;

  // If our position differs from our (potentially optimistic) estimate, abort.
  return *container_builder_.BfcBlockOffset() !=
         GetConstraintSpace().ExpectedBfcBlockOffset();
}

std::optional<LayoutUnit>
BlockLayoutAlgorithm::CalculateQuirkyBodyMarginBlockSum(
    const MarginStrut& end_margin_strut) {
  if (!Node().IsQuirkyAndFillsViewport())
    return std::nullopt;

  if (!Style().LogicalHeight().IsAuto()) {
    return std::nullopt;
  }

  if (GetConstraintSpace().IsNewFormattingContext()) {
    return std::nullopt;
  }

  DCHECK(Node().IsBody());
  LayoutUnit block_end_margin =
      ComputeMarginsForSelf(GetConstraintSpace(), Style()).block_end;

  // The |end_margin_strut| is the block-start margin if the body doesn't have
  // a resolved BFC block-offset.
  if (!container_builder_.BfcBlockOffset())
    return end_margin_strut.Sum() + block_end_margin;

  MarginStrut body_strut = end_margin_strut;
  body_strut.Append(block_end_margin, Style().HasMarginBlockEndQuirk());
  return *container_builder_.BfcBlockOffset() -
         GetConstraintSpace().GetBfcOffset().block_offset + body_strut.Sum();
}

bool BlockLayoutAlgorithm::PositionOrPropagateListMarker(
    const LayoutResult& layout_result,
    LogicalOffset* content_offset,
    PreviousInflowPosition* previous_inflow_position) {
  // If this is not a list-item, propagate unpositioned list markers to
  // ancestors.
  if (!ShouldPlaceUnpositionedListMarker())
    return true;

  // If this is a list item, add the unpositioned list marker as a child.
  UnpositionedListMarker list_marker =
      container_builder_.GetUnpositionedListMarker();
  if (!list_marker)
    return true;
  container_builder_.ClearUnpositionedListMarker();

  const ConstraintSpace& space = GetConstraintSpace();
  const auto& content = layout_result.GetPhysicalFragment();
  FontBaseline baseline_type = Style().GetFontBaseline();
  if 
"""


```