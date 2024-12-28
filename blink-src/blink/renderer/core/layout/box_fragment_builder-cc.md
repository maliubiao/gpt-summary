Response:
Let's break down the thought process to analyze the provided C++ code and generate the desired output.

1. **Understand the Goal:** The primary goal is to analyze the `BoxFragmentBuilder` class in the Chromium Blink rendering engine. This involves understanding its purpose, its relationship to web technologies (HTML, CSS, JavaScript), and identifying potential user/programmer errors.

2. **Initial Code Scan (Keywords and Includes):**  Quickly scan the `#include` directives and the class name. This provides initial clues. The includes suggest interactions with layout concepts like `BlockBreakToken`, `InlineBreakToken`, `LayoutObject`, `LayoutResult`, etc. The name "BoxFragmentBuilder" strongly suggests a role in constructing fragments of layout boxes.

3. **High-Level Purpose Inference:** Based on the name and includes, hypothesize that `BoxFragmentBuilder` is responsible for creating and managing fragments of layout boxes during the rendering process. This fragmentation is likely related to how content is broken across lines, pages, or columns.

4. **Function-by-Function Analysis:**  Go through each function in the class, focusing on what it *does* and what data it manipulates. Here's a potential internal thought process for some key functions:

    * **`UpdateBorderPaddingForClonedBoxDecorations()`:**  "Cloned Box Decorations" suggests this is relevant to how borders and padding are handled when a box is split across fragments. The logic involving `break_token->SequenceNumber()` indicates it's dealing with repeated fragments.

    * **`LayoutResultForPropagation()`:** This function takes a `LayoutResult` and potentially returns a different one. The conditions involving `PhysicalLineBoxFragment` and `items_builder_` suggest it's handling cases where block-level content is nested within inline content.

    * **`AddBreakBeforeChild()`:**  The name is self-explanatory. It's adding a break before a child element. The logic checks for forced breaks and manages different types of break tokens (block and inline).

    * **`AddResult()`:** This is a crucial function. It takes a child's `LayoutResult` and integrates it into the current fragment. It handles offsets, margins, and propagates break information. The comment about line boxes with blocks inside is important.

    * **`AddChild()`:**  This function appears to be a lower-level version of `AddResult`, focusing on adding a child fragment. It deals with relative positioning, scroll container logic, and the `may_have_descendant_above_block_start_` flag.

    * **`PropagateBreakInfo()`:**  This function is about propagating information related to breaks from child elements up to the parent. The logic about pagination and monolithic overflow is a key detail.

    * **`PropagateChildBreakValues()`:** This function seems to be specifically about propagating CSS `break-before` and `break-after` property values.

    * **`ToBoxFragment()`:** This function seems to be the final step in creating the `PhysicalBoxFragment`. It handles adjustments related to fragmentation and creates the `LayoutResult`.

5. **Relate to Web Technologies (HTML, CSS, JavaScript):**  After understanding the functions, connect them back to the core web technologies.

    * **HTML:**  The structure of the HTML document leads to a hierarchy of layout objects. `BoxFragmentBuilder` helps in laying out these elements. Examples: `<div>`, `<span>`, etc.

    * **CSS:** CSS properties directly influence the behavior of `BoxFragmentBuilder`. Think about properties like `border`, `padding`, `margin`, `break-before`, `break-after`, `overflow`, `position: relative`, `position: fixed`, and column layout properties. Provide specific examples of how these properties would affect the builder's logic.

    * **JavaScript:** JavaScript can dynamically modify the DOM and CSS, indirectly triggering re-layout and thus involving `BoxFragmentBuilder`. Consider scenarios where JavaScript adds/removes elements or changes styles.

6. **Identify Logical Reasoning and Assumptions:**  Note places where the code makes decisions based on certain conditions. Formulate these as "if input X, then output Y" scenarios. For example, the handling of forced breaks or the logic within `PropagateBreakInfo()` regarding pagination.

7. **Pinpoint Potential Errors:**  Think about common mistakes developers make with CSS and how these might interact with the layout engine. Examples include incorrect usage of `break-before`/`break-after`, negative margins causing unexpected behavior in scroll containers, or misunderstandings about how fixed positioning interacts with fragmented content.

8. **Structure the Output:** Organize the information clearly using headings and bullet points.

    * Start with a concise summary of the class's purpose.
    * List the core functionalities.
    * Explain the relationships with HTML, CSS, and JavaScript with concrete examples.
    * Provide illustrative examples of logical reasoning (input/output).
    * List common usage errors with examples.

9. **Refine and Review:** Read through the generated output to ensure accuracy, clarity, and completeness. Check for any inconsistencies or areas that could be explained better. Ensure the examples are relevant and easy to understand. For example, initially, I might have just said "handles CSS properties." Refining this to specific property examples makes the explanation much clearer.

This iterative process of understanding the code, connecting it to web technologies, identifying logic, and considering potential errors allows for a comprehensive analysis of the `BoxFragmentBuilder` class.
这是一个定义在 `blink/renderer/core/layout/box_fragment_builder.cc` 文件中的 C++ 类 `BoxFragmentBuilder`，它是 Chromium Blink 渲染引擎的一部分。`BoxFragmentBuilder` 的主要功能是**构建和管理布局盒子的片段（fragments）**。在渲染过程中，一个逻辑上的布局盒子（例如一个 `div` 元素）可能因为分页、多列布局或者元素自身的特性而被分割成多个物理上的片段。`BoxFragmentBuilder` 负责生成和维护这些片段的信息。

以下是 `BoxFragmentBuilder` 的具体功能分解：

**核心功能：**

1. **创建布局片段 (Creating Layout Fragments):**
   - 负责为布局盒子创建 `PhysicalBoxFragment` 对象。这些片段代表了盒子在特定分页、列或区域中的一部分。
   - 跟踪和管理已创建的子片段。

2. **处理分片 (Fragmentation Handling):**
   - **块级分片 (Block Fragmentation):**  处理块级元素的跨页、跨列等分片。这涉及到计算每个片段的大小、位置以及如何中断和继续内容。
   - **内联分片 (Inline Fragmentation):** 虽然这个类主要关注盒子片段，但它也间接处理内联内容的布局，例如通过 `items_builder_` 管理行盒子的信息。
   - **强制分片 (Forced Breaks):** 处理 CSS 属性 `break-before` 和 `break-after` 引起的强制分片。
   - **避免分片 (Break Avoidance):** 考虑 `break-inside: avoid` 等属性，尝试避免在元素内部进行分片。

3. **管理分片上下文 (Fragmentation Context Management):**
   - 维护与分片相关的状态信息，例如是否允许内部断点 (`has_inflow_child_break_inside_`)、是否需要内容才能进行分片 (`requires_content_before_breaking_`)。
   - 跟踪和传播分片信息，例如从子元素接收分片请求和偏好。

4. **处理浮动和定位元素 (Handling Floats and Positioned Elements):**
   - 考虑浮动元素对布局片段的影响。
   - 管理绝对定位和固定定位的元素在分片上下文中的位置和影响。

5. **处理滚动容器 (Scroll Container Handling):**
   - 跟踪滚动容器的内流边界 (`inflow_bounds_`)，用于计算滚动条所需的大小。

6. **传播布局结果 (Propagating Layout Results):**
   - 从子元素的布局结果中提取有用的信息，例如分片信息、外边距信息等，并将其传播到父片段构建器。

7. **处理多列布局 (Multi-column Layout Handling):**
   -  与多列布局相关的逻辑，例如处理跨列元素（spanners）。

8. **处理超出流 (Out-of-flow) 内容:**
   - 管理超出正常文档流的元素（例如，浮动和绝对/固定定位元素）如何影响布局片段的构建。

**与 JavaScript, HTML, CSS 的关系：**

`BoxFragmentBuilder` 直接受到 HTML 结构和 CSS 样式的驱动，并影响最终的渲染结果，而 JavaScript 可以动态地修改 HTML 和 CSS，从而间接地影响 `BoxFragmentBuilder` 的行为。

**HTML:**

- `BoxFragmentBuilder` 为 HTML 元素对应的布局盒子创建片段。例如，一个 `<div>` 元素可能被分割成多个 `PhysicalBoxFragment` 对象，如果它跨越了多个页面或列。
- **举例:** 考虑以下 HTML 结构：
  ```html
  <div style="column-count: 2;">
    <p>This is some long content that will span across columns.</p>
  </div>
  ```
  `BoxFragmentBuilder` 会为 `div` 创建片段，每个片段代表内容在不同列中的部分。

**CSS:**

- **分片属性:**  `break-before`, `break-after`, `break-inside`, `column-break-before`, `column-break-after`, `column-break-inside` 等 CSS 属性直接影响 `BoxFragmentBuilder` 如何进行分片。
  - **举例:** `style="break-after: page;"`  会导致 `BoxFragmentBuilder` 在该元素之后强制分页。
- **多列布局属性:** `column-count`, `column-width`, `column-span` 等属性指示 `BoxFragmentBuilder` 如何将内容分割到不同的列中。
  - **举例:** `style="column-span: all;"` 会让一个元素跨越所有列，`BoxFragmentBuilder` 需要相应地处理。
- **浮动和定位属性:** `float`, `position` 属性会影响 `BoxFragmentBuilder` 如何安排片段的位置。
  - **举例:**  一个设置了 `float: left;` 的元素会影响后续内容的布局和分片，`BoxFragmentBuilder` 需要考虑其对可用空间的影响。
- **滚动属性:** `overflow: auto;` 或 `overflow: scroll;` 会使元素成为滚动容器，`BoxFragmentBuilder` 需要跟踪其内流边界。
- **外边距属性:** `margin` 影响元素的尺寸和与其他元素之间的间隔，`BoxFragmentBuilder` 在计算片段大小时需要考虑外边距。

**JavaScript:**

- JavaScript 可以动态地修改 HTML 结构和 CSS 样式，这些修改会导致重新布局，从而触发 `BoxFragmentBuilder` 重新构建片段。
  - **举例:**  JavaScript 通过 `element.style.breakAfter = 'page';` 修改元素的 `break-after` 属性，会导致重新布局，`BoxFragmentBuilder` 会创建新的页面片段。
  - **举例:**  JavaScript 动态添加或删除 DOM 元素也会触发重新布局，`BoxFragmentBuilder` 需要为新的元素创建片段或移除不再需要的片段。

**逻辑推理示例 (假设输入与输出):**

假设我们有一个 `<div>` 元素，其 CSS 样式为 `style="height: 500px; overflow: auto;"`，并且内部有一些内容，这些内容的总高度超过了 500px。

**假设输入:**

- `BoxFragmentBuilder` 正在为该 `<div>` 元素构建片段。
- 可用的垂直空间（例如，视口高度）有限，不足以容纳所有内容。
- `overflow` 属性设置为 `auto`。

**逻辑推理过程:**

1. `BoxFragmentBuilder` 会检查元素的 `overflow` 属性，发现它是 `auto`。
2. `BoxFragmentBuilder` 会计算元素的内容高度，发现它超过了元素自身的高度 (500px)。
3. 由于 `overflow` 是 `auto` 且内容溢出，`BoxFragmentBuilder` 会将该 `<div>` 视为一个滚动容器。
4. `BoxFragmentBuilder` 会计算内流边界 (`inflow_bounds_`)，以确定滚动条需要的空间。
5. 最终，`BoxFragmentBuilder` 会创建一个 `PhysicalBoxFragment`，其尺寸为 500px，并且指示该片段存在垂直方向的溢出，从而触发渲染引擎绘制滚动条。

**假设输出:**

- 创建一个 `PhysicalBoxFragment` 对象，其块级大小（高度）为 500px。
- 该 `PhysicalBoxFragment` 标记为可能存在块级溢出。
- 相关的滚动信息会被传递给渲染管道，以便绘制滚动条。

**用户或编程常见的使用错误示例:**

1. **错误地使用 `break-before` 和 `break-after` 导致意外的分页或分列。**
   - **例子:** 用户可能在一个很小的内联元素上设置了 `break-before: page;`，导致出现不必要的空白页。
   - **例子:** 开发者可能在循环生成列表项时，忘记清除之前设置的分页属性，导致每项都单独分页。

2. **混淆了逻辑盒子和物理片段的概念。**
   - **例子:** 开发者可能会尝试直接操作 `PhysicalBoxFragment` 的属性来影响所有片段，但实际上每个片段是独立的。对一个片段的修改不一定影响其他片段。

3. **不理解浮动元素对后续内容布局和分片的影响。**
   - **例子:** 开发者可能期望一个浮动元素后的内容能够完全填充剩余空间，但由于浮动元素的特性，后续内容可能会围绕着浮动元素流动，导致分片行为与预期不符。

4. **在多列布局中错误地使用 `column-span`。**
   - **例子:**  开发者可能错误地将一个不应该跨列的元素设置为 `column-span: all;`，导致布局错乱。

5. **忽略滚动容器的内流边界，导致滚动区域计算错误。**
   - **例子:**  开发者可能动态添加内容到滚动容器中，但没有触发重新布局，导致滚动条的长度不正确。

6. **过度依赖 JavaScript 来实现分片效果，而不是利用 CSS 的分片属性。**
   - **例子:** 开发者可能使用 JavaScript 来计算分页位置并手动分割内容，这比使用 CSS 的 `break-before` 和 `break-after` 效率更低且更易出错。

总而言之，`BoxFragmentBuilder` 是 Blink 渲染引擎中一个核心的布局构建模块，它负责将逻辑上的布局盒子分割成物理上的片段，以便在不同的渲染上下文中（如页面、列）进行展示。它与 HTML 的结构和 CSS 的样式紧密相关，并通过考虑各种布局约束和属性来实现精确的内容呈现。理解其功能有助于开发者更好地理解浏览器如何渲染网页，并避免常见的布局错误。

Prompt: 
```
这是目录为blink/renderer/core/layout/box_fragment_builder.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/box_fragment_builder.h"

#include "third_party/blink/renderer/core/layout/block_break_token.h"
#include "third_party/blink/renderer/core/layout/block_node.h"
#include "third_party/blink/renderer/core/layout/break_token.h"
#include "third_party/blink/renderer/core/layout/column_spanner_path.h"
#include "third_party/blink/renderer/core/layout/exclusions/exclusion_space.h"
#include "third_party/blink/renderer/core/layout/fragmentation_utils.h"
#include "third_party/blink/renderer/core/layout/inline/inline_break_token.h"
#include "third_party/blink/renderer/core/layout/inline/inline_node.h"
#include "third_party/blink/renderer/core/layout/inline/physical_line_box_fragment.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/layout/layout_result.h"
#include "third_party/blink/renderer/core/layout/length_utils.h"
#include "third_party/blink/renderer/core/layout/logical_box_fragment.h"
#include "third_party/blink/renderer/core/layout/out_of_flow_layout_part.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"
#include "third_party/blink/renderer/core/layout/positioned_float.h"
#include "third_party/blink/renderer/core/layout/relative_utils.h"

namespace blink {

void BoxFragmentBuilder::UpdateBorderPaddingForClonedBoxDecorations() {
  const BlockBreakToken* break_token = PreviousBreakToken();
  if (!IsBreakInside(break_token)) {
    return;
  }
  // BorderPadding() is used for resolving the box size, and it needs to include
  // the border/padding space taken up by this new fragment (to be created),
  // plus all preceding ones.
  int fragment_count_including_this = break_token->SequenceNumber() + 2;
  border_padding_.block_start *= fragment_count_including_this;
  border_padding_.block_end *= fragment_count_including_this;
}

const LayoutResult& BoxFragmentBuilder::LayoutResultForPropagation(
    const LayoutResult& layout_result) const {
  if (layout_result.Status() != LayoutResult::kSuccess) {
    return layout_result;
  }
  const auto& fragment = layout_result.GetPhysicalFragment();
  if (fragment.IsBox()) {
    return layout_result;
  }

  const auto* line = DynamicTo<PhysicalLineBoxFragment>(&fragment);
  if (!line || !line->IsBlockInInline() || !items_builder_) {
    return layout_result;
  }

  const auto& line_items = items_builder_->GetLogicalLineItems(*line);
  DCHECK(line_items.BlockInInlineLayoutResult());
  return *line_items.BlockInInlineLayoutResult();
}

void BoxFragmentBuilder::AddBreakBeforeChild(LayoutInputNode child,
                                             std::optional<BreakAppeal> appeal,
                                             bool is_forced_break) {
  // If there's a pre-set break token, we shouldn't be here.
  DCHECK(!break_token_);

  if (is_forced_break) {
    SetHasForcedBreak();
    // A forced break is considered to always have perfect appeal; they should
    // never be weighed against other potential breakpoints.
    DCHECK(!appeal || *appeal == kBreakAppealPerfect);
  } else if (appeal) {
    ClampBreakAppeal(*appeal);
  }

  DCHECK(has_block_fragmentation_);

  if (!has_inflow_child_break_inside_)
    has_inflow_child_break_inside_ = !child.IsFloatingOrOutOfFlowPositioned();

  if (auto* child_inline_node = DynamicTo<InlineNode>(child)) {
    if (!last_inline_break_token_) {
      // In some cases we may want to break before the first line in the
      // fragment. This happens if there's a tall float before the line, or, as
      // a last resort, when there are no better breakpoints to choose from, and
      // we're out of space. When laying out, we store the inline break token
      // from the last line added to the builder, but if we haven't added any
      // lines at all, we are still going to need a break token, so that the we
      // can tell where to resume in the inline formatting context in the next
      // fragmentainer.

      if (PreviousBreakToken()) {
        // If there's an incoming break token, see if it has a child inline
        // break token, and use that one. We may be past floats or lines that
        // were laid out in earlier fragments.
        const auto& child_tokens = PreviousBreakToken()->ChildBreakTokens();
        if (child_tokens.size()) {
          // If there is an inline break token, it will always be the last
          // child.
          last_inline_break_token_ =
              DynamicTo<InlineBreakToken>(child_tokens.back().Get());
          if (last_inline_break_token_)
            return;
        }
      }

      // We're at the beginning of the inline formatting context.
      last_inline_break_token_ = InlineBreakToken::Create(
          *child_inline_node, /* style */ nullptr, InlineItemTextIndex(),
          InlineBreakToken::kDefault);
    }
    return;
  }
  auto* token = BlockBreakToken::CreateBreakBefore(child, is_forced_break);
  child_break_tokens_.push_back(token);
}

void BoxFragmentBuilder::AddResult(
    const LayoutResult& child_layout_result,
    const LogicalOffset offset,
    std::optional<const BoxStrut> margins,
    std::optional<LogicalOffset> relative_offset,
    const OofInlineContainer<LogicalOffset>* inline_container) {
  const auto& fragment = child_layout_result.GetPhysicalFragment();

  // We'll normally propagate info from child_layout_result here, but if that's
  // a line box with a block inside, we'll use the result for that block
  // instead. The fact that we create a line box at all in such cases is just an
  // implementation detail -- anything of interest is stored on the child block
  // fragment.
  const LayoutResult* result_for_propagation = &child_layout_result;

  if (!fragment.IsBox() && items_builder_) {
    if (const auto* line = DynamicTo<PhysicalLineBoxFragment>(&fragment)) {
      if (line->IsBlockInInline() && has_block_fragmentation_) [[unlikely]] {
        // If this line box contains a block-in-inline, propagate break data
        // from the block-in-inline.
        const auto& line_items = items_builder_->GetLogicalLineItems(*line);
        result_for_propagation = line_items.BlockInInlineLayoutResult();
        DCHECK(result_for_propagation);
      }

      items_builder_->AddLine(*line, offset);
      // TODO(kojii): We probably don't need to AddChild this line, but there
      // maybe OOF objects. Investigate how to handle them.
    }
  }

  const MarginStrut end_margin_strut = child_layout_result.EndMarginStrut();
  // No margins should pierce outside formatting-context roots.
  DCHECK(!fragment.IsFormattingContextRoot() || end_margin_strut.IsEmpty());

  AddChild(fragment, offset, &end_margin_strut,
           child_layout_result.IsSelfCollapsing(), relative_offset,
           inline_container);
  if (margins) {
    const auto& box_fragment = To<PhysicalBoxFragment>(fragment);
    if (!margins->IsEmpty() || !box_fragment.Margins().IsZero()) {
      box_fragment.GetMutableForContainerLayout().SetMargins(
          margins->ConvertToPhysical(GetWritingDirection()));
    }
  }

  if (has_block_fragmentation_) [[unlikely]] {
    PropagateBreakInfo(*result_for_propagation, offset);
  }
  if (GetConstraintSpace().ShouldPropagateChildBreakValues()) [[unlikely]] {
    PropagateChildBreakValues(*result_for_propagation);
  }

  PropagateFromLayoutResult(*result_for_propagation);
}

void BoxFragmentBuilder::AddResult(const LayoutResult& child_layout_result,
                                   const LogicalOffset offset) {
  AddResult(child_layout_result, offset, std::nullopt, std::nullopt, nullptr);
}

void BoxFragmentBuilder::AddChild(
    const PhysicalFragment& child,
    const LogicalOffset& child_offset,
    const MarginStrut* margin_strut,
    bool is_self_collapsing,
    std::optional<LogicalOffset> relative_offset,
    const OofInlineContainer<LogicalOffset>* inline_container) {
#if DCHECK_IS_ON()
  needs_inflow_bounds_explicitly_set_ = !!relative_offset;
  needs_may_have_descendant_above_block_start_explicitly_set_ =
      !!relative_offset;
#endif

  if (!relative_offset) {
    relative_offset = LogicalOffset();
    if (box_type_ != PhysicalFragment::BoxType::kInlineBox) {
      if (child.IsLineBox()) {
        if (child.MayHaveDescendantAboveBlockStart()) [[unlikely]] {
          may_have_descendant_above_block_start_ = true;
        }
      } else if (child.IsCSSBox()) {
        // Apply the relative position offset.
        const auto& box_child = To<PhysicalBoxFragment>(child);
        if (box_child.Style().GetPosition() == EPosition::kRelative) {
          relative_offset = ComputeRelativeOffsetForBoxFragment(
              box_child, GetWritingDirection(), child_available_size_);
        }

        // The |may_have_descendant_above_block_start_| flag is used to
        // determine if a fragment can be re-used when preceding floats are
        // present. This is relatively rare, and is true if:
        //  - An inflow child is positioned above our block-start edge.
        //  - Any inflow descendants (within the same formatting-context) which
        //    *may* have a child positioned above our block-start edge.
        if ((child_offset.block_offset < LayoutUnit() &&
             !box_child.IsOutOfFlowPositioned()) ||
            (!box_child.IsFormattingContextRoot() &&
             box_child.MayHaveDescendantAboveBlockStart()))
          may_have_descendant_above_block_start_ = true;
      }

      // If we are a scroll container, we need to track the maximum bounds of
      // any inflow children (including line-boxes) to calculate the
      // scrollable-overflow.
      //
      // This is used for determining the "padding-box" of the scroll container
      // which is *sometimes* considered as part of the scrollable area. Inflow
      // children contribute to this area, out-of-flow positioned children
      // don't.
      //
      // Out-of-flow positioned children still contribute to the
      // scrollable-overflow, but just don't influence where this padding is.
      if (Node().IsScrollContainer() && !IsFragmentainerBoxType() &&
          !child.IsOutOfFlowPositioned()) {
        BoxStrut margins;
        if (child.IsCSSBox()) {
          margins = ComputeMarginsFor(child.Style(),
                                      child_available_size_.inline_size,
                                      GetWritingDirection());
        }

        // If we are in block-flow layout we use the end *margin-strut* as the
        // block-end "margin" (instead of just the block-end margin).
        if (margin_strut) {
          MarginStrut end_margin_strut = *margin_strut;
          end_margin_strut.Append(margins.block_end, /* is_quirky */ false);

          // Self-collapsing blocks are special, their end margin-strut is part
          // of their inflow position. To correctly determine the "end" margin,
          // we need to the "final" margin-strut from their end margin-strut.
          margins.block_end = is_self_collapsing
                                  ? end_margin_strut.Sum() - margin_strut->Sum()
                                  : end_margin_strut.Sum();
        }

        // Use the original offset (*without* relative-positioning applied).
        LogicalFragment fragment(GetWritingDirection(), child);
        LogicalRect bounds = {child_offset, fragment.Size()};

        // Margins affect the inflow-bounds in interesting ways.
        //
        // For the margin which is closest to the direction which we are
        // scrolling, we allow negative margins, but only up to the size of the
        // fragment. For the margin furthest away we disallow negative margins.
        if (!margins.IsEmpty()) {
          // Convert the physical overflow directions to logical.
          const bool has_top_overflow = Node().HasTopOverflow();
          const bool has_left_overflow = Node().HasLeftOverflow();
          PhysicalToLogical<bool> converter(
              GetWritingDirection(), has_top_overflow, !has_left_overflow,
              !has_top_overflow, has_left_overflow);

          if (converter.InlineStart()) {
            margins.inline_end = margins.inline_end.ClampNegativeToZero();
            margins.inline_start =
                std::max(margins.inline_start, -fragment.InlineSize());
          } else {
            margins.inline_start = margins.inline_start.ClampNegativeToZero();
            margins.inline_end =
                std::max(margins.inline_end, -fragment.InlineSize());
          }
          if (converter.BlockStart()) {
            margins.block_end = margins.block_end.ClampNegativeToZero();
            margins.block_start =
                std::max(margins.block_start, -fragment.BlockSize());
          } else {
            margins.block_start = margins.block_start.ClampNegativeToZero();
            margins.block_end =
                std::max(margins.block_end, -fragment.BlockSize());
          }

          // Shift the bounds by the (potentially clamped) margins.
          bounds.offset -= {margins.inline_start, margins.block_start};
          bounds.size.inline_size += margins.InlineSum();
          bounds.size.block_size += margins.BlockSum();

          // Our bounds size should never go negative.
          DCHECK_GE(bounds.size.inline_size, LayoutUnit());
          DCHECK_GE(bounds.size.block_size, LayoutUnit());
        }

        // Even an empty (0x0) fragment contributes to the inflow-bounds.
        if (!inflow_bounds_)
          inflow_bounds_ = bounds;
        else
          inflow_bounds_->UniteEvenIfEmpty(bounds);
      }
    }
  }

  DCHECK(relative_offset);
  PropagateFromFragment(child, child_offset, *relative_offset,
                        inline_container);
  AddChildInternal(&child, child_offset + *relative_offset);

  // We have got some content, so follow normal breaking rules from now on.
  SetRequiresContentBeforeBreaking(false);
}

void BoxFragmentBuilder::AddBreakToken(const BreakToken* token,
                                       bool is_in_parallel_flow) {
  // If there's a pre-set break token, we shouldn't be here.
  DCHECK(!break_token_);

  DCHECK(token);
  child_break_tokens_.push_back(token);
  has_inflow_child_break_inside_ |= !is_in_parallel_flow;
}

EBreakBetween BoxFragmentBuilder::JoinedBreakBetweenValue(
    EBreakBetween break_before) const {
  return JoinFragmentainerBreakValues(previous_break_after_, break_before);
}

void BoxFragmentBuilder::MoveChildrenInBlockDirection(LayoutUnit delta) {
  DCHECK(is_new_fc_);
  DCHECK_NE(FragmentBlockSize(), kIndefiniteSize);
  DCHECK(oof_positioned_descendants_.empty());

  has_moved_children_in_block_direction_ = true;

  if (delta == LayoutUnit())
    return;

  if (first_baseline_)
    *first_baseline_ += delta;
  if (last_baseline_)
    *last_baseline_ += delta;

  if (inflow_bounds_)
    inflow_bounds_->offset.block_offset += delta;

  for (auto& child : children_)
    child.offset.block_offset += delta;

  for (auto& candidate : oof_positioned_candidates_)
    candidate.static_position.offset.block_offset += delta;
  for (auto& descendant : oof_positioned_fragmentainer_descendants_) {
    // If we have already returned past (above) the containing block of the OOF
    // (but not all the way the outermost fragmentainer), the containing block
    // is affected by this shift that we just decided to make. This shift wasn't
    // known at the time of normal propagation. So shift accordingly now.
    descendant.containing_block.IncreaseBlockOffset(delta);
    descendant.fixedpos_containing_block.IncreaseBlockOffset(delta);
  }

  if (FragmentItemsBuilder* items_builder = ItemsBuilder()) {
    items_builder->MoveChildrenInBlockDirection(delta);
  }
}

void BoxFragmentBuilder::PropagateBreakInfo(
    const LayoutResult& child_layout_result,
    LogicalOffset offset) {
  DCHECK(has_block_fragmentation_);

  // Include the bounds of this child (in the block direction).
  LayoutUnit block_end_in_container =
      offset.block_offset -
      child_layout_result.AnnotationBlockOffsetAdjustment() +
      BlockSizeForFragmentation(child_layout_result, writing_direction_);

  block_size_for_fragmentation_ =
      std::max(block_size_for_fragmentation_, block_end_in_container);

  if (GetConstraintSpace().RequiresContentBeforeBreaking()) {
    if (child_layout_result.IsBlockSizeForFragmentationClamped())
      is_block_size_for_fragmentation_clamped_ = true;
  }

  const auto& child_fragment = child_layout_result.GetPhysicalFragment();
  const auto* child_box_fragment =
      DynamicTo<PhysicalBoxFragment>(child_fragment);
  const BlockBreakToken* token =
      child_box_fragment ? child_box_fragment->GetBreakToken() : nullptr;

  // Figure out if this child break is in the same flow as this parent. If it's
  // an out-of-flow positioned box, it's not. If it's in a parallel flow, it's
  // also not.
  bool child_is_in_same_flow =
      ((!token || !token->IsAtBlockEnd()) &&
       !child_fragment.IsFloatingOrOutOfFlowPositioned()) ||
      child_layout_result.ShouldForceSameFragmentationFlow();

  // If we're paginated, monolithic overflow will be placed on subsequent pages,
  // even though there are no fragments for the content there. We need to be
  // aware of such overflow when laying out subsequent pages, so that we can
  // move past it, rather than overlapping with it. This approach works (kind
  // of) because in our implementation, pages are stacked in the block
  // direction, so that the block-start offset of the next page is the same as
  // the block-end offset of the preceding page.
  //
  // We need to reserve space for monolithic overflow caused by any child that
  // is in the same flow as its parent, so that subsequent content in this flow
  // gets pushed below the monolithic overflow. If we're at the root, even
  // include content from parallel flows, since we want to encompass everything
  // in that case, in order to create enough pages for it.
  //
  // Some children disable this monolithic overflow propagation, if they are
  // out-of-flow and inside another out-of-flow (so that the containing block
  // chain is broken), and the outer out-of-flow has clipped overflow.
  //
  // TODO(mstensho): Figure out if the !IsFragmentainerBoxType() condition below
  // makes any sense.
  if (GetConstraintSpace().IsPaginated() &&
      ((child_is_in_same_flow && !IsFragmentainerBoxType()) ||
       Node().IsPaginatedRoot()) &&
      (!child_box_fragment ||
       !child_box_fragment->IsMonolithicOverflowPropagationDisabled())) {
    DCHECK(GetConstraintSpace().HasKnownFragmentainerBlockSize());
    // Include overflow inside monolithic content if this is for a page
    // fragment. Otherwise just use the fragment size.
    LayoutUnit block_size;
    if (Node().IsPaginatedRoot() &&
        !child_fragment.HasNonVisibleBlockOverflow()) {
      // The root node is guaranteed to be block-level, so there should be a
      // child box fragment here.
      DCHECK(child_box_fragment);

      LogicalBoxFragment logical_fragment(
          child_box_fragment->Style().GetWritingDirection(),
          *child_box_fragment);
      block_size = logical_fragment.BlockEndScrollableOverflow();
    } else {
      LogicalFragment logical_fragment(
          child_fragment.Style().GetWritingDirection(), child_fragment);
      block_size = logical_fragment.BlockSize();
    }
    LayoutUnit fragment_block_end = offset.block_offset + block_size;
    LayoutUnit fragmentainer_overflow =
        fragment_block_end -
        FragmentainerSpaceLeft(*this, /*is_for_children=*/false);
    if (fragmentainer_overflow > LayoutUnit()) {
      // This child overflows the page, because there's something monolithic
      // inside.
      ReserveSpaceForMonolithicOverflow(fragmentainer_overflow);
    }
  }

  if (IsBreakInside(token)) {
    if (child_is_in_same_flow) {
      has_inflow_child_break_inside_ = true;
    }

    // Downgrade the appeal of breaking inside this container, if the break
    // inside the child is less appealing than what we've found so far.
    BreakAppeal appeal_inside =
        CalculateBreakAppealInside(GetConstraintSpace(), child_layout_result);
    ClampBreakAppeal(appeal_inside);
  }

  if (IsInitialColumnBalancingPass()) {
    PropagateTallestUnbreakableBlockSize(
        child_layout_result.TallestUnbreakableBlockSize());
  }

  if (child_layout_result.HasForcedBreak())
    SetHasForcedBreak();
  else if (!IsInitialColumnBalancingPass())
    PropagateSpaceShortage(child_layout_result.MinimalSpaceShortage());

  if (!child_box_fragment) {
    return;
  }

  // If a spanner was found inside the child, we need to finish up and propagate
  // the spanner to the column layout algorithm, so that it can take care of it.
  if (GetConstraintSpace().IsInColumnBfc()) [[unlikely]] {
    if (const auto* child_spanner_path =
            child_layout_result.GetColumnSpannerPath()) {
      DCHECK(HasInflowChildBreakInside() ||
             !child_layout_result.GetPhysicalFragment().IsBox());
      const auto* spanner_path =
          MakeGarbageCollected<ColumnSpannerPath>(Node(), child_spanner_path);
      SetColumnSpannerPath(spanner_path);
      SetIsEmptySpannerParent(child_layout_result.IsEmptySpannerParent());
    }
  } else {
    DCHECK(!child_layout_result.GetColumnSpannerPath());
  }

  if (!child_box_fragment->IsFragmentainerBox() &&
      !HasOutOfFlowInFragmentainerSubtree()) {
    SetHasOutOfFlowInFragmentainerSubtree(
        child_box_fragment->HasOutOfFlowInFragmentainerSubtree());
  }
}

void BoxFragmentBuilder::PropagateChildBreakValues(
    const LayoutResult& child_layout_result) {
  if (child_layout_result.Status() != LayoutResult::kSuccess) {
    return;
  }

  // Propagate from regular in-flow child blocks, and also from page areas and
  // page border boxes (need to do this for page* boxes in order to propagate
  // page names).
  const auto& fragment = child_layout_result.GetPhysicalFragment();
  if (fragment.IsInline() || !fragment.IsBox() || fragment.IsColumnBox() ||
      fragment.IsFloatingOrOutOfFlowPositioned()) {
    return;
  }

  const ComputedStyle& child_style = fragment.Style();

  // We need to propagate the initial break-before value up our container
  // chain, until we reach a container that's not a first child. If we get all
  // the way to the root of the fragmentation context without finding any such
  // container, we have no valid class A break point, and if a forced break
  // was requested, none will be inserted.
  EBreakBetween break_before = JoinFragmentainerBreakValues(
      child_layout_result.InitialBreakBefore(), child_style.BreakBefore());
  SetInitialBreakBeforeIfNeeded(break_before);

  // We also need to store the previous break-after value we've seen, since it
  // will serve as input to the next breakpoint (where we will combine the
  // break-after value of the previous child and the break-before value of the
  // next child, to figure out what to do at the breakpoint). The break-after
  // value of the last child will also be propagated up our container chain,
  // until we reach a container that's not a last child. This will be the
  // class A break point that it affects.
  EBreakBetween break_after = JoinFragmentainerBreakValues(
      child_layout_result.FinalBreakAfter(), child_style.BreakAfter());
  SetPreviousBreakAfter(break_after);

  SetPageNameIfNeeded(To<PhysicalBoxFragment>(fragment).PageName());
}

void BoxFragmentBuilder::HandleOofsAndSpecialDescendants() {
  OutOfFlowLayoutPart(this).Run();
  if (Style().ScrollMarkerGroup() != EScrollMarkerGroup::kNone &&
      !GetConstraintSpace().IsAnonymous()) {
    Node().HandleScrollMarkerGroup();
  }
}

const LayoutResult* BoxFragmentBuilder::ToBoxFragment(
    WritingMode block_or_line_writing_mode) {
#if DCHECK_IS_ON()
  if (ItemsBuilder()) {
    for (const LogicalFragmentLink& child : Children()) {
      DCHECK(child.fragment);
      const PhysicalFragment& fragment = *child.fragment;
      DCHECK(fragment.IsLineBox() ||
             // TODO(kojii): How to place floats and OOF is TBD.
             fragment.IsFloatingOrOutOfFlowPositioned());
    }
  }
#endif

  if (box_type_ == PhysicalFragment::kNormalBox && node_ &&
      node_.IsBlockInInline()) [[unlikely]] {
    SetIsBlockInInline();
  }

  if (has_block_fragmentation_ && node_) [[unlikely]] {
    if (PreviousBreakToken() && PreviousBreakToken()->IsAtBlockEnd()) {
      // Avoid trailing margin propagation from a node that just has overflowing
      // content here in the current fragmentainer. It's in a parallel flow. If
      // we don't prevent such propagation, the trailing margin may push down
      // subsequent nodes that are being resumed after a break, rather than
      // resuming at the block-start of the fragmentainer.
      end_margin_strut_ = MarginStrut();
    }

    if (!break_token_) {
      if (last_inline_break_token_)
        child_break_tokens_.push_back(std::move(last_inline_break_token_));
      if (DidBreakSelf() || ShouldBreakInside())
        break_token_ = BlockBreakToken::Create(this);
    }

    // Make some final adjustments to block-size for fragmentation, unless this
    // is a fragmentainer (so that we only include the block-size propagated
    // from children in that case).
    if (!PhysicalFragment::IsFragmentainerBoxType(box_type_)) {
      OverflowClipAxes block_axis = GetWritingDirection().IsHorizontal()
                                        ? kOverflowClipY
                                        : kOverflowClipX;
      if ((To<BlockNode>(node_).GetOverflowClipAxes() & block_axis) ||
          is_block_size_for_fragmentation_clamped_) {
        // If block-axis overflow is clipped, ignore child overflow and just use
        // the border-box size of the fragment itself. Also do this if the node
        // was forced to stay in the current fragmentainer. We'll ignore
        // overflow in such cases, because children are allowed to overflow
        // without affecting fragmentation then.
        block_size_for_fragmentation_ = FragmentBlockSize();
      } else {
        // Include the border-box size of the fragment itself.
        block_size_for_fragmentation_ =
            std::max(block_size_for_fragmentation_, FragmentBlockSize());
      }

      // If the node fits inside the current fragmentainer, any break inside it
      // will establish a parallel flow, which means that breaking early inside
      // it isn't going to help honor any break avoidance requests on content
      // that comes after this node. So don't propagate it.
      if (IsKnownToFitInFragmentainer())
        early_break_ = nullptr;
    }
  }

  const PhysicalBoxFragment* fragment =
      PhysicalBoxFragment::Create(this, block_or_line_writing_mode);
  fragment->CheckType();

  return MakeGarbageCollected<LayoutResult>(
      LayoutResult::BoxFragmentBuilderPassKey(), std::move(fragment), this);
}

void BoxFragmentBuilder::AdjustFragmentainerDescendant(
    LogicalOofNodeForFragmentation& descendant,
    bool only_fixedpos_containing_block) {
  LayoutUnit previous_consumed_block_size;
  if (PreviousBreakToken())
    previous_consumed_block_size = PreviousBreakToken()->ConsumedBlockSize();

  // If the containing block is fragmented, adjust the offset to be from the
  // first containing block fragment to the fragmentation context root. Also,
  // adjust the static position to be relative to the adjusted containing block
  // offset.
  if (!only_fixedpos_containing_block &&
      !descendant.containing_block.Fragment()) {
    descendant.containing_block.IncreaseBlockOffset(
        -previous_consumed_block_size);
    descendant.static_position.offset.block_offset +=
        previous_consumed_block_size;
  }

  // If the fixedpos containing block is fragmented, adjust the offset to be
  // from the first containing block fragment to the fragmentation context root.
  if (!descendant.fixedpos_containing_block.Fragment() &&
      (node_.IsFixedContainer() ||
       descendant.fixedpos_inline_container.container)) {
    descendant.fixedpos_containing_block.IncreaseBlockOffset(
        -previous_consumed_block_size);
  }
}

void BoxFragmentBuilder::
    AdjustFixedposContainingBlockForFragmentainerDescendants() {
  if (!HasOutOfFlowFragmentainerDescendants())
    return;

  for (auto& descendant : oof_positioned_fragmentainer_descendants_) {
    AdjustFragmentainerDescendant(descendant,
                                  /* only_fixedpos_containing_block */ true);
  }
}

void BoxFragmentBuilder::AdjustFixedposContainingBlockForInnerMulticols() {
  if (!HasMulticolsWithPendingOOFs() || !PreviousBreakToken())
    return;

  // If the fixedpos containing block is fragmented, adjust the offset to be
  // from the first containing block fragment to the fragmentation context root.
  // Also, update the multicol offset such that it is relative to the fixedpos
  // containing block.
  LayoutUnit previous_consumed_block_size =
      PreviousBreakToken()->ConsumedBlockSize();
  for (auto& multicol : multicols_with_pending_oofs_) {
    MulticolWithPendingOofs<LogicalOffset>& value = *multicol.value;
    if (!value.fixedpos_containing_block.Fragment() &&
        (node_.IsFixedContainer() ||
         value.fixedpos_inline_container.container)) {
      value.fixedpos_containing_block.IncreaseBlockOffset(
          -previous_consumed_block_size);
      value.multicol_offset.block_offset += previous_consumed_block_size;
    }
  }
}

#if DCHECK_IS_ON()

void BoxFragmentBuilder::CheckNoBlockFragmentation() const {
  DCHECK(!ShouldBreakInside());
  DCHECK(!HasInflowChildBreakInside());
  DCHECK(!DidBreakSelf());
  DCHECK(!has_forced_break_);
  DCHECK(GetConstraintSpace().ShouldRepeat() || !HasBreakTokenData());
  DCHECK_EQ(minimal_space_shortage_, kIndefiniteSize);
  if (!GetConstraintSpace().ShouldPropagateChildBreakValues()) {
    DCHECK(!initial_break_before_);
    DCHECK_EQ(previous_break_after_, EBreakBetween::kAuto);
  }
}

#endif

}  // namespace blink

"""

```