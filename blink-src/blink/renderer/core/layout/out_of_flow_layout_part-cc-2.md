Response:
My thought process to answer the request goes like this:

1. **Understand the Core Request:** The request asks for the functionality of a specific C++ source code file (`out_of_flow_layout_part.cc`) within the Chromium Blink rendering engine. It also asks for connections to web technologies (HTML, CSS, JavaScript), examples, logical reasoning with input/output, common usage errors, and a summary. Crucially, it specifies *part 3 of 5*. This means the analysis should focus on the code *within* the provided snippet.

2. **Initial Code Scan and High-Level Understanding:** I first read through the provided code snippet to grasp its overall purpose. Keywords like "out-of-flow," "descendants," "fragmentainer," "anchor positioning," "offset," and "layout" immediately jump out. The code seems to deal with the layout of elements that are taken out of the normal document flow (like `position: absolute` or `position: fixed`).

3. **Break Down into Key Sections:** I mentally divide the code into logical sections based on the function definitions and the flow of operations. The major functions I see are:
    * `LayoutOutOfFlowChildren`: This is the main function in this snippet and iterates through and lays out out-of-flow elements.
    * `CreateAnchorEvaluator`:  Handles the creation of an object to evaluate anchor relationships (for CSS anchor positioning).
    * `SetupNodeInfo`:  Gathers information about the out-of-flow node and its containing blocks.
    * `LayoutOOFNode`:  Performs the actual layout of a single out-of-flow node, including handling scrollbars and potential re-layout.
    * The anonymous namespace with `SortNonOverflowingCandidates` and the `NonOverflowingCandidate` struct: This deals with the logic for handling `position-try-fallbacks`.
    * `CalculateOffset` and `TryCalculateOffset`:  These functions are central to determining the position of the out-of-flow element, considering various factors like anchor positioning and `position-try-fallbacks`.

4. **Analyze Each Section for Functionality:**  I then go through each section and try to explain what it does. For example:
    * `LayoutOutOfFlowChildren`: It iterates through descendant out-of-flow elements, potentially delays layout based on fragmentainers, considers anchor positioning dependencies, determines starting fragmentainers, and then layouts the elements within their respective fragmentainers.
    * `CreateAnchorEvaluator`:  It creates an `AnchorEvaluatorImpl` object, which is crucial for resolving the positions of elements using CSS anchor positioning. It takes into account implicit anchors.
    * `SetupNodeInfo`: It gathers vital information like the node itself, its static position, containing block information, and writing direction.
    * `LayoutOOFNode`: This is where the core layout happens. It calls the main `Layout` function, and also handles the complexity of re-laying out if scrollbars appear or disappear, and deals with display locks for anchor positioning.
    * The `@position-try` logic: This section implements the CSS `position-try-fallbacks` feature, trying different positioning options until one fits or a defined order is followed.

5. **Connect to Web Technologies (HTML, CSS, JavaScript):**  As I understand the functionality, I think about how these C++ functions relate to what web developers do:
    * **CSS:** The code directly implements CSS features like `position: absolute/fixed`, CSS anchor positioning (`anchor-name`, `anchor()`, `inset()`), fragmentation (columns), and `position-try-fallbacks`.
    * **HTML:** The layout process is about positioning HTML elements. The code deals with the structure of the HTML document (parent-child relationships).
    * **JavaScript:** While this C++ code doesn't directly *execute* JavaScript, the layout it performs influences how JavaScript interacts with the page. For example, JavaScript might read element positions or trigger reflows.

6. **Provide Examples:**  For each connection to web technologies, I try to create simple, concrete examples. This makes the explanation clearer and shows the practical impact of the C++ code.

7. **Logical Reasoning (Input/Output):** I try to think of specific scenarios and how the code would handle them. This often involves considering the inputs to the functions (e.g., node properties, containing block information) and the expected outputs (e.g., element position). The `@position-try` example is a good illustration of this.

8. **Common Usage Errors:** I consider what mistakes web developers might make that would be related to this code. Incorrectly specified anchor relationships, forgetting about containing block relationships with `position: fixed`, and misusing `position-try-fallbacks` are good examples.

9. **Focus on Part 3:**  It's crucial to remember that this is *part 3*. This means the analysis should primarily focus on the functionality within this specific code snippet. I avoid making assumptions or broad statements about the entire `out_of_flow_layout_part.cc` file, as the other parts might handle different aspects.

10. **Summarize the Functionality:**  Finally, I provide a concise summary that captures the main responsibilities of the code in this particular part. The summary emphasizes the layout of out-of-flow elements, handling fragmentation, and the complexities introduced by CSS anchor positioning and `position-try-fallbacks`.

11. **Review and Refine:** I reread my answer to ensure it is accurate, clear, and directly addresses all parts of the request. I check for any inconsistencies or areas where further clarification might be needed. I ensure the examples are valid and easy to understand.

By following these steps, I can construct a comprehensive and accurate answer that addresses all aspects of the prompt. The key is to combine a detailed understanding of the code with knowledge of web technologies and common development practices.
好的，让我们来分析一下 `blink/renderer/core/layout/out_of_flow_layout_part.cc` 文件的这段代码（第 3 部分）。

**核心功能归纳：**

这段代码的主要功能是负责 **布局处理超出正常文档流的元素 (out-of-flow elements)**，例如 `position: absolute` 或 `position: fixed` 的元素。 它专注于在不同的分片容器 (fragmentainer) 中定位和布局这些元素，并处理与 CSS 锚点定位 (`CSS Anchor Positioning`) 和 `position-try-fallbacks` 相关的复杂逻辑。

**详细功能列举：**

1. **按分片容器索引排序后代元素：**
   - 代码首先对需要布局的后代元素 (`descendants_to_layout`) 按照它们所属的分片容器索引进行排序。
   - **原因：** 确保这些超出文档流的元素按照正确的顺序进行布局，特别是当它们可能分布在不同的列或分页中时。

2. **处理列跨越元素和延迟布局：**
   - 如果当前的分片容器类型是列 (`kFragmentColumn`)，并且遇到了列跨越元素 (column spanner) 或者正在进行列平衡 (column balancing)，则会检查包含块是否已经完成布局。
   - 如果包含块尚未完成布局，则会将该后代元素添加到 `delayed_descendants_` 列表中，稍后进行布局。
   - **原因：**  超出文档流元素的位置可能依赖于其包含块的最终大小，因此需要等待包含块布局完成后再进行布局。

3. **处理 CSS 锚点定位：**
   - 如果存在 CSS 锚点查询 (`stitched_anchor_queries`) 或者潜在的锚点 (`may_have_anchors_on_oof`)，代码会确保每个包含块在其包含的超出文档流元素布局之前完成布局。
   - 它会按 CSS 包含块对超出文档流元素的布局进行分块处理，以优化性能，减少重建分片容器的次数。
   - **原因：** CSS 锚点定位的计算结果可能因为包含块的不同而有所不同，并且可能需要引用已经布局的其他包含块。

4. **准备节点信息和计算偏移：**
   - 对于每个需要布局的后代元素，代码会调用 `SetupNodeInfo` 获取节点的必要信息（例如，节点、静态位置、包含块信息等）。
   - 然后，调用 `CalculateOffset` 计算元素的偏移量，其中会考虑 CSS 锚点查询。

5. **确定起始分片容器并调整偏移：**
   - 代码会确定超出文档流元素应该从哪个分片容器开始布局 (`start_index`)。
   - 并将元素的偏移量调整为相对于该分片容器的偏移。

6. **按分片容器索引布局超出文档流元素：**
   - 代码按照分片容器的索引顺序遍历 `descendants_to_layout`，并对每个分片容器中的超出文档流元素调用 `LayoutOOFsInFragmentainer` 进行布局。
   - **注意：** 在列平衡阶段会跳过此步骤。

7. **处理重复的固定定位元素：**
   - 代码会处理重复的固定定位元素 (`repeated_fixedpos_descendants`)，特别是在分页根元素的情况下。
   - 当遇到新的分片容器时，会将之前添加的重复固定定位元素再次添加到新的分片容器中。

8. **处理分片和单体溢出：**
   - 代码会检查是否有超出文档流元素分片到新的分片容器中，或者是否存在单体溢出 (monolithic overflow，例如在打印时)。
   - 如果需要，会扩展 `descendants_to_layout` 的大小以容纳新的分片容器。

9. **清理和更新：**
   - 在布局完一个包含块的超出文档流元素后，如果存在锚点，会更新锚点查询 (`stitched_anchor_queries`)。
   - 代码会清理可能从分片冒泡到 `container_builder_` 的后代元素，除非正在进行列平衡。

10. **完成重复固定定位元素的布局：**
    - 对于分页根元素，会最终完成重复固定定位元素的布局。

11. **创建锚点评估器 (`CreateAnchorEvaluator`)：**
    - 此函数用于创建一个 `AnchorEvaluatorImpl` 对象，用于评估 CSS 锚点定位。
    - 它考虑了隐式锚点，并根据是否存在分片来使用不同的锚点查询数据源。

12. **设置节点信息 (`SetupNodeInfo`)：**
    - 此函数用于收集布局超出文档流节点所需的各种信息，例如节点本身、静态位置、基础包含块信息、书写模式等。

13. **布局超出文档流节点 (`LayoutOOFNode`)：**
    - 此函数负责实际布局单个超出文档流节点。
    - 它调用底层的 `Layout` 函数进行布局。
    - **关键点：**  它会处理由于滚动条出现或消失而可能需要的重新布局。这是因为超出文档流元素的尺寸可能依赖于滚动条的存在。它会冻结滚动条并重新布局直到状态稳定。
    - 还会处理与 CSS 锚点定位相关的显示锁 (display locks)。

14. **处理 `position-try-fallbacks` (`CalculateOffset` 和 `TryCalculateOffset`)：**
    - `CalculateOffset` 是计算元素偏移量的主函数，它会调用 `TryCalculateOffset` 来尝试不同的 `@position-try` 候选值。
    - `TryCalculateOffset` 尝试使用不同的样式（来自 `position-try-fallbacks`）来计算偏移量，并检查结果是否在可用空间内。
    - 它会根据 `position-try-order` 属性对成功的候选值进行排序，并选择最佳的偏移量。
    - 它还会考虑 `position-visibility: no-overflow` 属性。

**与 JavaScript, HTML, CSS 的关系：**

* **CSS:**  这段代码的核心功能是实现 CSS 中关于超出文档流元素布局的规范，例如：
    * `position: absolute;`, `position: fixed;`：这段代码处理这些定位方式的元素的布局。
    * `inset`, `top`, `right`, `bottom`, `left` 等属性：计算偏移量时会考虑这些属性。
    * CSS 锚点定位 (`anchor-name`, `anchor()`, `inset()` 函数)：代码中有专门的逻辑来处理锚点定位，创建 `AnchorEvaluatorImpl` 并使用锚点查询。
    * CSS 列布局 (`column-count`, `column-width`, `column-span` 等)：代码会根据分片容器的类型（是否为列）进行不同的处理。
    * CSS 分页 (`break-before`, `break-after`, `break-inside` 等)：代码在处理分页根元素时会考虑分片和重复固定定位元素。
    * `position-try-fallbacks`, `position-visibility`: 代码实现了这些 CSS 属性的逻辑，尝试不同的定位方式并检查是否溢出。

    **示例：**
    ```html
    <div style="position: relative;">
      <div style="position: absolute; top: 10px; left: 20px;">绝对定位元素</div>
    </div>

    <div id="anchor-el" style="position: relative;">我是锚点</div>
    <div style="position: absolute; inset: anchor(--anchor-el)">使用锚点定位的元素</div>

    <div class="container" style="columns: 2;">
      <div style="break-inside: avoid;">我不想被断开</div>
      <div style="position: absolute; top: 0; left: 0;">绝对定位在列容器内的元素</div>
    </div>

    <div style="position: relative;">
      <div style="position: absolute;
                  position-try-fallbacks: top left, bottom right;">尝试不同位置</div>
    </div>
    ```

* **HTML:**  这段代码处理的是 HTML 元素的布局。它遍历 HTML 元素的树结构，特别是超出文档流的元素。

* **JavaScript:** JavaScript 可以通过修改元素的样式（包括 `position` 等属性）来触发这段 C++ 代码的执行。当 JavaScript 动态地改变元素的定位方式或相关属性时，Blink 渲染引擎会重新计算布局，从而调用这段代码。

    **示例：**
    ```javascript
    const element = document.querySelector('.absolute-element');
    element.style.top = '50px'; // JavaScript 修改样式，可能触发重新布局
    ```

**逻辑推理与假设输入/输出：**

**假设输入：**

一个 HTML 结构如下：

```html
<div style="position: relative; width: 200px; height: 100px;">
  <div style="position: absolute; top: 10px; left: 20px; width: 50px; height: 30px;"></div>
</div>
```

**逻辑推理：**

1. `LayoutOutOfFlowChildren` 会被调用来处理绝对定位的 `div` 元素。
2. 代码会检查该元素的包含块（`position: relative` 的父元素）。
3. `CalculateOffset` 会计算绝对定位元素的偏移量，基于 `top: 10px` 和 `left: 20px`。
4. 最终，该绝对定位的 `div` 会被放置在其包含块内的 (10px, 20px) 的位置。

**假设输出：**

绝对定位的 `div` 的最终布局位置（相对于其包含块的内容区域）将会是：`x: 20px, y: 10px`。

**用户或编程常见的使用错误：**

1. **忘记设置包含块：** 对于 `position: absolute` 的元素，如果其父元素没有设置 `position: relative`, `position: absolute`, 或 `position: fixed`，则其包含块会是根元素 (通常是 `<html>`)，这可能导致元素出现在意想不到的位置。

   **示例：**

   ```html
   <div>  <!-- 没有设置 position -->
     <div style="position: absolute; top: 10px; left: 20px;"></div>
   </div>
   ```

2. **误解 `position: fixed` 的包含块：** `position: fixed` 的元素的包含块是视口 (viewport)，而不是其父元素。初学者可能会错误地认为它会相对于父元素定位。

   **示例：**

   ```html
   <div style="position: relative; height: 500px; overflow: auto;">
     <div style="position: fixed; top: 10px; left: 20px;"></div>
   </div>
   ```

   在这个例子中，固定定位的元素会相对于浏览器窗口的左上角定位，而不是相对于父 `div`。

3. **CSS 锚点定位错误：**
    -  锚点元素不存在或无法访问。
    -  锚点查询 `anchor()` 的语法错误。
    -  循环依赖的锚点关系。

4. **`position-try-fallbacks` 使用不当：**
    -  提供的回退位置都无法满足条件，导致元素可能溢出或放置在不期望的位置。
    -  没有理解 `position-try-order` 的作用。

**总结这段代码的功能 (基于第 3 部分)：**

这段代码主要负责 **处理和布局超出正常文档流的子元素**，特别关注于：

* **确保布局顺序的正确性**，尤其是在存在分片容器（如列）的情况下。
* **处理 CSS 锚点定位的复杂性**，包括确定包含块和使用锚点查询。
* **实现 `position-try-fallbacks` 逻辑**，尝试不同的定位方式并选择最佳方案。
* **优化布局性能**，例如通过按包含块分块处理超出文档流元素。
* **处理由于滚动条变化可能导致的重新布局。**

这段代码是 Blink 渲染引擎布局过程中的一个关键组成部分，确保了网页上具有各种定位方式的元素能够正确地呈现给用户。

Prompt: 
```
这是目录为blink/renderer/core/layout/out_of_flow_layout_part.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第3部分，共5部分，请归纳一下它的功能

"""
/ Sort the descendants by fragmentainer index in |descendants_to_layout|.
      // This will ensure that the descendants are laid out in the correct
      // order.
      DCHECK(!descendants_span.empty());
      for (size_t i = 0; i < descendants_span.size(); ++i) {
        auto& descendant = descendants_span[i];
        if (GetFragmentainerType() == kFragmentColumn) {
          auto* containing_block = To<LayoutBox>(
              descendant.containing_block.Fragment()->GetLayoutObject());
          DCHECK(containing_block);

          // We may try to lay out an OOF once we reach a column spanner or when
          // column balancing. However, if the containing block has not finished
          // layout, we should wait to lay out the OOF in case its position is
          // dependent on its containing block's final size.
          if (containing_block->PhysicalFragments().back().GetBreakToken()) {
            delayed_descendants_.push_back(descendant);
            continue;
          }
        }

        // Ensure each containing block is laid out before laying out other
        // containing blocks. The CSS Anchor Positioning may evaluate
        // differently when the containing block is different, and may refer to
        // other containing blocks that were already laid out.
        //
        // Do this only when needed, because doing so may rebuild fragmentainers
        // multiple times, which can hit the performance when there are many
        // containing blocks in the block formatting context.
        //
        // Use |LayoutObject::Container|, not |LayoutObject::ContainingBlock|.
        // The latter is not the CSS containing block for inline boxes. See the
        // comment of |LayoutObject::ContainingBlock|.
        //
        // Note |descendant.containing_block.fragment| is |ContainingBlock|, not
        // the CSS containing block.
        if (!stitched_anchor_queries.IsEmpty() || may_have_anchors_on_oof) {
          const LayoutObject* css_containing_block =
              descendant.box->Container();
          DCHECK(css_containing_block);
          if (css_containing_block != last_css_containing_block) {
            // Chunking the layout of OOFs by the containing blocks is done only
            // if it has anchor query, for the performance reasons to minimize
            // the number of rebuilding fragmentainer fragments.
            if (last_css_containing_block &&
                (last_css_containing_block->MayHaveAnchorQuery() ||
                 may_have_anchors_on_oof)) {
              has_new_descendants_span = true;
              descendants_span = descendants_span.subspan(i);
              break;
            }
            last_css_containing_block = css_containing_block;
          }
        }

        NodeInfo node_info = SetupNodeInfo(descendant);
        NodeToLayout node_to_layout = {
            node_info, CalculateOffset(node_info, &stitched_anchor_queries)};
        node_to_layout.containing_block_fragment =
            descendant.containing_block.Fragment();
        node_to_layout.offset_info.original_offset =
            node_to_layout.offset_info.offset;

        DCHECK(node_to_layout.offset_info.block_estimate);

        // Determine in which fragmentainer this OOF element will start its
        // layout and adjust the offset to be relative to that fragmentainer.
        wtf_size_t start_index = 0;
        ComputeStartFragmentIndexAndRelativeOffset(
            node_info.default_writing_direction.GetWritingMode(),
            *node_to_layout.offset_info.block_estimate,
            node_info.containing_block.ClippedContainerBlockOffset(),
            &start_index, &node_to_layout.offset_info.offset);
        if (start_index >= descendants_to_layout.size())
          descendants_to_layout.resize(start_index + 1);
        descendants_to_layout[start_index].emplace_back(node_to_layout);
      }

      HeapVector<NodeToLayout> fragmented_descendants;
      ClearCollectionScope<HeapVector<NodeToLayout>>
          fragmented_descendants_scope(&fragmented_descendants);
      fragmentainer_consumed_block_size_ = LayoutUnit();

      // Even if all OOFs are done creating fragments, we need to create enough
      // fragmentainers to encompass all monolithic overflow when printing.
      LayoutUnit monolithic_overflow;

      // Set to true if an OOF inside a fragmentainer breaks. This does not
      // include repeated fixed-positioned elements.
      bool last_fragmentainer_has_break_inside = false;

      // Layout the OOF descendants in order of fragmentainer index.
      for (wtf_size_t index = 0; index < descendants_to_layout.size();
           index++) {
        const PhysicalBoxFragment* fragment = nullptr;
        if (index < ChildCount()) {
          fragment = &GetChildFragment(index);
        } else if (column_balancing_info_) {
          column_balancing_info_->num_new_columns++;
        }

        // Skip over any column spanners.
        if (!fragment || fragment->IsFragmentainerBox()) {
          HeapVector<NodeToLayout>& pending_descendants =
              descendants_to_layout[index];

          if (!repeated_fixedpos_descendants.empty() &&
              index == previous_repeaded_fixedpos_resume_idx) {
            // This is a new fragmentainer, and we had previously added repeated
            // fixed-positioned elements to all preceding fragmentainers (in a
            // previous iteration; this may happen when there are nested OOFs).
            // We now need to make sure that we add the repeated
            // fixed-positioned elements to all new fragmentainers as well.
            fragmented_descendants.PrependVector(repeated_fixedpos_descendants);
            // We need to clear the vector, since we'll find and re-add all the
            // repeated elements (both these, and any new ones discovered) in
            // fragmented_descendants when we're done with the current loop.
            repeated_fixedpos_descendants.clear();
          }

          bool has_oofs_in_later_fragmentainer =
              index + 1 < descendants_to_layout.size();
          last_fragmentainer_has_break_inside = false;
          LayoutOOFsInFragmentainer(
              pending_descendants, index, fragmentainer_progression,
              has_oofs_in_later_fragmentainer, &monolithic_overflow,
              &last_fragmentainer_has_break_inside, &fragmented_descendants);

          // Retrieve the updated or newly added fragmentainer, and add its
          // block contribution to the consumed block size. Skip this if we are
          // column balancing, though, since this is only needed when adding
          // OOFs to the builder in the true layout pass.
          if (!column_balancing_info_) {
            fragment = &GetChildFragment(index);
            fragmentainer_consumed_block_size_ +=
                fragment->Size()
                    .ConvertToLogical(
                        container_builder_->Style().GetWritingMode())
                    .block_size;
          }
        }

        // Extend |descendants_to_layout| if an OOF element fragments into a
        // fragmentainer at an index that does not yet exist in
        // |descendants_to_layout|. We also need to do this if there's
        // monolithic overflow (when printing), so that there are enough
        // fragmentainers to paint the overflow. At the same time we need to
        // make sure that repeated fixed-positioned elements don't trigger
        // creation of additional fragmentainers on their own (since they'd just
        // repeat forever).
        if (index == descendants_to_layout.size() - 1 &&
            (last_fragmentainer_has_break_inside ||
             monolithic_overflow > LayoutUnit() ||
             (!fragmented_descendants.empty() && index + 1 < ChildCount()))) {
          descendants_to_layout.resize(index + 2);
        }
      }

      if (!fragmented_descendants.empty()) {
        // We have repeated fixed-positioned elements. If we add more
        // fragmentainers in the next iteration (because of nested OOFs), we
        // need to resume those when a new fragmentainer is added.
        DCHECK(container_builder_->Node().IsPaginatedRoot());
        DCHECK(previous_repeaded_fixedpos_resume_idx == WTF::kNotFound ||
               previous_repeaded_fixedpos_resume_idx <=
                   descendants_to_layout.size());
        previous_repeaded_fixedpos_resume_idx = descendants_to_layout.size();

        // Add all repeated fixed-positioned elements to a list that we'll
        // consume if we add more fragmentainers in a subsequent iteration
        // (because of nested OOFs), so that we keep on generating fragments for
        // the repeated fixed-positioned elements in the new fragmentainers as
        // well.
        repeated_fixedpos_descendants.AppendVector(fragmented_descendants);
      }
      descendants_to_layout.Shrink(0);

      if (!has_new_descendants_span)
        break;
      // If laying out by containing blocks and there are more containing blocks
      // to be laid out, move on to the next containing block. Before laying
      // them out, if OOFs have anchors, update the anchor queries.
      if (may_have_anchors_on_oof) {
        stitched_anchor_queries.SetChildren(
            builder_for_anchor_query->Children());
      }
    }

    // Sweep any descendants that might have been bubbled up from the fragment
    // to the |container_builder_|. This happens when we have nested absolute
    // position elements.
    //
    // Don't do this if we are in a column balancing pass, though, since we
    // won't propagate OOF info of nested OOFs in this case. Any OOFs already
    // added to the builder should remain there so that they can be handled
    // later.
    descendants->Shrink(0);
    if (!column_balancing_info_)
      container_builder_->SwapOutOfFlowFragmentainerDescendants(descendants);
  }

  if (container_builder_->Node().IsPaginatedRoot()) {
    // Finish repeated fixed-positioned elements.
    for (const NodeToLayout& node_to_layout : repeated_fixedpos_descendants) {
      const BlockNode& node = node_to_layout.node_info.node;
      DCHECK_EQ(node.Style().GetPosition(), EPosition::kFixed);
      node.FinishRepeatableRoot();
    }
  } else {
    DCHECK(repeated_fixedpos_descendants.empty());
  }
}

AnchorEvaluatorImpl OutOfFlowLayoutPart::CreateAnchorEvaluator(
    const ContainingBlockInfo& container_info,
    const BlockNode& candidate,
    const LogicalAnchorQueryMap* anchor_queries) const {
  const LayoutObject* implicit_anchor = nullptr;
  const LayoutBox& candidate_layout_box = *candidate.GetLayoutBox();
  if (const Element* element =
          DynamicTo<Element>(candidate_layout_box.GetNode())) {
    if (const Element* implicit_anchor_element =
            element->ImplicitAnchorElement()) {
      implicit_anchor = implicit_anchor_element->GetLayoutObject();
    }
  }

  LogicalSize container_content_size = container_info.rect.size;
  PhysicalSize container_physical_content_size = ToPhysicalSize(
      container_content_size, GetConstraintSpace().GetWritingMode());
  WritingDirectionMode self_writing_direction =
      candidate.Style().GetWritingDirection();
  const WritingModeConverter container_converter(
      container_info.writing_direction, container_physical_content_size);
  if (anchor_queries) {
    // When the containing block is block-fragmented, the |container_builder_|
    // is the fragmentainer, not the containing block, and the coordinate system
    // is stitched. Use the given |anchor_query|.
    const LayoutObject* css_containing_block = candidate_layout_box.Container();
    CHECK(css_containing_block);
    return AnchorEvaluatorImpl(
        candidate_layout_box, *anchor_queries, implicit_anchor,
        *css_containing_block, container_converter, self_writing_direction,
        container_converter.ToPhysical(container_info.rect).offset,
        container_physical_content_size);
  }
  if (const LogicalAnchorQuery* anchor_query =
          container_builder_->AnchorQuery()) {
    // Otherwise the |container_builder_| is the containing block.
    return AnchorEvaluatorImpl(
        candidate_layout_box, *anchor_query, implicit_anchor,
        container_converter, self_writing_direction,
        container_converter.ToPhysical(container_info.rect).offset,
        container_physical_content_size);
  }
  return AnchorEvaluatorImpl();
}

OutOfFlowLayoutPart::NodeInfo OutOfFlowLayoutPart::SetupNodeInfo(
    const LogicalOofPositionedNode& oof_node) {
  BlockNode node = oof_node.Node();
  const PhysicalFragment* containing_block_fragment =
      oof_node.is_for_fragmentation
          ? To<LogicalOofNodeForFragmentation>(oof_node)
                .containing_block.Fragment()
          : nullptr;

#if DCHECK_IS_ON()
  const LayoutObject* container =
      containing_block_fragment ? containing_block_fragment->GetLayoutObject()
                                : container_builder_->GetLayoutObject();

  if (container) {
    // "OutOfFlowLayoutPart container is ContainingBlock" invariant cannot be
    // enforced for tables. Tables are special, in that the ContainingBlock is
    // TABLE, but constraint space is generated by TBODY/TR/. This happens
    // because TBODY/TR are not LayoutBlocks, but LayoutBoxModelObjects.
    DCHECK(container == node.GetLayoutBox()->ContainingBlock() ||
           node.GetLayoutBox()->ContainingBlock()->IsTable());
  } else {
    // If there's no layout object associated, the containing fragment should be
    // a page, and the containing block of the node should be the LayoutView.
    DCHECK_EQ(containing_block_fragment->GetBoxType(),
              PhysicalFragment::kPageArea);
    DCHECK_EQ(node.GetLayoutBox()->ContainingBlock(),
              node.GetLayoutBox()->View());
  }
#endif

  const ContainingBlockInfo base_container_info =
      GetContainingBlockInfo(oof_node);

  OofContainingBlock<LogicalOffset> containing_block;
  OofContainingBlock<LogicalOffset> fixedpos_containing_block;
  OofInlineContainer<LogicalOffset> fixedpos_inline_container;
  if (containing_block_fragment) {
    containing_block =
        To<LogicalOofNodeForFragmentation>(oof_node).containing_block;
    fixedpos_containing_block =
        To<LogicalOofNodeForFragmentation>(oof_node).fixedpos_containing_block;
    fixedpos_inline_container =
        To<LogicalOofNodeForFragmentation>(oof_node).fixedpos_inline_container;
  }

  return NodeInfo(
      node, oof_node.static_position, base_container_info,
      GetConstraintSpace().GetWritingDirection(),
      /* is_fragmentainer_descendant */ containing_block_fragment,
      containing_block, fixedpos_containing_block, fixedpos_inline_container,
      oof_node.requires_content_before_breaking, oof_node.is_hidden_for_paint);
}

const LayoutResult* OutOfFlowLayoutPart::LayoutOOFNode(
    NodeToLayout& oof_node_to_layout,
    const ConstraintSpace* fragmentainer_constraint_space,
    bool is_last_fragmentainer_so_far) {
  const HeapHashSet<Member<Element>>* past_display_lock_elements = nullptr;
  if (auto* box = oof_node_to_layout.node_info.node.GetLayoutBox()) {
    past_display_lock_elements = box->DisplayLocksAffectedByAnchors();
  }

  const NodeInfo& node_info = oof_node_to_layout.node_info;
  OffsetInfo& offset_info = oof_node_to_layout.offset_info;

  BoxStrut scrollbars_before = ComputeScrollbarsForNonAnonymous(node_info.node);
  const LayoutResult* layout_result =
      Layout(oof_node_to_layout, fragmentainer_constraint_space,
             is_last_fragmentainer_so_far);

  // Since out-of-flow positioning sets up a constraint space with fixed
  // inline-size, the regular layout code (|BlockNode::Layout()|) cannot
  // re-layout if it discovers that a scrollbar was added or removed. Handle
  // that situation here. The assumption is that if intrinsic logical widths are
  // dirty after layout, AND its inline-size depends on the intrinsic logical
  // widths, it means that scrollbars appeared or disappeared.
  if (node_info.node.GetLayoutBox()->IntrinsicLogicalWidthsDirty() &&
      offset_info.inline_size_depends_on_min_max_sizes) {
    WritingDirectionMode writing_mode_direction =
        node_info.node.Style().GetWritingDirection();
    bool freeze_horizontal = false, freeze_vertical = false;
    BoxStrut scrollbars_after =
        ComputeScrollbarsForNonAnonymous(node_info.node);
    bool ignore_first_inline_freeze =
        scrollbars_after.InlineSum() && scrollbars_after.BlockSum();
    // If we're in a measure pass, freeze both scrollbars right away, to avoid
    // quadratic time complexity for deeply nested flexboxes.
    if (GetConstraintSpace().CacheSlot() == LayoutResultCacheSlot::kMeasure) {
      freeze_horizontal = freeze_vertical = true;
      ignore_first_inline_freeze = false;
    }
    do {
      // Freeze any scrollbars that appeared, and relayout. Repeat until both
      // have appeared, or until the scrollbar situation doesn't change,
      // whichever comes first.
      AddScrollbarFreeze(scrollbars_before, scrollbars_after,
                         writing_mode_direction, &freeze_horizontal,
                         &freeze_vertical);
      if (ignore_first_inline_freeze) {
        ignore_first_inline_freeze = false;
        // We allow to remove the inline-direction scrollbar only once
        // because the box might have unnecessary scrollbar due to
        // SetIsFixedInlineSize(true).
        if (writing_mode_direction.IsHorizontal())
          freeze_horizontal = false;
        else
          freeze_vertical = false;
      }
      scrollbars_before = scrollbars_after;
      PaintLayerScrollableArea::FreezeScrollbarsRootScope freezer(
          *node_info.node.GetLayoutBox(), freeze_horizontal, freeze_vertical);

      if (!IsBreakInside(oof_node_to_layout.break_token)) {
        // The offset itself does not need to be recalculated. However, the
        // |node_dimensions| and |initial_layout_result| may need to be updated,
        // so recompute the OffsetInfo.
        //
        // Only do this if we're currently building the first fragment of the
        // OOF. If we're resuming after a fragmentainer break, we can't update
        // our intrinsic inline-size. First of all, the intrinsic inline-size
        // should be the same across all fragments [1], and besides, this
        // operation would lead to performing a non-fragmented layout pass (to
        // measure intrinsic block-size; see IntrinsicBlockSizeFunc in
        // ComputeOutOfFlowBlockDimensions()), which in turn would overwrite the
        // result of the first fragment entry in LayoutBox without a break
        // token, causing major confusion everywhere.
        //
        // [1] https://drafts.csswg.org/css-break/#varying-size-boxes
        offset_info = CalculateOffset(node_info);
      }

      layout_result = Layout(oof_node_to_layout, fragmentainer_constraint_space,
                             is_last_fragmentainer_so_far);

      scrollbars_after = ComputeScrollbarsForNonAnonymous(node_info.node);
      DCHECK(!freeze_horizontal || !freeze_vertical ||
             scrollbars_after == scrollbars_before);
    } while (scrollbars_after != scrollbars_before);
  }

  auto& state = oof_node_to_layout.node_info.node.GetLayoutBox()
                    ->GetDocument()
                    .GetDisplayLockDocumentState();

  if (state.DisplayLockCount() >
      state.DisplayLockBlockingAllActivationCount()) {
    if (auto* box = oof_node_to_layout.node_info.node.GetLayoutBox()) {
      box->NotifyContainingDisplayLocksForAnchorPositioning(
          past_display_lock_elements,
          offset_info.display_locks_affected_by_anchors);
    }
  }

  return layout_result;
}

namespace {

// The spec says:
//
// "
// Implementations may choose to impose an implementation-defined limit on the
// length of position fallbacks lists, to limit the amount of excess layout work
// that may be required. This limit must be at least five.
// "
//
// We use 6 here because the first attempt is without anything from the
// position fallbacks list applied.
constexpr unsigned kMaxTryAttempts = 6;

// When considering multiple candidate styles (i.e. position-try-fallbacks),
// we keep track of each successful placement as a NonOverflowingCandidate.
// These candidates are then sorted according to the specified
// position-try-order.
//
// https://drafts.csswg.org/css-anchor-position-1/#position-try-order-property
struct NonOverflowingCandidate {
  DISALLOW_NEW();

 public:
  // The index into the position-try-fallbacks list that generated this
  // NonOverflowingCandidate. A value of nullopt means the regular styles
  // (without any position-try-fallback applied) generated the object.
  std::optional<wtf_size_t> try_fallback_index;
  // The result of TryCalculateOffset.
  OutOfFlowLayoutPart::OffsetInfo offset_info;

  void Trace(Visitor* visitor) const { visitor->Trace(offset_info); }
};

EPositionTryOrder ToLogicalPositionTryOrder(
    EPositionTryOrder position_try_order,
    WritingDirectionMode writing_direction) {
  switch (position_try_order) {
    case EPositionTryOrder::kNormal:
    case EPositionTryOrder::kMostBlockSize:
    case EPositionTryOrder::kMostInlineSize:
      return position_try_order;
    case EPositionTryOrder::kMostWidth:
      return writing_direction.IsHorizontal()
                 ? EPositionTryOrder::kMostInlineSize
                 : EPositionTryOrder::kMostBlockSize;
    case EPositionTryOrder::kMostHeight:
      return writing_direction.IsHorizontal()
                 ? EPositionTryOrder::kMostBlockSize
                 : EPositionTryOrder::kMostInlineSize;
  }
}

// Sorts `candidates` according to `position_try_order`, such that the correct
// candidate is at candidates.front().
void SortNonOverflowingCandidates(
    EPositionTryOrder position_try_order,
    WritingDirectionMode writing_direction,
    HeapVector<NonOverflowingCandidate, kMaxTryAttempts>& candidates) {
  EPositionTryOrder logical_position_try_order =
      ToLogicalPositionTryOrder(position_try_order, writing_direction);

  if (logical_position_try_order == EPositionTryOrder::kNormal) {
    // §5.2, normal: "Try the position fallbacks in the order specified by
    // position-try-fallbacks".
    return;
  }

  // §5.2, most-block-size (etc): "Stably sort the position fallbacks list
  // according to this size, with the largest coming first".
  std::stable_sort(
      candidates.begin(), candidates.end(),
      [logical_position_try_order](const NonOverflowingCandidate& a,
                                   const NonOverflowingCandidate& b) {
        switch (logical_position_try_order) {
          case EPositionTryOrder::kMostBlockSize:
            return a.offset_info.imcb_for_position_order->BlockSize() >
                   b.offset_info.imcb_for_position_order->BlockSize();
          case EPositionTryOrder::kMostInlineSize:
            return a.offset_info.imcb_for_position_order->InlineSize() >
                   b.offset_info.imcb_for_position_order->InlineSize();
          case EPositionTryOrder::kNormal:
            // Should have exited early.
          case EPositionTryOrder::kMostWidth:
          case EPositionTryOrder::kMostHeight:
            // We should have already converted to logical.
            NOTREACHED();
        }
      });
}

}  // namespace

OutOfFlowLayoutPart::OffsetInfo OutOfFlowLayoutPart::CalculateOffset(
    const NodeInfo& node_info,
    const LogicalAnchorQueryMap* anchor_queries) {
  // See non_overflowing_scroll_range.h for documentation.
  HeapVector<NonOverflowingScrollRange> non_overflowing_scroll_ranges;

  // Note: This assumes @position-try rounds can't affect
  // writing-mode/position-anchor.
  AnchorEvaluatorImpl anchor_evaluator = CreateAnchorEvaluator(
      node_info.base_container_info, node_info.node, anchor_queries);

  OOFCandidateStyleIterator iter(*node_info.node.GetLayoutBox(),
                                 anchor_evaluator);
  bool has_try_fallbacks = iter.HasPositionTryFallbacks();
  EPositionTryOrder position_try_order = iter.PositionTryOrder();

  unsigned attempts_left = kMaxTryAttempts;
  bool has_no_overflow_visibility =
      node_info.node.Style().HasPositionVisibility(
          PositionVisibility::kNoOverflow);
  // If `position-try-fallbacks` or `position-visibility: no-overflow` exists,
  // let |TryCalculateOffset| check if the result fits the available space.
  bool try_fit_available_space =
      has_try_fallbacks || has_no_overflow_visibility;
  // Non-overflowing candidates (i.e. successfully placed candidates) are
  // collected into a vector. If position-try-order is non-normal, then we
  // collect *all* such candidates into the vector, and sort them according
  // to position-try-order.
  HeapVector<NonOverflowingCandidate, kMaxTryAttempts>
      non_overflowing_candidates;
  do {
    NonOverflowingScrollRange non_overflowing_range;
    // Do @position-try placement decisions on the *base style* to avoid
    // interference from animations and transitions.
    const ComputedStyle& style = iter.ActivateBaseStyleForTryAttempt();
    // However, without @position-try, the style is the current style.
    CHECK(has_try_fallbacks || &style == &iter.GetStyle());
    std::optional<OffsetInfo> offset_info =
        TryCalculateOffset(node_info, style, anchor_evaluator,
                           try_fit_available_space, &non_overflowing_range);

    // Also check if it fits the containing block after applying scroll offset
    // (i.e. the scroll-adjusted inset-modified containing block).
    if (offset_info) {
      if (try_fit_available_space) {
        non_overflowing_scroll_ranges.push_back(non_overflowing_range);
        if (!non_overflowing_range.Contains(GetAnchorOffset(
                node_info.node, style, anchor_evaluator.AnchorQuery()))) {
          continue;
        }
      }
      non_overflowing_candidates.push_back(
          NonOverflowingCandidate{iter.TryFallbackIndex(), *offset_info});
    }
  } while ((non_overflowing_candidates.empty() ||
            position_try_order != EPositionTryOrder::kNormal) &&
           --attempts_left != 0 && has_try_fallbacks && iter.MoveToNextStyle());

  // https://drafts.csswg.org/css-anchor-position-1/#position-try-order-property
  SortNonOverflowingCandidates(position_try_order,
                               node_info.base_container_info.writing_direction,
                               non_overflowing_candidates);

  std::optional<OffsetInfo> offset_info =
      non_overflowing_candidates.empty()
          ? std::optional<OffsetInfo>()
          : non_overflowing_candidates.front().offset_info;

  if (try_fit_available_space) {
    bool overflows_containing_block = false;
    if (non_overflowing_candidates.empty()) {
      // None of the fallbacks worked out.
      // Fall back to style without any fallbacks applied.
      iter.MoveToLastSuccessfulOrStyleWithoutFallbacks();
      overflows_containing_block = true;
    } else {
      // Move the iterator to the chosen candidate.
      iter.MoveToChosenTryFallbackIndex(
          non_overflowing_candidates.front().try_fallback_index);
    }
    // Once the position-try-fallbacks placement has been decided, calculate the
    // offset again, using the non-base style.
    const ComputedStyle& style = iter.ActivateStyleForChosenFallback();
    NonOverflowingScrollRange non_overflowing_range_unused;
    offset_info = TryCalculateOffset(node_info, style, anchor_evaluator,
                                     /* try_fit_available_space */ false,
                                     &non_overflowing_range_unused);
    offset_info->overflows_containing_block = overflows_containing_block;
  }
  CHECK(offset_info);

  if (try_fit_available_space) {
    offset_info->non_overflowing_scroll_ranges =
        std::move(non_overflowing_scroll_ranges);
  } else {
    DCHECK(offset_info->non_overflowing_scroll_ranges.empty());
  }

  offset_info->accessibility_anchor = anchor_evaluator.AccessibilityAnchor();
  offset_info->display_locks_affected_by_anchors =
      anchor_evaluator.GetDisplayLocksAffectedByAnchors();

  return *offset_info;
}

std::optional<OutOfFlowLayoutPart::OffsetInfo>
OutOfFlowLayoutPart::TryCalculateOffset(
    const NodeInfo& node_info,
    const ComputedStyle& candidate_style,
    AnchorEvaluatorImpl& anchor_evaluator,
    bool try_fit_available_space,
    NonOverflowingScrollRange* out_non_overflowing_range) {
  // TryCalculateOffset may be called multiple times if we have multiple @try
  // candidates. However, the AnchorEvaluatorImpl instance remains the same
  // across TryCalculateOffset calls, and was created with the "original"
  // writing-mode/position-anchor values.
  //
  // Those properties are not allowed within @try, so it should not be possible
  // to end up with a candidate style with different values.
  DCHECK_EQ(node_info.node.Style().GetWritingDirection(),
            candidate_style.GetWritingDirection());
  DCHECK(base::ValuesEquivalent(node_info.node.Style().PositionAnchor(),
                                candidate_style.PositionAnchor()));

  const ContainingBlockInfo container_info = ([&]() -> ContainingBlockInfo {
    ContainingBlockInfo container_info = node_info.base_container_info;
    if (const std::optional<PositionAreaOffsets> offsets =
            candidate_style.PositionAreaOffsets()) {
      container_info =
          ApplyPositionAreaOffsets(offsets.value(), container_info);
    }
    return container_info;
  })();

  const WritingDirectionMode candidate_writing_direction =
      candidate_style.GetWritingDirection();
  const auto container_writing_direction = container_info.writing_direction;

  const LogicalRect& container_rect = container_info.rect;
  const PhysicalSize container_physical_content_size =
      ToPhysicalSize(container_rect.size,
                     node_info.default_writing_direction.GetWritingMode());

  // The container insets. Don't use the position-area offsets directly as they
  // may be clamped to produce non-negative space. Instead take the difference
  // between the base, and adjusted container-info.
  const BoxStrut container_insets = ([&]() -> BoxStrut {
    const LogicalRect& base_rect = node_info.base_container_info.rect;
    const BoxStrut insets(
        container_rect.offset.inline_offset - base_rect.offset.inline_offset,
        base_rect.InlineEndOffset() - container_rect.InlineEndOffset(),
        container_rect.offset.block_offset - base_rect.offset.block_offset,
        base_rect.BlockEndOffset() - container_rect.BlockEndOffset());

    // Convert into the candidate writing-direction.
    return insets.ConvertToPhysical(node_info.default_writing_direction)
        .ConvertToLogical(candidate_writing_direction);
  })();

  // Create a constraint space to resolve border/padding/insets.
  const ConstraintSpace space = ([&]() -> ConstraintSpace {
    ConstraintSpaceBuilder builder(GetConstraintSpace(),
                                   candidate_writing_direction,
                                   /* is_new_fc */ true);
    builder.SetAvailableSize(container_rect.size);
    builder.SetPercentageResolutionSize(container_rect.size);
    if (node_info.is_hidden_for_paint) {
      builder.SetIsHiddenForPaint(true);
    }

    if (container_builder_->IsInitialColumnBalancingPass()) {
      // The |fragmentainer_offset_delta| will not make a difference in the
      // initial column balancing pass.
      SetupSpaceBuilderForFragmentation(
          GetConstraintSpace(), node_info.node,
          /*fragmentainer_offset_delta=*/LayoutUnit(),
          GetConstraintSpace().FragmentainerBlockSize(),
          /*is_resuming_past_block_end_edge=*/false, &builder);
    }
    return builder.ToConstraintSpace();
  })();

  const LogicalAlignment alignment = ComputeAlignment(
      candidate_style, container_info.is_scroll_container,
      container_writing_direction, candidate_writing_direction);

  const LogicalOofInsets insets =
      ComputeOutOfFlowInsets(candidate_style, space.AvailableSize(), alignment,
                             candidate_writing_direction);

  // Adjust the |static_position| (which is currently relative to the default
  // container's border-box) to be relative to the padding-box.
  // Since |container_rect.offset| is relative to its fragmentainer in this
  // case, we also need to adjust the offset to account for this.
  LogicalStaticPosition static_position = node_info.static_position;
  static_position.offset +=
      node_info.containing_block.Offset() - container_rect.offset;

  // Convert to the candidate's writing-direction.
  s
"""


```