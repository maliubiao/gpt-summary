Response:
Let's break down the thought process for analyzing the `fragment_items_builder.cc` file.

1. **Understand the Goal:** The primary goal is to explain the functionality of this C++ file within the Chromium Blink rendering engine, focusing on its relationship with HTML, CSS, and JavaScript, along with identifying potential usage errors and illustrating logical reasoning.

2. **Initial Scan and Keywords:** Quickly read through the code, paying attention to:
    * **File Path:** `blink/renderer/core/layout/inline/fragment_items_builder.cc` suggests this is related to laying out inline content.
    * **Includes:** `#include` directives reveal dependencies: `box_fragment_builder.h`, `writing_mode_converter.h`, `fragment_items.h`, `inline_cursor.h`, `physical_box_fragment.h`, `svg_text_layout_algorithm.h`. These hint at building fragments (pieces of rendered output), handling text direction, iterating through inline content, and dealing with SVG text.
    * **Namespace:** `blink` indicates it's part of the Blink rendering engine.
    * **Class Name:** `FragmentItemsBuilder` clearly suggests its purpose is to *build* something called `FragmentItems`.
    * **Key Data Structures:**  `items_` (likely a vector), `line_container_map_`, `current_line_container_`, `LogicalLineContainer`, `LogicalLineItems`. These point to managing the structure of rendered inline content, potentially line by line.
    * **Key Methods:** `AddLine`, `AddItems`, `AddListMarker`, `AddPreviousItems`, `ConvertToPhysical`, `MoveChildrenInBlockDirection`, `ToFragmentItems`. These are the core actions the builder performs.

3. **Deconstruct the Class Functionality:** Go through the `FragmentItemsBuilder` class method by method:

    * **Constructors:**  Note the different constructors and what information they take (e.g., `InlineNode`, writing direction, whether it's block-fragmented). This sets the initial state.
    * **Destructor:**  Pay attention to cleanup (`ReleaseCurrentLogicalLineContainer`, `Clear`). This often indicates resource management.
    * **`ReleaseCurrentLogicalLineContainer` and Related Methods:**  These methods (`MoveCurrentLogicalLineItemsToMap`, `AcquireLogicalLineContainer`, `GetLogicalLineItems`, `AssociateLogicalLineContainer`) suggest a mechanism for managing and caching line-level information. The use of a `line_container_pool_` hints at optimization through object reuse.
    * **`AddLine`:** This is a crucial method. It takes a `PhysicalLineBoxFragment` and offset, and seems to build the items for a single line. Notice the handling of annotations and descendant items.
    * **`AddItems`:** This method appears to recursively add items, handling nested inline elements and managing descendant counts. The flattening of inline box children is a key detail.
    * **`AddListMarker`:** This specifically handles the addition of list markers.
    * **`AddPreviousItems`:** This is interesting. It's about reusing already built `FragmentItems`, potentially for optimization or incremental rendering. The checks for `::first-line` pseudo-element styles are important.
    * **`ConvertToPhysical`:** This method is critical for understanding the logical-to-physical coordinate transformation. The use of `WritingModeConverter` is key here. The separate handling of line children's offsets is a subtle but important detail.
    * **`MoveChildrenInBlockDirection`:**  This method adjusts the position of items in the block direction.
    * **`ToFragmentItems`:** This seems to finalize the building process, potentially performing additional layout steps for SVG text, and then creating the final `FragmentItems` object.

4. **Identify Relationships with Web Technologies:**

    * **HTML:** The builder processes elements represented by `InlineNode` and creates fragments. Examples like `<span>`, `<a>`, `<img>` within a text flow are relevant. List markers directly relate to HTML lists (`<ul>`, `<ol>`).
    * **CSS:** Writing modes (`writing-mode`, `direction`) are explicitly handled by the `WritingDirectionMode` and `WritingModeConverter`. Line breaking, implicit through the creation of `PhysicalLineBoxFragment` objects, is driven by CSS rules. The mention of `::first-line` is a direct CSS pseudo-element example. Properties affecting inline layout (like `line-height`) are indirectly involved.
    * **JavaScript:** While this C++ code doesn't directly *execute* JavaScript, the layout it performs is a consequence of the DOM (manipulated by JavaScript) and the CSSOM (also influenced by JavaScript). Changes to styles or the DOM structure will trigger this layout code to run.

5. **Infer Logical Reasoning and Provide Examples:**

    * **Line Building Logic:**  The `AddLine` method's logic of adding a line start item, then the content items, and finally setting the descendant count shows a clear pattern for structuring line information.
    * **Reusing Previous Items:** The logic in `AddPreviousItems` demonstrates an optimization strategy. Hypothesize scenarios where this would be beneficial (e.g., incremental rendering of a long text block).
    * **Coordinate Conversion:** The `ConvertToPhysical` method's use of `WritingModeConverter` showcases how logical and physical coordinates are mapped, depending on writing direction and orientation. Provide examples of how different writing modes affect the rendering.

6. **Consider Potential User/Programming Errors:**

    * **Incorrect Assumptions about Coordinate Systems:**  Explain how forgetting the logical-to-physical conversion can lead to positioning issues.
    * **Modifying Fragments After Building:** Highlight that the `FragmentItems` are a snapshot and modifying them directly later could lead to inconsistencies.
    * **Memory Management Issues (though less direct for the user):** Briefly mention the role of the `line_container_pool_` for optimization and the potential for memory leaks if not handled correctly (though this is more of an internal developer concern).

7. **Structure the Explanation:**  Organize the findings into clear sections: Functionality, Relationships, Logical Reasoning, Usage Errors. Use headings, bullet points, and code snippets (where appropriate) for readability.

8. **Review and Refine:**  Read through the explanation to ensure accuracy, clarity, and completeness. Check for any jargon that needs further explanation. Make sure the examples are illustrative and easy to understand. Ensure the connection to the original code is evident.这个文件 `fragment_items_builder.cc` 的主要功能是 **构建用于表示渲染片段（fragments）的结构，尤其是在处理内联布局时。** 它负责收集和组织内联元素（如文本、inline-block 元素等）的布局信息，以便后续的渲染流程可以使用这些信息来绘制页面。

更具体地说，`FragmentItemsBuilder` 做了以下事情：

**1. 管理和存储布局项 (Fragment Items):**

* 它维护一个 `items_` 向量，用于存储 `FragmentItemWithOffset` 对象。每个 `FragmentItemWithOffset` 包含一个 `FragmentItem` 和它在容器内的逻辑偏移量。
* `FragmentItem` 是一个轻量级的结构，描述了一个内联布局的基本单元，例如一行文本、一个内联盒子或者一个列表标记。
* 它负责在布局过程中创建、添加和管理这些 `FragmentItem`。

**2. 处理逻辑坐标到物理坐标的转换:**

* 在布局的早期阶段，它使用逻辑坐标（与书写模式无关）。
* 当容器的大小确定后，它会将逻辑坐标转换为物理坐标，以便用于实际的渲染。
* `ConvertToPhysical` 方法执行此转换，考虑到书写模式（水平或垂直）和文本方向。

**3. 管理逻辑行的信息:**

* 它使用 `LogicalLineContainer` 来存储每一行的布局信息，例如行中的 `LogicalLineItem`。
* `LogicalLineItem` 描述了行内的基本布局单元，类似于 `FragmentItem`，但在逻辑层面。
* 它使用 `line_container_map_` 来缓存已经处理过的行的 `LogicalLineContainer`，避免重复计算。
* `AddLine` 方法负责处理一行的布局项，将逻辑行的信息转换为物理行的 `FragmentItem`。

**4. 支持从之前的布局结果中重用信息:**

* `AddPreviousItems` 方法允许从之前的 `FragmentItems` 对象中复制信息，用于优化布局过程，例如在内容变化不大的情况下。

**5. 处理列表标记:**

* `AddListMarker` 方法专门用于添加列表标记的 `FragmentItem`。

**6. 处理 SVG 文本布局:**

* 对于 SVG 文本元素，它会调用 `SvgTextLayoutAlgorithm` 来进行特定的布局计算。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`FragmentItemsBuilder` 位于渲染引擎的核心，直接参与将 HTML、CSS 描述的内容转化为屏幕上的像素。

* **HTML:**
    * `FragmentItemsBuilder` 处理的是 HTML 元素在内联布局上下文中的表示。例如，当浏览器渲染如下 HTML 时：
      ```html
      <p>This is <span>some</span> text.</p>
      ```
    * `FragmentItemsBuilder` 会为 `<p>` 元素创建包含多个 `FragmentItem` 的结构，分别对应 "This is " 文本节点、 `<span>` 元素（作为一个 inline box）以及 " text." 文本节点。

* **CSS:**
    * CSS 样式直接影响 `FragmentItemsBuilder` 的行为和输出。例如：
        * **`display: inline` 或 `display: inline-block`:** 这些属性会让元素参与内联布局，从而被 `FragmentItemsBuilder` 处理。
        * **`writing-mode` 和 `direction`:**  这些属性决定了文本的书写方向和排列方式，`FragmentItemsBuilder` 使用 `WritingModeConverter` 来处理不同书写模式下的坐标转换。
        * **`line-height`:**  影响行框的高度，`FragmentItemsBuilder` 在 `AddLine` 中会涉及到行高的处理。
        * **字体大小、颜色等:** 这些样式虽然不直接影响 `FragmentItemsBuilder` 的逻辑，但会影响 `FragmentItem` 中尺寸和位置的计算。
    * **例子:**
      ```html
      <span style="color: red; font-size: 16px;">Important</span>
      ```
      `FragmentItemsBuilder` 会为 `<span>` 创建一个 `FragmentItem`，其尺寸和位置会受到 `font-size` 的影响，而颜色信息会在后续的渲染阶段使用。

* **JavaScript:**
    * JavaScript 可以通过 DOM API 修改 HTML 结构和 CSS 样式。当这些修改发生时，会导致布局树的更新，并最终触发 `FragmentItemsBuilder` 重新构建片段信息。
    * **例子:**
      ```javascript
      const span = document.querySelector('span');
      span.style.fontWeight = 'bold';
      ```
      这段 JavaScript 代码会修改 `<span>` 元素的 `font-weight` 属性，这可能导致文本的宽度发生变化，从而触发布局引擎重新运行，`FragmentItemsBuilder` 会生成新的 `FragmentItem` 来反映这个变化。

**逻辑推理的假设输入与输出:**

**假设输入:** 考虑以下简单的 HTML 和 CSS：

```html
<p style="width: 200px;">One two three</p>
```

**内部处理 (Simplified):**

1. **`FragmentItemsBuilder` 初始化:** 接收 `<p>` 元素的 `InlineNode` 信息，宽度约束为 200px。
2. **文本分行:** 布局引擎会根据宽度和空格将文本 "One two three" 分成一行或多行。假设一行能放下。
3. **`AddLine` 调用:**  `FragmentItemsBuilder` 的 `AddLine` 方法会被调用，接收到表示该行的 `PhysicalLineBoxFragment`。
4. **`AddItems` 调用:**  `AddItems` 会被调用来处理行内的文本节点。
5. **`FragmentItem` 创建:**  会为 "One two three" 创建一个 `FragmentItem`，记录其逻辑偏移量和尺寸。
6. **`ConvertToPhysical` 调用:** 当容器的最终尺寸确定后（可能仍然是 200px），`ConvertToPhysical` 会将逻辑偏移量转换为物理偏移量。

**可能的输出 (简化表示):**

`items_` 向量可能包含一个 `FragmentItemWithOffset`，其内容类似于：

```
{
  offset: { inline_offset: 0, block_offset: 0 }, // 假设从容器左上角开始
  item: {
    type: kText,
    text_range: { start: 0, length: 13 }, // 文本 "One two three" 的范围
    size: { inline_size: calculated_width, block_size: calculated_height }, // 根据字体计算的宽度和行高
    // ... 其他属性
  }
}
```

如果宽度不足以容纳所有文本，可能会分成两行，`items_` 中会包含两个代表行的 `FragmentItem`，每个行又包含文本的 `FragmentItem`。

**用户或编程常见的使用错误:**

由于 `FragmentItemsBuilder` 是 Blink 内部的组件，用户或前端开发者不会直接与其交互。但理解其背后的原理可以帮助避免一些与布局相关的常见误解：

1. **错误地假设内联元素的尺寸:** 开发者可能会认为可以通过直接设置内联元素的宽度和高度来精确控制其尺寸。但实际上，内联元素的尺寸是由其内容和周围的上下文（如行框）决定的。`FragmentItemsBuilder` 的工作正是体现了这一点。

2. **忽略书写模式的影响:** 当处理国际化内容或者使用了非标准的书写模式时，开发者可能会忘记考虑 `writing-mode` 和 `direction` 属性对布局的影响。了解 `FragmentItemsBuilder` 如何使用 `WritingModeConverter` 可以帮助理解这些属性的重要性。

3. **过度依赖 JavaScript 来调整内联布局:** 虽然 JavaScript 可以修改样式和结构，但频繁地进行细粒度的布局调整可能会导致性能问题。理解浏览器的布局流程，包括 `FragmentItemsBuilder` 的作用，可以帮助开发者更有效地利用 CSS 来实现布局。

4. **混淆逻辑坐标和物理坐标:**  在某些高级的渲染或动画场景中，开发者可能需要直接操作元素的坐标。理解逻辑坐标和物理坐标的区别，以及 `FragmentItemsBuilder` 的转换过程，可以避免因坐标系混淆而导致的问题。

总而言之，`fragment_items_builder.cc` 是 Blink 渲染引擎中负责构建内联布局片段信息的关键组件，它将 HTML 结构和 CSS 样式转化为可用于渲染的中间表示。虽然前端开发者不会直接操作它，但了解其功能有助于更深入地理解浏览器的布局机制。

Prompt: 
```
这是目录为blink/renderer/core/layout/inline/fragment_items_builder.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/core/layout/inline/fragment_items_builder.h"

#include "base/not_fatal_until.h"
#include "third_party/blink/renderer/core/layout/box_fragment_builder.h"
#include "third_party/blink/renderer/core/layout/geometry/writing_mode_converter.h"
#include "third_party/blink/renderer/core/layout/inline/fragment_items.h"
#include "third_party/blink/renderer/core/layout/inline/inline_cursor.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"
#include "third_party/blink/renderer/core/layout/svg/svg_text_layout_algorithm.h"

namespace blink {

FragmentItemsBuilder::FragmentItemsBuilder(
    WritingDirectionMode writing_direction)
    : node_(nullptr), writing_direction_(writing_direction) {}

FragmentItemsBuilder::FragmentItemsBuilder(
    const InlineNode& node,
    WritingDirectionMode writing_direction,
    bool is_block_fragmented)
    : node_(node), writing_direction_(writing_direction) {
  const InlineItemsData& items_data = node.ItemsData(false);
  text_content_ = items_data.text_content;
  const InlineItemsData& first_line = node.ItemsData(true);
  if (&items_data != &first_line)
    first_line_text_content_ = first_line.text_content;

  // For a very large inline formatting context, the vector reallocation becomes
  // hot. Estimate the number of items by assuming 40 characters can fit in a
  // line, and each line contains 3 items; a line box, an inline box, and a
  // text. If it will require more than one reallocations, make an initial
  // reservation here.
  //
  // Skip this if we constrained by a fragmentainer's block-size. The estimate
  // will be way too high in such cases, and we're going to make this
  // reservation for every fragmentainer, potentially running out of memory if
  // oilpan doesn't get around to collecting it.
  if (!is_block_fragmented) {
    const wtf_size_t estimated_item_count = text_content_.length() / 40 * 3;
    if (estimated_item_count > items_.capacity() * 2) [[unlikely]] {
      items_.ReserveInitialCapacity(estimated_item_count);
    }
  }
}

FragmentItemsBuilder::~FragmentItemsBuilder() {
  ReleaseCurrentLogicalLineContainer();

  // Delete leftovers that were associated, but were not added. Clear() is
  // explicitly called here for memory performance.
  DCHECK(line_container_pool_);
  line_container_pool_->Clear();
  for (const auto& i : line_container_map_) {
    if (i.value != line_container_pool_) {
      i.value->Clear();
    }
  }
}

void FragmentItemsBuilder::ReleaseCurrentLogicalLineContainer() {
  if (!current_line_container_) {
    return;
  }
  if (current_line_container_ == line_container_pool_) {
    DCHECK(is_line_items_pool_acquired_);
    is_line_items_pool_acquired_ = false;
  } else {
    current_line_container_->Clear();
  }
  current_line_container_ = nullptr;
}

void FragmentItemsBuilder::MoveCurrentLogicalLineItemsToMap() {
  if (!current_line_container_) {
    DCHECK(!current_line_fragment_);
    return;
  }
  DCHECK(current_line_fragment_);
  line_container_map_.insert(current_line_fragment_, current_line_container_);
  current_line_fragment_ = nullptr;
  current_line_container_ = nullptr;
}

LogicalLineContainer* FragmentItemsBuilder::AcquireLogicalLineContainer() {
  if (line_container_pool_ && !is_line_items_pool_acquired_) {
    is_line_items_pool_acquired_ = true;
    return line_container_pool_;
  }
  MoveCurrentLogicalLineItemsToMap();
  DCHECK(!current_line_container_);
  current_line_container_ = MakeGarbageCollected<LogicalLineContainer>();
  return current_line_container_;
}

const LogicalLineItems& FragmentItemsBuilder::GetLogicalLineItems(
    const PhysicalLineBoxFragment& line_fragment) const {
  if (&line_fragment == current_line_fragment_) {
    DCHECK(current_line_container_);
    return current_line_container_->BaseLine();
  }
  const LogicalLineContainer* container =
      line_container_map_.at(&line_fragment);
  DCHECK(container);
  return container->BaseLine();
}

void FragmentItemsBuilder::AssociateLogicalLineContainer(
    LogicalLineContainer* line_container,
    const PhysicalFragment& line_fragment) {
  DCHECK(!current_line_container_ || current_line_container_ == line_container);
  current_line_container_ = line_container;
  DCHECK(!current_line_fragment_);
  current_line_fragment_ = &line_fragment;
}

void FragmentItemsBuilder::AddLine(const PhysicalLineBoxFragment& line_fragment,
                                   const LogicalOffset& offset) {
  DCHECK(!is_converted_to_physical_);
  if (&line_fragment == current_line_fragment_) {
    DCHECK(current_line_container_);
    current_line_fragment_ = nullptr;
  } else {
    MoveCurrentLogicalLineItemsToMap();
    DCHECK(!current_line_container_);
    current_line_container_ = line_container_map_.Take(&line_fragment);
    DCHECK(current_line_container_);
  }
  LogicalLineContainer* line_container = current_line_container_;
  LogicalLineItems& line_items = line_container->BaseLine();

  // Reserve the capacity for (children + line box item).
  const wtf_size_t size_before = items_.size();
  const wtf_size_t estimated_size =
      size_before + line_container->EstimatedFragmentItemCount();
  const wtf_size_t old_capacity = items_.capacity();
  if (estimated_size > old_capacity)
    items_.reserve(std::max(estimated_size, old_capacity * 2));

  // Add an empty item so that the start of the line can be set later.
  const wtf_size_t line_start_index = items_.size();
  items_.emplace_back(offset, line_fragment);

  AddItems(base::span(line_items));

  for (auto& annotation_line : line_container->AnnotationLineList()) {
    const wtf_size_t annotation_line_start_index = items_.size();
    const LayoutUnit line_height = annotation_line.metrics.LineHeight();
    if (!annotation_line->FirstInFlowChild()) {
      continue;
    }

    // If the line is hidden (e.g. because of line-clamp), annotations on that
    // line should be hidden as well.
    if (line_fragment.IsHiddenForPaint()) {
      for (auto& item : *annotation_line.line_items) {
        item.is_hidden_for_paint = true;
      }
    }

    LogicalOffset line_offset = annotation_line->FirstInFlowChild()->Offset();
    LayoutUnit line_inline_size =
        annotation_line->LastInFlowChild()->rect.InlineEndOffset() -
        line_offset.inline_offset;
    PhysicalSize size = IsHorizontalWritingMode(GetWritingMode())
                            ? PhysicalSize(line_inline_size, line_height)
                            : PhysicalSize(line_height, line_inline_size);
    // The offset must be relative to the base line box for now.
    items_.emplace_back(line_offset, size, line_fragment);
    AddItems(base::span(*annotation_line.line_items));
    items_[annotation_line_start_index].item.SetDescendantsCount(
        items_.size() - annotation_line_start_index);
  }

  // All children are added. Create an item for the start of the line.
  FragmentItem& line_item = items_[line_start_index].item;
  const wtf_size_t item_count = items_.size() - line_start_index;
  DCHECK_EQ(line_item.DescendantsCount(), 1u);
  line_item.SetDescendantsCount(item_count);

  // Keep children's offsets relative to |line|. They will be adjusted later in
  // |ConvertToPhysical()|.

  ReleaseCurrentLogicalLineContainer();

  DCHECK_LE(items_.size(), estimated_size);
}

void FragmentItemsBuilder::AddItems(base::span<LogicalLineItem> child_span) {
  DCHECK(!is_converted_to_physical_);

  const WritingMode writing_mode = GetWritingMode();
  for (size_t i = 0; i < child_span.size();) {
    LogicalLineItem& child = child_span[i];
    // OOF children should have been added to their parent box fragments.
    DCHECK(!child.out_of_flow_positioned_box);
    if (!child.CanCreateFragmentItem()) {
      ++i;
      continue;
    }

    if (child.children_count <= 1) {
      items_.emplace_back(child.rect.offset, std::move(child), writing_mode);
      ++i;
      continue;
    }

    const unsigned children_count = child.children_count;
    // Children of inline boxes are flattened and added to |items_|, with the
    // count of descendant items to preserve the tree structure.
    //
    // Add an empty item so that the start of the box can be set later.
    const wtf_size_t box_start_index = items_.size();
    items_.emplace_back(child.rect.offset, std::move(child), writing_mode);

    // Add all children, including their desendants, skipping this item.
    CHECK_GE(children_count, 1u);  // 0 will loop infinitely.
    AddItems(child_span.subspan(i + 1, children_count - 1));
    i += children_count;

    // All children are added. Compute how many items are actually added. The
    // number of items added may be different from |children_count|.
    const wtf_size_t item_count = items_.size() - box_start_index;
    FragmentItem& box_item = items_[box_start_index].item;
    DCHECK_EQ(box_item.DescendantsCount(), 1u);
    box_item.SetDescendantsCount(item_count);
  }
}

void FragmentItemsBuilder::AddListMarker(
    const PhysicalBoxFragment& marker_fragment,
    const LogicalOffset& offset) {
  DCHECK(!is_converted_to_physical_);

  // Resolved direction matters only for inline items, and outside list markers
  // are not inline.
  const TextDirection resolved_direction = TextDirection::kLtr;
  items_.emplace_back(offset, marker_fragment, resolved_direction);
}

FragmentItemsBuilder::AddPreviousItemsResult
FragmentItemsBuilder::AddPreviousItems(const PhysicalBoxFragment& container,
                                       const FragmentItems& items,
                                       BoxFragmentBuilder* container_builder,
                                       const FragmentItem* end_item,
                                       wtf_size_t max_lines) {
  if (end_item) {
    DCHECK(node_);
    DCHECK(container_builder);
    DCHECK(text_content_);

    if (items.FirstLineText() && !first_line_text_content_) [[unlikely]] {
      // Don't reuse previous items if they have different `::first-line` style
      // but |this| doesn't. Reaching here means that computed style doesn't
      // change, but |FragmentItem| has wrong |StyleVariant|.
      return AddPreviousItemsResult();
    }
  } else {
    DCHECK(!container_builder);
    DCHECK(!text_content_);
    text_content_ = items.NormalText();
    first_line_text_content_ = items.FirstLineText();
  }

  DCHECK(items_.empty());
  const FragmentItems::Span source_items = items.Items();
  const wtf_size_t estimated_size =
      base::checked_cast<wtf_size_t>(source_items.size());
  items_.reserve(estimated_size);

  // Convert offsets to logical. The logic is opposite to |ConvertToPhysical|.
  // This is needed because the container size may be different, in that case,
  // the physical offsets are different when `writing-mode: vertial-rl`.
  DCHECK(!is_converted_to_physical_);
  const WritingModeConverter converter(GetWritingDirection(), container.Size());
  const WritingMode writing_mode = GetWritingMode();
  WritingModeConverter line_converter(
      {ToLineWritingMode(writing_mode), TextDirection::kLtr});

  const InlineBreakToken* last_break_token = nullptr;
  const InlineItemsData* items_data = nullptr;
  LayoutUnit used_block_size;
  wtf_size_t line_count = 0;

  for (InlineCursor cursor(container, items); cursor;) {
    DCHECK(cursor.Current().Item());
    const FragmentItem& item = *cursor.Current().Item();
    if (&item == end_item)
      break;
    DCHECK(!item.IsDirty());

    const LogicalOffset item_offset =
        converter.ToLogical(item.OffsetInContainerFragment(), item.Size());

    if (item.Type() == FragmentItem::kLine) {
      DCHECK(item.LineBoxFragment());
      if (end_item) {
        // Check if this line has valid item_index and offset.
        const PhysicalLineBoxFragment* line_fragment = item.LineBoxFragment();
        // Block-in-inline should have been prevented by |EndOfReusableItems|.
        DCHECK(!line_fragment->IsBlockInInline());
        const auto* break_token =
            To<InlineBreakToken>(line_fragment->GetBreakToken());
        DCHECK(break_token);
        const InlineItemsData* current_items_data;
        if (break_token->UseFirstLineStyle()) [[unlikely]] {
          current_items_data = &node_.ItemsData(true);
        } else if (items_data) {
          current_items_data = items_data;
        } else {
          current_items_data = items_data = &node_.ItemsData(false);
        }
        if (!current_items_data->IsValidOffset(break_token->Start()))
            [[unlikely]] {
          DUMP_WILL_BE_NOTREACHED();
          break;
        }

        last_break_token = break_token;
        container_builder->AddChild(*line_fragment, item_offset);
        used_block_size +=
            item.Size().ConvertToLogical(writing_mode).block_size;
      }

      items_.emplace_back(item_offset, item);
      const PhysicalRect line_box_bounds = item.RectInContainerFragment();
      line_converter.SetOuterSize(line_box_bounds.size);
      for (InlineCursor line = cursor.CursorForDescendants(); line;
           line.MoveToNext()) {
        const FragmentItem& line_child = *line.Current().Item();
        if (line_child.Type() != FragmentItem::kLine) {
          if (end_item) {
            // If |end_item| is given, the caller has computed the range safe
            // to reuse by calling |EndOfReusableItems|. All children should
            // be safe to reuse.
            DCHECK(line_child.CanReuse());
          } else if (!line_child.CanReuse()) {
            // Abort and report the failure if any child is not reusable.
            return AddPreviousItemsResult();
          }
        }
#if DCHECK_IS_ON()
        // |RebuildFragmentTreeSpine| does not rebuild spine if |NeedsLayout|.
        // Such block needs to copy PostLayout fragment while running simplified
        // layout.
        std::optional<PhysicalBoxFragment::AllowPostLayoutScope>
            allow_post_layout;
        if (line_child.IsRelayoutBoundary())
          allow_post_layout.emplace();
#endif
        items_.emplace_back(
            line_converter.ToLogical(
                line_child.OffsetInContainerFragment() - line_box_bounds.offset,
                line_child.Size()),
            line_child);

        // Be sure to pick the post-layout fragment.
        const FragmentItem& new_item = items_.back().item;
        if (const PhysicalBoxFragment* box = new_item.BoxFragment()) {
          box = box->PostLayout();
          new_item.GetMutableForCloning().ReplaceBoxFragment(*box);
        }
      }
      if (++line_count == max_lines)
        break;
      cursor.MoveToNextSkippingChildren();
      continue;
    }

    DCHECK_NE(item.Type(), FragmentItem::kLine);
    DCHECK(!end_item);
    items_.emplace_back(item_offset, item);
    cursor.MoveToNext();
  }
  DCHECK_LE(items_.size(), estimated_size);

  if (end_item && last_break_token) {
    DCHECK_GT(line_count, 0u);
    DCHECK(!max_lines || line_count <= max_lines);
    return AddPreviousItemsResult{last_break_token, used_block_size, line_count,
                                  true};
  }
  return AddPreviousItemsResult();
}

const FragmentItemsBuilder::ItemWithOffsetList& FragmentItemsBuilder::Items(
    const PhysicalSize& outer_size) {
  ConvertToPhysical(outer_size);
  return items_;
}

// Convert internal logical offsets to physical. Items are kept with logical
// offset until outer box size is determined.
void FragmentItemsBuilder::ConvertToPhysical(const PhysicalSize& outer_size) {
  if (is_converted_to_physical_)
    return;

  const WritingModeConverter converter(GetWritingDirection(), outer_size);
  // Children of lines have line-relative offsets. Use line-writing mode to
  // convert their logical offsets. Use `kLtr` because inline items are after
  // bidi-reoder, and that their offset is visual, not logical.
  WritingModeConverter line_converter(
      {ToLineWritingMode(GetWritingMode()), TextDirection::kLtr});

  for (auto iter = items_.begin(); iter != items_.end(); ++iter) {
    FragmentItem* item = &iter->item;
    item->SetOffset(converter.ToPhysical(iter->offset, item->Size()));

    // Transform children of lines separately from children of the block,
    // because they may have different directions from the block. To do
    // this, their offsets are relative to their containing line box.
    if (item->Type() == FragmentItem::kLine) {
      unsigned descendants_count = item->DescendantsCount();
      DCHECK(descendants_count);
      if (descendants_count) {
        const PhysicalRect line_box_bounds = item->RectInContainerFragment();
        line_converter.SetOuterSize(line_box_bounds.size);
        while (--descendants_count) {
          ++iter;
          CHECK_NE(iter, items_.end(), base::NotFatalUntil::M130);
          item = &iter->item;
          item->SetOffset(
              line_converter.ToPhysical(iter->offset, item->Size()) +
              line_box_bounds.offset);
        }
      }
    }
  }

  is_converted_to_physical_ = true;
}

void FragmentItemsBuilder::MoveChildrenInBlockDirection(LayoutUnit delta) {
  DCHECK(!is_converted_to_physical_);
  for (auto iter = items_.begin(); iter != items_.end(); ++iter) {
    if (iter->item->Type() == FragmentItem::kLine) {
      iter->offset.block_offset += delta;
      std::advance(iter, iter->item->DescendantsCount() - 1);
      DCHECK_LE(iter, items_.end());
      continue;
    }
    iter->offset.block_offset += delta;
  }
}

std::optional<PhysicalSize> FragmentItemsBuilder::ToFragmentItems(
    const PhysicalSize& outer_size,
    void* data) {
  DCHECK(text_content_);
  ConvertToPhysical(outer_size);
  std::optional<PhysicalSize> new_size;
  if (node_.IsSvgText()) {
    new_size = SvgTextLayoutAlgorithm(node_, GetWritingMode())
                   .Layout(TextContent(false), items_);
  }
  new (data) FragmentItems(this);
  return new_size;
}

}  // namespace blink

"""

```