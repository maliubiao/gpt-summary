Response:
My thought process for analyzing the code and generating the response followed these steps:

1. **Understand the Goal:** The request asks for a summary of the functionality of `fragmentation_utils.cc`, including its relation to web technologies (JavaScript, HTML, CSS), examples, and identification of potential errors. It's the first part of a three-part request, so focusing on summarization is key.

2. **Initial Code Scan (Headers and Namespaces):** I first looked at the included headers and the namespace. This immediately gives a sense of the code's domain. The presence of `<...>blink/renderer/core/layout/...>`, `<...>blink/renderer/core/dom/...>`, `<...>blink/renderer/core/style/...>` clearly indicates this code is deeply involved in the layout process of the Blink rendering engine. The namespace `blink` and the anonymous namespace within confirm this is internal Blink code.

3. **Identify Key Data Structures and Concepts:** I then scanned the code for important types and function names. I noted:
    * `EBreakBetween`, `EBreakInside`: These enums suggest handling CSS break properties (`break-before`, `break-after`, `break-inside`).
    * `ConstraintSpace`, `ConstraintSpaceBuilder`: These likely manage the constraints during the layout process, especially related to fragmentation.
    * `BoxFragmentBuilder`, `PhysicalBoxFragment`, `LogicalBoxFragment`: These classes are clearly involved in building the visual fragments of elements.
    * `BlockBreakToken`: This suggests tracking break points between layout blocks.
    * `LayoutInputNode`, `LayoutResult`:  These are foundational types in the layout process, representing input and output of layout calculations.
    * Functions like `JoinFragmentainerBreakValues`, `IsForcedBreakValue`, `CalculateBreakAppealBefore`, `CalculateBreakAppealInside`, `FragmentainerLogicalCapacity`, `SetupSpaceBuilderForFragmentation`, `SetupFragmentBuilderForFragmentation`, `FinishFragmentation`. These names directly point to the core functionalities.

4. **Analyze Function by Function (High-Level):** I went through each function, trying to understand its purpose based on its name and the types it manipulates. For instance:
    * `FragmentainerBreakPrecedence`:  Clearly defines the priority of different break values.
    * `JoinFragmentainerBreakValues`: Combines break values, respecting precedence.
    * `IsForcedBreakValue`, `IsAvoidBreakValue`: Check if a break is forced or should be avoided based on context.
    * `CalculateBreakAppeal...`: Determines how "desirable" a break is at a particular point. This is crucial for making layout decisions.
    * `FragmentainerLogicalCapacity`: Calculates the available space within a fragmentainer.
    * `Setup...ForFragmentation`:  Configures the `ConstraintSpaceBuilder` and `BoxFragmentBuilder` for handling fragmentation.
    * `FinishFragmentation`:  Finalizes the fragmentation process for a block.

5. **Connect to Web Technologies:** With an understanding of the functions' purposes, I started linking them to CSS properties:
    * `EBreakBetween`, `EBreakInside`: Directly correspond to `break-before`, `break-after`, and `break-inside`.
    * `FragmentainerLogicalCapacity`: Relates to how elements with `overflow: auto`, `overflow: scroll` or multicolumn layouts are sized.
    * The entire file revolves around CSS Fragmentation Module Level 3, which includes properties like `break-before`, `break-after`, `break-inside`, `columns`, `column-span`, and page-related properties for print.

6. **Formulate Examples:** Based on the connection to CSS, I created simple HTML and CSS examples to illustrate the functions' effects. The focus was on demonstrating how the code would behave in practical scenarios involving breaking and avoiding breaks.

7. **Identify Potential Errors:** By considering how the code manipulates break values and makes layout decisions, I could identify common user errors:
    * Conflicting break properties.
    * Expecting breaks where they are not allowed due to container constraints.
    * Misunderstanding the precedence of break values.

8. **Infer Logic and Assumptions (Where Applicable):** For functions like `CalculateBreakAppeal...`, I made assumptions about the inputs and outputs to illustrate their logical flow. This involved imagining scenarios where different break values were applied and how the function would rank the break points.

9. **Structure the Response:**  I organized the information into logical sections: overall functionality, relationship to web technologies, examples, logical inferences, and potential errors. This makes the response clear and easy to understand.

10. **Focus on Summarization (Part 1 Constraint):** Since the request specified this was Part 1, I emphasized summarizing the functionality rather than diving into every implementation detail. The goal was to provide a good overview.

11. **Review and Refine:** I reviewed the generated response to ensure accuracy, clarity, and completeness, addressing all parts of the original request. I made sure the examples were simple and directly relevant.

By following these steps, I was able to produce a comprehensive and informative summary of the `fragmentation_utils.cc` file. The key was to break down the code into smaller, manageable parts and then connect those parts to the broader context of web technologies and layout.
好的，这是对 `blink/renderer/core/layout/fragmentation_utils.cc` 文件第一部分的分析和归纳：

**功能归纳：**

`fragmentation_utils.cc` 文件（的第一部分）主要负责处理与 CSS 盒模型碎片化相关的各种实用工具函数。这些函数用于辅助 Blink 渲染引擎在布局过程中，决定如何在不同的碎片容器（fragmentainer，例如多列布局的列或分页布局的页）之间进行内容分割和布局。

具体来说，这部分代码的核心功能围绕以下几个方面展开：

1. **处理和比较碎片容器的分割属性 (Break Properties)：**
   - 定义了不同 `break-before`, `break-after` 属性值的优先级 (`FragmentainerBreakPrecedence`)。
   - 提供了合并不同来源的分割属性值的方法 (`JoinFragmentainerBreakValues`)，遵循优先级规则。
   - 提供了判断一个分割值是否是强制分割 (`IsForcedBreakValue`) 或避免分割 (`IsAvoidBreakValue`) 的方法，并考虑了当前的约束空间 (`ConstraintSpace`)。

2. **计算和评估分割点的吸引力 (Break Appeal)：**
   - 提供了计算在特定子节点之前进行分割的吸引力 (`CalculateBreakAppealBefore`) 的方法，考虑了强制分割、避免分割、容器分割等因素。
   - 提供了计算在子节点内部进行分割的吸引力 (`CalculateBreakAppealInside`) 的方法，考虑了 `break-inside` 属性。

3. **计算碎片容器的容量和偏移：**
   - 提供了计算碎片容器逻辑容量 (`FragmentainerLogicalCapacity`) 的方法。
   - 提供了根据碎片化类型 (`kFragmentColumn`, `kFragmentPage`) 获取碎片容器的偏移量 (`GetFragmentainerProgression`) 的方法。

4. **设置用于碎片化的约束空间和碎片构建器 (ConstraintSpace & BoxFragmentBuilder)：**
   - 提供了 `SetupSpaceBuilderForFragmentation` 函数，用于根据父约束空间、子节点信息、碎片容器的偏移和大小等信息，配置子节点的约束空间构建器 (`ConstraintSpaceBuilder`)，以便进行碎片化布局。
   - 提供了 `SetupFragmentBuilderForFragmentation` 函数，用于根据约束空间、节点信息和之前的分割标记 (`BlockBreakToken`) 配置碎片构建器 (`BoxFragmentBuilder`)，为创建碎片做准备。这包括设置是否需要克隆边框和内边距，以及标记是否是节点的第一个碎片。

5. **判断是否包含边框和内边距：**
   - 提供了 `ShouldIncludeBlockStartBorderPadding` 和 `ShouldIncludeBlockEndBorderPadding` 函数，用于判断在碎片中是否应该包含块起始和块结束的边框和内边距，这与 `box-decoration-break` 属性有关。

6. **完成碎片化过程：**
   - 提供了 `FinishFragmentation` 函数，用于在完成对一个块的碎片化布局后，计算最终的碎片大小，并设置碎片的相关属性，例如是否发生了分割。

**与 JavaScript, HTML, CSS 的关系：**

这个文件与 HTML 和 CSS 的关系非常密切，它直接处理 CSS 布局中与碎片化相关的属性。

* **CSS 分割属性 (Break Properties)：**  例如 `break-before: page;`, `break-after: column;`, `break-inside: avoid;` 等属性会影响 `FragmentainerBreakPrecedence`, `JoinFragmentainerBreakValues`, `IsForcedBreakValue`, `IsAvoidBreakValue`, `CalculateBreakAppealBefore`, `CalculateBreakAppealInside` 等函数的行为。

   **举例：**

   ```html
   <div style="columns: 2;">
     <h2 style="break-before: column;">This heading will start in a new column.</h2>
     <p>Content in the first column.</p>
     <p>More content.</p>
   </div>
   ```

   在这个例子中，`break-before: column;` 会影响 `CalculateBreakAppealBefore` 函数的计算，使得在 `h2` 元素之前进行列分割的吸引力更高。

* **CSS `box-decoration-break` 属性：** `ShouldCloneBlockStartBorderPadding` 和 `ShouldIncludeBlockEndBorderPadding` 函数与 `box-decoration-break` 属性有关。

   **举例：**

   ```html
   <div style="border: 1px solid black; padding: 5px; box-decoration-break: clone;">
     This div will have its border and padding repeated on each fragment.
   </div>
   ```

   如果 `box-decoration-break` 设置为 `clone`，`ShouldCloneBlockStartBorderPadding` 将返回 `true`，导致每个碎片都包含起始的边框和内边距。

* **CSS 多列布局 (Multi-column Layout)：** 当使用 `columns` 或 `column-count` 等属性创建多列布局时，`fragmentation_utils.cc` 中的函数会被调用来决定如何在不同的列之间分割内容。`GetFragmentainerProgression` 函数在多列布局中会返回列的内联方向的偏移。

* **CSS 分页布局 (Paged Media)：** 当为打印样式设置 `break-before: page;` 或 `break-after: page;` 等属性时，这个文件中的函数会参与决定如何在不同的页面之间分割内容。

**逻辑推理 (假设输入与输出)：**

假设我们有以下 HTML 和 CSS：

```html
<div style="height: 100px; overflow: auto;">
  <p style="height: 60px;">First paragraph.</p>
  <p style="break-before: avoid; height: 70px;">Second paragraph.</p>
</div>
```

假设布局引擎正在处理第二个段落 (`<p style="break-before: avoid; height: 70px;">`)，并且当前的碎片容器（高度 100px 的 `div`）剩余空间为 50px。

* **输入到 `CalculateBreakAppealBefore` 函数的可能参数：**
    * `space`: 代表 `div` 的约束空间信息。
    * `child`: 代表第二个段落的布局输入节点。
    * `layout_result`:  可能为空，因为这是布局前的评估。
    * `builder`: 代表当前碎片构建器。

* **逻辑推理：**
    * `child.Style().BreakBefore()` 将返回 `EBreakBetween::kAvoid`。
    * `IsAvoidBreakValue(space, EBreakBetween::kAvoid)` 可能会返回 `true`，取决于 `space` 是否允许避免分割。
    * 由于剩余空间 (50px) 小于第二个段落的高度 (70px)，如果强制避免分割，则 `CalculateBreakAppealBefore` 可能会返回 `kBreakAppealViolatingBreakAvoid` 或更低的吸引力，表示这里不是一个好的分割点。

* **可能的输出：** `kBreakAppealViolatingBreakAvoid`

**用户或编程常见的使用错误：**

1. **CSS 分割属性冲突：** 用户可能在不同的元素上设置相互冲突的分割属性，导致意外的布局结果。例如，在一个强制分割的元素内部，尝试避免分割。

   **举例：**

   ```html
   <div style="break-after: page;">
     <p style="break-before: avoid;">This paragraph might still start on a new page.</p>
   </div>
   ```

   `break-after: page;` 的优先级高于 `break-before: avoid;`，所以段落很可能仍然会开始于新的一页。

2. **误解 `break-inside: avoid;` 的作用域：** 开发者可能认为 `break-inside: avoid;` 可以阻止在元素内的任何位置进行分割，但实际上，如果元素的父容器强制分割，那么仍然可能会发生分割。

   **举例：**

   ```html
   <div style="columns: 2;">
     <div style="break-inside: avoid;">
       <p>Long content that might still be split across columns.</p>
     </div>
   </div>
   ```

   即使内部的 `div` 设置了 `break-inside: avoid;`，如果内容太长，仍然可能在列之间被分割。

3. **忽略碎片容器的限制：**  开发者可能没有考虑到碎片容器的固定大小或剩余空间，导致预期的分割行为没有发生。

   **举例：**

   ```html
   <div style="height: 50px; overflow: hidden;">
     <p style="break-before: always;">This might not start on a new 'page' if the container is too small.</p>
   </div>
   ```

   在这个例子中，如果 `div` 的高度太小，`break-before: always;` 可能不会像在分页媒体中那样创建一个新的页面。

**总结：**

`fragmentation_utils.cc` 的第一部分提供了一系列核心工具函数，用于 Blink 渲染引擎在布局过程中处理 CSS 盒模型的碎片化。它涉及到分割属性的优先级判断、分割点吸引力的评估、碎片容器容量的计算以及碎片构建器的配置。理解这些函数的功能有助于深入理解浏览器如何处理多列布局、分页打印等与内容碎片化相关的 CSS 特性。

### 提示词
```
这是目录为blink/renderer/core/layout/fragmentation_utils.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/fragmentation_utils.h"

#include "base/containers/adapters.h"
#include "third_party/blink/renderer/core/core_export.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/layout/block_break_token.h"
#include "third_party/blink/renderer/core/layout/box_fragment_builder.h"
#include "third_party/blink/renderer/core/layout/constraint_space.h"
#include "third_party/blink/renderer/core/layout/constraint_space_builder.h"
#include "third_party/blink/renderer/core/layout/length_utils.h"
#include "third_party/blink/renderer/core/layout/logical_box_fragment.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"

namespace blink {

namespace {
// At a class A break point [1], the break value with the highest precedence
// wins. If the two values have the same precedence (e.g. "left" and "right"),
// the value specified on a latter object wins.
//
// [1] https://drafts.csswg.org/css-break/#possible-breaks
inline int FragmentainerBreakPrecedence(EBreakBetween break_value) {
  // "auto" has the lowest priority.
  // "avoid*" values win over "auto".
  // "avoid-page" wins over "avoid-column".
  // "avoid" wins over "avoid-page".
  // Forced break values win over "avoid".
  // Any forced page break value wins over "column" forced break.
  // More specific break values (left, right, recto, verso) wins over generic
  // "page" values.

  switch (break_value) {
    default:
      NOTREACHED();
    case EBreakBetween::kAuto:
      return 0;
    case EBreakBetween::kAvoidColumn:
      return 1;
    case EBreakBetween::kAvoidPage:
      return 2;
    case EBreakBetween::kAvoid:
      return 3;
    case EBreakBetween::kColumn:
      return 4;
    case EBreakBetween::kPage:
      return 5;
    case EBreakBetween::kLeft:
    case EBreakBetween::kRight:
    case EBreakBetween::kRecto:
    case EBreakBetween::kVerso:
      return 6;
  }
}

bool ShouldCloneBlockStartBorderPadding(const BoxFragmentBuilder& builder) {
  if (builder.Node().Style().BoxDecorationBreak() !=
      EBoxDecorationBreak::kClone) {
    return false;
  }
  const BlockBreakToken* previous_break_token = builder.PreviousBreakToken();
  if (!previous_break_token) {
    return true;
  }
  if (previous_break_token->MonolithicOverflow()) {
    LayoutUnit space_left =
        FragmentainerSpaceLeft(builder, /*is_for_children=*/false);
    if (space_left < builder.BorderScrollbarPadding().BlockSum()) {
      return false;
    }
  }
  return !previous_break_token->IsAtBlockEnd();
}

}  // anonymous namespace

EBreakBetween JoinFragmentainerBreakValues(EBreakBetween first_value,
                                           EBreakBetween second_value) {
  if (FragmentainerBreakPrecedence(second_value) >=
      FragmentainerBreakPrecedence(first_value))
    return second_value;
  return first_value;
}

bool IsForcedBreakValue(const ConstraintSpace& constraint_space,
                        EBreakBetween break_value) {
  if (constraint_space.ShouldIgnoreForcedBreaks())
    return false;
  if (break_value == EBreakBetween::kColumn)
    return constraint_space.BlockFragmentationType() == kFragmentColumn;
  // TODO(mstensho): The innermost fragmentation type doesn't tell us everything
  // here. We might want to force a break to the next page, even if we're in
  // multicol (printing multicol, for instance).
  if (break_value == EBreakBetween::kLeft ||
      break_value == EBreakBetween::kPage ||
      break_value == EBreakBetween::kRecto ||
      break_value == EBreakBetween::kRight ||
      break_value == EBreakBetween::kVerso)
    return constraint_space.BlockFragmentationType() == kFragmentPage;
  return false;
}

template <typename Property>
bool IsAvoidBreakValue(const ConstraintSpace& constraint_space,
                       Property break_value) {
  if (break_value == Property::kAvoid)
    return constraint_space.HasBlockFragmentation();
  if (break_value == Property::kAvoidColumn)
    return constraint_space.BlockFragmentationType() == kFragmentColumn;
  // TODO(mstensho): The innermost fragmentation type doesn't tell us everything
  // here. We might want to avoid breaking to the next page, even if we're
  // in multicol (printing multicol, for instance).
  if (break_value == Property::kAvoidPage)
    return constraint_space.BlockFragmentationType() == kFragmentPage;
  return false;
}
// The properties break-after, break-before and break-inside may all specify
// avoid* values. break-after and break-before use EBreakBetween, and
// break-inside uses EBreakInside.
template bool CORE_TEMPLATE_EXPORT IsAvoidBreakValue(const ConstraintSpace&,
                                                     EBreakBetween);
template bool CORE_TEMPLATE_EXPORT IsAvoidBreakValue(const ConstraintSpace&,
                                                     EBreakInside);

EBreakBetween CalculateBreakBetweenValue(LayoutInputNode child,
                                         const LayoutResult& layout_result,
                                         const BoxFragmentBuilder& builder) {
  if (child.IsInline())
    return EBreakBetween::kAuto;

  // Since it's not an inline node, if we have a fragment at all, it has to be a
  // box fragment.
  const PhysicalBoxFragment* box_fragment = nullptr;
  if (layout_result.Status() == LayoutResult::kSuccess) {
    box_fragment =
        &To<PhysicalBoxFragment>(layout_result.GetPhysicalFragment());
    if (!box_fragment->IsFirstForNode()) {
      // If the node is resumed after a break, we are not *before* it anymore,
      // so ignore values. We normally don't even consider breaking before a
      // resumed node, since there normally is no container separation. The
      // normal place to resume is at the very start of the fragmentainer -
      // cannot break there!  However, there are cases where a node is resumed
      // at a location past the start of the fragmentainer, e.g. when printing
      // monolithic overflowing content.
      return EBreakBetween::kAuto;
    }
  }

  EBreakBetween break_before = JoinFragmentainerBreakValues(
      child.Style().BreakBefore(), layout_result.InitialBreakBefore());
  break_before = builder.JoinedBreakBetweenValue(break_before);
  const auto& space = builder.GetConstraintSpace();
  if (space.IsPaginated() && box_fragment &&
      !IsForcedBreakValue(builder.GetConstraintSpace(), break_before)) {
    AtomicString current_name = builder.PageName();
    if (current_name == g_null_atom) {
      current_name = space.PageName();
    }
    // If the page name propagated from the child differs from what we already
    // have, we need to break before the child.
    if (box_fragment->PageName() != current_name) {
      return EBreakBetween::kPage;
    }
  }
  return break_before;
}

bool IsBreakableAtStartOfResumedContainer(
    const ConstraintSpace& space,
    const LayoutResult& child_layout_result,
    const BoxFragmentBuilder& builder) {
  if (child_layout_result.Status() != LayoutResult::kSuccess) {
    return false;
  }
  bool is_first_for_node = true;
  if (const auto* box_fragment = DynamicTo<PhysicalBoxFragment>(
          child_layout_result.GetPhysicalFragment())) {
    is_first_for_node = box_fragment->IsFirstForNode();
  }
  return IsBreakableAtStartOfResumedContainer(space, builder,
                                              is_first_for_node);
}

bool IsBreakableAtStartOfResumedContainer(const ConstraintSpace& space,
                                          const BoxFragmentBuilder& builder,
                                          bool is_first_for_node) {
  return space.MinBreakAppeal() != kBreakAppealLastResort &&
         IsBreakInside(builder.PreviousBreakToken()) && is_first_for_node;
}

BreakAppeal CalculateBreakAppealBefore(const ConstraintSpace& space,
                                       LayoutInputNode child,
                                       const LayoutResult& layout_result,
                                       const BoxFragmentBuilder& builder,
                                       bool has_container_separation) {
  bool breakable_at_start_of_container =
      IsBreakableAtStartOfResumedContainer(space, layout_result, builder);
  EBreakBetween break_between =
      CalculateBreakBetweenValue(child, layout_result, builder);
  return CalculateBreakAppealBefore(space, layout_result.Status(),
                                    break_between, has_container_separation,
                                    breakable_at_start_of_container);
}

BreakAppeal CalculateBreakAppealBefore(
    const ConstraintSpace& space,
    LayoutResult::EStatus layout_result_status,
    EBreakBetween break_between,
    bool has_container_separation,
    bool breakable_at_start_of_container) {
  DCHECK(layout_result_status == LayoutResult::kSuccess ||
         layout_result_status == LayoutResult::kOutOfFragmentainerSpace);
  BreakAppeal break_appeal = kBreakAppealPerfect;
  if (!has_container_separation &&
      layout_result_status == LayoutResult::kSuccess) {
    if (!breakable_at_start_of_container) {
      // This is not a valid break point. If there's no container separation, it
      // means that we're breaking before the first piece of in-flow content
      // inside this block, even if it's not a valid class C break point [1]. We
      // really don't want to break here, if we can find something better.
      //
      // [1] https://www.w3.org/TR/css-break-3/#possible-breaks
      return kBreakAppealLastResort;
    }

    // This is the first child after a break. We are normally not allowed to
    // break before those, but in this case we will allow it, to prevent
    // suboptimal breaks that might otherwise occur further ahead in the
    // fragmentainer. If necessary, we'll push this child (and all subsequent
    // content) past all the columns in the current row all the way to the the
    // next row in the next outer fragmentainer, where there may be more space,
    // in order to avoid suboptimal breaks.
    break_appeal = space.MinBreakAppeal();
  }

  if (IsAvoidBreakValue(space, break_between)) {
    // If there's a break-{after,before}:avoid* involved at this breakpoint, its
    // appeal will decrease.
    break_appeal = std::min(break_appeal, kBreakAppealViolatingBreakAvoid);
  }
  return break_appeal;
}

BreakAppeal CalculateBreakAppealInside(
    const ConstraintSpace& space,
    const LayoutResult& layout_result,
    std::optional<BreakAppeal> hypothetical_appeal) {
  if (layout_result.HasForcedBreak())
    return kBreakAppealPerfect;
  const auto& physical_fragment = layout_result.GetPhysicalFragment();
  const auto* break_token =
      DynamicTo<BlockBreakToken>(physical_fragment.GetBreakToken());
  BreakAppeal appeal;
  bool consider_break_inside_avoidance;
  if (hypothetical_appeal) {
    // The hypothetical appeal of breaking inside should only be considered if
    // we haven't actually broken.
    DCHECK(!break_token);
    appeal = *hypothetical_appeal;
    consider_break_inside_avoidance = true;
  } else {
    appeal = layout_result.GetBreakAppeal();
    consider_break_inside_avoidance = IsBreakInside(break_token);
  }

  // We don't let break-inside:avoid affect the child's stored break appeal, but
  // we rather handle it now, on the outside. The reason is that we want to be
  // able to honor any 'avoid' values on break-before or break-after among the
  // children of the child, even if we need to disregrard a break-inside:avoid
  // rule on the child itself. This prevents us from violating more rules than
  // necessary: if we need to break inside the child (even if it should be
  // avoided), we'll at least break at the most appealing location inside.
  if (consider_break_inside_avoidance &&
      appeal > kBreakAppealViolatingBreakAvoid &&
      IsAvoidBreakValue(space, physical_fragment.Style().BreakInside()))
    appeal = kBreakAppealViolatingBreakAvoid;
  return appeal;
}

LogicalSize FragmentainerLogicalCapacity(
    const PhysicalBoxFragment& fragmentainer) {
  DCHECK(fragmentainer.IsFragmentainerBox());
  LogicalSize logical_size =
      WritingModeConverter(fragmentainer.Style().GetWritingDirection())
          .ToLogical(fragmentainer.Size());
  // TODO(layout-dev): This should really be checking if there are any
  // descendants that take up block space rather than if it has overflow. In
  // other words, we would still want to clamp a zero height fragmentainer if
  // it had content with zero inline size and non-zero block size. This would
  // likely require us to store an extra flag on PhysicalBoxFragment.
  if (fragmentainer.HasScrollableOverflow()) {
    // Don't clamp the fragmentainer to a block size of 1 if it is truly a
    // zero-height column.
    logical_size.block_size =
        ClampedToValidFragmentainerCapacity(logical_size.block_size);
  }
  return logical_size;
}

LogicalOffset GetFragmentainerProgression(const BoxFragmentBuilder& builder,
                                          FragmentationType type) {
  if (type == kFragmentColumn) {
    LayoutUnit column_inline_progression = ColumnInlineProgression(
        builder.ChildAvailableSize().inline_size, builder.Style());
    return LogicalOffset(column_inline_progression, LayoutUnit());
  }
  DCHECK_EQ(type, kFragmentPage);
  return LogicalOffset(LayoutUnit(), builder.ChildAvailableSize().block_size);
}

void SetupSpaceBuilderForFragmentation(const ConstraintSpace& parent_space,
                                       const LayoutInputNode& child,
                                       LayoutUnit fragmentainer_offset,
                                       LayoutUnit fragmentainer_block_size,
                                       bool requires_content_before_breaking,
                                       ConstraintSpaceBuilder* builder) {
  DCHECK(parent_space.HasBlockFragmentation());

  // If the child is truly unbreakable, it won't participate in block
  // fragmentation. If it's too tall to fit, it will either overflow the
  // fragmentainer or get brutally sliced into pieces (without looking for
  // allowed breakpoints, since there are none, by definition), depending on
  // fragmentation type (multicol vs. printing). We still need to perform block
  // fragmentation inside inline nodes, though: While the line box itself is
  // monolithic, there may be floats inside, which are fragmentable.
  if (child.IsMonolithic() && !child.IsInline()) {
    builder->SetShouldPropagateChildBreakValues(false);
    return;
  }

  builder->SetFragmentainerBlockSize(fragmentainer_block_size);
  builder->SetFragmentainerOffset(fragmentainer_offset);
  if (fragmentainer_offset <= LayoutUnit())
    builder->SetIsAtFragmentainerStart();
  builder->SetFragmentationType(parent_space.BlockFragmentationType());
  builder->SetShouldPropagateChildBreakValues();
  DCHECK(!requires_content_before_breaking ||
         !parent_space.IsInitialColumnBalancingPass());
  builder->SetRequiresContentBeforeBreaking(requires_content_before_breaking);

  if (parent_space.IsInsideBalancedColumns())
    builder->SetIsInsideBalancedColumns();

  // We lack the required machinery to resume layout inside out-of-flow
  // positioned elements during regular layout. OOFs are handled by regular
  // layout during the initial column balacning pass, while it's handled
  // specially during actual layout - at the outermost fragmentation context in
  // OutOfFlowLayoutPart (so this is only an issue when calculating the
  // initial column block-size). So just disallow breaks (we only need to worry
  // about forced breaks, as soft breaks are impossible in the initial column
  // balancing pass). This might result in over-stretched columns in some
  // strange cases, but probably something we can live with.
  if ((parent_space.IsInitialColumnBalancingPass() &&
       child.IsOutOfFlowPositioned()) ||
      parent_space.ShouldIgnoreForcedBreaks())
    builder->SetShouldIgnoreForcedBreaks();

  builder->SetMinBreakAppeal(parent_space.MinBreakAppeal());

  if (parent_space.IsPaginated()) {
    if (AtomicString page_name = child.PageName())
      builder->SetPageName(page_name);
    else
      builder->SetPageName(parent_space.PageName());
  }
}

void SetupSpaceBuilderForFragmentation(
    const BoxFragmentBuilder& parent_fragment_builder,
    const LayoutInputNode& child,
    LayoutUnit fragmentainer_offset_delta,
    ConstraintSpaceBuilder* builder) {
  LayoutUnit fragmentainer_block_size =
      FragmentainerCapacity(parent_fragment_builder, /*is_for_children=*/true);
  LayoutUnit fragmentainer_block_offset =
      FragmentainerOffset(parent_fragment_builder, /*is_for_children=*/true) +
      fragmentainer_offset_delta;
  return SetupSpaceBuilderForFragmentation(
      parent_fragment_builder.GetConstraintSpace(), child,
      fragmentainer_block_offset, fragmentainer_block_size,
      parent_fragment_builder.RequiresContentBeforeBreaking(), builder);
}

void SetupFragmentBuilderForFragmentation(
    const ConstraintSpace& space,
    const LayoutInputNode& node,
    const BlockBreakToken* previous_break_token,
    BoxFragmentBuilder* builder) {
  // When resuming layout after a break, we may not be allowed to break again
  // (because of clipped overflow). In such situations, we should not call
  // SetHasBlockFragmentation(), but we still need to resume layout correctly,
  // based on the previous break token.
  DCHECK(space.HasBlockFragmentation() || previous_break_token);
  // If the node itself is monolithic, we shouldn't be here.
  DCHECK(!node.IsMonolithic() || space.IsAnonymous());
  // If we turn off fragmentation on a non-monolithic node, we need to treat the
  // resulting fragment as monolithic. This matters when it comes to determining
  // the containing block of out-of-flow positioned descendants. In order to
  // match the behavior in OOF layout, however, the fragment should only become
  // monolithic when fragmentation is forced off at the first fragment. If we
  // reach the end of the visible area after the containing block has inserted a
  // break, it should not be set as monolithic. (How can we be monolithic, if we
  // create more than one fragment, anyway?) An OOF fragment will always become
  // a direct child of the fragmentainer if the containing block generates more
  // than one fragment. The monolithicness flag is ultimately checked by
  // pre-paint, in order to know where in the tree to look for the OOF fragment
  // (direct fragmentainer child vs. child of the actual containing block).
  builder->SetIsMonolithic(!space.IsAnonymous() &&
                           space.IsBlockFragmentationForcedOff() &&
                           !IsBreakInside(previous_break_token));

  if (space.HasBlockFragmentation())
    builder->SetHasBlockFragmentation();

  if (space.IsInitialColumnBalancingPass())
    builder->SetIsInitialColumnBalancingPass();

  unsigned sequence_number = 0;
  if (previous_break_token && !previous_break_token->IsBreakBefore()) {
    sequence_number = previous_break_token->SequenceNumber() + 1;
    builder->SetIsFirstForNode(false);
  }

  LayoutUnit space_left =
      FragmentainerSpaceLeft(*builder, /*is_for_children=*/false);

  // If box decorations are to be cloned, both block-start and block-end should
  // obviosuly be present in every fragment, but whether block-end decorations
  // count as being cloned or not depends on whether the fragment currently
  // being built is known to be the last fragment. If it is, block-end box
  // decorations will behave as normally, so that child content may overflow it.
  bool clone_box_start_decorations =
      ShouldCloneBlockStartBorderPadding(*builder);
  bool clone_box_end_decorations = clone_box_start_decorations;

  if (clone_box_start_decorations) {
    // Include border/padding from previous fragments. When resolving the
    // block-size for this fragment, we need the total space used by
    // decorations.
    builder->UpdateBorderPaddingForClonedBoxDecorations();
  }

  if (space.HasBlockFragmentation() && !space.IsAnonymous() &&
      !space.IsInitialColumnBalancingPass()) {
    bool requires_content_before_breaking =
        space.RequiresContentBeforeBreaking();
    // We're now going to figure out if the (remainder of the) node is
    // guaranteed to fit in the fragmentainer, and make some decisions based on
    // that. We'll skip this for tables, because table sizing is complicated,
    // since captions are not part of the "table box", and any specified
    // block-size pertains to the table box, while the captions are on the
    // outside of the "table box", but still part of the fragment.
    if (!node.IsTable() &&
        builder->InitialBorderBoxSize().inline_size != kIndefiniteSize) {
      // Pass an "infinite" intrinsic size to see how the block-size is
      // constrained. If it doesn't affect the block size, it means that we can
      // tell before layout how much more space this node needs.
      LayoutUnit max_block_size = ComputeBlockSizeForFragment(
          space, To<BlockNode>(node), builder->BorderPadding(),
          LayoutUnit::Max(), builder->InitialBorderBoxSize().inline_size);
      DCHECK(space.HasKnownFragmentainerBlockSize());

      // If max_block_size is "infinite", we can't tell for sure that it's going
      // to fit. The calculation below will normally detect that, but it's going
      // to be incorrect when we have reached the point where space left
      // incorrectly seems to be enough to contain the remaining fragment when
      // subtracting previously consumed block-size from its max size.
      if (max_block_size != LayoutUnit::Max()) {
        LayoutUnit previously_consumed_block_size;
        if (previous_break_token) {
          previously_consumed_block_size =
              previous_break_token->ConsumedBlockSize();
        }

        if (max_block_size - previously_consumed_block_size <= space_left) {
          builder->SetIsKnownToFitInFragmentainer(true);
          clone_box_end_decorations = false;
          if (builder->MustStayInCurrentFragmentainer())
            requires_content_before_breaking = true;
        }
      }
    }

    if (clone_box_end_decorations) {
      builder->SetShouldCloneBoxEndDecorations(true);

      // If block-end border+padding is cloned, they should be repeated in every
      // fragment, so breaking before them would be wrong and make no sense.
      builder->SetShouldPreventBreakBeforeBlockEndDecorations(true);
    }

    builder->SetRequiresContentBeforeBreaking(requires_content_before_breaking);
  }
  builder->SetSequenceNumber(sequence_number);

  if (IsBreakInside(previous_break_token) && !clone_box_start_decorations) {
    // When resuming after a fragmentation break in the slicing box decoration
    // break model, block-start border and padding are omitted. Don't omit it
    // here for tables, though. The table box (which contains the border) might
    // not start in the first fragment, if there are preceding captions, so the
    // table algorithm needs to handle this logic on its own.
    if (!node.IsTable()) {
      builder->ClearBorderScrollbarPaddingBlockStart();
    }
  }

  if (builder->IsInitialColumnBalancingPass()) {
    const BoxStrut& unbreakable = builder->BorderScrollbarPadding();
    builder->PropagateTallestUnbreakableBlockSize(unbreakable.block_start);
    builder->PropagateTallestUnbreakableBlockSize(unbreakable.block_end);
  }
}

bool ShouldIncludeBlockStartBorderPadding(const BoxFragmentBuilder& builder) {
  return !IsBreakInside(builder.PreviousBreakToken()) ||
         ShouldCloneBlockStartBorderPadding(builder);
}

bool ShouldIncludeBlockEndBorderPadding(const BoxFragmentBuilder& builder) {
  if (builder.PreviousBreakToken() &&
      builder.PreviousBreakToken()->IsAtBlockEnd()) {
    // Past the block-end, and therefore past block-end border+padding.
    return false;
  }
  if (!builder.ShouldBreakInside() || builder.IsKnownToFitInFragmentainer() ||
      builder.ShouldCloneBoxEndDecorations()) {
    return true;
  }

  // We're going to break inside.
  if (builder.GetConstraintSpace().IsNewFormattingContext()) {
    return false;
  }
  // Not being a formatting context root, only in-flow child breaks will have an
  // effect on where the block ends.
  return !builder.HasInflowChildBreakInside();
}

BreakStatus FinishFragmentation(BoxFragmentBuilder* builder) {
  const BlockNode& node = builder->Node();
  const ConstraintSpace& space = builder->GetConstraintSpace();
  LayoutUnit space_left = FragmentainerSpaceLeft(*builder,
                                                 /*is_for_children=*/false);
  const BlockBreakToken* previous_break_token = builder->PreviousBreakToken();
  LayoutUnit previously_consumed_block_size;
  if (previous_break_token && !previous_break_token->IsBreakBefore())
    previously_consumed_block_size = previous_break_token->ConsumedBlockSize();
  bool is_past_end =
      previous_break_token && previous_break_token->IsAtBlockEnd();

  LayoutUnit fragments_total_block_size = builder->FragmentsTotalBlockSize();
  LayoutUnit desired_block_size =
      fragments_total_block_size - previously_consumed_block_size;

  // Consumed block-size stored in the break tokens is always stretched to the
  // fragmentainers. If this wasn't also the case for all previous fragments
  // (because we reached the end of the node and were overflowing), we may end
  // up with negative values here.
  desired_block_size = desired_block_size.ClampNegativeToZero();

  LayoutUnit desired_intrinsic_block_size = builder->IntrinsicBlockSize();

  LayoutUnit final_block_size = desired_block_size;

  LayoutUnit trailing_border_padding =
      builder->BorderScrollbarPadding().block_end;
  LayoutUnit subtractable_border_padding;
  if (!builder->ShouldPreventBreakBeforeBlockEndDecorations()) {
    if (desired_block_size > trailing_border_padding ||
        (previous_break_token && previous_break_token->MonolithicOverflow())) {
      // There is a last-resort breakpoint before trailing border and padding,
      // if progress can still be guaranteed.
      //
      // Note that we're always guaranteed progress if there's incoming
      // monolithic overflow. We're going to move past monolithic overflow, and
      // just add as many fragments we need in order to get past the overflow.
      subtractable_border_padding = trailing_border_padding;
    }
  }

  if (space_left != kIndefiniteSize) {
    // If intrinsic block-size is larger than space left, it means that we have
    // some tall unbreakable child content (otherwise it would already have
    // broken to stay within the limits). In such cases, this fragment will be
    // allowed to take up more space (within applicable constraints) in a
    // similarly unbreakable manner, to encompass the unbreakable content. This
    // effectively increases the fragmentainer space available, as far as this
    // node is concerned.
    space_left = std::max(
        space_left, desired_intrinsic_block_size - subtractable_border_padding);
  }

  if (space.IsPaginated()) {
    // Descendants take precedence, but if none of them propagated a page name,
    // use the one specified on this element (or on something in the ancestry)
    // now, if any.
    builder->SetPageNameIfNeeded(space.PageName());
  }

  if (builder->FoundColumnSpanner())
    builder->SetDidBreakSelf();

  if (is_past_end) {
    final_block_size = LayoutUnit();
  } else if (builder->FoundColumnSpanner()) {
    // There's a column spanner (or more) inside. This means that layout got
    // interrupted and thus hasn't reached the end of this block yet. We're
    // going to resume inside this block when done with the spanner(s). This is
    // true even if there is no column content siblings after the spanner(s).
    //
    // <div style="columns:2;">
    //   <div id="container" style="height:100px;">
    //     <div id="child" style="height:20px;"></div>
    //     <div style="column-span:all;"></div>
    //   </div>
    // </div>
    //
    // We'll create fragments for #container both before and after the spanner.
    // Before the spanner we'll create one for each column, each 10px tall
    // (height of #child divided into 2 columns). After the spanner, there's no
    // more content, but the specified height is 100px, so distribute what we
    // haven't already consumed (100px - 20px = 80px) over two columns. We get
    // two fragments for #container after the spanner, each 40px tall.
    final_block_size =
        std::min(final_block_size, desired_intrinsic_block_size) -
        trailing_border_padding;

    // TODO(crbug.com/1381327): We shouldn't get negative sizes here, but this
    // happens if we have incorrectly added trailing border/padding of a
    // block-size-restricted container (of a spanner) in a previous fragment, so
    // that we're past the block-end border edge, in which case
    // desired_block_size will be zero (because of an overly large
    // previously_consumed_block_size) - so that subtracting
    // trailing_border_padding here might result in a negative value. Note that
    // the code block right below has some subtractable_border_padding logic
    // that could have saved us here, but it still wouldn't be correct. We
    // should never add block-end border/padding if we're interrupted by as
    // spanner. So just clamp to zero, to avoid DCHECK failures.
    final_block_size = final_block_size.ClampNegativeToZero();
  } else if (space_left != kIndefiniteSize && desired_block_size > space_left &&
             space.HasBlockFragmentation()) {
    // We're taller than what we have room for. We don't want to use more than
    // |space_left|, but if the intrinsic block-size is larger than that, it
    // means that there's something unbreakable (monolithic) inside (or we'd
    // already have broken inside). We'll allow this to overflow the
    // fragmentainer.
    DCHECK_GE(desired_intrinsic_block_size, trailing_border_padding);
    DCHECK_GE(desired_block_size, trailing_border_padding);

    LayoutUnit modified_intrinsic_block_size = std::max(
        space_left, desired_intrinsic_block_size - subtractable_border_padding);
    builder->SetIntrinsicBlockSize(modified_intrinsic_block_size);
    final_block_size =
        std::min(desired_block_size - subtractable_border_padding,
                 modified_intrinsic_block_size);

    // We'll only need to break inside if we need more space after any
    // unbreakable content that we may have forcefully fitted here.
    if (final_block_size < desired_block_size)
      builder->SetDidBreakSelf();
  }

  LogicalBoxSides sides;
  // If this isn't the first fragment, omit the block-start border, if in the
  // slicing box decoration break model.
  if (previously_consumed_block_size &&
      (node.Style().BoxDecorationBreak() == EBoxDecorationBreak::kSlice ||
       is_past_end)) {
    sides.block_start = false;
  }
  // If this isn't the last fragment with same-flow content, omit the block-end
  // border. If something overflows the node, we'll keep on creating empty
  // fragments to contain the overflow (which establishes a parallel flow), but
  // those fragments should make no room (nor paint) block-end border/paddding.
  if ((builder->DidBreakSelf() && !builder->ShouldCloneBoxEndDecorations()) ||
      is_past_end) {
    sides.block_end = false;
  }
  builder->SetSidesToInclude(sides);

  builder->SetConsumedBlockSize(previously_consumed_block_size +
                                final_block_size);
  builder->SetFragmentBlockSize(final_block_size);

  if (builder->FoundColumnSpanner() || !space.HasBlockFragmentation())
    return BreakStatus::kContinue;

  bool was_broken_by_child = builder->HasInflowChildBreakInside();
  if (!was_broken_by_child && space.IsNewFormattingContext())
    was_broken_by_child = builder->GetExclusionSpace().HasFragmentainerBreak();

  if (space_left == kIndefiniteSize) {
    // We don't know how space is available (initial column balancing pass), so
    // we won't break.
    if (!was_broken_by_child)
      builder->SetIsAtBlockEnd();
    return BreakStatus::kContinue;
  }

  if (!final_block_size && previous_break_token &&
      previous_break_token->MonolithicOverflow()) {
    // See if we've now managed to move past previous fragmentainer overflow, or
    // if we need to steer clear of at least some of it in the nex
```