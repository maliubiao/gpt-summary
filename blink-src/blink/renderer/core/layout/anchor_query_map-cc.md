Response:
Let's break down the thought process for analyzing this C++ code and generating the response.

1. **Understand the Goal:** The primary goal is to explain the functionality of `anchor_query_map.cc` in the Blink rendering engine and relate it to web technologies like JavaScript, HTML, and CSS. We also need to provide examples, logical inferences, and highlight potential usage errors.

2. **Initial Scan and Keyword Recognition:**  The first step is to quickly scan the code for prominent keywords and structures. Things that immediately jump out are:

    * `#include`: Indicates dependencies on other parts of the Blink engine (geometry, inline, layout).
    * `namespace blink`:  Confirms this is Blink-specific code.
    * `AnchorQueryMap`, `StitchedAnchorQuery`, `LogicalAnchorQuery`: These are likely the core data structures.
    * `Fragment`, `Fragmentainer`: Suggests this code deals with how content is broken up for layout (like multi-column layouts or fragmentation).
    * `LayoutObject`, `LayoutBox`: Fundamental classes in Blink representing elements in the render tree.
    * `PhysicalRect`, `LogicalRect`, `PhysicalOffset`, `LogicalOffset`: Indicate the code handles geometric calculations, likely converting between different coordinate systems.
    * `AnchorKey`, `AnchorReference`:  Strong indication this code is related to the CSS anchor positioning feature.
    * `OutOfFlowPositioned`:  Specifically mentions handling absolutely or fixed positioned elements.

3. **Identify the Core Functionality (High-Level):** Based on the keywords, the core purpose seems to be:  **Managing and querying information about "anchors" within a layout, especially in the context of fragmented content and out-of-flow positioned elements.**

4. **Break Down the Code into Key Components:**  Now, let's examine the major structures and functions:

    * **`FragmentainerContext`:** This seems to store information about a fragmentation container, including its offset and a `WritingModeConverter`. This suggests it's essential for handling different writing directions and fragmentation scenarios.

    * **`StitchedAnchorReference`:** This is a key concept. The name "stitched" implies it's combining information from fragmented pieces as if they were one continuous block. It stores the anchor's rectangle relative to the *first* fragmentainer and calculates the "stitched" rectangle. This is crucial for anchor positioning across fragments.

    * **`StitchedAnchorQuery`:** This acts as a container for `StitchedAnchorReference` objects, using `AnchorKey` (likely the anchor name or the element itself) as the key. The `GetStitchedAnchorQuery()` method suggests it converts this "stitched" representation into a more standard `LogicalAnchorQuery`. The `AddAnchorQuery` and `AddAnchorReference` methods handle populating this map, dealing with potential conflicts (e.g., multiple anchors with the same name).

    * **`StitchedAnchorQueries`:** This structure seems to manage multiple `StitchedAnchorQuery` objects, one for each containing block. It iterates through the layout tree (fragments and their children) and populates the individual `StitchedAnchorQuery` maps. The logic for handling out-of-flow elements is important here.

    * **`LogicalAnchorQueryMap`:** This is the main class exposed by the file. It holds the results of the anchor query calculations. The `AnchorQuery()` method provides access to the anchor information for a specific containing block. The `Update()` method is responsible for performing the core calculation logic using `StitchedAnchorQueries`.

5. **Connect to Web Technologies:**  Now, link the C++ concepts to HTML, CSS, and JavaScript:

    * **CSS:** The most direct connection is to the CSS anchor positioning properties (`anchor-name`, `position-anchor`, `inset-anchor`, etc.). Explain how the code relates to resolving these properties. The concepts of containing blocks and out-of-flow positioning are also critical CSS concepts.

    * **HTML:**  Mention how HTML elements are the basis for layout and how the `LayoutObject` represents these elements. Anchor names are often tied to element IDs or names.

    * **JavaScript:** While this C++ code doesn't directly interact with JS execution, explain how JS can trigger layout changes that would necessitate recalculating the anchor queries. Also, mention the possibility of JS APIs (though not explicitly shown here) that might expose or use this anchor information.

6. **Logical Inferences and Examples:**  Think about specific scenarios and how the code would handle them:

    * **Fragmentation:** Illustrate how anchors are handled when an element spans multiple columns or pages. The "stitched" concept is key here. Provide a simple HTML example.

    * **Out-of-Flow Positioning:** Explain how absolutely or fixed positioned elements acting as anchors are processed and how their containing blocks are involved. Provide an HTML/CSS example.

7. **Potential Usage Errors:** Consider common mistakes developers might make when using anchor positioning:

    * **Circular Dependencies:**  This is a classic issue with layout dependencies. Explain how an anchor might indirectly depend on its target, leading to infinite loops or incorrect layouts.

    * **Incorrect Containing Blocks:**  Emphasize the importance of understanding how containing blocks are determined, especially for absolutely positioned elements.

    * **Performance:**  Briefly mention that excessive use of complex anchor positioning could impact performance due to the calculations involved.

8. **Structure the Response:** Organize the information logically:

    * **Introduction:** Briefly state the file's purpose.
    * **Core Functionality:** Explain the main goal of the code.
    * **Detailed Explanation:** Break down the key classes and functions.
    * **Relationship to Web Technologies:**  Connect the C++ concepts to HTML, CSS, and JavaScript.
    * **Examples:** Provide concrete HTML/CSS examples to illustrate the functionality.
    * **Logical Inferences:** Describe how the code handles different layout scenarios.
    * **Potential Errors:** Highlight common pitfalls.
    * **Summary:** Briefly reiterate the key takeaways.

9. **Refine and Elaborate:**  Review the initial draft and add more detail and clarity. Ensure the language is easy to understand for someone with a general understanding of web development concepts. For instance, explicitly defining terms like "fragmentainer" is helpful.

By following these steps, we can systematically analyze the C++ code and generate a comprehensive and informative explanation that addresses all aspects of the prompt. The key is to go from a high-level understanding to a more detailed examination of the code, and then relate those technical details back to the broader context of web technologies and developer practices.
这个文件 `anchor_query_map.cc` 是 Chromium Blink 渲染引擎中的一部分，它的主要功能是**管理和维护锚点查询（Anchor Query）信息**。锚点查询是 CSS 锚点定位规范（CSS Anchor Positioning）的核心机制，允许一个元素（定位元素）相对于另一个元素（锚点元素）的位置进行定位。

更具体地说，`anchor_query_map.cc` 负责在布局过程中收集和组织页面上所有符合条件的锚点元素的信息，并为需要进行锚点定位的元素提供查询这些锚点信息的接口。  它需要处理各种复杂的布局情况，例如：

* **分片（Fragmentation）：** 当内容被分成多个片段显示时（例如，多列布局或分页），锚点和定位元素可能位于不同的片段中。
* **绝对定位和固定定位元素（Out-of-flow positioned elements）：** 这些元素的定位上下文可能与文档流中的元素不同。

下面我们详细列举一下它的功能，并解释它与 JavaScript、HTML 和 CSS 的关系：

**功能列表：**

1. **存储锚点信息：**  维护一个数据结构（`LogicalAnchorQueryMap`）来存储页面上所有可用锚点的信息。这些信息包括锚点元素的布局对象（`LayoutObject`）以及其在文档中的位置和尺寸（以逻辑坐标表示）。

2. **处理分片上下文：**  针对内容分片的情况，例如多列布局或分页容器，收集每个片段中的锚点信息，并将这些信息整合起来，使得即使锚点和定位元素在不同的片段中也能正确计算相对位置。 这通过 `StitchedAnchorReference` 和 `StitchedAnchorQuery` 来实现，它们将跨片段的锚点信息“缝合”在一起，仿佛它们位于同一个连续的容器中。

3. **处理绝对定位和固定定位元素：**  当锚点元素是绝对定位或固定定位时，需要考虑其相对于哪个包含块（containing block）进行定位。`AnchorQueryMap` 需要正确识别这些锚点元素的包含块，并将锚点信息存储在正确的上下文中。

4. **提供查询接口：**  为需要进行锚点定位的元素提供查询接口 (`AnchorQuery`)，允许它们根据锚点名称或隐式锚点关系查找相关的锚点信息。

5. **增量更新：** 当布局发生变化时，例如元素的位置或尺寸改变，`AnchorQueryMap` 需要能够高效地更新其存储的锚点信息。

**与 JavaScript, HTML, CSS 的关系举例说明：**

* **CSS:**
    * **`anchor-name` 属性：**  CSS 的 `anchor-name` 属性用于显式地为一个元素指定一个锚点名称。`AnchorQueryMap` 会解析这个属性，并将具有相同 `anchor-name` 的元素的信息存储起来，以便其他元素可以通过 `position-anchor` 属性引用它们。
        ```css
        #anchor-element {
          anchor-name: --my-anchor;
        }

        #positioned-element {
          position: absolute;
          top: anchor(--my-anchor top);
          left: anchor(--my-anchor left);
        }
        ```
        在这个例子中，`AnchorQueryMap` 会记录 `#anchor-element` 的位置和尺寸，并将其与锚点名称 `--my-anchor` 关联起来。当布局引擎处理 `#positioned-element` 的样式时，会查询 `AnchorQueryMap` 获取 `--my-anchor` 的信息，从而计算出 `#positioned-element` 的 `top` 和 `left` 值。

    * **`position-anchor` 属性：** CSS 的 `position-anchor` 属性用于指定定位元素应该相对于哪个锚点进行定位。`AnchorQueryMap` 负责查找与 `position-anchor` 中指定的锚点名称匹配的锚点信息。
    * **隐式锚点：**  如果一个元素没有显式的 `anchor-name`，它自身可以作为其后代元素的隐式锚点。`AnchorQueryMap` 也需要处理这种情况。

* **HTML:**
    * HTML 元素是 CSS 样式应用的基础。`AnchorQueryMap` 处理的是 `LayoutObject`，这些 `LayoutObject` 是 HTML 元素在渲染树中的表示。
    * HTML 结构决定了元素的包含关系和文档流，这对于确定绝对定位和固定定位元素的包含块至关重要，而 `AnchorQueryMap` 需要考虑这些包含块。

* **JavaScript:**
    * JavaScript 可以动态地修改 HTML 结构和 CSS 样式。当 JavaScript 导致页面布局发生变化（例如，添加、删除或移动元素，修改样式），Blink 渲染引擎会重新进行布局计算，这会触发 `AnchorQueryMap` 更新其存储的锚点信息。
    * 虽然这个文件本身是 C++ 代码，不直接涉及 JavaScript 执行，但 JavaScript 的行为会影响 `AnchorQueryMap` 的工作。例如，如果 JavaScript 动态地添加了一个带有 `anchor-name` 属性的元素，`AnchorQueryMap` 需要能够识别并存储这个新的锚点信息。

**逻辑推理的假设输入与输出：**

**假设输入：**

一个包含以下 HTML 结构的文档：

```html
<div id="container">
  <div id="anchor1" style="anchor-name: --first-anchor;">Anchor 1</div>
  <div id="fragment-container" style="columns: 2;">
    <div id="anchor2" style="anchor-name: --second-anchor;">Anchor 2 in column</div>
    <div id="positioned" style="position: absolute; top: anchor(--first-anchor bottom); left: anchor(--second-anchor right);">Positioned</div>
  </div>
</div>
```

**预期输出（`AnchorQueryMap` 中存储的信息）：**

* 对于 `#container` 元素，可能存储一个空的 `LogicalAnchorQuery`，因为它本身不是定位元素的直接包含块。
* 对于 `#fragment-container` 元素，它会存储一个 `LogicalAnchorQuery`，包含以下信息（简化表示）：
    * 锚点 `--first-anchor`: 指向 `#anchor1` 元素的布局对象及其在 `#container` 坐标系中的逻辑矩形。
    * 锚点 `--second-anchor`: 指向 `#anchor2` 元素的布局对象及其在 `#fragment-container` 的 **每个片段** 中的逻辑矩形。 由于 `#anchor2` 位于分片容器中，`AnchorQueryMap` 需要处理其在不同列中的位置。`StitchedAnchorReference` 会将其缝合起来。

当布局引擎处理 `#positioned` 元素时，会查询 `#fragment-container` 的 `AnchorQuery`，并能找到 `--first-anchor` 和 `--second-anchor` 的信息，从而计算出 `#positioned` 的 `top` 和 `left` 值。

**用户或编程常见的使用错误举例说明：**

1. **循环依赖：** 如果一个锚点元素的定位依赖于另一个元素，而那个元素又依赖于这个锚点元素进行定位，就会形成循环依赖。这可能导致布局无限循环或不可预测的结果。
    ```css
    #a {
      anchor-name: --anchor-a;
      top: anchor(--anchor-b bottom);
    }

    #b {
      anchor-name: --anchor-b;
      top: anchor(--anchor-a bottom);
    }
    ```
    在这种情况下，`AnchorQueryMap` 可能会尝试无限次地更新锚点信息，导致性能问题甚至崩溃。Blink 可能会采取一些措施来检测和打破这种循环。

2. **锚点名称拼写错误或不存在：** 如果在 `position-anchor` 中引用的锚点名称在文档中不存在，定位元素将无法找到对应的锚点，其定位可能会回退到默认行为（通常是相对于其包含块的左上角）。开发者可能会因为拼写错误或者忘记定义锚点而遇到这个问题。

3. **错误的包含块理解：** 对于绝对定位元素，其定位是相对于最近的定位祖先元素（`position: relative`, `absolute`, `fixed`, `sticky`）或初始包含块（viewport）。如果开发者对包含块的理解有误，即使锚点信息正确，定位元素也可能出现在错误的位置。`AnchorQueryMap` 依赖于正确的包含块信息来存储和检索锚点位置。

4. **动态更新问题：** 如果 JavaScript 动态地改变了锚点元素的位置或尺寸，但布局引擎没有及时更新 `AnchorQueryMap`，可能会导致定位元素的计算位置不正确。Blink 的布局机制通常会处理这种情况，但在某些复杂的动态场景下，可能会出现短暂的同步问题。

总而言之，`anchor_query_map.cc` 是 Blink 渲染引擎中实现 CSS 锚点定位功能的重要组成部分，它负责收集、组织和提供页面上锚点元素的信息，使得定位元素能够根据这些信息进行布局。它需要处理各种复杂的布局情况，并与 HTML、CSS 以及 JavaScript 的动态行为协同工作。

Prompt: 
```
这是目录为blink/renderer/core/layout/anchor_query_map.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/anchor_query_map.h"

#include "third_party/blink/renderer/core/layout/geometry/writing_mode_converter.h"
#include "third_party/blink/renderer/core/layout/inline/inline_cursor.h"
#include "third_party/blink/renderer/core/layout/logical_fragment_link.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"

namespace blink {

namespace {

// Represents a fragmentainer. This is in the logical coordinate system
// because the size of the fragmentation context may not have determined yet.
// In that case, physical coordinates can't be computed yet.
struct FragmentainerContext {
  STACK_ALLOCATED();

 public:
  LogicalOffset offset;
  // The block offset when all fragments are stitched in the block direction.
  // That is, the sum of block offsets of preceding fragments.
  LayoutUnit stitched_offset;
  WritingModeConverter converter;
};

// This struct is a variation of |AnchorReference|, using the stitched
// coordinate system for the block-fragmented out-of-flow positioned objects.
struct StitchedAnchorReference
    : public GarbageCollected<StitchedAnchorReference> {
  StitchedAnchorReference(const LayoutObject& layout_object,
                          const LogicalRect& rect,
                          const FragmentainerContext& fragmentainer)
      : layout_object(&layout_object),
        rect_in_first_fragmentainer(rect),
        first_fragmentainer_offset(fragmentainer.offset),
        first_fragmentainer_stitched_offset(fragmentainer.stitched_offset) {}

  LogicalRect StitchedRect() const {
    LogicalRect stitched_rect = rect_in_first_fragmentainer;
    stitched_rect.offset.block_offset += first_fragmentainer_stitched_offset;
    return stitched_rect;
  }

  LogicalAnchorReference* GetStitchedAnchorReference() const {
    DCHECK(layout_object);
    return MakeGarbageCollected<LogicalAnchorReference>(
        *layout_object, StitchedRect(), /* is_out_of_flow */ false, nullptr);
  }

  void Unite(const LogicalRect& other_rect,
             const LogicalOffset& fragmentainer_offset) {
    // To unite fragments in the physical coordinate system as defined in the
    // spec while keeping the |reference.rect| relative to the first
    // fragmentainer, make the |fragmentainer_offset| relative to the first
    // fragmentainer.
    const LogicalRect other_rect_in_first_fragmentainer =
        other_rect + (fragmentainer_offset - first_fragmentainer_offset);
    rect_in_first_fragmentainer.Unite(other_rect_in_first_fragmentainer);
  }

  void Trace(Visitor* visitor) const { visitor->Trace(layout_object); }

  Member<const LayoutObject> layout_object;
  // The |rect_in_first_fragmentainer| is relative to the first fragmentainer,
  // so that it can a) unite following fragments in the physical coordinate
  // system, and b) compute the result in the stitched coordinate system.
  LogicalRect rect_in_first_fragmentainer;
  LogicalOffset first_fragmentainer_offset;
  // The block offset when all fragments are stitched in the block direction.
  LayoutUnit first_fragmentainer_stitched_offset;
};

// This creates anchor queries in the stitched coordinate system. The result
// can be converted to a |LogicalAnchorQuery|.
struct StitchedAnchorQuery : public GarbageCollected<StitchedAnchorQuery>,
                             public AnchorQueryBase<StitchedAnchorReference> {
  using Base = AnchorQueryBase<StitchedAnchorReference>;

  // Convert |this| to a |LogicalAnchorQuery|. The result is a regular
  // |LogicalAnchorQuery| except that its coordinate system is stitched
  // (i.e., as if they weren't fragmented.)
  LogicalAnchorQuery* GetStitchedAnchorQuery() const {
    auto* anchor_query = MakeGarbageCollected<LogicalAnchorQuery>();
    for (const auto entry : *this)
      anchor_query->Set(entry.key, entry.value->GetStitchedAnchorReference());
    return anchor_query;
  }

  enum class Conflict {
    // The last entry wins. The calls must be in the tree order.
    kLastInCallOrder,
    // Overwrite existing entry if the new one is before the existing one.
    kOverwriteIfAfter,
  };

  void AddAnchorQuery(const PhysicalFragment& fragment,
                      const PhysicalOffset& offset_from_fragmentainer,
                      const FragmentainerContext& fragmentainer) {
    const PhysicalAnchorQuery* anchor_query = fragment.AnchorQuery();
    if (!anchor_query)
      return;
    for (auto entry : *anchor_query) {
      DCHECK(entry.value->layout_object);
      AddAnchorReference(entry.key, *entry.value->layout_object,
                         entry.value->rect + offset_from_fragmentainer,
                         fragmentainer, Conflict::kLastInCallOrder);
    }
  }

  void AddAnchorReference(const AnchorKey& key,
                          const LayoutObject& new_object,
                          const PhysicalRect& physical_rect_in_fragmentainer,
                          const FragmentainerContext& fragmentainer,
                          Conflict conflict) {
    const LogicalRect rect_in_fragmentainer =
        fragmentainer.converter.ToLogical(physical_rect_in_fragmentainer);
    auto* new_value = MakeGarbageCollected<StitchedAnchorReference>(
        new_object, rect_in_fragmentainer, fragmentainer);
    const auto result = Base::insert(key, new_value);
    if (result.is_new_entry)
      return;

    // If this is a fragment of the existing box, unite it with other fragments.
    StitchedAnchorReference* existing = *result.stored_value;
    const LayoutObject* existing_object = existing->layout_object;
    DCHECK(existing_object);
    if (existing_object == &new_object) {
      existing->Unite(rect_in_fragmentainer, fragmentainer.offset);
      return;
    }

    // If this is the same anchor-name on a different box, the last one in the
    // pre-order wins. Normally, the call order is in the layout-order, which is
    // pre-order of the box tree. But OOFs may be laid out later, check the tree
    // order in such case.
    switch (conflict) {
      case Conflict::kLastInCallOrder:
        DCHECK(existing_object->IsBeforeInPreOrder(new_object));
        *existing = *new_value;
        break;
      case Conflict::kOverwriteIfAfter:
        if (!new_object.IsBeforeInPreOrder(*existing_object)) {
          *existing = *new_value;
        }
        break;
    }
  }
};

// This collects |StitchedAnchorQuery| for each containing block.
struct StitchedAnchorQueries {
  STACK_ALLOCATED();

 public:
  StitchedAnchorQueries(const LayoutBox& root,
                        const HeapHashSet<Member<const LayoutObject>>&
                            anchored_oof_containers_and_ancestors)
      : anchored_oof_containers_and_ancestors_(
            anchored_oof_containers_and_ancestors),
        root_(root) {}

  void AddChildren(base::span<const LogicalFragmentLink> children,
                   const FragmentItemsBuilder::ItemWithOffsetList* items,
                   const WritingModeConverter& converter) {
    const FragmentainerContext fragmentainer{{}, {}, converter};
    if (items) {
      for (const FragmentItemsBuilder::ItemWithOffset& item_with_offset :
           *items) {
        const FragmentItem& item = item_with_offset.item;
        if (const PhysicalBoxFragment* fragment = item.BoxFragment()) {
          AddBoxChild(*fragment, item.OffsetInContainerFragment(),
                      fragmentainer);
        }
      }
    }

    for (const LogicalFragmentLink& child : children) {
      DCHECK(!child->IsFragmentainerBox());
      DCHECK(!child->IsColumnSpanAll());
      const PhysicalOffset child_offset =
          converter.ToPhysical(child.offset, child->Size());
      AddChild(*child, child_offset, fragmentainer);
    }
  }

  void AddFragmentainerChildren(base::span<const LogicalFragmentLink> children,
                                WritingDirectionMode writing_direction) {
    LayoutUnit fragmentainer_stitched_offset;
    for (const LogicalFragmentLink& child : children) {
      if (child->IsFragmentainerBox()) {
        const FragmentainerContext fragmentainer{
            child.offset,
            fragmentainer_stitched_offset,
            {writing_direction, child->Size()}};
        AddChild(*child, /* offset_from_fragmentainer */ {}, fragmentainer);
        fragmentainer_stitched_offset +=
            child->Size()
                .ConvertToLogical(writing_direction.GetWritingMode())
                .block_size;
        continue;
      }

      // The containing block of the spanner is the multicol container itself.
      // https://drafts.csswg.org/css-multicol/#column-span
      // So anchor queries in column spanners should not be added to any
      // containing blocks in the multicol.
      DCHECK(child->IsColumnSpanAll());
    }
  }

  void AddChild(const PhysicalFragment& fragment,
                const PhysicalOffset& offset_from_fragmentainer,
                const FragmentainerContext& fragmentainer) {
    if (const auto* box = DynamicTo<PhysicalBoxFragment>(&fragment)) {
      AddBoxChild(*box, offset_from_fragmentainer, fragmentainer);
    }
  }

  void AddBoxChild(const PhysicalBoxFragment& fragment,
                   const PhysicalOffset& offset_from_fragmentainer,
                   const FragmentainerContext& fragmentainer) {
    if (fragment.IsOutOfFlowPositioned()) {
      AddOutOfFlowChild(fragment, offset_from_fragmentainer, fragmentainer);
      return;
    }

    // Return early if the |fragment| doesn't have any anchors. No need to
    // traverse descendants.
    const PhysicalAnchorQuery* anchor_query = fragment.AnchorQuery();
    if (!anchor_query)
      return;

    // Create |StitchedAnchorQuery| if this is a containing block.
    if (const LayoutObject* layout_object = fragment.GetLayoutObject()) {
      if (!anchored_oof_containers_and_ancestors_.Contains(layout_object))
        return;
      if (layout_object->CanContainAbsolutePositionObjects() ||
          layout_object->CanContainFixedPositionObjects()) {
        EnsureStitchedAnchorQuery(*layout_object)
            .AddAnchorQuery(fragment, offset_from_fragmentainer, fragmentainer);
      }
    }

    if (fragment.IsFragmentationContextRoot()) {
      AddFragmentationContextRootChild(fragment, offset_from_fragmentainer,
                                       fragmentainer);
      return;
    }

    // Add inline children if any.
    if (const FragmentItems* items = fragment.Items()) {
      for (InlineCursor cursor(fragment, *items); cursor; cursor.MoveToNext()) {
        if (cursor.Current().IsInlineBox()) {
          DCHECK(cursor.Current().BoxFragment());
          AddBoxChild(*cursor.Current().BoxFragment(),
                      offset_from_fragmentainer +
                          cursor.Current()->OffsetInContainerFragment(),
                      fragmentainer);
        }
      }
    }

    // Add block children if any.
    for (const PhysicalFragmentLink& child : fragment.Children()) {
      DCHECK(!child->IsFragmentainerBox());
      const auto child_offset_from_fragmentainer =
          offset_from_fragmentainer + child.offset;
      AddChild(*child, child_offset_from_fragmentainer, fragmentainer);
    }
  }

  void AddFragmentationContextRootChild(
      const PhysicalBoxFragment& fragment,
      const PhysicalOffset& offset_from_fragmentainer,
      const FragmentainerContext& fragmentainer) {
    DCHECK(fragment.IsFragmentationContextRoot());
    DCHECK(!fragment.Items());
    HeapVector<LogicalFragmentLink> children;
    for (const PhysicalFragmentLink& child : fragment.Children()) {
      const LogicalOffset child_offset =
          fragmentainer.converter.ToLogical(
              offset_from_fragmentainer + child.offset, child->Size()) +
          fragmentainer.offset;
      children.push_back(LogicalFragmentLink{child.fragment, child_offset});
    }
    AddFragmentainerChildren(children,
                             fragmentainer.converter.GetWritingDirection());
  }

  void AddOutOfFlowChild(const PhysicalBoxFragment& fragment,
                         const PhysicalOffset& offset_from_fragmentainer,
                         const FragmentainerContext& fragmentainer) {
    DCHECK(fragment.IsOutOfFlowPositioned());
    if (!fragment.Style().AnchorName() && !fragment.IsImplicitAnchor() &&
        !fragment.AnchorQuery()) {
      return;
    }
    // OOF fragments in block-fragmentation context are children of the
    // fragmentainers, but they should be added to anchor queries of their
    // containing block chain. Traverse the containing block chain and add
    // references to all |LayoutObject|, up to the |root_|.
    const LayoutObject* layout_object = fragment.GetLayoutObject();
    DCHECK(layout_object);
    LayoutObject::AncestorSkipInfo skip_info(&root_);
    const LayoutObject* containing_block = layout_object->Container(&skip_info);
    // If the OOF is to be laid out in the fragmentation context, its containing
    // block should be a descendant of the |root_|.
    DCHECK(containing_block);
    DCHECK_NE(containing_block, &root_);
    DCHECK(!skip_info.AncestorSkipped());
    // Skip the first containing block, because the spec defines "If el has the
    // same containing block as query el, el is not absolutely positioned." That
    // said, for absolutely positioned anchors should be invalid for the first
    // containing block.
    // https://drafts.csswg.org/css-anchor-1/#determining
    containing_block = containing_block->Container(&skip_info);
    while (containing_block && containing_block != root_ &&
           !skip_info.AncestorSkipped()) {
      StitchedAnchorQuery& query = EnsureStitchedAnchorQuery(*containing_block);
      if (fragment.Style().AnchorName()) {
        for (const ScopedCSSName* name :
             fragment.Style().AnchorName()->GetNames()) {
          query.AddAnchorReference(
              name, *fragment.GetLayoutObject(),
              {offset_from_fragmentainer, fragment.Size()}, fragmentainer,
              StitchedAnchorQuery::Conflict::kOverwriteIfAfter);
        }
      }
      if (fragment.IsImplicitAnchor()) {
        query.AddAnchorReference(
            layout_object, *fragment.GetLayoutObject(),
            {offset_from_fragmentainer, fragment.Size()}, fragmentainer,
            StitchedAnchorQuery::Conflict::kOverwriteIfAfter);
      }
      query.AddAnchorQuery(fragment, offset_from_fragmentainer, fragmentainer);
      containing_block = containing_block->Container(&skip_info);
    }
  }

  StitchedAnchorQuery& EnsureStitchedAnchorQuery(
      const LayoutObject& containing_block) {
    const auto result = anchor_queries_.insert(
        &containing_block, MakeGarbageCollected<StitchedAnchorQuery>());
    DCHECK(result.stored_value->value);
    return *result.stored_value->value;
  }

  HeapHashMap<Member<const LayoutObject>, Member<StitchedAnchorQuery>>
      anchor_queries_;
  // The set of |LayoutObject| to traverse. When adding children, children not
  // in this set are skipped.
  const HeapHashSet<Member<const LayoutObject>>&
      anchored_oof_containers_and_ancestors_;
  const LayoutBox& root_;
};

}  // namespace

LogicalAnchorQueryMap::LogicalAnchorQueryMap(
    const LayoutBox& root_box,
    const LogicalFragmentLinkVector& children,
    WritingDirectionMode writing_direction)
    : root_box_(root_box), writing_direction_(writing_direction) {
  DCHECK(&root_box);
  SetChildren(children);
}

void LogicalAnchorQueryMap::SetChildren(
    const LogicalFragmentLinkVector& children) {
  children_ = &children;

  // Invalidate the cache when children may have changed.
  computed_for_ = nullptr;

  // To allow early returns, check if any child has anchor queries.
  has_anchor_queries_ = false;
  for (const LogicalFragmentLink& child : children) {
    if (child->HasAnchorQuery()) {
      has_anchor_queries_ = true;
      break;
    }
  }
}

const LogicalAnchorQuery& LogicalAnchorQueryMap::AnchorQuery(
    const LayoutObject& containing_block) const {
  DCHECK(&containing_block);
  DCHECK(containing_block.CanContainAbsolutePositionObjects() ||
         containing_block.CanContainFixedPositionObjects());

  if (!has_anchor_queries_)
    return LogicalAnchorQuery::Empty();

  // Update |queries_| if it hasn't computed for |containing_block|.
  if (!computed_for_ || !computed_for_->IsDescendantOf(&containing_block))
    Update(containing_block);

  const auto& it = queries_.find(&containing_block);
  if (it != queries_.end())
    return *it->value;
  return LogicalAnchorQuery::Empty();
}

// Update |queries_| for the given |layout_object| and its ancestors. This is
// `const`, modifies `mutable` caches only, so that other `const` functions such
// as |AnchorQuery| can call.
void LogicalAnchorQueryMap::Update(const LayoutObject& layout_object) const {
  // Compute descendants to collect anchor queries from. This helps reducing the
  // number of descendants to traverse.
  HeapHashSet<Member<const LayoutObject>> anchored_oof_containers_and_ancestors;
  for (const LayoutObject* runner = &layout_object;
       runner && runner != &root_box_; runner = runner->Parent()) {
    const auto result = anchored_oof_containers_and_ancestors.insert(runner);
    if (!result.is_new_entry)
      break;
  }

  // Traverse descendants and collect anchor queries for each containing block.
  StitchedAnchorQueries stitched_anchor_queries(
      root_box_, anchored_oof_containers_and_ancestors);
  if (converter_) {
    stitched_anchor_queries.AddChildren(*children_, items_, *converter_);
  } else {
    stitched_anchor_queries.AddFragmentainerChildren(*children_,
                                                     writing_direction_);
  }

  // TODO(kojii): Currently this clears and rebuilds all anchor queries on
  // incremental updates. It may be possible to reduce the computation when
  // there are previous results.
  queries_.clear();
  for (const auto& it : stitched_anchor_queries.anchor_queries_) {
    const auto result =
        queries_.insert(it.key, it.value->GetStitchedAnchorQuery());
    DCHECK(result.is_new_entry);
  }

  computed_for_ = &layout_object;
}

}  // namespace blink

"""

```