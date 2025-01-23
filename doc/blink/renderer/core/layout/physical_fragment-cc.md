Response:
My goal is to understand the functionality of the provided C++ code snippet for `physical_fragment.cc` in the Chromium Blink engine and then summarize it in the context of web technologies (JavaScript, HTML, CSS). Here's a breakdown of my thought process:

1. **Identify the Core Purpose:** The file name "physical_fragment.cc" and the inclusion of headers like `physical_box_fragment.h`, `inline_node.h`, `layout_block.h`, etc., strongly suggest this code deals with the *visual representation* of elements on a web page. The term "fragment" likely refers to a piece of this visual representation.

2. **Examine Key Data Structures:**  I scanned the code for important classes and structs:
    * `PhysicalFragment`: This is the central class. Its member variables (`size_`, `type_`, `layout_object_`, `oof_data_`, `break_token_`, etc.) hint at its role in storing geometry, type information, associated layout objects, out-of-flow data, and breaking information.
    * `PhysicalBoxFragment`, `PhysicalLineBoxFragment`: These derived classes likely represent fragments of block-level and inline-level elements respectively.
    * `FragmentBuilder`:  This class seems to be responsible for constructing `PhysicalFragment` instances.
    * `FragmentTreeDumper`: This class is clearly for debugging and visualization, dumping the structure of the fragment tree.
    * `OofData`, `FragmentedOofData`: These likely manage information related to out-of-flow positioned elements.

3. **Analyze Key Functions:** I looked for functions that reveal the core operations:
    * Constructors of `PhysicalFragment`: They take a `FragmentBuilder`, indicating the construction process.
    * `IsBlockFlow()`, `IsLineBox()`, `IsOutOfFlowPositioned()`, etc.: These are type-checking methods, confirming the role of `PhysicalFragment` in classifying visual elements.
    * `OutOfFlowPositionedDescendants()`, `GetFragmentedOofData()`:  These accessors provide information about out-of-flow elements.
    * `DumpFragmentTree()`: This confirms the debugging/visualization purpose.
    * `ConvertChildToLogical()`: This suggests coordinate system transformations, crucial for layout.
    * `AddOutlineRectsForNormalChildren()`: This hints at the process of drawing outlines around elements.

4. **Connect to Web Technologies:** Now I started to bridge the gap between the C++ code and web concepts:
    * **HTML:**  The code deals with the visual representation of HTML elements. A `<div>` would likely correspond to a `PhysicalBoxFragment`, and inline elements like `<span>` might also have corresponding fragments.
    * **CSS:** CSS properties heavily influence the creation and positioning of these fragments. `position: absolute`, `float`, `display: inline`, `width`, `height`, etc., all play a role in determining the `type_`, `size_`, and `offset` of `PhysicalFragment`s. The `FragmentBuilder` likely uses computed styles.
    * **JavaScript:** While this C++ code doesn't directly *execute* JavaScript, it's part of the rendering engine that *implements* the visual effects of JavaScript manipulations of the DOM and CSS. For example, if JavaScript changes an element's `display` property, the layout engine (including this code) would rebuild the fragment tree accordingly.

5. **Consider Edge Cases and Errors:** I looked for parts of the code that might handle special situations or potential issues:
    * The `DEAD LAYOUT OBJECT!` message in `FragmentTreeDumper` suggests a mechanism for handling situations where the underlying layout object is no longer valid.
    * The code dealing with out-of-flow positioned elements (`OofData`) addresses the complexities of absolute and fixed positioning.

6. **Formulate Examples and Explanations:** Based on the above analysis, I started constructing explanations and examples:
    * **Functionality:** I listed the key responsibilities of the code, such as representing visual elements, managing geometry, handling out-of-flow elements, and providing debugging tools.
    * **Relationships with Web Tech:**  I gave specific examples of how HTML, CSS, and JavaScript relate to `PhysicalFragment`. For instance, the connection between CSS `display` values and the `BoxType` enum.
    * **Logical Reasoning:** I created simple scenarios (e.g., a `<div>` with specific CSS) and described how the code might represent it.
    * **Common Errors:** I considered potential developer mistakes that this code might implicitly handle or expose, such as manipulating styles in ways that lead to invalid layouts.

7. **Structure the Summary:** Finally, I organized my findings into a clear and concise summary, addressing the specific prompts in the request (functionality, relationship with web technologies, logical reasoning, common errors). I made sure to explicitly state that this was the *first part* of the analysis and focused on a high-level overview.

**Self-Correction/Refinement during the process:**

* Initially, I might have focused too much on the low-level details of the C++ syntax. I then shifted to understanding the *purpose* and how it connects to the bigger picture of web rendering.
* I considered different interpretations of "fragment."  Realized it's not about file fragments but rather visual fragments of elements.
* I made sure to connect the code to specific CSS properties and HTML elements to make the explanation more concrete.
* I recognized the importance of the `FragmentTreeDumper` for debugging and included it in the functionality summary.

By following this systematic approach of analyzing the code structure, key functions, and then relating it back to core web technologies, I was able to arrive at a comprehensive understanding and generate the summary.
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"

#include "base/ranges/algorithm.h"
#include "third_party/blink/renderer/core/dom/document_lifecycle.h"
#include "third_party/blink/renderer/core/html/shadow/shadow_element_utils.h"
#include "third_party/blink/renderer/core/layout/block_node.h"
#include "third_party/blink/renderer/core/layout/fragment_builder.h"
#include "third_party/blink/renderer/core/layout/geometry/box_strut.h"
#include "third_party/blink/renderer/core/layout/geometry/writing_mode_converter.h"
#include "third_party/blink/renderer/core/layout/inline/inline_cursor.h"
#include "third_party/blink/renderer/core/layout/inline/inline_node.h"
#include "third_party/blink/renderer/core/layout/inline/physical_line_box_fragment.h"
#include "third_party/blink/renderer/core/layout/inline/ruby_utils.h"
#include "third_party/blink/renderer/core/layout/layout_block.h"
#include "third_party/blink/renderer/core/layout/layout_text_combine.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"
#include "third_party/blink/renderer/core/layout/scrollable_overflow_calculator.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/platform/fonts/shaping/shape_result_view.h"
#include "third_party/blink/renderer/platform/wtf/size_assertions.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

namespace blink {
namespace {

struct SameSizeAsPhysicalFragment
    : public GarbageCollected<SameSizeAsPhysicalFragment> {
  Member<void*> layout_object;
  PhysicalSize size;
  uint8_t flags[4];
  Member<void*> members[3];
};

ASSERT_SIZE(PhysicalFragment, SameSizeAsPhysicalFragment);

String StringForBoxType(const PhysicalFragment& fragment) {
  StringBuilder result;
  switch (fragment.GetBoxType()) {
    case PhysicalFragment::BoxType::kNormalBox:
      break;
    case PhysicalFragment::BoxType::kInlineBox:
      result.Append("inline");
      break;
    case PhysicalFragment::BoxType::kColumnBox:
      result.Append("column");
      break;
    case PhysicalFragment::BoxType::kPageContainer:
      result.Append("page container");
      break;
    case PhysicalFragment::BoxType::kPageBorderBox:
      result.Append("page border box");
      break;
    case PhysicalFragment::BoxType::kPageMargin:
      result.Append("page margin");
      break;
    case PhysicalFragment::BoxType::kPageArea:
      result.Append("page area");
      break;
    case PhysicalFragment::BoxType::kAtomicInline:
      result.Append("atomic-inline");
      break;
    case PhysicalFragment::BoxType::kFloating:
      result.Append("floating");
      break;
    case PhysicalFragment::BoxType::kOutOfFlowPositioned:
      result.Append("out-of-flow-positioned");
      break;
    case PhysicalFragment::BoxType::kBlockFlowRoot:
      result.Append("block-flow-root");
      break;
    case PhysicalFragment::BoxType::kRenderedLegend:
      result.Append("rendered-legend");
      break;
  }
  if (fragment.IsBlockFlow()) {
    if (result.length())
      result.Append(" ");
    result.Append("block-flow");
  }
  if (fragment.IsFieldsetContainer()) {
    if (result.length())
      result.Append(" ");
    result.Append("fieldset-container");
  }
  if (fragment.IsBox() &&
      To<PhysicalBoxFragment>(fragment).IsInlineFormattingContext()) {
    if (result.length())
      result.Append(" ");
    result.Append("children-inline");
  }

  return result.ToString();
}

class FragmentTreeDumper {
  STACK_ALLOCATED();

 public:
  FragmentTreeDumper(StringBuilder* builder,
                     PhysicalFragment::DumpFlags flags,
                     const PhysicalFragment* target = nullptr)
      : builder_(builder), target_fragment_(target), flags_(flags) {}

  void Append(const PhysicalFragment* fragment,
              std::optional<PhysicalOffset> fragment_offset,
              unsigned indent = 2) {
    Vector<String> attributes;
    Append(fragment, fragment_offset, attributes, indent);
  }

  void Append(const PhysicalFragment* fragment,
              std::optional<PhysicalOffset> fragment_offset,
              Vector<String>& attributes,
              unsigned indent = 2) {
    AppendIndentation(indent, fragment);

    bool has_content = false;
    if (const auto* box = DynamicTo<PhysicalBoxFragment>(fragment)) {
      if (box->IsLayoutObjectDestroyedOrMoved()) {
        builder_->Append("DEAD LAYOUT OBJECT!\n");
        return;
      }
      const LayoutObject* layout_object = box->GetLayoutObject();
      if (flags_ & PhysicalFragment::DumpType) {
        builder_->Append("Box");
        String box_type = StringForBoxType(*fragment);
        has_content = true;
        if (!box_type.empty()) {
          attributes.push_back(box_type);
        }
        if (flags_ & PhysicalFragment::DumpSelfPainting &&
            box->HasSelfPaintingLayer()) {
          attributes.push_back("self paint");
        }
      }
      AppendAttributes(attributes);
      has_content = AppendOffsetAndSize(fragment, fragment_offset, has_content);

      if (flags_ & PhysicalFragment::DumpNodeName && layout_object) {
        if (has_content)
          builder_->Append(" ");
        builder_->Append(layout_object->DebugName());
      }
      builder_->Append("\n");

      bool has_fragment_items = false;
      if (flags_ & PhysicalFragment::DumpItems) {
        if (const FragmentItems* fragment_items = box->Items()) {
          InlineCursor cursor(*box, *fragment_items);
          Append(&cursor, indent + 2);
          has_fragment_items = true;
        }
      }
      if (flags_ & PhysicalFragment::DumpSubtree) {
        if (flags_ & PhysicalFragment::DumpLegacyDescendants && layout_object &&
            !layout_object->IsLayoutNGObject() && box->Children().empty()) {
          AppendLegacySubtree(*layout_object, indent);
          return;
        }
        for (auto& child : box->Children()) {
          if (has_fragment_items && child->IsLineBox())
            continue;
          Append(child.get(), child.Offset(), indent + 2);
        }
      }
      return;
    }

    if (const auto* line_box = DynamicTo<PhysicalLineBoxFragment>(fragment)) {
      if (flags_ & PhysicalFragment::DumpType) {
        builder_->Append("LineBox");
        has_content = true;
      }
      has_content = AppendOffsetAndSize(fragment, fragment_offset, has_content);
      builder_->Append("\n");

      if (flags_ & PhysicalFragment::DumpSubtree) {
        for (auto& child : line_box->Children()) {
          Append(child.get(), child.Offset(), indent + 2);
        }
        return;
      }
    }

    if (flags_ & PhysicalFragment::DumpType) {
      builder_->Append("Unknown fragment type");
      has_content = true;
    }
    has_content = AppendOffsetAndSize(fragment, fragment_offset, has_content);
    builder_->Append("\n");
  }

  void AppendAttributes(const Vector<String>& attributes) {
    if (!attributes.empty()) {
      String separator = " (";
      for (const String& attribute : attributes) {
        builder_->Append(separator);
        builder_->Append(attribute);
        separator = ")(";
      }
      builder_->Append(")");
    }
  }

  void AppendLegacySubtree(const LayoutObject& layout_object, unsigned indent) {
    for (const LayoutObject* descendant = &layout_object; descendant;) {
      if (!IsNGRootWithFragments(*descendant)) {
        if (descendant->IsOutOfFlowPositioned() && descendant != &layout_object)
          descendant = descendant->NextInPreOrderAfterChildren(&layout_object);
        else
          descendant = descendant->NextInPreOrder(&layout_object);
        continue;
      }
      AppendNGRootInLegacySubtree(*descendant, indent);
      descendant = descendant->NextInPreOrderAfterChildren(&layout_object);
    }
  }

  void AppendLegacySubtree(const LayoutObject& layout_object) {
    AppendLegacySubtree(layout_object, 0);
    if (target_fragment_ && !target_fragment_found_) {
      if (flags_ & PhysicalFragment::DumpHeaderText) {
        builder_->Append("(Fragment not found when searching the subtree)\n");
        builder_->Append("(Dumping detached fragment tree now:)\n");
      }
      Append(target_fragment_, std::nullopt);
    }
  }

  void AppendNGRootInLegacySubtree(const LayoutObject& layout_object,
                                   unsigned indent) {
    DCHECK(IsNGRootWithFragments(layout_object));
    if (flags_ & PhysicalFragment::DumpHeaderText) {
      AppendIndentation(indent + 2);
      builder_->Append(
          "(NG fragment root inside fragment-less or legacy subtree:)\n");
    }
    const LayoutBox& box_descendant = To<LayoutBox>(layout_object);
    DCHECK_EQ(box_descendant.PhysicalFragmentCount(), 1u);
    Append(box_descendant.GetPhysicalFragment(0), std::nullopt, indent + 4);
  }

 private:
  void Append(InlineCursor* cursor, unsigned indent) {
    for (; *cursor; cursor->MoveToNextSkippingChildren()) {
      const InlineCursorPosition& current = cursor->Current();
      const PhysicalFragment* box = current.BoxFragment();
      if (box && !box->IsInlineBox()) {
        Vector<String> attributes;
        if (current->IsHiddenForPaint()) {
          attributes.push_back("hidden");
        }
        Append(box, current.OffsetInContainerFragment(), attributes, indent);
        continue;
      }

      if (!box)
        box = current.Item()->LineBoxFragment();
      AppendIndentation(indent, box);

      if (current.Item()->IsLayoutObjectDestroyedOrMoved()) {
        builder_->Append("DEAD LAYOUT OBJECT!\n");
        return;
      }

      // TODO(kojii): Use the same format as layout tree dump for now. We can
      // make this more similar to |AppendFragmentToString| above.
      builder_->Append(current->ToString());

      if (flags_ & PhysicalFragment::DumpOffset) {
        builder_->Append(" offset:");
        builder_->Append(current.OffsetInContainerFragment().ToString());
      }
      if (flags_ & PhysicalFragment::DumpSize) {
        builder_->Append(" size:");
        builder_->Append(current.Size().ToString());
      }

      builder_->Append("\n");

      if (flags_ & PhysicalFragment::DumpSubtree && current.HasChildren()) {
        InlineCursor descendants = cursor->CursorForDescendants();
        Append(&descendants, indent + 2);
      }
    }
  }

  bool AppendOffsetAndSize(const PhysicalFragment* fragment,
                           std::optional<PhysicalOffset> fragment_offset,
                           bool has_content) {
    if (flags_ & PhysicalFragment::DumpOffset) {
      if (has_content)
        builder_->Append(" ");
      builder_->Append("offset:");
      if (fragment_offset)
        builder_->Append(fragment_offset->ToString());
      else
        builder_->Append("unplaced");
      has_content = true;
    }
    if (flags_ & PhysicalFragment::DumpSize) {
      if (has_content)
        builder_->Append(" ");
      builder_->Append("size:");
      builder_->Append(fragment->Size().ToString());
      has_content = true;
    }
    return has_content;
  }

  void AppendIndentation(unsigned indent,
                         const PhysicalFragment* fragment = nullptr) {
    if (flags_ & PhysicalFragment::DumpIndentation) {
      unsigned start_idx = 0;
      if (fragment && fragment == target_fragment_) {
        builder_->Append("*");
        start_idx = 1;
        target_fragment_found_ = true;
      }
      for (unsigned i = start_idx; i < indent; i++)
        builder_->Append(" ");
    }
  }

  // Check if the object is an NG root ready to be traversed. If layout of the
  // object hasn't finished yet, there'll be no fragment, and false will be
  // returned.
  bool IsNGRootWithFragments(const LayoutObject& object) const {
    if (!object.IsLayoutNGObject())
      return false;
    const LayoutBox* box = DynamicTo<LayoutBox>(&object);
    if (!box)
      return false;
    // A root should only have at most one fragment, or zero if it hasn't been
    // laid out yet.
    DCHECK_LE(box->PhysicalFragmentCount(), 1u);
    return box->PhysicalFragmentCount();
  }

  StringBuilder* builder_;
  const PhysicalFragment* target_fragment_ = nullptr;
  PhysicalFragment::DumpFlags flags_;
  bool target_fragment_found_ = false;
};

OofContainingBlock<PhysicalOffset> PhysicalContainingBlock(
    FragmentBuilder* builder,
    PhysicalSize outer_size,
    PhysicalSize inner_size,
    const OofContainingBlock<LogicalOffset>& containing_block) {
  return OofContainingBlock<PhysicalOffset>(
      containing_block.Offset().ConvertToPhysical(
          builder->Style().GetWritingDirection(), outer_size, inner_size),
      RelativeInsetToPhysical(containing_block.RelativeOffset(),
                              builder->Style().GetWritingDirection()),
      containing_block.Fragment(),
      containing_block.ClippedContainerBlockOffset(),
      containing_block.IsInsideColumnSpanner());
}

OofContainingBlock<PhysicalOffset> PhysicalContainingBlock(
    FragmentBuilder* builder,
    PhysicalSize size,
    const OofContainingBlock<LogicalOffset>& containing_block) {
  PhysicalSize containing_block_size =
      containing_block.Fragment() ? containing_block.Fragment()->Size() : size;
  return PhysicalContainingBlock(builder, size, containing_block_size,
                                 containing_block);
}

}  // namespace

PhysicalFragment::PhysicalFragment(FragmentBuilder* builder,
                                   WritingMode block_or_line_writing_mode,
                                   FragmentType type,
                                   unsigned sub_type)
    : layout_object_(builder->layout_object_),
      size_(ToPhysicalSize(builder->size_, builder->GetWritingMode())),
      type_(type),
      sub_type_(sub_type),
      style_variant_((unsigned)builder->style_variant_),
      is_hidden_for_paint_(builder->is_hidden_for_paint_),
      has_floating_descendants_for_paint_(false),
      children_valid_(true),
      is_opaque_(builder->is_opaque_),
      is_block_in_inline_(builder->is_block_in_inline_),
      is_line_for_parallel_flow_(builder->is_line_for_parallel_flow_),
      may_have_descendant_above_block_start_(
          builder->may_have_descendant_above_block_start_),
      is_fieldset_container_(false),
      is_table_part_(false),
      is_painted_atomically_(false),
      has_collapsed_borders_(builder->has_collapsed_borders_),
      has_first_baseline_(false),
      has_last_baseline_(false),
      use_last_baseline_for_inline_baseline_(false),
      has_fragmented_out_of_flow_data_(
          !builder->oof_positioned_fragmentainer_descendants_.empty() ||
          !builder->multicols_with_pending_oofs_.empty()),
      has_out_of_flow_fragment_child_(builder->HasOutOfFlowFragmentChild()),
      has_out_of_flow_in_fragmentainer_subtree_(
          builder->HasOutOfFlowInFragmentainerSubtree()),
      propagated_data_((builder->sticky_descendants_ || builder->snap_areas_ ||
                        builder->scroll_start_target_)
                           ? MakeGarbageCollected<PropagatedData>(
                                 builder->sticky_descendants_,
                                 builder->snap_areas_,
                                 builder->scroll_start_target_)
                           : nullptr),
      break_token_(std::move(builder->break_token_)),
      oof_data_(builder->oof_positioned_descendants_.empty() &&
                        !builder->AnchorQuery() &&
                        !has_fragmented_out_of_flow_data_
                    ? nullptr
                    : OofDataFromBuilder(builder)) {
  CHECK(builder->layout_object_);

  // A line with a float / block in a parallel flow should not have an outgoing
  // break token associated. An outgoing inline break token from a line means
  // that it is to be resumed in the main flow of the container.
  DCHECK(!is_line_for_parallel_flow_ || !break_token_);

  has_floating_descendants_for_paint_ =
      builder->has_floating_descendants_for_paint_;
  has_adjoining_object_descendants_ =
      builder->has_adjoining_object_descendants_;
  depends_on_percentage_block_size_ = DependsOnPercentageBlockSize(*builder);
  children_valid_ = true;
}

// Even though the other constructors don't initialize many of these fields
// (instead set by their super-classes), the copy constructor does.
PhysicalFragment::PhysicalFragment(const PhysicalFragment& other)
    : layout_object_(other.layout_object_),
      size_(other.size_),
      type_(other.type_),
      sub_type_(other.sub_type_),
      style_variant_(other.style_variant_),
      is_hidden_for_paint_(other.is_hidden_for_paint_),
      has_floating_descendants_for_paint_(
          other.has_floating_descendants_for_paint_),
      has_adjoining_object_descendants_(
          other.has_adjoining_object_descendants_),
      depends_on_percentage_block_size_(
          other.depends_on_percentage_block_size_),
      children_valid_(other.children_valid_),
      has_propagated_descendants_(other.has_propagated_descendants_),
      has_hanging_(other.has_hanging_),
      is_opaque_(other.is_opaque_),
      is_block_in_inline_(other.is_block_in_inline_),
      is_line_for_parallel_flow_(other.is_line_for_parallel_flow_),
      is_math_fraction_(other.is_math_fraction_),
      is_math_operator_(other.is_math_operator_),
      may_have_descendant_above_block_start_(
          other.may_have_descendant_above_block_start_),
      is_fieldset_container_(other.is_fieldset_container_),
      is_table_part_(other.is_table_part_),
      is_painted_atomically_(other.is_painted_atomically_),
      has_collapsed_borders_(other.has_collapsed_borders_),
      has_first_baseline_(other.has_first_baseline_),
      has_last_baseline_(other.has_last_baseline_),
      use_last_baseline_for_inline_baseline_(
          other.use_last_baseline_for_inline_baseline_),
      has_fragmented_out_of_flow_data_(other.has_fragmented_out_of_flow_data_),
      has_out_of_flow_fragment_child_(other.has_out_of_flow_fragment_child_),
      has_out_of_flow_in_fragmentainer_subtree_(
          other.has_out_of_flow_in_fragmentainer_subtree_),
      base_direction_(other.base_direction_),
      propagated_data_(other.propagated_data_),
      break_token_(other.break_token_),
      oof_data_(other.oof_data_ ? other.CloneOofData() : nullptr) {
  CHECK(layout_object_);
  DCHECK(other.children_valid_);
  DCHECK(children_valid_);
}

bool PhysicalFragment::IsBlockFlow() const {
  return !IsLineBox() && layout_object_->IsLayoutBlockFlow();
}

bool PhysicalFragment::IsTextControlContainer() const {
  return IsCSSBox() && blink::IsTextControlContainer(layout_object_->GetNode());
}

bool PhysicalFragment::IsTextControlPlaceholder() const {
  return IsCSSBox() &&
         blink::IsTextControlPlaceholder(layout_object_->GetNode());
}

base::span<PhysicalOofPositionedNode>
PhysicalFragment::OutOfFlowPositionedDescendants() const {
  if (!HasOutOfFlowPositionedDescendants())
    return base::span<PhysicalOofPositionedNode>();
  return {oof_data_->OofPositionedDescendants().data(),
          oof_data_->OofPositionedDescendants().size()};
}

const FragmentedOofData* PhysicalFragment::GetFragmentedOofData() const {
  if (!has_fragmented_out_of_flow_data_)
    return nullptr;
  auto* oof_data = reinterpret_cast<FragmentedOofData*>(oof_data_.Get());
  DCHECK(!oof_data->multicols_with_pending_oofs.empty() ||
         !oof_data->oof_positioned_fragmentainer_descendants.empty());
  return oof_data;
}

bool PhysicalFragment::HasNestedMulticolsWithOOFs() const {
  const auto* oof_data = GetFragmentedOofData();
  return oof_data && !oof_data->multicols_with_pending_oofs.empty();
}

bool PhysicalFragment::NeedsOOFPositionedInfoPropagation() const {
  // If we have |oof_data_|, it should mean at least one of OOF propagation data
  // exists.
  DCHECK_EQ(!!oof_data_,
            HasOutOfFlowPositionedDescendants() || HasAnchorQuery() ||
                (GetFragmentedOofData() &&
                 GetFragmentedOofData()->NeedsOOFPositionedInfoPropagation()));
  return !!oof_data_;
}

PhysicalFragment::OofData* PhysicalFragment::OofDataFromBuilder(
    FragmentBuilder* builder) {
  OofData* oof_data = nullptr;
  if (has_fragmented_out_of_flow_data_) {
    oof_data = FragmentedOofDataFromBuilder(builder);
  }

  const WritingModeConverter converter(
      {builder->Style().GetWritingMode(), builder->Direction()}, Size());

  if (!builder->oof_positioned_descendants_.empty()) {
    if (!oof_data) {
      oof_data = MakeGarbageCollected<OofData>();
    }
    oof_data->OofPositionedDescendants().reserve(
        builder->oof_positioned_descendants_.size());
    for (const auto& descendant : builder->oof_positioned_descendants_) {
      OofInlineContainer<PhysicalOffset> inline_container(
          descendant.inline_container.container,
          converter.ToPhysical(descendant.inline_container.relative_offset,
                               PhysicalSize()));
      oof_data->OofPositionedDescendants().emplace_back(
          descendant.Node(),
          descendant.static_position.ConvertToPhysical(converter),
          descendant.requires_content_before_breaking,
          descendant.is_hidden_for_paint, inline_container);
    }
  }

  if (const LogicalAnchorQuery* anchor_query = builder->AnchorQuery()) {
    if (!oof_data) {
      oof_data = MakeGarbageCollected<OofData>();
    }
    oof_data->AnchorQuery().SetFromLogical(*anchor_query, converter);
  }

  return oof_data;
}

PhysicalFragment::OofData* PhysicalFragment::FragmentedOofDataFromBuilder(
    FragmentBuilder* builder) {
  DCHECK(has_fragmented_out_of_flow_data_);
  DCHECK_EQ(has_fragmented_out_of_flow_data_,
            !builder->oof_positioned_fragmentainer_descendants_.empty() ||
                !builder->multicols_with_pending_oofs_.empty());
  auto* fragmented_data = MakeGarbageCollected<FragmentedOofData>();
  fragmented_data->oof_positioned_fragmentainer_descendants.reserve(
      builder->oof_positioned_fragmentainer_descendants_.size());
  const PhysicalSize& size = Size();
  WritingDirectionMode writing_direction = builder->GetWritingDirection();
  const WritingModeConverter converter(writing_direction, size);
  for (const auto& descendant :
       builder->oof_positioned_fragmentainer_descendants_) {
    OofInlineContainer<PhysicalOffset> inline_container(
        descendant.inline_container.container,
        converter.ToPhysical(descendant.inline_container.relative_offset,
                             PhysicalSize()));
    OofInlineContainer<PhysicalOffset> fixedpos_inline_container(
        descendant.fixedpos_inline_container.container,
        converter.ToPhysical(
            descendant.fixedpos_inline_container.relative_offset,
            PhysicalSize()));

    // The static position should remain relative to the containing block.
    PhysicalSize containing_block_size =
        descendant.containing_block.Fragment()
            ? descendant.containing_block.Fragment()->Size()
            : size;
    const WritingModeConverter containing_block_converter(
        writing_direction, containing_block_size);

    fragmented_data->oof_positioned_fragmentainer_descendants.emplace_back(
        descendant.Node(),
        descendant.static_position.ConvertToPhysical(
            containing_block_converter),
        descendant.requires_content_before_breaking,
        descendant.is_hidden_for_paint, inline_container,
        PhysicalContainingBlock(builder, size, containing_block_size,
                                descendant.containing_block),
        PhysicalContainingBlock(builder, size,
                                descendant.fixedpos_containing_block),
        fixedpos_inline_container);
  }
  for (const auto& multicol : builder->multicols_with_pending_oofs_) {
    auto& value = multicol.value;
    OofInlineContainer<PhysicalOffset> fixedpos_inline_container(
        value->fixedpos_inline_container.container,
        converter.ToPhysical(value->fixedpos_inline_container.relative_offset,
                             PhysicalSize()));
    fragmented_data->multicols_with_pending_oofs.insert(
        multicol.key,
        MakeGarbageCollected<MulticolWithPendingOofs<PhysicalOffset>>(
            value->multicol_offset.ConvertToPhysical(
                builder->Style().GetWritingDirection(), size, PhysicalSize()),
            PhysicalContainingBlock(builder, size,
                                    value->fixedpos_containing_block),
            fixedpos_inline_container));
  }
  return fragmented_data;
}

void PhysicalFragment::ClearOofData() {
  if (!oof_data_)
    return;
  if (HasAnchorQuery())
    oof_data_->OofPositionedDescendants().clear();
  else
    oof_data_ = nullptr;
}

PhysicalFragment::OofData* PhysicalFragment::CloneOofData() const {
  DCHECK(oof_data_);
  if (!has_fragmented_out_of_flow_data_)
    return MakeGarbageCollected<OofData>(*oof_data_);
  DCHECK(GetFragmentedOofData());
  return MakeGarbageCollected<FragmentedOofData>(*GetFragmentedOofData());
}

bool PhysicalFragment::IsMonolithic() const {
  // Line boxes are monolithic, except for line boxes that are just there to
  // contain a block inside an inline, in which case the anonymous block child
  // wrapper inside the line is breakable.
  if (IsLineBox())
    return !IsBlock
### 提示词
```
这是目录为blink/renderer/core/layout/physical_fragment.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"

#include "base/ranges/algorithm.h"
#include "third_party/blink/renderer/core/dom/document_lifecycle.h"
#include "third_party/blink/renderer/core/html/shadow/shadow_element_utils.h"
#include "third_party/blink/renderer/core/layout/block_node.h"
#include "third_party/blink/renderer/core/layout/fragment_builder.h"
#include "third_party/blink/renderer/core/layout/geometry/box_strut.h"
#include "third_party/blink/renderer/core/layout/geometry/writing_mode_converter.h"
#include "third_party/blink/renderer/core/layout/inline/inline_cursor.h"
#include "third_party/blink/renderer/core/layout/inline/inline_node.h"
#include "third_party/blink/renderer/core/layout/inline/physical_line_box_fragment.h"
#include "third_party/blink/renderer/core/layout/inline/ruby_utils.h"
#include "third_party/blink/renderer/core/layout/layout_block.h"
#include "third_party/blink/renderer/core/layout/layout_text_combine.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"
#include "third_party/blink/renderer/core/layout/scrollable_overflow_calculator.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/platform/fonts/shaping/shape_result_view.h"
#include "third_party/blink/renderer/platform/wtf/size_assertions.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

namespace blink {
namespace {

struct SameSizeAsPhysicalFragment
    : public GarbageCollected<SameSizeAsPhysicalFragment> {
  Member<void*> layout_object;
  PhysicalSize size;
  uint8_t flags[4];
  Member<void*> members[3];
};

ASSERT_SIZE(PhysicalFragment, SameSizeAsPhysicalFragment);

String StringForBoxType(const PhysicalFragment& fragment) {
  StringBuilder result;
  switch (fragment.GetBoxType()) {
    case PhysicalFragment::BoxType::kNormalBox:
      break;
    case PhysicalFragment::BoxType::kInlineBox:
      result.Append("inline");
      break;
    case PhysicalFragment::BoxType::kColumnBox:
      result.Append("column");
      break;
    case PhysicalFragment::BoxType::kPageContainer:
      result.Append("page container");
      break;
    case PhysicalFragment::BoxType::kPageBorderBox:
      result.Append("page border box");
      break;
    case PhysicalFragment::BoxType::kPageMargin:
      result.Append("page margin");
      break;
    case PhysicalFragment::BoxType::kPageArea:
      result.Append("page area");
      break;
    case PhysicalFragment::BoxType::kAtomicInline:
      result.Append("atomic-inline");
      break;
    case PhysicalFragment::BoxType::kFloating:
      result.Append("floating");
      break;
    case PhysicalFragment::BoxType::kOutOfFlowPositioned:
      result.Append("out-of-flow-positioned");
      break;
    case PhysicalFragment::BoxType::kBlockFlowRoot:
      result.Append("block-flow-root");
      break;
    case PhysicalFragment::BoxType::kRenderedLegend:
      result.Append("rendered-legend");
      break;
  }
  if (fragment.IsBlockFlow()) {
    if (result.length())
      result.Append(" ");
    result.Append("block-flow");
  }
  if (fragment.IsFieldsetContainer()) {
    if (result.length())
      result.Append(" ");
    result.Append("fieldset-container");
  }
  if (fragment.IsBox() &&
      To<PhysicalBoxFragment>(fragment).IsInlineFormattingContext()) {
    if (result.length())
      result.Append(" ");
    result.Append("children-inline");
  }

  return result.ToString();
}

class FragmentTreeDumper {
  STACK_ALLOCATED();

 public:
  FragmentTreeDumper(StringBuilder* builder,
                     PhysicalFragment::DumpFlags flags,
                     const PhysicalFragment* target = nullptr)
      : builder_(builder), target_fragment_(target), flags_(flags) {}

  void Append(const PhysicalFragment* fragment,
              std::optional<PhysicalOffset> fragment_offset,
              unsigned indent = 2) {
    Vector<String> attributes;
    Append(fragment, fragment_offset, attributes, indent);
  }

  void Append(const PhysicalFragment* fragment,
              std::optional<PhysicalOffset> fragment_offset,
              Vector<String>& attributes,
              unsigned indent = 2) {
    AppendIndentation(indent, fragment);

    bool has_content = false;
    if (const auto* box = DynamicTo<PhysicalBoxFragment>(fragment)) {
      if (box->IsLayoutObjectDestroyedOrMoved()) {
        builder_->Append("DEAD LAYOUT OBJECT!\n");
        return;
      }
      const LayoutObject* layout_object = box->GetLayoutObject();
      if (flags_ & PhysicalFragment::DumpType) {
        builder_->Append("Box");
        String box_type = StringForBoxType(*fragment);
        has_content = true;
        if (!box_type.empty()) {
          attributes.push_back(box_type);
        }
        if (flags_ & PhysicalFragment::DumpSelfPainting &&
            box->HasSelfPaintingLayer()) {
          attributes.push_back("self paint");
        }
      }
      AppendAttributes(attributes);
      has_content = AppendOffsetAndSize(fragment, fragment_offset, has_content);

      if (flags_ & PhysicalFragment::DumpNodeName && layout_object) {
        if (has_content)
          builder_->Append(" ");
        builder_->Append(layout_object->DebugName());
      }
      builder_->Append("\n");

      bool has_fragment_items = false;
      if (flags_ & PhysicalFragment::DumpItems) {
        if (const FragmentItems* fragment_items = box->Items()) {
          InlineCursor cursor(*box, *fragment_items);
          Append(&cursor, indent + 2);
          has_fragment_items = true;
        }
      }
      if (flags_ & PhysicalFragment::DumpSubtree) {
        if (flags_ & PhysicalFragment::DumpLegacyDescendants && layout_object &&
            !layout_object->IsLayoutNGObject() && box->Children().empty()) {
          AppendLegacySubtree(*layout_object, indent);
          return;
        }
        for (auto& child : box->Children()) {
          if (has_fragment_items && child->IsLineBox())
            continue;
          Append(child.get(), child.Offset(), indent + 2);
        }
      }
      return;
    }

    if (const auto* line_box = DynamicTo<PhysicalLineBoxFragment>(fragment)) {
      if (flags_ & PhysicalFragment::DumpType) {
        builder_->Append("LineBox");
        has_content = true;
      }
      has_content = AppendOffsetAndSize(fragment, fragment_offset, has_content);
      builder_->Append("\n");

      if (flags_ & PhysicalFragment::DumpSubtree) {
        for (auto& child : line_box->Children()) {
          Append(child.get(), child.Offset(), indent + 2);
        }
        return;
      }
    }

    if (flags_ & PhysicalFragment::DumpType) {
      builder_->Append("Unknown fragment type");
      has_content = true;
    }
    has_content = AppendOffsetAndSize(fragment, fragment_offset, has_content);
    builder_->Append("\n");
  }

  void AppendAttributes(const Vector<String>& attributes) {
    if (!attributes.empty()) {
      String separator = " (";
      for (const String& attribute : attributes) {
        builder_->Append(separator);
        builder_->Append(attribute);
        separator = ")(";
      }
      builder_->Append(")");
    }
  }

  void AppendLegacySubtree(const LayoutObject& layout_object, unsigned indent) {
    for (const LayoutObject* descendant = &layout_object; descendant;) {
      if (!IsNGRootWithFragments(*descendant)) {
        if (descendant->IsOutOfFlowPositioned() && descendant != &layout_object)
          descendant = descendant->NextInPreOrderAfterChildren(&layout_object);
        else
          descendant = descendant->NextInPreOrder(&layout_object);
        continue;
      }
      AppendNGRootInLegacySubtree(*descendant, indent);
      descendant = descendant->NextInPreOrderAfterChildren(&layout_object);
    }
  }

  void AppendLegacySubtree(const LayoutObject& layout_object) {
    AppendLegacySubtree(layout_object, 0);
    if (target_fragment_ && !target_fragment_found_) {
      if (flags_ & PhysicalFragment::DumpHeaderText) {
        builder_->Append("(Fragment not found when searching the subtree)\n");
        builder_->Append("(Dumping detached fragment tree now:)\n");
      }
      Append(target_fragment_, std::nullopt);
    }
  }

  void AppendNGRootInLegacySubtree(const LayoutObject& layout_object,
                                   unsigned indent) {
    DCHECK(IsNGRootWithFragments(layout_object));
    if (flags_ & PhysicalFragment::DumpHeaderText) {
      AppendIndentation(indent + 2);
      builder_->Append(
          "(NG fragment root inside fragment-less or legacy subtree:)\n");
    }
    const LayoutBox& box_descendant = To<LayoutBox>(layout_object);
    DCHECK_EQ(box_descendant.PhysicalFragmentCount(), 1u);
    Append(box_descendant.GetPhysicalFragment(0), std::nullopt, indent + 4);
  }

 private:
  void Append(InlineCursor* cursor, unsigned indent) {
    for (; *cursor; cursor->MoveToNextSkippingChildren()) {
      const InlineCursorPosition& current = cursor->Current();
      const PhysicalFragment* box = current.BoxFragment();
      if (box && !box->IsInlineBox()) {
        Vector<String> attributes;
        if (current->IsHiddenForPaint()) {
          attributes.push_back("hidden");
        }
        Append(box, current.OffsetInContainerFragment(), attributes, indent);
        continue;
      }

      if (!box)
        box = current.Item()->LineBoxFragment();
      AppendIndentation(indent, box);

      if (current.Item()->IsLayoutObjectDestroyedOrMoved()) {
        builder_->Append("DEAD LAYOUT OBJECT!\n");
        return;
      }

      // TODO(kojii): Use the same format as layout tree dump for now. We can
      // make this more similar to |AppendFragmentToString| above.
      builder_->Append(current->ToString());

      if (flags_ & PhysicalFragment::DumpOffset) {
        builder_->Append(" offset:");
        builder_->Append(current.OffsetInContainerFragment().ToString());
      }
      if (flags_ & PhysicalFragment::DumpSize) {
        builder_->Append(" size:");
        builder_->Append(current.Size().ToString());
      }

      builder_->Append("\n");

      if (flags_ & PhysicalFragment::DumpSubtree && current.HasChildren()) {
        InlineCursor descendants = cursor->CursorForDescendants();
        Append(&descendants, indent + 2);
      }
    }
  }

  bool AppendOffsetAndSize(const PhysicalFragment* fragment,
                           std::optional<PhysicalOffset> fragment_offset,
                           bool has_content) {
    if (flags_ & PhysicalFragment::DumpOffset) {
      if (has_content)
        builder_->Append(" ");
      builder_->Append("offset:");
      if (fragment_offset)
        builder_->Append(fragment_offset->ToString());
      else
        builder_->Append("unplaced");
      has_content = true;
    }
    if (flags_ & PhysicalFragment::DumpSize) {
      if (has_content)
        builder_->Append(" ");
      builder_->Append("size:");
      builder_->Append(fragment->Size().ToString());
      has_content = true;
    }
    return has_content;
  }

  void AppendIndentation(unsigned indent,
                         const PhysicalFragment* fragment = nullptr) {
    if (flags_ & PhysicalFragment::DumpIndentation) {
      unsigned start_idx = 0;
      if (fragment && fragment == target_fragment_) {
        builder_->Append("*");
        start_idx = 1;
        target_fragment_found_ = true;
      }
      for (unsigned i = start_idx; i < indent; i++)
        builder_->Append(" ");
    }
  }

  // Check if the object is an NG root ready to be traversed. If layout of the
  // object hasn't finished yet, there'll be no fragment, and false will be
  // returned.
  bool IsNGRootWithFragments(const LayoutObject& object) const {
    if (!object.IsLayoutNGObject())
      return false;
    const LayoutBox* box = DynamicTo<LayoutBox>(&object);
    if (!box)
      return false;
    // A root should only have at most one fragment, or zero if it hasn't been
    // laid out yet.
    DCHECK_LE(box->PhysicalFragmentCount(), 1u);
    return box->PhysicalFragmentCount();
  }

  StringBuilder* builder_;
  const PhysicalFragment* target_fragment_ = nullptr;
  PhysicalFragment::DumpFlags flags_;
  bool target_fragment_found_ = false;
};

OofContainingBlock<PhysicalOffset> PhysicalContainingBlock(
    FragmentBuilder* builder,
    PhysicalSize outer_size,
    PhysicalSize inner_size,
    const OofContainingBlock<LogicalOffset>& containing_block) {
  return OofContainingBlock<PhysicalOffset>(
      containing_block.Offset().ConvertToPhysical(
          builder->Style().GetWritingDirection(), outer_size, inner_size),
      RelativeInsetToPhysical(containing_block.RelativeOffset(),
                              builder->Style().GetWritingDirection()),
      containing_block.Fragment(),
      containing_block.ClippedContainerBlockOffset(),
      containing_block.IsInsideColumnSpanner());
}

OofContainingBlock<PhysicalOffset> PhysicalContainingBlock(
    FragmentBuilder* builder,
    PhysicalSize size,
    const OofContainingBlock<LogicalOffset>& containing_block) {
  PhysicalSize containing_block_size =
      containing_block.Fragment() ? containing_block.Fragment()->Size() : size;
  return PhysicalContainingBlock(builder, size, containing_block_size,
                                 containing_block);
}

}  // namespace

PhysicalFragment::PhysicalFragment(FragmentBuilder* builder,
                                   WritingMode block_or_line_writing_mode,
                                   FragmentType type,
                                   unsigned sub_type)
    : layout_object_(builder->layout_object_),
      size_(ToPhysicalSize(builder->size_, builder->GetWritingMode())),
      type_(type),
      sub_type_(sub_type),
      style_variant_((unsigned)builder->style_variant_),
      is_hidden_for_paint_(builder->is_hidden_for_paint_),
      has_floating_descendants_for_paint_(false),
      children_valid_(true),
      is_opaque_(builder->is_opaque_),
      is_block_in_inline_(builder->is_block_in_inline_),
      is_line_for_parallel_flow_(builder->is_line_for_parallel_flow_),
      may_have_descendant_above_block_start_(
          builder->may_have_descendant_above_block_start_),
      is_fieldset_container_(false),
      is_table_part_(false),
      is_painted_atomically_(false),
      has_collapsed_borders_(builder->has_collapsed_borders_),
      has_first_baseline_(false),
      has_last_baseline_(false),
      use_last_baseline_for_inline_baseline_(false),
      has_fragmented_out_of_flow_data_(
          !builder->oof_positioned_fragmentainer_descendants_.empty() ||
          !builder->multicols_with_pending_oofs_.empty()),
      has_out_of_flow_fragment_child_(builder->HasOutOfFlowFragmentChild()),
      has_out_of_flow_in_fragmentainer_subtree_(
          builder->HasOutOfFlowInFragmentainerSubtree()),
      propagated_data_((builder->sticky_descendants_ || builder->snap_areas_ ||
                        builder->scroll_start_target_)
                           ? MakeGarbageCollected<PropagatedData>(
                                 builder->sticky_descendants_,
                                 builder->snap_areas_,
                                 builder->scroll_start_target_)
                           : nullptr),
      break_token_(std::move(builder->break_token_)),
      oof_data_(builder->oof_positioned_descendants_.empty() &&
                        !builder->AnchorQuery() &&
                        !has_fragmented_out_of_flow_data_
                    ? nullptr
                    : OofDataFromBuilder(builder)) {
  CHECK(builder->layout_object_);

  // A line with a float / block in a parallel flow should not have an outgoing
  // break token associated. An outgoing inline break token from a line means
  // that it is to be resumed in the main flow of the container.
  DCHECK(!is_line_for_parallel_flow_ || !break_token_);

  has_floating_descendants_for_paint_ =
      builder->has_floating_descendants_for_paint_;
  has_adjoining_object_descendants_ =
      builder->has_adjoining_object_descendants_;
  depends_on_percentage_block_size_ = DependsOnPercentageBlockSize(*builder);
  children_valid_ = true;
}

// Even though the other constructors don't initialize many of these fields
// (instead set by their super-classes), the copy constructor does.
PhysicalFragment::PhysicalFragment(const PhysicalFragment& other)
    : layout_object_(other.layout_object_),
      size_(other.size_),
      type_(other.type_),
      sub_type_(other.sub_type_),
      style_variant_(other.style_variant_),
      is_hidden_for_paint_(other.is_hidden_for_paint_),
      has_floating_descendants_for_paint_(
          other.has_floating_descendants_for_paint_),
      has_adjoining_object_descendants_(
          other.has_adjoining_object_descendants_),
      depends_on_percentage_block_size_(
          other.depends_on_percentage_block_size_),
      children_valid_(other.children_valid_),
      has_propagated_descendants_(other.has_propagated_descendants_),
      has_hanging_(other.has_hanging_),
      is_opaque_(other.is_opaque_),
      is_block_in_inline_(other.is_block_in_inline_),
      is_line_for_parallel_flow_(other.is_line_for_parallel_flow_),
      is_math_fraction_(other.is_math_fraction_),
      is_math_operator_(other.is_math_operator_),
      may_have_descendant_above_block_start_(
          other.may_have_descendant_above_block_start_),
      is_fieldset_container_(other.is_fieldset_container_),
      is_table_part_(other.is_table_part_),
      is_painted_atomically_(other.is_painted_atomically_),
      has_collapsed_borders_(other.has_collapsed_borders_),
      has_first_baseline_(other.has_first_baseline_),
      has_last_baseline_(other.has_last_baseline_),
      use_last_baseline_for_inline_baseline_(
          other.use_last_baseline_for_inline_baseline_),
      has_fragmented_out_of_flow_data_(other.has_fragmented_out_of_flow_data_),
      has_out_of_flow_fragment_child_(other.has_out_of_flow_fragment_child_),
      has_out_of_flow_in_fragmentainer_subtree_(
          other.has_out_of_flow_in_fragmentainer_subtree_),
      base_direction_(other.base_direction_),
      propagated_data_(other.propagated_data_),
      break_token_(other.break_token_),
      oof_data_(other.oof_data_ ? other.CloneOofData() : nullptr) {
  CHECK(layout_object_);
  DCHECK(other.children_valid_);
  DCHECK(children_valid_);
}

bool PhysicalFragment::IsBlockFlow() const {
  return !IsLineBox() && layout_object_->IsLayoutBlockFlow();
}

bool PhysicalFragment::IsTextControlContainer() const {
  return IsCSSBox() && blink::IsTextControlContainer(layout_object_->GetNode());
}

bool PhysicalFragment::IsTextControlPlaceholder() const {
  return IsCSSBox() &&
         blink::IsTextControlPlaceholder(layout_object_->GetNode());
}

base::span<PhysicalOofPositionedNode>
PhysicalFragment::OutOfFlowPositionedDescendants() const {
  if (!HasOutOfFlowPositionedDescendants())
    return base::span<PhysicalOofPositionedNode>();
  return {oof_data_->OofPositionedDescendants().data(),
          oof_data_->OofPositionedDescendants().size()};
}

const FragmentedOofData* PhysicalFragment::GetFragmentedOofData() const {
  if (!has_fragmented_out_of_flow_data_)
    return nullptr;
  auto* oof_data = reinterpret_cast<FragmentedOofData*>(oof_data_.Get());
  DCHECK(!oof_data->multicols_with_pending_oofs.empty() ||
         !oof_data->oof_positioned_fragmentainer_descendants.empty());
  return oof_data;
}

bool PhysicalFragment::HasNestedMulticolsWithOOFs() const {
  const auto* oof_data = GetFragmentedOofData();
  return oof_data && !oof_data->multicols_with_pending_oofs.empty();
}

bool PhysicalFragment::NeedsOOFPositionedInfoPropagation() const {
  // If we have |oof_data_|, it should mean at least one of OOF propagation data
  // exists.
  DCHECK_EQ(!!oof_data_,
            HasOutOfFlowPositionedDescendants() || HasAnchorQuery() ||
                (GetFragmentedOofData() &&
                 GetFragmentedOofData()->NeedsOOFPositionedInfoPropagation()));
  return !!oof_data_;
}

PhysicalFragment::OofData* PhysicalFragment::OofDataFromBuilder(
    FragmentBuilder* builder) {
  OofData* oof_data = nullptr;
  if (has_fragmented_out_of_flow_data_) {
    oof_data = FragmentedOofDataFromBuilder(builder);
  }

  const WritingModeConverter converter(
      {builder->Style().GetWritingMode(), builder->Direction()}, Size());

  if (!builder->oof_positioned_descendants_.empty()) {
    if (!oof_data) {
      oof_data = MakeGarbageCollected<OofData>();
    }
    oof_data->OofPositionedDescendants().reserve(
        builder->oof_positioned_descendants_.size());
    for (const auto& descendant : builder->oof_positioned_descendants_) {
      OofInlineContainer<PhysicalOffset> inline_container(
          descendant.inline_container.container,
          converter.ToPhysical(descendant.inline_container.relative_offset,
                               PhysicalSize()));
      oof_data->OofPositionedDescendants().emplace_back(
          descendant.Node(),
          descendant.static_position.ConvertToPhysical(converter),
          descendant.requires_content_before_breaking,
          descendant.is_hidden_for_paint, inline_container);
    }
  }

  if (const LogicalAnchorQuery* anchor_query = builder->AnchorQuery()) {
    if (!oof_data) {
      oof_data = MakeGarbageCollected<OofData>();
    }
    oof_data->AnchorQuery().SetFromLogical(*anchor_query, converter);
  }

  return oof_data;
}

PhysicalFragment::OofData* PhysicalFragment::FragmentedOofDataFromBuilder(
    FragmentBuilder* builder) {
  DCHECK(has_fragmented_out_of_flow_data_);
  DCHECK_EQ(has_fragmented_out_of_flow_data_,
            !builder->oof_positioned_fragmentainer_descendants_.empty() ||
                !builder->multicols_with_pending_oofs_.empty());
  auto* fragmented_data = MakeGarbageCollected<FragmentedOofData>();
  fragmented_data->oof_positioned_fragmentainer_descendants.reserve(
      builder->oof_positioned_fragmentainer_descendants_.size());
  const PhysicalSize& size = Size();
  WritingDirectionMode writing_direction = builder->GetWritingDirection();
  const WritingModeConverter converter(writing_direction, size);
  for (const auto& descendant :
       builder->oof_positioned_fragmentainer_descendants_) {
    OofInlineContainer<PhysicalOffset> inline_container(
        descendant.inline_container.container,
        converter.ToPhysical(descendant.inline_container.relative_offset,
                             PhysicalSize()));
    OofInlineContainer<PhysicalOffset> fixedpos_inline_container(
        descendant.fixedpos_inline_container.container,
        converter.ToPhysical(
            descendant.fixedpos_inline_container.relative_offset,
            PhysicalSize()));

    // The static position should remain relative to the containing block.
    PhysicalSize containing_block_size =
        descendant.containing_block.Fragment()
            ? descendant.containing_block.Fragment()->Size()
            : size;
    const WritingModeConverter containing_block_converter(
        writing_direction, containing_block_size);

    fragmented_data->oof_positioned_fragmentainer_descendants.emplace_back(
        descendant.Node(),
        descendant.static_position.ConvertToPhysical(
            containing_block_converter),
        descendant.requires_content_before_breaking,
        descendant.is_hidden_for_paint, inline_container,
        PhysicalContainingBlock(builder, size, containing_block_size,
                                descendant.containing_block),
        PhysicalContainingBlock(builder, size,
                                descendant.fixedpos_containing_block),
        fixedpos_inline_container);
  }
  for (const auto& multicol : builder->multicols_with_pending_oofs_) {
    auto& value = multicol.value;
    OofInlineContainer<PhysicalOffset> fixedpos_inline_container(
        value->fixedpos_inline_container.container,
        converter.ToPhysical(value->fixedpos_inline_container.relative_offset,
                             PhysicalSize()));
    fragmented_data->multicols_with_pending_oofs.insert(
        multicol.key,
        MakeGarbageCollected<MulticolWithPendingOofs<PhysicalOffset>>(
            value->multicol_offset.ConvertToPhysical(
                builder->Style().GetWritingDirection(), size, PhysicalSize()),
            PhysicalContainingBlock(builder, size,
                                    value->fixedpos_containing_block),
            fixedpos_inline_container));
  }
  return fragmented_data;
}

void PhysicalFragment::ClearOofData() {
  if (!oof_data_)
    return;
  if (HasAnchorQuery())
    oof_data_->OofPositionedDescendants().clear();
  else
    oof_data_ = nullptr;
}

PhysicalFragment::OofData* PhysicalFragment::CloneOofData() const {
  DCHECK(oof_data_);
  if (!has_fragmented_out_of_flow_data_)
    return MakeGarbageCollected<OofData>(*oof_data_);
  DCHECK(GetFragmentedOofData());
  return MakeGarbageCollected<FragmentedOofData>(*GetFragmentedOofData());
}

bool PhysicalFragment::IsMonolithic() const {
  // Line boxes are monolithic, except for line boxes that are just there to
  // contain a block inside an inline, in which case the anonymous block child
  // wrapper inside the line is breakable.
  if (IsLineBox())
    return !IsBlockInInline();
  if (const auto* box_fragment = DynamicTo<PhysicalBoxFragment>(this)) {
    return box_fragment->IsMonolithic();
  }
  return false;
}

bool PhysicalFragment::IsImplicitAnchor() const {
  if (Element* element = DynamicTo<Element>(GetNode())) {
    return element->HasImplicitlyAnchoredElement();
  }
  return false;
}

const FragmentData* PhysicalFragment::GetFragmentData() const {
  const LayoutBox* box = DynamicTo<LayoutBox>(GetLayoutObject());
  if (!box) {
    DCHECK(!GetLayoutObject());
    return nullptr;
  }
  return box->FragmentDataFromPhysicalFragment(To<PhysicalBoxFragment>(*this));
}

const PhysicalFragment* PhysicalFragment::PostLayout() const {
  if (const auto* box = DynamicTo<PhysicalBoxFragment>(this)) {
    return box->PostLayout();
  }
  return this;
}

#if DCHECK_IS_ON()
void PhysicalFragment::CheckType() const {
  switch (Type()) {
    case kFragmentBox:
      if (IsInlineBox()) {
        DCHECK(layout_object_->IsLayoutInline());
      } else {
        DCHECK(layout_object_->IsBox());
      }
      if (IsFragmentainerBox() || GetBoxType() == kPageContainer ||
          GetBoxType() == kPageBorderBox || GetBoxType() == kPageMargin) {
        // Fragmentainers are associated with the same layout object as their
        // multicol container (or the LayoutView, in case of printing). The
        // fragments themselves are regular in-flow block container fragments
        // for most purposes.
        DCHECK(layout_object_->IsLayoutBlockFlow());
        DCHECK(IsBox());
        DCHECK(!IsFloating());
        DCHECK(!IsOutOfFlowPositioned());
        DCHECK(!IsAtomicInline());
        DCHECK(!IsFormattingContextRoot());
        break;
      }
      if (layout_object_->IsLayoutOutsideListMarker()) {
        // List marker is an atomic inline if it appears in a line box, or a
        // block box.
        DCHECK(!IsFloating());
        DCHECK(!IsOutOfFlowPositioned());
        DCHECK(IsAtomicInline() || (IsBox() && GetBoxType() == kBlockFlowRoot));
        break;
      }
      DCHECK_EQ(IsFloating(), layout_object_->IsFloating());
      DCHECK_EQ(IsOutOfFlowPositioned(),
                layout_object_->IsOutOfFlowPositioned());
      DCHECK_EQ(IsAtomicInline(), layout_object_->IsInline() &&
                                      layout_object_->IsAtomicInlineLevel());
      break;
    case kFragmentLineBox:
      DCHECK(layout_object_->IsLayoutBlockFlow());
      DCHECK(!IsFloating());
      DCHECK(!IsOutOfFlowPositioned());
      DCHECK(!IsInlineBox());
      DCHECK(!IsAtomicInline());
      break;
  }
}
#endif

LogicalRect PhysicalFragment::ConvertChildToLogical(
    const PhysicalRect& physical_rect) const {
  return WritingModeConverter(Style().GetWritingDirection(), Size())
      .ToLogical(physical_rect);
}

String PhysicalFragment::ToString() const {
  StringBuilder output;
  output.AppendFormat("Type: '%d' Size: '%s'", Type(),
                      Size().ToString().Ascii().c_str());
  switch (Type()) {
    case kFragmentBox:
      output.AppendFormat(", BoxType: '%s'",
                          StringForBoxType(*this).Ascii().c_str());
      break;
    case kFragmentLineBox:
      break;
  }
  return output.ToString();
}

String PhysicalFragment::DumpFragmentTree(
    DumpFlags flags,
    const PhysicalFragment* target,
    std::optional<PhysicalOffset> fragment_offset,
    unsigned indent) const {
  StringBuilder string_builder;
  if (flags & DumpHeaderText)
    string_builder.Append(".:: LayoutNG Physical Fragment Tree ::.\n");
  FragmentTreeDumper(&string_builder, flags, target)
      .Append(this, fragment_offset, indent);
  return string_builder.ToString();
}

String PhysicalFragment::DumpFragmentTree(const LayoutObject& root,
                                          DumpFlags flags,
                                          const PhysicalFragment* target) {
  if (root.IsLayoutNGObject()) {
    const LayoutBox& root_box = To<LayoutBox>(root);
    DCHECK_EQ(root_box.PhysicalFragmentCount(), 1u);
    return root_box.GetPhysicalFragment(0)->DumpFragmentTree(flags, target);
  }
  StringBuilder string_builder;
  if (flags & DumpHeaderText) {
    string_builder.Append(
        ".:: LayoutNG Physical Fragment Tree at legacy root ");
    string_builder.Append(root.DebugName());
    string_builder.Append(" ::.\n");
  }
  FragmentTreeDumper(&string_builder, flags, target).AppendLegacySubtree(root);
  return string_builder.ToString();
}

void PhysicalFragment::Trace(Visitor* visitor) const {
  switch (Type()) {
    case kFragmentBox:
      static_cast<const PhysicalBoxFragment*>(this)->TraceAfterDispatch(
          visitor);
      break;
    case kFragmentLineBox:
      static_cast<const PhysicalLineBoxFragment*>(this)->TraceAfterDispatch(
          visitor);
      break;
  }
}

void PhysicalFragment::TraceAfterDispatch(Visitor* visitor) const {
  visitor->Trace(layout_object_);
  visitor->Trace(propagated_data_);
  visitor->Trace(break_token_);
  visitor->Trace(oof_data_);
}

// TODO(dlibby): remove `Children` and `PostLayoutChildren` and move the
// casting and/or branching to the callers.
base::span<const PhysicalFragmentLink> PhysicalFragment::Children() const {
  if (Type() == kFragmentBox)
    return static_cast<const PhysicalBoxFragment*>(this)->Children();
  return base::make_span(static_cast<PhysicalFragmentLink*>(nullptr), 0u);
}

PhysicalFragment::PostLayoutChildLinkList PhysicalFragment::PostLayoutChildren()
    const {
  if (Type() == kFragmentBox) {
    return static_cast<const PhysicalBoxFragment*>(this)->PostLayoutChildren();
  }
  return PostLayoutChildLinkList(0, nullptr);
}

void PhysicalFragment::SetChildrenInvalid() const {
  if (!children_valid_)
    return;

  for (const PhysicalFragmentLink& child : Children()) {
    const_cast<PhysicalFragmentLink&>(child).fragment = nullptr;
  }
  children_valid_ = false;
}

// additional_offset must be offset from the containing_block.
void PhysicalFragment::AddOutlineRectsForNormalChildren(
    OutlineRectCollector& collector,
    const PhysicalOffset& additional_offset,
    OutlineType outline_type,
    const LayoutBoxModelObject* containing_block) const {
  if (const auto* box = DynamicTo<PhysicalBoxFragment>(this)) {
    DCHECK_EQ(box->PostLayout(), box);
    if (const FragmentItems* items = box->Items()) {
      InlineCursor cursor(*box, *items);
      AddOutlineRectsForCursor(collector, additional_offset, outline_type,
                               containing_block, &cursor);
      // Don't add |Children()|. If |this| has |FragmentItems|, children are
      // either line box, which we already handled in items, or OOF, which we
      // should ignore.
      DCHECK(base::ranges::all_of(
          PostLayoutChildren(), [](const PhysicalFragmentLink& child) {
            return child->IsLineBox() || child->IsOutOfFlowPositioned();
          }));
      return;
    }
  }

  for (const auto& child : PostLayoutChildren()) {
    // Outlines of out-of-flow positioned descendants are handled in
    // PhysicalBoxFragment::AddSelfOutlineRects().
    if (child->IsOutOfFlowPo
```