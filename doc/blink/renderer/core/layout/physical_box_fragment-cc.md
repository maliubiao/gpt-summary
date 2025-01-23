Response:
My goal is to analyze the provided C++ code snippet for the `PhysicalBoxFragment` class and summarize its functionalities, relating them to web technologies like JavaScript, HTML, and CSS where applicable. Here's my thought process:

1. **Identify the Core Class:** The central focus is `PhysicalBoxFragment`. The file path confirms this is part of the Blink rendering engine, specifically the layout component.

2. **Understand the Purpose of "Fragment":** The term "fragment" in layout contexts usually refers to a portion of a layout object that is rendered separately, often due to fragmentation (like pagination or multi-column layouts). This is a crucial initial understanding.

3. **Examine the Includes:** The included header files provide significant clues about the class's responsibilities. I'll categorize them:
    * **Layout Fundamentals:** `layout/physical_box_fragment.h`, `layout/box_fragment_builder.h`, `layout/geometry/...`, `layout/inline/...`, `layout/layout_block_flow.h`, `layout/layout_inline.h`, `layout/layout_object.h`, etc. These strongly suggest this class is fundamental to the layout process.
    * **Editing:** `editing/...`. This indicates interaction with text editing functionalities.
    * **HTML Elements:** `html/html_anchor_element.h`. Shows it can interact with specific HTML elements.
    * **Painting:** `paint/...`. Implies involvement in the rendering process.
    * **Utilities/Platform:** `build/chromeos_buildflags.h`, `platform/wtf/...`. Standard utilities and platform-specific configurations.
    * **Display Locking:** `display_lock/...`. Suggests a role in optimizing rendering updates.

4. **Analyze Key Members and Methods:** I'll scan the code for important data members and methods, focusing on their names and what they likely do:
    * **`Create()`:**  Likely responsible for instantiating `PhysicalBoxFragment` objects. It takes a `BoxFragmentBuilder` as input, indicating a builder pattern. The calculations within this method for borders, padding, scrollable overflow, and child fragment positioning are key.
    * **`Clone()`:** Creates copies of `PhysicalBoxFragment` objects. The existence of `CloneWithPostLayoutFragments()` suggests a distinction between the initial layout and a "post-layout" state, which is important for understanding rendering updates and optimizations.
    * **`ContentRect()`, `SelfInkOverflowRect()`, `ContentsInkOverflowRect()`, `InkOverflowRect()`, `OverflowClipRect()`:**  These methods clearly deal with the geometry and clipping of the fragment, crucial for correct rendering and handling overflow. "Ink overflow" is related to how effects like box-shadows and outlines are rendered.
    * **`OffsetFromOwnerLayoutBox()`:**  Determines the fragment's position relative to its parent, essential for positioning within a fragmented layout.
    * **`PostLayout()`:**  Returns the "post-layout" version of the fragment, indicating that the layout process can have different phases.
    * **`MayIntersect()`:**  Used in hit-testing, determining if a point intersects with the fragment.
    * **`ScrollSize()`, `PixelSnappedScrolledContentOffset()`:**  Related to scrolling behavior.
    * **`InlineContainerFragmentIfOutlineOwner()`:**  Specifically handles outlines for inline elements.
    * **`MutableForStyleRecalc`, `MutableForContainerLayout`, `MutableForOofFragmentation`:** These inner classes with "Mutable" in their names suggest methods for modifying the fragment's properties during specific phases of the layout process (style recalculation, container layout, and out-of-flow fragmentation).

5. **Connect to Web Technologies:**  Based on the understanding of the class's responsibilities, I can now relate it to JavaScript, HTML, and CSS:
    * **HTML:** The structure of the HTML document dictates the creation of layout objects and their fragmentation. Different HTML elements (like `<div>`, `<p>`, `<span>`, tables) will result in different layout structures and potentially different fragmentation patterns. The interaction with `HTMLAnchorElement` shows a direct link to specific HTML tags.
    * **CSS:** CSS styles directly influence the properties of `PhysicalBoxFragment` objects: dimensions (width, height), positioning (static, relative, absolute, fixed), margins, padding, borders, overflow, visibility, and fragmentation properties (like `break-before`, `break-after`, columns). The methods dealing with borders, padding, overflow, and clipping directly reflect CSS properties.
    * **JavaScript:** JavaScript can trigger layout changes by manipulating the DOM (adding, removing, or modifying elements and their styles). This, in turn, will cause the Blink engine to recalculate the layout, including the creation and manipulation of `PhysicalBoxFragment` objects. JavaScript can also interact with scrolling, which is related to methods like `ScrollSize()`.

6. **Infer Logic and Provide Examples:**  Based on the method names and parameters, I can infer the logic and create hypothetical input/output examples. For instance, in `ApplyOverflowClip`, I can assume that if `kOverflowClipX` is set, the X and Width of the `result` rect will be set to the values of the `no_overflow_rect`.

7. **Identify Potential Usage Errors:** Understanding the purpose of the class allows me to anticipate common programming mistakes within the Blink engine itself (since this is internal Chromium code, not directly used by web developers). For example, incorrectly calculating or setting the dimensions or offsets of a fragment could lead to rendering issues. Failing to update the fragment tree correctly after modifications could lead to inconsistencies.

8. **Summarize the Functionality:** Finally, I synthesize the gathered information into a concise summary of the `PhysicalBoxFragment`'s role. The key aspects are: representing a rectangular area of a layout object, storing geometric information, handling fragmentation, participating in hit-testing, and contributing to the painting process.

By following these steps, I can systematically analyze the code snippet and extract the required information, connecting it to the broader context of web technologies and identifying potential usage considerations. The focus is on understanding the *purpose* and *role* of the class within the rendering engine.
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"

#include "build/chromeos_buildflags.h"
#include "third_party/blink/renderer/core/display_lock/display_lock_utilities.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/position_with_affinity.h"
#include "third_party/blink/renderer/core/editing/text_affinity.h"
#include "third_party/blink/renderer/core/html/html_anchor_element.h"
#include "third_party/blink/renderer/core/layout/block_break_token.h"
#include "third_party/blink/renderer/core/layout/box_fragment_builder.h"
#include "third_party/blink/renderer/core/layout/disable_layout_side_effects_scope.h"
#include "third_party/blink/renderer/core/layout/geometry/box_strut.h"
#include "third_party/blink/renderer/core/layout/geometry/physical_rect.h"
#include "third_party/blink/renderer/core/layout/geometry/writing_mode_converter.h"
#include "third_party/blink/renderer/core/layout/inline/fragment_item.h"
#include "third_party/blink/renderer/core/layout/inline/inline_cursor.h"
#include "third_party/blink/renderer/core/layout/inline/inline_item.h"
#include "third_party/blink/renderer/core/layout/inline/physical_line_box_fragment.h"
#include "third_party/blink/renderer/core/layout/layout_block_flow.h"
#include "third_party/blink/renderer/core/layout/layout_inline.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/layout/layout_object_inlines.h"
#include "third_party/blink/renderer/core/layout/layout_text_combine.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/layout/outline_utils.h"
#include "third_party/blink/renderer/core/layout/relative_utils.h"
#include "third_party/blink/renderer/core/layout/table/layout_table_cell.h"
#include "third_party/blink/renderer/core/paint/inline_paint_context.h"
#include "third_party/blink/renderer/core/paint/outline_painter.h"
#include "third_party/blink/renderer/platform/wtf/size_assertions.h"

namespace blink {

#if DCHECK_IS_ON()
unsigned PhysicalBoxFragment::AllowPostLayoutScope::allow_count_ = 0;
#endif

namespace {

struct SameSizeAsPhysicalBoxFragment : PhysicalFragment {
  unsigned flags;
  LayoutUnit baseline;
  LayoutUnit last_baseline;
  Member<void*> rare;
  InkOverflow ink_overflow;
  HeapVector<PhysicalFragmentLink> children;
};

ASSERT_SIZE(PhysicalBoxFragment, SameSizeAsPhysicalBoxFragment);

bool HasControlClip(const PhysicalBoxFragment& self) {
  const LayoutBox* box = DynamicTo<LayoutBox>(self.GetLayoutObject());
  return box && box->HasControlClip();
}

bool ShouldUsePositionForPointInBlockFlowDirection(
    const LayoutObject& layout_object) {
  const LayoutBlockFlow* const layout_block_flow =
      DynamicTo<LayoutBlockFlow>(layout_object);
  if (!layout_block_flow) {
    // For <tr>, see editing/selection/click-before-and-after-table.html
    return false;
  }
  if (layout_block_flow->StyleRef().SpecifiesColumns()) {
    // Columns are laid out in inline direction.
    return false;
  }
  return true;
}

inline bool IsHitTestCandidate(const PhysicalBoxFragment& fragment) {
  return fragment.Size().height &&
         fragment.Style().Visibility() == EVisibility::kVisible &&
         !fragment.IsFloatingOrOutOfFlowPositioned();
}

// Applies the overflow clip to |result|. For any axis that is clipped, |result|
// is reset to |no_overflow_rect|. If neither axis is clipped, nothing is
// changed.
void ApplyOverflowClip(OverflowClipAxes overflow_clip_axes,
                       const PhysicalRect& no_overflow_rect,
                       PhysicalRect* result) {
  if (overflow_clip_axes & kOverflowClipX) {
    result->SetX(no_overflow_rect.X());
    result->SetWidth(no_overflow_rect.Width());
  }
  if (overflow_clip_axes & kOverflowClipY) {
    result->SetY(no_overflow_rect.Y());
    result->SetHeight(no_overflow_rect.Height());
  }
}

}  // namespace

// static
const PhysicalBoxFragment* PhysicalBoxFragment::Create(
    BoxFragmentBuilder* builder,
    WritingMode block_or_line_writing_mode) {
  const auto writing_direction = builder->GetWritingDirection();
  const PhysicalBoxStrut borders =
      builder->ApplicableBorders().ConvertToPhysical(writing_direction);
  const PhysicalBoxStrut scrollbar =
      builder->ApplicableScrollbar().ConvertToPhysical(writing_direction);
  const PhysicalBoxStrut padding =
      builder->ApplicablePadding().ConvertToPhysical(writing_direction);

  const PhysicalSize physical_size =
      ToPhysicalSize(builder->Size(), builder->GetWritingMode());
  WritingModeConverter converter(writing_direction, physical_size);

  std::optional<PhysicalRect> inflow_bounds;
  if (builder->inflow_bounds_)
    inflow_bounds = converter.ToPhysical(*builder->inflow_bounds_);

#if DCHECK_IS_ON()
  if (builder->needs_inflow_bounds_explicitly_set_ && builder->node_ &&
      builder->node_.IsScrollContainer() && !builder->IsFragmentainerBoxType())
    DCHECK(builder->is_inflow_bounds_explicitly_set_);
  if (builder->needs_may_have_descendant_above_block_start_explicitly_set_)
    DCHECK(builder->is_may_have_descendant_above_block_start_explicitly_set_);
#endif

  PhysicalRect scrollable_overflow = {PhysicalOffset(), physical_size};
  if (builder->ShouldCalculateScrollableOverflow()) {
    ScrollableOverflowCalculator calculator(
        To<BlockNode>(builder->node_),
        /* is_css_box */ !builder->IsFragmentainerBoxType(),
        builder->GetConstraintSpace().HasBlockFragmentation(), borders,
        scrollbar, padding, physical_size, writing_direction);

    if (FragmentItemsBuilder* items_builder = builder->ItemsBuilder()) {
      calculator.AddItems(builder->GetLayoutObject(),
                          items_builder->Items(physical_size));
    }

    for (auto& child : builder->children_) {
      const auto* box_fragment =
          DynamicTo<PhysicalBoxFragment>(*child.fragment);
      if (!box_fragment)
        continue;

      calculator.AddChild(*box_fragment, child.offset.ConvertToPhysical(
                                             writing_direction, physical_size,
                                             box_fragment->Size()));
    }

    if (builder->table_collapsed_borders_)
      calculator.AddTableSelfRect();

    scrollable_overflow = calculator.Result(inflow_bounds);
  }

  // For the purposes of object allocation we have scrollable-overflow if it
  // differs from the fragment size.
  bool has_scrollable_overflow =
      scrollable_overflow != PhysicalRect({}, physical_size);

  // Omit |FragmentItems| if there were no items; e.g., display-lock.
  bool has_fragment_items = false;
  if (FragmentItemsBuilder* items_builder = builder->ItemsBuilder()) {
    if (items_builder->Size())
      has_fragment_items = true;
  }

  size_t byte_size = AdditionalByteSize(has_fragment_items);

  // We store the children list inline in the fragment as a flexible
  // array. Therefore, we need to make sure to allocate enough space for
  // that array here, which requires a manual allocation + placement new.
  // The initialization of the array is done by PhysicalFragment;
  // we pass the buffer as a constructor argument.
  return MakeGarbageCollected<PhysicalBoxFragment>(
      AdditionalBytes(byte_size), PassKey(), builder, has_scrollable_overflow,
      scrollable_overflow, borders.IsZero() ? nullptr : &borders,
      scrollbar.IsZero() ? nullptr : &scrollbar,
      padding.IsZero() ? nullptr : &padding, inflow_bounds, has_fragment_items,
      block_or_line_writing_mode);
}

// static
const PhysicalBoxFragment* PhysicalBoxFragment::Clone(
    const PhysicalBoxFragment& other) {
  // The size of the new fragment shouldn't differ from the old one.
  size_t byte_size = AdditionalByteSize(other.HasItems());

  return MakeGarbageCollected<PhysicalBoxFragment>(
      AdditionalBytes(byte_size), PassKey(), other,
      other.HasScrollableOverflow(), other.ScrollableOverflow());
}

// static
const PhysicalBoxFragment* PhysicalBoxFragment::CloneWithPostLayoutFragments(
    const PhysicalBoxFragment& other) {
  PhysicalRect scrollable_overflow = other.ScrollableOverflow();
  bool has_scrollable_overflow = other.HasScrollableOverflow();

  // The size of the new fragment shouldn't differ from the old one.
  size_t byte_size = AdditionalByteSize(other.HasItems());

  const auto* cloned_fragment = MakeGarbageCollected<PhysicalBoxFragment>(
      AdditionalBytes(byte_size), PassKey(), other, has_scrollable_overflow,
      scrollable_overflow);

  // To ensure the fragment tree is consistent, use the post-layout fragment.
#if DCHECK_IS_ON()
  AllowPostLayoutScope allow_post_layout_scope;
#endif

  for (PhysicalFragmentLink& child :
       cloned_fragment->GetMutableForCloning().Children()) {
    child.fragment = child->PostLayout();
    DCHECK(child.fragment);

    if (!child->IsFragmentainerBox())
      continue;

    // Fragmentainers don't have the concept of post-layout fragments, so if
    // this is a fragmentation context root (such as a multicol container), we
    // need to not only update its children, but also the children of the
    // children that are fragmentainers.
    auto& fragmentainer = *To<PhysicalBoxFragment>(child.fragment.Get());
    for (PhysicalFragmentLink& fragmentainer_child :
         fragmentainer.GetMutableForCloning().Children()) {
      auto& old_child =
          *To<PhysicalBoxFragment>(fragmentainer_child.fragment.Get());
      fragmentainer_child.fragment = old_child.PostLayout();
    }
  }

  if (cloned_fragment->HasItems()) {
    // Replace box fragment items with post layout fragments.
    for (const auto& cloned_item : cloned_fragment->Items()->Items()) {
      const PhysicalBoxFragment* box = cloned_item.BoxFragment();
      if (!box)
        continue;
      box = box->PostLayout();
      DCHECK(box);
      cloned_item.GetMutableForCloning().ReplaceBoxFragment(*box);
    }
  }

  return cloned_fragment;
}

namespace {
template <typename T>
constexpr void AccountSizeAndPadding(size_t& current_size) {
  const size_t current_size_with_padding =
      base::bits::AlignUp(current_size, alignof(T));
  current_size = current_size_with_padding + sizeof(T);
}
}  // namespace

// static
size_t PhysicalBoxFragment::AdditionalByteSize(bool has_fragment_items) {
  size_t additional_size = 0;
  if (has_fragment_items) {
    AccountSizeAndPadding<FragmentItems>(additional_size);
  }
  return additional_size;
}

PhysicalBoxFragment::PhysicalBoxFragment(
    PassKey key,
    BoxFragmentBuilder* builder,
    bool has_scrollable_overflow,
    const PhysicalRect& scrollable_overflow,
    const PhysicalBoxStrut* borders,
    const PhysicalBoxStrut* scrollbar,
    const PhysicalBoxStrut* padding,
    const std::optional<PhysicalRect>& inflow_bounds,
    bool has_fragment_items,
    WritingMode block_or_line_writing_mode)
    : PhysicalFragment(builder,
                       block_or_line_writing_mode,
                       kFragmentBox,
                       builder->GetBoxType()),
      bit_field_(ConstHasFragmentItemsFlag::encode(has_fragment_items) |
                 HasDescendantsForTablePartFlag::encode(false) |
                 IsFragmentationContextRootFlag::encode(
                     builder->is_fragmentation_context_root_) |
                 IsMonolithicFlag::encode(builder->is_monolithic_) |
                 IsMonolithicOverflowPropagationDisabledFlag::encode(
                     builder->GetConstraintSpace()
                         .IsMonolithicOverflowPropagationDisabled()) |
                 HasMovedChildrenInBlockDirectionFlag::encode(
                     builder->has_moved_children_in_block_direction_)) {
  DCHECK(layout_object_);
  DCHECK(layout_object_->IsBoxModelObject());
  DCHECK(!builder->break_token_ || builder->break_token_->IsBlockType());

  children_.resize(builder->children_.size());
  PhysicalSize size = Size();
  const WritingModeConverter converter(
      {block_or_line_writing_mode, builder->Direction()}, size);
  wtf_size_t i = 0;
  for (auto& child : builder->children_) {
    children_[i].offset =
        converter.ToPhysical(child.offset, child.fragment->Size());
    // Fragments in |builder| are not used after |this| was constructed.
    children_[i].fragment = child.fragment.Release();
    ++i;
  }

  if (HasItems()) {
    FragmentItemsBuilder* items_builder = builder->ItemsBuilder();
    auto* items = const_cast<FragmentItems*>(ComputeItemsAddress());
    DCHECK_EQ(items_builder->GetWritingMode(), block_or_line_writing_mode);
    DCHECK_EQ(items_builder->Direction(), builder->Direction());
    std::optional<PhysicalSize> new_size =
        items_builder->ToFragmentItems(Size(), items);
    if (new_size)
      size_ = *new_size;
  }

  SetInkOverflowType(InkOverflow::Type::kNotSet);

  wtf_size_t rare_fields_size =
      has_scrollable_overflow + !!builder->frame_set_layout_data_ +
      !!builder->mathml_paint_info_ + !!builder->table_grid_rect_ +
      !!builder->table_collapsed_borders_ +
      !!builder->table_collapsed_borders_geometry_ +
      !!builder->table_cell_column_index_ +
      (builder->table_section_row_offsets_.empty() ? 0 : 2) +
      !!builder->page_name_ + !!borders + !!scrollbar + !!padding +
      inflow_bounds.has_value() + !!builder->Style().MayHaveMargin();

  if (rare_fields_size > 0 || !builder->table_column_geometries_.empty() ||
      !builder->reading_flow_elements_.empty()) {
    rare_data_ = MakeGarbageCollected<PhysicalFragmentRareData>(
        has_scrollable_overflow ? &scrollable_overflow : nullptr, borders,
        scrollbar, padding, inflow_bounds, *builder, rare_fields_size);
  }

  bit_field_.set<IsFirstForNodeFlag>(builder->is_first_for_node_);
  is_fieldset_container_ = builder->is_fieldset_container_;
  is_table_part_ = builder->is_table_part_;
  is_painted_atomically_ = builder->space_.IsPaintedAtomically();
  PhysicalBoxSides sides_to_include(builder->sides_to_include_,
                                    builder->GetWritingMode());
  bit_field_.set<IncludeBorderTopFlag>(sides_to_include.top);
  bit_field_.set<IncludeBorderRightFlag>(sides_to_include.right);
  bit_field_.set<IncludeBorderBottomFlag>(sides_to_include.bottom);
  bit_field_.set<IncludeBorderLeftFlag>(sides_to_include.left);
  bit_field_.set<IsInlineFormattingContextFlag>(
      builder->is_inline_formatting_context_);
  is_math_fraction_ = builder->is_math_fraction_;
  is_math_operator_ = builder->is_math_operator_;

  const bool allow_baseline = !layout_object_->ShouldApplyLayoutContainment() ||
                              layout_object_->IsTableCell();
  if (allow_baseline && builder->first_baseline_.has_value()) {
    has_first_baseline_ = true;
    first_baseline_ = *builder->first_baseline_;
  } else {
    has_first_baseline_ = false;
    first_baseline_ = LayoutUnit::Min();
  }
  if (allow_baseline && builder->last_baseline_.has_value()) {
    has_last_baseline_ = true;
    last_baseline_ = *builder->last_baseline_;
  } else {
    has_last_baseline_ = false;
    last_baseline_ = LayoutUnit::Min();
  }
  use_last_baseline_for_inline_baseline_ =
      builder->use_last_baseline_for_inline_baseline_;

  bit_field_.set<HasDescendantsForTablePartFlag>(
      children_.size() || NeedsOOFPositionedInfoPropagation());

#if DCHECK_IS_ON()
  CheckIntegrity();
#endif
}

PhysicalBoxFragment::PhysicalBoxFragment(
    PassKey key,
    const PhysicalBoxFragment& other,
    bool has_scrollable_overflow,
    const PhysicalRect& scrollable_overflow)
    : PhysicalFragment(other),
      bit_field_(other.bit_field_),
      first_baseline_(other.first_baseline_),
      last_baseline_(other.last_baseline_),
      ink_overflow_(other.InkOverflowType(), other.ink_overflow_),
      children_(other.children_) {
  SetInkOverflowType(other.InkOverflowType());
  if (HasItems()) {
    auto* items = const_cast<FragmentItems*>(ComputeItemsAddress());
    new (items) FragmentItems(*other.ComputeItemsAddress());
  }
  if (other.rare_data_) {
    rare_data_ =
        MakeGarbageCollected<PhysicalFragmentRareData>(*other.rare_data_);
  }
}

PhysicalBoxFragment::~PhysicalBoxFragment() {
  if (HasInkOverflow())
    SetInkOverflowType(ink_overflow_.Reset(InkOverflowType()));
  if (HasItems())
    ComputeItemsAddress()->~FragmentItems();
}

PhysicalRect PhysicalBoxFragment::ContentRect() const {
  PhysicalRect rect(PhysicalOffset(), Size());
  rect.Contract(Borders() + Padding());
  DCHECK_GE(rect.size.width, LayoutUnit());
  DCHECK_GE(rect.size.height, LayoutUnit());
  return rect;
}

const LayoutBox* PhysicalBoxFragment::OwnerLayoutBox() const {
  // TODO(layout-dev): We should probably get rid of this method, now that it
  // does nothing, apart from some checking. The checks are useful, but could be
  // moved elsewhere.
  const LayoutBox* owner_box =
      DynamicTo<LayoutBox>(GetSelfOrContainerLayoutObject());

#if DCHECK_IS_ON()
  DCHECK(owner_box);
  if (IsFragmentainerBox()) [[unlikely]] {
    if (owner_box->IsLayoutView()) {
      DCHECK_EQ(GetBoxType(), kPageArea);
      DCHECK(To<LayoutView>(owner_box)->ShouldUsePaginatedLayout());
    } else {
      DCHECK(IsColumnBox());
    }
  } else {
    // Check |this| and the |LayoutBox| that produced it are in sync.
    DCHECK(owner_box->PhysicalFragments().Contains(*this));
    DCHECK_EQ(IsFirstForNode(), this == owner_box->GetPhysicalFragment(0));
  }
#endif

  return owner_box;
}

LayoutBox* PhysicalBoxFragment::MutableOwnerLayoutBox() const {
  return const_cast<LayoutBox*>(OwnerLayoutBox());
}

PhysicalOffset PhysicalBoxFragment::OffsetFromOwnerLayoutBox() const {
  DCHECK(IsCSSBox());

  // This function uses |FragmentData|, so must be |kPrePaintClean|.
  DCHECK_GE(GetDocument().Lifecycle().GetState(),
            DocumentLifecycle::kPrePaintClean);

  const LayoutBox* owner_box = OwnerLayoutBox();
  DCHECK(owner_box);
  DCHECK(owner_box->PhysicalFragments().Contains(*this));
  if (owner_box->PhysicalFragmentCount() <= 1)
    return PhysicalOffset();

  // When LTR, compute the offset from the first fragment. The first fragment is
  // at the left top of the |LayoutBox| regardless of the writing mode.
  const auto* containing_block = owner_box->ContainingBlock();
  const ComputedStyle& containing_block_style = containing_block->StyleRef();
  if (IsLtr(containing_block_style.Direction())) {
    DCHECK_EQ(IsFirstForNode(), this == owner_box->GetPhysicalFragment(0));
    if (IsFirstForNode())
      return PhysicalOffset();

    const FragmentData* fragment_data =
        owner_box->FragmentDataFromPhysicalFragment(*this);
    DCHECK(fragment_data);
    const FragmentData& first_fragment_data = owner_box->FirstFragment();
    // All |FragmentData| for an NG block fragmented |LayoutObject| should be in
    // the same transform node that their |PaintOffset()| are in the same
    // coordinate system.
    return fragment_data->PaintOffset() - first_fragment_data.PaintOffset();
  }

  // When RTL, compute the offset from the last fragment.
  const FragmentData* fragment_data =
      owner_box->FragmentDataFromPhysicalFragment(*this);
  DCHECK(fragment_data);
  const FragmentData& last_fragment_data = owner_box->FragmentList().back();
  return fragment_data->PaintOffset() - last_fragment_data.PaintOffset();
}

const PhysicalBoxFragment* PhysicalBoxFragment::PostLayout() const {
  // While side effects are disabled, new fragments are not copied to
  // |LayoutBox|. Just return the given fragment.
  if (DisableLayoutSideEffectsScope::IsDisabled()) {
    return this;
  }

  const LayoutObject* layout_object = GetLayoutObject();
  if (!layout_object) [[unlikely]] {
    // Some fragments don't have a layout object associated directly with
    // them. This is the case for lines and fragmentainers (columns / pages).
    // We don't need to do anything special for such fragments. Any post-layout
    // fragmentainers should be found as children of the post-layout fragments
    // of the containing block.
    //
    // In some cases the layout object may also have been removed. This can of
    // course not happen if we have actually performed layout, but we may in
    // some cases clone a fragment *before* layout, to ensure that the fragment
    // tree spine is correctly rebuilt after a subtree layout.
    return this;
  }
  const auto* box = DynamicTo<LayoutBox>(layout_object);
  if (!box) [[unlikely]] {
    DCHECK(IsInlineBox());
    return this;
  }

  const wtf_size_t fragment_count = box->PhysicalFragmentCount();
  if (fragment_count == 0) [[unlikely]] {
#if DCHECK_IS_ON()
    DCHECK(AllowPostLayoutScope::IsAllowed());
#endif
    return nullptr;
  }

  const PhysicalBoxFragment* post_layout = nullptr;
  if (fragment_count == 1) {
    post_layout = box->GetPhysicalFragment(0);
    DCHECK(post_layout);
  } else if (const auto* break_token = GetBreakToken()) {
    const unsigned index = break_token->SequenceNumber();
    if (index < fragment_count) {
      post_layout = box->GetPhysicalFragment(index);
      DCHECK(post_layout);
      DCHECK(!post_layout->GetBreakToken() ||
             post_layout->GetBreakToken()->SequenceNumber() == index);
    }
  } else {
    post_layout = &box->PhysicalFragments().back();
  }

  if (post_layout == this)
    return this;

// TODO(crbug.com/1241721): Revert https://crrev.com/c/3108806 to re-enable this
// DCHECK on CrOS.
#if DCHECK_IS_ON() && !BUILDFLAG(IS_CHROMEOS_ASH)
  DCHECK(AllowPostLayoutScope::IsAllowed());
#endif
  return post_layout;
}

PhysicalRect PhysicalBoxFragment::SelfInkOverflowRect() const {
  if (!CanUseFragmentsForInkOverflow()) [[unlikely]] {
    const auto* owner_box = DynamicTo<LayoutBox>(GetLayoutObject());
    return owner_box->SelfVisualOverflowRect();
  }
  if (!HasInkOverflow())
    return LocalRect();
  return ink_overflow_.Self(InkOverflowType(), Size());
}

PhysicalRect PhysicalBoxFragment::ContentsInkOverflowRect() const {
  if (!CanUseFragmentsForInkOverflow()) [[unlikely]] {
    const auto* owner_box = DynamicTo<LayoutBox>(GetLayoutObject());
    return owner_box->ContentsVisualOverflowRect();
  }
  if (!HasInkOverflow())
    return LocalRect();
  return ink_overflow_.Contents(InkOverflowType(), Size());
}

PhysicalRect PhysicalBoxFragment::InkOverflowRect() const {
  if (!CanUseFragmentsForInkOverflow()) [[unlikely]] {
    const auto* owner_box = DynamicTo<LayoutBox>(GetLayoutObject());
    return owner_box->VisualOverflowRect();
  }

  if (!HasInkOverflow())
    return LocalRect();

  const PhysicalRect self_rect = ink_overflow_.Self(InkOverflowType(), Size());
  const ComputedStyle& style = Style();
  if (style.HasMask())
    return self_rect;

  const OverflowClipAxes overflow_clip_axes = GetOverflowClipAxes();
  if (overflow_clip_axes == kNoOverflowClip) {
    return UnionRect(self_rect,
                     ink_overflow_.Contents(InkOverflowType(), Size()));
  }

  if (overflow_clip_axes == kOverflowClipBothAxis) {
    if (ShouldApplyOverflowClipMargin()) {
      const PhysicalRect& contents_rect =
          ink_overflow_.Contents(InkOverflowType(), Size());
      if (!contents_rect.IsEmpty()) {
        PhysicalRect result = LocalRect();
        result.Expand(OverflowClipMarginOutsets());
        result.Intersect(contents_rect);
        result.Unite(self_rect);
        return result;
      }
    }
    return self_rect;
  }

  PhysicalRect result = ink_overflow_.Contents(InkOverflowType(), Size());
  result.Unite(self_rect);
  ApplyOverflowClip(overflow_clip_axes, self_rect, &result);
  return result;
}

PhysicalRect PhysicalBoxFragment::OverflowClipRect(
    const PhysicalOffset& location,
    OverlayScrollbarClipBehavior overlay_scrollbar_clip_behavior) const {
  DCHECK(GetLayoutObject() && GetLayoutObject()->IsBox());
  const LayoutBox* box = To<LayoutBox>(GetLayoutObject());
  return box->OverflowClipRect(location, overlay_scrollbar_clip_behavior);
}

PhysicalRect PhysicalBoxFragment::OverflowClipRect(
    const PhysicalOffset& location,
    const BlockBreakToken* incoming_break_token,
    OverlayScrollbarClipBehavior overlay_scrollbar_clip_behavior) const {
  PhysicalRect clip_rect =
      OverflowClipRect(location, overlay_scrollbar_clip_behavior);
  if (!incoming_break_token && !GetBreakToken()) {
    return clip_rect;
  }

  // Clip the stitched box clip rectangle against the
### 提示词
```
这是目录为blink/renderer/core/layout/physical_box_fragment.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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

#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"

#include "build/chromeos_buildflags.h"
#include "third_party/blink/renderer/core/display_lock/display_lock_utilities.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/position_with_affinity.h"
#include "third_party/blink/renderer/core/editing/text_affinity.h"
#include "third_party/blink/renderer/core/html/html_anchor_element.h"
#include "third_party/blink/renderer/core/layout/block_break_token.h"
#include "third_party/blink/renderer/core/layout/box_fragment_builder.h"
#include "third_party/blink/renderer/core/layout/disable_layout_side_effects_scope.h"
#include "third_party/blink/renderer/core/layout/geometry/box_strut.h"
#include "third_party/blink/renderer/core/layout/geometry/physical_rect.h"
#include "third_party/blink/renderer/core/layout/geometry/writing_mode_converter.h"
#include "third_party/blink/renderer/core/layout/inline/fragment_item.h"
#include "third_party/blink/renderer/core/layout/inline/inline_cursor.h"
#include "third_party/blink/renderer/core/layout/inline/inline_item.h"
#include "third_party/blink/renderer/core/layout/inline/physical_line_box_fragment.h"
#include "third_party/blink/renderer/core/layout/layout_block_flow.h"
#include "third_party/blink/renderer/core/layout/layout_inline.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/layout/layout_object_inlines.h"
#include "third_party/blink/renderer/core/layout/layout_text_combine.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/layout/outline_utils.h"
#include "third_party/blink/renderer/core/layout/relative_utils.h"
#include "third_party/blink/renderer/core/layout/table/layout_table_cell.h"
#include "third_party/blink/renderer/core/paint/inline_paint_context.h"
#include "third_party/blink/renderer/core/paint/outline_painter.h"
#include "third_party/blink/renderer/platform/wtf/size_assertions.h"

namespace blink {

#if DCHECK_IS_ON()
unsigned PhysicalBoxFragment::AllowPostLayoutScope::allow_count_ = 0;
#endif

namespace {

struct SameSizeAsPhysicalBoxFragment : PhysicalFragment {
  unsigned flags;
  LayoutUnit baseline;
  LayoutUnit last_baseline;
  Member<void*> rare;
  InkOverflow ink_overflow;
  HeapVector<PhysicalFragmentLink> children;
};

ASSERT_SIZE(PhysicalBoxFragment, SameSizeAsPhysicalBoxFragment);

bool HasControlClip(const PhysicalBoxFragment& self) {
  const LayoutBox* box = DynamicTo<LayoutBox>(self.GetLayoutObject());
  return box && box->HasControlClip();
}

bool ShouldUsePositionForPointInBlockFlowDirection(
    const LayoutObject& layout_object) {
  const LayoutBlockFlow* const layout_block_flow =
      DynamicTo<LayoutBlockFlow>(layout_object);
  if (!layout_block_flow) {
    // For <tr>, see editing/selection/click-before-and-after-table.html
    return false;
  }
  if (layout_block_flow->StyleRef().SpecifiesColumns()) {
    // Columns are laid out in inline direction.
    return false;
  }
  return true;
}

inline bool IsHitTestCandidate(const PhysicalBoxFragment& fragment) {
  return fragment.Size().height &&
         fragment.Style().Visibility() == EVisibility::kVisible &&
         !fragment.IsFloatingOrOutOfFlowPositioned();
}

// Applies the overflow clip to |result|. For any axis that is clipped, |result|
// is reset to |no_overflow_rect|. If neither axis is clipped, nothing is
// changed.
void ApplyOverflowClip(OverflowClipAxes overflow_clip_axes,
                       const PhysicalRect& no_overflow_rect,
                       PhysicalRect* result) {
  if (overflow_clip_axes & kOverflowClipX) {
    result->SetX(no_overflow_rect.X());
    result->SetWidth(no_overflow_rect.Width());
  }
  if (overflow_clip_axes & kOverflowClipY) {
    result->SetY(no_overflow_rect.Y());
    result->SetHeight(no_overflow_rect.Height());
  }
}

}  // namespace

// static
const PhysicalBoxFragment* PhysicalBoxFragment::Create(
    BoxFragmentBuilder* builder,
    WritingMode block_or_line_writing_mode) {
  const auto writing_direction = builder->GetWritingDirection();
  const PhysicalBoxStrut borders =
      builder->ApplicableBorders().ConvertToPhysical(writing_direction);
  const PhysicalBoxStrut scrollbar =
      builder->ApplicableScrollbar().ConvertToPhysical(writing_direction);
  const PhysicalBoxStrut padding =
      builder->ApplicablePadding().ConvertToPhysical(writing_direction);

  const PhysicalSize physical_size =
      ToPhysicalSize(builder->Size(), builder->GetWritingMode());
  WritingModeConverter converter(writing_direction, physical_size);

  std::optional<PhysicalRect> inflow_bounds;
  if (builder->inflow_bounds_)
    inflow_bounds = converter.ToPhysical(*builder->inflow_bounds_);

#if DCHECK_IS_ON()
  if (builder->needs_inflow_bounds_explicitly_set_ && builder->node_ &&
      builder->node_.IsScrollContainer() && !builder->IsFragmentainerBoxType())
    DCHECK(builder->is_inflow_bounds_explicitly_set_);
  if (builder->needs_may_have_descendant_above_block_start_explicitly_set_)
    DCHECK(builder->is_may_have_descendant_above_block_start_explicitly_set_);
#endif

  PhysicalRect scrollable_overflow = {PhysicalOffset(), physical_size};
  if (builder->ShouldCalculateScrollableOverflow()) {
    ScrollableOverflowCalculator calculator(
        To<BlockNode>(builder->node_),
        /* is_css_box */ !builder->IsFragmentainerBoxType(),
        builder->GetConstraintSpace().HasBlockFragmentation(), borders,
        scrollbar, padding, physical_size, writing_direction);

    if (FragmentItemsBuilder* items_builder = builder->ItemsBuilder()) {
      calculator.AddItems(builder->GetLayoutObject(),
                          items_builder->Items(physical_size));
    }

    for (auto& child : builder->children_) {
      const auto* box_fragment =
          DynamicTo<PhysicalBoxFragment>(*child.fragment);
      if (!box_fragment)
        continue;

      calculator.AddChild(*box_fragment, child.offset.ConvertToPhysical(
                                             writing_direction, physical_size,
                                             box_fragment->Size()));
    }

    if (builder->table_collapsed_borders_)
      calculator.AddTableSelfRect();

    scrollable_overflow = calculator.Result(inflow_bounds);
  }

  // For the purposes of object allocation we have scrollable-overflow if it
  // differs from the fragment size.
  bool has_scrollable_overflow =
      scrollable_overflow != PhysicalRect({}, physical_size);

  // Omit |FragmentItems| if there were no items; e.g., display-lock.
  bool has_fragment_items = false;
  if (FragmentItemsBuilder* items_builder = builder->ItemsBuilder()) {
    if (items_builder->Size())
      has_fragment_items = true;
  }

  size_t byte_size = AdditionalByteSize(has_fragment_items);

  // We store the children list inline in the fragment as a flexible
  // array. Therefore, we need to make sure to allocate enough space for
  // that array here, which requires a manual allocation + placement new.
  // The initialization of the array is done by PhysicalFragment;
  // we pass the buffer as a constructor argument.
  return MakeGarbageCollected<PhysicalBoxFragment>(
      AdditionalBytes(byte_size), PassKey(), builder, has_scrollable_overflow,
      scrollable_overflow, borders.IsZero() ? nullptr : &borders,
      scrollbar.IsZero() ? nullptr : &scrollbar,
      padding.IsZero() ? nullptr : &padding, inflow_bounds, has_fragment_items,
      block_or_line_writing_mode);
}

// static
const PhysicalBoxFragment* PhysicalBoxFragment::Clone(
    const PhysicalBoxFragment& other) {
  // The size of the new fragment shouldn't differ from the old one.
  size_t byte_size = AdditionalByteSize(other.HasItems());

  return MakeGarbageCollected<PhysicalBoxFragment>(
      AdditionalBytes(byte_size), PassKey(), other,
      other.HasScrollableOverflow(), other.ScrollableOverflow());
}

// static
const PhysicalBoxFragment* PhysicalBoxFragment::CloneWithPostLayoutFragments(
    const PhysicalBoxFragment& other) {
  PhysicalRect scrollable_overflow = other.ScrollableOverflow();
  bool has_scrollable_overflow = other.HasScrollableOverflow();

  // The size of the new fragment shouldn't differ from the old one.
  size_t byte_size = AdditionalByteSize(other.HasItems());

  const auto* cloned_fragment = MakeGarbageCollected<PhysicalBoxFragment>(
      AdditionalBytes(byte_size), PassKey(), other, has_scrollable_overflow,
      scrollable_overflow);

  // To ensure the fragment tree is consistent, use the post-layout fragment.
#if DCHECK_IS_ON()
  AllowPostLayoutScope allow_post_layout_scope;
#endif

  for (PhysicalFragmentLink& child :
       cloned_fragment->GetMutableForCloning().Children()) {
    child.fragment = child->PostLayout();
    DCHECK(child.fragment);

    if (!child->IsFragmentainerBox())
      continue;

    // Fragmentainers don't have the concept of post-layout fragments, so if
    // this is a fragmentation context root (such as a multicol container), we
    // need to not only update its children, but also the children of the
    // children that are fragmentainers.
    auto& fragmentainer = *To<PhysicalBoxFragment>(child.fragment.Get());
    for (PhysicalFragmentLink& fragmentainer_child :
         fragmentainer.GetMutableForCloning().Children()) {
      auto& old_child =
          *To<PhysicalBoxFragment>(fragmentainer_child.fragment.Get());
      fragmentainer_child.fragment = old_child.PostLayout();
    }
  }

  if (cloned_fragment->HasItems()) {
    // Replace box fragment items with post layout fragments.
    for (const auto& cloned_item : cloned_fragment->Items()->Items()) {
      const PhysicalBoxFragment* box = cloned_item.BoxFragment();
      if (!box)
        continue;
      box = box->PostLayout();
      DCHECK(box);
      cloned_item.GetMutableForCloning().ReplaceBoxFragment(*box);
    }
  }

  return cloned_fragment;
}

namespace {
template <typename T>
constexpr void AccountSizeAndPadding(size_t& current_size) {
  const size_t current_size_with_padding =
      base::bits::AlignUp(current_size, alignof(T));
  current_size = current_size_with_padding + sizeof(T);
}
}  // namespace

// static
size_t PhysicalBoxFragment::AdditionalByteSize(bool has_fragment_items) {
  size_t additional_size = 0;
  if (has_fragment_items) {
    AccountSizeAndPadding<FragmentItems>(additional_size);
  }
  return additional_size;
}

PhysicalBoxFragment::PhysicalBoxFragment(
    PassKey key,
    BoxFragmentBuilder* builder,
    bool has_scrollable_overflow,
    const PhysicalRect& scrollable_overflow,
    const PhysicalBoxStrut* borders,
    const PhysicalBoxStrut* scrollbar,
    const PhysicalBoxStrut* padding,
    const std::optional<PhysicalRect>& inflow_bounds,
    bool has_fragment_items,
    WritingMode block_or_line_writing_mode)
    : PhysicalFragment(builder,
                       block_or_line_writing_mode,
                       kFragmentBox,
                       builder->GetBoxType()),
      bit_field_(ConstHasFragmentItemsFlag::encode(has_fragment_items) |
                 HasDescendantsForTablePartFlag::encode(false) |
                 IsFragmentationContextRootFlag::encode(
                     builder->is_fragmentation_context_root_) |
                 IsMonolithicFlag::encode(builder->is_monolithic_) |
                 IsMonolithicOverflowPropagationDisabledFlag::encode(
                     builder->GetConstraintSpace()
                         .IsMonolithicOverflowPropagationDisabled()) |
                 HasMovedChildrenInBlockDirectionFlag::encode(
                     builder->has_moved_children_in_block_direction_)) {
  DCHECK(layout_object_);
  DCHECK(layout_object_->IsBoxModelObject());
  DCHECK(!builder->break_token_ || builder->break_token_->IsBlockType());

  children_.resize(builder->children_.size());
  PhysicalSize size = Size();
  const WritingModeConverter converter(
      {block_or_line_writing_mode, builder->Direction()}, size);
  wtf_size_t i = 0;
  for (auto& child : builder->children_) {
    children_[i].offset =
        converter.ToPhysical(child.offset, child.fragment->Size());
    // Fragments in |builder| are not used after |this| was constructed.
    children_[i].fragment = child.fragment.Release();
    ++i;
  }

  if (HasItems()) {
    FragmentItemsBuilder* items_builder = builder->ItemsBuilder();
    auto* items = const_cast<FragmentItems*>(ComputeItemsAddress());
    DCHECK_EQ(items_builder->GetWritingMode(), block_or_line_writing_mode);
    DCHECK_EQ(items_builder->Direction(), builder->Direction());
    std::optional<PhysicalSize> new_size =
        items_builder->ToFragmentItems(Size(), items);
    if (new_size)
      size_ = *new_size;
  }

  SetInkOverflowType(InkOverflow::Type::kNotSet);

  wtf_size_t rare_fields_size =
      has_scrollable_overflow + !!builder->frame_set_layout_data_ +
      !!builder->mathml_paint_info_ + !!builder->table_grid_rect_ +
      !!builder->table_collapsed_borders_ +
      !!builder->table_collapsed_borders_geometry_ +
      !!builder->table_cell_column_index_ +
      (builder->table_section_row_offsets_.empty() ? 0 : 2) +
      !!builder->page_name_ + !!borders + !!scrollbar + !!padding +
      inflow_bounds.has_value() + !!builder->Style().MayHaveMargin();

  if (rare_fields_size > 0 || !builder->table_column_geometries_.empty() ||
      !builder->reading_flow_elements_.empty()) {
    rare_data_ = MakeGarbageCollected<PhysicalFragmentRareData>(
        has_scrollable_overflow ? &scrollable_overflow : nullptr, borders,
        scrollbar, padding, inflow_bounds, *builder, rare_fields_size);
  }

  bit_field_.set<IsFirstForNodeFlag>(builder->is_first_for_node_);
  is_fieldset_container_ = builder->is_fieldset_container_;
  is_table_part_ = builder->is_table_part_;
  is_painted_atomically_ = builder->space_.IsPaintedAtomically();
  PhysicalBoxSides sides_to_include(builder->sides_to_include_,
                                    builder->GetWritingMode());
  bit_field_.set<IncludeBorderTopFlag>(sides_to_include.top);
  bit_field_.set<IncludeBorderRightFlag>(sides_to_include.right);
  bit_field_.set<IncludeBorderBottomFlag>(sides_to_include.bottom);
  bit_field_.set<IncludeBorderLeftFlag>(sides_to_include.left);
  bit_field_.set<IsInlineFormattingContextFlag>(
      builder->is_inline_formatting_context_);
  is_math_fraction_ = builder->is_math_fraction_;
  is_math_operator_ = builder->is_math_operator_;

  const bool allow_baseline = !layout_object_->ShouldApplyLayoutContainment() ||
                              layout_object_->IsTableCell();
  if (allow_baseline && builder->first_baseline_.has_value()) {
    has_first_baseline_ = true;
    first_baseline_ = *builder->first_baseline_;
  } else {
    has_first_baseline_ = false;
    first_baseline_ = LayoutUnit::Min();
  }
  if (allow_baseline && builder->last_baseline_.has_value()) {
    has_last_baseline_ = true;
    last_baseline_ = *builder->last_baseline_;
  } else {
    has_last_baseline_ = false;
    last_baseline_ = LayoutUnit::Min();
  }
  use_last_baseline_for_inline_baseline_ =
      builder->use_last_baseline_for_inline_baseline_;

  bit_field_.set<HasDescendantsForTablePartFlag>(
      children_.size() || NeedsOOFPositionedInfoPropagation());

#if DCHECK_IS_ON()
  CheckIntegrity();
#endif
}

PhysicalBoxFragment::PhysicalBoxFragment(
    PassKey key,
    const PhysicalBoxFragment& other,
    bool has_scrollable_overflow,
    const PhysicalRect& scrollable_overflow)
    : PhysicalFragment(other),
      bit_field_(other.bit_field_),
      first_baseline_(other.first_baseline_),
      last_baseline_(other.last_baseline_),
      ink_overflow_(other.InkOverflowType(), other.ink_overflow_),
      children_(other.children_) {
  SetInkOverflowType(other.InkOverflowType());
  if (HasItems()) {
    auto* items = const_cast<FragmentItems*>(ComputeItemsAddress());
    new (items) FragmentItems(*other.ComputeItemsAddress());
  }
  if (other.rare_data_) {
    rare_data_ =
        MakeGarbageCollected<PhysicalFragmentRareData>(*other.rare_data_);
  }
}

PhysicalBoxFragment::~PhysicalBoxFragment() {
  if (HasInkOverflow())
    SetInkOverflowType(ink_overflow_.Reset(InkOverflowType()));
  if (HasItems())
    ComputeItemsAddress()->~FragmentItems();
}

PhysicalRect PhysicalBoxFragment::ContentRect() const {
  PhysicalRect rect(PhysicalOffset(), Size());
  rect.Contract(Borders() + Padding());
  DCHECK_GE(rect.size.width, LayoutUnit());
  DCHECK_GE(rect.size.height, LayoutUnit());
  return rect;
}

const LayoutBox* PhysicalBoxFragment::OwnerLayoutBox() const {
  // TODO(layout-dev): We should probably get rid of this method, now that it
  // does nothing, apart from some checking. The checks are useful, but could be
  // moved elsewhere.
  const LayoutBox* owner_box =
      DynamicTo<LayoutBox>(GetSelfOrContainerLayoutObject());

#if DCHECK_IS_ON()
  DCHECK(owner_box);
  if (IsFragmentainerBox()) [[unlikely]] {
    if (owner_box->IsLayoutView()) {
      DCHECK_EQ(GetBoxType(), kPageArea);
      DCHECK(To<LayoutView>(owner_box)->ShouldUsePaginatedLayout());
    } else {
      DCHECK(IsColumnBox());
    }
  } else {
    // Check |this| and the |LayoutBox| that produced it are in sync.
    DCHECK(owner_box->PhysicalFragments().Contains(*this));
    DCHECK_EQ(IsFirstForNode(), this == owner_box->GetPhysicalFragment(0));
  }
#endif

  return owner_box;
}

LayoutBox* PhysicalBoxFragment::MutableOwnerLayoutBox() const {
  return const_cast<LayoutBox*>(OwnerLayoutBox());
}

PhysicalOffset PhysicalBoxFragment::OffsetFromOwnerLayoutBox() const {
  DCHECK(IsCSSBox());

  // This function uses |FragmentData|, so must be |kPrePaintClean|.
  DCHECK_GE(GetDocument().Lifecycle().GetState(),
            DocumentLifecycle::kPrePaintClean);

  const LayoutBox* owner_box = OwnerLayoutBox();
  DCHECK(owner_box);
  DCHECK(owner_box->PhysicalFragments().Contains(*this));
  if (owner_box->PhysicalFragmentCount() <= 1)
    return PhysicalOffset();

  // When LTR, compute the offset from the first fragment. The first fragment is
  // at the left top of the |LayoutBox| regardless of the writing mode.
  const auto* containing_block = owner_box->ContainingBlock();
  const ComputedStyle& containing_block_style = containing_block->StyleRef();
  if (IsLtr(containing_block_style.Direction())) {
    DCHECK_EQ(IsFirstForNode(), this == owner_box->GetPhysicalFragment(0));
    if (IsFirstForNode())
      return PhysicalOffset();

    const FragmentData* fragment_data =
        owner_box->FragmentDataFromPhysicalFragment(*this);
    DCHECK(fragment_data);
    const FragmentData& first_fragment_data = owner_box->FirstFragment();
    // All |FragmentData| for an NG block fragmented |LayoutObject| should be in
    // the same transform node that their |PaintOffset()| are in the same
    // coordinate system.
    return fragment_data->PaintOffset() - first_fragment_data.PaintOffset();
  }

  // When RTL, compute the offset from the last fragment.
  const FragmentData* fragment_data =
      owner_box->FragmentDataFromPhysicalFragment(*this);
  DCHECK(fragment_data);
  const FragmentData& last_fragment_data = owner_box->FragmentList().back();
  return fragment_data->PaintOffset() - last_fragment_data.PaintOffset();
}

const PhysicalBoxFragment* PhysicalBoxFragment::PostLayout() const {
  // While side effects are disabled, new fragments are not copied to
  // |LayoutBox|. Just return the given fragment.
  if (DisableLayoutSideEffectsScope::IsDisabled()) {
    return this;
  }

  const LayoutObject* layout_object = GetLayoutObject();
  if (!layout_object) [[unlikely]] {
    // Some fragments don't have a layout object associated directly with
    // them. This is the case for lines and fragmentainers (columns / pages).
    // We don't need to do anything special for such fragments. Any post-layout
    // fragmentainers should be found as children of the post-layout fragments
    // of the containing block.
    //
    // In some cases the layout object may also have been removed. This can of
    // course not happen if we have actually performed layout, but we may in
    // some cases clone a fragment *before* layout, to ensure that the fragment
    // tree spine is correctly rebuilt after a subtree layout.
    return this;
  }
  const auto* box = DynamicTo<LayoutBox>(layout_object);
  if (!box) [[unlikely]] {
    DCHECK(IsInlineBox());
    return this;
  }

  const wtf_size_t fragment_count = box->PhysicalFragmentCount();
  if (fragment_count == 0) [[unlikely]] {
#if DCHECK_IS_ON()
    DCHECK(AllowPostLayoutScope::IsAllowed());
#endif
    return nullptr;
  }

  const PhysicalBoxFragment* post_layout = nullptr;
  if (fragment_count == 1) {
    post_layout = box->GetPhysicalFragment(0);
    DCHECK(post_layout);
  } else if (const auto* break_token = GetBreakToken()) {
    const unsigned index = break_token->SequenceNumber();
    if (index < fragment_count) {
      post_layout = box->GetPhysicalFragment(index);
      DCHECK(post_layout);
      DCHECK(!post_layout->GetBreakToken() ||
             post_layout->GetBreakToken()->SequenceNumber() == index);
    }
  } else {
    post_layout = &box->PhysicalFragments().back();
  }

  if (post_layout == this)
    return this;

// TODO(crbug.com/1241721): Revert https://crrev.com/c/3108806 to re-enable this
// DCHECK on CrOS.
#if DCHECK_IS_ON() && !BUILDFLAG(IS_CHROMEOS_ASH)
  DCHECK(AllowPostLayoutScope::IsAllowed());
#endif
  return post_layout;
}

PhysicalRect PhysicalBoxFragment::SelfInkOverflowRect() const {
  if (!CanUseFragmentsForInkOverflow()) [[unlikely]] {
    const auto* owner_box = DynamicTo<LayoutBox>(GetLayoutObject());
    return owner_box->SelfVisualOverflowRect();
  }
  if (!HasInkOverflow())
    return LocalRect();
  return ink_overflow_.Self(InkOverflowType(), Size());
}

PhysicalRect PhysicalBoxFragment::ContentsInkOverflowRect() const {
  if (!CanUseFragmentsForInkOverflow()) [[unlikely]] {
    const auto* owner_box = DynamicTo<LayoutBox>(GetLayoutObject());
    return owner_box->ContentsVisualOverflowRect();
  }
  if (!HasInkOverflow())
    return LocalRect();
  return ink_overflow_.Contents(InkOverflowType(), Size());
}

PhysicalRect PhysicalBoxFragment::InkOverflowRect() const {
  if (!CanUseFragmentsForInkOverflow()) [[unlikely]] {
    const auto* owner_box = DynamicTo<LayoutBox>(GetLayoutObject());
    return owner_box->VisualOverflowRect();
  }

  if (!HasInkOverflow())
    return LocalRect();

  const PhysicalRect self_rect = ink_overflow_.Self(InkOverflowType(), Size());
  const ComputedStyle& style = Style();
  if (style.HasMask())
    return self_rect;

  const OverflowClipAxes overflow_clip_axes = GetOverflowClipAxes();
  if (overflow_clip_axes == kNoOverflowClip) {
    return UnionRect(self_rect,
                     ink_overflow_.Contents(InkOverflowType(), Size()));
  }

  if (overflow_clip_axes == kOverflowClipBothAxis) {
    if (ShouldApplyOverflowClipMargin()) {
      const PhysicalRect& contents_rect =
          ink_overflow_.Contents(InkOverflowType(), Size());
      if (!contents_rect.IsEmpty()) {
        PhysicalRect result = LocalRect();
        result.Expand(OverflowClipMarginOutsets());
        result.Intersect(contents_rect);
        result.Unite(self_rect);
        return result;
      }
    }
    return self_rect;
  }

  PhysicalRect result = ink_overflow_.Contents(InkOverflowType(), Size());
  result.Unite(self_rect);
  ApplyOverflowClip(overflow_clip_axes, self_rect, &result);
  return result;
}

PhysicalRect PhysicalBoxFragment::OverflowClipRect(
    const PhysicalOffset& location,
    OverlayScrollbarClipBehavior overlay_scrollbar_clip_behavior) const {
  DCHECK(GetLayoutObject() && GetLayoutObject()->IsBox());
  const LayoutBox* box = To<LayoutBox>(GetLayoutObject());
  return box->OverflowClipRect(location, overlay_scrollbar_clip_behavior);
}

PhysicalRect PhysicalBoxFragment::OverflowClipRect(
    const PhysicalOffset& location,
    const BlockBreakToken* incoming_break_token,
    OverlayScrollbarClipBehavior overlay_scrollbar_clip_behavior) const {
  PhysicalRect clip_rect =
      OverflowClipRect(location, overlay_scrollbar_clip_behavior);
  if (!incoming_break_token && !GetBreakToken()) {
    return clip_rect;
  }

  // Clip the stitched box clip rectangle against the bounds of the fragment.
  //
  // TODO(layout-dev): It's most likely better to actually store the clip
  // rectangle in each fragment, rather than post-processing the stitched clip
  // rectangle like this.
  auto writing_direction = Style().GetWritingDirection();
  const LayoutBox* box = To<LayoutBox>(GetLayoutObject());
  WritingModeConverter converter(writing_direction, PhysicalSize(box->Size()));
  // Make the clip rectangle relative to the layout box.
  clip_rect.offset -= location;
  LogicalOffset stitched_offset;
  if (incoming_break_token)
    stitched_offset.block_offset = incoming_break_token->ConsumedBlockSize();
  LogicalRect logical_fragment_rect(
      stitched_offset,
      Size().ConvertToLogical(writing_direction.GetWritingMode()));
  PhysicalRect physical_fragment_rect =
      converter.ToPhysical(logical_fragment_rect);

  // For monolithic descendants that get sliced (for certain values of "sliced";
  // keep on reading) when printing, we will keep the stitched box clip
  // rectangle, and just translate it so that it becomes relative to this
  // fragment. The problem this addresses is the fact that monolithic
  // descendants only get sliced visually and overflow nicely into the next
  // pages, whereas, internally, a monolithic element always generates only one
  // fragment. If we clip it strictly against the originating fragment, we risk
  // losing content.
  //
  // This is a work-around for the fact that we never break monolithic content
  // into fragments (which the spec actually suggests that we do in such cases).
  //
  // This work-around only makes sense when printing, since pages are simply
  // stacked in the writing direction internally when printing, so that
  // overflowing content from one page "accidentally" ends up at the right place
  // on the next page. This isn't the case for multicol for instance (where this
  // problem is "unfixable" unless we implement support for breaking monolithic
  // content into fragments), so if we're not printing, clip it against the
  // bounds of the fragment now.
  if (!GetDocument().Printing()) {
    const auto overflow_clip = box->GetOverflowClipAxes();
    PhysicalRect overflow_physical_fragment_rect = physical_fragment_rect;
    if (overflow_clip != kOverflowClipBothAxis) {
      ApplyVisibleOverflowToClipRect(overflow_clip,
                                     overflow_physical_fragment_rect);
    } else if (box->ShouldApplyOverflowClipMargin()) {
      overflow_physical_fragment_rect.Expand(OverflowClipMarginOutsets());
    }

    // Clip against the fragment's bounds.
    clip_rect.Intersect(overflow_physical_fragment_rect);
  }

  // Make the clip rectangle relative to the fragment.
  clip_rect.offset -= physical_fragment_rect.offset;
  // Make the clip rectangle relative to whatever the caller wants.
  clip_rect.offset += location;
  return clip_rect;
}

bool PhysicalBoxFragment::MayIntersect(
    const HitTestResult& result,
    const HitTestLocation& hit_test_location,
    const PhysicalOffset& accumulated_offset) const {
  if (const auto* box = DynamicTo<LayoutBox>(GetLayoutObject()))
    return box->MayIntersect(result, hit_test_location, accumulated_offset);
  // TODO(kojii): (!IsCSSBox() || IsInlineBox()) is not supported yet. Implement
  // if needed. For now, just return |true| not to do early return.
  return true;
}

gfx::Vector2d PhysicalBoxFragment::PixelSnappedScrolledContentOffset() const {
  DCHECK(GetLayoutObject());
  return To<LayoutBox>(*GetLayoutObject()).PixelSnappedScrolledContentOffset();
}

PhysicalSize PhysicalBoxFragment::ScrollSize() const {
  DCHECK(GetLayoutObject());
  const LayoutBox* box = To<LayoutBox>(GetLayoutObject());
  return {box->ScrollWidth(), box->ScrollHeight()};
}

const PhysicalBoxFragment*
PhysicalBoxFragment::InlineContainerFragmentIfOutlineOwner() const {
  DCHECK(IsInlineBox());
  // In order to compute united outlines, collect all rectangles of inline
  // fragments for |LayoutInline| if |this| is the first inline fragment.
  // Otherwise return none.
  const LayoutObject* layout_object = GetLayoutObject();
  DCHECK(layout_object);
  DCHECK(layout_object->IsLayoutInline());
  InlineCursor cursor;
  cursor.MoveTo(*layout_object);
  DCHECK(cursor);
  if (cursor.Current().BoxFragment() == this)
    return &cursor.ContainerFragment();
  if (!cursor.IsBlockFragmented())
    return nullptr;

  // When |LayoutInline| is block fragmented, unite rectangles for each block
  // fragment. To do this, return |true| if |this| is the first inline fragment
  // of a block fragment.
  for (wtf_size_t previous_fragment_index = cursor.ContainerFragmentIndex();;) {
    cursor.MoveToNextForSameLayoutObject();
    DCHECK(cursor);
    const wtf_size_t fragment_index = cursor.ContainerFragmentIndex();
    if (cursor.Current().BoxFragment() == this) {
      if (fragment_index != previous_fragment_index)
        return &cursor.ContainerFragment();
      return nullptr;
    }
    previous_fragment_index = fragment_index;
  }
}

PhysicalFragmentRareData::RareField& PhysicalBoxFragment::EnsureRareField(
    FieldId id) {
  if (!rare_data_) {
    rare_data_ = MakeGarbageCollected<PhysicalFragmentRareData>(1);
  }
  return rare_data_->EnsureField(id);
}

PhysicalBoxFragment::MutableForStyleRecalc::MutableForStyleRecalc(
    base::PassKey<PhysicalBoxFragment>,
    PhysicalBoxFragment& fragment)
    : fragment_(fragment) {}

void PhysicalBoxFragment::MutableForStyleRecalc::SetScrollableOverflow(
    const PhysicalRect& scrollable_overflow) {
  bool has_scrollable_overflow =
      scrollable_overflow != PhysicalRect({}, fragment_.Size());
  if (has_scrollable_overflow) {
    // This can be called even without rare_data_.
    fragment_.EnsureRareField(FieldId::kScrollableOverflow)
        .scrollable_overflow = scrollable_overflow;
  } else if (fragment_.HasScrollableOverflow()) {
    fragment_.rare_data_->RemoveField(FieldId::kScrollableOverflow);
  }
}

PhysicalBoxFragment::MutableForStyleRecalc
PhysicalBoxFragment::GetMutableForStyleRecalc() const {
  DCHECK(layout_object_->GetDocument().Lifecycle().GetState() ==
             DocumentLifecycle::kInStyleRecalc ||
         layout_object_->GetDocument().Lifecycle().GetState() ==
             DocumentLifecycle::kInPerformLayout);
  return MutableForStyleRecalc(base::PassKey<PhysicalBoxFragment>(),
                               const_cast<PhysicalBoxFragment&>(*this));
}

PhysicalBoxFragment::MutableForContainerLayout::MutableForContainerLayout(
    base::PassKey<PhysicalBoxFragment>,
    PhysicalBoxFragment& fragment)
    : fragment_(fragment) {}

void PhysicalBoxFragment::MutableForContainerLayout::SetMargins(
    const PhysicalBoxStrut& margins) {
  // This can be called even without rare_data_.
  fragment_.EnsureRareField(FieldId::kMargins).margins = margins;
}

PhysicalBoxFragment::MutableForContainerLayout
PhysicalBoxFragment::GetMutableForContainerLayout() const {
  DCHECK(layout_object_->GetFrameView()->IsInPerformLayout());
  return MutableForContainerLayout(base::PassKey<PhysicalBoxFragment>(),
                                   const_cast<PhysicalBoxFragment&>(*this));
}

void PhysicalBoxFragment::MutableForOofFragmentation::AddChildFragmentainer(
    const PhysicalBoxFragment& child_fragment,
    LogicalOffset child_offset) {
  // We should only end up here when updating a nested multicol container that
  // has already being laid out, to add new fragmentainers to hold OOFs.
  DCHECK(fragment_.IsFragmentationContextRoot());
  DCHECK(child_fragment.IsFragmentainerBox());

  WritingModeConverter converter(fragment_.Style().GetWritingDirection(),
                                 fragment_.Size());
  PhysicalFragmentLink link;
  link.offset = converter.ToPhysical(child_offset, child_fragment.Size());
  link.fragment = &child_fragment;
  fragment_.children_.push_back(link);
}

void PhysicalBoxFragment::MutableForOofFragmentation::Merge(
    const PhysicalBoxFragment& placeholder_fragmentainer) {
  DCHECK(placeholder_fragmentainer.IsFragmentainerBox());

  // Copy all child fragments.
  for (const PhysicalFragmentLink& new_child :
       placeholder_fragmentainer.children_) {
    fragment_.children_.push_back(new_child);
```