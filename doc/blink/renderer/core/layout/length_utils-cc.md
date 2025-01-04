Response:
The user wants to understand the functionality of the `length_utils.cc` file in the Chromium Blink rendering engine. I need to:

1. **List the functionalities:**  Identify the core purposes of the functions defined in the code. This will likely involve resolving lengths based on different constraints and style properties.
2. **Relate to web technologies (JS, HTML, CSS):** Explain how these functionalities connect to the behavior of web pages, providing concrete examples.
3. **Demonstrate logical reasoning:** If any functions involve calculations or conditional logic, provide hypothetical inputs and outputs to illustrate their behavior.
4. **Highlight common usage errors:** Identify potential mistakes developers might make that this code helps handle or prevent.
5. **Summarize the overall functionality:** Provide a concise overview of the file's main purpose.

Based on the code, the file seems to be primarily focused on resolving different types of CSS length values (like pixels, percentages, `auto`, `min-content`, `max-content`, `fit-content`) in various layout contexts. It considers factors like:

* **Constraint Space:** Available width and height, writing mode, etc.
* **Computed Style:** CSS properties like `width`, `height`, `min-width`, `max-width`, `box-sizing`, `aspect-ratio`.
* **Box Strut:** Border and padding sizes.
* **Intrinsic Sizes:** Minimum and maximum content sizes of elements.

Let's break down the functions and their roles:

* **`ResolveInlineLengthInternal` and `ResolveBlockLengthInternal`:** These are core functions for calculating the resolved size of an element in the inline (horizontal) and block (vertical) directions, respectively. They handle different length types and consider constraints.
* **`InlineSizeFromAspectRatio` and `BlockSizeFromAspectRatio`:** These calculate sizes based on an element's aspect ratio.
* **`ComputeMinAndMaxContentContribution*`:** These functions determine the minimum and maximum content sizes an element contributes to its parent, taking into account writing modes, replaced elements, and aspect ratios.
* **`ComputeInlineSizeForFragment` and `ComputeUsedInlineSizeForTableFragment`:**  These calculate the inline size of a layout fragment, especially considering tables.
* **`ComputeInitialMinMaxBlockSizes` and `ComputeMinMaxBlockSizes`:** These compute the minimum and maximum block sizes based on specified properties and available space.
* **`ComputeTransferredMinMaxInlineSizes` and `ComputeTransferredMinMaxBlockSizes`:** These functions handle the transfer of min/max sizes based on aspect ratios.
* **`ComputeMinMaxInlineSizesFromAspectRatio`:** Specifically calculates min/max inline sizes when an aspect ratio is present.
* **`ComputeMinMaxInlineSizes`:** A more general function for calculating min/max inline sizes, considering aspect ratios.
* **`ComputeBlockSizeForFragmentInternal`:** Calculates the block size of a fragment.

Now, I can formulate the response based on these observations.
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/length_utils.h"

#include <algorithm>
#include <optional>

#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/layout/block_node.h"
#include "third_party/blink/renderer/core/layout/constraint_space.h"
#include "third_party/blink/renderer/core/layout/constraint_space_builder.h"
#include "third_party/blink/renderer/core/layout/fragmentation_utils.h"
#include "third_party/blink/renderer/core/layout/geometry/box_strut.h"
#include "third_party/blink/renderer/core/layout/geometry/logical_size.h"
#include "third_party/blink/renderer/core/layout/layout_box.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/layout/space_utils.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_root.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/platform/geometry/layout_unit.h"
#include "third_party/blink/renderer/platform/geometry/length.h"
#include "third_party/blink/renderer/platform/geometry/length_functions.h"

namespace blink {

LayoutUnit ResolveInlineLengthInternal(
    const ConstraintSpace& constraint_space,
    const ComputedStyle& style,
    const BoxStrut& border_padding,
    MinMaxSizesFunctionRef min_max_sizes_func,
    const Length& original_length,
    const Length* auto_length,
    LengthTypeInternal length_type,
    LayoutUnit override_available_size,
    CalcSizeKeywordBehavior calc_size_keyword_behavior) {
  DCHECK_EQ(constraint_space.GetWritingMode(), style.GetWritingMode());

  // For min-inline-size, this might still be 'auto'.
  const Length& length =
      original_length.IsAuto() && auto_length ? *auto_length : original_length;
  switch (length.GetType()) {
    case Length::kStretch: {
      const LayoutUnit available_size =
          override_available_size == kIndefiniteSize
              ? constraint_space.AvailableSize().inline_size
              : override_available_size;
      if (available_size == kIndefiniteSize) {
        return kIndefiniteSize;
      }
      DCHECK_GE(available_size, LayoutUnit());
      const BoxStrut margins = ComputeMarginsForSelf(constraint_space, style);
      return std::max(border_padding.InlineSum(),
                      available_size - margins.InlineSum());
    }
    case Length::kPercent:
    case Length::kFixed:
    case Length::kCalculated: {
      const LayoutUnit percentage_resolution_size =
          constraint_space.PercentageResolutionInlineSize();
      if (length.HasPercent() &&
          percentage_resolution_size == kIndefiniteSize) {
        return kIndefiniteSize;
      }
      bool evaluated_indefinite = false;
      LayoutUnit value = MinimumValueForLength(
          length, percentage_resolution_size,
          {.intrinsic_evaluator =
               [&](const Length& length_to_evaluate) {
                 LayoutUnit result = ResolveInlineLengthInternal(
                     constraint_space, style, border_padding,
                     min_max_sizes_func, length_to_evaluate, auto_length,
                     length_type, override_available_size,
                     calc_size_keyword_behavior);
                 if (result == kIndefiniteSize) {
                   evaluated_indefinite = true;
                   return kIndefiniteSize;
                 }
                 if (style.BoxSizing() == EBoxSizing::kContentBox) {
                   result -= border_padding.InlineSum();
                 }
                 DCHECK_GE(result, LayoutUnit());
                 return result;
               },
           .calc_size_keyword_behavior = calc_size_keyword_behavior});

      if (evaluated_indefinite) {
        return kIndefiniteSize;
      }

      if (style.BoxSizing() == EBoxSizing::kBorderBox)
        value = std::max(border_padding.InlineSum(), value);
      else
        value += border_padding.InlineSum();
      return value;
    }
    case Length::kContent:
    case Length::kMaxContent:
      return min_max_sizes_func(SizeType::kContent).sizes.max_size;
    case Length::kMinContent:
      return min_max_sizes_func(SizeType::kContent).sizes.min_size;
    case Length::kMinIntrinsic:
      return min_max_sizes_func(SizeType::kIntrinsic).sizes.min_size;
    case Length::kFitContent: {
      const LayoutUnit available_size =
          override_available_size == kIndefiniteSize
              ? constraint_space.AvailableSize().inline_size
              : override_available_size;

      // fit-content resolves differently depending on the type of length.
      if (available_size == kIndefiniteSize) {
        switch (length_type) {
          case LengthTypeInternal::kMin:
            return min_max_sizes_func(SizeType::kContent).sizes.min_size;
          case LengthTypeInternal::kMain:
            return kIndefiniteSize;
          case LengthTypeInternal::kMax:
            return min_max_sizes_func(SizeType::kContent).sizes.max_size;
        }
      }
      DCHECK_GE(available_size, LayoutUnit());

      const BoxStrut margins = ComputeMarginsForSelf(constraint_space, style);
      return min_max_sizes_func(SizeType::kContent)
          .sizes.ShrinkToFit(
              (available_size - margins.InlineSum()).ClampNegativeToZero());
    }
    case Length::kAuto:
    case Length::kNone:
      return kIndefiniteSize;
    case Length::kFlex:
      NOTREACHED() << "Should only be used for grid.";
    case Length::kDeviceWidth:
    case Length::kDeviceHeight:
    case Length::kExtendToZoom:
      NOTREACHED() << "Should only be used for viewport definitions.";
  }
}

LayoutUnit ResolveBlockLengthInternal(
    const ConstraintSpace& constraint_space,
    const ComputedStyle& style,
    const BoxStrut& border_padding,
    const Length& original_length,
    const Length* auto_length,
    LengthTypeInternal length_type,
    LayoutUnit override_available_size,
    const LayoutUnit* override_percentage_resolution_size,
    BlockSizeFunctionRef block_size_func) {
  DCHECK_EQ(constraint_space.GetWritingMode(), style.GetWritingMode());

  // For min-block-size, this might still be 'auto'.
  const Length& length =
      original_length.IsAuto() && auto_length ? *auto_length : original_length;
  switch (length.GetType()) {
    case Length::kStretch: {
      const LayoutUnit available_size =
          override_available_size == kIndefiniteSize
              ? constraint_space.AvailableSize().block_size
              : override_available_size;
      if (available_size == kIndefiniteSize) {
        return length_type == LengthTypeInternal::kMain
                   ? block_size_func(SizeType::kContent)
                   : kIndefiniteSize;
      }
      DCHECK_GE(available_size, LayoutUnit());
      const BoxStrut margins = ComputeMarginsForSelf(constraint_space, style);
      return std::max(border_padding.BlockSum(),
                      available_size - margins.BlockSum());
    }
    case Length::kPercent:
    case Length::kFixed:
    case Length::kCalculated: {
      const LayoutUnit percentage_resolution_size =
          override_percentage_resolution_size
              ? *override_percentage_resolution_size
              : constraint_space.PercentageResolutionBlockSize();
      if (length.HasPercent() &&
          percentage_resolution_size == kIndefiniteSize) {
        return length_type == LengthTypeInternal::kMain
                   ? block_size_func(SizeType::kContent)
                   : kIndefiniteSize;
      }
      bool evaluated_indefinite = false;
      LayoutUnit value = MinimumValueForLength(
          length, percentage_resolution_size,
          {.intrinsic_evaluator = [&](const Length& length_to_evaluate) {
            LayoutUnit result = ResolveBlockLengthInternal(
                constraint_space, style, border_padding, length_to_evaluate,
                auto_length, length_type, override_available_size,
                override_percentage_resolution_size, block_size_func);
            if (result == kIndefiniteSize) {
              evaluated_indefinite = true;
              return kIndefiniteSize;
            }
            if (style.BoxSizing() == EBoxSizing::kContentBox) {
              result -= border_padding.BlockSum();
            }
            DCHECK_GE(result, LayoutUnit());
            return result;
          }});

      if (evaluated_indefinite) {
        return kIndefiniteSize;
      }

      if (style.BoxSizing() == EBoxSizing::kBorderBox)
        value = std::max(border_padding.BlockSum(), value);
      else
        value += border_padding.BlockSum();
      return value;
    }
    case Length::kContent:
    case Length::kMinContent:
    case Length::kMaxContent:
    case Length::kMinIntrinsic:
    case Length::kFitContent: {
      const LayoutUnit intrinsic_size = block_size_func(
          length.IsMinIntrinsic() ? SizeType::kIntrinsic : SizeType::kContent);
#if DCHECK_IS_ON()
      // Due to how intrinsic_size is calculated, it should always include
      // border and padding. We cannot check for this if we are
      // block-fragmented, though, because then the block-start border/padding
      // may be in a different fragmentainer than the block-end border/padding.
      if (intrinsic_size != kIndefiniteSize &&
          !constraint_space.HasBlockFragmentation())
        DCHECK_GE(intrinsic_size, border_padding.BlockSum());
#endif  // DCHECK_IS_ON()
      return intrinsic_size;
    }
    case Length::kAuto:
    case Length::kNone:
      return kIndefiniteSize;
    case Length::kFlex:
      NOTREACHED() << "Should only be used for grid.";
    case Length::kDeviceWidth:
    case Length::kDeviceHeight:
    case Length::kExtendToZoom:
      NOTREACHED() << "Should only be used for viewport definitions.";
  }
}

LayoutUnit InlineSizeFromAspectRatio(const BoxStrut& border_padding,
                                     const LogicalSize& aspect_ratio,
                                     EBoxSizing box_sizing,
                                     LayoutUnit block_size) {
  if (box_sizing == EBoxSizing::kBorderBox) {
    return std::max(
        border_padding.InlineSum(),
        block_size.MulDiv(aspect_ratio.inline_size, aspect_ratio.block_size));
  }
  block_size -= border_padding.BlockSum();
  return block_size.MulDiv(aspect_ratio.inline_size, aspect_ratio.block_size) +
         border_padding.InlineSum();
}

LayoutUnit BlockSizeFromAspectRatio(const BoxStrut& border_padding,
                                    const LogicalSize& aspect_ratio,
                                    EBoxSizing box_sizing,
                                    LayoutUnit inline_size) {
  DCHECK_GE(inline_size, border_padding.InlineSum());
  if (box_sizing == EBoxSizing::kBorderBox) {
    return std::max(
        border_padding.BlockSum(),
        inline_size.MulDiv(aspect_ratio.block_size, aspect_ratio.inline_size));
  }
  inline_size -= border_padding.InlineSum();
  return inline_size.MulDiv(aspect_ratio.block_size, aspect_ratio.inline_size) +
         border_padding.BlockSum();
}

namespace {

// Currently this simply sets the correct override sizes for the replaced
// element, and lets legacy layout do the result.
MinMaxSizesResult ComputeMinAndMaxContentContributionForReplaced(
    const BlockNode& child,
    const ConstraintSpace& space) {
  const auto& child_style = child.Style();
  const BoxStrut border_padding =
      ComputeBorders(space, child) + ComputePadding(space, child_style);

  MinMaxSizes result;
  result = ComputeReplacedSize(child, space, border_padding).inline_size;

  if (child_style.LogicalWidth().HasPercent() ||
      child_style.LogicalMaxWidth().HasPercent()) {
    // TODO(ikilpatrick): No browser does this today, but we'd get slightly
    // better results here if we also considered the min-block size, and
    // transferred through the aspect-ratio (if available).
    result.min_size = ResolveMinInlineLength(
        space, child_style, border_padding,
        [&](SizeType) -> MinMaxSizesResult {
          // Behave the same as if we couldn't resolve the min-inline size.
          MinMaxSizes sizes;
          sizes = border_padding.InlineSum();
          return {sizes, /* depends_on_block_constraints */ false};
        },
        child_style.LogicalMinWidth());
  }

  // Replaced elements which have a percentage block-size always depend on
  // their block constraints (as they have an aspect-ratio which changes their
  // min/max content size).
  // TODO(https://crbug.com/40339056): These should also check for 'stretch'
  // values. (We could add Length::MayHaveStretchOrPercentDependence or
  // similar.)
  const bool depends_on_block_constraints =
      child_style.LogicalHeight().MayHavePercentDependence() ||
      child_style.LogicalMinHeight().MayHavePercentDependence() ||
      child_style.LogicalMaxHeight().MayHavePercentDependence() ||
      (child_style.LogicalHeight().HasAuto() &&
       space.IsBlockAutoBehaviorStretch());
  return MinMaxSizesResult(result, depends_on_block_constraints);
}

}  // namespace

MinMaxSizesResult ComputeMinAndMaxContentContributionInternal(
    WritingMode parent_writing_mode,
    const BlockNode& child,
    const ConstraintSpace& space,
    MinMaxSizesFunctionRef original_min_max_sizes_func) {
  const auto& style = child.Style();
  const auto border_padding =
      ComputeBorders(space, child) + ComputePadding(space, style);

  // First check if we are an orthogonal writing-mode root, then attempt to
  // resolve the block-size.
  if (!IsParallelWritingMode(parent_writing_mode, style.GetWritingMode())) {
    const LayoutUnit block_size = ComputeBlockSizeForFragment(
        space, child, border_padding, /* intrinsic_size */ kIndefiniteSize,
        /* inline_size */ kIndefiniteSize);

    // If we weren't able to resolve the block-size, or we might have intrinsic
    // constraints, just perform a full layout via the callback.
    if (block_size == kIndefiniteSize ||
        style.LogicalMinHeight().HasContentOrIntrinsic() ||
        style.LogicalMaxHeight().HasContentOrIntrinsic() || child.IsTable()) {
      return original_min_max_sizes_func(SizeType::kContent);
    }

    return {{block_size, block_size}, /* depends_on_block_constraints */ false};
  }

  // Intercept the min/max sizes function so we can access both the
  // `depends_on_block_constraints` and `applied_aspect_ratio` variables.
  bool depends_on_block_constraints = false;
  bool applied_aspect_ratio = false;
  auto min_max_sizes_func = [&](SizeType type) {
    const MinMaxSizesResult result = original_min_max_sizes_func(type);
    depends_on_block_constraints |= result.depends_on_block_constraints;
    applied_aspect_ratio |= result.applied_aspect_ratio;
    return result;
  };

  DCHECK_EQ(space.AvailableSize().inline_size, kIndefiniteSize);

  // First attempt to resolve the main-length, if we can't resolve (e.g. a
  // percentage, or similar) it'll return a kIndefiniteSize.
  const Length& main_length = style.LogicalWidth();
  const LayoutUnit extent =
      ResolveMainInlineLength(space, style, border_padding, min_max_sizes_func,
                              main_length, &Length::FitContent());

  // If we successfully resolved our main size, just use that as the
  // contribution, otherwise invoke the callback.
  MinMaxSizes sizes = (extent == kIndefiniteSize)
                          ? min_max_sizes_func(SizeType::kContent).sizes
                          : MinMaxSizes{extent, extent};

  // If we have calc-size() with a sizing-keyword of auto/fit-content/stretch
  // we need to perform an additional step. Treat the sizing-keyword as auto,
  // then resolve auto as both min-content, and max-content.
  if (main_length.IsCalculated() &&
      (main_length.HasAuto() || main_length.HasFitContent() ||
       main_length.HasStretch())) {
    sizes.min_size = ResolveMainInlineLength(
        space, style, border_padding, min_max_sizes_func, main_length,
        /* auto_length */ &Length::MinContent(),
        /* override_available_size */ kIndefiniteSize,
        CalcSizeKeywordBehavior::kAsAuto);
    sizes.max_size = ResolveMainInlineLength(
        space, style, border_padding, min_max_sizes_func, main_length,
        /* auto_length */ &Length::MaxContent(),
        /* override_available_size */ kIndefiniteSize,
        CalcSizeKeywordBehavior::kAsAuto);
  }

  // Check if we should apply the automatic minimum size.
  // https://drafts.csswg.org/css-sizing-4/#aspect-ratio-minimum
  const bool apply_automatic_min_size =
      !style.IsScrollContainer() && applied_aspect_ratio;

  const MinMaxSizes min_max_sizes = ComputeMinMaxInlineSizes(
      space, child, border_padding,
      apply_automatic_min_size ? &Length::MinIntrinsic() : nullptr,
      min_max_sizes_func);
  sizes.Constrain(min_max_sizes.max_size);
  sizes.Encompass(min_max_sizes.min_size);

  return {sizes, depends_on_block_constraints};
}

MinMaxSizesResult ComputeMinAndMaxContentContribution(
    const ComputedStyle& parent_style,
    const BlockNode& child,
    const ConstraintSpace& space,
    const MinMaxSizesFloatInput float_input) {
  const auto& child_style = child.Style();
  const auto parent_writing_mode = parent_style.GetWritingMode();
  const auto child_writing_mode = child_style.GetWritingMode();

  if (IsParallelWritingMode(parent_writing_mode, child_writing_mode)) {
    if (child.IsReplaced())
      return ComputeMinAndMaxContentContributionForReplaced(child, space);
  }

  auto MinMaxSizesFunc = [&](SizeType type) -> MinMaxSizesResult {
    return child.ComputeMinMaxSizes(parent_writing_mode, type, space,
                                    float_input);
  };

  return ComputeMinAndMaxContentContributionInternal(parent_writing_mode, child,
                                                     space, MinMaxSizesFunc);
}

MinMaxSizesResult ComputeMinAndMaxContentContributionForSelf(
    const BlockNode& child,
    const ConstraintSpace& space) {
  DCHECK(child.CreatesNewFormattingContext());

  const ComputedStyle& child_style = child.Style();
  WritingMode writing_mode = child_style.GetWritingMode();

  if (child.IsReplaced())
    return ComputeMinAndMaxContentContributionForReplaced(child, space);

  auto MinMaxSizesFunc = [&](SizeType type) -> MinMaxSizesResult {
    return child.ComputeMinMaxSizes(writing_mode, type, space);
  };

  return ComputeMinAndMaxContentContributionInternal(writing_mode, child, space,
                                                     MinMaxSizesFunc);
}

MinMaxSizesResult ComputeMinAndMaxContentContributionForSelf(
    const BlockNode& child,
    const ConstraintSpace& space,
    MinMaxSizesFunctionRef min_max_sizes_func) {
  DCHECK(child.CreatesNewFormattingContext());

  return child.IsReplaced()
             ? ComputeMinAndMaxContentContributionForReplaced(child, space)
             : ComputeMinAndMaxContentContributionInternal(
                   child.Style().GetWritingMode(), child, space,
                   min_max_sizes_func);
}

MinMaxSizes ComputeMinAndMaxContentContributionForTest(
    WritingMode parent_writing_mode,
    const BlockNode& child,
    const ConstraintSpace& space,
    const MinMaxSizes& min_max_sizes) {
  auto MinMaxSizesFunc = [&](SizeType) -> MinMaxSizesResult {
    return MinMaxSizesResult(min_max_sizes,
                             /* depends_on_block_constraints */ false);
  };
  return ComputeMinAndMaxContentContributionInternal(parent_writing_mode, child,
                                                     space, MinMaxSizesFunc)
      .sizes;
}

LayoutUnit ComputeInlineSizeForFragmentInternal(
    const ConstraintSpace& space,
    const BlockNode& node,
    const BoxStrut& border_padding,
    MinMaxSizesFunctionRef min_max_sizes_func) {
  const auto& style = node.Style();
  const Length& logical_width = style.LogicalWidth();

  const bool may_apply_aspect_ratio = ([&]() {
    if (style.AspectRatio().IsAuto()) {
      return false;
    }

    // Even though an implicit stretch will resolve - we prefer the inline-axis
    // size for this case.
    if (style.LogicalHeight().HasAuto() &&
        space.BlockAutoBehavior() != AutoSizeBehavior::kStretchExplicit) {
      return false;
    }

    // If we can resolve our block-size with no intrinsic-size we can use our
    // aspect-ratio.
    return ComputeBlockSizeForFragment(space, node, border_padding,
                                       /* intrinsic_size */ kIndefiniteSize,
                                       /* inline_size */ kIndefiniteSize) !=
           kIndefiniteSize;
  })();

  const Length& auto_length = ([&]() {
    if (space.AvailableSize().inline_size == kIndefiniteSize) {
      return Length::MinContent();
    }
    if (space.InlineAutoBehavior() == AutoSizeBehavior::kStretchExplicit) {
      return Length::Stretch();
    }
    if (may_apply_aspect_ratio) {
      return Length::FitContent();
    }
    if (space.InlineAutoBehavior() == AutoSizeBehavior::kStretchImplicit) {
      return Length::Stretch();
    }
    DCHECK_EQ(space.InlineAutoBehavior(), AutoSizeBehavior::kFitContent);
    return Length::FitContent();
  })();

  // Check if we should apply the automatic minimum size.
  // https://drafts.csswg.org/css-sizing-4/#aspect-ratio-minimum
  bool apply_automatic_min_size = ([&]() {
    if (style.IsScrollContainer()) {
      return false;
    }
    if (!may_apply_aspect_ratio) {
      return false;
    }
    if (logical_width.HasContentOrIntrinsic()) {
      return true;
    }
    if (logical_width.HasAuto() && auto_length.HasContentOrIntrinsic()) {
      return true;
    }
    return false;
  })();

  const LayoutUnit extent =
      ResolveMainInlineLength(space, style, border_padding, min_max_sizes_func,
                              logical_width, &auto_length);

  return ComputeMinMaxInlineSizes(
             space, node, border_padding,
             apply_automatic_min_size ? &Length::MinIntrinsic() : nullptr,
             min_max_sizes_func)
      .ClampSizeToMinAndMax(extent);
}

LayoutUnit ComputeInlineSizeForFragment(
    const ConstraintSpace& space,
    const BlockNode& node,
    const BoxStrut& border_padding,
    MinMaxSizesFunctionRef min_max_sizes_func) {
  if (space.IsFixedInlineSize() || space.IsAnonymous()) {
    return space.AvailableSize().inline_size;
  }

  if (node.IsTable()) {
    return To<TableNode>(node).ComputeTableInlineSize(space, border_padding);
  }

  return ComputeInlineSizeForFragmentInternal(space, node, border_padding,
                                              min_max_sizes_func);
}

LayoutUnit ComputeUsedInlineSizeForTableFragment(
    const ConstraintSpace& space,
    const BlockNode& node,
    const BoxStrut& border_padding,
    const MinMaxSizes& table_grid_min_max_sizes) {
  DCHECK(!space.IsFixedInlineSize());

  auto MinMaxSizesFunc = [&](SizeType type) -> MinMaxSizesResult {
    const auto& style = node.Style();
    const bool has_aspect_ratio = !style.AspectRatio().IsAuto();

    // Check if we have an aspect-ratio.
    if (has_aspect_ratio && type == SizeType::kContent) {
      const LayoutUnit block_size =
          ComputeBlockSizeForFragment(space, node, border_padding,
                                      /* intrinsic_size */ kIndefiniteSize,
                                      /* inline_size */ kIndefiniteSize);
      if (block_size != kIndefiniteSize) {
        const LayoutUnit inline_size = InlineSizeFromAspectRatio(
            border_padding, style.LogicalAspectRatio(),
            style.BoxSizingForAspectRatio(), block_size);
        return MinMaxSizesResult({inline_size, inline_size},
                                 /* depends_on_block_constraints */ false);
      }
    }
    return MinMaxSizesResult(table_grid_min_max_sizes,
                             /* depends_on_block_constraints */ false);
  };

  return ComputeInlineSizeForFragmentInternal(space, node, border_padding,
                                              MinMaxSizesFunc);
}

MinMaxSizes ComputeInitialMinMaxBlockSizes(const ConstraintSpace& space,
                                           const BlockNode& node,
                                           const BoxStrut& border_padding) {
  const ComputedStyle& style = node.Style();
  MinMaxSizes sizes = {
      ResolveInitialMinBlockLength(space, style, border_padding,
                                   style.LogicalMinHeight()),
      ResolveInitialMaxBlockLength(space, style, border_padding,
                                   style.LogicalMaxHeight())};
  sizes.max_size = std::max(sizes.max_size, sizes.min_size);
  return sizes;
}

MinMaxSizes ComputeMinMaxBlockSizes(const ConstraintSpace& space,
                                    const BlockNode& node,
                                    const BoxStrut& border_padding,
                                    const Length* auto_min_length,
                                    BlockSizeFunctionRef block_size_func,
                                    LayoutUnit override_available_size) {
  const ComputedStyle& style = node.Style();
  MinMaxSizes sizes = {
      ResolveMinBlockLength(space, style, border_padding, block_size_func,
                            style.LogicalMinHeight(), auto_min_length,
                            override_available_size),
      ResolveMaxBlockLength(space, style, border_padding,
                            style.LogicalMaxHeight(), block_size_func,
                            override_available_size)};

  // Clamp the auto min-size by the max-size.
  if (auto_min_length && style.LogicalMinHeight().HasAuto()) {
    sizes.min_size = std::min(sizes.min_size, sizes.max_size);
  }

  // Tables can't shrink below their min-intrinsic size.
  if (node.IsTable()) {
    sizes.Encompass(block_size_func(SizeType::kIntrinsic));
  }

  sizes.max_size = std::max(sizes.max_size, sizes.min_size);
  return sizes;
}

MinMaxSizes ComputeTransferredMinMaxInlineSizes(
    const LogicalSize& ratio,
    const MinMaxSizes& block_min_max,
    const BoxStrut& border_padding,
    const EBoxSizing sizing) {
  MinMaxSizes transferred_min_max = {LayoutUnit(), LayoutUnit::Max()};
  if (block_min_max.min_size > LayoutUnit()) {
    transferred_min_max.min_size = InlineSizeFromAspectRatio(
        border_padding, ratio, sizing, block_min_max.min_size);
  }
  if (block_min_max.max_size != LayoutUnit::Max()) {
    transferred_min_max.max_size = InlineSizeFromAspectRatio(
        border_padding, ratio, sizing, block_min_max.max_size);
  }
  // Minimum size wins over maximum size.
  transferred_min_max.max_size =
      std::max(transferred_min_max.max_size, transferred_min_max.min_size);
  return transferred_min_max;
}

MinMaxSizes ComputeTransferredMinMaxBlockSizes(
    const LogicalSize& ratio,
    const MinMaxSizes& inline_min_max,
    const BoxStrut& border_padding,
    const EBoxSizing sizing) {
  MinMaxSizes transferred_min_max = {LayoutUnit(), LayoutUnit::Max()};
  if (inline_min_max.min_size > LayoutUnit()) {
    transferred_min_max.min_size = BlockSizeFromAspectRatio(
        border_padding, ratio, sizing, inline_min_max.min_size);
  }
  if (inline_min_max.max_size != LayoutUnit::Max()) {
    transferred_min_max.max_size = BlockSizeFromAspectRatio(
        border_padding, ratio, sizing, inline_min_max.max_size);
  }
  // Minimum size wins over maximum size.
  transferred_min_max.max_size =
      std::max(transferred_min_max.max_size, transferred_min_max.min_size);
  return transferred_min_max;
}

MinMaxSizes ComputeMinMaxInlineSizesFromAspectRatio(
    const ConstraintSpace& constraint_space,
    const BlockNode& node,
    const BoxStrut& border_padding) {
  // The spec requires us to clamp these by the specified size (it calls it the
  // preferred size). However, we actually don't need to worry about that,
  // because we only use this if the width is indefinite.

  // We do not need to compute the min/max inline sizes; as long as we always
  // apply the transferred min/max size before the
Prompt: 
```
这是目录为blink/renderer/core/layout/length_utils.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/length_utils.h"

#include <algorithm>
#include <optional>

#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/layout/block_node.h"
#include "third_party/blink/renderer/core/layout/constraint_space.h"
#include "third_party/blink/renderer/core/layout/constraint_space_builder.h"
#include "third_party/blink/renderer/core/layout/fragmentation_utils.h"
#include "third_party/blink/renderer/core/layout/geometry/box_strut.h"
#include "third_party/blink/renderer/core/layout/geometry/logical_size.h"
#include "third_party/blink/renderer/core/layout/layout_box.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/layout/space_utils.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_root.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/platform/geometry/layout_unit.h"
#include "third_party/blink/renderer/platform/geometry/length.h"
#include "third_party/blink/renderer/platform/geometry/length_functions.h"

namespace blink {

LayoutUnit ResolveInlineLengthInternal(
    const ConstraintSpace& constraint_space,
    const ComputedStyle& style,
    const BoxStrut& border_padding,
    MinMaxSizesFunctionRef min_max_sizes_func,
    const Length& original_length,
    const Length* auto_length,
    LengthTypeInternal length_type,
    LayoutUnit override_available_size,
    CalcSizeKeywordBehavior calc_size_keyword_behavior) {
  DCHECK_EQ(constraint_space.GetWritingMode(), style.GetWritingMode());

  // For min-inline-size, this might still be 'auto'.
  const Length& length =
      original_length.IsAuto() && auto_length ? *auto_length : original_length;
  switch (length.GetType()) {
    case Length::kStretch: {
      const LayoutUnit available_size =
          override_available_size == kIndefiniteSize
              ? constraint_space.AvailableSize().inline_size
              : override_available_size;
      if (available_size == kIndefiniteSize) {
        return kIndefiniteSize;
      }
      DCHECK_GE(available_size, LayoutUnit());
      const BoxStrut margins = ComputeMarginsForSelf(constraint_space, style);
      return std::max(border_padding.InlineSum(),
                      available_size - margins.InlineSum());
    }
    case Length::kPercent:
    case Length::kFixed:
    case Length::kCalculated: {
      const LayoutUnit percentage_resolution_size =
          constraint_space.PercentageResolutionInlineSize();
      if (length.HasPercent() &&
          percentage_resolution_size == kIndefiniteSize) {
        return kIndefiniteSize;
      }
      bool evaluated_indefinite = false;
      LayoutUnit value = MinimumValueForLength(
          length, percentage_resolution_size,
          {.intrinsic_evaluator =
               [&](const Length& length_to_evaluate) {
                 LayoutUnit result = ResolveInlineLengthInternal(
                     constraint_space, style, border_padding,
                     min_max_sizes_func, length_to_evaluate, auto_length,
                     length_type, override_available_size,
                     calc_size_keyword_behavior);
                 if (result == kIndefiniteSize) {
                   evaluated_indefinite = true;
                   return kIndefiniteSize;
                 }
                 if (style.BoxSizing() == EBoxSizing::kContentBox) {
                   result -= border_padding.InlineSum();
                 }
                 DCHECK_GE(result, LayoutUnit());
                 return result;
               },
           .calc_size_keyword_behavior = calc_size_keyword_behavior});

      if (evaluated_indefinite) {
        return kIndefiniteSize;
      }

      if (style.BoxSizing() == EBoxSizing::kBorderBox)
        value = std::max(border_padding.InlineSum(), value);
      else
        value += border_padding.InlineSum();
      return value;
    }
    case Length::kContent:
    case Length::kMaxContent:
      return min_max_sizes_func(SizeType::kContent).sizes.max_size;
    case Length::kMinContent:
      return min_max_sizes_func(SizeType::kContent).sizes.min_size;
    case Length::kMinIntrinsic:
      return min_max_sizes_func(SizeType::kIntrinsic).sizes.min_size;
    case Length::kFitContent: {
      const LayoutUnit available_size =
          override_available_size == kIndefiniteSize
              ? constraint_space.AvailableSize().inline_size
              : override_available_size;

      // fit-content resolves differently depending on the type of length.
      if (available_size == kIndefiniteSize) {
        switch (length_type) {
          case LengthTypeInternal::kMin:
            return min_max_sizes_func(SizeType::kContent).sizes.min_size;
          case LengthTypeInternal::kMain:
            return kIndefiniteSize;
          case LengthTypeInternal::kMax:
            return min_max_sizes_func(SizeType::kContent).sizes.max_size;
        }
      }
      DCHECK_GE(available_size, LayoutUnit());

      const BoxStrut margins = ComputeMarginsForSelf(constraint_space, style);
      return min_max_sizes_func(SizeType::kContent)
          .sizes.ShrinkToFit(
              (available_size - margins.InlineSum()).ClampNegativeToZero());
    }
    case Length::kAuto:
    case Length::kNone:
      return kIndefiniteSize;
    case Length::kFlex:
      NOTREACHED() << "Should only be used for grid.";
    case Length::kDeviceWidth:
    case Length::kDeviceHeight:
    case Length::kExtendToZoom:
      NOTREACHED() << "Should only be used for viewport definitions.";
  }
}

LayoutUnit ResolveBlockLengthInternal(
    const ConstraintSpace& constraint_space,
    const ComputedStyle& style,
    const BoxStrut& border_padding,
    const Length& original_length,
    const Length* auto_length,
    LengthTypeInternal length_type,
    LayoutUnit override_available_size,
    const LayoutUnit* override_percentage_resolution_size,
    BlockSizeFunctionRef block_size_func) {
  DCHECK_EQ(constraint_space.GetWritingMode(), style.GetWritingMode());

  // For min-block-size, this might still be 'auto'.
  const Length& length =
      original_length.IsAuto() && auto_length ? *auto_length : original_length;
  switch (length.GetType()) {
    case Length::kStretch: {
      const LayoutUnit available_size =
          override_available_size == kIndefiniteSize
              ? constraint_space.AvailableSize().block_size
              : override_available_size;
      if (available_size == kIndefiniteSize) {
        return length_type == LengthTypeInternal::kMain
                   ? block_size_func(SizeType::kContent)
                   : kIndefiniteSize;
      }
      DCHECK_GE(available_size, LayoutUnit());
      const BoxStrut margins = ComputeMarginsForSelf(constraint_space, style);
      return std::max(border_padding.BlockSum(),
                      available_size - margins.BlockSum());
    }
    case Length::kPercent:
    case Length::kFixed:
    case Length::kCalculated: {
      const LayoutUnit percentage_resolution_size =
          override_percentage_resolution_size
              ? *override_percentage_resolution_size
              : constraint_space.PercentageResolutionBlockSize();
      if (length.HasPercent() &&
          percentage_resolution_size == kIndefiniteSize) {
        return length_type == LengthTypeInternal::kMain
                   ? block_size_func(SizeType::kContent)
                   : kIndefiniteSize;
      }
      bool evaluated_indefinite = false;
      LayoutUnit value = MinimumValueForLength(
          length, percentage_resolution_size,
          {.intrinsic_evaluator = [&](const Length& length_to_evaluate) {
            LayoutUnit result = ResolveBlockLengthInternal(
                constraint_space, style, border_padding, length_to_evaluate,
                auto_length, length_type, override_available_size,
                override_percentage_resolution_size, block_size_func);
            if (result == kIndefiniteSize) {
              evaluated_indefinite = true;
              return kIndefiniteSize;
            }
            if (style.BoxSizing() == EBoxSizing::kContentBox) {
              result -= border_padding.BlockSum();
            }
            DCHECK_GE(result, LayoutUnit());
            return result;
          }});

      if (evaluated_indefinite) {
        return kIndefiniteSize;
      }

      if (style.BoxSizing() == EBoxSizing::kBorderBox)
        value = std::max(border_padding.BlockSum(), value);
      else
        value += border_padding.BlockSum();
      return value;
    }
    case Length::kContent:
    case Length::kMinContent:
    case Length::kMaxContent:
    case Length::kMinIntrinsic:
    case Length::kFitContent: {
      const LayoutUnit intrinsic_size = block_size_func(
          length.IsMinIntrinsic() ? SizeType::kIntrinsic : SizeType::kContent);
#if DCHECK_IS_ON()
      // Due to how intrinsic_size is calculated, it should always include
      // border and padding. We cannot check for this if we are
      // block-fragmented, though, because then the block-start border/padding
      // may be in a different fragmentainer than the block-end border/padding.
      if (intrinsic_size != kIndefiniteSize &&
          !constraint_space.HasBlockFragmentation())
        DCHECK_GE(intrinsic_size, border_padding.BlockSum());
#endif  // DCHECK_IS_ON()
      return intrinsic_size;
    }
    case Length::kAuto:
    case Length::kNone:
      return kIndefiniteSize;
    case Length::kFlex:
      NOTREACHED() << "Should only be used for grid.";
    case Length::kDeviceWidth:
    case Length::kDeviceHeight:
    case Length::kExtendToZoom:
      NOTREACHED() << "Should only be used for viewport definitions.";
  }
}

LayoutUnit InlineSizeFromAspectRatio(const BoxStrut& border_padding,
                                     const LogicalSize& aspect_ratio,
                                     EBoxSizing box_sizing,
                                     LayoutUnit block_size) {
  if (box_sizing == EBoxSizing::kBorderBox) {
    return std::max(
        border_padding.InlineSum(),
        block_size.MulDiv(aspect_ratio.inline_size, aspect_ratio.block_size));
  }
  block_size -= border_padding.BlockSum();
  return block_size.MulDiv(aspect_ratio.inline_size, aspect_ratio.block_size) +
         border_padding.InlineSum();
}

LayoutUnit BlockSizeFromAspectRatio(const BoxStrut& border_padding,
                                    const LogicalSize& aspect_ratio,
                                    EBoxSizing box_sizing,
                                    LayoutUnit inline_size) {
  DCHECK_GE(inline_size, border_padding.InlineSum());
  if (box_sizing == EBoxSizing::kBorderBox) {
    return std::max(
        border_padding.BlockSum(),
        inline_size.MulDiv(aspect_ratio.block_size, aspect_ratio.inline_size));
  }
  inline_size -= border_padding.InlineSum();
  return inline_size.MulDiv(aspect_ratio.block_size, aspect_ratio.inline_size) +
         border_padding.BlockSum();
}

namespace {

// Currently this simply sets the correct override sizes for the replaced
// element, and lets legacy layout do the result.
MinMaxSizesResult ComputeMinAndMaxContentContributionForReplaced(
    const BlockNode& child,
    const ConstraintSpace& space) {
  const auto& child_style = child.Style();
  const BoxStrut border_padding =
      ComputeBorders(space, child) + ComputePadding(space, child_style);

  MinMaxSizes result;
  result = ComputeReplacedSize(child, space, border_padding).inline_size;

  if (child_style.LogicalWidth().HasPercent() ||
      child_style.LogicalMaxWidth().HasPercent()) {
    // TODO(ikilpatrick): No browser does this today, but we'd get slightly
    // better results here if we also considered the min-block size, and
    // transferred through the aspect-ratio (if available).
    result.min_size = ResolveMinInlineLength(
        space, child_style, border_padding,
        [&](SizeType) -> MinMaxSizesResult {
          // Behave the same as if we couldn't resolve the min-inline size.
          MinMaxSizes sizes;
          sizes = border_padding.InlineSum();
          return {sizes, /* depends_on_block_constraints */ false};
        },
        child_style.LogicalMinWidth());
  }

  // Replaced elements which have a percentage block-size always depend on
  // their block constraints (as they have an aspect-ratio which changes their
  // min/max content size).
  // TODO(https://crbug.com/40339056): These should also check for 'stretch'
  // values.  (We could add Length::MayHaveStretchOrPercentDependence or
  // similar.)
  const bool depends_on_block_constraints =
      child_style.LogicalHeight().MayHavePercentDependence() ||
      child_style.LogicalMinHeight().MayHavePercentDependence() ||
      child_style.LogicalMaxHeight().MayHavePercentDependence() ||
      (child_style.LogicalHeight().HasAuto() &&
       space.IsBlockAutoBehaviorStretch());
  return MinMaxSizesResult(result, depends_on_block_constraints);
}

}  // namespace

MinMaxSizesResult ComputeMinAndMaxContentContributionInternal(
    WritingMode parent_writing_mode,
    const BlockNode& child,
    const ConstraintSpace& space,
    MinMaxSizesFunctionRef original_min_max_sizes_func) {
  const auto& style = child.Style();
  const auto border_padding =
      ComputeBorders(space, child) + ComputePadding(space, style);

  // First check if we are an orthogonal writing-mode root, then attempt to
  // resolve the block-size.
  if (!IsParallelWritingMode(parent_writing_mode, style.GetWritingMode())) {
    const LayoutUnit block_size = ComputeBlockSizeForFragment(
        space, child, border_padding, /* intrinsic_size */ kIndefiniteSize,
        /* inline_size */ kIndefiniteSize);

    // If we weren't able to resolve the block-size, or we might have intrinsic
    // constraints, just perform a full layout via the callback.
    if (block_size == kIndefiniteSize ||
        style.LogicalMinHeight().HasContentOrIntrinsic() ||
        style.LogicalMaxHeight().HasContentOrIntrinsic() || child.IsTable()) {
      return original_min_max_sizes_func(SizeType::kContent);
    }

    return {{block_size, block_size}, /* depends_on_block_constraints */ false};
  }

  // Intercept the min/max sizes function so we can access both the
  // `depends_on_block_constraints` and `applied_aspect_ratio` variables.
  bool depends_on_block_constraints = false;
  bool applied_aspect_ratio = false;
  auto min_max_sizes_func = [&](SizeType type) {
    const MinMaxSizesResult result = original_min_max_sizes_func(type);
    depends_on_block_constraints |= result.depends_on_block_constraints;
    applied_aspect_ratio |= result.applied_aspect_ratio;
    return result;
  };

  DCHECK_EQ(space.AvailableSize().inline_size, kIndefiniteSize);

  // First attempt to resolve the main-length, if we can't resolve (e.g. a
  // percentage, or similar) it'll return a kIndefiniteSize.
  const Length& main_length = style.LogicalWidth();
  const LayoutUnit extent =
      ResolveMainInlineLength(space, style, border_padding, min_max_sizes_func,
                              main_length, &Length::FitContent());

  // If we successfully resolved our main size, just use that as the
  // contribution, otherwise invoke the callback.
  MinMaxSizes sizes = (extent == kIndefiniteSize)
                          ? min_max_sizes_func(SizeType::kContent).sizes
                          : MinMaxSizes{extent, extent};

  // If we have calc-size() with a sizing-keyword of auto/fit-content/stretch
  // we need to perform an additional step. Treat the sizing-keyword as auto,
  // then resolve auto as both min-content, and max-content.
  if (main_length.IsCalculated() &&
      (main_length.HasAuto() || main_length.HasFitContent() ||
       main_length.HasStretch())) {
    sizes.min_size = ResolveMainInlineLength(
        space, style, border_padding, min_max_sizes_func, main_length,
        /* auto_length */ &Length::MinContent(),
        /* override_available_size */ kIndefiniteSize,
        CalcSizeKeywordBehavior::kAsAuto);
    sizes.max_size = ResolveMainInlineLength(
        space, style, border_padding, min_max_sizes_func, main_length,
        /* auto_length */ &Length::MaxContent(),
        /* override_available_size */ kIndefiniteSize,
        CalcSizeKeywordBehavior::kAsAuto);
  }

  // Check if we should apply the automatic minimum size.
  // https://drafts.csswg.org/css-sizing-4/#aspect-ratio-minimum
  const bool apply_automatic_min_size =
      !style.IsScrollContainer() && applied_aspect_ratio;

  const MinMaxSizes min_max_sizes = ComputeMinMaxInlineSizes(
      space, child, border_padding,
      apply_automatic_min_size ? &Length::MinIntrinsic() : nullptr,
      min_max_sizes_func);
  sizes.Constrain(min_max_sizes.max_size);
  sizes.Encompass(min_max_sizes.min_size);

  return {sizes, depends_on_block_constraints};
}

MinMaxSizesResult ComputeMinAndMaxContentContribution(
    const ComputedStyle& parent_style,
    const BlockNode& child,
    const ConstraintSpace& space,
    const MinMaxSizesFloatInput float_input) {
  const auto& child_style = child.Style();
  const auto parent_writing_mode = parent_style.GetWritingMode();
  const auto child_writing_mode = child_style.GetWritingMode();

  if (IsParallelWritingMode(parent_writing_mode, child_writing_mode)) {
    if (child.IsReplaced())
      return ComputeMinAndMaxContentContributionForReplaced(child, space);
  }

  auto MinMaxSizesFunc = [&](SizeType type) -> MinMaxSizesResult {
    return child.ComputeMinMaxSizes(parent_writing_mode, type, space,
                                    float_input);
  };

  return ComputeMinAndMaxContentContributionInternal(parent_writing_mode, child,
                                                     space, MinMaxSizesFunc);
}

MinMaxSizesResult ComputeMinAndMaxContentContributionForSelf(
    const BlockNode& child,
    const ConstraintSpace& space) {
  DCHECK(child.CreatesNewFormattingContext());

  const ComputedStyle& child_style = child.Style();
  WritingMode writing_mode = child_style.GetWritingMode();

  if (child.IsReplaced())
    return ComputeMinAndMaxContentContributionForReplaced(child, space);

  auto MinMaxSizesFunc = [&](SizeType type) -> MinMaxSizesResult {
    return child.ComputeMinMaxSizes(writing_mode, type, space);
  };

  return ComputeMinAndMaxContentContributionInternal(writing_mode, child, space,
                                                     MinMaxSizesFunc);
}

MinMaxSizesResult ComputeMinAndMaxContentContributionForSelf(
    const BlockNode& child,
    const ConstraintSpace& space,
    MinMaxSizesFunctionRef min_max_sizes_func) {
  DCHECK(child.CreatesNewFormattingContext());

  return child.IsReplaced()
             ? ComputeMinAndMaxContentContributionForReplaced(child, space)
             : ComputeMinAndMaxContentContributionInternal(
                   child.Style().GetWritingMode(), child, space,
                   min_max_sizes_func);
}

MinMaxSizes ComputeMinAndMaxContentContributionForTest(
    WritingMode parent_writing_mode,
    const BlockNode& child,
    const ConstraintSpace& space,
    const MinMaxSizes& min_max_sizes) {
  auto MinMaxSizesFunc = [&](SizeType) -> MinMaxSizesResult {
    return MinMaxSizesResult(min_max_sizes,
                             /* depends_on_block_constraints */ false);
  };
  return ComputeMinAndMaxContentContributionInternal(parent_writing_mode, child,
                                                     space, MinMaxSizesFunc)
      .sizes;
}

LayoutUnit ComputeInlineSizeForFragmentInternal(
    const ConstraintSpace& space,
    const BlockNode& node,
    const BoxStrut& border_padding,
    MinMaxSizesFunctionRef min_max_sizes_func) {
  const auto& style = node.Style();
  const Length& logical_width = style.LogicalWidth();

  const bool may_apply_aspect_ratio = ([&]() {
    if (style.AspectRatio().IsAuto()) {
      return false;
    }

    // Even though an implicit stretch will resolve - we prefer the inline-axis
    // size for this case.
    if (style.LogicalHeight().HasAuto() &&
        space.BlockAutoBehavior() != AutoSizeBehavior::kStretchExplicit) {
      return false;
    }

    // If we can resolve our block-size with no intrinsic-size we can use our
    // aspect-ratio.
    return ComputeBlockSizeForFragment(space, node, border_padding,
                                       /* intrinsic_size */ kIndefiniteSize,
                                       /* inline_size */ kIndefiniteSize) !=
           kIndefiniteSize;
  })();

  const Length& auto_length = ([&]() {
    if (space.AvailableSize().inline_size == kIndefiniteSize) {
      return Length::MinContent();
    }
    if (space.InlineAutoBehavior() == AutoSizeBehavior::kStretchExplicit) {
      return Length::Stretch();
    }
    if (may_apply_aspect_ratio) {
      return Length::FitContent();
    }
    if (space.InlineAutoBehavior() == AutoSizeBehavior::kStretchImplicit) {
      return Length::Stretch();
    }
    DCHECK_EQ(space.InlineAutoBehavior(), AutoSizeBehavior::kFitContent);
    return Length::FitContent();
  })();

  // Check if we should apply the automatic minimum size.
  // https://drafts.csswg.org/css-sizing-4/#aspect-ratio-minimum
  bool apply_automatic_min_size = ([&]() {
    if (style.IsScrollContainer()) {
      return false;
    }
    if (!may_apply_aspect_ratio) {
      return false;
    }
    if (logical_width.HasContentOrIntrinsic()) {
      return true;
    }
    if (logical_width.HasAuto() && auto_length.HasContentOrIntrinsic()) {
      return true;
    }
    return false;
  })();

  const LayoutUnit extent =
      ResolveMainInlineLength(space, style, border_padding, min_max_sizes_func,
                              logical_width, &auto_length);

  return ComputeMinMaxInlineSizes(
             space, node, border_padding,
             apply_automatic_min_size ? &Length::MinIntrinsic() : nullptr,
             min_max_sizes_func)
      .ClampSizeToMinAndMax(extent);
}

LayoutUnit ComputeInlineSizeForFragment(
    const ConstraintSpace& space,
    const BlockNode& node,
    const BoxStrut& border_padding,
    MinMaxSizesFunctionRef min_max_sizes_func) {
  if (space.IsFixedInlineSize() || space.IsAnonymous()) {
    return space.AvailableSize().inline_size;
  }

  if (node.IsTable()) {
    return To<TableNode>(node).ComputeTableInlineSize(space, border_padding);
  }

  return ComputeInlineSizeForFragmentInternal(space, node, border_padding,
                                              min_max_sizes_func);
}

LayoutUnit ComputeUsedInlineSizeForTableFragment(
    const ConstraintSpace& space,
    const BlockNode& node,
    const BoxStrut& border_padding,
    const MinMaxSizes& table_grid_min_max_sizes) {
  DCHECK(!space.IsFixedInlineSize());

  auto MinMaxSizesFunc = [&](SizeType type) -> MinMaxSizesResult {
    const auto& style = node.Style();
    const bool has_aspect_ratio = !style.AspectRatio().IsAuto();

    // Check if we have an aspect-ratio.
    if (has_aspect_ratio && type == SizeType::kContent) {
      const LayoutUnit block_size =
          ComputeBlockSizeForFragment(space, node, border_padding,
                                      /* intrinsic_size */ kIndefiniteSize,
                                      /* inline_size */ kIndefiniteSize);
      if (block_size != kIndefiniteSize) {
        const LayoutUnit inline_size = InlineSizeFromAspectRatio(
            border_padding, style.LogicalAspectRatio(),
            style.BoxSizingForAspectRatio(), block_size);
        return MinMaxSizesResult({inline_size, inline_size},
                                 /* depends_on_block_constraints */ false);
      }
    }
    return MinMaxSizesResult(table_grid_min_max_sizes,
                             /* depends_on_block_constraints */ false);
  };

  return ComputeInlineSizeForFragmentInternal(space, node, border_padding,
                                              MinMaxSizesFunc);
}

MinMaxSizes ComputeInitialMinMaxBlockSizes(const ConstraintSpace& space,
                                           const BlockNode& node,
                                           const BoxStrut& border_padding) {
  const ComputedStyle& style = node.Style();
  MinMaxSizes sizes = {
      ResolveInitialMinBlockLength(space, style, border_padding,
                                   style.LogicalMinHeight()),
      ResolveInitialMaxBlockLength(space, style, border_padding,
                                   style.LogicalMaxHeight())};
  sizes.max_size = std::max(sizes.max_size, sizes.min_size);
  return sizes;
}

MinMaxSizes ComputeMinMaxBlockSizes(const ConstraintSpace& space,
                                    const BlockNode& node,
                                    const BoxStrut& border_padding,
                                    const Length* auto_min_length,
                                    BlockSizeFunctionRef block_size_func,
                                    LayoutUnit override_available_size) {
  const ComputedStyle& style = node.Style();
  MinMaxSizes sizes = {
      ResolveMinBlockLength(space, style, border_padding, block_size_func,
                            style.LogicalMinHeight(), auto_min_length,
                            override_available_size),
      ResolveMaxBlockLength(space, style, border_padding,
                            style.LogicalMaxHeight(), block_size_func,
                            override_available_size)};

  // Clamp the auto min-size by the max-size.
  if (auto_min_length && style.LogicalMinHeight().HasAuto()) {
    sizes.min_size = std::min(sizes.min_size, sizes.max_size);
  }

  // Tables can't shrink below their min-intrinsic size.
  if (node.IsTable()) {
    sizes.Encompass(block_size_func(SizeType::kIntrinsic));
  }

  sizes.max_size = std::max(sizes.max_size, sizes.min_size);
  return sizes;
}

MinMaxSizes ComputeTransferredMinMaxInlineSizes(
    const LogicalSize& ratio,
    const MinMaxSizes& block_min_max,
    const BoxStrut& border_padding,
    const EBoxSizing sizing) {
  MinMaxSizes transferred_min_max = {LayoutUnit(), LayoutUnit::Max()};
  if (block_min_max.min_size > LayoutUnit()) {
    transferred_min_max.min_size = InlineSizeFromAspectRatio(
        border_padding, ratio, sizing, block_min_max.min_size);
  }
  if (block_min_max.max_size != LayoutUnit::Max()) {
    transferred_min_max.max_size = InlineSizeFromAspectRatio(
        border_padding, ratio, sizing, block_min_max.max_size);
  }
  // Minimum size wins over maximum size.
  transferred_min_max.max_size =
      std::max(transferred_min_max.max_size, transferred_min_max.min_size);
  return transferred_min_max;
}

MinMaxSizes ComputeTransferredMinMaxBlockSizes(
    const LogicalSize& ratio,
    const MinMaxSizes& inline_min_max,
    const BoxStrut& border_padding,
    const EBoxSizing sizing) {
  MinMaxSizes transferred_min_max = {LayoutUnit(), LayoutUnit::Max()};
  if (inline_min_max.min_size > LayoutUnit()) {
    transferred_min_max.min_size = BlockSizeFromAspectRatio(
        border_padding, ratio, sizing, inline_min_max.min_size);
  }
  if (inline_min_max.max_size != LayoutUnit::Max()) {
    transferred_min_max.max_size = BlockSizeFromAspectRatio(
        border_padding, ratio, sizing, inline_min_max.max_size);
  }
  // Minimum size wins over maximum size.
  transferred_min_max.max_size =
      std::max(transferred_min_max.max_size, transferred_min_max.min_size);
  return transferred_min_max;
}

MinMaxSizes ComputeMinMaxInlineSizesFromAspectRatio(
    const ConstraintSpace& constraint_space,
    const BlockNode& node,
    const BoxStrut& border_padding) {
  // The spec requires us to clamp these by the specified size (it calls it the
  // preferred size). However, we actually don't need to worry about that,
  // because we only use this if the width is indefinite.

  // We do not need to compute the min/max inline sizes; as long as we always
  // apply the transferred min/max size before the explicit min/max size, the
  // result will be identical.
  const ComputedStyle& style = node.Style();
  DCHECK(!style.AspectRatio().IsAuto());

  const MinMaxSizes block_min_max =
      ComputeInitialMinMaxBlockSizes(constraint_space, node, border_padding);
  return ComputeTransferredMinMaxInlineSizes(style.LogicalAspectRatio(),
                                             block_min_max, border_padding,
                                             style.BoxSizingForAspectRatio());
}

MinMaxSizes ComputeMinMaxInlineSizes(
    const ConstraintSpace& space,
    const BlockNode& node,
    const BoxStrut& border_padding,
    const Length* auto_min_length,
    MinMaxSizesFunctionRef min_max_sizes_func,
    TransferredSizesMode transferred_sizes_mode,
    LayoutUnit override_available_size) {
  const ComputedStyle& style = node.Style();
  MinMaxSizes sizes = {
      ResolveMinInlineLength(space, style, border_padding, min_max_sizes_func,
                             style.LogicalMinWidth(), auto_min_length,
                             override_available_size),
      ResolveMaxInlineLength(space, style, border_padding, min_max_sizes_func,
                             style.LogicalMaxWidth(), override_available_size)};

  // Clamp the auto min-size by the max-size.
  if (auto_min_length && style.LogicalMinWidth().HasAuto()) {
    sizes.min_size = std::min(sizes.min_size, sizes.max_size);
  }

  // This implements the transferred min/max sizes per:
  // https://drafts.csswg.org/css-sizing-4/#aspect-ratio-size-transfers
  if (transferred_sizes_mode == TransferredSizesMode::kNormal &&
      !style.AspectRatio().IsAuto() && style.LogicalWidth().HasAuto() &&
      space.InlineAutoBehavior() != AutoSizeBehavior::kStretchExplicit) {
    MinMaxSizes transferred_sizes =
        ComputeMinMaxInlineSizesFromAspectRatio(space, node, border_padding);
    sizes.min_size = std::max(
        sizes.min_size, std::min(transferred_sizes.min_size, sizes.max_size));
    sizes.max_size = std::min(sizes.max_size, transferred_sizes.max_size);
  }

  // Tables can't shrink below their min-intrinsic size.
  if (node.IsTable()) {
    sizes.Encompass(min_max_sizes_func(SizeType::kIntrinsic).sizes.min_size);
  }

  sizes.max_size = std::max(sizes.max_size, sizes.min_size);
  return sizes;
}

namespace {

// Computes the block-size for a fragment, ignoring the fixed block-size if set.
LayoutUnit ComputeBlockSizeForFragmentInternal(
    const ConstraintSpace& space,
    const BlockNode& node,
    const BoxStrut& border_padding,
    LayoutUnit intrinsic_size,
    LayoutUnit inline_size,
    LayoutUnit override_available_size = kIndefiniteSize) {
  const ComputedStyle& style = node.Style();

  // Scrollable percentage-sized children of table cells (sometimes) are sized
  // to their initial min-size.
  // See: https://drafts.csswg.org/css-tables-3/#row-layout
  if (space.IsRestrictedBlockSizeTableCellChild()) {
    return ResolveInitialMinBlockLength(space, style, border_padding,
                                        style.LogicalMinHeight(),
                                        override_available_size);
  }

  const Length& logical_height = style.LogicalHeight();
  const bool has_aspect_ratio = !style.AspectRatio().IsAuto();
  const bool may_apply_aspect_ratio =
      has_aspect_ratio && inline_size != kIndefiniteSize;

  const Length& auto_length = ([&]() {
    if (space.AvailableSize().block_size == kIndefiniteSize) {
      return Length::FitContent();
    }
    if (space.BlockAutoBehavior() == AutoSizeBehavior::kStretchExplicit) {
      return Length::Stretch();
    }
    if (may_apply_aspect_ratio) {
      return Length::FitContent();
    }
    if (space.BlockAutoBehavior() == AutoSizeBehavior::kStretchImplicit) {
      return Length::Stretch();
    }
    DCHECK_EQ(space.BlockAutoBehavior(), AutoSizeBehavior::kFitContent);
    return Length::FitContent();
  })();

  // Check if we should apply the automatic minimum size.
  // https://drafts.csswg.org/css-sizing-4/#aspect-ratio-minimum
  bool apply_automatic_min_size = ([&]() {
    // We check for LayoutUnit::Max() as flexbox uses this as a "placeholder"
    // to compute the flex line length while still respecting max-block-size.
    if (intrinsic_size == kIndefiniteSize ||
        intrinsic_size == LayoutUnit::Max()) {
      return false;
    }
    if (style.IsScrollContainer()) {
      return false;
    }
    if (!may_apply_aspect_ratio) {
      return false;
    }
    if (logical_height.HasContentOrIntrinsic()) {
      return true;
    }
    if (logical_height.HasAuto() && auto_length.HasContentOrIntrinsic()) {
      return true;
    }
   
"""


```