Response:
My thinking process to summarize the provided code snippet goes like this:

1. **Understand the Goal:** The request asks for a summary of the provided C++ code, specifically focusing on its functionality and relationships to web technologies (JavaScript, HTML, CSS). It also asks for examples, input/output scenarios, and common errors. Crucially, this is part 2 of a 3-part request, indicating that this is likely a segment of a larger file.

2. **Initial Skim and Keyword Identification:** I quickly read through the code, looking for recurring keywords and function names. Terms like `ComputeBlockSize`, `ComputeReplacedSize`, `Resolve`, `MinMaxSizes`, `AspectRatio`, `Border`, `Padding`, `Margin`, `ConstraintSpace`, `BlockNode`, `ComputedStyle`, `LayoutUnit`, and the use of `DCHECK` stand out. These give me a high-level idea that the code deals with calculating sizes and dimensions of elements based on various constraints and styling information.

3. **Function-Level Analysis:** I start examining the individual functions. I note the purpose of each function based on its name and the operations within it:
    * `ComputeBlockSizeForFragment` and `ComputeInitialBlockSizeForFragment`: These seem to be responsible for calculating the block (vertical) size of an element fragment. They take into account constraints, intrinsic size, and available space.
    * `ComputeDefaultNaturalSize`: This function appears to provide default dimensions for elements (like replaced elements).
    * `ComputeNormalizedNaturalSize`:  This function takes natural sizes and aspect ratios and tries to normalize them.
    * `ComputeReplacedSizeInternal` and `ComputeReplacedSize`: These are the core functions for calculating the size of replaced elements (like `<img>`, `<video>`). They handle aspect ratios, intrinsic sizes, min/max constraints, and different sizing modes. The "internal" version likely does the heavy lifting, while the outer version handles specific cases like SVG root elements.
    * `ResolveUsedColumnCount`, `ResolveUsedColumnInlineSize`, `ResolveUsedColumnGap`, `ColumnInlineProgression`: These functions deal with the layout of multi-column elements, calculating the number of columns, their widths, and gaps.
    * `ComputePhysicalMargins`, `ComputeMarginsFor`: These functions calculate the margins of elements, taking into account percentage-based values.
    * `ComputeBordersInternal`, `ComputeBorders`, `ComputeBordersForInline`, `ComputeNonCollapsedTableBorders`, `ComputeBordersForTest`:  These functions compute the border widths of elements. The different versions likely handle specific contexts like tables and inline elements.
    * `ComputePadding`: Calculates the padding of elements.
    * `ComputeScrollbarsForNonAnonymous`: Determines the space occupied by scrollbars.
    * `ResolveInlineAutoMargins`, `ResolveAutoMargins` (overloads): These functions handle the calculation of automatic margins to center elements.
    * `LineOffsetForTextAlign`: Calculates the horizontal offset for text based on the `text-align` property.
    * `CalculateDefaultBlockSize`:  Handles a special case for calculating the default block size of `html` and `body` elements in quirks mode.
    * `CalculateInitialFragmentGeometry`: This seems to calculate the initial geometry (size, borders, padding, scrollbars) of a fragment.

4. **Identifying Relationships with Web Technologies:** As I analyze the functions, I look for connections to CSS properties and HTML elements:
    * **CSS:**  Many function names directly correspond to CSS properties like `width`, `height`, `min-width`, `max-width`, `aspect-ratio`, `margin`, `padding`, `border`, `column-count`, `column-width`, `column-gap`, `text-align`. The code manipulates `ComputedStyle`, which represents the final CSS styles applied to an element. The handling of percentages and different box-sizing models also points to CSS.
    * **HTML:** The code deals with `BlockNode`, `TableNode`, `LayoutSVGRoot`, and refers to replaced elements, indicating it's concerned with the layout of HTML elements. The special handling of `html` and `body` in quirks mode is a direct HTML-specific behavior.
    * **JavaScript:** While this specific code is C++, its purpose is to implement the rendering engine that interprets CSS and HTML, ultimately impacting how JavaScript interacts with the DOM and CSSOM. JavaScript can manipulate styles and element dimensions, and this C++ code is what makes those manipulations visually happen.

5. **Inferring Input/Output and Logic:** I consider the inputs and outputs of the functions. Most functions take some form of size information (`LayoutUnit`), style information (`ComputedStyle`), and constraint information (`ConstraintSpace`) as input and output a `LayoutUnit` (for single dimensions) or `LogicalSize` or `BoxStrut` (for multiple dimensions). The logic involves conditional checks (e.g., checking for `auto` values, aspect ratios, constraints) and calculations based on these inputs.

6. **Identifying Potential Errors:** The use of `DCHECK` suggests assertions that should always be true. If these assertions fail, it indicates a bug. Common user/programming errors would involve incorrect or conflicting CSS values that might lead to unexpected layout results, which this code attempts to resolve according to CSS specifications.

7. **Synthesizing the Summary:** Finally, I combine my observations into a concise summary. I focus on the main purpose of the code, its relation to web technologies, and the key functionalities it provides. I group related functions and concepts together for clarity. I explicitly mention the CSS properties and HTML elements that are relevant.

8. **Refining and Organizing:** I review the summary for clarity and accuracy, ensuring it addresses all aspects of the prompt. I organize the information logically, starting with the overall purpose and then diving into specific functionalities. I use bullet points or lists to make the information easier to read. I also note that this is part of a larger file.

This iterative process of skimming, analyzing, connecting, and synthesizing allows me to build a comprehensive understanding of the code and generate the requested summary.
```cpp
 return false;
  })();

  auto BlockSizeFunc = [&](SizeType type) {
    if (type == SizeType::kContent && has_aspect_ratio &&
        inline_size != kIndefiniteSize) {
      return BlockSizeFromAspectRatio(
          border_padding, style.LogicalAspectRatio(),
          style.BoxSizingForAspectRatio(), inline_size);
    }
    return intrinsic_size;
  };

  const LayoutUnit extent = ResolveMainBlockLength(
      space, style, border_padding, logical_height, &auto_length, BlockSizeFunc,
      override_available_size);
  if (extent == kIndefiniteSize) {
    DCHECK_EQ(intrinsic_size, kIndefiniteSize);
    return extent;
  }

  MinMaxSizes min_max = ComputeMinMaxBlockSizes(
      space, node, border_padding,
      apply_automatic_min_size ? &Length::MinIntrinsic() : nullptr,
      BlockSizeFunc, override_available_size);

  // When fragmentation is present often want to encompass the intrinsic size.
  if (space.MinBlockSizeShouldEncompassIntrinsicSize() &&
      intrinsic_size != kIndefiniteSize) {
    min_max.Encompass(std::min(intrinsic_size, min_max.max_size));
  }

  return min_max.ClampSizeToMinAndMax(extent);
}

}  // namespace

LayoutUnit ComputeBlockSizeForFragment(const ConstraintSpace& constraint_space,
                                       const BlockNode& node,
                                       const BoxStrut& border_padding,
                                       LayoutUnit intrinsic_size,
                                       LayoutUnit inline_size,
                                       LayoutUnit override_available_size) {
  // The |override_available_size| should only be used for <table>s.
  DCHECK(override_available_size == kIndefiniteSize || node.IsTable());

  if (constraint_space.IsFixedBlockSize()) {
    LayoutUnit block_size = override_available_size == kIndefiniteSize
                                ? constraint_space.AvailableSize().block_size
                                : override_available_size;
    if (constraint_space.MinBlockSizeShouldEncompassIntrinsicSize())
      return std::max(intrinsic_size, block_size);
    return block_size;
  }

  if (constraint_space.IsTableCell() && intrinsic_size != kIndefiniteSize)
    return intrinsic_size;

  if (constraint_space.IsAnonymous())
    return intrinsic_size;

  return ComputeBlockSizeForFragmentInternal(
      constraint_space, node, border_padding, intrinsic_size, inline_size,
      override_available_size);
}

LayoutUnit ComputeInitialBlockSizeForFragment(
    const ConstraintSpace& space,
    const BlockNode& node,
    const BoxStrut& border_padding,
    LayoutUnit intrinsic_size,
    LayoutUnit inline_size,
    LayoutUnit override_available_size) {
  if (space.IsInitialBlockSizeIndefinite())
    return intrinsic_size;
  return ComputeBlockSizeForFragment(space, node, border_padding,
                                     intrinsic_size, inline_size,
                                     override_available_size);
}

namespace {

// Returns the default natural size.
LogicalSize ComputeDefaultNaturalSize(const BlockNode& node) {
  const auto& style = node.Style();
  PhysicalSize natural_size(LayoutUnit(300), LayoutUnit(150));
  natural_size.Scale(style.EffectiveZoom());
  return natural_size.ConvertToLogical(style.GetWritingMode());
}

// This takes the aspect-ratio, and natural-sizes and normalizes them returning
// the border-box natural-size.
//
// The following combinations are possible:
//  - an aspect-ratio with a natural-size
//  - an aspect-ratio with no natural-size
//  - no aspect-ratio with a natural-size
//
// It is not possible to have no aspect-ratio with no natural-size (as we'll
// use the default replaced size of 300x150 as a last resort).
// https://www.w3.org/TR/CSS22/visudet.html#inline-replaced-width
std::optional<LogicalSize> ComputeNormalizedNaturalSize(
    const BlockNode& node,
    const BoxStrut& border_padding,
    const EBoxSizing box_sizing,
    const LogicalSize& aspect_ratio) {
  std::optional<LayoutUnit> intrinsic_inline;
  std::optional<LayoutUnit> intrinsic_block;
  node.IntrinsicSize(&intrinsic_inline, &intrinsic_block);

  // Add the border-padding. If we *don't* have an aspect-ratio use the default
  // natural size (300x150).
  if (intrinsic_inline) {
    intrinsic_inline = *intrinsic_inline + border_padding.InlineSum();
  } else if (aspect_ratio.IsEmpty()) {
    intrinsic_inline = ComputeDefaultNaturalSize(node).inline_size +
                       border_padding.InlineSum();
  }

  if (intrinsic_block) {
    intrinsic_block = *intrinsic_block + border_padding.BlockSum();
  } else if (aspect_ratio.IsEmpty()) {
    intrinsic_block =
        ComputeDefaultNaturalSize(node).block_size + border_padding.BlockSum();
  }

  // If we have one natural size reflect via. the aspect-ratio.
  if (!intrinsic_inline && intrinsic_block) {
    DCHECK(!aspect_ratio.IsEmpty());
    intrinsic_inline = InlineSizeFromAspectRatio(border_padding, aspect_ratio,
                                                 box_sizing, *intrinsic_block);
  }
  if (intrinsic_inline && !intrinsic_block) {
    DCHECK(!aspect_ratio.IsEmpty());
    intrinsic_block = BlockSizeFromAspectRatio(border_padding, aspect_ratio,
                                               box_sizing, *intrinsic_inline);
  }

  DCHECK(intrinsic_inline.has_value() == intrinsic_block.has_value());
  if (intrinsic_inline && intrinsic_block)
    return LogicalSize(*intrinsic_inline, *intrinsic_block);

  return std::nullopt;
}

// The main part of ComputeReplacedSize(). This function doesn't handle a
// case of <svg> as the documentElement.
LogicalSize ComputeReplacedSizeInternal(const BlockNode& node,
                                        const ConstraintSpace& space,
                                        const BoxStrut& border_padding,
                                        ReplacedSizeMode mode) {
  DCHECK(node.IsReplaced());

  const ComputedStyle& style = node.Style();
  const EBoxSizing box_sizing = style.BoxSizingForAspectRatio();
  const LogicalSize aspect_ratio = node.GetAspectRatio();
  const std::optional<LogicalSize> natural_size = ComputeNormalizedNaturalSize(
      node, border_padding, box_sizing, aspect_ratio);

  const Length& block_length = style.LogicalHeight();

  auto BlockSizeFunc = [&](SizeType) -> LayoutUnit {
    if (aspect_ratio.IsEmpty()) {
      DCHECK(natural_size);
      return natural_size->block_size;
    }
    if (mode == ReplacedSizeMode::kNormal) {
      return ComputeReplacedSize(node, space, border_padding,
                                 ReplacedSizeMode::kIgnoreBlockLengths)
          .block_size;
    }
    return kIndefiniteSize;
  };

  MinMaxSizes block_min_max_sizes;
  std::optional<LayoutUnit> replaced_block;
  if (mode == ReplacedSizeMode::kIgnoreBlockLengths) {
    // Don't resolve any block lengths or constraints.
    block_min_max_sizes = {LayoutUnit(), LayoutUnit::Max()};
  } else {
    // Replaced elements in quirks-mode resolve their min/max block-sizes
    // against a different size than the main size. See:
    //  - https://www.w3.org/TR/CSS21/visudet.html#min-max-heights
    //  - https://bugs.chromium.org/p/chromium/issues/detail?id=385877
    // For the history on this behavior. Fortunately if this is the case we can
    // just use the given available size to resolve these sizes against.
    const LayoutUnit min_max_percentage_resolution_size =
        node.GetDocument().InQuirksMode() && !node.IsOutOfFlowPositioned()
            ? space.AvailableSize().block_size
            : space.ReplacedPercentageResolutionBlockSize();

    block_min_max_sizes = {
        ResolveMinBlockLength(space, style, border_padding, BlockSizeFunc,
                              style.LogicalMinHeight(),
                              /* auto_length */ nullptr,
                              /* override_available_size */ kIndefiniteSize,
                              &min_max_percentage_resolution_size),
        ResolveMaxBlockLength(space, style, border_padding,
                              style.LogicalMaxHeight(), BlockSizeFunc,
                              /* override_available_size */ kIndefiniteSize,
                              &min_max_percentage_resolution_size)};

    if (space.IsFixedBlockSize()) {
      replaced_block = space.AvailableSize().block_size;
      DCHECK_GE(*replaced_block, 0);
    } else if (!block_length.HasAutoOrContentOrIntrinsic() ||
               (space.IsBlockAutoBehaviorStretch() &&
                space.AvailableSize().block_size != kIndefiniteSize)) {
      const Length& block_length_to_resolve =
          block_length.HasAuto() ? Length::Stretch() : block_length;

      const LayoutUnit main_percentage_resolution_size =
          space.ReplacedPercentageResolutionBlockSize();
      const LayoutUnit block_size = ResolveMainBlockLength(
          space, style, border_padding, block_length_to_resolve,
          /* auto_length*/ nullptr,
          /* intrinsic_size */ kIndefiniteSize,
          /* override_available_size */ kIndefiniteSize,
          &main_percentage_resolution_size);
      if (block_size != kIndefiniteSize) {
        DCHECK_GE(block_size, LayoutUnit());
        replaced_block = block_min_max_sizes.ClampSizeToMinAndMax(block_size);
      }
    }
  }

  const Length& inline_length = style.LogicalWidth();

  auto StretchFit = [&]() -> LayoutUnit {
    LayoutUnit size;
    if (space.AvailableSize().inline_size == kIndefiniteSize) {
      size = border_padding.InlineSum();
      // TODO(crbug.com/1218055): Instead of using the default natural size, we
      // should be using the initial containing block size. When doing this
      // we'll need to invalidated (sparingly) on window resize.
      // TODO(https://crbug.com/313072): Values with intrinsic sizing or
      // content sizing keywords should perhaps also get the natural size here
      // (or be zero).
      if (inline_length.HasPercent()) {
        size += ComputeDefaultNaturalSize(node).inline_size;
      }
    } else {
      // Stretch to the available-size if it is definite.
      size = ResolveMainInlineLength(
          space, style, border_padding,
          [](SizeType) -> MinMaxSizesResult { NOTREACHED(); },
          Length::Stretch(), /* auto_length */ nullptr,
          /* override_available_size */ kIndefiniteSize);
    }

    // If stretch-fit applies we must have an aspect-ratio.
    DCHECK(!aspect_ratio.IsEmpty());

    // Apply the transferred min/max sizes.
    const MinMaxSizes transferred_min_max_sizes =
        ComputeTransferredMinMaxInlineSizes(aspect_ratio, block_min_max_sizes,
                                            border_padding, box_sizing);
    size = transferred_min_max_sizes.ClampSizeToMinAndMax(size);

    return size;
  };

  auto MinMaxSizesFunc = [&](SizeType) -> MinMaxSizesResult {
    LayoutUnit size;
    if (aspect_ratio.IsEmpty()) {
      DCHECK(natural_size);
      size = natural_size->inline_size;
    } else if (replaced_block) {
      size = InlineSizeFromAspectRatio(border_padding, aspect_ratio, box_sizing,
                                       *replaced_block);
    } else if (natural_size) {
      DCHECK_NE(mode, ReplacedSizeMode::kIgnoreInlineLengths);
      size = ComputeReplacedSize(node, space, border_padding,
                                 ReplacedSizeMode::kIgnoreInlineLengths)
                 .inline_size;
    } else {
      // We don't have a natural size - default to stretching.
      size = StretchFit();
    }

    // |depends_on_block_constraints| doesn't matter in this context.
    MinMaxSizes sizes;
    sizes += size;
    return {sizes, /* depends_on_block_constraints */ false};
  };

  MinMaxSizes inline_min_max_sizes;
  std::optional<LayoutUnit> replaced_inline;
  if (mode == ReplacedSizeMode::kIgnoreInlineLengths) {
    // Don't resolve any inline lengths or constraints.
    inline_min_max_sizes = {LayoutUnit(), LayoutUnit::Max()};
  } else {
    inline_min_max_sizes = {
        ResolveMinInlineLength(space, style, border_padding, MinMaxSizesFunc,
                               style.LogicalMinWidth()),
        ResolveMaxInlineLength(space, style, border_padding, MinMaxSizesFunc,
                               style.LogicalMaxWidth())};

    if (space.IsFixedInlineSize()) {
      replaced_inline = space.AvailableSize().inline_size;
      DCHECK_GE(*replaced_inline, 0);
    } else if (!inline_length.HasAuto() ||
               (space.IsInlineAutoBehaviorStretch() &&
                space.AvailableSize().inline_size != kIndefiniteSize)) {
      const Length& auto_length = space.IsInlineAutoBehaviorStretch()
                                      ? Length::Stretch()
                                      : Length::FitContent();
      const LayoutUnit inline_size =
          ResolveMainInlineLength(space, style, border_padding, MinMaxSizesFunc,
                                  inline_length, &auto_length);
      if (inline_size != kIndefiniteSize) {
        DCHECK_GE(inline_size, LayoutUnit());
        replaced_inline =
            inline_min_max_sizes.ClampSizeToMinAndMax(inline_size);
      }
    }
  }

  if (replaced_inline && replaced_block)
    return LogicalSize(*replaced_inline, *replaced_block);

  // We have *only* an aspect-ratio with no sizes (natural or otherwise), we
  // default to stretching.
  if (!natural_size && !replaced_inline && !replaced_block) {
    replaced_inline = StretchFit();
    replaced_inline =
        inline_min_max_sizes.ClampSizeToMinAndMax(*replaced_inline);
  }

  // We only know one size, the other gets computed via the aspect-ratio (if
  // present), or defaults to the natural-size.
  if (replaced_inline) {
    DCHECK(!replaced_block);
    DCHECK(natural_size || !aspect_ratio.IsEmpty());
    replaced_block = aspect_ratio.IsEmpty() ? natural_size->block_size
                                            : BlockSizeFromAspectRatio(
                                                  border_padding, aspect_ratio,
                                                  box_sizing, *replaced_inline);
    replaced_block = block_min_max_sizes.ClampSizeToMinAndMax(*replaced_block);
    return LogicalSize(*replaced_inline, *replaced_block);
  }

  if (replaced_block) {
    DCHECK(!replaced_inline);
    DCHECK(natural_size || !aspect_ratio.IsEmpty());
    replaced_inline = aspect_ratio.IsEmpty() ? natural_size->inline_size
                                             : InlineSizeFromAspectRatio(
                                                   border_padding, aspect_ratio,
                                                   box_sizing, *replaced_block);
    replaced_inline =
        inline_min_max_sizes.ClampSizeToMinAndMax(*replaced_inline);
    return LogicalSize(*replaced_inline, *replaced_block);
  }

  // Both lengths are unknown, start with the natural-size.
  DCHECK(!replaced_inline);
  DCHECK(!replaced_block);
  replaced_inline = natural_size->inline_size;
  replaced_block = natural_size->block_size;

  // Apply the min/max sizes to the natural-size.
  const LayoutUnit constrained_inline =
      inline_min_max_sizes.ClampSizeToMinAndMax(*replaced_inline);
  const LayoutUnit constrained_block =
      block_min_max_sizes.ClampSizeToMinAndMax(*replaced_block);

  // If the min/max sizes had no effect, just return the natural-size.
  if (constrained_inline == replaced_inline &&
      constrained_block == replaced_block)
    return LogicalSize(*replaced_inline, *replaced_block);

  // If we have no aspect-ratio, use both constrained sizes.
  if (aspect_ratio.IsEmpty())
    return {constrained_inline, constrained_block};

  // The min/max sizes have applied, try to respect the aspect-ratio.

  // The following implements the table from section 10.4 at:
  // https://www.w3.org/TR/CSS22/visudet.html#min-max-widths
  const bool is_min_inline_constrained = constrained_inline > *replaced_inline;
  const bool is_max_inline_constrained = constrained_inline < *replaced_inline;
  const bool is_min_block_constrained = constrained_block > *replaced_block;
  const bool is_max_block_constrained = constrained_block < *replaced_block;

  // Constraints caused us to grow in one dimension and shrink in the other.
  // Use both constrained sizes.
  if ((is_max_inline_constrained && is_min_block_constrained) ||
      (is_min_inline_constrained && is_max_block_constrained))
    return {constrained_inline, constrained_block};

  const LayoutUnit hypothetical_block = BlockSizeFromAspectRatio(
      border_padding, aspect_ratio, box_sizing, constrained_inline);
  const LayoutUnit hypothetical_inline = InlineSizeFromAspectRatio(
      border_padding, aspect_ratio, box_sizing, constrained_block);

  // If the inline-size got constrained more extremely than the block-size, use
  // the constrained inline-size, and recalculate the block-size.
  if (constrained_block == *replaced_block ||
      (is_max_inline_constrained && hypothetical_block <= constrained_block) ||
      (is_min_inline_constrained &&
       constrained_inline >= hypothetical_inline)) {
    return {constrained_inline,
            block_min_max_sizes.ClampSizeToMinAndMax(hypothetical_block)};
  }

  // If the block-size got constrained more extremely than the inline-size, use
  // the constrained block-size, and recalculate the inline-size.
  return {inline_min_max_sizes.ClampSizeToMinAndMax(hypothetical_inline),
          constrained_block};
}

}  // namespace

// Computes size for a replaced element.
LogicalSize ComputeReplacedSize(const BlockNode& node,
                                const ConstraintSpace& space,
                                const BoxStrut& border_padding,
                                ReplacedSizeMode mode) {
  DCHECK(node.IsReplaced());

  const auto* svg_root = DynamicTo<LayoutSVGRoot>(node.GetLayoutBox());
  if (!svg_root || !svg_root->IsDocumentElement()) {
    return ComputeReplacedSizeInternal(node, space, border_padding, mode);
  }

  PhysicalSize container_size(svg_root->GetContainerSize());
  if (!container_size.IsEmpty()) {
    LogicalSize size =
        container_size.ConvertToLogical(node.Style().GetWritingMode());
    size.inline_size += border_padding.InlineSum();
    size.block_size += border_padding.BlockSum();
    return size;
  }

  if (svg_root->IsEmbeddedThroughFrameContainingSVGDocument()) {
    LogicalSize size = space.AvailableSize();
    size.block_size = node.Style().IsHorizontalWritingMode()
                          ? node.InitialContainingBlockSize().height
                          : node.InitialContainingBlockSize().width;
    return size;
  }

  LogicalSize size =
      ComputeReplacedSizeInternal(node, space, border_padding, mode);

  if (node.Style().LogicalWidth().HasPercent()) {
    double factor = svg_root->LogicalSizeScaleFactorForPercentageLengths();
    if (factor != 1.0) {
      // TODO(https://crbug.com/313072): Just because a calc *has* percentages
      // doesn't mean *all* the lengths are percentages.
      size.inline_size *= factor;
    }
  }

  const Length& logical_height = node.Style().LogicalHeight();
  if (logical_height.HasPercent()) {
    // TODO(https://crbug.com/313072): Might this also be needed for intrinsic
    // sizing keywords?
    LayoutUnit height = ValueForLength(
        logical_height,
        node.GetDocument().GetLayoutView()->ViewLogicalHeightForPercentages());
    double factor = svg_root->LogicalSizeScaleFactorForPercentageLengths();
    if (factor != 1.0) {
      // TODO(https://crbug.com/313072): Just because a calc *has* percentages
      // doesn't mean *all* the lengths are percentages.
      height *= factor;
    }
    size.block_size = height;
  }
  return size;
}

int ResolveUsedColumnCount(int computed_count,
                           LayoutUnit computed_size,
                           LayoutUnit used_gap,
                           LayoutUnit available_size) {
  if (computed_size == kIndefiniteSize) {
    DCHECK(computed_count);
    return computed_count;
  }
  DCHECK_GT(computed_size, LayoutUnit());
  int count_from_width =
      ((available_size + used_gap) / (computed_size + used_gap)).ToInt();
  count_from_width = std::max(1, count_from_width);
  if (!computed_count)
    return count_from_width;
  return std::max(1, std::min(computed_count, count_from_width));
}

int ResolveUsedColumnCount(LayoutUnit available_size,
                           const ComputedStyle& style) {
  LayoutUnit computed_column_inline_size =
      style.HasAutoColumnWidth()
          ? kIndefiniteSize
          : std::max(LayoutUnit(1), LayoutUnit(style.ColumnWidth()));
  LayoutUnit gap = ResolveUsedColumnGap(available_size, style);
  int computed_count = style.HasAutoColumnCount() ? 0 : style.ColumnCount();
  return ResolveUsedColumnCount(computed_count, computed_column_inline_size,
                                gap, available_size);
}

LayoutUnit ResolveUsedColumnInlineSize(int computed_count,
                                       LayoutUnit computed_size,
                                       LayoutUnit used_gap,
                                       LayoutUnit available_size) {
  int used_count = ResolveUsedColumnCount(computed_count, computed_size,
                                          used_gap, available_size);
  return std::max(((available_size + used_gap) / used_count) - used_gap,
                  LayoutUnit());
}

LayoutUnit ResolveUsedColumnInlineSize(LayoutUnit available_size,
                                       const ComputedStyle& style) {
  // Should only attempt to resolve this if columns != auto.
  DCHECK(!style.HasAutoColumnCount() || !style.HasAutoColumnWidth());

  LayoutUnit computed_size =
      style.HasAutoColumnWidth()
          ? kIndefiniteSize
          : std::max(LayoutUnit(1), LayoutUnit(style.ColumnWidth()));
  int computed_count = style.HasAutoColumnCount() ? 0 : style.ColumnCount();
  LayoutUnit used_gap = ResolveUsedColumnGap(available_size, style);
  return ResolveUsedColumnInlineSize(computed_count, computed_size, used_gap,
                                     available_size);
}

LayoutUnit ResolveUsedColumnGap(LayoutUnit available_size,
                                const ComputedStyle& style) {
  if (const std::optional<Length>& column_gap = style.ColumnGap()) {
    return ValueForLength(*column_gap, available_size);
  }
  return LayoutUnit(style.GetFontDescription().ComputedPixelSize());
}

LayoutUnit ColumnInlineProgression(LayoutUnit available_size,
                                   const ComputedStyle& style) {
  LayoutUnit column_inline_size =
      ResolveUsedColumnInlineSize(available_size, style);
  return column_inline_size + ResolveUsedColumnGap(available_size, style);
}

PhysicalBoxStrut ComputePhysicalMargins(
    const ComputedStyle& style,
    PhysicalSize percentage_resolution_size) {
  if (!style.MayHaveMargin())
    return PhysicalBoxStrut();

  return PhysicalBoxStrut(
      MinimumValueForLength(style.MarginTop(),
                            percentage_resolution_size.height),
      MinimumValueForLength(style.MarginRight(),
                            percentage_resolution_size.width),
      MinimumValueForLength(style.MarginBottom(),
                            percentage_resolution_size.height),
      MinimumValueForLength(style.MarginLeft(),
                            percentage_resolution_size.width));
}

BoxStrut ComputeMarginsFor(const ConstraintSpace& constraint_space,
                           const ComputedStyle& style,
                           const ConstraintSpace& compute_for) {
  if (!style.MayHaveMargin() || constraint_space.IsAnonymous())
    return BoxStrut();
  LogicalSize percentage_resolution_size =
      constraint_space.MarginPaddingPercentageResolutionSize();
  return ComputePhysicalMargins(style, percentage_resolution_size)
      .ConvertToLogical(compute_for.GetWritingDirection());
}

namespace {

BoxStrut ComputeBordersInternal(const ComputedStyle& style) {
  return {LayoutUnit(style.BorderInlineStartWidth()),
          LayoutUnit(style.BorderInlineEndWidth()),
          LayoutUnit(style.BorderBlockStartWidth()),
          LayoutUnit(style.BorderBlockEndWidth())};
}

}  // namespace

BoxStrut ComputeBorders(const ConstraintSpace& constraint_space,
                        const BlockNode& node) {
  // If we are producing an anonymous fragment (e.g. a column), it has no
  // borders, padding or scrollbars. Using the ones from the container can only
  // cause trouble.
  if (constraint_space.IsAnonymous())
    return BoxStrut();

  // If we are a table cell we just access the values set by the parent table
  // layout as border may be collapsed etc.
  if (constraint_space.IsTableCell())
    return constraint_space.TableCellBorders();

  if (node.IsTable()) {
    return To<TableNode>(node).GetTableBorders()->TableBorder();
  }

  return ComputeBordersInternal(node.Style());
}

BoxStrut ComputeBordersForInline(const ComputedStyle& style) {
  return ComputeBordersInternal(style);
}

BoxStrut ComputeNonCollapsedTableBorders(const ComputedStyle& style) {
  return ComputeBordersInternal(style);
}

BoxStrut ComputeBordersForTest(const ComputedStyle& style) {
  return ComputeBordersInternal(style);
}

BoxStrut ComputePadding(const ConstraintSpace& constraint_space,
                        const ComputedStyle& style) {
  // If we are producing an anonymous fragment (e.g. a column) we shouldn't
  // have any padding.
  if (!style.MayHavePadding() || constraint_space.IsAnonymous())
    return BoxStrut();

  // Tables with collapsed borders don't have any padding.
  if (style.IsDisplayTableBox() &&
      style.BorderCollapse() == EBorderCollapse::kCollapse) {
    return BoxStrut();
  }

  // This function may be called for determining intrinsic padding, clamp
  // indefinite %-sizes to zero. See:
  // https://drafts.csswg.org/css-sizing-3/#min-percentage-contribution
  LogicalSize percentage_resolution_size =
      constraint_space.MarginPaddingPercentageResolutionSize()
          .ClampIndefiniteToZero();
  return {MinimumValueForLength(style.PaddingInlineStart(),
                                percentage_resolution_size.inline_size),
          MinimumValueForLength(style.PaddingInlineEnd(),
                                percentage_resolution_size.inline_size),
          MinimumValueForLength(style.PaddingBlockStart(),
                                percentage_resolution_size.block_size),
          MinimumValueForLength(style.PaddingBlockEnd(),
                                percentage_resolution_size.block_size)};
}

BoxStrut ComputeScrollbarsForNonAnonymous(const BlockNode& node) {
  const ComputedStyle& style = node.Style();
  if (!style.IsScrollContainer() && style.
Prompt: 
```
这是目录为blink/renderer/core/layout/length_utils.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
 return false;
  })();

  auto BlockSizeFunc = [&](SizeType type) {
    if (type == SizeType::kContent && has_aspect_ratio &&
        inline_size != kIndefiniteSize) {
      return BlockSizeFromAspectRatio(
          border_padding, style.LogicalAspectRatio(),
          style.BoxSizingForAspectRatio(), inline_size);
    }
    return intrinsic_size;
  };

  const LayoutUnit extent = ResolveMainBlockLength(
      space, style, border_padding, logical_height, &auto_length, BlockSizeFunc,
      override_available_size);
  if (extent == kIndefiniteSize) {
    DCHECK_EQ(intrinsic_size, kIndefiniteSize);
    return extent;
  }

  MinMaxSizes min_max = ComputeMinMaxBlockSizes(
      space, node, border_padding,
      apply_automatic_min_size ? &Length::MinIntrinsic() : nullptr,
      BlockSizeFunc, override_available_size);

  // When fragmentation is present often want to encompass the intrinsic size.
  if (space.MinBlockSizeShouldEncompassIntrinsicSize() &&
      intrinsic_size != kIndefiniteSize) {
    min_max.Encompass(std::min(intrinsic_size, min_max.max_size));
  }

  return min_max.ClampSizeToMinAndMax(extent);
}

}  // namespace

LayoutUnit ComputeBlockSizeForFragment(const ConstraintSpace& constraint_space,
                                       const BlockNode& node,
                                       const BoxStrut& border_padding,
                                       LayoutUnit intrinsic_size,
                                       LayoutUnit inline_size,
                                       LayoutUnit override_available_size) {
  // The |override_available_size| should only be used for <table>s.
  DCHECK(override_available_size == kIndefiniteSize || node.IsTable());

  if (constraint_space.IsFixedBlockSize()) {
    LayoutUnit block_size = override_available_size == kIndefiniteSize
                                ? constraint_space.AvailableSize().block_size
                                : override_available_size;
    if (constraint_space.MinBlockSizeShouldEncompassIntrinsicSize())
      return std::max(intrinsic_size, block_size);
    return block_size;
  }

  if (constraint_space.IsTableCell() && intrinsic_size != kIndefiniteSize)
    return intrinsic_size;

  if (constraint_space.IsAnonymous())
    return intrinsic_size;

  return ComputeBlockSizeForFragmentInternal(
      constraint_space, node, border_padding, intrinsic_size, inline_size,
      override_available_size);
}

LayoutUnit ComputeInitialBlockSizeForFragment(
    const ConstraintSpace& space,
    const BlockNode& node,
    const BoxStrut& border_padding,
    LayoutUnit intrinsic_size,
    LayoutUnit inline_size,
    LayoutUnit override_available_size) {
  if (space.IsInitialBlockSizeIndefinite())
    return intrinsic_size;
  return ComputeBlockSizeForFragment(space, node, border_padding,
                                     intrinsic_size, inline_size,
                                     override_available_size);
}

namespace {

// Returns the default natural size.
LogicalSize ComputeDefaultNaturalSize(const BlockNode& node) {
  const auto& style = node.Style();
  PhysicalSize natural_size(LayoutUnit(300), LayoutUnit(150));
  natural_size.Scale(style.EffectiveZoom());
  return natural_size.ConvertToLogical(style.GetWritingMode());
}

// This takes the aspect-ratio, and natural-sizes and normalizes them returning
// the border-box natural-size.
//
// The following combinations are possible:
//  - an aspect-ratio with a natural-size
//  - an aspect-ratio with no natural-size
//  - no aspect-ratio with a natural-size
//
// It is not possible to have no aspect-ratio with no natural-size (as we'll
// use the default replaced size of 300x150 as a last resort).
// https://www.w3.org/TR/CSS22/visudet.html#inline-replaced-width
std::optional<LogicalSize> ComputeNormalizedNaturalSize(
    const BlockNode& node,
    const BoxStrut& border_padding,
    const EBoxSizing box_sizing,
    const LogicalSize& aspect_ratio) {
  std::optional<LayoutUnit> intrinsic_inline;
  std::optional<LayoutUnit> intrinsic_block;
  node.IntrinsicSize(&intrinsic_inline, &intrinsic_block);

  // Add the border-padding. If we *don't* have an aspect-ratio use the default
  // natural size (300x150).
  if (intrinsic_inline) {
    intrinsic_inline = *intrinsic_inline + border_padding.InlineSum();
  } else if (aspect_ratio.IsEmpty()) {
    intrinsic_inline = ComputeDefaultNaturalSize(node).inline_size +
                       border_padding.InlineSum();
  }

  if (intrinsic_block) {
    intrinsic_block = *intrinsic_block + border_padding.BlockSum();
  } else if (aspect_ratio.IsEmpty()) {
    intrinsic_block =
        ComputeDefaultNaturalSize(node).block_size + border_padding.BlockSum();
  }

  // If we have one natural size reflect via. the aspect-ratio.
  if (!intrinsic_inline && intrinsic_block) {
    DCHECK(!aspect_ratio.IsEmpty());
    intrinsic_inline = InlineSizeFromAspectRatio(border_padding, aspect_ratio,
                                                 box_sizing, *intrinsic_block);
  }
  if (intrinsic_inline && !intrinsic_block) {
    DCHECK(!aspect_ratio.IsEmpty());
    intrinsic_block = BlockSizeFromAspectRatio(border_padding, aspect_ratio,
                                               box_sizing, *intrinsic_inline);
  }

  DCHECK(intrinsic_inline.has_value() == intrinsic_block.has_value());
  if (intrinsic_inline && intrinsic_block)
    return LogicalSize(*intrinsic_inline, *intrinsic_block);

  return std::nullopt;
}

// The main part of ComputeReplacedSize(). This function doesn't handle a
// case of <svg> as the documentElement.
LogicalSize ComputeReplacedSizeInternal(const BlockNode& node,
                                        const ConstraintSpace& space,
                                        const BoxStrut& border_padding,
                                        ReplacedSizeMode mode) {
  DCHECK(node.IsReplaced());

  const ComputedStyle& style = node.Style();
  const EBoxSizing box_sizing = style.BoxSizingForAspectRatio();
  const LogicalSize aspect_ratio = node.GetAspectRatio();
  const std::optional<LogicalSize> natural_size = ComputeNormalizedNaturalSize(
      node, border_padding, box_sizing, aspect_ratio);

  const Length& block_length = style.LogicalHeight();

  auto BlockSizeFunc = [&](SizeType) -> LayoutUnit {
    if (aspect_ratio.IsEmpty()) {
      DCHECK(natural_size);
      return natural_size->block_size;
    }
    if (mode == ReplacedSizeMode::kNormal) {
      return ComputeReplacedSize(node, space, border_padding,
                                 ReplacedSizeMode::kIgnoreBlockLengths)
          .block_size;
    }
    return kIndefiniteSize;
  };

  MinMaxSizes block_min_max_sizes;
  std::optional<LayoutUnit> replaced_block;
  if (mode == ReplacedSizeMode::kIgnoreBlockLengths) {
    // Don't resolve any block lengths or constraints.
    block_min_max_sizes = {LayoutUnit(), LayoutUnit::Max()};
  } else {
    // Replaced elements in quirks-mode resolve their min/max block-sizes
    // against a different size than the main size. See:
    //  - https://www.w3.org/TR/CSS21/visudet.html#min-max-heights
    //  - https://bugs.chromium.org/p/chromium/issues/detail?id=385877
    // For the history on this behavior. Fortunately if this is the case we can
    // just use the given available size to resolve these sizes against.
    const LayoutUnit min_max_percentage_resolution_size =
        node.GetDocument().InQuirksMode() && !node.IsOutOfFlowPositioned()
            ? space.AvailableSize().block_size
            : space.ReplacedPercentageResolutionBlockSize();

    block_min_max_sizes = {
        ResolveMinBlockLength(space, style, border_padding, BlockSizeFunc,
                              style.LogicalMinHeight(),
                              /* auto_length */ nullptr,
                              /* override_available_size */ kIndefiniteSize,
                              &min_max_percentage_resolution_size),
        ResolveMaxBlockLength(space, style, border_padding,
                              style.LogicalMaxHeight(), BlockSizeFunc,
                              /* override_available_size */ kIndefiniteSize,
                              &min_max_percentage_resolution_size)};

    if (space.IsFixedBlockSize()) {
      replaced_block = space.AvailableSize().block_size;
      DCHECK_GE(*replaced_block, 0);
    } else if (!block_length.HasAutoOrContentOrIntrinsic() ||
               (space.IsBlockAutoBehaviorStretch() &&
                space.AvailableSize().block_size != kIndefiniteSize)) {
      const Length& block_length_to_resolve =
          block_length.HasAuto() ? Length::Stretch() : block_length;

      const LayoutUnit main_percentage_resolution_size =
          space.ReplacedPercentageResolutionBlockSize();
      const LayoutUnit block_size = ResolveMainBlockLength(
          space, style, border_padding, block_length_to_resolve,
          /* auto_length*/ nullptr,
          /* intrinsic_size */ kIndefiniteSize,
          /* override_available_size */ kIndefiniteSize,
          &main_percentage_resolution_size);
      if (block_size != kIndefiniteSize) {
        DCHECK_GE(block_size, LayoutUnit());
        replaced_block = block_min_max_sizes.ClampSizeToMinAndMax(block_size);
      }
    }
  }

  const Length& inline_length = style.LogicalWidth();

  auto StretchFit = [&]() -> LayoutUnit {
    LayoutUnit size;
    if (space.AvailableSize().inline_size == kIndefiniteSize) {
      size = border_padding.InlineSum();
      // TODO(crbug.com/1218055): Instead of using the default natural size, we
      // should be using the initial containing block size. When doing this
      // we'll need to invalidated (sparingly) on window resize.
      // TODO(https://crbug.com/313072): Values with intrinsic sizing or
      // content sizing keywords should perhaps also get the natural size here
      // (or be zero).
      if (inline_length.HasPercent()) {
        size += ComputeDefaultNaturalSize(node).inline_size;
      }
    } else {
      // Stretch to the available-size if it is definite.
      size = ResolveMainInlineLength(
          space, style, border_padding,
          [](SizeType) -> MinMaxSizesResult { NOTREACHED(); },
          Length::Stretch(), /* auto_length */ nullptr,
          /* override_available_size */ kIndefiniteSize);
    }

    // If stretch-fit applies we must have an aspect-ratio.
    DCHECK(!aspect_ratio.IsEmpty());

    // Apply the transferred min/max sizes.
    const MinMaxSizes transferred_min_max_sizes =
        ComputeTransferredMinMaxInlineSizes(aspect_ratio, block_min_max_sizes,
                                            border_padding, box_sizing);
    size = transferred_min_max_sizes.ClampSizeToMinAndMax(size);

    return size;
  };

  auto MinMaxSizesFunc = [&](SizeType) -> MinMaxSizesResult {
    LayoutUnit size;
    if (aspect_ratio.IsEmpty()) {
      DCHECK(natural_size);
      size = natural_size->inline_size;
    } else if (replaced_block) {
      size = InlineSizeFromAspectRatio(border_padding, aspect_ratio, box_sizing,
                                       *replaced_block);
    } else if (natural_size) {
      DCHECK_NE(mode, ReplacedSizeMode::kIgnoreInlineLengths);
      size = ComputeReplacedSize(node, space, border_padding,
                                 ReplacedSizeMode::kIgnoreInlineLengths)
                 .inline_size;
    } else {
      // We don't have a natural size - default to stretching.
      size = StretchFit();
    }

    // |depends_on_block_constraints| doesn't matter in this context.
    MinMaxSizes sizes;
    sizes += size;
    return {sizes, /* depends_on_block_constraints */ false};
  };

  MinMaxSizes inline_min_max_sizes;
  std::optional<LayoutUnit> replaced_inline;
  if (mode == ReplacedSizeMode::kIgnoreInlineLengths) {
    // Don't resolve any inline lengths or constraints.
    inline_min_max_sizes = {LayoutUnit(), LayoutUnit::Max()};
  } else {
    inline_min_max_sizes = {
        ResolveMinInlineLength(space, style, border_padding, MinMaxSizesFunc,
                               style.LogicalMinWidth()),
        ResolveMaxInlineLength(space, style, border_padding, MinMaxSizesFunc,
                               style.LogicalMaxWidth())};

    if (space.IsFixedInlineSize()) {
      replaced_inline = space.AvailableSize().inline_size;
      DCHECK_GE(*replaced_inline, 0);
    } else if (!inline_length.HasAuto() ||
               (space.IsInlineAutoBehaviorStretch() &&
                space.AvailableSize().inline_size != kIndefiniteSize)) {
      const Length& auto_length = space.IsInlineAutoBehaviorStretch()
                                      ? Length::Stretch()
                                      : Length::FitContent();
      const LayoutUnit inline_size =
          ResolveMainInlineLength(space, style, border_padding, MinMaxSizesFunc,
                                  inline_length, &auto_length);
      if (inline_size != kIndefiniteSize) {
        DCHECK_GE(inline_size, LayoutUnit());
        replaced_inline =
            inline_min_max_sizes.ClampSizeToMinAndMax(inline_size);
      }
    }
  }

  if (replaced_inline && replaced_block)
    return LogicalSize(*replaced_inline, *replaced_block);

  // We have *only* an aspect-ratio with no sizes (natural or otherwise), we
  // default to stretching.
  if (!natural_size && !replaced_inline && !replaced_block) {
    replaced_inline = StretchFit();
    replaced_inline =
        inline_min_max_sizes.ClampSizeToMinAndMax(*replaced_inline);
  }

  // We only know one size, the other gets computed via the aspect-ratio (if
  // present), or defaults to the natural-size.
  if (replaced_inline) {
    DCHECK(!replaced_block);
    DCHECK(natural_size || !aspect_ratio.IsEmpty());
    replaced_block = aspect_ratio.IsEmpty() ? natural_size->block_size
                                            : BlockSizeFromAspectRatio(
                                                  border_padding, aspect_ratio,
                                                  box_sizing, *replaced_inline);
    replaced_block = block_min_max_sizes.ClampSizeToMinAndMax(*replaced_block);
    return LogicalSize(*replaced_inline, *replaced_block);
  }

  if (replaced_block) {
    DCHECK(!replaced_inline);
    DCHECK(natural_size || !aspect_ratio.IsEmpty());
    replaced_inline = aspect_ratio.IsEmpty() ? natural_size->inline_size
                                             : InlineSizeFromAspectRatio(
                                                   border_padding, aspect_ratio,
                                                   box_sizing, *replaced_block);
    replaced_inline =
        inline_min_max_sizes.ClampSizeToMinAndMax(*replaced_inline);
    return LogicalSize(*replaced_inline, *replaced_block);
  }

  // Both lengths are unknown, start with the natural-size.
  DCHECK(!replaced_inline);
  DCHECK(!replaced_block);
  replaced_inline = natural_size->inline_size;
  replaced_block = natural_size->block_size;

  // Apply the min/max sizes to the natural-size.
  const LayoutUnit constrained_inline =
      inline_min_max_sizes.ClampSizeToMinAndMax(*replaced_inline);
  const LayoutUnit constrained_block =
      block_min_max_sizes.ClampSizeToMinAndMax(*replaced_block);

  // If the min/max sizes had no effect, just return the natural-size.
  if (constrained_inline == replaced_inline &&
      constrained_block == replaced_block)
    return LogicalSize(*replaced_inline, *replaced_block);

  // If we have no aspect-ratio, use both constrained sizes.
  if (aspect_ratio.IsEmpty())
    return {constrained_inline, constrained_block};

  // The min/max sizes have applied, try to respect the aspect-ratio.

  // The following implements the table from section 10.4 at:
  // https://www.w3.org/TR/CSS22/visudet.html#min-max-widths
  const bool is_min_inline_constrained = constrained_inline > *replaced_inline;
  const bool is_max_inline_constrained = constrained_inline < *replaced_inline;
  const bool is_min_block_constrained = constrained_block > *replaced_block;
  const bool is_max_block_constrained = constrained_block < *replaced_block;

  // Constraints caused us to grow in one dimension and shrink in the other.
  // Use both constrained sizes.
  if ((is_max_inline_constrained && is_min_block_constrained) ||
      (is_min_inline_constrained && is_max_block_constrained))
    return {constrained_inline, constrained_block};

  const LayoutUnit hypothetical_block = BlockSizeFromAspectRatio(
      border_padding, aspect_ratio, box_sizing, constrained_inline);
  const LayoutUnit hypothetical_inline = InlineSizeFromAspectRatio(
      border_padding, aspect_ratio, box_sizing, constrained_block);

  // If the inline-size got constrained more extremely than the block-size, use
  // the constrained inline-size, and recalculate the block-size.
  if (constrained_block == *replaced_block ||
      (is_max_inline_constrained && hypothetical_block <= constrained_block) ||
      (is_min_inline_constrained &&
       constrained_inline >= hypothetical_inline)) {
    return {constrained_inline,
            block_min_max_sizes.ClampSizeToMinAndMax(hypothetical_block)};
  }

  // If the block-size got constrained more extremely than the inline-size, use
  // the constrained block-size, and recalculate the inline-size.
  return {inline_min_max_sizes.ClampSizeToMinAndMax(hypothetical_inline),
          constrained_block};
}

}  // namespace

// Computes size for a replaced element.
LogicalSize ComputeReplacedSize(const BlockNode& node,
                                const ConstraintSpace& space,
                                const BoxStrut& border_padding,
                                ReplacedSizeMode mode) {
  DCHECK(node.IsReplaced());

  const auto* svg_root = DynamicTo<LayoutSVGRoot>(node.GetLayoutBox());
  if (!svg_root || !svg_root->IsDocumentElement()) {
    return ComputeReplacedSizeInternal(node, space, border_padding, mode);
  }

  PhysicalSize container_size(svg_root->GetContainerSize());
  if (!container_size.IsEmpty()) {
    LogicalSize size =
        container_size.ConvertToLogical(node.Style().GetWritingMode());
    size.inline_size += border_padding.InlineSum();
    size.block_size += border_padding.BlockSum();
    return size;
  }

  if (svg_root->IsEmbeddedThroughFrameContainingSVGDocument()) {
    LogicalSize size = space.AvailableSize();
    size.block_size = node.Style().IsHorizontalWritingMode()
                          ? node.InitialContainingBlockSize().height
                          : node.InitialContainingBlockSize().width;
    return size;
  }

  LogicalSize size =
      ComputeReplacedSizeInternal(node, space, border_padding, mode);

  if (node.Style().LogicalWidth().HasPercent()) {
    double factor = svg_root->LogicalSizeScaleFactorForPercentageLengths();
    if (factor != 1.0) {
      // TODO(https://crbug.com/313072): Just because a calc *has* percentages
      // doesn't mean *all* the lengths are percentages.
      size.inline_size *= factor;
    }
  }

  const Length& logical_height = node.Style().LogicalHeight();
  if (logical_height.HasPercent()) {
    // TODO(https://crbug.com/313072): Might this also be needed for intrinsic
    // sizing keywords?
    LayoutUnit height = ValueForLength(
        logical_height,
        node.GetDocument().GetLayoutView()->ViewLogicalHeightForPercentages());
    double factor = svg_root->LogicalSizeScaleFactorForPercentageLengths();
    if (factor != 1.0) {
      // TODO(https://crbug.com/313072): Just because a calc *has* percentages
      // doesn't mean *all* the lengths are percentages.
      height *= factor;
    }
    size.block_size = height;
  }
  return size;
}

int ResolveUsedColumnCount(int computed_count,
                           LayoutUnit computed_size,
                           LayoutUnit used_gap,
                           LayoutUnit available_size) {
  if (computed_size == kIndefiniteSize) {
    DCHECK(computed_count);
    return computed_count;
  }
  DCHECK_GT(computed_size, LayoutUnit());
  int count_from_width =
      ((available_size + used_gap) / (computed_size + used_gap)).ToInt();
  count_from_width = std::max(1, count_from_width);
  if (!computed_count)
    return count_from_width;
  return std::max(1, std::min(computed_count, count_from_width));
}

int ResolveUsedColumnCount(LayoutUnit available_size,
                           const ComputedStyle& style) {
  LayoutUnit computed_column_inline_size =
      style.HasAutoColumnWidth()
          ? kIndefiniteSize
          : std::max(LayoutUnit(1), LayoutUnit(style.ColumnWidth()));
  LayoutUnit gap = ResolveUsedColumnGap(available_size, style);
  int computed_count = style.HasAutoColumnCount() ? 0 : style.ColumnCount();
  return ResolveUsedColumnCount(computed_count, computed_column_inline_size,
                                gap, available_size);
}

LayoutUnit ResolveUsedColumnInlineSize(int computed_count,
                                       LayoutUnit computed_size,
                                       LayoutUnit used_gap,
                                       LayoutUnit available_size) {
  int used_count = ResolveUsedColumnCount(computed_count, computed_size,
                                          used_gap, available_size);
  return std::max(((available_size + used_gap) / used_count) - used_gap,
                  LayoutUnit());
}

LayoutUnit ResolveUsedColumnInlineSize(LayoutUnit available_size,
                                       const ComputedStyle& style) {
  // Should only attempt to resolve this if columns != auto.
  DCHECK(!style.HasAutoColumnCount() || !style.HasAutoColumnWidth());

  LayoutUnit computed_size =
      style.HasAutoColumnWidth()
          ? kIndefiniteSize
          : std::max(LayoutUnit(1), LayoutUnit(style.ColumnWidth()));
  int computed_count = style.HasAutoColumnCount() ? 0 : style.ColumnCount();
  LayoutUnit used_gap = ResolveUsedColumnGap(available_size, style);
  return ResolveUsedColumnInlineSize(computed_count, computed_size, used_gap,
                                     available_size);
}

LayoutUnit ResolveUsedColumnGap(LayoutUnit available_size,
                                const ComputedStyle& style) {
  if (const std::optional<Length>& column_gap = style.ColumnGap()) {
    return ValueForLength(*column_gap, available_size);
  }
  return LayoutUnit(style.GetFontDescription().ComputedPixelSize());
}

LayoutUnit ColumnInlineProgression(LayoutUnit available_size,
                                   const ComputedStyle& style) {
  LayoutUnit column_inline_size =
      ResolveUsedColumnInlineSize(available_size, style);
  return column_inline_size + ResolveUsedColumnGap(available_size, style);
}

PhysicalBoxStrut ComputePhysicalMargins(
    const ComputedStyle& style,
    PhysicalSize percentage_resolution_size) {
  if (!style.MayHaveMargin())
    return PhysicalBoxStrut();

  return PhysicalBoxStrut(
      MinimumValueForLength(style.MarginTop(),
                            percentage_resolution_size.height),
      MinimumValueForLength(style.MarginRight(),
                            percentage_resolution_size.width),
      MinimumValueForLength(style.MarginBottom(),
                            percentage_resolution_size.height),
      MinimumValueForLength(style.MarginLeft(),
                            percentage_resolution_size.width));
}

BoxStrut ComputeMarginsFor(const ConstraintSpace& constraint_space,
                           const ComputedStyle& style,
                           const ConstraintSpace& compute_for) {
  if (!style.MayHaveMargin() || constraint_space.IsAnonymous())
    return BoxStrut();
  LogicalSize percentage_resolution_size =
      constraint_space.MarginPaddingPercentageResolutionSize();
  return ComputePhysicalMargins(style, percentage_resolution_size)
      .ConvertToLogical(compute_for.GetWritingDirection());
}

namespace {

BoxStrut ComputeBordersInternal(const ComputedStyle& style) {
  return {LayoutUnit(style.BorderInlineStartWidth()),
          LayoutUnit(style.BorderInlineEndWidth()),
          LayoutUnit(style.BorderBlockStartWidth()),
          LayoutUnit(style.BorderBlockEndWidth())};
}

}  // namespace

BoxStrut ComputeBorders(const ConstraintSpace& constraint_space,
                        const BlockNode& node) {
  // If we are producing an anonymous fragment (e.g. a column), it has no
  // borders, padding or scrollbars. Using the ones from the container can only
  // cause trouble.
  if (constraint_space.IsAnonymous())
    return BoxStrut();

  // If we are a table cell we just access the values set by the parent table
  // layout as border may be collapsed etc.
  if (constraint_space.IsTableCell())
    return constraint_space.TableCellBorders();

  if (node.IsTable()) {
    return To<TableNode>(node).GetTableBorders()->TableBorder();
  }

  return ComputeBordersInternal(node.Style());
}

BoxStrut ComputeBordersForInline(const ComputedStyle& style) {
  return ComputeBordersInternal(style);
}

BoxStrut ComputeNonCollapsedTableBorders(const ComputedStyle& style) {
  return ComputeBordersInternal(style);
}

BoxStrut ComputeBordersForTest(const ComputedStyle& style) {
  return ComputeBordersInternal(style);
}

BoxStrut ComputePadding(const ConstraintSpace& constraint_space,
                        const ComputedStyle& style) {
  // If we are producing an anonymous fragment (e.g. a column) we shouldn't
  // have any padding.
  if (!style.MayHavePadding() || constraint_space.IsAnonymous())
    return BoxStrut();

  // Tables with collapsed borders don't have any padding.
  if (style.IsDisplayTableBox() &&
      style.BorderCollapse() == EBorderCollapse::kCollapse) {
    return BoxStrut();
  }

  // This function may be called for determining intrinsic padding, clamp
  // indefinite %-sizes to zero. See:
  // https://drafts.csswg.org/css-sizing-3/#min-percentage-contribution
  LogicalSize percentage_resolution_size =
      constraint_space.MarginPaddingPercentageResolutionSize()
          .ClampIndefiniteToZero();
  return {MinimumValueForLength(style.PaddingInlineStart(),
                                percentage_resolution_size.inline_size),
          MinimumValueForLength(style.PaddingInlineEnd(),
                                percentage_resolution_size.inline_size),
          MinimumValueForLength(style.PaddingBlockStart(),
                                percentage_resolution_size.block_size),
          MinimumValueForLength(style.PaddingBlockEnd(),
                                percentage_resolution_size.block_size)};
}

BoxStrut ComputeScrollbarsForNonAnonymous(const BlockNode& node) {
  const ComputedStyle& style = node.Style();
  if (!style.IsScrollContainer() && style.IsScrollbarGutterAuto())
    return BoxStrut();
  const LayoutBox* layout_box = node.GetLayoutBox();
  return layout_box->ComputeLogicalScrollbars();
}

void ResolveInlineAutoMargins(const ComputedStyle& style,
                              const ComputedStyle& container_style,
                              LayoutUnit available_inline_size,
                              LayoutUnit inline_size,
                              BoxStrut* margins) {
  const LayoutUnit used_space = inline_size + margins->InlineSum();
  const LayoutUnit available_space = available_inline_size - used_space;
  bool is_start_auto = style.MarginInlineStartUsing(container_style).IsAuto();
  bool is_end_auto = style.MarginInlineEndUsing(container_style).IsAuto();
  if (is_start_auto && is_end_auto) {
    margins->inline_start = (available_space / 2).ClampNegativeToZero();
    margins->inline_end =
        available_inline_size - inline_size - margins->inline_start;
  } else if (is_start_auto) {
    margins->inline_start = available_space.ClampNegativeToZero();
  } else if (is_end_auto) {
    margins->inline_end =
        available_inline_size - inline_size - margins->inline_start;
  }
}

void ResolveAutoMargins(Length start_length,
                        Length end_length,
                        LayoutUnit additional_space,
                        LayoutUnit* start_result,
                        LayoutUnit* end_result) {
  bool start_is_auto = start_length.IsAuto();
  bool end_is_auto = end_length.IsAuto();
  if (start_is_auto) {
    if (end_is_auto) {
      *start_result = additional_space / 2;
      additional_space -= *start_result;
    } else {
      *start_result = additional_space;
    }
  }
  if (end_is_auto) {
    *end_result = additional_space;
  }
}

void ResolveAutoMargins(Length inline_start_length,
                        Length inline_end_length,
                        Length block_start_length,
                        Length block_end_length,
                        LayoutUnit additional_inline_space,
                        LayoutUnit additional_block_space,
                        BoxStrut* margins) {
  ResolveAutoMargins(inline_start_length, inline_end_length,
                     additional_inline_space, &margins->inline_start,
                     &margins->inline_end);
  ResolveAutoMargins(block_start_length, block_end_length,
                     additional_block_space, &margins->block_start,
                     &margins->block_end);
}

LayoutUnit LineOffsetForTextAlign(ETextAlign text_align,
                                  TextDirection direction,
                                  LayoutUnit space_left) {
  bool is_ltr = IsLtr(direction);
  if (text_align == ETextAlign::kStart || text_align == ETextAlign::kJustify)
    text_align = is_ltr ? ETextAlign::kLeft : ETextAlign::kRight;
  else if (text_align == ETextAlign::kEnd)
    text_align = is_ltr ? ETextAlign::kRight : ETextAlign::kLeft;

  switch (text_align) {
    case ETextAlign::kLeft:
    case ETextAlign::kWebkitLeft: {
      // The direction of the block should determine what happens with wide
      // lines. In particular with RTL blocks, wide lines should still spill
      // out to the left.
      if (is_ltr)
        return LayoutUnit();
      return space_left.ClampPositiveToZero();
    }
    case ETextAlign::kRight:
    case ETextAlign::kWebkitRight: {
      // In RTL, trailing spaces appear on the left of the line.
      if (!is_ltr) [[unlikely]] {
        return space_left;
      }
      // Wide lines spill out of the block based off direction.
      // So even if text-align is right, if direction is LTR, wide lines
      // should overflow out of the right side of the block.
      if (space_left > LayoutUnit())
        return space_left;
      return LayoutUnit();
    }
    case ETextAlign::kCenter:
    case ETextAlign::kWebkitCenter: {
      if (is_ltr)
        return (space_left / 2).ClampNegativeToZero();
      // In RTL, trailing spaces appear on the left of the line.
      if (space_left > LayoutUnit())
        return (space_left / 2).ClampNegativeToZero();
      // In RTL, wide lines should spill out to the left, same as kRight.
      return space_left;
    }
    default:
      NOTREACHED();
  }
}

// Calculates default content size for html and body elements in quirks mode.
// Returns |kIndefiniteSize| in all other cases.
LayoutUnit CalculateDefaultBlockSize(const ConstraintSpace& space,
                                     const BlockNode& node,
                                     const BlockBreakToken* break_token,
                                     const BoxStrut& border_scrollbar_padding) {
  // In quirks mode, html and body elements will completely fill the ICB, block
  // percentages should resolve against this size.
  if (node.IsQuirkyAndFillsViewport() && !IsBreakInside(break_token)) {
    LayoutUnit block_size = space.AvailableSize().block_size;
    block_size -= ComputeMarginsForSelf(space, node.Style()).BlockSum();
    return std::max(block_size.ClampNegativeToZero(),
                    border_scrollbar_padding.BlockSum());
  }
  return kIndefiniteSize;
}

FragmentGeometry CalculateInitialFragmentGeometry(
    const ConstraintSpace& space,
    const BlockNode& node,
    const BlockBreakToken* break_token,
    MinMaxSizesFunctionRef min_max_sizes_func,
    bool is_intrinsic) {
  const auto& style = node.Style();

  if (node.IsFrameSet()) {
    if (node.IsParentNGFrameSet()) {
      const auto size = space.AvailableSize();
      DCHECK_NE(size.inline_size, kIndefiniteSize);
      DCHECK_NE(size.block_size, kIndefiniteSize);
      DCHECK(space.IsFixedInlineSize());
      DCHECK(space.IsFixedBlockSize());
      return {size, {}, {}, {}};
    }

    const auto size = node.InitialContainingBlockSize();
    return {size.ConvertToLogical(style.GetWritingMode()), {}, {}, {}};
  }

  const auto border = ComputeBorders(space, node);
  const auto padding = ComputePadding(space, style);
  auto scrollbar = ComputeScrollbars(space, node);

  const auto border_padding = border + padding;
  const auto border_scro
"""


```