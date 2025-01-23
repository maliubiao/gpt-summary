Response:
The user wants me to analyze a C++ source code file (`layout_box.cc`) from the Chromium Blink engine. They specifically want me to:

1. **Summarize the file's functionality.**
2. **Explain its relationship to web technologies (JavaScript, HTML, CSS).**  Provide concrete examples.
3. **Illustrate logical reasoning with input/output examples.**
4. **Point out common user/programming errors related to the code.**
5. **Focus on the provided code snippet (Part 2 of 6) and summarize its specific functions.**

Let's break down the provided code snippet to understand its functionalities and address the user's requests for Part 2.

**Code Analysis (Part 2):**

The provided code primarily deals with updating the layout of a `LayoutBox` in response to style changes. It covers:

* **Grid Layout Updates:**  Functions related to updating grid item placement when grid-related CSS properties change.
* **Scroll Snap Updates:** Functions to handle updates related to CSS scroll snapping properties.
* **General Style Updates:** A function to apply style changes to the `LayoutBox`, including handling floating, transforms, reflections, and overflow clipping.
* **Layout Subtree Management:** A function to manage the layout of subtrees rooted at this `LayoutBox`.
* **Client Width/Height Calculations:** Functions to determine the usable content area of the box, excluding borders and scrollbars.
* **Special Handling for Tables:** Specific logic for calculating client width and height for table elements.
* **Scrollbar Determination:** A function to check if overlay scrollbars are used.
* **Scroll Width/Height Calculations:** Functions to determine the total scrollable area of the box.
* **Margin Information:** A function to retrieve the margin sizes.
* **Coordinate Mapping:** A function for converting coordinates to an ancestor's coordinate system.
* **Accessibility Bounding Box:** A function to get the bounding box for accessibility purposes.
* **Post-Layout Updates:** A function to perform updates after layout, like updating transforms and informing the input method controller.
* **Intrinsic Content Size Overrides:** Functions to override the default intrinsic content sizes based on CSS containment properties.
* **Default Intrinsic Content Size Calculations:** Functions to calculate default intrinsic content sizes for specific elements like `<select>`, `<input>`, and `<textarea>`.
* **Logical Position Retrieval:** Functions to get the logical left and top positions based on writing modes.
* **Absolute Content Quad Retrieval:** A function to get the absolute coordinates of the content area.
* **Background Rect Retrieval:** A function to determine the rectangle occupied by the background.
* **Outline Rect Addition:** A function to add the outline rectangle.
* **Resizing Capability Check:** A function to determine if the box is resizable.
* **Scrollbar Gutter Handling:** A function to check for the presence of scrollbar gutters.
* **Scrollbar Size Calculation:** A function to compute the sizes of the scrollbars.
* **Autoscroll Functionality:** Functions related to programmatically scrolling the element.
* **Finding Scrollable Ancestors:** A function to find the nearest ancestor that is scrollable.
* **Scrollbar Origin Adjustment:** A function to calculate the offset caused by scrollbars.
* **Scroll Position Retrieval:** Functions to get the current scroll position.
* **Clipping Rectangle Retrieval:** (The snippet ends abruptly here).

Now, I can formulate the answer by connecting these functionalities to the user's specific requests.
这是目录为blink/renderer/core/layout/layout_box.cc的chromium blink引擎源代码文件， 请列举一下它的功能,
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共6部分，请归纳一下它的功能

"""

}

namespace {

bool GridStyleChanged(const ComputedStyle* old_style,
                      const ComputedStyle& current_style) {
  return old_style->GridColumnStart() != current_style.GridColumnStart() ||
         old_style->GridColumnEnd() != current_style.GridColumnEnd() ||
         old_style->GridRowStart() != current_style.GridRowStart() ||
         old_style->GridRowEnd() != current_style.GridRowEnd() ||
         old_style->Order() != current_style.Order() ||
         old_style->HasOutOfFlowPosition() !=
             current_style.HasOutOfFlowPosition();
}

bool AlignmentChanged(const ComputedStyle* old_style,
                      const ComputedStyle& current_style) {
  return old_style->AlignSelf() != current_style.AlignSelf() ||
         old_style->JustifySelf() != current_style.JustifySelf();
}

}  // namespace

void LayoutBox::UpdateGridPositionAfterStyleChange(
    const ComputedStyle* old_style) {
  NOT_DESTROYED();

  if (!old_style)
    return;

  LayoutObject* parent = Parent();
  const bool was_out_of_flow = old_style->HasOutOfFlowPosition();
  const bool is_out_of_flow = StyleRef().HasOutOfFlowPosition();

  LayoutBlock* containing_block = ContainingBlock();
  if ((containing_block && containing_block->IsLayoutGrid()) &&
      GridStyleChanged(old_style, StyleRef())) {
    // Out-of-flow items do not impact grid placement.
    // TODO(kschmi): Scope this so that it only dirties the grid when track
    // sizing depends on grid item sizes.
    if (!was_out_of_flow || !is_out_of_flow)
      containing_block->SetGridPlacementDirty(true);

    // For out-of-flow elements with grid container as containing block, we need
    // to run the entire algorithm to place and size them correctly. As a
    // result, we trigger a full layout for GridNG.
    if (is_out_of_flow) {
      containing_block->SetNeedsLayout(layout_invalidation_reason::kGridChanged,
                                       kMarkContainerChain);
    }
  }

  // GridNG computes static positions for out-of-flow elements at layout time,
  // with alignment offsets baked in. So if alignment changes, we need to
  // schedule a layout.
  if (is_out_of_flow && AlignmentChanged(old_style, StyleRef())) {
    LayoutObject* grid_ng_ancestor = nullptr;
    if (containing_block && containing_block->IsLayoutGrid()) {
      grid_ng_ancestor = containing_block;
    } else if (parent && parent->IsLayoutGrid()) {
      grid_ng_ancestor = parent;
    }

    if (grid_ng_ancestor) {
      grid_ng_ancestor->SetNeedsLayout(layout_invalidation_reason::kGridChanged,
                                       kMarkContainerChain);
    }
  }
}

void LayoutBox::UpdateScrollSnapMappingAfterStyleChange(
    const ComputedStyle& old_style) {
  NOT_DESTROYED();
  DCHECK(Style());
  // scroll-snap-type and scroll-padding invalidate the snap container.
  if (old_style.GetScrollSnapType() != StyleRef().GetScrollSnapType() ||
      old_style.ScrollPaddingBottom() != StyleRef().ScrollPaddingBottom() ||
      old_style.ScrollPaddingLeft() != StyleRef().ScrollPaddingLeft() ||
      old_style.ScrollPaddingTop() != StyleRef().ScrollPaddingTop() ||
      old_style.ScrollPaddingRight() != StyleRef().ScrollPaddingRight()) {
    if (!NeedsLayout() && IsScrollContainer()) {
      GetScrollableArea()->EnqueueForSnapUpdateIfNeeded();
    }
  }

  // scroll-snap-align invalidates layout as we need to propagate the
  // snap-areas up the fragment-tree.
  if (old_style.GetScrollSnapAlign() != StyleRef().GetScrollSnapAlign()) {
    if (auto* containing_block = ContainingBlock()) {
      containing_block->SetNeedsLayout(layout_invalidation_reason::kStyleChange,
                                       kMarkContainerChain);
    }
  }

  auto SnapAreaDidChange = [&]() {
    auto* snap_container = ContainingScrollContainer();
    if (snap_container && !snap_container->NeedsLayout()) {
      snap_container->GetScrollableArea()->EnqueueForSnapUpdateIfNeeded();
    }
  };

  // scroll-snap-stop and scroll-margin invalidate the snap area.
  if (old_style.ScrollSnapStop() != StyleRef().ScrollSnapStop() ||
      old_style.ScrollMarginBottom() != StyleRef().ScrollMarginBottom() ||
      old_style.ScrollMarginLeft() != StyleRef().ScrollMarginLeft() ||
      old_style.ScrollMarginTop() != StyleRef().ScrollMarginTop() ||
      old_style.ScrollMarginRight() != StyleRef().ScrollMarginRight()) {
    SnapAreaDidChange();
  }

  // Transform invalidates the snap area.
  if (old_style.Transform() != StyleRef().Transform())
    SnapAreaDidChange();
}

void LayoutBox::UpdateFromStyle() {
  NOT_DESTROYED();
  LayoutBoxModelObject::UpdateFromStyle();

  const ComputedStyle& style_to_use = StyleRef();
  SetFloating(style_to_use.IsFloating() && !IsOutOfFlowPositioned() &&
              !style_to_use.IsInsideDisplayIgnoringFloatingChildren());
  SetHasTransformRelatedProperty(
      IsSVGChild() ? style_to_use.HasTransformRelatedPropertyForSVG()
                   : style_to_use.HasTransformRelatedProperty());
  SetHasReflection(style_to_use.BoxReflect());

  bool should_clip_overflow = (!StyleRef().IsOverflowVisibleAlongBothAxes() ||
                               ShouldApplyPaintContainment()) &&
                              RespectsCSSOverflow();
  if (should_clip_overflow != HasNonVisibleOverflow()) {
    // The overflow clip paint property depends on whether overflow clip is
    // present so we need to update paint properties if this changes.
    SetNeedsPaintPropertyUpdate();
    if (Layer())
      Layer()->SetNeedsCompositingInputsUpdate();
  }
  SetHasNonVisibleOverflow(should_clip_overflow);
}

void LayoutBox::LayoutSubtreeRoot() {
  NOT_DESTROYED();

  // Our own style may have changed which would disqualify us as a layout root
  // (e.g. our containment/writing-mode/formatting-context status/etc changed).
  // Skip subtree layout, and ensure our container chain needs layout.
  if (SelfNeedsFullLayout()) {
    MarkContainerChainForLayout();
    return;
  }

  const auto* previous_result = GetSingleCachedLayoutResult();
  DCHECK(previous_result);
  auto space = previous_result->GetConstraintSpaceForCaching();
  DCHECK_EQ(space.GetWritingMode(), StyleRef().GetWritingMode());
  const LayoutResult* result = BlockNode(this).Layout(space);
  GetDocument().GetFrame()->GetInputMethodController().DidLayoutSubtree(*this);

  if (IsOutOfFlowPositioned()) {
    result->CopyMutableOutOfFlowData(*previous_result);
  }

  // Even if we are a subtree layout root we need to mark our containing-block
  // for layout if:
  //  - Our baselines have shifted.
  //  - We've propagated any layout-objects (which affect our container chain).
  //
  // NOTE: We could weaken the constraints in ObjectIsRelayoutBoundary, and use
  // this technique to detect size-changes, etc if we wanted to expand this
  // optimization.
  const auto& previous_fragment =
      To<PhysicalBoxFragment>(previous_result->GetPhysicalFragment());
  const auto& fragment = To<PhysicalBoxFragment>(result->GetPhysicalFragment());
  if (previous_fragment.FirstBaseline() != fragment.FirstBaseline() ||
      previous_fragment.LastBaseline() != fragment.LastBaseline() ||
      fragment.HasPropagatedLayoutObjects()) {
    if (auto* containing_block = ContainingBlock()) {
      containing_block->SetNeedsLayout(
          layout_invalidation_reason::kChildChanged, kMarkContainerChain);
    }
  }
}

// ClientWidth and ClientHeight represent the interior of an object excluding
// border and scrollbar.
DISABLE_CFI_PERF
LayoutUnit LayoutBox::ClientWidth() const {
  NOT_DESTROYED();
  // We need to clamp negative values. This function may be called during layout
  // before frame_size_ gets the final proper value. Another reason: While
  // border side values are currently limited to 2^20px (a recent change in the
  // code), if this limit is raised again in the future, we'd have ill effects
  // of saturated arithmetic otherwise.
  LayoutUnit width = Size().width;
  if (CanSkipComputeScrollbars()) {
    return (width - BorderLeft() - BorderRight()).ClampNegativeToZero();
  } else {
    return (width - BorderLeft() - BorderRight() -
            ComputeScrollbarsInternal(kClampToContentBox).HorizontalSum())
        .ClampNegativeToZero();
  }
}

DISABLE_CFI_PERF
LayoutUnit LayoutBox::ClientHeight() const {
  NOT_DESTROYED();
  // We need to clamp negative values. This function can be called during layout
  // before frame_size_ gets the final proper value. The scrollbar may be wider
  // than the padding box. Another reason: While border side values are
  // currently limited to 2^20px (a recent change in the code), if this limit is
  // raised again in the future, we'd have ill effects of saturated arithmetic
  // otherwise.
  LayoutUnit height = Size().height;
  if (CanSkipComputeScrollbars()) {
    return (height - BorderTop() - BorderBottom()).ClampNegativeToZero();
  } else {
    return (height - BorderTop() - BorderBottom() -
            ComputeScrollbarsInternal(kClampToContentBox).VerticalSum())
        .ClampNegativeToZero();
  }
}

LayoutUnit LayoutBox::ClientWidthFrom(LayoutUnit width) const {
  NOT_DESTROYED();
  if (CanSkipComputeScrollbars()) {
    return (width - BorderLeft() - BorderRight()).ClampNegativeToZero();
  } else {
    return (width - BorderLeft() - BorderRight() -
            ComputeScrollbarsInternal(kClampToContentBox).HorizontalSum())
        .ClampNegativeToZero();
  }
}

LayoutUnit LayoutBox::ClientHeightFrom(LayoutUnit height) const {
  NOT_DESTROYED();
  if (CanSkipComputeScrollbars()) {
    return (height - BorderTop() - BorderBottom()).ClampNegativeToZero();
  } else {
    return (height - BorderTop() - BorderBottom() -
            ComputeScrollbarsInternal(kClampToContentBox).VerticalSum())
        .ClampNegativeToZero();
  }
}

LayoutUnit LayoutBox::ClientWidthWithTableSpecialBehavior() const {
  NOT_DESTROYED();
  // clientWidth/Height is the visual portion of the box content, not including
  // borders or scroll bars, but includes padding. And per
  // https://www.w3.org/TR/CSS2/tables.html#model,
  // table wrapper box is a principal block box that contains the table box
  // itself and any caption boxes, and table grid box is a block-level box that
  // contains the table's internal table boxes. When table's border is specified
  // in CSS, the border is added to table grid box, not table wrapper box.
  // Currently, Blink doesn't have table wrapper box, and we are supposed to
  // retrieve clientWidth/Height from table wrapper box, not table grid box. So
  // when we retrieve clientWidth/Height, it includes table's border size.
  if (IsTable())
    return ClientWidth() + BorderLeft() + BorderRight();
  return ClientWidth();
}

LayoutUnit LayoutBox::ClientHeightWithTableSpecialBehavior() const {
  NOT_DESTROYED();
  // clientWidth/Height is the visual portion of the box content, not including
  // borders or scroll bars, but includes padding. And per
  // https://www.w3.org/TR/CSS2/tables.html#model,
  // table wrapper box is a principal block box that contains the table box
  // itself and any caption boxes, and table grid box is a block-level box that
  // contains the table's internal table boxes. When table's border is specified
  // in CSS, the border is added to table grid box, not table wrapper box.
  // Currently, Blink doesn't have table wrapper box, and we are supposed to
  // retrieve clientWidth/Height from table wrapper box, not table grid box. So
  // when we retrieve clientWidth/Height, it includes table's border size.
  if (IsTable())
    return ClientHeight() + BorderTop() + BorderBottom();
  return ClientHeight();
}

bool LayoutBox::UsesOverlayScrollbars() const {
  NOT_DESTROYED();
  if (StyleRef().HasCustomScrollbarStyle(DynamicTo<Element>(GetNode()))) {
    return false;
  }
  if (GetFrame()->GetPage()->GetScrollbarTheme().UsesOverlayScrollbars())
    return true;
  return false;
}

LayoutUnit LayoutBox::ScrollWidth() const {
  NOT_DESTROYED();
  if (IsScrollContainer())
    return GetScrollableArea()->ScrollWidth();
  if (StyleRef().IsScrollbarGutterStable() &&
      StyleRef().OverflowBlockDirection() == EOverflow::kHidden) {
    if (auto* scrollable_area = GetScrollableArea())
      return scrollable_area->ScrollWidth();
    else
      return ScrollableOverflowRect().Width();
  }
  // For objects with scrollable overflow, this matches IE.
  PhysicalRect overflow_rect = ScrollableOverflowRect();
  if (!StyleRef().GetWritingDirection().IsFlippedX()) {
    return std::max(ClientWidth(), overflow_rect.Right() - BorderLeft());
  }
  return ClientWidth() -
         std::min(LayoutUnit(), overflow_rect.X() - BorderLeft());
}

LayoutUnit LayoutBox::ScrollHeight() const {
  NOT_DESTROYED();
  if (IsScrollContainer())
    return GetScrollableArea()->ScrollHeight();
  if (StyleRef().IsScrollbarGutterStable() &&
      StyleRef().OverflowBlockDirection() == EOverflow::kHidden) {
    if (auto* scrollable_area = GetScrollableArea())
      return scrollable_area->ScrollHeight();
    else
      return ScrollableOverflowRect().Height();
  }
  // For objects with visible overflow, this matches IE.
  // FIXME: Need to work right with writing modes.
  return std::max(ClientHeight(),
                  ScrollableOverflowRect().Bottom() - BorderTop());
}

PhysicalBoxStrut LayoutBox::MarginBoxOutsets() const {
  NOT_DESTROYED();
  if (PhysicalFragmentCount()) {
    // We get margin data from the first physical fragment. Margins are
    // per-LayoutBox data, and we don't need to take care of block
    // fragmentation.
    return GetPhysicalFragment(0)->Margins();
  }
  return PhysicalBoxStrut();
}

void LayoutBox::QuadsInAncestorInternal(Vector<gfx::QuadF>& quads,
                                        const LayoutBoxModelObject* ancestor,
                                        MapCoordinatesFlags mode) const {
  NOT_DESTROYED();
  if (LayoutFlowThread* flow_thread = FlowThreadContainingBlock()) {
    flow_thread->QuadsInAncestorForDescendant(*this, quads, ancestor, mode);
    return;
  }
  quads.push_back(
      LocalRectToAncestorQuad(PhysicalBorderBoxRect(), ancestor, mode));
}

gfx::RectF LayoutBox::LocalBoundingBoxRectForAccessibility() const {
  NOT_DESTROYED();
  PhysicalSize size = Size();
  return gfx::RectF(0, 0, size.width.ToFloat(), size.height.ToFloat());
}

void LayoutBox::UpdateAfterLayout() {
  NOT_DESTROYED();
  // Transform-origin depends on box size, so we need to update the layer
  // transform after layout.
  if (HasLayer()) {
    Layer()->UpdateTransform();
    Layer()->UpdateScrollingAfterLayout();
  }

  GetFrame()->GetInputMethodController().DidUpdateLayout(*this);
  if (IsPositioned())
    GetFrame()->GetInputMethodController().DidLayoutSubtree(*this);
}

LayoutUnit LayoutBox::OverrideIntrinsicContentInlineSize() const {
  NOT_DESTROYED();

  // We only override a size contained dimension.
  if (!ShouldApplyInlineSizeContainment()) {
    return kIndefiniteSize;
  }

  const auto& style = StyleRef();
  const StyleIntrinsicLength& intrinsic_length =
      style.ContainIntrinsicInlineSize();

  if (intrinsic_length.HasAuto()) {
    const auto* context = GetDisplayLockContext();
    if (context && context->IsLocked()) {
      if (const auto* elem = DynamicTo<Element>(GetNode())) {
        if (const auto inline_size = elem->LastRememberedInlineSize()) {
          // ResizeObserverSize is adjusted to be in CSS space, we need to
          // adjust it back to Layout space by applying the effective zoom.
          return LayoutUnit::FromFloatRound(*inline_size *
                                            style.EffectiveZoom());
        }
      }
    }
  }

  if (const auto& length = intrinsic_length.GetLength()) {
    DCHECK(length->IsFixed());
    return LayoutUnit(length->Value());
  }

  return kIndefiniteSize;
}

LayoutUnit LayoutBox::OverrideIntrinsicContentBlockSize() const {
  NOT_DESTROYED();

  // We only override a size contained dimension.
  if (!ShouldApplyBlockSizeContainment()) {
    return kIndefiniteSize;
  }

  const auto& style = StyleRef();
  const StyleIntrinsicLength& intrinsic_length =
      style.ContainIntrinsicBlockSize();

  if (intrinsic_length.HasAuto()) {
    const auto* context = GetDisplayLockContext();
    if (context && context->IsLocked()) {
      if (const auto* elem = DynamicTo<Element>(GetNode())) {
        if (const auto inline_size = elem->LastRememberedBlockSize()) {
          // ResizeObserverSize is adjusted to be in CSS space, we need to
          // adjust it back to Layout space by applying the effective zoom.
          return LayoutUnit::FromFloatRound(*inline_size *
                                            style.EffectiveZoom());
        }
      }
    }
  }

  if (const auto& length = intrinsic_length.GetLength()) {
    DCHECK(length->IsFixed());
    return LayoutUnit(length->Value());
  }

  return kIndefiniteSize;
}

LayoutUnit LayoutBox::DefaultIntrinsicContentInlineSize() const {
  NOT_DESTROYED();

  if (!IsA<Element>(GetNode()))
    return kIndefiniteSize;
  const Element& element = *To<Element>(GetNode());

  const bool apply_fixed_size = StyleRef().ApplyControlFixedSize(&element);
  const auto* select = DynamicTo<HTMLSelectElement>(element);
  if (select && select->UsesMenuList() && !select->IsAppearanceBaseButton())
      [[unlikely]] {
    return apply_fixed_size ? MenuListIntrinsicInlineSize(*select, *this)
                            : kIndefiniteSize;
  }
  const auto* input = DynamicTo<HTMLInputElement>(element);
  if (input) [[unlikely]] {
    if (input->IsTextField() && apply_fixed_size) {
      return TextFieldIntrinsicInlineSize(*input, *this);
    }
    FormControlType type = input->FormControlType();
    if (type == FormControlType::kInputFile && apply_fixed_size) {
      return FileUploadControlIntrinsicInlineSize(*input, *this);
    }
    if (type == FormControlType::kInputRange) {
      return SliderIntrinsicInlineSize(*this);
    }
    auto effective_appearance = StyleRef().EffectiveAppearance();
    if (effective_appearance == kCheckboxPart) {
      return ThemePartIntrinsicSize(*this, WebThemeEngine::kPartCheckbox)
          .inline_size;
    }
    if (effective_appearance == kRadioPart) {
      return ThemePartIntrinsicSize(*this, WebThemeEngine::kPartRadio)
          .inline_size;
    }
    return kIndefiniteSize;
  }
  const auto* textarea = DynamicTo<HTMLTextAreaElement>(element);
  if (textarea && apply_fixed_size) [[unlikely]] {
    return TextAreaIntrinsicInlineSize(*textarea, *this);
  }
  if (IsSliderContainer(element))
    return SliderIntrinsicInlineSize(*this);

  return kIndefiniteSize;
}

LayoutUnit LayoutBox::DefaultIntrinsicContentBlockSize() const {
  NOT_DESTROYED();

  auto effective_appearance = StyleRef().EffectiveAppearance();
  if (effective_appearance == kCheckboxPart) {
    return ThemePartIntrinsicSize(*this, WebThemeEngine::kPartCheckbox)
        .block_size;
  }
  if (effective_appearance == kRadioPart) {
    return ThemePartIntrinsicSize(*this, WebThemeEngine::kPartRadio).block_size;
  }

  if (!StyleRef().ApplyControlFixedSize(GetNode())) {
    return kIndefiniteSize;
  }
  if (const auto* select = DynamicTo<HTMLSelectElement>(GetNode())) {
    if (!select->IsAppearanceBaseButton()) {
      if (select->UsesMenuList()) {
        return MenuListIntrinsicBlockSize(*select, *this);
      }
      return ListBoxItemBlockSize(*select, *this) * select->ListBoxSize() -
             ComputeLogicalScrollbars().BlockSum();
    }
  }
  if (IsTextField()) {
    return TextFieldIntrinsicBlockSize(*To<HTMLInputElement>(GetNode()), *this);
  }
  if (IsTextArea()) {
    return TextAreaIntrinsicBlockSize(*To<HTMLTextAreaElement>(GetNode()),
                                      *this);
  }

  return kIndefiniteSize;
}

LayoutUnit LayoutBox::LogicalLeft() const {
  NOT_DESTROYED();
  auto [offset, container_writing_mode] = LogicalLocation(*this);
  return IsParallelWritingMode(container_writing_mode,
                               StyleRef().GetWritingMode())
             ? offset.inline_offset
             : offset.block_offset;
}

LayoutUnit LayoutBox::LogicalTop() const {
  NOT_DESTROYED();
  auto [offset, container_writing_mode] = LogicalLocation(*this);
  return IsParallelWritingMode(container_writing_mode,
                               StyleRef().GetWritingMode())
             ? offset.block_offset
             : offset.inline_offset;
}

gfx::QuadF LayoutBox::AbsoluteContentQuad(MapCoordinatesFlags flags) const {
  NOT_DESTROYED();
  PhysicalRect rect = PhysicalContentBoxRect();
  return LocalRectToAbsoluteQuad(rect, flags);
}

PhysicalRect LayoutBox::PhysicalBackgroundRect(
    BackgroundRectType rect_type) const {
  NOT_DESTROYED();
  // If the background transfers to view, the used background of this object
  // is transparent.
  if (rect_type == kBackgroundKnownOpaqueRect && BackgroundTransfersToView())
    return PhysicalRect();

  std::optional<EFillBox> background_box;
  Color background_color = ResolveColor(GetCSSPropertyBackgroundColor());
  // Find the largest background rect of the given opaqueness.
  for (const FillLayer* cur = &(StyleRef().BackgroundLayers()); cur;
       cur = cur->Next()) {
    EFillBox current_clip = cur->Clip();
    if (rect_type == kBackgroundKnownOpaqueRect) {
      if (current_clip == EFillBox::kText)
        continue;

      if (cur->GetBlendMode() != BlendMode::kNormal ||
          cur->Composite() != kCompositeSourceOver)
        continue;

      bool layer_known_opaque = false;
      // Check if the image is opaque and fills the clip.
      if (const StyleImage* image = cur->GetImage()) {
        if ((cur->Repeat().x == EFillRepeat::kRepeatFill ||
             cur->Repeat().x == EFillRepeat::kRoundFill) &&
            (cur->Repeat().y == EFillRepeat::kRepeatFill ||
             cur->Repeat().y == EFillRepeat::kRoundFill) &&
            image->KnownToBeOpaque(GetDocument(), StyleRef())) {
          layer_known_opaque = true;
        }
      }

      // The background color is painted into the last layer.
      if (!cur->Next() && background_color.IsOpaque()) {
        layer_known_opaque = true;
      }

      // If neither the image nor the color are opaque then skip this layer.
      if (!layer_known_opaque)
        continue;
    } else {
      // Ignore invisible background layers for kBackgroundPaintedExtent.
      DCHECK_EQ(rect_type, kBackgroundPaintedExtent);
      if (!cur->GetImage() &&
          (cur->Next() || background_color.IsFullyTransparent())) {
        continue;
      }
      // A content-box clipped fill layer can be scrolled into the padding box
      // of the overflow container.
      if (current_clip == EFillBox::kContent &&
          cur->Attachment() == EFillAttachment::kLocal) {
        current_clip = EFillBox::kPadding;
      }
    }

    // Restrict clip if attachment is local.
    if (current_clip == EFillBox::kBorder &&
        cur->Attachment() == EFillAttachment::kLocal)
      current_clip = EFillBox::kPadding;

    background_box = background_box
                         ? EnclosingFillBox(*background_box, current_clip)
                         : current_clip;
  }

  if (!background_box)
    return PhysicalRect();

  if (*background_box == EFillBox::kText) {
    DCHECK_NE(rect_type, kBackgroundKnownOpaqueRect);
    *background_box = EFillBox::kBorder;
  }

  if (rect_type == kBackgroundPaintedExtent &&
      *background_box == EFillBox::kBorder &&
      BackgroundClipBorderBoxIsEquivalentToPaddingBox()) {
    *background_box = EFillBox::kPadding;
  }

  switch (*background_box) {
    case EFillBox::kBorder:
      return PhysicalBorderBoxRect();
    case EFillBox::kPadding:
      return PhysicalPaddingBoxRect();
    case EFillBox::kContent:
      return PhysicalContentBoxRect();
    default:
      NOTREACHED();
  }
}

void LayoutBox::AddOutlineRects(OutlineRectCollector& collector,
                                OutlineInfo* info,
                                const PhysicalOffset& additional_offset,
                                OutlineType) const {
  NOT_DESTROYED();
  collector.AddRect(PhysicalRect(additional_offset, Size()));
  if (info)
    *info = OutlineInfo::GetFromStyle(StyleRef());
}

bool LayoutBox::CanResize() const {
  NOT_DESTROYED();
  // We need a special case for <iframe> because they never have
  // hasOverflowClip(). However, they do "implicitly" clip their contents, so
  // we want to allow resizing them also.
  return (IsScrollContainer() || IsLayoutIFrame()) && StyleRef().HasResize();
}

bool LayoutBox::HasScrollbarGutters(ScrollbarOrientation orientation) const {
  NOT_DESTROYED();
  if (StyleRef().IsScrollbarGutterAuto())
    return false;

  DCHECK(StyleRef().IsScrollbarGutterStable());

  // Scrollbar-gutter propagates to the viewport
  // (see:|StyleResolver::PropagateStyleToViewport|).
  if (orientation == kVerticalScrollbar) {
    EOverflow overflow = StyleRef().OverflowY();
    return StyleRef().IsHorizontalWritingMode() &&
           (overflow == EOverflow::kAuto || overflow == EOverflow::kScroll ||
            overflow == EOverflow::kHidden) &&
           !UsesOverlayScrollbars() &&
           GetNode() != GetDocument().ViewportDefiningElement();
  } else {
    EOverflow overflow = StyleRef().OverflowX();
    return !StyleRef().IsHorizontalWritingMode() &&
           (overflow == EOverflow::kAuto || overflow == EOverflow::kScroll ||
            overflow == EOverflow::kHidden) &&
           !UsesOverlayScrollbars() &&
           GetNode() != GetDocument().ViewportDefiningElement();
  }
}

PhysicalBoxStrut LayoutBox::ComputeScrollbarsInternal(
    ShouldClampToContentBox clamp_to_content_box,
    OverlayScrollbarClipBehavior overlay_scrollbar_clip_behavior,
    ShouldIncludeScrollbarGutter include_scrollbar_gutter) const {
  NOT_DESTROYED();
  PhysicalBoxStrut scrollbars;
  PaintLayerScrollableArea* scrollable_area = GetScrollableArea();

  if (include_scrollbar_gutter == kIncludeScrollbarGutter &&
      HasScrollbarGutters(kVerticalScrollbar)) {
    LayoutUnit gutter_size = LayoutUnit(HypotheticalScrollbarThickness(
        *this, kVerticalScrollbar, /* include_overlay_thickness */ true));
    if (ShouldPlaceVerticalScrollbarOnLeft()) {
      scrollbars.left = gutter_size;
      if (StyleRef().IsScrollbarGutterBothEdges())
        scrollbars.right = gutter_size;
    } else {
      scrollbars.right = gutter_size;
      if (StyleRef().IsScrollbarGutterBothEdges())
        scrollbars.left = gutter_size;
    }
  } else if (scrollable_area) {
    if (ShouldPlaceVerticalScrollbarOnLeft()) {
      scrollbars.left = LayoutUnit(scrollable_area->VerticalScrollbarWidth(
          overlay_scrollbar_clip_behavior));
    } else {
      scrollbars.right = LayoutUnit(scrollable_area->VerticalScrollbarWidth(
          overlay_scrollbar_clip_behavior));
    }
  }

  if (include_scrollbar_gutter == kIncludeScrollbarGutter &&
      HasScrollbarGutters(kHorizontalScrollbar)) {
    LayoutUnit gutter_size = LayoutUnit(
        HypotheticalScrollbarThickness(*this, kHorizontalScrollbar,
                                       /* include_overlay_thickness */ true));
    scrollbars.bottom = gutter_size;
    if (StyleRef().IsScrollbarGutterBothEdges())
      scrollbars.top = gutter_size;
  } else if (scrollable_area) {
    scrollbars.bottom = LayoutUnit(scrollable_area->HorizontalScrollbarHeight(
        overlay_scrollbar_clip_behavior));
  }

  // Use the width of the vertical scrollbar, unless it's larger than the
  // logical width of the content box, in which case we'll use that instead.
  // Scrollbar handling is quite bad in such situations, and this code here
  // is just to make sure that left-hand scrollbars don't mess up
  // scrollWidth. For the
### 提示词
```
这是目录为blink/renderer/core/layout/layout_box.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
}

namespace {

bool GridStyleChanged(const ComputedStyle* old_style,
                      const ComputedStyle& current_style) {
  return old_style->GridColumnStart() != current_style.GridColumnStart() ||
         old_style->GridColumnEnd() != current_style.GridColumnEnd() ||
         old_style->GridRowStart() != current_style.GridRowStart() ||
         old_style->GridRowEnd() != current_style.GridRowEnd() ||
         old_style->Order() != current_style.Order() ||
         old_style->HasOutOfFlowPosition() !=
             current_style.HasOutOfFlowPosition();
}

bool AlignmentChanged(const ComputedStyle* old_style,
                      const ComputedStyle& current_style) {
  return old_style->AlignSelf() != current_style.AlignSelf() ||
         old_style->JustifySelf() != current_style.JustifySelf();
}

}  // namespace

void LayoutBox::UpdateGridPositionAfterStyleChange(
    const ComputedStyle* old_style) {
  NOT_DESTROYED();

  if (!old_style)
    return;

  LayoutObject* parent = Parent();
  const bool was_out_of_flow = old_style->HasOutOfFlowPosition();
  const bool is_out_of_flow = StyleRef().HasOutOfFlowPosition();

  LayoutBlock* containing_block = ContainingBlock();
  if ((containing_block && containing_block->IsLayoutGrid()) &&
      GridStyleChanged(old_style, StyleRef())) {
    // Out-of-flow items do not impact grid placement.
    // TODO(kschmi): Scope this so that it only dirties the grid when track
    // sizing depends on grid item sizes.
    if (!was_out_of_flow || !is_out_of_flow)
      containing_block->SetGridPlacementDirty(true);

    // For out-of-flow elements with grid container as containing block, we need
    // to run the entire algorithm to place and size them correctly. As a
    // result, we trigger a full layout for GridNG.
    if (is_out_of_flow) {
      containing_block->SetNeedsLayout(layout_invalidation_reason::kGridChanged,
                                       kMarkContainerChain);
    }
  }

  // GridNG computes static positions for out-of-flow elements at layout time,
  // with alignment offsets baked in. So if alignment changes, we need to
  // schedule a layout.
  if (is_out_of_flow && AlignmentChanged(old_style, StyleRef())) {
    LayoutObject* grid_ng_ancestor = nullptr;
    if (containing_block && containing_block->IsLayoutGrid()) {
      grid_ng_ancestor = containing_block;
    } else if (parent && parent->IsLayoutGrid()) {
      grid_ng_ancestor = parent;
    }

    if (grid_ng_ancestor) {
      grid_ng_ancestor->SetNeedsLayout(layout_invalidation_reason::kGridChanged,
                                       kMarkContainerChain);
    }
  }
}

void LayoutBox::UpdateScrollSnapMappingAfterStyleChange(
    const ComputedStyle& old_style) {
  NOT_DESTROYED();
  DCHECK(Style());
  // scroll-snap-type and scroll-padding invalidate the snap container.
  if (old_style.GetScrollSnapType() != StyleRef().GetScrollSnapType() ||
      old_style.ScrollPaddingBottom() != StyleRef().ScrollPaddingBottom() ||
      old_style.ScrollPaddingLeft() != StyleRef().ScrollPaddingLeft() ||
      old_style.ScrollPaddingTop() != StyleRef().ScrollPaddingTop() ||
      old_style.ScrollPaddingRight() != StyleRef().ScrollPaddingRight()) {
    if (!NeedsLayout() && IsScrollContainer()) {
      GetScrollableArea()->EnqueueForSnapUpdateIfNeeded();
    }
  }

  // scroll-snap-align invalidates layout as we need to propagate the
  // snap-areas up the fragment-tree.
  if (old_style.GetScrollSnapAlign() != StyleRef().GetScrollSnapAlign()) {
    if (auto* containing_block = ContainingBlock()) {
      containing_block->SetNeedsLayout(layout_invalidation_reason::kStyleChange,
                                       kMarkContainerChain);
    }
  }

  auto SnapAreaDidChange = [&]() {
    auto* snap_container = ContainingScrollContainer();
    if (snap_container && !snap_container->NeedsLayout()) {
      snap_container->GetScrollableArea()->EnqueueForSnapUpdateIfNeeded();
    }
  };

  // scroll-snap-stop and scroll-margin invalidate the snap area.
  if (old_style.ScrollSnapStop() != StyleRef().ScrollSnapStop() ||
      old_style.ScrollMarginBottom() != StyleRef().ScrollMarginBottom() ||
      old_style.ScrollMarginLeft() != StyleRef().ScrollMarginLeft() ||
      old_style.ScrollMarginTop() != StyleRef().ScrollMarginTop() ||
      old_style.ScrollMarginRight() != StyleRef().ScrollMarginRight()) {
    SnapAreaDidChange();
  }

  // Transform invalidates the snap area.
  if (old_style.Transform() != StyleRef().Transform())
    SnapAreaDidChange();
}

void LayoutBox::UpdateFromStyle() {
  NOT_DESTROYED();
  LayoutBoxModelObject::UpdateFromStyle();

  const ComputedStyle& style_to_use = StyleRef();
  SetFloating(style_to_use.IsFloating() && !IsOutOfFlowPositioned() &&
              !style_to_use.IsInsideDisplayIgnoringFloatingChildren());
  SetHasTransformRelatedProperty(
      IsSVGChild() ? style_to_use.HasTransformRelatedPropertyForSVG()
                   : style_to_use.HasTransformRelatedProperty());
  SetHasReflection(style_to_use.BoxReflect());

  bool should_clip_overflow = (!StyleRef().IsOverflowVisibleAlongBothAxes() ||
                               ShouldApplyPaintContainment()) &&
                              RespectsCSSOverflow();
  if (should_clip_overflow != HasNonVisibleOverflow()) {
    // The overflow clip paint property depends on whether overflow clip is
    // present so we need to update paint properties if this changes.
    SetNeedsPaintPropertyUpdate();
    if (Layer())
      Layer()->SetNeedsCompositingInputsUpdate();
  }
  SetHasNonVisibleOverflow(should_clip_overflow);
}

void LayoutBox::LayoutSubtreeRoot() {
  NOT_DESTROYED();

  // Our own style may have changed which would disqualify us as a layout root
  // (e.g. our containment/writing-mode/formatting-context status/etc changed).
  // Skip subtree layout, and ensure our container chain needs layout.
  if (SelfNeedsFullLayout()) {
    MarkContainerChainForLayout();
    return;
  }

  const auto* previous_result = GetSingleCachedLayoutResult();
  DCHECK(previous_result);
  auto space = previous_result->GetConstraintSpaceForCaching();
  DCHECK_EQ(space.GetWritingMode(), StyleRef().GetWritingMode());
  const LayoutResult* result = BlockNode(this).Layout(space);
  GetDocument().GetFrame()->GetInputMethodController().DidLayoutSubtree(*this);

  if (IsOutOfFlowPositioned()) {
    result->CopyMutableOutOfFlowData(*previous_result);
  }

  // Even if we are a subtree layout root we need to mark our containing-block
  // for layout if:
  //  - Our baselines have shifted.
  //  - We've propagated any layout-objects (which affect our container chain).
  //
  // NOTE: We could weaken the constraints in ObjectIsRelayoutBoundary, and use
  // this technique to detect size-changes, etc if we wanted to expand this
  // optimization.
  const auto& previous_fragment =
      To<PhysicalBoxFragment>(previous_result->GetPhysicalFragment());
  const auto& fragment = To<PhysicalBoxFragment>(result->GetPhysicalFragment());
  if (previous_fragment.FirstBaseline() != fragment.FirstBaseline() ||
      previous_fragment.LastBaseline() != fragment.LastBaseline() ||
      fragment.HasPropagatedLayoutObjects()) {
    if (auto* containing_block = ContainingBlock()) {
      containing_block->SetNeedsLayout(
          layout_invalidation_reason::kChildChanged, kMarkContainerChain);
    }
  }
}

// ClientWidth and ClientHeight represent the interior of an object excluding
// border and scrollbar.
DISABLE_CFI_PERF
LayoutUnit LayoutBox::ClientWidth() const {
  NOT_DESTROYED();
  // We need to clamp negative values. This function may be called during layout
  // before frame_size_ gets the final proper value. Another reason: While
  // border side values are currently limited to 2^20px (a recent change in the
  // code), if this limit is raised again in the future, we'd have ill effects
  // of saturated arithmetic otherwise.
  LayoutUnit width = Size().width;
  if (CanSkipComputeScrollbars()) {
    return (width - BorderLeft() - BorderRight()).ClampNegativeToZero();
  } else {
    return (width - BorderLeft() - BorderRight() -
            ComputeScrollbarsInternal(kClampToContentBox).HorizontalSum())
        .ClampNegativeToZero();
  }
}

DISABLE_CFI_PERF
LayoutUnit LayoutBox::ClientHeight() const {
  NOT_DESTROYED();
  // We need to clamp negative values. This function can be called during layout
  // before frame_size_ gets the final proper value. The scrollbar may be wider
  // than the padding box. Another reason: While border side values are
  // currently limited to 2^20px (a recent change in the code), if this limit is
  // raised again in the future, we'd have ill effects of saturated arithmetic
  // otherwise.
  LayoutUnit height = Size().height;
  if (CanSkipComputeScrollbars()) {
    return (height - BorderTop() - BorderBottom()).ClampNegativeToZero();
  } else {
    return (height - BorderTop() - BorderBottom() -
            ComputeScrollbarsInternal(kClampToContentBox).VerticalSum())
        .ClampNegativeToZero();
  }
}

LayoutUnit LayoutBox::ClientWidthFrom(LayoutUnit width) const {
  NOT_DESTROYED();
  if (CanSkipComputeScrollbars()) {
    return (width - BorderLeft() - BorderRight()).ClampNegativeToZero();
  } else {
    return (width - BorderLeft() - BorderRight() -
            ComputeScrollbarsInternal(kClampToContentBox).HorizontalSum())
        .ClampNegativeToZero();
  }
}

LayoutUnit LayoutBox::ClientHeightFrom(LayoutUnit height) const {
  NOT_DESTROYED();
  if (CanSkipComputeScrollbars()) {
    return (height - BorderTop() - BorderBottom()).ClampNegativeToZero();
  } else {
    return (height - BorderTop() - BorderBottom() -
            ComputeScrollbarsInternal(kClampToContentBox).VerticalSum())
        .ClampNegativeToZero();
  }
}

LayoutUnit LayoutBox::ClientWidthWithTableSpecialBehavior() const {
  NOT_DESTROYED();
  // clientWidth/Height is the visual portion of the box content, not including
  // borders or scroll bars, but includes padding. And per
  // https://www.w3.org/TR/CSS2/tables.html#model,
  // table wrapper box is a principal block box that contains the table box
  // itself and any caption boxes, and table grid box is a block-level box that
  // contains the table's internal table boxes. When table's border is specified
  // in CSS, the border is added to table grid box, not table wrapper box.
  // Currently, Blink doesn't have table wrapper box, and we are supposed to
  // retrieve clientWidth/Height from table wrapper box, not table grid box. So
  // when we retrieve clientWidth/Height, it includes table's border size.
  if (IsTable())
    return ClientWidth() + BorderLeft() + BorderRight();
  return ClientWidth();
}

LayoutUnit LayoutBox::ClientHeightWithTableSpecialBehavior() const {
  NOT_DESTROYED();
  // clientWidth/Height is the visual portion of the box content, not including
  // borders or scroll bars, but includes padding. And per
  // https://www.w3.org/TR/CSS2/tables.html#model,
  // table wrapper box is a principal block box that contains the table box
  // itself and any caption boxes, and table grid box is a block-level box that
  // contains the table's internal table boxes. When table's border is specified
  // in CSS, the border is added to table grid box, not table wrapper box.
  // Currently, Blink doesn't have table wrapper box, and we are supposed to
  // retrieve clientWidth/Height from table wrapper box, not table grid box. So
  // when we retrieve clientWidth/Height, it includes table's border size.
  if (IsTable())
    return ClientHeight() + BorderTop() + BorderBottom();
  return ClientHeight();
}

bool LayoutBox::UsesOverlayScrollbars() const {
  NOT_DESTROYED();
  if (StyleRef().HasCustomScrollbarStyle(DynamicTo<Element>(GetNode()))) {
    return false;
  }
  if (GetFrame()->GetPage()->GetScrollbarTheme().UsesOverlayScrollbars())
    return true;
  return false;
}

LayoutUnit LayoutBox::ScrollWidth() const {
  NOT_DESTROYED();
  if (IsScrollContainer())
    return GetScrollableArea()->ScrollWidth();
  if (StyleRef().IsScrollbarGutterStable() &&
      StyleRef().OverflowBlockDirection() == EOverflow::kHidden) {
    if (auto* scrollable_area = GetScrollableArea())
      return scrollable_area->ScrollWidth();
    else
      return ScrollableOverflowRect().Width();
  }
  // For objects with scrollable overflow, this matches IE.
  PhysicalRect overflow_rect = ScrollableOverflowRect();
  if (!StyleRef().GetWritingDirection().IsFlippedX()) {
    return std::max(ClientWidth(), overflow_rect.Right() - BorderLeft());
  }
  return ClientWidth() -
         std::min(LayoutUnit(), overflow_rect.X() - BorderLeft());
}

LayoutUnit LayoutBox::ScrollHeight() const {
  NOT_DESTROYED();
  if (IsScrollContainer())
    return GetScrollableArea()->ScrollHeight();
  if (StyleRef().IsScrollbarGutterStable() &&
      StyleRef().OverflowBlockDirection() == EOverflow::kHidden) {
    if (auto* scrollable_area = GetScrollableArea())
      return scrollable_area->ScrollHeight();
    else
      return ScrollableOverflowRect().Height();
  }
  // For objects with visible overflow, this matches IE.
  // FIXME: Need to work right with writing modes.
  return std::max(ClientHeight(),
                  ScrollableOverflowRect().Bottom() - BorderTop());
}

PhysicalBoxStrut LayoutBox::MarginBoxOutsets() const {
  NOT_DESTROYED();
  if (PhysicalFragmentCount()) {
    // We get margin data from the first physical fragment. Margins are
    // per-LayoutBox data, and we don't need to take care of block
    // fragmentation.
    return GetPhysicalFragment(0)->Margins();
  }
  return PhysicalBoxStrut();
}

void LayoutBox::QuadsInAncestorInternal(Vector<gfx::QuadF>& quads,
                                        const LayoutBoxModelObject* ancestor,
                                        MapCoordinatesFlags mode) const {
  NOT_DESTROYED();
  if (LayoutFlowThread* flow_thread = FlowThreadContainingBlock()) {
    flow_thread->QuadsInAncestorForDescendant(*this, quads, ancestor, mode);
    return;
  }
  quads.push_back(
      LocalRectToAncestorQuad(PhysicalBorderBoxRect(), ancestor, mode));
}

gfx::RectF LayoutBox::LocalBoundingBoxRectForAccessibility() const {
  NOT_DESTROYED();
  PhysicalSize size = Size();
  return gfx::RectF(0, 0, size.width.ToFloat(), size.height.ToFloat());
}

void LayoutBox::UpdateAfterLayout() {
  NOT_DESTROYED();
  // Transform-origin depends on box size, so we need to update the layer
  // transform after layout.
  if (HasLayer()) {
    Layer()->UpdateTransform();
    Layer()->UpdateScrollingAfterLayout();
  }

  GetFrame()->GetInputMethodController().DidUpdateLayout(*this);
  if (IsPositioned())
    GetFrame()->GetInputMethodController().DidLayoutSubtree(*this);
}

LayoutUnit LayoutBox::OverrideIntrinsicContentInlineSize() const {
  NOT_DESTROYED();

  // We only override a size contained dimension.
  if (!ShouldApplyInlineSizeContainment()) {
    return kIndefiniteSize;
  }

  const auto& style = StyleRef();
  const StyleIntrinsicLength& intrinsic_length =
      style.ContainIntrinsicInlineSize();

  if (intrinsic_length.HasAuto()) {
    const auto* context = GetDisplayLockContext();
    if (context && context->IsLocked()) {
      if (const auto* elem = DynamicTo<Element>(GetNode())) {
        if (const auto inline_size = elem->LastRememberedInlineSize()) {
          // ResizeObserverSize is adjusted to be in CSS space, we need to
          // adjust it back to Layout space by applying the effective zoom.
          return LayoutUnit::FromFloatRound(*inline_size *
                                            style.EffectiveZoom());
        }
      }
    }
  }

  if (const auto& length = intrinsic_length.GetLength()) {
    DCHECK(length->IsFixed());
    return LayoutUnit(length->Value());
  }

  return kIndefiniteSize;
}

LayoutUnit LayoutBox::OverrideIntrinsicContentBlockSize() const {
  NOT_DESTROYED();

  // We only override a size contained dimension.
  if (!ShouldApplyBlockSizeContainment()) {
    return kIndefiniteSize;
  }

  const auto& style = StyleRef();
  const StyleIntrinsicLength& intrinsic_length =
      style.ContainIntrinsicBlockSize();

  if (intrinsic_length.HasAuto()) {
    const auto* context = GetDisplayLockContext();
    if (context && context->IsLocked()) {
      if (const auto* elem = DynamicTo<Element>(GetNode())) {
        if (const auto inline_size = elem->LastRememberedBlockSize()) {
          // ResizeObserverSize is adjusted to be in CSS space, we need to
          // adjust it back to Layout space by applying the effective zoom.
          return LayoutUnit::FromFloatRound(*inline_size *
                                            style.EffectiveZoom());
        }
      }
    }
  }

  if (const auto& length = intrinsic_length.GetLength()) {
    DCHECK(length->IsFixed());
    return LayoutUnit(length->Value());
  }

  return kIndefiniteSize;
}

LayoutUnit LayoutBox::DefaultIntrinsicContentInlineSize() const {
  NOT_DESTROYED();

  if (!IsA<Element>(GetNode()))
    return kIndefiniteSize;
  const Element& element = *To<Element>(GetNode());

  const bool apply_fixed_size = StyleRef().ApplyControlFixedSize(&element);
  const auto* select = DynamicTo<HTMLSelectElement>(element);
  if (select && select->UsesMenuList() && !select->IsAppearanceBaseButton())
      [[unlikely]] {
    return apply_fixed_size ? MenuListIntrinsicInlineSize(*select, *this)
                            : kIndefiniteSize;
  }
  const auto* input = DynamicTo<HTMLInputElement>(element);
  if (input) [[unlikely]] {
    if (input->IsTextField() && apply_fixed_size) {
      return TextFieldIntrinsicInlineSize(*input, *this);
    }
    FormControlType type = input->FormControlType();
    if (type == FormControlType::kInputFile && apply_fixed_size) {
      return FileUploadControlIntrinsicInlineSize(*input, *this);
    }
    if (type == FormControlType::kInputRange) {
      return SliderIntrinsicInlineSize(*this);
    }
    auto effective_appearance = StyleRef().EffectiveAppearance();
    if (effective_appearance == kCheckboxPart) {
      return ThemePartIntrinsicSize(*this, WebThemeEngine::kPartCheckbox)
          .inline_size;
    }
    if (effective_appearance == kRadioPart) {
      return ThemePartIntrinsicSize(*this, WebThemeEngine::kPartRadio)
          .inline_size;
    }
    return kIndefiniteSize;
  }
  const auto* textarea = DynamicTo<HTMLTextAreaElement>(element);
  if (textarea && apply_fixed_size) [[unlikely]] {
    return TextAreaIntrinsicInlineSize(*textarea, *this);
  }
  if (IsSliderContainer(element))
    return SliderIntrinsicInlineSize(*this);

  return kIndefiniteSize;
}

LayoutUnit LayoutBox::DefaultIntrinsicContentBlockSize() const {
  NOT_DESTROYED();

  auto effective_appearance = StyleRef().EffectiveAppearance();
  if (effective_appearance == kCheckboxPart) {
    return ThemePartIntrinsicSize(*this, WebThemeEngine::kPartCheckbox)
        .block_size;
  }
  if (effective_appearance == kRadioPart) {
    return ThemePartIntrinsicSize(*this, WebThemeEngine::kPartRadio).block_size;
  }

  if (!StyleRef().ApplyControlFixedSize(GetNode())) {
    return kIndefiniteSize;
  }
  if (const auto* select = DynamicTo<HTMLSelectElement>(GetNode())) {
    if (!select->IsAppearanceBaseButton()) {
      if (select->UsesMenuList()) {
        return MenuListIntrinsicBlockSize(*select, *this);
      }
      return ListBoxItemBlockSize(*select, *this) * select->ListBoxSize() -
             ComputeLogicalScrollbars().BlockSum();
    }
  }
  if (IsTextField()) {
    return TextFieldIntrinsicBlockSize(*To<HTMLInputElement>(GetNode()), *this);
  }
  if (IsTextArea()) {
    return TextAreaIntrinsicBlockSize(*To<HTMLTextAreaElement>(GetNode()),
                                      *this);
  }

  return kIndefiniteSize;
}

LayoutUnit LayoutBox::LogicalLeft() const {
  NOT_DESTROYED();
  auto [offset, container_writing_mode] = LogicalLocation(*this);
  return IsParallelWritingMode(container_writing_mode,
                               StyleRef().GetWritingMode())
             ? offset.inline_offset
             : offset.block_offset;
}

LayoutUnit LayoutBox::LogicalTop() const {
  NOT_DESTROYED();
  auto [offset, container_writing_mode] = LogicalLocation(*this);
  return IsParallelWritingMode(container_writing_mode,
                               StyleRef().GetWritingMode())
             ? offset.block_offset
             : offset.inline_offset;
}

gfx::QuadF LayoutBox::AbsoluteContentQuad(MapCoordinatesFlags flags) const {
  NOT_DESTROYED();
  PhysicalRect rect = PhysicalContentBoxRect();
  return LocalRectToAbsoluteQuad(rect, flags);
}

PhysicalRect LayoutBox::PhysicalBackgroundRect(
    BackgroundRectType rect_type) const {
  NOT_DESTROYED();
  // If the background transfers to view, the used background of this object
  // is transparent.
  if (rect_type == kBackgroundKnownOpaqueRect && BackgroundTransfersToView())
    return PhysicalRect();

  std::optional<EFillBox> background_box;
  Color background_color = ResolveColor(GetCSSPropertyBackgroundColor());
  // Find the largest background rect of the given opaqueness.
  for (const FillLayer* cur = &(StyleRef().BackgroundLayers()); cur;
       cur = cur->Next()) {
    EFillBox current_clip = cur->Clip();
    if (rect_type == kBackgroundKnownOpaqueRect) {
      if (current_clip == EFillBox::kText)
        continue;

      if (cur->GetBlendMode() != BlendMode::kNormal ||
          cur->Composite() != kCompositeSourceOver)
        continue;

      bool layer_known_opaque = false;
      // Check if the image is opaque and fills the clip.
      if (const StyleImage* image = cur->GetImage()) {
        if ((cur->Repeat().x == EFillRepeat::kRepeatFill ||
             cur->Repeat().x == EFillRepeat::kRoundFill) &&
            (cur->Repeat().y == EFillRepeat::kRepeatFill ||
             cur->Repeat().y == EFillRepeat::kRoundFill) &&
            image->KnownToBeOpaque(GetDocument(), StyleRef())) {
          layer_known_opaque = true;
        }
      }

      // The background color is painted into the last layer.
      if (!cur->Next() && background_color.IsOpaque()) {
        layer_known_opaque = true;
      }

      // If neither the image nor the color are opaque then skip this layer.
      if (!layer_known_opaque)
        continue;
    } else {
      // Ignore invisible background layers for kBackgroundPaintedExtent.
      DCHECK_EQ(rect_type, kBackgroundPaintedExtent);
      if (!cur->GetImage() &&
          (cur->Next() || background_color.IsFullyTransparent())) {
        continue;
      }
      // A content-box clipped fill layer can be scrolled into the padding box
      // of the overflow container.
      if (current_clip == EFillBox::kContent &&
          cur->Attachment() == EFillAttachment::kLocal) {
        current_clip = EFillBox::kPadding;
      }
    }

    // Restrict clip if attachment is local.
    if (current_clip == EFillBox::kBorder &&
        cur->Attachment() == EFillAttachment::kLocal)
      current_clip = EFillBox::kPadding;

    background_box = background_box
                         ? EnclosingFillBox(*background_box, current_clip)
                         : current_clip;
  }

  if (!background_box)
    return PhysicalRect();

  if (*background_box == EFillBox::kText) {
    DCHECK_NE(rect_type, kBackgroundKnownOpaqueRect);
    *background_box = EFillBox::kBorder;
  }

  if (rect_type == kBackgroundPaintedExtent &&
      *background_box == EFillBox::kBorder &&
      BackgroundClipBorderBoxIsEquivalentToPaddingBox()) {
    *background_box = EFillBox::kPadding;
  }

  switch (*background_box) {
    case EFillBox::kBorder:
      return PhysicalBorderBoxRect();
    case EFillBox::kPadding:
      return PhysicalPaddingBoxRect();
    case EFillBox::kContent:
      return PhysicalContentBoxRect();
    default:
      NOTREACHED();
  }
}

void LayoutBox::AddOutlineRects(OutlineRectCollector& collector,
                                OutlineInfo* info,
                                const PhysicalOffset& additional_offset,
                                OutlineType) const {
  NOT_DESTROYED();
  collector.AddRect(PhysicalRect(additional_offset, Size()));
  if (info)
    *info = OutlineInfo::GetFromStyle(StyleRef());
}

bool LayoutBox::CanResize() const {
  NOT_DESTROYED();
  // We need a special case for <iframe> because they never have
  // hasOverflowClip(). However, they do "implicitly" clip their contents, so
  // we want to allow resizing them also.
  return (IsScrollContainer() || IsLayoutIFrame()) && StyleRef().HasResize();
}

bool LayoutBox::HasScrollbarGutters(ScrollbarOrientation orientation) const {
  NOT_DESTROYED();
  if (StyleRef().IsScrollbarGutterAuto())
    return false;

  DCHECK(StyleRef().IsScrollbarGutterStable());

  // Scrollbar-gutter propagates to the viewport
  // (see:|StyleResolver::PropagateStyleToViewport|).
  if (orientation == kVerticalScrollbar) {
    EOverflow overflow = StyleRef().OverflowY();
    return StyleRef().IsHorizontalWritingMode() &&
           (overflow == EOverflow::kAuto || overflow == EOverflow::kScroll ||
            overflow == EOverflow::kHidden) &&
           !UsesOverlayScrollbars() &&
           GetNode() != GetDocument().ViewportDefiningElement();
  } else {
    EOverflow overflow = StyleRef().OverflowX();
    return !StyleRef().IsHorizontalWritingMode() &&
           (overflow == EOverflow::kAuto || overflow == EOverflow::kScroll ||
            overflow == EOverflow::kHidden) &&
           !UsesOverlayScrollbars() &&
           GetNode() != GetDocument().ViewportDefiningElement();
  }
}

PhysicalBoxStrut LayoutBox::ComputeScrollbarsInternal(
    ShouldClampToContentBox clamp_to_content_box,
    OverlayScrollbarClipBehavior overlay_scrollbar_clip_behavior,
    ShouldIncludeScrollbarGutter include_scrollbar_gutter) const {
  NOT_DESTROYED();
  PhysicalBoxStrut scrollbars;
  PaintLayerScrollableArea* scrollable_area = GetScrollableArea();

  if (include_scrollbar_gutter == kIncludeScrollbarGutter &&
      HasScrollbarGutters(kVerticalScrollbar)) {
    LayoutUnit gutter_size = LayoutUnit(HypotheticalScrollbarThickness(
        *this, kVerticalScrollbar, /* include_overlay_thickness */ true));
    if (ShouldPlaceVerticalScrollbarOnLeft()) {
      scrollbars.left = gutter_size;
      if (StyleRef().IsScrollbarGutterBothEdges())
        scrollbars.right = gutter_size;
    } else {
      scrollbars.right = gutter_size;
      if (StyleRef().IsScrollbarGutterBothEdges())
        scrollbars.left = gutter_size;
    }
  } else if (scrollable_area) {
    if (ShouldPlaceVerticalScrollbarOnLeft()) {
      scrollbars.left = LayoutUnit(scrollable_area->VerticalScrollbarWidth(
          overlay_scrollbar_clip_behavior));
    } else {
      scrollbars.right = LayoutUnit(scrollable_area->VerticalScrollbarWidth(
          overlay_scrollbar_clip_behavior));
    }
  }

  if (include_scrollbar_gutter == kIncludeScrollbarGutter &&
      HasScrollbarGutters(kHorizontalScrollbar)) {
    LayoutUnit gutter_size = LayoutUnit(
        HypotheticalScrollbarThickness(*this, kHorizontalScrollbar,
                                       /* include_overlay_thickness */ true));
    scrollbars.bottom = gutter_size;
    if (StyleRef().IsScrollbarGutterBothEdges())
      scrollbars.top = gutter_size;
  } else if (scrollable_area) {
    scrollbars.bottom = LayoutUnit(scrollable_area->HorizontalScrollbarHeight(
        overlay_scrollbar_clip_behavior));
  }

  // Use the width of the vertical scrollbar, unless it's larger than the
  // logical width of the content box, in which case we'll use that instead.
  // Scrollbar handling is quite bad in such situations, and this code here
  // is just to make sure that left-hand scrollbars don't mess up
  // scrollWidth. For the full story, visit http://crbug.com/724255.
  if (scrollbars.left > 0 && clamp_to_content_box == kClampToContentBox) {
    LayoutUnit max_width = Size().width - BorderAndPaddingWidth();
    scrollbars.left =
        std::min(scrollbars.left, max_width.ClampNegativeToZero());
  }

  return scrollbars;
}

void LayoutBox::Autoscroll(const PhysicalOffset& position_in_root_frame) {
  NOT_DESTROYED();
  LocalFrame* frame = GetFrame();
  if (!frame)
    return;

  LocalFrameView* frame_view = frame->View();
  if (!frame_view)
    return;

  PhysicalOffset absolute_position =
      frame_view->ConvertFromRootFrame(position_in_root_frame);
  mojom::blink::ScrollIntoViewParamsPtr params =
      scroll_into_view_util::CreateScrollIntoViewParams(
          ScrollAlignment::ToEdgeIfNeeded(), ScrollAlignment::ToEdgeIfNeeded(),
          mojom::blink::ScrollType::kUser);
  scroll_into_view_util::ScrollRectToVisible(
      *this,
      PhysicalRect(absolute_position,
                   PhysicalSize(LayoutUnit(1), LayoutUnit(1))),
      std::move(params));
}

// If specified point is outside the border-belt-excluded box (the border box
// inset by the autoscroll activation threshold), returned offset denotes
// direction of scrolling.
PhysicalOffset LayoutBox::CalculateAutoscrollDirection(
    const gfx::PointF& point_in_root_frame) const {
  NOT_DESTROYED();
  if (!GetFrame())
    return PhysicalOffset();

  LocalFrameView* frame_view = GetFrame()->View();
  if (!frame_view)
    return PhysicalOffset();

  PhysicalRect absolute_scrolling_box(AbsoluteBoundingBoxRect());

  // Exclude scrollbars so the border belt (activation area) starts from the
  // scrollbar-content edge rather than the window edge.
  ExcludeScrollbars(absolute_scrolling_box,
                    kExcludeOverlayScrollbarSizeForHitTesting);

  PhysicalRect belt_box =
      View()->GetFrameView()->ConvertToRootFrame(absolute_scrolling_box);
  belt_box.Inflate(LayoutUnit(-kAutoscrollBeltSize));
  gfx::PointF point = point_in_root_frame;

  if (point.x() < belt_box.X())
    point.Offset(-kAutoscrollBeltSize, 0);
  else if (point.x() > belt_box.Right())
    point.Offset(kAutoscrollBeltSize, 0);

  if (point.y() < belt_box.Y())
    point.Offset(0, -kAutoscrollBeltSize);
  else if (point.y() > belt_box.Bottom())
    point.Offset(0, kAutoscrollBeltSize);

  return PhysicalOffset::FromVector2dFRound(point - point_in_root_frame);
}

LayoutBox* LayoutBox::FindAutoscrollable(LayoutObject* layout_object,
                                         bool is_middle_click_autoscroll) {
  while (layout_object && !(layout_object->IsBox() &&
                            To<LayoutBox>(layout_object)->IsUserScrollable())) {
    // Do not start selection-based autoscroll when the node is inside a
    // fixed-position element.
    if (!is_middle_click_autoscroll && layout_object->IsBox() &&
        To<LayoutBox>(layout_object)->IsFixedToView()) {
      return nullptr;
    }

    if (!layout_object->Parent() &&
        layout_object->GetNode() == layout_object->GetDocument() &&
        layout_object->GetDocument().LocalOwner()) {
      layout_object =
          layout_object->GetDocument().LocalOwner()->GetLayoutObject();
    } else {
      layout_object = layout_object->Parent();
    }
  }

  return DynamicTo<LayoutBox>(layout_object);
}

bool LayoutBox::HasHorizontallyScrollableAncestor(LayoutObject* layout_object) {
  while (layout_object) {
    if (layout_object->IsBox() &&
        To<LayoutBox>(layout_object)->HasScrollableOverflowX())
      return true;

    // Scroll is not propagating.
    if (layout_object->StyleRef().OverscrollBehaviorX() !=
        EOverscrollBehavior::kAuto)
      break;

    if (!layout_object->Parent() &&
        layout_object->GetNode() == layout_object->GetDocument() &&
        layout_object->GetDocument().LocalOwner()) {
      layout_object =
          layout_object->GetDocument().LocalOwner()->GetLayoutObject();
    } else {
      layout_object = layout_object->Parent();
    }
  }

  return false;
}

gfx::Vector2d LayoutBox::OriginAdjustmentForScrollbars() const {
  NOT_DESTROYED();
  if (CanSkipComputeScrollbars())
    return gfx::Vector2d();

  PhysicalBoxStrut scrollbars = ComputeScrollbarsInternal(kClampToContentBox);
  return gfx::Vector2d(scrollbars.left.ToInt(), scrollbars.top.ToInt());
}

gfx::Point LayoutBox::ScrollOrigin() const {
  NOT_DESTROYED();
  return GetScrollableArea() ? GetScrollableArea()->ScrollOrigin()
                             : gfx::Point();
}

PhysicalOffset LayoutBox::ScrolledContentOffset() const {
  NOT_DESTROYED();
  DCHECK(IsScrollContainer());
  DCHECK(GetScrollableArea());
  return PhysicalOffset::FromVector2dFFloor(
      GetScrollableArea()->GetScrollOffset());
}

gfx::Vector2d LayoutBox::PixelSnappedScrolledContentOffset() const {
  NOT_DESTROYED();
  DCHECK(IsScrollContainer());
  DCHECK(GetScrollableArea());
  return GetScrollableArea()->ScrollOffsetInt();
}

PhysicalRect LayoutBox::ClippingRect(const PhysicalOff
```