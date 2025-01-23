Response:
The user wants a summary of the `LayoutObject.cc` file in the Chromium Blink engine. I need to identify the key functionalities implemented in the provided code snippet. The code deals with:

1. **Finding the offset parent:**  The `offsetParent()` method determines the containing element for absolutely positioned elements.
2. **Image removal notification:** The `NotifyImageFullyRemoved()` method informs other parts of the engine when an image is fully removed.
3. **Creating text positions:** Several methods like `CreatePositionWithAffinity()`, `FindPosition()`, `FirstPositionInOrBeforeThis()`, `LastPositionInOrAfterThis()`, `PositionAfterThis()`, and `PositionBeforeThis()` are involved in creating and locating text positions within the layout tree.
4. **Cursor management:** The `GetCursor()` method determines the appropriate cursor to display.
5. **Selection update:** The `CanUpdateSelectionOnRootLineBoxes()` method checks if the selection can be updated.
6. **SVG layout:**  Placeholders for SVG layout methods like `UpdateSVGLayout()`, `ObjectBoundingBox()`, `StrokeBoundingBox()`, `DecoratedBoundingBox()`, `VisualRectInLocalSVGCoordinates()`, and `LocalSVGTransform()`.
7. **Relayout boundary:** The `IsRelayoutBoundary()` method checks if the object is a boundary for relayout.
8. **Paint invalidation:** A significant portion of the code deals with various aspects of paint invalidation, including setting flags for invalidation, reasons for invalidation, and clearing invalidation flags. This includes methods like `SetShouldInvalidateSelection()`, `SetShouldDoFullPaintInvalidation()`, `SetShouldCheckForPaintInvalidation()`, `ClearPaintInvalidationFlags()`, and related helper functions.
9. **Paint flags:** Methods like `ClearPaintFlags()` manage paint-related flags.
10. **Layout tree modification:** The `IsAllowedToModifyLayoutTreeStructure()` method checks if layout tree modifications are permitted.
11. **Fixed background attachment:** Methods like `SetIsBackgroundAttachmentFixedObject()` and `SetCanCompositeBackgroundAttachmentFixed()` handle elements with fixed background attachments.
12. **Debugging:** The `DebugRect()` method is likely for debugging purposes.
13. **Invalidating selected children:** The `InvalidateSelectedChildrenOnStyleChange()` method handles invalidation when the style of selected children changes.
14. **Effective allowed touch action:** Methods like `MarkEffectiveAllowedTouchActionChanged()` and `MarkDescendantEffectiveAllowedTouchActionChanged()` track changes related to allowed touch actions.
15. **Blocking wheel event handlers:** Methods like `MarkBlockingWheelEventHandlerChanged()` and `MarkDescendantBlockingWheelEventHandlerChanged()` track changes related to blocking wheel event handlers.
16. **Finding associated layout objects:** The `AssociatedLayoutObjectOf()` function helps find the layout object associated with a specific node and offset.
17. **Selection leaf determination:** The `CanBeSelectionLeaf()` method checks if an object can be a leaf in the selection.
18. **Collecting outline rectangles:** Methods like `CollectOutlineRectsAndAdvance()` and `OutlineRects()` are used for collecting the rectangles that form an element's outline.
19. **Setting modified style:** The `SetModifiedStyleOutsideStyleRecalc()` method sets the style of an object outside the normal style recalculation process.
20. **Writing mode flipping:** The `FlipForWritingModeInternal()` method adjusts positions based on the writing mode.
21. **Self-painting layer visual overflow:** Methods like `SelfPaintingLayerNeedsVisualOverflowRecalc()` and `MarkSelfPaintingLayerForVisualOverflowRecalc()` manage visual overflow for self-painting layers.
22. **SVG animation and viewport dependencies:** Methods like `SetSVGDescendantMayHaveTransformRelatedAnimation()` and `SetSVGSelfOrDescendantHasViewportDependency()` track SVG-specific properties.
23. **Invalidating subtree position try:** The `InvalidateSubtreePositionTry()` method handles invalidation related to the `@position-fallback` CSS feature.
24. **Debugging output:** The `ShowTree()` and `ShowLayoutTree()` functions are used for printing the layout tree for debugging.

Now, I will organize these functionalities and provide examples where they relate to JavaScript, HTML, and CSS. I'll also consider common errors and provide relevant input/output scenarios where applicable.
```cpp
// Copyright 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/layout_object.h"

#include "build/build_config.h"
#include "third_party/blink/renderer/build/generated/v8_initializer.h"
#include "third_party/blink/renderer/core/accessibility/ax_node_object.h"
#include "third_party/blink/renderer/core/animation/css_animations.h"
#include "third_party/blink/renderer/core/animation/css_transitions.h"
#include "third_party/blink/renderer/core/css/computed_style.h"
#include "third_party/blink/renderer/core/css/css_custom_property_data.h"
#include "third_party/blink/renderer/core/css/css_property_in_style.h"
#include "third_party/blink/renderer/core/css/css_variable_reference_data.h"
#include "third_party/blink/renderer/core/css/style_change_reason.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/dom/character_data.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/node_computed_style.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/editing/ephemeral/position_with_affinity.h"
#include "third_party/blink/renderer/core/editing/selection/layout_selection.h"
#include "third_party/blink/renderer/core/frame/frame_view.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/geometry/affine_transform.h"
#include "third_party/blink/renderer/core/geometry/layout_point.h"
#include "third_party/blink/renderer/core/geometry/physical_rect.h"
#include "third_party/blink/renderer/core/geometry/transform_state.h"
#include "third_party/blink/renderer/core/html/html_body_element.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/html/html_table_cell_element.h"
#include "third_party/blink/renderer/core/html/html_table_element.h"
#include "third_party/blink/renderer/core/layout/layout_block.h"
#include "third_party/blink/renderer/core/layout/layout_box.h"
#include "third_party/blink/renderer/core/layout/layout_box_model_object.h"
#include "third_party/blink/renderer/core/layout/layout_embedded_content.h"
#include "third_party/blink/renderer/core/layout/layout_inline.h"
#include "third_party/blink/renderer/core/layout/layout_svg_resource.h"
#include "third_party/blink/renderer/core/layout/layout_text.h"
#include "third_party/blink/renderer/core/layout/layout_text_fragment.h"
#include "third_party/blink/renderer/core/layout/outline_info.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_container.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_root.h"
#include "third_party/blink/renderer/core/layout/svg/svg_layout_support.h"
#include "third_party/blink/renderer/core/paint/box_painter.h"
#include "third_party/blink/renderer/core/paint/compositing/composited_layer_mapping.h"
#include "third_party/blink/renderer/core/paint/embedded_content_embedded_node_painting_data.h"
#include "third_party/blink/renderer/core/paint/image_element_timing.h"
#include "third_party/blink/renderer/core/paint/local_paint_timing.h"
#include "third_party/blink/renderer/core/paint/paint_info.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/paint/svg_painter.h"
#include "third_party/blink/renderer/core/paint/text_painter.h"
#include "third_party/blink/renderer/core/paint/viewport_painter.h"
#include "third_party/blink/renderer/core/style/computed_style_constants.h"
#include "third_party/blink/renderer/core/style/container_query_features.h"
#include "third_party/blink/renderer/core/style/scroll_timeline.h"
#include "third_party/blink/renderer/core/style/stylable_element.h"
#include "third_party/blink/renderer/platform/geometry/float_rect.h"
#include "third_party/blink/renderer/platform/graphics/graphics_context.h"
#include "third_party/blink/renderer/platform/instrumentation/instrumentation.h"
#include "third_party/blink/renderer/platform/layout/layout_theme.h"
#include "third_party/blink/renderer/platform/logging/logging.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/scroll/scroll_types.h"
#include "third_party/blink/renderer/platform/text/text_affinities.h"
#include "third_party/blink/renderer/platform/text/text_ курсор.h"
#include "third_party/blink/renderer/platform/wtf/hash_set.h"
#include "third_party/blink/renderer/platform/wtf/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink {

// This value is only used in an ASSERT.
static int layout_object_counter = 0;

LayoutObject::LayoutObject(Node* node)
    : ContextLifecycleObserver(node ? &node->GetDocument() : nullptr),
      bitfields_(0),
      node_(node),
      paint_invalidation_reason_for_pre_paint_(
          static_cast<unsigned>(PaintInvalidationReason::kNone)) {
  ASSERT(++layout_object_counter >= 0);
  if (node_)
    node_->SetLayoutObject(this);
}

LayoutObject::~LayoutObject() {
  ASSERT(--layout_object_counter >= 0);
  // The node might be gone already in the case of a Document.
  if (node_) {
    ASSERT(node_->GetLayoutObject() == this);
    node_->SetLayoutObject(nullptr);
  }
}

Element* LayoutObject::offsetParent(const LayoutPoint&,
                                   const HashSet<const TreeScope>* ancestor_tree_scopes,
                                   Element* base) const {
  // https://drafts.csswg.org/cssom-view/#offset-parent
  // An element's offsetParent is:
  // 1. If the element has 'position: fixed', null.
  if (IsFixedPositioned())
    return nullptr;

  // 2. If the element is the root element, null.
  if (IsDocumentElement())
    return nullptr;

  // 3. If the element is the body element and the 'position' of the html
  //    element is 'static' or 'relative', null.
  if (IsBody() && (DocumentElement()->StyleRef().IsStaticPositioned() ||
                   DocumentElement()->IsRelativelyPositioned()))
    return nullptr;

  // 4. Otherwise, the nearest ancestor of the element that satisfies one of the
  //    following conditions:
  //    1. has a 'transform' property whose value is not 'none'
  //    2. has a 'perspective' property whose value is not 'none'
  //    3. has a 'filter' property whose value is not 'none'
  //    4. has a 'backdrop-filter' property whose value is not 'none'
  //    5. has a 'isolation' property whose value is 'isolate'
  //    6. has a 'will-change' property whose value contains 'transform'
  //    7. has a '-webkit-overflow-scrolling' property whose value is 'touch'
  //    8. is the viewport
  //
  //    A condition is satisfied if the ancestor is such an element itself or
  //    is the body element.

  const auto& effective_zoom = GetFrameView()->EffectiveZoom();
  Zoom();
  Node* node = nullptr;
  for (LayoutObject* ancestor = Parent(); ancestor;
       ancestor = ancestor->Parent()) {
    // Spec: http://www.w3.org/TR/cssom-view/#offset-attributes

    node = ancestor->GetNode();

    if (!node)
      continue;

    // If |base| was provided, then we should not return an Element which is
    // closed shadow hidden from |base|. If we keep going up the flat tree, then
    // we will eventually get to a node which is not closed shadow hidden from
    // |base|. https://github.com/w3c/csswg-drafts/issues/159
    if (base && !ancestor_tree_scopes.Contains(&node->GetTreeScope())) {
      // If 'position: fixed' node is found while traversing up, terminate the
      // loop and return null.
      if (ancestor->IsFixedPositioned())
        return nullptr;
      continue;
    }

    if (ancestor->CanContainAbsolutePositionObjects())
      break;

    if (IsA<HTMLBodyElement>(*node))
      break;

    if (!IsPositioned() &&
        (IsA<HTMLTableElement>(*node) || IsA<HTMLTableCellElement>(*node)))
      break;

    // Webkit specific extension where offsetParent stops at zoom level changes.
    if (effective_zoom != ancestor->StyleRef().EffectiveZoom())
      break;
  }

  return DynamicTo<Element>(node);
}

void LayoutObject::NotifyImageFullyRemoved(ImageResourceContent* image) {
  NOT_DESTROYED();
  if (LocalDOMWindow* window = GetDocument().domWindow())
    ImageElementTiming::From(*window).NotifyImageRemoved(this, image);
  if (LocalFrameView* frame_view = GetFrameView())
    frame_view->GetPaintTimingDetector().NotifyImageRemoved(*this, image);
}

PositionWithAffinity LayoutObject::CreatePositionWithAffinity(
    int offset,
    TextAffinity affinity) const {
  NOT_DESTROYED();
  // If this is a non-anonymous layoutObject in an editable area, then it's
  // simple.
  Node* const node = NonPseudoNode();
  if (!node)
    return FindPosition();
  return AdjustForEditingBoundary(
      PositionWithAffinity(Position(node, offset), affinity));
}

PositionWithAffinity LayoutObject::FindPosition() const {
  NOT_DESTROYED();
  // We don't want to cross the boundary between editable and non-editable
  // regions of the document, but that is either impossible or at least
  // extremely unlikely in any normal case because we stop as soon as we
  // find a single non-anonymous layoutObject.

  // Find a nearby non-anonymous layoutObject.
  const LayoutObject* child = this;
  while (const LayoutObject* parent = child->Parent()) {
    // Find non-anonymous content after.
    for (const LayoutObject* layout_object = child->NextInPreOrder(parent);
         layout_object; layout_object = layout_object->NextInPreOrder(parent)) {
      if (const Node* node = layout_object->NonPseudoNode()) {
        return PositionWithAffinity(FirstPositionInOrBeforeNode(*node));
      }
    }

    // Find non-anonymous content before.
    for (const LayoutObject* layout_object = child->PreviousInPreOrder();
         layout_object; layout_object = layout_object->PreviousInPreOrder()) {
      if (layout_object == parent)
        break;
      if (const Node* node = layout_object->NonPseudoNode())
        return PositionWithAffinity(LastPositionInOrAfterNode(*node));
    }

    // Use the parent itself unless it too is anonymous.
    if (const Node* node = parent->NonPseudoNode())
      return PositionWithAffinity(FirstPositionInOrBeforeNode(*node));

    // Repeat at the next level up.
    child = parent;
  }

  // Everything was anonymous. Give up.
  return PositionWithAffinity();
}

PositionWithAffinity LayoutObject::FirstPositionInOrBeforeThis() const {
  NOT_DESTROYED();
  if (Node* node = NonPseudoNode())
    return AdjustForEditingBoundary(FirstPositionInOrBeforeNode(*node));
  return FindPosition();
}

PositionWithAffinity LayoutObject::LastPositionInOrAfterThis() const {
  NOT_DESTROYED();
  if (Node* node = NonPseudoNode())
    return AdjustForEditingBoundary(LastPositionInOrAfterNode(*node));
  return FindPosition();
}

PositionWithAffinity LayoutObject::PositionAfterThis() const {
  NOT_DESTROYED();
  if (Node* node = NonPseudoNode())
    return AdjustForEditingBoundary(Position::AfterNode(*node));
  return FindPosition();
}

PositionWithAffinity LayoutObject::PositionBeforeThis() const {
  NOT_DESTROYED();
  if (Node* node = NonPseudoNode())
    return AdjustForEditingBoundary(Position::BeforeNode(*node));
  return FindPosition();
}

PositionWithAffinity LayoutObject::CreatePositionWithAffinity(
    int offset) const {
  NOT_DESTROYED();
  return CreatePositionWithAffinity(offset, TextAffinity::kDownstream);
}

CursorDirective LayoutObject::GetCursor(const PhysicalOffset&,
                                        ui::Cursor&) const {
  NOT_DESTROYED();
  return kSetCursorBasedOnStyle;
}

bool LayoutObject::CanUpdateSelectionOnRootLineBoxes() const {
  NOT_DESTROYED();
  if (NeedsLayout())
    return false;

  const LayoutBlock* containing_block = ContainingBlock();
  return containing_block ? !containing_block->NeedsLayout() : false;
}

SVGLayoutResult LayoutObject::UpdateSVGLayout(const SVGLayoutInfo&) {
  NOT_DESTROYED();
  NOTREACHED();
}

gfx::RectF LayoutObject::ObjectBoundingBox() const {
  NOT_DESTROYED();
  NOTREACHED();
}

gfx::RectF LayoutObject::StrokeBoundingBox() const {
  NOT_DESTROYED();
  NOTREACHED();
}

gfx::RectF LayoutObject::DecoratedBoundingBox() const {
  NOT_DESTROYED();
  NOTREACHED();
}

gfx::RectF LayoutObject::VisualRectInLocalSVGCoordinates() const {
  NOT_DESTROYED();
  NOTREACHED();
}

AffineTransform LayoutObject::LocalSVGTransform() const {
  NOT_DESTROYED();
  return AffineTransform();
}

bool LayoutObject::IsRelayoutBoundary() const {
  NOT_DESTROYED();
  return ObjectIsRelayoutBoundary(this);
}

void LayoutObject::SetShouldInvalidateSelection() {
  NOT_DESTROYED();
  bitfields_.SetShouldInvalidateSelection(true);
  SetShouldCheckForPaintInvalidation();
  // Invalidate overflow for ::selection styles that contain overflowing
  // effects. Do this only for text objects, at least until
  // crbug.com/1128199 is resolved (see InvalidateVisualOverflow())
  if (IsText()) {
    if (auto* computed_style = GetSelectionStyle()) {
      if (computed_style->HasAppliedTextDecorations() ||
          computed_style->HasVisualOverflowingEffect()) {
        InvalidateVisualOverflow();
      }
    }
  }
}

void LayoutObject::SetShouldDoFullPaintInvalidation(
    PaintInvalidationReason reason) {
  NOT_DESTROYED();
  DCHECK(IsLayoutFullPaintInvalidationReason(reason));
  SetShouldCheckForPaintInvalidation();
  SetShouldDoFullPaintInvalidationWithoutLayoutChangeInternal(reason);
}

void LayoutObject::SetShouldDoFullPaintInvalidationWithoutLayoutChange(
    PaintInvalidationReason reason) {
  NOT_DESTROYED();
  DCHECK(IsNonLayoutFullPaintInvalidationReason(reason));
  // Use SetBackgroundNeedsFullPaintInvalidation() instead. See comment of the
  // function.
  DCHECK_NE(reason, PaintInvalidationReason::kBackground);
  SetShouldDoFullPaintInvalidationWithoutLayoutChangeInternal(reason);
}

void LayoutObject::SetShouldDoFullPaintInvalidationWithoutLayoutChangeInternal(
    PaintInvalidationReason reason) {
  NOT_DESTROYED();
  // Only full invalidation reasons are allowed.
  DCHECK(IsFullPaintInvalidationReason(reason));
  const bool was_delayed = bitfields_.ShouldDelayFullPaintInvalidation();
  bitfields_.SetShouldDelayFullPaintInvalidation(false);
  const bool should_upgrade_reason =
      reason > PaintInvalidationReasonForPrePaint();
  if (was_delayed || should_upgrade_reason) {
    SetShouldCheckForPaintInvalidationWithoutLayoutChange();
  }
  if (should_upgrade_reason) {
    paint_invalidation_reason_for_pre_paint_ = static_cast<unsigned>(reason);
    DCHECK_EQ(reason, PaintInvalidationReasonForPrePaint());
  }
}

void LayoutObject::SetShouldInvalidatePaintForHitTest() {
  NOT_DESTROYED();
  DCHECK(RuntimeEnabledFeatures::HitTestOpaquenessEnabled());
  if (PaintInvalidationReasonForPrePaint() <
      PaintInvalidationReason::kHitTest) {
    SetShouldCheckForPaintInvalidationWithoutLayoutChange();
    paint_invalidation_reason_for_pre_paint_ =
        static_cast<unsigned>(PaintInvalidationReason::kHitTest);
    DCHECK(ShouldInvalidatePaintForHitTestOnly());
  }
}

void LayoutObject::SetShouldCheckForPaintInvalidation() {
  NOT_DESTROYED();
  if (ShouldCheckLayoutForPaintInvalidation()) {
    DCHECK(ShouldCheckForPaintInvalidation());
    return;
  }
  GetFrameView()->ScheduleVisualUpdateForPaintInvalidationIfNeeded();

  bitfields_.SetShouldCheckForPaintInvalidation(true);
  bitfields_.SetShouldCheckLayoutForPaintInvalidation(true);

  // This is not a good place to be during pre-paint. Marking the the ancestry
  // for paint invalidation checking during pre-paint is bad, since we may
  // already be done with those objects, and never get to visit them again in
  // the pre-paint phase. LayoutObject ancestors as they may be, the structure
  // of the physical fragment tree could be different.
  DCHECK(GetDocument().Lifecycle().GetState() !=
         DocumentLifecycle::kInPrePaint);

  for (LayoutObject* ancestor = Parent();
       ancestor && !ancestor->DescendantShouldCheckLayoutForPaintInvalidation();
       ancestor = ancestor->Parent()) {
    ancestor->bitfields_.SetShouldCheckForPaintInvalidation(true);
    ancestor->bitfields_.SetDescendantShouldCheckLayoutForPaintInvalidation(
        true);
  }
}

void LayoutObject::SetShouldCheckForPaintInvalidationWithoutLayoutChange() {
  NOT_DESTROYED();
  if (ShouldCheckForPaintInvalidation()) {
    return;
  }
  GetFrameView()->ScheduleVisualUpdateForPaintInvalidationIfNeeded();

  bitfields_.SetShouldCheckForPaintInvalidation(true);
  for (LayoutObject* ancestor = Parent();
       ancestor && !ancestor->ShouldCheckForPaintInvalidation();
       ancestor = ancestor->Parent()) {
    ancestor->bitfields_.SetShouldCheckForPaintInvalidation(true);
  }
}

void LayoutObject::SetSubtreeShouldCheckForPaintInvalidation() {
  NOT_DESTROYED();
  if (SubtreeShouldCheckForPaintInvalidation()) {
    DCHECK(ShouldCheckForPaintInvalidation());
    return;
  }
  SetShouldCheckForPaintInvalidation();
  bitfields_.SetSubtreeShouldCheckForPaintInvalidation(true);
}

void LayoutObject::SetMayNeedPaintInvalidationAnimatedBackgroundImage() {
  NOT_DESTROYED();
  if (MayNeedPaintInvalidationAnimatedBackgroundImage())
    return;
  bitfields_.SetMayNeedPaintInvalidationAnimatedBackgroundImage(true);
  SetShouldCheckForPaintInvalidationWithoutLayoutChange();
}

void LayoutObject::SetShouldDelayFullPaintInvalidation() {
  NOT_DESTROYED();
  // Should have already set a full paint invalidation reason.
  DCHECK(IsFullPaintInvalidationReason(PaintInvalidationReasonForPrePaint()));
  // Subtree full paint invalidation can't be delayed.
  if (bitfields_.SubtreeShouldDoFullPaintInvalidation()) {
    return;
  }

  bitfields_.SetShouldDelayFullPaintInvalidation(true);
  if (!ShouldCheckForPaintInvalidation()) {
    // This will also schedule a visual update.
    SetShouldCheckForPaintInvalidationWithoutLayoutChange();
  } else {
    // Schedule visual update for the next document cycle in which we will
    // check if the delayed invalidation should be promoted to a real
    // invalidation.
    GetFrameView()->ScheduleVisualUpdateForPaintInvalidationIfNeeded();
  }
}

void LayoutObject::ClearShouldDelayFullPaintInvalidation() {
  // This will clear ShouldDelayFullPaintInvalidation() flag.
  SetShouldDoFullPaintInvalidationWithoutLayoutChangeInternal(
      PaintInvalidationReasonForPrePaint());
}

void LayoutObject::ClearPaintInvalidationFlags() {
  NOT_DESTROYED();
// PaintInvalidationStateIsDirty should be kept in sync with the
// booleans that are cleared below.
#if DCHECK_IS_ON()
  DCHECK(!ShouldCheckForPaintInvalidation() || PaintInvalidationStateIsDirty());
#endif
  if (!ShouldDelayFullPaintInvalidation()) {
    paint_invalidation_reason_for_pre_paint_ =
        static_cast<unsigned>(PaintInvalidationReason::kNone);
    bitfields_.SetBackgroundNeedsFullPaintInvalidation(false);
  }
  bitfields_.SetShouldCheckForPaintInvalidation(false);
  bitfields_.SetSubtreeShouldCheckForPaintInvalidation(false);
  bitfields_.SetSubtreeShouldDoFullPaintInvalidation(false);
  bitfields_.SetMayNeedPaintInvalidationAnimatedBackgroundImage(false);
  bitfields_.SetShouldCheckLayoutForPaintInvalidation(false);
  bitfields_.SetDescendantShouldCheckLayoutForPaintInvalidation(false);
  bitfields_.SetShouldInvalidateSelection(false);
}

#if DCHECK_IS_ON()
bool LayoutObject::PaintInvalidationStateIsDirty() const {
  NOT_DESTROYED();
  return BackgroundNeedsFullPaintInvalidation() ||
         ShouldCheckForPaintInvalidation() || ShouldInvalidateSelection() ||
         ShouldCheckLayoutForPaintInvalidation() ||
         DescendantShouldCheckLayoutForPaintInvalidation() ||
         ShouldDoFullPaintInvalidation() ||
         SubtreeShouldDoFullPaintInvalidation() ||
         MayNeedPaintInvalidationAnimatedBackgroundImage();
}
#endif

void LayoutObject::EnsureIsReadyForPaintInvalidation() {
  NOT_DESTROYED();
  DCHECK(!NeedsLayout() || ChildLayoutBlockedByDisplayLock());

  // Force full paint invalidation if the outline may be affected by descendants
  // and this object is marked for checking paint invalidation for any reason.
  if (bitfields_.OutlineMayBeAffectedByDescendants() ||
      bitfields_.PreviousOutlineMayBeAffectedByDescendants()) {
    SetShouldDoFullPaintInvalidationWithoutLayoutChange(
        PaintInvalidationReason::kOutline);
  }
  bitfields_.SetPreviousOutlineMayBeAffectedByDescendants(
      bitfields_.OutlineMayBeAffectedByDescendants());
}

void LayoutObject::ClearPaintFlags() {
  NOT_DESTROYED();
  DCHECK_EQ(GetDocument().Lifecycle().GetState(),
            DocumentLifecycle::kInPrePaint);
  ClearPaintInvalidationFlags();
  bitfields_.SetNeedsPaintPropertyUpdate(false);
  bitfields_.SetEffectiveAllowedTouchActionChanged(false);
  bitfields_.SetBlockingWheelEventHandlerChanged(false);

  if (!ChildPrePaintBlockedByDisplayLock()) {
    bitfields_.SetDescendantNeedsPaintPropertyUpdate(false);
    bitfields_.SetDescendantEffectiveAllowedTouchActionChanged(false);
    bitfields_.SetDescendantBlockingWheelEventHandlerChanged(false);
    subtree_paint_property_update_reasons_ =
        static_cast<unsigned>(SubtreePaintPropertyUpdateReason::kNone);
  }
}

bool LayoutObject::IsAllowedToModifyLayoutTreeStructure(Document& document) {
  return document.Lifecycle().StateAllowsLayoutTreeMutations() ||
         document.GetStyleEngine().InContainerQueryStyleRecalc() ||
         document.GetStyleEngine().InScrollMarkersAttachment();
}

void LayoutObject::SetSubtreeShouldDoFullPaintInvalidation(
    PaintInvalidationReason reason) {
  NOT_DESTROYED();
  SetShouldDoFullPaintInvalidation(reason);
  bitfields_.SetSubtreeShouldDoFullPaintInvalidation(true);
}

void LayoutObject::SetIsBackgroundAttachmentFixedObject(
    bool is_background_attachment_fixed_object) {
  NOT_DESTROYED();
  DCHECK(GetFrameView());
  DCHECK(IsBoxModelObject());
  if (bitfields_.IsBackgroundAttachmentFixedObject() ==
      is_background_attachment_fixed_object) {
    return;
  }
  bitfields_.SetIsBackgroundAttachmentFixedObject(
      is_background_attachment_fixed_object);
  if (is_background_attachment_fixed_object) {
    GetFrameView()->AddBackgroundAttachmentFixedObject(
        To<LayoutBoxModelObject>(*this));
  } else {
    SetCanCompositeBackgroundAttachmentFixed(false);
    GetFrameView()->RemoveBackgroundAttachmentFixedObject(
        To<LayoutBoxModelObject>(*this));
  }
}

void LayoutObject::SetCanCompositeBackgroundAttachmentFixed(
    bool can_composite) {
  if (can_composite != bitfields_.CanCompositeBackgroundAttachmentFixed()) {
    bitfields_.SetCanCompositeBackgroundAttachmentFixed(can_composite);
    SetNeedsPaintPropertyUpdate();
  }
}

PhysicalRect LayoutObject::DebugRect() const {
  NOT_DESTROYED();
  return PhysicalRect();
}

void LayoutObject::InvalidateSelectedChildrenOnStyleChange() {
  NOT_DESTROYED();
  // LayoutSelection::Commit() propagates the state up the containing node
  // chain to
  // tell if a block contains selected nodes or not. If this layout object is
  // not a block, we need to get the selection state from the containing block
  // to tell if we have any selected node children.
  LayoutBlock* block =
      IsLayoutBlock() ? To<LayoutBlock>(this) : ContainingBlock();
  if (!block)
    return;
  if (!block->IsSelected())
    return;

  // ::selection style only applies to direct selection leaf children of the
  // element on which the ::selection style is set. Thus, we only walk the
  // direct children here.
  for (LayoutObject* child = SlowFirstChild(); child;
       child = child->NextSibling()) {
    if (!child->CanBeSelectionLeaf())
      continue;
    if (!child->IsSelected())
      continue;
    child->SetShouldInvalidateSelection();
  }
}

void LayoutObject::MarkEffectiveAllowedTouchActionChanged() {
  NOT_DESTROYED();
  DCHECK(!GetDocument().InvalidationDisallowed());
  bitfields_.SetEffectiveAllowedTouchActionChanged(true);
  // If we're locked, mark our descendants as needing this change. This is used
  // a signal to ensure we mark the element as needing effective allowed
  // touch action recalculation when the element becomes unlocked.
  if (ChildPrePaintBlockedByDisplayLock()) {
    bitfields_.SetDescendantEffectiveAllowedTouchActionChanged(true);
    return;
  }

  if (Parent())
    Parent()->MarkDescendantEffectiveAllowedTouchActionChanged();
}

void LayoutObject::MarkDescendantEffectiveAllowedTouchActionChanged() {
  DCHECK(!GetDocument().InvalidationDisallowed());
  LayoutObject* obj = this;
  while (obj && !obj->DescendantEffectiveAllowedTouchActionChanged()) {
    obj->bitfields_.SetDescendantEffectiveAllowedTouchActionChanged(true);
    if (obj->ChildPrePaintBlockedByDisplayLock())
      break;

    obj = obj->Parent();
  }
}

void LayoutObject::MarkBlockingWheelEventHandlerChanged() {
  DCHECK(!GetDocument().InvalidationDisallowed());
  bitfields_.SetBlockingWheelEventHandlerChanged(true);
  // If we're locked, mark our descendants as needing this change. This is used
  // as a signal to ensure we mark the element as needing wheel event handler
  // recalculation when the element becomes unlocked.
  if (ChildPrePaintBlockedByDisplayLock()) {
    bitfields_.SetDescendantBlockingWheelEventHandlerChanged(true);
    return;
  }

  if (Parent())
    Parent()->MarkDescendantBlockingWheelEventHandlerChanged();
}

void LayoutObject::MarkDescendantBlockingWheelEventHandlerChanged() {
  DCHECK(!GetDocument().InvalidationDisallowed());
  LayoutObject* obj = this;
  while (obj && !obj->DescendantBlockingWheelEventHandlerChanged()) {
    obj->bitfields_.SetDescendantBlockingWheelEventHandlerChanged(true);
    if (obj->ChildPrePaintBlockedByDisplayLock())
      break;

    obj = obj->Parent();
  }
}

// Note about ::first-letter pseudo-element:
//   When an element has ::first-letter pseudo-element, first letter characters
//   are taken from |Text| node and first letter
### 提示词
```
这是目录为blink/renderer/core/layout/layout_object.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第6部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
Zoom();
  Node* node = nullptr;
  for (LayoutObject* ancestor = Parent(); ancestor;
       ancestor = ancestor->Parent()) {
    // Spec: http://www.w3.org/TR/cssom-view/#offset-attributes

    node = ancestor->GetNode();

    if (!node)
      continue;

    // If |base| was provided, then we should not return an Element which is
    // closed shadow hidden from |base|. If we keep going up the flat tree, then
    // we will eventually get to a node which is not closed shadow hidden from
    // |base|. https://github.com/w3c/csswg-drafts/issues/159
    if (base && !ancestor_tree_scopes.Contains(&node->GetTreeScope())) {
      // If 'position: fixed' node is found while traversing up, terminate the
      // loop and return null.
      if (ancestor->IsFixedPositioned())
        return nullptr;
      continue;
    }

    if (ancestor->CanContainAbsolutePositionObjects())
      break;

    if (IsA<HTMLBodyElement>(*node))
      break;

    if (!IsPositioned() &&
        (IsA<HTMLTableElement>(*node) || IsA<HTMLTableCellElement>(*node)))
      break;

    // Webkit specific extension where offsetParent stops at zoom level changes.
    if (effective_zoom != ancestor->StyleRef().EffectiveZoom())
      break;
  }

  return DynamicTo<Element>(node);
}

void LayoutObject::NotifyImageFullyRemoved(ImageResourceContent* image) {
  NOT_DESTROYED();
  if (LocalDOMWindow* window = GetDocument().domWindow())
    ImageElementTiming::From(*window).NotifyImageRemoved(this, image);
  if (LocalFrameView* frame_view = GetFrameView())
    frame_view->GetPaintTimingDetector().NotifyImageRemoved(*this, image);
}

PositionWithAffinity LayoutObject::CreatePositionWithAffinity(
    int offset,
    TextAffinity affinity) const {
  NOT_DESTROYED();
  // If this is a non-anonymous layoutObject in an editable area, then it's
  // simple.
  Node* const node = NonPseudoNode();
  if (!node)
    return FindPosition();
  return AdjustForEditingBoundary(
      PositionWithAffinity(Position(node, offset), affinity));
}

PositionWithAffinity LayoutObject::FindPosition() const {
  NOT_DESTROYED();
  // We don't want to cross the boundary between editable and non-editable
  // regions of the document, but that is either impossible or at least
  // extremely unlikely in any normal case because we stop as soon as we
  // find a single non-anonymous layoutObject.

  // Find a nearby non-anonymous layoutObject.
  const LayoutObject* child = this;
  while (const LayoutObject* parent = child->Parent()) {
    // Find non-anonymous content after.
    for (const LayoutObject* layout_object = child->NextInPreOrder(parent);
         layout_object; layout_object = layout_object->NextInPreOrder(parent)) {
      if (const Node* node = layout_object->NonPseudoNode()) {
        return PositionWithAffinity(FirstPositionInOrBeforeNode(*node));
      }
    }

    // Find non-anonymous content before.
    for (const LayoutObject* layout_object = child->PreviousInPreOrder();
         layout_object; layout_object = layout_object->PreviousInPreOrder()) {
      if (layout_object == parent)
        break;
      if (const Node* node = layout_object->NonPseudoNode())
        return PositionWithAffinity(LastPositionInOrAfterNode(*node));
    }

    // Use the parent itself unless it too is anonymous.
    if (const Node* node = parent->NonPseudoNode())
      return PositionWithAffinity(FirstPositionInOrBeforeNode(*node));

    // Repeat at the next level up.
    child = parent;
  }

  // Everything was anonymous. Give up.
  return PositionWithAffinity();
}

PositionWithAffinity LayoutObject::FirstPositionInOrBeforeThis() const {
  NOT_DESTROYED();
  if (Node* node = NonPseudoNode())
    return AdjustForEditingBoundary(FirstPositionInOrBeforeNode(*node));
  return FindPosition();
}

PositionWithAffinity LayoutObject::LastPositionInOrAfterThis() const {
  NOT_DESTROYED();
  if (Node* node = NonPseudoNode())
    return AdjustForEditingBoundary(LastPositionInOrAfterNode(*node));
  return FindPosition();
}

PositionWithAffinity LayoutObject::PositionAfterThis() const {
  NOT_DESTROYED();
  if (Node* node = NonPseudoNode())
    return AdjustForEditingBoundary(Position::AfterNode(*node));
  return FindPosition();
}

PositionWithAffinity LayoutObject::PositionBeforeThis() const {
  NOT_DESTROYED();
  if (Node* node = NonPseudoNode())
    return AdjustForEditingBoundary(Position::BeforeNode(*node));
  return FindPosition();
}

PositionWithAffinity LayoutObject::CreatePositionWithAffinity(
    int offset) const {
  NOT_DESTROYED();
  return CreatePositionWithAffinity(offset, TextAffinity::kDownstream);
}

CursorDirective LayoutObject::GetCursor(const PhysicalOffset&,
                                        ui::Cursor&) const {
  NOT_DESTROYED();
  return kSetCursorBasedOnStyle;
}

bool LayoutObject::CanUpdateSelectionOnRootLineBoxes() const {
  NOT_DESTROYED();
  if (NeedsLayout())
    return false;

  const LayoutBlock* containing_block = ContainingBlock();
  return containing_block ? !containing_block->NeedsLayout() : false;
}

SVGLayoutResult LayoutObject::UpdateSVGLayout(const SVGLayoutInfo&) {
  NOT_DESTROYED();
  NOTREACHED();
}

gfx::RectF LayoutObject::ObjectBoundingBox() const {
  NOT_DESTROYED();
  NOTREACHED();
}

gfx::RectF LayoutObject::StrokeBoundingBox() const {
  NOT_DESTROYED();
  NOTREACHED();
}

gfx::RectF LayoutObject::DecoratedBoundingBox() const {
  NOT_DESTROYED();
  NOTREACHED();
}

gfx::RectF LayoutObject::VisualRectInLocalSVGCoordinates() const {
  NOT_DESTROYED();
  NOTREACHED();
}

AffineTransform LayoutObject::LocalSVGTransform() const {
  NOT_DESTROYED();
  return AffineTransform();
}

bool LayoutObject::IsRelayoutBoundary() const {
  NOT_DESTROYED();
  return ObjectIsRelayoutBoundary(this);
}

void LayoutObject::SetShouldInvalidateSelection() {
  NOT_DESTROYED();
  bitfields_.SetShouldInvalidateSelection(true);
  SetShouldCheckForPaintInvalidation();
  // Invalidate overflow for ::selection styles that contain overflowing
  // effects. Do this only for text objects, at least until
  // crbug.com/1128199 is resolved (see InvalidateVisualOverflow())
  if (IsText()) {
    if (auto* computed_style = GetSelectionStyle()) {
      if (computed_style->HasAppliedTextDecorations() ||
          computed_style->HasVisualOverflowingEffect()) {
        InvalidateVisualOverflow();
      }
    }
  }
}

void LayoutObject::SetShouldDoFullPaintInvalidation(
    PaintInvalidationReason reason) {
  NOT_DESTROYED();
  DCHECK(IsLayoutFullPaintInvalidationReason(reason));
  SetShouldCheckForPaintInvalidation();
  SetShouldDoFullPaintInvalidationWithoutLayoutChangeInternal(reason);
}

void LayoutObject::SetShouldDoFullPaintInvalidationWithoutLayoutChange(
    PaintInvalidationReason reason) {
  NOT_DESTROYED();
  DCHECK(IsNonLayoutFullPaintInvalidationReason(reason));
  // Use SetBackgroundNeedsFullPaintInvalidation() instead. See comment of the
  // function.
  DCHECK_NE(reason, PaintInvalidationReason::kBackground);
  SetShouldDoFullPaintInvalidationWithoutLayoutChangeInternal(reason);
}

void LayoutObject::SetShouldDoFullPaintInvalidationWithoutLayoutChangeInternal(
    PaintInvalidationReason reason) {
  NOT_DESTROYED();
  // Only full invalidation reasons are allowed.
  DCHECK(IsFullPaintInvalidationReason(reason));
  const bool was_delayed = bitfields_.ShouldDelayFullPaintInvalidation();
  bitfields_.SetShouldDelayFullPaintInvalidation(false);
  const bool should_upgrade_reason =
      reason > PaintInvalidationReasonForPrePaint();
  if (was_delayed || should_upgrade_reason) {
    SetShouldCheckForPaintInvalidationWithoutLayoutChange();
  }
  if (should_upgrade_reason) {
    paint_invalidation_reason_for_pre_paint_ = static_cast<unsigned>(reason);
    DCHECK_EQ(reason, PaintInvalidationReasonForPrePaint());
  }
}

void LayoutObject::SetShouldInvalidatePaintForHitTest() {
  NOT_DESTROYED();
  DCHECK(RuntimeEnabledFeatures::HitTestOpaquenessEnabled());
  if (PaintInvalidationReasonForPrePaint() <
      PaintInvalidationReason::kHitTest) {
    SetShouldCheckForPaintInvalidationWithoutLayoutChange();
    paint_invalidation_reason_for_pre_paint_ =
        static_cast<unsigned>(PaintInvalidationReason::kHitTest);
    DCHECK(ShouldInvalidatePaintForHitTestOnly());
  }
}

void LayoutObject::SetShouldCheckForPaintInvalidation() {
  NOT_DESTROYED();
  if (ShouldCheckLayoutForPaintInvalidation()) {
    DCHECK(ShouldCheckForPaintInvalidation());
    return;
  }
  GetFrameView()->ScheduleVisualUpdateForPaintInvalidationIfNeeded();

  bitfields_.SetShouldCheckForPaintInvalidation(true);
  bitfields_.SetShouldCheckLayoutForPaintInvalidation(true);

  // This is not a good place to be during pre-paint. Marking the the ancestry
  // for paint invalidation checking during pre-paint is bad, since we may
  // already be done with those objects, and never get to visit them again in
  // the pre-paint phase. LayoutObject ancestors as they may be, the structure
  // of the physical fragment tree could be different.
  DCHECK(GetDocument().Lifecycle().GetState() !=
         DocumentLifecycle::kInPrePaint);

  for (LayoutObject* ancestor = Parent();
       ancestor && !ancestor->DescendantShouldCheckLayoutForPaintInvalidation();
       ancestor = ancestor->Parent()) {
    ancestor->bitfields_.SetShouldCheckForPaintInvalidation(true);
    ancestor->bitfields_.SetDescendantShouldCheckLayoutForPaintInvalidation(
        true);
  }
}

void LayoutObject::SetShouldCheckForPaintInvalidationWithoutLayoutChange() {
  NOT_DESTROYED();
  if (ShouldCheckForPaintInvalidation()) {
    return;
  }
  GetFrameView()->ScheduleVisualUpdateForPaintInvalidationIfNeeded();

  bitfields_.SetShouldCheckForPaintInvalidation(true);
  for (LayoutObject* ancestor = Parent();
       ancestor && !ancestor->ShouldCheckForPaintInvalidation();
       ancestor = ancestor->Parent()) {
    ancestor->bitfields_.SetShouldCheckForPaintInvalidation(true);
  }
}

void LayoutObject::SetSubtreeShouldCheckForPaintInvalidation() {
  NOT_DESTROYED();
  if (SubtreeShouldCheckForPaintInvalidation()) {
    DCHECK(ShouldCheckForPaintInvalidation());
    return;
  }
  SetShouldCheckForPaintInvalidation();
  bitfields_.SetSubtreeShouldCheckForPaintInvalidation(true);
}

void LayoutObject::SetMayNeedPaintInvalidationAnimatedBackgroundImage() {
  NOT_DESTROYED();
  if (MayNeedPaintInvalidationAnimatedBackgroundImage())
    return;
  bitfields_.SetMayNeedPaintInvalidationAnimatedBackgroundImage(true);
  SetShouldCheckForPaintInvalidationWithoutLayoutChange();
}

void LayoutObject::SetShouldDelayFullPaintInvalidation() {
  NOT_DESTROYED();
  // Should have already set a full paint invalidation reason.
  DCHECK(IsFullPaintInvalidationReason(PaintInvalidationReasonForPrePaint()));
  // Subtree full paint invalidation can't be delayed.
  if (bitfields_.SubtreeShouldDoFullPaintInvalidation()) {
    return;
  }

  bitfields_.SetShouldDelayFullPaintInvalidation(true);
  if (!ShouldCheckForPaintInvalidation()) {
    // This will also schedule a visual update.
    SetShouldCheckForPaintInvalidationWithoutLayoutChange();
  } else {
    // Schedule visual update for the next document cycle in which we will
    // check if the delayed invalidation should be promoted to a real
    // invalidation.
    GetFrameView()->ScheduleVisualUpdateForPaintInvalidationIfNeeded();
  }
}

void LayoutObject::ClearShouldDelayFullPaintInvalidation() {
  // This will clear ShouldDelayFullPaintInvalidation() flag.
  SetShouldDoFullPaintInvalidationWithoutLayoutChangeInternal(
      PaintInvalidationReasonForPrePaint());
}

void LayoutObject::ClearPaintInvalidationFlags() {
  NOT_DESTROYED();
// PaintInvalidationStateIsDirty should be kept in sync with the
// booleans that are cleared below.
#if DCHECK_IS_ON()
  DCHECK(!ShouldCheckForPaintInvalidation() || PaintInvalidationStateIsDirty());
#endif
  if (!ShouldDelayFullPaintInvalidation()) {
    paint_invalidation_reason_for_pre_paint_ =
        static_cast<unsigned>(PaintInvalidationReason::kNone);
    bitfields_.SetBackgroundNeedsFullPaintInvalidation(false);
  }
  bitfields_.SetShouldCheckForPaintInvalidation(false);
  bitfields_.SetSubtreeShouldCheckForPaintInvalidation(false);
  bitfields_.SetSubtreeShouldDoFullPaintInvalidation(false);
  bitfields_.SetMayNeedPaintInvalidationAnimatedBackgroundImage(false);
  bitfields_.SetShouldCheckLayoutForPaintInvalidation(false);
  bitfields_.SetDescendantShouldCheckLayoutForPaintInvalidation(false);
  bitfields_.SetShouldInvalidateSelection(false);
}

#if DCHECK_IS_ON()
bool LayoutObject::PaintInvalidationStateIsDirty() const {
  NOT_DESTROYED();
  return BackgroundNeedsFullPaintInvalidation() ||
         ShouldCheckForPaintInvalidation() || ShouldInvalidateSelection() ||
         ShouldCheckLayoutForPaintInvalidation() ||
         DescendantShouldCheckLayoutForPaintInvalidation() ||
         ShouldDoFullPaintInvalidation() ||
         SubtreeShouldDoFullPaintInvalidation() ||
         MayNeedPaintInvalidationAnimatedBackgroundImage();
}
#endif

void LayoutObject::EnsureIsReadyForPaintInvalidation() {
  NOT_DESTROYED();
  DCHECK(!NeedsLayout() || ChildLayoutBlockedByDisplayLock());

  // Force full paint invalidation if the outline may be affected by descendants
  // and this object is marked for checking paint invalidation for any reason.
  if (bitfields_.OutlineMayBeAffectedByDescendants() ||
      bitfields_.PreviousOutlineMayBeAffectedByDescendants()) {
    SetShouldDoFullPaintInvalidationWithoutLayoutChange(
        PaintInvalidationReason::kOutline);
  }
  bitfields_.SetPreviousOutlineMayBeAffectedByDescendants(
      bitfields_.OutlineMayBeAffectedByDescendants());
}

void LayoutObject::ClearPaintFlags() {
  NOT_DESTROYED();
  DCHECK_EQ(GetDocument().Lifecycle().GetState(),
            DocumentLifecycle::kInPrePaint);
  ClearPaintInvalidationFlags();
  bitfields_.SetNeedsPaintPropertyUpdate(false);
  bitfields_.SetEffectiveAllowedTouchActionChanged(false);
  bitfields_.SetBlockingWheelEventHandlerChanged(false);

  if (!ChildPrePaintBlockedByDisplayLock()) {
    bitfields_.SetDescendantNeedsPaintPropertyUpdate(false);
    bitfields_.SetDescendantEffectiveAllowedTouchActionChanged(false);
    bitfields_.SetDescendantBlockingWheelEventHandlerChanged(false);
    subtree_paint_property_update_reasons_ =
        static_cast<unsigned>(SubtreePaintPropertyUpdateReason::kNone);
  }
}

bool LayoutObject::IsAllowedToModifyLayoutTreeStructure(Document& document) {
  return document.Lifecycle().StateAllowsLayoutTreeMutations() ||
         document.GetStyleEngine().InContainerQueryStyleRecalc() ||
         document.GetStyleEngine().InScrollMarkersAttachment();
}

void LayoutObject::SetSubtreeShouldDoFullPaintInvalidation(
    PaintInvalidationReason reason) {
  NOT_DESTROYED();
  SetShouldDoFullPaintInvalidation(reason);
  bitfields_.SetSubtreeShouldDoFullPaintInvalidation(true);
}

void LayoutObject::SetIsBackgroundAttachmentFixedObject(
    bool is_background_attachment_fixed_object) {
  NOT_DESTROYED();
  DCHECK(GetFrameView());
  DCHECK(IsBoxModelObject());
  if (bitfields_.IsBackgroundAttachmentFixedObject() ==
      is_background_attachment_fixed_object) {
    return;
  }
  bitfields_.SetIsBackgroundAttachmentFixedObject(
      is_background_attachment_fixed_object);
  if (is_background_attachment_fixed_object) {
    GetFrameView()->AddBackgroundAttachmentFixedObject(
        To<LayoutBoxModelObject>(*this));
  } else {
    SetCanCompositeBackgroundAttachmentFixed(false);
    GetFrameView()->RemoveBackgroundAttachmentFixedObject(
        To<LayoutBoxModelObject>(*this));
  }
}

void LayoutObject::SetCanCompositeBackgroundAttachmentFixed(
    bool can_composite) {
  if (can_composite != bitfields_.CanCompositeBackgroundAttachmentFixed()) {
    bitfields_.SetCanCompositeBackgroundAttachmentFixed(can_composite);
    SetNeedsPaintPropertyUpdate();
  }
}

PhysicalRect LayoutObject::DebugRect() const {
  NOT_DESTROYED();
  return PhysicalRect();
}

void LayoutObject::InvalidateSelectedChildrenOnStyleChange() {
  NOT_DESTROYED();
  // LayoutSelection::Commit() propagates the state up the containing node
  // chain to
  // tell if a block contains selected nodes or not. If this layout object is
  // not a block, we need to get the selection state from the containing block
  // to tell if we have any selected node children.
  LayoutBlock* block =
      IsLayoutBlock() ? To<LayoutBlock>(this) : ContainingBlock();
  if (!block)
    return;
  if (!block->IsSelected())
    return;

  // ::selection style only applies to direct selection leaf children of the
  // element on which the ::selection style is set. Thus, we only walk the
  // direct children here.
  for (LayoutObject* child = SlowFirstChild(); child;
       child = child->NextSibling()) {
    if (!child->CanBeSelectionLeaf())
      continue;
    if (!child->IsSelected())
      continue;
    child->SetShouldInvalidateSelection();
  }
}

void LayoutObject::MarkEffectiveAllowedTouchActionChanged() {
  NOT_DESTROYED();
  DCHECK(!GetDocument().InvalidationDisallowed());
  bitfields_.SetEffectiveAllowedTouchActionChanged(true);
  // If we're locked, mark our descendants as needing this change. This is used
  // a signal to ensure we mark the element as needing effective allowed
  // touch action recalculation when the element becomes unlocked.
  if (ChildPrePaintBlockedByDisplayLock()) {
    bitfields_.SetDescendantEffectiveAllowedTouchActionChanged(true);
    return;
  }

  if (Parent())
    Parent()->MarkDescendantEffectiveAllowedTouchActionChanged();
}

void LayoutObject::MarkDescendantEffectiveAllowedTouchActionChanged() {
  DCHECK(!GetDocument().InvalidationDisallowed());
  LayoutObject* obj = this;
  while (obj && !obj->DescendantEffectiveAllowedTouchActionChanged()) {
    obj->bitfields_.SetDescendantEffectiveAllowedTouchActionChanged(true);
    if (obj->ChildPrePaintBlockedByDisplayLock())
      break;

    obj = obj->Parent();
  }
}

void LayoutObject::MarkBlockingWheelEventHandlerChanged() {
  DCHECK(!GetDocument().InvalidationDisallowed());
  bitfields_.SetBlockingWheelEventHandlerChanged(true);
  // If we're locked, mark our descendants as needing this change. This is used
  // as a signal to ensure we mark the element as needing wheel event handler
  // recalculation when the element becomes unlocked.
  if (ChildPrePaintBlockedByDisplayLock()) {
    bitfields_.SetDescendantBlockingWheelEventHandlerChanged(true);
    return;
  }

  if (Parent())
    Parent()->MarkDescendantBlockingWheelEventHandlerChanged();
}

void LayoutObject::MarkDescendantBlockingWheelEventHandlerChanged() {
  DCHECK(!GetDocument().InvalidationDisallowed());
  LayoutObject* obj = this;
  while (obj && !obj->DescendantBlockingWheelEventHandlerChanged()) {
    obj->bitfields_.SetDescendantBlockingWheelEventHandlerChanged(true);
    if (obj->ChildPrePaintBlockedByDisplayLock())
      break;

    obj = obj->Parent();
  }
}

// Note about ::first-letter pseudo-element:
//   When an element has ::first-letter pseudo-element, first letter characters
//   are taken from |Text| node and first letter characters are considered
//   as content of <pseudo:first-letter>.
//   For following HTML,
//      <style>div::first-letter {color: red}</style>
//      <div>abc</div>
//   we have following layout tree:
//      LayoutBlockFlow {DIV} at (0,0) size 784x55
//        LayoutInline {<pseudo:first-letter>} at (0,0) size 22x53
//          LayoutTextFragment (anonymous) at (0,1) size 22x53
//            text run at (0,1) width 22: "a"
//        LayoutTextFragment {#text} at (21,30) size 16x17
//          text run at (21,30) width 16: "bc"
//  In this case, |Text::layoutObject()| for "abc" returns |LayoutTextFragment|
//  containing "bc", and it is called remaining part.
//
//  Even if |Text| node contains only first-letter characters, e.g. just "a",
//  remaining part of |LayoutTextFragment|, with |fragmentLength()| == 0, is
//  appeared in layout tree.
//
//  When |Text| node contains only first-letter characters and whitespaces, e.g.
//  "B\n", associated |LayoutTextFragment| is first-letter part instead of
//  remaining part.
//
//  Punctuation characters are considered as first-letter. For "(1)ab",
//  "(1)" are first-letter part and "ab" are remaining part.
const LayoutObject* AssociatedLayoutObjectOf(const Node& node,
                                             int offset_in_node,
                                             LayoutObjectSide object_side) {
  DCHECK_GE(offset_in_node, 0);
  LayoutObject* layout_object = node.GetLayoutObject();
  if (!node.IsTextNode() || !layout_object ||
      !To<LayoutText>(layout_object)->IsTextFragment())
    return layout_object;
  auto* layout_text_fragment = To<LayoutTextFragment>(layout_object);
  if (!layout_text_fragment->IsRemainingTextLayoutObject()) {
    DCHECK_LE(
        static_cast<unsigned>(offset_in_node),
        layout_text_fragment->Start() + layout_text_fragment->FragmentLength());
    return layout_text_fragment;
  }
  if (layout_text_fragment->FragmentLength()) {
    const unsigned threshold =
        object_side == LayoutObjectSide::kRemainingTextIfOnBoundary
            ? layout_text_fragment->Start()
            : layout_text_fragment->Start() + 1;
    if (static_cast<unsigned>(offset_in_node) >= threshold)
      return layout_object;
  }
  return layout_text_fragment->GetFirstLetterPart();
}

bool LayoutObject::CanBeSelectionLeaf() const {
  NOT_DESTROYED();
  if (SlowFirstChild() || StyleRef().Visibility() != EVisibility::kVisible ||
      DisplayLockUtilities::LockedAncestorPreventingPaint(*this)) {
    return false;
  }
  return CanBeSelectionLeafInternal();
}

Vector<PhysicalRect> LayoutObject::CollectOutlineRectsAndAdvance(
    OutlineType outline_type,
    AccompaniedFragmentIterator& iterator) const {
  NOT_DESTROYED();
  Vector<PhysicalRect> outline_rects;
  PhysicalOffset paint_offset = iterator.GetFragmentData()->PaintOffset();

  VectorOutlineRectCollector collector;
  if (iterator.Cursor()) {
    wtf_size_t fragment_index = iterator.Cursor()->ContainerFragmentIndex();
    do {
      const FragmentItem* item = iterator.Cursor()->Current().Item();
      if (!item)
        continue;
      if (const PhysicalBoxFragment* box_fragment = item->BoxFragment()) {
        box_fragment->AddSelfOutlineRects(
            paint_offset + item->OffsetInContainerFragment(), outline_type,
            collector, nullptr);
      } else {
        PhysicalRect rect;
        rect = item->RectInContainerFragment();
        rect.Move(paint_offset);
        collector.AddRect(rect);
      }
      // Keep going as long as we're within the same container fragment. If
      // we're block-fragmented, there will be multiple container fragments,
      // each with their own FragmentData object.
    } while (iterator.Advance() &&
             iterator.Cursor()->ContainerFragmentIndex() == fragment_index);
    outline_rects = collector.TakeRects();
  } else {
    if (const auto* box_fragment = iterator.GetPhysicalBoxFragment()) {
      box_fragment->AddSelfOutlineRects(paint_offset, outline_type, collector,
                                        nullptr);
      outline_rects = collector.TakeRects();
    } else {
      outline_rects = OutlineRects(nullptr, paint_offset, outline_type);
    }
    iterator.Advance();
  }

  return outline_rects;
}

Vector<PhysicalRect> LayoutObject::OutlineRects(
    OutlineInfo* info,
    const PhysicalOffset& additional_offset,
    OutlineType outline_type) const {
  NOT_DESTROYED();
  VectorOutlineRectCollector collector;
  AddOutlineRects(collector, info, additional_offset, outline_type);
  return collector.TakeRects();
}

void LayoutObject::SetModifiedStyleOutsideStyleRecalc(
    const ComputedStyle* style,
    ApplyStyleChanges apply_changes) {
  NOT_DESTROYED();
  SetStyle(style, apply_changes);
  if (IsAnonymous()) {
    return;
  }
  if (auto* element = DynamicTo<Element>(GetNode())) {
    element->SetComputedStyle(style);
  }
}

LayoutUnit LayoutObject::FlipForWritingModeInternal(
    LayoutUnit position,
    LayoutUnit width,
    const LayoutBox* box_for_flipping) const {
  NOT_DESTROYED();
  DCHECK(!IsBox());
  DCHECK(HasFlippedBlocksWritingMode());
  DCHECK(!box_for_flipping || box_for_flipping == ContainingBlock());
  // For now, block flipping doesn't apply for non-box SVG objects.
  if (IsSVG())
    return position;
  return (box_for_flipping ? box_for_flipping : ContainingBlock())
      ->FlipForWritingMode(position, width);
}

bool LayoutObject::SelfPaintingLayerNeedsVisualOverflowRecalc() const {
  NOT_DESTROYED();
  if (HasLayer()) {
    auto* box_model_object = To<LayoutBoxModelObject>(this);
    if (box_model_object->HasSelfPaintingLayer())
      return box_model_object->Layer()->NeedsVisualOverflowRecalc();
  }
  return false;
}

void LayoutObject::MarkSelfPaintingLayerForVisualOverflowRecalc() {
  NOT_DESTROYED();
  DCHECK(!GetDocument().InvalidationDisallowed());
  if (HasLayer()) {
    auto* box_model_object = To<LayoutBoxModelObject>(this);
    if (box_model_object->HasSelfPaintingLayer())
      box_model_object->Layer()->SetNeedsVisualOverflowRecalc();
  }
#if DCHECK_IS_ON()
  InvalidateVisualOverflowForDCheck();
#endif
}

void LayoutObject::SetSVGDescendantMayHaveTransformRelatedAnimation() {
  NOT_DESTROYED();
  auto* object = this;
  while (!object->IsSVGRoot()) {
    DCHECK(object->IsSVGChild());
    if (object->SVGDescendantMayHaveTransformRelatedAnimation())
      break;
    if (object->IsSVGHiddenContainer())
      return;
    object->bitfields_.SetSVGDescendantMayHaveTransformRelatedAnimation(true);
    object = object->Parent();
    if (!object)
      return;
  }
  // If we have set SetSVGDescendantMayHaveTransformRelatedAnimation() for
  // any object, set the enclosing layer needs repaint because some
  // LayoutSVGContainer may paint differently by ignoring the cull rect.
  // See SVGContainerPainter.
  if (object != this) {
    if (auto* layer = object->EnclosingLayer())
      layer->SetNeedsRepaint();
  }
}

void LayoutObject::SetSVGSelfOrDescendantHasViewportDependency() {
  NOT_DESTROYED();
  auto* object = this;
  do {
    DCHECK(object->IsSVGChild());
    if (object->SVGSelfOrDescendantHasViewportDependency()) {
      break;
    }
    object->bitfields_.SetSVGSelfOrDescendantHasViewportDependency(true);
    object = object->Parent();
  } while (object && !object->IsSVGRoot());
}

void LayoutObject::InvalidateSubtreePositionTry(bool mark_style_dirty) {
  NOT_DESTROYED();

  bool invalidate = StyleRef().GetPositionTryFallbacks() != nullptr;
  if (invalidate) {
    // Invalidate layout as @position-fallback styles are applied during layout.
    SetNeedsLayout(layout_invalidation_reason::kStyleChange);
  }

  if (mark_style_dirty) {
    if (Node* node = GetNode()) {
      if (node->GetStyleChangeType() == kSubtreeStyleChange) {
        // No need to further mark for style recalc inside this subtree.
        mark_style_dirty = false;
      }
      if (invalidate && mark_style_dirty) {
        // Need to invalidate style to avoid using stale cached position
        // fallback styles.
        node->SetNeedsStyleRecalc(kLocalStyleChange,
                                  StyleChangeReasonForTracing::Create(
                                      style_change_reason::kPositionTryChange));
      }
    }
  }

  for (LayoutObject* child = SlowFirstChild(); child;
       child = child->NextSibling()) {
    child->InvalidateSubtreePositionTry(mark_style_dirty);
  }
}

}  // namespace blink

#if DCHECK_IS_ON()

void ShowTree(const blink::LayoutObject* object) {
  if (getenv("RUNNING_UNDER_RR")) {
    // Printing timestamps requires an IPC to get the local time, which
    // does not work in an rr replay session. Just disable timestamp printing
    // globally, since we don't need them. Affecting global state isn't a
    // problem because invoking this from a rr session creates a temporary
    // program environment that will be destroyed as soon as the invocation
    // completes.
    logging::SetLogItems(true, true, false, false);
  }

  if (object)
    object->ShowTreeForThis();
  else
    DLOG(INFO) << "Cannot showTree. Root is (nil)";
}

void ShowLayoutTree(const blink::LayoutObject* object1) {
  ShowLayoutTree(object1, nullptr);
}

void ShowLayoutTree(const blink::LayoutObject* object1,
                    const blink::LayoutObject* object2) {
  if (getenv("RUNNING_UNDER_RR")) {
    // Printing timestamps requires an IPC to get the local time, which
    // does not work in an rr replay session. Just disable timestamp printing
    // globally, since we don't need them. Affecting global state isn't a
    // problem because invoking this from a rr session creates a temporary
    // program environment that will be destroyed as soon as the invocation
    // completes.
    logging::SetLogItems(true, true, false, false);
  }

  if (object1) {
    const blink::LayoutObject* root = object1;
    while (root->Parent())
      root = root->Parent();
    if (object1) {
      StringBuilder string_builder;
      root->DumpLayoutTreeAndMark(string_builder, object1, "*", object2, "-",
                                  0);
      DLOG(INFO) << "\n" << string_builder.ToString().Utf8();
    }
  } else {
    DLOG(INFO) << "Cannot showLayoutTree. Root is (nil)";
  }
}

#endif  // DCHECK_IS_ON()
```