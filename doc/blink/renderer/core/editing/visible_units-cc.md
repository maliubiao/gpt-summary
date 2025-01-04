Response:

Prompt: 
```
这是目录为blink/renderer/core/editing/visible_units.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 2004, 2005, 2006, 2007, 2008, 2009 Apple Inc. All rights
 * reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE COMPUTER, INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL APPLE COMPUTER, INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/editing/visible_units.h"

#include "base/trace_event/trace_event.h"
#include "third_party/blink/renderer/core/display_lock/display_lock_utilities.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/first_letter_pseudo_element.h"
#include "third_party/blink/renderer/core/dom/node_computed_style.h"
#include "third_party/blink/renderer/core/dom/node_traversal.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/iterators/character_iterator.h"
#include "third_party/blink/renderer/core/editing/local_caret_rect.h"
#include "third_party/blink/renderer/core/editing/position.h"
#include "third_party/blink/renderer/core/editing/position_iterator.h"
#include "third_party/blink/renderer/core/editing/position_with_affinity.h"
#include "third_party/blink/renderer/core/editing/selection_adjuster.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/editing/text_affinity.h"
#include "third_party/blink/renderer/core/editing/visible_position.h"
#include "third_party/blink/renderer/core/editing/visible_selection.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/html/forms/text_control_element.h"
#include "third_party/blink/renderer/core/html/html_body_element.h"
#include "third_party/blink/renderer/core/html/html_br_element.h"
#include "third_party/blink/renderer/core/html/html_marquee_element.h"
#include "third_party/blink/renderer/core/html/html_table_element.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/layout/hit_test_location.h"
#include "third_party/blink/renderer/core/layout/hit_test_request.h"
#include "third_party/blink/renderer/core/layout/hit_test_result.h"
#include "third_party/blink/renderer/core/layout/inline/inline_node_data.h"
#include "third_party/blink/renderer/core/layout/layout_inline.h"
#include "third_party/blink/renderer/core/layout/layout_text_fragment.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/svg/svg_foreign_object_element.h"
#include "third_party/blink/renderer/core/svg/svg_text_element.h"
#include "third_party/blink/renderer/core/svg_element_type_helpers.h"
#include "third_party/blink/renderer/platform/text/text_boundaries.h"
#include "ui/gfx/geometry/rect_conversions.h"

namespace blink {

namespace {

bool IsEmptyInline(const LayoutInline& inline_object) {
  for (const LayoutObject* curr = inline_object.FirstChild(); curr;
       curr = curr->NextSibling()) {
    if (curr->IsFloatingOrOutOfFlowPositioned()) {
      continue;
    }
    if (const auto* inline_child = DynamicTo<LayoutInline>(curr)) {
      if (IsEmptyInline(*inline_child)) {
        continue;
      }
    }
    if (const auto* text_child = DynamicTo<LayoutText>(curr)) {
      if (text_child->IsAllCollapsibleWhitespace()) {
        continue;
      }
    }
    return false;
  }
  return true;
}

}  // anonymous namespace

template <typename PositionType>
static PositionType CanonicalizeCandidate(const PositionType& candidate) {
  if (candidate.IsNull())
    return PositionType();
  DCHECK(IsVisuallyEquivalentCandidate(candidate));
  PositionType upstream = MostBackwardCaretPosition(candidate);
  if (IsVisuallyEquivalentCandidate(upstream))
    return upstream;
  return candidate;
}

static bool InSameBlock(const Node* original_node,
                        const Node* new_position_node) {
  DCHECK(new_position_node);
  if (!original_node) {
    return false;
  }

  // If ｜new_position_node｜ is child node of ｜original_node｜, they must be in
  // the same block flow element.
  if (new_position_node->IsDescendantOf(original_node)) {
    return true;
  }

  Element* const original_block = EnclosingBlockFlowElement(*original_node);
  // If both nodes are in editable elements, whether they are in the same block
  // flow element depends on DOM hierarchy.
  // Note: tests [1][2] require this.
  // [1] editing/execCommand/indent-pre-list.html
  // [2] editing/execCommand/indent-pre.html
  if ((IsEditable(*original_node) && IsEditable(*new_position_node))) {
    return new_position_node->IsDescendantOf(original_block) ||
           new_position_node == original_block;
  }

  return original_block == EnclosingBlockFlowElement(*new_position_node);
}

template <typename PositionType>
static PositionType CanonicalPosition(const PositionType& position) {
  // Sometimes updating selection positions can be extremely expensive and
  // occur frequently.  Often calling preventDefault on mousedown events can
  // avoid doing unnecessary text selection work.  http://crbug.com/472258.
  TRACE_EVENT0("input", "VisibleUnits::canonicalPosition");

  // FIXME (9535):  Canonicalizing to the leftmost candidate means that if
  // we're at a line wrap, we will ask layoutObjects to paint downstream
  // carets for other layoutObjects. To fix this, we need to either a) add
  // code to all paintCarets to pass the responsibility off to the appropriate
  // layoutObject for VisiblePosition's like these, or b) canonicalize to the
  // rightmost candidate unless the affinity is upstream.
  if (position.IsNull())
    return PositionType();

  DCHECK(position.GetDocument());
  DCHECK(!position.GetDocument()->NeedsLayoutTreeUpdate());

  const PositionType& backward_candidate = MostBackwardCaretPosition(position);
  if (IsVisuallyEquivalentCandidate(backward_candidate))
    return backward_candidate;

  const PositionType& forward_candidate = MostForwardCaretPosition(position);
  if (IsVisuallyEquivalentCandidate(forward_candidate))
    return forward_candidate;

  // When neither upstream or downstream gets us to a candidate
  // (upstream/downstream won't leave blocks or enter new ones), we search
  // forward and backward until we find one.
  const PositionType& next = CanonicalizeCandidate(NextCandidate(position));
  const PositionType& prev = CanonicalizeCandidate(PreviousCandidate(position));

  // The new position must be in the same editable element. Enforce that
  // first. Unless the descent is from a non-editable html element to an
  // editable body.
  Node* const node = position.ComputeContainerNode();
  if (node && node->GetDocument().documentElement() == node &&
      !IsEditable(*node) && node->GetDocument().body() &&
      IsEditable(*node->GetDocument().body()))
    return next.IsNotNull() ? next : prev;

  Element* const editing_root = RootEditableElementOf(position);
  // If the html element is editable, descending into its body will look like
  // a descent from non-editable to editable content since
  // |rootEditableElementOf()| always stops at the body.
  if ((editing_root &&
       editing_root->GetDocument().documentElement() == editing_root) ||
      position.AnchorNode()->IsDocumentNode())
    return next.IsNotNull() ? next : prev;

  Node* const next_node = next.AnchorNode();
  Node* const prev_node = prev.AnchorNode();
  const bool prev_is_in_same_editable_element =
      prev_node && RootEditableElementOf(prev) == editing_root;
  const bool next_is_in_same_editable_element =
      next_node && RootEditableElementOf(next) == editing_root;
  if (prev_is_in_same_editable_element && !next_is_in_same_editable_element)
    return prev;

  if (next_is_in_same_editable_element && !prev_is_in_same_editable_element)
    return next;

  if (!next_is_in_same_editable_element && !prev_is_in_same_editable_element)
    return PositionType();

  // The new position should be in the same block flow element. Favor that.
  const bool next_is_same_original_block = InSameBlock(node, next_node);
  const bool prev_is_same_original_block = InSameBlock(node, prev_node);
  if (prev_is_same_original_block && !next_is_same_original_block)
    return prev;

  return next;
}

Position CanonicalPositionOf(const Position& position) {
  return CanonicalPosition(position);
}

PositionInFlatTree CanonicalPositionOf(const PositionInFlatTree& position) {
  return CanonicalPosition(position);
}

template <typename Strategy>
static PositionWithAffinityTemplate<Strategy>
AdjustBackwardPositionToAvoidCrossingEditingBoundariesTemplate(
    const PositionWithAffinityTemplate<Strategy>& pos,
    const PositionTemplate<Strategy>& anchor) {
  if (pos.IsNull())
    return pos;

  ContainerNode* highest_root = HighestEditableRoot(anchor);

  // Return empty position if |pos| is not somewhere inside the editable
  // region containing this position
  if (RuntimeEnabledFeatures::
          CheckIfHighestRootContainsPositionAnchorNodeEnabled()) {
    if (highest_root && !highest_root->contains(pos.AnchorNode())) {
      return PositionWithAffinityTemplate<Strategy>();
    }
  } else {
    if (highest_root && !pos.AnchorNode()->IsDescendantOf(highest_root)) {
      return PositionWithAffinityTemplate<Strategy>();
    }
  }

  // Return |pos| itself if the two are from the very same editable region, or
  // both are non-editable
  // TODO(yosin) In the non-editable case, just because the new position is
  // non-editable doesn't mean movement to it is allowed.
  // |VisibleSelection::adjustForEditableContent()| has this problem too.
  if (HighestEditableRoot(pos.GetPosition()) == highest_root)
    return pos;

  // Return empty position if this position is non-editable, but |pos| is
  // editable.
  // TODO(yosin) Move to the previous non-editable region.
  if (!highest_root)
    return PositionWithAffinityTemplate<Strategy>();

  // Return the last position before |pos| that is in the same editable region
  // as this position
  return PositionWithAffinityTemplate<Strategy>(
      LastEditablePositionBeforePositionInRoot(pos.GetPosition(),
                                               *highest_root));
}

PositionWithAffinity AdjustBackwardPositionToAvoidCrossingEditingBoundaries(
    const PositionWithAffinity& pos,
    const Position& anchor) {
  return AdjustBackwardPositionToAvoidCrossingEditingBoundariesTemplate(pos,
                                                                        anchor);
}

PositionInFlatTreeWithAffinity
AdjustBackwardPositionToAvoidCrossingEditingBoundaries(
    const PositionInFlatTreeWithAffinity& pos,
    const PositionInFlatTree& anchor) {
  return AdjustBackwardPositionToAvoidCrossingEditingBoundariesTemplate(pos,
                                                                        anchor);
}

template <typename Strategy>
static PositionWithAffinityTemplate<Strategy>
AdjustForwardPositionToAvoidCrossingEditingBoundariesTemplate(
    const PositionWithAffinityTemplate<Strategy>& pos,
    const PositionTemplate<Strategy>& anchor) {
  if (pos.IsNull())
    return pos;

  ContainerNode* highest_root = HighestEditableRoot(anchor);

  // Return empty position if |pos| is not somewhere inside the editable
  // region containing this position
  if (highest_root && !pos.AnchorNode()->IsDescendantOf(highest_root))
    return PositionWithAffinityTemplate<Strategy>();

  // Return |pos| itself if the two are from the very same editable region, or
  // both are non-editable
  // TODO(yosin) In the non-editable case, just because the new position is
  // non-editable doesn't mean movement to it is allowed.
  // |VisibleSelection::adjustForEditableContent()| has this problem too.
  if (HighestEditableRoot(pos.GetPosition()) == highest_root)
    return pos;

  // Returns the last position in the highest non-editable ancestor of |anchor|.
  if (!highest_root) {
    const Node* last_non_editable = anchor.ComputeContainerNode();
    for (const Node& ancestor : Strategy::AncestorsOf(*last_non_editable)) {
      if (IsEditable(ancestor)) {
        return PositionWithAffinityTemplate<Strategy>(
            PositionTemplate<Strategy>::LastPositionInNode(*last_non_editable));
      }
      last_non_editable = &ancestor;
    }
    return PositionWithAffinityTemplate<Strategy>();
  }

  // Return the next position after |pos| that is in the same editable region
  // as this position
  return PositionWithAffinityTemplate<Strategy>(
      FirstEditablePositionAfterPositionInRoot(pos.GetPosition(),
                                               *highest_root));
}

PositionWithAffinity AdjustForwardPositionToAvoidCrossingEditingBoundaries(
    const PositionWithAffinity& pos,
    const Position& anchor) {
  return AdjustForwardPositionToAvoidCrossingEditingBoundariesTemplate(pos,
                                                                       anchor);
}

PositionInFlatTreeWithAffinity
AdjustForwardPositionToAvoidCrossingEditingBoundaries(
    const PositionInFlatTreeWithAffinity& pos,
    const PositionInFlatTree& anchor) {
  return AdjustForwardPositionToAvoidCrossingEditingBoundariesTemplate(
      PositionInFlatTreeWithAffinity(pos), anchor);
}

template <typename Strategy>
static ContainerNode* NonShadowBoundaryParentNode(Node* node) {
  ContainerNode* parent = Strategy::Parent(*node);
  return parent && !parent->IsShadowRoot() ? parent : nullptr;
}

template <typename Strategy>
static Node* ParentEditingBoundary(const PositionTemplate<Strategy>& position) {
  Node* const anchor_node = position.AnchorNode();
  if (!anchor_node)
    return nullptr;

  Node* document_element = anchor_node->GetDocument().documentElement();
  if (!document_element)
    return nullptr;

  Node* boundary = position.ComputeContainerNode();
  while (boundary != document_element &&
         NonShadowBoundaryParentNode<Strategy>(boundary) &&
         IsEditable(*anchor_node) == IsEditable(*Strategy::Parent(*boundary)))
    boundary = NonShadowBoundaryParentNode<Strategy>(boundary);

  return boundary;
}

// ---------

template <typename Strategy>
static PositionTemplate<Strategy> StartOfDocumentAlgorithm(
    const PositionTemplate<Strategy>& position) {
  const Node* const node = position.AnchorNode();
  if (!node || !node->GetDocument().documentElement())
    return PositionTemplate<Strategy>();

  return PositionTemplate<Strategy>::FirstPositionInNode(
      *node->GetDocument().documentElement());
}

Position StartOfDocument(const Position& c) {
  return StartOfDocumentAlgorithm<EditingStrategy>(c);
}

PositionInFlatTree StartOfDocument(const PositionInFlatTree& c) {
  return StartOfDocumentAlgorithm<EditingInFlatTreeStrategy>(c);
}

template <typename Strategy>
static VisiblePositionTemplate<Strategy> EndOfDocumentAlgorithm(
    const VisiblePositionTemplate<Strategy>& visible_position) {
  DCHECK(visible_position.IsValid()) << visible_position;
  Node* node = visible_position.DeepEquivalent().AnchorNode();
  if (!node || !node->GetDocument().documentElement())
    return VisiblePositionTemplate<Strategy>();

  Element* doc = node->GetDocument().documentElement();
  return CreateVisiblePosition(
      PositionTemplate<Strategy>::LastPositionInNode(*doc));
}

VisiblePosition EndOfDocument(const VisiblePosition& c) {
  return EndOfDocumentAlgorithm<EditingStrategy>(c);
}

VisiblePositionInFlatTree EndOfDocument(const VisiblePositionInFlatTree& c) {
  return EndOfDocumentAlgorithm<EditingInFlatTreeStrategy>(c);
}

bool IsStartOfDocument(const VisiblePosition& p) {
  DCHECK(p.IsValid()) << p;
  return p.IsNotNull() &&
         PreviousPositionOf(p, kCanCrossEditingBoundary).IsNull();
}

bool IsEndOfDocument(const VisiblePosition& p) {
  DCHECK(p.IsValid()) << p;
  return p.IsNotNull() && NextPositionOf(p, kCanCrossEditingBoundary).IsNull();
}

// ---------

PositionInFlatTree StartOfEditableContent(const PositionInFlatTree& position) {
  ContainerNode* highest_root = HighestEditableRoot(position);
  if (!highest_root)
    return PositionInFlatTree();

  return PositionInFlatTree::FirstPositionInNode(*highest_root);
}

PositionInFlatTree EndOfEditableContent(const PositionInFlatTree& position) {
  ContainerNode* highest_root = HighestEditableRoot(position);
  if (!highest_root)
    return PositionInFlatTree();

  return PositionInFlatTree::LastPositionInNode(*highest_root);
}

bool IsEndOfEditableOrNonEditableContent(const VisiblePosition& position) {
  DCHECK(position.IsValid()) << position;
  return position.IsNotNull() && NextPositionOf(position).IsNull();
}

// TODO(yosin) We should rename |isEndOfEditableOrNonEditableContent()| what
// this function does, e.g. |isLastVisiblePositionOrEndOfInnerEditor()|.
bool IsEndOfEditableOrNonEditableContent(
    const VisiblePositionInFlatTree& position) {
  DCHECK(position.IsValid()) << position;
  if (position.IsNull())
    return false;
  const VisiblePositionInFlatTree next_position = NextPositionOf(position);
  if (next_position.IsNull())
    return true;
  // In DOM version, following condition, the last position of inner editor
  // of INPUT/TEXTAREA element, by |nextPosition().isNull()|, because of
  // an inner editor is an only leaf node.
  if (!next_position.DeepEquivalent().IsAfterAnchor())
    return false;
  return IsTextControl(next_position.DeepEquivalent().AnchorNode());
}

// TODO(editing-dev): The semantics seems wrong when we're in a one-letter block
// with first-letter style, e.g., <div>F</div>, where the letter is laid-out in
// an anonymous first-letter LayoutTextFragment instead of the LayoutObject of
// the text node. It seems weird to return false in this case.
bool HasRenderedNonAnonymousDescendantsWithHeight(
    const LayoutObject* layout_object) {
  // If we're not painting the element then we conceptually don't have children
  // with height. We should treat this as if we didn't have layout objects (i.e.
  // we were display: none).
  if (DisplayLockUtilities::LockedInclusiveAncestorPreventingPaint(
          *layout_object))
    return false;
  if (auto* block_flow = DynamicTo<LayoutBlockFlow>(layout_object)) {
    // Returns false for empty content editable, e.g.
    //  - <div contenteditable></div>
    //  - <div contenteditable><span></span></div>
    // Note: tests[1][2] require this.
    // [1] editing/style/underline.html
    // [2] editing/inserting/return-with-object-element.html
    if (const InlineNodeData* inline_data = block_flow->GetInlineNodeData()) {
      if (inline_data->ItemsData(false).text_content.empty() &&
          block_flow->HasLineIfEmpty()) {
        return false;
      }
    }
  }
  const LayoutObject* stop = layout_object->NextInPreOrderAfterChildren();
  // TODO(editing-dev): Avoid single-character parameter names.
  for (LayoutObject* o = layout_object->SlowFirstChild(); o && o != stop;
       o = o->ChildPaintBlockedByDisplayLock()
               ? o->NextInPreOrderAfterChildren()
               : o->NextInPreOrder()) {
    if (o->ChildPaintBlockedByDisplayLock() || !o->NonPseudoNode()) {
      continue;
    }

    if (const auto* text = DynamicTo<LayoutText>(o);
        text && text->HasNonCollapsedText()) {
      return true;
    } else if (const auto* box = DynamicTo<LayoutBox>(o);
               box && box->LogicalHeight()) {
      return true;
    } else if (const auto* inline_object = DynamicTo<LayoutInline>(o);
               inline_object && IsEmptyInline(*inline_object) &&
               !inline_object->PhysicalLinesBoundingBox().IsEmpty()) {
      return true;
    }
  }
  return false;
}

PositionWithAffinity PositionForContentsPointRespectingEditingBoundary(
    const gfx::Point& contents_point,
    LocalFrame* frame) {
  HitTestRequest request = HitTestRequest::kMove | HitTestRequest::kReadOnly |
                           HitTestRequest::kActive |
                           HitTestRequest::kIgnoreClipping;
  HitTestLocation location(contents_point);
  HitTestResult result(request, location);
  frame->GetDocument()->GetLayoutView()->HitTest(location, result);

  if (result.InnerNode()) {
    return PositionRespectingEditingBoundary(
        frame->Selection().ComputeVisibleSelectionInDOMTree().Start(), result);
  }
  return PositionWithAffinity();
}

// TODO(yosin): We should use |AssociatedLayoutObjectOf()| in "visible_units.cc"
// where it takes |LayoutObject| from |Position|.
int CaretMinOffset(const Node* node) {
  const LayoutObject* layout_object = AssociatedLayoutObjectOf(*node, 0);
  if (const LayoutText* layout_text = DynamicTo<LayoutText>(layout_object))
    return layout_text->CaretMinOffset();
  return 0;
}

int CaretMaxOffset(const Node* n) {
  return EditingStrategy::CaretMaxOffset(*n);
}

template <typename Strategy>
static bool InRenderedText(const PositionTemplate<Strategy>& position) {
  Node* const anchor_node = position.AnchorNode();
  if (!anchor_node || !anchor_node->IsTextNode())
    return false;

  const int offset_in_node = position.ComputeEditingOffset();
  const LayoutObject* layout_object =
      AssociatedLayoutObjectOf(*anchor_node, offset_in_node);
  if (!layout_object)
    return false;

  const auto* text_layout_object = To<LayoutText>(layout_object);
  const int text_offset =
      offset_in_node - text_layout_object->TextStartOffset();
  if (!text_layout_object->ContainsCaretOffset(text_offset))
    return false;
  // Return false for offsets inside composed characters.
  // TODO(editing-dev): Previous/NextGraphemeBoundaryOf() work on DOM offsets,
  // So they should use |offset_in_node| instead of |text_offset|.
  return text_offset == text_layout_object->CaretMinOffset() ||
         text_offset == NextGraphemeBoundaryOf(*anchor_node,
                                               PreviousGraphemeBoundaryOf(
                                                   *anchor_node, text_offset));
}

bool RendersInDifferentPosition(const Position& position1,
                                const Position& position2) {
  if (position1.IsNull() || position2.IsNull())
    return false;
  const LocalCaretRect& caret_rect1 =
      LocalCaretRectOfPosition(PositionWithAffinity(position1));
  const LocalCaretRect& caret_rect2 =
      LocalCaretRectOfPosition(PositionWithAffinity(position2));
  if (!caret_rect1.layout_object || !caret_rect2.layout_object)
    return caret_rect1.layout_object != caret_rect2.layout_object;
  return LocalToAbsoluteQuadOf(caret_rect1) !=
         LocalToAbsoluteQuadOf(caret_rect2);
}

// TODO(editing-dev): Share code with IsVisuallyEquivalentCandidate if possible.
bool EndsOfNodeAreVisuallyDistinctPositions(const Node* node) {
  if (!node)
    return false;

  LayoutObject* layout_object = node->GetLayoutObject();
  if (!layout_object)
    return false;

  if (!layout_object->IsInline())
    return true;

  // Don't include inline tables.
  if (IsA<HTMLTableElement>(*node))
    return false;

  // A Marquee elements are moving so we should assume their ends are always
  // visibily distinct.
  if (IsA<HTMLMarqueeElement>(*node))
    return true;

  // There is a VisiblePosition inside an empty inline-block container.
  return layout_object->IsAtomicInlineLevel() &&
         CanHaveChildrenForEditing(node) &&
         !To<LayoutBox>(layout_object)->Size().IsEmpty() &&
         !HasRenderedNonAnonymousDescendantsWithHeight(layout_object);
}

template <typename Strategy>
static Node* EnclosingVisualBoundary(Node* node) {
  while (node && !EndsOfNodeAreVisuallyDistinctPositions(node))
    node = Strategy::Parent(*node);

  return node;
}

// upstream() and downstream() want to return positions that are either in a
// text node or at just before a non-text node.  This method checks for that.
template <typename Strategy>
static bool IsStreamer(const PositionIteratorAlgorithm<Strategy>& pos) {
  if (!pos.GetNode())
    return true;

  if (IsAtomicNode(pos.GetNode()))
    return true;

  return pos.AtStartOfNode();
}

template <typename F>
static Position MostBackwardOrForwardCaretPosition(
    const Position& position,
    EditingBoundaryCrossingRule rule,
    SnapToClient client,
    F AlgorithmInFlatTree) {
  Node* position_anchor = position.AnchorNode();
  if (!position_anchor)
    return Position();
  DCHECK(position.IsValidFor(*position.GetDocument())) << position;

  // Find the most backward or forward caret position in the flat tree.
  const Position& candidate = ToPositionInDOMTree(
      AlgorithmInFlatTree(ToPositionInFlatTree(position), rule, client));
  Node* candidate_anchor = candidate.AnchorNode();
  if (!candidate_anchor)
    return position;

  // Fast path for common cases when there is no shadow involved.
  if (!position_anchor->IsInShadowTree() && !IsShadowHost(position_anchor) &&
      !candidate_anchor->IsInShadowTree() && !IsShadowHost(candidate_anchor)) {
    return candidate;
  }

  // Adjust the candidate to avoid crossing shadow boundaries.
  const SelectionInDOMTree& selection =
      SelectionInDOMTree::Builder()
          .SetBaseAndExtent(position, candidate)
          .Build();
  if (selection.IsCaret())
    return candidate;
  const SelectionInDOMTree& shadow_adjusted_selection =
      SelectionAdjuster::AdjustSelectionToAvoidCrossingShadowBoundaries(
          selection);
  const Position& adjusted_candidate = shadow_adjusted_selection.Focus();

  // The adjusted candidate should be between the candidate and the original
  // position. Otherwise, return the original position.
  if (position.CompareTo(candidate) == candidate.CompareTo(adjusted_candidate))
    return position;

  // If we have to adjust the position, the editability may change, so avoid
  // crossing editing boundaries if it's not allowed.
  if (rule == kCannotCrossEditingBoundary &&
      selection != shadow_adjusted_selection) {
    const SelectionInDOMTree& editing_adjusted_selection =
        SelectionAdjuster::AdjustSelectionToAvoidCrossingEditingBoundaries(
            shadow_adjusted_selection);
    return editing_adjusted_selection.Focus();
  }
  return adjusted_candidate;
}

template <typename Strategy>
static PositionTemplate<Strategy> AdjustPositionForBackwardIteration(
    const PositionTemplate<Strategy>& position) {
  DCHECK(!position.IsNull());
  if (!position.IsAfterAnchor())
    return position;
  if (IsUserSelectContain(*position.AnchorNode()))
    return position.ToOffsetInAnchor();
  return PositionTemplate<Strategy>::EditingPositionOf(
      position.AnchorNode(), Strategy::CaretMaxOffset(*position.AnchorNode()));
}

static bool CanHaveCaretPosition(const Node& node) {
  if (!node.IsSVGElement())
    return true;
  if (IsA<SVGTextElement>(node))
    return true;  // See http://crbug.com/891908
  if (IsA<SVGForeignObjectElement>(node))
    return true;  // See http://crbug.com/1348816
  // There is no caret position in non-text svg elements.
  return false;
}

// TODO(yosin): We should make |Most{Back,For}kwardCaretPosition()| to work for
// positions other than |kOffsetInAnchor|. When we convert |position| to
// |kOffsetInAnchor|, following tests are failed:
//  * editing/execCommand/delete-non-editable-range-crash.html
//  * editing/execCommand/keep_typing_style.html
//  * editing/selection/skip-over-contenteditable.html
// See also |AdjustForEditingBoundary()|. It has workaround for before/after
// positions.
template <typename Strategy>
static PositionTemplate<Strategy> MostBackwardCaretPosition(
    const PositionTemplate<Strategy>& position,
    EditingBoundaryCrossingRule rule,
    SnapToClient client) {
  DCHECK(!NeedsLayoutTreeUpdate(position)) << position;
  TRACE_EVENT0("input", "VisibleUnits::mostBackwardCaretPosition");

  Node* const start_node = position.AnchorNode();
  if (!start_node)
    return PositionTemplate<Strategy>();

  // iterate backward from there, looking for a qualified position
  Node* const boundary = EnclosingVisualBoundary<Strategy>(start_node);
  // FIXME: PositionIterator should respect Before and After positions.
  const PositionTemplate<Strategy>& adjusted_position =
      AdjustPositionForBackwardIteration<Strategy>(position);
#if DCHECK_IS_ON()
  // Debug what causes bug 1248744
  if (adjusted_position.IsNull())
    position.ShowTreeForThis();
  DCHECK(adjusted_position.IsNotNull()) << position;
#endif
  PositionIteratorAlgorithm<Strategy> last_visible(adjusted_position);
  Node* last_node;
  // If we're snapping the caret to the edges of an inline element rather than
  // crossing an editing boundary, we want to detect that editable boundary even
  // if it happens between the position's container and anchor nodes.
  if (rule == kCannotCrossEditingBoundary &&
      client == SnapToClient::kLocalCaretRect) {
    last_node = position.ComputeContainerNode();
  } else {
    last_node = start_node;
  }
  const bool start_editable = IsEditable(*last_node);
  bool boundary_crossed = false;
  std::optional<WritingMode> writing_mode;
  for (PositionIteratorAlgorithm<Strategy> current_pos = last_visible;
       !current_pos.AtStart(); current_pos.Decrement()) {
    Node* current_node = current_pos.GetNode();
    DCHECK(current_node);
    // Don't check for an editability change if we haven't moved to a different
    // node, to avoid the expense of computing IsEditable().
    if (current_node != last_node) {
      // Don't change editability.
      const bool current_editable = IsEditable(*current_node);
      if (start_editable != current_editable) {
        if (rule == kCannotCrossEditingBoundary &&
            client != SnapToClient::kLocalCaretRect)
          break;
        boundary_crossed = true;
      }
      last_node = current_node;
    }

    if (!CanHaveCaretPosition(*current_node)) {
      if (boundary_crossed && rule == kCannotCrossEditingBoundary)
        break;
      continue;
    }

    // If we've moved to a position that is visually distinct, return the last
    // saved position. There is code below that terminates early if we're
    // *about* to move to a visually distinct position.
    if (EndsOfNodeAreVisuallyDistinctPositions(current_node) &&
        current_node != boundary)
      return last_visible.DeprecatedComputePosition();

    // skip position in non-laid out or invisible node
    const LayoutObject* const layout_object = AssociatedLayoutObjectOf(
        *current_node,
        IsA<Text>(current_node) ? current_pos.OffsetInTextNode() : 0,
        LayoutObjectSide::kFirstLetterIfOnBoundary);
    if (!layout_object ||
        layout_object->Style()->Visibility() != EVisibility::kVisible) {
      if (boundary_crossed && rule == kCannotCrossEditingBoundary)
        break;
      continue;
    }

    if (DisplayLockUtilities::LockedAncestorPreventingPaint(*layout_object)) {
      if (boundary_crossed && rule == kCannotCrossEditingBoundary)
        break;
      continue;
    }

    if (!writing_mode.has_value()) {
      writing_mode.emplace(layout_object->Style()->GetWritingMode());
    } else if (*writing_mode != layout_object->Style()->GetWritingMode()) {
      return last_visible.ComputePosition();
    }

    if (boundary_crossed) {
      if (rule == kCannotCrossEditingBoundary) {
        if (current_node == start_node) {
          DCHECK(position.IsBeforeAnchor() || position.IsAfterAnchor());
          return position;
        }
        return PositionTemplate<Strategy>::AfterNode(*current_node);
      }
      if (rule == k
"""


```