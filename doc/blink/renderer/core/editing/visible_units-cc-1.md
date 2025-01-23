Response:

### 提示词
```
这是目录为blink/renderer/core/editing/visible_units.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
CanCrossEditingBoundary) {
        last_visible = current_pos;
        break;
      }
    }

    // track last visible streamer position
    if (IsStreamer<Strategy>(current_pos))
      last_visible = current_pos;

    // Don't move past a position that is visually distinct.  We could rely on
    // code above to terminate and return lastVisible on the next iteration, but
    // we terminate early to avoid doing a nodeIndex() call.
    if (EndsOfNodeAreVisuallyDistinctPositions(current_node) &&
        current_pos.AtStartOfNode())
      return last_visible.DeprecatedComputePosition();

    // Return position after tables and nodes which have content that can be
    // ignored.
    if (EditingIgnoresContent(*current_node) ||
        IsDisplayInsideTable(current_node)) {
      if (current_pos.AtEndOfNode())
        return PositionTemplate<Strategy>::AfterNode(*current_node);
      continue;
    }

    // return current position if it is in laid out text
    if (!layout_object->IsText())
      continue;
    const auto* const text_layout_object = To<LayoutText>(layout_object);
    if (!text_layout_object->HasNonCollapsedText())
      continue;
    const unsigned text_start_offset = text_layout_object->TextStartOffset();
    if (current_node != start_node) {
      // This assertion fires in web tests in the case-transform.html test
      // because of a mix-up between offsets in the text in the DOM tree with
      // text in the layout tree which can have a different length due to case
      // transformation.
      // Until we resolve that, disable this so we can run the web tests!
      // DCHECK_GE(currentOffset, layoutObject->caretMaxOffset());
      return PositionTemplate<Strategy>(
          current_node,
          text_layout_object->CaretMaxOffset() + text_start_offset);
    }

    DCHECK_GE(current_pos.OffsetInTextNode(),
              static_cast<int>(text_layout_object->TextStartOffset()));
    if (text_layout_object->IsAfterNonCollapsedCharacter(
            current_pos.OffsetInTextNode() -
            text_layout_object->TextStartOffset()))
      return current_pos.ComputePosition();
  }
  return last_visible.DeprecatedComputePosition();
}

Position MostBackwardCaretPosition(const Position& position,
                                   EditingBoundaryCrossingRule rule,
                                   SnapToClient client) {
  return MostBackwardOrForwardCaretPosition(
      position, rule, client,
      MostBackwardCaretPosition<EditingInFlatTreeStrategy>);
}

PositionInFlatTree MostBackwardCaretPosition(const PositionInFlatTree& position,
                                             EditingBoundaryCrossingRule rule,
                                             SnapToClient client) {
  return MostBackwardCaretPosition<EditingInFlatTreeStrategy>(position, rule,
                                                              client);
}

namespace {
bool HasInvisibleFirstLetter(const Node* node) {
  if (!node || !node->IsTextNode())
    return false;
  const auto* remaining_text =
      DynamicTo<LayoutTextFragment>(node->GetLayoutObject());
  if (!remaining_text || !remaining_text->IsRemainingTextLayoutObject())
    return false;
  const auto* first_letter =
      DynamicTo<LayoutTextFragment>(AssociatedLayoutObjectOf(*node, 0));
  if (!first_letter || first_letter == remaining_text)
    return false;
  return first_letter->StyleRef().Visibility() != EVisibility::kVisible ||
         DisplayLockUtilities::LockedAncestorPreventingPaint(*first_letter);
}
}  // namespace

template <typename Strategy>
PositionTemplate<Strategy> MostForwardCaretPosition(
    const PositionTemplate<Strategy>& position,
    EditingBoundaryCrossingRule rule,
    SnapToClient client) {
  DCHECK(!NeedsLayoutTreeUpdate(position)) << position;
  TRACE_EVENT0("input", "VisibleUnits::mostForwardCaretPosition");

  Node* const start_node = position.AnchorNode();
  if (!start_node)
    return PositionTemplate<Strategy>();

  // iterate forward from there, looking for a qualified position
  Node* const boundary = EnclosingVisualBoundary<Strategy>(start_node);
  // FIXME: PositionIterator should respect Before and After positions.
  PositionIteratorAlgorithm<Strategy> last_visible(
      position.IsAfterAnchor()
          ? PositionTemplate<Strategy>::EditingPositionOf(
                position.AnchorNode(),
                Strategy::CaretMaxOffset(*position.AnchorNode()))
          : position);
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
       !current_pos.AtEnd(); current_pos.Increment()) {
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

    // stop before going above the body, up into the head
    // return the last visible streamer position
    if (IsA<HTMLBodyElement>(*current_node) && current_pos.AtEndOfNode())
      break;

    if (!CanHaveCaretPosition(*current_node)) {
      if (boundary_crossed && rule == kCannotCrossEditingBoundary)
        break;
      continue;
    }

    // Do not move to a visually distinct position.
    if (EndsOfNodeAreVisuallyDistinctPositions(current_node) &&
        current_node != boundary)
      return last_visible.DeprecatedComputePosition();
    // Do not move past a visually disinct position.
    // Note: The first position after the last in a node whose ends are visually
    // distinct positions will be [boundary->parentNode(),
    // originalBlock->nodeIndex() + 1].
    if (boundary && Strategy::Parent(*boundary) == current_node)
      return last_visible.DeprecatedComputePosition();

    // skip position in non-laid out or invisible node
    const LayoutObject* const layout_object = AssociatedLayoutObjectOf(
        *current_node,
        IsA<Text>(current_node) ? current_pos.OffsetInTextNode() : 0);
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
        return PositionTemplate<Strategy>::BeforeNode(*current_node);
      }
      if (rule == kCanCrossEditingBoundary)
        return current_pos.DeprecatedComputePosition();
    }

    // track last visible streamer position
    if (IsStreamer<Strategy>(current_pos))
      last_visible = current_pos;

    // Return position before tables and nodes which have content that can be
    // ignored.
    if (EditingIgnoresContent(*current_node) ||
        IsDisplayInsideTable(current_node)) {
      if (current_pos.AtStartOfNode())
        return PositionTemplate<Strategy>::EditingPositionOf(current_node, 0);
      continue;
    }

    // return current position if it is in laid out text
    if (!layout_object->IsText())
      continue;
    const auto* const text_layout_object = To<LayoutText>(layout_object);
    if (!text_layout_object->HasNonCollapsedText())
      continue;
    const unsigned text_start_offset = text_layout_object->TextStartOffset();
    if (current_node != start_node) {
      DCHECK(current_pos.AtStartOfNode() ||
             HasInvisibleFirstLetter(current_node));
      return PositionTemplate<Strategy>(
          current_node,
          text_layout_object->CaretMinOffset() + text_start_offset);
    }

    DCHECK_GE(current_pos.OffsetInTextNode(),
              static_cast<int>(text_layout_object->TextStartOffset()));
    if (text_layout_object->IsBeforeNonCollapsedCharacter(
            current_pos.OffsetInTextNode() -
            text_layout_object->TextStartOffset()))
      return current_pos.ComputePosition();
  }
  return last_visible.DeprecatedComputePosition();
}

Position MostForwardCaretPosition(const Position& position,
                                  EditingBoundaryCrossingRule rule,
                                  SnapToClient client) {
  return MostBackwardOrForwardCaretPosition(
      position, rule, client,
      MostForwardCaretPosition<EditingInFlatTreeStrategy>);
}

PositionInFlatTree MostForwardCaretPosition(const PositionInFlatTree& position,
                                            EditingBoundaryCrossingRule rule,
                                            SnapToClient client) {
  return MostForwardCaretPosition<EditingInFlatTreeStrategy>(position, rule,
                                                             client);
}

// Returns true if the visually equivalent positions around have different
// editability. A position is considered at editing boundary if one of the
// following is true:
// 1. It is the first position in the node and the next visually equivalent
//    position is non editable.
// 2. It is the last position in the node and the previous visually equivalent
//    position is non editable.
// 3. It is an editable position and both the next and previous visually
//    equivalent positions are both non editable.
template <typename Strategy>
static bool AtEditingBoundary(const PositionTemplate<Strategy> positions) {
  PositionTemplate<Strategy> next_position =
      MostForwardCaretPosition(positions, kCanCrossEditingBoundary);
  if (positions.AtFirstEditingPositionForNode() && next_position.IsNotNull() &&
      !IsEditable(*next_position.AnchorNode()))
    return true;

  PositionTemplate<Strategy> prev_position =
      MostBackwardCaretPosition(positions, kCanCrossEditingBoundary);
  if (positions.AtLastEditingPositionForNode() && prev_position.IsNotNull() &&
      !IsEditable(*prev_position.AnchorNode()))
    return true;

  return next_position.IsNotNull() &&
         !IsEditable(*next_position.AnchorNode()) &&
         prev_position.IsNotNull() && !IsEditable(*prev_position.AnchorNode());
}

template <typename Strategy>
static bool IsVisuallyEquivalentCandidateAlgorithm(
    const PositionTemplate<Strategy>& position) {
  Node* const anchor_node = position.AnchorNode();
  if (!anchor_node)
    return false;

  LayoutObject* layout_object = anchor_node->GetLayoutObject();
  if (!layout_object)
    return false;

  if (layout_object->Style()->Visibility() != EVisibility::kVisible) {
    return false;
  }

  if (DisplayLockUtilities::LockedAncestorPreventingPaint(*layout_object))
    return false;

  if (layout_object->IsBR()) {
    // TODO(leviw) The condition should be
    // anchor_type_ == PositionAnchorType::kBeforeAnchor, but for now we
    // still need to support legacy positions.
    if (position.IsAfterAnchor())
      return false;
    if (position.ComputeEditingOffset())
      return false;
    const Node* parent = Strategy::Parent(*anchor_node);
    return parent->GetLayoutObject() &&
           parent->GetLayoutObject()->IsSelectable();
  }

  if (layout_object->IsText())
    return layout_object->IsSelectable() && InRenderedText(position);

  if (layout_object->IsSVG()) {
    // We don't consider SVG elements are contenteditable except for
    // associated |layoutObject| returns |isText()| true,
    // e.g. |LayoutSVGInlineText|.
    return false;
  }

  if (IsDisplayInsideTable(anchor_node) ||
      EditingIgnoresContent(*anchor_node)) {
    if (!position.AtFirstEditingPositionForNode() &&
        !position.AtLastEditingPositionForNode())
      return false;
    const Node* parent = Strategy::Parent(*anchor_node);
    return parent->GetLayoutObject() &&
           parent->GetLayoutObject()->IsSelectable();
  }

  if (anchor_node->GetDocument().documentElement() == anchor_node ||
      anchor_node->IsDocumentNode())
    return false;

  if (!layout_object->IsSelectable())
    return false;

  if (layout_object->IsLayoutBlockFlow() || layout_object->IsFlexibleBox() ||
      layout_object->IsLayoutGrid()) {
    if (To<LayoutBlock>(layout_object)->LogicalHeight() ||
        anchor_node->GetDocument().body() == anchor_node) {
      if (!HasRenderedNonAnonymousDescendantsWithHeight(layout_object))
        return position.AtFirstEditingPositionForNode();
      return IsEditable(*anchor_node) && AtEditingBoundary(position);
    }
  } else {
    return IsEditable(*anchor_node) && AtEditingBoundary(position);
  }

  return false;
}

bool IsVisuallyEquivalentCandidate(const Position& position) {
  return IsVisuallyEquivalentCandidateAlgorithm<EditingStrategy>(position);
}

bool IsVisuallyEquivalentCandidate(const PositionInFlatTree& position) {
  return IsVisuallyEquivalentCandidateAlgorithm<EditingInFlatTreeStrategy>(
      position);
}

template <typename Strategy>
static PositionTemplate<Strategy> SkipToEndOfEditingBoundary(
    const PositionTemplate<Strategy>& pos,
    const PositionTemplate<Strategy>& anchor) {
  if (pos.IsNull())
    return pos;

  ContainerNode* highest_root = HighestEditableRoot(anchor);
  ContainerNode* highest_root_of_pos = HighestEditableRoot(pos);

  // Return |pos| itself if the two are from the very same editable region,
  // or both are non-editable.
  if (highest_root_of_pos == highest_root)
    return pos;

  // If this is not editable but |pos| has an editable root, skip to the end
  if (!highest_root && highest_root_of_pos) {
    return PositionTemplate<Strategy>(highest_root_of_pos,
                                      PositionAnchorType::kAfterAnchor)
        .ParentAnchoredEquivalent();
  }

  // That must mean that |pos| is not editable. Return the next position after
  // |pos| that is in the same editable region as this position
  DCHECK(highest_root);
  return FirstEditablePositionAfterPositionInRoot(pos, *highest_root);
}

template <typename Strategy>
static UChar32 CharacterAfterAlgorithm(
    const VisiblePositionTemplate<Strategy>& visible_position) {
  DCHECK(visible_position.IsValid()) << visible_position;
  // We canonicalize to the first of two equivalent candidates, but the second
  // of the two candidates is the one that will be inside the text node
  // containing the character after this visible position.
  const PositionTemplate<Strategy> pos =
      MostForwardCaretPosition(visible_position.DeepEquivalent());
  if (!pos.IsOffsetInAnchor())
    return 0;
  auto* text_node = DynamicTo<Text>(pos.ComputeContainerNode());
  if (!text_node)
    return 0;
  unsigned offset = static_cast<unsigned>(pos.OffsetInContainerNode());
  unsigned length = text_node->length();
  if (offset >= length)
    return 0;

  return text_node->data().CharacterStartingAt(offset);
}

UChar32 CharacterAfter(const VisiblePosition& visible_position) {
  return CharacterAfterAlgorithm<EditingStrategy>(visible_position);
}

UChar32 CharacterAfter(const VisiblePositionInFlatTree& visible_position) {
  return CharacterAfterAlgorithm<EditingInFlatTreeStrategy>(visible_position);
}

template <typename Strategy>
static UChar32 CharacterBeforeAlgorithm(
    const VisiblePositionTemplate<Strategy>& visible_position) {
  DCHECK(visible_position.IsValid()) << visible_position;
  return CharacterAfter(PreviousPositionOf(visible_position));
}

UChar32 CharacterBefore(const VisiblePosition& visible_position) {
  return CharacterBeforeAlgorithm<EditingStrategy>(visible_position);
}

UChar32 CharacterBefore(const VisiblePositionInFlatTree& visible_position) {
  return CharacterBeforeAlgorithm<EditingInFlatTreeStrategy>(visible_position);
}

template <typename Strategy>
static VisiblePositionTemplate<Strategy> NextPositionOfAlgorithm(
    const PositionWithAffinityTemplate<Strategy>& position,
    EditingBoundaryCrossingRule rule) {
  const VisiblePositionTemplate<Strategy> next = CreateVisiblePosition(
      NextVisuallyDistinctCandidate(position.GetPosition()),
      position.Affinity());

  switch (rule) {
    case kCanCrossEditingBoundary:
      return next;
    case kCannotCrossEditingBoundary:
      return CreateVisiblePosition(
          AdjustForwardPositionToAvoidCrossingEditingBoundaries(
              next.ToPositionWithAffinity(), position.GetPosition()));
    case kCanSkipOverEditingBoundary:
      return CreateVisiblePosition(SkipToEndOfEditingBoundary(
          next.DeepEquivalent(), position.GetPosition()));
  }
  NOTREACHED();
}

VisiblePosition NextPositionOf(const Position& position,
                               EditingBoundaryCrossingRule rule) {
  DCHECK(position.IsValidFor(*position.GetDocument())) << position;
  return NextPositionOfAlgorithm<EditingStrategy>(
      PositionWithAffinityTemplate<EditingStrategy>(position), rule);
}

VisiblePosition NextPositionOf(const VisiblePosition& visible_position,
                               EditingBoundaryCrossingRule rule) {
  DCHECK(visible_position.IsValid()) << visible_position;
  return NextPositionOfAlgorithm<EditingStrategy>(
      visible_position.ToPositionWithAffinity(), rule);
}

VisiblePositionInFlatTree NextPositionOf(
    const VisiblePositionInFlatTree& visible_position,
    EditingBoundaryCrossingRule rule) {
  DCHECK(visible_position.IsValid()) << visible_position;
  return NextPositionOfAlgorithm<EditingInFlatTreeStrategy>(
      visible_position.ToPositionWithAffinity(), rule);
}

template <typename Strategy>
static PositionTemplate<Strategy> SkipToStartOfEditingBoundary(
    const PositionTemplate<Strategy>& pos,
    const PositionTemplate<Strategy>& anchor) {
  if (pos.IsNull())
    return pos;

  ContainerNode* highest_root = HighestEditableRoot(anchor);
  ContainerNode* highest_root_of_pos = HighestEditableRoot(pos);

  // Return |pos| itself if the two are from the very same editable region, or
  // both are non-editable.
  if (highest_root_of_pos == highest_root)
    return pos;

  // If this is not editable but |pos| has an editable root, skip to the start
  if (!highest_root && highest_root_of_pos) {
    return PreviousVisuallyDistinctCandidate(
        PositionTemplate<Strategy>(highest_root_of_pos,
                                   PositionAnchorType::kBeforeAnchor)
            .ParentAnchoredEquivalent());
  }

  // That must mean that |pos| is not editable. Return the last position
  // before |pos| that is in the same editable region as this position
  DCHECK(highest_root);
  return LastEditablePositionBeforePositionInRoot(pos, *highest_root);
}

template <typename Strategy>
static VisiblePositionTemplate<Strategy> PreviousPositionOfAlgorithm(
    const PositionTemplate<Strategy>& position,
    EditingBoundaryCrossingRule rule) {
  const PositionTemplate<Strategy> prev_position =
      PreviousVisuallyDistinctCandidate(position);

  // return null visible position if there is no previous visible position
  if (prev_position.AtStartOfTree())
    return VisiblePositionTemplate<Strategy>();

  // we should always be able to make the affinity |TextAffinity::Downstream|,
  // because going previous from an |TextAffinity::Upstream| position can
  // never yield another |TextAffinity::Upstream position| (unless line wrap
  // length is 0!).
  const VisiblePositionTemplate<Strategy> prev =
      CreateVisiblePosition(prev_position);
  if (prev.DeepEquivalent() == position)
    return VisiblePositionTemplate<Strategy>();

  switch (rule) {
    case kCanCrossEditingBoundary:
      return prev;
    case kCannotCrossEditingBoundary:
      return CreateVisiblePosition(
          AdjustBackwardPositionToAvoidCrossingEditingBoundaries(
              prev.ToPositionWithAffinity(), position));
    case kCanSkipOverEditingBoundary:
      return CreateVisiblePosition(
          SkipToStartOfEditingBoundary(prev.DeepEquivalent(), position));
  }

  NOTREACHED();
}

VisiblePosition PreviousPositionOf(const VisiblePosition& visible_position,
                                   EditingBoundaryCrossingRule rule) {
  DCHECK(visible_position.IsValid()) << visible_position;
  return PreviousPositionOfAlgorithm<EditingStrategy>(
      visible_position.DeepEquivalent(), rule);
}

VisiblePositionInFlatTree PreviousPositionOf(
    const VisiblePositionInFlatTree& visible_position,
    EditingBoundaryCrossingRule rule) {
  DCHECK(visible_position.IsValid()) << visible_position;
  return PreviousPositionOfAlgorithm<EditingInFlatTreeStrategy>(
      visible_position.DeepEquivalent(), rule);
}

template <typename Strategy>
static EphemeralRangeTemplate<Strategy> MakeSearchRange(
    const PositionTemplate<Strategy>& pos) {
  Node* node = pos.ComputeContainerNode();
  if (!node)
    return EphemeralRangeTemplate<Strategy>();
  Document& document = node->GetDocument();
  if (!document.documentElement())
    return EphemeralRangeTemplate<Strategy>();
  Element* boundary = EnclosingBlockFlowElement(*node);
  if (!boundary)
    return EphemeralRangeTemplate<Strategy>();

  return EphemeralRangeTemplate<Strategy>(
      pos, PositionTemplate<Strategy>::LastPositionInNode(*boundary));
}

template <typename Strategy>
static PositionTemplate<Strategy> SkipWhitespaceAlgorithm(
    const PositionTemplate<Strategy>& position) {
  const EphemeralRangeTemplate<Strategy>& search_range =
      MakeSearchRange(position);
  if (search_range.IsNull())
    return position;

  CharacterIteratorAlgorithm<Strategy> char_it(
      search_range.StartPosition(), search_range.EndPosition(),
      TextIteratorBehavior::Builder()
          .SetEmitsCharactersBetweenAllVisiblePositions(true)
          .Build());
  PositionTemplate<Strategy> runner = position;
  // TODO(editing-dev): We should consider U+20E3, COMBINING ENCLOSING KEYCAP.
  // When whitespace character followed by U+20E3, we should not consider
  // it as trailing white space.
  for (; char_it.length(); char_it.Advance(1)) {
    UChar c = char_it.CharacterAt(0);
    if ((!IsSpaceOrNewline(c) && c != kNoBreakSpaceCharacter) || c == '\n')
      return runner;
    runner = char_it.EndPosition();
  }
  return runner;
}

Position SkipWhitespace(const Position& position) {
  return SkipWhitespaceAlgorithm(position);
}

PositionInFlatTree SkipWhitespace(const PositionInFlatTree& position) {
  return SkipWhitespaceAlgorithm(position);
}

template <typename Strategy>
static Vector<gfx::QuadF> ComputeTextBounds(
    const EphemeralRangeTemplate<Strategy>& range) {
  const PositionTemplate<Strategy>& start_position = range.StartPosition();
  const PositionTemplate<Strategy>& end_position = range.EndPosition();
  Node* const start_container = start_position.ComputeContainerNode();
  DCHECK(start_container);
  Node* const end_container = end_position.ComputeContainerNode();
  DCHECK(end_container);
  DCHECK(!start_container->GetDocument().NeedsLayoutTreeUpdate());

  Vector<gfx::QuadF> result;
  for (const Node& node : range.Nodes()) {
    LayoutObject* const layout_object = node.GetLayoutObject();
    if (!layout_object || !layout_object->IsText())
      continue;
    const auto* layout_text = To<LayoutText>(layout_object);
    unsigned start_offset =
        node == start_container ? start_position.OffsetInContainerNode() : 0;
    unsigned end_offset = node == end_container
                              ? end_position.OffsetInContainerNode()
                              : std::numeric_limits<unsigned>::max();
    layout_text->AbsoluteQuadsForRange(result, start_offset, end_offset);
  }
  return result;
}

template <typename Strategy>
static gfx::RectF ComputeTextRectTemplate(
    const EphemeralRangeTemplate<Strategy>& range) {
  gfx::RectF result;
  for (auto rect : ComputeTextBounds<Strategy>(range))
    result.Union(rect.BoundingBox());
  return result;
}

gfx::Rect ComputeTextRect(const EphemeralRange& range) {
  return gfx::ToEnclosingRect(ComputeTextRectTemplate(range));
}

gfx::Rect ComputeTextRect(const EphemeralRangeInFlatTree& range) {
  return gfx::ToEnclosingRect(ComputeTextRectTemplate(range));
}

gfx::RectF ComputeTextRectF(const EphemeralRange& range) {
  return ComputeTextRectTemplate(range);
}

gfx::Rect FirstRectForRange(const EphemeralRange& range) {
  DCHECK(!range.GetDocument().NeedsLayoutTreeUpdate());
  DocumentLifecycle::DisallowTransitionScope disallow_transition(
      range.GetDocument().Lifecycle());

  DCHECK(range.IsNotNull());

  const PositionWithAffinity start_position(
      CreateVisiblePosition(range.StartPosition()).DeepEquivalent(),
      TextAffinity::kDownstream);
  gfx::Rect start_caret_rect = AbsoluteCaretBoundsOf(start_position);
  if (start_caret_rect.IsEmpty())
    return gfx::Rect();

  const PositionWithAffinity end_position(
      CreateVisiblePosition(range.EndPosition()).DeepEquivalent(),
      TextAffinity::kUpstream);

  const PositionWithAffinity end_position_in_same_line =
      InSameLine(start_position, end_position) ? end_position
                                               : EndOfLine(start_position);
  gfx::Rect end_caret_rect = AbsoluteCaretBoundsOf(end_position_in_same_line);
  if (end_caret_rect.IsEmpty()) {
    return gfx::Rect();
  }

  // Some tests expect the resultant rectangles don't include caret widths.
  // e.g.
  //  - RenderViewImplTest.GetCompositionCharacterBoundsTest
  //  - LocalFrameTest.CharacterIndexAtPointWithPinchZoom
  if (start_position.AnchorNode()
          ->GetComputedStyleForElementOrLayoutObject()
          ->IsHorizontalWritingMode()) {
    end_caret_rect.set_width(0);
    start_caret_rect.set_width(0);
  } else {
    end_caret_rect.set_height(0);
    start_caret_rect.set_height(0);
  }

  const gfx::Point left_top = {
      std::min(start_caret_rect.x(), end_caret_rect.x()),
      std::min(start_caret_rect.y(), end_caret_rect.y())};
  const int right = std::max(start_caret_rect.right(), end_caret_rect.right());
  const int bottom =
      std::max(start_caret_rect.bottom(), end_caret_rect.bottom());
  return gfx::Rect(left_top, {right - left_top.x(), bottom - left_top.y()});
}

}  // namespace blink
```