Response:

### 提示词
```
这是目录为blink/renderer/core/editing/layout_selection.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
nt(
        SelectionState::kEnd);
  }
}

static NewPaintRangeAndSelectedNodes CalcSelectionRangeAndSetSelectionState(
    const FrameSelection& frame_selection) {
  const SelectionInDOMTree& selection_in_dom =
      frame_selection.GetSelectionInDOMTree();
  if (selection_in_dom.IsNone())
    return {};

  const EphemeralRangeInFlatTree& selection =
      CalcSelectionInFlatTree(frame_selection);
  if (selection.IsCollapsed() || frame_selection.IsHidden())
    return {};

  // Find first/last Node which has a visible LayoutObject while
  // marking SelectionState and collecting invalidation candidate LayoutObjects.
  const Node* start_node = nullptr;
  const Node* end_node = nullptr;
  HeapHashSet<Member<const Node>> selected_objects;
  for (Node& node : selection.Nodes()) {
    LayoutObject* const layout_object = node.GetLayoutObject();
    if (!layout_object || !layout_object->CanBeSelectionLeaf())
      continue;

    if (!start_node) {
      DCHECK(!end_node);
      start_node = end_node = &node;
      continue;
    }

    // In this loop, |end_node| is pointing current last candidate
    // LayoutObject and if it is not start and we find next, we mark the
    // current one as kInside.
    if (end_node != start_node) {
      SetSelectionStateIfNeeded(*end_node, SelectionState::kInside);
      selected_objects.insert(end_node);
    }
    end_node = &node;
  }

  // No valid LayOutObject found.
  if (!start_node) {
    DCHECK(!end_node);
    return {};
  }

  SetSelectionStateForPaint(selection);

  // Compute offset. It has value iff start/end is text.
  const std::optional<unsigned> start_offset = ComputeStartOffset(
      *start_node, selection.StartPosition().ToOffsetInAnchor());
  const std::optional<unsigned> end_offset =
      ComputeEndOffset(*end_node, selection.EndPosition().ToOffsetInAnchor());
  if (start_node == end_node) {
    SetSelectionStateIfNeeded(*start_node, SelectionState::kStartAndEnd);
    selected_objects.insert(start_node);
  } else {
    SetSelectionStateIfNeeded(*start_node, SelectionState::kStart);
    selected_objects.insert(start_node);
    SetSelectionStateIfNeeded(*end_node, SelectionState::kEnd);
    selected_objects.insert(end_node);
  }

  SelectionPaintRange* new_range = MakeGarbageCollected<SelectionPaintRange>(
      *start_node, start_offset, *end_node, end_offset);
  return {ComputeNewPaintRange(*new_range), std::move(selected_objects)};
}

void LayoutSelection::SetHasPendingSelection() {
  has_pending_selection_ = true;
}

void LayoutSelection::Commit() {
  if (!has_pending_selection_)
    return;
  has_pending_selection_ = false;

  DCHECK(!frame_selection_->GetDocument().NeedsLayoutTreeUpdate());
  DCHECK_GE(frame_selection_->GetDocument().Lifecycle().GetState(),
            DocumentLifecycle::kLayoutClean);
  DocumentLifecycle::DisallowTransitionScope disallow_transition(
      frame_selection_->GetDocument().Lifecycle());

  const OldSelectedNodes& old_selected_objects = ResetOldSelectedNodes(
      frame_selection_->GetDocument(), paint_range_->start_offset,
      paint_range_->end_offset);
  const NewPaintRangeAndSelectedNodes& new_range =
      CalcSelectionRangeAndSetSelectionState(*frame_selection_);
  new_range.AssertSanity();
  DCHECK(frame_selection_->GetDocument().GetLayoutView()->GetFrameView());
  SetShouldInvalidateSelection(new_range, old_selected_objects);

  paint_range_ = new_range.paint_range;
}

void LayoutSelection::ContextDestroyed() {
  has_pending_selection_ = false;
  paint_range_->start_node = nullptr;
  paint_range_->start_offset = std::nullopt;
  paint_range_->end_node = nullptr;
  paint_range_->end_offset = std::nullopt;
}

static PhysicalRect SelectionRectForLayoutObject(const LayoutObject* object) {
  if (!object->IsRooted())
    return PhysicalRect();

  if (!object->CanUpdateSelectionOnRootLineBoxes())
    return PhysicalRect();

  return object->AbsoluteSelectionRect();
}

template <typename Visitor>
static void VisitLayoutObjectsOf(const Node& node, Visitor* visitor) {
  LayoutObject* layout_object = node.GetLayoutObject();
  if (!layout_object)
    return;
  if (layout_object->GetSelectionState() == SelectionState::kContain)
    return;
  if (LayoutTextFragment* first_letter = FirstLetterPartFor(layout_object))
    visitor->Visit(first_letter);
  visitor->Visit(layout_object);
}

gfx::Rect LayoutSelection::AbsoluteSelectionBounds() {
  Commit();
  if (paint_range_->IsNull())
    return gfx::Rect();

  // Create a single bounding box rect that encloses the whole selection.
  class SelectionBoundsVisitor {
    STACK_ALLOCATED();

   public:
    void Visit(const Node& node) { VisitLayoutObjectsOf(node, this); }
    void Visit(LayoutObject* layout_object) {
      selected_rect.Unite(SelectionRectForLayoutObject(layout_object));
    }
    PhysicalRect selected_rect;
  } visitor;
  VisitSelectedInclusiveDescendantsOf(frame_selection_->GetDocument(),
                                      &visitor);
  return ToPixelSnappedRect(visitor.selected_rect);
}

void LayoutSelection::InvalidateStyleAndPaintForSelection() {
  if (paint_range_->IsNull())
    return;

  class InvalidatingVisitor {
    STACK_ALLOCATED();

   public:
    void Visit(Node& node) {
      if (!node.GetLayoutObject()) {
        return;
      }

      // Invalidate style to force an update to ::selection pseudo
      // elements so that ::selection::inactive-window style is applied
      // (or removed).
      if (auto* this_element = DynamicTo<Element>(node)) {
        const ComputedStyle* element_style = this_element->GetComputedStyle();
        if (element_style &&
            element_style->HasPseudoElementStyle(kPseudoIdSelection)) {
          node.SetNeedsStyleRecalc(
              kLocalStyleChange,
              StyleChangeReasonForTracing::CreateWithExtraData(
                  style_change_reason::kPseudoClass,
                  style_change_extra_data::g_active));
          this_element->PseudoStateChanged(CSSSelector::kPseudoSelection);
        }
      }

      VisitLayoutObjectsOf(node, this);
    }
    void Visit(LayoutObject* layout_object) {
      layout_object->SetShouldInvalidateSelection();
    }
  } visitor;
  VisitSelectedInclusiveDescendantsOf(frame_selection_->GetDocument(),
                                      &visitor);
}

void LayoutSelection::Trace(Visitor* visitor) const {
  visitor->Trace(frame_selection_);
  visitor->Trace(paint_range_);
}

void PrintSelectionStatus(std::ostream& ostream, const Node& node) {
  ostream << (void*)&node;
  if (node.IsTextNode())
    ostream << "#text";
  else if (const auto* element = DynamicTo<Element>(node))
    ostream << element->tagName().Utf8();
  LayoutObject* layout_object = node.GetLayoutObject();
  if (!layout_object) {
    ostream << " <null LayoutObject>";
    return;
  }
  ostream << ' ' << layout_object->GetSelectionState();
}

#if DCHECK_IS_ON()
std::ostream& operator<<(std::ostream& ostream,
                         const std::optional<unsigned>& offset) {
  if (offset.has_value())
    ostream << offset.value();
  else
    ostream << "<nullopt>";
  return ostream;
}

std::ostream& operator<<(std::ostream& ostream,
                         const SelectionPaintRange& range) {
  ostream << range.start_node << ": " << range.start_offset << ", "
          << range.end_node << ": " << range.end_offset;
  return ostream;
}

std::ostream& operator<<(
    std::ostream& ostream,
    const HeapHashMap<Member<const Node>, SelectionState>& map) {
  ostream << "[";
  const char* comma = "";
  for (const auto& key_value : map) {
    const Node* const node = key_value.key;
    const SelectionState old_state = key_value.value;
    ostream << comma << node << "." << old_state;
    comma = ", ";
  }
  ostream << "]";
  return ostream;
}

std::ostream& operator<<(std::ostream& ostream,
                         const OldSelectedNodes& old_node) {
  ostream << old_node.paint_range << ". " << old_node.selected_map;
  return ostream;
}

void PrintOldSelectedNodes(const OldSelectedNodes& old_node) {
  std::stringstream stream;
  stream << std::endl << old_node;
  LOG(INFO) << stream.str();
}

std::ostream& operator<<(
    std::ostream& ostream,
    const HeapHashSet<Member<const Node>>& selected_objects) {
  ostream << "[";
  const char* comma = "";
  for (const Node* node : selected_objects) {
    ostream << comma;
    PrintSelectionStatus(ostream, *node);
    comma = ", ";
  }
  ostream << "]";
  return ostream;
}

std::ostream& operator<<(std::ostream& ostream,
                         const NewPaintRangeAndSelectedNodes& new_range) {
  ostream << new_range.paint_range << ". " << new_range.selected_objects;
  return ostream;
}

void PrintSelectedNodes(const NewPaintRangeAndSelectedNodes& new_range) {
  std::stringstream stream;
  stream << std::endl << new_range;
  LOG(INFO) << stream.str();
}

void PrintSelectionStateInDocument(const FrameSelection& selection) {
  class PrintVisitor {
    STACK_ALLOCATED();

   public:
    void Visit(const Node& node) { PrintSelectionStatus(stream, node); }
    std::stringstream stream;
  } visitor;
  VisitSelectedInclusiveDescendantsOf(selection.GetDocument(), &visitor);
  LOG(INFO) << std::endl << visitor.stream.str();
}
#endif

}  // namespace blink
```