Response:
The user is asking for a summary of the functionality of the provided C++ code snippet from `ax_node_object.cc`. I need to analyze each function within the snippet and determine its purpose. I should also consider if these functions relate to JavaScript, HTML, or CSS and provide examples if so. Logical reasoning should be explained with input and output examples. Common user or programming errors should be identified and illustrated. I also need to think about how a user's interaction might lead to this code being executed and use that as a debugging clue. Finally, I need to synthesize all of this information into a concise summary.

Here's a breakdown of the functions and their functionalities:

1. **`IsLineBreakingObject()`**: Checks if an object should cause a line break. This relates to CSS (`white-space: pre`).
2. **`IsLoaded()`**: Checks if the document and its resources are fully loaded. This is relevant to JavaScript that might depend on a fully loaded DOM.
3. **`IsMultiSelectable()`**: Determines if an element allows multiple selections. This relates to HTML elements like `<select multiple>` and ARIA attributes.
4. **`IsNativeImage()`**: Checks if an element is a native image element (`<img>`, `<input type="image">`, plugins). This is directly related to HTML.
5. **`IsVisible()`**: Determines if an element is currently visible to the user, considering factors like `display: none`, ancestor visibility, and collapsed `<select>` elements. This heavily involves CSS and HTML structure.
6. **`IsLinked()`**: Checks if an element is a hyperlink with a valid `href`. This is directly related to HTML `<a>` tags.
7. **`IsVisited()`**: Determines if a link has been visited based on its CSS styling. This connects to CSS pseudo-classes like `:visited`.
8. **`IsProgressIndicator()`, `IsSlider()`, `IsSpinButton()`**: Checks if an element has the corresponding ARIA role.
9. **`IsNativeSlider()`, `IsNativeSpinButton()`**: Checks if an element is a native HTML slider or number input.
10. **`IsEmbeddingElement()`**:  Checks if an element is an embedding element (like `<embed>`, `<object>`, `<iframe>`).
11. **`IsClickable()`**: Determines if an element can be clicked, considering event listeners and native clickable elements. This involves JavaScript event handling and HTML element semantics.
12. **`IsFocused()`**: Checks if an element has focus. This is relevant to both JavaScript (focus events) and HTML element interaction.
13. **`IsSelected()`**: Determines if an element is selected, considering ARIA attributes and the selection state of form elements.
14. **`IsSelectedFromFocusSupported()`, `IsSelectedFromFocus()`**:  Deals with implicit selection based on focus in single-select containers.
15. **`IsNotUserSelectable()`**: Checks if the CSS `user-select: none` property is applied.
16. **`IsTabItemSelected()`**:  Determines if a tab item is selected, possibly based on focus within an associated tab panel. This involves ARIA attributes and focus management.
17. **`Restriction()`**: Determines if an element is disabled or read-only, considering both HTML attributes and ARIA attributes.
18. **`IsExpanded()`**: Checks if an element is in an expanded state, considering ARIA attributes, `<details>` elements, and `<select>` elements.
19. **`IsRequired()`**: Checks if a form control is required.
20. **`CanvasHasFallbackContent()`**: Checks if a `<canvas>` element has fallback content.
21. **`HeadingLevel()`**: Determines the heading level of an element (`<h1>` to `<h6>` or ARIA roles).
22. **`HierarchicalLevel()`**: Calculates the hierarchical level of an element within a structure like a list or tree.
23. **`AutoComplete()`**:  Determines the autocomplete behavior of a text field, considering HTML attributes, ARIA attributes, and cached data.
24. **`SerializeMarkerAttributes()`**: Collects information about document markers (like spelling errors) associated with a text node.
25. **`GetListStyle()`**: Determines the visual style of a list item marker based on CSS.
26. **`InPageLinkTarget()`**:  Finds the target element of an in-page link (a link with a fragment identifier).
27. **`EffectiveTarget()`**: Gets the effective browsing context target of a link (considering the `<base>` tag).
28. **`Orientation()`**: Determines the orientation of a component (horizontal or vertical), based on ARIA attributes and the element's role.
29. **`GetChildFigcaption()`**: Finds the `<figcaption>` element that is a direct child of the current element.
30. **`RadioButtonsInGroup()`**:  Finds all radio buttons within the same group as the current radio button.
31. **`FindAllRadioButtonsWithSameName()`**: (Static helper) Finds all radio buttons with the same name.
32. **`GetTextDirection()`**: Gets the text direction (left-to-right or right-to-left) based on CSS.
```cpp
bool AXNodeObject::IsLineBreakingObject() const {
  // only occur if line breaks are preserved and a newline character is present
  // in their collapsed text. Text collapsing removes all whitespace found in
  // the HTML file, but a special style rule could be used to preserve line
  // breaks.
  //
  // The best example is the <pre> element:
  // <pre>Line 1
  // Line 2</pre>
  if (const LayoutText* layout_text = DynamicTo<LayoutText>(layout_object)) {
    const ComputedStyle& style = layout_object->StyleRef();
    if (layout_text->HasNonCollapsedText() && style.ShouldPreserveBreaks() &&
        layout_text->PlainText().find('\n') != WTF::kNotFound) {
      return true;
    }
  }

  // Rely on the ARIA role to figure out if this object is line breaking.
  return AXObject::IsLineBreakingObject();
}

bool AXNodeObject::IsLoaded() const {
  if (!GetDocument())
    return false;

  if (!GetDocument()->IsLoadCompleted())
    return false;

  // Check for a navigation API single-page app navigation in progress.
  if (auto* window = GetDocument()->domWindow()) {
    if (window->navigation()->HasNonDroppedOngoingNavigation())
      return false;
  }

  return true;
}

bool AXNodeObject::IsMultiSelectable() const {
  switch (RoleValue()) {
    case ax::mojom::blink::Role::kGrid:
    case ax::mojom::blink::Role::kTreeGrid:
    case ax::mojom::blink::Role::kTree:
    case ax::mojom::blink::Role::kListBox:
    case ax::mojom::blink::Role::kTabList:
      bool multiselectable;
      if (AriaBooleanAttribute(html_names::kAriaMultiselectableAttr,
                               &multiselectable)) {
        return multiselectable;
      }
      break;
    default:
      break;
  }

  auto* html_select_element = DynamicTo<HTMLSelectElement>(GetNode());
  return html_select_element && html_select_element->IsMultiple();
}

bool AXNodeObject::IsNativeImage() const {
  Node* node = GetNode();
  if (!node)
    return false;

  if (IsA<HTMLImageElement>(*node) || IsA<HTMLPlugInElement>(*node))
    return true;

  if (const auto* input = DynamicTo<HTMLInputElement>(*node))
    return input->FormControlType() == FormControlType::kInputImage;

  return false;
}

bool AXNodeObject::IsVisible() const {
  // Any descendant of a <select size=1> should be considered invisible if
  // the select is collapsed.
  if (RoleValue() == ax::mojom::blink::Role::kMenuListPopup) {
    CHECK(parent_);
    return parent_->IsExpanded() == kExpandedExpanded;
  }

  if (IsRoot()) {
    return true;
  }

  // Anything else inside of a collapsed select is also invisible.
  if (const AXObject* ax_select = ParentObject()->AncestorMenuList()) {
    // If the select is invisible, so is everything inside of it.
    if (!ax_select->IsVisible()) {
      return false;
    }
    // Inside of a collapsed select:
    // - The selected option's subtree is visible.
    // - Everything else is invisible.
    if (ax_select->IsExpanded() == kExpandedCollapsed) {
      if (const AXObject* ax_option = AncestorMenuListOption()) {
        return ax_option->IsSelected() == kSelectedStateTrue;
      }
      return false;
    }
  }

  return AXObject::IsVisible();
}

bool AXNodeObject::IsLinked() const {
  if (!IsLinkable(*this)) {
    return false;
  }

  if (auto* anchor = DynamicTo<HTMLAnchorElementBase>(AnchorElement())) {
    return !anchor->Href().IsEmpty();
  }
  return false;
}

bool AXNodeObject::IsVisited() const {
  return GetLayoutObject() && GetLayoutObject()->Style()->IsLink() &&
         GetLayoutObject()->Style()->InsideLink() ==
             EInsideLink::kInsideVisitedLink;
}

bool AXNodeObject::IsProgressIndicator() const {
  return RoleValue() == ax::mojom::blink::Role::kProgressIndicator;
}

bool AXNodeObject::IsSlider() const {
  return RoleValue() == ax::mojom::blink::Role::kSlider;
}

bool AXNodeObject::IsSpinButton() const {
  return RoleValue() == ax::mojom::blink::Role::kSpinButton;
}

bool AXNodeObject::IsNativeSlider() const {
  if (const auto* input = DynamicTo<HTMLInputElement>(GetNode()))
    return input->FormControlType() == FormControlType::kInputRange;
  return false;
}

bool AXNodeObject::IsNativeSpinButton() const {
  if (const auto* input = DynamicTo<HTMLInputElement>(GetNode()))
    return input->FormControlType() == FormControlType::kInputNumber;
  return false;
}

bool AXNodeObject::IsEmbeddingElement() const {
  return ui::IsEmbeddingElement(native_role_);
}

bool AXNodeObject::IsClickable() const {
  // Determine whether the element is clickable either because there is a
  // mouse button handler or because it has a native element where click
  // performs an action. Disabled nodes are never considered clickable.
  // Note: we can't call |node->WillRespondToMouseClickEvents()| because that
  // triggers a style recalc and can delete this.

  // Treat mouse button listeners on the |window|, |document| as if they're on
  // the |documentElement|.
  if (GetNode() == GetDocument()->documentElement()) {
    return GetNode()->HasAnyEventListeners(
               event_util::MouseButtonEventTypes()) ||
           GetDocument()->HasAnyEventListeners(
               event_util::MouseButtonEventTypes()) ||
           GetDocument()->domWindow()->HasAnyEventListeners(
               event_util::MouseButtonEventTypes());
  }

  // Look for mouse listeners only on element nodes, e.g. skip text nodes.
  const Element* element = GetElement();
  if (!element)
    return false;

  if (IsDisabled())
    return false;

  if (element->HasAnyEventListeners(event_util::MouseButtonEventTypes()))
    return true;

  if (HasContentEditableAttributeSet())
    return true;

  // Certain user-agent shadow DOM elements are expected to be clickable but
  // they do not have event listeners attached or a clickable native role. We
  // whitelist them here.
  if (element->ShadowPseudoId() ==
      shadow_element_names::kPseudoCalendarPickerIndicator) {
    return true;
  }

  // Only use native roles. For ARIA elements, require a click listener.
  return ui::IsClickable(native_role_);
}

bool AXNodeObject::IsFocused() const {
  if (!GetDocument())
    return false;

  // A web area is represented by the Document node in the DOM tree, which isn't
  // focusable. Check instead if the frame's selection controller is focused.
  if (IsWebArea() &&
      GetDocument()->GetFrame()->Selection().FrameIsFocusedAndActive()) {
    return true;
  }

  Element* focused_element = GetDocument()->FocusedElement();
  return focused_element && focused_element == GetElement();
}

AccessibilitySelectedState AXNodeObject::IsSelected() const {
  if (!GetNode() || !IsSubWidget()) {
    return kSelectedStateUndefined;
  }

  // The aria-selected attribute overrides automatic behaviors.
  bool is_selected;
  if (AriaBooleanAttribute(html_names::kAriaSelectedAttr, &is_selected)) {
    return is_selected ? kSelectedStateTrue : kSelectedStateFalse;
  }

  // The selection should only follow the focus when the aria-selected attribute
  // is marked as required or implied for this element in the ARIA specs.
  // If this object can't follow the focus, then we can't say that it's selected
  // nor that it's not.
  if (!ui::IsSelectRequiredOrImplicit(RoleValue()))
    return kSelectedStateUndefined;

  if (auto* option_element = DynamicTo<HTMLOptionElement>(GetNode())) {
    if (!CanSetSelectedAttribute()) {
      return kSelectedStateUndefined;
    }
    return (option_element->Selected()) ? kSelectedStateTrue
                                        : kSelectedStateFalse;
  }
  // Selection follows focus, but ONLY in single selection containers, and only
  // if aria-selected was not present to override.
  return IsSelectedFromFocus() ? kSelectedStateTrue : kSelectedStateFalse;
}

bool AXNodeObject::IsSelectedFromFocusSupported() const {
  // The selection should only follow the focus when the aria-selected attribute
  // is marked as required or implied for this element in the ARIA specs.
  // If this object can't follow the focus, then we can't say that it's selected
  // nor that it's not.
  // TODO(crbug.com/1143483): Consider allowing more roles.
  if (!ui::IsSelectRequiredOrImplicit(RoleValue()))
    return false;

  // Selection follows focus only when in a single selection container.
  const AXObject* container = ContainerWidget();
  if (!container || container->IsMultiSelectable()) {
    return false;
  }

  // Certain properties inside the container widget mean that implicit selection
  // must be turned off.
  if (!AXObjectCache().IsImplicitSelectionAllowed(container)) {
    return false;
  }

  return true;
}

// In single selection containers, selection follows focus unless aria_selected
// is set to false. This is only valid for a subset of elements.
bool AXNodeObject::IsSelectedFromFocus() const {
  // A tab item can also be selected if it is associated to a focused tabpanel
  // via the aria-labelledby attribute.
  if (IsTabItem() && IsSelectedFromFocusSupported() && IsTabItemSelected()) {
    return true;
  }

  // If this object is not accessibility focused, then it is not selected from
  // focus.
  AXObject* focused_object = AXObjectCache().FocusedObject();
  if (focused_object != this &&
      (!focused_object || focused_object->ActiveDescendant() != this))
    return false;

  return IsSelectedFromFocusSupported();
}

// Returns true if the object is marked user-select:none
bool AXNodeObject::IsNotUserSelectable() const {
  if (!GetLayoutObject()) {
    return false;
  }

  if (IsA<PseudoElement>(GetClosestElement())) {
    return true;
  }

  const ComputedStyle* style = GetLayoutObject()->Style();
  if (!style) {
    return false;
  }

  return (style->UsedUserSelect() == EUserSelect::kNone);
}

bool AXNodeObject::IsTabItemSelected() const {
  if (!IsTabItem() || !GetLayoutObject())
    return false;

  Node* node = GetNode();
  if (!node || !node->IsElementNode())
    return false;

  // The ARIA spec says a tab item can also be selected if it is aria-labeled by
  // a tabpanel that has keyboard focus inside of it, or if a tabpanel in its
  // aria-controls list has KB focus inside of it.
  AXObject* focused_element = AXObjectCache().FocusedObject();
  if (!focused_element)
    return false;

  DCHECK(GetElement());
  const HeapVector<Member<Element>>* elements =
      AXObject::ElementsFromAttributeOrInternals(GetElement(),
                                                 html_names::kAriaControlsAttr);
  if (!elements) {
    return false;
  }

  for (const auto& element : *elements) {
    AXObject* tab_panel = AXObjectCache().Get(element);

    // A tab item should only control tab panels.
    if (!tab_panel ||
        tab_panel->RoleValue() != ax::mojom::blink::Role::kTabPanel) {
      continue;
    }

    AXObject* check_focus_element = focused_element;
    // Check if the focused element is a descendant of the element controlled by
    // the tab item.
    while (check_focus_element) {
      if (tab_panel == check_focus_element)
        return true;
      check_focus_element = check_focus_element->ParentObject();
    }
  }

  return false;
}

AXRestriction AXNodeObject::Restriction() const {
  Element* elem = GetElement();
  if (!elem)
    return kRestrictionNone;

  // An <optgroup> is not exposed directly in the AX tree.
  if (IsA<HTMLOptGroupElement>(elem))
    return kRestrictionNone;

  // According to ARIA, all elements of the base markup can be disabled.
  // According to CORE-AAM, any focusable descendant of aria-disabled
  // ancestor is also disabled.
  if (IsDisabled())
    return kRestrictionDisabled;

  // Only editable fields can be marked @readonly (unlike @aria-readonly).
  auto* text_area_element = DynamicTo<HTMLTextAreaElement>(*elem);
  if (text_area_element && text_area_element->IsReadOnly())
    return kRestrictionReadOnly;
  if (const auto* input = DynamicTo<HTMLInputElement>(*elem)) {
    if (input->IsTextField() && input->IsReadOnly())
      return kRestrictionReadOnly;
  }

  // Check aria-readonly if supported by current role.
  bool is_read_only;
  if (SupportsARIAReadOnly() &&
      AriaBooleanAttribute(html_names::kAriaReadonlyAttr, &is_read_only)) {
    // ARIA overrides other readonly state markup.
    return is_read_only ? kRestrictionReadOnly : kRestrictionNone;
  }

  // If a grid cell does not have it's own ARIA input restriction,
  // fall back on parent grid's readonly state.
  // See ARIA specification regarding grid/treegrid and readonly.
  if (IsTableCellLikeRole()) {
    AXObject* row = ParentObjectUnignored();
    if (row && row->IsTableRowLikeRole()) {
      AXObject* table = row->ParentObjectUnignored();
      if (table && table->IsTableLikeRole() &&
          (table->RoleValue() == ax::mojom::blink::Role::kGrid ||
           table->RoleValue() == ax::mojom::blink::Role::kTreeGrid)) {
        if (table->Restriction() == kRestrictionReadOnly)
          return kRestrictionReadOnly;
      }
    }
  }

  // This is a node that is not readonly and not disabled.
  return kRestrictionNone;
}

AccessibilityExpanded AXNodeObject::IsExpanded() const {
  if (!SupportsARIAExpanded())
    return kExpandedUndefined;

  auto* element = GetElement();
  if (!element)
    return kExpandedUndefined;

  if (RoleValue() == ax::mojom::blink::Role::kComboBoxSelect) {
    DCHECK(IsA<HTMLSelectElement>(element));
    bool is_expanded = To<HTMLSelectElement>(element)->PopupIsVisible();
    return is_expanded ? kExpandedExpanded : kExpandedCollapsed;
  }

  // For form controls that act as triggering elements for popovers, then set
  // aria-expanded=false when the popover is hidden, and aria-expanded=true when
  // it is showing.
  if (auto* form_control = DynamicTo<HTMLFormControlElement>(element)) {
    if (auto popover = form_control->popoverTargetElement().popover) {
      if (!form_control->IsDescendantOrShadowDescendantOf(popover)) {
        // Only expose expanded/collapsed if the trigger button isn't contained
        // within the popover itself. E.g. a close button within the popover.
        return popover->popoverOpen() ? kExpandedExpanded : kExpandedCollapsed;
      }
    }
  }

  if (IsA<HTMLSummaryElement>(*element)) {
    if (element->parentNode() &&
        IsA<HTMLDetailsElement>(element->parentNode())) {
      return To<Element>(element->parentNode())
                     ->FastHasAttribute(html_names::kOpenAttr)
                 ? kExpandedExpanded
                 : kExpandedCollapsed;
    }
  }

  bool expanded = false;
  if (AriaBooleanAttribute(html_names::kAriaExpandedAttr, &expanded)) {
    return expanded ? kExpandedExpanded : kExpandedCollapsed;
  }

  return kExpandedUndefined;
}

bool AXNodeObject::IsRequired() const {
  auto* form_control = DynamicTo<HTMLFormControlElement>(GetNode());
  if (form_control && form_control->IsRequired())
    return true;

  if (IsAriaAttributeTrue(html_names::kAriaRequiredAttr)) {
    return true;
  }

  return false;
}

bool AXNodeObject::CanvasHasFallbackContent() const {
  if (IsDetached())
    return false;
  Node* node = GetNode();
  return IsA<HTMLCanvasElement>(node) && node->hasChildren();
}

int AXNodeObject::HeadingLevel() const {
  // headings can be in block flow and non-block flow
  Node* node = GetNode();
  if (!node)
    return 0;

  if (RoleValue() == ax::mojom::blink::Role::kHeading) {
    int32_t level;
    if (AriaIntAttribute(html_names::kAriaLevelAttr, &level)) {
      if (level >= 1 && level <= 9) {
        return level;
      }
    }
  }

  auto* element = DynamicTo<HTMLElement>(node);
  if (!element)
    return 0;

  if (element->HasTagName(html_names::kH1Tag))
    return 1;

  if (element->HasTagName(html_names::kH2Tag))
    return 2;

  if (element->HasTagName(html_names::kH3Tag))
    return 3;

  if (element->HasTagName(html_names::kH4Tag))
    return 4;

  if (element->HasTagName(html_names::kH5Tag))
    return 5;

  if (element->HasTagName(html_names::kH6Tag))
    return 6;

  if (RoleValue() == ax::mojom::blink::Role::kHeading)
    return kDefaultHeadingLevel;

  // TODO(accessibility) For kDisclosureTriangle, kDisclosureTriangleGrouping,
  // if IsAccessibilityExposeSummaryAsHeadingEnabled(), we should expose
  // a default heading level that makes sense in the context of the document.
  // Will likely be easier to do on the browser side.
  if (ui::IsHeading(RoleValue())) {
    return 5;
  }

  return 0;
}

unsigned AXNodeObject::HierarchicalLevel() const {
  Element* element = GetElement();
  if (!element)
    return 0;

  int32_t level;
  if (AriaIntAttribute(html_names::kAriaLevelAttr, &level)) {
    if (level >= 1)
      return level;
  }

  // Helper lambda for calculating hierarchical levels by counting ancestor
  // nodes that match a target role.
  auto accumulateLevel = [&](int initial_level,
                             ax::mojom::blink::Role target_role) {
    int level = initial_level;
    for (AXObject* parent = ParentObject(); parent;
         parent = parent->ParentObject()) {
      if (parent->RoleValue() == target_role)
        level++;
    }
    return level;
  };

  switch (RoleValue()) {
    case ax::mojom::blink::Role::kComment:
      // Comment: level is based on counting comment ancestors until the root.
      return accumulateLevel(1, ax::mojom::blink::Role::kComment);
    case ax::mojom::blink::Role::kListItem:
      level = accumulateLevel(0, ax::mojom::blink::Role::kList);
      // When level count is 0 due to this list item not having an ancestor of
      // Role::kList, not nested in list groups, this list item has a level
      // of 1.
      return level == 0 ? 1 : level;
    case ax::mojom::blink::Role::kTabList:
      return accumulateLevel(1, ax::mojom::blink::Role::kTabList);
    case ax::mojom::blink::Role::kTreeItem: {
      // Hierarchy leveling starts at 1, to match the aria-level spec.
      // We measure tree hierarchy by the number of groups that the item is
      // within.
      level = 1;
      for (AXObject* parent = ParentObject(); parent;
           parent = parent->ParentObject()) {
        ax::mojom::blink::Role parent_role = parent->RoleValue();
        if (parent_role == ax::mojom::blink::Role::kGroup)
          level++;
        else if (parent_role == ax::mojom::blink::Role::kTree)
          break;
      }
      return level;
    }
    default:
      return 0;
  }
}

String AXNodeObject::AutoComplete() const {
  // Check cache for auto complete state.
  if (AXObjectCache().GetAutofillSuggestionAvailability(AXObjectID()) ==
      WebAXAutofillSuggestionAvailability::kAutocompleteAvailable) {
    return "list";
  }

  if (IsAtomicTextField() || IsARIATextField()) {
    const AtomicString& aria_auto_complete =
        AriaTokenAttribute(html_names::kAriaAutocompleteAttr);
    // Illegal values must be passed through, according to CORE-AAM.
    if (aria_auto_complete) {
      return aria_auto_complete == "none" ? String()
                                          : aria_auto_complete.LowerASCII();
      ;
    }
  }

  if (auto* input = DynamicTo<HTMLInputElement>(GetNode())) {
    if (input->DataList())
      return "list";
  }

  return String();
}

// TODO(nektar): Consider removing this method in favor of
// AXInlineTextBox::GetDocumentMarkers, or add document markers to the tree data
// instead of nodes objects.
void AXNodeObject::SerializeMarkerAttributes(ui::AXNodeData* node_data) const {
  if (!GetNode() || !GetDocument() || !GetDocument()->View())
    return;

  auto* text_node = DynamicTo<Text>(GetNode());
  if (!text_node)
    return;

  std::vector<int32_t> marker_types;
  std::vector<int32_t> highlight_types;
  std::vector<int32_t> marker_starts;
  std::vector<int32_t> marker_ends;

  // First use ARIA markers for spelling/grammar if available.
  std::optional<DocumentMarker::MarkerType> aria_marker_type =
      GetAriaSpellingOrGrammarMarker();
  if (aria_marker_type) {
    AXRange range = AXRange::RangeOfContents(*this);
    marker_types.push_back(ToAXMarkerType(aria_marker_type.value()));
    marker_starts.push_back(range.Start().TextOffset());
    marker_ends.push_back(range.End().TextOffset());
  }

  DocumentMarkerController& marker_controller = GetDocument()->Markers();
  const DocumentMarker::MarkerTypes markers_used_by_accessibility(
      DocumentMarker::kSpelling | DocumentMarker::kGrammar |
      DocumentMarker::kTextMatch | DocumentMarker::kActiveSuggestion |
      DocumentMarker::kSuggestion | DocumentMarker::kTextFragment |
      DocumentMarker::kCustomHighlight);
  const DocumentMarkerVector markers =
      marker_controller.MarkersFor(*text_node, markers_used_by_accessibility);
  for (const DocumentMarker* marker : markers) {
    if (aria_marker_type == marker->GetType())
      continue;

    const Position start_position(*GetNode(), marker->StartOffset());
    const Position end_position(*GetNode(), marker->EndOffset());
    if (!start_position.IsValidFor(*GetDocument()) ||
        !end_position.IsValidFor(*GetDocument())) {
      continue;
    }

    int32_t highlight_type =
        static_cast<int32_t>(ax::mojom::blink::HighlightType::kNone);
    if (marker->GetType() == DocumentMarker::kCustomHighlight) {
      const auto& highlight_marker = To<CustomHighlightMarker>(*marker);
      highlight_type =
          ToAXHighlightType(highlight_marker.GetHighlight()->type());
    }

    marker_types.push_back(ToAXMarkerType(marker->GetType()));
    highlight_types.push_back(static_cast<int32_t>(highlight_type));
    auto start_pos =
        AXPosition::FromPosition(start_position, TextAffinity::kDownstream,
                                 AXPositionAdjustmentBehavior::kMoveLeft);
    auto end_pos =
        AXPosition::FromPosition(end_position, TextAffinity::kDownstream,
                                 AXPositionAdjustmentBehavior::kMoveRight);
    marker_starts.push_back(start_pos.TextOffset());
    marker_ends.push_back(end_pos.TextOffset());
  }

  if (marker_types.empty())
    return;

  node_data->AddIntListAttribute(
      ax::mojom::blink::IntListAttribute::kMarkerTypes, marker_types);
  node_data->AddIntListAttribute(
      ax::mojom::blink::IntListAttribute::kHighlightTypes, highlight_types);
  node_data->AddIntListAttribute(
      ax::mojom::blink::IntListAttribute::kMarkerStarts, marker_starts);
  node_data->AddIntListAttribute(
      ax::mojom::blink::IntListAttribute::kMarkerEnds, marker_ends);
}

ax::mojom::blink::ListStyle AXNodeObject::GetListStyle() const {
  const LayoutObject* layout_object = GetLayoutObject();
  if (!layout_object) {
    return AXObject::GetListStyle();
  }

  const ComputedStyle* computed_style = layout_object->Style();
  if (!computed_style) {
    return AXObject::GetListStyle();
  }

  const StyleImage* style_image = computed_style->ListStyleImage();
  if (style_image && !style_image->ErrorOccurred()) {
    return ax::mojom::blink::ListStyle::kImage;
  }

  if (RuntimeEnabledFeatures::CSSAtRuleCounterStyleSpeakAsDescriptorEnabled()) {
    if (!computed_style->ListStyleType()) {
      return ax::mojom::blink::ListStyle::kNone;
    }
    if (computed_style->ListStyleType()->IsString()) {
      return ax::mojom::blink::ListStyle::kOther;
    }

    DCHECK(computed_style->ListStyleType()->IsCounterStyle());
    const CounterStyle& counter_style =
        ListMarker::GetCounterStyle(*GetDocument(), *computed_style);
    switch (counter_style.EffectiveSpeakAs()) {
      case CounterStyleSpeakAs::kBullets: {
        // See |ua_counter_style_map.cc| for predefined symbolic counter styles.
        UChar symbol = counter_style.GenerateTextAlternative(0)[0];
        switch (symbol) {
          case 0x2022:
            return ax::mojom::blink::ListStyle::kDisc;
          case 0x25E6:
            return ax::mojom::blink::ListStyle::kCircle;
          case 0x25A0:
            return ax::mojom::blink::ListStyle::kSquare;
          default:
            return ax::mojom::blink::ListStyle::kOther;
        }
      }
      case CounterStyleSpeakAs::kNumbers:
        return ax::mojom::blink::ListStyle::kNumeric;
      case CounterStyleSpeakAs::kWords:
        return ax::mojom::blink::ListStyle::kOther;
      case CounterStyleSpeakAs::kAuto:
      case CounterStyleSpeakAs::kReference:
        NOTREACHED();
    }
  }

  switch (ListMarker::GetListStyleCategory(*GetDocument(), *computed_style)) {
    case ListMarker::ListStyleCategory::kNone:
      return ax::mojom::blink::ListStyle::kNone;
    case ListMarker::ListStyleCategory::kSymbol: {
      const AtomicString& counter_style_name =
          computed_style->ListStyleType()->GetCounterStyleName();
      if (counter_style_name == keywords::kDisc) {
        return ax::mojom::blink::ListStyle::kDisc;
      }
      if (counter_style_name == keywords::kCircle) {
        return ax::mojom::blink::ListStyle::kCircle;
      }
      if (counter_style_name == keywords::kSquare) {
        return ax::mojom::blink::ListStyle::kSquare;
      }
      return ax::mojom::blink::ListStyle::kOther;
    }
    case ListMarker::ListStyleCategory::kLanguage: {
      const AtomicString& counter_style_name =
          computed_style->ListStyleType()->GetCounterStyleName();
      if (counter_style_name == keywords
### 提示词
```
这是目录为blink/renderer/modules/accessibility/ax_node_object.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共10部分，请归纳一下它的功能
```

### 源代码
```cpp
This can
  // only occur if line breaks are preserved and a newline character is present
  // in their collapsed text. Text collapsing removes all whitespace found in
  // the HTML file, but a special style rule could be used to preserve line
  // breaks.
  //
  // The best example is the <pre> element:
  // <pre>Line 1
  // Line 2</pre>
  if (const LayoutText* layout_text = DynamicTo<LayoutText>(layout_object)) {
    const ComputedStyle& style = layout_object->StyleRef();
    if (layout_text->HasNonCollapsedText() && style.ShouldPreserveBreaks() &&
        layout_text->PlainText().find('\n') != WTF::kNotFound) {
      return true;
    }
  }

  // Rely on the ARIA role to figure out if this object is line breaking.
  return AXObject::IsLineBreakingObject();
}

bool AXNodeObject::IsLoaded() const {
  if (!GetDocument())
    return false;

  if (!GetDocument()->IsLoadCompleted())
    return false;

  // Check for a navigation API single-page app navigation in progress.
  if (auto* window = GetDocument()->domWindow()) {
    if (window->navigation()->HasNonDroppedOngoingNavigation())
      return false;
  }

  return true;
}

bool AXNodeObject::IsMultiSelectable() const {
  switch (RoleValue()) {
    case ax::mojom::blink::Role::kGrid:
    case ax::mojom::blink::Role::kTreeGrid:
    case ax::mojom::blink::Role::kTree:
    case ax::mojom::blink::Role::kListBox:
    case ax::mojom::blink::Role::kTabList:
      bool multiselectable;
      if (AriaBooleanAttribute(html_names::kAriaMultiselectableAttr,
                               &multiselectable)) {
        return multiselectable;
      }
      break;
    default:
      break;
  }

  auto* html_select_element = DynamicTo<HTMLSelectElement>(GetNode());
  return html_select_element && html_select_element->IsMultiple();
}

bool AXNodeObject::IsNativeImage() const {
  Node* node = GetNode();
  if (!node)
    return false;

  if (IsA<HTMLImageElement>(*node) || IsA<HTMLPlugInElement>(*node))
    return true;

  if (const auto* input = DynamicTo<HTMLInputElement>(*node))
    return input->FormControlType() == FormControlType::kInputImage;

  return false;
}

bool AXNodeObject::IsVisible() const {
  // Any descendant of a <select size=1> should be considered invisible if
  // the select is collapsed.
  if (RoleValue() == ax::mojom::blink::Role::kMenuListPopup) {
    CHECK(parent_);
    return parent_->IsExpanded() == kExpandedExpanded;
  }

  if (IsRoot()) {
    return true;
  }

  // Anything else inside of a collapsed select is also invisible.
  if (const AXObject* ax_select = ParentObject()->AncestorMenuList()) {
    // If the select is invisible, so is everything inside of it.
    if (!ax_select->IsVisible()) {
      return false;
    }
    // Inside of a collapsed select:
    // - The selected option's subtree is visible.
    // - Everything else is invisible.
    if (ax_select->IsExpanded() == kExpandedCollapsed) {
      if (const AXObject* ax_option = AncestorMenuListOption()) {
        return ax_option->IsSelected() == kSelectedStateTrue;
      }
      return false;
    }
  }

  return AXObject::IsVisible();
}

bool AXNodeObject::IsLinked() const {
  if (!IsLinkable(*this)) {
    return false;
  }

  if (auto* anchor = DynamicTo<HTMLAnchorElementBase>(AnchorElement())) {
    return !anchor->Href().IsEmpty();
  }
  return false;
}

bool AXNodeObject::IsVisited() const {
  return GetLayoutObject() && GetLayoutObject()->Style()->IsLink() &&
         GetLayoutObject()->Style()->InsideLink() ==
             EInsideLink::kInsideVisitedLink;
}

bool AXNodeObject::IsProgressIndicator() const {
  return RoleValue() == ax::mojom::blink::Role::kProgressIndicator;
}

bool AXNodeObject::IsSlider() const {
  return RoleValue() == ax::mojom::blink::Role::kSlider;
}

bool AXNodeObject::IsSpinButton() const {
  return RoleValue() == ax::mojom::blink::Role::kSpinButton;
}

bool AXNodeObject::IsNativeSlider() const {
  if (const auto* input = DynamicTo<HTMLInputElement>(GetNode()))
    return input->FormControlType() == FormControlType::kInputRange;
  return false;
}

bool AXNodeObject::IsNativeSpinButton() const {
  if (const auto* input = DynamicTo<HTMLInputElement>(GetNode()))
    return input->FormControlType() == FormControlType::kInputNumber;
  return false;
}

bool AXNodeObject::IsEmbeddingElement() const {
  return ui::IsEmbeddingElement(native_role_);
}

bool AXNodeObject::IsClickable() const {
  // Determine whether the element is clickable either because there is a
  // mouse button handler or because it has a native element where click
  // performs an action. Disabled nodes are never considered clickable.
  // Note: we can't call |node->WillRespondToMouseClickEvents()| because that
  // triggers a style recalc and can delete this.

  // Treat mouse button listeners on the |window|, |document| as if they're on
  // the |documentElement|.
  if (GetNode() == GetDocument()->documentElement()) {
    return GetNode()->HasAnyEventListeners(
               event_util::MouseButtonEventTypes()) ||
           GetDocument()->HasAnyEventListeners(
               event_util::MouseButtonEventTypes()) ||
           GetDocument()->domWindow()->HasAnyEventListeners(
               event_util::MouseButtonEventTypes());
  }

  // Look for mouse listeners only on element nodes, e.g. skip text nodes.
  const Element* element = GetElement();
  if (!element)
    return false;

  if (IsDisabled())
    return false;

  if (element->HasAnyEventListeners(event_util::MouseButtonEventTypes()))
    return true;

  if (HasContentEditableAttributeSet())
    return true;

  // Certain user-agent shadow DOM elements are expected to be clickable but
  // they do not have event listeners attached or a clickable native role. We
  // whitelist them here.
  if (element->ShadowPseudoId() ==
      shadow_element_names::kPseudoCalendarPickerIndicator) {
    return true;
  }

  // Only use native roles. For ARIA elements, require a click listener.
  return ui::IsClickable(native_role_);
}

bool AXNodeObject::IsFocused() const {
  if (!GetDocument())
    return false;

  // A web area is represented by the Document node in the DOM tree, which isn't
  // focusable.  Check instead if the frame's selection controller is focused.
  if (IsWebArea() &&
      GetDocument()->GetFrame()->Selection().FrameIsFocusedAndActive()) {
    return true;
  }

  Element* focused_element = GetDocument()->FocusedElement();
  return focused_element && focused_element == GetElement();
}

AccessibilitySelectedState AXNodeObject::IsSelected() const {
  if (!GetNode() || !IsSubWidget()) {
    return kSelectedStateUndefined;
  }

  // The aria-selected attribute overrides automatic behaviors.
  bool is_selected;
  if (AriaBooleanAttribute(html_names::kAriaSelectedAttr, &is_selected)) {
    return is_selected ? kSelectedStateTrue : kSelectedStateFalse;
  }

  // The selection should only follow the focus when the aria-selected attribute
  // is marked as required or implied for this element in the ARIA specs.
  // If this object can't follow the focus, then we can't say that it's selected
  // nor that it's not.
  if (!ui::IsSelectRequiredOrImplicit(RoleValue()))
    return kSelectedStateUndefined;

  if (auto* option_element = DynamicTo<HTMLOptionElement>(GetNode())) {
    if (!CanSetSelectedAttribute()) {
      return kSelectedStateUndefined;
    }
    return (option_element->Selected()) ? kSelectedStateTrue
                                        : kSelectedStateFalse;
  }
  // Selection follows focus, but ONLY in single selection containers, and only
  // if aria-selected was not present to override.
  return IsSelectedFromFocus() ? kSelectedStateTrue : kSelectedStateFalse;
}

bool AXNodeObject::IsSelectedFromFocusSupported() const {
  // The selection should only follow the focus when the aria-selected attribute
  // is marked as required or implied for this element in the ARIA specs.
  // If this object can't follow the focus, then we can't say that it's selected
  // nor that it's not.
  // TODO(crbug.com/1143483): Consider allowing more roles.
  if (!ui::IsSelectRequiredOrImplicit(RoleValue()))
    return false;

  // Selection follows focus only when in a single selection container.
  const AXObject* container = ContainerWidget();
  if (!container || container->IsMultiSelectable()) {
    return false;
  }

  // Certain properties inside the container widget mean that implicit selection
  // must be turned off.
  if (!AXObjectCache().IsImplicitSelectionAllowed(container)) {
    return false;
  }

  return true;
}

// In single selection containers, selection follows focus unless aria_selected
// is set to false. This is only valid for a subset of elements.
bool AXNodeObject::IsSelectedFromFocus() const {
  // A tab item can also be selected if it is associated to a focused tabpanel
  // via the aria-labelledby attribute.
  if (IsTabItem() && IsSelectedFromFocusSupported() && IsTabItemSelected()) {
    return true;
  }

  // If this object is not accessibility focused, then it is not selected from
  // focus.
  AXObject* focused_object = AXObjectCache().FocusedObject();
  if (focused_object != this &&
      (!focused_object || focused_object->ActiveDescendant() != this))
    return false;

  return IsSelectedFromFocusSupported();
}

// Returns true if the object is marked user-select:none
bool AXNodeObject::IsNotUserSelectable() const {
  if (!GetLayoutObject()) {
    return false;
  }

  if (IsA<PseudoElement>(GetClosestElement())) {
    return true;
  }

  const ComputedStyle* style = GetLayoutObject()->Style();
  if (!style) {
    return false;
  }

  return (style->UsedUserSelect() == EUserSelect::kNone);
}

bool AXNodeObject::IsTabItemSelected() const {
  if (!IsTabItem() || !GetLayoutObject())
    return false;

  Node* node = GetNode();
  if (!node || !node->IsElementNode())
    return false;

  // The ARIA spec says a tab item can also be selected if it is aria-labeled by
  // a tabpanel that has keyboard focus inside of it, or if a tabpanel in its
  // aria-controls list has KB focus inside of it.
  AXObject* focused_element = AXObjectCache().FocusedObject();
  if (!focused_element)
    return false;

  DCHECK(GetElement());
  const HeapVector<Member<Element>>* elements =
      AXObject::ElementsFromAttributeOrInternals(GetElement(),
                                                 html_names::kAriaControlsAttr);
  if (!elements) {
    return false;
  }

  for (const auto& element : *elements) {
    AXObject* tab_panel = AXObjectCache().Get(element);

    // A tab item should only control tab panels.
    if (!tab_panel ||
        tab_panel->RoleValue() != ax::mojom::blink::Role::kTabPanel) {
      continue;
    }

    AXObject* check_focus_element = focused_element;
    // Check if the focused element is a descendant of the element controlled by
    // the tab item.
    while (check_focus_element) {
      if (tab_panel == check_focus_element)
        return true;
      check_focus_element = check_focus_element->ParentObject();
    }
  }

  return false;
}

AXRestriction AXNodeObject::Restriction() const {
  Element* elem = GetElement();
  if (!elem)
    return kRestrictionNone;

  // An <optgroup> is not exposed directly in the AX tree.
  if (IsA<HTMLOptGroupElement>(elem))
    return kRestrictionNone;

  // According to ARIA, all elements of the base markup can be disabled.
  // According to CORE-AAM, any focusable descendant of aria-disabled
  // ancestor is also disabled.
  if (IsDisabled())
    return kRestrictionDisabled;

  // Only editable fields can be marked @readonly (unlike @aria-readonly).
  auto* text_area_element = DynamicTo<HTMLTextAreaElement>(*elem);
  if (text_area_element && text_area_element->IsReadOnly())
    return kRestrictionReadOnly;
  if (const auto* input = DynamicTo<HTMLInputElement>(*elem)) {
    if (input->IsTextField() && input->IsReadOnly())
      return kRestrictionReadOnly;
  }

  // Check aria-readonly if supported by current role.
  bool is_read_only;
  if (SupportsARIAReadOnly() &&
      AriaBooleanAttribute(html_names::kAriaReadonlyAttr, &is_read_only)) {
    // ARIA overrides other readonly state markup.
    return is_read_only ? kRestrictionReadOnly : kRestrictionNone;
  }

  // If a grid cell does not have it's own ARIA input restriction,
  // fall back on parent grid's readonly state.
  // See ARIA specification regarding grid/treegrid and readonly.
  if (IsTableCellLikeRole()) {
    AXObject* row = ParentObjectUnignored();
    if (row && row->IsTableRowLikeRole()) {
      AXObject* table = row->ParentObjectUnignored();
      if (table && table->IsTableLikeRole() &&
          (table->RoleValue() == ax::mojom::blink::Role::kGrid ||
           table->RoleValue() == ax::mojom::blink::Role::kTreeGrid)) {
        if (table->Restriction() == kRestrictionReadOnly)
          return kRestrictionReadOnly;
      }
    }
  }

  // This is a node that is not readonly and not disabled.
  return kRestrictionNone;
}

AccessibilityExpanded AXNodeObject::IsExpanded() const {
  if (!SupportsARIAExpanded())
    return kExpandedUndefined;

  auto* element = GetElement();
  if (!element)
    return kExpandedUndefined;

  if (RoleValue() == ax::mojom::blink::Role::kComboBoxSelect) {
    DCHECK(IsA<HTMLSelectElement>(element));
    bool is_expanded = To<HTMLSelectElement>(element)->PopupIsVisible();
    return is_expanded ? kExpandedExpanded : kExpandedCollapsed;
  }

  // For form controls that act as triggering elements for popovers, then set
  // aria-expanded=false when the popover is hidden, and aria-expanded=true when
  // it is showing.
  if (auto* form_control = DynamicTo<HTMLFormControlElement>(element)) {
    if (auto popover = form_control->popoverTargetElement().popover) {
      if (!form_control->IsDescendantOrShadowDescendantOf(popover)) {
        // Only expose expanded/collapsed if the trigger button isn't contained
        // within the popover itself. E.g. a close button within the popover.
        return popover->popoverOpen() ? kExpandedExpanded : kExpandedCollapsed;
      }
    }
  }

  if (IsA<HTMLSummaryElement>(*element)) {
    if (element->parentNode() &&
        IsA<HTMLDetailsElement>(element->parentNode())) {
      return To<Element>(element->parentNode())
                     ->FastHasAttribute(html_names::kOpenAttr)
                 ? kExpandedExpanded
                 : kExpandedCollapsed;
    }
  }

  bool expanded = false;
  if (AriaBooleanAttribute(html_names::kAriaExpandedAttr, &expanded)) {
    return expanded ? kExpandedExpanded : kExpandedCollapsed;
  }

  return kExpandedUndefined;
}

bool AXNodeObject::IsRequired() const {
  auto* form_control = DynamicTo<HTMLFormControlElement>(GetNode());
  if (form_control && form_control->IsRequired())
    return true;

  if (IsAriaAttributeTrue(html_names::kAriaRequiredAttr)) {
    return true;
  }

  return false;
}

bool AXNodeObject::CanvasHasFallbackContent() const {
  if (IsDetached())
    return false;
  Node* node = GetNode();
  return IsA<HTMLCanvasElement>(node) && node->hasChildren();
}

int AXNodeObject::HeadingLevel() const {
  // headings can be in block flow and non-block flow
  Node* node = GetNode();
  if (!node)
    return 0;

  if (RoleValue() == ax::mojom::blink::Role::kHeading) {
    int32_t level;
    if (AriaIntAttribute(html_names::kAriaLevelAttr, &level)) {
      if (level >= 1 && level <= 9) {
        return level;
      }
    }
  }

  auto* element = DynamicTo<HTMLElement>(node);
  if (!element)
    return 0;

  if (element->HasTagName(html_names::kH1Tag))
    return 1;

  if (element->HasTagName(html_names::kH2Tag))
    return 2;

  if (element->HasTagName(html_names::kH3Tag))
    return 3;

  if (element->HasTagName(html_names::kH4Tag))
    return 4;

  if (element->HasTagName(html_names::kH5Tag))
    return 5;

  if (element->HasTagName(html_names::kH6Tag))
    return 6;

  if (RoleValue() == ax::mojom::blink::Role::kHeading)
    return kDefaultHeadingLevel;

  // TODO(accessibility) For kDisclosureTriangle, kDisclosureTriangleGrouping,
  // if IsAccessibilityExposeSummaryAsHeadingEnabled(), we should expose
  // a default heading level that makes sense in the context of the document.
  // Will likely be easier to do on the browser side.
  if (ui::IsHeading(RoleValue())) {
    return 5;
  }

  return 0;
}

unsigned AXNodeObject::HierarchicalLevel() const {
  Element* element = GetElement();
  if (!element)
    return 0;

  int32_t level;
  if (AriaIntAttribute(html_names::kAriaLevelAttr, &level)) {
    if (level >= 1)
      return level;
  }

  // Helper lambda for calculating hierarchical levels by counting ancestor
  // nodes that match a target role.
  auto accumulateLevel = [&](int initial_level,
                             ax::mojom::blink::Role target_role) {
    int level = initial_level;
    for (AXObject* parent = ParentObject(); parent;
         parent = parent->ParentObject()) {
      if (parent->RoleValue() == target_role)
        level++;
    }
    return level;
  };

  switch (RoleValue()) {
    case ax::mojom::blink::Role::kComment:
      // Comment: level is based on counting comment ancestors until the root.
      return accumulateLevel(1, ax::mojom::blink::Role::kComment);
    case ax::mojom::blink::Role::kListItem:
      level = accumulateLevel(0, ax::mojom::blink::Role::kList);
      // When level count is 0 due to this list item not having an ancestor of
      // Role::kList, not nested in list groups, this list item has a level
      // of 1.
      return level == 0 ? 1 : level;
    case ax::mojom::blink::Role::kTabList:
      return accumulateLevel(1, ax::mojom::blink::Role::kTabList);
    case ax::mojom::blink::Role::kTreeItem: {
      // Hierarchy leveling starts at 1, to match the aria-level spec.
      // We measure tree hierarchy by the number of groups that the item is
      // within.
      level = 1;
      for (AXObject* parent = ParentObject(); parent;
           parent = parent->ParentObject()) {
        ax::mojom::blink::Role parent_role = parent->RoleValue();
        if (parent_role == ax::mojom::blink::Role::kGroup)
          level++;
        else if (parent_role == ax::mojom::blink::Role::kTree)
          break;
      }
      return level;
    }
    default:
      return 0;
  }
}

String AXNodeObject::AutoComplete() const {
  // Check cache for auto complete state.
  if (AXObjectCache().GetAutofillSuggestionAvailability(AXObjectID()) ==
      WebAXAutofillSuggestionAvailability::kAutocompleteAvailable) {
    return "list";
  }

  if (IsAtomicTextField() || IsARIATextField()) {
    const AtomicString& aria_auto_complete =
        AriaTokenAttribute(html_names::kAriaAutocompleteAttr);
    // Illegal values must be passed through, according to CORE-AAM.
    if (aria_auto_complete) {
      return aria_auto_complete == "none" ? String()
                                          : aria_auto_complete.LowerASCII();
      ;
    }
  }

  if (auto* input = DynamicTo<HTMLInputElement>(GetNode())) {
    if (input->DataList())
      return "list";
  }

  return String();
}

// TODO(nektar): Consider removing this method in favor of
// AXInlineTextBox::GetDocumentMarkers, or add document markers to the tree data
// instead of nodes objects.
void AXNodeObject::SerializeMarkerAttributes(ui::AXNodeData* node_data) const {
  if (!GetNode() || !GetDocument() || !GetDocument()->View())
    return;

  auto* text_node = DynamicTo<Text>(GetNode());
  if (!text_node)
    return;

  std::vector<int32_t> marker_types;
  std::vector<int32_t> highlight_types;
  std::vector<int32_t> marker_starts;
  std::vector<int32_t> marker_ends;

  // First use ARIA markers for spelling/grammar if available.
  std::optional<DocumentMarker::MarkerType> aria_marker_type =
      GetAriaSpellingOrGrammarMarker();
  if (aria_marker_type) {
    AXRange range = AXRange::RangeOfContents(*this);
    marker_types.push_back(ToAXMarkerType(aria_marker_type.value()));
    marker_starts.push_back(range.Start().TextOffset());
    marker_ends.push_back(range.End().TextOffset());
  }

  DocumentMarkerController& marker_controller = GetDocument()->Markers();
  const DocumentMarker::MarkerTypes markers_used_by_accessibility(
      DocumentMarker::kSpelling | DocumentMarker::kGrammar |
      DocumentMarker::kTextMatch | DocumentMarker::kActiveSuggestion |
      DocumentMarker::kSuggestion | DocumentMarker::kTextFragment |
      DocumentMarker::kCustomHighlight);
  const DocumentMarkerVector markers =
      marker_controller.MarkersFor(*text_node, markers_used_by_accessibility);
  for (const DocumentMarker* marker : markers) {
    if (aria_marker_type == marker->GetType())
      continue;

    const Position start_position(*GetNode(), marker->StartOffset());
    const Position end_position(*GetNode(), marker->EndOffset());
    if (!start_position.IsValidFor(*GetDocument()) ||
        !end_position.IsValidFor(*GetDocument())) {
      continue;
    }

    int32_t highlight_type =
        static_cast<int32_t>(ax::mojom::blink::HighlightType::kNone);
    if (marker->GetType() == DocumentMarker::kCustomHighlight) {
      const auto& highlight_marker = To<CustomHighlightMarker>(*marker);
      highlight_type =
          ToAXHighlightType(highlight_marker.GetHighlight()->type());
    }

    marker_types.push_back(ToAXMarkerType(marker->GetType()));
    highlight_types.push_back(static_cast<int32_t>(highlight_type));
    auto start_pos =
        AXPosition::FromPosition(start_position, TextAffinity::kDownstream,
                                 AXPositionAdjustmentBehavior::kMoveLeft);
    auto end_pos =
        AXPosition::FromPosition(end_position, TextAffinity::kDownstream,
                                 AXPositionAdjustmentBehavior::kMoveRight);
    marker_starts.push_back(start_pos.TextOffset());
    marker_ends.push_back(end_pos.TextOffset());
  }

  if (marker_types.empty())
    return;

  node_data->AddIntListAttribute(
      ax::mojom::blink::IntListAttribute::kMarkerTypes, marker_types);
  node_data->AddIntListAttribute(
      ax::mojom::blink::IntListAttribute::kHighlightTypes, highlight_types);
  node_data->AddIntListAttribute(
      ax::mojom::blink::IntListAttribute::kMarkerStarts, marker_starts);
  node_data->AddIntListAttribute(
      ax::mojom::blink::IntListAttribute::kMarkerEnds, marker_ends);
}

ax::mojom::blink::ListStyle AXNodeObject::GetListStyle() const {
  const LayoutObject* layout_object = GetLayoutObject();
  if (!layout_object) {
    return AXObject::GetListStyle();
  }

  const ComputedStyle* computed_style = layout_object->Style();
  if (!computed_style) {
    return AXObject::GetListStyle();
  }

  const StyleImage* style_image = computed_style->ListStyleImage();
  if (style_image && !style_image->ErrorOccurred()) {
    return ax::mojom::blink::ListStyle::kImage;
  }

  if (RuntimeEnabledFeatures::CSSAtRuleCounterStyleSpeakAsDescriptorEnabled()) {
    if (!computed_style->ListStyleType()) {
      return ax::mojom::blink::ListStyle::kNone;
    }
    if (computed_style->ListStyleType()->IsString()) {
      return ax::mojom::blink::ListStyle::kOther;
    }

    DCHECK(computed_style->ListStyleType()->IsCounterStyle());
    const CounterStyle& counter_style =
        ListMarker::GetCounterStyle(*GetDocument(), *computed_style);
    switch (counter_style.EffectiveSpeakAs()) {
      case CounterStyleSpeakAs::kBullets: {
        // See |ua_counter_style_map.cc| for predefined symbolic counter styles.
        UChar symbol = counter_style.GenerateTextAlternative(0)[0];
        switch (symbol) {
          case 0x2022:
            return ax::mojom::blink::ListStyle::kDisc;
          case 0x25E6:
            return ax::mojom::blink::ListStyle::kCircle;
          case 0x25A0:
            return ax::mojom::blink::ListStyle::kSquare;
          default:
            return ax::mojom::blink::ListStyle::kOther;
        }
      }
      case CounterStyleSpeakAs::kNumbers:
        return ax::mojom::blink::ListStyle::kNumeric;
      case CounterStyleSpeakAs::kWords:
        return ax::mojom::blink::ListStyle::kOther;
      case CounterStyleSpeakAs::kAuto:
      case CounterStyleSpeakAs::kReference:
        NOTREACHED();
    }
  }

  switch (ListMarker::GetListStyleCategory(*GetDocument(), *computed_style)) {
    case ListMarker::ListStyleCategory::kNone:
      return ax::mojom::blink::ListStyle::kNone;
    case ListMarker::ListStyleCategory::kSymbol: {
      const AtomicString& counter_style_name =
          computed_style->ListStyleType()->GetCounterStyleName();
      if (counter_style_name == keywords::kDisc) {
        return ax::mojom::blink::ListStyle::kDisc;
      }
      if (counter_style_name == keywords::kCircle) {
        return ax::mojom::blink::ListStyle::kCircle;
      }
      if (counter_style_name == keywords::kSquare) {
        return ax::mojom::blink::ListStyle::kSquare;
      }
      return ax::mojom::blink::ListStyle::kOther;
    }
    case ListMarker::ListStyleCategory::kLanguage: {
      const AtomicString& counter_style_name =
          computed_style->ListStyleType()->GetCounterStyleName();
      if (counter_style_name == keywords::kDecimal) {
        return ax::mojom::blink::ListStyle::kNumeric;
      }
      if (counter_style_name == "decimal-leading-zero") {
        // 'decimal-leading-zero' may be overridden by custom counter styles. We
        // return kNumeric only when we are using the predefined counter style.
        if (ListMarker::GetCounterStyle(*GetDocument(), *computed_style)
                .IsPredefined()) {
          return ax::mojom::blink::ListStyle::kNumeric;
        }
      }
      return ax::mojom::blink::ListStyle::kOther;
    }
    case ListMarker::ListStyleCategory::kStaticString:
      return ax::mojom::blink::ListStyle::kOther;
  }
}

AXObject* AXNodeObject::InPageLinkTarget() const {
  if (!IsLink() || !GetDocument())
    return AXObject::InPageLinkTarget();

  const Element* anchor = AnchorElement();
  if (!anchor)
    return AXObject::InPageLinkTarget();

  KURL link_url = anchor->HrefURL();
  if (!link_url.IsValid())
    return AXObject::InPageLinkTarget();

  KURL document_url = GetDocument()->Url();
  if (!document_url.IsValid() ||
      !EqualIgnoringFragmentIdentifier(document_url, link_url)) {
    return AXObject::InPageLinkTarget();
  }

  String fragment = link_url.FragmentIdentifier().ToString();
  TreeScope& tree_scope = anchor->GetTreeScope();
  Node* target = tree_scope.FindAnchor(fragment);
  AXObject* ax_target = AXObjectCache().Get(target);
  if (!ax_target || !IsPotentialInPageLinkTarget(*ax_target->GetNode()))
    return AXObject::InPageLinkTarget();

#if DCHECK_IS_ON()
  // Link targets always have an element, unless it is the document itself,
  // e.g. via <a href="#">.
  DCHECK(ax_target->IsWebArea() || ax_target->GetElement())
      << "The link target is expected to be a document or an element: "
      << ax_target << "\n* URL fragment = " << fragment;
#endif

  // Usually won't be ignored, but could be e.g. if aria-hidden.
  if (ax_target->IsIgnored())
    return nullptr;

  return ax_target;
}

const AtomicString& AXNodeObject::EffectiveTarget() const {
  // The "target" attribute defines the target browser context and is supported
  // on <a>, <area>, <base>, and <form>. Valid values are: "frame_name", "self",
  // "blank", "top", and "parent", where "frame_name" is the value of the "name"
  // attribute on any enclosing iframe.
  //
  // <area> is a subclass of <a>, while <base> provides the document's base
  // target that any <a>'s or any <area>'s target can override.
  // `HtmlAnchorElement::GetEffectiveTarget()` will take <base> into account.
  //
  // <form> is out of scope, because it affects the target to which the form is
  // submitted, and could also be overridden by a "formTarget" attribute on e.g.
  // a form's submit button. However, screen reader users have no need to know
  // to which target (browser context) a form would be submitted.
  const auto* anchor = DynamicTo<HTMLAnchorElementBase>(GetNode());
  if (anchor) {
    const AtomicString self_value("_self");
    const AtomicString& effective_target = anchor->GetEffectiveTarget();
    if (effective_target != self_value) {
      return anchor->GetEffectiveTarget();
    }
  }
  return AXObject::EffectiveTarget();
}

AccessibilityOrientation AXNodeObject::Orientation() const {
  const AtomicString& aria_orientation =
      AriaTokenAttribute(html_names::kAriaOrientationAttr);
  AccessibilityOrientation orientation = kAccessibilityOrientationUndefined;
  if (EqualIgnoringASCIICase(aria_orientation, "horizontal"))
    orientation = kAccessibilityOrientationHorizontal;
  else if (EqualIgnoringASCIICase(aria_orientation, "vertical"))
    orientation = kAccessibilityOrientationVertical;

  switch (RoleValue()) {
    case ax::mojom::blink::Role::kListBox:
    case ax::mojom::blink::Role::kMenu:
    case ax::mojom::blink::Role::kScrollBar:
    case ax::mojom::blink::Role::kTree:
      if (orientation == kAccessibilityOrientationUndefined)
        orientation = kAccessibilityOrientationVertical;

      return orientation;
    case ax::mojom::blink::Role::kMenuBar:
    case ax::mojom::blink::Role::kSlider:
    case ax::mojom::blink::Role::kSplitter:
    case ax::mojom::blink::Role::kTabList:
    case ax::mojom::blink::Role::kToolbar:
      if (orientation == kAccessibilityOrientationUndefined)
        orientation = kAccessibilityOrientationHorizontal;

      return orientation;
    case ax::mojom::blink::Role::kComboBoxGrouping:
    case ax::mojom::blink::Role::kComboBoxMenuButton:
    case ax::mojom::blink::Role::kRadioGroup:
    case ax::mojom::blink::Role::kTreeGrid:
      return orientation;
    default:
      return AXObject::Orientation();
  }
}

// According to the standard, the figcaption should only be the first or
// last child: https://html.spec.whatwg.org/#the-figcaption-element
AXObject* AXNodeObject::GetChildFigcaption() const {
  AXObject* child = FirstChildIncludingIgnored();
  if (!child)
    return nullptr;
  if (child->RoleValue() == ax::mojom::blink::Role::kFigcaption)
    return child;

  child = LastChildIncludingIgnored();
  if (child->RoleValue() == ax::mojom::blink::Role::kFigcaption)
    return child;

  return nullptr;
}

AXObject::AXObjectVector AXNodeObject::RadioButtonsInGroup() const {
  AXObjectVector radio_buttons;
  if (!node_ || RoleValue() != ax::mojom::blink::Role::kRadioButton)
    return radio_buttons;

  if (auto* node_radio_button = DynamicTo<HTMLInputElement>(node_.Get())) {
    HeapVector<Member<HTMLInputElement>> html_radio_buttons =
        FindAllRadioButtonsWithSameName(node_radio_button);
    for (HTMLInputElement* radio_button : html_radio_buttons) {
      AXObject* ax_radio_button = AXObjectCache().Get(radio_button);
      if (ax_radio_button)
        radio_buttons.push_back(ax_radio_button);
    }
    return radio_buttons;
  }

  // If the immediate parent is a radio group, return all its children that are
  // radio buttons.
  AXObject* parent = ParentObjectUnignored();
  if (parent && parent->RoleValue() == ax::mojom::blink::Role::kRadioGroup) {
    for (AXObject* child : parent->UnignoredChildren()) {
      DCHECK(child);
      if (child->RoleValue() == ax::mojom::blink::Role::kRadioButton &&
          child->IsIncludedInTree()) {
        radio_buttons.push_back(child);
      }
    }
  }

  return radio_buttons;
}

// static
HeapVector<Member<HTMLInputElement>>
AXNodeObject::FindAllRadioButtonsWithSameName(HTMLInputElement* radio_button) {
  HeapVector<Member<HTMLInputElement>> all_radio_buttons;
  if (!radio_button ||
      radio_button->FormControlType() != FormControlType::kInputRadio) {
    return all_radio_buttons;
  }

  constexpr bool kTraverseForward = true;
  constexpr bool kTraverseBackward = false;
  HTMLInputElement* first_radio_button = radio_button;
  do {
    radio_button = RadioInputType::NextRadioButtonInGroup(first_radio_button,
                                                          kTraverseBackward);
    if (radio_button)
      first_radio_button = radio_button;
  } while (radio_button);

  HTMLInputElement* next_radio_button = first_radio_button;
  do {
    all_radio_buttons.push_back(next_radio_button);
    next_radio_button = RadioInputType::NextRadioButtonInGroup(
        next_radio_button, kTraverseForward);
  } while (next_radio_button);
  return all_radio_buttons;
}

ax::mojom::blink::WritingDirection AXNodeObject::GetTextDirection() const {
  if (!GetLayoutObject())
    return AXObject::GetTextDirection();

  const ComputedStyle* style = GetLayoutObject()->Style();
  if (!style)
    return AXObject::GetTextDirection();

  switch (style->GetWritingDirection().InlineEnd()) {
    case PhysicalDirection::kRight:
      return ax::mojo
```