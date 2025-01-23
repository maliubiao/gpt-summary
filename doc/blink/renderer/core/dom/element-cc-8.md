Response:
My thinking process to arrive at the summary of the provided code snippet goes through these stages:

1. **Initial Skim and Keyword Identification:** I quickly read through the code, looking for recurring keywords and function names. Terms like `PseudoStateChanged`, `SetNeedsStyleRecalc`, `Focus`, `ViewTransition`, `DisplayLock`, `PseudoElement`, `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `PointerCapture`, and `ComputedStyle` stand out. These immediately give clues about the functionalities being implemented.

2. **Function-Level Analysis:** I examine each function individually, understanding its purpose. For example:
    * Functions like `FocusVisibleStateChanged`, `ActiveViewTransitionStateChanged`, and `FocusWithinStateChanged` clearly relate to CSS pseudo-classes and triggering style recalculations.
    * `ActivateDisplayLockIfNeeded` suggests a mechanism for controlling rendering updates.
    * The block dealing with `ColumnPseudoElement` indicates the creation and management of specific pseudo-elements.
    * `setInnerHTML`, `setOuterHTML`, and `insertAdjacentHTML` are clearly DOM manipulation functions.
    * The `setPointerCapture` and related functions point to pointer event handling.
    * `EnsureComputedStyle` is a crucial function related to styling.

3. **Identifying Connections to Web Technologies:** As I analyze each function, I actively link it to JavaScript, HTML, and CSS concepts. For instance:
    * Pseudo-class related functions directly tie to CSS selectors.
    * DOM manipulation functions (`innerHTML`, `outerHTML`, `insertAdjacentHTML`) are fundamental JavaScript APIs for interacting with the HTML structure.
    * `DisplayLock` likely relates to performance optimizations or advanced rendering control that developers might indirectly trigger through JavaScript.
    * Pointer capture is a web API exposed through JavaScript.
    * `ComputedStyle` is the core concept in CSSOM, accessible through JavaScript.

4. **Inferring Logic and Potential Issues:** I look for conditional logic (`if` statements) and how different functions interact. The code often checks for feature flags (`RuntimeEnabledFeatures`), suggesting that certain functionalities are experimental or conditionally enabled. I also consider potential user errors or edge cases: trying to set `outerHTML` on an element without a parent, attempting to capture a non-existent pointer, etc.

5. **Tracing User Actions:** I try to imagine how a user interaction might lead to the execution of these code snippets. For example, focusing an element, clicking, hovering, or JavaScript code modifying the DOM could all trigger these functions.

6. **Considering the "Part X of Y" Context:**  Knowing this is part 9 of 13, I understand it's likely a continuation of broader `Element` functionality. This helps in not over-interpreting isolated functions but seeing them as components within a larger system.

7. **Synthesizing the Summary:**  Based on the function-level analysis and the connections to web technologies, I start drafting the summary. I group related functionalities together (e.g., focus-related methods, DOM manipulation methods, etc.) for clarity. I prioritize the core responsibilities and highlight the interactions with JavaScript, HTML, and CSS.

8. **Refining and Organizing:** I review the summary for clarity, conciseness, and accuracy. I ensure that the examples are relevant and easy to understand. I organize the information logically, starting with the core functions and then moving to more specific or less frequent operations. I also make sure to address the specific requests of the prompt (JavaScript/HTML/CSS relations, examples, debugging cues).

9. **Adding the "Part 9" Contextualization:** Finally, I explicitly state that this section focuses on specific aspects of the `Element` class, particularly around state changes, DOM manipulation, and pseudo-element management. This acknowledges the "part X of Y" context.

Essentially, my process is a combination of code reading comprehension, knowledge of web technologies, logical deduction, and structured summarization. I start with the micro-level details and gradually build up to a higher-level understanding of the code's purpose and context.
Based on the provided C++ code snippet from `blink/renderer/core/dom/element.cc`, here's a breakdown of its functionality:

**Core Functionality:**

This section of the `Element.cc` file primarily deals with:

* **Managing Element State and Style Recalculation:**  It handles changes to various element states (like focus, focus-within, view transitions) and triggers style recalculations when necessary. This ensures the visual representation of the element updates correctly based on its state.
* **Pseudo-Class Management:**  It specifically manages the application of pseudo-classes like `:focus-visible`, `:active-view-transition`, `:focus-within`, and potentially others through the `PseudoStateChanged` function and setting style recalculation needs.
* **Focus Management:** It includes logic for setting focus within an element's subtree (`SetHasFocusWithinUpToAncestor`), and determining if an element is a clickable control (`IsClickableControl`).
* **Display Lock Mechanism:**  It implements a `DisplayLock` mechanism to potentially control rendering updates based on element state and ancestor contexts.
* **Pseudo-Element Creation and Management:**  It includes functions for creating and managing column-related pseudo-elements (`CreateColumnPseudoElementIfNeeded`, `GetColumnPseudoElements`, `ClearColumnPseudoElements`) and scroll marker pseudo-elements within them.
* **Tracking Element Properties for Styling:** It maintains flags related to how CSS selectors and features (like `:has()`, logical combinators, multiple `:has()`) affect the element's styling and its ancestors/siblings.
* **Event Dispatching:** It provides methods for dispatching focus and blur events (`DispatchFocusEvent`, `DispatchBlurEvent`, `DispatchFocusInEvent`, `DispatchFocusOutEvent`).
* **innerHTML and outerHTML Manipulation:** It implements the functionality for getting and setting the `innerHTML` and `outerHTML` properties, allowing manipulation of the element's content and the element itself.
* **insertAdjacentHTML/Text/Element:** It provides methods for inserting HTML, text, or other elements at specific positions relative to the current element.
* **Pointer Capture:** It includes methods for setting, releasing, and checking pointer capture on the element.
* **innerText and outerText:** It provides methods for getting the text content of the element and its descendants.
* **Shadow DOM Integration:**  It handles setting and retrieving the shadow pseudo ID for elements within Shadow DOM.
* **Ensuring Computed Style:**  It provides a mechanism (`EnsureComputedStyle`) to force the calculation of an element's computed style, even if it's in a display: none subtree.

**Relationship to JavaScript, HTML, and CSS:**

* **JavaScript:**  These functions are the underlying C++ implementation that supports JavaScript DOM APIs. When JavaScript code interacts with the DOM (e.g., setting `element.innerHTML`, focusing an element, using `element.classList.add('active')`), it often triggers these C++ methods.
    * **Example (JavaScript):** `document.getElementById('myDiv').focus();`  This JavaScript call would eventually lead to the execution of focus-related methods within this `element.cc` file, potentially triggering `FocusVisibleStateChanged` and `SetNeedsStyleRecalc`.
    * **Example (JavaScript):** `myElement.innerHTML = '<p>New content</p>';` This JavaScript call would invoke the `setInnerHTML` method in this file.
* **HTML:** The structure and attributes of HTML elements directly influence the behavior of these functions. For example, the presence of the `nonce` attribute triggers the `HideNonce` logic. The hierarchy of elements in the HTML document is crucial for methods like `SetHasFocusWithinUpToAncestor` and `InsertAdjacent`.
* **CSS:** The CSS styles applied to an element determine which pseudo-classes are active and whether style recalculation is needed.
    * **Example (CSS):**  The CSS rule `:focus-visible` will cause the `FocusVisibleStateChanged` function to be called when the element gains focus and the browser determines that the focus should be visually indicated.
    * **Example (CSS):**  CSS View Transitions will trigger `ActiveViewTransitionStateChanged`.
    * **Example (CSS):** CSS selectors like `:has(:focus-within)` will interact with the flags managed by functions like `SetAffectedBySubjectHas`.

**Logical Inference (Hypothetical Input and Output):**

Let's consider the `FocusVisibleStateChanged` function:

* **Hypothetical Input:**
    * The element has gained focus.
    * The browser's heuristics (or user settings) determine that a focus indicator should be visible (e.g., the user is navigating with the keyboard).
* **Logical Steps:**
    1. The `FocusVisibleStateChanged` function is called.
    2. It checks if the `:focus-visible` pseudo-class needs to trigger a style change.
    3. It calls `SetNeedsStyleRecalc` with the appropriate reason (`kPseudoClass`) and extra data (`g_focus_visible`).
    4. It calls `PseudoStateChanged(CSSSelector::kPseudoFocusVisible)`.
* **Hypothetical Output:**
    * A flag is set indicating that the element's style needs to be recalculated.
    * The `PseudoStateChanged` function likely updates internal state related to active pseudo-classes.
    * The rendering engine will eventually recalculate the element's style, applying any CSS rules associated with the `:focus-visible` pseudo-class.

**Common User or Programming Errors:**

* **Incorrectly manipulating `innerHTML` on elements with shadow roots:** This can lead to unexpected behavior as the shadow DOM is not directly accessible through `innerHTML`.
* **Using `outerHTML` to replace an element, expecting JavaScript references to the old element to still be valid:**  The old element is removed and replaced; existing references will point to a detached node.
* **Misunderstanding the behavior of `insertAdjacentHTML`:** Incorrectly specifying the `where` parameter can lead to elements being inserted in unexpected locations or causing errors.
* **Trying to set `outerHTML` on an element without a parent:** This will throw a `NoModificationAllowedError`.
* **Attempting pointer capture on an element that is not connected to the document or when pointer lock is active:** This will result in an `InvalidStateError`.

**User Operation to Reach This Code (Debugging Clues):**

1. **User Interaction:**
   * **Focusing an element:**  Clicking on a focusable element or navigating using the Tab key. This can trigger `FocusVisibleStateChanged`, `FocusWithinStateChanged`, and related focus management functions.
   * **Clicking an element:** This could involve checking `IsClickableControl`.
   * **Interacting with View Transitions:** Navigating between pages or states that utilize CSS View Transitions could trigger `ActiveViewTransitionStateChanged`.
   * **Using JavaScript to modify the DOM:**
      * Calling `element.innerHTML = ...` will lead to `SetInnerHTMLInternal`.
      * Calling `element.outerHTML = ...` will lead to the `setOuterHTML` logic.
      * Calling `element.insertAdjacentHTML(...)` will execute the `insertAdjacentHTML` method.
      * Calling `element.setPointerCapture(...)` will trigger the pointer capture logic.
   * **Hovering over an element with `:hover` styles or a `:has(:hover)` selector:** While not directly in this snippet, it relates to how style changes are managed.
2. **Browser Processing:**
   * The browser detects the user interaction.
   * Event listeners (if any) are triggered.
   * The browser's rendering engine evaluates the element's state and CSS styles.
   * If a state change occurs (e.g., focus, pseudo-class activation), the corresponding functions in `element.cc` are called.
   * The `SetNeedsStyleRecalc` function is crucial in marking the element (and potentially its ancestors/descendants) for style recalculation.
   * The style recalculation process will eventually re-evaluate the element's styles based on the changes.

**Summary of Functionality (Part 9 of 13):**

This portion of `blink/renderer/core/dom/element.cc` focuses on the **dynamic behavior and manipulation of individual DOM elements**. It manages how elements react to state changes (like focus and view transitions), how their styles are updated in response, and how their content and structure can be modified through JavaScript APIs. It also handles more advanced features like display locks and pointer capture. Essentially, it's responsible for a significant part of the element's lifecycle and its interaction with the rendering engine and JavaScript.

### 提示词
```
这是目录为blink/renderer/core/dom/element.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第9部分，共13部分，请归纳一下它的功能
```

### 源代码
```cpp
ange_type,
                      StyleChangeReasonForTracing::CreateWithExtraData(
                          style_change_reason::kPseudoClass,
                          style_change_extra_data::g_focus_visible));

  PseudoStateChanged(CSSSelector::kPseudoFocusVisible);
}

void Element::ActiveViewTransitionStateChanged() {
  if (!RuntimeEnabledFeatures::ViewTransitionTypesEnabled()) {
    return;
  }
  SetNeedsStyleRecalc(kLocalStyleChange,
                      StyleChangeReasonForTracing::CreateWithExtraData(
                          style_change_reason::kPseudoClass,
                          style_change_extra_data::g_active_view_transition));
  PseudoStateChanged(CSSSelector::kPseudoActiveViewTransition);
}

void Element::ActiveViewTransitionTypeStateChanged() {
  if (!RuntimeEnabledFeatures::ViewTransitionTypesEnabled()) {
    return;
  }
  SetNeedsStyleRecalc(
      kLocalStyleChange,
      StyleChangeReasonForTracing::CreateWithExtraData(
          style_change_reason::kPseudoClass,
          style_change_extra_data::g_active_view_transition_type));
  PseudoStateChanged(CSSSelector::kPseudoActiveViewTransitionType);
}

void Element::FocusWithinStateChanged() {
  if (GetComputedStyle() && GetComputedStyle()->AffectedByFocusWithin()) {
    StyleChangeType change_type =
        GetComputedStyle()->HasPseudoElementStyle(kPseudoIdFirstLetter)
            ? kSubtreeStyleChange
            : kLocalStyleChange;
    SetNeedsStyleRecalc(change_type,
                        StyleChangeReasonForTracing::CreateWithExtraData(
                            style_change_reason::kPseudoClass,
                            style_change_extra_data::g_focus_within));
  }
  PseudoStateChanged(CSSSelector::kPseudoFocusWithin);
}

void Element::SetHasFocusWithinUpToAncestor(bool flag,
                                            Element* ancestor,
                                            bool need_snap_container_search) {
  bool reached_ancestor = false;
  for (Element* element = this;
       element && (need_snap_container_search || !reached_ancestor);
       element = FlatTreeTraversal::ParentElement(*element)) {
    if (!reached_ancestor && element != ancestor) {
      element->SetHasFocusWithin(flag);
      element->FocusWithinStateChanged();
    }
    // If |ancestor| or any of its ancestors is a snap container, that snap
    // container needs to know which one of its descendants newly gained or lost
    // focus even if its own HasFocusWithin state has not changed.
    if (element != this && need_snap_container_search) {
      if (const LayoutBox* box = element->GetLayoutBoxForScrolling()) {
        if (box->Style() && !box->Style()->GetScrollSnapType().is_none) {
          // TODO(crbug.com/340983092): We should be able to just call
          // LocalFrameView::AddPendingSnapUpdate, but that results in a snap
          // which cancels ongoing scroll animations.
          // UpdateFocusDataForSnapAreas should be considered a temporary
          // workaround until the linked bug is addressed.
          box->GetScrollableArea()->UpdateFocusDataForSnapAreas();
        }
      }
    }
    reached_ancestor |= element == ancestor;
  }
}

bool Element::IsClickableControl(Node* node) {
  auto* element = DynamicTo<Element>(node);
  if (!element) {
    return false;
  }
  if (element->IsFormControlElement()) {
    return true;
  }
  Element* host = element->OwnerShadowHost();
  if (host && host->IsFormControlElement()) {
    return true;
  }
  while (node && this != node) {
    if (node->HasActivationBehavior()) {
      return true;
    }
    node = node->ParentOrShadowHostNode();
  }
  return false;
}

bool Element::ActivateDisplayLockIfNeeded(DisplayLockActivationReason reason) {
  if (!GetDocument().GetDisplayLockDocumentState().HasActivatableLocks()) {
    return false;
  }

  HeapVector<Member<Element>> activatable_targets;
  for (Node& ancestor : FlatTreeTraversal::InclusiveAncestorsOf(*this)) {
    auto* ancestor_element = DynamicTo<Element>(ancestor);
    if (!ancestor_element) {
      continue;
    }
    if (auto* context = ancestor_element->GetDisplayLockContext()) {
      // If any of the ancestors is not activatable for the given reason, we
      // can't activate.
      if (context->IsLocked() && !context->IsActivatable(reason)) {
        return false;
      }
      activatable_targets.push_back(ancestor_element);
    }
  }

  bool activated = false;
  for (const auto& target : activatable_targets) {
    if (auto* context = target->GetDisplayLockContext()) {
      if (context->ShouldCommitForActivation(reason)) {
        activated = true;
        context->CommitForActivation(reason);
      }
    }
  }
  return activated;
}

bool Element::HasUndoStack() const {
  if (const ElementRareDataVector* data = GetElementRareData()) {
    return data->HasUndoStack();
  }
  return false;
}

void Element::SetHasUndoStack(bool value) {
  EnsureElementRareData().SetHasUndoStack(value);
}

void Element::SetPseudoElementStylesChangeCounters(bool value) {
  EnsureElementRareData().SetPseudoElementStylesChangeCounters(value);
}

ColumnPseudoElement* Element::CreateColumnPseudoElementIfNeeded(
    wtf_size_t index,
    const PhysicalRect& column_rect) {
  if (const ComputedStyle* style = GetComputedStyle();
      !style || !style->HasPseudoElementStyle(kPseudoIdColumn)) {
    return nullptr;
  }
  auto* column_pseudo_element = MakeGarbageCollected<ColumnPseudoElement>(
      /*originating_element=*/this, index, column_rect);
  const ComputedStyle* style =
      column_pseudo_element->CustomStyleForLayoutObject(
          StyleRecalcContext::FromInclusiveAncestors(*this));
  if (!style) {
    style = &GetDocument().GetStyleResolver().InitialStyle();
  }
  column_pseudo_element->SetComputedStyle(style);
  ElementRareDataVector& data = EnsureElementRareData();
  data.AddColumnPseudoElement(*column_pseudo_element);
  column_pseudo_element->InsertedInto(*this);
  probe::PseudoElementCreated(column_pseudo_element);
  if (!style->CanGeneratePseudoElement(kPseudoIdScrollMarker)) {
    return column_pseudo_element;
  }

  auto* scroll_marker =
      MakeGarbageCollected<ScrollMarkerPseudoElement>(column_pseudo_element);
  const ComputedStyle* scroll_marker_style =
      scroll_marker->CustomStyleForLayoutObject(
          StyleRecalcContext::FromInclusiveAncestors(*column_pseudo_element));
  if (!scroll_marker_style) {
    scroll_marker->Dispose();
    return column_pseudo_element;
  }

  scroll_marker->SetComputedStyle(scroll_marker_style);
  column_pseudo_element->EnsureElementRareData().SetPseudoElement(
      kPseudoIdScrollMarker, scroll_marker);
  scroll_marker->InsertedInto(*column_pseudo_element);
  probe::PseudoElementCreated(scroll_marker);

  return column_pseudo_element;
}

const ColumnPseudoElementsVector* Element::GetColumnPseudoElements() const {
  ElementRareDataVector* data = GetElementRareData();
  if (!data) {
    return nullptr;
  }
  return data->GetColumnPseudoElements();
}

void Element::ClearColumnPseudoElements() {
  ElementRareDataVector* data = GetElementRareData();
  if (!data) {
    return;
  }
  if (const ColumnPseudoElementsVector* column_pseudo_elements =
          data->GetColumnPseudoElements()) {
    for (PseudoElement* column_pseudo_element : *column_pseudo_elements) {
      if (ElementRareDataVector* column_data =
              column_pseudo_element->GetElementRareData()) {
        column_data->ClearPseudoElements();
      }
    }
  }
  data->ClearColumnPseudoElements();
}

void Element::SetScrollbarPseudoElementStylesDependOnFontMetrics(bool value) {
  EnsureElementRareData().SetScrollbarPseudoElementStylesDependOnFontMetrics(
      value);
}

bool Element::HasBeenExplicitlyScrolled() const {
  if (const ElementRareDataVector* data = GetElementRareData()) {
    return data->HasBeenExplicitlyScrolled();
  }
  return false;
}

void Element::SetHasBeenExplicitlyScrolled() {
  EnsureElementRareData().SetHasBeenExplicitlyScrolled();
}

bool Element::AffectedBySubjectHas() const {
  if (const ElementRareDataVector* data = GetElementRareData()) {
    return data->AffectedBySubjectHas();
  }
  return false;
}

void Element::SetAffectedBySubjectHas() {
  EnsureElementRareData().SetAffectedBySubjectHas();
}

bool Element::AffectedByNonSubjectHas() const {
  if (const ElementRareDataVector* data = GetElementRareData()) {
    return data->AffectedByNonSubjectHas();
  }
  return false;
}

void Element::SetAffectedByNonSubjectHas() {
  EnsureElementRareData().SetAffectedByNonSubjectHas();
}

bool Element::AncestorsOrAncestorSiblingsAffectedByHas() const {
  if (const ElementRareDataVector* data = GetElementRareData()) {
    return data->AncestorsOrAncestorSiblingsAffectedByHas();
  }
  return false;
}

void Element::SetAncestorsOrAncestorSiblingsAffectedByHas() {
  EnsureElementRareData().SetAncestorsOrAncestorSiblingsAffectedByHas();
}

unsigned Element::GetSiblingsAffectedByHasFlags() const {
  if (const ElementRareDataVector* data = GetElementRareData()) {
    return data->GetSiblingsAffectedByHasFlags();
  }
  return false;
}

bool Element::HasSiblingsAffectedByHasFlags(unsigned flags) const {
  if (const ElementRareDataVector* data = GetElementRareData()) {
    return data->HasSiblingsAffectedByHasFlags(flags);
  }
  return false;
}

void Element::SetSiblingsAffectedByHasFlags(unsigned flags) {
  EnsureElementRareData().SetSiblingsAffectedByHasFlags(flags);
}

bool Element::AffectedByPseudoInHas() const {
  if (const ElementRareDataVector* data = GetElementRareData()) {
    return data->AffectedByPseudoInHas();
  }
  return false;
}

void Element::SetAffectedByPseudoInHas() {
  EnsureElementRareData().SetAffectedByPseudoInHas();
}

bool Element::AncestorsOrSiblingsAffectedByHoverInHas() const {
  if (const ElementRareDataVector* data = GetElementRareData()) {
    return data->AncestorsOrSiblingsAffectedByHoverInHas();
  }
  return false;
}

void Element::SetAncestorsOrSiblingsAffectedByHoverInHas() {
  EnsureElementRareData().SetAncestorsOrSiblingsAffectedByHoverInHas();
}

bool Element::AncestorsOrSiblingsAffectedByActiveInHas() const {
  if (const ElementRareDataVector* data = GetElementRareData()) {
    return data->AncestorsOrSiblingsAffectedByActiveInHas();
  }
  return false;
}

void Element::SetAncestorsOrSiblingsAffectedByActiveInHas() {
  EnsureElementRareData().SetAncestorsOrSiblingsAffectedByActiveInHas();
}

bool Element::AncestorsOrSiblingsAffectedByFocusInHas() const {
  if (const ElementRareDataVector* data = GetElementRareData()) {
    return data->AncestorsOrSiblingsAffectedByFocusInHas();
  }
  return false;
}

void Element::SetAncestorsOrSiblingsAffectedByFocusInHas() {
  EnsureElementRareData().SetAncestorsOrSiblingsAffectedByFocusInHas();
}

bool Element::AncestorsOrSiblingsAffectedByFocusVisibleInHas() const {
  if (const ElementRareDataVector* data = GetElementRareData()) {
    return data->AncestorsOrSiblingsAffectedByFocusVisibleInHas();
  }
  return false;
}

void Element::SetAncestorsOrSiblingsAffectedByFocusVisibleInHas() {
  EnsureElementRareData().SetAncestorsOrSiblingsAffectedByFocusVisibleInHas();
}

bool Element::AffectedByLogicalCombinationsInHas() const {
  if (const ElementRareDataVector* data = GetElementRareData()) {
    return data->AffectedByLogicalCombinationsInHas();
  }
  return false;
}

void Element::SetAffectedByLogicalCombinationsInHas() {
  EnsureElementRareData().SetAffectedByLogicalCombinationsInHas();
}

bool Element::AffectedByMultipleHas() const {
  if (const ElementRareDataVector* data = GetElementRareData()) {
    return data->AffectedByMultipleHas();
  }
  return false;
}

void Element::SetAffectedByMultipleHas() {
  EnsureElementRareData().SetAffectedByMultipleHas();
}

bool Element::IsFocusedElementInDocument() const {
  return this == GetDocument().FocusedElement();
}

Element* Element::AdjustedFocusedElementInTreeScope() const {
  return IsInTreeScope() ? GetTreeScope().AdjustedFocusedElement() : nullptr;
}

bool Element::DispatchFocusEvent(Element* old_focused_element,
                                 mojom::blink::FocusType type,
                                 InputDeviceCapabilities* source_capabilities) {
  Document& document = GetDocument();
  if (DispatchEvent(*FocusEvent::Create(
          event_type_names::kFocus, Event::Bubbles::kNo, document.domWindow(),
          0, old_focused_element, source_capabilities)) !=
      DispatchEventResult::kNotCanceled) {
    return false;
  }
  return true;
}

void Element::DispatchBlurEvent(Element* new_focused_element,
                                mojom::blink::FocusType type,
                                InputDeviceCapabilities* source_capabilities) {
  DispatchEvent(*FocusEvent::Create(
      event_type_names::kBlur, Event::Bubbles::kNo, GetDocument().domWindow(),
      0, new_focused_element, source_capabilities));
}

void Element::DispatchFocusInEvent(
    const AtomicString& event_type,
    Element* old_focused_element,
    mojom::blink::FocusType,
    InputDeviceCapabilities* source_capabilities) {
#if DCHECK_IS_ON()
  DCHECK(!EventDispatchForbiddenScope::IsEventDispatchForbidden());
#endif
  DCHECK(event_type == event_type_names::kFocusin ||
         event_type == event_type_names::kDOMFocusIn);
  DispatchScopedEvent(*FocusEvent::Create(
      event_type, Event::Bubbles::kYes, GetDocument().domWindow(), 0,
      old_focused_element, source_capabilities));
}

void Element::DispatchFocusOutEvent(
    const AtomicString& event_type,
    Element* new_focused_element,
    InputDeviceCapabilities* source_capabilities) {
#if DCHECK_IS_ON()
  DCHECK(!EventDispatchForbiddenScope::IsEventDispatchForbidden());
#endif
  DCHECK(event_type == event_type_names::kFocusout ||
         event_type == event_type_names::kDOMFocusOut);
  DispatchScopedEvent(*FocusEvent::Create(
      event_type, Event::Bubbles::kYes, GetDocument().domWindow(), 0,
      new_focused_element, source_capabilities));
}

String Element::innerHTML() const {
  return CreateMarkup(this, kChildrenOnly);
}

String Element::outerHTML() const {
  return CreateMarkup(this);
}

void Element::SetInnerHTMLInternal(
    const String& html,
    ParseDeclarativeShadowRoots parse_declarative_shadows,
    ForceHtml force_html,
    SanitizeHtml sanitize_html,
    SetHTMLOptions* set_html_options,
    ExceptionState& exception_state) {
  if (html.empty() && !HasNonInBodyInsertionMode()) {
    setTextContent(html);
  } else {
    if (DocumentFragment* fragment = CreateFragmentForInnerOuterHTML(
            html, this, kAllowScriptingContent, parse_declarative_shadows,
            force_html, exception_state)) {
      if (RuntimeEnabledFeatures::SanitizerAPIEnabled()) {
        // TODO(vogelheim): Not sure if this is the correct point in time for
        // sanitization. It should be before the parse result is connected to
        // a live DOM tree. But I'm not sure (yet) how this interacts with the
        // DOMParts handling below.
        if (sanitize_html == SanitizeHtml::kSanitizeSafe) {
          SanitizerAPI::SanitizeSafeInternal(fragment, set_html_options,
                                             exception_state);
        } else if (sanitize_html == SanitizeHtml::kSanitizeUnsafe) {
          SanitizerAPI::SanitizeUnsafeInternal(fragment, set_html_options,
                                               exception_state);
        }
      }
      ContainerNode* container = this;
      bool swap_dom_parts{false};
      if (auto* template_element = DynamicTo<HTMLTemplateElement>(*this)) {
        container = template_element->content();
        swap_dom_parts =
            RuntimeEnabledFeatures::DOMPartsAPIEnabled() &&
            template_element->hasAttribute(html_names::kParsepartsAttr);
      }
      ReplaceChildrenWithFragment(container, fragment, exception_state);
      if (swap_dom_parts &&
          !RuntimeEnabledFeatures::DOMPartsAPIMinimalEnabled()) {
        // Move the parts list over to the template's content document's
        // DocumentPartRoot.
        To<DocumentFragment>(*container)
            .getPartRoot()
            .SwapPartsList(fragment->getPartRoot());
      }
    }
  }
}

void Element::setInnerHTML(const String& html,
                           ExceptionState& exception_state) {
  probe::BreakableLocation(GetExecutionContext(), "Element.setInnerHTML");
  SetInnerHTMLInternal(html, ParseDeclarativeShadowRoots::kDontParse,
                       ForceHtml::kDontForce, SanitizeHtml::kDont,
                       /*set_html_options=*/nullptr, exception_state);
}

void Element::setOuterHTML(const String& html,
                           ExceptionState& exception_state) {
  Node* p = parentNode();
  if (!p) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNoModificationAllowedError,
        "This element has no parent node.");
    return;
  }

  auto* parent = DynamicTo<Element>(p);
  if (!parent) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNoModificationAllowedError,
        "This element's parent is of type '" + p->nodeName() +
            "', which is not an element node.");
    return;
  }

  Node* prev = previousSibling();
  Node* next = nextSibling();

  DocumentFragment* fragment =
      CreateFragmentForInnerOuterHTML(html, parent, kAllowScriptingContent,
                                      ParseDeclarativeShadowRoots::kDontParse,
                                      ForceHtml::kDontForce, exception_state);
  if (exception_state.HadException()) {
    return;
  }

  parent->ReplaceChild(fragment, this, exception_state);
  if (exception_state.HadException()) {
    return;
  }

  Node* node = next ? next->previousSibling() : nullptr;
  if (auto* text = DynamicTo<Text>(node)) {
    MergeWithNextTextNode(text, exception_state);
    if (exception_state.HadException()) {
      return;
    }
  }

  if (auto* prev_text = DynamicTo<Text>(prev)) {
    MergeWithNextTextNode(prev_text, exception_state);
    if (exception_state.HadException()) {
      return;
    }
  }
}

// Step 4 of http://domparsing.spec.whatwg.org/#insertadjacenthtml()
Node* Element::InsertAdjacent(const String& where,
                              Node* new_child,
                              ExceptionState& exception_state) {
  if (EqualIgnoringASCIICase(where, "beforeBegin")) {
    if (ContainerNode* parent = parentNode()) {
      parent->InsertBefore(new_child, this, exception_state);
      if (!exception_state.HadException()) {
        return new_child;
      }
    }
    return nullptr;
  }

  if (EqualIgnoringASCIICase(where, "afterBegin")) {
    InsertBefore(new_child, firstChild(), exception_state);
    return exception_state.HadException() ? nullptr : new_child;
  }

  if (EqualIgnoringASCIICase(where, "beforeEnd")) {
    AppendChild(new_child, exception_state);
    return exception_state.HadException() ? nullptr : new_child;
  }

  if (EqualIgnoringASCIICase(where, "afterEnd")) {
    if (ContainerNode* parent = parentNode()) {
      parent->InsertBefore(new_child, nextSibling(), exception_state);
      if (!exception_state.HadException()) {
        return new_child;
      }
    }
    return nullptr;
  }

  exception_state.ThrowDOMException(
      DOMExceptionCode::kSyntaxError,
      "The value provided ('" + where +
          "') is not one of 'beforeBegin', 'afterBegin', "
          "'beforeEnd', or 'afterEnd'.");
  return nullptr;
}

void Element::HideNonce() {
  // This is a relatively hot codepath.  Get to the common early return as
  // fast as possible.
  const AtomicString& nonce_value = FastGetAttribute(html_names::kNonceAttr);
  if (nonce_value.empty()) {
    return;
  }
  if (GetDocument().StatePreservingAtomicMoveInProgress()) {
    return;
  }
  if (!InActiveDocument()) {
    return;
  }
  if (GetExecutionContext()
          ->GetContentSecurityPolicy()
          ->HasHeaderDeliveredPolicy()) {
    setAttribute(html_names::kNonceAttr, g_empty_atom);
  }
}

ElementIntersectionObserverData* Element::IntersectionObserverData() const {
  if (const ElementRareDataVector* data = GetElementRareData()) {
    return data->IntersectionObserverData();
  }
  return nullptr;
}

ElementIntersectionObserverData& Element::EnsureIntersectionObserverData() {
  return EnsureElementRareData().EnsureIntersectionObserverData();
}

HeapHashMap<Member<ResizeObserver>, Member<ResizeObservation>>*
Element::ResizeObserverData() const {
  if (const ElementRareDataVector* data = GetElementRareData()) {
    return data->ResizeObserverData();
  }
  return nullptr;
}

HeapHashMap<Member<ResizeObserver>, Member<ResizeObservation>>&
Element::EnsureResizeObserverData() {
  return EnsureElementRareData().EnsureResizeObserverData();
}

DisplayLockContext* Element::GetDisplayLockContextFromRareData() const {
  DCHECK(HasDisplayLockContext());
  DCHECK(GetElementRareData());
  return GetElementRareData()->GetDisplayLockContext();
}

DisplayLockContext& Element::EnsureDisplayLockContext() {
  SetHasDisplayLockContext();
  return *EnsureElementRareData().EnsureDisplayLockContext(this);
}

ContainerQueryData* Element::GetContainerQueryData() const {
  if (const ElementRareDataVector* data = GetElementRareData()) {
    return data->GetContainerQueryData();
  }
  return nullptr;
}

ContainerQueryEvaluator* Element::GetContainerQueryEvaluator() const {
  if (const ContainerQueryData* cq_data = GetContainerQueryData()) {
    return cq_data->GetContainerQueryEvaluator();
  }
  return nullptr;
}

ContainerQueryEvaluator& Element::EnsureContainerQueryEvaluator() {
  ContainerQueryData& data = EnsureElementRareData().EnsureContainerQueryData();
  ContainerQueryEvaluator* evaluator = data.GetContainerQueryEvaluator();
  if (!evaluator) {
    evaluator = MakeGarbageCollected<ContainerQueryEvaluator>(*this);
    data.SetContainerQueryEvaluator(evaluator);
  }
  return *evaluator;
}

StyleScopeData& Element::EnsureStyleScopeData() {
  return EnsureElementRareData().EnsureStyleScopeData();
}

StyleScopeData* Element::GetStyleScopeData() const {
  if (const ElementRareDataVector* data = GetElementRareData()) {
    return data->GetStyleScopeData();
  }
  return nullptr;
}

OutOfFlowData& Element::EnsureOutOfFlowData() {
  return EnsureElementRareData().EnsureOutOfFlowData();
}

OutOfFlowData* Element::GetOutOfFlowData() const {
  if (const ElementRareDataVector* data = GetElementRareData()) {
    return data->GetOutOfFlowData();
  }
  return nullptr;
}

bool Element::SkippedContainerStyleRecalc() const {
  if (const ContainerQueryData* cq_data = GetContainerQueryData()) {
    return cq_data->SkippedStyleRecalc();
  }
  return false;
}

// Step 1 of http://domparsing.spec.whatwg.org/#insertadjacenthtml()
static Node* ContextNodeForInsertion(const String& where,
                                     Element* element,
                                     ExceptionState& exception_state) {
  if (EqualIgnoringASCIICase(where, "beforeBegin") ||
      EqualIgnoringASCIICase(where, "afterEnd")) {
    Node* parent = element->parentNode();
    if (!parent || IsA<Document>(parent)) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kNoModificationAllowedError,
          "The element has no parent.");
      return nullptr;
    }
    return parent;
  }
  if (EqualIgnoringASCIICase(where, "afterBegin") ||
      EqualIgnoringASCIICase(where, "beforeEnd")) {
    return element;
  }
  exception_state.ThrowDOMException(
      DOMExceptionCode::kSyntaxError,
      "The value provided ('" + where +
          "') is not one of 'beforeBegin', 'afterBegin', "
          "'beforeEnd', or 'afterEnd'.");
  return nullptr;
}

Element* Element::insertAdjacentElement(const String& where,
                                        Element* new_child,
                                        ExceptionState& exception_state) {
  Node* return_value = InsertAdjacent(where, new_child, exception_state);
  return To<Element>(return_value);
}

void Element::insertAdjacentText(const String& where,
                                 const String& text,
                                 ExceptionState& exception_state) {
  InsertAdjacent(where, GetDocument().createTextNode(text), exception_state);
}

void Element::insertAdjacentHTML(const String& where,
                                 const String& markup,
                                 ExceptionState& exception_state) {
  Node* context_node = ContextNodeForInsertion(where, this, exception_state);
  if (!context_node) {
    return;
  }

  // Step 2 of http://domparsing.spec.whatwg.org/#insertadjacenthtml()
  Element* context_element;
  if (!IsA<Element>(context_node) ||
      (IsA<HTMLDocument>(context_node->GetDocument()) &&
       IsA<HTMLHtmlElement>(context_node))) {
    context_element =
        MakeGarbageCollected<HTMLBodyElement>(context_node->GetDocument());
  } else {
    context_element = To<Element>(context_node);
  }

  // Step 3 of http://domparsing.spec.whatwg.org/#insertadjacenthtml()
  DocumentFragment* fragment = CreateFragmentForInnerOuterHTML(
      markup, context_element, kAllowScriptingContent,
      ParseDeclarativeShadowRoots::kDontParse, ForceHtml::kDontForce,
      exception_state);
  if (!fragment) {
    return;
  }
  InsertAdjacent(where, fragment, exception_state);
}

void Element::setPointerCapture(PointerId pointer_id,
                                ExceptionState& exception_state) {
  if (GetDocument().GetFrame()) {
    if (!GetDocument().GetFrame()->GetEventHandler().IsPointerEventActive(
            pointer_id)) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kNotFoundError,
          "No active pointer with the given id is found.");
    } else if (!isConnected() ||
               (GetDocument().GetPage() && GetDocument()
                                               .GetPage()
                                               ->GetPointerLockController()
                                               .GetElement())) {
      exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                        "InvalidStateError");
    } else {
      GetDocument().GetFrame()->GetEventHandler().SetPointerCapture(
          pointer_id, this, /* explicit_capture */ true);
    }
  }
}

void Element::releasePointerCapture(PointerId pointer_id,
                                    ExceptionState& exception_state) {
  if (GetDocument().GetFrame()) {
    if (!GetDocument().GetFrame()->GetEventHandler().IsPointerEventActive(
            pointer_id)) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kNotFoundError,
          "No active pointer with the given id is found.");
    } else {
      GetDocument().GetFrame()->GetEventHandler().ReleasePointerCapture(
          pointer_id, this);
    }
  }
}

bool Element::hasPointerCapture(PointerId pointer_id) const {
  return GetDocument().GetFrame() &&
         GetDocument().GetFrame()->GetEventHandler().HasPointerCapture(
             pointer_id, this);
}

String Element::outerText() {
  // Getting outerText is the same as getting innerText, only
  // setting is different. You would think this should get the plain
  // text for the outer range, but this is wrong, <br> for instance
  // would return different values for inner and outer text by such
  // a rule, but it doesn't in WinIE, and we want to match that.
  return innerText();
}

String Element::TextFromChildren() {
  Text* first_text_node = nullptr;
  bool found_multiple_text_nodes = false;
  unsigned total_length = 0;

  for (Node* child = firstChild(); child; child = child->nextSibling()) {
    auto* child_text_node = DynamicTo<Text>(child);
    if (!child_text_node) {
      continue;
    }
    if (!first_text_node) {
      first_text_node = child_text_node;
    } else {
      found_multiple_text_nodes = true;
    }
    unsigned length = child_text_node->data().length();
    if (length > std::numeric_limits<unsigned>::max() - total_length) {
      return g_empty_string;
    }
    total_length += length;
  }

  if (!first_text_node) {
    return g_empty_string;
  }

  if (first_text_node && !found_multiple_text_nodes) {
    first_text_node->MakeParkable();
    return first_text_node->data();
  }

  StringBuilder content;
  content.ReserveCapacity(total_length);
  for (Node* child = first_text_node; child; child = child->nextSibling()) {
    auto* child_text_node = DynamicTo<Text>(child);
    if (!child_text_node) {
      continue;
    }
    content.Append(child_text_node->data());
  }

  DCHECK_EQ(content.length(), total_length);
  return content.ReleaseString();
}

const AtomicString& Element::ShadowPseudoId() const {
  if (ShadowRoot* root = ContainingShadowRoot()) {
    if (root->IsUserAgent()) {
      return FastGetAttribute(html_names::kPseudoAttr);
    }
  }
  return g_null_atom;
}

void Element::SetShadowPseudoId(const AtomicString& id) {
#if DCHECK_IS_ON()
  {
    // NOTE: This treats "cue" as kPseudoWebKitCustomElement, so "cue"
    // is allowed here.
    CSSSelector::PseudoType type =
        CSSSelectorParser::ParsePseudoType(id, false, &GetDocument());
    DCHECK(type == CSSSelector::kPseudoWebKitCustomElement ||
           type == CSSSelector::kPseudoBlinkInternalElement ||
           type == CSSSelector::kPseudoDetailsContent ||
           type == CSSSelector::kPseudoCheck ||
           id == shadow_element_names::kPickerSelect)
        << "type: " << type << ", id: " << id;
  }
#endif
  setAttribute(html_names::kPseudoAttr, id);
}

bool Element::IsInDescendantTreeOf(const Element* shadow_host) const {
  DCHECK(shadow_host);
  DCHECK(IsShadowHost(shadow_host));

  for (const Element* ancestor_shadow_host = OwnerShadowHost();
       ancestor_shadow_host;
       ancestor_shadow_host = ancestor_shadow_host->OwnerShadowHost()) {
    if (ancestor_shadow_host == shadow_host) {
      return true;
    }
  }
  return false;
}

namespace {

bool NeedsEnsureComputedStyle(Element& element) {
  const ComputedStyle* style = element.GetComputedStyle();
  return !style || style->IsEnsuredOutsideFlatTree();
}

HeapVector<Member<Element>> CollectAncestorsToEnsure(Element& element) {
  HeapVector<Member<Element>> ancestors;

  Element* ancestor = &element;
  while ((ancestor = DynamicTo<Element>(
              LayoutTreeBuilderTraversal::Parent(*ancestor)))) {
    if (!NeedsEnsureComputedStyle(*ancestor)) {
      break;
    }
    ancestors.push_back(ancestor);
  }

  return ancestors;
}

}  // namespace

const ComputedStyle* Element::EnsureComputedStyle(
    PseudoId pseudo_element_specifier,
    const AtomicString& pseudo_argument) {
  // Style computation should not be triggered when in a NoAllocationScope
  // because there is always a possibility that it could allocate something on
  // the V8 heap.
  DCHECK(ThreadState::Current()->IsAllocationAllowed());

  StyleEngine::InEnsureComputedStyleScope ensure_scope(
      GetDocument().GetStyleEngine());

  if (Element* element =
          GetStyledPseudoElement(pseudo_element_specifier, pseudo_argument)) {
    return element->EnsureComputedStyle();
  }

  if (!InActiveDocument()) {
    return nullptr;
  }

  // EnsureComputedStyle is expected to be called to forcibly compute style for
  // elements in display:none subtrees on otherwise style-clean documents. If
  // you hit this DCHECK, consider if you really need ComputedStyle for
  // display:none elements. If not, use GetComputedStyle() instead.
  // Regardless, you need to UpdateStyleAndLayoutTree() before calling
  // EnsureComputedStyle. In some cases you might be fine using GetComputedStyle
  // without updating the style, but in most cases you want a clean tree for
  // that as well.
  DCHECK(
      !GetDocument().NeedsLayoutTreeUpdateForNodeIncludingDisplayLocked(*this));

  // EnsureComputedStyle is called even for rendered elements which have a non-
  // null ComputedStyle already. Early out to avoid the expensive setup below.
  if (pseudo_element_specifier == kPseudoIdNone) {
    if (const ComputedStyle* style =
            ComputedStyle::NullifyEnsured(GetComputedStyle())) {
      return style;
    }
  }

  // Retrieve a list of (non-inclusive) ancestors that we need to ensure the
  // ComputedStyle for *before* we can ensure the ComputedStyle for this
  // element. Note that the list of ancestors can be empty if |this| is the
  // root of the display:none subtree.
  //
  // The front() element is the LayoutTreeBuilderTraversal::Parent of |this|,
  // and the back() element is the "top-most" ancestor in the chain.
  HeapVector<Member<Element>> ancestors = CollectAncestorsToEnsure(*this);

  Element* top = ancestors.empty() ? this : ancestors.back().Get();

  // Prepare the selector filter to fast reject rules.
  Element* filter_root = FlatTree
```