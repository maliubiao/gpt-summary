Response:
My thinking process for summarizing the provided code snippet and addressing the prompt's requirements goes like this:

1. **Understand the Goal:** The primary goal is to summarize the functionality of the provided C++ code snippet from Chromium's Blink rendering engine, specifically focusing on `blink/renderer/core/dom/element.cc`. I also need to relate this functionality to web technologies (JavaScript, HTML, CSS), provide examples, address potential user errors, explain how a user might reach this code, and acknowledge this is part 2 of a larger file.

2. **Initial Code Scan and Keyword Identification:** I'll quickly scan the code for recurring patterns, keywords, and function names. In this snippet, I see:
    * `Clone`, `CloneWithChildren`, `CloneWithoutChildren`, `CloneWithoutAttributesAndChildren`:  These strongly suggest object duplication.
    * `Attribute`, `setAttribute`, `removeAttribute`, `getAttribute`:  These clearly deal with managing element attributes.
    * `ShadowRoot`, `AttachShadowRootInternal`, `GetShadowRoot`:  This points to shadow DOM functionality.
    * `GetElementAttribute`, `SetElementAttribute`, `GetAttrAssociatedElements`: These handle attributes that refer to other elements.
    * `scrollIntoView`, `OffsetLeft`, `OffsetTop`, `OffsetWidth`, `OffsetHeight`, `OffsetParent`:  These are related to element geometry and scrolling.
    * `aria-*`: These indicate ARIA attribute handling for accessibility.
    * `InterestEvent`, `interestTargetElement`, `interestAction`: This suggests handling user interest/interaction.
    * `NamedNodeMap`, `ElementAnimations`, `PopoverData`:  These point to internal data structures.

3. **Group Functionality by Theme:**  Based on the identified keywords, I can group the functionalities:
    * **Cloning:** Duplicating elements, including handling child nodes, attributes, and shadow DOM.
    * **Attribute Management:** Setting, getting, removing, and managing attributes (both string and element-referencing).
    * **Shadow DOM:**  Cloning shadow roots and accessing reference targets.
    * **Element Geometry and Scrolling:**  Getting offsets, dimensions, and scrolling elements into view.
    * **ARIA Attributes:** Specific functions for getting and setting ARIA attributes that refer to other elements.
    * **Internal Data:** Managing internal data structures related to attributes, animations, and popovers.
    * **Interest/Interaction:** Handling "interest" events.

4. **Summarize Each Theme:** I'll write a concise summary for each group of functionalities, using clear and understandable language. I'll avoid overly technical jargon where possible.

5. **Relate to JavaScript, HTML, and CSS:** For each functionality, I'll think about how it manifests in web technologies:
    * **Cloning:**  `cloneNode()` in JavaScript. HTML structures being copied. CSS styles being inherited.
    * **Attributes:**  `element.setAttribute()`, `element.getAttribute()`, `element.removeAttribute()` in JavaScript. HTML attributes directly. CSS selectors based on attributes.
    * **Shadow DOM:** `attachShadow()` in JavaScript. `<slot>` elements in HTML. CSS styling within shadow roots.
    * **Geometry and Scrolling:** `element.offsetLeft`, `element.offsetTop`, `element.scrollIntoView()` in JavaScript. Element positioning in HTML. CSS layout and scrolling properties.
    * **ARIA:**  ARIA attributes directly in HTML. JavaScript manipulation of ARIA attributes. CSS styling based on ARIA attributes.
    * **Interest:** Event listeners in JavaScript. Potentially new HTML attributes related to interest (though less direct).

6. **Provide Examples:**  I'll create simple, illustrative examples for each relationship between the C++ code and web technologies. These examples will show how the underlying C++ functionality is used in practice.

7. **Address Logic and Assumptions:**  For functions like `Clone`, I can infer the logic based on the function names and parameters (e.g., cloning with or without children). I can describe the assumed input (an element) and the expected output (a new element).

8. **Identify User/Programming Errors:**  I'll consider common mistakes developers might make when interacting with these functionalities:
    * Incorrect attribute names.
    * Trying to clone elements in an invalid context.
    * Misunderstanding how element attributes work.
    * Incorrectly using scrolling methods.
    * Setting ARIA attributes to invalid element IDs.

9. **Explain User Steps to Reach the Code:** I'll outline a plausible sequence of user actions that would trigger the execution of the code, focusing on the DOM manipulation aspects. This helps illustrate the practical context of the code.

10. **Acknowledge Part 2 of 13:**  I will explicitly state that this is part 2 and that the summary focuses on the provided snippet.

11. **Review and Refine:**  Finally, I'll review the entire summary for clarity, accuracy, and completeness, ensuring that it addresses all aspects of the prompt. I'll check for any logical inconsistencies or areas where the explanation could be improved. For example, I initially might not have explicitly linked the `DCHECK` statements to internal consistency checks, so I would add that. I would also ensure the language is accessible to someone with a general understanding of web development concepts.
```cpp
anvas() &&
             layout_object->StyleRef().IsFocusable();
    }
  }

  return false;
}

Node* Element::Clone(Document& factory,
                     NodeCloningData& data,
                     ContainerNode* append_to,
                     ExceptionState& append_exception_state) const {
  Element* copy;
  if (!data.Has(CloneOption::kIncludeDescendants)) {
    copy = &CloneWithoutChildren(data, &factory);
    if (append_to) {
      append_to->AppendChild(copy, append_exception_state);
    }
  } else {
    copy =
        &CloneWithChildren(data, &factory, append_to, append_exception_state);
  }
  // 7. If node is a shadow host whose shadow root’s clonable is true:
  auto* shadow_root = GetShadowRoot();
  if (!shadow_root) {
    return copy;
  }
  if (shadow_root->clonable()) {
    if (shadow_root->GetMode() == ShadowRootMode::kOpen ||
        shadow_root->GetMode() == ShadowRootMode::kClosed) {
      // 7.1 Run attach a shadow root with copy, node’s shadow root’s mode,
      // true, node’s shadow root’s delegates focus, and node’s shadow root’s
      // slot assignment.
      // TODO(crbug.com/1523816): it seems like the `registry` parameter should
      // not always be nullptr.
      ShadowRoot& cloned_shadow_root = copy->AttachShadowRootInternal(
          shadow_root->GetMode(),
          shadow_root->delegatesFocus() ? FocusDelegation::kDelegateFocus
                                        : FocusDelegation::kNone,
          shadow_root->GetSlotAssignmentMode(), /*registry*/ nullptr,
          shadow_root->serializable(),
          /*clonable*/ true, shadow_root->referenceTarget());

      // 7.2 Set copy’s shadow root’s declarative to node’s shadow root’s
      // declarative.
      cloned_shadow_root.SetIsDeclarativeShadowRoot(
          shadow_root->IsDeclarativeShadowRoot());

      // This step is not currently spec'd.
      cloned_shadow_root.SetAvailableToElementInternals(
          shadow_root->IsAvailableToElementInternals());

      // 7.3 If the clone children flag is set, then for each child child of
      // node’s shadow root, in tree order: append the result of cloning child
      // with document and the clone children flag set, to copy’s shadow root.
      NodeCloningData shadow_data{CloneOption::kIncludeDescendants};
      cloned_shadow_root.CloneChildNodesFrom(*shadow_root, shadow_data);
    }
  }
  return copy;
}

Element& Element::CloneWithChildren(
    NodeCloningData& data,
    Document* nullable_factory,
    ContainerNode* append_to,
    ExceptionState& append_exception_state) const {
  Element& clone = CloneWithoutAttributesAndChildren(
      nullable_factory ? *nullable_factory : GetDocument());
  // This will catch HTML elements in the wrong namespace that are not correctly
  // copied. This is a sanity check as HTML overloads some of the DOM methods.
  DCHECK_EQ(IsHTMLElement(), clone.IsHTMLElement());

  clone.CloneAttributesFrom(*this);
  clone.CloneNonAttributePropertiesFrom(*this, data);
  if (data.Has(CloneOption::kPreserveDOMPartsMinimalAPI) && HasNodePart()) {
    DCHECK(RuntimeEnabledFeatures::DOMPartsAPIMinimalEnabled());
    clone.SetHasNodePart();
  } else if (data.Has(CloneOption::kPreserveDOMParts)) {
    PartRoot::CloneParts(*this, clone, data);
  }

  // Append the clone to its parent first, before cloning children. If this is
  // done in the reverse order, each new child will receive treeDepth calls to
  // Node::InsertedInto().
  if (append_to) {
    append_to->AppendChild(&clone, append_exception_state);
  }
  clone.CloneChildNodesFrom(*this, data);
  return clone;
}

Element& Element::CloneWithoutChildren() const {
  NodeCloningData data;
  return CloneWithoutChildren(data);
}

Element& Element::CloneWithoutChildren(NodeCloningData& data,
                                       Document* nullable_factory) const {
  Element& clone = CloneWithoutAttributesAndChildren(
      nullable_factory ? *nullable_factory : GetDocument());
  // This will catch HTML elements in the wrong namespace that are not correctly
  // copied. This is a sanity check as HTML overloads some of the DOM methods.
  DCHECK_EQ(IsHTMLElement(), clone.IsHTMLElement());

  clone.CloneAttributesFrom(*this);
  clone.CloneNonAttributePropertiesFrom(*this, data);
  if (data.Has(CloneOption::kPreserveDOMPartsMinimalAPI) && HasNodePart()) {
    DCHECK(RuntimeEnabledFeatures::DOMPartsAPIMinimalEnabled());
    clone.SetHasNodePart();
  } else if (data.Has(CloneOption::kPreserveDOMParts)) {
    PartRoot::CloneParts(*this, clone, data);
  }
  return clone;
}

Element& Element::CloneWithoutAttributesAndChildren(Document& factory) const {
  return *factory.CreateElement(TagQName(), CreateElementFlags::ByCloneNode(),
                                IsValue());
}

Attr* Element::DetachAttribute(wtf_size_t index) {
  DCHECK(HasElementData());
  const Attribute& attribute = GetElementData()->Attributes().at(index);
  Attr* attr_node = AttrIfExists(attribute.GetName());
  if (attr_node) {
    DetachAttrNodeAtIndex(attr_node, index);
  } else {
    attr_node = MakeGarbageCollected<Attr>(GetDocument(), attribute.GetName(),
                                           attribute.Value());
    RemoveAttributeInternal(index, AttributeModificationReason::kDirectly);
  }
  return attr_node;
}

void Element::DetachAttrNodeAtIndex(Attr* attr, wtf_size_t index) {
  DCHECK(attr);
  DCHECK(HasElementData());

  const Attribute& attribute = GetElementData()->Attributes().at(index);
  DCHECK(attribute.GetName() == attr->GetQualifiedName());
  DetachAttrNodeFromElementWithValue(attr, attribute.Value());
  RemoveAttributeInternal(index, AttributeModificationReason::kDirectly);
}

void Element::removeAttribute(const QualifiedName& name) {
  wtf_size_t index = FindAttributeIndex(name);
  if (index == kNotFound) {
    return;
  }

  RemoveAttributeInternal(index, AttributeModificationReason::kDirectly);
}

void Element::SetBooleanAttribute(const QualifiedName& name, bool value) {
  if (value) {
    setAttribute(name, g_empty_atom);
  } else {
    removeAttribute(name);
  }
}

bool Element::HasExplicitlySetAttrAssociatedElements(
    const QualifiedName& name) const {
  return GetExplicitlySetElementsForAttr(name);
}

HeapLinkedHashSet<WeakMember<Element>>*
Element::GetExplicitlySetElementsForAttr(const QualifiedName& name) const {
  ExplicitlySetAttrElementsMap* element_attribute_map =
      GetDocument().GetExplicitlySetAttrElementsMap(this);
  auto it = element_attribute_map->find(name);
  if (it == element_attribute_map->end()) {
    return nullptr;
  }
  const auto& elements = it->value;
  return elements->size() ? elements : nullptr;
}

void Element::SynchronizeContentAttributeAndElementReference(
    const QualifiedName& name) {
  ExplicitlySetAttrElementsMap* element_attribute_map =
      GetDocument().GetExplicitlySetAttrElementsMap(this);
  element_attribute_map->erase(name);
}

void Element::SetElementAttribute(const QualifiedName& name, Element* element) {
  DCHECK(IsElementReflectionAttribute(name))
      << " Element attributes must be added to IsElementReflectionAttribute. "
         "name: "
      << name;
  ExplicitlySetAttrElementsMap* explicitly_set_attr_elements_map =
      GetDocument().GetExplicitlySetAttrElementsMap(this);

  // If the reflected element is explicitly null then we remove the content
  // attribute and the explicitly set attr-element.
  if (!element) {
    explicitly_set_attr_elements_map->erase(name);
    removeAttribute(name);
    return;
  }

  setAttribute(name, g_empty_atom);

  auto result = explicitly_set_attr_elements_map->insert(name, nullptr);
  if (result.is_new_entry) {
    result.stored_value->value =
        MakeGarbageCollected<HeapLinkedHashSet<WeakMember<Element>>>();
  } else {
    result.stored_value->value->clear();
  }
  result.stored_value->value->insert(element);

  if (isConnected()) {
    if (AXObjectCache* cache = GetDocument().ExistingAXObjectCache()) {
      cache->HandleAttributeChanged(name, this);
    }
  }
}

Element* Element::GetShadowReferenceTarget(const QualifiedName& name) const {
  if (!RuntimeEnabledFeatures::ShadowRootReferenceTargetEnabled()) {
    return nullptr;
  }

  // TODO (crbug.com/353750122): Disallow aria-owns from participating in
  // ReferenceTarget.

  if (ShadowRoot* shadow_root = GetShadowRoot()) {
    if (Element* target = shadow_root->referenceTargetElement()) {
      if (Element* inner_target = target->GetShadowReferenceTarget(name)) {
        return inner_target;
      }
      return target;
    }
  }
  return nullptr;
}

Element* Element::GetShadowReferenceTargetOrSelf(const QualifiedName& name) {
  if (Element* target = GetShadowReferenceTarget(name)) {
    return target;
  }
  return this;
}

const Element* Element::GetShadowReferenceTargetOrSelf(
    const QualifiedName& name) const {
  if (Element* target = GetShadowReferenceTarget(name)) {
    return target;
  }
  return this;
}

Element* Element::getElementByIdIncludingDisconnected(
    const Element& element,
    const AtomicString& id) const {
  if (id.empty()) {
    return nullptr;
  }
  if (element.isConnected()) {
    return element.GetTreeScope().getElementById(id);
  }
  // https://html.spec.whatwg.org/#attr-associated-element
  // Attr associated element lookup does not depend on whether the element
  // is connected. However, the TreeOrderedMap that is used for
  // TreeScope::getElementById() only stores connected elements.
  Node& root = element.TreeRoot();
  for (Element& el : ElementTraversal::DescendantsOf(root)) {
    if (el.GetIdAttribute() == id) {
      return &el;
    }
  }
  return nullptr;
}

Element* Element::GetElementAttribute(const QualifiedName& name) const {
  HeapLinkedHashSet<WeakMember<Element>>* element_attribute_vector =
      GetExplicitlySetElementsForAttr(name);
  if (element_attribute_vector) {
    DCHECK_EQ(element_attribute_vector->size(), 1u);
    Element* explicitly_set_element = *(element_attribute_vector->begin());
    DCHECK_NE(explicitly_set_element, nullptr);

    // Only return the explicit element if it still exists within a valid scope.
    if (!ElementIsDescendantOfShadowIncludingAncestor(
            *this, *explicitly_set_element)) {
      return nullptr;
    }

    return explicitly_set_element;
  }

  // Compute the attr-associated element from the content attribute if present,
  // id can be null.
  AtomicString id = getAttribute(name);
  if (id.IsNull()) {
    return nullptr;
  }

  // Will return null if the id is empty.
  return getElementByIdIncludingDisconnected(*this, id);
}

Element* Element::GetElementAttributeResolvingReferenceTarget(
    const QualifiedName& name) const {
  if (Element* element = GetElementAttribute(name)) {
    return element->GetShadowReferenceTargetOrSelf(name);
  }

  return nullptr;
}

HeapVector<Member<Element>>* Element::GetAttrAssociatedElements(
    const QualifiedName& name,
    bool resolve_reference_target) const {
  // https://html.spec.whatwg.org/multipage/common-dom-interfaces.html#attr-associated-elements
  // 1. Let elements be an empty list.
  HeapVector<Member<Element>>* result_elements =
      MakeGarbageCollected<HeapVector<Member<Element>>>();
  HeapLinkedHashSet<WeakMember<Element>>* explicitly_set_elements =
      GetExplicitlySetElementsForAttr(name);
  if (explicitly_set_elements) {
    // 3. If reflectedTarget's explicitly set attr-elements is not null:
    for (auto attr_element : *explicitly_set_elements) {
      // 3.1. If attrElement is not a descendant of any of element's
      // shadow-including ancestors, then continue.
      if (ElementIsDescendantOfShadowIncludingAncestor(*this, *attr_element)) {
        if (resolve_reference_target) {
          // 3.NEW. Resolve the referenceTarget of attr_element
          attr_element = attr_element->GetShadowReferenceTargetOrSelf(name);
        }
        // 3.2. Append attrElement to elements.
        result_elements->push_back(attr_element);
      }
    }
  } else {
    // 4. Otherwise:
    // 4.1. Let contentAttributeValue be the result of running reflectedTarget's
    // get the content attribute.
    QualifiedName attr = name;

    // Account for labelled vs labeled spelling
    if (attr == html_names::kAriaLabelledbyAttr) {
      attr = hasAttribute(html_names::kAriaLabeledbyAttr) &&
                     !hasAttribute(html_names::kAriaLabelledbyAttr)
                 ? html_names::kAriaLabeledbyAttr
                 : html_names::kAriaLabelledbyAttr;
    }

    if (!hasAttribute(attr)) {
      // 4.2. If contentAttributeValue is null, then return null.
      return nullptr;
    }

    String attribute_value = getAttribute(attr).GetString();

    // 4.3. Let tokens be contentAttributeValue, split on ASCII whitespace.
    Vector<String> tokens;
    attribute_value = attribute_value.SimplifyWhiteSpace();
    attribute_value.Split(' ', tokens);

    for (auto id : tokens) {
      // 4.3.1. Let candidate be the first element, in tree order, that meets
      // [certain criteria].
      Element* candidate =
          getElementByIdIncludingDisconnected(*this, AtomicString(id));
      if (candidate) {
        if (resolve_reference_target) {
          // 4.3.NEW. Resolve the referenceTarget of the candidate element
         candidate = candidate->GetShadowReferenceTargetOrSelf(attr);
        }
        // 4.3.2. Append candidate to elements.
        result_elements->push_back(candidate);
      }
    }
  }
  // 5. Return elements.
  return result_elements;
}

FrozenArray<Element>* Element::GetElementArrayAttribute(
    const QualifiedName& name) {
  // https://html.spec.whatwg.org/multipage/common-dom-interfaces.html#reflecting-content-attributes-in-idl-attributes:element-3

  // 1. Let elements be this's attr-associated elements.
  HeapVector<Member<Element>>* elements =
      GetAttrAssociatedElements(name, /*resolve_reference_target=*/false);

  CachedAttrAssociatedElementsMap* cached_attr_associated_elements_map =
      GetDocument().GetCachedAttrAssociatedElementsMap(this);
  DCHECK(cached_attr_associated_elements_map);

  if (!elements) {
    // 4. Set this's cached attr-associated elements to elementsAsFrozenArray.
    cached_attr_associated_elements_map->erase(name);
    // 5. Return elementsAsFrozenArray.
    return nullptr;
  }

  auto it = cached_attr_associated_elements_map->find(name);
  if (it != cached_attr_associated_elements_map->end()) {
    FrozenArray<Element>* cached_attr_associated_elements = it->value.Get();
    DCHECK(cached_attr_associated_elements);
    if (cached_attr_associated_elements->AsVector() == *elements) {
      // 2. If the contents of elements is equal to the contents of this's
      // cached attr-associated elements, then return this's cached
      // attr-associated elements.
      return cached_attr_associated_elements;
    }
  }

  // 3. Let elementsAsFrozenArray be elements, converted to a FrozenArray<T>?.
  FrozenArray<Element>* elements_as_frozen_array =
      MakeGarbageCollected<FrozenArray<Element>>(std::move(*elements));

  // 4. Set this's cached attr-associated elements to elementsAsFrozenArray.
  cached_attr_associated_elements_map->Set(name, elements_as_frozen_array);

  // 5. Return elementsAsFrozenArray.
  return elements_as_frozen_array;
}

void Element::SetElementArrayAttribute(
    const QualifiedName& name,
    const HeapVector<Member<Element>>* given_elements) {
  // https://html.spec.whatwg.org/multipage/common-dom-interfaces.html#reflecting-content-attributes-in-idl-attributes:element-3

  ExplicitlySetAttrElementsMap* element_attribute_map =
      GetDocument().GetExplicitlySetAttrElementsMap(this);

  if (!given_elements) {
    // 1. If the given value is null:
    //   1. Set this's explicitly set attr-elements to null.
    element_attribute_map->erase(name);
    //   2. Run this's delete the content attribute.
    removeAttribute(name);
    return;
  }

  // 2. Run this's set the content attribute with the empty string.
  setAttribute(name, g_empty_atom);

  // 3. Let elements be an empty list.
  // 4. For each element in the given value: Append a weak reference to
  // element to elements.
  // 5. Set this's explicitly set attr-elements to elements.
  //
  // In practice, we're fetching elements from element_attribute_map, clearing
  // the previous value if necessary to get an empty list, and then populating
  // the list.
  auto it = element_attribute_map->find(name);
  HeapLinkedHashSet<WeakMember<Element>>* stored_elements =
      it != element_attribute_map->end() ? it->value : nullptr;
  if (!stored_elements) {
    stored_elements =
        MakeGarbageCollected<HeapLinkedHashSet<WeakMember<Element>>>();
    element_attribute_map->Set(name, stored_elements);
  } else {
    stored_elements->clear();
  }

  for (auto element : *given_elements) {
    stored_elements->insert(element);
  }

  // This |Set| call must occur after our call to |setAttribute| above.
  //
  // |setAttribute| will call through to |AttributeChanged| which calls
  // |SynchronizeContentAttributeAndElementReference| erasing the entry for
  // |name| from the map.
  element_attribute_map->Set(name, stored_elements);

  // |HandleAttributeChanged| must be called after updating the attribute map.
  if (isConnected()) {
    if (AXObjectCache* cache = GetDocument().ExistingAXObjectCache()) {
      cache->HandleAttributeChanged(name, this);
    }
  }
}

FrozenArray<Element>* Element::ariaControlsElements() {
  return GetElementArrayAttribute(html_names::kAriaControlsAttr);
}
void Element::setAriaControlsElements(
    HeapVector<Member<Element>>* given_elements) {
  SetElementArrayAttribute(html_names::kAriaControlsAttr, given_elements);
}

FrozenArray<Element>* Element::ariaDescribedByElements() {
  return GetElementArrayAttribute(html_names::kAriaDescribedbyAttr);
}
void Element::setAriaDescribedByElements(
    HeapVector<Member<Element>>* given_elements) {
  SetElementArrayAttribute(html_names::kAriaDescribedbyAttr, given_elements);
}

FrozenArray<Element>* Element::ariaDetailsElements() {
  return GetElementArrayAttribute(html_names::kAriaDetailsAttr);
}
void Element::setAriaDetailsElements(
    HeapVector<Member<Element>>* given_elements) {
  SetElementArrayAttribute(html_names::kAriaDetailsAttr, given_elements);
}

FrozenArray<Element>* Element::ariaErrorMessageElements() {
  return GetElementArrayAttribute(html_names::kAriaErrormessageAttr);
}
void Element::setAriaErrorMessageElements(
    HeapVector<Member<Element>>* given_elements) {
  SetElementArrayAttribute(html_names::kAriaErrormessageAttr, given_elements);
}

FrozenArray<Element>* Element::ariaFlowToElements() {
  return GetElementArrayAttribute(html_names::kAriaFlowtoAttr);
}
void Element::setAriaFlowToElements(
    HeapVector<Member<Element>>* given_elements) {
  SetElementArrayAttribute(html_names::kAriaFlowtoAttr, given_elements);
}

FrozenArray<Element>* Element::ariaLabelledByElements() {
  return GetElementArrayAttribute(html_names::kAriaLabelledbyAttr);
}
void Element::setAriaLabelledByElements(
    HeapVector<Member<Element>>* given_elements) {
  SetElementArrayAttribute(html_names::kAriaLabelledbyAttr, given_elements);
}

FrozenArray<Element>* Element::ariaOwnsElements() {
  return GetElementArrayAttribute(html_names::kAriaOwnsAttr);
}
void Element::setAriaOwnsElements(HeapVector<Member<Element>>* given_elements) {
  SetElementArrayAttribute(html_names::kAriaOwnsAttr, given_elements);
}

NamedNodeMap* Element::attributesForBindings() const {
  ElementRareDataVector& rare_data =
      const_cast<Element*>(this)->EnsureElementRareData();
  if (NamedNodeMap* attribute_map = rare_data.AttributeMap()) {
    return attribute_map;
  }

  rare_data.SetAttributeMap(
      MakeGarbageCollected<NamedNodeMap>(const_cast<Element*>(this)));
  return rare_data.AttributeMap();
}

AttributeNamesView Element::getAttributeNamesForBindings() const {
  return bindings::Transform<AttributeToNameTransform>(Attributes());
}

Vector<AtomicString> Element::getAttributeNames() const {
  Vector<AtomicString> result;
  auto view = getAttributeNamesForBindings();
  std::transform(view.begin(), view.end(), std::back_inserter(result),
                 [](const String& str) { return AtomicString(str); });
  return result;
}

Vector<QualifiedName> Element::getAttributeQualifiedNames() const {
  Vector<QualifiedName> result;
  auto attrs = Attributes();
  std::transform(attrs.begin(), attrs.end(), std::back_inserter(result),
                 [](const Attribute& attr) { return attr.GetName(); });
  return result;
}

inline ElementRareDataVector* Element::GetElementRareData() const {
  return static_cast<ElementRareDataVector*>(RareData());
}

inline ElementRareDataVector& Element::EnsureElementRareData() {
  return static_cast<ElementRareDataVector&>(EnsureRareData());
}

void Element::RemovePopoverData() {
  DCHECK(GetElementRareData());
  GetElementRareData()->RemovePopoverData();
}

PopoverData* Element::EnsurePopoverData() {
  return &EnsureElementRareData().EnsurePopoverData();
}
PopoverData* Element::GetPopoverData() const {
  if (const ElementRareDataVector* data = GetElementRareData()) {
    return data->GetPopoverData();
  }
  return nullptr;
}

void Element::InterestGained() {
  CHECK(RuntimeEnabledFeatures::HTMLInterestTargetAttributeEnabled());

  if (!IsInTreeScope()) {
    return;
  }

  Element* interest_target_element = this->interestTargetElement();
  AtomicString interest_action = this->interestAction();
  if (interest_target_element && !interest_action.IsNull()) {
    // TODO(crbug.com/326681249): This should only fire if action is valid.
    Event* interest_event = InterestEvent::Create(event_type_names::kInterest,
                                                  interest_action, this);
    interest_target_element->DispatchEvent(*interest_event);
    if (!interest_event->defaultPrevented()) {
      if (auto* popover = DynamicTo<HTMLElement>(interest_target_element);
          popover && popover->PopoverType() != PopoverValueType::kNone) {
        if (!(interest_action.empty() ||
              EqualIgnoringASCIICase(interest_action,
                                     keywords::kTogglePopover))) {
          return;
        }

        // TODO(crbug.com/326681249): This might need to queue a task with a
        // delay based on CSS properties.
        auto& document = GetDocument();
        bool can_show = popover->IsPopoverReady(
            PopoverTriggerAction::kShow,
            /*exception_state=*/nullptr,
            /*include_event_handler_text=*/true, &document);
        bool can_hide = popover->IsPopoverReady(
            PopoverTriggerAction::kHide,
            /*exception_state=*/nullptr,
            /*include_event_handler_text=*/true, &document);
        if (can_hide) {
          popover->HidePopoverInternal(
              HidePopoverFocusBehavior::kFocusPreviousElement,
              HidePopoverTransitionBehavior::kFireEventsAndWaitForTransitions,
              /*exception_state=*/nullptr);
        } else if (can_show) {
          popover->InvokePopover(*this);
        }
      }
    }
  }
}

Element* Element::anchorElement() const {
  // TODO(crbug.com/1425215): Fix GetElementAttribute() for out-of-tree-scope
  // elements, so that we can remove the hack below.
  if (!RuntimeEnabledFeatures::HTMLAnchorAttributeEnabled()) {
    return nullptr;
  }
  if (!IsInTreeScope()) {
    return nullptr;
  }
  return GetElementAttributeResolvingReferenceTarget(html_names::kAnchorAttr);
}

// For JavaScript binding, return the anchor element without resolving the
// reference target, to avoid exposing shadow root content to JS.
Element* Element::anchorElementForBinding() const {
  // TODO(crbug.com/1425215): Fix GetElementAttribute() for out-of-tree-scope
  // elements, so that we can remove the hack below.
  if (!RuntimeEnabledFeatures::HTMLAnchorAttributeEnabled()) {
    return nullptr;
  }
  if (!IsInTreeScope()) {
    return nullptr;
  }
  return GetElementAttribute(html_names::kAnchorAttr);
}

void Element::setAnchorElementForBinding(Element* new_element) {
  CHECK(RuntimeEnabledFeatures::HTMLAnchorAttributeEnabled());
  SetElementAttribute(html_names::kAnchorAttr, new_element);
  EnsureAnchorElementObserver().Notify();
}

inline void Element::SynchronizeAttribute(const QualifiedName& name) const {
  if (!HasElementData()) {
    return;
  }
  if (name == html_names::kStyleAttr &&
      GetElementData()->style_attribute_is_dirty()) [[unlikely]] {
    DCHECK(IsStyledElement());
    SynchronizeStyleAttributeInternal();
    return;
  }
  if (GetElementData()->svg_attributes_are_dirty()) [[unlikely]] {
    // See comment in the AtomicString version of SynchronizeAttribute()
    // also.
    To<SVGElement>(this)->SynchronizeSVGAttribute(name);
  }
}

ElementAnimations* Element::GetElementAnimations() const {
  if (ElementRareDataVector* data = GetElementRareData()) {
    return data->GetElementAnimations();
  }
  return nullptr;
}

ElementAnimations& Element::EnsureElementAnimations() {
  ElementRareDataVector& rare_data = EnsureElementRareData();
  if (!rare_data.GetElementAnimations()) {
    rare_data.SetElementAnimations(MakeGarbageCollected<ElementAnimations>());
  }
  return *rare_data.GetElementAnimations();
}

bool Element::HasAnimations() const {
  if (ElementRareDataVector* data = GetElementRareData()) {
    const ElementAnimations* element_animations = data->GetElementAnimations();
    return element_animations && !element_animations->IsEmpty();
  }
  return false;
}

bool Element::hasAttribute(const QualifiedName& name) const {
  if (!HasElementData()) {
    return false;
  }
  SynchronizeAttribute(name);
  return GetElementData()->Attributes
Prompt: 
```
这是目录为blink/renderer/core/dom/element.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共13部分，请归纳一下它的功能

"""
anvas() &&
             layout_object->StyleRef().IsFocusable();
    }
  }

  return false;
}

Node* Element::Clone(Document& factory,
                     NodeCloningData& data,
                     ContainerNode* append_to,
                     ExceptionState& append_exception_state) const {
  Element* copy;
  if (!data.Has(CloneOption::kIncludeDescendants)) {
    copy = &CloneWithoutChildren(data, &factory);
    if (append_to) {
      append_to->AppendChild(copy, append_exception_state);
    }
  } else {
    copy =
        &CloneWithChildren(data, &factory, append_to, append_exception_state);
  }
  // 7. If node is a shadow host whose shadow root’s clonable is true:
  auto* shadow_root = GetShadowRoot();
  if (!shadow_root) {
    return copy;
  }
  if (shadow_root->clonable()) {
    if (shadow_root->GetMode() == ShadowRootMode::kOpen ||
        shadow_root->GetMode() == ShadowRootMode::kClosed) {
      // 7.1 Run attach a shadow root with copy, node’s shadow root’s mode,
      // true, node’s shadow root’s delegates focus, and node’s shadow root’s
      // slot assignment.
      // TODO(crbug.com/1523816): it seems like the `registry` parameter should
      // not always be nullptr.
      ShadowRoot& cloned_shadow_root = copy->AttachShadowRootInternal(
          shadow_root->GetMode(),
          shadow_root->delegatesFocus() ? FocusDelegation::kDelegateFocus
                                        : FocusDelegation::kNone,
          shadow_root->GetSlotAssignmentMode(), /*registry*/ nullptr,
          shadow_root->serializable(),
          /*clonable*/ true, shadow_root->referenceTarget());

      // 7.2 Set copy’s shadow root’s declarative to node’s shadow root’s
      // declarative.
      cloned_shadow_root.SetIsDeclarativeShadowRoot(
          shadow_root->IsDeclarativeShadowRoot());

      // This step is not currently spec'd.
      cloned_shadow_root.SetAvailableToElementInternals(
          shadow_root->IsAvailableToElementInternals());

      // 7.3 If the clone children flag is set, then for each child child of
      // node’s shadow root, in tree order: append the result of cloning child
      // with document and the clone children flag set, to copy’s shadow root.
      NodeCloningData shadow_data{CloneOption::kIncludeDescendants};
      cloned_shadow_root.CloneChildNodesFrom(*shadow_root, shadow_data);
    }
  }
  return copy;
}

Element& Element::CloneWithChildren(
    NodeCloningData& data,
    Document* nullable_factory,
    ContainerNode* append_to,
    ExceptionState& append_exception_state) const {
  Element& clone = CloneWithoutAttributesAndChildren(
      nullable_factory ? *nullable_factory : GetDocument());
  // This will catch HTML elements in the wrong namespace that are not correctly
  // copied.  This is a sanity check as HTML overloads some of the DOM methods.
  DCHECK_EQ(IsHTMLElement(), clone.IsHTMLElement());

  clone.CloneAttributesFrom(*this);
  clone.CloneNonAttributePropertiesFrom(*this, data);
  if (data.Has(CloneOption::kPreserveDOMPartsMinimalAPI) && HasNodePart()) {
    DCHECK(RuntimeEnabledFeatures::DOMPartsAPIMinimalEnabled());
    clone.SetHasNodePart();
  } else if (data.Has(CloneOption::kPreserveDOMParts)) {
    PartRoot::CloneParts(*this, clone, data);
  }

  // Append the clone to its parent first, before cloning children. If this is
  // done in the reverse order, each new child will receive treeDepth calls to
  // Node::InsertedInto().
  if (append_to) {
    append_to->AppendChild(&clone, append_exception_state);
  }
  clone.CloneChildNodesFrom(*this, data);
  return clone;
}

Element& Element::CloneWithoutChildren() const {
  NodeCloningData data;
  return CloneWithoutChildren(data);
}

Element& Element::CloneWithoutChildren(NodeCloningData& data,
                                       Document* nullable_factory) const {
  Element& clone = CloneWithoutAttributesAndChildren(
      nullable_factory ? *nullable_factory : GetDocument());
  // This will catch HTML elements in the wrong namespace that are not correctly
  // copied.  This is a sanity check as HTML overloads some of the DOM methods.
  DCHECK_EQ(IsHTMLElement(), clone.IsHTMLElement());

  clone.CloneAttributesFrom(*this);
  clone.CloneNonAttributePropertiesFrom(*this, data);
  if (data.Has(CloneOption::kPreserveDOMPartsMinimalAPI) && HasNodePart()) {
    DCHECK(RuntimeEnabledFeatures::DOMPartsAPIMinimalEnabled());
    clone.SetHasNodePart();
  } else if (data.Has(CloneOption::kPreserveDOMParts)) {
    PartRoot::CloneParts(*this, clone, data);
  }
  return clone;
}

Element& Element::CloneWithoutAttributesAndChildren(Document& factory) const {
  return *factory.CreateElement(TagQName(), CreateElementFlags::ByCloneNode(),
                                IsValue());
}

Attr* Element::DetachAttribute(wtf_size_t index) {
  DCHECK(HasElementData());
  const Attribute& attribute = GetElementData()->Attributes().at(index);
  Attr* attr_node = AttrIfExists(attribute.GetName());
  if (attr_node) {
    DetachAttrNodeAtIndex(attr_node, index);
  } else {
    attr_node = MakeGarbageCollected<Attr>(GetDocument(), attribute.GetName(),
                                           attribute.Value());
    RemoveAttributeInternal(index, AttributeModificationReason::kDirectly);
  }
  return attr_node;
}

void Element::DetachAttrNodeAtIndex(Attr* attr, wtf_size_t index) {
  DCHECK(attr);
  DCHECK(HasElementData());

  const Attribute& attribute = GetElementData()->Attributes().at(index);
  DCHECK(attribute.GetName() == attr->GetQualifiedName());
  DetachAttrNodeFromElementWithValue(attr, attribute.Value());
  RemoveAttributeInternal(index, AttributeModificationReason::kDirectly);
}

void Element::removeAttribute(const QualifiedName& name) {
  wtf_size_t index = FindAttributeIndex(name);
  if (index == kNotFound) {
    return;
  }

  RemoveAttributeInternal(index, AttributeModificationReason::kDirectly);
}

void Element::SetBooleanAttribute(const QualifiedName& name, bool value) {
  if (value) {
    setAttribute(name, g_empty_atom);
  } else {
    removeAttribute(name);
  }
}

bool Element::HasExplicitlySetAttrAssociatedElements(
    const QualifiedName& name) const {
  return GetExplicitlySetElementsForAttr(name);
}

HeapLinkedHashSet<WeakMember<Element>>*
Element::GetExplicitlySetElementsForAttr(const QualifiedName& name) const {
  ExplicitlySetAttrElementsMap* element_attribute_map =
      GetDocument().GetExplicitlySetAttrElementsMap(this);
  auto it = element_attribute_map->find(name);
  if (it == element_attribute_map->end()) {
    return nullptr;
  }
  const auto& elements = it->value;
  return elements->size() ? elements : nullptr;
}

void Element::SynchronizeContentAttributeAndElementReference(
    const QualifiedName& name) {
  ExplicitlySetAttrElementsMap* element_attribute_map =
      GetDocument().GetExplicitlySetAttrElementsMap(this);
  element_attribute_map->erase(name);
}

void Element::SetElementAttribute(const QualifiedName& name, Element* element) {
  DCHECK(IsElementReflectionAttribute(name))
      << " Element attributes must be added to IsElementReflectionAttribute. "
         "name: "
      << name;
  ExplicitlySetAttrElementsMap* explicitly_set_attr_elements_map =
      GetDocument().GetExplicitlySetAttrElementsMap(this);

  // If the reflected element is explicitly null then we remove the content
  // attribute and the explicitly set attr-element.
  if (!element) {
    explicitly_set_attr_elements_map->erase(name);
    removeAttribute(name);
    return;
  }

  setAttribute(name, g_empty_atom);

  auto result = explicitly_set_attr_elements_map->insert(name, nullptr);
  if (result.is_new_entry) {
    result.stored_value->value =
        MakeGarbageCollected<HeapLinkedHashSet<WeakMember<Element>>>();
  } else {
    result.stored_value->value->clear();
  }
  result.stored_value->value->insert(element);

  if (isConnected()) {
    if (AXObjectCache* cache = GetDocument().ExistingAXObjectCache()) {
      cache->HandleAttributeChanged(name, this);
    }
  }
}

Element* Element::GetShadowReferenceTarget(const QualifiedName& name) const {
  if (!RuntimeEnabledFeatures::ShadowRootReferenceTargetEnabled()) {
    return nullptr;
  }

  // TODO (crbug.com/353750122): Disallow aria-owns from participating in
  // ReferenceTarget.

  if (ShadowRoot* shadow_root = GetShadowRoot()) {
    if (Element* target = shadow_root->referenceTargetElement()) {
      if (Element* inner_target = target->GetShadowReferenceTarget(name)) {
        return inner_target;
      }
      return target;
    }
  }
  return nullptr;
}

Element* Element::GetShadowReferenceTargetOrSelf(const QualifiedName& name) {
  if (Element* target = GetShadowReferenceTarget(name)) {
    return target;
  }
  return this;
}

const Element* Element::GetShadowReferenceTargetOrSelf(
    const QualifiedName& name) const {
  if (Element* target = GetShadowReferenceTarget(name)) {
    return target;
  }
  return this;
}

Element* Element::getElementByIdIncludingDisconnected(
    const Element& element,
    const AtomicString& id) const {
  if (id.empty()) {
    return nullptr;
  }
  if (element.isConnected()) {
    return element.GetTreeScope().getElementById(id);
  }
  // https://html.spec.whatwg.org/#attr-associated-element
  // Attr associated element lookup does not depend on whether the element
  // is connected. However, the TreeOrderedMap that is used for
  // TreeScope::getElementById() only stores connected elements.
  Node& root = element.TreeRoot();
  for (Element& el : ElementTraversal::DescendantsOf(root)) {
    if (el.GetIdAttribute() == id) {
      return &el;
    }
  }
  return nullptr;
}

Element* Element::GetElementAttribute(const QualifiedName& name) const {
  HeapLinkedHashSet<WeakMember<Element>>* element_attribute_vector =
      GetExplicitlySetElementsForAttr(name);
  if (element_attribute_vector) {
    DCHECK_EQ(element_attribute_vector->size(), 1u);
    Element* explicitly_set_element = *(element_attribute_vector->begin());
    DCHECK_NE(explicitly_set_element, nullptr);

    // Only return the explicit element if it still exists within a valid scope.
    if (!ElementIsDescendantOfShadowIncludingAncestor(
            *this, *explicitly_set_element)) {
      return nullptr;
    }

    return explicitly_set_element;
  }

  // Compute the attr-associated element from the content attribute if present,
  // id can be null.
  AtomicString id = getAttribute(name);
  if (id.IsNull()) {
    return nullptr;
  }

  // Will return null if the id is empty.
  return getElementByIdIncludingDisconnected(*this, id);
}

Element* Element::GetElementAttributeResolvingReferenceTarget(
    const QualifiedName& name) const {
  if (Element* element = GetElementAttribute(name)) {
    return element->GetShadowReferenceTargetOrSelf(name);
  }

  return nullptr;
}

HeapVector<Member<Element>>* Element::GetAttrAssociatedElements(
    const QualifiedName& name,
    bool resolve_reference_target) const {
  // https://html.spec.whatwg.org/multipage/common-dom-interfaces.html#attr-associated-elements
  // 1. Let elements be an empty list.
  HeapVector<Member<Element>>* result_elements =
      MakeGarbageCollected<HeapVector<Member<Element>>>();
  HeapLinkedHashSet<WeakMember<Element>>* explicitly_set_elements =
      GetExplicitlySetElementsForAttr(name);
  if (explicitly_set_elements) {
    // 3. If reflectedTarget's explicitly set attr-elements is not null:
    for (auto attr_element : *explicitly_set_elements) {
      // 3.1. If attrElement is not a descendant of any of element's
      // shadow-including ancestors, then continue.
      if (ElementIsDescendantOfShadowIncludingAncestor(*this, *attr_element)) {
        if (resolve_reference_target) {
          // 3.NEW. Resolve the referenceTarget of attr_element
          attr_element = attr_element->GetShadowReferenceTargetOrSelf(name);
        }
        // 3.2. Append attrElement to elements.
        result_elements->push_back(attr_element);
      }
    }
  } else {
    // 4. Otherwise:
    // 4.1. Let contentAttributeValue be the result of running reflectedTarget's
    // get the content attribute.
    QualifiedName attr = name;

    // Account for labelled vs labeled spelling
    if (attr == html_names::kAriaLabelledbyAttr) {
      attr = hasAttribute(html_names::kAriaLabeledbyAttr) &&
                     !hasAttribute(html_names::kAriaLabelledbyAttr)
                 ? html_names::kAriaLabeledbyAttr
                 : html_names::kAriaLabelledbyAttr;
    }

    if (!hasAttribute(attr)) {
      // 4.2.  If contentAttributeValue is null, then return null.
      return nullptr;
    }

    String attribute_value = getAttribute(attr).GetString();

    // 4.3. Let tokens be contentAttributeValue, split on ASCII whitespace.
    Vector<String> tokens;
    attribute_value = attribute_value.SimplifyWhiteSpace();
    attribute_value.Split(' ', tokens);

    for (auto id : tokens) {
      // 4.3.1. Let candidate be the first element, in tree order, that meets
      // [certain criteria].
      Element* candidate =
          getElementByIdIncludingDisconnected(*this, AtomicString(id));
      if (candidate) {
        if (resolve_reference_target) {
          // 4.3.NEW. Resolve the referenceTarget of the candidate element
         candidate = candidate->GetShadowReferenceTargetOrSelf(attr);
        }
        // 4.3.2. Append candidate to elements.
        result_elements->push_back(candidate);
      }
    }
  }
  // 5. Return elements.
  return result_elements;
}

FrozenArray<Element>* Element::GetElementArrayAttribute(
    const QualifiedName& name) {
  // https://html.spec.whatwg.org/multipage/common-dom-interfaces.html#reflecting-content-attributes-in-idl-attributes:element-3

  // 1. Let elements be this's attr-associated elements.
  HeapVector<Member<Element>>* elements =
      GetAttrAssociatedElements(name, /*resolve_reference_target=*/false);

  CachedAttrAssociatedElementsMap* cached_attr_associated_elements_map =
      GetDocument().GetCachedAttrAssociatedElementsMap(this);
  DCHECK(cached_attr_associated_elements_map);

  if (!elements) {
    // 4. Set this's cached attr-associated elements to elementsAsFrozenArray.
    cached_attr_associated_elements_map->erase(name);
    // 5. Return elementsAsFrozenArray.
    return nullptr;
  }

  auto it = cached_attr_associated_elements_map->find(name);
  if (it != cached_attr_associated_elements_map->end()) {
    FrozenArray<Element>* cached_attr_associated_elements = it->value.Get();
    DCHECK(cached_attr_associated_elements);
    if (cached_attr_associated_elements->AsVector() == *elements) {
      // 2. If the contents of elements is equal to the contents of this's
      // cached attr-associated elements, then return this's cached
      // attr-associated elements.
      return cached_attr_associated_elements;
    }
  }

  // 3. Let elementsAsFrozenArray be elements, converted to a FrozenArray<T>?.
  FrozenArray<Element>* elements_as_frozen_array =
      MakeGarbageCollected<FrozenArray<Element>>(std::move(*elements));

  // 4. Set this's cached attr-associated elements to elementsAsFrozenArray.
  cached_attr_associated_elements_map->Set(name, elements_as_frozen_array);

  // 5. Return elementsAsFrozenArray.
  return elements_as_frozen_array;
}

void Element::SetElementArrayAttribute(
    const QualifiedName& name,
    const HeapVector<Member<Element>>* given_elements) {
  // https://html.spec.whatwg.org/multipage/common-dom-interfaces.html#reflecting-content-attributes-in-idl-attributes:element-3

  ExplicitlySetAttrElementsMap* element_attribute_map =
      GetDocument().GetExplicitlySetAttrElementsMap(this);

  if (!given_elements) {
    // 1. If the given value is null:
    //   1. Set this's explicitly set attr-elements to null.
    element_attribute_map->erase(name);
    //   2. Run this's delete the content attribute.
    removeAttribute(name);
    return;
  }

  // 2. Run this's set the content attribute with the empty string.
  setAttribute(name, g_empty_atom);

  // 3. Let elements be an empty list.
  // 4. For each element in the given value: Append a weak reference to
  // element to elements.
  // 5. Set this's explicitly set attr-elements to elements.
  //
  // In practice, we're fetching elements from element_attribute_map, clearing
  // the previous value if necessary to get an empty list, and then populating
  // the list.
  auto it = element_attribute_map->find(name);
  HeapLinkedHashSet<WeakMember<Element>>* stored_elements =
      it != element_attribute_map->end() ? it->value : nullptr;
  if (!stored_elements) {
    stored_elements =
        MakeGarbageCollected<HeapLinkedHashSet<WeakMember<Element>>>();
    element_attribute_map->Set(name, stored_elements);
  } else {
    stored_elements->clear();
  }

  for (auto element : *given_elements) {
    stored_elements->insert(element);
  }

  // This |Set| call must occur after our call to |setAttribute| above.
  //
  // |setAttribute| will call through to |AttributeChanged| which calls
  // |SynchronizeContentAttributeAndElementReference| erasing the entry for
  // |name| from the map.
  element_attribute_map->Set(name, stored_elements);

  // |HandleAttributeChanged| must be called after updating the attribute map.
  if (isConnected()) {
    if (AXObjectCache* cache = GetDocument().ExistingAXObjectCache()) {
      cache->HandleAttributeChanged(name, this);
    }
  }
}

FrozenArray<Element>* Element::ariaControlsElements() {
  return GetElementArrayAttribute(html_names::kAriaControlsAttr);
}
void Element::setAriaControlsElements(
    HeapVector<Member<Element>>* given_elements) {
  SetElementArrayAttribute(html_names::kAriaControlsAttr, given_elements);
}

FrozenArray<Element>* Element::ariaDescribedByElements() {
  return GetElementArrayAttribute(html_names::kAriaDescribedbyAttr);
}
void Element::setAriaDescribedByElements(
    HeapVector<Member<Element>>* given_elements) {
  SetElementArrayAttribute(html_names::kAriaDescribedbyAttr, given_elements);
}

FrozenArray<Element>* Element::ariaDetailsElements() {
  return GetElementArrayAttribute(html_names::kAriaDetailsAttr);
}
void Element::setAriaDetailsElements(
    HeapVector<Member<Element>>* given_elements) {
  SetElementArrayAttribute(html_names::kAriaDetailsAttr, given_elements);
}

FrozenArray<Element>* Element::ariaErrorMessageElements() {
  return GetElementArrayAttribute(html_names::kAriaErrormessageAttr);
}
void Element::setAriaErrorMessageElements(
    HeapVector<Member<Element>>* given_elements) {
  SetElementArrayAttribute(html_names::kAriaErrormessageAttr, given_elements);
}

FrozenArray<Element>* Element::ariaFlowToElements() {
  return GetElementArrayAttribute(html_names::kAriaFlowtoAttr);
}
void Element::setAriaFlowToElements(
    HeapVector<Member<Element>>* given_elements) {
  SetElementArrayAttribute(html_names::kAriaFlowtoAttr, given_elements);
}

FrozenArray<Element>* Element::ariaLabelledByElements() {
  return GetElementArrayAttribute(html_names::kAriaLabelledbyAttr);
}
void Element::setAriaLabelledByElements(
    HeapVector<Member<Element>>* given_elements) {
  SetElementArrayAttribute(html_names::kAriaLabelledbyAttr, given_elements);
}

FrozenArray<Element>* Element::ariaOwnsElements() {
  return GetElementArrayAttribute(html_names::kAriaOwnsAttr);
}
void Element::setAriaOwnsElements(HeapVector<Member<Element>>* given_elements) {
  SetElementArrayAttribute(html_names::kAriaOwnsAttr, given_elements);
}

NamedNodeMap* Element::attributesForBindings() const {
  ElementRareDataVector& rare_data =
      const_cast<Element*>(this)->EnsureElementRareData();
  if (NamedNodeMap* attribute_map = rare_data.AttributeMap()) {
    return attribute_map;
  }

  rare_data.SetAttributeMap(
      MakeGarbageCollected<NamedNodeMap>(const_cast<Element*>(this)));
  return rare_data.AttributeMap();
}

AttributeNamesView Element::getAttributeNamesForBindings() const {
  return bindings::Transform<AttributeToNameTransform>(Attributes());
}

Vector<AtomicString> Element::getAttributeNames() const {
  Vector<AtomicString> result;
  auto view = getAttributeNamesForBindings();
  std::transform(view.begin(), view.end(), std::back_inserter(result),
                 [](const String& str) { return AtomicString(str); });
  return result;
}

Vector<QualifiedName> Element::getAttributeQualifiedNames() const {
  Vector<QualifiedName> result;
  auto attrs = Attributes();
  std::transform(attrs.begin(), attrs.end(), std::back_inserter(result),
                 [](const Attribute& attr) { return attr.GetName(); });
  return result;
}

inline ElementRareDataVector* Element::GetElementRareData() const {
  return static_cast<ElementRareDataVector*>(RareData());
}

inline ElementRareDataVector& Element::EnsureElementRareData() {
  return static_cast<ElementRareDataVector&>(EnsureRareData());
}

void Element::RemovePopoverData() {
  DCHECK(GetElementRareData());
  GetElementRareData()->RemovePopoverData();
}

PopoverData* Element::EnsurePopoverData() {
  return &EnsureElementRareData().EnsurePopoverData();
}
PopoverData* Element::GetPopoverData() const {
  if (const ElementRareDataVector* data = GetElementRareData()) {
    return data->GetPopoverData();
  }
  return nullptr;
}

void Element::InterestGained() {
  CHECK(RuntimeEnabledFeatures::HTMLInterestTargetAttributeEnabled());

  if (!IsInTreeScope()) {
    return;
  }

  Element* interest_target_element = this->interestTargetElement();
  AtomicString interest_action = this->interestAction();
  if (interest_target_element && !interest_action.IsNull()) {
    // TODO(crbug.com/326681249): This should only fire if action is valid.
    Event* interest_event = InterestEvent::Create(event_type_names::kInterest,
                                                  interest_action, this);
    interest_target_element->DispatchEvent(*interest_event);
    if (!interest_event->defaultPrevented()) {
      if (auto* popover = DynamicTo<HTMLElement>(interest_target_element);
          popover && popover->PopoverType() != PopoverValueType::kNone) {
        if (!(interest_action.empty() ||
              EqualIgnoringASCIICase(interest_action,
                                     keywords::kTogglePopover))) {
          return;
        }

        // TODO(crbug.com/326681249): This might need to queue a task with a
        // delay based on CSS properties.
        auto& document = GetDocument();
        bool can_show = popover->IsPopoverReady(
            PopoverTriggerAction::kShow,
            /*exception_state=*/nullptr,
            /*include_event_handler_text=*/true, &document);
        bool can_hide = popover->IsPopoverReady(
            PopoverTriggerAction::kHide,
            /*exception_state=*/nullptr,
            /*include_event_handler_text=*/true, &document);
        if (can_hide) {
          popover->HidePopoverInternal(
              HidePopoverFocusBehavior::kFocusPreviousElement,
              HidePopoverTransitionBehavior::kFireEventsAndWaitForTransitions,
              /*exception_state=*/nullptr);
        } else if (can_show) {
          popover->InvokePopover(*this);
        }
      }
    }
  }
}

Element* Element::anchorElement() const {
  // TODO(crbug.com/1425215): Fix GetElementAttribute() for out-of-tree-scope
  // elements, so that we can remove the hack below.
  if (!RuntimeEnabledFeatures::HTMLAnchorAttributeEnabled()) {
    return nullptr;
  }
  if (!IsInTreeScope()) {
    return nullptr;
  }
  return GetElementAttributeResolvingReferenceTarget(html_names::kAnchorAttr);
}

// For JavaScript binding, return the anchor element without resolving the
// reference target, to avoid exposing shadow root content to JS.
Element* Element::anchorElementForBinding() const {
  // TODO(crbug.com/1425215): Fix GetElementAttribute() for out-of-tree-scope
  // elements, so that we can remove the hack below.
  if (!RuntimeEnabledFeatures::HTMLAnchorAttributeEnabled()) {
    return nullptr;
  }
  if (!IsInTreeScope()) {
    return nullptr;
  }
  return GetElementAttribute(html_names::kAnchorAttr);
}

void Element::setAnchorElementForBinding(Element* new_element) {
  CHECK(RuntimeEnabledFeatures::HTMLAnchorAttributeEnabled());
  SetElementAttribute(html_names::kAnchorAttr, new_element);
  EnsureAnchorElementObserver().Notify();
}

inline void Element::SynchronizeAttribute(const QualifiedName& name) const {
  if (!HasElementData()) {
    return;
  }
  if (name == html_names::kStyleAttr &&
      GetElementData()->style_attribute_is_dirty()) [[unlikely]] {
    DCHECK(IsStyledElement());
    SynchronizeStyleAttributeInternal();
    return;
  }
  if (GetElementData()->svg_attributes_are_dirty()) [[unlikely]] {
    // See comment in the AtomicString version of SynchronizeAttribute()
    // also.
    To<SVGElement>(this)->SynchronizeSVGAttribute(name);
  }
}

ElementAnimations* Element::GetElementAnimations() const {
  if (ElementRareDataVector* data = GetElementRareData()) {
    return data->GetElementAnimations();
  }
  return nullptr;
}

ElementAnimations& Element::EnsureElementAnimations() {
  ElementRareDataVector& rare_data = EnsureElementRareData();
  if (!rare_data.GetElementAnimations()) {
    rare_data.SetElementAnimations(MakeGarbageCollected<ElementAnimations>());
  }
  return *rare_data.GetElementAnimations();
}

bool Element::HasAnimations() const {
  if (ElementRareDataVector* data = GetElementRareData()) {
    const ElementAnimations* element_animations = data->GetElementAnimations();
    return element_animations && !element_animations->IsEmpty();
  }
  return false;
}

bool Element::hasAttribute(const QualifiedName& name) const {
  if (!HasElementData()) {
    return false;
  }
  SynchronizeAttribute(name);
  return GetElementData()->Attributes().Find(name);
}

bool Element::HasAttributeIgnoringNamespace(
    const AtomicString& local_name) const {
  if (!HasElementData()) {
    return false;
  }
  WTF::AtomicStringTable::WeakResult hint =
      WeakLowercaseIfNecessary(local_name);
  SynchronizeAttributeHinted(local_name, hint);
  if (hint.IsNull()) {
    return false;
  }
  for (const Attribute& attribute : GetElementData()->Attributes()) {
    if (hint == attribute.LocalName()) {
      return true;
    }
  }
  return false;
}

void Element::SynchronizeAllAttributes() const {
  if (!HasElementData()) {
    return;
  }
  // NOTE: AnyAttributeMatches in selector_checker.cc currently assumes that all
  // lazy attributes have a null namespace.  If that ever changes we'll need to
  // fix that code.
  if (GetElementData()->style_attribute_is_dirty()) {
    DCHECK(IsStyledElement());
    SynchronizeStyleAttributeInternal();
  }
  SynchronizeAllAttributesExceptStyle();
}

void Element::SynchronizeAllAttributesExceptStyle() const {
  if (!HasElementData()) {
    return;
  }
  if (GetElementData()->svg_attributes_are_dirty()) {
    To<SVGElement>(this)->SynchronizeAllSVGAttributes();
  }
}

const AtomicString& Element::getAttribute(const QualifiedName& name) const {
  if (!HasElementData()) {
    return g_null_atom;
  }
  SynchronizeAttribute(name);
  if (const Attribute* attribute = GetElementData()->Attributes().Find(name)) {
    return attribute->Value();
  }
  return g_null_atom;
}

AtomicString Element::LowercaseIfNecessary(AtomicString name) const {
  return IsHTMLElement() && IsA<HTMLDocument>(GetDocument())
             ? AtomicString::LowerASCII(std::move(name))
             : std::move(name);
}

const AtomicString& Element::nonce() const {
  if (const ElementRareDataVector* data = GetElementRareData()) {
    return data->GetNonce();
  }
  return g_null_atom;
}

void Element::setNonce(const AtomicString& nonce) {
  EnsureElementRareData().SetNonce(nonce);
}

void Element::scrollIntoView(const V8UnionBooleanOrScrollIntoViewOptions* arg) {
  ScrollIntoViewOptions* options = nullptr;
  switch (arg->GetContentType()) {
    case V8UnionBooleanOrScrollIntoViewOptions::ContentType::kBoolean:
      options = ScrollIntoViewOptions::Create();
      options->setBlock(arg->GetAsBoolean() ? "start" : "end");
      options->setInlinePosition("nearest");
      break;
    case V8UnionBooleanOrScrollIntoViewOptions::ContentType::
        kScrollIntoViewOptions:
      options = arg->GetAsScrollIntoViewOptions();
      break;
  }
  DCHECK(options);
  scrollIntoViewWithOptions(options);
}

void Element::scrollIntoView(bool align_to_top) {
  auto* arg =
      MakeGarbageCollected<V8UnionBooleanOrScrollIntoViewOptions>(align_to_top);
  scrollIntoView(arg);
}

void Element::scrollIntoViewWithOptions(const ScrollIntoViewOptions* options) {
  ActivateDisplayLockIfNeeded(DisplayLockActivationReason::kScrollIntoView);
  GetDocument().EnsurePaintLocationDataValidForNode(
      this, DocumentUpdateReason::kJavaScript);

  if (!GetLayoutObject() || !GetDocument().GetPage()) {
    return;
  }

  mojom::blink::ScrollIntoViewParamsPtr params =
      scroll_into_view_util::CreateScrollIntoViewParams(*options,
                                                        *GetComputedStyle());

  ScrollIntoViewNoVisualUpdate(std::move(params));
}

void Element::ScrollIntoViewNoVisualUpdate(
    mojom::blink::ScrollIntoViewParamsPtr params) {
  if (!GetLayoutObject() || !GetDocument().GetPage()) {
    return;
  }

  Element* originating_element = this;
  LayoutObject* target = nullptr;
  auto* pseudo_element = DynamicTo<PseudoElement>(this);
  if (pseudo_element) {
    originating_element = pseudo_element->UltimateOriginatingElement();
    if (pseudo_element->parentNode()->IsColumnPseudoElement()) {
      // The originating element of a ::column is a multicol container. See if
      // it also is the scrollable container that is to be scrolled, or if it's
      // a descendant (in the latter case `target` will remain nullptr here).
      target = originating_element->GetLayoutBoxForScrolling();
    }
  }
  if (!target) {
    target = originating_element->GetLayoutObject();
  }

  if (DisplayLockUtilities::ShouldIgnoreNodeDueToDisplayLock(
          *originating_element, DisplayLockActivationReason::kScrollIntoView)) {
    return;
  }

  PhysicalRect bounds = BoundingBoxForScrollIntoView();
  scroll_into_view_util::ScrollRectToVisible(*target, bounds,
                                             std::move(params));

  GetDocument().SetSequentialFocusNavigationStartingPoint(originating_element);
}

void Element::scrollIntoViewIfNeeded(bool center_if_needed) {
  GetDocument().EnsurePaintLocationDataValidForNode(
      this, DocumentUpdateReason::kJavaScript);

  if (!GetLayoutObject()) {
    return;
  }

  PhysicalRect bounds = BoundingBoxForScrollIntoView();
  if (center_if_needed) {
    scroll_into_view_util::ScrollRectToVisible(
        *GetLayoutObject(), bounds,
        scroll_into_view_util::CreateScrollIntoViewParams(
            ScrollAlignment::CenterIfNeeded(),
            ScrollAlignment::CenterIfNeeded()));
  } else {
    scroll_into_view_util::ScrollRectToVisible(
        *GetLayoutObject(), bounds,
        scroll_into_view_util::CreateScrollIntoViewParams(
            ScrollAlignment::ToEdgeIfNeeded(),
            ScrollAlignment::ToEdgeIfNeeded()));
  }
}

int Element::OffsetLeft() {
  GetDocument().EnsurePaintLocationDataValidForNode(
      this, DocumentUpdateReason::kJavaScript);
  if (const auto* layout_object = GetLayoutBoxModelObject()) {
    return AdjustForAbsoluteZoom::AdjustLayoutUnit(
               layout_object->OffsetLeft(OffsetParent()),
               layout_object->StyleRef())
        .Round();
  }
  return 0;
}

int Element::OffsetTop() {
  GetDocument().EnsurePaintLocationDataValidForNode(
      this, DocumentUpdateReason::kJavaScript);
  if (const auto* layout_object = GetLayoutBoxModelObject()) {
    return AdjustForAbsoluteZoom::AdjustLayoutUnit(
               layout_object->OffsetTop(OffsetParent()),
               layout_object->StyleRef())
        .Round();
  }
  return 0;
}

int Element::OffsetWidth() {
  GetDocument().EnsurePaintLocationDataValidForNode(
      this, DocumentUpdateReason::kJavaScript);
  if (const auto* layout_object = GetLayoutBoxModelObject()) {
    return AdjustForAbsoluteZoom::AdjustLayoutUnit(layout_object->OffsetWidth(),
                                                   layout_object->StyleRef())
        .Round();
  }
  return 0;
}

int Element::OffsetHeight() {
  GetDocument().EnsurePaintLocationDataValidForNode(
      this, DocumentUpdateReason::kJavaScript);
  if (const auto* layout_object = GetLayoutBoxModelObject()) {
    return AdjustForAbsoluteZoom::AdjustLayoutUnit(
               layout_object->OffsetHeight(), layout_object->StyleRef())
        .Round();
  }
  return 0;
}

Element* Element::OffsetParent() {
  GetDocument().UpdateStyleAndLayoutForNode(this,
                                            DocumentUpdat
"""


```