Response:
Let's break down the thought process for analyzing this code snippet of `element.cc`.

**1. Initial Skim and Keyword Spotting:**

The first step is a quick read-through, looking for familiar terms and patterns. Keywords like `GetBoundingClientRect`, `computedRole`, `computedName`, `toggleAttribute`, `AttributeChanged`, `InsertedInto`, `RemovedFrom`, `AttachLayoutTree`, and `DetachLayoutTree` immediately jump out. These suggest the file deals with:

* **Geometry/Layout:**  `BoundingClientRect`
* **Accessibility:** `computedRole`, `computedName`, `ariaNotify`
* **Attributes:** `toggleAttribute`, `getAttributeNS`, `AttributeChanged`, parsing attributes
* **DOM Tree Manipulation:** `InsertedInto`, `RemovedFrom`, `MovedFrom`
* **Layout Process:** `AttachLayoutTree`, `DetachLayoutTree`
* **JavaScript Interaction:** Mentions of `DocumentUpdateReason::kJavaScript`, `blur()`, and event handlers.

**2. Function-by-Function Analysis:**

Next, examine each function individually. For each function, ask:

* **What is its purpose?**  (The function name often gives a strong hint).
* **What data does it use?** (Look at the member variables and arguments accessed).
* **What actions does it perform?** (Follow the control flow and note any calls to other functions).
* **Does it interact with other subsystems (JavaScript, HTML, CSS)?** (Look for calls to related APIs or mentions of these technologies).

**Example - `GetBoundingClientRect()`:**

* **Purpose:**  The name clearly indicates it's for getting the bounding rectangle of an element.
* **Data:** Accesses `GetDocument()` and `this` (the Element itself).
* **Actions:** Calls `EnsurePaintLocationDataValidForNode` (suggests synchronization related to rendering) and `GetBoundingClientRectNoLifecycleUpdate`. Converts the result to a `DOMRect`.
* **Interaction:** Directly related to JavaScript, as the comment mentions `DocumentUpdateReason::kJavaScript`, implying this function is often called from JS. It also relates to HTML (the element itself) and CSS (as the bounding box is influenced by styling).

**3. Identifying Relationships with JavaScript, HTML, and CSS:**

As you analyze each function, specifically consider these connections:

* **JavaScript:** Look for parameters or return types that map to JS objects (`DOMRect`), mentions of JS-triggered updates, and functions that would be directly callable from JS.
* **HTML:**  Identify functions that manipulate or query attributes (which are core to HTML), and those involved in the element lifecycle (insertion, removal).
* **CSS:** Pay attention to functions dealing with layout (`AttachLayoutTree`), attributes like `class` and `style`, and concepts like `ComputedStyle`.

**4. Logical Reasoning and Hypothetical Scenarios:**

Think about how these functions would be used in practice. For example, with `toggleAttribute`:

* **Input:** An element, an attribute name, and optionally a boolean `force`.
* **Output:** A boolean indicating whether the attribute was added or removed.
* **Logic:**  If the attribute exists, remove it (unless `force` is true). If it doesn't exist, add it (unless `force` is false).

**5. Identifying User/Programming Errors:**

Consider common mistakes developers might make when interacting with these functionalities. For instance, `toggleAttribute` throws an `InvalidCharacterError` for invalid attribute names. Accessing layout information before the layout is calculated can lead to unexpected results (though this code tries to mitigate that with lifecycle checks).

**6. Tracing User Actions (Debugging Clues):**

Think about how a user's interaction with a web page could lead to these functions being called. For example:

* Clicking on an element might trigger JavaScript that calls `GetBoundingClientRect`.
* Modifying an element's `class` attribute in the DevTools would call `AttributeChanged`.
* Dynamically adding or removing elements through JavaScript would involve `InsertedInto` and `RemovedFrom`.

**7. Synthesizing Functionality (Summarization):**

After analyzing individual functions, group them by their general purpose. Look for overarching themes. In this case, the major themes are:

* **Element Geometry and Layout Information:**  Getting the bounding box.
* **Accessibility Information:**  Retrieving computed role and name.
* **Attribute Manipulation:**  Getting, setting, toggling attributes, and handling attribute changes.
* **Element Lifecycle Management:** Handling insertion and removal from the DOM tree, attaching and detaching from the layout tree.
* **Interaction with JavaScript and other Browser Components:**  Serving as an interface between the DOM and other parts of the rendering engine.

**8. Iteration and Refinement:**

Review the initial analysis. Are there any connections missed?  Can the explanations be clearer? For example, initially, I might just say `AttributeChanged` handles attribute changes. But upon closer inspection, I'd realize it also interacts with the style engine, accessibility tree, and potentially triggers other updates.

By following this systematic approach, we can effectively dissect the functionality of a complex source code file and understand its role within a larger system like the Chromium rendering engine.
```cpp
cycleUpdate() const {
  gfx::RectF result = GetBoundingClientRectNoLifecycleUpdateNoAdjustment();
  if (result == gfx::RectF()) {
    return result;
  }

  LayoutObject* element_layout_object = GetLayoutObject();
  DCHECK(element_layout_object);
  GetDocument().AdjustRectForScrollAndAbsoluteZoom(result,
                                                   *element_layout_object);
  return result;
}

DOMRect* Element::GetBoundingClientRect() {
  GetDocument().EnsurePaintLocationDataValidForNode(
      this, DocumentUpdateReason::kJavaScript);
  return DOMRect::FromRectF(GetBoundingClientRectNoLifecycleUpdate());
}

DOMRect* Element::GetBoundingClientRectForBinding() {
  // TODO(crbug.com/1499981): This should be removed once synchronized scrolling
  // impact is understood.
  SyncScrollAttemptHeuristic::DidAccessScrollOffset();
  return GetBoundingClientRect();
}

const AtomicString& Element::computedRole() {
  Document& document = GetDocument();
  if (!document.IsActive() || !document.View()) {
    return g_null_atom;
  }
  AXContext ax_context(document, ui::kAXModeBasic);
  document.View()->UpdateAllLifecyclePhasesExceptPaint(
      DocumentUpdateReason::kJavaScript);
  return ax_context.GetAXObjectCache().ComputedRoleForNode(this);
}

const AtomicString& Element::ComputedRoleNoLifecycleUpdate() {
  Document& document = GetDocument();
  if (!document.IsActive() || !document.View()) {
    return g_null_atom;
  }
  // TODO(chrishtr) this should never happen. Possibly changes already in
  // InspectorOverlayAgent already make this unnecessary.
  if (document.Lifecycle().GetState() < DocumentLifecycle::kPrePaintClean) {
    DCHECK(false);
    return g_null_atom;
  }
  AXContext ax_context(document, ui::kAXModeBasic);
  // Allocating the AXContext needs to not change lifecycle states.
  DCHECK_GE(document.Lifecycle().GetState(), DocumentLifecycle::kPrePaintClean)
      << " State was: " << document.Lifecycle().GetState();
  return ax_context.GetAXObjectCache().ComputedRoleForNode(this);
}

String Element::computedName() {
  Document& document = GetDocument();
  if (!document.IsActive() || !document.View()) {
    return String();
  }
  AXContext ax_context(document, ui::kAXModeBasic);
  document.View()->UpdateAllLifecyclePhasesExceptPaint(
      DocumentUpdateReason::kJavaScript);
  return ax_context.GetAXObjectCache().ComputedNameForNode(this);
}

String Element::ComputedNameNoLifecycleUpdate() {
  Document& document = GetDocument();
  if (!document.IsActive() || !document.View()) {
    return String();
  }
  // TODO(chrishtr) this should never happen. Possibly changes already in
  // InspectorOverlayAgent already make this unnecessary.
  if (document.Lifecycle().GetState() < DocumentLifecycle::kPrePaintClean) {
    DCHECK(false);
    return g_null_atom;
  }
  AXContext ax_context(document, ui::kAXModeBasic);
  // Allocating the AXContext needs to not change lifecycle states.
  DCHECK_GE(document.Lifecycle().GetState(), DocumentLifecycle::kPrePaintClean)
      << " State was: " << document.Lifecycle().GetState();
  return ax_context.GetAXObjectCache().ComputedNameForNode(this);
}

void Element::ariaNotify(const String& announcement,
                         const AriaNotificationOptions* options) {
  DCHECK(RuntimeEnabledFeatures::AriaNotifyEnabled());

  if (auto* cache = GetDocument().ExistingAXObjectCache()) {
    cache->HandleAriaNotification(this, announcement, options);
  }
}

bool Element::toggleAttribute(const AtomicString& qualified_name,
                              ExceptionState& exception_state) {
  // https://dom.spec.whatwg.org/#dom-element-toggleattribute
  // 1. If qualifiedName does not match the Name production in XML, then throw
  // an "InvalidCharacterError" DOMException.
  if (!Document::IsValidName(qualified_name)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidCharacterError,
        "'" + qualified_name + "' is not a valid attribute name.");
    return false;
  }
  // 2. If the context object is in the HTML namespace and its node document is
  // an HTML document, then set qualifiedName to qualifiedName in ASCII
  // lowercase.
  AtomicString lowercase_name = LowercaseIfNecessary(qualified_name);
  WTF::AtomicStringTable::WeakResult hint(lowercase_name.Impl());
  // 3. Let attribute be the first attribute in the context object’s attribute
  // list whose qualified name is qualifiedName, and null otherwise.
  SynchronizeAttributeHinted(lowercase_name, hint);
  auto [index, q_name] =
      LookupAttributeQNameHinted(std::move(lowercase_name), hint);
  // 4. If attribute is null, then
  if (index == kNotFound) {
    // 4. 1. If force is not given or is true, create an attribute whose local
    // name is qualified_name, value is the empty string, and node document is
    // the context object’s node document, then append this attribute to the
    // context object, and then return true.
    SetAttributeInternal(index, q_name, g_empty_atom,
                         AttributeModificationReason::kDirectly);
    return true;
  }
  // 5. Otherwise, if force is not given or is false, remove an attribute given
  // qualifiedName and the context object, and then return false.
  SetAttributeInternal(index, q_name, g_null_atom,
                       AttributeModificationReason::kDirectly);
  return false;
}

bool Element::toggleAttribute(const AtomicString& qualified_name,
                              bool force,
                              ExceptionState& exception_state) {
  // https://dom.spec.whatwg.org/#dom-element-toggleattribute
  // 1. If qualifiedName does not match the Name production in XML, then throw
  // an "InvalidCharacterError" DOMException.
  if (!Document::IsValidName(qualified_name)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidCharacterError,
        "'" + qualified_name + "' is not a valid attribute name.");
    return false;
  }
  // 2. If the context object is in the HTML namespace and its node document is
  // an HTML document, then set qualifiedName to qualifiedName in ASCII
  // lowercase.
  AtomicString lowercase_name = LowercaseIfNecessary(qualified_name);
  WTF::AtomicStringTable::WeakResult hint(lowercase_name.Impl());
  // 3. Let attribute be the first attribute in the context object’s attribute
  // list whose qualified name is qualifiedName, and null otherwise.
  SynchronizeAttributeHinted(lowercase_name, hint);
  auto [index, q_name] =
      LookupAttributeQNameHinted(std::move(lowercase_name), hint);
  // 4. If attribute is null, then
  if (index == kNotFound) {
    // 4. 1. If force is not given or is true, create an attribute whose local
    // name is qualified_name, value is the empty string, and node document is
    // the context object’s node document, then append this attribute to the
    // context object, and then return true.
    if (force) {
      SetAttributeInternal(index, q_name, g_empty_atom,
                           AttributeModificationReason::kDirectly);
      return true;
    }
    // 4. 2. Return false.
    return false;
  }
  // 5. Otherwise, if force is not given or is false, remove an attribute given
  // qualifiedName and the context object, and then return false.
  if (!force) {
    SetAttributeInternal(index, q_name, g_null_atom,
                         AttributeModificationReason::kDirectly);
    return false;
  }
  // 6. Return true.
  return true;
}

const AtomicString& Element::getAttributeNS(
    const AtomicString& namespace_uri,
    const AtomicString& local_name) const {
  return getAttribute(QualifiedName(g_null_atom, local_name, namespace_uri));
}

const AttrNameToTrustedType& Element::GetCheckedAttributeTypes() const {
  DEFINE_STATIC_LOCAL(AttrNameToTrustedType, attribute_map, ({}));
  return attribute_map;
}

SpecificTrustedType Element::ExpectedTrustedTypeForAttribute(
    const QualifiedName& q_name) const {
  // There are only a handful of namespaced attributes we care about
  // (xlink:href), and all of those have identical Trusted Types
  // properties to their namespace-less counterpart. So we check whether this
  // is one of SVG's 'known' attributes, and if so just check the local
  // name part as usual.
  if (!q_name.NamespaceURI().IsNull() &&
      !SVGAnimatedHref::IsKnownAttribute(q_name)) {
    return SpecificTrustedType::kNone;
  }

  const AttrNameToTrustedType* attribute_types = &GetCheckedAttributeTypes();
  AttrNameToTrustedType::const_iterator iter =
      attribute_types->find(q_name.LocalName());
  if (iter != attribute_types->end()) {
    return iter->value;
  }

  // Since event handlers can be defined on nearly all elements, we will
  // consider them independently of the specific element they're attached to.
  //
  // Note: Element::IsEventHandlerAttribute is different and over-approximates
  // event-handler-ness, since it is expected to work only for builtin
  // attributes (like "onclick"), while Trusted Types needs to deal with
  // whatever users pass into setAttribute (for example "one"). Also, it
  // requires the actual Attribute rather than the QName, which means
  // Element::IsEventHandlerAttribute can only be called after an attribute has
  // been constructed.
  if (IsTrustedTypesEventHandlerAttribute(q_name)) {
    return SpecificTrustedType::kScript;
  }

  return SpecificTrustedType::kNone;
}

DISABLE_CFI_PERF
void Element::AttributeChanged(const AttributeModificationParams& params) {
  ParseAttribute(params);

  GetDocument().IncDOMTreeVersion();
  GetDocument().NotifyAttributeChanged(*this, params.name, params.old_value,
                                       params.new_value);

  const QualifiedName& name = params.name;
  if (name == html_names::kIdAttr) {
    AtomicString lowercase_id;
    if (GetDocument().InQuirksMode() && !params.new_value.IsLowerASCII()) {
      lowercase_id = params.new_value.LowerASCII();
    }
    const AtomicString& new_id = lowercase_id ? lowercase_id : params.new_value;
    if (new_id != GetElementData()->IdForStyleResolution()) {
      AtomicString old_id = GetElementData()->SetIdForStyleResolution(new_id);
      GetDocument().GetStyleEngine().IdChangedForElement(old_id, new_id, *this);
    }

    if (GetDocument().HasRenderBlockingExpectLinkElements() &&
        IsFinishedParsingChildren()) {
      DCHECK(GetDocument().GetRenderBlockingResourceManager());
      GetDocument()
          .GetRenderBlockingResourceManager()
          ->RemovePendingParsingElement(GetIdAttribute(), this);
    }
  } else if (name == html_names::kClassAttr) {
    if (params.old_value == params.new_value &&
        params.reason != AttributeModificationReason::kByMoveToNewDocument) {
      return;
    }
    ClassAttributeChanged(params.new_value);
    UpdateClassList(params.old_value, params.new_value);
  } else if (name == html_names::kNameAttr) {
    SetHasName(!params.new_value.IsNull());
  } else if (name == html_names::kPartAttr) {
    part().DidUpdateAttributeValue(params.old_value, params.new_value);
    GetDocument().GetStyleEngine().PartChangedForElement(*this);
  } else if (name == html_names::kExportpartsAttr) {
    EnsureElementRareData().SetPartNamesMap(params.new_value);
    GetDocument().GetStyleEngine().ExportpartsChangedForElement(*this);
  } else if (name == html_names::kTabindexAttr) {
    int tabindex = 0;
    if (params.new_value.empty() ||
        !ParseHTMLInteger(params.new_value, tabindex)) {
      ClearTabIndexExplicitlyIfNeeded();
    } else {
      // We only set when value is in integer range.
      SetTabIndexExplicitly();
    }
    if (params.reason == AttributeModificationReason::kDirectly &&
        AdjustedFocusedElementInTreeScope() == this) {
      // The attribute change may cause supportsFocus() to return false
      // for the element which had focus.
      //
      // TODO(tkent): We should avoid updating style. We'd like to check only
      // DOM-level focusability here.
      GetDocument().UpdateStyleAndLayoutTreeForElement(
          this, DocumentUpdateReason::kFocus);
      if (!IsFocusable() && !GetFocusableArea()) {
        blur();
      }
    }
  } else if (params.name == html_names::kAnchorAttr) {
    if (RuntimeEnabledFeatures::HTMLAnchorAttributeEnabled()) {
      EnsureAnchorElementObserver().Notify();
      return;
    }
  } else if (name == html_names::kSlotAttr) {
    if (params.old_value != params.new_value) {
      if (ShadowRoot* root = ShadowRootOfParent()) {
        root->DidChangeHostChildSlotName(params.old_value, params.new_value);
      }
    }
  } else if (name == html_names::kFocusgroupAttr) {
    // Only update the focusgroup flags when the node has been added to the
    // tree. This is because the computed focusgroup value will depend on the
    // focusgroup value of its closest ancestor node that is a focusgroup, if
    // any.
    if (parentNode()) {
      UpdateFocusgroup(params.new_value);
    }
  } else if (IsElementReflectionAttribute(name)) {
    SynchronizeContentAttributeAndElementReference(name);
  } else if (IsStyledElement()) {
    if (name == html_names::kStyleAttr) {
      if (params.old_value == params.new_value) {
        return;
      }
      StyleAttributeChanged(params.new_value, params.reason);
    } else if (IsPresentationAttribute(name)) {
      GetElementData()->SetPresentationAttributeStyleIsDirty(true);
      SetNeedsStyleRecalc(kLocalStyleChange,
                          StyleChangeReasonForTracing::FromAttribute(name));
    }
  }

  InvalidateNodeListCachesInAncestors(&name, this, nullptr);

  if (isConnected()) {
    if (AXObjectCache* cache = GetDocument().ExistingAXObjectCache()) {
      if (params.old_value != params.new_value) {
        cache->HandleAttributeChanged(name, this);
      }
    }
  }
}

bool Element::HasLegalLinkAttribute(const QualifiedName&) const {
  return false;
}

void Element::ClassAttributeChanged(const AtomicString& new_class_string) {
  DCHECK(HasElementData());
  // Note that this is a copy-by-value of the class names.
  const SpaceSplitString old_classes = GetElementData()->ClassNames();
  if (new_class_string.empty()) [[unlikely]] {
    GetDocument().GetStyleEngine().ClassChangedForElement(old_classes, *this);
    GetElementData()->ClearClass();
    return;
  }
  if (GetDocument().InQuirksMode()) [[unlikely]] {
    GetElementData()->SetClassFoldingCase(new_class_string);
  } else {
    GetElementData()->SetClass(new_class_string);
  }
  const SpaceSplitString& new_classes = GetElementData()->ClassNames();
  GetDocument().GetStyleEngine().ClassChangedForElement(old_classes,
                                                        new_classes, *this);
}

void Element::UpdateClassList(const AtomicString& old_class_string,
                              const AtomicString& new_class_string) {
  if (const ElementRareDataVector* data = GetElementRareData()) {
    if (DOMTokenList* class_list = data->GetClassList()) {
      class_list->DidUpdateAttributeValue(old_class_string, new_class_string);
    }
  }
}

// Returns true if the given attribute is an event handler.
// We consider an event handler any attribute that begins with "on".
// It is a simple solution that has the advantage of not requiring any
// code or configuration change if a new event handler is defined.

static inline bool IsEventHandlerAttribute(const Attribute& attribute) {
  return attribute.GetName().NamespaceURI().IsNull() &&
         attribute.GetName().LocalName().StartsWith("on");
}

bool Element::AttributeValueIsJavaScriptURL(const Attribute& attribute) {
  return ProtocolIsJavaScript(
      StripLeadingAndTrailingHTMLSpaces(attribute.Value()));
}

bool Element::IsJavaScriptURLAttribute(const Attribute& attribute) const {
  return IsURLAttribute(attribute) && AttributeValueIsJavaScriptURL(attribute);
}

bool Element::IsScriptingAttribute(const Attribute& attribute) const {
  return IsEventHandlerAttribute(attribute) ||
         IsJavaScriptURLAttribute(attribute) ||
         IsHTMLContentAttribute(attribute) ||
         IsSVGAnimationAttributeSettingJavaScriptURL(attribute);
}

void Element::StripScriptingAttributes(
    Vector<Attribute, kAttributePrealloc>& attribute_vector) const {
  wtf_size_t destination = 0;
  for (wtf_size_t source = 0; source < attribute_vector.size(); ++source) {
    if (IsScriptingAttribute(attribute_vector[source])) {
      continue;
    }

    if (source != destination) {
      attribute_vector[destination] = attribute_vector[source];
    }

    ++destination;
  }
  attribute_vector.Shrink(destination);
}

void Element::ParserSetAttributes(
    const Vector<Attribute, kAttributePrealloc>& attribute_vector) {
  DCHECK(!isConnected());
  DCHECK(!parentNode());
  DCHECK(!element_data_);

  if (!attribute_vector.empty()) {
    if (GetDocument().GetElementDataCache()) {
      element_data_ =
          GetDocument()
              .GetElementDataCache()
              ->CachedShareableElementDataWithAttributes(attribute_vector);
    } else {
      element_data_ =
          ShareableElementData::CreateWithAttributes(attribute_vector);
    }
  }

  ParserDidSetAttributes();

  // Use attribute_vector instead of element_data_ because AttributeChanged
  // might modify element_data_.
  for (const auto& attribute : attribute_vector) {
    AttributeChanged(AttributeModificationParams(
        attribute.GetName(), g_null_atom, attribute.Value(),
        AttributeModificationReason::kByParser));
  }
}

bool Element::HasEquivalentAttributes(const Element& other) const {
  SynchronizeAllAttributes();
  other.SynchronizeAllAttributes();
  if (GetElementData() == other.GetElementData()) {
    return true;
  }
  if (HasElementData()) {
    return GetElementData()->IsEquivalent(other.GetElementData());
  }
  if (other.HasElementData()) {
    return other.GetElementData()->IsEquivalent(GetElementData());
  }
  return true;
}

String Element::nodeName() const {
  return tag_name_.ToString();
}

AtomicString Element::LocalNameForSelectorMatching() const {
  if (IsHTMLElement() || !IsA<HTMLDocument>(GetDocument())) {
    return localName();
  }
  return localName().LowerASCII();
}

const AtomicString& Element::LocateNamespacePrefix(
    const AtomicString& namespace_to_locate) const {
  if (!prefix().IsNull() && namespaceURI() == namespace_to_locate) {
    return prefix();
  }

  AttributeCollection attributes = Attributes();
  for (const Attribute& attr : attributes) {
    if (attr.Prefix() == g_xmlns_atom && attr.Value() == namespace_to_locate) {
      return attr.LocalName();
    }
  }

  if (Element* parent = parentElement()) {
    return parent->LocateNamespacePrefix(namespace_to_locate);
  }

  return g_null_atom;
}

const AtomicString Element::ImageSourceURL() const {
  return FastGetAttribute(html_names::kSrcAttr);
}

bool Element::LayoutObjectIsNeeded(const DisplayStyle& style) const {
  return style.Display() != EDisplay::kNone &&
         style.Display() != EDisplay::kContents;
}

bool Element::LayoutObjectIsNeeded(const ComputedStyle& style) const {
  return LayoutObjectIsNeeded(style.GetDisplayStyle());
}

LayoutObject* Element::CreateLayoutObject(const ComputedStyle& style) {
  return LayoutObject::CreateObject(this, style);
}

Node::InsertionNotificationRequest Element::InsertedInto(
    ContainerNode& insertion_point) {
  // need to do superclass processing first so isConnected() is true
  // by the time we reach updateId
  ContainerNode::InsertedInto(insertion_point);

  DCHECK(!GetElementRareData() || !GetElementRareData()->HasPseudoElements() || GetDocument().StatePreservingAtomicMoveInProgress());

  RecomputeDirectionFromParent();

  if (AnchorElementObserver* observer = GetAnchorElementObserver()) {
    observer->Notify();
  }

  if (!insertion_point.IsInTreeScope()) {
    return kInsertionDone;
  }

  if (isConnected()) {
    if (ElementRareDataVector* rare_data = GetElementRareData()) {
      if (ElementIntersectionObserverData* observer_data =
              rare_data->IntersectionObserverData()) {
        observer_data->TrackWithController(
            GetDocument().EnsureIntersectionObserverController());
        if (!observer_data->IsEmpty()) {
          if (LocalFrameView* frame_view = GetDocument().View()) {
            frame_view->SetIntersectionObservationState(
                LocalFrameView::kRequired);
          }
        }
      }

      if (auto* context = rare_data->GetDisplayLockContext()) {
        context->ElementConnected();
      }
    }
  }

  if (isConnected()) {
    EnqueueAutofocus(*this);

    if (GetCustomElementState() == CustomElementState::kCustom) {
      if (GetDocument().StatePreservingAtomicMoveInProgress()) {
        CustomElement::EnqueueConnectedMoveCallback(*this);
      } else {
        CustomElement::EnqueueConnectedCallback(*this);
      }
    } else if (GetCustomElementState() == CustomElementState::kUndefined) {
      CustomElement::TryToUpgrade(*this);
    }
  }

  TreeScope& scope = insertion_point.GetTreeScope();
  if (scope != GetTreeScope()) {
    return kInsertionDone;
  }

  const AtomicString& id_value = GetIdAttribute();
  if (!id_value.IsNull()) {
    UpdateId(scope, g_null_atom, id_value);
  }

  const AtomicString& name_value = GetNameAttribute();
  if (!name_value.IsNull()) {
    UpdateName(g_null_atom, name_value);
  }

  ExecutionContext* context = GetExecutionContext();
  if (RuntimeEnabledFeatures::FocusgroupEnabled(context)) {
    const AtomicString& focusgroup_value =
        FastGetAttribute(html_names::kFocusgroupAttr);
    if (!focusgroup_value.IsNull()) {
      UpdateFocusgroup(focusgroup_value);
    }

    // We parse the focusgroup attribute for the ShadowDOM elements before we
    // parse it for any of its root's ancestors, which might lead to an
    // incorrect focusgroup value. Re-run the algorithm for the ShadowDOM
    // elements when the ShadowRoot's parent gets inserted in the tree.
    if (GetShadowRoot()) {
      UpdateFocusgroupInShadowRootIfNeeded();
    }
  }

  if (parentElement() && parentElement()->IsInCanvasSubtree()) {
    SetIsInCanvasSubtree(true);
  }

  if (GetDocument().StatePreservingAtomicMoveInProgress() &&
      Fullscreen::IsFullscreenElement(*this)) {
    // We don't actually need to cross frame boundaries, but we do need to mark
    // all our ancestors as containing a full screen element.
    SetContainsFullScreenElementOnAncestorsCrossingFrameBoundaries(true);
  }

  return kInsertionDone;
}

void Element::MovedFrom(ContainerNode& old_parent) {
  Node::MovedFrom(old_parent);

  DCHECK(!GetDocument().StatePreservingAtomicMoveInProgress());

  // `old_parent` can be the document.
  if (!old_parent.IsElementNode()) {
    return;
  }

  Element* focused_element = GetDocument().FocusedElement();
  Element* new_parent_element = parentElement();
  Element* old_parent_element = &To<Element>(old_parent);
  if (focused_element && old_parent.HasFocusWithin() &&
      contains(focused_element) && old_parent != *new_parent_element) {
    Element* common_ancestor = To<Element>(NodeTraversal::CommonAncestor(
        *old_parent_element, *new_parent_element));

    // The "focus within" flag is set separately on each ancestor, and affects
    // the :focus-within CSS property. We set it to the right value here because
    // we skipped the step that sets it on removal/insertion.
    old_parent_element->SetHasFocusWithinUpToAncestor(false, common_ancestor);
    new_parent_element->SetHasFocusWithinUpToAncestor(true, common_ancestor);
  }
}

void Element::RemovedFrom(ContainerNode& insertion_point) {
  bool was_in_document = insertion_point.isConnected();

  if (!GetDocument().StatePreservingAtomicMoveInProgress()) {
    SetComputedStyle(nullptr);
  }

  if (Fullscreen::IsFullscreenElement(*this)) {
    SetContainsFullScreenElementOnAncestorsCrossingFrameBoundaries(false);
    if (auto* insertion_point_element = DynamicTo<Element>(insertion_point)) {
      insertion_point_element->SetContainsFullScreenElement(false);
      insertion_point_element
          ->SetContainsFullScreenElementOnAncestorsCrossingFrameBoundaries(
              false);
    }
  }
  Document& document = GetDocument();
  Page* page = document.GetPage();
  if (page) {
    page->GetPointerLockController().ElementRemoved(this);
  }

  document.UnobserveForIntrinsicSize(this);
  if (auto* local_frame_view = document.View();
      local_frame_view &&
      (LastRememberedInlineSize() || LastRememberedBlockSize())) {
    local_frame_view->NotifyElementWithRememberedSizeDisconnected(this);
  }

  SetSavedLayerScrollOffset(ScrollOffset());

  if (insertion_point.IsInTreeScope() && GetTreeScope() == document) {
    const AtomicString& id_value = GetIdAttribute();
    if (!id_value.IsNull()) {
      UpdateId(insertion_point.GetTreeScope(), id_value, g_null_atom);
    }

    const AtomicString& name_value = GetNameAttribute();
    if (!name_value.IsNull()) {
      UpdateName(name_value, g_null_atom);
    }
  }

  ContainerNode::RemovedFrom(insertion_point);

  if (was_in_document) {
    if (!RuntimeEnabledFeatures::KeepCSSTargetAfterReattachEnabled() &&
        this == document.CssTarget()) {
      document.SetCSSTarget(nullptr);
    }

    if (GetCustomElementState() == CustomElementState::kCustom &&
        !GetDocument().StatePreservingAtomicMoveInProgress()) {
      CustomElement::EnqueueDisconnectedCallback(*this);
    }
  }

  RecomputeDirectionFromParent();

  document.GetRootScrollerController().ElementRemoved(*this);

  if (IsInTopLayer() && !document.StatePreservingAtomicMoveInProgress()) {
    Fullscreen::ElementRemoved(*this);
    document.RemoveFromTopLayerImmediately(this);
  }

  ClearElementFlag(ElementFlags::kIsInCanvasSubtree);

  if (ElementRareDataVector* data = GetElementRareData()) {
    data->ClearFocusgroupFlags();
    data->ClearRestyleFlags();

    if (!GetDocument().StatePreservingAtomicMoveInProgress()) {
      if (ElementAnimations* element_animations =
              data->GetElementAnimations()) {
        element_animations->CssAnimations().Cancel();
      }
    }

    NodeRareData* node_data = RareData();
    node_data->InvalidateAssociatedAnimationEffects();
    if (was_in_document) {
      if (auto* observer_data = data->IntersectionObserverData()) {
        observer_data->ComputeIntersectionsForTarget();
        observer_data->StopTrackingWithController(
            document.EnsureIntersectionObserverController());
      }
    }

    if (auto* context = data->GetDisplayLockContext()) {
      context->ElementDisconnected();
    }

    DCHECK(!data->HasPseudoElements() ||
           GetDocument().StatePreservingAtomicMoveInProgress
### 提示词
```
这是目录为blink/renderer/core/dom/element.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共13部分，请归纳一下它的功能
```

### 源代码
```cpp
cycleUpdate() const {
  gfx::RectF result = GetBoundingClientRectNoLifecycleUpdateNoAdjustment();
  if (result == gfx::RectF()) {
    return result;
  }

  LayoutObject* element_layout_object = GetLayoutObject();
  DCHECK(element_layout_object);
  GetDocument().AdjustRectForScrollAndAbsoluteZoom(result,
                                                   *element_layout_object);
  return result;
}

DOMRect* Element::GetBoundingClientRect() {
  GetDocument().EnsurePaintLocationDataValidForNode(
      this, DocumentUpdateReason::kJavaScript);
  return DOMRect::FromRectF(GetBoundingClientRectNoLifecycleUpdate());
}

DOMRect* Element::GetBoundingClientRectForBinding() {
  // TODO(crbug.com/1499981): This should be removed once synchronized scrolling
  // impact is understood.
  SyncScrollAttemptHeuristic::DidAccessScrollOffset();
  return GetBoundingClientRect();
}

const AtomicString& Element::computedRole() {
  Document& document = GetDocument();
  if (!document.IsActive() || !document.View()) {
    return g_null_atom;
  }
  AXContext ax_context(document, ui::kAXModeBasic);
  document.View()->UpdateAllLifecyclePhasesExceptPaint(
      DocumentUpdateReason::kJavaScript);
  return ax_context.GetAXObjectCache().ComputedRoleForNode(this);
}

const AtomicString& Element::ComputedRoleNoLifecycleUpdate() {
  Document& document = GetDocument();
  if (!document.IsActive() || !document.View()) {
    return g_null_atom;
  }
  // TODO(chrishtr) this should never happen. Possibly changes already in
  // InspectorOverlayAgent already make this unnecessary.
  if (document.Lifecycle().GetState() < DocumentLifecycle::kPrePaintClean) {
    DCHECK(false);
    return g_null_atom;
  }
  AXContext ax_context(document, ui::kAXModeBasic);
  // Allocating the AXContext needs to not change lifecycle states.
  DCHECK_GE(document.Lifecycle().GetState(), DocumentLifecycle::kPrePaintClean)
      << " State was: " << document.Lifecycle().GetState();
  return ax_context.GetAXObjectCache().ComputedRoleForNode(this);
}

String Element::computedName() {
  Document& document = GetDocument();
  if (!document.IsActive() || !document.View()) {
    return String();
  }
  AXContext ax_context(document, ui::kAXModeBasic);
  document.View()->UpdateAllLifecyclePhasesExceptPaint(
      DocumentUpdateReason::kJavaScript);
  return ax_context.GetAXObjectCache().ComputedNameForNode(this);
}

String Element::ComputedNameNoLifecycleUpdate() {
  Document& document = GetDocument();
  if (!document.IsActive() || !document.View()) {
    return String();
  }
  // TODO(chrishtr) this should never happen. Possibly changes already in
  // InspectorOverlayAgent already make this unnecessary.
  if (document.Lifecycle().GetState() < DocumentLifecycle::kPrePaintClean) {
    DCHECK(false);
    return g_null_atom;
  }
  AXContext ax_context(document, ui::kAXModeBasic);
  // Allocating the AXContext needs to not change lifecycle states.
  DCHECK_GE(document.Lifecycle().GetState(), DocumentLifecycle::kPrePaintClean)
      << " State was: " << document.Lifecycle().GetState();
  return ax_context.GetAXObjectCache().ComputedNameForNode(this);
}

void Element::ariaNotify(const String& announcement,
                         const AriaNotificationOptions* options) {
  DCHECK(RuntimeEnabledFeatures::AriaNotifyEnabled());

  if (auto* cache = GetDocument().ExistingAXObjectCache()) {
    cache->HandleAriaNotification(this, announcement, options);
  }
}

bool Element::toggleAttribute(const AtomicString& qualified_name,
                              ExceptionState& exception_state) {
  // https://dom.spec.whatwg.org/#dom-element-toggleattribute
  // 1. If qualifiedName does not match the Name production in XML, then throw
  // an "InvalidCharacterError" DOMException.
  if (!Document::IsValidName(qualified_name)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidCharacterError,
        "'" + qualified_name + "' is not a valid attribute name.");
    return false;
  }
  // 2. If the context object is in the HTML namespace and its node document is
  // an HTML document, then set qualifiedName to qualifiedName in ASCII
  // lowercase.
  AtomicString lowercase_name = LowercaseIfNecessary(qualified_name);
  WTF::AtomicStringTable::WeakResult hint(lowercase_name.Impl());
  // 3. Let attribute be the first attribute in the context object’s attribute
  // list whose qualified name is qualifiedName, and null otherwise.
  SynchronizeAttributeHinted(lowercase_name, hint);
  auto [index, q_name] =
      LookupAttributeQNameHinted(std::move(lowercase_name), hint);
  // 4. If attribute is null, then
  if (index == kNotFound) {
    // 4. 1. If force is not given or is true, create an attribute whose local
    // name is qualified_name, value is the empty string, and node document is
    // the context object’s node document, then append this attribute to the
    // context object, and then return true.
    SetAttributeInternal(index, q_name, g_empty_atom,
                         AttributeModificationReason::kDirectly);
    return true;
  }
  // 5. Otherwise, if force is not given or is false, remove an attribute given
  // qualifiedName and the context object, and then return false.
  SetAttributeInternal(index, q_name, g_null_atom,
                       AttributeModificationReason::kDirectly);
  return false;
}

bool Element::toggleAttribute(const AtomicString& qualified_name,
                              bool force,
                              ExceptionState& exception_state) {
  // https://dom.spec.whatwg.org/#dom-element-toggleattribute
  // 1. If qualifiedName does not match the Name production in XML, then throw
  // an "InvalidCharacterError" DOMException.
  if (!Document::IsValidName(qualified_name)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidCharacterError,
        "'" + qualified_name + "' is not a valid attribute name.");
    return false;
  }
  // 2. If the context object is in the HTML namespace and its node document is
  // an HTML document, then set qualifiedName to qualifiedName in ASCII
  // lowercase.
  AtomicString lowercase_name = LowercaseIfNecessary(qualified_name);
  WTF::AtomicStringTable::WeakResult hint(lowercase_name.Impl());
  // 3. Let attribute be the first attribute in the context object’s attribute
  // list whose qualified name is qualifiedName, and null otherwise.
  SynchronizeAttributeHinted(lowercase_name, hint);
  auto [index, q_name] =
      LookupAttributeQNameHinted(std::move(lowercase_name), hint);
  // 4. If attribute is null, then
  if (index == kNotFound) {
    // 4. 1. If force is not given or is true, create an attribute whose local
    // name is qualified_name, value is the empty string, and node document is
    // the context object’s node document, then append this attribute to the
    // context object, and then return true.
    if (force) {
      SetAttributeInternal(index, q_name, g_empty_atom,
                           AttributeModificationReason::kDirectly);
      return true;
    }
    // 4. 2. Return false.
    return false;
  }
  // 5. Otherwise, if force is not given or is false, remove an attribute given
  // qualifiedName and the context object, and then return false.
  if (!force) {
    SetAttributeInternal(index, q_name, g_null_atom,
                         AttributeModificationReason::kDirectly);
    return false;
  }
  // 6. Return true.
  return true;
}

const AtomicString& Element::getAttributeNS(
    const AtomicString& namespace_uri,
    const AtomicString& local_name) const {
  return getAttribute(QualifiedName(g_null_atom, local_name, namespace_uri));
}

const AttrNameToTrustedType& Element::GetCheckedAttributeTypes() const {
  DEFINE_STATIC_LOCAL(AttrNameToTrustedType, attribute_map, ({}));
  return attribute_map;
}

SpecificTrustedType Element::ExpectedTrustedTypeForAttribute(
    const QualifiedName& q_name) const {
  // There are only a handful of namespaced attributes we care about
  // (xlink:href), and all of those have identical Trusted Types
  // properties to their namespace-less counterpart. So we check whether this
  // is one of SVG's 'known' attributes, and if so just check the local
  // name part as usual.
  if (!q_name.NamespaceURI().IsNull() &&
      !SVGAnimatedHref::IsKnownAttribute(q_name)) {
    return SpecificTrustedType::kNone;
  }

  const AttrNameToTrustedType* attribute_types = &GetCheckedAttributeTypes();
  AttrNameToTrustedType::const_iterator iter =
      attribute_types->find(q_name.LocalName());
  if (iter != attribute_types->end()) {
    return iter->value;
  }

  // Since event handlers can be defined on nearly all elements, we will
  // consider them independently of the specific element they're attached to.
  //
  // Note: Element::IsEventHandlerAttribute is different and over-approximates
  // event-handler-ness, since it is expected to work only for builtin
  // attributes (like "onclick"), while Trusted Types needs to deal with
  // whatever users pass into setAttribute (for example "one"). Also, it
  // requires the actual Attribute rather than the QName, which means
  // Element::IsEventHandlerAttribute can only be called after an attribute has
  // been constructed.
  if (IsTrustedTypesEventHandlerAttribute(q_name)) {
    return SpecificTrustedType::kScript;
  }

  return SpecificTrustedType::kNone;
}

DISABLE_CFI_PERF
void Element::AttributeChanged(const AttributeModificationParams& params) {
  ParseAttribute(params);

  GetDocument().IncDOMTreeVersion();
  GetDocument().NotifyAttributeChanged(*this, params.name, params.old_value,
                                       params.new_value);

  const QualifiedName& name = params.name;
  if (name == html_names::kIdAttr) {
    AtomicString lowercase_id;
    if (GetDocument().InQuirksMode() && !params.new_value.IsLowerASCII()) {
      lowercase_id = params.new_value.LowerASCII();
    }
    const AtomicString& new_id = lowercase_id ? lowercase_id : params.new_value;
    if (new_id != GetElementData()->IdForStyleResolution()) {
      AtomicString old_id = GetElementData()->SetIdForStyleResolution(new_id);
      GetDocument().GetStyleEngine().IdChangedForElement(old_id, new_id, *this);
    }

    if (GetDocument().HasRenderBlockingExpectLinkElements() &&
        IsFinishedParsingChildren()) {
      DCHECK(GetDocument().GetRenderBlockingResourceManager());
      GetDocument()
          .GetRenderBlockingResourceManager()
          ->RemovePendingParsingElement(GetIdAttribute(), this);
    }
  } else if (name == html_names::kClassAttr) {
    if (params.old_value == params.new_value &&
        params.reason != AttributeModificationReason::kByMoveToNewDocument) {
      return;
    }
    ClassAttributeChanged(params.new_value);
    UpdateClassList(params.old_value, params.new_value);
  } else if (name == html_names::kNameAttr) {
    SetHasName(!params.new_value.IsNull());
  } else if (name == html_names::kPartAttr) {
    part().DidUpdateAttributeValue(params.old_value, params.new_value);
    GetDocument().GetStyleEngine().PartChangedForElement(*this);
  } else if (name == html_names::kExportpartsAttr) {
    EnsureElementRareData().SetPartNamesMap(params.new_value);
    GetDocument().GetStyleEngine().ExportpartsChangedForElement(*this);
  } else if (name == html_names::kTabindexAttr) {
    int tabindex = 0;
    if (params.new_value.empty() ||
        !ParseHTMLInteger(params.new_value, tabindex)) {
      ClearTabIndexExplicitlyIfNeeded();
    } else {
      // We only set when value is in integer range.
      SetTabIndexExplicitly();
    }
    if (params.reason == AttributeModificationReason::kDirectly &&
        AdjustedFocusedElementInTreeScope() == this) {
      // The attribute change may cause supportsFocus() to return false
      // for the element which had focus.
      //
      // TODO(tkent): We should avoid updating style.  We'd like to check only
      // DOM-level focusability here.
      GetDocument().UpdateStyleAndLayoutTreeForElement(
          this, DocumentUpdateReason::kFocus);
      if (!IsFocusable() && !GetFocusableArea()) {
        blur();
      }
    }
  } else if (params.name == html_names::kAnchorAttr) {
    if (RuntimeEnabledFeatures::HTMLAnchorAttributeEnabled()) {
      EnsureAnchorElementObserver().Notify();
      return;
    }
  } else if (name == html_names::kSlotAttr) {
    if (params.old_value != params.new_value) {
      if (ShadowRoot* root = ShadowRootOfParent()) {
        root->DidChangeHostChildSlotName(params.old_value, params.new_value);
      }
    }
  } else if (name == html_names::kFocusgroupAttr) {
    // Only update the focusgroup flags when the node has been added to the
    // tree. This is because the computed focusgroup value will depend on the
    // focusgroup value of its closest ancestor node that is a focusgroup, if
    // any.
    if (parentNode()) {
      UpdateFocusgroup(params.new_value);
    }
  } else if (IsElementReflectionAttribute(name)) {
    SynchronizeContentAttributeAndElementReference(name);
  } else if (IsStyledElement()) {
    if (name == html_names::kStyleAttr) {
      if (params.old_value == params.new_value) {
        return;
      }
      StyleAttributeChanged(params.new_value, params.reason);
    } else if (IsPresentationAttribute(name)) {
      GetElementData()->SetPresentationAttributeStyleIsDirty(true);
      SetNeedsStyleRecalc(kLocalStyleChange,
                          StyleChangeReasonForTracing::FromAttribute(name));
    }
  }

  InvalidateNodeListCachesInAncestors(&name, this, nullptr);

  if (isConnected()) {
    if (AXObjectCache* cache = GetDocument().ExistingAXObjectCache()) {
      if (params.old_value != params.new_value) {
        cache->HandleAttributeChanged(name, this);
      }
    }
  }
}

bool Element::HasLegalLinkAttribute(const QualifiedName&) const {
  return false;
}

void Element::ClassAttributeChanged(const AtomicString& new_class_string) {
  DCHECK(HasElementData());
  // Note that this is a copy-by-value of the class names.
  const SpaceSplitString old_classes = GetElementData()->ClassNames();
  if (new_class_string.empty()) [[unlikely]] {
    GetDocument().GetStyleEngine().ClassChangedForElement(old_classes, *this);
    GetElementData()->ClearClass();
    return;
  }
  if (GetDocument().InQuirksMode()) [[unlikely]] {
    GetElementData()->SetClassFoldingCase(new_class_string);
  } else {
    GetElementData()->SetClass(new_class_string);
  }
  const SpaceSplitString& new_classes = GetElementData()->ClassNames();
  GetDocument().GetStyleEngine().ClassChangedForElement(old_classes,
                                                        new_classes, *this);
}

void Element::UpdateClassList(const AtomicString& old_class_string,
                              const AtomicString& new_class_string) {
  if (const ElementRareDataVector* data = GetElementRareData()) {
    if (DOMTokenList* class_list = data->GetClassList()) {
      class_list->DidUpdateAttributeValue(old_class_string, new_class_string);
    }
  }
}

// Returns true if the given attribute is an event handler.
// We consider an event handler any attribute that begins with "on".
// It is a simple solution that has the advantage of not requiring any
// code or configuration change if a new event handler is defined.

static inline bool IsEventHandlerAttribute(const Attribute& attribute) {
  return attribute.GetName().NamespaceURI().IsNull() &&
         attribute.GetName().LocalName().StartsWith("on");
}

bool Element::AttributeValueIsJavaScriptURL(const Attribute& attribute) {
  return ProtocolIsJavaScript(
      StripLeadingAndTrailingHTMLSpaces(attribute.Value()));
}

bool Element::IsJavaScriptURLAttribute(const Attribute& attribute) const {
  return IsURLAttribute(attribute) && AttributeValueIsJavaScriptURL(attribute);
}

bool Element::IsScriptingAttribute(const Attribute& attribute) const {
  return IsEventHandlerAttribute(attribute) ||
         IsJavaScriptURLAttribute(attribute) ||
         IsHTMLContentAttribute(attribute) ||
         IsSVGAnimationAttributeSettingJavaScriptURL(attribute);
}

void Element::StripScriptingAttributes(
    Vector<Attribute, kAttributePrealloc>& attribute_vector) const {
  wtf_size_t destination = 0;
  for (wtf_size_t source = 0; source < attribute_vector.size(); ++source) {
    if (IsScriptingAttribute(attribute_vector[source])) {
      continue;
    }

    if (source != destination) {
      attribute_vector[destination] = attribute_vector[source];
    }

    ++destination;
  }
  attribute_vector.Shrink(destination);
}

void Element::ParserSetAttributes(
    const Vector<Attribute, kAttributePrealloc>& attribute_vector) {
  DCHECK(!isConnected());
  DCHECK(!parentNode());
  DCHECK(!element_data_);

  if (!attribute_vector.empty()) {
    if (GetDocument().GetElementDataCache()) {
      element_data_ =
          GetDocument()
              .GetElementDataCache()
              ->CachedShareableElementDataWithAttributes(attribute_vector);
    } else {
      element_data_ =
          ShareableElementData::CreateWithAttributes(attribute_vector);
    }
  }

  ParserDidSetAttributes();

  // Use attribute_vector instead of element_data_ because AttributeChanged
  // might modify element_data_.
  for (const auto& attribute : attribute_vector) {
    AttributeChanged(AttributeModificationParams(
        attribute.GetName(), g_null_atom, attribute.Value(),
        AttributeModificationReason::kByParser));
  }
}

bool Element::HasEquivalentAttributes(const Element& other) const {
  SynchronizeAllAttributes();
  other.SynchronizeAllAttributes();
  if (GetElementData() == other.GetElementData()) {
    return true;
  }
  if (HasElementData()) {
    return GetElementData()->IsEquivalent(other.GetElementData());
  }
  if (other.HasElementData()) {
    return other.GetElementData()->IsEquivalent(GetElementData());
  }
  return true;
}

String Element::nodeName() const {
  return tag_name_.ToString();
}

AtomicString Element::LocalNameForSelectorMatching() const {
  if (IsHTMLElement() || !IsA<HTMLDocument>(GetDocument())) {
    return localName();
  }
  return localName().LowerASCII();
}

const AtomicString& Element::LocateNamespacePrefix(
    const AtomicString& namespace_to_locate) const {
  if (!prefix().IsNull() && namespaceURI() == namespace_to_locate) {
    return prefix();
  }

  AttributeCollection attributes = Attributes();
  for (const Attribute& attr : attributes) {
    if (attr.Prefix() == g_xmlns_atom && attr.Value() == namespace_to_locate) {
      return attr.LocalName();
    }
  }

  if (Element* parent = parentElement()) {
    return parent->LocateNamespacePrefix(namespace_to_locate);
  }

  return g_null_atom;
}

const AtomicString Element::ImageSourceURL() const {
  return FastGetAttribute(html_names::kSrcAttr);
}

bool Element::LayoutObjectIsNeeded(const DisplayStyle& style) const {
  return style.Display() != EDisplay::kNone &&
         style.Display() != EDisplay::kContents;
}

bool Element::LayoutObjectIsNeeded(const ComputedStyle& style) const {
  return LayoutObjectIsNeeded(style.GetDisplayStyle());
}

LayoutObject* Element::CreateLayoutObject(const ComputedStyle& style) {
  return LayoutObject::CreateObject(this, style);
}

Node::InsertionNotificationRequest Element::InsertedInto(
    ContainerNode& insertion_point) {
  // need to do superclass processing first so isConnected() is true
  // by the time we reach updateId
  ContainerNode::InsertedInto(insertion_point);

  DCHECK(!GetElementRareData() || !GetElementRareData()->HasPseudoElements() || GetDocument().StatePreservingAtomicMoveInProgress());

  RecomputeDirectionFromParent();

  if (AnchorElementObserver* observer = GetAnchorElementObserver()) {
    observer->Notify();
  }

  if (!insertion_point.IsInTreeScope()) {
    return kInsertionDone;
  }

  if (isConnected()) {
    if (ElementRareDataVector* rare_data = GetElementRareData()) {
      if (ElementIntersectionObserverData* observer_data =
              rare_data->IntersectionObserverData()) {
        observer_data->TrackWithController(
            GetDocument().EnsureIntersectionObserverController());
        if (!observer_data->IsEmpty()) {
          if (LocalFrameView* frame_view = GetDocument().View()) {
            frame_view->SetIntersectionObservationState(
                LocalFrameView::kRequired);
          }
        }
      }

      if (auto* context = rare_data->GetDisplayLockContext()) {
        context->ElementConnected();
      }
    }
  }

  if (isConnected()) {
    EnqueueAutofocus(*this);

    if (GetCustomElementState() == CustomElementState::kCustom) {
      if (GetDocument().StatePreservingAtomicMoveInProgress()) {
        CustomElement::EnqueueConnectedMoveCallback(*this);
      } else {
        CustomElement::EnqueueConnectedCallback(*this);
      }
    } else if (GetCustomElementState() == CustomElementState::kUndefined) {
      CustomElement::TryToUpgrade(*this);
    }
  }

  TreeScope& scope = insertion_point.GetTreeScope();
  if (scope != GetTreeScope()) {
    return kInsertionDone;
  }

  const AtomicString& id_value = GetIdAttribute();
  if (!id_value.IsNull()) {
    UpdateId(scope, g_null_atom, id_value);
  }

  const AtomicString& name_value = GetNameAttribute();
  if (!name_value.IsNull()) {
    UpdateName(g_null_atom, name_value);
  }

  ExecutionContext* context = GetExecutionContext();
  if (RuntimeEnabledFeatures::FocusgroupEnabled(context)) {
    const AtomicString& focusgroup_value =
        FastGetAttribute(html_names::kFocusgroupAttr);
    if (!focusgroup_value.IsNull()) {
      UpdateFocusgroup(focusgroup_value);
    }

    // We parse the focusgroup attribute for the ShadowDOM elements before we
    // parse it for any of its root's ancestors, which might lead to an
    // incorrect focusgroup value. Re-run the algorithm for the ShadowDOM
    // elements when the ShadowRoot's parent gets inserted in the tree.
    if (GetShadowRoot()) {
      UpdateFocusgroupInShadowRootIfNeeded();
    }
  }

  if (parentElement() && parentElement()->IsInCanvasSubtree()) {
    SetIsInCanvasSubtree(true);
  }

  if (GetDocument().StatePreservingAtomicMoveInProgress() &&
      Fullscreen::IsFullscreenElement(*this)) {
    // We don't actually need to cross frame boundaries, but we do need to mark
    // all our ancestors as containing a full screen element.
    SetContainsFullScreenElementOnAncestorsCrossingFrameBoundaries(true);
  }

  return kInsertionDone;
}

void Element::MovedFrom(ContainerNode& old_parent) {
  Node::MovedFrom(old_parent);

  DCHECK(!GetDocument().StatePreservingAtomicMoveInProgress());

  // `old_parent` can be the document.
  if (!old_parent.IsElementNode()) {
    return;
  }

  Element* focused_element = GetDocument().FocusedElement();
  Element* new_parent_element = parentElement();
  Element* old_parent_element = &To<Element>(old_parent);
  if (focused_element && old_parent.HasFocusWithin() &&
      contains(focused_element) && old_parent != *new_parent_element) {
    Element* common_ancestor = To<Element>(NodeTraversal::CommonAncestor(
        *old_parent_element, *new_parent_element));

    // The "focus within" flag is set separately on each ancestor, and affects
    // the :focus-within CSS property. We set it to the right value here because
    // we skipped the step that sets it on removal/insertion.
    old_parent_element->SetHasFocusWithinUpToAncestor(false, common_ancestor);
    new_parent_element->SetHasFocusWithinUpToAncestor(true, common_ancestor);
  }
}

void Element::RemovedFrom(ContainerNode& insertion_point) {
  bool was_in_document = insertion_point.isConnected();

  if (!GetDocument().StatePreservingAtomicMoveInProgress()) {
    SetComputedStyle(nullptr);
  }

  if (Fullscreen::IsFullscreenElement(*this)) {
    SetContainsFullScreenElementOnAncestorsCrossingFrameBoundaries(false);
    if (auto* insertion_point_element = DynamicTo<Element>(insertion_point)) {
      insertion_point_element->SetContainsFullScreenElement(false);
      insertion_point_element
          ->SetContainsFullScreenElementOnAncestorsCrossingFrameBoundaries(
              false);
    }
  }
  Document& document = GetDocument();
  Page* page = document.GetPage();
  if (page) {
    page->GetPointerLockController().ElementRemoved(this);
  }

  document.UnobserveForIntrinsicSize(this);
  if (auto* local_frame_view = document.View();
      local_frame_view &&
      (LastRememberedInlineSize() || LastRememberedBlockSize())) {
    local_frame_view->NotifyElementWithRememberedSizeDisconnected(this);
  }

  SetSavedLayerScrollOffset(ScrollOffset());

  if (insertion_point.IsInTreeScope() && GetTreeScope() == document) {
    const AtomicString& id_value = GetIdAttribute();
    if (!id_value.IsNull()) {
      UpdateId(insertion_point.GetTreeScope(), id_value, g_null_atom);
    }

    const AtomicString& name_value = GetNameAttribute();
    if (!name_value.IsNull()) {
      UpdateName(name_value, g_null_atom);
    }
  }

  ContainerNode::RemovedFrom(insertion_point);

  if (was_in_document) {
    if (!RuntimeEnabledFeatures::KeepCSSTargetAfterReattachEnabled() &&
        this == document.CssTarget()) {
      document.SetCSSTarget(nullptr);
    }

    if (GetCustomElementState() == CustomElementState::kCustom &&
        !GetDocument().StatePreservingAtomicMoveInProgress()) {
      CustomElement::EnqueueDisconnectedCallback(*this);
    }
  }

  RecomputeDirectionFromParent();

  document.GetRootScrollerController().ElementRemoved(*this);

  if (IsInTopLayer() && !document.StatePreservingAtomicMoveInProgress()) {
    Fullscreen::ElementRemoved(*this);
    document.RemoveFromTopLayerImmediately(this);
  }

  ClearElementFlag(ElementFlags::kIsInCanvasSubtree);

  if (ElementRareDataVector* data = GetElementRareData()) {
    data->ClearFocusgroupFlags();
    data->ClearRestyleFlags();

    if (!GetDocument().StatePreservingAtomicMoveInProgress()) {
      if (ElementAnimations* element_animations =
              data->GetElementAnimations()) {
        element_animations->CssAnimations().Cancel();
      }
    }

    NodeRareData* node_data = RareData();
    node_data->InvalidateAssociatedAnimationEffects();
    if (was_in_document) {
      if (auto* observer_data = data->IntersectionObserverData()) {
        observer_data->ComputeIntersectionsForTarget();
        observer_data->StopTrackingWithController(
            document.EnsureIntersectionObserverController());
      }
    }

    if (auto* context = data->GetDisplayLockContext()) {
      context->ElementDisconnected();
    }

    DCHECK(!data->HasPseudoElements() ||
           GetDocument().StatePreservingAtomicMoveInProgress());

  }

  if (auto* const frame = document.GetFrame()) {
    if (HasUndoStack()) [[unlikely]] {
      frame->GetEditor().GetUndoStack().ElementRemoved(this);
    }
    frame->GetEditor().ElementRemoved(this);
    frame->GetSpellChecker().ElementRemoved(this);
    frame->GetEventHandler().ElementRemoved(this);
  }

  if (AnchorElementObserver* observer = GetAnchorElementObserver()) {
    observer->Notify();
  }
}

void Element::AttachLayoutTree(AttachContext& context) {
  DCHECK(GetDocument().InStyleRecalc() ||
         GetDocument().GetStyleEngine().InScrollMarkersAttachment());

  StyleEngine& style_engine = GetDocument().GetStyleEngine();

  const ComputedStyle* style = GetComputedStyle();
  bool being_rendered =
      context.parent && style && !style->IsEnsuredInDisplayNone();

  bool skipped_container_descendants = SkippedContainerStyleRecalc();

  if (!being_rendered && !ChildNeedsReattachLayoutTree()) {
    // We may have skipped recalc for this Element if it's a query container for
    // size queries. This recalc must be resumed now, since we're not going to
    // create a LayoutObject for the Element after all.
    if (skipped_container_descendants) {
      style_engine.UpdateStyleForNonEligibleContainer(*this);
      skipped_container_descendants = false;
    }
    // The above recalc may have marked some descendant for reattach, which
    // would set the child-needs flag.
    if (!ChildNeedsReattachLayoutTree()) {
      Node::AttachLayoutTree(context);
      return;
    }
  }

  AttachPseudoElement(kPseudoIdScrollMarkerGroupBefore, context);

  AttachContext children_context(context);
  LayoutObject* layout_object = nullptr;
  if (being_rendered) {
    LayoutTreeBuilderForElement builder(*this, context, style);
    builder.CreateLayoutObject();

    layout_object = GetLayoutObject();
    if (layout_object) {
      children_context.previous_in_flow = nullptr;
      children_context.parent = layout_object;
      children_context.next_sibling = nullptr;
      children_context.next_sibling_valid = true;
    } else if (style->Display() != EDisplay::kContents) {
      // The layout object creation was suppressed for other reasons than
      // being display:none or display:contents (E.g.
      // LayoutObject::CanHaveChildren() returning false). Make sure we don't
      // attempt to create LayoutObjects further down the subtree.
      children_context.parent = nullptr;
    }
    // For display:contents elements, we keep the previous_in_flow,
    // next_sibling, and parent, in the context for attaching children.
  } else {
    // We are a display:none element. Set the parent to nullptr to make sure
    // we never create any child layout boxes.
    children_context.parent = nullptr;
  }
  children_context.use_previous_in_flow = true;

  AttachPseudoElement(kPseudoIdScrollMarkerGroupAfter, context);

  if (skipped_container_descendants &&
      (!layout_object || !layout_object->IsEligibleForSizeContainment())) {
    style_engine.UpdateStyleForNonEligibleContainer(*this);
    skipped_container_descendants = false;
  }

  bool skip_lock_descendants = ChildStyleRecalcBlockedByDisplayLock();
  if (skipped_container_descendants || skip_lock_descendants) {
    // Since we block style recalc on descendants of this node due to display
    // locking or container queries, none of its descendants should have the
    // NeedsReattachLayoutTree bit set.
    DCHECK(!ChildNeedsReattachLayoutTree());

    if (skip_lock_descendants) {
      // If an element is locked we shouldn't attach the layout tree for its
      // descendants. We should notify that we blocked a reattach so that we
      // will correctly attach the descendants when allowed.
      GetDisplayLockContext()->NotifyReattachLayoutTreeWasBlocked();
    }
    Node::AttachLayoutTree(context);
    if (layout_object && layout_object->AffectsWhitespaceSiblings()) {
      context.previous_in_flow = layout_object;
    }
    return;
  }

  if (!IsPseudoElement() && layout_object) {
    context.counters_context.EnterObject(*layout_object);
  }

  AttachPrecedingPseudoElements(children_context);

  if (ShadowRoot* shadow_root = GetShadowRoot()) {
    // When a shadow root exists, it does the work of attaching the children.
    shadow_root->AttachLayoutTree(children_context);
    Node::AttachLayoutTree(context);
    ClearChildNeedsReattachLayoutTree();
  } else if (HTMLSlotElement* slot =
                 ToHTMLSlotElementIfSupportsAssignmentOrNull(this)) {
    slot->AttachLayoutTreeForSlotChildren(children_context);
    Node::AttachLayoutTree(context);
    ClearChildNeedsReattachLayoutTree();
  } else {
    ContainerNode::AttachLayoutTree(children_context);
  }

  AttachSucceedingPseudoElements(children_context);

  if (!IsPseudoElement() && layout_object) {
    context.counters_context.LeaveObject(*layout_object);
  }

  if (layout_object) {
    if (layout_object->AffectsWhitespaceSiblings()) {
      context.previous_in_flow = layout_object;
    }
    layout_object->HandleSubtreeModifications();
  } else {
    context.previous_in_flow = children_context.previous_in_flow;
  }
}

void Element::DetachLayoutTree(bool performing_reattach) {
  HTMLFrameOwnerElement::PluginDisposeSuspendScope suspend_plugin_dispose;

  // Pseudo elements that may have child pseudo elements (such as ::column) must
  // be cleared before clearing the rare data vector below.
  ClearColumnPseudoElements();

  if (ElementRareDataVector* data = GetElementRareData()) {
    if (!performing_reattach) {
      data->ClearPseudoElements();
      data->ClearContainerQueryData();
      data->ClearOutOfFlowData();
    } else if (data->GetOutOfFlowData()) {
      GetDocument()
          .GetStyleEngine()
          .MarkLastSuccessfulPositionFallbackDirtyForElement(*this);
    }

    if (ElementAnimations* element_animations = data->GetElementAnimations()) {
      if (!performing_reattach) {
        DocumentLifecycle::DetachScope will_detach(GetDocument().Lifecycle());
        element_animations->CssAnimations().Cancel();
        element_animations->SetAnimationStyleChange(false);
      }
      element_ani
```