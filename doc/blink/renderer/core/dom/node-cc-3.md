Response:
The user is asking for a summary of the functionality of the provided C++ code snippet from `blink/renderer/core/dom/node.cc`. They want to know what the code does, its relationship to web technologies like JavaScript, HTML, and CSS, potential usage errors, debugging approaches, and a general summarization of the code's purpose within the broader context of the `Node` class.

Here's a breakdown of the thinking process:

1. **Identify the Core Functionality:** The code primarily deals with methods related to visualizing and understanding the structure of the DOM tree, including shadow DOM, and also touches on event handling and mutation observers. Specifically, the functions `AppendMarkedTree`, `AppendMarkedFlatTree`, `ToMarkedTreeString`, and `ToMarkedFlatTreeString` stand out as focused on representing the DOM.

2. **Relate to Web Technologies:**
    * **HTML:** The DOM tree *is* the representation of HTML. The code manipulates and visualizes this structure. The presence of pseudo-elements like `::before` and shadow roots directly relates to HTML's structure and extensibility.
    * **CSS:** Pseudo-elements (`::before`, `::after`, etc.) are a CSS concept. The code iterates through these, indicating a link between the DOM structure and CSS styling rules that generate these elements.
    * **JavaScript:** While this specific code is C++, the functionality it provides is *used* by the browser when developers interact with the DOM using JavaScript. For instance, debugging tools (which might use this kind of visualization) are often used to understand how JavaScript has manipulated the DOM. Events and mutation observers, although handled internally by Blink, are triggered and observed by JavaScript.

3. **Identify Logic and Potential Input/Output:**
    * The `AppendMarkedTree` and `AppendMarkedFlatTree` functions seem to take a starting node and optionally two "marked" nodes, along with labels for those nodes. They then traverse the DOM tree and build a string representation, potentially highlighting the marked nodes.
    * **Hypothetical Input:**  A `Node` object (e.g., a `<div>` element), and potentially pointers to other `Node` objects within that tree that need to be marked with specific labels.
    * **Hypothetical Output:** A string representing the DOM structure, with indentation to show hierarchy, and the marked nodes prefixed with their labels.

4. **Consider Common Usage Errors and Debugging:**
    * **User Errors:** Developers often have difficulty understanding the impact of shadow DOM or complex CSS selectors on the actual DOM structure. This code could be part of tools that help visualize these complexities.
    * **Debugging:**  When debugging web page rendering or JavaScript interactions, understanding the precise DOM structure is crucial. Functions like `ToMarkedTreeString` are likely used by browser developer tools to show the DOM hierarchy. The marking of specific nodes is a strong hint toward debugging use cases, allowing developers to pinpoint specific elements of interest. Stepping through the code would involve examining how the tree is traversed and how the string representation is built.

5. **Connect to Previous Parts:**  The request explicitly mentions this is part 4 of 5. This implies that the earlier parts likely laid the groundwork for the `Node` class itself and its basic functionalities. This part seems to be adding debugging and introspection capabilities.

6. **Formulate the Summary:** Based on the analysis, the code provides functionality to generate string representations of the DOM tree, focusing on debugging and visualization. It directly relates to HTML (DOM structure) and CSS (pseudo-elements) and aids in understanding how JavaScript manipulations affect the DOM.

7. **Refine and Structure the Answer:** Organize the findings into the requested categories: functionality, relationship to web technologies, logical reasoning, usage errors, debugging, and a final summary. Provide concrete examples where possible.
Based on the provided code snippet from `blink/renderer/core/dom/node.cc`, here's a breakdown of its functionality:

**Core Functionality:**

This code snippet primarily focuses on providing methods to generate string representations of the DOM tree, particularly for debugging and inspection purposes. It allows for:

* **Tree-like representation:**  Generating a string output that visually represents the hierarchical structure of the DOM, including the nesting of elements and shadow roots.
* **Flat-tree representation:** Generating a string output based on the flat tree traversal order, which is important for understanding slot assignment in shadow DOM.
* **Marking specific nodes:**  Highlighting specific nodes within the generated tree string with user-provided labels. This is extremely useful for debugging and identifying particular nodes of interest.
* **Traversal across frames:** Printing the subtree structure even when it spans across different HTML frames.

**Relationship to Javascript, HTML, and CSS:**

* **HTML:** The entire purpose of this code revolves around the HTML DOM (Document Object Model). It's responsible for visualizing the structure that HTML creates. The code traverses the `Node` hierarchy, which directly reflects the HTML structure of a web page.
    * **Example:**  The code would represent the following HTML:
      ```html
      <div>
        <span>Hello</span>
      </div>
      ```
      with indentation showing the `<span>` element is a child of the `<div>`.
* **CSS:** The code specifically considers CSS pseudo-elements (like `::before`, `::after`, `::marker`, etc.) and shadow roots. These are core concepts in CSS that allow for styling and encapsulation. The code iterates through these pseudo-elements to include them in the tree representation.
    * **Example:** If a `div` element has a `::before` pseudo-element defined in CSS, the `AppendMarkedTree` function will find it using `GetPseudoElement(kPseudoIdBefore)` and include it in the output.
* **Javascript:** While this code is in C++, the output it generates is invaluable for JavaScript developers debugging their code. When JavaScript manipulates the DOM, developers often need to inspect the resulting structure. Browser developer tools likely use similar mechanisms to show the DOM tree in the "Elements" tab.
    * **Example:** A JavaScript function might dynamically create and append new elements to the DOM. Developers can then use the output of functions like `ToMarkedTreeString` (likely exposed through internal debugging tools) to verify that the DOM structure is as expected after the JavaScript execution.

**Logical Reasoning, Assumptions, and Input/Output:**

* **Assumption:** The input is a valid `Node` object within a Blink rendering tree.
* **Input:**
    * `this`:  A pointer to the starting `Node` from which the tree traversal begins.
    * `marked_node1`, `marked_node2`: Optional pointers to specific `Node` objects within the tree that need to be marked.
    * `marked_label1`, `marked_label2`: Optional C-style strings used as labels for the marked nodes.
* **Logical Steps:**
    1. **Determine the root:** The code first finds the root of the subtree to be printed. It traverses up the parent chain until it reaches the document or the `<body>` element.
    2. **Recursive traversal:** The `AppendMarkedTree` and `AppendMarkedFlatTree` functions recursively traverse the DOM tree (or flat tree), building the string representation.
    3. **Indentation:** Indentation is added to the output string to visually represent the parent-child relationship between nodes.
    4. **Pseudo-element handling:** For `Element` nodes, the code checks for various pseudo-elements and includes them in the output.
    5. **Shadow root handling:** If a node has a shadow root, it's also traversed and included in the output.
    6. **Marking nodes:** If `marked_node1` or `marked_node2` match the currently visited node, their corresponding labels are prepended to the output.
* **Output:** A `String` object containing the formatted representation of the DOM tree.

**Example Input and Output (Conceptual):**

**Input:**
* `this`: Pointer to the `<span>` element in the HTML example above.
* `marked_node1`: Pointer to the `<div>` element.
* `marked_label1`: "[DIV]"

**Conceptual Output (using `ToMarkedTreeString`):**

```
[DIV]div
	span
```

**Conceptual Output (using `ToMarkedFlatTreeString`):**

```
[DIV]div
	span
```

**User or Programming Common Usage Errors:**

* **Incorrect `marked_node` pointers:** Passing invalid or null pointers for `marked_node1` or `marked_node2` might lead to crashes or unexpected behavior (although the code doesn't seem to explicitly handle null checks in these marking sections, relying on the caller to provide valid pointers).
* **Misunderstanding the difference between tree and flat tree:** Developers might use the wrong function (`ToMarkedTreeString` vs. `ToMarkedFlatTreeString`) if they don't understand the distinction between the regular DOM tree and the flat tree used for shadow DOM composition. This could lead to incorrect assumptions about the DOM structure, especially when dealing with slots and distributed nodes.
* **Performance overhead in production:** These string generation functions are likely intended for debugging and should not be used extensively in performance-critical production code due to the overhead of string manipulation and tree traversal.

**User Operation to Reach This Code (Debugging Scenario):**

1. **Developer notices an issue:** A web page isn't rendering correctly, JavaScript is behaving unexpectedly, or there are issues with shadow DOM slot assignment.
2. **Open browser developer tools:** The developer opens the browser's DevTools (e.g., Chrome DevTools).
3. **Inspect the DOM tree:** The developer navigates to the "Elements" tab to inspect the DOM structure.
4. **Potentially trigger a "break on subtree modification" breakpoint:** If the issue is related to dynamic DOM changes, the developer might set a breakpoint to pause JavaScript execution when a specific node or its subtree is modified.
5. **Use a DevTools command or API:** Internally, the DevTools might call a function similar to `ToMarkedTreeString` or `ToMarkedFlatTreeString` to generate the visual representation of the DOM that is displayed in the "Elements" tab. The "mark node" functionality in DevTools would directly utilize the marking capabilities of these functions.
6. **Step through the code:** If the developer needs more granular insight, they might step through the Blink rendering engine's code (if they have access to the source and a suitable debugging environment). They might set a breakpoint within `AppendMarkedTree` to see how the tree is being traversed and the string is being built.

**Summary of Functionality (Part 4):**

This part of the `blink/renderer/core/dom/node.cc` file provides functionality for generating string representations of the DOM tree, both in its traditional hierarchical form and the "flat tree" representation relevant for shadow DOM. It includes features to mark specific nodes within these representations, making it a valuable tool for debugging and understanding the structure of the DOM, especially when dealing with complex scenarios involving shadow DOM and dynamically generated content. It bridges the internal C++ representation of the DOM with the visual representations used in developer tools.

### 提示词
```
这是目录为blink/renderer/core/dom/node.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
}
      if (Element* pseudo = element->GetPseudoElement(kPseudoIdMarker)) {
        AppendMarkedTree(indent_string, pseudo, marked_node1, marked_label1,
                         marked_node2, marked_label2, builder);
      }
      if (const ColumnPseudoElementsVector* column_pseudo_elements =
              element->GetColumnPseudoElements()) {
        for (const ColumnPseudoElement* pseudo : *column_pseudo_elements) {
          AppendMarkedTree(indent_string, pseudo, marked_node1, marked_label1,
                           marked_node2, marked_label2, builder);
        }
      }
      if (Element* pseudo = element->GetPseudoElement(kPseudoIdScrollMarker)) {
        AppendMarkedTree(indent_string, pseudo, marked_node1, marked_label1,
                         marked_node2, marked_label2, builder);
      }
      if (Element* pseudo = element->GetPseudoElement(kPseudoIdCheck)) {
        AppendMarkedTree(indent_string, pseudo, marked_node1, marked_label1,
                         marked_node2, marked_label2, builder);
      }
      if (Element* pseudo = element->GetPseudoElement(kPseudoIdBefore))
        AppendMarkedTree(indent_string, pseudo, marked_node1, marked_label1,
                         marked_node2, marked_label2, builder);
      if (Element* pseudo = element->GetPseudoElement(kPseudoIdAfter))
        AppendMarkedTree(indent_string, pseudo, marked_node1, marked_label1,
                         marked_node2, marked_label2, builder);
      if (Element* pseudo = element->GetPseudoElement(kPseudoIdSelectArrow)) {
        AppendMarkedTree(indent_string, pseudo, marked_node1, marked_label1,
                         marked_node2, marked_label2, builder);
      }
      if (Element* pseudo =
              element->GetPseudoElement(kPseudoIdScrollMarkerGroupAfter)) {
        AppendMarkedTree(indent_string, pseudo, marked_node1, marked_label1,
                         marked_node2, marked_label2, builder);
      }
      if (Element* pseudo = element->GetPseudoElement(kPseudoIdFirstLetter))
        AppendMarkedTree(indent_string, pseudo, marked_node1, marked_label1,
                         marked_node2, marked_label2, builder);
      if (Element* pseudo = element->GetPseudoElement(kPseudoIdBackdrop))
        AppendMarkedTree(indent_string, pseudo, marked_node1, marked_label1,
                         marked_node2, marked_label2, builder);
    }

    if (ShadowRoot* shadow_root = node.GetShadowRoot()) {
      AppendMarkedTree(indent_string, shadow_root, marked_node1, marked_label1,
                       marked_node2, marked_label2, builder);
    }
  }
}

static void AppendMarkedFlatTree(const String& base_indent,
                                 const Node* root_node,
                                 const Node* marked_node1,
                                 const char* marked_label1,
                                 const Node* marked_node2,
                                 const char* marked_label2,
                                 StringBuilder& builder) {
  for (const Node* node = root_node; node;
       node = FlatTreeTraversal::NextSibling(*node)) {
    StringBuilder indent;
    if (node == marked_node1)
      indent.Append(marked_label1);
    if (node == marked_node2)
      indent.Append(marked_label2);
    indent.Append(base_indent);
    builder.Append(indent);
    builder.Append(node->ToString());
    builder.Append("\n");
    indent.Append('\t');

    if (Node* child = FlatTreeTraversal::FirstChild(*node))
      AppendMarkedFlatTree(indent.ReleaseString(), child, marked_node1,
                           marked_label1, marked_node2, marked_label2, builder);
  }
}

String Node::ToMarkedTreeString(const Node* marked_node1,
                                const char* marked_label1,
                                const Node* marked_node2,
                                const char* marked_label2) const {
  const Node* root_node;
  const Node* node = this;
  while (node->ParentOrShadowHostNode() && !IsA<HTMLBodyElement>(*node))
    node = node->ParentOrShadowHostNode();
  root_node = node;

  StringBuilder builder;
  String starting_indent;
  AppendMarkedTree(starting_indent, root_node, marked_node1, marked_label1,
                   marked_node2, marked_label2, builder);
  return builder.ReleaseString();
}

String Node::ToMarkedFlatTreeString(const Node* marked_node1,
                                    const char* marked_label1,
                                    const Node* marked_node2,
                                    const char* marked_label2) const {
  const Node* root_node;
  const Node* node = this;
  while (node->ParentOrShadowHostNode() && !IsA<HTMLBodyElement>(*node))
    node = node->ParentOrShadowHostNode();
  root_node = node;

  StringBuilder builder;
  String starting_indent;
  AppendMarkedFlatTree(starting_indent, root_node, marked_node1, marked_label1,
                       marked_node2, marked_label2, builder);
  return builder.ReleaseString();
}

static ContainerNode* ParentOrShadowHostOrFrameOwner(const Node* node) {
  ContainerNode* parent = node->ParentOrShadowHostNode();
  if (!parent && node->GetDocument().GetFrame())
    parent = node->GetDocument().GetFrame()->DeprecatedLocalOwner();
  return parent;
}

static void PrintSubTreeAcrossFrame(const Node* node,
                                    const Node* marked_node,
                                    const String& indent,
                                    std::ostream& stream) {
  if (node == marked_node)
    stream << "*";
  stream << indent.Utf8() << *node << "\n";
  if (auto* frame_owner_element = DynamicTo<HTMLFrameOwnerElement>(node)) {
    PrintSubTreeAcrossFrame(frame_owner_element->contentDocument(), marked_node,
                            indent + "\t", stream);
  }
  if (ShadowRoot* shadow_root = node->GetShadowRoot())
    PrintSubTreeAcrossFrame(shadow_root, marked_node, indent + "\t", stream);
  for (const Node* child = node->firstChild(); child;
       child = child->nextSibling())
    PrintSubTreeAcrossFrame(child, marked_node, indent + "\t", stream);
}

void Node::ShowTreeForThisAcrossFrame() const {
  const Node* root_node = this;
  while (ParentOrShadowHostOrFrameOwner(root_node))
    root_node = ParentOrShadowHostOrFrameOwner(root_node);
  std::stringstream stream;
  PrintSubTreeAcrossFrame(root_node, this, "", stream);
  LOG(INFO) << "\n" << stream.str();
}

#endif

// --------

Element* Node::EnclosingLinkEventParentOrSelf() const {
  // https://crbug.com/784492
  DCHECK(this);

  for (const Node* node = this; node; node = FlatTreeTraversal::Parent(*node)) {
    // For imagemaps, the enclosing link node is the associated area element not
    // the image itself.  So we don't let images be the enclosingLinkNode, even
    // though isLink sometimes returns true for them.
    if (node->IsLink() && !IsA<HTMLImageElement>(*node)) {
      // Casting to Element is safe because only HTMLAnchorElement,
      // HTMLImageElement and SVGAElement can return true for isLink().
      return To<Element>(const_cast<Node*>(node));
    }
  }

  return nullptr;
}

const AtomicString& Node::InterfaceName() const {
  return event_target_names::kNode;
}

ExecutionContext* Node::GetExecutionContext() const {
  return GetDocument().GetExecutionContext();
}

void Node::WillMoveToNewDocument(Document& new_document) {
  Document& old_document = GetDocument();
  DCHECK_NE(&old_document, &new_document);

  // In rare situations, this node may be the focused element of the old
  // document. In this case, we need to clear the focused element of the old
  // document, and since we are currently in an event forbidden scope, we can't
  // fire the blur event.
  if (old_document.FocusedElement() == this) {
    FocusParams params(SelectionBehaviorOnFocus::kNone,
                       mojom::blink::FocusType::kNone, nullptr);
    params.omit_blur_events = true;
    old_document.SetFocusedElement(nullptr, params);
  }

  if (!old_document.GetPage() ||
      old_document.GetPage() == new_document.GetPage())
    return;

  old_document.GetFrame()->GetEventHandlerRegistry().DidMoveOutOfPage(*this);

  if (auto* this_element = DynamicTo<Element>(this)) {
    StylePropertyMapReadOnly* computed_style_map_item =
        old_document.RemoveComputedStyleMapItem(this_element);
    if (computed_style_map_item) {
      new_document.AddComputedStyleMapItem(this_element,
                                           computed_style_map_item);
    }
  }
}

void Node::DidMoveToNewDocument(Document& old_document) {
  TreeScopeAdopter::EnsureDidMoveToNewDocumentWasCalled(old_document);
  DCHECK_NE(&GetDocument(), &old_document);

  if (auto* text_node = DynamicTo<Text>(this)) {
    old_document.Markers().RemoveMarkersForNode(*text_node);
  }
}

void Node::AddedEventListener(const AtomicString& event_type,
                              RegisteredEventListener& registered_listener) {
  EventTarget::AddedEventListener(event_type, registered_listener);
  GetDocument().AddListenerTypeIfNeeded(event_type, *this);
  GetDocument().DidAddEventListeners(/*count*/ 1);
  if (auto* frame = GetDocument().GetFrame()) {
    frame->GetEventHandlerRegistry().DidAddEventHandler(
        *this, event_type, registered_listener.Options());
    // We need to track the existence of the visibilitychange event listeners to
    // enable/disable sudden terminations.
    if (IsDocumentNode() && event_type == event_type_names::kVisibilitychange) {
      frame->AddedSuddenTerminationDisablerListener(*this, event_type);
    }
  }
  if (AXObjectCache* cache = GetDocument().ExistingAXObjectCache())
    cache->HandleEventListenerAdded(*this, event_type);
}

void Node::RemovedEventListener(
    const AtomicString& event_type,
    const RegisteredEventListener& registered_listener) {
  EventTarget::RemovedEventListener(event_type, registered_listener);
  GetDocument().DidRemoveEventListeners(/*count*/ 1);
  // FIXME: Notify Document that the listener has vanished. We need to keep
  // track of a number of listeners for each type, not just a bool - see
  // https://bugs.webkit.org/show_bug.cgi?id=33861
  if (auto* frame = GetDocument().GetFrame()) {
    frame->GetEventHandlerRegistry().DidRemoveEventHandler(
        *this, event_type, registered_listener.Options());
  }
  if (AXObjectCache* cache = GetDocument().ExistingAXObjectCache())
    cache->HandleEventListenerRemoved(*this, event_type);
}

void Node::RemoveAllEventListeners() {
  Vector<AtomicString> event_types = EventTypes();
  Document& document = GetDocument();
  if (HasEventListeners()) {
    GetEventTargetData()->event_listener_map.ForAllEventListenerTypes(
        [&document](const AtomicString& event_type, uint32_t count) {
          document.DidRemoveEventListeners(count);
        });

    if (document.GetPage()) {
      document.GetFrame()->GetEventHandlerRegistry().DidRemoveAllEventHandlers(
          *this);
    }
  }
  EventTarget::RemoveAllEventListeners();
  if (AXObjectCache* cache = document.ExistingAXObjectCache()) {
    for (const AtomicString& event_type : event_types) {
      cache->HandleEventListenerRemoved(*this, event_type);
    }
  }
}

void Node::RemoveAllEventListenersRecursively() {
  ScriptForbiddenScope forbid_script_during_raw_iteration;
  for (Node& node : NodeTraversal::StartsAt(*this)) {
    node.RemoveAllEventListeners();
    if (ShadowRoot* root = node.GetShadowRoot())
      root->RemoveAllEventListenersRecursively();
  }
}

void Node::MoveEventListenersToNewDocument(Document& old_document,
                                           Document& new_document) {
  DCHECK_EQ(&new_document, &GetDocument());
  if (const EventTargetData* event_target_data = GetEventTargetData()) {
    const EventListenerMap& listener_map =
        event_target_data->event_listener_map;
    if (!listener_map.IsEmpty()) {
      listener_map.ForAllEventListenerTypes(
          [this, &old_document, &new_document](const AtomicString& event_type,
                                               uint32_t count) {
            old_document.DidRemoveEventListeners(count);
            new_document.AddListenerTypeIfNeeded(event_type, *this);
            new_document.DidAddEventListeners(count);
          });
    }
  }

  if (new_document.GetPage() &&
      new_document.GetPage() != old_document.GetPage()) {
    new_document.GetFrame()->GetEventHandlerRegistry().DidMoveIntoPage(*this);
  }
}

const HeapVector<Member<MutationObserverRegistration>>*
Node::MutationObserverRegistry() {
  if (!data_) {
    return nullptr;
  }
  NodeMutationObserverData* data = data_->MutationObserverData();
  if (!data)
    return nullptr;
  return &data->Registry();
}

const HeapHashSet<Member<MutationObserverRegistration>>*
Node::TransientMutationObserverRegistry() {
  if (!data_) {
    return nullptr;
  }
  NodeMutationObserverData* data = data_->MutationObserverData();
  if (!data)
    return nullptr;
  return &data->TransientRegistry();
}

void Node::MoveMutationObserversToNewDocument(Document& new_document) {
  DCHECK_EQ(&new_document, &GetDocument());
  if (const HeapVector<Member<MutationObserverRegistration>>* registry =
          MutationObserverRegistry()) {
    for (const auto& registration : *registry) {
      new_document.AddMutationObserverTypes(registration->MutationTypes());
    }
  }

  if (const HeapHashSet<Member<MutationObserverRegistration>>*
          transient_registry = TransientMutationObserverRegistry()) {
    for (const auto& registration : *transient_registry) {
      new_document.AddMutationObserverTypes(registration->MutationTypes());
    }
  }
}

template <typename Registry>
static inline void CollectMatchingObserversForMutation(
    HeapHashMap<Member<MutationObserver>, MutationRecordDeliveryOptions>&
        observers,
    Registry* registry,
    Node& target,
    MutationType type,
    const QualifiedName* attribute_name) {
  if (!registry)
    return;

  for (const auto& registration : *registry) {
    if (registration->ShouldReceiveMutationFrom(target, type, attribute_name)) {
      MutationRecordDeliveryOptions delivery_options =
          registration->DeliveryOptions();
      HeapHashMap<Member<MutationObserver>,
                  MutationRecordDeliveryOptions>::AddResult result =
          observers.insert(&registration->Observer(), delivery_options);
      if (!result.is_new_entry)
        result.stored_value->value |= delivery_options;
    }
  }
}

void Node::GetRegisteredMutationObserversOfType(
    HeapHashMap<Member<MutationObserver>, MutationRecordDeliveryOptions>&
        observers,
    MutationType type,
    const QualifiedName* attribute_name) {
  DCHECK((type == kMutationTypeAttributes && attribute_name) ||
         !attribute_name);
  CollectMatchingObserversForMutation(observers, MutationObserverRegistry(),
                                      *this, type, attribute_name);
  CollectMatchingObserversForMutation(observers,
                                      TransientMutationObserverRegistry(),
                                      *this, type, attribute_name);
  ScriptForbiddenScope forbid_script_during_raw_iteration;
  for (Node* node = parentNode(); node; node = node->parentNode()) {
    CollectMatchingObserversForMutation(observers,
                                        node->MutationObserverRegistry(), *this,
                                        type, attribute_name);
    CollectMatchingObserversForMutation(
        observers, node->TransientMutationObserverRegistry(), *this, type,
        attribute_name);
  }
}

void Node::RegisterMutationObserver(
    MutationObserver& observer,
    MutationObserverOptions options,
    const HashSet<AtomicString>& attribute_filter) {
  MutationObserverRegistration* registration = nullptr;
  for (const auto& item :
       EnsureRareData().EnsureMutationObserverData().Registry()) {
    if (&item->Observer() == &observer) {
      registration = item.Get();
      registration->ResetObservation(options, attribute_filter);
    }
  }

  if (!registration) {
    registration = MakeGarbageCollected<MutationObserverRegistration>(
        observer, this, options, attribute_filter);
    EnsureRareData().EnsureMutationObserverData().AddRegistration(registration);
  }

  GetDocument().AddMutationObserverTypes(registration->MutationTypes());
}

void Node::UnregisterMutationObserver(
    MutationObserverRegistration* registration) {
  const HeapVector<Member<MutationObserverRegistration>>* registry =
      MutationObserverRegistry();
  DCHECK(registry);
  if (!registry)
    return;

  // FIXME: Simplify the registration/transient registration logic to make this
  // understandable by humans.  The explicit dispose() is needed to have the
  // registration object unregister itself promptly.
  registration->Dispose();
  EnsureRareData().EnsureMutationObserverData().RemoveRegistration(
      registration);
}

void Node::RegisterTransientMutationObserver(
    MutationObserverRegistration* registration) {
  EnsureRareData().EnsureMutationObserverData().AddTransientRegistration(
      registration);
}

void Node::UnregisterTransientMutationObserver(
    MutationObserverRegistration* registration) {
  const HeapHashSet<Member<MutationObserverRegistration>>* transient_registry =
      TransientMutationObserverRegistry();
  DCHECK(transient_registry);
  if (!transient_registry)
    return;

  EnsureRareData().EnsureMutationObserverData().RemoveTransientRegistration(
      registration);
}

void Node::NotifyMutationObserversNodeWillDetach() {
  if (!GetDocument().HasMutationObservers())
    return;

  ScriptForbiddenScope forbid_script_during_raw_iteration;
  for (Node* node = parentNode(); node; node = node->parentNode()) {
    if (const HeapVector<Member<MutationObserverRegistration>>* registry =
            node->MutationObserverRegistry()) {
      for (const auto& registration : *registry)
        registration->ObservedSubtreeNodeWillDetach(*this);
    }

    if (const HeapHashSet<Member<MutationObserverRegistration>>*
            transient_registry = node->TransientMutationObserverRegistry()) {
      for (auto& registration : *transient_registry)
        registration->ObservedSubtreeNodeWillDetach(*this);
    }
  }
}

void Node::HandleLocalEvents(Event& event) {
  if (!GetEventTargetData()) {
    return;
  }

  FireEventListeners(event);
}

void Node::DispatchScopedEvent(Event& event) {
  event.SetTrusted(true);
  EventDispatcher::DispatchScopedEvent(*this, event);
}

DispatchEventResult Node::DispatchEventInternal(Event& event) {
  return EventDispatcher::DispatchEvent(*this, event);
}

void Node::DispatchSubtreeModifiedEvent() {
  if (IsInShadowTree() || GetDocument().ShouldSuppressMutationEvents()) {
    return;
  }

#if DCHECK_IS_ON()
  DCHECK(!EventDispatchForbiddenScope::IsEventDispatchForbidden());
#endif

  if (!GetDocument().HasListenerType(Document::kDOMSubtreeModifiedListener))
    return;

  DispatchScopedEvent(*MutationEvent::Create(
      event_type_names::kDOMSubtreeModified, Event::Bubbles::kYes));
}

DispatchEventResult Node::DispatchDOMActivateEvent(int detail,
                                                   Event& underlying_event) {
#if DCHECK_IS_ON()
  DCHECK(!EventDispatchForbiddenScope::IsEventDispatchForbidden());
#endif
  UIEvent& event = *UIEvent::Create();
  event.initUIEvent(event_type_names::kDOMActivate, true, true,
                    GetDocument().domWindow(), detail);
  event.SetUnderlyingEvent(&underlying_event);
  event.SetComposed(underlying_event.composed());
  if (!isConnected())
    event.SetCopyEventPathFromUnderlyingEvent();
  DispatchScopedEvent(event);

  // TODO(dtapuska): Dispatching scoped events shouldn't check the return
  // type because the scoped event could get put off in the delayed queue.
  return EventTarget::GetDispatchEventResult(event);
}

void Node::DispatchSimulatedClick(const Event* underlying_event,
                                  SimulatedClickCreationScope scope) {
  if (auto* element = IsElementNode() ? To<Element>(this) : parentElement()) {
    element->ActivateDisplayLockIfNeeded(
        DisplayLockActivationReason::kSimulatedClick);
  }
  EventDispatcher::DispatchSimulatedClick(*this, underlying_event, scope);
}

void Node::DefaultEventHandler(Event& event) {
  if (event.target() != this)
    return;
  const AtomicString& event_type = event.type();
  if (event_type == event_type_names::kKeydown ||
      event_type == event_type_names::kKeypress ||
      event_type == event_type_names::kKeyup) {
    if (auto* keyboard_event = DynamicTo<KeyboardEvent>(&event)) {
      if (LocalFrame* frame = GetDocument().GetFrame()) {
        frame->GetEventHandler().DefaultKeyboardEventHandler(keyboard_event);
      }
    }
  } else if (event_type == event_type_names::kClick) {
    auto* ui_event = DynamicTo<UIEvent>(event);
    int detail = ui_event ? ui_event->detail() : 0;
    if (DispatchDOMActivateEvent(detail, event) !=
        DispatchEventResult::kNotCanceled)
      event.SetDefaultHandled();
  } else if (event_type == event_type_names::kContextmenu &&
             IsA<MouseEvent>(event)) {
    if (Page* page = GetDocument().GetPage()) {
      page->GetContextMenuController().HandleContextMenuEvent(
          To<MouseEvent>(&event));
    }
  } else if (event_type == event_type_names::kTextInput) {
    if (event.HasInterface(event_interface_names::kTextEvent)) {
      if (LocalFrame* frame = GetDocument().GetFrame()) {
        frame->GetEventHandler().DefaultTextInputEventHandler(
            To<TextEvent>(&event));
      }
    }
  } else if (RuntimeEnabledFeatures::MiddleClickAutoscrollEnabled() &&
             event_type == event_type_names::kMousedown &&
             IsA<MouseEvent>(event)) {
    auto& mouse_event = To<MouseEvent>(event);
    if (mouse_event.button() ==
        static_cast<int16_t>(WebPointerProperties::Button::kMiddle)) {
      if (EnclosingLinkEventParentOrSelf())
        return;

      // Avoid that IsUserScrollable changes layout tree structure.
      // FIXME: We should avoid synchronous layout if possible. We can
      // remove this synchronous layout if we avoid synchronous layout in
      // LayoutTextControlSingleLine::scrollHeight
      GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kInput);
      LayoutObject* layout_object = GetLayoutObject();
      while (layout_object &&
             (!layout_object->IsBox() ||
              !To<LayoutBox>(layout_object)->IsUserScrollable())) {
        if (auto* document = DynamicTo<Document>(layout_object->GetNode())) {
          Element* owner = document->LocalOwner();
          layout_object = owner ? owner->GetLayoutObject() : nullptr;
        } else {
          layout_object = layout_object->Parent();
        }
      }
      if (layout_object) {
        if (LocalFrame* frame = GetDocument().GetFrame())
          frame->GetEventHandler().StartMiddleClickAutoscroll(layout_object);
      }
    }
  }
}

void Node::UpdateHadKeyboardEvent(const Event& event) {
  if (GetDocument().HadKeyboardEvent())
    return;

  GetDocument().SetHadKeyboardEvent(true);

  // Changes to HadKeyboardEvent may affect :focus-visible matching,
  // ShouldHaveFocusAppearance and theme painting.
  if (GetLayoutObject()) {
    InvalidateIfHasEffectiveAppearance();

    if (auto* this_element = DynamicTo<Element>(this)) {
      this_element->FocusVisibleStateChanged();
    }
  }
}

bool Node::HasActivationBehavior() const {
  return false;
}

bool Node::WillRespondToMouseMoveEvents() const {
  if (IsDisabledFormControl(this))
    return false;
  return HasEventListeners(event_type_names::kMousemove) ||
         HasEventListeners(event_type_names::kMouseover) ||
         HasEventListeners(event_type_names::kMouseout);
}

bool Node::WillRespondToMouseClickEvents() {
  if (IsDisabledFormControl(this))
    return false;
  GetDocument().UpdateStyleAndLayoutTree();
  return IsEditable(*this) ||
         HasAnyEventListeners(event_util::MouseButtonEventTypes());
}

unsigned Node::ConnectedSubframeCount() const {
  return data_ ? data_->ConnectedSubframeCount() : 0;
}

void Node::IncrementConnectedSubframeCount() {
  DCHECK(IsContainerNode());
  EnsureRareData().IncrementConnectedSubframeCount();
}

void Node::DecrementConnectedSubframeCount() {
  RareData()->DecrementConnectedSubframeCount();
}

ShadowRoot* Node::GetSlotAssignmentRoot() const {
  DCHECK(!IsPseudoElement());
  ShadowRoot* root = ShadowRootOfParent();
  return (root && root->HasSlotAssignment()) ? root : nullptr;
}

HTMLSlotElement* Node::AssignedSlot() const {
  ShadowRoot* root = GetSlotAssignmentRoot();
  if (!root)
    return nullptr;

  // TODO(hayato): Node::AssignedSlot() shouldn't be called while
  // in executing RecalcAssignment(), however, unfortunately,
  // that could happen as follows:
  //
  // 1. RecalcAssignment() can detach a node
  // 2. Then, DetachLayoutTree() may use FlatTreeTraversal via the hook of
  // AXObjectCacheImpl::ChildrenChanged().
  //
  // Note that using FlatTreeTraversal in detaching layout tree should be banned
  // in the long term.
  //
  // If we can remove such code path, we don't need to check
  // IsInSlotAssignmentRecalc() here.
  if (GetDocument().IsInSlotAssignmentRecalc()) {
    // FlatTreeNodeData is not realiable here. Entering slow path.
    return root->AssignedSlotFor(*this);
  }

  // Recalc assignment, if necessary, to make sure the FlatTreeNodeData is not
  // dirty. RecalcAssignment() is almost no-op if we don't need to recalc.
  root->GetSlotAssignment().RecalcAssignment();
  if (FlatTreeNodeData* data = GetFlatTreeNodeData()) {
#if DCHECK_IS_ON()
    // User agent shadow slot assignment (FindSlotInUserAgentShadow()) will
    // re-check the DOM tree, and if we're in the process of removing nodes
    // from the tree, there could be a mismatch here.
    if (root->IsNamedSlotting()) {
      DCHECK_EQ(root->AssignedSlotFor(*this), data->AssignedSlot())
          << "Assigned slot mismatch for node " << this;
    }
#endif
    return data->AssignedSlot();
  }
  return nullptr;
}

// Used when assignment recalc is forbidden, i.e., DetachLayoutTree().
// Returned assignedSlot is not guaranteed up to date.
HTMLSlotElement* Node::AssignedSlotWithoutRecalc() const {
  if (!GetSlotAssignmentRoot())
    return nullptr;

  if (FlatTreeNodeData* data = GetFlatTreeNodeData())
    return data->AssignedSlot();

  return nullptr;
}

HTMLSlotElement* Node::assignedSlotForBinding() {
  // assignedSlot doesn't need to recalc slot assignment
  if (ShadowRoot* root = ShadowRootOfParent()) {
    if (root->GetMode() == ShadowRootMode::kOpen) {
      return AssignedSlot();
    }
  }
  return nullptr;
}

void Node::SetHasFocusWithin(bool flag) {
  GetDocument().UserActionElements().SetHasFocusWithin(this, flag);
}

void Node::SetDragged(bool flag) {
  GetDocument().UserActionElements().SetDragged(this, flag);
}

bool Node::IsUserActionElementActive() const {
  DCHECK(IsUserActionElement());
  return GetDocument().UserActionElements().IsActive(this);
}

bool Node::IsUserActionElementInActiveChain() const {
  DCHECK(IsUserActionElement());
  return GetDocument().UserActionElements().IsInActiveChain(this);
}

bool Node::IsUserActionElementDragged() const {
  DCHECK(IsUserActionElement());
  return GetDocument().UserActionElements().IsDragged(this);
}

bool Node::IsUserActionElementHovered() const {
  DCHECK(IsUserActionElement());
  return GetDocument().UserActionElements().IsHovered(this);
}

bool Node::IsUserActionElementFocused() const {
  DCHECK(IsUserActionElement());
  return GetDocument().UserActionElements().IsFocused(this);
}

bool Node::IsUserActionElementHasFocusWithin() const {
  DCHECK(IsUserActionElement());
  return GetDocument().UserActionElements().HasFocusWithin(this);
}

void Node::SetCustomElementState(CustomElementState new_state) {
  CustomElementState old_state = GetCustomElementState();

  switch (new_state) {
    case CustomElementState::kUncustomized:
      NOTREACHED();  // Everything starts in this state

    case CustomElementState::kUndefined:
      DCHECK_EQ(CustomElementState::kUncustomized, old_state);
      break;

    case CustomElementState::kCustom:
      DCHECK(old_state == CustomElementState::kUndefined ||
             old_state == CustomElementState::kFailed ||
             old_state == CustomElementState::kPreCustomized);
      break;

    case CustomElementState::kFailed:
      DCHECK_NE(CustomElementState::kFailed, old_state);
      break;

    case CustomElementState::kPreCustomized:
      DCHECK_EQ(CustomElementState::kFailed, old_state);
      break;
  }

  DCHECK(IsHTMLElement());

  auto* element = To<Element>(this);
  bool was_defined = element->IsDefined();

  node_flags_ = (node_flags_ & ~kCustomElementStateMask) |
                static_cast<NodeFlags>(new_state);
  DCHECK(new_state == GetCustomElementState());

  if (element->IsDefined() != was_defined)
    element->PseudoStateChanged(CSSSelector::kPseudoDefined);
}

void Node::CheckSlotChange(SlotChangeType slot_change_type) {
  // Common check logic is used in both cases, "after inserted" and "before
  // removed". This function calls DidSlotChange() on the appropriate nodes,
  // e.g. the assigned slot for this node, or the parent slot for a slot's
  // fallback content.

  // Relevant DOM Standard:
  // https://dom.spec.whatwg.org/#concept-node-insert
  // https://dom.spec.whatwg.org/#concept-node-remove

  // This function is usually called while DOM Mutation is still in-progress.
  // For "after inserted" case, we assume that a parent and a child have been
  // already connected. For "before removed" case, we assume that a parent and a
  // child have not been disconnected yet.

  if (!IsSlotable())
    return;

  if (ShadowRoot* root = ShadowRootOfParent()) {
    // A shadow host's child can be assigned to a slot in the host's shadow
    // tree.

    // Although DOM Standard requires "assign a slot for node / run assign
    // slotables" at this timing, we skip it as an optimization.
    if (HTMLSlotElement* slot = root->AssignedSlotFor(*this))
      slot->DidSlotChange(slot_change_type);
  } else if (IsInShadowTree()) {
    // Checking for fallback content if the node is in a shadow tree.
    if (auto* parent_slot = DynamicTo<HTMLSlotElement>(parentElement())) {
      // The parent_slot's assigned nodes might not be calculated because they
      // are lazy evaluated later in RecalcAssignment(), so we have to check
      // here. Also, parent_slot may have already been removed, if this was the
      // removal of nested slots, e.g.
      //   <slot name=parent-slot><slot name=this-slot>fallback</slot></slot>.
      // In that case, parent-slot has already been removed, so parent_slot->
      // SupportsAssignment() is false, but this-slot is still in the process
      // of being removed, so IsInShadowTree() is still true.
      if (parent_slot->SupportsAssignment() &&
          !parent_slot->HasAssignedNodesSlow())
        parent_slot->DidSlotChange(slot_change_type);
    }
  }
}

bool Node::IsEffectiveRootScroller() const {
  return GetLayoutObject() ? GetLayoutObject()->IsEffectiveRootScroller()
                           : false;
}

LayoutBox* Node::AutoscrollBox() {
  return nullptr;
}

void Node::StopAutoscroll() {}

WebPluginContainerImpl* Node::GetWebPluginContainer() const {
  if (!IsA<HTMLObjectElement>(this) && !IsA<HTMLEmbedElement>(this)) {
    return nullptr;
  }

  if (auto* embedded = DynamicTo<LayoutEmbeddedContent>(GetLayoutObject()))
    return embedded->Plugin();
  return nullptr;
}

bool Node::HasMediaControlAncestor() const {
  const Node* current = this;

  while (current) {
    if (current->IsMediaControls() || current->IsMediaControlElement())
      return true;

    if (current->IsShadowRoot())
      current = current->OwnerShadowHost();
    else
      current = current->ParentOrShadowHostElement();
  }

  return false;
}

void Node::ParentSlotChanged() {
  if (!isConnected()) {
    return;
  }
  DCHECK(IsSlotable());
  DCHECK(IsShadowHost(parentNode()) || IsA<HTMLSlotElement>(parentNode()));
  FlatTreeParentChanged();
}

void Node::FlatTreeParentChanged() {
  DCHECK(isConnected());
  const ComputedStyle* style =
      IsElementNode() ? To<Element>(this)->GetComputedStyle() : nullptr;
  bool detach = false;
  if (ShouldSkipMarkingStyleDirty()) {
    // If we should not mark the node dirty in the new flat tree position,
    // detach to make sure all computes styles, layout objects, and dirty
    // flags are cleared.
    detach = IsDirtyForStyleRecalc() || ChildNeedsStyleRecalc() || style ||
             GetLayoutObject();
  }
  if (!detach) {
    // We are moving a node with ensured computed style into the flat tree.
    // Clear ensured styles so that we can use IsEn
```