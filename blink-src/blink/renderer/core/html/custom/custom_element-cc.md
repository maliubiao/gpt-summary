Response:
Let's break down the request and the provided code. The goal is to understand the functionality of `custom_element.cc` in the Chromium Blink rendering engine. Here's a thought process to generate the comprehensive answer:

1. **Identify the Core Purpose:** The filename and the initial comment clearly indicate this file deals with "custom elements." This is the central theme.

2. **Analyze Includes:** The `#include` directives reveal dependencies and give clues about related functionalities:
    * `dom/document.h`, `dom/qualified_name.h`, `dom/shadow_root.h`: DOM manipulation and structure.
    * `frame/local_dom_window.h`: Browser window context.
    * `html/custom/*.h`:  Other files specifically related to custom elements (definitions, reactions, registry). This suggests this file is a central point for custom element logic.
    * `html/html_element.h`, `html/html_unknown_element.h`, `html_element_factory.h`, `html_element_type_helpers.h`:  Standard HTML element handling.
    * Platform headers (`heap`, `wtf`):  Memory management and utility functions.

3. **Examine the Namespace:**  The code is within the `blink` namespace, confirming it's part of the Blink rendering engine.

4. **Deconstruct the Functions:** Go through each function and understand its role. Group related functions together for clarity.

    * **Registry Access:** `Registry(const Element&)` and `Registry(const TreeScope&)`:  Focus on retrieving the `CustomElementRegistry`. Note the handling of scoped registries in Shadow DOM and the fallback to the document's registry.

    * **Definition Retrieval:** `DefinitionForElementWithoutCheck`, `DefinitionForElement`, `DefinitionFor`:  These are about finding the `CustomElementDefinition` associated with an element or tag name. The naming suggests different levels of checking.

    * **Embedder Custom Elements:** `EmbedderCustomElementNames`, `AddEmbedderCustomElementName`, `AddEmbedderCustomElementNameForTesting`: These seem to handle custom elements defined by the embedder (the application using the rendering engine). The testing version suggests stricter validation.

    * **Naming Conventions:** `IsHyphenatedSpecElementName`, `ShouldCreateCustomElement`:  These functions enforce naming rules for custom elements, linking to HTML specifications.

    * **Element Creation:**  `CreateCustomElement`, `CreateUncustomizedOrUndefinedElementTemplate`, `CreateUncustomizedOrUndefinedElement`, `CreateFailedElement`: This is a core area. Notice the different scenarios: creating fully custom elements, creating "undefined" elements before upgrade, and handling errors by creating `HTMLUnknownElement`. The template function suggests code reuse.

    * **Reaction Queuing:** `Enqueue`, `EnqueueConnectedCallback`, `EnqueueConnectedMoveCallback`, `EnqueueDisconnectedCallback`, `EnqueueAdoptedCallback`, `EnqueueAttributeChangedCallback`, `EnqueueFormAssociatedCallback`, `EnqueueFormResetCallback`, `EnqueueFormDisabledCallback`, `EnqueueFormStateRestoreCallback`: This section is about scheduling lifecycle callbacks for custom elements. The `CEReactionsScope` hints at a mechanism for managing these reactions. The different `Enqueue...Callback` functions map to specific lifecycle events.

    * **Upgrade Mechanism:** `TryToUpgrade`:  This function handles the process of turning an "undefined" element into a fully functional custom element once its definition is registered.

5. **Identify Relationships with Web Technologies:**  Connect the function groups to JavaScript, HTML, and CSS concepts:

    * **JavaScript:** Custom element definitions are done in JavaScript using `customElements.define()`. The lifecycle callbacks (`connectedCallback`, `disconnectedCallback`, etc.) are JavaScript methods.
    * **HTML:**  Custom elements are used in HTML like any other tag. The `<is="...">` syntax is for customized built-in elements. The `<template>` element is relevant for defining the structure of custom elements.
    * **CSS:**  Custom elements can be styled with CSS just like regular elements. The Shadow DOM, which is mentioned in the code, is often used to encapsulate the styling of custom elements.

6. **Illustrate with Examples:** Create concrete examples for each relationship:

    * **JavaScript:** Show the `customElements.define()` syntax and basic lifecycle callbacks.
    * **HTML:** Demonstrate the usage of custom tags and the `<is="...">` attribute.
    * **CSS:** Show how to style custom elements.

7. **Consider Logic and Assumptions:** For functions with conditional logic, think about the "if/else" branches and the input/output scenarios:

    * **Registry lookup:** What happens if a registry exists? What if it doesn't?
    * **Element creation:** How does the `is` attribute affect the creation process?
    * **Reaction queuing:**  What's the difference between the current queue and the backup queue?

8. **Identify Common Errors:** Think about mistakes developers might make when working with custom elements:

    * Incorrect naming.
    * Forgetting to register the element.
    * Not defining lifecycle callbacks properly.
    * Confusing autonomous and customized built-in elements.

9. **Trace User Interaction:**  Think about how a user's actions in a browser could lead to the execution of code in this file:

    * Loading a page with custom elements.
    * Dynamically creating custom elements with JavaScript.
    * Moving elements in the DOM.
    * Modifying attributes.
    * Submitting forms containing custom form-associated elements.

10. **Structure the Answer:** Organize the information logically:

    * Start with a high-level overview.
    * Detail the functionalities by grouping related functions.
    * Explain the connections to web technologies with examples.
    * Provide examples of logic and assumptions.
    * List common user errors.
    * Describe the user interaction flow.

11. **Review and Refine:** Read through the generated answer to ensure clarity, accuracy, and completeness. Check for any inconsistencies or areas that could be explained better. For example, explicitly mentioning the role of the `CustomElementDefinition` in holding the JavaScript class.

By following this thought process, we can systematically analyze the code and generate a comprehensive and informative answer that addresses all aspects of the request. The iterative nature of this process is important – you might jump back and forth between analyzing functions and thinking about examples, refining your understanding as you go.
This C++ source file `custom_element.cc` within the Chromium Blink engine is a core component responsible for managing **Custom Elements**, a Web Components standard that allows developers to define their own HTML elements with custom behavior.

Here's a breakdown of its functionalities:

**Core Responsibilities:**

1. **Custom Element Registration and Lookup:**
   - It provides mechanisms to access the `CustomElementRegistry` associated with a given element or tree scope (document or shadow root). The registry stores the definitions of custom elements (tag names and their corresponding JavaScript classes).
   - Functions like `Registry(const Element&)` and `Registry(const TreeScope&)` facilitate this lookup.
   - Functions like `DefinitionForElement`, `DefinitionForElementWithoutCheck`, and the static `DefinitionFor` help retrieve the `CustomElementDefinition` for a given element or descriptor (tag name and optional `is` attribute).

2. **Custom Element Creation:**
   - It handles the creation of custom elements when encountered in HTML parsing or JavaScript DOM manipulation.
   - `CreateCustomElement` is the main function for creating autonomous custom elements. It checks the registry for a definition and, if found, instantiates the custom element using its registered class.
   - `CreateUncustomizedOrUndefinedElementTemplate` and `CreateUncustomizedOrUndefinedElement` handle the creation of elements that *might* become custom elements. These elements are initially in an "undefined" state until their definition is registered.
   - `CreateFailedElement` is used when the custom element definition is not found or an error occurs during creation. It creates an `HTMLUnknownElement` with a "failed" custom element state.

3. **Lifecycle Callback Management:**
   - It manages the queuing and execution of custom element lifecycle callbacks defined in JavaScript (e.g., `connectedCallback`, `disconnectedCallback`, `attributeChangedCallback`, `adoptedCallback`).
   - Functions like `EnqueueConnectedCallback`, `EnqueueDisconnectedCallback`, `EnqueueAttributeChangedCallback`, `EnqueueAdoptedCallback`, and the generic `Enqueue` are responsible for adding these callbacks to appropriate queues for later execution.
   - The `CEReactionsScope` and `CustomElementReactionStack` (mentioned in includes) are used for managing the order and context of these callbacks.

4. **Customized Built-in Elements:**
   - It supports "customized built-in elements" where developers can extend the functionality of standard HTML elements using the `<element is="...">` syntax.
   - Functions like `ShouldCreateCustomizedBuiltinElement` check if a given tag name corresponds to a built-in HTML element that can be customized.

5. **Embedder-Defined Custom Elements:**
   - It allows the embedding application (like Chrome itself) to register custom element names that should be treated as custom elements even without explicit registration via `customElements.define()`.
   - `EmbedderCustomElementNames`, `AddEmbedderCustomElementName`, and `AddEmbedderCustomElementNameForTesting` handle this.

6. **Name Validation:**
   - It enforces rules for valid custom element names (must contain a hyphen, cannot be a reserved name, etc.).
   - `IsValidName` (not directly in this file but likely used by the included headers) performs this validation.
   - `IsHyphenatedSpecElementName` checks for specific hyphenated names reserved by HTML specifications.

7. **Upgrade Mechanism:**
   - `TryToUpgrade` handles the process of upgrading an "undefined" element to a fully functional custom element once its definition is registered.

**Relationship with JavaScript, HTML, and CSS:**

* **JavaScript:** This file is the bridge between the C++ rendering engine and the JavaScript API for custom elements (`customElements.define()`, lifecycle callbacks). When JavaScript code registers a custom element using `customElements.define()`, the information is stored in the `CustomElementRegistry`, which is accessed and managed by this C++ code. The lifecycle callbacks defined in JavaScript are invoked by the mechanisms implemented in this file.

    * **Example:** When JavaScript calls `customElements.define('my-element', MyElementClass)`, the Blink engine (through this file) stores the association between the tag name `'my-element'` and the JavaScript class `MyElementClass`. When an `<my-element>` tag is encountered, this file uses that information to create an instance of `MyElementClass`.

* **HTML:** This file is crucial for processing HTML that contains custom elements. When the HTML parser encounters a tag that is a registered custom element name, this file's logic determines how that element is created and initialized. It also handles the `<element is="...">` syntax for customized built-in elements.

    * **Example:** When the browser parses the HTML `<my-element></my-element>`, this file checks if `'my-element'` is registered. If it is, it creates an instance of the corresponding JavaScript class. If the HTML contains `<button is="styled-button">Click Me</button>`, this file handles the creation of a button element and associates it with the custom definition for `'styled-button'`.

* **CSS:** While this file doesn't directly deal with CSS parsing or styling, it plays a role in how CSS selectors interact with custom elements. Custom elements can be styled using CSS just like regular HTML elements. The Shadow DOM, which is often used with custom elements for encapsulation, is also related (as seen in the `ShadowRoot` include).

    * **Example:** CSS rules like `my-element { color: blue; }` will be applied to instances of the `<my-element>` tag. If the custom element uses Shadow DOM, CSS rules defined within the shadow root will be scoped to that element.

**Logic and Assumptions (Hypothetical):**

Let's consider the `CreateCustomElement` function.

**Hypothetical Input:**

* `tree_scope`:  The document's tree scope.
* `tag_name`: A `QualifiedName` representing `<my-element>`.
* `flags`: Default creation flags.

**Assumptions:**

* A custom element named `'my-element'` has been previously registered via JavaScript.
* The `CustomElementRegistry` for the document exists and contains the definition for `'my-element'`.

**Logical Steps within `CreateCustomElement`:**

1. Check if `ShouldCreateCustomElement(tag_name)` returns true (verifies the tag name is a valid custom element name).
2. Call `DefinitionFor` to look up the `CustomElementDefinition` for `'my-element'` in the document's registry.
3. The `DefinitionFor` function finds the registered definition.
4. `CreateCustomElement` then calls the `CreateElement` method of the found `CustomElementDefinition`.
5. The `CustomElementDefinition::CreateElement` (not in this file) likely creates the appropriate `HTMLElement` subclass associated with the custom element (potentially triggering the JavaScript constructor).

**Hypothetical Output:**

* A newly created instance of the custom element's corresponding `HTMLElement` subclass (e.g., `HTMLUnknownElement` if the definition wasn't found, or a specific subclass if it was).

**User or Programming Common Usage Errors:**

1. **Incorrect Custom Element Name:** Developers might use invalid names that don't contain a hyphen (e.g., `<myelement>`). This file's validation logic (or related functions) will prevent this from being treated as a custom element.
   * **Example:**  If the HTML is `<myelement></myelement>` and no custom element with that name is registered (and it's not a built-in element), it will likely be treated as an `HTMLUnknownElement`.

2. **Forgetting to Register the Custom Element:** Developers might use a custom element tag in HTML without defining it in JavaScript using `customElements.define()`.
   * **Example:**  If the HTML contains `<my-element></my-element>` but `customElements.define('my-element', ...)` is not called, the element will remain in an "undefined" state until registration occurs (or might be treated as an `HTMLUnknownElement` depending on the timing).

3. **Defining Lifecycle Callbacks Incorrectly:**  Developers might misspell or define lifecycle callbacks with incorrect signatures. This file relies on the correct definition of these callbacks within the JavaScript class.
   * **Example:** If the JavaScript class has `connectedCallback()` misspelled as `connectCallback()`, the `EnqueueConnectedCallback` function won't be able to invoke the intended method.

4. **Trying to Customize Non-Customizable Built-in Elements:**  Developers might attempt to use the `<element is="...">` syntax with built-in elements that are not allowed to be customized.
   * **Example:** `<div is="my-custom-div">` might not work if `div` is not a customizable built-in element, and the `ShouldCreateCustomizedBuiltinElement` function would return `false`.

**User Operation Steps to Reach This Code:**

1. **User types a URL or clicks a link:** This initiates the process of fetching and loading a web page.
2. **The browser receives the HTML content:** The HTML parser in the Blink engine starts processing the HTML.
3. **The HTML parser encounters a tag:**
   * **Case 1: Autonomous Custom Element:** If the tag name looks like a custom element (contains a hyphen) and a definition exists in the `CustomElementRegistry`, the `CreateCustomElement` function in this file is called to create an instance of the custom element.
   * **Case 2: Customized Built-in Element:** If the tag has the `<element is="...">` syntax, the code checks if the base element is customizable and if a definition exists for the specified custom type.
   * **Case 3: "Undefined" Element:** If the tag looks like a custom element but no definition is immediately available, the element is created in an "undefined" state using `CreateUncustomizedOrUndefinedElement`. The `TryToUpgrade` function might be called later when the definition becomes available.
4. **JavaScript interacts with the DOM:** JavaScript code running on the page might:
   * **Call `customElements.define()`:** This updates the `CustomElementRegistry` managed by this file.
   * **Create new elements using `document.createElement()`:**  If the tag name passed to `createElement()` is a registered custom element, `CreateCustomElement` is invoked.
   * **Move elements in the DOM:** This can trigger `connectedCallback` and `disconnectedCallback` lifecycle methods, which are managed by the enqueueing mechanisms in this file.
   * **Modify attributes of custom elements:** This can trigger the `attributeChangedCallback`, which is also managed here.

In essence, this `custom_element.cc` file is a central hub for all things related to custom elements within the Blink rendering engine. It orchestrates their creation, manages their lifecycle, and acts as the intermediary between the HTML markup, the JavaScript definitions, and the underlying C++ rendering infrastructure.

Prompt: 
```
这是目录为blink/renderer/core/html/custom/custom_element.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
如果能说明用户操作是如何一步步的到达这里，就更棒了。

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/html/custom/custom_element.h"

#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/qualified_name.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/html/custom/ce_reactions_scope.h"
#include "third_party/blink/renderer/core/html/custom/custom_element_definition.h"
#include "third_party/blink/renderer/core/html/custom/custom_element_reaction_factory.h"
#include "third_party/blink/renderer/core/html/custom/custom_element_reaction_stack.h"
#include "third_party/blink/renderer/core/html/custom/custom_element_registry.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/html/html_unknown_element.h"
#include "third_party/blink/renderer/core/html_element_factory.h"
#include "third_party/blink/renderer/core/html_element_type_helpers.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/wtf/text/atomic_string_hash.h"

namespace blink {

CustomElementRegistry* CustomElement::Registry(const Element& element) {
  return Registry(element.GetTreeScope());
}

CustomElementRegistry* CustomElement::Registry(const TreeScope& tree_scope) {
  if (RuntimeEnabledFeatures::ScopedCustomElementRegistryEnabled()) {
    if (const ShadowRoot* shadow = DynamicTo<ShadowRoot>(tree_scope)) {
      if (CustomElementRegistry* registry = shadow->registry()) {
        return registry;
      }
    }
  }
  if (LocalDOMWindow* window = tree_scope.GetDocument().domWindow()) {
    return window->customElements();
  }
  return nullptr;
}

static CustomElementDefinition* DefinitionForElementWithoutCheck(
    const Element& element) {
  DCHECK_EQ(element.GetCustomElementState(), CustomElementState::kCustom);
  return element.GetCustomElementDefinition();
}

CustomElementDefinition* CustomElement::DefinitionForElement(
    const Element* element) {
  if (!element ||
      element->GetCustomElementState() != CustomElementState::kCustom)
    return nullptr;
  return DefinitionForElementWithoutCheck(*element);
}

Vector<AtomicString>& CustomElement::EmbedderCustomElementNames() {
  DEFINE_STATIC_LOCAL(Vector<AtomicString>, names, ());
  return names;
}

void CustomElement::AddEmbedderCustomElementName(const AtomicString& name) {
  DCHECK_EQ(name, name.LowerASCII());
  DCHECK(Document::IsValidName(name)) << name;
  DCHECK(!IsKnownBuiltinTagName(name)) << name;
  DCHECK(!IsValidName(name, false)) << name;

  if (EmbedderCustomElementNames().Contains(name))
    return;
  EmbedderCustomElementNames().push_back(name);
}

void CustomElement::AddEmbedderCustomElementNameForTesting(
    const AtomicString& name,
    ExceptionState& exception_state) {
  if (name != name.LowerASCII() || !Document::IsValidName(name) ||
      IsKnownBuiltinTagName(name) || IsValidName(name, false)) {
    exception_state.ThrowDOMException(DOMExceptionCode::kSyntaxError,
                                      "Name cannot be used");
    return;
  }

  AddEmbedderCustomElementName(name);
}

bool CustomElement::IsHyphenatedSpecElementName(const AtomicString& name) {
  // Even if Blink does not implement one of the related specs, we must prohibit
  // using the name because that is required by the HTML spec which we *do*
  // implement. Don't remove names from this list without removing them from the
  // HTML spec first.
  DEFINE_STATIC_LOCAL(HashSet<AtomicString>, hyphenated_spec_element_names,
                      ({
                          AtomicString("annotation-xml"),
                          AtomicString("color-profile"),
                          AtomicString("font-face"),
                          AtomicString("font-face-src"),
                          AtomicString("font-face-uri"),
                          AtomicString("font-face-format"),
                          AtomicString("font-face-name"),
                          AtomicString("missing-glyph"),
                      }));
  return hyphenated_spec_element_names.Contains(name);
}

bool CustomElement::ShouldCreateCustomElement(const AtomicString& name) {
  return IsValidName(name);
}

bool CustomElement::ShouldCreateCustomElement(const QualifiedName& tag_name) {
  return ShouldCreateCustomElement(tag_name.LocalName()) &&
         tag_name.NamespaceURI() == html_names::xhtmlNamespaceURI;
}

bool CustomElement::ShouldCreateCustomizedBuiltinElement(
    const AtomicString& local_name,
    const Document& document) {
  return HtmlElementTypeForTag(local_name, &document) !=
         HTMLElementType::kHTMLUnknownElement;
}

bool CustomElement::ShouldCreateCustomizedBuiltinElement(
    const QualifiedName& tag_name,
    const Document& document) {
  return ShouldCreateCustomizedBuiltinElement(tag_name.LocalName(), document) &&
         tag_name.NamespaceURI() == html_names::xhtmlNamespaceURI;
}

static CustomElementDefinition* DefinitionFor(
    const TreeScope& tree_scope,
    const CustomElementDescriptor desc) {
  if (CustomElementRegistry* registry = CustomElement::Registry(tree_scope)) {
    return registry->DefinitionFor(desc);
  }
  return nullptr;
}

// https://dom.spec.whatwg.org/#concept-create-element
HTMLElement* CustomElement::CreateCustomElement(TreeScope& tree_scope,
                                                const QualifiedName& tag_name,
                                                CreateElementFlags flags) {
  DCHECK(ShouldCreateCustomElement(tag_name)) << tag_name;
  Document& document = tree_scope.GetDocument();
  // 4. Let definition be the result of looking up a custom element
  // definition given document, namespace, localName, and is.
  if (auto* definition = DefinitionFor(
          tree_scope, CustomElementDescriptor(tag_name.LocalName(),
                                              tag_name.LocalName()))) {
    DCHECK(definition->Descriptor().IsAutonomous());
    // 6. Otherwise, if definition is non-null, then:
    return definition->CreateElement(document, tag_name, flags);
  }
  // 7. Otherwise:
  return To<HTMLElement>(
      CreateUncustomizedOrUndefinedElementTemplate<kQNameIsValid>(
          document, tag_name, flags, g_null_atom));
}

// Step 7 of https://dom.spec.whatwg.org/#concept-create-element
template <CustomElement::CreateUUCheckLevel level>
Element* CustomElement::CreateUncustomizedOrUndefinedElementTemplate(
    Document& document,
    const QualifiedName& tag_name,
    const CreateElementFlags flags,
    const AtomicString& is_value) {
  if (level == kQNameIsValid) {
    DCHECK(is_value.IsNull());
    DCHECK(ShouldCreateCustomElement(tag_name)) << tag_name;
  }

  // 7.1. Let interface be the element interface for localName and namespace.
  // 7.2. Set result to a new element that implements interface, with ...
  Element* element = document.CreateRawElement(tag_name, flags);
  if (level == kCheckAll && !is_value.IsNull())
    element->SetIsValue(is_value);

  // 7.3. If namespace is the HTML namespace, and either localName is a
  // valid custom element name or is is non-null, then set result’s
  // custom element state to "undefined".
  if (level == kQNameIsValid)
    element->SetCustomElementState(CustomElementState::kUndefined);
  else if (tag_name.NamespaceURI() == html_names::xhtmlNamespaceURI &&
           (CustomElement::IsValidName(tag_name.LocalName()) ||
            !is_value.IsNull()))
    element->SetCustomElementState(CustomElementState::kUndefined);

  return element;
}

Element* CustomElement::CreateUncustomizedOrUndefinedElement(
    Document& document,
    const QualifiedName& tag_name,
    const CreateElementFlags flags,
    const AtomicString& is_value) {
  return CreateUncustomizedOrUndefinedElementTemplate<kCheckAll>(
      document, tag_name, flags, is_value);
}

HTMLElement* CustomElement::CreateFailedElement(Document& document,
                                                const QualifiedName& tag_name) {
  CHECK(ShouldCreateCustomElement(tag_name))
      << "HTMLUnknownElement with built-in tag name: " << tag_name;

  // "create an element for a token":
  // https://html.spec.whatwg.org/C/#create-an-element-for-the-token

  // 7. If this step throws an exception, let element be instead a new element
  // that implements HTMLUnknownElement, with no attributes, namespace set to
  // given namespace, namespace prefix set to null, custom element state set
  // to "failed", and node document set to document.

  auto* element = MakeGarbageCollected<HTMLUnknownElement>(tag_name, document);
  element->SetCustomElementState(CustomElementState::kFailed);
  return element;
}

void CustomElement::Enqueue(Element& element, CustomElementReaction& reaction) {
  // To enqueue an element on the appropriate element queue
  // https://html.spec.whatwg.org/C/#enqueue-an-element-on-the-appropriate-element-queue

  CustomElementReactionStack& stack =
      CustomElementReactionStack::From(element.GetDocument().GetAgent());
  // If the custom element reactions stack is not empty, then
  // Add element to the current element queue.
  if (CEReactionsScope* current = CEReactionsScope::Current()) {
    current->EnqueueToCurrentQueue(stack, element, reaction);
    return;
  }

  // If the custom element reactions stack is empty, then
  // Add element to the backup element queue.
  stack.EnqueueToBackupQueue(element, reaction);
}

void CustomElement::EnqueueConnectedCallback(Element& element) {
  auto* definition = DefinitionForElementWithoutCheck(element);
  if (definition->HasConnectedCallback())
    definition->EnqueueConnectedCallback(element);
}

void CustomElement::EnqueueConnectedMoveCallback(Element& element) {
  auto* definition = DefinitionForElementWithoutCheck(element);
  if (definition->HasConnectedMoveCallback()) {
    definition->EnqueueConnectedMoveCallback(element);
  } else {
    definition->EnqueueDisconnectedCallback(element);
    definition->EnqueueConnectedCallback(element);
  }
}

void CustomElement::EnqueueDisconnectedCallback(Element& element) {
  auto* definition = DefinitionForElementWithoutCheck(element);
  if (definition->HasDisconnectedCallback())
    definition->EnqueueDisconnectedCallback(element);
}

void CustomElement::EnqueueAdoptedCallback(Element& element,
                                           Document& old_owner,
                                           Document& new_owner) {
  auto* definition = DefinitionForElementWithoutCheck(element);
  if (definition->HasAdoptedCallback())
    definition->EnqueueAdoptedCallback(element, old_owner, new_owner);
}

void CustomElement::EnqueueAttributeChangedCallback(
    Element& element,
    const QualifiedName& name,
    const AtomicString& old_value,
    const AtomicString& new_value) {
  auto* definition = DefinitionForElementWithoutCheck(element);
  if (definition->HasAttributeChangedCallback(name))
    definition->EnqueueAttributeChangedCallback(element, name, old_value,
                                                new_value);
}

void CustomElement::EnqueueFormAssociatedCallback(
    Element& element,
    HTMLFormElement* nullable_form) {
  auto& definition = *DefinitionForElementWithoutCheck(element);
  if (definition.HasFormAssociatedCallback()) {
    Enqueue(element, CustomElementReactionFactory::CreateFormAssociated(
                         definition, nullable_form));
  }
}

void CustomElement::EnqueueFormResetCallback(Element& element) {
  auto& definition = *DefinitionForElementWithoutCheck(element);
  if (definition.HasFormResetCallback()) {
    Enqueue(element, CustomElementReactionFactory::CreateFormReset(definition));
  }
}

void CustomElement::EnqueueFormDisabledCallback(Element& element,
                                                bool is_disabled) {
  auto& definition = *DefinitionForElementWithoutCheck(element);
  if (definition.HasFormDisabledCallback()) {
    Enqueue(element, CustomElementReactionFactory::CreateFormDisabled(
                         definition, is_disabled));
  }
}

void CustomElement::EnqueueFormStateRestoreCallback(Element& element,
                                                    const V8ControlValue* value,
                                                    const String& mode) {
  auto& definition = *DefinitionForElementWithoutCheck(element);
  if (definition.HasFormStateRestoreCallback()) {
    Enqueue(element, CustomElementReactionFactory::CreateFormStateRestore(
                         definition, value, mode));
  }
}

void CustomElement::TryToUpgrade(Element& element) {
  // Try to upgrade an element
  // https://html.spec.whatwg.org/C/#concept-try-upgrade

  DCHECK_EQ(element.GetCustomElementState(), CustomElementState::kUndefined);

  CustomElementRegistry* registry = CustomElement::Registry(element);
  if (!registry)
    return;
  const AtomicString& is_value = element.IsValue();
  if (CustomElementDefinition* definition =
          registry->DefinitionFor(CustomElementDescriptor(
              is_value.IsNull() ? element.localName() : is_value,
              element.localName())))
    definition->EnqueueUpgradeReaction(element);
  else
    registry->AddCandidate(element);
}

}  // namespace blink

"""

```