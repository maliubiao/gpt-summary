Response:
Let's break down the thought process for analyzing this C++ code and generating the explanation.

1. **Understand the Goal:** The request asks for a functional explanation of the `CustomElementDefinition.cc` file in the Blink rendering engine. It also asks for connections to web technologies (JavaScript, HTML, CSS), examples, logical reasoning, common errors, and how a user might trigger this code.

2. **Initial Skim for High-Level Purpose:**  The first step is to quickly read through the code, paying attention to class names, method names, and included headers. Keywords like `CustomElement`, `registry`, `upgrade`, `connectedCallback`, `attributeChangedCallback`, and `HTMLElement` immediately stand out. This suggests the file is crucial for defining how custom HTML elements work within Blink.

3. **Identify Key Classes and Relationships:** Note the main class `CustomElementDefinition` and its dependencies. The includes reveal its interactions with:
    * `CustomElementRegistry`:  Manages the registration of custom elements.
    * `CustomElement`: The base class for custom elements.
    * `HTMLElement`: The standard HTML element base class.
    * `Document`: Represents the HTML document.
    * `Attr`: Represents HTML attributes.
    * `CustomElementReaction` and its factory/stack:  Mechanisms for scheduling and executing lifecycle callbacks.
    * `ElementInternals`:  Handles form-related features for custom elements.
    * `HTMLElementFactory`:  Used for creating HTML elements.

4. **Analyze Constructor and Member Variables:**  Examine the constructors of `CustomElementDefinition`. This tells us how a definition is created and what data it holds:
    * `registry_`: A reference to the `CustomElementRegistry`.
    * `descriptor_`: Holds the custom element's tag name and potentially the `is` attribute for customized built-ins.
    * `observed_attributes_`:  A set of attributes the custom element wants to track for changes.
    * Flags like `disable_shadow_`, `disable_internals_`, `is_form_associated_`: Indicate optional features and behaviors.

5. **Focus on Key Methods and their Functionality:** Go through the important methods, understanding their roles:
    * `CreateElementForConstructor`:  Creates a basic `HTMLElement` instance during the custom element constructor call. Crucially, it sets the initial state and links the element to its definition.
    * `CreateElement`:  The core logic for creating custom elements (both autonomous and customized built-ins). It handles synchronous and asynchronous upgrades. This is where the connection to `document.createElement()` in JavaScript becomes evident.
    * `Upgrade`:  The heart of the custom element lifecycle. It executes the constructor, manages attribute callbacks, and triggers `connectedCallback`.
    * Callback Enqueue Methods (`EnqueueUpgradeReaction`, `EnqueueConnectedCallback`, etc.): These methods are responsible for scheduling the execution of JavaScript lifecycle methods.
    * `CheckConstructorResult`: Enforces constraints on what the custom element constructor can return.

6. **Connect to Web Technologies (JavaScript, HTML, CSS):**  Now, actively look for how these C++ concepts relate to web standards:
    * **JavaScript:** The lifecycle callbacks (`connectedCallback`, `disconnectedCallback`, `attributeChangedCallback`, `adoptedCallback`) directly correspond to JavaScript methods defined in custom element classes. The `constructor` call is also a key interaction point. The `observedAttributes` static getter in JavaScript maps to the `observed_attributes_` member.
    * **HTML:** The custom element tag itself (`<my-element>`) is defined here. The `is` attribute for customized built-ins is handled. The `formAssociated` concept links to HTML forms.
    * **CSS:** While not directly manipulated in this file, the `has_style_attribute_changed_callback_` member and mentions of shadow DOM connection hint at interactions with CSS styling.

7. **Construct Examples and Scenarios:**  Think about concrete examples of how developers use custom elements and how these C++ functions would be involved:
    * **Autonomous Custom Element:**  `<my-element>`
    * **Customized Built-in Element:** `<button is="my-button">`
    * **Observing Attributes:**  Changing attributes like `data-count` or `style`.
    * **Lifecycle Hooks:**  Elements being added to or removed from the DOM.

8. **Consider Logical Reasoning and Assumptions:**  Think about potential input and output:
    * **Input:** A call to `document.createElement('my-element')` or parsing HTML containing `<my-element>`.
    * **Output:**  The creation and upgrading of a `CustomElement` instance in Blink's internal representation.

9. **Identify Common Errors:** Consider what mistakes developers might make:
    * Returning incorrect types from the constructor.
    * Modifying the element in the constructor in ways that violate the specification (adding attributes or children).
    * Forgetting to register the custom element before using it.

10. **Trace User Actions:**  Imagine the steps a user takes that lead to this code being executed:
    * Typing HTML with a custom element tag.
    * JavaScript calling `document.createElement()`.
    * JavaScript manipulating attributes of a custom element.
    * Moving a custom element between different parts of the DOM.
    * Interacting with a form containing a form-associated custom element.

11. **Structure the Explanation:** Organize the findings logically, starting with the main purpose, then detailing functionalities, connections to web technologies, examples, etc. Use clear and concise language. Use formatting (like bullet points) to improve readability.

12. **Refine and Review:**  Read through the explanation to ensure accuracy, clarity, and completeness. Check if all parts of the original request have been addressed. For example, double-check if both autonomous and customized built-in elements are explained.

This iterative process of reading, analyzing, connecting concepts, and generating examples leads to a comprehensive understanding and explanation of the code. The key is to not just describe *what* the code does, but *why* it does it and how it fits into the broader web ecosystem.
这个文件 `custom_element_definition.cc` 是 Chromium Blink 引擎中负责 **定义和管理自定义元素** 的核心组件。它包含了 `CustomElementDefinition` 类的实现，该类存储了关于一个自定义元素的所有关键信息，并负责其生命周期的管理。

以下是它的主要功能及其与 JavaScript, HTML, CSS 的关系：

**核心功能：**

1. **存储自定义元素定义信息：**
   - 关联的 `CustomElementRegistry`：指向注册该自定义元素的注册表。
   - `CustomElementDescriptor`：包含自定义元素的标签名 (`localName`) 和可选的 `is` 属性值（用于定制内置元素）。
   - `observedAttributes_`：一个集合，存储了该自定义元素声明需要监听变化的属性名称。这对应 JavaScript 中自定义元素类的 `static get observedAttributes()` 方法返回的数组。
   - `has_style_attribute_changed_callback_`：一个布尔值，指示是否监听 `style` 属性的变化。
   - `disable_shadow_` 和 `disable_internals_`：标志，指示是否禁用 shadow DOM 和 ElementInternals 功能。
   - `is_form_associated_`：标志，指示该自定义元素是否与 HTML 表单关联。

2. **管理自定义元素的创建过程：**
   - `CreateElementForConstructor(Document& document)`：在自定义元素的构造函数执行时，创建一个临时的、未完全初始化的 `HTMLElement` 实例。这个方法确保构造函数返回的是一个有效的 HTML 元素，并进行一些基本的状态设置。
   - `CreateElement(Document& document, const QualifiedName& tag_name, CreateElementFlags flags)`： 这是创建自定义元素的核心方法。它根据是否是自主自定义元素或定制内置元素，以及是否是异步创建，来执行不同的创建逻辑。
      - 对于**自主自定义元素**（例如 `<my-element>`），它会创建一个新的 `HTMLElement` 实例，并将其状态设置为 "undefined"，然后加入升级队列等待升级。
      - 对于**定制内置元素**（例如 `<button is="my-button">`），它会创建一个指定内置元素的实例（例如 `<button>`），并设置其 `is` 属性，然后同样进行升级。
      - 它会处理同步和异步自定义元素的创建流程。

3. **执行自定义元素的升级过程 (`Upgrade(Element& element)`)：**
   - 当一个自定义元素被创建或从文档中解析出来时，需要进行“升级”。这个方法负责执行以下步骤：
     - 检查元素的状态，确保只对 "undefined" 或 "uncustomized" 的元素进行升级。
     - 将元素的状态设置为 "failed"（暂时），以便在构造函数执行失败时可以识别。
     - 触发 `attributeChangedCallback` 回调（如果定义了 `observedAttributes`）。
     - 如果元素已连接到文档，则触发 `connectedCallback` 回调。
     - **执行自定义元素的构造函数**（这是与 JavaScript 代码交互的关键点）。
     - 如果构造函数执行成功，则将元素的状态更新，并设置其 `CustomElementDefinition`。
     - 对于表单关联的自定义元素，还会调用 `ElementInternals::DidUpgrade()` 进行进一步的初始化。

4. **管理自定义元素的生命周期回调：**
   - 提供了一系列 `Enqueue...Callback` 方法，用于将自定义元素的生命周期回调（`connectedCallback`, `disconnectedCallback`, `attributeChangedCallback`, `adoptedCallback`) 加入到执行队列中。
   - `EnqueueAttributeChangedCallbackForAllAttributes(Element& element)`：用于在元素升级时，对所有观察的属性触发 `attributeChangedCallback`。

5. **检查构造函数的返回值 (`CheckConstructorResult`)：**
   - 在自定义元素的构造函数执行后，会调用此方法来验证构造函数返回的对象是否符合规范（例如，必须是 `HTMLElement` 实例，不能有属性或子节点，必须与文档关联等）。

**与 JavaScript, HTML, CSS 的关系：**

* **JavaScript:**
    - **定义自定义元素类：** 这个 C++ 文件中定义的 `CustomElementDefinition` 对象与 JavaScript 中使用 `class MyElement extends HTMLElement { ... }` 定义的自定义元素类相对应。
    - **生命周期回调：** `connectedCallback`, `disconnectedCallback`, `attributeChangedCallback`, `adoptedCallback` 这些 JavaScript 方法的调用是由这里的 `Enqueue...Callback` 方法触发的。
        - **例子：** 当一个自定义元素 `<my-element>` 被添加到 DOM 中时，Blink 引擎会调用 `EnqueueConnectedCallback`，最终在 JavaScript 中执行 `MyElement.prototype.connectedCallback`。
    - **`observedAttributes`：** JavaScript 中自定义元素类的 `static get observedAttributes()` 方法返回的属性列表，会被存储到 `CustomElementDefinition` 的 `observed_attributes_` 成员中。
        - **例子：** 如果 JavaScript 中定义了 `static get observedAttributes() { return ['name', 'count']; }`，那么当 `<my-element name="foo">` 的 `name` 属性发生变化时，Blink 引擎会调用 `EnqueueAttributeChangedCallback`，并在 JavaScript 中执行 `MyElement.prototype.attributeChangedCallback('name', 'oldValue', 'newValue')`。
    - **构造函数：** `CustomElementDefinition::Upgrade` 方法中会调用自定义元素的 JavaScript 构造函数。
        - **假设输入：** JavaScript 中定义了 `class MyElement extends HTMLElement { constructor() { super(); this.textContent = 'Hello'; } }`。
        - **输出：** 当 `<my-element>` 被创建并升级时，`MyElement` 的构造函数会被执行，`this.textContent = 'Hello'` 会将元素的文本内容设置为 "Hello"。

* **HTML:**
    - **自定义元素标签：**  `CustomElementDefinition` 存储了自定义元素的标签名，例如 `<my-element>`。当 HTML 解析器遇到这个标签时，会查找对应的 `CustomElementDefinition`。
        - **用户操作：** 用户在 HTML 文件中输入 `<my-element>`。
        - **到达这里：** HTML 解析器解析到 `<my-element>` 标签，会尝试在 `CustomElementRegistry` 中查找名为 `my-element` 的定义。如果找到，就会使用对应的 `CustomElementDefinition` 来创建元素。
    - **`is` 属性：** 对于定制内置元素，HTML 中的 `is` 属性与 `CustomElementDefinition` 中的 `CustomElementDescriptor` 相关联。
        - **用户操作：** 用户在 HTML 文件中输入 `<button is="my-button">Click Me</button>`。
        - **到达这里：** HTML 解析器解析到 `<button is="my-button">`，会查找名为 `my-button` 且 `descriptor_.IsAutonomous()` 为 false 的 `CustomElementDefinition`。

* **CSS:**
    - **样式应用：** 虽然这个文件本身不直接处理 CSS，但自定义元素可以像其他 HTML 元素一样被 CSS 样式化。
    - **`style` 属性监听：** `has_style_attribute_changed_callback_` 成员允许自定义元素监听 `style` 属性的变化，并在 JavaScript 中执行 `attributeChangedCallback`。这使得自定义元素可以根据 CSS 样式的变化做出响应。
        - **用户操作：** 用户通过 JavaScript 修改自定义元素的 `style` 属性，例如 `element.style.color = 'red'`; 或者通过 CSS 规则修改了元素的样式。
        - **到达这里：** 如果 `has_style_attribute_changed_callback_` 为 true，当 `style` 属性发生变化时，会调用 `EnqueueAttributeChangedCallback`，最终触发 JavaScript 中的 `attributeChangedCallback`。

**逻辑推理的假设输入与输出：**

假设输入：

1. **JavaScript 注册自定义元素：**
   ```javascript
   class MyElement extends HTMLElement {
     constructor() {
       super();
       this.innerHTML = '<span>Initial Content</span>';
     }
     connectedCallback() {
       console.log('MyElement connected');
     }
     static get observedAttributes() {
       return ['data-name'];
     }
     attributeChangedCallback(name, oldValue, newValue) {
       console.log(`Attribute ${name} changed from ${oldValue} to ${newValue}`);
     }
   }
   customElements.define('my-element', MyElement);
   ```
2. **HTML 中使用自定义元素：** `<my-element data-name="initial"></my-element>`
3. **JavaScript 修改属性：** `document.querySelector('my-element').setAttribute('data-name', 'updated');`

输出：

1. 当 HTML 解析器遇到 `<my-element>` 时，`CustomElementDefinition::CreateElement` 会被调用，创建一个 `HTMLElement` 实例，状态为 "undefined"。
2. 当元素被添加到 DOM 时，`CustomElementDefinition::Upgrade` 会被调用。
3. `MyElement` 的构造函数会被执行，元素的 `innerHTML` 会被设置为 `<span>Initial Content</span>`。
4. `connectedCallback` 会被加入队列并执行，控制台输出 "MyElement connected"。
5. 当 JavaScript 调用 `setAttribute` 修改 `data-name` 属性时，由于 `observedAttributes` 中包含了 `data-name`，`CustomElementDefinition::EnqueueAttributeChangedCallback` 会被调用。
6. `attributeChangedCallback` 会被加入队列并执行，控制台输出 "Attribute data-name changed from initial to updated"。

**用户或编程常见的使用错误：**

1. **构造函数返回非 HTMLElement 对象：**
   - **错误示例：**
     ```javascript
     class MyElement extends HTMLElement {
       constructor() {
         return {}; // 错误！
       }
     }
     ```
   - **结果：** `CustomElementDefinition::CheckConstructorResult` 会抛出 `TypeError: The result must implement HTMLElement interface` 错误。

2. **在构造函数中添加属性或子节点：**
   - **错误示例：**
     ```javascript
     class MyElement extends HTMLElement {
       constructor() {
         super();
         this.setAttribute('foo', 'bar'); // 错误！
         this.appendChild(document.createElement('div')); // 错误！
       }
     }
     ```
   - **结果：** `CustomElementDefinition::CheckConstructorResult` 会抛出 `NotSupportedError: The result must not have attributes` 或 `NotSupportedError: The result must not have children` 错误。

3. **未注册就使用自定义元素：**
   - **错误示例：** 在 JavaScript 中没有调用 `customElements.define('my-element', MyElement)` 就直接在 HTML 中使用 `<my-element>`。
   - **结果：** 浏览器会将 `<my-element>` 视为一个未知的 HTML 标签，不会执行自定义元素的逻辑。

4. **`observedAttributes` 返回非字符串数组：**
   - **错误示例：**
     ```javascript
     class MyElement extends HTMLElement {
       static get observedAttributes() {
         return [123]; // 错误！
       }
     }
     ```
   - **结果：**  这可能会导致类型错误或未预期的行为，因为 `CustomElementDefinition` 期望 `observed_attributes_` 中的元素是字符串。

**用户操作是如何一步步的到达这里：**

1. **用户在浏览器中加载包含自定义元素的 HTML 页面。**
2. **HTML 解析器开始解析 HTML 文档。**
3. **当解析器遇到一个自定义元素的标签（例如 `<my-element>`）时，它会尝试在已注册的自定义元素列表中查找该标签对应的定义。**
4. **如果找到了对应的 `CustomElementDefinition`，Blink 引擎会根据该定义创建一个新的 `HTMLElement` 实例。** 这会调用 `CustomElementDefinition::CreateElement`。
5. **如果该自定义元素定义了 `observedAttributes`，这些属性会被存储在 `CustomElementDefinition` 对象中。**
6. **如果该自定义元素有对应的 JavaScript 类，那么在元素被添加到文档时（或在某些情况下同步升级），`CustomElementDefinition::Upgrade` 会被调用，负责执行自定义元素的构造函数。**
7. **在自定义元素的生命周期中（例如，属性被修改，元素被添加到或移除出文档），相应的 `Enqueue...Callback` 方法会被调用，将 JavaScript 的生命周期回调加入执行队列。**
8. **当 JavaScript 代码通过 `setAttribute` 等方法修改自定义元素的属性时，如果该属性在 `observedAttributes` 中，`CustomElementDefinition::EnqueueAttributeChangedCallback` 会被调用。**

总而言之，`custom_element_definition.cc` 是 Blink 引擎中管理自定义元素的核心，它连接了 HTML 标记、JavaScript 代码和浏览器的渲染引擎，确保自定义元素能够按照 Web 标准的定义正确地创建、升级和响应生命周期事件。

Prompt: 
```
这是目录为blink/renderer/core/html/custom/custom_element_definition.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
如果能说明用户操作是如何一步步的到达这里，就更棒了。

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/html/custom/custom_element_definition.h"
#include "third_party/blink/renderer/core/dom/attr.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/html/custom/custom_element.h"
#include "third_party/blink/renderer/core/html/custom/custom_element_construction_stack.h"
#include "third_party/blink/renderer/core/html/custom/custom_element_reaction.h"
#include "third_party/blink/renderer/core/html/custom/custom_element_reaction_factory.h"
#include "third_party/blink/renderer/core/html/custom/custom_element_reaction_stack.h"
#include "third_party/blink/renderer/core/html/custom/custom_element_registry.h"
#include "third_party/blink/renderer/core/html/custom/element_internals.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/html_element_factory.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"

namespace blink {

CustomElementDefinition::CustomElementDefinition(
    CustomElementRegistry& registry,
    const CustomElementDescriptor& descriptor)
    : registry_(registry), descriptor_(descriptor) {}

CustomElementDefinition::CustomElementDefinition(
    CustomElementRegistry& registry,
    const CustomElementDescriptor& descriptor,
    const HashSet<AtomicString>& observed_attributes,
    const Vector<String>& disabled_features,
    FormAssociationFlag form_association_flag)
    : registry_(registry),
      descriptor_(descriptor),
      observed_attributes_(observed_attributes),
      has_style_attribute_changed_callback_(
          observed_attributes.Contains(html_names::kStyleAttr.LocalName())),
      disable_shadow_(disabled_features.Contains(String("shadow"))),
      disable_internals_(disabled_features.Contains(String("internals"))),
      is_form_associated_(form_association_flag == FormAssociationFlag::kYes) {}

CustomElementDefinition::~CustomElementDefinition() = default;

void CustomElementDefinition::Trace(Visitor* visitor) const {
  visitor->Trace(registry_);
  ElementRareDataField::Trace(visitor);
}

static String ErrorMessageForConstructorResult(Element& element,
                                               Document& document,
                                               const QualifiedName& tag_name) {
  // https://dom.spec.whatwg.org/#concept-create-element
  // 6.1.4. If result's attribute list is not empty, then throw a
  // NotSupportedError.
  if (element.hasAttributes())
    return "The result must not have attributes";
  // 6.1.5. If result has children, then throw a NotSupportedError.
  if (element.HasChildren())
    return "The result must not have children";
  // 6.1.6. If result's parent is not null, then throw a NotSupportedError.
  if (element.parentNode())
    return "The result must not have a parent";
  // 6.1.7. If result's node document is not document, then throw a
  // NotSupportedError.
  if (&element.GetDocument() != &document)
    return "The result must be in the same document";
  // 6.1.8. If result's namespace is not the HTML namespace, then throw a
  // NotSupportedError.
  if (element.namespaceURI() != html_names::xhtmlNamespaceURI)
    return "The result must have HTML namespace";
  // 6.1.9. If result's local name is not equal to localName, then throw a
  // NotSupportedError.
  if (element.localName() != tag_name.LocalName())
    return "The result must have the same localName";
  return String();
}

void CustomElementDefinition::CheckConstructorResult(
    Element* element,
    Document& document,
    const QualifiedName& tag_name,
    ExceptionState& exception_state) {
  // https://dom.spec.whatwg.org/#concept-create-element
  // 6.1.3. If result does not implement the HTMLElement interface, throw a
  // TypeError.
  // See https://github.com/whatwg/html/issues/1402 for more clarifications.
  if (!element || !element->IsHTMLElement()) {
    exception_state.ThrowTypeError(
        "The result must implement HTMLElement interface");
    return;
  }

  // 6.1.4. through 6.1.9.
  const String message =
      ErrorMessageForConstructorResult(*element, document, tag_name);
  if (!message.empty()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kNotSupportedError,
                                      message);
  }
}

HTMLElement* CustomElementDefinition::CreateElementForConstructor(
    Document& document) {
  HTMLElement* element =
      HTMLElementFactory::Create(Descriptor().LocalName(), document,
                                 CreateElementFlags::ByCreateElement());
  if (element) {
    element->SetIsValue(Descriptor().GetName());
  } else {
    element = MakeGarbageCollected<HTMLElement>(
        QualifiedName(g_null_atom, Descriptor().LocalName(),
                      html_names::xhtmlNamespaceURI),
        document);
  }
  // TODO(davaajav): write this as one call to setCustomElementState instead of
  // two.
  element->SetCustomElementState(CustomElementState::kUndefined);
  element->SetCustomElementDefinition(this);
  return element;
}

// A part of https://dom.spec.whatwg.org/#concept-create-element
HTMLElement* CustomElementDefinition::CreateElement(
    Document& document,
    const QualifiedName& tag_name,
    CreateElementFlags flags) {
  DCHECK(
      CustomElement::ShouldCreateCustomElement(tag_name) ||
      CustomElement::ShouldCreateCustomizedBuiltinElement(tag_name, document))
      << tag_name;

  // 5. If definition is non-null, and definition’s name is not equal to
  // its local name (i.e., definition represents a customized built-in
  // element), then:
  if (!descriptor_.IsAutonomous()) {
    // 5.1. Let interface be the element interface for localName and the
    // HTML namespace.
    // 5.2. Set result to a new element that implements interface, with
    // no attributes, namespace set to the HTML namespace, namespace
    // prefix set to prefix, local name set to localName, custom element
    // state set to "undefined", custom element definition set to null,
    // is value set to is, and node document set to document.
    auto* result = document.CreateRawElement(tag_name, flags);
    result->SetCustomElementState(CustomElementState::kUndefined);
    result->SetIsValue(Descriptor().GetName());

    if (!flags.IsAsyncCustomElements()) {
      // 5.3 If the synchronous custom elements flag is set, then run this step
      // while catching any exceptions:
      //   1. Upgrade element using definition.
      // If this step threw an exception, then:
      //   1. Report the exception.
      //   2. Set result's custom element state to "failed".
      Upgrade(*result);
    } else {
      // 5.4. Otherwise, enqueue a custom element upgrade reaction given
      // result and definition.
      EnqueueUpgradeReaction(*result);
    }
    return To<HTMLElement>(result);
  }

  // 6. If definition is non-null, then:
  // 6.1. If the synchronous custom elements flag is set, then run these
  // steps while catching any exceptions:
  if (!flags.IsAsyncCustomElements()) {
    // It's impossible to create a custom element with a scoped definition
    // without push the custom element construction stack. Make sure that
    // doesn't happen for synchrnous autonomous custom elements, which  don't
    // push the stack,
    // TODO(crbug.com/1304439): Alternatively, we can push the construction
    // stack only when using a scoped definition. Decide the exact behavior.
    CHECK(!RuntimeEnabledFeatures::ScopedCustomElementRegistryEnabled() ||
          registry_->IsGlobalRegistry());
    return CreateAutonomousCustomElementSync(document, tag_name);
  }

  // 6.2. Otherwise: (the synchronous custom elements flag is not set)
  // 6.2.1. Set result to a new element that implements the HTMLElement
  // interface, with no attributes, namespace set to the HTML namespace,
  // namespace prefix set to prefix, local name set to localName, custom
  // element state set to "undefined", and node document set to document.
  auto* element = MakeGarbageCollected<HTMLElement>(tag_name, document);
  element->SetCustomElementState(CustomElementState::kUndefined);
  // 6.2.2. Enqueue a custom element upgrade reaction given result and
  // definition.
  EnqueueUpgradeReaction(*element);
  return element;
}

// https://html.spec.whatwg.org/C/#concept-upgrade-an-element
void CustomElementDefinition::Upgrade(Element& element) {
  // 4.13.5.1 If element's custom element state is not "undefined" or
  // "uncustomized", then return.
  if (element.GetCustomElementState() != CustomElementState::kUndefined &&
      element.GetCustomElementState() != CustomElementState::kUncustomized) {
    return;
  }

  // 4.13.5.3. Set element's custom element state to "failed".
  element.SetCustomElementState(CustomElementState::kFailed);

  // 4.13.5.4: For each attribute in element's attribute list, in order, enqueue
  // a custom element callback reaction with element, callback name
  // "attributeChangedCallback", and an argument list containing attribute's
  // local name, null, attribute's value, and attribute's namespace.
  if (!observed_attributes_.empty())
    EnqueueAttributeChangedCallbackForAllAttributes(element);

  // 4.13.5.5: If element is connected, then enqueue a custom element callback
  // reaction with element, callback name "connectedCallback", and an empty
  // argument list.
  if (element.isConnected() && HasConnectedCallback())
    EnqueueConnectedCallback(element);

  bool succeeded = false;
  {
    // 4.13.5.6: Add element to the end of definition's construction stack.
    CustomElementConstructionStackScope construction_stack_scope(*this,
                                                                 element);
    // 4.13.5.8: Run the constructor, catching exceptions.
    succeeded = RunConstructor(element);
  }
  if (!succeeded) {
    // 4.13.5.?: If the above steps threw an exception, then element's custom
    // element state will remain "failed".
    CustomElementReactionStack::From(element.GetDocument().GetAgent())
        .ClearQueue(element);
    return;
  }

  element.SetCustomElementDefinition(this);

  // Setting the custom element definition changes the value of
  // IsFormAssociatedCustomElement(), which impacts whether HTMLElement calls
  // to the ListedElement when an attribute changes. Call the various change
  // methods now to ensure ListedElements state is correct.
  if (ListedElement* listed_element = ListedElement::From(element)) {
    if (element.FastHasAttribute(html_names::kReadonlyAttr))
      listed_element->ReadonlyAttributeChanged();
    if (element.FastHasAttribute(html_names::kDisabledAttr))
      listed_element->DisabledAttributeChanged();
  }

  if (IsFormAssociated())
    To<HTMLElement>(element).EnsureElementInternals().DidUpgrade();
}

bool CustomElementDefinition::HasAttributeChangedCallback(
    const QualifiedName& name) const {
  return observed_attributes_.Contains(name.LocalName());
}

bool CustomElementDefinition::HasStyleAttributeChangedCallback() const {
  return has_style_attribute_changed_callback_;
}

void CustomElementDefinition::EnqueueUpgradeReaction(Element& element) {
  CustomElement::Enqueue(element,
                         CustomElementReactionFactory::CreateUpgrade(*this));
}

void CustomElementDefinition::EnqueueConnectedCallback(Element& element) {
  CustomElement::Enqueue(element,
                         CustomElementReactionFactory::CreateConnected(*this));
}

void CustomElementDefinition::EnqueueDisconnectedCallback(Element& element) {
  CustomElement::Enqueue(
      element, CustomElementReactionFactory::CreateDisconnected(*this));
}

void CustomElementDefinition::EnqueueConnectedMoveCallback(Element& element) {
  CustomElement::Enqueue(
      element, CustomElementReactionFactory::CreateConnectedMove(*this));
}

void CustomElementDefinition::EnqueueAdoptedCallback(Element& element,
                                                     Document& old_document,
                                                     Document& new_document) {
  CustomElement::Enqueue(element, CustomElementReactionFactory::CreateAdopted(
                                      *this, old_document, new_document));
}

void CustomElementDefinition::EnqueueAttributeChangedCallback(
    Element& element,
    const QualifiedName& name,
    const AtomicString& old_value,
    const AtomicString& new_value) {
  CustomElement::Enqueue(element,
                         CustomElementReactionFactory::CreateAttributeChanged(
                             *this, name, old_value, new_value));
}

void CustomElementDefinition::EnqueueAttributeChangedCallbackForAllAttributes(
    Element& element) {
  // Avoid synchronizing all attributes unless it is needed, while enqueing
  // callbacks "in order" as defined in the spec.
  // https://html.spec.whatwg.org/C/#concept-upgrade-an-element
  for (const AtomicString& name : observed_attributes_)
    element.SynchronizeAttribute(name);
  for (const auto& attribute : element.AttributesWithoutUpdate()) {
    if (HasAttributeChangedCallback(attribute.GetName())) {
      EnqueueAttributeChangedCallback(element, attribute.GetName(), g_null_atom,
                                      attribute.Value());
    }
  }
}

}  // namespace blink

"""

```