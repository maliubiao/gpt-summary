Response:
Let's break down the thought process for analyzing the provided C++ test file for Chromium's Blink engine.

**1. Initial Understanding: What is the file about?**

The filename `custom_element_registry_test.cc` immediately suggests this file contains unit tests for the `CustomElementRegistry` class. The path `blink/renderer/core/html/custom/` further confirms this, placing it within the HTML custom element implementation within the Blink rendering engine.

**2. High-Level Functionality Identification:**

Reading the includes gives a broad overview of what the `CustomElementRegistry` is involved with:

* `CustomElementRegistry.h`: The class being tested.
* `gtest/gtest.h`: The Google Test framework.
* `WebCustomElement.h`:  Indicates interaction with the web platform's custom elements API.
* `v8_...h`:  Suggests interaction with JavaScript (V8 engine).
* `ElementDefinitionOptions.h`, `ShadowRootInit.h`: Options and settings related to custom element definitions and shadow DOM.
* `StyleSheetContents.h`: Indicates possible interaction with CSS.
* `Document.h`, `Element.h`, `ShadowRoot.h`: Core DOM concepts, fundamental to custom elements.
* `LocalDomWindow.h`, `LocalFrame.h`: Browser frame and window context.
* `ce_reactions_scope.h`: Likely related to the lifecycle callbacks of custom elements.
* `CustomElement.h`, `CustomElementDefinition.h`, `CustomElementDefinitionBuilder.h`, `CustomElementDescriptor.h`:  Core components of the custom elements implementation.
* `CustomElementTestHelpers.h`: Utility functions for testing custom elements.
* `HTMLElement.h`:  Base class for HTML elements.
* `NullExecutionContext.h`: For creating controlled test environments.
* `ExceptionState.h`: Handling errors and exceptions.
* `ScriptForbiddenScope.h`:  Controlling script execution during tests.
* `GarbageCollected.h`: Memory management within Blink.
* `TaskEnvironment.h`:  Managing asynchronous tasks in tests.
* `AtomicString.h`:  Efficient string handling.

From these includes, we can infer that `CustomElementRegistry` is responsible for:

* Storing and managing custom element definitions.
* Upgrading elements to custom elements.
* Handling lifecycle callbacks (constructor, connectedCallback, disconnectedCallback, adoptedCallback, attributeChangedCallback).
* Interacting with the DOM (Document, Element).
* Potentially involving CSS and Shadow DOM.
* Being influenced by JavaScript through the V8 integration.

**3. Examining the Test Structure:**

The `CustomElementRegistryTest` class, inheriting from `::testing::Test`, provides the testing fixture. The `TEST_F` macros define individual test cases. The helper methods within the test fixture (`Registry()`, `GetScriptState()`, `GetDocument()`, `Define()`, `CollectCandidates()`) are used to interact with the `CustomElementRegistry` in a controlled manner.

**4. Analyzing Individual Test Cases (Examples):**

* **`collectCandidates_shouldNotIncludeElementsRemovedFromDocument`:**  Tests that elements no longer in the document are not considered candidates for custom element upgrades. This highlights a key aspect of the registry's behavior: it focuses on the active DOM.
* **`define_upgradesInDocumentElements`:**  Tests the scenario where a custom element is defined *after* elements with the same tag name already exist in the document. It verifies that these existing elements are "upgraded" to the custom element behavior, triggering the constructor and attribute change callbacks. This directly relates to how custom elements are applied to existing DOM.
* **`attributeChangedCallback`:** Verifies that when an attribute of a custom element is changed, the `attributeChangedCallback` is correctly invoked. This is a core lifecycle event.
* **`lookupCustomElementDefinition`:**  Tests the ability to retrieve a custom element definition based on its tag name and/or the `is` attribute (for customized built-in elements). This is fundamental for the browser to know how to handle specific tags.

**5. Identifying Relationships with Web Technologies:**

* **JavaScript:** The use of `V8CustomElementConstructor`, `ScriptState`, and the test scenarios involving element upgrades directly tie into how custom elements are defined and interacted with via JavaScript's `customElements.define()` API. The test for defining embedder custom elements also hints at potential browser-level APIs.
* **HTML:** The tests create and manipulate HTML elements (`CreateElement`), check for presence in the document, and deal with attributes. The core purpose of custom elements is to extend HTML.
* **CSS:** While not explicitly tested for direct CSS interaction in *this specific file*, the inclusion of `v8_css_style_sheet_init.h` and the concept of Shadow DOM (which can encapsulate styles) in other included headers suggest that CSS styling of custom elements is likely handled elsewhere in the Blink engine and is a related area.

**6. Logical Reasoning and Assumptions:**

* **Assumption:**  The `CustomElementTestingScope` is a helper class specifically designed to set up isolated testing environments for custom elements.
* **Reasoning (example from `collectCandidates_shouldBeInDocumentOrder`):** The test adds elements to the registry in one order but appends them to the DOM in a different order. It then verifies that `CollectCandidates` returns the elements in document order. This demonstrates the registry's awareness of the DOM tree structure. *Input:*  Adding elements b, a, then c to the registry. Appending a, then b as a child of a, then c as a sibling of a. *Output:*  The collected candidates are in the order a, b, c.

**7. Identifying Common Usage Errors (and how tests prevent them):**

The tests implicitly demonstrate correct usage and highlight potential errors:

* **Not registering a custom element before using it:**  While not a specific error tested here, the overall test structure implies that registration is a prerequisite. Other tests likely cover the error scenarios of using an unregistered element.
* **Defining the same custom element name twice:**  The `Define` method likely handles this, possibly throwing an exception. Tests for this would exist elsewhere.
* **Incorrectly implementing lifecycle callbacks:** The tests with `LogUpgradeDefinition` explicitly verify the order and invocation of these callbacks, helping to ensure developers implement them correctly.

**8. User Operations Leading to This Code:**

This is more speculative but involves the developer-facing API:

1. **Web Developer writes JavaScript code:**  A developer uses `customElements.define('my-element', MyElementClass)` in their JavaScript.
2. **Browser parses the JavaScript:** The JavaScript engine encounters this line and needs to register the custom element.
3. **The browser's HTML parser encounters an unknown tag:** If the developer uses `<my-element>` in their HTML before registration, the parser might add it to a list of potential custom elements.
4. **The `CustomElementRegistry` comes into play:**  When `customElements.define` is called, the browser interacts with the `CustomElementRegistry` (the C++ code being tested) to store the definition. If elements with the registered tag name already exist, the registry manages their upgrade.
5. **DOM manipulation:**  Adding or removing elements via JavaScript or the browser's rendering process will trigger the registry to check for custom element definitions and potentially invoke lifecycle callbacks.

**Self-Correction/Refinement during Analysis:**

Initially, I might have focused too heavily on just the individual tests. Realizing the importance of the included headers and the overall structure helped me gain a more holistic understanding of the `CustomElementRegistry`'s role. Also, connecting the C++ code back to the web developer's experience (using JavaScript and HTML) provided a crucial context. Recognizing that error handling and other aspects of custom element behavior are likely tested in *other* files prevented me from trying to find everything within this single test file.
这个文件 `custom_element_registry_test.cc` 是 Chromium Blink 引擎中负责测试 `CustomElementRegistry` 类的单元测试文件。 `CustomElementRegistry` 类在 Web Components 技术中扮演着核心角色，它负责管理自定义元素的定义和生命周期。

**这个文件的主要功能是：**

1. **测试自定义元素的注册和查找功能:** 验证 `CustomElementRegistry` 是否能正确地注册新的自定义元素定义，并且能够根据元素标签名（tag name）或者 `is` 属性（对于定制化的内置元素）来找到对应的定义。

2. **测试自定义元素的升级 (Upgrade) 机制:**  当一个 HTML 元素在定义其对应的自定义元素之前就已经存在于 DOM 树中时，`CustomElementRegistry` 负责在定义被注册后，将这些现有的元素“升级”为自定义元素。这个文件会测试这种升级过程是否正确触发了自定义元素的构造函数和生命周期回调函数。

3. **测试自定义元素的生命周期回调函数:**  自定义元素可以定义一些特定的回调函数，例如 `constructor`（构造函数）, `connectedCallback`（连接到 DOM 时触发）, `disconnectedCallback`（从 DOM 断开连接时触发）, `adoptedCallback`（被移动到新的文档时触发）, 和 `attributeChangedCallback`（属性发生变化时触发）。这个文件会测试这些回调函数在合适的时机是否被正确调用。

4. **测试候选元素的收集 (Collecting Candidates):** 在定义自定义元素之后，浏览器需要找到文档中所有尚未升级但标签名匹配的元素。这个文件测试 `CustomElementRegistry` 是否能正确地收集这些候选元素，并且不会包含已经被移除或不在当前文档中的元素。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **JavaScript:**
    * **关联:** `CustomElementRegistry` 是通过 JavaScript 的 `customElements.define()` API 来交互的。开发者使用 JavaScript 来定义自定义元素的类，并将其与一个标签名关联起来。
    * **举例:**  在 JavaScript 中，你可以这样定义和注册一个自定义元素：
      ```javascript
      class MyGreeting extends HTMLElement {
        constructor() {
          super();
          this.textContent = 'Hello, world!';
        }
      }
      customElements.define('my-greeting', MyGreeting);
      ```
      `CustomElementRegistry` 的功能就是处理 `customElements.define()` 这一步，存储 `my-greeting` 和 `MyGreeting` 之间的关联，并在遇到 `<my-greeting>` 标签时创建 `MyGreeting` 的实例。
    * **测试中的体现:** 文件中的 `Define` 函数模拟了 JavaScript 调用 `customElements.define()` 的过程。`V8CustomElementConstructor` 等类型表明了与 V8 引擎（Chrome 的 JavaScript 引擎）的集成。

* **HTML:**
    * **关联:** 自定义元素最终会以 HTML 标签的形式出现在页面中。`CustomElementRegistry` 负责将 HTML 标签与自定义元素的 JavaScript 类关联起来。
    * **举例:** 在 HTML 中使用上面定义的自定义元素：
      ```html
      <my-greeting></my-greeting>
      ```
      当浏览器解析到 `<my-greeting>` 标签时，`CustomElementRegistry` 会查找该标签对应的定义，并创建 `MyGreeting` 的实例来渲染这个元素。
    * **测试中的体现:** 文件中大量使用了 `CreateElement` 函数来创建模拟的 HTML 元素，并测试这些元素在自定义元素定义注册前后的状态变化。

* **CSS:**
    * **关联:** 虽然这个测试文件本身并没有直接测试 CSS，但自定义元素可以像普通 HTML 元素一样被 CSS 样式化。此外，自定义元素还可以使用 Shadow DOM 来封装自己的样式。
    * **举例:** 可以为自定义元素添加 CSS 样式：
      ```css
      my-greeting {
        color: blue;
        font-weight: bold;
      }
      ```
      如果自定义元素使用了 Shadow DOM，那么其内部的样式可以与外部样式隔离。
    * **间接体现:** 文件中包含了 `v8_css_style_sheet_init.h` 和 `v8_shadow_root_init.h` 的头文件，暗示了 `CustomElementRegistry` 的实现可能需要与 CSS 样式表和 Shadow DOM 的初始化过程进行交互，虽然具体的 CSS 测试可能在其他文件中。

**逻辑推理的假设输入与输出:**

* **假设输入:**  在文档中创建了一个 `<my-element>` 元素。然后，JavaScript 调用 `customElements.define('my-element', MyElementClass)` 注册了一个名为 `my-element` 的自定义元素。
* **输出:** `CustomElementRegistry` 会找到文档中已存在的 `<my-element>` 元素，并对其进行“升级”，即创建 `MyElementClass` 的实例，并将其关联到该元素上。 `MyElementClass` 的构造函数和 `connectedCallback` 等生命周期回调函数会被调用。

* **假设输入:**  JavaScript 调用 `customElements.define('my-button', MyButtonClass, { extends: 'button' })` 注册了一个定制化的内置元素。然后在文档中创建了一个 `<button is="my-button"></button>` 元素。
* **输出:** `CustomElementRegistry` 会识别出 `is="my-button"` 属性，并创建 `MyButtonClass` 的实例来增强这个原生的 `<button>` 元素的功能。

**涉及用户或编程常见的使用错误及举例说明:**

* **错误:** 在自定义元素定义注册之前就使用了该元素。
    * **例子:**  HTML 中有 `<my-element></my-element>`，但相应的 `customElements.define('my-element', ...)` 代码在 HTML 解析完成之后才执行。
    * **`CustomElementRegistry` 的处理:**  在这种情况下，浏览器会将 `<my-element>` 视为一个未知的 HTML 元素。一旦 `define` 调用发生，`CustomElementRegistry` 会找到这些“待升级”的元素并进行升级。测试文件中的 `define_upgradesInDocumentElements` 测试了这种情况。

* **错误:**  尝试多次定义同一个自定义元素名称。
    * **例子:**  多次调用 `customElements.define('my-element', ...)` 使用相同的标签名。
    * **`CustomElementRegistry` 的处理:**  这通常会导致一个 JavaScript 错误。 `CustomElementRegistry` 需要确保每个自定义元素名称只能对应一个定义。 虽然这个测试文件可能没有直接测试错误处理，但 `DefineInternal` 方法和 `ExceptionState` 参数暗示了这种错误处理机制的存在。

* **错误:**  在自定义元素的生命周期回调函数中执行了不恰当的操作，例如在 `connectedCallback` 中同步地修改了大量 DOM 结构，可能导致性能问题或无限循环。
    * **`CustomElementRegistry` 的处理:**  `CustomElementRegistry` 负责调用这些回调，但它本身不负责限制回调函数内的行为。开发者需要谨慎处理这些回调函数中的逻辑。测试文件通过 `LogUpgradeDefinition` 类记录回调函数的调用情况，可以帮助开发者理解回调发生的时机。

**用户操作如何一步步到达这里:**

1. **开发者编写 Web 代码:**  开发者创建包含自定义元素的 HTML、CSS 和 JavaScript 代码。
2. **用户访问网页:** 用户在浏览器中打开包含这些代码的网页。
3. **浏览器解析 HTML:**  当浏览器解析 HTML 时，遇到了自定义元素的标签（例如 `<my-greeting>`）。
4. **浏览器执行 JavaScript:** 浏览器执行网页中的 JavaScript 代码，其中包括调用 `customElements.define()` 来注册自定义元素。
5. **`CustomElementRegistry` 工作:**
    * 当 `customElements.define()` 被调用时，浏览器内部会调用 `CustomElementRegistry` 的方法来存储自定义元素的定义。
    * 如果在定义之前已经存在与该标签名匹配的元素，`CustomElementRegistry` 会将这些元素标记为需要升级。
    * 当元素被添加到 DOM 或从 DOM 中移除时，`CustomElementRegistry` 会触发相应的生命周期回调函数。
6. **渲染和交互:** 浏览器根据自定义元素的定义来渲染和处理用户的交互。

因此，`custom_element_registry_test.cc` 这个文件是在 Chromium 浏览器开发过程中，为了确保自定义元素的核心管理机制 `CustomElementRegistry` 功能正确而编写的自动化测试代码。它模拟了各种场景，包括自定义元素的注册、升级、生命周期管理等，以保证 Web Components 技术在 Chrome 浏览器中的稳定性和可靠性。

Prompt: 
```
这是目录为blink/renderer/core/html/custom/custom_element_registry_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
如果能说明用户操作是如何一步步的到达这里，就更棒了。

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/html/custom/custom_element_registry.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/web/web_custom_element.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_css_style_sheet_init.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_element_definition_options.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_shadow_root_init.h"
#include "third_party/blink/renderer/core/css/style_sheet_contents.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/html/custom/ce_reactions_scope.h"
#include "third_party/blink/renderer/core/html/custom/custom_element.h"
#include "third_party/blink/renderer/core/html/custom/custom_element_definition.h"
#include "third_party/blink/renderer/core/html/custom/custom_element_definition_builder.h"
#include "third_party/blink/renderer/core/html/custom/custom_element_descriptor.h"
#include "third_party/blink/renderer/core/html/custom/custom_element_test_helpers.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/testing/null_execution_context.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_forbidden_scope.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/wtf/text/atomic_string.h"

namespace blink {

class CustomElementRegistryTest : public ::testing::Test {
 public:
  CustomElementRegistry& Registry() {
    return CustomElementTestingScope::GetInstance().Registry();
  }

  ScriptState* GetScriptState() {
    return CustomElementTestingScope::GetInstance().GetScriptState();
  }

  Document& GetDocument() {
    return CustomElementTestingScope::GetInstance().GetDocument();
  }

  CustomElementDefinition* Define(const char* name,
                                  CustomElementDefinitionBuilder& builder,
                                  const ElementDefinitionOptions* options,
                                  ExceptionState& exception_state) {
    return Registry().DefineInternal(GetScriptState(), AtomicString(name),
                                     builder, options, exception_state);
  }

  void CollectCandidates(const CustomElementDescriptor& desc,
                         HeapVector<Member<Element>>* elements) {
    Registry().CollectCandidates(desc, elements);
  }
  test::TaskEnvironment task_environment_;
};

TEST_F(CustomElementRegistryTest,
       collectCandidates_shouldNotIncludeElementsRemovedFromDocument) {
  CustomElementTestingScope testing_scope;
  Element& element =
      *CreateElement(AtomicString("a-a")).InDocument(&GetDocument());
  Registry().AddCandidate(element);

  HeapVector<Member<Element>> elements;
  CollectCandidates(
      CustomElementDescriptor(AtomicString("a-a"), AtomicString("a-a")),
      &elements);

  EXPECT_TRUE(elements.empty())
      << "no candidates should have been found, but we have "
      << elements.size();
  EXPECT_FALSE(elements.Contains(element))
      << "the out-of-document candidate should not have been found";
}

TEST_F(CustomElementRegistryTest,
       collectCandidates_shouldNotIncludeElementsInDifferentDocument) {
  CustomElementTestingScope testing_scope;
  Element* element =
      CreateElement(AtomicString("a-a")).InDocument(&GetDocument());
  Registry().AddCandidate(*element);

  ScopedNullExecutionContext execution_context;
  auto* other_document =
      HTMLDocument::CreateForTest(execution_context.GetExecutionContext());
  other_document->AppendChild(element);
  EXPECT_EQ(other_document, element->ownerDocument())
      << "sanity: another document should have adopted an element on append";

  HeapVector<Member<Element>> elements;
  CollectCandidates(
      CustomElementDescriptor(AtomicString("a-a"), AtomicString("a-a")),
      &elements);

  EXPECT_TRUE(elements.empty())
      << "no candidates should have been found, but we have "
      << elements.size();
  EXPECT_FALSE(elements.Contains(element))
      << "the adopted-away candidate should not have been found";
}

TEST_F(CustomElementRegistryTest,
       collectCandidates_shouldOnlyIncludeCandidatesMatchingDescriptor) {
  CustomElementTestingScope testing_scope;
  CustomElementDescriptor descriptor(AtomicString("hello-world"),
                                     AtomicString("hello-world"));

  // Does not match: namespace is not HTML
  Element& element_a =
      *CreateElement(AtomicString("hello-world"))
           .InDocument(&GetDocument())
           .InNamespace(AtomicString("data:text/date,1981-03-10"));
  // Matches
  Element& element_b =
      *CreateElement(AtomicString("hello-world")).InDocument(&GetDocument());
  // Does not match: local name is not hello-world
  Element& element_c = *CreateElement(AtomicString("button"))
                            .InDocument(&GetDocument())
                            .WithIsValue(AtomicString("hello-world"));
  GetDocument().documentElement()->AppendChild(&element_a);
  element_a.AppendChild(&element_b);
  element_a.AppendChild(&element_c);

  Registry().AddCandidate(element_a);
  Registry().AddCandidate(element_b);
  Registry().AddCandidate(element_c);

  HeapVector<Member<Element>> elements;
  CollectCandidates(descriptor, &elements);

  EXPECT_EQ(1u, elements.size())
      << "only one candidates should have been found";
  EXPECT_EQ(element_b, elements[0])
      << "the matching element should have been found";
}

TEST_F(CustomElementRegistryTest, collectCandidates_oneCandidate) {
  CustomElementTestingScope testing_scope;
  Element& element =
      *CreateElement(AtomicString("a-a")).InDocument(&GetDocument());
  Registry().AddCandidate(element);
  GetDocument().documentElement()->AppendChild(&element);

  HeapVector<Member<Element>> elements;
  CollectCandidates(
      CustomElementDescriptor(AtomicString("a-a"), AtomicString("a-a")),
      &elements);

  EXPECT_EQ(1u, elements.size())
      << "exactly one candidate should have been found";
  EXPECT_TRUE(elements.Contains(element))
      << "the candidate should be the element that was added";
}

TEST_F(CustomElementRegistryTest, collectCandidates_shouldBeInDocumentOrder) {
  CustomElementTestingScope testing_scope;
  CreateElement factory = CreateElement(AtomicString("a-a"));
  factory.InDocument(&GetDocument());
  Element* element_a = factory.WithId(AtomicString("a"));
  Element* element_b = factory.WithId(AtomicString("b"));
  Element* element_c = factory.WithId(AtomicString("c"));

  Registry().AddCandidate(*element_b);
  Registry().AddCandidate(*element_a);
  Registry().AddCandidate(*element_c);

  GetDocument().documentElement()->AppendChild(element_a);
  element_a->AppendChild(element_b);
  GetDocument().documentElement()->AppendChild(element_c);

  HeapVector<Member<Element>> elements;
  CollectCandidates(
      CustomElementDescriptor(AtomicString("a-a"), AtomicString("a-a")),
      &elements);

  EXPECT_EQ(element_a, elements[0].Get());
  EXPECT_EQ(element_b, elements[1].Get());
  EXPECT_EQ(element_c, elements[2].Get());
}

// Classes which use trace macros cannot be local because of the
// traceImpl template.
class LogUpgradeDefinition : public TestCustomElementDefinition {
 public:
  LogUpgradeDefinition(const CustomElementDescriptor& descriptor,
                       V8CustomElementConstructor* constructor)
      : TestCustomElementDefinition(
            descriptor,
            constructor,
            {
                AtomicString("attr1"),
                AtomicString("attr2"),
                html_names::kContenteditableAttr.LocalName(),
            },
            {}) {}
  LogUpgradeDefinition(const LogUpgradeDefinition&) = delete;
  LogUpgradeDefinition& operator=(const LogUpgradeDefinition&) = delete;

  void Trace(Visitor* visitor) const override {
    TestCustomElementDefinition::Trace(visitor);
    visitor->Trace(element_);
    visitor->Trace(adopted_);
  }

  // TODO(dominicc): Make this class collect a vector of what's
  // upgraded; it will be useful in more tests.
  Member<Element> element_;
  enum MethodType {
    kConstructor,
    kConnectedCallback,
    kDisconnectedCallback,
    kAdoptedCallback,
    kAttributeChangedCallback,
  };
  Vector<MethodType> logs_;

  struct AttributeChanged {
    QualifiedName name;
    AtomicString old_value;
    AtomicString new_value;
  };
  Vector<AttributeChanged> attribute_changed_;

  struct Adopted : public GarbageCollected<Adopted> {
    Adopted(Document& old_owner, Document& new_owner)
        : old_owner_(old_owner), new_owner_(new_owner) {}

    Member<Document> old_owner_;
    Member<Document> new_owner_;

    void Trace(Visitor* visitor) const {
      visitor->Trace(old_owner_);
      visitor->Trace(new_owner_);
    }
  };
  HeapVector<Member<Adopted>> adopted_;

  void Clear() {
    logs_.clear();
    attribute_changed_.clear();
  }

  bool RunConstructor(Element& element) override {
    logs_.push_back(kConstructor);
    element_ = element;
    return TestCustomElementDefinition::RunConstructor(element);
  }

  bool HasConnectedCallback() const override { return true; }
  bool HasDisconnectedCallback() const override { return true; }
  bool HasAdoptedCallback() const override { return true; }

  void RunConnectedCallback(Element& element) override {
    logs_.push_back(kConnectedCallback);
    EXPECT_EQ(&element, element_);
  }

  void RunDisconnectedCallback(Element& element) override {
    logs_.push_back(kDisconnectedCallback);
    EXPECT_EQ(&element, element_);
  }

  void RunAdoptedCallback(Element& element,
                          Document& old_owner,
                          Document& new_owner) override {
    logs_.push_back(kAdoptedCallback);
    EXPECT_EQ(&element, element_);
    adopted_.push_back(MakeGarbageCollected<Adopted>(old_owner, new_owner));
  }

  void RunAttributeChangedCallback(Element& element,
                                   const QualifiedName& name,
                                   const AtomicString& old_value,
                                   const AtomicString& new_value) override {
    logs_.push_back(kAttributeChangedCallback);
    EXPECT_EQ(&element, element_);
    attribute_changed_.push_back(AttributeChanged{name, old_value, new_value});
  }
};

class LogUpgradeBuilder final : public TestCustomElementDefinitionBuilder {
  STACK_ALLOCATED();

 public:
  LogUpgradeBuilder() = default;
  LogUpgradeBuilder(const LogUpgradeBuilder&) = delete;
  LogUpgradeBuilder& operator=(const LogUpgradeBuilder&) = delete;

  CustomElementDefinition* Build(
      const CustomElementDescriptor& descriptor) override {
    return MakeGarbageCollected<LogUpgradeDefinition>(descriptor,
                                                      Constructor());
  }
};

TEST_F(CustomElementRegistryTest, define_upgradesInDocumentElements) {
  CustomElementTestingScope testing_scope;
  ScriptForbiddenScope do_not_rely_on_script;

  Element* element =
      CreateElement(AtomicString("a-a")).InDocument(&GetDocument());
  element->setAttribute(QualifiedName(g_null_atom, AtomicString("attr1"),
                                      html_names::xhtmlNamespaceURI),
                        AtomicString("v1"));
  element->SetBooleanAttribute(html_names::kContenteditableAttr, true);
  GetDocument().documentElement()->AppendChild(element);

  LogUpgradeBuilder builder;
  NonThrowableExceptionState should_not_throw;
  {
    CEReactionsScope reactions;
    Define("a-a", builder, ElementDefinitionOptions::Create(),
           should_not_throw);
  }
  LogUpgradeDefinition* definition = static_cast<LogUpgradeDefinition*>(
      Registry().DefinitionForName(AtomicString("a-a")));
  EXPECT_EQ(LogUpgradeDefinition::kConstructor, definition->logs_[0])
      << "defining the element should have 'upgraded' the existing element";
  EXPECT_EQ(element, definition->element_)
      << "the existing a-a element should have been upgraded";

  EXPECT_EQ(LogUpgradeDefinition::kAttributeChangedCallback,
            definition->logs_[1])
      << "Upgrade should invoke attributeChangedCallback for all attributes";
  EXPECT_EQ("attr1", definition->attribute_changed_[0].name.LocalName());
  EXPECT_EQ(g_null_atom, definition->attribute_changed_[0].old_value);
  EXPECT_EQ("v1", definition->attribute_changed_[0].new_value);

  EXPECT_EQ(LogUpgradeDefinition::kAttributeChangedCallback,
            definition->logs_[2])
      << "Upgrade should invoke attributeChangedCallback for all attributes";
  EXPECT_EQ("contenteditable",
            definition->attribute_changed_[1].name.LocalName());
  EXPECT_EQ(g_null_atom, definition->attribute_changed_[1].old_value);
  EXPECT_EQ(g_empty_atom, definition->attribute_changed_[1].new_value);
  EXPECT_EQ(2u, definition->attribute_changed_.size())
      << "Upgrade should invoke attributeChangedCallback for all attributes";

  EXPECT_EQ(LogUpgradeDefinition::kConnectedCallback, definition->logs_[3])
      << "upgrade should invoke connectedCallback";

  EXPECT_EQ(4u, definition->logs_.size())
      << "upgrade should not invoke other callbacks";
}

TEST_F(CustomElementRegistryTest, attributeChangedCallback) {
  CustomElementTestingScope testing_scope;
  ScriptForbiddenScope do_not_rely_on_script;

  Element* element =
      CreateElement(AtomicString("a-a")).InDocument(&GetDocument());
  GetDocument().documentElement()->AppendChild(element);

  LogUpgradeBuilder builder;
  NonThrowableExceptionState should_not_throw;
  {
    CEReactionsScope reactions;
    Define("a-a", builder, ElementDefinitionOptions::Create(),
           should_not_throw);
  }
  LogUpgradeDefinition* definition = static_cast<LogUpgradeDefinition*>(
      Registry().DefinitionForName(AtomicString("a-a")));

  definition->Clear();
  {
    CEReactionsScope reactions;
    element->setAttribute(QualifiedName(g_null_atom, AtomicString("attr2"),
                                        html_names::xhtmlNamespaceURI),
                          AtomicString("v2"));
  }
  EXPECT_EQ(LogUpgradeDefinition::kAttributeChangedCallback,
            definition->logs_[0])
      << "Adding an attribute should invoke attributeChangedCallback";
  EXPECT_EQ(1u, definition->attribute_changed_.size())
      << "Adding an attribute should invoke attributeChangedCallback";
  EXPECT_EQ("attr2", definition->attribute_changed_[0].name.LocalName());
  EXPECT_EQ(g_null_atom, definition->attribute_changed_[0].old_value);
  EXPECT_EQ("v2", definition->attribute_changed_[0].new_value);

  EXPECT_EQ(1u, definition->logs_.size())
      << "upgrade should not invoke other callbacks";
}

TEST_F(CustomElementRegistryTest, disconnectedCallback) {
  CustomElementTestingScope testing_scope;
  ScriptForbiddenScope do_not_rely_on_script;

  Element* element =
      CreateElement(AtomicString("a-a")).InDocument(&GetDocument());
  GetDocument().documentElement()->AppendChild(element);

  LogUpgradeBuilder builder;
  NonThrowableExceptionState should_not_throw;
  {
    CEReactionsScope reactions;
    Define("a-a", builder, ElementDefinitionOptions::Create(),
           should_not_throw);
  }
  LogUpgradeDefinition* definition = static_cast<LogUpgradeDefinition*>(
      Registry().DefinitionForName(AtomicString("a-a")));

  definition->Clear();
  {
    CEReactionsScope reactions;
    element->remove(should_not_throw);
  }
  EXPECT_EQ(LogUpgradeDefinition::kDisconnectedCallback, definition->logs_[0])
      << "remove() should invoke disconnectedCallback";

  EXPECT_EQ(1u, definition->logs_.size())
      << "remove() should not invoke other callbacks";
}

TEST_F(CustomElementRegistryTest, adoptedCallback) {
  CustomElementTestingScope testing_scope;
  ScriptForbiddenScope do_not_rely_on_script;

  Element* element =
      CreateElement(AtomicString("a-a")).InDocument(&GetDocument());
  GetDocument().documentElement()->AppendChild(element);

  LogUpgradeBuilder builder;
  NonThrowableExceptionState should_not_throw;
  {
    CEReactionsScope reactions;
    Define("a-a", builder, ElementDefinitionOptions::Create(),
           should_not_throw);
  }
  LogUpgradeDefinition* definition = static_cast<LogUpgradeDefinition*>(
      Registry().DefinitionForName(AtomicString("a-a")));

  definition->Clear();
  auto* other_document =
      HTMLDocument::CreateForTest(*GetDocument().GetExecutionContext());
  {
    CEReactionsScope reactions;
    other_document->adoptNode(element, ASSERT_NO_EXCEPTION);
  }
  EXPECT_EQ(LogUpgradeDefinition::kDisconnectedCallback, definition->logs_[0])
      << "adoptNode() should invoke disconnectedCallback";

  EXPECT_EQ(LogUpgradeDefinition::kAdoptedCallback, definition->logs_[1])
      << "adoptNode() should invoke adoptedCallback";

  EXPECT_EQ(GetDocument(), definition->adopted_[0]->old_owner_.Get())
      << "adoptedCallback should have been passed the old owner document";
  EXPECT_EQ(other_document, definition->adopted_[0]->new_owner_.Get())
      << "adoptedCallback should have been passed the new owner document";

  EXPECT_EQ(2u, definition->logs_.size())
      << "adoptNode() should not invoke other callbacks";
}

TEST_F(CustomElementRegistryTest, lookupCustomElementDefinition) {
  CustomElementTestingScope testing_scope;
  NonThrowableExceptionState should_not_throw;
  TestCustomElementDefinitionBuilder builder_a;
  CustomElementDefinition* definition_a = Define(
      "a-a", builder_a, ElementDefinitionOptions::Create(), should_not_throw);
  TestCustomElementDefinitionBuilder builder_b;
  ElementDefinitionOptions* options = ElementDefinitionOptions::Create();
  options->setExtends("div");
  CustomElementDefinition* definition_b =
      Define("b-b", builder_b, options, should_not_throw);
  // look up defined autonomous custom element
  CustomElementDefinition* definition =
      Registry().DefinitionFor(CustomElementDescriptor(
          CustomElementDescriptor(AtomicString("a-a"), AtomicString("a-a"))));
  EXPECT_NE(nullptr, definition) << "a-a, a-a should be registered";
  EXPECT_EQ(definition_a, definition);
  // look up undefined autonomous custom element
  definition = Registry().DefinitionFor(
      CustomElementDescriptor(AtomicString("a-a"), AtomicString("div")));
  EXPECT_EQ(nullptr, definition) << "a-a, div should not be registered";
  // look up defined customized built-in element
  definition = Registry().DefinitionFor(
      CustomElementDescriptor(AtomicString("b-b"), AtomicString("div")));
  EXPECT_NE(nullptr, definition) << "b-b, div should be registered";
  EXPECT_EQ(definition_b, definition);
  // look up undefined customized built-in element
  definition = Registry().DefinitionFor(
      CustomElementDescriptor(AtomicString("a-a"), AtomicString("div")));
  EXPECT_EQ(nullptr, definition) << "a-a, div should not be registered";
}

// The embedder may define its own elements via the CustomElementRegistry
// whose names are not valid custom element names. Ensure that such a definition
// may be done.
TEST_F(CustomElementRegistryTest, DefineEmbedderCustomElements) {
  CustomElementTestingScope testing_scope;
  CustomElement::AddEmbedderCustomElementName(
      AtomicString("embeddercustomelement"));

  WebCustomElement::EmbedderNamesAllowedScope embedder_names_scope;

  NonThrowableExceptionState should_not_throw;
  TestCustomElementDefinitionBuilder builder;
  CustomElementDefinition* definition_embedder =
      Define("embeddercustomelement", builder,
             ElementDefinitionOptions::Create(), should_not_throw);
  CustomElementDefinition* definition = Registry().DefinitionFor(
      CustomElementDescriptor(AtomicString("embeddercustomelement"),
                              AtomicString("embeddercustomelement")));
  EXPECT_NE(nullptr, definition)
      << "embeddercustomelement, embeddercustomelement should be registered";
  EXPECT_EQ(definition_embedder, definition);
}

// Ensure that even when the embedder has declared that an invalid name may
// be used for a custom element definition, the caller of |define| may disallow
// the use of the invalid name (so that we don't expose the ability to use such
// a name to the web).
TEST_F(CustomElementRegistryTest, DisallowedEmbedderCustomElements) {
  CustomElementTestingScope testing_scope;
  CustomElement::AddEmbedderCustomElementName(
      AtomicString("embeddercustomelement"));

  // Without a WebCustomElement::EmbedderNamesAllowedScope, this registration
  // is disallowed.

  TestCustomElementDefinitionBuilder builder;
  CustomElementDefinition* definition_embedder =
      Define("embeddercustomelement", builder,
             ElementDefinitionOptions::Create(), IGNORE_EXCEPTION_FOR_TESTING);
  CustomElementDefinition* definition = Registry().DefinitionFor(
      CustomElementDescriptor(AtomicString("embeddercustomelement"),
                              AtomicString("embeddercustomelement")));
  EXPECT_EQ(nullptr, definition) << "embeddercustomelement, "
                                    "embeddercustomelement should not be "
                                    "registered";
  EXPECT_EQ(definition_embedder, definition);
}

// TODO(dominicc): Add tests which adjust the "is" attribute when type
// extensions are implemented.

}  // namespace blink

"""

```