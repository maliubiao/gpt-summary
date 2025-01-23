Response:
Let's break down the thought process for analyzing the `script_custom_element_definition.cc` file.

1. **Understand the Goal:** The primary goal is to understand the functionality of this specific source code file within the Chromium Blink engine, particularly its role in defining custom elements. The prompt also asks about its relationship to web technologies (JavaScript, HTML, CSS), logic inference, common errors, and debugging.

2. **Initial Scan and Keywords:**  Start by quickly scanning the file for recognizable keywords and structures.
    * `#include`: Immediately suggests dependencies on other files, pointing towards related functionalities. Note the included files like `v8_custom_element_*`, `v8_element.h`, `document.h`, `custom_element.h`, etc. These give strong hints about the file's purpose.
    * `namespace blink`:  Confirms this is part of the Blink rendering engine.
    * `ScriptCustomElementDefinition`: This is the core class. Pay close attention to its members and methods.
    * Constructor:  The constructor takes a `ScriptCustomElementDefinitionData` and a `CustomElementDescriptor`. This implies it's initialized with data about the custom element.
    * Methods with names like `RunConnectedCallback`, `RunDisconnectedCallback`, `RunAttributeChangedCallback`, etc.: These strongly suggest event handling related to the custom element lifecycle.
    * `CreateAutonomousCustomElementSync`: Indicates synchronous creation of custom elements.
    * `RunConstructor`: Deals with the JavaScript constructor of the custom element.
    * `FormAssociationFlag`: Hints at custom elements being associated with HTML forms.

3. **Deconstruct the Class `ScriptCustomElementDefinition`:**  Focus on the member variables and methods.

    * **Member Variables:**  Notice the prevalence of function pointers or similar representations (e.g., `constructor_`, `connected_callback_`). These store references to JavaScript functions that define the behavior of the custom element. The `script_state_` is crucial for interacting with the V8 JavaScript engine. `CustomElementDefinition` in the inheritance list indicates this class extends a base class for custom element definitions.

    * **Constructor:** Understand how the class is initialized. It takes data and a descriptor, storing information like observed attributes, disabled features, and whether the element is form-associated.

    * **`CreateAutonomousCustomElementSync`:**  This function seems to handle the creation of the custom element instance when the tag is encountered in the HTML. The "Sync" suggests it happens during the initial parsing. The steps within the function clearly mirror the custom element creation process as defined in the HTML specification.

    * **`RunConstructor`:** This method is responsible for executing the JavaScript constructor associated with the custom element. It includes error handling for exceptions thrown during construction and checks if the constructor returns the correct object.

    * **`CallConstructor`:** This is a helper function that actually invokes the JavaScript constructor using the V8 API.

    * **`Run*Callback` methods:** These methods are the heart of the custom element lifecycle. They invoke the corresponding JavaScript callbacks (e.g., `connectedCallback`, `disconnectedCallback`) at the appropriate times.

4. **Relate to Web Technologies (JavaScript, HTML, CSS):**

    * **JavaScript:**  The file heavily interacts with V8, Chrome's JavaScript engine. The `constructor_`, `connected_callback_`, etc., directly correspond to JavaScript methods defined in the custom element class. The file is responsible for calling these JavaScript functions.
    * **HTML:** The file is involved in how the browser interprets and creates instances of custom elements declared in HTML. The `CreateAutonomousCustomElementSync` function is directly tied to encountering a custom element tag in the HTML.
    * **CSS:** While this specific file doesn't directly *process* CSS, custom elements can influence styling through their JavaScript logic (e.g., adding/removing classes, manipulating the shadow DOM). The existence of a shadow DOM (mentioned in the `RunConstructor` method's check) directly relates to CSS encapsulation.

5. **Logic Inference:**  Consider scenarios and how the code would behave.

    * **Assumption:** A developer registers a custom element named `<my-element>` with a constructor and a `connectedCallback`.
    * **Input:** The browser encounters `<my-element></my-element>` in the HTML.
    * **Output:** `CreateAutonomousCustomElementSync` would be called to create the element, and later, when the element is attached to the DOM, `RunConnectedCallback` would execute the JavaScript `connectedCallback` function.

6. **Common Errors:** Think about what could go wrong from a developer's perspective.

    * **Constructor not calling `super()`:** The `RunConstructor` method explicitly checks for this.
    * **Constructor returning a different object:**  Again, `RunConstructor` checks for this.
    * **Incorrect callback signatures:**  While not directly handled in this file, the binding layer (which this file is a part of) ensures the correct number and type of arguments are passed to the JavaScript callbacks.

7. **Debugging Scenario:**  Imagine a developer reporting that their custom element's `connectedCallback` isn't being called. How might they arrive at this file during debugging?

    * They'd likely start in the JavaScript code of their custom element.
    * Using browser developer tools, they might set breakpoints in their `connectedCallback`.
    * If the breakpoint isn't hit, they might suspect the element isn't being properly created or connected.
    * They might then investigate the custom element registration process or the element's lifecycle.
    * By searching through the Chromium source code or looking at call stacks in debugging tools, they could potentially trace the execution flow back to `ScriptCustomElementDefinition::RunConnectedCallback`.

8. **Structure and Refine:** Organize the findings into clear sections as requested by the prompt. Use code examples and clear explanations. Ensure that the explanations are accessible to someone who might not be intimately familiar with the Chromium source code. Use the provided code snippets to illustrate the points.

9. **Review and Iterate:** Read through the generated explanation to ensure accuracy and clarity. Are there any ambiguities?  Is the language precise?  Could anything be explained more simply? For instance, initially, I might have focused too much on the V8 API specifics. Refining the explanation to focus on the *purpose* of these interactions, rather than the low-level details, makes it more understandable.
好的，让我们来分析一下 `blink/renderer/bindings/core/v8/script_custom_element_definition.cc` 这个文件。

**文件功能概述**

这个文件 `script_custom_element_definition.cc` 的核心功能是**定义和管理由 JavaScript 代码创建的自定义元素（Custom Elements）**在 Blink 渲染引擎中的表示和行为。它桥接了 JavaScript 代码中定义的自定义元素类和 Blink 引擎的内部表示，使得引擎能够正确地创建、管理和执行自定义元素的生命周期回调函数。

具体来说，这个文件做了以下几件事：

1. **存储自定义元素的定义信息：**  `ScriptCustomElementDefinition` 类存储了从 JavaScript 传递过来的关于自定义元素的各种信息，例如构造函数、生命周期回调函数（connectedCallback, disconnectedCallback, adoptedCallback, attributeChangedCallback 等）、观察的属性以及其他配置信息。

2. **创建自定义元素实例：** 当浏览器遇到 HTML 中定义的自定义元素标签时，这个文件中的代码负责创建相应的 `HTMLElement` 实例，并将其与之前注册的 JavaScript 自定义元素定义关联起来。

3. **执行自定义元素的生命周期回调：**  当自定义元素的状态发生变化时（例如被添加到 DOM、从 DOM 移除、属性被修改等），这个文件中的代码负责调用相应的 JavaScript 生命周期回调函数。

4. **处理与表单相关的自定义元素：** 如果自定义元素关联了表单行为（`formAssociated`），这个文件还负责管理与表单相关的回调函数，例如 `formAssociatedCallback`，`formResetCallback`，`formDisabledCallback`，`formStateRestoreCallback`。

5. **处理同步自定义元素的创建：** 文件中包含了 `CreateAutonomousCustomElementSync` 方法，用于处理在 HTML 解析过程中同步创建的自定义元素。

**与 JavaScript, HTML, CSS 的关系及举例说明**

这个文件是连接 JavaScript 和 HTML 的关键桥梁，对于 CSS 的影响是间接的，主要体现在自定义元素可能操作 DOM 结构和属性，从而影响 CSS 样式。

* **JavaScript:**
    * **功能关系：**  自定义元素的定义完全在 JavaScript 中完成，包括构造函数和各种生命周期回调函数。这个文件负责将 JavaScript 中定义的这些函数调用到 Blink 引擎中。
    * **举例说明：**
        ```javascript
        // JavaScript 中定义一个自定义元素
        class MyElement extends HTMLElement {
          constructor() {
            super();
            this.innerHTML = '<span>Hello from my-element!</span>';
          }

          connectedCallback() {
            console.log('my-element is connected to the DOM');
          }

          attributeChangedCallback(name, oldValue, newValue) {
            console.log(`Attribute ${name} changed from ${oldValue} to ${newValue}`);
          }

          static get observedAttributes() {
            return ['data-name'];
          }
        }

        customElements.define('my-element', MyElement);
        ```
        `ScriptCustomElementDefinition` 对象会存储 `MyElement` 类的构造函数和 `connectedCallback`、`attributeChangedCallback` 的引用。当 `<my-element>` 被添加到 DOM 时，`RunConnectedCallback` 会被调用，从而执行 JavaScript 中的 `connectedCallback` 函数。当 `data-name` 属性改变时，`RunAttributeChangedCallback` 会被调用，执行 JavaScript 中的 `attributeChangedCallback` 函数。

* **HTML:**
    * **功能关系：** HTML 中使用自定义元素的标签名，浏览器会根据已注册的自定义元素定义来创建相应的元素实例。
    * **举例说明：**
        ```html
        <!-- HTML 中使用自定义元素 -->
        <my-element data-name="World"></my-element>
        ```
        当浏览器解析到 `<my-element>` 标签时，会查找名为 `my-element` 的自定义元素定义，并调用 `ScriptCustomElementDefinition::CreateAutonomousCustomElementSync` 或相关的函数来创建 `MyElement` 的实例。

* **CSS:**
    * **功能关系：**  自定义元素可以通过 JavaScript 操作自身的 Shadow DOM 或直接修改自身属性，从而影响 CSS 样式。此外，自定义元素本身也可以被 CSS 选择器选中并设置样式。
    * **举例说明：**
        ```javascript
        class MyStyledElement extends HTMLElement {
          constructor() {
            super();
            this.attachShadow({ mode: 'open' });
            this.shadowRoot.innerHTML = `
              <style>
                .container {
                  background-color: lightblue;
                  padding: 10px;
                }
              </style>
              <div class="container">I'm a styled custom element.</div>
            `;
          }
        }
        customElements.define('my-styled-element', MyStyledElement);
        ```
        在这个例子中，JavaScript 代码在自定义元素的 Shadow DOM 中定义了 CSS 样式。`ScriptCustomElementDefinition` 本身不直接处理 CSS，但它创建的自定义元素实例可以包含和应用 CSS。

**逻辑推理及假设输入与输出**

假设我们有一个已注册的自定义元素 `<fancy-button>`，其定义如下：

* **假设输入：**
    1. JavaScript 代码注册了名为 `fancy-button` 的自定义元素，并定义了 `connectedCallback` 函数，该函数会在元素添加到 DOM 时在控制台打印 "Fancy button connected!"。
    2. HTML 中添加了 `<fancy-button>` 元素到文档中。
* **逻辑推理：**
    1. 浏览器解析 HTML，遇到 `<fancy-button>`。
    2. Blink 引擎查找与 `fancy-button` 关联的 `ScriptCustomElementDefinition` 对象。
    3. `ScriptCustomElementDefinition::CreateAutonomousCustomElementSync` 或相关方法被调用以创建元素实例。
    4. 当元素被真正添加到 DOM 树时，Blink 引擎会调用 `ScriptCustomElementDefinition::RunConnectedCallback`。
    5. `RunConnectedCallback` 会执行 JavaScript 中定义的 `fancy-button` 的 `connectedCallback` 函数。
* **预期输出：**
    控制台会输出 "Fancy button connected!"。

**用户或编程常见的使用错误及举例说明**

1. **构造函数没有调用 `super()`：**
   * **错误代码：**
     ```javascript
     class MyBadElement extends HTMLElement {
       constructor() {
         // 忘记调用 super();
         this.innerHTML = 'Oops!';
       }
     }
     customElements.define('my-bad-element', MyBadElement);
     ```
   * **说明：** 自定义元素的构造函数必须首先调用 `super()` 来初始化父类 `HTMLElement` 的状态。如果忘记调用，会导致运行时错误。`ScriptCustomElementDefinition::RunConstructor` 中会进行检查，如果构造函数返回的对象不是期望的，则会抛出错误。

2. **生命周期回调函数名拼写错误：**
   * **错误代码：**
     ```javascript
     class MyMistakeElement extends HTMLElement {
       connectedСallback() { // 注意，这里是西里尔字母 'С' 而不是拉丁字母 'C'
         console.log('This will not be called correctly.');
       }
     }
     customElements.define('my-mistake-element', MyMistakeElement);
     ```
   * **说明：** 如果生命周期回调函数名拼写错误，Blink 引擎无法识别这些回调，因此它们不会被调用。虽然 `script_custom_element_definition.cc` 不直接检查拼写错误，但由于对应的函数指针为空，`RunConnectedCallback` 等方法会直接返回，不会执行任何操作。

3. **在构造函数中进行 DOM 操作不安全：**
   * **错误代码：**
     ```javascript
     class MyRiskyElement extends HTMLElement {
       constructor() {
         super();
         this.querySelector('div'); // 此时元素可能还未完全构建或连接
       }
     }
     customElements.define('my-risky-element', MyRiskyElement);
     ```
   * **说明：** 在构造函数中进行依赖于元素在 DOM 树中的操作是不安全的，因为元素可能尚未连接到文档。推荐在 `connectedCallback` 中执行此类操作。

**用户操作如何一步步到达这里，作为调试线索**

假设用户发现自定义元素的 `connectedCallback` 没有被调用，他们进行调试的步骤可能如下：

1. **用户在 HTML 中添加了自定义元素标签：** 这是触发自定义元素创建的起点。
2. **浏览器解析 HTML：**  解析器遇到自定义元素标签。
3. **Blink 引擎查找自定义元素定义：**  浏览器尝试找到与该标签名对应的已注册的 `ScriptCustomElementDefinition` 对象。
4. **创建自定义元素实例：**  如果找到定义，`ScriptCustomElementDefinition::CreateAutonomousCustomElementSync` 或类似方法会被调用。
5. **元素被添加到 DOM 树：** 当元素被插入到文档中时，Blink 引擎会触发 `connectedCallback` 生命周期回调。
6. **`ScriptCustomElementDefinition::RunConnectedCallback` 被调用：** 这个文件中的代码负责执行 JavaScript 中定义的 `connectedCallback` 函数。

**调试线索：**

* **检查自定义元素是否已正确注册：** 用户应该首先确认他们的 JavaScript 代码中是否使用了 `customElements.define()` 正确地注册了自定义元素。
* **检查标签名是否匹配：** HTML 中的标签名必须与注册时使用的名称完全一致。
* **在 `connectedCallback` 中设置断点：** 用户可以在他们的 JavaScript `connectedCallback` 函数中设置断点，查看该函数是否被执行。如果没有被执行，可能意味着元素没有被正确地连接到 DOM，或者定义本身有问题。
* **查看浏览器的开发者工具的 "Elements" 面板：** 确认自定义元素是否真的被添加到 DOM 中。
* **搜索错误消息：**  浏览器控制台可能会输出与自定义元素相关的错误信息，例如构造函数错误或类型错误。
* **逐步调试 Blink 引擎代码：** 对于更深入的调试，开发者可能需要下载 Chromium 源代码，并在 `blink/renderer/bindings/core/v8/script_custom_element_definition.cc` 文件中相关的 `RunConnectedCallback` 函数处设置断点，查看执行流程以及相关的变量状态，以找出回调函数没有被调用的原因。这通常是高级开发者或 Blink 引擎贡献者才会进行的操作。

总而言之，`script_custom_element_definition.cc` 文件在 Blink 引擎中扮演着至关重要的角色，它负责将 JavaScript 中定义的自定义元素桥接到浏览器的渲染机制中，并管理其生命周期。理解这个文件的功能有助于我们更好地理解自定义元素的工作原理以及如何进行调试。

### 提示词
```
这是目录为blink/renderer/bindings/core/v8/script_custom_element_definition.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/bindings/core/v8/script_custom_element_definition.h"

#include "third_party/blink/renderer/bindings/core/v8/script_custom_element_definition_data.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_custom_element_adopted_callback.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_custom_element_attribute_changed_callback.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_custom_element_constructor.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_custom_element_form_associated_callback.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_custom_element_form_disabled_callback.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_custom_element_form_state_restore_callback.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_element.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_form_state_restore_mode.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_function.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_script_runner.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_throw_dom_exception.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_void_function.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/events/error_event.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/html/custom/custom_element.h"
#include "third_party/blink/renderer/core/html/custom/custom_element_registry.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/platform/bindings/v8_throw_exception.h"

namespace blink {

ScriptCustomElementDefinition::ScriptCustomElementDefinition(
    const ScriptCustomElementDefinitionData& data,
    const CustomElementDescriptor& descriptor)
    : CustomElementDefinition(*data.registry_,
                              descriptor,
                              std::move(data.observed_attributes_),
                              data.disabled_features_,
                              data.is_form_associated_
                                  ? FormAssociationFlag::kYes
                                  : FormAssociationFlag::kNo),
      script_state_(data.script_state_),
      constructor_(data.constructor_),
      connected_callback_(data.connected_callback_),
      disconnected_callback_(data.disconnected_callback_),
      connected_move_callback_(data.connected_move_callback_),
      adopted_callback_(data.adopted_callback_),
      attribute_changed_callback_(data.attribute_changed_callback_),
      form_associated_callback_(data.form_associated_callback_),
      form_reset_callback_(data.form_reset_callback_),
      form_disabled_callback_(data.form_disabled_callback_),
      form_state_restore_callback_(data.form_state_restore_callback_) {
  DCHECK(data.registry_);
}

void ScriptCustomElementDefinition::Trace(Visitor* visitor) const {
  visitor->Trace(script_state_);
  visitor->Trace(constructor_);
  visitor->Trace(connected_callback_);
  visitor->Trace(disconnected_callback_);
  visitor->Trace(connected_move_callback_);
  visitor->Trace(adopted_callback_);
  visitor->Trace(attribute_changed_callback_);
  visitor->Trace(form_associated_callback_);
  visitor->Trace(form_reset_callback_);
  visitor->Trace(form_disabled_callback_);
  visitor->Trace(form_state_restore_callback_);
  CustomElementDefinition::Trace(visitor);
}

HTMLElement* ScriptCustomElementDefinition::CreateAutonomousCustomElementSync(
    Document& document,
    const QualifiedName& tag_name) {
  DCHECK(CustomElement::ShouldCreateCustomElement(tag_name)) << tag_name;
  if (!script_state_->ContextIsValid())
    return CustomElement::CreateFailedElement(document, tag_name);
  ScriptState::Scope scope(script_state_);
  v8::Isolate* isolate = script_state_->GetIsolate();
  v8::TryCatch try_catch(isolate);

  // Create an element with the synchronous custom elements flag set.
  // https://dom.spec.whatwg.org/#concept-create-element

  // TODO(dominicc): Implement step 5 which constructs customized
  // built-in elements.

  Element* element = nullptr;
  {
    element = CallConstructor();
    if (try_catch.HasCaught()) {
      // 6.1."If any of these subsubsteps threw an exception".1
      // Report the exception.
      V8ScriptRunner::ReportException(isolate, try_catch.Exception());
      // ... .2 Return HTMLUnknownElement.
      return CustomElement::CreateFailedElement(document, tag_name);
    }
  }

  // 6.1.3. through 6.1.9.
  CheckConstructorResult(element, document, tag_name,
                         PassThroughException(isolate));
  if (try_catch.HasCaught()) {
    // 6.1."If any of these subsubsteps threw an exception".1
    // Report the exception.
    V8ScriptRunner::ReportException(isolate, try_catch.Exception());
    // ... .2 Return HTMLUnknownElement.
    return CustomElement::CreateFailedElement(document, tag_name);
  }
  // 6.1.10. Set result’s namespace prefix to prefix.
  if (element->prefix() != tag_name.Prefix())
    element->SetTagNameForCreateElementNS(tag_name);
  DCHECK_EQ(element->GetCustomElementState(), CustomElementState::kCustom);
  return To<HTMLElement>(element);
}

// https://html.spec.whatwg.org/C/#upgrades
bool ScriptCustomElementDefinition::RunConstructor(Element& element) {
  if (!script_state_->ContextIsValid())
    return false;
  ScriptState::Scope scope(script_state_);
  v8::Isolate* isolate = script_state_->GetIsolate();

  // Step 5 says to rethrow the exception; but there is no one to
  // catch it. The side effect is to report the error.
  v8::TryCatch try_catch(isolate);
  try_catch.SetVerbose(true);

  if (DisableShadow() && element.GetShadowRoot()) {
    v8::Local<v8::Value> exception = V8ThrowDOMException::CreateOrEmpty(
        script_state_->GetIsolate(), DOMExceptionCode::kNotSupportedError,
        "The element already has a ShadowRoot though it is disabled by "
        "disabledFeatures static field.");
    if (!exception.IsEmpty())
      V8ScriptRunner::ReportException(isolate, exception);
    return false;
  }

  // 8.1.new: set custom element state to kPreCustomized.
  element.SetCustomElementState(CustomElementState::kPreCustomized);

  Element* result = CallConstructor();

  // To report exception thrown from callConstructor()
  if (try_catch.HasCaught())
    return false;

  // Report a TypeError Exception if the constructor returns a different object.
  if (result != &element) {
    const String& message =
        "custom element constructors must call super() first and must "
        "not return a different object";
    v8::Local<v8::Value> exception =
        V8ThrowException::CreateTypeError(script_state_->GetIsolate(), message);
    if (!exception.IsEmpty())
      V8ScriptRunner::ReportException(isolate, exception);
    return false;
  }

  return true;
}

Element* ScriptCustomElementDefinition::CallConstructor() {
  ScriptValue result;
  if (!constructor_->Construct().To(&result)) {
    return nullptr;
  }

  return V8Element::ToWrappable(constructor_->GetIsolate(), result.V8Value());
}

v8::Local<v8::Object> ScriptCustomElementDefinition::Constructor() const {
  return constructor_->CallbackObject();
}

// CustomElementDefinition
ScriptValue ScriptCustomElementDefinition::GetConstructorForScript() {
  return ScriptValue(script_state_->GetIsolate(), Constructor());
}

bool ScriptCustomElementDefinition::HasConnectedCallback() const {
  return connected_callback_ != nullptr;
}

bool ScriptCustomElementDefinition::HasDisconnectedCallback() const {
  return disconnected_callback_ != nullptr;
}

bool ScriptCustomElementDefinition::HasConnectedMoveCallback() const {
  return connected_move_callback_ != nullptr;
}

bool ScriptCustomElementDefinition::HasAdoptedCallback() const {
  return adopted_callback_ != nullptr;
}

bool ScriptCustomElementDefinition::HasFormAssociatedCallback() const {
  return form_associated_callback_ != nullptr;
}

bool ScriptCustomElementDefinition::HasFormResetCallback() const {
  return form_reset_callback_ != nullptr;
}

bool ScriptCustomElementDefinition::HasFormDisabledCallback() const {
  return form_disabled_callback_ != nullptr;
}

bool ScriptCustomElementDefinition::HasFormStateRestoreCallback() const {
  return form_state_restore_callback_ != nullptr;
}

void ScriptCustomElementDefinition::RunConnectedCallback(Element& element) {
  if (!connected_callback_)
    return;

  connected_callback_->InvokeAndReportException(&element);
}

void ScriptCustomElementDefinition::RunDisconnectedCallback(Element& element) {
  if (!disconnected_callback_)
    return;

  disconnected_callback_->InvokeAndReportException(&element);
}

void ScriptCustomElementDefinition::RunConnectedMoveCallback(Element& element) {
  if (!connected_move_callback_) {
    return;
  }

  connected_move_callback_->InvokeAndReportException(&element);
}

void ScriptCustomElementDefinition::RunAdoptedCallback(Element& element,
                                                       Document& old_owner,
                                                       Document& new_owner) {
  if (!adopted_callback_)
    return;

  adopted_callback_->InvokeAndReportException(&element, &old_owner, &new_owner);
}

void ScriptCustomElementDefinition::RunAttributeChangedCallback(
    Element& element,
    const QualifiedName& name,
    const AtomicString& old_value,
    const AtomicString& new_value) {
  if (!attribute_changed_callback_)
    return;

  attribute_changed_callback_->InvokeAndReportException(
      &element, name.LocalName(), old_value, new_value, name.NamespaceURI());
}

void ScriptCustomElementDefinition::RunFormAssociatedCallback(
    Element& element,
    HTMLFormElement* nullable_form) {
  if (!form_associated_callback_)
    return;
  form_associated_callback_->InvokeAndReportException(&element, nullable_form);
}

void ScriptCustomElementDefinition::RunFormResetCallback(Element& element) {
  if (!form_reset_callback_)
    return;
  form_reset_callback_->InvokeAndReportException(&element);
}

void ScriptCustomElementDefinition::RunFormDisabledCallback(Element& element,
                                                            bool is_disabled) {
  if (!form_disabled_callback_)
    return;
  form_disabled_callback_->InvokeAndReportException(&element, is_disabled);
}

void ScriptCustomElementDefinition::RunFormStateRestoreCallback(
    Element& element,
    const V8ControlValue* value,
    const String& mode) {
  if (!form_state_restore_callback_)
    return;
  form_state_restore_callback_->InvokeAndReportException(
      &element, value, V8FormStateRestoreMode::Create(mode).value());
}

}  // namespace blink
```