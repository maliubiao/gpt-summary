Response:
Let's break down the thought process to generate the detailed explanation of `custom_element_registry.cc`.

1. **Understand the Core Purpose:** The file name itself gives a strong clue: `custom_element_registry`. This immediately suggests it's responsible for managing the registration and lookup of custom elements within the Blink rendering engine.

2. **Identify Key Data Structures:**  Scan the code for important data members. We see:
    * `constructor_map_`:  Likely maps JavaScript constructors to their definitions.
    * `name_map_`: Maps custom element names to their definitions.
    * `upgrade_candidates_`:  Stores elements that *might* be custom elements but haven't been fully upgraded yet.
    * `when_defined_promise_map_`: Handles the `whenDefined()` promise for custom elements.
    * `associated_documents_`: Tracks which documents this registry is associated with.

3. **Analyze Key Functions:** Go through the prominent functions and their roles:
    * `Create()`:  Obvious factory function for creating instances.
    * `define()`/`DefineInternal()`:  The core registration logic for custom elements. Pay attention to the steps involved (name validation, checking for duplicates, handling `extends`, setting the `element_definition_is_running_` flag,  collecting upgrade candidates, and resolving the `whenDefined` promise).
    * `get()`:  Retrieves the constructor for a given custom element name.
    * `getName()`:  Retrieves the name for a given constructor.
    * `DefinitionFor()`:  Looks up a definition based on a descriptor (name and `is` attribute).
    * `NameIsDefined()`:  Checks if a name is already registered.
    * `DefinitionForName()`/`DefinitionForConstructor()`:  Helper lookup functions.
    * `AddCandidate()`:  Registers an element as a potential custom element for later upgrade.
    * `whenDefined()`: Implements the `whenDefined()` promise.
    * `CollectCandidates()`:  Gathers and sorts elements that need to be upgraded.
    * `upgrade()`:  Forces the upgrade of elements within a given subtree.
    * `AssociatedWith()`: Links the registry to a document.

4. **Connect to Web Standards (HTML, JavaScript):**  Recognize that this code directly implements the Custom Elements specification. Think about how the JavaScript API (`customElements.define()`, `customElements.get()`, `customElements.whenDefined()`) maps to the C++ code. Consider how custom elements are declared in HTML and how the browser needs to identify and upgrade them.

5. **Illustrate with Examples:** Concrete examples make the explanation much clearer. For each key function or concept, create simple JavaScript/HTML snippets that demonstrate its usage and how it relates to the C++ code. For instance, showing how `customElements.define('my-element', MyElement)` triggers the `define()` function.

6. **Consider Potential Errors:** Think about common mistakes developers might make when working with custom elements, and how this C++ code helps prevent or handle them. Examples include:
    * Invalid custom element names.
    * Redefining custom elements.
    * Trying to define custom elements while another definition is in progress.
    * Using `extends` incorrectly.

7. **Trace User Interaction (Optional but Helpful):** Try to follow the steps a user might take that eventually lead to this code being executed. For example:  a user loads a webpage -> the HTML parser encounters a potential custom element tag -> Blink checks the registry -> if not registered, adds it as a candidate -> when `customElements.define()` is called, the candidate is upgraded.

8. **Structure and Clarity:** Organize the information logically. Start with a high-level overview, then delve into specific functionalities. Use clear and concise language, and avoid jargon where possible. Use headings and bullet points to improve readability.

9. **Refine and Iterate:** Review the explanation for accuracy and completeness. Are there any gaps in the explanation?  Are the examples clear and correct? Could the explanation be more concise?

**Self-Correction/Refinement during the process:**

* **Initial Thought:**  Maybe just list the functions and a brief description.
* **Correction:**  Realized a more detailed explanation of *why* these functions exist and how they relate to the web standards would be much more helpful. The examples are crucial for understanding.
* **Initial Thought:** Focus heavily on the C++ implementation details.
* **Correction:** Shifted the focus to the *functionality* from a user's perspective and then connect it to the underlying C++ implementation. The relationship with JavaScript/HTML is paramount.
* **Initial Thought:**  Provide very technical details about memory management and Blink internals.
* **Correction:** While acknowledging the C++ nature, focused on the logical flow and the purpose of the code within the larger context of web development. Avoided unnecessary low-level details.

By following these steps and incorporating self-correction, the resulting explanation becomes comprehensive, understandable, and directly relevant to someone trying to understand the role of `custom_element_registry.cc`.
这个文件 `blink/renderer/core/html/custom/custom_element_registry.cc` 是 Chromium Blink 渲染引擎中负责 **自定义元素注册和管理** 的核心组件。 它实现了 Web 标准中定义的 `CustomElementRegistry` 接口，使得 JavaScript 能够定义和管理自定义 HTML 元素。

以下是它的主要功能：

**1. 自定义元素的注册 (Registration):**

* **`define(ScriptState* script_state, const AtomicString& name, V8CustomElementConstructor* constructor, const ElementDefinitionOptions* options, ExceptionState& exception_state)` 和 `DefineInternal(...)`:**  这两个函数是注册自定义元素的核心。
    * **输入 (假设):**
        * `name`:  自定义元素的标签名，例如 "my-element"。
        * `constructor`:  一个 JavaScript 类 (构造函数)，当该自定义元素被创建时，它的实例将被创建。
        * `options`:  一个可选的对象，可以指定 `extends` 属性，用于创建内置元素扩展的自定义元素。
    * **输出 (假设):**
        * 如果注册成功，返回一个 `CustomElementDefinition` 对象，包含自定义元素的定义信息。
        * 如果注册失败 (例如，名称无效、已注册等)，会抛出 JavaScript 异常。
    * **功能:**
        * 验证自定义元素名称的有效性。
        * 检查该名称是否已经被注册。
        * 存储自定义元素的定义 (包含构造函数、生命周期回调等)。
        * 处理 `extends` 选项，创建内置元素扩展的自定义元素。
        * 触发对页面中已存在的但尚未升级为自定义元素的元素的升级过程。

* **与 JavaScript 的关系:**  JavaScript 代码通过 `customElements.define('my-element', MyElement)` 调用到这个 C++ 代码的 `define` 函数。  `MyElement` 就是传入的 `constructor`。

* **与 HTML 的关系:**  当 HTML 解析器遇到一个未知的标签，并且该标签名在 `CustomElementRegistry` 中注册过，那么该标签会被识别为一个自定义元素。

* **与 CSS 的关系:** CSS 可以像操作普通 HTML 元素一样操作自定义元素，例如使用标签名选择器 `my-element { ... }`。

**2. 查询自定义元素的定义 (Lookup):**

* **`get(const AtomicString& name)`:**  根据自定义元素的名称获取其构造函数。
    * **输入 (假设):**  自定义元素的名称，例如 "my-element"。
    * **输出 (假设):**
        * 如果已注册，返回对应的 JavaScript 构造函数。
        * 如果未注册，返回 `undefined`。
    * **功能:**  允许 JavaScript 查询已经注册的自定义元素的构造函数。

* **`getName(V8CustomElementConstructor* constructor)`:**  根据自定义元素的构造函数获取其注册的名称。
    * **输入 (假设):**  自定义元素的 JavaScript 构造函数。
    * **输出 (假设):**
        * 如果已注册，返回对应的自定义元素名称。
        * 如果未注册，返回空字符串。

* **`DefinitionFor(const CustomElementDescriptor& desc)` 和 `DefinitionForName(const AtomicString& name)` 和 `DefinitionForConstructor(...)`:**  这些函数在内部用于根据不同的标识 (名称、构造函数) 查找 `CustomElementDefinition` 对象。

* **与 JavaScript 的关系:** JavaScript 代码通过 `customElements.get('my-element')` 调用到这个 C++ 代码的 `get` 函数。

**3. 处理自定义元素的升级 (Upgrading):**

* **`AddCandidate(Element& candidate)`:**  当解析器遇到潜在的自定义元素标签时，会将其添加到待升级的候选列表中。这通常发生在 `customElements.define()` 调用之前。
    * **输入 (假设):**  一个 `Element` 对象，可能是自定义元素。
    * **输出 (假设):**  无。
    * **功能:**  将潜在的自定义元素加入到等待升级的队列中。

* **`CollectCandidates(const CustomElementDescriptor& desc, HeapVector<Member<Element>>* elements)`:**  当一个自定义元素被注册后，此函数会收集页面中所有匹配该定义的待升级元素。
    * **输入 (假设):**  一个 `CustomElementDescriptor` 对象，描述了要查找的自定义元素。
    * **输出 (假设):**  一个包含匹配的 `Element` 对象的向量。
    * **功能:**  查找并返回所有需要升级为指定自定义元素的元素。

* **`upgrade(Node* root)`:**  强制对给定节点及其子树中的所有候选自定义元素进行升级。
    * **输入 (假设):**  一个 DOM 节点。
    * **输出 (假设):**  无。
    * **功能:**  遍历节点及其子树，尝试将所有标记为未定义的元素升级为已注册的自定义元素。

* **用户操作如何到达这里 (示例):**
    1. 用户在 HTML 文件中使用了自定义元素标签 `<my-element></my-element>`。
    2. 浏览器开始解析 HTML。
    3. 当解析器遇到 `<my-element>` 时，由于该标签不是内置的 HTML 标签，它会被标记为 `kUndefined` 状态的元素，并可能被添加到升级候选列表中 (通过 `AddCandidate`)。
    4. JavaScript 代码执行 `customElements.define('my-element', MyElement)`。
    5. `CustomElementRegistry::define` 函数被调用，注册了 `my-element` 的定义。
    6. `define` 函数内部或之后，会调用 `CollectCandidates` 查找之前添加的 `<my-element>` 元素。
    7. 找到这些元素后，会调用 `CustomElement::TryToUpgrade` 来实例化 `MyElement` 并将其关联到 DOM 元素上。

**4. 处理 `whenDefined` Promise:**

* **`whenDefined(ScriptState* script_state, const AtomicString& name, ExceptionState& exception_state)`:**  返回一个 Promise，该 Promise 在指定的自定义元素被注册后 resolve。
    * **输入 (假设):**  自定义元素的名称，例如 "my-element"。
    * **输出 (假设):**  一个 JavaScript Promise 对象。
    * **功能:**  允许 JavaScript 代码等待某个自定义元素被注册后再执行某些操作。

* **与 JavaScript 的关系:** JavaScript 代码通过 `customElements.whenDefined('my-element').then(...)` 调用到这个 C++ 代码的 `whenDefined` 函数。

**5. 管理关联的文档 (Associated Documents):**

* **`AssociatedWith(Document& document)`:**  记录哪些 `Document` 对象与当前的 `CustomElementRegistry` 关联。这对于处理 Shadow DOM 和 Scoped Custom Element Registries 非常重要。

**常见的使用错误 (举例):**

* **尝试注册无效的自定义元素名称:**  例如，包含大写字母或不是以字母开头的名称 (`customElements.define('MyElement', MyElement)` 会报错，因为名称必须包含连字符)。  `ThrowIfInvalidName` 函数会捕捉这种错误。
    * **假设输入:** `name = "MyElement"`
    * **输出:**  抛出 `DOMExceptionCode::kSyntaxError` 异常。

* **重复注册同一个自定义元素名称:**  在一个 `CustomElementRegistry` 中，同一个名称只能注册一次。
    * **假设输入:**  连续两次调用 `customElements.define('my-element', MyElement)`。
    * **输出:**  第二次调用会抛出 `DOMExceptionCode::kNotSupportedError` 异常。

* **在元素定义正在进行时尝试注册新的自定义元素:**  `element_definition_is_running_` 标志用于防止在定义一个自定义元素的过程中又开始定义另一个，这可能导致循环依赖或其他问题。
    * **假设场景:** 在一个自定义元素的构造函数或生命周期回调中尝试调用 `customElements.define()`。
    * **输出:**  会抛出 `DOMExceptionCode::kNotSupportedError` 异常。

* **尝试扩展一个无效的内置元素:**  在使用 `extends` 选项时，必须指定一个有效的内置 HTML 元素名称。
    * **假设输入:** `customElements.define('my-button', MyButton, { extends: 'non-existent-tag' });`
    * **输出:**  抛出 `DOMExceptionCode::kNotSupportedError` 异常。

**逻辑推理示例:**

* **假设输入:**  HTML 中存在 `<x-foo></x-foo>`，且稍后 JavaScript 执行了 `customElements.define('x-foo', XFooElement)`.
* **推理:**
    1. 当解析器遇到 `<x-foo>` 时，`CustomElementRegistry` 中没有 `x-foo` 的定义。
    2. `<x-foo>` 元素会被标记为 `kUndefined` 并可能被添加到升级候选列表中。
    3. 当 `customElements.define('x-foo', XFooElement)` 被调用时，`DefineInternal` 会被执行。
    4. `CollectCandidates` 会找到之前添加的 `<x-foo>` 元素。
    5. 这些 `<x-foo>` 元素会被升级，它们的内部状态会从 `kUndefined` 变为 `kCustom`，并且会调用 `XFooElement` 的构造函数和 `connectedCallback` 生命周期回调。
* **输出:**  页面中的 `<x-foo></x-foo>` 元素现在具有了 `XFooElement` 的行为。

总而言之，`custom_element_registry.cc` 是 Blink 引擎中实现 Web Components 中 Custom Elements 规范的关键部分，它负责管理自定义元素的注册、查找和升级，连接了 JavaScript、HTML 和 CSS，使得开发者能够创建具有更强语义和可重用性的 Web 组件。

Prompt: 
```
这是目录为blink/renderer/core/html/custom/custom_element_registry.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
如果能说明用户操作是如何一步步的到达这里，就更棒了。

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/html/custom/custom_element_registry.h"

#include <limits>

#include "base/auto_reset.h"
#include "third_party/blink/public/web/web_custom_element.h"
#include "third_party/blink/renderer/bindings/core/v8/script_custom_element_definition_builder.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_element_definition_options.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/element_traversal.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/html/custom/ce_reactions_scope.h"
#include "third_party/blink/renderer/core/html/custom/custom_element.h"
#include "third_party/blink/renderer/core/html/custom/custom_element_definition.h"
#include "third_party/blink/renderer/core/html/custom/custom_element_definition_builder.h"
#include "third_party/blink/renderer/core/html/custom/custom_element_descriptor.h"
#include "third_party/blink/renderer/core/html/custom/custom_element_reaction_stack.h"
#include "third_party/blink/renderer/core/html/custom/custom_element_upgrade_sorter.h"
#include "third_party/blink/renderer/core/html_element_type_helpers.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"

namespace blink {

namespace {

void CollectUpgradeCandidateInNode(Node& root,
                                   HeapVector<Member<Element>>& candidates) {
  if (auto* root_element = DynamicTo<Element>(root)) {
    if (root_element->GetCustomElementState() == CustomElementState::kUndefined)
      candidates.push_back(root_element);
    if (auto* shadow_root = root_element->GetShadowRoot()) {
      if (shadow_root->GetMode() != ShadowRootMode::kUserAgent) {
        CollectUpgradeCandidateInNode(*shadow_root, candidates);
      }
    }
  }
  for (auto& element : Traversal<HTMLElement>::ChildrenOf(root))
    CollectUpgradeCandidateInNode(element, candidates);
}

// Returns true if |name| is invalid.
bool ThrowIfInvalidName(const AtomicString& name,
                        bool allow_embedder_names,
                        ExceptionState& exception_state) {
  if (CustomElement::IsValidName(name, allow_embedder_names))
    return false;
  exception_state.ThrowDOMException(
      DOMExceptionCode::kSyntaxError,
      "\"" + name + "\" is not a valid custom element name");
  return true;
}

// Returns true if |name| is valid.
bool ThrowIfValidName(const AtomicString& name,
                      ExceptionState& exception_state) {
  if (!CustomElement::IsValidName(name, false))
    return false;
  exception_state.ThrowDOMException(
      DOMExceptionCode::kNotSupportedError,
      "\"" + name + "\" is a valid custom element name");
  return true;
}

}  // namespace

// static
CustomElementRegistry* CustomElementRegistry::Create(
    ScriptState* script_state) {
  DCHECK(RuntimeEnabledFeatures::ScopedCustomElementRegistryEnabled());
  return MakeGarbageCollected<CustomElementRegistry>(
      LocalDOMWindow::From(script_state));
}

CustomElementRegistry::CustomElementRegistry(const LocalDOMWindow* owner)
    : element_definition_is_running_(false),
      owner_(owner),
      upgrade_candidates_(MakeGarbageCollected<UpgradeCandidateMap>()),
      associated_documents_(MakeGarbageCollected<AssociatedDocumentSet>()) {}

Vector<AtomicString> CustomElementRegistry::DefinedNames() const {
  Vector<AtomicString> names;
  for (const auto& name : name_map_.Keys()) {
    names.push_back(name);
  }
  return names;
}

void CustomElementRegistry::Trace(Visitor* visitor) const {
  visitor->Trace(constructor_map_);
  visitor->Trace(name_map_);
  visitor->Trace(owner_);
  visitor->Trace(upgrade_candidates_);
  visitor->Trace(when_defined_promise_map_);
  visitor->Trace(associated_documents_);
  ScriptWrappable::Trace(visitor);
}

CustomElementDefinition* CustomElementRegistry::define(
    ScriptState* script_state,
    const AtomicString& name,
    V8CustomElementConstructor* constructor,
    const ElementDefinitionOptions* options,
    ExceptionState& exception_state) {
  ScriptCustomElementDefinitionBuilder builder(script_state, this, constructor,
                                               exception_state);
  return DefineInternal(script_state, name, builder, options, exception_state);
}

// https://html.spec.whatwg.org/C/#element-definition
CustomElementDefinition* CustomElementRegistry::DefineInternal(
    ScriptState* script_state,
    const AtomicString& name,
    CustomElementDefinitionBuilder& builder,
    const ElementDefinitionOptions* options,
    ExceptionState& exception_state) {
  TRACE_EVENT1("blink", "CustomElementRegistry::define", "name", name.Utf8());
  if (!builder.CheckConstructorIntrinsics())
    return nullptr;

  const bool allow_embedder_names =
      WebCustomElement::EmbedderNamesAllowedScope::IsAllowed();
  if (ThrowIfInvalidName(name, allow_embedder_names, exception_state))
    return nullptr;

  if (NameIsDefined(name)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotSupportedError,
        "the name \"" + name + "\" has already been used with this registry");
    return nullptr;
  }

  if (!builder.CheckConstructorNotRegistered())
    return nullptr;

  // Polymer V2/V3 uses Custom Elements V1. <dom-module> is defined in its base
  // library and is a strong signal that this is a Polymer V2+.
  if (name == "dom-module") {
    if (Document* document = owner_->document())
      UseCounter::Count(*document, WebFeature::kPolymerV2Detected);
  }
  AtomicString local_name = name;

  // Step 7. customized built-in elements definition
  // element interface extends option checks
  if (!options->extends().IsNull()) {
    // 7.1. If element interface is valid custom element name, throw exception
    const AtomicString& extends = AtomicString(options->extends());
    if (ThrowIfValidName(AtomicString(options->extends()), exception_state))
      return nullptr;
    // 7.2. If element interface is undefined element, throw exception
    if (HtmlElementTypeForTag(extends, owner_->document()) ==
        HTMLElementType::kHTMLUnknownElement) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kNotSupportedError,
          "\"" + extends + "\" is an HTMLUnknownElement");
      return nullptr;
    }
    // 7.3. Set localName to extends
    local_name = extends;
  }

  // 8. If this CustomElementRegistry's element definition is
  // running flag is set, then throw a "NotSupportedError"
  // DOMException and abort these steps.
  if (element_definition_is_running_) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotSupportedError,
        "an element definition is already being processed");
    return nullptr;
  }

  {
    // 9. Set this CustomElementRegistry's element definition is
    // running flag.
    base::AutoReset<bool> defining(&element_definition_is_running_, true);

    // 10. Run the following substeps while catching any exceptions: ...
    if (!builder.RememberOriginalProperties())
      return nullptr;

    // "Then, perform the following substep, regardless of whether
    // the above steps threw an exception or not: Unset this
    // CustomElementRegistry's element definition is running
    // flag."
    // (|defining|'s destructor does this.)
  }

  // During step 10, property getters might have detached the frame. Abort in
  // the case.
  if (!script_state->ContextIsValid()) {
    // Intentionally do not throw an exception so that, when Blink will support
    // detached frames, the behavioral change whether Blink throws or not will
    // not be observable from author.
    // TODO(yukishiino): Support detached frames.
    return nullptr;
  }

  CustomElementDescriptor descriptor(name, local_name);
  CustomElementDefinition* definition = builder.Build(descriptor);
  CHECK(!exception_state.HadException());
  CHECK(definition->Descriptor() == descriptor);

  auto name_add_result = name_map_.insert(descriptor.GetName(), definition);
  // This CHECK follows from the NameIsDefined call above.
  CHECK(name_add_result.is_new_entry);

  auto constructor_add_result =
      constructor_map_.insert(builder.Constructor(), definition);
  // This CHECK follows from the CheckConstructorNotRegistered call above.
  CHECK(constructor_add_result.is_new_entry);

  if (definition->IsFormAssociated()) {
    if (Document* document = owner_->document())
      UseCounter::Count(*document, WebFeature::kFormAssociatedCustomElement);
  }

  HeapVector<Member<Element>> candidates;
  CollectCandidates(descriptor, &candidates);
  for (Element* candidate : candidates)
    definition->EnqueueUpgradeReaction(*candidate);

  // 16: when-defined promise processing
  const auto& entry = when_defined_promise_map_.find(name);
  if (entry != when_defined_promise_map_.end()) {
    auto* resolver = entry->value.Get();
    when_defined_promise_map_.erase(entry);
    // Resolve() may run synchronous JavaScript that invalidates iterators of
    // |when_defined_promise_map_|, so it must be called after erasing |entry|.
    resolver->Resolve(definition->GetV8CustomElementConstructor());
  }

  return definition;
}

// https://html.spec.whatwg.org/C/#dom-customelementsregistry-get
ScriptValue CustomElementRegistry::get(const AtomicString& name) {
  CustomElementDefinition* definition = DefinitionForName(name);
  if (!definition) {
    // Binding layer converts |ScriptValue()| to script specific value,
    // e.g. |undefined| for v8.
    return ScriptValue();
  }
  return definition->GetConstructorForScript();
}

// https://html.spec.whatwg.org/C/#dom-customelementregistry-getname
const AtomicString& CustomElementRegistry::getName(
    V8CustomElementConstructor* constructor) {
  if (!constructor) {
    return g_null_atom;
  }
  CustomElementDefinition* definition = DefinitionForConstructor(constructor);
  if (!definition) {
    return g_null_atom;
  }
  return definition->Descriptor().GetName();
}

// https://html.spec.whatwg.org/C/#look-up-a-custom-element-definition
// At this point, what the spec calls 'is' is 'name' from desc
CustomElementDefinition* CustomElementRegistry::DefinitionFor(
    const CustomElementDescriptor& desc) const {
  // desc.name() is 'is' attribute
  // 4. If definition in registry with name equal to local name...
  CustomElementDefinition* definition = DefinitionForName(desc.LocalName());
  // 5. If definition in registry with name equal to name...
  if (!definition)
    definition = DefinitionForName(desc.GetName());
  // 4&5. ...and local name equal to localName, return that definition
  if (definition and definition->Descriptor().LocalName() == desc.LocalName()) {
    return definition;
  }
  // 6. Return null
  return nullptr;
}

bool CustomElementRegistry::NameIsDefined(const AtomicString& name) const {
  return name_map_.Contains(name);
}

CustomElementDefinition* CustomElementRegistry::DefinitionForName(
    const AtomicString& name) const {
  const auto it = name_map_.find(name);
  if (it == name_map_.end())
    return nullptr;
  return it->value.Get();
}

CustomElementDefinition* CustomElementRegistry::DefinitionForConstructor(
    V8CustomElementConstructor* constructor) const {
  const auto it = constructor_map_.find(constructor);
  if (it == constructor_map_.end())
    return nullptr;
  return it->value.Get();
}

CustomElementDefinition* CustomElementRegistry::DefinitionForConstructor(
    v8::Local<v8::Object> constructor) const {
  const auto it =
      constructor_map_.Find<V8CustomElementConstructorHashTranslator>(
          constructor);
  if (it == constructor_map_.end())
    return nullptr;
  return it->value.Get();
}

void CustomElementRegistry::AddCandidate(Element& candidate) {
  AtomicString name = candidate.localName();
  if (!CustomElement::IsValidName(name)) {
    const AtomicString& is = candidate.IsValue();
    if (!is.IsNull())
      name = is;
  }
  if (NameIsDefined(name))
    return;
  UpgradeCandidateMap::iterator it = upgrade_candidates_->find(name);
  UpgradeCandidateSet* set;
  if (it != upgrade_candidates_->end()) {
    set = it->value;
  } else {
    set = upgrade_candidates_
              ->insert(name, MakeGarbageCollected<UpgradeCandidateSet>())
              .stored_value->value;
  }
  set->insert(&candidate);
}

// https://html.spec.whatwg.org/C/#dom-customelementsregistry-whendefined
ScriptPromise<V8CustomElementConstructor> CustomElementRegistry::whenDefined(
    ScriptState* script_state,
    const AtomicString& name,
    ExceptionState& exception_state) {
  if (ThrowIfInvalidName(name, false, exception_state))
    return EmptyPromise();
  if (CustomElementDefinition* definition = DefinitionForName(name)) {
    return ToResolvedPromise<V8CustomElementConstructor>(
        script_state, definition->GetV8CustomElementConstructor());
  }
  const auto it = when_defined_promise_map_.find(name);
  if (it != when_defined_promise_map_.end())
    return it->value->Promise();
  auto* new_resolver =
      MakeGarbageCollected<ScriptPromiseResolver<V8CustomElementConstructor>>(
          script_state, exception_state.GetContext());
  when_defined_promise_map_.insert(name, new_resolver);
  return new_resolver->Promise();
}

void CustomElementRegistry::CollectCandidates(
    const CustomElementDescriptor& desc,
    HeapVector<Member<Element>>* elements) {
  UpgradeCandidateMap::iterator it = upgrade_candidates_->find(desc.GetName());
  if (it == upgrade_candidates_->end())
    return;
  CustomElementUpgradeSorter sorter;
  for (Element* element : *it.Get()->value) {
    if (!element || !desc.Matches(*element))
      continue;
    if (RuntimeEnabledFeatures::ScopedCustomElementRegistryEnabled()) {
      if (CustomElement::Registry(*element) != this) {
        // The element has been moved away from the original tree scope and no
        // longer uses this registry.
        continue;
      }
    }
    sorter.Add(element);
  }

  upgrade_candidates_->erase(it);

  for (Document* document : *associated_documents_) {
    if (document && document->GetFrame()) {
      sorter.Sorted(elements, document);
    }
  }
}

// https://html.spec.whatwg.org/C/#dom-customelementregistry-upgrade
void CustomElementRegistry::upgrade(Node* root) {
  DCHECK(root);

  // 1. Let candidates be a list of all of root's shadow-including
  // inclusive descendant elements, in tree order.
  HeapVector<Member<Element>> candidates;
  CollectUpgradeCandidateInNode(*root, candidates);

  // 2. For each candidate of candidates, try to upgrade candidate.
  for (auto& candidate : candidates)
    CustomElement::TryToUpgrade(*candidate);
}

bool CustomElementRegistry::IsGlobalRegistry() const {
  return this == owner_->customElements();
}

void CustomElementRegistry::AssociatedWith(Document& document) {
  associated_documents_->insert(&document);
}

}  // namespace blink

"""

```