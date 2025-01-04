Response:
My thinking process to analyze the `generated_code_helper.cc` file and answer the prompt goes through these steps:

1. **Understand the Context:** The prompt explicitly states this is a Chromium Blink engine source file in the `blink/renderer/bindings/core/v8/` directory. This immediately tells me it's related to the interaction between JavaScript and the Blink rendering engine, specifically using the V8 JavaScript engine. The "generated_code_helper" part suggests it provides utility functions for code generated automatically from WebIDL definitions.

2. **Initial Scan for Key Functionality:** I'd quickly scan the code for major sections and keywords. I see namespaces (`blink`, anonymous), includes of other Blink headers (related to DOM, HTML, CSS indirectly through DOM), and a lot of functions. Keywords like "callback", "exception", "promise", "template", "enum", "attribute", "iterator", and "CEReactions" stand out.

3. **Categorize Functionality:** Based on the initial scan, I would start grouping the functionalities.

    * **Callback Handling:**  The `IsCallbackFunctionRunnable` functions clearly deal with determining if a JavaScript callback can be executed, considering factors like paused execution contexts.
    * **Promise Rejection:** `ExceptionToRejectPromiseScope` handles converting exceptions to rejected promises, bridging native exceptions to JavaScript promise rejections.
    * **IDL Interface Setup:** The `SetupIDL...Template` functions are crucial. They are responsible for setting up the V8 templates (structures in V8 that represent JavaScript classes and objects) for different kinds of WebIDL constructs (interfaces, namespaces, callbacks, iterators). This is the core of the generated code helper.
    * **Enum Handling:** `FindIndexInEnumStringTable` and `ReportInvalidEnumSetToAttribute` handle the conversion and validation of string-based enum values between JavaScript and native code.
    * **Iterable Detection:** `IsEsIterableObject` checks if a JavaScript object is iterable, essential for handling collections in JavaScript.
    * **Context Conversion:** `ToDocumentFromExecutionContext`, `ExecutionContextFromV8Wrappable` convert between different Blink context objects.
    * **Legacy Factory Functions:** `CreateLegacyFactoryFunctionFunction` seems to deal with creating JavaScript functions that act as factories for certain objects.
    * **Unscopable Properties:** `InstallUnscopablePropertyNames` relates to controlling which properties are accessible within `with` statements in JavaScript (a deprecated feature).
    * **Indexed Properties:** `EnumerateIndexedProperties` helps in representing indexed properties of JavaScript objects.
    * **Attribute Setting with Custom Element Reactions:**  The `PerformAttributeSetCEReactionsReflect...` family of functions handles setting attributes on DOM elements, triggering custom element lifecycle callbacks.
    * **WebDX Feature Counting:** `CountWebDXFeature` is for internal Chromium usage tracking.

4. **Explain Functionality in Plain Language:**  Once I have categorized the functions, I would explain the purpose of each category in simple terms, focusing on what problem it solves or what task it performs. For example, instead of saying "`SetupIDLInterfaceTemplate` sets up the V8 template...", I'd say "This function is responsible for creating the underlying V8 representation of a JavaScript class defined in WebIDL, allowing JavaScript to interact with the native C++ implementation."

5. **Relate to JavaScript, HTML, CSS:** This is where I connect the functionality to web development concepts.

    * **JavaScript:**  Most of the file directly deals with JavaScript interaction. The IDL template setup, callback handling, promise rejection, and iterable checks are all about how JavaScript code interacts with the browser's internal objects.
    * **HTML:** The attribute setting functions (`PerformAttributeSetCEReactionsReflect...`) are directly related to HTML attributes on elements. The functions involving `Document` and `Element` also tie into the HTML DOM structure.
    * **CSS:** While not directly manipulating CSS properties, the functionality is essential for JavaScript APIs that *do* interact with CSS. For example, getting or setting the `style` attribute of an element, or using APIs like `getComputedStyle`. The generated code using these helpers makes those JavaScript-to-native calls possible.

6. **Provide Examples:**  Concrete examples are crucial for understanding. I would think of common web development tasks that involve the concepts mentioned:

    * **Event Listeners:** Connect `IsCallbackFunctionRunnable` to event handlers.
    * **Promises:**  Relate `ExceptionToRejectPromiseScope` to asynchronous operations and error handling.
    * **DOM Manipulation:**  Show how setting an attribute in JavaScript uses the CEReactions functions.
    * **Enums:**  Give examples of HTML attributes or JavaScript API arguments that use enums.

7. **Logical Reasoning (Assumptions and Outputs):** For functions like `IsCallbackFunctionRunnable`, I'd consider the inputs (script states) and the output (a boolean). I'd make explicit the assumptions about the state of the execution context (paused or not).

8. **Common Usage Errors:** I would consider what mistakes developers might make that would lead to these helper functions being involved or where these helpers prevent errors. Examples include setting invalid enum values, trying to call methods on destroyed objects (leading to checks in callback execution), or unexpected exceptions in promise resolution.

9. **Debugging Scenario:**  The debugging scenario requires thinking backward from the code. How would a developer end up looking at this file during debugging?  It's likely related to issues with JavaScript-to-native communication, exceptions being thrown in native code but not correctly reflected in JavaScript promises, or problems with event handlers not firing. I'd construct a step-by-step scenario that leads to investigating this area of the code.

10. **Structure and Clarity:** Finally, I'd organize the information logically with clear headings and bullet points to make it easy to read and understand. I'd use terminology that is accessible to developers familiar with web development concepts.

Essentially, I'm dissecting the code, understanding its purpose within the larger Blink architecture, and then bridging the gap to the world of web development to explain its relevance and potential points of interaction and error. The "generated_code_helper" part is key – it's not the code that *implements* specific web features, but the infrastructure that *enables* those features to be exposed to JavaScript.

这个文件 `blink/renderer/bindings/core/v8/generated_code_helper.cc` 在 Chromium 的 Blink 渲染引擎中扮演着关键的辅助角色，它的主要功能是提供一系列的实用工具函数，用于简化和统一将 WebIDL 定义的接口绑定到 V8 JavaScript 引擎的过程。由于这些接口最终暴露给 JavaScript，所以它与 JavaScript、HTML 和 CSS 的功能都有着密切的联系。

**主要功能列举:**

1. **判断 JavaScript 回调函数是否可执行:**
   - `IsCallbackFunctionRunnable` 和 `IsCallbackFunctionRunnableIgnoringPause`: 这两个函数用于判断一个 JavaScript 回调函数是否可以被安全地执行。它们会检查回调函数相关的执行上下文是否有效、是否被销毁、是否被暂停等状态。
   - **与 JavaScript 的关系:** 当浏览器需要执行一个由 JavaScript 注册的回调函数（例如事件监听器）时，会使用这些函数来确保执行环境的合法性。

2. **将异常转换为 Promise 的拒绝:**
   - `ExceptionToRejectPromiseScope::ConvertExceptionToRejectPromise`:  当原生 C++ 代码中发生异常，并且需要在 JavaScript 中以 Promise 被拒绝的形式处理时，这个函数可以将 C++ 的异常转换为一个被拒绝的 JavaScript Promise。
   - **与 JavaScript 的关系:** 这确保了异步操作中的错误可以被 JavaScript 的 Promise 机制捕获和处理，例如 `fetch` API。

3. **设置 IDL 接口模板:**
   - `SetupIDLInterfaceTemplate`, `SetupIDLNamespaceTemplate`, `SetupIDLCallbackInterfaceTemplate`, `SetupIDLObservableArrayBackingListTemplate`, `SetupIDLIteratorTemplate`: 这些函数负责设置 V8 的模板，用于表示不同类型的 WebIDL 定义的接口、命名空间、回调接口、可观察数组、迭代器等。它们定义了这些对象在 JavaScript 中的结构和行为。
   - **与 JavaScript、HTML、CSS 的关系:** WebIDL 定义了浏览器提供的各种 API，包括 DOM 接口 (与 HTML 元素交互)、BOM 接口 (如 `window` 对象)、CSSOM 接口 (操作 CSS 样式) 等。这些模板的设置使得 JavaScript 可以访问和操作这些底层的 C++ 对象。

4. **处理枚举类型:**
   - `FindIndexInEnumStringTable`: 在给定的字符串枚举值表中查找指定值的索引。
   - `ReportInvalidEnumSetToAttribute`: 当尝试将一个无效的枚举值设置给属性时，发出警告信息到控制台。
   - **与 JavaScript、HTML 的关系:** 许多 HTML 属性和 JavaScript API 参数使用枚举类型 (例如，`<input type="...">` 的 `type` 属性)。这些函数确保了枚举值的正确性和提供了错误提示。

5. **判断对象是否为可迭代对象:**
   - `IsEsIterableObject`: 检查一个 JavaScript 值是否为 ES6 的可迭代对象。
   - **与 JavaScript 的关系:** 这用于验证传递给某些 API 的参数是否支持迭代，例如 `for...of` 循环的参数。

6. **在执行上下文中获取 Document 对象:**
   - `ToDocumentFromExecutionContext`: 从给定的执行上下文中获取关联的 `Document` 对象。
   - **与 JavaScript、HTML 的关系:**  `Document` 对象是访问和操作 HTML 内容的核心入口，这个函数允许在绑定代码中方便地获取它。

7. **从 V8 可包裹对象中获取执行上下文:**
   - `ExecutionContextFromV8Wrappable`:  从实现了 V8 可包裹接口的对象（例如 `Range`, `DOMParser`）获取其关联的执行上下文。
   - **与 JavaScript、HTML 的关系:**  这允许在处理特定的 DOM 对象时，获取其相关的执行环境信息。

8. **创建遗留工厂函数:**
   - `CreateLegacyFactoryFunctionFunction`:  为特定的 C++ 回调函数创建 JavaScript 工厂函数。
   - **与 JavaScript 的关系:**  用于创建一些特定的全局函数或对象构造器。

9. **安装不可枚举的属性名:**
   - `InstallUnscopablePropertyNames`:  为接口原型对象安装不可枚举的属性名，用于控制 `with` 语句的作用域。
   - **与 JavaScript 的关系:**  `with` 语句在 JavaScript 中被认为是不良实践，这个函数用于管理其作用域内的属性访问。

10. **枚举索引属性:**
    - `EnumerateIndexedProperties`:  创建一个包含指定长度的索引的 JavaScript 数组。
    - **与 JavaScript 的关系:**  用于支持对具有数字索引属性的对象进行枚举。

11. **执行带有自定义元素反应的属性设置:**
    - `PerformAttributeSetCEReactionsReflect...`:  用于设置 HTML 元素的属性，并触发自定义元素的生命周期回调 (Custom Element Reactions)。
    - **与 JavaScript、HTML 的关系:** 当通过 JavaScript 设置 HTML 元素的属性时，这些函数确保了自定义元素能够正确地响应这些变化。

12. **统计 WebDX 特性使用情况:**
    - `CountWebDXFeature`: 用于统计内部的 WebDX 特性的使用情况。
    - **与 JavaScript、HTML、CSS 的关系:** 间接地，任何通过 JavaScript API 暴露的 WebDX 特性都可能涉及到这个函数。

**与 JavaScript, HTML, CSS 的关系举例:**

* **JavaScript 事件监听器:** 当 JavaScript 代码使用 `addEventListener` 注册一个事件监听器时，当事件触发时，Blink 引擎会调用 `IsCallbackFunctionRunnable` 来确保当前的执行上下文可以安全地执行该监听器函数。
    ```javascript
    document.getElementById('myButton').addEventListener('click', function() {
      console.log('Button clicked!');
    });
    ```

* **Promise 错误处理:**  假设一个 JavaScript 的 `fetch` 请求失败了，底层的网络代码可能会抛出一个异常。`ExceptionToRejectPromiseScope::ConvertExceptionToRejectPromise` 会将这个异常转换为一个被拒绝的 Promise，以便 JavaScript 代码可以使用 `.catch()` 方法来处理错误。
    ```javascript
    fetch('invalid-url').catch(error => {
      console.error('Fetch error:', error);
    });
    ```

* **设置 HTML 元素属性:** 当 JavaScript 代码设置一个 HTML 元素的属性时，例如 `element.className = 'active'`, 可能会调用 `PerformAttributeSetCEReactionsReflectTypeString` 来执行实际的属性设置，并触发自定义元素的 `attributeChangedCallback` (如果元素是自定义元素)。
    ```javascript
    const div = document.createElement('div');
    div.className = 'my-class'; // 可能会用到 generated_code_helper.cc 中的函数
    ```

* **使用枚举类型的 API:** 考虑 `<input type="range">`，当你尝试通过 JavaScript 设置 `type` 属性为一个无效的值时，`FindIndexInEnumStringTable` 可能会被用来验证输入，如果无效，`ReportInvalidEnumSetToAttribute` 可能会在控制台输出警告。
    ```javascript
    const input = document.createElement('input');
    input.type = 'invalid-type'; // 可能会触发枚举值验证相关的逻辑
    ```

**逻辑推理 (假设输入与输出):**

假设我们调用 `IsCallbackFunctionRunnable` 函数，它接收两个 `ScriptState` 指针作为输入：`callback_relevant_script_state` 和 `incumbent_script_state`。

* **假设输入 1:**
    * `callback_relevant_script_state`: 指向一个有效的、未暂停的执行上下文。
    * `incumbent_script_state`: 指向当前正在执行脚本的有效、未暂停的执行上下文。
* **预期输出 1:** `true` (回调函数可以执行)。

* **假设输入 2:**
    * `callback_relevant_script_state`: 指向一个有效的、**已暂停**的执行上下文。
    * `incumbent_script_state`: 指向当前正在执行脚本的有效、未暂停的执行上下文。
* **预期输出 2:** `false` (回调函数通常不能在暂停的上下文中执行，除非使用 `IsCallbackFunctionRunnableIgnoringPause`)。

**用户或编程常见的使用错误:**

1. **设置无效的枚举值:**  开发者可能会尝试将一个不在 WebIDL 定义的枚举值范围内的字符串赋值给一个属性。例如，将 `<input>` 元素的 `type` 属性设置为一个不存在的类型。这会导致 `FindIndexInEnumStringTable` 返回空，并且 `ReportInvalidEnumSetToAttribute` 会发出警告。

2. **在错误的上下文中操作对象:**  如果开发者尝试在一个已经销毁或者暂停的执行上下文中调用方法或访问属性，可能会导致程序崩溃或者产生不可预测的行为。`IsCallbackFunctionRunnable` 等函数旨在防止这种情况发生。

3. **忘记处理 Promise 的拒绝:**  如果原生代码通过 `ExceptionToRejectPromiseScope` 将异常转换为 Promise 的拒绝，但 JavaScript 代码没有使用 `.catch()` 或 `try...catch` 来处理这个拒绝，可能会导致未处理的 Promise 拒绝错误。

**用户操作如何一步步到达这里作为调试线索:**

假设用户在网页上点击了一个按钮，这个按钮绑定了一个 JavaScript 事件监听器，并且这个监听器尝试访问一个自定义元素的属性。在调试过程中，开发者可能会遇到以下情况，并最终查看 `generated_code_helper.cc` 文件：

1. **用户操作:** 用户点击了页面上的一个按钮。
2. **事件触发:** 浏览器接收到点击事件，并开始执行与该按钮关联的 JavaScript 事件监听器。
3. **回调执行检查:** 在执行监听器代码之前，Blink 引擎可能会调用 `IsCallbackFunctionRunnable` 来确保执行上下文是有效的。
4. **访问自定义元素属性:** 监听器代码尝试访问或修改一个自定义元素的属性。
5. **属性设置:** 如果涉及到属性设置，可能会调用 `PerformAttributeSetCEReactionsReflect...` 函数，这会触发自定义元素的生命周期回调。
6. **异常发生 (假设):**  在自定义元素的生命周期回调中，由于某种原因 (例如，依赖的资源未加载)，原生 C++ 代码抛出了一个异常。
7. **Promise 拒绝 (假设):** 如果这个操作是在一个 Promise 链中，`ExceptionToRejectPromiseScope::ConvertExceptionToRejectPromise` 可能会被用来将这个原生异常转换为一个被拒绝的 Promise。
8. **调试:** 开发者在浏览器的开发者工具中看到一个未处理的 Promise 拒绝错误，或者在调试器中步进执行 JavaScript 代码时，发现错误源于与原生代码的交互。
9. **查看 Blink 源代码:** 为了理解 Promise 拒绝的来源，或者为了查看属性设置是如何触发自定义元素回调的，开发者可能会查看 Blink 引擎的源代码，最终可能会定位到 `generated_code_helper.cc`，因为它涉及到 JavaScript 和原生 C++ 代码之间的桥梁，以及 Promise 和异常处理的关键部分。

总而言之，`generated_code_helper.cc` 是 Blink 引擎中一个幕后的英雄，它提供了基础设施，使得 JavaScript 和底层的渲染引擎能够安全、高效地交互，从而驱动着现代 Web 应用的各种功能。 开发者通常不会直接调用这个文件中的函数，但当涉及到 JavaScript 和原生代码之间的交互、错误处理、以及 WebIDL 定义的 API 的使用时，这个文件中的逻辑就会发挥作用。

Prompt: 
```
这是目录为blink/renderer/bindings/core/v8/generated_code_helper.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/bindings/core/v8/generated_code_helper.h"

#include "third_party/blink/renderer/bindings/core/v8/capture_source_location.h"
#include "third_party/blink/renderer/bindings/core/v8/native_value_traits_impl.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_dom_exception.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_element.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_set_return_value_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_throw_dom_exception.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/range.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/html/custom/ce_reactions_scope.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/xml/dom_parser.h"
#include "third_party/blink/renderer/platform/bindings/v8_binding.h"
#include "third_party/blink/renderer/platform/bindings/v8_per_context_data.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

namespace blink {

namespace {

enum class IgnorePause { kDontIgnore, kIgnore };

// 'beforeunload' event listeners are runnable even when execution contexts are
// paused. Use |RespectPause::kPrioritizeOverPause| in such a case.
bool IsCallbackFunctionRunnableInternal(
    const ScriptState* callback_relevant_script_state,
    const ScriptState* incumbent_script_state,
    IgnorePause ignore_pause) {
  if (!callback_relevant_script_state->ContextIsValid())
    return false;
  const ExecutionContext* relevant_execution_context =
      ExecutionContext::From(callback_relevant_script_state);
  if (!relevant_execution_context ||
      relevant_execution_context->IsContextDestroyed()) {
    return false;
  }
  if (relevant_execution_context->IsContextPaused()) {
    if (ignore_pause == IgnorePause::kDontIgnore)
      return false;
  }

  // TODO(yukishiino): Callback function type value must make the incumbent
  // environment alive, i.e. the reference to v8::Context must be strong.
  v8::HandleScope handle_scope(incumbent_script_state->GetIsolate());
  v8::Local<v8::Context> incumbent_context =
      incumbent_script_state->GetContext();
  ExecutionContext* incumbent_execution_context =
      incumbent_context.IsEmpty() ? nullptr
                                  : ToExecutionContext(incumbent_context);
  // The incumbent realm schedules the currently-running callback although it
  // may not correspond to the currently-running function object. So we check
  // the incumbent context which originally schedules the currently-running
  // callback to see whether the script setting is disabled before invoking
  // the callback.
  // TODO(crbug.com/608641): move IsMainWorld check into
  // ExecutionContext::CanExecuteScripts()
  if (!incumbent_execution_context ||
      incumbent_execution_context->IsContextDestroyed()) {
    return false;
  }
  if (incumbent_execution_context->IsContextPaused()) {
    if (ignore_pause == IgnorePause::kDontIgnore)
      return false;
  }
  return !incumbent_script_state->World().IsMainWorld() ||
         incumbent_execution_context->CanExecuteScripts(kAboutToExecuteScript);
}

}  // namespace

bool IsCallbackFunctionRunnable(
    const ScriptState* callback_relevant_script_state,
    const ScriptState* incumbent_script_state) {
  return IsCallbackFunctionRunnableInternal(callback_relevant_script_state,
                                            incumbent_script_state,
                                            IgnorePause::kDontIgnore);
}

bool IsCallbackFunctionRunnableIgnoringPause(
    const ScriptState* callback_relevant_script_state,
    const ScriptState* incumbent_script_state) {
  return IsCallbackFunctionRunnableInternal(callback_relevant_script_state,
                                            incumbent_script_state,
                                            IgnorePause::kIgnore);
}

void ExceptionToRejectPromiseScope::ConvertExceptionToRejectPromise() {
  // As exceptions must always be created in the current realm, reject
  // promises must also be created in the current realm while regular promises
  // are created in the relevant realm of the context object.
  //
  // We don't know the type of the promise here - but given that we're only
  // going to extract the v8::Value and discard the ScriptPromise, it
  // doesn't matter what type we use.
  bindings::V8SetReturnValue(
      info_, ScriptPromise<IDLUndefined>::Reject(
                 ScriptState::ForCurrentRealm(info_), try_catch_.Exception()));
}

namespace bindings {

void SetupIDLInterfaceTemplate(
    v8::Isolate* isolate,
    const WrapperTypeInfo* wrapper_type_info,
    v8::Local<v8::ObjectTemplate> instance_template,
    v8::Local<v8::ObjectTemplate> prototype_template,
    v8::Local<v8::FunctionTemplate> interface_template,
    v8::Local<v8::FunctionTemplate> parent_interface_template) {
  v8::Local<v8::String> class_string =
      V8AtomicString(isolate, wrapper_type_info->interface_name);

  if (!parent_interface_template.IsEmpty())
    interface_template->Inherit(parent_interface_template);
  interface_template->ReadOnlyPrototype();
  interface_template->SetClassName(class_string);

  prototype_template->Set(
      v8::Symbol::GetToStringTag(isolate), class_string,
      static_cast<v8::PropertyAttribute>(v8::ReadOnly | v8::DontEnum));
}

void SetupIDLNamespaceTemplate(
    v8::Isolate* isolate,
    const WrapperTypeInfo* wrapper_type_info,
    v8::Local<v8::ObjectTemplate> interface_template) {
  v8::Local<v8::String> class_string =
      V8AtomicString(isolate, wrapper_type_info->interface_name);

  interface_template->Set(
      v8::Symbol::GetToStringTag(isolate), class_string,
      static_cast<v8::PropertyAttribute>(v8::ReadOnly | v8::DontEnum));
}

void SetupIDLCallbackInterfaceTemplate(
    v8::Isolate* isolate,
    const WrapperTypeInfo* wrapper_type_info,
    v8::Local<v8::FunctionTemplate> interface_template) {
  interface_template->RemovePrototype();
  interface_template->SetClassName(
      V8AtomicString(isolate, wrapper_type_info->interface_name));
}

void SetupIDLObservableArrayBackingListTemplate(
    v8::Isolate* isolate,
    const WrapperTypeInfo* wrapper_type_info,
    v8::Local<v8::ObjectTemplate> instance_template,
    v8::Local<v8::FunctionTemplate> interface_template) {
  interface_template->SetClassName(
      V8AtomicString(isolate, wrapper_type_info->interface_name));
}

void SetupIDLIteratorTemplate(
    v8::Isolate* isolate,
    const WrapperTypeInfo* wrapper_type_info,
    v8::Local<v8::ObjectTemplate> instance_template,
    v8::Local<v8::ObjectTemplate> prototype_template,
    v8::Local<v8::FunctionTemplate> interface_template,
    v8::Intrinsic parent_intrinsic_prototype,
    const char* class_string) {
  DCHECK(parent_intrinsic_prototype == v8::Intrinsic::kAsyncIteratorPrototype ||
         parent_intrinsic_prototype == v8::Intrinsic::kIteratorPrototype ||
         parent_intrinsic_prototype == v8::Intrinsic::kMapIteratorPrototype ||
         parent_intrinsic_prototype == v8::Intrinsic::kSetIteratorPrototype);

  v8::Local<v8::String> v8_class_string = V8String(isolate, class_string);

  // https://webidl.spec.whatwg.org/#es-asynchronous-iterator-prototype-object
  // https://webidl.spec.whatwg.org/#es-iterator-prototype-object
  // https://webidl.spec.whatwg.org/#es-map-iterator
  // https://webidl.spec.whatwg.org/#es-set-iterator
  v8::Local<v8::FunctionTemplate>
      intrinsic_iterator_prototype_interface_template =
          v8::FunctionTemplate::New(isolate, nullptr, v8::Local<v8::Value>(),
                                    v8::Local<v8::Signature>(), 0,
                                    v8::ConstructorBehavior::kThrow);
  // It's not clear whether we need to remove the existing prototype object
  // before we replace it with another object. Despite that the following test
  // in V8 removes the existing one before setting a new one with a comment,
  // it's not yet crystal clear if RemovePrototype() is mandatory or not.
  // https://source.chromium.org/chromium/chromium/src/+/main:v8/test/cctest/test-api.cc;l=25249;drc=00a341994fa5cc0b41ffa0e886eeef67fce0c804
  intrinsic_iterator_prototype_interface_template->RemovePrototype();
  intrinsic_iterator_prototype_interface_template->SetIntrinsicDataProperty(
      V8AtomicString(isolate, "prototype"), parent_intrinsic_prototype);
  interface_template->Inherit(intrinsic_iterator_prototype_interface_template);

  interface_template->ReadOnlyPrototype();
  interface_template->SetClassName(v8_class_string);

  prototype_template->Set(
      v8::Symbol::GetToStringTag(isolate), v8_class_string,
      static_cast<v8::PropertyAttribute>(v8::ReadOnly | v8::DontEnum));
}

std::optional<size_t> FindIndexInEnumStringTable(
    v8::Isolate* isolate,
    v8::Local<v8::Value> value,
    base::span<const char* const> enum_value_table,
    const char* enum_type_name,
    ExceptionState& exception_state) {
  auto adapter = NativeValueTraits<IDLString>::NativeValue(isolate, value,
                                                           exception_state);
  const StringView& str_value = adapter;
  if (exception_state.HadException()) [[unlikely]] {
    return std::nullopt;
  }

  std::optional<size_t> index =
      FindIndexInEnumStringTable(str_value, enum_value_table);

  if (!index.has_value()) [[unlikely]] {
    exception_state.ThrowTypeError("The provided value '" + str_value +
                                   "' is not a valid enum value of type " +
                                   enum_type_name + ".");
  }
  return index;
}

std::optional<size_t> FindIndexInEnumStringTable(
    const StringView& str_value,
    base::span<const char* const> enum_value_table) {
  for (size_t i = 0; i < enum_value_table.size(); ++i) {
    // Avoid operator== because of the strlen inside a StringView construction.
    if (WTF::EqualToCString(str_value, enum_value_table[i])) {
      return i;
    }
  }
  return std::nullopt;
}

void ReportInvalidEnumSetToAttribute(v8::Isolate* isolate,
                                     const String& value,
                                     const String& enum_type_name,
                                     ExceptionState& exception_state) {
  ScriptState* script_state = ScriptState::ForCurrentRealm(isolate);
  ExecutionContext* execution_context = ExecutionContext::From(script_state);

  String message = "The provided value '" + value +
                   "' is not a valid enum value of type " + enum_type_name +
                   ".";

  execution_context->AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
      mojom::blink::ConsoleMessageSource::kJavaScript,
      mojom::blink::ConsoleMessageLevel::kWarning, message,
      CaptureSourceLocation(execution_context)));
}

bool IsEsIterableObject(v8::Isolate* isolate,
                        v8::Local<v8::Value> value,
                        ExceptionState& exception_state) {
  // https://webidl.spec.whatwg.org/#es-overloads
  // step 9. Otherwise: if Type(V) is Object and ...
  if (!value->IsObject())
    return false;

  // step 9.1. Let method be ? GetMethod(V, @@iterator).
  // https://tc39.es/ecma262/#sec-getmethod
  TryRethrowScope rethrow_scope(isolate, exception_state);
  v8::Local<v8::Value> iterator_key = v8::Symbol::GetIterator(isolate);
  v8::Local<v8::Value> iterator_value;
  if (!value.As<v8::Object>()
           ->Get(isolate->GetCurrentContext(), iterator_key)
           .ToLocal(&iterator_value)) {
    return false;
  }

  if (iterator_value->IsNullOrUndefined())
    return false;

  if (!iterator_value->IsFunction()) {
    exception_state.ThrowTypeError("@@iterator must be a function");
    return false;
  }

  return true;
}

Document* ToDocumentFromExecutionContext(ExecutionContext* execution_context) {
  return DynamicTo<LocalDOMWindow>(execution_context)->document();
}

ExecutionContext* ExecutionContextFromV8Wrappable(const Range* range) {
  return range->startContainer()->GetExecutionContext();
}

ExecutionContext* ExecutionContextFromV8Wrappable(const DOMParser* parser) {
  return parser->GetWindow();
}

v8::MaybeLocal<v8::Value> CreateLegacyFactoryFunctionFunction(
    ScriptState* script_state,
    v8::FunctionCallback callback,
    const char* func_name,
    int func_length,
    const WrapperTypeInfo* wrapper_type_info) {
  v8::Isolate* isolate = script_state->GetIsolate();
  const DOMWrapperWorld& world = script_state->World();
  V8PerIsolateData* per_isolate_data = V8PerIsolateData::From(isolate);
  const void* callback_key = reinterpret_cast<const void*>(callback);

  if (!script_state->ContextIsValid()) {
    return v8::Undefined(isolate);
  }

  v8::Local<v8::FunctionTemplate> function_template =
      per_isolate_data->FindV8Template(world, callback_key)
          .As<v8::FunctionTemplate>();
  if (function_template.IsEmpty()) {
    function_template = v8::FunctionTemplate::New(
        isolate, callback, v8::Local<v8::Value>(), v8::Local<v8::Signature>(),
        func_length, v8::ConstructorBehavior::kAllow,
        v8::SideEffectType::kHasSideEffect);
    v8::Local<v8::FunctionTemplate> interface_template =
        wrapper_type_info->GetV8ClassTemplate(isolate, world)
            .As<v8::FunctionTemplate>();
    function_template->Inherit(interface_template);
    function_template->SetClassName(V8AtomicString(isolate, func_name));
    function_template->SetExceptionContext(v8::ExceptionContext::kConstructor);
    per_isolate_data->AddV8Template(world, callback_key, function_template);
  }

  v8::Local<v8::Context> context = script_state->GetContext();
  V8PerContextData* per_context_data = script_state->PerContextData();
  v8::Local<v8::Function> function;
  if (!function_template->GetFunction(context).ToLocal(&function)) {
    return v8::MaybeLocal<v8::Value>();
  }
  v8::Local<v8::Object> prototype_object =
      per_context_data->PrototypeForType(wrapper_type_info);
  bool did_define;
  if (!function
           ->DefineOwnProperty(
               context, V8AtomicString(isolate, "prototype"), prototype_object,
               static_cast<v8::PropertyAttribute>(v8::ReadOnly | v8::DontEnum |
                                                  v8::DontDelete))
           .To(&did_define)) {
    return v8::MaybeLocal<v8::Value>();
  }
  CHECK(did_define);
  return function;
}

void InstallUnscopablePropertyNames(
    v8::Isolate* isolate,
    v8::Local<v8::Context> context,
    v8::Local<v8::Object> prototype_object,
    base::span<const char* const> property_name_table) {
  // 3.6.3. Interface prototype object
  // https://webidl.spec.whatwg.org/#interface-prototype-object
  // step 8. If interface has any member declared with the [Unscopable]
  //   extended attribute, then:
  // step 8.1. Let unscopableObject be the result of performing
  //   ! ObjectCreate(null).
  v8::Local<v8::Object> unscopable_object =
      v8::Object::New(isolate, v8::Null(isolate), nullptr, nullptr, 0);
  for (const char* const property_name : property_name_table) {
    // step 8.2.2. Perform ! CreateDataProperty(unscopableObject, id, true).
    unscopable_object
        ->CreateDataProperty(context, V8AtomicString(isolate, property_name),
                             v8::True(isolate))
        .ToChecked();
  }
  // step 8.3. Let desc be the PropertyDescriptor{[[Value]]: unscopableObject,
  //   [[Writable]]: false, [[Enumerable]]: false, [[Configurable]]: true}.
  // step 8.4. Perform ! DefinePropertyOrThrow(interfaceProtoObj,
  //   @@unscopables, desc).
  prototype_object
      ->DefineOwnProperty(
          context, v8::Symbol::GetUnscopables(isolate), unscopable_object,
          static_cast<v8::PropertyAttribute>(v8::ReadOnly | v8::DontEnum))
      .ToChecked();
}

v8::Local<v8::Array> EnumerateIndexedProperties(v8::Isolate* isolate,
                                                uint32_t length) {
  v8::LocalVector<v8::Value> elements(isolate);
  elements.reserve(length);
  for (uint32_t i = 0; i < length; ++i)
    elements.push_back(v8::Integer::New(isolate, i));
  return v8::Array::New(isolate, elements.data(), elements.size());
}

template <typename IDLType,
          typename ArgType,
          void (Element::*MemFunc)(const QualifiedName&, ArgType)>
void PerformAttributeSetCEReactionsReflect(
    const v8::FunctionCallbackInfo<v8::Value>& info,
    const QualifiedName& content_attribute,
    const char* interface_name,
    const char* attribute_name) {
  v8::Isolate* isolate = info.GetIsolate();
  ExceptionState exception_state(isolate, v8::ExceptionContext::kAttributeSet,
                                 interface_name, attribute_name);
  if (info.Length() < 1) [[unlikely]] {
    exception_state.ThrowTypeError(
        ExceptionMessages::NotEnoughArguments(1, info.Length()));
    return;
  }

  CEReactionsScope ce_reactions_scope;

  Element* blink_receiver = V8Element::ToWrappableUnsafe(isolate, info.This());
  auto&& arg_value = NativeValueTraits<IDLType>::NativeValue(isolate, info[0],
                                                             exception_state);
  if (exception_state.HadException()) [[unlikely]] {
    return;
  }

  (blink_receiver->*MemFunc)(content_attribute, arg_value);
}

void PerformAttributeSetCEReactionsReflectTypeBoolean(
    const v8::FunctionCallbackInfo<v8::Value>& info,
    const QualifiedName& content_attribute,
    const char* interface_name,
    const char* attribute_name) {
  PerformAttributeSetCEReactionsReflect<IDLBoolean, bool,
                                        &Element::SetBooleanAttribute>(
      info, content_attribute, interface_name, attribute_name);
}

void PerformAttributeSetCEReactionsReflectTypeString(
    const v8::FunctionCallbackInfo<v8::Value>& info,
    const QualifiedName& content_attribute,
    const char* interface_name,
    const char* attribute_name) {
  PerformAttributeSetCEReactionsReflect<IDLString, const AtomicString&,
                                        &Element::setAttribute>(
      info, content_attribute, interface_name, attribute_name);
}

void PerformAttributeSetCEReactionsReflectTypeStringLegacyNullToEmptyString(
    const v8::FunctionCallbackInfo<v8::Value>& info,
    const QualifiedName& content_attribute,
    const char* interface_name,
    const char* attribute_name) {
  PerformAttributeSetCEReactionsReflect<IDLStringLegacyNullToEmptyString,
                                        const AtomicString&,
                                        &Element::setAttribute>(
      info, content_attribute, interface_name, attribute_name);
}

void PerformAttributeSetCEReactionsReflectTypeStringOrNull(
    const v8::FunctionCallbackInfo<v8::Value>& info,
    const QualifiedName& content_attribute,
    const char* interface_name,
    const char* attribute_name) {
  PerformAttributeSetCEReactionsReflect<
      IDLNullable<IDLString>, const AtomicString&, &Element::setAttribute>(
      info, content_attribute, interface_name, attribute_name);
}

CORE_EXPORT void CountWebDXFeature(v8::Isolate* isolate, WebDXFeature feature) {
  v8::Local<v8::Context> current_context = isolate->GetCurrentContext();
  ScriptState* current_script_state =
      ScriptState::From(isolate, current_context);
  ExecutionContext* current_execution_context =
      ToExecutionContext(current_script_state);
  UseCounter::CountWebDXFeature(current_execution_context, feature);
}

}  // namespace bindings

}  // namespace blink

"""

```