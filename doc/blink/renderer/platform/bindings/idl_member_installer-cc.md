Response:
The user wants to understand the functionality of the `idl_member_installer.cc` file in the Chromium Blink engine. I need to analyze the code to identify its purpose and how it interacts with JavaScript, HTML, and CSS. The code heavily utilizes V8 APIs, indicating it's involved in binding C++ code to JavaScript.

**Plan:**

1. **Identify the core purpose:** Based on the file name and the included headers (especially `v8_binding.h`), the file is likely responsible for installing members (properties, methods, constants) of Web IDL interfaces onto JavaScript objects.

2. **Break down the functionality:** Analyze the key functions like `InstallAttribute`, `InstallOperation`, `InstallConstants`, and `InstallExposedConstructs`. Understand what types of members each function handles.

3. **Explain the relation to JavaScript:** Show how the code connects Web IDL definitions (like attributes and operations) to JavaScript properties and methods accessible to web developers.

4. **Explain the relation to HTML and CSS:** While the file itself doesn't directly manipulate HTML or CSS, its functionality enables JavaScript to interact with the DOM, which represents the structure of HTML and styles defined by CSS.

5. **Provide examples:** Illustrate the concepts with simple examples of how JavaScript interacts with HTML elements and their properties, which are set up by this code.

6. **Address common errors:** Think about common JavaScript errors related to accessing properties or calling methods that might be influenced by the setup done by this code (e.g., trying to set a read-only property).

7. **Consider assumptions and outputs:**  For logical parts, imagine an input configuration and the resulting changes to a JavaScript object.
这个文件 `idl_member_installer.cc` 的主要功能是**将 Web IDL (Interface Definition Language) 中定义的接口成员（属性、方法、常量等）安装到 JavaScript 的原型链和接口对象上，使得 JavaScript 代码能够访问和操作这些接口成员**。

简单来说，它负责建立 C++ 实现的 Web API 和 JavaScript 代码之间的桥梁。Web IDL 定义了 Web 平台提供的各种功能，例如 DOM 元素的属性和方法，而这个文件中的代码则负责将这些定义转化为 V8 引擎可以理解和执行的形式，最终让开发者可以通过 JavaScript 来使用这些功能。

以下是对其功能的详细解释，并说明了它与 JavaScript、HTML、CSS 的关系：

**核心功能：将 IDL 定义的成员安装到 JavaScript 对象上**

* **处理不同类型的成员：** 文件中包含了 `InstallAttribute`、`InstallOperation`、`InstallConstants` 和 `InstallExposedConstructs` 等函数，分别用于安装不同类型的 IDL 成员：
    * **属性 (Attributes):**  通过 `InstallAttribute` 安装，对应 JavaScript 对象的属性，可以进行读取（getter）和写入（setter）操作。
    * **操作 (Operations):** 通过 `InstallOperation` 安装，对应 JavaScript 对象的方法，可以被调用执行。
    * **常量 (Constants):** 通过 `InstallConstants` 安装，对应 JavaScript 对象上的只读常量。
    * **暴露的构造器 (Exposed Constructs):** 通过 `InstallExposedConstructs` 安装，使得某些对象可以在 JavaScript 中通过 `new` 关键字进行实例化。

* **支持不同的安装目标：**  这些安装函数可以将成员安装到以下几个 JavaScript 对象上：
    * **实例模板 (Instance Template):**  用于创建对象实例的模板，成员安装到这里后，每个实例对象都会拥有这些成员。
    * **原型模板 (Prototype Template):**  定义了对象实例的原型链，成员安装到这里后，实例对象可以通过原型链继承这些成员。
    * **接口模板 (Interface Template):** 代表接口本身的构造器对象，通常用于存放静态成员或常量。

* **处理不同的上下文 (Worlds):**  通过 `DoesWorldMatch` 函数，可以控制成员是否只在主线程 (Main World) 或非主线程 (Non-Main Worlds) 中安装。这对于隔离不同上下文中的行为非常重要，例如 Service Worker 和主页面有不同的执行环境。

**与 JavaScript 的关系：**

* **JavaScript 可以访问 IDL 定义的属性和方法：**  `idl_member_installer.cc` 的核心作用就是让 JavaScript 代码能够直接使用在 Web IDL 中定义的接口成员。例如，在 Web IDL 中定义了 `HTMLElement` 接口的 `id` 属性和 `setAttribute` 方法，这个文件中的代码会负责将这些属性和方法安装到 JavaScript 中对应的 `HTMLElement` 对象上。

    **举例：**

    ```javascript
    // HTML 中有一个 div 元素
    const divElement = document.getElementById('myDiv');

    // JavaScript 可以访问和设置 IDL 定义的 'id' 属性
    console.log(divElement.id); // 输出 "myDiv"
    divElement.id = 'newId';

    // JavaScript 可以调用 IDL 定义的 'setAttribute' 方法
    divElement.setAttribute('class', 'highlight');
    ```

* **JavaScript 错误与 IDL 定义的约束：**  IDL 定义中可能包含对属性的类型、是否只读、是否需要跨域检查等约束。`idl_member_installer.cc` 中的代码会根据这些约束配置 V8 引擎，从而在 JavaScript 中表现出相应的行为。

    **假设输入：**  一个 IDL 属性被定义为 `readonly`。
    **输出：**  尝试在 JavaScript 中设置该属性会失败，或者抛出一个错误（取决于具体的实现和错误处理机制）。

**与 HTML 的关系：**

* **为 DOM 元素提供 JavaScript 接口：** HTML 定义了网页的结构，而 `idl_member_installer.cc` 负责为这些 HTML 元素（例如 `<div>`, `<span>`, `<a>` 等）提供相应的 JavaScript 接口。这意味着 JavaScript 可以通过操作这些接口来动态地修改 HTML 结构和内容。

    **举例：**

    ```javascript
    // 获取 HTML 中的一个段落元素
    const paragraph = document.querySelector('p');

    // 通过 JavaScript 修改段落的文本内容，这背后涉及到对 IDL 定义的 'textContent' 属性的操作
    paragraph.textContent = '新的段落内容';
    ```

**与 CSS 的关系：**

* **允许 JavaScript 操作元素的样式：**  CSS 负责网页的样式，而 JavaScript 可以通过操作 DOM 元素的样式相关的属性（这些属性也是通过 `idl_member_installer.cc` 安装的）来动态地改变元素的视觉呈现。

    **举例：**

    ```javascript
    // 获取一个 div 元素
    const div = document.querySelector('div');

    // 修改元素的 'style' 属性，这背后涉及到对 CSSOM 相关的 IDL 接口的操作
    div.style.backgroundColor = 'lightblue';
    div.style.fontSize = '16px';
    ```

**逻辑推理示例：**

假设我们有一个简单的 IDL 定义：

```idl
interface MyObject {
    readonly attribute DOMString name;
    void sayHello();
};
```

* **假设输入（对于 `InstallAttribute`）：**  `IDLMemberInstaller::AttributeConfig` 结构体包含了 `property_name = "name"`, `callback_for_get` 指向了获取 `name` 属性值的 C++ 函数，并且 `v8_property_attribute` 设置为 `ReadOnly`.
* **输出：** 在 JavaScript 中，`MyObject` 的实例将拥有一个名为 `name` 的属性，尝试设置该属性会失败，因为它是只读的。

* **假设输入（对于 `InstallOperation`）：** `IDLMemberInstaller::OperationConfig` 结构体包含了 `property_name = "sayHello"`, `callback` 指向了执行 `sayHello` 操作的 C++ 函数。
* **输出：** 在 JavaScript 中，`MyObject` 的实例将拥有一个名为 `sayHello` 的方法，可以被调用执行。

**用户或编程常见的使用错误示例：**

1. **尝试设置只读属性：** 如果 IDL 中定义了某个属性为 `readonly`，例如 `HTMLElement.tagName`， 开发者尝试在 JavaScript 中修改它会导致错误。

   ```javascript
   const divElement = document.createElement('div');
   console.log(divElement.tagName); // 输出 "DIV"
   divElement.tagName = 'SPAN'; // 尝试设置只读属性，通常不会生效，或者在严格模式下会抛出错误。
   ```

2. **跨域访问受限的属性或方法：**  IDL 中可以定义某些属性或方法需要进行跨域检查。如果 JavaScript 代码尝试在不同的域之间访问这些受限的成员，可能会遇到安全错误。

   **假设输入：**  一个 `<img>` 元素的 `crossOrigin` 属性设置为 `'anonymous'`，但尝试访问 `naturalWidth` 属性时，图片服务器没有发送正确的 CORS 头。
   **输出：** JavaScript 代码可能无法成功获取 `naturalWidth` 的值，或者会抛出一个安全相关的错误。

3. **在错误的上下文中访问成员：**  某些 IDL 成员可能只在特定的上下文中可用。例如，某些与 Worker 相关的 API 可能在主线程中不可用。开发者如果在错误的上下文中尝试访问这些成员，会导致 `undefined` 或错误。

总而言之，`idl_member_installer.cc` 是 Blink 引擎中至关重要的一个组成部分，它负责将 Web IDL 定义的接口转化为 JavaScript 可以理解和使用的形式，是连接 Web 标准和 JavaScript 运行环境的关键桥梁。它使得 JavaScript 能够操作 HTML 结构、控制 CSS 样式，并利用浏览器提供的各种 Web API 功能。

Prompt: 
```
这是目录为blink/renderer/platform/bindings/idl_member_installer.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/bindings/idl_member_installer.h"

#include "third_party/blink/renderer/platform/bindings/dom_wrapper_world.h"
#include "third_party/blink/renderer/platform/bindings/v8_binding.h"
#include "third_party/blink/renderer/platform/bindings/v8_private_property.h"

namespace blink {

namespace bindings {

namespace {

template <typename Config>
bool DoesWorldMatch(const Config& config, const DOMWrapperWorld& world) {
  const unsigned world_bit = static_cast<unsigned>(
      world.IsMainWorld() ? IDLMemberInstaller::FlagWorld::kMainWorld
                          : IDLMemberInstaller::FlagWorld::kNonMainWorlds);
  return config.world & world_bit;
}

template <v8::ExceptionContext kind, typename Config>
v8::FunctionCallback GetConfigCallback(const Config& config);
template <>
v8::FunctionCallback GetConfigCallback<v8::ExceptionContext::kAttributeGet>(
    const IDLMemberInstaller::AttributeConfig& config) {
  return config.callback_for_get;
}
template <>
v8::FunctionCallback GetConfigCallback<v8::ExceptionContext::kAttributeSet>(
    const IDLMemberInstaller::AttributeConfig& config) {
  return config.callback_for_set;
}
template <>
v8::FunctionCallback GetConfigCallback<v8::ExceptionContext::kOperation>(
    const IDLMemberInstaller::OperationConfig& config) {
  return config.callback;
}

template <v8::ExceptionContext kind, typename Config>
int GetConfigLength(const Config& config);
template <>
int GetConfigLength<v8::ExceptionContext::kAttributeGet>(
    const IDLMemberInstaller::AttributeConfig& config) {
  return 0;
}
template <>
int GetConfigLength<v8::ExceptionContext::kAttributeSet>(
    const IDLMemberInstaller::AttributeConfig& config) {
  return 1;
}
template <>
int GetConfigLength<v8::ExceptionContext::kOperation>(
    const IDLMemberInstaller::OperationConfig& config) {
  return config.length;
}

template <v8::ExceptionContext kind, typename Config>
IDLMemberInstaller::FlagCrossOriginCheck GetConfigCrossOriginCheck(
    const Config& config);
template <>
IDLMemberInstaller::FlagCrossOriginCheck
GetConfigCrossOriginCheck<v8::ExceptionContext::kAttributeGet>(
    const IDLMemberInstaller::AttributeConfig& config) {
  return static_cast<IDLMemberInstaller::FlagCrossOriginCheck>(
      config.cross_origin_check_for_get);
}
template <>
IDLMemberInstaller::FlagCrossOriginCheck
GetConfigCrossOriginCheck<v8::ExceptionContext::kAttributeSet>(
    const IDLMemberInstaller::AttributeConfig& config) {
  return static_cast<IDLMemberInstaller::FlagCrossOriginCheck>(
      config.cross_origin_check_for_set);
}
template <>
IDLMemberInstaller::FlagCrossOriginCheck
GetConfigCrossOriginCheck<v8::ExceptionContext::kOperation>(
    const IDLMemberInstaller::OperationConfig& config) {
  return static_cast<IDLMemberInstaller::FlagCrossOriginCheck>(
      config.cross_origin_check);
}

template <v8::ExceptionContext kind, typename Config>
v8::SideEffectType GetConfigSideEffect(const Config& config);
template <>
v8::SideEffectType GetConfigSideEffect<v8::ExceptionContext::kAttributeGet>(
    const IDLMemberInstaller::AttributeConfig& config) {
  return static_cast<v8::SideEffectType>(config.v8_side_effect);
}
template <>
v8::SideEffectType GetConfigSideEffect<v8::ExceptionContext::kAttributeSet>(
    const IDLMemberInstaller::AttributeConfig& config) {
  return v8::SideEffectType::kHasSideEffect;
}
template <>
v8::SideEffectType GetConfigSideEffect<v8::ExceptionContext::kOperation>(
    const IDLMemberInstaller::OperationConfig& config) {
  return static_cast<v8::SideEffectType>(config.v8_side_effect);
}

template <v8::ExceptionContext kind, typename Config>
V8PrivateProperty::CachedAccessor GetConfigV8CachedAccessor(
    const Config& config);
template <>
V8PrivateProperty::CachedAccessor
GetConfigV8CachedAccessor<v8::ExceptionContext::kAttributeGet>(
    const IDLMemberInstaller::AttributeConfig& config) {
  return static_cast<V8PrivateProperty::CachedAccessor>(
      config.v8_cached_accessor);
}
template <>
V8PrivateProperty::CachedAccessor
GetConfigV8CachedAccessor<v8::ExceptionContext::kAttributeSet>(
    const IDLMemberInstaller::AttributeConfig& config) {
  return V8PrivateProperty::CachedAccessor::kNone;
}
template <>
V8PrivateProperty::CachedAccessor
GetConfigV8CachedAccessor<v8::ExceptionContext::kOperation>(
    const IDLMemberInstaller::OperationConfig& config) {
  return V8PrivateProperty::CachedAccessor::kNone;
}

template <v8::ExceptionContext kind, typename Config>
v8::Local<v8::FunctionTemplate> CreateFunctionTemplate(
    v8::Isolate* isolate,
    const DOMWrapperWorld& world,
    v8::Local<v8::Signature> signature,
    v8::Local<v8::String> property_name,
    v8::Local<v8::String> interface_name,
    v8::ExceptionContext exception_context,
    const Config& config,
    const v8::CFunction* v8_cfunction_table_data = nullptr,
    uint32_t v8_cfunction_table_size = 0) {
  v8::FunctionCallback callback = GetConfigCallback<kind>(config);
  if (!callback)
    return v8::Local<v8::FunctionTemplate>();

  int length = GetConfigLength<kind>(config);
  v8::SideEffectType v8_side_effect = GetConfigSideEffect<kind>(config);
  V8PrivateProperty::CachedAccessor v8_cached_accessor =
      GetConfigV8CachedAccessor<kind>(config);

  v8::Local<v8::FunctionTemplate> function_template;
  if (v8_cached_accessor == V8PrivateProperty::CachedAccessor::kNone ||
      (v8_cached_accessor ==
           V8PrivateProperty::CachedAccessor::kWindowDocument &&
       !world.IsMainWorld())) {
    function_template = v8::FunctionTemplate::NewWithCFunctionOverloads(
        isolate, callback, v8::Local<v8::Value>(), signature, length,
        v8::ConstructorBehavior::kThrow, v8_side_effect,
        {v8_cfunction_table_data, v8_cfunction_table_size});
  } else {
    DCHECK(!v8_cfunction_table_data);
    DCHECK_EQ(v8_cfunction_table_size, 0u);
    function_template = v8::FunctionTemplate::NewWithCache(
        isolate, callback,
        V8PrivateProperty::GetCachedAccessor(isolate, v8_cached_accessor)
            .GetPrivate(),
        v8::Local<v8::Value>(), signature, length, v8_side_effect);
    function_template->RemovePrototype();
  }

  function_template->SetClassName(property_name);
  function_template->SetInterfaceName(interface_name);
  function_template->SetExceptionContext(kind);

  function_template->SetAcceptAnyReceiver(
      GetConfigCrossOriginCheck<kind>(config) ==
      IDLMemberInstaller::FlagCrossOriginCheck::kDoNotCheck);

  return function_template;
}

template <v8::ExceptionContext kind, typename Config>
v8::Local<v8::Function> CreateFunction(
    v8::Isolate* isolate,
    v8::Local<v8::Context> context,
    const DOMWrapperWorld& world,
    v8::Local<v8::Signature> signature,
    v8::Local<v8::String> property_name,
    v8::Local<v8::String> interface_name,
    v8::ExceptionContext exception_context,
    const Config& config,
    const v8::CFunction* v8_cfunction_table_data = nullptr,
    uint32_t v8_cfunction_table_size = 0) {
  if (!GetConfigCallback<kind>(config))
    return v8::Local<v8::Function>();

  return CreateFunctionTemplate<kind>(isolate, world, signature, property_name,
                                      interface_name, exception_context, config,
                                      v8_cfunction_table_data,
                                      v8_cfunction_table_size)
      ->GetFunction(context)
      .ToLocalChecked();
}

void InstallAttribute(v8::Isolate* isolate,
                      const DOMWrapperWorld& world,
                      v8::Local<v8::Template> instance_template,
                      v8::Local<v8::Template> prototype_template,
                      v8::Local<v8::Template> interface_template,
                      v8::Local<v8::Signature> signature,
                      const IDLMemberInstaller::AttributeConfig& config) {
  if (!DoesWorldMatch(config, world))
    return;

  IDLMemberInstaller::FlagLocation location =
      static_cast<IDLMemberInstaller::FlagLocation>(config.location);
  if (static_cast<IDLMemberInstaller::FlagReceiverCheck>(
          config.receiver_check) ==
          IDLMemberInstaller::FlagReceiverCheck::kDoNotCheck ||
      location == IDLMemberInstaller::FlagLocation::kInterface)
    signature = v8::Local<v8::Signature>();

  StringView property_name_as_view(config.property_name);
  v8::Local<v8::String> property_name =
      V8AtomicString(isolate, property_name_as_view);
  v8::Local<v8::String> interface_name =
      V8AtomicString(isolate, config.interface_name);
  v8::Local<v8::String> get_name = V8AtomicString(
      isolate,
      static_cast<String>(StringView("get ", 4) + property_name_as_view));
  v8::Local<v8::String> set_name = V8AtomicString(
      isolate,
      static_cast<String>(StringView("set ", 4) + property_name_as_view));
  v8::Local<v8::FunctionTemplate> get_func =
      CreateFunctionTemplate<v8::ExceptionContext::kAttributeGet>(
          isolate, world, signature, get_name, interface_name,
          v8::ExceptionContext::kAttributeGet, config);
  v8::Local<v8::FunctionTemplate> set_func =
      CreateFunctionTemplate<v8::ExceptionContext::kAttributeSet>(
          isolate, world, signature, set_name, interface_name,
          v8::ExceptionContext::kAttributeSet, config);

  v8::Local<v8::Template> target_template;
  switch (location) {
    case IDLMemberInstaller::FlagLocation::kInstance:
      target_template = instance_template;
      break;
    case IDLMemberInstaller::FlagLocation::kPrototype:
      target_template = prototype_template;
      break;
    case IDLMemberInstaller::FlagLocation::kInterface:
      target_template = interface_template;
      break;
    default:
      NOTREACHED();
  }
  target_template->SetAccessorProperty(
      property_name, get_func, set_func,
      static_cast<v8::PropertyAttribute>(config.v8_property_attribute));
}

void InstallAttribute(v8::Isolate* isolate,
                      v8::Local<v8::Context> context,
                      const DOMWrapperWorld& world,
                      v8::Local<v8::Object> instance_object,
                      v8::Local<v8::Object> prototype_object,
                      v8::Local<v8::Object> interface_object,
                      v8::Local<v8::Signature> signature,
                      const IDLMemberInstaller::AttributeConfig& config) {
  if (!DoesWorldMatch(config, world))
    return;

  IDLMemberInstaller::FlagLocation location =
      static_cast<IDLMemberInstaller::FlagLocation>(config.location);
  if (static_cast<IDLMemberInstaller::FlagReceiverCheck>(
          config.receiver_check) ==
          IDLMemberInstaller::FlagReceiverCheck::kDoNotCheck ||
      location == IDLMemberInstaller::FlagLocation::kInterface)
    signature = v8::Local<v8::Signature>();

  StringView name_as_view(config.property_name);
  v8::Local<v8::String> property_name = V8AtomicString(isolate, name_as_view);
  v8::Local<v8::String> interface_name =
      V8AtomicString(isolate, config.interface_name);
  v8::Local<v8::String> get_name = V8AtomicString(
      isolate, static_cast<String>(StringView("get ", 4) + name_as_view));
  v8::Local<v8::String> set_name = V8AtomicString(
      isolate, static_cast<String>(StringView("set ", 4) + name_as_view));
  v8::Local<v8::Function> get_func =
      CreateFunction<v8::ExceptionContext::kAttributeGet>(
          isolate, context, world, signature, get_name, interface_name,
          v8::ExceptionContext::kAttributeGet, config);
  v8::Local<v8::Function> set_func =
      CreateFunction<v8::ExceptionContext::kAttributeSet>(
          isolate, context, world, signature, set_name, interface_name,
          v8::ExceptionContext::kAttributeSet, config);

  v8::Local<v8::Object> target_object;
  switch (location) {
    case IDLMemberInstaller::FlagLocation::kInstance:
      target_object = instance_object;
      break;
    case IDLMemberInstaller::FlagLocation::kPrototype:
      target_object = prototype_object;
      break;
    case IDLMemberInstaller::FlagLocation::kInterface:
      target_object = interface_object;
      break;
    default:
      NOTREACHED();
  }
  target_object->SetAccessorProperty(
      property_name, get_func, set_func,
      static_cast<v8::PropertyAttribute>(config.v8_property_attribute));
}

void InstallOperation(v8::Isolate* isolate,
                      const DOMWrapperWorld& world,
                      v8::Local<v8::Template> instance_template,
                      v8::Local<v8::Template> prototype_template,
                      v8::Local<v8::Template> interface_template,
                      v8::Local<v8::Signature> signature,
                      const IDLMemberInstaller::OperationConfig& config,
                      const v8::CFunction* v8_cfunction_table_data = nullptr,
                      uint32_t v8_cfunction_table_size = 0) {
  if (!DoesWorldMatch(config, world))
    return;

  IDLMemberInstaller::FlagLocation location =
      static_cast<IDLMemberInstaller::FlagLocation>(config.location);
  if (static_cast<IDLMemberInstaller::FlagReceiverCheck>(
          config.receiver_check) ==
          IDLMemberInstaller::FlagReceiverCheck::kDoNotCheck ||
      location == IDLMemberInstaller::FlagLocation::kInterface)
    signature = v8::Local<v8::Signature>();

  v8::Local<v8::String> property_name =
      V8AtomicString(isolate, config.property_name);
  v8::Local<v8::String> interface_name =
      V8AtomicString(isolate, config.interface_name);
  v8::Local<v8::FunctionTemplate> func =
      CreateFunctionTemplate<v8::ExceptionContext::kOperation>(
          isolate, world, signature, property_name, interface_name,
          v8::ExceptionContext::kOperation, config, v8_cfunction_table_data,
          v8_cfunction_table_size);

  v8::Local<v8::Template> target_template;
  switch (location) {
    case IDLMemberInstaller::FlagLocation::kInstance:
      target_template = instance_template;
      break;
    case IDLMemberInstaller::FlagLocation::kPrototype:
      target_template = prototype_template;
      break;
    case IDLMemberInstaller::FlagLocation::kInterface:
      target_template = interface_template;
      break;
    default:
      NOTREACHED();
  }
  target_template->Set(
      property_name, func,
      static_cast<v8::PropertyAttribute>(config.v8_property_attribute));
}

void InstallOperation(v8::Isolate* isolate,
                      v8::Local<v8::Context> context,
                      const DOMWrapperWorld& world,
                      v8::Local<v8::Object> instance_object,
                      v8::Local<v8::Object> prototype_object,
                      v8::Local<v8::Object> interface_object,
                      v8::Local<v8::Signature> signature,
                      const IDLMemberInstaller::OperationConfig& config,
                      const v8::CFunction* v8_cfunction_table_data = nullptr,
                      uint32_t v8_cfunction_table_size = 0) {
  if (!DoesWorldMatch(config, world))
    return;

  IDLMemberInstaller::FlagLocation location =
      static_cast<IDLMemberInstaller::FlagLocation>(config.location);
  if (static_cast<IDLMemberInstaller::FlagReceiverCheck>(
          config.receiver_check) ==
          IDLMemberInstaller::FlagReceiverCheck::kDoNotCheck ||
      location == IDLMemberInstaller::FlagLocation::kInterface)
    signature = v8::Local<v8::Signature>();

  v8::Local<v8::String> property_name =
      V8AtomicString(isolate, config.property_name);
  v8::Local<v8::String> interface_name =
      V8AtomicString(isolate, config.interface_name);
  v8::Local<v8::Function> func =
      CreateFunction<v8::ExceptionContext::kOperation>(
          isolate, context, world, signature, property_name, interface_name,
          v8::ExceptionContext::kOperation, config, v8_cfunction_table_data,
          v8_cfunction_table_size);

  v8::Local<v8::Object> target_object;
  switch (location) {
    case IDLMemberInstaller::FlagLocation::kInstance:
      target_object = instance_object;
      break;
    case IDLMemberInstaller::FlagLocation::kPrototype:
      target_object = prototype_object;
      break;
    case IDLMemberInstaller::FlagLocation::kInterface:
      target_object = interface_object;
      break;
    default:
      NOTREACHED();
  }
  target_object
      ->DefineOwnProperty(
          context, property_name, func,
          static_cast<v8::PropertyAttribute>(config.v8_property_attribute))
      .ToChecked();
}

}  // namespace

// static
void IDLMemberInstaller::InstallAttributes(
    v8::Isolate* isolate,
    const DOMWrapperWorld& world,
    v8::Local<v8::Template> instance_template,
    v8::Local<v8::Template> prototype_template,
    v8::Local<v8::Template> interface_template,
    v8::Local<v8::Signature> signature,
    base::span<const AttributeConfig> configs) {
  for (const auto& config : configs) {
    InstallAttribute(isolate, world, instance_template, prototype_template,
                     interface_template, signature, config);
  }
}

// static
void IDLMemberInstaller::InstallAttributes(
    v8::Isolate* isolate,
    const DOMWrapperWorld& world,
    v8::Local<v8::Object> instance_object,
    v8::Local<v8::Object> prototype_object,
    v8::Local<v8::Object> interface_object,
    v8::Local<v8::Signature> signature,
    base::span<const AttributeConfig> configs) {
  v8::Local<v8::Context> context = isolate->GetCurrentContext();
  for (const auto& config : configs) {
    InstallAttribute(isolate, context, world, instance_object, prototype_object,
                     interface_object, signature, config);
  }
}

// static
void IDLMemberInstaller::InstallConstants(
    v8::Isolate* isolate,
    const DOMWrapperWorld& world,
    v8::Local<v8::Template> instance_template,
    v8::Local<v8::Template> prototype_template,
    v8::Local<v8::Template> interface_template,
    v8::Local<v8::Signature> signature,
    base::span<const ConstantCallbackConfig> configs) {
  const bool has_prototype_template = !prototype_template.IsEmpty();
  const v8::PropertyAttribute v8_property_attribute =
      static_cast<v8::PropertyAttribute>(v8::ReadOnly | v8::DontDelete);
  for (const auto& config : configs) {
    v8::Local<v8::String> name = V8AtomicString(isolate, config.name);
    if (has_prototype_template) {
      prototype_template->SetLazyDataProperty(
          name, config.callback, v8::Local<v8::Value>(), v8_property_attribute,
          v8::SideEffectType::kHasNoSideEffect);
    }
    interface_template->SetLazyDataProperty(
        name, config.callback, v8::Local<v8::Value>(), v8_property_attribute,
        v8::SideEffectType::kHasNoSideEffect);
  }
}

// static
void IDLMemberInstaller::InstallConstants(
    v8::Isolate* isolate,
    const DOMWrapperWorld& world,
    v8::Local<v8::Template> instance_template,
    v8::Local<v8::Template> prototype_template,
    v8::Local<v8::Template> interface_template,
    v8::Local<v8::Signature> signature,
    base::span<const ConstantValueConfig> configs) {
  const bool has_prototype_template = !prototype_template.IsEmpty();
  const v8::PropertyAttribute v8_property_attribute =
      static_cast<v8::PropertyAttribute>(v8::ReadOnly | v8::DontDelete);
  for (const auto& config : configs) {
    v8::Local<v8::String> name = V8AtomicString(isolate, config.name);
    v8::Local<v8::Integer> value;
    if (config.value < 0) {
      int32_t i32_value = static_cast<int32_t>(config.value);
      DCHECK_EQ(static_cast<int64_t>(i32_value), config.value);
      value = v8::Integer::New(isolate, i32_value);
    } else {
      uint32_t u32_value = static_cast<uint32_t>(config.value);
      DCHECK_EQ(static_cast<int64_t>(u32_value), config.value);
      value = v8::Integer::NewFromUnsigned(isolate, u32_value);
    }
    if (has_prototype_template) {
      prototype_template->Set(name, value, v8_property_attribute);
    }
    interface_template->Set(name, value, v8_property_attribute);
  }
}

// static
void IDLMemberInstaller::InstallOperations(
    v8::Isolate* isolate,
    const DOMWrapperWorld& world,
    v8::Local<v8::Template> instance_template,
    v8::Local<v8::Template> prototype_template,
    v8::Local<v8::Template> interface_template,
    v8::Local<v8::Signature> signature,
    base::span<const OperationConfig> configs) {
  for (const auto& config : configs) {
    InstallOperation(isolate, world, instance_template, prototype_template,
                     interface_template, signature, config);
  }
}

// static
void IDLMemberInstaller::InstallOperations(
    v8::Isolate* isolate,
    const DOMWrapperWorld& world,
    v8::Local<v8::Object> instance_object,
    v8::Local<v8::Object> prototype_object,
    v8::Local<v8::Object> interface_object,
    v8::Local<v8::Signature> signature,
    base::span<const OperationConfig> configs) {
  v8::Local<v8::Context> context = isolate->GetCurrentContext();
  for (const auto& config : configs) {
    InstallOperation(isolate, context, world, instance_object, prototype_object,
                     interface_object, signature, config);
  }
}

// static
void IDLMemberInstaller::InstallOperations(
    v8::Isolate* isolate,
    const DOMWrapperWorld& world,
    v8::Local<v8::Template> instance_template,
    v8::Local<v8::Template> prototype_template,
    v8::Local<v8::Template> interface_template,
    v8::Local<v8::Signature> signature,
    base::span<const NoAllocDirectCallOperationConfig> configs) {
  for (const auto& config : configs) {
    InstallOperation(isolate, world, instance_template, prototype_template,
                     interface_template, signature, config.operation_config,
                     config.v8_cfunction_table_data,
                     config.v8_cfunction_table_size);
  }
}

// static
void IDLMemberInstaller::InstallOperations(
    v8::Isolate* isolate,
    const DOMWrapperWorld& world,
    v8::Local<v8::Object> instance_object,
    v8::Local<v8::Object> prototype_object,
    v8::Local<v8::Object> interface_object,
    v8::Local<v8::Signature> signature,
    base::span<const NoAllocDirectCallOperationConfig> configs) {
  v8::Local<v8::Context> context = isolate->GetCurrentContext();
  for (const auto& config : configs) {
    InstallOperation(isolate, context, world, instance_object, prototype_object,
                     interface_object, signature, config.operation_config,
                     config.v8_cfunction_table_data,
                     config.v8_cfunction_table_size);
  }
}

// static
void IDLMemberInstaller::InstallExposedConstructs(
    v8::Isolate* isolate,
    const DOMWrapperWorld& world,
    v8::Local<v8::Template> instance_template,
    v8::Local<v8::Template> prototype_template,
    v8::Local<v8::Template> interface_template,
    v8::Local<v8::Signature> signature,
    base::span<const ExposedConstructConfig> configs) {
  for (const auto& config : configs) {
    v8::Local<v8::String> name = V8AtomicString(isolate, config.name);
    instance_template->SetLazyDataProperty(
        name, config.callback, v8::Local<v8::Value>(), v8::DontEnum,
        v8::SideEffectType::kHasNoSideEffect);
  }
}

// static
void IDLMemberInstaller::InstallExposedConstructs(
    v8::Isolate* isolate,
    const DOMWrapperWorld& world,
    v8::Local<v8::Object> instance_object,
    v8::Local<v8::Object> prototype_object,
    v8::Local<v8::Object> interface_object,
    v8::Local<v8::Signature> signature,
    base::span<const ExposedConstructConfig> configs) {
  v8::Local<v8::Context> context = isolate->GetCurrentContext();
  for (const auto& config : configs) {
    instance_object
        ->SetLazyDataProperty(context, V8AtomicString(isolate, config.name),
                              config.callback, v8::Local<v8::Value>(),
                              v8::DontEnum,
                              v8::SideEffectType::kHasNoSideEffect)
        .ToChecked();
  }
}

}  // namespace bindings

}  // namespace blink

"""

```