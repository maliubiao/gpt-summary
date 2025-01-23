Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/api/api.cc`. I need to analyze the code and:

1. **List the functionalities**: Identify the core tasks and operations performed by the code.
2. **Check for Torque**: Determine if the file would be a Torque file if it ended with `.tq`.
3. **Relate to JavaScript**: If any functionality relates to JavaScript concepts, provide JavaScript examples.
4. **Provide logic examples**: If there are logical operations, create example inputs and outputs.
5. **Highlight common errors**: Point out potential mistakes developers might make when using the related APIs.
6. **Summarize the functionality**: Condense the identified functionalities into a brief overview.

Based on the code, it seems to be focused on:

- **InterceptorInfo**: Creating and configuring interceptors for object property access. This involves handling `getter`, `setter`, `query`, `descriptor`, `deleter`, `enumerator`, and `definer` callbacks for both named and indexed properties.
- **ObjectTemplate**: Setting up property handlers, access checks, and call-as-function handlers for object templates.
- **NamedPropertyHandlerConfiguration and IndexedPropertyHandlerConfiguration**: Structures to hold configurations for property handlers.
- **AccessCheckCallback**:  Setting up callbacks for access checks on object properties.
- **ObjectTemplate methods**: `MarkAsUndetectable`, `SetInternalFieldCount`, `SetImmutableProto`, `SetCodeLike`.
- **DictionaryTemplate**: Creating dictionary templates and instances.
- **Script handling**: Binding unbound scripts to contexts, retrieving script information (ID, line/column numbers, names, URLs), and running scripts.
- **Module handling**: Retrieving information about module requests, status, exceptions, and namespaces.
- **PrimitiveArray and FixedArray**: Creating and manipulating primitive arrays and fixed arrays.
- **CompileHintsCollector**:  Accessing compile hints associated with scripts.

**Plan:**

1. Summarize the `CreateInterceptorInfo` functions and their purpose.
2. Explain the `ObjectTemplate` methods related to property handlers and access control.
3. Describe the functionality of `DictionaryTemplate`.
4. Detail the script and module related functions.
5. Explain `PrimitiveArray` and `FixedArray`.
6. Summarize `CompileHintsCollector`.
7. Check for Torque relevance.
8. Provide JavaScript examples for relevant parts.
9. Create input/output examples if applicable.
10. Point out common errors.
这是 `v8/src/api/api.cc` 源代码的第三部分，主要关注以下功能：

**核心功能归纳：对象模板（ObjectTemplate）的属性拦截、访问控制、函数调用处理，以及字典模板（DictionaryTemplate）的创建和使用。此外，还涉及脚本（Script）和模块（Module）的部分操作，以及对数组（PrimitiveArray, FixedArray）的一些基础支持。**

**详细功能列表：**

1. **属性拦截器 (Interceptors) 的创建和配置:**
   - 提供了创建和配置属性拦截器 (`InterceptorInfo`) 的机制，允许在访问对象的属性时执行自定义的 JavaScript 代码。
   - 可以为命名属性 (named properties) 和索引属性 (indexed properties) 分别设置拦截器。
   - 允许设置 `getter`、`setter`、`query`、`descriptor`、`deleter`、`enumerator` 和 `definer` 等回调函数，以精细控制属性访问的行为。
   - 可以设置拦截器的数据 (`data`) 和标志 (`flags`)，例如 `kOnlyInterceptStrings`、`kNonMasking`、`kHasNoSideEffect`。

2. **对象模板 (ObjectTemplate) 的属性处理器设置:**
   - 提供了 `SetHandler` 方法，用于将命名属性或索引属性的拦截器配置应用到对象模板上。
   - `NamedPropertyHandlerConfiguration` 和 `IndexedPropertyHandlerConfiguration` 结构体用于封装属性处理器的各种回调函数和数据。

3. **对象模板的访问检查回调 (Access Check Callback):**
   - 允许设置 `AccessCheckCallback`，用于在访问对象的属性前执行权限检查。
   - 可以同时设置命名和索引属性的拦截器，并与访问检查回调关联起来。
   - `MarkAsUndetectable` 方法可以将对象模板标记为无法被 `in` 操作符检测到。

4. **对象模板的函数调用处理 (Call As Function Handler):**
   - 提供了 `SetCallAsFunctionHandler` 方法，允许将对象模板的实例作为函数调用时执行自定义的 JavaScript 代码。

5. **对象模板的内部字段计数 (Internal Field Count):**
   - 提供了 `SetInternalFieldCount` 和 `InternalFieldCount` 方法，用于管理对象模板实例的内部字段数量。

6. **对象模板的原型链控制:**
   - `SetImmutableProto` 方法可以将对象模板的原型链设置为不可变。
   - `IsImmutableProto` 方法用于检查原型链是否不可变。

7. **对象模板的代码特性设置:**
   - `SetCodeLike` 方法可以将对象模板标记为类似代码的对象。
   - `IsCodeLike` 方法用于检查对象模板是否被标记为类似代码。

8. **字典模板 (DictionaryTemplate) 的创建和实例化:**
   - 提供了 `DictionaryTemplate::New` 方法用于创建新的字典模板。
   - 提供了 `DictionaryTemplate::NewInstance` 方法，可以根据字典模板创建新的对象实例，并初始化属性值。

9. **脚本 (Script) 的绑定和信息获取:**
   - `UnboundScript::BindToCurrentContext` 方法可以将未绑定的脚本绑定到当前上下文。
   - `UnboundScript` 提供获取脚本 ID (`GetId`)、行号 (`GetLineNumber`)、列号 (`GetColumnNumber`)、脚本名称 (`GetScriptName`)、源码 URL (`GetSourceURL`) 和 Source Mapping URL (`GetSourceMappingURL`) 的方法。

10. **脚本的运行:**
    - `Script::Run` 方法用于在指定的上下文中执行脚本。

11. **脚本或模块的资源名称和宿主定义选项获取:**
    - `ScriptOrModule::GetResourceName` 用于获取脚本或模块的资源名称。
    - `ScriptOrModule::HostDefinedOptions` 用于获取脚本或模块的宿主定义选项。

12. **获取脚本的未绑定版本:**
    - `Script::GetUnboundScript` 用于获取脚本的未绑定版本 (`UnboundScript`)。

13. **获取脚本的编译提示:**
    - `Script::GetProducedCompileHints` 用于获取脚本编译时产生的提示信息。
    - `Script::GetCompileHintsCollector` 用于获取编译提示收集器。
    - `CompileHintsCollector::GetCompileHints` 用于从收集器中获取编译提示。

14. **原始数组 (PrimitiveArray) 的创建和操作:**
    - 提供了 `PrimitiveArray::New` 方法用于创建指定长度的原始类型数组。
    - 提供了 `Length`、`Set` 和 `Get` 方法用于获取数组长度、设置和获取数组元素。

15. **固定数组 (FixedArray) 的操作:**
    - 提供了 `Length` 和 `Get` 方法用于获取固定数组的长度和元素。

16. **模块 (Module) 的请求信息获取:**
    - `ModuleRequest::GetSpecifier` 用于获取模块请求的标识符。
    - `ModuleRequest::GetPhase` 用于获取模块请求的阶段。
    - `ModuleRequest::GetSourceOffset` 用于获取模块请求在源代码中的偏移量。
    - `ModuleRequest::GetImportAttributes` 用于获取模块导入的属性。

17. **模块的状态和异常信息获取:**
    - `Module::GetStatus` 用于获取模块的当前状态（例如，未实例化、实例化中、已执行等）。
    - `Module::GetException` 用于获取模块执行过程中发生的异常。

18. **模块的依赖关系和命名空间获取:**
    - `Module::GetModuleRequests` 用于获取模块依赖的其他模块请求。
    - `Module::GetModuleNamespace` 用于获取模块的命名空间对象。

19. **模块的源代码位置映射:**
    - `Module::SourceOffsetToLocation` 用于将源代码偏移量映射到行号和列号。

20. **获取模块的未绑定版本:**
    - `Module::GetUnboundModuleScript` 用于获取模块的未绑定版本 (`UnboundModuleScript`)。

21. **获取模块的 Script ID 和是否包含顶层 await:**
    - `Module::ScriptId` 用于获取模块关联的脚本 ID。
    - `Module::HasTopLevelAwait` 用于判断模块是否包含顶层 `await`。

22. **判断模块的异步性:**
    - `Module::IsGraphAsync` 用于判断模块的依赖图是否是异步的。

23. **判断模块的类型:**
    - `Module::IsSourceTextModule` 用于判断模块是否是源代码文本模块。
    - `Module::IsSyntheticModule` 用于判断模块是否是合成模块。

24. **获取模块的 Identity Hash:**
    - `Module::GetIdentityHash` 用于获取模块的唯一标识哈希值.

25. **模块的实例化:**
    - `Module::InstantiateModule` 用于实例化模块，需要提供模块解析和源码解析的回调函数。

**如果 `v8/src/api/api.cc` 以 `.tq` 结尾，那它是个 v8 torque 源代码。**

当前文件名为 `.cc`，因此是标准的 C++ 源代码。如果以 `.tq` 结尾，则表示它是使用 V8 的 Torque 语言编写的，Torque 是一种用于定义 V8 内部运行时函数的领域特定语言。

**与 JavaScript 功能的关系和 JavaScript 示例：**

这些 C++ 代码主要实现了 V8 引擎暴露给 JavaScript 的 API 的底层逻辑。以下是一些与 JavaScript 功能相关的例子：

**1. 对象属性拦截器 (JavaScript 的 `Proxy` 类似概念):**

```javascript
const myObject = {};

// 定义一个 handler，模拟 C++ 中的 InterceptorInfo
const handler = {
  get: function(target, prop, receiver) {
    console.log(`Getting property "${prop}"`);
    return target[prop];
  },
  set: function(target, prop, value, receiver) {
    console.log(`Setting property "${prop}" to`, value);
    target[prop] = value;
    return true;
  }
};

const proxy = new Proxy(myObject, handler);

proxy.name = "John"; // 输出: Setting property "name" to John
console.log(proxy.name); // 输出: Getting property "name", 然后输出: John
```

**2. 对象模板和访问检查:**

```javascript
// 在 C++ 中创建 ObjectTemplate 并设置 AccessCheckCallback
// (JavaScript 中无法直接创建 ObjectTemplate，这里仅为概念演示)

// 假设 C++ 中创建了一个名为 'secureTemplate' 的 ObjectTemplate，并设置了访问检查

const secureObject = {}; // 假设这是由 'secureTemplate' 创建的对象

// 当尝试访问 secureObject 的属性时，会触发 C++ 中设置的 AccessCheckCallback
// C++ 的回调函数可以根据上下文决定是否允许访问
```

**3. 将对象作为函数调用:**

```javascript
// 在 C++ 中创建 ObjectTemplate 并设置 SetCallAsFunctionHandler
// (JavaScript 中无法直接创建 ObjectTemplate，这里仅为概念演示)

function MyFunction() {
  console.log("MyFunction was called");
}

const callableObject = MyFunction; // 在 C++ 中使用 ObjectTemplate 创建，并设置了 SetCallAsFunctionHandler

callableObject(); // 会调用 C++ 中设置的 FunctionCallback
```

**4. 字典模板:**

```javascript
const myDictionary = { a: 1, b: "hello" }; // JavaScript 对象可以被视为字典

// C++ 中的 DictionaryTemplate 提供了更底层的机制来创建类似字典的对象
// 可以在创建时预分配空间或进行其他优化
```

**5. 脚本的运行:**

```javascript
// 创建一个脚本
const scriptSource = 'console.log("Hello from script!");';

// 在 Node.js 环境或其他 V8 宿主环境中运行脚本
// (具体的运行方式取决于宿主环境的 API)
// 例如在 Node.js 中可以使用 vm 模块：
const vm = require('vm');
const script = new vm.Script(scriptSource);
script.runInThisContext(); // 输出: Hello from script!
```

**6. 模块的导入:**

```javascript
// myModule.js
export const message = "Hello from module!";

// main.js
import { message } from './myModule.js';
console.log(message); // 输出: Hello from module!
```

**代码逻辑推理和假设输入输出：**

**示例： `CreateNamedInterceptorInfo` 函数**

**假设输入：**

- `i_isolate`: 一个有效的 V8 隔离区指针。
- `getter`: 一个指向 getter 回调函数的指针（假设存在）。
- 其他回调函数指针：部分或全部为 `nullptr`。
- `data`: 一个 V8 Value 的 Local 句柄，例如 `v8::String::NewFromUtf8Literal(isolate, "some data")`.
- `flags`:  `PropertyHandlerFlags::kHasNoSideEffect`.

**代码逻辑：**

函数 `CreateNamedInterceptorInfo` 会创建一个 `i::InterceptorInfo` 对象，并将传入的回调函数指针、数据和标志设置到该对象中。由于 `getter` 不为 `nullptr`，它会设置 `getter` 回调和相应的 tag。由于设置了 `PropertyHandlerFlags::kHasNoSideEffect`，`obj->set_has_no_side_effect` 将被设置为 `true`。

**预期输出：**

- 返回一个指向新创建的 `i::InterceptorInfo` 对象的 `i::Handle`。
- 该 `InterceptorInfo` 对象的以下属性将被设置：
    - `is_named` 为 `true`.
    - `getter` 字段指向传入的 getter 回调函数。
    - `data` 字段指向包含 "some data" 的 V8 字符串对象。
    - `has_no_side_effect` 标志为 `true`.
    - 其他回调函数对应的字段如果输入为 `nullptr`，则保持默认值（通常表示没有设置）。

**用户常见的编程错误：**

1. **在不合适的时机调用需要 `ENTER_V8` 的 API：**  很多 V8 API 需要在 V8 引擎的上下文中运行。如果在引擎没有启动或上下文不正确的情况下调用这些 API，会导致崩溃或未定义的行为。

   ```c++
   // 错误示例：在没有 Isolate 或 Context 的情况下调用
   v8::Isolate* isolate = nullptr;
   v8::Local<v8::String> str = v8::String::NewFromUtf8Literal(isolate, "hello"); // 错误！isolate 为空
   ```

2. **忘记处理 `MaybeLocal` 返回值：** 很多 V8 API 返回 `MaybeLocal`，表示操作可能失败。不检查返回值直接使用可能导致程序崩溃。

   ```c++
   v8::Local<v8::Context> context = isolate->GetCurrentContext();
   v8::MaybeLocal<v8::Value> result_maybe = script->Run(context);
   v8::Local<v8::Value> result = result_maybe.ToLocalChecked(); // 如果 Run 失败，这里会抛出异常
   ```

   **正确的做法:**

   ```c++
   v8::Local<v8::Context> context = isolate->GetCurrentContext();
   v8::MaybeLocal<v8::Value> result_maybe = script->Run(context);
   v8::Local<v8::Value> result;
   if (!result_maybe.ToLocal(&result)) {
       // 处理脚本运行失败的情况
       v8::Local<v8::String> error = exception->ToString(context).ToLocalChecked();
       // ... 记录错误或采取其他措施
   } else {
       // 使用 result
   }
   ```

3. **不正确地管理 V8 的句柄 (Handles)：** V8 使用句柄来管理 JavaScript 对象。如果句柄管理不当（例如，忘记使用 `HandleScope`），可能导致内存泄漏或悬挂指针。

4. **在回调函数中执行耗时操作：**  V8 的回调函数应该快速执行，避免阻塞 JavaScript 引擎的事件循环。如果需要在回调中执行耗时操作，应该将其放入后台线程或使用异步操作。

5. **在不应该使用快照的地方使用快照：** 快照用于序列化 V8 堆的状态。不正确地使用快照可能导致安全问题或兼容性问题。

**总结一下 `v8/src/api/api.cc` (第 3 部分) 的功能：**

这部分代码主要负责 V8 API 中关于对象模板、字典模板、脚本和模块操作的基础设施建设。它提供了创建和配置对象模板属性拦截器、访问控制器和函数调用处理器的能力，以及创建和使用字典模板的机制。此外，它还包含了获取脚本和模块基本信息以及执行脚本、实例化模块的相关功能。这些功能是 V8 引擎暴露给 JavaScript 开发者进行高级对象定制和模块化编程的重要组成部分。

### 提示词
```
这是目录为v8/src/api/api.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/api/api.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共15部分，请归纳一下它的功能
```

### 源代码
```cpp
andle(*name),
                                 intrinsic,
                                 static_cast<i::PropertyAttributes>(attribute));
}

namespace {
enum class PropertyType { kNamed, kIndexed };
template <PropertyType property_type, typename Getter, typename Setter,
          typename Query, typename Descriptor, typename Deleter,
          typename Enumerator, typename Definer>
i::Handle<i::InterceptorInfo> CreateInterceptorInfo(
    i::Isolate* i_isolate, Getter getter, Setter setter, Query query,
    Descriptor descriptor, Deleter remover, Enumerator enumerator,
    Definer definer, Local<Value> data,
    base::Flags<PropertyHandlerFlags> flags) {
  // TODO(saelo): instead of an in-sandbox struct with a lot of external
  // pointers (with different tags), consider creating an object in trusted
  // space instead. That way, only a single reference going out of the sandbox
  // would be required.
  auto obj = i::Cast<i::InterceptorInfo>(i_isolate->factory()->NewStruct(
      i::INTERCEPTOR_INFO_TYPE, i::AllocationType::kOld));
  obj->set_flags(0);

#define CALLBACK_TAG(NAME)                             \
  property_type == PropertyType::kNamed                \
      ? internal::kApiNamedProperty##NAME##CallbackTag \
      : internal::kApiIndexedProperty##NAME##CallbackTag;

  if (getter != nullptr) {
    constexpr internal::ExternalPointerTag tag = CALLBACK_TAG(Getter);
    SET_FIELD_WRAPPED(i_isolate, obj, set_getter, getter, tag);
  }
  if (setter != nullptr) {
    constexpr internal::ExternalPointerTag tag = CALLBACK_TAG(Setter);
    SET_FIELD_WRAPPED(i_isolate, obj, set_setter, setter, tag);
  }
  if (query != nullptr) {
    constexpr internal::ExternalPointerTag tag = CALLBACK_TAG(Query);
    SET_FIELD_WRAPPED(i_isolate, obj, set_query, query, tag);
  }
  if (descriptor != nullptr) {
    constexpr internal::ExternalPointerTag tag = CALLBACK_TAG(Descriptor);
    SET_FIELD_WRAPPED(i_isolate, obj, set_descriptor, descriptor, tag);
  }
  if (remover != nullptr) {
    constexpr internal::ExternalPointerTag tag = CALLBACK_TAG(Deleter);
    SET_FIELD_WRAPPED(i_isolate, obj, set_deleter, remover, tag);
  }
  if (enumerator != nullptr) {
    SET_FIELD_WRAPPED(i_isolate, obj, set_enumerator, enumerator,
                      internal::kApiIndexedPropertyEnumeratorCallbackTag);
  }
  if (definer != nullptr) {
    constexpr internal::ExternalPointerTag tag = CALLBACK_TAG(Definer);
    SET_FIELD_WRAPPED(i_isolate, obj, set_definer, definer, tag);
  }

#undef CALLBACK_TAG

  obj->set_can_intercept_symbols(
      !(flags & PropertyHandlerFlags::kOnlyInterceptStrings));
  obj->set_non_masking(flags & PropertyHandlerFlags::kNonMasking);
  obj->set_has_no_side_effect(flags & PropertyHandlerFlags::kHasNoSideEffect);

  if (data.IsEmpty()) {
    data = v8::Undefined(reinterpret_cast<v8::Isolate*>(i_isolate));
  }
  obj->set_data(*Utils::OpenDirectHandle(*data));
  return obj;
}

template <typename Getter, typename Setter, typename Query, typename Descriptor,
          typename Deleter, typename Enumerator, typename Definer>
i::Handle<i::InterceptorInfo> CreateNamedInterceptorInfo(
    i::Isolate* i_isolate, Getter getter, Setter setter, Query query,
    Descriptor descriptor, Deleter remover, Enumerator enumerator,
    Definer definer, Local<Value> data,
    base::Flags<PropertyHandlerFlags> flags) {
  auto interceptor = CreateInterceptorInfo<PropertyType::kNamed>(
      i_isolate, getter, setter, query, descriptor, remover, enumerator,
      definer, data, flags);
  interceptor->set_is_named(true);
  return interceptor;
}

template <typename Getter, typename Setter, typename Query, typename Descriptor,
          typename Deleter, typename Enumerator, typename Definer>
i::Handle<i::InterceptorInfo> CreateIndexedInterceptorInfo(
    i::Isolate* i_isolate, Getter getter, Setter setter, Query query,
    Descriptor descriptor, Deleter remover, Enumerator enumerator,
    Definer definer, Local<Value> data,
    base::Flags<PropertyHandlerFlags> flags) {
  auto interceptor = CreateInterceptorInfo<PropertyType::kIndexed>(
      i_isolate, getter, setter, query, descriptor, remover, enumerator,
      definer, data, flags);
  interceptor->set_is_named(false);
  return interceptor;
}

template <typename Getter, typename Setter, typename Query, typename Descriptor,
          typename Deleter, typename Enumerator, typename Definer>
void ObjectTemplateSetNamedPropertyHandler(
    ObjectTemplate* templ, Getter getter, Setter setter, Query query,
    Descriptor descriptor, Deleter remover, Enumerator enumerator,
    Definer definer, Local<Value> data, PropertyHandlerFlags flags) {
  i::Isolate* i_isolate = Utils::OpenDirectHandle(templ)->GetIsolate();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::HandleScope scope(i_isolate);
  auto cons = EnsureConstructor(i_isolate, templ);
  EnsureNotPublished(cons, "ObjectTemplateSetNamedPropertyHandler");
  auto obj =
      CreateNamedInterceptorInfo(i_isolate, getter, setter, query, descriptor,
                                 remover, enumerator, definer, data, flags);
  i::FunctionTemplateInfo::SetNamedPropertyHandler(i_isolate, cons, obj);
}
}  // namespace

void ObjectTemplate::SetHandler(
    const NamedPropertyHandlerConfiguration& config) {
  ObjectTemplateSetNamedPropertyHandler(
      this, config.getter, config.setter, config.query, config.descriptor,
      config.deleter, config.enumerator, config.definer, config.data,
      config.flags);
}

void ObjectTemplate::MarkAsUndetectable() {
  i::Isolate* i_isolate = Utils::OpenDirectHandle(this)->GetIsolate();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::HandleScope scope(i_isolate);
  auto cons = EnsureConstructor(i_isolate, this);
  EnsureNotPublished(cons, "v8::ObjectTemplate::MarkAsUndetectable");
  cons->set_undetectable(true);
}

void ObjectTemplate::SetAccessCheckCallback(AccessCheckCallback callback,
                                            Local<Value> data) {
  i::Isolate* i_isolate = Utils::OpenDirectHandle(this)->GetIsolate();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::HandleScope scope(i_isolate);
  auto cons = EnsureConstructor(i_isolate, this);
  EnsureNotPublished(cons, "v8::ObjectTemplate::SetAccessCheckCallback");

  i::Handle<i::Struct> struct_info = i_isolate->factory()->NewStruct(
      i::ACCESS_CHECK_INFO_TYPE, i::AllocationType::kOld);
  auto info = i::Cast<i::AccessCheckInfo>(struct_info);

  SET_FIELD_WRAPPED(i_isolate, info, set_callback, callback,
                    internal::kApiAccessCheckCallbackTag);
  info->set_named_interceptor(i::Smi::zero());
  info->set_indexed_interceptor(i::Smi::zero());

  if (data.IsEmpty()) {
    data = v8::Undefined(reinterpret_cast<v8::Isolate*>(i_isolate));
  }
  info->set_data(*Utils::OpenDirectHandle(*data));

  i::FunctionTemplateInfo::SetAccessCheckInfo(i_isolate, cons, info);
  cons->set_needs_access_check(true);
}

void ObjectTemplate::SetAccessCheckCallbackAndHandler(
    AccessCheckCallback callback,
    const NamedPropertyHandlerConfiguration& named_handler,
    const IndexedPropertyHandlerConfiguration& indexed_handler,
    Local<Value> data) {
  i::Isolate* i_isolate = Utils::OpenDirectHandle(this)->GetIsolate();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::HandleScope scope(i_isolate);
  auto cons = EnsureConstructor(i_isolate, this);
  EnsureNotPublished(cons,
                     "v8::ObjectTemplate::SetAccessCheckCallbackWithHandler");

  i::Handle<i::Struct> struct_info = i_isolate->factory()->NewStruct(
      i::ACCESS_CHECK_INFO_TYPE, i::AllocationType::kOld);
  auto info = i::Cast<i::AccessCheckInfo>(struct_info);

  SET_FIELD_WRAPPED(i_isolate, info, set_callback, callback,
                    internal::kApiAccessCheckCallbackTag);
  auto named_interceptor = CreateNamedInterceptorInfo(
      i_isolate, named_handler.getter, named_handler.setter,
      named_handler.query, named_handler.descriptor, named_handler.deleter,
      named_handler.enumerator, named_handler.definer, named_handler.data,
      named_handler.flags);
  info->set_named_interceptor(*named_interceptor);
  auto indexed_interceptor = CreateIndexedInterceptorInfo(
      i_isolate, indexed_handler.getter, indexed_handler.setter,
      indexed_handler.query, indexed_handler.descriptor,
      indexed_handler.deleter, indexed_handler.enumerator,
      indexed_handler.definer, indexed_handler.data, indexed_handler.flags);
  info->set_indexed_interceptor(*indexed_interceptor);

  if (data.IsEmpty()) {
    data = v8::Undefined(reinterpret_cast<v8::Isolate*>(i_isolate));
  }
  info->set_data(*Utils::OpenDirectHandle(*data));

  i::FunctionTemplateInfo::SetAccessCheckInfo(i_isolate, cons, info);
  cons->set_needs_access_check(true);
}

void ObjectTemplate::SetHandler(
    const IndexedPropertyHandlerConfiguration& config) {
  i::Isolate* i_isolate = Utils::OpenDirectHandle(this)->GetIsolate();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::HandleScope scope(i_isolate);
  auto cons = EnsureConstructor(i_isolate, this);
  EnsureNotPublished(cons, "v8::ObjectTemplate::SetHandler");
  auto obj = CreateIndexedInterceptorInfo(
      i_isolate, config.getter, config.setter, config.query, config.descriptor,
      config.deleter, config.enumerator, config.definer, config.data,
      config.flags);
  i::FunctionTemplateInfo::SetIndexedPropertyHandler(i_isolate, cons, obj);
}

void ObjectTemplate::SetCallAsFunctionHandler(FunctionCallback callback,
                                              Local<Value> data) {
  i::Isolate* i_isolate = Utils::OpenDirectHandle(this)->GetIsolate();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::HandleScope scope(i_isolate);
  auto cons = EnsureConstructor(i_isolate, this);
  EnsureNotPublished(cons, "v8::ObjectTemplate::SetCallAsFunctionHandler");
  DCHECK_NOT_NULL(callback);

  // This template is just a container for callback and data values and thus
  // it's not supposed to be instantiated. Don't cache it.
  constexpr bool do_not_cache = true;
  constexpr int length = 0;
  i::Handle<i::FunctionTemplateInfo> templ =
      i_isolate->factory()->NewFunctionTemplateInfo(length, do_not_cache);
  templ->set_is_object_template_call_handler(true);
  Utils::ToLocal(templ)->SetCallHandler(callback, data);
  i::FunctionTemplateInfo::SetInstanceCallHandler(i_isolate, cons, templ);
}

int ObjectTemplate::InternalFieldCount() const {
  return Utils::OpenDirectHandle(this)->embedder_field_count();
}

void ObjectTemplate::SetInternalFieldCount(int value) {
  i::Isolate* i_isolate = Utils::OpenDirectHandle(this)->GetIsolate();
  if (!Utils::ApiCheck(i::Smi::IsValid(value),
                       "v8::ObjectTemplate::SetInternalFieldCount()",
                       "Invalid embedder field count")) {
    return;
  }
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  if (value > 0) {
    // The embedder field count is set by the constructor function's
    // construct code, so we ensure that there is a constructor
    // function to do the setting.
    EnsureConstructor(i_isolate, this);
  }
  Utils::OpenDirectHandle(this)->set_embedder_field_count(value);
}

bool ObjectTemplate::IsImmutableProto() const {
  return Utils::OpenDirectHandle(this)->immutable_proto();
}

void ObjectTemplate::SetImmutableProto() {
  auto self = Utils::OpenDirectHandle(this);
  i::Isolate* i_isolate = self->GetIsolate();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  self->set_immutable_proto(true);
}

bool ObjectTemplate::IsCodeLike() const {
  return Utils::OpenDirectHandle(this)->code_like();
}

void ObjectTemplate::SetCodeLike() {
  auto self = Utils::OpenDirectHandle(this);
  i::Isolate* i_isolate = self->GetIsolate();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  self->set_code_like(true);
}

Local<DictionaryTemplate> DictionaryTemplate::New(
    Isolate* isolate, MemorySpan<const std::string_view> names) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  API_RCS_SCOPE(i_isolate, DictionaryTemplate, New);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  return Utils::ToLocal(i::DictionaryTemplateInfo::Create(i_isolate, names));
}

Local<Object> DictionaryTemplate::NewInstance(
    Local<Context> context, MemorySpan<MaybeLocal<Value>> property_values) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(context->GetIsolate());
  API_RCS_SCOPE(i_isolate, DictionaryTemplate, NewInstance);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  auto self = Utils::OpenDirectHandle(this);
  return ToApiHandle<Object>(i::DictionaryTemplateInfo::NewInstance(
      Utils::OpenHandle(*context), self, property_values));
}

// --- S c r i p t s ---

// Internally, UnboundScript and UnboundModuleScript are SharedFunctionInfos,
// and Script is a JSFunction.

ScriptCompiler::CachedData::CachedData(const uint8_t* data_, int length_,
                                       BufferPolicy buffer_policy_)
    : data(data_),
      length(length_),
      rejected(false),
      buffer_policy(buffer_policy_) {}

ScriptCompiler::CachedData::~CachedData() {
  if (buffer_policy == BufferOwned) {
    delete[] data;
  }
}

ScriptCompiler::CachedData::CompatibilityCheckResult
ScriptCompiler::CachedData::CompatibilityCheck(Isolate* isolate) {
  i::AlignedCachedData aligned(data, length);
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  i::SerializedCodeSanityCheckResult result;
  i::SerializedCodeData scd =
      i::SerializedCodeData::FromCachedDataWithoutSource(
          i_isolate->AsLocalIsolate(), &aligned, &result);
  return static_cast<ScriptCompiler::CachedData::CompatibilityCheckResult>(
      result);
}

ScriptCompiler::StreamedSource::StreamedSource(
    std::unique_ptr<ExternalSourceStream> stream, Encoding encoding)
    : impl_(new i::ScriptStreamingData(std::move(stream), encoding)) {}

ScriptCompiler::StreamedSource::~StreamedSource() = default;

Local<Script> UnboundScript::BindToCurrentContext() {
  auto function_info = Utils::OpenHandle(this);
  // TODO(jgruber): Remove this DCHECK once Function::GetUnboundScript is gone.
  DCHECK(!i::HeapLayout::InReadOnlySpace(*function_info));
  i::Isolate* i_isolate = i::GetIsolateFromWritableObject(*function_info);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::DirectHandle<i::JSFunction> function =
      i::Factory::JSFunctionBuilder{i_isolate, function_info,
                                    i_isolate->native_context()}
          .Build();
  return ToApiHandle<Script>(function);
}

int UnboundScript::GetId() const {
  auto function_info = Utils::OpenDirectHandle(this);
  // TODO(jgruber): Remove this DCHECK once Function::GetUnboundScript is gone.
  DCHECK(!i::HeapLayout::InReadOnlySpace(*function_info));
  API_RCS_SCOPE(i::GetIsolateFromWritableObject(*function_info), UnboundScript,
                GetId);
  return i::Cast<i::Script>(function_info->script())->id();
}

int UnboundScript::GetLineNumber(int code_pos) {
  auto obj = Utils::OpenDirectHandle(this);
  if (i::IsScript(obj->script())) {
    // TODO(jgruber): Remove this DCHECK once Function::GetUnboundScript is
    // gone.
    DCHECK(!i::HeapLayout::InReadOnlySpace(*obj));
    i::Isolate* i_isolate = i::GetIsolateFromWritableObject(*obj);
    ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
    API_RCS_SCOPE(i_isolate, UnboundScript, GetLineNumber);
    i::DirectHandle<i::Script> script(i::Cast<i::Script>(obj->script()),
                                      i_isolate);
    return i::Script::GetLineNumber(script, code_pos);
  } else {
    return -1;
  }
}

int UnboundScript::GetColumnNumber(int code_pos) {
  auto obj = Utils::OpenDirectHandle(this);
  if (i::IsScript(obj->script())) {
    // TODO(jgruber): Remove this DCHECK once Function::GetUnboundScript is
    // gone.
    DCHECK(!i::HeapLayout::InReadOnlySpace(*obj));
    i::Isolate* i_isolate = i::GetIsolateFromWritableObject(*obj);
    ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
    API_RCS_SCOPE(i_isolate, UnboundScript, GetColumnNumber);
    i::DirectHandle<i::Script> script(i::Cast<i::Script>(obj->script()),
                                      i_isolate);
    return i::Script::GetColumnNumber(script, code_pos);
  } else {
    return -1;
  }
}

Local<Value> UnboundScript::GetScriptName() {
  auto obj = Utils::OpenDirectHandle(this);
  if (i::IsScript(obj->script())) {
    // TODO(jgruber): Remove this DCHECK once Function::GetUnboundScript is
    // gone.
    DCHECK(!i::HeapLayout::InReadOnlySpace(*obj));
    i::Isolate* i_isolate = i::GetIsolateFromWritableObject(*obj);
    ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
    API_RCS_SCOPE(i_isolate, UnboundScript, GetName);
    i::Tagged<i::Object> name = i::Cast<i::Script>(obj->script())->name();
    return Utils::ToLocal(i::direct_handle(name, i_isolate));
  } else {
    return Local<String>();
  }
}

Local<Value> UnboundScript::GetSourceURL() {
  auto obj = Utils::OpenDirectHandle(this);
  if (i::IsScript(obj->script())) {
    // TODO(jgruber): Remove this DCHECK once Function::GetUnboundScript is
    // gone.
    DCHECK(!i::HeapLayout::InReadOnlySpace(*obj));
    i::Isolate* i_isolate = i::GetIsolateFromWritableObject(*obj);
    API_RCS_SCOPE(i_isolate, UnboundScript, GetSourceURL);
    ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
    i::Tagged<i::Object> url = i::Cast<i::Script>(obj->script())->source_url();
    return Utils::ToLocal(i::direct_handle(url, i_isolate));
  } else {
    return Local<String>();
  }
}

Local<Value> UnboundScript::GetSourceMappingURL() {
  auto obj = Utils::OpenDirectHandle(this);
  if (i::IsScript(obj->script())) {
    // TODO(jgruber): Remove this DCHECK once Function::GetUnboundScript is
    // gone.
    DCHECK(!i::HeapLayout::InReadOnlySpace(*obj));
    i::Isolate* i_isolate = i::GetIsolateFromWritableObject(*obj);
    API_RCS_SCOPE(i_isolate, UnboundScript, GetSourceMappingURL);
    ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
    i::Tagged<i::Object> url =
        i::Cast<i::Script>(obj->script())->source_mapping_url();
    return Utils::ToLocal(i::direct_handle(url, i_isolate));
  } else {
    return Local<String>();
  }
}

Local<Value> UnboundModuleScript::GetSourceURL() {
  auto obj = Utils::OpenDirectHandle(this);
  if (i::IsScript(obj->script())) {
    // TODO(jgruber): Remove this DCHECK once Function::GetUnboundScript is
    // gone.
    DCHECK(!i::HeapLayout::InReadOnlySpace(*obj));
    i::Isolate* i_isolate = i::GetIsolateFromWritableObject(*obj);
    API_RCS_SCOPE(i_isolate, UnboundModuleScript, GetSourceURL);
    ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
    i::Tagged<i::Object> url = i::Cast<i::Script>(obj->script())->source_url();
    return Utils::ToLocal(i::direct_handle(url, i_isolate));
  } else {
    return Local<String>();
  }
}

Local<Value> UnboundModuleScript::GetSourceMappingURL() {
  auto obj = Utils::OpenDirectHandle(this);
  if (i::IsScript(obj->script())) {
    // TODO(jgruber): Remove this DCHECK once Function::GetUnboundScript is
    // gone.
    DCHECK(!i::HeapLayout::InReadOnlySpace(*obj));
    i::Isolate* i_isolate = i::GetIsolateFromWritableObject(*obj);
    API_RCS_SCOPE(i_isolate, UnboundModuleScript, GetSourceMappingURL);
    ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
    i::Tagged<i::Object> url =
        i::Cast<i::Script>(obj->script())->source_mapping_url();
    return Utils::ToLocal(i::direct_handle(url, i_isolate));
  } else {
    return Local<String>();
  }
}

MaybeLocal<Value> Script::Run(Local<Context> context) {
  return Run(context, Local<Data>());
}

MaybeLocal<Value> Script::Run(Local<Context> context,
                              Local<Data> host_defined_options) {
  auto v8_isolate = context->GetIsolate();
  auto i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  TRACE_EVENT_CALL_STATS_SCOPED(i_isolate, "v8", "V8.Execute");
  ENTER_V8(i_isolate, context, Script, Run, InternalEscapableScope);
  i::TimerEventScope<i::TimerEventExecute> timer_scope(i_isolate);
  i::NestedTimedHistogramScope execute_timer(i_isolate->counters()->execute(),
                                             i_isolate);
  i::AggregatingHistogramTimerScope histogram_timer(
      i_isolate->counters()->compile_lazy());

#if defined(V8_OS_WIN) && defined(V8_ENABLE_ETW_STACK_WALKING)
  // In case ETW has been activated, tasks to log existing code are
  // created. But in case the task runner does not run those before
  // starting to execute code (as it happens in d8, that will run
  // first the code from prompt), then that code will not have
  // JIT instrumentation on time.
  //
  // To avoid this, on running scripts check first if JIT code log is
  // pending and generate immediately.
  if (i::v8_flags.enable_etw_stack_walking) {
    i::ETWJITInterface::MaybeSetHandlerNow(i_isolate);
  }
#endif
  auto fun = i::Cast<i::JSFunction>(Utils::OpenHandle(this));
  i::Handle<i::Object> receiver = i_isolate->global_proxy();
  // TODO(cbruni, chromium:1244145): Remove once migrated to the context.
  i::Handle<i::Object> options(
      i::Cast<i::Script>(fun->shared()->script())->host_defined_options(),
      i_isolate);
  Local<Value> result;
  has_exception = !ToLocal<Value>(
      i::Execution::CallScript(i_isolate, fun, receiver, options), &result);

  RETURN_ON_FAILED_EXECUTION(Value);
  RETURN_ESCAPED(result);
}

Local<Value> ScriptOrModule::GetResourceName() {
  auto obj = Utils::OpenDirectHandle(this);
  i::Isolate* i_isolate = i::GetIsolateFromWritableObject(*obj);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  return ToApiHandle<Value>(i::direct_handle(obj->resource_name(), i_isolate));
}

Local<Data> ScriptOrModule::HostDefinedOptions() {
  auto obj = Utils::OpenDirectHandle(this);
  i::Isolate* i_isolate = i::GetIsolateFromWritableObject(*obj);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  return ToApiHandle<Data>(
      i::direct_handle(obj->host_defined_options(), i_isolate));
}

Local<UnboundScript> Script::GetUnboundScript() {
  i::DisallowGarbageCollection no_gc;
  auto obj = Utils::OpenDirectHandle(this);
  i::DirectHandle<i::SharedFunctionInfo> sfi(obj->shared(), obj->GetIsolate());
  DCHECK(!i::HeapLayout::InReadOnlySpace(*sfi));
  return ToApiHandle<UnboundScript>(sfi);
}

Local<Value> Script::GetResourceName() {
  i::DisallowGarbageCollection no_gc;
  auto func = Utils::OpenDirectHandle(this);
  i::Tagged<i::SharedFunctionInfo> sfi = func->shared();
  CHECK(IsScript(sfi->script()));
  i::Isolate* i_isolate = func->GetIsolate();
  return ToApiHandle<Value>(
      i::direct_handle(i::Cast<i::Script>(sfi->script())->name(), i_isolate));
}

std::vector<int> Script::GetProducedCompileHints() const {
  i::DisallowGarbageCollection no_gc;
  auto func = Utils::OpenDirectHandle(this);
  i::Isolate* i_isolate = func->GetIsolate();
  i::Tagged<i::SharedFunctionInfo> sfi = func->shared();
  CHECK(IsScript(sfi->script()));
  i::Tagged<i::Script> script = i::Cast<i::Script>(sfi->script());
  i::Tagged<i::Object> maybe_array_list =
      script->compiled_lazy_function_positions();
  std::vector<int> result;
  if (!IsUndefined(maybe_array_list, i_isolate)) {
    i::Tagged<i::ArrayList> array_list =
        i::Cast<i::ArrayList>(maybe_array_list);
    result.reserve(array_list->length());
    for (int i = 0; i < array_list->length(); ++i) {
      i::Tagged<i::Object> item = array_list->get(i);
      CHECK(IsSmi(item));
      result.push_back(i::Smi::ToInt(item));
    }
  }
  return result;
}

Local<CompileHintsCollector> Script::GetCompileHintsCollector() const {
  i::DisallowGarbageCollection no_gc;
  auto func = Utils::OpenDirectHandle(this);
  i::Isolate* i_isolate = func->GetIsolate();
  i::Tagged<i::SharedFunctionInfo> sfi = func->shared();
  CHECK(IsScript(sfi->script()));
  i::DirectHandle<i::Script> script(i::Cast<i::Script>(sfi->script()),
                                    i_isolate);
  return ToApiHandle<CompileHintsCollector>(script);
}

std::vector<int> CompileHintsCollector::GetCompileHints(
    Isolate* v8_isolate) const {
  i::DisallowGarbageCollection no_gc;
  auto script = Utils::OpenDirectHandle(this);
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  i::Tagged<i::Object> maybe_array_list =
      script->compiled_lazy_function_positions();
  std::vector<int> result;
  if (!IsUndefined(maybe_array_list, i_isolate)) {
    i::Tagged<i::ArrayList> array_list =
        i::Cast<i::ArrayList>(maybe_array_list);
    result.reserve(array_list->length());
    for (int i = 0; i < array_list->length(); ++i) {
      i::Tagged<i::Object> item = array_list->get(i);
      CHECK(IsSmi(item));
      result.push_back(i::Smi::ToInt(item));
    }
  }
  return result;
}

// static
Local<PrimitiveArray> PrimitiveArray::New(Isolate* v8_isolate, int length) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  Utils::ApiCheck(length >= 0, "v8::PrimitiveArray::New",
                  "length must be equal or greater than zero");
  i::DirectHandle<i::FixedArray> array =
      i_isolate->factory()->NewFixedArray(length);
  return ToApiHandle<PrimitiveArray>(array);
}

int PrimitiveArray::Length() const {
  return Utils::OpenDirectHandle(this)->length();
}

void PrimitiveArray::Set(Isolate* v8_isolate, int index,
                         Local<Primitive> item) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  auto array = Utils::OpenDirectHandle(this);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  Utils::ApiCheck(index >= 0 && index < array->length(),
                  "v8::PrimitiveArray::Set",
                  "index must be greater than or equal to 0 and less than the "
                  "array length");
  array->set(index, *Utils::OpenDirectHandle(*item));
}

Local<Primitive> PrimitiveArray::Get(Isolate* v8_isolate, int index) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  auto array = Utils::OpenDirectHandle(this);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  Utils::ApiCheck(index >= 0 && index < array->length(),
                  "v8::PrimitiveArray::Get",
                  "index must be greater than or equal to 0 and less than the "
                  "array length");
  return ToApiHandle<Primitive>(i::direct_handle(array->get(index), i_isolate));
}

void v8::PrimitiveArray::CheckCast(v8::Data* that) {
  auto obj = Utils::OpenDirectHandle(that);
  Utils::ApiCheck(
      i::IsFixedArray(*obj), "v8::PrimitiveArray::Cast",
      "Value is not a PrimitiveArray; this is a temporary issue, v8::Data and "
      "v8::PrimitiveArray will not be compatible in the future");
}

int FixedArray::Length() const {
  return Utils::OpenDirectHandle(this)->length();
}

Local<Data> FixedArray::Get(Local<Context> context, int i) const {
  auto self = Utils::OpenDirectHandle(this);
  auto i_isolate = reinterpret_cast<i::Isolate*>(context->GetIsolate());
  CHECK_LT(i, self->length());
  return ToApiHandle<Data>(i::direct_handle(self->get(i), i_isolate));
}

Local<String> ModuleRequest::GetSpecifier() const {
  auto self = Utils::OpenDirectHandle(this);
  i::Isolate* i_isolate = self->GetIsolate();
  return ToApiHandle<String>(i::direct_handle(self->specifier(), i_isolate));
}

ModuleImportPhase ModuleRequest::GetPhase() const {
  auto self = Utils::OpenDirectHandle(this);
  return self->phase();
}

int ModuleRequest::GetSourceOffset() const {
  return Utils::OpenDirectHandle(this)->position();
}

Local<FixedArray> ModuleRequest::GetImportAttributes() const {
  auto self = Utils::OpenDirectHandle(this);
  i::Isolate* i_isolate = self->GetIsolate();
  return ToApiHandle<FixedArray>(
      i::direct_handle(self->import_attributes(), i_isolate));
}

Module::Status Module::GetStatus() const {
  auto self = Utils::OpenDirectHandle(this);
  switch (self->status()) {
    case i::Module::kUnlinked:
    case i::Module::kPreLinking:
      return kUninstantiated;
    case i::Module::kLinking:
      return kInstantiating;
    case i::Module::kLinked:
      return kInstantiated;
    case i::Module::kEvaluating:
      return kEvaluating;
    case i::Module::kEvaluatingAsync:
      // TODO(syg): Expose kEvaluatingAsync in API as well.
    case i::Module::kEvaluated:
      return kEvaluated;
    case i::Module::kErrored:
      return kErrored;
  }
  UNREACHABLE();
}

Local<Value> Module::GetException() const {
  Utils::ApiCheck(GetStatus() == kErrored, "v8::Module::GetException",
                  "Module status must be kErrored");
  auto self = Utils::OpenDirectHandle(this);
  i::Isolate* i_isolate = self->GetIsolate();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  return ToApiHandle<Value>(i::direct_handle(self->GetException(), i_isolate));
}

Local<FixedArray> Module::GetModuleRequests() const {
  auto self = Utils::OpenDirectHandle(this);
  i::Isolate* i_isolate = self->GetIsolate();
  DCHECK_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  if (i::IsSyntheticModule(*self)) {
    // Synthetic modules are leaf nodes in the module graph. They have no
    // ModuleRequests.
    return ToApiHandle<FixedArray>(
        self->GetReadOnlyRoots().empty_fixed_array_handle());
  } else {
    return ToApiHandle<FixedArray>(i::direct_handle(
        i::Cast<i::SourceTextModule>(self)->info()->module_requests(),
        i_isolate));
  }
}

Location Module::SourceOffsetToLocation(int offset) const {
  auto self = Utils::OpenDirectHandle(this);
  i::Isolate* i_isolate = self->GetIsolate();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::HandleScope scope(i_isolate);
  Utils::ApiCheck(
      i::IsSourceTextModule(*self), "v8::Module::SourceOffsetToLocation",
      "v8::Module::SourceOffsetToLocation must be used on an SourceTextModule");
  i::DirectHandle<i::Script> script(
      i::Cast<i::SourceTextModule>(self)->GetScript(), i_isolate);
  i::Script::PositionInfo info;
  i::Script::GetPositionInfo(script, offset, &info);
  return v8::Location(info.line, info.column);
}

Local<Value> Module::GetModuleNamespace() {
  Utils::ApiCheck(
      GetStatus() >= kInstantiated, "v8::Module::GetModuleNamespace",
      "v8::Module::GetModuleNamespace must be used on an instantiated module");
  auto self = Utils::OpenHandle(this);
  auto i_isolate = self->GetIsolate();
  DCHECK_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::DirectHandle<i::JSModuleNamespace> module_namespace =
      i::Module::GetModuleNamespace(i_isolate, self);
  return ToApiHandle<Value>(module_namespace);
}

Local<UnboundModuleScript> Module::GetUnboundModuleScript() {
  auto self = Utils::OpenDirectHandle(this);
  Utils::ApiCheck(
      i::IsSourceTextModule(*self), "v8::Module::GetUnboundModuleScript",
      "v8::Module::GetUnboundModuleScript must be used on an SourceTextModule");
  auto i_isolate = self->GetIsolate();
  DCHECK_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  return ToApiHandle<UnboundModuleScript>(i::direct_handle(
      i::Cast<i::SourceTextModule>(self)->GetSharedFunctionInfo(), i_isolate));
}

int Module::ScriptId() const {
  i::Tagged<i::Module> self = *Utils::OpenDirectHandle(this);
  Utils::ApiCheck(i::IsSourceTextModule(self), "v8::Module::ScriptId",
                  "v8::Module::ScriptId must be used on an SourceTextModule");
  DCHECK_NO_SCRIPT_NO_EXCEPTION(self->GetIsolate());
  return i::Cast<i::SourceTextModule>(self)->GetScript()->id();
}

bool Module::HasTopLevelAwait() const {
  i::Tagged<i::Module> self = *Utils::OpenDirectHandle(this);
  if (!i::IsSourceTextModule(self)) return false;
  return i::Cast<i::SourceTextModule>(self)->has_toplevel_await();
}

bool Module::IsGraphAsync() const {
  Utils::ApiCheck(
      GetStatus() >= kInstantiated, "v8::Module::IsGraphAsync",
      "v8::Module::IsGraphAsync must be used on an instantiated module");
  i::Tagged<i::Module> self = *Utils::OpenDirectHandle(this);
  auto i_isolate = self->GetIsolate();
  DCHECK_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  return self->IsGraphAsync(i_isolate);
}

bool Module::IsSourceTextModule() const {
  auto self = Utils::OpenDirectHandle(this);
  DCHECK_NO_SCRIPT_NO_EXCEPTION(self->GetIsolate());
  return i::IsSourceTextModule(*self);
}

bool Module::IsSyntheticModule() const {
  auto self = Utils::OpenDirectHandle(this);
  DCHECK_NO_SCRIPT_NO_EXCEPTION(self->GetIsolate());
  return i::IsSyntheticModule(*self);
}

int Module::GetIdentityHash() const {
  auto self = Utils::OpenDirectHandle(this);
  DCHECK_NO_SCRIPT_NO_EXCEPTION(self->GetIsolate());
  return self->hash();
}

Maybe<bool> Module::InstantiateModule(Local<Context> context,
                                      ResolveModuleCallback module_callback,
                                      ResolveSourceCallback source_callback) {
  auto i_isolate = reinterpret_cast<i::Isolate*>(context->GetIsolate());
  ENTER_V8(i_isolate, context, Module, InstantiateModule, i::HandleScope);
  has_exception =
      !i::Module::Instantiate(i_is
```