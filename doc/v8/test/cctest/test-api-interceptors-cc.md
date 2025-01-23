Response:
The user wants a summary of the provided C++ code for V8, specifically the file `v8/test/cctest/test-api-interceptors.cc`. I need to analyze the code and identify its main functionalities.

Here's a breakdown of the thought process:

1. **File Extension Check:** The first instruction is to check the file extension. The file ends with `.cc`, not `.tq`, so it's C++, not Torque. This eliminates the Torque-related condition.

2. **Core Functionality Identification:**  The filename "test-api-interceptors.cc" strongly suggests that the code is testing the V8 API related to interceptors. Interceptors are mechanisms in V8 to intercept property access (get, set, delete, etc.) and customize the behavior.

3. **Code Analysis - Focus on Callbacks and Handlers:**  A quick scan reveals numerous functions with names like `InterceptorGetter`, `InterceptorSetter`, `QueryCallback`, `GetterCallback`, `SetterCallback`, and configurations using `SetHandler` with `NamedPropertyHandlerConfiguration`. These are clear indicators of interceptor testing.

4. **Specific Interceptor Behaviors:**  Looking at the implementations of these callback functions:
    * Some return fixed values (like `Returns42`).
    * Some access private properties (like `InterceptorGetter` and `InterceptorSetter`).
    * Some perform checks on the property name (like `InterceptorGetter` looking for prefixes).
    * Some introduce side effects (like `EmptyInterceptorDefinerWithSideEffect`).
    * Some interact with internal V8 functions (like the GC in `InterceptorHasOwnPropertyCausingGC`).
    * Some are designed to test the order of execution (like `DefinerCallbackGetAndDefine`).
    * Some test specific scenarios, like how interceptors interact with `defineProperty`, function declarations, and object literals.
    * Several functions named `CheckThis...` are clearly for verifying the `this` object within the callbacks.

5. **JavaScript Relationship:** The code interacts heavily with the V8 API, which is the foundation for running JavaScript. The tests involve setting up interceptors on objects and then executing JavaScript code to trigger those interceptors. This directly relates to how JavaScript property access behaves when interceptors are in place.

6. **Example Generation (JavaScript):**  To illustrate the JavaScript relationship, I need a simple JavaScript example that would trigger an interceptor defined in the C++ code. A getter interceptor is a good starting point. I can create a JavaScript object, set up a getter interceptor in the C++ test, and then access a property on the JavaScript object.

7. **Code Logic Reasoning:**  Some tests involve specific logic, like the `QueryInterceptor` test. I need to consider what JavaScript operations trigger the query interceptor. `Object.getOwnPropertyDescriptor`, `Object.defineProperty`, `propertyIsEnumerable`, and `hasOwnProperty` are good examples. I can create scenarios with these operations and predict the counter values.

8. **Common Programming Errors:**  Interceptors are an advanced feature, and a common error would be misunderstanding the order of execution or the specific conditions under which different interceptor callbacks are invoked. An example is trying to define a non-configurable, non-writable property and then redeclaring a function with the same name.

9. **Structure and Organization:** The code is structured as a series of `THREADED_TEST` macros. Each test focuses on a particular aspect of interceptor behavior.

10. **Synthesis and Summarization:**  Based on the analysis, the main function of the code is to test the V8 API for interceptors. It covers various aspects like getter/setter interception, query interception, definer interception, deletion interception, and how interceptors interact with different JavaScript language features.

11. **Constraint Check (Part 1 of 8):** The prompt specifies "Part 1 of 8". This implies the need to keep the summary concise and focused on the provided code snippet, avoiding speculation about what might be in the subsequent parts.

By following these steps, I can generate a comprehensive and accurate summary of the provided V8 C++ test code.
这是位于 `v8/test/cctest/test-api-interceptors.cc` 的 V8 源代码文件，它**主要用于测试 V8 引擎中关于 API 拦截器 (API Interceptors) 的功能**.

**功能归纳:**

该文件包含了一系列的 C++ 测试用例，用于验证 V8 的 C++ API 中提供的各种拦截器机制是否按预期工作。这些测试覆盖了以下几个核心方面：

1. **属性访问拦截 (Getter/Setter Interceptors):** 测试当 JavaScript 代码尝试读取或设置对象的属性时，V8 的 C++ API 拦截器是否能够被正确地调用，并能够自定义属性的读取和设置行为。
2. **属性查询拦截 (Query Interceptors):** 测试当 JavaScript 代码查询对象的属性是否存在或其属性特性时（例如使用 `Object.getOwnPropertyDescriptor`，`hasOwnProperty` 等），V8 的 C++ API 拦截器是否能够被正确地调用。
3. **属性定义拦截 (Definer Interceptors):** 测试当 JavaScript 代码尝试定义对象的属性时（例如使用 `Object.defineProperty`），V8 的 C++ API 拦截器是否能够被正确地调用，并允许自定义属性的定义过程。
4. **属性删除拦截 (Deleter Interceptors):** 测试当 JavaScript 代码尝试删除对象的属性时，V8 的 C++ API 拦截器是否能够被正确地调用。
5. **属性枚举拦截 (Enumerator Interceptors):** 测试当 JavaScript 代码尝试枚举对象的属性时，V8 的 C++ API 拦截器是否能够被正确地调用。
6. **拦截器的返回值 (`v8::Intercepted`):** 测试不同的返回值 (`kYes`, `kNo`) 对拦截器行为的影响，例如是否继续执行默认的属性访问操作。
7. **`this` 对象的绑定:** 测试在拦截器回调函数中 `this` 对象是否指向预期的对象。
8. **特定场景的测试:** 包括拦截器与函数声明、对象字面量定义、`hasOwnProperty` 方法等的交互。
9. **非屏蔽拦截器 (Non-Masking Interceptors):** 测试非屏蔽拦截器的行为，即使属性已经存在，拦截器仍然会被调用。

**关于文件类型:**

`v8/test/cctest/test-api-interceptors.cc` 的文件扩展名是 `.cc`，这表明它是一个 **C++ 源代码文件**，而不是 Torque 源代码文件（Torque 文件以 `.tq` 结尾）。

**与 JavaScript 的关系和示例:**

V8 的 C++ API 拦截器允许 C++ 代码介入 JavaScript 对象的属性访问过程，从而实现高度定制的行为。

**JavaScript 示例：**

假设我们在 C++ 中定义了一个对象模板，并为其设置了一个 getter 拦截器，当访问名为 `myProperty` 的属性时，拦截器会返回固定的值 42。

```cpp
// C++ 代码片段 (简化)
void MyGetter(v8::Local<v8::Name> name,
              const v8::PropertyCallbackInfo<v8::Value>& info) {
  info.GetReturnValue().Set(v8::Integer::New(info.GetIsolate(), 42));
}

// ... 在对象模板上设置拦截器
templ->InstanceTemplate()->SetHandler(v8::NamedPropertyHandlerConfiguration(
    MyGetter, /* setter, query, deleter, enumerator, definer */ nullptr, nullptr, nullptr, nullptr, nullptr));
```

现在，在 JavaScript 中使用这个对象：

```javascript
// JavaScript 代码
let myObject = new MyConstructor(); // MyConstructor 是基于上面 C++ 模板创建的构造函数
console.log(myObject.myProperty); // 输出 42，即使对象本身可能没有名为 myProperty 的属性
```

在这个例子中，当 JavaScript 代码尝试访问 `myObject.myProperty` 时，C++ 中定义的 `MyGetter` 拦截器会被调用，并返回 42，而不是访问 `myObject` 自身。

**代码逻辑推理和假设输入输出:**

考虑 `Return239Callback` 这个函数：

```cpp
void Return239Callback(Local<Name> name,
                       const v8::PropertyCallbackInfo<Value>& info) {
  ApiTestFuzzer::Fuzz();
  CheckReturnValue(info, FUNCTION_ADDR(Return239Callback));
  info.GetReturnValue().Set(v8_str("bad value"));
  info.GetReturnValue().Set(v8_num(239));
}
```

**假设输入：** JavaScript 代码尝试读取一个设置了 `Return239Callback` 作为 getter 拦截器的属性。例如：

```javascript
let obj = new MyConstructorWithInterceptor();
console.log(obj.someProperty);
```

**代码逻辑推理：**

1. 当访问 `obj.someProperty` 时，`Return239Callback` 会被调用。
2. `ApiTestFuzzer::Fuzz()` 会执行一些模糊测试相关的操作（这里不深入讨论其具体行为）。
3. `CheckReturnValue` 会进行一些检查，确保 `info` 参数的某些状态符合预期。
4. `info.GetReturnValue().Set(v8_str("bad value"));`  尝试将返回值设置为字符串 "bad value"。
5. `info.GetReturnValue().Set(v8_num(239));`  然后将返回值设置为数字 239。

**输出：**  最终 JavaScript 代码 `console.log(obj.someProperty)` 会输出 `239`。  **注意：**  `GetReturnValue().Set()` 会覆盖之前设置的值，所以只有最后一次 `Set()` 的值会生效。

**用户常见的编程错误:**

使用 V8 API 拦截器时，用户可能会犯以下错误：

1. **忘记设置 `v8::Intercepted` 的返回值：**  如果不返回 `v8::Intercepted::kYes` 来表明拦截器已经处理了请求，V8 可能会继续执行默认的属性访问逻辑，导致意外的行为。

   **C++ 示例错误：**

   ```cpp
   v8::Intercepted MyBadGetter(
       Local<Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
     // 忘记设置返回值
     info.GetReturnValue().Set(v8::Integer::New(info.GetIsolate(), 42));
     // 应该返回 v8::Intercepted::kYes;
   }
   ```

   **后果：**  V8 可能会在 `MyBadGetter` 执行后，仍然尝试获取属性的默认值，导致逻辑错误或性能问题。

2. **在 setter 拦截器中修改了不应该修改的状态：**  Setter 拦截器的目的是处理属性的设置操作，不应该在其中引入与设置操作无关的副作用，这可能导致程序状态混乱。

   **C++ 示例错误：**

   ```cpp
   v8::Intercepted MySideEffectSetter(
       Local<Name> name, Local<Value> value,
       const v8::PropertyCallbackInfo<void>& info) {
     // 不应该在这里修改全局变量或执行其他副作用
     extern int globalCounter;
     globalCounter++;
     // ... 设置属性值
     return v8::Intercepted::kYes;
   }
   ```

   **后果：**  程序的行为可能变得难以预测和调试，因为属性设置操作会意外地影响其他部分的代码。

**总结 (针对第 1 部分):**

`v8/test/cctest/test-api-interceptors.cc` 的第一部分主要定义了一些辅助函数和最初的测试用例，**旨在验证 V8 的 C++ API 提供的各种属性访问拦截器机制的基本功能和行为是否符合预期**。它涵盖了 getter、setter 拦截器的基本用法，以及一些简单的场景测试。这些测试为后续更复杂的拦截器测试奠定了基础。

### 提示词
```
这是目录为v8/test/cctest/test-api-interceptors.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-api-interceptors.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdlib.h>

#include <optional>

#include "include/v8-function.h"
#include "src/api/api-inl.h"
#include "src/codegen/compilation-cache.h"
#include "src/execution/execution.h"
#include "src/objects/objects-inl.h"
#include "src/objects/objects.h"
#include "src/runtime/runtime.h"
#include "src/strings/unicode-inl.h"
#include "test/cctest/heap/heap-utils.h"
#include "test/cctest/test-api.h"

using ::v8::Context;
using ::v8::Function;
using ::v8::FunctionTemplate;
using ::v8::Local;
using ::v8::Name;
using ::v8::Object;
using ::v8::ObjectTemplate;
using ::v8::Script;
using ::v8::String;
using ::v8::Symbol;
using ::v8::Value;

namespace {

void Returns42(const v8::FunctionCallbackInfo<v8::Value>& info) {
  info.GetReturnValue().Set(42);
}

void Return239Callback(Local<Name> name,
                       const v8::PropertyCallbackInfo<Value>& info) {
  ApiTestFuzzer::Fuzz();
  CheckReturnValue(info, FUNCTION_ADDR(Return239Callback));
  info.GetReturnValue().Set(v8_str("bad value"));
  info.GetReturnValue().Set(v8_num(239));
}

v8::Intercepted EmptyInterceptorGetter(
    Local<Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  return v8::Intercepted::kNo;
}

v8::Intercepted EmptyInterceptorSetter(
    Local<Name> name, Local<Value> value,
    const v8::PropertyCallbackInfo<void>& info) {
  return v8::Intercepted::kNo;
}

v8::Intercepted EmptyInterceptorQuery(
    Local<Name> name, const v8::PropertyCallbackInfo<v8::Integer>& info) {
  return v8::Intercepted::kNo;
}

v8::Intercepted EmptyInterceptorDeleter(
    Local<Name> name, const v8::PropertyCallbackInfo<v8::Boolean>& info) {
  return v8::Intercepted::kNo;
}

void EmptyInterceptorEnumerator(
    const v8::PropertyCallbackInfo<v8::Array>& info) {}

v8::Intercepted EmptyInterceptorDefinerWithSideEffect(
    Local<Name> name, const v8::PropertyDescriptor& desc,
    const v8::PropertyCallbackInfo<void>& info) {
  ApiTestFuzzer::Fuzz();
  v8::Local<v8::Value> result = CompileRun("interceptor_definer_side_effect()");
  if (!result->IsNull()) {
    return v8::Intercepted::kYes;
  }
  return v8::Intercepted::kNo;
}

void SimpleGetterImpl(Local<String> name_str,
                      const v8::FunctionCallbackInfo<v8::Value>& info) {
  Local<Object> self = info.This();
  info.GetReturnValue().Set(
      self->Get(
              info.GetIsolate()->GetCurrentContext(),
              String::Concat(info.GetIsolate(), v8_str("accessor_"), name_str))
          .ToLocalChecked());
}

void SimpleSetterImpl(Local<String> name_str,
                      const v8::FunctionCallbackInfo<v8::Value>& info) {
  Local<Object> self = info.This();
  Local<Value> value = info[0];
  self->Set(info.GetIsolate()->GetCurrentContext(),
            String::Concat(info.GetIsolate(), v8_str("accessor_"), name_str),
            value)
      .FromJust();
}

void SimpleGetterCallback(const v8::FunctionCallbackInfo<v8::Value>& args) {
  Local<String> name_str = args.Data().As<String>();
  SimpleGetterImpl(name_str, args);
}

void SimpleSetterCallback(const v8::FunctionCallbackInfo<v8::Value>& info) {
  Local<String> name_str = info.Data().As<String>();
  SimpleSetterImpl(name_str, info);
}

void SymbolGetterCallback(const v8::FunctionCallbackInfo<v8::Value>& info) {
  Local<Name> name = info.Data().As<Name>();
  CHECK(name->IsSymbol());
  v8::Isolate* isolate = info.GetIsolate();
  Local<Symbol> sym = name.As<Symbol>();
  if (sym->Description(isolate)->IsUndefined()) return;
  SimpleGetterImpl(sym->Description(isolate).As<String>(), info);
}

void SymbolSetterCallback(const v8::FunctionCallbackInfo<v8::Value>& info) {
  Local<Name> name = info.Data().As<Name>();
  CHECK(name->IsSymbol());
  v8::Isolate* isolate = info.GetIsolate();
  Local<Symbol> sym = name.As<Symbol>();
  if (sym->Description(isolate)->IsUndefined()) return;
  SimpleSetterImpl(sym->Description(isolate).As<String>(), info);
}

v8::Intercepted InterceptorGetter(
    Local<Name> generic_name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  if (generic_name->IsSymbol()) return v8::Intercepted::kNo;
  Local<String> name = generic_name.As<String>();
  String::Utf8Value utf8(info.GetIsolate(), name);
  char* name_str = *utf8;
  char prefix[] = "interceptor_";
  int i;
  for (i = 0; name_str[i] && prefix[i]; ++i) {
    if (name_str[i] != prefix[i]) return v8::Intercepted::kNo;
  }
  Local<Object> self = info.This().As<Object>();
  info.GetReturnValue().Set(
      self->GetPrivate(
              info.GetIsolate()->GetCurrentContext(),
              v8::Private::ForApi(info.GetIsolate(), v8_str(name_str + i)))
          .ToLocalChecked());
  return v8::Intercepted::kYes;
}

v8::Intercepted InterceptorSetter(Local<Name> generic_name, Local<Value> value,
                                  const v8::PropertyCallbackInfo<void>& info) {
  if (generic_name->IsSymbol()) return v8::Intercepted::kNo;
  Local<String> name = generic_name.As<String>();
  // Intercept accesses that set certain integer values, for which the name does
  // not start with 'accessor_'.
  String::Utf8Value utf8(info.GetIsolate(), name);
  char* name_str = *utf8;
  char prefix[] = "accessor_";
  int i;
  for (i = 0; name_str[i] && prefix[i]; ++i) {
    if (name_str[i] != prefix[i]) break;
  }
  if (!prefix[i]) return v8::Intercepted::kNo;

  Local<Context> context = info.GetIsolate()->GetCurrentContext();
  if (value->IsInt32() && value->Int32Value(context).FromJust() < 10000) {
    Local<Object> self = info.This().As<Object>();
    Local<v8::Private> symbol = v8::Private::ForApi(info.GetIsolate(), name);
    self->SetPrivate(context, symbol, value).FromJust();
    return v8::Intercepted::kYes;
  }
  return v8::Intercepted::kNo;
}

v8::Intercepted GenericInterceptorGetter(
    Local<Name> generic_name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  v8::Isolate* isolate = info.GetIsolate();
  Local<String> str;
  if (generic_name->IsSymbol()) {
    Local<Value> name = generic_name.As<Symbol>()->Description(isolate);
    if (name->IsUndefined()) return v8::Intercepted::kNo;
    str = String::Concat(info.GetIsolate(), v8_str("_sym_"), name.As<String>());
  } else {
    Local<String> name = generic_name.As<String>();
    String::Utf8Value utf8(info.GetIsolate(), name);
    char* name_str = *utf8;
    if (*name_str == '_') return v8::Intercepted::kNo;
    str = String::Concat(info.GetIsolate(), v8_str("_str_"), name);
  }

  Local<Object> self = info.This().As<Object>();
  info.GetReturnValue().Set(
      self->Get(info.GetIsolate()->GetCurrentContext(), str).ToLocalChecked());
  return v8::Intercepted::kYes;
}

v8::Intercepted GenericInterceptorSetter(
    Local<Name> generic_name, Local<Value> value,
    const v8::PropertyCallbackInfo<void>& info) {
  v8::Isolate* isolate = info.GetIsolate();
  Local<String> str;
  if (generic_name->IsSymbol()) {
    Local<Value> name = generic_name.As<Symbol>()->Description(isolate);
    if (name->IsUndefined()) return v8::Intercepted::kNo;
    str = String::Concat(info.GetIsolate(), v8_str("_sym_"), name.As<String>());
  } else {
    Local<String> name = generic_name.As<String>();
    String::Utf8Value utf8(info.GetIsolate(), name);
    char* name_str = *utf8;
    if (*name_str == '_') return v8::Intercepted::kNo;
    str = String::Concat(info.GetIsolate(), v8_str("_str_"), name);
  }

  Local<Object> self = info.This().As<Object>();
  self->Set(info.GetIsolate()->GetCurrentContext(), str, value).FromJust();
  return v8::Intercepted::kYes;
}

void AddAccessor(v8::Isolate* isolate, Local<FunctionTemplate> templ,
                 Local<Name> name, v8::FunctionCallback getter,
                 v8::FunctionCallback setter) {
  Local<FunctionTemplate> getter_templ =
      FunctionTemplate::New(isolate, getter, name);
  Local<FunctionTemplate> setter_templ =
      FunctionTemplate::New(isolate, setter, name);

  templ->PrototypeTemplate()->SetAccessorProperty(name, getter_templ,
                                                  setter_templ);
}

void AddStringOnlyInterceptor(Local<FunctionTemplate> templ,
                              v8::NamedPropertyGetterCallback getter,
                              v8::NamedPropertySetterCallback setter) {
  templ->InstanceTemplate()->SetHandler(v8::NamedPropertyHandlerConfiguration(
      getter, setter, nullptr, nullptr, nullptr, Local<v8::Value>(),
      v8::PropertyHandlerFlags::kOnlyInterceptStrings));
}

void AddInterceptor(Local<FunctionTemplate> templ,
                    v8::NamedPropertyGetterCallback getter,
                    v8::NamedPropertySetterCallback setter) {
  templ->InstanceTemplate()->SetHandler(
      v8::NamedPropertyHandlerConfiguration(getter, setter));
}

v8::Global<v8::Object> bottom_global;

v8::Intercepted CheckThisIndexedPropertyHandler(
    uint32_t index, const v8::PropertyCallbackInfo<v8::Value>& info) {
  v8::Isolate* isolate = info.GetIsolate();
  CheckReturnValue(info, FUNCTION_ADDR(CheckThisIndexedPropertyHandler));
  // The request is not intercepted so don't call ApiTestFuzzer::Fuzz() here.
  CHECK(info.This()
            ->Equals(isolate->GetCurrentContext(), bottom_global.Get(isolate))
            .FromJust());
  return v8::Intercepted::kNo;
}

v8::Intercepted CheckThisNamedPropertyHandler(
    Local<Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  v8::Isolate* isolate = info.GetIsolate();
  CheckReturnValue(info, FUNCTION_ADDR(CheckThisNamedPropertyHandler));
  // The request is not intercepted so don't call ApiTestFuzzer::Fuzz() here.
  CHECK(info.This()
            ->Equals(isolate->GetCurrentContext(), bottom_global.Get(isolate))
            .FromJust());
  return v8::Intercepted::kNo;
}

v8::Intercepted CheckThisIndexedPropertyDefiner(
    uint32_t index, const v8::PropertyDescriptor& desc,
    const v8::PropertyCallbackInfo<void>& info) {
  v8::Isolate* isolate = info.GetIsolate();
  CheckReturnValue(info, FUNCTION_ADDR(CheckThisIndexedPropertyDefiner));
  // The request is not intercepted so don't call ApiTestFuzzer::Fuzz() here.
  CHECK(info.This()
            ->Equals(isolate->GetCurrentContext(), bottom_global.Get(isolate))
            .FromJust());
  return v8::Intercepted::kNo;
}

v8::Intercepted CheckThisNamedPropertyDefiner(
    Local<Name> property, const v8::PropertyDescriptor& desc,
    const v8::PropertyCallbackInfo<void>& info) {
  v8::Isolate* isolate = info.GetIsolate();
  CheckReturnValue(info, FUNCTION_ADDR(CheckThisNamedPropertyDefiner));
  // The request is not intercepted so don't call ApiTestFuzzer::Fuzz() here.
  CHECK(info.This()
            ->Equals(isolate->GetCurrentContext(), bottom_global.Get(isolate))
            .FromJust());
  return v8::Intercepted::kNo;
}

v8::Intercepted CheckThisIndexedPropertySetter(
    uint32_t index, Local<Value> value,
    const v8::PropertyCallbackInfo<void>& info) {
  v8::Isolate* isolate = info.GetIsolate();
  CheckReturnValue(info, FUNCTION_ADDR(CheckThisIndexedPropertySetter));
  // The request is not intercepted so don't call ApiTestFuzzer::Fuzz() here.
  CHECK(info.This()
            ->Equals(isolate->GetCurrentContext(), bottom_global.Get(isolate))
            .FromJust());
  return v8::Intercepted::kNo;
}

v8::Intercepted CheckThisNamedPropertySetter(
    Local<Name> property, Local<Value> value,
    const v8::PropertyCallbackInfo<void>& info) {
  v8::Isolate* isolate = info.GetIsolate();
  CheckReturnValue(info, FUNCTION_ADDR(CheckThisNamedPropertySetter));
  // The request is not intercepted so don't call ApiTestFuzzer::Fuzz() here.
  CHECK(info.This()
            ->Equals(isolate->GetCurrentContext(), bottom_global.Get(isolate))
            .FromJust());
  return v8::Intercepted::kNo;
}

v8::Intercepted CheckThisIndexedPropertyDescriptor(
    uint32_t index, const v8::PropertyCallbackInfo<v8::Value>& info) {
  v8::Isolate* isolate = info.GetIsolate();
  CheckReturnValue(info, FUNCTION_ADDR(CheckThisIndexedPropertyDescriptor));
  // The request is not intercepted so don't call ApiTestFuzzer::Fuzz() here.
  CHECK(info.This()
            ->Equals(isolate->GetCurrentContext(), bottom_global.Get(isolate))
            .FromJust());
  return v8::Intercepted::kNo;
}

v8::Intercepted CheckThisNamedPropertyDescriptor(
    Local<Name> property, const v8::PropertyCallbackInfo<v8::Value>& info) {
  v8::Isolate* isolate = info.GetIsolate();
  CheckReturnValue(info, FUNCTION_ADDR(CheckThisNamedPropertyDescriptor));
  // The request is not intercepted so don't call ApiTestFuzzer::Fuzz() here.
  CHECK(info.This()
            ->Equals(isolate->GetCurrentContext(), bottom_global.Get(isolate))
            .FromJust());
  return v8::Intercepted::kNo;
}

v8::Intercepted CheckThisIndexedPropertyQuery(
    uint32_t index, const v8::PropertyCallbackInfo<v8::Integer>& info) {
  v8::Isolate* isolate = info.GetIsolate();
  CheckReturnValue(info, FUNCTION_ADDR(CheckThisIndexedPropertyQuery));
  // The request is not intercepted so don't call ApiTestFuzzer::Fuzz() here.
  CHECK(info.This()
            ->Equals(isolate->GetCurrentContext(), bottom_global.Get(isolate))
            .FromJust());
  return v8::Intercepted::kNo;
}

v8::Intercepted CheckThisNamedPropertyQuery(
    Local<Name> property, const v8::PropertyCallbackInfo<v8::Integer>& info) {
  v8::Isolate* isolate = info.GetIsolate();
  CheckReturnValue(info, FUNCTION_ADDR(CheckThisNamedPropertyQuery));
  // The request is not intercepted so don't call ApiTestFuzzer::Fuzz() here.
  CHECK(info.This()
            ->Equals(isolate->GetCurrentContext(), bottom_global.Get(isolate))
            .FromJust());
  return v8::Intercepted::kNo;
}

v8::Intercepted CheckThisIndexedPropertyDeleter(
    uint32_t index, const v8::PropertyCallbackInfo<v8::Boolean>& info) {
  v8::Isolate* isolate = info.GetIsolate();
  CheckReturnValue(info, FUNCTION_ADDR(CheckThisIndexedPropertyDeleter));
  // The request is not intercepted so don't call ApiTestFuzzer::Fuzz() here.
  CHECK(info.This()
            ->Equals(isolate->GetCurrentContext(), bottom_global.Get(isolate))
            .FromJust());
  return v8::Intercepted::kNo;
}

v8::Intercepted CheckThisNamedPropertyDeleter(
    Local<Name> property, const v8::PropertyCallbackInfo<v8::Boolean>& info) {
  v8::Isolate* isolate = info.GetIsolate();
  CheckReturnValue(info, FUNCTION_ADDR(CheckThisNamedPropertyDeleter));
  // The request is not intercepted so don't call ApiTestFuzzer::Fuzz() here.
  CHECK(info.This()
            ->Equals(isolate->GetCurrentContext(), bottom_global.Get(isolate))
            .FromJust());
  return v8::Intercepted::kNo;
}

void CheckThisIndexedPropertyEnumerator(
    const v8::PropertyCallbackInfo<v8::Array>& info) {
  v8::Isolate* isolate = info.GetIsolate();
  CheckReturnValue(info, FUNCTION_ADDR(CheckThisIndexedPropertyEnumerator));
  // The request is not intercepted so don't call ApiTestFuzzer::Fuzz() here.
  CHECK(info.This()
            ->Equals(isolate->GetCurrentContext(), bottom_global.Get(isolate))
            .FromJust());
}


void CheckThisNamedPropertyEnumerator(
    const v8::PropertyCallbackInfo<v8::Array>& info) {
  v8::Isolate* isolate = info.GetIsolate();
  CheckReturnValue(info, FUNCTION_ADDR(CheckThisNamedPropertyEnumerator));
  // The request is not intercepted so don't call ApiTestFuzzer::Fuzz() here.
  CHECK(info.This()
            ->Equals(isolate->GetCurrentContext(), bottom_global.Get(isolate))
            .FromJust());
}


int echo_named_call_count;

v8::Intercepted EchoNamedProperty(
    Local<Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  ApiTestFuzzer::Fuzz();
  CHECK(v8_str("data")
            ->Equals(info.GetIsolate()->GetCurrentContext(), info.Data())
            .FromJust());
  echo_named_call_count++;
  info.GetReturnValue().Set(name);
  return v8::Intercepted::kYes;
}

v8::Intercepted InterceptorHasOwnPropertyGetter(
    Local<Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  // The request is not intercepted so don't call ApiTestFuzzer::Fuzz() here.
  return v8::Intercepted::kNo;
}

v8::Intercepted InterceptorHasOwnPropertyGetterGC(
    Local<Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  // The request is not intercepted so don't call ApiTestFuzzer::Fuzz() here.
  i::heap::InvokeMajorGC(CcTest::heap());
  return v8::Intercepted::kNo;
}

int query_counter_int = 0;

v8::Intercepted QueryCallback(
    Local<Name> property, const v8::PropertyCallbackInfo<v8::Integer>& info) {
  query_counter_int++;
  return v8::Intercepted::kNo;
}

}  // namespace

// Examples that show when the query callback is triggered.
THREADED_TEST(QueryInterceptor) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::FunctionTemplate> templ = v8::FunctionTemplate::New(isolate);
  templ->InstanceTemplate()->SetHandler(
      v8::NamedPropertyHandlerConfiguration(nullptr, nullptr, QueryCallback));
  LocalContext env;
  env->Global()
      ->Set(env.local(), v8_str("obj"), templ->GetFunction(env.local())
                                            .ToLocalChecked()
                                            ->NewInstance(env.local())
                                            .ToLocalChecked())
      .FromJust();
  CHECK_EQ(0, query_counter_int);
  v8::Local<Value> result =
      v8_compile("Object.getOwnPropertyDescriptor(obj, 'x');")
          ->Run(env.local())
          .ToLocalChecked();
  CHECK_EQ(1, query_counter_int);
  CHECK_EQ(v8::PropertyAttribute::None,
           static_cast<v8::PropertyAttribute>(
               result->Int32Value(env.local()).FromJust()));

  v8_compile("Object.defineProperty(obj, 'not_enum', {value: 17});")
      ->Run(env.local())
      .ToLocalChecked();
  CHECK_EQ(2, query_counter_int);

  v8_compile(
      "Object.defineProperty(obj, 'enum', {value: 17, enumerable: true, "
      "writable: true});")
      ->Run(env.local())
      .ToLocalChecked();
  CHECK_EQ(3, query_counter_int);

  CHECK(v8_compile("obj.propertyIsEnumerable('enum');")
            ->Run(env.local())
            .ToLocalChecked()
            ->BooleanValue(isolate));
  CHECK_EQ(4, query_counter_int);

  CHECK(!v8_compile("obj.propertyIsEnumerable('not_enum');")
             ->Run(env.local())
             .ToLocalChecked()
             ->BooleanValue(isolate));
  CHECK_EQ(5, query_counter_int);

  CHECK(v8_compile("obj.hasOwnProperty('enum');")
            ->Run(env.local())
            .ToLocalChecked()
            ->BooleanValue(isolate));
  CHECK_EQ(5, query_counter_int);

  CHECK(v8_compile("obj.hasOwnProperty('not_enum');")
            ->Run(env.local())
            .ToLocalChecked()
            ->BooleanValue(isolate));
  CHECK_EQ(5, query_counter_int);

  CHECK(!v8_compile("obj.hasOwnProperty('x');")
             ->Run(env.local())
             .ToLocalChecked()
             ->BooleanValue(isolate));
  CHECK_EQ(6, query_counter_int);

  CHECK(!v8_compile("obj.propertyIsEnumerable('undef');")
             ->Run(env.local())
             .ToLocalChecked()
             ->BooleanValue(isolate));
  CHECK_EQ(7, query_counter_int);

  v8_compile("Object.defineProperty(obj, 'enum', {value: 42});")
      ->Run(env.local())
      .ToLocalChecked();
  CHECK_EQ(8, query_counter_int);

  v8_compile("Object.isFrozen('obj.x');")->Run(env.local()).ToLocalChecked();
  CHECK_EQ(8, query_counter_int);

  v8_compile("'x' in obj;")->Run(env.local()).ToLocalChecked();
  CHECK_EQ(9, query_counter_int);
}

namespace {

bool get_was_called = false;
bool set_was_called = false;

int set_was_called_counter = 0;

v8::Intercepted GetterCallback(
    Local<Name> property, const v8::PropertyCallbackInfo<v8::Value>& info) {
  get_was_called = true;
  return v8::Intercepted::kNo;
}

v8::Intercepted SetterCallback(Local<Name> property, Local<Value> value,
                               const v8::PropertyCallbackInfo<void>& info) {
  set_was_called = true;
  set_was_called_counter++;
  return v8::Intercepted::kNo;
}

v8::Intercepted InterceptingSetterCallback(
    Local<Name> property, Local<Value> value,
    const v8::PropertyCallbackInfo<void>& info) {
  return v8::Intercepted::kYes;
}

}  // namespace

// Check that get callback is called in defineProperty with accessor descriptor.
THREADED_TEST(DefinerCallbackAccessorInterceptor) {
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::FunctionTemplate> templ =
      v8::FunctionTemplate::New(CcTest::isolate());
  templ->InstanceTemplate()->SetHandler(
      v8::NamedPropertyHandlerConfiguration(GetterCallback, SetterCallback));
  LocalContext env;
  env->Global()
      ->Set(env.local(), v8_str("obj"), templ->GetFunction(env.local())
                                            .ToLocalChecked()
                                            ->NewInstance(env.local())
                                            .ToLocalChecked())
      .FromJust();

  get_was_called = false;
  set_was_called = false;

  v8_compile("Object.defineProperty(obj, 'x', {set: function() {return 17;}});")
      ->Run(env.local())
      .ToLocalChecked();
  CHECK(get_was_called);
  CHECK(!set_was_called);
}

// Check that set callback is called for function declarations.
THREADED_TEST(SetterCallbackFunctionDeclarationInterceptor) {
  v8::HandleScope scope(CcTest::isolate());
  LocalContext env;
  v8::Local<v8::FunctionTemplate> templ =
      v8::FunctionTemplate::New(CcTest::isolate());

  v8::Local<ObjectTemplate> object_template = templ->InstanceTemplate();
  object_template->SetHandler(
      v8::NamedPropertyHandlerConfiguration(nullptr, SetterCallback));
  v8::Local<v8::Context> ctx =
      v8::Context::New(CcTest::isolate(), nullptr, object_template);

  set_was_called_counter = 0;

  // Declare function.
  v8::Local<v8::String> code = v8_str("function x() {return 42;}; x();");
  CHECK_EQ(42, v8::Script::Compile(ctx, code)
                   .ToLocalChecked()
                   ->Run(ctx)
                   .ToLocalChecked()
                   ->Int32Value(ctx)
                   .FromJust());
  CHECK_EQ(1, set_was_called_counter);

  // Redeclare function.
  code = v8_str("function x() {return 43;}; x();");
  CHECK_EQ(43, v8::Script::Compile(ctx, code)
                   .ToLocalChecked()
                   ->Run(ctx)
                   .ToLocalChecked()
                   ->Int32Value(ctx)
                   .FromJust());
  CHECK_EQ(2, set_was_called_counter);

  // Redefine function.
  code = v8_str("x = function() {return 44;}; x();");
  CHECK_EQ(44, v8::Script::Compile(ctx, code)
                   .ToLocalChecked()
                   ->Run(ctx)
                   .ToLocalChecked()
                   ->Int32Value(ctx)
                   .FromJust());
  CHECK_EQ(3, set_was_called_counter);
}

namespace {
int descriptor_was_called;

v8::Intercepted PropertyDescriptorCallback(
    Local<Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  // Intercept the callback and create some descriptor.
  descriptor_was_called++;
  const char* code =
      "var desc = {value: 5};"
      "desc;";
  Local<Value> descriptor = v8_compile(code)
                                ->Run(info.GetIsolate()->GetCurrentContext())
                                .ToLocalChecked();
  info.GetReturnValue().Set(descriptor);
  return v8::Intercepted::kYes;
}
}  // namespace

// Check that the descriptor callback is called on the global object.
THREADED_TEST(DescriptorCallbackOnGlobalObject) {
  v8::HandleScope scope(CcTest::isolate());
  LocalContext env;
  v8::Local<v8::FunctionTemplate> templ =
      v8::FunctionTemplate::New(CcTest::isolate());

  v8::Local<ObjectTemplate> object_template = templ->InstanceTemplate();
  object_template->SetHandler(v8::NamedPropertyHandlerConfiguration(
      nullptr, nullptr, PropertyDescriptorCallback, nullptr, nullptr, nullptr));
  v8::Local<v8::Context> ctx =
      v8::Context::New(CcTest::isolate(), nullptr, object_template);

  descriptor_was_called = 0;

  // Declare function.
  v8::Local<v8::String> code = v8_str(
      "var x = 42; var desc = Object.getOwnPropertyDescriptor(this, 'x'); "
      "desc.value;");
  CHECK_EQ(5, v8::Script::Compile(ctx, code)
                  .ToLocalChecked()
                  ->Run(ctx)
                  .ToLocalChecked()
                  ->Int32Value(ctx)
                  .FromJust());
  CHECK_EQ(1, descriptor_was_called);
}

namespace {
v8::Intercepted QueryCallbackSetDontDelete(
    Local<Name> property, const v8::PropertyCallbackInfo<v8::Integer>& info) {
  info.GetReturnValue().Set(v8::DontDelete);
  return v8::Intercepted::kYes;
}

}  // namespace

// Regression for a Node.js test that fails in debug mode.
THREADED_TEST(InterceptorFunctionRedeclareWithQueryCallback) {
  v8::HandleScope scope(CcTest::isolate());
  LocalContext env;
  v8::Local<v8::FunctionTemplate> templ =
      v8::FunctionTemplate::New(CcTest::isolate());

  v8::Local<ObjectTemplate> object_template = templ->InstanceTemplate();
  object_template->SetHandler(v8::NamedPropertyHandlerConfiguration(
      nullptr, nullptr, QueryCallbackSetDontDelete));
  v8::Local<v8::Context> ctx =
      v8::Context::New(CcTest::isolate(), nullptr, object_template);

  // Declare and redeclare function.
  v8::Local<v8::String> code = v8_str(
      "function x() {return 42;};"
      "function x() {return 43;};");
  v8::Script::Compile(ctx, code).ToLocalChecked()->Run(ctx).ToLocalChecked();
}

// Regression test for chromium bug 656648.
// Do not crash on non-masking, intercepting setter callbacks.
THREADED_TEST(NonMaskingInterceptor) {
  v8::HandleScope scope(CcTest::isolate());
  LocalContext env;
  v8::Local<v8::FunctionTemplate> templ =
      v8::FunctionTemplate::New(CcTest::isolate());

  v8::Local<ObjectTemplate> object_template = templ->InstanceTemplate();
  object_template->SetHandler(v8::NamedPropertyHandlerConfiguration(
      nullptr, InterceptingSetterCallback, nullptr, nullptr, nullptr,
      Local<Value>(), v8::PropertyHandlerFlags::kNonMasking));
  v8::Local<v8::Context> ctx =
      v8::Context::New(CcTest::isolate(), nullptr, object_template);

  v8::Local<v8::String> code = v8_str("function x() {return 43;};");
  v8::Script::Compile(ctx, code).ToLocalChecked()->Run(ctx).ToLocalChecked();
}

// Check that function re-declarations throw if they are read-only.
THREADED_TEST(SetterCallbackFunctionDeclarationInterceptorThrow) {
  v8::HandleScope scope(CcTest::isolate());
  LocalContext env;
  v8::Local<v8::FunctionTemplate> templ =
      v8::FunctionTemplate::New(CcTest::isolate());

  v8::Local<ObjectTemplate> object_template = templ->InstanceTemplate();
  object_template->SetHandler(
      v8::NamedPropertyHandlerConfiguration(nullptr, SetterCallback));
  v8::Local<v8::Context> ctx =
      v8::Context::New(CcTest::isolate(), nullptr, object_template);

  set_was_called = false;

  v8::Local<v8::String> code = v8_str(
      "function x() {return 42;};"
      "Object.defineProperty(this, 'x', {"
      "configurable: false, "
      "writable: false});"
      "x();");
  CHECK_EQ(42, v8::Script::Compile(ctx, code)
                   .ToLocalChecked()
                   ->Run(ctx)
                   .ToLocalChecked()
                   ->Int32Value(ctx)
                   .FromJust());

  CHECK(set_was_called);

  v8::TryCatch try_catch(CcTest::isolate());
  set_was_called = false;

  // Redeclare function that is read-only.
  code = v8_str("function x() {return 43;};");
  CHECK(v8::Script::Compile(ctx, code).ToLocalChecked()->Run(ctx).IsEmpty());
  CHECK(try_catch.HasCaught());

  CHECK(!set_was_called);
}


namespace {

bool get_was_called_in_order = false;
bool define_was_called_in_order = false;

v8::Intercepted GetterCallbackOrder(
    Local<Name> property, const v8::PropertyCallbackInfo<v8::Value>& info) {
  get_was_called_in_order = true;
  CHECK(!define_was_called_in_order);
  info.GetReturnValue().Set(property);
  return v8::Intercepted::kYes;
}

v8::Intercepted DefinerCallbackOrder(
    Local<Name> property, const v8::PropertyDescriptor& desc,
    const v8::PropertyCallbackInfo<void>& info) {
  // Get called before DefineProperty because we query the descriptor first.
  CHECK(get_was_called_in_order);
  define_was_called_in_order = true;
  return v8::Intercepted::kNo;
}

}  // namespace

// Check that getter callback is called before definer callback.
THREADED_TEST(DefinerCallbackGetAndDefine) {
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::FunctionTemplate> templ =
      v8::FunctionTemplate::New(CcTest::isolate());
  templ->InstanceTemplate()->SetHandler(v8::NamedPropertyHandlerConfiguration(
      GetterCallbackOrder, SetterCallback, nullptr, nullptr, nullptr,
      DefinerCallbackOrder));
  LocalContext env;
  env->Global()
      ->Set(env.local(), v8_str("obj"), templ->GetFunction(env.local())
                                            .ToLocalChecked()
                                            ->NewInstance(env.local())
                                            .ToLocalChecked())
      .FromJust();

  CHECK(!get_was_called_in_order);
  CHECK(!define_was_called_in_order);

  v8_compile("Object.defineProperty(obj, 'x', {set: function() {return 17;}});")
      ->Run(env.local())
      .ToLocalChecked();
  CHECK(get_was_called_in_order);
  CHECK(define_was_called_in_order);
}

namespace {  //  namespace for InObjectLiteralDefinitionWithInterceptor

// Workaround for no-snapshot builds: only intercept once Context::New() is
// done, otherwise we'll intercept
// bootstrapping like defining array on the global object.
bool context_is_done = false;
bool getter_callback_was_called = false;

v8::Intercepted ReturnUndefinedGetterCallback(
    Local<Name> property, const v8::PropertyCallbackInfo<v8::Value>& info) {
  if (context_is_done) {
    getter_callback_was_called = true;
    info.GetReturnValue().SetUndefined();
    return v8::Intercepted::kYes;
  }
  return v8::Intercepted::kNo;
}

}  // namespace

// Check that an interceptor is not invoked during ES6 style definitions inside
// an object literal.
THREADED_TEST(InObjectLiteralDefinitionWithInterceptor) {
  v8::HandleScope scope(CcTest::isolate());
  LocalContext env;

  // Set up a context in which all global object definitions are intercepted.
  v8::Local<v8::FunctionTemplate> templ =
      v8::FunctionTemplate::New(CcTest::isolate());
  v8::Local<ObjectTemplate> object_template = templ->InstanceTemplate();
  object_template->SetHandler(
      v8::NamedPropertyHandlerConfiguration(ReturnUndefinedGetterCallback));
  v8::Local<v8::Context> ctx =
      v8::Context::New(CcTest::isolate(), nullptr, object_template);

  context_is_done = true;

  // The interceptor returns undefined for any global object,
  // so setting a property on an object should throw.
  v8::Local<v8::String> code = v8_str("var o = {}; o.x = 5");
  {
    getter_callback_was_called = false;
    v8::TryCatch try_catch(CcTest::isolate());
    CHECK(v8::Script::Compile(ctx, code).ToLocalChecked()->Run(ctx).IsEmpty());
    CHECK(try_catch.HasCaught());
    CHECK(getter_callback_was_called);
  }

  // Defining a property in the object literal should not throw
  // because the interceptor is not invoked.
  {
    getter_callback_was_called = false;
    v8::TryCatch try_catch(CcTest::isolate());
    code = v8_str("var l = {x: 5};");
    CHECK(v8::Script::Compile(ctx, code)
              .ToLocalChecked()
              ->Run(ctx)
              .ToLocalChecked()
              ->IsUndefined());
    CHECK(!try_catch.HasCaught());
    CHECK(!getter_callback_was_called);
  }
}

THREADED_TEST(InterceptorHasOwnProperty) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  Local<v8::FunctionTemplate> fun_templ = v8::FunctionTemplate::New(isolate);
  Local<v8::ObjectTemplate> instance_templ = fun_templ->InstanceTemplate();
  instance_templ->SetHandler(
      v8::NamedPropertyHandlerConfiguration(InterceptorHasOwnPropertyGetter));
  Local<Function> function =
      fun_templ->GetFunction(context.local()).ToLocalChecked();
  context->Global()
      ->Set(context.local(), v8_str("constructor"), function)
      .FromJust();
  v8::Local<Value> value = CompileRun(
      "var o = new constructor();"
      "o.hasOwnProperty('ostehaps');");
  CHECK(!value->BooleanValue(isolate));
  value = CompileRun(
      "o.ostehaps = 42;"
      "o.hasOwnProperty('ostehaps');");
  CHECK(value->BooleanValue(isolate));
  value = CompileRun(
      "var p = new constructor();"
      "p.hasOwnProperty('ostehaps');");
  CHECK(!value->BooleanValue(isolate));
}


THREADED_TEST(InterceptorHasOwnPropertyCausingGC) {
  LocalContext context;
  v8
```