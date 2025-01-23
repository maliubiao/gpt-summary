Response:
Let's break down the thought process for analyzing this V8 test file.

**1. Initial Scan and Understanding the Context:**

* **Filename:** `v8/test/cctest/test-accessors.cc`. The `.cc` extension immediately tells us it's C++ code. The path suggests it's a component test for V8, specifically focusing on "accessors."  This hints that the code is testing how JavaScript properties are accessed and modified, likely involving custom behavior through C++ callbacks.
* **Copyright and License:**  Standard boilerplate, not crucial for functional analysis but confirms it's part of the V8 project.
* **Includes:**  These are critical. They reveal the core V8 APIs and test infrastructure being used:
    * `include/v8-function.h`:  Working with JavaScript functions.
    * `src/api/api-inl.h`:  Internal V8 API details.
    * `src/execution/frames-inl.h`:  Dealing with the call stack.
    * `src/strings/string-stream.h`:  String manipulation (likely for debugging or diagnostics).
    * `test/cctest/cctest.h`:  The core testing framework for V8's C++ tests.
    * `test/cctest/heap/heap-utils.h`:  Utilities for interacting with V8's garbage-collected heap.
* **`using namespace` directives:**  Simplifying the code by avoiding repetitive `v8::` prefixes. The specific namespaces (`::v8`, `::v8::ObjectTemplate`, etc.) confirm the focus on V8's embedding API.

**2. Analyzing the Core Logic (Function by Function/Test by Test):**

* **Static helper functions:**  Functions like `handle_property`, `handle_property_2`. The signatures (`Local<Name>`, `const v8::PropertyCallbackInfo<v8::Value>& info`) are the key. They clearly indicate these are callbacks triggered when JavaScript code accesses properties. The `info.GetReturnValue().Set(...)` line is the standard way to return a value from the callback back to JavaScript. The `ApiTestFuzzer::Fuzz()` call is a detail for V8's internal fuzzing and can be initially ignored for high-level understanding.
* **`THREADED_TEST` macros:** These mark the individual test cases. Each test sets up a V8 environment, defines JavaScript behavior using C++ callbacks, and then executes JavaScript code to verify the callbacks are working correctly.
* **`PropertyHandler` test:**  This is the first substantial test. It creates a function template (`fun_templ`) and uses `SetNativeDataProperty` and `SetAccessorProperty`. This is a direct demonstration of how to hook C++ functions to JavaScript property access. The subsequent JavaScript code (`var obj = new Fun(); obj.instance_foo;`) executes and the `CHECK_EQ` statements verify the expected return values from the C++ callbacks. The test also covers static properties (`Fun.object_foo`) and prototype manipulation.
* **`GlobalVariableAccess` test:**  This test demonstrates how C++ global variables can be directly accessed and modified by JavaScript using native data properties. The `GetIntValue` and `SetIntValue` callbacks mediate this access.
* **`AccessorIC` test:** The name "IC" suggests "Inline Cache," a performance optimization in V8. This test likely focuses on how V8 optimizes repeated access to properties handled by C++ accessors. The structure with `x_register`, `x_receiver_global`, and `x_holder_global` hints at tracking the receiver and holder objects during property access. The JavaScript code with the loop and array manipulations is designed to trigger the inline caching mechanisms.
* **`HandleScopePop` test:**  Handle scopes are crucial for memory management in V8's embedding API. This test checks that handles created within a handle scope are properly cleaned up when the scope exits, preventing memory leaks.
* **`DirectCall`, `EmptyResult`, `NoReuseRegress` tests:** These appear to be smaller, focused tests on specific aspects of accessor behavior, likely addressing edge cases or regressions.
* **`Regress1054726`, `Gc`, `StackIteration`, `HandleScopeSegment` tests:**  These names suggest they are regression tests (fixing previously found bugs) or tests for specific features like garbage collection interaction, stack frame inspection, and handle scope management.
* **`JSONStringifyNamedInterceptorObject` test:** This test explores how custom accessors interact with `JSON.stringify`, a common JavaScript operation.
* **`AccessorPropertyCrossContext` test:** This tests how accessors behave when accessed from different V8 contexts, which is important for embedding scenarios.
* **`GlobalObjectAccessor` test:** This specifically focuses on accessors defined on the global object's prototype chain.
* **`Regress433458` test:** Another regression test, likely targeting a specific bug related to property definitions and generic getters.
* **`PrototypeGetterAccessCheck` test:** This test examines the interaction of accessors with V8's security checks.
* **`Regress609134` test:**  A regression test related to prototype chains and accessor lookups.
* **`ObjectSetLazyDataProperty` and `ObjectSetLazyDataPropertyForIndex` tests:** These test the functionality of setting "lazy" data properties, where the value is computed only when the property is first accessed.

**3. Identifying Core Functionality and Relationships to JavaScript:**

* The code demonstrably tests the core concepts of **getters** and **setters** in JavaScript. The C++ callbacks directly implement the logic for these operations.
* It shows how to create **native data properties** and **accessor properties**, bridging C++ data and functions into the JavaScript world.
* The tests cover various scenarios: instance properties, static properties, prototype inheritance, and interaction with built-in JavaScript features like `JSON.stringify`.

**4. Considering Potential User Errors and Logic:**

* **Common Errors:**  Incorrectly implementing the callback signatures, forgetting to set the return value, memory management issues if handles are not handled properly, and misunderstanding the `this` binding within accessors.
* **Logic Inference:**  The tests often follow a pattern:
    1. Set up a V8 environment and define a JavaScript object or function with custom accessors using C++.
    2. Execute JavaScript code that accesses or modifies these properties.
    3. Use `CHECK_EQ` or similar assertions to verify the expected behavior (e.g., the correct callback was invoked, the return value is as expected).

**5. Structuring the Summary:**

Based on the analysis above, the summary should highlight the key aspects:

* **Primary Function:** Testing the functionality of accessors (getters and setters) in V8.
* **Mechanism:** Using C++ callbacks to define custom property access behavior.
* **JavaScript Relevance:** Directly related to how JavaScript objects and their properties work.
* **Key Concepts Tested:** Native data properties, accessor properties, prototype inheritance, interaction with built-in functions, performance aspects (IC).
* **Potential Errors:**  Focus on common mistakes when implementing C++ accessors.

By following this systematic approach, one can effectively understand the purpose and functionality of a complex C++ test file like this. The key is to focus on the interactions between the C++ code and the JavaScript concepts it's testing.
这是目录为 `v8/test/cctest/test-accessors.cc` 的一个 V8 源代码文件，它的功能是测试 V8 引擎中 **访问器 (accessors)** 的相关特性。

**功能归纳:**

这个 C++ 文件包含了多个测试用例，用来验证 V8 JavaScript 引擎在处理对象属性的读取和设置时，由 C++ 代码实现的自定义访问器（getters 和 setters）的行为是否符合预期。 这些测试涵盖了以下几个主要方面：

1. **基本访问器功能:**
   - 测试使用 `SetNativeDataProperty` 和 `SetAccessorProperty` 设置的 C++ 回调函数能否正确地处理属性的读取和设置。
   - 验证实例属性和静态属性的访问器行为。

2. **访问器与原型链的交互:**
   - 测试当对象的原型链上定义了访问器时，属性访问的行为是否正确，包括原型为 `null` 的情况。

3. **全局变量访问:**
   - 测试如何使用访问器来控制 JavaScript 代码对 C++ 全局变量的访问和修改。

4. **内联缓存 (IC) 的影响:**
   - 测试访问器在 V8 的内联缓存优化下的行为，确保性能优化的正确性。

5. **句柄作用域管理:**
   - 测试在访问器回调函数中创建的 V8 句柄是否能正确地被句柄作用域管理，防止内存泄漏。

6. **访问器参数验证:**
   - 测试传递给访问器回调函数的参数（如 `name`, `info`）是否包含了正确的信息，例如 `this` 指针、`Holder` 指针以及自定义数据。

7. **空返回值处理:**
   - 测试当访问器返回空值 (`v8::Local<v8::Value>`) 时，V8 的处理方式。

8. **异常处理:**
   - 测试当访问器抛出异常时，V8 能否正确地捕获和处理这些异常。

9. **垃圾回收 (GC) 的影响:**
   - 测试访问器的行为是否与 V8 的垃圾回收机制正确地协同工作。

10. **堆栈迭代:**
    - 测试在访问器回调中遍历 JavaScript 堆栈的功能是否正常。

11. **跨上下文访问:**
    - 测试在不同 V8 上下文之间访问带有访问器的属性时的行为。

12. **全局对象访问器:**
    - 测试在全局对象的原型链上定义的访问器的行为。

13. **命名属性拦截器:**
    - 测试使用 `NamedPropertyHandlerConfiguration` 设置的拦截器与访问器的交互，特别是在 `JSON.stringify` 等场景下的行为。

14. **安全检查:**
    - 测试访问器与 V8 的安全检查机制的集成，验证在访问受保护的属性时访问检查回调是否被正确调用。

15. **惰性数据属性:**
    - 测试 `SetLazyDataProperty` 方法设置的属性，其 getter 只在首次访问时被调用。

**关于文件类型和 JavaScript 关联:**

- `v8/test/cctest/test-accessors.cc` 以 `.cc` 结尾，因此它是一个 **V8 C++ 源代码文件**，而不是 Torque 文件。
- 这个文件与 JavaScript 的功能密切相关，因为它测试的是 V8 引擎如何执行和管理 JavaScript 中的属性访问机制。

**JavaScript 示例说明:**

虽然 `test-accessors.cc` 是 C++ 代码，但它测试的是以下 JavaScript 概念：

```javascript
// 定义一个对象
const obj = {};

// 使用 Object.defineProperty 定义访问器属性
Object.defineProperty(obj, 'myProperty', {
  get: function() {
    console.log('Getter 被调用');
    return 10;
  },
  set: function(value) {
    console.log('Setter 被调用，新值为:', value);
  },
  enumerable: true,
  configurable: true
});

// 读取属性，触发 getter
const value = obj.myProperty; // 输出: Getter 被调用
console.log(value);           // 输出: 10

// 设置属性，触发 setter
obj.myProperty = 20;         // 输出: Setter 被调用，新值为: 20
```

在 `test-accessors.cc` 中，C++ 代码会模拟类似 `Object.defineProperty` 的功能，通过 `SetNativeDataProperty` 或 `SetAccessorProperty` 来关联 C++ 函数作为 JavaScript 对象的属性的 getter 或 setter。

**代码逻辑推理示例:**

假设 `test-accessors.cc` 中有以下测试用例片段：

```c++
THREADED_TEST(SimpleGetter) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  Local<v8::ObjectTemplate> obj_templ = ObjectTemplate::New(isolate);
  obj_templ->SetNativeDataProperty(v8_str("data"), handle_property); // 使用 handle_property 作为 getter
  Local<v8::Object> obj = obj_templ->NewInstance(env.local()).ToLocalChecked();
  CHECK(env->Global()->Set(env.local(), v8_str("myObj"), obj).FromJust());
  Local<Script> script = v8_compile("myObj.data");
  Local<Value> result = script->Run(env.local()).ToLocalChecked();
  CHECK_EQ(900, result->Int32Value(env.local()).FromJust());
}

static void handle_property(Local<Name> name,
                            const v8::PropertyCallbackInfo<v8::Value>& info) {
  info.GetReturnValue().Set(v8_num(900));
}
```

**假设输入与输出:**

- **假设输入 (JavaScript 代码):** `myObj.data`
- **预期输出 (C++ 回调的返回值):**  `900`

**推理:**

1. `THREADED_TEST(SimpleGetter)` 创建了一个 V8 环境。
2. 创建了一个对象模板 `obj_templ`。
3. 使用 `SetNativeDataProperty` 将 C++ 函数 `handle_property` 与对象模板的 `data` 属性关联。这意味着当 JavaScript 代码尝试读取 `data` 属性时，`handle_property` 函数会被调用。
4. `handle_property` 函数内部，`info.GetReturnValue().Set(v8_num(900))` 将返回值设置为 900。
5. 执行 JavaScript 代码 `myObj.data`。
6. 由于 `data` 属性关联了 `handle_property`，该函数被调用。
7. `handle_property` 返回 900。
8. `CHECK_EQ(900, result->Int32Value(env.local()).FromJust())` 验证了 JavaScript 代码读取到的值确实是 900。

**用户常见的编程错误示例:**

在实现 C++ 访问器时，用户可能会犯以下错误：

```c++
// 错误的 getter 实现 - 没有设置返回值
static void bad_getter(Local<Name> name,
                       const v8::PropertyCallbackInfo<v8::Value>& info) {
  // 忘记调用 info.GetReturnValue().Set(...)
  // 结果是访问该属性会返回 undefined
}

// 错误的 setter 实现 - 参数处理错误
static void bad_setter(Local<Name> name, Local<Value> value,
                       const v8::PropertyCallbackInfo<void>& info) {
  // 假设 value 是一个数字，但没有进行类型检查
  int int_value = value->Int32Value(info.GetIsolate()->GetCurrentContext()).FromJust();
  // 如果 value 不是数字，这里会抛出异常
}
```

在 `test-accessors.cc` 中，会有相应的测试用例来捕捉这些错误行为，例如检查当 getter 没有返回值时是否返回 `undefined`，或者当 setter 接收到错误类型的值时是否会抛出异常。

**总结:**

总而言之，`v8/test/cctest/test-accessors.cc` 是一个关键的测试文件，它全面地测试了 V8 引擎中 C++ 访问器的功能，确保了这些底层的机制能够正确地支持 JavaScript 中灵活的属性访问模式。

### 提示词
```
这是目录为v8/test/cctest/test-accessors.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-accessors.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2012 the V8 project authors. All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above
//       copyright notice, this list of conditions and the following
//       disclaimer in the documentation and/or other materials provided
//       with the distribution.
//     * Neither the name of Google Inc. nor the names of its
//       contributors may be used to endorse or promote products derived
//       from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include <stdlib.h>

#include "include/v8-function.h"
#include "src/api/api-inl.h"
#include "src/execution/frames-inl.h"
#include "src/strings/string-stream.h"
#include "test/cctest/cctest.h"
#include "test/cctest/heap/heap-utils.h"

using ::v8::ObjectTemplate;
using ::v8::Value;
using ::v8::Context;
using ::v8::Local;
using ::v8::Name;
using ::v8::String;
using ::v8::Script;
using ::v8::Function;
using ::v8::Extension;

static void handle_property(Local<Name> name,
                            const v8::PropertyCallbackInfo<v8::Value>& info) {
  ApiTestFuzzer::Fuzz();
  info.GetReturnValue().Set(v8_num(900));
}

static void handle_property_2(Local<Name> name,
                              const v8::PropertyCallbackInfo<v8::Value>& info) {
  ApiTestFuzzer::Fuzz();
  info.GetReturnValue().Set(v8_num(902));
}

static void handle_property(const v8::FunctionCallbackInfo<v8::Value>& info) {
  ApiTestFuzzer::Fuzz();
  CHECK_EQ(0, info.Length());
  info.GetReturnValue().Set(v8_num(907));
}


THREADED_TEST(PropertyHandler) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  Local<v8::FunctionTemplate> fun_templ = v8::FunctionTemplate::New(isolate);
  fun_templ->InstanceTemplate()->SetNativeDataProperty(v8_str("foo"),
                                                       handle_property);
  Local<v8::FunctionTemplate> getter_templ =
      v8::FunctionTemplate::New(isolate, handle_property);
  getter_templ->SetLength(0);
  fun_templ->
      InstanceTemplate()->SetAccessorProperty(v8_str("bar"), getter_templ);
  fun_templ->InstanceTemplate()->
      SetNativeDataProperty(v8_str("instance_foo"), handle_property);
  fun_templ->SetNativeDataProperty(v8_str("object_foo"), handle_property_2);
  Local<Function> fun = fun_templ->GetFunction(env.local()).ToLocalChecked();
  CHECK(env->Global()->Set(env.local(), v8_str("Fun"), fun).FromJust());
  Local<Script> getter;
  Local<Script> setter;
  // check function instance accessors
  getter = v8_compile("var obj = new Fun(); obj.instance_foo;");
  for (int i = 0; i < 4; i++) {
    CHECK_EQ(900, getter->Run(env.local())
                      .ToLocalChecked()
                      ->Int32Value(env.local())
                      .FromJust());
  }
  setter = v8_compile("obj.instance_foo = 901;");
  for (int i = 0; i < 4; i++) {
    CHECK_EQ(901, setter->Run(env.local())
                      .ToLocalChecked()
                      ->Int32Value(env.local())
                      .FromJust());
  }
  getter = v8_compile("obj.bar;");
  for (int i = 0; i < 4; i++) {
    CHECK_EQ(907, getter->Run(env.local())
                      .ToLocalChecked()
                      ->Int32Value(env.local())
                      .FromJust());
  }
  setter = v8_compile("obj.bar = 908;");
  for (int i = 0; i < 4; i++) {
    CHECK_EQ(908, setter->Run(env.local())
                      .ToLocalChecked()
                      ->Int32Value(env.local())
                      .FromJust());
  }
  // check function static accessors
  getter = v8_compile("Fun.object_foo;");
  for (int i = 0; i < 4; i++) {
    CHECK_EQ(902, getter->Run(env.local())
                      .ToLocalChecked()
                      ->Int32Value(env.local())
                      .FromJust());
  }
  setter = v8_compile("Fun.object_foo = 903;");
  for (int i = 0; i < 4; i++) {
    CHECK_EQ(903, setter->Run(env.local())
                      .ToLocalChecked()
                      ->Int32Value(env.local())
                      .FromJust());
  }

  // And now with null prototype.
  CompileRun(env.local(), "obj.__proto__ = null;");
  getter = v8_compile("obj.bar;");
  for (int i = 0; i < 4; i++) {
    CHECK_EQ(907, getter->Run(env.local())
                      .ToLocalChecked()
                      ->Int32Value(env.local())
                      .FromJust());
  }
  setter = v8_compile("obj.bar = 908;");
  for (int i = 0; i < 4; i++) {
    CHECK_EQ(908, setter->Run(env.local())
                      .ToLocalChecked()
                      ->Int32Value(env.local())
                      .FromJust());
  }
}

static void GetIntValue(Local<Name> property,
                        const v8::PropertyCallbackInfo<v8::Value>& info) {
  ApiTestFuzzer::Fuzz();
  int* value = static_cast<int*>(info.Data().As<v8::External>()->Value());
  info.GetReturnValue().Set(v8_num(*value));
}

static void SetIntValue(Local<Name> property, Local<Value> value,
                        const v8::PropertyCallbackInfo<void>& info) {
  int* field = static_cast<int*>(info.Data().As<v8::External>()->Value());
  *field = value->Int32Value(info.GetIsolate()->GetCurrentContext()).FromJust();
}

int foo, bar, baz;

THREADED_TEST(GlobalVariableAccess) {
  foo = 0;
  bar = -4;
  baz = 10;
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::FunctionTemplate> templ = v8::FunctionTemplate::New(isolate);
  templ->InstanceTemplate()->SetNativeDataProperty(
      v8_str("foo"), GetIntValue, SetIntValue,
      v8::External::New(isolate, &foo));
  templ->InstanceTemplate()->SetNativeDataProperty(
      v8_str("bar"), GetIntValue, SetIntValue,
      v8::External::New(isolate, &bar));
  templ->InstanceTemplate()->SetNativeDataProperty(
      v8_str("baz"), GetIntValue, SetIntValue,
      v8::External::New(isolate, &baz));
  LocalContext env(nullptr, templ->InstanceTemplate());
  v8_compile("foo = (++bar) + baz")->Run(env.local()).ToLocalChecked();
  CHECK_EQ(-3, bar);
  CHECK_EQ(7, foo);
}

static int x_register[2] = {0, 0};
static v8::Global<v8::Object> x_receiver_global;
static v8::Global<v8::Object> x_holder_global;

template<class Info>
static void XGetter(const Info& info, int offset) {
  ApiTestFuzzer::Fuzz();
  v8::Isolate* isolate = CcTest::isolate();
  CHECK_EQ(isolate, info.GetIsolate());
  CHECK(x_receiver_global.Get(isolate)
            ->Equals(isolate->GetCurrentContext(), info.This())
            .FromJust());
  info.GetReturnValue().Set(v8_num(x_register[offset]));
}

static void XGetter(Local<Name> name,
                    const v8::PropertyCallbackInfo<v8::Value>& info) {
  v8::Isolate* isolate = info.GetIsolate();
  CHECK(x_holder_global.Get(isolate)
            ->Equals(isolate->GetCurrentContext(), info.HolderV2())
            .FromJust());
  XGetter(info, 0);
}

static void XGetter(const v8::FunctionCallbackInfo<v8::Value>& info) {
  v8::Isolate* isolate = info.GetIsolate();
  CHECK(x_receiver_global.Get(isolate)
            ->Equals(isolate->GetCurrentContext(),
                     info.HolderSoonToBeDeprecated())
            .FromJust());
  XGetter(info, 1);
}

template <typename Info>
Local<v8::Object> GetHolder(const Info& info);

template <>
Local<v8::Object> GetHolder<v8::PropertyCallbackInfo<void>>(
    const v8::PropertyCallbackInfo<void>& info) {
  return info.HolderV2();
}

template <>
Local<v8::Object> GetHolder<v8::FunctionCallbackInfo<v8::Value>>(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  return info.HolderSoonToBeDeprecated();
}

template<class Info>
static void XSetter(Local<Value> value, const Info& info, int offset) {
  v8::Isolate* isolate = CcTest::isolate();
  CHECK_EQ(isolate, info.GetIsolate());
  CHECK(x_holder_global.Get(isolate)
            ->Equals(isolate->GetCurrentContext(), info.This())
            .FromJust());
  CHECK(x_holder_global.Get(isolate)
            ->Equals(isolate->GetCurrentContext(), GetHolder(info))
            .FromJust());
  x_register[offset] =
      value->Int32Value(isolate->GetCurrentContext()).FromJust();
}

static void XSetter(Local<Name> name, Local<Value> value,
                    const v8::PropertyCallbackInfo<void>& info) {
  XSetter(value, info, 0);
}

static void XSetter(const v8::FunctionCallbackInfo<v8::Value>& info) {
  CHECK_EQ(1, info.Length());
  XSetter(info[0], info, 1);
  info.GetReturnValue().Set(v8_num(-1));
}


THREADED_TEST(AccessorIC) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> obj = ObjectTemplate::New(isolate);
  obj->SetNativeDataProperty(v8_str("x0"), XGetter, XSetter);
  obj->SetAccessorProperty(v8_str("x1"),
                           v8::FunctionTemplate::New(isolate, XGetter),
                           v8::FunctionTemplate::New(isolate, XSetter));
  v8::Local<v8::Object> x_holder =
      obj->NewInstance(context.local()).ToLocalChecked();
  x_holder_global.Reset(isolate, x_holder);
  CHECK(context->Global()
            ->Set(context.local(), v8_str("holder"), x_holder)
            .FromJust());
  v8::Local<v8::Object> x_receiver = v8::Object::New(isolate);
  x_receiver_global.Reset(isolate, x_receiver);
  CHECK(context->Global()
            ->Set(context.local(), v8_str("obj"), x_receiver)
            .FromJust());
  v8::Local<v8::Array> array = v8::Local<v8::Array>::Cast(
      CompileRun("obj.__proto__ = holder;"
                 "var result = [];"
                 "var key_0 = 'x0';"
                 "var key_1 = 'x1';"
                 "for (var j = 0; j < 10; j++) {"
                 "  var i = 4*j;"
                 "  result.push(holder.x0 = i);"
                 "  result.push(obj.x0);"
                 "  result.push(holder.x1 = i + 1);"
                 "  result.push(obj.x1);"
                 "  result.push(holder[key_0] = i + 2);"
                 "  result.push(obj[key_0]);"
                 "  result.push(holder[key_1] = i + 3);"
                 "  result.push(obj[key_1]);"
                 "}"
                 "result"));
  CHECK_EQ(80u, array->Length());
  for (int i = 0; i < 80; i++) {
    v8::Local<Value> entry =
        array->Get(context.local(), v8::Integer::New(isolate, i))
            .ToLocalChecked();
    CHECK(v8::Integer::New(isolate, i / 2)
              ->Equals(context.local(), entry)
              .FromJust());
  }
  x_holder_global.Reset();
  x_receiver_global.Reset();
}

template <int C>
static void HandleAllocatingGetter(
    Local<Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  ApiTestFuzzer::Fuzz();
  for (int i = 0; i < C; i++) {
    USE(v8::String::NewFromUtf8Literal(info.GetIsolate(), "foo"));
  }
  info.GetReturnValue().Set(
      v8::String::NewFromUtf8Literal(info.GetIsolate(), "foo"));
}

THREADED_TEST(HandleScopePop) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> obj = ObjectTemplate::New(isolate);
  obj->SetNativeDataProperty(v8_str("one"), HandleAllocatingGetter<1>);
  obj->SetNativeDataProperty(v8_str("many"), HandleAllocatingGetter<1024>);
  v8::Local<v8::Object> inst =
      obj->NewInstance(context.local()).ToLocalChecked();
  CHECK(
      context->Global()->Set(context.local(), v8_str("obj"), inst).FromJust());
  int count_before =
      i::HandleScope::NumberOfHandles(reinterpret_cast<i::Isolate*>(isolate));
  {
    v8::HandleScope inner_scope(isolate);
    CompileRun(
        "for (var i = 0; i < 1000; i++) {"
        "  obj.one;"
        "  obj.many;"
        "}");
  }
  int count_after =
      i::HandleScope::NumberOfHandles(reinterpret_cast<i::Isolate*>(isolate));
  CHECK_EQ(count_before, count_after);
}

// Allow usages of v8::PropertyCallbackInfo<T>::Holder() for now.
// TODO(https://crbug.com/333672197): remove.
START_ALLOW_USE_DEPRECATED()

static void CheckAccessorArgsCorrect(
    Local<Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  i::ValidateCallbackInfo(info);
  CHECK(info.GetIsolate() == CcTest::isolate());
  CHECK(info.This() == info.Holder());
  CHECK(info.Data()
            ->Equals(info.GetIsolate()->GetCurrentContext(), v8_str("data"))
            .FromJust());
  ApiTestFuzzer::Fuzz();
  CHECK(info.GetIsolate() == CcTest::isolate());
  CHECK(info.This() == info.Holder());
  CHECK(info.Data()
            ->Equals(info.GetIsolate()->GetCurrentContext(), v8_str("data"))
            .FromJust());
  CHECK(info.GetIsolate() == CcTest::isolate());
  i::heap::InvokeMajorGC(CcTest::heap());
  CHECK(info.This() == info.Holder());
  CHECK(info.Data()
            ->Equals(info.GetIsolate()->GetCurrentContext(), v8_str("data"))
            .FromJust());
  info.GetReturnValue().Set(17);
}

// Allow usages of v8::PropertyCallbackInfo<T>::Holder() for now.
// TODO(https://crbug.com/333672197): remove.
END_ALLOW_USE_DEPRECATED()

THREADED_TEST(DirectCall) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> obj = ObjectTemplate::New(isolate);
  obj->SetNativeDataProperty(v8_str("xxx"), CheckAccessorArgsCorrect, nullptr,
                             v8_str("data"));
  v8::Local<v8::Object> inst =
      obj->NewInstance(context.local()).ToLocalChecked();
  CHECK(
      context->Global()->Set(context.local(), v8_str("obj"), inst).FromJust());
  Local<Script> scr =
      v8::Script::Compile(context.local(), v8_str("obj.xxx")).ToLocalChecked();
  for (int i = 0; i < 10; i++) {
    Local<Value> result = scr->Run(context.local()).ToLocalChecked();
    CHECK(!result.IsEmpty());
    CHECK_EQ(17, result->Int32Value(context.local()).FromJust());
  }
}

static void EmptyGetter(Local<Name> name,
                        const v8::PropertyCallbackInfo<v8::Value>& info) {
  CheckAccessorArgsCorrect(name, info);
  ApiTestFuzzer::Fuzz();
  CheckAccessorArgsCorrect(name, info);
  info.GetReturnValue().Set(v8::Local<v8::Value>());
}

THREADED_TEST(EmptyResult) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> obj = ObjectTemplate::New(isolate);
  obj->SetNativeDataProperty(v8_str("xxx"), EmptyGetter, nullptr,
                             v8_str("data"));
  v8::Local<v8::Object> inst =
      obj->NewInstance(context.local()).ToLocalChecked();
  CHECK(
      context->Global()->Set(context.local(), v8_str("obj"), inst).FromJust());
  Local<Script> scr =
      v8::Script::Compile(context.local(), v8_str("obj.xxx")).ToLocalChecked();
  for (int i = 0; i < 10; i++) {
    Local<Value> result = scr->Run(context.local()).ToLocalChecked();
    CHECK(result == v8::Undefined(isolate));
  }
}


THREADED_TEST(NoReuseRegress) {
  // Check that the IC generated for the one test doesn't get reused
  // for the other.
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  {
    v8::Local<v8::ObjectTemplate> obj = ObjectTemplate::New(isolate);
    obj->SetNativeDataProperty(v8_str("xxx"), EmptyGetter, nullptr,
                               v8_str("data"));
    LocalContext context;
    v8::Local<v8::Object> inst =
        obj->NewInstance(context.local()).ToLocalChecked();
    CHECK(context->Global()
              ->Set(context.local(), v8_str("obj"), inst)
              .FromJust());
    Local<Script> scr = v8::Script::Compile(context.local(), v8_str("obj.xxx"))
                            .ToLocalChecked();
    for (int i = 0; i < 2; i++) {
      Local<Value> result = scr->Run(context.local()).ToLocalChecked();
      CHECK(result == v8::Undefined(isolate));
    }
  }
  {
    v8::Local<v8::ObjectTemplate> obj = ObjectTemplate::New(isolate);
    obj->SetNativeDataProperty(v8_str("xxx"), CheckAccessorArgsCorrect, nullptr,
                               v8_str("data"));
    LocalContext context;
    v8::Local<v8::Object> inst =
        obj->NewInstance(context.local()).ToLocalChecked();
    CHECK(context->Global()
              ->Set(context.local(), v8_str("obj"), inst)
              .FromJust());
    Local<Script> scr = v8::Script::Compile(context.local(), v8_str("obj.xxx"))
                            .ToLocalChecked();
    for (int i = 0; i < 10; i++) {
      Local<Value> result = scr->Run(context.local()).ToLocalChecked();
      CHECK(!result.IsEmpty());
      CHECK_EQ(17, result->Int32Value(context.local()).FromJust());
    }
  }
}

static void ThrowingGetAccessor(
    Local<Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  ApiTestFuzzer::Fuzz();
  info.GetIsolate()->ThrowException(v8_str("g"));
}

static void ThrowingSetAccessor(Local<Name> name, Local<Value> value,
                                const v8::PropertyCallbackInfo<void>& info) {
  info.GetIsolate()->ThrowException(value);
}

THREADED_TEST(Regress1054726) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> obj = ObjectTemplate::New(isolate);
  obj->SetNativeDataProperty(v8_str("x"), ThrowingGetAccessor,
                             ThrowingSetAccessor, Local<Value>());

  CHECK(env->Global()
            ->Set(env.local(), v8_str("obj"),
                  obj->NewInstance(env.local()).ToLocalChecked())
            .FromJust());

  // Use the throwing property setter/getter in a loop to force
  // the accessor ICs to be initialized.
  v8::Local<Value> result;
  result = Script::Compile(env.local(),
                           v8_str("var result = '';"
                                  "for (var i = 0; i < 5; i++) {"
                                  "  try { obj.x; } catch (e) { result += e; }"
                                  "}; result"))
               .ToLocalChecked()
               ->Run(env.local())
               .ToLocalChecked();
  CHECK(v8_str("ggggg")->Equals(env.local(), result).FromJust());

  result =
      Script::Compile(env.local(),
                      v8_str("var result = '';"
                             "for (var i = 0; i < 5; i++) {"
                             "  try { obj.x = i; } catch (e) { result += e; }"
                             "}; result"))
          .ToLocalChecked()
          ->Run(env.local())
          .ToLocalChecked();
  CHECK(v8_str("01234")->Equals(env.local(), result).FromJust());
}

static void AllocGetter(Local<Name> name,
                        const v8::PropertyCallbackInfo<v8::Value>& info) {
  ApiTestFuzzer::Fuzz();
  info.GetReturnValue().Set(v8::Array::New(info.GetIsolate(), 1000));
}

THREADED_TEST(Gc) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> obj = ObjectTemplate::New(isolate);
  obj->SetNativeDataProperty(v8_str("xxx"), AllocGetter);
  CHECK(env->Global()
            ->Set(env.local(), v8_str("obj"),
                  obj->NewInstance(env.local()).ToLocalChecked())
            .FromJust());
  Script::Compile(env.local(), v8_str("var last = [];"
                                      "for (var i = 0; i < 2048; i++) {"
                                      "  var result = obj.xxx;"
                                      "  result[0] = last;"
                                      "  last = result;"
                                      "}"))
      .ToLocalChecked()
      ->Run(env.local())
      .ToLocalChecked();
}

static void StackCheck(Local<Name> name,
                       const v8::PropertyCallbackInfo<v8::Value>& info) {
  i::Isolate* isolate = reinterpret_cast<i::Isolate*>(info.GetIsolate());
  i::StackFrameIterator iter(isolate);
  for (int i = 0; !iter.done(); i++) {
    i::StackFrame* frame = iter.frame();
    if (i == 0) {
      // The topmost frame could be either EXIT frame in case the callback
      // was called from IC miss or API_ACCESSOR_EXIT in case the callback
      // was called via CallApiGetter builtin.
      CHECK(frame->is_exit() || frame->is_api_accessor_exit());
    }
    i::Tagged<i::Code> code = frame->LookupCode();
    CHECK(code->contains(isolate, frame->pc()));
    iter.Advance();
  }
}

THREADED_TEST(StackIteration) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> obj = ObjectTemplate::New(isolate);
  i::StringStream::ClearMentionedObjectCache(
      reinterpret_cast<i::Isolate*>(isolate));
  obj->SetNativeDataProperty(v8_str("xxx"), StackCheck);
  CHECK(env->Global()
            ->Set(env.local(), v8_str("obj"),
                  obj->NewInstance(env.local()).ToLocalChecked())
            .FromJust());
  Script::Compile(env.local(), v8_str("function foo() {"
                                      "  return obj.xxx;"
                                      "}"
                                      "for (var i = 0; i < 100; i++) {"
                                      "  foo();"
                                      "}"))
      .ToLocalChecked()
      ->Run(env.local())
      .ToLocalChecked();
}

static void AllocateHandles(Local<Name> name,
                            const v8::PropertyCallbackInfo<v8::Value>& info) {
  for (int i = 0; i < i::kHandleBlockSize + 1; i++) {
    v8::Local<v8::Value>::New(info.GetIsolate(), name);
  }
  info.GetReturnValue().Set(v8::Integer::New(info.GetIsolate(), 100));
}

THREADED_TEST(HandleScopeSegment) {
  // Check that we can return values past popping of handle scope
  // segments.
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> obj = ObjectTemplate::New(isolate);
  obj->SetNativeDataProperty(v8_str("xxx"), AllocateHandles);
  CHECK(env->Global()
            ->Set(env.local(), v8_str("obj"),
                  obj->NewInstance(env.local()).ToLocalChecked())
            .FromJust());
  v8::Local<v8::Value> result =
      Script::Compile(env.local(), v8_str("var result;"
                                          "for (var i = 0; i < 4; i++)"
                                          "  result = obj.xxx;"
                                          "result;"))
          .ToLocalChecked()
          ->Run(env.local())
          .ToLocalChecked();
  CHECK_EQ(100, result->Int32Value(env.local()).FromJust());
}


void JSONStringifyEnumerator(const v8::PropertyCallbackInfo<v8::Array>& info) {
  v8::Local<v8::Array> array = v8::Array::New(info.GetIsolate(), 1);
  CHECK(array->Set(info.GetIsolate()->GetCurrentContext(), 0, v8_str("regress"))
            .FromJust());
  info.GetReturnValue().Set(array);
}

v8::Intercepted JSONStringifyGetter(
    Local<Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  info.GetReturnValue().Set(v8_str("crbug-161028"));
  return v8::Intercepted::kYes;
}

THREADED_TEST(JSONStringifyNamedInterceptorObject) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  v8::Local<v8::ObjectTemplate> obj = ObjectTemplate::New(isolate);
  obj->SetHandler(v8::NamedPropertyHandlerConfiguration(
      JSONStringifyGetter, nullptr, nullptr, nullptr, JSONStringifyEnumerator));
  CHECK(env->Global()
            ->Set(env.local(), v8_str("obj"),
                  obj->NewInstance(env.local()).ToLocalChecked())
            .FromJust());
  v8::Local<v8::String> expected = v8_str("{\"regress\":\"crbug-161028\"}");
  CHECK(CompileRun("JSON.stringify(obj)")
            ->Equals(env.local(), expected)
            .FromJust());
}

static v8::Global<v8::Context> expected_current_context_global;

static void check_contexts(const v8::FunctionCallbackInfo<v8::Value>& info) {
  ApiTestFuzzer::Fuzz();
  v8::Isolate* isolate = info.GetIsolate();
  CHECK_EQ(expected_current_context_global.Get(isolate),
           isolate->GetCurrentContext());
}


THREADED_TEST(AccessorPropertyCrossContext) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::Function> fun =
      v8::Function::New(env.local(), check_contexts).ToLocalChecked();
  LocalContext switch_context;
  CHECK(switch_context->Global()
            ->Set(switch_context.local(), v8_str("fun"), fun)
            .FromJust());
  v8::TryCatch try_catch(isolate);
  expected_current_context_global.Reset(isolate, env.local());
  CompileRun(
      "var o = Object.create(null, { n: { get:fun } });"
      "for (var i = 0; i < 10; i++) o.n;");
  CHECK(!try_catch.HasCaught());
  expected_current_context_global.Reset();
}


THREADED_TEST(GlobalObjectAccessor) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  CompileRun(
      "var set_value = 1;"
      "Object.defineProperty(this.__proto__, 'x', {"
      "    get : function() { return this; },"
      "    set : function() { set_value = this; }"
      "});"
      "function getter() { return x; }"
      "function setter() { x = 1; }");

  Local<Script> check_getter = v8_compile("getter()");
  Local<Script> check_setter = v8_compile("setter(); set_value");

  // Ensure that LoadGlobalICs in getter and StoreGlobalICs setter get
  // JSGlobalProxy as a receiver regardless of the current IC state and
  // the order in which ICs are executed.
  for (int i = 0; i < 10; i++) {
    CHECK(IsJSGlobalProxy(*v8::Utils::OpenDirectHandle(
        *check_getter->Run(env.local()).ToLocalChecked())));
  }
  for (int i = 0; i < 10; i++) {
    CHECK(IsJSGlobalProxy(*v8::Utils::OpenDirectHandle(
        *check_setter->Run(env.local()).ToLocalChecked())));
  }
  for (int i = 0; i < 10; i++) {
    CHECK(IsJSGlobalProxy(*v8::Utils::OpenDirectHandle(
        *check_getter->Run(env.local()).ToLocalChecked())));
    CHECK(IsJSGlobalProxy(*v8::Utils::OpenDirectHandle(
        *check_setter->Run(env.local()).ToLocalChecked())));
  }
}

namespace {
v8::Intercepted EmptyGenericGetter(
    Local<Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  // The request is not intercepted so don't call ApiTestFuzzer::Fuzz() here.
  return v8::Intercepted::kNo;
}

void OneProperty(Local<Name> name,
                 const v8::PropertyCallbackInfo<v8::Value>& info) {
  ApiTestFuzzer::Fuzz();
  info.GetReturnValue().Set(v8_num(1));
}
}  // namespace

THREADED_TEST(Regress433458) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> obj = ObjectTemplate::New(isolate);
  obj->SetHandler(v8::NamedPropertyHandlerConfiguration(EmptyGenericGetter));
  obj->SetNativeDataProperty(v8_str("prop"), OneProperty);
  CHECK(env->Global()
            ->Set(env.local(), v8_str("obj"),
                  obj->NewInstance(env.local()).ToLocalChecked())
            .FromJust());
  CompileRun(
      "Object.defineProperty(obj, 'prop', { writable: false });"
      "Object.defineProperty(obj, 'prop', { writable: true });");
}


static bool security_check_value = false;

static bool SecurityTestCallback(Local<v8::Context> accessing_context,
                                 Local<v8::Object> accessed_object,
                                 Local<v8::Value> data) {
  return security_check_value;
}


TEST(PrototypeGetterAccessCheck) {
  i::v8_flags.allow_natives_syntax = true;
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  auto fun_templ = v8::FunctionTemplate::New(isolate);
  auto getter_templ = v8::FunctionTemplate::New(isolate, handle_property);
  getter_templ->SetAcceptAnyReceiver(false);
  fun_templ->InstanceTemplate()->SetAccessorProperty(v8_str("foo"),
                                                     getter_templ);
  auto obj_templ = v8::ObjectTemplate::New(isolate);
  obj_templ->SetAccessCheckCallback(SecurityTestCallback);
  CHECK(env->Global()
            ->Set(env.local(), v8_str("Fun"),
                  fun_templ->GetFunction(env.local()).ToLocalChecked())
            .FromJust());
  CHECK(env->Global()
            ->Set(env.local(), v8_str("obj"),
                  obj_templ->NewInstance(env.local()).ToLocalChecked())
            .FromJust());
  CHECK(env->Global()
            ->Set(env.local(), v8_str("obj2"),
                  obj_templ->NewInstance(env.local()).ToLocalChecked())
            .FromJust());

  security_check_value = true;
  CompileRun("var proto = new Fun();");
  CompileRun("obj.__proto__ = proto;");
  ExpectInt32("proto.foo", 907);

  // Test direct.
  security_check_value = true;
  ExpectInt32("obj.foo", 907);
  security_check_value = false;
  {
    v8::TryCatch try_catch(isolate);
    CompileRun("obj.foo");
    CHECK(try_catch.HasCaught());
  }

  // Test through call.
  security_check_value = true;
  ExpectInt32("proto.__lookupGetter__('foo').call(obj)", 907);
  security_check_value = false;
  {
    v8::TryCatch try_catch(isolate);
    CompileRun("proto.__lookupGetter__('foo').call(obj)");
    CHECK(try_catch.HasCaught());
  }

  // Test ics.
  CompileRun(
      "function f() {"
      "   var x;"
      "  for (var i = 0; i < 4; i++) {"
      "    x = obj.foo;"
      "  }"
      "  return x;"
      "};"
      "%PrepareFunctionForOptimization(f);");

  security_check_value = true;
  ExpectInt32("f()", 907);
  security_check_value = false;
  {
    v8::TryCatch try_catch(isolate);
    CompileRun("f();");
    CHECK(try_catch.HasCaught());
  }

  // Test TurboFan.
  CompileRun("%OptimizeFunctionOnNextCall(f);");

  security_check_value = true;
  ExpectInt32("f()", 907);
  security_check_value = false;
  {
    v8::TryCatch try_catch(isolate);
    CompileRun("f();");
    CHECK(try_catch.HasCaught());
  }
}

static void CheckReceiver(Local<Name> name,
                          const v8::PropertyCallbackInfo<v8::Value>& info) {
  CHECK(info.This()->IsObject());
}

TEST(Regress609134) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  auto fun_templ = v8::FunctionTemplate::New(isolate);
  fun_templ->InstanceTemplate()->SetNativeDataProperty(v8_str("foo"),
                                                       CheckReceiver);

  CHECK(env->Global()
            ->Set(env.local(), v8_str("Fun"),
                  fun_templ->GetFunction(env.local()).ToLocalChecked())
            .FromJust());

  CompileRun(
      "var f = new Fun();"
      "Number.prototype.__proto__ = f;"
      "var a = 42;"
      "for (var i = 0; i<3; i++) { a.foo; }");
}

TEST(ObjectSetLazyDataProperty) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::Object> obj = v8::Object::New(isolate);
  CHECK(env->Global()->Set(env.local(), v8_str("obj"), obj).FromJust());

  // Despite getting the property multiple times, the getter should only be
  // called once and data property reads should continue to produce the same
  // value.
  static int getter_call_count;
  getter_call_count = 0;
  auto result = obj->SetLazyDataProperty(
      env.local(), v8_str("foo"),
      [](Local<Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
        getter_call_count++;
        info.GetReturnValue().Set(getter_call_count);
      });
  CHECK(result.FromJust());
  CHECK_EQ(0, getter_call_count);
  for (int i = 0; i < 2; i++) {
    ExpectInt32("obj.foo", 1);
    CHECK_EQ(1, getter_call_count);
  }

  // Setting should overwrite the data property.
  result = obj->SetLazyDataProperty(
      env.local(), v8_str("bar"),
      [](Local<Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
        CHECK(false);
      });
  CHECK(result.FromJust());
  ExpectInt32("obj.bar = -1; obj.bar;", -1);
}

TEST(ObjectSetLazyDataPropertyForIndex) {
  // Regression test for crbug.com/1136800 .
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::
```