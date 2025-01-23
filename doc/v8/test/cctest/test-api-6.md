Response: The user wants a summary of the C++ code provided, focusing on its functionalities and relating it to JavaScript concepts. Since this is part 7 of a larger file, I need to consider that the code likely builds upon concepts introduced earlier.

Here's a breakdown of the thought process:

1. **Identify the Core Theme:** Skimming through the code, I see a lot of `THREADED_TEST` macros, which strongly suggest this file contains unit tests for V8's API. The tests seem to focus on how C++ interacts with JavaScript objects, prototypes, and function calls.

2. **Categorize Test Scenarios:**  I can group the tests based on the functionality they are exercising:
    * **Shadow Objects and Properties:**  Tests named `ShadowObjectAndDataProperty` and related variants. This seems to deal with how objects can intercept property access.
    * **Prototype Manipulation:** Tests like `SetPrototype`, `FunctionReadOnlyPrototype`, `SetPrototypeThrows`, and `FunctionRemovePrototype`. These are clearly about the JavaScript prototype chain.
    * **Property Access and Enumeration:**  `Regress91517` touches on property enumeration.
    * **Function Calls and Constructors:** `Constructor`, `FunctionDescriptorException`.
    * **`eval()` and Contexts:**  `EvalAliasedDynamic`, `CrossEval`, `EvalInDetachedGlobal`. These explore the behavior of `eval()` in different scenarios and contexts.
    * **Calling Non-Function Objects:** `CallAsFunction`, `CallableObject`. This is about making C++ objects callable from JavaScript.
    * **Undetectable Objects:** `Regress567998`.
    * **Handle Scopes:** `HandleIteration`. This is related to V8's memory management.
    * **Fast API Calls:** Tests involving `CallICFastApi`, `LoadICFastApi`, and `InterceptorCallICFastApi`. These are testing optimized paths for calling C++ functions from JavaScript.
    * **Error Handling and Exceptions:** Tests involving throwing getters, setters, and the propagation of exceptions (`GetterSetterExceptions`, `SetPrototypeThrows`, `VariousGetPropertiesAndThrowingCallbacks`, `ExceptionsDoNotPropagatePastTryCatch`).
    * **Inheritance and Overriding:** `Overriding`.
    * **`ShouldThrowOnError`:**  Tests checking the behavior of this flag in different API contexts.

3. **Summarize Each Category:**  For each category, I need to briefly explain what the tests are checking. I'll use descriptive language and highlight key V8 API functions being tested.

4. **Connect to JavaScript:** This is crucial. For each category, I need to provide a simple JavaScript example that illustrates the corresponding concept being tested in the C++ code. This helps the user understand the practical implications of the C++ API.

5. **Address the "Part 7 of 18" Constraint:**  I should explicitly mention that this part focuses on API testing, building upon earlier foundational parts and likely setting the stage for more complex interactions in later parts.

6. **Refine and Organize:** I'll structure the summary logically, starting with general API testing and moving towards more specific features. I'll ensure the language is clear and concise. I'll also pay attention to the naming conventions used in the C++ code (e.g., `ShadowObject`, `SetPrototype`) to make the explanation easier to follow.

7. **Self-Correction/Refinement during thought process:**
    * Initially, I might focus too much on the C++ implementation details. I need to shift the emphasis towards the *functionality* being tested and its JavaScript equivalent.
    * I should avoid getting bogged down in the internal V8 details like "feedback vectors" unless it's directly relevant to the *observable behavior* from a JavaScript perspective.
    * For JavaScript examples, I need to keep them short and focused on the specific concept being illustrated. Avoid complex scenarios that might obscure the point.

By following this thought process, I can generate a comprehensive and informative summary that addresses all aspects of the user's request.
这个C++源代码文件 `v8/test/cctest/test-api.cc` 的第7部分，主要包含了一系列用于测试 **V8 JavaScript 引擎 C++ API** 功能的单元测试。 这些测试覆盖了与 **对象属性处理、原型链操作、函数调用、上下文管理、异常处理以及调用 C++ 代码** 等相关的 API 功能。

更具体地说，这部分测试主要关注以下几个方面：

**1. 影子对象 (Shadow Objects) 和数据属性 (Data Properties):**

*   测试了如何使用 `NamedPropertyHandlerConfiguration` 创建影子对象，并通过 `__proto__` 来模拟全局对象的行为。
*   验证了当访问影子对象的属性时，`NamedPropertyGetter` 回调函数会被调用。
*   测试了影子对象与正常数据属性的交互，包括属性的可枚举性。
*   特别关注了在优化代码中，影子对象对全局变量访问的影响，以及反馈向量的正确性。

**JavaScript 示例:**

```javascript
// 假设 C++ 代码创建了一个影子对象并将其设置为全局对象的原型

// 访问全局对象上不存在的变量 x，实际上会触发影子对象的 getter
console.log(x); // 可能会输出 C++ 代码中影子对象返回的值

// 判断属性是否可枚举，这与 C++ 代码中的 propertyIsEnumerable 测试对应
console.log(this.propertyIsEnumerable('some_property_on_shadow'));
```

**2. 原型链操作 (Prototype Chain Manipulation):**

*   测试了 `SetPrototypeV2` 方法，用于动态设置对象的原型。
*   验证了设置原型后，对象能够访问原型链上的属性。
*   测试了尝试设置只读的原型属性时的行为。
*   测试了设置原型时可能抛出的异常情况，例如形成循环引用。
*   测试了使用 `RemovePrototype` 方法移除函数的原型。

**JavaScript 示例:**

```javascript
// 对应 C++ 代码中的 SetPrototype 测试
const obj0 = {};
const obj1 = { y: 1 };
const obj2 = { z: 2 };

Object.setPrototypeOf(obj0, obj1);
console.log(obj0.y); // 输出 1

Object.setPrototypeOf(obj1, obj2);
console.log(obj0.z); // 输出 2

// 对应 C++ 代码中的 FunctionReadOnlyPrototype 测试
function Func() {}
Object.defineProperty(Func, 'prototype', { writable: false });
// 尝试修改 Func 的 prototype 会失败或被忽略

// 对应 C++ 代码中的 SetPrototypeThrows 测试
const a = {};
const b = {};
Object.setPrototypeOf(a, b);
try {
  Object.setPrototypeOf(b, a); // 尝试创建循环原型链会抛出错误 (在某些引擎中)
} catch (e) {
  console.error("Caught an error:", e);
}
```

**3. 函数只读原型 (Function ReadOnly Prototype):**

*   测试了 `ReadOnlyPrototype` 方法，用于将函数的 `prototype` 属性设置为只读。
*   验证了在 JavaScript 中无法修改只读的 `prototype` 属性。

**4. 获取属性名称 (Getting Property Names):**

*   测试了 `GetOwnPropertyNames` 方法在处理具有原型链的对象时的行为，特别是当原型链中存在字典类型的属性存储时，防止程序崩溃。

**5. `eval` 函数和上下文 (Eval and Contexts):**

*   测试了 `eval` 函数在不同上下文中的行为，包括动态解析的 `eval` 和跨上下文的 `eval`。
*   验证了跨上下文 `eval` 中变量的作用域和 `this` 指针的指向。
*   测试了在与其全局代理分离的上下文中调用 `eval` 的情况。

**JavaScript 示例:**

```javascript
// 对应 C++ 代码中的 EvalAliasedDynamic 测试
function f(obj) {
  var foo = 2;
  with (obj) {
    return eval('foo');
  }
}
var globalFoo = 0;
console.log(f({})); // 输出 2 (因为 with 作用域中的 foo 被优先访问)
console.log(f(this)); // 输出 0 (访问全局的 globalFoo)

// 对应 C++ 代码中的 CrossEval 测试
const otherGlobal = {};
globalThis.other = otherGlobal;
other.eval('var bar = 123;');
console.log(other.bar); // 输出 123
// console.log(bar); // 在当前上下文中无法访问 other 中的 bar

// 对应 C++ 代码中的 EvalInDetachedGlobal 测试 (概念上)
// V8 内部实现细节，JavaScript 中无法直接模拟
```

**6. 调用非函数对象 (Calling Non-Function Objects):**

*   测试了 `SetCallAsFunctionHandler` 方法，允许将非函数对象作为函数调用。
*   验证了调用处理函数的参数和返回值。

**JavaScript 示例:**

```javascript
// 对应 C++ 代码中的 CallAsFunction 测试 (假设 C++ 创建了一个可调用的对象 myObj)
console.log(myObj(42)); // 实际上会调用 C++ 中设置的 CallAsFunctionHandler
```

**7. 构造函数 (Constructor):**

*   测试了通过 C++ API 创建的函数作为构造函数时的行为。
*   验证了通过 `new` 关键字创建的实例的 `constructor` 属性指向该函数。

**8. 异常处理 (Exception Handling):**

*   测试了在 getter 和 setter 回调函数中抛出异常时的行为。
*   验证了 `TryCatch` 能够捕获 C++ 回调函数中抛出的异常。
*   测试了消息监听器 (Message Listener) 如何处理异常。

**9. 句柄迭代 (Handle Iteration):**

*   测试了 `HandleScope` 的使用和句柄的数量管理。

**10. 快速 API 调用 (Fast API Calls):**

*   测试了使用 `v8::FunctionTemplate::New` 创建带有 C++ 回调函数的 JavaScript 函数。
*   验证了直接调用 C++ 回调函数的性能和在垃圾回收期间的稳定性。
*   测试了拦截器 (Interceptor) 与快速 API 调用的交互。
*   测试了快速 API 调用中抛出异常的情况。

**11. `ShouldThrowOnError` 标志:**

*   测试了在属性访问器 (getter/setter) 和拦截器中使用 `ShouldThrowOnError` 标志，该标志指示操作是否应该在发生错误时抛出异常。

**关系到 JavaScript 功能的总结:**

这部分 C++ 代码直接测试了 V8 引擎实现 JavaScript 语言特性的底层 API。 例如：

*   **原型继承:** `SetPrototypeV2` 和相关的测试直接对应 JavaScript 中 `Object.setPrototypeOf()` 和 `__proto__` 的行为。
*   **属性描述符:** `FunctionReadOnlyPrototype` 测试了 JavaScript 中属性描述符的 `writable` 属性。
*   **`eval` 函数:**  `EvalAliasedDynamic` 和 `CrossEval` 测试了 JavaScript 中 `eval` 函数在不同作用域和上下文中的行为。
*   **函数调用:** `CallAsFunction` 测试了 JavaScript 中对象被作为函数调用时的特殊机制。
*   **构造函数和 `new` 关键字:** `Constructor` 测试了 JavaScript 中构造函数的行为。
*   **异常处理:**  `GetterSetterExceptions` 等测试模拟了 JavaScript 中 `try...catch` 语句捕获异常的情况。

总而言之，这部分测试代码是 V8 引擎开发过程中的重要组成部分，它确保了 V8 的 C++ API 能够正确地实现和支持 JavaScript 的各种语言特性。 作为第7部分，它很可能建立在之前部分介绍的基础 API 功能之上，并为后续更复杂的测试场景奠定基础。

### 提示词
```
这是目录为v8/test/cctest/test-api.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第7部分，共18部分，请归纳一下它的功能
```

### 源代码
```
ance(context.local())
                       .ToLocalChecked();
  CHECK(context->Global()
            ->Set(context.local(), v8_str("__proto__"), o)
            .FromJust());

  Local<Value> value =
      CompileRun("this.propertyIsEnumerable(0)");
  CHECK(value->IsBoolean());
  CHECK(!value->BooleanValue(isolate));

  value = CompileRun("x");
  CHECK_EQ(12, value->Int32Value(context.local()).FromJust());

  value = CompileRun("f()");
  CHECK_EQ(42, value->Int32Value(context.local()).FromJust());

  CompileRun("y = 43");
  CHECK_EQ(0, shadow_y_setter_call_count);
  value = CompileRun("y");
  CHECK_EQ(0, shadow_y_getter_call_count);
  CHECK_EQ(43, value->Int32Value(context.local()).FromJust());
}

THREADED_TEST(ShadowObjectAndDataProperty) {
  // Lite mode doesn't make use of feedback vectors, which is what we
  // want to ensure has the correct form.
  if (i::v8_flags.lite_mode) return;
  // This test mimics the kind of shadow property the Chromium embedder
  // uses for undeclared globals. The IC subsystem has special handling
  // for this case, using a PREMONOMORPHIC state to delay entering
  // MONOMORPHIC state until enough information is available to support
  // efficient access and good feedback for optimization.
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope handle_scope(isolate);
  i::v8_flags.allow_natives_syntax = true;

  Local<ObjectTemplate> global_template = v8::ObjectTemplate::New(isolate);
  LocalContext context(nullptr, global_template);

  Local<v8::FunctionTemplate> t = v8::FunctionTemplate::New(isolate);
  t->InstanceTemplate()->SetHandler(
      v8::NamedPropertyHandlerConfiguration(ShadowNamedGet));

  Local<Value> o = t->GetFunction(context.local())
                       .ToLocalChecked()
                       ->NewInstance(context.local())
                       .ToLocalChecked();
  CHECK(context->Global()
            ->Set(context.local(), v8_str("__proto__"), o)
            .FromJust());

  CompileRun(
      "function foo(x) { i = x; }"
      "%EnsureFeedbackVectorForFunction(foo);"
      "foo(0)");

  i::DirectHandle<i::JSFunction> foo = i::Cast<i::JSFunction>(
      v8::Utils::OpenDirectHandle(*context->Global()
                                       ->Get(context.local(), v8_str("foo"))
                                       .ToLocalChecked()));
  CHECK(foo->has_feedback_vector());
  i::FeedbackSlot slot = i::FeedbackVector::ToSlot(0);
  i::FeedbackNexus nexus(CcTest::i_isolate(), foo->feedback_vector(), slot);
  CHECK_EQ(i::FeedbackSlotKind::kStoreGlobalSloppy, nexus.kind());
  CompileRun("foo(1)");
  CHECK_EQ(i::InlineCacheState::MONOMORPHIC, nexus.ic_state());
  // We go a bit further, checking that the form of monomorphism is
  // a PropertyCell in the vector. This is because we want to make sure
  // we didn't settle for a "poor man's monomorphism," such as a
  // slow_stub bailout which would mean a trip to the runtime on all
  // subsequent stores, and a lack of feedback for the optimizing
  // compiler downstream.
  i::Tagged<i::HeapObject> heap_object;
  CHECK(nexus.GetFeedback().GetHeapObject(&heap_object));
  CHECK(IsPropertyCell(heap_object));
}

THREADED_TEST(ShadowObjectAndDataPropertyTurbo) {
  // This test is the same as the previous one except that it triggers
  // optimization of {foo} after its first invocation.
  i::v8_flags.allow_natives_syntax = true;

  if (i::v8_flags.lite_mode) return;
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope handle_scope(isolate);

  Local<ObjectTemplate> global_template = v8::ObjectTemplate::New(isolate);
  LocalContext context(nullptr, global_template);

  Local<v8::FunctionTemplate> t = v8::FunctionTemplate::New(isolate);
  t->InstanceTemplate()->SetHandler(
      v8::NamedPropertyHandlerConfiguration(ShadowNamedGet));

  Local<Value> o = t->GetFunction(context.local())
                       .ToLocalChecked()
                       ->NewInstance(context.local())
                       .ToLocalChecked();
  CHECK(context->Global()
            ->Set(context.local(), v8_str("__proto__"), o)
            .FromJust());

  CompileRun(
      "function foo(x) { i = x; };"
      "%PrepareFunctionForOptimization(foo);"
      "foo(0)");

  i::DirectHandle<i::JSFunction> foo = i::Cast<i::JSFunction>(
      v8::Utils::OpenDirectHandle(*context->Global()
                                       ->Get(context.local(), v8_str("foo"))
                                       .ToLocalChecked()));
  CHECK(foo->has_feedback_vector());
  i::FeedbackSlot slot = i::FeedbackVector::ToSlot(0);
  i::FeedbackNexus nexus(CcTest::i_isolate(), foo->feedback_vector(), slot);
  CHECK_EQ(i::FeedbackSlotKind::kStoreGlobalSloppy, nexus.kind());
  CompileRun("%OptimizeFunctionOnNextCall(foo); foo(1)");
  CHECK_EQ(i::InlineCacheState::MONOMORPHIC, nexus.ic_state());
  i::Tagged<i::HeapObject> heap_object;
  CHECK(nexus.GetFeedback().GetHeapObject(&heap_object));
  CHECK(IsPropertyCell(heap_object));
}

THREADED_TEST(SetPrototype) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope handle_scope(isolate);

  Local<v8::FunctionTemplate> t0 = v8::FunctionTemplate::New(isolate);
  t0->InstanceTemplate()->Set(isolate, "x", v8_num(0));
  Local<v8::FunctionTemplate> t1 = v8::FunctionTemplate::New(isolate);
  t1->InstanceTemplate()->Set(isolate, "y", v8_num(1));
  Local<v8::FunctionTemplate> t2 = v8::FunctionTemplate::New(isolate);
  t2->InstanceTemplate()->Set(isolate, "z", v8_num(2));
  Local<v8::FunctionTemplate> t3 = v8::FunctionTemplate::New(isolate);
  t3->InstanceTemplate()->Set(isolate, "u", v8_num(3));

  Local<v8::Object> o0 = t0->GetFunction(context.local())
                             .ToLocalChecked()
                             ->NewInstance(context.local())
                             .ToLocalChecked();
  Local<v8::Object> o1 = t1->GetFunction(context.local())
                             .ToLocalChecked()
                             ->NewInstance(context.local())
                             .ToLocalChecked();
  Local<v8::Object> o2 = t2->GetFunction(context.local())
                             .ToLocalChecked()
                             ->NewInstance(context.local())
                             .ToLocalChecked();
  Local<v8::Object> o3 = t3->GetFunction(context.local())
                             .ToLocalChecked()
                             ->NewInstance(context.local())
                             .ToLocalChecked();

  CHECK_EQ(0, o0->Get(context.local(), v8_str("x"))
                  .ToLocalChecked()
                  ->Int32Value(context.local())
                  .FromJust());
  CHECK(o0->SetPrototypeV2(context.local(), o1).FromJust());
  CHECK_EQ(0, o0->Get(context.local(), v8_str("x"))
                  .ToLocalChecked()
                  ->Int32Value(context.local())
                  .FromJust());
  CHECK_EQ(1, o0->Get(context.local(), v8_str("y"))
                  .ToLocalChecked()
                  ->Int32Value(context.local())
                  .FromJust());
  CHECK(o1->SetPrototypeV2(context.local(), o2).FromJust());
  CHECK_EQ(0, o0->Get(context.local(), v8_str("x"))
                  .ToLocalChecked()
                  ->Int32Value(context.local())
                  .FromJust());
  CHECK_EQ(1, o0->Get(context.local(), v8_str("y"))
                  .ToLocalChecked()
                  ->Int32Value(context.local())
                  .FromJust());
  CHECK_EQ(2, o0->Get(context.local(), v8_str("z"))
                  .ToLocalChecked()
                  ->Int32Value(context.local())
                  .FromJust());
  CHECK(o2->SetPrototypeV2(context.local(), o3).FromJust());
  CHECK_EQ(0, o0->Get(context.local(), v8_str("x"))
                  .ToLocalChecked()
                  ->Int32Value(context.local())
                  .FromJust());
  CHECK_EQ(1, o0->Get(context.local(), v8_str("y"))
                  .ToLocalChecked()
                  ->Int32Value(context.local())
                  .FromJust());
  CHECK_EQ(2, o0->Get(context.local(), v8_str("z"))
                  .ToLocalChecked()
                  ->Int32Value(context.local())
                  .FromJust());
  CHECK_EQ(3, o0->Get(context.local(), v8_str("u"))
                  .ToLocalChecked()
                  ->Int32Value(context.local())
                  .FromJust());

  Local<Value> proto =
      o0->Get(context.local(), v8_str("__proto__")).ToLocalChecked();
  CHECK(proto->IsObject());
  CHECK(proto.As<v8::Object>()->Equals(context.local(), o1).FromJust());

  Local<Value> proto0 = o0->GetPrototypeV2();
  CHECK(proto0->IsObject());
  CHECK(proto0.As<v8::Object>()->Equals(context.local(), o1).FromJust());

  Local<Value> proto1 = o1->GetPrototypeV2();
  CHECK(proto1->IsObject());
  CHECK(proto1.As<v8::Object>()->Equals(context.local(), o2).FromJust());

  Local<Value> proto2 = o2->GetPrototypeV2();
  CHECK(proto2->IsObject());
  CHECK(proto2.As<v8::Object>()->Equals(context.local(), o3).FromJust());
}


// Getting property names of an object with a prototype chain that
// triggers dictionary elements in GetOwnPropertyNames() shouldn't
// crash the runtime.
THREADED_TEST(Regress91517) {
  i::v8_flags.allow_natives_syntax = true;
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope handle_scope(isolate);

  Local<v8::FunctionTemplate> t1 = v8::FunctionTemplate::New(isolate);
  t1->InstanceTemplate()->Set(isolate, "foo", v8_num(1));
  Local<v8::FunctionTemplate> t2 = v8::FunctionTemplate::New(isolate);
  t2->InstanceTemplate()->Set(isolate, "fuz1", v8_num(2));
  t2->InstanceTemplate()->Set(isolate, "objects",
                              v8::ObjectTemplate::New(isolate));
  t2->InstanceTemplate()->Set(isolate, "fuz2", v8_num(2));
  Local<v8::FunctionTemplate> t3 = v8::FunctionTemplate::New(isolate);
  t3->InstanceTemplate()->Set(isolate, "boo", v8_num(3));
  Local<v8::FunctionTemplate> t4 = v8::FunctionTemplate::New(isolate);
  t4->InstanceTemplate()->Set(isolate, "baz", v8_num(4));

  // Force dictionary-based properties.
  v8::base::ScopedVector<char> name_buf(1024);
  for (int i = 1; i <= 1000; i++) {
    v8::base::SNPrintF(name_buf, "sdf%d", i);
    t2->InstanceTemplate()->Set(v8_str(name_buf.begin()), v8_num(2));
  }

  Local<v8::Object> o1 = t1->GetFunction(context.local())
                             .ToLocalChecked()
                             ->NewInstance(context.local())
                             .ToLocalChecked();
  Local<v8::Object> o2 = t2->GetFunction(context.local())
                             .ToLocalChecked()
                             ->NewInstance(context.local())
                             .ToLocalChecked();
  Local<v8::Object> o3 = t3->GetFunction(context.local())
                             .ToLocalChecked()
                             ->NewInstance(context.local())
                             .ToLocalChecked();
  Local<v8::Object> o4 = t4->GetFunction(context.local())
                             .ToLocalChecked()
                             ->NewInstance(context.local())
                             .ToLocalChecked();

  CHECK(o4->SetPrototypeV2(context.local(), o3).FromJust());
  CHECK(o3->SetPrototypeV2(context.local(), o2).FromJust());
  CHECK(o2->SetPrototypeV2(context.local(), o1).FromJust());

  // Call the runtime version of GetOwnPropertyNames() on the natively
  // created object through JavaScript.
  CHECK(context->Global()->Set(context.local(), v8_str("obj"), o4).FromJust());
  // PROPERTY_FILTER_NONE = 0
  CompileRun("var names = %GetOwnPropertyKeys(obj, 0);");

  ExpectInt32("names.length", 1);
  ExpectTrue("names.indexOf(\"baz\") >= 0");
  ExpectFalse("names.indexOf(\"boo\") >= 0");
  ExpectFalse("names.indexOf(\"foo\") >= 0");
  ExpectFalse("names.indexOf(\"fuz1\") >= 0");
  ExpectFalse("names.indexOf(\"objects\") >= 0");
  ExpectFalse("names.indexOf(\"fuz2\") >= 0");
  ExpectTrue("names[1005] == undefined");
}


THREADED_TEST(FunctionReadOnlyPrototype) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope handle_scope(isolate);

  Local<v8::FunctionTemplate> t1 = v8::FunctionTemplate::New(isolate);
  t1->PrototypeTemplate()->Set(isolate, "x", v8::Integer::New(isolate, 42));
  t1->ReadOnlyPrototype();
  CHECK(context->Global()
            ->Set(context.local(), v8_str("func1"),
                  t1->GetFunction(context.local()).ToLocalChecked())
            .FromJust());
  // Configured value of ReadOnly flag.
  CHECK(
      CompileRun(
          "(function() {"
          "  descriptor = Object.getOwnPropertyDescriptor(func1, 'prototype');"
          "  return (descriptor['writable'] == false);"
          "})()")
          ->BooleanValue(isolate));
  CHECK_EQ(
      42,
      CompileRun("func1.prototype.x")->Int32Value(context.local()).FromJust());
  CHECK_EQ(42, CompileRun("func1.prototype = {}; func1.prototype.x")
                   ->Int32Value(context.local())
                   .FromJust());

  Local<v8::FunctionTemplate> t2 = v8::FunctionTemplate::New(isolate);
  t2->PrototypeTemplate()->Set(isolate, "x", v8::Integer::New(isolate, 42));
  CHECK(context->Global()
            ->Set(context.local(), v8_str("func2"),
                  t2->GetFunction(context.local()).ToLocalChecked())
            .FromJust());
  // Default value of ReadOnly flag.
  CHECK(
      CompileRun(
          "(function() {"
          "  descriptor = Object.getOwnPropertyDescriptor(func2, 'prototype');"
          "  return (descriptor['writable'] == true);"
          "})()")
          ->BooleanValue(isolate));
  CHECK_EQ(
      42,
      CompileRun("func2.prototype.x")->Int32Value(context.local()).FromJust());
}


THREADED_TEST(SetPrototypeThrows) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope handle_scope(isolate);

  Local<v8::FunctionTemplate> t = v8::FunctionTemplate::New(isolate);

  Local<v8::Object> o0 = t->GetFunction(context.local())
                             .ToLocalChecked()
                             ->NewInstance(context.local())
                             .ToLocalChecked();
  Local<v8::Object> o1 = t->GetFunction(context.local())
                             .ToLocalChecked()
                             ->NewInstance(context.local())
                             .ToLocalChecked();

  CHECK(o0->SetPrototypeV2(context.local(), o1).FromJust());
  // If setting the prototype leads to the cycle, SetPrototype should
  // return false, because cyclic prototype chains would be invalid.
  v8::TryCatch try_catch(isolate);
  CHECK(o1->SetPrototypeV2(context.local(), o0).IsNothing());
  CHECK(!try_catch.HasCaught());

  CHECK_EQ(42, CompileRun("function f() { return 42; }; f()")
                   ->Int32Value(context.local())
                   .FromJust());
}


THREADED_TEST(FunctionRemovePrototype) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope handle_scope(isolate);

  Local<v8::FunctionTemplate> t1 = v8::FunctionTemplate::New(isolate);
  t1->RemovePrototype();
  Local<v8::Function> fun = t1->GetFunction(context.local()).ToLocalChecked();
  CHECK(!fun->IsConstructor());
  CHECK(context->Global()->Set(context.local(), v8_str("fun"), fun).FromJust());
  CHECK(!CompileRun("'prototype' in fun")->BooleanValue(isolate));

  v8::TryCatch try_catch(isolate);
  CompileRun("new fun()");
  CHECK(try_catch.HasCaught());

  try_catch.Reset();
  CHECK(fun->NewInstance(context.local()).IsEmpty());
  CHECK(try_catch.HasCaught());
}


THREADED_TEST(GetterSetterExceptions) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope handle_scope(isolate);
  CompileRun(
      "function Foo() { };"
      "function Throw() { throw 5; };"
      "var x = { };"
      "x.__defineSetter__('set', Throw);"
      "x.__defineGetter__('get', Throw);");
  Local<v8::Object> x = Local<v8::Object>::Cast(
      context->Global()->Get(context.local(), v8_str("x")).ToLocalChecked());
  v8::TryCatch try_catch(isolate);
  CHECK(x->Set(context.local(), v8_str("set"), v8::Integer::New(isolate, 8))
            .IsNothing());
  CHECK(x->Get(context.local(), v8_str("get")).IsEmpty());
  CHECK(x->Set(context.local(), v8_str("set"), v8::Integer::New(isolate, 8))
            .IsNothing());
  CHECK(x->Get(context.local(), v8_str("get")).IsEmpty());
  CHECK(x->Set(context.local(), v8_str("set"), v8::Integer::New(isolate, 8))
            .IsNothing());
  CHECK(x->Get(context.local(), v8_str("get")).IsEmpty());
  CHECK(x->Set(context.local(), v8_str("set"), v8::Integer::New(isolate, 8))
            .IsNothing());
  CHECK(x->Get(context.local(), v8_str("get")).IsEmpty());
}


THREADED_TEST(Constructor) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope handle_scope(isolate);
  Local<v8::FunctionTemplate> templ = v8::FunctionTemplate::New(isolate);
  templ->SetClassName(v8_str("Fun"));
  Local<Function> cons = templ->GetFunction(context.local()).ToLocalChecked();
  CHECK(
      context->Global()->Set(context.local(), v8_str("Fun"), cons).FromJust());
  Local<v8::Object> inst = cons->NewInstance(context.local()).ToLocalChecked();
  i::DirectHandle<i::JSReceiver> obj = v8::Utils::OpenDirectHandle(*inst);
  CHECK(IsJSObject(*obj));
  Local<Value> value = CompileRun("(new Fun()).constructor === Fun");
  CHECK(value->BooleanValue(isolate));
}


THREADED_TEST(FunctionDescriptorException) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope handle_scope(isolate);
  Local<v8::FunctionTemplate> templ = v8::FunctionTemplate::New(isolate);
  templ->SetClassName(v8_str("Fun"));
  Local<Function> cons = templ->GetFunction(context.local()).ToLocalChecked();
  CHECK(
      context->Global()->Set(context.local(), v8_str("Fun"), cons).FromJust());
  Local<Value> value = CompileRun(
      "function test() {"
      "  try {"
      "    (new Fun()).blah()"
      "  } catch (e) {"
      "    var str = String(e);"
      // "    if (str.indexOf('TypeError') == -1) return 1;"
      // "    if (str.indexOf('[object Fun]') != -1) return 2;"
      // "    if (str.indexOf('#<Fun>') == -1) return 3;"
      "    return 0;"
      "  }"
      "  return 4;"
      "}"
      "test();");
  CHECK_EQ(0, value->Int32Value(context.local()).FromJust());
}


THREADED_TEST(EvalAliasedDynamic) {
  LocalContext current;
  v8::HandleScope scope(current->GetIsolate());

  // Tests where aliased eval can only be resolved dynamically.
  Local<Script> script = v8_compile(
      "function f(x) { "
      "  var foo = 2;"
      "  with (x) { return eval('foo'); }"
      "}"
      "foo = 0;"
      "result1 = f(new Object());"
      "result2 = f(this);"
      "var x = new Object();"
      "x.eval = function(x) { return 1; };"
      "result3 = f(x);");
  script->Run(current.local()).ToLocalChecked();
  CHECK_EQ(2, current->Global()
                  ->Get(current.local(), v8_str("result1"))
                  .ToLocalChecked()
                  ->Int32Value(current.local())
                  .FromJust());
  CHECK_EQ(0, current->Global()
                  ->Get(current.local(), v8_str("result2"))
                  .ToLocalChecked()
                  ->Int32Value(current.local())
                  .FromJust());
  CHECK_EQ(1, current->Global()
                  ->Get(current.local(), v8_str("result3"))
                  .ToLocalChecked()
                  ->Int32Value(current.local())
                  .FromJust());

  v8::TryCatch try_catch(current->GetIsolate());
  script = v8_compile(
      "function f(x) { "
      "  var bar = 2;"
      "  with (x) { return eval('bar'); }"
      "}"
      "result4 = f(this)");
  script->Run(current.local()).ToLocalChecked();
  CHECK(!try_catch.HasCaught());
  CHECK_EQ(2, current->Global()
                  ->Get(current.local(), v8_str("result4"))
                  .ToLocalChecked()
                  ->Int32Value(current.local())
                  .FromJust());

  try_catch.Reset();
}


THREADED_TEST(CrossEval) {
  v8::HandleScope scope(CcTest::isolate());
  LocalContext other;
  LocalContext current;

  Local<String> token = v8_str("<security token>");
  other->SetSecurityToken(token);
  current->SetSecurityToken(token);

  // Set up reference from current to other.
  CHECK(current->Global()
            ->Set(current.local(), v8_str("other"), other->Global())
            .FromJust());

  // Check that new variables are introduced in other context.
  Local<Script> script = v8_compile("other.eval('var foo = 1234')");
  script->Run(current.local()).ToLocalChecked();
  Local<Value> foo =
      other->Global()->Get(current.local(), v8_str("foo")).ToLocalChecked();
  CHECK_EQ(1234, foo->Int32Value(other.local()).FromJust());
  CHECK(!current->Global()->Has(current.local(), v8_str("foo")).FromJust());

  // Check that writing to non-existing properties introduces them in
  // the other context.
  script = v8_compile("other.eval('na = 1234')");
  script->Run(current.local()).ToLocalChecked();
  CHECK_EQ(1234, other->Global()
                     ->Get(current.local(), v8_str("na"))
                     .ToLocalChecked()
                     ->Int32Value(other.local())
                     .FromJust());
  CHECK(!current->Global()->Has(current.local(), v8_str("na")).FromJust());

  // Check that global variables in current context are not visible in other
  // context.
  v8::TryCatch try_catch(CcTest::isolate());
  script = v8_compile("var bar = 42; other.eval('bar');");
  CHECK(script->Run(current.local()).IsEmpty());
  CHECK(try_catch.HasCaught());
  try_catch.Reset();

  // Check that local variables in current context are not visible in other
  // context.
  script = v8_compile(
      "(function() { "
      "  var baz = 87;"
      "  return other.eval('baz');"
      "})();");
  CHECK(script->Run(current.local()).IsEmpty());
  CHECK(try_catch.HasCaught());
  try_catch.Reset();

  // Check that global variables in the other environment are visible
  // when evaluting code.
  CHECK(other->Global()
            ->Set(other.local(), v8_str("bis"), v8_num(1234))
            .FromJust());
  script = v8_compile("other.eval('bis')");
  CHECK_EQ(1234, script->Run(current.local())
                     .ToLocalChecked()
                     ->Int32Value(current.local())
                     .FromJust());
  CHECK(!try_catch.HasCaught());

  // Check that the 'this' pointer points to the global object evaluating
  // code.
  CHECK(other->Global()
            ->Set(current.local(), v8_str("t"), other->Global())
            .FromJust());
  script = v8_compile("other.eval('this == t')");
  Local<Value> result = script->Run(current.local()).ToLocalChecked();
  CHECK(result->IsTrue());
  CHECK(!try_catch.HasCaught());

  // Check that variables introduced in with-statement are not visible in
  // other context.
  script = v8_compile("with({x:2}){other.eval('x')}");
  CHECK(script->Run(current.local()).IsEmpty());
  CHECK(try_catch.HasCaught());
  try_catch.Reset();

  // Check that you cannot use 'eval.call' with another object than the
  // current global object.
  script = v8_compile("other.y = 1; eval.call(other, 'y')");
  CHECK(script->Run(current.local()).IsEmpty());
  CHECK(try_catch.HasCaught());
}


// Test that calling eval in a context which has been detached from
// its global proxy works.
THREADED_TEST(EvalInDetachedGlobal) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);

  v8::Local<Context> context0 = Context::New(isolate);
  v8::Local<Context> context1 = Context::New(isolate);
  Local<String> token = v8_str("<security token>");
  context0->SetSecurityToken(token);
  context1->SetSecurityToken(token);

  // Set up function in context0 that uses eval from context0.
  context0->Enter();
  v8::Local<v8::Value> fun = CompileRun(
      "var x = 42;"
      "(function() {"
      "  var e = eval;"
      "  return function(s) { return e(s); }"
      "})()");
  context0->Exit();

  // Put the function into context1 and call it before and after
  // detaching the global.  Before detaching, the call succeeds and
  // after detaching undefined is returned.
  context1->Enter();
  CHECK(context1->Global()->Set(context1, v8_str("fun"), fun).FromJust());
  v8::Local<v8::Value> x_value = CompileRun("fun('x')");
  CHECK_EQ(42, x_value->Int32Value(context1).FromJust());
  context0->DetachGlobal();
  x_value = CompileRun("fun('x')");
  CHECK(x_value->IsUndefined());
  context1->Exit();
}


THREADED_TEST(CrossLazyLoad) {
  v8::HandleScope scope(CcTest::isolate());
  LocalContext other;
  LocalContext current;

  Local<String> token = v8_str("<security token>");
  other->SetSecurityToken(token);
  current->SetSecurityToken(token);

  // Set up reference from current to other.
  CHECK(current->Global()
            ->Set(current.local(), v8_str("other"), other->Global())
            .FromJust());

  // Trigger lazy loading in other context.
  Local<Script> script = v8_compile("other.eval('new Date(42)')");
  Local<Value> value = script->Run(current.local()).ToLocalChecked();
  CHECK_EQ(42.0, value->NumberValue(current.local()).FromJust());
}


static void call_as_function(const v8::FunctionCallbackInfo<v8::Value>& args) {
  ApiTestFuzzer::Fuzz();
  if (args.IsConstructCall()) {
    if (args[0]->IsInt32()) {
      args.GetReturnValue().Set(
          v8_num(-args[0]
                      ->Int32Value(args.GetIsolate()->GetCurrentContext())
                      .FromJust()));
      return;
    }
  }

  args.GetReturnValue().Set(args[0]);
}


// Test that a call handler can be set for objects which will allow
// non-function objects created through the API to be called as
// functions.
THREADED_TEST(CallAsFunction) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);

  {
    Local<v8::FunctionTemplate> t = v8::FunctionTemplate::New(isolate);
    Local<ObjectTemplate> instance_template = t->InstanceTemplate();
    instance_template->SetCallAsFunctionHandler(call_as_function);
    Local<v8::Object> instance = t->GetFunction(context.local())
                                     .ToLocalChecked()
                                     ->NewInstance(context.local())
                                     .ToLocalChecked();
    CHECK(context->Global()
              ->Set(context.local(), v8_str("obj"), instance)
              .FromJust());
    v8::TryCatch try_catch(isolate);
    Local<Value> value;
    CHECK(!try_catch.HasCaught());

    value = CompileRun("obj(42)");
    CHECK(!try_catch.HasCaught());
    CHECK_EQ(42, value->Int32Value(context.local()).FromJust());

    value = CompileRun("(function(o){return o(49)})(obj)");
    CHECK(!try_catch.HasCaught());
    CHECK_EQ(49, value->Int32Value(context.local()).FromJust());

    // test special case of call as function
    value = CompileRun("[obj]['0'](45)");
    CHECK(!try_catch.HasCaught());
    CHECK_EQ(45, value->Int32Value(context.local()).FromJust());

    value = CompileRun(
        "obj.call = Function.prototype.call;"
        "obj.call(null, 87)");
    CHECK(!try_catch.HasCaught());
    CHECK_EQ(87, value->Int32Value(context.local()).FromJust());

    // Regression tests for bug #1116356: Calling call through call/apply
    // must work for non-function receivers.
    const char* apply_99 = "Function.prototype.call.apply(obj, [this, 99])";
    value = CompileRun(apply_99);
    CHECK(!try_catch.HasCaught());
    CHECK_EQ(99, value->Int32Value(context.local()).FromJust());

    const char* call_17 = "Function.prototype.call.call(obj, this, 17)";
    value = CompileRun(call_17);
    CHECK(!try_catch.HasCaught());
    CHECK_EQ(17, value->Int32Value(context.local()).FromJust());

    // Check that the call-as-function handler can be called through new.
    value = CompileRun("new obj(43)");
    CHECK(!try_catch.HasCaught());
    CHECK_EQ(-43, value->Int32Value(context.local()).FromJust());

    // Check that the call-as-function handler can be called through
    // the API.
    v8::Local<Value> args[] = {v8_num(28)};
    value = instance->CallAsFunction(context.local(), instance, 1, args)
                .ToLocalChecked();
    CHECK(!try_catch.HasCaught());
    CHECK_EQ(28, value->Int32Value(context.local()).FromJust());
  }

  {
    Local<v8::FunctionTemplate> t = v8::FunctionTemplate::New(isolate);
    Local<ObjectTemplate> instance_template(t->InstanceTemplate());
    USE(instance_template);
    Local<v8::Object> instance = t->GetFunction(context.local())
                                     .ToLocalChecked()
                                     ->NewInstance(context.local())
                                     .ToLocalChecked();
    CHECK(context->Global()
              ->Set(context.local(), v8_str("obj2"), instance)
              .FromJust());
    v8::TryCatch try_catch(isolate);
    Local<Value> value;
    CHECK(!try_catch.HasCaught());

    // Call an object without call-as-function handler through the JS
    value = CompileRun("obj2(28)");
    CHECK(value.IsEmpty());
    CHECK(try_catch.HasCaught());
    String::Utf8Value exception_value1(isolate, try_catch.Exception());
    // TODO(verwaest): Better message
    CHECK_EQ(0, strcmp("TypeError: obj2 is not a function", *exception_value1));
    try_catch.Reset();

    // Call an object without call-as-function handler through the API
    v8::Local<Value> args[] = {v8_num(28)};
    CHECK(
        instance->CallAsFunction(context.local(), instance, 1, args).IsEmpty());
    CHECK(try_catch.HasCaught());
    String::Utf8Value exception_value2(isolate, try_catch.Exception());
    CHECK_EQ(0,
             strcmp("TypeError: object is not a function", *exception_value2));
    try_catch.Reset();
  }

  {
    Local<v8::FunctionTemplate> t = v8::FunctionTemplate::New(isolate);
    Local<ObjectTemplate> instance_template = t->InstanceTemplate();
    instance_template->SetCallAsFunctionHandler(ThrowValue);
    Local<v8::Object> instance = t->GetFunction(context.local())
                                     .ToLocalChecked()
                                     ->NewInstance(context.local())
                                     .ToLocalChecked();
    CHECK(context->Global()
              ->Set(context.local(), v8_str("obj3"), instance)
              .FromJust());
    v8::TryCatch try_catch(isolate);
    Local<Value> value;
    CHECK(!try_catch.HasCaught());

    // Catch the exception which is thrown by call-as-function handler
    value = CompileRun("obj3(22)");
    CHECK(try_catch.HasCaught());
    String::Utf8Value exception_value1(isolate, try_catch.Exception());
    CHECK_EQ(0, strcmp("22", *exception_value1));
    try_catch.Reset();

    v8::Local<Value> args[] = {v8_num(23)};
    CHECK(
        instance->CallAsFunction(context.local(), instance, 1, args).IsEmpty());
    CHECK(try_catch.HasCaught());
    String::Utf8Value exception_value2(isolate, try_catch.Exception());
    CHECK_EQ(0, strcmp("23", *exception_value2));
    try_catch.Reset();
  }

  {
    Local<v8::FunctionTemplate> t = v8::FunctionTemplate::New(isolate);
    Local<ObjectTemplate> instance_template = t->InstanceTemplate();
    instance_template->SetCallAsFunctionHandler(ReturnThis);
    Local<v8::Object> instance = t->GetFunction(context.local())
                                     .ToLocalChecked()
                                     ->NewInstance(context.local())
                                     .ToLocalChecked();

    Local<v8::Value> a1 =
        instance
            ->CallAsFunction(context.local(), v8::Undefined(isolate), 0,
                             nullptr)
            .ToLocalChecked();
    CHECK(a1->StrictEquals(instance));
    Local<v8::Value> a2 =
        instance->CallAsFunction(context.local(), v8::Null(isolate), 0, nullptr)
            .ToLocalChecked();
    CHECK(a2->StrictEquals(instance));
    Local<v8::Value> a3 =
        instance->CallAsFunction(context.local(), v8_num(42), 0, nullptr)
            .ToLocalChecked();
    CHECK(a3->StrictEquals(instance));
    Local<v8::Value> a4 =
        instance->CallAsFunction(context.local(), v8_str("hello"), 0, nullptr)
            .ToLocalChecked();
    CHECK(a4->StrictEquals(instance));
    Local<v8::Value> a5 =
        instance->CallAsFunction(context.local(), v8::True(isolate), 0, nullptr)
            .ToLocalChecked();
    CHECK(a5->StrictEquals(instance));
  }

  {
    CompileRun(
        "function ReturnThisSloppy() {"
        "  return this;"
        "}"
        "function ReturnThisStrict() {"
        "  'use strict';"
        "  return this;"
        "}");
    Local<Function> ReturnThisSloppy = Local<Function>::Cast(
        context->Global()
            ->Get(context.local(), v8_str("ReturnThisSloppy"))
            .ToLocalChecked());
    Local<Function> ReturnThisStrict = Local<Function>::Cast(
        context->Global()
            ->Get(context.local(), v8_str("ReturnThisStrict"))
            .ToLocalChecked());

    Local<v8::Value> a1 =
        ReturnThisSloppy
            ->CallAsFunction(context.local(), v8::Undefined(isolate), 0,
                             nullptr)
            .ToLocalChecked();
    CHECK(a1->StrictEquals(context->Global()));
    Local<v8::Value> a2 =
        ReturnThisSloppy
            ->CallAsFunction(context.local(), v8::Null(isolate), 0, nullptr)
            .ToLocalChecked();
    CHECK(a2->StrictEquals(context->Global()));
    Local<v8::Value> a3 =
        ReturnThisSloppy
            ->CallAsFunction(context.local(), v8_num(42), 0, nullptr)
            .ToLocalChecked();
    CHECK(a3->IsNumberObject());
    CHECK_EQ(42.0, a3.As<v8::NumberObject>()->ValueOf());
    Local<v8::Value> a4 =
        ReturnThisSloppy
            ->CallAsFunction(context.local(), v8_str("hello"), 0, nullptr)
            .ToLocalChecked();
    CHECK(a4->IsStringObject());
    CHECK(a4.As<v8::StringObject>()->ValueOf()->StrictEquals(v8_str("hello")));
    Local<v8::Value> a5 =
        ReturnThisSloppy
            ->CallAsFunction(context.local(), v8::True(isolate), 0, nullptr)
            .ToLocalChecked();
    CHECK(a5->IsBooleanObject());
    CHECK(a5.As<v8::BooleanObject>()->ValueOf());

    Local<v8::Value> a6 =
        ReturnThisStrict
            ->CallAsFunction(context.local(), v8::Undefined(isolate), 0,
                             nullptr)
            .ToLocalChecked();
    CHECK(a6->IsUndefined());
    Local<v8::Value> a7 =
        ReturnThisStrict
            ->CallAsFunction(context.local(), v8::Null(isolate), 0, nullptr)
            .ToLocalChecked();
    CHECK(a7->IsNull());
    Local<v8::Value> a8 =
        ReturnThisStrict
            ->CallAsFunction(context.local(), v8_num(42), 0, nullptr)
            .ToLocalChecked();
    CHECK(a8->StrictEquals(v8_num(42)));
    Local<v8::Value> a9 =
        ReturnThisStrict
            ->CallAsFunction(context.local(), v8_str("hello"), 0, nullptr)
            .ToLocalChecked();
    CHECK(a9->StrictEquals(v8_str("hello")));
    Local<v8::Value> a10 =
        ReturnThisStrict
            ->CallAsFunction(context.local(), v8::True(isolate), 0, nullptr)
            .ToLocalChecked();
    CHECK(a10->StrictEquals(v8::True(isolate)));
  }
}


// Check whether a non-function object is callable.
THREADED_TEST(CallableObject) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);

  {
    Local<ObjectTemplate> instance_template = ObjectTemplate::New(isolate);
    instance_template->SetCallAsFunctionHandler(call_as_function);
    Local<Object> instance =
        instance_template->NewInstance(context.local()).ToLocalChecked();
    v8::TryCatch try_catch(isolate);

    CHECK(instance->IsCallable());
    CHECK(!try_catch.HasCaught());
  }

  {
    Local<ObjectTemplate> instance_template = ObjectTemplate::New(isolate);
    Local<Object> instance =
        instance_template->NewInstance(context.local()).ToLocalChecked();
    v8::TryCatch try_catch(isolate);

    CHECK(!instance->IsCallable());
    CHECK(!try_catch.HasCaught());
  }

  {
    Local<FunctionTemplate> function_template =
        FunctionTemplate::New(isolate, call_as_function);
    Local<Function> function =
        function_template->GetFunction(context.local()).ToLocalChecked();
    Local<Object> instance = function;
    v8::TryCatch try_catch(isolate);

    CHECK(instance->IsCallable());
    CHECK(!try_catch.HasCaught());
  }

  {
    Local<FunctionTemplate> function_template = FunctionTemplate::New(isolate);
    Local<Function> function =
        function_template->GetFunction(context.local()).ToLocalChecked();
    Local<Object> instance = function;
    v8::TryCatch try_catch(isolate);

    CHECK(instance->IsCallable());
    CHECK(!try_catch.HasCaught());
  }
}


THREADED_TEST(Regress567998) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  Local<v8::FunctionTemplate> desc =
      v8::FunctionTemplate::New(env->GetIsolate());
  desc->InstanceTemplate()->MarkAsUndetectable();  // undetectable
  desc->InstanceTemplate()->SetCallAsFunctionHandler(ReturnThis);  // callable

  Local<v8::Object> obj = desc->GetFunction(env.local())
                              .ToLocalChecked()
                              ->NewInstance(env.local())
                              .ToLocalChecked();
  CHECK(
      env->Global()->Set(env.local(), v8_str("undetectable"), obj).FromJust());

  ExpectString("undetectable.toString()", "[object Object]");
  ExpectString("typeof undetectable", "undefined");
  ExpectString("typeof(undetectable)", "undefined");
  ExpectBoolean("typeof undetectable == 'undefined'", true);
  ExpectBoolean("typeof undetectable == 'object'", false);
  ExpectBoolean("if (undetectable) { true; } else { false; }", false);
  ExpectBoolean("!undetectable", true);

  ExpectObject("true&&undetectable", obj);
  ExpectBoolean("false&&undetectable", false);
  ExpectBoolean("true||undetectable", true);
  ExpectObject("false||undetectable", obj);

  ExpectObject("undetectable&&true", obj);
  ExpectObject("undetectable&&false", obj);
  ExpectBoolean("undetectable||true", true);
  ExpectBoolean("undetectable||false", false);

  ExpectBoolean("undetectable==null", true);
  ExpectBoolean("null==undetectable", true);
  ExpectBoolean("undetectable==undefined", true);
  ExpectBoolean("undefined==undetectable", true);
  ExpectBoolean("undetectable==undetectable", true);

  ExpectBoolean("undetectable===null", false);
  ExpectBoolean("null===undetectable", false);
  ExpectBoolean("undetectable===undefined", false);
  ExpectBoolean("undefined===undetectable", false);
  ExpectBoolean("undetectable===undetectable", true);
}


static int Recurse(v8::Isolate* isolate, int depth, int iterations) {
  v8::HandleScope scope(isolate);
  if (depth == 0) return v8::HandleScope::NumberOfHandles(isolate);
  for (int i = 0; i < iterations; i++) {
    Local<v8::Number> n(v8::Integer::New(isolate, 42));
  }
  return Recurse(isolate, depth - 1, iterations);
}


THREADED_TEST(HandleIteration) {
  static const int kIterations = 500;
  static const int kNesting = 200;
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope0(isolate);
  CHECK_EQ(0, v8::HandleScope::NumberOfHandles(isolate));
  {
    v8::HandleScope scope1(isolate);
    CHECK_EQ(0, v8::HandleScope::NumberOfHandles(isolate));
    for (int i = 0; i < kIterations; i++) {
      Local<v8::Number> n(v8::Integer::New(CcTest::isolate(), 42));
      CHECK_EQ(i + 1, v8::HandleScope::NumberOfHandles(isolate));
    }

    CHECK_EQ(kIterations, v8::HandleScope::NumberOfHandles(isolate));
    {
      v8::HandleScope scope2(CcTest::isolate());
      for (int j = 0; j < kIterations; j++) {
        Local<v8::Number> n(v8::Integer::New(CcTest::isolate(), 42));
        CHECK_EQ(j + 1 + kIterations,
                 v8::HandleScope::NumberOfHandles(isolate));
      }
    }
    CHECK_EQ(kIterations, v8::HandleScope::NumberOfHandles(isolate));
  }
  CHECK_EQ(0, v8::HandleScope::NumberOfHandles(isolate));
  CHECK_EQ(kNesting * kIterations, Recurse(isolate, kNesting, kIterations));
}

namespace {
v8::Intercepted InterceptorCallICFastApi(
    Local<Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  // The request is not intercepted so don't call ApiTestFuzzer::Fuzz() here.
  CheckReturnValue(info, FUNCTION_ADDR(InterceptorCallICFastApi));
  int* call_count =
      reinterpret_cast<int*>(v8::External::Cast(*info.Data())->Value());
  ++(*call_count);
  if ((*call_count) % 20 == 0) {
    i::heap::InvokeMajorGC(CcTest::heap());
  }
  return v8::Intercepted::kNo;
}

void FastApiCallback_TrivialSignature(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  ApiTestFuzzer::Fuzz();
  CheckReturnValue(info, FUNCTION_ADDR(FastApiCallback_TrivialSignature));
  v8::Isolate* isolate = CcTest::isolate();
  CHECK_EQ(isolate, info.GetIsolate());
  CHECK(info.This()
            ->Equals(isolate->GetCurrentContext(),
                     info.HolderSoonToBeDeprecated())
            .FromJust());
  CHECK(info.Data()
            ->Equals(isolate->GetCurrentContext(), v8_str("method_data"))
            .FromJust());
  info.GetReturnValue().Set(
      info[0]->Int32Value(isolate->GetCurrentContext()).FromJust() + 1);
}

// Allow usages of v8::Object::GetPrototype() for now.
// TODO(https://crbug.com/333672197): remove.
START_ALLOW_USE_DEPRECATED()

void FastApiCallback_SimpleSignature(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  ApiTestFuzzer::Fuzz();
  CheckReturnValue(info, FUNCTION_ADDR(FastApiCallback_SimpleSignature));
  v8::Isolate* isolate = CcTest::isolate();
  CHECK_EQ(isolate, info.GetIsolate());
  CHECK(info.This()
            ->GetPrototype()
            ->Equals(isolate->GetCurrentContext(),
                     info.HolderSoonToBeDeprecated())
            .FromJust());
  CHECK(info.Data()
            ->Equals(isolate->GetCurrentContext(), v8_str("method_data"))
            .FromJust());
  // Note, we're using HasRealNamedProperty instead of Has to avoid
  // invoking the interceptor again.
  CHECK(info.HolderSoonToBeDeprecated()
            ->HasRealNamedProperty(isolate->GetCurrentContext(), v8_str("foo"))
            .FromJust());
  info.GetReturnValue().Set(
      info[0]->Int32Value(isolate->GetCurrentContext()).FromJust() + 1);
}

// Allow usages of v8::Object::GetPrototype() for now.
// TODO(https://crbug.com/333672197): remove.
END_ALLOW_USE_DEPRECATED()

// Helper to maximize the odds of object moving.
void GenerateSomeGarbage() {
  CompileRun(
      "var garbage;"
      "for (var i = 0; i < 1000; i++) {"
      "  garbage = [1/i, \"garbage\" + i, garbage, {foo: garbage}];"
      "}"
      "garbage = undefined;");
}

void DirectApiCallback(const v8::FunctionCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  static int count = 0;
  if (count++ % 3 == 0) {
    i::heap::InvokeMajorGC(CcTest::heap());
    // This should move the stub
    GenerateSomeGarbage();  // This should ensure the old stub memory is flushed
  }
}
}  // namespace

THREADED_TEST(CallICFastApi_DirectCall_GCMoveStub) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> nativeobject_templ =
      v8::ObjectTemplate::New(isolate);
  nativeobject_templ->Set(isolate, "callback",
                          v8::FunctionTemplate::New(isolate,
                                                    DirectApiCallback));
  v8::Local<v8::Object> nativeobject_obj =
      nativeobject_templ->NewInstance(context.local()).ToLocalChecked();
  CHECK(context->Global()
            ->Set(context.local(), v8_str("nativeobject"), nativeobject_obj)
            .FromJust());
  // call the api function multiple times to ensure direct call stub creation.
  CompileRun(
      "function f() {"
      "  for (var i = 1; i <= 30; i++) {"
      "    nativeobject.callback();"
      "  }"
      "}"
      "f();");
}

void ThrowingDirectApiCallback(
    const v8::FunctionCallbackInfo<v8::Value>& args) {
  args.GetIsolate()->ThrowException(v8_str("g"));
}

THREADED_TEST(CallICFastApi_DirectCall_Throw) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> nativeobject_templ =
      v8::ObjectTemplate::New(isolate);
  nativeobject_templ->Set(
      isolate, "callback",
      v8::FunctionTemplate::New(isolate, ThrowingDirectApiCallback));
  v8::Local<v8::Object> nativeobject_obj =
      nativeobject_templ->NewInstance(context.local()).ToLocalChecked();
  CHECK(context->Global()
            ->Set(context.local(), v8_str("nativeobject"), nativeobject_obj)
            .FromJust());
  // call the api function multiple times to ensure direct call stub creation.
  v8::Local<Value> result = CompileRun(
      "var result = '';"
      "function f() {"
      "  for (var i = 1; i <= 5; i++) {"
      "    try { nativeobject.callback(); } catch (e) { result += e; }"
      "  }"
      "}"
      "f(); result;");
  CHECK(v8_str("ggggg")->Equals(context.local(), result).FromJust());
}

namespace {
int p_getter_count_3;

Local<Value> DoDirectGetter() {
  if (++p_getter_count_3 % 3 == 0) {
    i::heap::InvokeMajorGC(CcTest::heap());
    GenerateSomeGarbage();
  }
  return v8_str("Direct Getter Result");
}

void DirectGetterCallback(Local<Name> name,
                          const v8::PropertyCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  CheckReturnValue(info, FUNCTION_ADDR(DirectGetterCallback));
  info.GetReturnValue().Set(DoDirectGetter());
}

template <typename Accessor>
void LoadICFastApi_DirectCall_GCMoveStub(Accessor accessor) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> obj = v8::ObjectTemplate::New(isolate);
  obj->SetNativeDataProperty(v8_str("p1"), accessor);
  CHECK(context->Global()
            ->Set(context.local(), v8_str("o1"),
                  obj->NewInstance(context.local()).ToLocalChecked())
            .FromJust());
  p_getter_count_3 = 0;
  v8::Local<v8::Value> result = CompileRun(
      "function f() {"
      "  for (var i = 0; i < 30; i++) o1.p1;"
      "  return o1.p1"
      "}"
      "f();");
  CHECK(v8_str("Direct Getter Result")
            ->Equals(context.local(), result)
            .FromJust());
  CHECK_EQ(31, p_getter_count_3);
}
}  // namespace

THREADED_PROFILED_TEST(LoadICFastApi_DirectCall_GCMoveStub) {
  LoadICFastApi_DirectCall_GCMoveStub(DirectGetterCallback);
}

void ThrowingDirectGetterCallback(
    Local<Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  info.GetIsolate()->ThrowException(v8_str("g"));
}

THREADED_TEST(LoadICFastApi_DirectCall_Throw) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> obj = v8::ObjectTemplate::New(isolate);
  obj->SetNativeDataProperty(v8_str("p1"), ThrowingDirectGetterCallback);
  CHECK(context->Global()
            ->Set(context.local(), v8_str("o1"),
                  obj->NewInstance(context.local()).ToLocalChecked())
            .FromJust());
  v8::Local<Value> result = CompileRun(
      "var result = '';"
      "for (var i = 0; i < 5; i++) {"
      "    try { o1.p1; } catch (e) { result += e; }"
      "}"
      "result;");
  CHECK(v8_str("ggggg")->Equals(context.local(), result).FromJust());
}

THREADED_PROFILED_TEST(InterceptorCallICFastApi_TrivialSignature) {
  int interceptor_call_count = 0;
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::FunctionTemplate> fun_templ =
      v8::FunctionTemplate::New(isolate);
  v8::Local<v8::FunctionTemplate> method_templ = v8::FunctionTemplate::New(
      isolate, FastApiCallback_TrivialSignature, v8_str("method_data"),
      v8::Local<v8::Signature>());
  v8::Local<v8::ObjectTemplate> proto_templ = fun_templ->PrototypeTemplate();
  proto_templ->Set(isolate, "method", method_templ);
  v8::Local<v8::ObjectTemplate> templ = fun_templ->InstanceTemplate();
  templ->SetHandler(v8::NamedPropertyHandlerConfiguration(
      InterceptorCallICFastApi, nullptr, nullptr, nullptr, nullptr,
      v8::External::New(isolate, &interceptor_call_count)));
  LocalContext context;
  v8::Local<v8::Function> fun =
      fun_templ->GetFunction(context.local()).ToLocalChecked();
  GenerateSomeGarbage();
  CHECK(context->Global()
            ->Set(context.local(), v8_str("o"),
                  fun->NewInstance(context.local()).ToLocalChecked())
            .FromJust());
  CompileRun(
      "var result = 0;"
      "for (var i = 0; i < 100; i++) {"
      "  result = o.method(41);"
      "}");
  CHECK_EQ(42, context->Global()
                   ->Get(context.local(), v8_str("result"))
                   .ToLocalChecked()
                   ->Int32Value(context.local())
                   .FromJust());
  CHECK_EQ(100, interceptor_call_count);
}

THREADED_PROFILED_TEST(CallICFastApi_TrivialSignature) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::FunctionTemplate> fun_templ =
      v8::FunctionTemplate::New(isolate);
  v8::Local<v8::FunctionTemplate> method_templ = v8::FunctionTemplate::New(
      isolate, FastApiCallback_TrivialSignature, v8_str("method_data"),
      v8::Local<v8::Signature>());
  v8::Local<v8::ObjectTemplate> proto_templ = fun_templ->PrototypeTemplate();
  proto_templ->Set(isolate, "method", method_templ);
  v8::Local<v8::ObjectTemplate> templ(fun_templ->InstanceTemplate());
  USE(templ);
  LocalContext context;
  v8::Local<v8::Function> fun =
      fun_templ->GetFunction(context.local()).ToLocalChecked();
  GenerateSomeGarbage();
  CHECK(context->Global()
            ->Set(context.local(), v8_str("o"),
                  fun->NewInstance(context.local()).ToLocalChecked())
            .FromJust());
  CompileRun(
      "var result = 0;"
      "for (var i = 0; i < 100; i++) {"
      "  result = o.method(41);"
      "}");

  CHECK_EQ(42, context->Global()
                   ->Get(context.local(), v8_str("result"))
                   .ToLocalChecked()
                   ->Int32Value(context.local())
                   .FromJust());
}

static void ThrowingGetter(Local<Name> name,
                           const v8::PropertyCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  ApiTestFuzzer::Fuzz();
  info.GetIsolate()->ThrowException(Local<Value>());
  info.GetReturnValue().SetUndefined();
}

THREADED_TEST(VariousGetPropertiesAndThrowingCallbacks) {
  LocalContext context;
  HandleScope scope(context->GetIsolate());

  Local<FunctionTemplate> templ = FunctionTemplate::New(context->GetIsolate());
  Local<ObjectTemplate> instance_templ = templ->InstanceTemplate();
  instance_templ->SetNativeDataProperty(v8_str("f"), ThrowingGetter);

  Local<Object> instance = templ->GetFunction(context.local())
                               .ToLocalChecked()
                               ->NewInstance(context.local())
                               .ToLocalChecked();

  Local<Object> another = Object::New(context->GetIsolate());
  CHECK(another->SetPrototypeV2(context.local(), instance).FromJust());

  Local<Object> with_js_getter = CompileRun(
      "o = {};\n"
      "o.__defineGetter__('f', function() { throw undefined; });\n"
      "o\n").As<Object>();
  CHECK(!with_js_getter.IsEmpty());

  TryCatch try_catch(context->GetIsolate());

  v8::MaybeLocal<Value> result =
      instance->GetRealNamedProperty(context.local(), v8_str("f"));
  CHECK(try_catch.HasCaught());
  try_catch.Reset();
  CHECK(result.IsEmpty());

  Maybe<PropertyAttribute> attr =
      instance->GetRealNamedPropertyAttributes(context.local(), v8_str("f"));
  CHECK(!try_catch.HasCaught());
  CHECK(Just(None) == attr);

  result = another->GetRealNamedProperty(context.local(), v8_str("f"));
  CHECK(try_catch.HasCaught());
  try_catch.Reset();
  CHECK(result.IsEmpty());

  attr = another->GetRealNamedPropertyAttributes(context.local(), v8_str("f"));
  CHECK(!try_catch.HasCaught());
  CHECK(Just(None) == attr);

  result = another->GetRealNamedPropertyInPrototypeChain(context.local(),
                                                         v8_str("f"));
  CHECK(try_catch.HasCaught());
  try_catch.Reset();
  CHECK(result.IsEmpty());

  attr = another->GetRealNamedPropertyAttributesInPrototypeChain(
      context.local(), v8_str("f"));
  CHECK(!try_catch.HasCaught());
  CHECK(Just(None) == attr);

  result = another->Get(context.local(), v8_str("f"));
  CHECK(try_catch.HasCaught());
  try_catch.Reset();
  CHECK(result.IsEmpty());

  result = with_js_getter->GetRealNamedProperty(context.local(), v8_str("f"));
  CHECK(try_catch.HasCaught());
  try_catch.Reset();
  CHECK(result.IsEmpty());

  attr = with_js_getter->GetRealNamedPropertyAttributes(context.local(),
                                                        v8_str("f"));
  CHECK(!try_catch.HasCaught());
  CHECK(Just(None) == attr);

  result = with_js_getter->Get(context.local(), v8_str("f"));
  CHECK(try_catch.HasCaught());
  try_catch.Reset();
  CHECK(result.IsEmpty());

  Local<Object> target = CompileRun("({})").As<Object>();
  Local<Object> handler = CompileRun("({})").As<Object>();
  Local<v8::Proxy> proxy =
      v8::Proxy::New(context.local(), target, handler).ToLocalChecked();

  result = target->GetRealNamedProperty(context.local(), v8_str("f"));
  CHECK(!try_catch.HasCaught());
  CHECK(result.IsEmpty());

  result = proxy->GetRealNamedProperty(context.local(), v8_str("f"));
  CHECK(!try_catch.HasCaught());
  CHECK(result.IsEmpty());
}

THREADED_TEST(GetRealNamedPropertyAttributes_With_Proxy) {
  LocalContext context;
  HandleScope scope(context->GetIsolate());

  {
    Local<Object> proxy =
        CompileRun(
            "new Proxy({ p: 1 }, { getOwnPropertyDescriptor: _ => { "
            "  throw new Error('xyz'); } });")
            .As<Object>();
    TryCatch try_catch(context->GetIsolate());
    v8::Maybe<v8::PropertyAttribute> result =
        proxy->GetRealNamedPropertyAttributes(context.local(), v8_str("p"));
    CHECK(result.IsNothing());
    CHECK(try_catch.HasCaught());
    CHECK(try_catch.Exception()
              .As<Object>()
              ->Get(context.local(), v8_str("message"))
              .ToLocalChecked()
              ->StrictEquals(v8_str("xyz")));
  }

  {
    Local<Object> proxy =
        CompileRun(
            "Object.create("
            "  new Proxy({ p: 1 }, { getOwnPropertyDescriptor: _ => { "
            "    throw new Error('abc'); } }))")
            .As<Object>();
    TryCatch try_catch(context->GetIsolate());
    v8::Maybe<v8::PropertyAttribute> result =
        proxy->GetRealNamedPropertyAttributesInPrototypeChain(context.local(),
                                                              v8_str("p"));
    CHECK(result.IsNothing());
    CHECK(try_catch.HasCaught());
    CHECK(try_catch.Exception()
              .As<Object>()
              ->Get(context.local(), v8_str("message"))
              .ToLocalChecked()
              ->StrictEquals(v8_str("abc")));
  }
}

static void ThrowingCallbackWithTryCatch(
    const v8::FunctionCallbackInfo<v8::Value>& args) {
  TryCatch try_catch(args.GetIsolate());
  // Verboseness is important: it triggers message delivery which can call into
  // external code.
  try_catch.SetVerbose(true);
  CompileRun("throw 'from JS';");
  CHECK(try_catch.HasCaught());
}


static int call_depth;


static void WithTryCatch(Local<Message> message, Local<Value> data) {
  TryCatch try_catch(CcTest::isolate());
}


static void ThrowFromJS(Local<Message> message, Local<Value> data) {
  if (--call_depth) CompileRun("throw 'ThrowInJS';");
}


static void ThrowViaApi(Local<Message> message, Local<Value> data) {
  if (--call_depth) CcTest::isolate()->ThrowException(v8_str("ThrowViaApi"));
}


static void WebKitLike(Local<Message> message, Local<Value> data) {
  Local<String> errorMessageString = message->Get();
  CHECK(!errorMessageString.IsEmpty());
  message->GetStackTrace();
  message->GetScriptOrigin().ResourceName();
}


THREADED_TEST(ExceptionsDoNotPropagatePastTryCatch) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  HandleScope scope(isolate);

  Local<Function> func =
      FunctionTemplate::New(isolate, ThrowingCallbackWithTryCatch)
          ->GetFunction(context.local())
          .ToLocalChecked();
  CHECK(
      context->Global()->Set(context.local(), v8_str("func"), func).FromJust());

  MessageCallback callbacks[] = {nullptr, WebKitLike, ThrowViaApi, ThrowFromJS,
                                 WithTryCatch};
  for (unsigned i = 0; i < sizeof(callbacks)/sizeof(callbacks[0]); i++) {
    MessageCallback callback = callbacks[i];
    if (callback != nullptr) {
      isolate->AddMessageListener(callback);
    }
    // Some small number to control number of times message handler should
    // throw an exception.
    call_depth = 5;
    ExpectFalse(
        "var thrown = false;\n"
        "try { func(); } catch(e) { thrown = true; }\n"
        "thrown\n");
    if (callback != nullptr) {
      isolate->RemoveMessageListeners(callback);
    }
  }
}

static void ParentGetter(Local<Name> name,
                         const v8::PropertyCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  ApiTestFuzzer::Fuzz();
  info.GetReturnValue().Set(v8_num(1));
}

static void ChildGetter(Local<Name> name,
                        const v8::PropertyCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  ApiTestFuzzer::Fuzz();
  info.GetReturnValue().Set(v8_num(42));
}

THREADED_TEST(Overriding) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);

  // Parent template.
  Local<v8::FunctionTemplate> parent_templ = v8::FunctionTemplate::New(isolate);
  Local<ObjectTemplate> parent_instance_templ =
      parent_templ->InstanceTemplate();
  parent_instance_templ->SetNativeDataProperty(v8_str("f"), ParentGetter);

  // Template that inherits from the parent template.
  Local<v8::FunctionTemplate> child_templ = v8::FunctionTemplate::New(isolate);
  Local<ObjectTemplate> child_instance_templ =
      child_templ->InstanceTemplate();
  child_templ->Inherit(parent_templ);
  // Override 'f'.  The child version of 'f' should get called for child
  // instances.
  child_instance_templ->SetNativeDataProperty(v8_str("f"), ChildGetter);
  // Add 'g' twice.  The 'g' added last should get called for instances.
  child_instance_templ->SetNativeDataProperty(v8_str("g"), ParentGetter);
  child_instance_templ->SetNativeDataProperty(v8_str("g"), ChildGetter);

  // Add 'h' as an accessor to the proto template with ReadOnly attributes
  // so 'h' can be shadowed on the instance object.
  Local<ObjectTemplate> child_proto_templ = child_templ->PrototypeTemplate();
  child_proto_templ->SetNativeDataProperty(v8_str("h"), ParentGetter, nullptr,
                                           v8::Local<Value>(), v8::ReadOnly);

  // Add 'i' as an accessor to the instance template with ReadOnly attributes
  // but the attribute does not have effect because it is duplicated with
  // nullptr setter.
  child_instance_templ->SetNativeDataProperty(v8_str("i"), ChildGetter, nullptr,
                                              v8::Local<Value>(), v8::ReadOnly);

  // Instantiate the child template.
  Local<v8::Object> instance = child_templ->GetFunction(context.local())
                                   .ToLocalChecked()
                                   ->NewInstance(context.local())
                                   .ToLocalChecked();

  // Check that the child function overrides the parent one.
  CHECK(context->Global()
            ->Set(context.local(), v8_str("o"), instance)
            .FromJust());
  Local<Value> value = v8_compile("o.f")->Run(context.local()).ToLocalChecked();
  // Check that the 'g' that was added last is hit.
  CHECK_EQ(42, value->Int32Value(context.local()).FromJust());
  value = v8_compile("o.g")->Run(context.local()).ToLocalChecked();
  CHECK_EQ(42, value->Int32Value(context.local()).FromJust());

  // Check that 'h' cannot be shadowed.
  value = v8_compile("o.h = 3; o.h")->Run(context.local()).ToLocalChecked();
  CHECK_EQ(1, value->Int32Value(context.local()).FromJust());

  // Check that 'i' cannot be shadowed or changed.
  value = v8_compile("o.i = 3; o.i")->Run(context.local()).ToLocalChecked();
  CHECK_EQ(42, value->Int32Value(context.local()).FromJust());
}

namespace {
void ShouldThrowOnErrorAccessorGetter(
    Local<Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  ApiTestFuzzer::Fuzz();
  v8::Isolate* isolate = info.GetIsolate();
  Local<Boolean> should_throw_on_error =
      Boolean::New(isolate, info.ShouldThrowOnError());
  info.GetReturnValue().Set(should_throw_on_error);
}

void ShouldThrowOnErrorAccessorSetter(
    Local<Name> name, Local<v8::Value> value,
    const v8::PropertyCallbackInfo<void>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  ApiTestFuzzer::Fuzz();
  v8::Isolate* isolate = info.GetIsolate();
  auto context = isolate->GetCurrentContext();
  Local<Boolean> should_throw_on_error_value =
      Boolean::New(isolate, info.ShouldThrowOnError());
  CHECK(context->Global()
            ->Set(isolate->GetCurrentContext(), v8_str("should_throw_setter"),
                  should_throw_on_error_value)
            .FromJust());
}
}  // namespace

THREADED_TEST(AccessorShouldThrowOnError) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  Local<Object> global = context->Global();

  Local<v8::FunctionTemplate> templ = v8::FunctionTemplate::New(isolate);
  Local<ObjectTemplate> instance_templ = templ->InstanceTemplate();
  instance_templ->SetNativeDataProperty(v8_str("f"),
                                        ShouldThrowOnErrorAccessorGetter,
                                        ShouldThrowOnErrorAccessorSetter);

  Local<v8::Object> instance = templ->GetFunction(context.local())
                                   .ToLocalChecked()
                                   ->NewInstance(context.local())
                                   .ToLocalChecked();

  CHECK(global->Set(context.local(), v8_str("o"), instance).FromJust());

  // SLOPPY mode
  Local<Value> value = v8_compile("o.f")->Run(context.local()).ToLocalChecked();
  CHECK(value->IsFalse());
  v8_compile("o.f = 153")->Run(context.local()).ToLocalChecked();
  value = global->Get(context.local(), v8_str("should_throw_setter"))
              .ToLocalChecked();
  CHECK(value->IsFalse());

  // STRICT mode
  value = v8_compile("'use strict';o.f")->Run(context.local()).ToLocalChecked();
  CHECK(value->IsFalse());
  v8_compile("'use strict'; o.f = 153")->Run(context.local()).ToLocalChecked();
  value = global->Get(context.local(), v8_str("should_throw_setter"))
              .ToLocalChecked();
  CHECK(value->IsTrue());
}

namespace {
v8::Intercepted ShouldThrowOnErrorGetter(
    Local<Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  ApiTestFuzzer::Fuzz();
  v8::Isolate* isolate = info.GetIsolate();
  Local<Boolean> should_throw_on_error =
      Boolean::New(isolate, info.ShouldThrowOnError());
  info.GetReturnValue().Set(should_throw_on_error);
  return v8::Intercepted::kYes;
}

v8::Intercepted ShouldThrowOnErrorSetter(
    Local<Name> name, Local<v8::Value> value,
    const v8::PropertyCallbackInfo<void>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  ApiTestFuzzer::Fuzz();
  v8::Isolate* isolate = info.GetIsolate();
  auto context = isolate->GetCurrentContext();
  Local<Boolean> should_throw_on_error_value =
      Boolean::New(isolate, info.ShouldThrowOnError());
  CHECK(context->Global()
            ->Set(isolate->GetCurrentContext(), v8_str("should_throw_setter"),
                  should_throw_on_error_value)
            .FromJust());
  return v8::Intercepted::kYes;
}

v8::Intercepted ShouldThrowOnErrorQuery(
    Local<Name> name, const v8::PropertyCallbackInfo<v8::Integer>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  ApiTestFuzzer::Fuzz();
  v8::Isolate* isolate = info.GetIsolate();
  info.GetReturnValue().Set(v8::None);

  auto context = isolate->GetCurrentContext();
  Local<Boolean> should_throw_on_error_value =
      Boolean::New(isolate, info.ShouldThrowOnError());
  CHECK(context->Global()
            ->Set(isolate->GetCurrentContext(), v8_str("should_throw_query"),
                  should_throw_on_error_value)
            .FromJust());
  return v8::Intercepted::kYes;
}

v8::Intercepted ShouldThrowOnErrorDeleter(
    Local<Name> name, const v8::PropertyCallbackInfo<v8::Boolean>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  ApiTestFuzzer::Fuzz();
  v8::Isolate* isolate = info.GetIsolate();
  info.GetReturnValue().Set(v8::True(isolate));

  auto context = isolate->GetCurrentContext();
  Local<Boolean> should_throw_on_error_value =
      Boolean::New(isolate, info.ShouldThrowOnError());
  CHECK(context->Global()
            ->Set(isolate->GetCurrentContext(), v8_str("should_throw_deleter"),
                  should_throw_on_error_value)
```