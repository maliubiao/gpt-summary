Response:
The user wants a summary of the functionality of the provided C++ code snippet from V8's test suite.

Here's a breakdown of the thought process to generate the response:

1. **Identify the Core Purpose:** The code consists of several `THREADED_TEST` functions. This immediately suggests that the file's primary purpose is to test specific aspects of the V8 API.

2. **Analyze Individual Tests:** Go through each `THREADED_TEST` function and determine what it's testing. Look for key API calls and the assertions being made.

    * **`ShadowObject`:**  This test sets up a "shadow object" on the prototype chain using a named property handler. It then checks if properties are correctly accessed from the shadow object and if `propertyIsEnumerable` behaves as expected.

    * **`ShadowObjectAndDataProperty`:**  This test builds upon the shadow object concept but focuses on how V8's inline caches (ICs) handle stores to global variables when a shadow object is present. It verifies that the IC transitions to a `MONOMORPHIC` state. The key here is `%EnsureFeedbackVectorForFunction`.

    * **`ShadowObjectAndDataPropertyTurbo`:** This is very similar to the previous test, but it explicitly triggers optimization of the function using `%PrepareFunctionForOptimization` and `%OptimizeFunctionOnNextCall`.

    * **`SetPrototype`:** This test explores the `SetPrototypeV2` API, checking how it modifies the prototype chain and how property lookups behave after setting prototypes. It also checks the `__proto__` property.

    * **`Regress91517`:** The name "Regress" suggests this is testing a fix for a specific bug. The code creates a prototype chain, including an object with many dictionary properties, and then uses `%GetOwnPropertyKeys` to ensure it doesn't crash.

    * **`FunctionReadOnlyPrototype`:** This test verifies the `ReadOnlyPrototype` API. It checks that the `prototype` property of a function created with `ReadOnlyPrototype` is non-writable.

    * **`SetPrototypeThrows`:** This test checks the behavior of `SetPrototypeV2` when attempting to create a cyclic prototype chain. It confirms that it doesn't throw an exception but returns `false` (or `IsNothing` in the C++ API).

    * **`FunctionRemovePrototype`:** This tests the `RemovePrototype` API. It verifies that functions created with this option are not constructable and don't have a `prototype` property.

    * **`GetterSetterExceptions`:** This test focuses on how exceptions thrown from getter and setter handlers are handled when using the `__defineSetter__` and `__defineGetter__` methods.

    * **`Constructor`:** This test verifies that the `constructor` property of an object created via a `FunctionTemplate` points back to the function.

    * **`FunctionDescriptorException`:** This test checks the error message and exception type when calling a non-existent method on an object created from a `FunctionTemplate`.

    * **`EvalAliasedDynamic`:**  This test explores different scenarios of using `eval` within `with` statements, demonstrating how `eval` can resolve identifiers dynamically.

    * **`CrossEval`:** This test focuses on cross-context evaluation using `eval`. It demonstrates how code evaluated in one context can access and modify variables in another context if the security tokens match.

    * **`EvalInDetachedGlobal`:** This test checks how `eval` behaves when the context from which the `eval` function originated has its global object detached.

    * **`CrossLazyLoad`:** This test checks that lazy loading of code works correctly across different contexts when using `eval`.

    * **`CallAsFunction`:** This test examines the `SetCallAsFunctionHandler` API. It demonstrates how to make non-function objects callable and how different calling conventions (`()`, `call`, `apply`, `new`) interact with this handler.

3. **Identify JavaScript Relevance and Examples:** Many tests directly relate to JavaScript features. For each relevant test, create a simple JavaScript example that illustrates the tested functionality.

4. **Identify Potential Programming Errors:**  Look for common mistakes that developers might make related to the tested APIs and concepts. Examples include prototype cycles, attempting to set read-only properties, and incorrect assumptions about `this` in different contexts.

5. **Check for Torque:** The prompt asks about `.tq` files. Scanning the code, there are no explicit mentions or indications of Torque. Therefore, the conclusion is that it's not Torque.

6. **Summarize Overall Functionality:** Combine the descriptions of individual tests into a concise summary of the file's purpose.

7. **Address the "Part X of Y" Request:**  Note that this is part 13 of 36, implying this file covers a subset of the API testing.

8. **Review and Refine:** Ensure the language is clear, accurate, and addresses all parts of the user's request. Double-check the JavaScript examples for correctness. Make sure the assumptions and input/output examples are helpful.
```cpp
THREADED_TEST(ShadowObject) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope handle_scope(isolate);
  int shadow_x_getter_call_count = 0;
  int shadow_x_setter_call_count = 0;
  int shadow_y_getter_call_count = 0;
  int shadow_y_setter_call_count = 0;

  auto ShadowNamedGet =
      [&](Local<Name> name, const PropertyCallbackInfo<Value>& info) {
    if (name->IsString() && v8_str("x")->Equals(info.GetIsolate(), name)) {
      shadow_x_getter_call_count++;
      info.GetReturnValue().Set(v8::Integer::New(info.GetIsolate(), 12));
    } else if (name->IsString() && v8_str("y")->Equals(info.GetIsolate(), name)) {
      shadow_y_getter_call_count++;
      info.GetReturnValue().Set(v8::Integer::New(info.GetIsolate(), 13));
    }
  };

  auto ShadowNamedSet =
      [&](Local<Name> name, Local<Value> value,
          const PropertyCallbackInfo<void>& info) {
    if (name->IsString() && v8_str("x")->Equals(info.GetIsolate(), name)) {
      shadow_x_setter_call_count++;
    } else if (name->IsString() && v8_str("y")->Equals(info.GetIsolate(), name)) {
      shadow_y_setter_call_count++;
    }
    CHECK(info.ShouldThrowOnError());
    // Don't actually set the property on the shadow object.
    return;
  };

  auto ShadowNamedQuery =
      [&](Local<Name> name, const PropertyCallbackInfo<Integer>& info) {
    if (name->IsString() &&
        (v8_str("x")->Equals(info.GetIsolate(), name) ||
         v8_str("y")->Equals(info.GetIsolate(), name))) {
      return info.GetReturnValue().Set(0);  // Present and configurable.
    }
    return MaybeLocal<Integer>();
  };

  auto ShadowNamedEnumerator =
      [&](const PropertyCallbackInfo<Array>& info) {
    Local<Array> array = Array::New(info.GetIsolate(), 2);
    array->Set(context.local(), 0, v8_str("x"));
    array->Set(context.local(), 1, v8_str("y"));
    info.GetReturnValue().Set(array);
  };

  auto ShadowNamedDeleter =
      [&](Local<Name> name, const PropertyCallbackInfo<Boolean>& info) {
    if (name->IsString() &&
        (v8_str("x")->Equals(info.GetIsolate(), name) ||
         v8_str("y")->Equals(info.GetIsolate(), name))) {
      return info.GetReturnValue().Set(false);  // Prevent deletion.
    }
    return MaybeLocal<Boolean>();
  };

  auto ShadowNamedDefiner =
      [&](Local<Name> name, const PropertyDescriptor& desc,
          const PropertyCallbackInfo<Boolean>& info) {
    if (name->IsString() &&
        (v8_str("x")->Equals(info.GetIsolate(), name) ||
         v8_str("y")->Equals(info.GetIsolate(), name))) {
      return info.GetReturnValue().Set(false);  // Prevent definition.
    }
    return MaybeLocal<Boolean>();
  };

  Local<v8::FunctionTemplate> t = v8::FunctionTemplate::New(isolate);
  t->InstanceTemplate()->SetHandler(
      v8::NamedPropertyHandlerConfiguration(ShadowNamedGet, ShadowNamedSet,
                                            ShadowNamedQuery,
                                            ShadowNamedDeleter,
                                            ShadowNamedEnumerator,
                                            ShadowNamedDefiner));

  Local<v8::Function> f = t->GetFunction(context.local()).ToLocalChecked();
  Local<v8::Object> o = f->NewInstance(context.local()).ToLocalChecked();
  CHECK(context->Global()
            ->Set(context.local(), v8_str("__proto__"), o)
            .FromJust());
  CompileRun("var x = 11");
  CompileRun("function f() { return 42; }");
  CompileRun("this[0] = 10");

  CHECK_EQ(0, shadow_x_getter_call_count);
  Local<Value> value = CompileRun("x");
  CHECK_EQ(1, shadow_x_getter_call_count);
  CHECK_EQ(12, value->Int32Value(context.local()).FromJust());

  CHECK_EQ(0, shadow_y_getter_call_count);
  value = CompileRun("y");
  CHECK_EQ(1, shadow_y_getter_call_count);
  CHECK_EQ(13, value->Int32Value(context.local()).FromJust());

  CHECK_EQ(0, shadow_x_setter_call_count);
  CompileRun("x = 14");
  CHECK_EQ(1, shadow_x_setter_call_count);
  value = CompileRun("x");
  CHECK_EQ(2, shadow_x_getter_call_count);
  CHECK_EQ(12, value->Int32Value(context.local()).FromJust());

  CHECK_EQ(0, shadow_y_setter_call_count);
  CompileRun("y = 15");
  CHECK_EQ(1, shadow_y_setter_call_count);
  value = CompileRun("y");
  CHECK_EQ(2, shadow_y_getter_call_count);
  CHECK_EQ(13, value->Int32Value(context.local()).FromJust());

  CHECK(CompileRun("delete x")->IsFalse());
  CHECK(CompileRun("delete y")->IsFalse());
  CHECK(CompileRun("delete this[0]")->IsTrue());

  CHECK(CompileRun("Object.defineProperty(this, 'x', { value: 16 })")->IsFalse());
  CHECK(CompileRun("Object.defineProperty(this, 'y', { value: 17 })")->IsFalse());

  Local<Object> obj = Object::New(isolate);
  CHECK(obj->DefineOwnProperty(context.local(), v8_str("x"),
                               v8::Integer::New(isolate, 18),
                               v8::ReadOnly).IsFalse());
  CHECK(obj->DefineOwnProperty(context.local(), v8_str("y"),
                               v8::Integer::New(isolate, 19),
                               v8::ReadOnly).IsFalse());

  value = CompileRun("Object.keys(this)");
  CHECK(value->IsArray());
  Local<Array> keys = Local<Array>::Cast(value);
  // '0', 'f'
  CHECK_EQ(2, keys->Length());

  value = CompileRun("Object.getOwnPropertyNames(this)");
  CHECK(value->IsArray());
  Local<Array> names = Local<Array>::Cast(value);
  // '0', 'f', 'x', 'y'
  CHECK_EQ(4, names->Length());

  value = CompileRun("for (var p in this) p");
  CHECK_EQ(v8_str("f"), value);

  Local<v8::FunctionTemplate> t1 = v8::FunctionTemplate::New(isolate);
  t1->InstanceTemplate()->SetHandler(
      v8::NamedPropertyHandlerConfiguration(ShadowNamedGet));
  Local<v8::Object> o1 = t1->GetFunction(context.local())
                             .ToLocalChecked()
                             ->NewInstance(context.local())
                             .ToLocalChecked();
  CHECK(context->Global()
            ->Set(context.local(), v8_str("__proto__"), o1)
            .FromJust());

  value = CompileRun("this.propertyIsEnumerable('x')");
  CHECK(value->IsBoolean());
  CHECK(value->BooleanValue(isolate));

  value = CompileRun("this.propertyIsEnumerable('y')");
  CHECK(value->IsBoolean());
  CHECK(value->BooleanValue(isolate));

  Local<v8::FunctionTemplate> t2 = v8::FunctionTemplate::New(isolate);
  t2->InstanceTemplate()->SetHandler(
      v8::NamedPropertyHandlerConfiguration(ShadowNamedGet, ShadowNamedSet));
  Local<v8::Object> o2 = t2->GetFunction(context.local())
                             .ToLocalChecked()
                             ->NewInstance(context.local())
                             .ToLocalChecked();
  CHECK(context->Global()
            ->Set(context.local(), v8_str("__proto__"), o2)
            .FromJust());

  value = CompileRun("this.propertyIsEnumerable('x')");
  CHECK(value->IsBoolean());
  CHECK(value->BooleanValue(isolate));

  value = CompileRun("this.propertyIsEnumerable('y')");
  CHECK(value->IsBoolean());
  CHECK(value->BooleanValue(isolate));

  Local<v8::FunctionTemplate> t3 = v8::FunctionTemplate::New(isolate);
  t3->InstanceTemplate()->SetHandler(
      v8::NamedPropertyHandlerConfiguration(ShadowNamedGet, ShadowNamedSet,
                                            ShadowNamedQuery));
  Local<v8::Object> o3 = t3->GetFunction(context.local())
                             .ToLocalChecked()
                             ->NewInstance(context.local())
                             .ToLocalChecked();
  CHECK(context->Global()
            ->Set(context.local(), v8_str("__proto__"), o3)
            .FromJust());

  value = CompileRun("this.propertyIsEnumerable('x')");
  CHECK(value->IsBoolean());
  CHECK(value->BooleanValue(isolate));

  value = CompileRun("this.propertyIsEnumerable('y')");
  CHECK(value->IsBoolean());
  CHECK(value->BooleanValue(isolate));

  Local<v8::FunctionTemplate> t4 = v8::FunctionTemplate::New(isolate);
  t4->InstanceTemplate()->SetHandler(
      v8::NamedPropertyHandlerConfiguration(ShadowNamedGet, ShadowNamedSet,
                                            ShadowNamedQuery, ShadowNamedDeleter));
  Local<v8::Object> o4 = t4->GetFunction(context.local())
                             .ToLocalChecked()
                             ->NewInstance(context.local())
                             .ToLocalChecked();
  CHECK(context->Global()
            ->Set(context.local(), v8_str("__proto__"), o4)
            .FromJust());

  value = CompileRun("this.propertyIsEnumerable('x')");
  CHECK(value->IsBoolean());
  CHECK(value->BooleanValue(isolate));

  value = CompileRun("this.propertyIsEnumerable('y')");
  CHECK(value->IsBoolean());
  CHECK(value->BooleanValue(isolate));

  Local<v8::FunctionTemplate> t5 = v8::FunctionTemplate::New(isolate);
  t5->InstanceTemplate()->SetHandler(
      v8::NamedPropertyHandlerConfiguration(ShadowNamedGet, ShadowNamedSet,
                                            ShadowNamedQuery, ShadowNamedDeleter,
                                            ShadowNamedEnumerator));
  Local<v8::Object> o5 = t5->GetFunction(context.local())
                             .ToLocalChecked()
                             ->NewInstance(context.local())
                             .ToLocalChecked();
  CHECK(context->Global()
            ->Set(context.local(), v8_str("__proto__"), o5)
            .FromJust());

  value = CompileRun("this.propertyIsEnumerable('x')");
  CHECK(value->IsBoolean());
  CHECK(value->BooleanValue(isolate));

  value = CompileRun("this.propertyIsEnumerable('y')");
  CHECK(value->IsBoolean());
  CHECK(value->BooleanValue(isolate));

  Local<v8::FunctionTemplate> t6 = v8::FunctionTemplate::New(isolate);
  t6->InstanceTemplate()->SetHandler(
      v8::NamedPropertyHandlerConfiguration(ShadowNamedGet, ShadowNamedSet,
                                            ShadowNamedQuery, ShadowNamedDeleter,
                                            ShadowNamedEnumerator, ShadowNamedDefiner));
  Local<v8::Object> o6 = t6->GetFunction(context.local())
                             .ToLocalChecked()
                             ->NewInstance(context.local())
                             .ToLocalChecked();
  CHECK(context->Global()
            ->Set(context.local(), v8_str("__proto__"), o6)
            .FromJust());

  value = CompileRun("this.propertyIsEnumerable('x')");
  CHECK(value->IsBoolean());
  CHECK(value->BooleanValue(isolate));

  value = CompileRun("this.propertyIsEnumerable('y')");
  CHECK(value->IsBoolean());
  CHECK(value->BooleanValue(isolate));
}

THREADED_TEST(ShadowObjectAndDataProperty) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope handle_scope(isolate);
  int shadow_y_getter_call_count = 0;
  int shadow_y_setter_call_count = 0;

  auto ShadowNamedGet =
      [&](Local<Name> name, const PropertyCallbackInfo<Value>& info) {
    if (name->IsString() && v8_str("y")->Equals(info.GetIsolate(), name)) {
      shadow_y_getter_call_count++;
      info.GetReturnValue().Set(v8::Integer::New(info.GetIsolate(), 13));
    }
  };

  auto ShadowNamedSet =
      [&](Local<Name> name, Local<Value> value,
          const PropertyCallbackInfo<void>& info) {
    if (name->IsString() && v8_str("y")->Equals(info.GetIsolate(), name)) {
      shadow_y_setter_call_count++;
    }
    CHECK(info.ShouldThrowOnError());
    // Don't actually set the property on the shadow object.
    return;
  };

  Local<v8::FunctionTemplate> t = v8::FunctionTemplate::New(isolate);
  t->InstanceTemplate()->SetHandler(
      v8::NamedPropertyHandlerConfiguration(ShadowNamedGet, ShadowNamedSet));

  Local<v8::Object> o = t->GetFunction(context.local())
                       .ToLocalChecked()
                       ->NewInstance(context.local())
                       .ToLocalChecked();
  CHECK(context->Global()
            ->Set(context.local(), v8_str("__proto__"), o)
            .FromJust());
  CompileRun("var x = 12");
  CompileRun("function f() { return 42; }");

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
```

### 功能列举

`v8/test/cctest/test-api.cc` 的这一部分主要测试了 V8 C++ API 中关于**对象属性处理、原型链操作以及代码执行**的相关功能。具体包括：

1. **影子对象 (Shadow Objects):**  测试了通过 `NamedPropertyHandlerConfiguration` 设置命名属性拦截器 (getter, setter, query, enumerator, deleter, definer) 来创建影子对象。当访问对象的属性时，这些拦截器可以介入并提供自定义的行为，例如返回预设的值，阻止属性的设置或删除等。

2. **影子对象和数据属性的交互:**  测试了当影子对象存在于原型链上时，对普通数据属性的访问和修改行为，以及 V8 的内联缓存 (Inline Cache, IC) 系统如何处理这种情况，特别是对于全局变量的赋值操作。

3. **原型链操作:** 测试了 `SetPrototypeV2` 方法，用于动态地修改对象的原型链。验证了原型链的正确设置和属性查找机制。

4. **只读原型:** 测试了 `ReadOnlyPrototype` 方法，用于将函数的 `prototype` 属性设置为只读，防止在 JavaScript 中修改。

5. **设置原型导致的异常:**  测试了当尝试通过 `SetPrototypeV2` 创建循环原型链时，V8 的行为，预期不会抛出异常。

6. **移除原型:** 测试了 `RemovePrototype` 方法，用于移除函数的 `prototype` 属性，使其不能作为构造函数使用。

7. **Getter 和 Setter 的异常处理:** 测试了当 getter 或 setter 函数抛出异常时，V8 的异常处理机制。

8. **构造函数:** 测试了通过 `FunctionTemplate` 创建的构造函数及其创建的实例对象的 `constructor` 属性。

9. **函数描述符异常:** 测试了当调用构造函数创建的实例对象上不存在的方法时，抛出的异常类型。

10. **别名动态求值 (Eval Aliased Dynamic):**  测试了在 `with` 语句中使用 `eval` 的场景，`eval` 中的变量解析会受到 `with` 语句的影响。

11. **跨上下文求值 (Cross Eval):** 测试了在不同的 V8 上下文之间使用 `eval` 执行代码的情况，验证了安全令牌 (security token) 的作用以及变量作用域的隔离。

12. **在分离的全局对象中求值:** 测试了在一个与其全局代理分离的上下文中调用 `eval` 的行为。

13. **跨上下文的惰性加载:** 测试了在不同上下文之间使用 `eval` 触发惰性加载代码的情况。

14. **将对象作为函数调用:** 测试了通过 `SetCallAsFunctionHandler` 设置回调函数，使得非函数对象可以像函数一样被调用，并验证了不同的调用方式（普通调用、`call`、`apply`、`new`）的行为。

### 关于 .tq 结尾

如果 `v8/test/cctest/test-api.cc` 以 `.tq` 结尾，那么它的确是一个 V8 Torque 源代码文件。然而，根据您提供的文件名，它以 `.cc` 结尾，因此是 C++ 源代码。

### 与 JavaScript 功能的关系及举例

这些测试用例覆盖了许多与 JavaScript 密切相关的功能，因为 V8 是 JavaScript 的引擎。以下是一些与 JavaScript 功能对应的例子：

1. **影子对象:**  JavaScript 中可以使用 `Object.defineProperty()` 的 getter 和 setter 来实现类似的效果，但 V8 的命名属性拦截器提供了更底层的控制。

   ```javascript
   let obj = {};
   let shadowValue = 12;
   Object.defineProperty(obj, 'x', {
     get: function() {
       console.log('Getting x');
       return shadowValue;
     },
     set: function(newValue) {
       console.log('Setting x to', newValue);
       // 不实际设置
     },
     enumerable: true,
     configurable: true
   });

   console.log(obj.x); // 输出: Getting x, 12
   obj.x = 15;       // 输出: Setting x to 15
   console.log(obj.x); // 输出: Getting x, 12
   ```

2. **原型链操作:** 这是 JavaScript 中继承的核心概念。

   ```javascript
   function Parent(name) {
     this.name = name;
   }
   Parent.prototype.sayHello = function() {
     console.log('Hello, my name is ' + this.name);
   };

   function Child(name, age) {
     Parent.call(this, name);
     this.age = age;
   }
   Child.prototype = Object.create(Parent.prototype); // 设置原型
   Child.prototype.constructor = Child; // 修正 constructor 指向

   let child = new Child('Alice', 10);
   child.sayHello(); // 输出: Hello, my name is Alice
   ```

3. **只读原型:**  防止修改函数的 `prototype`。

   ```javascript
   function MyClass() {}
   Object.defineProperty(MyClass, 'prototype', { writable: false });

   // 尝试修改会失败（在严格模式下会抛出 TypeError）
   MyClass.prototype = {};
   ```

4. **`eval` 函数:** JavaScript 的 `eval()` 函数允许将字符串作为代码执行。

   ```javascript
   let x = 10;
   let code = 'x = 20; console.log(x);';
   eval(code); // 输出: 20
   console.log(x); // 输出: 20
   ```

5. **将对象作为函数调用:**  JavaScript 中函数对象是可调用的。可以通过 `Function.prototype.call` 或 `Function.prototype.apply` 来改变 `this` 上下文。V8 的 `SetCallAsFunctionHandler` 允许非函数对象也具有这种行为。

   ```javascript
   let obj = {
     value: 42,
     callMe: function() {
       console.log('Called with value:', this.value);
     }
   };

   obj.callMe(); // 输出: Called with value: 42
   obj.callMe.call({ value: 99 }); // 输出: Called with value: 99
   ```

### 代码逻辑推理、假设输入与输出

**示例：`ShadowObject` 测试中的一部分**

**假设输入:**

*   在 JavaScript 中执行 `var x = 11;` 和 `function f() { return 42; }`。
*   全局对象的 `__proto__` 被设置为一个通过 `NamedPropertyHandlerConfiguration` 配置了影子对象的实例。该影子对象对属性 `x` 的 getter 返回 `12`。

**代码逻辑推理:**

当执行 `CompileRun("x")` 时，V8 会首先在当前全局对象上查找属性 `x`，找到值为 `11`。由于原型链上有影子对象，V8 可能会继续在原型链上查找。但是，由于没有明确说明原型链上的查找行为，我们可以假设影子对象的 getter 会被调用。

**预期输出:**

*   `shadow_x_getter_call_count` 的值会增加。
*   `value->Int32Value(context.local()).FromJust()` 的结果是 `12`，因为影子对象的 getter 返回了这个值。

**实际输出（根据代码）:**

*   `CHECK_EQ(0, shadow_x_getter_call_count);`  // 初始化为 0
*   `Local<Value> value = CompileRun("x");`
*   `CHECK_EQ(1, shadow_x_getter_call_count);`  // Getter 被调用一次
*   `CHECK_EQ(12, value->Int32Value(context.local()).FromJust());` // 返回影子对象的值

**示例：`SetPrototype` 测试**

**假设输入:**

*   创建了四个对象 `o0`, `o1`, `o2`, `o3`，它们分别具有属性 `x`, `y`, `z`, `u`。
*   通过 `SetPrototypeV2` 依次将 `o0` 的原型设置为 `o1`，`o1` 的原型设置为 `o2`，`o2` 的原型设置为 `o3`。

**代码逻辑推理:**

当访问 `o0` 的属性时，如果 `o0` 本身没有该属性，V8 会沿着原型链向上查找。

**预期输出:**

*   `o0->Get(context.local(), v8_str("x"))` 应该返回 `0` (来自 `o0`)。
*   `o0->Get(context.local(), v8_str("y"))` 应该返回 `1` (来自 `o1`)。
*   `o0->Get(context.local(), v8_str("z"))` 应该返回 `2` (来自 `o2`)。
*   `o0->Get(context.local(), v8_str("u"))` 应该返回 `3` (来自 `o3`)。

### 用户常见的编程错误

1. **原型链循环:** 尝试通过 `SetPrototypeV2` 创建一个循环的原型链会导致错误或未定义的行为。V8 会阻止这种情况，如 `SetPrototypeThrows` 测试所示。

    ```javascript
    const obj1 = {};
    const obj2 = {};
    Object.setPrototypeOf(obj1, obj2);
    Object.setPrototypeOf(obj2, obj1); // 报错: TypeError: Cyclic __proto__ value
    ```

2. **修改只读属性:** 尝试修改通过 `ReadOnlyPrototype` 设置为只读的 `prototype` 属性会失败或抛出 `TypeError`。

    ```javascript
    function
Prompt: 
```
这是目录为v8/test/cctest/test-api.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-api.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第13部分，共36部分，请归纳一下它的功能

"""
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
            ->Get(context.local(), v8_str("ReturnThisS
"""


```