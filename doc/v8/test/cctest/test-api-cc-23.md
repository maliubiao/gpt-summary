Response:
The user wants to understand the functionality of a V8 source code snippet located at `v8/test/cctest/test-api.cc`.

Here's a breakdown of how to approach this:

1. **Identify the core functionality:** Look for patterns in the code, especially V8 API calls and assertions (CHECK_EQ, CHECK). The code seems to be testing the `v8::MicrotasksScope`.

2. **Explain the `v8::MicrotasksScope`:**  This class controls the execution of microtasks. The code explores different modes: `kRunMicrotasks` and `kDoNotRunMicrotasks`.

3. **Analyze the test cases:**  Each block enclosed in curly braces `{}` seems to represent a test case. Pay attention to what happens inside each scope and the assertions made afterwards.

4. **Connect to JavaScript:** Microtasks are related to Promises and the `queueMicrotask` API in JavaScript. Provide examples of how these work.

5. **Identify potential user errors:** Misunderstanding when microtasks are executed is a common mistake. Show an example where the execution timing might be surprising.

6. **Address the ".tq" check:**  Clearly state that the file is `.cc` and not `.tq`, meaning it's C++ and not Torque.

7. **Summarize the functionality:** Provide a concise overview of what the code tests.

8. **Handle the "part 24 of 36" instruction:** Acknowledge this and state the summary in the context of being a part of a larger test suite.

**Mental Sandbox:**

* **If the file were `.tq`:** I'd be looking for Torque syntax and explaining its purpose in V8 (low-level builtins).
* **If the code directly manipulated JavaScript objects:** I'd demonstrate the equivalent JavaScript behavior.
* **If the code involved complex logic:** I'd try to trace the execution flow with example inputs and outputs.

**Constraint Checklist & Confidence Score:**

*列举一下它的功能: Yes
*如果v8/test/cctest/test-api.cc以.tq结尾，那它是个v8 torque源代码: Yes
*如果它与javascript的功能有关系，请用javascript举例说明: Yes
*如果有代码逻辑推理，请给出假设输入与输出: Yes (implicit in the test assertions)
*如果涉及用户常见的编程错误，请举例说明: Yes
*这是第24部分，共36部分，请归纳一下它的功能: Yes

Confidence Score: 5/5

**Strategizing complete. Proceeding with response generation.**

这段V8 C++源代码 (`v8/test/cctest/test-api.cc`) 的主要功能是**测试 V8 API 中关于微任务（Microtasks）的功能**，特别是 `v8::MicrotasksScope` 类的行为。

**功能列举：**

这段代码通过一系列的测试用例来验证 `v8::MicrotasksScope` 在不同配置下的工作方式，包括：

1. **控制微任务的执行时机：** 测试在 `v8::MicrotasksScope` 创建时指定 `kRunMicrotasks` 和 `kDoNotRunMicrotasks` 参数时，微任务是否会立即执行。
2. **嵌套的 `v8::MicrotasksScope`：**  验证嵌套的 scope 对微任务执行的影响。
3. **`v8::Isolate::SuppressMicrotaskExecutionScope`：** 测试该 scope 如何阻止微任务的执行。
4. **`v8::MicrotasksScope::PerformCheckpoint`：**  验证手动触发微任务执行的功能。
5. **微任务的入队和执行顺序：**  通过 `env->GetIsolate()->EnqueueMicrotask` 入队微任务，并观察它们的执行顺序和次数。
6. **与外部调用相关的微任务：** 代码中使用了 `ext1Calls` 和 `ext2Calls` 变量，暗示测试了与外部 C++ 函数调用相关的微任务执行。

**关于文件扩展名：**

你提供的代码片段是 C++ 代码，它的目录表明它位于 `v8/test/cctest/`，这是 V8 的 C++ 单元测试目录。因此，`v8/test/cctest/test-api.cc` **不是**以 `.tq` 结尾，它是一个 **C++** 源文件，而不是 Torque 源文件。

**与 JavaScript 的关系及示例：**

微任务在 JavaScript 中与 Promise 的 `then`、`catch`、`finally` 回调以及 `queueMicrotask` API 密切相关。它们用于异步操作完成后的清理工作，会在 JavaScript 执行栈清空后，但在事件循环的下一次迭代开始前执行。

**JavaScript 示例：**

```javascript
console.log('开始');

Promise.resolve().then(() => {
  console.log('Promise 回调');
});

queueMicrotask(() => {
  console.log('queueMicrotask 回调');
});

console.log('结束');

// 输出顺序通常是：
// 开始
// 结束
// queueMicrotask 回调
// Promise 回调
```

在 V8 内部，`v8::MicrotasksScope` 提供了 C++ 接口来控制这些 JavaScript 微任务的执行。例如，当创建一个 `v8::MicrotasksScope` 并指定 `kRunMicrotasks` 时，就相当于告诉 V8 执行当前作用域内添加到微任务队列中的所有任务，这类似于 JavaScript 引擎在执行完同步代码后处理微任务队列。

**代码逻辑推理、假设输入与输出：**

代码中的逻辑主要是通过 `CompileRun` 执行 JavaScript 代码，并检查全局变量 `ext1Calls` 和 `ext2Calls` 的值。这些变量很可能在 `MicrotaskOne` 和 `MicrotaskTwo` 函数中被递增。

**假设：**

* `MicrotaskOne` 函数会使 `ext1Calls` 递增。
* `MicrotaskTwo` 函数会使 `ext2Calls` 递增。

**推理与示例：**

在第一个主要的测试块中：

```c++
  {
    v8::MicrotasksScope scope(env.local(),
                              v8::MicrotasksScope::kRunMicrotasks);
    CompileRun("ls = 0;");
    CompileRun("1+1;");
    CHECK_EQ(0, CompileRun("ext1Calls")->Int32Value(env.local()).FromJust());
    CHECK_EQ(0, CompileRun("ext2Calls")->Int32Value(env.local()).FromJust());
    // ... 嵌套的 scope ...
  }
  CHECK_EQ(1, CompileRun("ext1Calls")->Int32Value(env.local()).FromJust());
  CHECK_EQ(0, CompileRun("ext2Calls")->Int32Value(env.local()).FromJust());
  env->GetIsolate()->EnqueueMicrotask(
      Function::New(env.local(), MicrotaskTwo).ToLocalChecked());
```

* 在最外层的 `kRunMicrotasks` scope 创建时，虽然指定了运行微任务，但此时并没有微任务入队，所以 `ext1Calls` 和 `ext2Calls` 仍然是 0。
* 嵌套的 `kRunMicrotasks` scope 也类似，因为没有入队微任务。
* 当最外层的 scope 结束时，由于之前调用了 `MicrotaskOne`（虽然代码片段中没有直接显示调用，但从后续的检查可以推断），这个微任务会被执行，所以 `ext1Calls` 变为 1。`ext2Calls` 仍然是 0。
* 之后，通过 `EnqueueMicrotask` 将 `MicrotaskTwo` 入队。

**用户常见的编程错误：**

一个常见的错误是**不理解微任务的执行时机**，认为它们会立即执行，或者与宏任务（例如 `setTimeout`）的执行顺序混淆。

**示例：**

```javascript
console.log('开始');

Promise.resolve().then(() => {
  console.log('Promise 回调');
});

setTimeout(() => {
  console.log('setTimeout 回调');
}, 0);

console.log('结束');

// 错误地认为输出顺序会是：
// 开始
// Promise 回调
// setTimeout 回调
// 结束

// 正确的输出顺序是：
// 开始
// 结束
// Promise 回调
// setTimeout 回调
```

在这个例子中，`Promise` 的回调（微任务）会在同步代码执行完后立即执行，而 `setTimeout` 的回调（宏任务）会被添加到下一个事件循环迭代中执行。

**第24部分，共36部分的功能归纳：**

作为 `v8/test/cctest/test-api.cc` 的一部分，这段代码专注于 **测试 V8 API 中 `v8::MicrotasksScope` 类的功能和行为**。它通过创建不同配置的 scope，并结合微任务的入队和手动触发，来验证 V8 引擎在处理微任务时的正确性。 这部分测试旨在确保 V8 的微任务机制按照预期工作，这对于正确执行 JavaScript 中基于 Promise 和 `queueMicrotask` 的异步代码至关重要。

Prompt: 
```
这是目录为v8/test/cctest/test-api.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-api.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第24部分，共36部分，请归纳一下它的功能

"""
ls = 0;");
    CompileRun("1+1;");
    CHECK_EQ(0, CompileRun("ext1Calls")->Int32Value(env.local()).FromJust());
    CHECK_EQ(0, CompileRun("ext2Calls")->Int32Value(env.local()).FromJust());
    {
      v8::MicrotasksScope scope2(env.local(),
                                 v8::MicrotasksScope::kRunMicrotasks);
      CompileRun("1+1;");
      CHECK_EQ(0, CompileRun("ext1Calls")->Int32Value(env.local()).FromJust());
      CHECK_EQ(0, CompileRun("ext2Calls")->Int32Value(env.local()).FromJust());
      {
        v8::MicrotasksScope scope3(env.local(),
                                   v8::MicrotasksScope::kRunMicrotasks);
        CompileRun("1+1;");
        CHECK_EQ(0,
                 CompileRun("ext1Calls")->Int32Value(env.local()).FromJust());
        CHECK_EQ(0,
                 CompileRun("ext2Calls")->Int32Value(env.local()).FromJust());
      }
      CHECK_EQ(0, CompileRun("ext1Calls")->Int32Value(env.local()).FromJust());
      CHECK_EQ(0, CompileRun("ext2Calls")->Int32Value(env.local()).FromJust());
    }
    CHECK_EQ(1, CompileRun("ext1Calls")->Int32Value(env.local()).FromJust());
    CHECK_EQ(0, CompileRun("ext2Calls")->Int32Value(env.local()).FromJust());
    env->GetIsolate()->EnqueueMicrotask(
        Function::New(env.local(), MicrotaskTwo).ToLocalChecked());
  }

  {
    v8::MicrotasksScope scope(env.local(),
                              v8::MicrotasksScope::kDoNotRunMicrotasks);
    CHECK_EQ(1, CompileRun("ext1Calls")->Int32Value(env.local()).FromJust());
    CHECK_EQ(0, CompileRun("ext2Calls")->Int32Value(env.local()).FromJust());
  }

  {
    v8::MicrotasksScope scope1(env.local(),
                               v8::MicrotasksScope::kRunMicrotasks);
    CompileRun("1+1;");
    CHECK_EQ(1, CompileRun("ext1Calls")->Int32Value(env.local()).FromJust());
    CHECK_EQ(0, CompileRun("ext2Calls")->Int32Value(env.local()).FromJust());
    {
      v8::MicrotasksScope scope2(env.local(),
                                 v8::MicrotasksScope::kDoNotRunMicrotasks);
    }
    CHECK_EQ(1, CompileRun("ext1Calls")->Int32Value(env.local()).FromJust());
    CHECK_EQ(0, CompileRun("ext2Calls")->Int32Value(env.local()).FromJust());
  }

  {
    v8::MicrotasksScope scope(env.local(),
                              v8::MicrotasksScope::kDoNotRunMicrotasks);
    CHECK_EQ(1, CompileRun("ext1Calls")->Int32Value(env.local()).FromJust());
    CHECK_EQ(1, CompileRun("ext2Calls")->Int32Value(env.local()).FromJust());
    env->GetIsolate()->EnqueueMicrotask(
        Function::New(env.local(), MicrotaskTwo).ToLocalChecked());
  }

  {
    v8::Isolate::SuppressMicrotaskExecutionScope scope1(env->GetIsolate());
    {
      v8::MicrotasksScope scope2(env.local(),
                                 v8::MicrotasksScope::kRunMicrotasks);
    }
    v8::MicrotasksScope scope3(env.local(),
                               v8::MicrotasksScope::kDoNotRunMicrotasks);
    CHECK_EQ(1, CompileRun("ext1Calls")->Int32Value(env.local()).FromJust());
    CHECK_EQ(1, CompileRun("ext2Calls")->Int32Value(env.local()).FromJust());
  }

  {
    v8::MicrotasksScope scope1(env.local(),
                               v8::MicrotasksScope::kRunMicrotasks);
    v8::MicrotasksScope::PerformCheckpoint(env->GetIsolate());
    CHECK_EQ(1, CompileRun("ext1Calls")->Int32Value(env.local()).FromJust());
    CHECK_EQ(1, CompileRun("ext2Calls")->Int32Value(env.local()).FromJust());
  }

  {
    v8::MicrotasksScope scope(env.local(),
                              v8::MicrotasksScope::kDoNotRunMicrotasks);
    CHECK_EQ(1, CompileRun("ext1Calls")->Int32Value(env.local()).FromJust());
    CHECK_EQ(2, CompileRun("ext2Calls")->Int32Value(env.local()).FromJust());
  }

  v8::MicrotasksScope::PerformCheckpoint(env->GetIsolate());

  {
    v8::MicrotasksScope scope(env.local(),
                              v8::MicrotasksScope::kDoNotRunMicrotasks);
    CHECK_EQ(1, CompileRun("ext1Calls")->Int32Value(env.local()).FromJust());
    CHECK_EQ(2, CompileRun("ext2Calls")->Int32Value(env.local()).FromJust());
    env->GetIsolate()->EnqueueMicrotask(
        Function::New(env.local(), MicrotaskTwo).ToLocalChecked());
  }

  v8::MicrotasksScope::PerformCheckpoint(env->GetIsolate());

  {
    v8::MicrotasksScope scope(env.local(),
                              v8::MicrotasksScope::kDoNotRunMicrotasks);
    CHECK_EQ(1, CompileRun("ext1Calls")->Int32Value(env.local()).FromJust());
    CHECK_EQ(3, CompileRun("ext2Calls")->Int32Value(env.local()).FromJust());
  }

  env->GetIsolate()->EnqueueMicrotask(
      Function::New(env.local(), MicrotaskOne).ToLocalChecked());
  {
    v8::Isolate::SuppressMicrotaskExecutionScope scope1(env->GetIsolate());
    v8::MicrotasksScope::PerformCheckpoint(env->GetIsolate());
    v8::MicrotasksScope scope2(env.local(),
                               v8::MicrotasksScope::kDoNotRunMicrotasks);
    CHECK_EQ(1, CompileRun("ext1Calls")->Int32Value(env.local()).FromJust());
    CHECK_EQ(3, CompileRun("ext2Calls")->Int32Value(env.local()).FromJust());
  }

  v8::MicrotasksScope::PerformCheckpoint(env->GetIsolate());

  {
    v8::MicrotasksScope scope(env.local(),
                              v8::MicrotasksScope::kDoNotRunMicrotasks);
    CHECK_EQ(2, CompileRun("ext1Calls")->Int32Value(env.local()).FromJust());
    CHECK_EQ(3, CompileRun("ext2Calls")->Int32Value(env.local()).FromJust());
  }

  env->GetIsolate()->SetMicrotasksPolicy(v8::MicrotasksPolicy::kAuto);
}

namespace {

void AssertCowElements(bool expected, const char* source) {
  Local<Value> object = CompileRun(source);
  i::DirectHandle<i::JSObject> array =
      i::Cast<i::JSObject>(v8::Utils::OpenDirectHandle(*object.As<Object>()));
  CHECK_EQ(expected, array->elements()->IsCowArray());
}

}  // namespace

TEST(CheckCOWArraysCreatedRuntimeCounter) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  AssertCowElements(true, "[1, 2, 3]");
  AssertCowElements(false, "[[1], 2, 3]");
  AssertCowElements(true, "[[1], 2, 3][0]");
  AssertCowElements(true, "({foo: [4, 5, 6], bar: [3, 0]}.foo)");
  AssertCowElements(true, "({foo: [4, 5, 6], bar: [3, 0]}.bar)");
  AssertCowElements(false, "({foo: [1, 2, 3, [4, 5, 6]], bar: 'hi'}.foo)");
  AssertCowElements(true, "({foo: [1, 2, 3, [4, 5, 6]], bar: 'hi'}.foo[3])");
}


TEST(StaticGetters) {
  LocalContext context;
  i::Factory* factory = CcTest::i_isolate()->factory();
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  i::DirectHandle<i::Object> undefined_value = factory->undefined_value();
  CHECK(*v8::Utils::OpenDirectHandle(*v8::Undefined(isolate)) ==
        *undefined_value);
  i::DirectHandle<i::Object> null_value = factory->null_value();
  CHECK(*v8::Utils::OpenDirectHandle(*v8::Null(isolate)) == *null_value);
  i::DirectHandle<i::Object> true_value = factory->true_value();
  CHECK(*v8::Utils::OpenDirectHandle(*v8::True(isolate)) == *true_value);
  i::DirectHandle<i::Object> false_value = factory->false_value();
  CHECK(*v8::Utils::OpenDirectHandle(*v8::False(isolate)) == *false_value);
}

UNINITIALIZED_TEST(IsolateEmbedderData) {
  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  isolate->Enter();
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  for (uint32_t slot = 0; slot < v8::Isolate::GetNumberOfDataSlots(); ++slot) {
    CHECK(!isolate->GetData(slot));
    CHECK(!i_isolate->GetData(slot));
  }
  for (uint32_t slot = 0; slot < v8::Isolate::GetNumberOfDataSlots(); ++slot) {
    void* data = reinterpret_cast<void*>(0xACCE55ED + slot);
    isolate->SetData(slot, data);
  }
  for (uint32_t slot = 0; slot < v8::Isolate::GetNumberOfDataSlots(); ++slot) {
    void* data = reinterpret_cast<void*>(0xACCE55ED + slot);
    CHECK_EQ(data, isolate->GetData(slot));
    CHECK_EQ(data, i_isolate->GetData(slot));
  }
  for (uint32_t slot = 0; slot < v8::Isolate::GetNumberOfDataSlots(); ++slot) {
    void* data = reinterpret_cast<void*>(0xDECEA5ED + slot);
    isolate->SetData(slot, data);
  }
  for (uint32_t slot = 0; slot < v8::Isolate::GetNumberOfDataSlots(); ++slot) {
    void* data = reinterpret_cast<void*>(0xDECEA5ED + slot);
    CHECK_EQ(data, isolate->GetData(slot));
    CHECK_EQ(data, i_isolate->GetData(slot));
  }
  isolate->Exit();
  isolate->Dispose();
}

TEST(StringEmpty) {
  LocalContext context;
  i::Factory* factory = CcTest::i_isolate()->factory();
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  i::DirectHandle<i::Object> empty_string = factory->empty_string();
  CHECK_EQ(*v8::Utils::OpenDirectHandle(*v8::String::Empty(isolate)),
           *empty_string);
}

THREADED_TEST(CheckIsLeafTemplateForApiObject) {
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());

  Local<FunctionTemplate> templ = FunctionTemplate::New(context->GetIsolate());
  CHECK(context->Global()
            ->Set(context.local(), v8_str("f"),
                  templ->GetFunction(context.local()).ToLocalChecked())
            .FromJust());

  printf("Testing positive ...\n");
  CompileRun("var obj = new f();");
  CHECK(templ->IsLeafTemplateForApiObject(
      context->Global()->Get(context.local(), v8_str("obj")).ToLocalChecked()));

  printf("Testing negative ...\n");
  CompileRun(
      "var obj = {};"
      "obj.__proto__ = new f();");
  CHECK(!templ->IsLeafTemplateForApiObject(
      context->Global()->Get(context.local(), v8_str("obj")).ToLocalChecked()));

  printf("Testing positive with modified prototype chain ...\n");
  CompileRun(
      "var obj = new f();"
      "var pro = {};"
      "pro.__proto__ = obj.__proto__;"
      "obj.__proto__ = pro;");
  CHECK(templ->IsLeafTemplateForApiObject(
      context->Global()->Get(context.local(), v8_str("obj")).ToLocalChecked()));

  Local<FunctionTemplate> child_templ =
      FunctionTemplate::New(context->GetIsolate());
  child_templ->Inherit(templ);
  Local<Object> instance = child_templ->GetFunction(context.local())
                               .ToLocalChecked()
                               ->NewInstance(context.local())
                               .ToLocalChecked();

  printf("Testing positive for child ...\n");
  CHECK(child_templ->IsLeafTemplateForApiObject(instance));
  printf("Testing negative for parent ...\n");
  CHECK(!templ->IsLeafTemplateForApiObject(instance));
}

static void Helper137002(bool do_store,
                         bool polymorphic,
                         bool remove_accessor,
                         bool interceptor) {
  LocalContext context;
  Local<ObjectTemplate> templ = ObjectTemplate::New(context->GetIsolate());
  if (interceptor) {
    templ->SetHandler(v8::NamedPropertyHandlerConfiguration(FooGetInterceptor,
                                                            FooSetInterceptor));
  } else {
    templ->SetNativeDataProperty(v8_str("foo"), GetterWhichReturns42,
                                 SetterWhichSetsYOnThisTo23);
  }
  CHECK(context->Global()
            ->Set(context.local(), v8_str("obj"),
                  templ->NewInstance(context.local()).ToLocalChecked())
            .FromJust());

  // Turn monomorphic on slow object with native accessor, then turn
  // polymorphic, finally optimize to create negative lookup and fail.
  CompileRun(do_store ?
             "function f(x) { x.foo = void 0; }" :
             "function f(x) { return x.foo; }");
  CompileRun("%PrepareFunctionForOptimization(f);");
  CompileRun("obj.y = void 0;");
  if (!interceptor) {
    CompileRun("%OptimizeObjectForAddingMultipleProperties(obj, 1);");
  }
  CompileRun("obj.__proto__ = null;"
             "f(obj); f(obj); f(obj);");
  if (polymorphic) {
    CompileRun("f({});");
  }
  CompileRun("obj.y = void 0;"
             "%OptimizeFunctionOnNextCall(f);");
  if (remove_accessor) {
    CompileRun("delete obj.foo;");
  }
  CompileRun("var result = f(obj);");
  if (do_store) {
    CompileRun("result = obj.y;");
  }
  if (remove_accessor && !interceptor) {
    CHECK(context->Global()
              ->Get(context.local(), v8_str("result"))
              .ToLocalChecked()
              ->IsUndefined());
  } else {
    CHECK_EQ(do_store ? 23 : 42, context->Global()
                                     ->Get(context.local(), v8_str("result"))
                                     .ToLocalChecked()
                                     ->Int32Value(context.local())
                                     .FromJust());
  }
}


THREADED_TEST(Regress137002a) {
  i::v8_flags.allow_natives_syntax = true;
  i::v8_flags.compilation_cache = false;
  v8::HandleScope scope(CcTest::isolate());
  for (int i = 0; i < 16; i++) {
    Helper137002(i & 8, i & 4, i & 2, i & 1);
  }
}


THREADED_TEST(Regress137002b) {
  i::v8_flags.allow_natives_syntax = true;
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->SetNativeDataProperty(v8_str("foo"), GetterWhichReturns42,
                               SetterWhichSetsYOnThisTo23);
  CHECK(context->Global()
            ->Set(context.local(), v8_str("obj"),
                  templ->NewInstance(context.local()).ToLocalChecked())
            .FromJust());

  // Turn monomorphic on slow object with native accessor, then just
  // delete the property and fail.
  CompileRun("function load(x) { return x.foo; }"
             "function store(x) { x.foo = void 0; }"
             "function keyed_load(x, key) { return x[key]; }"
             // Second version of function has a different source (add void 0)
             // so that it does not share code with the first version.  This
             // ensures that the ICs are monomorphic.
             "function load2(x) { void 0; return x.foo; }"
             "function store2(x) { void 0; x.foo = void 0; }"
             "function keyed_load2(x, key) { void 0; return x[key]; }"

             "obj.y = void 0;"
             "obj.__proto__ = null;"
             "var subobj = {};"
             "subobj.y = void 0;"
             "subobj.__proto__ = obj;"
             "%OptimizeObjectForAddingMultipleProperties(obj, 1);"

             // Make the ICs monomorphic.
             "load(obj); load(obj);"
             "load2(subobj); load2(subobj);"
             "store(obj); store(obj);"
             "store2(subobj); store2(subobj);"
             "keyed_load(obj, 'foo'); keyed_load(obj, 'foo');"
             "keyed_load2(subobj, 'foo'); keyed_load2(subobj, 'foo');"

             // Actually test the shiny new ICs and better not crash. This
             // serves as a regression test for issue 142088 as well.
             "load(obj);"
             "load2(subobj);"
             "store(obj);"
             "store2(subobj);"
             "keyed_load(obj, 'foo');"
             "keyed_load2(subobj, 'foo');"

             // Delete the accessor.  It better not be called any more now.
             "delete obj.foo;"
             "obj.y = void 0;"
             "subobj.y = void 0;"

             "var load_result = load(obj);"
             "var load_result2 = load2(subobj);"
             "var keyed_load_result = keyed_load(obj, 'foo');"
             "var keyed_load_result2 = keyed_load2(subobj, 'foo');"
             "store(obj);"
             "store2(subobj);"
             "var y_from_obj = obj.y;"
             "var y_from_subobj = subobj.y;");
  CHECK(context->Global()
            ->Get(context.local(), v8_str("load_result"))
            .ToLocalChecked()
            ->IsUndefined());
  CHECK(context->Global()
            ->Get(context.local(), v8_str("load_result2"))
            .ToLocalChecked()
            ->IsUndefined());
  CHECK(context->Global()
            ->Get(context.local(), v8_str("keyed_load_result"))
            .ToLocalChecked()
            ->IsUndefined());
  CHECK(context->Global()
            ->Get(context.local(), v8_str("keyed_load_result2"))
            .ToLocalChecked()
            ->IsUndefined());
  CHECK(context->Global()
            ->Get(context.local(), v8_str("y_from_obj"))
            .ToLocalChecked()
            ->IsUndefined());
  CHECK(context->Global()
            ->Get(context.local(), v8_str("y_from_subobj"))
            .ToLocalChecked()
            ->IsUndefined());
}


THREADED_TEST(Regress142088) {
  i::v8_flags.allow_natives_syntax = true;
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->SetNativeDataProperty(v8_str("foo"), GetterWhichReturns42,
                               SetterWhichSetsYOnThisTo23);
  CHECK(context->Global()
            ->Set(context.local(), v8_str("obj"),
                  templ->NewInstance(context.local()).ToLocalChecked())
            .FromJust());

  CompileRun("function load(x) { return x.foo; }"
             "var o = Object.create(obj);"
             "%OptimizeObjectForAddingMultipleProperties(obj, 1);"
             "load(o); load(o); load(o); load(o);");
}


THREADED_TEST(Regress137496) {
  i::v8_flags.expose_gc = true;
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());

  // Compile a try-finally clause where the finally block causes a GC
  // while there still is a message pending for external reporting.
  TryCatch try_catch(context->GetIsolate());
  try_catch.SetVerbose(true);
  CompileRun("try { throw new Error(); } finally { gc(); }");
  CHECK(try_catch.HasCaught());
}


THREADED_TEST(Regress157124) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
  Local<Object> obj = templ->NewInstance(context.local()).ToLocalChecked();
  obj->GetIdentityHash();
  obj->DeletePrivate(context.local(),
                     v8::Private::ForApi(isolate, v8_str("Bug")))
      .FromJust();
}


THREADED_TEST(Regress2535) {
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());
  Local<Value> set_value = CompileRun("new Set();");
  Local<Object> set_object(Local<Object>::Cast(set_value));
  CHECK_EQ(0, set_object->InternalFieldCount());
  Local<Value> map_value = CompileRun("new Map();");
  Local<Object> map_object(Local<Object>::Cast(map_value));
  CHECK_EQ(0, map_object->InternalFieldCount());
}


THREADED_TEST(Regress2746) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  Local<Object> obj = Object::New(isolate);
  Local<v8::Private> key = v8::Private::New(isolate, v8_str("key"));
  CHECK(
      obj->SetPrivate(context.local(), key, v8::Undefined(isolate)).FromJust());
  Local<Value> value = obj->GetPrivate(context.local(), key).ToLocalChecked();
  CHECK(!value.IsEmpty());
  CHECK(value->IsUndefined());
}


THREADED_TEST(Regress260106) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  Local<FunctionTemplate> templ = FunctionTemplate::New(isolate,
                                                        DummyCallHandler);
  CompileRun("for (var i = 0; i < 128; i++) Object.prototype[i] = 0;");
  Local<Function> function =
      templ->GetFunction(context.local()).ToLocalChecked();
  CHECK(!function.IsEmpty());
  CHECK(function->IsFunction());
}

THREADED_TEST(JSONParseObject) {
  LocalContext context;
  HandleScope scope(context->GetIsolate());
  Local<Value> obj =
      v8::JSON::Parse(context.local(), v8_str("{\"x\":42}")).ToLocalChecked();
  Local<Object> global = context->Global();
  global->Set(context.local(), v8_str("obj"), obj).FromJust();
  ExpectString("JSON.stringify(obj)", "{\"x\":42}");
}

THREADED_TEST(JSONParseNumber) {
  LocalContext context;
  HandleScope scope(context->GetIsolate());
  Local<Value> obj =
      v8::JSON::Parse(context.local(), v8_str("42")).ToLocalChecked();
  Local<Object> global = context->Global();
  global->Set(context.local(), v8_str("obj"), obj).FromJust();
  ExpectString("JSON.stringify(obj)", "42");
}

namespace {
void TestJSONParseArray(Local<Context> context, const char* input_str,
                        const char* expected_output_str,
                        i::ElementsKind expected_elements_kind) {
  Local<Value> obj =
      v8::JSON::Parse(context, v8_str(input_str)).ToLocalChecked();

  i::DirectHandle<i::JSArray> a =
      i::Cast<i::JSArray>(v8::Utils::OpenDirectHandle(*obj));
  CHECK_EQ(expected_elements_kind, a->GetElementsKind());

  Local<Object> global = context->Global();
  global->Set(context, v8_str("obj"), obj).FromJust();
  ExpectString("JSON.stringify(obj)", expected_output_str);
}
}  // namespace

THREADED_TEST(JSONParseArray) {
  LocalContext context;
  HandleScope scope(context->GetIsolate());

  TestJSONParseArray(context.local(), "[0, 1, 2]", "[0,1,2]",
                     i::PACKED_SMI_ELEMENTS);
  TestJSONParseArray(context.local(), "[0, 1.2, 2]", "[0,1.2,2]",
                     i::PACKED_DOUBLE_ELEMENTS);
  TestJSONParseArray(context.local(), "[0.2, 1, 2]", "[0.2,1,2]",
                     i::PACKED_DOUBLE_ELEMENTS);
  TestJSONParseArray(context.local(), "[0, \"a\", 2]", "[0,\"a\",2]",
                     i::PACKED_ELEMENTS);
  TestJSONParseArray(context.local(), "[\"a\", 1, 2]", "[\"a\",1,2]",
                     i::PACKED_ELEMENTS);
  TestJSONParseArray(context.local(), "[\"a\", 1.2, 2]", "[\"a\",1.2,2]",
                     i::PACKED_ELEMENTS);
  TestJSONParseArray(context.local(), "[0, 1.2, \"a\"]", "[0,1.2,\"a\"]",
                     i::PACKED_ELEMENTS);
}

THREADED_TEST(JSONStringifyObject) {
  LocalContext context;
  HandleScope scope(context->GetIsolate());
  Local<Value> value =
      v8::JSON::Parse(context.local(), v8_str("{\"x\":42}")).ToLocalChecked();
  Local<Object> obj = value->ToObject(context.local()).ToLocalChecked();
  Local<Object> global = context->Global();
  global->Set(context.local(), v8_str("obj"), obj).FromJust();
  Local<String> json =
      v8::JSON::Stringify(context.local(), obj).ToLocalChecked();
  v8::String::Utf8Value utf8(context->GetIsolate(), json);
  ExpectString("JSON.stringify(obj)", *utf8);
}

THREADED_TEST(JSONStringifyObjectWithGap) {
  LocalContext context;
  HandleScope scope(context->GetIsolate());
  Local<Value> value =
      v8::JSON::Parse(context.local(), v8_str("{\"x\":42}")).ToLocalChecked();
  Local<Object> obj = value->ToObject(context.local()).ToLocalChecked();
  Local<Object> global = context->Global();
  global->Set(context.local(), v8_str("obj"), obj).FromJust();
  Local<String> json =
      v8::JSON::Stringify(context.local(), obj, v8_str("*")).ToLocalChecked();
  v8::String::Utf8Value utf8(context->GetIsolate(), json);
  ExpectString("JSON.stringify(obj, null,  '*')", *utf8);
}

#if V8_OS_POSIX
class ThreadInterruptTest {
 public:
  ThreadInterruptTest() : sem_(0), sem_value_(0) { }
  ~ThreadInterruptTest() = default;

  void RunTest() {
    InterruptThread i_thread(this);
    CHECK(i_thread.Start());

    sem_.Wait();
    CHECK_EQ(kExpectedValue, sem_value_);
  }

 private:
  static const int kExpectedValue = 1;

  class InterruptThread : public v8::base::Thread {
   public:
    explicit InterruptThread(ThreadInterruptTest* test)
        : Thread(Options("InterruptThread")), test_(test) {}

    void Run() override {
      struct sigaction action;

      // Ensure that we'll enter waiting condition
      v8::base::OS::Sleep(v8::base::TimeDelta::FromMilliseconds(100));

      // Setup signal handler
      memset(&action, 0, sizeof(action));
      action.sa_handler = SignalHandler;
      sigaction(SIGCHLD, &action, nullptr);

      // Send signal
      kill(getpid(), SIGCHLD);

      // Ensure that if wait has returned because of error
      v8::base::OS::Sleep(v8::base::TimeDelta::FromMilliseconds(100));

      // Set value and signal semaphore
      test_->sem_value_ = 1;
      test_->sem_.Signal();
    }

    static void SignalHandler(int signal) {
    }

   private:
     ThreadInterruptTest* test_;
  };

  v8::base::Semaphore sem_;
  volatile int sem_value_;
};


THREADED_TEST(SemaphoreInterruption) {
  ThreadInterruptTest().RunTest();
}


#endif  // V8_OS_POSIX


void UnreachableCallback(const v8::FunctionCallbackInfo<v8::Value>& args) {
  UNREACHABLE();
}

TEST(JSONStringifyAccessCheck) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);

  // Create an ObjectTemplate for global objects and install access
  // check callbacks that will block access.
  v8::Local<v8::ObjectTemplate> global_template =
      v8::ObjectTemplate::New(isolate);
  global_template->SetAccessCheckCallback(AccessAlwaysBlocked);

  // Create a context and set an x property on it's global object.
  LocalContext context0(nullptr, global_template);
  v8::Local<v8::Object> global0 = context0->Global();
  global0->Set(context0.local(), v8_str("x"), v8_num(42)).FromJust();
  ExpectString("JSON.stringify(this)", "{\"x\":42}");

  for (int i = 0; i < 2; i++) {
    if (i == 1) {
      // Install a toJSON function on the second run.
      v8::Local<v8::FunctionTemplate> toJSON =
          v8::FunctionTemplate::New(isolate, UnreachableCallback);

      global0->Set(context0.local(), v8_str("toJSON"),
                   toJSON->GetFunction(context0.local()).ToLocalChecked())
          .FromJust();
    }
    // Create a context with a different security token so that the
    // failed access check callback will be called on each access.
    LocalContext context1(nullptr, global_template);
    CHECK(context1->Global()
              ->Set(context1.local(), v8_str("other"), global0)
              .FromJust());

    CHECK(CompileRun("JSON.stringify(other)").IsEmpty());
    CHECK(CompileRun("JSON.stringify({ 'a' : other, 'b' : ['c'] })").IsEmpty());
    CHECK(CompileRun("JSON.stringify([other, 'b', 'c'])").IsEmpty());
  }
}

bool access_check_fail_thrown = false;
bool catch_callback_called = false;


// Failed access check callback that performs a GC on each invocation.
void FailedAccessCheckThrows(Local<v8::Object> target,
                             v8::AccessType type,
                             Local<v8::Value> data) {
  access_check_fail_thrown = true;
  i::PrintF("Access check failed. Error thrown.\n");
  CcTest::isolate()->ThrowException(
      v8::Exception::Error(v8_str("cross context")));
}


void CatcherCallback(const v8::FunctionCallbackInfo<v8::Value>& args) {
  for (int i = 0; i < args.Length(); i++) {
    i::PrintF("%s\n", *String::Utf8Value(args.GetIsolate(), args[i]));
  }
  catch_callback_called = true;
}


void HasOwnPropertyCallback(const v8::FunctionCallbackInfo<v8::Value>& args) {
  v8::Local<v8::Context> context = args.GetIsolate()->GetCurrentContext();
  CHECK(
      args[0]
          ->ToObject(context)
          .ToLocalChecked()
          ->HasOwnProperty(context, args[1]->ToString(context).ToLocalChecked())
          .IsNothing());
}


void CheckCorrectThrow(const char* script) {
  // Test that the script, when wrapped into a try-catch, triggers the catch
  // clause due to failed access check throwing an exception.
  // The subsequent try-catch should run without any exception.
  access_check_fail_thrown = false;
  catch_callback_called = false;
  v8::base::ScopedVector<char> source(1024);
  v8::base::SNPrintF(source, "try { %s; } catch (e) { catcher(e); }", script);
  CompileRun(source.begin());
  CHECK(access_check_fail_thrown);
  CHECK(catch_callback_called);

  access_check_fail_thrown = false;
  catch_callback_called = false;
  CompileRun("try { [1, 2, 3].sort(); } catch (e) { catcher(e) };");
  CHECK(!access_check_fail_thrown);
  CHECK(!catch_callback_called);
}


TEST(AccessCheckThrows) {
  i::v8_flags.allow_natives_syntax = true;
  v8::Isolate* isolate = CcTest::isolate();
  isolate->SetFailedAccessCheckCallbackFunction(&FailedAccessCheckThrows);
  v8::HandleScope scope(isolate);

  // Create an ObjectTemplate for global objects and install access
  // check callbacks that will block access.
  v8::Local<v8::ObjectTemplate> global_template =
      v8::ObjectTemplate::New(isolate);
  global_template->SetAccessCheckCallback(AccessAlwaysBlocked);

  // Create a context and set an x property on it's global object.
  LocalContext context0(nullptr, global_template);
  v8::Local<v8::Object> global0 = context0->Global();
  CHECK(global0->Set(context0.local(), v8_str("x"), global0).FromJust());

  // Create a context with a different security token so that the
  // failed access check callback will be called on each access.
  LocalContext context1(nullptr, global_template);
  CHECK(context1->Global()
            ->Set(context1.local(), v8_str("other"), global0)
            .FromJust());

  v8::Local<v8::FunctionTemplate> catcher_fun =
      v8::FunctionTemplate::New(isolate, CatcherCallback);
  CHECK(context1->Global()
            ->Set(context1.local(), v8_str("catcher"),
                  catcher_fun->GetFunction(context1.local()).ToLocalChecked())
            .FromJust());

  v8::Local<v8::FunctionTemplate> has_own_property_fun =
      v8::FunctionTemplate::New(isolate, HasOwnPropertyCallback);
  CHECK(context1->Global()
            ->Set(context1.local(), v8_str("has_own_property"),
                  has_own_property_fun->GetFunction(context1.local())
                      .ToLocalChecked())
            .FromJust());

  {
    v8::TryCatch try_catch(isolate);
    access_check_fail_thrown = false;
    CompileRun("other.x;");
    CHECK(access_check_fail_thrown);
    CHECK(try_catch.HasCaught());
  }

  CheckCorrectThrow("other.x");
  CheckCorrectThrow("other[1]");
  CheckCorrectThrow("JSON.stringify(other)");
  CheckCorrectThrow("has_own_property(other, 'x')");
  CheckCorrectThrow("%GetProperty(other, 'x')");
  CheckCorrectThrow("%SetKeyedProperty(other, 'x', 'foo')");
  CheckCorrectThrow("%SetNamedProperty(other, 'y', 'foo')");
  static_assert(static_cast<int>(i::LanguageMode::kSloppy) == 0);
  static_assert(static_cast<int>(i::LanguageMode::kStrict) == 1);
  CheckCorrectThrow("%DeleteProperty(other, 'x', 0)");  // 0 == SLOPPY
  CheckCorrectThrow("%DeleteProperty(other, 'x', 1)");  // 1 == STRICT
  CheckCorrectThrow("%DeleteProperty(other, '1', 0)");
  CheckCorrectThrow("%DeleteProperty(other, '1', 1)");
  CheckCorrectThrow("Object.prototype.hasOwnProperty.call(other, 'x')");
  CheckCorrectThrow("%HasProperty(other, 'x')");
  CheckCorrectThrow("Object.prototype.propertyIsEnumerable(other, 'x')");
  // PROPERTY_ATTRIBUTES_NONE = 0
  CheckCorrectThrow("%DefineAccessorPropertyUnchecked("
                        "other, 'x', null, null, 1)");

  // Reset the failed access check callback so it does not influence
  // the other tests.
  isolate->SetFailedAccessCheckCallbackFunction(nullptr);
}

class RequestInterruptTestBase {
 public:
  RequestInterruptTestBase()
      : env_(),
        isolate_(env_->GetIsolate()),
        sem_(0),
        warmup_(20000),
        should_continue_(true) {
  }

  virtual ~RequestInterruptTestBase() = default;

  virtual void StartInterruptThread() = 0;

  virtual void TestBody() = 0;

  void RunTest() {
    StartInterruptThread();

    v8::HandleScope handle_scope(isolate_);

    TestBody();

    // Verify we arrived here because interruptor was called
    // not due to a bug causing us to exit the loop too early.
    CHECK(!should_continue());
  }

  void WakeUpInterruptor() {
    sem_.Signal();
  }

  bool should_continue() const { return should_continue_; }

  bool ShouldContinue() {
    if (warmup_ > 0) {
      if (--warmup_ == 0) {
        WakeUpInterruptor();
      }
    }

    return should_continue_;
  }

  static void ShouldContinueCallback(
      const v8::FunctionCallbackInfo<Value>& info) {
    RequestInterruptTestBase* test =
        reinterpret_cast<RequestInterruptTestBase*>(
            info.Data().As<v8::External>()->Value());
    info.GetReturnValue().Set(test->ShouldContinue());
  }

  LocalContext env_;
  v8::Isolate* isolate_;
  v8::base::Semaphore sem_;
  int warmup_;
  bool should_continue_;
};


class RequestInterruptTestBaseWithSimpleInterrupt
    : public RequestInterruptTestBase {
 public:
  RequestInterruptTestBaseWithSimpleInterrupt() : i_thread(this) { }

  void StartInterruptThread() override { CHECK(i_thread.Start()); }

 private:
  class InterruptThread : public v8::base::Thread {
   public:
    explicit InterruptThread(RequestInterruptTestBase* test)
        : Thread(Options("RequestInterruptTest")), test_(test) {}

    void Run() override {
      test_->sem_.Wait();
      test_->isolate_->RequestInterrupt(&OnInterrupt, test_);
    }

    static void OnInterrupt(v8::Isolate* isolate, void* data) {
      reinterpret_cast<RequestInterruptTestBase*>(data)->
          should_con
"""


```