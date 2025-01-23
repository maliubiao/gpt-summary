Response:
The user wants a summary of the provided C++ code snippet from `v8/test/cctest/test-api.cc`. The summary should include:

1. **Functionality:** What does the code do?
2. **Torque Source:** Is it a Torque file (ends with `.tq`)?
3. **JavaScript Relation:** Does it relate to JavaScript features? If so, provide a JavaScript example.
4. **Code Logic Inference:** Are there any logical deductions based on inputs and outputs?
5. **Common Programming Errors:** Does it illustrate any typical programming mistakes?
6. **Overall Summary:** A concise recap of its purpose.

Let's break down the code section by section:

*   **Proxy Revocation Test:** Tests the creation and revocation of `v8::Proxy` objects. This directly relates to the JavaScript Proxy object.
*   **WeakCallCounter and Memory Pressure Test:**  Demonstrates how memory pressure notifications trigger garbage collection and weak callbacks. This relates to JavaScript's garbage collection mechanisms and how V8 handles memory.
*   **SetIntegrityLevel Test:** Checks the functionality of `Object.freeze()` in JavaScript, which is mirrored by `SetIntegrityLevel`.
*   **PrivateForApiIsNumber Test:**  Likely a simple test to ensure `v8::Private::ForApi` doesn't crash with number-like strings. Not directly user-facing in JavaScript.
*   **ImmutableProto Tests:** Focuses on preventing modification of the `__proto__` property, which is a core concept in JavaScript's prototype inheritance.
*   **CrossActivationEval Test:** Explores the behavior of `eval` across different contexts. `eval` is a standard JavaScript function.
*   **EvalInAccessCheckedContext Test:**  Tests how access checks interact with `eval` within different security contexts. Related to JavaScript security and `eval`.
*   **InternalFieldsOnGlobalProxy Test:** Checks the ability to set internal fields on the global proxy object, which is less directly related to standard JavaScript but relevant for embedding V8.
*   **Global Immutable/Mutable Proto Tests:** Similar to the `ImmutableProto` tests, but specifically for the global object's prototype.
*   **SetPrototypeTemplate Test:** Demonstrates setting up prototype chains using templates, a more advanced API concept related to JavaScript inheritance.
*   **GlobalAccessorInfo Test:**  Checks that accessors on the global object are correctly invoked.
*   **DeterministicRandomNumberGeneration Test:**  Tests the predictability of `Math.random()` when a specific seed is set, important for testing JavaScript code.
*   **AllowAtomicsWait Test:** Verifies the control over the `Atomics.wait()` feature, a JavaScript concurrency feature.
*   **CorrectEnteredContext Test:**  Tests the correct tracking of the current and entered contexts, important for V8's internal management and less directly exposed in typical JavaScript.
*   **Dynamic Import Tests:** Covers the asynchronous module loading functionality (`import()`) in JavaScript, including handling host-defined options and import attributes.
*   **Import Meta Tests:** Focuses on the `import.meta` object available in JavaScript modules.
*   **CreateShadowRealmContext Tests:** Examines the experimental ShadowRealm API in JavaScript for creating isolated execution environments.
*   **GetModuleNamespace Test:** Checks the structure of the namespace object created for JavaScript modules.
*   **ModuleGetUnboundModuleScript Test:**  Likely tests accessing the underlying script of an uninstantiated module, a more internal V8 concept.

Based on this breakdown, the code snippet is heavily involved in testing various aspects of the V8 API, many of which directly correspond to JavaScript features.

**Plan:**

1. State that the code is from a C++ test file for the V8 API.
2. List the main functionalities tested, linking them to corresponding JavaScript concepts where applicable.
3. Confirm that it's not a Torque file.
4. Provide JavaScript examples for relevant features like Proxy, `Object.freeze`, prototype manipulation, `eval`, dynamic import, `import.meta`, and ShadowRealm.
5. For code logic inference, focus on the Proxy revocation and the memory pressure triggering GC. Create simple input/output scenarios.
6. For common programming errors, highlight issues related to incorrect prototype manipulation and `eval` usage.
7. Summarize the overall purpose as testing the V8 API's correctness in implementing JavaScript features.
这是一个V8源代码文件，路径为 `v8/test/cctest/test-api.cc`。根据文件名和路径可以推断，这是一个用于测试V8 C++ API功能的测试文件。

**功能列举:**

这个代码片段主要测试了V8 API中与以下功能相关的特性：

*   **Proxy 对象:** 测试了 `v8::Proxy` 对象的创建、属性访问以及撤销（revocation）功能。
*   **弱回调和内存压力:**  测试了在内存压力下，弱回调（weak callback）机制如何与垃圾回收器交互。
*   **对象完整性级别:**  测试了使用 `SetIntegrityLevel` 方法设置对象的完整性级别，例如冻结对象（freezing）。
*   **私有符号:**  测试了 `v8::Private::ForApi` 的使用，可能与处理私有符号或内部属性有关。
*   **不可变原型:**  测试了设置对象的原型为不可变 (`SetImmutableProto`) 后，尝试修改原型会抛出异常的行为。
*   **跨上下文 `eval`:**  测试了在不同 V8 上下文中使用 `eval` 的行为。
*   **访问检查上下文中的 `eval`:** 测试了在设置了访问检查回调的上下文中执行 `eval` 的情况。
*   **全局代理对象的内部字段:** 测试了全局代理对象是否可以设置内部字段。
*   **全局对象的不可变/可变原型:**  测试了设置全局对象的原型是否可以修改，以及如何设置为不可变。
*   **设置原型模板:**  测试了使用 `SetPrototypeProviderTemplate` 设置对象原型链的方式。
*   **全局访问器信息:**  测试了全局对象的访问器属性在被访问时的行为。
*   **确定性随机数生成:**  测试了当设置了随机种子时，`Math.random()` 生成的随机数是否具有确定性。
*   **允许 Atomics.wait:**  测试了控制是否允许使用 `Atomics.wait` 功能。
*   **正确的已进入上下文:** 测试了 V8 跟踪当前和已进入上下文的正确性。
*   **动态导入 (Dynamic Import):** 测试了 JavaScript 的动态导入 `import()` 功能，包括主机提供的选项和导入属性。
*   **Import Meta:** 测试了 JavaScript 模块中的 `import.meta` 对象。
*   **创建 ShadowRealm 上下文:** 测试了创建隔离的 JavaScript 执行环境 `ShadowRealm` 的功能。
*   **获取模块命名空间:** 测试了获取 JavaScript 模块的命名空间对象。
*   **获取未绑定模块脚本:** 测试了获取尚未实例化的模块的脚本。

**Torque 源代码:**

`v8/test/cctest/test-api.cc` 文件名以 `.cc` 结尾，因此它是一个 **C++** 源代码文件，而不是 Torque 源代码文件（Torque 文件以 `.tq` 结尾）。

**与 JavaScript 的功能关系及示例:**

是的，这个文件中的很多测试都直接关系到 JavaScript 的功能。以下是一些示例：

1. **Proxy 对象:**
    ```javascript
    const target = {};
    const handler = {
      get: function(obj, prop) {
        console.log(`访问了属性: ${prop}`);
        return obj[prop];
      }
    };
    const proxy = new Proxy(target, handler);
    proxy.name = "V8"; // 触发 handler.set (如果定义了)
    console.log(proxy.name); // 触发 handler.get
    ```

2. **对象完整性级别 (Object.freeze):**
    ```javascript
    const obj = { prop: 42 };
    Object.freeze(obj);
    obj.prop = 100; // 严格模式下会报错，非严格模式下修改失败
    console.log(obj.prop); // 输出 42
    console.log(Object.isFrozen(obj)); // 输出 true
    ```

3. **不可变原型:**
    ```javascript
    function MyClass() {}
    const instance = new MyClass();
    Object.setPrototypeOf(instance, null); // 可以修改原型

    function ImmutableClass() {}
    // 假设 V8 内部创建的具有不可变原型的对象
    const immutableInstance = new ImmutableClass();
    // 尝试修改 __proto__ 会抛出 TypeError
    // immutableInstance.__proto__ = null; // 会报错
    ```

4. **动态导入 (Dynamic Import):**
    ```javascript
    async function loadModule() {
      try {
        const module = await import('./my-module.js');
        console.log(module.default);
      } catch (error) {
        console.error("加载模块失败:", error);
      }
    }
    loadModule();
    ```

5. **Import Meta:**
    ```javascript
    // my-module.js
    console.log(import.meta.url);
    export default {};
    ```

6. **创建 ShadowRealm 上下文:**
    ```javascript
    // 这段代码需要在支持 ShadowRealm 的环境中运行
    if (globalThis.ShadowRealm) {
      const realm = new ShadowRealm();
      const result = realm.evaluate('1 + 2');
      console.log(result); // 输出 3，在隔离的环境中执行
    } else {
      console.log("ShadowRealm 不被支持");
    }
    ```

**代码逻辑推理 (假设输入与输出):**

**测试 Proxy 撤销:**

*   **假设输入:** 创建一个 target 对象 `{}` 和一个 handler 对象 `{}`, 并用它们创建一个 Proxy 对象。
*   **预期输出 (创建后):**
    *   `proxy->IsProxy()` 为 true
    *   `target->IsProxy()` 为 false
    *   `proxy->IsRevoked()` 为 false
    *   `proxy->GetTarget()->SameValue(target)` 为 true
    *   `proxy->GetHandler()->SameValue(handler)` 为 true
*   **假设输入:** 调用 `proxy->Revoke()` 撤销 Proxy。
*   **预期输出 (撤销后):**
    *   `proxy->IsProxy()` 为 true (Proxy 对象仍然存在)
    *   `target->IsProxy()` 为 false
    *   `proxy->IsRevoked()` 为 true
    *   `proxy->GetTarget()->IsNull()` 为 true
    *   `proxy->GetHandler()->IsNull()` 为 true

**测试内存压力触发弱回调:**

*   **假设输入:** 创建一个带有弱回调的对象 `garbage`。初始时，弱回调计数器为 0。
*   **预期输出:** `counter.NumberOfWeakCalls()` 为 0。
*   **假设输入:** 触发一个临界内存压力通知 (`v8::MemoryPressureLevel::kCritical`)。
*   **预期输出:**  垃圾回收器被触发，弱回调被调用。`counter.NumberOfWeakCalls()` 变为 1。

**用户常见的编程错误:**

1. **错误地修改冻结对象:** 尝试修改通过 `Object.freeze()` 冻结的对象，导致在严格模式下抛出 `TypeError`，在非严格模式下修改失败但不会报错，容易引起程序行为不符合预期。
    ```javascript
    "use strict";
    const obj = { prop: 42 };
    Object.freeze(obj);
    try {
      obj.prop = 100; // 抛出 TypeError
    } catch (e) {
      console.error(e);
    }
    ```

2. **不理解原型链导致意外的原型修改失败:**  假设一个对象的原型被设置为不可变，用户尝试修改其 `__proto__` 可能会失败，但没有明确的错误提示，导致调试困难。
    ```javascript
    function Parent() {}
    function Child() {}
    Child.prototype = new Parent();
    Object.setPrototypeOf(Child.prototype, null); // 如果 Parent 的原型被设置为不可变，这行可能失败
    ```

3. **滥用 `eval` 导致安全风险和性能问题:**  `eval` 可以执行任意字符串代码，如果字符串内容来自用户输入，则可能存在安全漏洞。此外，`eval` 通常比直接执行代码慢。
    ```javascript
    const userInput = "alert('Hello!');";
    // eval(userInput); // 潜在的安全风险
    ```

**功能归纳:**

这是 `v8/test/cctest/test-api.cc` 文件的一部分，它主要负责测试 V8 C++ API 的各种功能，特别是那些直接对应或支持 JavaScript 语言特性的 API。这些测试覆盖了对象生命周期管理（如弱回调和垃圾回收）、对象属性和原型操作、安全特性（如对象完整性级别和跨上下文 `eval`）、以及新的语言特性（如动态导入和 ShadowRealm）。通过这些测试，可以验证 V8 引擎在实现 JavaScript 规范时的正确性和稳定性。

**总结来说，这段代码的功能是测试 V8 引擎提供的 C++ API，以确保其能够正确地实现和支持各种 JavaScript 语言特性和底层机制。**

### 提示词
```
这是目录为v8/test/cctest/test-api.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-api.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第30部分，共36部分，请归纳一下它的功能
```

### 源代码
```cpp
te* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::Object> target = CompileRun("({})").As<v8::Object>();
  v8::Local<v8::Object> handler = CompileRun("({})").As<v8::Object>();

  v8::Local<v8::Proxy> proxy =
      v8::Proxy::New(context.local(), target, handler).ToLocalChecked();
  CHECK(proxy->IsProxy());
  CHECK(!target->IsProxy());
  CHECK(!proxy->IsRevoked());
  CHECK(proxy->GetTarget()->SameValue(target));
  CHECK(proxy->GetHandler()->SameValue(handler));

  proxy->Revoke();
  CHECK(proxy->IsProxy());
  CHECK(!target->IsProxy());
  CHECK(proxy->IsRevoked());
  CHECK(proxy->GetTarget()->IsNull());
  CHECK(proxy->GetHandler()->IsNull());
}

WeakCallCounterAndPersistent<Value>* CreateGarbageWithWeakCallCounter(
    v8::Isolate* isolate, WeakCallCounter* counter) {
  v8::Locker locker(isolate);
  LocalContext env;
  HandleScope scope(isolate);
  WeakCallCounterAndPersistent<Value>* val =
      new WeakCallCounterAndPersistent<Value>(counter);
  val->handle.Reset(isolate, Object::New(isolate));
  val->handle.SetWeak(val, &WeakPointerCallback,
                      v8::WeakCallbackType::kParameter);
  return val;
}

class MemoryPressureThread : public v8::base::Thread {
 public:
  explicit MemoryPressureThread(v8::Isolate* isolate,
                                v8::MemoryPressureLevel level)
      : Thread(Options("MemoryPressureThread")),
        isolate_(isolate),
        level_(level) {}

  void Run() override { isolate_->MemoryPressureNotification(level_); }

 private:
  v8::Isolate* isolate_;
  v8::MemoryPressureLevel level_;
};

TEST(MemoryPressure) {
  if (i::v8_flags.optimize_for_size) return;
  v8::Isolate* isolate = CcTest::isolate();
  WeakCallCounter counter(1234);

  // Conservative stack scanning might break results.
  i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
      CcTest::heap());

  // Check that critical memory pressure notification sets GC interrupt.
  auto garbage = CreateGarbageWithWeakCallCounter(isolate, &counter);
  CHECK(!v8::Locker::IsLocked(isolate));
  {
    v8::Locker locker(isolate);
    v8::HandleScope scope(isolate);
    LocalContext env;
    MemoryPressureThread memory_pressure_thread(
        isolate, v8::MemoryPressureLevel::kCritical);
    CHECK(memory_pressure_thread.Start());
    memory_pressure_thread.Join();
    // This should trigger GC.
    CHECK_EQ(0, counter.NumberOfWeakCalls());
    CompileRun("(function noop() { return 0; })()");
    CHECK_EQ(1, counter.NumberOfWeakCalls());
  }
  delete garbage;
  // Check that critical memory pressure notification triggers GC.
  garbage = CreateGarbageWithWeakCallCounter(isolate, &counter);
  {
    v8::Locker locker(isolate);
    // If isolate is locked, memory pressure notification should trigger GC.
    CHECK_EQ(1, counter.NumberOfWeakCalls());
    isolate->MemoryPressureNotification(v8::MemoryPressureLevel::kCritical);
    CHECK_EQ(2, counter.NumberOfWeakCalls());
  }
  delete garbage;
  // Check that moderate memory pressure notification sets GC into memory
  // optimizing mode.
  isolate->MemoryPressureNotification(v8::MemoryPressureLevel::kModerate);
  CHECK(CcTest::i_isolate()->heap()->ShouldOptimizeForMemoryUsage());
  // Check that disabling memory pressure returns GC into normal mode.
  isolate->MemoryPressureNotification(v8::MemoryPressureLevel::kNone);
  CHECK(!CcTest::i_isolate()->heap()->ShouldOptimizeForMemoryUsage());
}

TEST(SetIntegrityLevel) {
  LocalContext context;
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);

  v8::Local<v8::Object> obj = v8::Object::New(isolate);
  CHECK(context->Global()->Set(context.local(), v8_str("o"), obj).FromJust());

  v8::Local<v8::Value> is_frozen = CompileRun("Object.isFrozen(o)");
  CHECK(!is_frozen->BooleanValue(isolate));

  CHECK(obj->SetIntegrityLevel(context.local(), v8::IntegrityLevel::kFrozen)
            .FromJust());

  is_frozen = CompileRun("Object.isFrozen(o)");
  CHECK(is_frozen->BooleanValue(isolate));
}

TEST(PrivateForApiIsNumber) {
  LocalContext context;
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);

  // Shouldn't crash.
  v8::Private::ForApi(isolate, v8_str("42"));
}

THREADED_TEST(ImmutableProto) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope handle_scope(isolate);

  Local<v8::FunctionTemplate> templ = v8::FunctionTemplate::New(isolate);
  templ->InstanceTemplate()->SetImmutableProto();

  Local<v8::Object> object = templ->GetFunction(context.local())
                                 .ToLocalChecked()
                                 ->NewInstance(context.local())
                                 .ToLocalChecked();

  // Look up the prototype
  Local<v8::Value> original_proto =
      object->Get(context.local(), v8_str("__proto__")).ToLocalChecked();

  // Setting the prototype (e.g., to null) throws
  CHECK(object->SetPrototypeV2(context.local(), v8::Null(isolate)).IsNothing());

  // The original prototype is still there
  Local<Value> new_proto =
      object->Get(context.local(), v8_str("__proto__")).ToLocalChecked();
  CHECK(new_proto->IsObject());
  CHECK(new_proto.As<v8::Object>()
            ->Equals(context.local(), original_proto)
            .FromJust());
}

namespace {

v8::Global<v8::Context> call_eval_context_global;
v8::Global<v8::Function> call_eval_bound_function_global;

void CallEval(const v8::FunctionCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  v8::Isolate* isolate = info.GetIsolate();
  Local<v8::Context> call_eval_context = call_eval_context_global.Get(isolate);
  Local<v8::Function> call_eval_bound_function =
      call_eval_bound_function_global.Get(isolate);
  v8::Context::Scope scope(call_eval_context);
  info.GetReturnValue().Set(
      call_eval_bound_function
          ->Call(call_eval_context, call_eval_context->Global(), 0, nullptr)
          .ToLocalChecked());
}

}  // namespace

TEST(CrossActivationEval) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  {
    Local<v8::Context> call_eval_context = v8::Context::New(isolate);
    call_eval_context_global.Reset(isolate, call_eval_context);
    v8::Context::Scope context_scope(call_eval_context);
    v8::Local<v8::Function> call_eval_bound_function =
        Local<Function>::Cast(CompileRun("eval.bind(this, '1')"));
    call_eval_bound_function_global.Reset(isolate, call_eval_bound_function);
  }
  env->Global()
      ->Set(env.local(), v8_str("CallEval"),
            v8::FunctionTemplate::New(isolate, CallEval)
                ->GetFunction(env.local())
                .ToLocalChecked())
      .FromJust();
  Local<Value> result = CompileRun("CallEval();");
  CHECK(result->IsInt32());
  CHECK_EQ(1, result->Int32Value(env.local()).FromJust());
  call_eval_context_global.Reset();
  call_eval_bound_function_global.Reset();
}

TEST(EvalInAccessCheckedContext) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);

  v8::Local<v8::ObjectTemplate> obj_template = v8::ObjectTemplate::New(isolate);

  obj_template->SetAccessCheckCallback(AccessAlwaysAllowed);

  v8::Local<Context> context0 = Context::New(isolate, nullptr, obj_template);
  v8::Local<Context> context1 = Context::New(isolate, nullptr, obj_template);

  Local<Value> foo = v8_str("foo");
  Local<Value> bar = v8_str("bar");

  // Set to different domains.
  context0->SetSecurityToken(foo);
  context1->SetSecurityToken(bar);

  // Set up function in context0 that uses eval from context0.
  context0->Enter();
  v8::Local<v8::Value> fun = CompileRun(
      "var x = 42;"
      "(function() {"
      "  var e = eval;"
      "  return function(s) { return e(s); }"
      "})()");
  context0->Exit();

  // Put the function into context1 and call it. Since the access check
  // callback always returns true, the call succeeds even though the tokens
  // are different.
  context1->Enter();
  context1->Global()->Set(context1, v8_str("fun"), fun).FromJust();
  v8::Local<v8::Value> x_value = CompileRun("fun('x')");
  CHECK_EQ(42, x_value->Int32Value(context1).FromJust());
  context1->Exit();
}

THREADED_TEST(ImmutableProtoWithParent) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope handle_scope(isolate);

  Local<v8::FunctionTemplate> parent = v8::FunctionTemplate::New(isolate);

  Local<v8::FunctionTemplate> templ = v8::FunctionTemplate::New(isolate);
  templ->Inherit(parent);
  templ->PrototypeTemplate()->SetImmutableProto();

  Local<v8::Function> function =
      templ->GetFunction(context.local()).ToLocalChecked();
  Local<v8::Object> instance =
      function->NewInstance(context.local()).ToLocalChecked();
  Local<v8::Object> prototype =
      instance->Get(context.local(), v8_str("__proto__"))
          .ToLocalChecked()
          ->ToObject(context.local())
          .ToLocalChecked();

  // Look up the prototype
  Local<v8::Value> original_proto =
      prototype->Get(context.local(), v8_str("__proto__")).ToLocalChecked();

  // Setting the prototype (e.g., to null) throws
  CHECK(prototype->SetPrototypeV2(context.local(), v8::Null(isolate))
            .IsNothing());

  // The original prototype is still there
  Local<Value> new_proto =
      prototype->Get(context.local(), v8_str("__proto__")).ToLocalChecked();
  CHECK(new_proto->IsObject());
  CHECK(new_proto.As<v8::Object>()
            ->Equals(context.local(), original_proto)
            .FromJust());
}

TEST(InternalFieldsOnGlobalProxy) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);

  v8::Local<v8::ObjectTemplate> obj_template = v8::ObjectTemplate::New(isolate);
  obj_template->SetInternalFieldCount(1);

  v8::Local<v8::Context> context = Context::New(isolate, nullptr, obj_template);
  v8::Local<v8::Object> global = context->Global();
  CHECK_EQ(1, global->InternalFieldCount());
}

THREADED_TEST(ImmutableProtoGlobal) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope handle_scope(isolate);
  Local<ObjectTemplate> global_template = ObjectTemplate::New(isolate);
  global_template->SetImmutableProto();
  v8::Local<Context> context = Context::New(isolate, nullptr, global_template);
  Context::Scope context_scope(context);
  v8::Local<Value> result = CompileRun(
      "global = this;"
      "(function() {"
      "  try {"
      "    global.__proto__ = {};"
      "    return 0;"
      "  } catch (e) {"
      "    return 1;"
      "  }"
      "})()");
  CHECK(result->Equals(context, v8::Integer::New(CcTest::isolate(), 1))
            .FromJust());
}

THREADED_TEST(MutableProtoGlobal) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope handle_scope(isolate);
  Local<ObjectTemplate> global_template = ObjectTemplate::New(isolate);
  v8::Local<Context> context = Context::New(isolate, nullptr, global_template);
  Context::Scope context_scope(context);
  v8::Local<Value> result = CompileRun(
      "global = this;"
      "(function() {"
      "  try {"
      "    global.__proto__ = {};"
      "    return 0;"
      "  } catch (e) {"
      "    return 1;"
      "  }"
      "})()");
  CHECK(result->Equals(context, v8::Integer::New(CcTest::isolate(), 0))
            .FromJust());
}

TEST(SetPrototypeTemplate) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  Local<FunctionTemplate> HTMLElementTemplate = FunctionTemplate::New(isolate);
  Local<FunctionTemplate> HTMLImageElementTemplate =
      FunctionTemplate::New(isolate);
  HTMLImageElementTemplate->Inherit(HTMLElementTemplate);

  Local<FunctionTemplate> ImageTemplate = FunctionTemplate::New(isolate);
  ImageTemplate->SetPrototypeProviderTemplate(HTMLImageElementTemplate);

  Local<Function> HTMLImageElement =
      HTMLImageElementTemplate->GetFunction(env.local()).ToLocalChecked();
  Local<Function> Image =
      ImageTemplate->GetFunction(env.local()).ToLocalChecked();

  CHECK(env->Global()
            ->Set(env.local(), v8_str("HTMLImageElement"), HTMLImageElement)
            .FromJust());
  CHECK(env->Global()->Set(env.local(), v8_str("Image"), Image).FromJust());

  ExpectTrue("Image.prototype === HTMLImageElement.prototype");
}

void ensure_receiver_is_global_proxy(
    v8::Local<v8::Name>, const v8::PropertyCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  CHECK(IsJSGlobalProxy(*v8::Utils::OpenDirectHandle(*info.This())));
}

THREADED_TEST(GlobalAccessorInfo) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  Local<v8::ObjectTemplate> global_template = v8::ObjectTemplate::New(isolate);
  global_template->SetNativeDataProperty(
      v8::String::NewFromUtf8Literal(isolate, "prop",
                                     v8::NewStringType::kInternalized),
      &ensure_receiver_is_global_proxy);
  LocalContext env(nullptr, global_template);
  CompileRun("for (var i = 0; i < 10; i++) this.prop");
  CompileRun("for (var i = 0; i < 10; i++) prop");
}

TEST(DeterministicRandomNumberGeneration) {
  v8::HandleScope scope(CcTest::isolate());

  int previous_seed = i::v8_flags.random_seed;
  i::v8_flags.random_seed = 1234;

  double first_value;
  double second_value;
  {
    v8::Local<Context> context = Context::New(CcTest::isolate());
    Context::Scope context_scope(context);
    v8::Local<Value> result = CompileRun("Math.random();");
    first_value = result->ToNumber(context).ToLocalChecked()->Value();
  }
  {
    v8::Local<Context> context = Context::New(CcTest::isolate());
    Context::Scope context_scope(context);
    v8::Local<Value> result = CompileRun("Math.random();");
    second_value = result->ToNumber(context).ToLocalChecked()->Value();
  }
  CHECK_EQ(first_value, second_value);

  i::v8_flags.random_seed = previous_seed;
}

UNINITIALIZED_TEST(AllowAtomicsWait) {
  v8::Isolate::CreateParams create_params;
  create_params.allow_atomics_wait = false;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  {
    CHECK_EQ(false, i_isolate->allow_atomics_wait());
    isolate->SetAllowAtomicsWait(true);
    CHECK_EQ(true, i_isolate->allow_atomics_wait());
  }
  isolate->Dispose();
}

enum ContextId { EnteredContext, CurrentContext };

void CheckContexts(v8::Isolate* isolate) {
  CHECK_EQ(CurrentContext, isolate->GetCurrentContext()
                               ->GetEmbedderData(1)
                               .As<v8::Integer>()
                               ->Value());
  CHECK_EQ(EnteredContext, isolate->GetEnteredOrMicrotaskContext()
                               ->GetEmbedderData(1)
                               .As<v8::Integer>()
                               ->Value());
}

void ContextCheckGetter(Local<Name> name,
                        const v8::PropertyCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  CheckContexts(info.GetIsolate());
  info.GetReturnValue().Set(true);
}

void ContextCheckSetter(Local<Name> name, Local<Value>,
                        const v8::PropertyCallbackInfo<void>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  CheckContexts(info.GetIsolate());
}

void ContextCheckToString(const v8::FunctionCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  CheckContexts(info.GetIsolate());
  info.GetReturnValue().Set(v8_str("foo"));
}

TEST(CorrectEnteredContext) {
  v8::HandleScope scope(CcTest::isolate());

  LocalContext currentContext;
  currentContext->SetEmbedderData(
      1, v8::Integer::New(currentContext->GetIsolate(), CurrentContext));
  LocalContext enteredContext;
  enteredContext->SetEmbedderData(
      1, v8::Integer::New(enteredContext->GetIsolate(), EnteredContext));

  v8::Context::Scope contextScope(enteredContext.local());

  v8::Local<v8::ObjectTemplate> object_template =
      ObjectTemplate::New(currentContext->GetIsolate());
  object_template->SetNativeDataProperty(v8_str("p"), &ContextCheckGetter,
                                         &ContextCheckSetter);

  v8::Local<v8::Object> object =
      object_template->NewInstance(currentContext.local()).ToLocalChecked();

  object->Get(currentContext.local(), v8_str("p")).ToLocalChecked();
  object->Set(currentContext.local(), v8_str("p"), v8_int(0)).FromJust();

  v8::Local<v8::Function> to_string =
      v8::Function::New(currentContext.local(), ContextCheckToString)
          .ToLocalChecked();

  to_string->Call(currentContext.local(), object, 0, nullptr).ToLocalChecked();

  object
      ->CreateDataProperty(currentContext.local(), v8_str("toString"),
                           to_string)
      .FromJust();

  object->ToString(currentContext.local()).ToLocalChecked();
}

// For testing only, the host-defined options are provided entirely by the host
// and have an abritrary length. Use this constant here for testing that we get
// the correct value during the tests.
const int kCustomHostDefinedOptionsLengthForTesting = 7;

v8::MaybeLocal<v8::Promise> HostImportModuleDynamicallyCallbackResolve(
    Local<v8::Context> context, Local<v8::Data> host_defined_options,
    Local<v8::Value> resource_name, Local<v8::String> specifier,
    Local<v8::FixedArray> import_attributes) {
  String::Utf8Value referrer_utf8(context->GetIsolate(),
                                  resource_name.As<String>());
  CHECK_EQ(0, strcmp("www.google.com", *referrer_utf8));
  CHECK_EQ(host_defined_options.As<v8::FixedArray>()->Length(),
           kCustomHostDefinedOptionsLengthForTesting);
  CHECK(!specifier.IsEmpty());
  String::Utf8Value specifier_utf8(context->GetIsolate(), specifier);
  CHECK_EQ(0, strcmp("index.js", *specifier_utf8));

  CHECK_EQ(0, import_attributes->Length());

  Local<v8::Promise::Resolver> resolver =
      v8::Promise::Resolver::New(context).ToLocalChecked();
  auto result = v8_str("hello world");
  resolver->Resolve(context, result).ToChecked();
  return resolver->GetPromise();
}

TEST(DynamicImport) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  isolate->SetHostImportModuleDynamicallyCallback(
      HostImportModuleDynamicallyCallbackResolve);

  i::DirectHandle<i::String> url =
      v8::Utils::OpenDirectHandle(*v8_str("www.google.com"));
  i::Handle<i::Object> specifier(v8::Utils::OpenHandle(*v8_str("index.js")));
  i::DirectHandle<i::String> result =
      v8::Utils::OpenDirectHandle(*v8_str("hello world"));
  i::DirectHandle<i::String> source =
      v8::Utils::OpenDirectHandle(*v8_str("foo"));
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  i::Handle<i::Script> referrer = i_isolate->factory()->NewScript(source);
  referrer->set_name(*url);
  i::DirectHandle<i::FixedArray> options = i_isolate->factory()->NewFixedArray(
      kCustomHostDefinedOptionsLengthForTesting);
  referrer->set_host_defined_options(*options);
  i::MaybeHandle<i::JSPromise> maybe_promise =
      i_isolate->RunHostImportModuleDynamicallyCallback(
          referrer, specifier, v8::ModuleImportPhase::kEvaluation,
          i::MaybeHandle<i::Object>());
  i::DirectHandle<i::JSPromise> promise = maybe_promise.ToHandleChecked();
  isolate->PerformMicrotaskCheckpoint();
  CHECK(result->Equals(i::Cast<i::String>(promise->result())));
}

v8::MaybeLocal<v8::Promise>
HostImportModuleDynamicallyWithAttributesCallbackResolve(
    Local<v8::Context> context, Local<v8::Data> host_defined_options,
    Local<v8::Value> resource_name, Local<v8::String> specifier,
    Local<v8::FixedArray> import_attributes) {
  String::Utf8Value referrer_utf8(context->GetIsolate(),
                                  resource_name.As<String>());
  CHECK_EQ(0, strcmp("www.google.com", *referrer_utf8));
  CHECK_EQ(host_defined_options.As<v8::FixedArray>()->Length(),
           kCustomHostDefinedOptionsLengthForTesting);

  CHECK(!specifier.IsEmpty());
  String::Utf8Value specifier_utf8(context->GetIsolate(), specifier);
  CHECK_EQ(0, strcmp("index.js", *specifier_utf8));

  CHECK_EQ(8, import_attributes->Length());
  constexpr int kAttributeEntrySizeForDynamicImport = 2;
  for (int i = 0;
       i < import_attributes->Length() / kAttributeEntrySizeForDynamicImport;
       ++i) {
    Local<String> attribute_key =
        import_attributes
            ->Get(context, (i * kAttributeEntrySizeForDynamicImport))
            .As<Value>()
            .As<String>();
    Local<String> attribute_value =
        import_attributes
            ->Get(context, (i * kAttributeEntrySizeForDynamicImport) + 1)
            .As<Value>()
            .As<String>();
    if (v8_str("a")->StrictEquals(attribute_key)) {
      CHECK(v8_str("z")->StrictEquals(attribute_value));
    } else if (v8_str("aa")->StrictEquals(attribute_key)) {
      CHECK(v8_str("x")->StrictEquals(attribute_value));
    } else if (v8_str("b")->StrictEquals(attribute_key)) {
      CHECK(v8_str("w")->StrictEquals(attribute_value));
    } else if (v8_str("c")->StrictEquals(attribute_key)) {
      CHECK(v8_str("y")->StrictEquals(attribute_value));
    } else {
      UNREACHABLE();
    }
  }

  Local<v8::Promise::Resolver> resolver =
      v8::Promise::Resolver::New(context).ToLocalChecked();
  auto result = v8_str("hello world");
  resolver->Resolve(context, result).ToChecked();
  return resolver->GetPromise();
}

TEST(DynamicImportWithAttributes) {
  FLAG_SCOPE(harmony_import_attributes);

  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  isolate->SetHostImportModuleDynamicallyCallback(
      HostImportModuleDynamicallyWithAttributesCallbackResolve);

  i::DirectHandle<i::String> url =
      v8::Utils::OpenDirectHandle(*v8_str("www.google.com"));
  i::Handle<i::Object> specifier(v8::Utils::OpenHandle(*v8_str("index.js")));
  i::DirectHandle<i::String> result =
      v8::Utils::OpenDirectHandle(*v8_str("hello world"));
  i::DirectHandle<i::String> source(v8::Utils::OpenHandle(*v8_str("foo")));
  v8::Local<v8::Object> import_options =
      CompileRun(
          "var arg = { with: { 'b': 'w', aa: 'x',  c: 'y', a: 'z'} };"
          "arg;")
          ->ToObject(context.local())
          .ToLocalChecked();

  i::Handle<i::Object> i_import_options =
      v8::Utils::OpenHandle(*import_options);

  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  i::Handle<i::Script> referrer = i_isolate->factory()->NewScript(source);
  referrer->set_name(*url);
  i::DirectHandle<i::FixedArray> options = i_isolate->factory()->NewFixedArray(
      kCustomHostDefinedOptionsLengthForTesting);
  referrer->set_host_defined_options(*options);
  i::MaybeHandle<i::JSPromise> maybe_promise =
      i_isolate->RunHostImportModuleDynamicallyCallback(
          referrer, specifier, v8::ModuleImportPhase::kEvaluation,
          i_import_options);
  i::DirectHandle<i::JSPromise> promise = maybe_promise.ToHandleChecked();
  isolate->PerformMicrotaskCheckpoint();
  CHECK(result->Equals(i::Cast<i::String>(promise->result())));
}

void HostInitializeImportMetaObjectCallbackStatic(Local<Context> context,
                                                  Local<Module> module,
                                                  Local<Object> meta) {
  CHECK(!module.IsEmpty());
  meta->CreateDataProperty(context, v8_str("foo"), v8_str("bar")).ToChecked();
}

TEST(ImportMeta) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);

  isolate->SetHostInitializeImportMetaObjectCallback(
      HostInitializeImportMetaObjectCallbackStatic);

  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  Local<String> url = v8_str("www.google.com");
  Local<String> source_text = v8_str("globalThis.Result = import.meta;");
  v8::ScriptOrigin origin(url, 0, 0, false, -1, Local<v8::Value>(), false,
                          false, true);
  v8::ScriptCompiler::Source source(source_text, origin);
  Local<Module> module =
      v8::ScriptCompiler::CompileModule(isolate, &source).ToLocalChecked();
  i::Handle<i::JSObject> meta =
      i::SourceTextModule::GetImportMeta(
          i_isolate,
          i::Cast<i::SourceTextModule>(v8::Utils::OpenHandle(*module)))
          .ToHandleChecked();
  Local<Object> meta_obj = Local<Object>::Cast(v8::Utils::ToLocal(meta));
  CHECK(meta_obj->Get(context.local(), v8_str("foo"))
            .ToLocalChecked()
            ->IsString());
  CHECK(meta_obj->Get(context.local(), v8_str("zapp"))
            .ToLocalChecked()
            ->IsUndefined());

  module->InstantiateModule(context.local(), UnexpectedModuleResolveCallback)
      .ToChecked();
  Local<Value> result = module->Evaluate(context.local()).ToLocalChecked();
  Local<v8::Promise> promise(Local<v8::Promise>::Cast(result));
  CHECK_EQ(promise->State(), v8::Promise::kFulfilled);
  CHECK(promise->Result()->IsUndefined());
  CHECK(context.local()
            ->Global()
            ->Get(context.local(), v8_str("Result"))
            .ToLocalChecked()
            ->StrictEquals(Local<v8::Value>::Cast(v8::Utils::ToLocal(meta))));
}

void HostInitializeImportMetaObjectCallbackThrow(Local<Context> context,
                                                 Local<Module> module,
                                                 Local<Object> meta) {
  CcTest::isolate()->ThrowException(v8_num(42));
}

TEST(ImportMetaThrowUnhandled) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);

  isolate->SetHostInitializeImportMetaObjectCallback(
      HostInitializeImportMetaObjectCallbackThrow);

  Local<String> url = v8_str("www.google.com");
  Local<String> source_text =
      v8_str("export default function() { return import.meta }");
  v8::ScriptOrigin origin(url, 0, 0, false, -1, Local<v8::Value>(), false,
                          false, true);
  v8::ScriptCompiler::Source source(source_text, origin);
  Local<Module> module =
      v8::ScriptCompiler::CompileModule(isolate, &source).ToLocalChecked();
  module->InstantiateModule(context.local(), UnexpectedModuleResolveCallback)
      .ToChecked();

  Local<Value> result = module->Evaluate(context.local()).ToLocalChecked();
  auto promise = Local<v8::Promise>::Cast(result);
  CHECK_EQ(promise->State(), v8::Promise::kFulfilled);

  Local<Object> ns = module->GetModuleNamespace().As<Object>();
  Local<Value> closure =
      ns->Get(context.local(), v8_str("default")).ToLocalChecked();

  v8::TryCatch try_catch(isolate);
  CHECK(Function::Cast(*closure)
            ->Call(context.local(), v8::Undefined(isolate), 0, nullptr)
            .IsEmpty());
  CHECK(try_catch.HasCaught());
  CHECK(try_catch.Exception()->StrictEquals(v8_num(42)));
}

TEST(ImportMetaThrowHandled) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);

  isolate->SetHostInitializeImportMetaObjectCallback(
      HostInitializeImportMetaObjectCallbackThrow);

  Local<String> url = v8_str("www.google.com");
  Local<String> source_text = v8_str(R"javascript(
      export default function() {
        try {
          import.meta;
        } catch {
          return true;
        }
        return false;
      }
      )javascript");
  v8::ScriptOrigin origin(url, 0, 0, false, -1, Local<v8::Value>(), false,
                          false, true);
  v8::ScriptCompiler::Source source(source_text, origin);
  Local<Module> module =
      v8::ScriptCompiler::CompileModule(isolate, &source).ToLocalChecked();
  module->InstantiateModule(context.local(), UnexpectedModuleResolveCallback)
      .ToChecked();

  Local<Value> result = module->Evaluate(context.local()).ToLocalChecked();
  auto promise = Local<v8::Promise>::Cast(result);
  CHECK_EQ(promise->State(), v8::Promise::kFulfilled);

  Local<Object> ns = module->GetModuleNamespace().As<Object>();
  Local<Value> closure =
      ns->Get(context.local(), v8_str("default")).ToLocalChecked();

  v8::TryCatch try_catch(isolate);
  CHECK(Function::Cast(*closure)
            ->Call(context.local(), v8::Undefined(isolate), 0, nullptr)
            .ToLocalChecked()
            ->IsTrue());
  CHECK(!try_catch.HasCaught());
}

v8::MaybeLocal<v8::Context> HostCreateShadowRealmContextCallbackStatic(
    v8::Local<v8::Context> initiator_context) {
  CHECK(!initiator_context.IsEmpty());
  return v8::Context::New(initiator_context->GetIsolate());
}

TEST(CreateShadowRealmContextHostNotSupported) {
  i::v8_flags.harmony_shadow_realm = true;
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);

  Local<String> url = v8_str("www.google.com");
  Local<String> source_text = v8_str("new ShadowRealm()");
  v8::ScriptOrigin origin(url, 0, 0, false, -1, Local<v8::Value>(), false,
                          false, false);
  v8::ScriptCompiler::Source source(source_text, origin);
  Local<Script> script =
      v8::ScriptCompiler::Compile(context.local(), &source).ToLocalChecked();

  v8::TryCatch try_catch(isolate);
  v8::MaybeLocal<v8::Value> result = script->Run(context.local());
  CHECK(try_catch.HasCaught());
  CHECK(result.IsEmpty());
  CHECK(v8_str("Error: Not supported")
            ->Equals(isolate->GetCurrentContext(),
                     try_catch.Exception()
                         ->ToString(isolate->GetCurrentContext())
                         .ToLocalChecked())
            .FromJust());
}

TEST(CreateShadowRealmContext) {
  i::v8_flags.harmony_shadow_realm = true;
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);

  isolate->SetHostCreateShadowRealmContextCallback(
      HostCreateShadowRealmContextCallbackStatic);

  Local<String> url = v8_str("www.google.com");
  Local<String> source_text = v8_str("new ShadowRealm()");
  v8::ScriptOrigin origin(url, 0, 0, false, -1, Local<v8::Value>(), false,
                          false, false);
  v8::ScriptCompiler::Source source(source_text, origin);
  Local<Script> script =
      v8::ScriptCompiler::Compile(context.local(), &source).ToLocalChecked();

  Local<Value> result = script->Run(context.local()).ToLocalChecked();
  CHECK(result->IsObject());
  i::DirectHandle<i::Object> object = v8::Utils::OpenDirectHandle(*result);
  CHECK(IsJSShadowRealm(*object));
}

v8::MaybeLocal<v8::Context> HostCreateShadowRealmContextCallbackThrow(
    v8::Local<v8::Context> initiator_context) {
  CcTest::isolate()->ThrowException(v8_num(42));
  return v8::MaybeLocal<v8::Context>();
}

TEST(CreateShadowRealmContextThrow) {
  i::v8_flags.harmony_shadow_realm = true;
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);

  isolate->SetHostCreateShadowRealmContextCallback(
      HostCreateShadowRealmContextCallbackThrow);

  Local<String> url = v8_str("www.google.com");
  Local<String> source_text = v8_str("new ShadowRealm()");
  v8::ScriptOrigin origin(url, 0, 0, false, -1, Local<v8::Value>(), false,
                          false, false);
  v8::ScriptCompiler::Source source(source_text, origin);
  Local<Script> script =
      v8::ScriptCompiler::Compile(context.local(), &source).ToLocalChecked();

  v8::TryCatch try_catch(isolate);
  CHECK(script->Run(context.local()).IsEmpty());
  CHECK(try_catch.HasCaught());
  CHECK(try_catch.Exception()->StrictEquals(v8_num(42)));
}

TEST(GetModuleNamespace) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);

  Local<String> url = v8_str("www.google.com");
  Local<String> source_text = v8_str("export default 5; export const a = 10;");
  v8::ScriptOrigin origin(url, 0, 0, false, -1, Local<v8::Value>(), false,
                          false, true);
  v8::ScriptCompiler::Source source(source_text, origin);
  Local<Module> module =
      v8::ScriptCompiler::CompileModule(isolate, &source).ToLocalChecked();
  module->InstantiateModule(context.local(), UnexpectedModuleResolveCallback)
      .ToChecked();
  module->Evaluate(context.local()).ToLocalChecked();

  Local<Value> ns_val = module->GetModuleNamespace();
  CHECK(ns_val->IsModuleNamespaceObject());
  Local<Object> ns = ns_val.As<Object>();
  CHECK(ns->Get(context.local(), v8_str("default"))
            .ToLocalChecked()
            ->StrictEquals(v8::Number::New(isolate, 5)));
  CHECK(ns->Get(context.local(), v8_str("a"))
            .ToLocalChecked()
            ->StrictEquals(v8::Number::New(isolate, 10)));
}

TEST(ModuleGetUnboundModuleScript) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);

  Local<String> url = v8_str("www.google.c
```