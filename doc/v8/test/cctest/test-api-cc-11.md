Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/test/cctest/test-api.cc`.

Here's a breakdown of the request and how to approach it:

1. **Identify the core purpose:** The file name suggests it tests the V8 API. The code confirms this by using V8 API functions extensively.

2. **Scan for `TEST` macros:** These mark individual test cases, providing clues about specific features being tested.

3. **Analyze each test case:**  Describe what each test does in terms of V8 API usage and the scenarios it covers.

4. **Look for JavaScript connections:** The code uses `CompileRun` to execute JavaScript code within the V8 environment. Identify how this JavaScript interacts with the C++ API being tested. Provide JavaScript examples where relevant.

5. **Infer code logic and provide examples:**  For tests involving setting up contexts, objects, and properties, devise simple scenarios with input and expected output to illustrate the test's behavior.

6. **Identify common programming errors:** Some tests seem designed to check error handling or unexpected behavior. Highlight these and relate them to potential mistakes developers might make.

7. **Address specific instructions:**
    * Check for `.tq` files (none found).
    * Note the section number (12/36).

8. **Synthesize a concise summary:** Combine the individual test case analyses into a broader overview of the file's purpose.

**Mental Walkthrough of the Code:**

* **`PropertyCallbacks`:** Tests basic property getter/setter behavior.
* **`NonExistentProperty`:** Checks how V8 handles access to non-existent properties.
* **`ContextSecurityTokens`:** Explores the role of security tokens in cross-context access.
* **`DetachedAccesses`:** Focuses on the behavior of detached and reattached contexts.
* **`AccessControl` and `AccessControlES5`:**  Examine V8's access control mechanisms using `SetAccessCheckCallback`.
* **`Regress470113`:**  Likely a regression test for a specific bug related to access control and strict mode.
* **`CrossDomainAccessors`:** Tests access to accessors across different V8 contexts.
* **`AccessControlIC`:**  Investigates how inline caches interact with access control checks.
* **`Version`:**  Simple test to get the V8 version.
* **`InstanceProperties`:**  Tests properties on object instances created from templates.
* **`ContextScriptExecutionCallback`:** Examines the `SetAbortScriptExecution` callback.
* **`GlobalObjectInstanceProperties`:**  Tests properties on the global object instance.
* **`ObjectGetOwnPropertyNames`:**  Checks the behavior of `Object.getOwnPropertyNames`.
* **`CallKnownGlobalReceiver`:** Seems to test a specific scenario related to deoptimization and global object proxies.
* **`ShadowObject`:** Explores how properties are resolved in the presence of shadowing and interceptors.

**Pre-computation/Analysis:**

* Recognize the core V8 API functions being used (e.g., `Context::New`, `ObjectTemplate`, `SetAccessorProperty`, `CompileRun`, `SetAccessCheckCallback`).
* Understand the concept of V8 contexts and isolates.
* Recall how JavaScript property access and prototypes work.

By following this thought process, I can systematically analyze the code and generate the comprehensive summary requested by the user.
这个v8源代码文件 `v8/test/cctest/test-api.cc` 的主要功能是 **测试 V8 JavaScript 引擎提供的 C++ API 的各种特性和功能**。 它通过一系列的单元测试来验证这些 API 的行为是否符合预期，包括对象创建、属性访问、上下文管理、安全控制、以及性能相关的方面。

**功能列表：**

1. **测试属性回调 (Property Callbacks):**  验证自定义的属性 getter 和 setter 函数能否正确执行，以及对不存在的属性的访问行为。
2. **测试上下文安全令牌 (Context Security Tokens):**  验证不同 V8 上下文之间的安全隔离机制，确保只有拥有相同安全令牌的上下文才能互相访问。
3. **测试分离上下文访问 (Detached Accesses):**  测试在 V8 上下文被分离 (DetachGlobal) 和重新附加后，通过闭包和 `this` 关键字访问其内部变量的行为。
4. **测试访问控制 (Access Control):**  测试 V8 的访问控制机制，通过 `SetAccessCheckCallback` 函数定义访问控制策略，限制跨上下文的对象属性访问。
5. **测试 ES5 访问控制 (Access Control ES5):**  针对 ES5 规范，测试访问控制机制在 `Object.keys`、`Object.defineProperty`、`Object.preventExtensions` 等方法上的行为。
6. **回归测试 (Regression Tests):**  包含了一些针对特定 bug 的回归测试，例如 `Regress470113`，确保之前修复的问题不会再次出现。
7. **测试跨域访问器 (Cross-Domain Accessors):**  测试在不同的 V8 上下文中访问属性访问器时的行为。
8. **测试访问控制和内联缓存 (Access Control IC):**  测试访问控制机制与 V8 的内联缓存 (Inline Caches) 之间的交互，验证访问控制回调是否在优化场景下仍然会被调用。
9. **获取 V8 版本 (Version):**  一个简单的测试，用于获取 V8 引擎的版本号。
10. **测试实例属性 (Instance Properties):**  测试通过对象模板创建的实例的属性访问和函数调用。
11. **测试上下文脚本执行回调 (Context Script Execution Callback):**  测试 `SetAbortScriptExecution` 函数，允许在脚本执行过程中注册一个回调函数，并在特定情况下中断脚本执行。
12. **测试全局对象实例属性 (Global Object Instance Properties):**  测试全局对象实例的属性处理和访问。
13. **测试 `Object.getOwnPropertyNames`:**  验证 JavaScript 的 `Object.getOwnPropertyNames` 方法在 C++ API 中的行为，包括不同类型的属性过滤和键转换模式。
14. **测试已知全局接收者的调用 (Call Known Global Receiver):**  测试在特定场景下（例如去优化时）调用全局函数时的行为，确保全局对象状态正确。
15. **测试阴影对象 (Shadow Object):**  测试当原型链和对象自身都定义了同名属性时，属性查找的优先级和拦截器的行为。

**如果 `v8/test/cctest/test-api.cc` 以 `.tq` 结尾：**

如果文件名以 `.tq` 结尾，那么它确实是一个 **V8 Torque 源代码**。Torque 是 V8 用来生成高效的运行时代码的领域特定语言。然而，根据你提供的信息，该文件名为 `.cc`，所以它是 C++ 源代码。

**与 JavaScript 功能的关系及 JavaScript 示例：**

这个文件中的每一个测试都直接或间接地与 JavaScript 的功能相关，因为它测试的是 V8 引擎执行 JavaScript 代码时的行为。以下是一些与 JavaScript 功能相关的示例：

* **属性访问:**

```javascript
// 对应 PropertyCallbacks 测试
const obj = {};
obj.foo = 10; // 设置属性
console.log(obj.foo); // 获取属性
delete obj.foo; // 删除属性
```

* **上下文安全令牌:**

```javascript
// 对应 ContextSecurityTokens 测试 (需要创建多个 V8 上下文)
// 假设 env1 和 env2 是两个不同的 V8 上下文
// 如果它们拥有不同的安全令牌，则以下操作会失败
// 在 env1 中创建对象 o
// 在 env2 中尝试访问 o 的属性
```

* **访问控制:**

```javascript
// 对应 AccessControl 测试 (需要创建多个 V8 上下文)
// 假设 env1 中定义了具有访问控制的对象 other
// 在 env2 中尝试访问 other 的属性，可能会因为访问控制被阻止
console.log(other.blocked_prop); // 可能会返回 undefined 或抛出错误
```

* **`Object.getOwnPropertyNames`:**

```javascript
// 对应 ObjectGetOwnPropertyNames 测试
const str = "test";
const propertyNames = Object.getOwnPropertyNames(str);
console.log(propertyNames); // 输出: ['0', '1', '2', '3', 'length']
```

**代码逻辑推理和假设输入/输出：**

以 `ContextSecurityTokens` 测试为例：

**假设输入：**

1. 创建两个 V8 上下文 `env1` 和 `env2`。
2. 在 `env1` 中创建一个对象 `obj` 并设置属性 `p` 的值为 `23`。
3. 为 `env1` 设置一个安全令牌 "token"。
4. 不为 `env2` 设置安全令牌，或者设置一个不同的安全令牌。
5. 尝试在 `env2` 中访问 `env1` 的 `obj.p`。

**预期输出：**

由于 `env1` 和 `env2` 的安全令牌不同，`env2` 应该无法直接访问 `env1` 中对象的属性。`CompileRun("obj.p")` 在 `env2` 中执行应该返回一个空值或者抛出一个错误，表明访问被拒绝。

**涉及用户常见的编程错误：**

* **跨上下文访问不兼容的对象:**  开发者可能会错误地尝试在一个上下文中创建对象，然后在另一个不具有相同安全令牌的上下文中直接访问该对象，导致访问被拒绝。

```javascript
// 错误示例：
// 假设在不同的 iframe 或 worker 中创建了对象
const iframe = document.createElement('iframe');
document.body.appendChild(iframe);
const otherContextWindow = iframe.contentWindow;
otherContextWindow.myObject = { value: 10 };

// 在当前窗口尝试访问
console.log(otherContextWindow.myObject.value); // 可能会因为跨域安全策略失败
```

* **对分离的上下文进行操作:**  在多线程或异步操作中，开发者可能会忘记检查上下文是否仍然有效，尝试访问已经分离的上下文的全局对象，导致程序崩溃或出现不可预测的行为。

```javascript
// 错误示例 (模拟上下文分离):
let myContext = createContext();
let globalObj = myContext.global;

detachContext(myContext); // 模拟上下文分离

// 稍后尝试访问已经分离的上下文的全局对象
console.log(globalObj.someVariable); // 可能会出错
```

**功能归纳 (第 12 部分，共 36 部分):**

作为测试套件的第 12 部分，这个文件主要关注 **V8 JavaScript 引擎 C++ API 中与上下文管理、安全控制以及基础对象操作相关的特性**。它深入测试了跨上下文访问的限制、如何通过安全令牌进行控制、以及在上下文生命周期变化（例如分离和重新附加）时 API 的行为。此外，它还涵盖了属性访问的细节，包括自定义 getter/setter 和 `Object.getOwnPropertyNames` 等反射 API。总的来说，这个文件旨在确保 V8 引擎在处理多上下文和安全敏感的操作时能够正确且可靠地工作。

Prompt: 
```
这是目录为v8/test/cctest/test-api.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-api.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第12部分，共36部分，请归纳一下它的功能

"""
)
              .FromJust());
  }

  // Check that other.p is now the property in env3 and that we have access.
  result = CompileRun("other.p");
  CHECK(result->IsInt32());
  CHECK_EQ(24, result->Int32Value(env3).FromJust());
}


void GetThisX(const v8::FunctionCallbackInfo<v8::Value>& info) {
  v8::Local<v8::Context> context = info.GetIsolate()->GetCurrentContext();
  info.GetReturnValue().Set(
      context->Global()->Get(context, v8_str("x")).ToLocalChecked());
}


TEST(DetachedAccesses) {
  LocalContext env1;
  v8::HandleScope scope(env1->GetIsolate());

  // Create second environment.
  Local<ObjectTemplate> inner_global_template =
      FunctionTemplate::New(env1->GetIsolate())->InstanceTemplate();
  inner_global_template ->SetAccessorProperty(
      v8_str("this_x"), FunctionTemplate::New(env1->GetIsolate(), GetThisX));
  v8::Local<Context> env2 =
      Context::New(env1->GetIsolate(), nullptr, inner_global_template);

  Local<Value> foo = v8_str("foo");

  // Set same security token for env1 and env2.
  env1->SetSecurityToken(foo);
  env2->SetSecurityToken(foo);

  CHECK(env1->Global()
            ->Set(env1.local(), v8_str("x"), v8_str("env1_x"))
            .FromJust());

  {
    v8::Context::Scope context_scope(env2);
    CHECK(env2->Global()->Set(env2, v8_str("x"), v8_str("env2_x")).FromJust());
    CompileRun(
        "function bound_x() { return x; }"
        "function get_x()   { return this.x; }"
        "function get_x_w() { return (function() {return this.x;})(); }");
    CHECK(env1->Global()
              ->Set(env1.local(), v8_str("bound_x"), CompileRun("bound_x"))
              .FromJust());
    CHECK(env1->Global()
              ->Set(env1.local(), v8_str("get_x"), CompileRun("get_x"))
              .FromJust());
    CHECK(env1->Global()
              ->Set(env1.local(), v8_str("get_x_w"), CompileRun("get_x_w"))
              .FromJust());
    env1->Global()
        ->Set(env1.local(), v8_str("this_x"),
              CompileRun("Object.getOwnPropertyDescriptor(this, 'this_x').get"))
        .FromJust();
  }

  Local<Object> env2_global = env2->Global();
  env2->DetachGlobal();

  Local<Value> result;
  result = CompileRun("bound_x()");
  CHECK(v8_str("env2_x")->Equals(env1.local(), result).FromJust());
  result = CompileRun("get_x()");
  CHECK(result.IsEmpty());
  result = CompileRun("get_x_w()");
  CHECK(result.IsEmpty());
  result = CompileRun("this_x()");
  CHECK(v8_str("env2_x")->Equals(env1.local(), result).FromJust());

  // Reattach env2's proxy
  env2 = Context::New(env1->GetIsolate(), nullptr,
                      v8::Local<v8::ObjectTemplate>(), env2_global);
  env2->SetSecurityToken(foo);
  {
    v8::Context::Scope context_scope(env2);
    CHECK(env2->Global()->Set(env2, v8_str("x"), v8_str("env3_x")).FromJust());
    CHECK(env2->Global()->Set(env2, v8_str("env1"), env1->Global()).FromJust());
    result = CompileRun(
        "results = [];"
        "for (var i = 0; i < 4; i++ ) {"
        "  results.push(env1.bound_x());"
        "  results.push(env1.get_x());"
        "  results.push(env1.get_x_w());"
        "  results.push(env1.this_x());"
        "}"
        "results");
    Local<v8::Array> results = Local<v8::Array>::Cast(result);
    CHECK_EQ(16u, results->Length());
    for (int i = 0; i < 16; i += 4) {
      CHECK(v8_str("env2_x")
                ->Equals(env2, results->Get(env2, i + 0).ToLocalChecked())
                .FromJust());
      CHECK(v8_str("env1_x")
                ->Equals(env2, results->Get(env2, i + 1).ToLocalChecked())
                .FromJust());
      CHECK(v8_str("env3_x")
                ->Equals(env2, results->Get(env2, i + 2).ToLocalChecked())
                .FromJust());
      CHECK(v8_str("env2_x")
                ->Equals(env2, results->Get(env2, i + 3).ToLocalChecked())
                .FromJust());
    }
  }

  result = CompileRun(
      "results = [];"
      "for (var i = 0; i < 4; i++ ) {"
      "  results.push(bound_x());"
      "  results.push(get_x());"
      "  results.push(get_x_w());"
      "  results.push(this_x());"
      "}"
      "results");
  Local<v8::Array> results = Local<v8::Array>::Cast(result);
  CHECK_EQ(16u, results->Length());
  for (int i = 0; i < 16; i += 4) {
    CHECK(v8_str("env2_x")
              ->Equals(env1.local(),
                       results->Get(env1.local(), i + 0).ToLocalChecked())
              .FromJust());
    CHECK(v8_str("env3_x")
              ->Equals(env1.local(),
                       results->Get(env1.local(), i + 1).ToLocalChecked())
              .FromJust());
    CHECK(v8_str("env3_x")
              ->Equals(env1.local(),
                       results->Get(env1.local(), i + 2).ToLocalChecked())
              .FromJust());
    CHECK(v8_str("env2_x")
              ->Equals(env1.local(),
                       results->Get(env1.local(), i + 3).ToLocalChecked())
              .FromJust());
  }

  result = CompileRun(
      "results = [];"
      "for (var i = 0; i < 4; i++ ) {"
      "  results.push(this.bound_x());"
      "  results.push(this.get_x());"
      "  results.push(this.get_x_w());"
      "  results.push(this.this_x());"
      "}"
      "results");
  results = Local<v8::Array>::Cast(result);
  CHECK_EQ(16u, results->Length());
  for (int i = 0; i < 16; i += 4) {
    CHECK(v8_str("env2_x")
              ->Equals(env1.local(),
                       results->Get(env1.local(), i + 0).ToLocalChecked())
              .FromJust());
    CHECK(v8_str("env1_x")
              ->Equals(env1.local(),
                       results->Get(env1.local(), i + 1).ToLocalChecked())
              .FromJust());
    CHECK(v8_str("env3_x")
              ->Equals(env1.local(),
                       results->Get(env1.local(), i + 2).ToLocalChecked())
              .FromJust());
    CHECK(v8_str("env2_x")
              ->Equals(env1.local(),
                       results->Get(env1.local(), i + 3).ToLocalChecked())
              .FromJust());
  }
}


static bool allowed_access = false;
static bool AccessBlocker(Local<v8::Context> accessing_context,
                          Local<v8::Object> accessed_object,
                          Local<v8::Value> data) {
  v8::Local<v8::Context> context = CcTest::isolate()->GetCurrentContext();
  return context->Global()->Equals(context, accessed_object).FromJust() ||
         allowed_access;
}

static void UnreachableGetter(Local<Name> name,
                              const v8::PropertyCallbackInfo<v8::Value>& info) {
  UNREACHABLE();  // This function should not be called..
}

static void UnreachableSetter(Local<Name>, Local<Value>,
                              const v8::PropertyCallbackInfo<void>&) {
  UNREACHABLE();  // This function should not be called.
}

static void UnreachableFunction(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  UNREACHABLE();  // This function should not be called..
}


TEST(AccessControl) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope handle_scope(isolate);
  v8::Local<v8::ObjectTemplate> global_template =
      v8::ObjectTemplate::New(isolate);

  global_template->SetAccessCheckCallback(AccessBlocker);

  // Add an accessor that is not accessible by cross-domain JS code.
  global_template->SetNativeDataProperty(v8_str("blocked_prop"),
                                         UnreachableGetter, UnreachableSetter,
                                         v8::Local<Value>());

  global_template->SetAccessorProperty(
      v8_str("blocked_js_prop"),
      v8::FunctionTemplate::New(isolate, UnreachableFunction),
      v8::FunctionTemplate::New(isolate, UnreachableFunction), v8::None);

  // Create an environment
  v8::Local<Context> context0 = Context::New(isolate, nullptr, global_template);
  context0->Enter();

  v8::Local<v8::Object> global0 = context0->Global();

  // Define a property with JS getter and setter.
  CompileRun(
      "function getter() { return 'getter'; };\n"
      "function setter() { return 'setter'; }\n"
      "Object.defineProperty(this, 'js_accessor_p', {get:getter, set:setter})");

  Local<Value> getter =
      global0->Get(context0, v8_str("getter")).ToLocalChecked();
  Local<Value> setter =
      global0->Get(context0, v8_str("setter")).ToLocalChecked();

  // And define normal element.
  CHECK(global0->Set(context0, 239, v8_str("239")).FromJust());

  // Define an element with JS getter and setter.
  CompileRun(
      "function el_getter() { return 'el_getter'; };\n"
      "function el_setter() { return 'el_setter'; };\n"
      "Object.defineProperty(this, '42', {get: el_getter, set: el_setter});");

  Local<Value> el_getter =
      global0->Get(context0, v8_str("el_getter")).ToLocalChecked();
  Local<Value> el_setter =
      global0->Get(context0, v8_str("el_setter")).ToLocalChecked();

  v8::HandleScope scope1(isolate);

  v8::Local<Context> context1 = Context::New(isolate);
  context1->Enter();

  v8::Local<v8::Object> global1 = context1->Global();
  CHECK(global1->Set(context1, v8_str("other"), global0).FromJust());

  // Access blocked property.
  CompileRun("other.blocked_prop = 1");

  CHECK(CompileRun("other.blocked_prop").IsEmpty());
  CHECK(CompileRun("Object.getOwnPropertyDescriptor(other, 'blocked_prop')")
            .IsEmpty());
  CHECK(
      CompileRun("propertyIsEnumerable.call(other, 'blocked_prop')").IsEmpty());

  // Access blocked element.
  CHECK(CompileRun("other[239] = 1").IsEmpty());

  CHECK(CompileRun("other[239]").IsEmpty());
  CHECK(CompileRun("Object.getOwnPropertyDescriptor(other, '239')").IsEmpty());
  CHECK(CompileRun("propertyIsEnumerable.call(other, '239')").IsEmpty());

  allowed_access = true;
  // Now we can enumerate the property.
  ExpectTrue("propertyIsEnumerable.call(other, '239')");
  allowed_access = false;

  // Access a property with JS accessor.
  CHECK(CompileRun("other.js_accessor_p = 2").IsEmpty());

  CHECK(CompileRun("other.js_accessor_p").IsEmpty());
  CHECK(CompileRun("Object.getOwnPropertyDescriptor(other, 'js_accessor_p')")
            .IsEmpty());

  allowed_access = true;

  ExpectString("other.js_accessor_p", "getter");
  ExpectObject(
      "Object.getOwnPropertyDescriptor(other, 'js_accessor_p').get", getter);
  ExpectObject(
      "Object.getOwnPropertyDescriptor(other, 'js_accessor_p').set", setter);
  ExpectUndefined(
      "Object.getOwnPropertyDescriptor(other, 'js_accessor_p').value");

  allowed_access = false;

  // Access an element with JS accessor.
  CHECK(CompileRun("other[42] = 2").IsEmpty());

  CHECK(CompileRun("other[42]").IsEmpty());
  CHECK(CompileRun("Object.getOwnPropertyDescriptor(other, '42')").IsEmpty());

  allowed_access = true;

  ExpectString("other[42]", "el_getter");
  ExpectObject("Object.getOwnPropertyDescriptor(other, '42').get", el_getter);
  ExpectObject("Object.getOwnPropertyDescriptor(other, '42').set", el_setter);
  ExpectUndefined("Object.getOwnPropertyDescriptor(other, '42').value");

  allowed_access = false;

  v8::Local<Value> value;

  // Enumeration doesn't enumerate accessors from inaccessible objects in
  // the prototype chain even if the accessors are in themselves accessible.
  // Enumeration doesn't throw, it silently ignores what it can't access.
  value = CompileRun(
      "(function() {"
      "  var obj = { '__proto__': other };"
      "  try {"
      "    for (var p in obj) {"
      "      if (p == 'blocked_js_prop' ||"
      "          p == 'blocked_js_prop') {"
      "        return false;"
      "      }"
      "    }"
      "    return true;"
      "  } catch (e) {"
      "    return false;"
      "  }"
      "})()");
  CHECK(value->IsTrue());

  // Test that preventExtensions fails on a non-accessible object even if that
  // object is already non-extensible.
  CHECK(global1->Set(context1, v8_str("checked_object"),
                     global_template->NewInstance(context1).ToLocalChecked())
            .FromJust());
  allowed_access = true;
  CompileRun("Object.preventExtensions(checked_object)");
  ExpectFalse("Object.isExtensible(checked_object)");
  allowed_access = false;
  CHECK(CompileRun("Object.preventExtensions(checked_object)").IsEmpty());

  context1->Exit();
  context0->Exit();
}


TEST(AccessControlES5) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope handle_scope(isolate);
  v8::Local<v8::ObjectTemplate> global_template =
      v8::ObjectTemplate::New(isolate);

  global_template->SetAccessCheckCallback(AccessBlocker);

  // Add an accessor that is not accessible by cross-domain JS code.
  global_template->SetNativeDataProperty(v8_str("blocked_prop"),
                                         UnreachableGetter, UnreachableSetter,
                                         v8::Local<Value>());

  // Create an environment
  v8::Local<Context> context0 = Context::New(isolate, nullptr, global_template);
  context0->Enter();

  v8::Local<v8::Object> global0 = context0->Global();

  v8::Local<Context> context1 = Context::New(isolate);
  context1->Enter();
  v8::Local<v8::Object> global1 = context1->Global();
  CHECK(global1->Set(context1, v8_str("other"), global0).FromJust());

  // Regression test for issue 1154.
  CHECK(CompileRun("Object.keys(other).length == 0")->BooleanValue(isolate));
  CHECK(CompileRun("other.blocked_prop").IsEmpty());

  // Regression test for issue 1027.
  CompileRun("Object.defineProperty(\n"
             "  other, 'blocked_prop', {configurable: false})");
  CHECK(CompileRun("other.blocked_prop").IsEmpty());
  CHECK(CompileRun("Object.getOwnPropertyDescriptor(other, 'blocked_prop')")
            .IsEmpty());

  // Regression test for issue 1171.
  ExpectTrue("Object.isExtensible(other)");
  CompileRun("Object.preventExtensions(other)");
  ExpectTrue("Object.isExtensible(other)");

  // Object.seal and Object.freeze.
  CompileRun("Object.freeze(other)");
  ExpectTrue("Object.isExtensible(other)");

  CompileRun("Object.seal(other)");
  ExpectTrue("Object.isExtensible(other)");
}

static bool AccessAlwaysBlocked(Local<v8::Context> accessing_context,
                                Local<v8::Object> global,
                                Local<v8::Value> data) {
  i::PrintF("Access blocked.\n");
  return false;
}

static bool AccessAlwaysAllowed(Local<v8::Context> accessing_context,
                                Local<v8::Object> global,
                                Local<v8::Value> data) {
  i::PrintF("Access allowed.\n");
  return true;
}

TEST(Regress470113) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope handle_scope(isolate);
  v8::Local<v8::ObjectTemplate> obj_template = v8::ObjectTemplate::New(isolate);
  obj_template->SetAccessCheckCallback(AccessAlwaysBlocked);
  LocalContext env;
  CHECK(env->Global()
            ->Set(env.local(), v8_str("prohibited"),
                  obj_template->NewInstance(env.local()).ToLocalChecked())
            .FromJust());

  {
    v8::TryCatch try_catch(isolate);
    CompileRun(
        "'use strict';\n"
        "class C extends Object {\n"
        "   m() { super.powned = 'Powned!'; }\n"
        "}\n"
        "let c = new C();\n"
        "c.m.call(prohibited)");

    CHECK(try_catch.HasCaught());
  }
}

THREADED_TEST(CrossDomainAccessors) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope handle_scope(isolate);

  v8::Local<v8::FunctionTemplate> func_template =
      v8::FunctionTemplate::New(isolate);

  v8::Local<v8::ObjectTemplate> global_template =
      func_template->InstanceTemplate();

  // Add an accessor that is not accessible by cross-domain JS code.
  global_template->SetNativeDataProperty(
      v8_str("unreachable"), UnreachableGetter, nullptr, v8::Local<Value>());

  v8::Local<Context> context0 = Context::New(isolate, nullptr, global_template);
  context0->Enter();

  Local<v8::Object> global = context0->Global();

  // Enter a new context.
  v8::HandleScope scope1(CcTest::isolate());
  v8::Local<Context> context1 = Context::New(isolate);
  context1->Enter();

  v8::Local<v8::Object> global1 = context1->Global();
  CHECK(global1->Set(context1, v8_str("other"), global).FromJust());

  v8::MaybeLocal<v8::Value> maybe_value =
      v8_compile("other.unreachable")->Run(context1);
  CHECK(maybe_value.IsEmpty());

  context1->Exit();
  context0->Exit();
}


static int access_count = 0;

static bool AccessCounter(Local<v8::Context> accessing_context,
                          Local<v8::Object> accessed_object,
                          Local<v8::Value> data) {
  access_count++;
  return true;
}


// This one is too easily disturbed by other tests.
TEST(AccessControlIC) {
  access_count = 0;

  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope handle_scope(isolate);

  // Create an environment.
  v8::Local<Context> context0 = Context::New(isolate);
  context0->Enter();

  // Create an object that requires access-check functions to be
  // called for cross-domain access.
  v8::Local<v8::ObjectTemplate> object_template =
      v8::ObjectTemplate::New(isolate);
  object_template->SetAccessCheckCallback(AccessCounter);
  Local<v8::Object> object =
      object_template->NewInstance(context0).ToLocalChecked();

  v8::HandleScope scope1(isolate);

  // Create another environment.
  v8::Local<Context> context1 = Context::New(isolate);
  context1->Enter();

  // Make easy access to the object from the other environment.
  v8::Local<v8::Object> global1 = context1->Global();
  CHECK(global1->Set(context1, v8_str("obj"), object).FromJust());

  v8::Local<Value> value;

  // Check that the named access-control function is called every time.
  CompileRun("function testProp(obj) {"
             "  for (var i = 0; i < 10; i++) obj.prop = 1;"
             "  for (var j = 0; j < 10; j++) obj.prop;"
             "  return obj.prop"
             "}");
  value = CompileRun("testProp(obj)");
  CHECK(value->IsNumber());
  CHECK_EQ(1, value->Int32Value(context1).FromJust());
  CHECK_EQ(21, access_count);

  // Check that the named access-control function is called every time.
  CompileRun("var p = 'prop';"
             "function testKeyed(obj) {"
             "  for (var i = 0; i < 10; i++) obj[p] = 1;"
             "  for (var j = 0; j < 10; j++) obj[p];"
             "  return obj[p];"
             "}");
  // Use obj which requires access checks.  No inline caching is used
  // in that case.
  value = CompileRun("testKeyed(obj)");
  CHECK(value->IsNumber());
  CHECK_EQ(1, value->Int32Value(context1).FromJust());
  CHECK_EQ(42, access_count);
  // Force the inline caches into generic state and try again.
  CompileRun("testKeyed({ a: 0 })");
  CompileRun("testKeyed({ b: 0 })");
  value = CompileRun("testKeyed(obj)");
  CHECK(value->IsNumber());
  CHECK_EQ(1, value->Int32Value(context1).FromJust());
  CHECK_EQ(63, access_count);

  // Check that the indexed access-control function is called every time.
  access_count = 0;

  CompileRun("function testIndexed(obj) {"
             "  for (var i = 0; i < 10; i++) obj[0] = 1;"
             "  for (var j = 0; j < 10; j++) obj[0];"
             "  return obj[0]"
             "}");
  value = CompileRun("testIndexed(obj)");
  CHECK(value->IsNumber());
  CHECK_EQ(1, value->Int32Value(context1).FromJust());
  CHECK_EQ(21, access_count);
  // Force the inline caches into generic state.
  CompileRun("testIndexed(new Array(1))");
  // Test that the indexed access check is called.
  value = CompileRun("testIndexed(obj)");
  CHECK(value->IsNumber());
  CHECK_EQ(1, value->Int32Value(context1).FromJust());
  CHECK_EQ(42, access_count);

  access_count = 0;
  // Check that the named access check is called when invoking
  // functions on an object that requires access checks.
  CompileRun("obj.f = function() {}");
  CompileRun("function testCallNormal(obj) {"
             "  for (var i = 0; i < 10; i++) obj.f();"
             "}");
  CompileRun("testCallNormal(obj)");
  printf("%i\n", access_count);
  CHECK_EQ(11, access_count);

  // Force obj into slow case.
  value = CompileRun("delete obj.prop");
  CHECK(value->BooleanValue(isolate));
  // Force inline caches into dictionary probing mode.
  CompileRun("var o = { x: 0 }; delete o.x; testProp(o);");
  // Test that the named access check is called.
  value = CompileRun("testProp(obj);");
  CHECK(value->IsNumber());
  CHECK_EQ(1, value->Int32Value(context1).FromJust());
  CHECK_EQ(33, access_count);

  // Force the call inline cache into dictionary probing mode.
  CompileRun("o.f = function() {}; testCallNormal(o)");
  // Test that the named access check is still called for each
  // invocation of the function.
  value = CompileRun("testCallNormal(obj)");
  CHECK_EQ(43, access_count);

  context1->Exit();
  context0->Exit();
}


THREADED_TEST(Version) { v8::V8::GetVersion(); }


static void InstanceFunctionCallback(
    const v8::FunctionCallbackInfo<v8::Value>& args) {
  ApiTestFuzzer::Fuzz();
  args.GetReturnValue().Set(v8_num(12));
}


THREADED_TEST(InstanceProperties) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope handle_scope(isolate);

  Local<v8::FunctionTemplate> t = v8::FunctionTemplate::New(isolate);
  Local<ObjectTemplate> instance = t->InstanceTemplate();

  instance->Set(isolate, "x", v8_num(42));
  instance->Set(isolate, "f",
                v8::FunctionTemplate::New(isolate, InstanceFunctionCallback));

  Local<Value> o = t->GetFunction(context.local())
                       .ToLocalChecked()
                       ->NewInstance(context.local())
                       .ToLocalChecked();

  CHECK(context->Global()->Set(context.local(), v8_str("i"), o).FromJust());
  Local<Value> value = CompileRun("i.x");
  CHECK_EQ(42, value->Int32Value(context.local()).FromJust());

  value = CompileRun("i.f()");
  CHECK_EQ(12, value->Int32Value(context.local()).FromJust());
}

namespace {
v8::Intercepted GlobalObjectInstancePropertiesGet(
    Local<Name> key, const v8::PropertyCallbackInfo<v8::Value>& info) {
  // The request is not intercepted so don't call ApiTestFuzzer::Fuzz() here.
  CHECK(i::ValidateCallbackInfo(info));
  return v8::Intercepted::kNo;
}

int script_execution_count = 0;
void ScriptExecutionCallback(v8::Isolate* isolate, Local<Context> context) {
  script_execution_count++;
}
}  // namespace

THREADED_TEST(ContextScriptExecutionCallback) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope handle_scope(isolate);
  LocalContext context;

  {
    v8::TryCatch try_catch(isolate);
    script_execution_count = 0;
    ExpectTrue("1 + 1 == 2");
    CHECK_EQ(0, script_execution_count);
    CHECK(!try_catch.HasCaught());
  }

  context->SetAbortScriptExecution(ScriptExecutionCallback);

  {  // Function binding does not trigger callback.
    v8::Local<v8::FunctionTemplate> function_template =
        v8::FunctionTemplate::New(isolate, DummyCallHandler);
    v8::Local<v8::Function> function =
        function_template->GetFunction(context.local()).ToLocalChecked();

    v8::TryCatch try_catch(isolate);
    script_execution_count = 0;

    CHECK_EQ(13.4,
             function->Call(context.local(), v8::Undefined(isolate), 0, nullptr)
                 .ToLocalChecked()
                 ->NumberValue(context.local())
                 .FromJust());
    CHECK_EQ(0, script_execution_count);
    CHECK(!try_catch.HasCaught());
  }

  {  // Script execution triggers callback.
    v8::TryCatch try_catch(isolate);
    script_execution_count = 0;
    CHECK(CompileRun(context.local(), "2 + 2 == 4").IsEmpty());
    CHECK_EQ(1, script_execution_count);
    CHECK(try_catch.HasCaught());
  }

  context->SetAbortScriptExecution(nullptr);

  {  // Script execution no longer triggers callback.
    v8::TryCatch try_catch(isolate);
    script_execution_count = 0;
    ExpectTrue("2 + 2 == 4");
    CHECK_EQ(0, script_execution_count);
    CHECK(!try_catch.HasCaught());
  }
}

THREADED_TEST(GlobalObjectInstanceProperties) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope handle_scope(isolate);

  Local<Value> global_object;

  Local<v8::FunctionTemplate> t = v8::FunctionTemplate::New(isolate);
  t->InstanceTemplate()->SetHandler(
      v8::NamedPropertyHandlerConfiguration(GlobalObjectInstancePropertiesGet));
  Local<ObjectTemplate> instance_template = t->InstanceTemplate();
  instance_template->Set(isolate, "x", v8_num(42));
  instance_template->Set(
      isolate, "f",
      v8::FunctionTemplate::New(isolate, InstanceFunctionCallback));

  // The script to check how TurboFan compiles missing global function
  // invocations.  function g is not defined and should throw on call.
  const char* script =
      "function wrapper(call) {"
      "  var x = 0, y = 1;"
      "  for (var i = 0; i < 1000; i++) {"
      "    x += i * 100;"
      "    y += i * 100;"
      "  }"
      "  if (call) g();"
      "}"
      "for (var i = 0; i < 17; i++) wrapper(false);"
      "var thrown = 0;"
      "try { wrapper(true); } catch (e) { thrown = 1; };"
      "thrown";

  {
    LocalContext env(nullptr, instance_template);
    // Hold on to the global object so it can be used again in another
    // environment initialization.
    global_object = env->Global();

    Local<Value> value = CompileRun("x");
    CHECK_EQ(42, value->Int32Value(env.local()).FromJust());
    value = CompileRun("f()");
    CHECK_EQ(12, value->Int32Value(env.local()).FromJust());
    value = CompileRun(script);
    CHECK_EQ(1, value->Int32Value(env.local()).FromJust());
  }

  {
    // Create new environment reusing the global object.
    LocalContext env(nullptr, instance_template, global_object);
    Local<Value> value = CompileRun("x");
    CHECK_EQ(42, value->Int32Value(env.local()).FromJust());
    value = CompileRun("f()");
    CHECK_EQ(12, value->Int32Value(env.local()).FromJust());
    value = CompileRun(script);
    CHECK_EQ(1, value->Int32Value(env.local()).FromJust());
  }
}

THREADED_TEST(ObjectGetOwnPropertyNames) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope handle_scope(isolate);

  v8::Local<v8::Object> value = v8::Local<v8::Object>::Cast(
      v8::StringObject::New(CcTest::isolate(), v8_str("test")));
  v8::Local<v8::Array> properties;

  CHECK(value
            ->GetOwnPropertyNames(context.local(),
                                  static_cast<v8::PropertyFilter>(
                                      v8::PropertyFilter::ALL_PROPERTIES |
                                      v8::PropertyFilter::SKIP_SYMBOLS),
                                  v8::KeyConversionMode::kKeepNumbers)
            .ToLocal(&properties));
  CHECK_EQ(5u, properties->Length());
  v8::Local<v8::Value> property;
  CHECK(properties->Get(context.local(), 4).ToLocal(&property) &&
        property->IsString());
  CHECK(property.As<v8::String>()
            ->Equals(context.local(), v8_str("length"))
            .FromMaybe(false));
  for (int i = 0; i < 4; ++i) {
    CHECK(properties->Get(context.local(), i).ToLocal(&property) &&
          property->IsInt32());
    CHECK_EQ(property.As<v8::Int32>()->Value(), i);
  }

  CHECK(value
            ->GetOwnPropertyNames(context.local(),
                                  v8::PropertyFilter::ONLY_ENUMERABLE,
                                  v8::KeyConversionMode::kKeepNumbers)
            .ToLocal(&properties));
  v8::Local<v8::Array> number_properties;
  CHECK(value
            ->GetOwnPropertyNames(context.local(),
                                  v8::PropertyFilter::ONLY_ENUMERABLE,
                                  v8::KeyConversionMode::kConvertToString)
            .ToLocal(&number_properties));
  CHECK_EQ(4u, properties->Length());
  for (int i = 0; i < 4; ++i) {
    v8::Local<v8::Value> property_index;
    v8::Local<v8::Value> property_name;

    CHECK(number_properties->Get(context.local(), i).ToLocal(&property_name));
    CHECK(property_name->IsString());

    CHECK(properties->Get(context.local(), i).ToLocal(&property_index));
    CHECK(property_index->IsInt32());

    CHECK_EQ(property_index.As<v8::Int32>()->Value(), i);
    CHECK_EQ(property_name->ToNumber(context.local())
                 .ToLocalChecked()
                 .As<v8::Int32>()
                 ->Value(),
             i);
  }

  value = value->GetPrototypeV2().As<v8::Object>();
  CHECK(value
            ->GetOwnPropertyNames(context.local(),
                                  static_cast<v8::PropertyFilter>(
                                      v8::PropertyFilter::ALL_PROPERTIES |
                                      v8::PropertyFilter::SKIP_SYMBOLS))
            .ToLocal(&properties));
  bool concat_found = false;
  bool starts_with_found = false;
  for (uint32_t i = 0; i < properties->Length(); ++i) {
    CHECK(properties->Get(context.local(), i).ToLocal(&property));
    if (!property->IsString()) continue;
    if (!concat_found)
      concat_found = property.As<v8::String>()
                         ->Equals(context.local(), v8_str("concat"))
                         .FromMaybe(false);
    if (!starts_with_found)
      starts_with_found = property.As<v8::String>()
                              ->Equals(context.local(), v8_str("startsWith"))
                              .FromMaybe(false);
  }
  CHECK(concat_found && starts_with_found);
}

THREADED_TEST(CallKnownGlobalReceiver) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope handle_scope(isolate);

  Local<Value> global_object;

  Local<v8::FunctionTemplate> t = v8::FunctionTemplate::New(isolate);
  Local<ObjectTemplate> instance_template = t->InstanceTemplate();

  // The script to check that we leave global object not
  // global object proxy on stack when we deoptimize from inside
  // arguments evaluation.
  // To provoke error we need to both force deoptimization
  // from arguments evaluation and to force CallIC to take
  // CallIC_Miss code path that can't cope with global proxy.
  const char* script =
      "function bar(x, y) { try { } finally { } }"
      "function baz(x) { try { } finally { } }"
      "function bom(x) { try { } finally { } }"
      "function foo(x) { bar([x], bom(2)); }"
      "for (var i = 0; i < 10000; i++) foo(1);"
      "foo";

  Local<Value> foo;
  {
    LocalContext env(nullptr, instance_template);
    // Hold on to the global object so it can be used again in another
    // environment initialization.
    global_object = env->Global();
    foo = CompileRun(script);
  }

  {
    // Create new environment reusing the global object.
    LocalContext env(nullptr, instance_template, global_object);
    CHECK(env->Global()->Set(env.local(), v8_str("foo"), foo).FromJust());
    CompileRun("foo()");
  }
}

namespace {
void ShadowFunctionCallback(const v8::FunctionCallbackInfo<v8::Value>& args) {
  ApiTestFuzzer::Fuzz();
  args.GetReturnValue().Set(v8_num(42));
}

int shadow_y;
int shadow_y_setter_call_count;
int shadow_y_getter_call_count;

void ShadowYSetter(Local<Name>, Local<Value>,
                   const v8::PropertyCallbackInfo<void>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  shadow_y_setter_call_count++;
  shadow_y = 42;
}

void ShadowYGetter(Local<Name> name,
                   const v8::PropertyCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  ApiTestFuzzer::Fuzz();
  shadow_y_getter_call_count++;
  info.GetReturnValue().Set(v8_num(shadow_y));
}

v8::Intercepted ShadowIndexedGet(
    uint32_t index, const v8::PropertyCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  return v8::Intercepted::kNo;
}

v8::Intercepted ShadowNamedGet(
    Local<Name> key, const v8::PropertyCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  return v8::Intercepted::kNo;
}
}  // namespace

THREADED_TEST(ShadowObject) {
  shadow_y = shadow_y_setter_call_count = shadow_y_getter_call_count = 0;
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope handle_scope(isolate);

  Local<ObjectTemplate> global_template = v8::ObjectTemplate::New(isolate);
  LocalContext context(nullptr, global_template);

  Local<v8::FunctionTemplate> t = v8::FunctionTemplate::New(isolate);
  t->InstanceTemplate()->SetHandler(
      v8::NamedPropertyHandlerConfiguration(ShadowNamedGet));
  t->InstanceTemplate()->SetHandler(
      v8::IndexedPropertyHandlerConfiguration(ShadowIndexedGet));
  Local<ObjectTemplate> proto = t->PrototypeTemplate();
  Local<ObjectTemplate> instance = t->InstanceTemplate();

  proto->Set(isolate, "f",
             v8::FunctionTemplate::New(isolate, ShadowFunctionCallback,
                                       Local<Value>()));
  proto->Set(isolate, "x", v8_num(12));

  instance->SetNativeDataProperty(v8_str("y"), ShadowYGetter, ShadowYSetter);

  Local<Value> o = t->GetFunction(context.local())
                       .ToLocalChecked()
                       ->NewInst
"""


```