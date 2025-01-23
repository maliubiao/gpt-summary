Response:
Let's break down the thought process for analyzing the provided C++ code.

**1. Initial Understanding: What is the Goal?**

The first step is always to get a high-level idea of what the code is trying to achieve. The file name `test-api-incumbent.cc` strongly suggests it's testing the "incumbent context" API within V8. The comments in the code reinforce this: "This callback checks that the incumbent context equals to the expected one..." and the description of `SetupCrossContextTest`. Therefore, the core goal is to verify that V8 correctly tracks and returns the appropriate incumbent context during cross-context calls.

**2. Examining Key Components:**

Once the general goal is understood, we can delve into the specific parts of the code:

* **Includes:**  The includes provide clues about the functionality. We see `v8-function-callback.h`, `v8-function.h`, and core V8 headers, confirming we're dealing with V8's C++ API. The presence of `"test/cctest/cctest.h"` indicates this is a unit test within the V8 project.

* **Namespaces and Usings:** These simplify the code and tell us what V8 API elements are being used directly (like `v8::Context`, `v8::Isolate`, etc.).

* **`EmptyHandler`:** A simple callback function. It likely exists for basic testing or as a placeholder. The `ApiTestFuzzer::Fuzz()` suggests involvement in some form of testing or security hardening.

* **`IncumbentTestExpectations`:** This `struct` is crucial. It clearly defines what the tests are trying to verify: the expected `incumbent_context` and `function_context`, and a counter for the number of calls.

* **`FunctionWithIncumbentCheck`:** This is the heart of the test logic. It's a callback function that performs the core assertions:
    * Verifies the callback info.
    * Increments a counter.
    * Retrieves the current context and the incumbent context.
    * **Crucially, compares them to the `expected` values.**
    * Handles both regular calls and constructor calls.

* **`SetupCrossContextTest`:** This function is complex but essential. Its purpose is to create multiple isolated V8 contexts and set them up for cross-context calls. Key aspects:
    * Creates `n` contexts.
    * Sets security tokens to allow cross-domain access.
    * Sets an `id` property on `Object.prototype` in each context (for easy identification).
    * Creates helper JavaScript functions (`call0`, `call1`, etc.) within each context to facilitate calling between contexts.
    * **Optimizes these helper functions to different compilation tiers (Ignition, Sparkplug, Maglev, TurboFan).** This is a significant point – the tests aim to verify incumbent context behavior across different optimization levels.
    * Creates the core function `f` (using `FunctionWithIncumbentCheck`) in each context. This `f` function is the one that does the incumbent context checking.

* **`Run`:** A simple helper function to execute JavaScript code within the current context.

* **`IncumbentContextTest_Api` and `IncumbentContextTest_ApiWithIncumbent`:** These test cases demonstrate setting the incumbent context explicitly using `Context::BackupIncumbentScope`.

* **Other `THREADED_TEST` functions:** These tests (`IncumbentContextTest_Basic1`, `_Basic2`, `_WithBuiltins3`, `_WithBuiltins4`) set up scenarios where cross-context calls occur *without* explicitly setting the incumbent context via the API. They use the helper functions created in `SetupCrossContextTest` to orchestrate these calls.

**3. Inferring Functionality and Relationships:**

Based on the components, we can infer the following:

* The code tests the correctness of V8's `Isolate::GetIncumbentContext()` API.
* It does this by creating multiple V8 contexts and making calls between them.
* It verifies that when a function is called from a different context, `GetIncumbentContext()` returns the context where the call originated.
* The tests cover scenarios with and without explicitly setting the incumbent context using `Context::BackupIncumbentScope`.
* The tests also consider the impact of different levels of JavaScript optimization on incumbent context tracking.

**4. Addressing Specific Questions in the Prompt:**

Now, we can systematically answer the questions in the prompt:

* **Functionality:**  List the key functions and their roles as described above.

* **`.tq` Extension:**  The code is C++, so it's not a Torque file.

* **Relationship to JavaScript:** The code heavily relates to JavaScript. It creates JavaScript contexts, defines JavaScript functions, and executes JavaScript code to trigger cross-context calls. The `FunctionWithIncumbentCheck` is called from JavaScript.

* **JavaScript Examples:**  Provide concrete JavaScript examples that would trigger the scenarios tested in the C++ code (cross-context calls).

* **Code Logic Reasoning (Hypothetical Inputs and Outputs):** Focus on the `FunctionWithIncumbentCheck` function. Describe how the `expected` struct is set up and how the assertions within the callback function work. Provide examples of how the `expected` values would be set for different test cases.

* **Common Programming Errors:** Think about what mistakes developers might make when dealing with V8 contexts and callbacks, such as assuming the current context is always the same or not understanding how incumbent contexts work.

**5. Refinement and Organization:**

Finally, organize the information logically and clearly, using headings, bullet points, and code examples to make the explanation easy to understand. Ensure that the language is precise and avoids jargon where possible, or explains it when necessary. For instance, explaining what "incumbent context" means in the V8 context.

This systematic approach, starting with the high-level goal and then breaking down the code into its components, allows for a thorough understanding and accurate explanation of the provided V8 test code.
这个C++源代码文件 `v8/test/cctest/test-api-incumbent.cc` 的主要功能是 **测试 V8 API 中关于“incumbent context”（现任上下文）的功能**。

**功能详细解释:**

1. **测试 `Isolate::GetIncumbentContext()`:**  该文件通过一系列测试用例，验证 V8 引擎在执行 JavaScript 代码时，能否正确地跟踪和返回当前的现任上下文。现任上下文指的是发起当前调用的那个上下文。

2. **跨上下文调用测试:**  代码设置了多个独立的 V8 上下文 (Context)，并在这些上下文之间进行函数调用。这是测试现任上下文的关键，因为当一个上下文中的函数调用另一个上下文的函数时，现任上下文会发生变化。

3. **不同调用方式测试:**  测试涵盖了多种 JavaScript 函数调用方式，例如直接调用、使用 `call`、`apply`、`Reflect.apply`、展开运算符等，以及构造函数调用。这确保了现任上下文功能在各种调用场景下都能正常工作。

4. **不同优化级别测试:**  代码利用 V8 的内部机制 (`%CompileBaseline`, `%OptimizeMaglevOnNextCall`, `%OptimizeFunctionOnNextCall`) 将 JavaScript 函数编译到不同的优化级别 (Ignition, Sparkplug, Maglev, TurboFan)。这旨在验证现任上下文功能在不同编译器优化级别下的一致性。

5. **显式设置现任上下文测试:**  `IncumbentContextTest_ApiWithIncumbent` 测试用例使用了 `Context::BackupIncumbentScope` 来显式地设置现任上下文，然后进行调用，验证 API 是否按预期工作。

**关于文件扩展名 `.tq`:**

`v8/test/cctest/test-api-incumbent.cc` 的扩展名是 `.cc`，表示它是一个 **C++ 源代码文件**。如果文件名以 `.tq` 结尾，那么它才是一个 **V8 Torque 源代码文件**。 Torque 是一种 V8 内部使用的领域特定语言，用于编写内置函数。

**与 JavaScript 的关系及示例:**

此 C++ 文件通过 V8 的 C++ API 与 JavaScript 功能紧密相关。它创建和操作 V8 上下文，并在这些上下文中执行 JavaScript 代码来触发和测试现任上下文的行为。

**JavaScript 示例:**

假设我们有两个上下文 `context1` 和 `context2`，它们在 C++ 代码中被创建。

```javascript
// 在 context1 中定义一个函数
function functionInContext1() {
  console.log("执行在 context1");
  return globalThis.id; // 返回当前上下文的 id
}

// 在 context2 中定义一个函数，调用 context1 的函数
function functionInContext2(func) {
  console.log("执行在 context2");
  return func(); // 调用 context1 的函数
}

// 假设 'realm1.f' 指向 context1 中定义的 'functionInContext1'
// 假设 'realm2.call1' 指向 context2 中定义的 'functionInContext2'

// 在某个上下文中执行以下代码，例如在 C++ 测试用例中：
realm2.call1(realm1.f);
```

在这个例子中，当 `realm2.call1(realm1.f)` 被执行时：

1. 当前执行的上下文是 `context2`。
2. `functionInContext2` 被调用。
3. 在 `functionInContext2` 内部，`func()` (实际上是 `functionInContext1`) 被调用。
4. 当 `functionInContext1` 执行时，**现任上下文应该是 `context2`**，因为 `functionInContext2` 是发起这次调用的上下文。
5. `globalThis.id` 在 `functionInContext1` 中被访问，它会返回 `context1` 的 id。但是，`Isolate::GetIncumbentContext()` 在 `FunctionWithIncumbentCheck` 中被调用时，应该返回 `context2`。

**代码逻辑推理 (假设输入与输出):**

假设在 `IncumbentContextTest_Basic1` 中，当循环到 `i = 1` 时，当前的上下文是 `contexts[1]`。 执行 `Run("realm0.f()")`：

* **假设输入:**
    * 当前上下文: `contexts[1]` (id 为 1)
    * 调用的函数: `realm0.f` (在 `contexts[0]` 中定义)
    * `expected` 在此次调用前被设置为 `expected.incumbent_context = contexts[1]` 和 `expected.function_context = contexts[0]`。

* **代码执行流程:**
    1. `realm0.f()` 在 `contexts[1]` 中被调用。
    2. V8 切换到 `contexts[0]` 来执行 `realm0.f` 函数。
    3. 在 `FunctionWithIncumbentCheck` 回调函数中：
        * `info.GetIsolate()->GetCurrentContext()` 将返回 `contexts[0]`.
        * `info.GetIsolate()->GetIncumbentContext()` 将返回 `contexts[1]`.
        * 代码会检查 `expected->function_context == contexts[0]` (应该为真) 和 `expected->incumbent_context == contexts[1]` (应该为真)。
        * `expected->call_count` 会增加。
    4. `realm0.f` 函数返回 `contexts[0]` 的 `id` (即 0)。

* **预期输出 (断言结果):**  `CHECK_EQ(expected->function_context, context)` 和 `CHECK_EQ(expected->incumbent_context, isolate->GetIncumbentContext())` 这两个断言都会成功。

**用户常见的编程错误:**

1. **混淆当前上下文和现任上下文:**  开发者可能会错误地认为在回调函数中 `info.GetIsolate()->GetCurrentContext()` 总是返回发起调用的上下文。但实际上，它返回的是当前正在执行代码的上下文。理解现任上下文的概念对于处理跨上下文调用至关重要。

   **错误示例 (JavaScript):**

   ```javascript
   // context1
   function callMe(callback) {
     console.log("callMe 执行时的全局 id:", globalThis.id); // 输出 context1 的 id
     callback();
   }

   // context2
   function myCallback() {
     console.log("myCallback 执行时的全局 id:", globalThis.id); // 输出 context2 的 id
     // 错误地假设现任上下文是 context1
   }

   // 在 context1 中调用
   callMe(realm2.myCallback); // 假设 realm2.myCallback 指向 context2 的 myCallback
   ```

   在这个例子中，当 `myCallback` 执行时，当前的全局对象是 `context2` 的全局对象，而不是 `context1` 的。

2. **在错误的上下文中使用对象或函数:**  在跨上下文调用中，如果开发者没有正确理解上下文的边界，可能会尝试在一个上下文中访问另一个上下文的私有对象或函数，导致错误。

   **错误示例 (JavaScript):**

   ```javascript
   // context1
   let privateData = "secret";
   function getPrivateData() {
     return privateData;
   }

   // context2
   function attemptAccess(getter) {
     console.log(getter()); // 可能会出错，如果 getter 不是设计为跨上下文访问
   }

   // 在 context2 中调用，尝试访问 context1 的数据
   realm2.attemptAccess(realm1.getPrivateData); // 假设 realm1.getPrivateData 指向 context1 的 getPrivateData
   ```

   这种情况下，如果 V8 没有正确设置或者允许跨上下文访问，`getter()` 的执行可能会失败，或者访问到的 `globalThis` 会是错误的。

`v8/test/cctest/test-api-incumbent.cc` 的主要目标就是确保 V8 引擎能够正确处理这些跨上下文调用的场景，并为开发者提供可靠的 `GetIncumbentContext()` API，以便他们能够编写出正确的跨上下文交互代码。

### 提示词
```
这是目录为v8/test/cctest/test-api-incumbent.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-api-incumbent.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2023 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <optional>

#include "include/v8-function-callback.h"
#include "include/v8-function.h"
#include "src/base/strings.h"
#include "test/cctest/cctest.h"

using ::v8::Context;
using ::v8::External;
using ::v8::Function;
using ::v8::FunctionTemplate;
using ::v8::HandleScope;
using ::v8::Integer;
using ::v8::Isolate;
using ::v8::Local;
using ::v8::MaybeLocal;
using ::v8::Object;
using ::v8::String;
using ::v8::Value;

namespace {

void EmptyHandler(const v8::FunctionCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  ApiTestFuzzer::Fuzz();
}

struct IncumbentTestExpectations {
  Local<Context> incumbent_context;
  Local<Context> function_context;
  int call_count = 0;
};

// This callback checks that the incumbent context equals to the expected one
// and returns the function's context ID (i.e. "globalThis.id").
void FunctionWithIncumbentCheck(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  ApiTestFuzzer::Fuzz();

  IncumbentTestExpectations* expected =
      reinterpret_cast<IncumbentTestExpectations*>(
          info.Data().As<External>()->Value());

  expected->call_count++;

  Isolate* isolate = info.GetIsolate();
  Local<Context> context = isolate->GetCurrentContext();
  CHECK_EQ(expected->function_context, context);
  CHECK_EQ(expected->incumbent_context, isolate->GetIncumbentContext());

  if (info.IsConstructCall()) {
    MaybeLocal<Object> instance = Function::New(context, EmptyHandler)
                                      .ToLocalChecked()
                                      ->NewInstance(context, 0, nullptr);
    info.GetReturnValue().Set(instance.ToLocalChecked());
  } else {
    Local<Value> value =
        context->Global()->Get(context, v8_str("id")).ToLocalChecked();
    info.GetReturnValue().Set(value);
  }
}

// Creates test contexts in the folloing way:
// 1) Each context can access other contexts,
// 2) Each context is equipped with various user-level function that call
//    other functions provided as an argument,
// 3) The helper functions in i-th context are optimized to i-th level:
//    Ignition, Sparkplug, Maglev, TurboFan.
// 4) Each callee function is supposed to be monomorphic in each testing
//    scenario so that the optimizing compiler could inling the callee.
// 5) Each context gets an Api function "f" which checks current context
//    and incumbent context against expected ones. The function can be called
//    as a constructor.
// 6) The tests should setup a call chain in such a way that function "f" is
//    called from each context, thus we can test that GetIncumbentContext
//    works correctly for each compiler.
v8::LocalVector<Context> SetupCrossContextTest(
    Isolate* isolate, IncumbentTestExpectations* expected) {
  const int n = 4;  // Ignition, Sparkplug, Maglev, TurboFan.

  i::v8_flags.allow_natives_syntax = true;
#if V8_ENABLE_SPARKPLUG
  i::v8_flags.baseline_batch_compilation = false;
#endif

  v8::LocalVector<Context> contexts(isolate);

  Local<String> token = v8_str("<security token>");

  for (int i = 0; i < n; i++) {
    Local<Context> context = Context::New(isolate);
    contexts.push_back(context);

    // Allow cross-domain access.
    context->SetSecurityToken(token);

    // Set 'id' property on the Object.prototype in each realm.
    {
      Context::Scope context_scope(context);

      v8::base::ScopedVector<char> src(30);
      v8::base::SNPrintF(src, "Object.prototype.id = %d", i);
      CompileRun(src.begin());
    }
  }

  Local<External> expected_incumbent_context_ptr =
      External::New(isolate, expected);

  // Create cross-realm references in every realm's global object and
  // a constructor function that also checks the incumbent context.
  for (int i = 0; i < n; i++) {
    Local<Context> context = contexts[i];
    Context::Scope context_scope(context);

    // Add "realmX" properties referencing contextX->global.
    for (int j = 0; j < n; j++) {
      Local<Context> another_context = contexts[j];
      v8::base::ScopedVector<char> name(30);
      v8::base::SNPrintF(name, "realm%d", j);

      CHECK(context->Global()
                ->Set(context, v8_str(name.begin()), another_context->Global())
                .FromJust());

      // Check that 'id' property matches the realm index.
      v8::base::ScopedVector<char> src(30);
      v8::base::SNPrintF(src, "realm%d.id", j);
      Local<Value> value = CompileRun(src.begin());
      CHECK_EQ(j, value.As<Integer>()->Value());
    }

    // Create some helper functions so we can chain calls:
    //   call2(call1, call0, f)
    //   call2(call1, construct0, f)
    //   ...
    // and tier them up to the i-th level.
    CompileRun(R"JS(
        // This funcs set is used for collecting the names of the helper
        // functions defined below. We have to query the property names
        // in a separate script because otherwise the function definitions
        // would be hoisted above and it wouldn't be possible to compute the
        // diff of properties set before and after the functions are defined.
        var funcs = Object.getOwnPropertyNames(globalThis);
    )JS");

    CompileRun(R"JS(
        function call_spread(g, ...args) { return g(...args); }
        function call_via_apply(g, args_array) {
          return g.apply(undefined, args_array);
        }
        function call_via_reflect(g, args_array) {
          return Reflect.apply(g, undefined, args_array);
        }
        function construct_spread(g, ...args) { return new g(...args); }
        function construct_via_reflect(g, args_array) {
          return Reflect.construct(g, args_array);
        }

        function call0(g) { return g(); }
        function call0_via_call(g, self) { return g.call(self); }

        function construct0(g) { return new g(); }

        function call1(f, arg) { return f(arg); }
        function call1_via_call(g, self, arg) { return g.call(self, arg); }

        function call2(f, arg1, arg2) { return f(arg1, arg2); }
        function call2_via_call(g, self, arg1, arg2) {
          return g.call(self, arg1, arg2);
        }

        // Get only names of the functions added above.
        funcs = (Object.getOwnPropertyNames(globalThis).filter(
          (name) => { return !funcs.includes(name); }
        ));
        if (funcs.length == 0) {
          // Sanity check that the script is not broken.
          %SystemBreak();
        }
        // Convert names to functions.
        funcs = funcs.map((name) => globalThis[name]);

        // Compile them according to current context's level ('id' value).
        if (id > 0) {
          console.log("=== #"+id);
          if (id == 1 && %IsSparkplugEnabled()) {
            funcs.forEach((f) => {
              %CompileBaseline(f);
            });
          } else if (id == 2 && %IsMaglevEnabled()) {
            funcs.forEach((f) => {
              %PrepareFunctionForOptimization(f);
              %OptimizeMaglevOnNextCall(f);
            });
          } else if (id == 3 && %IsTurbofanEnabled()) {
            funcs.forEach((f) => {
              %PrepareFunctionForOptimization(f);
              %OptimizeFunctionOnNextCall(f);
            });
          }
        }
    )JS");

    Local<Function> func = Function::New(context, FunctionWithIncumbentCheck,
                                         expected_incumbent_context_ptr)
                               .ToLocalChecked();

    v8::base::ScopedVector<char> name(30);
    v8::base::SNPrintF(name, "realm%d.f", static_cast<int>(i));
    func->SetName(v8_str(name.begin()));

    CHECK(context->Global()->Set(context, v8_str("f"), func).FromJust());
  }
  return contexts;
}

void Run(const char* source) { CHECK(!CompileRun(source).IsEmpty()); }

void IncumbentContextTest_Api(bool with_api_incumbent) {
  Isolate* isolate = CcTest::isolate();
  HandleScope scope(isolate);

  IncumbentTestExpectations expected;
  auto contexts = SetupCrossContextTest(isolate, &expected);
  const int n = static_cast<int>(contexts.size());

  // Check calls and construct calls using various sequences of context to
  // context switches.
  for (int i = 0; i < n; i++) {
    Local<Context> context = contexts[i];
    Context::Scope context_scope(context);

    Local<Context> context0 = contexts[0];
    Local<Context> context2 = contexts[2];

    std::optional<Context::BackupIncumbentScope> incumbent_scope;

    if (with_api_incumbent) {
      // context -> set incumbent (context2) -> context0.
      incumbent_scope.emplace(context2);
      expected.incumbent_context = context2;
      expected.function_context = context0;
    } else {
      // context -> context0.
      expected.incumbent_context = context;
      expected.function_context = context0;
    }

    // realm0.f()
    Local<Function> realm0_f = context0->Global()
                                   ->Get(context, v8_str("f"))
                                   .ToLocalChecked()
                                   .As<Function>();
    realm0_f->Call(context, Undefined(isolate), 0, nullptr).ToLocalChecked();

    // new realm0.f()
    realm0_f->NewInstance(context).ToLocalChecked();
  }
  CHECK_LT(0, expected.call_count);
}

}  // namespace

THREADED_TEST(IncumbentContextTest_Api) { IncumbentContextTest_Api(false); }

THREADED_TEST(IncumbentContextTest_ApiWithIncumbent) {
  IncumbentContextTest_Api(true);
}

THREADED_TEST(IncumbentContextTest_Basic1) {
  Isolate* isolate = CcTest::isolate();
  HandleScope scope(isolate);

  IncumbentTestExpectations expected;
  auto contexts = SetupCrossContextTest(isolate, &expected);
  const int n = static_cast<int>(contexts.size());

  // Check calls and construct calls using various sequences of context to
  // context switches.
  for (int i = 0; i < n; i++) {
    Local<Context> context = contexts[i];
    Context::Scope context_scope(context);

    // context -> context0.
    expected.incumbent_context = context;
    expected.function_context = contexts[0];

    Run("realm0.f()");
    Run("realm0.f.call(realm0)");
    Run("realm0.f.apply(realm0)");
    Run("Reflect.apply(realm0.f, undefined, [])");
    Run("call_spread(realm0.f)");

    Run("new realm0.f()");
  }
  CHECK_LT(0, expected.call_count);
}

THREADED_TEST(IncumbentContextTest_Basic2) {
  Isolate* isolate = CcTest::isolate();
  HandleScope scope(isolate);

  IncumbentTestExpectations expected;
  auto contexts = SetupCrossContextTest(isolate, &expected);
  const int n = static_cast<int>(contexts.size());

  // Check calls and construct calls using various sequences of context to
  // context switches.
  for (int i = 0; i < n; i++) {
    Local<Context> context = contexts[i];
    Context::Scope context_scope(context);

    // context -> context -> context0.
    expected.incumbent_context = context;
    expected.function_context = contexts[0];

    Run("call0(realm0.f)");
    Run("call0_via_call(realm0.f, realm0)");
    Run("call_via_apply(realm0.f, [realm0])");
    Run("call_via_reflect(realm0.f, [realm0])");
    Run("call_spread(realm0.f, /* args */ 1, 2, 3)");

    Run("construct0(realm0.f)");
    Run("Reflect.construct(realm0.f, [])");
    Run("construct_spread(realm0.f, /* args */ 1, 2, 3)");
  }
  CHECK_LT(0, expected.call_count);
}

THREADED_TEST(IncumbentContextTest_WithBuiltins3) {
  Isolate* isolate = CcTest::isolate();
  HandleScope scope(isolate);

  IncumbentTestExpectations expected;
  auto contexts = SetupCrossContextTest(isolate, &expected);
  const int n = static_cast<int>(contexts.size());

  // Check calls and construct calls using various sequences of context to
  // context switches.
  for (int i = 0; i < n; i++) {
    Local<Context> context = contexts[i];
    Context::Scope context_scope(context);

    // context -> context2 -> context1 -> context.
    expected.incumbent_context = contexts[1];
    expected.function_context = context;

    Run("realm2.call1(realm1.call0, f)");
    Run("realm2.call1_via_call(realm1.call0, realm1, f)");
    Run("realm2.call_via_apply(realm1.call0, [f])");
    Run("realm2.call_via_reflect(realm1.call0, [f])");
    Run("realm2.call_spread(realm1.call_spread, f, 1, 2, 3)");

    Run("realm2.call1(realm1.construct0, f)");
    Run("realm2.call_spread(realm1.construct_via_reflect, f, [1, 2, 3])");
    Run("realm2.call_spread(realm1.construct_spread, f, 1, 2, 3)");
  }
  CHECK_LT(0, expected.call_count);
}

THREADED_TEST(IncumbentContextTest_WithBuiltins4) {
  Isolate* isolate = CcTest::isolate();
  HandleScope scope(isolate);

  IncumbentTestExpectations expected;
  auto contexts = SetupCrossContextTest(isolate, &expected);
  const int n = static_cast<int>(contexts.size());

  // Check calls and construct calls using various sequences of context to
  // context switches.
  for (int i = 0; i < n; i++) {
    Local<Context> context = contexts[i];
    Context::Scope context_scope(context);

    // context -> context0 -> context -> context1.
    expected.incumbent_context = context;
    expected.function_context = contexts[1];

    Run("realm0.call1(call0, realm1.f)");
    Run("realm0.call1_via_call(call0, undefined, realm1.f)");
    Run("realm0.call_via_apply(call0, [realm1.f])");
    Run("realm0.call_via_reflect(call0, [realm1.f])");
    Run("realm0.call_spread(call_spread, realm1.f, 1, 2, 3)");

    Run("realm0.call1(construct0, realm1.f)");
    Run("realm0.call_spread(construct_via_reflect, realm1.f, [1, 2])");
    Run("realm0.call_spread(construct_spread, realm1.f, 1, 2)");
  }
  CHECK_LT(0, expected.call_count);
}
```