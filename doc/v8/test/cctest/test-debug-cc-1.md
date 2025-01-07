Response:
The user wants a summary of the functionality of the provided C++ code snippet.
The code snippet is part of the V8 JavaScript engine's test suite, specifically for debugging features.
It focuses on testing breakpoints in various scenarios.

Here's a breakdown of the functionality:

1. **Setting breakpoints on built-in functions:** Tests if breakpoints can be set on native JavaScript functions like `String.prototype.indexOf` and `String.prototype.repeat`.
2. **Breakpoints in different contexts:** Verifies that breakpoints set in one context are triggered when the built-in function is called from a new context.
3. **Breakpoints on API functions:** Tests breakpoints on functions defined using the V8 C++ API. This includes regular function calls, constructor calls, and calls through getters and setters.
4. **Breakpoints on accessors:** Checks if breakpoints work correctly on getter and setter functions defined using `Object.defineProperty`.
5. **Breakpoints and optimization:**  Confirms that breakpoints are hit even when functions are optimized by V8.
6. **Conditional breakpoints:**  Tests breakpoints with conditions that need to evaluate to true for the breakpoint to be triggered.
7. **Breakpoints and inlining:** Verifies that breakpoints set in inlined functions are hit correctly.
8. **Breakpoints and garbage collection:**  Ensures that breakpoints remain active even after garbage collection cycles.
9. **Debugger statement:** Tests the functionality of the `debugger` statement in JavaScript, which triggers a breakpoint.
10. **Stepping:** Tests the basic stepping functionality of the debugger, where the execution pauses at each step.

Based on these observations, I can summarize the functionality.
这是 `v8/test/cctest/test-debug.cc` 源代码的第 2 部分，主要功能是测试 V8 JavaScript 引擎的调试功能，特别是断点 (Breakpoint) 的设置和触发在各种场景下的行为。

以下是该部分代码的具体功能归纳：

1. **测试在内置函数上设置断点：**
   - 验证可以在内置的 JavaScript 函数上设置断点，例如 `String.prototype.repeat` 和 `String.prototype.indexOf`。
   - 测试了在函数被优化后断点是否仍然有效。
   - 测试了在新的 JavaScript 上下文中调用带有断点的内置函数是否能触发断点。

   **JavaScript 示例:**
   ```javascript
   // 假设在 String.prototype.repeat 上设置了断点
   'a'.repeat(5); // 执行到这里会触发断点
   ```

2. **测试在通过 C++ API 创建的函数上设置断点：**
   - 验证可以在通过 V8 C++ API (`v8::FunctionTemplate`) 创建的函数上设置断点。
   - 测试了在 API 函数作为普通函数调用、作为构造函数调用、以及作为 getter 和 setter 被调用时，断点的触发情况。
   - 特别测试了通过 C++ API 直接调用函数是否会触发断点（预期不会）。

   **JavaScript 示例:**
   ```javascript
   // 假设通过 API 创建了一个名为 f 的函数
   function f() { return 2; }
   // 假设在 f 上设置了断点
   f(); // 执行到这里会触发断点
   new f(); // 执行到这里也会触发断点 (作为构造函数)

   var obj = { get prop() { return f(); } };
   obj.prop; // 执行到这里会触发断点 (作为 getter)

   var obj2 = { set prop(value) { f(); } };
   obj2.prop = 3; // 执行到这里会触发断点 (作为 setter)
   ```

3. **测试在访问器属性上设置断点：**
   - 验证可以在对象属性的 getter 和 setter 函数上设置断点。
   - 测试了在循环中访问带有断点的访问器属性时的触发次数。
   - 测试了在新的对象上创建相同的访问器属性，断点是否仍然有效。

   **JavaScript 示例:**
   ```javascript
   var o = {
       get prop() {
           // 假设这里设置了断点
           return 1;
       },
       set prop(value) {
           // 假设这里设置了断点
       }
   };
   o.prop; // 触发 getter 断点
   o.prop = 5; // 触发 setter 断点
   ```

4. **回归测试：**
   - 包含了一个针对特定 bug (Regress1163547) 的回归测试，该 bug 涉及到在原型对象上设置的访问器属性的断点。

5. **测试惰性访问器上的断点：**
   - 验证在惰性创建的访问器属性上设置的断点，在创建新的 JavaScript 上下文后是否仍然能被触发。

6. **测试内联 API 函数上的断点：**
   - 验证当一个调用了 API 函数的 JavaScript 函数被内联优化后，API 函数上的断点是否仍然可以触发。

   **假设输入与输出:**
   假设有一个 API 函数 `f` 和一个调用 `f` 的 JavaScript 函数 `g`。如果在 `f` 上设置了断点，并且 `g` 被内联优化，那么当调用 `g` 时，会触发 `f` 上的断点。

7. **测试带条件的断点：**
   - 验证可以设置带有条件的断点，只有当条件满足时断点才会被触发。
   - 测试了条件可以访问全局变量、函数参数 (`arguments`)、rest 参数，以及 `this` 指针。

   **JavaScript 示例:**
   ```javascript
   function myFunc(x) {
       // 假设在这行设置了断点，条件是 x > 5
       return x * 2;
   }
   myFunc(3); // 不会触发断点
   myFunc(7); // 会触发断点
   ```

8. **测试内联函数上的断点：**
   - 验证可以在被内联的 JavaScript 函数上设置断点，并且在调用包含该内联函数的函数时，断点会被触发。

9. **测试垃圾回收期间断点的保留：**
   - 测试了在断点激活期间进行垃圾回收 (GC) 操作，断点是否仍然有效并能被触发。
   - 涵盖了不同类型的垃圾回收，如 Scavenge 和 Mark-Sweep。

10. **测试 `debugger` 语句：**
    - 验证 JavaScript 代码中的 `debugger` 语句会触发断点。
    - 测试了在 `debugger` 语句上设置断点的行为。

    **JavaScript 示例:**
    ```javascript
    function myFunc() {
        debugger; // 执行到这里会触发断点
        console.log("after debugger");
    }
    myFunc();
    ```

11. **测试在禁止代码生成的环境下条件断点：**
    - 验证即使在禁止通过字符串生成代码的环境下（例如，使用 `eval` 或 `Function` 构造函数），条件断点仍然可以正常工作。

12. **测试单步调试：**
    - 测试了基本的单步调试功能，通过 `StepInto` 操作，程序会逐行执行，并在每个断点位置暂停。

**总结:**

这部分代码主要集中在测试 V8 引擎中各种断点功能的正确性和稳定性。它涵盖了在不同类型的函数（内置函数、API 函数、普通 JavaScript 函数）、不同的调用方式（普通调用、构造函数、getter/setter）、以及在代码优化和垃圾回收等复杂场景下，断点是否能够被正确设置和触发。 此外，还测试了 `debugger` 语句以及基本的单步调试功能。 这些测试用例确保了 V8 的调试功能能够可靠地帮助开发者进行代码调试。

**用户常见的编程错误（可能与断点调试相关）：**

- **断点设置位置错误：** 将断点设置在永远不会执行到的代码行上。
- **条件断点条件错误：**  条件表达式的逻辑错误导致断点永远不会被触发，或者被意外触发。
- **误解作用域：** 在条件断点中使用了不在当前作用域内的变量。
- **忘记清除断点：** 在调试完成后忘记清除断点，导致后续运行程序时意外暂停。
- **在优化后的代码中调试困难：**  V8 的优化可能会改变代码的执行顺序，导致单步调试时与源代码的对应关系不明确。

**JavaScript 示例 (用户常见错误):**

```javascript
function calculateSum(a, b) {
  if (debugMode) { // 假设 debugMode 未定义或为 false
    debugger; // 这个断点永远不会被触发
  }
  return a + b;
}

function processData(data) {
  for (let i = 0; i < data.length; i++) {
    // 假设在此处设置断点，条件是 element > 10，但变量名应该是 data[i]
    if (element > 10) {
      console.log(data[i]);
    }
  }
}
```

Prompt: 
```
这是目录为v8/test/cctest/test-debug.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-debug.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共8部分，请归纳一下它的功能

"""
mization(test);"
      "test(0.5); test(0.6);"
      "%DisableOptimizationFinalization();"
      "%OptimizeFunctionOnNextCall(test, 'concurrent');"
      "test(0.7);");
  CHECK_EQ(0, break_point_hit_count);

  // Run with breakpoint.
  bp = SetBreakPoint(builtin, 0);
  // Have the concurrent compile job finish now.
  CompileRun(
      "%FinalizeOptimization();"
      "%GetOptimizationStatus(test);");
  CompileRun("test(0.2);");
  CHECK_EQ(1, break_point_hit_count);

  // Run without breakpoints.
  ClearBreakPoint(bp);
  CompileRun("test(0.3);");
  CHECK_EQ(1, break_point_hit_count);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

TEST(BreakPointBuiltinTFOperator) {
  i::v8_flags.allow_natives_syntax = true;
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  DebugEventCounter delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);

  v8::Local<v8::Function> builtin;
  i::DirectHandle<i::BreakPoint> bp;

  // === Test builtin represented as operator ===
  break_point_hit_count = 0;
  builtin = CompileRun("String.prototype.indexOf").As<v8::Function>();
  CompileRun("function test(x) { return 1 + 'foo'.indexOf(x) }");
  CompileRun(
      "%PrepareFunctionForOptimization(f);"
      "test('a'); test('b');"
      "%OptimizeFunctionOnNextCall(test); test('c');");
  CHECK_EQ(0, break_point_hit_count);

  // Run with breakpoint.
  bp = SetBreakPoint(builtin, 0);
  CompileRun("'bar'.indexOf('x');");
  CHECK_EQ(1, break_point_hit_count);
  CompileRun("test('d');");
  CHECK_EQ(2, break_point_hit_count);

  // Re-optimize.
  CompileRun(
      "%PrepareFunctionForOptimization(f);"
      "%OptimizeFunctionOnNextCall(test);");
  CompileRun("test('e');");
  CHECK_EQ(3, break_point_hit_count);

  // Run without breakpoints.
  ClearBreakPoint(bp);
  CompileRun("test('f');");
  CHECK_EQ(3, break_point_hit_count);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

TEST(BreakPointBuiltinNewContext) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  DebugEventCounter delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);

  v8::Local<v8::Function> builtin;
  i::DirectHandle<i::BreakPoint> bp;

  // === Test builtin from a new context ===
  break_point_hit_count = 0;
  builtin = CompileRun("String.prototype.repeat").As<v8::Function>();
  CompileRun("'a'.repeat(10)");
  CHECK_EQ(0, break_point_hit_count);
  // Set breakpoint.
  bp = SetBreakPoint(builtin, 0);

  {
    // Create and use new context after breakpoint has been set.
    v8::HandleScope handle_scope(env->GetIsolate());
    v8::Local<v8::Context> new_context = v8::Context::New(env->GetIsolate());
    v8::Context::Scope context_scope(new_context);

    // Run with breakpoint.
    CompileRun("'b'.repeat(10)");
    CHECK_EQ(1, break_point_hit_count);

    CompileRun("'b'.repeat(10)");
    CHECK_EQ(2, break_point_hit_count);

    // Run without breakpoints.
    ClearBreakPoint(bp);
    CompileRun("'b'.repeat(10)");
    CHECK_EQ(2, break_point_hit_count);
  }

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

void NoOpFunctionCallback(const v8::FunctionCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  info.GetReturnValue().Set(v8_num(2));
}

TEST(BreakPointApiFunction) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  DebugEventCounter delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);

  i::DirectHandle<i::BreakPoint> bp;

  v8::Local<v8::FunctionTemplate> function_template =
      v8::FunctionTemplate::New(env->GetIsolate(), NoOpFunctionCallback);

  v8::Local<v8::Function> function =
      function_template->GetFunction(env.local()).ToLocalChecked();

  env->Global()->Set(env.local(), v8_str("f"), function).ToChecked();

  // === Test simple builtin ===
  break_point_hit_count = 0;

  // Run with breakpoint.
  bp = SetBreakPoint(function, 0, "this != 1");
  ExpectInt32("f()", 2);
  CHECK_EQ(1, break_point_hit_count);

  ExpectInt32("f()", 2);
  CHECK_EQ(2, break_point_hit_count);

  // Direct call through API does not trigger breakpoint.
  function->Call(env.local(), v8::Undefined(env->GetIsolate()), 0, nullptr)
      .ToLocalChecked();
  CHECK_EQ(2, break_point_hit_count);

  // Run without breakpoints.
  ClearBreakPoint(bp);
  ExpectInt32("f()", 2);
  CHECK_EQ(2, break_point_hit_count);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

TEST(BreakPointApiConstructor) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  DebugEventCounter delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);

  i::DirectHandle<i::BreakPoint> bp;

  v8::Local<v8::FunctionTemplate> function_template =
      v8::FunctionTemplate::New(env->GetIsolate(), NoOpFunctionCallback);

  v8::Local<v8::Function> function =
      function_template->GetFunction(env.local()).ToLocalChecked();

  env->Global()->Set(env.local(), v8_str("f"), function).ToChecked();

  // === Test simple builtin ===
  break_point_hit_count = 0;

  // Run with breakpoint.
  bp = SetBreakPoint(function, 0, "this != 1");
  CompileRun("new f()");
  CHECK_EQ(1, break_point_hit_count);
  CompileRun("new f()");
  CHECK_EQ(2, break_point_hit_count);

  // Direct call through API does not trigger breakpoint.
  function->NewInstance(env.local()).ToLocalChecked();
  CHECK_EQ(2, break_point_hit_count);

  // Run without breakpoints.
  ClearBreakPoint(bp);
  CompileRun("new f()");
  CHECK_EQ(2, break_point_hit_count);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

void GetWrapperCallback(const v8::FunctionCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  info.GetReturnValue().Set(
      info[0]
          .As<v8::Object>()
          ->Get(info.GetIsolate()->GetCurrentContext(), info[1])
          .ToLocalChecked());
}

TEST(BreakPointApiGetter) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  DebugEventCounter delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);

  i::DirectHandle<i::BreakPoint> bp;

  v8::Local<v8::FunctionTemplate> function_template =
      v8::FunctionTemplate::New(env->GetIsolate(), NoOpFunctionCallback);
  v8::Local<v8::FunctionTemplate> get_template =
      v8::FunctionTemplate::New(env->GetIsolate(), GetWrapperCallback);

  v8::Local<v8::Function> function =
      function_template->GetFunction(env.local()).ToLocalChecked();
  v8::Local<v8::Function> get =
      get_template->GetFunction(env.local()).ToLocalChecked();

  env->Global()->Set(env.local(), v8_str("f"), function).ToChecked();
  env->Global()->Set(env.local(), v8_str("get_wrapper"), get).ToChecked();
  CompileRun(
      "var o = {};"
      "Object.defineProperty(o, 'f', { get: f, enumerable: true });");

  // === Test API builtin as getter ===
  break_point_hit_count = 0;

  // Run with breakpoint.
  bp = SetBreakPoint(function, 0);
  CompileRun("get_wrapper(o, 'f')");
  CHECK_EQ(0, break_point_hit_count);

  CompileRun("o.f");
  CHECK_EQ(1, break_point_hit_count);

  // Run without breakpoints.
  ClearBreakPoint(bp);
  CompileRun("get_wrapper(o, 'f', 2)");
  CompileRun("o.f");
  CHECK_EQ(1, break_point_hit_count);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

void SetWrapperCallback(const v8::FunctionCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  CHECK(info[0]
            .As<v8::Object>()
            ->Set(info.GetIsolate()->GetCurrentContext(), info[1], info[2])
            .FromJust());
}

TEST(BreakPointApiSetter) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  DebugEventCounter delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);

  i::DirectHandle<i::BreakPoint> bp;

  v8::Local<v8::FunctionTemplate> function_template =
      v8::FunctionTemplate::New(env->GetIsolate(), NoOpFunctionCallback);
  v8::Local<v8::FunctionTemplate> set_template =
      v8::FunctionTemplate::New(env->GetIsolate(), SetWrapperCallback);

  v8::Local<v8::Function> function =
      function_template->GetFunction(env.local()).ToLocalChecked();
  v8::Local<v8::Function> set =
      set_template->GetFunction(env.local()).ToLocalChecked();

  env->Global()->Set(env.local(), v8_str("f"), function).ToChecked();
  env->Global()->Set(env.local(), v8_str("set_wrapper"), set).ToChecked();

  CompileRun(
      "var o = {};"
      "Object.defineProperty(o, 'f', { set: f, enumerable: true });");

  // === Test API builtin as setter ===
  break_point_hit_count = 0;

  // Run with breakpoint.
  bp = SetBreakPoint(function, 0);

  CompileRun("o.f = 3");
  CHECK_EQ(1, break_point_hit_count);

  CompileRun("set_wrapper(o, 'f', 2)");
  CHECK_EQ(1, break_point_hit_count);

  // Run without breakpoints.
  ClearBreakPoint(bp);
  CompileRun("o.f = 3");
  CHECK_EQ(1, break_point_hit_count);

  // === Test API builtin as setter, with condition ===
  break_point_hit_count = 0;

  // Run with breakpoint.
  bp = SetBreakPoint(function, 0, "arguments[0] == 3");
  CompileRun("set_wrapper(o, 'f', 2)");
  CHECK_EQ(0, break_point_hit_count);

  CompileRun("set_wrapper(o, 'f', 3)");
  CHECK_EQ(0, break_point_hit_count);

  CompileRun("o.f = 3");
  CHECK_EQ(1, break_point_hit_count);

  // Run without breakpoints.
  ClearBreakPoint(bp);
  CompileRun("set_wrapper(o, 'f', 2)");
  CompileRun("o.f = 3");
  CHECK_EQ(1, break_point_hit_count);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

TEST(BreakPointApiAccessor) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  DebugEventCounter delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);

  i::DirectHandle<i::BreakPoint> bp;

  // Create 'foo' class, with a hidden property.
  v8::Local<v8::ObjectTemplate> obj_template =
      v8::ObjectTemplate::New(env->GetIsolate());
  v8::Local<v8::FunctionTemplate> accessor_template =
      v8::FunctionTemplate::New(env->GetIsolate(), NoOpFunctionCallback);
  obj_template->SetAccessorProperty(v8_str("f"), accessor_template,
                                    accessor_template);
  v8::Local<v8::Object> obj =
      obj_template->NewInstance(env.local()).ToLocalChecked();
  env->Global()->Set(env.local(), v8_str("o"), obj).ToChecked();

  v8::Local<v8::Function> function =
      CompileRun("Object.getOwnPropertyDescriptor(o, 'f').set")
          .As<v8::Function>();

  // === Test API accessor ===
  break_point_hit_count = 0;

  CompileRun("function get_loop() { for (var i = 0; i < 10; i++) o.f }");
  CompileRun("function set_loop() { for (var i = 0; i < 10; i++) o.f = 2 }");

  CompileRun("get_loop(); set_loop();");  // Initialize ICs.

  // Run with breakpoint.
  bp = SetBreakPoint(function, 0);

  CompileRun("o.f = 3");
  CHECK_EQ(1, break_point_hit_count);

  CompileRun("o.f");
  CHECK_EQ(2, break_point_hit_count);

  CompileRun("for (var i = 0; i < 10; i++) o.f");
  CHECK_EQ(12, break_point_hit_count);

  CompileRun("get_loop();");
  CHECK_EQ(22, break_point_hit_count);

  CompileRun("for (var i = 0; i < 10; i++) o.f = 2");
  CHECK_EQ(32, break_point_hit_count);

  CompileRun("set_loop();");
  CHECK_EQ(42, break_point_hit_count);

  // Test that the break point also works when we install the function
  // template on a new property (with a fresh AccessorPair instance).
  v8::Local<v8::ObjectTemplate> baz_template =
      v8::ObjectTemplate::New(env->GetIsolate());
  baz_template->SetAccessorProperty(v8_str("g"), accessor_template,
                                    accessor_template);
  v8::Local<v8::Object> baz =
      baz_template->NewInstance(env.local()).ToLocalChecked();
  env->Global()->Set(env.local(), v8_str("b"), baz).ToChecked();

  CompileRun("b.g = 4");
  CHECK_EQ(43, break_point_hit_count);

  CompileRun("b.g");
  CHECK_EQ(44, break_point_hit_count);

  // Run without breakpoints.
  ClearBreakPoint(bp);
  CompileRun("o.f = 3");
  CompileRun("o.f");
  CHECK_EQ(44, break_point_hit_count);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

TEST(Regress1163547) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  DebugEventCounter delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);

  i::DirectHandle<i::BreakPoint> bp;

  auto constructor_tmpl = v8::FunctionTemplate::New(env->GetIsolate());
  auto prototype_tmpl = constructor_tmpl->PrototypeTemplate();
  auto accessor_tmpl =
      v8::FunctionTemplate::New(env->GetIsolate(), NoOpFunctionCallback);
  prototype_tmpl->SetAccessorProperty(v8_str("f"), accessor_tmpl);

  auto constructor =
      constructor_tmpl->GetFunction(env.local()).ToLocalChecked();
  env->Global()->Set(env.local(), v8_str("C"), constructor).ToChecked();

  CompileRun("o = new C();");
  v8::Local<v8::Function> function =
      CompileRun("Object.getOwnPropertyDescriptor(C.prototype, 'f').get")
          .As<v8::Function>();

  // === Test API accessor ===
  break_point_hit_count = 0;

  // At this point, the C.prototype - which holds the "f" accessor - is in
  // dictionary mode.
  auto constructor_fun =
      Cast<i::JSFunction>(v8::Utils::OpenHandle(*constructor));
  CHECK(
      !i::Cast<i::JSObject>(constructor_fun->prototype())->HasFastProperties());

  // Run with breakpoint.
  bp = SetBreakPoint(function, 0);

  CompileRun("o.f");
  CHECK_EQ(1, break_point_hit_count);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

TEST(BreakPointOnLazyAccessorInNewContexts) {
  // Check that breakpoints on a lazy accessor still get hit after creating new
  // contexts.
  // Regression test for parts of http://crbug.com/1368554.
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);

  DebugEventCounter delegate;
  v8::debug::SetDebugDelegate(isolate, &delegate);

  auto accessor_tmpl = v8::FunctionTemplate::New(isolate, NoOpFunctionCallback);
  accessor_tmpl->SetClassName(v8_str("get f"));
  auto object_tmpl = v8::ObjectTemplate::New(isolate);
  object_tmpl->SetAccessorProperty(v8_str("f"), accessor_tmpl);

  {
    v8::Local<v8::Context> context1 = v8::Context::New(isolate);
    context1->Global()
        ->Set(context1, v8_str("o"),
              object_tmpl->NewInstance(context1).ToLocalChecked())
        .ToChecked();
    v8::Context::Scope context_scope(context1);

    // 1. Set the breakpoint
    v8::Local<v8::Function> function =
        CompileRun(context1, "Object.getOwnPropertyDescriptor(o, 'f').get")
            .ToLocalChecked()
            .As<v8::Function>();
    SetBreakPoint(function, 0);

    // 2. Run and check that we hit the breakpoint
    break_point_hit_count = 0;
    CompileRun(context1, "o.f");
    CHECK_EQ(1, break_point_hit_count);
  }

  {
    // Create a second context and check that we also hit the breakpoint
    // without setting it again.
    v8::Local<v8::Context> context2 = v8::Context::New(isolate);
    context2->Global()
        ->Set(context2, v8_str("o"),
              object_tmpl->NewInstance(context2).ToLocalChecked())
        .ToChecked();
    v8::Context::Scope context_scope(context2);

    CompileRun(context2, "o.f");
    CHECK_EQ(2, break_point_hit_count);
  }

  {
    // Create a third context, but this time we use a global template instead
    // and let the bootstrapper initialize "o" instead.
    auto global_tmpl = v8::ObjectTemplate::New(isolate);
    global_tmpl->Set(v8_str("o"), object_tmpl);
    v8::Local<v8::Context> context3 =
        v8::Context::New(isolate, nullptr, global_tmpl);
    v8::Context::Scope context_scope(context3);

    CompileRun(context3, "o.f");
    CHECK_EQ(3, break_point_hit_count);
  }

  v8::debug::SetDebugDelegate(isolate, nullptr);
  CheckDebuggerUnloaded();
}

TEST(BreakPointInlineApiFunction) {
  i::v8_flags.allow_natives_syntax = true;
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  DebugEventCounter delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);

  i::DirectHandle<i::BreakPoint> bp;

  v8::Local<v8::FunctionTemplate> function_template =
      v8::FunctionTemplate::New(env->GetIsolate(), NoOpFunctionCallback);

  v8::Local<v8::Function> function =
      function_template->GetFunction(env.local()).ToLocalChecked();

  env->Global()->Set(env.local(), v8_str("f"), function).ToChecked();
  CompileRun(
      "function g() { return 1 +  f(); };"
      "%PrepareFunctionForOptimization(g);");

  // === Test simple builtin ===
  break_point_hit_count = 0;

  // Run with breakpoint.
  bp = SetBreakPoint(function, 0);
  ExpectInt32("g()", 3);
  CHECK_EQ(1, break_point_hit_count);

  ExpectInt32("g()", 3);
  CHECK_EQ(2, break_point_hit_count);

  CompileRun("%OptimizeFunctionOnNextCall(g)");
  ExpectInt32("g()", 3);
  CHECK_EQ(3, break_point_hit_count);

  // Run without breakpoints.
  ClearBreakPoint(bp);
  ExpectInt32("g()", 3);
  CHECK_EQ(3, break_point_hit_count);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

// Test that a break point can be set at a return store location.
TEST(BreakPointConditionBuiltin) {
  i::v8_flags.allow_natives_syntax = true;
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  DebugEventCounter delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);
  v8::Local<v8::Function> builtin;
  i::DirectHandle<i::BreakPoint> bp;

  // === Test global variable ===
  break_point_hit_count = 0;
  builtin = CompileRun("String.prototype.repeat").As<v8::Function>();
  CompileRun("var condition = false");
  CompileRun("'a'.repeat(10)");
  CHECK_EQ(0, break_point_hit_count);

  // Run with breakpoint.
  bp = SetBreakPoint(builtin, 0, "condition == true");
  CompileRun("'b'.repeat(10)");
  CHECK_EQ(0, break_point_hit_count);

  CompileRun("condition = true");
  CompileRun("'b'.repeat(10)");
  CHECK_EQ(1, break_point_hit_count);

  // Run without breakpoints.
  ClearBreakPoint(bp);
  CompileRun("'b'.repeat(10)");
  CHECK_EQ(1, break_point_hit_count);

  // === Test arguments ===
  break_point_hit_count = 0;
  builtin = CompileRun("String.prototype.repeat").As<v8::Function>();
  CompileRun("function f(x) { return 'a'.repeat(x * 2); }");
  CHECK_EQ(0, break_point_hit_count);

  // Run with breakpoint.
  bp = SetBreakPoint(builtin, 0, "arguments[0] == 20");
  ExpectString("f(5)", "aaaaaaaaaa");
  CHECK_EQ(0, break_point_hit_count);

  ExpectString("f(10)", "aaaaaaaaaaaaaaaaaaaa");
  CHECK_EQ(1, break_point_hit_count);

  // Run without breakpoints.
  ClearBreakPoint(bp);
  ExpectString("f(10)", "aaaaaaaaaaaaaaaaaaaa");
  CHECK_EQ(1, break_point_hit_count);

  // === Test adapted arguments ===
  break_point_hit_count = 0;
  builtin = CompileRun("String.prototype.repeat").As<v8::Function>();
  CompileRun("function f(x) { return 'a'.repeat(x * 2, x); }");
  CHECK_EQ(0, break_point_hit_count);

  // Run with breakpoint.
  bp = SetBreakPoint(builtin, 0,
                     "arguments[1] == 10 && arguments[2] == undefined");
  ExpectString("f(5)", "aaaaaaaaaa");
  CHECK_EQ(0, break_point_hit_count);

  ExpectString("f(10)", "aaaaaaaaaaaaaaaaaaaa");
  CHECK_EQ(1, break_point_hit_count);

  // Run without breakpoints.
  ClearBreakPoint(bp);
  ExpectString("f(10)", "aaaaaaaaaaaaaaaaaaaa");
  CHECK_EQ(1, break_point_hit_count);

  // === Test var-arg builtins ===
  break_point_hit_count = 0;
  builtin = CompileRun("String.fromCharCode").As<v8::Function>();
  CompileRun("function f() { return String.fromCharCode(1, 2, 3); }");
  CHECK_EQ(0, break_point_hit_count);

  // Run with breakpoint.
  bp = SetBreakPoint(builtin, 0, "arguments.length == 3 && arguments[1] == 2");
  CompileRun("f(1, 2, 3)");
  CHECK_EQ(1, break_point_hit_count);

  // Run without breakpoints.
  ClearBreakPoint(bp);
  CompileRun("f(1, 2, 3)");
  CHECK_EQ(1, break_point_hit_count);

  // === Test rest arguments ===
  break_point_hit_count = 0;
  builtin = CompileRun("String.fromCharCode").As<v8::Function>();
  CompileRun("function f(...info) { return String.fromCharCode(...info); }");
  CHECK_EQ(0, break_point_hit_count);

  // Run with breakpoint.
  bp = SetBreakPoint(builtin, 0, "arguments.length == 3 && arguments[1] == 2");
  CompileRun("f(1, 2, 3)");
  CHECK_EQ(1, break_point_hit_count);

  ClearBreakPoint(bp);
  CompileRun("f(1, 3, 3)");
  CHECK_EQ(1, break_point_hit_count);

  // Run without breakpoints.
  ClearBreakPoint(bp);
  CompileRun("f(1, 2, 3)");
  CHECK_EQ(1, break_point_hit_count);

  // === Test receiver ===
  break_point_hit_count = 0;
  builtin = CompileRun("String.prototype.repeat").As<v8::Function>();
  CompileRun("function f(x) { return x.repeat(10); }");
  CHECK_EQ(0, break_point_hit_count);

  // Run with breakpoint.
  bp = SetBreakPoint(builtin, 0, "this == 'a'");
  ExpectString("f('b')", "bbbbbbbbbb");
  CHECK_EQ(0, break_point_hit_count);

  ExpectString("f('a')", "aaaaaaaaaa");
  CHECK_EQ(1, break_point_hit_count);

  // Run without breakpoints.
  ClearBreakPoint(bp);
  ExpectString("f('a')", "aaaaaaaaaa");
  CHECK_EQ(1, break_point_hit_count);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

TEST(BreakPointInlining) {
  i::v8_flags.allow_natives_syntax = true;
  break_point_hit_count = 0;
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  DebugEventCounter delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);

  break_point_hit_count = 0;
  v8::Local<v8::Function> inlinee =
      CompileRun("function f(x) { return x*2; } f").As<v8::Function>();
  CompileRun("function test(x) { return 1 + f(x) }");
  CompileRun(
      "%PrepareFunctionForOptimization(test);"
      "test(0.5); test(0.6);"
      "%OptimizeFunctionOnNextCall(test); test(0.7);");
  CHECK_EQ(0, break_point_hit_count);

  // Run with breakpoint.
  i::DirectHandle<i::BreakPoint> bp = SetBreakPoint(inlinee, 0);
  CompileRun("f(0.1);");
  CHECK_EQ(1, break_point_hit_count);
  CompileRun("test(0.2);");
  CHECK_EQ(2, break_point_hit_count);

  // Re-optimize.
  CompileRun(
      "%PrepareFunctionForOptimization(test);"
      "%OptimizeFunctionOnNextCall(test);");
  CompileRun("test(0.3);");
  CHECK_EQ(3, break_point_hit_count);

  // Run without breakpoints.
  ClearBreakPoint(bp);
  CompileRun("test(0.3);");
  CHECK_EQ(3, break_point_hit_count);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

static void CallWithBreakPoints(v8::Local<v8::Context> context,
                                v8::Local<v8::Object> recv,
                                v8::Local<v8::Function> f,
                                int break_point_count, int call_count) {
  break_point_hit_count = 0;
  for (int i = 0; i < call_count; i++) {
    f->Call(context, recv, 0, nullptr).ToLocalChecked();
    CHECK_EQ((i + 1) * break_point_count, break_point_hit_count);
  }
}


// Test GC during break point processing.
TEST(GCDuringBreakPointProcessing) {
  break_point_hit_count = 0;
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::Local<v8::Context> context = env.local();

  DebugEventBreakPointCollectGarbage delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);
  v8::Local<v8::Function> foo;

  // Test IC store break point with garbage collection.
  foo = CompileFunction(&env, "function foo(){bar=0;}", "foo");
  SetBreakPoint(foo, 0);
  CallWithBreakPoints(context, env->Global(), foo, 1, 10);

  // Test IC load break point with garbage collection.
  foo = CompileFunction(&env, "bar=1;function foo(){var x=bar;}", "foo");
  SetBreakPoint(foo, 0);
  CallWithBreakPoints(context, env->Global(), foo, 1, 10);

  // Test IC call break point with garbage collection.
  foo = CompileFunction(&env, "function bar(){};function foo(){bar();}", "foo");
  SetBreakPoint(foo, 0);
  CallWithBreakPoints(context, env->Global(), foo, 1, 10);

  // Test return break point with garbage collection.
  foo = CompileFunction(&env, "function foo(){}", "foo");
  SetBreakPoint(foo, 0);
  CallWithBreakPoints(context, env->Global(), foo, 1, 25);

  // Test debug break slot break point with garbage collection.
  foo = CompileFunction(&env, "function foo(){var a;}", "foo");
  SetBreakPoint(foo, 0);
  CallWithBreakPoints(context, env->Global(), foo, 1, 25);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}


// Call the function three times with different garbage collections in between
// and make sure that the break point survives.
static void CallAndGC(v8::Local<v8::Context> context,
                      v8::Local<v8::Object> recv, v8::Local<v8::Function> f) {
  break_point_hit_count = 0;

  for (int i = 0; i < 3; i++) {
    // Call function.
    f->Call(context, recv, 0, nullptr).ToLocalChecked();
    CHECK_EQ(1 + i * 3, break_point_hit_count);

    // Scavenge and call function.
    i::heap::InvokeMinorGC(CcTest::heap());
    f->Call(context, recv, 0, nullptr).ToLocalChecked();
    CHECK_EQ(2 + i * 3, break_point_hit_count);

    // Mark sweep (and perhaps compact) and call function.
    i::heap::InvokeMajorGC(CcTest::heap());
    f->Call(context, recv, 0, nullptr).ToLocalChecked();
    CHECK_EQ(3 + i * 3, break_point_hit_count);
  }
}


// Test that a break point can be set at a return store location.
TEST(BreakPointSurviveGC) {
  break_point_hit_count = 0;
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::Local<v8::Context> context = env.local();

  DebugEventCounter delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);
  v8::Local<v8::Function> foo;

  // Test IC store break point with garbage collection.
  {
    CompileFunction(&env, "function foo(){}", "foo");
    foo = CompileFunction(&env, "function foo(){bar=0;}", "foo");
    SetBreakPoint(foo, 0);
  }
  CallAndGC(context, env->Global(), foo);

  // Test IC load break point with garbage collection.
  {
    CompileFunction(&env, "function foo(){}", "foo");
    foo = CompileFunction(&env, "bar=1;function foo(){var x=bar;}", "foo");
    SetBreakPoint(foo, 0);
  }
  CallAndGC(context, env->Global(), foo);

  // Test IC call break point with garbage collection.
  {
    CompileFunction(&env, "function foo(){}", "foo");
    foo = CompileFunction(&env,
                          "function bar(){};function foo(){bar();}",
                          "foo");
    SetBreakPoint(foo, 0);
  }
  CallAndGC(context, env->Global(), foo);

  // Test return break point with garbage collection.
  {
    CompileFunction(&env, "function foo(){}", "foo");
    foo = CompileFunction(&env, "function foo(){}", "foo");
    SetBreakPoint(foo, 0);
  }
  CallAndGC(context, env->Global(), foo);

  // Test non IC break point with garbage collection.
  {
    CompileFunction(&env, "function foo(){}", "foo");
    foo = CompileFunction(&env, "function foo(){var bar=0;}", "foo");
    SetBreakPoint(foo, 0);
  }
  CallAndGC(context, env->Global(), foo);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

// Test that the debugger statement causes a break.
TEST(DebuggerStatement) {
  break_point_hit_count = 0;
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  DebugEventCounter delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);
  v8::Local<v8::Context> context = env.local();
  v8::Script::Compile(context,
                      v8_str(env->GetIsolate(), "function bar(){debugger}"))
      .ToLocalChecked()
      ->Run(context)
      .ToLocalChecked();
  v8::Script::Compile(
      context, v8_str(env->GetIsolate(), "function foo(){debugger;debugger;}"))
      .ToLocalChecked()
      ->Run(context)
      .ToLocalChecked();
  v8::Local<v8::Function> foo = v8::Local<v8::Function>::Cast(
      env->Global()
          ->Get(context, v8_str(env->GetIsolate(), "foo"))
          .ToLocalChecked());
  v8::Local<v8::Function> bar = v8::Local<v8::Function>::Cast(
      env->Global()
          ->Get(context, v8_str(env->GetIsolate(), "bar"))
          .ToLocalChecked());

  // Run function with debugger statement
  bar->Call(context, env->Global(), 0, nullptr).ToLocalChecked();
  CHECK_EQ(1, break_point_hit_count);

  // Run function with two debugger statement
  foo->Call(context, env->Global(), 0, nullptr).ToLocalChecked();
  CHECK_EQ(3, break_point_hit_count);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}


// Test setting a breakpoint on the debugger statement.
TEST(DebuggerStatementBreakpoint) {
    break_point_hit_count = 0;
    LocalContext env;
    v8::HandleScope scope(env->GetIsolate());
    v8::Local<v8::Context> context = env.local();
    DebugEventCounter delegate;
    v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);
    v8::Script::Compile(context,
                        v8_str(env->GetIsolate(), "function foo(){debugger;}"))
        .ToLocalChecked()
        ->Run(context)
        .ToLocalChecked();
    v8::Local<v8::Function> foo = v8::Local<v8::Function>::Cast(
        env->Global()
            ->Get(context, v8_str(env->GetIsolate(), "foo"))
            .ToLocalChecked());

    // The debugger statement triggers breakpoint hit
    foo->Call(context, env->Global(), 0, nullptr).ToLocalChecked();
    CHECK_EQ(1, break_point_hit_count);

    i::DirectHandle<i::BreakPoint> bp = SetBreakPoint(foo, 0);

    // Set breakpoint does not duplicate hits
    foo->Call(context, env->Global(), 0, nullptr).ToLocalChecked();
    CHECK_EQ(2, break_point_hit_count);

    ClearBreakPoint(bp);
    v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
    CheckDebuggerUnloaded();
}


// Test that the conditional breakpoints work event if code generation from
// strings is prohibited in the debugee context.
TEST(ConditionalBreakpointWithCodeGenerationDisallowed) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  DebugEventCounter delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);

  v8::Local<v8::Context> context = env.local();
  v8::Local<v8::Function> foo = CompileFunction(&env,
    "function foo(x) {\n"
    "  var s = 'String value2';\n"
    "  return s + x;\n"
    "}",
    "foo");

  // Set conditional breakpoint with condition 'true'.
  SetBreakPoint(foo, 4, "true");

  break_point_hit_count = 0;
  env->AllowCodeGenerationFromStrings(false);
  foo->Call(context, env->Global(), 0, nullptr).ToLocalChecked();
  CHECK_EQ(1, break_point_hit_count);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}


// Simple test of the stepping mechanism using only store ICs.
TEST(DebugStepLinear) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  // Create a function for testing stepping.
  v8::Local<v8::Function> foo = CompileFunction(&env,
                                                "function foo(){a=1;b=1;c=1;}",
                                                "foo");

  // Run foo to allow it to get optimized.
  CompileRun("a=0; b=0; c=0; foo();");

  // Register a debug event listener which steps and counts.
  DebugEventCounter run_step;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &run_step);

  SetBreakPoint(foo, 3);

  run_step.set_step_action(StepInto);
  break_point_hit_count = 0;
  v8::Local<v8::Context> context = env.local();
  foo->Call(context, env->Global(), 0, nullptr).ToLocalChecked();

  // With stepping all break locations are hit.
  CHECK_EQ(4, break_point_hit_count);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

TEST(DebugCountLinear) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  // Create a function for testing stepping.
  v8::Local<v8::Function> foo =
      CompileFunction(&env, "function foo(){a=1;b=1;c=1;}", "foo");

  // Run foo to allow it to get optimized.
  CompileRun("a=0; b=0; c=0; foo();");

  // Register a debug event listener which just counts.
  DebugEventCounter delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);

  SetBreakPoint(foo, 3);
  break_point_hit_count = 0;
  v8::Local<v8::Context> context = env.local();
  foo->Call(context, env->Global(), 0, nullptr).ToLocalChecked();

  // Without stepping only active break points are hit.
  CHECK_EQ(1, break_point_hit_count);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

// Test of the stepping mechanism for keyed load in a loop.
TEST(DebugStepKeyedLoadLoop) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  // Register a debug event listener which steps and counts.
  DebugEventCounter run_step;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &run_step);

  // Create 
"""


```