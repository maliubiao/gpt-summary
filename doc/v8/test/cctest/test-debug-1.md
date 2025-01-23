Response: The user is asking me to summarize the functionality of the C++ code provided in the second part of a four-part series. The code seems to be testing the debugging capabilities of the V8 JavaScript engine, specifically focusing on stepping through different JavaScript constructs like loops, conditional statements, and function calls.

I need to:
1. Identify the core functionality demonstrated by the C++ code.
2. Explain how this relates to JavaScript debugging.
3. Provide a JavaScript example illustrating the demonstrated functionality.

Based on the code, it seems to be testing the "step-over" and "step-into" debugging actions in various JavaScript scenarios. The code sets breakpoints in JavaScript functions and then uses the V8 debugging API to step through the code, verifying that the debugger hits the expected locations.
这段C++代码是V8 JavaScript引擎测试套件的一部分，它专注于测试**调试器的单步执行功能**。更具体地说，这部分代码测试了在各种JavaScript代码结构中进行单步执行时的行为，例如：

* **keyed load（键式加载）和 keyed store（键式存储）的循环**:  测试在循环中访问数组元素 (`a[i]`) 时，单步执行是否能正确地停在每一步。
* **named load（命名加载）和 named store（命名存储）的循环**: 测试在循环中访问对象属性 (`v.y`, `a.a`) 时，单步执行是否能正确地停在每一步。
* **不同类型的IC（Inline Cache）**: 测试在包含不同类型内联缓存的代码中单步执行的行为。
* **变量声明**: 测试单步执行是否能够正确地停在变量声明语句上。
* **局部变量赋值**: 测试单步执行是否能够正确地停在局部变量赋值语句上。
* **`if` 语句**: 测试单步执行在 `if` 语句的不同分支（`then` 和 `else`）中的行为。
* **`switch` 语句**: 测试单步执行在 `switch` 语句的不同 `case` 分支中的行为。
* **`while` 循环**: 测试单步执行 `while` 循环的循环条件和循环体。
* **`do...while` 循环**: 测试单步执行 `do...while` 循环的循环体和循环条件。
* **`for` 循环**: 测试单步执行 `for` 循环的初始化、条件判断和更新语句以及循环体。
* **`for` 循环中的 `continue` 和 `break`**: 测试单步执行在 `for` 循环中使用 `continue` 和 `break` 时的行为。
* **`for...in` 循环**: 测试单步执行 `for...in` 循环遍历对象属性时的行为。
* **`with` 语句**: 测试单步执行 `with` 语句。
* **条件表达式（三元运算符）**: 测试单步执行条件表达式。
* **原生函数调用**: 测试单步执行是否会跳过原生函数（例如 `Math.sin()`）的内部。
* **`Function.apply` 和 `Function.call`**: 测试单步执行通过 `apply` 和 `call` 调用的函数。
* **`debugger` 语句**: 测试 `debugger` 语句是否会触发断点。

**它与 JavaScript 的功能关系密切，因为它直接测试了 V8 引擎在执行 JavaScript 代码时的调试能力。**  这些测试确保了开发者在使用 JavaScript 调试器时，能够按照预期的方式单步执行代码，理解代码的执行流程。

**JavaScript 示例：**

以下是一个与代码中 `TEST(DebugStepKeyedLoadLoop)` 功能相关的 JavaScript 示例：

```javascript
function foo(arr) {
  var x;
  var len = arr.length;
  for (var i = 0; i < len; i++) {
    y = 1; // 为了演示有多条可断点的语句
    x = arr[i]; // 关键：键式加载
  }
}

y = 0;
var myArray = [10, 20, 30];
foo(myArray);
```

在这个 JavaScript 示例中，当你在调试器中设置断点在 `x = arr[i];` 这一行，并使用“单步执行”（Step Over 或 Step Into）时，调试器应该会在每次循环迭代到这一行时暂停，允许你查看 `arr[i]` 的值。 这段 C++ 代码的目的就是验证 V8 引擎的调试器在这种情况下是否能正确工作。 C++ 代码模拟了设置断点、执行代码并检查断点被命中的次数，以此来确保单步执行的逻辑正确。

### 提示词
```
这是目录为v8/test/cctest/test-debug.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共4部分，请归纳一下它的功能
```

### 源代码
```
a function for testing stepping of keyed load. The statement 'y=1'
  // is there to have more than one breakable statement in the loop, TODO(315).
  v8::Local<v8::Function> foo = CompileFunction(
      &env,
      "function foo(a) {\n"
      "  var x;\n"
      "  var len = a.length;\n"
      "  for (var i = 0; i < len; i++) {\n"
      "    y = 1;\n"
      "    x = a[i];\n"
      "  }\n"
      "}\n"
      "y=0\n",
      "foo");

  v8::Local<v8::Context> context = env.local();
  // Create array [0,1,2,3,4,5,6,7,8,9]
  v8::Local<v8::Array> a = v8::Array::New(env->GetIsolate(), 10);
  for (int i = 0; i < 10; i++) {
    CHECK(a->Set(context, v8::Number::New(env->GetIsolate(), i),
                 v8::Number::New(env->GetIsolate(), i))
              .FromJust());
  }

  // Call function without any break points to ensure inlining is in place.
  const int kArgc = 1;
  v8::Local<v8::Value> args[kArgc] = {a};
  foo->Call(context, env->Global(), kArgc, args).ToLocalChecked();

  // Set up break point and step through the function.
  SetBreakPoint(foo, 3);
  run_step.set_step_action(StepOver);
  break_point_hit_count = 0;
  foo->Call(context, env->Global(), kArgc, args).ToLocalChecked();

  // With stepping all break locations are hit.
  CHECK_EQ(44, break_point_hit_count);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}


// Test of the stepping mechanism for keyed store in a loop.
TEST(DebugStepKeyedStoreLoop) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  // Register a debug event listener which steps and counts.
  DebugEventCounter run_step;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &run_step);

  // Create a function for testing stepping of keyed store. The statement 'y=1'
  // is there to have more than one breakable statement in the loop, TODO(315).
  v8::Local<v8::Function> foo = CompileFunction(
      &env,
      "function foo(a) {\n"
      "  var len = a.length;\n"
      "  for (var i = 0; i < len; i++) {\n"
      "    y = 1;\n"
      "    a[i] = 42;\n"
      "  }\n"
      "}\n"
      "y=0\n",
      "foo");

  v8::Local<v8::Context> context = env.local();
  // Create array [0,1,2,3,4,5,6,7,8,9]
  v8::Local<v8::Array> a = v8::Array::New(env->GetIsolate(), 10);
  for (int i = 0; i < 10; i++) {
    CHECK(a->Set(context, v8::Number::New(env->GetIsolate(), i),
                 v8::Number::New(env->GetIsolate(), i))
              .FromJust());
  }

  // Call function without any break points to ensure inlining is in place.
  const int kArgc = 1;
  v8::Local<v8::Value> args[kArgc] = {a};
  foo->Call(context, env->Global(), kArgc, args).ToLocalChecked();

  // Set up break point and step through the function.
  SetBreakPoint(foo, 3);
  run_step.set_step_action(StepOver);
  break_point_hit_count = 0;
  foo->Call(context, env->Global(), kArgc, args).ToLocalChecked();

  // With stepping all break locations are hit.
  CHECK_EQ(44, break_point_hit_count);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}


// Test of the stepping mechanism for named load in a loop.
TEST(DebugStepNamedLoadLoop) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  // Register a debug event listener which steps and counts.
  DebugEventCounter run_step;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &run_step);

  v8::Local<v8::Context> context = env.local();
  // Create a function for testing stepping of named load.
  v8::Local<v8::Function> foo = CompileFunction(
      &env,
      "function foo() {\n"
          "  var a = [];\n"
          "  var s = \"\";\n"
          "  for (var i = 0; i < 10; i++) {\n"
          "    var v = new V(i, i + 1);\n"
          "    v.y;\n"
          "    a.length;\n"  // Special case: array length.
          "    s.length;\n"  // Special case: string length.
          "  }\n"
          "}\n"
          "function V(x, y) {\n"
          "  this.x = x;\n"
          "  this.y = y;\n"
          "}\n",
          "foo");

  // Call function without any break points to ensure inlining is in place.
  foo->Call(context, env->Global(), 0, nullptr).ToLocalChecked();

  // Set up break point and step through the function.
  SetBreakPoint(foo, 4);
  run_step.set_step_action(StepOver);
  break_point_hit_count = 0;
  foo->Call(context, env->Global(), 0, nullptr).ToLocalChecked();

  // With stepping all break locations are hit.
  CHECK_EQ(65, break_point_hit_count);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}


static void DoDebugStepNamedStoreLoop(int expected) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  // Register a debug event listener which steps and counts.
  DebugEventCounter run_step;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &run_step);

  // Create a function for testing stepping of named store.
  v8::Local<v8::Context> context = env.local();
  v8::Local<v8::Function> foo = CompileFunction(
      &env,
      "function foo() {\n"
          "  var a = {a:1};\n"
          "  for (var i = 0; i < 10; i++) {\n"
          "    a.a = 2\n"
          "  }\n"
          "}\n",
          "foo");

  // Call function without any break points to ensure inlining is in place.
  foo->Call(context, env->Global(), 0, nullptr).ToLocalChecked();

  // Set up break point and step through the function.
  SetBreakPoint(foo, 3);
  run_step.set_step_action(StepOver);
  break_point_hit_count = 0;
  foo->Call(context, env->Global(), 0, nullptr).ToLocalChecked();

  // With stepping all expected break locations are hit.
  CHECK_EQ(expected, break_point_hit_count);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}


// Test of the stepping mechanism for named load in a loop.
TEST(DebugStepNamedStoreLoop) { DoDebugStepNamedStoreLoop(34); }

// Test the stepping mechanism with different ICs.
TEST(DebugStepLinearMixedICs) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  // Register a debug event listener which steps and counts.
  DebugEventCounter run_step;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &run_step);

  v8::Local<v8::Context> context = env.local();
  // Create a function for testing stepping.
  v8::Local<v8::Function> foo = CompileFunction(&env,
      "function bar() {};"
      "function foo() {"
      "  var x;"
      "  var index='name';"
      "  var y = {};"
      "  a=1;b=2;x=a;y[index]=3;x=y[index];bar();}", "foo");

  // Run functions to allow them to get optimized.
  CompileRun("a=0; b=0; bar(); foo();");

  SetBreakPoint(foo, 0);

  run_step.set_step_action(StepInto);
  break_point_hit_count = 0;
  foo->Call(context, env->Global(), 0, nullptr).ToLocalChecked();

  // With stepping all break locations are hit.
  CHECK_EQ(10, break_point_hit_count);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

TEST(DebugCountLinearMixedICs) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  v8::Local<v8::Context> context = env.local();
  // Create a function for testing stepping.
  v8::Local<v8::Function> foo =
      CompileFunction(&env,
                      "function bar() {};"
                      "function foo() {"
                      "  var x;"
                      "  var index='name';"
                      "  var y = {};"
                      "  a=1;b=2;x=a;y[index]=3;x=y[index];bar();}",
                      "foo");

  // Run functions to allow them to get optimized.
  CompileRun("a=0; b=0; bar(); foo();");

  // Register a debug event listener which just counts.
  DebugEventCounter delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);

  SetBreakPoint(foo, 0);
  break_point_hit_count = 0;
  foo->Call(context, env->Global(), 0, nullptr).ToLocalChecked();

  // Without stepping only active break points are hit.
  CHECK_EQ(1, break_point_hit_count);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

TEST(DebugStepDeclarations) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  // Register a debug event listener which steps and counts.
  DebugEventCounter run_step;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &run_step);

  v8::Local<v8::Context> context = env.local();
  // Create a function for testing stepping. Run it to allow it to get
  // optimized.
  const char* src = "function foo() { "
                    "  var a;"
                    "  var b = 1;"
                    "  var c = foo;"
                    "  var d = Math.floor;"
                    "  var e = b + d(1.2);"
                    "}"
                    "foo()";
  v8::Local<v8::Function> foo = CompileFunction(&env, src, "foo");

  SetBreakPoint(foo, 0);

  // Stepping through the declarations.
  run_step.set_step_action(StepInto);
  break_point_hit_count = 0;
  foo->Call(context, env->Global(), 0, nullptr).ToLocalChecked();
  CHECK_EQ(5, break_point_hit_count);

  // Get rid of the debug event listener.
  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}


TEST(DebugStepLocals) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  // Register a debug event listener which steps and counts.
  DebugEventCounter run_step;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &run_step);

  v8::Local<v8::Context> context = env.local();
  // Create a function for testing stepping. Run it to allow it to get
  // optimized.
  const char* src = "function foo() { "
                    "  var a,b;"
                    "  a = 1;"
                    "  b = a + 2;"
                    "  b = 1 + 2 + 3;"
                    "  a = Math.floor(b);"
                    "}"
                    "foo()";
  v8::Local<v8::Function> foo = CompileFunction(&env, src, "foo");

  SetBreakPoint(foo, 0);

  // Stepping through the declarations.
  run_step.set_step_action(StepInto);
  break_point_hit_count = 0;
  foo->Call(context, env->Global(), 0, nullptr).ToLocalChecked();
  CHECK_EQ(5, break_point_hit_count);

  // Get rid of the debug event listener.
  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}


TEST(DebugStepIf) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  // Register a debug event listener which steps and counts.
  DebugEventCounter run_step;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &run_step);

  v8::Local<v8::Context> context = env.local();
  // Create a function for testing stepping. Run it to allow it to get
  // optimized.
  const int argc = 1;
  const char* src = "function foo(x) { "
                    "  a = 1;"
                    "  if (x) {"
                    "    b = 1;"
                    "  } else {"
                    "    c = 1;"
                    "    d = 1;"
                    "  }"
                    "}"
                    "a=0; b=0; c=0; d=0; foo()";
  v8::Local<v8::Function> foo = CompileFunction(&env, src, "foo");
  SetBreakPoint(foo, 0);

  // Stepping through the true part.
  run_step.set_step_action(StepInto);
  break_point_hit_count = 0;
  v8::Local<v8::Value> argv_true[argc] = {v8::True(isolate)};
  foo->Call(context, env->Global(), argc, argv_true).ToLocalChecked();
  CHECK_EQ(4, break_point_hit_count);

  // Stepping through the false part.
  run_step.set_step_action(StepInto);
  break_point_hit_count = 0;
  v8::Local<v8::Value> argv_false[argc] = {v8::False(isolate)};
  foo->Call(context, env->Global(), argc, argv_false).ToLocalChecked();
  CHECK_EQ(5, break_point_hit_count);

  // Get rid of the debug event listener.
  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}


TEST(DebugStepSwitch) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  // Register a debug event listener which steps and counts.
  DebugEventCounter run_step;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &run_step);

  v8::Local<v8::Context> context = env.local();
  // Create a function for testing stepping. Run it to allow it to get
  // optimized.
  const int argc = 1;
  const char* src = "function foo(x) { "
                    "  a = 1;"
                    "  switch (x) {"
                    "    case 1:"
                    "      b = 1;"
                    "    case 2:"
                    "      c = 1;"
                    "      break;"
                    "    case 3:"
                    "      d = 1;"
                    "      e = 1;"
                    "      f = 1;"
                    "      break;"
                    "  }"
                    "}"
                    "a=0; b=0; c=0; d=0; e=0; f=0; foo()";
  v8::Local<v8::Function> foo = CompileFunction(&env, src, "foo");
  SetBreakPoint(foo, 0);

  // One case with fall-through.
  run_step.set_step_action(StepInto);
  break_point_hit_count = 0;
  v8::Local<v8::Value> argv_1[argc] = {v8::Number::New(isolate, 1)};
  foo->Call(context, env->Global(), argc, argv_1).ToLocalChecked();
  CHECK_EQ(6, break_point_hit_count);

  // Another case.
  run_step.set_step_action(StepInto);
  break_point_hit_count = 0;
  v8::Local<v8::Value> argv_2[argc] = {v8::Number::New(isolate, 2)};
  foo->Call(context, env->Global(), argc, argv_2).ToLocalChecked();
  CHECK_EQ(5, break_point_hit_count);

  // Last case.
  run_step.set_step_action(StepInto);
  break_point_hit_count = 0;
  v8::Local<v8::Value> argv_3[argc] = {v8::Number::New(isolate, 3)};
  foo->Call(context, env->Global(), argc, argv_3).ToLocalChecked();
  CHECK_EQ(7, break_point_hit_count);

  // Get rid of the debug event listener.
  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}


TEST(DebugStepWhile) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  // Register a debug event listener which steps and counts.
  DebugEventCounter run_step;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &run_step);

  v8::Local<v8::Context> context = env.local();
  // Create a function for testing stepping. Run it to allow it to get
  // optimized.
  const int argc = 1;
  const char* src = "function foo(x) { "
                    "  var a = 0;"
                    "  while (a < x) {"
                    "    a++;"
                    "  }"
                    "}"
                    "foo()";
  v8::Local<v8::Function> foo = CompileFunction(&env, src, "foo");
  SetBreakPoint(foo, 8);  // "var a = 0;"

  // Looping 0 times.  We still should break at the while-condition once.
  run_step.set_step_action(StepInto);
  break_point_hit_count = 0;
  v8::Local<v8::Value> argv_0[argc] = {v8::Number::New(isolate, 0)};
  foo->Call(context, env->Global(), argc, argv_0).ToLocalChecked();
  CHECK_EQ(3, break_point_hit_count);

  // Looping 10 times.
  run_step.set_step_action(StepInto);
  break_point_hit_count = 0;
  v8::Local<v8::Value> argv_10[argc] = {v8::Number::New(isolate, 10)};
  foo->Call(context, env->Global(), argc, argv_10).ToLocalChecked();
  CHECK_EQ(23, break_point_hit_count);

  // Looping 100 times.
  run_step.set_step_action(StepInto);
  break_point_hit_count = 0;
  v8::Local<v8::Value> argv_100[argc] = {v8::Number::New(isolate, 100)};
  foo->Call(context, env->Global(), argc, argv_100).ToLocalChecked();
  CHECK_EQ(203, break_point_hit_count);

  // Get rid of the debug event listener.
  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}


TEST(DebugStepDoWhile) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  // Register a debug event listener which steps and counts.
  DebugEventCounter run_step;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &run_step);

  v8::Local<v8::Context> context = env.local();
  // Create a function for testing stepping. Run it to allow it to get
  // optimized.
  const int argc = 1;
  const char* src = "function foo(x) { "
                    "  var a = 0;"
                    "  do {"
                    "    a++;"
                    "  } while (a < x)"
                    "}"
                    "foo()";
  v8::Local<v8::Function> foo = CompileFunction(&env, src, "foo");
  SetBreakPoint(foo, 8);  // "var a = 0;"

  // Looping 0 times.
  run_step.set_step_action(StepInto);
  break_point_hit_count = 0;
  v8::Local<v8::Value> argv_0[argc] = {v8::Number::New(isolate, 0)};
  foo->Call(context, env->Global(), argc, argv_0).ToLocalChecked();
  CHECK_EQ(4, break_point_hit_count);

  // Looping 10 times.
  run_step.set_step_action(StepInto);
  break_point_hit_count = 0;
  v8::Local<v8::Value> argv_10[argc] = {v8::Number::New(isolate, 10)};
  foo->Call(context, env->Global(), argc, argv_10).ToLocalChecked();
  CHECK_EQ(22, break_point_hit_count);

  // Looping 100 times.
  run_step.set_step_action(StepInto);
  break_point_hit_count = 0;
  v8::Local<v8::Value> argv_100[argc] = {v8::Number::New(isolate, 100)};
  foo->Call(context, env->Global(), argc, argv_100).ToLocalChecked();
  CHECK_EQ(202, break_point_hit_count);

  // Get rid of the debug event listener.
  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}


TEST(DebugStepFor) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  // Register a debug event listener which steps and counts.
  DebugEventCounter run_step;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &run_step);

  v8::Local<v8::Context> context = env.local();
  // Create a function for testing stepping. Run it to allow it to get
  // optimized.
  const int argc = 1;
  const char* src = "function foo(x) { "
                    "  a = 1;"
                    "  for (i = 0; i < x; i++) {"
                    "    b = 1;"
                    "  }"
                    "}"
                    "a=0; b=0; i=0; foo()";
  v8::Local<v8::Function> foo = CompileFunction(&env, src, "foo");

  SetBreakPoint(foo, 8);  // "a = 1;"

  // Looping 0 times.
  run_step.set_step_action(StepInto);
  break_point_hit_count = 0;
  v8::Local<v8::Value> argv_0[argc] = {v8::Number::New(isolate, 0)};
  foo->Call(context, env->Global(), argc, argv_0).ToLocalChecked();
  CHECK_EQ(4, break_point_hit_count);

  // Looping 10 times.
  run_step.set_step_action(StepInto);
  break_point_hit_count = 0;
  v8::Local<v8::Value> argv_10[argc] = {v8::Number::New(isolate, 10)};
  foo->Call(context, env->Global(), argc, argv_10).ToLocalChecked();
  CHECK_EQ(34, break_point_hit_count);

  // Looping 100 times.
  run_step.set_step_action(StepInto);
  break_point_hit_count = 0;
  v8::Local<v8::Value> argv_100[argc] = {v8::Number::New(isolate, 100)};
  foo->Call(context, env->Global(), argc, argv_100).ToLocalChecked();
  CHECK_EQ(304, break_point_hit_count);

  // Get rid of the debug event listener.
  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}


TEST(DebugStepForContinue) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  // Register a debug event listener which steps and counts.
  DebugEventCounter run_step;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &run_step);

  v8::Local<v8::Context> context = env.local();
  // Create a function for testing stepping. Run it to allow it to get
  // optimized.
  const int argc = 1;
  const char* src = "function foo(x) { "
                    "  var a = 0;"
                    "  var b = 0;"
                    "  var c = 0;"
                    "  for (var i = 0; i < x; i++) {"
                    "    a++;"
                    "    if (a % 2 == 0) continue;"
                    "    b++;"
                    "    c++;"
                    "  }"
                    "  return b;"
                    "}"
                    "foo()";
  v8::Local<v8::Function> foo = CompileFunction(&env, src, "foo");
  v8::Local<v8::Value> result;
  SetBreakPoint(foo, 8);  // "var a = 0;"

  // Each loop generates 4 or 5 steps depending on whether a is equal.

  // Looping 10 times.
  run_step.set_step_action(StepInto);
  break_point_hit_count = 0;
  v8::Local<v8::Value> argv_10[argc] = {v8::Number::New(isolate, 10)};
  result = foo->Call(context, env->Global(), argc, argv_10).ToLocalChecked();
  CHECK_EQ(5, result->Int32Value(context).FromJust());
  CHECK_EQ(62, break_point_hit_count);

  // Looping 100 times.
  run_step.set_step_action(StepInto);
  break_point_hit_count = 0;
  v8::Local<v8::Value> argv_100[argc] = {v8::Number::New(isolate, 100)};
  result = foo->Call(context, env->Global(), argc, argv_100).ToLocalChecked();
  CHECK_EQ(50, result->Int32Value(context).FromJust());
  CHECK_EQ(557, break_point_hit_count);

  // Get rid of the debug event listener.
  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}


TEST(DebugStepForBreak) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  // Register a debug event listener which steps and counts.
  DebugEventCounter run_step;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &run_step);

  v8::Local<v8::Context> context = env.local();
  // Create a function for testing stepping. Run it to allow it to get
  // optimized.
  const int argc = 1;
  const char* src = "function foo(x) { "
                    "  var a = 0;"
                    "  var b = 0;"
                    "  var c = 0;"
                    "  for (var i = 0; i < 1000; i++) {"
                    "    a++;"
                    "    if (a == x) break;"
                    "    b++;"
                    "    c++;"
                    "  }"
                    "  return b;"
                    "}"
                    "foo()";
  v8::Local<v8::Function> foo = CompileFunction(&env, src, "foo");
  v8::Local<v8::Value> result;
  SetBreakPoint(foo, 8);  // "var a = 0;"

  // Each loop generates 5 steps except for the last (when break is executed)
  // which only generates 4.

  // Looping 10 times.
  run_step.set_step_action(StepInto);
  break_point_hit_count = 0;
  v8::Local<v8::Value> argv_10[argc] = {v8::Number::New(isolate, 10)};
  result = foo->Call(context, env->Global(), argc, argv_10).ToLocalChecked();
  CHECK_EQ(9, result->Int32Value(context).FromJust());
  CHECK_EQ(64, break_point_hit_count);

  // Looping 100 times.
  run_step.set_step_action(StepInto);
  break_point_hit_count = 0;
  v8::Local<v8::Value> argv_100[argc] = {v8::Number::New(isolate, 100)};
  result = foo->Call(context, env->Global(), argc, argv_100).ToLocalChecked();
  CHECK_EQ(99, result->Int32Value(context).FromJust());
  CHECK_EQ(604, break_point_hit_count);

  // Get rid of the debug event listener.
  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}


TEST(DebugStepForIn) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  // Register a debug event listener which steps and counts.
  DebugEventCounter run_step;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &run_step);

  v8::Local<v8::Context> context = env.local();
  // Create a function for testing stepping. Run it to allow it to get
  // optimized.
  v8::Local<v8::Function> foo;
  const char* src_1 = "function foo() { "
                      "  var a = [1, 2];"
                      "  for (x in a) {"
                      "    b = 0;"
                      "  }"
                      "}"
                      "foo()";
  foo = CompileFunction(&env, src_1, "foo");
  SetBreakPoint(foo, 0);  // "var a = ..."

  run_step.set_step_action(StepInto);
  break_point_hit_count = 0;
  foo->Call(context, env->Global(), 0, nullptr).ToLocalChecked();
  CHECK_EQ(8, break_point_hit_count);

  // Create a function for testing stepping. Run it to allow it to get
  // optimized.
  const char* src_2 = "function foo() { "
                      "  var a = {a:[1, 2, 3]};"
                      "  for (x in a.a) {"
                      "    b = 0;"
                      "  }"
                      "}"
                      "foo()";
  foo = CompileFunction(&env, src_2, "foo");
  SetBreakPoint(foo, 0);  // "var a = ..."

  run_step.set_step_action(StepInto);
  break_point_hit_count = 0;
  foo->Call(context, env->Global(), 0, nullptr).ToLocalChecked();
  CHECK_EQ(10, break_point_hit_count);

  // Get rid of the debug event listener.
  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}


TEST(DebugStepWith) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  // Register a debug event listener which steps and counts.
  DebugEventCounter run_step;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &run_step);

  v8::Local<v8::Context> context = env.local();
  // Create a function for testing stepping. Run it to allow it to get
  // optimized.
  const char* src = "function foo(x) { "
                    "  var a = {};"
                    "  with (a) {}"
                    "  with (b) {}"
                    "}"
                    "foo()";
  CHECK(env->Global()
            ->Set(context, v8_str(env->GetIsolate(), "b"),
                  v8::Object::New(env->GetIsolate()))
            .FromJust());
  v8::Local<v8::Function> foo = CompileFunction(&env, src, "foo");
  SetBreakPoint(foo, 8);  // "var a = {};"

  run_step.set_step_action(StepInto);
  break_point_hit_count = 0;
  foo->Call(context, env->Global(), 0, nullptr).ToLocalChecked();
  CHECK_EQ(4, break_point_hit_count);

  // Get rid of the debug event listener.
  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}


TEST(DebugConditional) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  // Register a debug event listener which steps and counts.
  DebugEventCounter run_step;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &run_step);

  v8::Local<v8::Context> context = env.local();
  // Create a function for testing stepping. Run it to allow it to get
  // optimized.
  const char* src =
      "function foo(x) { "
      "  return x ? 1 : 2;"
      "}"
      "foo()";
  v8::Local<v8::Function> foo = CompileFunction(&env, src, "foo");
  SetBreakPoint(foo, 0);  // "var a;"

  run_step.set_step_action(StepInto);
  break_point_hit_count = 0;
  foo->Call(context, env->Global(), 0, nullptr).ToLocalChecked();
  CHECK_EQ(2, break_point_hit_count);

  run_step.set_step_action(StepInto);
  break_point_hit_count = 0;
  const int argc = 1;
  v8::Local<v8::Value> argv_true[argc] = {v8::True(isolate)};
  foo->Call(context, env->Global(), argc, argv_true).ToLocalChecked();
  CHECK_EQ(2, break_point_hit_count);

  // Get rid of the debug event listener.
  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

// Test that step in does not step into native functions.
TEST(DebugStepNatives) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  // Create a function for testing stepping.
  v8::Local<v8::Function> foo =
      CompileFunction(&env, "function foo(){debugger;Math.sin(1);}", "foo");

  // Register a debug event listener which steps and counts.
  DebugEventCounter run_step;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &run_step);

  v8::Local<v8::Context> context = env.local();
  run_step.set_step_action(StepInto);
  break_point_hit_count = 0;
  foo->Call(context, env->Global(), 0, nullptr).ToLocalChecked();

  // With stepping all break locations are hit.
  CHECK_EQ(3, break_point_hit_count);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

TEST(DebugCountNatives) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  // Create a function for testing stepping.
  v8::Local<v8::Function> foo =
      CompileFunction(&env, "function foo(){debugger;Math.sin(1);}", "foo");

  v8::Local<v8::Context> context = env.local();

  // Register a debug event listener which just counts.
  DebugEventCounter delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);

  break_point_hit_count = 0;
  foo->Call(context, env->Global(), 0, nullptr).ToLocalChecked();

  // Without stepping only active break points are hit.
  CHECK_EQ(1, break_point_hit_count);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

// Test that step in works with function.apply.
TEST(DebugStepFunctionApply) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  // Create a function for testing stepping.
  v8::Local<v8::Function> foo =
      CompileFunction(&env,
                      "function bar(x, y, z) { if (x == 1) { a = y; b = z; } }"
                      "function foo(){ debugger; bar.apply(this, [1,2,3]); }",
                      "foo");

  // Register a debug event listener which steps and counts.
  DebugEventCounter run_step;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &run_step);

  v8::Local<v8::Context> context = env.local();
  run_step.set_step_action(StepInto);
  break_point_hit_count = 0;
  foo->Call(context, env->Global(), 0, nullptr).ToLocalChecked();

  // With stepping all break locations are hit.
  CHECK_EQ(7, break_point_hit_count);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

// Test that step in works with function.apply.
TEST(DebugCountFunctionApply) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  // Create a function for testing stepping.
  v8::Local<v8::Function> foo =
      CompileFunction(&env,
                      "function bar(x, y, z) { if (x == 1) { a = y; b = z; } }"
                      "function foo(){ debugger; bar.apply(this, [1,2,3]); }",
                      "foo");

  // Register a debug event listener which just counts.
  DebugEventCounter delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);

  break_point_hit_count = 0;
  v8::Local<v8::Context> context = env.local();
  foo->Call(context, env->Global(), 0, nullptr).ToLocalChecked();

  // Without stepping only the debugger statement is hit.
  CHECK_EQ(1, break_point_hit_count);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

// Test that step in works with function.call.
TEST(DebugStepFunctionCall) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  v8::Local<v8::Context> context = env.local();
  // Create a function for testing stepping.
  v8::Local<v8::Function> foo = CompileFunction(
      &env,
      "function bar(x, y, z) { if (x == 1) { a = y; b = z; } }"
      "function foo(a){ debugger;"
      "                 if (a) {"
      "                   bar.call(this, 1, 2, 3);"
      "                 } else {"
      "                   bar.call(this, 0);"
      "                 }"
      "}",
      "foo");

  // Register a debug event listener which steps and counts.
  DebugEventCounter run_step;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &run_step);
  run_step.set_step_action(StepInto);

  // Check stepping where the if condition in bar is false.
  break_point_hit_count = 0;
  foo->Call(context, env->Global(), 0, nullptr).ToLocalChecked();
  CHECK_EQ(6, break_point_hit_count);

  // Check stepping where the if condition in bar is true.
  break_point_hit_count = 0;
  const int argc = 1;
  v8::Local<v8::Value> argv[argc] = {v8::True(isolate)};
  foo->Call(context, env->Global(), argc, argv).ToLocalChecked();
  CHECK_EQ(8, break_point_hit_count);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

TEST(DebugCountFunctionCall) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  v8::Local<v8::Context> context = env.local();
  // Create a function for testing stepping.
  v8::Local<v8::Function> foo =
      CompileFunction(&env,
                      "function bar(x, y, z) { if (x == 1) { a = y; b = z; } }"
                      "function foo(a){ debugger;"
                      "                 if (a) {"
                      "                   bar.call(this, 1, 2, 3);"
                      "                 } else {"
                      "                   bar.call(this, 0);"
                      "                 }"
                      "}",
                      "foo");

  // Register a debug event listener which just counts.
  DebugEventCounter delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);

  break_point_hit_count = 0;
  foo->Call(context, env->Global(), 0, nullptr).ToLocalChecked();

  // Without stepping only the debugger statement is hit.
  CHECK_EQ(1, break_point_hit_count);

  v8::debug::SetDebugDelegate(isolate, nullptr);
  CheckDebuggerUnloaded();
}

// Test that step in works with Function.call.apply.
TEST(DebugStepFunctionCallApply) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  v8::Local<v8::Context> context = env.local();
  // Create a function for testing stepping.
  v8::Local<v8::Function> foo =
      CompileFunction(&env,
                      "function bar() { }"
                      "function foo(){ debugger;"
                      "                Function.call.apply(bar);"
                      "                Function.call.apply(Function.call, "
                      "[Function.call, bar]);"
                      "}",
                      "foo");

  // Register a debug event listener which steps and counts.
  DebugEventCounter run_step;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &run_step);
  run_step.set_step_action(StepInto);

  break_point_hit_count = 0;
  foo->Call(context, env->Global(), 0, nullptr).ToLocalChecked();
  CHECK_EQ(6, break_point_hit_count);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

TEST(DebugCountFunctionCallApply) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  v8::Local<v8::Context> context = env.local();
  // Create a function for testing stepping.
  v8::Local<v8::Function> foo =
      CompileFunction(&env,
                      "function bar() { }"
                      "function foo(){ debugger;"
                      "                Function.call.apply(bar);"
                      "                Function.call.apply(Function.call, "
                      "[Function.call, bar]);"
                      "}",
                      "foo");

  // Register a debug event listener which just counts.
  DebugEventCounter delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);

  break_point_hit_count = 0;
  foo->Call(context, env->Global(), 0, nullptr).ToLocalChecked();

  // Without stepping only the debugger statement is hit.
  CHECK_EQ(1, break_point_hit_count);

  v8::debug::SetDebugDelegate(isolate, nullptr);
  CheckDebuggerUnloaded();
}

// Tests that breakpoint will be hit if it's set in script.
TEST(PauseInScript) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  i::Isolate* isolate = reinterpret_cast<i::Isolate*>(env->GetIsolate());

  // Register a debug event listener which counts.
  DebugEventCounter event_counter;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &event_counter);

  v8::Local<v8::Context> context = env.local();
  // Create a script that returns a function.
  const char* src = "(function (evt) {})";
  const char* script_name = "StepInHandlerTest";

  v8::ScriptOrigin origin(v8_str(env->GetIsolate(), script_name));
  v8::Local<v8::Script> script =
      v8::Script::Compile(context, v8_str(env->GetIsolate(), src), &origin)
          .ToLocalChecked();

  // Set breakpoint in the script.
  i::Handle<i::Script> i_script(
      i::Cast<i::Script>(
          v8::Utils::OpenDirectHandle(*script)->shared()->script()),
      isolate);
  i::DirectHandle<i::String> condition = isolate->factory()->empty_string();
  int position = 0;
  int id;
  isolate->debug()->SetBreakPointForScript(i_script, condition, &position, &id);
  break_point_hit_count = 0;

  v8::Local<v8::Value> r = script->Run(context).ToLocalChecked();

  CHECK(r->IsFunction());
  CHECK_EQ(1, break_point_hit_count);

  // Get rid of the debug delegate.
  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

int message_callback_count = 0;

TEST(DebugBreak) {
  i::v8_flags.stress_compaction = false;
#ifdef VERIFY_HEAP
  i::v8_flags.verify_heap = true;
#endif
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  // Register a debug event listener which sets the break flag and counts.
  DebugEventBreak delegate;
  v8::debug::SetDebugDelegate(isolate, &delegate);

  v8::Local<v8::Context> context = env.local();
  // Create a function for testing stepping.
  const char* src = "function f0() {}"
                    "function f1(x1) {}"
                    "function f2(x1,x2) {}"
                    "function f3(x1,x2,x3) {}";
  v8::Local<v8::Function> f0 = CompileFunction(&env, src, "f0");
  v8::Local<v8::Function> f1 = CompileFunction(&env, src, "f1");
  v8::Local<v8::Function> f2 = CompileFunction(&env, src, "f2");
  v8::Local<v8::Function> f3 = CompileFunction(&env, src, "f3");

  // Call the function to make sure it is compiled.
  v8::Local<v8::Value> argv[] = {
      v8::Number::New(isolate, 1), v8::Number::New(isolate, 1),
      v8::Number::New(isolate, 1), v8::Number::New(isolate, 1)};

  // Call all functions to make sure that they are compiled.
  f0->Call(context, env->Global(), 0, nullptr).ToLocalChecked();
  f1->Call(context, env->Global(), 0, nullptr).ToLocalChecked();
  f2->Call(context, env->Global(), 0, nullptr).ToLocalChecked();
  f3->Call(context, env->Global(), 0, nullptr).ToLocalChecked();

  // Set the debug break flag.
  v8::debug::SetBreakOnNextFunctionCall(env->GetIsolate());

  // Call all functions with different argument count.
  break_point_hit_count = 0;
  for (unsigned int i = 0; i < arraysize(argv); i++) {
    f0->Call(context, env->Global(), i, argv).ToLocalChecked();
    f1->Call(context, env->Global(), i, argv).ToLocalChecked();
    f2->Call(context, env->Global(), i, argv).ToLocalChecked();
    f3->Call(context, env->Global(), i, argv).ToLocalChecked();
  }

  // One break for each function called.
  CHECK_EQ(4 * arraysize(argv), break_point_hit_count);

  // Get rid of the debug event listener.
  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

class DebugScopingListener : public v8::debug::DebugDelegate {
 public:
  void ExceptionThrown(v8::Local<v8::Context> paused_context,
                       v8::Local<v8::Value> exception,
                       v8::Local<v8::Value> promise, bool is_uncaught,
                       v8::debug::ExceptionType exception_type) override {
    break_count_++;
    auto stack_traces =
        v8::debug::StackTraceIterator::Create(CcTest::isolate());
    v8::debug::Location location = stack_traces->GetSourceLocation();
    CHECK_EQ(26, location.GetColumnNumber());
    CHECK_EQ(0, location.GetLineNumber());

    auto scopes = stack_traces->GetScopeIterator();
    CHECK_EQ(v8::debug::ScopeIterator::ScopeTypeWith, scopes->GetType());
    CHECK_EQ(19, scopes->GetStartLocation().GetColumnNumber());
    CHECK_EQ(31, scopes->GetEndLocation().GetColumnNumber());

    scopes->Advance();
    CHECK_EQ(v8::debug::ScopeIterator::ScopeTypeLocal, scopes->GetType());
    CHECK_EQ(0, scopes->GetStartLocation().GetColumnNumber());
    CHECK_EQ(68, scopes->GetEndLocation().GetColumnNumber());

    scopes->Advance();
    CHECK_EQ(v8::debug::ScopeIterator::ScopeTypeGlobal, scopes->GetType());

    scopes->Advance();
    CHECK(scopes->Done());
  }
  unsigned break_count() const { return break_count_; }

 private:
  unsigned break_count_ = 0;
};

TEST(DebugBreakInWrappedScript) {
  i::v8_flags.stress_compaction = false;
#ifdef VERIFY_HEAP
  i::v8_flags.verify_heap = true;
#endif
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  // Register a debug event listener which sets the break flag and counts.
  DebugScopingListener delegate;
  v8::debug::SetDebugDelegate(isolate, &delegate);

  static const char* source =
      //   0         1         2         3         4         5         6 7
      "try { with({o : []}){ o[0](); } } catch (e) { return e.toString(); }";
  static const char* expect = "TypeError: o[0] is not a function";

  // For this test, we want to break on uncaught exceptions:
  ChangeBreakOnException(isolate, true, true);

  {
    v8::ScriptCompiler::Source script_source(v8_str(source));
    v8::Local<v8::Function> fun =
        v8::ScriptCompiler::CompileFunction(env.local(), &script_source)
            .ToLocalChecked();
    v8::Local<v8::Value> result =
        fun->Call(env.local(), env->Global(), 0, nullptr).ToLocalChecked();
    CHECK(result->IsString());
    CHECK(v8::Local<v8::String>::Cast(result)
              ->Equals(env.local(), v8_str(expect))
              .FromJust());
  }

  // Get rid of the debug event listener.
  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CHECK_EQ(1, delegate.break_count());
  CheckDebuggerUnloaded();
}

static void EmptyHandler(const v8::FunctionCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
}

TEST(DebugScopeIteratorWithFunctionTemplate) {
  LocalContext env;
  v8::HandleScope handle_scope(env->GetIsolate());
  v8::Isolate* isolate = env->GetIsolate();
  EnableDebugger(isolate);
  v8::Local<v8::Function> func =
      v8::Function::New(env.local(), EmptyHandler).ToLocalChecked();
  std::unique_ptr<v8::debug::ScopeIterator> iterator =
      v8::debug::ScopeIterator::CreateForFunction(isolate, func);
  CHECK(iterator->Done());
  DisableDebugger(isolate);
}

TEST(DebugBreakWithoutJS) {
  i::v8_flags.stress_compaction = false;
#ifdef VERIFY_HEAP
  i::v8_flags.verify_heap = true;
#endif
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::Context> context = env.local();

  // Register a debug event listener which sets the break flag and counts.
  DebugEventBreak delegate;
  v8::debug::SetDebugDelegate(isolate, &delegate);

  // Set the debug break flag.
  v8::debug::SetBreakOnNextFunctionCall(env->GetIsolate());

  v8::Local<v8::String> json = v8_str("[1]");
  v8::Local<v8::Value> parsed = v8::JSON::Parse(context, json).ToLocalChecked();
  CHECK(v8::JSON::Stringify(context, parsed)
            .ToLocalChecked()
            ->Equals(context, json)
            .FromJust());
  CHECK_EQ(0, break_point_hit_count);
  CompileRun("");
  CHECK_EQ(1, break_point_hit_count);

  // Get rid of the debug event listener.
  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

// Test to ensure that JavaScript code keeps running while the debug break
// through the stack limit flag is set but breaks are disabled.
TEST(DisableBreak) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  // Register a debug event listener which sets the break flag and counts.
  DebugEventCounter delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);

  v8::Local<v8::Context> context = env.local();
  // Create a function for testing stepping.
  const char* src = "function f() {g()};function g(){i=0; while(i<10){i++}}";
  v8::Local<v8::Function> f = CompileFunction(&env, src, "f");

  // Set, test and cancel debug break.
  v8::debug::SetBreakOnNextFunctionCall(env->GetIsolate());
  v8::debug::ClearBreakOnNextFunctionCall(env->GetIsolate());

  // Set the debug break flag.
  v8::debug::SetBreakOnNextFunctionCall(env->GetIsolate());

  // Call all functions with different argument count.
  break_point_hit_count = 0;
  f->Call(context, env->Global(), 0, nullptr).ToLocalChecked();
  CHECK_EQ(1, break_point_hit_count);

  {
    v8::debug::SetBreakOnNextFunctionCall(env->GetIsolate());
    i::Isolate* isolate = reinterpret_cast<i::Isolate*>(env->GetIsolate());
    v8::internal::DisableBreak disable_break(isolate->debug());
    f->Call(context, env->Global(), 0, nullptr).ToLocalChecked();
    CHECK_EQ(1, break_point_hit_count);
  }

  f->Call(context, env->Global(), 0, nullptr).ToLocalChecked();
  CHECK_EQ(2, break_point_hit_count);

  // Get rid of the debug event listener.
  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

TEST(DisableDebuggerStatement) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  // Register a debug event listener which sets the break flag and counts.
  DebugEventCounter delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);

  CompileRun("debugger;");
  CHECK_EQ(1, break_point_hit_count);

  // Check that we ignore debugger statement when breakpoints aren't active.
  i::Isolate* isolate = reinterpret_cast<i::Isolate*>(env->GetIsolate());
  isolate->debug()->set_break_points_active(false);
  CompileRun("debugger;");
  CHECK_EQ(1, break_point_hit_count);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
}

static const char* kSimpleExtensionSource =
  "(function Foo() {"
  "  return 4;"
  "})() ";

// http://crbug.com/28933
// Test that debug break is disabled when bootstrapper is active.
TEST(NoBreakWhenBootstrapping) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);

  // Register a debug event listener which sets the break flag and counts.
  DebugEventCounter delegate;
  v8::debug::SetDebugDelegate(isolate, &delegate);

  // Set the debug break flag.
  v8::debug::SetBreakOnNextFunctionCall(isolate);
  break_point_hit_count = 0;
  {
    // Create a context with an extension to make sure that some JavaScript
    // code is executed during bootstrapping.
    v8::RegisterExtension(
        std::make_unique<v8::Extension>("simpletest", kSimpleExtensionSource));
    const char* extension_names[] = { "simpletest" };
    v8::ExtensionConfiguration extensions(1, extension_names);
    v8::HandleScope handle_scope(isolate);
    v8::Context::New(isolate, &extensions);
  }
  // Check that no DebugBreak events occurred during the context creation.
  CHECK_EQ(0, break_point_hit_count);

  // Get rid of the debug event listener.
  v8::debug::SetDebugDelegate(isolate, nullptr);
  CheckDebuggerUnloaded();
}

TEST(SetDebugEventListenerOnUninitializedVM) {
  v8::HandleScope scope(CcTest::isolate());
  EnableDebugger(CcTest::isolate());
}

// Test that clearing the debug event listener actually clears all break points
// and related information.
TEST(DebuggerUnload) {
  LocalContext env;
  v8::HandleScope handle_scope(env->GetIsolate());
  // Check debugger is unloaded before it is used.
  CheckDebuggerUnloaded();

  // Set a debug event listener.
  break_point_hit_count = 0;
  DebugEventCounter delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);
  v8::Local<v8::Context> context = env.local();
  {
    v8::HandleScope scope(env->GetIsolate());
    // Create a couple of functions for the test.
    v8::Local<v8::Function> foo =
        CompileFunction(&env, "function foo(){x=1}", "foo");
    v8::Local<v8::Function> bar =
        CompileFunction(&env, "function bar(){y=2}", "bar");

    // Set some break points.
    SetBreakPoint(foo, 0);
    SetBreakPoint(foo, 4);
    SetBreakPoint(bar, 0);
    SetBreakPoint(bar, 4);

    // Make sure that the break points are there.
    break_point_hit_count = 0;
    foo->Call(context, env->Global(), 0, nullptr).ToLocalChecked();
    CHECK_EQ(2, break_point_hit_count);
    bar->Call(context, env->Global(), 0, nullptr).ToLocalChecked();
    CHECK_EQ(4, break_point_hit_count);
  }

  // Remove the debug event listener without clearing breakpoints. Do this
  // outside a handle scope.
  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

int event_listener_hit_count = 0;

// Test for issue http://code.google.com/p/v8/issues/detail?id=289.
// Make sure that DebugGetLoadedScripts doesn't return scripts
// with disposed external source.
class EmptyExternalStringResource : public v8::String::ExternalStringResource {
 public:
  EmptyExternalStringResource() { empty_[0] = 0; }
  ~EmptyExternalStringResource() override = default;
  size_t length() const override { return empty_.length(); }
  const uint16_t* data() const override { return empty_.begin(); }

 private:
  ::v8::base::EmbeddedVector<uint16_t, 1> empty_;
};

TEST(DebugScriptLineEndsAreAscending) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  // Compile a test script.
  v8::Local<v8::String> script_source = v8_str(isolate,
                                               "function f() {\n"
                                               "  debugger;\n"
                                               "}\n");

  v8::ScriptOrigin origin1 = v8::ScriptOrigin(v8_str(isolate, "name"));
  v8::Local<v8::Script> script =
      v8::Script::Compile(env.local(), script_source, &origin1)
          .ToLocalChecked();
  USE(script);

  DirectHandle<v8::internal::FixedArray> instances;
  {
    v8::internal::Debug* debug = CcTest::i_isolate()->debug();
    instances = debug->GetLoadedScripts();
  }

  CHECK_GT(instances->length(), 0);
  for (int i = 0; i < instances->length(); i++) {
    DirectHandle<v8::internal::Script> new_script(
        v8::internal::Cast<v8::internal::Script>(instances->get(i)),
        CcTest::i_isolate());

    v8::internal::Script::InitLineEnds(CcTest::i_isolate(), new_script);
    v8::internal::Tagged<v8::internal::FixedArray> ends =
        v8::internal::Cast<v8::internal::FixedArray>(new_script->line_ends());
    CHECK_GT(ends->length(), 0);

    int prev_end = -1;
    for (int j = 0; j < ends->length(); j++) {
      const int curr_end = v8::internal::Smi::ToInt(ends->get(j));
      CHECK_GT(curr_end, prev_end);
      prev_end = curr_end;
    }
  }
}

static v8::Global<v8::Context> expected_context_global;
static v8::Global<v8::Value> expected_context_data_global;

class ContextCheckEventListener : public v8::debug::DebugDelegate {
 public:
  void BreakProgramRequested(
      v8::Local<v8::Context> paused_context,
      const std::vector<v8::debug::BreakpointId>& inspector_break_points_hit,
      v8::debug::BreakReasons break_reasons) override {
    CheckContext();
  }
  void ScriptCompiled(v8::Local<v8::debug::Script> script, bool is_live_edited,
                      bool has_compile_error) override {
    CheckContext();
  }
  void ExceptionThrown(v8::Local<v8::Context> paused_context,
                       v8::Local<v8::Value> exception,
                       v8::Local<v8::Value> promise, bool is_uncaught,
                       v8::debug::ExceptionType) override {
    CheckContext();
  }
  bool IsFunctionBlackboxed(v8::Local<v8::debug::Script> script,
                            const v8::debug::Location& start,
                            const v8::debug::Location& end) override {
    CheckContext();
    return false;
  }

 private:
  void CheckContext() {
    v8::Local<v8::Context> context = CcTest::isolate()->GetCurrentContext();
    CHECK_EQ(context, expected_context_global.Get(CcTest::isolate()));
    CHECK(context->GetEmbedderData(0)->StrictEquals(
        expected_context_data_global.Get(CcTest::isolate())));
    event_listener_hit_count++;
  }
};

// Test which creates two contexts and sets different embedder data on each.
// Checks that this data is set correctly and that when the debug event
// listener is called the expected context is the one active.
TEST(ContextData) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);

  // Create two contexts.
  v8::Local<v8::Context> context_1;
  v8::Local<v8::Context> context_2;
  v8::Local<v8::ObjectTemplate> global_template =
      v8::Local<v8::ObjectTemplate>();
  v8::Local<v8::Value> global_object = v8::Local<v8::Value>();
  context_1 =
      v8::Context::New(isolate, nullptr, global_template, global_object);
  context_2 =
      v8::Context::New(isolate, nullptr, global_template, global_object);

  ContextCheckEventListener delegate;
  v8::debug::SetDebugDelegate(isolate, &delegate);

  // Default data value is undefined.
  CHECK_EQ(0, context_1->GetNumberOfEmbedderDataFields());
  CHECK_EQ(0, context_2->GetNumberOfEmbedderDataFields());

  // Set and check different data values.
  v8::Local<v8::String> data_1 = v8_str(isolate, "1");
  v8::Local<v8::String> data_2 = v8_str(isolate, "2");
  context_1->SetEmbedderData(0, data_1);
  context_2->SetEmbedderData(0, data_2);
  CHECK(context_1->GetEmbedderData(0)->StrictEquals(data_1));
  CHECK(context_2->GetEmbedderData(0)->StrictEquals(data_2));

  // Simple test function which causes a break.
  const char* source = "function f() { debugger; }";

  // Enter and run function in the first context.
  {
    v8::Context::Scope context_scope(context_1);
    expected_context_global.Reset(isolate, context_1);
    expected_context_data_global.Reset(isolate, data_1);
    v8::Local<v8::Function> f = CompileFunction(isolate, source, "f");
    f->Call(context_1, context_1->Global(), 0, nullptr).ToLocalChecked();
  }

  // Enter and run function in the second context.
  {
    v8::Context::Scope context_scope(context_2);
    expected_context_global.Reset(isolate, context_2);
    expected_context_data_global.Reset(isolate, data_2);
    v8::Local<v8::Function> f = CompileFunction(isolate, source, "f");
    f->Call(context_2, context_2->Global(), 0, nullptr).ToLocalChecked();
  }

  // Two times compile event and two times break event.
  CHECK_GT(event_listener_hit_count, 3);

  v8::debug::SetDebugDelegate(isolate, nullptr);
  CheckDebuggerUnloaded();

  expected_context_global.Reset();
  expected_context_data_global.Reset();
}

// Test which creates a context and sets embedder data on it. Checks that this
// data is set correctly and that when the debug event listener is called for
// break event in an eval statement the expected context is the one returned by
// Message.GetEventContext.
TEST(EvalContextData) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);

  v8::Local<v8::Context> context_1;
  v8::Local<v8::ObjectTemplate> global_template =
      v8::Local<v8::ObjectTemplate>();
  context_1 = v8::Context::New(isolate, nullptr, global_template);

  ContextCheckEventListener delegate;
  v8::debug::SetDebugDelegate(isolate, &delegate);

  // Contexts initially do not have embedder data fields.
  CHECK_EQ(0, context_1->GetNumberOfEmbedderDataFields());

  // Set and check a data value.
  v8::Local<v8::String> data_1 = v8_str(isolate, "1");
  context_1->SetEmbedderData(0, data_1);
  CHECK(context_1->GetEmbedderData(0)->StrictEquals(data_1));

  // Simple test function with eval that causes a break.
  const char* source = "function f() { eval('debugger;'); }";

  // Enter and run function in the context.
  {
    v8::Context::Scope context_scope(context_1);
    expected_context_global.Reset(isolate, context_1);
    expected_context_data_global.Reset(isolate, data_1);
    v8::Local<v8::Function> f = CompileFunction(isolate, source, "f");
    f->Call(context_1, context_1->Global(), 0, nullptr).ToLocalChecked();
  }

  v8::debug::SetDebugDelegate(isolate, nullptr);

  // One time compile event and one time break event.
  CHECK_GT(event_listener_hit_count, 2);
  CheckDebuggerUnloaded();

  expected_context_global.Reset();
  expected_context_data_global.Reset();
}

// Debug event listener which counts script compiled events.
class ScriptCompiledDelegate : public v8::debug::DebugDelegate {
 public:
  void ScriptCompiled(v8::Local<v8::debug::Script>, bool,
                      bool has_compile_error) override {
    if (!has_compile_error) {
      after_compile_event_count++;
    } else {
      compile_error_event_count++;
    }
  }

  int after_compile_event_count = 0;
  int compile_error_event_count = 0;
};

// Tests that after compile event is sent as many times as there are scripts
// compiled.
TEST(AfterCompileEventWhenEventListenerIsReset) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::Local<v8::Context> context = env.local();
  const char* script = "var a=1";

  ScriptCompiledDelegate delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);
  v8::Script::Compile(context, v8_str(env->GetIsolate(), script))
      .ToLocalChecked()
      ->Run(context)
      .ToLocalChecked();
  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);

  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);
  v8::debug::SetBreakOnNextFunctionCall(env->GetIsolate());
  v8::Script::Compile(context, v8_str(env->GetIsolate(), script))
      .ToLocalChecked()
      ->Run(context)
      .ToLocalChecked();

  // Setting listener to nullptr should cause debugger unload.
  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();

  // Compilation cache should be disabled when debugger is active.
  CHECK_EQ(2, delegate.after_compile_event_count);
}

// Tests that syntax error event is sent as many times as there are scripts
// with syntax error compiled.
TEST(SyntaxErrorEventOnSyntaxException) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  // For this test, we want to break on uncaught exceptions:
  ChangeBreakOnException(env->GetIsolate(), false, true);

  ScriptCompiledDelegate delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);
  v8::Local<v8::Context> context = env.local();

  // Check initial state.
  CHECK_EQ(0, delegate.compile_error_event_count);

  // Throws SyntaxError: Unexpected end of input
  CHECK(
      v8::Script::Compile(context, v8_str(env->GetIsolate(), "+++")).IsEmpty());
  CHECK_EQ(1, delegate.compile_error_event_count);

  CHECK(v8::Script::Compile(context, v8_str(env->GetIsolate(), "/sel\\/: \\"))
            .IsEmpty());
  CHECK_EQ(2, delegate.compile_error_event_count);

  v8::Local<v8::Script> script =
      v8::Script::Compile(context,
                          v8_str(env->GetIsolate(), "JSON.parse('1234:')"))
          .ToLocalChecked();
  CHECK_EQ(2, delegate.compile_error_event_count);
  CHECK(script->Run(context).IsEmpty());
  CHECK_EQ(3, delegate.compile_error_event_count);

  v8::Script::Compile(context,
                      v8_str(env->GetIsolate(), "new RegExp('/\\/\\\\');"))
      .ToLocalChecked();
  CHECK_EQ(3, delegate.compile_error_event_count);

  v8::Script::Compile(context, v8_str(env->GetIsolate(), "throw 1;"))
      .ToLocalChecked();
  CHECK_EQ(3, delegate.compile_error_event_count);
}

class ExceptionEventCounter : public v8::debug::DebugDelegate {
 public:
  void ExceptionThrown(v8::Local<v8::Context> paused_context,
                       v8::Local<v8::Value> exception,
                       v8::Local<v8::Value> promise, bool is_uncaught,
                       v8::debug::ExceptionType) override {
    exception_event_count++;
  }
  int exception_event_count = 0;
};

UNINITIALIZED_TEST(NoBreakOnStackOverflow) {
  // We must set v8_flags.stack_size before initializing the isolate.
  i::v8_flags.stack_size = 100;
  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  isolate->Enter();
  {
    LocalContext env(isolate);
    v8::HandleScope scope(isolate);

    ChangeBreakOnException(isolate, true, true);

    ExceptionEventCounter delegate;
    v8::debug::SetDebugDelegate(isolate, &delegate);
    CHECK_EQ(0, delegate.exception_event_count);

    CompileRun(
        "function f() { return f(); }"
        "try { f() } catch {}");

    CHECK_EQ(0, delegate.exception_event_count);
  }
  isolate->Exit();
  isolate->Dispose();
}

// Tests that break event is sent when event listener is reset.
TEST(BreakEventWhenEventListenerIsReset) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::Local<v8::Context> context = env.local();
  const char* script = "function f() {};";

  ScriptCompiledDelegate delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);
  v8::Script::Compile(context, v8_str(env->GetIsolate(), script))
      .ToLocalChecked()
      ->Run(context)
      .ToLocalChecked();
  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);

  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);
  v8::debug::SetBreakOnNextFunctionCall(env->GetIsolate());
  v8::Local<v8::Function> f = v8::Local<v8::Function>::Cast(
      env->Global()
          ->Get(context, v8_str(env->GetIsolate(), "f"))
          .ToLocalChecked());
  f->Call(context, env->Global(), 0, nullptr).ToLocalChecked();

  // Setting event listener to nullptr should cause debugger unload.
  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();

  // Compilation cache should be disabled when debugger is active.
  CHECK_EQ(1, delegate.after_compile_event_count);
}

// Tests that script is reported as compiled when bound to context.
TEST(AfterCompileEventOnBindToContext) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope handle_scope(isolate);
  ScriptCompiledDelegate delegate;
  v8::debug::SetDebugDelegate(isolate, &delegate);

  v8::ScriptCompiler::Source script_source(
      v8::String::NewFromUtf8Literal(isolate, "var a=1"));

  v8::Local<v8::UnboundScript> unbound =
      v8::ScriptCompiler::CompileUnboundScript(isolate, &script_source)
          .ToLocalChecked();
  CHECK_EQ(delegate.after_compile_event_count, 0);

  unbound->BindToCurrentContext();
  CHECK_EQ(delegate.after_compile_event_count, 1);
  v8::debug::SetDebugDelegate(isolate, nullptr);
}


// Test that if DebugBreak is forced it is ignored when code from
// debug-delay.js is executed.
TEST(NoDebugBreakInAfterCompileEventListener) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::Local<v8::Context> context = env.local();

  // Register a debug event listener which sets the break flag and counts.
  DebugEventCounter delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);

  // Set the debug break flag.
  v8::debug::SetBreakOnNextFunctionCall(env->GetIsolate());

  // Create a function for testing stepping.
  const char* src = "function f() { eval('var x = 10;'); } ";
  v8::Local<v8::Function> f = CompileFunction(&env, src, "f");

  // There should be only one break event.
  CHECK_EQ(1, break_point_hit_count);

  // Set the debug break flag again.
  v8::debug::SetBreakOnNextFunctionCall(env->GetIsolate());
  f->Call(context, env->Global(), 0, nullptr).ToLocalChecked();
  // There should be one more break event when the script is evaluated in 'f'.
  CHECK_EQ(2, break_point_hit_count);

  // Get rid of the debug event listener.
  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}


// Test that the debug break flag works with function.apply.
TEST(RepeatDebugBreak) {
  // Test that we can repeatedly set a break without JS execution continuing.
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::Local<v8::Context> context = env.local();

  // Create a function for testing breaking in apply.
  v8::Local<v8::Function> foo =
      CompileFunction(&env, "function foo() {}", "foo");

  // Register a debug delegate which repeatedly sets a break and counts.
  DebugEventBreakMax delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);

  // Set the debug break flag before calling the code using function.apply.
  v8::debug::SetBreakOnNextFunctionCall(env->GetIsolate());

  // Trigger a break by calling into foo().
  break_point_hit_count = 0;
  max_break_point_hit_count = 10000;
  foo->Call(context, env->Global(), 0, nullptr).ToLocalChecked();

  // When keeping the debug break several break will happen.
  CHECK_EQ(break_point_hit_count, max_break_point_hit_count);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

// Test that setting the terminate execution flag during debug break processing.
static void TestDebugBreakInLoop(const char* loop_head,
                                 const char** loop_bodies,
                                 const char* loop_tail) {
  // Receive 10 breaks for each test and then terminate JavaScript execution.
  static const int kBreaksPerTest = 10;

  for (int i = 0; loop_bodies[i] != nullptr; i++) {
    // Perform a lazy deoptimization after various numbers of breaks
    // have been hit.

    v8::base::EmbeddedVector<char, 1024> buffer;
    v8::base::SNPrintF(buffer, "function f() {%s%s%s}", loop_head,
                       loop_bodies[i], loop_tail);

    i::PrintF("%s\n", buffer.begin());

    for (int j = 0; j < 3; j++) {
      break_point_hit_count_deoptimize = j;
      if (j == 2) {
        break_point_hit_count_deoptimize = kBreaksPerTest;
      }

      break_point_hit_count = 0;
      max_break_point_hit_count = kBreaksPerTest;
      terminate_after_max_break_point_hit = true;

      // Function with infinite loop.
      CompileRun(buffer.begin());

      // Set the debug break to enter the debugger as soon as possible.
      v8::debug::SetBreakOnNextFunctionCall(CcTest::isolate());

      // Call function with infinite loop.
      CompileRun("f();");
      CHECK_EQ(kBreaksPerTest, break_point_hit_count);

      CHECK(!CcTest::isolate()->IsExecutionTerminating());
    }
  }
}

static const char* loop_bodies_1[] =
```