Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/test/cctest/test-cpu-profiler.cc`. The code seems to be testing the V8 CPU profiler.

Here's a breakdown of the thought process to answer the request:

1. **Identify the core purpose:** The filename `test-cpu-profiler.cc` strongly suggests that the code is related to testing the CPU profiler within the V8 engine. The various `TEST()` macros confirm this.

2. **Analyze individual tests:** Examine each `TEST()` function to understand its specific scenario. Look for:
    * Setup code (e.g., enabling native syntax, creating contexts).
    * JavaScript code execution (`CompileRun`).
    * Profiler interaction (`startProfiling`, `stopProfiling`, `CpuProfile::New`, `profile->Delete()`).
    * Assertions and checks on the profile data (e.g., `GetTopDownRoot`, `GetChild`, `CHECK_EQ`, `CHECK_GE`).
    * Names of the test functions (e.g., `JsNativeRuntimeJsSample`, `Inlining`, `CrossScriptInliningCallerLineNumbers`). These names often provide hints about the test's focus.

3. **Categorize the test functionalities:** Group similar tests together to identify broader themes. The code appears to test:
    * Basic profiling of JavaScript code.
    * Profiling across JavaScript and native code boundaries.
    * Profiling of inlined functions.
    * Profiling across different JavaScript scripts.
    * Handling of idle time in the profiler.
    * Detailed function information in profiles (name, script, line, column).
    * Profiling interactions with optimization and deoptimization (OSR, deopt events).
    * Edge cases in profiler management (e.g., deleting finished profiles).
    * Source code locations in profiles.

4. **Check for `.tq` files:**  The prompt specifically asks about `.tq` files. Review the provided snippet to see if any files with that extension are mentioned. In this case, there are none.

5. **Relate to JavaScript functionality:**  Since the tests involve JavaScript code, consider how the profiled scenarios relate to common JavaScript programming patterns. For instance, function calls, inlining, and interactions with native functions are standard JavaScript concepts.

6. **Provide JavaScript examples:** For the JavaScript-related tests, construct simple JavaScript code snippets that demonstrate the functionality being tested. This helps illustrate the concepts for someone familiar with JavaScript.

7. **Infer code logic and provide input/output examples:**  For tests involving specific code structures (like nested function calls or loops), imagine sample inputs and the expected output of the profiler (e.g., the call tree structure).

8. **Identify common programming errors:** Think about the types of errors a developer might encounter when writing JavaScript code that could be revealed by a CPU profiler (e.g., performance bottlenecks due to excessive function calls, inefficient loops).

9. **Address the "归纳一下它的功能" (Summarize its functionality) requirement:**  Condense the findings from the individual test analysis into a concise summary of the overall purpose and capabilities being tested in the code.

10. **Structure the response:** Organize the information clearly, addressing each part of the user's request (functionality listing, `.tq` check, JavaScript examples, code logic, common errors, and summary). Use headings and bullet points for readability.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  The code is just about basic profiling.
* **Correction:**  Realized that there are tests for more advanced scenarios like inlining, cross-script calls, and deoptimization, requiring a more nuanced explanation.
* **Initial thought:** Just list the test names.
* **Refinement:**  Provide a higher-level categorization of the tested features to make the information more digestible.
* **Initial thought:**  Provide very complex JavaScript examples.
* **Refinement:** Use simple, illustrative examples that directly relate to the C++ test cases.
这是 `v8/test/cctest/test-cpu-profiler.cc` 源代码的第 3 部分，它主要功能是测试 V8 引擎的 **CPU 性能分析器 (CPU profiler)** 的各种特性。

以下是这部分代码的具体功能归纳：

**核心功能：测试 CPU Profiler 的功能和正确性**

* **测试 JavaScript 与原生代码之间的多次调用和退出:**  `JsNativeRuntimeJsSampleMultiple` 测试了 JavaScript 代码调用原生 C++ 函数，原生 C++ 函数再调用回 JavaScript 代码的场景，并验证了性能分析器能否正确记录调用栈。
* **测试函数内联 (Inlining) 的性能分析:**  `Inlining` 和 `Inlining2` 测试了当 JavaScript 函数被编译器内联优化后，性能分析器是否能够正确地展现内联后的调用关系，并能追踪到原始的函数调用栈。这两个测试还特别关注了源代码位置的收集。
* **测试跨脚本 (Cross-Script) 内联的性能分析:** `CrossScriptInliningCallerLineNumbers` 和 `CrossScriptInliningCallerLineNumbers2` 测试了当函数内联发生在不同的 JavaScript 脚本文件之间时，性能分析器能否正确地记录调用者的源代码文件和行号。
* **测试空闲时间 (Idle Time) 的性能分析:** `IdleTime` 测试了性能分析器是否能正确地记录 V8 引擎处于空闲状态的时间。
* **测试函数详细信息 (Function Details) 的收集:** `FunctionDetails` 和 `FunctionDetailsInlining` 测试了性能分析器能否正确地收集函数的名称、所属脚本文件名、是否跨域共享、脚本 ID、行号和列号等详细信息，即使在函数被内联的情况下也能正确处理。
* **测试在 OSR (On-Stack Replacement，栈上替换) 优化后启动性能分析:** `StartProfilingAfterOsr` 测试了在代码被 OSR 优化之后再启动性能分析器，能否正确地采集到性能数据。目前的测试表明，对于在分析开始前进行 OSR 的代码，行为可能不完全符合预期。
* **测试删除已完成的性能分析记录不会导致错误:** `DontStopOnFinishedProfileDelete` 测试了正确管理性能分析记录的生命周期，确保删除已经停止的性能分析记录不会影响到其他正在进行的分析。
* **测试收集反优化 (Deoptimization) 事件:** `CollectDeoptEvents` 测试了性能分析器是否能够记录函数由于各种原因被反优化的事件，并能获取到反优化的原因。
* **测试源代码位置 (Source Location) 的处理:** `SourceLocation` 似乎是一个简单的测试，旨在确保在某些特定语法结构下（例如比较语句中使用 `this`），源代码位置的记录不会出错。
* **测试一级内联函数中的反优化事件:** `DeoptAtFirstLevelInlinedSource` 测试了当一个被内联的函数发生反优化时，性能分析器能否正确地记录这个事件。

**关于 `.tq` 结尾的文件:**

代码中没有出现以 `.tq` 结尾的文件名。因此，根据您的描述，这部分代码不是 V8 Torque 源代码。

**与 JavaScript 功能的关系及示例:**

这部分代码直接测试了与 JavaScript 运行时行为密切相关的功能，特别是：

* **函数调用:**  所有的测试都涉及到 JavaScript 函数的调用。
* **函数内联:** `Inlining`, `Inlining2`, `CrossScriptInliningCallerLineNumbers`, `CrossScriptInliningCallerLineNumbers2`, `FunctionDetailsInlining`, `DeoptAtFirstLevelInlinedSource` 等测试专门针对函数内联的场景。
* **跨原生代码调用:** `JsNativeRuntimeJsSampleMultiple` 测试了 JavaScript 与原生代码的交互。
* **优化和反优化:** `StartProfilingAfterOsr` 和 `CollectDeoptEvents` 测试了与 V8 引擎的优化和反优化机制的交互。

**JavaScript 示例:**

以下是一些与测试功能相关的 JavaScript 示例：

**函数内联:**

```javascript
function innerFunction(x) {
  return x * 2;
}

function outerFunction(y) {
  return innerFunction(y + 1); // innerFunction 很可能被内联到这里
}

startProfiling('inlining_test');
outerFunction(5);
stopProfiling('inlining_test');
```

**跨脚本调用:**

**script_a.js:**
```javascript
function action(n) {
  return n * n;
}
```

**script_b.js:**
```javascript
function level1(x) {
  return action(x) + 1; // 调用了 script_a.js 中的 action 函数
}

startProfiling('cross_script_test');
level1(10);
stopProfiling('cross_script_test');
```

**反优化:**

```javascript
function add(a, b) {
  return a + b;
}

%PrepareFunctionForOptimization(add);
add(1, 2); // 触发优化
add(1, 2);

startProfiling('deopt_test');
add(1, 'hello'); // 由于参数类型不一致，可能触发反优化
stopProfiling('deopt_test');
```

**代码逻辑推理及假设输入输出:**

以 `JsNativeRuntimeJsSampleMultiple` 测试为例：

**假设输入:**  执行 `start()` 函数。

**代码逻辑:**

1. `start()` 函数内部调用 `startProfiling('my_profile')` 启动性能分析。
2. 进入一个循环，持续 200 毫秒。
3. 在循环中，多次调用 `CallJsFunction(bar)`。
4. `CallJsFunction` 是一个原生 C++ 函数，它会调用 JavaScript 函数 `bar`。
5. `bar` 函数会调用 `foo.bind(this)()`，实际上是调用 `foo` 函数。
6. `foo` 函数返回一个随机数的正弦值。
7. 性能分析器会在整个过程中采样，记录函数调用栈。

**预期输出 (部分):**  性能分析结果的 Top-down 树应该包含以下节点，并且 Hit Count 符合预期：

```
(root)
  start
    CallJsFunction
      bar
        foo
(program)
```

**用户常见的编程错误:**

CPU profiler 经常用于诊断以下常见的编程错误：

* **性能瓶颈:**  分析结果可以显示哪些函数占用了最多的 CPU 时间，帮助开发者找到性能瓶颈。例如，在循环中执行了不必要的计算或 DOM 操作。
* **死循环或无限递归:**  性能分析器可能会显示某个函数被调用了极高的次数，提示可能存在死循环或无限递归。
* **过度调用某个函数:**  分析结果可以显示某个函数被频繁调用，但可能可以通过优化算法或缓存结果来减少调用次数。
* **意外的反优化:**  通过查看反优化事件，开发者可以了解哪些代码模式导致了性能下降，并进行相应的修改。

**示例：性能瓶颈**

```javascript
function processLargeArray(arr) {
  for (let i = 0; i < arr.length; i++) {
    // 假设这里有复杂的计算，导致性能问题
    let result = Math.sqrt(arr[i]) * Math.sin(arr[i]);
    console.log(result); // 假设这里有不必要的输出
  }
}

const largeArray = Array.from({ length: 10000 }, () => Math.random());

startProfiling('performance_issue');
processLargeArray(largeArray);
stopProfiling('performance_issue');
```

在这个例子中，性能分析器可能会指出 `processLargeArray` 函数占用了大量的 CPU 时间，开发者可以进一步分析循环内部的计算和 `console.log` 是否可以优化。

**总结:**

这部分 `v8/test/cctest/test-cpu-profiler.cc` 代码全面测试了 V8 引擎 CPU 性能分析器的核心功能，包括跨语言调用、函数内联、跨脚本分析、空闲时间记录、函数详细信息收集、与优化/反优化机制的交互以及基本的性能分析流程，旨在确保性能分析器能够准确可靠地为开发者提供性能分析数据。

### 提示词
```
这是目录为v8/test/cctest/test-cpu-profiler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-cpu-profiler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
de->GetChildrenCount());
  GetChild(env, start_node, "CallCollectSample");

  profile->Delete();
}

static const char* js_native_js_runtime_multiple_test_source =
    "%NeverOptimizeFunction(foo);\n"
    "%NeverOptimizeFunction(bar);\n"
    "%NeverOptimizeFunction(start);\n"
    "function foo() {\n"
    "  return Math.sin(Math.random());\n"
    "}\n"
    "var bound = foo.bind(this);\n"
    "function bar() {\n"
    "  return bound();\n"
    "}\n"
    "function start() {\n"
    "  startProfiling('my_profile');\n"
    "  var startTime = Date.now();\n"
    "  do {\n"
    "    CallJsFunction(bar);\n"
    "  } while (Date.now() - startTime < 200);\n"
    "}";

// The test check multiple entrances/exits between JS and native code.
//
// [Top down]:
//    (root) #0 1
//      start #16 3
//        CallJsFunction #0 4
//          bar #16 5
//            foo #16 6
//      (program) #0 2
TEST(JsNativeJsRuntimeJsSampleMultiple) {
  i::v8_flags.allow_natives_syntax = true;
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::Context> env = CcTest::NewContext({PROFILER_EXTENSION_ID});
  v8::Context::Scope context_scope(env);

  v8::Local<v8::FunctionTemplate> func_template =
      v8::FunctionTemplate::New(env->GetIsolate(), CallJsFunction);
  v8::Local<v8::Function> func =
      func_template->GetFunction(env).ToLocalChecked();
  func->SetName(v8_str("CallJsFunction"));
  env->Global()->Set(env, v8_str("CallJsFunction"), func).FromJust();

  CompileRun(js_native_js_runtime_multiple_test_source);

  ProfilerHelper helper(env);
  v8::Local<v8::Function> function = GetFunction(env, "start");
  v8::CpuProfile* profile = helper.Run(function, nullptr, 0, 500, 500);

  const v8::CpuProfileNode* root = profile->GetTopDownRoot();
  const v8::CpuProfileNode* start_node = GetChild(env, root, "start");
  const v8::CpuProfileNode* native_node =
      GetChild(env, start_node, "CallJsFunction");
  const v8::CpuProfileNode* bar_node = GetChild(env, native_node, "bar");
  GetChild(env, bar_node, "foo");

  profile->Delete();
}

static const char* inlining_test_source =
    "var finish = false;\n"
    "function action(n) {\n"
    "  var s = 0;\n"
    "  for (var i = 0; i < n; ++i) s += i*i*i;\n"
    "  if (finish)\n"
    "    startProfiling('my_profile');\n"
    "  return s;\n"
    "}\n"
    "function level3() { return action(100); }\n"
    "function level2() { return level3() * 2; }\n"
    "function level1() { return level2(); }\n"
    "function start() {\n"
    "  var n = 100;\n"
    "  while (--n)\n"
    "    level1();\n"
    "  finish = true;\n"
    "  level1();\n"
    "}"
    "%PrepareFunctionForOptimization(level1);\n"
    "%PrepareFunctionForOptimization(level2);\n"
    "%PrepareFunctionForOptimization(level3);\n"
    "%NeverOptimizeFunction(action);\n"
    "%NeverOptimizeFunction(start);\n"
    "level1();\n"
    "%OptimizeFunctionOnNextCall(level1);\n"
    "%OptimizeFunctionOnNextCall(level2);\n"
    "%OptimizeFunctionOnNextCall(level3);\n";

// The test check multiple entrances/exits between JS and native code.
//
// [Top down]:
//    (root) #0 1
//      start #16 3
//        level1 #0 4
//          level2 #16 5
//            level3 #16 6
//              action #16 7
//      (program) #0 2
TEST(Inlining) {
  if (!v8_flags.turbofan) return;
  if (v8_flags.optimize_on_next_call_optimizes_to_maglev) return;

  i::v8_flags.allow_natives_syntax = true;
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::Context> env = CcTest::NewContext({PROFILER_EXTENSION_ID});
  v8::Context::Scope context_scope(env);
  ProfilerHelper helper(env);
  // Ensure that source positions are collected everywhere.
  CcTest::i_isolate()->SetIsProfiling(true);

  CompileRun(inlining_test_source);
  v8::Local<v8::Function> function = GetFunction(env, "start");

  v8::Local<v8::String> profile_name = v8_str("my_profile");
  function->Call(env, env->Global(), 0, nullptr).ToLocalChecked();
  v8::CpuProfile* profile = helper.profiler()->StopProfiling(profile_name);
  CHECK(profile);
  // Dump collected profile to have a better diagnostic in case of failure.
  reinterpret_cast<i::CpuProfile*>(profile)->Print();

  const v8::CpuProfileNode* root = profile->GetTopDownRoot();
  const v8::CpuProfileNode* start_node = GetChild(env, root, "start");
  const v8::CpuProfileNode* level1_node = GetChild(env, start_node, "level1");
  const v8::CpuProfileNode* level2_node = GetChild(env, level1_node, "level2");
  const v8::CpuProfileNode* level3_node = GetChild(env, level2_node, "level3");
  GetChild(env, level3_node, "action");

  profile->Delete();
}

static const char* inlining_test_source2 = R"(
    function action(n) {
      var s = 0;
      for (var i = 0; i < n; ++i) s += i*i*i;
      return s;
    }
    function level4() {
      action(100);
      return action(100);
    }
    function level3() {
      const a = level4();
      const b = level4();
      return a + b * 1.1;
    }
    function level2() {
      return level3() * 2;
    }
    function level1() {
      action(1);
      action(200);
      action(1);
      return level2();
    }
    function start(n) {
      while (--n)
        level1();
    };
    %NeverOptimizeFunction(action);
    %NeverOptimizeFunction(start);
    %PrepareFunctionForOptimization(level1);
    %PrepareFunctionForOptimization(level2);
    %PrepareFunctionForOptimization(level3);
    %PrepareFunctionForOptimization(level4);
    level1();
    level1();
    %OptimizeFunctionOnNextCall(level1);
    %OptimizeFunctionOnNextCall(level2);
    %OptimizeFunctionOnNextCall(level3);
    %OptimizeFunctionOnNextCall(level4);
    level1();
  )";

// [Top down]:
//     0  (root):0 0 #1
//    13    start:34 6 #3
//              bailed out due to 'Optimization is always disabled'
//    19      level1:36 6 #4
//    16        action:29 6 #14
//                  bailed out due to 'Optimization is always disabled'
//  2748        action:30 6 #10
//                  bailed out due to 'Optimization is always disabled'
//    18        action:31 6 #15
//                  bailed out due to 'Optimization is always disabled'
//     0        level2:32 6 #5
//     0          level3:26 6 #6
//    12            level4:22 6 #11
//  1315              action:17 6 #13
//                        bailed out due to 'Optimization is always disabled'
//  1324              action:18 6 #12
//                        bailed out due to 'Optimization is always disabled'
//    16            level4:21 6 #7
//  1268              action:17 6 #9
//                        bailed out due to 'Optimization is always disabled'
//  1322              action:18 6 #8
//                        bailed out due to 'Optimization is always disabled'
//     2    (program):0 0 #2
TEST(Inlining2) {
  if (!v8_flags.turbofan) return;
  if (v8_flags.optimize_on_next_call_optimizes_to_maglev) return;
  // Skip test if concurrent sparkplug is enabled. The test becomes flaky,
  // since it requires a precise trace.
  if (v8_flags.concurrent_sparkplug) return;

  v8_flags.allow_natives_syntax = true;
  v8::Isolate* isolate = CcTest::isolate();
  LocalContext env;
  v8::CpuProfiler::UseDetailedSourcePositionsForProfiling(isolate);
  v8::HandleScope scope(isolate);
  ProfilerHelper helper(env.local());

  CompileRun(inlining_test_source2);
  v8::Local<v8::Function> function = GetFunction(env.local(), "start");

  v8::Local<v8::Value> args[] = {v8::Integer::New(env->GetIsolate(), 20)};
  static const unsigned min_samples = 4000;
  static const unsigned min_ext_samples = 0;
  v8::CpuProfile* profile =
      helper.Run(function, args, arraysize(args), min_samples, min_ext_samples,
                 v8::CpuProfilingMode::kCallerLineNumbers);
  CHECK(profile);

  const v8::CpuProfileNode* root = profile->GetTopDownRoot();
  const v8::CpuProfileNode* start_node = GetChild(env.local(), root, "start");

  NameLinePair l421_a17[] = {{"level1", 27},
                             {"level2", 23},
                             {"level3", 17},
                             {"level4", 12},
                             {"action", 8}};
  CheckBranch(start_node, l421_a17, arraysize(l421_a17));
  NameLinePair l422_a17[] = {{"level1", 27},
                             {"level2", 23},
                             {"level3", 17},
                             {"level4", 13},
                             {"action", 8}};
  CheckBranch(start_node, l422_a17, arraysize(l422_a17));

  NameLinePair l421_a18[] = {{"level1", 27},
                             {"level2", 23},
                             {"level3", 17},
                             {"level4", 12},
                             {"action", 9}};
  CheckBranch(start_node, l421_a18, arraysize(l421_a18));
  NameLinePair l422_a18[] = {{"level1", 27},
                             {"level2", 23},
                             {"level3", 17},
                             {"level4", 13},
                             {"action", 9}};
  CheckBranch(start_node, l422_a18, arraysize(l422_a18));

  NameLinePair action_direct[] = {{"level1", 27}, {"action", 21}};
  CheckBranch(start_node, action_direct, arraysize(action_direct));

  profile->Delete();
}

static const char* cross_script_source_a = R"(





    %NeverOptimizeFunction(action);
    function action(n) {
      var s = 0;
      for (var i = 0; i < n; ++i) s += i*i*i;
      return s;
    }
    function level1() {
      const a = action(1);
      const b = action(200);
      const c = action(1);
      return a + b + c;
    }
  )";

static const char* cross_script_source_b = R"(
    %PrepareFunctionForOptimization(start);
    %PrepareFunctionForOptimization(level1);
    start(1);
    start(1);
    %OptimizeFunctionOnNextCall(start);
    %OptimizeFunctionOnNextCall(level1);
    start(1);
    function start(n) {
      while (--n)
        level1();
    };
  )";

TEST(CrossScriptInliningCallerLineNumbers) {
  // Skip test if concurrent sparkplug is enabled. The test becomes flaky,
  // since it requires a precise trace.
  if (i::v8_flags.concurrent_sparkplug) return;

  i::v8_flags.allow_natives_syntax = true;
  v8::Isolate* isolate = CcTest::isolate();
  LocalContext env;
  v8::CpuProfiler::UseDetailedSourcePositionsForProfiling(isolate);
  v8::HandleScope scope(isolate);
  ProfilerHelper helper(env.local());

  v8::Local<v8::Script> script_a =
      CompileWithOrigin(cross_script_source_a, "script_a", false);
  v8::Local<v8::Script> script_b =
      CompileWithOrigin(cross_script_source_b, "script_b", false);

  script_a->Run(env.local()).ToLocalChecked();
  script_b->Run(env.local()).ToLocalChecked();

  v8::Local<v8::Function> function = GetFunction(env.local(), "start");

  v8::Local<v8::Value> args[] = {v8::Integer::New(env->GetIsolate(), 10)};
  static const unsigned min_samples = 1000;
  static const unsigned min_ext_samples = 0;
  v8::CpuProfile* profile =
      helper.Run(function, args, arraysize(args), min_samples, min_ext_samples,
                 v8::CpuProfilingMode::kCallerLineNumbers);
  CHECK(profile);

  const v8::CpuProfileNode* root = profile->GetTopDownRoot();
  const v8::CpuProfileNode* start_node = GetChild(env.local(), root, "start");
  CHECK_EQ(0, strcmp("script_b", start_node->GetScriptResourceNameStr()));

  NameLinePair l19_a10[] = {{"level1", 11}, {"action", 15}};
  CheckBranch(start_node, l19_a10, arraysize(l19_a10));

  const v8::CpuProfileNode* level1_node =
      GetChild(env.local(), start_node, "level1");
  CHECK_EQ(0, strcmp("script_a", level1_node->GetScriptResourceNameStr()));

  const v8::CpuProfileNode* action_node =
      GetChild(env.local(), level1_node, "action");
  CHECK_EQ(0, strcmp("script_a", action_node->GetScriptResourceNameStr()));

  profile->Delete();
}

static const char* cross_script_source_c = R"(
    function level3() {
      const a = action(1);
      const b = action(100);
      const c = action(1);
      return a + b + c;
    }
    %NeverOptimizeFunction(action);
    function action(n) {
      CallCollectSample();
      return n;
    }
  )";

static const char* cross_script_source_d = R"(
    function level2() {
      const p = level3();
      const q = level3();
      return p + q;
    }
  )";

static const char* cross_script_source_e = R"(
    function level1() {
      return level2() + 1000;
    }
  )";

static const char* cross_script_source_f = R"(
    %PrepareFunctionForOptimization(start);
    %PrepareFunctionForOptimization(level1);
    %PrepareFunctionForOptimization(level2);
    %PrepareFunctionForOptimization(level3);
    start(1);
    start(1);
    %OptimizeFunctionOnNextCall(start);
    %OptimizeFunctionOnNextCall(level1);
    %OptimizeFunctionOnNextCall(level2);
    %OptimizeFunctionOnNextCall(level3);
    start(1);
    function start(n) {
      while (--n)
        level1();
    };
  )";

TEST(CrossScriptInliningCallerLineNumbers2) {
  // Skip test if concurrent sparkplug is enabled. The test becomes flaky,
  // since it requires a precise trace.
  if (i::v8_flags.concurrent_sparkplug) return;

  i::v8_flags.allow_natives_syntax = true;
  LocalContext env;
  v8::HandleScope scope(CcTest::isolate());
  ProfilerHelper helper(env.local());

  // Install CollectSample callback for more deterministic sampling.
  InstallCollectSampleFunction(env.local());

  v8::Local<v8::Script> script_c =
      CompileWithOrigin(cross_script_source_c, "script_c", false);
  v8::Local<v8::Script> script_d =
      CompileWithOrigin(cross_script_source_d, "script_d", false);
  v8::Local<v8::Script> script_e =
      CompileWithOrigin(cross_script_source_e, "script_e", false);
  v8::Local<v8::Script> script_f =
      CompileWithOrigin(cross_script_source_f, "script_f", false);

  script_c->Run(env.local()).ToLocalChecked();
  script_d->Run(env.local()).ToLocalChecked();
  script_e->Run(env.local()).ToLocalChecked();
  script_f->Run(env.local()).ToLocalChecked();

  v8::Local<v8::Function> function = GetFunction(env.local(), "start");

  v8::Local<v8::Value> args[] = {v8::Integer::New(env->GetIsolate(), 10)};
  static const unsigned min_samples = 0;
  static const unsigned min_ext_samples = 0;
  v8::CpuProfile* profile =
      helper.Run(function, args, arraysize(args), min_samples, min_ext_samples,
                 v8::CpuProfilingMode::kCallerLineNumbers);
  CHECK(profile);

  const v8::CpuProfileNode* root = profile->GetTopDownRoot();
  const v8::CpuProfileNode* start_node = GetChild(env.local(), root, "start");
  CHECK_EQ(0, strcmp("script_f", start_node->GetScriptResourceNameStr()));

  const v8::CpuProfileNode* level1_node =
      GetChild(env.local(), start_node, "level1");
  CHECK_EQ(0, strcmp("script_e", level1_node->GetScriptResourceNameStr()));

  const v8::CpuProfileNode* level2_node =
      GetChild(env.local(), level1_node, "level2");
  CHECK_EQ(0, strcmp("script_d", level2_node->GetScriptResourceNameStr()));

  const v8::CpuProfileNode* level3_node =
      GetChild(env.local(), level2_node, "level3");
  CHECK_EQ(0, strcmp("script_c", level3_node->GetScriptResourceNameStr()));

  const v8::CpuProfileNode* action_node =
      GetChild(env.local(), level3_node, "action");
  CHECK_EQ(0, strcmp("script_c", action_node->GetScriptResourceNameStr()));

  profile->Delete();
}

// [Top down]:
//     0   (root) #0 1
//     2    (program) #0 2
//     3    (idle) #0 3
TEST(IdleTime) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::CpuProfiler* cpu_profiler = v8::CpuProfiler::New(env->GetIsolate());

  v8::Local<v8::String> profile_name = v8_str("my_profile");
  cpu_profiler->StartProfiling(profile_name);

  i::Isolate* isolate = CcTest::i_isolate();
  i::ProfilerEventsProcessor* processor =
      reinterpret_cast<i::CpuProfiler*>(cpu_profiler)->processor();

  processor->AddCurrentStack(true);
  isolate->SetIdle(true);
  for (int i = 0; i < 3; i++) {
    processor->AddCurrentStack(true);
  }
  isolate->SetIdle(false);
  processor->AddCurrentStack(true);

  v8::CpuProfile* profile = cpu_profiler->StopProfiling(profile_name);
  CHECK(profile);
  // Dump collected profile to have a better diagnostic in case of failure.
  reinterpret_cast<i::CpuProfile*>(profile)->Print();

  const v8::CpuProfileNode* root = profile->GetTopDownRoot();
  const v8::CpuProfileNode* program_node =
      GetChild(env.local(), root, CodeEntry::kProgramEntryName);
  CHECK_EQ(0, program_node->GetChildrenCount());
  CHECK_GE(program_node->GetHitCount(), 2u);

  const v8::CpuProfileNode* idle_node =
      GetChild(env.local(), root, CodeEntry::kIdleEntryName);
  CHECK_EQ(0, idle_node->GetChildrenCount());
  CHECK_GE(idle_node->GetHitCount(), 3u);

  profile->Delete();
  cpu_profiler->Dispose();
}

static void CheckFunctionDetails(v8::Isolate* isolate,
                                 const v8::CpuProfileNode* node,
                                 const char* name, const char* script_name,
                                 bool is_shared_cross_origin, int script_id,
                                 int line, int column,
                                 const v8::CpuProfileNode* parent) {
  v8::Local<v8::Context> context = isolate->GetCurrentContext();
  CHECK(v8_str(name)->Equals(context, node->GetFunctionName()).FromJust());
  CHECK_EQ(0, strcmp(name, node->GetFunctionNameStr()));
  CHECK(v8_str(script_name)
            ->Equals(context, node->GetScriptResourceName())
            .FromJust());
  CHECK_EQ(0, strcmp(script_name, node->GetScriptResourceNameStr()));
  CHECK_EQ(script_id, node->GetScriptId());
  CHECK_EQ(line, node->GetLineNumber());
  CHECK_EQ(column, node->GetColumnNumber());
  CHECK_EQ(parent, node->GetParent());
  CHECK_EQ(v8::CpuProfileNode::kScript, node->GetSourceType());
}

TEST(FunctionDetails) {
  i::v8_flags.allow_natives_syntax = true;
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::Context> env = CcTest::NewContext({PROFILER_EXTENSION_ID});
  v8::Context::Scope context_scope(env);
  ProfilerHelper helper(env);

  v8::Local<v8::Script> script_a = CompileWithOrigin(
      "%NeverOptimizeFunction(foo);\n"
      "%NeverOptimizeFunction(bar);\n"
      "    function foo\n() { bar(); }\n"
      " function bar() { startProfiling(); }\n",
      "script_a", false);
  script_a->Run(env).ToLocalChecked();
  v8::Local<v8::Script> script_b = CompileWithOrigin(
      "%NeverOptimizeFunction(baz);"
      "\n\n   function baz() { foo(); }\n"
      "\n\nbaz();\n"
      "stopProfiling();\n",
      "script_b", true);
  script_b->Run(env).ToLocalChecked();
  const v8::CpuProfile* profile = i::ProfilerExtension::last_profile;
  reinterpret_cast<const i::CpuProfile*>(profile)->Print();
  // The tree should look like this:
  //  0  (root):0 3 0 #1
  //  0    :0 0 5 #2 script_b:0
  //  0      baz:3 0 5 #3 script_b:3
  //             bailed out due to 'Optimization is always disabled'
  //  0        foo:4 0 4 #4 script_a:4
  //               bailed out due to 'Optimization is always disabled'
  //  0          bar:5 0 4 #5 script_a:5
  //                 bailed out due to 'Optimization is always disabled'
  //  0            startProfiling:0 2 0 #6
  const v8::CpuProfileNode* root = profile->GetTopDownRoot();
  CHECK_EQ(root->GetParent(), nullptr);
  const v8::CpuProfileNode* script = GetChild(env, root, "");
  CheckFunctionDetails(env->GetIsolate(), script, "", "script_b", true,
                       script_b->GetUnboundScript()->GetId(),
                       v8::CpuProfileNode::kNoLineNumberInfo,
                       CpuProfileNode::kNoColumnNumberInfo, root);
  const v8::CpuProfileNode* baz = GetChild(env, script, "baz");
  CheckFunctionDetails(env->GetIsolate(), baz, "baz", "script_b", true,
                       script_b->GetUnboundScript()->GetId(), 3, 16, script);
  const v8::CpuProfileNode* foo = GetChild(env, baz, "foo");
  CheckFunctionDetails(env->GetIsolate(), foo, "foo", "script_a", false,
                       script_a->GetUnboundScript()->GetId(), 4, 1, baz);
  const v8::CpuProfileNode* bar = GetChild(env, foo, "bar");
  CheckFunctionDetails(env->GetIsolate(), bar, "bar", "script_a", false,
                       script_a->GetUnboundScript()->GetId(), 5, 14, foo);
}

TEST(FunctionDetailsInlining) {
  if (!CcTest::i_isolate()->use_optimizer() || i::v8_flags.always_turbofan)
    return;
  i::v8_flags.allow_natives_syntax = true;
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::Context> env = CcTest::NewContext({PROFILER_EXTENSION_ID});
  v8::Context::Scope context_scope(env);
  ProfilerHelper helper(env);

  // alpha is in a_script, beta in b_script. beta is
  // inlined in alpha, but it should be attributed to b_script.

  v8::Local<v8::Script> script_b = CompileWithOrigin(
      "function beta(k) {\n"
      "  let sum = 2;\n"
      "  for(let i = 0; i < k; i ++) {\n"
      "    sum += i;\n"
      "    sum = sum + 'a';\n"
      "  }\n"
      "  return sum;\n"
      "}\n"
      "\n",
      "script_b", true);

  v8::Local<v8::Script> script_a = CompileWithOrigin(
      "function alpha(p) {\n"
      "  let res = beta(p);\n"
      "  res = res + res;\n"
      "  return res;\n"
      "}\n"
      "let p = 2;\n"
      "\n"
      "\n"
      "// Warm up before profiling or the inlining doesn't happen.\n"
      "%PrepareFunctionForOptimization(alpha);\n"
      "p = alpha(p);\n"
      "p = alpha(p);\n"
      "%OptimizeFunctionOnNextCall(alpha);\n"
      "p = alpha(p);\n"
      "\n"
      "\n"
      "startProfiling();\n"
      "for(let i = 0; i < 10000; i++) {\n"
      "  p = alpha(p);\n"
      "}\n"
      "stopProfiling();\n"
      "\n"
      "\n",
      "script_a", false);

  script_b->Run(env).ToLocalChecked();
  script_a->Run(env).ToLocalChecked();

  const v8::CpuProfile* profile = i::ProfilerExtension::last_profile;
  reinterpret_cast<const i::CpuProfile*>(profile)->Print();
  //   The tree should look like this:
  //  0  (root) 0 #1
  //  5    (program) 0 #6
  //  2     14 #2 script_a:0
  //    ;;; deopted at script_id: 14 position: 299 with reason 'Insufficient
  //    type feedback for call'.
  //  1      alpha 14 #4 script_a:1
  //  9        beta 13 #5 script_b:0
  //  0      startProfiling 0 #3

  const v8::CpuProfileNode* root = profile->GetTopDownRoot();
  CHECK_EQ(root->GetParent(), nullptr);
  const v8::CpuProfileNode* script = GetChild(env, root, "");
  CheckFunctionDetails(env->GetIsolate(), script, "", "script_a", false,
                       script_a->GetUnboundScript()->GetId(),
                       v8::CpuProfileNode::kNoLineNumberInfo,
                       v8::CpuProfileNode::kNoColumnNumberInfo, root);
  const v8::CpuProfileNode* alpha = FindChild(env, script, "alpha");
  // Return early if profiling didn't sample alpha.
  if (!alpha) return;
  CheckFunctionDetails(env->GetIsolate(), alpha, "alpha", "script_a", false,
                       script_a->GetUnboundScript()->GetId(), 1, 15, script);
  const v8::CpuProfileNode* beta = FindChild(env, alpha, "beta");
  if (!beta) return;
  CheckFunctionDetails(env->GetIsolate(), beta, "beta", "script_b", true,
                       script_b->GetUnboundScript()->GetId(), 1, 14, alpha);
}

static const char* pre_profiling_osr_script = R"(
    const kMinIterationDurationMs = 1;
    function whenPass(pass, optDuration) {
      if (pass == 5) startProfiling();
    }
    function hot(optDuration, deoptDuration) {
      %PrepareFunctionForOptimization(hot);
      for (let pass = 0; pass <= optDuration + deoptDuration; pass++) {
        const startTime = Date.now();
        // Let a few passes go by to ensure we have enough feeback info
        if (pass == 3) %OptimizeOsr();
        // Force deoptimization. %DeoptimizeNow and %DeoptimizeFunction don't
        // doptimize OSRs.
        if (pass == optDuration) whenPass = () => {};
        whenPass(pass, optDuration);
        while (Date.now() - startTime < kMinIterationDurationMs) {
          for (let j = 0; j < 1000; j++) {
            x = Math.random() * j;
          }
        }
      }
    }
    function notHot(optDuration, deoptDuration) {
      hot(optDuration, deoptDuration);
      stopProfiling()
    }
  )";

// Testing profiling of OSR code that was OSR optimized before profiling
// started. Currently the behavior is not quite right so we're currently
// testing a deopt event being sent to the sampling thread for a function
// it knows nothing about. This deopt does mean we start getting samples
// for hot so we expect some samples, just fewer than for notHot.
//
// We should get something like:
//     0  (root):0 3 0 #1
//    12    (garbage collector):0 3 0 #5
//     5    notHot:22 0 4 #2
//    85      hot:5 0 4 #6
//     0      whenPass:2 0 4 #3
//     0        startProfiling:0 2 0 #4
//
// But currently get something like:
//     0  (root):0 3 0 #1
//    12    (garbage collector):0 3 0 #5
//    57    notHot:22 0 4 #2
//    33      hot:5 0 4 #6
//     0      whenPass:2 0 4 #3
//     0        startProfiling:0 2 0 #4

TEST(StartProfilingAfterOsr) {
  i::v8_flags.allow_natives_syntax = true;
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::Context> env = CcTest::NewContext({PROFILER_EXTENSION_ID});
  v8::Context::Scope context_scope(env);
  ProfilerHelper helper(env);
  helper.profiler()->SetSamplingInterval(100);
  CompileRun(pre_profiling_osr_script);
  v8::Local<v8::Function> function = GetFunction(env, "notHot");

  int32_t profiling_optimized_ms = 120;
  int32_t profiling_deoptimized_ms = 40;
  v8::Local<v8::Value> args[] = {
      v8::Integer::New(env->GetIsolate(), profiling_optimized_ms),
      v8::Integer::New(env->GetIsolate(), profiling_deoptimized_ms)};
  function->Call(env, env->Global(), arraysize(args), args).ToLocalChecked();
  const v8::CpuProfile* profile = i::ProfilerExtension::last_profile;
  CHECK(profile);
  reinterpret_cast<const i::CpuProfile*>(profile)->Print();

  const CpuProfileNode* root = profile->GetTopDownRoot();
  const v8::CpuProfileNode* notHotNode = GetChild(env, root, "notHot");
  const v8::CpuProfileNode* hotNode = GetChild(env, notHotNode, "hot");
  USE(hotNode);
  // If/when OSR sampling is fixed the following CHECK_GT could/should be
  // uncommented and the node = node line deleted.
  // CHECK_GT(hotNode->GetHitCount(), notHotNode->GetHitCount());
}

TEST(DontStopOnFinishedProfileDelete) {
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::Context> env = CcTest::NewContext({PROFILER_EXTENSION_ID});
  v8::Context::Scope context_scope(env);

  v8::CpuProfiler* profiler = v8::CpuProfiler::New(env->GetIsolate());
  i::CpuProfiler* iprofiler = reinterpret_cast<i::CpuProfiler*>(profiler);

  CHECK_EQ(0, iprofiler->GetProfilesCount());
  v8::Local<v8::String> outer = v8_str("outer");
  profiler->StartProfiling(outer);
  CHECK_EQ(0, iprofiler->GetProfilesCount());

  v8::Local<v8::String> inner = v8_str("inner");
  profiler->StartProfiling(inner);
  CHECK_EQ(0, iprofiler->GetProfilesCount());

  v8::CpuProfile* inner_profile = profiler->StopProfiling(inner);
  CHECK(inner_profile);
  CHECK_EQ(1, iprofiler->GetProfilesCount());
  inner_profile->Delete();
  inner_profile = nullptr;
  CHECK_EQ(0, iprofiler->GetProfilesCount());

  v8::CpuProfile* outer_profile = profiler->StopProfiling(outer);
  CHECK(outer_profile);
  CHECK_EQ(1, iprofiler->GetProfilesCount());
  outer_profile->Delete();
  outer_profile = nullptr;
  CHECK_EQ(0, iprofiler->GetProfilesCount());
  profiler->Dispose();
}

const char* GetBranchDeoptReason(v8::Local<v8::Context> context,
                                 i::CpuProfile* iprofile, const char* branch[],
                                 int length) {
  v8::CpuProfile* profile = reinterpret_cast<v8::CpuProfile*>(iprofile);
  const ProfileNode* iopt_function = nullptr;
  iopt_function = GetSimpleBranch(context, profile, branch, length);
  if (iopt_function->deopt_infos().size() == 0) {
    iopt_function = iopt_function->parent();
  }
  CHECK_LE(1U, iopt_function->deopt_infos().size());
  return iopt_function->deopt_infos()[0].deopt_reason;
}

// deopt at top function
TEST(CollectDeoptEvents) {
  if (!CcTest::i_isolate()->use_optimizer() || i::v8_flags.always_turbofan) {
    return;
  }
  i::v8_flags.allow_natives_syntax = true;
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::Context> env = CcTest::NewContext({PROFILER_EXTENSION_ID});
  v8::Context::Scope context_scope(env);
  ProfilerHelper helper(env);
  i::CpuProfiler* iprofiler =
      reinterpret_cast<i::CpuProfiler*>(helper.profiler());

  const char opt_source[] =
      "function opt_function%d(value, depth) {\n"
      "  if (depth) return opt_function%d(value, depth - 1);\n"
      "\n"
      "  return  10 / value;\n"
      "}\n"
      "\n";

  for (int i = 0; i < 3; ++i) {
    base::EmbeddedVector<char, sizeof(opt_source) + 100> buffer;
    base::SNPrintF(buffer, opt_source, i, i);
    v8::Script::Compile(env, v8_str(buffer.begin()))
        .ToLocalChecked()
        ->Run(env)
        .ToLocalChecked();
  }

  const char* source =
      "startProfiling();\n"
      "\n"
      "%PrepareFunctionForOptimization(opt_function0);\n"
      "\n"
      "opt_function0(1, 1);\n"
      "\n"
      "%OptimizeFunctionOnNextCall(opt_function0)\n"
      "\n"
      "opt_function0(1, 1);\n"
      "\n"
      "opt_function0(undefined, 1);\n"
      "\n"
      "%PrepareFunctionForOptimization(opt_function1);\n"
      "\n"
      "opt_function1(1, 1);\n"
      "\n"
      "%OptimizeFunctionOnNextCall(opt_function1)\n"
      "\n"
      "opt_function1(1, 1);\n"
      "\n"
      "opt_function1(NaN, 1);\n"
      "\n"
      "%PrepareFunctionForOptimization(opt_function2);\n"
      "\n"
      "opt_function2(1, 1);\n"
      "\n"
      "%OptimizeFunctionOnNextCall(opt_function2)\n"
      "\n"
      "opt_function2(1, 1);\n"
      "\n"
      "opt_function2(0, 1);\n"
      "\n"
      "stopProfiling();\n"
      "\n";

  v8::Script::Compile(env, v8_str(source))
      .ToLocalChecked()
      ->Run(env)
      .ToLocalChecked();
  i::CpuProfile* iprofile = iprofiler->GetProfile(0);
  iprofile->Print();
  /* The expected profile. Note that the deopt reasons can hang off either of
     the two nodes for each function, depending on the exact timing at runtime.
  [Top down]:
      0  (root) 0 #1
     23     32 #2
      1      opt_function2 31 #7
      1        opt_function2 31 #8
                  ;;; deopted at script_id: 31 position: 106 with reason
  'division by zero'.
      2      opt_function0 29 #3
      4        opt_function0 29 #4
                  ;;; deopted at script_id: 29 position: 108 with reason 'not a
  heap number'.
      0      opt_function1 30 #5
      1        opt_function1 30 #6
                  ;;; deopted at script_id: 30 position: 108 with reason 'lost
  precision or NaN'.
  */

  {
    const char* branch[] = {"", "opt_function0", "opt_function0"};
    const char* deopt_reason =
        GetBranchDeoptReason(env, iprofile, branch, arraysize(branch));
    if (deopt_reason != reason(i::DeoptimizeReason::kNotAHeapNumber) &&
        deopt_reason != reason(i::DeoptimizeReason::kNotASmi)) {
      FATAL("%s", deopt_reason);
    }
  }
  {
    const char* branch[] = {"", "opt_function1", "opt_function1"};
    const char* deopt_reason =
        GetBranchDeoptReason(env, iprofile, branch, arraysize(branch));
    if (deopt_reason != reason(i::DeoptimizeReason::kNaN) &&
        deopt_reason != reason(i::DeoptimizeReason::kLostPrecisionOrNaN) &&
        deopt_reason != reason(i::DeoptimizeReason::kNotASmi)) {
      FATAL("%s", deopt_reason);
    }
  }
  {
    const char* branch[] = {"", "opt_function2", "opt_function2"};
    const char* deopt_reason =
        GetBranchDeoptReason(env, iprofile, branch, arraysize(branch));
    if (deopt_reason != reason(i::DeoptimizeReason::kDivisionByZero) &&
        deopt_reason != reason(i::DeoptimizeReason::kNotInt32)) {
      FATAL("%s", deopt_reason);
    }
  }
  iprofiler->DeleteProfile(iprofile);
}

TEST(SourceLocation) {
  i::v8_flags.always_turbofan = true;
  LocalContext env;
  v8::HandleScope scope(CcTest::isolate());

  const char* source =
      "function CompareStatementWithThis() {\n"
      "  if (this === 1) {}\n"
      "}\n"
      "CompareStatementWithThis();\n";

  v8::Script::Compile(env.local(), v8_str(source))
      .ToLocalChecked()
      ->Run(env.local())
      .ToLocalChecked();
}

static const char* inlined_source =
    "function opt_function(left, right) { var k = left*right; return k + 1; "
    "}\n";
//   0.........1.........2.........3.........4....*....5.........6......*..7

// deopt at the first level inlined function
TEST(DeoptAtFirstLevelInlinedSource) {
  if (!CcTest::i_isolate()->use_optimizer() || i::v8_flags.always_turbofan)
    return;
  i::v8_flags.allow_natives_syntax = true;
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::Context> env = CcTest::NewContext({PROFILER_EXTENSION_ID});
  v8::C
```