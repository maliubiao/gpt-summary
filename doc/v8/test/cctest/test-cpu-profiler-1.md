Response: The user wants a summary of the functionality of the provided C++ code snippet, which is part of the `test-cpu-profiler.cc` file. They have explicitly asked for the functionality and its relationship with JavaScript, providing JavaScript examples if applicable. This is the second part of a three-part request, so the focus should remain on the content within this specific part.

The code contains several test cases for the V8 CPU profiler. Each `TEST()` block focuses on a specific aspect of the profiler. Key functionalities being tested in this section include:

1. **Profiling JavaScript calls to native functions and back to JavaScript:** Tests scenarios where the execution flow moves between JavaScript and native C++ code.
2. **Profiling with inlining:** Examines how inlined JavaScript functions are represented in the profiler output, including caller line numbers and script information.
3. **Profiling across different scripts:** Verifies that the profiler correctly attributes execution time and function calls when the code is spread across multiple JavaScript files.
4. **Profiling idle time:** Checks if the profiler can capture periods where the JavaScript engine is idle.
5. **Capturing detailed function information:** Ensures that the profiler records accurate function names, script names, script IDs, line numbers, and column numbers.
6. **Handling inlining in function details:**  Tests if inlined functions in different scripts have their details correctly recorded.
7. **Profiling OSR (On-Stack Replacement) code:** Investigates how code that has been optimized mid-execution is represented in the profile.
8. **Managing multiple profiles:**  Tests the ability to start and stop multiple profiling sessions without issues.
9. **Collecting deoptimization events:** Verifies that the profiler captures and reports when optimized code is deoptimized, including the reason for deoptimization and the stack trace.
10. **Handling deoptimization in inlined functions:**  Tests that deoptimization information is correctly associated with inlined functions.
11. **Dealing with deoptimization in untracked functions:** Checks the behavior when deoptimization happens in a function that wasn't being actively profiled at the time of optimization.
12. **Using the tracing API for CPU profiling:** Explores the integration of the CPU profiler with the V8 tracing infrastructure.
13. **Handling deoptimization after closure creation:** Tests a specific scenario involving closure creation, optimization, and deoptimization.
14. **Using the static `v8::CpuProfiler::CollectSample` API:**  Checks the functionality of manually triggering a sample collection.
15. **Preventing memory leaks in code entry tracking:**  Ensures that the profiler doesn't leak memory when dealing with a large number of functions.
16. **Handling native frames without exit frames:**  Addresses a potential issue where stack unwinding might fail in certain native function calls.
17. **Testing the `SourcePositionTable`:** Verifies the correctness of the internal data structure used for mapping bytecode offsets to source code locations.
18. **Managing multiple profiler instances:**  Checks that multiple `CpuProfiler` instances can operate independently.
19. **Handling reused profilers:** Ensures that a `CpuProfiler` can be used multiple times without crashing.
20. **Preventing cross-profiler sample leakage:** Verifies that samples collected by one profiler are not accidentally attributed to another.
21. **Profiling code on different isolates:** Tests the profiler's behavior when used in a multi-isolate environment.
22. **Profiling with varying frame sizes:** Checks for issues that might arise when profiling functions with different stack frame sizes.
23. **Testing fast stop profiling:** Ensures that stopping a profile doesn't wait for the full sampling interval.
24. **Enforcing the maximum number of simultaneous profiles:**  Verifies that the profiler limits the number of concurrent profiling sessions.
25. **Testing low-precision sampling:** Checks the basic start and stop functionality of the profiler when using low-precision sampling.
26. **Standard naming of functions:** Tests how function names are represented in the profile when assigned to object properties.
The C++ code snippet you provided is a part of the V8 JavaScript engine's test suite, specifically for the CPU profiler. This section focuses on testing various aspects of how the profiler interacts with JavaScript code execution, including:

**Key Functionalities Being Tested:**

*   **Profiling transitions between JavaScript and native code:**  It tests scenarios where JavaScript code calls native C++ functions (like `CallJsFunction` in the example) and how the profiler captures these transitions.
*   **Profiling inlined functions:** It verifies how the profiler represents inlined JavaScript function calls, including tracking the source code locations correctly even when functions are inlined. This includes testing the accuracy of caller line numbers in inlined scenarios.
*   **Profiling across different JavaScript files (cross-script inlining):** It checks if the profiler can accurately track function calls and their origins when the code is split across multiple `<script>` tags or files.
*   **Profiling of code optimized with OSR (On-Stack Replacement):** It explores how the profiler behaves when profiling code that has been optimized during its execution.
*   **Collecting and reporting deoptimization events:** The tests verify that when optimized JavaScript code is deoptimized (reverted to a less optimized state), the profiler captures this event and the reason for deoptimization, including stack information.
*   **Integration with the Tracing API:** The code tests how the CPU profiler integrates with V8's tracing infrastructure, allowing profiling data to be captured as trace events.
*   **Handling multiple concurrent profiling sessions:** It checks the ability to start and stop multiple profiles simultaneously.
*   **Using the `v8::CpuProfiler::CollectSample()` API:** The tests demonstrate how to manually trigger a CPU sample collection from C++ or JavaScript.
*   **Ensuring no memory leaks:** There are tests to verify that the profiler does not leak memory when dealing with various scenarios, like tracking code entries.
*   **Handling specific edge cases:**  For instance, a test addresses a scenario where native function calls might not have a corresponding "exit" frame, which could lead to incomplete stack traces.
*   **Testing internal data structures:**  A test specifically checks the functionality of the `SourcePositionTable`, which maps bytecode offsets to source code locations.
*   **Testing the behavior of reused profiler instances.**
*   **Verifying that different profiler instances on the same isolate collect samples independently.**
*   **Testing the profiler's behavior in multi-isolate scenarios.**
*   **Handling profiling with varying JavaScript function frame sizes.**
*   **Ensuring that `StopProfiling` doesn't unnecessarily wait for the next sample tick.**
*   **Enforcing a limit on the maximum number of simultaneous active profiles.**
*   **Testing low-precision sampling mode.**
*   **Verifying standard function naming in profiles.**

**Relationship with JavaScript (with examples):**

The primary purpose of the CPU profiler is to analyze the performance of JavaScript code. The C++ tests interact with JavaScript code by:

1. **Compiling and running JavaScript code:**  The tests use V8's API to compile and execute JavaScript source code strings.
2. **Using the Profiler Extension API:**  The tests utilize the `%startProfiling()` and `%stopProfiling()` intrinsics (often enabled by `PROFILER_EXTENSION_ID`) within the JavaScript code to control the profiler.
3. **Accessing profiler data:**  After profiling, the tests retrieve and inspect the `v8::CpuProfile` object to verify the collected data.
4. **Injecting native functions:**  The tests can define native C++ functions and expose them to JavaScript (like `CallJsFunction` and `CallStaticCollectSample`) to simulate interactions between JavaScript and native code.

Here are some examples illustrating the connection, based on the provided code:

**1. Profiling JavaScript calling a native function:**

```javascript
// JavaScript code
function start() {
  startProfiling('my_profile');
  CallJsFunction(10); // Calls the native C++ function
  stopProfiling('my_profile');
}
```

The corresponding C++ test (`JsNativeRuntimeJsSample`) sets up the native function `CallJsFunction` and then runs the JavaScript code, expecting the profiler output to show the call stack involving both JavaScript (`start`) and the native function (`CallJsFunction`).

**2. Profiling inlined JavaScript functions:**

```javascript
// JavaScript code
function action(n) {
  // ... some code ...
}
function level3() { return action(100); }
function level2() { return level3() * 2; }
function level1() { return level2(); }
function start() {
  level1(); // This might get inlined
}

%PrepareFunctionForOptimization(level1);
%PrepareFunctionForOptimization(level2);
%PrepareFunctionForOptimization(level3);
%NeverOptimizeFunction(action);
%NeverOptimizeFunction(start);
%OptimizeFunctionOnNextCall(level1);
%OptimizeFunctionOnNextCall(level2);
%OptimizeFunctionOnNextCall(level3);
startProfiling('my_profile');
start();
stopProfiling('my_profile');
```

The C++ test (`Inlining`) runs this JavaScript code and then examines the generated CPU profile to ensure that the inlined calls to `level2`, `level3`, and `action` are correctly represented in the profile tree under `start`.

**3. Manually collecting a sample from JavaScript:**

```javascript
// JavaScript code
function start() {
  CallCollectSample(); // Calls the native function to collect a sample
}
```

The C++ test (`CollectSample`) sets up the `CallCollectSample` native function and verifies that calling it from JavaScript results in a sample being recorded in the CPU profile.

In essence, this C++ code acts as a rigorous testing framework for the V8 CPU profiler, simulating various JavaScript execution scenarios and validating that the profiler captures accurate and detailed performance information. The JavaScript examples within the C++ code define the workloads that the profiler is being tested against.

### 提示词
```
这是目录为v8/test/cctest/test-cpu-profiler.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```
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
  v8::Context::Scope context_scope(env);
  ProfilerHelper helper(env);
  i::CpuProfiler* iprofiler =
      reinterpret_cast<i::CpuProfiler*>(helper.profiler());

  //   0.........1.........2.........3.........4.........5.........6.........7
  const char* source =
      "function test(left, right) { return opt_function(left, right); }\n"
      "\n"
      "startProfiling();\n"
      "\n"
      "%EnsureFeedbackVectorForFunction(opt_function);\n"
      "%PrepareFunctionForOptimization(test);\n"
      "\n"
      "test(10, 10);\n"
      "\n"
      "%OptimizeFunctionOnNextCall(test)\n"
      "\n"
      "test(10, 10);\n"
      "\n"
      "test(undefined, 1e9);\n"
      "\n"
      "stopProfiling();\n"
      "\n";

  v8::Local<v8::Script> inlined_script = v8_compile(inlined_source);
  inlined_script->Run(env).ToLocalChecked();
  int inlined_script_id = inlined_script->GetUnboundScript()->GetId();

  v8::Local<v8::Script> script = v8_compile(source);
  script->Run(env).ToLocalChecked();
  int script_id = script->GetUnboundScript()->GetId();

  i::CpuProfile* iprofile = iprofiler->GetProfile(0);
  iprofile->Print();
  /* The expected profile output
  [Top down]:
      0  (root) 0 #1
     10     30 #2
      1      test 30 #3
                ;;; deopted at script_id: 29 position: 45 with reason 'not a
  heap number'.
                ;;;     Inline point: script_id 30 position: 36.
      4        opt_function 29 #4
  */
  v8::CpuProfile* profile = reinterpret_cast<v8::CpuProfile*>(iprofile);

  const char* branch[] = {"", "test"};
  const ProfileNode* itest_node =
      GetSimpleBranch(env, profile, branch, arraysize(branch));
  const std::vector<v8::CpuProfileDeoptInfo>& deopt_infos =
      itest_node->deopt_infos();
  CHECK_EQ(1U, deopt_infos.size());

  const v8::CpuProfileDeoptInfo& info = deopt_infos[0];
  CHECK(reason(i::DeoptimizeReason::kNotASmi) == info.deopt_reason ||
        reason(i::DeoptimizeReason::kNotAHeapNumber) == info.deopt_reason);
  CHECK_EQ(2U, info.stack.size());
  CHECK_EQ(inlined_script_id, info.stack[0].script_id);
  CHECK_LE(dist(offset(inlined_source, "*right"), info.stack[0].position), 1);
  CHECK_EQ(script_id, info.stack[1].script_id);
  CHECK_EQ(offset(source, "opt_function(left,"), info.stack[1].position);

  iprofiler->DeleteProfile(iprofile);
}

// deopt at the second level inlined function
TEST(DeoptAtSecondLevelInlinedSource) {
  if (!CcTest::i_isolate()->use_optimizer() || i::v8_flags.always_turbofan)
    return;
  i::v8_flags.allow_natives_syntax = true;
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::Context> env = CcTest::NewContext({PROFILER_EXTENSION_ID});
  v8::Context::Scope context_scope(env);
  ProfilerHelper helper(env);
  i::CpuProfiler* iprofiler =
      reinterpret_cast<i::CpuProfiler*>(helper.profiler());

  //   0.........1.........2.........3.........4.........5.........6.........7
  const char* source =
      "function test2(left, right) { return opt_function(left, right); }\n"
      "function test1(left, right) { return test2(left, right); } \n"
      "\n"
      "startProfiling();\n"
      "\n"
      "%EnsureFeedbackVectorForFunction(opt_function);\n"
      "%EnsureFeedbackVectorForFunction(test2);\n"
      "%PrepareFunctionForOptimization(test1);\n"
      "\n"
      "test1(10, 10);\n"
      "\n"
      "%OptimizeFunctionOnNextCall(test1)\n"
      "\n"
      "test1(10, 10);\n"
      "\n"
      "test1(undefined, 1e9);\n"
      "\n"
      "stopProfiling();\n"
      "\n";

  v8::Local<v8::Script> inlined_script = v8_compile(inlined_source);
  inlined_script->Run(env).ToLocalChecked();
  int inlined_script_id = inlined_script->GetUnboundScript()->GetId();

  v8::Local<v8::Script> script = v8_compile(source);
  script->Run(env).ToLocalChecked();
  int script_id = script->GetUnboundScript()->GetId();

  i::CpuProfile* iprofile = iprofiler->GetProfile(0);
  iprofile->Print();
  /* The expected profile output
  [Top down]:
      0  (root) 0 #1
     11     30 #2
      1      test1 30 #3
                ;;; deopted at script_id: 29 position: 45 with reason 'not a
  heap number'.
                ;;;     Inline point: script_id 30 position: 37.
                ;;;     Inline point: script_id 30 position: 103.
      1        test2 30 #4
      3          opt_function 29 #5
  */

  v8::CpuProfile* profile = reinterpret_cast<v8::CpuProfile*>(iprofile);

  const char* branch[] = {"", "test1"};
  const ProfileNode* itest_node =
      GetSimpleBranch(env, profile, branch, arraysize(branch));
  const std::vector<v8::CpuProfileDeoptInfo>& deopt_infos =
      itest_node->deopt_infos();
  CHECK_EQ(1U, deopt_infos.size());

  const v8::CpuProfileDeoptInfo info = deopt_infos[0];
  CHECK(reason(i::DeoptimizeReason::kNotASmi) == info.deopt_reason ||
        reason(i::DeoptimizeReason::kNotAHeapNumber) == info.deopt_reason);
  CHECK_EQ(3U, info.stack.size());
  CHECK_EQ(inlined_script_id, info.stack[0].script_id);
  CHECK_LE(dist(offset(inlined_source, "*right"), info.stack[0].position), 1);
  CHECK_EQ(script_id, info.stack[1].script_id);
  CHECK_EQ(offset(source, "opt_function(left,"), info.stack[1].position);
  CHECK_EQ(offset(source, "test2(left, right);"), info.stack[2].position);

  iprofiler->DeleteProfile(iprofile);
}

// deopt in untracked function
TEST(DeoptUntrackedFunction) {
  if (!CcTest::i_isolate()->use_optimizer() || i::v8_flags.always_turbofan)
    return;
  i::v8_flags.allow_natives_syntax = true;
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::Context> env = CcTest::NewContext({PROFILER_EXTENSION_ID});
  v8::Context::Scope context_scope(env);
  ProfilerHelper helper(env);
  i::CpuProfiler* iprofiler =
      reinterpret_cast<i::CpuProfiler*>(helper.profiler());

  //   0.........1.........2.........3.........4.........5.........6.........7
  const char* source =
      "function test(left, right) { return opt_function(left, right); }\n"
      "\n"
      "%EnsureFeedbackVectorForFunction(opt_function);"
      "%PrepareFunctionForOptimization(test);\n"
      "\n"
      "test(10, 10);\n"
      "\n"
      "%OptimizeFunctionOnNextCall(test)\n"
      "\n"
      "test(10, 10);\n"
      "\n"
      "startProfiling();\n"  // profiler started after compilation.
      "\n"
      "test(undefined, 10);\n"
      "\n"
      "stopProfiling();\n"
      "\n";

  v8::Local<v8::Script> inlined_script = v8_compile(inlined_source);
  inlined_script->Run(env).ToLocalChecked();

  v8::Local<v8::Script> script = v8_compile(source);
  script->Run(env).ToLocalChecked();

  i::CpuProfile* iprofile = iprofiler->GetProfile(0);
  iprofile->Print();
  v8::CpuProfile* profile = reinterpret_cast<v8::CpuProfile*>(iprofile);

  const char* branch[] = {"", "test"};
  const ProfileNode* itest_node =
      GetSimpleBranch(env, profile, branch, arraysize(branch));
  CHECK_EQ(0U, itest_node->deopt_infos().size());

  iprofiler->DeleteProfile(iprofile);
}

using v8::platform::tracing::TraceBuffer;
using v8::platform::tracing::TraceConfig;
using v8::platform::tracing::TraceObject;

namespace {

#ifdef V8_USE_PERFETTO
class CpuProfilerListener : public platform::tracing::TraceEventListener {
 public:
  void ParseFromArray(const std::vector<char>& array) {
    perfetto::protos::Trace trace;
    CHECK(trace.ParseFromArray(array.data(), static_cast<int>(array.size())));

    for (int i = 0; i < trace.packet_size(); i++) {
      // TODO(petermarshall): ChromeTracePacket instead.
      const perfetto::protos::TracePacket& packet = trace.packet(i);
      ProcessPacket(packet);
    }
  }

  const std::string& result_json() {
    result_json_ += "]";
    return result_json_;
  }
  void Reset() {
    result_json_.clear();
    profile_id_ = 0;
    sequence_state_.clear();
  }

 private:
  void ProcessPacket(const ::perfetto::protos::TracePacket& packet) {
    auto& seq_state = sequence_state_[packet.trusted_packet_sequence_id()];
    if (packet.incremental_state_cleared()) seq_state = SequenceState{};

    if (!packet.has_track_event()) return;

    // Update incremental state.
    if (packet.has_interned_data()) {
      const auto& interned_data = packet.interned_data();
      for (const auto& it : interned_data.event_names()) {
        CHECK_EQ(seq_state.event_names_.find(it.iid()),
                 seq_state.event_names_.end());
        seq_state.event_names_[it.iid()] = it.name();
      }
    }
    const auto& track_event = packet.track_event();
    auto name = seq_state.event_names_[track_event.name_iid()];
    if (name != "Profile" && name != "ProfileChunk") return;

    CHECK_EQ(1, track_event.debug_annotations_size());
    CHECK(track_event.debug_annotations()[0].has_legacy_json_value());
    CHECK(!profile_id_ ||
          track_event.legacy_event().unscoped_id() == profile_id_);
    profile_id_ = track_event.legacy_event().unscoped_id();
    result_json_ += result_json_.empty() ? "[" : ",\n";
    result_json_ += track_event.debug_annotations()[0].legacy_json_value();
  }

  std::string result_json_;
  uint64_t profile_id_ = 0;

  struct SequenceState {
    std::map<uint64_t, std::string> event_names_;
  };
  std::map<uint32_t, SequenceState> sequence_state_;
};

#else

class CpuProfileEventChecker : public v8::platform::tracing::TraceWriter {
 public:
  void AppendTraceEvent(TraceObject* trace_event) override {
    if (trace_event->name() != std::string("Profile") &&
        trace_event->name() != std::string("ProfileChunk"))
      return;
    CHECK(!profile_id_ || trace_event->id() == profile_id_);
    CHECK_EQ(1, trace_event->num_args());
    CHECK_EQ(TRACE_VALUE_TYPE_CONVERTABLE, trace_event->arg_types()[0]);
    profile_id_ = trace_event->id();
    v8::ConvertableToTraceFormat* arg =
        trace_event->arg_convertables()[0].get();
    result_json_ += result_json_.empty() ? "[" : ",\n";
    arg->AppendAsTraceFormat(&result_json_);
  }
  void Flush() override { result_json_ += "]"; }

  const std::string& result_json() const { return result_json_; }
  void Reset() {
    result_json_.clear();
    profile_id_ = 0;
  }

 private:
  std::string result_json_;
  uint64_t profile_id_ = 0;
};

#endif  // !V8_USE_PERFETTO

}  // namespace

TEST(TracingCpuProfiler) {
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::Context> env = CcTest::NewContext({PROFILER_EXTENSION_ID});
  v8::Context::Scope context_scope(env);

  auto* tracing_controller =
      static_cast<v8::platform::tracing::TracingController*>(
          i::V8::GetCurrentPlatform()->GetTracingController());

#ifdef V8_USE_PERFETTO
  std::ostringstream perfetto_output;
  tracing_controller->InitializeForPerfetto(&perfetto_output);
  CpuProfilerListener listener;
  tracing_controller->SetTraceEventListenerForTesting(&listener);
#else
  CpuProfileEventChecker* event_checker = new CpuProfileEventChecker();
  TraceBuffer* ring_buffer =
      TraceBuffer::CreateTraceBufferRingBuffer(1, event_checker);
  tracing_controller->Initialize(ring_buffer);
#endif

  bool result = false;
  for (int run_duration = 50; !result; run_duration += 50) {
    TraceConfig* trace_config = new TraceConfig();
    trace_config->AddIncludedCategory(
        TRACE_DISABLED_BY_DEFAULT("v8.cpu_profiler"));

    std::string test_code = R"(
        function foo() {
          let s = 0;
          const endTime = Date.now() + )" +
                            std::to_string(run_duration) + R"(
          while (Date.now() < endTime) s += Math.cos(s);
          return s;
        }
        foo();)";

    tracing_controller->StartTracing(trace_config);
    CompileRun(test_code.c_str());
#ifdef V8_USE_PERFETTO
    TrackEvent::Flush();
#endif
    tracing_controller->StopTracing();

#ifdef V8_USE_PERFETTO
    std::string profile_json = listener.result_json();
    listener.Reset();
#else
    std::string profile_json = event_checker->result_json();
    event_checker->Reset();
#endif
    CHECK_LT(0u, profile_json.length());
    printf("Profile JSON: %s\n", profile_json.c_str());

    std::string profile_checker_code = R"(
        function checkProfile(json) {
          const profile_header = json[0];
          if (typeof profile_header['startTime'] !== 'number')
            return false;
          return json.some(event => (event.lines || []).some(line => line)) &&
              json.filter(e => e.cpuProfile && e.cpuProfile.nodes)
              .some(e => e.cpuProfile.nodes
                  .some(n => n.callFrame.codeType == "JS"));
        }
        checkProfile()" + profile_json +
                                       ")";
    result = CompileRunChecked(CcTest::isolate(), profile_checker_code.c_str())
                 ->IsTrue();
  }

#ifndef V8_USE_PERFETTO
  static_cast<v8::platform::tracing::TracingController*>(
      i::V8::GetCurrentPlatform()->GetTracingController())
      ->Initialize(nullptr);
#endif  // !V8_USE_PERFETTO
}

TEST(Issue763073) {
  class AllowNativesSyntax {
   public:
    AllowNativesSyntax()
        : allow_natives_syntax_(i::v8_flags.allow_natives_syntax),
          trace_deopt_(i::v8_flags.trace_deopt) {
      i::v8_flags.allow_natives_syntax = true;
      i::v8_flags.trace_deopt = true;
    }

    ~AllowNativesSyntax() {
      i::v8_flags.allow_natives_syntax = allow_natives_syntax_;
      i::v8_flags.trace_deopt = trace_deopt_;
    }

   private:
    bool allow_natives_syntax_;
    bool trace_deopt_;
  };

  AllowNativesSyntax allow_natives_syntax_scope;
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  CompileRun(
      "function f() { return function g(x) { }; }"
      // Create first closure, optimize it, and deoptimize it.
      "var g = f();"
      "%PrepareFunctionForOptimization(g);\n"
      "g(1);"
      "%OptimizeFunctionOnNextCall(g);"
      "g(1);"
      "%DeoptimizeFunction(g);"
      // Create second closure, and optimize it. This will create another
      // optimized code object and put in the (shared) type feedback vector.
      "var h = f();"
      "%PrepareFunctionForOptimization(h);\n"
      "h(1);"
      "%OptimizeFunctionOnNextCall(h);"
      "h(1);");

  // Start profiling.
  v8::CpuProfiler* cpu_profiler = v8::CpuProfiler::New(env->GetIsolate());
  v8::Local<v8::String> profile_name = v8_str("test");

  // Here we test that the heap iteration upon profiling start is not
  // confused by having a deoptimized code object for a closure while
  // having a different optimized code object in the type feedback vector.
  cpu_profiler->StartProfiling(profile_name);
  v8::CpuProfile* p = cpu_profiler->StopProfiling(profile_name);
  p->Delete();
  cpu_profiler->Dispose();
}

static const char* js_collect_sample_api_source =
    "%NeverOptimizeFunction(start);\n"
    "function start() {\n"
    "  CallStaticCollectSample();\n"
    "}";

static void CallStaticCollectSample(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  v8::CpuProfiler::CollectSample(info.GetIsolate());
}

TEST(StaticCollectSampleAPI) {
  i::v8_flags.allow_natives_syntax = true;
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  v8::Local<v8::FunctionTemplate> func_template =
      v8::FunctionTemplate::New(env->GetIsolate(), CallStaticCollectSample);
  v8::Local<v8::Function> func =
      func_template->GetFunction(env.local()).ToLocalChecked();
  func->SetName(v8_str("CallStaticCollectSample"));
  env->Global()
      ->Set(env.local(), v8_str("CallStaticCollectSample"), func)
      .FromJust();

  CompileRun(js_collect_sample_api_source);
  v8::Local<v8::Function> function = GetFunction(env.local(), "start");

  ProfilerHelper helper(env.local());
  v8::CpuProfile* profile = helper.Run(function, nullptr, 0, 100);

  const v8::CpuProfileNode* root = profile->GetTopDownRoot();
  const v8::CpuProfileNode* start_node = GetChild(env.local(), root, "start");
  GetChild(env.local(), start_node, "CallStaticCollectSample");

  profile->Delete();
}

TEST(CodeEntriesMemoryLeak) {
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::Context> env = CcTest::NewContext({PROFILER_EXTENSION_ID});
  v8::Context::Scope context_scope(env);

  std::string source = "function start() {}\n";
  for (int i = 0; i < 1000; ++i) {
    source += "function foo" + std::to_string(i) + "() { return " +
              std::to_string(i) +
              "; }\n"
              "foo" +
              std::to_string(i) + "();\n";
  }
  CompileRun(source.c_str());
  v8::Local<v8::Function> function = GetFunction(env, "start");

  ProfilerHelper helper(env);

  for (int j = 0; j < 100; ++j) {
    v8::CpuProfile* profile = helper.Run(function, nullptr, 0);
    profile->Delete();
  }

  i::CpuProfiler* profiler =
      reinterpret_cast<i::CpuProfiler*>(helper.profiler());
  CHECK(!profiler->profiler_listener_for_test());
}

TEST(NativeFrameStackTrace) {
  // A test for issue https://crbug.com/768540
  // When a sample lands in a native function which has not EXIT frame
  // stack frame iterator used to bail out and produce an empty stack trace.
  // The source code below makes v8 call the
  // v8::internal::StringTable::TryStringToIndexOrLookupExisting native function
  // without producing an EXIT frame.
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::Context> env = CcTest::NewContext({PROFILER_EXTENSION_ID});
  v8::Context::Scope context_scope(env);

  const char* source = R"(
      function jsFunction() {
        var s = {};
        for (var i = 0; i < 1e4; ++i) {
          for (var j = 0; j < 100; j++) {
            s['item' + j] = 'alph';
          }
        }
      })";

  CompileRun(source);
  v8::Local<v8::Function> function = GetFunction(env, "jsFunction");

  ProfilerHelper helper(env);

  v8::CpuProfile* profile = helper.Run(function, nullptr, 0, 100, 0);

  // Count the fraction of samples landing in 'jsFunction' (valid stack)
  // vs '(program)' (no stack captured).
  const v8::CpuProfileNode* root = profile->GetTopDownRoot();
  const v8::CpuProfileNode* js_function = FindChild(root, "jsFunction");
  const v8::CpuProfileNode* program = FindChild(root, "(program)");
  if (program) {
    unsigned js_function_samples = TotalHitCount(js_function);
    unsigned program_samples = TotalHitCount(program);
    double valid_samples_ratio =
        1. * js_function_samples / (js_function_samples + program_samples);
    i::PrintF("Ratio: %f\n", valid_samples_ratio);
    // TODO(alph): Investigate other causes of dropped frames. The ratio
    // should be close to 99%.
    CHECK_GE(valid_samples_ratio, 0.3);
  }

  profile->Delete();
}

TEST(SourcePositionTable) {
  i::SourcePositionTable info;

  // Newly created tables should return NoLineNumberInfo for any lookup.
  int no_info = v8::CpuProfileNode::kNoLineNumberInfo;
  CHECK_EQ(no_info, info.GetSourceLineNumber(std::numeric_limits<int>::min()));
  CHECK_EQ(no_info, info.GetSourceLineNumber(0));
  CHECK_EQ(SourcePosition::kNotInlined, info.GetInliningId(0));
  CHECK_EQ(no_info, info.GetSourceLineNumber(1));
  CHECK_EQ(no_info, info.GetSourceLineNumber(9));
  CHECK_EQ(no_info, info.GetSourceLineNumber(10));
  CHECK_EQ(no_info, info.GetSourceLineNumber(11));
  CHECK_EQ(no_info, info.GetSourceLineNumber(19));
  CHECK_EQ(no_info, info.GetSourceLineNumber(20));
  CHECK_EQ(no_info, info.GetSourceLineNumber(21));
  CHECK_EQ(no_info, info.GetSourceLineNumber(100));
  CHECK_EQ(SourcePosition::kNotInlined, info.GetInliningId(100));
  CHECK_EQ(no_info, info.GetSourceLineNumber(std::numeric_limits<int>::max()));

  info.SetPosition(10, 1, SourcePosition::kNotInlined);
  info.SetPosition(20, 2, SourcePosition::kNotInlined);

  // The only valid return values are 1 or 2 - every pc maps to a line
  // number.
  CHECK_EQ(1, info.GetSourceLineNumber(std::numeric_limits<int>::min()));
  CHECK_EQ(1, info.GetSourceLineNumber(0));
  CHECK_EQ(1, info.GetSourceLineNumber(1));
  CHECK_EQ(1, info.GetSourceLineNumber(9));
  CHECK_EQ(1, info.GetSourceLineNumber(10));
  CHECK_EQ(1, info.GetSourceLineNumber(11));
  CHECK_EQ(1, info.GetSourceLineNumber(19));
  CHECK_EQ(1, info.GetSourceLineNumber(20));
  CHECK_EQ(2, info.GetSourceLineNumber(21));
  CHECK_EQ(2, info.GetSourceLineNumber(100));
  CHECK_EQ(2, info.GetSourceLineNumber(std::numeric_limits<int>::max()));

  CHECK_EQ(SourcePosition::kNotInlined, info.GetInliningId(0));
  CHECK_EQ(SourcePosition::kNotInlined, info.GetInliningId(100));

  // Test SetPosition behavior.
  info.SetPosition(25, 3, 0);
  CHECK_EQ(2, info.GetSourceLineNumber(21));
  CHECK_EQ(3, info.GetSourceLineNumber(100));
  CHECK_EQ(3, info.GetSourceLineNumber(std::numeric_limits<int>::max()));

  CHECK_EQ(SourcePosition::kNotInlined, info.GetInliningId(21));
  CHECK_EQ(0, info.GetInliningId(100));

  // Test that subsequent SetPosition calls with the same pc_offset are ignored.
  info.SetPosition(25, 4, SourcePosition::kNotInlined);
  CHECK_EQ(2, info.GetSourceLineNumber(21));
  CHECK_EQ(3, info.GetSourceLineNumber(100));
  CHECK_EQ(3, info.GetSourceLineNumber(std::numeric_limits<int>::max()));

  CHECK_EQ(SourcePosition::kNotInlined, info.GetInliningId(21));
  CHECK_EQ(0, info.GetInliningId(100));
}

TEST(MultipleProfilers) {
  std::unique_ptr<CpuProfiler> profiler1(new CpuProfiler(CcTest::i_isolate()));
  std::unique_ptr<CpuProfiler> profiler2(new CpuProfiler(CcTest::i_isolate()));
  profiler1->StartProfiling("1");
  profiler2->StartProfiling("2");
  profiler1->StopProfiling("1");
  profiler2->StopProfiling("2");
}

// Tests that logged CodeCreateEvent calls do not crash a reused CpuProfiler.
// crbug.com/929928
TEST(CrashReusedProfiler) {
  LocalContext env;
  i::Isolate* isolate = CcTest::i_isolate();
  i::HandleScope scope(isolate);

  std::unique_ptr<CpuProfiler> profiler(new CpuProfiler(isolate));
  profiler->StartProfiling("1");
  profiler->StopProfiling("1");

  profiler->StartProfiling("2");
  CreateCode(isolate, &env);
  profiler->StopProfiling("2");
}

// Tests that samples from different profilers on the same isolate do not leak
// samples to each other. See crbug.com/v8/8835.
TEST(MultipleProfilersSampleIndependently) {
  LocalContext env;
  i::Isolate* isolate = CcTest::i_isolate();
  i::HandleScope scope(isolate);

  // Create two profilers- one slow ticking one, and one fast ticking one.
  // Ensure that the slow ticking profiler does not receive samples from the
  // fast ticking one.
  std::unique_ptr<CpuProfiler> slow_profiler(
      new CpuProfiler(CcTest::i_isolate()));
  slow_profiler->set_sampling_interval(base::TimeDelta::FromSeconds(1));
  slow_profiler->StartProfiling("1", {kLeafNodeLineNumbers});

  CompileRun(R"(
    function start() {
      let val = 1;
      for (let i = 0; i < 10e3; i++) {
        val = (val * 2) % 3;
      }
      return val;
    }
  )");
  v8::Local<v8::Function> function = GetFunction(env.local(), "start");
  ProfilerHelper helper(env.local());
  v8::CpuProfile* profile = helper.Run(function, nullptr, 0, 100, 0);

  auto slow_profile = slow_profiler->StopProfiling("1");
  CHECK_GT(profile->GetSamplesCount(), slow_profile->samples_count());
}

void ProfileSomeCode(v8::Isolate* isolate) {
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope scope(isolate);
  LocalContext context(isolate);

  v8::CpuProfiler* profiler = v8::CpuProfiler::New(isolate);

  v8::Local<v8::String> profile_name = v8_str("1");
  profiler->StartProfiling(profile_name);
  const char* source = R"(
      function foo() {
        var x = 0;
        for (var i = 0; i < 1e3; i++) {
          for (var j = 0; j < 1e3; j++) {
            x = i * j;
          }
        }
        return x;
      }
      foo();
    )";

  CompileRun(source);
  profiler->StopProfiling(profile_name);
  profiler->Dispose();
}

class IsolateThread : public v8::base::Thread {
 public:
  IsolateThread() : Thread(Options("IsolateThread")) {}

  void Run() override {
    v8::Isolate::CreateParams create_params;
    create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
    v8::Isolate* isolate = v8::Isolate::New(create_params);
    ProfileSomeCode(isolate);
    isolate->Dispose();
  }
};

// Checking for crashes and TSAN issues with multiple isolates profiling.
TEST(MultipleIsolates) {
  IsolateThread thread1;
  IsolateThread thread2;

  CHECK(thread1.Start());
  CHECK(thread2.Start());

  thread1.Join();
  thread2.Join();
}

// Varying called function frame sizes increases the chance of something going
// wrong if sampling an unlocked frame. We also prevent optimization to prevent
// inlining so each function call has its own frame.
const char* varying_frame_size_script = R"(
    %NeverOptimizeFunction(maybeYield0);
    %NeverOptimizeFunction(maybeYield1);
    %NeverOptimizeFunction(maybeYield2);
    %NeverOptimizeFunction(bar);
    %NeverOptimizeFunction(foo);
    function maybeYield0(n) {
      YieldIsolate(Math.random() > yieldLimit);
    }
    function maybeYield1(n) {
      YieldIsolate(Math.random() > yieldLimit);
    }
    function maybeYield2(n) {
      YieldIsolate(Math.random() > yieldLimit);
    }
    maybeYield = [maybeYield0 ,maybeYield1, maybeYield2];
    function bar(threadNumber, a, b, c, d) {
      maybeYield[threadNumber](Math.random());
      return a.length + b.length + c.length + d.length;
    }
    function foo(timeLimit, yieldProbability, threadNumber) {
      yieldLimit = 1 - yieldProbability;
      const startTime = Date.now();
      for (let i = 0; i < 1e6; i++) {
        maybeYield[threadNumber](1);
        bar(threadNumber, "Hickory", "Dickory", "Doc", "Mouse");
        YieldIsolate(Math.random() > 0.999);
        if ((Date.now() - startTime) > timeLimit) break;
      }
    }
  )";

class UnlockingThread : public v8::base::Thread {
 public:
  explicit UnlockingThread(v8::Local<v8::Context> env, int32_t threadNumber)
      : Thread(Options("UnlockingThread")),
        env_(CcTest::isolate(), env),
        threadNumber_(threadNumber) {}

  void Run() override {
    v8::Isolate* isolate = CcTest::isolate();
    v8::Locker locker(isolate);
    v8::Isolate::Scope isolate_scope(isolate);
    v8::HandleScope scope(isolate);
    v8::Local<v8::Context> env = v8::Local<v8::Context>::New(isolate, env_);
    Profile(env, threadNumber_);
  }

  static void Profile(v8::Local<v8::Context> env, int32_t threadNumber) {
    CHECK_LT(threadNumber, maxThreads_);
    v8::Isolate* isolate = CcTest::isolate();
    v8::Context::Scope context_scope(env);
    v8::CpuProfiler* profiler = v8::CpuProfiler::New(isolate);
    profiler->SetSamplingInterval(200);
    v8::Local<v8::String> profile_name = v8_str("1");
    profiler->StartProfiling(profile_name);
    int32_t time_limit = 200;
    double yield_probability = 0.001;
    v8::Local<v8::Value> args[] = {v8::Integer::New(isolate, time_limit),
                                   v8::Number::New(isolate, yield_probability),
                                   v8::Integer::New(isolate, threadNumber)};
    v8::Local<v8::Function> function = GetFunction(env, "foo");
    function->Call(env, env->Global(), arraysize(args), args).ToLocalChecked();
    const v8::CpuProfile* profile = profiler->StopProfiling(profile_name);
    const CpuProfileNode* root = profile->GetTopDownRoot();
    for (int32_t number = 0; number < maxThreads_; number++) {
      std::string maybeYield = "maybeYield" + std::to_string(number);
      unsigned hit_count = TotalHitCount(root, maybeYield);
      if (hit_count) CHECK_EQ(number, threadNumber);
    }
    profiler->Dispose();
  }

 private:
  v8::Persistent<v8::Context> env_;
  int32_t threadNumber_;
  static const int32_t maxThreads_ = 3;
};

// Checking for crashes with multiple thread/single Isolate profiling.
TEST(MultipleThreadsSingleIsolate) {
  i::v8_flags.allow_natives_syntax = true;
  v8::Isolate* isolate = CcTest::isolate();
  v8::Locker locker(isolate);
  v8::HandleScope scope(isolate);
  v8::Local<v8::Context> env = CcTest::NewContext({PROFILER_EXTENSION_ID});
  v8::Context::Scope context_scope(env);
  CcTest::AddGlobalFunction(
      env, "YieldIsolate", [](const v8::FunctionCallbackInfo<v8::Value>& info) {
        v8::Isolate* isolate = info.GetIsolate();
        if (!info[0]->IsTrue()) return;
        isolate->Exit();
        {
          v8::Unlocker unlocker(isolate);
          v8::base::OS::Sleep(v8::base::TimeDelta::FromMilliseconds(1));
        }
        isolate->Enter();
      });

  CompileRun(varying_frame_size_script);
  UnlockingThread thread1(env, 1);
  UnlockingThread thread2(env, 2);

  CHECK(thread1.Start());
  CHECK(thread2.Start());

  // For good measure, profile on our own thread
  UnlockingThread::Profile(env, 0);
  isolate->Exit();
  {
    v8::Unlocker unlocker(isolate);
    thread1.Join();
    thread2.Join();
  }
  isolate->Enter();
}

// Tests that StopProfiling doesn't wait for the next sample tick in order to
// stop, but rather exits early before a given wait threshold.
TEST(FastStopProfiling) {
  static const base::TimeDelta kLongInterval = base::TimeDelta::FromSeconds(10);
  static const base::TimeDelta kWaitThreshold = base::TimeDelta::FromSeconds(5);

  std::unique_ptr<CpuProfiler> profiler(new CpuProfiler(CcTest::i_isolate()));
  profiler->set_sampling_interval(kLongInterval);
  profiler->StartProfiling("", {kLeafNodeLineNumbers});

  v8::Platform* platform = v8::internal::V8::GetCurrentPlatform();
  int64_t start = platform->CurrentClockTimeMilliseconds();
  profiler->StopProfiling("");
  int64_t duration = platform->CurrentClockTimeMilliseconds() - start;

  CHECK_LT(duration, kWaitThreshold.InMilliseconds());
}

// Tests that when current_profiles->size() is greater than the max allowable
// number of concurrent profiles (100), we don't allow a new Profile to be
// profiled
TEST(MaxSimultaneousProfiles) {
  LocalContext env;
  i::Isolate* isolate = CcTest::i_isolate();
  i::HandleScope scope(isolate);

  v8::CpuProfiler* profiler = v8::CpuProfiler::New(env->GetIsolate());

  // Spin up first profiler. Verify that status is kStarted
  CpuProfilingStatus firstStatus = profiler->StartProfiling(
      v8_str("1us"), {v8::CpuProfilingMode::kLeafNodeLineNumbers,
                      v8::CpuProfilingOptions::kNoSampleLimit, 1});

  CHECK_EQ(firstStatus, CpuProfilingStatus::kStarted);

  // Spin up profiler with same title. Verify that status is kAlreadyStarted
  CpuProfilingStatus startedStatus = profiler->StartProfiling(
      v8_str("1us"), {v8::CpuProfilingMode::kLeafNodeLineNumbers,
                      v8::CpuProfilingOptions::kNoSampleLimit, 1});

  CHECK_EQ(startedStatus, CpuProfilingStatus::kAlreadyStarted);

  // Spin up 99 more profilers, maxing out CpuProfilersCollection.
  // Check they all return status of kStarted
  for (int i = 2; i <= CpuProfilesCollection::kMaxSimultaneousProfiles; i++) {
    CpuProfilingStatus status =
        profiler->StartProfiling(v8_str((std::to_string(i) + "us").c_str()),
                                 {v8::CpuProfilingMode::kLeafNodeLineNumbers,
                                  v8::CpuProfilingOptions::kNoSampleLimit, i});
    CHECK_EQ(status, CpuProfilingStatus::kStarted);
  }

  // Spin up 101st profiler. Verify status is kErrorTooManyProfilers
  CpuProfilingStatus errorStatus = profiler->StartProfiling(
      v8_str("101us"), {v8::CpuProfilingMode::kLeafNodeLineNumbers,
                        v8::CpuProfilingOptions::kNoSampleLimit, 2});

  CHECK_EQ(errorStatus, CpuProfilingStatus::kErrorTooManyProfilers);

  // Clean up, otherwise will show a crash.
  for (int i = 1; i <= CpuProfilesCollection::kMaxSimultaneousProfiles + 1;
       i++) {
    profiler->StopProfiling(v8_str((std::to_string(i) + "us").c_str()));
  }
}

TEST(LowPrecisionSamplingStartStopInternal) {
  i::Isolate* isolate = CcTest::i_isolate();
  CodeEntryStorage storage;
  CpuProfilesCollection profiles(isolate);
  ProfilerCodeObserver code_observer(isolate, storage);
  Symbolizer symbolizer(code_observer.instruction_stream_map());
  std::unique_ptr<ProfilerEventsProcessor> processor(
      new SamplingEventsProcessor(
          isolate, &symbolizer, &code_observer, &profiles,
          v8::base::TimeDelta::FromMicroseconds(100), false));
  CHECK(processor->Start());
  processor->StopSynchronously();
}

TEST(LowPrecisionSamplingStartStopPublic) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::CpuProfiler* cpu_profiler = v8::CpuProfiler::New(env->GetIsolate());
  cpu_profiler->SetUsePreciseSampling(false);
  v8::Local<v8::String> profile_name = v8_str("");
  cpu_profiler->StartProfiling(profile_name, true);
  cpu_profiler->StopProfiling(profile_name);
  cpu_profiler->Dispose();
}

const char* naming_test_source = R"(
  (function testAssignmentPropertyNamedFunction() {
    let object = {};
    object.propNamed = function () {
      CallCollectSample();
    };
    object.propNamed();
  })();
  )";

TEST(StandardNaming) {
  LocalContext env;
  i::Isolate* isolate = CcTest::i_isolate();
  i
```