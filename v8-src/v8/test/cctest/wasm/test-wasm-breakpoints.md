Response: Let's break down the thought process for analyzing the C++ code and generating the summary and JavaScript examples.

1. **Understand the Goal:** The primary goal is to understand the functionality of the C++ file `test-wasm-breakpoints.cc` and relate it to JavaScript debugging concepts, providing illustrative JavaScript examples.

2. **High-Level Overview:**  The file name immediately suggests it's about testing WebAssembly breakpoint functionality within the V8 engine. The presence of `#include` directives for `wasm`, `debug`, and `test` reinforces this.

3. **Initial Code Scan and Keyword Identification:** Quickly scan the code for important keywords and patterns:
    * `namespace wasm`, `namespace internal`, `namespace v8`: Indicates V8's internal structure and the focus on WebAssembly.
    * `debug::Location`, `debug::BreakLocation`, `debug::DebugDelegate`, `debug::BreakPoint`: Clearly related to debugging concepts.
    * `WasmRunner`, `WasmFunctionCompiler`:  Suggests a testing framework for executing WebAssembly code.
    * `SetBreakpoint`, `ClearBreakpoint`, `GetPossibleBreakpoints`: Core functions related to breakpoint management.
    * `BreakProgramRequested`:  A callback function for when a breakpoint is hit.
    * `StepOver`, `StepInto`, `StepOut`, `Continue`: Standard debugging actions.
    * `CollectValuesBreakHandler`:  Indicates functionality to inspect local variables and the stack during debugging.
    * `WASM_COMPILED_EXEC_TEST`: A macro likely used for defining test cases.

4. **Functional Grouping and Code Analysis:**  Divide the code into logical blocks based on the identified keywords and their usage:

    * **Location Translation (`TranslateLocation`):**  This function seems to convert breakpoint locations from a function-specific format to a module-wide offset, which is how V8 likely internally represents breakpoint locations within a Wasm module.

    * **Breakpoint Location Checks (`CheckLocations`, `CheckLocationsFail`):** These functions test the ability to retrieve valid breakpoint locations within a Wasm module, given a start and end range.

    * **Breakpoint Handling (`BreakHandler`):** This class is a key component. It acts as a `debug::DebugDelegate` to intercept breakpoint events. It allows defining expected breakpoints with specific actions (continue, step over, step into, step out) and verifies that the debugger hits the expected locations.

    * **Setting and Clearing Breakpoints (`SetBreakpoint`, `ClearBreakpoint`):** These functions interact with V8's internal debugging API to set and remove breakpoints at specific offsets within a Wasm function.

    * **Value Collection (`CollectValuesBreakHandler`):** This class is another `debug::DebugDelegate` focused on inspecting the values of local variables and the Wasm stack when a breakpoint is hit.

    * **Test Cases (`WASM_COMPILED_EXEC_TEST` blocks):**  These are the actual unit tests, demonstrating various breakpoint scenarios, stepping behavior, and value inspection.

5. **Relating to JavaScript Debugging:**  Now, connect the C++ functionality to JavaScript debugging concepts:

    * **Breakpoints:** The core concept is the same – pausing execution at a specific point in the code.
    * **Stepping:** `Step Over`, `Step Into`, `Step Out` are standard debugger controls.
    * **Inspecting Variables:** The `CollectValuesBreakHandler` directly corresponds to the ability to inspect local variables and the call stack in a JavaScript debugger.

6. **Generating JavaScript Examples:** Create simple, illustrative JavaScript code snippets that demonstrate the analogous debugging features:

    * **Basic Breakpoint:** Show how to set a breakpoint using the `debugger;` statement or the browser's developer tools.
    * **Stepping:** Briefly explain `Step Over`, `Step Into`, and `Step Out`.
    * **Inspecting Variables:** Show how to access variables in the debugger's scope pane or console.

7. **Refining the Explanation:**  Organize the findings into a clear and concise summary. Use descriptive language, highlighting the key functionalities and their purpose within the context of testing WebAssembly debugging in V8. Explain the connection to JavaScript debugging in a way that's easy to understand for someone familiar with JavaScript debugging concepts.

8. **Review and Verification:** Read through the summary and examples to ensure accuracy and clarity. Check that the JavaScript examples are relevant and demonstrate the analogous features. Make sure the explanation accurately reflects the C++ code's functionality. For instance, double-check that the C++ code indeed sets breakpoints based on byte offsets within functions.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe the `TranslateLocation` function is about source map translation.
* **Correction:** Looking closer, it translates from `{func_index, offset_in_func}` to `{0, offset_in_module}`. This seems more about V8's internal representation of locations within a *compiled* Wasm module, not necessarily related to source maps (though source maps could build upon this).

* **Initial thought:**  Focus heavily on the specific C++ classes and their internal workings.
* **Correction:** Shift focus towards the *functionality* being tested. The goal isn't to understand the intricacies of V8's debugging internals, but to understand what aspects of Wasm debugging are being tested.

* **Initial draft of JavaScript examples:** Maybe too complex.
* **Correction:** Simplify the JavaScript examples to the most basic demonstration of each concept. The focus is on conveying the idea, not writing comprehensive debugging tutorials.

By following this structured approach, breaking down the code into manageable parts, and constantly relating the C++ functionality to familiar JavaScript concepts, we can effectively understand and summarize the purpose of the given C++ file.
这个C++源代码文件 `test-wasm-breakpoints.cc` 的主要功能是 **测试 V8 引擎中 WebAssembly 模块的断点调试功能**。

具体来说，它包含了多个测试用例，用于验证以下 WebAssembly 断点调试相关的特性：

1. **获取可能的断点位置 (`WasmCollectPossibleBreakpoints`):**
   - 测试 `WasmScript::GetPossibleBreakpoints` 函数，该函数用于查找 WebAssembly 模块中可以设置断点的有效代码位置。
   - 测试了在不同的代码范围内查找断点，包括起始和结束位置在指令内部、指令之间、函数边界等情况。

2. **设置和触发断点 (`WasmSimpleBreak`, `WasmNonBreakablePosition`):**
   - 测试 `WasmScript::SetBreakPoint` 函数，用于在指定的代码偏移处设置断点。
   - 使用 `BreakHandler` 类来监听断点事件，并在断点触发时进行验证。
   - `WasmNonBreakablePosition` 测试了在某些非指令起始位置设置断点，验证断点会被调整到最近的有效位置。

3. **单步调试 (`WasmSimpleStepping`, `WasmStepInAndOut`):**
   - 测试单步执行 WebAssembly 代码的功能，包括单步跳过 (`StepOver`)、单步进入 (`StepInto`) 和单步跳出 (`StepOut`)。
   - `BreakHandler` 类用于在每一步执行后进行断言，验证执行流程是否符合预期。
   - `WasmStepInAndOut` 测试了在函数调用时进行单步进入和跳出的情况。

4. **获取局部变量和堆栈信息 (`WasmGetLocalsAndStack`):**
   - 测试在断点处获取 WebAssembly 局部变量和操作数栈的值。
   - 使用 `CollectValuesBreakHandler` 类来监听断点事件，并在断点触发时获取局部变量和堆栈的值，并与预期值进行比较。

5. **移除断点 (`WasmRemoveBreakPoint`, `WasmRemoveLastBreakPoint`, `WasmRemoveAllBreakPoint`):**
   - 测试 `WasmScript::ClearBreakPoint` 函数，用于移除已设置的断点。
   - 验证了在断点被移除后，程序可以继续执行而不会再次触发断点。

6. **在包含 Post-MVP 特性的代码中设置断点 (`WasmBreakInPostMVP`):**
   - 测试在使用了实验性或 Post-MVP WebAssembly 指令的代码中设置断点的功能，确保不会出现错误。

7. **回归测试 (`Regress10889`):**
   - 包含一些特定的回归测试用例，用于修复和防止已知的 bug。

**与 JavaScript 的关系以及 JavaScript 示例:**

这个 C++ 文件测试的是 V8 引擎底层的 WebAssembly 断点调试功能，而这些功能最终会暴露给 JavaScript 开发者，让他们可以在浏览器或 Node.js 中调试 WebAssembly 代码。

**JavaScript 示例:**

假设我们有一个简单的 WebAssembly 模块和一个 JavaScript 文件来加载和执行它：

**WebAssembly 代码 (example.wat):**

```wat
(module
  (func $add (param $p1 i32) (param $p2 i32) (result i32)
    local.get $p1
    local.get $p2
    i32.add
  )
  (export "add" (func $add))
)
```

**JavaScript 代码 (index.js):**

```javascript
async function loadAndRunWasm() {
  const response = await fetch('example.wasm');
  const buffer = await response.arrayBuffer();
  const module = await WebAssembly.compile(buffer);
  const instance = await WebAssembly.instantiate(module);

  const result = instance.exports.add(5, 10);
  console.log("Result:", result);
}

loadAndRunWasm();
```

当我们在浏览器或 Node.js 中运行 `index.js` 时，我们可以使用开发者工具来设置 WebAssembly 代码的断点，就像调试普通的 JavaScript 代码一样。

**调试场景示例：**

1. **设置断点:**  我们可以在 `$add` 函数的 `i32.add` 指令处设置一个断点。在 Chrome 开发者工具中，这通常可以通过在 "Sources" 面板中打开 wasm 文件，然后在相应的行号上点击来实现。

2. **触发断点:** 当 JavaScript 代码调用 `instance.exports.add(5, 10)` 时，执行会暂停在我们在 WebAssembly 代码中设置的断点处。

3. **查看局部变量和堆栈:** 在断点处，开发者工具会显示 WebAssembly 函数的参数 (`$p1`, `$p2`) 和局部变量的值。在更复杂的场景中，还可以查看操作数栈的状态。这对应了 C++ 测试文件中的 `CollectValuesBreakHandler` 的功能。

4. **单步调试:** 我们可以使用 "Step Over"、"Step Into" 和 "Step Out" 按钮来控制 WebAssembly 代码的执行流程，逐行查看指令的执行。这对应了 C++ 测试文件中的 `WasmSimpleStepping` 和 `WasmStepInAndOut` 的功能。

5. **移除断点:**  我们可以随时移除已设置的断点，让程序继续正常执行。这对应了 C++ 测试文件中的 `WasmRemoveBreakPoint` 等功能。

**总结:**

`test-wasm-breakpoints.cc` 文件是 V8 引擎中用于确保 WebAssembly 断点调试功能正常工作的关键测试文件。它涵盖了断点的设置、触发、单步执行以及变量和堆栈信息的检查等核心调试特性，这些特性最终使得 JavaScript 开发者能够方便地调试他们的 WebAssembly 代码。

Prompt: 
```
这是目录为v8/test/cctest/wasm/test-wasm-breakpoints.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/codegen/assembler-inl.h"
#include "src/debug/debug-interface.h"
#include "src/execution/frames-inl.h"
#include "src/objects/property-descriptor.h"
#include "src/utils/utils.h"
#include "src/wasm/wasm-debug.h"
#include "src/wasm/wasm-objects-inl.h"
#include "test/cctest/cctest.h"
#include "test/cctest/wasm/wasm-run-utils.h"
#include "test/common/value-helper.h"
#include "test/common/wasm/test-signatures.h"
#include "test/common/wasm/wasm-macro-gen.h"

namespace v8 {
namespace internal {
namespace wasm {

namespace {

debug::Location TranslateLocation(WasmRunnerBase* runner,
                                  const debug::Location& loc) {
  // Convert locations from {func_index, offset_in_func} to
  // {0, offset_in_module}.
  int func_index = loc.GetLineNumber();
  int func_offset = runner->builder().GetFunctionAt(func_index)->code.offset();
  int offset = loc.GetColumnNumber() + func_offset;
  return {0, offset};
}

void CheckLocations(
    WasmRunnerBase* runner, NativeModule* native_module, debug::Location start,
    debug::Location end,
    std::initializer_list<debug::Location> expected_locations_init) {
  std::vector<debug::BreakLocation> locations;
  std::vector<debug::Location> expected_locations;
  for (auto loc : expected_locations_init) {
    expected_locations.push_back(TranslateLocation(runner, loc));
  }

  bool success = WasmScript::GetPossibleBreakpoints(
      native_module, TranslateLocation(runner, start),
      TranslateLocation(runner, end), &locations);
  CHECK(success);

  printf("got %d locations: ", static_cast<int>(locations.size()));
  for (size_t i = 0, e = locations.size(); i != e; ++i) {
    printf("%s<%d,%d>", i == 0 ? "" : ", ", locations[i].GetLineNumber(),
           locations[i].GetColumnNumber());
  }
  printf("\n");

  CHECK_EQ(expected_locations.size(), locations.size());
  for (size_t i = 0, e = locations.size(); i != e; ++i) {
    CHECK_EQ(expected_locations[i].GetLineNumber(),
             locations[i].GetLineNumber());
    CHECK_EQ(expected_locations[i].GetColumnNumber(),
             locations[i].GetColumnNumber());
  }
}

void CheckLocationsFail(WasmRunnerBase* runner, NativeModule* native_module,
                        debug::Location start, debug::Location end) {
  std::vector<debug::BreakLocation> locations;
  bool success = WasmScript::GetPossibleBreakpoints(
      native_module, TranslateLocation(runner, start),
      TranslateLocation(runner, end), &locations);
  CHECK(!success);
}

class BreakHandler : public debug::DebugDelegate {
 public:
  enum Action {
    Continue = StepAction::LastStepAction + 1,
    StepOver = StepAction::StepOver,
    StepInto = StepAction::StepInto,
    StepOut = StepAction::StepOut
  };
  struct BreakPoint {
    int position;
    Action action;
    std::function<void(void)> pre_action;
    BreakPoint(int position, Action action)
        : position(position), action(action), pre_action([]() {}) {}
    BreakPoint(int position, Action action,
               std::function<void(void)> pre_action)
        : position(position), action(action), pre_action(pre_action) {}
  };

  explicit BreakHandler(Isolate* isolate,
                        std::initializer_list<BreakPoint> expected_breaks)
      : isolate_(isolate), expected_breaks_(expected_breaks) {
    v8::debug::SetDebugDelegate(reinterpret_cast<v8::Isolate*>(isolate_), this);
  }
  ~BreakHandler() override {
    // Check that all expected breakpoints have been hit.
    CHECK_EQ(count_, expected_breaks_.size());
    v8::debug::SetDebugDelegate(reinterpret_cast<v8::Isolate*>(isolate_),
                                nullptr);
  }

  int count() const { return count_; }

 private:
  Isolate* isolate_;
  int count_ = 0;
  std::vector<BreakPoint> expected_breaks_;

  void BreakProgramRequested(v8::Local<v8::Context> paused_context,
                             const std::vector<int>&,
                             v8::debug::BreakReasons break_reasons) override {
    printf("Break #%d\n", count_);
    CHECK_GT(expected_breaks_.size(), count_);

    // Check the current position.
    DebuggableStackFrameIterator frame_it(isolate_);
    auto summ = FrameSummary::GetTop(frame_it.frame()).AsWasm();
    CHECK_EQ(expected_breaks_[count_].position, summ.code_offset());

    expected_breaks_[count_].pre_action();
    Action next_action = expected_breaks_[count_].action;
    switch (next_action) {
      case Continue:
        break;
      case StepOver:
      case StepInto:
      case StepOut:
        isolate_->debug()->PrepareStep(static_cast<StepAction>(next_action));
        break;
      default:
        UNREACHABLE();
    }
    ++count_;
  }
};

Handle<BreakPoint> SetBreakpoint(WasmRunnerBase* runner, int function_index,
                                 int byte_offset,
                                 int expected_set_byte_offset = -1) {
  runner->SwitchToDebug();
  int func_offset =
      runner->builder().GetFunctionAt(function_index)->code.offset();
  int code_offset = func_offset + byte_offset;
  if (expected_set_byte_offset == -1) expected_set_byte_offset = byte_offset;
  DirectHandle<WasmInstanceObject> instance =
      runner->builder().instance_object();
  DirectHandle<Script> script(instance->module_object()->script(),
                              runner->main_isolate());
  static int break_index = 0;
  Handle<BreakPoint> break_point =
      runner->main_isolate()->factory()->NewBreakPoint(
          break_index++, runner->main_isolate()->factory()->empty_string());
  CHECK(WasmScript::SetBreakPoint(script, &code_offset, break_point));
  return break_point;
}

void ClearBreakpoint(WasmRunnerBase* runner, int function_index,
                     int byte_offset, DirectHandle<BreakPoint> break_point) {
  int func_offset =
      runner->builder().GetFunctionAt(function_index)->code.offset();
  int code_offset = func_offset + byte_offset;
  DirectHandle<WasmInstanceObject> instance =
      runner->builder().instance_object();
  DirectHandle<Script> script(instance->module_object()->script(),
                              runner->main_isolate());
  CHECK(WasmScript::ClearBreakPoint(script, code_offset, break_point));
}

// Wrapper with operator<<.
struct WasmValWrapper {
  WasmValue val;

  bool operator==(const WasmValWrapper& other) const {
    return val == other.val;
  }
};

// Only needed in debug builds. Avoid unused warning otherwise.
#ifdef DEBUG
std::ostream& operator<<(std::ostream& out, const WasmValWrapper& wrapper) {
  switch (wrapper.val.type().kind()) {
    case kI32:
      out << "i32: " << wrapper.val.to<int32_t>();
      break;
    case kI64:
      out << "i64: " << wrapper.val.to<int64_t>();
      break;
    case kF32:
      out << "f32: " << wrapper.val.to<float>();
      break;
    case kF64:
      out << "f64: " << wrapper.val.to<double>();
      break;
    default:
      UNIMPLEMENTED();
  }
  return out;
}
#endif

class CollectValuesBreakHandler : public debug::DebugDelegate {
 public:
  struct BreakpointValues {
    std::vector<WasmValue> locals;
    std::vector<WasmValue> stack;
  };

  explicit CollectValuesBreakHandler(
      Isolate* isolate, std::initializer_list<BreakpointValues> expected_values)
      : isolate_(isolate), expected_values_(expected_values) {
    v8::debug::SetDebugDelegate(reinterpret_cast<v8::Isolate*>(isolate_), this);
  }
  ~CollectValuesBreakHandler() override {
    v8::debug::SetDebugDelegate(reinterpret_cast<v8::Isolate*>(isolate_),
                                nullptr);
  }

 private:
  Isolate* isolate_;
  int count_ = 0;
  std::vector<BreakpointValues> expected_values_;

  void BreakProgramRequested(v8::Local<v8::Context> paused_context,
                             const std::vector<int>&,
                             v8::debug::BreakReasons break_reasons) override {
    printf("Break #%d\n", count_);
    CHECK_GT(expected_values_.size(), count_);
    auto& expected = expected_values_[count_];
    ++count_;

    HandleScope handles(isolate_);

    DebuggableStackFrameIterator frame_it(isolate_);
    WasmFrame* frame = WasmFrame::cast(frame_it.frame());
    DebugInfo* debug_info = frame->native_module()->GetDebugInfo();

    int num_locals = debug_info->GetNumLocals(frame->pc(), isolate_);
    CHECK_EQ(expected.locals.size(), num_locals);
    for (int i = 0; i < num_locals; ++i) {
      WasmValue local_value = debug_info->GetLocalValue(
          i, frame->pc(), frame->fp(), frame->callee_fp(), isolate_);
      CHECK_EQ(WasmValWrapper{expected.locals[i]}, WasmValWrapper{local_value});
    }

    int stack_depth = debug_info->GetStackDepth(frame->pc(), isolate_);
    CHECK_EQ(expected.stack.size(), stack_depth);
    for (int i = 0; i < stack_depth; ++i) {
      WasmValue stack_value = debug_info->GetStackValue(
          i, frame->pc(), frame->fp(), frame->callee_fp(), isolate_);
      CHECK_EQ(WasmValWrapper{expected.stack[i]}, WasmValWrapper{stack_value});
    }

    isolate_->debug()->PrepareStep(StepAction::StepInto);
  }
};

// Special template to explicitly cast to WasmValue.
template <typename Arg>
WasmValue MakeWasmVal(Arg arg) {
  return WasmValue(arg);
}
// Translate long to i64 (ambiguous otherwise).
template <>
WasmValue MakeWasmVal(long arg) {  // NOLINT: allow long parameter
  return WasmValue(static_cast<int64_t>(arg));
}

template <typename... Args>
std::vector<WasmValue> wasmVec(Args... args) {
  std::array<WasmValue, sizeof...(args)> arr{{MakeWasmVal(args)...}};
  return std::vector<WasmValue>{arr.begin(), arr.end()};
}

int GetIntReturnValue(MaybeHandle<Object> retval) {
  CHECK(!retval.is_null());
  int result;
  CHECK(Object::ToInt32(*retval.ToHandleChecked(), &result));
  return result;
}

}  // namespace

WASM_COMPILED_EXEC_TEST(WasmCollectPossibleBreakpoints) {
  WasmRunner<int> runner(execution_tier);

  runner.Build({WASM_NOP, WASM_I32_ADD(WASM_ZERO, WASM_ONE)});

  Tagged<WasmInstanceObject> instance = *runner.builder().instance_object();
  NativeModule* native_module = instance->module_object()->native_module();

  std::vector<debug::Location> locations;
  // Check all locations for function 0.
  CheckLocations(&runner, native_module, {0, 0}, {0, 10},
                 {{0, 1}, {0, 2}, {0, 4}, {0, 6}, {0, 7}});
  // Check a range ending at an instruction.
  CheckLocations(&runner, native_module, {0, 2}, {0, 4}, {{0, 2}});
  // Check a range ending one behind an instruction.
  CheckLocations(&runner, native_module, {0, 2}, {0, 5}, {{0, 2}, {0, 4}});
  // Check a range starting at an instruction.
  CheckLocations(&runner, native_module, {0, 7}, {0, 8}, {{0, 7}});
  // Check from an instruction to beginning of next function.
  CheckLocations(&runner, native_module, {0, 7}, {0, 10}, {{0, 7}});
  // Check from end of one function (no valid instruction position) to beginning
  // of next function. Must be empty, but not fail.
  CheckLocations(&runner, native_module, {0, 8}, {0, 10}, {});
  // Check from one after the end of the function. Must fail.
  CheckLocationsFail(&runner, native_module, {0, 9}, {0, 10});
}

WASM_COMPILED_EXEC_TEST(WasmSimpleBreak) {
  WasmRunner<int> runner(execution_tier);
  Isolate* isolate = runner.main_isolate();

  runner.Build({WASM_NOP, WASM_I32_ADD(WASM_I32V_1(11), WASM_I32V_1(3))});

  Handle<JSFunction> main_fun_wrapper =
      runner.builder().WrapCode(runner.function_index());
  SetBreakpoint(&runner, runner.function_index(), 4, 4);

  BreakHandler count_breaks(isolate, {{4, BreakHandler::Continue}});

  Handle<Object> global(isolate->context()->global_object(), isolate);
  MaybeHandle<Object> retval =
      Execution::Call(isolate, main_fun_wrapper, global, 0, nullptr);
  CHECK_EQ(14, GetIntReturnValue(retval));
}

WASM_COMPILED_EXEC_TEST(WasmNonBreakablePosition) {
  WasmRunner<int> runner(execution_tier);
  Isolate* isolate = runner.main_isolate();

  runner.Build({WASM_RETURN(WASM_I32V_2(1024))});

  Handle<JSFunction> main_fun_wrapper =
      runner.builder().WrapCode(runner.function_index());
  SetBreakpoint(&runner, runner.function_index(), 2, 4);

  BreakHandler count_breaks(isolate, {{4, BreakHandler::Continue}});

  Handle<Object> global(isolate->context()->global_object(), isolate);
  MaybeHandle<Object> retval =
      Execution::Call(isolate, main_fun_wrapper, global, 0, nullptr);
  CHECK_EQ(1024, GetIntReturnValue(retval));
}

WASM_COMPILED_EXEC_TEST(WasmSimpleStepping) {
  WasmRunner<int> runner(execution_tier);
  runner.Build({WASM_I32_ADD(WASM_I32V_1(11), WASM_I32V_1(3))});

  Isolate* isolate = runner.main_isolate();
  Handle<JSFunction> main_fun_wrapper =
      runner.builder().WrapCode(runner.function_index());

  // Set breakpoint at the first I32Const.
  SetBreakpoint(&runner, runner.function_index(), 1, 1);

  BreakHandler count_breaks(isolate,
                            {
                                {1, BreakHandler::StepOver},  // I32Const
                                {3, BreakHandler::StepOver},  // I32Const
                                {5, BreakHandler::Continue}   // I32Add
                            });

  Handle<Object> global(isolate->context()->global_object(), isolate);
  MaybeHandle<Object> retval =
      Execution::Call(isolate, main_fun_wrapper, global, 0, nullptr);
  CHECK_EQ(14, GetIntReturnValue(retval));
}

WASM_COMPILED_EXEC_TEST(WasmStepInAndOut) {
  WasmRunner<int, int> runner(execution_tier);
  runner.SwitchToDebug();
  WasmFunctionCompiler& f2 = runner.NewFunction<void>();
  f2.AllocateLocal(kWasmI32);

  // Call f2 via indirect call, because a direct call requires f2 to exist when
  // we compile main, but we need to compile main first so that the order of
  // functions in the code section matches the function indexes.

  // return arg0
  runner.Build({WASM_RETURN(WASM_LOCAL_GET(0))});
  // for (int i = 0; i < 10; ++i) { f2(i); }
  f2.Build({WASM_LOOP(
      WASM_BR_IF(0,
                 WASM_BINOP(kExprI32GeU, WASM_LOCAL_GET(0), WASM_I32V_1(10))),
      WASM_LOCAL_SET(0, WASM_BINOP(kExprI32Sub, WASM_LOCAL_GET(0), WASM_ONE)),
      WASM_CALL_FUNCTION(runner.function_index(), WASM_LOCAL_GET(0)), WASM_DROP,
      WASM_BR(1))});

  Isolate* isolate = runner.main_isolate();
  Handle<JSFunction> main_fun_wrapper =
      runner.builder().WrapCode(f2.function_index());

  // Set first breakpoint on the LocalGet (offset 19) before the Call.
  SetBreakpoint(&runner, f2.function_index(), 19, 19);

  BreakHandler count_breaks(isolate,
                            {
                                {19, BreakHandler::StepInto},  // LocalGet
                                {21, BreakHandler::StepInto},  // Call
                                {1, BreakHandler::StepOut},    // in f2
                                {23, BreakHandler::Continue}   // After Call
                            });

  Handle<Object> global(isolate->context()->global_object(), isolate);
  CHECK(!Execution::Call(isolate, main_fun_wrapper, global, 0, nullptr)
             .is_null());
}

WASM_COMPILED_EXEC_TEST(WasmGetLocalsAndStack) {
  WasmRunner<void, int> runner(execution_tier);
  runner.AllocateLocal(kWasmI64);
  runner.AllocateLocal(kWasmF32);
  runner.AllocateLocal(kWasmF64);

  runner.Build(
      {// set [1] to 17
       WASM_LOCAL_SET(1, WASM_I64V_1(17)),
       // set [2] to <arg0> = 7
       WASM_LOCAL_SET(2, WASM_F32_SCONVERT_I32(WASM_LOCAL_GET(0))),
       // set [3] to <arg1>/2 = 8.5
       WASM_LOCAL_SET(3, WASM_F64_DIV(WASM_F64_SCONVERT_I64(WASM_LOCAL_GET(1)),
                                      WASM_F64(2)))});

  Isolate* isolate = runner.main_isolate();
  Handle<JSFunction> main_fun_wrapper =
      runner.builder().WrapCode(runner.function_index());

  // Set breakpoint at the first instruction (7 bytes for local decls: num
  // entries + 3x<count, type>).
  SetBreakpoint(&runner, runner.function_index(), 7, 7);

  CollectValuesBreakHandler break_handler(
      isolate,
      {
          // params + locals          stack
          {wasmVec(7, 0L, 0.f, 0.), wasmVec()},          // 0: i64.const[17]
          {wasmVec(7, 0L, 0.f, 0.), wasmVec(17L)},       // 1: set_local[1]
          {wasmVec(7, 17L, 0.f, 0.), wasmVec()},         // 2: get_local[0]
          {wasmVec(7, 17L, 0.f, 0.), wasmVec(7)},        // 3: f32.convert_s
          {wasmVec(7, 17L, 0.f, 0.), wasmVec(7.f)},      // 4: set_local[2]
          {wasmVec(7, 17L, 7.f, 0.), wasmVec()},         // 5: get_local[1]
          {wasmVec(7, 17L, 7.f, 0.), wasmVec(17L)},      // 6: f64.convert_s
          {wasmVec(7, 17L, 7.f, 0.), wasmVec(17.)},      // 7: f64.const[2]
          {wasmVec(7, 17L, 7.f, 0.), wasmVec(17., 2.)},  // 8: f64.div
          {wasmVec(7, 17L, 7.f, 0.), wasmVec(8.5)},      // 9: set_local[3]
          {wasmVec(7, 17L, 7.f, 8.5), wasmVec()},        // 10: end
      });

  Handle<Object> global(isolate->context()->global_object(), isolate);
  Handle<Object> args[]{handle(Smi::FromInt(7), isolate)};
  CHECK(!Execution::Call(isolate, main_fun_wrapper, global, 1, args).is_null());
}

WASM_COMPILED_EXEC_TEST(WasmRemoveBreakPoint) {
  WasmRunner<int> runner(execution_tier);
  Isolate* isolate = runner.main_isolate();

  runner.Build(
      {WASM_NOP, WASM_NOP, WASM_NOP, WASM_NOP, WASM_NOP, WASM_I32V_1(14)});

  Handle<JSFunction> main_fun_wrapper =
      runner.builder().WrapCode(runner.function_index());

  SetBreakpoint(&runner, runner.function_index(), 1, 1);
  SetBreakpoint(&runner, runner.function_index(), 2, 2);
  Handle<BreakPoint> to_delete =
      SetBreakpoint(&runner, runner.function_index(), 3, 3);
  SetBreakpoint(&runner, runner.function_index(), 4, 4);

  BreakHandler count_breaks(isolate, {{1, BreakHandler::Continue},
                                      {2, BreakHandler::Continue,
                                       [&runner, &to_delete]() {
                                         ClearBreakpoint(
                                             &runner, runner.function_index(),
                                             3, to_delete);
                                       }},
                                      {4, BreakHandler::Continue}});

  Handle<Object> global(isolate->context()->global_object(), isolate);
  MaybeHandle<Object> retval =
      Execution::Call(isolate, main_fun_wrapper, global, 0, nullptr);
  CHECK_EQ(14, GetIntReturnValue(retval));
}

WASM_COMPILED_EXEC_TEST(WasmRemoveLastBreakPoint) {
  WasmRunner<int> runner(execution_tier);
  Isolate* isolate = runner.main_isolate();

  runner.Build(
      {WASM_NOP, WASM_NOP, WASM_NOP, WASM_NOP, WASM_NOP, WASM_I32V_1(14)});

  Handle<JSFunction> main_fun_wrapper =
      runner.builder().WrapCode(runner.function_index());

  SetBreakpoint(&runner, runner.function_index(), 1, 1);
  SetBreakpoint(&runner, runner.function_index(), 2, 2);
  Handle<BreakPoint> to_delete =
      SetBreakpoint(&runner, runner.function_index(), 3, 3);

  BreakHandler count_breaks(
      isolate, {{1, BreakHandler::Continue},
                {2, BreakHandler::Continue, [&runner, &to_delete]() {
                   ClearBreakpoint(&runner, runner.function_index(), 3,
                                   to_delete);
                 }}});

  Handle<Object> global(isolate->context()->global_object(), isolate);
  MaybeHandle<Object> retval =
      Execution::Call(isolate, main_fun_wrapper, global, 0, nullptr);
  CHECK_EQ(14, GetIntReturnValue(retval));
}

WASM_COMPILED_EXEC_TEST(WasmRemoveAllBreakPoint) {
  WasmRunner<int> runner(execution_tier);
  Isolate* isolate = runner.main_isolate();

  runner.Build(
      {WASM_NOP, WASM_NOP, WASM_NOP, WASM_NOP, WASM_NOP, WASM_I32V_1(14)});

  Handle<JSFunction> main_fun_wrapper =
      runner.builder().WrapCode(runner.function_index());

  Handle<BreakPoint> bp1 =
      SetBreakpoint(&runner, runner.function_index(), 1, 1);
  Handle<BreakPoint> bp2 =
      SetBreakpoint(&runner, runner.function_index(), 2, 2);
  Handle<BreakPoint> bp3 =
      SetBreakpoint(&runner, runner.function_index(), 3, 3);

  BreakHandler count_breaks(
      isolate, {{1, BreakHandler::Continue, [&runner, &bp1, &bp2, &bp3]() {
                   ClearBreakpoint(&runner, runner.function_index(), 1, bp1);
                   ClearBreakpoint(&runner, runner.function_index(), 3, bp3);
                   ClearBreakpoint(&runner, runner.function_index(), 2, bp2);
                 }}});

  Handle<Object> global(isolate->context()->global_object(), isolate);
  MaybeHandle<Object> retval =
      Execution::Call(isolate, main_fun_wrapper, global, 0, nullptr);
  CHECK_EQ(14, GetIntReturnValue(retval));
}

WASM_COMPILED_EXEC_TEST(WasmBreakInPostMVP) {
  // This test checks that we don't fail if experimental / post-MVP opcodes are
  // being used. There was a bug where we were trying to update the "detected"
  // features set, but we were passing a nullptr when compiling with
  // breakpoints.
  WasmRunner<int> runner(execution_tier);
  Isolate* isolate = runner.main_isolate();

  // [] -> [i32, i32]
  ValueType sig_types[] = {kWasmI32, kWasmI32};
  FunctionSig sig{2, 0, sig_types};
  ModuleTypeIndex sig_idx = runner.builder().AddSignature(&sig);

  constexpr int kReturn = 13;
  constexpr int kIgnored = 23;
  runner.Build(
      {WASM_BLOCK_X(sig_idx, WASM_I32V_1(kReturn), WASM_I32V_1(kIgnored)),
       WASM_DROP});

  Handle<JSFunction> main_fun_wrapper =
      runner.builder().WrapCode(runner.function_index());

  SetBreakpoint(&runner, runner.function_index(), 3, 3);

  BreakHandler count_breaks(isolate, {{3, BreakHandler::Continue}});

  Handle<Object> global(isolate->context()->global_object(), isolate);
  MaybeHandle<Object> retval =
      Execution::Call(isolate, main_fun_wrapper, global, 0, nullptr);
  CHECK_EQ(kReturn, GetIntReturnValue(retval));
}

WASM_COMPILED_EXEC_TEST(Regress10889) {
  FLAG_SCOPE(print_wasm_code);
  WasmRunner<int> runner(execution_tier);
  runner.Build({WASM_I32V_1(0)});
  SetBreakpoint(&runner, runner.function_index(), 1, 1);
}

}  // namespace wasm
}  // namespace internal
}  // namespace v8

"""

```