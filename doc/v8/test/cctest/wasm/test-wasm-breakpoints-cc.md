Response:
Let's break down the thought process for analyzing the provided C++ code.

**1. Initial Understanding: File Path and Context**

The file path `v8/test/cctest/wasm/test-wasm-breakpoints.cc` immediately tells us this is a test file within the V8 project, specifically focused on WebAssembly (wasm) and breakpoints. The `.cc` extension confirms it's C++ code.

**2. High-Level Goal: Testing Breakpoint Functionality**

Given the file name and the `test` directory context, the primary goal of this code is to test the breakpoint functionality within V8's WebAssembly implementation. This likely involves setting breakpoints, triggering them, and verifying the state of execution when a breakpoint is hit.

**3. Decomposition into Functional Units**

Scan the code for key classes and functions that perform specific tasks. We can identify:

* **Helper Functions:**
    * `TranslateLocation`: Converts breakpoint locations between different representations.
    * `CheckLocations`:  Verifies that the engine correctly identifies possible breakpoint locations within a given range.
    * `CheckLocationsFail`:  Verifies that the engine correctly identifies invalid breakpoint ranges.
    * `SetBreakpoint`:  Sets a breakpoint at a specific location in the WASM code.
    * `ClearBreakpoint`: Removes a previously set breakpoint.
    * `GetIntReturnValue`: Helper to extract an integer return value from a V8 `Object`.
    * `MakeWasmVal`, `wasmVec`: Helpers for creating `WasmValue` objects, likely used for inspecting local variables and stack values.
* **Test Fixtures/Classes:**
    * `BreakHandler`:  A crucial class for managing breakpoint expectations and actions. It's a `debug::DebugDelegate`, indicating it interacts with V8's debugger interface.
    * `CollectValuesBreakHandler`: Similar to `BreakHandler`, but specifically designed to collect and verify the values of local variables and the stack at breakpoints.
* **`WASM_COMPILED_EXEC_TEST` Macros:** These are test cases using a framework specific to V8's WASM testing. Each test focuses on a particular aspect of breakpoint behavior.

**4. Analyzing Key Classes/Functions in Detail**

* **`TranslateLocation`:**  Recognize the need for different ways to represent code locations (function-relative vs. module-relative). This function performs that conversion, which is essential for interacting with the debugger.

* **`CheckLocations` and `CheckLocationsFail`:** Understand their purpose is to test the `WasmScript::GetPossibleBreakpoints` function. The success/failure check is vital. The use of `std::initializer_list` for expected locations suggests a concise way to define these expectations.

* **`BreakHandler`:** This is where the core breakpoint handling logic resides. Pay attention to:
    * `BreakPoint` struct:  Defines the expected breakpoint position and the action to take (continue, step over, etc.).
    * `BreakProgramRequested`:  The callback that V8's debugger calls when a breakpoint is hit. The checks within this function are crucial (position verification, pre-action execution). The `PrepareStep` call indicates the handler controls the stepping behavior.

* **`SetBreakpoint` and `ClearBreakpoint`:** These interact directly with V8's breakpoint setting and clearing mechanisms. Notice the conversion to module-relative offsets.

* **`CollectValuesBreakHandler`:**  Similar to `BreakHandler`, but focuses on inspecting local variables and the stack. The use of `DebuggableStackFrameIterator` and `DebugInfo` points to how it accesses this information.

* **`WASM_COMPILED_EXEC_TEST`:** Examine the structure of these tests:
    * `WasmRunner`: A utility class for building and running WASM code.
    * `runner.Build()`: Defines the WASM bytecode.
    * `SetBreakpoint()`: Sets the breakpoint under test.
    * Instantiation of `BreakHandler` or `CollectValuesBreakHandler`: Sets up the breakpoint expectations.
    * `Execution::Call()`: Executes the WASM code.
    * `CHECK_EQ()`: Verifies the expected outcome (return value or breakpoint hits).

**5. Identifying Relationships to JavaScript Debugging**

The presence of `debug::DebugDelegate`, `BreakPoint`, and stepping actions (StepOver, StepInto, StepOut) strongly suggests a connection to the debugging concepts familiar from JavaScript. WASM debugging in V8 leverages a similar underlying infrastructure.

**6. Inferring Code Logic and Scenarios**

By analyzing the test names and the WASM bytecode in each test case, we can infer the intended logic and the scenarios being tested:

* **`WasmCollectPossibleBreakpoints`:** Tests the ability to query valid breakpoint locations.
* **`WasmSimpleBreak`:** A basic test of setting and hitting a breakpoint.
* **`WasmNonBreakablePosition`:** Tests setting a breakpoint on a non-executable instruction and how the debugger handles it.
* **`WasmSimpleStepping`:**  Verifies the step-over functionality.
* **`WasmStepInAndOut`:** Tests stepping into and out of function calls.
* **`WasmGetLocalsAndStack`:**  Crucially tests the ability to inspect local variables and the operand stack at a breakpoint.
* **`WasmRemoveBreakPoint` family:** Tests the functionality of removing breakpoints.
* **`WasmBreakInPostMVP`:** Checks if breakpoints work correctly with newer WASM features.
* **`Regress10889`:** Likely a test to prevent a specific bug from recurring.

**7. Considering Potential User Errors**

Think about common debugging mistakes users might make when working with WASM:

* Setting breakpoints at invalid locations.
* Misunderstanding stepping behavior (e.g., expecting to step into a built-in function).
* Difficulty inspecting local variables and stack values.

The code's focus on these areas suggests it's designed to catch these kinds of issues.

**8. Structure and Presentation**

Organize the findings into logical sections (functionality, JavaScript relation, code logic, user errors). Use clear and concise language. Provide specific examples where possible.

**Self-Correction/Refinement during the process:**

* **Initial Thought:**  Might initially focus too much on the low-level C++ details.
* **Correction:** Shift focus to the *purpose* of the code and its relationship to WASM debugging concepts.
* **Refinement:**  Realize that the helper functions are important for understanding the overall test setup. The `BreakHandler` and `CollectValuesBreakHandler` classes are central to the testing methodology.

By following this systematic approach, we can effectively analyze and explain the functionality of the provided C++ code.
这个C++源代码文件 `v8/test/cctest/wasm/test-wasm-breakpoints.cc` 的主要功能是 **测试 V8 引擎中 WebAssembly (Wasm) 的断点功能**。它包含了一系列单元测试，用于验证在 WASM 代码中设置、触发和管理断点的行为是否正确。

以下是该文件功能的详细列表：

**1. 断点位置查询和验证:**

* **`TranslateLocation` 函数:**  这是一个辅助函数，用于在不同的断点位置表示之间进行转换。它将函数内的偏移量转换为模块内的偏移量，这在 WASM 调试中很常见。
* **`CheckLocations` 函数:**  这个函数用于验证 `WasmScript::GetPossibleBreakpoints` 函数的正确性。它给定一个 WASM 模块和一段代码范围，然后检查实际找到的可能断点位置是否与预期位置列表一致。
* **`CheckLocationsFail` 函数:** 与 `CheckLocations` 类似，但用于验证在给定的代码范围内没有找到任何可能的断点位置。
* **测试用例 (例如 `WasmCollectPossibleBreakpoints`):** 这些测试用例调用 `CheckLocations` 和 `CheckLocationsFail` 来确保 V8 能够正确识别 WASM 代码中可以设置断点的位置。

**2. 断点设置和触发:**

* **`BreakHandler` 类:**  这是一个自定义的调试代理类 (`debug::DebugDelegate`)，用于处理断点事件。
    * 它维护一个预期的断点列表 (`expected_breaks_`)，其中包含断点的位置和在断点处应该执行的操作（例如，继续、单步跳过、单步进入、单步跳出）。
    * `BreakProgramRequested` 方法是当断点被触发时调用的回调函数。它会检查当前断点的位置是否与预期一致，并根据预设的操作执行相应的调试操作。
* **`SetBreakpoint` 函数:**  这个函数用于在指定的 WASM 函数和字节偏移处设置断点。它会切换到调试模式，计算模块内的代码偏移量，并使用 `WasmScript::SetBreakPoint` 函数实际设置断点。
* **测试用例 (例如 `WasmSimpleBreak`, `WasmSimpleStepping`, `WasmStepInAndOut`):** 这些测试用例使用 `SetBreakpoint` 设置断点，并使用 `BreakHandler` 验证断点是否被正确触发，以及程序是否按照预期的步骤执行。

**3. 断点清除:**

* **`ClearBreakpoint` 函数:**  这个函数用于清除之前设置的断点。它计算模块内的代码偏移量，并使用 `WasmScript::ClearBreakPoint` 函数移除断点。
* **测试用例 (例如 `WasmRemoveBreakPoint`, `WasmRemoveLastBreakPoint`, `WasmRemoveAllBreakPoint`):** 这些测试用例验证了断点清除功能是否正常工作，包括清除单个断点、最后一个断点和所有断点。

**4. 检查局部变量和堆栈:**

* **`CollectValuesBreakHandler` 类:**  这是一个自定义的调试代理类，用于在断点处收集和检查局部变量和操作数堆栈的值。
    * 它维护一个预期的局部变量和堆栈值列表 (`expected_values_`)。
    * `BreakProgramRequested` 方法在断点触发时被调用，它会使用 `DebuggableStackFrameIterator` 和 `DebugInfo` 来获取当前的局部变量和堆栈值，并与预期值进行比较。
* **测试用例 (`WasmGetLocalsAndStack`):** 这个测试用例使用 `CollectValuesBreakHandler` 来验证在断点处获取的局部变量和堆栈值是否正确。

**5. 处理 Post-MVP 特性:**

* **测试用例 (`WasmBreakInPostMVP`):**  这个测试用例确保即使在使用了 WebAssembly Post-MVP (Minimum Viable Product) 的特性时，断点功能也能正常工作。这有助于防止在引入新特性时出现断点相关的回归错误。

**如果 `v8/test/cctest/wasm/test-wasm-breakpoints.cc` 以 `.tq` 结尾:**

那么它将是一个 **V8 Torque 源代码文件**。Torque 是 V8 用于生成高效的运行时代码的领域特定语言。在这种情况下，该文件可能包含用于实现 WASM 断点功能的 Torque 代码，或者用于生成测试 WASM 断点的 Torque 代码。  由于当前文件是 `.cc`，所以它不是 Torque 文件。

**与 JavaScript 功能的关系:**

WASM 的断点功能直接关系到 JavaScript 的调试体验。开发者可以使用 JavaScript 调试工具（例如 Chrome DevTools）来调试 WASM 代码。

**JavaScript 示例:**

```javascript
// 假设在浏览器中加载了一个包含以下 WASM 代码的模块

// WASM 代码 (简化示例):
// function add(a, b) {
//   return a + b;
// }

async function runWasm() {
  const response = await fetch('my_wasm_module.wasm');
  const buffer = await response.arrayBuffer();
  const module = await WebAssembly.instantiate(buffer);
  const instance = module.instance;

  debugger; // 在 JavaScript 中设置断点，可以进入 WASM 代码

  const result = instance.exports.add(5, 10);
  console.log(result);
}

runWasm();
```

在这个 JavaScript 示例中，当执行到 `debugger;` 语句时，JavaScript 调试器会被激活。如果 `instance.exports.add(5, 10)` 调用了设置了断点的 WASM 代码，调试器就会暂停在 WASM 代码的断点处，允许开发者检查 WASM 的局部变量、堆栈等信息。`v8/test/cctest/wasm/test-wasm-breakpoints.cc` 中的测试就是为了确保这种 JavaScript 到 WASM 的断点调试能够正常工作。

**代码逻辑推理 (假设输入与输出):**

**假设输入:**

* 一个简单的 WASM 函数，例如：`{WASM_I32_ADD(WASM_I32V_1(5), WASM_I32V_1(10))}`
* 在 `WASM_I32_ADD` 操作码的位置 (假设偏移量为 `X`) 设置一个断点。
* 调试器设置为 "继续" 操作。

**预期输出:**

1. 当 WASM 代码执行到偏移量 `X` 时，`BreakHandler::BreakProgramRequested` 方法会被调用。
2. 在 `BreakProgramRequested` 方法中，会检查当前的执行位置是否为 `X`。
3. 由于预设的操作是 "继续"，程序会继续执行，最终返回 `15`。

**涉及用户常见的编程错误:**

1. **在无效的位置设置断点:**  用户可能会尝试在操作码之间或在指令的中间设置断点。V8 应该能够处理这种情况，要么不允许设置断点，要么将其调整到最近的有效位置。`WasmCollectPossibleBreakpoints` 和 `CheckLocations` 就是用来测试这种场景的。

   ```javascript
   // 错误示例：假设尝试在 WASM 指令的中间设置断点
   // 这通常不会直接在 JS 中操作，而是 WASM 调试器需要处理的情况
   ```

2. **误解单步跳过和单步进入:** 用户可能不清楚单步跳过会跳过函数调用，而单步进入会进入函数内部。 `WasmSimpleStepping` 和 `WasmStepInAndOut` 测试用例旨在验证这些行为的正确性。

3. **无法检查局部变量或堆栈:**  用户可能期望能够在断点处查看 WASM 的局部变量和操作数堆栈，但如果 V8 的实现有缺陷，这可能会失败。 `CollectValuesBreakHandler` 和 `WasmGetLocalsAndStack` 就是为了确保这个功能正常工作。

总之，`v8/test/cctest/wasm/test-wasm-breakpoints.cc` 是 V8 引擎中一个非常重要的测试文件，它确保了 WASM 的断点调试功能能够可靠地工作，从而为开发者提供良好的调试体验。

Prompt: 
```
这是目录为v8/test/cctest/wasm/test-wasm-breakpoints.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/wasm/test-wasm-breakpoints.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

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