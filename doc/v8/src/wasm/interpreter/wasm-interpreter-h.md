Response:
Let's break down the thought process for analyzing the provided C++ header file (`wasm-interpreter.h`).

**1. Initial Scan and Keywords:**

The first step is a quick read-through, looking for recurring keywords and structural elements. Immediately noticeable are:

* `WebAssembly`, `Wasm`, `interpreter`:  This confirms the file's purpose.
* `#ifndef`, `#define`, `#include`: Standard C++ header guards and inclusions.
* `namespace v8`, `namespace internal`, `namespace wasm`:  Indicates the file belongs to the V8 JavaScript engine and specifically the WebAssembly interpreter.
* Class names: `DrumBrake`, `InterpreterCode`, `FrameState`, `WasmExecutionTimer`, `WasmInterpreterThread`, `WasmInterpreter`, `CodeMap`. These are the main building blocks and suggest the core functionalities.
* `struct`:  Used for data structures, often with associated methods.
* `enum`:  Defines sets of named constants, like `State` and `OperatorMode`.
* Comments:  Provide valuable high-level explanations (e.g., the purpose of `DrumBrake`, the state machine for `WasmInterpreterThread`).
* `V8_EXPORT_PRIVATE`:  Suggests this is an internal part of V8, not intended for external use.
* `VECTORCALL`: Hints at performance optimizations.

**2. Deconstructing the Core Components:**

Next, analyze the purpose and relationships of the key classes and structs:

* **`DrumBrake`:** The overarching name for the interpreter. The comment explicitly states it's an interpreter for WebAssembly.
* **`InterpreterCode`:** Holds the compiled (or rather, interpreted) representation of a single WebAssembly function. Key members are `function`, `locals`, `start`, and `end` (pointers to the bytecode).
* **`FrameState`:**  Represents the execution state of a single function call on the interpreter stack. It includes the current function, previous frame, stack pointer (`current_sp_`), and other context information. The tracing flags (`V8_ENABLE_DRUMBRAKE_TRACING`) are interesting and indicate debugging/profiling features.
* **`WasmExecutionTimer`:**  Focuses on performance monitoring of the interpreter, specifically the percentage of time spent in it. The histograms mentioned are typical V8 performance metrics.
* **`WasmInterpreterThreadMap` and `WasmInterpreterThread`:**  Deal with the execution of WebAssembly code in a thread-like manner within the interpreter. The state machine diagram in the `WasmInterpreterThread` comment is crucial for understanding its lifecycle. The concept of "Activations" is important for managing nested calls between different Wasm instances.
* **`WasmInterpreter`:** The main interface to the interpreter. It manages the `CodeMap` and the `WasmInterpreterRuntime`. It's responsible for starting and continuing the execution of WebAssembly functions.
* **`CodeMap`:**  Stores the `InterpreterCode` for all functions in a WebAssembly module. This is the central repository of the interpreted code.
* **`WasmInterpreterRuntime`:** (Mentioned but not fully defined in this header) Likely handles the interaction between the interpreter and the surrounding V8 environment (memory, imports, exports, etc.). This is a key bridge.

**3. Identifying Functionality based on Members and Methods:**

Examine the members and methods of each class to deduce specific functionalities:

* **`InterpreterCode::at()`:** Accesses bytecode at a specific offset.
* **`FrameState::SetCaughtException()`, `GetCaughtException()`:**  Relate to WebAssembly's exception handling mechanism.
* **`WasmExecutionTimer::Start()`, `Stop()`:** Start and stop the performance timer.
* **`WasmInterpreterThread::Run()`, `Stop()`, `Trap()`:** Control the execution state of the interpreter thread.
* **`WasmInterpreterThread::StartActivation()`, `FinishActivation()`:** Manage the call stack for different Wasm instances.
* **`WasmInterpreter::BeginExecution()`, `ContinueExecution()`:** Initiate and resume WebAssembly execution.
* **`WasmInterpreter::GetReturnValue()`:**  Retrieve the result of a function call.
* **`CodeMap::GetCode()`:** Retrieve the interpreted code for a function.

**4. Addressing Specific Instructions:**

* **`.tq` extension:** The file does *not* end in `.tq`, so it's not a Torque source file. This is a direct check based on the filename.
* **Relationship to JavaScript:**  The file is part of V8, which executes JavaScript. The `WasmInterpreter` allows JavaScript to run WebAssembly code. The `CallExternalJSFunction()` mentioned in the `WasmInterpreterThread` comments highlights this interaction. The `Handle<WasmInstanceObject>` also indicates integration with V8's object model.
* **Code Logic Inference:** The state machine for `WasmInterpreterThread` is the most prominent example of code logic. The transitions between states (STOPPED, RUNNING, TRAPPED, etc.) represent the flow of execution and error handling.
* **Common Programming Errors (Hypothetical):** While the header doesn't directly *cause* errors, understanding it helps prevent them. For example, a JavaScript developer might incorrectly assume synchronous execution of WebAssembly if they don't understand the threading model. Memory access errors (going beyond stack limits) are also relevant to the `ExpandStack()` function.
* **归纳功能 (Summarizing Functionality):**  Combine the understanding of individual components into a higher-level summary. Focus on the core responsibility of the file: providing an interpreter for WebAssembly within V8.

**5. Structuring the Output:**

Organize the findings logically, addressing each part of the prompt:

* **File Functionality:** Provide a concise overview.
* **`.tq` Check:** Explicitly state whether it's a Torque file.
* **Relationship to JavaScript:** Explain how the interpreter fits into the V8 ecosystem.
* **JavaScript Examples:** Provide simple, illustrative JavaScript snippets that trigger WebAssembly execution.
* **Code Logic Inference:** Describe the state machine and its implications.
* **Assumptions and Outputs (Example):**  Create a simple scenario to illustrate the flow.
* **Common Programming Errors:**  Give practical examples from a developer's perspective.
* **Summary of Functionality (Part 1):**  Reiterate the main purpose of the header file.

**Self-Correction/Refinement:**

During the analysis, if something is unclear, go back and re-read the relevant sections, especially the comments. If a concept like "Activations" isn't immediately obvious, spend more time understanding its role in managing nested calls. Ensure the JavaScript examples are accurate and directly relate to the discussed functionality. Make sure the summary accurately reflects the key responsibilities of the code.
这是对V8源代码文件 `v8/src/wasm/interpreter/wasm-interpreter.h` 功能的分析。

**文件功能归纳:**

`v8/src/wasm/interpreter/wasm-interpreter.h` 文件定义了 V8 中 WebAssembly 解释器 (`DrumBrake`) 的核心数据结构和接口。它主要负责：

1. **定义 WebAssembly 解释器的基本架构:** 包括解释器本身 (`WasmInterpreter`)、用于存储解释执行代码的结构 (`InterpreterCode`)、表示解释器执行帧状态的结构 (`FrameState`) 以及管理解释器线程的类 (`WasmInterpreterThread`).
2. **管理 WebAssembly 函数的解释执行:**  定义了如何存储和访问 WebAssembly 函数的字节码 (`InterpreterCode`)，以及如何在解释器中执行这些字节码。
3. **处理解释器执行过程中的状态管理:**  例如，通过 `WasmInterpreterThread` 管理解释器的运行状态 (RUNNING, STOPPED, TRAPPED 等)。
4. **提供性能监控机制:**  定义了 `WasmExecutionTimer` 类，用于监控 WebAssembly 解释器的执行时间，以便检测性能瓶颈。
5. **定义了指令处理相关的类型和枚举:**  例如 `OperatorMode` 和 `RegModeTransform`，这些与解释器如何优化指令执行有关。
6. **提供与 V8 其他部分的接口:**  例如，与 `WasmInstanceObject` 和 `Isolate` 的交互。

**关于文件后缀和 Torque:**

`v8/src/wasm/interpreter/wasm-interpreter.h` 的后缀是 `.h`，这表明它是一个 C++ 头文件，而不是以 `.tq` 结尾的 Torque 源代码文件。因此，它不是一个 V8 Torque 源代码文件。

**与 JavaScript 的功能关系:**

`v8/src/wasm/interpreter/wasm-interpreter.h` 中定义的 WebAssembly 解释器是 V8 执行 WebAssembly 代码的关键组成部分。当 JavaScript 调用 WebAssembly 模块中的函数时，如果该模块选择使用解释器执行（例如，在某些调试或性能分析场景下），V8 就会使用这里定义的解释器。

**JavaScript 示例:**

```javascript
// 假设你已经加载了一个 WebAssembly 模块的实例
const wasmInstance = // ... 加载 WebAssembly 模块的实例 ...

// 假设 WebAssembly 模块导出了一个名为 'add' 的函数
const addFunction = wasmInstance.exports.add;

// 调用 WebAssembly 函数
const result = addFunction(5, 10);

console.log(result); // 输出结果
```

在这个例子中，当 `addFunction(5, 10)` 被调用时，V8 内部可能会使用 `wasm-interpreter.h` 中定义的解释器来执行 `add` 函数的 WebAssembly 代码，尤其是在没有即时编译（JIT）或者强制使用解释器的情况下。

**代码逻辑推理 (假设输入与输出):**

假设有一个简单的 WebAssembly 函数，它将两个 i32 类型的参数相加并返回结果：

**WebAssembly 代码 (简略表示):**

```wasm
(func (param i32 i32) (result i32)
  local.get 0
  local.get 1
  i32.add
)
```

**假设输入:**

* `WasmInterpreterThread` 处于 `RUNNING` 状态。
* `InterpreterCode` 指向上述 WebAssembly 函数的字节码。
* `FrameState` 的栈顶包含两个 i32 类型的值：`5` 和 `10`。

**代码逻辑推理 (简化):**

1. 解释器从 `InterpreterCode` 中读取 `i32.add` 指令。
2. 解释器从 `FrameState` 的栈顶弹出两个值：`10` 和 `5`。
3. 解释器执行加法运算：`5 + 10 = 15`。
4. 解释器将结果 `15` 推入 `FrameState` 的栈顶。

**假设输出:**

* `FrameState` 的栈顶包含一个 i32 类型的值：`15`。
* `WasmInterpreterThread` 仍然处于 `RUNNING` 状态。

**用户常见的编程错误 (与解释器间接相关):**

虽然用户通常不会直接与解释器交互，但了解解释器的工作原理可以帮助理解某些与 WebAssembly 相关的错误：

* **栈溢出:** 如果 WebAssembly 函数调用层级过深，或者局部变量占用过多栈空间，可能会导致解释器栈溢出。这通常表现为运行时错误。
    ```javascript
    // 假设 WebAssembly 模块中有一个无限递归的函数
    // function recursive_function() { recursive_function(); }
    // wasmInstance.exports.recursive_function(); // 调用会导致栈溢出
    ```
* **类型不匹配:** 如果 JavaScript 传递给 WebAssembly 函数的参数类型与 WebAssembly 函数期望的类型不符，解释器在执行时可能会抛出类型错误。
    ```javascript
    // 假设 WebAssembly 函数 add 期望两个 i32 参数
    // const result = addFunction("hello", 10); // 传递了字符串，可能导致类型错误
    ```
* **内存访问错误:** WebAssembly 代码中可能存在越界内存访问的错误，这在解释器执行时会被捕获，并可能导致程序崩溃或抛出异常。

**总结 `v8/src/wasm/interpreter/wasm-interpreter.h` 的功能 (第 1 部分):**

`v8/src/wasm/interpreter/wasm-interpreter.h` 是 V8 中 WebAssembly 解释器的核心定义文件，它定义了解释器的基本结构、数据表示、执行状态管理以及与 V8 其他组件的接口。它为 WebAssembly 代码的解释执行提供了基础框架。虽然不是 Torque 文件，但它是 V8 执行 WebAssembly 代码的关键部分，与 JavaScript 通过 WebAssembly 模块进行交互息息相关。理解这个文件的内容有助于理解 V8 如何执行 WebAssembly 代码，并有助于调试与 WebAssembly 相关的错误。

Prompt: 
```
这是目录为v8/src/wasm/interpreter/wasm-interpreter.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/interpreter/wasm-interpreter.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2024 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#if !V8_ENABLE_WEBASSEMBLY
#error This header should only be included if WebAssembly is enabled.
#endif  // !V8_ENABLE_WEBASSEMBLY

#ifndef V8_WASM_INTERPRETER_WASM_INTERPRETER_H_
#define V8_WASM_INTERPRETER_WASM_INTERPRETER_H_

#include <atomic>
#include <memory>
#include <vector>

#include "src/base/platform/time.h"
#include "src/base/platform/wrappers.h"
#include "src/base/small-vector.h"
#include "src/base/vector.h"
#include "src/common/simd128.h"
#include "src/logging/counters.h"
#include "src/wasm/function-body-decoder-impl.h"
#include "src/wasm/interpreter/instruction-handlers.h"
#include "src/wasm/interpreter/wasm-interpreter-objects.h"
#include "src/wasm/wasm-value.h"

////////////////////////////////////////////////////////////////////////////////
//
// DrumBrake: An interpreter for WebAssembly.
//
////////////////////////////////////////////////////////////////////////////////

// Uncomment to enable profiling.
// #define DRUMBRAKE_ENABLE_PROFILING true
//

#ifdef V8_HOST_ARCH_ARM64
#define VECTORCALL
#else
#if defined(__clang__)
#define VECTORCALL __vectorcall
#else  // GCC or MSVC
#define VECTORCALL
#endif  // __clang__
#endif  // V8_HOST_ARCH_ARM64

typedef void InstrHandlerRetType;
#define INSTRUCTION_HANDLER_FUNC \
  static DISABLE_CFI_ICALL InstrHandlerRetType VECTORCALL

namespace v8 {

namespace internal {
class Cell;
class FixedArray;
class WasmInstanceObject;

namespace wasm {

// Forward declarations.
class Decoder;
struct InterpreterCode;
class InterpreterHandle;
struct ModuleWireBytes;
class WasmBytecode;
class WasmBytecodeGenerator;
class WasmCode;
struct WasmFunction;
struct WasmModule;
class WasmInterpreterRuntime;
class WasmInterpreterThread;

using pc_t = size_t;
using CodeOffset = size_t;
using WasmRef = Handle<Object>;

// We are using sizeof(WasmRef) and kSystemPointerSize interchangeably in the
// interpreter code.
static_assert(sizeof(WasmRef) == kSystemPointerSize);

// Code and metadata needed to execute a function.
struct InterpreterCode {
  InterpreterCode(const WasmFunction* function, BodyLocalDecls locals,
                  const uint8_t* start, const uint8_t* end)
      : function(function), locals(locals), start(start), end(end) {}

  const uint8_t* at(pc_t pc) { return start + pc; }

  const WasmFunction* function;  // wasm function
  BodyLocalDecls locals;         // local declarations
  const uint8_t* start;          // start of code
  const uint8_t* end;            // end of code
  std::unique_ptr<WasmBytecode> bytecode;
};

struct FrameState {
  FrameState()
      : current_function_(nullptr),
        previous_frame_(nullptr),
        current_bytecode_(nullptr),
        current_sp_(nullptr),
        thread_(nullptr),
        ref_array_current_sp_(0),
        ref_array_length_(0),
        handle_scope_(nullptr)
#ifdef V8_ENABLE_DRUMBRAKE_TRACING
        ,
        current_stack_height_(0),
        current_stack_start_args_(0),
        current_stack_start_locals_(0),
        current_stack_start_stack_(0)
#endif  // V8_ENABLE_DRUMBRAKE_TRACING
  {
  }

  const WasmBytecode* current_function_;
  const FrameState* previous_frame_;
  const uint8_t* current_bytecode_;
  uint8_t* current_sp_;
  WasmInterpreterThread* thread_;
  uint32_t ref_array_current_sp_;
  uint32_t ref_array_length_;
  HandleScope* handle_scope_;

  // Maintains a reference to the exceptions caught by each catch handler.
  void SetCaughtException(Isolate* isolate, uint32_t catch_block_index,
                          Handle<Object> exception);
  Handle<Object> GetCaughtException(Isolate* isolate,
                                    uint32_t catch_block_index) const;
  void DisposeCaughtExceptionsArray(Isolate* isolate);
  Handle<FixedArray> caught_exceptions_;

  inline void ResetHandleScope(Isolate* isolate);

#ifdef V8_ENABLE_DRUMBRAKE_TRACING
  uint32_t current_stack_height_;
  uint32_t current_stack_start_args_;
  uint32_t current_stack_start_locals_;
  uint32_t current_stack_start_stack_;
#endif  // V8_ENABLE_DRUMBRAKE_TRACING
};

// Manages the calculations of the
// V8.WasmInterpreterExecutionInTenSecondsPercentage histogram, which measures
// the percentage of time spent executing in the Wasm interpreter in a 10
// seconds window and it is useful to detect applications that are CPU-bound
// and that could be visibly slowed down by the interpreter. Only about one
// sample per minute is generated.
class WasmExecutionTimer {
 public:
  WasmExecutionTimer(Isolate* isolate, bool track_jitless_wasm);

  V8_INLINE void Start() {
    if (execute_ratio_histogram_->Enabled()) StartInternal();
  }

  V8_INLINE void Stop() {
    if (execute_ratio_histogram_->Enabled()) StopInternal();
  }

  void Terminate();

 private:
  void StartInternal();
  void StopInternal();

  void BeginInterval(bool start_timer);
  void EndInterval();

  void AddSample(int running_ratio);

  Histogram* execute_ratio_histogram_;
  Histogram* slow_wasm_histogram_;
  base::ElapsedTimer window_execute_timer_;
  bool window_has_started_;
  base::TimeTicks next_interval_time_;
  base::TimeTicks start_interval_time_;
  base::TimeDelta window_running_time_;
  const base::TimeDelta sample_duration_;
  base::TimeDelta cooldown_interval_;  // Pause between samples.
  const int slow_threshold_;
  const size_t slow_threshold_samples_count_;
  std::vector<int> samples_;
  Isolate* isolate_;

  static const int kMaxPercentValue = 100000;
};

class V8_EXPORT_PRIVATE WasmInterpreterThreadMap {
 public:
  WasmInterpreterThread* GetCurrentInterpreterThread(Isolate* isolate);

  void NotifyIsolateDisposal(Isolate* isolate);

 private:
  typedef std::unordered_map<int, std::unique_ptr<WasmInterpreterThread>>
      ThreadInterpreterMap;
  ThreadInterpreterMap map_;
  base::Mutex mutex_;
};

// Representation of a thread in the interpreter.
class V8_EXPORT_PRIVATE WasmInterpreterThread {
 public:
  // State machine for a WasmInterpreterThread:
  //
  //               STOPPED
  //                  |
  //             Run()|
  //                  V
  //               RUNNING <-----------------------------------+
  //                  |                                        |
  //                  |                                        |
  //    +-------------+---------------+---------------+        |
  //    |Stop()       |Trap()         |Finish()       |        |
  //    V             V               V               V        |
  // STOPPED <---- TRAPPED         FINISHED     EH_UNWINDING --+
  //    ^                                             |
  //    +---------------------------------------------+
  //
  // In more detail:
  // - For each loaded instance, an InterpreterHandler is created that owns a
  //   WasmInterpreter that owns a WasmInterpreterRuntime object.
  //
  // - The WasmInterpreterThread is created in STOPPED state.
  //
  // - InterpreterHandle::Execute(func_index, ...) executes Wasm code in
  // the interpreter:
  //   - WasmInterpreter::BeginExecution ->
  //       WasmInterpreterRuntime::BeginExecution ->
  //         WasmInterpreterThread::StartActivation() -> Run() -> RUNNING
  //         state.
  //   - WasmInterpreter::ContinueExecution ->
  //       WasmInterpreterRuntime::ContinueExecution ->
  //         WasmInterpreterRuntime::ExecuteFunction
  //
  // WasmInterpreterRuntime::ExecuteFunction(..., func_index, ...) executes a
  // specific Wasm function.
  // If 'func_index' indicates an imported function, and the call fails ->
  //   Stop() -> STOPPED state.
  // If 'func_index' indicates an not-imported function, we start executing a
  // sequence of instruction handlers. One of these handlers can cause a
  //   Trap()  -> TRAPPED state.
  // From these instructions sequence we can make several kinds of direct or
  // indirect wasm calls to:
  //  . An external JS function ->
  //      WasmInterpreterRuntime::CallExternalJSFunction() ->
  //      If the call fails -> Stop() -> STOPPED state.
  //  . A Wasm function in the same module instance, recursively calling
  //      WasmInterpreterRuntime::ExecuteFunction().
  //  . A Wasm function in a different module instance. In this case we
  //      recusively call InterpreterHandle::Execute with the
  //      InterpreterHandle of that different instance. If the call fails ->
  //      Stop() -> STOPPED state.
  //
  // After WasmInterpreterRuntime::ExecuteFunction() completes, if we ended up
  // in the TRAPPED state we raise a JS exception  -> RaiseException() ->
  // Stop() -> STOPPED state.
  //
  // If an exception can be handled by Wasm code, according to the Wasm
  // Exception Handling proposal, the thread can go to the EH_UNWINDING state
  // while looking for a Wasm function in the call stack that has a {catch}
  // instruction that can handle that exception. If no such catch handler is
  // found, the thread goes to STOPPED.
  //
  // If we are running the WasmInterpreter of instance A and we can call
  // from a function of a different instance B (via
  // InterpreterHandle::Execute()) the execution of instance A "suspends"
  // waiting for the execution in the WasmInterpreter of instance B to
  // complete. Instance B can call back into instance A, and so on... This
  // means that in the call stack we might have a sequence of stack frames for
  // the WasmInterpreter A followed by frames for instance B followed by
  // more frames of instance A.
  // To manage this case WasmInterpreterThread maintains a stack of
  // Activations, which represents the set of StackFrames for a given module
  // instance. Only when the last active Activation terminates we call
  // Finish() -> FINISHED state.

  enum State { STOPPED, RUNNING, FINISHED, TRAPPED, EH_UNWINDING };

  enum ExceptionHandlingResult { HANDLED, UNWOUND };

  struct TrapStatus {
    //  bool has_trapped;
    int trap_function_index;
    int trap_pc;
  };

  class Activation {
   public:
    Activation(WasmInterpreterThread* thread,
               WasmInterpreterRuntime* wasm_runtime, Address frame_pointer,
               uint8_t* start_fp, const FrameState& callee_frame_state)
        : thread_(thread),
          wasm_runtime_(wasm_runtime),
          frame_pointer_(frame_pointer),
          current_frame_size_(0),
          ref_stack_size_(0),
          current_fp_(start_fp),
          current_frame_state_(callee_frame_state)
#ifdef V8_ENABLE_DRUMBRAKE_TRACING
          ,
          current_stack_start_(callee_frame_state.current_stack_start_args_ +
                               thread->CurrentStackFrameSize()),
          current_stack_size_(0)
#endif  // V8_ENABLE_DRUMBRAKE_TRACING
    {
    }

    WasmInterpreterThread* thread() const { return thread_; }

    inline Isolate* GetIsolate() const;

    Address GetFramePointer() const { return frame_pointer_; }

    void SetCurrentFrame(const FrameState& frame_state) {
      current_frame_state_ = frame_state;
    }
    const FrameState& GetCurrentFrame() const { return current_frame_state_; }

    void SetCurrentActivationFrame(uint8_t* current_fp,
                                   uint32_t current_frame_size,
                                   uint32_t current_stack_size,
                                   uint32_t ref_stack_size) {
      current_fp_ = current_fp;
      current_frame_size_ = current_frame_size;
      ref_stack_size_ = ref_stack_size;

#ifdef V8_ENABLE_DRUMBRAKE_TRACING
      current_stack_size_ = current_stack_size;
#endif  // V8_ENABLE_DRUMBRAKE_TRACING
    }

    uint8_t* NextFrameAddress() const {
      return current_fp_ + current_frame_size_;
    }

    uint32_t NextRefStackOffset() const { return ref_stack_size_; }

    void SetTrapped(int trap_function_index, int trap_pc) {
      // Capture the call stack at the moment of the trap and store it to be
      // retrieved later. This works because, once an Activation has trapped,
      // execution will never resume in it, given that Wasm EH is not
      // supported yet.
      TrapStatus trap_status{trap_function_index, trap_pc};
      trap_stack_trace_ =
          std::make_unique<std::vector<WasmInterpreterStackEntry>>(
              CaptureStackTrace(&trap_status));
    }

    std::vector<WasmInterpreterStackEntry> GetStackTrace() {
      if (trap_stack_trace_) {
        return *trap_stack_trace_;
      }

      // If the Activation has not trapped, it is still executing so we need
      // to capture the current call stack.
      return CaptureStackTrace();
    }

    int GetFunctionIndex(int index) const;

    const WasmInterpreterRuntime* GetWasmRuntime() const {
      return wasm_runtime_;
    }

#ifdef V8_ENABLE_DRUMBRAKE_TRACING
    uint32_t CurrentStackFrameStart() const { return current_stack_start_; }
    uint32_t CurrentStackFrameSize() const { return current_stack_size_; }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING

   private:
    std::vector<WasmInterpreterStackEntry> CaptureStackTrace(
        const TrapStatus* trap_status = nullptr) const;

    WasmInterpreterThread* thread_;
    WasmInterpreterRuntime* wasm_runtime_;
    Address frame_pointer_;
    uint32_t current_frame_size_;
    uint32_t ref_stack_size_;
    uint8_t* current_fp_;
    FrameState current_frame_state_;
    std::unique_ptr<std::vector<WasmInterpreterStackEntry>> trap_stack_trace_;
#ifdef V8_ENABLE_DRUMBRAKE_TRACING
    uint32_t current_stack_start_;
    uint32_t current_stack_size_;
#endif  // V8_ENABLE_DRUMBRAKE_TRACING
  };

  explicit WasmInterpreterThread(Isolate* isolate)
      : isolate_(isolate),
        state_(State::STOPPED),
        trap_reason_(TrapReason::kTrapUnreachable),
        current_stack_size_(kInitialStackSize),
        stack_mem_(nullptr),
        execution_timer_(isolate, true) {
    PageAllocator* page_allocator = GetPlatformPageAllocator();
    stack_mem_ = AllocatePages(page_allocator, nullptr, kMaxStackSize,
                               page_allocator->AllocatePageSize(),
                               PageAllocator::kNoAccess);
    if (!stack_mem_ ||
        !SetPermissions(page_allocator, stack_mem_, current_stack_size_,
                        PageAllocator::Permission::kReadWrite)) {
      V8::FatalProcessOutOfMemory(
          nullptr, "WasmInterpreterThread::WasmInterpreterThread",
          "Cannot allocate Wasm interpreter stack");
      UNREACHABLE();
    }
  }

  ~WasmInterpreterThread() {
    FreePages(GetPlatformPageAllocator(), stack_mem_, kMaxStackSize);
  }

  bool ExpandStack(size_t additional_required_size) {
    if (current_stack_size_ + additional_required_size > kMaxStackSize) {
      return false;
    }

    uint32_t new_size = current_stack_size_;
    while (new_size < current_stack_size_ + additional_required_size) {
      new_size = std::min(new_size + kStackSizeIncrement, kMaxStackSize);
    }

    if (SetPermissions(GetPlatformPageAllocator(), stack_mem_, new_size,
                       PageAllocator::Permission::kReadWrite)) {
      current_stack_size_ = new_size;
      return true;
    }
    return false;
  }

  static void Initialize() {
    // This function can be called multiple times by fuzzers.
    if (thread_interpreter_map_s) return;
    thread_interpreter_map_s = new WasmInterpreterThreadMap();
  }

  static void Terminate() {
    delete thread_interpreter_map_s;
    thread_interpreter_map_s = nullptr;
  }

  static void NotifyIsolateDisposal(Isolate* isolate) {
    thread_interpreter_map_s->NotifyIsolateDisposal(isolate);
  }

  static WasmInterpreterThread* GetCurrentInterpreterThread(Isolate* isolate) {
    DCHECK_NOT_NULL(thread_interpreter_map_s);
    return thread_interpreter_map_s->GetCurrentInterpreterThread(isolate);
  }

  const Isolate* GetIsolate() const { return isolate_; }

  State state() const { return state_; }

  void Run() { state_ = State::RUNNING; }
  void Stop() { state_ = State::STOPPED; }

  void Trap(TrapReason trap_reason, int trap_function_index, int trap_pc,
            const FrameState& current_frame) {
    state_ = State::TRAPPED;
    trap_reason_ = trap_reason;

    DCHECK(!activations_.empty());
    activations_.back()->SetCurrentFrame(current_frame);
    activations_.back()->SetTrapped(trap_function_index, trap_pc);
  }
  TrapReason GetTrapReason() const { return trap_reason_; }

  void Unwinding() { state_ = State::EH_UNWINDING; }

  inline WasmInterpreterThread::Activation* StartActivation(
      WasmInterpreterRuntime* wasm_runtime, Address frame_pointer,
      uint8_t* interpreter_fp, const FrameState& frame_state);
  inline void FinishActivation();
  inline const FrameState* GetCurrentActivationFor(
      const WasmInterpreterRuntime* wasm_runtime) const;

  inline void SetCurrentFrame(const FrameState& frame_state) {
    DCHECK(!activations_.empty());
    activations_.back()->SetCurrentFrame(frame_state);
  }

  inline void SetCurrentActivationFrame(uint32_t* fp,
                                        uint32_t current_frame_size,
                                        uint32_t current_stack_size,
                                        uint32_t ref_stack_size) {
    DCHECK(!activations_.empty());
    activations_.back()->SetCurrentActivationFrame(
        reinterpret_cast<uint8_t*>(fp), current_frame_size, current_stack_size,
        ref_stack_size);
  }

  WasmInterpreterThread::Activation* GetActivation(
      Address frame_pointer) const {
    for (size_t i = 0; i < activations_.size(); i++) {
      if (activations_[i]->GetFramePointer() == frame_pointer) {
        return activations_[i].get();
      }
    }
    return nullptr;
  }

  uint8_t* NextFrameAddress() const {
    if (activations_.empty()) {
      return stack_mem();
    } else {
      return activations_.back()->NextFrameAddress();
    }
  }

  uint32_t NextRefStackOffset() const {
    if (activations_.empty()) {
      return 0;
    } else {
      return activations_.back()->NextRefStackOffset();
    }
  }
  const uint8_t* StackLimitAddress() const {
    return stack_mem() + current_stack_size_;
  }

  void StartExecutionTimer();
  void StopExecutionTimer();
  void TerminateExecutionTimers();

  static void SetRuntimeLastWasmError(Isolate* isolate,
                                      MessageTemplate message);
  static TrapReason GetRuntimeLastWasmError(Isolate* isolate);

#ifdef V8_ENABLE_DRUMBRAKE_TRACING
  uint32_t CurrentStackFrameStart() const {
    if (activations_.empty()) {
      return 0;
    } else {
      return activations_.back()->CurrentStackFrameStart();
    }
  }

  uint32_t CurrentStackFrameSize() const {
    if (activations_.empty()) {
      return 0;
    } else {
      return activations_.back()->CurrentStackFrameSize();
    }
  }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING

  void RaiseException(Isolate* isolate, MessageTemplate message);

 private:
  void Finish() { state_ = State::FINISHED; }

  inline uint8_t* stack_mem() const {
    return reinterpret_cast<uint8_t*>(stack_mem_);
  }

  static WasmInterpreterThreadMap* thread_interpreter_map_s;

  Isolate* isolate_;
  State state_;
  TrapReason trap_reason_;

  static constexpr uint32_t kInitialStackSize = 1 * MB;
  static constexpr uint32_t kStackSizeIncrement = 1 * MB;
  static constexpr uint32_t kMaxStackSize = 32 * MB;
  uint32_t current_stack_size_;
  void* stack_mem_;

  std::vector<std::unique_ptr<Activation>> activations_;

  WasmExecutionTimer execution_timer_;
};

// The interpreter interface.
class V8_EXPORT_PRIVATE WasmInterpreter {
 public:
  // The main storage for interpreter code. It maps {WasmFunction} to the
  // metadata needed to execute each function.
  class CodeMap {
   public:
    CodeMap(Isolate* isolate, const WasmModule* module,
            const uint8_t* module_start, Zone* zone);

    const WasmModule* module() const { return module_; }

    inline InterpreterCode* GetCode(uint32_t function_index);

    inline WasmBytecode* GetFunctionBytecode(uint32_t func_index);

    inline void AddFunction(const WasmFunction* function,
                            const uint8_t* code_start, const uint8_t* code_end);

    void SetFunctionCode(const WasmFunction* function, const uint8_t* start,
                         const uint8_t* end);

    size_t TotalBytecodeSize() {
      return generated_code_size_.load(std::memory_order_relaxed);
    }

   private:
    void Preprocess(uint32_t function_index);

    Zone* zone_;
    Isolate* isolate_;
    const WasmModule* module_;
    ZoneVector<InterpreterCode> interpreter_code_;

    base::TimeDelta bytecode_generation_time_;
    std::atomic<size_t> generated_code_size_;
  };

  WasmInterpreter(Isolate* isolate, const WasmModule* module,
                  const ModuleWireBytes& wire_bytes,
                  Handle<WasmInstanceObject> instance);

  static void InitializeOncePerProcess();
  static void GlobalTearDown();
  static void NotifyIsolateDisposal(Isolate* isolate);

  inline void BeginExecution(WasmInterpreterThread* thread,
                             uint32_t function_index, Address frame_pointer,
                             uint8_t* interpreter_fp, uint32_t ref_stack_offset,
                             const std::vector<WasmValue>& argument_values);
  inline void BeginExecution(WasmInterpreterThread* thread,
                             uint32_t function_index, Address frame_pointer,
                             uint8_t* interpreter_fp);

  WasmInterpreterThread::State ContinueExecution(WasmInterpreterThread* thread,
                                                 bool called_from_js);

  inline WasmValue GetReturnValue(int index) const;

  inline std::vector<WasmInterpreterStackEntry> GetInterpretedStack(
      Address frame_pointer);

  inline int GetFunctionIndex(Address frame_pointer, int index) const;

  inline void SetTrapFunctionIndex(int32_t func_index);

  inline WasmInterpreterRuntime* GetWasmRuntime() {
    return wasm_runtime_.get();
  }

 private:
  // This {Zone} has the lifespan of this {WasmInterpreter}, which should
  // have the lifespan of the corresponding {WasmInstanceObject}.
  // The zone is used to allocate the {module_bytes_} vector below and the
  // {InterpreterCode} vector in the {CodeMap}. It is also passed to
  // {WasmDecoder} used to parse the 'locals' in a Wasm function.
  Zone zone_;
  Handle<WasmInstanceObject> instance_object_;

  // Create a copy of the module bytes for the interpreter, since the passed
  // pointer might be invalidated after constructing the interpreter.
  const ZoneVector<uint8_t> module_bytes_;

  CodeMap codemap_;

  // DrumBrake
  std::shared_ptr<WasmInterpreterRuntime> wasm_runtime_;

  WasmInterpreter(const WasmInterpreter&) = delete;
  WasmInterpreter& operator=(const WasmInterpreter&) = delete;
};

typedef InstrHandlerRetType(VECTORCALL PWasmOp)(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0);
#ifdef __clang__
#define MUSTTAIL [[clang::musttail]]
#else
#define MUSTTAIL
#endif  // __clang__

extern PWasmOp* kInstructionTable[];

// {OperatorMode}s are used for the
// v8_flags.drumbrake_register_optimization. The prototype of instruction
// handlers contains two arguments int64_t r0 and double fp0 that can be used to
// pass in an integer or floating-point register the values that is at the top
// of the Wasm execution stack.
//
// For this reasons, whenever possible we define four different versions of each
// instruction handler, all identified by the following prefixes:
//
// - r2r_*: Wasm instruction handlers called when the stack top value is in a
//          register and that put the result in a register.
// - r2s_*: Wasm instruction handlers called when the stack top value is in a
//          register and that push the result on the stack.
// - s2r_*: Wasm instruction handlers called when the stack top value is not in
//          a register and that put the result in a register.
// - s2s_*: Wasm instruction handlers called when the stack top value is not in
//          a register and that push the result on the stack.
//
enum OperatorMode { kR2R = 0, kR2S, kS2R, kS2S };
static const size_t kOperatorModeCount = 4;

// {RegMode} and {RegModeTransform} specifies how an instruction handler can
// leverage the --drumbrake-register-optimization.
//
// {RegModeTransform} defines a pair of {RegMode}s, that specify whether an
// instruction handler can take its input or provide its output from the stack
// or from registers.
//
// For example:
//    {kF32Reg, kI32Reg},  // 0x5b F32Eq
// declares that the F32Eq instruction handler can read the stack top value from
// a floating point register as a F32 and pass the result to the next handler in
// an integer register as an I32, so saving one stack pop and one stack push
// operations.
enum class RegMode {
  kNoReg,  // The instruction handler only gets inputs from stack slots or
           // provide the result into a stack slot.

  kI32Reg,  // The instruction handler can be optimized to work with the integer
  kI64Reg,  // register 'r0'.

  kF32Reg,  // The instruction handler can be optimized to work with the
  kF64Reg,  // floating point register 'fp0'.

  kAnyReg,  // The instruction handler can be optimized to work either with the
            // integer or fp register; the specific register depends on the
            // type of the type of the value at the top of the stack. This is
            // used for instructions like 'drop', 'select' and 'local.set.
};

inline RegMode GetRegMode(ValueKind kind) {
  switch (kind) {
    case kI32:
      return RegMode::kI32Reg;
    case kI64:
      return RegMode::kI64Reg;
    case kF32:
      return RegMode::kF32Reg;
    case kF64:
      return RegMode::kF64Reg;
    default:
      UNREACHABLE();
  }
}

struct RegModeTransform {
  RegMode from;
  RegMode to;
};

static const RegModeTransform kRegModes[256] = {
    {RegMode::kNoReg, RegMode::kNoReg},   // 0x00 Unreachable
    {RegMode::kNoReg, RegMode::kNoReg},   // 0x01 Nop
    {RegMode::kNoReg, RegMode::kNoReg},   // 0x02 Block
    {RegMode::kNoReg, RegMode::kNoReg},   // 0x03 Loop
    {RegMode::kI32Reg, RegMode::kNoReg},  // 0x04 If
    {RegMode::kNoReg, RegMode::kNoReg},   // 0x05 Else
    {RegMode::kNoReg, RegMode::kNoReg},   // 0x06 Try - eh_prototype
    {RegMode::kNoReg, RegMode::kNoReg},   // 0x07 Catch - eh_prototype
    {RegMode::kNoReg, RegMode::kNoReg},   // 0x08 Throw - eh_prototype
    {RegMode::kNoReg, RegMode::kNoReg},   // 0x09 Rethrow - eh_prototype
    {RegMode::kNoReg, RegMode::kNoReg},   // 0x0a (reserved)
    {RegMode::kNoReg, RegMode::kNoReg},   // 0x0b End
    {RegMode::kNoReg, RegMode::kNoReg},   // 0x0c Br
    {RegMode::kI32Reg, RegMode::kNoReg},  // 0x0d BrIf
    {RegMode::kI32Reg, RegMode::kNoReg},  // 0x0e BrTable
    {RegMode::kNoReg, RegMode::kNoReg},   // 0x0f Return
    {RegMode::kNoReg, RegMode::kNoReg},   // 0x10 CallFunction
    {RegMode::kNoReg, RegMode::kNoReg},   // 0x11 CallIndirect
    {RegMode::kNoReg, RegMode::kNoReg},   // 0x12 ReturnCall
    {RegMode::kNoReg, RegMode::kNoReg},   // 0x13 ReturnCallIndirect

    {RegMode::kNoReg,
     RegMode::kNoReg},  // 0x14 CallRef - typed_funcref prototype - NOTIMPL
    {RegMode::kNoReg, RegMode::kNoReg},  // 0x15 ReturnCallRef - typed_funcref
                                         // prototype - NOTIMPL
    {RegMode::kNoReg, RegMode::kNoReg},  // 0x16 (reserved)
    {RegMode::kNoReg, RegMode::kNoReg},  // 0x17 (reserved)
    {RegMode::kNoReg, RegMode::kNoReg},  // 0x18 Delegate - eh_prototype
    {RegMode::kNoReg, RegMode::kNoReg},  // 0x19 CatchAll - eh_prototype

    {RegMode::kAnyReg, RegMode::kNoReg},   // 0x1a Drop
    {RegMode::kI32Reg, RegMode::kAnyReg},  // 0x1b Select
    {RegMode::kI32Reg, RegMode::kAnyReg},  // 0x1c SelectWithType

    {RegMode::kNoReg, RegMode::kNoReg},    // 0x1d (reserved)
    {RegMode::kNoReg, RegMode::kNoReg},    // 0x1e (reserved)
    {RegMode::kNoReg, RegMode::kNoReg},    // 0x1f (reserved)
    {RegMode::kNoReg, RegMode::kNoReg},    // 0x20 LocalGet
    {RegMode::kAnyReg, RegMode::kNoReg},   // 0x21 LocalSet
    {RegMode::kNoReg, RegMode::kNoReg},    // 0x22 LocalTee
    {RegMode::kNoReg, RegMode::kAnyReg},   // 0x23 GlobalGet
    {RegMode::kAnyReg, RegMode::kNoReg},   // 0x24 GlobalSet
    {RegMode::kNoReg, RegMode::kNoReg},    // 0x25 TableGet
    {RegMode::kNoReg, RegMode::kNoReg},    // 0x26 TableSet
    {RegMode::kNoReg, RegMode::kNoReg},    // 0x27 (reserved)
    {RegMode::kI32Reg, RegMode::kI32Reg},  // 0x28 I32LoadMem
    {RegMode::kI32Reg, RegMode::kI64Reg},  // 0x29 I64LoadMem
    {RegMode::kI32Reg, RegMode::kF32Reg},  // 0x2a F32LoadMem
    {RegMode::kI32Reg, RegMode::kF64Reg},  // 0x2b F64LoadMem
    {RegMode::kI32Reg, RegMode::kI32Reg},  // 0x2c I32LoadMem8S
    {RegMode::kI32Reg, RegMode::kI32Reg},  // 0x2d I32LoadMem8U
    {RegMode::kI32Reg, RegMode::kI32Reg},  // 0x2e I32LoadMem16S
    {RegMode::kI32Reg, RegMode::kI32Reg},  // 0x2f I32LoadMem16U
    {RegMode::kI32Reg, RegMode::kI64Reg},  // 0x30 I64LoadMem8S
    {RegMode::kI32Reg, RegMode::kI64Reg},  // 0x31 I64LoadMem8U
    {RegMode::kI32Reg, RegMode::kI64Reg},  // 0x32 I64LoadMem16S
    {RegMode::kI32Reg, RegMode::kI64Reg},  // 0x33 I64LoadMem16U
    {RegMode::kI32Reg, RegMode::kI64Reg},  // 0x34 I64LoadMem32S
    {RegMode::kI32Reg, RegMode::kI64Reg},  // 0x35 I64LoadMem32U
    {RegMode::kI32Reg, RegMode::kNoReg},   // 0x36 I32StoreMem
    {RegMode::kI64Reg, RegMode::kNoReg},   // 0x37 I64StoreMem
    {RegMode::kF32Reg, RegMode::kNoReg},   // 0x38 F32StoreMem
    {RegMode::kF64Reg, RegMode::kNoReg},   // 0x39 F64StoreMem
    {RegMode::kI32Reg, RegMode::kNoReg},   // 0x3a I32StoreMem8
    {RegMode::kI32Reg, RegMode::kNoReg},   // 0x3b I32StoreMem16
    {RegMode::kI64Reg, RegMode::kNoReg},   // 0x3c I64StoreMem8
    {RegMode::kI64Reg, RegMode::kNoReg},   // 0x3d I64StoreMem16
    {RegMode::kI64Reg, RegMode::kNoReg},   // 0x3e I64StoreMem32
    {RegMode::kNoReg, RegMode::kNoReg},    // 0x3f MemorySize
    {RegMode::kNoReg, RegMode::kNoReg},    // 0x40 MemoryGrow

    {RegMode::kNoReg, RegMode::kNoReg},  // 0x41 I32Const
    {RegMode::kNoReg, RegMode::kNoReg},  // 0x42 I64Const
    {RegMode::kNoReg, RegMode::kNoReg},  // 0x43 F32Const
    {RegMode::kNoReg, RegMode::kNoReg},  // 0x44 F64Const

    {RegMode::kI32Reg, RegMode::kI32Reg},  // 0x45 I32Eqz
    {RegMode::kI32Reg, RegMode::kI32Reg},  // 0x46 I32Eq
    {RegMode::kI32Reg, RegMode::kI32Reg},  // 0x47 I32Ne
    {RegMode::kI32Reg, RegMode::kI32Reg},  // 0x48 I32LtS
    {RegMode::kI32Reg, RegMode::kI32Reg},  // 0x49 I32LtU
    {RegMode::kI32Reg, RegMode::kI32Reg},  // 0x4a I32GtS
    {RegMode::kI32Reg, RegMode::kI32Reg},  // 0x4b I32GtU
    {RegMode::kI32Reg, RegMode::kI32Reg},  // 0x4c I32LeS
    {RegMode::kI32Reg, RegMode::kI32Reg},  // 0x4d I32LeU
    {RegMode::kI32Reg, RegMode::kI32Reg},  // 0x4e I32GeS
    {RegMode::kI32Reg, RegMode::kI32Reg},  // 0x4f I32GeU
    {RegMode::kI64Reg, RegMode::kI32Reg},  // 0x50 I64Eqz
    {RegMode::kI64Reg, RegMode::kI32Reg},  // 0x51 I64Eq
    {RegMode::kI64Reg, RegMode::kI32Reg},  // 0x52 I64Ne
    {RegMode::kI64Reg, RegMode::kI32Reg},  // 0x53 I64LtS
    {RegMode::kI64Reg, RegMode::kI32Reg},  // 0x54 I64LtU
    {RegMode::kI64Reg, RegMode::kI32Reg},  // 0x55 I64GtS
    {RegMode::kI64Reg, RegMode::kI32Reg},  // 0x56 I64GtU
    {RegMode::kI64Reg, RegMode::kI32Reg},  // 0x57 I64LeS
    {RegMode::kI64Reg, RegMode::kI32Reg},  // 0x58 I64LeU
    {RegMode::kI64Reg, RegMode::kI32Reg},  // 0x59 I64GeS
    {RegMode::kI64Reg, RegMode::kI32Reg},  // 0x5a I64GeU
    {RegMode::kF32Reg, RegMode::kI32Reg},  // 0x5b F32Eq
    {RegMode::kF32Reg, RegMode::kI32Reg},  // 0x5c F32Ne
    {RegMode::kF32Reg, RegMode::kI32Reg},  // 0x5d F32Lt
    {RegMode::kF32Reg, RegMode::kI32Reg},  // 0x5e F32Gt
    {RegMode::kF32Reg, RegMode::kI32Reg},  // 0x5f F32Le
    {RegMode::kF32Reg, RegMode::kI32Reg},  // 0x60 F32Ge
    {RegMode::kF64Reg, RegMode::kI32Reg},  // 0x61 F64Eq
    {RegMode::kF64Reg, RegMode::kI32Reg},  // 0x62 F64Ne
    {RegMode::kF64Reg, RegMode::kI32Reg},  // 0x63 F64Lt
    {RegMode::kF64Reg, RegMode::kI32Reg},  // 0x64 F64Gt
    {RegMode::kF64Reg, RegMode::kI32Reg},  // 0x65 F64Le
    {RegMode::kF64Reg, RegMode::kI32Reg},  // 0x66 F64Ge

    {RegMode::kI32Reg, RegMode::kI32Reg},  // 0x67 I32Clz
    {RegMode::kI32Reg, RegMode::kI32Reg},  // 0x68 I32Ctz
    {RegMode::kI32Reg, RegMode::kI32Reg},  // 0x69 I32Popcnt
    {RegMode::kI32Reg, RegMode::kI32Reg},  // 0x6a I32Add
    {RegMode::kI32Reg, RegMode::kI32Reg},  // 0x6b I32Sub
    {RegMode::kI32Reg, RegMode::kI32Reg},  // 0x6c I32Mul
    {RegMode::kI32Reg, RegMode::kI32Reg},  // 0x6d I32DivS
    {RegMode::kI32Reg, RegMode::kI32Reg},  // 0x6e I32DivU
    {RegMode::kI32Reg, RegMode::kI32Reg},  /
"""


```