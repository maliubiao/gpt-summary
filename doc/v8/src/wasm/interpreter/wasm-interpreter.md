Response: Let's break down the thought process for summarizing this C++ code.

1. **Understand the Goal:** The request asks for a functional summary of a C++ file related to the V8 JavaScript engine's WebAssembly interpreter. It specifically requests connections to JavaScript. It's also explicitly labeled as "part 1 of 8," suggesting a larger context.

2. **Initial Scan and Keywords:** Quickly scan the code for prominent keywords and structures:
    * `#include`:  Indicates dependencies on other V8 components (e.g., `wasm/interpreter/wasm-interpreter.h`, `wasm/decoder.h`). This immediately signals its role within the broader V8 ecosystem.
    * `namespace v8::internal::wasm`: Confirms this is part of V8's internal WebAssembly implementation.
    * `class WasmInterpreter`: This is likely the central class for the interpreter itself.
    * `class WasmInterpreter::CodeMap`:  Suggests management of the WebAssembly bytecode.
    * `class WasmInterpreterThread`: Hints at handling execution on different threads.
    * `class WasmExecutionTimer`:  Points to performance tracking.
    * `INSTRUCTION_HANDLER_FUNC`: This is a recurring pattern, strongly suggesting the core execution logic of the interpreter.
    * Opcodes (e.g., `k_##name` in `EMIT_INSTR_HANDLER`, `s2r_GlobalGetI`, `r2s_GlobalSetI`):  These are WebAssembly instructions.
    * `TrapReason`:  Indicates error handling within the interpreter.

3. **Identify Core Components and Their Roles:** Based on the initial scan, start grouping related elements:

    * **`WasmInterpreter` Class:**  Seems to be the main orchestrator. The constructor takes a `WasmModule` and `WasmInstanceObject`, which are fundamental WebAssembly concepts. The presence of `codemap_` and `wasm_runtime_` as members suggests delegation of responsibilities.

    * **`CodeMap` Class:**  Clearly manages the mapping of WebAssembly functions to their code. The `Preprocess` method involving `BytecodeIterator` and `WasmBytecodeGenerator` indicates a step where the raw bytecode is processed into a more usable form for the interpreter. This is a key insight.

    * **`WasmInterpreterThread` Class:**  Manages the state of an interpreter running on a thread. The `Activation` inner class and `FrameState` within it suggest stack management and execution context. The `CaptureStackTrace` function is a telltale sign of debugging and error reporting.

    * **`WasmExecutionTimer` Class:**  Responsible for measuring and reporting execution time, likely for performance analysis and optimization. The interaction with V8 counters (`isolate_->counters()`) reinforces this.

    * **Instruction Handlers (`INSTRUCTION_HANDLER_FUNC`)**:  The sheer number and naming convention (e.g., `s2r_GlobalGetI`, `r2s_GlobalSetI`) strongly imply that these are the functions that *actually execute* the WebAssembly instructions. The prefixes like `s2r`, `r2s`, `s2s` likely relate to stack manipulation (stack-to-register, register-to-stack, stack-to-stack).

4. **Infer Functionality and Connections to JavaScript:**

    * **Interpretation:** The file's name and the presence of instruction handlers strongly point to its role as an *interpreter* for WebAssembly. This contrasts with *compilation*.
    * **Execution:** The `WasmInterpreterThread` and the instruction handlers confirm that this code is responsible for the step-by-step execution of WebAssembly bytecode.
    * **Memory Management:**  References to `wasm_runtime->GetMemoryStart()` and `base::ReadUnalignedValue`/`base::WriteUnalignedValue` show how the interpreter interacts with WebAssembly's linear memory.
    * **Global Variables:**  The `GlobalGet` and `GlobalSet` handlers demonstrate how the interpreter accesses and modifies WebAssembly global variables.
    * **Stack Operations:** The `push` and `pop` functions and the `sp` (stack pointer) argument in the instruction handlers are fundamental to stack-based virtual machines like the WebAssembly interpreter.
    * **Error Handling:** The `Trap` function and `TrapReason` enum clearly indicate how the interpreter handles runtime errors in WebAssembly.
    * **Performance Monitoring:** The `WasmExecutionTimer` directly relates to how V8 tracks the performance of WebAssembly execution.
    * **Connection to JavaScript:**  The fact that this is part of V8 *itself* is the primary connection. When JavaScript code calls a WebAssembly function, V8 can choose to execute that function using this interpreter (especially in non-optimized scenarios or for debugging).

5. **Formulate the Summary:**  Based on the above analysis, start writing the summary, focusing on the key components and their functions. Use clear and concise language. Highlight the connection to JavaScript.

6. **Develop the JavaScript Example:** To illustrate the connection to JavaScript, think about how a user would interact with WebAssembly. The most common way is to load a WebAssembly module and call its exported functions. Create a simple JavaScript example that does this, demonstrating how the C++ interpreter would be involved behind the scenes. Keep the example concise and focused on the core interaction.

7. **Review and Refine:** Read through the summary and the JavaScript example. Ensure they are accurate, easy to understand, and directly address the prompt's requirements. Check for any technical jargon that might need clarification. Make sure the connection between the C++ code and the JavaScript example is clear.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "Maybe this file just *loads* WebAssembly code."  **Correction:** The presence of instruction handlers strongly suggests *execution*, not just loading.
* **Initial thought:** "The JavaScript connection is just that it's *in* V8." **Refinement:**  Provide a concrete example of how JavaScript code triggers the use of this interpreter (calling a WebAssembly function).
* **Focus on high-level functionality:** Avoid getting bogged down in the details of every instruction handler. Focus on the *purpose* of these handlers.
* **Use the "part 1 of 8" context:** Acknowledge that this is likely part of a larger system, but focus on summarizing *this specific file*.

By following this structured approach, combining code analysis with an understanding of WebAssembly and JavaScript concepts, one can effectively summarize the functionality of the given C++ code.
这是 `v8/src/wasm/interpreter/wasm-interpreter.cc` 文件的第一部分，它主要负责 **WebAssembly 解释器的核心结构和一些基础功能**。  简单来说，它定义了如何解释执行 WebAssembly 代码。

以下是该部分的主要功能归纳：

1. **定义了 `WasmInterpreter` 类:** 这是 WebAssembly 解释器的主要类，负责管理解释 WebAssembly 模块所需的各种数据结构和执行流程。它包含了：
    * `CodeMap`:  用于存储和预处理 WebAssembly 函数的代码信息，例如起始地址、结束地址以及生成的字节码。
    * `WasmInterpreterRuntime`:  一个辅助类，用于在解释执行期间提供运行时环境，例如访问内存、全局变量等。

2. **实现了 `WasmInterpreter::CodeMap` 类:**  这个类负责：
    * 存储 WebAssembly 模块中每个函数的代码信息。
    * 在解释执行前对函数代码进行预处理，生成解释器可以高效执行的字节码表示 (`WasmBytecodeGenerator`)。
    * 维护已生成字节码的大小统计信息。

3. **定义了 `WasmInterpreterThread` 和 `WasmInterpreterThreadMap` 类:**  用于管理解释器在多线程环境下的执行。
    * `WasmInterpreterThread`:  代表一个执行 WebAssembly 代码的解释器线程，包含当前线程的执行状态、调用栈等信息。
    * `WasmInterpreterThreadMap`:  用于管理和查找当前 Isolate 下的解释器线程。

4. **定义了 `FrameState` 类:**  用于存储函数调用栈帧的状态信息，例如局部变量、控制流信息以及捕获的异常。

5. **实现了 `WasmExecutionTimer` 类:**  用于测量 WebAssembly 代码的执行时间，并生成性能统计信息，例如执行时间比例和慢速执行事件。这有助于分析和优化 WebAssembly 的性能。

6. **定义了一些辅助函数:**
    * `MakeWeak`:  创建一个指向 `WasmInstanceObject` 的弱引用。
    * `GetWasmReturnTypeFromSignature`:  从函数签名中获取 WebAssembly 函数的返回类型。

7. **实现了 `WasmInterpreterThread::Activation` 类:**  表示解释器线程上的一个激活记录（或调用栈帧），用于跟踪当前的函数执行状态。它包含捕获堆栈跟踪、获取函数索引等功能。

8. **实现了 `WasmInterpreterThread` 的异常处理相关功能:**  例如 `RaiseException` 和 `SetRuntimeLastWasmError`，用于在解释执行过程中抛出和记录 WebAssembly 异常。

9. **实现了 `WasmInterpreterThread` 的执行时间控制功能:**  例如 `StartExecutionTimer` 和 `StopExecutionTimer`，用于控制执行计时器的启动和停止。

10. **包含了对 `DRUMBRAKE_BOUNDS_CHECKS` 的处理:**  这部分代码与内存访问边界检查有关，在特定配置下（`!V8_DRUMBRAKE_BOUNDS_CHECKS`）会注册一些特殊的指令处理器，利用 V8 的内置机制来处理内存越界访问。

**与 JavaScript 的关系 (通过 JavaScript 举例):**

WebAssembly 代码通常在 JavaScript 环境中加载和执行。  这个 `wasm-interpreter.cc` 文件是 V8 引擎的一部分，当 JavaScript 调用 WebAssembly 模块中的函数时，如果 V8 决定使用解释器来执行该函数（例如，在没有进行 JIT 编译的情况下，或者出于调试目的），那么这个文件中的代码就会被调用。

**JavaScript 例子:**

```javascript
// 假设我们已经加载了一个名为 'myModule' 的 WebAssembly 模块实例

// 获取导出的函数 'add'
const addFunction = myModule.exports.add;

// 调用 WebAssembly 函数
const result = addFunction(5, 10);

console.log(result); // 输出 15
```

**背后的 C++ 解释过程 (简化说明):**

当 JavaScript 调用 `addFunction(5, 10)` 时，V8 引擎可能会执行以下步骤（与本文件相关的部分）：

1. **查找函数代码:**  V8 会找到 `add` 函数在 `WasmInterpreter::CodeMap` 中对应的代码信息，包括其字节码。
2. **创建解释器线程 (如果需要):**  如果当前没有可用的解释器线程，V8 可能会通过 `WasmInterpreterThreadMap` 创建一个新的 `WasmInterpreterThread`。
3. **设置调用栈:** 在 `WasmInterpreterThread` 的上下文中创建一个新的 `Activation` 和 `FrameState` 来表示 `add` 函数的调用。
4. **解释执行字节码:**  `WasmInterpreter` 会逐步读取 `add` 函数的字节码指令，并执行相应的操作。例如，对于加法操作，可能会调用类似 `s2s_I32Add` 这样的指令处理器（在这个文件的后续部分定义）。
5. **访问内存和全局变量 (如果需要):**  在执行过程中，如果需要访问 WebAssembly 的线性内存或全局变量，会通过 `WasmInterpreterRuntime` 来进行。
6. **返回结果:**  `add` 函数执行完毕后，结果会被返回给 JavaScript 环境。

**总结:**

该文件是 V8 中 WebAssembly 解释器的核心组成部分，定义了其基本架构、代码管理、线程管理、执行状态跟踪以及性能监控等关键功能。它直接参与了在 JavaScript 环境中解释执行 WebAssembly 代码的过程。

### 提示词
```
这是目录为v8/src/wasm/interpreter/wasm-interpreter.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共8部分，请归纳一下它的功能
```

### 源代码
```
// Copyright 2024 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/wasm/interpreter/wasm-interpreter.h"

#include <atomic>
#include <limits>
#include <optional>
#include <type_traits>

#include "include/v8-metrics.h"
#include "src/base/overflowing-math.h"
#include "src/builtins/builtins.h"
#include "src/handles/global-handles-inl.h"
#include "src/snapshot/embedded/embedded-data-inl.h"
#include "src/wasm/decoder.h"
#include "src/wasm/function-body-decoder-impl.h"
#include "src/wasm/interpreter/wasm-interpreter-inl.h"
#include "src/wasm/interpreter/wasm-interpreter-runtime-inl.h"
#include "src/wasm/object-access.h"
#include "src/wasm/wasm-objects-inl.h"
#include "src/wasm/wasm-opcodes-inl.h"

namespace v8 {
namespace internal {
namespace wasm {

#define EMIT_INSTR_HANDLER(name) EmitFnId(k_##name);
#define EMIT_INSTR_HANDLER_WITH_PC(name, pc) EmitFnId(k_##name, pc);

static auto ReadI16 = Read<int16_t>;
static auto ReadI32 = Read<int32_t>;

WasmInterpreter::CodeMap::CodeMap(Isolate* isolate, const WasmModule* module,
                                  const uint8_t* module_start, Zone* zone)
    : zone_(zone),
      isolate_(isolate),
      module_(module),
      interpreter_code_(zone),
      bytecode_generation_time_(),
      generated_code_size_(0) {
  if (module == nullptr) return;
  interpreter_code_.reserve(module->functions.size());
  for (const WasmFunction& function : module->functions) {
    if (function.imported) {
      DCHECK(!function.code.is_set());
      AddFunction(&function, nullptr, nullptr);
    } else {
      AddFunction(&function, module_start + function.code.offset(),
                  module_start + function.code.end_offset());
    }
  }
}

void WasmInterpreter::CodeMap::SetFunctionCode(const WasmFunction* function,
                                               const uint8_t* start,
                                               const uint8_t* end) {
  DCHECK_LT(function->func_index, interpreter_code_.size());
  InterpreterCode* code = &interpreter_code_[function->func_index];
  DCHECK_EQ(function, code->function);
  code->start = const_cast<uint8_t*>(start);
  code->end = const_cast<uint8_t*>(end);
  Preprocess(function->func_index);
}

void WasmInterpreter::CodeMap::Preprocess(uint32_t function_index) {
  InterpreterCode* code = &interpreter_code_[function_index];
  DCHECK_EQ(code->function->imported, code->start == nullptr);
  DCHECK(!code->bytecode && code->start);

  base::TimeTicks start_time = base::TimeTicks::Now();

  // Compute the control targets map and the local declarations.
  BytecodeIterator it(code->start, code->end, &code->locals, zone_);

  WasmBytecodeGenerator bytecode_generator(function_index, code, module_);
  code->bytecode = bytecode_generator.GenerateBytecode();

  // Generate histogram sample to measure the time spent generating the
  // bytecode. Reuse the WasmCompileModuleMicroSeconds.wasm that is currently
  // obsolete.
  if (base::TimeTicks::IsHighResolution()) {
    base::TimeDelta duration = base::TimeTicks::Now() - start_time;
    bytecode_generation_time_ += duration;
    int bytecode_generation_time_usecs =
        static_cast<int>(bytecode_generation_time_.InMicroseconds());

    // TODO(paolosev@microsoft.com) Do not add a sample for each function!
    isolate_->counters()->wasm_compile_wasm_module_time()->AddSample(
        bytecode_generation_time_usecs);
  }

  // Generate histogram sample to measure the bytecode size. Reuse the
  // V8.WasmModuleCodeSizeMiB (see {NativeModule::SampleCodeSize}).
  int prev_code_size_mb = generated_code_size_ == 0
                              ? -1
                              : static_cast<int>(generated_code_size_ / MB);
  generated_code_size_.fetch_add(code->bytecode->GetCodeSize());
  int code_size_mb = static_cast<int>(generated_code_size_ / MB);
  if (prev_code_size_mb < code_size_mb) {
    Histogram* histogram = isolate_->counters()->wasm_module_code_size_mb();
    histogram->AddSample(code_size_mb);
  }
}

// static
WasmInterpreterThreadMap* WasmInterpreterThread::thread_interpreter_map_s =
    nullptr;

WasmInterpreterThread* WasmInterpreterThreadMap::GetCurrentInterpreterThread(
    Isolate* isolate) {
  const int current_thread_id = ThreadId::Current().ToInteger();
  {
    base::MutexGuard guard(&mutex_);

    auto it = map_.find(current_thread_id);
    if (it == map_.end()) {
      map_[current_thread_id] =
          std::make_unique<WasmInterpreterThread>(isolate);
      it = map_.find(current_thread_id);
    }
    return it->second.get();
  }
}

void WasmInterpreterThreadMap::NotifyIsolateDisposal(Isolate* isolate) {
  base::MutexGuard guard(&mutex_);

  auto it = map_.begin();
  while (it != map_.end()) {
    WasmInterpreterThread* thread = it->second.get();
    if (thread->GetIsolate() == isolate) {
      thread->TerminateExecutionTimers();
      it = map_.erase(it);
    } else {
      ++it;
    }
  }
}

void FrameState::SetCaughtException(Isolate* isolate,
                                    uint32_t catch_block_index,
                                    Handle<Object> exception) {
  if (caught_exceptions_.is_null()) {
    DCHECK_NOT_NULL(current_function_);
    uint32_t blocks_count = current_function_->GetBlocksCount();
    Handle<FixedArray> caught_exceptions =
        isolate->factory()->NewFixedArrayWithHoles(blocks_count);
    caught_exceptions_ = isolate->global_handles()->Create(*caught_exceptions);
  }
  caught_exceptions_->set(catch_block_index, *exception);
}

Handle<Object> FrameState::GetCaughtException(
    Isolate* isolate, uint32_t catch_block_index) const {
  Handle<Object> exception =
      handle(caught_exceptions_->get(catch_block_index), isolate);
  DCHECK(!IsTheHole(*exception));
  return exception;
}

void FrameState::DisposeCaughtExceptionsArray(Isolate* isolate) {
  if (!caught_exceptions_.is_null()) {
    isolate->global_handles()->Destroy(caught_exceptions_.location());
    caught_exceptions_ = Handle<FixedArray>::null();
  }
}

WasmExecutionTimer::WasmExecutionTimer(Isolate* isolate,
                                       bool track_jitless_wasm)
    : execute_ratio_histogram_(
          track_jitless_wasm
              ? isolate->counters()->wasm_jitless_execution_ratio()
              : isolate->counters()->wasm_jit_execution_ratio()),
      slow_wasm_histogram_(
          track_jitless_wasm
              ? isolate->counters()->wasm_jitless_execution_too_slow()
              : isolate->counters()->wasm_jit_execution_too_slow()),
      window_has_started_(false),
      next_interval_time_(),
      start_interval_time_(),
      window_running_time_(),
      sample_duration_(base::TimeDelta::FromMilliseconds(std::max(
          0, v8_flags.wasm_exec_time_histogram_sample_duration.value()))),
      slow_threshold_(v8_flags.wasm_exec_time_histogram_slow_threshold.value()),
      slow_threshold_samples_count_(std::max(
          1, v8_flags.wasm_exec_time_slow_threshold_samples_count.value())),
      isolate_(isolate) {
  int cooldown_interval_in_msec = std::max(
      0, v8_flags.wasm_exec_time_histogram_sample_period.value() -
             v8_flags.wasm_exec_time_histogram_sample_duration.value());
  cooldown_interval_ =
      base::TimeDelta::FromMilliseconds(cooldown_interval_in_msec);
}

void WasmExecutionTimer::BeginInterval(bool start_timer) {
  window_has_started_ = true;
  start_interval_time_ = base::TimeTicks::Now();
  window_running_time_ = base::TimeDelta();
  if (start_timer) {
    window_execute_timer_.Start();
  }
}

void WasmExecutionTimer::EndInterval() {
  window_has_started_ = false;
  base::TimeTicks now = base::TimeTicks::Now();
  next_interval_time_ = now + cooldown_interval_;
  int running_ratio = kMaxPercentValue *
                      window_running_time_.TimesOf(now - start_interval_time_);
  AddSample(running_ratio);
}

void WasmExecutionTimer::AddSample(int running_ratio) {
  DCHECK(v8_flags.wasm_enable_exec_time_histograms && v8_flags.slow_histograms);

  execute_ratio_histogram_->AddSample(running_ratio);

  // Emit a Jit[less]WasmExecutionTooSlow sample if the average of the last
  // {v8_flags.wasm_exec_time_slow_threshold_samples_count} samples is above
  // {v8_flags.wasm_exec_time_histogram_slow_threshold}.
  samples_.push_back(running_ratio);
  if (samples_.size() == slow_threshold_samples_count_) {
    int sum = 0;
    for (int sample : samples_) sum += sample;
    int average = sum / slow_threshold_samples_count_;
    if (average >= slow_threshold_) {
      slow_wasm_histogram_->AddSample(average);

      if (isolate_ && !isolate_->context().is_null()) {
        // Skip this event because not(yet) supported by Chromium.

        // HandleScope scope(isolate_);
        // v8::metrics::WasmInterpreterSlowExecution event;
        // event.slow_execution = true;
        // event.jitless = v8_flags.wasm_jitless;
        // event.cpu_percentage = average;
        // v8::metrics::Recorder::ContextId context_id =
        //     isolate_->GetOrRegisterRecorderContextId(
        //         isolate_->native_context());
        // isolate_->metrics_recorder()->DelayMainThreadEvent(event,
        // context_id);
      }
    }

    samples_.clear();
  }
}

void WasmExecutionTimer::StartInternal() {
  DCHECK(v8_flags.wasm_enable_exec_time_histograms && v8_flags.slow_histograms);
  DCHECK(!window_execute_timer_.IsStarted());

  base::TimeTicks now = base::TimeTicks::Now();
  if (window_has_started_) {
    if (now - start_interval_time_ > sample_duration_) {
      EndInterval();
    } else {
      window_execute_timer_.Start();
    }
  } else {
    if (now >= next_interval_time_) {
      BeginInterval(true);
    } else {
      // Ignore this start event.
    }
  }
}

void WasmExecutionTimer::StopInternal() {
  DCHECK(v8_flags.wasm_enable_exec_time_histograms && v8_flags.slow_histograms);

  base::TimeTicks now = base::TimeTicks::Now();
  if (window_has_started_) {
    DCHECK(window_execute_timer_.IsStarted());
    base::TimeDelta elapsed = window_execute_timer_.Elapsed();
    window_running_time_ += elapsed;
    window_execute_timer_.Stop();
    if (now - start_interval_time_ > sample_duration_) {
      EndInterval();
    }
  } else {
    if (now >= next_interval_time_) {
      BeginInterval(false);
    } else {
      // Ignore this stop event.
    }
  }
}

void WasmExecutionTimer::Terminate() {
  if (execute_ratio_histogram_->Enabled()) {
    if (window_has_started_) {
      if (window_execute_timer_.IsStarted()) {
        window_execute_timer_.Stop();
      }
      EndInterval();
    }
  }
}

namespace {
void NopFinalizer(const v8::WeakCallbackInfo<void>& data) {
  Address* global_handle_location =
      reinterpret_cast<Address*>(data.GetParameter());
  GlobalHandles::Destroy(global_handle_location);
}

Handle<WasmInstanceObject> MakeWeak(
    Isolate* isolate, Handle<WasmInstanceObject> instance_object) {
  Handle<WasmInstanceObject> weak_instance =
      isolate->global_handles()->Create<WasmInstanceObject>(*instance_object);
  Address* global_handle_location = weak_instance.location();
  GlobalHandles::MakeWeak(global_handle_location, global_handle_location,
                          &NopFinalizer, v8::WeakCallbackType::kParameter);
  return weak_instance;
}

std::optional<wasm::ValueType> GetWasmReturnTypeFromSignature(
    const FunctionSig* wasm_signature) {
  if (wasm_signature->return_count() == 0) return {};

  DCHECK_EQ(wasm_signature->return_count(), 1);
  return wasm_signature->GetReturn(0);
}

}  // namespace

// Build the interpreter call stack for the current activation. For each stack
// frame we need to calculate the Wasm function index and the original Wasm
// bytecode location, calculated from the current WasmBytecode offset.
std::vector<WasmInterpreterStackEntry>
WasmInterpreterThread::Activation::CaptureStackTrace(
    const TrapStatus* trap_status) const {
  std::vector<WasmInterpreterStackEntry> stack_trace;
  const FrameState* frame_state = &current_frame_state_;
  DCHECK_NOT_NULL(frame_state);

  if (trap_status) {
    stack_trace.push_back(WasmInterpreterStackEntry{
        trap_status->trap_function_index, trap_status->trap_pc});
  } else {
    if (frame_state->current_function_) {
      stack_trace.push_back(WasmInterpreterStackEntry{
          frame_state->current_function_->GetFunctionIndex(),
          frame_state->current_bytecode_
              ? static_cast<int>(
                    frame_state->current_function_->GetPcFromTrapCode(
                        frame_state->current_bytecode_))
              : 0});
    }
  }

  frame_state = frame_state->previous_frame_;
  while (frame_state && frame_state->current_function_) {
    stack_trace.insert(
        stack_trace.begin(),
        WasmInterpreterStackEntry{
            frame_state->current_function_->GetFunctionIndex(),
            frame_state->current_bytecode_
                ? static_cast<int>(
                      frame_state->current_function_->GetPcFromTrapCode(
                          frame_state->current_bytecode_))
                : 0});
    frame_state = frame_state->previous_frame_;
  }

  return stack_trace;
}

int WasmInterpreterThread::Activation::GetFunctionIndex(int index) const {
  std::vector<int> function_indexes;
  const FrameState* frame_state = &current_frame_state_;
  // TODO(paolosev@microsoft.com) - Too slow?
  while (frame_state->current_function_) {
    function_indexes.push_back(
        frame_state->current_function_->GetFunctionIndex());
    frame_state = frame_state->previous_frame_;
  }

  if (static_cast<size_t>(index) < function_indexes.size()) {
    return function_indexes[function_indexes.size() - index - 1];
  }
  return -1;
}

void WasmInterpreterThread::RaiseException(Isolate* isolate,
                                           MessageTemplate message) {
  DCHECK_EQ(WasmInterpreterThread::TRAPPED, state_);
  if (!isolate->has_exception()) {
    ClearThreadInWasmScope wasm_flag(isolate);
    Handle<JSObject> error_obj =
        isolate->factory()->NewWasmRuntimeError(message);
    JSObject::AddProperty(isolate, error_obj,
                          isolate->factory()->wasm_uncatchable_symbol(),
                          isolate->factory()->true_value(), NONE);
    isolate->Throw(*error_obj);
  }
}

// static
void WasmInterpreterThread::SetRuntimeLastWasmError(Isolate* isolate,
                                                    MessageTemplate message) {
  WasmInterpreterThread* current_thread = GetCurrentInterpreterThread(isolate);
  current_thread->trap_reason_ = WasmOpcodes::MessageIdToTrapReason(message);
}

// static
TrapReason WasmInterpreterThread::GetRuntimeLastWasmError(Isolate* isolate) {
  WasmInterpreterThread* current_thread = GetCurrentInterpreterThread(isolate);
  // TODO(paolosev@microsoft.com): store in new data member?
  return current_thread->trap_reason_;
}

void WasmInterpreterThread::StartExecutionTimer() {
  if (v8_flags.wasm_enable_exec_time_histograms && v8_flags.slow_histograms) {
    execution_timer_.Start();
  }
}

void WasmInterpreterThread::StopExecutionTimer() {
  if (v8_flags.wasm_enable_exec_time_histograms && v8_flags.slow_histograms) {
    execution_timer_.Stop();
  }
}

void WasmInterpreterThread::TerminateExecutionTimers() {
  if (v8_flags.wasm_enable_exec_time_histograms && v8_flags.slow_histograms) {
    execution_timer_.Terminate();
  }
}

#if !defined(V8_DRUMBRAKE_BOUNDS_CHECKS)

enum BoundsCheckedHandlersCounter {
#define ITEM_ENUM_DEFINE(name) name##counter,
  FOREACH_LOAD_STORE_INSTR_HANDLER(ITEM_ENUM_DEFINE)
#undef ITEM_ENUM_DEFINE
      kTotalItems
};

V8_DECLARE_ONCE(init_instruction_table_once);
V8_DECLARE_ONCE(init_trap_handlers_once);

// A subset of the Wasm instruction handlers is implemented as ASM builtins, and
// not with normal C++ functions. This is done only for LoadMem and StoreMem
// builtins, which can trap for out of bounds accesses.
// V8 already implements out of bounds trap handling for compiled Wasm code and
// allocates two large guard pages before and after each Wasm memory region to
// detect out of bounds memory accesses. Once an access violation exception
// arises, the V8 exception filter intercepts the exception and checks whether
// it originates from Wasm code.
// The Wasm interpreter reuses the same logic, and
// WasmInterpreter::HandleWasmTrap is called by the SEH exception handler to
// check whether the access violation was caused by an interpreter instruction
// handler. It is necessary that these handlers are Wasm builtins for two
// reasons:
// 1. We want to know precisely the start and end address of each handler to
// verify if the AV happened inside one of the Load/Store builtins and can be
// handled with a Wasm trap.
// 2. If the exception is handled, we interrupt the execution of
// TrapMemOutOfBounds, which sets the TRAPPED state and breaks the execution of
// the chain of instruction handlers with a x64 'ret'. This only works if there
// is no stack cleanup to do in the handler that caused the failure (no
// registers to pop from the stack before the 'ret'). Therefore we cannot rely
// on the compiler, we can only make sure that this is the case if we implement
// the handlers in assembly.

// Forward declaration
INSTRUCTION_HANDLER_FUNC TrapMemOutOfBounds(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0);

void InitTrapHandlersOnce(Isolate* isolate) {
  CHECK_LE(kInstructionCount, kInstructionTableSize);

  ClearThreadInWasmScope wasm_flag(isolate);

  // Overwrites the instruction handlers that access memory and can cause an
  // out-of-bounds trap with builtin versions that don't have explicit bounds
  // check but rely on a trap handler to intercept the access violation and
  // transform it into a trap.
  EmbeddedData embedded_data = EmbeddedData::FromBlob();
#define V(name)                                               \
  trap_handler::RegisterHandlerData(                          \
      reinterpret_cast<Address>(kInstructionTable[k_##name]), \
      embedded_data.InstructionSizeOf(Builtin::k##name), 0, nullptr);
  FOREACH_LOAD_STORE_INSTR_HANDLER(V)
#undef V
}

void InitInstructionTableOnce(Isolate* isolate) {
  size_t index = 0;
#define V(name)                                            \
  kInstructionTable[index++] = reinterpret_cast<PWasmOp*>( \
      isolate->builtins()->code(Builtin::k##name)->instruction_start());
#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcast-calling-convention"
#endif  // __clang__
  FOREACH_LOAD_STORE_INSTR_HANDLER(V)
#ifdef __clang__
#pragma clang diagnostic pop
#endif  // __clang__
#undef V
}
#endif  // !V8_DRUMBRAKE_BOUNDS_CHECKS

WasmInterpreter::WasmInterpreter(Isolate* isolate, const WasmModule* module,
                                 const ModuleWireBytes& wire_bytes,
                                 Handle<WasmInstanceObject> instance_object)
    : zone_(isolate->allocator(), ZONE_NAME),
      instance_object_(MakeWeak(isolate, instance_object)),
      module_bytes_(wire_bytes.start(), wire_bytes.end(), &zone_),
      codemap_(isolate, module, module_bytes_.data(), &zone_) {
  wasm_runtime_ = std::make_shared<WasmInterpreterRuntime>(
      module, isolate, instance_object_, &codemap_);
  module->SetWasmInterpreter(wasm_runtime_);

#if !defined(V8_DRUMBRAKE_BOUNDS_CHECKS)
  // TODO(paolosev@microsoft.com) - For modules that have 64-bit Wasm memory we
  // need to use explicit bound checks; memory guard pages only work with 32-bit
  // memories. This could be implemented by allocating a different dispatch
  // table for each instance (probably in the WasmInterpreterRuntime object) and
  // patching the entries of Load/Store instructions with bultin handlers only
  // for instances related to modules that have 32-bit memories. 64-bit memories
  // are not supported yet by DrumBrake.
  base::CallOnce(&init_instruction_table_once, &InitInstructionTableOnce,
                 isolate);
  base::CallOnce(&init_trap_handlers_once, &InitTrapHandlersOnce, isolate);

  trap_handler::SetLandingPad(reinterpret_cast<Address>(TrapMemOutOfBounds));
#endif  // !V8_DRUMBRAKE_BOUNDS_CHECKS
}

WasmInterpreterThread::State WasmInterpreter::ContinueExecution(
    WasmInterpreterThread* thread, bool called_from_js) {
  wasm_runtime_->ContinueExecution(thread, called_from_js);
  return thread->state();
}

////////////////////////////////////////////////////////////////////////////////
//
// DrumBrake: implementation of an interpreter for WebAssembly.
//
////////////////////////////////////////////////////////////////////////////////

constexpr uint32_t kFloat32SignBitMask = uint32_t{1} << 31;
constexpr uint64_t kFloat64SignBitMask = uint64_t{1} << 63;

#ifdef DRUMBRAKE_ENABLE_PROFILING

static const char* prev_op_name_s = nullptr;
static std::map<std::pair<const char*, const char*>, uint64_t>*
    ops_pairs_count_s = nullptr;
static std::map<const char*, uint64_t>* ops_count_s = nullptr;
static void ProfileOp(const char* op_name) {
  if (!ops_pairs_count_s) {
    ops_pairs_count_s =
        new std::map<std::pair<const char*, const char*>, uint64_t>();
    ops_count_s = new std::map<const char*, uint64_t>();
  }
  if (prev_op_name_s) {
    (*ops_pairs_count_s)[{prev_op_name_s, op_name}]++;
  }
  (*ops_count_s)[op_name]++;
  prev_op_name_s = op_name;
}

template <typename A, typename B>
std::pair<B, A> flip_pair(const std::pair<A, B>& p) {
  return std::pair<B, A>(p.second, p.first);
}
template <typename A, typename B>
std::multimap<B, A> flip_map(const std::map<A, B>& src) {
  std::multimap<B, A> dst;
  std::transform(src.begin(), src.end(), std::inserter(dst, dst.begin()),
                 flip_pair<A, B>);
  return dst;
}

static void PrintOpsCount() {
  std::multimap<uint64_t, const char*> count_ops_map = flip_map(*ops_count_s);
  uint64_t total_count = 0;
  for (auto& pair : count_ops_map) {
    printf("%10lld, %s\n", pair.first, pair.second);
    total_count += pair.first;
  }
  printf("Total count: %10lld\n\n", total_count);

  std::multimap<uint64_t, std::pair<const char*, const char*>>
      count_pairs_ops_map = flip_map(*ops_pairs_count_s);
  for (auto& pair : count_pairs_ops_map) {
    printf("%10lld, %s -> %s\n", pair.first, pair.second.first,
           pair.second.second);
  }
}

static void PrintAndClearProfilingData() {
  PrintOpsCount();
  delete ops_count_s;
  ops_count_s = nullptr;
  delete ops_pairs_count_s;
  ops_pairs_count_s = nullptr;
}

#define NextOp()                                                             \
  ProfileOp(__FUNCTION__);                                                   \
  MUSTTAIL return kInstructionTable[ReadFnId(code) & kInstructionTableMask]( \
      code, sp, wasm_runtime, r0, fp0)

#else  // DRUMBRAKE_ENABLE_PROFILING

#define NextOp()                                                             \
  MUSTTAIL return kInstructionTable[ReadFnId(code) & kInstructionTableMask]( \
      code, sp, wasm_runtime, r0, fp0)

#endif  // DRUMBRAKE_ENABLE_PROFILING

namespace {
INSTRUCTION_HANDLER_FUNC Trap(const uint8_t* code, uint32_t* sp,
                              WasmInterpreterRuntime* wasm_runtime, int64_t r0,
                              double fp0) {
  TrapReason trap_reason = static_cast<TrapReason>(r0);
  wasm_runtime->SetTrap(trap_reason, code);
  MUSTTAIL return s_unwind_func_addr(code, sp, wasm_runtime, trap_reason, .0);
}
}  // namespace

#define TRAP(trap_reason) \
  MUSTTAIL return Trap(code, sp, wasm_runtime, trap_reason, fp0);

#define INLINED_TRAP(trap_reason)           \
  wasm_runtime->SetTrap(trap_reason, code); \
  MUSTTAIL return s_unwind_func_addr(code, sp, wasm_runtime, trap_reason, .0);

////////////////////////////////////////////////////////////////////////////////
// GlobalGet

template <typename IntT>
INSTRUCTION_HANDLER_FUNC s2r_GlobalGetI(const uint8_t* code, uint32_t* sp,
                                        WasmInterpreterRuntime* wasm_runtime,
                                        int64_t r0, double fp0) {
  uint32_t index = ReadGlobalIndex(code);
  uint8_t* src_addr = wasm_runtime->GetGlobalAddress(index);
  r0 = base::ReadUnalignedValue<IntT>(reinterpret_cast<Address>(src_addr));

  NextOp();
}
static auto s2r_I32GlobalGet = s2r_GlobalGetI<int32_t>;
static auto s2r_I64GlobalGet = s2r_GlobalGetI<int64_t>;

template <typename FloatT>
INSTRUCTION_HANDLER_FUNC s2r_GlobalGetF(const uint8_t* code, uint32_t* sp,
                                        WasmInterpreterRuntime* wasm_runtime,
                                        int64_t r0, double fp0) {
  uint32_t index = ReadGlobalIndex(code);
  uint8_t* src_addr = wasm_runtime->GetGlobalAddress(index);
  fp0 = base::ReadUnalignedValue<FloatT>(reinterpret_cast<Address>(src_addr));

  NextOp();
}
static auto s2r_F32GlobalGet = s2r_GlobalGetF<float>;
static auto s2r_F64GlobalGet = s2r_GlobalGetF<double>;

template <typename T>
INSTRUCTION_HANDLER_FUNC s2s_GlobalGet(const uint8_t* code, uint32_t* sp,
                                       WasmInterpreterRuntime* wasm_runtime,
                                       int64_t r0, double fp0) {
  uint32_t index = ReadGlobalIndex(code);
  uint8_t* src_addr = wasm_runtime->GetGlobalAddress(index);
  push<T>(sp, code, wasm_runtime,
          base::ReadUnalignedValue<T>(reinterpret_cast<Address>(src_addr)));

  NextOp();
}
static auto s2s_I32GlobalGet = s2s_GlobalGet<int32_t>;
static auto s2s_I64GlobalGet = s2s_GlobalGet<int64_t>;
static auto s2s_F32GlobalGet = s2s_GlobalGet<float>;
static auto s2s_F64GlobalGet = s2s_GlobalGet<double>;
static auto s2s_S128GlobalGet = s2s_GlobalGet<Simd128>;

INSTRUCTION_HANDLER_FUNC s2s_RefGlobalGet(const uint8_t* code, uint32_t* sp,
                                          WasmInterpreterRuntime* wasm_runtime,
                                          int64_t r0, double fp0) {
  uint32_t index = ReadGlobalIndex(code);
  push<WasmRef>(sp, code, wasm_runtime, wasm_runtime->GetGlobalRef(index));

  NextOp();
}

////////////////////////////////////////////////////////////////////////////////
// GlobalSet

template <typename IntT>
INSTRUCTION_HANDLER_FUNC r2s_GlobalSetI(const uint8_t* code, uint32_t* sp,
                                        WasmInterpreterRuntime* wasm_runtime,
                                        int64_t r0, double fp0) {
  uint32_t index = ReadGlobalIndex(code);
  uint8_t* dst_addr = wasm_runtime->GetGlobalAddress(index);
  base::WriteUnalignedValue<IntT>(reinterpret_cast<Address>(dst_addr),
                                  static_cast<IntT>(r0));  // r0: value
  NextOp();
}
static auto r2s_I32GlobalSet = r2s_GlobalSetI<int32_t>;
static auto r2s_I64GlobalSet = r2s_GlobalSetI<int64_t>;

template <typename FloatT>
INSTRUCTION_HANDLER_FUNC r2s_GlobalSetF(const uint8_t* code, uint32_t* sp,
                                        WasmInterpreterRuntime* wasm_runtime,
                                        int64_t r0, double fp0) {
  uint32_t index = ReadGlobalIndex(code);
  uint8_t* dst_addr = wasm_runtime->GetGlobalAddress(index);
  base::WriteUnalignedValue<FloatT>(reinterpret_cast<Address>(dst_addr),
                                    static_cast<FloatT>(fp0));  // fp0: value
  NextOp();
}
static auto r2s_F32GlobalSet = r2s_GlobalSetF<float>;
static auto r2s_F64GlobalSet = r2s_GlobalSetF<double>;

template <typename T>
INSTRUCTION_HANDLER_FUNC s2s_GlobalSet(const uint8_t* code, uint32_t* sp,
                                       WasmInterpreterRuntime* wasm_runtime,
                                       int64_t r0, double fp0) {
  uint32_t index = ReadGlobalIndex(code);
  uint8_t* dst_addr = wasm_runtime->GetGlobalAddress(index);
  base::WriteUnalignedValue<T>(reinterpret_cast<Address>(dst_addr),
                               pop<T>(sp, code, wasm_runtime));
  NextOp();
}
static auto s2s_I32GlobalSet = s2s_GlobalSet<int32_t>;
static auto s2s_I64GlobalSet = s2s_GlobalSet<int64_t>;
static auto s2s_F32GlobalSet = s2s_GlobalSet<float>;
static auto s2s_F64GlobalSet = s2s_GlobalSet<double>;
static auto s2s_S128GlobalSet = s2s_GlobalSet<Simd128>;

INSTRUCTION_HANDLER_FUNC s2s_RefGlobalSet(const uint8_t* code, uint32_t* sp,
                                          WasmInterpreterRuntime* wasm_runtime,
                                          int64_t r0, double fp0) {
  uint32_t index = ReadGlobalIndex(code);
  wasm_runtime->SetGlobalRef(index, pop<WasmRef>(sp, code, wasm_runtime));

  NextOp();
}

////////////////////////////////////////////////////////////////////////////////
// Drop

template <typename T>
INSTRUCTION_HANDLER_FUNC r2s_Drop(const uint8_t* code, uint32_t* sp,
                                  WasmInterpreterRuntime* wasm_runtime,
                                  int64_t r0, double fp0) {
  NextOp();
}
static auto r2s_I32Drop = r2s_Drop<int32_t>;
static auto r2s_I64Drop = r2s_Drop<int64_t>;
static auto r2s_F32Drop = r2s_Drop<float>;
static auto r2s_F64Drop = r2s_Drop<double>;

INSTRUCTION_HANDLER_FUNC r2s_RefDrop(const uint8_t* code, uint32_t* sp,
                                     WasmInterpreterRuntime* wasm_runtime,
                                     int64_t r0, double fp0) {
  UNREACHABLE();
}

template <typename T>
INSTRUCTION_HANDLER_FUNC s2s_Drop(const uint8_t* code, uint32_t* sp,
                                  WasmInterpreterRuntime* wasm_runtime,
                                  int64_t r0, double fp0) {
  pop<T>(sp, code, wasm_runtime);

  NextOp();
}
static auto s2s_I32Drop = s2s_Drop<int32_t>;
static auto s2s_I64Drop = s2s_Drop<int64_t>;
static auto s2s_F32Drop = s2s_Drop<float>;
static auto s2s_F64Drop = s2s_Drop<double>;
static auto s2s_S128Drop = s2s_Drop<Simd128>;

INSTRUCTION_HANDLER_FUNC s2s_RefDrop(const uint8_t* code, uint32_t* sp,
                                     WasmInterpreterRuntime* wasm_runtime,
                                     int64_t r0, double fp0) {
  pop<WasmRef>(sp, code, wasm_runtime);

  NextOp();
}

////////////////////////////////////////////////////////////////////////////////
// LoadMem

#if defined(V8_DRUMBRAKE_BOUNDS_CHECKS)

template <typename IntT, typename IntU = IntT>
INSTRUCTION_HANDLER_FUNC r2r_LoadMemI(const uint8_t* code, uint32_t* sp,
                                      WasmInterpreterRuntime* wasm_runtime,
                                      int64_t r0, double fp0) {
  uint8_t* memory_start = wasm_runtime->GetMemoryStart();
  uint64_t offset = Read<uint64_t>(code);
  uint64_t index = r0;
  uint64_t effective_index = offset + index;

  if (V8_UNLIKELY(effective_index < index ||
                  !base::IsInBounds<uint64_t>(effective_index, sizeof(IntU),
                                              wasm_runtime->GetMemorySize()))) {
    TRAP(TrapReason::kTrapMemOutOfBounds)
  }

  uint8_t* address = memory_start + effective_index;

  IntU value =
      base::ReadUnalignedValue<IntU>(reinterpret_cast<Address>(address));
  r0 = static_cast<IntT>(value);

  NextOp();
}
static auto r2r_I32LoadMem8S = r2r_LoadMemI<int32_t, int8_t>;
static auto r2r_I32LoadMem8U = r2r_LoadMemI<int32_t, uint8_t>;
static auto r2r_I32LoadMem16S = r2r_LoadMemI<int32_t, int16_t>;
static auto r2r_I32LoadMem16U = r2r_LoadMemI<int32_t, uint16_t>;
static auto r2r_I64LoadMem8S = r2r_LoadMemI<int64_t, int8_t>;
static auto r2r_I64LoadMem8U = r2r_LoadMemI<int64_t, uint8_t>;
static auto r2r_I64LoadMem16S = r2r_LoadMemI<int64_t, int16_t>;
static auto r2r_I64LoadMem16U = r2r_LoadMemI<int64_t, uint16_t>;
static auto r2r_I64LoadMem32S = r2r_LoadMemI<int64_t, int32_t>;
static auto r2r_I64LoadMem32U = r2r_LoadMemI<int64_t, uint32_t>;
static auto r2r_I32LoadMem = r2r_LoadMemI<int32_t>;
static auto r2r_I64LoadMem = r2r_LoadMemI<int64_t>;

template <typename FloatT>
INSTRUCTION_HANDLER_FUNC r2r_LoadMemF(const uint8_t* code, uint32_t* sp,
                                      WasmInterpreterRuntime* wasm_runtime,
                                      int64_t r0, double fp0) {
  uint8_t* memory_start = wasm_runtime->GetMemoryStart();
  uint64_t offset = Read<uint64_t>(code);
  uint64_t index = r0;
  uint64_t effective_index = offset + index;

  if (V8_UNLIKELY(effective_index < index ||
                  !base::IsInBounds<uint64_t>(effective_index, sizeof(FloatT),
                                              wasm_runtime->GetMemorySize()))) {
    TRAP(TrapReason::kTrapMemOutOfBounds)
  }

  uint8_t* address = memory_start + effective_index;

  fp0 = base::ReadUnalignedValue<FloatT>(reinterpret_cast<Address>(address));

  NextOp();
}
static auto r2r_F32LoadMem = r2r_LoadMemF<float>;
static auto r2r_F64LoadMem = r2r_LoadMemF<double>;

template <typename T, typename U = T>
INSTRUCTION_HANDLER_FUNC r2s_LoadMem(const uint8_t* code, uint32_t* sp,
                                     WasmInterpreterRuntime* wasm_runtime,
                                     int64_t r0, double fp0) {
  uint8_t* memory_start = wasm_runtime->GetMemoryStart();
  uint64_t offset = Read<uint64_t>(code);
  uint64_t index = r0;
  uint64_t effective_index = offset + index;

  if (V8_UNLIKELY(effective_index < index ||
                  !base::IsInBounds<uint64_t>(effective_index, sizeof(U),
                                              wasm_runtime->GetMemorySize()))) {
    TRAP(TrapReason::kTrapMemOutOfBounds)
  }

  uint8_t* address = memory_start + effective_index;

  U value = base::ReadUnalignedValue<U>(reinterpret_cast<Address>(address));

  push<T>(sp, code, wasm_runtime, value);

  NextOp();
}
static auto r2s_I32LoadMem8S = r2s_LoadMem<int32_t, int8_t>;
static auto r2s_I32LoadMem8U = r2s_LoadMem<int32_t, uint8_t>;
static auto r2s_I32LoadMem16S = r2s_LoadMem<int32_t, int16_t>;
static auto r2s_I32LoadMem16U = r2s_LoadMem<int32_t, uint16_t>;
static auto r2s_I64LoadMem8S = r2s_LoadMem<int64_t, int8_t>;
static auto r2s_I64LoadMem8U = r2s_LoadMem<int64_t, uint8_t>;
static auto r2s_I64LoadMem16S = r2s_LoadMem<int64_t, int16_t>;
static auto r2s_I64LoadMem16U = r2s_LoadMem<int64_t, uint16_t>;
static auto r2s_I64LoadMem32S = r2s_LoadMem<int64_t, int32_t>;
static auto r2s_I64LoadMem32U = r2s_LoadMem<int64_t, uint32_t>;
static auto r2s_I32LoadMem = r2s_LoadMem<int32_t>;
static auto r2s_I64LoadMem = r2s_LoadMem<int64_t>;
static auto r2s_F32LoadMem = r2s_LoadMem<float>;
static auto r2s_F64LoadMem = r2s_LoadMem<double>;

template <typename IntT, typename IntU = IntT>
INSTRUCTION_HANDLER_FUNC s2r_LoadMemI(const uint8_t* code, uint32_t* sp,
                                      WasmInterpreterRuntime* wasm_runtime,
                                      int64_t r0, double fp0) {
  uint8_t* memory_start = wasm_runtime->GetMemoryStart();
  uint64_t offset = Read<uint64_t>(code);
  uint64_t index = pop<uint32_t>(sp, code, wasm_runtime);
  uint64_t effective_index = offset + index;

  if (V8_UNLIKELY(effective_index < index ||
                  !base::IsInBounds<uint64_t>(effective_index, sizeof(IntU),
                                              wasm_runtime->GetMemorySize()))) {
    TRAP(TrapReason::kTrapMemOutOfBounds)
  }

  uint8_t* address = memory_start + effective_index;

  r0 = static_cast<IntT>(
      base::ReadUnalignedValue<IntU>(reinterpret_cast<Address>(address)));

  NextOp();
}
static auto s2r_I32LoadMem8S = s2r_LoadMemI<int32_t, int8_t>;
static auto s2r_I32LoadMem8U = s2r_LoadMemI<int32_t, uint8_t>;
static auto s2r_I32LoadMem16S = s2r_LoadMemI<int32_t, int16_t>;
static auto s2r_I32LoadMem16U = s2r_LoadMemI<int32_t, uint16_t>;
static auto s2r_I64LoadMem8S = s2r_LoadMemI<int64_t, int8_t>;
static auto s2r_I64LoadMem8U = s2r_LoadMemI<int64_t, uint8_t>;
static auto s2r_I64LoadMem16S = s2r_LoadMemI<int64_t, int16_t>;
static auto s2r_I64LoadMem16U = s2r_LoadMemI<int64_t, uint16_t>;
static auto s2r_I64LoadMem32S = s2r_LoadMemI<int64_t, int32_t>;
static auto s2r_I64LoadMem32U = s2r_LoadMemI<int64_t, uint32_t>;
static auto s2r_I32LoadMem = s2r_LoadMemI<int32_t>;
static auto s2r_I64LoadMem = s2r_LoadMemI<int64_t>;

template <typename FloatT>
INSTRUCTION_HANDLER_FUNC s2r_LoadMemF(const uint8_t* code, uint32_t* sp,
                                      WasmInterpreterRuntime* wasm_runtime,
                                      int64_t r0, double fp0) {
  uint8_t* memory_start = wasm_runtime->GetMemoryStart();
  uint64_t offset = Read<uint64_t>(code);
  uint64_t index = pop<uint32_t>(sp, code, wasm_runtime);
  uint64_t effective_index = offset + index;

  if (V8_UNLIKELY(effective_index < index ||
                  !base::IsInBounds<uint64_t>(effective_index, sizeof(FloatT),
                                              wasm_runtime->GetMemorySize()))) {
    TRAP(TrapReason::kTrapMemOutOfBounds)
  }

  uint8_t* address = memory_start + effective_index;

  fp0 = static_cast<FloatT>(
      base::ReadUnalignedValue<FloatT>(reinterpret_cast<Address>(address)));

  NextOp();
}
static auto s2r_F32LoadMem = s2r_LoadMemF<float>;
static auto s2r_F64LoadMem = s2r_LoadMemF<double>;

template <typename T, typename U = T>
INSTRUCTION_HANDLER_FUNC s2s_LoadMem(const uint8_t* code, uint32_t* sp,
                                     WasmInterpreterRuntime* wasm_runtime,
                                     int64_t r0, double fp0) {
  uint8_t* memory_start = wasm_runtime->GetMemoryStart();
  uint64_t offset = Read<uint64_t>(code);
  uint64_t index = pop<uint32_t>(sp, code, wasm_runtime);
  uint64_t effective_index = offset + index;

  if (V8_UNLIKELY(effective_index < index ||
                  !base::IsInBounds<uint64_t>(effective_index, sizeof(U),
                                              wasm_runtime->GetMemorySize()))) {
    TRAP(TrapReason::kTrapMemOutOfBounds)
  }

  uint8_t* address = memory_start + effective_index;

  U value = base::ReadUnalignedValue<U>(reinterpret_cast<Address>(address));

  push<T>(sp, code, wasm_runtime, value);

  NextOp();
}
static auto s2s_I32LoadMem8S = s2s_LoadMem<int32_t, int8_t>;
static auto s2s_I32LoadMem8U = s2s_LoadMem<int32_t, uint8_t>;
static auto s2s_I32LoadMem16S = s2s_LoadMem<int32_t, int16_t>;
static auto s2s_I32LoadMem16U = s2s_LoadMem<int32_t, uint16_t>;
static auto s2s_I64LoadMem8S = s2s_LoadMem<int64_t, int8_t>;
static auto s2s_I64LoadMem8U = s2s_LoadMem<int64_t, uint8_t>;
static auto s2s_I64LoadMem16S = s2s_LoadMem<int64_t, int16_t>;
static auto s2s_I64LoadMem16U = s2s_LoadMem<int64_t, uint16_t>;
static auto s2s_I64LoadMem32S = s2s_LoadMem<int64_t, int32_t>;
static auto s2s_I64LoadMem32U = s2s_LoadMem<int64_t, uint32_t>;
static auto s2s_I32LoadMem = s2s_LoadMem<int32_t>;
static auto s2s_I64LoadMem = s2s_LoadMem<int64_t>;
static auto s2s_F32LoadMem = s2s_LoadMem<float>;
static auto s2s_F64LoadMem = s2s_LoadMem<double>;

////////////////////////////////////////////////////////////////////////////////
// LoadMem_LocalSet

template <typename T, typename U = T>
INSTRUCTION_HANDLER_FUNC r2s_LoadMem_LocalSet(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0) {
  uint8_t* memory_start = wasm_runtime->GetMemoryStart();
  uint64_t offset = Read<uint64_t>(code);
  uint64_t index = r0;
  uint64_t effective_index = offset + index;

  if (V8_UNLIKELY(effective_index < index ||
                  !base::IsInBounds<uint64_t>(effective_index, sizeof(U),
                                              wasm_runtime->GetMemorySize()))) {
    TRAP(TrapReason::kTrapMemOutOfBounds)
  }

  uint8_t* address = memory_start + effective_index;

  U value = base::ReadUnalignedValue<U>(reinterpret_cast<Address>(address));

  uint32_t to = ReadI32(code);
  base::WriteUnalignedValue<T>(reinterpret_cast<Address>(sp + to),
                               static_cast<T>(value));

  NextOp();
}
static auto r2s_I32LoadMem8S_LocalSet = r2s_LoadMem_LocalSet<int32_t, int8_t>;
static auto r2s_I32LoadMem8U_LocalSet = r2s_LoadMem_LocalSet<int32_t, uint8_t>;
static auto r2s_I32LoadMem16S_LocalSet = r2s_LoadMem_LocalSet<int32_t, int16_t>;
static auto r2s_I32LoadMem16U_LocalSet =
    r2s_LoadMem_LocalSet<int32_t, uint16_t>;
static auto r2s_I64LoadMem8S_LocalSet = r2s_LoadMem_LocalSet<int64_t, int8_t>;
static auto r2s_I64LoadMem8U_LocalSet = r2s_LoadMem_LocalSet<int64_t, uint8_t>;
static auto r2s_I64LoadMem16S_LocalSet = r2s_LoadMem_LocalSet<int64_t, int16_t>;
static auto r2s_I64LoadMem16U_LocalSet =
    r2s_LoadMem_LocalSet<int64_t, uint16_t>;
static auto r2s_I64LoadMem32S_LocalSet = r2s_LoadMem_LocalSet<int64_t, int32_t>;
static auto r2s_I64LoadMem32U_LocalSet =
    r2s_LoadMem_LocalSet<int64_t, uint32_t>;
static auto r2s_I32LoadMem_LocalSet = r2s_LoadMem_LocalSet<int32_t>;
static auto r2s_I64LoadMem_LocalSet = r2s_LoadMem_LocalSet<int64_t>;
static auto r2s_F32LoadMem_LocalSet = r2s_LoadMem_LocalSet<float>;
static auto r2s_F64LoadMem_LocalSet = r2s_LoadMem_LocalSet<double>;

template <typename T, typename U = T>
INSTRUCTION_HANDLER_FUNC s2s_LoadMem_LocalSet(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0) {
  uint8_t* memory_start = wasm_runtime->GetMemoryStart();
  uint64_t offset = Read<uint64_t>(code);
  uint64_t index = pop<int32_t>(sp, code, wasm_runtime);
  uint64_t effective_index = offset + index;

  if (V8_UNLIKELY(effective_index < index ||
                  !base::IsInBounds<uint64_t>(effective_index, sizeof(U),
                                              wasm_runtime->GetMemorySize()))) {
    TRAP(TrapReason::kTrapMemOutOfBounds)
  }

  uint8_t* address = memory_start + effective_index;

  U value = base::ReadUnalignedValue<U>(reinterpret_cast<Address>(address));

  uint32_t to = ReadI32(code);
  base::WriteUnalignedValue<T>(reinterpret_cast<Address>(sp + to),
                               static_cast<T>(value));

  NextOp();
}
static auto s2s_I32LoadMem8S_LocalSet = s2s_LoadMem_LocalSet<int32_t, int8_t>;
static auto s2s_I32LoadMem8U_LocalSet = s2s_LoadMem_LocalSet<int32_t, uint8_t>;
static auto s2s_I32LoadMem16S_LocalSet = s2s_LoadMem_LocalSet<int32_t, int16_t>;
static auto s2s_I32LoadMem16U_LocalSet =
    s2s_LoadMem_LocalSet<int32_t, uint16_t>;
static auto s2s_I64LoadMem8S_LocalSet = s2s_LoadMem_LocalSet<int64_t, int8_t>;
static auto s2s_I64LoadMem8U_LocalSet = s2s_LoadMem_LocalSet<int64_t, uint8_t>;
static auto s2s_I64LoadMem16S_LocalSet = s2s_LoadMem_LocalSet<int64_t, int16_t>;
static auto s2s_I64LoadMem16U_LocalSet =
    s2s_LoadMem_LocalSet<int64_t, uint16_t>;
static auto s2s_I64LoadMem32S_LocalSet = s2s_LoadMem_LocalSet<int64_t, int32_t>;
static auto s2s_I64LoadMem32U_LocalSet =
    s2s_LoadMem_LocalSet<int64_t, uint32_t>;
static auto s2s_I32LoadMem_LocalSet = s2s_LoadMem_LocalSet<int32_t>;
static auto s2s_I64LoadMem_LocalSet = s2s_LoadMem_LocalSet<int64_t>;
static auto s2s_F32LoadMem_LocalSet = s2s_LoadMem_LocalSet<float>;
static auto s2s_F64LoadMem_LocalSet = s2s_LoadMem_LocalSet<double>;

////////////////////////////////////////////////////////////////////////////////
// StoreMem

template <typename IntT, typename IntU = IntT>
INSTRUCTION_HANDLER_FUNC r2s_StoreMemI(const uint8_t* code, uint32_t* sp,
                                       WasmInterpreterRuntime* wasm_runtime,
                                       int64_t r0, double fp0) {
  IntT value = static_cast<IntT>(r0);

  uint8_t* memory_start = wasm_runtime->GetMemoryStart();
  uint64_t offset = Read<uint64_t>(code);
  uint64_t index = pop<uint32_t>(sp, code, wasm_runtime);
  uint64_t effective_index = offset + index;

  if (V8_UNLIKELY(effective_index < index ||
                  !base::IsInBounds<uint64_t>(effective_index, sizeof(IntU),
                                              wasm_runtime->GetMemorySize()))) {
    TRAP(TrapReason::kTrapMemOutOfBounds)
  }

  uint8_t* address = memory_start + effective_index;

  base::WriteUnalignedValue<IntU>(
      reinterpret_cast<Address>(address),
      base::ReadUnalignedValue<IntU>(reinterpret_cast<Address>(&value)));

  NextOp();
}
static auto r2s_I32StoreMem8 = r2s_StoreMemI<int32_t, int8_t>;
static auto r2s_I32StoreMem16 = r2s_StoreMemI<int32_t, int16_t>;
static auto r2s_I64StoreMem8 = r2s_StoreMemI<int64_t, int8_t>;
static auto r2s_I64StoreMem16 = r2s_StoreMemI<int64_t, int16_t>;
static auto r2s_I64StoreMem32 = r2s_StoreMemI<int64_t, int32_t>;
static auto r2s_I32StoreMem = r2s_StoreMemI<int32_t>;
static auto r2s_I64StoreMem = r2s_StoreMemI<int64_t>;

template <typename FloatT>
INSTRUCTION_HANDLER_FUNC r2s_StoreMemF(const uint8_t* code, uint32_t* sp,
                                       WasmInterpreterRuntime* wasm_runtime,
                                       int64_t r0, double fp0) {
  FloatT value = static_cast<FloatT>(fp0);

  uint8_t* memory_start = wasm_runtime->GetMemoryStart();
  uint64_t offset = Read<uint64_t>(code);
  uint64_t index = pop<uint32_t>(sp, code, wasm_runtime);
  uint64_t effective_index = offset + index;

  if (V8_UNLIKELY(effective_index < index ||
                  !base::IsInBounds<uint64_t>(effective_index, sizeof(FloatT),
                                              wasm_runtime->GetMemorySize()))) {
    TRAP(TrapReason::kTrapMemOutOfBounds)
  }

  uint8_t* address = memory_start + effective_index;

  base::WriteUnalignedValue<FloatT>(
      reinterpret_cast<Address>(address),
      base::ReadUnalignedValue<FloatT>(reinterpret_cast<Address>(&value)));

  NextOp();
}
static auto r2s_F32StoreMem = r2s_StoreMemF<float>;
static auto r2s_F64StoreMem = r2s_StoreMemF<double>;

template <typename T, typename U = T>
INSTRUCTION_HANDLER_FUNC s2s_StoreMem(const uint8_t* code, uint32_t* sp,
                                      WasmInterpreterRuntime* wasm_runtime,
                                      int64_t r0, double fp0) {
  T value = pop<T>(sp, code, wasm_runtime);

  uint8_t* memory_start = wasm_runtime->GetMemoryStart();
  uint64_t offset = Read<uint64_t>(code);
  uint64_t index = pop<uint32_t>(sp, code, wasm_runtime);
  uint64_t effective_index = offset + index;

  if (V8_UNLIKELY(effective_index < index ||
                  !base::IsInBounds<uint64_t>(effective_index, sizeof(U),
                                              wasm_runtime->GetMemorySize()))) {
    TRAP(TrapReason::kTrapMemOutOfBounds)
  }

  uint8_t* address = memory_start + effective_index;

  base::WriteUnalignedValue<U>(
      reinterpret_cast<Address>(address),
      base::ReadUnalignedValue<U>(reinterpret_cast<Address>(&value)));

  NextOp();
}
static auto s2s_I32StoreMem8 = s2s_StoreMem<int32_t, int8_t>;
static auto s2s_I32StoreMem16 = s2s_StoreMem<int32_t, int16_t>;
static auto s2s_I64StoreMem8 = s2s_StoreMem<int64_t, int8_t>;
static auto s2s_I64StoreMem16 = s2s_StoreMem<int64_t, int16_t>;
static auto s2s_I64StoreMem32 = s2s_StoreMem<int64_t, int32_t>;
static auto s2s_I32StoreMem = s2s_StoreMem<int32_t>;
static auto s2s_I64StoreMem = s2s_StoreMem<int64_t>;
static auto s2s_F32StoreMem = s2s_StoreMem<float>;
static auto s2s_F64StoreMem = s2s_StoreMem<double>;

////////////////////////////////////////////////////////////////////////////////
// LocalGet_StoreMem

template <typename T, typename U = T>
INSTRUCTION_HANDLER_FUNC s2s_LocalGet_StoreMem(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0) {
  uint32_t from = ReadI32(code);
  T value = base::ReadUnalignedValue<T>(reinterpret_cast<Address>(sp + from));

  uint8_t* memory_start = wasm_runtime->GetMemoryStart();
  uint64_t offset = Read<uint64_t>(code);
  uint64_t index = pop<uint32_t>(sp, code, wasm_runtime);
  uint64_t effective_index = offset + index;

  if (V8_UNLIKELY(effective_index < index ||
                  !base::IsInBounds<uint64_t>(effective_index, sizeof(U),
                                              wasm_runtime->GetMemorySize()))) {
    TRAP(TrapReason::kTrapMemOutOfBounds)
  }

  uint8_t* address = memory_start + effective_index;

  base::WriteUnalignedValue<U>(
      reinterpret_cast<Address>(address),
      base::ReadUnalignedValue<U>(reinterpret_cast<Address>(&value)));

  NextOp();
}
static auto s2s_LocalGet_I32StoreMem8 = s2s_LocalGet_StoreMem<int32_t, int8_t>;
static auto s2s_LocalGet_I32StoreMem16 =
    s2s_LocalGet_StoreMem<int32_t, int16_t>;
static auto s2s_LocalGet_I64StoreMem8 = s2s_LocalGet_StoreMem<int64_t, int8_t>;
static auto s2s_LocalGet_I64StoreMem16 =
    s2s_LocalGet_StoreMem<int64_t, int16_t>;
static auto s2s_LocalGet_I64StoreMem32 =
    s2s_LocalGet_StoreMem<int64_t, int32_t>;
static auto s2s_LocalGet_I32StoreMem = s2s_LocalGet_StoreMem<int32_t>;
static auto s2s_LocalGet_I64StoreMem = s2s_LocalGet_StoreMem<int64_t>;
static auto s2s_LocalGet_F32StoreMem = s2s_LocalGet_StoreMem<float>;
static auto s2s_LocalGet_F64StoreMem = s2s_LocalGet_StoreMem<double>;

////////////////////////////////////////////////////////////////////////////////
// LoadStoreMem

template <typename T>
INSTRUCTION_HANDLER_FUNC r2s_LoadStoreMem(const uint8_t* code, uint32_t* sp,
                                          WasmInterpreterRuntime* wasm_runtime,
                                          int64_t r0, double fp0) {
  uint8_t* memory_start = wasm_runtime->GetMemoryStart();

  uint64_t load_offset = Read<uint64_t>(code);
  uint64_t load_index = r0;
  uint64_t effective_load_index = load_offset + load_index;

  uint64_t store_offset = Read<uint64_t>(code);
  uint64_t store_index = pop<uint32_t>(sp, code, wasm_runtime);
  uint64_t effective_store_index = store_offset + store_index;

  if (V8_UNLIKELY(effective_load_index < load_index ||
                  !base::IsInBounds<uint64_t>(effective_load_index, sizeof(T),
                                              wasm_runtime->GetMemorySize()) ||
                  effective_store_index < store_offset ||
                  !base::IsInBounds<uint64_t>(effective_store_index, sizeof(T),
                                              wasm_runtime->GetMemorySize()))) {
    TRAP(TrapReason::kTrapMemOutOfBounds)
  }

  uint8_t* load_address = memory_start + effective_load_index;
  uint8_t* store_address = memory_start + effective_store_index;

  base::WriteUnalignedValue<T>(
      reinterpret_cast<Address>(store_address),
      base::ReadUnalignedValue<T>(reinterpret_cast<Address>(load_address)));

  NextOp();
}
static auto r2s_I32LoadStoreMem = r2s_LoadStoreMem<int32_t>;
static auto r2s_I64LoadStoreMem = r2s_LoadStoreMem<int64_t>;
static auto r2s_F32LoadStoreMem = r2s_LoadStoreMem<float>;
static auto r2s_F64LoadStoreMem = r2s_LoadStoreMem<double>;

template <typename T>
INSTRUCTION_HANDLER_FUNC s2s_LoadStoreMem(const uint8_t* code, uint32_t* sp,
                                          WasmInterpreterRuntime* wasm_runtime,
                                          int64_t r0, double fp0) {
  uint8_t* memory_start = wasm_runtime->GetMemoryStart();

  uint64_t load_offset = Read<uint64_t>(code);
  uint64_t load_index = pop<uint32_t>(sp, code, wasm_runtime);
  uint64_t effective_load_index = load_offset + load_index;

  uint64_t store_offset = Read<uint64_t>(code);
  uint64_t store_index = pop<uint32_t>(sp, code, wasm_runtime);
  uint64_t effective_store_index = store_offset + store_index;

  if (V8_UNLIKELY(effective_load_index < load_index ||
                  !base::IsInBounds<uint64_t>(effective_load_index, sizeof(T),
                                              wasm_runtime->GetMemorySize()) ||
                  effective_store_index < store_offset ||
                  !base::IsInBounds<uint64_t>(effective_store_index, sizeof(T),
                                              wasm_runtime->GetMemorySize()))) {
    TRAP(TrapReason::kTrapMemOutOfBounds)
  }

  uint8_t* load_address = memory_start + effective_load_index;
  uint8_t* store_address = memory_start + effective_store_index;

  base::WriteUnalignedValue<T>(
      reinterpret_cast<Address>(store_address),
      base::ReadUnalignedValue<T>(reinterpret_cast<Address>(load_address)));

  NextOp();
}
static auto s2s_I32LoadStoreMem = s2s_LoadStoreMem<int32_t>;
static auto s2s_I64LoadStoreMem = s2s_LoadStoreMem<int64_t>;
static auto s2s_F32LoadStoreMem = s2s_LoadStoreMem<float>;
static auto s2s_F64LoadStoreMem = s2s_LoadStoreMem<double>;

#endif  // V8_DRUMBRAKE_BOUNDS_CHECKS

////////////////////////////////////////////////////////////////////////////////
// Select

template <typename IntT>
INSTRUCTION_HANDLER_FUNC r2r_SelectI(const uint8_t* code, uint32_t* sp,
                                     WasmInterpreterRuntime* wasm_runtime,
                                     int64_t r0, double fp0) {
  IntT val2 = pop<IntT>(sp, code, wasm_runtime);
  IntT val1 = pop<IntT>(sp, code, wasm_runtime);

  // r0: condition
  r0 = r0 ? val1 : val2;

  NextOp();
}
static auto r2r_I32Select = r2r_SelectI<int32_t>;
static auto r2r_I64Select = r2r_SelectI<int64_t>;

template <typename FloatT>
INSTRUCTION_HANDLER_FUNC r2r_SelectF(const uint8_t* code, uint32_t* sp,
                                     WasmInterpreterRuntime* wasm_runtime,
                                     int64_t r0, double fp0) {
  FloatT val2 = pop<FloatT>(sp, code, wasm_runtime);
  FloatT val1 = pop<FloatT>(sp, code, wasm_runtime);

  // r0: condition
  fp0 = r0 ? val1 : val2;

  NextOp();
}
static auto r2r_F32Select = r2r_SelectF<float>;
static auto r2r_F64Select = r2r_SelectF<double>;

template <typename T>
INSTRUCTION_HANDLER_FUNC r2s_Select(const uint8_t* code, uint32_t* sp,
                                    WasmInterpreterRuntime* wasm_runtime,
                                    int64_t r0, double fp0) {
  T val2 = pop<T>(sp, code, wasm_runtime);
  T val1 = pop<T>(sp, code, wasm_runtime);

  push<T>(sp, code, wasm_runtime, r0 ? val1 : val2);

  NextOp();
}
static auto r2s_I32Select = r2s_Select<int32_t>;
static auto r2s_I64Select = r2s_Select<int64_t>;
static auto r2s_F32Select = r2s_Select<float>;
static auto r2s_F64Select = r2s_Select<double>;
static auto r2s_S128Select = r2s_Select<Simd128>;

INSTRUCTION_HANDLER_FUNC r2s_RefSelect(const uint8_t* code, uint32_t* sp,
                                       WasmInterpreterRuntime* wasm_runtime,
                                       int64_t r0, double fp0) {
  WasmRef val2 = pop<WasmRef>(sp, code, wasm_runtime);
  WasmRef val1 = pop<WasmRef>(sp, code, wasm_runtime);
  push<WasmRef>(sp, code, wasm_runtime, r0 ? val1 : val2);

  NextOp();
}

template <typename IntT>
INSTRUCTION_HANDLER_FUNC s2r_SelectI(const uint8_t* code, uint32_t* sp,
                                     WasmInterpreterRuntime* wasm_runtime,
                                     int64_t r0, double fp0) {
  int32_t cond = pop<int32_t>(sp, code, wasm_runtime);
  IntT val2 = pop<IntT>(sp, code, wasm_runtime);
  IntT val1 = pop<IntT>(sp, code, wasm_runtime);

  r0 = cond ? val1 : val2;

  NextOp();
}
static auto s2r_I32Select = s2r_SelectI<int32_t>;
static auto s2r_I64Select = s2r_SelectI<int64_t>;

template <typename FloatT>
INSTRUCTION_HANDLER_FUNC s2r_SelectF(const uint8_t* code, uint32_t* sp,
                                     WasmInterpreterRuntime* wasm_runtime,
                                     int64_t r0, double fp0) {
  int32_t cond = pop<int32_t>(sp, code, wasm_runtime);
  FloatT val2 = pop<FloatT>(sp, code, wasm_runtime);
  FloatT val1 = pop<FloatT>(sp, code, wasm_runtime);

  fp0 = cond ? val1 : val2;

  NextOp();
}
static auto s2r_F32Select = s2r_SelectF<float>;
static auto s2r_F64Select = s2r_SelectF<double>;

template <typename T>
INSTRUCTION_HANDLER_FUNC s2s_Select(const uint8_t* code, uint32_t* sp,
                                    WasmInterpreterRuntime* wasm_runtime,
                                    int64_t r0, double fp0) {
  int32_t cond = pop<int32_t>(sp, code, wasm_runtime);
  T val2 = pop<T>(sp, code, wasm_runtime);
  T val1 = pop<T>(sp, code, wasm_runtime);

  push<T>(sp, code, wasm_runtime, cond ? val1 : val2);

  NextOp();
}
static auto s2s_I32Select = s2s_Select<int32_t>;
static auto s2s_I64Select = s2s_Select<int64_t>;
static auto s2s_F32Select = s2s_Select<float>;
static auto s2s_F64Select = s2s_Select<double>;
static auto s2s_S128Select = s2s_Select<Simd128>;

INSTRUCTION_HANDLER_FUNC s2s_RefSelect(const uint8_t* code, uint32_t* sp,
                                       WasmInterpreterRuntime* wasm_runtime,
                                       int64_t r0, double fp0) {
  int32_t cond = pop<int32_t>(sp, code, wasm_runtime);
  WasmRef val2 = pop<WasmRef>(sp, code, wasm_runtime);
  WasmRef val1 = pop<WasmRef>(sp, code, wasm_runtime);
  push<WasmRef>(sp, code, wasm_runtime, cond ? val1 : val2);

  NextOp();
}

////////////////////////////////////////////////////////////////////////////////
// Binary arithmetic operators

#define FOREACH_ARITHMETIC_BINOP(V) \
  V(I32Add, uint32_t, r0, +, I32)   \
  V(I32Sub, uint32_t, r0, -, I32)   \
  V(I32Mul, uint32_t, r0, *, I32)   \
  V(I32And, uint32_t, r0, &, I32)   \
  V(I32Ior, uint32_t, r0, |, I32)   \
  V(I32Xor, uint32_t, r0, ^, I32)   \
  V(I64Add, uint64_t, r0, +, I64)   \
  V(I64Sub, uint64_t, r0, -, I64)   \
  V(I64Mul, uint64_t, r0, *, I64)   \
  V(I64And, uint64_t, r0, &, I64)   \
  V(I64Ior, uint64_t, r0, |, I64)   \
  V(I64Xor, uint64_t, r0, ^, I64)   \
  V(F32Add, float, fp0, +, F32)     \
  V(F32Sub, float, fp0, -, F32)     \
  V(F32Mul, float, fp0, *, F32)     \
  V(F32Div, float, fp0, /, F32)     \
  V(F64Add, double, fp0, +, F64)    \
  V(F64Sub, double, fp0, -, F64)    \
  V(F64Mul, double, fp0, *, F64)    \
  V(F64Div, double, fp0, /, F64)

#define DEFINE_BINOP(name, ctype, reg, op, type)                            \
  INSTRUCTION_HANDLER_FUNC r2r_##name(const uint8_t* code, uint32_t* sp,    \
                                      WasmInterpreterRuntime* wasm_runtime, \
                                      int64_t r0, double fp0) {             \
    ctype rval = static_cast<ctype>(reg);                                   \
    ctype lval = pop<ctype>(sp, code, wasm_runtime);                        \
    reg = static_cast<ctype>(lval op rval);                                 \
    NextOp();                                                               \
  }                                                                         \
                                                                            \
  INSTRUCTION_HANDLER_FUNC r2s_##name(const uint8_t* code, uint32_t* sp,    \
                                      WasmInterpreterRuntime* wasm_runtime, \
                                      int64_t r0, double fp0) {             \
    ctype rval = static_cast<ctype>(reg);                                   \
    ctype lval = pop<ctype>(sp, code, wasm_runtime);                        \
    push<ctype>(sp, code, wasm_runtime, lval op rval);                      \
    NextOp();                                                               \
  }                                                                         \
                                                                            \
  INSTRUCTION_HANDLER_FUNC s2r_##name(const uint8_t* code, uint32_t* sp,    \
                                      WasmInterpreterRuntime* wasm_runtime, \
                                      int64_t r0, double fp0) {             \
    ctype rval = pop<ctype>(sp, code, wasm_runtime);                        \
    ctype lval = pop<ctype>(sp, code, wasm_runtime);                        \
    reg = static_cast<ctype>(lval op rval);                                 \
    NextOp();                                                               \
  }                                                                         \
                                                                            \
  INSTRUCTION_HANDLER_FUNC s2s_##name(const uint8_t* code, uint32_t* sp,    \
                                      WasmInterpreterRuntime* wasm_runtime, \
                                      int64_t r0, double fp0) {             \
    ctype rval = pop<ctype>(sp, code, wasm_runtime);                        \
    ctype lval = pop<ctype>(sp, code, wasm_runtime);                        \
    push<ctype>(sp, code, wasm_runtime, lval op rval);                      \
    NextOp();                                                               \
  }
FOREACH_ARITHMETIC_BINOP(DEFINE_BINOP)
#undef DEFINE_BINOP

////////////////////////////////////////////////////////////////////////////////
// Binary arithmetic operators that can trap

#define FOREACH_SIGNED_DIV_BINOP(V) \
  V(I32DivS, int32_t, r0, /, I32)   \
  V(I64DivS, int64_t, r0, /, I64)

#define FOREACH_UNSIGNED_DIV_BINOP(V) \
  V(I32DivU, uint32_t, r0, /, I32)    \
  V(I64DivU, uint64_t, r0, /, I64)

#define FOREACH_REM_BINOP(V)                 \
  V(I32RemS, int32_t, r0, ExecuteRemS, I32)  \
  V(I64RemS, int64_t, r0, ExecuteRemS, I64)  \
  V(I32RemU, uint32_t, r0, ExecuteRemU, I32) \
  V(I64RemU, uint64_t, r0, ExecuteRemU, I64)

#define FOREACH_TRAPPING_BINOP(V) \
  FOREACH_SIGNED_DIV_BINOP(V)     \
  FOREACH_UNSIGNED_DIV_BINOP(V)   \
  FOREACH_REM_BINOP(V)

#define DEFINE_BINOP(name, ctype, reg, op, type)                            \
  INSTRUCTION_HANDLER_FUNC r2r_##name(const uint8_t* code, uint32_t* sp,    \
                                      WasmInterpreterRuntime* wasm_runtime, \
                                      int64_t r0, double fp0) {             \
    ctype rval = static_cast<ctype>(reg);                                   \
    ctype lval = pop<ctype>(sp, code, wasm_runtime);                        \
    if (rval == 0) {                                                        \
      TRAP(TrapReason::kTrapDivByZero)                                      \
    } else if (rval == -1 && lval == std::numeric_limits<ctype>::min()) {   \
      TRAP(TrapReason::kTrapDivUnrepresentable)                             \
    } else {                                                                \
      reg = static_cast<ctype>(lval op rval);                               \
    }                                                                       \
    NextOp();                                                               \
  }                                                                         \
                                                                            \
  INSTRUCTION_HANDLER_FUNC r2s_##name(const uint8_t* code, uint32_t* sp,    \
                                      WasmInterpreterRuntime* wasm_runtime, \
                                      int64_t r0, double fp0) {             \
    ctype rval = static_cast<ctype>(reg);                                   \
    ctype lval = pop<ctype>(sp, code, wasm_runtime);                        \
    if (rval == 0) {                                                        \
      TRAP(TrapReason::kTrapDivByZero)                                      \
    } else if (rval == -1 && lval == std::numeric_limits<ctype>::min()) {   \
      TRAP(TrapReason::kTrapDivUnrepresentable)                             \
    } else {                                                                \
      push<ctype>(sp, code, wasm_runtime, lval op rval);                    \
    }                                                                       \
    NextOp();                                                               \
  }                                                                         \
                                                                            \
  INSTRUCTION_HANDLER_FUNC s2r_##name(const uint8_t* code, uint32_t* sp,    \
                                      WasmInterpreterRuntime* wasm_runtime, \
                                      int64_t r0, double fp0) {             \
    ctype rval = pop<ctype>(sp, code, wasm_runtime);                        \
    ctype lval = pop<ctype>(sp, code, wasm_runtime);                        \
    if (rval == 0) {                                                        \
      TRAP(TrapReason::kTrapDivByZero)                                      \
    } else if (rval == -1 && lval == std::numeric_limits<ctype>::min()) {   \
      TRAP(TrapReason::kTrapDivUnrepresentable)                             \
    } else {                                                                \
      reg = static_cast<ctype>(lval op rval);                               \
    }                                                                       \
    NextOp();                                                               \
  }                                                                         \
                                                                            \
  INSTRUCTION_HANDLER_FUNC s2s_##name(const uint8_t* code, uint32_t* sp,    \
                                      WasmInterpreterRuntime* wasm_runtime, \
                                      int64_t r0, double fp0) {             \
    ctype rval = pop<ctype>(sp, code, wasm_runtime);                        \
    ctype lval = pop<ctype>(sp, code, wasm_runtime);                        \
    if (rval == 0) {                                                        \
      TRAP(TrapReason::kTrapDivByZero)                                      \
    } else if (rval == -1 && lval == std::numeric_limits<ctype>::min()) {   \
      TRAP(TrapReason::kTrapDivUnrepresentable)                             \
    } else {                                                                \
      push<ctype>(sp, code, wasm_runtime, lval op rval);                    \
    }                                                                       \
    NextOp();                                                               \
  }
FOREACH_SIGNED_DIV_BINOP(DEFI
```