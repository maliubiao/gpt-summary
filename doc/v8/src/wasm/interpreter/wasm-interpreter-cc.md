Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/wasm/interpreter/wasm-interpreter.cc`. I need to identify the key components and their roles within the WebAssembly interpreter. I should also address the specific questions about `.tq` files, JavaScript interaction, code logic, and common programming errors, if applicable based on the provided snippet.

Here's a breakdown of the code and its functionalities:

1. **Includes and Namespaces:** The code includes various V8 headers related to Wasm, handles, snapshots, and utilities. It operates within the `v8::internal::wasm` namespace.

2. **Helper Macros:** `EMIT_INSTR_HANDLER` and `EMIT_INSTR_HANDLER_WITH_PC` suggest mechanisms for registering or identifying instruction handlers. `ReadI16` and `ReadI32` are likely helpers for reading data from the bytecode stream.

3. **`WasmInterpreter::CodeMap`:** This class manages the mapping between Wasm functions and their corresponding interpreter code. It handles:
    - Storing the start and end pointers of function code.
    - Preprocessing function bytecode to generate an internal representation (`BytecodeIterator`, `WasmBytecodeGenerator`).
    - Collecting statistics about bytecode generation time and size.

4. **`WasmInterpreterThreadMap` and `WasmInterpreterThread`:** These classes manage threads used for executing Wasm code in the interpreter.
    - `WasmInterpreterThreadMap` likely maintains a mapping of thread IDs to `WasmInterpreterThread` instances.
    - `WasmInterpreterThread` seems to represent a single interpreter thread and holds state related to execution.

5. **`FrameState`:** This class stores the state of a function call on the interpreter stack. It includes:
    - Handling caught exceptions within blocks.

6. **`WasmExecutionTimer`:** This class is responsible for tracking the execution time of Wasm code, both JIT-compiled and interpreted. It collects statistics and potentially triggers events based on execution duration.

7. **Helper Functions:**
    - `MakeWeak`: Creates a weak handle to a `WasmInstanceObject`.
    - `GetWasmReturnTypeFromSignature`: Extracts the return type from a Wasm function signature.

8. **`WasmInterpreterThread::Activation`:** Represents an activation record on the interpreter stack, storing the current frame state. It allows capturing the stack trace.

9. **`WasmInterpreterThread` Methods:**
    - `RaiseException`: Throws a JavaScript exception from within the interpreter.
    - `SetRuntimeLastWasmError` and `GetRuntimeLastWasmError`: Manage the last Wasm error encountered.
    - `StartExecutionTimer`, `StopExecutionTimer`, `TerminateExecutionTimers`: Control the execution time tracking.

10. **Conditional Compilation (`V8_DRUMBRAKE_BOUNDS_CHECKS`):** This section deals with how memory access bounds checks are handled. It appears that when `V8_DRUMBRAKE_BOUNDS_CHECKS` is not defined, the interpreter relies on operating system-level trap handling for out-of-bounds memory accesses, using built-in assembly handlers.

11. **`WasmInterpreter`:**  The main class responsible for interpreting Wasm code. It holds:
    - A weak reference to the `WasmInstanceObject`.
    - The raw bytes of the Wasm module.
    - The `CodeMap`.
    - A `WasmInterpreterRuntime` instance.
    - Methods for continuing execution.

12. **DrumBrake Specifics:** The code includes a section marked "DrumBrake," which is the name for V8's Wasm interpreter. This section includes:
    - Constants for floating-point sign bit masks.
    - Conditional profiling code (`DRUMBRAKE_ENABLE_PROFILING`).
    - Macros for executing the next instruction (`NextOp`).
    - A `Trap` function for handling Wasm traps.
    - Implementations for various Wasm instruction handlers (e.g., `GlobalGet`, `GlobalSet`, `Drop`, `LoadMem`).

Based on this analysis, I can now formulate the summary.
```cpp
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
  fp0 = base::ReadUnalignedValue<FloatT>(reinterpret_cast
### 提示词
```
这是目录为v8/src/wasm/interpreter/wasm-interpreter.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/interpreter/wasm-interpreter.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共15部分，请归纳一下它的功能
```

### 源代码
```cpp
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
INSTRU
```