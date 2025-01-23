Response: Let's break down the thought process for analyzing the `tick-sample.cc` file.

1. **Understand the Goal:** The request asks for a summary of the file's functionality and how it relates to JavaScript, along with a JavaScript example.

2. **Initial Scan and Keywords:** I'll quickly read through the code, looking for recurring terms and important function names. I see "TickSample," "profiler," "stack," "frames," "registers," "Isolate," "JavaScript," "VMState," "external callback," "sampling interval." These words strongly suggest this file is involved in taking snapshots of the V8 engine's state during execution, likely for performance profiling.

3. **Core Class: `TickSample`:** The central entity is the `TickSample` class. I'll examine its members and methods.

    * **Members:**  `pc`, `stack`, `frames_count`, `state`, `has_external_callback`, `external_callback_entry`, `tos`, `sampling_interval_`, `timestamp`. These appear to store information about a specific point in time. `pc` (program counter), `stack`, and `frames_count` are clearly related to the execution stack. `state` probably indicates the V8 engine's current activity. `external_callback` hints at interactions with native code.

    * **`Init()` Method:** This looks like the constructor or initialization method. It takes `RegisterState` and other parameters. It calls `GetStackSample`. This suggests `Init` is responsible for gathering the snapshot information. The `update_stats` flag implies this process might contribute to overall profiler statistics.

    * **`GetStackSample()` Method:** This is the crucial part. It takes `RegisterState`, collects stack frames, and populates a `SampleInfo` structure. The logic within this function is complex and deals with different execution states (JS, C++, external callbacks), stack frame types, and handling potential issues like incomplete frame setup. The `USE_SIMULATOR` conditional compilation indicates support for running in a simulated environment.

    * **`print()` Method:** This is a utility for debugging, printing the contents of a `TickSample` object.

4. **Key Functionality - Gathering the Snapshot:** The core purpose is clearly to capture a snapshot of the V8 engine's execution state at a particular moment. This involves:

    * **Register State:** Obtaining the values of CPU registers (`pc`, `sp`, `fp`, `lr`).
    * **Stack Trace:** Walking the call stack to get a sequence of function addresses. This is done by `StackFrameIteratorForProfiler`.
    * **VM State:** Identifying whether the engine is executing JavaScript, in garbage collection, or in external (native) code.
    * **External Callbacks:** Detecting and recording information about calls from JavaScript to native code.

5. **Relationship to JavaScript:** The code directly deals with concepts fundamental to JavaScript execution within V8:

    * **Call Stack:**  `GetStackSample` directly works with the JavaScript call stack.
    * **Bytecode:** The code handles interpreted JavaScript frames and retrieves bytecode array pointers.
    * **Native Code Interaction:** It identifies and records information about external callbacks.
    * **Garbage Collection:** It explicitly avoids collecting stack traces during GC.

6. **JavaScript Example (Mental Simulation):** How would this manifest in JavaScript? Imagine a function calling a native function:

   ```javascript
   function jsFunction() {
     nativeFunction(); // Calls out to C++
   }

   function main() {
     jsFunction();
   }

   main();
   ```

   When the profiler takes a "tick" while `nativeFunction` is executing:

   * `TickSample::Init` would be called.
   * `GetStackSample` would examine the registers and stack.
   * `state` would likely be `EXTERNAL`.
   * `has_external_callback` would be true.
   * `external_callback_entry` would point to the address of `nativeFunction` (or a wrapper).
   * The `stack` might contain addresses related to `jsFunction` and `main`.

7. **Constructing the JavaScript Example (More Concrete):**  To make the example clearer, I'd want to show how to use V8's profiling API to *trigger* this process. The `v8-profiler.h` include gives a clue. I'd remember or look up how to start and stop the profiler and how it samples execution. The provided example in the prompt's answer is a good illustration of this.

8. **Refining the Explanation:** I'd then organize the information into a clear summary, highlighting the key methods and their roles. I'd emphasize the connection to JavaScript execution and provide a simple, illustrative JavaScript example. I would also mention the purpose of profiling (performance analysis).

9. **Self-Correction/Refinement:**  Initially, I might focus too much on the low-level details of stack walking. I'd then step back and ensure the explanation is understandable at a higher level, focusing on the *what* and *why* rather than just the *how*. I'd also make sure the JavaScript example clearly demonstrates the connection to the C++ code. For instance, initially, I might forget to explicitly mention the sampling interval's role. Reviewing the code helps to catch these details.
这个C++源代码文件 `tick-sample.cc` 的主要功能是**在 V8 引擎执行过程中，定期或在特定事件发生时，采集当前执行状态的快照，用于性能分析（Profiling）**。 这个快照被称为一个 "tick sample"，它包含了以下关键信息：

**主要功能归纳:**

1. **捕获执行状态:**  `TickSample::Init` 方法是核心，它负责获取当前 V8 引擎的执行状态。这包括：
    * **程序计数器 (PC):** 当前正在执行的指令地址。
    * **调用栈 (Stack):**  当前函数调用链的信息，一系列返回地址。
    * **虚拟机状态 (VM State):**  V8 引擎当前所处的状态（例如：执行 JavaScript，垃圾回收，执行外部 C++ 代码等）。
    * **是否执行外部回调 (External Callback):**  指示当前是否正在执行 JavaScript 调用到 C++ 的回调函数。
    * **外部回调入口地址:** 如果正在执行外部回调，则记录回调函数的地址。
    * **时间戳:** 采样发生的时间。
    * **采样间隔:**  这次采样与上次采样之间的时间间隔。
    * **上下文信息 (Context):** 当前的 JavaScript 执行上下文。
    * **嵌入器状态 (Embedder State):**  如果 V8 引擎被嵌入到其他应用程序中，则记录嵌入器的状态。

2. **获取调用栈:**  `TickSample::GetStackSample` 方法负责遍历和提取当前的函数调用栈信息。它会：
    * **使用 `StackFrameIteratorForProfiler`:**  这是一个用于遍历 V8 引擎调用栈的迭代器。
    * **处理不同类型的栈帧:**  包括 JavaScript 函数帧、内置函数帧、C++ 函数帧等。
    * **处理解释执行的 JavaScript:**  对于解释执行的 JavaScript 代码，它会尝试获取字节码数组的指针和偏移量。
    * **考虑模拟器环境:** 如果 V8 在模拟器中运行，它会尝试从模拟器中获取寄存器值。

3. **辅助功能:**
    * **判断是否处于无帧区域 (`IsNoFrameRegion`):**  检查给定的地址是否位于函数设置或清理栈帧的代码区域，如果是，则可能无法安全地遍历栈。
    * **与模拟器交互 (`SimulatorHelper`):** 在模拟器环境中，帮助获取寄存器状态。
    * **打印调试信息 (`print`):**  用于打印 `TickSample` 对象的内容，方便调试。

**与 JavaScript 的关系及示例:**

`tick-sample.cc` 的功能直接服务于 JavaScript 的性能分析。当开发者使用 V8 的 Profiler API 来收集 JavaScript 代码的性能数据时，`tick-sample.cc` 中的代码就会被调用。

**JavaScript 示例:**

假设有以下 JavaScript 代码：

```javascript
function a() {
  b();
}

function b() {
  c();
}

function c() {
  // 一些耗时的操作
  for (let i = 0; i < 1000000; i++) {
    // ...
  }
}

a();
```

当 V8 的 Profiler 正在运行时，它会定期触发采样。当采样发生时，`tick-sample.cc` 中的代码会被执行，可能会捕获到以下信息：

* **如果采样发生在 `c()` 函数的循环中：**
    * `pc` 会指向 `c()` 函数内部循环中的某个指令地址。
    * `stack` 数组可能会包含指向 `c`、`b`、`a` 函数的返回地址或其他相关信息。
    * `state` 可能会是 `JS_EXECUTION`，表示正在执行 JavaScript 代码。

* **如果 JavaScript 调用了 C++ 的外部回调函数：**

```javascript
// C++ 代码 (简化示例)
v8::Local<v8::String> MyNativeFunction(const v8::FunctionCallbackInfo<v8::Value>& args) {
  // 一些 C++ 操作
  return v8::String::NewFromUtf8(args.GetIsolate(), "Hello from C++").ToLocalChecked();
}

// JavaScript 代码
function jsFunction() {
  nativeFunction(); // 调用 C++ 函数
}

jsFunction();
```

当采样发生在 `MyNativeFunction` 执行期间：

* `pc` 会指向 `MyNativeFunction` 内部的某个指令地址。
* `state` 可能会是 `EXTERNAL`，表示正在执行外部 C++ 代码。
* `has_external_callback` 会是 `true`。
* `external_callback_entry` 会指向 `MyNativeFunction` 的地址。
* `stack` 数组可能会包含指向 `jsFunction` 的返回地址。

**如何通过 JavaScript 触发 Profiling:**

在 Node.js 环境中，可以使用内置的 `v8` 模块来启动和停止 Profiler：

```javascript
const v8 = require('v8');
const fs = require('fs');

function a() {
  b();
}

function b() {
  c();
}

function c() {
  for (let i = 0; i < 1000000; i++) {}
}

v8.startProfiling('MyProfile'); // 启动 CPU Profiler

a();

const profile = v8.stopProfiling('MyProfile'); // 停止 Profiler

// 将 Profile 数据写入文件
fs.writeFileSync('profile.cpuprofile', JSON.stringify(profile));
profile.delete();
```

当这段代码运行时，`v8.startProfiling` 会启动 CPU Profiler，V8 引擎会定期调用 `tick-sample.cc` 中的代码来收集执行状态快照。收集到的数据最终会包含在生成的 `profile.cpuprofile` 文件中，可以使用 Chrome DevTools 或其他性能分析工具来查看和分析这些数据，从而了解 JavaScript 代码的性能瓶颈。

**总结:**

`tick-sample.cc` 是 V8 引擎中用于性能分析的关键组件。它负责在执行过程中捕捉程序的状态，特别是调用栈信息，这对于理解代码的执行路径和识别性能瓶颈至关重要。它的工作直接支持了 JavaScript 开发者的性能分析工作。

### 提示词
```
这是目录为v8/src/profiler/tick-sample.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
// Copyright 2013 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/profiler/tick-sample.h"

#include <cinttypes>

#include "include/v8-profiler.h"
#include "src/base/sanitizer/asan.h"
#include "src/base/sanitizer/msan.h"
#include "src/execution/embedder-state.h"
#include "src/execution/frames-inl.h"
#include "src/execution/simulator.h"
#include "src/execution/vm-state-inl.h"
#include "src/heap/heap-inl.h"  // For Heap::code_range.
#include "src/logging/counters.h"
#include "src/profiler/profiler-stats.h"

namespace v8 {
namespace internal {
namespace {

bool IsSamePage(i::Address ptr1, i::Address ptr2) {
  const uint32_t kPageSize = 4096;
  i::Address mask = ~static_cast<i::Address>(kPageSize - 1);
  return (ptr1 & mask) == (ptr2 & mask);
}

// Check if the code at specified address could potentially be a
// frame setup code.
bool IsNoFrameRegion(i::Address address) {
  struct Pattern {
    int bytes_count;
    uint8_t bytes[8];
    int offsets[4];
  };
  static Pattern patterns[] = {
#if V8_HOST_ARCH_IA32
    // push %ebp
    // mov %esp,%ebp
    {3, {0x55, 0x89, 0xE5}, {0, 1, -1}},
    // pop %ebp
    // ret N
    {2, {0x5D, 0xC2}, {0, 1, -1}},
    // pop %ebp
    // ret
    {2, {0x5D, 0xC3}, {0, 1, -1}},
#elif V8_HOST_ARCH_X64
    // pushq %rbp
    // movq %rsp,%rbp
    {4, {0x55, 0x48, 0x89, 0xE5}, {0, 1, -1}},
    // popq %rbp
    // ret N
    {2, {0x5D, 0xC2}, {0, 1, -1}},
    // popq %rbp
    // ret
    {2, {0x5D, 0xC3}, {0, 1, -1}},
#endif
    {0, {}, {}}
  };
  uint8_t* pc = reinterpret_cast<uint8_t*>(address);
  for (Pattern* pattern = patterns; pattern->bytes_count; ++pattern) {
    for (int* offset_ptr = pattern->offsets; *offset_ptr != -1; ++offset_ptr) {
      int offset = *offset_ptr;
      if (!offset || IsSamePage(address, address - offset)) {
        MSAN_MEMORY_IS_INITIALIZED(pc - offset, pattern->bytes_count);
        if (!memcmp(pc - offset, pattern->bytes, pattern->bytes_count))
          return true;
      } else {
        // It is not safe to examine bytes on another page as it might not be
        // allocated thus causing a SEGFAULT.
        // Check the pattern part that's on the same page and
        // pessimistically assume it could be the entire pattern match.
        MSAN_MEMORY_IS_INITIALIZED(pc, pattern->bytes_count - offset);
        if (!memcmp(pc, pattern->bytes + offset, pattern->bytes_count - offset))
          return true;
      }
    }
  }
  return false;
}

#if defined(USE_SIMULATOR)
class SimulatorHelper {
 public:
  // Returns true if register values were successfully retrieved
  // from the simulator, otherwise returns false.
  static bool FillRegisters(Isolate* isolate, v8::RegisterState* state);
};

bool SimulatorHelper::FillRegisters(Isolate* isolate,
                                    v8::RegisterState* state) {
  Simulator* simulator = isolate->thread_local_top()->simulator_;
  // Check if there is active simulator.
  if (simulator == nullptr) return false;
#if V8_TARGET_ARCH_ARM
  if (!simulator->has_bad_pc()) {
    state->pc = reinterpret_cast<void*>(simulator->get_pc());
  }
  state->sp = reinterpret_cast<void*>(simulator->get_register(Simulator::sp));
  state->fp = reinterpret_cast<void*>(simulator->get_register(Simulator::r11));
  state->lr = reinterpret_cast<void*>(simulator->get_register(Simulator::lr));
#elif V8_TARGET_ARCH_ARM64
  state->pc = reinterpret_cast<void*>(simulator->pc());
  state->sp = reinterpret_cast<void*>(simulator->sp());
  state->fp = reinterpret_cast<void*>(simulator->fp());
  state->lr = reinterpret_cast<void*>(simulator->lr());
#elif V8_TARGET_ARCH_MIPS64 || V8_TARGET_ARCH_LOONG64
  if (!simulator->has_bad_pc()) {
    state->pc = reinterpret_cast<void*>(simulator->get_pc());
  }
  state->sp = reinterpret_cast<void*>(simulator->get_register(Simulator::sp));
  state->fp = reinterpret_cast<void*>(simulator->get_register(Simulator::fp));
#elif V8_TARGET_ARCH_PPC64
  if (!simulator->has_bad_pc()) {
    state->pc = reinterpret_cast<void*>(simulator->get_pc());
  }
  state->sp = reinterpret_cast<void*>(simulator->get_register(Simulator::sp));
  state->fp = reinterpret_cast<void*>(simulator->get_register(Simulator::fp));
  state->lr = reinterpret_cast<void*>(simulator->get_lr());
#elif V8_TARGET_ARCH_S390X
  if (!simulator->has_bad_pc()) {
    state->pc = reinterpret_cast<void*>(simulator->get_pc());
  }
  state->sp = reinterpret_cast<void*>(simulator->get_register(Simulator::sp));
  state->fp = reinterpret_cast<void*>(simulator->get_register(Simulator::fp));
  state->lr = reinterpret_cast<void*>(simulator->get_register(Simulator::ra));
#elif V8_TARGET_ARCH_RISCV64
  if (!simulator->has_bad_pc()) {
    state->pc = reinterpret_cast<void*>(simulator->get_pc());
  }
  state->sp = reinterpret_cast<void*>(simulator->get_register(Simulator::sp));
  state->fp = reinterpret_cast<void*>(simulator->get_register(Simulator::fp));
  state->lr = reinterpret_cast<void*>(simulator->get_register(Simulator::ra));
#elif V8_TARGET_ARCH_RISCV32
  if (!simulator->has_bad_pc()) {
    state->pc = reinterpret_cast<void*>(simulator->get_pc());
  }
  state->sp = reinterpret_cast<void*>(simulator->get_register(Simulator::sp));
  state->fp = reinterpret_cast<void*>(simulator->get_register(Simulator::fp));
  state->lr = reinterpret_cast<void*>(simulator->get_register(Simulator::ra));
#endif
  if (state->sp == 0 || state->fp == 0) {
    // It possible that the simulator is interrupted while it is updating
    // the sp or fp register. ARM64 simulator does this in two steps:
    // first setting it to zero and then setting it to the new value.
    // Bailout if sp/fp doesn't contain the new value.
    //
    // FIXME: The above doesn't really solve the issue.
    // If a 64-bit target is executed on a 32-bit host even the final
    // write is non-atomic, so it might obtain a half of the result.
    // Moreover as long as the register set code uses memcpy (as of now),
    // it is not guaranteed to be atomic even when both host and target
    // are of same bitness.
    return false;
  }
  return true;
}
#endif  // USE_SIMULATOR

}  // namespace

DISABLE_ASAN void TickSample::Init(Isolate* v8_isolate,
                                   const RegisterState& reg_state,
                                   RecordCEntryFrame record_c_entry_frame,
                                   bool update_stats,
                                   bool use_simulator_reg_state,
                                   base::TimeDelta sampling_interval) {
  update_stats_ = update_stats;
  SampleInfo info;
  RegisterState regs = reg_state;
  if (!GetStackSample(v8_isolate, &regs, record_c_entry_frame, stack,
                      kMaxFramesCount, &info, &state,
                      use_simulator_reg_state)) {
    // It is executing JS but failed to collect a stack trace.
    // Mark the sample as spoiled.
    pc = nullptr;
    return;
  }

  if (state != StateTag::EXTERNAL) {
    state = info.vm_state;
  }
  pc = regs.pc;
  frames_count = static_cast<unsigned>(info.frames_count);
  has_external_callback = info.external_callback_entry != nullptr;
  context = info.context;
  embedder_context = info.embedder_context;
  embedder_state = info.embedder_state;
  if (has_external_callback) {
    external_callback_entry = info.external_callback_entry;
  } else if (frames_count) {
    // sp register may point at an arbitrary place in memory, make
    // sure sanitizers don't complain about it.
    ASAN_UNPOISON_MEMORY_REGION(regs.sp, sizeof(void*));
    MSAN_MEMORY_IS_INITIALIZED(regs.sp, sizeof(void*));
    // Sample potential return address value for frameless invocation of
    // stubs (we'll figure out later, if this value makes sense).

    // TODO(petermarshall): This read causes guard page violations on Windows.
    // Either fix this mechanism for frameless stubs or remove it.
    // tos =
    // i::ReadUnalignedValue<void*>(reinterpret_cast<i::Address>(regs.sp));
    tos = nullptr;
  } else {
    tos = nullptr;
  }
  sampling_interval_ = sampling_interval;
  timestamp = base::TimeTicks::Now();
}

// IMPORTANT: 'GetStackSample' is sensitive to stack overflows. For this reason
// we try not to use any function/method marked as V8_EXPORT_PRIVATE with their
// only use-site in 'GetStackSample': The resulting linker stub needs quite
// a bit of stack space and has caused stack overflow crashes in the past.
bool TickSample::GetStackSample(Isolate* v8_isolate, RegisterState* regs,
                                RecordCEntryFrame record_c_entry_frame,
                                void** frames, size_t frames_limit,
                                v8::SampleInfo* sample_info,
                                StateTag* out_state,
                                bool use_simulator_reg_state) {
  i::Isolate* isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  sample_info->frames_count = 0;
  sample_info->vm_state = isolate->current_vm_state();
  sample_info->external_callback_entry = nullptr;
  sample_info->embedder_state = EmbedderStateTag::EMPTY;
  sample_info->embedder_context = nullptr;
  sample_info->context = nullptr;

  if (sample_info->vm_state == GC || v8_isolate->heap()->IsInGC()) {
    // GC can happen any time, not directly caused by its caller. Don't collect
    // stacks for it. We check for both GC VMState and IsInGC, since we can
    // observe LOGGING VM states during GC.
    // TODO(leszeks): We could still consider GC stacks (as long as this isn't a
    // moving GC), e.g. to surface if one particular function is triggering all
    // the GCs. However, this is a user-visible change, and we would need to
    // adjust the symbolizer and devtools to expose this information.
    return true;
  }

  EmbedderState* embedder_state = isolate->current_embedder_state();
  if (embedder_state != nullptr) {
    sample_info->embedder_context =
        reinterpret_cast<void*>(embedder_state->native_context_address());
    sample_info->embedder_state = embedder_state->GetState();
  }

  Tagged<Context> top_context = isolate->context();
  if (top_context.ptr() != i::Context::kNoContext &&
      top_context.ptr() != i::Context::kInvalidContext) {
    Tagged<NativeContext> top_native_context = top_context->native_context();
    sample_info->context = reinterpret_cast<void*>(top_native_context.ptr());
  }

  i::Address js_entry_sp = isolate->js_entry_sp();
  if (js_entry_sp == 0) return true;  // Not executing JS now.

#if defined(USE_SIMULATOR)
  if (use_simulator_reg_state) {
    if (!i::SimulatorHelper::FillRegisters(isolate, regs)) {
      i::ProfilerStats::Instance()->AddReason(
          i::ProfilerStats::Reason::kSimulatorFillRegistersFailed);
      return false;
    }
  }
#else
  USE(use_simulator_reg_state);
#endif
  DCHECK(regs->sp);

  // Check whether we interrupted setup/teardown of a stack frame in JS code.
  // Avoid this check for C++ code, as that would trigger false positives.
  // TODO(petermarshall): Code range is always null on ia32 so this check for
  // IsNoFrameRegion will never actually run there.
  if (regs->pc &&
      isolate->heap()->code_region().contains(
          reinterpret_cast<i::Address>(regs->pc)) &&
      IsNoFrameRegion(reinterpret_cast<i::Address>(regs->pc))) {
    // The frame is not setup, so it'd be hard to iterate the stack. Bailout.
    i::ProfilerStats::Instance()->AddReason(
        i::ProfilerStats::Reason::kNoFrameRegion);
    return false;
  }

  i::ExternalCallbackScope* scope = isolate->external_callback_scope();
  i::Address handler = i::Isolate::handler(isolate->thread_local_top());
  // If there is a handler on top of the external callback scope then
  // we have already entered JavaScript again and the external callback
  // is not the top function.
  if (scope && scope->JSStackComparableAddress() < handler) {
    i::Address* external_callback_entry_ptr =
        scope->callback_entrypoint_address();
    sample_info->external_callback_entry =
        external_callback_entry_ptr == nullptr
            ? nullptr
            : reinterpret_cast<void*>(*external_callback_entry_ptr);
  }
  // 'Fast API calls' are similar to fast C calls (see frames.cc) in that
  // they don't build an exit frame when entering C from JS. They have the
  // added speciality of having separate "fast" and "default" callbacks, the
  // latter being the regular API callback called before the JS function is
  // optimized. When TurboFan optimizes the JS caller, the fast callback
  // gets executed instead of the default one, therefore we need to store
  // its address in the sample.
  IsolateData* isolate_data = isolate->isolate_data();
  Address fast_c_fp = isolate_data->fast_c_call_caller_fp();
  if (fast_c_fp != kNullAddress &&
      isolate_data->fast_api_call_target() != kNullAddress) {
    sample_info->external_callback_entry =
        reinterpret_cast<void*>(isolate_data->fast_api_call_target());
    if (out_state) {
      *out_state = StateTag::EXTERNAL;
    }
  }

  i::StackFrameIteratorForProfiler it(
      isolate, reinterpret_cast<i::Address>(regs->pc),
      reinterpret_cast<i::Address>(regs->fp),
      reinterpret_cast<i::Address>(regs->sp),
      reinterpret_cast<i::Address>(regs->lr), js_entry_sp);

  if (it.done()) return true;

  size_t i = 0;
  if (record_c_entry_frame == kIncludeCEntryFrame &&
      (it.top_frame_type() == internal::StackFrame::EXIT ||
       it.top_frame_type() == internal::StackFrame::BUILTIN_EXIT)) {
    // While BUILTIN_EXIT definitely represents a call to CEntry the EXIT frame
    // might represent either a call to CEntry or an optimized call to
    // Api callback. In the latter case the ExternalCallbackScope points to
    // the same function, so skip adding a frame in that case in order to avoid
    // double-reporting.
    void* c_function = reinterpret_cast<void*>(isolate->c_function());
    if (sample_info->external_callback_entry != c_function) {
      frames[i] = c_function;
      i++;
    }
  }
#ifdef V8_RUNTIME_CALL_STATS
  i::RuntimeCallTimer* timer =
      isolate->counters()->runtime_call_stats()->current_timer();
#endif  // V8_RUNTIME_CALL_STATS
  for (; !it.done() && i < frames_limit; it.Advance()) {
#ifdef V8_RUNTIME_CALL_STATS
    while (timer && reinterpret_cast<i::Address>(timer) < it.frame()->fp() &&
           i < frames_limit) {
      frames[i++] = reinterpret_cast<void*>(timer->counter());
      timer = timer->parent();
    }
    if (i == frames_limit) break;
#endif  // V8_RUNTIME_CALL_STATS

    if (it.frame()->is_interpreted()) {
      // For interpreted frames use the bytecode array pointer as the pc.
      i::InterpretedFrame* frame =
          static_cast<i::InterpretedFrame*>(it.frame());
      // Since the sampler can interrupt execution at any point the
      // bytecode_array might be garbage, so don't actually dereference it. We
      // avoid the frame->GetXXX functions since they call Cast<BytecodeArray>,
      // which has a heap access in its DCHECK.
      i::Address bytecode_array = base::Memory<i::Address>(
          frame->fp() + i::InterpreterFrameConstants::kBytecodeArrayFromFp);
      i::Address bytecode_offset = base::Memory<i::Address>(
          frame->fp() + i::InterpreterFrameConstants::kBytecodeOffsetFromFp);

      // If the bytecode array is a heap object and the bytecode offset is a
      // Smi, use those, otherwise fall back to using the frame's pc.
      if (HAS_STRONG_HEAP_OBJECT_TAG(bytecode_array) &&
          HAS_SMI_TAG(bytecode_offset)) {
        frames[i++] = reinterpret_cast<void*>(
            bytecode_array + i::Internals::SmiValue(bytecode_offset));
        continue;
      }
    }
    // For arm64, the PC for the frame sometimes doesn't come from the stack,
    // but from the link register instead. For this reason, we skip
    // authenticating it.
    frames[i++] = reinterpret_cast<void*>(it.frame()->unauthenticated_pc());
  }
  sample_info->frames_count = i;
  return true;
}

void TickSample::print() const {
  PrintF("TickSample: at %p\n", this);
  PrintF(" - state: %s\n", StateToString(state));
  PrintF(" - pc: %p\n", pc);
  PrintF(" - stack: (%u frames)\n", frames_count);
  for (unsigned i = 0; i < frames_count; i++) {
    PrintF("    %p\n", stack[i]);
  }
  PrintF(" - has_external_callback: %d\n", has_external_callback);
  PrintF(" - %s: %p\n",
         has_external_callback ? "external_callback_entry" : "tos", tos);
  PrintF(" - update_stats: %d\n", update_stats_);
  PrintF(" - sampling_interval: %" PRId64 "\n",
         sampling_interval_.InMicroseconds());
  PrintF("\n");
}

}  // namespace internal
}  // namespace v8
```