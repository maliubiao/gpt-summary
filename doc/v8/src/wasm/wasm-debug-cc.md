Response:
My thinking process to answer the request about `v8/src/wasm/wasm-debug.cc` went something like this:

1. **Understand the Goal:** The request asks for a summary of the functionality of the provided C++ code, specifically focusing on its role in debugging WebAssembly. It also asks about Torque, JavaScript interaction, logic, and common errors. Finally, it emphasizes that this is part 1 of 2.

2. **Initial Scan and Keyword Recognition:** I quickly scanned the code, looking for recognizable keywords and patterns. I noticed:
    * `#include` directives, indicating dependencies (e.g., `wasm.h`, `debug.h`).
    * Namespaces like `v8::internal::wasm`.
    * Class names like `DebugSideTable`, `DebugInfoImpl`, `WasmFrame`.
    * Methods like `SetBreakpoint`, `RemoveBreakpoint`, `PrepareStep`, `GetLocalValue`.
    * Comments mentioning "debugging", "breakpoints", "stepping", "Liftoff".
    * Data structures like `std::unordered_map`, `std::vector`.
    * Use of mutexes for thread safety.

3. **Identify Core Functionality Areas:** Based on the initial scan, I started grouping the functionality into logical areas:
    * **Breakpoint Management:** The presence of `SetBreakpoint`, `RemoveBreakpoint`, and related logic clearly points to this.
    * **Stepping:** Functions like `PrepareStep`, `PrepareStepOutTo`, `ClearStepping` are key indicators.
    * **Frame Inspection:**  `GetLocalValue`, `GetStackValue`, and `GetStackDepth` are used to examine the state of a Wasm frame during debugging.
    * **Code Recompilation for Debugging:** The `RecompileLiftoffWithBreakpoints` function suggests that the code dynamically modifies the generated Wasm code to insert breakpoints.
    * **Debug Side Tables:** The `DebugSideTable` class and related logic are involved in storing information needed for debugging.
    * **Blackboxing:** `IsFrameBlackboxed` suggests support for excluding certain functions from debugging.
    * **Thread Safety:** The use of mutexes indicates a concern for multi-threaded debugging scenarios.

4. **Detailed Examination of Key Classes and Functions:** I then went back and examined the core classes and functions more closely:
    * **`DebugSideTable`:**  I analyzed its members (`entries_`, `num_locals_`) and methods (`Print`, `Entry::Print`) to understand its purpose of storing information about locals and stack values at specific code offsets.
    * **`DebugInfoImpl`:** This class appears to be the central point of contact for debugging operations. I paid attention to how it interacts with `NativeModule`, `WasmCode`, and `DebugSideTable`.
    * **`RecompileLiftoffWithBreakpoints`:** This function is crucial. I noted its role in recompiling functions with breakpoints and the caching mechanism (`cached_debugging_code_`). I recognized "Liftoff" as the baseline compiler, indicating this debugging is primarily for that tier.
    * **Breakpoint Management Functions:** I observed how breakpoints are stored per isolate and how recompilation is triggered when breakpoints change.
    * **Stepping Functions:** I saw how these functions manipulate the code by "flooding" with breakpoints and how they manage the stepping state.

5. **Address Specific Requirements:** I went back through the request and addressed each point:
    * **Functionality List:** I compiled the identified core areas into a concise list.
    * **Torque:** I correctly identified that the `.cc` extension means it's C++ and not Torque.
    * **JavaScript Relationship:** I considered how this C++ code would be used from the JavaScript debugger API. I focused on the conceptual link – JavaScript debugger commands would trigger actions in this C++ code. I provided an example of setting a breakpoint.
    * **Logic and Assumptions:** I picked a function (`FindNewPC`) with clear logic and described its assumptions (input parameters) and output.
    * **Common Errors:** I thought about common debugging mistakes users make and how this code relates. Setting breakpoints in optimized code or not understanding stepping behavior seemed relevant.
    * **Part 1 Summary:** I condensed the key functionalities into a summary.

6. **Review and Refine:**  I reviewed my answer for clarity, accuracy, and completeness. I made sure the language was easy to understand and that I addressed all aspects of the request. I emphasized that this is the first part and that further functionality might be in the next part.

Essentially, I used a combination of top-down (understanding the overall goal and architecture) and bottom-up (examining specific code elements) approaches. Keyword recognition and understanding the context of WebAssembly debugging were crucial. I iteratively built my understanding by connecting the individual pieces of code to the larger debugging process.
这是 `v8/src/wasm/wasm-debug.cc` 的第一部分源代码，它是一个 V8 引擎中用于 WebAssembly 调试功能的 C++ 代码文件。以下是根据代码内容归纳的功能列表：

**主要功能归纳:**

1. **断点管理:**
   - 允许在 WebAssembly 代码中设置和移除断点 (`SetBreakpoint`, `RemoveBreakpoint`)。
   - 跟踪每个 Isolate (V8 的隔离执行上下文) 中设置的断点 (`per_isolate_data_`)。
   - 当断点改变时，会重新编译 WebAssembly 函数以包含断点 (`RecompileLiftoffWithBreakpoints`)。
   - 提供 `FindAllBreakpoints` 用于查找特定函数的所有断点。

2. **单步执行:**
   - 支持单步执行 WebAssembly 代码 (`PrepareStep`, `PrepareStepOutTo`, `ClearStepping`)。
   - 使用“洪水填充”断点的方式来实现单步执行 (`FloodWithBreakpoints`)，即在当前指令后添加临时断点。
   - 跟踪当前正在单步执行的帧 (`stepping_frame`)。
   - 可以判断当前是否正在单步执行 (`IsStepping`)。

3. **帧信息检查:**
   - 允许获取 WebAssembly 帧的局部变量值 (`GetLocalValue`) 和堆栈值 (`GetStackValue`)。
   - 可以获取局部变量的数量 (`GetNumLocals`) 和堆栈深度 (`GetStackDepth`)。
   - 通过地址查找对应的 WebAssembly 函数 (`GetFunctionAtAddress`)。

4. **调试边表 (Debug Side Table):**
   - 使用 `DebugSideTable` 来存储在调试过程中需要的额外信息，例如局部变量在寄存器或堆栈中的位置。
   - `GenerateLiftoffDebugSideTable` 函数用于生成 Liftoff 编译器的调试边表。
   - 缓存调试边表 (`debug_side_tables_`) 以避免重复生成。

5. **代码重编译:**
   - 当需要设置或移除断点时，会使用 Liftoff 编译器重新编译 WebAssembly 函数 (`RecompileLiftoffWithBreakpoints`)。
   - 缓存用于调试的代码对象 (`cached_debugging_code_`)，以优化性能。

6. **黑盒功能 (Blackboxing):**
   - 可以将某些 WebAssembly 函数标记为黑盒，在调试时跳过这些函数 (`IsFrameBlackboxed`)。

7. **返回地址更新:**
   - 当代码因为断点设置或移除而重新编译时，需要更新调用栈中相关帧的返回地址 (`UpdateReturnAddresses`, `UpdateReturnAddress`)，以确保执行能够继续在新代码中进行。

8. **Isolate 管理:**
   - 跟踪每个 Isolate 的断点信息。
   - 提供 `RemoveIsolate` 用于清理特定 Isolate 的调试数据。

**关于代码特性的回答:**

* **`.tq` 结尾:**  `v8/src/wasm/wasm-debug.cc` 以 `.cc` 结尾，所以它是一个 **C++ 源代码文件**，而不是 Torque 源代码。

* **与 JavaScript 的关系:**  这个 C++ 代码是 V8 引擎内部实现 WebAssembly 调试功能的底层代码。JavaScript 开发者通常通过浏览器或 Node.js 提供的调试工具（如 Chrome DevTools 的调试器或 Node.js 的 `node --inspect`) 来与这些功能交互。

   **JavaScript 示例:**

   假设你在 JavaScript 中加载了一个 WebAssembly 模块，并且想在某个函数入口处设置一个断点：

   ```javascript
   // 假设 'instance' 是你的 WebAssembly 模块实例
   debugger; // 或者在开发者工具中手动设置断点

   instance.exports.myFunction(); // 调用 WebAssembly 函数

   // 在 JavaScript 调试器中，你可以设置在 'myFunction' 内部的某个偏移量的断点。
   // V8 引擎内部会调用 wasm-debug.cc 中的相关 C++ 代码来处理这个断点。
   ```

   当 JavaScript 调试器请求在 WebAssembly 代码中设置断点时，JavaScript 引擎会调用 V8 内部的 API，最终会触发 `wasm-debug.cc` 中的 `SetBreakpoint` 函数。

* **代码逻辑推理和假设输入/输出 (以 `FindNewPC` 为例):**

   **假设输入:**
   - `frame`: 指向当前 WebAssembly 帧的指针，包含当前的程序计数器 (PC) 等信息。
   - `wasm_code`: 指向新编译的 WebAssembly 代码的指针。
   - `byte_offset`: WebAssembly 源代码中的字节偏移量，表示断点所在的位置。
   - `return_location`: 枚举值，指示是在断点之后 (`kAfterBreakpoint`) 还是在 Wasm 调用之后 (`kAfterWasmCall`) 返回。

   **逻辑:**
   `FindNewPC` 函数的目标是找到重新编译后的代码中，对应于原始代码中 `byte_offset` 的新的程序计数器 (PC)。它需要考虑调用指令的大小，以便在断点命中后能正确地跳转到下一条指令。

   1. 它首先获取新旧代码的源位置表 (`source_positions()`)。
   2. 通过比较当前帧的 PC 与旧代码的指令起始地址，计算出当前指令的偏移量。
   3. 遍历旧代码的源位置表，找到当前指令的起始偏移量 (`call_offset`)，从而计算出调用指令的大小 (`call_instruction_size`)。
   4. 遍历新代码的源位置表，找到与 `byte_offset` 匹配的条目。
   5. 如果 `return_location` 是 `kAfterBreakpoint`，它会找到与 `byte_offset` 对应的语句的起始代码偏移，并加上调用指令的大小。
   6. 如果 `return_location` 是 `kAfterWasmCall`，它会找到与 `byte_offset` 关联的最后一个代码偏移，并加上调用指令的大小。

   **假设输出:**
   - `Address`: 新编译的代码中，与断点位置对应的指令的起始地址，用于更新帧的 PC，以便程序在断点命中后能正确恢复执行。

* **用户常见的编程错误 (与调试相关):**

   1. **在优化后的代码中设置断点，导致行为不符合预期:** 优化可能会改变代码的执行顺序，使得单步执行或断点命中的位置与源代码不完全对应。`wasm-debug.cc` 主要处理 Liftoff 编译的代码，Liftoff 是一个 baseline 编译器，优化程度较低，但对于更高级别的优化（如 TurboFan 生成的代码），调试行为可能会有所不同。

   2. **不理解单步执行的粒度:** 用户可能期望单步执行到源代码的每一行，但实际上单步执行的粒度可能更细，对应于 WebAssembly 的指令。

   3. **在异步操作中设置断点:** 当 WebAssembly 代码涉及异步操作（例如通过 JavaScript API 调用），断点的行为可能与同步代码不同，需要理解异步执行的流程。

   4. **在内联函数中设置断点:**  编译器可能会内联函数，导致在原始函数入口设置的断点不会被触发。

   5. **混淆 WebAssembly 的代码偏移和源代码的行号/列号:**  调试器通常会将代码偏移转换为源代码的位置，但用户直接操作代码偏移时可能会出错。

**总结 `v8/src/wasm/wasm-debug.cc` (第 1 部分):**

`v8/src/wasm/wasm-debug.cc` 的第一部分主要负责实现 WebAssembly 的基础调试功能，包括断点管理、单步执行、帧信息检查以及必要的代码重编译和调试信息管理。它为 V8 引擎提供了在 WebAssembly 代码上进行交互式调试的基础设施。该代码高度关注性能，通过缓存调试信息和仅在必要时重新编译代码来优化调试过程。同时，它也考虑了多 Isolate 环境下的调试需求，并提供了清理 Isolate 相关调试数据的机制。

Prompt: 
```
这是目录为v8/src/wasm/wasm-debug.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/wasm-debug.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/wasm/wasm-debug.h"

#include <iomanip>
#include <unordered_map>

#include "src/common/assert-scope.h"
#include "src/common/simd128.h"
#include "src/compiler/wasm-compiler.h"
#include "src/debug/debug-evaluate.h"
#include "src/debug/debug.h"
#include "src/execution/frames-inl.h"
#include "src/heap/factory.h"
#include "src/wasm/baseline/liftoff-compiler.h"
#include "src/wasm/baseline/liftoff-register.h"
#include "src/wasm/compilation-environment-inl.h"
#include "src/wasm/module-decoder.h"
#include "src/wasm/std-object-sizes.h"
#include "src/wasm/value-type.h"
#include "src/wasm/wasm-code-manager.h"
#include "src/wasm/wasm-engine.h"
#include "src/wasm/wasm-limits.h"
#include "src/wasm/wasm-module.h"
#include "src/wasm/wasm-objects-inl.h"
#include "src/wasm/wasm-opcodes-inl.h"
#include "src/wasm/wasm-subtyping.h"
#include "src/wasm/wasm-value.h"
#include "src/zone/accounting-allocator.h"

namespace v8 {
namespace internal {
namespace wasm {

namespace {

using ImportExportKey = std::pair<ImportExportKindCode, uint32_t>;

enum ReturnLocation { kAfterBreakpoint, kAfterWasmCall };

Address FindNewPC(WasmFrame* frame, WasmCode* wasm_code, int byte_offset,
                  ReturnLocation return_location) {
  base::Vector<const uint8_t> new_pos_table = wasm_code->source_positions();

  DCHECK_LE(0, byte_offset);

  // Find the size of the call instruction by computing the distance from the
  // source position entry to the return address.
  WasmCode* old_code = frame->wasm_code();
  int pc_offset = static_cast<int>(frame->pc() - old_code->instruction_start());
  base::Vector<const uint8_t> old_pos_table = old_code->source_positions();
  SourcePositionTableIterator old_it(old_pos_table);
  int call_offset = -1;
  while (!old_it.done() && old_it.code_offset() < pc_offset) {
    call_offset = old_it.code_offset();
    old_it.Advance();
  }
  DCHECK_LE(0, call_offset);
  int call_instruction_size = pc_offset - call_offset;

  // If {return_location == kAfterBreakpoint} we search for the first code
  // offset which is marked as instruction (i.e. not the breakpoint).
  // If {return_location == kAfterWasmCall} we return the last code offset
  // associated with the byte offset.
  SourcePositionTableIterator it(new_pos_table);
  while (!it.done() && it.source_position().ScriptOffset() != byte_offset) {
    it.Advance();
  }
  if (return_location == kAfterBreakpoint) {
    while (!it.is_statement()) it.Advance();
    DCHECK_EQ(byte_offset, it.source_position().ScriptOffset());
    return wasm_code->instruction_start() + it.code_offset() +
           call_instruction_size;
  }

  DCHECK_EQ(kAfterWasmCall, return_location);
  int code_offset;
  do {
    code_offset = it.code_offset();
    it.Advance();
  } while (!it.done() && it.source_position().ScriptOffset() == byte_offset);
  return wasm_code->instruction_start() + code_offset + call_instruction_size;
}

}  // namespace

void DebugSideTable::Print(std::ostream& os) const {
  os << "Debug side table (" << num_locals_ << " locals, " << entries_.size()
     << " entries):\n";
  for (auto& entry : entries_) entry.Print(os);
  os << "\n";
}

void DebugSideTable::Entry::Print(std::ostream& os) const {
  os << std::setw(6) << std::hex << pc_offset_ << std::dec << " stack height "
     << stack_height_ << " [";
  for (auto& value : changed_values_) {
    os << " " << value.type.name() << ":";
    switch (value.storage) {
      case kConstant:
        os << "const#" << value.i32_const;
        break;
      case kRegister:
        os << "reg#" << value.reg_code;
        break;
      case kStack:
        os << "stack#" << value.stack_offset;
        break;
    }
  }
  os << " ]\n";
}

size_t DebugSideTable::Entry::EstimateCurrentMemoryConsumption() const {
  UPDATE_WHEN_CLASS_CHANGES(DebugSideTable::Entry, 32);
  return ContentSize(changed_values_);
}

size_t DebugSideTable::EstimateCurrentMemoryConsumption() const {
  UPDATE_WHEN_CLASS_CHANGES(DebugSideTable, 32);
  size_t result = sizeof(DebugSideTable) + ContentSize(entries_);
  for (const Entry& entry : entries_) {
    result += entry.EstimateCurrentMemoryConsumption();
  }
  return result;
}

class DebugInfoImpl {
 public:
  explicit DebugInfoImpl(NativeModule* native_module)
      : native_module_(native_module) {}

  DebugInfoImpl(const DebugInfoImpl&) = delete;
  DebugInfoImpl& operator=(const DebugInfoImpl&) = delete;

  int GetNumLocals(Address pc, Isolate* isolate) {
    FrameInspectionScope scope(this, pc, isolate);
    if (!scope.is_inspectable()) return 0;
    return scope.debug_side_table->num_locals();
  }

  WasmValue GetLocalValue(int local, Address pc, Address fp,
                          Address debug_break_fp, Isolate* isolate) {
    FrameInspectionScope scope(this, pc, isolate);
    return GetValue(scope.debug_side_table, scope.debug_side_table_entry, local,
                    fp, debug_break_fp, isolate);
  }

  int GetStackDepth(Address pc, Isolate* isolate) {
    FrameInspectionScope scope(this, pc, isolate);
    if (!scope.is_inspectable()) return 0;
    int num_locals = scope.debug_side_table->num_locals();
    int stack_height = scope.debug_side_table_entry->stack_height();
    return stack_height - num_locals;
  }

  WasmValue GetStackValue(int index, Address pc, Address fp,
                          Address debug_break_fp, Isolate* isolate) {
    FrameInspectionScope scope(this, pc, isolate);
    int num_locals = scope.debug_side_table->num_locals();
    int value_count = scope.debug_side_table_entry->stack_height();
    if (num_locals + index >= value_count) return {};
    return GetValue(scope.debug_side_table, scope.debug_side_table_entry,
                    num_locals + index, fp, debug_break_fp, isolate);
  }

  const WasmFunction& GetFunctionAtAddress(Address pc, Isolate* isolate) {
    FrameInspectionScope scope(this, pc, isolate);
    auto* module = native_module_->module();
    return module->functions[scope.code->index()];
  }

  // If the frame position is not in the list of breakpoints, return that
  // position. Return 0 otherwise.
  // This is used to generate a "dead breakpoint" in Liftoff, which is necessary
  // for OSR to find the correct return address.
  int DeadBreakpoint(WasmFrame* frame, base::Vector<const int> breakpoints) {
    const auto& function =
        native_module_->module()->functions[frame->function_index()];
    int offset = frame->position() - function.code.offset();
    if (std::binary_search(breakpoints.begin(), breakpoints.end(), offset)) {
      return 0;
    }
    return offset;
  }

  // Find the dead breakpoint (see above) for the top wasm frame, if that frame
  // is in the function of the given index.
  int DeadBreakpoint(int func_index, base::Vector<const int> breakpoints,
                     Isolate* isolate) {
    DebuggableStackFrameIterator it(isolate);
#if !V8_ENABLE_DRUMBRAKE
    if (it.done() || !it.is_wasm()) return 0;
#else   // !V8_ENABLE_DRUMBRAKE
    // TODO(paolosev@microsoft.com) - Implement for Wasm interpreter.
    if (it.done() || !it.is_wasm() || it.is_wasm_interpreter_entry()) {
      return 0;
    }
#endif  // !V8_ENABLE_DRUMBRAKE
    auto* wasm_frame = WasmFrame::cast(it.frame());
    if (static_cast<int>(wasm_frame->function_index()) != func_index) return 0;
    return DeadBreakpoint(wasm_frame, breakpoints);
  }

  WasmCode* RecompileLiftoffWithBreakpoints(int func_index,
                                            base::Vector<const int> offsets,
                                            int dead_breakpoint) {
    mutex_.AssertHeld();  // Mutex is held externally.

    ForDebugging for_debugging = offsets.size() == 1 && offsets[0] == 0
                                     ? kForStepping
                                     : kWithBreakpoints;

    // Check the cache first.
    for (auto begin = cached_debugging_code_.begin(), it = begin,
              end = cached_debugging_code_.end();
         it != end; ++it) {
      if (it->func_index == func_index &&
          it->breakpoint_offsets.as_vector() == offsets &&
          it->dead_breakpoint == dead_breakpoint) {
        // Rotate the cache entry to the front (for LRU).
        for (; it != begin; --it) std::iter_swap(it, it - 1);
        if (for_debugging == kWithBreakpoints) {
          // Re-install the code, in case it was replaced in the meantime.
          native_module_->ReinstallDebugCode(it->code);
        }
        return it->code;
      }
    }

    // Recompile the function with Liftoff, setting the new breakpoints.
    // Not thread-safe. The caller is responsible for locking {mutex_}.
    CompilationEnv env = CompilationEnv::ForModule(native_module_);
    const WasmFunction* function = &env.module->functions[func_index];
    base::Vector<const uint8_t> wire_bytes = native_module_->wire_bytes();
    bool is_shared = env.module->type(function->sig_index).is_shared;
    FunctionBody body{function->sig, function->code.offset(),
                      wire_bytes.begin() + function->code.offset(),
                      wire_bytes.begin() + function->code.end_offset(),
                      is_shared};
    std::unique_ptr<DebugSideTable> debug_sidetable;

    // Debug side tables for stepping are generated lazily.
    bool generate_debug_sidetable = for_debugging == kWithBreakpoints;
    // If lazy validation is on, we might need to lazily validate here.
    if (V8_UNLIKELY(!env.module->function_was_validated(func_index))) {
      WasmDetectedFeatures unused_detected_features;
      Zone validation_zone(wasm::GetWasmEngine()->allocator(), ZONE_NAME);
      DecodeResult validation_result =
          ValidateFunctionBody(&validation_zone, env.enabled_features,
                               env.module, &unused_detected_features, body);
      // Handling illegal modules here is tricky. As lazy validation is off by
      // default anyway and this is for debugging only, we just crash for now.
      CHECK_WITH_MSG(validation_result.ok(),
                     validation_result.error().message().c_str());
      env.module->set_function_validated(func_index);
    }
    WasmCompilationResult result = ExecuteLiftoffCompilation(
        &env, body,
        LiftoffOptions{}
            .set_func_index(func_index)
            .set_for_debugging(for_debugging)
            .set_breakpoints(offsets)
            .set_dead_breakpoint(dead_breakpoint)
            .set_debug_sidetable(generate_debug_sidetable ? &debug_sidetable
                                                          : nullptr));
    // Liftoff compilation failure is a FATAL error. We rely on complete Liftoff
    // support for debugging.
    if (!result.succeeded()) FATAL("Liftoff compilation failed");
    DCHECK_EQ(generate_debug_sidetable, debug_sidetable != nullptr);

    WasmCode* new_code =
        native_module_->PublishCode(native_module_->AddCompiledCode(result));

    DCHECK(new_code->is_inspectable());
    if (generate_debug_sidetable) {
      base::MutexGuard lock(&debug_side_tables_mutex_);
      DCHECK_EQ(0, debug_side_tables_.count(new_code));
      debug_side_tables_.emplace(new_code, std::move(debug_sidetable));
    }

    // Insert new code into the cache. Insert before existing elements for LRU.
    cached_debugging_code_.insert(
        cached_debugging_code_.begin(),
        CachedDebuggingCode{func_index, base::OwnedVector<int>::Of(offsets),
                            dead_breakpoint, new_code});
    // Increase the ref count (for the cache entry).
    new_code->IncRef();
    // Remove exceeding element.
    if (cached_debugging_code_.size() > kMaxCachedDebuggingCode) {
      // Put the code in the surrounding CodeRefScope to delay deletion until
      // after the mutex is released.
      WasmCodeRefScope::AddRef(cached_debugging_code_.back().code);
      cached_debugging_code_.back().code->DecRefOnLiveCode();
      cached_debugging_code_.pop_back();
    }
    DCHECK_GE(kMaxCachedDebuggingCode, cached_debugging_code_.size());

    return new_code;
  }

  void SetBreakpoint(int func_index, int offset, Isolate* isolate) {
    // Put the code ref scope outside of the mutex, so we don't unnecessarily
    // hold the mutex while freeing code.
    WasmCodeRefScope wasm_code_ref_scope;

    // Hold the mutex while modifying breakpoints, to ensure consistency when
    // multiple isolates set/remove breakpoints at the same time.
    base::MutexGuard guard(&mutex_);

    // offset == 0 indicates flooding and should not happen here.
    DCHECK_NE(0, offset);

    // Get the set of previously set breakpoints, to check later whether a new
    // breakpoint was actually added.
    std::vector<int> all_breakpoints = FindAllBreakpoints(func_index);

    auto& isolate_data = per_isolate_data_[isolate];
    std::vector<int>& breakpoints =
        isolate_data.breakpoints_per_function[func_index];
    auto insertion_point =
        std::lower_bound(breakpoints.begin(), breakpoints.end(), offset);
    if (insertion_point != breakpoints.end() && *insertion_point == offset) {
      // The breakpoint is already set for this isolate.
      return;
    }
    breakpoints.insert(insertion_point, offset);

    DCHECK(std::is_sorted(all_breakpoints.begin(), all_breakpoints.end()));
    // Find the insertion position within {all_breakpoints}.
    insertion_point = std::lower_bound(all_breakpoints.begin(),
                                       all_breakpoints.end(), offset);
    bool breakpoint_exists =
        insertion_point != all_breakpoints.end() && *insertion_point == offset;
    // If the breakpoint was already set before, then we can just reuse the old
    // code. Otherwise, recompile it. In any case, rewrite this isolate's stack
    // to make sure that it uses up-to-date code containing the breakpoint.
    WasmCode* new_code;
    if (breakpoint_exists) {
      new_code = native_module_->GetCode(func_index);
    } else {
      all_breakpoints.insert(insertion_point, offset);
      int dead_breakpoint =
          DeadBreakpoint(func_index, base::VectorOf(all_breakpoints), isolate);
      new_code = RecompileLiftoffWithBreakpoints(
          func_index, base::VectorOf(all_breakpoints), dead_breakpoint);
    }
    UpdateReturnAddresses(isolate, new_code, isolate_data.stepping_frame);
  }

  std::vector<int> FindAllBreakpoints(int func_index) {
    mutex_.AssertHeld();  // Mutex must be held externally.
    std::set<int> breakpoints;
    for (auto& data : per_isolate_data_) {
      auto it = data.second.breakpoints_per_function.find(func_index);
      if (it == data.second.breakpoints_per_function.end()) continue;
      for (int offset : it->second) breakpoints.insert(offset);
    }
    return {breakpoints.begin(), breakpoints.end()};
  }

  void UpdateBreakpoints(int func_index, base::Vector<int> breakpoints,
                         Isolate* isolate, StackFrameId stepping_frame,
                         int dead_breakpoint) {
    mutex_.AssertHeld();  // Mutex is held externally.
    WasmCode* new_code = RecompileLiftoffWithBreakpoints(
        func_index, breakpoints, dead_breakpoint);
    UpdateReturnAddresses(isolate, new_code, stepping_frame);
  }

  void FloodWithBreakpoints(WasmFrame* frame, ReturnLocation return_location) {
    // 0 is an invalid offset used to indicate flooding.
    constexpr int kFloodingBreakpoints[] = {0};
    DCHECK(frame->wasm_code()->is_liftoff());
    // Generate an additional source position for the current byte offset.
    base::MutexGuard guard(&mutex_);
    WasmCode* new_code = RecompileLiftoffWithBreakpoints(
        frame->function_index(), base::ArrayVector(kFloodingBreakpoints), 0);
    UpdateReturnAddress(frame, new_code, return_location);

    per_isolate_data_[frame->isolate()].stepping_frame = frame->id();
  }

  bool IsFrameBlackboxed(WasmFrame* frame) {
    NativeModule* native_module = frame->native_module();
    int func_index = frame->function_index();
    WireBytesRef func_code =
        native_module->module()->functions[func_index].code;
    Isolate* isolate = frame->isolate();
    DirectHandle<Script> script(Cast<Script>(frame->script()), isolate);
    return isolate->debug()->IsFunctionBlackboxed(script, func_code.offset(),
                                                  func_code.end_offset());
  }

  bool PrepareStep(WasmFrame* frame) {
    WasmCodeRefScope wasm_code_ref_scope;
    wasm::WasmCode* code = frame->wasm_code();
    if (!code->is_liftoff()) return false;  // Cannot step in TurboFan code.
    if (IsAtReturn(frame)) return false;    // Will return after this step.
    FloodWithBreakpoints(frame, kAfterBreakpoint);
    return true;
  }

  void PrepareStepOutTo(WasmFrame* frame) {
    WasmCodeRefScope wasm_code_ref_scope;
    wasm::WasmCode* code = frame->wasm_code();
    if (!code->is_liftoff()) return;  // Cannot step out to TurboFan code.
    FloodWithBreakpoints(frame, kAfterWasmCall);
  }

  void ClearStepping(WasmFrame* frame) {
    WasmCodeRefScope wasm_code_ref_scope;
    base::MutexGuard guard(&mutex_);
    auto* code = frame->wasm_code();
    if (code->for_debugging() != kForStepping) return;
    int func_index = code->index();
    std::vector<int> breakpoints = FindAllBreakpoints(func_index);
    int dead_breakpoint = DeadBreakpoint(frame, base::VectorOf(breakpoints));
    WasmCode* new_code = RecompileLiftoffWithBreakpoints(
        func_index, base::VectorOf(breakpoints), dead_breakpoint);
    UpdateReturnAddress(frame, new_code, kAfterBreakpoint);
  }

  void ClearStepping(Isolate* isolate) {
    base::MutexGuard guard(&mutex_);
    auto it = per_isolate_data_.find(isolate);
    if (it != per_isolate_data_.end()) it->second.stepping_frame = NO_ID;
  }

  bool IsStepping(WasmFrame* frame) {
    Isolate* isolate = frame->isolate();
    if (isolate->debug()->last_step_action() == StepInto) return true;
    base::MutexGuard guard(&mutex_);
    auto it = per_isolate_data_.find(isolate);
    return it != per_isolate_data_.end() &&
           it->second.stepping_frame == frame->id();
  }

  void RemoveBreakpoint(int func_index, int position, Isolate* isolate) {
    // Put the code ref scope outside of the mutex, so we don't unnecessarily
    // hold the mutex while freeing code.
    WasmCodeRefScope wasm_code_ref_scope;

    // Hold the mutex while modifying breakpoints, to ensure consistency when
    // multiple isolates set/remove breakpoints at the same time.
    base::MutexGuard guard(&mutex_);

    const auto& function = native_module_->module()->functions[func_index];
    int offset = position - function.code.offset();

    auto& isolate_data = per_isolate_data_[isolate];
    std::vector<int>& breakpoints =
        isolate_data.breakpoints_per_function[func_index];
    DCHECK_LT(0, offset);
    auto insertion_point =
        std::lower_bound(breakpoints.begin(), breakpoints.end(), offset);
    if (insertion_point == breakpoints.end()) return;
    if (*insertion_point != offset) return;
    breakpoints.erase(insertion_point);

    std::vector<int> remaining = FindAllBreakpoints(func_index);
    // If the breakpoint is still set in another isolate, don't remove it.
    DCHECK(std::is_sorted(remaining.begin(), remaining.end()));
    if (std::binary_search(remaining.begin(), remaining.end(), offset)) return;
    int dead_breakpoint =
        DeadBreakpoint(func_index, base::VectorOf(remaining), isolate);
    UpdateBreakpoints(func_index, base::VectorOf(remaining), isolate,
                      isolate_data.stepping_frame, dead_breakpoint);
  }

  void RemoveDebugSideTables(base::Vector<WasmCode* const> codes) {
    base::MutexGuard guard(&debug_side_tables_mutex_);
    for (auto* code : codes) {
      debug_side_tables_.erase(code);
    }
  }

  DebugSideTable* GetDebugSideTableIfExists(const WasmCode* code) const {
    base::MutexGuard guard(&debug_side_tables_mutex_);
    auto it = debug_side_tables_.find(code);
    return it == debug_side_tables_.end() ? nullptr : it->second.get();
  }

  static bool HasRemovedBreakpoints(const std::vector<int>& removed,
                                    const std::vector<int>& remaining) {
    DCHECK(std::is_sorted(remaining.begin(), remaining.end()));
    for (int offset : removed) {
      // Return true if we removed a breakpoint which is not part of remaining.
      if (!std::binary_search(remaining.begin(), remaining.end(), offset)) {
        return true;
      }
    }
    return false;
  }

  void RemoveIsolate(Isolate* isolate) {
    // Put the code ref scope outside of the mutex, so we don't unnecessarily
    // hold the mutex while freeing code.
    WasmCodeRefScope wasm_code_ref_scope;

    base::MutexGuard guard(&mutex_);
    auto per_isolate_data_it = per_isolate_data_.find(isolate);
    if (per_isolate_data_it == per_isolate_data_.end()) return;
    std::unordered_map<int, std::vector<int>> removed_per_function =
        std::move(per_isolate_data_it->second.breakpoints_per_function);
    per_isolate_data_.erase(per_isolate_data_it);
    for (auto& entry : removed_per_function) {
      int func_index = entry.first;
      std::vector<int>& removed = entry.second;
      std::vector<int> remaining = FindAllBreakpoints(func_index);
      if (HasRemovedBreakpoints(removed, remaining)) {
        RecompileLiftoffWithBreakpoints(func_index, base::VectorOf(remaining),
                                        0);
      }
    }
  }

  size_t EstimateCurrentMemoryConsumption() const {
    UPDATE_WHEN_CLASS_CHANGES(DebugInfoImpl, 208);
    UPDATE_WHEN_CLASS_CHANGES(CachedDebuggingCode, 40);
    UPDATE_WHEN_CLASS_CHANGES(PerIsolateDebugData, 48);
    size_t result = sizeof(DebugInfoImpl);
    {
      base::MutexGuard lock(&debug_side_tables_mutex_);
      result += ContentSize(debug_side_tables_);
      for (const auto& [code, table] : debug_side_tables_) {
        result += table->EstimateCurrentMemoryConsumption();
      }
    }
    {
      base::MutexGuard lock(&mutex_);
      result += ContentSize(cached_debugging_code_);
      for (const CachedDebuggingCode& code : cached_debugging_code_) {
        result += code.breakpoint_offsets.size() * sizeof(int);
      }
      result += ContentSize(per_isolate_data_);
      for (const auto& [isolate, data] : per_isolate_data_) {
        // Inlined handling of {PerIsolateDebugData}.
        result += ContentSize(data.breakpoints_per_function);
        for (const auto& [idx, breakpoints] : data.breakpoints_per_function) {
          result += ContentSize(breakpoints);
        }
      }
    }
    if (v8_flags.trace_wasm_offheap_memory) {
      PrintF("DebugInfo: %zu\n", result);
    }
    return result;
  }

 private:
  struct FrameInspectionScope {
    FrameInspectionScope(DebugInfoImpl* debug_info, Address pc,
                         Isolate* isolate)
        : code(wasm::GetWasmCodeManager()->LookupCode(isolate, pc)),
          pc_offset(static_cast<int>(pc - code->instruction_start())),
          debug_side_table(code->is_inspectable()
                               ? debug_info->GetDebugSideTable(code)
                               : nullptr),
          debug_side_table_entry(debug_side_table
                                     ? debug_side_table->GetEntry(pc_offset)
                                     : nullptr) {
      DCHECK_IMPLIES(code->is_inspectable(), debug_side_table_entry != nullptr);
    }

    bool is_inspectable() const { return debug_side_table_entry; }

    wasm::WasmCodeRefScope wasm_code_ref_scope;
    wasm::WasmCode* code;
    int pc_offset;
    const DebugSideTable* debug_side_table;
    const DebugSideTable::Entry* debug_side_table_entry;
  };

  const DebugSideTable* GetDebugSideTable(WasmCode* code) {
    DCHECK(code->is_inspectable());
    {
      // Only hold the mutex temporarily. We can't hold it while generating the
      // debug side table, because compilation takes the {NativeModule} lock.
      base::MutexGuard guard(&debug_side_tables_mutex_);
      auto it = debug_side_tables_.find(code);
      if (it != debug_side_tables_.end()) return it->second.get();
    }

    // Otherwise create the debug side table now.
    std::unique_ptr<DebugSideTable> debug_side_table =
        GenerateLiftoffDebugSideTable(code);
    DebugSideTable* ret = debug_side_table.get();

    // Check cache again, maybe another thread concurrently generated a debug
    // side table already.
    {
      base::MutexGuard guard(&debug_side_tables_mutex_);
      auto& slot = debug_side_tables_[code];
      if (slot != nullptr) return slot.get();
      slot = std::move(debug_side_table);
    }

    // Print the code together with the debug table, if requested.
    code->MaybePrint();
    return ret;
  }

  // Get the value of a local (including parameters) or stack value. Stack
  // values follow the locals in the same index space.
  WasmValue GetValue(const DebugSideTable* debug_side_table,
                     const DebugSideTable::Entry* debug_side_table_entry,
                     int index, Address stack_frame_base,
                     Address debug_break_fp, Isolate* isolate) const {
    const DebugSideTable::Entry::Value* value =
        debug_side_table->FindValue(debug_side_table_entry, index);
    if (value->is_constant()) {
      DCHECK(value->type == kWasmI32 || value->type == kWasmI64);
      return value->type == kWasmI32 ? WasmValue(value->i32_const)
                                     : WasmValue(int64_t{value->i32_const});
    }

    if (value->is_register()) {
      auto reg = LiftoffRegister::from_liftoff_code(value->reg_code);
      auto gp_addr = [debug_break_fp](Register reg) {
        return debug_break_fp +
               WasmDebugBreakFrameConstants::GetPushedGpRegisterOffset(
                   reg.code());
      };
      if (reg.is_gp_pair()) {
        DCHECK_EQ(kWasmI64, value->type);
        uint32_t low_word = ReadUnalignedValue<uint32_t>(gp_addr(reg.low_gp()));
        uint32_t high_word =
            ReadUnalignedValue<uint32_t>(gp_addr(reg.high_gp()));
        return WasmValue((uint64_t{high_word} << 32) | low_word);
      }
      if (reg.is_gp()) {
        if (value->type == kWasmI32) {
          return WasmValue(ReadUnalignedValue<uint32_t>(gp_addr(reg.gp())));
        } else if (value->type == kWasmI64) {
          return WasmValue(ReadUnalignedValue<uint64_t>(gp_addr(reg.gp())));
        } else if (value->type.is_reference()) {
          Handle<Object> obj(
              Tagged<Object>(ReadUnalignedValue<Address>(gp_addr(reg.gp()))),
              isolate);
          return WasmValue(obj, value->type, value->module);
        } else {
          UNREACHABLE();
        }
      }
      DCHECK(reg.is_fp() || reg.is_fp_pair());
      // ifdef here to workaround unreachable code for is_fp_pair.
#ifdef V8_TARGET_ARCH_ARM
      int code = reg.is_fp_pair() ? reg.low_fp().code() : reg.fp().code();
#else
      int code = reg.fp().code();
#endif
      Address spilled_addr =
          debug_break_fp +
          WasmDebugBreakFrameConstants::GetPushedFpRegisterOffset(code);
      if (value->type == kWasmF32) {
        return WasmValue(ReadUnalignedValue<float>(spilled_addr));
      } else if (value->type == kWasmF64) {
        return WasmValue(ReadUnalignedValue<double>(spilled_addr));
      } else if (value->type == kWasmS128) {
        return WasmValue(Simd128(ReadUnalignedValue<int8x16>(spilled_addr)));
      } else {
        // All other cases should have been handled above.
        UNREACHABLE();
      }
    }

    // Otherwise load the value from the stack.
    Address stack_address = stack_frame_base - value->stack_offset;
    switch (value->type.kind()) {
      case kI32:
        return WasmValue(ReadUnalignedValue<int32_t>(stack_address));
      case kI64:
        return WasmValue(ReadUnalignedValue<int64_t>(stack_address));
      case kF32:
        return WasmValue(ReadUnalignedValue<float>(stack_address));
      case kF64:
        return WasmValue(ReadUnalignedValue<double>(stack_address));
      case kS128:
        return WasmValue(Simd128(ReadUnalignedValue<int8x16>(stack_address)));
      case kRef:
      case kRefNull:
      case kRtt: {
        Handle<Object> obj(
            Tagged<Object>(ReadUnalignedValue<Address>(stack_address)),
            isolate);
        return WasmValue(obj, value->type, value->module);
      }
      case kI8:
      case kI16:
      case kF16:
      case kVoid:
      case kTop:
      case kBottom:
        UNREACHABLE();
    }
  }

  // After installing a Liftoff code object with a different set of breakpoints,
  // update return addresses on the stack so that execution resumes in the new
  // code. The frame layout itself should be independent of breakpoints.
  void UpdateReturnAddresses(Isolate* isolate, WasmCode* new_code,
                             StackFrameId stepping_frame) {
    // The first return location is after the breakpoint, others are after wasm
    // calls.
    ReturnLocation return_location = kAfterBreakpoint;
    for (DebuggableStackFrameIterator it(isolate); !it.done();
         it.Advance(), return_location = kAfterWasmCall) {
      // We still need the flooded function for stepping.
      if (it.frame()->id() == stepping_frame) continue;
#if !V8_ENABLE_DRUMBRAKE
      if (!it.is_wasm()) continue;
#else   // !V8_ENABLE_DRUMBRAKE
      // TODO(paolosev@microsoft.com) - Implement for Wasm interpreter.
      if (!it.is_wasm() || it.is_wasm_interpreter_entry()) continue;
#endif  // !V8_ENABLE_DRUMBRAKE
      WasmFrame* frame = WasmFrame::cast(it.frame());
      if (frame->native_module() != new_code->native_module()) continue;
      if (frame->function_index() != new_code->index()) continue;
      if (!frame->wasm_code()->is_liftoff()) continue;
      UpdateReturnAddress(frame, new_code, return_location);
    }
  }

  void UpdateReturnAddress(WasmFrame* frame, WasmCode* new_code,
                           ReturnLocation return_location) {
    DCHECK(new_code->is_liftoff());
    DCHECK_EQ(frame->function_index(), new_code->index());
    DCHECK_EQ(frame->native_module(), new_code->native_module());
    DCHECK(frame->wasm_code()->is_liftoff());
    Address new_pc = FindNewPC(frame, new_code, frame->generated_code_offset(),
                               return_location);
#ifdef DEBUG
    int old_position = frame->position();
#endif
#if V8_TARGET_ARCH_X64
    if (frame->wasm_code()->for_debugging()) {
      base::Memory<Address>(frame->fp() - kOSRTargetOffset) = new_pc;
    }
#else
    PointerAuthentication::ReplacePC(frame->pc_address(), new_pc,
                                     kSystemPointerSize);
#endif
    // The frame position should still be the same after OSR.
    DCHECK_EQ(old_position, frame->position());
  }

  bool IsAtReturn(WasmFrame* frame) {
    DisallowGarbageCollection no_gc;
    int position = frame->position();
    NativeModule* native_module = frame->native_module();
    uint8_t opcode = native_module->wire_bytes()[position];
    if (opcode == kExprReturn) return true;
    // Another implicit return is at the last kExprEnd in the function body.
    int func_index = frame->function_index();
    WireBytesRef code = native_module->module()->functions[func_index].code;
    return static_cast<size_t>(position) == code.end_offset() - 1;
  }

  // Isolate-specific data, for debugging modules that are shared by multiple
  // isolates.
  struct PerIsolateDebugData {
    // Keeps track of the currently set breakpoints (by offset within that
    // function).
    std::unordered_map<int, std::vector<int>> breakpoints_per_function;

    // Store the frame ID when stepping, to avoid overwriting that frame when
    // setting or removing a breakpoint.
    StackFrameId stepping_frame = NO_ID;
  };

  NativeModule* const native_module_;

  mutable base::Mutex debug_side_tables_mutex_;

  // DebugSideTable per code object, lazily initialized.
  std::unordered_map<const WasmCode*, std::unique_ptr<DebugSideTable>>
      debug_side_tables_;

  // {mutex_} protects all fields below.
  mutable base::Mutex mutex_;

  // Cache a fixed number of WasmCode objects that were generated for debugging.
  // This is useful especially in stepping, because stepping code is cleared on
  // every pause and re-installed on the next step.
  // This is a LRU cache (most recently used entries first).
  static constexpr size_t kMaxCachedDebuggingCode = 3;
  struct CachedDebuggingCode {
    int func_index;
    base::OwnedVector<const int> breakpoint_offsets;
    int dead_breakpoint;
    WasmCode* code;
  };
  std::vector<CachedDebuggingCode> cached_debugging_code_;

  // Isolate-specific data.
  std::unordered_map<Isolate*, PerIsolateDebugD
"""


```