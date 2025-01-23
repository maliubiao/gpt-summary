Response: The user wants a summary of the C++ source code file `v8/src/deoptimizer/deoptimizer.cc`. I need to identify the main functionalities provided by this file. It seems to be related to the deoptimization process in V8, which is a mechanism to revert from optimized code back to interpreted code.

Here's a breakdown of the code's likely functions:

1. **Deoptimization Initiation:**  Creating `Deoptimizer` objects when a function needs to be deoptimized.
2. **Identifying Deoptimizable Code:**  Iterating through the heap to find code that can be deoptimized.
3. **Frame Management:** Creating and manipulating frame descriptions (`FrameDescription`) to represent the stack frames before and after deoptimization.
4. **State Translation:**  Converting the state of the optimized frame into the state of the unoptimized frame(s). This involves extracting values from registers and the stack.
5. **Stack Patching:** Modifying the stack of threads executing optimized code to redirect them to the deoptimizer.
6. **Handling Different Frame Types:**  Specialized logic for different kinds of frames (regular functions, built-in calls, constructor calls, etc.).
7. **Wasm Deoptimization:**  Specific handling for deoptimizing WebAssembly code.
8. **Debugging Support:**  Providing information for debuggers during deoptimization.
9. **Tracing and Logging:**  Outputting information about the deoptimization process for debugging and performance analysis.

The code interacts with JavaScript by performing deoptimization when optimized JavaScript code needs to revert to interpretation. I can illustrate this with an example where type assumptions in optimized code become invalid.
这个C++源代码文件 `v8/src/deoptimizer/deoptimizer.cc` 的主要功能是**实现 V8 引擎的去优化（Deoptimization）机制**。

以下是其主要功能的归纳：

1. **去优化过程的协调者:**  它负责协调整个去优化过程，从检测到需要去优化，到生成新的未优化状态的栈帧。
2. **管理去优化器对象 (`Deoptimizer`):**  创建和管理 `Deoptimizer` 对象，这些对象包含了执行去优化所需的所有信息，例如需要去优化的函数、去优化的原因、当前的执行位置等。
3. **识别可去优化的代码:**  它能够遍历堆中的代码对象，找出那些标记为需要去优化的代码。
4. **构建去优化后的栈帧信息 (`FrameDescription`):**  核心功能之一是将优化后的栈帧状态转换成未优化状态的栈帧信息。这包括计算新的栈帧大小、设置寄存器值、存储局部变量等。
5. **处理不同类型的栈帧:**  针对不同的栈帧类型（例如，普通函数调用、内置函数调用、构造函数调用等）有特定的处理逻辑。
6. **处理 WebAssembly 的去优化:** 提供了专门针对 WebAssembly 代码的去优化流程。
7. **更新程序计数器 (PC):**  在去优化时，需要将程序计数器 (PC) 指向未优化代码的入口点。
8. **支持调试:**  提供接口以便调试器能够检查去优化过程中的栈帧信息。
9. **性能分析和日志记录:**  支持跟踪去优化事件，记录去优化的原因和相关信息，用于性能分析和问题排查。
10. **标记需要去优化的代码:**  提供了标记代码对象为需要去优化的功能。
11. **处理代码依赖:**  当某个代码被标记为需要去优化时，它还会处理依赖于该代码的其他代码。

**与 JavaScript 的关系及示例**

去优化机制是 V8 优化 JavaScript 代码的关键组成部分。当 V8 的优化编译器（例如 TurboFan 或 Maglev）对 JavaScript 代码进行优化后，会基于一定的假设生成更高效的机器码。然而，这些假设在运行时可能会失效（例如，变量的类型发生了变化）。这时，就需要进行去优化，将程序的执行状态回退到解释器或基线编译器执行的状态。

**JavaScript 示例：**

```javascript
function add(x, y) {
  return x + y;
}

// 第一次调用，V8 可能会假设 x 和 y 都是数字
add(1, 2);

// 后续调用，如果传入非数字类型，之前的优化假设就失效了
add("hello", "world");
```

**去优化过程的内部运作：**

1. **优化编译:** 当 `add(1, 2)` 被调用多次后，V8 的优化编译器可能会对其进行优化，生成针对数字类型优化的机器码。
2. **类型假设:** 优化后的代码会假设 `x` 和 `y` 始终是数字。
3. **类型改变:** 当调用 `add("hello", "world")` 时，传入的参数是字符串，这违反了之前的类型假设。
4. **触发去优化:** V8 检测到类型不匹配，触发去优化机制。
5. **`deoptimizer.cc` 的作用:**
   - `Deoptimizer::New` (或类似函数) 会创建一个 `Deoptimizer` 对象，记录当前执行的优化代码和去优化的原因（例如，`kWrongCallTarget` 或 `kDeoptTypeCheckFailed`）。
   - `Deoptimizer` 会分析当前的优化栈帧，确定需要回退到哪个未优化的状态。
   - 它会生成新的 `FrameDescription`，描述未优化栈帧的布局和数据。
   - 它会修改当前的执行上下文，将程序计数器 (PC) 指向解释器中 `add` 函数的入口点。
   - 优化代码占用的资源会被释放，以便垃圾回收。
6. **回退到解释器:**  程序的执行会回退到解释器，使用更通用的方式执行 `add("hello", "world")`。

在这个例子中，`deoptimizer.cc` 中的代码负责将程序的执行状态从针对数字类型优化的机器码环境安全地转换回解释器的执行环境，确保程序能够正确处理新的参数类型。

总结来说，`v8/src/deoptimizer/deoptimizer.cc` 文件是 V8 引擎中实现去优化这一关键特性的核心组件，它保证了 V8 能够在运行时动态地根据实际情况调整代码的执行方式，以达到最佳的性能和正确性。

### 提示词
```
这是目录为v8/src/deoptimizer/deoptimizer.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```
// Copyright 2013 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/deoptimizer/deoptimizer.h"

#include <optional>

#include "src/base/memory.h"
#include "src/codegen/interface-descriptors.h"
#include "src/codegen/register-configuration.h"
#include "src/codegen/reloc-info.h"
#include "src/debug/debug.h"
#include "src/deoptimizer/deoptimized-frame-info.h"
#include "src/deoptimizer/materialized-object-store.h"
#include "src/deoptimizer/translated-state.h"
#include "src/execution/frames-inl.h"
#include "src/execution/isolate.h"
#include "src/execution/pointer-authentication.h"
#include "src/execution/v8threads.h"
#include "src/handles/handles-inl.h"
#include "src/heap/heap-inl.h"
#include "src/logging/counters.h"
#include "src/logging/log.h"
#include "src/logging/runtime-call-stats-scope.h"
#include "src/objects/deoptimization-data.h"
#include "src/objects/js-function-inl.h"
#include "src/objects/oddball.h"
#include "src/snapshot/embedded/embedded-data.h"
#include "src/utils/utils.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/wasm/baseline/liftoff-varstate.h"
#include "src/wasm/compilation-environment-inl.h"
#include "src/wasm/function-compiler.h"
#include "src/wasm/signature-hashing.h"
#include "src/wasm/wasm-deopt-data.h"
#include "src/wasm/wasm-engine.h"
#include "src/wasm/wasm-linkage.h"
#endif  // V8_ENABLE_WEBASSEMBLY

namespace v8 {

using base::Memory;

namespace internal {

namespace {

class DeoptimizableCodeIterator {
 public:
  explicit DeoptimizableCodeIterator(Isolate* isolate);
  DeoptimizableCodeIterator(const DeoptimizableCodeIterator&) = delete;
  DeoptimizableCodeIterator& operator=(const DeoptimizableCodeIterator&) =
      delete;
  Tagged<Code> Next();

 private:
  Isolate* const isolate_;
  std::unique_ptr<SafepointScope> safepoint_scope_;
  std::unique_ptr<ObjectIterator> object_iterator_;
  enum { kIteratingCodeSpace, kIteratingCodeLOSpace, kDone } state_;

  DISALLOW_GARBAGE_COLLECTION(no_gc)
};

DeoptimizableCodeIterator::DeoptimizableCodeIterator(Isolate* isolate)
    : isolate_(isolate),
      safepoint_scope_(std::make_unique<SafepointScope>(
          isolate, isolate->is_shared_space_isolate()
                       ? SafepointKind::kGlobal
                       : SafepointKind::kIsolate)),
      object_iterator_(
          isolate->heap()->code_space()->GetObjectIterator(isolate->heap())),
      state_(kIteratingCodeSpace) {}

Tagged<Code> DeoptimizableCodeIterator::Next() {
  while (true) {
    Tagged<HeapObject> object = object_iterator_->Next();
    if (object.is_null()) {
      // No objects left in the current iterator, try to move to the next space
      // based on the state.
      switch (state_) {
        case kIteratingCodeSpace: {
          object_iterator_ =
              isolate_->heap()->code_lo_space()->GetObjectIterator(
                  isolate_->heap());
          state_ = kIteratingCodeLOSpace;
          continue;
        }
        case kIteratingCodeLOSpace:
          // No other spaces to iterate, so clean up and we're done. Keep the
          // object iterator so that it keeps returning null on Next(), to avoid
          // needing to branch on state_ before the while loop, but drop the
          // safepoint scope since we no longer need to stop the heap from
          // moving.
          safepoint_scope_.reset();
          state_ = kDone;
          [[fallthrough]];
        case kDone:
          return Code();
      }
    }
    Tagged<InstructionStream> istream = Cast<InstructionStream>(object);
    Tagged<Code> code;
    if (!istream->TryGetCode(&code, kAcquireLoad)) continue;
    if (!CodeKindCanDeoptimize(code->kind())) continue;
    return code;
  }
}

}  // namespace

// {FrameWriter} offers a stack writer abstraction for writing
// FrameDescriptions. The main service the class provides is managing
// {top_offset_}, i.e. the offset of the next slot to write to.
//
// Note: Not in an anonymous namespace due to the friend class declaration
// in Deoptimizer.
class FrameWriter {
 public:
  static const int NO_INPUT_INDEX = -1;
  FrameWriter(Deoptimizer* deoptimizer, FrameDescription* frame,
              CodeTracer::Scope* trace_scope)
      : deoptimizer_(deoptimizer),
        frame_(frame),
        trace_scope_(trace_scope),
        top_offset_(frame->GetFrameSize()) {}

  void PushRawValue(intptr_t value, const char* debug_hint) {
    PushValue(value);
    if (trace_scope_ != nullptr) {
      DebugPrintOutputValue(value, debug_hint);
    }
  }

  void PushRawObject(Tagged<Object> obj, const char* debug_hint) {
    intptr_t value = obj.ptr();
    PushValue(value);
    if (trace_scope_ != nullptr) {
      DebugPrintOutputObject(obj, top_offset_, debug_hint);
    }
  }

  // There is no check against the allowed addresses for bottommost frames, as
  // the caller's pc could be anything. The caller's pc pushed here should never
  // be re-signed.
  void PushBottommostCallerPc(intptr_t pc) {
    top_offset_ -= kPCOnStackSize;
    frame_->SetFrameSlot(top_offset_, pc);
    DebugPrintOutputPc(pc, "bottommost caller's pc\n");
  }

  void PushApprovedCallerPc(intptr_t pc) {
    top_offset_ -= kPCOnStackSize;
    frame_->SetCallerPc(top_offset_, pc);
    DebugPrintOutputPc(pc, "caller's pc\n");
  }

  void PushCallerFp(intptr_t fp) {
    top_offset_ -= kFPOnStackSize;
    frame_->SetCallerFp(top_offset_, fp);
    DebugPrintOutputValue(fp, "caller's fp\n");
  }

  void PushCallerConstantPool(intptr_t cp) {
    top_offset_ -= kSystemPointerSize;
    frame_->SetCallerConstantPool(top_offset_, cp);
    DebugPrintOutputValue(cp, "caller's constant_pool\n");
  }

  void PushTranslatedValue(const TranslatedFrame::iterator& iterator,
                           const char* debug_hint = "") {
    Tagged<Object> obj = iterator->GetRawValue();
    PushRawObject(obj, debug_hint);
    if (trace_scope_ != nullptr) {
      PrintF(trace_scope_->file(), " (input #%d)\n", iterator.input_index());
    }
    deoptimizer_->QueueValueForMaterialization(output_address(top_offset_), obj,
                                               iterator);
  }

  void PushFeedbackVectorForMaterialization(
      const TranslatedFrame::iterator& iterator) {
    // Push a marker temporarily.
    PushRawObject(ReadOnlyRoots(deoptimizer_->isolate()).arguments_marker(),
                  "feedback vector");
    deoptimizer_->QueueFeedbackVectorForMaterialization(
        output_address(top_offset_), iterator);
  }

  void PushStackJSArguments(TranslatedFrame::iterator& iterator,
                            int parameters_count) {
    std::vector<TranslatedFrame::iterator> parameters;
    parameters.reserve(parameters_count);
    for (int i = 0; i < parameters_count; ++i, ++iterator) {
      parameters.push_back(iterator);
    }
    for (auto& parameter : base::Reversed(parameters)) {
      PushTranslatedValue(parameter, "stack parameter");
    }
  }

  unsigned top_offset() const { return top_offset_; }

  FrameDescription* frame() { return frame_; }

 private:
  void PushValue(intptr_t value) {
    CHECK_GE(top_offset_, 0);
    top_offset_ -= kSystemPointerSize;
    frame_->SetFrameSlot(top_offset_, value);
  }

  Address output_address(unsigned output_offset) {
    Address output_address =
        static_cast<Address>(frame_->GetTop()) + output_offset;
    return output_address;
  }

  void DebugPrintOutputValue(intptr_t value, const char* debug_hint = "") {
    if (trace_scope_ != nullptr) {
      PrintF(trace_scope_->file(),
             "    " V8PRIxPTR_FMT ": [top + %3d] <- " V8PRIxPTR_FMT " ;  %s",
             output_address(top_offset_), top_offset_, value, debug_hint);
    }
  }

  void DebugPrintOutputPc(intptr_t value, const char* debug_hint = "") {
#ifdef V8_ENABLE_CONTROL_FLOW_INTEGRITY
    if (trace_scope_ != nullptr) {
      PrintF(trace_scope_->file(),
             "    " V8PRIxPTR_FMT ": [top + %3d] <- " V8PRIxPTR_FMT
             " (signed) " V8PRIxPTR_FMT " (unsigned) ;  %s",
             output_address(top_offset_), top_offset_, value,
             PointerAuthentication::StripPAC(value), debug_hint);
    }
#else
    DebugPrintOutputValue(value, debug_hint);
#endif
  }

  void DebugPrintOutputObject(Tagged<Object> obj, unsigned output_offset,
                              const char* debug_hint = "") {
    if (trace_scope_ != nullptr) {
      PrintF(trace_scope_->file(), "    " V8PRIxPTR_FMT ": [top + %3d] <- ",
             output_address(output_offset), output_offset);
      if (IsSmi(obj)) {
        PrintF(trace_scope_->file(), V8PRIxPTR_FMT " <Smi %d>", obj.ptr(),
               Cast<Smi>(obj).value());
      } else {
        ShortPrint(obj, trace_scope_->file());
      }
      PrintF(trace_scope_->file(), " ;  %s", debug_hint);
    }
  }

  Deoptimizer* deoptimizer_;
  FrameDescription* frame_;
  CodeTracer::Scope* const trace_scope_;
  unsigned top_offset_;
};

// We rely on this function not causing a GC. It is called from generated code
// without having a real stack frame in place.
Deoptimizer* Deoptimizer::New(Address raw_function, DeoptimizeKind kind,
                              Address from, int fp_to_sp_delta,
                              Isolate* isolate) {
  // This is zero for wasm.
  Tagged<JSFunction> function =
      raw_function != 0 ? Cast<JSFunction>(Tagged<Object>(raw_function))
                        : Tagged<JSFunction>();
  Deoptimizer* deoptimizer =
      new Deoptimizer(isolate, function, kind, from, fp_to_sp_delta);
  isolate->set_current_deoptimizer(deoptimizer);
  return deoptimizer;
}

Deoptimizer* Deoptimizer::Grab(Isolate* isolate) {
  Deoptimizer* result = isolate->GetAndClearCurrentDeoptimizer();
  result->DeleteFrameDescriptions();
  return result;
}

size_t Deoptimizer::DeleteForWasm(Isolate* isolate) {
  // The deoptimizer disallows garbage collections.
  DCHECK(!AllowGarbageCollection::IsAllowed());
  Deoptimizer* deoptimizer = Deoptimizer::Grab(isolate);
  int output_count = deoptimizer->output_count();
  delete deoptimizer;
  // Now garbage collections are allowed again.
  DCHECK(AllowGarbageCollection::IsAllowed());
  return output_count;
}

DeoptimizedFrameInfo* Deoptimizer::DebuggerInspectableFrame(
    JavaScriptFrame* frame, int jsframe_index, Isolate* isolate) {
  CHECK(frame->is_optimized_js());

  TranslatedState translated_values(frame);
  translated_values.Prepare(frame->fp());

  TranslatedState::iterator frame_it = translated_values.end();
  int counter = jsframe_index;
  for (auto it = translated_values.begin(); it != translated_values.end();
       it++) {
    if (it->kind() == TranslatedFrame::kUnoptimizedFunction ||
        it->kind() == TranslatedFrame::kJavaScriptBuiltinContinuation ||
        it->kind() ==
            TranslatedFrame::kJavaScriptBuiltinContinuationWithCatch) {
      if (counter == 0) {
        frame_it = it;
        break;
      }
      counter--;
    }
  }
  CHECK(frame_it != translated_values.end());
  // We only include kJavaScriptBuiltinContinuation frames above to get the
  // counting right.
  CHECK_EQ(frame_it->kind(), TranslatedFrame::kUnoptimizedFunction);

  DeoptimizedFrameInfo* info =
      new DeoptimizedFrameInfo(&translated_values, frame_it, isolate);

  return info;
}

namespace {
class ActivationsFinder : public ThreadVisitor {
 public:
  ActivationsFinder(Tagged<GcSafeCode> topmost_optimized_code,
                    bool safe_to_deopt_topmost_optimized_code) {
#ifdef DEBUG
    topmost_ = topmost_optimized_code;
    safe_to_deopt_ = safe_to_deopt_topmost_optimized_code;
#endif
  }

  // Find the frames with activations of codes marked for deoptimization, search
  // for the trampoline to the deoptimizer call respective to each code, and use
  // it to replace the current pc on the stack.
  void VisitThread(Isolate* isolate, ThreadLocalTop* top) override {
    for (StackFrameIterator it(isolate, top, StackFrameIterator::NoHandles{});
         !it.done(); it.Advance()) {
      if (it.frame()->is_optimized_js()) {
        Tagged<GcSafeCode> code = it.frame()->GcSafeLookupCode();
        if (CodeKindCanDeoptimize(code->kind()) &&
            code->marked_for_deoptimization()) {
          // Obtain the trampoline to the deoptimizer call.
          int trampoline_pc;
          if (code->is_maglevved()) {
            MaglevSafepointEntry safepoint = MaglevSafepointTable::FindEntry(
                isolate, code, it.frame()->pc());
            trampoline_pc = safepoint.trampoline_pc();
          } else {
            SafepointEntry safepoint = SafepointTable::FindEntry(
                isolate, code, it.frame()->maybe_unauthenticated_pc());
            trampoline_pc = safepoint.trampoline_pc();
          }
          // TODO(saelo): currently we have to use full pointer comparison as
          // builtin Code is still inside the sandbox while runtime-generated
          // Code is in trusted space.
          static_assert(!kAllCodeObjectsLiveInTrustedSpace);
          DCHECK_IMPLIES(code.SafeEquals(topmost_), safe_to_deopt_);
          static_assert(SafepointEntry::kNoTrampolinePC == -1);
          CHECK_GE(trampoline_pc, 0);
          if (!it.frame()->InFastCCall()) {
            Address new_pc = code->instruction_start() + trampoline_pc;
            if (v8_flags.cet_compatible) {
              Address pc = *it.frame()->pc_address();
              Deoptimizer::PatchJumpToTrampoline(pc, new_pc);
            } else {
              // Replace the current pc on the stack with the trampoline.
              // TODO(v8:10026): avoid replacing a signed pointer.
              Address* pc_addr = it.frame()->pc_address();
              PointerAuthentication::ReplacePC(pc_addr, new_pc,
                                               kSystemPointerSize);
            }
          }
        }
      }
    }
  }

 private:
#ifdef DEBUG
  Tagged<GcSafeCode> topmost_;
  bool safe_to_deopt_;
#endif
};
}  // namespace

// Replace pc on the stack for codes marked for deoptimization.
// static
void Deoptimizer::DeoptimizeMarkedCode(Isolate* isolate) {
  DisallowGarbageCollection no_gc;

  Tagged<GcSafeCode> topmost_optimized_code;
  bool safe_to_deopt_topmost_optimized_code = false;
#ifdef DEBUG
  // Make sure all activations of optimized code can deopt at their current PC.
  // The topmost optimized code has special handling because it cannot be
  // deoptimized due to weak object dependency.
  for (StackFrameIterator it(isolate, isolate->thread_local_top(),
                             StackFrameIterator::NoHandles{});
       !it.done(); it.Advance()) {
    if (it.frame()->is_optimized_js()) {
      Tagged<GcSafeCode> code = it.frame()->GcSafeLookupCode();
      Tagged<JSFunction> function =
          static_cast<OptimizedJSFrame*>(it.frame())->function();
      TraceFoundActivation(isolate, function);
      bool safe_if_deopt_triggered;
      if (code->is_maglevved()) {
        MaglevSafepointEntry safepoint =
            MaglevSafepointTable::FindEntry(isolate, code, it.frame()->pc());
        safe_if_deopt_triggered = safepoint.has_deoptimization_index();
      } else {
        SafepointEntry safepoint = SafepointTable::FindEntry(
            isolate, code, it.frame()->maybe_unauthenticated_pc());
        safe_if_deopt_triggered = safepoint.has_deoptimization_index();
      }

      // Deopt is checked when we are patching addresses on stack.
      bool is_builtin_code = code->kind() == CodeKind::BUILTIN;
      DCHECK(topmost_optimized_code.is_null() || safe_if_deopt_triggered ||
             is_builtin_code);
      if (topmost_optimized_code.is_null()) {
        topmost_optimized_code = code;
        safe_to_deopt_topmost_optimized_code = safe_if_deopt_triggered;
      }
    }
  }
#endif

  ActivationsFinder visitor(topmost_optimized_code,
                            safe_to_deopt_topmost_optimized_code);
  // Iterate over the stack of this thread.
  visitor.VisitThread(isolate, isolate->thread_local_top());
  // In addition to iterate over the stack of this thread, we also
  // need to consider all the other threads as they may also use
  // the code currently beings deoptimized.
  isolate->thread_manager()->IterateArchivedThreads(&visitor);
}

void Deoptimizer::DeoptimizeAll(Isolate* isolate) {
  RCS_SCOPE(isolate, RuntimeCallCounterId::kDeoptimizeCode);
  TimerEventScope<TimerEventDeoptimizeCode> timer(isolate);
  TRACE_EVENT0("v8", "V8.DeoptimizeCode");
  TraceDeoptAll(isolate);
  isolate->AbortConcurrentOptimization(BlockingBehavior::kBlock);

  // Mark all code, then deoptimize.
  {
    DeoptimizableCodeIterator it(isolate);
    for (Tagged<Code> code = it.Next(); !code.is_null(); code = it.Next()) {
      code->set_marked_for_deoptimization(true);
    }
  }

  DeoptimizeMarkedCode(isolate);
}

// static
void Deoptimizer::DeoptimizeFunction(Tagged<JSFunction> function,
                                     Tagged<Code> code) {
  Isolate* isolate = function->GetIsolate();
  RCS_SCOPE(isolate, RuntimeCallCounterId::kDeoptimizeCode);
  TimerEventScope<TimerEventDeoptimizeCode> timer(isolate);
  TRACE_EVENT0("v8", "V8.DeoptimizeCode");
  function->ResetIfCodeFlushed(isolate);
  if (code.is_null()) code = function->code(isolate);

  if (CodeKindCanDeoptimize(code->kind())) {
    // Mark the code for deoptimization and unlink any functions that also
    // refer to that code. The code cannot be shared across native contexts,
    // so we only need to search one.
    code->set_marked_for_deoptimization(true);
#ifndef V8_ENABLE_LEAPTIERING_BOOL
    // The code in the function's optimized code feedback vector slot might
    // be different from the code on the function - evict it if necessary.
    function->feedback_vector()->EvictOptimizedCodeMarkedForDeoptimization(
        isolate, function->shared(), "unlinking code marked for deopt");
#endif  // !V8_ENABLE_LEAPTIERING_BOOL

    DeoptimizeMarkedCode(isolate);
  }
}

// static
void Deoptimizer::DeoptimizeAllOptimizedCodeWithFunction(
    Isolate* isolate, DirectHandle<SharedFunctionInfo> function) {
  RCS_SCOPE(isolate, RuntimeCallCounterId::kDeoptimizeCode);
  TimerEventScope<TimerEventDeoptimizeCode> timer(isolate);
  TRACE_EVENT0("v8", "V8.DeoptimizeAllOptimizedCodeWithFunction");

  // Make sure no new code is compiled with the function.
  isolate->AbortConcurrentOptimization(BlockingBehavior::kBlock);

  // Mark all code that inlines this function, then deoptimize.
  bool any_marked = false;
  {
    DeoptimizableCodeIterator it(isolate);
    for (Tagged<Code> code = it.Next(); !code.is_null(); code = it.Next()) {
      if (code->Inlines(*function)) {
        code->set_marked_for_deoptimization(true);
        any_marked = true;
      }
    }
  }
  if (any_marked) {
    DeoptimizeMarkedCode(isolate);
  }
}

#define DEOPTIMIZATION_HELPER_BUILTINS(V)                                    \
  V(Builtin::kInterpreterEnterAtBytecode,                                    \
    deopt_pc_offset_after_adapt_shadow_stack)                                \
  V(Builtin::kInterpreterEnterAtNextBytecode,                                \
    deopt_pc_offset_after_adapt_shadow_stack)                                \
  V(Builtin::kContinueToCodeStubBuiltinWithResult,                           \
    deopt_pc_offset_after_adapt_shadow_stack)                                \
  V(Builtin::kContinueToCodeStubBuiltin,                                     \
    deopt_pc_offset_after_adapt_shadow_stack)                                \
  V(Builtin::kContinueToJavaScriptBuiltinWithResult,                         \
    deopt_pc_offset_after_adapt_shadow_stack)                                \
  V(Builtin::kContinueToJavaScriptBuiltin,                                   \
    deopt_pc_offset_after_adapt_shadow_stack)                                \
  V(Builtin::kBaselineOrInterpreterEnterAtBytecode,                          \
    deopt_pc_offset_after_adapt_shadow_stack)                                \
  V(Builtin::kBaselineOrInterpreterEnterAtNextBytecode,                      \
    deopt_pc_offset_after_adapt_shadow_stack)                                \
  V(Builtin::kRestartFrameTrampoline,                                        \
    deopt_pc_offset_after_adapt_shadow_stack)                                \
  V(Builtin::kJSConstructStubGeneric, construct_stub_create_deopt_pc_offset) \
  V(Builtin::kInterpreterPushArgsThenFastConstructFunction,                  \
    construct_stub_invoke_deopt_pc_offset)

// static
Address Deoptimizer::EnsureValidReturnAddress(Isolate* isolate,
                                              Address address) {
  // TODO(42201233): We should make sure everything here we use for validation
  // (builtins array, code object, and offset values) are not writable.
  Builtins* builtins = isolate->builtins();
  Heap* heap = isolate->heap();
#define CHECK_BUILTIN(builtin, offset)                                        \
  if (builtins->code(builtin)->instruction_start() + heap->offset().value() - \
          Deoptimizer::kAdaptShadowStackOffsetToSubtract ==                   \
      address)                                                                \
    return address;

  DEOPTIMIZATION_HELPER_BUILTINS(CHECK_BUILTIN)
#undef CHECK_BUILTIN

  // NotifyDeoptimized is used for continuation.
  if (builtins->code(Builtin::kNotifyDeoptimized)->instruction_start() ==
      address)
    return address;

#if V8_ENABLE_WEBASSEMBLY
  if (v8_flags.wasm_deopt &&
      wasm::GetWasmCodeManager()->LookupCode(isolate, address) != nullptr) {
    // TODO(42204618): This does not check for the PC being a valid "deopt
    // point" but could be any arbitrary address inside a wasm code object
    // (including pointing into the middle of an instruction).
    return address;
  }
#endif

  CHECK_WITH_MSG(false, "Not allowed return address");
}

void Deoptimizer::ComputeOutputFrames(Deoptimizer* deoptimizer) {
  deoptimizer->DoComputeOutputFrames();
}

const char* Deoptimizer::MessageFor(DeoptimizeKind kind) {
  switch (kind) {
    case DeoptimizeKind::kEager:
      return "deopt-eager";
    case DeoptimizeKind::kLazy:
      return "deopt-lazy";
  }
}

Deoptimizer::Deoptimizer(Isolate* isolate, Tagged<JSFunction> function,
                         DeoptimizeKind kind, Address from, int fp_to_sp_delta)
    : isolate_(isolate),
      function_(function),
      deopt_exit_index_(kFixedExitSizeMarker),
      deopt_kind_(kind),
      from_(from),
      fp_to_sp_delta_(fp_to_sp_delta),
      deoptimizing_throw_(false),
      catch_handler_data_(-1),
      catch_handler_pc_offset_(-1),
      restart_frame_index_(-1),
      input_(nullptr),
      output_count_(0),
      output_(nullptr),
      caller_frame_top_(0),
      caller_fp_(0),
      caller_pc_(0),
      caller_constant_pool_(0),
      actual_argument_count_(0),
      stack_fp_(0),
      trace_scope_(v8_flags.trace_deopt || v8_flags.log_deopt
                       ? new CodeTracer::Scope(isolate->GetCodeTracer())
                       : nullptr) {
  if (isolate->deoptimizer_lazy_throw()) {
    CHECK_EQ(kind, DeoptimizeKind::kLazy);
    isolate->set_deoptimizer_lazy_throw(false);
    deoptimizing_throw_ = true;
  }

  if (isolate->debug()->IsRestartFrameScheduled()) {
    CHECK(deoptimizing_throw_);
    restart_frame_index_ = isolate->debug()->restart_inline_frame_index();
    CHECK_GE(restart_frame_index_, 0);
    isolate->debug()->clear_restart_frame();
  }

  DCHECK_NE(from, kNullAddress);

#ifdef DEBUG
  DCHECK(AllowGarbageCollection::IsAllowed());
  disallow_garbage_collection_ = new DisallowGarbageCollection();
#endif  // DEBUG

#if V8_ENABLE_WEBASSEMBLY
  if (v8_flags.wasm_deopt && function.is_null()) {
#if V8_ENABLE_SANDBOX
    no_heap_access_during_wasm_deopt_ =
        SandboxHardwareSupport::MaybeBlockAccess();
#endif
    wasm::WasmCode* code =
        wasm::GetWasmCodeManager()->LookupCode(isolate, from);
    compiled_optimized_wasm_code_ = code;
    DCHECK_NOT_NULL(code);
    CHECK_EQ(code->kind(), wasm::WasmCode::kWasmFunction);
    wasm::WasmDeoptView deopt_view(code->deopt_data());
    const wasm::WasmDeoptData& deopt_data = deopt_view.GetDeoptData();
    DCHECK_NE(deopt_data.translation_array_size, 0);
    CHECK_GE(from, deopt_data.deopt_exit_start_offset);
    Address deopt_exit_offset = from - code->instruction_start();
    // All eager deopt exits are calls "at the end" of the code to the builtin
    // generated by Generate_DeoptimizationEntry_Eager. These calls have a fixed
    // size kEagerDeoptExitsSize and the deopt data contains the offset of the
    // first such call to the beginning of the code, so we can map any PC of
    // such call to a unique index for this deopt point.
    deopt_exit_index_ =
        static_cast<uint32_t>(deopt_exit_offset -
                              deopt_data.deopt_exit_start_offset -
                              kEagerDeoptExitSize) /
        kEagerDeoptExitSize;

    // Note: The parameter stack slots are not really part of the frame.
    // However, the deoptimizer needs access to the incoming parameter values
    // and therefore they need to be included in the FrameDescription. Between
    // the parameters and the actual frame there are 2 pointers (the caller's pc
    // and saved stack pointer) that therefore also need to be included. Both
    // pointers as well as the incoming parameter stack slots are going to be
    // copied into the outgoing FrameDescription which will "push" them back
    // onto the stack. (This is consistent with how JS handles this.)
    const wasm::FunctionSig* sig =
        code->native_module()->module()->functions[code->index()].sig;
    int parameter_stack_slots, return_stack_slots;
    GetWasmStackSlotsCounts(sig, &parameter_stack_slots, &return_stack_slots);

    unsigned input_frame_size = fp_to_sp_delta +
                                parameter_stack_slots * kSystemPointerSize +
                                CommonFrameConstants::kFixedFrameSizeAboveFp;
    input_ = FrameDescription::Create(input_frame_size, parameter_stack_slots,
                                      isolate_);
    return;
  }
#endif

  compiled_code_ = isolate_->heap()->FindCodeForInnerPointer(from);
  DCHECK(!compiled_code_.is_null());
  DCHECK(IsCode(compiled_code_));

  DCHECK(IsJSFunction(function));
  CHECK(CodeKindCanDeoptimize(compiled_code_->kind()));
  {
    HandleScope scope(isolate_);
    PROFILE(isolate_, CodeDeoptEvent(handle(compiled_code_, isolate_), kind,
                                     from_, fp_to_sp_delta_));
  }
  unsigned size = ComputeInputFrameSize();
  const int parameter_count = compiled_code_->parameter_count();
  DCHECK_EQ(
      parameter_count,
      function->shared()->internal_formal_parameter_count_with_receiver());
  input_ = FrameDescription::Create(size, parameter_count, isolate_);

  DCHECK_EQ(deopt_exit_index_, kFixedExitSizeMarker);
  // Calculate the deopt exit index from return address.
  DCHECK_GT(kEagerDeoptExitSize, 0);
  DCHECK_GT(kLazyDeoptExitSize, 0);
  Tagged<DeoptimizationData> deopt_data =
      Cast<DeoptimizationData>(compiled_code_->deoptimization_data());
  Address deopt_start = compiled_code_->instruction_start() +
                        deopt_data->DeoptExitStart().value();
  int eager_deopt_count = deopt_data->EagerDeoptCount().value();
  Address lazy_deopt_start =
      deopt_start + eager_deopt_count * kEagerDeoptExitSize;
  // The deoptimization exits are sorted so that lazy deopt exits appear after
  // eager deopts.
  static_assert(static_cast<int>(DeoptimizeKind::kLazy) ==
                    static_cast<int>(kLastDeoptimizeKind),
                "lazy deopts are expected to be emitted last");
  // from_ is the value of the link register after the call to the
  // deoptimizer, so for the last lazy deopt, from_ points to the first
  // non-lazy deopt, so we use <=, similarly for the last non-lazy deopt and
  // the first deopt with resume entry.
  if (from_ <= lazy_deopt_start) {
    DCHECK_EQ(kind, DeoptimizeKind::kEager);
    int offset = static_cast<int>(from_ - kEagerDeoptExitSize - deopt_start);
    DCHECK_EQ(0, offset % kEagerDeoptExitSize);
    deopt_exit_index_ = offset / kEagerDeoptExitSize;
  } else {
    DCHECK_EQ(kind, DeoptimizeKind::kLazy);
    int offset =
        static_cast<int>(from_ - kLazyDeoptExitSize - lazy_deopt_start);
    DCHECK_EQ(0, offset % kLazyDeoptExitSize);
    deopt_exit_index_ = eager_deopt_count + (offset / kLazyDeoptExitSize);
  }
}

Handle<JSFunction> Deoptimizer::function() const {
  return Handle<JSFunction>(function_, isolate());
}

Handle<Code> Deoptimizer::compiled_code() const {
  return Handle<Code>(compiled_code_, isolate());
}

Deoptimizer::~Deoptimizer() {
  DCHECK(input_ == nullptr && output_ == nullptr);
#ifdef V8_ENABLE_CET_SHADOW_STACK
  DCHECK_NULL(shadow_stack_);
#endif
  DCHECK_NULL(disallow_garbage_collection_);
  delete trace_scope_;
}

void Deoptimizer::DeleteFrameDescriptions() {
  delete input_;
  for (int i = 0; i < output_count_; ++i) {
    if (output_[i] != input_) delete output_[i];
  }
  delete[] output_;
  input_ = nullptr;
  output_ = nullptr;
#ifdef V8_ENABLE_CET_SHADOW_STACK
  if (shadow_stack_ != nullptr) {
    delete[] shadow_stack_;
    shadow_stack_ = nullptr;
  }
#endif  // V8_ENABLE_CET_SHADOW_STACK
#ifdef DEBUG
  DCHECK(!AllowGarbageCollection::IsAllowed());
  DCHECK_NOT_NULL(disallow_garbage_collection_);
  delete disallow_garbage_collection_;
  disallow_garbage_collection_ = nullptr;
#endif  // DEBUG
}

Builtin Deoptimizer::GetDeoptimizationEntry(DeoptimizeKind kind) {
  switch (kind) {
    case DeoptimizeKind::kEager:
      return Builtin::kDeoptimizationEntry_Eager;
    case DeoptimizeKind::kLazy:
      return Builtin::kDeoptimizationEntry_Lazy;
  }
}

namespace {

int LookupCatchHandler(Isolate* isolate, TranslatedFrame* translated_frame,
                       int* data_out) {
  switch (translated_frame->kind()) {
    case TranslatedFrame::kUnoptimizedFunction: {
      int bytecode_offset = translated_frame->bytecode_offset().ToInt();
      HandlerTable table(
          translated_frame->raw_shared_info()->GetBytecodeArray(isolate));
      int handler_index = table.LookupHandlerIndexForRange(bytecode_offset);
      if (handler_index == HandlerTable::kNoHandlerFound) return handler_index;
      *data_out = table.GetRangeData(handler_index);
      table.MarkHandlerUsed(handler_index);
      return table.GetRangeHandler(handler_index);
    }
    case TranslatedFrame::kJavaScriptBuiltinContinuationWithCatch: {
      return 0;
    }
    default:
      break;
  }
  return -1;
}

}  // namespace

void Deoptimizer::TraceDeoptBegin(int optimization_id,
                                  BytecodeOffset bytecode_offset) {
  DCHECK(tracing_enabled());
  FILE* file = trace_scope()->file();
  Deoptimizer::DeoptInfo info = Deoptimizer::GetDeoptInfo();
  PrintF(file, "[bailout (kind: %s, reason: %s): begin. deoptimizing ",
         MessageFor(deopt_kind_), DeoptimizeReasonToString(info.deopt_reason));
  if (IsJSFunction(function_)) {
    ShortPrint(function_, file);
    PrintF(file, ", ");
  }
  ShortPrint(compiled_code_, file);
  PrintF(file,
         ", opt id %d, "
#ifdef DEBUG
         "node id %d, "
#endif  // DEBUG
         "bytecode offset %d, deopt exit %d, FP to SP "
         "delta %d, "
         "caller SP " V8PRIxPTR_FMT ", pc " V8PRIxPTR_FMT "]\n",
         optimization_id,
#ifdef DEBUG
         info.node_id,
#endif  // DEBUG
         bytecode_offset.ToInt(), deopt_exit_index_, fp_to_sp_delta_,
         caller_frame_top_, PointerAuthentication::StripPAC(from_));
  if (verbose_tracing_enabled() && deopt_kind_ != DeoptimizeKind::kLazy) {
    PrintF(file, "            ;;; deoptimize at ");
    OFStream outstr(file);
    info.position.Print(outstr, compiled_code_);
    PrintF(file, "\n");
  }
}

void Deoptimizer::TraceDeoptEnd(double deopt_duration) {
  DCHECK(verbose_tracing_enabled());
  PrintF(trace_scope()->file(), "[bailout end. took %0.3f ms]\n",
         deopt_duration);
}

// static
void Deoptimizer::TraceMarkForDeoptimization(Isolate* isolate,
                                             Tagged<Code> code,
                                             const char* reason) {
  DCHECK(code->uses_deoptimization_data());
  if (!v8_flags.trace_deopt && !v8_flags.log_deopt) return;

  DisallowGarbageCollection no_gc;
  Tagged<DeoptimizationData> deopt_data =
      Cast<DeoptimizationData>(code->deoptimization_data());
  CodeTracer::Scope scope(isolate->GetCodeTracer());
  if (v8_flags.trace_deopt) {
    PrintF(scope.file(), "[marking dependent code ");
    ShortPrint(code, scope.file());
    PrintF(scope.file(), " (");
    ShortPrint(deopt_data->GetSharedFunctionInfo(), scope.file());
    PrintF(") (opt id %d) for deoptimization, reason: %s]\n",
           deopt_data->OptimizationId().value(), reason);
  }
  if (!v8_flags.log_deopt) return;
  no_gc.Release();
  {
    HandleScope handle_scope(isolate);
    PROFILE(isolate,
            CodeDependencyChangeEvent(
                handle(code, isolate),
                handle(deopt_data->GetSharedFunctionInfo(), isolate), reason));
  }
}

// static
void Deoptimizer::TraceEvictFromOptimizedCodeCache(
    Isolate* isolate, Tagged<SharedFunctionInfo> sfi, const char* reason) {
  if (!v8_flags.trace_deopt_verbose) return;

  DisallowGarbageCollection no_gc;
  CodeTracer::Scope scope(isolate->GetCodeTracer());
  PrintF(scope.file(),
         "[evicting optimized code marked for deoptimization (%s) for ",
         reason);
  ShortPrint(sfi, scope.file());
  PrintF(scope.file(), "]\n");
}

#ifdef DEBUG
// static
void Deoptimizer::TraceFoundActivation(Isolate* isolate,
                                       Tagged<JSFunction> function) {
  if (!v8_flags.trace_deopt_verbose) return;
  CodeTracer::Scope scope(isolate->GetCodeTracer());
  PrintF(scope.file(), "[deoptimizer found activation of function: ");
  function->PrintName(scope.file());
  PrintF(scope.file(), " / %" V8PRIxPTR "]\n", function.ptr());
}
#endif  // DEBUG

// static
void Deoptimizer::TraceDeoptAll(Isolate* isolate) {
  if (!v8_flags.trace_deopt_verbose) return;
  CodeTracer::Scope scope(isolate->GetCodeTracer());
  PrintF(scope.file(), "[deoptimize all code in all contexts]\n");
}

#if V8_ENABLE_WEBASSEMBLY
namespace {
std::pair<wasm::WasmCode*,
          std::unique_ptr<wasm::LiftoffFrameDescriptionForDeopt>>
CompileWithLiftoffAndGetDeoptInfo(wasm::NativeModule* native_module,
                                  int function_index,
                                  BytecodeOffset deopt_point, bool is_topmost) {
  wasm::WasmCompilationUnit unit(function_index, wasm::ExecutionTier::kLiftoff,
                                 wasm::ForDebugging::kNotForDebugging);
  wasm::WasmDetectedFeatures detected;
  wasm::CompilationEnv env = wasm::CompilationEnv::ForModule(native_module);
  env.deopt_info_bytecode_offset = deopt_point.ToInt();
  env.deopt_location_kind = is_topmost
                                ? wasm::LocationKindForDeopt::kEagerDeopt
                                : wasm::LocationKindForDeopt::kInlinedCall;
  std::shared_ptr<wasm::WireBytesStorage> wire_bytes =
      native_module->compilation_state()->GetWireBytesStorage();
  wasm::WasmCompilationResult result =
      unit.ExecuteCompilation(&env, &*wire_bytes, nullptr, &detected);

  // Replace the optimized code with the unoptimized code in the
  // WasmCodeManager as a deopt was reached.
  std::unique_ptr<wasm::WasmCode> compiled_code =
      native_module->AddCompiledCode(result);
  wasm::WasmCodeRefScope code_ref_scope;
  // TODO(mliedtke): This might unoptimize functions because they were inlined
  // into a function that now needs to deopt them while the optimized function
  // might have taken different inlining decisions.
  // TODO(mliedtke): The code cache should also be invalidated.
  wasm::WasmCode* wasm_code = native_module->compilation_state()->PublishCode(
      base::VectorOf(&compiled_code, 1))[0];
  return {wasm_code, std::move(result.liftoff_frame_descriptions)};
}
}  // anonymous namespace

FrameDescription* Deoptimizer::DoComputeWasmLiftoffFrame(
    TranslatedFrame& frame, wasm::NativeModule* native_module,
    Tagged<WasmTrustedInstanceData> wasm_trusted_instance, int frame_index,
    std::stack<intptr_t>& shadow_stack) {
  // Given inlined frames where function a calls b, b is considered the topmost
  // because b is on top of the call stack! This is aligned with the names used
  // by the JS deopt.
  const bool is_bottommost = frame_index == 0;
  const bool is_topmost = output_count_ - 1 == frame_index;
  // Recompile the liftoff (unoptimized) wasm code for the input frame.
  // TODO(mliedtke): This recompiles every single function even if it never got
  // optimized and exists as a liftoff variant in the WasmCodeManager as we also
  // need to compute the deopt information. Can we avoid some of the extra work
  // here?
  auto [wasm_code, liftoff_description] = CompileWithLiftoffAndGetDeoptInfo(
      native_module, frame.wasm_function_index(), frame.bytecode_offset(),
      is_topmost);

  DCHECK(liftoff_description);

  int parameter_stack_slots, return_stack_slots;
  const wasm::FunctionSig* sig =
      native_module->module()->functions[frame.wasm_function_index()].sig;
  GetWasmStackSlotsCounts(sig, &parameter_stack_slots, &return_stack_slots);

  // Allocate and populate the FrameDescription describing the output frame.
  const uint32_t output_frame_size = liftoff_description->total_frame_size;
  const uint32_t total_output_frame_size =
      output_frame_size + parameter_stack_slots * kSystemPointerSize +
      CommonFrameConstants::kFixedFrameSizeAboveFp;

  if (verbose_tracing_enabled()) {
    std::ostringstream outstream;
    outstream << "  Liftoff stack & register state for function index "
              << frame.wasm_function_index() << ", frame size "
              << output_frame_size << ", total frame size "
              << total_output_frame_size << '\n';
    size_t index = 0;
    for (const wasm::LiftoffVarState& state : liftoff_description->var_state) {
      outstream << "     " << index++ << ": " << state << '\n';
    }
    FILE* file = trace_scope()->file();
    PrintF(file, "%s", outstream.str().c_str());
  }

  FrameDescription* output_frame = FrameDescription::Create(
      total_output_frame_size, parameter_stack_slots, isolate());

  // Copy the parameter stack slots.
  static_assert(CommonFrameConstants::kFixedFrameSizeAboveFp ==
                2 * kSystemPointerSize);
  uint32_t output_offset = total_output_frame_size;
  // Zero out the incoming parameter slots. This will make sure that tagged
  // values are safely ignored by the gc.
  // Note that zero is clearly not the correct value. Still, liftoff copies
  // all parameters into "its own" stack slots at the beginning and always
  // uses these slots to restore parameters from the stack.
  for (int i = 0; i < parameter_stack_slots; ++i) {
    output_offset -= kSystemPointerSize;
    output_frame->SetFrameSlot(output_offset, 0);
  }

  // Calculate top and update previous caller's pc.
  Address top = is_bottommost ? caller_frame_top_ - total_output_frame_size
                              : output_[frame_index - 1]->GetTop() -
                                    total_output_frame_size;
  output_frame->SetTop(top);
  Address pc = wasm_code->instruction_start() + liftoff_description->pc_offset;
  // Sign the PC. Note that for the non-topmost frames the stack pointer at
  // which the PC is stored as the "caller pc" / return address depends on the
  // amount of parameter stack slots of the callee. To simplify the code, we
  // just sign it as if there weren't any parameter stack slots.
  // When building up the next frame we can check and "move" the caller PC by
  // signing it again with the correct stack pointer.
  Address signed_pc = PointerAuthentication::SignAndCheckPC(
      isolate(), pc, output_frame->GetTop());
  output_frame->SetPc(signed_pc);
#ifdef V8_ENABLE_CET_SHADOW_STACK
  if (v8_flags.cet_compatible) {
    if (is_topmost) {
      shadow_stack.push(pc);
    } else {
      shadow_stack.push(wasm_code->instruction_start() +
                        liftoff_description->adapt_shadow_stack_pc_offset);
    }
  }
#endif  // V8_ENABLE_CET_SHADOW_STACK

  // Sign the previous frame's PC.
  if (is_bottommost) {
    Address old_context =
        caller_frame_top_ - input_->parameter_count() * kSystemPointerSize;
    Address new_context =
        caller_frame_top_ - parameter_stack_slots * kSystemPointerSize;
    caller_pc_ = PointerAuthentication::MoveSignedPC(isolate(), caller_pc_,
                                                     new_context, old_context);
  } else if (parameter_stack_slots != 0) {
    // The previous frame's PC is stored at a different stack slot, so we need
    // to re-sign the PC for the new context (stack pointer).
    FrameDescription* previous_frame = output_[frame_index - 1];
    Address pc = previous_frame->GetPc();
    Address old_context = previous_frame->GetTop();
    Address new_context =
        old_context - parameter_stack_slots * kSystemPointerSize;
    Address signed_pc = PointerAuthentication::MoveSignedPC(
        isolate(), pc, new_context, old_context);
    previous_frame->SetPc(signed_pc);
  }

  // Store the caller PC.
  output_offset -= kSystemPointerSize;
  output_frame->SetFrameSlot(
      output_offset,
      is_bottommost ? caller_pc_ : output_[frame_index - 1]->GetPc());
  // Store the caller frame pointer.
  output_offset -= kSystemPointerSize;
  output_frame->SetFrameSlot(
      output_offset,
      is_bottommost ? caller_fp_ : output_[frame_index - 1]->GetFp());

  CHECK_EQ(output_frame_size, output_offset);
  int base_offset = output_frame_size;

  // Set trusted instance data on output frame.
  output_frame->SetFrameSlot(
      base_offset - WasmLiftoffFrameConstants::kInstanceDataOffset,
      wasm_trusted_instance.ptr());
  if (liftoff_description->trusted_instance != no_reg) {
    output_frame->SetRegister(liftoff_description->trusted_instance.code(),
                              wasm_trusted_instance.ptr());
  }

  DCHECK_GE(translated_state_.frames().size(), 1);
  auto liftoff_iter = liftoff_description->var_state.begin();
  if constexpr (Is64()) {
    // On 32 bit platforms int64s are represented as 2 values on Turbofan.
    // Liftoff on the other hand treats them as 1 value (a register pair).
    CHECK_EQ(liftoff_description->var_state.size(), frame.GetValueCount());
  }

  bool int64_lowering_is_low = true;

  for (const TranslatedValue& value : frame) {
    bool skip_increase_liftoff_iter = false;
    switch (liftoff_iter->loc()) {
      case wasm::LiftoffVarState::kIntConst:
        if (!Is64() && liftoff_iter->kind() == wasm::ValueKind::kI64) {
          if (int64_lowering_is_low) skip_increase_liftoff_iter = true;
          int64_lowering_is_low = !int64_lowering_is_low;
        }
        break;  // Nothing to be done for constants in liftoff frame.
      case wasm::LiftoffVarState::kRegister:
        if (liftoff_iter->is_gp_reg()) {
          intptr_t reg_value = kZapValue;
          switch (value.kind()) {
            case TranslatedValue::Kind::kInt32:
              // Ensure that the upper half is zeroed out.
              reg_value = static_cast<uint32_t>(value.int32_value());
              break;
            case TranslatedValue::Kind::kTagged:
              reg_value = value.raw_literal().ptr();
              break;
            case TranslatedValue::Kind::kInt64:
              reg_value = value.int64_value();
              break;
            default:
              UNIMPLEMENTED();
          }
          output_frame->SetRegister(liftoff_iter->reg().gp().code(), reg_value);
        } else if (liftoff_iter->is_fp_reg()) {
          switch (value.kind()) {
            case TranslatedValue::Kind::kDouble:
              output_frame->SetDoubleRegister(liftoff_iter->reg().fp().code(),
                                              value.double_value());
              break;
            case TranslatedValue::Kind::kFloat:
              // Liftoff doesn't have a concept of floating point registers.
              // This is an important distinction as e.g. on arm s1 and d1 are
              // two completely distinct registers.
              static_assert(std::is_same_v<decltype(liftoff_iter->reg().fp()),
                                           DoubleRegister>);
              output_frame->SetDoubleRegister(
                  liftoff_iter->reg().fp().code(),
                  Float64::FromBits(value.float_value().get_bits()));
              break;
            case TranslatedValue::Kind::kSimd128:
              output_frame->SetSimd128Register(liftoff_iter->reg().fp().code(),
                                               value.simd_value());
              break;
            default:
              UNIMPLEMENTED();
          }
        } else if (!Is64() && liftoff_iter->is_gp_reg_pair()) {
          intptr_t reg_value = kZapValue;
          switch (value.kind()) {
            case TranslatedValue::Kind::kInt32:
              // Ensure that the upper half is zeroed out.
              reg_value = static_cast<uint32_t>(value.int32_value());
              break;
            case TranslatedValue::Kind::kTagged:
              reg_value = value.raw_literal().ptr();
              break;
            default:
              UNREACHABLE();
          }
          int8_t reg = int64_lowering_is_low
                           ? liftoff_iter->reg().low_gp().code()
                           : liftoff_iter->reg().high_gp().code();
          output_frame->SetRegister(reg, reg_value);
          if (int64_lowering_is_low) skip_increase_liftoff_iter = true;
          int64_lowering_is_low = !int64_lowering_is_low;
        } else if (!Is64() && liftoff_iter->is_fp_reg_pair()) {
          CHECK_EQ(value.kind(), TranslatedValue::Kind::kSimd128);
          Simd128 simd_value = value.simd_value();
          Address val_ptr = reinterpret_cast<Address>(&simd_value);
          output_frame->SetDoubleRegister(
              liftoff_iter->reg().low_fp().code(),
              Float64::FromBits(base::ReadUnalignedValue<uint64_t>(val_ptr)));
          output_frame->SetDoubleRegister(
              liftoff_iter->reg().high_fp().code(),
              Float64::FromBits(base::ReadUnalignedValue<uint64_t>(
                  val_ptr + sizeof(double))));
        } else {
          UNREACHABLE();
        }
        break;
      case wasm::LiftoffVarState::kStack:
#ifdef V8_TARGET_BIG_ENDIAN
        static constexpr int kLiftoffStackBias = 4;
#else
        static constexpr int kLiftoffStackBias = 0;
#endif
        switch (liftoff_iter->kind()) {
          case wasm::ValueKind::kI32:
            CHECK(value.kind() == TranslatedValue::Kind::kInt32 ||
                  value.kind() == TranslatedValue::Kind::kUint32);
            output_frame->SetLiftoffFrameSlot32(
                base_offset - liftoff_iter->offset() + kLiftoffStackBias,
                value.int32_value_);
            break;
          case wasm::ValueKind::kF32:
            CHECK_EQ(value.kind(), TranslatedValue::Kind::kFloat);
            output_frame->SetLiftoffFrameSlot32(
                base_offset - liftoff_iter->offset() + kLiftoffStackBias,
                value.float_value().get_bits());
            break;
          case wasm::ValueKind::kI64:
            if constexpr (Is64()) {
              CHECK(value.kind() == TranslatedValue::Kind::kInt64 ||
                    value.kind() == TranslatedValue::Kind::kUint64);
              output_frame->SetLiftoffFrameSlot64(
                  base_offset - liftoff_iter->offset(), value.int64_value_);
            } else {
              CHECK(value.kind() == TranslatedValue::Kind::kInt32 ||
                    value.kind() == TranslatedValue::Kind::kUint32);
              // TODO(bigendian): Either the offsets or the default for
              // int64_lowering_is_low might have to be swapped.
              if (int64_lowering_is_low) {
                skip_increase_liftoff_iter = true;
                output_frame->SetLiftoffFrameSlot32(
                    base_offset - liftoff_iter->offset(), value.int32_value_);
              } else {
                output_frame->SetLiftoffFrameSlot32(
                    base_offset - liftoff_iter->offset() + sizeof(int32_t),
                    value.int32_value_);
              }
              int64_lowering_is_low = !int64_lowering_is_low;
            }
            break;
          case wasm::ValueKind::kS128: {
            int64x2 values = value.simd_value().to_i64x2();
            const int offset = base_offset - liftoff_iter->offset();
            output_frame->SetLiftoffFrameSlot64(offset, values.val[0]);
            output_frame->SetLiftoffFrameSlot64(offset + sizeof(int64_t),
                                                values.val[1]);
            break;
          }
          case wasm::ValueKind::kF64:
            CHECK_EQ(value.kind(), TranslatedValue::Kind::kDouble);
            output_frame->SetLiftoffFrameSlot64(
                base_offset - liftoff_iter->offset(),
                value.double_value().get_bits());
            break;
          case wasm::ValueKind::kRef:
          case wasm::ValueKind::kRefNull:
            CHECK_EQ(value.kind(), TranslatedValue::Kind::kTagged);
            output_frame->SetLiftoffFrameSlotPointer(
                base_offset - liftoff_iter->offset(), value.raw_literal_.ptr());
            break;
          default:
            UNIMPLEMENTED();
        }
        break;
    }
    DCHECK_IMPLIES(skip_increase_liftoff_iter, !Is64());
    if (!skip_increase_liftoff_iter) {
      ++liftoff_iter;
    }
  }

  // Store frame kind.
  uint32_t frame_type_offset =
      base_offset + WasmLiftoffFrameConstants::kFrameTypeOffset;
  output_frame->SetFrameSlot(frame_type_offset,
                             StackFrame::TypeToMarker(StackFrame::WASM));
  // Store feedback vector in stack slot.
  Tagged<FixedArray> module_feedback =
      wasm_trusted_instance->feedback_vectors();
  uint32_t feedback_offset =
      base_offset - WasmLiftoffFrameConstants::kFeedbackVectorOffset;
  uint32_t fct_feedback_index = wasm::declared_function_index(
      native_module->module(), frame.wasm_function_index());
  CHECK_LT(fct_feedback_index, module_feedback->length());
  Tagged<Object> feedback_vector = module_feedback->get(fct_feedback_index);
  if (IsSmi(feedback_vector)) {
    if (verbose_tracing_enabled()) {
      PrintF(trace_scope()->file(),
             "Deopt with uninitialized feedback vector for function %s [%d]\n",
             wasm_code->DebugName().c_str(), frame.wasm_function_index());
    }
    // Not having a feedback vector can happen with multiple instantiations of
    // the same module as the type feedback is separate per instance but the
    // code is shared (even cross-isolate).
    // Note that we cannot allocate the feedback vector here. Instead, store
    // the function index, so that the feedback vector can be populated by the
    // deopt finish builtin called from Liftoff.
    output_frame->SetFrameSlot(feedback_offset,
                               Smi::FromInt(fct_feedback_index).ptr());
  } else {
    output_frame->SetFrameSlot(feedback_offset, feedback_vector.ptr());
  }

  // Instead of a builtin continuation for wasm the deopt builtin will
  // call a c function to destroy the Deoptimizer object and then directly
  // return to the liftoff code.
  output_frame->SetContinuation(0);

  const intptr_t fp_value = top + output_frame_size;
  output_frame->SetFp(fp_value);
  Register fp_reg = JavaScriptFrame::fp_register();
  output_frame->SetRegister(fp_reg.code(), fp_value);
  output_frame->SetRegister(kRootRegister.code(), isolate()->isolate_root());
#ifdef V8_COMPRESS_POINTERS
  output_frame->SetRegister(kPtrComprCageBaseRegister.code(),
                            isolate()->cage_base());
#endif

  return output_frame;
}

// Build up the output frames for a wasm deopt. This creates the
// FrameDescription objects representing the output frames to be "materialized"
// on the stack.
void Deoptimizer::DoComputeOutputFramesWasmImpl() {
  CHECK(v8_flags.wasm_deopt);
  base::ElapsedTimer timer;
  // Lookup the deopt info for the input frame.
  wasm::WasmCode* code = compiled_optimized_wasm_code_;
  DCHECK_NOT_NULL(code);
  DCHECK_EQ(code->kind(), wasm::WasmCode::kWasmFunction);
  wasm::WasmDeoptView deopt_view(code->deopt_data());
  wasm::WasmDeoptEntry deopt_entry =
      deopt_view.GetDeoptEntry(deopt_exit_index_);

  if (tracing_enabled()) {
    timer.Start();
    FILE* file = trace_scope()->file();
    PrintF(file,
           "[bailout (kind: %s, reason: %s, type: Wasm): begin. deoptimizing "
           "%s, function index %d, bytecode offset %d, deopt exit %d, FP to SP "
           "delta %d, "
           "pc " V8PRIxPTR_FMT "]\n",
           MessageFor(deopt_kind_),
           DeoptimizeReasonToString(DeoptimizeReason::kWrongCallTarget),
           code->DebugName().c_str(), code->index(),
           deopt_entry.bytecode_offset.ToInt(), deopt_entry.translation_index,
           fp_to_sp_delta_, PointerAuthentication::StripPAC(from_));
  }

  base::Vector<const uint8_t> off_heap_translations =
      deopt_view.GetTranslationsArray();

  DeoptTranslationIterator state_iterator(off_heap_translations,
                                          deopt_entry.translation_index);
  wasm::NativeModule* native_module = code->native_module();
  int parameter_count = static_cast<int>(
      native_module->module()->functions[code->index()].sig->parameter_count());
  DeoptimizationLiteralProvider literals(
      deopt_view.BuildDeoptimizationLiteralArray());

  Register fp_reg = JavaScriptFrame::fp_register();
  stack_fp_ = input_->GetRegister(fp_reg.code());
  Address fp_address = input_->GetFramePointerAddress();
  caller_fp_ = Memory<intptr_t>(fp_address);
  caller_pc_ =
      Memory<intptr_t>(fp_address + CommonFrameConstants::kCallerPCOffset);
  caller_frame_top_ = stack_fp_ + CommonFrameConstants::kFixedFrameSizeAboveFp +
                      input_->parameter_count() * kSystemPointerSize;

  FILE* trace_file =
      verbose_tracing_enabled() ? trace_scope()->file() : nullptr;
  translated_state_.Init(isolate_, input_->GetFramePointerAddress(), stack_fp_,
                         &state_iterator, {}, literals,
                         input_->GetRegisterValues(), trace_file,
                         parameter_count, parameter_count);

  const size_t output_frames = translated_state_.frames().size();
  CHECK_GT(output_frames, 0);
  output_count_ = static_cast<int>(output_frames);
  output_ = new FrameDescription* [output_frames] {};

  // The top output function *should* be the same as the optimized function
  // with the deopt. However, this is not the case in case of inlined return
  // calls. The optimized function still needs to be invalidated.
  if (translated_state_.frames()[0].wasm_function_index() !=
      compiled_optimized_wasm_code_->index()) {
    CompileWithLiftoffAndGetDeoptInfo(native_module,
                                      compiled_optimized_wasm_code_->index(),
                                      deopt_entry.bytecode_offset, false);
  }

  // Read the trusted instance data from the input frame.
  Tagged<WasmTrustedInstanceData> wasm_trusted_instance =
      Cast<WasmTrustedInstanceData>((Tagged<Object>(input_->GetFrameSlot(
          input_->GetFrameSize() -
          (2 + input_->parameter_count()) * kSystemPointerSize -
          WasmLiftoffFrameConstants::kInstanceDataOffset))));

  std::stack<intptr_t> shadow_stack;
  for (int i = 0; i < output_count_; ++i) {
    TranslatedFrame& frame = translated_state_.frames()[i];
    output_[i] = DoComputeWasmLiftoffFrame(
        frame, native_module, wasm_trusted_instance, i, shadow_stack);
  }

#ifdef V8_ENABLE_CET_SHADOW_STACK
  if (v8_flags.cet_compatible) {
    CHECK_EQ(shadow_stack_count_, 0);
    shadow_stack_ = new intptr_t[shadow_stack.size()];
    while (!shadow_stack.empty()) {
      shadow_stack_[shadow_stack_count_++] = shadow_stack.top();
      shadow_stack.pop();
    }
    CHECK_EQ(shadow_stack_count_, output_count_);
  }
#endif  // V8_ENABLE_CET_SHADOW_STACK

  {
    // Mark the cached feedback result produced by the
    // TransitiveTypeFeedbackProcessor as outdated.
    // This is required to prevent deopt loops as new feedback is ignored
    // otherwise.
    wasm::TypeFeedbackStorage& feedback =
        native_module->module()->type_feedback;
    base::SharedMutexGuard<base::kExclusive> mutex_guard(&feedback.mutex);
    for (const TranslatedFrame& frame : translated_state_) {
      int index = frame.wasm_function_index();
      auto iter = feedback.feedback_for_function.find(index);
      if (iter != feedback.feedback_for_function.end()) {
        iter->second.needs_reprocessing_after_deopt = true;
      }
    }
    // Reset tierup priority. This is important as the tierup trigger will only
    // be taken into account if the tierup_priority is a power of two (to
    // prevent a hot function being enqueued too many times into the compilation
    // queue.)
    feedback.feedback_for_function[code->index()].tierup_priority = 0;
    // Add sample for how many times this function was deopted.
    isolate()->counters()->wasm_deopts_per_function()->AddSample(
        ++feedback.deopt_count_for_function[code->index()]);
  }

  // Reset tiering budget of the function that triggered the deopt.
  int declared_func_index =
      wasm::declared_function_index(native_module->module(), code->index());
  wasm_trusted_instance->tiering_budget_array()[declared_func_index].store(
      v8_flags.wasm_tiering_budget, std::memory_order_relaxed);

  isolate()->counters()->wasm_deopts_executed()->AddSample(
      wasm::GetWasmEngine()->IncrementDeoptsExecutedCount());

  if (verbose_tracing_enabled()) {
    TraceDeoptEnd(timer.Elapsed().InMillisecondsF());
  }
}

void Deoptimizer::GetWasmStackSlotsCounts(const wasm::FunctionSig* sig,
                                          int* parameter_stack_slots,
                                          int* return_stack_slots) {
  class DummyResultCollector {
   public:
    void AddParamAt(size_t index, LinkageLocation location) {}
    void AddReturnAt(size_t index, LinkageLocation location) {}
  } result_collector;

  // On 32 bits we need to perform the int64 lowering for the signature.
#if V8_TARGET_ARCH_32_BIT
  if (!alloc_) {
    DCHECK(!zone_);
    alloc_.emplace();
    zone_.emplace(&*alloc_, "deoptimizer i32sig lowering");
  }
  sig = GetI32Sig(&*zone_, sig);
#endif
  int untagged_slots, untagged_return_slots;  // Unused.
  wasm::IterateSignatureImpl(sig, false, result_collector, &untagged_slots,
                             parameter_stack_slots, &untagged_return_slots,
                             return_stack_slots);
}
#endif  // V8_ENABLE_WEBASSEMBLY

namespace {

bool DeoptimizedMaglevvedCodeEarly(Isolate* isolate,
                                   Tagged<JSFunction> function,
                                   Tagged<Code> code) {
  if (!code->is_maglevved()) return false;
  if (function->GetRequestedOptimizationIfAny(isolate) ==
      CodeKind::TURBOFAN_JS) {
    // We request turbofan after consuming the invocation_count_for_turbofan
    // budget which is greater than
    // invocation_count_for_maglev_with_delay.
    return false;
  }
  int current_invocation_budget =
      function->raw_feedback_cell()->interrupt_budget() /
      function->shared()->GetBytecodeArray(isolate)->length();
  return current_invocation_budget >=
         v8_flags.invocation_count_for_turbofan -
             v8_flags.invocation_count_for_maglev_with_delay;
}

}  // namespace

// We rely on this function not causing a GC.  It is called from generated code
// without having a real stack frame in place.
void Deoptimizer::DoComputeOutputFrames() {
  // When we call this function, the return address of the previous frame has
  // been removed from the stack by the DeoptimizationEntry builtin, so the
  // stack is not iterable by the StackFrameIteratorForProfiler.
#if V8_TARGET_ARCH_STORES_RETURN_ADDRESS_ON_STACK
  DCHECK_EQ(0, isolate()->isolate_data()->stack_is_iterable());
#endif
  base::ElapsedTimer timer;

#if V8_ENABLE_WEBASSEMBLY
  if (v8_flags.wasm_deopt && function_.is_null()) {
    trap_handler::ClearThreadInWasm();
    DoComputeOutputFramesWasmImpl();
    trap_handler::SetThreadInWasm();
    return;
  }
#endif

  // Determine basic deoptimization information.  The optimized frame is
  // described by the input data.
  Tagged<DeoptimizationData> input_data =
      Cast<DeoptimizationData>(compiled_code_->deoptimization_data());

  {
    // Read caller's PC, caller's FP and caller's constant pool values
    // from input frame. Compute caller's frame top address.

    Register fp_reg = JavaScriptFrame::fp_register();
    stack_fp_ = input_->GetRegister(fp_reg.code());

    caller_frame_top_ = stack_fp_ + ComputeInputFrameAboveFpFixedSize();

    Address fp_address = input_->GetFramePointerAddress();
    caller_fp_ = Memory<intptr_t>(fp_address);
    caller_pc_ =
        Memory<intptr_t>(fp_address + CommonFrameConstants::kCallerPCOffset);
    actual_argument_count_ = static_cast<int>(
        Memory<intptr_t>(fp_address + StandardFrameConstants::kArgCOffset));

    if (V8_EMBEDDED_CONSTANT_POOL_BOOL) {
      caller_constant_pool_ = Memory<intptr_t>(
          fp_address + CommonFrameConstants::kConstantPoolOffset);
    }
  }

  StackGuard* const stack_guard = isolate()->stack_guard();
  CHECK_GT(static_cast<uintptr_t>(caller_frame_top_),
           stack_guard->real_jslimit());

  BytecodeOffset bytecode_offset =
      input_data->GetBytecodeOffsetOrBuiltinContinuationId(deopt_exit_index_);
  auto translations = input_data->FrameTranslation();
  unsigned translation_index =
      input_data->TranslationIndex(deopt_exit_index_).value();

  if (tracing_enabled()) {
    timer.Start();
    TraceDeoptBegin(input_data->OptimizationId().value(), bytecode_offset);
  }

  FILE* trace_file =
      verbose_tracing_enabled() ? trace_scope()->file() : nullptr;
  DeoptimizationFrameTranslation::Iterator state_iterator(translations,
                                                          translation_index);
  DeoptimizationLiteralProvider literals(input_data->LiteralArray());
  translated_state_.Init(isolate_, input_->GetFramePointerAddress(), stack_fp_,
                         &state_iterator, input_data->ProtectedLiteralArray(),
                         literals, input_->GetRegisterValues(), trace_file,
                         compiled_code_->parameter_count_without_receiver(),
                         actual_argument_count_ - kJSArgcReceiverSlots);

  bytecode_offset_in_outermost_frame_ =
      translated_state_.frames()[0].bytecode_offset();

  // Do the input frame to output frame(s) translation.
  size_t count = translated_state_.frames().size();
  if (is_restart_frame()) {
    // If the debugger requested to restart a particular frame, only materialize
    // up to that frame.
    count = restart_frame_index_ + 1;
  } else if (deoptimizing_throw_) {
    // If we are supposed to go to the catch handler, find the catching frame
    // for the catch and make sure we only deoptimize up to that frame.
    size_t catch_handler_frame_index = count;
    for (size_t i = count; i-- > 0;) {
      catch_handler_pc_offset_ = LookupCatchHandler(
          isolate(), &(translated_state_.frames()[i]), &catch_handler_data_);
      if (catch_handler_pc_offset_ >= 0) {
        catch_handler_frame_index = i;
        break;
      }
    }
    CHECK_LT(catch_handler_frame_index, count);
    count = catch_handler_frame_index + 1;
  }

  DCHECK_NULL(output_);
  output_ = new FrameDescription* [count] {};
  output_count_ = static_cast<int>(count);

  // Translate each output frame.
  int frame_index = 0;
  size_t total_output_frame_size = 0;
  for (size_t i = 0; i < count; ++i, ++frame_index) {
    TranslatedFrame* translated_frame = &(translated_state_.frames()[i]);
    const bool handle_exception = deoptimizing_throw_ && i == count - 1;
    switch (translated_frame->kind()) {
      case TranslatedFrame::kUnoptimizedFunction:
        DoComputeUnoptimizedFrame(translated_frame, frame_index,
                                  handle_exception);
        break;
      case TranslatedFrame::kInlinedExtraArguments:
        DoComputeInlinedExtraArguments(translated_frame, frame_index);
        break;
      case TranslatedFrame::kConstructCreateStub:
        DoComputeConstructCreateStubFrame(translated_frame, frame_index);
        break;
      case TranslatedFrame::kConstructInvokeStub:
        DoComputeConstructInvokeStubFrame(translated_frame, frame_index);
        break;
      case TranslatedFrame::kBuiltinContinuation:
#if V8_ENABLE_WEBASSEMBLY
      case TranslatedFrame::kJSToWasmBuiltinContinuation:
#endif  // V8_ENABLE_WEBASSEMBLY
        DoComputeBuiltinContinuation(translated_frame, frame_index,
                                     BuiltinContinuationMode::STUB);
        break;
      case TranslatedFrame::kJavaScriptBuiltinContinuation:
        DoComputeBuiltinContinuation(translated_frame, frame_index,
                                     BuiltinContinuationMode::JAVASCRIPT);
        brea
```