Response:
My thought process to arrive at the summary goes like this:

1. **Understand the Goal:** The request asks for a summary of the functionality of `v8/src/deoptimizer/deoptimizer.cc`. It also includes specific checks related to file extensions, JavaScript examples, code logic, and common errors, implying these should be considered when summarizing.

2. **Initial Scan for Keywords:** I quickly scan the code for recurring terms and concepts. "Deoptimizer," "deoptimize," "frame," "code," "stack," "safepoint," "trampoline," "translation," "wasm,"  "interpreter,"  "optimized," "bytecode," etc., stand out. These are strong indicators of the file's purpose.

3. **Identify Core Functionality:** The prevalence of "deoptimize" and related terms immediately suggests the primary role: managing the process of reverting optimized code back to a less optimized state (often the interpreter).

4. **Examine Key Classes and Functions:** I look at the major classes defined: `Deoptimizer`, `FrameWriter`, `DeoptimizableCodeIterator`, and `ActivationsFinder`. Their names provide clues:
    * `Deoptimizer`: The central class managing the deoptimization process. It likely orchestrates the entire operation.
    * `FrameWriter`: Seems responsible for manipulating and writing data related to stack frames during deoptimization. The methods like `PushRawValue`, `PushCallerPc`, `PushTranslatedValue` reinforce this.
    * `DeoptimizableCodeIterator`: Suggests a mechanism for iterating through code objects that are eligible for deoptimization.
    * `ActivationsFinder`:  Indicates a search mechanism, likely for finding active instances of code that needs to be deoptimized on the stack.

5. **Analyze Important Methods within `Deoptimizer`:** I focus on the public and significant methods of the `Deoptimizer` class:
    * `New`, `Grab`, `DeleteForWasm`:  Lifecycle management of the `Deoptimizer` object.
    * `DeoptimizeMarkedCode`, `DeoptimizeAll`, `DeoptimizeFunction`, `DeoptimizeAllOptimizedCodeWithFunction`: These are the core methods triggering different deoptimization scenarios.
    * `ComputeOutputFrames`:  Suggests the creation of new stack frames for the deoptimized execution.
    * `EnsureValidReturnAddress`:  A safety check, ensuring the return address is valid during deoptimization.
    * Methods related to tracing (`TraceDeoptBegin`, `TraceDeoptEnd`, `TraceMarkForDeoptimization`):  Debugging and logging functionalities.

6. **Connect the Pieces:**  I start to piece together the deoptimization process based on the identified components:
    * **Triggering Deoptimization:**  Methods like `DeoptimizeAll`, `DeoptimizeFunction`, etc., initiate the process, potentially based on various conditions (eager, lazy, function-specific, etc.).
    * **Marking Code:**  The code needs to be marked for deoptimization. The `DeoptimizableCodeIterator` is likely used here.
    * **Finding Activations:** `ActivationsFinder` locates active instances of the marked code on the stack.
    * **Replacing PC:**  The `ActivationsFinder` then replaces the program counter (PC) on the stack with a "trampoline" address, which will redirect execution to the deoptimizer.
    * **Frame Translation:** The `Deoptimizer` and `FrameWriter` work together to create a new stack frame (`FrameDescription`) representing the state before optimization. This involves copying or translating values from the optimized frame. The `TranslatedState` class is also relevant here.
    * **Resuming Execution:**  Execution resumes in the less optimized code (interpreter or a less optimized version).

7. **Address Specific Constraints:** I review the prompt's specific requests:
    * **`.tq` extension:** The code is `.cc`, so it's C++, not Torque.
    * **JavaScript examples:**  The code directly manipulates low-level details and interacts with the V8 engine's internals. A direct, simple JavaScript example demonstrating this specific file's functionality isn't feasible. Instead, the *effect* of deoptimization on JavaScript code is what's relevant (performance changes, going back to interpreter, etc.).
    * **Code logic inference:** The process of replacing the PC with a trampoline is a key logic point. The input is an optimized frame, and the output is the modification of the PC to redirect execution.
    * **Common programming errors:**  While this file doesn't *directly* cause user programming errors, it handles situations arising from the *engine's* optimizations. A related error is relying too heavily on optimization and being surprised by deoptimization's impact.
    * **Wasm:** The code explicitly handles WebAssembly deoptimization, so this must be mentioned.

8. **Synthesize the Summary:** I organize my findings into a coherent summary, starting with the main function and then elaborating on the key steps and components involved. I make sure to address the specific points raised in the prompt. I use clear and concise language, avoiding overly technical jargon where possible while still being accurate.

9. **Refine and Review:** I reread the summary and the code snippet to ensure accuracy and completeness. I check for any inconsistencies or areas where the explanation could be clearer. For example, explicitly mentioning the different deoptimization triggers and the role of the `DeoptimizationData` adds clarity. I also double-check that I have addressed all the specific constraints in the prompt.

This iterative process of scanning, analyzing, connecting, and refining allows me to build a comprehensive and accurate summary of the functionality of the given V8 source code.
Based on the provided C++ code snippet from `v8/src/deoptimizer/deoptimizer.cc`, here's a breakdown of its functionality:

**Core Functionality: Managing the Deoptimization Process in V8**

The primary function of `deoptimizer.cc` is to handle the **deoptimization** process within the V8 JavaScript engine. Deoptimization is the mechanism by which the engine reverts from highly optimized machine code back to a less optimized state (typically the interpreter or less aggressively optimized code). This is necessary when assumptions made during optimization become invalid at runtime.

**Key Aspects and Features:**

* **Deoptimizer Class:** The central class `Deoptimizer` orchestrates the entire process. It holds information about the function being deoptimized, the reason for deoptimization, and the state of the stack.
* **Triggering Deoptimization:** The code includes functions like `DeoptimizeAll`, `DeoptimizeFunction`, and `DeoptimizeAllOptimizedCodeWithFunction` that initiate deoptimization under different circumstances (e.g., deoptimizing all optimized code, a specific function's code, or code that inlines a particular function).
* **Marking Code for Deoptimization:**  The code allows marking optimized code (`Code` objects) for deoptimization. This involves setting a flag on the code object.
* **Finding Active Instances:** The `ActivationsFinder` class is used to locate active invocations (frames on the stack) of code that has been marked for deoptimization.
* **Replacing Program Counter (PC):**  Crucially, the deoptimizer modifies the program counter (PC) on the stack frames of the code being deoptimized. It replaces the current PC with the address of a "trampoline" function. This trampoline will then execute the actual deoptimization logic.
* **Frame Translation:** The `FrameWriter` class assists in constructing a description of the stack frame as it existed *before* optimization. This involves pushing values (registers, stack slots, etc.) onto a new `FrameDescription` object. This information is vital for correctly resuming execution in the less optimized code.
* **Handling Different Deoptimization Kinds:** The code distinguishes between `DeoptimizeKind::kEager` (immediate deoptimization) and `DeoptimizeKind::kLazy` (deoptimization happens the next time the code is entered).
* **Wasm Support:** The code includes conditional compilation (`#if V8_ENABLE_WEBASSEMBLY`) to handle deoptimization of WebAssembly code.
* **Debugging and Logging:**  The code includes tracing and logging functionalities (`v8_flags.trace_deopt`, `v8_flags.log_deopt`) to help understand and debug the deoptimization process.
* **Ensuring Valid Return Addresses:**  The `EnsureValidReturnAddress` function checks if a given address is a valid return address during deoptimization, preventing unexpected behavior.

**Is it a Torque Source File?**

The provided code snippet ends with `.cc`, indicating it's a **C++ source file**, not a Torque (`.tq`) file. Torque is a V8-specific language for generating parts of the engine, and while deoptimization logic might involve Torque-generated code elsewhere, this particular file is C++.

**Relationship to JavaScript and Example:**

Deoptimization is directly related to how V8 executes JavaScript. The engine aggressively optimizes frequently executed JavaScript code to improve performance. However, if the assumptions underlying those optimizations become invalid (e.g., a previously monomorphic function becomes polymorphic), the engine needs to deoptimize.

**JavaScript Example (Illustrating the *effect* of deoptimization):**

```javascript
function add(a, b) {
  return a + b;
}

// Initially, V8 might optimize this assuming a and b are always numbers.
add(5, 10); // Optimized execution

// Later, if we call it with different types:
add("hello", " world"); //  V8 might deoptimize the optimized version
                         //  because the assumption about numeric types is broken.

add(7, 8); //  Execution might now happen in the interpreter or a less
           //  aggressive optimization level.
```

In this example, V8 might initially optimize the `add` function for numeric inputs. When it encounters string inputs, the optimized code might no longer be valid, leading to deoptimization. The `deoptimizer.cc` code is responsible for the low-level mechanics of making this transition happen.

**Code Logic Inference (Simplified):**

**Hypothetical Input:**
* An optimized JavaScript function `foo` is currently executing.
* A condition is met that triggers lazy deoptimization for `foo`.
* The current program counter (PC) points to an instruction within the optimized code of `foo`.

**Hypothetical Output:**
* When execution returns from the current function call, the return address on the stack will point to a deoptimization trampoline.
* When this trampoline is executed, the `Deoptimizer` class will be invoked.
* A new stack frame representing the state before optimization will be constructed.
* Execution will resume in the interpreter or less optimized version of `foo` at the correct point.

**User Programming Errors (Indirectly Related):**

While `deoptimizer.cc` itself doesn't directly expose user-facing errors, certain programming patterns can *increase the likelihood* of deoptimization, potentially impacting performance. Common examples include:

* **Type Instability:** Writing JavaScript code where the types of variables or function arguments change frequently. This makes it harder for V8 to make effective optimization assumptions.
    ```javascript
    function process(input) {
      if (typeof input === 'number') {
        return input * 2;
      } else if (typeof input === 'string') {
        return input.toUpperCase();
      }
      return null;
    }

    process(5);
    process("hello"); // This might trigger deoptimization if 'process' was optimized assuming only numbers initially.
    ```
* **Polymorphic Functions:** Functions called with different types of arguments at different call sites.
* **Hidden Classes:**  Dynamically adding or removing properties from objects in a way that changes their underlying structure (hidden class).

**Summary of Functionality (Part 1):**

The `v8/src/deoptimizer/deoptimizer.cc` file implements the core logic for **deoptimizing JavaScript and WebAssembly code** within the V8 engine. It provides the mechanisms to identify code that needs to be deoptimized, locate its active instances on the stack, replace the program counter to redirect execution to the deoptimizer, and reconstruct the pre-optimization stack frame to allow execution to resume in a less optimized state. This process is crucial for maintaining the correctness of JavaScript execution when runtime conditions invalidate optimization assumptions.

### 提示词
```
这是目录为v8/src/deoptimizer/deoptimizer.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/deoptimizer/deoptimizer.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
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
    ShortPr
```