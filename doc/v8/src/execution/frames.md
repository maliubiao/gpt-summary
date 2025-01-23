Response: The user wants a summary of the C++ source code file `v8/src/execution/frames.cc`.
The request also asks to relate the functionality to Javascript with examples if possible.
This is part 1 of a 3-part request, so the summary should focus on the content presented in this first part.

Looking at the included headers, the file seems to be dealing with the concept of "frames" in the context of V8 execution. This likely involves how the call stack is represented and managed.

Key functionalities apparent from the code:

1. **Stack Frame Representation:** Defines classes like `StackFrame`, `JavaScriptStackFrame`, `WasmFrame`, etc., which represent different types of frames on the execution stack.
2. **Stack Frame Iteration:** Provides iterators like `StackFrameIterator` and `JavaScriptStackFrameIterator` to traverse the stack frames.
3. **Frame Type Identification:** Includes logic to determine the type of a stack frame based on the program counter (PC) and frame pointer (FP).
4. **Stack Handler Management:**  Deals with `StackHandler` and its iteration, which are likely related to exception handling or other stack unwinding mechanisms.
5. **Frame Information Extraction:** Methods to get information from a frame, such as the caller frame, function, receiver, and arguments.
6. **Integration with WebAssembly:** Contains specific handling for WebAssembly frames (`WasmFrame`, `CWasmEntryFrame`).

Relation to Javascript:

The code manages the execution stack when Javascript code is running. Each function call in Javascript creates a stack frame. This file defines how those frames are structured and how V8 can inspect them (e.g., for debugging, error reporting, or profiling).

Let's try to create a simple Javascript example to illustrate the concept of stack frames.
This C++ code file (`v8/src/execution/frames.cc`) defines the structure and manipulation of **stack frames** within the V8 JavaScript engine. Its primary function is to provide the mechanisms for:

1. **Representing and differentiating various types of stack frames:** It defines classes like `StackFrame`, `JavaScriptStackFrame`, `ExitFrame`, `BuiltinExitFrame`, and `WasmFrame` to represent different stages and contexts of execution (e.g., when executing JavaScript code, when calling native C++ functions, or when interacting with WebAssembly).

2. **Iterating through the call stack:**  It introduces iterators like `StackFrameIterator` and `JavaScriptStackFrameIterator` that allow V8 to traverse the stack of active function calls. This is crucial for debugging, profiling, and exception handling.

3. **Determining the type of a stack frame:**  The code includes logic to analyze the current execution state (program counter, frame pointer) and identify the specific type of frame, which is essential for understanding what kind of code is currently being executed.

4. **Accessing information within a stack frame:** It provides methods to retrieve key information from a frame, such as the return address, the caller frame, function arguments, and the associated code object.

5. **Handling stack handlers:** It manages `StackHandler` objects, which are likely related to exception handling and unwinding the stack when errors occur.

In essence, this file lays the groundwork for how V8 understands and interacts with the runtime call stack. It's a fundamental component for managing the flow of execution and providing introspection capabilities.

Regarding its relationship to JavaScript functionality, this file is **deeply intertwined** with how JavaScript code executes. Every function call in JavaScript creates a new stack frame. This `frames.cc` file defines the underlying structure and how V8 can examine these frames.

Here's a simple JavaScript example to illustrate the concept of stack frames, although the direct connection to the C++ code is at a lower level:

```javascript
function a() {
  console.log("Inside function a");
  b();
}

function b() {
  console.log("Inside function b");
  debugger; // This will pause execution, allowing inspection of the call stack
}

a();
```

When this JavaScript code is executed, V8 creates stack frames for both `a` and `b`. When the `debugger;` statement is encountered, the JavaScript engine pauses, and you can inspect the call stack in the browser's developer tools. The `frames.cc` file is responsible for the underlying representation and traversal of this call stack that the developer tools expose. The `StackFrameIterator` in the C++ code would be able to iterate through the frames corresponding to the calls to `a` and then `b`.

Furthermore, when an error occurs in JavaScript, V8 uses the stack frame information (managed by this file) to construct the stack trace that is displayed to the user.

For instance, consider this JavaScript code:

```javascript
function outer() {
  inner();
}

function inner() {
  throw new Error("Something went wrong!");
}

try {
  outer();
} catch (e) {
  console.error(e.stack);
}
```

The `e.stack` property contains a string representation of the call stack at the point the error was thrown. The information to generate this stack trace is gathered by V8 by iterating through the stack frames, a process facilitated by the code in `frames.cc`. It would identify the `inner` and `outer` function calls as distinct frames on the stack.

### 提示词
```
这是目录为v8/src/execution/frames.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/execution/frames.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <sstream>

#include "src/api/api-arguments.h"
#include "src/api/api-natives.h"
#include "src/base/bits.h"
#include "src/codegen/interface-descriptors.h"
#include "src/codegen/linkage-location.h"
#include "src/codegen/macro-assembler.h"
#include "src/codegen/maglev-safepoint-table.h"
#include "src/codegen/register-configuration.h"
#include "src/codegen/safepoint-table.h"
#include "src/common/globals.h"
#include "src/deoptimizer/deoptimizer.h"
#include "src/execution/arguments.h"
#include "src/execution/frame-constants.h"
#include "src/execution/frames-inl.h"
#include "src/execution/vm-state-inl.h"
#include "src/ic/ic-stats.h"
#include "src/logging/counters.h"
#include "src/objects/code.h"
#include "src/objects/slots.h"
#include "src/objects/smi.h"
#include "src/objects/visitors.h"
#include "src/roots/roots.h"
#include "src/snapshot/embedded/embedded-data-inl.h"
#include "src/strings/string-stream.h"
#include "src/zone/zone-containers.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/debug/debug-wasm-objects.h"
#include "src/wasm/stacks.h"
#include "src/wasm/wasm-code-manager.h"
#include "src/wasm/wasm-engine.h"
#include "src/wasm/wasm-linkage.h"
#include "src/wasm/wasm-objects-inl.h"
#if V8_ENABLE_DRUMBRAKE
#include "src/wasm/interpreter/wasm-interpreter-runtime.h"
#endif  // V8_ENABLE_DRUMBRAKE
#endif  // V8_ENABLE_WEBASSEMBLY

namespace v8 {
namespace internal {

ReturnAddressLocationResolver StackFrame::return_address_location_resolver_ =
    nullptr;

namespace {

Address AddressOf(const StackHandler* handler) {
  Address raw = handler->address();
#ifdef V8_USE_ADDRESS_SANITIZER
  // ASan puts C++-allocated StackHandler markers onto its fake stack.
  // We work around that by storing the real stack address in the "padding"
  // field. StackHandlers allocated from generated code have 0 as padding.
  Address padding =
      base::Memory<Address>(raw + StackHandlerConstants::kPaddingOffset);
  if (padding != 0) return padding;
#endif
  return raw;
}

}  // namespace

// Iterator that supports traversing the stack handlers of a
// particular frame. Needs to know the top of the handler chain.
class StackHandlerIterator {
 public:
  StackHandlerIterator(const StackFrame* frame, StackHandler* handler)
      : limit_(frame->fp()), handler_(handler) {
#if V8_ENABLE_WEBASSEMBLY
#if !V8_ENABLE_DRUMBRAKE || !USE_SIMULATOR
    // Make sure the handler has already been unwound to this frame. With stack
    // switching this is not equivalent to the inequality below, because the
    // frame and the handler could be in different stacks.
    DCHECK_IMPLIES(frame->isolate()->wasm_stacks().empty(),
                   frame->InFastCCall() || frame->sp() <= AddressOf(handler));
#endif  // !V8_ENABLE_DRUMBRAKE || !USE_SIMULATOR

    // For CWasmEntry frames, the handler was registered by the last C++
    // frame (Execution::CallWasm), so even though its address is already
    // beyond the limit, we know we always want to unwind one handler.
    if (frame->is_c_wasm_entry()) handler_ = handler_->next();
#if V8_ENABLE_DRUMBRAKE
    // Do the same for GenericWasmToJsInterpreterWrapper frames.
    else if (v8_flags.wasm_jitless && frame->is_wasm_to_js()) {
      handler_ = handler_->next();
#ifdef USE_SIMULATOR
      // If we are running in the simulator, the handler_ address here will
      // refer to the 'actual' stack, not to the 'simulated' stack, so we need
      // to fix 'limit_' to make sure that the StackHandlerIterator won't skip
      // any handler.
      limit_ = 0;
#endif  // USE_SIMULATOR
    }
#endif  // V8_ENABLE_DRUMBRAKE
#else
    // Make sure the handler has already been unwound to this frame.
    DCHECK_LE(frame->sp(), AddressOf(handler));
#endif  // V8_ENABLE_WEBASSEMBLY
  }

  StackHandler* handler() const { return handler_; }

  bool done() { return handler_ == nullptr || AddressOf(handler_) > limit_; }
  void Advance() {
    DCHECK(!done());
    handler_ = handler_->next();
  }

 private:
#if V8_ENABLE_DRUMBRAKE && USE_SIMULATOR
  Address limit_;
#else
  const Address limit_;
#endif  // V8_ENABLE_DRUMBRAKE && USE_SIMULATOR

  StackHandler* handler_;
};

// -------------------------------------------------------------------------

StackFrameIteratorBase::StackFrameIteratorBase(Isolate* isolate)
    : isolate_(isolate), frame_(nullptr), handler_(nullptr) {}

StackFrameIterator::StackFrameIterator(Isolate* isolate)
    : StackFrameIterator(isolate, isolate->thread_local_top()) {}

StackFrameIterator::StackFrameIterator(Isolate* isolate, ThreadLocalTop* t)
    : StackFrameIteratorBase(isolate) {
  Reset(t);
}

#if V8_ENABLE_WEBASSEMBLY
StackFrameIterator::StackFrameIterator(Isolate* isolate, ThreadLocalTop* t,
                                       NoHandles)
    : StackFrameIteratorBase(isolate) {
  no_gc_.emplace();
  Reset(t);
}

StackFrameIterator::StackFrameIterator(Isolate* isolate, ThreadLocalTop* t,
                                       FirstStackOnly)
    : StackFrameIteratorBase(isolate) {
  first_stack_only_ = true;
  Reset(t);
}

StackFrameIterator::StackFrameIterator(Isolate* isolate,
                                       wasm::StackMemory* stack)
    : StackFrameIteratorBase(isolate) {
  first_stack_only_ = true;
  Reset(isolate->thread_local_top(), stack);
}
#else
StackFrameIterator::StackFrameIterator(Isolate* isolate, ThreadLocalTop* t,
                                       NoHandles)
    : StackFrameIteratorBase(isolate) {
  Reset(t);
}
#endif

void StackFrameIterator::Advance() {
  DCHECK(!done());
  // Compute the state of the calling frame before restoring
  // callee-saved registers and unwinding handlers. This allows the
  // frame code that computes the caller state to access the top
  // handler and the value of any callee-saved register if needed.
  StackFrame::State state;
  StackFrame::Type type;
#if V8_ENABLE_WEBASSEMBLY
  if (frame_->type() == StackFrame::STACK_SWITCH &&
      Memory<Address>(frame_->fp() +
                      StackSwitchFrameConstants::kCallerFPOffset) ==
          kNullAddress &&
      !first_stack_only_) {
    // Handle stack switches here.
    // Note: both the "callee" frame (outermost frame of the child stack) and
    // the "caller" frame (top frame of the parent stack) have frame type
    // STACK_SWITCH. We use the caller FP to distinguish them: the callee frame
    // does not have a caller fp.
    auto parent = continuation()->parent();
    CHECK(!IsUndefined(parent));
    set_continuation(Cast<WasmContinuationObject>(parent));
    wasm_stack_ = reinterpret_cast<wasm::StackMemory*>(continuation()->stack());
    CHECK_EQ(wasm_stack_->jmpbuf()->state, wasm::JumpBuffer::Inactive);
    StackSwitchFrame::GetStateForJumpBuffer(wasm_stack_->jmpbuf(), &state);
    SetNewFrame(StackFrame::STACK_SWITCH, &state);
    return;
  }
#endif
  type = frame_->GetCallerState(&state);

  // {StackHandlerIterator} assumes that frame pointers strictly go from lower
  // to higher addresses as we iterate the stack. This breaks with
  // stack-switching, so only unwind the stack handlers for frames that are
  // known to use them.
  if (frame_->type() == StackFrame::ENTRY ||
      frame_->type() == StackFrame::CONSTRUCT_ENTRY
#if V8_ENABLE_WEBASSEMBLY
      || frame_->type() == StackFrame::C_WASM_ENTRY
#endif
  ) {
    StackHandlerIterator it(frame_, handler_);
    while (!it.done()) it.Advance();
    handler_ = it.handler();
  }

  // Advance to the calling frame.
  SetNewFrame(type, &state);
  // When we're done iterating over the stack frames, the handler
  // chain must have been completely unwound. Except if we are only iterating
  // the first stack of the chain for wasm stack-switching.
#if V8_ENABLE_WEBASSEMBLY
  DCHECK_IMPLIES(done() && !first_stack_only_, handler_ == nullptr);
#else
  DCHECK_IMPLIES(done(), handler_ == nullptr);
#endif
}

StackFrame* StackFrameIterator::Reframe() {
  StackFrame::State state = frame_->state_;
  StackFrame::Type type = ComputeStackFrameType(&state);
  SetNewFrame(type, &state);
  return frame();
}

namespace {
StackFrame::Type GetStateForFastCCallCallerFP(Isolate* isolate, Address fp,
                                              Address pc, Address pc_address,
                                              StackFrame::State* state) {
  // 'Fast C calls' are a special type of C call where we call directly from
  // JS to C without an exit frame inbetween. The CEntryStub is responsible
  // for setting Isolate::c_entry_fp, meaning that it won't be set for fast C
  // calls. To keep the stack iterable, we store the FP and PC of the caller
  // of the fast C call on the isolate. This is guaranteed to be the topmost
  // JS frame, because fast C calls cannot call back into JS. We start
  // iterating the stack from this topmost JS frame.
  DCHECK_NE(kNullAddress, pc);
  state->fp = fp;
  state->sp = kNullAddress;
  state->pc_address = reinterpret_cast<Address*>(pc_address);
  state->callee_pc = kNullAddress;
  state->constant_pool_address = nullptr;
#if V8_ENABLE_WEBASSEMBLY
  if (wasm::WasmCode* code =
          wasm::GetWasmCodeManager()->LookupCode(isolate, pc)) {
    if (code->kind() == wasm::WasmCode::kWasmToJsWrapper) {
      return StackFrame::WASM_TO_JS;
    }
    DCHECK_EQ(code->kind(), wasm::WasmCode::kWasmFunction);
    return StackFrame::WASM;
  }
#endif  // V8_ENABLE_WEBASSEMBLY
  return StackFrame::TURBOFAN_JS;
}
}  // namespace

void StackFrameIterator::Reset(ThreadLocalTop* top) {
  StackFrame::State state;
  StackFrame::Type type;

  const Address fast_c_call_caller_fp =
      isolate_->isolate_data()->fast_c_call_caller_fp();
  if (fast_c_call_caller_fp != kNullAddress) {
    const Address caller_pc = isolate_->isolate_data()->fast_c_call_caller_pc();
    const Address caller_pc_address =
        isolate_->isolate_data()->fast_c_call_caller_pc_address();
    type = GetStateForFastCCallCallerFP(isolate_, fast_c_call_caller_fp,
                                        caller_pc, caller_pc_address, &state);
  } else {
    type = ExitFrame::GetStateForFramePointer(Isolate::c_entry_fp(top), &state);
  }
#if V8_ENABLE_WEBASSEMBLY
  auto active_continuation = isolate_->root(RootIndex::kActiveContinuation);
  if (!IsUndefined(active_continuation, isolate_)) {
    auto continuation = Cast<WasmContinuationObject>(active_continuation);
    if (!first_stack_only_) {
      set_continuation(continuation);
    }
    wasm_stack_ = reinterpret_cast<wasm::StackMemory*>(continuation->stack());
  }
#endif
  handler_ = StackHandler::FromAddress(Isolate::handler(top));
  SetNewFrame(type, &state);
}

#if V8_ENABLE_WEBASSEMBLY
void StackFrameIterator::Reset(ThreadLocalTop* top, wasm::StackMemory* stack) {
  if (stack->jmpbuf()->state == wasm::JumpBuffer::Retired) {
    return;
  }
  StackFrame::State state;
  StackSwitchFrame::GetStateForJumpBuffer(stack->jmpbuf(), &state);
  handler_ = StackHandler::FromAddress(Isolate::handler(top));
  wasm_stack_ = stack;
  SetNewFrame(StackFrame::STACK_SWITCH, &state);
}
#endif

void StackFrameIteratorBase::SetNewFrame(StackFrame::Type type,
                                         StackFrame::State* state) {
  SetNewFrame(type);
  DCHECK_EQ(!frame_, type == StackFrame::NO_FRAME_TYPE);
  if (frame_) frame_->state_ = *state;
}

void StackFrameIteratorBase::SetNewFrame(StackFrame::Type type) {
  switch (type) {
#define FRAME_TYPE_CASE(type, class)      \
  case StackFrame::type:                  \
    frame_ = new (&class##_) class(this); \
    return;
    STACK_FRAME_TYPE_LIST(FRAME_TYPE_CASE)
#undef FRAME_TYPE_CASE

    case StackFrame::NO_FRAME_TYPE:
    // We don't expect to see NUMBER_OF_TYPES or MANUAL, but stay robust against
    // them rather than being UNREACHABLE in case stack frame iteration gets
    // wonky.
    case StackFrame::NUMBER_OF_TYPES:
    case StackFrame::MANUAL:
      break;
  }
  frame_ = nullptr;
}

#if V8_ENABLE_WEBASSEMBLY
Tagged<WasmContinuationObject> StackFrameIterator::continuation() {
  return no_gc_.has_value() ? continuation_.obj_ : *continuation_.handle_;
}

void StackFrameIterator::set_continuation(
    Tagged<WasmContinuationObject> continuation) {
  if (no_gc_.has_value()) {
    continuation_.obj_ = continuation;
  } else {
    continuation_.handle_ = handle(continuation, isolate_);
  }
}
#endif

// -------------------------------------------------------------------------

void TypedFrameWithJSLinkage::Iterate(RootVisitor* v) const {
  IterateExpressions(v);
  IteratePc(v, constant_pool_address(), GcSafeLookupCode());
}

// -------------------------------------------------------------------------

void ConstructFrame::Iterate(RootVisitor* v) const {
  // The frame contains the actual argument count (intptr) that should not
  // be visited.
  FullObjectSlot argc(
      &Memory<Address>(fp() + ConstructFrameConstants::kLengthOffset));
  const int last_object_offset = ConstructFrameConstants::kLastObjectOffset;
  FullObjectSlot base(&Memory<Address>(sp()));
  FullObjectSlot limit(&Memory<Address>(fp() + last_object_offset) + 1);
  v->VisitRootPointers(Root::kStackRoots, nullptr, base, argc);
  v->VisitRootPointers(Root::kStackRoots, nullptr, argc + 1, limit);
  IteratePc(v, constant_pool_address(), GcSafeLookupCode());
}

// -------------------------------------------------------------------------

void JavaScriptStackFrameIterator::Advance() {
  do {
    iterator_.Advance();
  } while (!iterator_.done() && !iterator_.frame()->is_javascript());
}

// -------------------------------------------------------------------------

DebuggableStackFrameIterator::DebuggableStackFrameIterator(Isolate* isolate)
    : iterator_(isolate) {
  if (!done() && !IsValidFrame(iterator_.frame())) Advance();
}

DebuggableStackFrameIterator::DebuggableStackFrameIterator(Isolate* isolate,
                                                           StackFrameId id)
    : DebuggableStackFrameIterator(isolate) {
  while (!done() && frame()->id() != id) Advance();
}

void DebuggableStackFrameIterator::Advance() {
  do {
    iterator_.Advance();
  } while (!done() && !IsValidFrame(iterator_.frame()));
}

int DebuggableStackFrameIterator::FrameFunctionCount() const {
  DCHECK(!done());
  if (!iterator_.frame()->is_optimized_js()) return 1;
  std::vector<Tagged<SharedFunctionInfo>> infos;
  TurbofanJSFrame::cast(iterator_.frame())->GetFunctions(&infos);
  return static_cast<int>(infos.size());
}

FrameSummary DebuggableStackFrameIterator::GetTopValidFrame() const {
  DCHECK(!done());
  // Like FrameSummary::GetTop, but additionally observes
  // DebuggableStackFrameIterator filtering semantics.
  std::vector<FrameSummary> frames;
  frame()->Summarize(&frames);
  if (is_javascript()) {
    for (int i = static_cast<int>(frames.size()) - 1; i >= 0; i--) {
      const FrameSummary& summary = frames[i];
      if (summary.is_subject_to_debugging()) {
        return summary;
      }
    }
    UNREACHABLE();
  }
#if V8_ENABLE_WEBASSEMBLY
  if (is_wasm()) return frames.back();
#endif  // V8_ENABLE_WEBASSEMBLY
  UNREACHABLE();
}

// static
bool DebuggableStackFrameIterator::IsValidFrame(StackFrame* frame) {
  if (frame->is_javascript()) {
    Tagged<JSFunction> function =
        static_cast<JavaScriptFrame*>(frame)->function();
    return function->shared()->IsSubjectToDebugging();
  }
#if V8_ENABLE_WEBASSEMBLY
  if (frame->is_wasm()) return true;
#endif  // V8_ENABLE_WEBASSEMBLY
  return false;
}

// -------------------------------------------------------------------------

namespace {

std::optional<bool> IsInterpreterFramePc(Isolate* isolate, Address pc,
                                         StackFrame::State* state) {
  Builtin builtin = OffHeapInstructionStream::TryLookupCode(isolate, pc);
  if (builtin != Builtin::kNoBuiltinId &&
      (builtin == Builtin::kInterpreterEntryTrampoline ||
       builtin == Builtin::kInterpreterEnterAtBytecode ||
       builtin == Builtin::kInterpreterEnterAtNextBytecode ||
       builtin == Builtin::kBaselineOrInterpreterEnterAtBytecode ||
       builtin == Builtin::kBaselineOrInterpreterEnterAtNextBytecode)) {
    return true;
  } else if (v8_flags.interpreted_frames_native_stack) {
    intptr_t marker = Memory<intptr_t>(
        state->fp + CommonFrameConstants::kContextOrFrameTypeOffset);
    MSAN_MEMORY_IS_INITIALIZED(
        state->fp + StandardFrameConstants::kFunctionOffset,
        kSystemPointerSize);
    Tagged<Object> maybe_function = Tagged<Object>(
        Memory<Address>(state->fp + StandardFrameConstants::kFunctionOffset));
    // There's no need to run a full ContainsSlow if we know the frame can't be
    // an InterpretedFrame,  so we do these fast checks first
    if (StackFrame::IsTypeMarker(marker) || IsSmi(maybe_function)) {
      return false;
    } else if (!isolate->heap()->InSpaceSlow(pc, CODE_SPACE)) {
      return false;
    }
    if (!ThreadIsolation::CanLookupStartOfJitAllocationAt(pc)) {
      return {};
    }
    Tagged<Code> interpreter_entry_trampoline =
        isolate->heap()->FindCodeForInnerPointer(pc);
    return interpreter_entry_trampoline->is_interpreter_trampoline_builtin();
  } else {
    return false;
  }
}

}  // namespace

bool StackFrameIteratorForProfiler::IsNoFrameBytecodeHandlerPc(
    Isolate* isolate, Address pc, Address fp) const {
  EmbeddedData d = EmbeddedData::FromBlob(isolate);
  if (pc < d.InstructionStartOfBytecodeHandlers() ||
      pc >= d.InstructionEndOfBytecodeHandlers()) {
    return false;
  }

  Address frame_type_address =
      fp + CommonFrameConstants::kContextOrFrameTypeOffset;
  if (!IsValidStackAddress(frame_type_address)) {
    return false;
  }

  // Check if top stack frame is a bytecode handler stub frame.
  MSAN_MEMORY_IS_INITIALIZED(frame_type_address, kSystemPointerSize);
  intptr_t marker = Memory<intptr_t>(frame_type_address);
  if (StackFrame::IsTypeMarker(marker) &&
      StackFrame::MarkerToType(marker) == StackFrame::STUB) {
    // Bytecode handler built a frame.
    return false;
  }
  return true;
}

StackFrameIteratorForProfiler::StackFrameIteratorForProfiler(
    Isolate* isolate, Address pc, Address fp, Address sp, Address lr,
    Address js_entry_sp)
    : StackFrameIteratorBase(isolate),
      low_bound_(sp),
      high_bound_(js_entry_sp),
      top_frame_type_(StackFrame::NO_FRAME_TYPE),
      external_callback_scope_(isolate->external_callback_scope()),
      top_link_register_(lr)
#if V8_ENABLE_WEBASSEMBLY
      ,
      wasm_stacks_(isolate->wasm_stacks())
#endif
{
  if (!isolate->isolate_data()->stack_is_iterable()) {
    // The stack is not iterable in a short time interval during deoptimization.
    // See also: ExternalReference::stack_is_iterable_address.
    DCHECK(done());
    return;
  }

  // For Advance below, we need frame_ to be set; and that only happens if the
  // type is not NO_FRAME_TYPE.
  // TODO(jgruber): Clean this up.
  static constexpr StackFrame::Type kTypeForAdvance = StackFrame::TURBOFAN_JS;

  StackFrame::State state;
  state.is_profiler_entry_frame = true;
  StackFrame::Type type;
  ThreadLocalTop* const top = isolate->thread_local_top();
  bool advance_frame = true;
  const Address fast_c_fp = isolate->isolate_data()->fast_c_call_caller_fp();
  if (fast_c_fp != kNullAddress) {
    // 'Fast C calls' are a special type of C call where we call directly from
    // JS to C without an exit frame inbetween. The CEntryStub is responsible
    // for setting Isolate::c_entry_fp, meaning that it won't be set for fast C
    // calls. To keep the stack iterable, we store the FP and PC of the caller
    // of the fast C call on the isolate. This is guaranteed to be the topmost
    // JS frame, because fast C calls cannot call back into JS. We start
    // iterating the stack from this topmost JS frame.
    DCHECK_NE(kNullAddress, isolate->isolate_data()->fast_c_call_caller_pc());
    state.fp = fast_c_fp;
    state.sp = sp;
    state.pc_address = reinterpret_cast<Address*>(
        isolate->isolate_data()->fast_c_call_caller_pc_address());

    // ComputeStackFrameType will read both kContextOffset and
    // kFunctionOffset, we check only that kFunctionOffset is within the stack
    // bounds and do a compile time check that kContextOffset slot is pushed on
    // the stack before kFunctionOffset.
    static_assert(StandardFrameConstants::kFunctionOffset <
                  StandardFrameConstants::kContextOffset);
    if (IsValidStackAddress(state.fp +
                            StandardFrameConstants::kFunctionOffset)) {
      type = ComputeStackFrameType(&state);
      if (IsValidFrameType(type)) {
        top_frame_type_ = type;
        advance_frame = false;
      }
    } else {
      // Cannot determine the actual type; the frame will be skipped below.
      type = kTypeForAdvance;
    }
  } else if (IsValidTop(top)) {
    type = ExitFrame::GetStateForFramePointer(Isolate::c_entry_fp(top), &state);
    top_frame_type_ = type;
  } else if (IsValidStackAddress(fp)) {
    DCHECK_NE(fp, kNullAddress);
    state.fp = fp;
    state.sp = sp;
    state.pc_address =
        StackFrame::ResolveReturnAddressLocation(reinterpret_cast<Address*>(
            fp + StandardFrameConstants::kCallerPCOffset));

    bool can_lookup_frame_type =
        // Ensure frame structure is not broken, otherwise it doesn't make
        // sense to try to detect a frame type.
        (sp < fp) &&
        // Ensure there is a context/frame type value in the frame.
        (fp - sp) >= TypedFrameConstants::kFixedFrameSizeFromFp;

    // If the current PC is in a bytecode handler, the top stack frame isn't
    // the bytecode handler's frame and the top of stack or link register is a
    // return address into the interpreter entry trampoline, then we are likely
    // in a bytecode handler with elided frame. In that case, set the PC
    // properly and make sure we do not drop the frame.
    bool is_no_frame_bytecode_handler = false;
    if (can_lookup_frame_type && IsNoFrameBytecodeHandlerPc(isolate, pc, fp)) {
      Address* top_location = nullptr;
      if (top_link_register_) {
        top_location = &top_link_register_;
      } else if (IsValidStackAddress(sp)) {
        MSAN_MEMORY_IS_INITIALIZED(sp, kSystemPointerSize);
        top_location = reinterpret_cast<Address*>(sp);
      }

      std::optional<bool> is_interpreter_frame_pc =
          IsInterpreterFramePc(isolate, *top_location, &state);
      // Since we're in a signal handler, the pc lookup might not be possible
      // since the required locks are taken by the same thread.
      if (!is_interpreter_frame_pc.has_value()) {
        can_lookup_frame_type = false;
      } else if (is_interpreter_frame_pc.value()) {
        state.pc_address = top_location;
        is_no_frame_bytecode_handler = true;
        advance_frame = false;
      }
    }

    // ComputeStackFrameType will read both kContextOffset and
    // kFunctionOffset, we check only that kFunctionOffset is within the stack
    // bounds and do a compile time check that kContextOffset slot is pushed on
    // the stack before kFunctionOffset.
    static_assert(StandardFrameConstants::kFunctionOffset <
                  StandardFrameConstants::kContextOffset);
    Address function_slot = fp + StandardFrameConstants::kFunctionOffset;
    if (!can_lookup_frame_type) {
      type = StackFrame::NO_FRAME_TYPE;
    } else if (IsValidStackAddress(function_slot)) {
      if (is_no_frame_bytecode_handler) {
        type = StackFrame::INTERPRETED;
      } else {
        type = ComputeStackFrameType(&state);
      }
      top_frame_type_ = type;
    } else {
      // Cannot determine the actual type; the frame will be skipped below.
      type = kTypeForAdvance;
    }
  } else {
    // Not iterable.
    DCHECK(done());
    return;
  }

  SetNewFrame(type, &state);
  if (advance_frame && !done()) {
    Advance();
  }
}

bool StackFrameIteratorForProfiler::IsValidTop(ThreadLocalTop* top) const {
  Address c_entry_fp = Isolate::c_entry_fp(top);
  if (!IsValidExitFrame(c_entry_fp)) return false;
  // There should be at least one JS_ENTRY stack handler.
  Address handler = Isolate::handler(top);
  if (handler == kNullAddress) return false;
  // Check that there are no js frames on top of the native frames.
  return c_entry_fp < handler;
}

void StackFrameIteratorForProfiler::AdvanceOneFrame() {
  DCHECK(!done());
  StackFrame* last_frame = frame_;
  Address last_sp = last_frame->sp(), last_fp = last_frame->fp();

  // Before advancing to the next stack frame, perform pointer validity tests.
  if (!IsValidState(last_frame->state_) ||
      !HasValidExitIfEntryFrame(last_frame)) {
    frame_ = nullptr;
    return;
  }

  // Advance to the previous frame, and perform pointer validity tests there
  // too.
  StackFrame::State state;
  last_frame->ComputeCallerState(&state);
  if (!IsValidState(state)) {
    frame_ = nullptr;
    return;
  }

  StackFrame::Type type = ComputeStackFrameType(&state);
  SetNewFrame(type, &state);
  if (!frame_) return;

  // Check that we have actually moved to the previous frame in the stack.
  if (frame_->sp() <= last_sp || frame_->fp() <= last_fp) {
    frame_ = nullptr;
  }
}

bool StackFrameIteratorForProfiler::IsValidState(
    const StackFrame::State& state) const {
  return IsValidStackAddress(state.sp) && IsValidStackAddress(state.fp);
}

bool StackFrameIteratorForProfiler::HasValidExitIfEntryFrame(
    const StackFrame* frame) const {
  if (!frame->is_entry() && !frame->is_construct_entry()) return true;

  // See EntryFrame::GetCallerState. It computes the caller FP address
  // and calls ExitFrame::GetStateForFramePointer on it. We need to be
  // sure that caller FP address is valid.
  Address next_exit_frame_fp_address =
      frame->fp() + EntryFrameConstants::kNextExitFrameFPOffset;
  // Profiling tick might be triggered in the middle of JSEntry builtin
  // before the next_exit_frame_fp value is initialized. IsValidExitFrame()
  // is able to deal with such a case, so just suppress the MSan warning.
  MSAN_MEMORY_IS_INITIALIZED(next_exit_frame_fp_address, kSystemPointerSize);
  Address next_exit_frame_fp = Memory<Address>(next_exit_frame_fp_address);
  return IsValidExitFrame(next_exit_frame_fp);
}

bool StackFrameIteratorForProfiler::IsValidExitFrame(Address fp) const {
  if (!IsValidStackAddress(fp)) return false;
  Address sp = ExitFrame::ComputeStackPointer(fp);
  if (!IsValidStackAddress(sp)) return false;
  StackFrame::State state;
  ExitFrame::FillState(fp, sp, &state);
  MSAN_MEMORY_IS_INITIALIZED(state.pc_address, sizeof(state.pc_address));
  return *state.pc_address != kNullAddress;
}

void StackFrameIteratorForProfiler::Advance() {
  while (true) {
    AdvanceOneFrame();
    if (done()) break;
    ExternalCallbackScope* last_callback_scope = nullptr;
    while (external_callback_scope_ != nullptr &&
           external_callback_scope_->JSStackComparableAddress() <
               frame_->fp()) {
      // As long as the setup of a frame is not atomic, we may happen to be
      // in an interval where an ExternalCallbackScope is already created,
      // but the frame is not yet entered. So we are actually observing
      // the previous frame.
      // Skip all the ExternalCallbackScope's that are below the current fp.
      last_callback_scope = external_callback_scope_;
      external_callback_scope_ = external_callback_scope_->previous();
    }
    if (frame_->is_javascript()) break;
#if V8_ENABLE_WEBASSEMBLY
    if (frame_->is_wasm() || frame_->is_wasm_to_js() ||
        frame_->is_js_to_wasm()) {
      break;
    }
#endif  // V8_ENABLE_WEBASSEMBLY
    if (frame_->is_exit() || frame_->is_builtin_exit() ||
        frame_->is_api_accessor_exit() || frame_->is_api_callback_exit()) {
      // Some of the EXIT frames may have ExternalCallbackScope allocated on
      // top of them. In that case the scope corresponds to the first EXIT
      // frame beneath it. There may be other EXIT frames on top of the
      // ExternalCallbackScope, just skip them as we cannot collect any useful
      // information about them.
      if (last_callback_scope) {
        frame_->state_.pc_address =
            last_callback_scope->callback_entrypoint_address();
      }
      break;
    }
  }
}

StackFrameIteratorForProfilerForTesting::
    StackFrameIteratorForProfilerForTesting(Isolate* isolate, Address pc,
                                            Address fp, Address sp, Address lr,
                                            Address js_entry_sp)
    : StackFrameIteratorForProfiler(isolate, pc, fp, sp, lr, js_entry_sp) {}

void StackFrameIteratorForProfilerForTesting::Advance() {
  StackFrameIteratorForProfiler::Advance();
}

// -------------------------------------------------------------------------

namespace {

std::optional<Tagged<GcSafeCode>> GetContainingCode(Isolate* isolate,
                                                    Address pc) {
  return isolate->inner_pointer_to_code_cache()->GetCacheEntry(pc)->code;
}

}  // namespace

Tagged<GcSafeCode> StackFrame::GcSafeLookupCode() const {
  return GcSafeLookupCodeAndOffset().first;
}

std::pair<Tagged<GcSafeCode>, int> StackFrame::GcSafeLookupCodeAndOffset()
    const {
  const Address pc = maybe_unauthenticated_pc();
  std::optional<Tagged<GcSafeCode>> result = GetContainingCode(isolate(), pc);
  return {result.value(),
          result.value()->GetOffsetFromInstructionStart(isolate(), pc)};
}

Tagged<Code> StackFrame::LookupCode() const {
  DCHECK_NE(isolate()->heap()->gc_state(), Heap::MARK_COMPACT);
  return GcSafeLookupCode()->UnsafeCastToCode();
}

std::pair<Tagged<Code>, int> StackFrame::LookupCodeAndOffset() const {
  DCHECK_NE(isolate()->heap()->gc_state(), Heap::MARK_COMPACT);
  auto gc_safe_pair = GcSafeLookupCodeAndOffset();
  return {gc_safe_pair.first->UnsafeCastToCode(), gc_safe_pair.second};
}

void StackFrame::IteratePc(RootVisitor* v, Address* constant_pool_address,
                           Tagged<GcSafeCode> holder) const {
  const Address old_pc = maybe_unauthenticated_pc();
  DCHECK_GE(old_pc, holder->InstructionStart(isolate(), old_pc));
  DCHECK_LT(old_pc, holder->InstructionEnd(isolate(), old_pc));

  // Keep the old pc offset before visiting the code since we need it to
  // calculate the new pc after a potential InstructionStream move.
  const uintptr_t pc_offset_from_start = old_pc - holder->instruction_start();

  // Visit.
  Tagged<GcSafeCode> visited_holder = holder;
  PtrComprCageBase code_cage_base{isolate()->code_cage_base()};
  const Tagged<Object> old_istream =
      holder->raw_instruction_stream(code_cage_base);
  Tagged<Object> visited_istream = old_istream;
  v->VisitRunningCode(FullObjectSlot{&visited_holder},
                      FullObjectSlot{&visited_istream});
  if (visited_istream == old_istream) {
    // Note this covers two important cases:
    // 1. the associated InstructionStream object did not move, and
    // 2. `holder` is an embedded builtin and has no InstructionStream.
    return;
  }

  DCHECK(visited_holder->has_instruction_stream());
  // We can only relocate the InstructionStream object when we are able to patch
  // the return address. We only know the location of the return address if the
  // stack pointer is known. This means we cannot relocate InstructionStreams
  // for fast c calls.
  DCHECK(!InFastCCall());
  // Currently we turn off code space compaction fully when performing a GC in a
  // fast C call.
  DCHECK(!isolate()->InFastCCall());

  Tagged<InstructionStream> istream =
      UncheckedCast<InstructionStream>(visited_istream);
  const Address new_pc = istream->instruction_start() + pc_offset_from_start;
  // TODO(v8:10026): avoid replacing a signed pointer.
  PointerAuthentication::ReplacePC(pc_address(), new_pc, kSystemPointerSize);
  if (V8_EMBEDDED_CONSTANT_POOL_BOOL && constant_pool_address != nullptr) {
    *constant_pool_address = istream->constant_pool();
  }
}

void StackFrame::SetReturnAddressLocationResolver(
    ReturnAddressLocationResolver resolver) {
  DCHECK_NULL(return_address_location_resolver_);
  return_address_location_resolver_ = resolver;
}

namespace {

StackFrame::Type ComputeBuiltinFrameType(Tagged<GcSafeCode> code) {
  if (code->is_interpreter_trampoline_builtin() ||
      code->is_baseline_trampoline_builtin()) {
    // Frames for baseline entry trampolines on the stack are still interpreted
    // frames.
    return StackFrame::INTERPRETED;
  } else if (code->is_baseline_leave_frame_builtin()) {
    return StackFrame::BASELINE;
  } else if (code->is_turbofanned()) {
    // TODO(bmeurer): We treat frames for BUILTIN Code objects as
    // OptimizedJSFrame for now (all the builtins with JavaScript linkage are
    // actually generated with TurboFan currently, so this is sound).
    return StackFrame::TURBOFAN_JS;
  }
  return StackFrame::BUILTIN;
}

StackFrame::Type SafeStackFrameType(StackFrame::Type candidate) {
  DCHECK_LE(static_cast<uintptr_t>(candidate), StackFrame::NUMBER_OF_TYPES);
  switch (candidate) {
    case StackFrame::API_ACCESSOR_EXIT:
    case StackFrame::API_CALLBACK_EXIT:
    case StackFrame::BUILTIN_CONTINUATION:
    case StackFrame::BUILTIN_EXIT:
    case StackFrame::CONSTRUCT:
    case StackFrame::FAST_CONSTRUCT:
    case StackFrame::CONSTRUCT_ENTRY:
    case StackFrame::ENTRY:
    case StackFrame::EXIT:
    case StackFrame::INTERNAL:
    case StackFrame::IRREGEXP:
    case StackFrame::JAVASCRIPT_BUILTIN_CONTINUATION:
    case StackFrame::JAVASCRIPT_BUILTIN_CONTINUATION_WITH_CATCH:
    case StackFrame::STUB:
      return candidate;

#if V8_ENABLE_WEBASSEMBLY
    case StackFrame::JS_TO_WASM:
    case StackFrame::STACK_SWITCH:
    case StackFrame::WASM:
    case StackFrame::WASM_DEBUG_BREAK:
    case StackFrame::WASM_EXIT:
    case StackFrame::WASM_LIFTOFF_SETUP:
    case StackFrame::WASM_TO_JS:
    case StackFrame::WASM_SEGMENT_START:
#if V8_ENABLE_DRUMBRAKE
    case StackFrame::C_WASM_ENTRY:
    case StackFrame::WASM_INTERPRETER_ENTRY:
#endif  // V8_ENABLE_DRUMBRAKE
      return candidate;
#endif  // V8_ENABLE_WEBASSEMBLY

    // Any other marker value is likely to be a bogus stack frame when being
    // called from the profiler (in particular, JavaScript frames, including
    // interpreted frames, should never have a StackFrame::Type marker).
    // Consider these frames "native".
    // TODO(jgruber): For the StackFrameIterator, I'm not sure this fallback
    // makes sense. Shouldn't we know how to handle all frames we encounter
    // there?
    case StackFrame::BASELINE:
    case StackFrame::BUILTIN:
    case StackFrame::INTERPRETED:
    case StackFrame::MAGLEV:
    case StackFrame::MANUAL:
    case StackFrame::NATIVE:
    case StackFrame::NO_FRAME_TYPE:
    case StackFrame::NUMBER_OF_TYPES:
    case StackFrame::TURBOFAN_JS:
    case StackFrame::TURBOFAN_STUB_WITH_CONTEXT:
#if V8_ENABLE_WEBASSEMBLY
#if !V8_ENABLE_DRUMBRAKE
    case StackFrame::C_WASM_ENTRY:
#endif  // !V8_ENABLE_DRUMBRAKE
    case StackFrame::WASM_TO_JS_FUNCTION:
#endif  // V8_ENABLE_WEBASSEMBLY
      return StackFrame::NATIVE;
  }
  UNREACHABLE();
}

}  // namespace

StackFrame::Type StackFrameIterator::ComputeStackFrameType(
    StackFrame::State* state) const {
#if V8_ENABLE_WEBASSEMBLY
  if (state->fp == kNullAddress && first_stack_only_) {
    DCHECK(!isolate_->wasm_stacks().empty());  // I.e., JSPI active
    return StackFrame::NO_FRAME_TYPE;
  }
#endif

  const Address pc = StackFrame::ReadPC(state->pc_address);

#if V8_ENABLE_WEBASSEMBLY
  // If the {pc} does not point into WebAssembly code we can rely on the
  // returned {wasm_code} to be null and fall back to {GetContainingCode}.
  if (wasm::WasmCode* wasm_code =
          wasm::GetWasmCodeManager()->LookupCode(isolate(), pc)) {
    switch (wasm_code->kind()) {
      case wasm::WasmCode::kWasmFunction:
        return StackFrame::WASM;
      case wasm::WasmCode::kWasmToCapiWrapper:
        return StackFrame::WASM_EXIT;
      case wasm::WasmCode::kWasmToJsWrapper:
        return StackFrame::WASM_TO_JS;
#if V8_ENABLE_DRUMBRAKE
      case wasm::WasmCode::kInterpreterEntry:
        return StackFrame::WASM_INTERPRETER_ENTRY;
#endif  // V8_ENABLE_DRUMBRAKE
      default:
        UNREACHABLE();
    }
  }
#endif  // V8_ENABLE_WEBASSEMBLY

  // Look up the code object to figure out the type of the stack frame.
  std::optional<Tagged<GcSafeCode>> lookup_result =
      GetContainingCode(isolate(), pc);
  if (!lookup_result.has_value()) return StackFrame::NATIVE;

  MSAN_MEMORY_IS_INITIALIZED(
      state->fp + CommonFrameConstants::kContextOrFrameTypeOffset,
      kSystemPointerSize);
  const intptr_t marker = Memory<intptr_t>(
      state->fp + CommonFrameConstants::kContextOrFrameTypeOffset);
  switch (lookup_result.value()->kind()) {
    case CodeKind::BUILTIN: {
      if (StackFrame::IsTypeMarker(marker)) break;
      return ComputeBuiltinFrameType(lookup_result.value());
    }
    case CodeKind::BASELINE:
      return StackFrame::BASELINE;
    case CodeKind::MAGLEV:
      if (StackFrame::IsTypeMarker(marker)) {
        // An INTERNAL frame can be set up with an associated Maglev code
        // object when calling into runtime to handle tiering. In this case,
        // all stack slots are tagged pointers and should be visited through
        // the usual logic.
        DCHECK_EQ(StackFrame::MarkerToType(marker), StackFrame::INTERNAL);
        return StackFrame::INTERNAL;
      }
      return StackFrame::MAGLEV;
    case CodeKind::TURBOFAN_JS:
      return StackFrame::TURBOFAN_JS;
#if V8_ENABLE_WEBASSEMBLY
    case CodeKind::JS_TO_WASM_FUNCTION:
      if (lookup_result.value()->builtin_id() == Builtin::kJSToWasmWrapperAsm) {
        return StackFrame::JS_TO_WASM;
      }
#if V8_ENABLE_DRUMBRAKE
      if (lookup_result.value()->builtin_id() ==
          Builtin::kGenericJSToWasmInterpreterWrapper) {
        return StackFrame::JS_TO_WASM;
      }
#endif  // V8_ENABLE_DRUMBRAKE
      return StackFrame::TURBOFAN_STUB_WITH_CONTEXT;
    case CodeKind::C_WASM_ENTRY:
      return StackFrame::C_WASM_ENTRY;
    case CodeKind::WASM_TO_JS_FUNCTION:
      return StackFrame::WASM_TO_JS_FUNCTION;
    case CodeKind::WASM_FUNCTION:
    case CodeKind::WASM_TO_CAPI_FUNCTION:
      // These never appear as on-heap Code objects.
      UNREACHABLE();
#else
    case CodeKind::C_WASM_ENTRY:
    case CodeKind::JS_TO_WASM_FUNCTION:
    case CodeKind::WASM_FUNCTION:
    case CodeKind::WASM_TO_CAPI_FUNCTION:
    case CodeKind::WASM_TO_JS_FUNCTION:
      UNREACHABLE();
#endif  // V8_ENABLE_WEBASSEMBLY
    case CodeKind::BYTECODE_HANDLER:
    case CodeKind::FOR_TESTING:
    case CodeKind::REGEXP:
    case CodeKind::INTERPRETED_FUNCTION:
      // Fall back to the marker.
      break;
  }

  return SafeStackFrameType(StackFrame::MarkerToType(marker));
}

StackFrame::Type StackFrameIteratorForProfiler::ComputeStackFrameType(
    StackFrame::State* state) const {
#if V8_ENABLE_WEBASSEMBLY
  if (state->fp == kNullAddress) {
    DCHECK(!isolate_->wasm_stacks().empty());  // I.e., JSPI active
    return StackFrame::NO_FRAME_TYPE;
  }
#endif

  // We use unauthenticated_pc because it may come from
  // fast_c_call_caller_pc_address, for which authentication does not work.
  const Address pc = StackFrame::unauthenticated_pc(state->pc_address);
#if V8_ENABLE_WEBASSEMBLY
  Tagged<Code> wrapper =
      isolate()->builtins()->code(Builtin::kWasmToJsWrapperCSA);
  if (pc >= wrapper->instruction_start() && pc <= wrapper->instruction_end()) {
    return StackFrame::WASM_TO_JS;
  }
#endif  // V8_ENABLE_WEBASSEMBLY

  MSAN_MEMORY_IS_INITIALIZED(
      state->fp + CommonFrameConstants::kContextOrFrameTypeOffset,
      kSystemPointerSize);
  const intptr_t marker = Memory<intptr_t>(
      state->fp + CommonFrameConstants::kContextOrFrameTypeOffset);
  if (StackFrame::IsTypeMarker(marker)) {
    return SafeStackFrameType(StackFrame::MarkerToType(marker));
  }

  MSAN_MEMORY_IS_INITIALIZED(
      state->fp + StandardFrameConstants::kFunctionOffset, kSystemPointerSize);
  Tagged<Object> maybe_function = Tagged<Object>(
      Memory<Address>(state->fp + StandardFrameConstants::kFunctionOffset));
  if (IsSmi(maybe_function)) {
    return StackFrame::NATIVE;
  }

  std::optional<bool> is_interpreter_frame =
      IsInterpreterFramePc(isolate(), pc, state);

  // We might not be able to lookup the frame type since we're inside a signal
  // handler and the required locks are taken.
  if (!is_interpreter_frame.has_value()) {
    return StackFrame::NO_FRAME_TYPE;
  }

  if (is_interpreter_frame.value()) {
    return StackFrame::INTERPRETED;
  }

  return StackFrame::TURBOFAN_JS;
}

StackFrame::Type StackFrame::GetCallerState(State* state) const {
  ComputeCallerState(state);
  return iterator_->ComputeStackFrameType(state);
}

Address CommonFrame::GetCallerStackPointer() const {
  return fp() + CommonFrameConstants::kCallerSPOffset;
}

void NativeFrame::ComputeCallerState(State* state) const {
  state->sp = caller_sp();
  state->fp = Memory<Address>(fp() + CommonFrameConstants::kCallerFPOffset);
  state->pc_address = ResolveReturnAddressLocation(
      reinterpret_cast<Address*>(fp() + CommonFrameConstants::kCallerPCOffset));
  state->callee_pc = kNullAddress;
  state->constant_pool_address = nullptr;
}

Tagged<HeapObject> EntryFrame::unchecked_code() const {
  return isolate()->builtins()->code(Builtin::kJSEntry);
}

void EntryFrame::ComputeCallerState(State* state) const {
  GetCallerState(state);
}

StackFrame::Type EntryFrame::GetCallerState(State* state) const {
  const Address fast_c_call_caller_fp =
      Memory<Address>(fp() + EntryFrameConstants::kNextFastCallFrameFPOffset);
  if (fast_c_call_caller_fp != kNullAddress) {
    Address caller_pc_address =
        fp() + EntryFrameConstants::kNextFastCallFramePCOffset;
    Address caller_pc = Memory<Address>(caller_pc_address);
    return GetStateForFastCCallCallerFP(isolate(), fast_c_call_caller_fp,
                                        caller_pc, caller_pc_address, state);
  }
  Address next_exit_frame_fp =
      Memory<Address>(fp() + EntryFrameConstants::kNextExitFrameFPOffset);
  return ExitFrame::GetStateForFramePointer(next_exit_frame_fp, state);
}

#if V8_ENABLE_WEBASSEMBLY
StackFrame::Type CWasmEntryFrame::GetCallerState(State* state) const {
  const int offset = CWasmEntryFrameConstants::kCEntryFPOffset;
  Address fp = Memory<Address>(this->fp() + offset);
  return ExitFrame::GetStateForFramePointer(fp, state);
}

#if V8_ENABLE_DRUMBRAKE
void CWasmEntryFrame::Iterate(RootVisitor* v) const {
  if (!v8_flags.wasm_jitless) {
    StubFrame::Iterate(v);
  }
}
#endif  // V8_ENABLE_DRUMBRAKE

#endif  // V8_ENABLE_WEBASSEMBLY

Tagged<HeapObject> ConstructEntryFrame::unchecked_code() const {
  return isolate()->builtins()->code(Builtin::kJSConstructEntry);
}

void ExitFrame::ComputeCallerState(State* state) const {
  // Set up the caller state.
  state->sp = caller_sp();
  state->fp = Memory<Address>(fp() + ExitFrameConstants::kCallerFPOffset);
  state->pc_address = ResolveReturnAddressLocation(
      reinterpret_cast<Address*>(fp() + ExitFrameConstants::kCallerPCOffset));
  state->callee_pc = kNullAddress;
  if (V8_EMBEDDED_CONSTANT_POOL_BOOL) {
    state->constant_pool_address = reinterpret_cast<Address*>(
        fp() + ExitFrameConstants::kConstantPoolOffset);
  }
}

void ExitFrame::Iterate(RootVisitor* v) const {
  // The arguments are traversed as part of the expression stack of
  // the calling frame.
  IteratePc(v, constant_pool_address(), GcSafeLookupCode());
}

StackFrame::Type ExitFrame::GetStateForFramePointer(Address fp, State* state) {
  if (fp == 0) return NO_FRAME_TYPE;
  StackFrame::Type type = ComputeFrameType(fp);
#if V8_ENABLE_WEBASSEMBLY
  Address sp = type == WASM_EXIT ? WasmExitFrame::ComputeStackPointer(fp)
                                 : ExitFrame::ComputeStackPointer(fp);
#else
  Address sp = ExitFrame::ComputeStackPointer(fp);
#endif  // V8_ENABLE_WEBASSEMBLY
  FillState(fp, sp, state);
  DCHECK_NE(*state->pc_address, kNullAddress);
  return type;
}

StackFrame::Type ExitFrame::ComputeFrameType(Address fp) {
  // Distinguish between different exit frame types.
  // Default to EXIT in all hairy cases (e.g., when called from profiler).
  const int offset = ExitFrameConstants::kFrameTypeOffset;
  Tagged<Object> marker(Memory<Address>(fp + offset));

  if (!IsSmi(marker)) {
    return EXIT;
  }

  intptr_t marker_int = base::bit_cast<intptr_t>(marker);

  StackFrame::Type frame_type = static_cast<StackFrame::Type>(marker_int >> 1);
  switch (frame_type) {
    case BUILTIN_EXIT:
    case API_ACCESSOR_EXIT:
    case API_CALLBACK_EXIT:
#if V8_ENABLE_WEBASSEMBLY
    case WASM_EXIT:
    case STACK_SWITCH:
#endif  // V8_ENABLE_WEBASSEMBLY
      return frame_type;
    default:
      return EXIT;
  }
}

Address ExitFrame::ComputeStackPointer(Address fp) {
  MSAN_MEMORY_IS_INITIALIZED(fp + ExitFrameConstants::kSPOffset,
                             kSystemPointerSize);
  return Memory<Address>(fp + ExitFrameConstants::kSPOffset);
}

#if V8_ENABLE_WEBASSEMBLY
Address WasmExitFrame::ComputeStackPointer(Address fp) {
  // For WASM_EXIT frames, {sp} is only needed for finding the PC slot,
  // everything else is handled via safepoint information.
  Address sp = fp + WasmExitFrameConstants::kWasmInstanceDataOffset;
  DCHECK_EQ(sp - 1 * kPCOnStackSize,
            fp + WasmExitFrameConstants::kCallingPCOffset);
  return sp;
}
#endif  // V8_ENABLE_WEBASSEMBLY

void ExitFrame::FillState(Address fp, Address sp, State* state) {
  state->sp = sp;
  state->fp = fp;
  state->pc_address = ResolveReturnAddressLocation(
      reinterpret_cast<Address*>(sp - 1 * kPCOnStackSize));
  state->callee_pc = kNullAddress;
  // The constant pool recorded in the exit frame is not associated
  // with the pc in this state (the return address into a C entry
  // stub).  ComputeCallerState will retrieve the constant pool
  // together with the associated caller pc.
  state->constant_pool_address = nullptr;
}

void BuiltinExitFrame::Summarize(std::vector<FrameSummary>* frames) const {
  DCHECK(frames->empty());
  DirectHandle<FixedArray> parameters = GetParameters();
  DisallowGarbageCollection no_gc;
  Tagged<Code> code;
  int code_offset = -1;
  std::tie(code, code_offset) = LookupCodeAndOffset();
  FrameSummary::JavaScriptFrameSummary summary(
      isolate(), receiver(), function(), Cast<AbstractCode>(code), code_offset,
      IsConstructor(), *parameters);
  frames->push_back(summary);
}

Tagged<JSFunction> BuiltinExitFrame::function() const {
  return Cast<JSFunction>(target_slot_object());
}

Tagged<Object> BuiltinExitFrame::receiver() const {
  return receiver_slot_object();
}

Tagged<Object> BuiltinExitFrame::GetParameter(int i) const {
  DCHECK(i >= 0 && i < ComputeParametersCount());
  int offset =
      BuiltinExitFrameConstants::kFirstArgumentOffset + i * kSystemPointerSize;
  return Tagged<Object>(Memory<Address>(fp() + offset));
}

int BuiltinExitFrame::ComputeParametersCount() const {
  Tagged<Object> argc_slot = argc_slot_object();
  DCHECK(IsSmi(argc_slot));
  // Argc also counts the receiver and extra arguments for BuiltinExitFrame
  // (target, new target and argc itself), therefore the real argument count
  // has to be adjusted.
  int argc = Smi::ToInt(argc_slot) -
             BuiltinExitFrameConstants::kNumExtraArgsWithReceiver;
  DCHECK_GE(argc, 0);
  return argc;
}

Handle<FixedArray> BuiltinExitFrame::GetParameters() const {
  if (V8_LIKELY(!v8_flags.detailed_error_stack_trace)) {
    return isolate()->factory()->empty_fixed_array();
  }
  int param_count = ComputeParametersCount();
  auto parameters = isolate()->factory()->NewFixedArray(param_count);
  for (int i = 0; i < param_count; i++) {
    parameters->set(i, GetParameter(i));
  }
  return parameters;
}

bool BuiltinExitFrame::IsConstructor() const {
  return !IsUndefined(new_target_slot_object(), isolate());
}

// Ensure layout of v8::FunctionCallbackInfo is in sync with
// ApiCallbackExitFrameConstants.
namespace ensure_layout {
using FC = ApiCallbackExitFrameConstants;
using FCA = FunctionCallbackArguments;
static_assert(FC::kFunctionCallbackInfoContextIndex == FCA::kContextIndex);
static_assert(FC::kFunctionCallbackInfoReturnValueIndex ==
              FCA::kReturnValueIndex);
static_assert(FC::kFunctionCallbackInfoTargetIndex == FCA::kTargetIndex);
static_assert(FC::kFunctionCallbackInfoNewTargetIndex == FCA::kNewTargetIndex);
static_assert(FC::kFunctionCallbackInfoArgsLength == FCA::kArgsLength);
}  // namespace ensure_layout

Handle<JSFunction> ApiCallbackExitFrame::GetFunction() const {
  Tagged<HeapObject> maybe_function = target();
  if (IsJSFunction(maybe_function)) {
    return Handle<JSFunction>(target_slot().location());
  }
  DCHECK(IsFunctionTemplateInfo(maybe_function));
  Handle<FunctionTemplateInfo> function_template_info(
      Cast<FunctionTemplateInfo>(maybe_function), isolate());

  // Instantiate function for the correct context.
  DCHECK(IsContext(context()));
  Handle<NativeContext> native_context(
      Cast<Context>(context())->native_context(), isolate());

  Handle<JSFunction> function =
      ApiNatives::InstantiateFunction(isolate(), native_context,
                                      function_template_info)
          .ToHandleChecked();

  set_target(*function);
  return function;
}

Handle<FunctionTemplateInfo> ApiCallbackExitFrame::GetFunctionTemplateInfo()
    const {
  Tagged<HeapObject> maybe_function = target();
  if (IsJSFunction(maybe_function)) {
    Tagged<SharedFunctionInfo> shared_info =
        Cast<JSFunction>(maybe_function)->shared();
    DCHECK(shared_info->IsApiFunction());
    return handle(shared_info->api_func_data(), isolate());
  }
  DCHECK(IsFunctionTemplateInfo(maybe_function));
  return handle(Cast<FunctionTemplateInfo>(maybe_function), isolate());
}

Handle<FixedArray> ApiCallbackExitFrame::GetParameters() const {
  if (V8_LIKELY(!v8_flags.detailed_error_stack_trace)) {
    return isolate()->factory()->empty_fixed_array();
  }
  int param_count = ComputeParametersCount();
  auto parameters = isolate()->factory()->NewFixedArray(param_count);
  for (int i = 0; i < param_count; i++) {
    parameters->set(i, GetParameter(i));
  }
  return parameters;
}

void ApiCallbackExitFrame::Summarize(std::vector<FrameSummary>* frames) const {
  DCHECK(frames->empty());
  DirectHandle<FixedArray> parameters = GetParameters();
  DirectHandle<JSFunction> function = GetFunction();
  DisallowGarbageCollection no_gc;
  Tagged<Code> code;
  int code_offset = -1;
  std::tie(code, code_offset) = LookupCodeAndOffset();
  FrameSummary::JavaScriptFrameSummary summary(
      isolate(), receiver(), *function, Cast<AbstractCode>(code), code_offset,
      IsConstructor(), *parameters);
  frames->push_back(summary);
}

// Ensure layout of v8::PropertyCallbackInfo is in sync with
// ApiAccessorExitFrameConstants.
static_assert(
    ApiAccessorExitFrameConstants::kPropertyCallbackInfoPropertyKeyIndex ==
    PropertyCallbackArguments::kPropertyKeyIndex);
static_assert(
    ApiAccessorExitFrameConstants::kPropertyCallbackInfoReturnValueIndex ==
    PropertyCallbackArguments::kReturnValueIndex);
static_assert(
    ApiAccessorExitFrameConstants::kPropertyCallbackInfoReceiverIndex ==
    PropertyCallbackArguments::kThisIndex);
static_assert(ApiAccessorExitFrameConstants::kPropertyCallbackInfoHolderIndex ==
              PropertyCallbackArguments::kHolderIndex);
static_assert(ApiAccessorExitFrameConstants::kPropertyCallbackInfoArgsLength ==
              PropertyCallbackArguments::kArgsLength);

void ApiAccessorExitFrame::Summarize(std::vector<FrameSummary>* frames) const {
  // This frame is not supposed to appear in exception stack traces.
  DCHECK(IsName(property_name()));
  DCHECK(IsJSReceiver(receiver()));
  DCHECK(IsJSReceiver(holder()));
}

namespace {
void PrintIndex(StringStream* accumulator, StackFrame::PrintMode mode,
                int index) {
  accumulator->Add((mode == StackFrame::OVERVIEW) ? "%5d: " : "[%d]: ", index);
}

const char* StringForStackFrameType(StackFrame::Type type) {
  switch (type) {
#define CASE(value, name) \
  case StackFrame::value: \
    return #name;
    STACK_FRAME_TYPE_LIST(CASE)
#undef CASE
    case StackFrame::NO_FRAME_TYPE:
      return "NoFrameType";
    default:
      UNREACHABLE();
  }
}
}  // namespace

void StackFrame::Print(StringStream* accumulator, PrintMode mode,
                       int index) const {
  DisallowGarbageCollection no_gc;
  PrintIndex(accumulator, mode, index);
  accumulator->Add(StringForStackFrameType(type()));
  accumulator->Add(" [pc: %p]\n",
                   reinterpret_cast<void*>(maybe_unauthenticated_pc()));
}

void BuiltinExitFrame::Print(StringStream* accumulator, PrintMode mode,
                             int index) const {
  DisallowGarbageCollection no_gc;
  Tagged<Object> receiver = this->receiver();
  Tagged<JSFunction> function = this->function();
  Tagged<SharedFunctionInfo> sfi = function->shared();

  accumulator->PrintSecurityTokenIfChanged(function);
  PrintIndex(accumulator, mode, index);
  accumulator->Add("BuiltinExitFrame ");
  if (sfi->HasBuiltinId()) {
    // API functions have builtin code but not builtin SFIs, so don't print the
    // builtins for those.
    accumulator->Add("[builtin: %s] ", Builtins::name(sfi->builtin_id()));
  }
  if (IsConstructor()) accumulator->Add("new ");
  accumulator->PrintFunction(function, receiver);

  accumulator->Add("(this=%o", receiver);

  // Print the parameters.
  int parameters_count = ComputeParametersCount();
  for (int i = 0; i < parameters_count; i++) {
    accumulator->Add(",%o", GetParameter(i));
  }

  accumulator->Add(")\n");
}

void ApiCallbackExitFrame::Print(StringStream* accumulator, PrintMode mode,
                                 int index) const {
  DirectHandle<JSFunction> function = GetFunction();
  DisallowGarbageCollection no_gc;
  Tagged<Object> receiver = this->receiver();

  accumulator->PrintSecurityTokenIfChanged(*function);
  PrintIndex(accumulator, mode, index);
  accumulator->Add("ApiCallbackExitFrame ");
  if (IsConstructor()) accumulator->Add("new ");
  accumulator->PrintFunction(*function, receiver);

  accumulator->Add("(this=%o", receiver);

  // Print the parameters.
  int parameters_count = ComputeParametersCount();
  for (int i = 0; i < parameters_count; i++) {
    accumulator->Add(",%o", GetParameter(i));
  }

  accumulator->Add(")\n\n");
}

void ApiAccessorExitFrame::Print(StringStream* accumulator, PrintMode mode,
                                 int index) const {
  DisallowGarbageCollection no_gc;

  PrintIndex(accumulator, mode, index);
  accumulator->Add("api accessor exit frame: ");

  Tagged<Name> name = property_name();
  Tagged<Object> receiver = this->receiver();
  Tagged<Object> holder = this->holder();
  accumulator->Add("(this=%o, holder=%o, name=%o)\n", receiver, holder, name);
}

Address CommonFrame::GetExpressionAddress(int n) const {
  const int offset = StandardFrameConstants::kExpressionsOffset;
  return fp() + offset - n * kSystemPointerSize;
}

Address UnoptimizedJSFrame::GetExpressionAddress(int n) const {
  const int offset = UnoptimizedFrameConstants::kExpressionsOffset;
  return fp() + offset - n * kSystemPointerSize;
}

Tagged<Object> CommonFrame::context() const {
  return ReadOnlyRoots(isolate()).undefined_value();
}

int CommonFrame::position() const {
  Tagged<Code> code;
  int code_offset = -1;
  std::tie(code, code_offset) = LookupCodeAndOffset();
  return code->SourcePosition(code_offset);
}

int CommonFrame::ComputeExpressionsCount() const {
  Address base = GetExpressionAddress(0);
  Address limit = sp() - kSystemPointerSize;
  DCHECK(base >= limit);  // stack grows downwards
  // Include register-allocated locals in number of expressions.
  return static_cast<int>((base - limit) / kSystemPointerSize);
}

void CommonFrame::ComputeCallerState(State* state) const {
  state->fp = caller_fp();
#if V8_ENABLE_WEBASSEMBLY
  if (state->fp == kNullAddress) {
    // An empty FP signals the first frame of a stack segment. The caller is
    // on a different stack, or is unbound (suspended stack).
    // DCHECK(isolate_->wasm_stacks() != nullptr); // I.e., JSPI active
    return;
  }
#endif
  state->sp = caller_sp();
  state->pc_address = ResolveReturnAddressLocation(reinterpret_cast<Address*>(
      fp() + StandardFrameConstants::kCallerPCOffset));
  state->callee_fp = fp();
  state->callee_pc = maybe_unauthenticated_pc();
  state->constant_pool_address = reinterpret_cast<Address*>(
      fp() + StandardFrameConstants::kConstantPoolOffset);
}

void CommonFrame::Summarize(std::vector<FrameSummary>* functions) const {
  // This should only be called on frames which override this method.
  UNREACHABLE();
}

namespace {
void VisitSpillSlot(Isolate* isolate, RootVisitor* v,
                    FullObjectSlot spill_slot) {
#ifdef V8_COMPRESS_POINTERS
  PtrComprCageBase cage_base(isolate);
  bool was_compressed = false;

  // Spill slots may contain compressed values in which case the upper
  // 32-bits will contain zeros. In order to simplify handling of such
  // slots in GC we ensure that the slot always contains full value.

  // The spill slot may actually contain weak references so we load/store
  // values using spill_slot.location() in order to avoid dealing with
  // FullMaybeObjectSlots here.
  if (V8_EXTERNAL_CODE_SPACE_BOOL) {
    // When external code space is enabled the spill slot could contain both
    // InstructionStream and non-InstructionStream references, which have
    // different cage bases. So unconditional decompression of the value might
    // corrupt InstructionStream pointers. However, given that 1) the
    // InstructionStream pointers are never compressed by design (because
    //    otherwise we wouldn't know which cage base to apply for
    //    decompression, see respective DCHECKs in
    //    RelocInfo::target_object()),
    // 2) there's no need to update the upper part of the full pointer
    //    because if it was there then it'll stay the same,
    // we can avoid updating upper part of the spill slot if it already
    // contains full value.
    // TODO(v8:11880): Remove this special handling by enforcing builtins
    // to use CodeTs instead of InstructionStream objects.
    Address value = *spill_slot.location();
    if (!HAS_SMI_TAG(value) && value <= 0xffffffff) {
      // We don't need to update smi values or full pointers.
      was_compressed = true;
      *spill_slot.location() = V8HeapCompressionScheme::DecompressTagged(
          cage_base, static_cast<Tagged_t>(value));
      if (DEBUG_BOOL) {
        // Ensure that the spill slot contains correct heap object.
        Tagged<HeapObject> raw =
            Cast<HeapObject>(Tagged<Object>(*spill_slot.location()));
        MapWord map_word = raw->map_word(cage_base, kRelaxedLoad);
        Tagged<HeapObject> forwarded = map_word.IsForwardingAddress()
                                           ? map_word.ToForwardingAddress(raw)
                                           : raw;
        bool is_self_forwarded =
            forwarded->map_word(cage_base, kRelaxedLoad) ==
            MapWord::FromForwardingAddress(forwarded, forwarded);
        if (is_self_forwarded) {
          // The object might be in a self-forwarding state if it's located
          // in new large object space. GC will fix this at a later stage.
          CHECK(
              MemoryChunk::FromHeapObject(forwarded)->InNewLargeObjectSpace());
        } else {
          Tagged<HeapObject> forwarded_map = forwarded->map(cage_base);
          // The map might be forwarded as well.
          MapWord fwd_map_map_word =
              forwarded_map->map_word(cage_base, kRelaxedLoad);
          if (fwd_map_map_word.IsForwardingAddress()) {
            forwarded_map = fwd_map_map_word.ToForwardingAddress(forwarded_map);
          }
          CHECK(IsMap(forwarded_map, cage_base));
        }
      }
    }
  } else {
    Address slot_contents = *spill_slot.location();
    Tagged_t compressed_value = static_cast<Tagged_t>(slot_contents);
    if (!HAS_SMI_TAG(compressed_value)) {
      was_compressed = slot_contents <= 0xFFFFFFFF;
      // We don't need to update smi values.
      *spill_slot.location() = V8HeapCompressionScheme::DecompressTagged(
          cage_base, compressed_value);
    }
  }
#endif
  v->VisitRootPointer(Root::kStackRoots, nullptr, spill_slot);
#if V8_COMPRESS_POINTERS
  if (was_compressed) {
    // Restore compression. Generated code should be able to trust that
    // compressed spill slots remain compressed.
    *spill_slot.location() =
        V8HeapCompressionScheme::CompressObject(*spill_slot.location());
  }
#endif
}

void VisitSpillSlots(Isolate* isolate, RootVisitor* v,
                     FullObjectSlot first_slot_offset,
                     base::Vector<const uint8_t> tagged_slots) {
  FullObjectSlot slot_offset = first_slot_offset;
  for (uint8_t bits : tagged_slots) {
    while (bits) {
      const int bit = base::bits::CountTrailingZeros(bits);
      bits &= ~(1 << bit);
      FullObjectSlot spill_slot = slot_offset + bit;
      VisitSpillSlot(isolate, v, spill_slot);
    }
    slot_offset += kBitsPerByte;
  }
}

SafepointEntry GetSafepointEntryFromCodeCache(
    Isolate* isolate, Address inner_pointer,
    InnerPointerToCodeCache::InnerPointerToCodeCacheEntry* entry) {
  if (!entry->safepoint_entry.is_initialized()) {
    entry->safepoint_entry =
        SafepointTable::FindEntry(isolate, entry->code.value(), inner_pointer);
    DCHECK(entry->safepoint_entry.is_initialized());
  } else {
    DCHECK_EQ(
        entry->safepoint_entry,
        SafepointTable::FindEntry(isolate, entry->code.value(), inner_pointer));
  }
  return entry->safepoint_entry;
}

MaglevSafepointEntry GetMaglevSafepointEntryFromCodeCache(
    Isolate* isolate, Address inner_pointer,
    InnerPointerToCodeCache::InnerPointerToCodeCacheEntry* entry) {
  if (!entry->maglev_safepoint_entry.is_initialized()) {
    entry->maglev_safepoint_entry = MaglevSafepointTable::FindEntry(
        isolate, entry->code.value(), inner_pointer);
    DCHECK(entry->maglev_safepoint_entry.is_initialized());
  } else {
    DCHECK_EQ(entry->maglev_safepoint_entry,
              MaglevSafepointTable::FindEntry(isolate, entry->code.value(),
                                              inner_pointer));
  }
  return entry->maglev_safepoint_entry;
}

}  // namespace

#ifdef V8_ENABLE_WEBASSEMBLY
#if V8_ENABLE_DRUMBRAKE
// Class DrumBrakeWasmCode is an adapter class that exposes just the accessors
// of the original WasmCode class that are used in WasmFrame::Iterate. For non
// DrumBrake frames, the class calls the corresponding accessor in a contained
// WasmCode object, while for DrumBrake frames it returns dummy values. This is
// useful to minimize the merge issues in WasmFrame::Iterate.
class DrumBrakeWasmCode {
 public:
  explicit DrumBrakeWasmCode(wasm::WasmCode* wasm_code)
      : wasm_code_(wasm_code) {}

  static std::unique_ptr<DrumBrakeWasmCode> Interpreted() {
    return std::make_unique<DrumBrakeWasmCode>(nullptr);
  }
  static std::unique_ptr<DrumBrakeWasmCode> Compiled(
      wasm::WasmCode* wasm_code) {
    return std::make_unique<DrumBrakeWasmCode>(wasm_code);
  }

  bool is_liftoff() const {
    return wasm_code_ ? wasm_code_->is_liftoff() : false;
  }
  bool frame_has_feedback_slot() const {
    return wasm_code_ ? wasm_code_->frame_has_feedback_slot() : false;
  }
  int stack_slots() const { return wasm_code_ ? wasm_code_->stack_slots() : 0; }
  wasm::WasmCode::Kind kind() const {
    return wasm_code_ ? wasm_code_->kind() : wasm::WasmCode::kInterpreterEntry;
  }
  uint16_t first_tagged_parameter_slot() const {
    return wasm_code_ ? wasm_code_->first_tagged_parameter_slot() : 0;
  }
  uint16_t num_tagged_parameter_slots() const {
    return wasm_code_ ? wasm_code_->num_tagged_parameter_slots() : 0;
  }

 private:
  const wasm::WasmCode* wasm_code_;
};
#endif  // V8_ENABLE_DRUMBRAKE

void WasmFrame::Iterate(RootVisitor* v) const {
  DCHECK(!iterator_->IsStackFrameIteratorForProfiler());

  //  ===  WasmFrame ===
  //  +-------------------------+-----------------------------------------
  //  |   out_param n           |  <-- parameters_base / sp
  //  |       ...               |
  //  |   out_param 0           |  (these can be tagged or untagged)
  //  +-------------------------+-----------------------------------------
  //  |   spill_slot n          |  <-- parameters_limit                  ^
  //  |       ...               |                               spill_slot_space
  //  |   spill_slot 0          |                                        v
  //  +-------------------------+-----------------------------------------
  //  | WasmFeedback(*)         |  <-- frame_header_base                 ^
  //  |- - - - - - - - - - - - -|                                        |
  //  | WasmTrustedInstanceData |                                        |
  //  |- - - - - - - - - - - - -|                                        |
  //  |   Type Marker           |                                        |
  //  |- - - - - - - - - - - - -|                              frame_header_size
  //  |
```