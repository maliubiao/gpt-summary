Response:
The user is asking for a summary of the functionality of the provided C++ code snippet from `v8/src/execution/frames.cc`.

Here's a breakdown of the thought process to generate the answer:

1. **Understand the Goal:** The primary goal is to explain what the code does within the context of V8. It's crucial to identify the core concepts being handled.

2. **Identify Key Data Structures:** The code heavily involves `StackFrame` and related classes like `StackFrameIterator`, `EntryFrame`, `ExitFrame`, `BuiltinExitFrame`, `ApiCallbackExitFrame`, `ApiAccessorExitFrame`, and `WasmFrame`. These represent different types of frames on the call stack during JavaScript execution.

3. **Focus on Core Functionality:** The code's primary concern is determining the `StackFrame::Type` and related information for different points in the call stack. This is essential for debugging, profiling, and garbage collection.

4. **Analyze Individual Sections:**
    * **`ComputeBuiltinFrameType`:**  This function deduces the type of a frame within a built-in function. The logic checks if it's an optimized built-in or a regular built-in.
    * **`SafeStackFrameType`:** This function acts as a filter, ensuring a given `StackFrame::Type` is valid or falling back to `StackFrame::NATIVE`. It lists the valid frame types.
    * **`StackFrameIterator::ComputeStackFrameType`:** This is a central piece, responsible for figuring out the frame type based on the program counter (`pc`) and frame pointer (`fp`). It handles WebAssembly frames specifically. It also considers `CodeKind` to differentiate frame types (BUILTIN, BASELINE, MAGLEV, TURBOFAN_JS, etc.).
    * **`StackFrameIteratorForProfiler::ComputeStackFrameType`:** This is a specialized version for profiling, potentially handling cases where full information isn't readily available. It relies on markers and heuristics.
    * **`StackFrame::GetCallerState`:** This initiates the process of finding the calling frame's information.
    * **`NativeFrame::ComputeCallerState`:**  Handles the basic case for native (non-V8) frames.
    * **`EntryFrame`, `ExitFrame`, `BuiltinExitFrame`, `ApiCallbackExitFrame`, `ApiAccessorExitFrame`, `CWasmEntryFrame`:** These represent specific frame types with their own logic for computing caller state and iterating through their contents for garbage collection. They often have custom constants (`EntryFrameConstants`, `ExitFrameConstants`, etc.) to access data within the frame.
    * **`WasmFrame::Iterate` (partial):**  The beginning of the `WasmFrame::Iterate` function provides insight into the structure of WebAssembly frames, including parameters and spill slots.

5. **Identify Relationships:** Notice how `StackFrameIterator` is used to determine the frame type. See how different frame types override `ComputeCallerState` to move up the call stack.

6. **Look for Conditional Compilation:** Pay attention to `#if V8_ENABLE_WEBASSEMBLY` blocks, which indicate features specific to WebAssembly integration.

7. **Relate to JavaScript (if applicable):**  The code deals with how JavaScript calls into built-in functions and native code, and how WebAssembly integrates. Think about how errors and debugging work in JavaScript and how stack traces are generated.

8. **Identify Potential User Errors:** The code deals with low-level stack manipulation. Common programming errors that might lead to issues handled by this code include stack overflows, incorrect function calls, and memory corruption.

9. **Infer the Overall Purpose:**  Based on the analysis, conclude that `frames.cc` is responsible for managing and interpreting the call stack in V8, essential for execution, debugging, and memory management.

10. **Structure the Answer:** Organize the findings into a clear and logical structure:
    * Overall functionality.
    * Explanation of key functions and classes.
    * Connection to JavaScript.
    * Examples of potential user errors.
    * Summary of the provided snippet.

11. **Review and Refine:** Ensure the explanation is accurate, concise, and easy to understand for someone with some programming background but perhaps not deep V8 internals knowledge. Check for any ambiguities or missing information. For instance, emphasizing the role in debugging and garbage collection makes the explanation more concrete. Adding examples, even if not directly from the code, helps illustrate the concepts.
这是对 `v8/src/execution/frames.cc` 文件代码片段的分析，该文件负责处理 V8 引擎中的调用栈帧。

**功能归纳:**

这段代码片段的主要功能是**确定和区分不同类型的调用栈帧**。它定义了多种栈帧类型，并提供了方法来根据程序计数器（PC）、帧指针（FP）以及其他元数据来判断当前栈帧的类型。这对于诸如调试、性能分析以及垃圾回收等 V8 内部操作至关重要。

**具体功能点:**

* **`ComputeBuiltinFrameType(Tagged<GcSafeCode> code)`:**  根据内置代码对象的属性判断内置函数的栈帧类型。它区分了优化的内置函数和普通的内置函数。
* **`SafeStackFrameType(StackFrame::Type candidate)`:**  验证给定的栈帧类型是否安全有效。它列举了所有被认为是安全的栈帧类型，并将其他类型视为 `StackFrame::NATIVE`。这可以防止处理错误的或恶意的栈帧类型。
* **`StackFrameIterator::ComputeStackFrameType(StackFrame::State* state)`:** 这是核心函数之一，负责根据当前栈帧的状态（包括程序计数器 `pc` 和帧指针 `fp`）来计算栈帧的类型。它会检查是否是 WebAssembly 代码，然后查找包含该程序计数器的代码对象，并根据代码对象的类型（如 `BUILTIN`, `BASELINE`, `MAGLEV`, `TURBOFAN_JS` 等）来确定栈帧类型。它还处理了通过帧指针上的标记来确定栈帧类型的情况。
* **`StackFrameIteratorForProfiler::ComputeStackFrameType(StackFrame::State* state)`:**  这是一个专门用于性能分析器的版本，它在某些情况下可能无法获取完整的代码对象信息，因此会使用不同的方法来推断栈帧类型，例如检查帧指针上的标记或者判断是否是解释器帧。
* **`StackFrame::GetCallerState(State* state)`:** 获取当前栈帧的调用者的状态信息，包括调用者的栈指针、帧指针和程序计数器等。
* **`NativeFrame::ComputeCallerState(State* state)`:**  计算原生（C++）函数的调用者状态。
* **`EntryFrame::ComputeCallerState(State* state)` 和 `EntryFrame::GetCallerState(State* state)`:**  处理 JavaScript 入口帧，这种帧是 V8 进入 JavaScript 代码执行的起始点。
* **`ExitFrame::ComputeCallerState(State* state)` 和 `ExitFrame::GetStateForFramePointer(Address fp, State* state)` 和 `ExitFrame::ComputeFrameType(Address fp)`:** 处理从 JavaScript 代码退出到 C++ 代码的出口帧。它需要区分不同类型的出口帧。
* **`BuiltinExitFrame::Summarize(std::vector<FrameSummary>* frames)` 和相关方法:** 处理内置函数调用后的出口帧，提取函数、接收者和参数等信息。
* **`ApiCallbackExitFrame::Summarize(std::vector<FrameSummary>* frames)` 和相关方法:** 处理通过 V8 API 调用的 JavaScript 回调函数的出口帧。
* **`ApiAccessorExitFrame::Summarize(std::vector<FrameSummary>* frames)`:** 处理通过 V8 API 访问器（getter/setter）的出口帧。
* **`WasmFrame::Iterate(RootVisitor* v)` (部分):**  开始处理 WebAssembly 栈帧的遍历，用于垃圾回收等操作。它描述了 WebAssembly 栈帧的内存布局。

**与 JavaScript 的关系 (示例):**

这段代码与 JavaScript 的执行过程息息相关。当 JavaScript 代码调用一个函数时，V8 会在调用栈上创建一个新的栈帧。`frames.cc` 中的代码负责识别这些栈帧的类型，这对于理解程序的执行流程至关重要。

```javascript
function foo() {
  bar();
}

function bar() {
  // 在 bar 函数执行期间，V8 会创建一个栈帧
  console.trace(); // 打印调用栈，frames.cc 的代码会参与确定栈帧类型
}

foo();
```

在这个例子中，当 `bar()` 函数执行时，V8 会创建一个栈帧。`frames.cc` 中的代码会判断这个栈帧的类型（可能是 `TURBOFAN_JS` 如果 `bar` 被优化过，或者 `INTERPRETED` 如果是解释执行）。`console.trace()` 函数的实现会利用这些信息来生成调用栈信息。

**代码逻辑推理 (假设输入与输出):**

假设在执行以下 JavaScript 代码时：

```javascript
function add(a, b) {
  return a + b;
}

add(5, 3);
```

当执行到 `add(5, 3)` 时，`StackFrameIterator::ComputeStackFrameType` 函数可能会被调用，并且：

**假设输入:**

* `state->pc_address`: 指向 `add` 函数代码的某个指令地址。
* `state->fp`: 指向 `add` 函数的栈帧起始地址。
* `lookup_result.value()->kind()`:  如果 `add` 函数被 TurboFan 优化，则可能是 `CodeKind::TURBOFAN_JS`。

**可能的输出:**

* `StackFrame::TURBOFAN_JS`: 如果 `add` 函数被 TurboFan 优化过。
* `StackFrame::INTERPRETED`: 如果 `add` 函数是解释执行的。

**用户常见的编程错误 (示例):**

虽然这段 C++ 代码不是用户直接编写的，但它处理的栈帧信息与用户代码的行为密切相关。用户的一些常见错误可能会导致产生特定类型的栈帧，或者使 V8 难以正确识别栈帧类型，例如：

* **栈溢出:**  大量的递归调用会导致栈空间耗尽，可能会产生无法识别的栈帧。
* **不正确的 C++ 插件调用:**  如果 JavaScript 调用了错误的或有缺陷的 C++ 插件（通过 V8 API），可能会导致产生类型不明确的出口帧。

**总结这段代码的功能:**

这段代码片段是 V8 引擎中负责**识别和管理不同类型调用栈帧**的关键部分。它定义了各种栈帧类型，并提供了基于程序计数器、帧指针和代码对象等信息来确定当前栈帧类型的方法。这项功能对于 V8 的调试、性能分析和垃圾回收等核心操作至关重要，并且直接关系到 JavaScript 代码的执行流程和错误处理。它区分了 JavaScript 函数的不同优化级别（解释执行、TurboFan 优化等）以及与 C++ 代码的交互方式（内置函数、API 调用等）。

Prompt: 
```
这是目录为v8/src/execution/frames.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/execution/frames.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共6部分，请归纳一下它的功能

"""
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
"""


```