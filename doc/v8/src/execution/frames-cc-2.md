Response:
My thought process to analyze the provided C++ code snippet and fulfill the request went through these stages:

1. **Understanding the Goal:** The request asks for a description of the `v8/src/execution/frames.cc` file's functionality based on a provided code excerpt. It also has specific constraints about format, potential Torque nature, relation to JavaScript, logic examples, common errors, and summarizing the functionality of the *provided snippet*.

2. **Initial Scan and Keyword Identification:**  I quickly scanned the code for keywords and patterns that reveal its purpose. Key observations were:
    *  Comments about "Constant Pool", "frame ptr", "return addr", "parameters". This strongly suggests stack frame manipulation.
    *  `WasmFrame`, `WasmExitFrame`, `WasmToJSWrapper`, `OptimizedWasmToJSWrapper`, `TypedFrame`, `MaglevFrame`, `TurbofanJSFrame`, `StubFrame`, `JavaScriptFrame`, `BaselineFrame`, `InterpretedFrame`. These names clearly indicate handling of different types of execution frames within V8.
    *  `RootVisitor`, `VisitRootPointers`, `VisitSpillSlots`, `Iterate`. These point to garbage collection and stack scanning.
    *  `SafepointEntry`, `DeoptimizationData`. These relate to debugging, optimization, and deoptimization.
    *  `isolate()`, `heap()`, `builtins()`. These are standard V8 API calls.
    *  Preprocessor directives like `#if`, `#ifdef`, `#else`. This indicates conditional compilation based on build flags.
    *  `DCHECK`, `CHECK`, `FATAL`. These are V8's assertion and error handling macros.

3. **Inferring High-Level Functionality:** Based on the keywords and structure, I concluded that `frames.cc` is responsible for:
    * **Representing and manipulating stack frames** of various types used in V8 (WASM, optimized JS, interpreted JS, etc.).
    * **Providing a way to iterate through the contents of these frames**, likely for garbage collection (visiting live objects) and debugging.
    * **Handling interactions between different execution environments** (e.g., WASM calling JavaScript, JavaScript calling WASM).
    * **Managing safepoint information** for deoptimization and debugging.

4. **Analyzing Specific Code Blocks:** I then examined the individual functions and code blocks to understand their particular roles:
    * The initial diagram and comments about the frame layout helped visualize the structure of a generic frame.
    * The WASM-related code blocks showed how WASM frames are structured and how parameters and spill slots are accessed. The `DrumBrakeWasmCode` usage indicated support for the WASM interpreter. The conditional compilation with `V8_ENABLE_DRUMBRAKE` was noted.
    * The `TypedFrame::Iterate` function demonstrated how to iterate through different parts of an optimized JS frame, using `SafepointEntry` to identify live objects.
    * The `MaglevFrame::Iterate` function showed a similar iteration process for Maglev-compiled code.
    * The `TurbofanJSFrame::Iterate` function handles iteration for Turbofan-optimized JS code.
    * The `JavaScriptFrame` methods provided access to information about JS frames (parameters, function, bytecode offset).

5. **Addressing Specific Constraints:**

    * **Functionality Listing:** I started listing the key functionalities identified in the previous steps.
    * **Torque:** I checked the file extension mentioned in the prompt (`.cc` vs. `.tq`). Since it's `.cc`, it's not a Torque file.
    * **JavaScript Relation:** I looked for direct interactions with JavaScript concepts. The WASM-to-JS wrapper functions and the handling of JavaScript frames are the primary links. I constructed a simple JavaScript example to illustrate the concept of a function call stack.
    * **Logic Reasoning:** I focused on the frame layout and the parameter passing mechanism. I created a simple scenario with input and output parameters to illustrate how the code might handle them.
    * **Common Errors:**  I considered typical mistakes developers might make that relate to stack frames or function calls, such as stack overflow or incorrect argument passing.
    * **Summary:**  I synthesized the key functionalities into a concise summary statement.

6. **Structuring the Output:**  I organized the information according to the prompt's requirements, using headings and bullet points for clarity. I made sure to address each of the specific questions.

7. **Refinement and Review:** I reread the generated output to ensure accuracy, completeness, and clarity. I checked that the JavaScript example was relevant and easy to understand. I confirmed that the logic example aligned with the frame structure described in the code. I double-checked the summary to ensure it captured the essence of the provided snippet.

Essentially, I followed a process of information extraction, analysis, and synthesis, guided by the specific requirements of the prompt. The key was to understand the context of the code within the V8 JavaScript engine.
好的，让我们来分析一下 `v8/src/execution/frames.cc` 这部分代码的功能。

**功能归纳：**

这段代码是 V8 JavaScript 引擎中负责处理和表示不同类型栈帧的核心部分。它的主要功能是：

1. **定义和操作各种类型的栈帧 (Stack Frames):**  代码中定义了多种栈帧类型，例如 `WasmFrame`, `WasmExitFrame`, `TypedFrame`, `MaglevFrame`, `TurbofanJSFrame`, `StubFrame`, `JavaScriptFrame` 等。每种栈帧都代表了程序执行过程中的一个函数调用。

2. **栈帧布局描述:** 代码通过注释详细描述了不同栈帧的内存布局，包括参数、局部变量（spill slots）、帧头部信息（例如保存的帧指针、返回地址、上下文、JSFunction 等）。这些布局信息对于理解函数调用机制和进行调试至关重要。

3. **支持垃圾回收 (Garbage Collection):**  通过 `Iterate` 方法和 `RootVisitor`，这段代码能够遍历栈帧中存储的对象引用（例如参数、局部变量、上下文），以便垃圾回收器能够正确地识别和管理这些对象。

4. **处理 WebAssembly (Wasm) 栈帧:** 代码专门处理了 WASM 相关的栈帧，包括 WASM 函数调用、WASM 到 JS 的调用、WASM 解释器等场景。这涉及到 WASM 代码的管理、安全点信息的查找以及参数的传递。

5. **处理不同优化级别的栈帧:** 代码涵盖了不同优化级别的栈帧，例如 `TypedFrame` (Turbofan 优化), `MaglevFrame` (Maglev 优化)。针对不同的优化策略，栈帧的布局和处理方式可能有所不同。

6. **提供栈帧信息的访问接口:** 代码中提供了诸如 `GetInnermostFunction`, `GetBytecodeOffsetForOSR`, `ComputeParametersCount` 等方法，用于获取栈帧相关的元信息，例如当前执行的函数、字节码偏移量、参数数量等。这些信息对于调试、性能分析和即时编译 (JIT) 优化非常重要。

**关于代码特性：**

* **`.tq` 后缀：**  你提到如果文件以 `.tq` 结尾，那就是 Torque 源代码。由于这里是 `.cc` 结尾，**它不是 Torque 源代码**。 Torque 是一种 V8 用于生成高效 C++ 代码的领域特定语言。

* **与 JavaScript 的关系：**  `v8/src/execution/frames.cc` 与 JavaScript 的功能密切相关。栈帧是 JavaScript 函数调用的基础结构。当 JavaScript 代码执行时，V8 会在栈上创建和管理这些帧。这段代码直接参与了：
    * **JavaScript 函数的调用和返回。**
    * **JavaScript 代码的垃圾回收。**
    * **JavaScript 代码的优化和反优化 (deoptimization)。**
    * **JavaScript 与 WebAssembly 的互操作。**

**JavaScript 示例：**

以下 JavaScript 示例可以帮助理解栈帧的概念：

```javascript
function foo(a, b) {
  console.log(a + b);
  bar(a, b);
}

function bar(x, y) {
  console.log(x * y);
}

foo(5, 10);
```

当这段代码执行时，会创建以下栈帧（简化）：

1. **全局栈帧 (Global Frame):**  程序启动时的初始栈帧。
2. **`foo` 的栈帧:** 当调用 `foo(5, 10)` 时创建，包含 `a` 和 `b` 的值以及返回地址等信息。
3. **`bar` 的栈帧:** 当 `foo` 内部调用 `bar(a, b)` 时创建，包含 `x` 和 `y` 的值以及返回地址等信息。

`v8/src/execution/frames.cc` 中的代码负责在 V8 引擎内部创建、管理和访问这些栈帧。

**代码逻辑推理（假设）：**

假设我们有一个 `TypedFrame`，并且需要访问它的参数：

**假设输入：**

* `TypedFrame` 实例 `frame`，其 `fp()` 指向帧指针。
* 知道参数在帧内的偏移量和大小。

**代码逻辑 (简化):**

```c++
// 假设参数 0 的偏移量是 first_parameter_offset
// 假设参数都是Tagged<Object>

Address parameter0_address = frame->fp() + first_parameter_offset;
Tagged<Object> parameter0 = Memory<Tagged<Object>>(parameter0_address);

// 访问参数 0 的值
// ...
```

**输出：**

* `parameter0` 将会包含 `TypedFrame` 对应函数调用时传递的第一个参数的值。

**用户常见的编程错误：**

与栈帧相关的常见编程错误包括：

1. **栈溢出 (Stack Overflow):**  当函数调用层级过深（例如递归调用没有终止条件）时，会导致栈空间耗尽。V8 的栈帧管理机制会限制栈的大小，防止程序崩溃。

   ```javascript
   function recursiveFunction() {
     recursiveFunction(); // 缺少终止条件
   }

   recursiveFunction(); // 可能导致栈溢出
   ```

2. **不正确的参数传递：**  在 C++ 扩展或 Native Modules 中，如果传递给 JavaScript 函数的参数类型或数量不正确，可能会导致 V8 尝试访问错误的内存位置，从而引发错误。

   ```c++
   // 假设有一个 C++ 函数，错误地传递了参数
   void CallJavaScriptFunction(v8::Local<v8::Function> function, v8::Local<v8::Context> context) {
       // 应该传递参数，但这里没有
       function->Call(context, context->Global(), 0, nullptr);
   }
   ```

3. **在异步操作中错误地访问栈上变量：**  由于异步操作可能会在函数调用返回后执行，因此直接访问其栈帧上的变量可能会导致未定义行为。V8 的异步机制（例如 Promises, async/await）会帮助管理这种情况，但开发者需要注意避免此类错误。

**总结 `v8/src/execution/frames.cc` (本部分) 的功能：**

这段 `v8/src/execution/frames.cc` 代码的核心功能是**定义、表示和管理 V8 引擎中各种类型的栈帧**。它描述了栈帧的内存布局，提供了访问栈帧信息的接口，并支持垃圾回收和处理不同执行环境（如 WebAssembly）的栈帧。这是 V8 引擎执行 JavaScript 代码的关键组成部分。

Prompt: 
```
这是目录为v8/src/execution/frames.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/execution/frames.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共6部分，请归纳一下它的功能

"""
 [Constant Pool]         |                                        |
  //  |- - - - - - - - - - - - -|                                        |
  //  | saved frame ptr         |  <-- fp                                |
  //  |- - - - - - - - - - - - -|                                        |
  //  |  return addr            |  <-- tagged_parameter_limit            v
  //  +-------------------------+-----------------------------------------
  //  |    in_param n           |
  //  |       ...               |
  //  |    in_param 0           |  <-- first_tagged_parameter_slot
  //  +-------------------------+-----------------------------------------
  //
  // (*) Only if compiled by Liftoff and with --wasm-inlining.

#if !V8_ENABLE_DRUMBRAKE
  auto pair = wasm::GetWasmCodeManager()->LookupCodeAndSafepoint(
      isolate(), maybe_unauthenticated_pc());
  wasm::WasmCode* wasm_code = pair.first;
  SafepointEntry safepoint_entry = pair.second;
#else   // !V8_ENABLE_DRUMBRAKE
  std::unique_ptr<DrumBrakeWasmCode> interpreter_wasm_code;
  SafepointEntry safepoint_entry;
  bool is_wasm_interpreter_frame =
      v8_flags.wasm_jitless &&
      (type() == WASM_INTERPRETER_ENTRY || type() == C_WASM_ENTRY);
  if (is_wasm_interpreter_frame) {
    interpreter_wasm_code = DrumBrakeWasmCode::Interpreted();
  } else {
    auto pair =
        wasm::GetWasmCodeManager()->LookupCodeAndSafepoint(isolate(), pc());
    wasm::WasmCode* wasm_code = pair.first;
    safepoint_entry = pair.second;
    DCHECK(wasm_code);
    interpreter_wasm_code = DrumBrakeWasmCode::Compiled(wasm_code);
  }

  // Reuse the same name "wasm_code" for this variable, to use the
  // DrumBrakeWasmCode adapter and minimize merge issues in the following code.
  DrumBrakeWasmCode* wasm_code = interpreter_wasm_code.get();
#endif  // !V8_ENABLE_DRUMBRAKE

#ifdef DEBUG
  intptr_t marker =
      Memory<intptr_t>(fp() + CommonFrameConstants::kContextOrFrameTypeOffset);
  DCHECK(StackFrame::IsTypeMarker(marker));
  StackFrame::Type type = StackFrame::MarkerToType(marker);
  DCHECK(type == WASM_TO_JS || type == WASM || type == WASM_EXIT ||
         type == WASM_SEGMENT_START);
#endif

  // Determine the fixed header and spill slot area size.
  // The last value in the frame header is the calling PC, which should
  // not be visited.
  static_assert(WasmExitFrameConstants::kFixedSlotCountFromFp ==
                    WasmFrameConstants::kFixedSlotCountFromFp + 1,
                "WasmExitFrame has one slot more than WasmFrame");

  int frame_header_size = WasmFrameConstants::kFixedFrameSizeFromFp;
  if (wasm_code->is_liftoff() && wasm_code->frame_has_feedback_slot()) {
    // Frame has Wasm feedback slot.
    frame_header_size += kSystemPointerSize;
  }
  int spill_slot_space =
      wasm_code->stack_slots() * kSystemPointerSize -
      (frame_header_size + StandardFrameConstants::kFixedFrameSizeAboveFp);
  // Fixed frame slots.
  FullObjectSlot frame_header_base(&Memory<Address>(fp() - frame_header_size));
  FullObjectSlot frame_header_limit(
      &Memory<Address>(fp() - StandardFrameConstants::kCPSlotSize));

  // Visit parameters passed to the callee.
  // Frame layout without stack switching (stack grows upwards):
  //
  //         | callee      |
  //         | frame       |
  //         |-------------| <- sp()
  //         | out params  |
  //         |-------------| <- frame_header_base - spill_slot_space
  //         | spill slots |
  //         |-------------| <- frame_header_base
  //         | frame header|
  //         |-------------| <- fp()
  //
  // With stack-switching:
  //
  //        Secondary stack:      Central stack:
  //
  //                              | callee     |
  //                              | frame      |
  //                              |------------| <- sp()
  //                              | out params |
  //        |-------------|       |------------| <- maybe_stack_switch.target_sp
  //        | spill slots |
  //        |-------------| <- frame_header_base
  //        | frame header|
  //        |-------------| <- fp()
  //
  // The base (lowest address) of the outgoing stack parameters area is always
  // sp(), and the limit (highest address) is either {frame_header_base -
  // spill_slot_space} or {maybe_stack_switch.target_sp} depending on
  // stack-switching.
  wasm::StackMemory::StackSwitchInfo maybe_stack_switch;
  if (iterator_->wasm_stack() != nullptr) {
    maybe_stack_switch = iterator_->wasm_stack()->stack_switch_info();
  }
  FullObjectSlot parameters_limit(
      maybe_stack_switch.has_value() && maybe_stack_switch.source_fp == fp()
          ? maybe_stack_switch.target_sp
          : frame_header_base.address() - spill_slot_space);
  FullObjectSlot spill_space_end =
      FullObjectSlot(frame_header_base.address() - spill_slot_space);

  // Visit the rest of the parameters if they are tagged.
  bool has_tagged_outgoing_params =
      wasm_code->kind() != wasm::WasmCode::kWasmFunction &&
      wasm_code->kind() != wasm::WasmCode::kWasmToCapiWrapper;
  if (!InFastCCall() && has_tagged_outgoing_params) {
    FullObjectSlot parameters_base(&Memory<Address>(sp()));
    v->VisitRootPointers(Root::kStackRoots, nullptr, parameters_base,
                         parameters_limit);
  }

  // Visit pointer spill slots and locals.
  if (safepoint_entry.is_initialized()) {
    DCHECK_GE((wasm_code->stack_slots() + kBitsPerByte) / kBitsPerByte,
              safepoint_entry.tagged_slots().size());
    VisitSpillSlots(isolate(), v, spill_space_end,
                    safepoint_entry.tagged_slots());
  }

  // Visit tagged parameters that have been passed to the function of this
  // frame. Conceptionally these parameters belong to the parent frame. However,
  // the exact count is only known by this frame (in the presence of tail calls,
  // this information cannot be derived from the call site).
  if (wasm_code->num_tagged_parameter_slots() > 0) {
    FullObjectSlot tagged_parameter_base(&Memory<Address>(caller_sp()));
    tagged_parameter_base += wasm_code->first_tagged_parameter_slot();
    FullObjectSlot tagged_parameter_limit =
        tagged_parameter_base + wasm_code->num_tagged_parameter_slots();

    v->VisitRootPointers(Root::kStackRoots, nullptr, tagged_parameter_base,
                         tagged_parameter_limit);
  }

  // Visit the instance object.
  v->VisitRootPointers(Root::kStackRoots, nullptr, frame_header_base,
                       frame_header_limit);
}

void TypedFrame::IterateParamsOfGenericWasmToJSWrapper(RootVisitor* v) const {
  Address maybe_sig =
      Memory<Address>(fp() + WasmToJSWrapperConstants::kSignatureOffset);
  if (maybe_sig == 0 || maybe_sig == static_cast<Address>(-1)) {
    // The signature slot was reset after processing all incoming parameters.
    // We don't have to keep them alive anymore.
    return;
  }

  const wasm::CanonicalSig* sig =
      reinterpret_cast<wasm::CanonicalSig*>(maybe_sig);
  DCHECK(wasm::GetTypeCanonicalizer()->Contains(sig));
  wasm::LinkageLocationAllocator allocator(wasm::kGpParamRegisters,
                                           wasm::kFpParamRegisters, 0);
  // The first parameter is the instance data, which we don't have to scan. We
  // have to tell the LinkageLocationAllocator about it though.
  allocator.Next(MachineRepresentation::kTaggedPointer);

  // Parameters are separated into two groups (first all untagged, then all
  // tagged parameters). Therefore we first have to iterate over the signature
  // first to process all untagged parameters, and afterwards we can scan the
  // tagged parameters.
  bool has_tagged_param = false;
  for (wasm::CanonicalValueType type : sig->parameters()) {
    MachineRepresentation param = type.machine_representation();
    // Skip tagged parameters (e.g. any-ref).
    if (IsAnyTagged(param)) {
      has_tagged_param = true;
      continue;
    }
    if (kSystemPointerSize == 8 || param != MachineRepresentation::kWord64) {
      allocator.Next(param);
    } else {
      allocator.Next(MachineRepresentation::kWord32);
      allocator.Next(MachineRepresentation::kWord32);
    }
  }

  // End the untagged area, so tagged slots come after. This means, especially,
  // that tagged parameters should not fill holes in the untagged area.
  allocator.EndSlotArea();

  if (!has_tagged_param) return;

#if V8_TARGET_ARCH_ARM64
  constexpr size_t size_of_sig = 2;
#else
  constexpr size_t size_of_sig = 1;
#endif

  for (wasm::CanonicalValueType type : sig->parameters()) {
    MachineRepresentation param = type.machine_representation();
    // Skip untagged parameters.
    if (!IsAnyTagged(param)) continue;
    LinkageLocation l = allocator.Next(param);
    if (l.IsRegister()) {
      // Calculate the slot offset.
      int slot_offset = 0;
      // We have to do a reverse lookup in the kGPParamRegisters array. This
      // can be optimized if necessary.
      for (size_t i = 1; i < arraysize(wasm::kGpParamRegisters); ++i) {
        if (wasm::kGpParamRegisters[i].code() == l.AsRegister()) {
          // The first register (the instance) does not get spilled.
          slot_offset = static_cast<int>(i) - 1;
          break;
        }
      }
      // Caller FP + return address + signature.
      size_t param_start_offset = 2 + size_of_sig;
      FullObjectSlot param_start(fp() +
                                 param_start_offset * kSystemPointerSize);
      FullObjectSlot tagged_slot = param_start + slot_offset;
      VisitSpillSlot(isolate(), v, tagged_slot);
    } else {
      // Caller frame slots have negative indices and start at -1. Flip it
      // back to a positive offset (to be added to the frame's FP to find the
      // slot).
      int slot_offset = -l.GetLocation() - 1;
      // Caller FP + return address + signature + spilled registers (without the
      // instance register).
      size_t slots_per_float64 = kDoubleSize / kSystemPointerSize;
      size_t param_start_offset =
          arraysize(wasm::kGpParamRegisters) - 1 +
          (arraysize(wasm::kFpParamRegisters) * slots_per_float64) + 2 +
          size_of_sig;

      // The wasm-to-js wrapper pushes all but the first gp parameter register
      // on the stack, so if the number of gp parameter registers is even, this
      // means that the wrapper pushed an odd number. In that case, and when the
      // size of a double on the stack is two words, then there is an alignment
      // word between the pushed gp registers and the pushed fp registers, so
      // that the whole spill area is double-size aligned.
      if (arraysize(wasm::kGpParamRegisters) % 2 == (0) &&
          kSystemPointerSize != kDoubleSize) {
        param_start_offset++;
      }
      FullObjectSlot param_start(fp() +
                                 param_start_offset * kSystemPointerSize);
      FullObjectSlot tagged_slot = param_start + slot_offset;
      VisitSpillSlot(isolate(), v, tagged_slot);
    }
  }
}

void TypedFrame::IterateParamsOfOptimizedWasmToJSWrapper(RootVisitor* v) const {
  Tagged<GcSafeCode> code = GcSafeLookupCode();
  if (code->wasm_js_tagged_parameter_count() > 0) {
    FullObjectSlot tagged_parameter_base(&Memory<Address>(caller_sp()));
    tagged_parameter_base += code->wasm_js_first_tagged_parameter();
    FullObjectSlot tagged_parameter_limit =
        tagged_parameter_base + code->wasm_js_tagged_parameter_count();
    v->VisitRootPointers(Root::kStackRoots, nullptr, tagged_parameter_base,
                         tagged_parameter_limit);
  }
}
#endif  // V8_ENABLE_WEBASSEMBLY

void TypedFrame::Iterate(RootVisitor* v) const {
  DCHECK(!iterator_->IsStackFrameIteratorForProfiler());

  //  ===  TypedFrame ===
  //  +-----------------+-----------------------------------------
  //  |   out_param n   |  <-- parameters_base / sp
  //  |       ...       |
  //  |   out_param 0   |
  //  +-----------------+-----------------------------------------
  //  |   spill_slot n  |  <-- parameters_limit          ^
  //  |       ...       |                          spill_slot_count
  //  |   spill_slot 0  |                                v
  //  +-----------------+-----------------------------------------
  //  |   Type Marker   |  <-- frame_header_base         ^
  //  |- - - - - - - - -|                                |
  //  | [Constant Pool] |                                |
  //  |- - - - - - - - -|                           kFixedSlotCount
  //  | saved frame ptr |  <-- fp                        |
  //  |- - - - - - - - -|                                |
  //  |  return addr    |                                v
  //  +-----------------+-----------------------------------------

  // Find the code and compute the safepoint information.
  Address inner_pointer = pc();
  InnerPointerToCodeCache::InnerPointerToCodeCacheEntry* entry =
      isolate()->inner_pointer_to_code_cache()->GetCacheEntry(inner_pointer);
  CHECK(entry->code.has_value());
  Tagged<GcSafeCode> code = entry->code.value();
#if V8_ENABLE_WEBASSEMBLY
  bool is_generic_wasm_to_js =
      code->is_builtin() && code->builtin_id() == Builtin::kWasmToJsWrapperCSA;
  bool is_optimized_wasm_to_js = this->type() == WASM_TO_JS_FUNCTION;
  if (is_generic_wasm_to_js) {
    IterateParamsOfGenericWasmToJSWrapper(v);
  } else if (is_optimized_wasm_to_js) {
    IterateParamsOfOptimizedWasmToJSWrapper(v);
  }
#endif  // V8_ENABLE_WEBASSEMBLY
  DCHECK(code->is_turbofanned());
  SafepointEntry safepoint_entry =
      GetSafepointEntryFromCodeCache(isolate(), inner_pointer, entry);

#ifdef DEBUG
  intptr_t marker =
      Memory<intptr_t>(fp() + CommonFrameConstants::kContextOrFrameTypeOffset);
  DCHECK(StackFrame::IsTypeMarker(marker));
#endif  // DEBUG

  // Determine the fixed header and spill slot area size.
  int frame_header_size = TypedFrameConstants::kFixedFrameSizeFromFp;
  int spill_slots_size =
      code->stack_slots() * kSystemPointerSize -
      (frame_header_size + StandardFrameConstants::kFixedFrameSizeAboveFp);

  // Fixed frame slots.
  FullObjectSlot frame_header_base(&Memory<Address>(fp() - frame_header_size));
  FullObjectSlot frame_header_limit(
      &Memory<Address>(fp() - StandardFrameConstants::kCPSlotSize));
  // Parameters passed to the callee.
#if V8_ENABLE_WEBASSEMBLY
  // Frame layout without stack switching (stack grows upwards):
  //
  //         | callee      |
  //         | frame       |
  //         |-------------| <- sp()
  //         | out params  |
  //         |-------------| <- frame_header_base - spill_slot_space
  //         | spill slots |
  //         |-------------| <- frame_header_base
  //         | frame header|
  //         |-------------| <- fp()
  //
  // With stack-switching:
  //
  //        Secondary stack:      Central stack:
  //
  //                              | callee     |
  //                              | frame      |
  //                              |------------| <- sp()
  //                              | out params |
  //        |-------------|       |------------| <- maybe_stack_switch.target_sp
  //        | spill slots |
  //        |-------------| <- frame_header_base
  //        | frame header|
  //        |-------------| <- fp()
  //
  // The base (lowest address) of the outgoing stack parameters area is always
  // sp(), and the limit (highest address) is either {frame_header_base -
  // spill_slot_size} or {maybe_stack_switch.target_sp} depending on
  // stack-switching.
  wasm::StackMemory::StackSwitchInfo maybe_stack_switch;
  if (iterator_->wasm_stack() != nullptr) {
    maybe_stack_switch = iterator_->wasm_stack()->stack_switch_info();
  }
  FullObjectSlot parameters_limit(
      maybe_stack_switch.has_value() && maybe_stack_switch.source_fp == fp()
          ? maybe_stack_switch.target_sp
          : frame_header_base.address() - spill_slots_size);
#else
  FullObjectSlot parameters_limit(frame_header_base.address() -
                                  spill_slots_size);
#endif
  FullObjectSlot parameters_base(&Memory<Address>(sp()));
  FullObjectSlot spill_slots_end(frame_header_base.address() -
                                 spill_slots_size);

  // Visit the rest of the parameters.
  if (HasTaggedOutgoingParams(code)) {
    v->VisitRootPointers(Root::kStackRoots, nullptr, parameters_base,
                         parameters_limit);
  }

  // Visit pointer spill slots and locals.
  DCHECK_GE((code->stack_slots() + kBitsPerByte) / kBitsPerByte,
            safepoint_entry.tagged_slots().size());
  VisitSpillSlots(isolate(), v, spill_slots_end,
                  safepoint_entry.tagged_slots());

  // Visit fixed header region.
  v->VisitRootPointers(Root::kStackRoots, nullptr, frame_header_base,
                       frame_header_limit);

  // Visit the return address in the callee and incoming arguments.
  IteratePc(v, constant_pool_address(), code);
}

void MaglevFrame::Iterate(RootVisitor* v) const {
  DCHECK(!iterator_->IsStackFrameIteratorForProfiler());

  //  ===  MaglevFrame ===
  //  +-----------------+-----------------------------------------
  //  |   out_param n   |  <-- parameters_base / sp
  //  |       ...       |
  //  |   out_param 0   |
  //  +-----------------+-----------------------------------------
  //  | pushed_double n |  <-- parameters_limit          ^
  //  |       ...       |                                |
  //  | pushed_double 0 |                                |
  //  +- - - - - - - - -+                     num_extra_spill_slots
  //  |   pushed_reg n  |                                |
  //  |       ...       |                                |
  //  |   pushed_reg 0  |  <-- pushed_register_base      v
  //  +-----------------+-----------------------------------------
  //  | untagged_slot n |                                ^
  //  |       ...       |                                |
  //  | untagged_slot 0 |                                |
  //  +- - - - - - - - -+                         spill_slot_count
  //  |  tagged_slot n  |                                |
  //  |       ...       |                                |
  //  |  tagged_slot 0  |                                v
  //  +-----------------+-----------------------------------------
  //  |      argc       |  <-- frame_header_base         ^
  //  |- - - - - - - - -|                                |
  //  |   JSFunction    |                                |
  //  |- - - - - - - - -|                                |
  //  |    Context      |                                |
  //  |- - - - - - - - -|                          kFixedSlotCount
  //  | [Constant Pool] |                                |
  //  |- - - - - - - - -|                                |
  //  | saved frame ptr |  <-- fp                        |
  //  |- - - - - - - - -|                                |
  //  |  return addr    |                                v
  //  +-----------------+-----------------------------------------

  // Find the code and compute the safepoint information.
  Address inner_pointer = pc();
  InnerPointerToCodeCache::InnerPointerToCodeCacheEntry* entry =
      isolate()->inner_pointer_to_code_cache()->GetCacheEntry(inner_pointer);
  CHECK(entry->code.has_value());
  Tagged<GcSafeCode> code = entry->code.value();
  DCHECK(code->is_maglevved());
  MaglevSafepointEntry maglev_safepoint_entry =
      GetMaglevSafepointEntryFromCodeCache(isolate(), inner_pointer, entry);

#ifdef DEBUG
  // Assert that it is a JS frame and it has a context.
  intptr_t marker =
      Memory<intptr_t>(fp() + CommonFrameConstants::kContextOrFrameTypeOffset);
  DCHECK(!StackFrame::IsTypeMarker(marker));
#endif  // DEBUG

  // Fixed frame slots.
  FullObjectSlot frame_header_base(
      &Memory<Address>(fp() - StandardFrameConstants::kFixedFrameSizeFromFp));
  FullObjectSlot frame_header_limit(
      &Memory<Address>(fp() - StandardFrameConstants::kCPSlotSize));

  // Determine spill slot area count.
  uint32_t tagged_slot_count = maglev_safepoint_entry.num_tagged_slots();
  uint32_t spill_slot_count =
      code->stack_slots() - StandardFrameConstants::kFixedSlotCount;

  // Visit the outgoing parameters if they are tagged.
  DCHECK(code->has_tagged_outgoing_params());
  FullObjectSlot parameters_base(&Memory<Address>(sp()));
  FullObjectSlot parameters_limit =
      frame_header_base - spill_slot_count -
      maglev_safepoint_entry.num_extra_spill_slots();
  v->VisitRootPointers(Root::kStackRoots, nullptr, parameters_base,
                       parameters_limit);

  // Maglev can also spill registers, tagged and untagged, just before making
  // a call. These are distinct from normal spill slots and live between the
  // normal spill slots and the pushed parameters. Some of these are tagged,
  // as indicated by the tagged register indexes, and should be visited too.
  if (maglev_safepoint_entry.num_extra_spill_slots() > 0) {
    FullObjectSlot pushed_register_base =
        frame_header_base - spill_slot_count - 1;
    uint32_t tagged_register_indexes =
        maglev_safepoint_entry.tagged_register_indexes();
    while (tagged_register_indexes != 0) {
      int index = base::bits::CountTrailingZeros(tagged_register_indexes);
      tagged_register_indexes &= ~(1 << index);
      FullObjectSlot spill_slot = pushed_register_base - index;
      VisitSpillSlot(isolate(), v, spill_slot);
    }
  }

  // Visit tagged spill slots.
  for (uint32_t i = 0; i < tagged_slot_count; ++i) {
    FullObjectSlot spill_slot = frame_header_base - 1 - i;
    VisitSpillSlot(isolate(), v, spill_slot);
  }

  // Visit fixed header region (the context and JSFunction), skipping the
  // argument count since it is stored untagged.
  v->VisitRootPointers(Root::kStackRoots, nullptr, frame_header_base + 1,
                       frame_header_limit);

  // Visit the return address in the callee and incoming arguments.
  IteratePc(v, constant_pool_address(), code);
}

Handle<JSFunction> MaglevFrame::GetInnermostFunction() const {
  std::vector<FrameSummary> frames;
  Summarize(&frames);
  return frames.back().AsJavaScript().function();
}

BytecodeOffset MaglevFrame::GetBytecodeOffsetForOSR() const {
  int deopt_index = SafepointEntry::kNoDeoptIndex;
  Tagged<Code> code = LookupCode();
  const Tagged<DeoptimizationData> data =
      GetDeoptimizationData(code, &deopt_index);
  if (deopt_index == SafepointEntry::kNoDeoptIndex) {
    CHECK(data.is_null());
    FATAL(
        "Missing deoptimization information for OptimizedJSFrame::Summarize.");
  }

  DeoptimizationFrameTranslation::Iterator it(
      data->FrameTranslation(), data->TranslationIndex(deopt_index).value());
  // Search the innermost interpreter frame and get its bailout id. The
  // translation stores frames bottom up.
  int js_frames = it.EnterBeginOpcode().js_frame_count;
  DCHECK_GT(js_frames, 0);
  BytecodeOffset offset = BytecodeOffset::None();
  while (js_frames > 0) {
    TranslationOpcode frame = it.SeekNextJSFrame();
    --js_frames;
    if (IsTranslationInterpreterFrameOpcode(frame)) {
      offset = BytecodeOffset(it.NextOperand());
      it.SkipOperands(TranslationOpcodeOperandCount(frame) - 1);
    } else {
      it.SkipOperands(TranslationOpcodeOperandCount(frame));
    }
  }

  return offset;
}

bool CommonFrame::HasTaggedOutgoingParams(
    Tagged<GcSafeCode> code_lookup) const {
#if V8_ENABLE_WEBASSEMBLY
  // With inlined JS-to-Wasm calls, we can be in an OptimizedJSFrame and
  // directly call a Wasm function from JavaScript. In this case the Wasm frame
  // is responsible for visiting incoming potentially tagged parameters.
  // (This is required for tail-call support: If the direct callee tail-called
  // another function which then caused a GC, the caller would not be able to
  // determine where there might be tagged parameters.)
  wasm::WasmCode* wasm_callee =
      wasm::GetWasmCodeManager()->LookupCode(isolate(), callee_pc());
  if (wasm_callee) return false;

  Tagged<Code> wrapper =
      isolate()->builtins()->code(Builtin::kWasmToJsWrapperCSA);
  if (callee_pc() >= wrapper->instruction_start() &&
      callee_pc() <= wrapper->instruction_end()) {
    return false;
  }
  return code_lookup->has_tagged_outgoing_params();
#else
  return code_lookup->has_tagged_outgoing_params();
#endif  // V8_ENABLE_WEBASSEMBLY
}

Tagged<HeapObject> TurbofanStubWithContextFrame::unchecked_code() const {
  std::optional<Tagged<GcSafeCode>> code_lookup =
      isolate()->heap()->GcSafeTryFindCodeForInnerPointer(pc());
  if (!code_lookup.has_value()) return {};
  return code_lookup.value();
}

void CommonFrame::IterateTurbofanJSOptimizedFrame(RootVisitor* v) const {
  DCHECK(!iterator_->IsStackFrameIteratorForProfiler());

  //  ===  TurbofanJSFrame ===
  //  +-----------------+-----------------------------------------
  //  |   out_param n   |  <-- parameters_base / sp
  //  |       ...       |
  //  |   out_param 0   |
  //  +-----------------+-----------------------------------------
  //  |   spill_slot n  | <-- parameters_limit           ^
  //  |       ...       |                          spill_slot_count
  //  |   spill_slot 0  |                                v
  //  +-----------------+-----------------------------------------
  //  |      argc       |  <-- frame_header_base         ^
  //  |- - - - - - - - -|                                |
  //  |   JSFunction    |                                |
  //  |- - - - - - - - -|                                |
  //  |    Context      |                                |
  //  |- - - - - - - - -|                           kFixedSlotCount
  //  | [Constant Pool] |                                |
  //  |- - - - - - - - -|                                |
  //  | saved frame ptr |  <-- fp                        |
  //  |- - - - - - - - -|                                |
  //  |  return addr    |                                v
  //  +-----------------+-----------------------------------------

  // Find the code and compute the safepoint information.
  const Address inner_pointer = maybe_unauthenticated_pc();
  InnerPointerToCodeCache::InnerPointerToCodeCacheEntry* entry =
      isolate()->inner_pointer_to_code_cache()->GetCacheEntry(inner_pointer);
  CHECK(entry->code.has_value());
  Tagged<GcSafeCode> code = entry->code.value();
  DCHECK(code->is_turbofanned());
  SafepointEntry safepoint_entry =
      GetSafepointEntryFromCodeCache(isolate(), inner_pointer, entry);

#ifdef DEBUG
  // Assert that it is a JS frame and it has a context.
  intptr_t marker =
      Memory<intptr_t>(fp() + CommonFrameConstants::kContextOrFrameTypeOffset);
  DCHECK(!StackFrame::IsTypeMarker(marker));
#endif  // DEBUG

  // Determine the fixed header and spill slot area size.
  int frame_header_size = StandardFrameConstants::kFixedFrameSizeFromFp;
  int spill_slot_count =
      code->stack_slots() - StandardFrameConstants::kFixedSlotCount;

  // Fixed frame slots.
  FullObjectSlot frame_header_base(&Memory<Address>(fp() - frame_header_size));
  FullObjectSlot frame_header_limit(
      &Memory<Address>(fp() - StandardFrameConstants::kCPSlotSize));

  FullObjectSlot parameters_limit = frame_header_base - spill_slot_count;

  if (!InFastCCall()) {
    // Parameters passed to the callee.
    FullObjectSlot parameters_base(&Memory<Address>(sp()));

    // Visit the outgoing parameters if they are tagged.
    if (HasTaggedOutgoingParams(code)) {
      v->VisitRootPointers(Root::kStackRoots, nullptr, parameters_base,
                           parameters_limit);
    }
  } else {
    // There are no outgoing parameters to visit for fast C calls.
  }

  // Spill slots are in the region ]frame_header_base, parameters_limit];
  // Visit pointer spill slots and locals.
  DCHECK_GE((code->stack_slots() + kBitsPerByte) / kBitsPerByte,
            safepoint_entry.tagged_slots().size());
  VisitSpillSlots(isolate(), v, parameters_limit,
                  safepoint_entry.tagged_slots());

  // Visit fixed header region (the context and JSFunction), skipping the
  // argument count since it is stored untagged.
  v->VisitRootPointers(Root::kStackRoots, nullptr, frame_header_base + 1,
                       frame_header_limit);

  // Visit the return address in the callee and incoming arguments.
  IteratePc(v, constant_pool_address(), code);
}

void TurbofanStubWithContextFrame::Iterate(RootVisitor* v) const {
  return IterateTurbofanJSOptimizedFrame(v);
}

void TurbofanJSFrame::Iterate(RootVisitor* v) const {
  return IterateTurbofanJSOptimizedFrame(v);
}

Tagged<HeapObject> StubFrame::unchecked_code() const {
  std::optional<Tagged<GcSafeCode>> code_lookup =
      isolate()->heap()->GcSafeTryFindCodeForInnerPointer(pc());
  if (!code_lookup.has_value()) return {};
  return code_lookup.value();
}

int StubFrame::LookupExceptionHandlerInTable() {
  Tagged<Code> code;
  int pc_offset = -1;
  std::tie(code, pc_offset) = LookupCodeAndOffset();
  DCHECK(code->is_turbofanned());
  DCHECK(code->has_handler_table());
  HandlerTable table(code);
  return table.LookupReturn(pc_offset);
}

void StubFrame::Summarize(std::vector<FrameSummary>* frames) const {
#if V8_ENABLE_WEBASSEMBLY
  Tagged<Code> code = LookupCode();
  if (code->kind() != CodeKind::BUILTIN) return;
  // We skip most stub frames from stack traces, but a few builtins
  // specifically exist to pretend to be another builtin throwing an
  // exception.
  switch (code->builtin_id()) {
    case Builtin::kThrowDataViewTypeError:
    case Builtin::kThrowDataViewDetachedError:
    case Builtin::kThrowDataViewOutOfBounds:
    case Builtin::kThrowIndexOfCalledOnNull:
    case Builtin::kThrowToLowerCaseCalledOnNull:
    case Builtin::kWasmIntToString: {
      // When adding builtins here, also implement naming support for them.
      DCHECK_NE(nullptr,
                Builtins::NameForStackTrace(isolate(), code->builtin_id()));
      FrameSummary::BuiltinFrameSummary summary(isolate(), code->builtin_id());
      frames->push_back(summary);
      break;
    }
    default:
      break;
  }
#endif  // V8_ENABLE_WEBASSEMBLY
}

void JavaScriptFrame::SetParameterValue(int index, Tagged<Object> value) const {
  Memory<Address>(GetParameterSlot(index)) = value.ptr();
}

bool JavaScriptFrame::IsConstructor() const {
  return IsConstructFrame(caller_fp());
}

Tagged<HeapObject> CommonFrameWithJSLinkage::unchecked_code() const {
  return function()->code(isolate());
}

int TurbofanJSFrame::ComputeParametersCount() const {
  if (GcSafeLookupCode()->kind() == CodeKind::BUILTIN) {
    return static_cast<int>(
               Memory<intptr_t>(fp() + StandardFrameConstants::kArgCOffset)) -
           kJSArgcReceiverSlots;
  } else {
    return JavaScriptFrame::ComputeParametersCount();
  }
}

Address JavaScriptFrame::GetCallerStackPointer() const {
  return fp() + StandardFrameConstants::kCallerSPOffset;
}

void JavaScriptFrame::GetFunctions(
    std::vector<Tagged<SharedFunctionInfo>>* functions) const {
  DCHECK(functions->empty());
  functions->push_back(function()->shared());
}

void JavaScriptFrame::GetFunctions(
    std::vector<Handle<SharedFunctionInfo>>* functions) const {
  DCHECK(functions->empty());
  std::vector<Tagged<SharedFunctionInfo>> raw_functions;
  GetFunctions(&raw_functions);
  for (const auto& raw_function : raw_functions) {
    functions->push_back(
        Handle<SharedFunctionInfo>(raw_function, function()->GetIsolate()));
  }
}

std::tuple<Tagged<AbstractCode>, int> JavaScriptFrame::GetActiveCodeAndOffset()
    const {
  int code_offset = 0;
  Tagged<AbstractCode> abstract_code;
  if (is_interpreted()) {
    const InterpretedFrame* iframe = InterpretedFrame::cast(this);
    code_offset = iframe->GetBytecodeOffset();
    abstract_code = Cast<AbstractCode>(iframe->GetBytecodeArray());
  } else if (is_baseline()) {
    // TODO(pthier): AbstractCode should fully support Baseline code.
    const BaselineFrame* baseline_frame = BaselineFrame::cast(this);
    code_offset = baseline_frame->GetBytecodeOffset();
    abstract_code = Cast<AbstractCode>(baseline_frame->GetBytecodeArray());
  } else {
    Tagged<Code> code;
    int pc_offset = -1;
    std::tie(code, pc_offset) = LookupCodeAndOffset();
    abstract_code = Cast<AbstractCode>(code);
  }
  return {abstract_code, code_offset};
}

bool CommonFrameWithJSLinkage::IsConstructor() const {
  return IsConstructFrame(caller_fp());
}

void CommonFrameWithJSLinkage::Summarize(
    std::vector<FrameSummary>* functions) const {
  DCHECK(functions->empty());
  Tagged<GcSafeCode> code;
  int offset = -1;
  std::tie(code, offset) = GcSafeLookupCodeAndOffset();
  DirectHandle<AbstractCode> abstract_code(
      Cast<AbstractCode>(code->UnsafeCastToCode()), isolate());
  DirectHandle<FixedArray> params = GetParameters();
  FrameSummary::JavaScriptFrameSum
"""


```