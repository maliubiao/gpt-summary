Response: The user wants me to summarize the functionality of the provided C++ code snippet from `v8/src/execution/frames.cc`. This is the second part of a three-part sequence, implying I should continue the summarization from the previous part and potentially anticipate the content of the next part. The code primarily deals with stack frame manipulation and iteration for different frame types in V8, specifically related to garbage collection and debugging.

I need to identify the different frame types being handled and the operations performed on them, such as iterating through parameters, spill slots, and header information. The code also seems to interact with the Wasm part of V8.

If there's a connection to JavaScript, I need to illustrate it with a simple example. Given that this code deals with the internal representation of execution stacks, the connection to JavaScript lies in how JavaScript function calls translate to these stack frames.
这是 `v8/src/execution/frames.cc` 文件的一部分，主要负责处理 V8 虚拟机中不同类型的栈帧的迭代和信息提取，特别是在垃圾回收 (GC) 过程中遍历栈上的对象引用。

**主要功能归纳:**

1. **处理 WebAssembly 相关的栈帧:**
   - 代码片段开始部分处理 `WasmFrame` (WebAssembly 函数的栈帧) 和 `WasmExitFrame` (从 WebAssembly 调用 JavaScript 的栈帧)。
   - 它查找与当前程序计数器 (PC) 关联的 `WasmCode` 对象和安全点信息 (`SafepointEntry`)，这些信息用于确定栈帧的布局和哪些栈槽可能包含对象引用。
   - 它会区分 Liftoff 编译的代码，因为 Liftoff 代码可能包含额外的反馈槽。
   - 代码遍历了 WebAssembly 栈帧的不同部分：
     - **固定帧头 (frame header):** 包含元数据，如保存的帧指针、返回地址等。
     - **溢出槽 (spill slots):**  用于存储寄存器中无法容纳的局部变量。
     - **传递给被调用函数的参数 (parameters):** 这部分需要考虑栈切换的情况。
     - **传递给当前函数的标记参数 (tagged parameters):**  这些参数实际上属于父帧。
     - **实例对象 (instance object):** 代表 WebAssembly 实例。
   -  `TypedFrame::IterateParamsOfGenericWasmToJSWrapper` 和 `TypedFrame::IterateParamsOfOptimizedWasmToJSWrapper` 函数专门处理从 WebAssembly 调用 JavaScript 的包装器的参数迭代，区分了通用包装器和优化包装器，并考虑了参数的寄存器分配和栈布局。

2. **处理 `TypedFrame` (Turbofan 编译的 JavaScript 函数的栈帧):**
   - `TypedFrame::Iterate` 函数用于遍历 Turbofan 编译的 JavaScript 函数的栈帧。
   - 它也通过程序计数器查找 `GcSafeCode` 对象和安全点信息。
   - 它遍历了固定帧头、溢出槽和传递给被调用函数的参数。
   - 它还调用 `IteratePc` 来访问返回地址。

3. **处理 `MaglevFrame` (Maglev 编译的 JavaScript 函数的栈帧):**
   - `MaglevFrame::Iterate` 函数用于遍历 Maglev 编译的 JavaScript 函数的栈帧。
   - 它使用 `MaglevSafepointEntry` 来获取更精细的安全点信息。
   - 除了标准的帧头、溢出槽和参数，它还处理 Maglev 特有的**额外的溢出槽 (extra spill slots)**，这些槽用于存储在调用之前溢出的寄存器。
   - `MaglevFrame::GetInnermostFunction` 和 `MaglevFrame::GetBytecodeOffsetForOSR` 用于获取帧对应的最内层函数和执行优化的字节码偏移量。

4. **通用栈帧迭代 (`TypedFrame::Iterate`, `MaglevFrame::Iterate`):**
   - 这些 `Iterate` 函数的核心任务是在垃圾回收过程中，通过 `RootVisitor` (`v`) 访问栈帧中可能包含对象引用的位置，以确保这些对象不会被错误地回收。

5. **检查传出参数是否被标记 (`CommonFrame::HasTaggedOutgoingParams`):**
   - 此函数用于判断当前栈帧调用的函数是否有可能接收标记的对象作为参数。这在 GC 过程中很重要，因为标记的对象需要被扫描。对于 WebAssembly 调用 JavaScript 的情况，需要特别处理。

**与 JavaScript 的关系及示例:**

这些 C++ 代码直接对应于 JavaScript 函数调用在 V8 虚拟机内部的执行状态。当 JavaScript 代码调用一个函数时，V8 会在栈上创建一个栈帧来记录该调用的信息，例如局部变量、参数、返回地址等。

**JavaScript 示例:**

```javascript
function foo(a, b) {
  let x = { value: a + b }; // 对象 'x' 可能会被存储在栈帧的溢出槽中
  return x.value;
}

function bar() {
  let y = 10;
  return foo(5, y); // 调用 'foo' 会创建一个新的栈帧
}

bar();
```

在这个例子中：

- 当 `bar()` 调用 `foo()` 时，会创建一个 `JavaScriptFrame` (如果 `foo` 没有被优化) 或 `TypedFrame`/`MaglevFrame` (如果 `foo` 被 Turbofan 或 Maglev 优化)。
- `frames.cc` 中的代码会遍历 `foo` 的栈帧，查找可能包含对象引用的位置。例如，局部变量 `x` 引用的对象 `{ value: a + b }` 可能会被存储在栈帧的溢出槽中。垃圾回收器需要能够找到这个引用以避免过早回收该对象。
- 对于 WebAssembly，如果 JavaScript 调用了一个 WebAssembly 函数，则会创建一个 `WasmFrame`。如果 WebAssembly 函数调用了 JavaScript 函数，则会创建一个 `WasmExitFrame`。`frames.cc` 中的代码负责正确地遍历这些类型的栈帧。

**总结:**

这部分 `frames.cc` 的代码是 V8 虚拟机实现的核心部分，它定义了如何理解和操作不同类型的函数调用在执行栈上的表示。这对于垃圾回收器正确识别和保留活动对象至关重要，同时也为调试器和性能分析工具提供了必要的信息。
Prompt: 
```
这是目录为v8/src/execution/frames.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共3部分，请归纳一下它的功能

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
  FrameSummary::JavaScriptFrameSummary summary(
      isolate(), receiver(), function(), *abstract_code, offset,
      IsConstructor(), *params);
  functions->push_back(summary);
}

Tagged<JSFunction> JavaScriptFrame::function() const {
  return Cast<JSFunction>(function_slot_object());
}

Tagged<Object> JavaScriptFrame::unchecked_function() const {
  // During deoptimization of an optimized function, we may have yet to
  // materialize some closures on the stack. The arguments marker object
  // marks this case.
  DCHECK(IsJSFunction(function_slot_object()) ||
         ReadOnlyRoots(isolate()).arguments_marker() == function_slot_object());
  return function_slot_object();
}

Tagged<Object> CommonFrameWithJSLinkage::receiver() const {
  // TODO(cbruni): document this better
  return GetParameter(-1);
}

Tagged<Object> JavaScriptFrame::context() const {
  const int offset = StandardFrameConstants::kContextOffset;
  Tagged<Object> maybe_result(Memory<Address>(fp() + offset));
  DCHECK(!IsSmi(maybe_result));
  return maybe_result;
}

Tagged<Script> JavaScriptFrame::script() const {
  return Cast<Script>(function()->shared()->script());
}

int CommonFrameWithJSLinkage::LookupExceptionHandlerInTable(
    int* stack_depth, HandlerTable::CatchPrediction* prediction) {
  if (DEBUG_BOOL) {
    Tagged<Code> code_lookup_result = LookupCode();
    CHECK(!code_lookup_result->has_handler_table());
    CHECK(!code_lookup_result->is_optimized_code() ||
          code_lookup_result->kind() == CodeKind::BASELINE);
  }
  return -1;
}

void JavaScriptFrame::PrintFunctionAndOffset(Isolate* isolate,
                                             Tagged<JSFunction> function,
                                             Tagged<AbstractCode> code,
                                             int code_offset, FILE* file,
                                             bool print_line_number) {
  PtrComprCageBase cage_base = GetPtrComprCageBase(function);
  PrintF(file, "%s", CodeKindToMarker(code->kind(cage_base)));
  function->PrintName(file);
  PrintF(file, "+%d", code_offset);
  if (print_line_number) {
    Tagged<SharedFunctionInfo> shared = function->shared();
    int source_pos = code->SourcePosition(isolate, code_offset);
    Tagged<Object> maybe_script = shared->script();
    if (IsScript(maybe_script)) {
      Tagged<Script> script = Cast<Script>(maybe_script);
      int line = script->GetLineNumber(source_pos) + 1;
      Tagged<Object> script_name_raw = script->name();
      if (IsString(script_name_raw)) {
        Tagged<String> script_name = Cast<String>(script->name());
        std::unique_ptr<char[]> c_script_name = script_name->ToCString();
        PrintF(file, " at %s:%d", c_script_name.get(), line);
      } else {
        PrintF(file, " at <unknown>:%d", line);
      }
    } else {
      PrintF(file, " at <unknown>:<unknown>");
    }
  }
}

void JavaScriptFrame::PrintTop(Isolate* isolate, FILE* file, bool print_args,
                               bool print_line_number) {
  // constructor calls
  DisallowGarbageCollection no_gc;
  JavaScriptStackFrameIterator it(isolate);
  while (!it.done()) {
    if (it.frame()->is_javascript()) {
      JavaScriptFrame* frame = it.frame();
      if (frame->IsConstructor()) PrintF(file, "new ");
      Tagged<JSFunction> function = frame->function();
      int code_offset = 0;
      Tagged<AbstractCode> code;
      std::tie(code, code_offset) = frame->GetActiveCodeAndOffset();
      PrintFunctionAndOffset(isolate, function, code, code_offset, file,
                             print_line_number);
      if (print_args) {
        // function arguments
        // (we are intentionally only printing the actually
        // supplied parameters, not all parameters required)
        PrintF(file, "(this=");
        ShortPrint(frame->receiver(), file);
        const int length = frame->ComputeParametersCount();
        for (int i = 0; i < length; i++) {
          PrintF(file, ", ");
          ShortPrint(frame->GetParameter(i), file);
        }
        PrintF(file, ")");
      }
      break;
    }
    it.Advance();
  }
}

// static
void JavaScriptFrame::CollectFunctionAndOffsetForICStats(
    Isolate* isolate, Tagged<JSFunction> function, Tagged<AbstractCode> code,
    int code_offset) {
  auto ic_stats = ICStats::instance();
  ICInfo& ic_info = ic_stats->Current();
  PtrComprCageBase cage_base = GetPtrComprCageBase(function);
  Tagged<SharedFunctionInfo> shared = function->shared(cage_base);

  ic_info.function_name = ic_stats->GetOrCacheFunctionName(isolate, function);
  ic_info.script_offset = code_offset;

  int source_pos = code->SourcePosition(isolate, code_offset);
  Tagged<Object> maybe_script = shared->script(cage_base, kAcquireLoad);
  if (IsScript(maybe_script, cage_base)) {
    Tagged<Script> script = Cast<Script>(maybe_script);
    Script::PositionInfo info;
    script->GetPositionInfo(source_pos, &info);
    ic_info.line_num = info.line + 1;
    ic_info.column_num = info.column + 1;
    ic_info.script_name = ic_stats->GetOrCacheScriptName(script);
  }
}

Tagged<Object> CommonFrameWithJSLinkage::GetParameter(int index) const {
  return Tagged<Object>(Memory<Address>(GetParameterSlot(index)));
}

int CommonFrameWithJSLinkage::ComputeParametersCount() const {
  DCHECK(!iterator_->IsStackFrameIteratorForProfiler() &&
         isolate()->heap()->gc_state() == Heap::NOT_IN_GC);
  return function()
      ->shared()
      ->internal_formal_parameter_count_without_receiver();
}

int JavaScriptFrame::GetActualArgumentCount() const {
  return static_cast<int>(
             Memory<intptr_t>(fp() + StandardFrameConstants::kArgCOffset)) -
         kJSArgcReceiverSlots;
}

Handle<FixedArray> CommonFrameWithJSLinkage::GetParameters() const {
  if (V8_LIKELY(!v8_flags.detailed_error_stack_trace)) {
    return isolate()->factory()->empty_fixed_array();
  }
  int param_count = ComputeParametersCount();
  Handle<FixedArray> parameters =
      isolate()->factory()->NewFixedArray(param_count);
  for (int i = 0; i < param_count; i++) {
    parameters->set(i, GetParameter(i));
  }

  return parameters;
}

Tagged<JSFunction> JavaScriptBuiltinContinuationFrame::function() const {
  const int offset = BuiltinContinuationFrameConstants::kFunctionOffset;
  return Cast<JSFunction>(Tagged<Object>(base::Memory<Address>(fp() + offset)));
}

int JavaScriptBuiltinContinuationFrame::ComputeParametersCount() const {
  // Assert that the first allocatable register is also the argument count
  // register.
  DCHECK_EQ(RegisterConfiguration::Default()->GetAllocatableGeneralCode(0),
            kJavaScriptCallArgCountRegister.code());
  Tagged<Object> argc_object(
      Memory<Address>(fp() + BuiltinContinuationFrameConstants::kArgCOffset));
  return Smi::ToInt(argc_object) - kJSArgcReceiverSlots;
}

intptr_t JavaScriptBuiltinContinuationFrame::GetSPToFPDelta() const {
  Address height_slot =
      fp() + BuiltinContinuationFrameConstants::kFrameSPtoFPDeltaAtDeoptimize;
  intptr_t height = Smi::ToInt(Tagged<Smi>(Memory<Address>(height_slot)));
  return height;
}

Tagged<Object> JavaScriptBuiltinContinuationFrame::context() const {
  return Tagged<Object>(Memory<Address>(
      fp() + BuiltinContinuationFrameConstants::kBuiltinContextOffset));
}

void JavaScriptBuiltinContinuationWithCatchFrame::SetException(
    Tagged<Object> exception) {
  int argc = ComputeParametersCount();
  Address exception_argument_slot =
      fp() + BuiltinContinuationFrameConstants::kFixedFrameSizeAboveFp +
      (argc - 1) * kSystemPointerSize;

  // Only allow setting exception if previous value was the hole.
  CHECK_EQ(ReadOnlyRoots(isolate()).the_hole_value(),
           Tagged<Object>(Memory<Address>(exception_argument_slot)));
  Memory<Address>(exception_argument_slot) = exception.ptr();
}

FrameSummary::JavaScriptFrameSummary::JavaScriptFrameSummary(
    Isolate* isolate, Tagged<Object> receiver, Tagged<JSFunction> function,
    Tagged<AbstractCode> abstract_code, int code_offset, bool is_constructor,
    Tagged<FixedArray> parameters)
    : FrameSummaryBase(isolate, FrameSummary::JAVASCRIPT),
      receiver_(receiver, isolate),
      function_(function, isolate),
      abstract_code_(abstract_code, isolate),
      code_offset_(code_offset),
      is_constructor_(is_constructor),
      parameters_(parameters, isolate) {
  DCHECK_IMPLIES(CodeKindIsOptimizedJSFunction(abstract_code->kind(isolate)),
                 // It might be an ApiCallbackBuiltin inlined into optimized
                 // code generated by Maglev.
                 (v8_flags.maglev_inline_api_calls &&
                  abstract_code->kind(isolate) == CodeKind::MAGLEV &&
                  function->shared()->IsApiFunction()));
}

void FrameSummary::EnsureSourcePositionsAvailable() {
  if (IsJavaScript()) {
    javascript_summary_.EnsureSourcePositionsAvailable();
  }
}

bool FrameSummary::AreSourcePositionsAvailable() const {
  if (IsJavaScript()) {
    return javascript_summary_.AreSourcePositionsAvailable();
  }
  return true;
}

void FrameSummary::JavaScriptFrameSummary::EnsureSourcePositionsAvailable() {
  Handle<SharedFunctionInfo> shared(function()->shared(), isolate());
  SharedFunctionInfo::EnsureSourcePositionsAvailable(isolate(), shared);
}

bool FrameSummary::JavaScriptFrameSummary::AreSourcePositionsAvailable() const {
  return !v8_flags.enable_lazy_source_positions ||
         function()
             ->shared()
             ->GetBytecodeArray(isolate())
             ->HasSourcePositionTable();
}

bool FrameSummary::JavaScriptFrameSummary::is_subject_to_debugging() const {
  return function()->shared()->IsSubjectToDebugging();
}

int FrameSummary::JavaScriptFrameSummary::SourcePosition() const {
  return abstract_code()->SourcePosition(isolate(), code_offset());
}

int FrameSummary::JavaScriptFrameSummary::SourceStatementPosition() const {
  return abstract_code()->SourceStatementPosition(isolate(), code_offset());
}

Handle<Object> FrameSummary::JavaScriptFrameSummary::script() const {
  return handle(function_->shared()->script(), isolate());
}

Handle<Context> FrameSummary::JavaScriptFrameSummary::native_context() const {
  return handle(function_->native_context(), isolate());
}

Handle<StackFrameInfo>
FrameSummary::JavaScriptFrameSummary::CreateStackFrameInfo() const {
  Handle<SharedFunctionInfo> shared(function_->shared(), isolate());
  DirectHandle<Script> script(Cast<Script>(shared->script()), isolate());
  DirectHandle<String> function_name = JSFunction::GetDebugName(function_);
  if (function_name->length() == 0 &&
      script->compilation_type() == Script::CompilationType::kEval) {
    function_name = isolate()->factory()->eval_string();
  }
  int bytecode_offset = code_offset();
  if (bytecode_offset == kFunctionEntryBytecodeOffset) {
    // For the special function entry bytecode offset (-1), which signals
    // that the stack trace was captured while the function entry was
    // executing (i.e. during the interrupt check), we cannot store this
    // sentinel in the bit field, so we just eagerly lookup the source
    // position within the script.
    SharedFunctionInfo::EnsureSourcePositionsAvailable(isolate(), shared);
    int source_position =
        abstract_code()->SourcePosition(isolate(), bytecode_offset);
    return isolate()->factory()->NewStackFrameInfo(
        script, source_position, function_name, is_constructor());
  }
  return isolate()->factory()->NewStackFrameInfo(
      shared, bytecode_offset, function_name, is_constructor());
}

#if V8_ENABLE_WEBASSEMBLY
FrameSummary::WasmFrameSummary::WasmFrameSummary(
    Isolate* isolate, Handle<WasmTrustedInstanceData> instance_data,
    wasm::WasmCode* code, int byte_offset, int function_index,
    bool at_to_number_conversion)
    : FrameSummaryBase(isolate, WASM),
      instance_data_(instance_data),
      at_to_number_conversion_(at_to_number_conversion),
      code_(code),
      byte_offset_(byte_offset),
      function_index_(function_index) {}

Handle<Object> FrameSummary::WasmFrameSummary::receiver() const {
  return isolate()->global_proxy();
}

uint32_t FrameSummary::WasmFrameSummary::function_index() const {
  return function_index_;
}

int FrameSummary::WasmFrameSummary::SourcePosition() const {
  const wasm::WasmModule* module = wasm_trusted_instance_data()->module();
  return GetSourcePosition(module, function_index(), code_offset(),
                           at_to_number_conversion());
}

Handle<Script> FrameSummary::WasmFrameSummary::script() const {
  return handle(wasm_instance()->module_object()->script(), isolate());
}

Handle<WasmInstanceObject> FrameSummary::WasmFrameSummary::wasm_instance()
    const {
  // TODO(42204563): Avoid crashing if the instance object is not available.
  CHECK(instance_data_->has_instance_object());
  return handle(instance_data_->instance_object(), isolate());
}

Handle<Context> FrameSummary::WasmFrameSummary::native_context() const {
  return handle(wasm_trusted_instance_data()->native_context(), isolate());
}

Handle<StackFrameInfo> FrameSummary::WasmFrameSummary::CreateStackFrameInfo()
    const {
  DirectHandle<String> function_name =
      GetWasmFunctionDebugName(isolate(), instance_data_, function_index());
  return isolate()->factory()->NewStackFrameInfo(script(), SourcePosition(),
                                                 function_name, false);
}

FrameSummary::WasmInlinedFrameSummary::WasmInlinedFrameSummary(
    Isolate* isolate, Handle<WasmTrustedInstanceData> instance_data,
    int function_index, int op_wire_bytes_offset)
    : FrameSummaryBase(isolate, WASM_INLINED),
      instance_data_(instance_data),
      function_index_(function_index),
      op_wire_bytes_offset_(op_wire_bytes_offset) {}

Handle<WasmInstanceObject>
FrameSummary::WasmInlinedFrameSummary::wasm_instance() const {
  // TODO(42204563): Avoid crashing if the instance object is not available.
  CHECK(instance_data_->has_instance_object());
  return handle(instance_data_->instance_object(), isolate());
}

Handle<Object> FrameSummary::WasmInlinedFrameSummary::receiver() const {
  return isolate()->global_proxy();
}

uint32_t FrameSummary::WasmInlinedFrameSummary::function_index() const {
  return function_index_;
}

int FrameSummary::WasmInlinedFrameSummary::SourcePosition() const {
  const wasm::WasmModule* module = instance_data_->module();
  return GetSourcePosition(module, function_index(), code_offset(), false);
}

Handle<Script> FrameSummary::WasmInlinedFrameSummary::script() const {
  return handle(wasm_instance()->module_object()->script(), isolate());
}

Handle<Context> FrameSummary::WasmInlinedFrameSummary::native_context() const {
  return handle(wasm_trusted_instance_data()->native_context(), isolate());
}

Handle<StackFrameInfo>
FrameSummary::WasmInlinedFrameSummary::CreateStackFrameInfo() const {
  DirectHandle<String> function_name =
      GetWasmFunctionDebugName(isolate(), instance_data_, function_index());
  return isolate()->factory()->NewStackFrameInfo(script(), SourcePosition(),
                                                 function_name, false);
}

#if V8_ENABLE_DRUMBRAKE
FrameSummary::WasmInterpretedFrameSummary::WasmInterpretedFrameSummary(
    Isolate* isolate, Handle<WasmInstanceObject> instance,
    uint32_t function_index, int byte_offset)
    : FrameSummaryBase(isolate, WASM_INTERPRETED),
      wasm_instance_(instance),
      function_index_(function_index),
      byte_offset_(byte_offset) {}

Handle<Object> FrameSummary::WasmInterpretedFrameSummary::receiver() const {
  return wasm_instance_->GetIsolate()->global_proxy();
}

int FrameSummary::WasmInterpretedFrameSummary::SourcePosition() const {
  const wasm::WasmModule* module = wasm_instance()->module_object()->module();
  return GetSourcePosition(module, function_index(), byte_offset(),
                           false /*at_to_number_conversion*/);
}

Handle<WasmTrustedInstanceData>
FrameSummary::WasmInterpretedFrameSummary::instance_data() const {
  return handle(wasm_instance_->trusted_data(isolate()), isolate());
}

Handle<Script> FrameSummary::WasmInterpretedFrameSummary::script() const {
  return handle(wasm_instance()->module_object()->script(),
                wasm_instance()->GetIsolate());
}

Handle<Context> FrameSummary::WasmInterpretedFrameSummary::native_context()
    const {
  return handle(wasm_instance_->trusted_data(isolate())->native_context(),
                isolate());
}

Handle<StackFrameInfo>
FrameSummary::WasmInterpretedFrameSummary::CreateStackFrameInfo() const {
  Handle<String> function_name =
      GetWasmFunctionDebugName(isolate(), instance_data(), function_index());
  return isolate()->factory()->NewStackFrameInfo(script(), SourcePosition(),
                                                 function_name, false);
}
#endif  // V8_ENABLE_DRUMBRAKE

FrameSummary::BuiltinFrameSummary::BuiltinFrameSummary(Isolate* isolate,
                                                       Builtin builtin)
    : FrameSummaryBase(isolate, FrameSummary::BUILTIN), builtin_(builtin) {}

Handle<Object> FrameSummary::BuiltinFrameSummary::receiver() const {
  return isolate()->factory()->undefined_value();
}

Handle<Object> FrameSummary::BuiltinFrameSummary::script() const {
  return isolate()->factory()->undefined_value();
}

Handle<Context> FrameSummary::BuiltinFrameSummary::native_context() const {
  return isolate()->native_context();
}

Handle<StackFrameInfo> FrameSummary::BuiltinFrameSummary::CreateStackFrameInfo()
    const {
  DirectHandle<String> name_str =
      isolate()->factory()->NewStringFromAsciiChecked(
          Builtins::NameForStackTrace(isolate(), builtin_));
  return isolate()->factory()->NewStackFrameInfo(
      Cast<Script>(script()), SourcePosition(), name_str, false);
}

#endif  // V8_ENABLE_WEBASSEMBLY

FrameSummary::~FrameSummary() {
#define FRAME_SUMMARY_DESTR(kind, type, field, desc) \
  case kind:                                         \
    field.~type();                                   \
    break;
  switch (base_.kind()) {
    FRAME_SUMMARY_VARIANTS(FRAME_SUMMARY_DESTR)
    default:
      UNREACHABLE();
  }
#undef FRAME_SUMMARY_DESTR
}

FrameSummary FrameSummary::GetTop(const CommonFrame* frame) {
  std::vector<FrameSummary> frames;
  frame->Summarize(&frames);
  DCHECK_LT(0, frames.size());
  return frames.back();
}

FrameSummary FrameSummary::GetBottom(const CommonFrame* frame) {
  return Get(frame, 0);
}

FrameSummary FrameSummary::GetSingle(const CommonFrame* frame) {
  std::vector<FrameSummary> frames;
  frame->Summarize(&frames);
  DCHECK_EQ(1, frames.size());
  return frames.front();
}

FrameSummary FrameSummary::Get(const CommonFrame* frame, int index) {
  DCHECK_LE(0, index);
  std::vector<FrameSummary> frames;
  frame->Summarize(&frames);
  DCHECK_GT(frames.size(), index);
  return frames[index];
}

#if V8_ENABLE_WEBASSEMBLY
#ifdef V8_ENABLE_DRUMBRAKE
#define CASE_WASM_INTERPRETED(name) \
  case WASM_INTERPRETED:            \
    return wasm_interpreted_summary_.name();
#else  // V8_ENABLE_DRUMBRAKE
#define CASE_WASM_INTERPRETED(name)
#endif  // V8_ENABLE_DRUMBRAKE
#define FRAME_SUMMARY_DISPATCH(ret, name)    \
  ret FrameSummary::name() const {           \
    switch (base_.kind()) {                  \
      case JAVASCRIPT:                       \
        return javascript_summary_.name();   \
      case WASM:                             \
        return wasm_summary_.name();         \
      case WASM_INLINED:                     \
        return wasm_inlined_summary_.name(); \
      case BUILTIN:                          \
        return builtin_summary_.name();      \
        CASE_WASM_INTERPRETED(name)          \
      default:                               \
        UNREACHABLE();                       \
    }                                        \
  }
#else
#define FRAME_SUMMARY_DISPATCH(ret, name) \
  ret FrameSummary::name() const {        \
    DCHECK_EQ(JAVASCRIPT, base_.kind());  \
    return javascript_summary_.name();    \
  }
#endif  // V8_ENABLE_WEBASSEMBLY

FRAME_SUMMARY_DISPATCH(Handle<Object>, receiver)
FRAME_SUMMARY_DISPATCH(int, code_offset)
FRAME_SUMMARY_DISPATCH(bool, is_constructor)
FRAME_SUMMARY_DISPATCH(bool, is_subject_to_debugging)
FRAME_SUMMARY_DISPATCH(Handle<Object>, script)
FRAME_SUMMARY_DISPATCH(int, SourcePosition)
FRAME_SUMMARY_DISPATCH(int, SourceStatementPosition)
FRAME_SUMMARY_DISPATCH(Handle<Context>, native_context)
FRAME_SUMMARY_DISPATCH(Handle<StackFrameInfo>, CreateStackFrameInfo)

#undef CASE_WASM_INTERPRETED
#undef FRAME_SUMMARY_DISPATCH

void OptimizedJSFrame::Summarize(std::vector<FrameSummary>* frames) const {
  DCHECK(frames->empty());
  DCHECK(is_optimized());

  // Delegate to JS frame in absence of deoptimization info.
  // TODO(turbofan): Revisit once we support deoptimization across the board.
  DirectHandle<Code> code(LookupCode(), isolate());
  if (code->kind() == CodeKind::BUILTIN) {
    return JavaScriptFrame::Summarize(frames);
  }

  int deopt_index = SafepointEntry::kNoDeoptIndex;
  Tagged<DeoptimizationData> const data =
      GetDeoptimizationData(*code, &deopt_index);
  if (deopt_index == SafepointEntry::kNoDeoptIndex) {
    // Hack: For maglevved function entry, we don't emit lazy deopt information,
    // so create an extra special summary here.
    //
    // TODO(leszeks): Remove this hack, by having a maglev-specific frame
    // summary which is a bit more aware of maglev behaviour and can e.g. handle
    // more compact safepointed frame information for both function entry and
    // loop stack checks.
    if (code->is_maglevved()) {
      DCHECK(frames->empty());
      DirectHandle<AbstractCode> abstract_code(
          Cast<AbstractCode>(function()->shared()->GetBytecodeArray(isolate())),
          isolate());
      DirectHandle<FixedArray> params = GetParameters();
      FrameSummary::JavaScriptFrameSummary summary(
          isolate(), receiver(), function(), *abstract_code,
          kFunctionEntryBytecodeOffset, IsConstructor(), *params);
      frames->push_back(summary);
      return;
    }

    CHECK(data.is_null());
    FATAL(
        "Missing deoptimization information for OptimizedJSFrame::Summarize.");
  }

  // Prepare iteration over translation. We must not materialize values here
  // because we do not deoptimize the function.
  TranslatedState translated(this);
  translated.Prepare(fp());

  // We create the summary in reverse order because the frames
  // in the deoptimization translation are ordered bottom-to-top.
  bool is_constructor = IsConstructor();
  for (auto it = translated.begin(); it != translated.end(); it++) {
    if (it->kind() == TranslatedFrame::kUnoptimizedFunction ||
        it->kind() == TranslatedFrame::kJavaScriptBuiltinContinuation ||
        it->kind() ==
            TranslatedFrame::kJavaScriptBuiltinContinuationWithCatch) {
      DirectHandle<SharedFunctionInfo> shared_info = it->shared_info();

      // The translation commands are ordered and the function is always
      // at the first position, and the receiver is next.
      TranslatedFrame::iterator translated_values = it->begin();

      // Get the correct function in the optimized frame.
      CHECK(!translated_values->IsMaterializedObject());
      DirectHandle<JSFunction> function =
          Cast<JSFunction>(translated_values->GetValue());
      translated_values++;

      // Get the correct receiver in the optimized frame.
      CHECK(!translated_values->IsMaterializedObject());
      DirectHandle<Object> receiver = translated_values->GetValue();
      translated_values++;

      // Determine the underlying code object and the position within it from
      // the translation corresponding to the frame type in question.
      DirectHandle<AbstractCode> abstract_code;
      unsigned code_offset;
      if (it->kind() == TranslatedFrame::kJavaScriptBuiltinContinuation ||
          it->kind() ==
              TranslatedFrame::kJavaScriptBuiltinContinuationWithCatch) {
        code_offset = 0;
        abstract_code = Cast<AbstractCode>(isolate()->builtins()->code_handle(
            Builtins::GetBuiltinFromBytecodeOffset(it->bytecode_offset())));
      } else {
        DCHECK_EQ(it->kind(), TranslatedFrame::kUnoptimizedFunction);
        code_offset = it->bytecode_offset().ToInt();
        abstract_code =
            direct_handle(shared_info->abstract_code(isolate()), isolate());
      }

      // Append full summary of the encountered JS frame.
      DirectHandle<FixedArray> params = GetParameters();
      FrameSummary::JavaScriptFrameSummary summary(
          isolate(), *receiver, *function, *abstract_code, code_offset,
          is_constructor, *params);
      frames->push_back(summary);
      is_constructor = false;
    } else if (it->kind() == TranslatedFrame::kConstructCreateStub ||
               it->kind() == TranslatedFrame::kConstructInvokeStub) {
      // The next encountered JS frame will be marked as a constructor call.
      DCHECK(!is_constructor);
      is_constructor = true;
#if V8_ENABLE_WEBASSEMBLY
    } else if (it->kind() == TranslatedFrame::kWasmInlinedIntoJS) {
      DirectHandle<SharedFunctionInfo> shared_info = it->shared_info();
      DCHECK_NE(isolate()->heap()->gc_state(), Heap::MARK_COMPACT);

      Tagged<WasmExportedFunctionData> function_data =
          shared_info->wasm_exported_function_data();
      Handle<WasmTrustedInstanceData> instance{function_data->instance_data(),
                                               isolate()};
      int func_index = function_data->function_index();
      FrameSummary::WasmInlinedFrameSummary summary(
          isolate(), instance, func_index, it->bytecode_offset().ToInt());
      frames->push_back(summary);
#endif  // V8_ENABLE_WEBASSEMBLY
    }
  }
}

int OptimizedJSFrame::LookupExceptionHandlerInTable(
    int* data, HandlerTable::CatchPrediction* prediction) {
  // We cannot perform exception prediction on optimized code. Instead, we need
  // to use FrameSummary to find the corresponding code offset in unoptimized
  // code to perform prediction there.
  DCHECK_NULL(prediction);
  Tagged<Code> code;
  int pc_offset = -1;
  std::tie(code, pc_offset) = LookupCodeAndOffset();

  HandlerTable table(code);
  if (table.NumberOfReturnEntries() == 0) return -1;

  DCHECK_NULL(data);  // Data is not used and will not return a value.

  // When the return pc has been replaced by a trampoline there won't be
  // a handler for this trampoline. Thus we need to use the return pc that
  // _used to be_ on the stack to get the right ExceptionHandler.
  if (CodeKindCanDeoptimize(code->kind())) {
    if (!code->marked_for_deoptimization()) {
      // Lazy deoptimize the function in case the handler table entry flags that
      // it wants to be lazily deoptimized on throw. This allows the optimizing
      // compiler to omit catch blocks that were never reached in practice.
      int optimized_exception_handler = table.LookupReturn(pc_offset);
      if (optimized_exception_handler != HandlerTable::kLazyDeopt) {
        return optimized_exception_handler;
      }
      Deoptimizer::DeoptimizeFunction(function(), code);
    }
    DCHECK(code->marked_for_deoptimization());
    pc_offset = FindReturnPCForTrampoline(code, pc_offset);
  }
  return table.LookupReturn(pc_offset);
}

int MaglevFrame::FindReturnPCForTrampoline(Tagged<Code> code,
                                           int trampoline_pc) const {
  DCHECK_EQ(code->kind(), CodeKind::MAGLEV);
  DCHECK(code->marked_for_deoptimization());
  MaglevSafepointTable safepoints(isolate(), pc(), code);
  return safepoints.find_return_pc(trampoline_pc);
}

int TurbofanJSFrame::FindReturnPCForTrampoline(Tagged<Code> code,
                                               int trampoline_pc) const {
  DCHECK_EQ(code->kind(), CodeKind::TURBOFAN_JS);
  DCHECK(code->marked_for_deoptimization());
  SafepointTable safepoints(isolate(), pc(), code);
  return safepoints.find_return_pc(trampoline_pc);
}

Tagged<DeoptimizationData> OptimizedJSFrame::GetDeoptimizationData(
    Tagged<Code> code, int* deopt_index) const {
  DCHECK(is_optimized());

  Address pc = maybe_unauthenticated_pc();

  DCHECK(code->contains(isolate(), pc));
  DCHECK(CodeKindCanDeoptimize(code->kind()));

  if (code->is_maglevved()) {
    MaglevSafepointEntry safepoint_entry =
        code->GetMaglevSafepointEntry(isolate(), pc);
    if (safepoint_entry.has_deoptimization_index()) {
      *deopt_index = safepoint_entry.deoptimization_index();
      return Cast<DeoptimizationData>(code->deoptimization_data());
    }
  } else {
    SafepointEntry safepoint_entry = code->GetSafepointEntry(isolate(), pc);
    if (safepoint_entry.has_deoptimization_index()) {
      *deopt_index = safepoint_entry.deoptimization_index();
      return Cast<DeoptimizationData>(code->deoptimization_data());
    }
  }
  *deopt_index = SafepointEntry::kNoDeoptIndex;
  return {};
}

void OptimizedJSFrame::GetFunctions(
    std::vector<Tagged<SharedFunctionInfo>>* functions) const {
  DCHECK(functions->empty());
  DCHECK(is_optimized());

  // Delegate to JS frame in absence of turbofan deoptimization.
  // TODO(turbofan): Revisit once we support deoptimization across the board.
  Tagged<Code> code = LookupCode();
  if (code->kind() == CodeKind::BUILTIN) {
    return JavaScriptFrame::GetFunctions(functions);
  }

  DisallowGarbageCollection no_gc;
  int deopt_index = SafepointEntry::kNoDeoptIndex;
  Tagged<DeoptimizationData> const data =
      GetDeoptimizationData(code, &deopt_index);
  DCHECK(!data.is_null());
  DCHECK_NE(SafepointEntry::kNoDeoptIndex, deopt_index);
  Tagged<DeoptimizationLiteralArray> const literal_array = data->LiteralArray();

  DeoptimizationFrameTranslation::Iterator it(
      data->FrameTranslation(), data->TranslationIndex(deopt_index).value());
  int jsframe_count = it.EnterBeginOpcode().js_frame_count;

  // We insert the frames in reverse order because the frames
  // in the deoptimization translation are ordered bottom-to-top.
  while (jsframe_count != 0) {
    TranslationOpcode opcode = it.SeekNextJSFrame();
    it.NextOperand();  // Skip bailout id.
    jsframe_count--;

    // The second operand of the frame points to the function.
    Tagged<Object> shared = literal_array->get(it.NextOperand());
    functions->push_back(Cast<SharedFunctionInfo>(shared));

    // Skip over remaining operands to advance to the next opcode.
    it.SkipOperands(TranslationOpcodeOperandCount(opcode) - 2);
  }
}

int OptimizedJSFrame::StackSlotOffsetRelativeToFp(int slot_index) {
  return StandardFrameConstants::kCallerSPOffset -
         ((slot_index + 1) * kSystemPointerSize);
}

int UnoptimizedJSFrame::position() const {
  Tagged<BytecodeArray> code = GetBytecodeArray();
  int code_offset = GetBytecodeOffset();
  return code->SourcePosition(code_offset);
}

int UnoptimizedJSFrame::LookupExceptionHandlerInTable(
    int* context_register, HandlerTable::CatchPrediction* prediction) {
  HandlerTable table(GetBytecodeArray());
  int handler_index = table.LookupHandlerIndexForRange(GetBytecodeOffset());
  if (handler_index != HandlerTable::kNoHandlerFound) {
    if (context_register) *context_register = table.GetRangeData(handler_index);
    if (prediction) *prediction = table.GetRangePrediction(handler_index);
    table.MarkHandlerUsed(handler_index);
    return table.GetRangeHandler(handler_index);
  }
  return handler_index;
}

Tagged<BytecodeArray> UnoptimizedJSFrame::GetBytecodeArray() const {
  const int index = UnoptimizedFrameConstants::kBytecodeArrayExpressionIndex;
  DCHECK_EQ(UnoptimizedFrameConstants::kBytecodeArrayFromFp,
            UnoptimizedFrameConstants::kExpressionsOffset -
                index * kSystemPointerSize);
  return Cast<BytecodeArray>(GetExpression(index));
}

Tagged<Object> UnoptimizedJSFrame::ReadInterpreterRegister(
    int register_index) const {
  const int index = UnoptimizedFrameConstants::kRegisterFileExpressionIndex;
  DCHECK_EQ(UnoptimizedFrameConstants::kRegisterFileFromFp,
            UnoptimizedFrameConstants::kExpressionsOffset -
                index * kSystemPointerSize);
  return GetExpression(index + register_index);
}

void UnoptimizedJSFrame::Summarize(std::vector<FrameSummary>* functions) const {
  DCHECK(functions->empty());
  DirectHandle<AbstractCode> abstract_code(
      Cast<AbstractCode>(GetBytecodeArray()), isolate());
  DirectHandle<FixedArray> params = GetParameters();
  FrameSummary::JavaScriptFrameSummary summary(
      isolate(), receiver(), function(), *abstract_code, GetBytecodeOffset(),
      IsConstructor(), *params);
  functions->push_back(summary);
}

int InterpretedFrame::GetBytecodeOffset() const {
  const int index = InterpreterFrameConstants::kBytecodeOffsetExpressionIndex;
  DCHECK_EQ(
"""


```