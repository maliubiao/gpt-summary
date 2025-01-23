Response: The user wants a summary of the C++ source code file `v8/src/execution/frames.cc`, specifically part 3 of 3. The request also asks to relate the functionality to JavaScript with examples if possible.

**Plan:**

1. **Identify the primary purpose of the code:**  Based on the class names and methods, the code deals with different types of frames in the V8 stack, such as interpreted frames, baseline frames, wasm frames, JavaScript frames, etc. It seems to provide ways to access and manipulate information within these frames.
2. **Summarize the functionality of each major class/structure:**
    - `InterpreterFrame`:  Focuses on bytecode offset patching and retrieval.
    - `BaselineFrame`:  Handles bytecode offset retrieval based on the PC and patching the context.
    - `BuiltinFrame`:  Deals with accessing the function and parameter count.
    - `WasmFrame`:  Provides extensive functionality for WebAssembly frames, including printing, accessing instance data, module information, source position, and handling inlining and exception handling.
    - `WasmDebugBreakFrame`:  Specifically for debugging WebAssembly.
    - `WasmToJsFrame`:  Handles the transition from WebAssembly to JavaScript.
    - `JsToWasmFrame`:  Manages the transition from JavaScript to WebAssembly, including garbage collection considerations.
    - `StackSwitchFrame`:  Used for switching between stacks, likely in WebAssembly contexts.
    - `WasmInterpreterEntryFrame`:  Represents a frame for the WebAssembly interpreter.
    - `WasmLiftoffSetupFrame`:  Likely involved in setting up Liftoff compilation for WebAssembly.
    - `JavaScriptFrame`:  Provides detailed information and manipulation for JavaScript stack frames, including printing, accessing receiver, function, parameters, and local variables.
    - `EntryFrame`:  Represents the entry point of execution.
    - `CommonFrame`:  Provides common iteration logic for stack frames.
    - `InnerPointerToCodeCache`:  A caching mechanism for looking up code based on inner pointers.
    - `UnoptimizedFrameInfo`, `ConstructStubFrameInfo`, `FastConstructStubFrameInfo`, `BuiltinContinuationFrameInfo`:  Structures containing information about the layout and sizes of different types of stack frames during unoptimized and built-in function calls.
3. **Identify connections to JavaScript:**  Many of these frame types directly correspond to JavaScript execution (e.g., `JavaScriptFrame`, `InterpreterFrame`). The WebAssembly frames are also directly related to executing WebAssembly code called from or calling into JavaScript.
4. **Provide JavaScript examples:** Illustrate how the concepts in the C++ code relate to observable behavior in JavaScript (e.g., stack traces, debugging, calling WebAssembly).

**Self-Correction during thought process:**

* Initially, I might have focused too much on the low-level details of memory offsets. I need to abstract that to the *purpose* of these operations (e.g., accessing bytecode offset, function, etc.).
*  The request emphasizes the *connection* to JavaScript. Simply stating the frame types exist isn't enough. I need to explain *how* these frames arise during JavaScript execution.
* For the JavaScript examples, I need to choose simple, clear examples that directly illustrate the concepts without being overly complex. Focus on stack traces and the interaction with WebAssembly.
这是 `v8/src/execution/frames.cc` 文件的第三部分，主要延续了前两部分关于**V8 引擎中不同类型栈帧 (stack frame)** 的定义和操作。

综合前两部分的内容，这个文件定义了 V8 引擎在执行 JavaScript 和 WebAssembly 代码时使用的各种栈帧结构，并提供了访问和操作这些栈帧信息的工具函数。栈帧是程序执行过程中的一个重要概念，它记录了函数调用时的上下文信息，例如局部变量、参数、返回地址等。

**第三部分主要涵盖了以下功能和栈帧类型：**

**1. WebAssembly 相关的栈帧:**

*   **`WasmDebugBreakFrame`**:  用于 WebAssembly 代码中的断点调试。它提供了访问被保存的寄存器的能力，这在调试时检查 WebAssembly 的状态很有用。
*   **`WasmToJsFrame`**:  表示从 WebAssembly 代码调用 JavaScript 函数时的栈帧。它允许访问 WebAssembly 实例数据。
*   **`JsToWasmFrame`**:  表示从 JavaScript 代码调用 WebAssembly 函数时的栈帧。它特别关注垃圾回收 (GC) 时对栈的遍历，确保正确识别和处理 WebAssembly 中的对象引用。
*   **`StackSwitchFrame`**:  用于在不同的栈之间切换，这在 WebAssembly 的执行环境中可能发生。它提供了获取跳转缓冲区状态的方法。
*   **`WasmInterpreterEntryFrame`**:  用于执行 WebAssembly 解释器时的栈帧。它可以访问 WebAssembly 实例、模块信息，并支持生成帧摘要。
*   **`WasmLiftoffSetupFrame`**:  与 WebAssembly 的 Liftoff 编译器相关，用于设置函数调用，并提供在 GC 时扫描参数寄存器和栈参数的能力。

**2. JavaScript 相关的栈帧:**

*   **`JavaScriptFrame`**:  这是最主要的 JavaScript 代码执行的栈帧类型。它提供了非常丰富的功能，包括：
    *   打印栈帧信息，包括函数名、接收者 (`this`)、参数、本地变量、表达式栈等。
    *   访问接收者、函数、参数、上下文等。
    *   处理源代码的显示。
    *   区分解释执行和编译执行的栈帧。
*   **`EntryFrame`**:  表示执行的入口点栈帧。它允许遍历代码中的常量池。
*   **`CommonFrame`**:  提供了一些通用的栈帧操作，例如遍历表达式栈。
*   **`InternalFrame`**:  表示 V8 引擎内部函数调用的栈帧。它也支持遍历表达式栈。

**3. 代码缓存相关的类:**

*   **`InnerPointerToCodeCache`**:  这是一个缓存，用于根据代码内部的指针快速查找对应的 `Code` 对象。这在 V8 引擎的优化和内联过程中非常重要。

**4. 栈帧布局信息类:**

*   **`UnoptimizedFrameInfo`**, **`ConstructStubFrameInfo`**, **`FastConstructStubFrameInfo`**, **`BuiltinContinuationFrameInfo`**: 这些类用于描述不同类型栈帧的布局和大小。这些信息在栈帧的创建和解析过程中至关重要。

**与 JavaScript 的关系及示例:**

这个文件中的代码直接支撑着 JavaScript 代码的执行。每当 JavaScript 函数被调用时，V8 引擎都会在栈上创建一个 `JavaScriptFrame` 来记录该调用的上下文。

*   **JavaScript 中的函数调用和栈帧：**
    ```javascript
    function foo(a, b) {
      let sum = a + b;
      return sum;
    }

    function bar() {
      let x = 10;
      let y = 20;
      return foo(x, y);
    }

    bar();
    ```
    当这段代码执行时，会先创建一个 `JavaScriptFrame` 用于 `bar` 函数，然后再创建一个 `JavaScriptFrame` 用于 `foo` 函数。`frames.cc` 中的代码负责定义这些栈帧的结构，并提供访问 `foo` 函数的参数 `a` 和 `b`，以及局部变量 `sum` 的方法。

*   **JavaScript 中的 `console.trace()` 和栈帧打印：**
    ```javascript
    function inner() {
      console.trace();
    }

    function outer() {
      inner();
    }

    outer();
    ```
    当执行 `console.trace()` 时，V8 引擎会遍历当前的栈帧，并利用 `JavaScriptFrame::Print` 等函数将栈帧信息打印到控制台。这些打印信息就包含了函数名、所在的文件和行号等，这些信息正是从栈帧中提取出来的。

*   **JavaScript 与 WebAssembly 的互操作：**
    ```javascript
    // Assume we have a WebAssembly module instance 'wasmInstance' with an exported function 'add'

    async function runWasm() {
      const result = wasmInstance.exports.add(5, 10);
      console.log(result);
    }

    runWasm();
    ```
    当 JavaScript 调用 WebAssembly 的 `add` 函数时，会创建一个 `JsToWasmFrame`。当 WebAssembly 函数调用 JavaScript 函数时，会创建一个 `WasmToJsFrame`。`frames.cc` 中的这些帧类型定义了在这些跨语言调用过程中如何组织和访问栈信息。

*   **JavaScript 调试和断点：**
    当你在 JavaScript 代码中设置断点并进行调试时，V8 引擎会暂停执行，并允许你检查当前的状态，包括变量的值和调用栈。调用栈的信息就是通过遍历和解析栈帧来获得的。对于 WebAssembly 中的断点，则会涉及到 `WasmDebugBreakFrame`。

**总结:**

`v8/src/execution/frames.cc` 文件的第三部分（以及整个文件）是 V8 引擎的核心组件之一，它定义了用于管理程序执行上下文的各种栈帧结构。这些结构不仅用于记录 JavaScript 代码的执行状态，也用于处理与 WebAssembly 的互操作。通过这些栈帧，V8 引擎可以进行函数调用、管理局部变量、处理异常、进行垃圾回收以及支持调试等关键操作。这些底层的 C++ 结构直接支撑着我们编写和运行的 JavaScript 和 WebAssembly 代码。

### 提示词
```
这是目录为v8/src/execution/frames.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```
InterpreterFrameConstants::kBytecodeOffsetFromFp,
            InterpreterFrameConstants::kExpressionsOffset -
                index * kSystemPointerSize);
  int raw_offset = Smi::ToInt(GetExpression(index));
  return raw_offset - BytecodeArray::kHeaderSize + kHeapObjectTag;
}

void InterpretedFrame::PatchBytecodeOffset(int new_offset) {
  const int index = InterpreterFrameConstants::kBytecodeOffsetExpressionIndex;
  DCHECK_EQ(InterpreterFrameConstants::kBytecodeOffsetFromFp,
            InterpreterFrameConstants::kExpressionsOffset -
                index * kSystemPointerSize);
  int raw_offset = BytecodeArray::kHeaderSize - kHeapObjectTag + new_offset;
  SetExpression(index, Smi::FromInt(raw_offset));
}

void InterpretedFrame::PatchBytecodeArray(
    Tagged<BytecodeArray> bytecode_array) {
  const int index = InterpreterFrameConstants::kBytecodeArrayExpressionIndex;
  DCHECK_EQ(InterpreterFrameConstants::kBytecodeArrayFromFp,
            InterpreterFrameConstants::kExpressionsOffset -
                index * kSystemPointerSize);
  SetExpression(index, bytecode_array);
}

int BaselineFrame::GetBytecodeOffset() const {
  Tagged<Code> code = LookupCode();
  return code->GetBytecodeOffsetForBaselinePC(this->pc(), GetBytecodeArray());
}

intptr_t BaselineFrame::GetPCForBytecodeOffset(int bytecode_offset) const {
  Tagged<Code> code = LookupCode();
  return code->GetBaselineStartPCForBytecodeOffset(bytecode_offset,
                                                   GetBytecodeArray());
}

void BaselineFrame::PatchContext(Tagged<Context> value) {
  base::Memory<Address>(fp() + BaselineFrameConstants::kContextOffset) =
      value.ptr();
}

Tagged<JSFunction> BuiltinFrame::function() const {
  const int offset = BuiltinFrameConstants::kFunctionOffset;
  return Cast<JSFunction>(Tagged<Object>(base::Memory<Address>(fp() + offset)));
}

int BuiltinFrame::ComputeParametersCount() const {
  const int offset = BuiltinFrameConstants::kLengthOffset;
  return Smi::ToInt(Tagged<Object>(base::Memory<Address>(fp() + offset))) -
         kJSArgcReceiverSlots;
}

#if V8_ENABLE_WEBASSEMBLY
void WasmFrame::Print(StringStream* accumulator, PrintMode mode,
                      int index) const {
  PrintIndex(accumulator, mode, index);

#if V8_ENABLE_DRUMBRAKE
  if (v8_flags.wasm_jitless) {
    DCHECK(is_wasm_to_js());
    accumulator->Add("Wasm-to-JS");
    if (mode != OVERVIEW) accumulator->Add("\n");
    return;
  }
#endif  // V8_ENABLE_DRUMBRAKE

  if (function_index() == wasm::kAnonymousFuncIndex) {
    accumulator->Add("Anonymous wasm wrapper [pc: %p]\n",
                     reinterpret_cast<void*>(pc()));
    return;
  }
  wasm::WasmCodeRefScope code_ref_scope;
  accumulator->Add(is_wasm_to_js() ? "Wasm-to-JS [" : "Wasm [");
  accumulator->PrintName(script()->name());
  Address instruction_start = wasm_code()->instruction_start();
  base::Vector<const uint8_t> raw_func_name =
      module_object()->GetRawFunctionName(function_index());
  const int kMaxPrintedFunctionName = 64;
  char func_name[kMaxPrintedFunctionName + 1];
  int func_name_len = std::min(kMaxPrintedFunctionName, raw_func_name.length());
  memcpy(func_name, raw_func_name.begin(), func_name_len);
  func_name[func_name_len] = '\0';
  int pos = position();
  const wasm::WasmModule* module = trusted_instance_data()->module();
  int func_index = function_index();
  int func_code_offset = module->functions[func_index].code.offset();
  accumulator->Add("], function #%u ('%s'), pc=%p (+0x%x), pos=%d (+%d)\n",
                   func_index, func_name, reinterpret_cast<void*>(pc()),
                   static_cast<int>(pc() - instruction_start), pos,
                   pos - func_code_offset);
  if (mode != OVERVIEW) accumulator->Add("\n");
}

wasm::WasmCode* WasmFrame::wasm_code() const {
  return wasm::GetWasmCodeManager()->LookupCode(isolate(),
                                                maybe_unauthenticated_pc());
}

Tagged<WasmInstanceObject> WasmFrame::wasm_instance() const {
  // TODO(42204563): Avoid crashing if the instance object is not available.
  CHECK(trusted_instance_data()->has_instance_object());
  return trusted_instance_data()->instance_object();
}

Tagged<WasmTrustedInstanceData> WasmFrame::trusted_instance_data() const {
  Tagged<Object> trusted_data(
      Memory<Address>(fp() + WasmFrameConstants::kWasmInstanceDataOffset));
  return Cast<WasmTrustedInstanceData>(trusted_data);
}

wasm::NativeModule* WasmFrame::native_module() const {
  return trusted_instance_data()->native_module();
}

Tagged<WasmModuleObject> WasmFrame::module_object() const {
  return trusted_instance_data()->module_object();
}

int WasmFrame::function_index() const { return wasm_code()->index(); }

Tagged<Script> WasmFrame::script() const { return module_object()->script(); }

int WasmFrame::position() const {
  const wasm::WasmModule* module = trusted_instance_data()->module();
  return GetSourcePosition(module, function_index(), generated_code_offset(),
                           at_to_number_conversion());
}

int WasmFrame::generated_code_offset() const {
  wasm::WasmCode* code = wasm_code();
  int offset = static_cast<int>(pc() - code->instruction_start());
  return code->GetSourceOffsetBefore(offset);
}

bool WasmFrame::is_inspectable() const { return wasm_code()->is_inspectable(); }

Tagged<Object> WasmFrame::context() const {
  return trusted_instance_data()->native_context();
}

void WasmFrame::Summarize(std::vector<FrameSummary>* functions) const {
  DCHECK(functions->empty());
  // The {WasmCode*} escapes this scope via the {FrameSummary}, which is fine,
  // since this code object is part of our stack.
  wasm::WasmCode* code = wasm_code();
  int offset =
      static_cast<int>(maybe_unauthenticated_pc() - code->instruction_start());
  Handle<WasmTrustedInstanceData> instance_data{trusted_instance_data(),
                                                isolate()};
  // Push regular non-inlined summary.
  SourcePosition pos = code->GetSourcePositionBefore(offset);
  bool at_conversion = at_to_number_conversion();
  bool child_was_tail_call = false;
  // Add summaries for each inlined function at the current location.
  while (pos.isInlined()) {
    // Use current pc offset as the code offset for inlined functions.
    // This is not fully correct but there isn't a real code offset of a stack
    // frame for an inlined function as the inlined function is not a true
    // function with a defined start and end in the generated code.
    const auto [func_index, was_tail_call, caller_pos] =
        code->GetInliningPosition(pos.InliningId());
    if (!child_was_tail_call) {
      FrameSummary::WasmFrameSummary summary(isolate(), instance_data, code,
                                             pos.ScriptOffset(), func_index,
                                             at_conversion);
      functions->push_back(summary);
    }
    pos = caller_pos;
    at_conversion = false;
    child_was_tail_call = was_tail_call;
  }

  if (!child_was_tail_call) {
    int func_index = code->index();
    FrameSummary::WasmFrameSummary summary(isolate(), instance_data, code,
                                           pos.ScriptOffset(), func_index,
                                           at_conversion);
    functions->push_back(summary);
  }

  // The caller has to be on top.
  std::reverse(functions->begin(), functions->end());
}

bool WasmFrame::at_to_number_conversion() const {
  if (callee_pc() == kNullAddress) return false;
  // Check whether our callee is a WASM_TO_JS frame, and this frame is at the
  // ToNumber conversion call.
  wasm::WasmCode* wasm_code =
      wasm::GetWasmCodeManager()->LookupCode(isolate(), callee_pc());

  if (wasm_code) {
    if (wasm_code->kind() != wasm::WasmCode::kWasmToJsWrapper) return false;
    int offset = static_cast<int>(callee_pc() - wasm_code->instruction_start());
    int pos = wasm_code->GetSourceOffsetBefore(offset);
    // The imported call has position 0, ToNumber has position 1.
    // If there is no source position available, this is also not a ToNumber
    // call.
    DCHECK(pos == wasm::kNoCodePosition || pos == 0 || pos == 1);
    return pos == 1;
  }

  InnerPointerToCodeCache::InnerPointerToCodeCacheEntry* entry =
      isolate()->inner_pointer_to_code_cache()->GetCacheEntry(callee_pc());
  CHECK(entry->code.has_value());
  Tagged<GcSafeCode> code = entry->code.value();
  if (code->builtin_id() != Builtin::kWasmToJsWrapperCSA) {
    return false;
  }

  // The generic wasm-to-js wrapper maintains a slot on the stack to indicate
  // its state. Initially this slot contains a pointer to the signature, so that
  // incoming parameters can be scanned. After all parameters have been
  // processed, this slot is reset to nullptr. After returning from JavaScript,
  // -1 is stored in the slot to indicate that any call from now on is a
  // ToNumber conversion.
  Address maybe_sig =
      Memory<Address>(callee_fp() + WasmToJSWrapperConstants::kSignatureOffset);

  return static_cast<intptr_t>(maybe_sig) == -1;
}

int WasmFrame::LookupExceptionHandlerInTable() {
  wasm::WasmCode* code =
      wasm::GetWasmCodeManager()->LookupCode(isolate(), pc());
  if (!code->IsAnonymous() && code->handler_table_size() > 0) {
    HandlerTable table(code);
    int pc_offset = static_cast<int>(pc() - code->instruction_start());
    return table.LookupReturn(pc_offset);
  }
  return -1;
}

void WasmDebugBreakFrame::Iterate(RootVisitor* v) const {
  DCHECK(caller_pc());
  auto pair = wasm::GetWasmCodeManager()->LookupCodeAndSafepoint(isolate(),
                                                                 caller_pc());
  SafepointEntry safepoint_entry = pair.second;
  uint32_t tagged_register_indexes = safepoint_entry.tagged_register_indexes();

  while (tagged_register_indexes != 0) {
    int reg_code = base::bits::CountTrailingZeros(tagged_register_indexes);
    tagged_register_indexes &= ~(1 << reg_code);
    FullObjectSlot spill_slot(&Memory<Address>(
        fp() +
        WasmDebugBreakFrameConstants::GetPushedGpRegisterOffset(reg_code)));

    v->VisitRootPointer(Root::kStackRoots, nullptr, spill_slot);
  }
}

void WasmDebugBreakFrame::Print(StringStream* accumulator, PrintMode mode,
                                int index) const {
  PrintIndex(accumulator, mode, index);
  accumulator->Add("WasmDebugBreak");
  if (mode != OVERVIEW) accumulator->Add("\n");
}

Tagged<WasmInstanceObject> WasmToJsFrame::wasm_instance() const {
  // WasmToJsFrames hold the {WasmImportData} object in the instance slot.
  // Load the instance from there.
  Tagged<WasmImportData> import_data = Cast<WasmImportData>(Tagged<Object>{
      Memory<Address>(fp() + WasmFrameConstants::kWasmInstanceDataOffset)});
  // TODO(42204563): Avoid crashing if the instance object is not available.
  CHECK(import_data->instance_data()->has_instance_object());
  return import_data->instance_data()->instance_object();
}

Tagged<WasmTrustedInstanceData> WasmToJsFrame::trusted_instance_data() const {
  return wasm_instance()->trusted_data(isolate());
}

void JsToWasmFrame::Iterate(RootVisitor* v) const {
  // WrapperBuffer slot is RawPtr pointing to a stack.
  // Wasm instance and JS result array are passed as stack params.
  // So there is no need to visit them.

#if V8_ENABLE_DRUMBRAKE
  // Please reference GenericJSToWasmInterpreterWrapper for stack layout.
  if (v8_flags.wasm_jitless) {
    DCHECK(GetContainingCode(isolate(), pc()).value()->builtin_id() ==
           Builtin::kGenericJSToWasmInterpreterWrapper);

    // In a GenericJSToWasmInterpreterWrapper stack layout
    //  ------+-----------------+----------------------
    //        |  return addr    |
    //    fp  |- - - - - - - - -|  -------------------|
    //        |     old fp      |                     |
    //   fp-p |- - - - - - - - -|                     |
    //        |  frame marker   |                     | no GC scan
    //  fp-2p |- - - - - - - - -|                     |
    //        |   scan_count    |                     |
    //  fp-3p |- - - - - - - - -|  -------------------|
    //        |      ....       |                     |
    //        |      ....       | <- spill_slot_limit |
    //        |   spill slots   |                     | GC scan scan_count slots
    //    sp  |      ....       | <- spill_slot_base--|
    //        |                 |                     |
    // The [fp + BuiltinFrameConstants::kGCScanSlotCount] on the stack is a
    // value indicating how many values should be scanned from the top.
    intptr_t scan_count = *reinterpret_cast<intptr_t*>(
        fp() + BuiltinWasmInterpreterWrapperConstants::kGCScanSlotCountOffset);

    FullObjectSlot spill_slot_base(&Memory<Address>(sp()));
    FullObjectSlot spill_slot_limit(
        &Memory<Address>(sp() + scan_count * kSystemPointerSize));
    v->VisitRootPointers(Root::kStackRoots, nullptr, spill_slot_base,
                         spill_slot_limit);

    // We should scan the arg/return values array which may hold heap pointers
    // for reference type of parameter/return values.
    uint32_t signature_data = *reinterpret_cast<uint32_t*>(
        fp() + BuiltinWasmInterpreterWrapperConstants::kSignatureDataOffset);
    bool has_ref_args =
        signature_data & wasm::WasmInterpreterRuntime::HasRefArgsField::kMask;
    bool has_ref_rets =
        signature_data & wasm::WasmInterpreterRuntime::HasRefRetsField::kMask;

    // This value indicates the array is currently used as args array. If false,
    // it's an array for return values.
    bool is_args = *reinterpret_cast<intptr_t*>(
        fp() + BuiltinWasmInterpreterWrapperConstants::kArgRetsIsArgsOffset);
    if ((is_args && !has_ref_args) || (!is_args && !has_ref_rets)) return;

    // Retrieve function signature.
    size_t return_count = *reinterpret_cast<size_t*>(
        fp() + BuiltinWasmInterpreterWrapperConstants::kReturnCountOffset);
    size_t param_count = *reinterpret_cast<size_t*>(
        fp() + BuiltinWasmInterpreterWrapperConstants::kParamCountOffset);
    const wasm::ValueType* reps = *reinterpret_cast<const wasm::ValueType**>(
        fp() +
        BuiltinWasmInterpreterWrapperConstants::kValueTypesArrayStartOffset);
    wasm::FunctionSig sig(return_count, param_count, reps);

    intptr_t slot_ptr = *reinterpret_cast<intptr_t*>(
        fp() + BuiltinWasmInterpreterWrapperConstants::kArgRetsAddressOffset);

    if (is_args) {
      size_t current_index = *reinterpret_cast<size_t*>(
          fp() + BuiltinWasmInterpreterWrapperConstants::kCurrentIndexOffset);
      DCHECK_LE(current_index, param_count);
      for (size_t i = 0; i < current_index; i++) {
        wasm::ValueType type = sig.GetParam(i);
        if (type.is_reference()) {
          // Make sure slot for ref args are 64-bit aligned.
          slot_ptr += (slot_ptr & 0x04);  // Branchless.
          FullObjectSlot array_slot(&Memory<Address>(slot_ptr));
          v->VisitRootPointer(Root::kStackRoots, nullptr, array_slot);
          slot_ptr += kSystemPointerSize;
        } else {
          switch (type.kind()) {
            case wasm::kI32:
            case wasm::kF32:
              slot_ptr += sizeof(int32_t);
              break;
            case wasm::kI64:
            case wasm::kF64:
              slot_ptr += sizeof(int64_t);
              break;
            case wasm::kS128:
            default:
              UNREACHABLE();
          }
        }
      }
    } else {
      // When converting return values, all results are already in the array.
      for (size_t i = 0; i < return_count; i++) {
        wasm::ValueType type = sig.GetReturn(i);
        if (type.is_reference()) {
          // Make sure slot for ref args are 64-bit aligned.
          slot_ptr += (slot_ptr & 0x04);  // Branchless.
          FullObjectSlot array_slot(&Memory<Address>(slot_ptr));
          v->VisitRootPointer(Root::kStackRoots, nullptr, array_slot);
          slot_ptr += kSystemPointerSize;
        } else {
          switch (type.kind()) {
            case wasm::kI32:
            case wasm::kF32:
              slot_ptr += sizeof(int32_t);
              break;
            case wasm::kI64:
            case wasm::kF64:
              slot_ptr += sizeof(int64_t);
              break;
            case wasm::kS128:
            default:
              UNREACHABLE();
          }
        }
      }
    }
  }
#endif  // V8_ENABLE_DRUMBRAKE
}

#if V8_ENABLE_DRUMBRAKE
void WasmToJsFrame::Iterate(RootVisitor* v) const {
  if (v8_flags.wasm_jitless) {
    // Called from GenericWasmToJSInterpreterWrapper.
    CHECK(v8_flags.jitless);
    // The [fp + BuiltinFrameConstants::kGCScanSlotCount] on the stack is a
    // value indicating how many values should be scanned from the top.
    intptr_t scan_count = *reinterpret_cast<intptr_t*>(
        fp() + WasmToJSInterpreterFrameConstants::kGCScanSlotCountOffset);

    Address original_sp = *reinterpret_cast<Address*>(
        fp() + WasmToJSInterpreterFrameConstants::kGCSPOffset);

    // The original sp is not assigned yet if GC is triggered in the middle of
    // param conversion loop. In this case, we just need to scan arguments from
    // the current sp.
    if (original_sp == 0) original_sp = sp();

    if (sp() != original_sp) {
      // The actual frame sp can be different from the sp we had at the moment
      // of the call to Call_ReceiverIsAny for two reasons:
      // 1. Call_ReceiverIsAny might call AdaptorWithBuiltinExitFrame, which
      // adds BuiltinExitFrameConstants::kNumExtraArgs additional
      // tagged arguments to the stack.
      // 2. If there is arity mismatch and the imported Wasm function declares
      // fewer arguments then the arguments expected by the JS function,
      // Call_ReceiverIsAny passes additional Undefined args.
      FullObjectSlot additional_spill_slot_base(&Memory<Address>(sp()));
      FullObjectSlot additional_spill_slot_limit(original_sp);
      v->VisitRootPointers(Root::kStackRoots, nullptr,
                           additional_spill_slot_base,
                           additional_spill_slot_limit);
    }
    FullObjectSlot spill_slot_base(&Memory<Address>(original_sp));
    FullObjectSlot spill_slot_limit(
        &Memory<Address>(original_sp + scan_count * kSystemPointerSize));
    v->VisitRootPointers(Root::kStackRoots, nullptr, spill_slot_base,
                         spill_slot_limit);
    return;
  }
  WasmFrame::Iterate(v);
}
#endif  // V8_ENABLE_DRUMBRAKE

void StackSwitchFrame::Iterate(RootVisitor* v) const {
  //  See JsToWasmFrame layout.
  //  We cannot DCHECK that the pc matches the expected builtin code here,
  //  because the return address is on a different stack.
  // The [fp + BuiltinFrameConstants::kGCScanSlotCountOffset] on the stack is a
  // value indicating how many values should be scanned from the top.
  intptr_t scan_count = Memory<intptr_t>(
      fp() + StackSwitchFrameConstants::kGCScanSlotCountOffset);

  FullObjectSlot spill_slot_base(&Memory<Address>(sp()));
  FullObjectSlot spill_slot_limit(
      &Memory<Address>(sp() + scan_count * kSystemPointerSize));
  v->VisitRootPointers(Root::kStackRoots, nullptr, spill_slot_base,
                       spill_slot_limit);
  // Also visit fixed spill slots that contain references.
  FullObjectSlot instance_slot(
      &Memory<Address>(fp() + StackSwitchFrameConstants::kImplicitArgOffset));
  v->VisitRootPointer(Root::kStackRoots, nullptr, instance_slot);
  FullObjectSlot result_array_slot(
      &Memory<Address>(fp() + StackSwitchFrameConstants::kResultArrayOffset));
  v->VisitRootPointer(Root::kStackRoots, nullptr, result_array_slot);
}

#if V8_ENABLE_DRUMBRAKE
void WasmInterpreterEntryFrame::Iterate(RootVisitor* v) const {
  //  WasmInterpreterEntryFrame stack layout
  //  ------+-----------------+----------------------
  //        |  return addr    |                     |
  //    fp  |- - - - - - - - -|  -------------------|
  //        |    prev fp      |                     |
  //   fp-p |- - - - - - - - -|                     | no GC scan
  //        |  frame marker   |                     |
  //  fp-2p |- - - - - - - - -|  -------------------|-------------
  //        | WasmInstanceObj |                     | GC scan
  //  fp-3p |- - - - - - - - -|  -------------------|-------------
  //        | function_index  |                     |
  //  fp-4p |- - - - - - - - -|  -------------------| no GC scan
  //        |   array_start   |                     |
  //  fp-5p |- - - - - - - - -|  -------------------|

  static constexpr int kWasmInstanceObjOffset = -2 * kSystemPointerSize;
  FullObjectSlot slot_base(&Memory<Address>(fp() + kWasmInstanceObjOffset));
  FullObjectSlot slot_limit(
      &Memory<Address>(fp() + kWasmInstanceObjOffset + kSystemPointerSize));
  v->VisitRootPointers(Root::kStackRoots, nullptr, slot_base, slot_limit);
}

void WasmInterpreterEntryFrame::Print(StringStream* accumulator, PrintMode mode,
                                      int index) const {
  PrintIndex(accumulator, mode, index);
  accumulator->Add("WASM INTERPRETER ENTRY [");
  Tagged<Script> script = this->script();
  accumulator->PrintName(script->name());
  accumulator->Add("]");
  if (mode != OVERVIEW) accumulator->Add("\n");
}

void WasmInterpreterEntryFrame::Summarize(
    std::vector<FrameSummary>* functions) const {
  Handle<WasmInstanceObject> instance(wasm_instance(), isolate());
  std::vector<WasmInterpreterStackEntry> interpreted_stack =
      WasmInterpreterObject::GetInterpretedStack(
          trusted_instance_data()->interpreter_object(), fp());

  for (auto& e : interpreted_stack) {
    FrameSummary::WasmInterpretedFrameSummary summary(
        isolate(), instance, e.function_index, e.byte_offset);
    functions->push_back(summary);
  }
}

Tagged<HeapObject> WasmInterpreterEntryFrame::unchecked_code() const {
  return InstructionStream();
}

Tagged<WasmInstanceObject> WasmInterpreterEntryFrame::wasm_instance() const {
  Tagged<Object> instance(Memory<Address>(
      fp() + WasmInterpreterFrameConstants::kWasmInstanceObjectOffset));
  return Cast<WasmInstanceObject>(instance);
}

Tagged<WasmTrustedInstanceData>
WasmInterpreterEntryFrame::trusted_instance_data() const {
  return wasm_instance()->trusted_data(isolate());
}

Tagged<Tuple2> WasmInterpreterEntryFrame::interpreter_object() const {
  return trusted_instance_data()->interpreter_object();
}

Tagged<WasmModuleObject> WasmInterpreterEntryFrame::module_object() const {
  return trusted_instance_data()->module_object();
}

int WasmInterpreterEntryFrame::function_index(
    int inlined_function_index) const {
  return WasmInterpreterObject::GetFunctionIndex(
      trusted_instance_data()->interpreter_object(), fp(),
      inlined_function_index);
}

int WasmInterpreterEntryFrame::position() const {
  return FrameSummary::GetBottom(this).AsWasmInterpreted().SourcePosition();
}

Tagged<Object> WasmInterpreterEntryFrame::context() const {
  return trusted_instance_data()->native_context();
}

Address WasmInterpreterEntryFrame::GetCallerStackPointer() const {
  return fp() + CommonFrameConstants::kCallerSPOffset;
}
#endif  // V8_ENABLE_DRUMBRAKE

// static
void StackSwitchFrame::GetStateForJumpBuffer(wasm::JumpBuffer* jmpbuf,
                                             State* state) {
  DCHECK_NE(jmpbuf->fp, kNullAddress);
  DCHECK_EQ(ComputeFrameType(jmpbuf->fp), STACK_SWITCH);
  FillState(jmpbuf->fp, jmpbuf->sp, state);
  state->pc_address = &jmpbuf->pc;
  state->is_stack_exit_frame = true;
  DCHECK_NE(*state->pc_address, kNullAddress);
}

int WasmLiftoffSetupFrame::GetDeclaredFunctionIndex() const {
  Tagged<Object> func_index(Memory<Address>(
      sp() + WasmLiftoffSetupFrameConstants::kDeclaredFunctionIndexOffset));
  return Smi::ToInt(func_index);
}

wasm::NativeModule* WasmLiftoffSetupFrame::GetNativeModule() const {
  return Memory<wasm::NativeModule*>(
      sp() + WasmLiftoffSetupFrameConstants::kNativeModuleOffset);
}

FullObjectSlot WasmLiftoffSetupFrame::wasm_instance_data_slot() const {
  return FullObjectSlot(&Memory<Address>(
      sp() + WasmLiftoffSetupFrameConstants::kWasmInstanceDataOffset));
}

void WasmLiftoffSetupFrame::Iterate(RootVisitor* v) const {
  FullObjectSlot spilled_instance_slot(&Memory<Address>(
      fp() + WasmLiftoffSetupFrameConstants::kInstanceSpillOffset));
  v->VisitRootPointer(Root::kStackRoots, "spilled wasm instance",
                      spilled_instance_slot);
  v->VisitRootPointer(Root::kStackRoots, "wasm instance data",
                      wasm_instance_data_slot());

  wasm::NativeModule* native_module = GetNativeModule();
  int func_index = GetDeclaredFunctionIndex() +
                   native_module->module()->num_imported_functions;

  // Scan the spill slots of the parameter registers. Parameters in WebAssembly
  // get reordered such that first all value parameters get put into registers.
  // If there are more registers than value parameters, the remaining registers
  // are used for reference parameters. Therefore we can determine which
  // registers get used for which parameters by counting the number of value
  // parameters and the number of reference parameters.
  int num_int_params = 0;
  int num_ref_params = 0;
  const wasm::FunctionSig* sig =
      native_module->module()->functions[func_index].sig;
  for (auto param : sig->parameters()) {
    if (param == wasm::kWasmI32) {
      num_int_params++;
    } else if (param == wasm::kWasmI64) {
      num_int_params += kSystemPointerSize == 8 ? 1 : 2;
    } else if (param.is_reference()) {
      num_ref_params++;
    }
  }

  // There are no reference parameters, there is nothing to scan.
  if (num_ref_params == 0) return;

  int num_int_params_in_registers =
      std::min(num_int_params,
               WasmLiftoffSetupFrameConstants::kNumberOfSavedGpParamRegs);
  int num_ref_params_in_registers =
      std::min(num_ref_params,
               WasmLiftoffSetupFrameConstants::kNumberOfSavedGpParamRegs -
                   num_int_params_in_registers);

  for (int i = 0; i < num_ref_params_in_registers; ++i) {
    FullObjectSlot spill_slot(
        fp() + WasmLiftoffSetupFrameConstants::kParameterSpillsOffset
                   [num_int_params_in_registers + i]);

    v->VisitRootPointer(Root::kStackRoots, "register parameter", spill_slot);
  }

  // Next we scan the slots of stack parameters.
  wasm::WasmCode* wasm_code = native_module->GetCode(func_index);
  uint32_t first_tagged_stack_slot = wasm_code->first_tagged_parameter_slot();
  uint32_t num_tagged_stack_slots = wasm_code->num_tagged_parameter_slots();

  // Visit tagged parameters that have been passed to the function of this
  // frame. Conceptionally these parameters belong to the parent frame.
  // However, the exact count is only known by this frame (in the presence of
  // tail calls, this information cannot be derived from the call site).
  if (num_tagged_stack_slots > 0) {
    FullObjectSlot tagged_parameter_base(&Memory<Address>(caller_sp()));
    tagged_parameter_base += first_tagged_stack_slot;
    FullObjectSlot tagged_parameter_limit =
        tagged_parameter_base + num_tagged_stack_slots;

    v->VisitRootPointers(Root::kStackRoots, "stack parameter",
                         tagged_parameter_base, tagged_parameter_limit);
  }
}
#endif  // V8_ENABLE_WEBASSEMBLY

namespace {

void PrintFunctionSource(StringStream* accumulator,
                         Tagged<SharedFunctionInfo> shared) {
  if (v8_flags.max_stack_trace_source_length != 0) {
    std::ostringstream os;
    os << "--------- s o u r c e   c o d e ---------\n"
       << SourceCodeOf(shared, v8_flags.max_stack_trace_source_length)
       << "\n-----------------------------------------\n";
    accumulator->Add(os.str().c_str());
  }
}

}  // namespace

void JavaScriptFrame::Print(StringStream* accumulator, PrintMode mode,
                            int index) const {
  Handle<SharedFunctionInfo> shared = handle(function()->shared(), isolate());
  SharedFunctionInfo::EnsureSourcePositionsAvailable(isolate(), shared);

  DisallowGarbageCollection no_gc;
  Tagged<Object> receiver = this->receiver();
  Tagged<JSFunction> function = this->function();

  accumulator->PrintSecurityTokenIfChanged(function);
  PrintIndex(accumulator, mode, index);
  PrintFrameKind(accumulator);
  if (IsConstructor()) accumulator->Add("new ");
  accumulator->PrintFunction(function, receiver);
  accumulator->Add(" [%p]", function);

  // Get scope information for nicer output, if possible. If code is nullptr, or
  // doesn't contain scope info, scope_info will return 0 for the number of
  // parameters, stack local variables, context local variables, stack slots,
  // or context slots.
  Tagged<ScopeInfo> scope_info = shared->scope_info();
  Tagged<Object> script_obj = shared->script();
  if (IsScript(script_obj)) {
    Tagged<Script> script = Cast<Script>(script_obj);
    accumulator->Add(" [");
    accumulator->PrintName(script->name());

    if (is_interpreted()) {
      const InterpretedFrame* iframe = InterpretedFrame::cast(this);
      Tagged<BytecodeArray> bytecodes = iframe->GetBytecodeArray();
      int offset = iframe->GetBytecodeOffset();
      int source_pos = bytecodes->SourcePosition(offset);
      int line = script->GetLineNumber(source_pos) + 1;
      accumulator->Add(":%d] [bytecode=%p offset=%d]", line,
                       reinterpret_cast<void*>(bytecodes.ptr()), offset);
    } else {
      int function_start_pos = shared->StartPosition();
      int line = script->GetLineNumber(function_start_pos) + 1;
      accumulator->Add(":~%d] [pc=%p]", line, reinterpret_cast<void*>(pc()));
    }
  }

  accumulator->Add("(this=%o", receiver);

  // Print the parameters.
  int parameters_count = ComputeParametersCount();
  for (int i = 0; i < parameters_count; i++) {
    accumulator->Add(",");
    accumulator->Add("%o", GetParameter(i));
  }

  accumulator->Add(")");
  if (mode == OVERVIEW) {
    accumulator->Add("\n");
    return;
  }
  if (is_optimized()) {
    accumulator->Add(" {\n// optimized frame\n");
    PrintFunctionSource(accumulator, *shared);
    accumulator->Add("}\n");
    return;
  }
  accumulator->Add(" {\n");

  // Compute the number of locals and expression stack elements.
  int heap_locals_count = scope_info->ContextLocalCount();
  int expressions_count = ComputeExpressionsCount();

  // Try to get hold of the context of this frame.
  Tagged<Context> context;
  if (IsContext(this->context())) {
    context = Cast<Context>(this->context());
    while (context->IsWithContext()) {
      context = context->previous();
      DCHECK(!context.is_null());
    }
  }

  // Print heap-allocated local variables.
  if (heap_locals_count > 0) {
    accumulator->Add("  // heap-allocated locals\n");
  }
  for (auto it : ScopeInfo::IterateLocalNames(scope_info, no_gc)) {
    accumulator->Add("  var ");
    accumulator->PrintName(it->name());
    accumulator->Add(" = ");
    if (!context.is_null()) {
      int slot_index = Context::MIN_CONTEXT_SLOTS + it->index();
      if (slot_index < context->length()) {
        accumulator->Add("%o", context->get(slot_index));
      } else {
        accumulator->Add(
            "// warning: missing context slot - inconsistent frame?");
      }
    } else {
      accumulator->Add("// warning: no context found - inconsistent frame?");
    }
    accumulator->Add("\n");
  }

  // Print the expression stack.
  if (0 < expressions_count) {
    accumulator->Add("  // expression stack (top to bottom)\n");
  }
  for (int i = expressions_count - 1; i >= 0; i--) {
    accumulator->Add("  [%02d] : %o\n", i, GetExpression(i));
  }

  PrintFunctionSource(accumulator, *shared);

  accumulator->Add("}\n\n");
}

void EntryFrame::Iterate(RootVisitor* v) const {
  IteratePc(v, constant_pool_address(), GcSafeLookupCode());
}

void CommonFrame::IterateExpressions(RootVisitor* v) const {
  const int last_object_offset = StandardFrameConstants::kLastObjectOffset;
  intptr_t marker =
      Memory<intptr_t>(fp() + CommonFrameConstants::kContextOrFrameTypeOffset);
  FullObjectSlot base(&Memory<Address>(sp()));
  FullObjectSlot limit(&Memory<Address>(fp() + last_object_offset) + 1);
  CHECK(StackFrame::IsTypeMarker(marker));
  v->VisitRootPointers(Root::kStackRoots, nullptr, base, limit);
}

void JavaScriptFrame::Iterate(RootVisitor* v) const {
  // The frame contains the actual argument count (intptr) that should not be
  // visited.
  FullObjectSlot argc(
      &Memory<Address>(fp() + StandardFrameConstants::kArgCOffset));
  const int last_object_offset = StandardFrameConstants::kLastObjectOffset;
  FullObjectSlot base(&Memory<Address>(sp()));
  FullObjectSlot limit(&Memory<Address>(fp() + last_object_offset) + 1);
  v->VisitRootPointers(Root::kStackRoots, nullptr, base, argc);
  v->VisitRootPointers(Root::kStackRoots, nullptr, argc + 1, limit);
  IteratePc(v, constant_pool_address(), GcSafeLookupCode());
}

void InternalFrame::Iterate(RootVisitor* v) const {
  Tagged<GcSafeCode> code = GcSafeLookupCode();
  IteratePc(v, constant_pool_address(), code);
  // Internal frames typically do not receive any arguments, hence their stack
  // only contains tagged pointers.
  // We are misusing the has_tagged_outgoing_params flag here to tell us whether
  // the full stack frame contains only tagged pointers or only raw values.
  // This is used for the WasmCompileLazy builtin, where we actually pass
  // untagged arguments and also store untagged values on the stack.
  if (code->has_tagged_outgoing_params()) IterateExpressions(v);
}

// -------------------------------------------------------------------------

namespace {

// Predictably converts PC to uint32 by calculating offset of the PC in
// from the embedded builtins start or from respective MemoryChunk.
uint32_t PcAddressForHashing(Isolate* isolate, Address address) {
  uint32_t hashable_address;
  if (OffHeapInstructionStream::TryGetAddressForHashing(isolate, address,
                                                        &hashable_address)) {
    return hashable_address;
  }
  return ObjectAddressForHashing(address);
}

}  // namespace

InnerPointerToCodeCache::InnerPointerToCodeCacheEntry*
InnerPointerToCodeCache::GetCacheEntry(Address inner_pointer) {
  DCHECK(base::bits::IsPowerOfTwo(kInnerPointerToCodeCacheSize));
  uint32_t hash =
      ComputeUnseededHash(PcAddressForHashing(isolate_, inner_pointer));
  uint32_t index = hash & (kInnerPointerToCodeCacheSize - 1);
  InnerPointerToCodeCacheEntry* entry = cache(index);
  if (entry->inner_pointer == inner_pointer) {
    // Why this DCHECK holds is nontrivial:
    //
    // - the cache is filled lazily on calls to this function.
    // - this function may be called while GC, and in particular
    //   MarkCompactCollector::UpdatePointersAfterEvacuation, is in progress.
    // - the cache is cleared at the end of UpdatePointersAfterEvacuation.
    // - now, why does pointer equality hold even during moving GC?
    // - .. because GcSafeFindCodeForInnerPointer does not follow forwarding
    //   pointers and always returns the old object (which is still valid,
    //   *except* for the map_word).
    DCHECK_EQ(entry->code,
              isolate_->heap()->GcSafeFindCodeForInnerPointer(inner_pointer));
  } else {
    // Because this code may be interrupted by a profiling signal that
    // also queries the cache, we cannot update inner_pointer before the code
    // has been set. Otherwise, we risk trying to use a cache entry before
    // the code has been computed.
    entry->code =
        isolate_->heap()->GcSafeFindCodeForInnerPointer(inner_pointer);
    if (entry->code.value()->is_maglevved()) {
      entry->maglev_safepoint_entry.Reset();
    } else {
      entry->safepoint_entry.Reset();
    }
    entry->inner_pointer = inner_pointer;
  }
  return entry;
}

// Frame layout helper class implementation.
// -------------------------------------------------------------------------

namespace {

// Some architectures need to push padding together with the TOS register
// in order to maintain stack alignment.
constexpr int TopOfStackRegisterPaddingSlots() {
  return ArgumentPaddingSlots(1);
}

bool BuiltinContinuationModeIsWithCatch(BuiltinContinuationMode mode) {
  switch (mode) {
    case BuiltinContinuationMode::STUB:
    case BuiltinContinuationMode::JAVASCRIPT:
      return false;
    case BuiltinContinuationMode::JAVASCRIPT_WITH_CATCH:
    case BuiltinContinuationMode::JAVASCRIPT_HANDLE_EXCEPTION:
      return true;
  }
  UNREACHABLE();
}

}  // namespace

UnoptimizedFrameInfo::UnoptimizedFrameInfo(int parameters_count_with_receiver,
                                           int translation_height,
                                           bool is_topmost, bool pad_arguments,
                                           FrameInfoKind frame_info_kind) {
  const int locals_count = translation_height;

  register_stack_slot_count_ =
      UnoptimizedFrameConstants::RegisterStackSlotCount(locals_count);

  static constexpr int kTheAccumulator = 1;
  static constexpr int kTopOfStackPadding = TopOfStackRegisterPaddingSlots();
  int maybe_additional_slots =
      (is_topmost || frame_info_kind == FrameInfoKind::kConservative)
          ? (kTheAccumulator + kTopOfStackPadding)
          : 0;
  frame_size_in_bytes_without_fixed_ =
      (register_stack_slot_count_ + maybe_additional_slots) *
      kSystemPointerSize;

  // The 'fixed' part of the frame consists of the incoming parameters and
  // the part described by InterpreterFrameConstants. This will include
  // argument padding, when needed.
  const int parameter_padding_slots =
      pad_arguments ? ArgumentPaddingSlots(parameters_count_with_receiver) : 0;
  const int fixed_frame_size =
      InterpreterFrameConstants::kFixedFrameSize +
      (parameters_count_with_receiver + parameter_padding_slots) *
          kSystemPointerSize;
  frame_size_in_bytes_ = frame_size_in_bytes_without_fixed_ + fixed_frame_size;
}

// static
uint32_t UnoptimizedFrameInfo::GetStackSizeForAdditionalArguments(
    int parameters_count) {
  return (parameters_count + ArgumentPaddingSlots(parameters_count)) *
         kSystemPointerSize;
}

ConstructStubFrameInfo::ConstructStubFrameInfo(int translation_height,
                                               bool is_topmost,
                                               FrameInfoKind frame_info_kind) {
  // Note: This is according to the Translation's notion of 'parameters' which
  // differs to that of the SharedFunctionInfo, e.g. by including the receiver.
  const int parameters_count = translation_height;

  // If the construct frame appears to be topmost we should ensure that the
  // value of result register is preserved during continuation execution.
  // We do this here by "pushing" the result of the constructor function to
  // the top of the reconstructed stack and popping it in
  // {Builtin::kNotifyDeoptimized}.

  static constexpr int kTopOfStackPadding = TopOfStackRegisterPaddingSlots();
  static constexpr int kTheResult = 1;
  const int argument_padding = ArgumentPaddingSlots(parameters_count);

  const int adjusted_height =
      (is_topmost || frame_info_kind == FrameInfoKind::kConservative)
          ? parameters_count + argument_padding + kTheResult +
                kTopOfStackPadding
          : parameters_count + argument_padding;
  frame_size_in_bytes_without_fixed_ = adjusted_height * kSystemPointerSize;
  frame_size_in_bytes_ = frame_size_in_bytes_without_fixed_ +
                         ConstructFrameConstants::kFixedFrameSize;
}

FastConstructStubFrameInfo::FastConstructStubFrameInfo(bool is_topmost) {
  // If the construct frame appears to be topmost we should ensure that the
  // value of result register is preserved during continuation execution.
  // We do this here by "pushing" the result of the constructor function to
  // the top of the reconstructed stack and popping it in
  // {Builtin::kNotifyDeoptimized}.

  static constexpr int kTopOfStackPadding = TopOfStackRegisterPaddingSlots();
  static constexpr int kTheResult = 1;
  const int adjusted_height =
      ArgumentPaddingSlots(1) +
      (is_topmost ? kTheResult + kTopOfStackPadding : 0);
  frame_size_in_bytes_without_fixed_ = adjusted_height * kSystemPointerSize;
  frame_size_in_bytes_ = frame_size_in_bytes_without_fixed_ +
                         FastConstructFrameConstants::kFixedFrameSize;
}

BuiltinContinuationFrameInfo::BuiltinContinuationFrameInfo(
    int translation_height,
    const CallInterfaceDescriptor& continuation_descriptor,
    const RegisterConfiguration* register_config, bool is_topmost,
    DeoptimizeKind deopt_kind, BuiltinContinuationMode continuation_mode,
    FrameInfoKind frame_info_kind) {
  const bool is_conservative = frame_info_kind == FrameInfoKind::kConservative;

  // Note: This is according to the Translation's notion of 'parameters' which
  // differs to that of the SharedFunctionInfo, e.g. by including the receiver.
  const int parameters_count = translation_height;
  frame_has_result_stack_slot_ =
      !is_topmost || deopt_kind == DeoptimizeKind::kLazy;
  const int result_slot_count =
      (frame_has_result_stack_slot_ || is_conservative) ? 1 : 0;

  const int exception_slot_count =
      (BuiltinContinuationModeIsWithCatch(continuation_mode) || is_conservative)
          ? 1
          : 0;

  const int allocatable_register_count =
      register_config->num_allocatable_general_registers();
  const int padding_slot_count =
      BuiltinContinuationFrameConstants::PaddingSlotCount(
          allocatable_register_count);

  const int register_parameter_count =
      continuation_descriptor.GetRegisterParameterCount();
  translated_stack_parameter_count_ =
      parameters_count - register_parameter_count;
  stack_parameter_count_ = translated_stack_parameter_count_ +
                           result_slot_count + exception_slot_count;
  const int stack_param_pad_count =
      ArgumentPaddingSlots(stack_parameter_count_);

  // If the builtins frame appears to be topmost we should ensure that the
  // value of result register is preserved during continuation execution.
  // We do this here by "pushing" the result of callback function to the
  // top of the reconstructed stack and popping it in
  // {Builtin::kNotifyDeoptimized}.
  static constexpr int kTopOfStackPadding = TopOfStackRegisterPaddingSlots();
  static constexpr int kTheResult = 1;
  const int push_result_count =
      (is_topmost || is_conservative) ? kTheResult + kTopOfStackPadding : 0;

  frame_size_in_bytes_ =
      kSystemPointerSize * (stack_parameter_count_ + stack_param_pad_count +
                            allocatable_register_count + padding_slot_count +
                            push_result_count) +
      BuiltinContinuationFrameConstants::kFixedFrameSize;

  frame_size_in_bytes_above_fp_ =
      kSystemPointerSize * (allocatable_register_count + padding_slot_count +
                            push_result_count) +
      (BuiltinContinuationFrameConstants::kFixedFrameSize -
       BuiltinContinuationFrameConstants::kFixedFrameSizeAboveFp);
}

}  // namespace internal
}  // namespace v8
```