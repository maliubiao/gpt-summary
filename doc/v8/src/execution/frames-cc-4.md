Response:
The user wants a summary of the provided C++ code snippet from `v8/src/execution/frames.cc`. The request has several constraints:

1. **List Functionality:** Describe what the code does.
2. **Torque Check:** Determine if the file is a Torque file (it's not, as it doesn't end with `.tq`).
3. **JavaScript Relation:** If related to JavaScript functionality, provide a JavaScript example.
4. **Code Logic Inference:** If there's code logic, provide example input and output.
5. **Common Programming Errors:**  Mention any common programming errors the code might relate to.
6. **Part of a Series:** This is part 5 of 6, so the summary should focus on the functions provided in this specific snippet.

**Plan:**

1. **High-level overview:** Understand the general purpose of `frames.cc` (handling stack frames).
2. **Individual function analysis:** Analyze each function in the provided snippet:
    - `InterpretedFrame::GetBytecodeOffset()`: Retrieves bytecode offset from an interpreted frame.
    - `InterpretedFrame::PatchBytecodeOffset()`: Updates the bytecode offset in an interpreted frame.
    - `InterpretedFrame::PatchBytecodeArray()`: Updates the bytecode array in an interpreted frame.
    - `BaselineFrame::GetBytecodeOffset()`: Retrieves bytecode offset from a baseline frame.
    - `BaselineFrame::GetPCForBytecodeOffset()`: Gets the program counter for a given bytecode offset in a baseline frame.
    - `BaselineFrame::PatchContext()`: Updates the context in a baseline frame.
    - `BuiltinFrame::function()`: Gets the JSFunction associated with a built-in frame.
    - `BuiltinFrame::ComputeParametersCount()`: Calculates the number of parameters for a built-in function.
    - `WasmFrame::Print()`: Prints information about a WebAssembly frame.
    - `WasmFrame::wasm_code()`: Retrieves the WasmCode object for a Wasm frame.
    - `WasmFrame::wasm_instance()`: Gets the WasmInstanceObject for a Wasm frame.
    - `WasmFrame::trusted_instance_data()`: Retrieves the WasmTrustedInstanceData for a Wasm frame.
    - `WasmFrame::native_module()`: Gets the NativeModule associated with a Wasm frame.
    - `WasmFrame::module_object()`: Gets the WasmModuleObject for a Wasm frame.
    - `WasmFrame::function_index()`: Gets the function index within the Wasm module.
    - `WasmFrame::script()`: Retrieves the Script object for a Wasm frame.
    - `WasmFrame::position()`: Gets the source code position within the Wasm function.
    - `WasmFrame::generated_code_offset()`: Calculates the offset within the generated code.
    - `WasmFrame::is_inspectable()`: Checks if the Wasm frame is inspectable.
    - `WasmFrame::context()`: Gets the context associated with a Wasm frame.
    - `WasmFrame::Summarize()`: Creates a summary of the Wasm frame for debugging.
    - `WasmFrame::at_to_number_conversion()`: Checks if the frame is at a ToNumber conversion point in Wasm-to-JS calls.
    - `WasmFrame::LookupExceptionHandlerInTable()`: Looks up exception handlers in the Wasm code's handler table.
    - `WasmDebugBreakFrame::Iterate()`: Iterates over roots within a Wasm debug break frame for garbage collection.
    - `WasmDebugBreakFrame::Print()`: Prints information about a Wasm debug break frame.
    - `WasmToJsFrame::wasm_instance()`: Retrieves the WasmInstanceObject for a Wasm-to-JS frame.
    - `WasmToJsFrame::trusted_instance_data()`: Retrieves the WasmTrustedInstanceData for a Wasm-to-JS frame.
    - `JsToWasmFrame::Iterate()`: Iterates over roots within a JS-to-Wasm frame for garbage collection.
    - `WasmToJsFrame::Iterate()`: Iterates over roots within a Wasm-to-JS frame for garbage collection (with DRUMBRAKE).
    - `StackSwitchFrame::Iterate()`: Iterates over roots within a stack switch frame for garbage collection.
    - `StackSwitchFrame::GetStateForJumpBuffer()`: Retrieves the state for a jump buffer.
    - `WasmInterpreterEntryFrame::Iterate()`: Iterates over roots within a Wasm interpreter entry frame for garbage collection (with DRUMBRAKE).
    - `WasmInterpreterEntryFrame::Print()`: Prints information about a Wasm interpreter entry frame.
    - `WasmInterpreterEntryFrame::Summarize()`: Creates a summary of the Wasm interpreter entry frame.
    - `WasmInterpreterEntryFrame::unchecked_code()`: Returns the instruction stream (for interpreter frames).
    - `WasmInterpreterEntryFrame::wasm_instance()`: Gets the WasmInstanceObject for a Wasm interpreter entry frame.
    - `WasmInterpreterEntryFrame::trusted_instance_data()`: Retrieves the WasmTrustedInstanceData for a Wasm interpreter entry frame.
    - `WasmInterpreterEntryFrame::interpreter_object()`: Gets the interpreter object for a Wasm interpreter entry frame.
    - `WasmInterpreterEntryFrame::module_object()`: Gets the WasmModuleObject for a Wasm interpreter entry frame.
    - `WasmInterpreterEntryFrame::function_index()`: Gets the function index within the Wasm module for an interpreter frame.
    - `WasmInterpreterEntryFrame::position()`: Gets the source code position within the Wasm function for an interpreter frame.
    - `WasmInterpreterEntryFrame::context()`: Gets the context associated with a Wasm interpreter entry frame.
    - `WasmInterpreterEntryFrame::GetCallerStackPointer()`: Gets the caller's stack pointer for a Wasm interpreter entry frame.
    - `WasmLiftoffSetupFrame::GetDeclaredFunctionIndex()`: Gets the declared function index for a Liftoff setup frame.
    - `WasmLiftoffSetupFrame::GetNativeModule()`: Gets the NativeModule for a Liftoff setup frame.
    - `WasmLiftoffSetupFrame::wasm_instance_data_slot()`: Gets the slot for the Wasm instance data in a Liftoff setup frame.
    - `WasmLiftoffSetupFrame::Iterate()`: Iterates over roots within a Wasm Liftoff setup frame for garbage collection.
    - `JavaScriptFrame::Print()`: Prints information about a JavaScript frame.
    - `EntryFrame::Iterate()`: Iterates over roots within an entry frame for garbage collection.
    - `CommonFrame::IterateExpressions()`: Iterates over expressions on the stack for garbage collection.
    - `JavaScriptFrame::Iterate()`: Iterates over roots within a JavaScript frame for garbage collection.

3. **JavaScript Examples:** For functions related to JavaScript execution (like retrieving bytecode offsets or parameters), provide simple examples.
4. **Logic Inference:** For functions that perform calculations or lookups, create hypothetical scenarios with inputs and expected outputs.
5. **Common Errors:** Relate frame manipulation to potential programming errors in JavaScript or WebAssembly.
6. **Concise Summary:** Combine the analysis into a summary of the file's purpose based on the provided functions.

**Self-Correction/Refinement:**

- Focus on the *functionality* of each method, not necessarily the low-level C++ details.
- Keep JavaScript examples simple and illustrative.
- Ensure the input/output examples for logic inference are clear and directly related to the function's purpose.
- When discussing common errors, link them to the high-level concepts the functions are manipulating (e.g., incorrect bytecode offset leading to unexpected behavior).
这是 `v8/src/execution/frames.cc` 源代码的第五部分，它主要负责处理 V8 虚拟机中不同类型的**栈帧 (stack frames)**。栈帧是程序执行期间在调用栈上为每个函数调用分配的内存区域，用于存储函数的局部变量、参数、返回地址以及其他控制信息。

**功能归纳:**

这部分代码定义和实现了多种栈帧的操作，特别是关注于 **WebAssembly (Wasm)** 相关的栈帧类型，但也包括对 **解释执行 (Interpreter)** 和 **基线编译 (Baseline)** 的栈帧的处理。其核心功能在于：

1. **访问和修改栈帧数据:**  提供了方法来获取和设置栈帧中存储的关键信息，例如：
    - 字节码偏移量 (`BytecodeOffset`)
    - 字节码数组 (`BytecodeArray`)
    - 上下文 (`Context`)
    - 函数对象 (`JSFunction`)
    - 参数数量
    - WebAssembly 实例数据 (`WasmInstanceObject`, `WasmTrustedInstanceData`)
    - WebAssembly 代码对象 (`WasmCode`)
    - WebAssembly 模块对象 (`WasmModuleObject`)
    - WebAssembly 函数索引 (`function_index`)
    - 源代码位置 (`position`)
    - 表达式栈 (`expression stack`)

2. **打印栈帧信息:** 提供了 `Print` 方法，用于以不同的模式（例如，详细信息或概览）输出栈帧的各种信息，这对于调试和性能分析非常有用。

3. **支持垃圾回收 (GC):**  实现了 `Iterate` 方法，用于遍历栈帧中可能包含的指向堆内存的指针 (roots)，以便垃圾回收器能够正确地追踪和管理这些对象。

4. **WebAssembly 特定的栈帧处理:**  定义了多种用于处理 WebAssembly 执行的栈帧类型，例如 `WasmFrame`, `WasmDebugBreakFrame`, `WasmToJsFrame`, `JsToWasmFrame`, `WasmInterpreterEntryFrame`, `WasmLiftoffSetupFrame`。这些栈帧类型包含了 WebAssembly 执行所需的特定信息，并提供了访问这些信息的方法。

**关于代码特征：**

* **`.tq` 后缀:**  `v8/src/execution/frames.cc` **没有**以 `.tq` 结尾，所以它不是一个 V8 Torque 源代码文件。 Torque 是一种用于生成 V8 代码的类型化的中间语言。

**与 JavaScript 的关系及示例:**

虽然这段代码本身是 C++，但它直接支持 JavaScript 和 WebAssembly 的执行。栈帧是执行 JavaScript 函数和 WebAssembly 模块的关键结构。

例如，`JavaScriptFrame::Print` 方法在打印 JavaScript 栈帧信息时会涉及到 JavaScript 函数、接收者 (this)、参数等概念。

```javascript
function myFunction(a, b) {
  console.trace(); // 打印当前调用栈信息，其中就包含栈帧信息
  return a + b;
}

myFunction(1, 2);
```

当执行 `console.trace()` 时，V8 内部会遍历调用栈，并使用类似 `JavaScriptFrame::Print` 的方法来格式化输出栈帧信息，其中会包含函数名 `myFunction`，参数 `a` 和 `b` 的值等。

对于 WebAssembly，当 JavaScript 调用 WebAssembly 函数，或者 WebAssembly 调用 JavaScript 函数时，会创建相应的 Wasm 相关的栈帧。

```javascript
// 假设有一个编译好的 WebAssembly 模块实例 'wasmInstance'
const add = wasmInstance.exports.add; // 假设 WebAssembly 模块导出了一个 'add' 函数
add(5, 10);
```

当调用 `add(5, 10)` 时，会创建一个 `WasmFrame` 或 `WasmToJsFrame` (如果 `add` 函数内部调用了 JavaScript) 栈帧，其中会包含 WebAssembly 实例、函数索引等信息，这些信息可以通过代码中的方法（如 `WasmFrame::function_index()`）访问。

**代码逻辑推理及示例:**

以 `InterpretedFrame::GetBytecodeOffset()` 为例：

**假设输入:**  一个指向 `InterpretedFrame` 对象的指针 `frame`。

**代码逻辑:**  该函数通过固定的偏移量从栈帧中获取存储字节码偏移量的表达式，并将其转换为整数。

**假设输出:**  如果栈帧中存储的字节码偏移量表达式是 `Smi(100)`，那么该函数将返回 `100 - BytecodeArray::kHeaderSize + kHeapObjectTag` 的值。这里的 `BytecodeArray::kHeaderSize` 和 `kHeapObjectTag` 是 V8 内部用于表示堆对象的常量。

以 `BaselineFrame::GetBytecodeOffset()` 为例：

**假设输入:**  一个指向 `BaselineFrame` 对象的指针 `frame`。

**代码逻辑:** 该函数首先通过 `LookupCode()` 获取与该栈帧关联的 `Code` 对象（已编译的代码），然后调用 `GetBytecodeOffsetForBaselinePC()` 方法，传入当前程序计数器 (`pc()`) 和字节码数组 (`GetBytecodeArray()`) 来计算字节码偏移量。

**假设输入:**  `frame->pc()` 指向已编译代码中与某个字节码指令对应的位置，`GetBytecodeArray()` 返回一个 `BytecodeArray` 对象。

**假设输出:**  `GetBytecodeOffsetForBaselinePC()` 方法会根据 `pc()` 在代码中的位置，查找对应的字节码偏移量并返回。

**用户常见的编程错误:**

与栈帧操作相关的常见编程错误通常发生在与 JavaScript 和 WebAssembly 互操作时，或者在进行底层调试时：

1. **错误的函数签名或参数传递:**  在 JavaScript 调用 WebAssembly 函数时，如果传递的参数类型或数量与 WebAssembly 函数的预期不符，会导致创建的栈帧信息不正确，或者在执行时发生错误。V8 会进行类型检查，但理解栈帧结构有助于排查此类问题。

2. **WebAssembly 模块链接错误:** 如果 WebAssembly 模块的导入和导出配置不正确，可能导致在尝试调用导入的函数时，栈帧信息指向错误的位置。

3. **在调试器中错误地分析栈帧:**  当使用调试器查看调用栈时，理解不同类型的栈帧以及它们包含的信息对于正确理解程序执行流程至关重要。错误地假设栈帧的布局可能导致对程序状态的误判。

4. **不正确的内联优化假设:**  优化后的代码可能导致栈帧结构与未优化代码不同。例如，内联函数可能不会创建独立的栈帧。在分析性能问题时，需要考虑这种差异。

**总结:**

作为 `v8/src/execution/frames.cc` 的一部分，这段代码专注于管理和操作 V8 虚拟机中的各种栈帧，特别是与 WebAssembly 执行相关的栈帧。它提供了访问、修改和打印栈帧数据的方法，并支持垃圾回收。虽然是 C++ 代码，但其功能直接支撑着 JavaScript 和 WebAssembly 的执行，对于理解 V8 的执行模型、调试和性能分析至关重要。

### 提示词
```
这是目录为v8/src/execution/frames.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/execution/frames.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
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
  FullObjectSlot limit(&Memory<Addres
```