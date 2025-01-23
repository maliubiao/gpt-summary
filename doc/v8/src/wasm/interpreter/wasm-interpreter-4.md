Response: The user wants to understand the functionality of the C++ code snippet provided, which is part 5 of an 8-part series of a file related to the V8 JavaScript engine's WebAssembly interpreter.

The code mainly defines instruction handlers for various WebAssembly operations. These handlers are functions that execute specific WebAssembly instructions during interpretation. Many of these instructions seem related to reference types and type checking, as well as conversions between JavaScript values and WebAssembly values. There's also a section related to tracing/debugging the interpreter.

To illustrate the connection with JavaScript, I can show how some of these WebAssembly instructions, especially the ones involving `WasmRef` and type conversions, could be used in a WebAssembly module that interacts with JavaScript.

Here's a breakdown of the code's functionality:

1. **Reference Type Operations:**  Several handlers deal with `WasmRef`, which represents a WebAssembly reference. These include:
    *   `s2s_RefI31`: Creating a reference to a 31-bit integer.
    *   `s2s_I31GetS`, `s2s_I31GetU`: Extracting signed and unsigned 31-bit integers from a reference.
    *   `s2s_RefCast`, `s2s_RefCastNull`: Casting references to specific types, potentially succeeding even if the reference is null.
    *   `s2s_RefTest`, `s2s_RefTestNull`: Testing if a reference can be cast to a specific type.
    *   `s2s_AssertNullTypecheck`, `s2s_AssertNotNullTypecheck`: Asserting the nullability of a reference against its declared type.
    *   `s2s_RefIsNonNull`, `s2s_RefAsNonNull`: Checking if a reference is not null and asserting that it's not null.

2. **JavaScript Interoperability:**  Handlers for converting between JavaScript and WebAssembly references:
    *   `s2s_AnyConvertExtern`: Converting a `WasmRef` (potentially from JavaScript) to a WebAssembly `externref`.
    *   `s2s_ExternConvertAny`: Converting a `WasmRef` (likely an `externref`) to a general WebAssembly reference, potentially returning null.

3. **Error Handling:**  `s2s_TrapIllegalCast`: A handler that triggers a trap due to an illegal cast.

4. **Control Flow Hints:** `s2s_RefTestSucceeds`, `s2s_RefTestFails`: Handlers that push boolean values onto the stack, likely used as hints for branch prediction during compilation or interpretation.

5. **Debugging and Tracing:**  A significant portion is dedicated to tracing the execution of the interpreter:
    *   `s2s_TraceInstruction`: Prints information about the currently executed instruction.
    *   `trace_UpdateStack`: Records updates to the interpreter's stack.
    *   `trace_PushConstSlot`, `trace_PushCopySlot`, `trace_PopSlot`: Trace stack push, copy, and pop operations.
    *   `trace_SetSlotType`: Records the type of a slot on the stack.
    *   The `ShadowStack` and `ShadowStack::Slot` structures and their `Print` methods are used for visualizing the interpreter's stack during tracing.

6. **Instruction Table:** `kInstructionTable`:  A large array that maps WebAssembly opcodes to their corresponding instruction handler functions. This is a crucial part of the interpreter's dispatch mechanism.

7. **Exception Handling Data:** The code defines structures (`WasmEHData`, `WasmEHData::TryBlock`, etc.) and related functions for managing WebAssembly's exception handling mechanism. It tracks try blocks, catch blocks, and the association between code offsets and try-catch regions.

8. **Bytecode Generation:** The `WasmBytecodeGenerator` class is responsible for converting WebAssembly bytecode into a more interpreter-friendly format. It manages the interpreter's stack, local variables, and constant values. It also integrates with the tracing mechanism.

**JavaScript Example:**

Consider the `s2s_AnyConvertExtern` and `s2s_ExternConvertAny` handlers. These are key to interaction between WebAssembly and JavaScript's garbage-collected heap.

```javascript
// JavaScript code
const importObject = {
  js: {
    getValue: () => {
      return { type: 'js_object', value: 'Hello from JS' };
    }
  }
};

WebAssembly.instantiateStreaming(fetch('module.wasm'), importObject)
  .then(result => {
    const wasmInstance = result.instance;
    const wasmGetValue = wasmInstance.exports.getValueFromJS;
    const jsValue = wasmGetValue();
    console.log(jsValue); // Output: { type: 'js_object', value: 'Hello from JS' }
  });
```

```wat
;; WebAssembly module (module.wasm)
(module
  (import "js" "getValue" (func $getValue (result externref)))
  (func $getValueFromJS (result externref)
    call $getValue
    ;; The 'anyref.to_externref' equivalent operation
    ;; would involve the s2s_AnyConvertExtern handler.
  )
  (export "getValueFromJS" (func $getValueFromJS))
)
```

In this example:

*   The JavaScript code imports a WebAssembly module.
*   The WebAssembly module imports a JavaScript function `getValue` that returns a JavaScript object (represented as an `externref` in WebAssembly).
*   The WebAssembly function `$getValueFromJS` calls the imported JavaScript function.
*   Internally, when the WebAssembly interpreter executes the call to the imported function and receives the JavaScript object, the `s2s_AnyConvertExtern` handler (or its compiled equivalent) might be involved in representing this JavaScript value within the WebAssembly environment.

Similarly, if the WebAssembly module needed to pass a WebAssembly reference (like a struct or array) back to JavaScript, the `s2s_ExternConvertAny` handler would be involved in converting that WebAssembly reference into a JavaScript-compatible representation.

In summary, this part of the V8 WebAssembly interpreter source code defines the core logic for handling various WebAssembly instructions, particularly those related to reference types, JavaScript interoperability, and includes a detailed tracing mechanism for debugging. It lays the groundwork for how the interpreter fetches, decodes, and executes WebAssembly code.
这是目录为`v8/src/wasm/interpreter/wasm-interpreter.cc` 的 C++ 源代码文件的第 5 部分（共 8 部分）。根据提供的代码片段，其主要功能可以归纳为：

**1. 定义 WebAssembly 解释器中与引用类型和类型转换相关的指令处理函数 (Instruction Handlers)。**

这部分代码专注于处理 WebAssembly 中引入的引用类型 (`WasmRef`) 和相关的操作，例如：

*   **`s2s_RefI31`**:  创建一个 `i31ref`，它是一个指向 31 位有符号整数的引用。
*   **`s2s_I31GetS` 和 `s2s_I31GetU`**: 从 `i31ref` 中提取有符号和无符号的 31 位整数值。
*   **`s2s_RefCast` 和 `s2s_RefCastNull`**:  将一个引用类型转换为另一个引用类型。`RefCastNull` 允许在输入为 null 的情况下转换成功。
*   **`s2s_RefTest` 和 `s2s_RefTestNull`**: 测试一个引用是否可以成功转换为指定的类型。`RefTestNull` 允许在输入为 null 的情况下测试成功。
*   **`s2s_AssertNullTypecheck` 和 `s2s_AssertNotNullTypecheck`**: 断言一个引用是否为 null，根据其类型信息进行检查。
*   **`s2s_RefIsNonNull`**: 检查一个引用是否非空。
*   **`s2s_RefAsNonNull`**: 断言一个引用非空，如果为空则触发陷阱。

**2. 处理 WebAssembly 与 JavaScript 之间的互操作性，特别是引用类型的转换。**

*   **`s2s_AnyConvertExtern`**: 将一个 WebAssembly 引用（`WasmRef`）转换为一个 `externref`。这通常用于将 JavaScript 值传递给 WebAssembly。
*   **`s2s_ExternConvertAny`**: 将一个 `externref` 转换为一个通用的 WebAssembly 引用 (`WasmRef`)。这通常用于将 WebAssembly 值传递回 JavaScript。

**3. 提供用于调试和追踪 WebAssembly 解释器执行的工具。**

代码包含了一系列以 `trace_` 开头的指令处理函数，这些函数在启用了特定的编译选项 (`V8_ENABLE_DRUMBRAKE_TRACING`) 时会被使用。这些函数用于：

*   **`s2s_TraceInstruction`**: 打印当前执行的指令信息。
*   **`trace_UpdateStack`**: 记录栈的更新。
*   **`trace_PushConstSlot`**, **`trace_PushCopySlot`**, **`trace_PopSlot`**: 记录常量值压栈、复制槽位和弹出槽位的操作。
*   **`trace_SetSlotType`**: 记录栈槽位的类型信息。
*   定义了 `ShadowStack` 和 `ShadowStack::Slot` 结构体，用于在追踪时表示和打印解释器的栈状态。

**4. 定义了指令表 (`kInstructionTable`) 的一部分。**

`kInstructionTable` 是一个函数指针数组，用于将 WebAssembly 的操作码映射到相应的指令处理函数。这部分代码初始化了部分指令表，特别是那些与本代码片段功能相关的指令。

**5. 实现了 WebAssembly 异常处理数据 (`WasmEHData`) 的相关逻辑。**

定义了 `WasmEHData` 结构体及其相关的辅助结构体（如 `TryBlock`，`CatchBlock`）和函数，用于管理 WebAssembly 的 try-catch 块信息。这包括：

*   存储和检索 try 块和 catch 块的信息。
*   记录代码偏移与 try-catch 块的对应关系。
*   处理 `try`，`catch`，`catch_all` 和 `delegate` 指令。

**6. 实现了 `WasmBytecodeGenerator` 类的一部分功能。**

`WasmBytecodeGenerator` 负责将 WebAssembly 的字节码转换成解释器可以执行的中间表示。这部分代码涉及：

*   管理解释器的栈 (`stack_`) 和槽位 (`slots_`)。
*   实现槽位的分配、复制和更新操作。
*   处理函数参数、局部变量和常量。
*   生成用于跳转和循环的指令。
*   与异常处理数据生成器 (`WasmEHDataGenerator`) 交互。
*   集成追踪功能。

**与 JavaScript 的关系及示例:**

这部分代码与 JavaScript 的主要关系在于 WebAssembly 的互操作性。WebAssembly 可以在 JavaScript 虚拟机中运行，并且可以与 JavaScript 代码进行交互。

例如，`s2s_AnyConvertExtern` 允许 WebAssembly 代码接收来自 JavaScript 的值。在 JavaScript 中，所有的对象都是引用。当 JavaScript 将一个对象传递给 WebAssembly 时，它会被转换为一个 `externref`。

```javascript
// JavaScript 代码
const importObject = {
  js: {
    log: (ref) => {
      console.log("Received ref from WASM:", ref);
    }
  }
};

WebAssembly.instantiateStreaming(fetch('module.wasm'), importObject)
  .then(result => {
    const wasmInstance = result.instance;
    const jsObject = { message: "Hello from JavaScript!" };
    wasmInstance.exports.processObject(jsObject);
  });
```

```wat
;; WebAssembly 代码 (module.wasm)
(module
  (import "js" "log" (func $log (param externref)))
  (func $processObject (export "processObject") (param $obj externref)
    local.get $obj  ;; 获取传入的 externref
    call $log       ;; 调用 JavaScript 的 log 函数
  )
)
```

在这个例子中，当 `wasmInstance.exports.processObject(jsObject)` 被调用时，`jsObject` 会被传递给 WebAssembly 的 `$processObject` 函数。在 WebAssembly 内部，`$obj` 参数的类型是 `externref`，它是由 JavaScript 对象转换而来。当 WebAssembly 调用 `call $log` 时，会将这个 `externref` 传递回 JavaScript 的 `log` 函数。  `s2s_AnyConvertExtern` 这样的指令处理函数会在 WebAssembly 接收 JavaScript 值时发挥作用，确保类型和值的正确转换。

反之，`s2s_ExternConvertAny` 则用于将 WebAssembly 的引用传递回 JavaScript。

总而言之，这部分代码是 V8 WebAssembly 解释器的核心组成部分，负责处理引用类型、类型转换以及与 JavaScript 的互操作，并提供了重要的调试和追踪能力。

### 提示词
```
这是目录为v8/src/wasm/interpreter/wasm-interpreter.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第5部分，共8部分，请归纳一下它的功能
```

### 源代码
```
ate high bit.
  Tagged<Smi> smi(Internals::IntToSmi(value & 0x7fffffff));
  push<WasmRef>(sp, code, wasm_runtime,
                handle(smi, wasm_runtime->GetIsolate()));

  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_I31GetS(const uint8_t* code, uint32_t* sp,
                                     WasmInterpreterRuntime* wasm_runtime,
                                     int64_t r0, double fp0) {
  WasmRef ref = pop<WasmRef>(sp, code, wasm_runtime);
  if (V8_UNLIKELY(wasm_runtime->IsRefNull(ref))) {
    TRAP(TrapReason::kTrapNullDereference)
  }
  DCHECK(IsSmi(*ref));
  push<int32_t>(sp, code, wasm_runtime, i::Smi::ToInt(*ref));

  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_I31GetU(const uint8_t* code, uint32_t* sp,
                                     WasmInterpreterRuntime* wasm_runtime,
                                     int64_t r0, double fp0) {
  WasmRef ref = pop<WasmRef>(sp, code, wasm_runtime);
  if (V8_UNLIKELY(wasm_runtime->IsRefNull(ref))) {
    TRAP(TrapReason::kTrapNullDereference)
  }
  DCHECK(IsSmi(*ref));
  push<uint32_t>(sp, code, wasm_runtime,
                 0x7fffffff & static_cast<uint32_t>(i::Smi::ToInt(*ref)));

  NextOp();
}

template <bool null_succeeds>
INSTRUCTION_HANDLER_FUNC RefCast(const uint8_t* code, uint32_t* sp,
                                 WasmInterpreterRuntime* wasm_runtime,
                                 int64_t r0, double fp0) {
  HeapType target_type(ReadI32(code));

  WasmRef ref = pop<WasmRef>(sp, code, wasm_runtime);

  const uint32_t ref_bitfield = ReadI32(code);
  ValueType ref_type = ValueType::FromRawBitField(ref_bitfield);

  if (!DoRefCast(ref, ref_type, target_type, null_succeeds, wasm_runtime)) {
    TRAP(TrapReason::kTrapIllegalCast)
  }

  push<WasmRef>(sp, code, wasm_runtime, ref);

  NextOp();
}
static auto s2s_RefCast = RefCast<false>;
static auto s2s_RefCastNull = RefCast<true>;

template <bool null_succeeds>
INSTRUCTION_HANDLER_FUNC RefTest(const uint8_t* code, uint32_t* sp,
                                 WasmInterpreterRuntime* wasm_runtime,
                                 int64_t r0, double fp0) {
  HeapType target_type(ReadI32(code));

  WasmRef ref = pop<WasmRef>(sp, code, wasm_runtime);

  const uint32_t ref_bitfield = ReadI32(code);
  ValueType ref_type = ValueType::FromRawBitField(ref_bitfield);

  bool cast_succeeds =
      DoRefCast(ref, ref_type, target_type, null_succeeds, wasm_runtime);
  push<int32_t>(sp, code, wasm_runtime, cast_succeeds ? 1 : 0);

  NextOp();
}
static auto s2s_RefTest = RefTest<false>;
static auto s2s_RefTestNull = RefTest<true>;

INSTRUCTION_HANDLER_FUNC s2s_AssertNullTypecheck(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0) {
  WasmRef ref = pop<WasmRef>(sp, code, wasm_runtime);

  const uint32_t ref_bitfield = ReadI32(code);
  ValueType ref_type = ValueType::FromRawBitField(ref_bitfield);
  if (!wasm_runtime->IsNullTypecheck(ref, ref_type)) {
    TRAP(TrapReason::kTrapIllegalCast)
  }
  push<WasmRef>(sp, code, wasm_runtime, ref);

  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_AssertNotNullTypecheck(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0) {
  WasmRef ref = pop<WasmRef>(sp, code, wasm_runtime);

  const uint32_t ref_bitfield = ReadI32(code);
  ValueType ref_type = ValueType::FromRawBitField(ref_bitfield);
  if (wasm_runtime->IsNullTypecheck(ref, ref_type)) {
    TRAP(TrapReason::kTrapIllegalCast)
  }
  push<WasmRef>(sp, code, wasm_runtime, ref);

  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_TrapIllegalCast(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0){TRAP(TrapReason::kTrapIllegalCast)}

INSTRUCTION_HANDLER_FUNC
    s2s_RefTestSucceeds(const uint8_t* code, uint32_t* sp,
                        WasmInterpreterRuntime* wasm_runtime, int64_t r0,
                        double fp0) {
  pop<WasmRef>(sp, code, wasm_runtime);
  push<int32_t>(sp, code, wasm_runtime, 1);  // true

  NextOp();
}

INSTRUCTION_HANDLER_FUNC
s2s_RefTestFails(const uint8_t* code, uint32_t* sp,
                 WasmInterpreterRuntime* wasm_runtime, int64_t r0, double fp0) {
  pop<WasmRef>(sp, code, wasm_runtime);
  push<int32_t>(sp, code, wasm_runtime, 0);  // false

  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_RefIsNonNull(const uint8_t* code, uint32_t* sp,
                                          WasmInterpreterRuntime* wasm_runtime,
                                          int64_t r0, double fp0) {
  WasmRef ref = pop<WasmRef>(sp, code, wasm_runtime);
  push<int32_t>(sp, code, wasm_runtime, wasm_runtime->IsRefNull(ref) ? 0 : 1);

  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_RefAsNonNull(const uint8_t* code, uint32_t* sp,
                                          WasmInterpreterRuntime* wasm_runtime,
                                          int64_t r0, double fp0) {
  WasmRef ref = pop<WasmRef>(sp, code, wasm_runtime);
  if (V8_UNLIKELY(wasm_runtime->IsRefNull(ref))) {
    TRAP(TrapReason::kTrapNullDereference)
  }
  push<WasmRef>(sp, code, wasm_runtime, ref);

  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_AnyConvertExtern(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0) {
  WasmRef extern_ref = pop<WasmRef>(sp, code, wasm_runtime);
  // Pass 0 as canonical type index; see implementation of builtin
  // WasmAnyConvertExtern.
  WasmRef result = wasm_runtime->WasmJSToWasmObject(
      extern_ref, kWasmAnyRef, 0 /* canonical type index */);
  if (V8_UNLIKELY(result.is_null())) {
    wasm::TrapReason reason = WasmInterpreterThread::GetRuntimeLastWasmError(
        wasm_runtime->GetIsolate());
    INLINED_TRAP(reason)
  }
  push<WasmRef>(sp, code, wasm_runtime, result);

  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_ExternConvertAny(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0) {
  WasmRef ref = pop<WasmRef>(sp, code, wasm_runtime);

  if (wasm_runtime->IsNullTypecheck(ref, kWasmAnyRef)) {
    ref = handle(wasm_runtime->GetNullValue(kWasmExternRef),
                 wasm_runtime->GetIsolate());
  }
  push<WasmRef>(sp, code, wasm_runtime, ref);

  NextOp();
}

#ifdef V8_ENABLE_DRUMBRAKE_TRACING

INSTRUCTION_HANDLER_FUNC s2s_TraceInstruction(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0) {
  uint32_t pc = ReadI32(code);
  uint32_t opcode = ReadI32(code);
  uint32_t reg_mode = ReadI32(code);

  if (v8_flags.trace_drumbrake_execution) {
    wasm_runtime->Trace(
        "@%-3u:         %-24s: ", pc,
        wasm::WasmOpcodes::OpcodeName(static_cast<WasmOpcode>(opcode)));
    wasm_runtime->PrintStack(sp, static_cast<RegMode>(reg_mode), r0, fp0);
  }

  NextOp();
}

INSTRUCTION_HANDLER_FUNC trace_UpdateStack(const uint8_t* code, uint32_t* sp,
                                           WasmInterpreterRuntime* wasm_runtime,
                                           int64_t r0, double fp0) {
  uint32_t stack_index = ReadI32(code);
  uint32_t slot_offset = ReadI32(code);
  wasm_runtime->TraceUpdate(stack_index, slot_offset);

  NextOp();
}

template <typename T>
INSTRUCTION_HANDLER_FUNC trace_PushConstSlot(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0) {
  uint32_t slot_offset = ReadI32(code);
  wasm_runtime->TracePush<T>(slot_offset * kSlotSize);

  NextOp();
}
static auto trace_PushConstI32Slot = trace_PushConstSlot<int32_t>;
static auto trace_PushConstI64Slot = trace_PushConstSlot<int64_t>;
static auto trace_PushConstF32Slot = trace_PushConstSlot<float>;
static auto trace_PushConstF64Slot = trace_PushConstSlot<double>;
static auto trace_PushConstS128Slot = trace_PushConstSlot<Simd128>;
static auto trace_PushConstRefSlot = trace_PushConstSlot<WasmRef>;

void WasmBytecodeGenerator::TracePushConstSlot(uint32_t slot_index) {
  if (v8_flags.trace_drumbrake_execution) {
    switch (slots_[slot_index].kind()) {
      case kI32:
        EMIT_INSTR_HANDLER(trace_PushConstI32Slot);
        break;
      case kI64:
        EMIT_INSTR_HANDLER(trace_PushConstI64Slot);
        break;
      case kF32:
        EMIT_INSTR_HANDLER(trace_PushConstF32Slot);
        break;
      case kF64:
        EMIT_INSTR_HANDLER(trace_PushConstF64Slot);
        break;
      case kS128:
        EMIT_INSTR_HANDLER(trace_PushConstS128Slot);
        break;
      case kRef:
      case kRefNull:
        EMIT_INSTR_HANDLER(trace_PushConstRefSlot);
        break;
      default:
        UNREACHABLE();
    }
    EmitI32Const(slots_[slot_index].slot_offset);
  }
}

INSTRUCTION_HANDLER_FUNC trace_PushCopySlot(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0) {
  uint32_t index = ReadI32(code);

  wasm_runtime->TracePushCopy(index);

  NextOp();
}

void WasmBytecodeGenerator::TracePushCopySlot(uint32_t from) {
  if (v8_flags.trace_drumbrake_execution) {
    EMIT_INSTR_HANDLER(trace_PushCopySlot);
    EmitI32Const(from);
  }
}

INSTRUCTION_HANDLER_FUNC trace_PopSlot(const uint8_t* code, uint32_t* sp,
                                       WasmInterpreterRuntime* wasm_runtime,
                                       int64_t r0, double fp0) {
  wasm_runtime->TracePop();

  NextOp();
}

INSTRUCTION_HANDLER_FUNC trace_SetSlotType(const uint8_t* code, uint32_t* sp,
                                           WasmInterpreterRuntime* wasm_runtime,
                                           int64_t r0, double fp0) {
  uint32_t stack_index = ReadI32(code);
  uint32_t type = ReadI32(code);
  wasm_runtime->TraceSetSlotType(stack_index, type);

  NextOp();
}

void WasmBytecodeGenerator::TraceSetSlotType(uint32_t stack_index,
                                             ValueType type) {
  if (v8_flags.trace_drumbrake_execution) {
    EMIT_INSTR_HANDLER(trace_SetSlotType);
    EmitI32Const(stack_index);
    EmitI32Const(type.raw_bit_field());
  }
}

void ShadowStack::Print(WasmInterpreterRuntime* wasm_runtime,
                        const uint32_t* sp, size_t start_params,
                        size_t start_locals, size_t start_stack,
                        RegMode reg_mode, int64_t r0, double fp0) const {
  for (size_t i = 0; i < stack_.size(); i++) {
    char slot_kind = i < start_locals - start_params  ? 'p'
                     : i < start_stack - start_params ? 'l'
                                                      : 's';
    const uint8_t* addr =
        reinterpret_cast<const uint8_t*>(sp) + stack_[i].slot_offset_;
    stack_[i].Print(wasm_runtime, start_params + i, slot_kind, addr);
  }

  switch (reg_mode) {
    case RegMode::kI32Reg:
      ShadowStack::Slot::Print(wasm_runtime, kWasmI32,
                               start_params + stack_.size(), 'R',
                               reinterpret_cast<const uint8_t*>(&r0));
      break;
    case RegMode::kI64Reg:
      ShadowStack::Slot::Print(wasm_runtime, kWasmI64,
                               start_params + stack_.size(), 'R',
                               reinterpret_cast<const uint8_t*>(&r0));
      break;
    case RegMode::kF32Reg: {
      float f = static_cast<float>(fp0);
      ShadowStack::Slot::Print(wasm_runtime, kWasmF32,
                               start_params + stack_.size(), 'R',
                               reinterpret_cast<const uint8_t*>(&f));
    } break;
    case RegMode::kF64Reg:
      ShadowStack::Slot::Print(wasm_runtime, kWasmF64,
                               start_params + stack_.size(), 'R',
                               reinterpret_cast<const uint8_t*>(&fp0));
      break;
    default:
      break;
  }

  wasm_runtime->Trace("\n");
}

// static
void ShadowStack::Slot::Print(WasmInterpreterRuntime* wasm_runtime,
                              ValueType type, size_t index, char kind,
                              const uint8_t* addr) {
  switch (type.kind()) {
    case kI32:
      wasm_runtime->Trace(
          "%c%zu:i32:%d ", kind, index,
          base::ReadUnalignedValue<int32_t>(reinterpret_cast<Address>(addr)));
      break;
    case kI64:
      wasm_runtime->Trace(
          "%c%zu:i64:%" PRId64, kind, index,
          base::ReadUnalignedValue<int64_t>(reinterpret_cast<Address>(addr)));
      break;
    case kF32: {
      float f =
          base::ReadUnalignedValue<float>(reinterpret_cast<Address>(addr));
      wasm_runtime->Trace("%c%zu:f32:%f ", kind, index, static_cast<double>(f));
    } break;
    case kF64:
      wasm_runtime->Trace(
          "%c%zu:f64:%f ", kind, index,
          base::ReadUnalignedValue<double>(reinterpret_cast<Address>(addr)));
      break;
    case kS128: {
      // This defaults to tracing all S128 values as i32x4 values for now,
      // when there is more state to know what type of values are on the
      // stack, the right format should be printed here.
      int32x4 s;
      s.val[0] =
          base::ReadUnalignedValue<uint32_t>(reinterpret_cast<Address>(addr));
      s.val[1] = base::ReadUnalignedValue<uint32_t>(
          reinterpret_cast<Address>(addr + 4));
      s.val[2] = base::ReadUnalignedValue<uint32_t>(
          reinterpret_cast<Address>(addr + 8));
      s.val[3] = base::ReadUnalignedValue<uint32_t>(
          reinterpret_cast<Address>(addr + 12));
      wasm_runtime->Trace("%c%zu:s128:%08x,%08x,%08x,%08x ", kind, index,
                          s.val[0], s.val[1], s.val[2], s.val[3]);
      break;
    }
    case kRef:
    case kRefNull:
      DCHECK_EQ(sizeof(uint64_t), sizeof(WasmRef));
      // TODO(paolosev@microsoft.com): Extract actual ref value from
      // reference_stack_.
      wasm_runtime->Trace(
          "%c%zu:ref:%" PRIx64, kind, index,
          base::ReadUnalignedValue<uint64_t>(reinterpret_cast<Address>(addr)));
      break;
    default:
      UNREACHABLE();
  }
}

#endif  // V8_ENABLE_DRUMBRAKE_TRACING

PWasmOp* kInstructionTable[kInstructionTableSize] = {
#ifndef V8_DRUMBRAKE_BOUNDS_CHECKS
// For this case, this table will be initialized in
// InitInstructionTableOnce.
#define V(_) nullptr,
    FOREACH_LOAD_STORE_INSTR_HANDLER(V)
#undef V

#else
#define V(name) name,
    FOREACH_LOAD_STORE_INSTR_HANDLER(V)
        FOREACH_LOAD_STORE_DUPLICATED_INSTR_HANDLER(V)
#undef V

#endif  // V8_DRUMBRAKE_BOUNDS_CHECKS

#define V(name) name,
        FOREACH_NO_BOUNDSCHECK_INSTR_HANDLER(V)
#ifdef V8_ENABLE_DRUMBRAKE_TRACING
            FOREACH_TRACE_INSTR_HANDLER(V)
#endif  // V8_ENABLE_DRUMBRAKE_TRACING
#undef V
};

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

const WasmEHData::TryBlock* WasmEHData::GetTryBlock(
    CodeOffset code_offset) const {
  const auto& catch_it = code_trycatch_map_.find(code_offset);
  if (catch_it == code_trycatch_map_.end()) return nullptr;
  BlockIndex try_block_index = catch_it->second;

  const auto& try_it = try_blocks_.find(try_block_index);
  DCHECK_NE(try_it, try_blocks_.end());
  const WasmEHData::TryBlock* try_block = &try_it->second;
  if (try_block->IsTryDelegate()) {
    try_block = GetDelegateTryBlock(try_block);
  }
  return try_block;
}

const WasmEHData::TryBlock* WasmEHData::GetParentTryBlock(
    const WasmEHData::TryBlock* try_block) const {
  const auto& try_it =
      try_blocks_.find(try_block->parent_or_matching_try_block);
  return try_it != try_blocks_.end() ? &try_it->second : nullptr;
}

const WasmEHData::TryBlock* WasmEHData::GetDelegateTryBlock(
    const WasmEHData::TryBlock* try_block) const {
  DCHECK_GE(try_block->delegate_try_index, 0);
  if (try_block->delegate_try_index == WasmEHData::kDelegateToCallerIndex) {
    return nullptr;
  }
  const auto& try_it = try_blocks_.find(try_block->delegate_try_index);
  DCHECK_NE(try_it, try_blocks_.end());
  return &try_it->second;
}

size_t WasmEHData::GetEndInstructionOffsetFor(
    WasmEHData::BlockIndex catch_block_index) const {
  int try_block_index = GetTryBranchOf(catch_block_index);
  DCHECK_GE(try_block_index, 0);

  const auto& it = try_blocks_.find(try_block_index);
  DCHECK_NE(it, try_blocks_.end());
  return it->second.end_instruction_code_offset;
}

WasmEHData::ExceptionPayloadSlotOffsets
WasmEHData::GetExceptionPayloadStartSlotOffsets(
    WasmEHData::BlockIndex catch_block_index) const {
  const auto& it = catch_blocks_.find(catch_block_index);
  DCHECK_NE(it, catch_blocks_.end());
  return {it->second.first_param_slot_offset,
          it->second.first_param_ref_stack_index};
}

WasmEHData::BlockIndex WasmEHData::GetTryBranchOf(
    WasmEHData::BlockIndex catch_block_index) const {
  const auto& it = catch_blocks_.find(catch_block_index);
  if (it == catch_blocks_.end()) return -1;
  return it->second.try_block_index;
}

void WasmEHDataGenerator::AddTryBlock(
    BlockIndex try_block_index, BlockIndex parent_or_matching_try_block_index,
    BlockIndex ancestor_try_block_index) {
  DCHECK_EQ(try_blocks_.find(try_block_index), try_blocks_.end());
  try_blocks_.insert(
      {try_block_index,
       TryBlock{parent_or_matching_try_block_index, ancestor_try_block_index}});
  current_try_block_index_ = try_block_index;
}

void WasmEHDataGenerator::AddCatchBlock(BlockIndex catch_block_index,
                                        int tag_index,
                                        uint32_t first_param_slot_offset,
                                        uint32_t first_param_ref_stack_index,
                                        CodeOffset code_offset) {
  DCHECK_EQ(catch_blocks_.find(catch_block_index), catch_blocks_.end());
  catch_blocks_.insert(
      {catch_block_index,
       CatchBlock{current_try_block_index_, first_param_slot_offset,
                  first_param_ref_stack_index}});

  auto it = try_blocks_.find(current_try_block_index_);
  DCHECK_NE(it, try_blocks_.end());
  it->second.catch_handlers.emplace_back(
      CatchHandler{catch_block_index, tag_index, code_offset});
}

void WasmEHDataGenerator::AddDelegatedBlock(
    BlockIndex delegate_try_block_index) {
  auto it = try_blocks_.find(current_try_block_index_);
  DCHECK_NE(it, try_blocks_.end());
  TryBlock& try_block = it->second;
  DCHECK(try_block.catch_handlers.empty());
  try_block.SetDelegated(delegate_try_block_index);
}

WasmEHData::BlockIndex WasmEHDataGenerator::EndTryCatchBlocks(
    WasmEHData::BlockIndex block_index, CodeOffset code_offset) {
  WasmEHData::BlockIndex try_block_index = GetTryBranchOf(block_index);
  if (try_block_index < 0) {
    // No catch/catch_all blocks.
    try_block_index = block_index;
  }

  const auto& try_it = try_blocks_.find(try_block_index);
  DCHECK_NE(try_it, try_blocks_.end());
  try_it->second.end_instruction_code_offset = code_offset;
  current_try_block_index_ = try_it->second.parent_or_matching_try_block;
  return try_block_index;
}

void WasmEHDataGenerator::RecordPotentialExceptionThrowingInstruction(
    WasmOpcode opcode, CodeOffset code_offset) {
  if (current_try_block_index_ < 0) {
    return;  // Not inside a try block.
  }

  BlockIndex try_block_index = current_try_block_index_;
  const auto& try_it = try_blocks_.find(current_try_block_index_);
  DCHECK_NE(try_it, try_blocks_.end());
  const TryBlock& try_block = try_it->second;

  bool inside_catch_handler = !try_block.catch_handlers.empty();
  if (inside_catch_handler) {
    // If we are throwing from inside a catch block, the exception should only
    // be caught by the catch handler of an ancestor try block.
    try_block_index = try_block.ancestor_try_index;
    if (try_block_index < 0) return;
  }

  code_trycatch_map_[code_offset] = try_block_index;
}

WasmBytecode::WasmBytecode(int func_index, const uint8_t* code_data,
                           size_t code_length, uint32_t stack_frame_size,
                           const FunctionSig* signature,
                           const InterpreterCode* interpreter_code,
                           size_t blocks_count, const uint8_t* const_slots_data,
                           size_t const_slots_length, uint32_t ref_slots_count,
                           const WasmEHData&& eh_data,
                           const std::map<CodeOffset, pc_t>&& code_pc_map)
    : code_(code_data, code_data + code_length),
      code_bytes_(code_.data()),
      signature_(signature),
      interpreter_code_(interpreter_code),
      const_slots_values_(const_slots_data,
                          const_slots_data + const_slots_length),
      func_index_(func_index),
      blocks_count_(static_cast<uint32_t>(blocks_count)),
      args_count_(static_cast<uint32_t>(signature_->parameter_count())),
      args_slots_size_(ArgsSizeInSlots(signature_)),
      return_count_(static_cast<uint32_t>(signature_->return_count())),
      rets_slots_size_(RetsSizeInSlots(signature_)),
      locals_count_(
          static_cast<uint32_t>(interpreter_code_->locals.num_locals)),
      locals_slots_size_(LocalsSizeInSlots(interpreter_code_)),
      total_frame_size_in_bytes_(stack_frame_size * kSlotSize +
                                 args_slots_size_ * kSlotSize +
                                 rets_slots_size_ * kSlotSize),
      ref_args_count_(RefArgsCount(signature_)),
      ref_rets_count_(RefRetsCount(signature_)),
      ref_locals_count_(RefLocalsCount(interpreter_code)),
      ref_slots_count_(ref_slots_count),
      eh_data_(eh_data),
      code_pc_map_(code_pc_map) {}

pc_t WasmBytecode::GetPcFromTrapCode(const uint8_t* current_code) const {
  DCHECK_GE(current_code, code_bytes_);
  size_t code_offset = current_code - code_bytes_;

  auto it = code_pc_map_.lower_bound(code_offset);
  if (it == code_pc_map_.begin()) return 0;
  it--;

  return it->second;
}

WasmBytecodeGenerator::WasmBytecodeGenerator(uint32_t function_index,
                                             InterpreterCode* wasm_code,
                                             const WasmModule* module)
    : const_slot_offset_(0),
      slot_offset_(0),
      ref_slots_count_(0),
      function_index_(function_index),
      wasm_code_(wasm_code),
      args_count_(0),
      args_slots_size_(0),
      return_count_(0),
      rets_slots_size_(0),
      locals_count_(0),
      current_block_index_(-1),
      is_instruction_reachable_(true),
      unreachable_block_count_(0),
#ifdef DEBUG
      was_current_instruction_reachable_(true),
#endif  // DEBUG
      module_(module),
      last_instr_offset_(kInvalidCodeOffset) {
  DCHECK(v8_flags.wasm_jitless);

  size_t wasm_code_size = wasm_code_->end - wasm_code_->start;
  code_.reserve(wasm_code_size * 6);
  slots_.reserve(wasm_code_size / 2);
  stack_.reserve(wasm_code_size / 4);
  blocks_.reserve(wasm_code_size / 8);

  const FunctionSig* sig = module_->functions[function_index].sig;
  args_count_ = static_cast<uint32_t>(sig->parameter_count());
  args_slots_size_ = WasmBytecode::ArgsSizeInSlots(sig);
  return_count_ = static_cast<uint32_t>(sig->return_count());
  rets_slots_size_ = WasmBytecode::RetsSizeInSlots(sig);
  locals_count_ = static_cast<uint32_t>(wasm_code->locals.num_locals);
}

size_t WasmBytecodeGenerator::Simd128Hash::operator()(
    const Simd128& s128) const {
  static_assert(sizeof(size_t) == sizeof(uint64_t));
  const int64x2 s = s128.to_i64x2();
  return s.val[0] ^ s.val[1];
}

// Look if the slot that hold the value at {stack_index} is being shared with
// other slots. This can happen if there are multiple load.get operations that
// copy from the same local.
bool WasmBytecodeGenerator::HasSharedSlot(uint32_t stack_index) const {
  // Only consider stack entries added in the current block.
  // We don't need to consider ancestor blocks because if a block has a
  // non-empty signature we always pass arguments and results into separate
  // slots, emitting CopySlot operations.
  uint32_t start_slot_index = blocks_[current_block_index_].stack_size_;

  for (uint32_t i = start_slot_index; i < stack_.size(); i++) {
    if (stack_[i] == stack_[stack_index]) {
      return true;
    }
  }
  return false;
}

// Look if the slot that hold the value at {stack_index} is being shared with
// other slots. This can happen if there are multiple load.get operations that
// copy from the same local. In this case when we modify the value of the slot
// with a local.set or local.tee we need to first duplicate the slot to make
// sure that the old value is preserved in the other shared slots.
bool WasmBytecodeGenerator::FindSharedSlot(uint32_t stack_index,
                                           uint32_t* new_slot_index) {
  *new_slot_index = UINT_MAX;
  ValueType value_type = slots_[stack_[stack_index]].value_type;
  if (value_type.is_reference()) return false;

  // Only consider stack entries added in the current block.
  // We don't need to consider ancestor blocks because if a block has a
  // non-empty signature we always pass arguments and results into separate
  // slots, emitting CopySlot operations.
  uint32_t start_slot_index = blocks_[current_block_index_].stack_size_;

  for (uint32_t i = start_slot_index; i < stack_.size(); i++) {
    if (stack_[i] == stack_[stack_index]) {
      // Allocate new slot to preserve the old value of a shared slot.
      *new_slot_index = CreateSlot(value_type);
      break;
    }
  }

  if (*new_slot_index == UINT_MAX) return false;

  // If there was a collision and we allocated a new slot to preserve the old
  // value, we need to do two things to keep the state up to date:
  // 1. For each shared slot, we update the stack value to refer to the new
  // slot. This track the change at bytecode generation time.
  // 2. We return {true} to indicate that the slot was shared and the caller
  // should emit a 's2s_PreserveCopySlot...' instruction to copy the old slot
  // value into the new slot, at runtime.

  // This loop works because stack_index is always greater or equal to the index
  // of args/globals.
  DCHECK_GT(start_slot_index, stack_index);
  for (uint32_t i = start_slot_index; i < stack_.size(); i++) {
    if (stack_[i] == stack_[stack_index]) {
      // Copy value into the new slot.
      UpdateStack(i, *new_slot_index);
#ifdef V8_ENABLE_DRUMBRAKE_TRACING
      if (v8_flags.trace_drumbrake_execution &&
          v8_flags.trace_drumbrake_execution_verbose) {
        EMIT_INSTR_HANDLER(trace_UpdateStack);
        EmitI32Const(i);
        EmitI32Const(slots_[*new_slot_index].slot_offset * kSlotSize);
        printf("Preserve UpdateStack: [%d] = %d\n", i,
               slots_[*new_slot_index].slot_offset);
      }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING
    }
  }

  return true;
}

void WasmBytecodeGenerator::EmitCopySlot(ValueType value_type,
                                         uint32_t from_slot_index,
                                         uint32_t to_slot_index,
                                         bool copy_from_reg) {
  const ValueKind kind = value_type.kind();
  switch (kind) {
    case kI32:
      if (copy_from_reg) {
        EMIT_INSTR_HANDLER(r2s_CopyR0ToSlot32);
      } else {
        EMIT_INSTR_HANDLER(s2s_CopySlot32);
      }
      break;
    case kI64:
      if (copy_from_reg) {
        EMIT_INSTR_HANDLER(r2s_CopyR0ToSlot64);
      } else {
        EMIT_INSTR_HANDLER(s2s_CopySlot64);
      }
      break;
    case kF32:
      if (copy_from_reg) {
        EMIT_INSTR_HANDLER(r2s_CopyFp0ToSlot32);
      } else {
        EMIT_INSTR_HANDLER(s2s_CopySlot32);
      }
      break;
    case kF64:
      if (copy_from_reg) {
        EMIT_INSTR_HANDLER(r2s_CopyFp0ToSlot64);
      } else {
        EMIT_INSTR_HANDLER(s2s_CopySlot64);
      }
      break;
    case kS128:
      DCHECK(!copy_from_reg);
      EMIT_INSTR_HANDLER(s2s_CopySlot128);
      break;
    case kRef:
    case kRefNull:
      DCHECK(!copy_from_reg);
      EMIT_INSTR_HANDLER(s2s_CopySlotRef);
      break;
    default:
      UNREACHABLE();
  }

  if (kind == kRefNull || kind == kRef) {
    DCHECK(!copy_from_reg);
    EmitI32Const(slots_[from_slot_index].ref_stack_index);
    EmitI32Const(slots_[to_slot_index].ref_stack_index);
  } else {
    if (!copy_from_reg) {
      EmitI32Const(slots_[from_slot_index].slot_offset);
    }
    EmitI32Const(slots_[to_slot_index].slot_offset);
  }

#ifdef V8_ENABLE_DRUMBRAKE_TRACING
  if (v8_flags.trace_drumbrake_bytecode_generator &&
      v8_flags.trace_drumbrake_execution_verbose) {
    printf("emit CopySlot: %d(%d) -> %d(%d)\n", from_slot_index,
           slots_[from_slot_index].slot_offset, to_slot_index,
           slots_[to_slot_index].slot_offset);
  }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING
}

// When a Wasm function starts the values for the function args and locals are
// already present in the Wasm stack. The stack entries for args and locals
// can be directly accessed with {local.get} and modified with {local.set} and
// {local.tee}, but they can never be popped, they are always present until
// the function returns.
// During the execution of the function other values are then pushed/popped
// into/from the stack, but these other entries are only accessible indirectly
// as operands/results of operations, not directly with local.get/set
// instructions.
//
// DrumBrake implements a "args/locals propagation" optimization that allows the
// stack slots for "local" stack entries to be shared with other stack entries
// (using the {stack_} and {slots_} arrays), in order to avoid emitting calls to
// 'local.get' instruction handlers.

// When an arg/local value is modified, and its slot is shared with other
// entries in the stack, we need to preserve the old value of the stack entry in
// a new slot.
void WasmBytecodeGenerator::CopyToSlot(ValueType value_type,
                                       uint32_t from_slot_index,
                                       uint32_t to_stack_index,
                                       bool copy_from_reg) {
  const ValueKind kind = value_type.kind();
  uint32_t to_slot_index = stack_[to_stack_index];
  DCHECK(copy_from_reg || CheckEqualKind(kind, slots_[from_slot_index].kind()));
  DCHECK(CheckEqualKind(slots_[to_slot_index].kind(), kind));

  uint32_t new_slot_index;
  // If the slot is shared {FindSharedSlot} creates a new slot and makes all the
  // 'non-locals' stack entries that shared the old slot point to this new slot.
  // We need to emit a {PreserveCopySlot} instruction to dynamically copy the
  // old value into the new slot.
  if (FindSharedSlot(to_stack_index, &new_slot_index)) {
    switch (kind) {
      case kI32:
        if (copy_from_reg) {
          EMIT_INSTR_HANDLER(r2s_PreserveCopyR0ToSlot32);
        } else {
          EMIT_INSTR_HANDLER(s2s_PreserveCopySlot32);
        }
        break;
      case kI64:
        if (copy_from_reg) {
          EMIT_INSTR_HANDLER(r2s_PreserveCopyR0ToSlot64);
        } else {
          EMIT_INSTR_HANDLER(s2s_PreserveCopySlot64);
        }
        break;
      case kF32:
        if (copy_from_reg) {
          EMIT_INSTR_HANDLER(r2s_PreserveCopyFp0ToSlot32);
        } else {
          EMIT_INSTR_HANDLER(s2s_PreserveCopySlot32);
        }
        break;
      case kF64:
        if (copy_from_reg) {
          EMIT_INSTR_HANDLER(r2s_PreserveCopyFp0ToSlot64);
        } else {
          EMIT_INSTR_HANDLER(s2s_PreserveCopySlot64);
        }
        break;
      case kS128:
        DCHECK(!copy_from_reg);
        EMIT_INSTR_HANDLER(s2s_PreserveCopySlot128);
        break;
      case kRef:
      case kRefNull:
        DCHECK(!copy_from_reg);
        EMIT_INSTR_HANDLER(s2s_PreserveCopySlotRef);
        break;
      default:
        UNREACHABLE();
    }

    if (kind == kRefNull || kind == kRef) {
      DCHECK(!copy_from_reg);
      EmitI32Const(slots_[from_slot_index].ref_stack_index);
      EmitI32Const(slots_[to_slot_index].ref_stack_index);
      EmitI32Const(slots_[new_slot_index].ref_stack_index);
    } else {
      if (!copy_from_reg) {
        EmitI32Const(slots_[from_slot_index].slot_offset);
      }
      EmitI32Const(slots_[to_slot_index].slot_offset);
      EmitI32Const(slots_[new_slot_index].slot_offset);
    }

#ifdef V8_ENABLE_DRUMBRAKE_TRACING
    if (v8_flags.trace_drumbrake_execution &&
        v8_flags.trace_drumbrake_execution_verbose) {
      printf("emit s2s_PreserveCopySlot: %d %d %d\n",
             slots_[from_slot_index].slot_offset,
             slots_[to_slot_index].slot_offset,
             slots_[new_slot_index].slot_offset);
    }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING
  } else {
    EmitCopySlot(value_type, from_slot_index, to_slot_index, copy_from_reg);
  }
}

// Used for 'local.tee' and 'local.set' instructions.
void WasmBytecodeGenerator::CopyToSlotAndPop(ValueType value_type,
                                             uint32_t to_stack_index,
                                             bool is_tee, bool copy_from_reg) {
  DCHECK(!stack_.empty());
  DCHECK_LT(to_stack_index, stack_.size() - (copy_from_reg ? 0 : 1));

  // LocalGet uses a "copy-on-write" mechanism: the arg/local value is not
  // copied and instead the stack entry references the same slot. When the
  // arg/local value is modified, we need to preserve the old value of the stack
  // entry in a new slot.
  CopyToSlot(value_type, stack_.back(), to_stack_index, copy_from_reg);

  if (!is_tee && !copy_from_reg) {
    PopSlot();

#ifdef V8_ENABLE_DRUMBRAKE_TRACING
    if (v8_flags.trace_drumbrake_execution) {
      EMIT_INSTR_HANDLER(trace_PopSlot);
    }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING
  }
}

// This function is called when we enter a new 'block', 'loop' or 'if' block
// statement. Checks whether any of the 'non-locals' stack entries share a slot
// with an arg/local stack entry. In that case stop make sure the local stack
// entry will get its own slot. This is necessary because at runtime we could
// jump at the block after having modified the local value in some other code
// path.
// TODO(paolosev@microsoft.com) - Understand why this is not required only for
// 'loop' blocks.
void WasmBytecodeGenerator::PreserveArgsAndLocals() {
  uint32_t num_args_and_locals = args_count_ + locals_count_;

  // If there are only args/locals entries in the stack, nothing to do.
  if (num_args_and_locals >= stack_size()) return;

  for (uint32_t local_index = 0; local_index < num_args_and_locals;
       ++local_index) {
    uint32_t new_slot_index;
    if (FindSharedSlot(local_index, &new_slot_index)) {
      ValueType value_type = slots_[stack_[local_index]].value_type;
      EmitCopySlot(value_type, stack_[local_index], new_slot_index);
    }
  }
}

uint32_t WasmBytecodeGenerator::ReserveBlockSlots(
    uint8_t opcode, const WasmInstruction::Optional::Block& block_data,
    size_t* rets_slots_count, size_t* params_slots_count) {
  uint32_t first_slot_index = 0;
  *rets_slots_count = 0;
  *params_slots_count = 0;
  bool first_slot_found = false;
  const ValueType value_type = block_data.value_type();
  if (value_type == kWasmBottom) {
    const FunctionSig* sig = module_->signature(block_data.sig_index);
    *rets_slots_count = sig->return_count();
    for (uint32_t i = 0; i < *rets_slots_count; i++) {
      uint32_t slot_index = CreateSlot(sig->GetReturn(i));
      if (!first_slot_found) {
        first_slot_index = slot_index;
        first_slot_found = true;
      }
    }
    *params_slots_count = sig->parameter_count();
    for (uint32_t i = 0; i < *params_slots_count; i++) {
      uint32_t slot_index = CreateSlot(sig->GetParam(i));
      if (!first_slot_found) {
        first_slot_index = slot_index;
        first_slot_found = true;
      }
    }
  } else if (value_type != kWasmVoid) {
    *rets_slots_count = 1;
    first_slot_index = CreateSlot(value_type);
  }
  return first_slot_index;
}

void WasmBytecodeGenerator::StoreBlockParamsIntoSlots(
    uint32_t target_block_index, bool update_stack) {
  const WasmBytecodeGenerator::BlockData& target_block_data =
      blocks_[target_block_index];
  DCHECK_EQ(target_block_data.opcode_, kExprLoop);

  uint32_t params_count = ParamsCount(target_block_data);
  uint32_t rets_count = ReturnsCount(target_block_data);
  uint32_t first_param_slot_index =
      target_block_data.first_block_index_ + rets_count;
  for (uint32_t i = 0; i < params_count; i++) {
    uint32_t from_slot_index =
        stack_[stack_top_index() - (params_count - 1) + i];
    uint32_t to_slot_index = first_param_slot_index + i;
    if (from_slot_index != to_slot_index) {
      EmitCopySlot(GetParamType(target_block_data, i), from_slot_index,
                   to_slot_index);
      if (update_stack) {
        DCHECK_EQ(GetParamType(target_block_data, i),
                  slots_[first_param_slot_index + i].value_type);
        UpdateStack(stack_top_index() - (params_count - 1) + i,
                    first_param_slot_index + i);

#ifdef V8_ENABLE_DRUMBRAKE_TRACING
        if (v8_flags.trace_drumbrake_execution) {
          EMIT_INSTR_HANDLER(trace_UpdateStack);
          EmitI32Const(stack_top_index() - (params_count - 1) + i);
          EmitI32Const(slots_[first_param_slot_index + i].slot_offset *
                       kSlotSize);
        }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING
      }
    }
  }
}

void WasmBytecodeGenerator::StoreBlockParamsAndResultsIntoSlots(
    uint32_t target_block_index, WasmOpcode opcode) {
  bool is_branch = kExprBr == opcode || kExprBrIf == opcode ||
                   kExprBrTable == opcode || kExprBrOnNull == opcode ||
                   kExprBrOnNonNull == opcode || kExprBrOnCast == opcode;
  const WasmBytecodeGenerator::BlockData& target_block_data =
      blocks_[target_block_index];
  bool is_target_loop_block = target_block_data.opcode_ == kExprLoop;
  if (is_target_loop_block && is_branch) {
    StoreBlockParamsIntoSlots(target_block_index, false);
  }

  // Ignore params if this is the function main block.
  uint32_t params_count =
      target_block_index == 0 ? 0 : ParamsCount(target_block_data);
  uint32_t rets_count = ReturnsCount(target_block_data);

  // There could be valid code where there are not enough elements in the
  // stack if some code in unreachable (for example if a 'i32.const 0' is
  // followed by a 'br_if' the if branch is never reachable).
  uint32_t count = std::min(static_cast<uint32_t>(stack_.size()), rets_count);
  for (uint32_t i = 0; i < count; i++) {
    uint32_t from_slot_index = stack_[stack_top_index() - (count - 1) + i];
    uint32_t to_slot_index = target_block_data.first_block_index_ + i;
    if (from_slot_index != to_slot_index) {
      EmitCopySlot(GetReturnType(target_block_data, i), from_slot_index,
                   to_slot_index);
    }
  }

  bool is_else = (kExprElse == opcode);
  bool is_return = (kExprReturn == opcode);
  bool is_catch = (kExprCatch == opcode || kExprCatchAll == opcode);
  if (!is_branch && !is_return && !is_else && !is_catch) {
    uint32_t new_stack_height =
        target_block_data.stack_size_ - params_count + rets_count;
    DCHECK(new_stack_height <= stack_.size() ||
           !was_current_instruction_reachable_);
    stack_.resize(new_stack_height);

    for (uint32_t i = 0; i < rets_count; i++) {
      DCHECK_EQ(GetReturnType(target_block_data, i),
                slots_[target_block_data.first_block_index_ + i].value_type);
      UpdateStack(target_block_data.stack_size_ - params_count + i,
                  target_block_data.first_block_index_ + i);

#ifdef V8_ENABLE_DRUMBRAKE_TRACING
      if (v8_flags.trace_drumbrake_execution) {
        EMIT_INSTR_HANDLER(trace_UpdateStack);
        EmitI32Const(target_block_data.stack_size_ - params_count + i);
        EmitI32Const(
            slots_[target_block_data.first_block_index_ + i].slot_offset *
            kSlotSize);
      }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING
    }
  }
}

void WasmBytecodeGenerator::RestoreIfElseParams(uint32_t if_block_index) {
  const WasmBytecodeGenerator::BlockData& if_block_data =
      blocks_[if_block_index];
  DCHECK_EQ(if_block_data.opcode_, kExprIf);

  stack_.resize(blocks_[if_block_index].stack_size_);
  uint32_t params_count = if_block_index == 0 ? 0 : ParamsCount(if_block_data);
  for (uint32_t i = 0; i < params_count; i++) {
    UpdateStack(if_block_data.stack_size_ - params_count + i,
                if_block_data.GetParam(i), GetParamType(if_block_data, i));
#ifdef V8_ENABLE_DRUMBRAKE_TRACING
    if (v8_flags.trace_drumbrake_execution) {
      EMIT_INSTR_HANDLER(trace_UpdateStack);
      EmitI32Const(if_block_data.stack_size_ - params_count + i);
      EmitI32Const(slots_[if_block_data.GetParam(i)].slot_offset * kSlotSize);
    }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING
  }
}

uint32_t WasmBytecodeGenerator::ScanConstInstructions() const {
  Decoder decoder(wasm_code_->start, wasm_code_->end);
  uint32_t const_slots_size = 0;
  pc_t pc = wasm_code_->locals.encoded_size;
  pc_t limit = wasm_code_->end - wasm_code_->start;
  while (pc < limit) {
    uint32_t opcode = wasm_code_->start[pc];
    if (opcode == kExprI32Const || opcode == kExprF32Const) {
      const_slots_size += sizeof(uint32_t) / kSlotSize;
    } else if (opcode == kExprI64Const || opcode == kExprF64Const) {
      const_slots_size += sizeof(uint64_t) / kSlotSize;
    } else if (opcode == kSimdPrefix) {
      auto [opcode_index, opcode_len] =
          decoder.read_u32v<Decoder::FullValidationTag>(
              wasm_code_->start + pc + 1, "prefixed opcode index");
      opcode = (kSimdPrefix << 8) | opcode_index;
      if (opcode == kExprS128Const || opcode == kExprI8x16Shuffle) {
        const_slots_size += sizeof(Simd128) / kSlotSize;
      }
    }
    pc++;
  }
  return const_slots_size;
}

int32_t WasmBytecodeGenerator::EndBlock(WasmOpcode opcode) {
  WasmBytecodeGenerator::BlockData& block_data = blocks_[current_block_index_];
  bool is_try_catch =
      block_data.IsTry() || block_data.IsCatch() || block_data.IsCatchAll();

  StoreBlockParamsAndResultsIntoSlots(current_block_index_, opcode);

  if (block_data.IsLoop()) {
    loop_end_code_offsets_.push_back(static_cast<uint32_t>(code_.size()));
    EMIT_INSTR_HANDLER(s2s_OnLoopBackwardJump);
  }

  block_data.end_code_offset_ = CurrentCodePos();
  if (opcode == kExprEnd && block_data.IsElse()) {
    DCHECK_GT(block_data.if_else_block_index_, 0);
    blocks_[block_data.if_else_block_index_].end_code_offset_ =
        CurrentCodePos();
  }

  if (!is_try_catch) {
    current_block_index_ = blocks_[current_block_index_].parent_block_index_;
  }

  if (is_try_catch && (opcode == kExprEnd || opcode == kExprDelegate)) {
    int32_t try_block_index =
        eh_data_.EndTryCatchBlocks(current_block_index_, CurrentCodePos());
    DCHECK_GE(try_block_index, 0);
    current_block_index_ = blocks_[try_block_index].parent_block_index_;
  }

  last_instr_offset_ = kInvalidCodeOffset;

  return current_block_index_;
}

void WasmBytecodeGenerator::Return() {
  if (current_block_index_ >= 0) {
    StoreBlockParamsAndResultsIntoSlots(0, kExprReturn);
  }

  EMIT_INSTR_HANDLER(s2s_Return);

  const WasmBytecodeGenerator::BlockData& target_block_data = blocks_[0];
  uint32_t final_stack_size =
      target_block_data.stack_size_ + ReturnsCount(target_block_data);
  EmitI32Const(final_stack_size);
}

WasmInstruction WasmBytecodeGenerator::DecodeInstruction(pc_t pc,
                                                         Decoder& decoder) {
  pc_t limit = wasm_code_->end - wasm_code_->start;
  if (pc >= limit) return WasmInstruction();

  int len = 1;
  uint8_t orig = wasm_code_->start[pc];
  WasmOpcode opcode = static_cast<WasmOpcode>(orig);
  if (WasmOpcodes::IsPrefixOpcode(opcode)) {
    uint32_t prefixed_opcode_length;
    std::tie(opcode, prefixed_opcode_length) =
        decoder.read_prefixed_opcode<Decoder::NoValidationTag>(
            wasm_code_->at(pc));
    // skip breakpoint by switching on original code.
    len = prefixed_opcode_length;
  }

  WasmInstruction::Optional optional;
  switch (orig) {
    case kExprUnreachable:
      break;
    case kExprNop:
      break;
    case kExprBlock:
    case kExprLoop:
    case kExprIf:
    case kExprTry: {
      BlockTypeImmediate imm(WasmEnabledFeatures::All(), &decoder,
                             wasm_code_->at(pc + 1), Decoder::kNoValidation);
      if (imm.sig_index.valid()) {
        // The block has at least one argument or at least two results, its
        // signature is identified by sig_index.
        optional.block.sig_index = imm.sig_index;
        optional.block.value_type_bitfield = kWasmBottom.raw_bit_field();
      } else if (imm.sig.return_count() + imm.sig.parameter_count() == 0) {
        // Void signature: no arguments and no results.
        optional.block.sig_index = ModuleTypeIndex::Invalid();
        optional.block.value_type_bitfield = kWasmVoid.raw_bit_field();
      } else {
        // No arguments and one result.
        optional.block.sig_index = ModuleTypeIndex::Invalid();
        std::optional<wasm::ValueType> wasm_return_type =
            GetWasmReturnTypeFromSignature(&imm.sig);
        DCHECK(wasm_return_type.has_value());
        optional.block.value_type_bitfield =
            wasm_return_type.value().raw_bit_field();
      }
      len = 1 + imm.length;
      break;
    }
    case kExprElse:
      break;
    case kExprCatch: {
      TagIndexImmediate imm(&decoder, wasm_code_->at(pc + 1),
                            Decoder::kNoValidation);
      optional.index = imm.index;
      len = 1 + imm.length;
      break;
    }
    case kExprCatchAll:
      break;
    case kExprEnd:
      break;
    case kExprThrow: {
      TagIndexImmediate imm(&decoder, wasm_code_->at(pc + 1),
                            Decoder::kNoValidation);
      len = 1 + imm.length;
      optional.index = imm.index;
      break;
    }
    case kExprRethrow:
    case kExprBr:
    case kExprBrIf:
    case kExprBrOnNull:
    case kExprBrOnNonNull:
    case kExprDelegate: {
      BranchDepthImmediate imm(&decoder, wasm_code_->at(pc + 1),
                               Decoder::kNoValidation);
      len = 1 + imm.length;
      optional.depth = imm.depth;
      break;
    }
    case kExprBrTable: {
      BranchTableImmediate imm(&decoder, wasm_code_->at(pc + 1),
                               Decoder::kNoValidation);
      BranchTableIterator<Decoder::NoValidationTag> iterator(&decoder, imm);
      optional.br_table.table_count = imm.table_count;
      optional.br_table.labels_index =
          static_cast<uint32_t>(br_table_labels_.size());
      for (uint32_t i = 0; i <= imm.table_count; i++) {
        DCHECK(iterator.has_next());
        br_table_labels_.emplace_back(iterator.next());
      }
      len = static_cast<int>(1 + iterator.pc() - imm.start);
      break;
    }
    case kExprReturn:
      break;
    case kExprCallFunction:
    case kExprReturnCall: {
      CallFunctionImmediate imm(&decoder, wasm_code_->at(pc + 1),
                                Decoder::kNoValidation);
      len = 1 + imm.length;
      optional.index = imm.index;
      break;
    }
    case kExprCallIndirect:
    case kExprReturnCallIndirect: {
      CallIndirectImmediate imm(&decoder, wasm_code_->at(pc + 1),
                                Decoder::kNoValidation);
      len = 1 + imm.length;
      optional.indirect_call.table_index = imm.table_imm.index;
      optional.indirect_call.sig_index = imm.sig_imm.index;
      break;
    }
    case kExprDrop:
      break;
    case kExprSelect:
      break;
    case kExprSelectWithType: {
      SelectTypeImmediate imm(WasmEnabledFeatures::All(), &decoder,
                              wasm_code_->at(pc + 1), Decoder::kNoValidation);
      len = 1 + imm.length;
      break;
    }
    case kExprLocalGet: {
      IndexImmediate imm(&decoder, wasm_code_->at(pc + 1), "local index",
                         Decoder::kNoValidation);
      len = 1 + imm.length;
      optional.index = imm.index;
      break;
    }
    case kExprLocalSet: {
      IndexImmediate imm(&decoder, wasm_code_->at(pc + 1), "local index",
                         Decoder::kNoValidation);
      len = 1 + imm.length;
      optional.index = imm.index;
      break;
    }
    case kExprLocalTee: {
      IndexImmediate imm(&decoder, wasm_code_->at(pc + 1), "local index",
                         Decoder::kNoValidation);
      len = 1 + imm.length;
      optional.index = imm.index;
      break;
    }
    case kExprGlobalGet: {
      GlobalIndexImmediate imm(&decoder, wasm_code_->at(pc + 1),
                               Decoder::kNoValidation);
      len = 1 + imm.length;
      optional.index = imm.index;
      break;
    }
    case kExprGlobalSet: {
      GlobalIndexImmediate imm(&decoder, wasm_code_->at(pc + 1),
                               Decoder::kNoValidation);
      len = 1 + imm.length;
      optional.index = imm.index;
      break;
    }
    case kExprTableGet: {
      IndexImmediate imm(&decoder, wasm_code_->at(pc + 1), "table index",
                         Decoder::kNoValidation);
      len = 1 + imm.length;
      optional.index = imm.index;
      break;
    }
    case kExprTableSet: {
      IndexImmediate imm(&decoder, wasm_code_->at(pc + 1), "table index",
                         Decoder::kNoValidation);
      len = 1 + imm.length;
      optional.index = imm.index;
      break;
    }

#define LOAD_CASE(name, ctype, mtype, rep, type)                        \
  case kExpr##name: {                                                   \
    MemoryAccessImmediate imm(                                          \
        &decoder, wasm_code_->at(pc + 1), sizeof(ctype),                \
        !module_->memories.empty() && module_->memories[0].is_memory64, \
        Decoder::kNoValidation);                                        \
    len = 1 + imm.length;                                               \
    optional.offset = imm.offset;                                       \
    break;                                                              \
  }
      LOAD_CASE(I32LoadMem8S, int32_t, int8_t, kWord8, I32);
      LOAD_CASE(I32LoadMem8U, int32_t, uint8_t, kWord8, I32);
      LOAD_CASE(I32LoadMem16S, int32_t, int16_t, kWord16, I32);
      LOAD_CASE(I32LoadMem16U, int32_t, uint16_t, kWord16, I32);
      LOAD_CASE(I64LoadMem8S, int64_t, int8_t, kWord8, I64);
      LOAD_CASE(I64LoadMem8U, int64_t, uint8_t, kWord16, I64);
      LOAD_CASE(I64LoadMem16S, int64_t, int16_t, kWord16, I64);
      LOAD_CASE(I64LoadMem16U, int64_t, uint16_t, kWord16, I64);
      LOAD_CASE(I64LoadMem32S, int64_t, int32_t, kWord32, I64);
      LOAD_CASE(I64LoadMem32U, int64_t, uint32_t, kWord32, I64);
      LOAD_CASE(I32LoadMem, int32_t, int32_t, kWord32, I32);
      LOAD_CASE(I64LoadMem, int64_t, int64_t, kWord64, I64);
      LOAD_CASE(F32LoadMem, Float32, uint32_t, kFloat32, F32);
      LOAD_CASE(F64LoadMem, Float64, uint64_t, kFloat64, F64);
#undef LOAD_CASE

#define STORE_CASE(name, ctype, mtype, rep, type)                       \
  case kExpr##name: {                                                   \
    MemoryAccessImmediate imm(                                          \
        &decoder, wasm_code_->at(pc + 1), sizeof(ctype),                \
        !module_->memories.empty() && module_->memories[0].is_memory64, \
        Decoder::kNoValidation);                                        \
    len = 1 + imm.length;                                               \
    optional.offset = imm.offset;                                       \
    break;                                                              \
  }
      STORE_CASE(I32StoreMem8, int32_t, int8_t, kWord8, I32);
      STORE_CASE(I32StoreMem16, int32_t, int16_t, kWord16, I32);
      STORE_CASE(I64StoreMem8, int64_t, int8_t, kWord8, I64);
      STORE_CASE(I64StoreMem16, int64_t, int16_t, kWord16, I64);
      STORE_CASE(I64StoreMem32, int64_t, int32_t, kWord32, I64);
      STORE_CASE(I32StoreMem, int32_t, int32_t, kWord32, I32);
      STORE_CASE(I64StoreMem, int64_t, int64_t, kWord64, I64);
      STORE_CASE(F32StoreMem, Float32, uint32_t, kFloat32, F32);
      STORE_CASE(F64StoreMem, Float64, uint64_t, kFloat64, F64);
#undef STORE_CASE

    case kExprMemorySize: {
      MemoryIndexImmediate imm(&decoder, wasm_code_->at(pc + 1),
                               Decoder::kNoValidation);
      len = 1 + imm.length;
      break;
    }
    case kExprMemoryGrow: {
      MemoryIndexImmediate imm(&decoder, wasm_code_->at(pc + 1),
                               Decoder::kNoValidation);
      len = 1 + imm.length;
      break;
    }
    case kExprI32Const: {
      ImmI32Immediate imm(&decoder, wasm_code_->at(pc + 1),
                          Decoder::kNoValidation);
      len = 1 + imm.length;
      optional.i32 = imm.value;
      break;
    }
    case kExprI64Const: {
      ImmI64Immediate imm(&decoder, wasm_code_->at(pc + 1),
                          Decoder::kNoValidation);
      len = 1 + imm.length;
      optional.i64 = imm.value;
      break;
    }
    case kExprF32Const: {
      ImmF32Immediate imm(&decoder, wasm_code_->at(pc + 1),
                          Decoder::kNoValidation);
      len = 1 + imm.length;
      optional.f32 = imm.value;
      break;
    }
    case kExprF64Const: {
      ImmF64Immediate imm(&decoder, wasm_code_->at(pc + 1),
                          Decoder::kNoValidation);
      len = 1 + imm.length;
      optional.f64 = imm.value;
      break;
    }

#define EXECUTE_BINOP(name, ctype, reg, op, type) \
  case kExpr##name:                               \
    break;

      FOREACH_COMPARISON_BINOP(EXECUTE_BINOP)
      FOREACH_ARITHMETIC_BINOP(EXECUTE_BINOP)
      FOREACH_TRAPPING_BINOP(EXECUTE_BINOP)
      FOREACH_MORE_BINOP(EXECUTE_BINOP)
#undef EXECUTE_BINOP

#define EXECUTE_UNOP(name, ctype, reg, op, type) \
  case kExpr##name:                              \
    break;

      FOREACH_SIMPLE_UNOP(EXECUTE_UNOP)
#undef EXECUTE_UNOP

#define EXECUTE_UNOP(name, from_ctype, from_type, from_reg, to_ctype, to_type, \
                     to_reg)                                                   \
  case kExpr##name:                                                            \
    break;

      FOREACH_ADDITIONAL_CONVERT_UNOP(EXECUTE_UNOP)
      FOREACH_CONVERT_UNOP(EXECUTE_UNOP)
      FOREACH_REINTERPRET_UNOP(EXECUTE_UNOP)
#undef EXECUTE_UNOP

#define EXECUTE_UNOP(name, from_ctype, from_type, to_ctype, to_type, op) \
  case kExpr##name:                                                      \
    break;

      FOREACH_BITS_UNOP(EXECUTE_UNOP)
#undef EXECUTE_UNOP

#define EXECUTE_UNOP(name, from_ctype, from_type, to_ctype, to_type) \
  case kExpr##name:                                                  \
    break;

      FOREACH_EXTENSION_UNOP(EXECUTE_UNOP)
#undef EXECUTE_UNOP

    case kExprRefNull: {
      HeapTypeImmediate imm(WasmEnabledFeatures::All(), &decoder,
                            wasm_code_->at(pc + 1), Decoder::kNoValidation);
      optional.ref_type = imm.type.representation();
      len = 1 + imm.length;
      break;
    }
    case kExprRefIsNull:
    case kExprRefEq:
    case kExprRefAsNonNull: {
      len = 1;
      break;
    }
    case kExprRefFunc: {
      IndexImmediate imm(&decoder, wasm_code_->at(pc + 1), "function index",
                         Decoder::kNoValidation);
      optional.index = imm.index;
      len = 1 + imm.length;
      break;
    }

    case kGCPrefix:
      DecodeGCOp(opcode, &optional, &decoder, wasm_code_, pc, &len);
      break;

    case kNumericPrefix:
      DecodeNumericOp(opcode, &optional, &decoder, wasm_code_, pc, &len);
      break;

    case kAtomicPrefix:
      DecodeAtomicOp(opcode, &optional, &decoder, wasm_code_, pc, &len);
      break;

    case kSimdPrefix: {
      bool is_valid_simd_op =
          DecodeSimdOp(opcode, &optional, &decoder, wasm_code_, pc, &len);
      if (V8_UNLIKELY(!is_valid_simd_op)) {
        UNREACHABLE();
      }
      break;
    }

    case kExprCallRef:
    case kExprReturnCallRef: {
      SigIndexImmediate imm(&decoder, wasm_code_->at(pc + 1),
                            Decoder::kNoValidation);
      optional.index = imm.index;
      len = 1 + imm.length;
      break;
    }

    default:
      // Not implemented yet
      UNREACHABLE();
  }

  return WasmInstruction{orig, opcode, len, static_cast<uint32_t>(pc),
                         optional};
}

void WasmBytecodeGenerator::DecodeGCOp(WasmOpcode opcode,
                                       WasmInstruction::Optional* optional,
                                       Decoder* decoder, InterpreterCode* code,
                                       pc_t pc, int* const len) {
  switch (opcode) {
    case kExprStructNew:
    case kExprStructNewDefault: {
      StructIndexImmediate imm(decoder, code->at(pc + *len),
                               Decoder::kNoValidation);
      optional->index = imm.index;
      *len += imm.length;
      break;
    }
    case kExprStructGet:
    case kExprStructGetS:
    case kExprStructGetU:
    case kExprStructSet: {
      FieldImmediate imm(decoder, code->at(pc + *len), Decoder::kNoValidation);
      optional->gc_field_immediate = {imm.struct_imm.index,
                                      imm.field_imm.index};
      *len += imm.length;
      break;
    }
    case kExprArrayNew:
    case kExprArrayNewDefault:
    case kExprArrayGet:
    case kExprArrayGetS:
    case kExprArrayGetU:
    case kExprArraySet:
    case kExprArrayFill: {
      ArrayIndexImmediate imm(decoder, code->at(pc + *len),
                              Decoder::kNoValidation);
      optional->index = imm.index;
      *len += imm.length;
      break;
    }

    case kExprArrayNewFixed: {
      ArrayIndexImmediate array_imm(decoder, code->at(pc + *len),
                                    Decoder::kNoValidation);
      optional->gc_array_new_fixed.array_index = array_imm.index;
      *len += array_imm.length;
      IndexImmediate data_imm(decoder, code->at(pc + *len), "array length",
                              Decoder::kNoValidation);
      optional->gc_array_new_fixed.length = data_imm.index;
      *len += data_imm.length;
      break;
    }

    case kExprArrayNewData:
    case kExprArrayNewElem:
    case kExprArrayInitData:
    case kExprArrayInitElem: {
      ArrayIndexImmediate array_imm(decoder, code->at(pc + *len),
                                    Decoder::kNoValidation);
      optional->gc_array_new_or_init_data.array_index = array_imm.index;
      *len += array_imm.length;
      IndexImmediate data_imm(decoder, code->at(pc + *len), "segment index",
                              Decoder::kNoValidation);
      optional->gc_array_new_or_init_data.data_index = data_imm.index;
      *len += data_imm.length;
      break;
    }

    case kExprArrayCopy: {
      ArrayIndexImmediate dest_array_imm(decoder, code->at(pc + *len),
                                         Decoder::kNoValidation);
      optional->gc_array_copy.dest_array_index = dest_array_imm.index;
      *len += dest_array_imm.length;
      ArrayIndexImmediate src_array_imm(decoder, code->at(pc + *len),
                                        Decoder::kNoValidation);
      optional->gc_array_copy.src_array_index = src_array_imm.index;
      *len += src_array_imm.length;
      break;
    }

    case kExprRefI31:
    case kExprI31GetS:
    case kExprI31GetU:
    case kExprAnyConvertExtern:
    case kExprExternConvertAny:
    case kExprArrayLen:
      break;

    case kExprRefCast:
    case kExprRefCastNull:
    case kExprRefTest:
    case kExprRefTestNull: {
      HeapTypeImmediate imm(WasmEnabledFeatures::All(), decoder,
                            code->at(pc + *len), Decoder::kNoValidation);
      optional->gc_heap_type_immediate.length = imm.length;
      optional->gc_heap_type_immediate.type_representation =
          imm.type.representation();
      *len += imm.length;
      break;
    }

    case kExprBrOnCast:
    case kExprBrOnCastFail: {
      BrOnCastImmediate flags_imm(decoder, code->at(pc + *len),
                                  Decoder::kNoValidation);
      *len += flags_imm.length;
      BranchDepthImmediate branch(decoder, code->at(pc + *len),
                                  Decoder::kNoValidation);
      *len += branch.length;
      HeapTypeImmediate source_imm(WasmEnabledFeatures::All(), decoder,
                                   code->at(pc + *len), Decoder::kNoValidation);
      *len += source_imm.length;
      HeapTypeImmediate target_imm(WasmEnabledFeatures::All(), decoder,
                                   code->at(pc + *len), Decoder::kNoValidation);
      *len += target_imm.length;
      optional->br_on_cast_data = BranchOnCastData{
          branch.depth, flags_imm.flags.src_is_null,
          flags_imm.flags.res_is_null, target_imm.type.representation()};
      break;
    }

    default:
      FATAL("Unknown or unimplemented opcode #%d:%s", code->start[pc],
            WasmOpcodes::OpcodeName(static_cast<WasmOpcode>(code->start[pc])));
      UNREACHABLE();
  }
}

void WasmBytecodeGenerator::DecodeNumericOp(WasmOpcode opcode,
                                            WasmInstruction::Optional* optional,
                                            Decoder* decoder,
                                            InterpreterCode* code, pc_t pc,
                                            int* const len) {
  switch (opcode) {
#define DECODE_UNOP(name, from_ctype, from_type, from_reg, to_ctype, to_type, \
                    to_reg)                                                   \
  case kExpr##name:                                                           \
    break;

    FOREACH_TRUNCSAT_UNOP(DECODE_UNOP)
#undef DECODE_UNOP

    case kExprMemoryInit: {
      MemoryInitImmediate imm(decoder, code->at(pc + *len),
                              Decoder::kNoValidation);
      DCHECK_LT(imm.data_segment.index, module_->num_declared_data_segments);
      optional->index = imm.data_segment.index;
      *len += imm.length;
      break;
    }
    case kExprDataDrop: {
      IndexImmediate imm(decoder, code->at(pc + *len), "data segment index",
                         Decoder::kNoValidation);
      DCHECK_LT(imm.index, module_->num_declared_data_segments);
      optional->index = imm.index;
      *len += imm.length;
      break;
    }
    case kExprMemoryCopy: {
      MemoryCopyImmediate imm(decoder, code->at(pc + *len),
                              Decoder::kNoValidation);
      *len += imm.length;
      break;
    }
    case kExprMemoryFill: {
      MemoryIndexImmediate imm(decoder, code->at(pc + *len),
                               Decoder::kNoValidation);
      *len += imm.length;
      break;
    }
    case kExprTableInit: {
      TableInitImmediate imm(decoder, code->at(pc + *len),
                             Decoder::kNoValidation);
      optional->table_init.table_index = imm.table.index;
      optional->table_init.element_segment_index = imm.element_segment.index;
      *len += imm.length;
      break;
    }
    case kExprElemDrop: {
      IndexImmediate imm(decoder, code->at(pc + *len), "element segment index",
                         Decoder::kNoValidation);
      optional->index = imm.index;
      *len += imm.length;
      break;
    }
    case kExprTableCopy: {
      TableCopyImmediate imm(decoder, code->at(pc + *len),
                             Decoder::kNoValidation);
      optional->table_copy.dst_table_index = imm.table_dst.index;
      optional->table_copy.src_table_index = imm.table_src.index;
      *len += imm.length;
      break;
    }
    case kExprTableGrow: {
      IndexImmediate imm(decoder, code->at(pc + *len), "table index",
                         Decoder::kNoValidation);
      optional->index = imm.index;
      *len += imm.length;
      break;
    }
    case kExprTableSize: {
      IndexImmediate imm(decoder, code->at(pc + *len), "table index",
                         Decoder::kNoValidation);
      optional->index = imm.index;
      *len += imm.length;
      break;
    }
    case kExprTableFill: {
      IndexImmediate imm(decoder, code->at(pc + *len), "table index",
                         Decoder::kNoValidation);
      optional->index = imm.index;
      *len += imm.length;
      break;
    }
    default:
      FATAL("Unknown or unimplemented opcode #%d:%s", code->start[pc],
            WasmOpcodes::OpcodeName(static_cast<WasmOpcode>(code->start[pc])));
      UNREACHABLE();
  }
}

void WasmBytecodeGenerator::DecodeAtomicOp(WasmOpcode opcode,
                                           WasmInstruction::Optional* optional,
                                           Decoder* decoder,
                                           InterpreterCode* code, pc_t pc,
                                           int* const len) {
  switch (opcode) {
    case kExprAtomicNotify:
    case kExprI32AtomicWait: {
      MachineType memtype = MachineType::Uint32();
      MemoryAccessImmediate imm(decoder, code->at(pc + *len),
                                ElementSizeLog2Of(memtype.representation()),
                                IsMemory64(), Decoder::kNoValidation);
      optional->offset = imm.offset;
      *len += imm.length;
      break;
    }
    case kExprI64AtomicWait: {
      MachineType memtype = MachineType::Uint64();
      MemoryAccessImmediate imm(decoder, code->at(pc + *len),
                                ElementSizeLog2Of(memtype.representation()),
                                IsMemory64(), Decoder::kNoValidation);
      optional->offset = imm.offset;
      *len += imm.length;
      break;
    }
    case kExprAtomicFence:
      *len += 1;
      break;

#define ATOMIC_BINOP(name, Type,
```