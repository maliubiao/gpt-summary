Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is a part of the V8 JavaScript engine, specifically the WebAssembly interpreter.

Here's a breakdown of the thinking process to address the user's request:

1. **Identify the core function:** The code defines a series of `INSTRUCTION_HANDLER_FUNC` functions. This strongly suggests that this file is responsible for handling the execution of individual WebAssembly instructions within the interpreter.

2. **Examine the function names:** The names of the functions, such as `s2s_I31New`, `s2s_I31GetS`, `s2s_RefCast`, `s2s_RefTest`, `s2s_RefIsNonNull`, `s2s_AnyConvertExtern`, and `s2s_ExternConvertAny`, give clues about the specific WebAssembly instructions they handle. They seem to deal with:
    * `i31` instructions (related to 31-bit integers).
    * Reference types (`RefCast`, `RefTest`, `RefIsNonNull`).
    * Conversions between JavaScript values and WebAssembly externrefs (`AnyConvertExtern`, `ExternConvertAny`).
    * Assertions and traps related to type checking.
    * Some tracing functionality (functions starting with `trace_`).

3. **Analyze the function bodies:** The bodies of these functions generally perform the following actions:
    * `pop` values from the stack.
    * Perform some operation (e.g., bit manipulation, type casting, null check).
    * Potentially `TRAP` (throw an error) based on conditions.
    * `push` results back onto the stack.
    * Call `NextOp()` to proceed to the next instruction.

4. **Identify data structures and types:**  The code uses types like `WasmRef`, `HeapType`, `ValueType`, `WasmInterpreterRuntime`, `Simd128`. These indicate that the code operates on WebAssembly values, heap types, and interacts with the interpreter's runtime environment. The `sp` parameter likely represents the stack pointer.

5. **Look for control flow and decision making:**  Conditional checks like `V8_UNLIKELY(wasm_runtime->IsRefNull(ref))` and the use of templates with boolean parameters (`RefCast<bool null_succeeds>`) suggest control flow based on runtime conditions and instruction variations.

6. **Connect to JavaScript:** The presence of `AnyConvertExtern` and `ExternConvertAny` strongly indicates a connection to JavaScript. These functions handle the interoperability between WebAssembly and JavaScript by converting between JavaScript objects and WebAssembly externrefs.

7. **Consider the `.tq` extension:** The prompt mentions the `.tq` extension, which signifies Torque code in V8. This means some of the underlying logic might be defined in Torque and called from these C++ handlers.

8. **Address the specific points in the prompt:**
    * **Functionality:** List the types of WebAssembly instructions handled (i31, ref types, conversions, etc.).
    * **`.tq` extension:** Explain that if the file had a `.tq` extension, it would be a Torque file.
    * **JavaScript relationship:**  Focus on the `AnyConvertExtern` and `ExternConvertAny` functions and illustrate with JavaScript examples.
    * **Code logic reasoning:** Choose a simple handler like `s2s_I31New` and demonstrate the input/output based on its logic.
    * **Common programming errors:** Discuss null dereferences as a potential issue related to the `Ref` types.
    * **Overall function (for part 9/15):**  Emphasize that this part focuses on specific sets of instructions, particularly those related to `i31` and reference types, and the interaction with the embedding environment (JavaScript).

9. **Structure the answer:** Organize the findings into clear sections addressing each point in the prompt. Use headings and bullet points for readability. Provide concrete examples where requested.

By following these steps, we can systematically analyze the code snippet and generate a comprehensive and accurate summary of its functionality within the V8 WebAssembly interpreter.
这是一个V8源代码文件，位于 `v8/src/wasm/interpreter/wasm-interpreter.cc`，它属于V8引擎中WebAssembly解释器的实现部分。根据提供的代码片段，我们可以归纳出以下功能：

**主要功能：WebAssembly 指令的处理**

这个文件定义了一系列 C++ 函数，每个函数都以 `INSTRUCTION_HANDLER_FUNC` 开头，并且处理特定的 WebAssembly 指令。这些函数负责模拟这些指令在解释器中的行为。

**具体功能点：**

1. **`i31` 类型相关的操作:**
   - `s2s_I31New`: 创建一个新的 `i31` 值，它是一个带有高位标记的31位有符号整数。
   - `s2s_I31GetS`: 从 `i31` 值中提取有符号的 31 位整数。
   - `s2s_I31GetU`: 从 `i31` 值中提取无符号的 31 位整数。

2. **引用类型 (`ref`) 相关的操作:**
   - `RefCast` 和 `s2s_RefCast`, `s2s_RefCastNull`:  尝试将一个引用类型转换为目标类型。`RefCastNull` 允许 null 值转换成功，而 `RefCast` 不允许。如果转换失败会触发 `kTrapIllegalCast` 错误。
   - `RefTest` 和 `s2s_RefTest`, `s2s_RefTestNull`:  测试一个引用类型是否可以转换为目标类型，返回 1 (成功) 或 0 (失败)。`RefTestNull` 对 null 值返回成功。
   - `s2s_AssertNullTypecheck`: 断言一个引用是 null，如果不是则触发 `kTrapIllegalCast`。
   - `s2s_AssertNotNullTypecheck`: 断言一个引用不是 null，如果是则触发 `kTrapIllegalCast`。
   - `s2s_TrapIllegalCast`:  直接触发 `kTrapIllegalCast` 错误。
   - `s2s_RefTestSucceeds`, `s2s_RefTestFails`: 用于测试场景，分别总是返回 1 (成功) 或 0 (失败)。
   - `s2s_RefIsNonNull`: 检查一个引用是否为 null，返回 1 (非 null) 或 0 (null)。
   - `s2s_RefAsNonNull`: 断言一个引用不是 null，如果是 null 则触发 `kTrapNullDereference`，否则将引用推入栈。

3. **JavaScript 与 WebAssembly 互操作相关的操作:**
   - `s2s_AnyConvertExtern`: 将一个 WebAssembly 的 `externref` 类型的值（通常是 JavaScript 对象）转换为 WebAssembly 的 `anyref` 类型。如果转换失败，会触发一个 WebAssembly 陷阱。
   - `s2s_ExternConvertAny`: 将一个 WebAssembly 的 `anyref` 类型的值转换为 `externref` 类型。如果输入是 null，则输出也是 null。

4. **调试和跟踪功能 (如果 `V8_ENABLE_DRUMBRAKE_TRACING` 宏定义存在):**
   - `s2s_TraceInstruction`: 打印当前执行的指令信息，包括程序计数器 (PC)、操作码和寄存器状态。
   - `trace_UpdateStack`:  记录堆栈的更新。
   - `trace_PushConstSlot` 系列: 记录常量值被推入堆栈的操作。
   - `trace_PushCopySlot`: 记录从一个堆栈位置复制值到另一个位置的操作。
   - `trace_PopSlot`: 记录从堆栈弹出值的操作。
   - `trace_SetSlotType`: 记录堆栈槽的类型设置。

5. **异常处理数据结构:**
   - `WasmEHData`, `WasmEHDataGenerator`:  定义了用于 WebAssembly 异常处理的数据结构和生成器，包括 try 块、catch 块以及它们之间的关系。这部分代码用于在解释器中管理和查找异常处理程序。

6. **WebAssembly 字节码结构:**
   - `WasmBytecode`: 定义了 WebAssembly 字节码的表示，包括代码、常量槽、异常处理数据等。
   - `WasmBytecodeGenerator`: 用于生成 `WasmBytecode` 结构。

**关于 `.tq` 结尾：**

如果 `v8/src/wasm/interpreter/wasm-interpreter.cc` 以 `.tq` 结尾，那么它确实是一个 V8 Torque 源代码文件。Torque 是一种 V8 内部使用的领域特定语言，用于生成高效的 C++ 代码。在这个例子中，文件名是 `.cc`，所以它是标准的 C++ 代码。

**与 JavaScript 的关系及示例：**

`s2s_AnyConvertExtern` 和 `s2s_ExternConvertAny` 直接关联了 JavaScript 和 WebAssembly 的互操作。

**`s2s_AnyConvertExtern` 示例：**

```javascript
// 假设在 WebAssembly 模块中有一个导入的函数，它接收 anyref 类型
// 以及一个导出的函数，它返回一个 JavaScript 对象 (会被转换为 externref)

const wasmCode = await WebAssembly.compileStreaming(fetch('your_wasm_module.wasm'));
const importObject = {
  imports: {
    // 假设 wasm 模块导入了一个名为 'receiveAnyRef' 的函数
    receiveAnyRef: (arg) => {
      console.log("Received from WASM:", arg);
    }
  }
};
const instance = await WebAssembly.instantiate(wasmCode, importObject);

// 假设 wasm 模块导出了一个名为 'getJsObject' 的函数，它返回一个 JavaScript 对象
const jsObject = instance.exports.getJsObject();

// 在 WebAssembly 内部，当 'getJsObject' 返回时，它会被转换为 externref
// 然后，如果 wasm 尝试将其转换为 anyref (例如，传递给另一个 wasm 函数)
// 就会使用 s2s_AnyConvertExtern 来处理这个转换

instance.exports.receiveAnyRef(jsObject); // jsObject 会被隐式地转换为 wasm 的 anyref
```

**`s2s_ExternConvertAny` 示例：**

```javascript
// 假设在 WebAssembly 模块中有一个导出的函数，它接收 anyref 并返回 externref

const wasmCode = await WebAssembly.compileStreaming(fetch('your_wasm_module.wasm'));
const instance = await WebAssembly.instantiate(wasmCode);

// 假设 wasm 模块导出了一个名为 'convertAndGetExtern' 的函数
// 它接收一个 wasm 的 anyref，然后在 wasm 内部将其转换为 externref 返回

// 创建一个 wasm 的 anyref (例如，一个 null ref)
const nullAnyRef = null; // 在 wasm 中会被解释为 null anyref

// 调用 wasm 函数
const externRefResult = instance.exports.convertAndGetExtern(nullAnyRef);

console.log("Received externref from WASM:", externRefResult); // 可能是 null
```

**代码逻辑推理（以 `s2s_I31New` 为例）：**

**假设输入：**

- `value` (在寄存器或栈中) = `10` (十进制)

**执行过程：**

1. `value & 0x7fffffff`:  `10 & 0x7fffffff` 仍然是 `10`，因为 `0x7fffffff` 的二进制表示除了最高位是 0 之外，其余位都是 1。
2. `Internals::IntToSmi(value & 0x7fffffff)`: 将 `10` 转换为 V8 的 Smi (Small Integer) 表示。
3. `handle(smi, wasm_runtime->GetIsolate())`: 创建一个指向该 Smi 的 Handle，用于 V8 的垃圾回收管理。
4. `push<WasmRef>(sp, code, wasm_runtime, handle(...))`: 将这个 Handle (作为 `WasmRef`) 推入 WebAssembly 解释器的栈中。

**输出：**

- WebAssembly 栈顶增加一个 `WasmRef`，其指向的值是 V8 中表示整数 `10` 的 Smi。

**用户常见的编程错误（涉及 `Ref` 类型）：**

一个常见的编程错误是**空指针解引用 (Null Dereference)**，这与 `Ref` 类型密切相关。

**示例：**

假设 WebAssembly 代码期望从一个非空的引用中读取数据，但实际接收到了一个 null 引用。

```c++
INSTRUCTION_HANDLER_FUNC s2s_SomeRefOperation(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0) {
  WasmRef ref = pop<WasmRef>(sp, code, wasm_runtime);
  // 程序员可能错误地认为 'ref' 总是非 null
  if (wasm_runtime->IsRefNull(ref)) {
    // 应该在这里处理 null 的情况，否则下面的操作会导致错误
    TRAP(TrapReason::kTrapNullDereference);
  }
  // 尝试访问 'ref' 指向的对象的成员
  // ...
  NextOp();
}
```

在 JavaScript 中触发这种错误的情况可能是：

```javascript
const wasmCode = await WebAssembly.compileStreaming(fetch('your_wasm_module.wasm'));
const instance = await WebAssembly.instantiate(wasmCode);

// 假设 wasm 模块导出了一个函数 'processRef'，它期望接收一个非 null 的引用
const myRef = null; // 模拟传递一个 null 引用

try {
  instance.exports.processRef(myRef); // 如果 wasm 代码没有正确处理 null，就会出错
} catch (e) {
  console.error("WebAssembly error:", e); // 可能会捕获一个由于 Null Dereference 导致的陷阱
}
```

**第 9 部分功能归纳：**

作为 15 个部分中的第 9 部分，这个代码片段主要集中在 **WebAssembly 解释器中特定指令的处理逻辑**，特别是以下方面：

- **`i31` 类型的操作**，包括创建和提取其内部的整数值。
- **引用类型 (`ref`) 的各种操作**，例如类型转换、类型测试、空值检查和断言。这些操作对于实现 WebAssembly 的类型安全至关重要。
- **JavaScript 与 WebAssembly 之间的互操作**，体现在 `anyref` 和 `externref` 之间的转换处理。这使得 WebAssembly 能够与 JavaScript 环境中的对象进行交互。
- **可能的调试和跟踪功能**，用于在开发和调试过程中监控解释器的执行状态（如果启用了相应的宏）。
- **异常处理机制的基础**，定义了用于管理 try-catch 块的数据结构。

总而言之，这部分代码是 WebAssembly 解释器核心执行引擎的一部分，负责模拟和执行一部分关键的 WebAssembly 指令，并且处理与 JavaScript 互操作以及异常处理相关的逻辑。

Prompt: 
```
这是目录为v8/src/wasm/interpreter/wasm-interpreter.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/interpreter/wasm-interpreter.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第9部分，共15部分，请归纳一下它的功能

"""
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
                                 
"""


```