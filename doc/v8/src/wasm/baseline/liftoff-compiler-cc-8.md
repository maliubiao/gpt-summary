Response:
Let's break down the request and the provided code.

**1. Understanding the Request:**

The core request is to analyze a specific V8 source code file (`v8/src/wasm/baseline/liftoff-compiler.cc`) and provide information about its functionality. The request has several specific sub-points:

* **List Functionalities:**  A general overview of what the code does.
* **Torque Source:** Check if the filename ends with `.tq`.
* **JavaScript Relationship:** If the code relates to JavaScript, provide a JavaScript example.
* **Code Logic Inference:** If there's complex logic, provide example inputs and outputs.
* **Common Programming Errors:** Identify potential user errors related to the code's functionality.
* **Part of a Series:** Acknowledge it's part 9 of 13 and summarize the functionality within this context.

**2. Initial Code Examination (Skimming and Keyword Spotting):**

I quickly scanned the code, looking for key elements:

* **Class Name:** `LiftoffCompiler`. This immediately suggests it's part of the Liftoff compiler for WebAssembly.
* **Method Names:**  Methods like `IndexToVarStateSaturating`, `MemoryInit`, `DataDrop`, `MemoryCopy`, `MemoryFill`, `TableInit`, `ElemDrop`, `TableCopy`, `TableGrow`, `TableSize`, `TableFill`, `StructNew`, `StructGet`, `StructSet`, `ArrayNew`, `ArrayFill`, `ArrayGet`, `ArraySet`, `ArrayLen`, `ArrayCopy`, `ArrayNewFixed`, `ArrayNewSegment`. These names strongly indicate the code handles various WebAssembly instructions related to memory, tables, structs, and arrays.
* **`FullDecoder`:** This suggests it interacts with the WebAssembly decoding process.
* **`WasmMemory`, `WasmTableObject`, `WasmStruct`, `WasmArray`:**  These are clearly data structures related to WebAssembly memory, tables, structs, and arrays.
* **`Builtin::k...`:** Calls to built-in functions, which are often lower-level runtime functions within V8.
* **`ExternalReference::wasm_...`:**  Calls to external C++ functions.
* **`LiftoffRegister`:**  Indicates it's dealing with register allocation and management within the Liftoff compiler.
* **`VarState`:** Likely represents the state of a variable (e.g., its location in a register or on the stack).
* **`__ emit_...`:**  These likely generate machine code instructions.
* **`DCHECK`:**  Assertions for debugging.
* **`FREEZE_STATE`:**  Likely related to capturing the current compilation state for error reporting or debugging.
* **`kMaxUint32`:** A constant related to unsigned 32-bit integers.

**3. Detailed Analysis and Mapping to Request Points:**

Now I started to connect the code elements to the specific points in the request:

* **Functionalities:** The prominent method names (e.g., `MemoryInit`, `TableCopy`, `StructNew`, `ArrayGet`) directly map to WebAssembly instructions. The code is responsible for *implementing* the behavior of these instructions within the Liftoff compiler. It handles memory access, table manipulation, struct and array creation and access. The `IndexToVarStateSaturating` function suggests handling potential overflow or out-of-bounds issues when accessing memory or table indices.

* **Torque Source:**  The request explicitly mentions checking the file extension. The provided information states the file is `liftoff-compiler.cc`, not `.tq`. So, it's C++, not Torque.

* **JavaScript Relationship:**  WebAssembly directly interacts with JavaScript. The functions in this file are responsible for the *low-level execution* of WebAssembly instructions. If a JavaScript program uses WebAssembly, and that WebAssembly code performs a memory operation or accesses a table, *this* code (or similar code within the Liftoff compiler) will be responsible for carrying out that operation. I can create a simple JavaScript example that triggers these kinds of operations.

* **Code Logic Inference:**  The `IndexToVarStateSaturating` function has conditional logic based on the system's pointer size (32-bit vs. 64-bit) and the size of the data being accessed (32-bit vs. 64-bit). I can create hypothetical scenarios with different pointer sizes and data types to illustrate the input and output of this function. Similarly, the `MemoryInit`, `MemoryCopy`, and `MemoryFill` functions involve calls to external functions with specific parameters, and there's error handling with `trap_label`.

* **Common Programming Errors:**  Based on the function names and logic, I can infer common WebAssembly programming errors that this code is designed to handle or that could lead to issues: out-of-bounds memory access, accessing dropped data segments, incorrect index usage for tables and arrays, type mismatches when accessing struct fields or array elements, and issues with table initialization.

* **Part of a Series:** Knowing this is part 9 of 13, I can infer that previous parts likely covered earlier stages of the Liftoff compilation process (e.g., instruction decoding, basic block building), and subsequent parts will probably deal with later stages (e.g., optimization, final code generation). This part focuses on the implementation of specific WebAssembly instructions.

**4. Structuring the Output:**

Finally, I organized the gathered information into the requested format, ensuring to address each point clearly and concisely. I included the JavaScript examples and the input/output scenarios for the code logic inference. I also made sure to explicitly state that the file is C++ and not Torque.
这是一个V8源代码文件，属于WebAssembly的Liftoff编译器的一部分。Liftoff是一个为WebAssembly设计的基础（baseline）编译器，它的目标是快速生成代码，虽然生成的代码性能可能不如优化编译器（如TurboFan）。

**功能归纳:**

`v8/src/wasm/baseline/liftoff-compiler.cc` 文件的主要功能是**为WebAssembly指令生成机器码，特别关注于内存操作、表操作、结构体和数组操作**。它实现了WebAssembly规范中定义的各种指令，例如内存加载/存储、内存初始化/复制/填充、表的创建/访问/修改、结构体和数组的创建/访问/修改等。

**具体功能列举:**

1. **处理栈操作:**  管理Liftoff编译器的栈状态，包括压入和弹出值，以及根据栈索引获取变量状态。 例如 `IndexToVarStateSaturating`, `PopIndexToVarStateSaturating`。
2. **内存操作指令实现:**
   - `MemoryInit`: 实现 `memory.init` 指令，将数据段的内容复制到线性内存中。
   - `DataDrop`: 实现 `data.drop` 指令，使特定的数据段不可用。
   - `MemoryCopy`: 实现 `memory.copy` 指令，将内存的一部分复制到另一部分。
   - `MemoryFill`: 实现 `memory.fill` 指令，用一个给定的值填充内存区域。
3. **表操作指令实现:**
   - `TableInit`: 实现 `table.init` 指令，将元素段的内容复制到表中。
   - `ElemDrop`: 实现 `elem.drop` 指令，使特定的元素段不可用。
   - `TableCopy`: 实现 `table.copy` 指令，将表的一部分复制到同一或另一个表的另一部分。
   - `TableGrow`: 实现 `table.grow` 指令，增加表的大小。
   - `TableSize`: 实现 `table.size` 指令，获取表的当前大小。
   - `TableFill`: 实现 `table.fill` 指令，用一个给定的值填充表的区域。
4. **结构体操作指令实现:**
   - `StructNew`: 实现 `struct.new` 和 `struct.new_default` 指令，创建新的结构体实例。
   - `StructGet`: 实现 `struct.get` 指令，获取结构体字段的值。
   - `StructSet`: 实现 `struct.set` 指令，设置结构体字段的值。
5. **数组操作指令实现:**
   - `ArrayNew`: 实现 `array.new` 和 `array.new_default` 指令，创建新的数组实例。
   - `ArrayFill`: 实现 `array.fill` 指令，用一个给定的值填充数组的区域。
   - `ArrayGet`: 实现 `array.get` 指令，获取数组元素的值。
   - `ArraySet`: 实现 `array.set` 指令，设置数组元素的值。
   - `ArrayLen`: 实现 `array.len` 指令，获取数组的长度。
   - `ArrayCopy`: 实现 `array.copy` 指令，将数组的一部分复制到同一或另一个数组的另一部分。
   - `ArrayNewFixed`: 实现 `array.new_fixed` 指令，创建一个具有固定大小和初始值的数组。
   - `ArrayNewSegment`: 实现 `array.new_segment` 指令，从元素段创建一个数组。
6. **辅助功能:**
   - `IndexToVarStateSaturating`:  根据栈索引获取变量状态，并在32位平台上饱和处理64位值，防止溢出。
   - `LoadSmi`/`LoadSmiConstant`: 加载小的整数常量（Smi）。
   - `CallBuiltin`: 调用内置的运行时函数。
   - `GenerateCCall`: 生成对C++函数的调用。
   - `CheckHighWordEmptyForTableType`: 检查用于表操作的索引高位是否为空，以避免越界访问。
   - `RttCanon`: 获取 RTT (Runtime Type) 的规范表示。
   - `MaybeEmitNullCheck`:  根据配置选择性地生成空值检查代码。
   - `BoundsCheckArray`: 生成数组边界检查的代码。
   - `ArrayFillImpl`:  实现数组填充的通用逻辑。
   - `StoreObjectField`/`LoadObjectField`:  存储和加载对象的字段，包括结构体和数组的元素。
   - `SetDefaultValue`: 设置指定类型的默认值。

**关于源代码类型:**

`v8/src/wasm/baseline/liftoff-compiler.cc` 以 `.cc` 结尾，**不是**以 `.tq` 结尾。因此，它是一个 **C++** 源代码文件，而不是 V8 Torque 源代码。V8 Torque 是一种用于定义 V8 内部函数的领域特定语言，通常用于类型检查和生成优化的代码。

**与 JavaScript 的关系:**

这个文件中的代码直接支持 WebAssembly 在 JavaScript 环境中的执行。当 JavaScript 代码加载并执行 WebAssembly 模块时，如果 Liftoff 编译器被选中来编译该模块，那么这个文件中的代码将负责将 WebAssembly 指令转换为可以在底层硬件上执行的机器码。

**JavaScript 示例:**

```javascript
const wasmCode = new Uint8Array([
  0, 97, 115, 109, 1, 0, 0, 0, 1, 7, 1, 96, 0, 1, 127, 3, 2, 1, 0, 4, 4, 1,
  112, 0, 0, 10, 9, 1, 7, 0, 65, 0, 17, 0, 26, 11
]);
const wasmModule = new WebAssembly.Module(wasmCode);
const wasmInstance = new WebAssembly.Instance(wasmModule);

// 假设 WebAssembly 代码包含一个访问内存的操作
// 例如，i32.load  offset=0
const memory = new WebAssembly.Memory({ initial: 1 });
const importObject = { memory: memory };
const wasmInstanceWithMemory = new WebAssembly.Instance(wasmModule, importObject);

// 当 WebAssembly 代码执行 i32.load 指令时，
// `liftoff-compiler.cc` 中相应的代码会被执行，
// 生成机器码来从线性内存中加载一个 32 位整数。
const value = wasmInstanceWithMemory.exports.someFunctionThatLoadsMemory();

console.log(value);
```

在这个例子中，当 `wasmInstanceWithMemory.exports.someFunctionThatLoadsMemory()` 被调用时，如果该 WebAssembly 函数内部包含了内存加载指令（例如 `i32.load`），那么 `liftoff-compiler.cc` 中的相关代码（可能是间接调用的）会负责生成实际的机器码来执行这个加载操作。

**代码逻辑推理示例:**

**假设输入:**

- 当前系统是 32 位系统 (`kSystemPointerSize == kInt32Size`)。
- 栈顶有一个 `i64` 类型的值，其低 32 位是 `0x12345678`，高 32 位是 `0x00000000`。
- 调用 `IndexToVarStateSaturating(0, pinned)`。

**代码逻辑推理:**

1. `stack_index` 为 0，所以访问栈顶元素。
2. 栈顶元素的 `kind()` 是 `kI64`。
3. `kSystemPointerSize == kInt32Size`，`is_mem64` 为 true。条件 `(kSystemPointerSize == kInt64Size) == is_mem64` 为 `false`。
4. 元素不是常量且类型为 `kI64`，执行 `LiftoffRegister reg = __ LoadToModifiableRegister(slot, *pinned);` 将 `i64` 的低 32 位加载到一个可修改的寄存器 `reg.low()`，高 32 位加载到 `reg.high()`。
5. 进入 "For memory64 on 32-bit systems, saturate the low word." 分支。
6. `pinned->set(reg.low())` 将低位寄存器标记为已占用。
7. `__ emit_cond_jump(kZero, &ok, kI32, reg.high().gp(), no_reg, frozen);` 检查高位寄存器是否为零。在本例中，高位为 `0x00000000`，所以条件为真，跳转到 `ok` 标签。
8. 返回 `{kIntPtrKind, reg.low(), 0}`。

**输出:**

- 返回一个 `VarState`，其类型为 `kIntPtrKind`（在 32 位系统上通常是 `kI32`），寄存器为 `reg.low()`，常量部分为 0。实际上返回的是栈顶 `i64` 值的低 32 位。

**假设输入 (另一种情况):**

- 当前系统是 32 位系统。
- 栈顶有一个 `i64` 类型的值，其低 32 位是 `0x12345678`，高 32 位是 `0xFFFFFFFF`。
- 调用 `IndexToVarStateSaturating(0, pinned)`。

**代码逻辑推理:**

与上述步骤类似，直到检查高位寄存器。

7. `__ emit_cond_jump(kZero, &ok, kI32, reg.high().gp(), no_reg, frozen);` 检查高位寄存器是否为零。在本例中，高位为 `0xFFFFFFFF`，所以条件为假，不跳转。
8. `__ LoadConstant(reg.low(), WasmValue{kMaxUInt32});` 将低位寄存器 `reg.low()` 加载为 `kMaxUInt32` (0xFFFFFFFF)。
9. `__ emit_jump(&ok);` 跳转到 `ok` 标签。
10. 返回 `{kIntPtrKind, reg.low(), 0}`。

**输出:**

- 返回一个 `VarState`，其类型为 `kIntPtrKind`，寄存器为 `reg.low()`，常量部分为 0。 寄存器 `reg.low()` 的值将是 `0xFFFFFFFF`，因为高位不为零，进行了饱和处理。

**用户常见的编程错误示例:**

1. **内存访问越界:**  WebAssembly 代码尝试访问超出线性内存边界的地址。例如，使用 `i32.load` 或 `i32.store` 时，提供的偏移量加上访问的大小超过了内存的大小。`liftoff-compiler.cc` 中的代码会生成相应的边界检查，如果发生越界，会抛出 WebAssembly 陷阱。

   ```javascript
   // 假设 WebAssembly 模块导出一个函数，该函数尝试访问超出内存边界的位置
   // (假设内存大小为 65536 字节)
   wasmInstance.exports.accessMemoryOutOfBounds(70000); // 偏移量超出范围
   ```

2. **表索引越界:** WebAssembly 代码尝试访问表中不存在的元素。例如，使用 `call_indirect` 或 `table.get` 时，提供的索引超出表的当前大小。`liftoff-compiler.cc` 中会生成代码检查索引的有效性。

   ```javascript
   // 假设 WebAssembly 模块导出一个函数，该函数尝试通过超出范围的索引调用表中的元素
   wasmInstance.exports.callIndirectOutOfBounds(1000); // 假设表大小小于 1000
   ```

3. **类型不匹配的结构体/数组访问:**  尝试以错误的类型访问结构体字段或数组元素。例如，将一个 `i32` 值存储到一个声明为 `f64` 的数组元素中。虽然 Liftoff 是一个基础编译器，它仍然需要遵循 WebAssembly 的类型系统，但类型检查更多可能发生在更早的验证阶段。在 Liftoff 中，可能会生成代码来处理不同大小的数据的加载和存储，但高级的类型安全由 WebAssembly 虚拟机保证。

4. **对已丢弃的数据段/元素段进行操作:**  在 `data.drop` 或 `elem.drop` 指令执行后，尝试使用这些段进行 `memory.init` 或 `table.init` 操作。`liftoff-compiler.cc` 中的 `DataDrop` 和 `ElemDrop` 函数会修改内部状态，使得后续的初始化操作会失败或产生预期外的行为。

**作为第 9 部分的功能归纳:**

作为 13 个部分中的第 9 部分，`v8/src/wasm/baseline/liftoff-compiler.cc` 文件专注于 **Liftoff 编译器中核心的 WebAssembly 指令实现，特别是关于内存、表、结构体和数组的操作**。 前面的部分可能涵盖了 Liftoff 编译器的初始化、指令解码、基本块构建等，而后续的部分可能涉及更高级的编译优化、代码生成收尾工作或者与其他 V8 基础设施的集成。  这部分是 Liftoff 编译器将高级 WebAssembly 指令转化为底层机器码的关键环节，直接决定了 WebAssembly 代码在 V8 中的执行方式和性能。它确保了 Liftoff 能够快速地为各种内存和数据结构操作生成可执行代码。

### 提示词
```
这是目录为v8/src/wasm/baseline/liftoff-compiler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/baseline/liftoff-compiler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第9部分，共13部分，请归纳一下它的功能
```

### 源代码
```cpp
kMaxUint32 if the high word had any
  // bits set.
  VarState IndexToVarStateSaturating(int stack_index, LiftoffRegList* pinned) {
    DCHECK_LE(0, stack_index);
    DCHECK_LT(stack_index, __ cache_state()->stack_height());
    VarState& slot = __ cache_state()->stack_state.end()[-1 - stack_index];
    const bool is_mem64 = slot.kind() == kI64;
    // For memory32 on a 32-bit system or memory64 on a 64-bit system, there is
    // nothing to do.
    if ((kSystemPointerSize == kInt64Size) == is_mem64) {
      if (slot.is_reg()) pinned->set(slot.reg());
      return slot;
    }

    // {kI64} constants will be stored as 32-bit integers in the {VarState} and
    // will be sign-extended later. Hence we can return constants if they are
    // positive (such that sign-extension and zero-extension are identical).
    if (slot.is_const() && (kIntPtrKind == kI32 || slot.i32_const() >= 0)) {
      return {kIntPtrKind, slot.i32_const(), 0};
    }

    LiftoffRegister reg = __ LoadToModifiableRegister(slot, *pinned);
    // For memory32 on 64-bit hosts, zero-extend.
    if constexpr (Is64()) {
      DCHECK(!is_mem64);  // Handled above.
      __ emit_u32_to_uintptr(reg.gp(), reg.gp());
      pinned->set(reg);
      return {kIntPtrKind, reg, 0};
    }

    // For memory64 on 32-bit systems, saturate the low word.
    DCHECK(is_mem64);  // Other cases are handled above.
    DCHECK_EQ(kSystemPointerSize, kInt32Size);
    pinned->set(reg.low());
    Label ok;
    FREEZE_STATE(frozen);
    __ emit_cond_jump(kZero, &ok, kI32, reg.high().gp(), no_reg, frozen);
    __ LoadConstant(reg.low(), WasmValue{kMaxUInt32});
    __ emit_jump(&ok);
    __ bind(&ok);
    return {kIntPtrKind, reg.low(), 0};
  }

  // Same as {PopIndexToVarState}, but saturates 64-bit values on 32-bit
  // platforms like {IndexToVarStateSaturating}.
  VarState PopIndexToVarStateSaturating(LiftoffRegList* pinned) {
    VarState result = IndexToVarStateSaturating(0, pinned);
    __ DropValues(1);
    return result;
  }

  // The following functions are to be used inside a DCHECK. They always return
  // true and will fail internally on a detected inconsistency.
#ifdef DEBUG
  // Checks that the top-of-stack value matches the declared memory (64-bit or
  // 32-bit).
  bool MatchingMemTypeOnTopOfStack(const WasmMemory* memory) {
    return MatchingAddressTypeOnTopOfStack(memory->is_memory64());
  }

  // Checks that the top-of-stack value matches the expected bitness.
  bool MatchingAddressTypeOnTopOfStack(bool expect_64bit_value) {
    DCHECK_LT(0, __ cache_state()->stack_height());
    ValueKind expected_kind = expect_64bit_value ? kI64 : kI32;
    DCHECK_EQ(expected_kind, __ cache_state()->stack_state.back().kind());
    return true;
  }

  bool MatchingMemType(const WasmMemory* memory, int stack_index) {
    DCHECK_LE(0, stack_index);
    DCHECK_LT(stack_index, __ cache_state()->stack_state.size());
    ValueKind expected_kind = memory->is_memory64() ? kI64 : kI32;
    DCHECK_EQ(expected_kind,
              __ cache_state()->stack_state.end()[-1 - stack_index].kind());
    return true;
  }
#endif

  void MemoryInit(FullDecoder* decoder, const MemoryInitImmediate& imm,
                  const Value&, const Value&, const Value&) {
    FUZZER_HEAVY_INSTRUCTION;
    Register mem_offsets_high_word = no_reg;
    LiftoffRegList pinned;
    VarState size = __ PopVarState();
    if (size.is_reg()) pinned.set(size.reg());
    VarState src = __ PopVarState();
    if (src.is_reg()) pinned.set(src.reg());
    DCHECK(MatchingMemTypeOnTopOfStack(imm.memory.memory));
    VarState dst = PopIndexToVarState(&mem_offsets_high_word, &pinned);

    Register instance_data = __ cache_state() -> cached_instance_data;
    if (instance_data == no_reg) {
      instance_data = __ GetUnusedRegister(kGpReg, pinned).gp();
      __ LoadInstanceDataFromFrame(instance_data);
    }
    pinned.set(instance_data);

    // TODO(crbug.com/41480344): The stack state in the OOL code should reflect
    // the state before popping any values (for a better debugging experience).
    Label* trap_label =
        AddOutOfLineTrap(decoder, Builtin::kThrowWasmTrapMemOutOfBounds);
    if (mem_offsets_high_word != no_reg) {
      // If any high word has bits set, jump to the OOB trap.
      FREEZE_STATE(trapping);
      __ emit_cond_jump(kNotZero, trap_label, kI32, mem_offsets_high_word,
                        no_reg, trapping);
      pinned.clear(mem_offsets_high_word);
    }

    LiftoffRegister result =
        GenerateCCall(kI32,
                      {{kIntPtrKind, LiftoffRegister{instance_data}, 0},
                       {kI32, static_cast<int32_t>(imm.memory.index), 0},
                       dst,
                       src,
                       {kI32, static_cast<int32_t>(imm.data_segment.index), 0},
                       size},
                      ExternalReference::wasm_memory_init());
    FREEZE_STATE(trapping);
    __ emit_cond_jump(kEqual, trap_label, kI32, result.gp(), no_reg, trapping);
  }

  void DataDrop(FullDecoder* decoder, const IndexImmediate& imm) {
    LiftoffRegList pinned;

    Register seg_size_array =
        pinned.set(__ GetUnusedRegister(kGpReg, pinned)).gp();
    LOAD_TAGGED_PTR_INSTANCE_FIELD(seg_size_array, DataSegmentSizes, pinned);

    LiftoffRegister seg_index =
        pinned.set(__ GetUnusedRegister(kGpReg, pinned));
    // Scale the seg_index for the array access.
    __ LoadConstant(
        seg_index,
        WasmValue(wasm::ObjectAccess::ElementOffsetInTaggedFixedUInt32Array(
            imm.index)));

    // Set the length of the segment to '0' to drop it.
    LiftoffRegister null_reg = pinned.set(__ GetUnusedRegister(kGpReg, pinned));
    __ LoadConstant(null_reg, WasmValue(0));
    __ Store(seg_size_array, seg_index.gp(), 0, null_reg, StoreType::kI32Store,
             pinned);
  }

  void MemoryCopy(FullDecoder* decoder, const MemoryCopyImmediate& imm,
                  const Value&, const Value&, const Value&) {
    FUZZER_HEAVY_INSTRUCTION;
    Register mem_offsets_high_word = no_reg;
    LiftoffRegList pinned;

    // The type of {size} is the min of {src} and {dst} (where {kI32 < kI64}).
    DCHECK(
        MatchingAddressTypeOnTopOfStack(imm.memory_dst.memory->is_memory64() &&
                                        imm.memory_src.memory->is_memory64()));
    VarState size = PopIndexToVarState(&mem_offsets_high_word, &pinned);
    DCHECK(MatchingMemTypeOnTopOfStack(imm.memory_src.memory));
    VarState src = PopIndexToVarState(&mem_offsets_high_word, &pinned);
    DCHECK(MatchingMemTypeOnTopOfStack(imm.memory_dst.memory));
    VarState dst = PopIndexToVarState(&mem_offsets_high_word, &pinned);

    Register instance_data = __ cache_state() -> cached_instance_data;
    if (instance_data == no_reg) {
      instance_data = __ GetUnusedRegister(kGpReg, pinned).gp();
      __ LoadInstanceDataFromFrame(instance_data);
    }
    pinned.set(instance_data);

    // TODO(crbug.com/41480344): The stack state in the OOL code should reflect
    // the state before popping any values (for a better debugging experience).
    Label* trap_label =
        AddOutOfLineTrap(decoder, Builtin::kThrowWasmTrapMemOutOfBounds);
    DCHECK_IMPLIES(Is64(), mem_offsets_high_word == no_reg);
    if (!Is64() && mem_offsets_high_word != no_reg) {
      // If any high word has bits set, jump to the OOB trap.
      FREEZE_STATE(trapping);
      __ emit_cond_jump(kNotZero, trap_label, kI32, mem_offsets_high_word,
                        no_reg, trapping);
    }

    LiftoffRegister result =
        GenerateCCall(kI32,
                      {{kIntPtrKind, LiftoffRegister{instance_data}, 0},
                       {kI32, static_cast<int32_t>(imm.memory_dst.index), 0},
                       {kI32, static_cast<int32_t>(imm.memory_src.index), 0},
                       dst,
                       src,
                       size},
                      ExternalReference::wasm_memory_copy());
    FREEZE_STATE(trapping);
    __ emit_cond_jump(kEqual, trap_label, kI32, result.gp(), no_reg, trapping);
  }

  void MemoryFill(FullDecoder* decoder, const MemoryIndexImmediate& imm,
                  const Value&, const Value&, const Value&) {
    FUZZER_HEAVY_INSTRUCTION;
    Register mem_offsets_high_word = no_reg;
    LiftoffRegList pinned;
    DCHECK(MatchingMemTypeOnTopOfStack(imm.memory));
    VarState size = PopIndexToVarState(&mem_offsets_high_word, &pinned);
    VarState value = __ PopVarState();
    if (value.is_reg()) pinned.set(value.reg());
    DCHECK(MatchingMemTypeOnTopOfStack(imm.memory));
    VarState dst = PopIndexToVarState(&mem_offsets_high_word, &pinned);

    Register instance_data = __ cache_state() -> cached_instance_data;
    if (instance_data == no_reg) {
      instance_data = __ GetUnusedRegister(kGpReg, pinned).gp();
      __ LoadInstanceDataFromFrame(instance_data);
    }
    pinned.set(instance_data);

    // TODO(crbug.com/41480344): The stack state in the OOL code should reflect
    // the state before popping any values (for a better debugging experience).
    Label* trap_label =
        AddOutOfLineTrap(decoder, Builtin::kThrowWasmTrapMemOutOfBounds);
    if (mem_offsets_high_word != no_reg) {
      // If any high word has bits set, jump to the OOB trap.
      FREEZE_STATE(trapping);
      __ emit_cond_jump(kNotZero, trap_label, kI32, mem_offsets_high_word,
                        no_reg, trapping);
    }

    LiftoffRegister result =
        GenerateCCall(kI32,
                      {{kIntPtrKind, LiftoffRegister{instance_data}, 0},
                       {kI32, static_cast<int32_t>(imm.index), 0},
                       dst,
                       value,
                       size},
                      ExternalReference::wasm_memory_fill());
    FREEZE_STATE(trapping);
    __ emit_cond_jump(kEqual, trap_label, kI32, result.gp(), no_reg, trapping);
  }

  void LoadSmi(LiftoffRegister reg, int value) {
    Address smi_value = Smi::FromInt(value).ptr();
    using smi_type = std::conditional_t<kSmiKind == kI32, int32_t, int64_t>;
    __ LoadConstant(reg, WasmValue{static_cast<smi_type>(smi_value)});
  }

  VarState LoadSmiConstant(int32_t constant, LiftoffRegList* pinned) {
    if constexpr (kSmiKind == kI32) {
      int32_t smi_const = static_cast<int32_t>(Smi::FromInt(constant).ptr());
      return VarState{kI32, smi_const, 0};
    } else {
      LiftoffRegister reg = pinned->set(__ GetUnusedRegister(kGpReg, *pinned));
      LoadSmi(reg, constant);
      return VarState{kSmiKind, reg, 0};
    }
  }

  void TableInit(FullDecoder* decoder, const TableInitImmediate& imm,
                 const Value&, const Value&, const Value&) {
    FUZZER_HEAVY_INSTRUCTION;
    LiftoffRegList pinned;

    VarState table_index = LoadSmiConstant(imm.table.index, &pinned);
    VarState segment_index =
        LoadSmiConstant(imm.element_segment.index, &pinned);
    VarState extract_shared_data = LoadSmiConstant(0, &pinned);

    VarState size = __ PopVarState();
    if (size.is_reg()) pinned.set(size.reg());
    VarState src = __ PopVarState();
    if (src.is_reg()) pinned.set(src.reg());
    Register index_high_word = no_reg;
    VarState dst = PopIndexToVarState(&index_high_word, &pinned);

    // Trap if any bit in high word was set.
    CheckHighWordEmptyForTableType(decoder, index_high_word, &pinned);

    CallBuiltin(
        Builtin::kWasmTableInit,
        MakeSig::Params(kIntPtrKind, kI32, kI32, kSmiKind, kSmiKind, kSmiKind),
        {dst, src, size, table_index, segment_index, extract_shared_data},
        decoder->position());

    RegisterDebugSideTableEntry(decoder, DebugSideTableBuilder::kDidSpill);
  }

  void ElemDrop(FullDecoder* decoder, const IndexImmediate& imm) {
    LiftoffRegList pinned;
    Register element_segments =
        pinned.set(__ GetUnusedRegister(kGpReg, pinned)).gp();
    LOAD_TAGGED_PTR_INSTANCE_FIELD(element_segments, ElementSegments, pinned);

    LiftoffRegister seg_index =
        pinned.set(__ GetUnusedRegister(kGpReg, pinned));
    __ LoadConstant(
        seg_index,
        WasmValue(
            wasm::ObjectAccess::ElementOffsetInTaggedFixedArray(imm.index)));

    // Mark the segment as dropped by setting it to the empty fixed array.
    Register empty_fixed_array =
        pinned.set(__ GetUnusedRegister(kGpReg, pinned)).gp();
    __ LoadFullPointer(
        empty_fixed_array, kRootRegister,
        IsolateData::root_slot_offset(RootIndex::kEmptyFixedArray));

    __ StoreTaggedPointer(element_segments, seg_index.gp(), 0,
                          empty_fixed_array, pinned);
  }

  void TableCopy(FullDecoder* decoder, const TableCopyImmediate& imm,
                 const Value&, const Value&, const Value&) {
    FUZZER_HEAVY_INSTRUCTION;
    Register index_high_word = no_reg;
    LiftoffRegList pinned;

    VarState table_src_index = LoadSmiConstant(imm.table_src.index, &pinned);
    VarState table_dst_index = LoadSmiConstant(imm.table_dst.index, &pinned);
    VarState extract_shared_data = LoadSmiConstant(0, &pinned);

    VarState size = PopIndexToVarState(&index_high_word, &pinned);
    VarState src = PopIndexToVarState(&index_high_word, &pinned);
    VarState dst = PopIndexToVarState(&index_high_word, &pinned);

    // Trap if any bit in the combined high words was set.
    CheckHighWordEmptyForTableType(decoder, index_high_word, &pinned);

    CallBuiltin(
        Builtin::kWasmTableCopy,
        MakeSig::Params(kIntPtrKind, kIntPtrKind, kIntPtrKind, kSmiKind,
                        kSmiKind, kSmiKind),
        {dst, src, size, table_dst_index, table_src_index, extract_shared_data},
        decoder->position());

    RegisterDebugSideTableEntry(decoder, DebugSideTableBuilder::kDidSpill);
  }

  void TableGrow(FullDecoder* decoder, const TableIndexImmediate& imm,
                 const Value&, const Value&, Value* result) {
    FUZZER_HEAVY_INSTRUCTION;
    LiftoffRegList pinned;

    LiftoffRegister table_index_reg =
        pinned.set(__ GetUnusedRegister(kGpReg, pinned));
    LoadSmi(table_index_reg, imm.index);
    VarState table_index(kSmiKind, table_index_reg, 0);
    // If `delta` is, OOB table.grow should return -1.
    VarState delta = PopIndexToVarStateSaturating(&pinned);
    VarState value = __ PopVarState();
    VarState extract_shared_data(kI32, 0, 0);

    CallBuiltin(Builtin::kWasmTableGrow,
                MakeSig::Returns(kSmiKind).Params(kSmiKind, kIntPtrKind, kI32,
                                                  kRefNull),
                {table_index, delta, extract_shared_data, value},
                decoder->position());

    RegisterDebugSideTableEntry(decoder, DebugSideTableBuilder::kDidSpill);
    __ SmiToInt32(kReturnRegister0);
    if (imm.table->is_table64()) {
      LiftoffRegister result64 = LiftoffRegister(kReturnRegister0);
      if (kNeedI64RegPair) {
        result64 = LiftoffRegister::ForPair(kReturnRegister0, kReturnRegister1);
      }
      __ emit_type_conversion(kExprI64SConvertI32, result64,
                              LiftoffRegister(kReturnRegister0), nullptr);
      __ PushRegister(kI64, result64);
    } else {
      __ PushRegister(kI32, LiftoffRegister(kReturnRegister0));
    }
  }

  void TableSize(FullDecoder* decoder, const TableIndexImmediate& imm, Value*) {
    // We have to look up instance->tables[table_index].length.

    LiftoffRegList pinned;
    // Get the number of calls array address.
    Register tables = pinned.set(__ GetUnusedRegister(kGpReg, pinned)).gp();
    LOAD_TAGGED_PTR_INSTANCE_FIELD(tables, Tables, pinned);

    Register table = tables;
    __ LoadTaggedPointer(
        table, tables, no_reg,
        ObjectAccess::ElementOffsetInTaggedFixedArray(imm.index));

    int length_field_size = WasmTableObject::kCurrentLengthOffsetEnd -
                            WasmTableObject::kCurrentLengthOffset + 1;

    Register result = table;
    __ Load(LiftoffRegister(result), table, no_reg,
            wasm::ObjectAccess::ToTagged(WasmTableObject::kCurrentLengthOffset),
            length_field_size == 4 ? LoadType::kI32Load : LoadType::kI64Load);

    __ SmiUntag(result);

    if (imm.table->is_table64()) {
      LiftoffRegister result64 = LiftoffRegister(result);
      if (kNeedI64RegPair) {
        result64 = LiftoffRegister::ForPair(
            result, __ GetUnusedRegister(kGpReg, pinned).gp());
      }
      __ emit_type_conversion(kExprI64SConvertI32, result64,
                              LiftoffRegister(result), nullptr);
      __ PushRegister(kI64, result64);
    } else {
      __ PushRegister(kI32, LiftoffRegister(result));
    }
  }

  void TableFill(FullDecoder* decoder, const TableIndexImmediate& imm,
                 const Value&, const Value&, const Value&) {
    FUZZER_HEAVY_INSTRUCTION;
    Register high_words = no_reg;
    LiftoffRegList pinned;

    VarState table_index = LoadSmiConstant(imm.index, &pinned);
    VarState extract_shared_data{kI32, 0, 0};

    VarState count = PopIndexToVarState(&high_words, &pinned);
    VarState value = __ PopVarState();
    if (value.is_reg()) pinned.set(value.reg());
    VarState start = PopIndexToVarState(&high_words, &pinned);
    // Trap if any bit in the combined high words was set.
    CheckHighWordEmptyForTableType(decoder, high_words, &pinned);

    CallBuiltin(
        Builtin::kWasmTableFill,
        MakeSig::Params(kIntPtrKind, kIntPtrKind, kI32, kSmiKind, kRefNull),
        {start, count, extract_shared_data, table_index, value},
        decoder->position());

    RegisterDebugSideTableEntry(decoder, DebugSideTableBuilder::kDidSpill);
  }

  void StructNew(FullDecoder* decoder, const StructIndexImmediate& imm,
                 bool initial_values_on_stack) {
    LiftoffRegister rtt = RttCanon(imm.index, {});

    CallBuiltin(Builtin::kWasmAllocateStructWithRtt,
                MakeSig::Returns(kRef).Params(kRtt, kI32),
                {VarState{kRtt, rtt, 0},
                 VarState{kI32, WasmStruct::Size(imm.struct_type), 0}},
                decoder->position());

    LiftoffRegister obj(kReturnRegister0);
    LiftoffRegList pinned{obj};

    for (uint32_t i = imm.struct_type->field_count(); i > 0;) {
      i--;
      int offset = StructFieldOffset(imm.struct_type, i);
      ValueType field_type = imm.struct_type->field(i);
      LiftoffRegister value = pinned.set(
          initial_values_on_stack
              ? __ PopToRegister(pinned)
              : __ GetUnusedRegister(reg_class_for(field_type.kind()), pinned));
      if (!initial_values_on_stack) {
        if (!CheckSupportedType(decoder, field_type.kind(), "default value")) {
          return;
        }
        SetDefaultValue(value, field_type);
      }
      // Skipping the write barrier is safe as long as:
      // (1) {obj} is freshly allocated, and
      // (2) {obj} is in new-space (not pretenured).
      StoreObjectField(decoder, obj.gp(), no_reg, offset, value, false, pinned,
                       field_type.kind(), LiftoffAssembler::kSkipWriteBarrier);
      pinned.clear(value);
    }
    // If this assert fails then initialization of padding field might be
    // necessary.
    static_assert(Heap::kMinObjectSizeInTaggedWords == 2 &&
                      WasmStruct::kHeaderSize == 2 * kTaggedSize,
                  "empty struct might require initialization of padding field");
    __ PushRegister(kRef, obj);
  }

  void StructNew(FullDecoder* decoder, const StructIndexImmediate& imm,
                 const Value args[], Value* result) {
    StructNew(decoder, imm, true);
  }

  void StructNewDefault(FullDecoder* decoder, const StructIndexImmediate& imm,
                        Value* result) {
    StructNew(decoder, imm, false);
  }

  void StructGet(FullDecoder* decoder, const Value& struct_obj,
                 const FieldImmediate& field, bool is_signed, Value* result) {
    const StructType* struct_type = field.struct_imm.struct_type;
    ValueKind field_kind = struct_type->field(field.field_imm.index).kind();
    if (!CheckSupportedType(decoder, field_kind, "field load")) return;
    int offset = StructFieldOffset(struct_type, field.field_imm.index);
    LiftoffRegList pinned;
    LiftoffRegister obj = pinned.set(__ PopToRegister(pinned));

    auto [explicit_check, implicit_check] =
        null_checks_for_struct_op(struct_obj.type, field.field_imm.index);

    if (explicit_check) {
      MaybeEmitNullCheck(decoder, obj.gp(), pinned, struct_obj.type);
    }
    LiftoffRegister value =
        __ GetUnusedRegister(reg_class_for(field_kind), pinned);
    LoadObjectField(decoder, value, obj.gp(), no_reg, offset, field_kind,
                    is_signed, implicit_check, pinned);
    __ PushRegister(unpacked(field_kind), value);
  }

  void StructSet(FullDecoder* decoder, const Value& struct_obj,
                 const FieldImmediate& field, const Value& field_value) {
    const StructType* struct_type = field.struct_imm.struct_type;
    ValueKind field_kind = struct_type->field(field.field_imm.index).kind();
    int offset = StructFieldOffset(struct_type, field.field_imm.index);
    LiftoffRegList pinned;
    LiftoffRegister value = pinned.set(__ PopToRegister(pinned));
    LiftoffRegister obj = pinned.set(__ PopToRegister(pinned));

    auto [explicit_check, implicit_check] =
        null_checks_for_struct_op(struct_obj.type, field.field_imm.index);

    if (explicit_check) {
      MaybeEmitNullCheck(decoder, obj.gp(), pinned, struct_obj.type);
    }

    StoreObjectField(decoder, obj.gp(), no_reg, offset, value, implicit_check,
                     pinned, field_kind);
  }

  void ArrayNew(FullDecoder* decoder, const ArrayIndexImmediate& imm,
                bool initial_value_on_stack) {
    FUZZER_HEAVY_INSTRUCTION;
    // Max length check.
    {
      LiftoffRegister length =
          __ LoadToRegister(__ cache_state()->stack_state.end()[-1], {});
      Label* trap_label =
          AddOutOfLineTrap(decoder, Builtin::kThrowWasmTrapArrayTooLarge);
      FREEZE_STATE(trapping);
      __ emit_i32_cond_jumpi(kUnsignedGreaterThan, trap_label, length.gp(),
                             WasmArray::MaxLength(imm.array_type), trapping);
    }
    ValueType elem_type = imm.array_type->element_type();
    ValueKind elem_kind = elem_type.kind();
    int elem_size = value_kind_size(elem_kind);
    // Allocate the array.
    {
      LiftoffRegister rtt = RttCanon(imm.index, {});
      CallBuiltin(Builtin::kWasmAllocateArray_Uninitialized,
                  MakeSig::Returns(kRef).Params(kRtt, kI32, kI32),
                  {VarState{kRtt, rtt, 0},
                   __ cache_state()->stack_state.end()[-1],  // length
                   VarState{kI32, elem_size, 0}},
                  decoder->position());
    }

    LiftoffRegister obj(kReturnRegister0);
    LiftoffRegList pinned{obj};
    LiftoffRegister length = pinned.set(__ PopToModifiableRegister(pinned));
    LiftoffRegister value =
        pinned.set(__ GetUnusedRegister(reg_class_for(elem_kind), pinned));
    if (initial_value_on_stack) {
      __ PopToFixedRegister(value);
    } else {
      if (!CheckSupportedType(decoder, elem_kind, "default value")) return;
      SetDefaultValue(value, elem_type);
    }

    LiftoffRegister index = pinned.set(__ GetUnusedRegister(kGpReg, pinned));
    __ LoadConstant(index, WasmValue(int32_t{0}));

    // Initialize the array's elements.
    // Skipping the write barrier is safe as long as:
    // (1) {obj} is freshly allocated, and
    // (2) {obj} is in new-space (not pretenured).
    ArrayFillImpl(decoder, pinned, obj, index, value, length, elem_kind,
                  LiftoffAssembler::kSkipWriteBarrier);

    __ PushRegister(kRef, obj);
  }

  void ArrayNew(FullDecoder* decoder, const ArrayIndexImmediate& imm,
                const Value& length_value, const Value& initial_value,
                Value* result) {
    ArrayNew(decoder, imm, true);
  }

  void ArrayNewDefault(FullDecoder* decoder, const ArrayIndexImmediate& imm,
                       const Value& length, Value* result) {
    ArrayNew(decoder, imm, false);
  }

  void ArrayFill(FullDecoder* decoder, ArrayIndexImmediate& imm,
                 const Value& array, const Value& /* index */,
                 const Value& /* value */, const Value& /* length */) {
    FUZZER_HEAVY_INSTRUCTION;
    {
      // Null check.
      LiftoffRegList pinned;
      LiftoffRegister array_reg = pinned.set(__ PeekToRegister(3, pinned));
      if (null_check_strategy_ == compiler::NullCheckStrategy::kExplicit) {
        MaybeEmitNullCheck(decoder, array_reg.gp(), pinned, array.type);
      }

      // Bounds checks.
      Label* trap_label =
          AddOutOfLineTrap(decoder, Builtin::kThrowWasmTrapArrayOutOfBounds);
      LiftoffRegister array_length =
          pinned.set(__ GetUnusedRegister(kGpReg, pinned));
      bool implicit_null_check =
          array.type.is_nullable() &&
          null_check_strategy_ == compiler::NullCheckStrategy::kTrapHandler;
      LoadObjectField(decoder, array_length, array_reg.gp(), no_reg,
                      ObjectAccess::ToTagged(WasmArray::kLengthOffset), kI32,
                      false, implicit_null_check, pinned);
      LiftoffRegister index = pinned.set(__ PeekToRegister(2, pinned));
      LiftoffRegister length = pinned.set(__ PeekToRegister(0, pinned));
      LiftoffRegister index_plus_length =
          pinned.set(__ GetUnusedRegister(kGpReg, pinned));
      DCHECK(index_plus_length != array_length);
      __ emit_i32_add(index_plus_length.gp(), length.gp(), index.gp());
      FREEZE_STATE(frozen);
      __ emit_cond_jump(kUnsignedGreaterThan, trap_label, kI32,
                        index_plus_length.gp(), array_length.gp(), frozen);
      // Guard against overflow.
      __ emit_cond_jump(kUnsignedGreaterThan, trap_label, kI32, index.gp(),
                        index_plus_length.gp(), frozen);
    }

    LiftoffRegList pinned;
    LiftoffRegister length = pinned.set(__ PopToModifiableRegister(pinned));
    LiftoffRegister value = pinned.set(__ PopToRegister(pinned));
    LiftoffRegister index = pinned.set(__ PopToModifiableRegister(pinned));
    LiftoffRegister obj = pinned.set(__ PopToRegister(pinned));

    ArrayFillImpl(decoder, pinned, obj, index, value, length,
                  imm.array_type->element_type().kind(),
                  LiftoffAssembler::kNoSkipWriteBarrier);
  }

  void ArrayGet(FullDecoder* decoder, const Value& array_obj,
                const ArrayIndexImmediate& imm, const Value& index_val,
                bool is_signed, Value* result) {
    LiftoffRegList pinned;
    LiftoffRegister index = pinned.set(__ PopToModifiableRegister(pinned));
    LiftoffRegister array = pinned.set(__ PopToRegister(pinned));
    if (null_check_strategy_ == compiler::NullCheckStrategy::kExplicit) {
      MaybeEmitNullCheck(decoder, array.gp(), pinned, array_obj.type);
    }
    bool implicit_null_check =
        array_obj.type.is_nullable() &&
        null_check_strategy_ == compiler::NullCheckStrategy::kTrapHandler;
    BoundsCheckArray(decoder, implicit_null_check, array, index, pinned);
    ValueKind elem_kind = imm.array_type->element_type().kind();
    if (!CheckSupportedType(decoder, elem_kind, "array load")) return;
    int elem_size_shift = value_kind_size_log2(elem_kind);
    if (elem_size_shift != 0) {
      __ emit_i32_shli(index.gp(), index.gp(), elem_size_shift);
    }
    LiftoffRegister value =
        __ GetUnusedRegister(reg_class_for(elem_kind), pinned);
    LoadObjectField(decoder, value, array.gp(), index.gp(),
                    wasm::ObjectAccess::ToTagged(WasmArray::kHeaderSize),
                    elem_kind, is_signed, false, pinned);
    __ PushRegister(unpacked(elem_kind), value);
  }

  void ArraySet(FullDecoder* decoder, const Value& array_obj,
                const ArrayIndexImmediate& imm, const Value& index_val,
                const Value& value_val) {
    LiftoffRegList pinned;
    LiftoffRegister value = pinned.set(__ PopToRegister(pinned));
    DCHECK_EQ(reg_class_for(imm.array_type->element_type().kind()),
              value.reg_class());
    LiftoffRegister index = pinned.set(__ PopToModifiableRegister(pinned));
    LiftoffRegister array = pinned.set(__ PopToRegister(pinned));
    if (null_check_strategy_ == compiler::NullCheckStrategy::kExplicit) {
      MaybeEmitNullCheck(decoder, array.gp(), pinned, array_obj.type);
    }
    bool implicit_null_check =
        array_obj.type.is_nullable() &&
        null_check_strategy_ == compiler::NullCheckStrategy::kTrapHandler;
    BoundsCheckArray(decoder, implicit_null_check, array, index, pinned);
    ValueKind elem_kind = imm.array_type->element_type().kind();
    int elem_size_shift = value_kind_size_log2(elem_kind);
    if (elem_size_shift != 0) {
      __ emit_i32_shli(index.gp(), index.gp(), elem_size_shift);
    }
    StoreObjectField(decoder, array.gp(), index.gp(),
                     wasm::ObjectAccess::ToTagged(WasmArray::kHeaderSize),
                     value, false, pinned, elem_kind);
  }

  void ArrayLen(FullDecoder* decoder, const Value& array_obj, Value* result) {
    LiftoffRegList pinned;
    LiftoffRegister obj = pinned.set(__ PopToRegister(pinned));
    if (null_check_strategy_ == compiler::NullCheckStrategy::kExplicit) {
      MaybeEmitNullCheck(decoder, obj.gp(), pinned, array_obj.type);
    }
    LiftoffRegister len = __ GetUnusedRegister(kGpReg, pinned);
    int kLengthOffset = wasm::ObjectAccess::ToTagged(WasmArray::kLengthOffset);
    bool implicit_null_check =
        array_obj.type.is_nullable() &&
        null_check_strategy_ == compiler::NullCheckStrategy::kTrapHandler;
    LoadObjectField(decoder, len, obj.gp(), no_reg, kLengthOffset, kI32,
                    false /* is_signed */, implicit_null_check, pinned);
    __ PushRegister(kI32, len);
  }

  void ArrayCopy(FullDecoder* decoder, const Value& dst, const Value& dst_index,
                 const Value& src, const Value& src_index,
                 const ArrayIndexImmediate& src_imm, const Value& length) {
    // TODO(14034): Unify implementation with TF: Implement this with
    // GenerateCCallWithStackBuffer. Remove runtime function and builtin in
    // wasm.tq.
    CallBuiltin(Builtin::kWasmArrayCopy,
                MakeSig::Params(kI32, kI32, kI32, kRefNull, kRefNull),
                // Builtin parameter order:
                // [dst_index, src_index, length, dst, src].
                {__ cache_state()->stack_state.end()[-4],
                 __ cache_state()->stack_state.end()[-2],
                 __ cache_state()->stack_state.end()[-1],
                 __ cache_state()->stack_state.end()[-5],
                 __ cache_state()->stack_state.end()[-3]},
                decoder->position());
    __ DropValues(5);
  }

  void ArrayNewFixed(FullDecoder* decoder, const ArrayIndexImmediate& array_imm,
                     const IndexImmediate& length_imm,
                     const Value* /* elements */, Value* /* result */) {
    LiftoffRegister rtt = RttCanon(array_imm.index, {});
    ValueKind elem_kind = array_imm.array_type->element_type().kind();
    int32_t elem_count = length_imm.index;
    // Allocate the array.
    CallBuiltin(Builtin::kWasmAllocateArray_Uninitialized,
                MakeSig::Returns(kRef).Params(kRtt, kI32, kI32),
                {VarState{kRtt, rtt, 0}, VarState{kI32, elem_count, 0},
                 VarState{kI32, value_kind_size(elem_kind), 0}},
                decoder->position());

    // Initialize the array with stack arguments.
    LiftoffRegister array(kReturnRegister0);
    if (!CheckSupportedType(decoder, elem_kind, "array.new_fixed")) return;
    for (int i = elem_count - 1; i >= 0; i--) {
      LiftoffRegList pinned{array};
      LiftoffRegister element = pinned.set(__ PopToRegister(pinned));
      int offset =
          WasmArray::kHeaderSize + (i << value_kind_size_log2(elem_kind));
      // Skipping the write barrier is safe as long as:
      // (1) {array} is freshly allocated, and
      // (2) {array} is in new-space (not pretenured).
      StoreObjectField(decoder, array.gp(), no_reg,
                       wasm::ObjectAccess::ToTagged(offset), element, false,
                       pinned, elem_kind, LiftoffAssembler::kSkipWriteBarrier);
    }

    // Push the array onto the stack.
    __ PushRegister(kRef, array);
  }

  void ArrayNewSegment(FullDecoder* decoder,
                       const ArrayIndexImmediate& array_imm,
                       const IndexImmediate& segment_imm,
                       const Value& /* offset */, const Value& /* length */,
                       Value* /* result */) {
    FUZZER_HEAVY_INSTRUCTION;
    LiftoffRegList pinned;

    LiftoffRegister rtt = pinned.set(RttCanon(array_imm.index, pinned));
```