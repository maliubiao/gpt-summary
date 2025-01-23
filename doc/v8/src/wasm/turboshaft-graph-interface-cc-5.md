Response:
The user wants a summary of the functionality of the provided C++ code snippet.

Here's a breakdown of how to approach this:

1. **Identify the core purpose:** The code seems to handle various WebAssembly (Wasm) atomic and memory-related operations within the Turboshaft compiler in V8.

2. **Categorize the functions:** Group the functions by the type of operation they perform (e.g., atomic operations, memory access, table manipulation, struct/array operations).

3. **Describe each category:** For each category, briefly explain what the functions within it do.

4. **Check for Torque:** The filename ends with `.cc`, not `.tq`, so it's not Torque.

5. **Check for JavaScript relevance:**  Wasm interacts closely with JavaScript. Think about which Wasm features these functions support and how they might be used from JavaScript.

6. **Provide JavaScript examples:** If a connection to JavaScript is found, create simple examples to illustrate the concept.

7. **Look for logic and provide examples:**  For functions with clear logic (like bounds checking), provide hypothetical inputs and outputs.

8. **Identify common programming errors:** Think about potential errors users might make when using the Wasm features these functions implement.

9. **Address the "part X of 12" instruction:** Acknowledge this and tailor the summary accordingly.

**Detailed breakdown of the code:**

* **Atomic Operations:** The `AtomicNotify`, `AtomicWait`, and `AtomicOp` functions clearly deal with Wasm's atomic instructions. They involve memory access with synchronization primitives.
* **Memory Operations:** `MemoryInit`, `MemoryCopy`, `MemoryFill`, and `DataDrop` manage Wasm linear memory.
* **Table Operations:**  `TableGet`, `TableSet`, `TableInit`, `TableCopy`, `TableGrow`, `TableFill`, `TableSize`, and `LoadTable` are responsible for handling Wasm tables (dynamic arrays of references).
* **Struct and Array Operations:** `StructNew`, `StructNewDefault`, `StructGet`, `StructSet`, `ArrayNew`, `ArrayNewDefault`, `ArrayGet`, `ArraySet`, `ArrayLen`, and `ArrayCopy` handle Wasm's reference types: structs and arrays.
* **Bounds Checking:**  Functions like `BoundsCheckMem` and `BoundsCheckArray` are crucial for memory safety.

**Pre-computation/Analysis:**

* The code uses a lot of `CallC` and `CallBuiltinThroughJumptable`, indicating calls to runtime functions or built-in functions within V8.
* It uses Turboshaft-specific constructs like `OpIndex`, `V<>`, and `__`.
* The code includes checks for shared memory and handles different memory access kinds (normal, protected).
* There's endianness handling for atomic loads and stores.

**Constraint Checklist & Confidence Score:**

1. List functionalities? Yes.
2. Check for `.tq`? Yes.
3. Javascript relation? Yes.
4. Javascript example? Yes.
5. Logic inference? Yes.
6. Input/output? Yes.
7. Common errors? Yes.
8. Part of series? Yes.
9. Summarize functionality? Yes.

Confidence Score: 5/5

**Overall thought process:** The key is to understand the context (Wasm compilation in V8), identify the functional units, and then explain what each unit does in a clear and concise way, keeping the user's request in mind. The "part X of 12" instruction suggests a higher-level overview might be more appropriate than diving into very technical details of each function.
这是 V8 源代码文件 `v8/src/wasm/turboshaft-graph-interface.cc` 的一部分，它在 V8 的 Turboshaft 编译器中扮演着关键角色，用于将 WebAssembly 指令转换为 Turboshaft 图形表示。这个图形表示是后续优化和代码生成的基础。

以下是该代码片段的主要功能归纳：

**核心功能：实现 WebAssembly 的原子操作、内存操作和引用类型操作**

具体来说，这段代码负责处理以下几类 WebAssembly 指令：

1. **原子操作 (Atomic Operations):**
   - `AtomicNotify`: 实现 `atomic.notify` 指令，用于唤醒等待在共享内存特定地址上的线程。
   - `AtomicWait`: 实现 `atomic.wait` 指令，允许线程在共享内存的特定地址上等待特定值的出现。
   - `AtomicOp`:  实现各种原子读-修改-写操作，例如 `atomic.add`, `atomic.sub`, `atomic.load`, `atomic.store` 等，确保在多线程环境下的数据一致性。
   - `AtomicFence`: 实现 `atomic.fence` 指令，用于强制内存顺序，防止指令重排。

2. **内存操作 (Memory Operations):**
   - `MemoryInit`: 实现 `memory.init` 指令，从数据段初始化线性内存的指定区域。
   - `MemoryCopy`: 实现 `memory.copy` 指令，将线性内存的一部分复制到另一部分。
   - `MemoryFill`: 实现 `memory.fill` 指令，用指定的值填充线性内存的指定区域。
   - `DataDrop`: 实现 `data.drop` 指令，释放不再需要的数据段。

3. **表操作 (Table Operations):**
   - `TableGet`: 实现 `table.get` 指令，获取表中指定索引的元素。
   - `TableSet`: 实现 `table.set` 指令，设置表中指定索引的元素。
   - `TableInit`: 实现 `table.init` 指令，从元素段初始化表的指定区域。
   - `TableCopy`: 实现 `table.copy` 指令，将表的一部分复制到另一部分。
   - `TableGrow`: 实现 `table.grow` 指令，增加表的大小。
   - `TableFill`: 实现 `table.fill` 指令，用指定的值填充表的指定区域。
   - `TableSize`: 实现 `table.size` 指令，获取当前表的大小。
   - `LoadTable`:  辅助函数，用于加载 Table 对象。
   - `ElemDrop`: 实现 `elem.drop` 指令，释放不再需要的元素段。

4. **结构体操作 (Struct Operations):**
   - `StructNew`: 实现 `struct.new` 指令，创建一个新的结构体实例。
   - `StructNewDefault`: 实现 `struct.new_default` 指令，创建一个所有字段都使用默认值的结构体实例。
   - `StructGet`: 实现 `struct.get` 指令，获取结构体中指定字段的值。
   - `StructSet`: 实现 `struct.set` 指令，设置结构体中指定字段的值。

5. **数组操作 (Array Operations):**
   - `ArrayNew`: 实现 `array.new` 指令，创建一个指定长度和初始值的数组。
   - `ArrayNewDefault`: 实现 `array.new_default` 指令，创建一个指定长度和默认初始值的数组。
   - `ArrayGet`: 实现 `array.get` 指令，获取数组中指定索引的元素。
   - `ArraySet`: 实现 `array.set` 指令，设置数组中指定索引的元素。
   - `ArrayLen`: 实现 `array.len` 指令，获取数组的长度。
   - `ArrayCopy`: 实现 `array.copy` 指令，将数组的一部分复制到另一个数组。

**关于代码的特性：**

* **Turboshaft 图形接口:**  代码中的函数通常会生成 Turboshaft 图形节点 (`OpIndex`)，这些节点代表了计算操作。
* **Bounds Check:** 代码中可以看到对内存访问和表访问进行边界检查的逻辑 (`BoundsCheckMem`, `TableAddressToUintPtrOrOOBTrap`, `BoundsCheckArray`)，以确保安全性。
* **原子性与同步:**  针对原子操作，代码会生成相应的原子操作节点，确保在多线程环境下的正确性。
* **类型信息:** 代码中使用了大量的类型信息 (`MachineType`, `MemoryRepresentation`, `ValueType`)，这对于生成高效的代码至关重要。
* **与 Builtin 和 C 函数的交互:**  许多操作是通过调用 V8 的内置函数 (`CallBuiltinThroughJumptable`) 或 C++ 运行时函数 (`CallC`) 来实现的。

**它不是 Torque 源代码**

该文件的扩展名是 `.cc`，表明它是 C++ 源代码。如果以 `.tq` 结尾，则会是 V8 的 Torque 源代码。

**与 JavaScript 的关系 (JavaScript Examples)**

这段代码实现的功能直接对应于 WebAssembly 模块中使用的指令。当 JavaScript 代码加载并执行 WebAssembly 模块时，这些指令会被 V8 的 Turboshaft 编译器处理，并最终执行。

以下是一些 JavaScript 示例，展示了这些 Wasm 功能的使用：

```javascript
// 原子操作
const sab = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT * 2);
const i32a = new Int32Array(sab);
Atomics.store(i32a, 0, 123);
Atomics.add(i32a, 0, 456);
console.log(Atomics.load(i32a, 0)); // 输出 579
Atomics.wait(i32a, 1, 0); // 等待 i32a[1] 的值变为非 0

// 内存操作 (需要启用 Wasm 的内存操作提案)
const memory = new WebAssembly.Memory({ initial: 1, maximum: 1 });
const buffer = new Uint8Array(memory.buffer);
// (假设 Wasm 模块有 memory.init 指令)

// 表操作
const table = new WebAssembly.Table({ initial: 2, element: 'anyfunc' });
table.set(0, () => console.log("Hello from table!"));
table.get(0)();

// 结构体和数组操作 (需要启用引用类型提案)
// (假设 Wasm 模块定义了结构体和数组类型)
// const myStruct = new WebAssembly.Instance(module).exports.create_struct();
// myStruct.field1 = 10;
// console.log(myStruct.field1);
```

**代码逻辑推理 (假设输入与输出)**

以 `AtomicAdd` 操作为例：

**假设输入：**

* `imm.memory`: 指向共享内存的描述信息。
* `index`: 要进行原子操作的内存地址的偏移量。
* `value`: 要加上的值。
* `result`: 用于存储原子加法结果的 `Value` 对象。

**处理过程：**

1. **边界检查:** `BoundsCheckMem` 函数会检查 `index + imm.offset` 是否在内存边界内。
2. **计算有效地址:** 将转换后的索引和偏移量相加，得到实际的内存地址。
3. **生成原子加法操作节点:** 使用 `__ AtomicRMW` 函数生成一个表示原子加法操作的 Turboshaft 图形节点。该节点包含了内存地址、要加上的值、操作类型（`BinOp::kAdd`）以及内存表示等信息。
4. **设置结果:** 将生成的图形节点赋值给 `result->op`。

**假设输出：**

`result->op` 将包含一个表示原子加法操作的 `OpIndex`，这个 `OpIndex` 指向 Turboshaft 图形中的一个节点，该节点在后续的编译阶段会被转化为机器码。

**用户常见的编程错误 (举例说明)**

1. **原子操作使用不当:**
   ```javascript
   // 错误示例：没有使用原子操作进行递增
   let counter = 0;
   function increment() {
     counter++; // 在多线程环境下可能出现数据竞争
   }

   // 正确示例：使用原子操作
   const sab = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT);
   const i32a = new Int32Array(sab);
   function incrementAtomic() {
     Atomics.add(i32a, 0, 1);
   }
   ```
   **解释:** 在多线程环境下，直接使用 `counter++` 可能导致多个线程同时读取和修改 `counter` 的值，从而产生数据竞争。使用 `Atomics.add` 可以确保操作的原子性。

2. **内存访问越界:**
   ```javascript
   const memory = new WebAssembly.Memory({ initial: 1 });
   const buffer = new Uint8Array(memory.buffer);
   buffer[1000000] = 10; // 错误：可能超出内存边界
   ```
   **解释:** 尝试访问超出 WebAssembly 线性内存边界的地址会导致运行时错误。

3. **表操作索引越界:**
   ```javascript
   const table = new WebAssembly.Table({ initial: 2, element: 'anyfunc' });
   table.get(5); // 错误：索引 5 超出表的大小
   ```
   **解释:** 访问超出表大小的索引会导致运行时错误。

4. **类型不匹配的结构体/数组操作:**
   ```javascript
   // 假设 Wasm 定义了一个接受 i32 的结构体
   // const myStruct = new WebAssembly.Instance(module).exports.create_struct();
   // myStruct.field1 = "hello"; // 错误：类型不匹配
   ```
   **解释:**  尝试将错误类型的值赋给结构体或数组的字段会导致类型错误。

**功能归纳 (作为第 6 部分，共 12 部分)**

作为 Turboshaft 编译器实现 WebAssembly 功能的一部分，`v8/src/wasm/turboshaft-graph-interface.cc` 的这一部分主要负责将 WebAssembly 的**原子操作、内存操作以及引用类型（结构体和数组）操作**转换为 Turboshaft 图形表示。它是将高级 Wasm 指令转化为底层可执行代码的关键步骤，确保了 Wasm 代码在 V8 中的正确和高效执行。考虑到这是 12 个部分中的第 6 部分，可以推测前面的部分可能涉及了更基础的 Wasm 指令处理和控制流，而后面的部分可能会涉及更高级的优化、代码生成或其他特定的 Wasm 特性。

### 提示词
```
这是目录为v8/src/wasm/turboshaft-graph-interface.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/turboshaft-graph-interface.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第6部分，共12部分，请归纳一下它的功能
```

### 源代码
```cpp
compiler::BoundsCheckResult bounds_check_result;
    std::tie(converted_index, bounds_check_result) = BoundsCheckMem(
        imm.memory, MemoryRepresentation::Int32(), index, imm.offset,
        compiler::EnforceBoundsCheck::kNeedsBoundsCheck,
        compiler::AlignmentCheck::kYes);

    OpIndex effective_offset = __ WordPtrAdd(converted_index, imm.offset);
    OpIndex addr = __ WordPtrAdd(MemStart(imm.mem_index), effective_offset);

    auto sig = FixedSizeSignature<MachineType>::Returns(MachineType::Int32())
                   .Params(MachineType::Pointer(), MachineType::Uint32());
    result->op = CallC(&sig, ExternalReference::wasm_atomic_notify(),
                       {addr, num_waiters_to_wake});
  }

  void AtomicWait(FullDecoder* decoder, WasmOpcode opcode,
                  const MemoryAccessImmediate& imm, OpIndex index,
                  OpIndex expected, V<Word64> timeout, Value* result) {
    constexpr StubCallMode kStubMode = StubCallMode::kCallWasmRuntimeStub;
    V<WordPtr> converted_index;
    compiler::BoundsCheckResult bounds_check_result;
    std::tie(converted_index, bounds_check_result) = BoundsCheckMem(
        imm.memory,
        opcode == kExprI32AtomicWait ? MemoryRepresentation::Int32()
                                     : MemoryRepresentation::Int64(),
        index, imm.offset, compiler::EnforceBoundsCheck::kNeedsBoundsCheck,
        compiler::AlignmentCheck::kYes);

    OpIndex effective_offset = __ WordPtrAdd(converted_index, imm.offset);
    V<BigInt> bigint_timeout = BuildChangeInt64ToBigInt(timeout, kStubMode);

    if (opcode == kExprI32AtomicWait) {
      result->op =
          CallBuiltinThroughJumptable<BuiltinCallDescriptor::WasmI32AtomicWait>(
              decoder, {__ Word32Constant(imm.memory->index), effective_offset,
                        expected, bigint_timeout});
      return;
    }
    DCHECK_EQ(opcode, kExprI64AtomicWait);
    V<BigInt> bigint_expected = BuildChangeInt64ToBigInt(expected, kStubMode);
    result->op =
        CallBuiltinThroughJumptable<BuiltinCallDescriptor::WasmI64AtomicWait>(
            decoder, {__ Word32Constant(imm.memory->index), effective_offset,
                      bigint_expected, bigint_timeout});
  }

  void AtomicOp(FullDecoder* decoder, WasmOpcode opcode, const Value args[],
                const size_t argc, const MemoryAccessImmediate& imm,
                Value* result) {
    if (opcode == WasmOpcode::kExprAtomicNotify) {
      return AtomicNotify(decoder, imm, args[0].op, args[1].op, result);
    }
    if (opcode == WasmOpcode::kExprI32AtomicWait ||
        opcode == WasmOpcode::kExprI64AtomicWait) {
      return AtomicWait(decoder, opcode, imm, args[0].op, args[1].op,
                        args[2].op, result);
    }
    using Binop = compiler::turboshaft::AtomicRMWOp::BinOp;
    enum OpType { kBinop, kLoad, kStore };
    struct AtomicOpInfo {
      OpType op_type;
      // Initialize with a default value, to allow constexpr constructors.
      Binop bin_op = Binop::kAdd;
      RegisterRepresentation in_out_rep;
      MemoryRepresentation memory_rep;

      constexpr AtomicOpInfo(Binop bin_op, RegisterRepresentation in_out_rep,
                             MemoryRepresentation memory_rep)
          : op_type(kBinop),
            bin_op(bin_op),
            in_out_rep(in_out_rep),
            memory_rep(memory_rep) {}

      constexpr AtomicOpInfo(OpType op_type, RegisterRepresentation in_out_rep,
                             MemoryRepresentation memory_rep)
          : op_type(op_type), in_out_rep(in_out_rep), memory_rep(memory_rep) {}

      static constexpr AtomicOpInfo Get(wasm::WasmOpcode opcode) {
        switch (opcode) {
#define CASE_BINOP(OPCODE, BINOP, RESULT, INPUT)                           \
  case WasmOpcode::kExpr##OPCODE:                                          \
    return AtomicOpInfo(Binop::k##BINOP, RegisterRepresentation::RESULT(), \
                        MemoryRepresentation::INPUT());
#define RMW_OPERATION(V)                                          \
  V(I32AtomicAdd, Add, Word32, Uint32)                            \
  V(I32AtomicAdd8U, Add, Word32, Uint8)                           \
  V(I32AtomicAdd16U, Add, Word32, Uint16)                         \
  V(I32AtomicSub, Sub, Word32, Uint32)                            \
  V(I32AtomicSub8U, Sub, Word32, Uint8)                           \
  V(I32AtomicSub16U, Sub, Word32, Uint16)                         \
  V(I32AtomicAnd, And, Word32, Uint32)                            \
  V(I32AtomicAnd8U, And, Word32, Uint8)                           \
  V(I32AtomicAnd16U, And, Word32, Uint16)                         \
  V(I32AtomicOr, Or, Word32, Uint32)                              \
  V(I32AtomicOr8U, Or, Word32, Uint8)                             \
  V(I32AtomicOr16U, Or, Word32, Uint16)                           \
  V(I32AtomicXor, Xor, Word32, Uint32)                            \
  V(I32AtomicXor8U, Xor, Word32, Uint8)                           \
  V(I32AtomicXor16U, Xor, Word32, Uint16)                         \
  V(I32AtomicExchange, Exchange, Word32, Uint32)                  \
  V(I32AtomicExchange8U, Exchange, Word32, Uint8)                 \
  V(I32AtomicExchange16U, Exchange, Word32, Uint16)               \
  V(I32AtomicCompareExchange, CompareExchange, Word32, Uint32)    \
  V(I32AtomicCompareExchange8U, CompareExchange, Word32, Uint8)   \
  V(I32AtomicCompareExchange16U, CompareExchange, Word32, Uint16) \
  V(I64AtomicAdd, Add, Word64, Uint64)                            \
  V(I64AtomicAdd8U, Add, Word64, Uint8)                           \
  V(I64AtomicAdd16U, Add, Word64, Uint16)                         \
  V(I64AtomicAdd32U, Add, Word64, Uint32)                         \
  V(I64AtomicSub, Sub, Word64, Uint64)                            \
  V(I64AtomicSub8U, Sub, Word64, Uint8)                           \
  V(I64AtomicSub16U, Sub, Word64, Uint16)                         \
  V(I64AtomicSub32U, Sub, Word64, Uint32)                         \
  V(I64AtomicAnd, And, Word64, Uint64)                            \
  V(I64AtomicAnd8U, And, Word64, Uint8)                           \
  V(I64AtomicAnd16U, And, Word64, Uint16)                         \
  V(I64AtomicAnd32U, And, Word64, Uint32)                         \
  V(I64AtomicOr, Or, Word64, Uint64)                              \
  V(I64AtomicOr8U, Or, Word64, Uint8)                             \
  V(I64AtomicOr16U, Or, Word64, Uint16)                           \
  V(I64AtomicOr32U, Or, Word64, Uint32)                           \
  V(I64AtomicXor, Xor, Word64, Uint64)                            \
  V(I64AtomicXor8U, Xor, Word64, Uint8)                           \
  V(I64AtomicXor16U, Xor, Word64, Uint16)                         \
  V(I64AtomicXor32U, Xor, Word64, Uint32)                         \
  V(I64AtomicExchange, Exchange, Word64, Uint64)                  \
  V(I64AtomicExchange8U, Exchange, Word64, Uint8)                 \
  V(I64AtomicExchange16U, Exchange, Word64, Uint16)               \
  V(I64AtomicExchange32U, Exchange, Word64, Uint32)               \
  V(I64AtomicCompareExchange, CompareExchange, Word64, Uint64)    \
  V(I64AtomicCompareExchange8U, CompareExchange, Word64, Uint8)   \
  V(I64AtomicCompareExchange16U, CompareExchange, Word64, Uint16) \
  V(I64AtomicCompareExchange32U, CompareExchange, Word64, Uint32)

          RMW_OPERATION(CASE_BINOP)
#undef RMW_OPERATION
#undef CASE
#define CASE_LOAD(OPCODE, RESULT, INPUT)                         \
  case WasmOpcode::kExpr##OPCODE:                                \
    return AtomicOpInfo(kLoad, RegisterRepresentation::RESULT(), \
                        MemoryRepresentation::INPUT());
#define LOAD_OPERATION(V)             \
  V(I32AtomicLoad, Word32, Uint32)    \
  V(I32AtomicLoad16U, Word32, Uint16) \
  V(I32AtomicLoad8U, Word32, Uint8)   \
  V(I64AtomicLoad, Word64, Uint64)    \
  V(I64AtomicLoad32U, Word64, Uint32) \
  V(I64AtomicLoad16U, Word64, Uint16) \
  V(I64AtomicLoad8U, Word64, Uint8)
          LOAD_OPERATION(CASE_LOAD)
#undef LOAD_OPERATION
#undef CASE_LOAD
#define CASE_STORE(OPCODE, INPUT, OUTPUT)                        \
  case WasmOpcode::kExpr##OPCODE:                                \
    return AtomicOpInfo(kStore, RegisterRepresentation::INPUT(), \
                        MemoryRepresentation::OUTPUT());
#define STORE_OPERATION(V)             \
  V(I32AtomicStore, Word32, Uint32)    \
  V(I32AtomicStore16U, Word32, Uint16) \
  V(I32AtomicStore8U, Word32, Uint8)   \
  V(I64AtomicStore, Word64, Uint64)    \
  V(I64AtomicStore32U, Word64, Uint32) \
  V(I64AtomicStore16U, Word64, Uint16) \
  V(I64AtomicStore8U, Word64, Uint8)
          STORE_OPERATION(CASE_STORE)
#undef STORE_OPERATION_OPERATION
#undef CASE_STORE
          default:
            UNREACHABLE();
        }
      }
    };

    AtomicOpInfo info = AtomicOpInfo::Get(opcode);
    V<WordPtr> index;
    compiler::BoundsCheckResult bounds_check_result;
    std::tie(index, bounds_check_result) =
        BoundsCheckMem(imm.memory, info.memory_rep, args[0].op, imm.offset,
                       compiler::EnforceBoundsCheck::kCanOmitBoundsCheck,
                       compiler::AlignmentCheck::kYes);
    // MemoryAccessKind::kUnaligned is impossible due to explicit aligment
    // check.
    MemoryAccessKind access_kind =
        bounds_check_result == compiler::BoundsCheckResult::kTrapHandler
            ? MemoryAccessKind::kProtectedByTrapHandler
            : MemoryAccessKind::kNormal;

    if (info.op_type == kBinop) {
      if (info.bin_op == Binop::kCompareExchange) {
        result->op = __ AtomicCompareExchange(
            MemBuffer(imm.memory->index, imm.offset), index, args[1].op,
            args[2].op, info.in_out_rep, info.memory_rep, access_kind);
        return;
      }
      result->op = __ AtomicRMW(MemBuffer(imm.memory->index, imm.offset), index,
                                args[1].op, info.bin_op, info.in_out_rep,
                                info.memory_rep, access_kind);
      return;
    }
    if (info.op_type == kStore) {
      OpIndex value = args[1].op;
      if (info.in_out_rep == RegisterRepresentation::Word64() &&
          info.memory_rep != MemoryRepresentation::Uint64()) {
        value = __ TruncateWord64ToWord32(value);
      }
#ifdef V8_TARGET_BIG_ENDIAN
      // Reverse the value bytes before storing.
      DCHECK(info.in_out_rep == RegisterRepresentation::Word32() ||
             info.in_out_rep == RegisterRepresentation::Word64());
      wasm::ValueType wasm_type =
          info.in_out_rep == RegisterRepresentation::Word32() ? wasm::kWasmI32
                                                              : wasm::kWasmI64;
      value = BuildChangeEndiannessStore(
          value, info.memory_rep.ToMachineType().representation(), wasm_type);
#endif
      __ Store(MemBuffer(imm.memory->index, imm.offset), index, value,
               access_kind == MemoryAccessKind::kProtectedByTrapHandler
                   ? LoadOp::Kind::Protected().Atomic()
                   : LoadOp::Kind::RawAligned().Atomic(),
               info.memory_rep, compiler::kNoWriteBarrier);
      return;
    }
    DCHECK_EQ(info.op_type, kLoad);
    RegisterRepresentation loaded_value_rep = info.in_out_rep;
#if V8_TARGET_BIG_ENDIAN
    // Do not sign-extend / zero-extend the value to 64 bits as the bytes need
    // to be reversed first to keep little-endian load / store semantics. Still
    // extend for 1 byte loads as it doesn't require reversing any bytes.
    bool needs_zero_extension_64 = false;
    if (info.in_out_rep == RegisterRepresentation::Word64() &&
        info.memory_rep.SizeInBytes() < 8 &&
        info.memory_rep.SizeInBytes() != 1) {
      needs_zero_extension_64 = true;
      loaded_value_rep = RegisterRepresentation::Word32();
    }
#endif
    result->op =
        __ Load(MemBuffer(imm.memory->index, imm.offset), index,
                access_kind == MemoryAccessKind::kProtectedByTrapHandler
                    ? LoadOp::Kind::Protected().Atomic()
                    : LoadOp::Kind::RawAligned().Atomic(),
                info.memory_rep, loaded_value_rep);

#ifdef V8_TARGET_BIG_ENDIAN
    // Reverse the value bytes after load.
    DCHECK(info.in_out_rep == RegisterRepresentation::Word32() ||
           info.in_out_rep == RegisterRepresentation::Word64());
    wasm::ValueType wasm_type =
        info.in_out_rep == RegisterRepresentation::Word32() ? wasm::kWasmI32
                                                            : wasm::kWasmI64;
    result->op = BuildChangeEndiannessLoad(
        result->op, info.memory_rep.ToMachineType(), wasm_type);

    if (needs_zero_extension_64) {
      result->op = __ ChangeUint32ToUint64(result->op);
    }
#endif
  }

  void AtomicFence(FullDecoder* decoder) {
    __ MemoryBarrier(AtomicMemoryOrder::kSeqCst);
  }

  void MemoryInit(FullDecoder* decoder, const MemoryInitImmediate& imm,
                  const Value& dst, const Value& src, const Value& size) {
    V<WordPtr> dst_uintptr = MemoryAddressToUintPtrOrOOBTrap(
        imm.memory.memory->address_type, dst.op);
    DCHECK_EQ(size.type, kWasmI32);
    auto sig = FixedSizeSignature<MachineType>::Returns(MachineType::Int32())
                   .Params(MachineType::Pointer(), MachineType::Uint32(),
                           MachineType::UintPtr(), MachineType::Uint32(),
                           MachineType::Uint32(), MachineType::Uint32());
    // TODO(14616): Fix sharedness.
    V<Word32> result =
        CallC(&sig, ExternalReference::wasm_memory_init(),
              {__ BitcastHeapObjectToWordPtr(trusted_instance_data(false)),
               __ Word32Constant(imm.memory.index), dst_uintptr, src.op,
               __ Word32Constant(imm.data_segment.index), size.op});
    __ TrapIfNot(result, TrapId::kTrapMemOutOfBounds);
  }

  void MemoryCopy(FullDecoder* decoder, const MemoryCopyImmediate& imm,
                  const Value& dst, const Value& src, const Value& size) {
    const WasmMemory* dst_memory = imm.memory_dst.memory;
    const WasmMemory* src_memory = imm.memory_src.memory;
    V<WordPtr> dst_uintptr =
        MemoryAddressToUintPtrOrOOBTrap(dst_memory->address_type, dst.op);
    V<WordPtr> src_uintptr =
        MemoryAddressToUintPtrOrOOBTrap(src_memory->address_type, src.op);
    AddressType min_address_type =
        dst_memory->is_memory64() && src_memory->is_memory64()
            ? AddressType::kI64
            : AddressType::kI32;
    V<WordPtr> size_uintptr =
        MemoryAddressToUintPtrOrOOBTrap(min_address_type, size.op);
    auto sig = FixedSizeSignature<MachineType>::Returns(MachineType::Int32())
                   .Params(MachineType::Pointer(), MachineType::Uint32(),
                           MachineType::Uint32(), MachineType::UintPtr(),
                           MachineType::UintPtr(), MachineType::UintPtr());
    // TODO(14616): Fix sharedness.
    V<Word32> result =
        CallC(&sig, ExternalReference::wasm_memory_copy(),
              {__ BitcastHeapObjectToWordPtr(trusted_instance_data(false)),
               __ Word32Constant(imm.memory_dst.index),
               __ Word32Constant(imm.memory_src.index), dst_uintptr,
               src_uintptr, size_uintptr});
    __ TrapIfNot(result, TrapId::kTrapMemOutOfBounds);
  }

  void MemoryFill(FullDecoder* decoder, const MemoryIndexImmediate& imm,
                  const Value& dst, const Value& value, const Value& size) {
    AddressType address_type = imm.memory->address_type;
    V<WordPtr> dst_uintptr =
        MemoryAddressToUintPtrOrOOBTrap(address_type, dst.op);
    V<WordPtr> size_uintptr =
        MemoryAddressToUintPtrOrOOBTrap(address_type, size.op);
    auto sig = FixedSizeSignature<MachineType>::Returns(MachineType::Int32())
                   .Params(MachineType::Pointer(), MachineType::Uint32(),
                           MachineType::UintPtr(), MachineType::Uint8(),
                           MachineType::UintPtr());
    // TODO(14616): Fix sharedness.
    V<Word32> result = CallC(
        &sig, ExternalReference::wasm_memory_fill(),
        {__ BitcastHeapObjectToWordPtr(trusted_instance_data(false)),
         __ Word32Constant(imm.index), dst_uintptr, value.op, size_uintptr});

    __ TrapIfNot(result, TrapId::kTrapMemOutOfBounds);
  }

  void DataDrop(FullDecoder* decoder, const IndexImmediate& imm) {
    // TODO(14616): Data segments aren't available during streaming compilation.
    // Discussion: github.com/WebAssembly/shared-everything-threads/issues/83
    bool shared = decoder->enabled_.has_shared() &&
                  decoder->module_->data_segments[imm.index].shared;
    V<FixedUInt32Array> data_segment_sizes = LOAD_IMMUTABLE_INSTANCE_FIELD(
        trusted_instance_data(shared), DataSegmentSizes,
        MemoryRepresentation::TaggedPointer());
    __ Store(data_segment_sizes, __ Word32Constant(0),
             StoreOp::Kind::TaggedBase(), MemoryRepresentation::Int32(),
             compiler::kNoWriteBarrier,
             FixedUInt32Array::OffsetOfElementAt(imm.index));
  }

  void TableGet(FullDecoder* decoder, const Value& index, Value* result,
                const TableIndexImmediate& imm) {
    V<WasmTableObject> table = LoadTable(decoder, imm);
    V<Smi> size_smi = __ Load(table, LoadOp::Kind::TaggedBase(),
                              MemoryRepresentation::TaggedSigned(),
                              WasmTableObject::kCurrentLengthOffset);
    V<WordPtr> index_wordptr =
        TableAddressToUintPtrOrOOBTrap(imm.table->address_type, index.op);
    DCHECK_GE(kSmiMaxValue, v8_flags.wasm_max_table_size.value());
    V<Word32> in_bounds = __ UintPtrLessThan(
        index_wordptr, __ ChangeUint32ToUintPtr(__ UntagSmi(size_smi)));
    __ TrapIfNot(in_bounds, TrapId::kTrapTableOutOfBounds);
    V<FixedArray> entries = __ Load(table, LoadOp::Kind::TaggedBase(),
                                    MemoryRepresentation::TaggedPointer(),
                                    WasmTableObject::kEntriesOffset);
    OpIndex entry = __ LoadFixedArrayElement(entries, index_wordptr);

    if (IsSubtypeOf(imm.table->type, kWasmFuncRef, decoder->module_) ||
        IsSubtypeOf(imm.table->type, ValueType::RefNull(HeapType::kFuncShared),
                    decoder->module_)) {
      // If the entry has map type Tuple2, call WasmFunctionTableGet which will
      // initialize the function table entry.
      Label<Object> resolved(&asm_);
      Label<> call_runtime(&asm_);
      // The entry is a WasmFuncRef, WasmNull, or Tuple2. Hence
      // it is safe to cast it to HeapObject.
      V<Map> entry_map = __ LoadMapField(V<HeapObject>::Cast(entry));
      V<Word32> instance_type = __ LoadInstanceTypeField(entry_map);
      GOTO_IF(
          UNLIKELY(__ Word32Equal(instance_type, InstanceType::TUPLE2_TYPE)),
          call_runtime);
      // Otherwise the entry is WasmFuncRef or WasmNull; we are done.
      GOTO(resolved, entry);

      BIND(call_runtime);
      bool extract_shared_data = !shared_ && imm.table->shared;
      GOTO(resolved,
           CallBuiltinThroughJumptable<
               BuiltinCallDescriptor::WasmFunctionTableGet>(
               decoder, {__ IntPtrConstant(imm.index), index_wordptr,
                         __ Word32Constant(extract_shared_data ? 1 : 0)}));

      BIND(resolved, resolved_entry);
      result->op = resolved_entry;
    } else {
      result->op = entry;
    }
    result->op = AnnotateResultIfReference(result->op, imm.table->type);
  }

  void TableSet(FullDecoder* decoder, const Value& index, const Value& value,
                const TableIndexImmediate& imm) {
    bool extract_shared_data = !shared_ && imm.table->shared;

    V<WordPtr> index_wordptr =
        TableAddressToUintPtrOrOOBTrap(imm.table->address_type, index.op);

    if (IsSubtypeOf(imm.table->type, kWasmFuncRef, decoder->module_) ||
        IsSubtypeOf(imm.table->type, ValueType::RefNull(HeapType::kFuncShared),
                    decoder->module_)) {
      CallBuiltinThroughJumptable<BuiltinCallDescriptor::WasmTableSetFuncRef>(
          decoder, {__ IntPtrConstant(imm.index),
                    __ Word32Constant(extract_shared_data ? 1 : 0),
                    index_wordptr, value.op});
    } else {
      CallBuiltinThroughJumptable<BuiltinCallDescriptor::WasmTableSet>(
          decoder, {__ IntPtrConstant(imm.index),
                    __ Word32Constant(extract_shared_data ? 1 : 0),
                    index_wordptr, value.op});
    }
  }

  void TableInit(FullDecoder* decoder, const TableInitImmediate& imm,
                 const Value& dst_val, const Value& src_val,
                 const Value& size_val) {
    const WasmTable* table = imm.table.table;
    V<WordPtr> dst_wordptr =
        TableAddressToUintPtrOrOOBTrap(table->address_type, dst_val.op);
    V<Word32> src = src_val.op;
    V<Word32> size = size_val.op;
    DCHECK_EQ(table->shared, table->shared);
    CallBuiltinThroughJumptable<BuiltinCallDescriptor::WasmTableInit>(
        decoder, {
                     dst_wordptr,
                     src,
                     size,
                     __ NumberConstant(imm.table.index),
                     __ NumberConstant(imm.element_segment.index),
                     __ NumberConstant((!shared_ && table->shared) ? 1 : 0),
                 });
  }

  void TableCopy(FullDecoder* decoder, const TableCopyImmediate& imm,
                 const Value& dst_val, const Value& src_val,
                 const Value& size_val) {
    const WasmTable* dst_table = imm.table_dst.table;
    const WasmTable* src_table = imm.table_src.table;
    V<WordPtr> dst_wordptr =
        TableAddressToUintPtrOrOOBTrap(dst_table->address_type, dst_val.op);
    V<WordPtr> src_wordptr =
        TableAddressToUintPtrOrOOBTrap(src_table->address_type, src_val.op);
    AddressType min_address_type =
        dst_table->is_table64() && src_table->is_table64() ? AddressType::kI64
                                                           : AddressType::kI32;
    V<WordPtr> size_wordptr =
        TableAddressToUintPtrOrOOBTrap(min_address_type, size_val.op);
    bool table_is_shared = imm.table_dst.table->shared;
    // TODO(14616): Is this too restrictive?
    DCHECK_EQ(table_is_shared, imm.table_src.table->shared);
    CallBuiltinThroughJumptable<BuiltinCallDescriptor::WasmTableCopy>(
        decoder, {dst_wordptr, src_wordptr, size_wordptr,
                  __ NumberConstant(imm.table_dst.index),
                  __ NumberConstant(imm.table_src.index),
                  __ NumberConstant((!shared_ && table_is_shared) ? 1 : 0)});
  }

  void TableGrow(FullDecoder* decoder, const TableIndexImmediate& imm,
                 const Value& value, const Value& delta, Value* result) {
    Label<Word32> end(&asm_);
    V<WordPtr> delta_wordptr;

    // If `delta` is OOB, return -1.
    if (!imm.table->is_table64()) {
      delta_wordptr = __ ChangeUint32ToUintPtr(delta.op);
    } else if constexpr (Is64()) {
      delta_wordptr = delta.op;
    } else {
      GOTO_IF(UNLIKELY(__ TruncateWord64ToWord32(
                  __ Word64ShiftRightLogical(delta.op, 32))),
              end, __ Word32Constant(-1));
      delta_wordptr = V<WordPtr>::Cast(__ TruncateWord64ToWord32(delta.op));
    }

    bool extract_shared_data = !shared_ && imm.table->shared;
    DCHECK_GE(kSmiMaxValue, v8_flags.wasm_max_table_size.value());
    V<Word32> call_result = __ UntagSmi(
        CallBuiltinThroughJumptable<BuiltinCallDescriptor::WasmTableGrow>(
            decoder, {__ NumberConstant(imm.index), delta_wordptr,
                      __ Word32Constant(extract_shared_data), value.op}));
    GOTO(end, call_result);

    BIND(end, result_i32);
    if (imm.table->is_table64()) {
      result->op = __ ChangeInt32ToInt64(result_i32);
    } else {
      result->op = result_i32;
    }
  }

  void TableFill(FullDecoder* decoder, const TableIndexImmediate& imm,
                 const Value& start, const Value& value, const Value& count) {
    V<WordPtr> start_wordptr =
        TableAddressToUintPtrOrOOBTrap(imm.table->address_type, start.op);
    V<WordPtr> count_wordptr =
        TableAddressToUintPtrOrOOBTrap(imm.table->address_type, count.op);
    bool extract_shared_data = !shared_ && imm.table->shared;
    CallBuiltinThroughJumptable<BuiltinCallDescriptor::WasmTableFill>(
        decoder,
        {start_wordptr, count_wordptr, __ Word32Constant(extract_shared_data),
         __ NumberConstant(imm.index), value.op});
  }

  V<WasmTableObject> LoadTable(FullDecoder* decoder,
                               const TableIndexImmediate& imm) {
    V<FixedArray> tables = LOAD_IMMUTABLE_INSTANCE_FIELD(
        trusted_instance_data(imm.table->shared), Tables,
        MemoryRepresentation::TaggedPointer());
    return V<WasmTableObject>::Cast(
        __ LoadFixedArrayElement(tables, imm.index));
  }

  void TableSize(FullDecoder* decoder, const TableIndexImmediate& imm,
                 Value* result) {
    V<WasmTableObject> table = LoadTable(decoder, imm);
    V<Word32> size_word32 = __ UntagSmi(__ Load(
        table, LoadOp::Kind::TaggedBase(), MemoryRepresentation::TaggedSigned(),
        WasmTableObject::kCurrentLengthOffset));
    if (imm.table->is_table64()) {
      result->op = __ ChangeUint32ToUint64(size_word32);
    } else {
      result->op = size_word32;
    }
  }

  void ElemDrop(FullDecoder* decoder, const IndexImmediate& imm) {
    // Note: Contrary to data segments, elem segments occur before the code
    // section, so we can be sure that they're available even during streaming
    // compilation.
    bool shared = decoder->module_->elem_segments[imm.index].shared;
    V<FixedArray> elem_segments = LOAD_IMMUTABLE_INSTANCE_FIELD(
        trusted_instance_data(shared), ElementSegments,
        MemoryRepresentation::TaggedPointer());
    __ StoreFixedArrayElement(elem_segments, imm.index,
                              LOAD_ROOT(EmptyFixedArray),
                              compiler::kFullWriteBarrier);
  }

  void StructNew(FullDecoder* decoder, const StructIndexImmediate& imm,
                 const Value args[], Value* result) {
    uint32_t field_count = imm.struct_type->field_count();
    SmallZoneVector<OpIndex, 16> args_vector(field_count, decoder->zone_);
    for (uint32_t i = 0; i < field_count; ++i) {
      args_vector[i] = args[i].op;
    }
    result->op = StructNewImpl(decoder, imm, args_vector.data());
  }

  void StructNewDefault(FullDecoder* decoder, const StructIndexImmediate& imm,
                        Value* result) {
    uint32_t field_count = imm.struct_type->field_count();
    SmallZoneVector<OpIndex, 16> args(field_count, decoder->zone_);
    for (uint32_t i = 0; i < field_count; i++) {
      ValueType field_type = imm.struct_type->field(i);
      args[i] = DefaultValue(field_type);
    }
    result->op = StructNewImpl(decoder, imm, args.data());
  }

  void StructGet(FullDecoder* decoder, const Value& struct_object,
                 const FieldImmediate& field, bool is_signed, Value* result) {
    result->op = __ StructGet(
        V<WasmStructNullable>::Cast(struct_object.op),
        field.struct_imm.struct_type, field.struct_imm.index,
        field.field_imm.index, is_signed,
        struct_object.type.is_nullable() ? compiler::kWithNullCheck
                                         : compiler::kWithoutNullCheck);
  }

  void StructSet(FullDecoder* decoder, const Value& struct_object,
                 const FieldImmediate& field, const Value& field_value) {
    __ StructSet(V<WasmStructNullable>::Cast(struct_object.op), field_value.op,
                 field.struct_imm.struct_type, field.struct_imm.index,
                 field.field_imm.index,
                 struct_object.type.is_nullable()
                     ? compiler::kWithNullCheck
                     : compiler::kWithoutNullCheck);
  }

  void ArrayNew(FullDecoder* decoder, const ArrayIndexImmediate& imm,
                const Value& length, const Value& initial_value,
                Value* result) {
    result->op = ArrayNewImpl(decoder, imm.index, imm.array_type,
                              V<Word32>::Cast(length.op),
                              V<Any>::Cast(initial_value.op));
  }

  void ArrayNewDefault(FullDecoder* decoder, const ArrayIndexImmediate& imm,
                       const Value& length, Value* result) {
    V<Any> initial_value = DefaultValue(imm.array_type->element_type());
    result->op = ArrayNewImpl(decoder, imm.index, imm.array_type,
                              V<Word32>::Cast(length.op), initial_value);
  }

  void ArrayGet(FullDecoder* decoder, const Value& array_obj,
                const ArrayIndexImmediate& imm, const Value& index,
                bool is_signed, Value* result) {
    auto array_value = V<WasmArrayNullable>::Cast(array_obj.op);
    BoundsCheckArray(array_value, index.op, array_obj.type);
    result->op = __ ArrayGet(array_value, V<Word32>::Cast(index.op),
                             imm.array_type, is_signed);
  }

  void ArraySet(FullDecoder* decoder, const Value& array_obj,
                const ArrayIndexImmediate& imm, const Value& index,
                const Value& value) {
    auto array_value = V<WasmArrayNullable>::Cast(array_obj.op);
    BoundsCheckArray(array_value, index.op, array_obj.type);
    __ ArraySet(array_value, V<Word32>::Cast(index.op), V<Any>::Cast(value.op),
                imm.array_type->element_type());
  }

  void ArrayLen(FullDecoder* decoder, const Value& array_obj, Value* result) {
    result->op = __ ArrayLength(V<WasmArrayNullable>::Cast(array_obj.op),
                                array_obj.type.is_nullable()
                                    ? compiler::kWithNullCheck
                                    : compiler::kWithoutNullCheck);
  }

  void ArrayCopy(FullDecoder* decoder, const Value& dst, const Value& dst_index,
                 const Value& src, const Value& src_index,
                 const ArrayIndexImmediate& src_imm, const Value& length) {
    V<WasmArrayNullable> src_array = V<WasmArrayNullable>::Cast(src.op);
    V<WasmArrayNullable> dst_array = V<WasmArrayNullable>::Cast(dst.op);
    BoundsCheckArrayWithLength(dst_array, dst_index.op, length.op,
                               dst.type.is_nullable()
                                   ? compiler::kWithNullCheck
                                   : compiler::kWithoutNullCheck);
    BoundsCheckArrayWithLength(src_array, src_index.op, length.op,
                               src.type.is_nullable()
                                   ? compiler::kWithNullCheck
                                   : compiler::kWithoutNullCheck);

    ValueType element_type = src_imm.array_type->element_type();

    IF_NOT (__ Word32Equal(length.op, 0)) {
      // Values determined by test/mjsunit/wasm/array-copy-benchmark.js on x64.
      int array_copy_max_loop_length;
      switch (element_type.kind()) {
        case wasm::kI32:
        case wasm::kI64:
        case wasm::kI8:
        case wasm::kI16:
          array_copy_max_loop_length = 20;
          break;
        case wasm::kF16:  // TODO(irezvov): verify the threshold for F16.
        case wasm::kF32:
        case wasm::kF64:
          array_copy_max_loop_length = 35;
          break;
        case wasm::kS128:
          array_copy_max_loop_length = 100;
          break;
        case wasm::kRtt:
        case wasm::kRef:
        case wasm::kRefNull:
          array_copy_max_loop_length = 15;
          break;
        case wasm::kVoid:
        case kTop:
        case wasm::kBottom:
          UNREACHABLE();
      }

      IF (__ Uint32LessThan(array_copy_max_loop_length, length.op)) {
        // Builtin
        MachineType arg_types[]{MachineType::TaggedPointer(),
                                MachineType::Uint32(),
                                MachineType::TaggedPointer(),
                                MachineType::Uint32(), MachineType::Uint32()};
        MachineSignature sig(0, 5, arg_types);

        CallC(&sig, ExternalReference::wasm_array_copy(),
              {dst_array, dst_index.op, src_array, src_index.op, length.op});
      } ELSE {
        V<Word32> src_end_index =
            __ Word32Sub(__ Word32Add(src_index.op, length.op), 1);

        IF (__ Uint32LessThan(src_index.op, dst_index.op)) {
          // Reverse
          V<Word32> dst_end_index =
              __ Word32Sub(__ Word32Add(dst_index.op, length.op), 1);
          ScopedVar<Word32> src_index_loop(this, src_end_index);
          ScopedVar<Word32> dst_index_loop(this, dst_end_index);

          WHILE(__ Word32Constant(1)) {
            V<Any> value = __ ArrayGet(src_array, src_index_loop,
                                       src_imm.array_type, true);
```