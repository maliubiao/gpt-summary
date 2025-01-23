Response:
The user wants a summary of the functionality of the provided C++ code snippet. The code is part of the V8 JavaScript engine, specifically within the `turboshaft` compiler component and the `recreate-schedule.cc` file.

The code seems to define a class `ScheduleBuilder` with methods for processing different types of operations (`ProcessOperation`). These operations likely represent intermediate representations of JavaScript code during compilation. The `ScheduleBuilder` appears to be responsible for translating these high-level operations into lower-level machine instructions or graph nodes that will eventually be used for code generation.

Here's a breakdown of how to approach the user's request:

1. **Identify the core purpose:** The filename `recreate-schedule.cc` and the methods like `ProcessOperation` strongly suggest this code is involved in constructing a scheduling graph, which is a crucial step in compilation.

2. **Analyze the `ProcessOperation` methods:** Each overloaded `ProcessOperation` method handles a specific operation type (e.g., `SelectOp`, `AtomicWord32PairOp`, `LoadOp`, `StoreOp`, `CallOp`, `ReturnOp`, `BranchOp`, etc.). The logic within these methods translates the high-level operation into a corresponding lower-level representation using objects like `machine` and `common`.

3. **Infer the overall functionality:** By looking at the different types of operations being processed, we can infer the broad range of JavaScript features that this part of the compiler handles (e.g., conditional execution, atomic operations, memory access, function calls, control flow).

4. **Address specific instructions:**
    - `.tq` check: The code explicitly mentions this, so it's important to note that this file is C++, not Torque.
    - JavaScript relation: Since this is part of a JavaScript engine's compiler, all the operations are ultimately related to JavaScript functionality. We need to pick a few representative examples and illustrate them with JavaScript code.
    - Code logic and examples: For some of the simpler operations (like `SelectOp`), we can provide a hypothetical input and output.
    - Common programming errors:  Relate some of the operations (like memory access) to common programming errors.

5. **Summarize the functionality:**  Condense the analysis into a concise summary.

**Mental Sandbox:**

- Imagine each `ProcessOperation` as a translation step. For example, `ProcessOperation(const SelectOp& op)` takes a high-level "select" operation and converts it into a machine-level "select" instruction based on the data type.
- Consider the role of `machine` and `common`. These likely provide abstractions for machine-specific instructions and common compiler primitives, respectively.
- Think about how these operations map to JavaScript. A `BranchOp` corresponds to an `if` statement, a `CallOp` to a function call, `LoadOp`/`StoreOp` to variable access.

**Constraint Checklist & Confidence Score:**

1. List functionalities? Yes.
2. Check for `.tq` extension? Yes.
3. Relate to JavaScript? Yes.
4. JavaScript examples? Yes.
5. Code logic and examples? Yes, for suitable ops.
6. Common programming errors? Yes.
7. Functionality summary? Yes.

Confidence Score: 5/5

**Strategizing complete.** I will now proceed with generating the response based on the above analysis.
这是V8 Turboshaft 编译器的 `recreate-schedule.cc` 文件的第二部分，它的主要功能是**根据 Turboshaft 图（Turboshaft Graph）中的操作（Operation），重新构建 Turbofan 图（Turbofan Graph）的调度（Schedule）**。

简单来说，Turboshaft 是 V8 引擎中新的编译器框架，它生成自己的中间表示（Turboshaft Graph）。为了最终生成机器码，Turboshaft 需要将它的表示转换为 Turbofan，V8 引擎中原有的优化编译器框架。 `recreate-schedule.cc` 的核心任务就是执行这个转换过程中的调度重建部分。调度指的是指令执行的顺序和控制流。

**具体功能归纳：**

这个代码片段中的主要功能是 `ScheduleBuilder::ProcessOperation` 方法针对各种不同类型的操作进行处理，并将其转换为 Turbofan 图中的节点。

* **条件移动 (`SelectOp`):** 将 Turboshaft 的条件选择操作 (`SelectOp`) 转换为 Turbofan 的 `Word32Select`、`Word64Select` 等操作，根据不同的数据类型选择不同的机器指令。
* **循环 Phi (`PendingLoopPhiOp`):**  这个操作目前被标记为 `UNREACHABLE()`，可能表示循环的 Phi 节点在调度重建的这个阶段还未完全处理或有特定的处理方式。
* **原子操作对 (`AtomicWord32PairOp`):** 处理 32 位原子操作对，例如原子加、减、与、或、异或、交换、加载和比较交换。根据不同的操作类型，生成 Turbofan 中对应的原子操作节点。
* **原子读-修改-写操作 (`AtomicRMWOp`):** 处理更通用的原子读-修改-写操作，例如原子加、减、与、或、异或、交换和比较交换。根据操作数的大小（32 位或 64 位）和具体的操作类型，生成相应的 Turbofan 原子操作节点。
* **内存屏障 (`MemoryBarrierOp`):**  将 Turboshaft 的内存屏障操作转换为 Turbofan 的 `MemoryBarrier` 节点。
* **元组 (`TupleOp`):**  元组在调度重建阶段通常是未使用的，因此返回 `nullptr`。
* **常量 (`ConstantOp`):** 将各种类型的常量（32 位整数、64 位整数、Smi、外部引用、堆对象、数字、浮点数等）转换为 Turbofan 中对应的常量节点。
* **加载 (`LoadOp`):**  处理内存加载操作，根据是否对齐、是否是原子操作、是否需要陷阱处理等因素，生成不同的 Turbofan 加载节点 (`Load`、`UnalignedLoad`、`Word32AtomicLoad`、`Word64AtomicLoad`、`LoadTrapOnNull`、`ProtectedLoad`)。
* **存储 (`StoreOp`):** 处理内存存储操作，同样根据是否对齐、是否是原子操作、是否需要陷阱处理、是否需要写屏障等因素，生成不同的 Turbofan 存储节点 (`Store`、`UnalignedStore`、`Word32AtomicStore`、`Word64AtomicStore`、`StoreTrapOnNull`、`ProtectedStore`、`StoreIndirectPointer`)。
* **保留 (`RetainOp`):**  转换为 Turbofan 的 `Retain` 节点。
* **参数 (`ParameterOp`):**  将 Turboshaft 的函数参数转换为 Turbofan 的 `Parameter` 节点。为了避免重复创建相同参数的节点，会进行缓存。
* **OSR 值 (`OsrValueOp`):**  将 OSR（On-Stack Replacement）的值转换为 Turbofan 的 `OsrValue` 节点，同样进行缓存。
* **跳转 (`GotoOp`):**  在 Turbofan 调度中添加一个跳转到目标基本块的边。
* **栈指针比较 (`StackPointerGreaterThanOp`):** 转换为 Turbofan 的 `StackPointerGreaterThan` 节点。
* **栈槽 (`StackSlotOp`):** 转换为 Turbofan 的 `StackSlot` 节点。
* **帧常量 (`FrameConstantOp`):**  加载帧相关的常量，例如栈检查偏移量、帧指针、父帧指针。
* **条件反优化 (`DeoptimizeIfOp`):** 将 Turboshaft 的条件反优化操作转换为 Turbofan 的 `DeoptimizeIf` 或 `DeoptimizeUnless` 节点。
* **条件陷阱 (`TrapIfOp`):** (如果启用了 WebAssembly) 将 Turboshaft 的条件陷阱操作转换为 Turbofan 的 `TrapIf` 或 `TrapUnless` 节点。
* **反优化 (`DeoptimizeOp`):** 将 Turboshaft 的反优化操作转换为 Turbofan 的 `Deoptimize` 节点。
* **Phi (`PhiOp`):**  将 Turboshaft 的 Phi 节点转换为 Turbofan 的 `Phi` 节点。对于循环 Phi 节点和非循环 Phi 节点的处理方式有所不同，需要处理前驱块的顺序。
* **投影 (`ProjectionOp`):**  将 Turboshaft 的投影操作转换为 Turbofan 的 `Projection` 节点。
* **假设 Map (`AssumeMapOp`):**  `AssumeMapOp` 在 Turbofan 中没有直接的对应物，因此返回 `nullptr`。
* **构建反优化输入 (`BuildDeoptInput`):**  一个辅助方法，用于构建反优化所需的输入值，处理不同类型的输入指令。
* **构建状态值 (`BuildStateValues`):** 一个辅助方法，用于构建表示程序状态的值，通常用于反优化和调试。
* **构建标签输入 (`BuildTaggedInput`):** 一个辅助方法，用于构建标签指针类型的输入。
* **帧状态 (`FrameStateOp`):**  将 Turboshaft 的帧状态信息转换为 Turbofan 的 `FrameState` 节点，包含了闭包、参数、上下文、寄存器状态、累加器状态和父帧状态等信息。
* **调用 (`CallOp`):** 将 Turboshaft 的函数调用操作转换为 Turbofan 的 `Call` 节点。
* **检查异常 (`CheckExceptionOp`):** 处理可能抛出异常的调用，创建 Turbofan 的 `IfSuccess` 和 `IfException` 节点来表示成功和异常两种控制流。
* **捕获块开始 (`CatchBlockBeginOp`):**  获取与异常处理相关的 `IfException` 节点。
* **未抛出异常 (`DidntThrowOp`):**  获取未抛出异常时的操作结果。
* **尾调用 (`TailCallOp`):** 将 Turboshaft 的尾调用操作转换为 Turbofan 的 `TailCall` 节点。
* **不可达 (`UnreachableOp`):**  将 Turboshaft 的不可达操作转换为 Turbofan 的 `Unreachable` 和 `Throw` 节点。
* **返回 (`ReturnOp`):** 将 Turboshaft 的返回操作转换为 Turbofan 的 `Return` 节点。
* **分支 (`BranchOp`):** 将 Turboshaft 的条件分支操作转换为 Turbofan 的 `Branch`、`IfTrue` 和 `IfFalse` 节点。
* **开关 (`SwitchOp`):** 将 Turboshaft 的开关语句转换为 Turbofan 的 `Switch`、`IfValue` 和 `IfDefault` 节点。
* **调试断点 (`DebugBreakOp`):** 转换为 Turbofan 的 `DebugBreak` 节点。
* **加载根寄存器 (`LoadRootRegisterOp`):** 转换为 Turbofan 的 `LoadRootRegister` 节点。
* **32 位整数对二元操作 (`Word32PairBinopOp`):** 处理 32 位整数对的二元运算，例如加、减、乘、左移、算术右移和逻辑右移。
* **注释 (`CommentOp`):** 添加 Turbofan 的注释节点。
* **中止 CSA 检查 (`AbortCSADcheckOp`):** 添加 Turbofan 的 `AbortCSADcheck` 节点，用于 CSA（Code Stub Assembler）的调试检查。
* **SIMD 128 位操作 (`Simd128ConstantOp`, `Simd128BinopOp`, `Simd128UnaryOp`, `Simd128ReduceOp`, `Simd128ShiftOp`, `Simd128TestOp`, `Simd128SplatOp`, `Simd128TernaryOp`):** (如果启用了 WebAssembly) 处理 SIMD 128 位向量相关的常量、二元操作、一元操作、规约操作、移位操作、测试操作、填充操作和三元操作。

**关于文件扩展名：**

你提供的代码片段是 C++ 代码，因此 `v8/src/compiler/turboshaft/recreate-schedule.cc` 不会以 `.tq` 结尾。以 `.tq` 结尾的文件是 V8 的 **Torque** 语言源代码。Torque 是一种用于定义 V8 内部运行时函数的领域特定语言。

**与 Javascript 的关系：**

所有这些操作最终都与 Javascript 的功能息息相关。编译器的工作就是将 Javascript 代码转换成机器可以执行的指令。例如：

* **`SelectOp`:**  对应 Javascript 中的三元运算符 `condition ? valueIfTrue : valueIfFalse`。
   ```javascript
   let x = condition ? 10 : 20;
   ```
* **`AtomicWord32PairOp` / `AtomicRMWOp`:** 对应 Javascript 中的 `Atomics` API，用于多线程环境下的原子操作。
   ```javascript
   const sab = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT * 2);
   const view = new Int32Array(sab);
   Atomics.add(view, 0, 5); // 原子地将 view[0] 加 5
   ```
* **`LoadOp` / `StoreOp`:** 对应 Javascript 中访问对象属性或数组元素。
   ```javascript
   let obj = { a: 1 };
   let value = obj.a; // LoadOp
   obj.a = 2;       // StoreOp

   let arr = [1, 2];
   let element = arr[0]; // LoadOp
   arr[1] = 3;          // StoreOp
   ```
* **`CallOp`:** 对应 Javascript 中的函数调用。
   ```javascript
   function myFunction(a, b) {
       return a + b;
   }
   let result = myFunction(3, 4);
   ```
* **`BranchOp`:** 对应 Javascript 中的 `if` 语句。
   ```javascript
   if (x > 5) {
       // ...
   } else {
       // ...
   }
   ```
* **`SwitchOp`:** 对应 Javascript 中的 `switch` 语句。
   ```javascript
   switch (value) {
       case 1:
           // ...
           break;
       case 2:
           // ...
           break;
       default:
           // ...
   }
   ```

**代码逻辑推理示例：**

**假设输入 (`SelectOp`):**

* `op.implem`: `SelectOp::Implementation::kCMove`
* `op.rep`: `RegisterRepresentation::Word32()`
* `op.cond()` 返回一个表示条件的 `OpIndex`
* `op.vtrue()` 返回一个表示真值的 `OpIndex`
* `op.vfalse()` 返回一个表示假值的 `OpIndex`

**输出 (`SelectOp`):**

Turbofan 图中会添加一个 `Word32Select` 节点，其输入为：

1. 通过 `GetNode(op.cond())` 获取的条件节点。
2. 通过 `GetNode(op.vtrue())` 获取的真值节点。
3. 通过 `GetNode(op.vfalse())` 获取的假值节点。

**涉及用户常见的编程错误：**

* **内存访问错误 (与 `LoadOp` 和 `StoreOp` 相关):**
    * **访问未初始化的内存:**  在 Javascript 中可能表现为读取未赋值的变量或对象属性，虽然 V8 会进行初始化，但在底层编译阶段，这涉及到内存的加载操作。
    * **越界访问数组:** 访问数组时索引超出范围，会导致内存访问错误。
    * **使用空指针/未定义的引用:** 尝试访问 `null` 或 `undefined` 的属性会导致运行时错误，但在编译阶段，编译器需要处理这些情况，并可能生成带有陷阱处理的加载操作。

    ```javascript
    let arr = [1, 2];
    console.log(arr[5]); // 越界访问

    let obj = null;
    console.log(obj.a); // 访问空对象的属性
    ```

* **原子操作使用不当 (与 `AtomicWord32PairOp` 和 `AtomicRMWOp` 相关):** 在多线程环境下，如果原子操作使用不当，可能会导致数据竞争和不一致性。例如，忘记使用原子操作来更新共享变量。

**第 2 部分功能归纳：**

总而言之，`v8/src/compiler/turboshaft/recreate-schedule.cc` 的第二部分的核心功能是实现了 `ScheduleBuilder::ProcessOperation` 方法，用于将 Turboshaft 图中的各种操作转换为 Turbofan 图中对应的节点，这是 Turboshaft 编译器将高级表示转换为低级表示的关键步骤，为后续的 Turbofan 优化和代码生成奠定了基础。它覆盖了包括算术运算、逻辑运算、内存访问、控制流、函数调用、异常处理、原子操作等多种 Javascript 语言特性在内的底层表示转换。

### 提示词
```
这是目录为v8/src/compiler/turboshaft/recreate-schedule.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/turboshaft/recreate-schedule.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
with cmove.
  DCHECK_EQ(op.implem, SelectOp::Implementation::kCMove);
  DCHECK((op.rep == RegisterRepresentation::Word32() &&
          SupportedOperations::word32_select()) ||
         (op.rep == RegisterRepresentation::Word64() &&
          SupportedOperations::word64_select()) ||
         (op.rep == RegisterRepresentation::Float32() &&
          SupportedOperations::float32_select()) ||
         (op.rep == RegisterRepresentation::Float64() &&
          SupportedOperations::float64_select()));
  const Operator* o = nullptr;
  switch (op.rep.value()) {
    case RegisterRepresentation::Enum::kWord32:
      o = machine.Word32Select().op();
      break;
    case RegisterRepresentation::Enum::kWord64:
      o = machine.Word64Select().op();
      break;
    case RegisterRepresentation::Enum::kFloat32:
      o = machine.Float32Select().op();
      break;
    case RegisterRepresentation::Enum::kFloat64:
      o = machine.Float64Select().op();
      break;
    case RegisterRepresentation::Enum::kTagged:
    case RegisterRepresentation::Enum::kCompressed:
    case RegisterRepresentation::Enum::kSimd128:
    case RegisterRepresentation::Enum::kSimd256:
      UNREACHABLE();
  }

  return AddNode(
      o, {GetNode(op.cond()), GetNode(op.vtrue()), GetNode(op.vfalse())});
}
Node* ScheduleBuilder::ProcessOperation(const PendingLoopPhiOp& op) {
  UNREACHABLE();
}

Node* ScheduleBuilder::ProcessOperation(const AtomicWord32PairOp& op) {
  DCHECK(!Is64());
  Node* index;
  if (op.index().valid() && op.offset) {
    index = AddNode(machine.Int32Add(),
                    {GetNode(op.index().value()), IntPtrConstant(op.offset)});
  } else if (op.index().valid()) {
    index = GetNode(op.index().value());
  } else {
    index = IntPtrConstant(op.offset);
  }
#define BINOP_CASE(OP)                                               \
  if (op.kind == AtomicWord32PairOp::Kind::k##OP) {                  \
    return AddNode(                                                  \
        machine.Word32AtomicPair##OP(),                              \
        {GetNode(op.base()), index, GetNode(op.value_low().value()), \
         GetNode(op.value_high().value())});                         \
  }
#define ATOMIC_BINOPS(V) \
  V(Add)                 \
  V(Sub)                 \
  V(And)                 \
  V(Or)                  \
  V(Xor)                 \
  V(Exchange)
  ATOMIC_BINOPS(BINOP_CASE)
#undef ATOMIC_BINOPS
#undef BINOP_CASE

  if (op.kind == AtomicWord32PairOp::Kind::kLoad) {
    return AddNode(machine.Word32AtomicPairLoad(AtomicMemoryOrder::kSeqCst),
                   {GetNode(op.base()), index});
  }
  if (op.kind == AtomicWord32PairOp::Kind::kStore) {
    return AddNode(machine.Word32AtomicPairStore(AtomicMemoryOrder::kSeqCst),
                   {GetNode(op.base()), index, GetNode(op.value_low().value()),
                    GetNode(op.value_high().value())});
  }
  DCHECK_EQ(op.kind, AtomicWord32PairOp::Kind::kCompareExchange);
  return AddNode(
      machine.Word32AtomicPairCompareExchange(),
      {GetNode(op.base()), index, GetNode(op.expected_low().value()),
       GetNode(op.expected_high().value()), GetNode(op.value_low().value()),
       GetNode(op.value_high().value())});
}

Node* ScheduleBuilder::ProcessOperation(const AtomicRMWOp& op) {
#define ATOMIC_BINOPS(V) \
  V(Add)                 \
  V(Sub)                 \
  V(And)                 \
  V(Or)                  \
  V(Xor)                 \
  V(Exchange)            \
  V(CompareExchange)

  AtomicOpParameters param(op.memory_rep.ToMachineType(),
                           op.memory_access_kind);
  const Operator* node_op;
  if (op.in_out_rep == RegisterRepresentation::Word32()) {
    switch (op.bin_op) {
#define CASE(Name)                               \
  case AtomicRMWOp::BinOp::k##Name:              \
    node_op = machine.Word32Atomic##Name(param); \
    break;
      ATOMIC_BINOPS(CASE)
#undef CASE
    }
  } else {
    DCHECK_EQ(op.in_out_rep, RegisterRepresentation::Word64());
    switch (op.bin_op) {
#define CASE(Name)                               \
  case AtomicRMWOp::BinOp::k##Name:              \
    node_op = machine.Word64Atomic##Name(param); \
    break;
      ATOMIC_BINOPS(CASE)
#undef CASE
    }
  }
#undef ATOMIC_BINOPS
  Node* base = GetNode(op.base());
  Node* index = GetNode(op.index());
  Node* value = GetNode(op.value());
  if (op.bin_op == AtomicRMWOp::BinOp::kCompareExchange) {
    Node* expected = GetNode(op.expected().value());
    return AddNode(node_op, {base, index, expected, value});
  } else {
    return AddNode(node_op, {base, index, value});
  }
}

Node* ScheduleBuilder::ProcessOperation(const MemoryBarrierOp& op) {
  return AddNode(machine.MemoryBarrier(op.memory_order), {});
}

Node* ScheduleBuilder::ProcessOperation(const TupleOp& op) {
  // Tuples are only used for lowerings during reduction. Therefore, we can
  // assume that it is unused if it occurs at this point.
  return nullptr;
}
Node* ScheduleBuilder::ProcessOperation(const ConstantOp& op) {
  switch (op.kind) {
    case ConstantOp::Kind::kWord32:
      return AddNode(common.Int32Constant(static_cast<int32_t>(op.word32())),
                     {});
    case ConstantOp::Kind::kWord64:
      return AddNode(common.Int64Constant(static_cast<int64_t>(op.word64())),
                     {});
    case ConstantOp::Kind::kSmi:
      if constexpr (Is64()) {
        return AddNode(
            machine.BitcastWordToTaggedSigned(),
            {AddNode(common.Int64Constant(static_cast<int64_t>(op.smi().ptr())),
                     {})});
      } else {
        return AddNode(
            machine.BitcastWordToTaggedSigned(),
            {AddNode(common.Int32Constant(static_cast<int32_t>(op.smi().ptr())),
                     {})});
      }
    case ConstantOp::Kind::kExternal:
      return AddNode(common.ExternalConstant(op.external_reference()), {});
    case ConstantOp::Kind::kHeapObject:
      return AddNode(common.HeapConstant(op.handle()), {});
    case ConstantOp::Kind::kCompressedHeapObject:
      return AddNode(common.CompressedHeapConstant(op.handle()), {});
    case ConstantOp::Kind::kTrustedHeapObject:
      return AddNode(common.TrustedHeapConstant(op.handle()), {});
    case ConstantOp::Kind::kNumber:
      return AddNode(common.NumberConstant(op.number().get_scalar()), {});
    case ConstantOp::Kind::kTaggedIndex:
      return AddNode(common.TaggedIndexConstant(op.tagged_index()), {});
    case ConstantOp::Kind::kFloat64:
      return AddNode(common.Float64Constant(op.float64().get_scalar()), {});
    case ConstantOp::Kind::kFloat32:
      return AddNode(common.Float32Constant(op.float32().get_scalar()), {});
    case ConstantOp::Kind::kRelocatableWasmCall:
      return RelocatableIntPtrConstant(op.integral(), RelocInfo::WASM_CALL);
    case ConstantOp::Kind::kRelocatableWasmStubCall:
      return RelocatableIntPtrConstant(op.integral(),
                                       RelocInfo::WASM_STUB_CALL);
    case ConstantOp::Kind::kRelocatableWasmCanonicalSignatureId:
      return AddNode(common.RelocatableInt32Constant(
                         base::checked_cast<int32_t>(op.integral()),
                         RelocInfo::WASM_CANONICAL_SIG_ID),
                     {});
    case ConstantOp::Kind::kRelocatableWasmIndirectCallTarget:
      if constexpr (V8_ENABLE_WASM_CODE_POINTER_TABLE_BOOL) {
        return AddNode(common.RelocatableInt32Constant(
                           base::checked_cast<int32_t>(op.integral()),
                           RelocInfo::WASM_INDIRECT_CALL_TARGET),
                       {});
      } else {
        return RelocatableIntPtrConstant(op.integral(),
                                         RelocInfo::WASM_INDIRECT_CALL_TARGET);
      }
  }
}

Node* ScheduleBuilder::ProcessOperation(const LoadOp& op) {
  intptr_t offset = op.offset;
  if (op.kind.tagged_base) {
    CHECK_GE(offset, std::numeric_limits<int32_t>::min() + kHeapObjectTag);
    offset -= kHeapObjectTag;
  }
  Node* base = GetNode(op.base());
  Node* index;
  if (op.index().valid()) {
    index = GetNode(op.index().value());
    if (op.element_size_log2 != 0) {
      index = IntPtrShl(index, IntPtrConstant(op.element_size_log2));
    }
    if (offset != 0) {
      index = IntPtrAdd(index, IntPtrConstant(offset));
    }
  } else {
    index = IntPtrConstant(offset);
  }

  MachineType loaded_rep = op.machine_type();
  const Operator* o;
  if (op.kind.maybe_unaligned) {
    DCHECK(!op.kind.with_trap_handler);
    if (loaded_rep.representation() == MachineRepresentation::kWord8 ||
        machine.UnalignedLoadSupported(loaded_rep.representation())) {
      o = machine.Load(loaded_rep);
    } else {
      o = machine.UnalignedLoad(loaded_rep);
    }
  } else if (op.kind.is_atomic) {
    DCHECK(!op.kind.maybe_unaligned);
    AtomicLoadParameters params(loaded_rep, AtomicMemoryOrder::kSeqCst,
                                op.kind.with_trap_handler
                                    ? MemoryAccessKind::kProtectedByTrapHandler
                                    : MemoryAccessKind::kNormal);
    if (op.result_rep == RegisterRepresentation::Word32()) {
      o = machine.Word32AtomicLoad(params);
    } else {
      DCHECK_EQ(op.result_rep, RegisterRepresentation::Word64());
      o = machine.Word64AtomicLoad(params);
    }
  } else if (op.kind.with_trap_handler) {
    DCHECK(!op.kind.maybe_unaligned);
    if (op.kind.tagged_base) {
      o = machine.LoadTrapOnNull(loaded_rep);
    } else {
      o = machine.ProtectedLoad(loaded_rep);
    }
  } else {
    o = machine.Load(loaded_rep);
  }
  return AddNode(o, {base, index});
}

Node* ScheduleBuilder::ProcessOperation(const StoreOp& op) {
  intptr_t offset = op.offset;
  if (op.kind.tagged_base) {
    CHECK(offset >= std::numeric_limits<int32_t>::min() + kHeapObjectTag);
    offset -= kHeapObjectTag;
  }
  Node* base = GetNode(op.base());
  Node* index;
  if (op.index().valid()) {
    index = GetNode(op.index().value());
    if (op.element_size_log2 != 0) {
      index = IntPtrShl(index, IntPtrConstant(op.element_size_log2));
    }
    if (offset != 0) {
      index = IntPtrAdd(index, IntPtrConstant(offset));
    }
  } else {
    index = IntPtrConstant(offset);
  }
  Node* value = GetNode(op.value());

  const Operator* o;
  if (op.kind.maybe_unaligned) {
    DCHECK(!op.kind.with_trap_handler);
    DCHECK_EQ(op.write_barrier, WriteBarrierKind::kNoWriteBarrier);
    if (op.stored_rep.ToMachineType().representation() ==
            MachineRepresentation::kWord8 ||
        machine.UnalignedStoreSupported(
            op.stored_rep.ToMachineType().representation())) {
      o = machine.Store(StoreRepresentation(
          op.stored_rep.ToMachineType().representation(), op.write_barrier));
    } else {
      o = machine.UnalignedStore(
          op.stored_rep.ToMachineType().representation());
    }
  } else if (op.kind.is_atomic) {
    AtomicStoreParameters params(op.stored_rep.ToMachineType().representation(),
                                 op.write_barrier, AtomicMemoryOrder::kSeqCst,
                                 op.kind.with_trap_handler
                                     ? MemoryAccessKind::kProtectedByTrapHandler
                                     : MemoryAccessKind::kNormal);
    if (op.stored_rep == MemoryRepresentation::Int64() ||
        op.stored_rep == MemoryRepresentation::Uint64()) {
      o = machine.Word64AtomicStore(params);
    } else {
      o = machine.Word32AtomicStore(params);
    }
  } else if (op.kind.with_trap_handler) {
    DCHECK(!op.kind.maybe_unaligned);
    if (op.kind.tagged_base) {
      o = machine.StoreTrapOnNull(StoreRepresentation(
          op.stored_rep.ToMachineType().representation(), op.write_barrier));
    } else {
      DCHECK_EQ(op.write_barrier, WriteBarrierKind::kNoWriteBarrier);
      o = machine.ProtectedStore(
          op.stored_rep.ToMachineType().representation());
    }
  } else if (op.stored_rep == MemoryRepresentation::IndirectPointer()) {
    o = machine.StoreIndirectPointer(op.write_barrier);
    // In this case we need a fourth input: the indirect pointer tag.
    Node* tag = IntPtrConstant(op.indirect_pointer_tag());
    return AddNode(o, {base, index, value, tag});
  } else {
    o = machine.Store(StoreRepresentation(
        op.stored_rep.ToMachineType().representation(), op.write_barrier));
  }
  return AddNode(o, {base, index, value});
}

Node* ScheduleBuilder::ProcessOperation(const RetainOp& op) {
  return AddNode(common.Retain(), {GetNode(op.retained())});
}
Node* ScheduleBuilder::ProcessOperation(const ParameterOp& op) {
  // Parameters need to be cached because the register allocator assumes that
  // there are no duplicate nodes for the same parameter.
  if (parameters.count(op.parameter_index)) {
    return parameters[op.parameter_index];
  }
  Node* parameter = MakeNode(
      common.Parameter(static_cast<int>(op.parameter_index), op.debug_name),
      {tf_graph->start()});
  schedule->AddNode(schedule->start(), parameter);
  parameters[op.parameter_index] = parameter;
  return parameter;
}
Node* ScheduleBuilder::ProcessOperation(const OsrValueOp& op) {
  // OSR values behave like parameters, so they also need to be cached.
  if (osr_values.count(op.index)) {
    return osr_values[op.index];
  }
  Node* osr_value = MakeNode(common.OsrValue(static_cast<int>(op.index)),
                             {tf_graph->start()});
  schedule->AddNode(schedule->start(), osr_value);
  osr_values[op.index] = osr_value;
  return osr_value;
}
Node* ScheduleBuilder::ProcessOperation(const GotoOp& op) {
  schedule->AddGoto(current_block, blocks[op.destination->index().id()]);
  current_block = nullptr;
  return nullptr;
}
Node* ScheduleBuilder::ProcessOperation(const StackPointerGreaterThanOp& op) {
  return AddNode(machine.StackPointerGreaterThan(op.kind),
                 {GetNode(op.stack_limit())});
}
Node* ScheduleBuilder::ProcessOperation(const StackSlotOp& op) {
  return AddNode(machine.StackSlot(op.size, op.alignment, op.is_tagged), {});
}
Node* ScheduleBuilder::ProcessOperation(const FrameConstantOp& op) {
  switch (op.kind) {
    case FrameConstantOp::Kind::kStackCheckOffset:
      return AddNode(machine.LoadStackCheckOffset(), {});
    case FrameConstantOp::Kind::kFramePointer:
      return AddNode(machine.LoadFramePointer(), {});
    case FrameConstantOp::Kind::kParentFramePointer:
      return AddNode(machine.LoadParentFramePointer(), {});
  }
}
Node* ScheduleBuilder::ProcessOperation(const DeoptimizeIfOp& op) {
  Node* condition = GetNode(op.condition());
  Node* frame_state = GetNode(op.frame_state());
  const Operator* o = op.negated
                          ? common.DeoptimizeUnless(op.parameters->reason(),
                                                    op.parameters->feedback())
                          : common.DeoptimizeIf(op.parameters->reason(),
                                                op.parameters->feedback());
  return AddNode(o, {condition, frame_state});
}

#if V8_ENABLE_WEBASSEMBLY
Node* ScheduleBuilder::ProcessOperation(const TrapIfOp& op) {
  Node* condition = GetNode(op.condition());
  bool has_frame_state = op.frame_state().valid();
  Node* frame_state =
      has_frame_state ? GetNode(op.frame_state().value()) : nullptr;
  const Operator* o = op.negated
                          ? common.TrapUnless(op.trap_id, has_frame_state)
                          : common.TrapIf(op.trap_id, has_frame_state);
  return has_frame_state ? AddNode(o, {condition, frame_state})
                         : AddNode(o, {condition});
}
#endif  // V8_ENABLE_WEBASSEMBLY

Node* ScheduleBuilder::ProcessOperation(const DeoptimizeOp& op) {
  Node* frame_state = GetNode(op.frame_state());
  const Operator* o =
      common.Deoptimize(op.parameters->reason(), op.parameters->feedback());
  Node* node = MakeNode(o, {frame_state});
  schedule->AddDeoptimize(current_block, node);
  current_block = nullptr;
  return nullptr;
}
Node* ScheduleBuilder::ProcessOperation(const PhiOp& op) {
  if (current_input_block->IsLoop()) {
    DCHECK_EQ(op.input_count, 2);
    Node* input = GetNode(op.input(0));
    // The second `input` is a placeholder that is patched when we process the
    // backedge.
    Node* node =
        AddNode(common.Phi(op.rep.machine_representation(), 2), {input, input});
    loop_phis.emplace_back(node, op.input(1));
    return node;
  } else {
    // Predecessors of {current_input_block} and the TF's matching block might
    // not be in the same order, so Phi inputs might need to be reordered to
    // match the new order.
    // This is similar to what AssembleOutputGraphPhi in CopyingPhase does,
    // except that CopyingPhase has a new->old block mapping, which we
    // don't have here in RecreateSchedule, so the implementation is slightly
    // different (relying on std::lower_bound rather than looking up the
    // old->new mapping).
    ZoneVector<BasicBlock*> new_predecessors = current_block->predecessors();
    // Since RecreateSchedule visits the blocks in increasing ID order,
    // predecessors should be sorted (we rely on this property to binary search
    // new predecessors corresponding to old ones).
    auto cmp_basic_block = [](BasicBlock* a, BasicBlock* b) {
      return a->id().ToInt() < b->id().ToInt();
    };
    DCHECK(std::is_sorted(new_predecessors.begin(), new_predecessors.end(),
                          cmp_basic_block));
    size_t predecessor_count = new_predecessors.size();
    base::SmallVector<Node*, 8> inputs(predecessor_count);
#ifdef DEBUG
    std::fill(inputs.begin(), inputs.end(), nullptr);
#endif

    int current_index = 0;
    for (const Block* pred : current_input_block->PredecessorsIterable()) {
      size_t pred_index = predecessor_count - current_index - 1;
      auto lower =
          std::lower_bound(new_predecessors.begin(), new_predecessors.end(),
                           GetBlock(*pred), cmp_basic_block);
      DCHECK_NE(lower, new_predecessors.end());
      size_t new_pred_index = std::distance(new_predecessors.begin(), lower);
      // Block {pred_index} became predecessor {new_pred_index} in the TF graph.
      // We thus put the input {pred_index} in position {new_pred_index}.
      inputs[new_pred_index] = GetNode(op.input(pred_index));
      ++current_index;
    }
    DCHECK(!base::contains(inputs, nullptr));

    return AddNode(common.Phi(op.rep.machine_representation(), op.input_count),
                   base::VectorOf(inputs));
  }
}
Node* ScheduleBuilder::ProcessOperation(const ProjectionOp& op) {
  return AddNode(common.Projection(op.index), {GetNode(op.input())});
}
Node* ScheduleBuilder::ProcessOperation(const AssumeMapOp&) {
  // AssumeMapOp is just a hint that optimization phases can use, but has no
  // Turbofan equivalent and is thus not used past this point.
  return nullptr;
}

std::pair<Node*, MachineType> ScheduleBuilder::BuildDeoptInput(
    FrameStateData::Iterator* it) {
  switch (it->current_instr()) {
    using Instr = FrameStateData::Instr;
    case Instr::kInput: {
      MachineType type;
      OpIndex input;
      it->ConsumeInput(&type, &input);
      const Operation& op = input_graph.Get(input);
      if (op.outputs_rep()[0] == RegisterRepresentation::Word64() &&
          type.representation() == MachineRepresentation::kWord32) {
        // 64 to 32-bit conversion is implicit in turboshaft, but explicit in
        // turbofan, so we insert this conversion.
        Node* conversion =
            AddNode(machine.TruncateInt64ToInt32(), {GetNode(input)});
        return {conversion, type};
      }
      return {GetNode(input), type};
    }
    case Instr::kDematerializedObject: {
      uint32_t obj_id;
      uint32_t field_count;
      it->ConsumeDematerializedObject(&obj_id, &field_count);
      base::SmallVector<Node*, 16> fields;
      ZoneVector<MachineType>& field_types =
          *tf_graph->zone()->New<ZoneVector<MachineType>>(field_count,
                                                          tf_graph->zone());
      for (uint32_t i = 0; i < field_count; ++i) {
        std::pair<Node*, MachineType> p = BuildDeoptInput(it);
        fields.push_back(p.first);
        field_types[i] = p.second;
      }
      return {AddNode(common.TypedObjectState(obj_id, &field_types),
                      base::VectorOf(fields)),
              MachineType::AnyTagged()};
    }
    case Instr::kDematerializedObjectReference: {
      uint32_t obj_id;
      it->ConsumeDematerializedObjectReference(&obj_id);
      return {AddNode(common.ObjectId(obj_id), {}), MachineType::AnyTagged()};
    }
    case Instr::kArgumentsElements: {
      CreateArgumentsType type;
      it->ConsumeArgumentsElements(&type);
      return {AddNode(common.ArgumentsElementsState(type), {}),
              MachineType::AnyTagged()};
    }
    case Instr::kArgumentsLength: {
      it->ConsumeArgumentsLength();
      return {AddNode(common.ArgumentsLengthState(), {}),
              MachineType::AnyTagged()};
    }
    case Instr::kRestLength:
      // For now, kRestLength is only generated when using the Maglev frontend,
      // which doesn't use recreate-schedule.
      [[fallthrough]];
    case Instr::kDematerializedStringConcat:
      // Escaped StringConcat are not supported by the Turbofan instruction
      // selector.
      [[fallthrough]];
    case Instr::kUnusedRegister:
      UNREACHABLE();
  }
}

// Create a mostly balanced tree of `StateValues` nodes.
Node* ScheduleBuilder::BuildStateValues(FrameStateData::Iterator* it,
                                        int32_t size) {
  constexpr int32_t kMaxStateValueInputCount = 8;

  base::SmallVector<Node*, kMaxStateValueInputCount> inputs;
  base::SmallVector<MachineType, kMaxStateValueInputCount> types;
  SparseInputMask::BitMaskType input_mask = 0;
  int32_t child_size =
      (size + kMaxStateValueInputCount - 1) / kMaxStateValueInputCount;
  // `state_value_inputs` counts the number of inputs used for the current
  // `StateValues` node. It is gradually adjusted as nodes are shifted to lower
  // levels in the tree.
  int32_t state_value_inputs = size;
  int32_t mask_size = 0;
  for (int32_t i = 0; i < state_value_inputs; ++i) {
    DCHECK_LT(i, kMaxStateValueInputCount);
    ++mask_size;
    if (state_value_inputs <= kMaxStateValueInputCount) {
      // All the remaining inputs fit at the current level.
      if (it->current_instr() == FrameStateData::Instr::kUnusedRegister) {
        it->ConsumeUnusedRegister();
      } else {
        std::pair<Node*, MachineType> p = BuildDeoptInput(it);
        input_mask |= SparseInputMask::BitMaskType{1} << i;
        inputs.push_back(p.first);
        types.push_back(p.second);
      }
    } else {
      // We have too many inputs, so recursively create another `StateValues`
      // node.
      input_mask |= SparseInputMask::BitMaskType{1} << i;
      int32_t actual_child_size = std::min(child_size, state_value_inputs - i);
      inputs.push_back(BuildStateValues(it, actual_child_size));
      // This is a dummy type that shouldn't matter.
      types.push_back(MachineType::AnyTagged());
      // `child_size`-many inputs were shifted to the next level, being replaced
      // with 1 `StateValues` node.
      state_value_inputs = state_value_inputs - actual_child_size + 1;
    }
  }
  input_mask |= SparseInputMask::kEndMarker << mask_size;
  return AddNode(
      common.TypedStateValues(graph_zone->New<ZoneVector<MachineType>>(
                                  types.begin(), types.end(), graph_zone),
                              SparseInputMask(input_mask)),
      base::VectorOf(inputs));
}

Node* ScheduleBuilder::BuildTaggedInput(FrameStateData::Iterator* it) {
  std::pair<Node*, MachineType> p = BuildDeoptInput(it);
  DCHECK(p.second.IsTagged());
  return p.first;
}

Node* ScheduleBuilder::ProcessOperation(const FrameStateOp& op) {
  const FrameStateInfo& info = op.data->frame_state_info;
  auto it = op.data->iterator(op.state_values());

  Node* closure = BuildTaggedInput(&it);
  Node* parameter_state_values = BuildStateValues(&it, info.parameter_count());
  Node* context = BuildTaggedInput(&it);
  Node* register_state_values = BuildStateValues(&it, info.local_count());
  Node* accumulator_state_values = BuildStateValues(&it, info.stack_count());
  Node* parent =
      op.inlined ? GetNode(op.parent_frame_state()) : tf_graph->start();

  return AddNode(common.FrameState(info.bailout_id(), info.state_combine(),
                                   info.function_info()),
                 {parameter_state_values, register_state_values,
                  accumulator_state_values, context, closure, parent});
}
Node* ScheduleBuilder::ProcessOperation(const CallOp& op) {
  base::SmallVector<Node*, 16> inputs;
  inputs.push_back(GetNode(op.callee()));
  for (OpIndex i : op.arguments()) {
    inputs.push_back(GetNode(i));
  }
  if (op.HasFrameState()) {
    DCHECK(op.frame_state().valid());
    inputs.push_back(GetNode(op.frame_state().value()));
  }
  return AddNode(common.Call(op.descriptor->descriptor),
                 base::VectorOf(inputs));
}
Node* ScheduleBuilder::ProcessOperation(const CheckExceptionOp& op) {
  Node* call_node = GetNode(op.throwing_operation());
  DCHECK_EQ(call_node->opcode(), IrOpcode::kCall);

  // Re-building the IfSuccess/IfException mechanism.
  BasicBlock* success_block = GetBlock(*op.didnt_throw_block);
  BasicBlock* exception_block = GetBlock(*op.catch_block);
  exception_block->set_deferred(true);
  schedule->AddCall(current_block, call_node, success_block, exception_block);
  // Pass `call` as the control input of `IfSuccess` and as both the effect and
  // control input of `IfException`.
  Node* if_success = MakeNode(common.IfSuccess(), {call_node});
  Node* if_exception = MakeNode(common.IfException(), {call_node, call_node});
  schedule->AddNode(success_block, if_success);
  schedule->AddNode(exception_block, if_exception);
  current_block = nullptr;
  return nullptr;
}
Node* ScheduleBuilder::ProcessOperation(const CatchBlockBeginOp& op) {
  Node* if_exception = current_block->NodeAt(0);
  DCHECK(if_exception != nullptr &&
         if_exception->opcode() == IrOpcode::kIfException);
  return if_exception;
}
Node* ScheduleBuilder::ProcessOperation(const DidntThrowOp& op) {
  return GetNode(op.throwing_operation());
}
Node* ScheduleBuilder::ProcessOperation(const TailCallOp& op) {
  base::SmallVector<Node*, 16> inputs;
  inputs.push_back(GetNode(op.callee()));
  for (OpIndex i : op.arguments()) {
    inputs.push_back(GetNode(i));
  }
  Node* call = MakeNode(common.TailCall(op.descriptor->descriptor),
                        base::VectorOf(inputs));
  schedule->AddTailCall(current_block, call);
  current_block = nullptr;
  return nullptr;
}
Node* ScheduleBuilder::ProcessOperation(const UnreachableOp& op) {
  Node* node = MakeNode(common.Throw(), {});
  schedule->AddNode(current_block, MakeNode(common.Unreachable(), {}));
  schedule->AddThrow(current_block, node);
  current_block = nullptr;
  return nullptr;
}
Node* ScheduleBuilder::ProcessOperation(const ReturnOp& op) {
  base::SmallVector<Node*, 8> inputs = {GetNode(op.pop_count())};
  for (OpIndex i : op.return_values()) {
    inputs.push_back(GetNode(i));
  }
  Node* node =
      MakeNode(common.Return(static_cast<int>(op.return_values().size())),
               base::VectorOf(inputs));
  schedule->AddReturn(current_block, node);
  current_block = nullptr;
  return nullptr;
}
Node* ScheduleBuilder::ProcessOperation(const BranchOp& op) {
  Node* branch = MakeNode(common.Branch(op.hint), {GetNode(op.condition())});
  BasicBlock* true_block = GetBlock(*op.if_true);
  BasicBlock* false_block = GetBlock(*op.if_false);
  schedule->AddBranch(current_block, branch, true_block, false_block);
  schedule->AddNode(true_block, MakeNode(common.IfTrue(), {branch}));
  schedule->AddNode(false_block, MakeNode(common.IfFalse(), {branch}));
  switch (op.hint) {
    case BranchHint::kNone:
      break;
    case BranchHint::kTrue:
      false_block->set_deferred(true);
      break;
    case BranchHint::kFalse:
      true_block->set_deferred(true);
      break;
  }
  current_block = nullptr;
  return nullptr;
}
Node* ScheduleBuilder::ProcessOperation(const SwitchOp& op) {
  size_t succ_count = op.cases.size() + 1;
  Node* switch_node =
      MakeNode(common.Switch(succ_count), {GetNode(op.input())});

  base::SmallVector<BasicBlock*, 16> successors;
  for (SwitchOp::Case c : op.cases) {
    BasicBlock* case_block = GetBlock(*c.destination);
    successors.push_back(case_block);
    Node* case_node =
        MakeNode(common.IfValue(c.value, 0, c.hint), {switch_node});
    schedule->AddNode(case_block, case_node);
    if (c.hint == BranchHint::kFalse) {
      case_block->set_deferred(true);
    }
  }
  BasicBlock* default_block = GetBlock(*op.default_case);
  successors.push_back(default_block);
  schedule->AddNode(default_block,
                    MakeNode(common.IfDefault(op.default_hint), {switch_node}));
  if (op.default_hint == BranchHint::kFalse) {
    default_block->set_deferred(true);
  }

  schedule->AddSwitch(current_block, switch_node, successors.data(),
                      successors.size());
  current_block = nullptr;
  return nullptr;
}

Node* ScheduleBuilder::ProcessOperation(const DebugBreakOp& op) {
  return AddNode(machine.DebugBreak(), {});
}

Node* ScheduleBuilder::ProcessOperation(const LoadRootRegisterOp& op) {
  return AddNode(machine.LoadRootRegister(), {});
}

Node* ScheduleBuilder::ProcessOperation(const Word32PairBinopOp& op) {
  using Kind = Word32PairBinopOp::Kind;
  const Operator* pair_operator = nullptr;
  switch (op.kind) {
    case Kind::kAdd:
      pair_operator = machine.Int32PairAdd();
      break;
    case Kind::kSub:
      pair_operator = machine.Int32PairSub();
      break;
    case Kind::kMul:
      pair_operator = machine.Int32PairMul();
      break;
    case Kind::kShiftLeft:
      pair_operator = machine.Word32PairShl();
      break;
    case Kind::kShiftRightArithmetic:
      pair_operator = machine.Word32PairSar();
      break;
    case Kind::kShiftRightLogical:
      pair_operator = machine.Word32PairShr();
      break;
  }
  return AddNode(pair_operator,
                 {GetNode(op.left_low()), GetNode(op.left_high()),
                  GetNode(op.right_low()), GetNode(op.right_high())});
}

Node* ScheduleBuilder::ProcessOperation(const CommentOp& op) {
  return AddNode(machine.Comment(op.message), {});
}

Node* ScheduleBuilder::ProcessOperation(const AbortCSADcheckOp& op) {
  return AddNode(machine.AbortCSADcheck(), {GetNode(op.message())});
}

#ifdef V8_ENABLE_WEBASSEMBLY
Node* ScheduleBuilder::ProcessOperation(const Simd128ConstantOp& op) {
  return AddNode(machine.S128Const(op.value), {});
}

Node* ScheduleBuilder::ProcessOperation(const Simd128BinopOp& op) {
  switch (op.kind) {
#define HANDLE_KIND(kind)             \
  case Simd128BinopOp::Kind::k##kind: \
    return AddNode(machine.kind(), {GetNode(op.left()), GetNode(op.right())});
    FOREACH_SIMD_128_BINARY_OPCODE(HANDLE_KIND);
#undef HANDLE_KIND
  }
}

Node* ScheduleBuilder::ProcessOperation(const Simd128UnaryOp& op) {
  switch (op.kind) {
#define HANDLE_KIND(kind)             \
  case Simd128UnaryOp::Kind::k##kind: \
    return AddNode(machine.kind(), {GetNode(op.input())});
    FOREACH_SIMD_128_UNARY_OPCODE(HANDLE_KIND);
#undef HANDLE_KIND
  }
}

Node* ScheduleBuilder::ProcessOperation(const Simd128ReduceOp& op) {
  UNIMPLEMENTED();
}

Node* ScheduleBuilder::ProcessOperation(const Simd128ShiftOp& op) {
  switch (op.kind) {
#define HANDLE_KIND(kind)             \
  case Simd128ShiftOp::Kind::k##kind: \
    return AddNode(machine.kind(), {GetNode(op.input()), GetNode(op.shift())});
    FOREACH_SIMD_128_SHIFT_OPCODE(HANDLE_KIND);
#undef HANDLE_KIND
  }
}

Node* ScheduleBuilder::ProcessOperation(const Simd128TestOp& op) {
  switch (op.kind) {
#define HANDLE_KIND(kind)            \
  case Simd128TestOp::Kind::k##kind: \
    return AddNode(machine.kind(), {GetNode(op.input())});
    FOREACH_SIMD_128_TEST_OPCODE(HANDLE_KIND);
#undef HANDLE_KIND
  }
}

Node* ScheduleBuilder::ProcessOperation(const Simd128SplatOp& op) {
  switch (op.kind) {
#define HANDLE_KIND(kind)             \
  case Simd128SplatOp::Kind::k##kind: \
    return AddNode(machine.kind##Splat(), {GetNode(op.input())});
    FOREACH_SIMD_128_SPLAT_OPCODE(HANDLE_KIND);
#undef HANDLE_KIND
  }
}

Node* ScheduleBuilder::ProcessOperation(const Simd128TernaryOp& op) {
  switch (op.kind) {
#define HANDLE_KIND(kind)                                                      \
  case Simd128TernaryOp::Kind::k##kind:                                        \
    return AddNode(machine.kind(), {GetNode(op.first()), GetNode(op
```