Response:
My thinking process to answer the request goes like this:

1. **Understand the Core Request:** The main goal is to analyze the provided C++ code snippet from V8 and describe its functionality, considering its role in the V8 architecture, potential JavaScript connections, logic, and common errors. The prompt explicitly mentions it's part 9 of 11, implying a larger context.

2. **Identify the File's Purpose:** The file name `instruction-selector-arm64.cc` immediately suggests its role: selecting specific ARM64 instructions to implement higher-level operations. The directory `v8/src/compiler/backend/arm64/` reinforces this. It's part of the compiler's backend, responsible for generating machine code for the ARM64 architecture.

3. **Scan for Key Functionalities:** I'll go through the code, identifying the different `Visit...` methods. Each `Visit` method handles a specific IR (Intermediate Representation) node, representing an operation. I'll group these by the type of operation they perform (e.g., floating-point, atomic, SIMD).

4. **Categorize Functionalities:** Based on the `Visit` methods, I can create categories of functionalities:
    * **Floating-Point Operations:**  `Float64InsertLowWord32`, `Float64InsertHighWord32`, `Float64Neg`, `Float64Mul`. These manipulate 64-bit floating-point numbers.
    * **Memory Barriers:** `MemoryBarrier`. Ensures proper memory ordering.
    * **Atomic Operations:**  `Word32AtomicLoad/Store/Exchange/CompareExchange/BinaryOperation` and their 64-bit counterparts. These handle thread-safe memory operations.
    * **SIMD (Single Instruction, Multiple Data) Operations:**  A large section with functions like `S128Const`, `S128AndNot`, `S128And`, `S128Zero`, `I32x4DotI8x16AddS`, `I8x16BitMask`, `F64x2ExtractLane`, `F64x2ReplaceLane`, and many more. This indicates support for vectorized operations.
    * **Unimplemented/Unreachable:** `Int32AbsWithOverflow`, `Int64AbsWithOverflow`. These are explicitly marked as not implemented for this architecture (or potentially handled differently).

5. **Address Specific Instructions:**
    * **".tq" Check:** The code is `.cc`, so it's C++, not Torque. This part is straightforward.
    * **JavaScript Relationship:**  Think about which JavaScript features these low-level operations enable. Floating-point math, atomic operations for shared memory concurrency (like in SharedArrayBuffer), and SIMD for performance-critical array manipulations are the key connections. I'll provide concrete JavaScript examples.
    * **Code Logic and Assumptions:** Focus on the optimization patterns within the `Visit` methods. For example, the `Float64InsertHighWord32` and `Float64Neg/Mul` methods check for specific input node types (`kFloat64InsertLowWord32`, `kFloat64Mul`, `kFloat64Neg`) and the `CanCover` condition. This indicates peephole optimizations where sequences of IR nodes are combined into a single, more efficient instruction. I'll create hypothetical IR node structures as input and the resulting ARM64 instructions as output.
    * **Common Programming Errors:** Consider how misuse of the JavaScript features related to these operations could lead to errors. For atomic operations, race conditions are a prime example. For SIMD, incorrect usage of typed arrays or out-of-bounds access can occur.

6. **Synthesize the Functionalities:**  Based on the identified categories, I will write a concise summary of the file's purpose. It's about translating platform-independent IR into ARM64-specific instructions, focusing on efficiency and leveraging specific ARM64 features.

7. **Address the "Part 9 of 11" Context:** Since this is part of a larger sequence, I'll infer that the surrounding parts likely deal with other aspects of instruction selection or the overall compilation pipeline. I'll mention this in the summary.

8. **Review and Refine:**  Read through the generated answer, ensuring clarity, accuracy, and completeness. Check that all aspects of the prompt have been addressed. For example, ensure the JavaScript examples are clear and directly relate to the C++ code's functionality.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Focus only on individual `Visit` methods.
* **Correction:**  Realize the importance of grouping them into functional categories for a better overview.
* **Initial thought:** Simply state that it's for ARM64 instruction selection.
* **Correction:** Elaborate on the "why" – optimization, leveraging ARM64 features (like fused multiply-accumulate for floating-point or specific atomic instructions).
* **Initial thought:**  Provide very technical, low-level details about ARM64 instructions.
* **Correction:** Balance the technical details with higher-level explanations and JavaScript connections to make it understandable for a broader audience.
* **Initial thought:** Focus on simple examples for code logic.
* **Correction:** Choose examples that demonstrate the optimization patterns observed in the code (like instruction fusion).

By following this structured approach and incorporating self-correction, I can generate a comprehensive and informative answer that addresses all parts of the prompt.
这是一个V8源代码文件 `v8/src/compiler/backend/arm64/instruction-selector-arm64.cc`，它的主要功能是 **为 ARM64 架构选择合适的机器指令，以实现 V8 编译器生成的中间表示 (IR) 节点所代表的操作**。  它是 V8 编译器后端的一部分，负责将与平台无关的 IR 转换为目标架构（这里是 ARM64）的机器码。

下面列举一下它的具体功能：

1. **处理各种 IR 节点:** 文件中的每个 `Visit...` 函数都对应一种特定的 IR 节点类型，例如 `VisitFloat64Mul` 处理浮点数乘法操作的节点，`VisitWord32AtomicLoad` 处理 32 位原子加载操作的节点等等。

2. **指令选择:**  对于每个 IR 节点，`InstructionSelectorT` 类会根据当前架构（ARM64）的可用指令，选择最合适的机器指令来实现该操作。 这通常涉及到考虑性能、代码大小以及是否能够利用特殊的硬件特性。

3. **操作数生成:** `Arm64OperandGeneratorT` 类用于生成指令的操作数，例如寄存器、立即数或内存地址。

4. **指令发射:** `Emit` 函数用于将选择好的机器指令及其操作数添加到最终生成的代码中。

5. **优化:**  代码中包含一些针对特定 IR 节点组合的优化。例如，`VisitFloat64InsertHighWord32` 中检查前一个操作是否是 `Float64InsertLowWord32`，如果是，则可以合并成一个更高效的 `kArm64Bfi` 指令。`VisitFloat64Neg` 和 `VisitFloat64Mul` 中也展示了类似的模式，将 `neg` 和 `mul` 操作合并成 `fnmul` 指令。

6. **支持原子操作:** 文件中包含了处理各种原子操作的函数，例如加载、存储、交换和比较交换，并根据数据大小选择合适的原子指令。

7. **支持 SIMD (Single Instruction, Multiple Data) 操作:**  文件中大量 `Visit` 函数以 `VisitS128...`, `VisitI32x4...`, `VisitF64x2...` 等开头，这表明它支持 WebAssembly 的 SIMD 指令。这些函数负责将 SIMD 操作的 IR 节点转换为 ARM64 的 SIMD 指令 (例如 NEON 指令)。

8. **Turbofan 和 Turboshaft 支持:**  模板类 `InstructionSelectorT<Adapter>` 的使用表明该文件同时支持 V8 的两个编译器管道：Turbofan 和 Turboshaft。通过不同的 `Adapter` 实现，可以为不同的编译器生成相应的指令。

**关于源代码类型：**

`v8/src/compiler/backend/arm64/instruction-selector-arm64.cc` 以 `.cc` 结尾，因此它是一个 **C++ 源代码文件**，而不是 Torque 源代码。 Torque 源代码文件通常以 `.tq` 结尾。

**与 JavaScript 的关系及举例：**

虽然这个文件本身是 C++ 代码，但它直接关系到 JavaScript 代码的执行效率。  JavaScript 中的各种操作，最终都需要通过编译器转换成机器码来执行。  `instruction-selector-arm64.cc` 的功能就是确保在 ARM64 架构上，JavaScript 的操作能够被高效地执行。

例如，JavaScript 中的浮点数乘法操作 `a * b`：

```javascript
let a = 3.14;
let b = 2.71;
let result = a * b;
```

当 V8 编译这段 JavaScript 代码时，会生成一个表示浮点数乘法的 IR 节点。  `VisitFloat64Mul` 函数的任务就是将这个 IR 节点转换为对应的 ARM64 浮点数乘法指令，例如 `fmul d0, d1, d2` (具体指令可能因上下文而异)。

再例如，JavaScript 中的原子操作（使用 `SharedArrayBuffer` 和 `Atomics`）：

```javascript
const sab = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT * 1);
const view = new Int32Array(sab);

Atomics.add(view, 0, 5);
```

`VisitWord32AtomicAdd` 函数会负责为 `Atomics.add` 操作选择合适的 ARM64 原子加法指令。

对于 SIMD 操作，例如 WebAssembly 中的 SIMD 指令：

```javascript
// WebAssembly 代码 (示例)
// (local $a v128)
// (local $b v128)
// (v128.add $a $b)
```

当 V8 执行这段 WebAssembly 代码时，`VisitS128Add` 或 `VisitF32x4Add` 等函数会将 WebAssembly 的 SIMD 加法操作转换为 ARM64 的 NEON 加法指令，例如 `fadd v0.4s, v1.4s, v2.4s`。

**代码逻辑推理 (假设输入与输出):**

假设 `VisitFloat64InsertHighWord32` 的输入 IR 节点 `node` 代表一个将 64 位浮点数的高 32 位插入的操作，且其第一个输入 `left` 是一个 `Float64InsertLowWord32` 节点，第二个输入 `right` 是要插入的高 32 位的值。

**假设输入:**

* `node` 的类型是 `IrOpcode::kFloat64InsertHighWord32`
* `left` (node 的第一个输入) 的类型是 `IrOpcode::kFloat64InsertLowWord32`
* `right` (node 的第二个输入) 是包含高 32 位值的节点
* `right_of_left` (left 的第二个输入) 是包含低 32 位值的节点

**代码逻辑:**

代码会识别出这种模式 (`left->opcode() == IrOpcode::kFloat64InsertLowWord32 && CanCover(node, left)`)。这意味着我们先插入了低 32 位，然后要插入高 32 位。

**假设输出 (生成的 ARM64 指令):**

1. `Emit(kArm64Bfi, ...)`:  使用 `BFI` (Bitfield Insert) 指令，将 `right_of_left` (低 32 位) 插入到目标寄存器的低位，然后将 `right` (高 32 位) 插入到目标寄存器的高位。
2. `Emit(kArm64Float64MoveU64, ...)`: 将合并后的 64 位值从通用寄存器移动到浮点寄存器。

**用户常见的编程错误举例：**

虽然这个 C++ 文件不直接涉及用户编写的 JavaScript 代码，但它处理的底层操作与一些常见的 JavaScript 编程错误有关：

1. **浮点数精度问题:**  JavaScript 中的所有数字都是双精度浮点数。  如果用户期望高精度的计算，但由于浮点数的表示方式导致精度丢失，这与 `VisitFloat64Mul` 等函数处理的浮点数运算有关。

   ```javascript
   let a = 0.1;
   let b = 0.2;
   console.log(a + b); // 输出 0.30000000000000004，而不是 0.3
   ```

2. **并发编程中的数据竞争:** 如果用户在多线程环境中使用 `SharedArrayBuffer` 和 `Atomics` 不当，可能导致数据竞争。  例如，多个线程同时修改同一个内存位置，而没有使用适当的原子操作进行同步，这与 `VisitWord32AtomicStore` 等函数处理的原子操作有关。

   ```javascript
   const sab = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT * 1);
   const view = new Int32Array(sab);

   // 线程 1
   view[0]++;

   // 线程 2
   view[0]++;
   ```
   如果没有使用原子操作，最终结果可能不是预期的。

3. **SIMD 操作的类型错误:**  在使用 WebAssembly 的 SIMD 指令时，如果传递了错误类型的操作数，例如将浮点数向量传递给需要整数向量的操作，就会导致错误。这与 `VisitI32x4Add` 等函数处理的 SIMD 指令的类型检查有关。

**功能归纳 (作为第 9 部分):**

作为 11 个部分中的第 9 部分，`v8/src/compiler/backend/arm64/instruction-selector-arm64.cc` 的主要功能是 **V8 编译器后端中 ARM64 架构的指令选择器**。它负责将编译器生成的、与平台无关的中间表示 (IR) 节点转换为可以在 ARM64 处理器上执行的具体机器指令。  这个过程包括选择合适的指令、生成操作数，并进行一些针对 ARM64 架构的优化。  考虑到这是第 9 部分，可以推测之前的部分可能涉及 IR 的生成和优化，而后续的部分可能涉及指令的调度、寄存器分配和最终的代码生成。 这个文件是连接高级语言（JavaScript 或 WebAssembly）操作和底层硬件指令的关键桥梁。

Prompt: 
```
这是目录为v8/src/compiler/backend/arm64/instruction-selector-arm64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/arm64/instruction-selector-arm64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第9部分，共11部分，请归纳一下它的功能

"""
    Node* right_of_left = left->InputAt(1);
      Emit(kArm64Bfi, g.DefineSameAsFirst(left), g.UseRegister(right),
           g.UseRegister(right_of_left), g.TempImmediate(32),
           g.TempImmediate(32));
      Emit(kArm64Float64MoveU64, g.DefineAsRegister(node), g.UseRegister(left));
      return;
    }
    Emit(kArm64Float64InsertLowWord32, g.DefineSameAsFirst(node),
         g.UseRegister(left), g.UseRegister(right));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64InsertHighWord32(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    UNIMPLEMENTED();
  } else {
    Arm64OperandGeneratorT<Adapter> g(this);
    Node* left = node->InputAt(0);
    Node* right = node->InputAt(1);
    if (left->opcode() == IrOpcode::kFloat64InsertLowWord32 &&
        CanCover(node, left)) {
      Node* right_of_left = left->InputAt(1);
      Emit(kArm64Bfi, g.DefineSameAsFirst(left), g.UseRegister(right_of_left),
           g.UseRegister(right), g.TempImmediate(32), g.TempImmediate(32));
      Emit(kArm64Float64MoveU64, g.DefineAsRegister(node), g.UseRegister(left));
      return;
    }
    Emit(kArm64Float64InsertHighWord32, g.DefineSameAsFirst(node),
         g.UseRegister(left), g.UseRegister(right));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Neg(node_t node) {
  Arm64OperandGeneratorT<Adapter> g(this);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    OpIndex input = this->Get(node).input(0);
    const Operation& input_op = this->Get(input);
    if (input_op.Is<Opmask::kFloat64Mul>() && CanCover(node, input)) {
      const FloatBinopOp& mul = input_op.Cast<FloatBinopOp>();
      Emit(kArm64Float64Fnmul, g.DefineAsRegister(node),
           g.UseRegister(mul.left()), g.UseRegister(mul.right()));
      return;
    }
    VisitRR(this, kArm64Float64Neg, node);
  } else {
    Node* in = node->InputAt(0);
    if (in->opcode() == IrOpcode::kFloat64Mul && CanCover(node, in)) {
      Float64BinopMatcher m(in);
      Emit(kArm64Float64Fnmul, g.DefineAsRegister(node),
           g.UseRegister(m.left().node()), g.UseRegister(m.right().node()));
      return;
    }
    VisitRR(this, kArm64Float64Neg, node);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Mul(node_t node) {
  Arm64OperandGeneratorT<Adapter> g(this);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const FloatBinopOp& mul = this->Get(node).template Cast<FloatBinopOp>();
    const Operation& lhs = this->Get(mul.left());
    if (lhs.Is<Opmask::kFloat64Negate>() && CanCover(node, mul.left())) {
      Emit(kArm64Float64Fnmul, g.DefineAsRegister(node),
           g.UseRegister(lhs.input(0)), g.UseRegister(mul.right()));
      return;
    }

    const Operation& rhs = this->Get(mul.right());
    if (rhs.Is<Opmask::kFloat64Negate>() && CanCover(node, mul.right())) {
      Emit(kArm64Float64Fnmul, g.DefineAsRegister(node),
           g.UseRegister(rhs.input(0)), g.UseRegister(mul.left()));
      return;
    }
    return VisitRRR(this, kArm64Float64Mul, node);

  } else {
    Float64BinopMatcher m(node);

    if (m.left().IsFloat64Neg() && CanCover(node, m.left().node())) {
      Emit(kArm64Float64Fnmul, g.DefineAsRegister(node),
           g.UseRegister(m.left().node()->InputAt(0)),
           g.UseRegister(m.right().node()));
      return;
    }

    if (m.right().IsFloat64Neg() && CanCover(node, m.right().node())) {
      Emit(kArm64Float64Fnmul, g.DefineAsRegister(node),
           g.UseRegister(m.right().node()->InputAt(0)),
           g.UseRegister(m.left().node()));
      return;
    }
    return VisitRRR(this, kArm64Float64Mul, node);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitMemoryBarrier(node_t node) {
  // Use DMB ISH for both acquire-release and sequentially consistent barriers.
  Arm64OperandGeneratorT<Adapter> g(this);
  Emit(kArm64DmbIsh, g.NoOutput());
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicLoad(node_t node) {
  VisitAtomicLoad(this, node, AtomicWidth::kWord32);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64AtomicLoad(node_t node) {
  VisitAtomicLoad(this, node, AtomicWidth::kWord64);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicStore(node_t node) {
  VisitAtomicStore(this, node, AtomicWidth::kWord32);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64AtomicStore(node_t node) {
  VisitAtomicStore(this, node, AtomicWidth::kWord64);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord32AtomicExchange(
    node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const AtomicRMWOp& atomic_op = this->Get(node).template Cast<AtomicRMWOp>();
  ArchOpcode opcode;
  if (atomic_op.memory_rep == MemoryRepresentation::Int8()) {
    opcode = kAtomicExchangeInt8;
  } else if (atomic_op.memory_rep == MemoryRepresentation::Uint8()) {
    opcode = kAtomicExchangeUint8;
  } else if (atomic_op.memory_rep == MemoryRepresentation::Int16()) {
    opcode = kAtomicExchangeInt16;
  } else if (atomic_op.memory_rep == MemoryRepresentation::Uint16()) {
    opcode = kAtomicExchangeUint16;
  } else if (atomic_op.memory_rep == MemoryRepresentation::Int32() ||
             atomic_op.memory_rep == MemoryRepresentation::Uint32()) {
    opcode = kAtomicExchangeWord32;
  } else {
    UNREACHABLE();
  }
  VisitAtomicExchange(this, node, opcode, AtomicWidth::kWord32,
                      atomic_op.memory_access_kind);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitWord32AtomicExchange(
    Node* node) {
  ArchOpcode opcode;
  AtomicOpParameters params = AtomicOpParametersOf(node->op());
  if (params.type() == MachineType::Int8()) {
    opcode = kAtomicExchangeInt8;
  } else if (params.type() == MachineType::Uint8()) {
    opcode = kAtomicExchangeUint8;
  } else if (params.type() == MachineType::Int16()) {
    opcode = kAtomicExchangeInt16;
  } else if (params.type() == MachineType::Uint16()) {
    opcode = kAtomicExchangeUint16;
  } else if (params.type() == MachineType::Int32()
    || params.type() == MachineType::Uint32()) {
    opcode = kAtomicExchangeWord32;
  } else {
    UNREACHABLE();
  }
  VisitAtomicExchange(this, node, opcode, AtomicWidth::kWord32, params.kind());
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord64AtomicExchange(
    node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const AtomicRMWOp& atomic_op = this->Get(node).template Cast<AtomicRMWOp>();
  ArchOpcode opcode;
  if (atomic_op.memory_rep == MemoryRepresentation::Uint8()) {
    opcode = kAtomicExchangeUint8;
  } else if (atomic_op.memory_rep == MemoryRepresentation::Uint16()) {
    opcode = kAtomicExchangeUint16;
  } else if (atomic_op.memory_rep == MemoryRepresentation::Uint32()) {
    opcode = kAtomicExchangeWord32;
  } else if (atomic_op.memory_rep == MemoryRepresentation::Uint64()) {
    opcode = kArm64Word64AtomicExchangeUint64;
  } else {
    UNREACHABLE();
  }
  VisitAtomicExchange(this, node, opcode, AtomicWidth::kWord64,
                      atomic_op.memory_access_kind);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitWord64AtomicExchange(
    Node* node) {
  ArchOpcode opcode;
  AtomicOpParameters params = AtomicOpParametersOf(node->op());
  if (params.type() == MachineType::Uint8()) {
    opcode = kAtomicExchangeUint8;
  } else if (params.type() == MachineType::Uint16()) {
    opcode = kAtomicExchangeUint16;
  } else if (params.type() == MachineType::Uint32()) {
    opcode = kAtomicExchangeWord32;
  } else if (params.type() == MachineType::Uint64()) {
    opcode = kArm64Word64AtomicExchangeUint64;
  } else {
    UNREACHABLE();
  }
  VisitAtomicExchange(this, node, opcode, AtomicWidth::kWord64, params.kind());
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord32AtomicCompareExchange(
    node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const AtomicRMWOp& atomic_op = this->Get(node).template Cast<AtomicRMWOp>();
  ArchOpcode opcode;
  if (atomic_op.memory_rep == MemoryRepresentation::Int8()) {
    opcode = kAtomicCompareExchangeInt8;
  } else if (atomic_op.memory_rep == MemoryRepresentation::Uint8()) {
    opcode = kAtomicCompareExchangeUint8;
  } else if (atomic_op.memory_rep == MemoryRepresentation::Int16()) {
    opcode = kAtomicCompareExchangeInt16;
  } else if (atomic_op.memory_rep == MemoryRepresentation::Uint16()) {
    opcode = kAtomicCompareExchangeUint16;
  } else if (atomic_op.memory_rep == MemoryRepresentation::Int32() ||
             atomic_op.memory_rep == MemoryRepresentation::Uint32()) {
    opcode = kAtomicCompareExchangeWord32;
  } else {
    UNREACHABLE();
  }
  VisitAtomicCompareExchange(this, node, opcode, AtomicWidth::kWord32,
                             atomic_op.memory_access_kind);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitWord32AtomicCompareExchange(
    Node* node) {
  ArchOpcode opcode;
  AtomicOpParameters params = AtomicOpParametersOf(node->op());
  if (params.type() == MachineType::Int8()) {
    opcode = kAtomicCompareExchangeInt8;
  } else if (params.type() == MachineType::Uint8()) {
    opcode = kAtomicCompareExchangeUint8;
  } else if (params.type() == MachineType::Int16()) {
    opcode = kAtomicCompareExchangeInt16;
  } else if (params.type() == MachineType::Uint16()) {
    opcode = kAtomicCompareExchangeUint16;
  } else if (params.type() == MachineType::Int32()
    || params.type() == MachineType::Uint32()) {
    opcode = kAtomicCompareExchangeWord32;
  } else {
    UNREACHABLE();
  }
  VisitAtomicCompareExchange(this, node, opcode, AtomicWidth::kWord32,
                             params.kind());
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord64AtomicCompareExchange(
    node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const AtomicRMWOp& atomic_op = this->Get(node).template Cast<AtomicRMWOp>();
  ArchOpcode opcode;
  if (atomic_op.memory_rep == MemoryRepresentation::Uint8()) {
    opcode = kAtomicCompareExchangeUint8;
  } else if (atomic_op.memory_rep == MemoryRepresentation::Uint16()) {
    opcode = kAtomicCompareExchangeUint16;
  } else if (atomic_op.memory_rep == MemoryRepresentation::Uint32()) {
    opcode = kAtomicCompareExchangeWord32;
  } else if (atomic_op.memory_rep == MemoryRepresentation::Uint64()) {
    opcode = kArm64Word64AtomicCompareExchangeUint64;
  } else {
    UNREACHABLE();
  }
  VisitAtomicCompareExchange(this, node, opcode, AtomicWidth::kWord64,
                             atomic_op.memory_access_kind);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitWord64AtomicCompareExchange(
    Node* node) {
  ArchOpcode opcode;
  AtomicOpParameters params = AtomicOpParametersOf(node->op());
  if (params.type() == MachineType::Uint8()) {
    opcode = kAtomicCompareExchangeUint8;
  } else if (params.type() == MachineType::Uint16()) {
    opcode = kAtomicCompareExchangeUint16;
  } else if (params.type() == MachineType::Uint32()) {
    opcode = kAtomicCompareExchangeWord32;
  } else if (params.type() == MachineType::Uint64()) {
    opcode = kArm64Word64AtomicCompareExchangeUint64;
  } else {
    UNREACHABLE();
  }
  VisitAtomicCompareExchange(this, node, opcode, AtomicWidth::kWord64,
                             params.kind());
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicBinaryOperation(
    node_t node, ArchOpcode int8_op, ArchOpcode uint8_op, ArchOpcode int16_op,
    ArchOpcode uint16_op, ArchOpcode word32_op) {
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const AtomicRMWOp& atomic_op = this->Get(node).template Cast<AtomicRMWOp>();
    ArchOpcode opcode;
    if (atomic_op.memory_rep == MemoryRepresentation::Int8()) {
      opcode = int8_op;
    } else if (atomic_op.memory_rep == MemoryRepresentation::Uint8()) {
      opcode = uint8_op;
    } else if (atomic_op.memory_rep == MemoryRepresentation::Int16()) {
      opcode = int16_op;
    } else if (atomic_op.memory_rep == MemoryRepresentation::Uint16()) {
      opcode = uint16_op;
    } else if (atomic_op.memory_rep == MemoryRepresentation::Int32() ||
               atomic_op.memory_rep == MemoryRepresentation::Uint32()) {
      opcode = word32_op;
    } else {
      UNREACHABLE();
    }
    VisitAtomicBinop(this, node, opcode, AtomicWidth::kWord32,
                     atomic_op.memory_access_kind);
  } else {
    ArchOpcode opcode;
    AtomicOpParameters params = AtomicOpParametersOf(node->op());
    if (params.type() == MachineType::Int8()) {
      opcode = int8_op;
    } else if (params.type() == MachineType::Uint8()) {
      opcode = uint8_op;
    } else if (params.type() == MachineType::Int16()) {
      opcode = int16_op;
    } else if (params.type() == MachineType::Uint16()) {
      opcode = uint16_op;
    } else if (params.type() == MachineType::Int32() ||
               params.type() == MachineType::Uint32()) {
      opcode = word32_op;
    } else {
      UNREACHABLE();
    }
    VisitAtomicBinop(this, node, opcode, AtomicWidth::kWord32, params.kind());
  }
}

#define VISIT_ATOMIC_BINOP(op)                                             \
  template <typename Adapter>                                              \
  void InstructionSelectorT<Adapter>::VisitWord32Atomic##op(node_t node) { \
    VisitWord32AtomicBinaryOperation(                                      \
        node, kAtomic##op##Int8, kAtomic##op##Uint8, kAtomic##op##Int16,   \
        kAtomic##op##Uint16, kAtomic##op##Word32);                         \
  }
VISIT_ATOMIC_BINOP(Add)
VISIT_ATOMIC_BINOP(Sub)
VISIT_ATOMIC_BINOP(And)
VISIT_ATOMIC_BINOP(Or)
VISIT_ATOMIC_BINOP(Xor)
#undef VISIT_ATOMIC_BINOP

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64AtomicBinaryOperation(
    node_t node, ArchOpcode uint8_op, ArchOpcode uint16_op,
    ArchOpcode uint32_op, ArchOpcode uint64_op) {
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const AtomicRMWOp& atomic_op = this->Get(node).template Cast<AtomicRMWOp>();
    ArchOpcode opcode;
    if (atomic_op.memory_rep == MemoryRepresentation::Uint8()) {
      opcode = uint8_op;
    } else if (atomic_op.memory_rep == MemoryRepresentation::Uint16()) {
      opcode = uint16_op;
    } else if (atomic_op.memory_rep == MemoryRepresentation::Uint32()) {
      opcode = uint32_op;
    } else if (atomic_op.memory_rep == MemoryRepresentation::Uint64()) {
      opcode = uint64_op;
    } else {
      UNREACHABLE();
    }
    VisitAtomicBinop(this, node, opcode, AtomicWidth::kWord64,
                     atomic_op.memory_access_kind);
  } else {
    ArchOpcode opcode;
    AtomicOpParameters params = AtomicOpParametersOf(node->op());
    if (params.type() == MachineType::Uint8()) {
      opcode = uint8_op;
    } else if (params.type() == MachineType::Uint16()) {
      opcode = uint16_op;
    } else if (params.type() == MachineType::Uint32()) {
      opcode = uint32_op;
    } else if (params.type() == MachineType::Uint64()) {
      opcode = uint64_op;
    } else {
      UNREACHABLE();
    }
    VisitAtomicBinop(this, node, opcode, AtomicWidth::kWord64, params.kind());
  }
}

#define VISIT_ATOMIC_BINOP(op)                                                 \
  template <typename Adapter>                                                  \
  void InstructionSelectorT<Adapter>::VisitWord64Atomic##op(node_t node) {     \
    VisitWord64AtomicBinaryOperation(node, kAtomic##op##Uint8,                 \
                                     kAtomic##op##Uint16, kAtomic##op##Word32, \
                                     kArm64Word64Atomic##op##Uint64);          \
  }
VISIT_ATOMIC_BINOP(Add)
VISIT_ATOMIC_BINOP(Sub)
VISIT_ATOMIC_BINOP(And)
VISIT_ATOMIC_BINOP(Or)
VISIT_ATOMIC_BINOP(Xor)
#undef VISIT_ATOMIC_BINOP

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32AbsWithOverflow(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64AbsWithOverflow(node_t node) {
  UNREACHABLE();
}

#if V8_ENABLE_WEBASSEMBLY
#define SIMD_UNOP_LIST(V)                                       \
  V(F64x2ConvertLowI32x4S, kArm64F64x2ConvertLowI32x4S)         \
  V(F64x2ConvertLowI32x4U, kArm64F64x2ConvertLowI32x4U)         \
  V(F64x2PromoteLowF32x4, kArm64F64x2PromoteLowF32x4)           \
  V(F32x4SConvertI32x4, kArm64F32x4SConvertI32x4)               \
  V(F32x4UConvertI32x4, kArm64F32x4UConvertI32x4)               \
  V(F32x4DemoteF64x2Zero, kArm64F32x4DemoteF64x2Zero)           \
  V(F16x8SConvertI16x8, kArm64F16x8SConvertI16x8)               \
  V(F16x8UConvertI16x8, kArm64F16x8UConvertI16x8)               \
  V(I16x8SConvertF16x8, kArm64I16x8SConvertF16x8)               \
  V(I16x8UConvertF16x8, kArm64I16x8UConvertF16x8)               \
  V(F16x8DemoteF32x4Zero, kArm64F16x8DemoteF32x4Zero)           \
  V(F16x8DemoteF64x2Zero, kArm64F16x8DemoteF64x2Zero)           \
  V(F32x4PromoteLowF16x8, kArm64F32x4PromoteLowF16x8)           \
  V(I64x2BitMask, kArm64I64x2BitMask)                           \
  V(I32x4SConvertF32x4, kArm64I32x4SConvertF32x4)               \
  V(I32x4UConvertF32x4, kArm64I32x4UConvertF32x4)               \
  V(I32x4RelaxedTruncF32x4S, kArm64I32x4SConvertF32x4)          \
  V(I32x4RelaxedTruncF32x4U, kArm64I32x4UConvertF32x4)          \
  V(I32x4BitMask, kArm64I32x4BitMask)                           \
  V(I32x4TruncSatF64x2SZero, kArm64I32x4TruncSatF64x2SZero)     \
  V(I32x4TruncSatF64x2UZero, kArm64I32x4TruncSatF64x2UZero)     \
  V(I32x4RelaxedTruncF64x2SZero, kArm64I32x4TruncSatF64x2SZero) \
  V(I32x4RelaxedTruncF64x2UZero, kArm64I32x4TruncSatF64x2UZero) \
  V(I16x8BitMask, kArm64I16x8BitMask)                           \
  V(S128Not, kArm64S128Not)                                     \
  V(V128AnyTrue, kArm64V128AnyTrue)                             \
  V(I64x2AllTrue, kArm64I64x2AllTrue)                           \
  V(I32x4AllTrue, kArm64I32x4AllTrue)                           \
  V(I16x8AllTrue, kArm64I16x8AllTrue)                           \
  V(I8x16AllTrue, kArm64I8x16AllTrue)

#define SIMD_UNOP_LANE_SIZE_LIST(V) \
  V(F64x2Splat, kArm64FSplat, 64)   \
  V(F64x2Abs, kArm64FAbs, 64)       \
  V(F64x2Sqrt, kArm64FSqrt, 64)     \
  V(F64x2Neg, kArm64FNeg, 64)       \
  V(F32x4Splat, kArm64FSplat, 32)   \
  V(F32x4Abs, kArm64FAbs, 32)       \
  V(F32x4Sqrt, kArm64FSqrt, 32)     \
  V(F32x4Neg, kArm64FNeg, 32)       \
  V(I64x2Splat, kArm64ISplat, 64)   \
  V(I64x2Abs, kArm64IAbs, 64)       \
  V(I64x2Neg, kArm64INeg, 64)       \
  V(I32x4Splat, kArm64ISplat, 32)   \
  V(I32x4Abs, kArm64IAbs, 32)       \
  V(I32x4Neg, kArm64INeg, 32)       \
  V(F16x8Splat, kArm64FSplat, 16)   \
  V(F16x8Abs, kArm64FAbs, 16)       \
  V(F16x8Sqrt, kArm64FSqrt, 16)     \
  V(F16x8Neg, kArm64FNeg, 16)       \
  V(I16x8Splat, kArm64ISplat, 16)   \
  V(I16x8Abs, kArm64IAbs, 16)       \
  V(I16x8Neg, kArm64INeg, 16)       \
  V(I8x16Splat, kArm64ISplat, 8)    \
  V(I8x16Abs, kArm64IAbs, 8)        \
  V(I8x16Neg, kArm64INeg, 8)

#define SIMD_SHIFT_OP_LIST(V) \
  V(I64x2Shl, 64)             \
  V(I64x2ShrS, 64)            \
  V(I64x2ShrU, 64)            \
  V(I32x4Shl, 32)             \
  V(I32x4ShrS, 32)            \
  V(I32x4ShrU, 32)            \
  V(I16x8Shl, 16)             \
  V(I16x8ShrS, 16)            \
  V(I16x8ShrU, 16)            \
  V(I8x16Shl, 8)              \
  V(I8x16ShrS, 8)             \
  V(I8x16ShrU, 8)

#define SIMD_BINOP_LIST(V)                        \
  V(I32x4Mul, kArm64I32x4Mul)                     \
  V(I32x4DotI16x8S, kArm64I32x4DotI16x8S)         \
  V(I16x8DotI8x16I7x16S, kArm64I16x8DotI8x16S)    \
  V(I16x8SConvertI32x4, kArm64I16x8SConvertI32x4) \
  V(I16x8Mul, kArm64I16x8Mul)                     \
  V(I16x8UConvertI32x4, kArm64I16x8UConvertI32x4) \
  V(I16x8Q15MulRSatS, kArm64I16x8Q15MulRSatS)     \
  V(I16x8RelaxedQ15MulRS, kArm64I16x8Q15MulRSatS) \
  V(I8x16SConvertI16x8, kArm64I8x16SConvertI16x8) \
  V(I8x16UConvertI16x8, kArm64I8x16UConvertI16x8) \
  V(S128Or, kArm64S128Or)                         \
  V(S128Xor, kArm64S128Xor)

#define SIMD_BINOP_LANE_SIZE_LIST(V)                   \
  V(F64x2Min, kArm64FMin, 64)                          \
  V(F64x2Max, kArm64FMax, 64)                          \
  V(F64x2Add, kArm64FAdd, 64)                          \
  V(F64x2Sub, kArm64FSub, 64)                          \
  V(F64x2Div, kArm64FDiv, 64)                          \
  V(F64x2RelaxedMin, kArm64FMin, 64)                   \
  V(F64x2RelaxedMax, kArm64FMax, 64)                   \
  V(F32x4Min, kArm64FMin, 32)                          \
  V(F32x4Max, kArm64FMax, 32)                          \
  V(F32x4Add, kArm64FAdd, 32)                          \
  V(F32x4Sub, kArm64FSub, 32)                          \
  V(F32x4Div, kArm64FDiv, 32)                          \
  V(F32x4RelaxedMin, kArm64FMin, 32)                   \
  V(F32x4RelaxedMax, kArm64FMax, 32)                   \
  V(F16x8Add, kArm64FAdd, 16)                          \
  V(F16x8Sub, kArm64FSub, 16)                          \
  V(F16x8Div, kArm64FDiv, 16)                          \
  V(F16x8Min, kArm64FMin, 16)                          \
  V(F16x8Max, kArm64FMax, 16)                          \
  V(I64x2Sub, kArm64ISub, 64)                          \
  V(I32x4GtU, kArm64IGtU, 32)                          \
  V(I32x4GeU, kArm64IGeU, 32)                          \
  V(I32x4MinS, kArm64IMinS, 32)                        \
  V(I32x4MaxS, kArm64IMaxS, 32)                        \
  V(I32x4MinU, kArm64IMinU, 32)                        \
  V(I32x4MaxU, kArm64IMaxU, 32)                        \
  V(I16x8AddSatS, kArm64IAddSatS, 16)                  \
  V(I16x8SubSatS, kArm64ISubSatS, 16)                  \
  V(I16x8AddSatU, kArm64IAddSatU, 16)                  \
  V(I16x8SubSatU, kArm64ISubSatU, 16)                  \
  V(I16x8GtU, kArm64IGtU, 16)                          \
  V(I16x8GeU, kArm64IGeU, 16)                          \
  V(I16x8RoundingAverageU, kArm64RoundingAverageU, 16) \
  V(I8x16RoundingAverageU, kArm64RoundingAverageU, 8)  \
  V(I16x8MinS, kArm64IMinS, 16)                        \
  V(I16x8MaxS, kArm64IMaxS, 16)                        \
  V(I16x8MinU, kArm64IMinU, 16)                        \
  V(I16x8MaxU, kArm64IMaxU, 16)                        \
  V(I8x16Sub, kArm64ISub, 8)                           \
  V(I8x16AddSatS, kArm64IAddSatS, 8)                   \
  V(I8x16SubSatS, kArm64ISubSatS, 8)                   \
  V(I8x16AddSatU, kArm64IAddSatU, 8)                   \
  V(I8x16SubSatU, kArm64ISubSatU, 8)                   \
  V(I8x16GtU, kArm64IGtU, 8)                           \
  V(I8x16GeU, kArm64IGeU, 8)                           \
  V(I8x16MinS, kArm64IMinS, 8)                         \
  V(I8x16MaxS, kArm64IMaxS, 8)                         \
  V(I8x16MinU, kArm64IMinU, 8)                         \
  V(I8x16MaxU, kArm64IMaxU, 8)

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitS128Const(node_t node) {
  Arm64OperandGeneratorT<Adapter> g(this);
  static const int kUint32Immediates = 4;
  uint32_t val[kUint32Immediates];
  static_assert(sizeof(val) == kSimd128Size);
  if constexpr (Adapter::IsTurboshaft) {
    const turboshaft::Simd128ConstantOp& constant =
        this->Get(node).template Cast<turboshaft::Simd128ConstantOp>();
    memcpy(val, constant.value, kSimd128Size);
  } else {
    memcpy(val, S128ImmediateParameterOf(node->op()).data(), kSimd128Size);
  }
  Emit(kArm64S128Const, g.DefineAsRegister(node), g.UseImmediate(val[0]),
       g.UseImmediate(val[1]), g.UseImmediate(val[2]), g.UseImmediate(val[3]));
}

namespace {

struct BicImmParam {
  BicImmParam(uint32_t imm, uint8_t lane_size, uint8_t shift_amount)
      : imm(imm), lane_size(lane_size), shift_amount(shift_amount) {}
  uint8_t imm;
  uint8_t lane_size;
  uint8_t shift_amount;
};

template <typename node_t>
struct BicImmResult {
  BicImmResult(std::optional<BicImmParam> param, node_t const_node,
               node_t other_node)
      : param(param), const_node(const_node), other_node(other_node) {}
  std::optional<BicImmParam> param;
  node_t const_node;
  node_t other_node;
};

std::optional<BicImmParam> BicImm16bitHelper(uint16_t val) {
  uint8_t byte0 = val & 0xFF;
  uint8_t byte1 = val >> 8;
  // Cannot use Bic if both bytes are not 0x00
  if (byte0 == 0x00) {
    return BicImmParam(byte1, 16, 8);
  }
  if (byte1 == 0x00) {
    return BicImmParam(byte0, 16, 0);
  }
  return std::nullopt;
}

std::optional<BicImmParam> BicImm32bitHelper(uint32_t val) {
  for (int i = 0; i < 4; i++) {
    // All bytes are 0 but one
    if ((val & (0xFF << (8 * i))) == val) {
      return BicImmParam(static_cast<uint8_t>(val >> i * 8), 32, i * 8);
    }
  }
  // Low and high 2 bytes are equal
  if ((val >> 16) == (0xFFFF & val)) {
    return BicImm16bitHelper(0xFFFF & val);
  }
  return std::nullopt;
}

std::optional<BicImmParam> BicImmConstHelper(Node* const_node, bool not_imm) {
  const int kUint32Immediates = 4;
  uint32_t val[kUint32Immediates];
  static_assert(sizeof(val) == kSimd128Size);
  memcpy(val, S128ImmediateParameterOf(const_node->op()).data(), kSimd128Size);
  // If 4 uint32s are not the same, cannot emit Bic
  if (!(val[0] == val[1] && val[1] == val[2] && val[2] == val[3])) {
    return std::nullopt;
  }
  return BicImm32bitHelper(not_imm ? ~val[0] : val[0]);
}

std::optional<BicImmParam> BicImmConstHelper(const turboshaft::Operation& op,
                                             bool not_imm) {
  const int kUint32Immediates = 4;
  uint32_t val[kUint32Immediates];
  static_assert(sizeof(val) == kSimd128Size);
  memcpy(val, op.Cast<turboshaft::Simd128ConstantOp>().value, kSimd128Size);
  // If 4 uint32s are not the same, cannot emit Bic
  if (!(val[0] == val[1] && val[1] == val[2] && val[2] == val[3])) {
    return std::nullopt;
  }
  return BicImm32bitHelper(not_imm ? ~val[0] : val[0]);
}

std::optional<BicImmResult<turboshaft::OpIndex>> BicImmHelper(
    InstructionSelectorT<TurboshaftAdapter>* selector,
    turboshaft::OpIndex and_node, bool not_imm) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const Simd128BinopOp& op = selector->Get(and_node).Cast<Simd128BinopOp>();
  // If we are negating the immediate then we are producing And(x, imm), and so
  // can take the immediate from the left or right input. Otherwise we are
  // producing And(x, Not(imm)), which can only be used when the immediate is
  // the right (negated) input.
  if (not_imm && selector->Get(op.left()).Is<Simd128ConstantOp>()) {
    return BicImmResult<OpIndex>(
        BicImmConstHelper(selector->Get(op.left()), not_imm), op.left(),
        op.right());
  }
  if (selector->Get(op.right()).Is<Simd128ConstantOp>()) {
    return BicImmResult<OpIndex>(
        BicImmConstHelper(selector->Get(op.right()), not_imm), op.right(),
        op.left());
  }
  return std::nullopt;
}

std::optional<BicImmResult<Node*>> BicImmHelper(
    InstructionSelectorT<TurbofanAdapter>* selector, Node* and_node,
    bool not_imm) {
  Node* left = and_node->InputAt(0);
  Node* right = and_node->InputAt(1);
  // If we are negating the immediate then we are producing And(x, imm), and so
  // can take the immediate from the left or right input. Otherwise we are
  // producing And(x, Not(imm)), which can only be used when the immediate is
  // the right (negated) input.
  if (not_imm && left->opcode() == IrOpcode::kS128Const) {
    return BicImmResult<Node*>(BicImmConstHelper(left, not_imm), left, right);
  }
  if (right->opcode() == IrOpcode::kS128Const) {
    return BicImmResult<Node*>(BicImmConstHelper(right, not_imm), right, left);
  }
  return std::nullopt;
}

template <typename Adapter>
bool TryEmitS128AndNotImm(InstructionSelectorT<Adapter>* selector,
                          typename Adapter::node_t node, bool not_imm) {
  Arm64OperandGeneratorT<Adapter> g(selector);
  std::optional<BicImmResult<typename Adapter::node_t>> result =
      BicImmHelper(selector, node, not_imm);
  if (!result.has_value()) return false;
  std::optional<BicImmParam> param = result->param;
  if (param.has_value()) {
    if (selector->CanCover(node, result->other_node)) {
      selector->Emit(
          kArm64S128AndNot | LaneSizeField::encode(param->lane_size),
          g.DefineSameAsFirst(node), g.UseRegister(result->other_node),
          g.UseImmediate(param->imm), g.UseImmediate(param->shift_amount));
      return true;
    }
  }
  return false;
}

}  // namespace

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitS128AndNot(node_t node) {
  if (!TryEmitS128AndNotImm(this, node, false)) {
    VisitRRR(this, kArm64S128AndNot, node);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitS128And(node_t node) {
  // AndNot can be used if we negate the immediate input of And.
  if (!TryEmitS128AndNotImm(this, node, true)) {
    VisitRRR(this, kArm64S128And, node);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitS128Zero(node_t node) {
  Arm64OperandGeneratorT<Adapter> g(this);
  Emit(kArm64S128Const, g.DefineAsRegister(node), g.UseImmediate(0),
       g.UseImmediate(0), g.UseImmediate(0), g.UseImmediate(0));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4DotI8x16I7x16AddS(node_t node) {
  Arm64OperandGeneratorT<Adapter> g(this);
  InstructionOperand output = CpuFeatures::IsSupported(DOTPROD)
                                  ? g.DefineSameAsInput(node, 2)
                                  : g.DefineAsRegister(node);
  Emit(kArm64I32x4DotI8x16AddS, output, g.UseRegister(this->input_at(node, 0)),
       g.UseRegister(this->input_at(node, 1)),
       g.UseRegister(this->input_at(node, 2)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI8x16BitMask(node_t node) {
  Arm64OperandGeneratorT<Adapter> g(this);
  InstructionOperand temps[1];
  size_t temp_count = 0;

  if (CpuFeatures::IsSupported(PMULL1Q)) {
    temps[0] = g.TempSimd128Register();
    temp_count = 1;
  }

  Emit(kArm64I8x16BitMask, g.DefineAsRegister(node),
       g.UseRegister(this->input_at(node, 0)), temp_count, temps);
}

#define SIMD_VISIT_EXTRACT_LANE(Type, T, Sign, LaneSize)                     \
  template <typename Adapter>                                                \
  void InstructionSelectorT<Adapter>::Visit##Type##ExtractLane##Sign(        \
      node_t node) {                                                         \
    VisitRRI(this,                                                           \
             kArm64##T##ExtractLane##Sign | LaneSizeField::encode(LaneSize), \
             node);                                                          \
  }
SIMD_VISIT_EXTRACT_LANE(F64x2, F, , 64)
SIMD_VISIT_EXTRACT_LANE(F32x4, F, , 32)
SIMD_VISIT_EXTRACT_LANE(F16x8, F, , 16)
SIMD_VISIT_EXTRACT_LANE(I64x2, I, , 64)
SIMD_VISIT_EXTRACT_LANE(I32x4, I, , 32)
SIMD_VISIT_EXTRACT_LANE(I16x8, I, U, 16)
SIMD_VISIT_EXTRACT_LANE(I16x8, I, S, 16)
SIMD_VISIT_EXTRACT_LANE(I8x16, I, U, 8)
SIMD_VISIT_EXTRACT_LANE(I8x16, I, S, 8)
#undef SIMD_VISIT_EXTRACT_LANE

#define SIMD_VISIT_REPLACE_LANE(Type, T, LaneSize)                            \
  template <typename Adapter>                                                 \
  void InstructionSelectorT<Adapter>::Visit##Type##ReplaceLane(node_t node) { \
    VisitRRIR(this, kArm64##T##ReplaceLane | LaneSizeField::encode(LaneSize), \
              node);                                                          \
  }
SIMD_VISIT_REPLACE_LANE(F64x2, F, 64)
SIMD_VISIT_REPLACE_LANE(F32x4, F, 32)
SIMD_VISIT_REPLACE_LANE(F16x8, F, 16)
SIMD_VISIT_REPLACE_LANE(I64x2, I, 64)
SIMD_VISIT_REPLACE_LANE(I32x4, I, 32)
SIMD_VISIT_REPLACE_LANE(I16x8, I, 16)
SIMD_VISIT_REPLACE_LANE(I8x16, I, 8)
#undef SIMD_VISIT_REPLACE_LANE

#define SIMD_VISIT_UNOP(Name, instruction)                       \
  template <typename Adapter>                                    \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) { \
    VisitRR(this, instruction, node);                            \
  }
SIMD_UNOP_LIST(SIMD_VISIT_UNOP)
#undef SIMD_VISIT_UNOP
#undef SIMD_UNOP_LIST

#define SIMD_VISIT_SHIFT_OP(Name, width)                         \
  template <typename Adapter>                                    \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) { \
    VisitSimdShiftRRR(this, kArm64##Name, node, width);          \
  }
SIM
"""


```