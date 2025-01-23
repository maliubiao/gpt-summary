Response: My thinking process to summarize the C++ code snippet goes like this:

1. **Identify the core task:** The file name "instruction-selector-arm64.cc" and the class name `InstructionSelectorT` strongly suggest this code is responsible for *selecting* specific ARM64 instructions based on higher-level operations. This is a crucial step in a compiler's backend.

2. **Look for key methods/patterns:**  I scan the code for recurring patterns and function names. The `Visit...` methods are immediately apparent. These likely correspond to different intermediate representation (IR) node types or operations. The template structure `template <typename Adapter>` indicates flexibility to work with different IRs (like Turbofan and Turboshaft).

3. **Focus on the operations being handled:**  I examine the `Visit...` methods to see what kinds of operations are being translated to ARM64 instructions. I see:
    * Floating-point operations (`Float64InsertLowWord32`, `Float64InsertHighWord32`, `Float64Neg`, `Float64Mul`).
    * Memory barriers (`MemoryBarrier`).
    * Atomic operations (`Word32AtomicLoad`, `Word64AtomicLoad`, `Word32AtomicStore`, `Word64AtomicStore`, `Word32AtomicExchange`, `Word64AtomicExchange`, `Word32AtomicCompareExchange`, `Word64AtomicCompareExchange`, and various atomic binary operations like `Add`, `Sub`, `And`, `Or`, `Xor`).
    * SIMD (Single Instruction, Multiple Data) operations (starting with `#if V8_ENABLE_WEBASSEMBLY`). These include `S128Const`, `S128AndNot`, `S128And`, `S128Zero`, `I32x4DotI8x16I7x16AddS`, `I8x16BitMask`, `ExtractLane`, `ReplaceLane`, and numerous other SIMD arithmetic, logical, and comparison operations.

4. **Infer the role of the "Adapter":** The template parameter `Adapter` is used extensively. The code comments and conditional compilation (`if constexpr (Adapter::IsTurboshaft)`) suggest that this class is designed to work with different compilation pipelines or IR representations (Turbofan and Turboshaft being explicitly mentioned). The adapter likely provides an interface to access the specifics of each IR.

5. **Consider the relationship with JavaScript:**  Since this is part of V8, the JavaScript engine, the operations being handled are ultimately derived from JavaScript code. Atomic operations are relevant for shared memory concurrency. SIMD operations are increasingly used in JavaScript for performance-critical tasks, often related to graphics, audio, and data processing.

6. **Formulate the summary:** Based on the observations above, I can construct a summary that highlights the core function of the code: selecting ARM64 instructions for various operations. I'll then elaborate on the specific categories of operations handled (float, atomic, SIMD) and the role of the adapter.

7. **Construct the JavaScript example:** To illustrate the connection with JavaScript, I choose a simple example that directly maps to one of the handled operations. A SIMD addition (`Float32x4`) is a good choice because it's relatively easy to understand and demonstrates how JavaScript can leverage these low-level optimizations.

8. **Review and refine:** I read through the summary and the JavaScript example to ensure they are clear, concise, and accurate. I double-check that the example aligns with the operations identified in the C++ code. I also make sure to address the "part 5 of 6" instruction by noting that this snippet represents a portion of the overall instruction selection process.

By following these steps, I arrive at the kind of detailed and informative summary you provided as the initial prompt. The key is to understand the context (compiler backend), identify the recurring patterns (Visit methods), categorize the operations, and connect it back to the higher-level language (JavaScript).
这个C++源代码文件是V8 JavaScript引擎中针对ARM64架构的**指令选择器（Instruction Selector）**的其中一部分（第五部分）。

它的主要功能是：

**将中间表示（IR）节点转换为具体的ARM64机器指令。**

更具体地说，这部分代码负责处理以下类型的操作（IR节点）：

* **浮点数操作 (Float64):**
    * `Float64InsertLowWord32`: 将一个32位字插入到64位浮点数的低位部分。
    * `Float64InsertHighWord32`: 将一个32位字插入到64位浮点数的高位部分。
    * `Float64Neg`:  对64位浮点数取反。
    * `Float64Mul`:  执行64位浮点数乘法。

* **内存屏障 (MemoryBarrier):**  插入一个内存屏障指令，确保内存操作的顺序。

* **原子操作 (Atomic Operations):**
    * `Word32AtomicLoad`, `Word64AtomicLoad`: 原子加载32位或64位的值。
    * `Word32AtomicStore`, `Word64AtomicStore`: 原子存储32位或64位的值。
    * `Word32AtomicExchange`, `Word64AtomicExchange`: 原子交换32位或64位的值。
    * `Word32AtomicCompareExchange`, `Word64AtomicCompareExchange`: 原子比较并交换32位或64位的值。
    * `Word32AtomicAdd`, `Word32AtomicSub`, `Word32AtomicAnd`, `Word32AtomicOr`, `Word32AtomicXor`:  原子执行32位加、减、与、或、异或操作。
    * `Word64AtomicAdd`, `Word64AtomicSub`, `Word64AtomicAnd`, `Word64AtomicOr`, `Word64AtomicXor`:  原子执行64位加、减、与、或、异或操作。

* **SIMD (Single Instruction, Multiple Data) 操作 (当 `V8_ENABLE_WEBASSEMBLY` 宏定义存在时):**  这是针对WebAssembly中SIMD指令的支持，包括：
    * **类型转换和转换：**  例如 `F64x2ConvertLowI32x4S`, `F32x4SConvertI32x4` 等。
    * **基本运算：** 例如 `S128Not`, `I32x4Mul`, `S128Or`, `F64x2Min`, `I32x4Add` 等。
    * **常数加载：** `S128Const`.
    * **按位与非：** `S128AndNot`.
    * **按位与：** `S128And`.
    * **零值：** `S128Zero`.
    * **点积：** `I32x4DotI8x16I7x16AddS`.
    * **位掩码：** `I8x16BitMask`, `I64x2BitMask`, `I32x4BitMask`, `I16x8BitMask`.
    * **车道操作：**  `...ExtractLane...`, `...ReplaceLane...`.
    * **选择：** `S128Select`, `I8x16RelaxedLaneSelect`.
    * **规约操作：** `I8x16AddReduce`, `F32x4AddReducePairwise` 等。
    * **比较操作：** `F64x2Eq`, `I32x4GtU` 等。

**与 JavaScript 的关系：**

这段代码直接影响 V8 执行 JavaScript 的效率。JavaScript 引擎在执行代码时，会将 JavaScript 代码转换为中间表示（IR），然后指令选择器会将这些 IR 节点翻译成特定架构（例如 ARM64）的机器指令。

**JavaScript 示例：**

```javascript
// 浮点数操作
let a = 1.5;
let b = -a; // 对应 VisitFloat64Neg
let c = a * 2.0; // 对应 VisitFloat64Mul

// 原子操作 (需要 SharedArrayBuffer 和 Atomics API)
const sab = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT * 1);
const view = new Int32Array(sab);
Atomics.add(view, 0, 5); // 对应 VisitWord32AtomicAdd

// SIMD 操作 (需要使用 Typed Arrays 的 SIMD 类型)
let a4 = Float32x4(1, 2, 3, 4);
let b4 = Float32x4(5, 6, 7, 8);
let c4 = Float32x4.mul(a4, b4); // 对应 VisitF32x4Mul

// WebAssembly SIMD (需要在 WebAssembly 模块中使用)
// ... (WebAssembly 代码中使用 i32x4.mul 等指令)
```

**总结一下，这部分指令选择器代码是 V8 编译 JavaScript 代码到 ARM64 机器码的关键组成部分，它负责将各种高级操作（包括浮点数、原子操作和 SIMD）转换为可以在 ARM64 处理器上执行的低级指令，从而实现 JavaScript 代码的执行。**

作为第六部分之前的第五部分，可以推断，这个文件负责处理一部分指令的选择工作，剩下的指令选择工作将在第六部分中完成。 不同的部分可能负责处理不同类型的 IR 节点或优化策略。

### 提示词
```
这是目录为v8/src/compiler/backend/arm64/instruction-selector-arm64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第5部分，共6部分，请归纳一下它的功能
```

### 源代码
```
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
SIMD_SHIFT_OP_LIST(SIMD_VISIT_SHIFT_OP)
#undef SIMD_VISIT_SHIFT_OP
#undef SIMD_SHIFT_OP_LIST

#define SIMD_VISIT_BINOP(Name, instruction)                      \
  template <typename Adapter>                                    \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) { \
    VisitRRR(this, instruction, node);                           \
  }
SIMD_BINOP_LIST(SIMD_VISIT_BINOP)
#undef SIMD_VISIT_BINOP
#undef SIMD_BINOP_LIST

#define SIMD_VISIT_BINOP_LANE_SIZE(Name, instruction, LaneSize)          \
  template <typename Adapter>                                            \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) {         \
    VisitRRR(this, instruction | LaneSizeField::encode(LaneSize), node); \
  }
SIMD_BINOP_LANE_SIZE_LIST(SIMD_VISIT_BINOP_LANE_SIZE)
#undef SIMD_VISIT_BINOP_LANE_SIZE
#undef SIMD_BINOP_LANE_SIZE_LIST

#define SIMD_VISIT_UNOP_LANE_SIZE(Name, instruction, LaneSize)          \
  template <typename Adapter>                                           \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) {        \
    VisitRR(this, instruction | LaneSizeField::encode(LaneSize), node); \
  }
SIMD_UNOP_LANE_SIZE_LIST(SIMD_VISIT_UNOP_LANE_SIZE)
#undef SIMD_VISIT_UNOP_LANE_SIZE
#undef SIMD_UNOP_LANE_SIZE_LIST

using ShuffleMatcher =
    ValueMatcher<S128ImmediateParameter, IrOpcode::kI8x16Shuffle>;
using BinopWithShuffleMatcher = BinopMatcher<ShuffleMatcher, ShuffleMatcher,
                                             MachineRepresentation::kSimd128>;

namespace {
// Struct holding the result of pattern-matching a mul+dup.
struct MulWithDupResult {
  Node* input;     // Node holding the vector elements.
  Node* dup_node;  // Node holding the lane to multiply.
  int index;
  // Pattern-match is successful if dup_node is set.
  explicit operator bool() const { return dup_node != nullptr; }
};

// Struct holding the result of pattern-matching a mul+dup.
struct MulWithDup {
  turboshaft::OpIndex input;     // Node holding the vector elements.
  turboshaft::OpIndex dup_node;  // Node holding the lane to multiply.
  int index;
  // Pattern-match is successful if dup_node is set.
  explicit operator bool() const { return dup_node.valid(); }
};

template <int LANES>
MulWithDupResult TryMatchMulWithDup(Node* node) {
  // Pattern match:
  //   f32x4.mul(x, shuffle(x, y, indices)) => f32x4.mul(x, y, laneidx)
  //   f64x2.mul(x, shuffle(x, y, indices)) => f64x2.mul(x, y, laneidx)
  //   where shuffle(x, y, indices) = dup(x[laneidx]) or dup(y[laneidx])
  // f32x4.mul and f64x2.mul are commutative, so use BinopMatcher.
  Node* input = nullptr;
  Node* dup_node = nullptr;

  int index = 0;
  BinopWithShuffleMatcher m = BinopWithShuffleMatcher(node);
  ShuffleMatcher left = m.left();
  ShuffleMatcher right = m.right();

  // TODO(zhin): We can canonicalize first to avoid checking index < LANES.
  // e.g. shuffle(x, y, [16, 17, 18, 19...]) => shuffle(y, y, [0, 1, 2,
  // 3]...). But doing so can mutate the inputs of the shuffle node without
  // updating the shuffle immediates themselves. Fix that before we
  // canonicalize here. We don't want CanCover here because in many use cases,
  // the shuffle is generated early in the function, but the f32x4.mul happens
  // in a loop, which won't cover the shuffle since they are different basic
  // blocks.
  if (left.HasResolvedValue() && wasm::SimdShuffle::TryMatchSplat<LANES>(
                                     left.ResolvedValue().data(), &index)) {
    dup_node = left.node()->InputAt(index < LANES ? 0 : 1);
    input = right.node();
  } else if (right.HasResolvedValue() &&
             wasm::SimdShuffle::TryMatchSplat<LANES>(
                 right.ResolvedValue().data(), &index)) {
    dup_node = right.node()->InputAt(index < LANES ? 0 : 1);
    input = left.node();
  }

  // Canonicalization would get rid of this too.
  index %= LANES;

  return {input, dup_node, index};
}

template <int LANES>
MulWithDup TryMatchMulWithDup(InstructionSelectorT<TurboshaftAdapter>* selector,
                              turboshaft::OpIndex node) {
  // Pattern match:
  //   f32x4.mul(x, shuffle(x, y, indices)) => f32x4.mul(x, y, laneidx)
  //   f64x2.mul(x, shuffle(x, y, indices)) => f64x2.mul(x, y, laneidx)
  //   where shuffle(x, y, indices) = dup(x[laneidx]) or dup(y[laneidx])
  // f32x4.mul and f64x2.mul are commutative, so use BinopMatcher.
  using namespace turboshaft;  // NOLINT(build/namespaces)
  OpIndex input;
  OpIndex dup_node;

  int index = 0;
#if V8_ENABLE_WEBASSEMBLY
  const Simd128BinopOp& mul = selector->Get(node).Cast<Simd128BinopOp>();
  const Operation& left = selector->Get(mul.left());
  const Operation& right = selector->Get(mul.right());

  // TODO(zhin): We can canonicalize first to avoid checking index < LANES.
  // e.g. shuffle(x, y, [16, 17, 18, 19...]) => shuffle(y, y, [0, 1, 2,
  // 3]...). But doing so can mutate the inputs of the shuffle node without
  // updating the shuffle immediates themselves. Fix that before we
  // canonicalize here. We don't want CanCover here because in many use cases,
  // the shuffle is generated early in the function, but the f32x4.mul happens
  // in a loop, which won't cover the shuffle since they are different basic
  // blocks.
  if (left.Is<Simd128ShuffleOp>() &&
      wasm::SimdShuffle::TryMatchSplat<LANES>(
          left.Cast<Simd128ShuffleOp>().shuffle, &index)) {
    dup_node = left.input(index < LANES ? 0 : 1);
    input = mul.right();
  } else if (right.Is<Simd128ShuffleOp>() &&
             wasm::SimdShuffle::TryMatchSplat<LANES>(
                 right.Cast<Simd128ShuffleOp>().shuffle, &index)) {
    dup_node = right.input(index < LANES ? 0 : 1);
    input = mul.left();
  }
#endif  // V8_ENABLE_WEBASSEMBLY

  // Canonicalization would get rid of this too.
  index %= LANES;

  return {input, dup_node, index};
}
}  // namespace

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitF16x8Mul(node_t node) {
  if (MulWithDup result = TryMatchMulWithDup<8>(this, node)) {
    Arm64OperandGeneratorT<TurboshaftAdapter> g(this);
    Emit(kArm64FMulElement | LaneSizeField::encode(16),
         g.DefineAsRegister(node), g.UseRegister(result.input),
         g.UseRegister(result.dup_node), g.UseImmediate(result.index));
  } else {
    return VisitRRR(this, kArm64FMul | LaneSizeField::encode(16), node);
  }
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitF16x8Mul(Node* node) {
  if (MulWithDupResult result = TryMatchMulWithDup<8>(node)) {
    Arm64OperandGeneratorT<TurbofanAdapter> g(this);
    Emit(kArm64FMulElement | LaneSizeField::encode(16),
         g.DefineAsRegister(node), g.UseRegister(result.input),
         g.UseRegister(result.dup_node), g.UseImmediate(result.index));
  } else {
    return VisitRRR(this, kArm64FMul | LaneSizeField::encode(16), node);
  }
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitF32x4Mul(node_t node) {
  if (MulWithDup result = TryMatchMulWithDup<4>(this, node)) {
    Arm64OperandGeneratorT<TurboshaftAdapter> g(this);
    Emit(kArm64FMulElement | LaneSizeField::encode(32),
         g.DefineAsRegister(node), g.UseRegister(result.input),
         g.UseRegister(result.dup_node), g.UseImmediate(result.index));
  } else {
    return VisitRRR(this, kArm64FMul | LaneSizeField::encode(32), node);
  }
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitF32x4Mul(Node* node) {
  if (MulWithDupResult result = TryMatchMulWithDup<4>(node)) {
    Arm64OperandGeneratorT<TurbofanAdapter> g(this);
    Emit(kArm64FMulElement | LaneSizeField::encode(32),
         g.DefineAsRegister(node), g.UseRegister(result.input),
         g.UseRegister(result.dup_node), g.UseImmediate(result.index));
  } else {
    return VisitRRR(this, kArm64FMul | LaneSizeField::encode(32), node);
  }
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitF64x2Mul(node_t node) {
  if (MulWithDup result = TryMatchMulWithDup<2>(this, node)) {
    Arm64OperandGeneratorT<TurboshaftAdapter> g(this);
    Emit(kArm64FMulElement | LaneSizeField::encode(64),
         g.DefineAsRegister(node), g.UseRegister(result.input),
         g.UseRegister(result.dup_node), g.UseImmediate(result.index));
  } else {
    return VisitRRR(this, kArm64FMul | LaneSizeField::encode(64), node);
  }
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitF64x2Mul(Node* node) {
  if (MulWithDupResult result = TryMatchMulWithDup<2>(node)) {
    Arm64OperandGeneratorT<TurbofanAdapter> g(this);
    Emit(kArm64FMulElement | LaneSizeField::encode(64),
         g.DefineAsRegister(node), g.UseRegister(result.input),
         g.UseRegister(result.dup_node), g.UseImmediate(result.index));
  } else {
    return VisitRRR(this, kArm64FMul | LaneSizeField::encode(64), node);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI64x2Mul(node_t node) {
  Arm64OperandGeneratorT<Adapter> g(this);
  InstructionOperand temps[] = {g.TempSimd128Register()};
  Emit(kArm64I64x2Mul, g.DefineAsRegister(node),
       g.UseRegister(this->input_at(node, 0)),
       g.UseRegister(this->input_at(node, 1)), arraysize(temps), temps);
}

namespace {

// Used for pattern matching SIMD Add operations where one of the inputs matches
// |opcode| and ensure that the matched input is on the LHS (input 0).
struct SimdAddOpMatcher : public NodeMatcher {
  explicit SimdAddOpMatcher(Node* node, IrOpcode::Value opcode)
      : NodeMatcher(node),
        opcode_(opcode),
        left_(InputAt(0)),
        right_(InputAt(1)) {
    DCHECK(HasProperty(Operator::kCommutative));
    PutOpOnLeft();
  }

  bool Matches() { return left_->opcode() == opcode_; }
  Node* left() const { return left_; }
  Node* right() const { return right_; }

 private:
  void PutOpOnLeft() {
    if (right_->opcode() == opcode_) {
      std::swap(left_, right_);
      node()->ReplaceInput(0, left_);
      node()->ReplaceInput(1, right_);
    }
  }
  IrOpcode::Value opcode_;
  Node* left_;
  Node* right_;
};

// Tries to match either input of a commutative binop to a given Opmask.
class SimdBinopMatcherTurboshaft {
 public:
  SimdBinopMatcherTurboshaft(InstructionSelectorT<TurboshaftAdapter>* selector,
                             turboshaft::OpIndex node)
      : selector_(selector), node_(node) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const Simd128BinopOp& add_op = selector->Get(node).Cast<Simd128BinopOp>();
    DCHECK(Simd128BinopOp::IsCommutative(add_op.kind));
    input0_ = add_op.left();
    input1_ = add_op.right();
  }
  template <typename OpmaskT>
  bool InputMatches() {
    if (selector_->Get(input1_).Is<OpmaskT>()) {
      std::swap(input0_, input1_);
      return true;
    }
    return selector_->Get(input0_).Is<OpmaskT>();
  }
  turboshaft::OpIndex matched_input() const { return input0_; }
  turboshaft::OpIndex other_input() const { return input1_; }

 private:
  InstructionSelectorT<TurboshaftAdapter>* selector_;
  turboshaft::OpIndex node_;
  turboshaft::OpIndex input0_;
  turboshaft::OpIndex input1_;
};

bool ShraHelper(InstructionSelectorT<TurbofanAdapter>* selector, Node* node,
                int lane_size, InstructionCode shra_code,
                InstructionCode add_code, IrOpcode::Value shift_op) {
  Arm64OperandGeneratorT<TurbofanAdapter> g(selector);
  SimdAddOpMatcher m(node, shift_op);
  if (!m.Matches() || !selector->CanCover(node, m.left())) return false;
  if (!g.IsIntegerConstant(m.left()->InputAt(1))) return false;

  // If shifting by zero, just do the addition
  if (g.GetIntegerConstantValue(m.left()->InputAt(1)) % lane_size == 0) {
    selector->Emit(add_code, g.DefineAsRegister(node),
                   g.UseRegister(m.left()->InputAt(0)),
                   g.UseRegister(m.right()));
  } else {
    selector->Emit(shra_code | LaneSizeField::encode(lane_size),
                   g.DefineSameAsFirst(node), g.UseRegister(m.right()),
                   g.UseRegister(m.left()->InputAt(0)),
                   g.UseImmediate(m.left()->InputAt(1)));
  }
  return true;
}

template <typename OpmaskT>
bool ShraHelper(InstructionSelectorT<TurboshaftAdapter>* selector,
                turboshaft::OpIndex node, int lane_size,
                InstructionCode shra_code, InstructionCode add_code) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  Arm64OperandGeneratorT<TurboshaftAdapter> g(selector);
  SimdBinopMatcherTurboshaft m(selector, node);
  if (!m.InputMatches<OpmaskT>() ||
      !selector->CanCover(node, m.matched_input())) {
    return false;
  }
  const Simd128ShiftOp& shiftop =
      selector->Get(m.matched_input()).Cast<Simd128ShiftOp>();
  if (!selector->is_integer_constant(shiftop.shift())) return false;

  // If shifting by zero, just do the addition
  if (selector->integer_constant(shiftop.shift()) % lane_size == 0) {
    selector->Emit(add_code, g.DefineAsRegister(node),
                   g.UseRegister(shiftop.input()),
                   g.UseRegister(m.other_input()));
  } else {
    selector->Emit(shra_code | LaneSizeField::encode(lane_size),
                   g.DefineSameAsFirst(node), g.UseRegister(m.other_input()),
                   g.UseRegister(shiftop.input()),
                   g.UseImmediate(shiftop.shift()));
  }
  return true;
}

bool AdalpHelper(InstructionSelectorT<TurbofanAdapter>* selector, Node* node,
                 int lane_size, InstructionCode adalp_code,
                 IrOpcode::Value ext_op) {
  Arm64OperandGeneratorT<TurbofanAdapter> g(selector);
  SimdAddOpMatcher m(node, ext_op);
  if (!m.Matches() || !selector->CanCover(node, m.left())) return false;
  selector->Emit(adalp_code | LaneSizeField::encode(lane_size),
                 g.DefineSameAsFirst(node), g.UseRegister(m.right()),
                 g.UseRegister(m.left()->InputAt(0)));
  return true;
}

template <typename OpmaskT>
bool AdalpHelper(InstructionSelectorT<TurboshaftAdapter>* selector,
                 turboshaft::OpIndex node, int lane_size,
                 InstructionCode adalp_code) {
  Arm64OperandGeneratorT<TurboshaftAdapter> g(selector);
  SimdBinopMatcherTurboshaft m(selector, node);
  if (!m.InputMatches<OpmaskT>() ||
      !selector->CanCover(node, m.matched_input())) {
    return false;
  }
  selector->Emit(adalp_code | LaneSizeField::encode(lane_size),
                 g.DefineSameAsFirst(node), g.UseRegister(m.other_input()),
                 g.UseRegister(selector->Get(m.matched_input()).input(0)));
  return true;
}

bool MlaHelper(InstructionSelectorT<TurbofanAdapter>* selector, Node* node,
               InstructionCode mla_code, IrOpcode::Value mul_op) {
  Arm64OperandGeneratorT<TurbofanAdapter> g(selector);
  SimdAddOpMatcher m(node, mul_op);
  if (!m.Matches() || !selector->CanCover(node, m.left())) return false;
  selector->Emit(mla_code, g.DefineSameAsFirst(node), g.UseRegister(m.right()),
                 g.UseRegister(m.left()->InputAt(0)),
                 g.UseRegister(m.left()->InputAt(1)));
  return true;
}

template <typename OpmaskT>
bool MlaHelper(InstructionSelectorT<TurboshaftAdapter>* selector,
               turboshaft::OpIndex node, InstructionCode mla_code) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  Arm64OperandGeneratorT<TurboshaftAdapter> g(selector);
  SimdBinopMatcherTurboshaft m(selector, node);
  if (!m.InputMatches<OpmaskT>() ||
      !selector->CanCover(node, m.matched_input())) {
    return false;
  }
  const Operation& mul = selector->Get(m.matched_input());
  selector->Emit(mla_code, g.DefineSameAsFirst(node),
                 g.UseRegister(m.other_input()), g.UseRegister(mul.input(0)),
                 g.UseRegister(mul.input(1)));
  return true;
}

bool SmlalHelper(InstructionSelectorT<TurbofanAdapter>* selector, Node* node,
                 int lane_size, InstructionCode smlal_code,
                 IrOpcode::Value ext_mul_op) {
  Arm64OperandGeneratorT<TurbofanAdapter> g(selector);
  SimdAddOpMatcher m(node, ext_mul_op);
  if (!m.Matches() || !selector->CanCover(node, m.left())) return false;

  selector->Emit(smlal_code | LaneSizeField::encode(lane_size),
                 g.DefineSameAsFirst(node), g.UseRegister(m.right()),
                 g.UseRegister(m.left()->InputAt(0)),
                 g.UseRegister(m.left()->InputAt(1)));
  return true;
}

template <turboshaft::Simd128BinopOp::Kind kind>
bool SmlalHelper(InstructionSelectorT<TurboshaftAdapter>* selector,
                 turboshaft::OpIndex node, int lane_size,
                 InstructionCode smlal_code) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  Arm64OperandGeneratorT<TurboshaftAdapter> g(selector);
  SimdBinopMatcherTurboshaft m(selector, node);
  using OpmaskT = Opmask::Simd128BinopMask::For<kind>;
  if (!m.InputMatches<OpmaskT>() ||
      !selector->CanCover(node, m.matched_input()))
    return false;

  const Operation& matched = selector->Get(m.matched_input());
  selector->Emit(smlal_code | LaneSizeField::encode(lane_size),
                 g.DefineSameAsFirst(node), g.UseRegister(m.other_input()),
                 g.UseRegister(matched.input(0)),
                 g.UseRegister(matched.input(1)));
  return true;
}

}  // namespace

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitI64x2Add(node_t node) {
  if (ShraHelper(this, node, 64, kArm64Ssra,
                 kArm64IAdd | LaneSizeField::encode(64),
                 IrOpcode::kI64x2ShrS) ||
      ShraHelper(this, node, 64, kArm64Usra,
                 kArm64IAdd | LaneSizeField::encode(64),
                 IrOpcode::kI64x2ShrU)) {
    return;
  }
  VisitRRR(this, kArm64IAdd | LaneSizeField::encode(64), node);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitI64x2Add(
    turboshaft::OpIndex node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  if (ShraHelper<Opmask::kSimd128I64x2ShrS>(
          this, node, 64, kArm64Ssra, kArm64IAdd | LaneSizeField::encode(64)) ||
      ShraHelper<Opmask::kSimd128I64x2ShrU>(
          this, node, 64, kArm64Usra, kArm64IAdd | LaneSizeField::encode(64))) {
    return;
  }
  VisitRRR(this, kArm64IAdd | LaneSizeField::encode(64), node);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitI8x16Add(node_t node) {
  if (!ShraHelper(this, node, 8, kArm64Ssra,
                  kArm64IAdd | LaneSizeField::encode(8),
                  IrOpcode::kI8x16ShrS) &&
      !ShraHelper(this, node, 8, kArm64Usra,
                  kArm64IAdd | LaneSizeField::encode(8),
                  IrOpcode::kI8x16ShrU)) {
    VisitRRR(this, kArm64IAdd | LaneSizeField::encode(8), node);
  }
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitI8x16Add(node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  if (!ShraHelper<Opmask::kSimd128I8x16ShrS>(
          this, node, 8, kArm64Ssra, kArm64IAdd | LaneSizeField::encode(8)) &&
      !ShraHelper<Opmask::kSimd128I8x16ShrU>(
          this, node, 8, kArm64Usra, kArm64IAdd | LaneSizeField::encode(8))) {
    VisitRRR(this, kArm64IAdd | LaneSizeField::encode(8), node);
  }
}

#define VISIT_SIMD_ADD(Type, PairwiseType, LaneSize)                          \
  template <>                                                                 \
  void InstructionSelectorT<TurbofanAdapter>::Visit##Type##Add(node_t node) { \
    /* Select Mla(z, x, y) for Add(x, Mul(y, z)). */                          \
    if (MlaHelper(this, node, kArm64Mla | LaneSizeField::encode(LaneSize),    \
                  IrOpcode::k##Type##Mul)) {                                  \
      return;                                                                 \
    }                                                                         \
    /* Select S/Uadalp(x, y) for Add(x, ExtAddPairwise(y)). */                \
    if (AdalpHelper(this, node, LaneSize, kArm64Sadalp,                       \
                    IrOpcode::k##Type##ExtAddPairwise##PairwiseType##S) ||    \
        AdalpHelper(this, node, LaneSize, kArm64Uadalp,                       \
                    IrOpcode::k##Type##ExtAddPairwise##PairwiseType##U)) {    \
      return;                                                                 \
    }                                                                         \
    /* Select S/Usra(x, y) for Add(x, ShiftRight(y, imm)). */                 \
    if (ShraHelper(this, node, LaneSize, kArm64Ssra,                          \
                   kArm64IAdd | LaneSizeField::encode(LaneSize),              \
                   IrOpcode::k##Type##ShrS) ||                                \
        ShraHelper(this, node, LaneSize, kArm64Usra,                          \
                   kArm64IAdd | LaneSizeField::encode(LaneSize),              \
                   IrOpcode::k##Type##ShrU)) {                                \
      return;                                                                 \
    }                                                                         \
    /* Select Smlal/Umlal(x, y, z) for Add(x, ExtMulLow(y, z)) and            \
     * Smlal2/Umlal2(x, y, z) for Add(x, ExtMulHigh(y, z)). */                \
    if (SmlalHelper(this, node, LaneSize, kArm64Smlal,                        \
                    IrOpcode::k##Type##ExtMulLow##PairwiseType##S) ||         \
        SmlalHelper(this, node, LaneSize, kArm64Smlal2,                       \
                    IrOpcode::k##Type##ExtMulHigh##PairwiseType##S) ||        \
        SmlalHelper(this, node, LaneSize, kArm64Umlal,                        \
                    IrOpcode::k##Type##ExtMulLow##PairwiseType##U) ||         \
        SmlalHelper(this, node, LaneSize, kArm64Umlal2,                       \
                    IrOpcode::k##Type##ExtMulHigh##PairwiseType##U)) {        \
      return;                                                                 \
    }                                                                         \
    VisitRRR(this, kArm64IAdd | LaneSizeField::encode(LaneSize), node);       \
  }                                                                           \
                                                                              \
  template <>                                                                 \
  void InstructionSelectorT<TurboshaftAdapter>::Visit##Type##Add(             \
      node_t node) {                                                          \
    using namespace turboshaft; /*NOLINT(build/namespaces)*/                  \
    /* Select Mla(z, x, y) for Add(x, Mul(y, z)). */                          \
    if (MlaHelper<Opmask::kSimd128##Type##Mul>(                               \
            this, node, kArm64Mla | LaneSizeField::encode(LaneSize))) {       \
      return;                                                                 \
    }                                                                         \
    /* Select S/Uadalp(x, y) for Add(x, ExtAddPairwise(y)). */                \
    if (AdalpHelper<Opmask::kSimd128##Type##ExtAddPairwise##PairwiseType##S>( \
            this, node, LaneSize, kArm64Sadalp) ||                            \
        AdalpHelper<Opmask::kSimd128##Type##ExtAddPairwise##PairwiseType##U>( \
            this, node, LaneSize, kArm64Uadalp)) {                            \
      return;                                                                 \
    }                                                                         \
    /* Select S/Usra(x, y) for Add(x, ShiftRight(y, imm)). */                 \
    if (ShraHelper<Opmask::kSimd128##Type##ShrS>(                             \
            this, node, LaneSize, kArm64Ssra,                                 \
            kArm64IAdd | LaneSizeField::encode(LaneSize)) ||                  \
        ShraHelper<Opmask::kSimd128##Type##ShrU>(                             \
            this, node, LaneSize, kArm64Usra,                                 \
            kArm64IAdd | LaneSizeField::encode(LaneSize))) {                  \
      return;                                                                 \
    }                                                                         \
    /* Select Smlal/Umlal(x, y, z) for Add(x, ExtMulLow(y, z)) and            \
     * Smlal2/Umlal2(x, y, z) for Add(x, ExtMulHigh(y, z)). */                \
    if (SmlalHelper<                                                          \
            Simd128BinopOp::Kind::k##Type##ExtMulLow##PairwiseType##S>(       \
            this, node, LaneSize, kArm64Smlal) ||                             \
        SmlalHelper<                                                          \
            Simd128BinopOp::Kind::k##Type##ExtMulHigh##PairwiseType##S>(      \
            this, node, LaneSize, kArm64Smlal2) ||                            \
        SmlalHelper<                                                          \
            Simd128BinopOp::Kind::k##Type##ExtMulLow##PairwiseType##U>(       \
            this, node, LaneSize, kArm64Umlal) ||                             \
        SmlalHelper<                                                          \
            Simd128BinopOp::Kind::k##Type##ExtMulHigh##PairwiseType##U>(      \
            this, node, LaneSize, kArm64Umlal2)) {                            \
      return;                                                                 \
    }                                                                         \
    VisitRRR(this, kArm64IAdd | LaneSizeField::encode(LaneSize), node);       \
  }

VISIT_SIMD_ADD(I32x4, I16x8, 32)
VISIT_SIMD_ADD(I16x8, I8x16, 16)
#undef VISIT_SIMD_ADD

#define VISIT_SIMD_SUB(Type, LaneSize)                                        \
  template <>                                                                 \
  void InstructionSelectorT<TurboshaftAdapter>::Visit##Type##Sub(             \
      node_t node) {                                                          \
    using namespace turboshaft; /* NOLINT(build/namespaces) */                \
    Arm64OperandGeneratorT<TurboshaftAdapter> g(this);                        \
    const Simd128BinopOp& sub = Get(node).Cast<Simd128BinopOp>();             \
    const Operation& right = Get(sub.right());                                \
    /* Select Mls(z, x, y) for Sub(z, Mul(x, y)). */                          \
    if (right.Is<Opmask::kSimd128##Type##Mul>() &&                            \
        CanCover(node, sub.right())) {                                        \
      Emit(kArm64Mls | LaneSizeField::encode(LaneSize),                       \
           g.DefineSameAsFirst(node), g.UseRegister(sub.left()),              \
           g.UseRegister(right.input(0)), g.UseRegister(right.input(1)));     \
      return;                                                                 \
    }                                                                         \
    VisitRRR(this, kArm64ISub | LaneSizeField::encode(LaneSize), node);       \
  }                                                                           \
  template <>                                                                 \
  void InstructionSelectorT<TurbofanAdapter>::Visit##Type##Sub(Node* node) {  \
    Arm64OperandGeneratorT<TurbofanAdapter> g(this);                          \
    Node* left = node->InputAt(0);                                            \
    Node* right = node->InputAt(1);                                           \
    /* Select Mls(z, x, y) for Sub(z, Mul(x, y)). */                          \
    if (right->opcode() == IrOpcode::k##Type##Mul && CanCover(node, right)) { \
      Emit(kArm64Mls | LaneSizeField::encode(LaneSize),                       \
           g.DefineSameAsFirst(node), g.UseRegister(left),                    \
           g.UseRegister(right->InputAt(0)),                                  \
           g.UseRegister(right->InputAt(1)));                                 \
      return;                                                                 \
    }                                                                         \
    VisitRRR(this, kArm64ISub | LaneSizeField::encode(LaneSize), node);       \
  }

VISIT_SIMD_SUB(I32x4, 32)
VISIT_SIMD_SUB(I16x8, 16)
#undef VISIT_SIMD_SUB

namespace {
void VisitSimdReduce(InstructionSelectorT<TurboshaftAdapter>* selector,
                     turboshaft::OpIndex node, InstructionCode opcode) {
  Arm64OperandGeneratorT<TurboshaftAdapter> g(selector);
  selector->Emit(opcode, g.DefineAsRegister(node),
                 g.UseRegister(selector->Get(node).input(0)));
}

}  // namespace

#define VISIT_SIMD_REDUCE(Type, Opcode)                                 \
  template <>                                                           \
  void InstructionSelectorT<TurboshaftAdapter>::Visit##Type##AddReduce( \
      turboshaft::OpIndex node) {                                       \
    VisitSimdReduce(this, node, Opcode);                                \
  }

VISIT_SIMD_REDUCE(I8x16, kArm64I8x16Addv)
VISIT_SIMD_REDUCE(I16x8, kArm64I16x8Addv)
VISIT_SIMD_REDUCE(I32x4, kArm64I32x4Addv)
VISIT_SIMD_REDUCE(I64x2, kArm64I64x2AddPair)
VISIT_SIMD_REDUCE(F32x4, kArm64F32x4AddReducePairwise)
VISIT_SIMD_REDUCE(F64x2, kArm64F64x2AddPair)
#undef VISIT_SIMD_REDUCE

namespace {
bool isSimdZero(InstructionSelectorT<TurbofanAdapter>* selector, Node* node) {
  auto m = V128ConstMatcher(node);
  if (m.HasResolvedValue()) {
    auto imms = m.ResolvedValue().immediate();
    return (std::all_of(imms.begin(), imms.end(), std::logical_not<uint8_t>()));
  }
  return node->opcode() == IrOpcode::kS128Zero;
}

bool isSimdZero(InstructionSelectorT<TurboshaftAdapter>* selector,
                turboshaft::OpIndex node) {
  const turboshaft::Operation& op = selector->Get(node);
  if (auto constant = op.TryCast<turboshaft::Simd128ConstantOp>()) {
    return constant->IsZero();
  }
  return false;
}

}  // namespace

#define VISIT_SIMD_CM(Type, T, CmOp, CmOpposite, LaneSize)                   \
  template <typename Adapter>                                                \
  void InstructionSelectorT<Adapter>::Visit##Type##CmOp(node_t node) {       \
    Arm64OperandGeneratorT<Adapter> g(this);                                 \
    node_t left = this->input_at(node, 0);                                   \
    node_t right = this->input_at(node, 1);                                  \
    if (isSimdZero(this, left)) {                                            \
      Emit(kArm64##T##CmOpposite | LaneSizeField::encode(LaneSize),          \
           g.DefineAsRegister(node), g.UseRegister(right));                  \
      return;                                                                \
    } else if (isSimdZero(this, right)) {                                    \
      Emit(kArm64##T##CmOp | LaneSizeField::encode(LaneSize),                \
           g.DefineAsRegister(node), g.UseRegister(left));                   \
      return;                                                                \
    }                                                                        \
    VisitRRR(this, kArm64##T##CmOp | LaneSizeField::encode(LaneSize), node); \
  }

VISIT_SIMD_CM(F64x2, F, Eq, Eq, 64)
VISIT_SIMD_CM(F64x2, F, Ne, Ne, 64)
VISIT_SIMD_CM(F64x2, F, Lt, Gt, 64)
VISIT_SIMD_CM(F64x2, F, Le, Ge, 64)
VISIT_SIMD_CM(F32x4, F, Eq, Eq, 32)
VISIT_SIMD_CM(F32x4, F, Ne, Ne, 32)
VISIT_SIMD_CM(F32x4, F, Lt, Gt, 32)
VISIT_SIMD_CM(F32x4, F, Le, Ge, 32)
VISIT_SIMD_CM(F16x8, F, Eq, Eq, 16)
VISIT_SIMD_CM(F16x8, F, Ne, Ne, 16)
VISIT_SIMD_CM(F16x8, F, Lt, Gt, 16)
VISIT_SIMD_CM(F16x8, F, Le, Ge, 16)

VISIT_SIMD_CM(I64x2, I, Eq, Eq, 64)
VISIT_SIMD_CM(I64x2, I, Ne, Ne, 64)
VISIT_SIMD_CM(I64x2, I, GtS, LtS, 64)
VISIT_SIMD_CM(I64x2, I, GeS, LeS, 64)
VISIT_SIMD_CM(I32x4, I, Eq, Eq, 32)
VISIT_SIMD_CM(I32x4, I, Ne, Ne, 32)
VISIT_SIMD_CM(I32x4, I, GtS, LtS, 32)
VISIT_SIMD_CM(I32x4, I, GeS, LeS, 32)
VISIT_SIMD_CM(I16x8, I, Eq, Eq, 16)
VISIT_SIMD_CM(I16x8, I, Ne, Ne, 16)
VISIT_SIMD_CM(I16x8, I, GtS, LtS, 16)
VISIT_SIMD_CM(I16x8, I, GeS, LeS, 16)
VISIT_SIMD_CM(I8x16, I, Eq, Eq, 8)
VISIT_SIMD_CM(I8x16, I, Ne, Ne, 8)
VISIT_SIMD_CM(I8x16, I, GtS, LtS, 8)
VISIT_SIMD_CM(I8x16, I, GeS, LeS, 8)
#undef VISIT_SIMD_CM

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitS128Select(node_t node) {
  Arm64OperandGeneratorT<Adapter> g(this);
  Emit(kArm64S128Select, g.DefineSameAsFirst(node),
       g.UseRegister(this->input_at(node, 0)),
       g.UseRegister(this->input_at(node, 1)),
       g.UseRegister(this->input_at(node, 2)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI8x16RelaxedLaneSelect(node_t node) {
  VisitS128Select(node);
}

template <typename Adapter>
vo
```