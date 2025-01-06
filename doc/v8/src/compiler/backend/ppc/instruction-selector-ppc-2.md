Response: The user wants to understand the functionality of the provided C++ code snippet, which is part of the V8 JavaScript engine, specifically the instruction selector for the PowerPC (PPC) architecture. This is the third part of a three-part file.

Here's a breakdown of the thought process to arrive at the summary:

1. **Identify the core purpose:** The filename `instruction-selector-ppc.cc` immediately suggests this code is responsible for *instruction selection*. Instruction selection is a crucial part of a compiler's backend, translating high-level intermediate representations (like the V8 IR) into low-level machine instructions for a specific architecture (PPC in this case).

2. **Analyze the class structure:** The code defines a template class `InstructionSelectorT`. This suggests the code is designed to be adaptable, likely to different compilation pipelines within V8 (like Turbofan and Turboshaft, as seen later). The `<typename Adapter>` confirms this.

3. **Examine the core methods:** The vast majority of the code consists of `Visit...` methods. These methods correspond to different *operations* in the V8 intermediate representation. Each `Visit` method is responsible for selecting the appropriate PPC instructions to implement that operation.

4. **Focus on the operations being handled:**  Scanning the `Visit` methods reveals categories of operations:
    * **Atomic Operations:** `VisitWord32AtomicBinaryOperation`, `VisitWord64AtomicBinaryOperation`, `VISIT_ATOMIC_BINOP`. These handle atomic read-modify-write operations on memory.
    * **SIMD (Single Instruction, Multiple Data) Operations:** A large section deals with SIMD instructions (`VisitF64x2Add`, `VisitI32x4Neg`, `VisitI8x16Shuffle`, etc.). This is evident from the `SIMD_TYPES`, `SIMD_BINOP_LIST`, and `SIMD_UNOP_LIST` macros.
    * **Memory Access (Load/Store with Lane/Transform):** `VisitLoadLane`, `VisitStoreLane`, `VisitLoadTransform`. These handle loading and storing specific lanes of SIMD vectors or transforming data during loads.
    * **Stack Pointer Manipulation:** `VisitSetStackPointer`.
    * **Constants:** `VisitS128Const`.
    * **Specific Vector Operations:** `VisitI16x8DotI8x16I7x16S`, `VisitI32x4DotI8x16I7x16AddS`.
    * **Call Handling:** `EmitPrepareResults`.

5. **Consider the architecture specifics (PPC):** The `kPPC_...` constants (e.g., `kPPC_AtomicAddInt8`, `kPPC_I8x16Shuffle`) clearly indicate that this code is generating instructions specific to the PowerPC architecture.

6. **Infer the relationship to JavaScript:** Instruction selection is a core part of compiling JavaScript code. The operations being handled (SIMD, atomic operations, memory access) are all functionalities that can be expressed and used within JavaScript.

7. **Construct JavaScript examples:** For each category of operations, create simple JavaScript code snippets that would likely trigger the corresponding `Visit` methods during compilation. Focus on using language features that map directly to the kinds of operations seen in the C++ code.

8. **Address the "Part 3" aspect:** Since this is the final part, it's likely to contain the implementation of more complex or specialized instruction selection logic. The presence of SIMD operations, atomic operations, and specific load/store transformations supports this.

9. **Summarize the findings:** Combine the observations into a concise summary highlighting the core function, the types of operations handled, and the connection to JavaScript.

10. **Review and refine:** Ensure the summary is accurate, clear, and addresses all parts of the user's request. Check for any jargon that might need clarification. Make sure the JavaScript examples are relevant and easy to understand. For instance, initially, I might have just said "SIMD operations," but specifying examples like vector addition, negation, and shuffling makes it much clearer. Similarly, simply saying "memory access" is less informative than specifying "loading/storing lanes of SIMD vectors".
这是文件 `v8/src/compiler/backend/ppc/instruction-selector-ppc.cc` 的第三部分，延续了前两部分的功能，**负责将 V8 编译器生成的中间代码（IR）节点转换为 PowerPC (PPC) 架构的机器指令。**  它定义了 `InstructionSelectorT` 模板类的特化版本，用于处理各种特定的 IR 节点，生成相应的 PPC 汇编指令。

**具体功能归纳：**

* **原子操作的指令选择：** 包含了对原子加、减、与、或、异或等操作的指令选择，针对不同的数据类型（int8, uint8, int16, uint16, int32, uint32, int64, uint64）。
* **SIMD (Single Instruction, Multiple Data) 操作的指令选择：**  这是本部分代码的重点，包含了大量的 SIMD 指令选择逻辑，涵盖了各种 SIMD 数据类型 (F64x2, F32x4, I64x2, I32x4, I16x8, I8x16) 的各种操作，如：
    * **算术运算：** 加、减、乘、除、绝对值、取反等。
    * **比较运算：** 等于、不等于、小于、小于等于、大于、大于等于。
    * **类型转换：** 不同 SIMD 数据类型之间的转换，以及标量类型与 SIMD 类型之间的转换。
    * **位运算：** 与、或、异或、非。
    * **通道操作：** 提取和替换 SIMD 向量中的特定通道的值。
    * **其他操作：**  如点积、饱和运算、移位、shuffle 等。
* **处理 WebAssembly SIMD 指令：**  如果启用了 WebAssembly，则包含对 WebAssembly 特有的 SIMD 指令（如 `I8x16Shuffle`）的指令选择。
* **栈指针操作：**  处理设置栈指针的指令 (`VisitSetStackPointer`)。
* **S128 (128 位) 常量操作：**  处理创建 128 位常量的指令 (`VisitS128Const`)。
* **Load/Store Lane 操作：**  处理加载和存储 SIMD 向量中特定通道的指令 (`VisitLoadLane`, `VisitStoreLane`)。
* **Load Transform 操作：** 处理加载时进行数据转换的指令，例如将内存中的字节加载并扩展为 128 位向量的每个字节 (`VisitLoadTransform`)。
* **函数调用结果处理：**  处理函数调用后将结果从栈中取出到寄存器的操作 (`EmitPrepareResults`)。
* **浮点数舍入操作：** 包含对浮点数进行舍入到最接近的偶数的操作，但目前标记为 `UNREACHABLE()`，可能尚未实现或在其他部分处理。
* **其他未实现或标记为 `UNREACHABLE()` 的操作：**  例如 `Int32AbsWithOverflow`，可能表示这些操作在 PPC 架构上没有直接对应的指令，或者由其他更通用的指令序列来实现。

**与 JavaScript 的关系：**

这个文件直接参与了将 JavaScript 代码编译成可以在 PPC 架构上运行的机器码的过程。当 JavaScript 代码中使用了某些特定的语言特性时，V8 编译器会生成相应的 IR 节点，而这个文件中的代码则负责将这些 IR 节点翻译成底层的 PPC 指令。

**JavaScript 举例说明：**

1. **原子操作:**

   ```javascript
   const sab = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT * 1);
   const ia = new Int32Array(sab);
   Atomics.add(ia, 0, 5); // 原子地将 ia[0] 的值加上 5
   ```

   这段 JavaScript 代码使用了原子操作 `Atomics.add`。V8 编译器在编译这段代码时，会生成一个表示原子加操作的 IR 节点，而 `instruction-selector-ppc.cc` 中的 `VisitWord32AtomicAdd` 方法就会负责选择合适的 PPC 原子加指令来实现这个操作。

2. **SIMD 操作:**

   ```javascript
   const a = Float64Array.of(1.0, 2.0);
   const b = Float64Array.of(3.0, 4.0);
   const va = SIMD.float64x2(a[0], a[1]);
   const vb = SIMD.float64x2(b[0], b[1]);
   const vc = SIMD.float64x2.add(va, vb); // SIMD 浮点数加法
   ```

   这段 JavaScript 代码使用了 SIMD API 进行浮点数向量加法。编译器会生成表示 SIMD 加法的 IR 节点，`instruction-selector-ppc.cc` 中的 `VisitF64x2Add` 方法会选择对应的 PPC SIMD 加法指令来执行。

3. **WebAssembly SIMD (如果启用):**

   ```javascript
   // WebAssembly 模块
   const wasmCode = new Uint8Array([
       // ... wasm 二进制代码，包含 SIMD 指令 ...
   ]);
   const wasmModule = new WebAssembly.Module(wasmCode);
   const wasmInstance = new WebAssembly.Instance(wasmModule);
   // 调用 wasm 模块中的 SIMD 函数
   ```

   如果 JavaScript 代码加载并执行了包含 SIMD 指令的 WebAssembly 模块，`instruction-selector-ppc.cc` 中的 `VisitI8x16Shuffle` 或其他相关的 WebAssembly SIMD 指令处理方法将被调用，将 WebAssembly 的 SIMD 操作翻译成 PPC 的 SIMD 指令。

**总结来说，这是 `v8/src/compiler/backend/ppc/instruction-selector-ppc.cc` 文件的最后一部分，专注于将 V8 编译器生成的中间代码中关于原子操作、SIMD 操作（包括 JavaScript SIMD API 和 WebAssembly SIMD）、内存加载/存储的特定操作以及其他底层操作转换为 PowerPC 架构的机器指令，从而使得 JavaScript 代码能够在 PPC 架构的处理器上高效地执行。**

Prompt: 
```
这是目录为v8/src/compiler/backend/ppc/instruction-selector-ppc.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共3部分，请归纳一下它的功能

"""
yRepresentation::Uint64()) {
      opcode = uint64_op;
    } else {
      UNREACHABLE();
    }
  } else {
    MachineType type = AtomicOpType(node->op());
    if (type == MachineType::Int8()) {
      opcode = int8_op;
    } else if (type == MachineType::Uint8()) {
      opcode = uint8_op;
    } else if (type == MachineType::Int16()) {
      opcode = int16_op;
    } else if (type == MachineType::Uint16()) {
      opcode = uint16_op;
    } else if (type == MachineType::Int32()) {
      opcode = int32_op;
    } else if (type == MachineType::Uint32()) {
      opcode = uint32_op;
    } else if (type == MachineType::Int64()) {
      opcode = int64_op;
    } else if (type == MachineType::Uint64()) {
      opcode = uint64_op;
    } else {
      UNREACHABLE();
    }
  }

  AddressingMode addressing_mode = kMode_MRR;
  InstructionCode code = opcode | AddressingModeField::encode(addressing_mode);
  InstructionOperand inputs[3];

  size_t input_count = 0;
  inputs[input_count++] = g.UseUniqueRegister(base);
  inputs[input_count++] = g.UseUniqueRegister(index);
  inputs[input_count++] = g.UseUniqueRegister(value);

  InstructionOperand outputs[1];
  size_t output_count = 0;
  outputs[output_count++] = g.DefineAsRegister(node);

  selector->Emit(code, output_count, outputs, input_count, inputs);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicBinaryOperation(
    node_t node, ArchOpcode int8_op, ArchOpcode uint8_op, ArchOpcode int16_op,
    ArchOpcode uint16_op, ArchOpcode word32_op) {
  // Unused
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64AtomicBinaryOperation(
    node_t node, ArchOpcode uint8_op, ArchOpcode uint16_op,
    ArchOpcode uint32_op, ArchOpcode uint64_op) {
  // Unused
  UNREACHABLE();
}

#define VISIT_ATOMIC_BINOP(op)                                             \
  template <typename Adapter>                                              \
  void InstructionSelectorT<Adapter>::VisitWord32Atomic##op(node_t node) { \
      VisitAtomicBinaryOperation(                                          \
          this, node, kPPC_Atomic##op##Int8, kPPC_Atomic##op##Uint8,       \
          kPPC_Atomic##op##Int16, kPPC_Atomic##op##Uint16,                 \
          kPPC_Atomic##op##Int32, kPPC_Atomic##op##Uint32,                 \
          kPPC_Atomic##op##Int64, kPPC_Atomic##op##Uint64);                \
  }                                                                        \
  template <typename Adapter>                                              \
  void InstructionSelectorT<Adapter>::VisitWord64Atomic##op(node_t node) { \
      VisitAtomicBinaryOperation(                                          \
          this, node, kPPC_Atomic##op##Int8, kPPC_Atomic##op##Uint8,       \
          kPPC_Atomic##op##Int16, kPPC_Atomic##op##Uint16,                 \
          kPPC_Atomic##op##Int32, kPPC_Atomic##op##Uint32,                 \
          kPPC_Atomic##op##Int64, kPPC_Atomic##op##Uint64);                \
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

#define SIMD_TYPES(V) \
  V(F64x2)            \
  V(F32x4)            \
  V(I64x2)            \
  V(I32x4)            \
  V(I16x8)            \
  V(I8x16)

#define SIMD_BINOP_LIST(V) \
  V(F64x2Add)              \
  V(F64x2Sub)              \
  V(F64x2Mul)              \
  V(F64x2Eq)               \
  V(F64x2Ne)               \
  V(F64x2Le)               \
  V(F64x2Lt)               \
  V(F64x2Div)              \
  V(F64x2Min)              \
  V(F64x2Max)              \
  V(F64x2Pmin)             \
  V(F64x2Pmax)             \
  V(F32x4Add)              \
  V(F32x4Sub)              \
  V(F32x4Mul)              \
  V(F32x4Eq)               \
  V(F32x4Ne)               \
  V(F32x4Lt)               \
  V(F32x4Le)               \
  V(F32x4Div)              \
  V(F32x4Min)              \
  V(F32x4Max)              \
  V(F32x4Pmin)             \
  V(F32x4Pmax)             \
  V(I64x2Add)              \
  V(I64x2Sub)              \
  V(I64x2Mul)              \
  V(I64x2Eq)               \
  V(I64x2Ne)               \
  V(I64x2ExtMulLowI32x4S)  \
  V(I64x2ExtMulHighI32x4S) \
  V(I64x2ExtMulLowI32x4U)  \
  V(I64x2ExtMulHighI32x4U) \
  V(I64x2GtS)              \
  V(I64x2GeS)              \
  V(I64x2Shl)              \
  V(I64x2ShrS)             \
  V(I64x2ShrU)             \
  V(I32x4Add)              \
  V(I32x4Sub)              \
  V(I32x4Mul)              \
  V(I32x4MinS)             \
  V(I32x4MinU)             \
  V(I32x4MaxS)             \
  V(I32x4MaxU)             \
  V(I32x4Eq)               \
  V(I32x4Ne)               \
  V(I32x4GtS)              \
  V(I32x4GeS)              \
  V(I32x4GtU)              \
  V(I32x4GeU)              \
  V(I32x4DotI16x8S)        \
  V(I32x4ExtMulLowI16x8S)  \
  V(I32x4ExtMulHighI16x8S) \
  V(I32x4ExtMulLowI16x8U)  \
  V(I32x4ExtMulHighI16x8U) \
  V(I32x4Shl)              \
  V(I32x4ShrS)             \
  V(I32x4ShrU)             \
  V(I16x8Add)              \
  V(I16x8Sub)              \
  V(I16x8Mul)              \
  V(I16x8MinS)             \
  V(I16x8MinU)             \
  V(I16x8MaxS)             \
  V(I16x8MaxU)             \
  V(I16x8Eq)               \
  V(I16x8Ne)               \
  V(I16x8GtS)              \
  V(I16x8GeS)              \
  V(I16x8GtU)              \
  V(I16x8GeU)              \
  V(I16x8SConvertI32x4)    \
  V(I16x8UConvertI32x4)    \
  V(I16x8AddSatS)          \
  V(I16x8SubSatS)          \
  V(I16x8AddSatU)          \
  V(I16x8SubSatU)          \
  V(I16x8RoundingAverageU) \
  V(I16x8Q15MulRSatS)      \
  V(I16x8ExtMulLowI8x16S)  \
  V(I16x8ExtMulHighI8x16S) \
  V(I16x8ExtMulLowI8x16U)  \
  V(I16x8ExtMulHighI8x16U) \
  V(I16x8Shl)              \
  V(I16x8ShrS)             \
  V(I16x8ShrU)             \
  V(I8x16Add)              \
  V(I8x16Sub)              \
  V(I8x16MinS)             \
  V(I8x16MinU)             \
  V(I8x16MaxS)             \
  V(I8x16MaxU)             \
  V(I8x16Eq)               \
  V(I8x16Ne)               \
  V(I8x16GtS)              \
  V(I8x16GeS)              \
  V(I8x16GtU)              \
  V(I8x16GeU)              \
  V(I8x16SConvertI16x8)    \
  V(I8x16UConvertI16x8)    \
  V(I8x16AddSatS)          \
  V(I8x16SubSatS)          \
  V(I8x16AddSatU)          \
  V(I8x16SubSatU)          \
  V(I8x16RoundingAverageU) \
  V(I8x16Swizzle)          \
  V(I8x16Shl)              \
  V(I8x16ShrS)             \
  V(I8x16ShrU)             \
  V(S128And)               \
  V(S128Or)                \
  V(S128Xor)               \
  V(S128AndNot)

#define SIMD_UNOP_LIST(V)      \
  V(F64x2Abs)                  \
  V(F64x2Neg)                  \
  V(F64x2Sqrt)                 \
  V(F64x2Ceil)                 \
  V(F64x2Floor)                \
  V(F64x2Trunc)                \
  V(F64x2ConvertLowI32x4S)     \
  V(F64x2ConvertLowI32x4U)     \
  V(F64x2PromoteLowF32x4)      \
  V(F64x2Splat)                \
  V(F32x4Abs)                  \
  V(F32x4Neg)                  \
  V(F32x4Sqrt)                 \
  V(F32x4SConvertI32x4)        \
  V(F32x4UConvertI32x4)        \
  V(F32x4Ceil)                 \
  V(F32x4Floor)                \
  V(F32x4Trunc)                \
  V(F32x4DemoteF64x2Zero)      \
  V(F32x4Splat)                \
  V(I64x2Abs)                  \
  V(I64x2Neg)                  \
  V(I64x2SConvertI32x4Low)     \
  V(I64x2SConvertI32x4High)    \
  V(I64x2UConvertI32x4Low)     \
  V(I64x2UConvertI32x4High)    \
  V(I64x2AllTrue)              \
  V(I64x2BitMask)              \
  V(I32x4Neg)                  \
  V(I64x2Splat)                \
  V(I32x4Abs)                  \
  V(I32x4SConvertF32x4)        \
  V(I32x4UConvertF32x4)        \
  V(I32x4SConvertI16x8Low)     \
  V(I32x4SConvertI16x8High)    \
  V(I32x4UConvertI16x8Low)     \
  V(I32x4UConvertI16x8High)    \
  V(I32x4ExtAddPairwiseI16x8S) \
  V(I32x4ExtAddPairwiseI16x8U) \
  V(I32x4TruncSatF64x2SZero)   \
  V(I32x4TruncSatF64x2UZero)   \
  V(I32x4AllTrue)              \
  V(I32x4BitMask)              \
  V(I32x4Splat)                \
  V(I16x8Neg)                  \
  V(I16x8Abs)                  \
  V(I16x8AllTrue)              \
  V(I16x8BitMask)              \
  V(I16x8Splat)                \
  V(I8x16Neg)                  \
  V(I8x16Abs)                  \
  V(I8x16Popcnt)               \
  V(I8x16AllTrue)              \
  V(I8x16BitMask)              \
  V(I8x16Splat)                \
  V(I16x8SConvertI8x16Low)     \
  V(I16x8SConvertI8x16High)    \
  V(I16x8UConvertI8x16Low)     \
  V(I16x8UConvertI8x16High)    \
  V(I16x8ExtAddPairwiseI8x16S) \
  V(I16x8ExtAddPairwiseI8x16U) \
  V(S128Not)                   \
  V(V128AnyTrue)

#define SIMD_VISIT_EXTRACT_LANE(Type, T, Sign, LaneSize)                   \
  template <typename Adapter>                                              \
  void InstructionSelectorT<Adapter>::Visit##Type##ExtractLane##Sign(      \
      node_t node) {                                                       \
    PPCOperandGeneratorT<Adapter> g(this);                                 \
    int32_t lane;                                                          \
    if constexpr (Adapter::IsTurboshaft) {                                 \
      using namespace turboshaft; /* NOLINT(build/namespaces) */           \
      const Operation& op = this->Get(node);                               \
      lane = op.template Cast<Simd128ExtractLaneOp>().lane;                \
    } else {                                                               \
      lane = OpParameter<int32_t>(node->op());                             \
    }                                                                      \
    Emit(kPPC_##T##ExtractLane##Sign | LaneSizeField::encode(LaneSize),    \
         g.DefineAsRegister(node), g.UseRegister(this->input_at(node, 0)), \
         g.UseImmediate(lane));                                            \
  }
SIMD_VISIT_EXTRACT_LANE(F64x2, F, , 64)
SIMD_VISIT_EXTRACT_LANE(F32x4, F, , 32)
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
    PPCOperandGeneratorT<Adapter> g(this);                                    \
    int32_t lane;                                                             \
    if constexpr (Adapter::IsTurboshaft) {                                    \
      using namespace turboshaft; /* NOLINT(build/namespaces) */              \
      const Operation& op = this->Get(node);                                  \
      lane = op.template Cast<Simd128ReplaceLaneOp>().lane;                   \
    } else {                                                                  \
      lane = OpParameter<int32_t>(node->op());                                \
    }                                                                         \
    Emit(kPPC_##T##ReplaceLane | LaneSizeField::encode(LaneSize),             \
         g.DefineSameAsFirst(node), g.UseRegister(this->input_at(node, 0)),   \
         g.UseImmediate(lane), g.UseRegister(this->input_at(node, 1)));       \
  }
SIMD_VISIT_REPLACE_LANE(F64x2, F, 64)
SIMD_VISIT_REPLACE_LANE(F32x4, F, 32)
SIMD_VISIT_REPLACE_LANE(I64x2, I, 64)
SIMD_VISIT_REPLACE_LANE(I32x4, I, 32)
SIMD_VISIT_REPLACE_LANE(I16x8, I, 16)
SIMD_VISIT_REPLACE_LANE(I8x16, I, 8)
#undef SIMD_VISIT_REPLACE_LANE

#define SIMD_VISIT_BINOP(Opcode)                                           \
  template <typename Adapter>                                              \
  void InstructionSelectorT<Adapter>::Visit##Opcode(node_t node) {         \
    PPCOperandGeneratorT<Adapter> g(this);                                 \
    InstructionOperand temps[] = {g.TempRegister()};                       \
    Emit(kPPC_##Opcode, g.DefineAsRegister(node),                          \
         g.UseRegister(this->input_at(node, 0)),                           \
         g.UseRegister(this->input_at(node, 1)), arraysize(temps), temps); \
  }
SIMD_BINOP_LIST(SIMD_VISIT_BINOP)
#undef SIMD_VISIT_BINOP
#undef SIMD_BINOP_LIST

#define SIMD_VISIT_UNOP(Opcode)                                    \
  template <typename Adapter>                                      \
  void InstructionSelectorT<Adapter>::Visit##Opcode(node_t node) { \
    PPCOperandGeneratorT<Adapter> g(this);                         \
    Emit(kPPC_##Opcode, g.DefineAsRegister(node),                  \
         g.UseRegister(this->input_at(node, 0)));                  \
  }
SIMD_UNOP_LIST(SIMD_VISIT_UNOP)
#undef SIMD_VISIT_UNOP
#undef SIMD_UNOP_LIST

#define SIMD_VISIT_QFMOP(Opcode)                                   \
  template <typename Adapter>                                      \
  void InstructionSelectorT<Adapter>::Visit##Opcode(node_t node) { \
    PPCOperandGeneratorT<Adapter> g(this);                         \
    Emit(kPPC_##Opcode, g.DefineSameAsFirst(node),                 \
         g.UseRegister(this->input_at(node, 0)),                   \
         g.UseRegister(this->input_at(node, 1)),                   \
         g.UseRegister(this->input_at(node, 2)));                  \
  }
SIMD_VISIT_QFMOP(F64x2Qfma)
SIMD_VISIT_QFMOP(F64x2Qfms)
SIMD_VISIT_QFMOP(F32x4Qfma)
SIMD_VISIT_QFMOP(F32x4Qfms)
#undef SIMD_VISIT_QFMOP

#define SIMD_RELAXED_OP_LIST(V)                           \
  V(F64x2RelaxedMin, F64x2Pmin)                           \
  V(F64x2RelaxedMax, F64x2Pmax)                           \
  V(F32x4RelaxedMin, F32x4Pmin)                           \
  V(F32x4RelaxedMax, F32x4Pmax)                           \
  V(I32x4RelaxedTruncF32x4S, I32x4SConvertF32x4)          \
  V(I32x4RelaxedTruncF32x4U, I32x4UConvertF32x4)          \
  V(I32x4RelaxedTruncF64x2SZero, I32x4TruncSatF64x2SZero) \
  V(I32x4RelaxedTruncF64x2UZero, I32x4TruncSatF64x2UZero) \
  V(I16x8RelaxedQ15MulRS, I16x8Q15MulRSatS)               \
  V(I8x16RelaxedLaneSelect, S128Select)                   \
  V(I16x8RelaxedLaneSelect, S128Select)                   \
  V(I32x4RelaxedLaneSelect, S128Select)                   \
  V(I64x2RelaxedLaneSelect, S128Select)

#define SIMD_VISIT_RELAXED_OP(name, op)                          \
  template <typename Adapter>                                    \
  void InstructionSelectorT<Adapter>::Visit##name(node_t node) { \
    Visit##op(node);                                             \
  }
SIMD_RELAXED_OP_LIST(SIMD_VISIT_RELAXED_OP)
#undef SIMD_VISIT_RELAXED_OP
#undef SIMD_RELAXED_OP_LIST

#define F16_OP_LIST(V)    \
  V(F16x8Splat)           \
  V(F16x8ExtractLane)     \
  V(F16x8ReplaceLane)     \
  V(F16x8Abs)             \
  V(F16x8Neg)             \
  V(F16x8Sqrt)            \
  V(F16x8Floor)           \
  V(F16x8Ceil)            \
  V(F16x8Trunc)           \
  V(F16x8NearestInt)      \
  V(F16x8Add)             \
  V(F16x8Sub)             \
  V(F16x8Mul)             \
  V(F16x8Div)             \
  V(F16x8Min)             \
  V(F16x8Max)             \
  V(F16x8Pmin)            \
  V(F16x8Pmax)            \
  V(F16x8Eq)              \
  V(F16x8Ne)              \
  V(F16x8Lt)              \
  V(F16x8Le)              \
  V(F16x8SConvertI16x8)   \
  V(F16x8UConvertI16x8)   \
  V(I16x8SConvertF16x8)   \
  V(I16x8UConvertF16x8)   \
  V(F32x4PromoteLowF16x8) \
  V(F16x8DemoteF32x4Zero) \
  V(F16x8DemoteF64x2Zero) \
  V(F16x8Qfma)            \
  V(F16x8Qfms)

#define VISIT_F16_OP(name)                                       \
  template <typename Adapter>                                    \
  void InstructionSelectorT<Adapter>::Visit##name(node_t node) { \
    UNIMPLEMENTED();                                             \
  }
F16_OP_LIST(VISIT_F16_OP)
#undef VISIT_F16_OP
#undef F16_OP_LIST
#undef SIMD_TYPES

#if V8_ENABLE_WEBASSEMBLY
template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI8x16Shuffle(node_t node) {
    uint8_t shuffle[kSimd128Size];
    bool is_swizzle;
    // TODO(nicohartmann@): Properly use view here once Turboshaft support is
    // implemented.
    auto view = this->simd_shuffle_view(node);
    CanonicalizeShuffle(view, shuffle, &is_swizzle);
    PPCOperandGeneratorT<Adapter> g(this);
    node_t input0 = view.input(0);
    node_t input1 = view.input(1);
    // Remap the shuffle indices to match IBM lane numbering.
    int max_index = 15;
    int total_lane_count = 2 * kSimd128Size;
    uint8_t shuffle_remapped[kSimd128Size];
    for (int i = 0; i < kSimd128Size; i++) {
      uint8_t current_index = shuffle[i];
      shuffle_remapped[i] =
          (current_index <= max_index
               ? max_index - current_index
               : total_lane_count - current_index + max_index);
    }
    Emit(kPPC_I8x16Shuffle, g.DefineAsRegister(node), g.UseRegister(input0),
         g.UseRegister(input1),
         g.UseImmediate(wasm::SimdShuffle::Pack4Lanes(shuffle_remapped)),
         g.UseImmediate(wasm::SimdShuffle::Pack4Lanes(shuffle_remapped + 4)),
         g.UseImmediate(wasm::SimdShuffle::Pack4Lanes(shuffle_remapped + 8)),
         g.UseImmediate(wasm::SimdShuffle::Pack4Lanes(shuffle_remapped + 12)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSetStackPointer(node_t node) {
  OperandGenerator g(this);
  // TODO(miladfarca): Optimize by using UseAny.
  auto input = g.UseRegister(this->input_at(node, 0));
  Emit(kArchSetStackPointer, 0, nullptr, 1, &input);
}

#else
template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI8x16Shuffle(node_t node) {
  UNREACHABLE();
}
#endif  // V8_ENABLE_WEBASSEMBLY

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitS128Zero(node_t node) {
    PPCOperandGeneratorT<Adapter> g(this);
    Emit(kPPC_S128Zero, g.DefineAsRegister(node));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitS128Select(node_t node) {
    PPCOperandGeneratorT<Adapter> g(this);
    Emit(kPPC_S128Select, g.DefineAsRegister(node),
         g.UseRegister(this->input_at(node, 0)),
         g.UseRegister(this->input_at(node, 1)),
         g.UseRegister(this->input_at(node, 2)));
}

// This is a replica of SimdShuffle::Pack4Lanes. However, above function will
// not be available on builds with webassembly disabled, hence we need to have
// it declared locally as it is used on other visitors such as S128Const.
static int32_t Pack4Lanes(const uint8_t* shuffle) {
  int32_t result = 0;
  for (int i = 3; i >= 0; --i) {
    result <<= 8;
    result |= shuffle[i];
  }
  return result;
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitS128Const(node_t node) {
    PPCOperandGeneratorT<Adapter> g(this);
    uint32_t val[kSimd128Size / sizeof(uint32_t)];
    if constexpr (Adapter::IsTurboshaft) {
      const turboshaft::Simd128ConstantOp& constant =
          this->Get(node).template Cast<turboshaft::Simd128ConstantOp>();
      memcpy(val, constant.value, kSimd128Size);
    } else {
      memcpy(val, S128ImmediateParameterOf(node->op()).data(), kSimd128Size);
    }
    // If all bytes are zeros, avoid emitting code for generic constants.
    bool all_zeros = !(val[0] || val[1] || val[2] || val[3]);
    bool all_ones = val[0] == UINT32_MAX && val[1] == UINT32_MAX &&
                    val[2] == UINT32_MAX && val[3] == UINT32_MAX;
    InstructionOperand dst = g.DefineAsRegister(node);
    if (all_zeros) {
      Emit(kPPC_S128Zero, dst);
    } else if (all_ones) {
      Emit(kPPC_S128AllOnes, dst);
    } else {
      // We have to use Pack4Lanes to reverse the bytes (lanes) on BE,
      // Which in this case is ineffective on LE.
      Emit(
          kPPC_S128Const, g.DefineAsRegister(node),
          g.UseImmediate(Pack4Lanes(reinterpret_cast<uint8_t*>(&val[0]))),
          g.UseImmediate(Pack4Lanes(reinterpret_cast<uint8_t*>(&val[0]) + 4)),
          g.UseImmediate(Pack4Lanes(reinterpret_cast<uint8_t*>(&val[0]) + 8)),
          g.UseImmediate(Pack4Lanes(reinterpret_cast<uint8_t*>(&val[0]) + 12)));
    }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI16x8DotI8x16I7x16S(node_t node) {
    PPCOperandGeneratorT<Adapter> g(this);
    Emit(kPPC_I16x8DotI8x16S, g.DefineAsRegister(node),
         g.UseUniqueRegister(this->input_at(node, 0)),
         g.UseUniqueRegister(this->input_at(node, 1)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4DotI8x16I7x16AddS(node_t node) {
    PPCOperandGeneratorT<Adapter> g(this);
    Emit(kPPC_I32x4DotI8x16AddS, g.DefineAsRegister(node),
         g.UseUniqueRegister(this->input_at(node, 0)),
         g.UseUniqueRegister(this->input_at(node, 1)),
         g.UseUniqueRegister(this->input_at(node, 2)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::EmitPrepareResults(
    ZoneVector<PushParameter>* results, const CallDescriptor* call_descriptor,
    node_t node) {
    PPCOperandGeneratorT<Adapter> g(this);

    for (PushParameter output : *results) {
    if (!output.location.IsCallerFrameSlot()) continue;
    // Skip any alignment holes in nodes.
    if (this->valid(output.node)) {
      DCHECK(!call_descriptor->IsCFunctionCall());
      if (output.location.GetType() == MachineType::Float32()) {
        MarkAsFloat32(output.node);
      } else if (output.location.GetType() == MachineType::Float64()) {
        MarkAsFloat64(output.node);
      } else if (output.location.GetType() == MachineType::Simd128()) {
        MarkAsSimd128(output.node);
      }
      int offset = call_descriptor->GetOffsetToReturns();
      int reverse_slot = -output.location.GetLocation() - offset;
      Emit(kPPC_Peek, g.DefineAsRegister(output.node),
           g.UseImmediate(reverse_slot));
    }
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitLoadLane(node_t node) {
  PPCOperandGeneratorT<Adapter> g(this);
  InstructionCode opcode = kArchNop;
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const Simd128LaneMemoryOp& load =
        this->Get(node).template Cast<Simd128LaneMemoryOp>();
    switch (load.lane_kind) {
      case Simd128LaneMemoryOp::LaneKind::k8:
        opcode = kPPC_S128Load8Lane;
        break;
      case Simd128LaneMemoryOp::LaneKind::k16:
        opcode = kPPC_S128Load16Lane;
        break;
      case Simd128LaneMemoryOp::LaneKind::k32:
        opcode = kPPC_S128Load32Lane;
        break;
      case Simd128LaneMemoryOp::LaneKind::k64:
        opcode = kPPC_S128Load64Lane;
        break;
    }
    Emit(opcode | AddressingModeField::encode(kMode_MRR),
         g.DefineSameAsFirst(node), g.UseRegister(load.value()),
         g.UseRegister(load.base()), g.UseRegister(load.index()),
         g.UseImmediate(load.lane));
  } else {
    LoadLaneParameters params = LoadLaneParametersOf(node->op());
    if (params.rep == MachineType::Int8()) {
      opcode = kPPC_S128Load8Lane;
    } else if (params.rep == MachineType::Int16()) {
      opcode = kPPC_S128Load16Lane;
    } else if (params.rep == MachineType::Int32()) {
      opcode = kPPC_S128Load32Lane;
    } else if (params.rep == MachineType::Int64()) {
      opcode = kPPC_S128Load64Lane;
    } else {
      UNREACHABLE();
    }
    Emit(opcode | AddressingModeField::encode(kMode_MRR),
         g.DefineSameAsFirst(node), g.UseRegister(node->InputAt(2)),
         g.UseRegister(node->InputAt(0)), g.UseRegister(node->InputAt(1)),
         g.UseImmediate(params.laneidx));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitLoadTransform(node_t node) {
  PPCOperandGeneratorT<Adapter> g(this);
  ArchOpcode opcode;
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const Simd128LoadTransformOp& op =
        this->Get(node).template Cast<Simd128LoadTransformOp>();
    node_t base = op.base();
    node_t index = op.index();

    switch (op.transform_kind) {
      case Simd128LoadTransformOp::TransformKind::k8Splat:
        opcode = kPPC_S128Load8Splat;
        break;
      case Simd128LoadTransformOp::TransformKind::k16Splat:
        opcode = kPPC_S128Load16Splat;
        break;
      case Simd128LoadTransformOp::TransformKind::k32Splat:
        opcode = kPPC_S128Load32Splat;
        break;
      case Simd128LoadTransformOp::TransformKind::k64Splat:
        opcode = kPPC_S128Load64Splat;
        break;
      case Simd128LoadTransformOp::TransformKind::k8x8S:
        opcode = kPPC_S128Load8x8S;
        break;
      case Simd128LoadTransformOp::TransformKind::k8x8U:
        opcode = kPPC_S128Load8x8U;
        break;
      case Simd128LoadTransformOp::TransformKind::k16x4S:
        opcode = kPPC_S128Load16x4S;
        break;
      case Simd128LoadTransformOp::TransformKind::k16x4U:
        opcode = kPPC_S128Load16x4U;
        break;
      case Simd128LoadTransformOp::TransformKind::k32x2S:
        opcode = kPPC_S128Load32x2S;
        break;
      case Simd128LoadTransformOp::TransformKind::k32x2U:
        opcode = kPPC_S128Load32x2U;
        break;
      case Simd128LoadTransformOp::TransformKind::k32Zero:
        opcode = kPPC_S128Load32Zero;
        break;
      case Simd128LoadTransformOp::TransformKind::k64Zero:
        opcode = kPPC_S128Load64Zero;
        break;
      default:
        UNIMPLEMENTED();
    }
    Emit(opcode | AddressingModeField::encode(kMode_MRR),
         g.DefineAsRegister(node), g.UseRegister(base), g.UseRegister(index));
  } else {
    LoadTransformParameters params = LoadTransformParametersOf(node->op());
    PPCOperandGeneratorT<Adapter> g(this);
    Node* base = node->InputAt(0);
    Node* index = node->InputAt(1);

    switch (params.transformation) {
      case LoadTransformation::kS128Load8Splat:
        opcode = kPPC_S128Load8Splat;
        break;
      case LoadTransformation::kS128Load16Splat:
        opcode = kPPC_S128Load16Splat;
        break;
      case LoadTransformation::kS128Load32Splat:
        opcode = kPPC_S128Load32Splat;
        break;
      case LoadTransformation::kS128Load64Splat:
        opcode = kPPC_S128Load64Splat;
        break;
      case LoadTransformation::kS128Load8x8S:
        opcode = kPPC_S128Load8x8S;
        break;
      case LoadTransformation::kS128Load8x8U:
        opcode = kPPC_S128Load8x8U;
        break;
      case LoadTransformation::kS128Load16x4S:
        opcode = kPPC_S128Load16x4S;
        break;
      case LoadTransformation::kS128Load16x4U:
        opcode = kPPC_S128Load16x4U;
        break;
      case LoadTransformation::kS128Load32x2S:
        opcode = kPPC_S128Load32x2S;
        break;
      case LoadTransformation::kS128Load32x2U:
        opcode = kPPC_S128Load32x2U;
        break;
      case LoadTransformation::kS128Load32Zero:
        opcode = kPPC_S128Load32Zero;
        break;
      case LoadTransformation::kS128Load64Zero:
        opcode = kPPC_S128Load64Zero;
        break;
      default:
        UNREACHABLE();
    }
    Emit(opcode | AddressingModeField::encode(kMode_MRR),
         g.DefineAsRegister(node), g.UseRegister(base), g.UseRegister(index));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitStoreLane(node_t node) {
    PPCOperandGeneratorT<Adapter> g(this);
    InstructionCode opcode = kArchNop;
    InstructionOperand inputs[4];
    if constexpr (Adapter::IsTurboshaft) {
      using namespace turboshaft;  // NOLINT(build/namespaces)
      const Simd128LaneMemoryOp& store =
          this->Get(node).template Cast<Simd128LaneMemoryOp>();
      switch (store.lane_kind) {
        case Simd128LaneMemoryOp::LaneKind::k8:
          opcode = kPPC_S128Store8Lane;
          break;
        case Simd128LaneMemoryOp::LaneKind::k16:
          opcode = kPPC_S128Store16Lane;
          break;
        case Simd128LaneMemoryOp::LaneKind::k32:
          opcode = kPPC_S128Store32Lane;
          break;
        case Simd128LaneMemoryOp::LaneKind::k64:
          opcode = kPPC_S128Store64Lane;
          break;
      }

      inputs[0] = g.UseRegister(store.value());
      inputs[1] = g.UseRegister(store.base());
      inputs[2] = g.UseRegister(store.index());
      inputs[3] = g.UseImmediate(store.lane);
    } else {
      StoreLaneParameters params = StoreLaneParametersOf(node->op());
      if (params.rep == MachineRepresentation::kWord8) {
        opcode = kPPC_S128Store8Lane;
      } else if (params.rep == MachineRepresentation::kWord16) {
        opcode = kPPC_S128Store16Lane;
      } else if (params.rep == MachineRepresentation::kWord32) {
        opcode = kPPC_S128Store32Lane;
      } else if (params.rep == MachineRepresentation::kWord64) {
        opcode = kPPC_S128Store64Lane;
      } else {
        UNREACHABLE();
      }

      inputs[0] = g.UseRegister(node->InputAt(2));
      inputs[1] = g.UseRegister(node->InputAt(0));
      inputs[2] = g.UseRegister(node->InputAt(1));
      inputs[3] = g.UseImmediate(params.laneidx);
    }
    Emit(opcode | AddressingModeField::encode(kMode_MRR), 0, nullptr, 4,
         inputs);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::AddOutputToSelectContinuation(
    OperandGenerator* g, int first_input_index, node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32RoundTiesEven(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64RoundTiesEven(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x2NearestInt(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF32x4NearestInt(node_t node) {
  UNREACHABLE();
}

MachineOperatorBuilder::Flags
InstructionSelector::SupportedMachineOperatorFlags() {
  return MachineOperatorBuilder::kFloat32RoundDown |
         MachineOperatorBuilder::kFloat64RoundDown |
         MachineOperatorBuilder::kFloat32RoundUp |
         MachineOperatorBuilder::kFloat64RoundUp |
         MachineOperatorBuilder::kFloat32RoundTruncate |
         MachineOperatorBuilder::kFloat64RoundTruncate |
         MachineOperatorBuilder::kFloat64RoundTiesAway |
         MachineOperatorBuilder::kWord32Popcnt |
         MachineOperatorBuilder::kWord64Popcnt;
  // We omit kWord32ShiftIsSafe as s[rl]w use 0x3F as a mask rather than 0x1F.
}

MachineOperatorBuilder::AlignmentRequirements
InstructionSelector::AlignmentRequirements() {
  return MachineOperatorBuilder::AlignmentRequirements::
      FullUnalignedAccessSupport();
}

template class EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE)
    InstructionSelectorT<TurbofanAdapter>;
template class EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE)
    InstructionSelectorT<TurboshaftAdapter>;

}  // namespace compiler
}  // namespace internal
}  // namespace v8

"""


```