Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/compiler/backend/ppc/instruction-selector-ppc.cc`. They also have specific questions about the code's nature, its relation to JavaScript, logic, and potential errors.

Here's a breakdown of the thought process to answer the user's request:

1. **Identify the core purpose of the file:** The filename `instruction-selector-ppc.cc` strongly suggests this code is responsible for selecting machine instructions for the PowerPC (PPC) architecture during the compilation process in V8. It acts as a bridge between the high-level intermediate representation (IR) of the code and the low-level machine instructions.

2. **Check for Torque:** The prompt asks if the file ends in `.tq`, indicating a Torque source file. This file ends in `.cc`, so it's standard C++ code, not Torque.

3. **Analyze JavaScript relationship:** Instruction selectors are directly involved in translating JavaScript (after it's been processed by the V8 pipeline) into executable machine code. Therefore, there's a strong connection. To illustrate this, think of a simple JavaScript operation and how it might be translated.

4. **Examine code logic and provide examples:** The code contains numerous `Visit...` functions. Each of these functions likely handles a specific type of operation in the IR. Focus on some representative examples:
    * **Atomic Operations:**  The `VisitWord32Atomic...` and `VisitWord64Atomic...` functions and the `VISIT_ATOMIC_BINOP` macro clearly deal with atomic operations. Trace the logic of `VisitAtomicBinaryOperation` to understand how it selects the appropriate opcode based on the data type. Provide an example of a JavaScript atomic operation.
    * **SIMD Operations:** The numerous `Visit...` functions for `F64x2`, `F32x4`, `I64x2`, etc., clearly handle SIMD (Single Instruction, Multiple Data) operations. Pick a simple SIMD binary operation like `F64x2Add` and illustrate with a JavaScript SIMD example.
    * **Load/Store Operations:**  The `VisitLoadLane`, `VisitLoadTransform`, and `VisitStoreLane` functions deal with loading and storing data, especially within SIMD vectors. Explain their function and provide conceptual examples.
    * **Other Operations:**  Note other interesting functions like `VisitI8x16Shuffle`, `VisitS128Const`, `VisitSetStackPointer`, and their likely purpose.

5. **Identify potential programming errors:** Consider what mistakes a developer might make that would be relevant to this code. Type mismatches are a common source of errors when working with low-level code or when using features like atomic operations or SIMD, where specific data layouts are crucial.

6. **Address the "Part 5 of 5" instruction:** The user explicitly states this is part 5 of 5. This suggests they expect a summary or conclusion that ties together the functionality described in the previous parts (even though we don't have those parts). Therefore, provide a concise summary of the overall role of the `instruction-selector-ppc.cc` file within the V8 compilation pipeline.

7. **Review and Refine:** After drafting the initial answer, review it for clarity, accuracy, and completeness. Ensure the JavaScript examples are relevant and easy to understand. Check that the code logic explanations are correct and that the identified potential errors are pertinent. Ensure the summary addresses the "part 5 of 5" aspect. Specifically, confirm that the provided code *is* indeed an instruction selector and acts as the final stage before code emission for the PPC architecture.
`v8/src/compiler/backend/ppc/instruction-selector-ppc.cc` 是 V8 JavaScript 引擎中用于 PowerPC (PPC) 架构的**指令选择器**的源代码文件。它的主要功能是将**与架构无关的中间表示（IR）**的操作转换为**特定的 PPC 机器指令**。这是代码生成过程中的关键步骤，发生在调度（scheduling）之后，寄存器分配（register allocation）之前。

**具体功能列举：**

1. **遍历中间表示 (IR) 图:**  指令选择器会遍历编译器生成的中间表示图，该图由各种节点组成，每个节点代表一个操作（例如，加法、乘法、加载、存储等）。

2. **模式匹配:** 对于每个 IR 节点，指令选择器会尝试找到与该操作匹配的 PPC 指令模式。这意味着它会根据操作的类型、操作数类型和一些限制条件来选择合适的机器指令。

3. **生成机器指令:** 一旦找到匹配的指令模式，指令选择器就会生成相应的 PPC 机器指令。这包括确定操作码、操作数（寄存器、立即数、内存地址等）以及指令的寻址模式。

4. **处理各种操作类型:**  从代码中可以看出，指令选择器支持多种操作类型，包括：
    * **算术和逻辑运算:** 加法、减法、乘法、除法、按位与、按位或、按位异或等。
    * **比较运算:**  相等、不等、大于、小于等。
    * **加载和存储操作:** 从内存加载数据到寄存器，将寄存器中的数据存储到内存。
    * **类型转换:**  在不同的数据类型之间进行转换。
    * **原子操作:**  以原子方式执行的操作，例如原子加、原子减等。
    * **SIMD (Single Instruction, Multiple Data) 操作:**  针对向量数据执行并行操作，例如 F64x2Add (双精度浮点数向量加法)、I32x4Mul (32 位整数向量乘法) 等。
    * **浮点数操作:**  各种浮点数运算，包括基本的算术运算、平方根、取整等。
    * **WebAssembly 特定的操作:** 例如 `VisitI8x16Shuffle`，用于处理 WebAssembly 中的 SIMD shuffle 操作。
    * **调用操作:**  处理函数调用。
    * **加载和存储 Lane 操作:**  针对 SIMD 向量中的特定元素（lane）进行加载和存储。
    * **加载转换操作:**  将内存中的数据加载并转换成 SIMD 向量的特定形式（例如，将一个字节加载并复制到向量的所有字节）。

5. **处理不同的数据类型:**  指令选择器需要处理各种数据类型，包括整数 (8位、16位、32位、64位，有符号和无符号)、浮点数 (单精度、双精度) 以及 SIMD 向量。

6. **考虑寻址模式:**  不同的 PPC 指令支持不同的寻址模式（例如，寄存器寻址、立即数寻址、寄存器偏移寻址）。指令选择器需要根据操作数的位置和类型选择合适的寻址模式。

7. **与操作数生成器交互:**  `PPCOperandGeneratorT` 类负责生成机器指令的操作数。指令选择器会调用操作数生成器的方法来获取表示寄存器、立即数或内存地址的操作数。

8. **发射指令:**  `Emit` 函数用于将生成的机器指令添加到最终的代码流中。

**关于 `.tq` 结尾：**

如果 `v8/src/compiler/backend/ppc/instruction-selector-ppc.cc` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码文件**。Torque 是 V8 用于定义运行时内置函数和编译器辅助函数的领域特定语言。由于该文件以 `.cc` 结尾，它是一个标准的 C++ 源代码文件。

**与 JavaScript 的功能关系和 JavaScript 示例：**

指令选择器是 V8 编译管道的关键部分，它直接将 JavaScript 代码转换为机器码。以下是一些 JavaScript 示例以及指令选择器可能如何处理它们：

```javascript
// 简单的加法运算
let a = 10;
let b = 20;
let sum = a + b;

// 指令选择器可能生成类似的 PPC 指令：
// add r3, r1, r2  ; 将寄存器 r1 和 r2 的值相加，结果存储到 r3
```

```javascript
// 访问数组元素
let arr = [1, 2, 3];
let value = arr[1];

// 指令选择器可能生成类似的 PPC 指令：
// lwz r3, offset(r4) ; 从寄存器 r4 + offset 的内存地址加载字到寄存器 r3
// (其中 r4 可能指向数组的基地址，offset 是索引 1 对应的偏移量)
```

```javascript
// 使用 SIMD 进行向量加法
let a = [1.0, 2.0];
let b = [3.0, 4.0];
// ... (假设 JavaScript 引擎内部使用了类似 SIMD 的表示)

// 指令选择器可能生成类似的 PPC SIMD 指令：
// fadds v1, v2, v3 ; 将向量寄存器 v2 和 v3 的值相加，结果存储到 v1
```

**代码逻辑推理、假设输入与输出：**

以 `VisitAtomicBinaryOperation` 函数为例：

**假设输入：**

* `node`: 一个代表原子加操作的 IR 节点，其操作数分别是 `base`（内存地址的基址）、`index`（内存地址的偏移量）和 `value`（要加的值）。
* `AtomicOpType(node->op())`:  假设返回 `MachineType::Int32()`，表示原子操作的目标是 32 位整数。

**代码逻辑推理：**

1. 进入 `VisitAtomicBinaryOperation` 函数。
2. `is_弱表示` 条件为 false，因为 `AtomicOpType(node->op())` 返回了具体的 `MachineType`。
3. 进入 `else` 分支。
4. `type` 被设置为 `MachineType::Int32()`。
5. `opcode` 被设置为 `int32_op`，也就是 `kPPC_AtomicAddInt32`。
6. 寻址模式 `addressing_mode` 被设置为 `kMode_MRR`（寄存器 + 寄存器 + 寄存器）。
7. `code` 被设置为 `kPPC_AtomicAddInt32` 加上编码后的寻址模式。
8. 输入操作数 `inputs` 被设置为 `base`、`index` 和 `value` 对应的寄存器。
9. 输出操作数 `outputs` 被设置为 `node` 对应的寄存器。
10. 调用 `selector->Emit` 发射指令。

**假设输出（生成的 PPC 指令）：**

假设 `base`、`index` 和 `value` 分别分配到寄存器 `r10`、`r11` 和 `r12`，并且 `node` 的结果需要存储到 `r13`，则 `Emit` 函数可能会生成类似于以下的指令：

```assembly
lwarx r13, r12, r10, r11  ; Load word and reserve indexed (用于原子操作)
add r13, r13, r12
stwcx. r13, r10, r11      ; Store word conditional indexed
bne -                      ; 如果存储失败，则重试
```

**用户常见的编程错误：**

虽然指令选择器是编译器内部的组件，用户通常不会直接与之交互，但用户编写的 JavaScript 代码中的某些模式可能会导致编译器在指令选择阶段遇到困难或生成次优代码。以下是一些相关的例子：

1. **类型不匹配导致的频繁转换:**  如果 JavaScript 代码中频繁地在不同类型之间进行操作，例如整数和浮点数之间，指令选择器可能需要生成额外的类型转换指令，降低性能。

   ```javascript
   let x = 5;  // 整数
   let y = 2.5; // 浮点数
   let result = x + y; // 需要将 x 转换为浮点数
   ```

2. **过度使用动态特性:**  过度依赖 JavaScript 的动态特性，例如运行时添加属性，可能会使编译器难以进行类型推断和优化，从而导致指令选择器生成更通用的、效率较低的指令。

3. **在性能关键代码中使用非优化的模式:**  某些 JavaScript 编程模式可能不如其他模式高效。例如，在循环中进行大量的 DOM 操作或字符串拼接可能会导致指令选择器生成大量的内存访问和操作指令。

4. **SIMD 使用不当:** 如果尝试在不支持 SIMD 的环境中或者以错误的方式使用 SIMD API，可能会导致错误或者性能下降。指令选择器依赖于底层的硬件支持来生成 SIMD 指令。

**归纳功能 (作为第 5 部分的总结):**

作为整个编译过程的最后阶段之一，`v8/src/compiler/backend/ppc/instruction-selector-ppc.cc` 的核心功能是将高级的、与架构无关的中间表示操作**精确地翻译**成低级的、特定于 PowerPC 架构的机器指令。它负责：

* **理解中间表示的语义：**  识别每个操作的含义和所需的操作数。
* **映射到 PPC 指令集：**  为每个中间表示操作选择最合适的 PPC 指令或指令序列。
* **处理各种数据类型和操作：**  支持 JavaScript 中使用的各种数据类型和运算，包括标量和向量操作。
* **考虑目标架构的特性：**  利用 PPC 架构的特性和优化机会。
* **为后续的寄存器分配做准备：**  生成带有虚拟寄存器的指令，供后续的寄存器分配阶段使用物理寄存器替换。

总而言之，`instruction-selector-ppc.cc` 是 V8 引擎将 JavaScript 代码转换为可在 PPC 架构上执行的高效机器码的关键组成部分，它弥合了高级语言和底层硬件之间的鸿沟。它确保了生成的代码能够正确且高效地在 PowerPC 架构的处理器上运行。

### 提示词
```
这是目录为v8/src/compiler/backend/ppc/instruction-selector-ppc.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/ppc/instruction-selector-ppc.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
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
```