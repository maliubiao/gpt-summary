Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/compiler/backend/x64/instruction-selector-x64.cc`.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the core purpose:** The filename "instruction-selector-x64.cc" strongly suggests this code is responsible for selecting specific x64 machine instructions based on higher-level intermediate representations (IR) of the code. This is a key part of the compilation process.

2. **Analyze the code structure:**  The code uses a template pattern (`InstructionSelectorT<Adapter>`), indicating it's designed to work with different adapter types. This likely allows it to be used with both Turbofan (the older V8 compiler) and Turboshaft (the newer one).

3. **Examine the `case` statements:** The first large block of code is a `switch` statement on `IrOpcode`. This confirms the purpose of selecting instructions based on the type of operation in the IR. The listed opcodes (e.g., `kInt32Add`, `kLoad`, `kFloat64Div`) represent various arithmetic, memory access, and type conversion operations. The comments within this block are crucial for understanding its function (e.g., "implicitly zero-extend to 64-bit on x64").

4. **Focus on the functions:** The code defines numerous member functions within the `InstructionSelectorT` template. Functions like `VisitChangeUint32ToUint64`, `VisitRO`, `VisitRR`, `VisitFloatBinop`, `VisitFloatUnop`, and specific `Visit` methods for various IR opcodes (e.g., `VisitFloat32Add`, `VisitTruncateInt64ToInt32`) show how the instruction selection is implemented for different operations. The `Emit` calls within these functions are the actual point where machine instructions are generated.

5. **Recognize helper functions:**  Helper functions like `ZeroExtendsWord32ToWord64`, `VisitCompareWithMemoryOperand`, `VisitCompare`, `TryNarrowOpcodeSize`, and `MachineTypeForNarrow` indicate supporting logic for instruction selection, often dealing with optimization and handling specific cases.

6. **Infer broader context:**  The mention of "AVX" and "SSE" instructions points to the code's awareness of different x64 instruction set extensions for performance. The handling of function calls (`EmitPrepareArguments`, `EmitPrepareResults`) highlights its role in managing the calling convention.

7. **Address specific questions from the prompt:**
    * **Functionality:** Based on the above analysis, the main function is to translate IR operations into x64 machine instructions.
    * **.tq extension:**  The code is C++, not Torque.
    * **JavaScript relevance:** The operations handled directly correspond to JavaScript operations (arithmetic, type conversions, etc.). Provide illustrative JavaScript examples.
    * **Code logic推理:**  Focus on the `ZeroExtendsWord32ToWord64` function as a simple example with clear input/output.
    * **Common programming errors:** Connect the `TruncateInt64ToInt32` optimization to potential data loss when implicitly converting from 64-bit to 32-bit integers in JavaScript.
    * **Part of a larger process:** Emphasize that this is part of the compiler's backend and instruction selection phase.

8. **Structure the answer:** Organize the findings into logical sections addressing each point in the prompt. Use clear and concise language.

9. **Review and refine:** Check the accuracy of the explanations and examples. Ensure the answer is comprehensive and addresses all aspects of the prompt. For example, double-check the list of functionalities derived from the code analysis. Make sure the JavaScript examples are simple and illustrate the relevant concepts. Ensure the explanation about the `.tq` extension is clear.

By following these steps, we can systematically analyze the code snippet and generate a comprehensive and informative answer that addresses the user's request.
这个C++源代码文件 `v8/src/compiler/backend/x64/instruction-selector-x64.cc` 是V8 JavaScript引擎中针对x64架构的**指令选择器 (Instruction Selector)** 的实现。它的主要功能是将**平台无关的中间表示 (Intermediate Representation, IR)** 转换成特定的 **x64 机器指令**。

以下是更详细的功能列表：

1. **指令选择核心逻辑:**  该文件包含了将各种IR操作码 (例如 `kInt32Add`, `kLoad`, `kFloat64Div`) 映射到相应的x64汇编指令的核心逻辑。 例如，看到 `IrOpcode::kInt32Add`，它会选择对应的x64加法指令。

2. **处理不同的IR节点:**  代码中大量的 `case IrOpcode::...` 分支表明它针对不同的IR节点类型有特定的处理方式。每种IR节点代表一种操作，指令选择器负责为该操作选择最合适的x64指令序列。

3. **利用x64特性进行优化:** 代码中注释提到的一些x64的特性被利用，例如 "32-bit operations implicitly zero-extend to 64-bit on x64"。 这意味着对于某些32位操作，不需要显式地进行零扩展，可以省略一些指令。

4. **处理数据加载和存储:**  代码中包含对 `kLoad`, `kStore` 等操作的处理，涉及到选择正确的内存访问指令，并考虑不同的加载表示 (例如 `kWord8`, `kWord16`, `kWord32`)。

5. **处理常量:**  对于 `kInt32Constant`, `kInt64Constant` 等常量节点，会选择合适的指令将常量加载到寄存器中。 `g.CanBeImmediate(node)` 检查常量是否可以直接作为立即数使用，从而优化指令。

6. **处理类型转换:**  例如 `VisitChangeUint32ToUint64`, `VisitTruncateFloat64ToInt32` 等函数，负责选择正确的指令进行类型转换。  代码中还考虑了某些类型转换的隐式发生，从而避免不必要的指令。

7. **处理浮点运算:** 包含了对各种浮点数运算 (加、减、乘、除、平方根等) 的处理，并区分了使用 AVX 和 SSE 指令的情况，以利用硬件加速。

8. **处理位运算和逻辑运算:** 虽然这部分代码片段中没有直接展示，但指令选择器通常也会处理位运算 (AND, OR, XOR, SHIFT) 和逻辑运算。

9. **处理函数调用:**  `EmitPrepareArguments`, `EmitPrepareResults` 等函数负责处理函数调用时的参数准备和结果获取，包括将参数放置到寄存器或栈上。

10. **处理比较操作:**  `VisitCompare` 函数及其相关的逻辑负责将IR的比较操作转换为x64的比较指令，并处理条件跳转和条件选择的情况。

11. **指令融合 (Instruction Fusion):**  在 `VisitTruncateInt64ToInt32` 函数中，可以看到尝试将截断操作融入到之前的加载操作中 (`TryEmitLoadForLoadWord64AndShiftRight`, `TryMergeTruncateInt64ToInt32IntoLoad`)，这是一种优化手段，减少指令数量。

**关于问题中的其他点：**

* **`.tq` 结尾:**  根据你的描述，如果文件以 `.tq` 结尾，那它就是 Torque 源代码。但此文件名为 `.cc`，因此它是标准的 C++ 源代码，而非 Torque 代码。

* **与 JavaScript 功能的关系:**  这个文件直接关系到 JavaScript 的执行性能。指令选择器生成的机器指令是 CPU 最终执行的代码。例如，当你执行 JavaScript 的加法运算、访问对象属性或进行类型转换时，这个文件中的代码就负责将这些高级操作转化为底层的x64指令。

**JavaScript 举例说明:**

```javascript
let a = 10;
let b = 5;
let sum = a + b;
let isGreater = a > b;
let floatNum = 3.14;
let intNum = parseInt(floatNum);
```

当 V8 编译这段 JavaScript 代码时，指令选择器会：

* 对于 `a + b`，选择 x64 的加法指令 (`ADD`).
* 对于 `a > b`，选择 x64 的比较指令 (`CMP`) 和相应的条件跳转指令 (例如 `JG` - jump if greater).
* 对于 `parseInt(floatNum)`，选择将浮点数转换为整数的 x64 指令 (例如 `CVTTPS2DQ` 或类似的指令).

**代码逻辑推理示例 (假设输入与输出):**

**假设输入:** 一个代表 `IrOpcode::kInt32Add` 的 IR 节点，其输入是两个表示寄存器或内存位置的 ValueOperand。

**输出:**  一个 `Instruction` 对象，其包含 `kX64Add` 指令码，并指定了源操作数和目标操作数 (通常目标操作数与其中一个源操作数相同，表示将结果写回)。

**例如：**

如果输入的 `kInt32Add` 节点的两个输入分别对应寄存器 `rax` 和内存地址 `[rbp-0x10]`，那么指令选择器可能会生成一个 `kX64Add` 指令，其操作数为 `rax` 和 `[rbp-0x10]`，目标操作数为 `rax`。

**涉及用户常见的编程错误 (与优化相关):**

尽管指令选择器本身不直接处理用户代码的错误，但它的一些优化策略可能与某些编程习惯相关。 例如，在 `VisitTruncateInt64ToInt32` 中，代码尝试优化 64 位整数截断为 32 位整数的情况。

**常见错误:**  在 JavaScript 中，如果用户执行涉及大整数的运算，然后将其赋值给一个预期是 32 位整数的变量，可能会发生数据丢失。

```javascript
let bigNumber = 9007199254740991; // 大于 32 位有符号整数的最大值
let smallNumber = parseInt(bigNumber);
console.log(smallNumber); // 输出结果可能不是预期的，因为发生了截断
```

指令选择器在编译 `parseInt(bigNumber)` 时，会选择将 64 位浮点数 (JavaScript 中数字的表示方式) 转换为 32 位整数的指令，这会导致高位的丢失。

**归纳一下它的功能 (作为第 5 部分):**

作为编译过程的一部分，`v8/src/compiler/backend/x64/instruction-selector-x64.cc` 的主要功能是 **将高级的、平台无关的中间表示 (IR) 翻译成特定于 x64 架构的低级机器指令**。 这是代码生成阶段的关键步骤，它直接影响最终生成代码的性能。它针对不同的 IR 操作选择最优的 x64 指令，并利用 x64 架构的特性进行优化，从而确保 JavaScript 代码能在 x64 平台上高效执行。

### 提示词
```
这是目录为v8/src/compiler/backend/x64/instruction-selector-x64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/x64/instruction-selector-x64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共10部分，请归纳一下它的功能
```

### 源代码
```cpp
case IrOpcode::kInt32Add:
    case IrOpcode::kInt32Sub:
    case IrOpcode::kInt32Mul:
    case IrOpcode::kInt32MulHigh:
    case IrOpcode::kInt32Div:
    case IrOpcode::kInt32LessThan:
    case IrOpcode::kInt32LessThanOrEqual:
    case IrOpcode::kInt32Mod:
    case IrOpcode::kUint32Div:
    case IrOpcode::kUint32LessThan:
    case IrOpcode::kUint32LessThanOrEqual:
    case IrOpcode::kUint32Mod:
    case IrOpcode::kUint32MulHigh:
    case IrOpcode::kTruncateInt64ToInt32:
      // These 32-bit operations implicitly zero-extend to 64-bit on x64, so the
      // zero-extension is a no-op.
      return true;
    case IrOpcode::kProjection: {
      Node* const value = node->InputAt(0);
      switch (value->opcode()) {
        case IrOpcode::kInt32AddWithOverflow:
        case IrOpcode::kInt32SubWithOverflow:
        case IrOpcode::kInt32MulWithOverflow:
          return true;
        default:
          return false;
      }
    }
    case IrOpcode::kLoad:
    case IrOpcode::kLoadImmutable:
    case IrOpcode::kProtectedLoad:
    case IrOpcode::kLoadTrapOnNull: {
      // The movzxbl/movsxbl/movzxwl/movsxwl/movl operations implicitly
      // zero-extend to 64-bit on x64, so the zero-extension is a no-op.
      LoadRepresentation load_rep = LoadRepresentationOf(node->op());
      switch (load_rep.representation()) {
        case MachineRepresentation::kWord8:
        case MachineRepresentation::kWord16:
        case MachineRepresentation::kWord32:
          return true;
        default:
          return false;
      }
    }
    case IrOpcode::kInt32Constant:
    case IrOpcode::kInt64Constant:
      // Constants are loaded with movl or movq, or xorl for zero; see
      // CodeGenerator::AssembleMove. So any non-negative constant that fits
      // in a 32-bit signed integer is zero-extended to 64 bits.
      if (g.CanBeImmediate(node)) {
        return g.GetImmediateIntegerValue(node) >= 0;
      }
      return false;
    default:
      return false;
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitChangeUint32ToUint64(node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  DCHECK_EQ(this->value_input_count(node), 1);
  node_t value = this->input_at(node, 0);
  if (ZeroExtendsWord32ToWord64(value)) {
    // These 32-bit operations implicitly zero-extend to 64-bit on x64, so the
    // zero-extension is a no-op.
    return EmitIdentity(node);
  }
  Emit(kX64Movl, g.DefineAsRegister(node), g.Use(value));
}

namespace {

template <typename Adapter>
void VisitRO(InstructionSelectorT<Adapter>* selector,
             typename Adapter::node_t node, InstructionCode opcode) {
  X64OperandGeneratorT<Adapter> g(selector);
  DCHECK_EQ(selector->value_input_count(node), 1);
  selector->Emit(opcode, g.DefineAsRegister(node),
                 g.Use(selector->input_at(node, 0)));
}

template <typename Adapter>
void VisitRR(InstructionSelectorT<Adapter>* selector,
             typename Adapter::node_t node, InstructionCode opcode) {
  X64OperandGeneratorT<Adapter> g(selector);
  selector->Emit(opcode, g.DefineAsRegister(node),
                 g.UseRegister(selector->input_at(node, 0)));
}

template <typename Adapter>
void VisitRRO(InstructionSelectorT<Adapter>* selector,
              typename Adapter::node_t node, InstructionCode opcode) {
  X64OperandGeneratorT<Adapter> g(selector);
  selector->Emit(opcode, g.DefineSameAsFirst(node),
                 g.UseRegister(selector->input_at(node, 0)),
                 g.Use(selector->input_at(node, 1)));
}

template <typename Adapter>
void VisitFloatBinop(InstructionSelectorT<Adapter>* selector,
                     typename Adapter::node_t node, InstructionCode avx_opcode,
                     InstructionCode sse_opcode) {
  X64OperandGeneratorT<Adapter> g(selector);
  DCHECK_EQ(selector->value_input_count(node), 2);
  auto left = selector->input_at(node, 0);
  auto right = selector->input_at(node, 1);
  InstructionOperand inputs[8];
  size_t input_count = 0;
  InstructionOperand outputs[1];
  size_t output_count = 0;
  typename Adapter::node_t trapping_load = {};

  if (left == right) {
    // If both inputs refer to the same operand, enforce allocating a register
    // for both of them to ensure that we don't end up generating code like
    // this:
    //
    //   movss rax, [rbp-0x10]
    //   addss rax, [rbp-0x10]
    //   jo label
    InstructionOperand const input = g.UseRegister(left);
    inputs[input_count++] = input;
    inputs[input_count++] = input;
  } else {
    int effect_level = selector->GetEffectLevel(node);
    if (selector->IsCommutative(node) &&
        (g.CanBeBetterLeftOperand(right) ||
         g.CanBeMemoryOperand(avx_opcode, node, left, effect_level)) &&
        (!g.CanBeBetterLeftOperand(left) ||
         !g.CanBeMemoryOperand(avx_opcode, node, right, effect_level))) {
      std::swap(left, right);
    }
    if (g.CanBeMemoryOperand(avx_opcode, node, right, effect_level)) {
      inputs[input_count++] = g.UseRegister(left);
      AddressingMode addressing_mode =
          g.GetEffectiveAddressMemoryOperand(right, inputs, &input_count);
      avx_opcode |= AddressingModeField::encode(addressing_mode);
      sse_opcode |= AddressingModeField::encode(addressing_mode);
      if constexpr (Adapter::IsTurboshaft) {
        if (g.IsProtectedLoad(right) &&
            selector->CanCoverProtectedLoad(node, right)) {
          // In {CanBeMemoryOperand} we have already checked that
          // CanCover(node, right) succeds, which means that there is no
          // instruction with Effects required_when_unused or
          // produces.control_flow between right and node, and that the node has
          // no other uses. Therefore, we can record the fact that 'right' was
          // embedded in 'node' and we can later delete the Load instruction.
          selector->MarkAsProtected(node);
          avx_opcode |=
              AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
          sse_opcode |=
              AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
          selector->SetProtectedLoadToRemove(right);
          trapping_load = right;
        }
      }
    } else {
      inputs[input_count++] = g.UseRegister(left);
      inputs[input_count++] = g.Use(right);
    }
  }

  DCHECK_NE(0u, input_count);
  DCHECK_GE(arraysize(inputs), input_count);
  InstructionCode code = selector->IsSupported(AVX) ? avx_opcode : sse_opcode;
  outputs[output_count++] = selector->IsSupported(AVX)
                                ? g.DefineAsRegister(node)
                                : g.DefineSameAsFirst(node);
  DCHECK_EQ(1u, output_count);
  DCHECK_GE(arraysize(outputs), output_count);
  Instruction* instr =
      selector->Emit(code, output_count, outputs, input_count, inputs);
  if (selector->valid(trapping_load)) {
    selector->UpdateSourcePosition(instr, trapping_load);
  }
}

template <typename Adapter>
void VisitFloatUnop(InstructionSelectorT<Adapter>* selector,
                    typename Adapter::node_t node,
                    typename Adapter::node_t input, InstructionCode opcode) {
  X64OperandGeneratorT<Adapter> g(selector);
  if (selector->IsSupported(AVX)) {
    selector->Emit(opcode, g.DefineAsRegister(node), g.UseRegister(input));
  } else {
    selector->Emit(opcode, g.DefineSameAsFirst(node), g.UseRegister(input));
  }
}

}  // namespace

#define RO_OP_T_LIST(V)                                                \
  V(Word64Clz, kX64Lzcnt)                                              \
  V(Word32Clz, kX64Lzcnt32)                                            \
  V(Word64Ctz, kX64Tzcnt)                                              \
  V(Word32Ctz, kX64Tzcnt32)                                            \
  V(Word64Popcnt, kX64Popcnt)                                          \
  V(Word32Popcnt, kX64Popcnt32)                                        \
  V(Float64Sqrt, kSSEFloat64Sqrt)                                      \
  V(Float32Sqrt, kSSEFloat32Sqrt)                                      \
  V(RoundFloat64ToInt32, kSSEFloat64ToInt32)                           \
  V(ChangeInt32ToFloat64, kSSEInt32ToFloat64)                          \
  V(TruncateFloat64ToFloat32, kSSEFloat64ToFloat32)                    \
  V(ChangeFloat32ToFloat64, kSSEFloat32ToFloat64)                      \
  V(ChangeFloat64ToInt32, kSSEFloat64ToInt32)                          \
  V(ChangeFloat64ToUint32, kSSEFloat64ToUint32 | MiscField::encode(1)) \
  V(ChangeFloat64ToInt64, kSSEFloat64ToInt64)                          \
  V(ChangeFloat64ToUint64, kSSEFloat64ToUint64)                        \
  V(RoundInt32ToFloat32, kSSEInt32ToFloat32)                           \
  V(RoundInt64ToFloat32, kSSEInt64ToFloat32)                           \
  V(RoundUint64ToFloat32, kSSEUint64ToFloat32)                         \
  V(RoundInt64ToFloat64, kSSEInt64ToFloat64)                           \
  V(RoundUint64ToFloat64, kSSEUint64ToFloat64)                         \
  V(RoundUint32ToFloat32, kSSEUint32ToFloat32)                         \
  V(ChangeInt64ToFloat64, kSSEInt64ToFloat64)                          \
  V(ChangeUint32ToFloat64, kSSEUint32ToFloat64)                        \
  V(Float64ExtractLowWord32, kSSEFloat64ExtractLowWord32)              \
  V(Float64ExtractHighWord32, kSSEFloat64ExtractHighWord32)            \
  V(BitcastFloat32ToInt32, kX64BitcastFI)                              \
  V(BitcastFloat64ToInt64, kX64BitcastDL)                              \
  V(BitcastInt32ToFloat32, kX64BitcastIF)                              \
  V(BitcastInt64ToFloat64, kX64BitcastLD)                              \
  V(SignExtendWord8ToInt32, kX64Movsxbl)                               \
  V(SignExtendWord16ToInt32, kX64Movsxwl)                              \
  V(SignExtendWord8ToInt64, kX64Movsxbq)                               \
  V(SignExtendWord16ToInt64, kX64Movsxwq)                              \
  V(TruncateFloat64ToInt64, kSSEFloat64ToInt64)                        \
  V(TruncateFloat32ToInt32, kSSEFloat32ToInt32)                        \
  V(TruncateFloat32ToUint32, kSSEFloat32ToUint32)

#ifdef V8_ENABLE_WEBASSEMBLY
#define RR_OP_T_LIST_WEBASSEMBLY(V)                                       \
  V(F16x8Ceil, kX64F16x8Round | MiscField::encode(kRoundUp))              \
  V(F16x8Floor, kX64F16x8Round | MiscField::encode(kRoundDown))           \
  V(F16x8Trunc, kX64F16x8Round | MiscField::encode(kRoundToZero))         \
  V(F16x8NearestInt, kX64F16x8Round | MiscField::encode(kRoundToNearest)) \
  V(F32x4Ceil, kX64F32x4Round | MiscField::encode(kRoundUp))              \
  V(F32x4Floor, kX64F32x4Round | MiscField::encode(kRoundDown))           \
  V(F32x4Trunc, kX64F32x4Round | MiscField::encode(kRoundToZero))         \
  V(F32x4NearestInt, kX64F32x4Round | MiscField::encode(kRoundToNearest)) \
  V(F64x2Ceil, kX64F64x2Round | MiscField::encode(kRoundUp))              \
  V(F64x2Floor, kX64F64x2Round | MiscField::encode(kRoundDown))           \
  V(F64x2Trunc, kX64F64x2Round | MiscField::encode(kRoundToZero))         \
  V(F64x2NearestInt, kX64F64x2Round | MiscField::encode(kRoundToNearest))
#else
#define RR_OP_T_LIST_WEBASSEMBLY(V)
#endif  // V8_ENABLE_WEBASSEMBLY

#define RR_OP_T_LIST(V)                                                       \
  V(TruncateFloat64ToUint32, kSSEFloat64ToUint32 | MiscField::encode(0))      \
  V(SignExtendWord32ToInt64, kX64Movsxlq)                                     \
  V(Float32RoundDown, kSSEFloat32Round | MiscField::encode(kRoundDown))       \
  V(Float64RoundDown, kSSEFloat64Round | MiscField::encode(kRoundDown))       \
  V(Float32RoundUp, kSSEFloat32Round | MiscField::encode(kRoundUp))           \
  V(Float64RoundUp, kSSEFloat64Round | MiscField::encode(kRoundUp))           \
  V(Float32RoundTruncate, kSSEFloat32Round | MiscField::encode(kRoundToZero)) \
  V(Float64RoundTruncate, kSSEFloat64Round | MiscField::encode(kRoundToZero)) \
  V(Float32RoundTiesEven,                                                     \
    kSSEFloat32Round | MiscField::encode(kRoundToNearest))                    \
  V(Float64RoundTiesEven,                                                     \
    kSSEFloat64Round | MiscField::encode(kRoundToNearest))                    \
  RR_OP_T_LIST_WEBASSEMBLY(V)

#define RO_VISITOR(Name, opcode)                                 \
  template <typename Adapter>                                    \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) { \
    VisitRO(this, node, opcode);                                 \
  }
RO_OP_T_LIST(RO_VISITOR)
#undef RO_VIISTOR
#undef RO_OP_T_LIST

#define RR_VISITOR(Name, opcode)                                 \
  template <typename Adapter>                                    \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) { \
    VisitRR(this, node, opcode);                                 \
  }
RR_OP_T_LIST(RR_VISITOR)
#undef RR_VISITOR
#undef RR_OP_T_LIST

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTruncateFloat64ToWord32(node_t node) {
  VisitRR(this, node, kArchTruncateDoubleToI);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTruncateFloat64ToFloat16RawBits(
    node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  InstructionOperand temps[] = {g.TempDoubleRegister(), g.TempRegister()};
  Emit(kSSEFloat64ToFloat16RawBits, g.DefineAsRegister(node),
       g.UseUniqueRegister(this->input_at(node, 0)), arraysize(temps), temps);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTruncateInt64ToInt32(node_t node) {
  // We rely on the fact that TruncateInt64ToInt32 zero extends the
  // value (see ZeroExtendsWord32ToWord64). So all code paths here
  // have to satisfy that condition.
  X64OperandGeneratorT<Adapter> g(this);

  node_t value = this->input_at(node, 0);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    bool can_cover = false;
    if (const TaggedBitcastOp* value_op =
            this->Get(value)
                .template TryCast<
                    Opmask::kBitcastTaggedToWordPtrForTagAndSmiBits>()) {
      can_cover = CanCover(node, value) && CanCover(node, value_op->input());
      value = value_op->input();
    } else {
      can_cover = CanCover(node, value);
    }
    if (can_cover) {
      const Operation& value_op = this->Get(value);
      if (const ShiftOp * shift;
          (shift = value_op.TryCast<Opmask::kWord64ShiftRightArithmetic>()) ||
          (shift = value_op.TryCast<Opmask::kWord64ShiftRightLogical>())) {
        if (this->MatchIntegralWord32Constant(shift->right(), 32)) {
          if (CanCover(value, shift->left()) &&
              TryEmitLoadForLoadWord64AndShiftRight(this, value, kX64Movl)) {
            // We just defined and emitted a 32-bit Load for {value} (the upper
            // 32 bits only since it was getting shifted by 32 bits to the right
            // afterwards); we now define {node} as a rename of {value} without
            // needing to do a truncation.
            return EmitIdentity(node);
          }
          Emit(kX64Shr, g.DefineSameAsFirst(node), g.UseRegister(shift->left()),
               g.TempImmediate(32));
          return;
        }
      }
    }
  } else {
    bool can_cover = false;
    if (value->opcode() == IrOpcode::kBitcastTaggedToWordForTagAndSmiBits) {
      can_cover = CanCover(node, value) && CanCover(value, value->InputAt(0));
      value = value->InputAt(0);
    } else {
      can_cover = CanCover(node, value);
    }
    if (can_cover) {
      switch (value->opcode()) {
        case IrOpcode::kWord64Sar:
        case IrOpcode::kWord64Shr: {
          Int64BinopMatcher m(value);
          if (m.right().Is(32)) {
            if (CanCover(value, value->InputAt(0)) &&
                TryEmitLoadForLoadWord64AndShiftRight(this, value, kX64Movl)) {
              return EmitIdentity(node);
            }
            Emit(kX64Shr, g.DefineSameAsFirst(node),
                 g.UseRegister(m.left().node()), g.TempImmediate(32));
            return;
          }
          break;
        }
        case IrOpcode::kLoad:
        case IrOpcode::kLoadImmutable: {
          // Note: in Turboshaft, we shouldn't reach this point, because we'd
          // have a BitcastTaggedToWord32 instead of a TruncateInt64ToInt32.
          TryMergeTruncateInt64ToInt32IntoLoad(this, node, value);
          return;
        }
        default:
          break;
      }
    }
  }
  Emit(kX64Movl, g.DefineAsRegister(node), g.Use(value));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Add(node_t node) {
  VisitFloatBinop(this, node, kAVXFloat32Add, kSSEFloat32Add);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Sub(node_t node) {
  VisitFloatBinop(this, node, kAVXFloat32Sub, kSSEFloat32Sub);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Mul(node_t node) {
  VisitFloatBinop(this, node, kAVXFloat32Mul, kSSEFloat32Mul);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Div(node_t node) {
  VisitFloatBinop(this, node, kAVXFloat32Div, kSSEFloat32Div);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Abs(node_t node) {
  DCHECK_EQ(this->value_input_count(node), 1);
  VisitFloatUnop(this, node, this->input_at(node, 0), kX64Float32Abs);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Max(node_t node) {
  VisitRRO(this, node, kSSEFloat32Max);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Min(node_t node) {
  VisitRRO(this, node, kSSEFloat32Min);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Add(node_t node) {
  VisitFloatBinop(this, node, kAVXFloat64Add, kSSEFloat64Add);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Sub(node_t node) {
  VisitFloatBinop(this, node, kAVXFloat64Sub, kSSEFloat64Sub);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Mul(node_t node) {
  VisitFloatBinop(this, node, kAVXFloat64Mul, kSSEFloat64Mul);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Div(node_t node) {
  VisitFloatBinop(this, node, kAVXFloat64Div, kSSEFloat64Div);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Mod(node_t node) {
  DCHECK_EQ(this->value_input_count(node), 2);
  X64OperandGeneratorT<Adapter> g(this);
  InstructionOperand temps[] = {g.TempRegister(rax)};
  Emit(kSSEFloat64Mod, g.DefineSameAsFirst(node),
       g.UseRegister(this->input_at(node, 0)),
       g.UseRegister(this->input_at(node, 1)), 1, temps);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Max(node_t node) {
  VisitRRO(this, node, kSSEFloat64Max);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Min(node_t node) {
  VisitRRO(this, node, kSSEFloat64Min);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Abs(node_t node) {
  DCHECK_EQ(this->value_input_count(node), 1);
  VisitFloatUnop(this, node, this->input_at(node, 0), kX64Float64Abs);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64RoundTiesAway(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Neg(node_t node) {
  DCHECK_EQ(this->value_input_count(node), 1);
  VisitFloatUnop(this, node, this->input_at(node, 0), kX64Float32Neg);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Neg(node_t node) {
  DCHECK_EQ(this->value_input_count(node), 1);
  VisitFloatUnop(this, node, this->input_at(node, 0), kX64Float64Neg);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Ieee754Binop(
    node_t node, InstructionCode opcode) {
  DCHECK_EQ(this->value_input_count(node), 2);
  X64OperandGeneratorT<Adapter> g(this);
  Emit(opcode, g.DefineAsFixed(node, xmm0),
       g.UseFixed(this->input_at(node, 0), xmm0),
       g.UseFixed(this->input_at(node, 1), xmm1))
      ->MarkAsCall();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Ieee754Unop(
    node_t node, InstructionCode opcode) {
  X64OperandGeneratorT<Adapter> g(this);
  DCHECK_EQ(this->value_input_count(node), 1);
  Emit(opcode, g.DefineAsFixed(node, xmm0),
       g.UseFixed(this->input_at(node, 0), xmm0))
      ->MarkAsCall();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::EmitMoveParamToFPR(node_t node, int index) {
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::EmitMoveFPRToParam(
    InstructionOperand* op, LinkageLocation location) {}

template <typename Adapter>
void InstructionSelectorT<Adapter>::EmitPrepareArguments(
    ZoneVector<PushParameter>* arguments, const CallDescriptor* call_descriptor,
    node_t node) {
  X64OperandGeneratorT<Adapter> g(this);

  // Prepare for C function call.
  if (call_descriptor->IsCFunctionCall()) {
    Emit(kArchPrepareCallCFunction | MiscField::encode(static_cast<int>(
                                         call_descriptor->ParameterCount())),
         0, nullptr, 0, nullptr);

    // Poke any stack arguments.
    for (size_t n = 0; n < arguments->size(); ++n) {
      PushParameter input = (*arguments)[n];
      if (this->valid(input.node)) {
        int slot = static_cast<int>(n);
        InstructionOperand value = g.CanBeImmediate(input.node)
                                       ? g.UseImmediate(input.node)
                                       : g.UseRegister(input.node);
        Emit(kX64Poke | MiscField::encode(slot), g.NoOutput(), value);
      }
    }
  } else {
    // Push any stack arguments.
    int effect_level = GetEffectLevel(node);
    int stack_decrement = 0;
    for (PushParameter input : base::Reversed(*arguments)) {
      stack_decrement += kSystemPointerSize;
      // Skip holes in the param array. These represent both extra slots for
      // multi-slot values and padding slots for alignment.
      if (!this->valid(input.node)) continue;
      InstructionOperand decrement = g.UseImmediate(stack_decrement);
      stack_decrement = 0;
      if (g.CanBeImmediate(input.node)) {
        Emit(kX64Push, g.NoOutput(), decrement, g.UseImmediate(input.node));
      } else if (IsSupported(INTEL_ATOM) ||
                 sequence()->IsFP(GetVirtualRegister(input.node))) {
        // TODO(titzer): X64Push cannot handle stack->stack double moves
        // because there is no way to encode fixed double slots.
        Emit(kX64Push, g.NoOutput(), decrement, g.UseRegister(input.node));
      } else if (g.CanBeMemoryOperand(kX64Push, node, input.node,
                                      effect_level)) {
        InstructionOperand outputs[1];
        InstructionOperand inputs[5];
        size_t input_count = 0;
        inputs[input_count++] = decrement;
        AddressingMode mode = g.GetEffectiveAddressMemoryOperand(
            input.node, inputs, &input_count);
        InstructionCode opcode = kX64Push | AddressingModeField::encode(mode);
        Emit(opcode, 0, outputs, input_count, inputs);
      } else {
        Emit(kX64Push, g.NoOutput(), decrement, g.UseAny(input.node));
      }
    }
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::EmitPrepareResults(
    ZoneVector<PushParameter>* results, const CallDescriptor* call_descriptor,
    node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
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
      InstructionOperand result = g.DefineAsRegister(output.node);
      int offset = call_descriptor->GetOffsetToReturns();
      int reverse_slot = -output.location.GetLocation() - offset;
      InstructionOperand slot = g.UseImmediate(reverse_slot);
      Emit(kX64Peek, 1, &result, 1, &slot);
    }
  }
}

template <typename Adapter>
bool InstructionSelectorT<Adapter>::IsTailCallAddressImmediate() {
  return true;
}

namespace {

template <typename Adapter>
void VisitCompareWithMemoryOperand(InstructionSelectorT<Adapter>* selector,
                                   InstructionCode opcode,
                                   typename Adapter::node_t left,
                                   InstructionOperand right,
                                   FlagsContinuationT<Adapter>* cont) {
  DCHECK(selector->IsLoadOrLoadImmutable(left));
  X64OperandGeneratorT<Adapter> g(selector);
  size_t input_count = 0;
  InstructionOperand inputs[6];
  AddressingMode addressing_mode =
      g.GetEffectiveAddressMemoryOperand(left, inputs, &input_count);
  opcode |= AddressingModeField::encode(addressing_mode);
  inputs[input_count++] = right;
  if (cont->IsSelect()) {
    if (opcode == kUnorderedEqual) {
      cont->Negate();
      inputs[input_count++] = g.UseRegister(cont->true_value());
      inputs[input_count++] = g.Use(cont->false_value());
    } else {
      inputs[input_count++] = g.UseRegister(cont->false_value());
      inputs[input_count++] = g.Use(cont->true_value());
    }
  }

  selector->EmitWithContinuation(opcode, 0, nullptr, input_count, inputs, cont);
}

// Shared routine for multiple compare operations.
template <typename Adapter>
void VisitCompare(InstructionSelectorT<Adapter>* selector,
                  InstructionCode opcode, InstructionOperand left,
                  InstructionOperand right, FlagsContinuationT<Adapter>* cont) {
  if (cont->IsSelect()) {
    X64OperandGeneratorT<Adapter> g(selector);
    InstructionOperand inputs[4] = {left, right};
    if (cont->condition() == kUnorderedEqual) {
      cont->Negate();
      inputs[2] = g.UseRegister(cont->true_value());
      inputs[3] = g.Use(cont->false_value());
    } else {
      inputs[2] = g.UseRegister(cont->false_value());
      inputs[3] = g.Use(cont->true_value());
    }
    selector->EmitWithContinuation(opcode, 0, nullptr, 4, inputs, cont);
    return;
  }
  selector->EmitWithContinuation(opcode, left, right, cont);
}

// Shared routine for multiple compare operations.
template <typename Adapter>
void VisitCompare(InstructionSelectorT<Adapter>* selector,
                  InstructionCode opcode, typename Adapter::node_t left,
                  typename Adapter::node_t right,
                  FlagsContinuationT<Adapter>* cont, bool commutative) {
  X64OperandGeneratorT<Adapter> g(selector);
  if (commutative && g.CanBeBetterLeftOperand(right)) {
    std::swap(left, right);
  }
  VisitCompare(selector, opcode, g.UseRegister(left), g.Use(right), cont);
}

template <typename Adapter>
MachineType MachineTypeForNarrow(InstructionSelectorT<Adapter>* selector,
                                 typename Adapter::node_t node,
                                 typename Adapter::node_t hint_node) {
  if (selector->IsLoadOrLoadImmutable(hint_node)) {
    MachineType hint = selector->load_view(hint_node).loaded_rep();
    if (selector->is_integer_constant(node)) {
      int64_t constant = selector->integer_constant(node);
      if (hint == MachineType::Int8()) {
        if (constant >= std::numeric_limits<int8_t>::min() &&
            constant <= std::numeric_limits<int8_t>::max()) {
          return hint;
        }
      } else if (hint == MachineType::Uint8()) {
        if (constant >= std::numeric_limits<uint8_t>::min() &&
            constant <= std::numeric_limits<uint8_t>::max()) {
          return hint;
        }
      } else if (hint == MachineType::Int16()) {
        if (constant >= std::numeric_limits<int16_t>::min() &&
            constant <= std::numeric_limits<int16_t>::max()) {
          return hint;
        }
      } else if (hint == MachineType::Uint16()) {
        if (constant >= std::numeric_limits<uint16_t>::min() &&
            constant <= std::numeric_limits<uint16_t>::max()) {
          return hint;
        }
      } else if (hint == MachineType::Int32()) {
        if (constant >= std::numeric_limits<int32_t>::min() &&
            constant <= std::numeric_limits<int32_t>::max()) {
          return hint;
        }
      } else if (hint == MachineType::Uint32()) {
        if (constant >= std::numeric_limits<uint32_t>::min() &&
            constant <= std::numeric_limits<uint32_t>::max())
          return hint;
      }
    }
  }
  if (selector->IsLoadOrLoadImmutable(node)) {
    return selector->load_view(node).loaded_rep();
  }
  return MachineType::None();
}

bool IsIntConstant(InstructionSelectorT<TurbofanAdapter>*, Node* node) {
  return node->opcode() == IrOpcode::kInt32Constant ||
         node->opcode() == IrOpcode::kInt64Constant;
}
bool IsIntConstant(InstructionSelectorT<TurboshaftAdapter>* selector,
                   turboshaft::OpIndex node) {
  if (auto constant = selector->Get(node).TryCast<turboshaft::ConstantOp>()) {
    return constant->kind == turboshaft::ConstantOp::Kind::kWord32 ||
           constant->kind == turboshaft::ConstantOp::Kind::kWord64;
  }
  return false;
}
bool IsWordAnd(InstructionSelectorT<TurbofanAdapter>*, Node* node) {
  return node->opcode() == IrOpcode::kWord32And ||
         node->opcode() == IrOpcode::kWord64And;
}
bool IsWordAnd(InstructionSelectorT<TurboshaftAdapter>* selector,
               turboshaft::OpIndex node) {
  if (auto binop = selector->Get(node).TryCast<turboshaft::WordBinopOp>()) {
    return binop->kind == turboshaft::WordBinopOp::Kind::kBitwiseAnd;
  }
  return false;
}

// The result of WordAnd with a positive interger constant in X64 is known to
// be sign(zero)-extended. Comparing this result with another positive interger
// constant can have narrowed operand.
template <typename Adapter>
MachineType MachineTypeForNarrowWordAnd(
    InstructionSelectorT<Adapter>* selector, typename Adapter::node_t and_node,
    typename Adapter::node_t constant_node) {
  DCHECK_EQ(selector->value_input_count(and_node), 2);
  auto and_left = selector->input_at(and_node, 0);
  auto and_right = selector->input_at(and_node, 1);
  auto and_constant_node = IsIntConstant(selector, and_right) ? and_right
                           : IsIntConstant(selector, and_left)
                               ? and_left
                               : typename Adapter::node_t{};

  if (Adapter::valid(and_constant_node)) {
    int64_t and_constant = selector->integer_constant(and_constant_node);
    int64_t cmp_constant = selector->integer_constant(constant_node);
    if (and_constant >= 0 && cmp_constant >= 0) {
      int64_t constant =
          and_constant > cmp_constant ? and_constant : cmp_constant;
      if (constant <= std::numeric_limits<int8_t>::max()) {
        return MachineType::Int8();
      } else if (constant <= std::numeric_limits<uint8_t>::max()) {
        return MachineType::Uint8();
      } else if (constant <= std::numeric_limits<int16_t>::max()) {
        return MachineType::Int16();
      } else if (constant <= std::numeric_limits<uint16_t>::max()) {
        return MachineType::Uint16();
      } else if (constant <= std::numeric_limits<int32_t>::max()) {
        return MachineType::Int32();
      } else if (constant <= std::numeric_limits<uint32_t>::max()) {
        return MachineType::Uint32();
      }
    }
  }

  return MachineType::None();
}

// Tries to match the size of the given opcode to that of the operands, if
// possible.
template <typename Adapter>
InstructionCode TryNarrowOpcodeSize(InstructionSelectorT<Adapter>* selector,
                                    InstructionCode opcode,
                                    typename Adapter::node_t left,
                                    typename Adapter::node_t right,
                                    FlagsContinuationT<Adapter>* cont) {
  MachineType left_type = MachineType::None();
  MachineType right_type = MachineType::None();
  if (IsWordAnd(selector, left) && IsIntConstant(selector, right)) {
    left_type = MachineTypeForNarrowWordAnd(selector, left, right);
    right_type = left_type;
  } else if (IsWordAnd(selector, right) && IsIntConstant(selector, left)) {
    right_type = MachineTypeForNarrowWordAnd(selector, right, left);
    left_type = right_type;
  } else {
    // TODO(epertoso): we can probably get some size information out phi nodes.
    // If the load repres
```