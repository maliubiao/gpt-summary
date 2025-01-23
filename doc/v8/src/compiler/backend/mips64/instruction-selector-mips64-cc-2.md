Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of the V8 JavaScript engine, specifically for the MIPS64 architecture.

Here's a breakdown of how to approach this:

1. **Identify the file's role:** The filename `instruction-selector-mips64.cc` strongly suggests its purpose: selecting the appropriate machine instructions for the MIPS64 architecture based on higher-level operations.

2. **Analyze the code structure:** The code is a C++ template class `InstructionSelectorT`. This suggests it's a core component of the instruction selection process, likely handling various types of operations. The presence of `Visit...` methods indicates that it's using a visitor pattern to handle different instruction types.

3. **Examine the `Visit...` methods:**  Each `Visit...` method corresponds to a specific operation (e.g., `VisitChangeFloat64ToInt32`, `VisitFloat32Add`). By looking at the operations being visited, we can understand the range of functionalities covered by this file. These methods generally translate high-level operations into specific MIPS64 assembly instructions (e.g., `kMips64TruncWD`, `kMips64AddS`).

4. **Look for architectural specifics:** The code uses constants like `kMips64TruncWD` and interacts with MIPS64 specific registers (e.g., `f0`, `f12`). This confirms its role in generating MIPS64 code.

5. **Check for Torque mentions:** The initial prompt asks about `.tq` files. This code is `.cc`, so it's standard C++.

6. **Relate to JavaScript:**  JavaScript engines execute JavaScript code. This file is involved in the *compilation* process, taking higher-level representations of JavaScript operations and translating them into machine code that the processor can understand. We can illustrate this with examples of JavaScript operations that would trigger some of the `Visit...` methods.

7. **Identify code logic and potential errors:** Some `Visit...` methods have conditional logic or handle specific cases (e.g., optimizations for certain sequences of operations). We can provide hypothetical inputs and outputs to demonstrate this logic. We can also consider common programming errors that might lead to these specific code paths being executed.

8. **Consider the "part 3 of 6" information:** This suggests that this file is part of a larger instruction selection process. The functionality described here is likely focused on a specific subset of operations.

**Plan for the response:**

*   State the main function of the file: instruction selection for MIPS64.
*   Explain the visitor pattern and how `Visit...` methods work.
*   List the categories of operations handled (data type conversions, arithmetic, etc.).
*   Provide JavaScript examples for some of the handled operations.
*   Give a code logic example with input and output for a specific `Visit...` method.
*   Give a common programming error example that could lead to the execution of code within this file.
*   Summarize the overall function of this specific part of the instruction selection process.
这是 V8 JavaScript 引擎中用于 MIPS64 架构的指令选择器（Instruction Selector）的源代码文件。它的主要功能是将**与架构无关的中间表示（Intermediate Representation - IR）**的操作转换成**特定的 MIPS64 汇编指令**。

以下是更详细的功能分解：

1. **遍历 IR 图 (Instruction Graph):**  指令选择器接收 V8 编译器生成的 IR 图作为输入，这个图表示了需要执行的操作以及它们之间的数据依赖关系。

2. **模式匹配 (Pattern Matching):**  针对 IR 图中的每个节点（代表一个操作），指令选择器会尝试匹配特定的模式。这些模式对应于 MIPS64 架构上可用的指令。

3. **指令生成 (Instruction Emission):**  当找到匹配的模式时，指令选择器会生成相应的 MIPS64 汇编指令。这些指令被添加到最终要生成的机器代码序列中。

4. **处理不同类型的操作:**  代码中的 `Visit...` 方法对应于不同类型的 IR 节点（操作）。例如：
    *   `VisitTruncateFloat32ToInt32`: 处理将 32 位浮点数截断为 32 位整数的操作。
    *   `VisitChangeFloat64ToInt32`: 处理将 64 位浮点数转换为 32 位整数的操作。
    *   `VisitFloat32Add`: 处理 32 位浮点数加法操作。
    *   `VisitBitcastInt32ToFloat32`: 处理将 32 位整数重新解释为 32 位浮点数的操作。
    *   `VisitLoad`: 处理从内存中加载数据的操作。
    *   `VisitStore`: 处理将数据存储到内存的操作。

5. **处理数据类型转换:**  代码中包含了大量处理不同数据类型之间转换的 `Visit...` 方法，例如浮点数到整数、整数到浮点数、不同大小的整数之间的转换等。

6. **处理算术和逻辑运算:** 代码中也包含了处理各种算术和逻辑运算的 `Visit...` 方法，例如加法、减法、乘法、除法、取模、位运算等。

7. **优化 (Optimizations):**  在某些 `Visit...` 方法中，可以看到针对特定操作序列的优化。例如，`VisitChangeFloat64ToInt32` 方法会尝试匹配 `ChangeFloat64ToInt32(Float64Round##OP)` 这样的模式，以便直接使用带有舍入功能的 MIPS64 指令。

8. **处理函数调用 (Function Calls):**  `EmitPrepareArguments` 和 `EmitPrepareResults` 等方法用于处理函数调用时的参数准备和结果处理。

9. **处理非对齐访问 (Unaligned Access):** `VisitUnalignedLoad` 和 `VisitUnalignedStore` 方法处理对内存进行非对齐访问的情况。

**关于代码特性：**

*   **不是 Torque 代码:** 文件以 `.cc` 结尾，表明它是标准的 C++ 源代码，而不是 V8 的 Torque 语言。
*   **与 JavaScript 功能相关:**  指令选择器的最终目标是将 JavaScript 代码翻译成机器码来执行。因此，这里列举的每一种操作都直接或间接地与 JavaScript 的功能相关。

**JavaScript 举例说明:**

```javascript
let floatValue = 3.14;
let intValue = Math.trunc(floatValue); // 对应 VisitTruncateFloat64ToInt32 或 VisitTruncateFloat32ToInt32

let a = 1.5;
let b = 2.5;
let sum = a + b; // 对应 VisitFloat64Add 或 VisitFloat32Add

let num1 = 10;
let floatFromInt = Number(num1); // 可能不直接对应这里的某个 Visit，但涉及到类型转换

let buffer = new ArrayBuffer(4);
let view = new DataView(buffer);
view.setInt32(0, 0x12345678);
let floatFromBuffer = view.getFloat32(0); // 间接涉及到内存访问和类型转换，可能涉及到 VisitLoad 和 VisitBitcastInt32ToFloat32
```

**代码逻辑推理 - 假设输入与输出 (以 `VisitTruncateFloat32ToInt32` 为例):**

**假设输入:** 一个表示将 32 位浮点数截断为 32 位整数的 IR 节点 `node`，其输入是一个表示 32 位浮点数值的节点。

**输出:**  会调用 `Emit(kMips64TruncWS, g.DefineAsRegister(node), g.UseRegister(this->input_at(node, 0)));` 生成一个 MIPS64 的 `trunc.w.s` 指令。这个指令会将输入的浮点数寄存器中的值截断为整数并存储到目标寄存器中。

**用户常见的编程错误举例:**

```javascript
let veryLargeFloat = 9007199254740992.0; // 大于 32 位整数能精确表示的范围
let truncatedInt = Math.trunc(veryLargeFloat); // 可能会丢失精度，导致非预期的整数值

console.log(truncatedInt); // 输出可能不是期望的精确整数值
```

当 JavaScript 代码中进行可能导致数据溢出或精度丢失的类型转换时，指令选择器会生成相应的指令来执行这些转换。例如，将一个超出 32 位整数范围的浮点数截断为整数，就会触发 `VisitTruncateFloat64ToInt32` 或 `VisitTruncateFloat32ToInt32`，但最终生成的机器码会按照截断的规则执行，可能导致用户得到非预期的结果。

**功能归纳 (第 3 部分):**

作为指令选择过程的第三部分，这个代码片段专注于**处理各种数据类型转换操作 (尤其是浮点数和整数之间的转换) 以及一些基本的算术和逻辑运算**，并将其转换为 MIPS64 架构特定的机器指令。它还涉及到一些针对特定操作组合的优化。这部分的功能是确保 V8 能够有效地将 JavaScript 中涉及数值类型转换和基本运算的部分翻译成能在 MIPS64 架构上执行的机器码。

### 提示词
```
这是目录为v8/src/compiler/backend/mips64/instruction-selector-mips64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/mips64/instruction-selector-mips64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
erflowToMin>()) {
      opcode |= MiscField::encode(true);
    }

    Emit(opcode, g.DefineAsRegister(node),
         g.UseRegister(this->input_at(node, 0)));
  } else {
    InstructionCode opcode = kMips64TruncUwS;
    TruncateKind kind = OpParameter<TruncateKind>(node->op());
    if (kind == TruncateKind::kSetOverflowToMin) {
      opcode |= MiscField::encode(true);
    }
    Emit(opcode, g.DefineAsRegister(node), g.UseRegister(node->InputAt(0)));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitChangeFloat64ToInt32(node_t node) {
  Mips64OperandGeneratorT<Adapter> g(this);

  if constexpr (Adapter::IsTurboshaft) {
    // TODO(mips64): Check if could be optimized like turbofan here.
  } else {
    Node* value = node->InputAt(0);
    // Match ChangeFloat64ToInt32(Float64Round##OP) to corresponding instruction
    // which does rounding and conversion to integer format.
    if (CanCover(node, value)) {
      switch (value->opcode()) {
        case IrOpcode::kFloat64RoundDown:
          Emit(kMips64FloorWD, g.DefineAsRegister(node),
               g.UseRegister(value->InputAt(0)));
          return;
        case IrOpcode::kFloat64RoundUp:
          Emit(kMips64CeilWD, g.DefineAsRegister(node),
               g.UseRegister(value->InputAt(0)));
          return;
        case IrOpcode::kFloat64RoundTiesEven:
          Emit(kMips64RoundWD, g.DefineAsRegister(node),
               g.UseRegister(value->InputAt(0)));
          return;
        case IrOpcode::kFloat64RoundTruncate:
          Emit(kMips64TruncWD, g.DefineAsRegister(node),
               g.UseRegister(value->InputAt(0)));
          return;
        default:
          break;
      }
      if (value->opcode() == IrOpcode::kChangeFloat32ToFloat64) {
        Node* next = value->InputAt(0);
        if (CanCover(value, next)) {
          // Match
          // ChangeFloat64ToInt32(ChangeFloat32ToFloat64(Float64Round##OP))
          switch (next->opcode()) {
            case IrOpcode::kFloat32RoundDown:
              Emit(kMips64FloorWS, g.DefineAsRegister(node),
                   g.UseRegister(next->InputAt(0)));
              return;
            case IrOpcode::kFloat32RoundUp:
              Emit(kMips64CeilWS, g.DefineAsRegister(node),
                   g.UseRegister(next->InputAt(0)));
              return;
            case IrOpcode::kFloat32RoundTiesEven:
              Emit(kMips64RoundWS, g.DefineAsRegister(node),
                   g.UseRegister(next->InputAt(0)));
              return;
            case IrOpcode::kFloat32RoundTruncate:
              Emit(kMips64TruncWS, g.DefineAsRegister(node),
                   g.UseRegister(next->InputAt(0)));
              return;
            default:
              Emit(kMips64TruncWS, g.DefineAsRegister(node),
                   g.UseRegister(value->InputAt(0)));
              return;
          }
        } else {
          // Match float32 -> float64 -> int32 representation change path.
          Emit(kMips64TruncWS, g.DefineAsRegister(node),
               g.UseRegister(value->InputAt(0)));
          return;
        }
      }
    }
  }

  VisitRR(this, kMips64TruncWD, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitChangeFloat64ToInt64(node_t node) {
  VisitRR(this, kMips64TruncLD, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitChangeFloat64ToUint32(node_t node) {
  VisitRR(this, kMips64TruncUwD, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitChangeFloat64ToUint64(node_t node) {
  VisitRR(this, kMips64TruncUlD, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTruncateFloat64ToUint32(node_t node) {
  VisitRR(this, kMips64TruncUwD, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTruncateFloat64ToInt64(node_t node) {
  Mips64OperandGeneratorT<Adapter> g(this);

  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    InstructionCode opcode = kMips64TruncLD;
    const Operation& op = this->Get(node);
    if (op.Is<Opmask::kTruncateFloat64ToInt64OverflowToMin>()) {
      opcode |= MiscField::encode(true);
    }

    Emit(opcode, g.DefineAsRegister(node), g.UseRegister(op.input(0)));
  } else {
    InstructionCode opcode = kMips64TruncLD;
    TruncateKind kind = OpParameter<TruncateKind>(node->op());
    if (kind == TruncateKind::kSetOverflowToMin) {
      opcode |= MiscField::encode(true);
    }
    Emit(opcode, g.DefineAsRegister(node), g.UseRegister(node->InputAt(0)));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTruncateFloat64ToFloat16RawBits(
    node_t node) {
  UNIMPLEMENTED();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTryTruncateFloat32ToInt64(
    node_t node) {
  Mips64OperandGeneratorT<Adapter> g(this);

  InstructionOperand inputs[] = {g.UseRegister(this->input_at(node, 0))};
  InstructionOperand outputs[2];
  size_t output_count = 0;
  outputs[output_count++] = g.DefineAsRegister(node);

  node_t success_output = FindProjection(node, 1);
  if (this->valid(success_output)) {
    outputs[output_count++] = g.DefineAsRegister(success_output);
  }

  Emit(kMips64TruncLS, output_count, outputs, 1, inputs);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTryTruncateFloat64ToInt64(
    node_t node) {
  Mips64OperandGeneratorT<Adapter> g(this);

  InstructionOperand inputs[] = {g.UseRegister(this->input_at(node, 0))};
  InstructionOperand outputs[2];
  size_t output_count = 0;
  outputs[output_count++] = g.DefineAsRegister(node);

  node_t success_output = FindProjection(node, 1);
  if (this->valid(success_output)) {
    outputs[output_count++] = g.DefineAsRegister(success_output);
  }

  Emit(kMips64TruncLD, output_count, outputs, 1, inputs);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTryTruncateFloat32ToUint64(
    node_t node) {
  Mips64OperandGeneratorT<Adapter> g(this);

  InstructionOperand inputs[] = {g.UseRegister(this->input_at(node, 0))};
  InstructionOperand outputs[2];
  size_t output_count = 0;
  outputs[output_count++] = g.DefineAsRegister(node);

  node_t success_output = FindProjection(node, 1);
  if (this->valid(success_output)) {
    outputs[output_count++] = g.DefineAsRegister(success_output);
  }

  Emit(kMips64TruncUlS, output_count, outputs, 1, inputs);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTryTruncateFloat64ToUint64(
    node_t node) {
  Mips64OperandGeneratorT<Adapter> g(this);

  InstructionOperand inputs[] = {g.UseRegister(this->input_at(node, 0))};
  InstructionOperand outputs[2];
  size_t output_count = 0;
  outputs[output_count++] = g.DefineAsRegister(node);

  node_t success_output = FindProjection(node, 1);
  if (this->valid(success_output)) {
    outputs[output_count++] = g.DefineAsRegister(success_output);
  }

  Emit(kMips64TruncUlD, output_count, outputs, 1, inputs);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTryTruncateFloat64ToInt32(
    node_t node) {
  Mips64OperandGeneratorT<Adapter> g(this);

  InstructionOperand inputs[] = {g.UseRegister(this->input_at(node, 0))};
  InstructionOperand outputs[2];
  size_t output_count = 0;
  outputs[output_count++] = g.DefineAsRegister(node);

  node_t success_output = FindProjection(node, 1);
  if (this->valid(success_output)) {
    outputs[output_count++] = g.DefineAsRegister(success_output);
  }

  Emit(kMips64TruncWD, output_count, outputs, 1, inputs);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTryTruncateFloat64ToUint32(
    node_t node) {
  Mips64OperandGeneratorT<Adapter> g(this);

  InstructionOperand inputs[] = {g.UseRegister(this->input_at(node, 0))};
  InstructionOperand outputs[2];
  size_t output_count = 0;
  outputs[output_count++] = g.DefineAsRegister(node);

  node_t success_output = FindProjection(node, 1);
  if (this->valid(success_output)) {
    outputs[output_count++] = g.DefineAsRegister(success_output);
  }

  Emit(kMips64TruncUwD, output_count, outputs, 1, inputs);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitBitcastWord32ToWord64(node_t node) {
  UNIMPLEMENTED();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitChangeInt32ToInt64(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    Mips64OperandGeneratorT<Adapter> g(this);
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const ChangeOp& change_op = this->Get(node).template Cast<ChangeOp>();
    const Operation& input_op = this->Get(change_op.input());
    if (input_op.Is<LoadOp>() && CanCover(node, change_op.input())) {
      // Generate sign-extending load.
      LoadRepresentation load_rep =
          this->load_view(change_op.input()).loaded_rep();
      MachineRepresentation rep = load_rep.representation();
      InstructionCode opcode = kArchNop;
      switch (rep) {
        case MachineRepresentation::kBit:  // Fall through.
        case MachineRepresentation::kWord8:
          opcode = load_rep.IsUnsigned() ? kMips64Lbu : kMips64Lb;
          break;
        case MachineRepresentation::kWord16:
          opcode = load_rep.IsUnsigned() ? kMips64Lhu : kMips64Lh;
          break;
        case MachineRepresentation::kWord32:
          opcode = kMips64Lw;
          break;
        default:
          UNREACHABLE();
      }
      EmitLoad(this, change_op.input(), opcode, node);
      return;
    } else if (input_op.Is<Opmask::kWord32ShiftRightArithmetic>() &&
               CanCover(node, change_op.input())) {
      // TODO(MIPS_dev): May also optimize 'TruncateInt64ToInt32' here.
      EmitIdentity(node);
    }
    Emit(kMips64Shl, g.DefineAsRegister(node), g.UseRegister(change_op.input()),
         g.TempImmediate(0));
  } else {
    Mips64OperandGeneratorT<Adapter> g(this);
    Node* value = node->InputAt(0);
    if ((value->opcode() == IrOpcode::kLoad ||
         value->opcode() == IrOpcode::kLoadImmutable) &&
        CanCover(node, value)) {
      // Generate sign-extending load.
      LoadRepresentation load_rep = LoadRepresentationOf(value->op());
      InstructionCode opcode = kArchNop;
      switch (load_rep.representation()) {
        case MachineRepresentation::kBit:  // Fall through.
        case MachineRepresentation::kWord8:
          opcode = load_rep.IsUnsigned() ? kMips64Lbu : kMips64Lb;
          break;
        case MachineRepresentation::kWord16:
          opcode = load_rep.IsUnsigned() ? kMips64Lhu : kMips64Lh;
          break;
        case MachineRepresentation::kWord32:
          opcode = kMips64Lw;
          break;
        default:
          UNREACHABLE();
      }
      EmitLoad(this, value, opcode, node);
      return;
    } else if (value->opcode() == IrOpcode::kTruncateInt64ToInt32) {
      EmitIdentity(node);
      return;
    }
    Emit(kMips64Shl, g.DefineAsRegister(node), g.UseRegister(value),
         g.TempImmediate(0));
  }
}

template <>
bool InstructionSelectorT<TurboshaftAdapter>::ZeroExtendsWord32ToWord64NoPhis(
    node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  DCHECK(!this->Get(node).Is<PhiOp>());
  const Operation& op = this->Get(node);
  switch (op.opcode) {
    // Comparisons only emit 0/1, so the upper 32 bits must be zero.
    case Opcode::kComparison:
      return op.Cast<ComparisonOp>().rep == RegisterRepresentation::Word32();
    case Opcode::kOverflowCheckedBinop:
      return op.Cast<OverflowCheckedBinopOp>().rep ==
             WordRepresentation::Word32();
    case Opcode::kLoad: {
      auto load = this->load_view(node);
      LoadRepresentation load_rep = load.loaded_rep();
      if (load_rep.IsUnsigned()) {
        switch (load_rep.representation()) {
          case MachineRepresentation::kBit:    // Fall through.
          case MachineRepresentation::kWord8:  // Fall through.
          case MachineRepresentation::kWord16:
            return true;
          default:
            return false;
        }
      }
      return false;
    }
    default:
      return false;
  }
}

template <>
bool InstructionSelectorT<TurbofanAdapter>::ZeroExtendsWord32ToWord64NoPhis(
    Node* node) {
  DCHECK_NE(node->opcode(), IrOpcode::kPhi);
  switch (node->opcode()) {
    // Comparisons only emit 0/1, so the upper 32 bits must be zero.
    case IrOpcode::kWord32Equal:
    case IrOpcode::kInt32LessThan:
    case IrOpcode::kInt32LessThanOrEqual:
    case IrOpcode::kUint32LessThan:
    case IrOpcode::kUint32LessThanOrEqual:
      return true;
    case IrOpcode::kWord32And: {
      Int32BinopMatcher m(node);
      if (m.right().HasResolvedValue()) {
        uint32_t mask = m.right().ResolvedValue();
        return is_uint31(mask);
      }
      return false;
    }
    case IrOpcode::kWord32Shr: {
      Int32BinopMatcher m(node);
      if (m.right().HasResolvedValue()) {
        uint8_t sa = m.right().ResolvedValue() & 0x1f;
        return sa > 0;
      }
      return false;
    }
    case IrOpcode::kLoad:
    case IrOpcode::kLoadImmutable: {
      LoadRepresentation load_rep = LoadRepresentationOf(node->op());
      if (load_rep.IsUnsigned()) {
        switch (load_rep.representation()) {
          case MachineRepresentation::kWord8:
          case MachineRepresentation::kWord16:
            return true;
          default:
            return false;
        }
      }
      return false;
    }
    default:
      return false;
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitChangeUint32ToUint64(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    Mips64OperandGeneratorT<Adapter> g(this);
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const ChangeOp& change_op = this->Get(node).template Cast<ChangeOp>();
    node_t input = change_op.input();
    const Operation& input_op = this->Get(input);

    if (input_op.Is<LoadOp>() && CanCover(node, input)) {
      // Generate zero-extending load.
      LoadRepresentation load_rep = this->load_view(input).loaded_rep();
      if (load_rep.IsUnsigned() &&
          load_rep.representation() == MachineRepresentation::kWord32) {
        EmitLoad(this, input, kMips64Lwu, node);
        return;
      }
    }
    if (ZeroExtendsWord32ToWord64(input)) {
      EmitIdentity(node);
      return;
    }
    Emit(kMips64Dext, g.DefineAsRegister(node), g.UseRegister(input),
         g.TempImmediate(0), g.TempImmediate(32));
  } else {
    Mips64OperandGeneratorT<Adapter> g(this);
    Node* value = node->InputAt(0);
    IrOpcode::Value opcode = value->opcode();

    if (opcode == IrOpcode::kLoad || opcode == IrOpcode::kUnalignedLoad) {
      LoadRepresentation load_rep = LoadRepresentationOf(value->op());
      ArchOpcode arch_opcode =
          opcode == IrOpcode::kUnalignedLoad ? kMips64Ulwu : kMips64Lwu;
      if (load_rep.IsUnsigned() &&
          load_rep.representation() == MachineRepresentation::kWord32) {
        EmitLoad(this, value, arch_opcode, node);
        return;
      }
    }

    if (ZeroExtendsWord32ToWord64(value)) {
      EmitIdentity(node);
      return;
    }

    Emit(kMips64Dext, g.DefineAsRegister(node), g.UseRegister(node->InputAt(0)),
         g.TempImmediate(0), g.TempImmediate(32));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTruncateInt64ToInt32(node_t node) {
  Mips64OperandGeneratorT<Adapter> g(this);
  Node* value = node->InputAt(0);
  if (CanCover(node, value)) {
    switch (value->opcode()) {
      case IrOpcode::kWord64Sar: {
        if (CanCover(value, value->InputAt(0)) &&
            TryEmitExtendingLoad(this, value, node)) {
          return;
        } else {
          Int64BinopMatcher m(value);
          if (m.right().IsInRange(32, 63)) {
            // After smi untagging no need for truncate. Combine sequence.
            Emit(kMips64Dsar, g.DefineAsRegister(node),
                 g.UseRegister(m.left().node()),
                 g.UseImmediate(m.right().node()));
            return;
          }
        }
        break;
      }
      default:
        break;
    }
  }
    Emit(kMips64Shl, g.DefineAsRegister(node), g.UseRegister(node->InputAt(0)),
         g.TempImmediate(0));
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitTruncateInt64ToInt32(
    node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  Mips64OperandGeneratorT<TurboshaftAdapter> g(this);
  auto value = input_at(node, 0);
  if (CanCover(node, value)) {
    if (Get(value).Is<Opmask::kWord64ShiftRightArithmetic>()) {
      auto shift_value = input_at(value, 1);
      if (CanCover(value, input_at(value, 0)) &&
          TryEmitExtendingLoad(this, value, node)) {
        return;
      } else if (g.IsIntegerConstant(shift_value)) {
        auto constant = g.GetIntegerConstantValue(constant_view(shift_value));

        if (constant >= 32 && constant <= 63) {
          // After smi untagging no need for truncate. Combine sequence.
          Emit(kMips64Dsar, g.DefineAsRegister(node),
               g.UseRegister(input_at(value, 0)),
               g.UseImmediate(input_at(value, 1)));
          return;
        }
      }
    }
  }
  Emit(kMips64Shl, g.DefineAsRegister(node), g.UseRegister(value),
       g.TempImmediate(0));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTruncateFloat64ToFloat32(node_t node) {
  Mips64OperandGeneratorT<Adapter> g(this);

  if constexpr (Adapter::IsTurboshaft) {
    // TODO(mips64): Check if could be optimized like turbofan here.
  } else {
    Node* value = node->InputAt(0);
    // Match TruncateFloat64ToFloat32(ChangeInt32ToFloat64) to corresponding
    // instruction.
    if (CanCover(node, value) &&
        value->opcode() == IrOpcode::kChangeInt32ToFloat64) {
      Emit(kMips64CvtSW, g.DefineAsRegister(node),
           g.UseRegister(value->InputAt(0)));
      return;
    }
  }

  VisitRR(this, kMips64CvtSD, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTruncateFloat64ToWord32(node_t node) {
  VisitRR(this, kArchTruncateDoubleToI, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitRoundFloat64ToInt32(node_t node) {
  VisitRR(this, kMips64TruncWD, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitRoundInt64ToFloat32(node_t node) {
  VisitRR(this, kMips64CvtSL, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitRoundInt64ToFloat64(node_t node) {
  VisitRR(this, kMips64CvtDL, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitRoundUint64ToFloat32(node_t node) {
  VisitRR(this, kMips64CvtSUl, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitRoundUint64ToFloat64(node_t node) {
  VisitRR(this, kMips64CvtDUl, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitBitcastFloat32ToInt32(node_t node) {
  VisitRR(this, kMips64Float64ExtractLowWord32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitBitcastFloat64ToInt64(node_t node) {
  VisitRR(this, kMips64BitcastDL, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitBitcastInt32ToFloat32(node_t node) {
  // when move lower 32 bits of general registers to 64-bit fpu registers on
  // mips64, the upper 32 bits of the fpu register is undefined. So we could
  // just move the whole 64 bits to fpu registers.
  VisitRR(this, kMips64BitcastLD, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitBitcastInt64ToFloat64(node_t node) {
  VisitRR(this, kMips64BitcastLD, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Add(node_t node) {
  // Optimization with Madd.S(z, x, y) is intentionally removed.
  // See explanation for madd_s in assembler-mips64.cc.
  VisitRRR(this, kMips64AddS, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Add(node_t node) {
  // Optimization with Madd.D(z, x, y) is intentionally removed.
  // See explanation for madd_d in assembler-mips64.cc.
  VisitRRR(this, kMips64AddD, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Sub(node_t node) {
  // Optimization with Msub.S(z, x, y) is intentionally removed.
  // See explanation for madd_s in assembler-mips64.cc.
  VisitRRR(this, kMips64SubS, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Sub(node_t node) {
  // Optimization with Msub.D(z, x, y) is intentionally removed.
  // See explanation for madd_d in assembler-mips64.cc.
  VisitRRR(this, kMips64SubD, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Mul(node_t node) {
  VisitRRR(this, kMips64MulS, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Mul(node_t node) {
  VisitRRR(this, kMips64MulD, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Div(node_t node) {
  VisitRRR(this, kMips64DivS, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Div(node_t node) {
  VisitRRR(this, kMips64DivD, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Mod(node_t node) {
  Mips64OperandGeneratorT<Adapter> g(this);
  Emit(kMips64ModD, g.DefineAsFixed(node, f0),
       g.UseFixed(this->input_at(node, 0), f12),
       g.UseFixed(this->input_at(node, 1), f14))
      ->MarkAsCall();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Max(node_t node) {
  VisitRRR(this, kMips64Float32Max, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Max(node_t node) {
  VisitRRR(this, kMips64Float64Max, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Min(node_t node) {
  VisitRRR(this, kMips64Float32Min, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Min(node_t node) {
  VisitRRR(this, kMips64Float64Min, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Abs(node_t node) {
  VisitRR(this, kMips64AbsS, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Abs(node_t node) {
  VisitRR(this, kMips64AbsD, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Sqrt(node_t node) {
  VisitRR(this, kMips64SqrtS, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Sqrt(node_t node) {
  VisitRR(this, kMips64SqrtD, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32RoundDown(node_t node) {
  VisitRR(this, kMips64Float32RoundDown, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64RoundDown(node_t node) {
  VisitRR(this, kMips64Float64RoundDown, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32RoundUp(node_t node) {
  VisitRR(this, kMips64Float32RoundUp, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64RoundUp(node_t node) {
  VisitRR(this, kMips64Float64RoundUp, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32RoundTruncate(node_t node) {
  VisitRR(this, kMips64Float32RoundTruncate, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64RoundTruncate(node_t node) {
  VisitRR(this, kMips64Float64RoundTruncate, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64RoundTiesAway(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32RoundTiesEven(node_t node) {
  VisitRR(this, kMips64Float32RoundTiesEven, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64RoundTiesEven(node_t node) {
  VisitRR(this, kMips64Float64RoundTiesEven, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Neg(node_t node) {
  VisitRR(this, kMips64NegS, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Neg(node_t node) {
  VisitRR(this, kMips64NegD, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Ieee754Binop(
    node_t node, InstructionCode opcode) {
  Mips64OperandGeneratorT<Adapter> g(this);
  Emit(opcode, g.DefineAsFixed(node, f0),
       g.UseFixed(this->input_at(node, 0), f2),
       g.UseFixed(this->input_at(node, 1), f4))
      ->MarkAsCall();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Ieee754Unop(
    node_t node, InstructionCode opcode) {
  Mips64OperandGeneratorT<Adapter> g(this);
  Emit(opcode, g.DefineAsFixed(node, f0),
       g.UseFixed(this->input_at(node, 0), f12))
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
  Mips64OperandGeneratorT<Adapter> g(this);

  // Prepare for C function call.
  if (call_descriptor->IsCFunctionCall()) {
    Emit(kArchPrepareCallCFunction | MiscField::encode(static_cast<int>(
                                         call_descriptor->ParameterCount())),
         0, nullptr, 0, nullptr);

    // Poke any stack arguments.
    int slot = kCArgSlotCount;
    for (PushParameter input : (*arguments)) {
      Emit(kMips64StoreToStackSlot, g.NoOutput(), g.UseRegister(input.node),
           g.TempImmediate(slot << kSystemPointerSizeLog2));
      ++slot;
    }
  } else {
    int push_count = static_cast<int>(call_descriptor->ParameterSlotCount());
    if (push_count > 0) {
      // Calculate needed space
      int stack_size = 0;
      for (PushParameter input : (*arguments)) {
        if (this->valid(input.node)) {
          stack_size += input.location.GetSizeInPointers();
        }
      }
      Emit(kMips64StackClaim, g.NoOutput(),
           g.TempImmediate(stack_size << kSystemPointerSizeLog2));
    }
    for (size_t n = 0; n < arguments->size(); ++n) {
      PushParameter input = (*arguments)[n];
      if (this->valid(input.node)) {
        Emit(kMips64StoreToStackSlot, g.NoOutput(), g.UseRegister(input.node),
             g.TempImmediate(static_cast<int>(n << kSystemPointerSizeLog2)));
      }
    }
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::EmitPrepareResults(
    ZoneVector<PushParameter>* results, const CallDescriptor* call_descriptor,
    node_t node) {
  Mips64OperandGeneratorT<Adapter> g(this);

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
      Emit(kMips64Peek, g.DefineAsRegister(output.node),
           g.UseImmediate(reverse_slot));
    }
  }
}

template <typename Adapter>
bool InstructionSelectorT<Adapter>::IsTailCallAddressImmediate() {
  return false;
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUnalignedLoad(node_t node) {
  auto load = this->load_view(node);
  LoadRepresentation load_rep = load.loaded_rep();

  InstructionCode opcode = kArchNop;
  switch (load_rep.representation()) {
    case MachineRepresentation::kFloat32:
      opcode = kMips64Ulwc1;
      break;
    case MachineRepresentation::kFloat64:
      opcode = kMips64Uldc1;
      break;
    case MachineRepresentation::kWord8:
      opcode = load_rep.IsUnsigned() ? kMips64Lbu : kMips64Lb;
      break;
    case MachineRepresentation::kWord16:
      opcode = load_rep.IsUnsigned() ? kMips64Ulhu : kMips64Ulh;
      break;
    case MachineRepresentation::kWord32:
      opcode = kMips64Ulw;
      break;
    case MachineRepresentation::kTaggedSigned:   // Fall through.
    case MachineRepresentation::kTaggedPointer:  // Fall through.
    case MachineRepresentation::kTagged:         // Fall through.
    case MachineRepresentation::kWord64:
      opcode = kMips64Uld;
      break;
    case MachineRepresentation::kSimd128:
      opcode = kMips64MsaLd;
      break;
    case MachineRepresentation::kFloat16:
      UNIMPLEMENTED();
    case MachineRepresentation::kSimd256:            // Fall through.
    case MachineRepresentation::kBit:                // Fall through.
    case MachineRepresentation::kCompressedPointer:  // Fall through.
    case MachineRepresentation::kCompressed:         // Fall through.
    case MachineRepresentation::kProtectedPointer:   // Fall through.
    case MachineRepresentation::kSandboxedPointer:   // Fall through.
    case MachineRepresentation::kMapWord:            // Fall through.
    case MachineRepresentation::kIndirectPointer:    // Fall through.
    case MachineRepresentation::kNone:
      UNREACHABLE();
  }

  EmitLoad(this, node, opcode);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUnalignedStore(node_t node) {
  Mips64OperandGeneratorT<Adapter> g(this);
  typename Adapter::StoreView store_view = this->store_view(node);
  DCHECK_EQ(store_view.displacement(), 0);
  node_t base = store_view.base();
  node_t index = this->value(store_view.index());
  node_t value = store_view.value();

  MachineRepresentation rep = store_view.stored_rep().representation();

  ArchOpcode opcode;
  switch (rep) {
    case MachineRepresentation::kFloat32:
      opcode = kMips64Uswc1;
      break;
    case MachineRepresentation::kFloat64:
      opcode = kMips64Usdc1;
      break;
    case MachineRepresentation::kWord8:
      opcode = kMips64Sb;
      break;
    case MachineRepresentation::kWord16:
      opcode = kMips64Ush;
      break;
    case MachineRepresentation::kWord32:
      opcode = kMips64Usw;
      break;
    case MachineRepresentation::kTaggedSigned:   // Fall through.
    case MachineRepresentation::kTaggedPointer:  // Fall through.
    case MachineRepresentation::kTagged:         // Fall through.
    case MachineRepresentation::kWord64:
      opcode = kMips64Usd;
      break;
    case MachineRepresentation::kSimd128:
      opcode = kMips64MsaSt;
      break;
    case MachineRepresentation::kFloat16:
      UNIMPLEMENTED();
    case MachineRepresentation::kSimd256:            // Fall through.
    case MachineRepresentation::kBit:                // Fall through.
    case MachineRepresentation::kCompressedPointer:  // Fall through.
    case MachineRepresentation::kCompressed:         // Fall through.
    case MachineRepresentation::kProtectedPointer:   // Fall through.
    case MachineRepresentation::kSandboxedPointer:   // Fall through.
    case MachineRepresentation::kMapWord:            // Fall through.
    case MachineRepresentation::kIndirectPointer:    // Fall through.
    case MachineRepresentation::kNone:
      UNREACHABLE();
  }

  if (g.CanBeImmediate(index, opcode)) {
    Emit(opcode | AddressingModeField::encode(kMode_MRI), g.NoOutput(),
         g.UseRegister(base), g.UseImmediate(index),
         g.UseRegisterOrImmediateZero(value));
  } else {
    InstructionOperand addr_reg = g.TempRegister();
    Emit(kMips64Dadd | AddressingModeField::encode(kMode_None), addr_reg,
         g.UseRegister(index), g.UseRegister(base));
    // Emit desired store opcode, using temp addr_reg.
    Emit(opcode | AddressingModeField::encode(kMode_MRI), g.NoOutput(),
         addr_reg, g.TempImmediate(0), g.UseRegisterOrImmediateZero(value));
  }
}

namespace {

// Shared routine for multiple compare operations.
template <typename Adapter>
static Instruction* VisitCompare(InstructionSelectorT<Adapter>* selector,
                                 InstructionCode opcode,
                                 InstructionOperand left,
                                 InstructionOperand right,
                                 FlagsContinuationT<Adapter>* cont) {
  return selector->EmitWithContinuation(opcode, left, right, cont);
}

// Shared routine for multiple float32 compare operations.
tem
```