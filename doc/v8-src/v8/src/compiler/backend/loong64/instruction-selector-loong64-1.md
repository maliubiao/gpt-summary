Response: The user is asking for a summary of the functionality of the C++ code provided. This is the second part of a three-part file. I need to analyze the code snippets and identify the operations being performed. The code seems to be related to instruction selection for the LoongArch64 architecture within the V8 JavaScript engine. It defines how high-level operations are translated into low-level machine instructions. I should focus on the types of operations covered in this specific part and mention any connection to JavaScript concepts if applicable.

Looking at the code, it mainly deals with:
- Integer arithmetic operations (multiplication, division, modulo) for both 32-bit and 64-bit integers.
- Integer conversions (widening, narrowing, signed/unsigned).
- Floating-point conversions (between different precisions and to/from integers).
- Floating-point arithmetic operations (addition, subtraction, multiplication, division, modulo, min, max, absolute value, square root, rounding, negation).
- Bitwise operations (explicitly mentioned in the `VisitBitcast` functions).
- Comparisons (for integers and floating-point numbers).
- Atomic operations (load, store, exchange, compare exchange, and other binary operations).
- Stack pointer checks.

The connection to JavaScript lies in the fact that these operations are the low-level implementations of JavaScript's number manipulation features.
这是C++源代码文件 `v8/src/compiler/backend/loong64/instruction-selector-loong64.cc` 的第二部分，主要负责将中间表示 (IR) 节点转换为 LoongArch64 架构的机器指令。

**本部分的主要功能包括：**

1. **整数运算指令选择：**
   - 实现了 32 位和 64 位整数的乘法 (`VisitInt32Mul`, `VisitInt64Mul`)，包括一些针对常量乘数的优化，例如当乘数是 2 的幂次方时的移位操作，以及乘数是 2 的幂次方加/减 1 时的移位和加/减操作。
   - 实现了 32 位和 64 位整数的除法 (`VisitInt32Div`, `VisitUint32Div`, `VisitInt64Div`, `VisitUint64Div`)。
   - 实现了 32 位和 64 位整数的取模运算 (`VisitInt32Mod`, `VisitUint32Mod`, `VisitInt64Mod`, `VisitUint64Mod`)。
   - 实现了 32 位和 64 位整数的高位乘法 (`VisitInt32MulHigh`, `VisitInt64MulHigh`, `VisitUint32MulHigh`, `VisitUint64MulHigh`)。

2. **浮点数转换指令选择：**
   - 实现了各种浮点数之间的类型转换，例如 `float32` 到 `float64` (`VisitChangeFloat32ToFloat64`)，以及整数到浮点数的转换 (`VisitRoundInt32ToFloat32`, `VisitRoundUint32ToFloat32`, `VisitChangeInt32ToFloat64`, `VisitChangeInt64ToFloat64`, `VisitChangeUint32ToFloat64`)。
   - 实现了浮点数到整数的截断和转换，包括有符号和无符号的 32 位和 64 位整数 (`VisitTruncateFloat32ToInt32`, `VisitTruncateFloat32ToUint32`, `VisitChangeFloat64ToInt32`, `VisitChangeFloat64ToInt64`, `VisitChangeFloat64ToUint32`, `VisitChangeFloat64ToUint64`, `VisitTruncateFloat64ToUint32`, `VisitTruncateFloat64ToInt64`)，并且处理了溢出情况。
   - 实现了尝试将浮点数转换为整数的指令选择，会产生两个输出：转换后的整数和表示转换是否成功的布尔值 (`VisitTryTruncateFloat32ToInt64` 等)。
   - 实现了浮点数到浮点数的截断 (`VisitTruncateFloat64ToFloat32`)。

3. **整数类型转换指令选择：**
   - 实现了 32 位整数到 64 位整数的转换 (`VisitChangeInt32ToInt64`)，根据输入操作的不同，选择不同的指令，例如直接加载并进行符号扩展。
   - 实现了 32 位无符号整数到 64 位无符号整数的转换 (`VisitChangeUint32ToUint64`)，可以使用零扩展加载或者位域提取指令。
   - 实现了 64 位整数到 32 位整数的截断 (`VisitTruncateInt64ToInt32`)，针对移位操作进行了优化。

4. **位运算指令选择：**
   - 实现了不同类型之间的按位转换，例如 `word32` 到 `word64` (`VisitBitcastWord32ToWord64`)，以及整数和浮点数之间的位转换 (`VisitBitcastFloat32ToInt32`, `VisitBitcastFloat64ToInt64`, `VisitBitcastInt32ToFloat32`, `VisitBitcastInt64ToFloat64`)。

5. **浮点数运算指令选择：**
   - 实现了基本的浮点数算术运算，如加法 (`VisitFloat32Add`, `VisitFloat64Add`)，减法 (`VisitFloat32Sub`, `VisitFloat64Sub`)，乘法 (`VisitFloat32Mul`, `VisitFloat64Mul`)，除法 (`VisitFloat32Div`, `VisitFloat64Div`)，以及取模 (`VisitFloat64Mod`)。
   - 实现了浮点数的最大值 (`VisitFloat32Max`, `VisitFloat64Max`) 和最小值 (`VisitFloat32Min`, `VisitFloat64Min`)。
   - 实现了浮点数的绝对值 (`VisitFloat32Abs`, `VisitFloat64Abs`) 和平方根 (`VisitFloat32Sqrt`, `VisitFloat64Sqrt`)。
   - 实现了浮点数的舍入操作，包括向下舍入 (`VisitFloat32RoundDown`, `VisitFloat64RoundDown`)，向上舍入 (`VisitFloat32RoundUp`, `VisitFloat64RoundUp`)，向零舍入 (`VisitFloat32RoundTruncate`, `VisitFloat64RoundTruncate`)，以及向最接近的偶数舍入 (`VisitFloat32RoundTiesEven`, `VisitFloat64RoundTiesEven`)。
   - 实现了浮点数的取反运算 (`VisitFloat32Neg`, `VisitFloat64Neg`)。

6. **函数调用参数处理：**
   - 提供了将参数移动到浮点寄存器的函数 (`EmitMoveParamToFPR`) 和将浮点寄存器的值移动到参数位置的函数 (`EmitMoveFPRToParam`)。
   - 实现了函数调用前的参数准备 (`EmitPrepareArguments`)，包括为 C 函数调用和 JavaScript 函数调用准备参数。
   - 实现了函数调用后的结果准备 (`EmitPrepareResults`)，将返回值从寄存器或栈中取出。

7. **原子操作指令选择：**
   - 实现了原子加载操作 (`VisitAtomicLoad`)，针对不同的数据类型和原子宽度选择不同的指令。
   - 实现了原子存储操作 (`VisitAtomicStore`)，同样根据数据类型、原子宽度和是否需要写屏障选择合适的指令。
   - 实现了原子交换 (`VisitAtomicExchange`)、原子比较并交换 (`VisitAtomicCompareExchange`) 和原子二元运算 (`VisitAtomicBinop`) 等操作。

8. **栈指针检查：**
   - 实现了栈指针是否大于某个值的检查 (`VisitStackPointerGreaterThan`)，用于栈溢出检测。

9. **比较指令选择：**
   - 针对不同的数据类型 (整数和浮点数) 实现了比较指令的选择，并处理了与零比较的特殊情况 (`VisitWordCompareZero`)，尝试将比较操作与之前的运算合并。

**与 JavaScript 的关系：**

这部分代码负责将 JavaScript 中的数值运算和类型转换操作翻译成底层的机器指令。例如：

```javascript
let a = 10;
let b = 5;
let c = a * b; // 对应 VisitInt32Mul 或 VisitInt64Mul

let d = 3.14;
let e = parseInt(d); // 对应 VisitTruncateFloat64ToInt32

let f = 10000000000n;
let g = 5n;
let h = f + g; // 涉及到大整数运算，可能不会直接对应这里的指令，但涉及到位运算和算术运算的底层实现

let arr = new Int32Array(1);
Atomics.store(arr, 0, 42); // 对应 VisitAtomicStore
```

总而言之，这部分代码是 V8 引擎将 JavaScript 代码转换为可在 LoongArch64 架构上执行的机器码的关键组成部分，它负责选择最合适的机器指令来实现 JavaScript 的各种数值操作。
Prompt: 
```
这是目录为v8/src/compiler/backend/loong64/instruction-selector-loong64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
atcher leftInput(left), rightInput(right);
      if (leftInput.right().Is(32) && rightInput.right().Is(32)) {
        // Combine untagging shifts with Mulh_d.
        Emit(kLoong64Mulh_d, g.DefineSameAsFirst(node),
             g.UseRegister(leftInput.left().node()),
             g.UseRegister(rightInput.left().node()));
        return;
      }
    }
  }
  VisitRRR(this, kLoong64Mul_w, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32MulHigh(node_t node) {
  VisitRRR(this, kLoong64Mulh_w, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64MulHigh(node_t node) {
  VisitRRR(this, kLoong64Mulh_d, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint32MulHigh(node_t node) {
  VisitRRR(this, kLoong64Mulh_wu, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint64MulHigh(node_t node) {
  VisitRRR(this, kLoong64Mulh_du, node);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitInt64Mul(node_t node) {
  // TODO(LOONG_dev): May could be optimized like in Turbofan.
  VisitBinop(this, node, kLoong64Mul_d, true, kLoong64Mul_d);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitInt64Mul(Node* node) {
  Loong64OperandGeneratorT<TurbofanAdapter> g(this);
  Int64BinopMatcher m(node);
  if (m.right().HasResolvedValue() && m.right().ResolvedValue() > 0) {
    uint64_t value = static_cast<uint64_t>(m.right().ResolvedValue());
    if (base::bits::IsPowerOfTwo(value)) {
      Emit(kLoong64Sll_d | AddressingModeField::encode(kMode_None),
           g.DefineAsRegister(node), g.UseRegister(m.left().node()),
           g.TempImmediate(base::bits::WhichPowerOfTwo(value)));
      return;
    }
    if (base::bits::IsPowerOfTwo(value - 1) && value - 1 > 0) {
      // Alsl_d macro will handle the shifting value out of bound cases.
      Emit(kLoong64Alsl_d, g.DefineAsRegister(node),
           g.UseRegister(m.left().node()), g.UseRegister(m.left().node()),
           g.TempImmediate(base::bits::WhichPowerOfTwo(value - 1)));
      return;
    }
    if (base::bits::IsPowerOfTwo(value + 1)) {
      InstructionOperand temp = g.TempRegister();
      Emit(kLoong64Sll_d | AddressingModeField::encode(kMode_None), temp,
           g.UseRegister(m.left().node()),
           g.TempImmediate(base::bits::WhichPowerOfTwo(value + 1)));
      Emit(kLoong64Sub_d | AddressingModeField::encode(kMode_None),
           g.DefineAsRegister(node), temp, g.UseRegister(m.left().node()));
      return;
    }
  }
  Emit(kLoong64Mul_d, g.DefineAsRegister(node), g.UseRegister(m.left().node()),
       g.UseRegister(m.right().node()));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32Div(node_t node) {
  Loong64OperandGeneratorT<Adapter> g(this);

  if constexpr (Adapter::IsTurboshaft) {
    auto binop = this->word_binop_view(node);
    Emit(kLoong64Div_w, g.DefineSameAsFirst(node), g.UseRegister(binop.left()),
         g.UseRegister(binop.right()));
  } else {
    Int32BinopMatcher m(node);
    Node* left = node->InputAt(0);
    Node* right = node->InputAt(1);
    if (CanCover(node, left) && CanCover(node, right)) {
      if (left->opcode() == IrOpcode::kWord64Sar &&
          right->opcode() == IrOpcode::kWord64Sar) {
        Int64BinopMatcher rightInput(right), leftInput(left);
        if (rightInput.right().Is(32) && leftInput.right().Is(32)) {
          // Combine both shifted operands with Div_d.
          Emit(kLoong64Div_d, g.DefineSameAsFirst(node),
               g.UseRegister(leftInput.left().node()),
               g.UseRegister(rightInput.left().node()));
          return;
        }
      }
    }
    Emit(kLoong64Div_w, g.DefineSameAsFirst(node),
         g.UseRegister(m.left().node()), g.UseRegister(m.right().node()));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint32Div(node_t node) {
  Loong64OperandGeneratorT<Adapter> g(this);
  auto binop = this->word_binop_view(node);
  Emit(kLoong64Div_wu, g.DefineSameAsFirst(node), g.UseRegister(binop.left()),
       g.UseRegister(binop.right()));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32Mod(node_t node) {
  Loong64OperandGeneratorT<Adapter> g(this);

  if constexpr (Adapter::IsTurboshaft) {
    auto binop = this->word_binop_view(node);
    Emit(kLoong64Mod_w, g.DefineSameAsFirst(node), g.UseRegister(binop.left()),
         g.UseRegister(binop.right()));
  } else {
    Int32BinopMatcher m(node);
    Node* left = node->InputAt(0);
    Node* right = node->InputAt(1);
    if (CanCover(node, left) && CanCover(node, right)) {
      if (left->opcode() == IrOpcode::kWord64Sar &&
          right->opcode() == IrOpcode::kWord64Sar) {
        Int64BinopMatcher rightInput(right), leftInput(left);
        if (rightInput.right().Is(32) && leftInput.right().Is(32)) {
          // Combine both shifted operands with Mod_d.
          Emit(kLoong64Mod_d, g.DefineSameAsFirst(node),
               g.UseRegister(leftInput.left().node()),
               g.UseRegister(rightInput.left().node()));
          return;
        }
      }
    }
    Emit(kLoong64Mod_w, g.DefineAsRegister(node),
         g.UseRegister(m.left().node()), g.UseRegister(m.right().node()));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint32Mod(node_t node) {
  VisitRRR(this, kLoong64Mod_wu, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64Div(node_t node) {
  Loong64OperandGeneratorT<Adapter> g(this);
  auto binop = this->word_binop_view(node);
  Emit(kLoong64Div_d, g.DefineSameAsFirst(node), g.UseRegister(binop.left()),
       g.UseRegister(binop.right()));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint64Div(node_t node) {
  Loong64OperandGeneratorT<Adapter> g(this);
  auto binop = this->word_binop_view(node);
  Emit(kLoong64Div_du, g.DefineSameAsFirst(node), g.UseRegister(binop.left()),
       g.UseRegister(binop.right()));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64Mod(node_t node) {
  VisitRRR(this, kLoong64Mod_d, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint64Mod(node_t node) {
  VisitRRR(this, kLoong64Mod_du, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitChangeFloat32ToFloat64(node_t node) {
  VisitRR(this, kLoong64Float32ToFloat64, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitRoundInt32ToFloat32(node_t node) {
  VisitRR(this, kLoong64Int32ToFloat32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitRoundUint32ToFloat32(node_t node) {
  VisitRR(this, kLoong64Uint32ToFloat32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitChangeInt32ToFloat64(node_t node) {
  VisitRR(this, kLoong64Int32ToFloat64, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitChangeInt64ToFloat64(node_t node) {
  VisitRR(this, kLoong64Int64ToFloat64, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitChangeUint32ToFloat64(node_t node) {
  VisitRR(this, kLoong64Uint32ToFloat64, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTruncateFloat32ToInt32(node_t node) {
  Loong64OperandGeneratorT<Adapter> g(this);

  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const Operation& op = this->Get(node);
    InstructionCode opcode = kLoong64Float32ToInt32;
    opcode |= MiscField::encode(
        op.Is<Opmask::kTruncateFloat32ToInt32OverflowToMin>());
    Emit(opcode, g.DefineAsRegister(node),
         g.UseRegister(this->input_at(node, 0)));
  } else {
    InstructionCode opcode = kLoong64Float32ToInt32;
    TruncateKind kind = OpParameter<TruncateKind>(node->op());
    if (kind == TruncateKind::kSetOverflowToMin) {
      opcode |= MiscField::encode(true);
    }
    Emit(opcode, g.DefineAsRegister(node), g.UseRegister(node->InputAt(0)));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTruncateFloat32ToUint32(node_t node) {
  Loong64OperandGeneratorT<Adapter> g(this);

  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const Operation& op = this->Get(node);
    InstructionCode opcode = kLoong64Float32ToUint32;
    if (op.Is<Opmask::kTruncateFloat32ToUint32OverflowToMin>()) {
      opcode |= MiscField::encode(true);
    }

    Emit(opcode, g.DefineAsRegister(node),
         g.UseRegister(this->input_at(node, 0)));
  } else {
    InstructionCode opcode = kLoong64Float32ToUint32;
    TruncateKind kind = OpParameter<TruncateKind>(node->op());
    if (kind == TruncateKind::kSetOverflowToMin) {
      opcode |= MiscField::encode(true);
    }
    Emit(opcode, g.DefineAsRegister(node), g.UseRegister(node->InputAt(0)));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitChangeFloat64ToInt32(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    // TODO(loong64): Check if could be optimized like turbofan here.
  } else {
    Loong64OperandGeneratorT<Adapter> g(this);
    Node* value = node->InputAt(0);
    // TODO(LOONG_dev): LOONG64 Match ChangeFloat64ToInt32(Float64Round##OP) to
    // corresponding instruction which does rounding and conversion to
    // integer format.
    if (CanCover(node, value)) {
      if (value->opcode() == IrOpcode::kChangeFloat32ToFloat64) {
        Node* next = value->InputAt(0);
        if (!CanCover(value, next)) {
          // Match float32 -> float64 -> int32 representation change path.
          Emit(kLoong64Float32ToInt32, g.DefineAsRegister(node),
               g.UseRegister(value->InputAt(0)));
          return;
        }
      }
    }
  }

  VisitRR(this, kLoong64Float64ToInt32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitChangeFloat64ToInt64(node_t node) {
  VisitRR(this, kLoong64Float64ToInt64, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitChangeFloat64ToUint32(node_t node) {
  VisitRR(this, kLoong64Float64ToUint32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitChangeFloat64ToUint64(node_t node) {
  VisitRR(this, kLoong64Float64ToUint64, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTruncateFloat64ToUint32(node_t node) {
  VisitRR(this, kLoong64Float64ToUint32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTruncateFloat64ToInt64(node_t node) {
  Loong64OperandGeneratorT<Adapter> g(this);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    InstructionCode opcode = kLoong64Float64ToInt64;
    const Operation& op = this->Get(node);
    if (op.Is<Opmask::kTruncateFloat64ToInt64OverflowToMin>()) {
      opcode |= MiscField::encode(true);
    }

    Emit(opcode, g.DefineAsRegister(node), g.UseRegister(op.input(0)));
  } else {
    InstructionCode opcode = kLoong64Float64ToInt64;
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
  Loong64OperandGeneratorT<Adapter> g(this);

  InstructionOperand inputs[] = {g.UseRegister(this->input_at(node, 0))};
  InstructionOperand outputs[2];
  size_t output_count = 0;
  outputs[output_count++] = g.DefineAsRegister(node);

  node_t success_output = FindProjection(node, 1);
  if (this->valid(success_output)) {
    outputs[output_count++] = g.DefineAsRegister(success_output);
  }

  Emit(kLoong64Float32ToInt64, output_count, outputs, 1, inputs);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTryTruncateFloat64ToInt64(
    node_t node) {
  Loong64OperandGeneratorT<Adapter> g(this);

  InstructionOperand inputs[] = {g.UseRegister(this->input_at(node, 0))};
  InstructionOperand outputs[2];
  size_t output_count = 0;
  outputs[output_count++] = g.DefineAsRegister(node);

  node_t success_output = FindProjection(node, 1);
  if (this->valid(success_output)) {
    outputs[output_count++] = g.DefineAsRegister(success_output);
  }

  Emit(kLoong64Float64ToInt64, output_count, outputs, 1, inputs);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTryTruncateFloat32ToUint64(
    node_t node) {
  Loong64OperandGeneratorT<Adapter> g(this);

  InstructionOperand inputs[] = {g.UseRegister(this->input_at(node, 0))};
  InstructionOperand outputs[2];
  size_t output_count = 0;
  outputs[output_count++] = g.DefineAsRegister(node);

  node_t success_output = FindProjection(node, 1);
  if (this->valid(success_output)) {
    outputs[output_count++] = g.DefineAsRegister(success_output);
  }

  Emit(kLoong64Float32ToUint64, output_count, outputs, 1, inputs);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTryTruncateFloat64ToUint64(
    node_t node) {
  Loong64OperandGeneratorT<Adapter> g(this);

  InstructionOperand inputs[] = {g.UseRegister(this->input_at(node, 0))};
  InstructionOperand outputs[2];
  size_t output_count = 0;
  outputs[output_count++] = g.DefineAsRegister(node);

  node_t success_output = FindProjection(node, 1);
  if (this->valid(success_output)) {
    outputs[output_count++] = g.DefineAsRegister(success_output);
  }

  Emit(kLoong64Float64ToUint64, output_count, outputs, 1, inputs);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTryTruncateFloat64ToInt32(
    node_t node) {
  Loong64OperandGeneratorT<Adapter> g(this);

  InstructionOperand inputs[] = {g.UseRegister(this->input_at(node, 0))};
  InstructionOperand outputs[2];
  size_t output_count = 0;
  outputs[output_count++] = g.DefineAsRegister(node);

  node_t success_output = FindProjection(node, 1);
  if (this->valid(success_output)) {
    outputs[output_count++] = g.DefineAsRegister(success_output);
  }

  Emit(kLoong64Float64ToInt32, output_count, outputs, 1, inputs);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTryTruncateFloat64ToUint32(
    node_t node) {
  Loong64OperandGeneratorT<Adapter> g(this);

  InstructionOperand inputs[] = {g.UseRegister(this->input_at(node, 0))};
  InstructionOperand outputs[2];
  size_t output_count = 0;
  outputs[output_count++] = g.DefineAsRegister(node);

  node_t success_output = FindProjection(node, 1);
  if (this->valid(success_output)) {
    outputs[output_count++] = g.DefineAsRegister(success_output);
  }

  Emit(kLoong64Float64ToUint32, output_count, outputs, 1, inputs);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitBitcastWord32ToWord64(node_t node) {
  DCHECK(SmiValuesAre31Bits());
  DCHECK(COMPRESS_POINTERS_BOOL);
  EmitIdentity(node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitChangeInt32ToInt64(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    Loong64OperandGeneratorT<Adapter> g(this);
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
          opcode = load_rep.IsUnsigned() ? kLoong64Ld_bu : kLoong64Ld_b;
          break;
        case MachineRepresentation::kWord16:
          opcode = load_rep.IsUnsigned() ? kLoong64Ld_hu : kLoong64Ld_h;
          break;
        case MachineRepresentation::kWord32:
        case MachineRepresentation::kTaggedSigned:
        case MachineRepresentation::kTagged:
        case MachineRepresentation::kTaggedPointer:
          opcode = kLoong64Ld_w;
          break;
        default:
          UNREACHABLE();
      }
      EmitLoad(this, change_op.input(), opcode, node);
      return;
    } else if (input_op.Is<Opmask::kWord32ShiftRightArithmetic>() &&
               CanCover(node, change_op.input())) {
      // TODO(LOONG_dev): May also optimize 'TruncateInt64ToInt32' here.
      EmitIdentity(node);
    }
    Emit(kLoong64Sll_w, g.DefineAsRegister(node),
         g.UseRegister(change_op.input()), g.TempImmediate(0));
  } else {
    Loong64OperandGeneratorT<Adapter> g(this);
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
          opcode = load_rep.IsUnsigned() ? kLoong64Ld_bu : kLoong64Ld_b;
          break;
        case MachineRepresentation::kWord16:
          opcode = load_rep.IsUnsigned() ? kLoong64Ld_hu : kLoong64Ld_h;
          break;
        case MachineRepresentation::kWord32:
        case MachineRepresentation::kTaggedSigned:
        case MachineRepresentation::kTagged:
        case MachineRepresentation::kTaggedPointer:
          opcode = kLoong64Ld_w;
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
    Emit(kLoong64Sll_w, g.DefineAsRegister(node),
         g.UseRegister(node->InputAt(0)), g.TempImmediate(0));
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

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitChangeUint32ToUint64(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    Loong64OperandGeneratorT<Adapter> g(this);
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const ChangeOp& change_op = this->Get(node).template Cast<ChangeOp>();
    node_t input = change_op.input();
    const Operation& input_op = this->Get(input);

    if (input_op.Is<LoadOp>() && CanCover(node, input)) {
      // Generate zero-extending load.
      LoadRepresentation load_rep = this->load_view(input).loaded_rep();
      if (load_rep.IsUnsigned() &&
          load_rep.representation() == MachineRepresentation::kWord32) {
        EmitLoad(this, input, kLoong64Ld_wu, node);
        return;
      }
    }
    if (ZeroExtendsWord32ToWord64(input)) {
      EmitIdentity(node);
      return;
    }
    Emit(kLoong64Bstrpick_d, g.DefineAsRegister(node), g.UseRegister(input),
         g.TempImmediate(0), g.TempImmediate(32));
  } else {
    Loong64OperandGeneratorT<Adapter> g(this);
    Node* value = node->InputAt(0);

    if (value->opcode() == IrOpcode::kLoad) {
      LoadRepresentation load_rep = LoadRepresentationOf(value->op());
      if (load_rep.IsUnsigned() &&
          load_rep.representation() == MachineRepresentation::kWord32) {
        EmitLoad(this, value, kLoong64Ld_wu, node);
        return;
      }
    }
    if (ZeroExtendsWord32ToWord64(value)) {
      EmitIdentity(node);
      return;
    }
    Emit(kLoong64Bstrpick_d, g.DefineAsRegister(node),
         g.UseRegister(node->InputAt(0)), g.TempImmediate(0),
         g.TempImmediate(32));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTruncateInt64ToInt32(node_t node) {
    Loong64OperandGeneratorT<Adapter> g(this);
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
              Emit(kLoong64Sra_d, g.DefineAsRegister(node),
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
    Emit(kLoong64Sll_w, g.DefineAsRegister(node),
         g.UseRegister(node->InputAt(0)), g.TempImmediate(0));
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitTruncateInt64ToInt32(
    node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  Loong64OperandGeneratorT<TurboshaftAdapter> g(this);
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
          Emit(kLoong64Sra_d, g.DefineAsRegister(node),
               g.UseRegister(input_at(value, 0)), g.UseImmediate(constant));
          return;
        }
      }
    }
  }
  Emit(kLoong64Sll_w, g.DefineAsRegister(node), g.UseRegister(value),
       g.TempImmediate(0));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTruncateFloat64ToFloat32(node_t node) {
  Loong64OperandGeneratorT<Adapter> g(this);

  if constexpr (Adapter::IsTurboshaft) {
    // TODO(loong64): Check if could be optimized like turbofan here.
  } else {
    Node* value = node->InputAt(0);
    // Match TruncateFloat64ToFloat32(ChangeInt32ToFloat64) to corresponding
    // instruction.
    if (CanCover(node, value) &&
        value->opcode() == IrOpcode::kChangeInt32ToFloat64) {
      Emit(kLoong64Int32ToFloat32, g.DefineAsRegister(node),
           g.UseRegister(value->InputAt(0)));
      return;
    }
  }

  VisitRR(this, kLoong64Float64ToFloat32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTruncateFloat64ToWord32(node_t node) {
  VisitRR(this, kArchTruncateDoubleToI, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitRoundFloat64ToInt32(node_t node) {
  VisitRR(this, kLoong64Float64ToInt32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitRoundInt64ToFloat32(node_t node) {
  VisitRR(this, kLoong64Int64ToFloat32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitRoundInt64ToFloat64(node_t node) {
  VisitRR(this, kLoong64Int64ToFloat64, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitRoundUint64ToFloat32(node_t node) {
  VisitRR(this, kLoong64Uint64ToFloat32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitRoundUint64ToFloat64(node_t node) {
  VisitRR(this, kLoong64Uint64ToFloat64, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitBitcastFloat32ToInt32(node_t node) {
  VisitRR(this, kLoong64Float64ExtractLowWord32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitBitcastFloat64ToInt64(node_t node) {
  VisitRR(this, kLoong64BitcastDL, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitBitcastInt32ToFloat32(node_t node) {
  // when move lower 32 bits of general registers to 64-bit fpu registers on
  // LoongArch64, the upper 32 bits of the fpu register is undefined. So we
  // could just move the whole 64 bits to fpu registers.
  VisitRR(this, kLoong64BitcastLD, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitBitcastInt64ToFloat64(node_t node) {
  VisitRR(this, kLoong64BitcastLD, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Add(node_t node) {
  VisitRRR(this, kLoong64Float32Add, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Add(node_t node) {
  VisitRRR(this, kLoong64Float64Add, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Sub(node_t node) {
  VisitRRR(this, kLoong64Float32Sub, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Sub(node_t node) {
  VisitRRR(this, kLoong64Float64Sub, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Mul(node_t node) {
  VisitRRR(this, kLoong64Float32Mul, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Mul(node_t node) {
  VisitRRR(this, kLoong64Float64Mul, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Div(node_t node) {
  VisitRRR(this, kLoong64Float32Div, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Div(node_t node) {
  VisitRRR(this, kLoong64Float64Div, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Mod(node_t node) {
  Loong64OperandGeneratorT<Adapter> g(this);
  Emit(kLoong64Float64Mod, g.DefineAsFixed(node, f0),
       g.UseFixed(this->input_at(node, 0), f0),
       g.UseFixed(this->input_at(node, 1), f1))
      ->MarkAsCall();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Max(node_t node) {
  VisitRRR(this, kLoong64Float32Max, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Max(node_t node) {
  VisitRRR(this, kLoong64Float64Max, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Min(node_t node) {
  VisitRRR(this, kLoong64Float32Min, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Min(node_t node) {
  VisitRRR(this, kLoong64Float64Min, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Abs(node_t node) {
  VisitRR(this, kLoong64Float32Abs, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Abs(node_t node) {
  VisitRR(this, kLoong64Float64Abs, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Sqrt(node_t node) {
  VisitRR(this, kLoong64Float32Sqrt, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Sqrt(node_t node) {
  VisitRR(this, kLoong64Float64Sqrt, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32RoundDown(node_t node) {
  VisitRR(this, kLoong64Float32RoundDown, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64RoundDown(node_t node) {
  VisitRR(this, kLoong64Float64RoundDown, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32RoundUp(node_t node) {
  VisitRR(this, kLoong64Float32RoundUp, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64RoundUp(node_t node) {
  VisitRR(this, kLoong64Float64RoundUp, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32RoundTruncate(node_t node) {
  VisitRR(this, kLoong64Float32RoundTruncate, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64RoundTruncate(node_t node) {
  VisitRR(this, kLoong64Float64RoundTruncate, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64RoundTiesAway(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32RoundTiesEven(node_t node) {
  VisitRR(this, kLoong64Float32RoundTiesEven, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64RoundTiesEven(node_t node) {
  VisitRR(this, kLoong64Float64RoundTiesEven, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Neg(node_t node) {
  VisitRR(this, kLoong64Float32Neg, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Neg(node_t node) {
  VisitRR(this, kLoong64Float64Neg, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Ieee754Binop(
    node_t node, InstructionCode opcode) {
  Loong64OperandGeneratorT<Adapter> g(this);
  Emit(opcode, g.DefineAsFixed(node, f0),
       g.UseFixed(this->input_at(node, 0), f0),
       g.UseFixed(this->input_at(node, 1), f1))
      ->MarkAsCall();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Ieee754Unop(
    node_t node, InstructionCode opcode) {
  Loong64OperandGeneratorT<Adapter> g(this);
  Emit(opcode, g.DefineAsFixed(node, f0),
       g.UseFixed(this->input_at(node, 0), f0))
      ->MarkAsCall();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::EmitMoveParamToFPR(node_t node,
                                                       int32_t index) {
  if constexpr (Adapter::IsTurboshaft) {
    UNIMPLEMENTED();
  } else {
    OperandGenerator g(this);
    int count = linkage()->GetParameterLocation(index).GetLocation();
    InstructionOperand out_op = g.TempRegister(-count);
    Emit(kArchNop, out_op);
    Emit(kLoong64BitcastLD, g.DefineAsRegister(node), out_op);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::EmitMoveFPRToParam(
    InstructionOperand* op, LinkageLocation location) {
  OperandGenerator g(this);
  int count = location.GetLocation();
  InstructionOperand new_op = g.TempRegister(-count);
  Emit(kLoong64BitcastDL, new_op, *op);
  *op = new_op;
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::EmitPrepareArguments(
    ZoneVector<PushParameter>* arguments, const CallDescriptor* call_descriptor,
    node_t node) {
    Loong64OperandGeneratorT<Adapter> g(this);

    // Prepare for C function call.
    if (call_descriptor->IsCFunctionCall()) {
      int gp_param_count =
          static_cast<int>(call_descriptor->GPParameterCount());
      int fp_param_count =
          static_cast<int>(call_descriptor->FPParameterCount());
      Emit(kArchPrepareCallCFunction | ParamField::encode(gp_param_count) |
               FPParamField::encode(fp_param_count),
           0, nullptr, 0, nullptr);

      // Poke any stack arguments.
      int slot = 0;
      for (PushParameter input : (*arguments)) {
        Emit(kLoong64Poke, g.NoOutput(), g.UseRegister(input.node),
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
        Emit(kLoong64StackClaim, g.NoOutput(),
             g.TempImmediate(stack_size << kSystemPointerSizeLog2));
      }
      for (size_t n = 0; n < arguments->size(); ++n) {
        PushParameter input = (*arguments)[n];
        if (this->valid(input.node)) {
          Emit(kLoong64Poke, g.NoOutput(), g.UseRegister(input.node),
               g.TempImmediate(static_cast<int>(n << kSystemPointerSizeLog2)));
        }
      }
    }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::EmitPrepareResults(
    ZoneVector<PushParameter>* results, const CallDescriptor* call_descriptor,
    node_t node) {
  Loong64OperandGeneratorT<Adapter> g(this);

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
        abort();
      }
      int offset = call_descriptor->GetOffsetToReturns();
      int reverse_slot = -output.location.GetLocation() - offset;
      Emit(kLoong64Peek, g.DefineAsRegister(output.node),
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
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUnalignedStore(node_t node) {
  UNREACHABLE();
}

namespace {

// Shared routine for multiple compare operations.
template <typename Adapter>
static Instruction* VisitCompare(InstructionSelectorT<Adapter>* selector,
                                 InstructionCode opcode,
                                 InstructionOperand left,
                                 InstructionOperand right,
                                 FlagsContinuationT<Adapter>* cont) {
#ifdef V8_COMPRESS_POINTERS
  if (opcode == kLoong64Cmp32) {
    Loong64OperandGeneratorT<Adapter> g(selector);
    InstructionOperand inputs[] = {left, right};
    if (right.IsImmediate()) {
      InstructionOperand temps[1] = {g.TempRegister()};
      return selector->EmitWithContinuation(opcode, 0, nullptr,
                                            arraysize(inputs), inputs,
                                            arraysize(temps), temps, cont);
    } else {
      InstructionOperand temps[2] = {g.TempRegister(), g.TempRegister()};
      return selector->EmitWithContinuation(opcode, 0, nullptr,
                                            arraysize(inputs), inputs,
                                            arraysize(temps), temps, cont);
    }
  }
#endif
  return selector->EmitWithContinuation(opcode, left, right, cont);
}

// Shared routine for multiple float32 compare operations.
template <typename Adapter>
void VisitFloat32Compare(InstructionSelectorT<Adapter>* selector,
                         typename Adapter::node_t node,
                         FlagsContinuationT<Adapter>* cont) {
  Loong64OperandGeneratorT<Adapter> g(selector);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const ComparisonOp& op = selector->Get(node).template Cast<ComparisonOp>();
    OpIndex left = op.left();
    OpIndex right = op.right();
    InstructionOperand lhs, rhs;

    lhs =
        selector->MatchZero(left) ? g.UseImmediate(left) : g.UseRegister(left);
    rhs = selector->MatchZero(right) ? g.UseImmediate(right)
                                     : g.UseRegister(right);
    VisitCompare(selector, kLoong64Float32Cmp, lhs, rhs, cont);
  } else {
    Float32BinopMatcher m(node);
    InstructionOperand lhs, rhs;

    lhs = m.left().IsZero() ? g.UseImmediate(m.left().node())
                            : g.UseRegister(m.left().node());
    rhs = m.right().IsZero() ? g.UseImmediate(m.right().node())
                             : g.UseRegister(m.right().node());
    VisitCompare(selector, kLoong64Float32Cmp, lhs, rhs, cont);
  }
}

// Shared routine for multiple float64 compare operations.
template <typename Adapter>
void VisitFloat64Compare(InstructionSelectorT<Adapter>* selector,
                         typename Adapter::node_t node,
                         FlagsContinuationT<Adapter>* cont) {
  if constexpr (Adapter::IsTurboshaft) {
    Loong64OperandGeneratorT<Adapter> g(selector);
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const Operation& compare = selector->Get(node);
    DCHECK(compare.Is<ComparisonOp>());
    OpIndex lhs = compare.input(0);
    OpIndex rhs = compare.input(1);
    if (selector->MatchZero(rhs)) {
      VisitCompare(selector, kLoong64Float64Cmp, g.UseRegister(lhs),
                   g.UseImmediate(rhs), cont);
    } else if (selector->MatchZero(lhs)) {
      VisitCompare(selector, kLoong64Float64Cmp, g.UseImmediate(lhs),
                   g.UseRegister(rhs), cont);
    } else {
      VisitCompare(selector, kLoong64Float64Cmp, g.UseRegister(lhs),
                   g.UseRegister(rhs), cont);
    }
  } else {
    Loong64OperandGeneratorT<Adapter> g(selector);
    Float64BinopMatcher m(node);
    InstructionOperand lhs, rhs;

    lhs = m.left().IsZero() ? g.UseImmediate(m.left().node())
                            : g.UseRegister(m.left().node());
    rhs = m.right().IsZero() ? g.UseImmediate(m.right().node())
                             : g.UseRegister(m.right().node());
    VisitCompare(selector, kLoong64Float64Cmp, lhs, rhs, cont);
  }
}

// Shared routine for multiple word compare operations.
template <typename Adapter>
void VisitWordCompare(InstructionSelectorT<Adapter>* selector,
                      typename Adapter::node_t node, InstructionCode opcode,
                      FlagsContinuationT<Adapter>* cont, bool commutative) {
  Loong64OperandGeneratorT<Adapter> g(selector);
  DCHECK_EQ(selector->value_input_count(node), 2);
  auto left = selector->input_at(node, 0);
  auto right = selector->input_at(node, 1);

  // Match immediates on left or right side of comparison.
  if (g.CanBeImmediate(right, opcode)) {
    if (opcode == kLoong64Tst) {
      if constexpr (Adapter::IsTurbofan) {
        if (left->opcode() == IrOpcode::kTruncateInt64ToInt32) {
          VisitCompare(selector, opcode,
                       g.UseRegister(selector->input_at(left, 0)),
                       g.UseImmediate(right), cont);
          return;
        }
      }

      VisitCompare(selector, opcode, g.UseRegister(left), g.UseImmediate(right),
                   cont);
    } else {
      switch (cont->condition()) {
        case kEqual:
        case kNotEqual:
          if (cont->IsSet()) {
            VisitCompare(selector, opcode, g.UseUniqueRegister(left),
                         g.UseImmediate(right), cont);
          } else {
            VisitCompare(selector, opcode, g.UseUniqueRegister(left),
                         g.UseImmediate(right), cont);
          }
          break;
        case kSignedLessThan:
        case kSignedGreaterThanOrEqual:
        case kSignedLessThanOrEqual:
        case kSignedGreaterThan:
        case kUnsignedLessThan:
        case kUnsignedGreaterThanOrEqual:
        case kUnsignedLessThanOrEqual:
        case kUnsignedGreaterThan:
          VisitCompare(selector, opcode, g.UseUniqueRegister(left),
                       g.UseImmediate(right), cont);
          break;
        default:
          UNREACHABLE();
      }
    }
  } else if (g.CanBeImmediate(left, opcode)) {
    if (!commutative) cont->Commute();
    if (opcode == kLoong64Tst) {
      VisitCompare(selector, opcode, g.UseRegister(right), g.UseImmediate(left),
                   cont);
    } else {
      switch (cont->condition()) {
        case kEqual:
        case kNotEqual:
          if (cont->IsSet()) {
            VisitCompare(selector, opcode, g.UseUniqueRegister(right),
                         g.UseImmediate(left), cont);
          } else {
            VisitCompare(selector, opcode, g.UseUniqueRegister(right),
                         g.UseImmediate(left), cont);
          }
          break;
        case kSignedLessThan:
        case kSignedGreaterThanOrEqual:
        case kSignedLessThanOrEqual:
        case kSignedGreaterThan:
        case kUnsignedLessThan:
        case kUnsignedGreaterThanOrEqual:
        case kUnsignedLessThanOrEqual:
        case kUnsignedGreaterThan:
          VisitCompare(selector, opcode, g.UseUniqueRegister(right),
                       g.UseImmediate(left), cont);
          break;
        default:
          UNREACHABLE();
      }
    }
  } else {
    VisitCompare(selector, opcode, g.UseUniqueRegister(left),
                 g.UseUniqueRegister(right), cont);
  }
}

template <typename Adapter>
void VisitOptimizedWord32Compare(InstructionSelectorT<Adapter>* selector,
                                 Node* node, InstructionCode opcode,
                                 FlagsContinuationT<Adapter>* cont) {
  // TODO(LOONG_dev): LOONG64 Add check for debug mode
  VisitWordCompare(selector, node, opcode, cont, false);
}

// Shared routine for multiple word compare operations.
template <typename Adapter>
void VisitFullWord32Compare(InstructionSelectorT<Adapter>* selector,
                            typename Adapter::node_t node,
                            InstructionCode opcode,
                            FlagsContinuationT<Adapter>* cont) {
  Loong64OperandGeneratorT<Adapter> g(selector);
  InstructionOperand leftOp = g.TempRegister();
  InstructionOperand rightOp = g.TempRegister();

  selector->Emit(kLoong64Sll_d, leftOp,
                 g.UseRegister(selector->input_at(node, 0)),
                 g.TempImmediate(32));
  selector->Emit(kLoong64Sll_d, rightOp,
                 g.UseRegister(selector->input_at(node, 1)),
                 g.TempImmediate(32));

  Instruction* instr = VisitCompare(selector, opcode, leftOp, rightOp, cont);
  if constexpr (Adapter::IsTurboshaft) {
    selector->UpdateSourcePosition(instr, node);
  }
}

template <typename Adapter>
void VisitWord32Compare(InstructionSelectorT<Adapter>* selector,
                        typename Adapter::node_t node,
                        FlagsContinuationT<Adapter>* cont) {
  if constexpr (Adapter::IsTurboshaft) {
    VisitFullWord32Compare(selector, node, kLoong64Cmp64, cont);
  } else {
    // LOONG64 doesn't support Word32 compare instructions. Instead it relies
    // that the values in registers are correctly sign-extended and uses
    // Word64 comparison instead.
#ifdef USE_SIMULATOR
    // When call to a host function in simulator, if the function return a
    // int32 value, the simulator do not sign-extended to int64 because in
    // simulator we do not know the function whether return an int32 or int64.
    // so we need do a full word32 compare in this case.
    if (node->InputAt(0)->opcode() == IrOpcode::kCall ||
        node->InputAt(1)->opcode() == IrOpcode::kCall) {
      VisitFullWord32Compare(selector, node, kLoong64Cmp64, cont);
      return;
    }
#endif
    VisitOptimizedWord32Compare(selector, node, kLoong64Cmp32, cont);
  }
}

template <typename Adapter>
void VisitWord64Compare(InstructionSelectorT<Adapter>* selector,
                        typename Adapter::node_t node,
                        FlagsContinuationT<Adapter>* cont) {
  VisitWordCompare(selector, node, kLoong64Cmp64, cont, false);
}

template <typename Adapter>
void VisitAtomicLoad(InstructionSelectorT<Adapter>* selector,
                     typename Adapter::node_t node, AtomicWidth width) {
  using node_t = typename Adapter::node_t;
  Loong64OperandGeneratorT<Adapter> g(selector);
  auto load = selector->load_view(node);
  node_t base = load.base();
  node_t index = load.index();

  // The memory order is ignored.
  LoadRepresentation load_rep = load.loaded_rep();
  InstructionCode code;
  switch (load_rep.representation()) {
    case MachineRepresentation::kWord8:
      DCHECK_IMPLIES(load_rep.IsSigned(), width == AtomicWidth::kWord32);
      code = load_rep.IsSigned() ? kAtomicLoadInt8 : kAtomicLoadUint8;
      break;
    case MachineRepresentation::kWord16:
      DCHECK_IMPLIES(load_rep.IsSigned(), width == AtomicWidth::kWord32);
      code = load_rep.IsSigned() ? kAtomicLoadInt16 : kAtomicLoadUint16;
      break;
    case MachineRepresentation::kWord32:
      code = (width == AtomicWidth::kWord32) ? kAtomicLoadWord32
                                             : kLoong64Word64AtomicLoadUint32;
      break;
    case MachineRepresentation::kWord64:
      code = kLoong64Word64AtomicLoadUint64;
      break;
#ifdef V8_COMPRESS_POINTERS
    case MachineRepresentation::kTaggedSigned:
      code = kLoong64AtomicLoadDecompressTaggedSigned;
      break;
    case MachineRepresentation::kTaggedPointer:
    case MachineRepresentation::kTagged:
      code = kLoong64AtomicLoadDecompressTagged;
      break;
#else
    case MachineRepresentation::kTaggedSigned:   // Fall through.
    case MachineRepresentation::kTaggedPointer:  // Fall through.
    case MachineRepresentation::kTagged:
      code = kLoong64Word64AtomicLoadUint64;
      break;
#endif
    case MachineRepresentation::kCompressedPointer:  // Fall through.
    case MachineRepresentation::kCompressed:
      DCHECK(COMPRESS_POINTERS_BOOL);
      code = kLoong64Word64AtomicLoadUint32;
      break;
    default:
      UNREACHABLE();
  }

  bool traps_on_null;
  if (load.is_protected(&traps_on_null)) {
    // Atomic loads and null dereference are mutually exclusive. This might
    // change with multi-threaded wasm-gc in which case the access mode should
    // probably be kMemoryAccessProtectedNullDereference.
    DCHECK(!traps_on_null);
    code |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
  }

  if (g.CanBeImmediate(index, code)) {
    selector->Emit(code | AddressingModeField::encode(kMode_MRI) |
                       AtomicWidthField::encode(width),
                   g.DefineAsRegister(node), g.UseRegister(base),
                   g.UseImmediate(index));
  } else {
    selector->Emit(code | AddressingModeField::encode(kMode_MRR) |
                       AtomicWidthField::encode(width),
                   g.DefineAsRegister(node), g.UseRegister(base),
                   g.UseRegister(index));
  }
}

template <typename Adapter>
AtomicStoreParameters AtomicStoreParametersOf(
    InstructionSelectorT<Adapter>* selector, typename Adapter::node_t node) {
  auto store = selector->store_view(node);
  return AtomicStoreParameters(store.stored_rep().representation(),
                               store.stored_rep().write_barrier_kind(),
                               store.memory_order().value(),
                               store.access_kind());
}

template <typename Adapter>
void VisitAtomicStore(InstructionSelectorT<Adapter>* selector,
                      typename Adapter::node_t node, AtomicWidth width) {
  using node_t = typename Adapter::node_t;
  Loong64OperandGeneratorT<Adapter> g(selector);
  auto store = selector->store_view(node);
  node_t base = store.base();
  node_t index = selector->value(store.index());
  node_t value = store.value();
  DCHECK_EQ(store.displacement(), 0);

  // The memory order is ignored.
  AtomicStoreParameters store_params = AtomicStoreParametersOf(selector, node);
  WriteBarrierKind write_barrier_kind = store_params.write_barrier_kind();
  MachineRepresentation rep = store_params.representation();

  if (v8_flags.enable_unconditional_write_barriers &&
      CanBeTaggedOrCompressedPointer(rep)) {
    write_barrier_kind = kFullWriteBarrier;
  }

  InstructionCode code;

  if (write_barrier_kind != kNoWriteBarrier &&
      !v8_flags.disable_write_barriers) {
    DCHECK(CanBeTaggedPointer(rep));
    DCHECK_EQ(kTaggedSize, 8);

    RecordWriteMode record_write_mode =
        WriteBarrierKindToRecordWriteMode(write_barrier_kind);
    code = kArchAtomicStoreWithWriteBarrier;
    code |= RecordWriteModeField::encode(record_write_mode);
  } else {
    switch (rep) {
      case MachineRepresentation::kWord8:
        code = kAtomicStoreWord8;
        break;
      case MachineRepresentation::kWord16:
        code = kAtomicStoreWord16;
        break;
      case MachineRepresentation::kWord32:
        code = kAtomicStoreWord32;
        break;
      case MachineRepresentation::kWord64:
        DCHECK_EQ(width, AtomicWidth::kWord64);
        code = kLoong64Word64AtomicStoreWord64;
        break;
      case MachineRepresentation::kTaggedSigned:   // Fall through.
      case MachineRepresentation::kTaggedPointer:  // Fall through.
      case MachineRepresentation::kTagged:
        DCHECK_EQ(AtomicWidthSize(width), kTaggedSize);
        code = kLoong64AtomicStoreCompressTagged;
        break;
      case MachineRepresentation::kCompressedPointer:  // Fall through.
      case MachineRepresentation::kCompressed:
        DCHECK(COMPRESS_POINTERS_BOOL);
        DCHECK_EQ(width, AtomicWidth::kWord32);
        code = kLoong64AtomicStoreCompressTagged;
        break;
      default:
        UNREACHABLE();
    }
  }

  if (store_params.kind() == MemoryAccessKind::kProtectedByTrapHandler) {
    code |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
  }

  if (g.CanBeImmediate(index, code)) {
    selector->Emit(code | AddressingModeField::encode(kMode_MRI) |
                       AtomicWidthField::encode(width),
                   g.NoOutput(), g.UseRegister(base), g.UseImmediate(index),
                   g.UseRegisterOrImmediateZero(value));
  } else {
    selector->Emit(code | AddressingModeField::encode(kMode_MRR) |
                       AtomicWidthField::encode(width),
                   g.NoOutput(), g.UseRegister(base), g.UseRegister(index),
                   g.UseRegisterOrImmediateZero(value));
  }
}

template <typename Adapter>
void VisitAtomicExchange(InstructionSelectorT<Adapter>* selector,
                         typename Adapter::node_t node, ArchOpcode opcode,
                         AtomicWidth width, MemoryAccessKind access_kind) {
  using node_t = typename Adapter::node_t;
  Loong64OperandGeneratorT<Adapter> g(selector);
  auto atomic_op = selector->atomic_rmw_view(node);
  node_t base = atomic_op.base();
  node_t index = atomic_op.index();
  node_t value = atomic_op.value();

  AddressingMode addressing_mode = kMode_MRI;
  InstructionOperand inputs[3];
  size_t input_count = 0;
  inputs[input_count++] = g.UseUniqueRegister(base);
  inputs[input_count++] = g.UseUniqueRegister(index);
  inputs[input_count++] = g.UseUniqueRegister(value);
  InstructionOperand outputs[1];
  outputs[0] = g.UseUniqueRegister(node);
  InstructionOperand temp[3];
  temp[0] = g.TempRegister();
  temp[1] = g.TempRegister();
  temp[2] = g.TempRegister();
  InstructionCode code = opcode | AddressingModeField::encode(addressing_mode) |
                         AtomicWidthField::encode(width);
  if (access_kind == MemoryAccessKind::kProtectedByTrapHandler) {
    code |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
  }
  selector->Emit(code, 1, outputs, input_count, inputs, 3, temp);
}

template <typename Adapter>
void VisitAtomicCompareExchange(InstructionSelectorT<Adapter>* selector,
                                typename Adapter::node_t node,
                                ArchOpcode opcode, AtomicWidth width,
                                MemoryAccessKind access_kind) {
  using node_t = typename Adapter::node_t;
  Loong64OperandGeneratorT<Adapter> g(selector);
  auto atomic_op = selector->atomic_rmw_view(node);
  node_t base = atomic_op.base();
  node_t index = atomic_op.index();
  node_t old_value = atomic_op.expected();
  node_t new_value = atomic_op.value();

  AddressingMode addressing_mode = kMode_MRI;
  InstructionOperand inputs[4];
  size_t input_count = 0;
  inputs[input_count++] = g.UseUniqueRegister(base);
  inputs[input_count++] = g.UseUniqueRegister(index);
  inputs[input_count++] = g.UseUniqueRegister(old_value);
  inputs[input_count++] = g.UseUniqueRegister(new_value);
  InstructionOperand outputs[1];
  outputs[0] = g.UseUniqueRegister(node);
  InstructionOperand temp[3];
  temp[0] = g.TempRegister();
  temp[1] = g.TempRegister();
  temp[2] = g.TempRegister();
  InstructionCode code = opcode | AddressingModeField::encode(addressing_mode) |
                         AtomicWidthField::encode(width);
  if (access_kind == MemoryAccessKind::kProtectedByTrapHandler) {
    code |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
  }
  selector->Emit(code, 1, outputs, input_count, inputs, 3, temp);
}

template <typename Adapter>
void VisitAtomicBinop(InstructionSelectorT<Adapter>* selector,
                      typename Adapter::node_t node, ArchOpcode opcode,
                      AtomicWidth width, MemoryAccessKind access_kind) {
  using node_t = typename Adapter::node_t;
  Loong64OperandGeneratorT<Adapter> g(selector);
  auto atomic_op = selector->atomic_rmw_view(node);
  node_t base = atomic_op.base();
  node_t index = atomic_op.index();
  node_t value = atomic_op.value();

  AddressingMode addressing_mode = kMode_MRI;
  InstructionOperand inputs[3];
  size_t input_count = 0;
  inputs[input_count++] = g.UseUniqueRegister(base);
  inputs[input_count++] = g.UseUniqueRegister(index);
  inputs[input_count++] = g.UseUniqueRegister(value);
  InstructionOperand outputs[1];
  outputs[0] = g.UseUniqueRegister(node);
  InstructionOperand temps[4];
  temps[0] = g.TempRegister();
  temps[1] = g.TempRegister();
  temps[2] = g.TempRegister();
  temps[3] = g.TempRegister();
  InstructionCode code = opcode | AddressingModeField::encode(addressing_mode) |
                         AtomicWidthField::encode(width);
  if (access_kind == MemoryAccessKind::kProtectedByTrapHandler) {
    code |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
  }
  selector->Emit(code, 1, outputs, input_count, inputs, 4, temps);
}

}  // namespace

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitStackPointerGreaterThan(
    node_t node, FlagsContinuationT<Adapter>* cont) {
  StackCheckKind kind;
  node_t value;
  if constexpr (Adapter::IsTurboshaft) {
    const auto& op =
        this->turboshaft_graph()
            ->Get(node)
            .template Cast<turboshaft::StackPointerGreaterThanOp>();
    kind = op.kind;
    value = op.stack_limit();
  } else {
    kind = StackCheckKindOf(node->op());
    value = node->InputAt(0);
  }
  InstructionCode opcode =
      kArchStackPointerGreaterThan | MiscField::encode(static_cast<int>(kind));

  Loong64OperandGeneratorT<Adapter> g(this);

  // No outputs.
  InstructionOperand* const outputs = nullptr;
  const int output_count = 0;

  // TempRegister(0) is used to store the comparison result.
  // Applying an offset to this stack check requires a temp register. Offsets
  // are only applied to the first stack check. If applying an offset, we must
  // ensure the input and temp registers do not alias, thus kUniqueRegister.
  InstructionOperand temps[] = {g.TempRegister(), g.TempRegister()};
  const int temp_count = (kind == StackCheckKind::kJSFunctionEntry ? 2 : 1);
  const auto register_mode = (kind == StackCheckKind::kJSFunctionEntry)
                                 ? OperandGenerator::kUniqueRegister
                                 : OperandGenerator::kRegister;

  InstructionOperand inputs[] = {g.UseRegisterWithMode(value, register_mode)};
  static constexpr int input_count = arraysize(inputs);

  EmitWithContinuation(opcode, output_count, outputs, input_count, inputs,
                       temp_count, temps, cont);
}

// Shared routine for word comparisons against zero.
template <>
void InstructionSelectorT<TurbofanAdapter>::VisitWordCompareZero(
    node_t user, node_t value, FlagsContinuation* cont) {
  {
    Loong64OperandGeneratorT<TurbofanAdapter> g(this);
    // Try to combine with comparisons against 0 by simply inverting the branch.
    while (value->opcode() == IrOpcode::kWord32Equal && CanCover(user, value)) {
      Int32BinopMatcher m(value);
      if (!m.right().Is(0)) break;
      user = value;
      value = m.left().node();
      cont->Negate();
    }

    if (CanCover(user, value)) {
      switch (value->opcode()) {
        case IrOpcode::kWord32Equal:
          cont->OverwriteAndNegateIfEqual(kEqual);
          return VisitWord32Compare(this, value, cont);
        case IrOpcode::kInt32LessThan:
          cont->OverwriteAndNegateIfEqual(kSignedLessThan);
          return VisitWord32Compare(this, value, cont);
        case IrOpcode::kInt32LessThanOrEqual:
          cont->OverwriteAndNegateIfEqual(kSignedLessThanOrEqual);
          return VisitWord32Compare(this, value, cont);
        case IrOpcode::kUint32LessThan:
          cont->OverwriteAndNegateIfEqual(kUnsignedLessThan);
          return VisitWord32Compare(this, value, cont);
        case IrOpcode::kUint32LessThanOrEqual:
          cont->OverwriteAndNegateIfEqual(kUnsignedLessThanOrEqual);
          return VisitWord32Compare(this, value, cont);
        case IrOpcode::kWord64Equal:
          cont->OverwriteAndNegateIfEqual(kEqual);
          return VisitWord64Compare(this, value, cont);
        case IrOpcode::kInt64LessThan:
          cont->OverwriteAndNegateIfEqual(kSignedLessThan);
          return VisitWord64Compare(this, value, cont);
        case IrOpcode::kInt64LessThanOrEqual:
          cont->OverwriteAndNegateIfEqual(kSignedLessThanOrEqual);
          return VisitWord64Compare(this, value, cont);
        case IrOpcode::kUint64LessThan:
          cont->OverwriteAndNegateIfEqual(kUnsignedLessThan);
          return VisitWord64Compare(this, value, cont);
        case IrOpcode::kUint64LessThanOrEqual:
          cont->OverwriteAndNegateIfEqual(kUnsignedLessThanOrEqual);
          return VisitWord64Compare(this, value, cont);
        case IrOpcode::kFloat32Equal:
          cont->OverwriteAndNegateIfEqual(kEqual);
          return VisitFloat32Compare(this, value, cont);
        case IrOpcode::kFloat32LessThan:
          cont->OverwriteAndNegateIfEqual(kUnsignedLessThan);
          return VisitFloat32Compare(this, value, cont);
        case IrOpcode::kFloat32LessThanOrEqual:
          cont->OverwriteAndNegateIfEqual(kUnsignedLessThanOrEqual);
          return VisitFloat32Compare(this, value, cont);
        case IrOpcode::kFloat64Equal:
          cont->OverwriteAndNegateIfEqual(kEqual);
          return VisitFloat64Compare(this, value, cont);
        case IrOpcode::kFloat64LessThan:
          cont->OverwriteAndNegateIfEqual(kUnsignedLessThan);
          return VisitFloat64Compare(this, value, cont);
        case IrOpcode::kFloat64LessThanOrEqual:
          cont->OverwriteAndNegateIfEqual(kUnsignedLessThanOrEqual);
          return VisitFloat64Compare(this, value, cont);
        case IrOpcode::kProjection:
          // Check if this is the overflow output projection of an
          // <Operation>WithOverflow node.
          if (ProjectionIndexOf(value->op()) == 1u) {
            // We cannot combine the <Operation>WithOverflow with this branch
            // unless the 0th projection (the use of the actual value of the
            // <Operation> is either nullptr, which means there's no use of the
            // actual value, or was already defined, which means it is scheduled
            // *AFTER* this branch).
            Node* const node = value->InputAt(0);
            Node* const result = NodeProperties::FindProjection(node, 0);
            if (result == nullptr || IsDefined(result)) {
              switch (node->opcode()) {
                case IrOpcode::kInt32AddWithOverflow:
                  cont->OverwriteAndNegateIfEqual(kOverflow);
                  return VisitBinop(this, node, kLoong64Add_d, cont);
                case IrOpcode::kInt32SubWithOverflow:
                  cont->OverwriteAndNegateIfEqual(kOverflow);
                  return VisitBinop(this, node, kLoong64Sub_d, cont);
                case IrOpcode::kInt32MulWithOverflow:
                  cont->OverwriteAndNegateIfEqual(kOverflow);
                  return VisitBinop(this, node, kLoong64MulOvf_w, cont);
                case IrOpcode::kInt64MulWithOverflow:
                  cont->OverwriteAndNegateIfEqual(kOverflow);
                  return VisitBinop(this, node, kLoong64MulOvf_d, cont);
                case IrOpcode::kInt64AddWithOverflow:
                  cont->OverwriteAndNegateIfEqual(kOverflow);
                  return VisitBinop(this, node, kLoong64AddOvf_d, cont);
                case IrOpcode::kInt64SubWithOverflow:
                  cont->OverwriteAndNegateIfEqual(kOverflow);
                  return VisitBinop(this, node, kLoong64SubOvf_d, cont);
                default:
                  break;
              }
            }
          }
          break;
        case IrOpcode::kWord32And:
        case IrOpcode::kWord64And:
          return VisitWordCompare(this, value, kLoong64Tst, cont, true);
        case IrOpcode::kStackPointerGreaterThan:
          cont->OverwriteAndNegateIfEqual(kStackPointerGreaterThanCondition);
          return VisitStackPointerGreaterThan(value, cont);
        default:
          break;
      }
    }

    // Continuation could not be combined with a compare, emit compare against
    // 0.
    VisitCompare(this, kLoong64Cmp32, g.UseRegister(value), g.TempImmediate(0),
                 cont);
  }
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWordCompareZero(
    node_t user, node_t value, FlagsContinuation* cont) {
  {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    Loong64OperandGeneratorT<TurboshaftAdapter> g(this);
    // Try to combine with comparisons against 0 by simply inverting the branch.
    while (const ComparisonOp* equal =
               this->TryCast<Opmask::kWord32Equal>(value)) {
      if (!CanCover(user, value)) break;
      if (!MatchIntegralZero(equal->right())) break;
      user = value;
      value = equal->left();
      cont->Negate();
    }

    const Operation& value_op = Get(value);
    if (CanCover(user, value)) {
      if (const ComparisonOp* comparison = value_op.TryCast<ComparisonOp>()) {
        switch (comparison->rep.value()) {
          case RegisterRepresentation::Word32():
            cont->OverwriteAndNegateIfEqual(
                GetComparisonFlagCondition(*comparison));
            return VisitWord32Compare(this, value, cont);

          case RegisterRepresentation::Word64():
            cont->OverwriteAndNegateIfEqual(
                GetComparisonFlagCondition(*comparison));
            return VisitWord64Compare(this, value, cont);

          case RegisterRepresentation::Float32():
            switch (comparison->kind) {
              case ComparisonOp::Kind::kEqual:
                cont->OverwriteAndNegateIfEqual(kEqual);
                return VisitFloat32Compare(this, value, cont);
              case ComparisonOp::Kind::kSignedLessThan:
                cont->OverwriteAndNegateIfEqual(kFloatLessThan);
                return VisitFloat32Compare(this, value, cont);
              case ComparisonOp::Kind::kSignedLessThanOrEqual:
                cont->OverwriteAndNegateIfEqual(kFloatLessThanOrEqual);
                return VisitFloat32Compare(this, value, cont);
              default:
                UNREACHABLE();
            }
"""


```