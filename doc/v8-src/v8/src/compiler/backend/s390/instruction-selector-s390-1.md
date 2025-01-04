Response: The user wants a summary of the functionality of the provided C++ code snippet. This is the second part of a three-part file.

The code seems to be part of an instruction selector for the S390 architecture within the V8 JavaScript engine. It defines how high-level operations are translated into specific S390 assembly instructions.

Specifically, this part focuses on:

1. **Handling bitwise operations:**  `Word64Shl`, `Word64Shr`. It seems to have optimizations for specific patterns involving shifts and bitwise ANDs, potentially translating them into efficient `RotLeftAndClear` instructions.
2. **Sign extension:** `TryMatchSignExtInt16OrInt8FromWord32Sar`. It attempts to identify sequences of shift left and arithmetic shift right to perform sign extension using dedicated instructions.
3. **Unimplemented bitwise operations:** `Word32Rol`, `Word64Rol`, `Word32Ctz`, `Word64Ctz`, `Word32ReverseBits`, `Word64ReverseBits`. These indicate that these specific bitwise operations might not be directly supported or optimized in this instruction selector.
4. **Absolute value:** `Int32AbsWithOverflow`, `Int64AbsWithOverflow`. It uses dedicated absolute value instructions.
5. **Byte reversal:** `Word64ReverseBytes`, `Word32ReverseBytes`, `Simd128ReverseBytes`. It uses dedicated byte reversal instructions, potentially optimizing for load operations.
6. **Negation:** `TryMatchNegFromSub`. It tries to recognize negation patterns from subtraction with zero and uses dedicated negation instructions.
7. **Shift from multiplication:** `TryMatchShiftFromMul`. It optimizes multiplication by a power of two into a shift operation.
8. **Operations with overflow:** `TryMatchInt32AddWithOverflow`, `TryMatchInt32SubWithOverflow`, `TryMatchInt32MulWithOverflow`, `TryMatchInt64AddWithOverflow`, `TryMatchInt64SubWithOverflow`. It handles operations that can potentially overflow, using conditional flags and potentially different instruction sequences depending on CPU features.
9. **Double construction:** `TryMatchDoubleConstructFromInsert`. It attempts to recognize patterns of inserting low and high words into a double to create a double value using a specific instruction.
10. **A large number of unary and binary operations:** It defines `FLOAT_UNARY_OP_LIST`, `FLOAT_BIN_OP_LIST`, `WORD32_UNARY_OP_LIST`, `WORD32_BIN_OP_LIST`, `WORD64_UNARY_OP_LIST`, and `WORD64_BIN_OP_LIST`. These lists map high-level operations to their corresponding S390 instructions.
11. **Try truncate operations:** It handles operations that attempt to truncate floating-point numbers to integers.
12. **Bitcast:** `VisitBitcastWord32ToWord64`. It handles bitwise casting between integer types.
13. **Modulo operation:** `VisitFloat64Mod`. It uses a specific instruction for floating-point modulo.
14. **IEEE 754 operations:** `VisitFloat64Ieee754Unop`, `VisitFloat64Ieee754Binop`. It handles IEEE 754 compliant floating-point operations, potentially marking them as calls.
15. **Multiplication with overflow:** `VisitInt64MulWithOverflow`. It handles 64-bit multiplication that can overflow.
16. **Comparison operations:** It defines helper functions `VisitCompare`, `VisitWordCompare`, `VisitFloat32Compare`, `VisitFloat64Compare`, `VisitTestUnderMask`, and `VisitLoadAndTest` for handling various comparison operations, potentially optimizing for comparisons with zero and leveraging load-and-test instructions.
17. **Comparison against zero:** `VisitWordCompareZero`. It has specific logic for optimizing comparisons against zero, attempting to combine the comparison with preceding operations like subtraction or bitwise AND.

Considering the JavaScript context, the code is crucial for the performance of JavaScript code execution on S390 architecture. It ensures that JavaScript operations are translated into the most efficient S390 machine code.
这是 `v8/src/compiler/backend/s390/instruction-selector-s390.cc` 文件的第二部分，主要负责将 **中间表示（Intermediate Representation, IR）的节点** 转换为 **S390 汇编指令**。

具体来说，这部分代码继续实现了 `InstructionSelectorT` 类的成员函数，这些函数对应着不同的 IR 节点类型，并定义了如何为这些节点选择合适的 S390 指令。

以下是一些关键功能点的总结：

1. **处理位移操作的优化:**  `VisitWord64Shl` 和 `VisitWord64Shr` 函数尝试匹配特定的位移和按位与操作组合，并将其优化为更高效的 `kS390_RotLeftAndClearLeft64` 或 `kS390_RotLeftAndClearRight64` 指令。这是一种针对特定掩码和位移场景的优化。

2. **识别并优化符号扩展:** `TryMatchSignExtInt16OrInt8FromWord32Sar` 函数尝试识别由左移和算术右移组成的模式，这通常用于从 32 位值中提取并进行 8 位或 16 位有符号扩展。如果匹配成功，它会使用专门的符号扩展指令 `kS390_SignExtendWord16ToInt32` 或 `kS390_SignExtendWord8ToInt32`。

3. **处理未实现的位运算:**  `VisitWord32Rol`, `VisitWord64Rol`, `VisitWord32Ctz`, `VisitWord64Ctz`, `VisitWord32ReverseBits`, `VisitWord64ReverseBits` 函数目前抛出 `UNREACHABLE()` 异常，说明这些特定的位运算在当前的指令选择器中可能还没有直接的 S390 指令对应或优化。

4. **实现绝对值运算:** `VisitInt32AbsWithOverflow` 和 `VisitInt64AbsWithOverflow` 函数使用 `kS390_Abs32` 和 `kS390_Abs64` 指令来实现带溢出检查的绝对值运算。

5. **实现字节反转操作:** `VisitWord64ReverseBytes`, `VisitWord32ReverseBytes`, `VisitSimd128ReverseBytes` 函数使用 `kS390_LoadReverse64`, `kS390_LoadReverse32`, `kS390_LoadReverseSimd128` 指令来实现字节顺序的反转。它们还尝试针对从内存加载的情况进行优化。

6. **优化取反操作:** `TryMatchNegFromSub` 函数尝试识别从零减去一个值的模式，并将其优化为直接使用取反指令 `kS390_Neg32` 或 `kS390_Neg64`。

7. **优化乘法为移位操作:** `TryMatchShiftFromMul` 函数尝试识别乘以 2 的幂的模式，并将其优化为左移操作。

8. **处理带溢出的算术运算:**  `TryMatchInt32AddWithOverflow`, `TryMatchInt32SubWithOverflow`, `TryMatchInt32MulWithOverflow`, `TryMatchInt64AddWithOverflow`, `TryMatchInt64SubWithOverflow` 函数用于处理带溢出检查的加法、减法和乘法运算，它们会检查溢出投影节点，并根据情况选择合适的指令。

9. **构造双精度浮点数:** `TryMatchDoubleConstructFromInsert` 函数尝试识别将两个 32 位值插入到双精度浮点数的模式，并使用 `kS390_DoubleConstruct` 指令进行优化。

10. **大量的单目和双目运算的指令选择:** 代码中定义了 `FLOAT_UNARY_OP_LIST`, `FLOAT_BIN_OP_LIST`, `WORD32_UNARY_OP_LIST`, `WORD32_BIN_OP_LIST`, `WORD64_UNARY_OP_LIST`, `WORD64_BIN_OP_LIST` 宏，这些宏展开后定义了大量的 `Visit...` 函数，用于将各种 JavaScript 运算符（如加减乘除、位运算、类型转换等）映射到相应的 S390 汇编指令。

11. **处理浮点数截断操作:** `VisitTryTruncateFloat32ToInt64` 等函数处理将浮点数截断为整数的操作，并选择相应的 S390 指令。

12. **处理类型转换:** `VisitBitcastWord32ToWord64` 函数处理 32 位整数到 64 位整数的位转换。

13. **处理浮点数取模运算:** `VisitFloat64Mod` 函数使用 `kS390_ModDouble` 指令处理双精度浮点数的取模运算。

14. **处理 IEEE 754 浮点运算:** `VisitFloat64Ieee754Unop` 和 `VisitFloat64Ieee754Binop` 函数处理 IEEE 754 标准的浮点数运算。

15. **处理带溢出的 64 位乘法:** `VisitInt64MulWithOverflow` 函数处理带溢出检查的 64 位乘法。

16. **实现各种比较操作:** 代码定义了 `VisitCompare`, `VisitWordCompare`, `VisitFloat32Compare`, `VisitFloat64Compare`, `VisitTestUnderMask`, `VisitLoadAndTest` 等辅助函数，用于将 JavaScript 的比较运算符转换为 S390 的比较指令，并处理逻辑运算的短路特性。

17. **针对与零比较的优化:** `VisitWordCompareZero` 函数针对与零的比较进行了优化，尝试将比较操作与前面的运算（如减法、按位与等）合并，以减少指令数量。

**与 JavaScript 的关系：**

这段代码是 V8 JavaScript 引擎在 S390 架构上的代码生成器的核心部分。当 JavaScript 代码被编译成机器码时，指令选择器负责将 JavaScript 的高级操作（例如 `+`, `-`, `>>`, `===` 等）转换为目标架构（在这里是 S390）的底层汇编指令。

**JavaScript 示例：**

```javascript
function foo(a, b) {
  return (a >>> 2) & 0xFF; // 无符号右移和按位与
}

function bar(x) {
  return -x; // 取反
}

function baz(n) {
  return Math.abs(n); // 绝对值
}

function compare(p, q) {
  return p > q; // 比较
}

function mul_by_power_of_two(x) {
  return x * 8; // 乘以 2 的幂
}

function float_mod(a, b) {
  return a % b; // 浮点数取模
}
```

当 V8 编译 `foo` 函数时，`VisitWord32Shr` 和 `VisitWord32And` 函数（在完整代码的其他部分）可能会被调用，并且可能会应用其中的优化逻辑，将无符号右移和按位与操作转换为高效的 S390 指令。

编译 `bar` 函数时，`TryMatchNegFromSub` 可能会识别出取反的模式，并使用 `kS390_Neg32` 或 `kS390_Neg64` 指令。

编译 `baz` 函数时，`VisitInt32AbsWithOverflow` 或 `VisitFloat64Abs` 会被调用，并使用相应的绝对值指令。

编译 `compare` 函数时，`VisitWord32Compare` 或 `VisitFloat64Compare` 会被调用，生成 S390 的比较指令。

编译 `mul_by_power_of_two` 函数时，`TryMatchShiftFromMul` 可能会将乘法操作优化为左移操作。

编译 `float_mod` 函数时，`VisitFloat64Mod` 会被调用，使用特定的浮点数取模指令。

总而言之，这段代码是 V8 引擎将 JavaScript 代码高效地运行在 S390 架构上的关键组成部分，它定义了如何将高级的 JavaScript 操作转换为底层的机器指令。

Prompt: 
```
这是目录为v8/src/compiler/backend/s390/instruction-selector-s390.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
    if (mb > 63 - sh) mb = 63 - sh;
      sh = (64 - sh) & 0x3F;
      if (mb >= me) {
        bool match = false;
        ArchOpcode opcode;
        int mask;
        if (me == 0) {
          match = true;
          opcode = kS390_RotLeftAndClearLeft64;
          mask = mb;
        } else if (mb == 63) {
          match = true;
          opcode = kS390_RotLeftAndClearRight64;
          mask = me;
        }
        if (match) {
          Emit(opcode, g.DefineAsRegister(node),
               g.UseRegister(bitwise_and.left()), g.TempImmediate(sh),
               g.TempImmediate(mask));
          return;
        }
      }
    }
  }
  VisitWord64BinOp(this, node, kS390_ShiftRight64, Shift64OperandMode);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Shr(node_t node) {
    S390OperandGeneratorT<Adapter> g(this);
    Int64BinopMatcher m(node);
    if (m.left().IsWord64And() && m.right().IsInRange(0, 63)) {
      Int64BinopMatcher mleft(m.left().node());
      int sh = m.right().ResolvedValue();
      int mb;
      int me;
      if (mleft.right().HasResolvedValue() &&
          IsContiguousMask64((uint64_t)(mleft.right().ResolvedValue()) >> sh,
                             &mb, &me)) {
        // Adjust the mask such that it doesn't include any rotated bits.
        if (mb > 63 - sh) mb = 63 - sh;
        sh = (64 - sh) & 0x3F;
        if (mb >= me) {
          bool match = false;
          ArchOpcode opcode;
          int mask;
          if (me == 0) {
            match = true;
            opcode = kS390_RotLeftAndClearLeft64;
            mask = mb;
          } else if (mb == 63) {
            match = true;
            opcode = kS390_RotLeftAndClearRight64;
            mask = me;
          }
          if (match) {
            Emit(opcode, g.DefineAsRegister(node),
                 g.UseRegister(mleft.left().node()), g.TempImmediate(sh),
                 g.TempImmediate(mask));
            return;
          }
        }
      }
    }
    VisitWord64BinOp(this, node, kS390_ShiftRight64, Shift64OperandMode);
}

static inline bool TryMatchSignExtInt16OrInt8FromWord32Sar(
    InstructionSelectorT<TurboshaftAdapter>* selector,
    typename TurboshaftAdapter::node_t node) {
  S390OperandGeneratorT<TurboshaftAdapter> g(selector);

  using namespace turboshaft;  // NOLINT(build/namespaces)
  const ShiftOp& sar = selector->Get(node).template Cast<ShiftOp>();
  const Operation& lhs = selector->Get(sar.left());
  if (selector->CanCover(node, sar.left()) &&
      lhs.Is<Opmask::kWord32ShiftLeft>()) {
    const ShiftOp& shl = lhs.Cast<ShiftOp>();
    if (selector->is_integer_constant(sar.right()) &&
        selector->is_integer_constant(shl.right())) {
      uint32_t sar_by = selector->integer_constant(sar.right());
      uint32_t shl_by = selector->integer_constant(shl.right());
      if ((sar_by == shl_by) && (sar_by == 16)) {
        bool canEliminateZeroExt =
            ProduceWord32Result<TurboshaftAdapter>(selector, shl.left());
        selector->Emit(kS390_SignExtendWord16ToInt32,
                       canEliminateZeroExt ? g.DefineSameAsFirst(node)
                                           : g.DefineAsRegister(node),
                       g.UseRegister(shl.left()),
                       g.TempImmediate(!canEliminateZeroExt));
        return true;
      } else if ((sar_by == shl_by) && (sar_by == 24)) {
        bool canEliminateZeroExt =
            ProduceWord32Result<TurboshaftAdapter>(selector, shl.left());
        selector->Emit(kS390_SignExtendWord8ToInt32,
                       canEliminateZeroExt ? g.DefineSameAsFirst(node)
                                           : g.DefineAsRegister(node),
                       g.UseRegister(shl.left()),
                       g.TempImmediate(!canEliminateZeroExt));
        return true;
      }
    }
  }
  return false;
}

template <typename Adapter>
static inline bool TryMatchSignExtInt16OrInt8FromWord32Sar(
    InstructionSelectorT<Adapter>* selector, typename Adapter::node_t node) {
  S390OperandGeneratorT<Adapter> g(selector);
  Int32BinopMatcher m(node);
  if (selector->CanCover(node, m.left().node()) && m.left().IsWord32Shl()) {
    Int32BinopMatcher mleft(m.left().node());
    if (mleft.right().Is(16) && m.right().Is(16)) {
      bool canEliminateZeroExt =
          ProduceWord32Result<Adapter>(selector, mleft.left().node());
      selector->Emit(kS390_SignExtendWord16ToInt32,
                     canEliminateZeroExt ? g.DefineSameAsFirst(node)
                                         : g.DefineAsRegister(node),
                     g.UseRegister(mleft.left().node()),
                     g.TempImmediate(!canEliminateZeroExt));
      return true;
    } else if (mleft.right().Is(24) && m.right().Is(24)) {
      bool canEliminateZeroExt =
          ProduceWord32Result<Adapter>(selector, mleft.left().node());
      selector->Emit(kS390_SignExtendWord8ToInt32,
                     canEliminateZeroExt ? g.DefineSameAsFirst(node)
                                         : g.DefineAsRegister(node),
                     g.UseRegister(mleft.left().node()),
                     g.TempImmediate(!canEliminateZeroExt));
      return true;
    }
  }
  return false;
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Rol(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Rol(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Ctz(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Ctz(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32ReverseBits(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64ReverseBits(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32AbsWithOverflow(node_t node) {
    VisitWord32UnaryOp(this, node, kS390_Abs32, OperandMode::kNone);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64AbsWithOverflow(node_t node) {
    VisitWord64UnaryOp(this, node, kS390_Abs64, OperandMode::kNone);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64ReverseBytes(node_t node) {
    S390OperandGeneratorT<Adapter> g(this);
    if constexpr (Adapter::IsTurboshaft) {
      using namespace turboshaft;  // NOLINT(build/namespaces)
      node_t input = this->Get(node).input(0);
      const Operation& input_op = this->Get(input);
      if (CanCover(node, input) && input_op.Is<LoadOp>()) {
        auto load = this->load_view(input);
        LoadRepresentation load_rep = load.loaded_rep();
        if (load_rep.representation() == MachineRepresentation::kWord64) {
          InstructionOperand outputs[] = {g.DefineAsRegister(node)};
          InstructionOperand inputs[3];
          size_t input_count = 0;
          AddressingMode mode =
              g.GetEffectiveAddressMemoryOperand(input, inputs, &input_count);
          Emit(kS390_LoadReverse64 | AddressingModeField::encode(mode), 1,
               outputs, input_count, inputs);
          return;
        }
      }
      Emit(kS390_LoadReverse64RR, g.DefineAsRegister(node),
           g.UseRegister(this->input_at(node, 0)));
    } else {
      NodeMatcher input(node->InputAt(0));
      if (CanCover(node, input.node()) && input.IsLoad()) {
        LoadRepresentation load_rep = LoadRepresentationOf(input.node()->op());
        if (load_rep.representation() == MachineRepresentation::kWord64) {
          Node* base = input.node()->InputAt(0);
          Node* offset = input.node()->InputAt(1);
          Emit(kS390_LoadReverse64 | AddressingModeField::encode(kMode_MRR),
               // TODO(miladfarca): one of the base and offset can be imm.
               g.DefineAsRegister(node), g.UseRegister(base),
               g.UseRegister(offset));
          return;
        }
      }
      Emit(kS390_LoadReverse64RR, g.DefineAsRegister(node),
           g.UseRegister(node->InputAt(0)));
    }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32ReverseBytes(node_t node) {
    S390OperandGeneratorT<Adapter> g(this);
    if constexpr (Adapter::IsTurboshaft) {
      using namespace turboshaft;  // NOLINT(build/namespaces)
      node_t input = this->Get(node).input(0);
      const Operation& input_op = this->Get(input);
      if (CanCover(node, input) && input_op.Is<LoadOp>()) {
        auto load = this->load_view(input);
        LoadRepresentation load_rep = load.loaded_rep();
        if (load_rep.representation() == MachineRepresentation::kWord32) {
          InstructionOperand outputs[] = {g.DefineAsRegister(node)};
          InstructionOperand inputs[3];
          size_t input_count = 0;
          AddressingMode mode =
              g.GetEffectiveAddressMemoryOperand(input, inputs, &input_count);
          Emit(kS390_LoadReverse32 | AddressingModeField::encode(mode), 1,
               outputs, input_count, inputs);
          return;
        }
      }
      Emit(kS390_LoadReverse32RR, g.DefineAsRegister(node),
           g.UseRegister(this->input_at(node, 0)));
    } else {
      NodeMatcher input(node->InputAt(0));
      if (CanCover(node, input.node()) && input.IsLoad()) {
        LoadRepresentation load_rep = LoadRepresentationOf(input.node()->op());
        if (load_rep.representation() == MachineRepresentation::kWord32) {
          Node* base = input.node()->InputAt(0);
          Node* offset = input.node()->InputAt(1);
          Emit(kS390_LoadReverse32 | AddressingModeField::encode(kMode_MRR),
               // TODO(john.yan): one of the base and offset can be imm.
               g.DefineAsRegister(node), g.UseRegister(base),
               g.UseRegister(offset));
          return;
        }
      }
      Emit(kS390_LoadReverse32RR, g.DefineAsRegister(node),
           g.UseRegister(node->InputAt(0)));
    }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSimd128ReverseBytes(node_t node) {
    S390OperandGeneratorT<Adapter> g(this);
    if constexpr (Adapter::IsTurboshaft) {
      using namespace turboshaft;  // NOLINT(build/namespaces)
      node_t input = this->Get(node).input(0);
      const Operation& input_op = this->Get(input);
      if (CanCover(node, input) && input_op.Is<LoadOp>()) {
        auto load = this->load_view(input);
        LoadRepresentation load_rep = load.loaded_rep();
        if (load_rep.representation() == MachineRepresentation::kSimd128) {
          InstructionOperand outputs[] = {g.DefineAsRegister(node)};
          InstructionOperand inputs[3];
          size_t input_count = 0;
          AddressingMode mode =
              g.GetEffectiveAddressMemoryOperand(input, inputs, &input_count);
          Emit(kS390_LoadReverseSimd128 | AddressingModeField::encode(mode), 1,
               outputs, input_count, inputs);
          return;
        }
      }
      Emit(kS390_LoadReverseSimd128RR, g.DefineAsRegister(node),
           g.UseRegister(this->input_at(node, 0)));

    } else {
      NodeMatcher input(node->InputAt(0));
      if (CanCover(node, input.node()) && input.IsLoad()) {
        LoadRepresentation load_rep = LoadRepresentationOf(input.node()->op());
        if (load_rep.representation() == MachineRepresentation::kSimd128) {
          Node* base = input.node()->InputAt(0);
          Node* offset = input.node()->InputAt(1);
          Emit(
              kS390_LoadReverseSimd128 | AddressingModeField::encode(kMode_MRR),
              // TODO(miladfar): one of the base and offset can be imm.
              g.DefineAsRegister(node), g.UseRegister(base),
              g.UseRegister(offset));
          return;
        }
      }
      Emit(kS390_LoadReverseSimd128RR, g.DefineAsRegister(node),
           g.UseRegister(node->InputAt(0)));
    }
}

template <typename Adapter, class Matcher, ArchOpcode neg_opcode>
static inline bool TryMatchNegFromSub(InstructionSelectorT<Adapter>* selector,
                                      typename Adapter::node_t node) {
  S390OperandGeneratorT<Adapter> g(selector);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    static_assert(neg_opcode == kS390_Neg32 || neg_opcode == kS390_Neg64,
                  "Provided opcode is not a Neg opcode.");
    const WordBinopOp& sub_op =
        selector->Get(node).template Cast<WordBinopOp>();
    if (selector->MatchIntegralZero(sub_op.left())) {
      typename Adapter::node_t value = sub_op.right();
      bool doZeroExt = DoZeroExtForResult<Adapter>(selector, node);
      bool canEliminateZeroExt = ProduceWord32Result<Adapter>(selector, value);
      if (doZeroExt) {
        selector->Emit(neg_opcode,
                       canEliminateZeroExt ? g.DefineSameAsFirst(node)
                                           : g.DefineAsRegister(node),
                       g.UseRegister(value),
                       g.TempImmediate(!canEliminateZeroExt));
      } else {
        selector->Emit(neg_opcode, g.DefineAsRegister(node),
                       g.UseRegister(value));
      }
      return true;
    }
    return false;

  } else {
    Matcher m(node);
    static_assert(neg_opcode == kS390_Neg32 || neg_opcode == kS390_Neg64,
                  "Provided opcode is not a Neg opcode.");
    if (m.left().Is(0)) {
      Node* value = m.right().node();
      bool doZeroExt = DoZeroExtForResult<Adapter>(selector, node);
      bool canEliminateZeroExt = ProduceWord32Result<Adapter>(selector, value);
      if (doZeroExt) {
        selector->Emit(neg_opcode,
                       canEliminateZeroExt ? g.DefineSameAsFirst(node)
                                           : g.DefineAsRegister(node),
                       g.UseRegister(value),
                       g.TempImmediate(!canEliminateZeroExt));
      } else {
        selector->Emit(neg_opcode, g.DefineAsRegister(node),
                       g.UseRegister(value));
      }
      return true;
    }
    return false;
  }
}

template <typename Adapter, class Matcher, ArchOpcode shift_op>
bool TryMatchShiftFromMul(InstructionSelectorT<Adapter>* selector,
                          typename Adapter::node_t node) {
  S390OperandGeneratorT<Adapter> g(selector);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const Operation& op = selector->Get(node);
    const WordBinopOp& mul_op = op.Cast<WordBinopOp>();
    turboshaft::OpIndex left = mul_op.left();
    turboshaft::OpIndex right = mul_op.right();
    if (g.CanBeImmediate(right, OperandMode::kInt32Imm) &&
        base::bits::IsPowerOfTwo(g.GetImmediate(right))) {
      int power = 63 - base::bits::CountLeadingZeros64(g.GetImmediate(right));
      bool doZeroExt = DoZeroExtForResult<Adapter>(selector, node);
      bool canEliminateZeroExt = ProduceWord32Result<Adapter>(selector, left);
      InstructionOperand dst = (doZeroExt && !canEliminateZeroExt &&
                                CpuFeatures::IsSupported(DISTINCT_OPS))
                                   ? g.DefineAsRegister(node)
                                   : g.DefineSameAsFirst(node);

      if (doZeroExt) {
        selector->Emit(shift_op, dst, g.UseRegister(left),
                       g.UseImmediate(power),
                       g.TempImmediate(!canEliminateZeroExt));
      } else {
        selector->Emit(shift_op, dst, g.UseRegister(left),
                       g.UseImmediate(power));
      }
      return true;
    }
    return false;

  } else {
    Matcher m(node);
    Node* left = m.left().node();
    Node* right = m.right().node();
    if (g.CanBeImmediate(right, OperandMode::kInt32Imm) &&
        base::bits::IsPowerOfTwo(g.GetImmediate(right))) {
      int power = 63 - base::bits::CountLeadingZeros64(g.GetImmediate(right));
      bool doZeroExt = DoZeroExtForResult<Adapter>(selector, node);
      bool canEliminateZeroExt = ProduceWord32Result<Adapter>(selector, left);
      InstructionOperand dst = (doZeroExt && !canEliminateZeroExt &&
                                CpuFeatures::IsSupported(DISTINCT_OPS))
                                   ? g.DefineAsRegister(node)
                                   : g.DefineSameAsFirst(node);

      if (doZeroExt) {
        selector->Emit(shift_op, dst, g.UseRegister(left),
                       g.UseImmediate(power),
                       g.TempImmediate(!canEliminateZeroExt));
      } else {
        selector->Emit(shift_op, dst, g.UseRegister(left),
                       g.UseImmediate(power));
      }
      return true;
    }
    return false;
  }
}

template <typename Adapter, ArchOpcode opcode>
static inline bool TryMatchInt32OpWithOverflow(
    InstructionSelectorT<Adapter>* selector, typename Adapter::node_t node,
    OperandModes mode) {
  typename Adapter::node_t ovf = selector->FindProjection(node, 1);
  if (selector->valid(ovf)) {
    FlagsContinuationT<Adapter> cont =
        FlagsContinuationT<Adapter>::ForSet(kOverflow, ovf);
    VisitWord32BinOp(selector, node, opcode, mode, &cont);
    return true;
  }
  return false;
}

template <typename Adapter>
static inline bool TryMatchInt32AddWithOverflow(
    InstructionSelectorT<Adapter>* selector, typename Adapter::node_t node) {
  return TryMatchInt32OpWithOverflow<Adapter, kS390_Add32>(selector, node,
                                                           AddOperandMode);
}

template <typename Adapter>
static inline bool TryMatchInt32SubWithOverflow(
    InstructionSelectorT<Adapter>* selector, typename Adapter::node_t node) {
  return TryMatchInt32OpWithOverflow<Adapter, kS390_Sub32>(selector, node,
                                                           SubOperandMode);
}

template <typename Adapter>
static inline bool TryMatchInt32MulWithOverflow(
    InstructionSelectorT<Adapter>* selector, typename Adapter::node_t node) {
  typename Adapter::node_t ovf = selector->FindProjection(node, 1);
  if (selector->valid(ovf)) {
    if (CpuFeatures::IsSupported(MISC_INSTR_EXT2)) {
      TryMatchInt32OpWithOverflow<Adapter, kS390_Mul32>(
          selector, node, OperandMode::kAllowRRR | OperandMode::kAllowRM);
    } else {
      FlagsContinuationT<Adapter> cont =
          FlagsContinuationT<Adapter>::ForSet(kNotEqual, ovf);
      VisitWord32BinOp(selector, node, kS390_Mul32WithOverflow,
                       OperandMode::kInt32Imm | OperandMode::kAllowDistinctOps,
                       &cont);
    }
    return true;
  }
    return TryMatchShiftFromMul<Adapter, Int32BinopMatcher, kS390_ShiftLeft32>(
        selector, node);
}

template <typename Adapter, ArchOpcode opcode>
static inline bool TryMatchInt64OpWithOverflow(
    InstructionSelectorT<Adapter>* selector, typename Adapter::node_t node,
    OperandModes mode) {
  typename Adapter::node_t ovf = selector->FindProjection(node, 1);
  if (selector->valid(ovf)) {
    FlagsContinuationT<Adapter> cont =
        FlagsContinuationT<Adapter>::ForSet(kOverflow, ovf);
    VisitWord64BinOp(selector, node, opcode, mode, &cont);
    return true;
  }
  return false;
}

template <typename Adapter>
static inline bool TryMatchInt64AddWithOverflow(
    InstructionSelectorT<Adapter>* selector, typename Adapter::node_t node) {
  return TryMatchInt64OpWithOverflow<Adapter, kS390_Add64>(selector, node,
                                                           AddOperandMode);
}

template <typename Adapter>
static inline bool TryMatchInt64SubWithOverflow(
    InstructionSelectorT<Adapter>* selector, typename Adapter::node_t node) {
  return TryMatchInt64OpWithOverflow<Adapter, kS390_Sub64>(selector, node,
                                                           SubOperandMode);
}

template <typename Adapter>
void EmitInt64MulWithOverflow(InstructionSelectorT<Adapter>* selector,
                              typename Adapter::node_t node,
                              FlagsContinuationT<Adapter>* cont) {
  S390OperandGeneratorT<Adapter> g(selector);
  typename Adapter::node_t lhs = selector->input_at(node, 0);
  typename Adapter::node_t rhs = selector->input_at(node, 1);
  InstructionOperand inputs[2];
  size_t input_count = 0;
  InstructionOperand outputs[1];
  size_t output_count = 0;

  inputs[input_count++] = g.UseUniqueRegister(lhs);
  inputs[input_count++] = g.UseUniqueRegister(rhs);
  outputs[output_count++] = g.DefineAsRegister(node);
  selector->EmitWithContinuation(kS390_Mul64WithOverflow, output_count, outputs,
                                 input_count, inputs, cont);
}

template <typename Adapter>
static inline bool TryMatchDoubleConstructFromInsert(
    InstructionSelectorT<Adapter>* selector, typename Adapter::node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    UNIMPLEMENTED();
  } else {
    S390OperandGeneratorT<Adapter> g(selector);
    Node* left = node->InputAt(0);
    Node* right = node->InputAt(1);
    Node* lo32 = nullptr;
    Node* hi32 = nullptr;

    if (node->opcode() == IrOpcode::kFloat64InsertLowWord32) {
      lo32 = right;
    } else if (node->opcode() == IrOpcode::kFloat64InsertHighWord32) {
      hi32 = right;
    } else {
      return false;  // doesn't match
    }

    if (left->opcode() == IrOpcode::kFloat64InsertLowWord32) {
      lo32 = left->InputAt(1);
    } else if (left->opcode() == IrOpcode::kFloat64InsertHighWord32) {
      hi32 = left->InputAt(1);
    } else {
      return false;  // doesn't match
    }

    if (!lo32 || !hi32) return false;  // doesn't match

    selector->Emit(kS390_DoubleConstruct, g.DefineAsRegister(node),
                   g.UseRegister(hi32), g.UseRegister(lo32));
    return true;
  }
}

#define null ([]() { return false; })

#define FLOAT_UNARY_OP_LIST(V)                                                 \
  V(Float64, TruncateFloat64ToUint32, kS390_DoubleToUint32,                    \
    OperandMode::kNone, null)                                                  \
  V(Float64, Float64SilenceNaN, kS390_Float64SilenceNaN, OperandMode::kNone,   \
    null)                                                                      \
  V(Float64, Float64Sqrt, kS390_SqrtDouble, OperandMode::kNone, null)          \
  V(Float64, Float64RoundUp, kS390_CeilDouble, OperandMode::kNone, null)       \
  V(Float64, Float64RoundTruncate, kS390_TruncateDouble, OperandMode::kNone,   \
    null)                                                                      \
  V(Float64, Float64RoundTiesEven, kS390_DoubleNearestInt, OperandMode::kNone, \
    null)                                                                      \
  V(Float64, Float64RoundTiesAway, kS390_RoundDouble, OperandMode::kNone,      \
    null)                                                                      \
  V(Float64, Float64RoundDown, kS390_FloorDouble, OperandMode::kNone, null)    \
  V(Float64, Float64Neg, kS390_NegDouble, OperandMode::kNone, null)            \
  V(Float64, Float64Abs, kS390_AbsDouble, OperandMode::kNone, null)            \
  V(Float32, Float32Sqrt, kS390_SqrtFloat, OperandMode::kNone, null)           \
  V(Float32, Float32RoundUp, kS390_CeilFloat, OperandMode::kNone, null)        \
  V(Float32, Float32RoundTruncate, kS390_TruncateFloat, OperandMode::kNone,    \
    null)                                                                      \
  V(Float32, Float32RoundTiesEven, kS390_FloatNearestInt, OperandMode::kNone,  \
    null)                                                                      \
  V(Float32, Float32RoundDown, kS390_FloorFloat, OperandMode::kNone, null)     \
  V(Float32, Float32Neg, kS390_NegFloat, OperandMode::kNone, null)             \
  V(Float32, Float32Abs, kS390_AbsFloat, OperandMode::kNone, null)             \
  V(Float64, BitcastFloat64ToInt64, kS390_BitcastDoubleToInt64,                \
    OperandMode::kNone, null)                                                  \
  V(Float32, BitcastFloat32ToInt32, kS390_BitcastFloat32ToInt32,               \
    OperandMode::kAllowRM, null)                                               \
  V(Word32, Float64ExtractHighWord32, kS390_DoubleExtractHighWord32,           \
    OperandMode::kNone, null)                                                  \
  /* TODO(john.yan): can use kAllowRM */                                       \
  V(Word32, Float64ExtractLowWord32, kS390_DoubleExtractLowWord32,             \
    OperandMode::kNone, null)                                                  \
  V(Float64, ChangeFloat64ToUint64, kS390_DoubleToUint64, OperandMode::kNone,  \
    null)                                                                      \
  V(Float64, ChangeFloat64ToInt64, kS390_DoubleToInt64, OperandMode::kNone,    \
    null)                                                                      \
  V(Float64, ChangeFloat64ToUint32, kS390_DoubleToUint32, OperandMode::kNone,  \
    null)                                                                      \
  V(Float64, ChangeFloat64ToInt32, kS390_DoubleToInt32, OperandMode::kNone,    \
    null)                                                                      \
  V(Float64, TruncateFloat64ToInt64, kS390_DoubleToInt64, OperandMode::kNone,  \
    null)                                                                      \
  V(Float64, TruncateFloat64ToFloat32, kS390_DoubleToFloat32,                  \
    OperandMode::kNone, null)                                                  \
  V(Float64, TruncateFloat64ToWord32, kArchTruncateDoubleToI,                  \
    OperandMode::kNone, null)                                                  \
  V(Float32, ChangeFloat32ToFloat64, kS390_Float32ToDouble,                    \
    OperandMode::kAllowRM, null)                                               \
  V(Float64, RoundFloat64ToInt32, kS390_DoubleToInt32, OperandMode::kNone, null)

#define FLOAT_BIN_OP_LIST(V)                                           \
  V(Float64, Float64Mul, kS390_MulDouble, OperandMode::kAllowRM, null) \
  V(Float64, Float64Add, kS390_AddDouble, OperandMode::kAllowRM, null) \
  V(Float64, Float64Min, kS390_MinDouble, OperandMode::kNone, null)    \
  V(Float64, Float64Max, kS390_MaxDouble, OperandMode::kNone, null)    \
  V(Float32, Float32Min, kS390_MinFloat, OperandMode::kNone, null)     \
  V(Float32, Float32Max, kS390_MaxFloat, OperandMode::kNone, null)     \
  V(Float32, Float32Div, kS390_DivFloat, OperandMode::kAllowRM, null)  \
  V(Float32, Float32Mul, kS390_MulFloat, OperandMode::kAllowRM, null)  \
  V(Float32, Float32Sub, kS390_SubFloat, OperandMode::kAllowRM, null)  \
  V(Float32, Float32Add, kS390_AddFloat, OperandMode::kAllowRM, null)  \
  V(Float64, Float64Sub, kS390_SubDouble, OperandMode::kAllowRM, null) \
  V(Float64, Float64Div, kS390_DivDouble, OperandMode::kAllowRM, null)

#define WORD32_UNARY_OP_LIST(V)                                              \
  V(Word32, SignExtendWord32ToInt64, kS390_SignExtendWord32ToInt64,          \
    OperandMode::kNone, null)                                                \
  V(Word32, SignExtendWord16ToInt64, kS390_SignExtendWord16ToInt64,          \
    OperandMode::kNone, null)                                                \
  V(Word32, SignExtendWord8ToInt64, kS390_SignExtendWord8ToInt64,            \
    OperandMode::kNone, null)                                                \
  V(Word32, SignExtendWord16ToInt32, kS390_SignExtendWord16ToInt32,          \
    OperandMode::kNone, null)                                                \
  V(Word32, SignExtendWord8ToInt32, kS390_SignExtendWord8ToInt32,            \
    OperandMode::kNone, null)                                                \
  V(Word32, Word32Popcnt, kS390_Popcnt32, OperandMode::kNone, null)          \
  V(Word32, Word32Clz, kS390_Cntlz32, OperandMode::kNone, null)              \
  V(Word32, BitcastInt32ToFloat32, kS390_BitcastInt32ToFloat32,              \
    OperandMode::kNone, null)                                                \
  V(Word32, ChangeUint32ToFloat64, kS390_Uint32ToDouble, OperandMode::kNone, \
    null)                                                                    \
  V(Word32, RoundUint32ToFloat32, kS390_Uint32ToFloat32, OperandMode::kNone, \
    null)                                                                    \
  V(Word32, RoundInt32ToFloat32, kS390_Int32ToFloat32, OperandMode::kNone,   \
    null)                                                                    \
  V(Word32, ChangeInt32ToFloat64, kS390_Int32ToDouble, OperandMode::kNone,   \
    null)                                                                    \
  V(Word32, ChangeInt32ToInt64, kS390_SignExtendWord32ToInt64,               \
    OperandMode::kNone, null)                                                \
  V(Word32, ChangeUint32ToUint64, kS390_Uint32ToUint64, OperandMode::kNone,  \
    [&]() -> bool {                                                          \
      if (ProduceWord32Result<Adapter>(this, this->input_at(node, 0))) {     \
        EmitIdentity(node);                                                  \
        return true;                                                         \
      }                                                                      \
      return false;                                                          \
    })

#define WORD32_BIN_OP_LIST(V)                                                 \
  V(Word32, Float64InsertHighWord32, kS390_DoubleInsertHighWord32,            \
    OperandMode::kAllowRRR,                                                   \
    [&]() -> bool { return TryMatchDoubleConstructFromInsert(this, node); })  \
  V(Word32, Float64InsertLowWord32, kS390_DoubleInsertLowWord32,              \
    OperandMode::kAllowRRR,                                                   \
    [&]() -> bool { return TryMatchDoubleConstructFromInsert(this, node); })  \
  V(Word32, Int32SubWithOverflow, kS390_Sub32, SubOperandMode,                \
    ([&]() { return TryMatchInt32SubWithOverflow(this, node); }))             \
  V(Word32, Uint32MulHigh, kS390_MulHighU32,                                  \
    OperandMode::kAllowRRM | OperandMode::kAllowRRR, null)                    \
  V(Word32, Uint32Mod, kS390_ModU32,                                          \
    OperandMode::kAllowRRM | OperandMode::kAllowRRR, null)                    \
  V(Word32, Uint32Div, kS390_DivU32,                                          \
    OperandMode::kAllowRRM | OperandMode::kAllowRRR, null)                    \
  V(Word32, Int32Mod, kS390_Mod32,                                            \
    OperandMode::kAllowRRM | OperandMode::kAllowRRR, null)                    \
  V(Word32, Int32Div, kS390_Div32,                                            \
    OperandMode::kAllowRRM | OperandMode::kAllowRRR, null)                    \
  V(Word32, Int32Mul, kS390_Mul32, MulOperandMode, ([&]() {                   \
      return TryMatchShiftFromMul<Adapter, Int32BinopMatcher,                 \
                                  kS390_ShiftLeft32>(this, node);             \
    }))                                                                       \
  V(Word32, Int32MulHigh, kS390_MulHigh32,                                    \
    OperandMode::kInt32Imm | OperandMode::kAllowDistinctOps, null)            \
  V(Word32, Int32Sub, kS390_Sub32, SubOperandMode, ([&]() {                   \
      return TryMatchNegFromSub<Adapter, Int32BinopMatcher, kS390_Neg32>(     \
          this, node);                                                        \
    }))                                                                       \
  V(Word32, Int32Add, kS390_Add32, AddOperandMode, null)                      \
  V(Word32, Word32Xor, kS390_Xor32, Xor32OperandMode, null)                   \
  V(Word32, Word32Ror, kS390_RotRight32,                                      \
    OperandMode::kAllowRI | OperandMode::kAllowRRR | OperandMode::kAllowRRI | \
        OperandMode::kShift32Imm,                                             \
    null)                                                                     \
  V(Word32, Word32Shr, kS390_ShiftRight32, Shift32OperandMode, null)          \
  V(Word32, Word32Shl, kS390_ShiftLeft32, Shift32OperandMode, null)           \
  V(Word32, Int32AddWithOverflow, kS390_Add32, AddOperandMode,                \
    ([&]() { return TryMatchInt32AddWithOverflow(this, node); }))             \
  V(Word32, Int32MulWithOverflow, kS390_Mul32, MulOperandMode,                \
    ([&]() { return TryMatchInt32MulWithOverflow(this, node); }))             \
  V(Word32, Word32And, kS390_And32, And32OperandMode, null)                   \
  V(Word32, Word32Or, kS390_Or32, Or32OperandMode, null)                      \
  V(Word32, Word32Sar, kS390_ShiftRightArith32, Shift32OperandMode,           \
    [&]() { return TryMatchSignExtInt16OrInt8FromWord32Sar(this, node); })

#define WORD64_UNARY_OP_LIST(V)                                              \
  V(Word64, TruncateInt64ToInt32, kS390_Int64ToInt32, OperandMode::kNone,    \
    null)                                                                    \
  V(Word64, Word64Clz, kS390_Cntlz64, OperandMode::kNone, null)              \
  V(Word64, Word64Popcnt, kS390_Popcnt64, OperandMode::kNone, null)          \
  V(Word64, Int64SubWithOverflow, kS390_Sub64, SubOperandMode,               \
    ([&]() { return TryMatchInt64SubWithOverflow(this, node); }))            \
  V(Word64, BitcastInt64ToFloat64, kS390_BitcastInt64ToDouble,               \
    OperandMode::kNone, null)                                                \
  V(Word64, ChangeInt64ToFloat64, kS390_Int64ToDouble, OperandMode::kNone,   \
    null)                                                                    \
  V(Word64, RoundUint64ToFloat64, kS390_Uint64ToDouble, OperandMode::kNone,  \
    null)                                                                    \
  V(Word64, RoundUint64ToFloat32, kS390_Uint64ToFloat32, OperandMode::kNone, \
    null)                                                                    \
  V(Word64, RoundInt64ToFloat32, kS390_Int64ToFloat32, OperandMode::kNone,   \
    null)                                                                    \
  V(Word64, RoundInt64ToFloat64, kS390_Int64ToDouble, OperandMode::kNone, null)

#define WORD64_BIN_OP_LIST(V)                                              \
  V(Word64, Int64AddWithOverflow, kS390_Add64, AddOperandMode,             \
    ([&]() { return TryMatchInt64AddWithOverflow(this, node); }))          \
  V(Word64, Uint64MulHigh, kS390_MulHighU64, OperandMode::kAllowRRR, null) \
  V(Word64, Uint64Mod, kS390_ModU64,                                       \
    OperandMode::kAllowRRM | OperandMode::kAllowRRR, null)                 \
  V(Word64, Uint64Div, kS390_DivU64,                                       \
    OperandMode::kAllowRRM | OperandMode::kAllowRRR, null)                 \
  V(Word64, Int64Mod, kS390_Mod64,                                         \
    OperandMode::kAllowRRM | OperandMode::kAllowRRR, null)                 \
  V(Word64, Int64Div, kS390_Div64,                                         \
    OperandMode::kAllowRRM | OperandMode::kAllowRRR, null)                 \
  V(Word64, Int64MulHigh, kS390_MulHighS64, OperandMode::kAllowRRR, null)  \
  V(Word64, Int64Mul, kS390_Mul64, MulOperandMode, ([&]() {                \
      return TryMatchShiftFromMul<Adapter, Int64BinopMatcher,              \
                                  kS390_ShiftLeft64>(this, node);          \
    }))                                                                    \
  V(Word64, Int64Sub, kS390_Sub64, SubOperandMode, ([&]() {                \
      return TryMatchNegFromSub<Adapter, Int64BinopMatcher, kS390_Neg64>(  \
          this, node);                                                     \
    }))                                                                    \
  V(Word64, Word64Xor, kS390_Xor64, Xor64OperandMode, null)                \
  V(Word64, Word64Or, kS390_Or64, Or64OperandMode, null)                   \
  V(Word64, Word64Ror, kS390_RotRight64, Shift64OperandMode, null)         \
  V(Word64, Int64Add, kS390_Add64, AddOperandMode, null)                   \
  V(Word64, Word64Sar, kS390_ShiftRightArith64, Shift64OperandMode, null)

#define DECLARE_UNARY_OP(type, name, op, mode, try_extra)        \
  template <typename Adapter>                                    \
  void InstructionSelectorT<Adapter>::Visit##name(node_t node) { \
      if (std::function<bool()>(try_extra)()) return;            \
      Visit##type##UnaryOp(this, node, op, mode);                \
  }

#define DECLARE_BIN_OP(type, name, op, mode, try_extra)          \
  template <typename Adapter>                                    \
  void InstructionSelectorT<Adapter>::Visit##name(node_t node) { \
      if (std::function<bool()>(try_extra)()) return;            \
      Visit##type##BinOp(this, node, op, mode);                  \
  }

FLOAT_UNARY_OP_LIST(DECLARE_UNARY_OP)
FLOAT_BIN_OP_LIST(DECLARE_BIN_OP)
WORD32_UNARY_OP_LIST(DECLARE_UNARY_OP)
WORD32_BIN_OP_LIST(DECLARE_BIN_OP)
WORD64_UNARY_OP_LIST(DECLARE_UNARY_OP)
WORD64_BIN_OP_LIST(DECLARE_BIN_OP)

#undef FLOAT_UNARY_OP_LIST
#undef FLOAT_BIN_OP_LIST
#undef WORD32_UNARY_OP_LIST
#undef WORD32_BIN_OP_LIST
#undef WORD64_UNARY_OP_LIST
#undef WORD64_BIN_OP_LIST
#undef DECLARE_UNARY_OP
#undef DECLARE_BIN_OP
#undef null

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTryTruncateFloat32ToInt64(
    node_t node) {
    VisitTryTruncateDouble(this, kS390_Float32ToInt64, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTryTruncateFloat64ToInt64(
    node_t node) {
    VisitTryTruncateDouble(this, kS390_DoubleToInt64, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTryTruncateFloat32ToUint64(
    node_t node) {
    VisitTryTruncateDouble(this, kS390_Float32ToUint64, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTryTruncateFloat64ToUint64(
    node_t node) {
    VisitTryTruncateDouble(this, kS390_DoubleToUint64, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTryTruncateFloat64ToInt32(
    node_t node) {
    VisitTryTruncateDouble(this, kS390_DoubleToInt32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTryTruncateFloat64ToUint32(
    node_t node) {
    VisitTryTruncateDouble(this, kS390_DoubleToUint32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitBitcastWord32ToWord64(node_t node) {
    DCHECK(SmiValuesAre31Bits());
    DCHECK(COMPRESS_POINTERS_BOOL);
    EmitIdentity(node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Mod(node_t node) {
    S390OperandGeneratorT<Adapter> g(this);
    Emit(kS390_ModDouble, g.DefineAsFixed(node, d1),
         g.UseFixed(this->input_at(node, 0), d1),
         g.UseFixed(this->input_at(node, 1), d2))
        ->MarkAsCall();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Ieee754Unop(
    node_t node, InstructionCode opcode) {
    S390OperandGeneratorT<Adapter> g(this);
    Emit(opcode, g.DefineAsFixed(node, d1),
         g.UseFixed(this->input_at(node, 0), d1))
        ->MarkAsCall();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Ieee754Binop(
    node_t node, InstructionCode opcode) {
  S390OperandGeneratorT<Adapter> g(this);
  Emit(opcode, g.DefineAsFixed(node, d1),
       g.UseFixed(this->input_at(node, 0), d1),
       g.UseFixed(this->input_at(node, 1), d2))
      ->MarkAsCall();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64MulWithOverflow(node_t node) {
  node_t ovf = FindProjection(node, 1);
  if (this->valid(ovf)) {
    FlagsContinuation cont = FlagsContinuation::ForSet(
        CpuFeatures::IsSupported(MISC_INSTR_EXT2) ? kOverflow : kNotEqual, ovf);
    return EmitInt64MulWithOverflow(this, node, &cont);
  }
    FlagsContinuation cont;
    EmitInt64MulWithOverflow(this, node, &cont);
}

template <typename Adapter>
static bool CompareLogical(FlagsContinuationT<Adapter>* cont) {
  switch (cont->condition()) {
    case kUnsignedLessThan:
    case kUnsignedGreaterThanOrEqual:
    case kUnsignedLessThanOrEqual:
    case kUnsignedGreaterThan:
      return true;
    default:
      return false;
  }
  UNREACHABLE();
}

namespace {

// Shared routine for multiple compare operations.
template <typename Adapter>
void VisitCompare(InstructionSelectorT<Adapter>* selector,
                  InstructionCode opcode, InstructionOperand left,
                  InstructionOperand right, FlagsContinuationT<Adapter>* cont) {
  selector->EmitWithContinuation(opcode, left, right, cont);
}

template <typename Adapter>
void VisitLoadAndTest(InstructionSelectorT<Adapter>* selector,
                      InstructionCode opcode, typename Adapter::node_t node,
                      typename Adapter::node_t value,
                      FlagsContinuationT<Adapter>* cont,
                      bool discard_output = false);

// Shared routine for multiple word compare operations.
template <typename Adapter>
void VisitWordCompare(InstructionSelectorT<Adapter>* selector,
                      typename Adapter::node_t node, InstructionCode opcode,
                      FlagsContinuationT<Adapter>* cont,
                      OperandModes immediate_mode) {
    S390OperandGeneratorT<Adapter> g(selector);
    typename Adapter::node_t lhs = selector->input_at(node, 0);
    typename Adapter::node_t rhs = selector->input_at(node, 1);

    if constexpr (Adapter::IsTurboshaft) {
      using namespace turboshaft;  // NOLINT(build/namespaces)
      const Operation& op = selector->Get(node);
      DCHECK(op.Is<ComparisonOp>() || op.Is<Opmask::kWord32Sub>() ||
             op.Is<Opmask::kWord64Sub>());
      USE(op);
    } else {
      DCHECK(IrOpcode::IsComparisonOpcode(node->opcode()) ||
             node->opcode() == IrOpcode::kInt32Sub ||
             node->opcode() == IrOpcode::kInt64Sub);
    }

    InstructionOperand inputs[8];
    InstructionOperand outputs[1];
    size_t input_count = 0;
    size_t output_count = 0;

    // If one of the two inputs is an immediate, make sure it's on the right, or
    // if one of the two inputs is a memory operand, make sure it's on the left.
    int effect_level = selector->GetEffectLevel(node, cont);

    if ((!g.CanBeImmediate(rhs, immediate_mode) &&
         g.CanBeImmediate(lhs, immediate_mode)) ||
        (!g.CanBeMemoryOperand(opcode, node, rhs, effect_level) &&
         g.CanBeMemoryOperand(opcode, node, lhs, effect_level))) {
      if (!selector->IsCommutative(node)) cont->Commute();
      std::swap(lhs, rhs);
    }

    // check if compare with 0
    if (g.CanBeImmediate(rhs, immediate_mode) && g.GetImmediate(rhs) == 0) {
      DCHECK(opcode == kS390_Cmp32 || opcode == kS390_Cmp64);
      ArchOpcode load_and_test = (opcode == kS390_Cmp32)
                                     ? kS390_LoadAndTestWord32
                                     : kS390_LoadAndTestWord64;
      return VisitLoadAndTest(selector, load_and_test, node, lhs, cont, true);
    }

    inputs[input_count++] = g.UseRegister(lhs);
    if (g.CanBeMemoryOperand(opcode, node, rhs, effect_level)) {
      // generate memory operand
      AddressingMode addressing_mode = g.GetEffectiveAddressMemoryOperand(
          rhs, inputs, &input_count, OpcodeImmMode(opcode));
      opcode |= AddressingModeField::encode(addressing_mode);
    } else if (g.CanBeImmediate(rhs, immediate_mode)) {
      inputs[input_count++] = g.UseImmediate(rhs);
    } else {
      inputs[input_count++] = g.UseAnyExceptImmediate(rhs);
    }

    DCHECK(input_count <= 8 && output_count <= 1);
    selector->EmitWithContinuation(opcode, output_count, outputs, input_count,
                                   inputs, cont);
}

template <typename Adapter>
void VisitWord32Compare(InstructionSelectorT<Adapter>* selector,
                        typename Adapter::node_t node,
                        FlagsContinuationT<Adapter>* cont) {
    OperandModes mode = (CompareLogical(cont) ? OperandMode::kUint32Imm
                                              : OperandMode::kInt32Imm);
    VisitWordCompare(selector, node, kS390_Cmp32, cont, mode);
}

template <typename Adapter>
void VisitWord64Compare(InstructionSelectorT<Adapter>* selector,
                        typename Adapter::node_t node,
                        FlagsContinuationT<Adapter>* cont) {
  OperandModes mode =
      (CompareLogical(cont) ? OperandMode::kUint32Imm : OperandMode::kInt32Imm);
  VisitWordCompare(selector, node, kS390_Cmp64, cont, mode);
}

// Shared routine for multiple float32 compare operations.
template <typename Adapter>
void VisitFloat32Compare(InstructionSelectorT<Adapter>* selector,
                         typename Adapter::node_t node,
                         FlagsContinuationT<Adapter>* cont) {
    VisitWordCompare(selector, node, kS390_CmpFloat, cont, OperandMode::kNone);
}

// Shared routine for multiple float64 compare operations.
template <typename Adapter>
void VisitFloat64Compare(InstructionSelectorT<Adapter>* selector,
                         typename Adapter::node_t node,
                         FlagsContinuationT<Adapter>* cont) {
    VisitWordCompare(selector, node, kS390_CmpDouble, cont, OperandMode::kNone);
}

void VisitTestUnderMask(InstructionSelectorT<TurboshaftAdapter>* selector,
                        TurboshaftAdapter::node_t node,
                        FlagsContinuationT<TurboshaftAdapter>* cont) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const Operation& op = selector->Get(node);
  DCHECK(op.Is<Opmask::kWord32BitwiseAnd>() ||
         op.Is<Opmask::kWord64BitwiseAnd>());
  USE(op);

  ArchOpcode opcode;
  if (selector->Get(node).template TryCast<Opmask::kWord32BitwiseAnd>()) {
    opcode = kS390_Tst32;
  } else {
    opcode = kS390_Tst64;
  }

  S390OperandGeneratorT<TurboshaftAdapter> g(selector);
  typename TurboshaftAdapter::node_t lhs = selector->input_at(node, 0);
  typename TurboshaftAdapter::node_t rhs = selector->input_at(node, 1);
  if (!g.CanBeImmediate(rhs, OperandMode::kUint32Imm) &&
      g.CanBeImmediate(lhs, OperandMode::kUint32Imm)) {
    std::swap(lhs, rhs);
  }
  VisitCompare(selector, opcode, g.UseRegister(lhs),
               g.UseOperand(rhs, OperandMode::kUint32Imm), cont);
}

template <typename Adapter>
void VisitTestUnderMask(InstructionSelectorT<Adapter>* selector, Node* node,
                        FlagsContinuationT<Adapter>* cont) {
  DCHECK(node->opcode() == IrOpcode::kWord32And ||
         node->opcode() == IrOpcode::kWord64And);
  ArchOpcode opcode =
      (node->opcode() == IrOpcode::kWord32And) ? kS390_Tst32 : kS390_Tst64;
  S390OperandGeneratorT<Adapter> g(selector);
  Node* left = node->InputAt(0);
  Node* right = node->InputAt(1);
  if (!g.CanBeImmediate(right, OperandMode::kUint32Imm) &&
      g.CanBeImmediate(left, OperandMode::kUint32Imm)) {
    std::swap(left, right);
  }
  VisitCompare(selector, opcode, g.UseRegister(left),
               g.UseOperand(right, OperandMode::kUint32Imm), cont);
}

template <typename Adapter>
void VisitLoadAndTest(InstructionSelectorT<Adapter>* selector,
                      InstructionCode opcode, typename Adapter::node_t node,
                      typename Adapter::node_t value,
                      FlagsContinuationT<Adapter>* cont, bool discard_output) {
  static_assert(kS390_LoadAndTestFloat64 - kS390_LoadAndTestWord32 == 3,
                "LoadAndTest Opcode shouldn't contain other opcodes.");
  // TODO(john.yan): Add support for Float32/Float64.
  DCHECK(opcode >= kS390_LoadAndTestWord32 ||
         opcode <= kS390_LoadAndTestWord64);

  S390OperandGeneratorT<Adapter> g(selector);
  InstructionOperand inputs[8];
  InstructionOperand outputs[2];
  size_t input_count = 0;
  size_t output_count = 0;
  bool use_value = false;

  int effect_level = selector->GetEffectLevel(node, cont);

  if (g.CanBeMemoryOperand(opcode, node, value, effect_level)) {
    // generate memory operand
    AddressingMode addressing_mode =
        g.GetEffectiveAddressMemoryOperand(value, inputs, &input_count);
    opcode |= AddressingModeField::encode(addressing_mode);
  } else {
    inputs[input_count++] = g.UseAnyExceptImmediate(value);
    use_value = true;
  }

  if (!discard_output && !use_value) {
    outputs[output_count++] = g.DefineAsRegister(value);
  }

  DCHECK(input_count <= 8 && output_count <= 2);
  selector->EmitWithContinuation(opcode, output_count, outputs, input_count,
                                 inputs, cont);
}

}  // namespace

// Shared routine for word comparisons against zero.
template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWordCompareZero(
    node_t user, node_t value, FlagsContinuation* cont) {
  using namespace turboshaft;  // NOLINT(build/namespaces)

  // Try to combine with comparisons against 0 by simply inverting the branch.
  ConsumeEqualZero(&user, &value, cont);

  FlagsCondition fc = cont->condition();
  if (CanCover(user, value)) {
    const Operation& value_op = this->Get(value);
    if (const ComparisonOp* comparison = value_op.TryCast<ComparisonOp>()) {
      if (comparison->kind == ComparisonOp::Kind::kEqual) {
        switch (comparison->rep.MapTaggedToWord().value()) {
          case RegisterRepresentation::Word32(): {
            cont->OverwriteAndNegateIfEqual(kEqual);
            if (this->MatchIntegralZero(comparison->right())) {
              // Try to combine the branch with a comparison.
              if (CanCover(value, comparison->left())) {
                const Operation& left_op = this->Get(comparison->left());
                if (left_op.Is<Opmask::kWord32Sub>()) {
                  return VisitWord32Compare(this, comparison->left(), cont);
                } else if (left_op.Is<Opmask::kWord32BitwiseAnd>()) {
                  return VisitTestUnderMask(this, comparison->left(), cont);
                }
              }
            }
            return VisitWord32Compare(this, value, cont);
          }
          case RegisterRepresentation::Word64(): {
            cont->OverwriteAndNegateIfEqual(kEqual);
            if (this->MatchIntegralZero(comparison->right())) {
              // Try to combine the branch with a comparison.
              if (CanCover(value, comparison->left())) {
                const Operation& left_op = this->Get(comparison->left());
                if (left_op.Is<Opmask::kWord64Sub>()) {
                  return VisitWord64Compare(this, comparison->left(), cont);
                } else if (left_op.Is<Opmask::kWord64BitwiseAnd>()) {
                  return VisitTestUnderMask(this, comparison->left(), cont);
                }
              }
            }
            return VisitWord64Compare(this, value, cont);
          }
          case RegisterRepresentation::Float32():
            cont->OverwriteAndNegateIfEqual(kEqual);
            return VisitFloat32Compare(this, value, cont);
          case RegisterRepresentation::Float64():
            cont->OverwriteAndNegateIfEqual(kEqual);
            return VisitFloat64Compare(this, value, cont);
          default:
            break;
        }
      } else {
        switch (comparison->rep.MapTaggedToWord().value()) {
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
              case ComparisonOp::Kind::kSignedLessThan:
                cont->OverwriteAndNegateIfEqual(kUnsignedLessThan);
                return VisitFloat32Compare(this, value, cont);
              case ComparisonOp::Kind::kSignedLessThanOrEqual:
                cont->OverwriteAndNegateIfEqual(kUnsignedLessThanOrEqual);
                return VisitFloat32Compare(this, value, cont);
              default:
                UNREACHABLE();
            }
          case RegisterRepresentation::Float64():
            switch (comparison->kind) {
              case ComparisonOp::Kind::kSignedLessThan:
                cont->OverwriteAndNegateIfEqual(kUnsignedLessThan);
                return VisitFloat64Compare(this, value, cont);
              case ComparisonOp::Kind::kSignedLessThanOrEqual:
                cont->OverwriteAndNegateIfEqual(kUnsignedLessThanOrEqual);
                return VisitFloat64Compare(this, value, cont);
              default:
                UNREACHABLE();
            }
          default:
            break;
        }
      }
    } else if (const ProjectionOp* projection =
                   value_op.TryCast<ProjectionOp>()) {
      // Check if this is the overflow output projection of an
      // <Operation>WithOverflow node.
      if (projection->index == 1u) {
        // We cannot combine the <Operation>WithOverflow with this branch
        // unless the 0th projection (the use of the actual value of the
        // <Operation> is either nullptr, which means there's no use of the
        // actual value, or was already defined, which means it is scheduled
        // *AFTER* this branch).
        OpIndex node = projection->input();
        OpIndex result = FindProjection(node, 0);
        if (!result.valid() || IsDefined(result)) {
          if (const OverflowCheckedBinopOp* binop =
                  TryCast<OverflowCheckedBinopOp>(node)) {
            const bool is64 = binop->rep == WordRepresentation::Word64();
            switch (binop->kind) {
              case OverflowCheckedBinopOp::Kind::kSignedAdd:
                cont->OverwriteAndNegateIfEqual(kOverflow);
                if (is64) {
                  return VisitWord64BinOp(this, node, kS390_Add64,
                                          AddOperandMode, cont);
                } else {
                  return VisitWord32BinOp(this, node, kS390_Add32,
                                          AddOperandMode, cont);
                }
              case OverflowCheckedBinopOp::Kind::kSignedSub:
                cont->OverwriteAndNegateIfEqual(kOverflow);
                if (is64) {
                  return VisitWord64BinOp(this, node, kS390_Sub64,
                                          AddOperandMode, cont);
                } else {
                  return VisitWord32BinOp(this, node, kS390_Sub32,
                                          AddOperandMode, cont);
                }
              case OverflowCheckedBinopOp::Kind::kSignedMul:
                if (is64) {
                  cont->OverwriteAndNegateIfEqual(
                      CpuFeatures::IsSupported(MISC_INSTR_EXT2) ? kOverflow
                                                                : kNotEqual);
                  return EmitInt64MulWithOverflow(this, node, cont);

                } else {
                  if (CpuFeatures::IsSupported(MISC_INSTR_EXT2)) {
                    cont->OverwriteAndNegateIfEqual(kOverflow);
                    return VisitWord32BinOp(
                        this, node, kS390_Mul32,
                        OperandMode::kAllowRRR | OperandMode::kAllowRM, cont);
                  } else {
                    cont->OverwriteAndNegateIfEqual(kNotEqual);
                    return VisitWord32BinOp(
                        this, node, kS390_Mul32WithOverflow,
                        OperandMode::kInt32Imm | OperandMode::kAllowDistinctOps,
                        cont);
                  }
                }
              default:
                break;
            }
          } else if (const OverflowCheckedUnaryOp* unop =
                         TryCast<OverflowCheckedUnaryOp>(node)) {
            const bool is64 = unop->rep == WordRepresentation::Word64();
            switch (unop->kind) {
              case OverflowCheckedUnaryOp::Kind::kAbs:
                if (is64) {
                  cont->OverwriteAndNegateIfEqual(kOverflow);
                  return VisitWord64UnaryOp(this, node, kS390_Abs64,
                                            OperandMode::kNone, cont);
                } else {
                  cont->OverwriteAndNegateIfEqual(kOverflow);
                  return VisitWord32UnaryOp(this, node, kS390_Abs32,
                                            OperandMode::kNone, cont);
                }
              default:
                break;
            }
          }
        }
      }
    } else if (value_op.Is<Opmask::kWord32Sub>()) {
      if (fc == kNotEqual || fc == kEqual)
        return VisitWord32Compare(this, value, cont);
    } else if (value_op.Is<Opmask::kWord32BitwiseAnd>()) {
      return VisitTestUnderMask(this, value, cont);
    } else if (value_op.Is<LoadOp>()) {
      auto load = this->load_view(value);
      LoadRepresentation load_rep = load.loaded_rep();
      switch (load_rep.representation()) {
        case MachineRepresentation::kWord32:
          return VisitLoadAndTest(this, kS390_LoadAndTestWord32, user, value,
                                  cont);
        default:
          break;
      }
    } else if (value_op.Is<Opmask::kWord32BitwiseOr>()) {
      if (fc == kNotEqual || fc == kEqual)
        return VisitWord32BinOp(this, value, kS390_Or32, Or32OperandMode, cont);
    } else if (value_op.Is<Opmask::kWord32BitwiseXor>()) {
      if (fc == kNotEqual || fc == kEqual)
        return VisitWord32BinOp(this, value, kS390_Xor32, Xor32OperandMode,
                                cont);
    } else if (value_op.Is<Opmask::kWord64Sub>()) {
      if (fc == kNotEqual || fc == kEqual)
        return VisitWord64Compare(this, value, cont);
    } else if (value_op.Is<Opmask::kWord64BitwiseAnd>()) {
      return VisitTestUnderMask(this, value, cont);
    } else if (value_op.Is<Opmask::kWord64BitwiseOr>()) {
      if (fc == kNotEqual || fc == kEqual)
        return VisitWord64BinOp(this, value, kS390_Or64, Or64OperandMode, cont);
    } else if (value_op.Is<Opmask::kWord64BitwiseXor>()) {
      if (fc == kNotEqual || fc == kEqual)
        return VisitWord64BinOp(this, value, kS390_Xor64, Xor64OperandMode,
                                cont);
    } else if (value_op.Is<StackPointerGreaterThanOp>()) {
      cont->OverwriteAndNegateIfEqual(kStackPointerGreaterThanCondition);
      return VisitStackPointerGreaterThan(value, cont);
    }
  }
  // Branch could not be combined with a compare, emit LoadAndTest
  VisitLoadAndTest(this, kS390_LoadAndTestWord32, user, value, cont, true);
}

// Shared routine for word comparisons against zero.
template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWordCompareZero(
    node_t user, node_t value, FlagsContinuation* cont) {
    // Try to combine with comparisons against 0 by simply inverting the branch.
    while (value->opcode() == IrOpcode::kWord32Equal && CanCover(user, value)) {
      Int32BinopMatcher m(value);
      if (!m.right().Is(0)) break;

      user = value;
      value = m.left().node();
      cont->Negate();
    }

    FlagsCondition fc = cont->condition();
    if (CanCover(user, value)) {
      switch (value->opcode()) {
        case IrOpcode::kWord32Equal: {
          cont->OverwriteAndNegateIfEqual(kEqual);
          Int32BinopMatcher m(value);
          if (m.right().Is(0)) {
            // Try to combine the branch with a comparison.
            Node* const user = m.node();
            Node* const value = m.left().node();
            if (CanCover(user, value)) {
              switch (value->opcode()) {
                case IrOpcode::kInt32Sub:
                  return VisitWord32Compare(this, value, cont);
                case IrOpcode::kWord32And:
                  return VisitTestUnderMask(this, value, cont);
                default:
                  break;
              }
            }
          }
          return VisitWord32Compare(this, value, cont);
        }
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
      case IrOpcode::kWord64Equal: {
        cont->OverwriteAndNegateIfEqual(kEqual);
        Int64BinopMatcher m(value);
        if (m.right().Is(0)) {
          // Try to combine the branch with a comparison.
          Node* const user = m.node();
          Node* const value = m.left().node();
          if (CanCover(user, value)) {
            switch (value->opcode()) {
              case IrOpcode::kInt64Sub:
                return VisitWord64Compare(this, value, cont);
              case IrOpcode::kWord64And:
                return VisitTestUnderMask(this, value, cont);
              default:
                break;
            }
          }
        }
        return VisitWord64Compare(this, value, cont);
      }
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
                return VisitWord32BinOp(this, node, kS390_Add32, AddOperandMode,
                                        cont);
              case IrOpcode::kInt32SubWithOverflow:
                cont->OverwriteAndNegateIfEqual(kOverflow);
                return VisitWord32BinOp(this, node, kS390_Sub32, SubOperandMode,
                                        cont);
              case IrOpcode::kInt32MulWithOverflow:
                if (CpuFeatures::IsSupported(MISC_INSTR_EXT2)) {
                  cont->OverwriteAndNegateIfEqual(kOverflow);
                  return VisitWord32BinOp(
                      this, node, kS390_Mul32,
                      OperandMode::kAllowRRR | OperandMode::kAllowRM, cont);
                } else {
                  cont->OverwriteAndNegateIfEqual(kNotEqual);
                  return VisitWord32BinOp(
                      this, node, kS390_Mul32WithOverflow,
                      OperandMode::kInt32Imm | OperandMode::kAllowDistinctOps,
                      cont);
                }
              case IrOpcode::kInt32AbsWithOverflow:
                cont->OverwriteAndNegateIfEqual(kOverflow);
                return VisitWord32UnaryOp(this, node, kS390_Abs32,
                                          OperandMode::kNone, cont);
              case IrOpcode::kInt64AbsWithOverflow:
                cont->OverwriteAndNegateIfEqual(kOverflow);
          
"""


```