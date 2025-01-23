Response: The user wants to understand the functionality of the provided C++ code snippet from the file `v8/src/compiler/backend/mips64/instruction-selector-mips64.cc`. This is the second part of a three-part series.

The code implements the `InstructionSelectorT` class for the MIPS64 architecture. This class is responsible for selecting the appropriate machine instructions for a given sequence of abstract operations represented in the Intermediate Representation (IR) of the V8 JavaScript engine.

The snippet primarily handles the selection of instructions for various operations related to:

1. **Floating-point number conversions:** Converting between different floating-point precisions (float32 and float64) and between floating-point and integer types (int32, int64, uint32, uint64).
2. **Integer conversions:** Converting between integer types (int32 and int64, uint32 and uint64).
3. **Bit manipulation:** Bitcasting between integer and floating-point types.
4. **Floating-point arithmetic operations:** Addition, subtraction, multiplication, division, modulo, maximum, minimum, absolute value, square root, rounding, and negation for both float32 and float64.
5. **Comparisons:** Comparing both integer and floating-point values.
6. **Function calls:** Preparing arguments and results for function calls.
7. **Unaligned memory access:** Loading and storing data from memory locations that are not properly aligned.
8. **Atomic operations:** Loading, storing, exchanging, and performing binary operations on memory locations atomically.
9. **Stack checks:** Comparing the stack pointer against a limit.

The code also demonstrates instruction selection optimizations, such as combining multiple IR nodes into a single machine instruction where possible.

Regarding the relationship with JavaScript, the code directly translates JavaScript's numerical operations into low-level machine instructions. The various `Visit...` methods correspond to different operations in the V8's IR, which in turn represent JavaScript operations.

For example, a JavaScript addition of two floating-point numbers would be represented by a `Float64Add` node in the IR, which would then be handled by the `VisitFloat64Add` method in this code to select the appropriate MIPS64 `add.d` instruction.
This code snippet from `v8/src/compiler/backend/mips64/instruction-selector-mips64.cc` focuses on **instruction selection for various numerical operations in the V8 JavaScript engine on the MIPS64 architecture**. It defines how high-level operations represented in V8's intermediate representation (IR) are translated into specific MIPS64 assembly instructions.

Here's a breakdown of its functionalities:

*   **Handling Floating-Point Conversions:** It includes logic for converting between `float32` and `float64`, and between floating-point numbers and integers (`int32`, `int64`, `uint32`, `uint64`). This involves selecting instructions like `trunc.w.d`, `cvt.s.d`, `cvt.d.w`, etc.
*   **Handling Integer Conversions:**  It details how to convert between `int32` and `int64`, and `uint32` and `uint64`. This might involve instructions like `sll` (shift left logical for sign extension), `dext` (extract bits), and specialized load instructions like `lw` (load word), `lbu` (load byte unsigned), etc., for sign-extending loads.
*   **Bit Manipulation:** It covers bitcasting operations between integer and floating-point types using instructions like `mov.s` and `mov.d`.
*   **Floating-Point Arithmetic:** It specifies the MIPS64 instructions for basic arithmetic operations (`add.s`, `add.d`, `sub.s`, `sub.d`, `mul.s`, `mul.d`, `div.s`, `div.d`), as well as more complex operations like modulo (`mod.d`), maximum (`max.s`, `max.d`), minimum (`min.s`, `min.d`), absolute value (`abs.s`, `abs.d`), square root (`sqrt.s`, `sqrt.d`), and negation (`neg.s`, `neg.d`). It also handles different rounding modes (`round.w.s`, `ceil.w.d`, `floor.w.s`, etc.).
*   **Comparisons:** It defines how to perform comparisons for both integer (`cmp`) and floating-point values (`c.eq.s`, `c.lt.d`, etc.) using `VisitCompare` helper functions. It also handles specific cases like comparing against zero and optimizing comparisons involving bitwise AND.
*   **Function Call Preparation:** It includes logic for preparing arguments and results for function calls (`EmitPrepareArguments`, `EmitPrepareResults`), including handling C function calls and stack allocation.
*   **Unaligned Memory Access:** It deals with loading and storing data from memory addresses that are not properly aligned, using instructions like `ulw`, `uld`, `usw`, `usd`, etc.
*   **Atomic Operations:** It describes how to translate atomic load (`ll`, `sc`), store, exchange (`amoadd.w`, `amoswap.d`), and compare-and-exchange (`ll`, `sc.cond`) operations into their respective MIPS64 instructions.
*   **Stack Checks:** It defines the instruction selection for checking if the stack pointer is greater than a certain limit (`kArchStackPointerGreaterThan`).

**Relationship to JavaScript (with examples):**

This code is a crucial part of how the V8 engine executes JavaScript code efficiently on MIPS64. Each `Visit...` function corresponds to a specific operation in V8's internal representation of JavaScript code.

For example:

**JavaScript:**

```javascript
let x = 1.5;
let y = 2.5;
let sum = x + y;
```

**Internal V8 Process (Simplified):**

1. V8 parses the JavaScript code and creates an Abstract Syntax Tree (AST).
2. The AST is converted into an Intermediate Representation (IR). In this case, the addition `x + y` (assuming `x` and `y` are represented as `float64`) might be represented by a `Float64Add` IR node.
3. The `InstructionSelectorT` (specifically the MIPS64 version in this file) will then visit the `Float64Add` node.
4. The `VisitFloat64Add` method in the code snippet will be executed, which will emit the MIPS64 instruction `add.d` to perform the floating-point addition.

**Another Example (Integer Conversion):**

**JavaScript:**

```javascript
let a = 10;
let b = BigInt(a);
```

**Internal V8 Process (Simplified):**

1. The conversion of the integer `a` to a `BigInt` might involve creating a representation of a 64-bit integer.
2. If the internal representation needs to explicitly convert a 32-bit integer to a 64-bit integer, an IR node like `ChangeInt32ToInt64` might be generated.
3. The `VisitChangeInt32ToInt64` method in the code snippet will be called. This method will then select the appropriate MIPS64 instruction(s), potentially `sll` with an immediate of 0 for sign extension, or a sign-extending load instruction if the value is being loaded from memory.

**Floating-Point Rounding Example:**

**JavaScript:**

```javascript
let num = 3.7;
let roundedDown = Math.floor(num);
```

**Internal V8 Process (Simplified):**

1. `Math.floor(num)` will likely be represented by a `Float64RoundDown` IR node.
2. The `VisitFloat64RoundDown` method will be invoked, resulting in the emission of the `round.w.d` MIPS64 instruction.

In essence, this code acts as a translator, bridging the gap between the high-level semantics of JavaScript numerical operations and the low-level instructions that the MIPS64 processor can understand and execute. It optimizes this translation process by recognizing patterns in the IR and selecting the most efficient corresponding machine instructions.

### 提示词
```
这是目录为v8/src/compiler/backend/mips64/instruction-selector-mips64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```
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
template <typename Adapter>
void VisitFloat32Compare(InstructionSelectorT<Adapter>* selector,
                         typename Adapter::node_t node,
                         FlagsContinuationT<Adapter>* cont) {
  Mips64OperandGeneratorT<Adapter> g(selector);
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
    VisitCompare(selector, kMips64CmpS, lhs, rhs, cont);
  } else {
    Float32BinopMatcher m(node);
    InstructionOperand lhs, rhs;

    lhs = m.left().IsZero() ? g.UseImmediate(m.left().node())
                            : g.UseRegister(m.left().node());
    rhs = m.right().IsZero() ? g.UseImmediate(m.right().node())
                             : g.UseRegister(m.right().node());
    VisitCompare(selector, kMips64CmpS, lhs, rhs, cont);
  }
}

// Shared routine for multiple float64 compare operations.
template <typename Adapter>
void VisitFloat64Compare(InstructionSelectorT<Adapter>* selector,
                         typename Adapter::node_t node,
                         FlagsContinuationT<Adapter>* cont) {
  if constexpr (Adapter::IsTurboshaft) {
    Mips64OperandGeneratorT<Adapter> g(selector);
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const Operation& compare = selector->Get(node);
    DCHECK(compare.Is<ComparisonOp>());
    OpIndex lhs = compare.input(0);
    OpIndex rhs = compare.input(1);
    if (selector->MatchZero(rhs)) {
      VisitCompare(selector, kMips64CmpD, g.UseRegister(lhs),
                   g.UseImmediate(rhs), cont);
    } else if (selector->MatchZero(lhs)) {
      VisitCompare(selector, kMips64CmpD, g.UseImmediate(lhs),
                   g.UseRegister(rhs), cont);
    } else {
      VisitCompare(selector, kMips64CmpD, g.UseRegister(lhs),
                   g.UseRegister(rhs), cont);
    }
  } else {
    Mips64OperandGeneratorT<Adapter> g(selector);
    Float64BinopMatcher m(node);
    InstructionOperand lhs, rhs;

    lhs = m.left().IsZero() ? g.UseImmediate(m.left().node())
                            : g.UseRegister(m.left().node());
    rhs = m.right().IsZero() ? g.UseImmediate(m.right().node())
                             : g.UseRegister(m.right().node());
    VisitCompare(selector, kMips64CmpD, lhs, rhs, cont);
  }
}

// Shared routine for multiple word compare operations.
template <typename Adapter>
Instruction* VisitWordCompare(InstructionSelectorT<Adapter>* selector,
                              typename Adapter::node_t node,
                              InstructionCode opcode,
                              FlagsContinuationT<Adapter>* cont,
                              bool commutative) {
  Mips64OperandGeneratorT<Adapter> g(selector);
  DCHECK_EQ(selector->value_input_count(node), 2);
  auto left = selector->input_at(node, 0);
  auto right = selector->input_at(node, 1);

  // Match immediates on left or right side of comparison.
  if (g.CanBeImmediate(right, opcode)) {
    if (opcode == kMips64Tst) {
      return VisitCompare(selector, opcode, g.UseRegister(left),
                          g.UseImmediate(right), cont);
    } else {
      switch (cont->condition()) {
        case kEqual:
        case kNotEqual:
          if (cont->IsSet()) {
            return VisitCompare(selector, opcode, g.UseRegister(left),
                                g.UseImmediate(right), cont);
          } else {
            return VisitCompare(selector, opcode, g.UseRegister(left),
                                g.UseRegister(right), cont);
          }
          break;
        case kSignedLessThan:
        case kSignedGreaterThanOrEqual:
        case kUnsignedLessThan:
        case kUnsignedGreaterThanOrEqual:
          return VisitCompare(selector, opcode, g.UseRegister(left),
                              g.UseImmediate(right), cont);
          break;
        default:
          return VisitCompare(selector, opcode, g.UseRegister(left),
                              g.UseRegister(right), cont);
      }
    }
  } else if (g.CanBeImmediate(left, opcode)) {
    if (!commutative) cont->Commute();
    if (opcode == kMips64Tst) {
      return VisitCompare(selector, opcode, g.UseRegister(right),
                          g.UseImmediate(left), cont);
    } else {
      switch (cont->condition()) {
        case kEqual:
        case kNotEqual:
          if (cont->IsSet()) {
            return VisitCompare(selector, opcode, g.UseRegister(right),
                                g.UseImmediate(left), cont);
          } else {
            return VisitCompare(selector, opcode, g.UseRegister(right),
                                g.UseRegister(left), cont);
          }
          break;
        case kSignedLessThan:
        case kSignedGreaterThanOrEqual:
        case kUnsignedLessThan:
        case kUnsignedGreaterThanOrEqual:
          return VisitCompare(selector, opcode, g.UseRegister(right),
                              g.UseImmediate(left), cont);
          break;
        default:
          return VisitCompare(selector, opcode, g.UseRegister(right),
                              g.UseRegister(left), cont);
      }
    }
  } else {
    return VisitCompare(selector, opcode, g.UseRegister(left),
                        g.UseRegister(right), cont);
  }
}

bool IsNodeUnsigned(Node* n) {
  NodeMatcher m(n);

  if (m.IsLoad() || m.IsUnalignedLoad() || m.IsProtectedLoad()) {
    LoadRepresentation load_rep = LoadRepresentationOf(n->op());
    return load_rep.IsUnsigned();
  } else if (m.IsWord32AtomicLoad() || m.IsWord64AtomicLoad()) {
    AtomicLoadParameters atomic_load_params = AtomicLoadParametersOf(n->op());
    LoadRepresentation load_rep = atomic_load_params.representation();
    return load_rep.IsUnsigned();
  } else {
    return m.IsUint32Div() || m.IsUint32LessThan() ||
           m.IsUint32LessThanOrEqual() || m.IsUint32Mod() ||
           m.IsUint32MulHigh() || m.IsChangeFloat64ToUint32() ||
           m.IsTruncateFloat64ToUint32() || m.IsTruncateFloat32ToUint32();
  }
}

// Shared routine for multiple word compare operations.
template <typename Adapter>
void VisitFullWord32Compare(InstructionSelectorT<Adapter>* selector,
                            typename Adapter::node_t node,
                            InstructionCode opcode,
                            FlagsContinuationT<Adapter>* cont) {
  Mips64OperandGeneratorT<Adapter> g(selector);
  InstructionOperand leftOp = g.TempRegister();
  InstructionOperand rightOp = g.TempRegister();

  selector->Emit(kMips64Dshl, leftOp,
                 g.UseRegister(selector->input_at(node, 0)),
                 g.TempImmediate(32));
  selector->Emit(kMips64Dshl, rightOp,
                 g.UseRegister(selector->input_at(node, 1)),
                 g.TempImmediate(32));

  Instruction* instr = VisitCompare(selector, opcode, leftOp, rightOp, cont);
  if constexpr (Adapter::IsTurboshaft) {
    selector->UpdateSourcePosition(instr, node);
  }
}

template <typename Adapter>
void VisitOptimizedWord32Compare(InstructionSelectorT<Adapter>* selector,
                                 Node* node, InstructionCode opcode,
                                 FlagsContinuationT<Adapter>* cont) {
  if (v8_flags.debug_code) {
    Mips64OperandGeneratorT<Adapter> g(selector);
    InstructionOperand leftOp = g.TempRegister();
    InstructionOperand rightOp = g.TempRegister();
    InstructionOperand optimizedResult = g.TempRegister();
    InstructionOperand fullResult = g.TempRegister();
    FlagsCondition condition = cont->condition();
    InstructionCode testOpcode = opcode |
                                 FlagsConditionField::encode(condition) |
                                 FlagsModeField::encode(kFlags_set);

    selector->Emit(testOpcode, optimizedResult, g.UseRegister(node->InputAt(0)),
                   g.UseRegister(node->InputAt(1)));

    selector->Emit(kMips64Dshl, leftOp, g.UseRegister(node->InputAt(0)),
                   g.TempImmediate(32));
    selector->Emit(kMips64Dshl, rightOp, g.UseRegister(node->InputAt(1)),
                   g.TempImmediate(32));
    selector->Emit(testOpcode, fullResult, leftOp, rightOp);

    selector->Emit(
        kMips64AssertEqual, g.NoOutput(), optimizedResult, fullResult,
        g.TempImmediate(
            static_cast<int>(AbortReason::kUnsupportedNonPrimitiveCompare)));
  }

  Instruction* instr = VisitWordCompare(selector, node, opcode, cont, false);
  if constexpr (Adapter::IsTurboshaft) {
    selector->UpdateSourcePosition(instr, node);
  }
}

template <typename Adapter>
void VisitWord32Compare(InstructionSelectorT<Adapter>* selector,
                        typename Adapter::node_t node,
                        FlagsContinuationT<Adapter>* cont) {
  if constexpr (Adapter::IsTurboshaft) {
    VisitFullWord32Compare(selector, node, kMips64Cmp, cont);
  } else {
    // MIPS64 doesn't support Word32 compare instructions. Instead it relies
    // that the values in registers are correctly sign-extended and uses
    // Word64 comparison instead. This behavior is correct in most cases,
    // but doesn't work when comparing signed with unsigned operands.
    // We could simulate full Word32 compare in all cases but this would
    // create an unnecessary overhead since unsigned integers are rarely
    // used in JavaScript.
    // The solution proposed here tries to match a comparison of signed
    // with unsigned operand, and perform full Word32Compare only
    // in those cases. Unfortunately, the solution is not complete because
    // it might skip cases where Word32 full compare is needed, so
    // basically it is a hack.
    // When calling a host function in the simulator, if the function returns an
    // int32 value, the simulator does not sign-extend it to int64 because in
    // the simulator we do not know whether the function returns an int32 or
    // an int64. So we need to do a full word32 compare in this case.
#ifndef USE_SIMULATOR
    if (IsNodeUnsigned(node->InputAt(0)) != IsNodeUnsigned(node->InputAt(1))) {
#else
    if (IsNodeUnsigned(node->InputAt(0)) != IsNodeUnsigned(node->InputAt(1)) ||
        node->InputAt(0)->opcode() == IrOpcode::kCall ||
        node->InputAt(1)->opcode() == IrOpcode::kCall) {
#endif
      VisitFullWord32Compare(selector, node, kMips64Cmp, cont);
    } else {
      VisitOptimizedWord32Compare(selector, node, kMips64Cmp, cont);
    }
  }
}

template <typename Adapter>
void VisitWord64Compare(InstructionSelectorT<Adapter>* selector,
                        typename Adapter::node_t node,
                        FlagsContinuationT<Adapter>* cont) {
  VisitWordCompare(selector, node, kMips64Cmp, cont, false);
}

template <typename Adapter>
void EmitWordCompareZero(InstructionSelectorT<Adapter>* selector,
                         typename Adapter::node_t value,
                         FlagsContinuationT<Adapter>* cont) {
  Mips64OperandGeneratorT<Adapter> g(selector);
  selector->EmitWithContinuation(kMips64Cmp, g.UseRegister(value),
                                 g.TempImmediate(0), cont);
}

template <typename Adapter>
void VisitAtomicLoad(InstructionSelectorT<Adapter>* selector,
                     typename Adapter::node_t node, AtomicWidth width) {
  using node_t = typename Adapter::node_t;
  Mips64OperandGeneratorT<Adapter> g(selector);
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
      code = kAtomicLoadWord32;
      break;
    case MachineRepresentation::kWord64:
      code = kMips64Word64AtomicLoadUint64;
      break;
    case MachineRepresentation::kTaggedSigned:   // Fall through.
    case MachineRepresentation::kTaggedPointer:  // Fall through.
    case MachineRepresentation::kTagged:
      DCHECK_EQ(kTaggedSize, 8);
      code = kMips64Word64AtomicLoadUint64;
      break;
    default:
      UNREACHABLE();
  }

  if (g.CanBeImmediate(index, code)) {
    selector->Emit(code | AddressingModeField::encode(kMode_MRI) |
                       AtomicWidthField::encode(width),
                   g.DefineAsRegister(node), g.UseRegister(base),
                   g.UseImmediate(index));
  } else {
    InstructionOperand addr_reg = g.TempRegister();
    selector->Emit(kMips64Dadd | AddressingModeField::encode(kMode_None),
                   addr_reg, g.UseRegister(index), g.UseRegister(base));
    // Emit desired load opcode, using temp addr_reg.
    selector->Emit(code | AddressingModeField::encode(kMode_MRI) |
                       AtomicWidthField::encode(width),
                   g.DefineAsRegister(node), addr_reg, g.TempImmediate(0));
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
  Mips64OperandGeneratorT<Adapter> g(selector);
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
    DCHECK_EQ(AtomicWidthSize(width), kTaggedSize);

    InstructionOperand inputs[3];
    size_t input_count = 0;
    inputs[input_count++] = g.UseUniqueRegister(base);
    inputs[input_count++] = g.UseUniqueRegister(index);
    inputs[input_count++] = g.UseUniqueRegister(value);
    RecordWriteMode record_write_mode =
        WriteBarrierKindToRecordWriteMode(write_barrier_kind);
    InstructionOperand temps[] = {g.TempRegister(), g.TempRegister()};
    size_t const temp_count = arraysize(temps);
    code = kArchAtomicStoreWithWriteBarrier;
    code |= RecordWriteModeField::encode(record_write_mode);
    selector->Emit(code, 0, nullptr, input_count, inputs, temp_count, temps);
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
        code = kMips64Word64AtomicStoreWord64;
        break;
      case MachineRepresentation::kTaggedSigned:   // Fall through.
      case MachineRepresentation::kTaggedPointer:  // Fall through.
      case MachineRepresentation::kTagged:
        DCHECK_EQ(AtomicWidthSize(width), kTaggedSize);
        code = kMips64StoreCompressTagged;
        break;
      default:
        UNREACHABLE();
    }
    code |= AtomicWidthField::encode(width);

    if (g.CanBeImmediate(index, code)) {
      selector->Emit(code | AddressingModeField::encode(kMode_MRI) |
                         AtomicWidthField::encode(width),
                     g.NoOutput(), g.UseRegister(base), g.UseImmediate(index),
                     g.UseRegisterOrImmediateZero(value));
    } else {
      InstructionOperand addr_reg = g.TempRegister();
      selector->Emit(kMips64Dadd | AddressingModeField::encode(kMode_None),
                     addr_reg, g.UseRegister(index), g.UseRegister(base));
      // Emit desired store opcode, using temp addr_reg.
      selector->Emit(code | AddressingModeField::encode(kMode_MRI) |
                         AtomicWidthField::encode(width),
                     g.NoOutput(), addr_reg, g.TempImmediate(0),
                     g.UseRegisterOrImmediateZero(value));
    }
  }
}

template <typename Adapter>
void VisitAtomicExchange(InstructionSelectorT<Adapter>* selector,
                         typename Adapter::node_t node, ArchOpcode opcode,
                         AtomicWidth width) {
  using node_t = typename Adapter::node_t;
  Mips64OperandGeneratorT<Adapter> g(selector);
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
  selector->Emit(code, 1, outputs, input_count, inputs, 3, temp);
}

template <typename Adapter>
void VisitAtomicCompareExchange(InstructionSelectorT<Adapter>* selector,
                                typename Adapter::node_t node,
                                ArchOpcode opcode, AtomicWidth width) {
  using node_t = typename Adapter::node_t;
  Mips64OperandGeneratorT<Adapter> g(selector);
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
  selector->Emit(code, 1, outputs, input_count, inputs, 3, temp);
}

template <typename Adapter>
void VisitAtomicBinop(InstructionSelectorT<Adapter>* selector,
                      typename Adapter::node_t node, ArchOpcode opcode,
                      AtomicWidth width) {
  using node_t = typename Adapter::node_t;
  Mips64OperandGeneratorT<Adapter> g(selector);
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

  Mips64OperandGeneratorT<Adapter> g(this);

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
  Mips64OperandGeneratorT<TurbofanAdapter> g(this);
  // Try to combine with comparisons against 0 by simply inverting the branch.
  while (CanCover(user, value)) {
    if (value->opcode() == IrOpcode::kWord32Equal) {
      Int32BinopMatcher m(value);
      if (!m.right().Is(0)) break;
      user = value;
      value = m.left().node();
    } else if (value->opcode() == IrOpcode::kWord64Equal) {
      Int64BinopMatcher m(value);
      if (!m.right().Is(0)) break;
      user = value;
      value = m.left().node();
    } else {
      break;
    }

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
                return VisitBinop(this, node, kMips64Dadd, cont);
              case IrOpcode::kInt32SubWithOverflow:
                cont->OverwriteAndNegateIfEqual(kOverflow);
                return VisitBinop(this, node, kMips64Dsub, cont);
              case IrOpcode::kInt32MulWithOverflow:
                cont->OverwriteAndNegateIfEqual(kOverflow);
                return VisitBinop(this, node, kMips64MulOvf, cont);
              case IrOpcode::kInt64MulWithOverflow:
                cont->OverwriteAndNegateIfEqual(kOverflow);
                return VisitBinop(this, node, kMips64DMulOvf, cont);
              case IrOpcode::kInt64AddWithOverflow:
                cont->OverwriteAndNegateIfEqual(kOverflow);
                return VisitBinop(this, node, kMips64DaddOvf, cont);
              case IrOpcode::kInt64SubWithOverflow:
                cont->OverwriteAndNegateIfEqual(kOverflow);
                return VisitBinop(this, node, kMips64DsubOvf, cont);
              default:
                break;
            }
          }
        }
        break;
      case IrOpcode::kWord32And:
      case IrOpcode::kWord64And:
        VisitWordCompare(this, value, kMips64Tst, cont, true);
        return;
      case IrOpcode::kStackPointerGreaterThan:
        cont->OverwriteAndNegateIfEqual(kStackPointerGreaterThanCondition);
        return VisitStackPointerGreaterThan(value, cont);
      default:
        break;
    }
  }

  // Continuation could not be combined with a compare, emit compare against
  // 0.
  EmitWordCompareZero(this, value, cont);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWordCompareZero(
    node_t user, node_t value, FlagsContinuation* cont) {
  {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    Mips64OperandGeneratorT<TurboshaftAdapter> g(this);
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

          case RegisterRepresentation::Float64():
            switch (comparison->kind) {
              case ComparisonOp::Kind::kEqual:
                cont->OverwriteAndNegateIfEqual(kEqual);
                return VisitFloat64Compare(this, value, cont);
              case ComparisonOp::Kind::kSignedLessThan:
                cont->OverwriteAndNegateIfEqual(kFloatLessThan);
                return VisitFloat64Compare(this, value, cont);
              case ComparisonOp::Kind::kSignedLessThanOrEqual:
                cont->OverwriteAndNegateIfEqual(kFloatLessThanOrEqual);
                return VisitFloat64Compare(this, value, cont);
              default:
                UNREACHABLE();
            }

          default:
            break;
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
                  return VisitBinop(this, node,
                                    is64 ? kMips64DaddOvf : kMips64Dadd, cont);
                case OverflowCheckedBinopOp::Kind::kSignedSub:
                  cont->OverwriteAndNegateIfEqual(kOverflow);
                  return VisitBinop(this, node,
                                    is64 ? kMips64DsubOvf : kMips64Dsub, cont);
                case OverflowCheckedBinopOp::Kind::kSignedMul:
                  cont->OverwriteAndNegateIfEqual(kOverflow);
                  return VisitBinop(
                      this, node, is64 ? kMips64DMulOvf : kMips64MulOvf, cont);
              }
            }
```