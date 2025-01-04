Response: The user wants a summary of the functionality of the provided C++ code snippet. This is the third part of a five-part file, `instruction-selector-x64.cc`, located within the V8 JavaScript engine's compiler backend for the x64 architecture.

The code primarily deals with *instruction selection*, a crucial step in the compilation process where high-level intermediate representation (IR) operations are translated into low-level machine instructions specific to the target architecture (x64 in this case).

The provided snippet seems to focus on handling various arithmetic, logical, floating-point, and comparison operations. It defines functions and templates that map these IR opcodes to corresponding x64 instructions.

Key observations:

1. **Opcode Handling:** The code uses `case` statements and helper functions like `VisitRO`, `VisitRR`, `VisitRRO`, and `VisitFloatBinop` to handle different IR opcodes. These opcodes correspond to operations like addition, subtraction, multiplication, division, comparisons, and floating-point operations.
2. **Operand Generation:** The `X64OperandGeneratorT` class is used to generate the operands for the x64 instructions. This involves determining whether operands can be registers, immediate values, or memory locations.
3. **Instruction Emission:** The `Emit` function is used to generate the actual x64 instructions. It takes the opcode and the operands as arguments.
4. **Zero Extension:** The code includes logic to check if certain 32-bit operations implicitly zero-extend to 64-bit on x64, optimizing the code by avoiding explicit zero-extension instructions.
5. **AVX and SSE Support:** The code considers both AVX and SSE instruction sets for floating-point operations, choosing the appropriate instruction based on the supported features.
6. **Memory Operands:** The code handles operations where one of the operands is in memory. It uses addressing modes to access memory locations.
7. **Flags and Continuations:** The `FlagsContinuationT` template is used to handle conditional branching and selection based on the result of comparisons.
8. **Atomic Operations:** There are functions to handle atomic operations like compare-and-swap.
9. **Call Handling:** The code includes functions for preparing arguments and results for function calls (both regular and C function calls).
10. **Optimization:**  The code includes optimizations like removing unnecessary `WordAnd` operations and combining comparisons with branching.

Relationship to JavaScript:

This code is part of the V8 engine, which executes JavaScript. The instruction selection process is a vital step in compiling JavaScript code into efficient machine code. When JavaScript performs operations like `+`, `-`, `*`, `/`, comparisons (`>`, `<`, `==`), or uses floating-point numbers, the V8 compiler's instruction selector uses logic similar to what's in this file to generate the corresponding x64 instructions.

Example in JavaScript:

```javascript
function add(a, b) {
  return a + b;
}

let x = 10;
let y = 5;
let sum = add(x, y); // JavaScript addition operation
```

When the V8 engine compiles the `add` function, the `a + b` operation will be represented by an IR opcode (likely `kInt32Add` or similar if `a` and `b` are integers). The `instruction-selector-x64.cc` file (or parts of it) will contain the logic to translate this `kInt32Add` opcode into the x64 `add` instruction.

Based on the context ("Part 3 of 5"), this part likely handles a specific subset of operations. Without the other parts, it's difficult to say precisely which operations are covered here versus other parts. However, this section seems heavily focused on basic arithmetic, logical, and floating-point computations and comparisons.
This C++ source code file, `instruction-selector-x64.cc`, specifically this **third part**, plays a crucial role in the **instruction selection phase** of the V8 JavaScript engine's compiler for the x64 architecture. Its primary function is to **translate high-level intermediate representation (IR) operations into low-level x64 machine instructions** for a specific set of operations.

Specifically, this part of the code focuses on generating x64 instructions for:

* **Integer Arithmetic Operations (32-bit):**  It handles `Int32Add`, `Int32Sub`, `Int32Mul`, `Int32Div`, `Int32Mod`, and related comparison operations (`Int32LessThan`, etc.). It also considers cases with overflow (`Int32AddWithOverflow`, etc.). A key optimization here is recognizing that many 32-bit operations on x64 implicitly zero-extend to 64 bits, making explicit zero-extension instructions unnecessary.
* **Integer Arithmetic Operations (64-bit truncation):** It handles `TruncateInt64ToInt32`, focusing on efficient ways to perform this conversion, often leveraging implicit zero-extension or optimizing for specific patterns like right shifts.
* **Bitwise Operations (Clz, Ctz, Popcnt):** It includes instructions for counting leading zeros (`Word64Clz`, `Word32Clz`), trailing zeros (`Word64Ctz`, `Word32Ctz`), and set bits (`Word64Popcnt`, `Word32Popcnt`).
* **Floating-Point Operations (Single and Double Precision):** It covers a wide range of floating-point operations like addition (`Float32Add`, `Float64Add`), subtraction, multiplication, division, square root, rounding, type conversions between integers and floats, and bitwise reinterpretations. It handles both SSE and AVX instruction sets for these operations, selecting the appropriate instruction based on available CPU features.
* **Floating-Point Comparisons:** It provides logic for comparing floating-point numbers (`Float32Compare`, `Float64Compare`) and handles the nuances of unordered comparisons (NaNs).
* **Conversions between Integer and Floating-Point Types:** It includes instructions for converting between integer and floating-point representations (`ChangeInt32ToFloat64`, `ChangeFloat64ToInt32`, etc.).
* **Bitwise Operations on Floating-Point Numbers:** It includes instructions to extract the low and high 32-bit words of a 64-bit float (`Float64ExtractLowWord32`, `Float64ExtractHighWord32`) and to perform bitcasts between floats and integers (`BitcastFloat32ToInt32`, `BitcastInt32ToFloat32`, etc.).
* **Sign Extension:** Instructions for sign-extending smaller integer types to 32-bit and 64-bit integers (`SignExtendWord8ToInt32`, `SignExtendWord16ToInt32`, etc.).
* **Handling of Constants:** It deals with how integer constants are loaded and how their values can influence zero-extension behavior.
* **Function Call Setup:** It includes logic for preparing arguments for function calls, including both regular JavaScript calls and C function calls. This involves pushing parameters onto the stack and handling potential alignment requirements. It also handles retrieving return values from function calls.
* **Tail Call Optimization:** It indicates whether tail calls with immediate addresses are possible on the x64 architecture.
* **Optimizations for Comparisons:** It includes optimizations for comparisons, such as handling comparisons with zero, comparisons involving memory operands, and removing unnecessary bitwise AND operations when the mask doesn't affect the comparison result. It also attempts to combine comparisons with preceding arithmetic or bitwise operations to reduce the number of instructions.
* **Atomic Operations:**  It contains functions to handle atomic read-modify-write operations (like addition) and atomic compare-and-exchange.

**Relationship to JavaScript and Examples:**

This code directly impacts how JavaScript code is executed on x64 processors. Whenever JavaScript code performs operations covered by this section, the V8 compiler uses this code to select the most efficient corresponding x64 instructions.

Here are some JavaScript examples and how they relate:

```javascript
// Integer arithmetic
let a = 10 + 5;  // Likely uses kInt32Add, potentially optimized for zero-extension
let b = a * 2;    // Likely uses kInt32Mul

// Floating-point arithmetic
let pi = 3.14;
let radius = 5.0;
let area = pi * radius * radius; // Likely uses kFloat64Mul

// Comparisons
if (a > b) {     // Likely uses kInt32LessThan (with negation)
  console.log("a is greater");
}

// Type conversions
let intValue = 42;
let floatValue = parseFloat(intValue); // Likely uses kSSEInt32ToFloat64

// Bitwise operations (though less common in typical JavaScript)
let mask = 0xFF;
let maskedValue = intValue & mask; // Could involve kWord32And

// Function calls
function myFunction(x, y) {
  return x + y;
}
let result = myFunction(1, 2); // The code prepares arguments (1 and 2) for the call

// Code that might trigger atomic operations (less common in typical JS, more in SharedArrayBuffers etc.)
// Atomics.add(sharedArray, index, value); // Would involve logic similar to VisitAtomicBinop
```

In essence, this part of `instruction-selector-x64.cc` is a critical bridge between the abstract operations defined in the JavaScript language and the concrete instructions executed by the x64 CPU. It's responsible for making JavaScript code run efficiently on x64 architectures by choosing the optimal machine instructions for various operations. The optimizations included aim to further enhance performance.

Prompt: 
```
这是目录为v8/src/compiler/backend/x64/instruction-selector-x64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共5部分，请归纳一下它的功能

"""
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
    // If the load representations don't match, both operands will be
    // zero/sign-extended to 32bit.
    left_type = MachineTypeForNarrow(selector, left, right);
    right_type = MachineTypeForNarrow(selector, right, left);
  }
  if (left_type == right_type) {
    switch (left_type.representation()) {
      case MachineRepresentation::kBit:
      case MachineRepresentation::kWord8: {
        if (opcode == kX64Test || opcode == kX64Test32) return kX64Test8;
        if (opcode == kX64Cmp || opcode == kX64Cmp32) {
          if (left_type.semantic() == MachineSemantic::kUint32) {
            cont->OverwriteUnsignedIfSigned();
          } else {
            CHECK_EQ(MachineSemantic::kInt32, left_type.semantic());
          }
          return kX64Cmp8;
        }
        break;
      }
      // Cmp16/Test16 may introduce LCP(Length-Changing-Prefixes) stall, use
      // Cmp32/Test32 instead.
      case MachineRepresentation::kWord16:  // Fall through.
      case MachineRepresentation::kWord32:
        if (opcode == kX64Test) return kX64Test32;
        if (opcode == kX64Cmp) {
          if (left_type.semantic() == MachineSemantic::kUint32) {
            cont->OverwriteUnsignedIfSigned();
          } else {
            CHECK_EQ(MachineSemantic::kInt32, left_type.semantic());
          }
          return kX64Cmp32;
        }
        break;
#ifdef V8_COMPRESS_POINTERS
      case MachineRepresentation::kTaggedSigned:
      case MachineRepresentation::kTaggedPointer:
      case MachineRepresentation::kTagged:
        // When pointer compression is enabled the lower 32-bits uniquely
        // identify tagged value.
        if (opcode == kX64Cmp) return kX64Cmp32;
        break;
#endif
      default:
        break;
    }
  }
  return opcode;
}

/*
Remove unnecessary WordAnd
For example:
33:  IfFalse(31)
517: Int32Constant[65535]
518: Word32And(18, 517)
36:  Int32Constant[266]
37:  Int32LessThanOrEqual(36, 518)
38:  Branch[None]

If Int32LessThanOrEqual select cmp16, the above Word32And can be removed:
33:  IfFalse(31)
36:  Int32Constant[266]
37:  Int32LessThanOrEqual(36, 18)
38:  Branch[None]
*/
template <typename Adapter>
typename Adapter::node_t RemoveUnnecessaryWordAnd(
    InstructionSelectorT<Adapter>* selector, InstructionCode opcode,
    typename Adapter::node_t and_node) {
  int64_t mask = 0;

  if (opcode == kX64Cmp32 || opcode == kX64Test32) {
    mask = std::numeric_limits<uint32_t>::max();
  } else if (opcode == kX64Cmp16 || opcode == kX64Test16) {
    mask = std::numeric_limits<uint16_t>::max();
  } else if (opcode == kX64Cmp8 || opcode == kX64Test8) {
    mask = std::numeric_limits<uint8_t>::max();
  } else {
    return and_node;
  }

  DCHECK_EQ(selector->value_input_count(and_node), 2);
  auto and_left = selector->input_at(and_node, 0);
  auto and_right = selector->input_at(and_node, 1);
  auto and_constant_node = typename Adapter::node_t{};
  auto and_other_node = typename Adapter::node_t{};
  if (IsIntConstant(selector, and_left)) {
    and_constant_node = and_left;
    and_other_node = and_right;
  } else if (IsIntConstant(selector, and_right)) {
    and_constant_node = and_right;
    and_other_node = and_left;
  }

  if (Adapter::valid(and_constant_node)) {
    int64_t and_constant = selector->integer_constant(and_constant_node);
    if (and_constant == mask) return and_other_node;
  }
  return and_node;
}

// Shared routine for multiple word compare operations.
template <typename Adapter>
void VisitWordCompare(InstructionSelectorT<Adapter>* selector,
                      typename Adapter::node_t node, InstructionCode opcode,
                      FlagsContinuationT<Adapter>* cont) {
  X64OperandGeneratorT<Adapter> g(selector);
  DCHECK_EQ(selector->value_input_count(node), 2);
  auto left = selector->input_at(node, 0);
  auto right = selector->input_at(node, 1);

  // The 32-bit comparisons automatically truncate Word64
  // values to Word32 range, no need to do that explicitly.
  if (opcode == kX64Cmp32 || opcode == kX64Test32) {
    if (selector->is_truncate_word64_to_word32(left)) {
      left = selector->input_at(left, 0);
    }
    if (selector->is_truncate_word64_to_word32(right)) {
      right = selector->input_at(right, 0);
    }
  }

  opcode = TryNarrowOpcodeSize(selector, opcode, left, right, cont);

  // If one of the two inputs is an immediate, make sure it's on the right, or
  // if one of the two inputs is a memory operand, make sure it's on the left.
  int effect_level = selector->GetEffectLevel(node, cont);

  if ((!g.CanBeImmediate(right) && g.CanBeImmediate(left)) ||
      (g.CanBeMemoryOperand(opcode, node, right, effect_level) &&
       !g.CanBeMemoryOperand(opcode, node, left, effect_level))) {
    if (!selector->IsCommutative(node)) cont->Commute();
    std::swap(left, right);
  }

  if (IsWordAnd(selector, left)) {
    left = RemoveUnnecessaryWordAnd(selector, opcode, left);
  }

  // Match immediates on right side of comparison.
  if (g.CanBeImmediate(right)) {
    if (g.CanBeMemoryOperand(opcode, node, left, effect_level)) {
      return VisitCompareWithMemoryOperand(selector, opcode, left,
                                           g.UseImmediate(right), cont);
    }
    return VisitCompare(selector, opcode, g.Use(left), g.UseImmediate(right),
                        cont);
  }

  // Match memory operands on left side of comparison.
  if (g.CanBeMemoryOperand(opcode, node, left, effect_level)) {
    return VisitCompareWithMemoryOperand(selector, opcode, left,
                                         g.UseRegister(right), cont);
  }

  return VisitCompare(selector, opcode, left, right, cont,
                      selector->IsCommutative(node));
}

template <typename Adapter>
void VisitWord64EqualImpl(InstructionSelectorT<Adapter>* selector,
                          typename Adapter::node_t node,
                          FlagsContinuationT<Adapter>* cont) {
  if (selector->CanUseRootsRegister()) {
    X64OperandGeneratorT<Adapter> g(selector);
    const RootsTable& roots_table = selector->isolate()->roots_table();
    RootIndex root_index;
    if constexpr (Adapter::IsTurboshaft) {
      using namespace turboshaft;  // NOLINT(build/namespaces)
      const ComparisonOp& equal =
          selector->Get(node).template Cast<ComparisonOp>();
      DCHECK_EQ(equal.kind, ComparisonOp::Kind::kEqual);
      Handle<HeapObject> object;
      if (equal.rep == RegisterRepresentation::Tagged() &&
          selector->MatchHeapConstant(equal.right(), &object)) {
        if (roots_table.IsRootHandle(object, &root_index)) {
          InstructionCode opcode =
              kX64Cmp | AddressingModeField::encode(kMode_Root);
          return VisitCompare(
              selector, opcode,
              g.TempImmediate(
                  MacroAssemblerBase::RootRegisterOffsetForRootIndex(
                      root_index)),
              g.UseRegister(equal.left()), cont);
        }
      }
    } else {
      HeapObjectBinopMatcher m(node);
      if (m.right().HasResolvedValue() &&
          roots_table.IsRootHandle(m.right().ResolvedValue(), &root_index)) {
        InstructionCode opcode =
            kX64Cmp | AddressingModeField::encode(kMode_Root);
        return VisitCompare(
            selector, opcode,
            g.TempImmediate(
                MacroAssemblerBase::RootRegisterOffsetForRootIndex(root_index)),
            g.UseRegister(m.left().node()), cont);
      }
    }
  }
  VisitWordCompare(selector, node, kX64Cmp, cont);
}

bool MatchHeapObjectEqual(InstructionSelectorT<TurbofanAdapter>* selector,
                          Node* node, Node** left, Handle<HeapObject>* right) {
  DCHECK_EQ(node->opcode(), IrOpcode::kWord32Equal);
  CompressedHeapObjectBinopMatcher m(node);
  if (m.right().HasResolvedValue()) {
    *left = m.left().node();
    *right = m.right().ResolvedValue();
    return true;
  }
  HeapObjectBinopMatcher m2(node);
  if (m2.right().HasResolvedValue()) {
    *left = m2.left().node();
    *right = m2.right().ResolvedValue();
    return true;
  }
  return false;
}

bool MatchHeapObjectEqual(InstructionSelectorT<TurboshaftAdapter>* selector,
                          turboshaft::OpIndex node, turboshaft::OpIndex* left,
                          Handle<HeapObject>* right) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const ComparisonOp& equal = selector->Get(node).Cast<ComparisonOp>();
  DCHECK_EQ(equal.kind, ComparisonOp::Kind::kEqual);
  if (selector->MatchHeapConstant(equal.right(), right)) {
    *left = equal.left();
    return true;
  }
  return false;
}

template <typename Adapter>
void VisitWord32EqualImpl(InstructionSelectorT<Adapter>* selector,
                          typename Adapter::node_t node,
                          FlagsContinuationT<Adapter>* cont) {
  if (COMPRESS_POINTERS_BOOL && selector->isolate()) {
    X64OperandGeneratorT<Adapter> g(selector);
    const RootsTable& roots_table = selector->isolate()->roots_table();
    RootIndex root_index;
    typename Adapter::node_t left;
    Handle<HeapObject> right;
    // HeapConstants and CompressedHeapConstants can be treated the same when
    // using them as an input to a 32-bit comparison. Check whether either is
    // present.
    if (MatchHeapObjectEqual(selector, node, &left, &right)) {
      if (roots_table.IsRootHandle(right, &root_index)) {
        DCHECK(Adapter::valid(left));
        if (RootsTable::IsReadOnly(root_index) &&
            (V8_STATIC_ROOTS_BOOL || !selector->isolate()->bootstrapper())) {
          return VisitCompare(
              selector, kX64Cmp32, g.UseRegister(left),
              g.TempImmediate(MacroAssemblerBase::ReadOnlyRootPtr(
                  root_index, selector->isolate())),
              cont);
        }
        if (selector->CanUseRootsRegister()) {
          InstructionCode opcode =
              kX64Cmp32 | AddressingModeField::encode(kMode_Root);
          return VisitCompare(
              selector, opcode,
              g.TempImmediate(
                  MacroAssemblerBase::RootRegisterOffsetForRootIndex(
                      root_index)),
              g.UseRegister(left), cont);
        }
      }
    }
  }
  VisitWordCompare(selector, node, kX64Cmp32, cont);
}

void VisitCompareZero(InstructionSelectorT<TurboshaftAdapter>* selector,
                      turboshaft::OpIndex user, turboshaft::OpIndex node,
                      InstructionCode opcode,
                      FlagsContinuationT<TurboshaftAdapter>* cont) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  X64OperandGeneratorT<TurboshaftAdapter> g(selector);
  const Operation& op = selector->turboshaft_graph()->Get(node);
  if (cont->IsBranch() &&
      (cont->condition() == kNotEqual || cont->condition() == kEqual)) {
    if (const WordBinopOp* binop = op.TryCast<WordBinopOp>()) {
      if (selector->IsOnlyUserOfNodeInSameBlock(user, node)) {
        const bool is64 = binop->rep == WordRepresentation::Word64();
        switch (binop->kind) {
          case WordBinopOp::Kind::kAdd:
            return VisitBinop(selector, node, is64 ? kX64Add : kX64Add32, cont);
          case WordBinopOp::Kind::kSub:
            return VisitBinop(selector, node, is64 ? kX64Sub : kX64Sub32, cont);
          case WordBinopOp::Kind::kBitwiseAnd:
            return VisitBinop(selector, node, is64 ? kX64And : kX64And32, cont);
          case WordBinopOp::Kind::kBitwiseOr:
            return VisitBinop(selector, node, is64 ? kX64Or : kX64Or32, cont);
          default:
            break;
        }
      }
    } else if (const ShiftOp* shift = op.TryCast<ShiftOp>()) {
      if (selector->IsOnlyUserOfNodeInSameBlock(user, node)) {
        const bool is64 = shift->rep == WordRepresentation::Word64();
        switch (shift->kind) {
          case ShiftOp::Kind::kShiftLeft:
            if (TryVisitWordShift(selector, node, is64 ? 64 : 32,
                                  is64 ? kX64Shl : kX64Shl32, cont)) {
              return;
            }
            break;
          case ShiftOp::Kind::kShiftRightLogical:
            if (TryVisitWordShift(selector, node, is64 ? 64 : 32,
                                  is64 ? kX64Shr : kX64Shr32, cont)) {
              return;
            }
            break;
          default:
            break;
        }
      }
    }
  }

  int effect_level = selector->GetEffectLevel(node, cont);
  if (const auto load = op.TryCast<turboshaft::LoadOp>()) {
    if (load->loaded_rep == turboshaft::MemoryRepresentation::Int8() ||
        load->loaded_rep == turboshaft::MemoryRepresentation::Uint8()) {
      if (opcode == kX64Cmp32) {
        opcode = kX64Cmp8;
      } else if (opcode == kX64Test32) {
        opcode = kX64Test8;
      }
    } else if (load->loaded_rep == turboshaft::MemoryRepresentation::Int16() ||
               load->loaded_rep == turboshaft::MemoryRepresentation::Uint16()) {
      if (opcode == kX64Cmp32) {
        opcode = kX64Cmp16;
      } else if (opcode == kX64Test32) {
        opcode = kX64Test16;
      }
    }
  }
  if (g.CanBeMemoryOperand(opcode, user, node, effect_level)) {
    VisitCompareWithMemoryOperand(selector, opcode, node, g.TempImmediate(0),
                                  cont);
  } else {
    VisitCompare(selector, opcode, g.Use(node), g.TempImmediate(0), cont);
  }
}

// Shared routine for comparison with zero.
void VisitCompareZero(InstructionSelectorT<TurbofanAdapter>* selector,
                      Node* user, Node* node, InstructionCode opcode,
                      FlagsContinuationT<TurbofanAdapter>* cont) {
  X64OperandGeneratorT<TurbofanAdapter> g(selector);
  if (cont->IsBranch() &&
      (cont->condition() == kNotEqual || cont->condition() == kEqual)) {
    switch (node->opcode()) {
#define FLAGS_SET_BINOP_LIST(V)        \
  V(kInt32Add, VisitBinop, kX64Add32)  \
  V(kInt32Sub, VisitBinop, kX64Sub32)  \
  V(kWord32And, VisitBinop, kX64And32) \
  V(kWord32Or, VisitBinop, kX64Or32)   \
  V(kInt64Add, VisitBinop, kX64Add)    \
  V(kInt64Sub, VisitBinop, kX64Sub)    \
  V(kWord64And, VisitBinop, kX64And)   \
  V(kWord64Or, VisitBinop, kX64Or)
#define FLAGS_SET_BINOP(opcode, Visit, archOpcode)           \
  case IrOpcode::opcode:                                     \
    if (selector->IsOnlyUserOfNodeInSameBlock(user, node)) { \
      return Visit(selector, node, archOpcode, cont);        \
    }                                                        \
    break;
      FLAGS_SET_BINOP_LIST(FLAGS_SET_BINOP)
#undef FLAGS_SET_BINOP_LIST
#undef FLAGS_SET_BINOP

// Skip Word64Sar/Word32Sar since no instruction reduction in most cases.
#define FLAGS_SET_SHIFT_LIST(V) \
  V(kWord32Shl, 32, kX64Shl32)  \
  V(kWord32Shr, 32, kX64Shr32)  \
  V(kWord64Shl, 64, kX64Shl)    \
  V(kWord64Shr, 64, kX64Shr)
#define FLAGS_SET_SHIFT(opcode, bits, archOpcode)                            \
  case IrOpcode::opcode:                                                     \
    if (selector->IsOnlyUserOfNodeInSameBlock(user, node)) {                 \
      if (TryVisitWordShift(selector, node, bits, archOpcode, cont)) return; \
    }                                                                        \
    break;
      FLAGS_SET_SHIFT_LIST(FLAGS_SET_SHIFT)
#undef TRY_VISIT_WORD32_SHIFT
#undef TRY_VISIT_WORD64_SHIFT
#undef FLAGS_SET_SHIFT_LIST
#undef FLAGS_SET_SHIFT
      default:
        break;
    }
  }
  int effect_level = selector->GetEffectLevel(node, cont);
  if (node->opcode() == IrOpcode::kLoad ||
      node->opcode() == IrOpcode::kLoadImmutable) {
    switch (LoadRepresentationOf(node->op()).representation()) {
      case MachineRepresentation::kWord8:
        if (opcode == kX64Cmp32) {
          opcode = kX64Cmp8;
        } else if (opcode == kX64Test32) {
          opcode = kX64Test8;
        }
        break;
      case MachineRepresentation::kWord16:
        if (opcode == kX64Cmp32) {
          opcode = kX64Cmp16;
        } else if (opcode == kX64Test32) {
          opcode = kX64Test16;
        }
        break;
      default:
        break;
    }
  }
  if (g.CanBeMemoryOperand(opcode, user, node, effect_level)) {
    VisitCompareWithMemoryOperand(selector, opcode, node, g.TempImmediate(0),
                                  cont);
  } else {
    VisitCompare(selector, opcode, g.Use(node), g.TempImmediate(0), cont);
  }
}

// Shared routine for multiple float32 compare operations (inputs commuted).
template <typename Adapter>
void VisitFloat32Compare(InstructionSelectorT<Adapter>* selector,
                         typename Adapter::node_t node,
                         FlagsContinuationT<Adapter>* cont) {
  auto left = selector->input_at(node, 0);
  auto right = selector->input_at(node, 1);
  InstructionCode const opcode =
      selector->IsSupported(AVX) ? kAVXFloat32Cmp : kSSEFloat32Cmp;
  VisitCompare(selector, opcode, right, left, cont, false);
}

// Shared routine for multiple float64 compare operations (inputs commuted).
template <typename Adapter>
void VisitFloat64Compare(InstructionSelectorT<Adapter>* selector,
                         typename Adapter::node_t node,
                         FlagsContinuationT<Adapter>* cont) {
  auto left = selector->input_at(node, 0);
  auto right = selector->input_at(node, 1);
  InstructionCode const opcode =
      selector->IsSupported(AVX) ? kAVXFloat64Cmp : kSSEFloat64Cmp;
  VisitCompare(selector, opcode, right, left, cont, false);
}

// Shared routine for Word32/Word64 Atomic Binops
template <typename Adapter>
void VisitAtomicBinop(InstructionSelectorT<Adapter>* selector,
                      typename Adapter::node_t node, ArchOpcode opcode,
                      AtomicWidth width, MemoryAccessKind access_kind) {
  auto atomic_op = selector->atomic_rmw_view(node);
  X64OperandGeneratorT<Adapter> g(selector);
  AddressingMode addressing_mode;
  InstructionOperand inputs[] = {
      g.UseUniqueRegister(atomic_op.value()),
      g.UseUniqueRegister(atomic_op.base()),
      g.GetEffectiveIndexOperand(atomic_op.index(), &addressing_mode)};
  InstructionOperand outputs[] = {g.DefineAsFixed(node, rax)};
  InstructionOperand temps[] = {g.TempRegister()};
  InstructionCode code = opcode | AddressingModeField::encode(addressing_mode) |
                         AtomicWidthField::encode(width);
  if (access_kind == MemoryAccessKind::kProtectedByTrapHandler) {
    code |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
  }
  selector->Emit(code, arraysize(outputs), outputs, arraysize(inputs), inputs,
                 arraysize(temps), temps);
}

// Shared routine for Word32/Word64 Atomic CmpExchg
template <typename Adapter>
void VisitAtomicCompareExchange(InstructionSelectorT<Adapter>* selector,
                                typename Adapter::node_t node,
                                ArchOpcode opcode, AtomicWidth width,
                                MemoryAccessKind access_kind) {
  auto atomic_op = selector->atomic_rmw_view(node);
  X64OperandGeneratorT<Adapter> g(selector);
  AddressingMode addressing_mode;
  InstructionOperand inputs[] = {
      g.UseFixed(atomic_op.expected(), rax),
      g.UseUniqueRegister(atomic_op.value()),
      g.UseUniqueRegister(atomic_op.base()),
      g.GetEffectiveIndexOperand(atomic_op.index(), &addressing_mode)};
  InstructionOperand outputs[] = {g.DefineAsFixed(node, rax)};
  InstructionCode code = opcode | AddressingModeField::encode(addressing_mode) |
                         AtomicWidthField::encode(width);
  if (access_kind == MemoryAccessKind::kProtectedByTrapHandler) {
    code |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
  }
  selector->Emit(code, arraysize(outputs), outputs, arraysize(inputs), inputs);
}

}  // namespace

// Shared routine for word comparison against zero.
template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWordCompareZero(
    node_t user, node_t value, FlagsContinuation* cont) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  // Try to combine with comparisons against 0 by simply inverting the branch.
  ConsumeEqualZero(&user, &value, cont);

  if (CanCover(user, value)) {
    const Operation& value_op = this->Get(value);
    if (const ComparisonOp* comparison = value_op.TryCast<ComparisonOp>()) {
      if (comparison->kind == ComparisonOp::Kind::kEqual) {
        switch (comparison->rep.MapTaggedToWord().value()) {
          case RegisterRepresentation::Word32():
            cont->OverwriteAndNegateIfEqual(kEqual);
            return VisitWord32EqualImpl(this, value, cont);
          case RegisterRepresentation::Word64(): {
            cont->OverwriteAndNegateIfEqual(kEqual);
            if (this->MatchIntegralZero(comparison->right())) {
              // Try to combine the branch with a comparison.
              if (CanCover(value, comparison->left())) {
                const Operation& left_op = this->Get(comparison->left());
                if (left_op.Is<Opmask::kWord64Sub>()) {
                  return VisitWordCompare(this, comparison->left(), kX64Cmp,
                                          cont);
                } else if (left_op.Is<Opmask::kWord64BitwiseAnd>()) {
                  return VisitWordCompare(this, comparison->left(), kX64Test,
                                          cont);
                }
              }
              return VisitCompareZero(this, value, comparison->left(), kX64Cmp,
                                      cont);
            }
            return VisitWord64EqualImpl(this, value, cont);
          }
          case RegisterRepresentation::Float32():
            cont->OverwriteAndNegateIfEqual(kUnorderedEqual);
            return VisitFloat32Compare(this, value, cont);
          case RegisterRepresentation::Float64(): {
            bool is_self_compare =
                this->input_at(value, 0) == this->input_at(value, 1);
            cont->OverwriteAndNegateIfEqual(is_self_compare ? kIsNotNaN
                                                            : kUnorderedEqual);
            return VisitFloat64Compare(this, value, cont);
          }
          default:
            break;
        }
      } else {
        switch (comparison->rep.MapTaggedToWord().value()) {
          case RegisterRepresentation::Word32(): {
            cont->OverwriteAndNegateIfEqual(
                GetComparisonFlagCondition(*comparison));
            return VisitWordCompare(this, value, kX64Cmp32, cont);
          }
          case RegisterRepresentation::Word64(): {
            cont->OverwriteAndNegateIfEqual(
                GetComparisonFlagCondition(*comparison));
            return VisitWordCompare(this, value, kX64Cmp, cont);
          }
          case RegisterRepresentation::Float32():
            if (comparison->kind == ComparisonOp::Kind::kSignedLessThan) {
              cont->OverwriteAndNegateIfEqual(kUnsignedGreaterThan);
              return VisitFloat32Compare(this, value, cont);
            } else {
              DCHECK_EQ(comparison->kind,
                        ComparisonOp::Kind::kSignedLessThanOrEqual);
              cont->OverwriteAndNegateIfEqual(kUnsignedGreaterThanOrEqual);
              return VisitFloat32Compare(this, value, cont);
            }
          case RegisterRepresentation::Float64():
            if (comparison->kind == ComparisonOp::Kind::kSignedLessThan) {
              if (MatchZero(comparison->left())) {
                const Operation& right = this->Get(comparison->right());
                if (right.Is<Opmask::kFloat64Abs>()) {
                  // This matches the pattern
                  //
                  //   Float64LessThan(#0.0, Float64Abs(x))
                  //
                  // which TurboFan generates for NumberToBoolean in the general
                  // case, and which evaluates to false if x is 0, -0 or NaN. We
                  // can compile this to a simple (v)ucomisd using not_equal
                  // flags condition, which avoids the costly Float64Abs.
                  cont->OverwriteAndNegateIfEqual(kNotEqual);
                  InstructionCode const opcode =
                      IsSupported(AVX) ? kAVXFloat64Cmp : kSSEFloat64Cmp;
                  return VisitCompare(this, opcode, comparison->left(),
                                      right.Cast<FloatUnaryOp>().input(), cont,
                                      false);
                }
              }
              cont->OverwriteAndNegateIfEqual(kUnsignedGreaterThan);
              return VisitFloat64Compare(this, value, cont);
            } else {
              DCHECK_EQ(comparison->kind,
                        ComparisonOp::Kind::kSignedLessThanOrEqual);
              cont->OverwriteAndNegateIfEqual(kUnsignedGreaterThanOrEqual);
              return VisitFloat64Compare(this, value, cont);
            }
          default:
            break;
        }
      }
    } else if (value_op.Is<Opmask::kWord32Sub>()) {
      return VisitWordCompare(this, value, kX64Cmp32, cont);
    } else if (value_op.Is<Opmask::kWord32BitwiseAnd>()) {
      return VisitWordCompare(this, value, kX64Test32, cont);
    } else if (const ProjectionOp* projection =
                   value_op.TryCast<ProjectionOp>()) {
      // Check if this is the overflow output projection of an
      // OverflowCheckedBinop operation.
      if (projection->index == 1u) {
        // We cannot combine the OverflowCheckedBinop operation with this branch
        // unless the 0th projection (the use of the actual value of the
        // operation is either {OpIndex::Invalid()}, which means there's no use
        // of the actual value, or was already defined, which means it is
        // scheduled *AFTER* this branch).
        OpIndex node = projection->input();
        OpIndex result = FindProjection(node, 0);
        if (!result.valid() || IsDefined(result)) {
          if (const OverflowCheckedBinopOp* binop =
                  this->TryCast<OverflowCheckedBinopOp>(node)) {
            const bool is64 = binop->rep == WordRepresentation::Word64();
            cont->OverwriteAndNegateIfEqual(kOverflow);
            switch (binop->kind) {
              case OverflowCheckedBinopOp::Kind::kSignedAdd:
                return VisitBinop(this, node, is64 ? kX64Add : kX64Add32, cont);
              case OverflowCheckedBinopOp::Kind::kSignedSub:
                return VisitBinop(this, node, is64 ? kX64Sub : kX64Sub32, cont);
              case OverflowCheckedBinopOp::Kind::kSignedMul:
                return VisitBinop(this, node, is64 ? kX64Imul : kX64Imul32,
                                  cont);
            }
            UNREACHABLE();
          }
        }
      }
    } else if (value_op.Is<StackPointerGreaterThanOp>()) {
      cont->OverwriteAndNegateIfEqual(kStackPointerGreaterThanCondition);
      return VisitStackPointerGreaterThan(value, cont);
    }
  }

  // Branch could not be combined with a compare, emit compare against 0.
  VisitCompareZero(this, user, value, kX64Cmp32, cont);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitWordCompareZero(
    Node* user, Node* value, FlagsContinuation* cont) {
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
        return VisitWord32EqualImpl(this, value, cont);
      case IrOpcode::kInt32LessThan:
        cont->OverwriteAndNegateIfEqual(kSignedLessThan);
        return VisitWordCompare(this, value, kX64Cmp32, cont);
      case IrOpcode::kInt32LessThanOrEqual:
        cont->OverwriteAndNegateIfEqual(kSignedLessThanOrEqual);
        return VisitWordCompare(this, value, kX64Cmp32, cont);
      case IrOpcode::kUint32LessThan:
        cont->OverwriteAndNegateIfEqual(kUnsignedLessThan);
        return VisitWordCompare(this, value, kX64Cmp32, cont);
      case IrOpcode::kUint32LessThanOrEqual:
        cont->OverwriteAndNegateIfEqual(kUnsignedLessThanOrEqual);
        return VisitWordCompare(this, value, kX64Cmp32, cont);
      case IrOpcode::kWord64Equal: {
        cont->OverwriteAndNegateIfEqual(kEqual);
        Int64BinopMatcher m(value);
        if (m.right().Is(0)) {
          // Try to combine the branch with a comparison.
          Node* const eq_user = m.node();
          Node* const eq_value = m.left().node();
          if (CanCover(eq_user, eq_value)) {
            switch (eq_value->opcode()) {
              case IrOpcode::kInt64Sub:
                return VisitWordCompare(this, eq_value, kX64Cmp, cont);
              case IrOpcode::kWord64And:
                return VisitWordCompare(this, eq_value, kX64Test, cont);
              default:
                break;
            }
          }
          return VisitCompareZero(this, eq_user, eq_value, kX64Cmp, cont);
        }
        return VisitWord64EqualImpl(this, value, cont);
      }
      case IrOpcode::kInt64LessThan:
        cont->OverwriteAndNegateIfEqual(kSignedLessThan);
        return VisitWordCompare(this, value, kX64Cmp, cont);
      case IrOpcode::kInt64LessThanOrEqual:
        cont->OverwriteAndNegateIfEqual(kSignedLessThanOrEqual);
        return VisitWordCompare(this, value, kX64Cmp, cont);
      case IrOpcode::kUint64LessThan:
        cont->OverwriteAndNegateIfEqual(kUnsignedLessThan);
        return VisitWordCompare(this, value, kX64Cmp, cont);
      case IrOpcode::kUint64LessThanOrEqual:
        cont->OverwriteAndNegateIfEqual(kUnsignedLessThanOrEqual);
        return VisitWordCompare(this, value, kX64Cmp, cont);
      case IrOpcode::kFloat32Equal:
        cont->OverwriteAndNegateIfEqual(kUnorderedEqual);
        return VisitFloat32Compare(this, value, cont);
      case IrOpcode::kFloat32LessThan:
        cont->OverwriteAndNegateIfEqual(kUnsignedGreaterThan);
        return VisitFloat32Compare(this, value, cont);
      case IrOpcode::kFloat32LessThanOrEqual:
        cont->OverwriteAndNegateIfEqual(kUnsignedGreaterThanOrEqual);
        return VisitFloat32Compare(this, value, cont);
      case IrOpcode::kFloat64Equal: {
        bool is_self_compare =
            this->input_at(value, 0) == this->input_at(value, 1);
        cont->OverwriteAndNegateIfEqual(is_self_compare ? kIsNotNaN
                                                        : kUnorderedEqual);
        return VisitFloat64Compare(this, value, cont);
      }
      case IrOpcode::kFloat64LessThan: {
        Float64BinopMatcher m(value);
        if (m.left().Is(0.0) && m.right().IsFloat64Abs()) {
          // This matches the pattern
          //
          //   Float64LessThan(#0.0, Float64Abs(x))
          //
          // which TurboFan generates for NumberToBoolean in the general case,
          // and which evaluates to false if x is 0, -0 or NaN. We can compile
          // this to a simple (v)ucomisd using not_equal flags condition, which
          // avoids the costly Float64Abs.
          cont->OverwriteAndNegateIfEqual(kNotEqual);
          InstructionCode const opcode =
              IsSupported(AVX) ? kAVXFloat64Cmp : kSSEFloat64Cmp;
          return VisitCompare(this, opcode, m.left().node(),
                              m.right().InputAt(0), cont, false);
        }
        cont->OverwriteAndNegateIfEqual(kUnsignedGreaterThan);
        return VisitFloat64Compare(this, value, cont);
      }
      case IrOpcode::kFloat64LessThanOrEqual:
        cont->OverwriteAndNegateIfEqual(kUnsignedGreaterThanOrEqual);
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
                return VisitBinop(this, node, kX64Add32, cont);
              case IrOpcode::kInt32SubWithOverflow:
                cont->OverwriteAndNegateIfEqual(kOverflow);
                return VisitBinop(this, node, kX64Sub32, cont);

"""


```