Response:
Let's break down the thought process for analyzing this code snippet.

1. **Initial Understanding:** The code is a C++ file (`.cc`) for V8's S390 architecture, specifically within the `compiler/backend` directory. The filename `instruction-selector-s390.cc` strongly suggests it's responsible for selecting machine instructions for the S390 architecture based on the intermediate representation (IR) of the JavaScript code.

2. **High-Level Structure Identification:** The code starts with a series of `#define` macros. These are used to generate similar code for different data types (Word32, Word64, Float). This pattern is common for reducing code duplication.

3. **Macro Analysis (Key Insight):** The macros `*_UNARY_OP_LIST` and `*_BIN_OP_LIST` are crucial. They define lists of operations, linking V8's internal operation names (e.g., `Word32Or`, `Int64AddWithOverflow`) to specific S390 assembly instructions (e.g., `kS390_Or32`, `kS390_Add64`). The `OperandMode` and `try_extra` parts hint at how operands are handled and potential optimization logic.

4. **`DECLARE_UNARY_OP` and `DECLARE_BIN_OP` Macros:** These macros further reveal the code's structure. They define template functions `Visit##name` that handle the instruction selection for each operation listed in the previous macros. The `Visit##type##UnaryOp` and `Visit##type##BinOp` suggest a generic handling mechanism.

5. **Specific `Visit` Function Analysis:**  The code then presents a series of concrete `Visit` functions like `VisitTryTruncateFloat32ToInt64`, `VisitFloat64Mod`, `VisitInt64MulWithOverflow`. These functions implement the specific logic for translating a higher-level operation into one or more S390 instructions. The use of `S390OperandGeneratorT` points to a helper class for managing operands. The `Emit` function is likely the core mechanism for emitting the selected S390 instruction.

6. **Comparison Logic:**  The section with `VisitCompare`, `VisitWordCompare`, `VisitFloat32Compare`, `VisitFloat64Compare`, and `VisitTestUnderMask` is clearly focused on handling comparison operations. The `FlagsContinuation` suggests dealing with setting and using CPU flags for conditional branching. The logic for optimizing comparisons with zero is interesting.

7. **`VisitWordCompareZero` (Key Optimization):**  This function appears to be a significant optimization. It tries to combine comparisons with zero with the preceding operation, potentially avoiding an explicit compare instruction. It checks for specific patterns (e.g., comparing the result of a subtraction with zero) and modifies the flags continuation accordingly. This is a classic compiler optimization technique.

8. **Answering the Specific Questions:**

   * **Functionality:** Based on the analysis, the primary function is instruction selection for S390, mapping V8's IR to S390 assembly.
   * **Torque:** The filename doesn't end in `.tq`, so it's not Torque.
   * **JavaScript Relation:** Yes, it's directly related. It takes the output of V8's JavaScript compilation pipeline (the IR) and generates the final machine code that the CPU executes.
   * **JavaScript Example:**  Simple arithmetic operations, comparisons, and type conversions in JavaScript will eventually be processed by this code.
   * **Code Logic Inference:** The `VisitWordCompareZero` provides good examples. Input: a JavaScript `if (x - 5 == 0)` statement (represented in IR). Output: S390 instruction that performs the subtraction and sets flags, potentially without an explicit compare-to-zero instruction if the optimization applies.
   * **Common Programming Errors:** Overflow errors in arithmetic operations are explicitly handled (e.g., `Int64AddWithOverflow`). A common mistake is relying on wrapping behavior instead of checking for overflow.
   * **Part 4 Summary:** This part specifically deals with the implementation details of instruction selection for various arithmetic, logical, comparison, and type conversion operations on 32-bit and 64-bit integers and floating-point numbers. It includes optimizations like combining comparisons with zero.

9. **Refinement and Structure:** Organize the findings logically, starting with the core functionality and then addressing the specific questions in order. Use clear and concise language. Highlight the key aspects like instruction selection, the role of macros, and the optimization techniques.

This detailed thought process allows for a comprehensive understanding of the code snippet and helps in answering the user's questions accurately and thoroughly.
Based on the provided C++ code snippet from `v8/src/compiler/backend/s390/instruction-selector-s390.cc`, here's a breakdown of its functionality:

**Core Functionality:**

This code snippet is a part of the **instruction selector** for the S390 architecture within the V8 JavaScript engine's optimizing compiler. Its primary function is to **translate intermediate representation (IR) nodes** (representing operations in the compiled JavaScript code) **into specific S390 machine instructions.**

Here's a more detailed breakdown:

* **Operation Mapping:** It defines mappings between high-level operations (like addition, subtraction, bitwise operations, comparisons, type conversions) and their corresponding S390 assembly instructions. This is evident in the `*_OP_LIST` macros (e.g., `WORD32_BIN_OP_LIST`, `FLOAT_UNARY_OP_LIST`). Each entry in these lists associates a V8 operation name (e.g., `Word32Or`) with an S390 instruction code (e.g., `kS390_Or32`) and potentially an operand mode.
* **Operand Handling:** The `OperandMode` specifies how the operands of the instruction should be handled (e.g., whether an immediate value is allowed, specific register constraints).
* **Instruction Emission:** The `Visit##name` functions (generated by the `DECLARE_*_OP` macros) are responsible for handling specific IR nodes. They typically use an `S390OperandGeneratorT` to manage operands and then call an `Emit` function to generate the actual S390 instruction.
* **Optimization and Special Cases:** The code includes logic for specific optimizations or handling of particular scenarios. Examples include:
    * `TryMatchSignExtInt16OrInt8FromWord32Sar`:  Potentially trying to match a signed extension from a shift operation.
    * `TryMatchInt64AddWithOverflow`, `TryMatchInt64SubWithOverflow`: Handling operations that can result in overflow.
    * `TryMatchShiftFromMul`, `TryMatchNegFromSub`: Recognizing patterns to use more efficient shift or negate instructions.
    * The `VisitWordCompareZero` function attempts to combine comparisons with zero with preceding operations for optimization.
* **Handling Comparisons and Branches:** A significant portion deals with translating comparison operations (`kInt32LessThan`, `kFloat64Equal`, etc.) into S390 compare instructions (`kS390_Cmp32`, `kS390_CmpDouble`) and managing the `FlagsContinuation` to handle conditional branching based on the comparison result.
* **Type Conversions:**  Functions like `VisitTryTruncateFloat32ToInt64` handle the translation of floating-point to integer conversions.
* **Overflow Handling:**  The code explicitly deals with operations that can overflow (e.g., `Int64AddWithOverflow`, `Int64MulWithOverflow`) and how to check for and potentially branch based on overflow conditions.

**Is it a Torque file?**

No, the code snippet is from a `.cc` file, which indicates it's a standard C++ source file. If it were a Torque file, it would end with `.tq`.

**Relationship to JavaScript and Examples:**

This code is directly responsible for the performance of JavaScript code executed on S390 architectures. Every time a JavaScript operation is performed, the optimizing compiler in V8 uses code like this to select the most efficient S390 machine instructions to execute that operation.

**JavaScript Examples:**

```javascript
// Simple addition
let a = 10;
let b = 20;
let sum = a + b; // The instruction selector will generate an S390 add instruction.

// Bitwise OR
let flags = 0b0011;
let mask = 0b0101;
let result = flags | mask; // The instruction selector will generate an S390 OR instruction.

// Comparison
let x = 5;
let y = 10;
if (x < y) { // The instruction selector will generate an S390 compare instruction
  console.log("x is less than y");
}

// Type conversion
let floatValue = 3.14;
let intValue = Math.trunc(floatValue); // The instruction selector will generate an S390 instruction to truncate the float.

// Operations that might overflow
let largeInt1 = 9223372036854775807; // Max 64-bit integer
let largeInt2 = 1;
// The instruction selector will use instructions that can detect overflow if needed.
// In strict mode, overflow in addition throws an error.
try {
  let overflowSum = largeInt1 + largeInt2;
} catch (e) {
  console.error("Overflow occurred:", e);
}
```

**Code Logic Inference (Example: `VisitWordCompareZero`)**

**Hypothetical Input (IR Node):**  A conditional branch that checks if the result of `x - 5` is equal to zero.

**Code Logic:** The `VisitWordCompareZero` function recognizes this pattern. It sees a comparison against zero (`kWord32Equal` or similar) and checks if the compared value is the result of a subtraction (`kInt32Sub`).

**Assumptions:**
* `user`: The node representing the conditional branch.
* `value`: The node representing the equality comparison (`x - 5 == 0`).

**Output (S390 Instructions):** Instead of generating a separate subtraction instruction and then a compare-to-zero instruction, `VisitWordCompareZero` might optimize this by:

1. **Modifying the `FlagsContinuation`:** It could set the flags continuation to directly check the zero flag that is set as a side effect of the subtraction instruction.
2. **Generating the subtraction instruction directly:**  The subtraction instruction itself sets the zero flag if the result is zero. The conditional branch can then directly use this flag.

**Simplified Example of the Optimization:**

Instead of:

```assembly
; ... calculate x - 5 and store in a register ...
SUB  r1, r2, #5  ; r1 = x, r2 = result of subtraction
CFI  r2, #0      ; Compare r2 with 0
BEQ  target      ; Branch to target if equal
```

The optimized code might simply rely on the flags set by the subtraction:

```assembly
; ... calculate x - 5 and store in a register ...
SUB  r1, r2, #5  ; r1 = x, r2 = result of subtraction (flags are set)
BEQ  target      ; Branch to target if the zero flag is set (result was zero)
```

**Common Programming Errors and How This Code Relates:**

This code is part of the *compiler*, not the code that directly executes user-written JavaScript. However, the choices made in the instruction selector can impact how common programming errors manifest.

* **Integer Overflow:** JavaScript numbers are generally 64-bit floating-point. However, bitwise operations and certain other contexts treat them as 32-bit integers. If a JavaScript program performs an integer operation that overflows a 32-bit or 64-bit representation, this code will generate instructions that either:
    * **Wrap around:**  This is the standard behavior for unsigned integer overflow.
    * **Potentially throw an error:** In strict mode, overflow in some arithmetic operations can throw `TypeError`. The instruction selector needs to generate code that can detect these overflow conditions if necessary.
    * **Produce incorrect results without warning:** For signed integer overflow, the behavior is often to wrap around, which can lead to unexpected results if the programmer doesn't anticipate it.

**Example of a potential programming error:**

```javascript
let maxInt32 = 2147483647;
let result = maxInt32 + 1; // In JavaScript, this will become a floating-point number.

let unsignedMaxInt32 = 4294967295;
let unsignedResult = unsignedMaxInt32 + 1; // This will wrap around to 0 in bitwise operations.
```

The instruction selector needs to correctly translate these JavaScript operations into S390 instructions that either perform the wrapping behavior or detect overflow as required by the JavaScript semantics.

**Summary of Part 4's Functionality:**

This specific part of `instruction-selector-s390.cc` focuses on the implementation details of selecting S390 instructions for a range of core arithmetic, logical, comparison, and type conversion operations on 32-bit and 64-bit integer and floating-point values. It includes logic for handling overflow conditions and optimizations for specific patterns, like comparisons with zero. This code is crucial for translating the platform-independent intermediate representation of JavaScript code into efficient, architecture-specific machine code for S390 processors.

Prompt: 
```
这是目录为v8/src/compiler/backend/s390/instruction-selector-s390.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/s390/instruction-selector-s390.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共6部分，请归纳一下它的功能

"""
       \
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