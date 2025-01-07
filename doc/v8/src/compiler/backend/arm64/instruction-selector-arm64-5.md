Response: The user wants to understand the functionality of the provided C++ code snippet. This file is part of the V8 JavaScript engine, specifically the ARM64 backend's instruction selector. I need to analyze the code and explain its role in the compilation process. Since this is part 6 of 6, it's likely covering the final stages or specific, potentially more complex, instruction selection patterns.

Key observations in the code:
- **SIMD/Vector Instructions:**  There are numerous `Visit` methods for various SIMD operations (e.g., `VisitI16x8RelaxedLaneSelect`, `VisitF64x2Qfma`, `VisitI8x16Shuffle`). This suggests a core responsibility of mapping high-level SIMD operations to specific ARM64 instructions.
- **Shuffle Operations:** The `VisitI8x16Shuffle` function and related helper functions (`TryMatchArchShuffle`, `ArrangeShuffleTable`) deal with reordering elements within SIMD vectors. This is a complex operation with multiple possible ARM64 instruction mappings.
- **Type Conversions:**  Functions like `VisitSignExtendWord8ToInt32` and blocks of `VisitI64x2SConvertI32x4Low` indicate handling of data type conversions, specifically sign extension and potentially widening of vector lanes.
- **Min/Max Operations:** `VisitF16x8Pmin` and similar functions point to the selection of instructions for finding the minimum or maximum values within SIMD vectors.
- **Stack Pointer Manipulation:** `VisitSetStackPointer` suggests handling operations related to the call stack.
- **WebAssembly Support:** The `#if V8_ENABLE_WEBASSEMBLY` blocks highlight that some of this code is specifically for optimizing WebAssembly code execution.
- **Template Metaprogramming:** The use of `template <typename Adapter>` suggests this code is designed to be adaptable to different compilation stages or intermediate representations.

**Overall Function:** This file seems to be responsible for the final stages of instruction selection for the ARM64 architecture within the V8 compiler. It focuses on mapping intermediate representation (IR) nodes, particularly those related to SIMD operations, type conversions, and potentially stack manipulation, to concrete ARM64 machine instructions. It handles various complex scenarios and optimizations, especially for WebAssembly.

**Relationship to JavaScript:**  JavaScript's typed arrays and the WebAssembly standard both expose SIMD capabilities. This code directly contributes to efficiently executing JavaScript and WebAssembly code that utilizes these features. The instruction selector takes the abstract operations expressed in the compiler's intermediate representation and translates them into the low-level ARM64 instructions that the processor can understand and execute.

**Example in JavaScript (Illustrative):**  Since the code handles SIMD shuffles, I can create a JavaScript example that uses a similar concept. While JavaScript doesn't have direct byte-level SIMD shuffles, typed arrays allow for similar manipulations at a higher level.
This C++ code snippet is a part of the V8 JavaScript engine's instruction selector for the ARM64 architecture. Specifically, this is the **final part** of the `instruction-selector-arm64.cc` file, suggesting it handles more specialized or less frequently encountered instruction selection patterns.

Here's a breakdown of its functionality:

**Core Function:**

This file's primary function is to **translate high-level, architecture-independent operations (represented as nodes in V8's intermediate representation) into specific ARM64 machine instructions**. This process is crucial for compiling JavaScript code (and WebAssembly) down to executable machine code.

**Specific Functionalities Demonstrated in this Snippet:**

* **Relaxed Lane Select for SIMD:** The `VisitI16x8RelaxedLaneSelect`, `VisitI32x4RelaxedLaneSelect`, and `VisitI64x2RelaxedLaneSelect` functions likely handle a more flexible or optimized form of selecting elements from SIMD vectors. They all call `VisitS128Select`, suggesting a common underlying implementation for these relaxed operations.
* **Fused Multiply-Add/Subtract for SIMD (QFMOP):** The `VISIT_SIMD_QFMOP` macro generates functions like `VisitF64x2Qfma`, `VisitF32x4Qfms`, etc. These functions handle fused multiply-add and multiply-subtract operations on SIMD floating-point vectors. These operations are often more efficient than separate multiply and add/subtract instructions.
* **SIMD Shuffle Operations:** The `VisitI8x16Shuffle` function is a significant part of this snippet. It deals with rearranging the elements within a 128-bit SIMD vector. This involves:
    * **Canonicalization:**  `CanonicalizeShuffle` likely normalizes the shuffle pattern.
    * **Matching Architectural Shuffles:** It attempts to match common shuffle patterns to specific, optimized ARM64 instructions (like `kArm64S32x4ZipLeft`, `kArm64S8x16TransposeRight`).
    * **Handling Specific Shuffle Cases:**  It includes logic for common shuffle patterns like concatenation, splatting (duplicating elements), reversing lanes, and single-lane swizzles.
    * **General Shuffle Implementation:** If no specific optimized instruction matches, it uses a general shuffle instruction (`kArm64I8x16Shuffle`) using lookup tables.
* **Setting the Stack Pointer:** The `VisitSetStackPointer` function handles the low-level operation of setting the stack pointer register.
* **Sign Extension:** Functions like `VisitSignExtendWord8ToInt32`, `VisitSignExtendWord16ToInt64`, etc., handle the conversion of smaller integer types to larger ones while preserving the sign.
* **SIMD Min/Max Operations:** Functions like `VisitF16x8Pmin`, `VisitF32x4Pmax` select instructions to find the minimum or maximum values within SIMD vectors.
* **SIMD Lane Extension (Conversions):** Functions like `VisitI64x2SConvertI32x4Low`, `VisitI32x4UConvertI16x8High`, etc., handle extending the lanes of a SIMD vector (e.g., converting a vector of 32-bit integers to a vector of 64-bit integers). The "Low" and "High" suffixes likely indicate which part of the source vector to use for the conversion.
* **SIMD Popcount:** `VisitI8x16Popcnt` handles counting the number of set bits (1s) in each byte of a SIMD vector.
* **Handling Select Continuations:** `AddOutputToSelectContinuation` seems related to control flow and how the results of select operations (like `if-else`) are handled.
* **Supported Machine Operator Flags and Alignment Requirements:**  These static functions define the capabilities and constraints of the ARM64 backend in terms of supported operations and memory access alignment.

**Relationship to JavaScript and Examples:**

This code is directly related to optimizing the execution of JavaScript, especially when using features that map well to SIMD instructions or require specific low-level operations.

* **SIMD Operations (JavaScript Typed Arrays/WebAssembly):** JavaScript's `TypedArray` and the WebAssembly SIMD proposal allow developers to work with vector data. The shuffle operations, fused multiply-add, and min/max functions in this C++ code directly translate operations on these data types into efficient ARM64 instructions.

   ```javascript
   // Example using TypedArrays (conceptually similar to SIMD)
   const a = new Int32Array([1, 2, 3, 4]);
   const b = new Int32Array([5, 6, 7, 8]);
   const c = new Int32Array(4);

   // Imagine a "shuffle" operation (not a direct JavaScript equivalent)
   // where you rearrange elements from a and b into c

   // The C++ code would be responsible for generating the ARM64
   // instructions to perform this efficient shuffling if a SIMD
   // instruction exists for that pattern.
   ```

* **WebAssembly SIMD:** WebAssembly has explicit SIMD instructions. The C++ code in this file is crucial for efficiently compiling WebAssembly modules that utilize these instructions to ARM64.

   ```javascript
   // WebAssembly example (hypothetical SIMD shuffle)
   // (This is a conceptual example, actual WebAssembly syntax might differ)
   // func.export "shuffle"(v128.i32x4, v128.i32x4) -> v128.i32x4
   //   local.get 0
   //   local.get 1
   //   i32x4.shuffle 0 4 1 5 // Shuffle elements from the two input vectors
   //   return
   ```
   When the V8 engine compiles this WebAssembly code for ARM64, the `VisitI8x16Shuffle` function (and related code) would be responsible for selecting the appropriate ARM64 SIMD shuffle instruction.

* **Low-Level Operations:** Operations like setting the stack pointer are fundamental for function calls and stack management in JavaScript execution. The `VisitSetStackPointer` function ensures this critical operation is correctly translated to ARM64 instructions.

**In summary, this part of the `instruction-selector-arm64.cc` file focuses on the intricate details of mapping specific high-level operations, particularly those related to SIMD and low-level architecture concerns, to the most efficient equivalent ARM64 machine instructions. It plays a vital role in optimizing the performance of JavaScript and WebAssembly code on ARM64 platforms.**

Prompt: 
```
这是目录为v8/src/compiler/backend/arm64/instruction-selector-arm64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第6部分，共6部分，请归纳一下它的功能

"""
id InstructionSelectorT<Adapter>::VisitI16x8RelaxedLaneSelect(node_t node) {
  VisitS128Select(node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4RelaxedLaneSelect(node_t node) {
  VisitS128Select(node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI64x2RelaxedLaneSelect(node_t node) {
  VisitS128Select(node);
}

#define VISIT_SIMD_QFMOP(op)                                   \
  template <typename Adapter>                                  \
  void InstructionSelectorT<Adapter>::Visit##op(node_t node) { \
    Arm64OperandGeneratorT<Adapter> g(this);                   \
    Emit(kArm64##op, g.DefineSameAsInput(node, 2),             \
         g.UseRegister(this->input_at(node, 0)),               \
         g.UseRegister(this->input_at(node, 1)),               \
         g.UseRegister(this->input_at(node, 2)));              \
  }
VISIT_SIMD_QFMOP(F64x2Qfma)
VISIT_SIMD_QFMOP(F64x2Qfms)
VISIT_SIMD_QFMOP(F32x4Qfma)
VISIT_SIMD_QFMOP(F32x4Qfms)
VISIT_SIMD_QFMOP(F16x8Qfma)
VISIT_SIMD_QFMOP(F16x8Qfms)
#undef VISIT_SIMD_QFMOP

namespace {

struct ShuffleEntry {
  uint8_t shuffle[kSimd128Size];
  ArchOpcode opcode;
};

static const ShuffleEntry arch_shuffles[] = {
    {{0, 1, 2, 3, 16, 17, 18, 19, 4, 5, 6, 7, 20, 21, 22, 23},
     kArm64S32x4ZipLeft},
    {{8, 9, 10, 11, 24, 25, 26, 27, 12, 13, 14, 15, 28, 29, 30, 31},
     kArm64S32x4ZipRight},
    {{0, 1, 2, 3, 8, 9, 10, 11, 16, 17, 18, 19, 24, 25, 26, 27},
     kArm64S32x4UnzipLeft},
    {{4, 5, 6, 7, 12, 13, 14, 15, 20, 21, 22, 23, 28, 29, 30, 31},
     kArm64S32x4UnzipRight},
    {{0, 1, 2, 3, 16, 17, 18, 19, 8, 9, 10, 11, 24, 25, 26, 27},
     kArm64S32x4TransposeLeft},
    {{4, 5, 6, 7, 20, 21, 22, 23, 12, 13, 14, 15, 21, 22, 23, 24},
     kArm64S32x4TransposeRight},
    {{4, 5, 6, 7, 0, 1, 2, 3, 12, 13, 14, 15, 8, 9, 10, 11},
     kArm64S32x2Reverse},

    {{0, 1, 16, 17, 2, 3, 18, 19, 4, 5, 20, 21, 6, 7, 22, 23},
     kArm64S16x8ZipLeft},
    {{8, 9, 24, 25, 10, 11, 26, 27, 12, 13, 28, 29, 14, 15, 30, 31},
     kArm64S16x8ZipRight},
    {{0, 1, 4, 5, 8, 9, 12, 13, 16, 17, 20, 21, 24, 25, 28, 29},
     kArm64S16x8UnzipLeft},
    {{2, 3, 6, 7, 10, 11, 14, 15, 18, 19, 22, 23, 26, 27, 30, 31},
     kArm64S16x8UnzipRight},
    {{0, 1, 16, 17, 4, 5, 20, 21, 8, 9, 24, 25, 12, 13, 28, 29},
     kArm64S16x8TransposeLeft},
    {{2, 3, 18, 19, 6, 7, 22, 23, 10, 11, 26, 27, 14, 15, 30, 31},
     kArm64S16x8TransposeRight},
    {{6, 7, 4, 5, 2, 3, 0, 1, 14, 15, 12, 13, 10, 11, 8, 9},
     kArm64S16x4Reverse},
    {{2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13},
     kArm64S16x2Reverse},

    {{0, 16, 1, 17, 2, 18, 3, 19, 4, 20, 5, 21, 6, 22, 7, 23},
     kArm64S8x16ZipLeft},
    {{8, 24, 9, 25, 10, 26, 11, 27, 12, 28, 13, 29, 14, 30, 15, 31},
     kArm64S8x16ZipRight},
    {{0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30},
     kArm64S8x16UnzipLeft},
    {{1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 27, 29, 31},
     kArm64S8x16UnzipRight},
    {{0, 16, 2, 18, 4, 20, 6, 22, 8, 24, 10, 26, 12, 28, 14, 30},
     kArm64S8x16TransposeLeft},
    {{1, 17, 3, 19, 5, 21, 7, 23, 9, 25, 11, 27, 13, 29, 15, 31},
     kArm64S8x16TransposeRight},
    {{7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8}, kArm64S8x8Reverse},
    {{3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12}, kArm64S8x4Reverse},
    {{1, 0, 3, 2, 5, 4, 7, 6, 9, 8, 11, 10, 13, 12, 15, 14},
     kArm64S8x2Reverse}};

bool TryMatchArchShuffle(const uint8_t* shuffle, const ShuffleEntry* table,
                         size_t num_entries, bool is_swizzle,
                         ArchOpcode* opcode) {
  uint8_t mask = is_swizzle ? kSimd128Size - 1 : 2 * kSimd128Size - 1;
  for (size_t i = 0; i < num_entries; i++) {
    const ShuffleEntry& entry = table[i];
    int j = 0;
    for (; j < kSimd128Size; j++) {
      if ((entry.shuffle[j] & mask) != (shuffle[j] & mask)) {
        break;
      }
    }
    if (j == kSimd128Size) {
      *opcode = entry.opcode;
      return true;
    }
  }
  return false;
}

template <typename Adapter>
void ArrangeShuffleTable(Arm64OperandGeneratorT<Adapter>* g,
                         typename Adapter::node_t input0,
                         typename Adapter::node_t input1,
                         InstructionOperand* src0, InstructionOperand* src1) {
  if (input0 == input1) {
    // Unary, any q-register can be the table.
    *src0 = *src1 = g->UseRegister(input0);
  } else {
    // Binary, table registers must be consecutive.
    *src0 = g->UseFixed(input0, fp_fixed1);
    *src1 = g->UseFixed(input1, fp_fixed2);
  }
}

}  // namespace

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI8x16Shuffle(node_t node) {
  uint8_t shuffle[kSimd128Size];
  bool is_swizzle;
  auto view = this->simd_shuffle_view(node);
  CanonicalizeShuffle(view, shuffle, &is_swizzle);
  node_t input0 = view.input(0);
  node_t input1 = view.input(1);
  uint8_t shuffle32x4[4];
  Arm64OperandGeneratorT<Adapter> g(this);
  ArchOpcode opcode;
  if (TryMatchArchShuffle(shuffle, arch_shuffles, arraysize(arch_shuffles),
                          is_swizzle, &opcode)) {
    Emit(opcode, g.DefineAsRegister(node), g.UseRegister(input0),
         g.UseRegister(input1));
    return;
  }
  uint8_t offset;
  if (wasm::SimdShuffle::TryMatchConcat(shuffle, &offset)) {
    Emit(kArm64S8x16Concat, g.DefineAsRegister(node), g.UseRegister(input0),
         g.UseRegister(input1), g.UseImmediate(offset));
    return;
  }
  int index = 0;
  uint8_t from = 0;
  uint8_t to = 0;
  if (wasm::SimdShuffle::TryMatch32x4Shuffle(shuffle, shuffle32x4)) {
    if (wasm::SimdShuffle::TryMatchSplat<4>(shuffle, &index)) {
      DCHECK_GT(4, index);
      Emit(kArm64S128Dup, g.DefineAsRegister(node), g.UseRegister(input0),
           g.UseImmediate(4), g.UseImmediate(index % 4));
    } else if (wasm::SimdShuffle::TryMatch32x4Reverse(shuffle32x4)) {
      Emit(kArm64S32x4Reverse, g.DefineAsRegister(node), g.UseRegister(input0));
    } else if (wasm::SimdShuffle::TryMatch32x4OneLaneSwizzle(shuffle32x4, &from,
                                                             &to)) {
      Emit(kArm64S32x4OneLaneSwizzle, g.DefineAsRegister(node),
           g.UseRegister(input0), g.TempImmediate(from), g.TempImmediate(to));
    } else if (wasm::SimdShuffle::TryMatchIdentity(shuffle)) {
      // Bypass normal shuffle code generation in this case.
      // EmitIdentity
      MarkAsUsed(input0);
      MarkAsDefined(node);
      SetRename(node, input0);
    } else {
      Emit(kArm64S32x4Shuffle, g.DefineAsRegister(node), g.UseRegister(input0),
           g.UseRegister(input1),
           g.UseImmediate(wasm::SimdShuffle::Pack4Lanes(shuffle32x4)));
    }
    return;
  }
  if (wasm::SimdShuffle::TryMatchSplat<8>(shuffle, &index)) {
    DCHECK_GT(8, index);
    Emit(kArm64S128Dup, g.DefineAsRegister(node), g.UseRegister(input0),
         g.UseImmediate(8), g.UseImmediate(index % 8));
    return;
  }
  if (wasm::SimdShuffle::TryMatchSplat<16>(shuffle, &index)) {
    DCHECK_GT(16, index);
    Emit(kArm64S128Dup, g.DefineAsRegister(node), g.UseRegister(input0),
         g.UseImmediate(16), g.UseImmediate(index % 16));
    return;
  }
  // Code generator uses vtbl, arrange sources to form a valid lookup table.
  InstructionOperand src0, src1;
  ArrangeShuffleTable(&g, input0, input1, &src0, &src1);
  Emit(kArm64I8x16Shuffle, g.DefineAsRegister(node), src0, src1,
       g.UseImmediate(wasm::SimdShuffle::Pack4Lanes(shuffle)),
       g.UseImmediate(wasm::SimdShuffle::Pack4Lanes(shuffle + 4)),
       g.UseImmediate(wasm::SimdShuffle::Pack4Lanes(shuffle + 8)),
       g.UseImmediate(wasm::SimdShuffle::Pack4Lanes(shuffle + 12)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSetStackPointer(node_t node) {
  OperandGenerator g(this);
  auto input = g.UseRegister(this->input_at(node, 0));
  Emit(kArchSetStackPointer, 0, nullptr, 1, &input);
}

#endif  // V8_ENABLE_WEBASSEMBLY

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSignExtendWord8ToInt32(node_t node) {
  VisitRR(this, kArm64Sxtb32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSignExtendWord16ToInt32(node_t node) {
  VisitRR(this, kArm64Sxth32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSignExtendWord8ToInt64(node_t node) {
  VisitRR(this, kArm64Sxtb, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSignExtendWord16ToInt64(node_t node) {
  VisitRR(this, kArm64Sxth, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSignExtendWord32ToInt64(node_t node) {
  VisitRR(this, kArm64Sxtw, node);
}

#if V8_ENABLE_WEBASSEMBLY
namespace {
template <typename Adapter>
void VisitPminOrPmax(InstructionSelectorT<Adapter>* selector, ArchOpcode opcode,
                     typename Adapter::node_t node) {
  Arm64OperandGeneratorT<Adapter> g(selector);
  // Need all unique registers because we first compare the two inputs, then
  // we need the inputs to remain unchanged for the bitselect later.
  selector->Emit(opcode, g.DefineAsRegister(node),
                 g.UseUniqueRegister(selector->input_at(node, 0)),
                 g.UseUniqueRegister(selector->input_at(node, 1)));
}
}  // namespace

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF16x8Pmin(node_t node) {
  VisitPminOrPmax(this, kArm64F16x8Pmin, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF16x8Pmax(node_t node) {
  VisitPminOrPmax(this, kArm64F16x8Pmax, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF32x4Pmin(node_t node) {
  VisitPminOrPmax(this, kArm64F32x4Pmin, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF32x4Pmax(node_t node) {
  VisitPminOrPmax(this, kArm64F32x4Pmax, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x2Pmin(node_t node) {
  VisitPminOrPmax(this, kArm64F64x2Pmin, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x2Pmax(node_t node) {
  VisitPminOrPmax(this, kArm64F64x2Pmax, node);
}

namespace {
template <typename Adapter>
void VisitSignExtendLong(InstructionSelectorT<Adapter>* selector,
                         ArchOpcode opcode, typename Adapter::node_t node,
                         int lane_size) {
  InstructionCode code = opcode;
  code |= LaneSizeField::encode(lane_size);
  VisitRR(selector, code, node);
}
}  // namespace

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI64x2SConvertI32x4Low(node_t node) {
  VisitSignExtendLong(this, kArm64Sxtl, node, 64);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI64x2SConvertI32x4High(node_t node) {
  VisitSignExtendLong(this, kArm64Sxtl2, node, 64);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI64x2UConvertI32x4Low(node_t node) {
  VisitSignExtendLong(this, kArm64Uxtl, node, 64);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI64x2UConvertI32x4High(node_t node) {
  VisitSignExtendLong(this, kArm64Uxtl2, node, 64);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4SConvertI16x8Low(node_t node) {
  VisitSignExtendLong(this, kArm64Sxtl, node, 32);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4SConvertI16x8High(node_t node) {
  VisitSignExtendLong(this, kArm64Sxtl2, node, 32);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4UConvertI16x8Low(node_t node) {
  VisitSignExtendLong(this, kArm64Uxtl, node, 32);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4UConvertI16x8High(node_t node) {
  VisitSignExtendLong(this, kArm64Uxtl2, node, 32);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI16x8SConvertI8x16Low(node_t node) {
  VisitSignExtendLong(this, kArm64Sxtl, node, 16);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI16x8SConvertI8x16High(node_t node) {
  VisitSignExtendLong(this, kArm64Sxtl2, node, 16);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI16x8UConvertI8x16Low(node_t node) {
  VisitSignExtendLong(this, kArm64Uxtl, node, 16);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI16x8UConvertI8x16High(node_t node) {
  VisitSignExtendLong(this, kArm64Uxtl2, node, 16);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI8x16Popcnt(node_t node) {
  InstructionCode code = kArm64Cnt;
  code |= LaneSizeField::encode(8);
  VisitRR(this, code, node);
}
#endif  // V8_ENABLE_WEBASSEMBLY

template <typename Adapter>
void InstructionSelectorT<Adapter>::AddOutputToSelectContinuation(
    OperandGenerator* g, int first_input_index, node_t node) {
  continuation_outputs_.push_back(g->DefineAsRegister(node));
}

// static
MachineOperatorBuilder::Flags
InstructionSelector::SupportedMachineOperatorFlags() {
  auto flags = MachineOperatorBuilder::kFloat32RoundDown |
               MachineOperatorBuilder::kFloat64RoundDown |
               MachineOperatorBuilder::kFloat32RoundUp |
               MachineOperatorBuilder::kFloat64RoundUp |
               MachineOperatorBuilder::kFloat32RoundTruncate |
               MachineOperatorBuilder::kFloat64RoundTruncate |
               MachineOperatorBuilder::kFloat64RoundTiesAway |
               MachineOperatorBuilder::kFloat32RoundTiesEven |
               MachineOperatorBuilder::kFloat64RoundTiesEven |
               MachineOperatorBuilder::kWord32Popcnt |
               MachineOperatorBuilder::kWord64Popcnt |
               MachineOperatorBuilder::kWord32ShiftIsSafe |
               MachineOperatorBuilder::kInt32DivIsSafe |
               MachineOperatorBuilder::kUint32DivIsSafe |
               MachineOperatorBuilder::kWord32ReverseBits |
               MachineOperatorBuilder::kWord64ReverseBits |
               MachineOperatorBuilder::kSatConversionIsSafe |
               MachineOperatorBuilder::kFloat32Select |
               MachineOperatorBuilder::kFloat64Select |
               MachineOperatorBuilder::kWord32Select |
               MachineOperatorBuilder::kWord64Select |
               MachineOperatorBuilder::kLoadStorePairs;
  if (CpuFeatures::IsSupported(FP16)) {
    flags |= MachineOperatorBuilder::kFloat16 |
             MachineOperatorBuilder::kTruncateFloat64ToFloat16RawBits;
  }
  return flags;
}

// static
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