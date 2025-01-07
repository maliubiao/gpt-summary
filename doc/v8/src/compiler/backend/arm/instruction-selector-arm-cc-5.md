Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/compiler/backend/arm/instruction-selector-arm.cc`.

Here's a breakdown of the thought process to generate the response:

1. **Identify the Core Function:** The file name itself, `instruction-selector-arm.cc`, strongly suggests this code is responsible for selecting ARM instructions based on higher-level operations. This is the primary function.

2. **Look for Patterns:**  The code is full of `Visit...` methods. These methods correspond to different node types or operations within the V8 compiler's intermediate representation (IR). This reinforces the idea of instruction selection based on operation type.

3. **Examine Individual `Visit` Methods:**  Each `Visit` method seems to perform the following:
    * Create an `ArmOperandGeneratorT`. This likely helps in managing and generating ARM operands (registers, immediates, etc.).
    * Call an `Emit` function. This suggests the actual emission of the selected ARM instruction.
    * The `Emit` function often takes an `ArchOpcode` (like `kArmS128Zero`, `kArmF64x2Splat`, etc.) as an argument. This confirms the instruction selection aspect.
    * Many methods deal with SIMD (Single Instruction, Multiple Data) operations, especially those related to WebAssembly (`V8_ENABLE_WEBASSEMBLY`).

4. **Pay Attention to Conditional Compilation:** The `#if V8_ENABLE_WEBASSEMBLY` blocks indicate that a significant portion of this code is dedicated to handling WebAssembly SIMD instructions.

5. **Identify Helper Functions and Macros:**
    * Macros like `SIMD_VISIT_EXTRACT_LANE`, `SIMD_VISIT_UNOP`, `SIMD_VISIT_BINOP` are used to generate similar `Visit` methods for various SIMD operations, reducing code duplication.
    * The `TryMatchArchShuffle` function and the `arch_shuffles` array suggest the code is trying to find optimized ARM instructions for SIMD shuffle operations.
    * The `ArrangeShuffleTable` function seems related to setting up operands for shuffle operations.

6. **Infer Data Types:** The names of the `Visit` methods (e.g., `VisitS128Zero`, `VisitF64x2Splat`, `VisitI32x4Add`) reveal the data types being processed (S128, F64x2, I32x4), often corresponding to SIMD vector types.

7. **Consider the `Adapter` Template:** The `<typename Adapter>` template suggests this code is designed to be adaptable to different compilation phases or contexts. The presence of `TurboshaftAdapter` and `TurbofanAdapter` confirms this.

8. **Look for "UNIMPLEMENTED"**: The presence of `UNIMPLEMENTED()` for certain operations (like `VisitF16x8Splat`) indicates that support for those specific instructions is not yet available.

9. **Connect to JavaScript (if possible):** Since the code deals with WebAssembly SIMD, which is a feature accessible from JavaScript, try to illustrate with a JavaScript example. A simple SIMD operation like adding two vectors is a good starting point.

10. **Consider Potential Errors:** Think about what could go wrong when dealing with instruction selection and SIMD operations. Incorrect lane indexing, type mismatches, or using unsupported operations are common programming errors.

11. **Address the `.tq` Check:**  The prompt explicitly asks about the `.tq` extension. Since the provided code is `.cc`,  state that it's not a Torque file.

12. **Structure the Summary:** Organize the findings into a clear and logical structure:
    * Overall purpose.
    * Key functionalities (instruction selection, SIMD support, WebAssembly).
    * Use of macros and helper functions.
    * Handling of different data types.
    * Adaptability through templates.
    * Areas of ongoing development (`UNIMPLEMENTED`).
    * JavaScript relation (with an example).
    * Code logic example (with assumptions and output).
    * Common programming errors.
    * Conclusion for this part.

13. **Refine and Elaborate:** Review the summary and add more details where necessary. Ensure the language is clear and concise. For example, explicitly mention that instruction selection involves mapping high-level operations to low-level ARM instructions.

By following these steps, the comprehensive summary of the provided code can be generated.
这是提供的 `v8/src/compiler/backend/arm/instruction-selector-arm.cc` 源代码的第 6 部分，主要集中在处理 **SIMD (Single Instruction, Multiple Data)** 相关的操作，特别是与 **WebAssembly** 集成相关的 SIMD 指令选择。

**主要功能归纳:**

1. **SIMD 指令的选择和生成:**  这段代码的核心功能是根据编译器 IR (Intermediate Representation) 中的 SIMD 操作节点，选择合适的 ARM SIMD 指令 (通常是 NEON 指令) 并生成相应的机器码。 这包括各种 SIMD 操作，例如：
    * **创建 (Splat):** 将一个标量值复制到 SIMD 向量的所有元素。
    * **零初始化 (Zero):** 创建一个所有元素都为零的 SIMD 向量。
    * **提取 Lane (Extract Lane):** 从 SIMD 向量中提取特定索引的元素。
    * **替换 Lane (Replace Lane):**  将 SIMD 向量中特定索引的元素替换为新值。
    * **一元操作 (Unary Operations):**  例如，取绝对值 (`Abs`), 取反 (`Neg`), 平方根 (`Sqrt`) 等。
    * **二元操作 (Binary Operations):** 例如，加法 (`Add`), 减法 (`Sub`), 乘法 (`Mul`), 除法 (`Div`), 最小值 (`Min`), 最大值 (`Max`) 等。
    * **位移操作 (Shift Operations):**  例如，左移 (`Shl`), 右移 (`Shr`)。
    * **Shuffle (混洗):**  根据指定的索引重新排列 SIMD 向量中的元素。
    * **选择 (Select):**  根据掩码从两个 SIMD 向量中选择元素。
    * **扩展乘法 (Extended Multiply):**  执行更大位宽的乘法并将结果存储在 SIMD 向量中。
    * **成对加法 (Pairwise Add):**  将 SIMD 向量中相邻的元素相加。
    * **类型转换 (Conversions):**  在不同的 SIMD 数据类型之间进行转换。
    * **Fused Multiply-Add/Subtract (Qfma/Qfms):**  执行乘法和加法/减法操作，通常具有更高的精度。
    * **Swizzle:**  使用一个索引向量来选择另一个向量的元素。
    * **BitMask:**  根据 SIMD 向量中每个元素的符号位生成一个掩码。
    * **Packed Min/Max (Pmin/Pmax):**  按元素比较两个 SIMD 向量，并选择最小值/最大值。

2. **WebAssembly SIMD 支持:**  代码中大量使用了 `#if V8_ENABLE_WEBASSEMBLY` 宏，表明这部分代码专注于支持 WebAssembly 的 SIMD 特性。

3. **针对不同的 Adapter:** 代码使用了模板 `template <typename Adapter>`，这表明 `InstructionSelectorT` 可以被不同的适配器实例化，例如 `TurbofanAdapter` 和 `TurboshaftAdapter`，这两个是 V8 编译器的不同阶段或架构。 这允许代码在不同的编译流程中复用。

4. **优化特定的 SIMD 操作:**  对于某些 SIMD 操作（例如加法），代码会尝试匹配特定的模式（例如 `ExtAddPairwise` 操作），并生成更优化的指令 `kArmVpadal`。

5. **处理 Shuffle 操作的特殊情况:**  对于 `I8x16Shuffle` 操作，代码会尝试匹配各种常见和优化的 shuffle 模式，例如 splat (复制单个元素)、identity (保持不变)、concat (连接两个向量) 以及特定架构支持的 shuffle 指令 (如 zip, unzip, transpose, reverse)。

6. **处理 `SetStackPointer`:**  代码中包含处理 `SetStackPointer` 操作的逻辑，用于设置栈指针。

7. **标记未实现的 SIMD 操作:**  代码中存在 `UNIMPLEMENTED()` 的调用，表明某些 SIMD 操作（例如 `F16x8` 相关的操作）在 ARM 架构上尚未实现或支持。

**关于问题中的其他点:**

* **`.tq` 结尾:**  代码的后缀是 `.cc`，因此它是一个 **C++ 源代码**，而不是 Torque 源代码。

* **与 JavaScript 的关系:**  这段代码直接支持了 WebAssembly 的 SIMD 功能，而 WebAssembly 可以在 JavaScript 中调用。  因此，这段代码间接地与 JavaScript 的功能相关。

   **JavaScript 示例:**

   ```javascript
   const wasmCode = new Uint8Array([
     0, 97, 115, 109, 1, 0, 0, 0, 7, 15, 1, 1, 118, 128, 1, 127, 1, 96, 0, 1, 127, 3, 2, 1, 0, 10, 9, 1, 7, 0, 65, 0, 253, 15, 26, 11
   ]);
   const wasmModule = new WebAssembly.Module(wasmCode);
   const wasmInstance = new WebAssembly.Instance(wasmModule);

   // 假设 WebAssembly 模块中有一个函数接受两个 i32x4 参数并返回它们的和
   const addI32x4 = wasmInstance.exports.addI32x4;

   const a = new Int32Array([1, 2, 3, 4]);
   const b = new Int32Array([5, 6, 7, 8]);

   const result = addI32x4(a, b); // 内部会使用这段 C++ 代码选择 ARM SIMD 加法指令
   console.log(result); // 输出类似 [6, 8, 10, 12] 的结果
   ```

* **代码逻辑推理:**

   **假设输入:**  一个表示 `I32x4Add` 操作的 IR 节点，其输入是两个 `I32x4` 类型的寄存器 (假设寄存器分别为 `r1` 和 `r2`)。

   **输出:**  生成的 ARM 指令是 `kArmI32x4Add r0, r1, r2`，其中 `r0` 是用于存储结果的新分配的寄存器。  `Emit` 函数会将这个指令添加到当前的机器码序列中。

* **用户常见的编程错误:**  在使用 SIMD 指令时，常见的错误包括：

   1. **Lane 索引错误:**  访问了超出向量边界的 lane，例如在一个 4 元素向量中尝试访问第 5 个元素。

      ```javascript
      // 假设 wasmInstance.exports.extractLane(vector, index) 提取指定索引的元素
      const vec = new Int32Array([1, 2, 3, 4]);
      // extractLane 会对应到 C++ 的 VisitI32x4ExtractLane
      const value = wasmInstance.exports.extractLane(vec, 4); // 错误: 索引超出范围
      ```

   2. **类型不匹配:**  对不同类型的 SIMD 向量执行操作，例如将 `f32x4` 向量与 `i32x4` 向量相加，而没有进行显式的类型转换。

      ```javascript
      // 假设 wasmInstance.exports.add(a, b) 执行加法
      const floatVec = new Float32Array([1.0, 2.0, 3.0, 4.0]);
      const intVec = new Int32Array([1, 2, 3, 4]);
      // add 操作可能要求输入类型相同，否则会出错
      const result = wasmInstance.exports.add(floatVec, intVec);
      ```

   3. **使用未实现的 SIMD 操作:**  尝试使用硬件架构不支持或 V8 尚未实现的 SIMD 操作。

      ```javascript
      // 假设 wasmInstance.exports.f16x8Abs(vector) 计算 f16x8 向量的绝对值
      // 但如果 F16x8Abs 在 ARM 上未实现 (如代码中所示)，则会出错
      const f16Vec = new Uint16Array([ /* ... */ ]);
      const absVec = wasmInstance.exports.f16x8Abs(f16Vec);
      ```

**总结第 6 部分的功能:**

第 6 部分的 `v8/src/compiler/backend/arm/instruction-selector-arm.cc` 源代码主要负责 **为 ARM 架构上的 WebAssembly SIMD 操作选择和生成机器指令**。它涵盖了各种 SIMD 操作的指令选择逻辑，并特别处理了 shuffle 操作的优化。 代码使用了模板来实现对不同编译器阶段的适配，并标记了尚未实现的 SIMD 操作。 这部分代码是 V8 引擎支持高性能 WebAssembly 执行的关键组成部分。

Prompt: 
```
这是目录为v8/src/compiler/backend/arm/instruction-selector-arm.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/arm/instruction-selector-arm.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第6部分，共7部分，请归纳一下它的功能

"""
, g.UseImmediate(val[1]),
         g.UseImmediate(val[2]), g.UseImmediate(val[3]));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitS128Zero(node_t node) {
  ArmOperandGeneratorT<Adapter> g(this);
  Emit(kArmS128Zero, g.DefineAsRegister(node));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x2Splat(node_t node) {
  VisitRR(this, kArmF64x2Splat, node);
}
template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF32x4Splat(node_t node) {
  VisitRR(this, kArmF32x4Splat, node);
}
template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF16x8Splat(node_t node) {
  UNIMPLEMENTED();
}
template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4Splat(node_t node) {
  VisitRR(this, kArmI32x4Splat, node);
}
template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI16x8Splat(node_t node) {
  VisitRR(this, kArmI16x8Splat, node);
}
#endif  // V8_ENABLE_WEBASSEMBLY

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI8x16Splat(node_t node) {
  VisitRR(this, kArmI8x16Splat, node);
}

#if V8_ENABLE_WEBASSEMBLY
#define SIMD_VISIT_EXTRACT_LANE(Type, Sign)                           \
  template <typename Adapter>                                         \
  void InstructionSelectorT<Adapter>::Visit##Type##ExtractLane##Sign( \
      node_t node) {                                                  \
    VisitRRI(this, kArm##Type##ExtractLane##Sign, node);              \
  }
SIMD_VISIT_EXTRACT_LANE(F64x2, )
SIMD_VISIT_EXTRACT_LANE(F32x4, )
SIMD_VISIT_EXTRACT_LANE(I32x4, )
SIMD_VISIT_EXTRACT_LANE(I16x8, U)
SIMD_VISIT_EXTRACT_LANE(I16x8, S)
SIMD_VISIT_EXTRACT_LANE(I8x16, U)
SIMD_VISIT_EXTRACT_LANE(I8x16, S)
#undef SIMD_VISIT_EXTRACT_LANE

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF16x8ExtractLane(node_t node) {
  UNIMPLEMENTED();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x2ReplaceLane(node_t node) {
  VisitRRIR(this, kArmF64x2ReplaceLane, node);
}
template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF32x4ReplaceLane(node_t node) {
  VisitRRIR(this, kArmF32x4ReplaceLane, node);
}
template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF16x8ReplaceLane(node_t node) {
  UNIMPLEMENTED();
}
template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4ReplaceLane(node_t node) {
  VisitRRIR(this, kArmI32x4ReplaceLane, node);
}
template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI16x8ReplaceLane(node_t node) {
  VisitRRIR(this, kArmI16x8ReplaceLane, node);
}
template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI8x16ReplaceLane(node_t node) {
  VisitRRIR(this, kArmI8x16ReplaceLane, node);
}

#define SIMD_VISIT_UNOP(Name, instruction)                       \
  template <typename Adapter>                                    \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) { \
    VisitRR(this, instruction, node);                            \
  }
SIMD_UNOP_LIST(SIMD_VISIT_UNOP)
#undef SIMD_VISIT_UNOP
#undef SIMD_UNOP_LIST

#define UNIMPLEMENTED_SIMD_UNOP_LIST(V) \
  V(F16x8Abs)                           \
  V(F16x8Neg)                           \
  V(F16x8Sqrt)                          \
  V(F16x8Floor)                         \
  V(F16x8Ceil)                          \
  V(F16x8Trunc)                         \
  V(F16x8NearestInt)

#define SIMD_VISIT_UNIMPL_UNOP(Name)                             \
  template <typename Adapter>                                    \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) { \
    UNIMPLEMENTED();                                             \
  }

UNIMPLEMENTED_SIMD_UNOP_LIST(SIMD_VISIT_UNIMPL_UNOP)
#undef SIMD_VISIT_UNIMPL_UNOP
#undef UNIMPLEMENTED_SIMD_UNOP_LIST

#define UNIMPLEMENTED_SIMD_CVTOP_LIST(V) \
  V(F16x8SConvertI16x8)                  \
  V(F16x8UConvertI16x8)                  \
  V(I16x8SConvertF16x8)                  \
  V(I16x8UConvertF16x8)                  \
  V(F32x4PromoteLowF16x8)                \
  V(F16x8DemoteF32x4Zero)                \
  V(F16x8DemoteF64x2Zero)

#define SIMD_VISIT_UNIMPL_CVTOP(Name)                            \
  template <typename Adapter>                                    \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) { \
    UNIMPLEMENTED();                                             \
  }

UNIMPLEMENTED_SIMD_CVTOP_LIST(SIMD_VISIT_UNIMPL_CVTOP)
#undef SIMD_VISIT_UNIMPL_CVTOP
#undef UNIMPLEMENTED_SIMD_CVTOP_LIST

#define SIMD_VISIT_SHIFT_OP(Name, width)                         \
  template <typename Adapter>                                    \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) { \
    VisitSimdShiftRRR(this, kArm##Name, node, width);            \
  }
SIMD_SHIFT_OP_LIST(SIMD_VISIT_SHIFT_OP)
#undef SIMD_VISIT_SHIFT_OP
#undef SIMD_SHIFT_OP_LIST

#define SIMD_VISIT_BINOP(Name, instruction)                      \
  template <typename Adapter>                                    \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) { \
    VisitRRR(this, instruction, node);                           \
  }
SIMD_BINOP_LIST(SIMD_VISIT_BINOP)
#undef SIMD_VISIT_BINOP
#undef SIMD_BINOP_LIST

#define UNIMPLEMENTED_SIMD_BINOP_LIST(V) \
  V(F16x8Add)                            \
  V(F16x8Sub)                            \
  V(F16x8Mul)                            \
  V(F16x8Div)                            \
  V(F16x8Min)                            \
  V(F16x8Max)                            \
  V(F16x8Pmin)                           \
  V(F16x8Pmax)                           \
  V(F16x8Eq)                             \
  V(F16x8Ne)                             \
  V(F16x8Lt)                             \
  V(F16x8Le)

#define SIMD_VISIT_UNIMPL_BINOP(Name)                            \
  template <typename Adapter>                                    \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) { \
    UNIMPLEMENTED();                                             \
  }

UNIMPLEMENTED_SIMD_BINOP_LIST(SIMD_VISIT_UNIMPL_BINOP)
#undef SIMD_VISIT_UNIMPL_BINOP
#undef UNIMPLEMENTED_SIMD_BINOP_LIST

// TODO(mliedtke): This macro has only two uses. Maybe this could be refactored
// into some helpers instead of the huge macro.
#define VISIT_SIMD_ADD(Type, PairwiseType, NeonWidth)                          \
  template <>                                                                  \
  void InstructionSelectorT<TurboshaftAdapter>::Visit##Type##Add(              \
      node_t node) {                                                           \
    using namespace turboshaft; /*NOLINT(build/namespaces)*/                   \
    ArmOperandGeneratorT<TurboshaftAdapter> g(this);                           \
    const Simd128BinopOp& add_op = Get(node).Cast<Simd128BinopOp>();           \
    const Operation& left = Get(add_op.left());                                \
    const Operation& right = Get(add_op.right());                              \
    if (left.Is<Opmask::kSimd128##Type##ExtAddPairwise##PairwiseType##S>() &&  \
        CanCover(node, add_op.left())) {                                       \
      Emit(kArmVpadal | MiscField::encode(NeonS##NeonWidth),                   \
           g.DefineSameAsFirst(node), g.UseRegister(add_op.right()),           \
           g.UseRegister(left.input(0)));                                      \
      return;                                                                  \
    }                                                                          \
    if (left.Is<Opmask::kSimd128##Type##ExtAddPairwise##PairwiseType##U>() &&  \
        CanCover(node, add_op.left())) {                                       \
      Emit(kArmVpadal | MiscField::encode(NeonU##NeonWidth),                   \
           g.DefineSameAsFirst(node), g.UseRegister(add_op.right()),           \
           g.UseRegister(left.input(0)));                                      \
      return;                                                                  \
    }                                                                          \
    if (right.Is<Opmask::kSimd128##Type##ExtAddPairwise##PairwiseType##S>() && \
        CanCover(node, add_op.right())) {                                      \
      Emit(kArmVpadal | MiscField::encode(NeonS##NeonWidth),                   \
           g.DefineSameAsFirst(node), g.UseRegister(add_op.left()),            \
           g.UseRegister(right.input(0)));                                     \
      return;                                                                  \
    }                                                                          \
    if (right.Is<Opmask::kSimd128##Type##ExtAddPairwise##PairwiseType##U>() && \
        CanCover(node, add_op.right())) {                                      \
      Emit(kArmVpadal | MiscField::encode(NeonU##NeonWidth),                   \
           g.DefineSameAsFirst(node), g.UseRegister(add_op.left()),            \
           g.UseRegister(right.input(0)));                                     \
      return;                                                                  \
    }                                                                          \
    VisitRRR(this, kArm##Type##Add, node);                                     \
  }                                                                            \
  template <>                                                                  \
  void InstructionSelectorT<TurbofanAdapter>::Visit##Type##Add(Node* node) {   \
    ArmOperandGeneratorT<TurbofanAdapter> g(this);                             \
    Node* left = node->InputAt(0);                                             \
    Node* right = node->InputAt(1);                                            \
    if (left->opcode() ==                                                      \
            IrOpcode::k##Type##ExtAddPairwise##PairwiseType##S &&              \
        CanCover(node, left)) {                                                \
      Emit(kArmVpadal | MiscField::encode(NeonS##NeonWidth),                   \
           g.DefineSameAsFirst(node), g.UseRegister(right),                    \
           g.UseRegister(left->InputAt(0)));                                   \
      return;                                                                  \
    }                                                                          \
    if (left->opcode() ==                                                      \
            IrOpcode::k##Type##ExtAddPairwise##PairwiseType##U &&              \
        CanCover(node, left)) {                                                \
      Emit(kArmVpadal | MiscField::encode(NeonU##NeonWidth),                   \
           g.DefineSameAsFirst(node), g.UseRegister(right),                    \
           g.UseRegister(left->InputAt(0)));                                   \
      return;                                                                  \
    }                                                                          \
    if (right->opcode() ==                                                     \
            IrOpcode::k##Type##ExtAddPairwise##PairwiseType##S &&              \
        CanCover(node, right)) {                                               \
      Emit(kArmVpadal | MiscField::encode(NeonS##NeonWidth),                   \
           g.DefineSameAsFirst(node), g.UseRegister(left),                     \
           g.UseRegister(right->InputAt(0)));                                  \
      return;                                                                  \
    }                                                                          \
    if (right->opcode() ==                                                     \
            IrOpcode::k##Type##ExtAddPairwise##PairwiseType##U &&              \
        CanCover(node, right)) {                                               \
      Emit(kArmVpadal | MiscField::encode(NeonU##NeonWidth),                   \
           g.DefineSameAsFirst(node), g.UseRegister(left),                     \
           g.UseRegister(right->InputAt(0)));                                  \
      return;                                                                  \
    }                                                                          \
    VisitRRR(this, kArm##Type##Add, node);                                     \
  }

VISIT_SIMD_ADD(I16x8, I8x16, 8)
VISIT_SIMD_ADD(I32x4, I16x8, 16)
#undef VISIT_SIMD_ADD

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI64x2SplatI32Pair(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    // In turboshaft it gets lowered to an I32x4Splat.
    UNREACHABLE();
  } else {
    ArmOperandGeneratorT<Adapter> g(this);
    InstructionOperand operand0 = g.UseRegister(node->InputAt(0));
    InstructionOperand operand1 = g.UseRegister(node->InputAt(1));
    Emit(kArmI64x2SplatI32Pair, g.DefineAsRegister(node), operand0, operand1);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI64x2ReplaceLaneI32Pair(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    // In turboshaft it gets lowered to an I32x4ReplaceLane.
    UNREACHABLE();
  } else {
    ArmOperandGeneratorT<Adapter> g(this);
    InstructionOperand operand = g.UseRegister(node->InputAt(0));
    InstructionOperand lane = g.UseImmediate(OpParameter<int32_t>(node->op()));
    InstructionOperand low = g.UseRegister(node->InputAt(1));
    InstructionOperand high = g.UseRegister(node->InputAt(2));
    Emit(kArmI64x2ReplaceLaneI32Pair, g.DefineSameAsFirst(node), operand, lane,
         low, high);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI64x2Neg(node_t node) {
    ArmOperandGeneratorT<Adapter> g(this);
    Emit(kArmI64x2Neg, g.DefineAsRegister(node),
         g.UseUniqueRegister(this->input_at(node, 0)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI64x2Mul(node_t node) {
    ArmOperandGeneratorT<Adapter> g(this);
    InstructionOperand temps[] = {g.TempSimd128Register()};
    Emit(kArmI64x2Mul, g.DefineAsRegister(node),
         g.UseUniqueRegister(this->input_at(node, 0)),
         g.UseUniqueRegister(this->input_at(node, 1)), arraysize(temps), temps);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF32x4Sqrt(node_t node) {
  ArmOperandGeneratorT<Adapter> g(this);
  // Use fixed registers in the lower 8 Q-registers so we can directly access
  // mapped registers S0-S31.
  Emit(kArmF32x4Sqrt, g.DefineAsFixed(node, q0),
       g.UseFixed(this->input_at(node, 0), q0));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF32x4Div(node_t node) {
  ArmOperandGeneratorT<Adapter> g(this);
  // Use fixed registers in the lower 8 Q-registers so we can directly access
  // mapped registers S0-S31.
  Emit(kArmF32x4Div, g.DefineAsFixed(node, q0),
       g.UseFixed(this->input_at(node, 0), q0),
       g.UseFixed(this->input_at(node, 1), q1));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitS128Select(node_t node) {
  ArmOperandGeneratorT<Adapter> g(this);
  Emit(kArmS128Select, g.DefineSameAsFirst(node),
       g.UseRegister(this->input_at(node, 0)),
       g.UseRegister(this->input_at(node, 1)),
       g.UseRegister(this->input_at(node, 2)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI8x16RelaxedLaneSelect(node_t node) {
  VisitS128Select(node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI16x8RelaxedLaneSelect(node_t node) {
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
    ArmOperandGeneratorT<Adapter> g(this);                     \
    Emit(kArm##op, g.DefineAsRegister(node),                   \
         g.UseUniqueRegister(this->input_at(node, 0)),         \
         g.UseUniqueRegister(this->input_at(node, 1)),         \
         g.UseUniqueRegister(this->input_at(node, 2)));        \
  }
VISIT_SIMD_QFMOP(F64x2Qfma)
VISIT_SIMD_QFMOP(F64x2Qfms)
VISIT_SIMD_QFMOP(F32x4Qfma)
VISIT_SIMD_QFMOP(F32x4Qfms)
#undef VISIT_SIMD_QFMOP

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF16x8Qfma(node_t node) {
  UNIMPLEMENTED();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF16x8Qfms(node_t node) {
  UNIMPLEMENTED();
}
namespace {

struct ShuffleEntry {
  uint8_t shuffle[kSimd128Size];
  ArchOpcode opcode;
};

static const ShuffleEntry arch_shuffles[] = {
    {{0, 1, 2, 3, 16, 17, 18, 19, 4, 5, 6, 7, 20, 21, 22, 23},
     kArmS32x4ZipLeft},
    {{8, 9, 10, 11, 24, 25, 26, 27, 12, 13, 14, 15, 28, 29, 30, 31},
     kArmS32x4ZipRight},
    {{0, 1, 2, 3, 8, 9, 10, 11, 16, 17, 18, 19, 24, 25, 26, 27},
     kArmS32x4UnzipLeft},
    {{4, 5, 6, 7, 12, 13, 14, 15, 20, 21, 22, 23, 28, 29, 30, 31},
     kArmS32x4UnzipRight},
    {{0, 1, 2, 3, 16, 17, 18, 19, 8, 9, 10, 11, 24, 25, 26, 27},
     kArmS32x4TransposeLeft},
    {{4, 5, 6, 7, 20, 21, 22, 23, 12, 13, 14, 15, 28, 29, 30, 31},
     kArmS32x4TransposeRight},
    {{4, 5, 6, 7, 0, 1, 2, 3, 12, 13, 14, 15, 8, 9, 10, 11}, kArmS32x2Reverse},

    {{0, 1, 16, 17, 2, 3, 18, 19, 4, 5, 20, 21, 6, 7, 22, 23},
     kArmS16x8ZipLeft},
    {{8, 9, 24, 25, 10, 11, 26, 27, 12, 13, 28, 29, 14, 15, 30, 31},
     kArmS16x8ZipRight},
    {{0, 1, 4, 5, 8, 9, 12, 13, 16, 17, 20, 21, 24, 25, 28, 29},
     kArmS16x8UnzipLeft},
    {{2, 3, 6, 7, 10, 11, 14, 15, 18, 19, 22, 23, 26, 27, 30, 31},
     kArmS16x8UnzipRight},
    {{0, 1, 16, 17, 4, 5, 20, 21, 8, 9, 24, 25, 12, 13, 28, 29},
     kArmS16x8TransposeLeft},
    {{2, 3, 18, 19, 6, 7, 22, 23, 10, 11, 26, 27, 14, 15, 30, 31},
     kArmS16x8TransposeRight},
    {{6, 7, 4, 5, 2, 3, 0, 1, 14, 15, 12, 13, 10, 11, 8, 9}, kArmS16x4Reverse},
    {{2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13}, kArmS16x2Reverse},

    {{0, 16, 1, 17, 2, 18, 3, 19, 4, 20, 5, 21, 6, 22, 7, 23},
     kArmS8x16ZipLeft},
    {{8, 24, 9, 25, 10, 26, 11, 27, 12, 28, 13, 29, 14, 30, 15, 31},
     kArmS8x16ZipRight},
    {{0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30},
     kArmS8x16UnzipLeft},
    {{1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 27, 29, 31},
     kArmS8x16UnzipRight},
    {{0, 16, 2, 18, 4, 20, 6, 22, 8, 24, 10, 26, 12, 28, 14, 30},
     kArmS8x16TransposeLeft},
    {{1, 17, 3, 19, 5, 21, 7, 23, 9, 25, 11, 27, 13, 29, 15, 31},
     kArmS8x16TransposeRight},
    {{7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8}, kArmS8x8Reverse},
    {{3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12}, kArmS8x4Reverse},
    {{1, 0, 3, 2, 5, 4, 7, 6, 9, 8, 11, 10, 13, 12, 15, 14}, kArmS8x2Reverse}};

bool TryMatchArchShuffle(const uint8_t* shuffle, const ShuffleEntry* table,
                         size_t num_entries, bool is_swizzle,
                         ArchOpcode* opcode) {
  uint8_t mask = is_swizzle ? kSimd128Size - 1 : 2 * kSimd128Size - 1;
  for (size_t i = 0; i < num_entries; ++i) {
    const ShuffleEntry& entry = table[i];
    int j = 0;
    for (; j < kSimd128Size; ++j) {
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
void ArrangeShuffleTable(ArmOperandGeneratorT<Adapter>* g,
                         typename Adapter::node_t input0,
                         typename Adapter::node_t input1,
                         InstructionOperand* src0, InstructionOperand* src1) {
  if (input0 == input1) {
    // Unary, any q-register can be the table.
    *src0 = *src1 = g->UseRegister(input0);
  } else {
    // Binary, table registers must be consecutive.
    *src0 = g->UseFixed(input0, q0);
    *src1 = g->UseFixed(input1, q1);
  }
}

}  // namespace

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI8x16Shuffle(node_t node) {
  uint8_t shuffle[kSimd128Size];
  bool is_swizzle;
  // TODO(nicohartmann@): Properly use view here once Turboshaft support is
  // implemented.
  auto view = this->simd_shuffle_view(node);
  CanonicalizeShuffle(view, shuffle, &is_swizzle);
  node_t input0 = view.input(0);
  node_t input1 = view.input(1);
  uint8_t shuffle32x4[4];
  ArmOperandGeneratorT<Adapter> g(this);
  int index = 0;
  if (wasm::SimdShuffle::TryMatch32x4Shuffle(shuffle, shuffle32x4)) {
    if (wasm::SimdShuffle::TryMatchSplat<4>(shuffle, &index)) {
      DCHECK_GT(4, index);
      Emit(kArmS128Dup, g.DefineAsRegister(node), g.UseRegister(input0),
           g.UseImmediate(Neon32), g.UseImmediate(index % 4));
    } else if (wasm::SimdShuffle::TryMatchIdentity(shuffle)) {
      // Bypass normal shuffle code generation in this case.
      // EmitIdentity
      MarkAsUsed(input0);
      MarkAsDefined(node);
      SetRename(node, input0);
    } else {
      // 32x4 shuffles are implemented as s-register moves. To simplify these,
      // make sure the destination is distinct from both sources.
      InstructionOperand src0 = g.UseUniqueRegister(input0);
      InstructionOperand src1 = is_swizzle ? src0 : g.UseUniqueRegister(input1);
      Emit(kArmS32x4Shuffle, g.DefineAsRegister(node), src0, src1,
           g.UseImmediate(wasm::SimdShuffle::Pack4Lanes(shuffle32x4)));
    }
    return;
  }
  if (wasm::SimdShuffle::TryMatchSplat<8>(shuffle, &index)) {
    DCHECK_GT(8, index);
    Emit(kArmS128Dup, g.DefineAsRegister(node), g.UseRegister(input0),
         g.UseImmediate(Neon16), g.UseImmediate(index % 8));
    return;
  }
  if (wasm::SimdShuffle::TryMatchSplat<16>(shuffle, &index)) {
    DCHECK_GT(16, index);
    Emit(kArmS128Dup, g.DefineAsRegister(node), g.UseRegister(input0),
         g.UseImmediate(Neon8), g.UseImmediate(index % 16));
    return;
  }
  ArchOpcode opcode;
  if (TryMatchArchShuffle(shuffle, arch_shuffles, arraysize(arch_shuffles),
                          is_swizzle, &opcode)) {
    VisitRRRShuffle(this, opcode, node, input0, input1);
    return;
  }
  uint8_t offset;
  if (wasm::SimdShuffle::TryMatchConcat(shuffle, &offset)) {
    Emit(kArmS8x16Concat, g.DefineAsRegister(node), g.UseRegister(input0),
         g.UseRegister(input1), g.UseImmediate(offset));
    return;
  }
  // Code generator uses vtbl, arrange sources to form a valid lookup table.
  InstructionOperand src0, src1;
  ArrangeShuffleTable(&g, input0, input1, &src0, &src1);
  Emit(kArmI8x16Shuffle, g.DefineAsRegister(node), src0, src1,
       g.UseImmediate(wasm::SimdShuffle::Pack4Lanes(shuffle)),
       g.UseImmediate(wasm::SimdShuffle::Pack4Lanes(shuffle + 4)),
       g.UseImmediate(wasm::SimdShuffle::Pack4Lanes(shuffle + 8)),
       g.UseImmediate(wasm::SimdShuffle::Pack4Lanes(shuffle + 12)));
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitSetStackPointer(Node* node) {
  OperandGenerator g(this);
  auto input = g.UseRegister(node->InputAt(0));
  Emit(kArchSetStackPointer, 0, nullptr, 1, &input);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitSetStackPointer(
    node_t node) {
  OperandGenerator g(this);
  auto input = g.UseRegister(this->input_at(node, 0));
  Emit(kArchSetStackPointer, 0, nullptr, 1, &input);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI8x16Swizzle(node_t node) {
    ArmOperandGeneratorT<Adapter> g(this);
    // We don't want input 0 (the table) to be the same as output, since we will
    // modify output twice (low and high), and need to keep the table the same.
    Emit(kArmI8x16Swizzle, g.DefineAsRegister(node),
         g.UseUniqueRegister(this->input_at(node, 0)),
         g.UseRegister(this->input_at(node, 1)));
}

#endif  // V8_ENABLE_WEBASSEMBLY

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSignExtendWord8ToInt32(node_t node) {
  ArmOperandGeneratorT<Adapter> g(this);
  Emit(kArmSxtb, g.DefineAsRegister(node),
       g.UseRegister(this->input_at(node, 0)), g.TempImmediate(0));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSignExtendWord16ToInt32(node_t node) {
  ArmOperandGeneratorT<Adapter> g(this);
  Emit(kArmSxth, g.DefineAsRegister(node),
       g.UseRegister(this->input_at(node, 0)), g.TempImmediate(0));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32AbsWithOverflow(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64AbsWithOverflow(node_t node) {
  UNREACHABLE();
}

namespace {
template <typename Adapter, ArchOpcode opcode>
void VisitBitMask(InstructionSelectorT<Adapter>* selector,
                  typename Adapter::node_t node) {
    ArmOperandGeneratorT<Adapter> g(selector);
    InstructionOperand temps[] = {g.TempSimd128Register()};
    selector->Emit(opcode, g.DefineAsRegister(node),
                   g.UseRegister(selector->input_at(node, 0)), arraysize(temps),
                   temps);
}
}  // namespace

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI8x16BitMask(node_t node) {
  VisitBitMask<Adapter, kArmI8x16BitMask>(this, node);
}

#if V8_ENABLE_WEBASSEMBLY
template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI16x8BitMask(node_t node) {
  VisitBitMask<Adapter, kArmI16x8BitMask>(this, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4BitMask(node_t node) {
  VisitBitMask<Adapter, kArmI32x4BitMask>(this, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI64x2BitMask(node_t node) {
  VisitBitMask<Adapter, kArmI64x2BitMask>(this, node);
}

namespace {
template <typename Adapter>
void VisitF32x4PminOrPmax(InstructionSelectorT<Adapter>* selector,
                          ArchOpcode opcode, typename Adapter::node_t node) {
    ArmOperandGeneratorT<Adapter> g(selector);
    // Need all unique registers because we first compare the two inputs, then
    // we need the inputs to remain unchanged for the bitselect later.
    selector->Emit(opcode, g.DefineAsRegister(node),
                   g.UseUniqueRegister(selector->input_at(node, 0)),
                   g.UseUniqueRegister(selector->input_at(node, 1)));
}

template <typename Adapter>
void VisitF64x2PminOrPMax(InstructionSelectorT<Adapter>* selector,
                          ArchOpcode opcode, typename Adapter::node_t node) {
    ArmOperandGeneratorT<Adapter> g(selector);
    selector->Emit(opcode, g.DefineSameAsFirst(node),
                   g.UseRegister(selector->input_at(node, 0)),
                   g.UseRegister(selector->input_at(node, 1)));
}
}  // namespace

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF32x4Pmin(node_t node) {
  VisitF32x4PminOrPmax(this, kArmF32x4Pmin, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF32x4Pmax(node_t node) {
  VisitF32x4PminOrPmax(this, kArmF32x4Pmax, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x2Pmin(node_t node) {
  VisitF64x2PminOrPMax(this, kArmF64x2Pmin, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x2Pmax(node_t node) {
  VisitF64x2PminOrPMax(this, kArmF64x2Pmax, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x2RelaxedMin(node_t node) {
  VisitF64x2Pmin(node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x2RelaxedMax(node_t node) {
  VisitF64x2Pmax(node);
}

#define EXT_MUL_LIST(V)                            \
  V(I16x8ExtMulLowI8x16S, kArmVmullLow, NeonS8)    \
  V(I16x8ExtMulHighI8x16S, kArmVmullHigh, NeonS8)  \
  V(I16x8ExtMulLowI8x16U, kArmVmullLow, NeonU8)    \
  V(I16x8ExtMulHighI8x16U, kArmVmullHigh, NeonU8)  \
  V(I32x4ExtMulLowI16x8S, kArmVmullLow, NeonS16)   \
  V(I32x4ExtMulHighI16x8S, kArmVmullHigh, NeonS16) \
  V(I32x4ExtMulLowI16x8U, kArmVmullLow, NeonU16)   \
  V(I32x4ExtMulHighI16x8U, kArmVmullHigh, NeonU16) \
  V(I64x2ExtMulLowI32x4S, kArmVmullLow, NeonS32)   \
  V(I64x2ExtMulHighI32x4S, kArmVmullHigh, NeonS32) \
  V(I64x2ExtMulLowI32x4U, kArmVmullLow, NeonU32)   \
  V(I64x2ExtMulHighI32x4U, kArmVmullHigh, NeonU32)

#define VISIT_EXT_MUL(OPCODE, VMULL, NEONSIZE)                     \
  template <typename Adapter>                                      \
  void InstructionSelectorT<Adapter>::Visit##OPCODE(node_t node) { \
    VisitRRR(this, VMULL | MiscField::encode(NEONSIZE), node);     \
  }

EXT_MUL_LIST(VISIT_EXT_MUL)

#undef VISIT_EXT_MUL
#undef EXT_MUL_LIST

#define VISIT_EXTADD_PAIRWISE(OPCODE, NEONSIZE)                    \
  template <typename Adapter>                                      \
  void InstructionSelectorT<Adapter>::Visit##OPCODE(node_t node) { \
    VisitRR(this, kArmVpaddl | MiscField::encode(NEONSIZE), node); \
  }
VISIT_EXTADD_PAIRWISE(I16x8ExtAddPairwiseI8x16S, NeonS8)
VISIT_EXTADD_PAIRWISE(I16x8ExtAddPairwiseI8x16U, NeonU8)
VISIT_EXTADD_PAIRWISE(I32x4ExtAddPairwiseI16x8S, NeonS16)
VISIT_EXTADD_PAIRWISE(I32x4ExtAddPairwiseI16x8U, NeonU16)
#undef VISIT_EXTADD_PAIRWISE

// TODO(v8:9780)
// These double precision conversion instructions need a low Q register (q0-q7)
// because the codegen accesses the S registers they overlap with.
template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x2ConvertLowI32x4S(node_t node) {
    ArmOperandGeneratorT<Adapter> g(this);
    Emit(kArmF64x2ConvertLowI32x4S, g.DefineAsRegister(node),
         g.UseFixed(this->input_at(node, 0), q0));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x2ConvertLowI32x4U(node_t node) {
    ArmOperandGeneratorT<Adapter> g(this);
    Emit(kArmF64x2ConvertLowI32x4U, g.DefineAsRegister(node),
         g.UseFixed(this->input_at(node, 0), q0));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4TruncSatF64x2SZero(node_t node) {
    ArmOperandGeneratorT<Adapter> g(this);
    Emit(kArmI32x4TruncSatF64x2SZero, g.DefineAsFixed(node, q0),
         g.UseUniqueRegister(this->input_at(node, 0)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4TruncSatF64x2UZero(node_t node) {
  ArmOperandGeneratorT<Adapter> g(this);
  Emit(kArmI32x4TruncSatF64x2UZero, g.DefineAsFixed(node, q0),
       g.UseUniqueRegister(this->input_at(node, 0)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF32x4DemoteF64x2Zero(node_t node) {
    ArmOperandGeneratorT<Adapter> g(this);
    Emit(kArmF32x4DemoteF64x2Zero, g.DefineAsFixed(node, q0),
         g.UseUniqueRegister(this->input_at(node, 0)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x2PromoteLowF32x4(node_t node) {
    ArmOperandGeneratorT<Adapter> g(this);
    Emit(kArmF64x2PromoteLowF32x4, g.DefineAsRegister(node),
         g.UseFixed(this->input_at(node, 0), q0));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4RelaxedTruncF64x2SZero(
    node_t node) {
  VisitI32x4TruncSatF64x2SZero(node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4RelaxedTruncF64x2UZero(
    node_t node) {
  VisitI32x4TruncSatF64x2UZero(node);
}
#endif  // V8_ENABLE_WEBASSEMBLY

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTruncateFloat32ToInt32(node_t node) {
  ArmOperandGeneratorT<Adapter> g(this);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const Operation& op = this->Get(node);
    InstructionCode opcode = kArmVcvtS32F32;
    if (op.Is<Opmask::kTruncateFloat32ToInt32OverflowToMin>()) {
      opcode |= MiscField::encode(true);
    }
    Emit(opcode, g.DefineAsRegister(node),
         g.UseRegister(this->input_at(node, 0)));
  } else {
    InstructionCode opcode = kArmVcvtS32F32;
    TruncateKind kind = OpParameter<TruncateKind>(node->op());
    if (kind == TruncateKind::kSetOverflowToMin) {
      opcode |= MiscField::encode(true);
    }

    Emit(opcode, g.DefineAsRegister(node), g.UseRegister(node->InputAt(0)));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTruncateFloat32ToUint32(node_t node) {
  ArmOperandGeneratorT<Adapter> g(this);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const Operation& op =
"""


```