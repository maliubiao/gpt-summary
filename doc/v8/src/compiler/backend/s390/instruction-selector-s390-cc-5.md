Response:
Let's break down the thought process for analyzing this C++ code snippet.

1. **Understanding the Context:** The first step is to recognize the file path `v8/src/compiler/backend/s390/instruction-selector-s390.cc`. This immediately tells us several key things:
    * It's part of the V8 JavaScript engine.
    * It's related to the compiler.
    * It's specifically for the s390 architecture (IBM z/Architecture).
    * The `instruction-selector` part strongly suggests its role is in selecting machine instructions based on higher-level operations.
    * The `.cc` extension indicates it's a C++ source file. This is crucial because the prompt mentions `.tq` which would signify Torque (V8's internal DSL). This mismatch needs to be addressed early.

2. **High-Level Functionality Identification:**  Scanning through the code, even without deeply understanding every macro, reveals patterns:
    * **Macros Defining Lists:**  There are macros like `SIMD_BINOP_LIST`, `SIMD_UNOP_LIST`, `SIMD_RELAXED_OP_LIST`, and `F16_OP_LIST`. These likely define sets of supported SIMD (Single Instruction, Multiple Data) operations.
    * **`Visit...` Functions:**  A large number of functions with the `Visit` prefix (e.g., `VisitI64x2Add`, `VisitF32x4Sqrt`, `VisitI8x16Shuffle`). The naming convention suggests these functions handle specific intermediate representation (IR) nodes or operations within the compilation process. The pattern `Visit[OperationName]` is a common pattern in compiler design for traversing and processing the IR.
    * **`Emit(...)` Calls:**  Inside the `Visit` functions, there are calls to `Emit(...)`. This strongly suggests the core function of these `Visit` functions is to generate the actual machine instructions. The `kS390_...` prefixes in the `Emit` calls confirm these are s390-specific instructions.
    * **Templates:** The code uses C++ templates (`template <typename Adapter>`). This indicates a level of abstraction, likely to support different compilation pipelines or adapter patterns within V8. The presence of `TurbofanAdapter` and `TurboshaftAdapter` confirms this.
    * **SIMD Operations:** The frequent mentions of `I64x2`, `F32x4`, `I8x16`, etc., clearly point towards support for SIMD instructions, which are essential for performance in JavaScript's numerical computations and WebAssembly.
    * **WebAssembly Conditional Compilation:** The `#if V8_ENABLE_WEBASSEMBLY` blocks show specific handling for WebAssembly instructions.

3. **Inferring the Core Task:** Based on the above observations, the primary function of this file is to translate high-level, architecture-independent operations (likely from V8's intermediate representation) into concrete s390 assembly instructions. This is the core job of an instruction selector in a compiler.

4. **Addressing the `.tq` Misconception:** The prompt asks about `.tq`. The file extension is `.cc`. This is a straightforward factual correction. It's important to state clearly that it's C++ and not Torque.

5. **JavaScript Relationship and Examples:**  Since the code deals with SIMD operations, which are exposed in JavaScript through the `SIMD` API and are crucial for WebAssembly, it's easy to create illustrative JavaScript examples. Focus on operations directly corresponding to the C++ function names (e.g., `SIMD.Int32x4.add`, `SIMD.Float32x4.sqrt`). Mentioning WebAssembly as another relevant domain is also important.

6. **Code Logic Inference and Examples:**  The `Visit...` functions and `Emit` calls provide the basis for inferring the code's logic. A good strategy is to pick a simple `Visit` function, like `VisitI64x2Add`, and:
    * **Identify Inputs:**  It takes a `node_t node`. Assume this `node` represents an "add two 64-bit integer vectors" operation. The inputs are likely the two vectors to be added.
    * **Identify Outputs:** The output is likely the resulting vector.
    * **Trace the `Emit` Call:** The `Emit(kS390_I64x2Add, ...)` indicates the generation of the corresponding s390 instruction.
    * **Hypothesize Input/Output:** Create a simple example with concrete SIMD values to illustrate the transformation.

7. **Common Programming Errors:**  Relate the functionality to potential errors. For SIMD operations, type mismatches, incorrect lane access, and out-of-bounds access are common errors. Provide simple JavaScript examples to demonstrate these.

8. **归纳总结 (Summarization):**  Combine the identified functionalities into a concise summary. Focus on the core role of instruction selection, the target architecture (s390), the support for SIMD and WebAssembly, and the use of templates.

9. **Self-Correction/Refinement:** During the process, review the generated information. Are the explanations clear and concise?  Are the examples accurate and relevant?  Is the overall explanation aligned with the prompt's requirements?  For instance, initially, I might have focused too much on the low-level details of the s390 instructions. However, realizing the prompt is for a general understanding, I would shift the focus to the higher-level purpose and the JavaScript/WebAssembly connections. The correction about `.tq` vs. `.cc` is another example of a crucial refinement.
好的，让我们来分析一下 `v8/src/compiler/backend/s390/instruction-selector-s390.cc` 这个文件的功能。

**文件功能归纳：**

`v8/src/compiler/backend/s390/instruction-selector-s390.cc` 是 V8 JavaScript 引擎中针对 **s390 架构** 的 **指令选择器** 的实现。它的主要功能是将 V8 编译器生成的**平台无关的中间表示（IR）** 转换为 **s390 架构特定的机器指令**。

更具体地说，它负责：

1. **识别 IR 节点类型:**  遍历 V8 编译器生成的抽象语法树（AST）或更低级的中间表示图中的节点。
2. **为每个 IR 节点选择合适的 s390 指令:**  根据 IR 节点的类型和操作数，选择最佳的 s390 汇编指令序列来实现该操作。这涉及到考虑 s390 架构的特性、指令集、寄存器分配和寻址模式。
3. **生成机器指令:**  将选择好的 s390 指令及其操作数编码成最终的机器代码。
4. **处理 SIMD 指令:** 特别关注和优化 SIMD（单指令多数据）操作，将 V8 的 SIMD 操作映射到高效的 s390 SIMD 指令（例如，Vector Facility）。
5. **处理浮点运算:** 为浮点数运算选择合适的 s390 浮点指令。
6. **处理类型转换:**  选择正确的指令来执行不同数据类型之间的转换。
7. **支持 WebAssembly:**  为 WebAssembly 的操作选择相应的 s390 指令。

**关于文件扩展名和 Torque：**

`v8/src/compiler/backend/s390/instruction-selector-s390.cc` 的文件扩展名是 `.cc`，这表明它是一个 **C++ 源文件**。

如果文件名以 `.tq` 结尾，那么它才是 V8 Torque 源代码。Torque 是 V8 内部使用的一种领域特定语言（DSL），用于生成 C++ 代码，通常用于实现内置函数或一些底层的操作。

**与 JavaScript 功能的关系及示例：**

`instruction-selector-s390.cc` 的工作直接影响 JavaScript 代码的执行效率。它负责将 JavaScript 的高级操作转换为底层机器指令。例如，考虑 JavaScript 中的 SIMD 操作：

```javascript
const a = SIMD.Int32x4(1, 2, 3, 4);
const b = SIMD.Int32x4(5, 6, 7, 8);
const sum = SIMD.Int32x4.add(a, b);
// sum 将会是 SIMD.Int32x4(6, 8, 10, 12)
```

在 V8 的编译过程中，`instruction-selector-s390.cc` 会将 `SIMD.Int32x4.add(a, b)` 这个操作识别出来，并选择合适的 s390 的向量加法指令来实现。 这部分代码中的 `SIMD_VISIT_BINOP` 宏和 `VisitI32x4Add` 函数就负责处理这类操作。

**代码逻辑推理和示例：**

让我们以 `VisitI64x2Add` 这个函数为例进行代码逻辑推理。

**假设输入：**

* `node`: 一个表示 "将两个 64 位整数向量相加" 操作的 IR 节点。
* `this->input_at(node, 0)`: 表示第一个 64 位整数向量的 IR 节点，假设其编译结果对应 s390 寄存器 `rA`.
* `this->input_at(node, 1)`: 表示第二个 64 位整数向量的 IR 节点，假设其编译结果对应 s390 寄存器 `rB`.

**代码逻辑：**

```c++
template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI64x2Add(node_t node) {
  S390OperandGeneratorT<Adapter> g(this);
  Emit(kS390_I64x2Add, g.DefineAsRegister(node),
       g.UseRegister(this->input_at(node, 0)),
       g.UseRegister(this->input_at(node, 1)));
}
```

1. `S390OperandGeneratorT<Adapter> g(this);`: 创建一个用于生成 s390 操作数的对象 `g`。
2. `Emit(kS390_I64x2Add, ...)`:  调用 `Emit` 函数来生成机器指令。
   * `kS390_I64x2Add`:  表示 s390 架构中用于执行两个 64 位整数向量加法的指令。
   * `g.DefineAsRegister(node)`:  为当前节点 `node` 的结果分配一个 s390 寄存器，假设分配到 `rC`。
   * `g.UseRegister(this->input_at(node, 0))`: 获取第一个输入操作数对应的 s390 寄存器 (`rA`)。
   * `g.UseRegister(this->input_at(node, 1))`: 获取第二个输入操作数对应的 s390 寄存器 (`rB`)。

**输出：**

生成的 s390 汇编指令可能类似于：

```assembly
VADD rC, rA, rB  // 将寄存器 rA 和 rB 中的 64 位整数向量相加，结果存入 rC
```

**用户常见的编程错误示例：**

虽然 `instruction-selector-s390.cc` 本身不直接处理用户的 JavaScript 代码错误，但它的工作与一些常见的性能问题相关。例如：

1. **过度使用标量操作代替 SIMD 操作:** 用户可能编写循环来处理数组元素，而没有意识到可以使用 SIMD 来并行处理多个元素，从而提高性能。 `instruction-selector-s390.cc` 的 SIMD 支持旨在优化这类场景。

   **错误示例 (JavaScript):**

   ```javascript
   const arr1 = [1, 2, 3, 4];
   const arr2 = [5, 6, 7, 8];
   const result = [];
   for (let i = 0; i < arr1.length; i++) {
     result.push(arr1[i] + arr2[i]);
   }
   ```

   **优化方案 (JavaScript):**

   ```javascript
   const a = SIMD.Int32x4(1, 2, 3, 4);
   const b = SIMD.Int32x4(5, 6, 7, 8);
   const sum = SIMD.Int32x4.add(a, b);
   // 需要进一步处理 sum 来得到最终的数组
   ```

2. **不必要的类型转换:** 在涉及到 SIMD 操作时，如果数据类型不匹配，可能会导致额外的转换开销，降低性能。`instruction-selector-s390.cc` 会生成相应的类型转换指令，但避免不必要的转换是提高性能的关键。

   **错误示例 (假设需要将浮点数向量转换为整数向量):**

   ```javascript
   const floatVec = SIMD.Float32x4(1.1, 2.2, 3.3, 4.4);
   const intVec = SIMD.Int32x4.fromFloat32x4Bits(floatVec); // 使用位转换，可能不是想要的截断或舍入
   ```

   应该使用明确的转换操作，例如 `SIMD.Int32x4.trunc(floatVec)`，并且理解不同转换操作的语义。

**第 6 部分，共 6 部分的归纳：**

作为系列文章的最后一部分，这部分代码主要关注的是 **SIMD 操作** 的指令选择。 从列出的宏定义 `SIMD_BINOP_LIST`, `SIMD_UNOP_LIST`，以及具体的 `Visit` 函数（如 `VisitI64x2Add`, `VisitF32x4Sqrt`, `VisitI8x16Shuffle` 等）可以看出，这部分代码专门负责将 V8 的各种 SIMD 操作（例如加法、减法、平方根、shuffle 等）映射到 s390 架构上的相应向量指令。

此外，代码中也包含了对 **浮点数操作**（例如 `F64x2Qfma`, `F32x4Qfms`）和一些 **类型转换操作** 的处理，这些都是指令选择器需要覆盖的关键方面。

总而言之，`v8/src/compiler/backend/s390/instruction-selector-s390.cc` 在 V8 编译流程中扮演着至关重要的角色，它负责将高级的、平台无关的 JavaScript 或 WebAssembly 代码转化为可以在 s390 架构上高效执行的机器指令。 特别是，它对 SIMD 指令的支持对于提升现代 JavaScript 应用的性能至关重要。

### 提示词
```
这是目录为v8/src/compiler/backend/s390/instruction-selector-s390.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/s390/instruction-selector-s390.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第6部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
V(I64x2BitMask)            \
  V(I64x2Splat)              \
  V(I64x2AllTrue)            \
  V(I32x4Neg)                \
  V(I32x4Abs)                \
  V(I32x4SConvertF32x4)      \
  V(I32x4UConvertF32x4)      \
  V(I32x4SConvertI16x8Low)   \
  V(I32x4SConvertI16x8High)  \
  V(I32x4UConvertI16x8Low)   \
  V(I32x4UConvertI16x8High)  \
  V(I32x4TruncSatF64x2SZero) \
  V(I32x4TruncSatF64x2UZero) \
  V(I32x4BitMask)            \
  V(I32x4Splat)              \
  V(I32x4AllTrue)            \
  V(I16x8Neg)                \
  V(I16x8Abs)                \
  V(I16x8SConvertI8x16Low)   \
  V(I16x8SConvertI8x16High)  \
  V(I16x8UConvertI8x16Low)   \
  V(I16x8UConvertI8x16High)  \
  V(I16x8BitMask)            \
  V(I16x8Splat)              \
  V(I16x8AllTrue)            \
  V(I8x16Neg)                \
  V(I8x16Abs)                \
  V(I8x16Popcnt)             \
  V(I8x16BitMask)            \
  V(I8x16Splat)              \
  V(I8x16AllTrue)            \
  V(S128Not)                 \
  V(V128AnyTrue)

#define SIMD_UNOP_UNIQUE_REGISTER_LIST(V) \
  V(I32x4ExtAddPairwiseI16x8S)            \
  V(I32x4ExtAddPairwiseI16x8U)            \
  V(I16x8ExtAddPairwiseI8x16S)            \
  V(I16x8ExtAddPairwiseI8x16U)

#define SIMD_VISIT_EXTRACT_LANE(Type, Sign)                             \
  template <typename Adapter>                                           \
  void InstructionSelectorT<Adapter>::Visit##Type##ExtractLane##Sign(   \
      node_t node) {                                                    \
    S390OperandGeneratorT<Adapter> g(this);                             \
    int32_t lane;                                                       \
    if constexpr (Adapter::IsTurboshaft) {                              \
      using namespace turboshaft; /* NOLINT(build/namespaces) */        \
      const Operation& op = this->Get(node);                            \
      lane = op.template Cast<Simd128ExtractLaneOp>().lane;             \
    } else {                                                            \
      lane = OpParameter<int32_t>(node->op());                          \
    }                                                                   \
    Emit(kS390_##Type##ExtractLane##Sign, g.DefineAsRegister(node),     \
         g.UseRegister(this->input_at(node, 0)), g.UseImmediate(lane)); \
  }
SIMD_VISIT_EXTRACT_LANE(F64x2, )
SIMD_VISIT_EXTRACT_LANE(F32x4, )
SIMD_VISIT_EXTRACT_LANE(I64x2, )
SIMD_VISIT_EXTRACT_LANE(I32x4, )
SIMD_VISIT_EXTRACT_LANE(I16x8, U)
SIMD_VISIT_EXTRACT_LANE(I16x8, S)
SIMD_VISIT_EXTRACT_LANE(I8x16, U)
SIMD_VISIT_EXTRACT_LANE(I8x16, S)
#undef SIMD_VISIT_EXTRACT_LANE

#define SIMD_VISIT_REPLACE_LANE(Type)                                         \
  template <typename Adapter>                                                 \
  void InstructionSelectorT<Adapter>::Visit##Type##ReplaceLane(node_t node) { \
    S390OperandGeneratorT<Adapter> g(this);                                   \
    int32_t lane;                                                             \
    if constexpr (Adapter::IsTurboshaft) {                                    \
      using namespace turboshaft; /* NOLINT(build/namespaces) */              \
      const Operation& op = this->Get(node);                                  \
      lane = op.template Cast<Simd128ReplaceLaneOp>().lane;                   \
    } else {                                                                  \
      lane = OpParameter<int32_t>(node->op());                                \
    }                                                                         \
    Emit(kS390_##Type##ReplaceLane, g.DefineAsRegister(node),                 \
         g.UseRegister(this->input_at(node, 0)), g.UseImmediate(lane),        \
         g.UseRegister(this->input_at(node, 1)));                             \
  }
SIMD_TYPES(SIMD_VISIT_REPLACE_LANE)
#undef SIMD_VISIT_REPLACE_LANE

#define SIMD_VISIT_BINOP(Opcode)                                   \
  template <typename Adapter>                                      \
  void InstructionSelectorT<Adapter>::Visit##Opcode(node_t node) { \
    S390OperandGeneratorT<Adapter> g(this);                        \
    Emit(kS390_##Opcode, g.DefineAsRegister(node),                 \
         g.UseRegister(this->input_at(node, 0)),                   \
         g.UseRegister(this->input_at(node, 1)));                  \
  }
SIMD_BINOP_LIST(SIMD_VISIT_BINOP)
#undef SIMD_VISIT_BINOP
#undef SIMD_BINOP_LIST

#define SIMD_VISIT_BINOP_UNIQUE_REGISTER(Opcode)                         \
  template <typename Adapter>                                            \
  void InstructionSelectorT<Adapter>::Visit##Opcode(node_t node) {       \
    S390OperandGeneratorT<Adapter> g(this);                              \
    InstructionOperand temps[] = {g.TempSimd128Register(),               \
                                  g.TempSimd128Register()};              \
    Emit(kS390_##Opcode, g.DefineAsRegister(node),                       \
         g.UseUniqueRegister(this->input_at(node, 0)),                   \
         g.UseUniqueRegister(this->input_at(node, 1)), arraysize(temps), \
         temps);                                                         \
  }
SIMD_BINOP_UNIQUE_REGISTER_LIST(SIMD_VISIT_BINOP_UNIQUE_REGISTER)
#undef SIMD_VISIT_BINOP_UNIQUE_REGISTER
#undef SIMD_BINOP_UNIQUE_REGISTER_LIST

#define SIMD_VISIT_UNOP(Opcode)                                    \
  template <typename Adapter>                                      \
  void InstructionSelectorT<Adapter>::Visit##Opcode(node_t node) { \
    S390OperandGeneratorT<Adapter> g(this);                        \
    Emit(kS390_##Opcode, g.DefineAsRegister(node),                 \
         g.UseRegister(this->input_at(node, 0)));                  \
  }
SIMD_UNOP_LIST(SIMD_VISIT_UNOP)
#undef SIMD_VISIT_UNOP
#undef SIMD_UNOP_LIST

#define SIMD_VISIT_UNOP_UNIQUE_REGISTER(Opcode)                          \
  template <typename Adapter>                                            \
  void InstructionSelectorT<Adapter>::Visit##Opcode(node_t node) {       \
    S390OperandGeneratorT<Adapter> g(this);                              \
    InstructionOperand temps[] = {g.TempSimd128Register()};              \
    Emit(kS390_##Opcode, g.DefineAsRegister(node),                       \
         g.UseUniqueRegister(this->input_at(node, 0)), arraysize(temps), \
         temps);                                                         \
  }
SIMD_UNOP_UNIQUE_REGISTER_LIST(SIMD_VISIT_UNOP_UNIQUE_REGISTER)
#undef SIMD_VISIT_UNOP_UNIQUE_REGISTER
#undef SIMD_UNOP_UNIQUE_REGISTER_LIST

#define SIMD_VISIT_QFMOP(Opcode)                                   \
  template <typename Adapter>                                      \
  void InstructionSelectorT<Adapter>::Visit##Opcode(node_t node) { \
    S390OperandGeneratorT<Adapter> g(this);                        \
    Emit(kS390_##Opcode, g.DefineSameAsFirst(node),                \
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
    S390OperandGeneratorT<Adapter> g(this);
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
    Emit(kS390_I8x16Shuffle, g.DefineAsRegister(node), g.UseRegister(input0),
         g.UseRegister(input1),
         g.UseImmediate(wasm::SimdShuffle::Pack4Lanes(shuffle_remapped)),
         g.UseImmediate(wasm::SimdShuffle::Pack4Lanes(shuffle_remapped + 4)),
         g.UseImmediate(wasm::SimdShuffle::Pack4Lanes(shuffle_remapped + 8)),
         g.UseImmediate(wasm::SimdShuffle::Pack4Lanes(shuffle_remapped + 12)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI8x16Swizzle(node_t node) {
  S390OperandGeneratorT<Adapter> g(this);
  bool relaxed;
  if constexpr (Adapter::IsTurboshaft) {
    const turboshaft::Simd128BinopOp& binop =
        this->Get(node).template Cast<turboshaft::Simd128BinopOp>();
    DCHECK(binop.kind ==
           turboshaft::any_of(
               turboshaft::Simd128BinopOp::Kind::kI8x16Swizzle,
               turboshaft::Simd128BinopOp::Kind::kI8x16RelaxedSwizzle));
    relaxed =
        binop.kind == turboshaft::Simd128BinopOp::Kind::kI8x16RelaxedSwizzle;
  } else {
    relaxed = OpParameter<bool>(node->op());
  }
    // TODO(miladfarca): Optimize Swizzle if relaxed.
    USE(relaxed);

    Emit(kS390_I8x16Swizzle, g.DefineAsRegister(node),
         g.UseUniqueRegister(this->input_at(node, 0)),
         g.UseUniqueRegister(this->input_at(node, 1)));
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
template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI8x16Swizzle(node_t node) {
  UNREACHABLE();
}
#endif  // V8_ENABLE_WEBASSEMBLY

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
    S390OperandGeneratorT<Adapter> g(this);
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
      Emit(kS390_S128Zero, dst);
    } else if (all_ones) {
      Emit(kS390_S128AllOnes, dst);
    } else {
      // We have to use Pack4Lanes to reverse the bytes (lanes) on BE,
      // Which in this case is ineffective on LE.
      Emit(
          kS390_S128Const, dst,
          g.UseImmediate(Pack4Lanes(reinterpret_cast<uint8_t*>(&val[0]))),
          g.UseImmediate(Pack4Lanes(reinterpret_cast<uint8_t*>(&val[0]) + 4)),
          g.UseImmediate(Pack4Lanes(reinterpret_cast<uint8_t*>(&val[0]) + 8)),
          g.UseImmediate(Pack4Lanes(reinterpret_cast<uint8_t*>(&val[0]) + 12)));
    }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitS128Zero(node_t node) {
    S390OperandGeneratorT<Adapter> g(this);
    Emit(kS390_S128Zero, g.DefineAsRegister(node));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitS128Select(node_t node) {
    S390OperandGeneratorT<Adapter> g(this);
    Emit(kS390_S128Select, g.DefineAsRegister(node),
         g.UseRegister(this->input_at(node, 0)),
         g.UseRegister(this->input_at(node, 1)),
         g.UseRegister(this->input_at(node, 2)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::EmitPrepareResults(
    ZoneVector<PushParameter>* results, const CallDescriptor* call_descriptor,
    node_t node) {
    S390OperandGeneratorT<Adapter> g(this);

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
        Emit(kS390_Peek, g.DefineAsRegister(output.node),
             g.UseImmediate(reverse_slot));
      }
    }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitLoadLane(node_t node) {
  InstructionCode opcode;
  int32_t lane;
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const Simd128LaneMemoryOp& load =
        this->Get(node).template Cast<Simd128LaneMemoryOp>();
    lane = load.lane;
    switch (load.lane_kind) {
      case Simd128LaneMemoryOp::LaneKind::k8:
        opcode = kS390_S128Load8Lane;
        break;
      case Simd128LaneMemoryOp::LaneKind::k16:
        opcode = kS390_S128Load16Lane;
        break;
      case Simd128LaneMemoryOp::LaneKind::k32:
        opcode = kS390_S128Load32Lane;
        break;
      case Simd128LaneMemoryOp::LaneKind::k64:
        opcode = kS390_S128Load64Lane;
        break;
    }
  } else {
    LoadLaneParameters params = LoadLaneParametersOf(node->op());
    lane = params.laneidx;
    if (params.rep == MachineType::Int8()) {
      opcode = kS390_S128Load8Lane;
    } else if (params.rep == MachineType::Int16()) {
      opcode = kS390_S128Load16Lane;
    } else if (params.rep == MachineType::Int32()) {
      opcode = kS390_S128Load32Lane;
    } else if (params.rep == MachineType::Int64()) {
      opcode = kS390_S128Load64Lane;
    } else {
      UNREACHABLE();
    }
  }
    S390OperandGeneratorT<Adapter> g(this);
    InstructionOperand outputs[] = {g.DefineSameAsFirst(node)};
    InstructionOperand inputs[5];
    size_t input_count = 0;

    inputs[input_count++] = g.UseRegister(this->input_at(node, 2));
    inputs[input_count++] = g.UseImmediate(lane);

    AddressingMode mode =
        g.GetEffectiveAddressMemoryOperand(node, inputs, &input_count);
    opcode |= AddressingModeField::encode(mode);
    Emit(opcode, 1, outputs, input_count, inputs);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitLoadTransform(node_t node) {
  ArchOpcode opcode;
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const Simd128LoadTransformOp& op =
        this->Get(node).template Cast<Simd128LoadTransformOp>();
    switch (op.transform_kind) {
      case Simd128LoadTransformOp::TransformKind::k8Splat:
        opcode = kS390_S128Load8Splat;
        break;
      case Simd128LoadTransformOp::TransformKind::k16Splat:
        opcode = kS390_S128Load16Splat;
        break;
      case Simd128LoadTransformOp::TransformKind::k32Splat:
        opcode = kS390_S128Load32Splat;
        break;
      case Simd128LoadTransformOp::TransformKind::k64Splat:
        opcode = kS390_S128Load64Splat;
        break;
      case Simd128LoadTransformOp::TransformKind::k8x8S:
        opcode = kS390_S128Load8x8S;
        break;
      case Simd128LoadTransformOp::TransformKind::k8x8U:
        opcode = kS390_S128Load8x8U;
        break;
      case Simd128LoadTransformOp::TransformKind::k16x4S:
        opcode = kS390_S128Load16x4S;
        break;
      case Simd128LoadTransformOp::TransformKind::k16x4U:
        opcode = kS390_S128Load16x4U;
        break;
      case Simd128LoadTransformOp::TransformKind::k32x2S:
        opcode = kS390_S128Load32x2S;
        break;
      case Simd128LoadTransformOp::TransformKind::k32x2U:
        opcode = kS390_S128Load32x2U;
        break;
      case Simd128LoadTransformOp::TransformKind::k32Zero:
        opcode = kS390_S128Load32Zero;
        break;
      case Simd128LoadTransformOp::TransformKind::k64Zero:
        opcode = kS390_S128Load64Zero;
        break;
      default:
        UNIMPLEMENTED();
    }
  } else {
    LoadTransformParameters params = LoadTransformParametersOf(node->op());
    switch (params.transformation) {
      case LoadTransformation::kS128Load8Splat:
        opcode = kS390_S128Load8Splat;
        break;
      case LoadTransformation::kS128Load16Splat:
        opcode = kS390_S128Load16Splat;
        break;
      case LoadTransformation::kS128Load32Splat:
        opcode = kS390_S128Load32Splat;
        break;
      case LoadTransformation::kS128Load64Splat:
        opcode = kS390_S128Load64Splat;
        break;
      case LoadTransformation::kS128Load8x8S:
        opcode = kS390_S128Load8x8S;
        break;
      case LoadTransformation::kS128Load8x8U:
        opcode = kS390_S128Load8x8U;
        break;
      case LoadTransformation::kS128Load16x4S:
        opcode = kS390_S128Load16x4S;
        break;
      case LoadTransformation::kS128Load16x4U:
        opcode = kS390_S128Load16x4U;
        break;
      case LoadTransformation::kS128Load32x2S:
        opcode = kS390_S128Load32x2S;
        break;
      case LoadTransformation::kS128Load32x2U:
        opcode = kS390_S128Load32x2U;
        break;
      case LoadTransformation::kS128Load32Zero:
        opcode = kS390_S128Load32Zero;
        break;
      case LoadTransformation::kS128Load64Zero:
        opcode = kS390_S128Load64Zero;
        break;
      default:
        UNREACHABLE();
    }
  }
  VisitLoad(node, node, opcode);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitStoreLane(node_t node) {
  InstructionCode opcode = kArchNop;
  int32_t lane;
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const Simd128LaneMemoryOp& store =
        this->Get(node).template Cast<Simd128LaneMemoryOp>();
    lane = store.lane;
    switch (store.lane_kind) {
      case Simd128LaneMemoryOp::LaneKind::k8:
        opcode = kS390_S128Store8Lane;
        break;
      case Simd128LaneMemoryOp::LaneKind::k16:
        opcode = kS390_S128Store16Lane;
        break;
      case Simd128LaneMemoryOp::LaneKind::k32:
        opcode = kS390_S128Store32Lane;
        break;
      case Simd128LaneMemoryOp::LaneKind::k64:
        opcode = kS390_S128Store64Lane;
        break;
    }
  } else {
    StoreLaneParameters params = StoreLaneParametersOf(node->op());
    lane = params.laneidx;
    if (params.rep == MachineRepresentation::kWord8) {
      opcode = kS390_S128Store8Lane;
    } else if (params.rep == MachineRepresentation::kWord16) {
      opcode = kS390_S128Store16Lane;
    } else if (params.rep == MachineRepresentation::kWord32) {
      opcode = kS390_S128Store32Lane;
    } else if (params.rep == MachineRepresentation::kWord64) {
      opcode = kS390_S128Store64Lane;
    } else {
      UNREACHABLE();
    }
  }
  S390OperandGeneratorT<Adapter> g(this);
  InstructionOperand inputs[5];
  size_t input_count = 0;

  inputs[input_count++] = g.UseRegister(this->input_at(node, 2));
  inputs[input_count++] = g.UseImmediate(lane);

  AddressingMode mode =
      g.GetEffectiveAddressMemoryOperand(node, inputs, &input_count);
  opcode |= AddressingModeField::encode(mode);
  Emit(opcode, 0, nullptr, input_count, inputs);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI16x8DotI8x16I7x16S(node_t node) {
    S390OperandGeneratorT<Adapter> g(this);
    Emit(kS390_I16x8DotI8x16S, g.DefineAsRegister(node),
         g.UseUniqueRegister(this->input_at(node, 0)),
         g.UseUniqueRegister(this->input_at(node, 1)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4DotI8x16I7x16AddS(node_t node) {
    S390OperandGeneratorT<Adapter> g(this);
    InstructionOperand temps[] = {g.TempSimd128Register()};
    Emit(kS390_I32x4DotI8x16AddS, g.DefineAsRegister(node),
         g.UseUniqueRegister(this->input_at(node, 0)),
         g.UseUniqueRegister(this->input_at(node, 1)),
         g.UseUniqueRegister(this->input_at(node, 2)), arraysize(temps), temps);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTruncateFloat32ToInt32(node_t node) {
  S390OperandGeneratorT<Adapter> g(this);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const Operation& op = this->Get(node);
    InstructionCode opcode = kS390_Float32ToInt32;
    if (op.Is<Opmask::kTruncateFloat32ToInt32OverflowToMin>()) {
      opcode |= MiscField::encode(true);
    }
    Emit(opcode, g.DefineAsRegister(node),
         g.UseRegister(this->input_at(node, 0)));
  } else {
    InstructionCode opcode = kS390_Float32ToInt32;
    TruncateKind kind = OpParameter<TruncateKind>(node->op());
    if (kind == TruncateKind::kSetOverflowToMin) {
      opcode |= MiscField::encode(true);
    }

    Emit(opcode, g.DefineAsRegister(node), g.UseRegister(node->InputAt(0)));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTruncateFloat32ToUint32(node_t node) {
    S390OperandGeneratorT<Adapter> g(this);
    if constexpr (Adapter::IsTurboshaft) {
      using namespace turboshaft;  // NOLINT(build/namespaces)
      const Operation& op = this->Get(node);
      InstructionCode opcode = kS390_Float32ToUint32;
      if (op.Is<Opmask::kTruncateFloat32ToUint32OverflowToMin>()) {
        opcode |= MiscField::encode(true);
      }

      Emit(opcode, g.DefineAsRegister(node),
           g.UseRegister(this->input_at(node, 0)));
    } else {
      InstructionCode opcode = kS390_Float32ToUint32;
      TruncateKind kind = OpParameter<TruncateKind>(node->op());
      if (kind == TruncateKind::kSetOverflowToMin) {
        opcode |= MiscField::encode(true);
      }

      Emit(opcode, g.DefineAsRegister(node), g.UseRegister(node->InputAt(0)));
    }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::AddOutputToSelectContinuation(
    OperandGenerator* g, int first_input_index, node_t node) {
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
         MachineOperatorBuilder::kFloat32RoundTiesEven |
         MachineOperatorBuilder::kFloat64RoundTiesEven |
         MachineOperatorBuilder::kFloat64RoundTiesAway |
         MachineOperatorBuilder::kWord32Popcnt |
         MachineOperatorBuilder::kInt32AbsWithOverflow |
         MachineOperatorBuilder::kInt64AbsWithOverflow |
         MachineOperatorBuilder::kWord64Popcnt;
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