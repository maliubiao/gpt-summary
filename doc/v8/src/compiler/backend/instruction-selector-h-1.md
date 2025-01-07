Response:
The user is asking for a summary of the functionality of the provided C++ header file `v8/src/compiler/backend/instruction-selector.h`. This is the second part of the file. I need to extract the key responsibilities and operations defined within this section.

Here's a breakdown of how to approach this:

1. **Identify Key Structures and Methods:** Look for class and method declarations. These are the building blocks of the functionality.
2. **Analyze Method Names:** The names of the methods often provide a strong indication of their purpose (e.g., `VisitBlock`, `VisitInt32Add`, `EmitPrepareArguments`).
3. **Group Related Functionality:**  Notice patterns in the method names. Many methods start with `Visit`, suggesting a pattern for processing different types of nodes in a graph.
4. **Pay Attention to Data Structures:**  Look for the types of arguments and return values. This can reveal what data is being processed.
5. **Consider the Context:** The file path `v8/src/compiler/backend/` suggests this code is part of the V8 compiler's backend, specifically involved in instruction selection.
6. **Address Specific Instructions:** The prompt asks about `.tq` files, JavaScript relevance, code logic, and common errors. I need to address these points based on the content.
7. **Synthesize a Summary:** Combine the observations into a concise description of the header file's role.

**Mental Walkthrough of the Code:**

* **`AddInputsToFrameStateDescriptor` and `AddOperandToStateValueDescriptor`:** These seem related to managing the state of the program during execution, potentially for debugging or optimization.
* **`VisitBlock`, `VisitControl`, `VisitNode`:** These are core methods for traversing and processing a code graph.
* **`Visit[OperationName]` (e.g., `VisitWord32And`, `VisitFloat64Add`):**  A large number of these indicate the component is responsible for generating instructions for specific operations. This is the heart of instruction selection.
* **`VisitLoad`, `VisitStore`:** Handling memory access operations.
* **`VisitBitcast...`, `Change...`, `Truncate...`, `Round...`:**  Dealing with type conversions and manipulations.
* **`VisitFloat...` methods:**  Specific handling for floating-point operations, including IEEE 754 standards.
* **`VisitCall`, `VisitDeoptimize...`, `VisitTailCall`, `VisitGoto`, `VisitBranch`, `VisitSwitch`, `VisitReturn`, `VisitThrow`:** Managing control flow and exceptional situations.
* **`EmitPrepareArguments`, `EmitPrepareResults`:** Preparing for function calls.
* **`VisitI8x16RelaxedSwizzle`, `CanonicalizeShuffle`, `SwapShuffleInputs`, `VisitSimd...`:**  Handling SIMD (Single Instruction, Multiple Data) vector operations.
* **Atomic operations (`Word32Atomic...`, `Word64Atomic...`):**  Dealing with thread-safe operations.
* **Helper functions:**  Methods like `GetComparisonFlagCondition`, `MarkPairProjectionsAsWord32`, etc., provide auxiliary functionality.
* **Member variables:**  Variables like `schedule_`, `linkage_`, `sequence_`, `instructions_`, etc., hold the state and data used during instruction selection.

**Addressing Specific Instructions from the Prompt:**

* **`.tq` files:** The code is C++ (`.h`), not Torque (`.tq`).
* **JavaScript relevance:** The operations listed (arithmetic, bitwise, floating-point, memory access, function calls) directly correspond to JavaScript operations.
* **Code logic/Assumptions:** The `Visit...` methods likely assume the input `node_t` represents a valid node in the intermediate representation (IR) of the code. The output would be the corresponding machine instructions.
* **Common errors:**  While the header doesn't directly show error handling, a common error in instruction selection would be generating incorrect or inefficient instructions for a given IR node.

By following this process, I can construct a comprehensive and accurate summary of the provided header file.
这是 `v8/src/compiler/backend/instruction-selector.h` 文件的第二部分，它延续了第一部分定义的功能，主要集中在以下几个方面：

**1. 架构特定的代码生成方法 (Architecture-specific graph covering methods):**

这部分定义了针对特定中间表示节点（`node_t`）生成机器指令的方法。每个 `Visit` 开头的方法都负责处理一种特定的操作符或节点类型。

* **算术和逻辑运算:** 涵盖了各种 32 位和 64 位整数以及浮点数的算术（加、减、乘、除、模）、位运算（与、或、异或、移位、循环移位）操作。例如 `VisitInt32Add` 处理 32 位整数加法。
* **溢出检测运算:** 包含带溢出检测的加法、减法和乘法操作，例如 `VisitInt32AddWithOverflow`。
* **比较运算:**  定义了各种整数和浮点数的比较操作，例如 `VisitInt32LessThan`，`VisitFloat64Equal`。
* **内存操作:** 包含了加载 (`VisitLoad`) 和存储 (`VisitStore`) 操作，以及一些特殊的内存操作如受保护的存储 (`VisitProtectedStore`) 和未对齐的加载/存储 (`VisitUnalignedLoad`, `VisitUnalignedStore`)。
* **类型转换:**  提供了各种类型之间的转换操作，例如整数到浮点数 (`ChangeInt32ToFloat64`)，浮点数到整数 (`TruncateFloat64ToInt32`)，以及位转换 (`BitcastTaggedToWord`)。
* **浮点数特殊运算:** 包括 IEEE 754 标准的浮点数运算（例如，平方根、三角函数、指数、对数），以及一些特殊的浮点数操作，例如提取和插入浮点数的低/高 32 位字 (`Float64ExtractLowWord32`, `Float64InsertHighWord32`)。
* **原子操作:**  定义了 32 位和 64 位整数的原子加载、存储和各种原子算术/逻辑运算 (`Word32AtomicAdd`, `Word64AtomicCompareExchange`)。
* **控制流操作:** 处理控制流相关的节点，例如调用 (`VisitCall`)、条件跳转 (`VisitBranch`)、switch 语句 (`VisitSwitch`)、返回 (`VisitReturn`)、抛出异常 (`VisitThrow`) 和各种形式的去优化 (`VisitDeoptimizeIf`, `VisitDeoptimizeUnless`)。
* **调试和断言:** 包含用于调试的断点 (`VisitDebugBreak`) 和静态断言 (`VisitStaticAssert`)。
* **SIMD (单指令多数据) 向量操作:**  定义了针对 SIMD 指令的处理方法，例如 `VisitI8x16RelaxedSwizzle` 以及通过宏 `MACHINE_SIMD128_OP_LIST` 和 `MACHINE_SIMD256_OP_LIST` 定义的更多 SIMD 操作。
* **Wasm 特有操作:**  使用 `IF_WASM` 宏包裹了一些 WebAssembly 特有的操作，例如加载和设置栈指针 (`LoadStackPointer`, `SetStackPointer`)。

**2. 其他辅助方法:**

* **`VisitLoad(node_t node, node_t value, InstructionCode opcode)`:**  允许使用给定的值和操作码替换加载节点。
* **`VisitLoadTransform`:** 用于在加载后进行转换。
* **`VisitFinishRegion`:**  可能用于标记代码区域的结束。
* **`VisitParameter`, `VisitIfException`, `VisitOsrValue`, `VisitPhi`, `VisitProjection`, `VisitConstant`:** 处理不同类型的中间表示节点。
* **`VisitTailCall`:** 处理尾调用优化。
* **`VisitGoto`:** 处理无条件跳转。
* **`VisitSelect`:** 处理选择操作（类似于三元运算符）。
* **`VisitRetain`:**  可能与对象的保留或生命周期管理有关。
* **`VisitUnreachable`:**  处理不可达代码。
* **`VisitDeadValue`:**  处理死值（不再使用的值）。
* **`VisitBitcastWord32PairToFloat64`:**  将 32 位字对转换为 64 位浮点数。
* **`TryPrepareScheduleFirstProjection`:**  可能与调度投影节点有关。
* **`VisitStackPointerGreaterThan`:**  比较栈指针。
* **`VisitWordCompareZero`:**  与零进行比较。
* **`EmitPrepareArguments`, `EmitPrepareResults`:**  为函数调用准备参数和结果。
* **`EmitMoveFPRToParam`, `EmitMoveParamToFPR`:** (LOONG64 特有)  处理浮点参数在寄存器之间的移动。
* **`CanProduceSignalingNaN`:**  检查节点是否可能产生信号 NaN。
* **`AddOutputToSelectContinuation`:**  为选择操作添加输出。
* **`ConsumeEqualZero`:**  处理与零相等的比较。
* **`CanonicalizeShuffle`, `SwapShuffleInputs`:**  用于规范化和调整 SIMD shuffle 操作，以便更好地匹配架构指令。

**3. 数据成员和类型定义:**

* 包含了一些用于存储和管理指令选择过程中的状态和数据的成员变量，例如 `instructions_` (生成的指令列表), `defined_`, `used_` (寄存器定义和使用信息)。
* 定义了一些辅助的结构体和枚举，例如 `FrameStateInput` 用于缓存帧状态信息。

**如果 `v8/src/compiler/backend/instruction-selector.h` 以 `.tq` 结尾:**

那么它将是一个 **V8 Torque 源代码**。Torque 是一种用于编写 V8 内部函数的领域特定语言，它允许以更类型安全和可维护的方式生成 C++ 代码。  在这种情况下，该文件将包含用 Torque 语法编写的指令选择逻辑。

**与 JavaScript 功能的关系:**

`instruction-selector.h` 中定义的功能直接对应于 JavaScript 语言的各种操作。当 V8 执行 JavaScript 代码时，编译器会将 JavaScript 代码转换为中间表示，然后指令选择器负责将这些中间表示节点转换为目标机器的实际机器指令。

**JavaScript 示例:**

```javascript
function add(a, b) {
  return a + b;
}

let x = 10;
let y = 20;
let sum = add(x, y);
```

在这个简单的 JavaScript 例子中，指令选择器需要生成以下类型的机器指令（简化说明）：

* **加载常量:** 将 `10` 和 `20` 加载到寄存器中。
* **加法运算:**  执行整数加法操作（对应 `VisitInt32Add`）。
* **存储结果:** 将加法结果存储到 `sum` 变量对应的内存位置。
* **函数调用:**  生成调用 `add` 函数的指令（对应 `VisitCall` 或 `VisitTailCall`，取决于是否是尾调用）。
* **返回指令:**  生成函数返回的指令（对应 `VisitReturn`）。

**代码逻辑推理和假设输入输出:**

假设输入是一个代表整数加法操作的中间表示节点 `node_t add_node`，它有两个输入：表示操作数 `a` 和 `b` 的节点。

**假设输入:**

* `add_node`:  表示整数加法的中间表示节点。
* `add_node` 的输入 0: `operand_a_node`，其值为 10，类型为 `Int32`。
* `add_node` 的输入 1: `operand_b_node`，其值为 20，类型为 `Int32`。

**代码逻辑:**

`VisitInt32Add(add_node)` 方法会被调用。它会：

1. 获取 `operand_a_node` 和 `operand_b_node` 对应的操作数（可能已经分配了寄存器）。
2. 生成一条目标架构的整数加法指令，例如在 x64 架构上可能是 `addl %reg1, %reg2` (将 `%reg1` 的值加到 `%reg2` 上)。
3. 将结果存储到一个新的寄存器或内存位置。

**假设输出:**

一条表示整数加法的机器指令，例如：

```assembly
addl $10, $20, %regX  // 假设将 10 和 20 相加，结果存储到寄存器 %regX
```

或者更常见的，假设操作数已经存在于寄存器中：

```assembly
movl $10, %reg1       // 将 10 移动到寄存器 %reg1
movl $20, %reg2       // 将 20 移动到寄存器 %reg2
addl %reg1, %reg2      // 将 %reg1 和 %reg2 相加，结果存储到 %reg2
```

**用户常见的编程错误:**

虽然 `instruction-selector.h` 是编译器内部的代码，但其目标是正确地将高级语言转换为机器码。用户编程错误最终会导致不同的中间表示，并由指令选择器处理。一些可能与指令选择相关的用户错误包括：

* **类型不匹配:**  例如，尝试将一个字符串与一个数字相加，会导致类型转换或错误，指令选择器需要为这些转换生成代码。
* **溢出:**  整数运算超出范围，例如非常大的整数相加，指令选择器可能需要生成带溢出检测的指令。
* **浮点数精度问题:**  浮点数运算的精度限制可能导致意外的结果，指令选择器需要生成正确的浮点数运算指令来尽可能地符合 IEEE 754 标准。
* **未定义的行为:**  例如，除以零，指令选择器可能需要生成检查和抛出异常的代码。

**归纳一下 `v8/src/compiler/backend/instruction-selector.h` 的功能 (第 2 部分):**

`v8/src/compiler/backend/instruction-selector.h` 的第二部分主要负责定义了 `InstructionSelector` 类的成员函数，这些函数实现了**将编译器生成的中间表示 (IR) 转换为目标机器指令的核心逻辑**。它包含了针对各种操作符、数据类型和控制流结构的特定代码生成方法。这部分还包含了处理 SIMD 指令、WebAssembly 特有操作以及提供辅助功能的其他方法。  本质上，它是 V8 编译器后端将高级抽象的代码转化为实际可在硬件上执行的低级指令的关键组件。

Prompt: 
```
这是目录为v8/src/compiler/backend/instruction-selector.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/instruction-selector.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
ndVector* inputs,
                                         FrameStateInputKind kind, Zone* zone);
  size_t AddInputsToFrameStateDescriptor(StateValueList* values,
                                         InstructionOperandVector* inputs,
                                         OperandGenerator* g,
                                         StateObjectDeduplicator* deduplicator,
                                         node_t node, FrameStateInputKind kind,
                                         Zone* zone);
  size_t AddOperandToStateValueDescriptor(StateValueList* values,
                                          InstructionOperandVector* inputs,
                                          OperandGenerator* g,
                                          StateObjectDeduplicator* deduplicator,
                                          node_t input, MachineType type,
                                          FrameStateInputKind kind, Zone* zone);

  // ===========================================================================
  // ============= Architecture-specific graph covering methods. ===============
  // ===========================================================================

  // Visit nodes in the given block and generate code.
  void VisitBlock(block_t block);

  // Visit the node for the control flow at the end of the block, generating
  // code if necessary.
  void VisitControl(block_t block);

  // Visit the node and generate code, if any.
  void VisitNode(node_t node);

  // Visit the node and generate code for IEEE 754 functions.
  void VisitFloat64Ieee754Binop(node_t, InstructionCode code);
  void VisitFloat64Ieee754Unop(node_t, InstructionCode code);

#define DECLARE_GENERATOR_T(x) void Visit##x(node_t node);
  DECLARE_GENERATOR_T(Word32And)
  DECLARE_GENERATOR_T(Word32Xor)
  DECLARE_GENERATOR_T(Int32Add)
  DECLARE_GENERATOR_T(Int32Sub)
  DECLARE_GENERATOR_T(Int32Mul)
  DECLARE_GENERATOR_T(Int32MulHigh)
  DECLARE_GENERATOR_T(Int32Div)
  DECLARE_GENERATOR_T(Int32Mod)
  DECLARE_GENERATOR_T(Uint32Div)
  DECLARE_GENERATOR_T(Uint32Mod)
  DECLARE_GENERATOR_T(Uint32MulHigh)
  DECLARE_GENERATOR_T(Word32Or)
  DECLARE_GENERATOR_T(Word32Sar)
  DECLARE_GENERATOR_T(Word32Shl)
  DECLARE_GENERATOR_T(Word32Shr)
  DECLARE_GENERATOR_T(Word32Rol)
  DECLARE_GENERATOR_T(Word32Ror)
  DECLARE_GENERATOR_T(Word64Shl)
  DECLARE_GENERATOR_T(Word64Sar)
  DECLARE_GENERATOR_T(Word64Shr)
  DECLARE_GENERATOR_T(Word64Rol)
  DECLARE_GENERATOR_T(Word64Ror)
  DECLARE_GENERATOR_T(Int32AddWithOverflow)
  DECLARE_GENERATOR_T(Int32MulWithOverflow)
  DECLARE_GENERATOR_T(Int32SubWithOverflow)
  DECLARE_GENERATOR_T(Int64AddWithOverflow)
  DECLARE_GENERATOR_T(Int64SubWithOverflow)
  DECLARE_GENERATOR_T(Int64MulWithOverflow)
  DECLARE_GENERATOR_T(Int64Add)
  DECLARE_GENERATOR_T(Word64And)
  DECLARE_GENERATOR_T(Word64Or)
  DECLARE_GENERATOR_T(Word64Xor)
  DECLARE_GENERATOR_T(Int64Sub)
  DECLARE_GENERATOR_T(Int64Mul)
  DECLARE_GENERATOR_T(Int64MulHigh)
  DECLARE_GENERATOR_T(Int64Div)
  DECLARE_GENERATOR_T(Int64Mod)
  DECLARE_GENERATOR_T(Uint64Div)
  DECLARE_GENERATOR_T(Uint64Mod)
  DECLARE_GENERATOR_T(Uint64MulHigh)
  DECLARE_GENERATOR_T(Word32AtomicStore)
  DECLARE_GENERATOR_T(Word64AtomicStore)
  DECLARE_GENERATOR_T(Word32Equal)
  DECLARE_GENERATOR_T(Word64Equal)
  DECLARE_GENERATOR_T(Int32LessThan)
  DECLARE_GENERATOR_T(Int32LessThanOrEqual)
  DECLARE_GENERATOR_T(Int64LessThan)
  DECLARE_GENERATOR_T(Int64LessThanOrEqual)
  DECLARE_GENERATOR_T(Uint32LessThan)
  DECLARE_GENERATOR_T(Uint32LessThanOrEqual)
  DECLARE_GENERATOR_T(Uint64LessThan)
  DECLARE_GENERATOR_T(Uint64LessThanOrEqual)
  DECLARE_GENERATOR_T(Float64Sub)
  DECLARE_GENERATOR_T(Float64Div)
  DECLARE_GENERATOR_T(Float32Equal)
  DECLARE_GENERATOR_T(Float32LessThan)
  DECLARE_GENERATOR_T(Float32LessThanOrEqual)
  DECLARE_GENERATOR_T(Float64Equal)
  DECLARE_GENERATOR_T(Float64LessThan)
  DECLARE_GENERATOR_T(Float64LessThanOrEqual)
  DECLARE_GENERATOR_T(Load)
  DECLARE_GENERATOR_T(StackPointerGreaterThan)
  DECLARE_GENERATOR_T(Store)
  DECLARE_GENERATOR_T(ProtectedStore)
  DECLARE_GENERATOR_T(BitcastTaggedToWord)
  DECLARE_GENERATOR_T(BitcastWordToTagged)
  DECLARE_GENERATOR_T(BitcastSmiToWord)
  DECLARE_GENERATOR_T(ChangeInt32ToInt64)
  DECLARE_GENERATOR_T(ChangeInt32ToFloat64)
  DECLARE_GENERATOR_T(ChangeFloat32ToFloat64)
  DECLARE_GENERATOR_T(RoundFloat64ToInt32)
  DECLARE_GENERATOR_T(TruncateFloat64ToWord32)
  DECLARE_GENERATOR_T(TruncateFloat64ToFloat32)
  DECLARE_GENERATOR_T(TruncateFloat64ToFloat16RawBits)
  DECLARE_GENERATOR_T(TruncateFloat32ToInt32)
  DECLARE_GENERATOR_T(TruncateFloat32ToUint32)
  DECLARE_GENERATOR_T(ChangeFloat64ToInt32)
  DECLARE_GENERATOR_T(ChangeFloat64ToUint32)
  DECLARE_GENERATOR_T(ChangeFloat64ToInt64)
  DECLARE_GENERATOR_T(ChangeFloat64ToUint64)
  DECLARE_GENERATOR_T(TruncateFloat64ToInt64)
  DECLARE_GENERATOR_T(RoundInt32ToFloat32)
  DECLARE_GENERATOR_T(RoundInt64ToFloat32)
  DECLARE_GENERATOR_T(RoundInt64ToFloat64)
  DECLARE_GENERATOR_T(RoundUint32ToFloat32)
  DECLARE_GENERATOR_T(RoundUint64ToFloat32)
  DECLARE_GENERATOR_T(RoundUint64ToFloat64)
  DECLARE_GENERATOR_T(ChangeInt64ToFloat64)
  DECLARE_GENERATOR_T(ChangeUint32ToFloat64)
  DECLARE_GENERATOR_T(ChangeUint32ToUint64)
  DECLARE_GENERATOR_T(Float64ExtractLowWord32)
  DECLARE_GENERATOR_T(Float64ExtractHighWord32)
  DECLARE_GENERATOR_T(Float32Add)
  DECLARE_GENERATOR_T(Float32Sub)
  DECLARE_GENERATOR_T(Float32Mul)
  DECLARE_GENERATOR_T(Float32Div)
  DECLARE_GENERATOR_T(Float32Max)
  DECLARE_GENERATOR_T(Float32Min)
  DECLARE_GENERATOR_T(Float64Atan2)
  DECLARE_GENERATOR_T(Float64Max)
  DECLARE_GENERATOR_T(Float64Min)
  DECLARE_GENERATOR_T(Float64Add)
  DECLARE_GENERATOR_T(Float64Mul)
  DECLARE_GENERATOR_T(Float64Mod)
  DECLARE_GENERATOR_T(Float64Pow)
  DECLARE_GENERATOR_T(BitcastWord32ToWord64)
  DECLARE_GENERATOR_T(BitcastFloat32ToInt32)
  DECLARE_GENERATOR_T(BitcastFloat64ToInt64)
  DECLARE_GENERATOR_T(BitcastInt32ToFloat32)
  DECLARE_GENERATOR_T(BitcastInt64ToFloat64)
  DECLARE_GENERATOR_T(Float32Abs)
  DECLARE_GENERATOR_T(Float32Neg)
  DECLARE_GENERATOR_T(Float32RoundDown)
  DECLARE_GENERATOR_T(Float32RoundTiesEven)
  DECLARE_GENERATOR_T(Float32RoundTruncate)
  DECLARE_GENERATOR_T(Float32RoundUp)
  DECLARE_GENERATOR_T(Float32Sqrt)
  DECLARE_GENERATOR_T(Float64Abs)
  DECLARE_GENERATOR_T(Float64Acos)
  DECLARE_GENERATOR_T(Float64Acosh)
  DECLARE_GENERATOR_T(Float64Asin)
  DECLARE_GENERATOR_T(Float64Asinh)
  DECLARE_GENERATOR_T(Float64Atan)
  DECLARE_GENERATOR_T(Float64Atanh)
  DECLARE_GENERATOR_T(Float64Cbrt)
  DECLARE_GENERATOR_T(Float64Cos)
  DECLARE_GENERATOR_T(Float64Cosh)
  DECLARE_GENERATOR_T(Float64Exp)
  DECLARE_GENERATOR_T(Float64Expm1)
  DECLARE_GENERATOR_T(Float64Log)
  DECLARE_GENERATOR_T(Float64Log1p)
  DECLARE_GENERATOR_T(Float64Log10)
  DECLARE_GENERATOR_T(Float64Log2)
  DECLARE_GENERATOR_T(Float64Neg)
  DECLARE_GENERATOR_T(Float64RoundDown)
  DECLARE_GENERATOR_T(Float64RoundTiesAway)
  DECLARE_GENERATOR_T(Float64RoundTiesEven)
  DECLARE_GENERATOR_T(Float64RoundTruncate)
  DECLARE_GENERATOR_T(Float64RoundUp)
  DECLARE_GENERATOR_T(Float64Sin)
  DECLARE_GENERATOR_T(Float64Sinh)
  DECLARE_GENERATOR_T(Float64Sqrt)
  DECLARE_GENERATOR_T(Float64Tan)
  DECLARE_GENERATOR_T(Float64Tanh)
  DECLARE_GENERATOR_T(Float64SilenceNaN)
  DECLARE_GENERATOR_T(Word32Clz)
  DECLARE_GENERATOR_T(Word32Ctz)
  DECLARE_GENERATOR_T(Word32ReverseBytes)
  DECLARE_GENERATOR_T(Word32Popcnt)
  DECLARE_GENERATOR_T(Word64Popcnt)
  DECLARE_GENERATOR_T(Word64Clz)
  DECLARE_GENERATOR_T(Word64Ctz)
  DECLARE_GENERATOR_T(Word64ReverseBytes)
  DECLARE_GENERATOR_T(SignExtendWord8ToInt32)
  DECLARE_GENERATOR_T(SignExtendWord16ToInt32)
  DECLARE_GENERATOR_T(SignExtendWord8ToInt64)
  DECLARE_GENERATOR_T(SignExtendWord16ToInt64)
  DECLARE_GENERATOR_T(TruncateInt64ToInt32)
  DECLARE_GENERATOR_T(StackSlot)
  DECLARE_GENERATOR_T(LoadRootRegister)
  DECLARE_GENERATOR_T(DebugBreak)
  DECLARE_GENERATOR_T(TryTruncateFloat32ToInt64)
  DECLARE_GENERATOR_T(TryTruncateFloat64ToInt64)
  DECLARE_GENERATOR_T(TryTruncateFloat32ToUint64)
  DECLARE_GENERATOR_T(TryTruncateFloat64ToUint64)
  DECLARE_GENERATOR_T(TryTruncateFloat64ToInt32)
  DECLARE_GENERATOR_T(TryTruncateFloat64ToUint32)
  DECLARE_GENERATOR_T(Int32PairAdd)
  DECLARE_GENERATOR_T(Int32PairSub)
  DECLARE_GENERATOR_T(Int32PairMul)
  DECLARE_GENERATOR_T(Word32PairShl)
  DECLARE_GENERATOR_T(Word32PairShr)
  DECLARE_GENERATOR_T(Word32PairSar)
  DECLARE_GENERATOR_T(Float64InsertLowWord32)
  DECLARE_GENERATOR_T(Float64InsertHighWord32)
  DECLARE_GENERATOR_T(Comment)
  DECLARE_GENERATOR_T(Word32ReverseBits)
  DECLARE_GENERATOR_T(Word64ReverseBits)
  DECLARE_GENERATOR_T(AbortCSADcheck)
  DECLARE_GENERATOR_T(StorePair)
  DECLARE_GENERATOR_T(UnalignedLoad)
  DECLARE_GENERATOR_T(UnalignedStore)
  DECLARE_GENERATOR_T(Int32AbsWithOverflow)
  DECLARE_GENERATOR_T(Int64AbsWithOverflow)
  DECLARE_GENERATOR_T(TruncateFloat64ToUint32)
  DECLARE_GENERATOR_T(SignExtendWord32ToInt64)
  DECLARE_GENERATOR_T(TraceInstruction)
  DECLARE_GENERATOR_T(MemoryBarrier)
  DECLARE_GENERATOR_T(LoadStackCheckOffset)
  DECLARE_GENERATOR_T(LoadFramePointer)
  DECLARE_GENERATOR_T(LoadParentFramePointer)
  DECLARE_GENERATOR_T(ProtectedLoad)
  DECLARE_GENERATOR_T(Word32AtomicAdd)
  DECLARE_GENERATOR_T(Word32AtomicSub)
  DECLARE_GENERATOR_T(Word32AtomicAnd)
  DECLARE_GENERATOR_T(Word32AtomicOr)
  DECLARE_GENERATOR_T(Word32AtomicXor)
  DECLARE_GENERATOR_T(Word32AtomicExchange)
  DECLARE_GENERATOR_T(Word32AtomicCompareExchange)
  DECLARE_GENERATOR_T(Word64AtomicAdd)
  DECLARE_GENERATOR_T(Word64AtomicSub)
  DECLARE_GENERATOR_T(Word64AtomicAnd)
  DECLARE_GENERATOR_T(Word64AtomicOr)
  DECLARE_GENERATOR_T(Word64AtomicXor)
  DECLARE_GENERATOR_T(Word64AtomicExchange)
  DECLARE_GENERATOR_T(Word64AtomicCompareExchange)
  DECLARE_GENERATOR_T(Word32AtomicLoad)
  DECLARE_GENERATOR_T(Word64AtomicLoad)
  DECLARE_GENERATOR_T(Word32AtomicPairLoad)
  DECLARE_GENERATOR_T(Word32AtomicPairStore)
  DECLARE_GENERATOR_T(Word32AtomicPairAdd)
  DECLARE_GENERATOR_T(Word32AtomicPairSub)
  DECLARE_GENERATOR_T(Word32AtomicPairAnd)
  DECLARE_GENERATOR_T(Word32AtomicPairOr)
  DECLARE_GENERATOR_T(Word32AtomicPairXor)
  DECLARE_GENERATOR_T(Word32AtomicPairExchange)
  DECLARE_GENERATOR_T(Word32AtomicPairCompareExchange)
  DECLARE_GENERATOR_T(Simd128ReverseBytes)
  MACHINE_SIMD128_OP_LIST(DECLARE_GENERATOR_T)
  MACHINE_SIMD256_OP_LIST(DECLARE_GENERATOR_T)
  IF_WASM(DECLARE_GENERATOR_T, LoadStackPointer)
  IF_WASM(DECLARE_GENERATOR_T, SetStackPointer)
#undef DECLARE_GENERATOR_T

  // Visit the load node with a value and opcode to replace with.
  void VisitLoad(node_t node, node_t value, InstructionCode opcode);
  void VisitLoadTransform(Node* node, Node* value, InstructionCode opcode);
  void VisitFinishRegion(Node* node);
  void VisitParameter(node_t node);
  void VisitIfException(node_t node);
  void VisitOsrValue(node_t node);
  void VisitPhi(node_t node);
  void VisitProjection(node_t node);
  void VisitConstant(node_t node);
  void VisitCall(node_t call, block_t handler = {});
  void VisitDeoptimizeIf(node_t node);
  void VisitDeoptimizeUnless(node_t node);
  void VisitDynamicCheckMapsWithDeoptUnless(Node* node);
  void VisitTrapIf(node_t node, TrapId trap_id);
  void VisitTrapUnless(node_t node, TrapId trap_id);
  void VisitTailCall(node_t call);
  void VisitGoto(block_t target);
  void VisitBranch(node_t input, block_t tbranch, block_t fbranch);
  void VisitSwitch(node_t node, const SwitchInfo& sw);
  void VisitDeoptimize(DeoptimizeReason reason, id_t node_id,
                       FeedbackSource const& feedback, node_t frame_state);
  void VisitSelect(node_t node);
  void VisitReturn(node_t node);
  void VisitThrow(Node* node);
  void VisitRetain(node_t node);
  void VisitUnreachable(node_t node);
  void VisitStaticAssert(node_t node);
  void VisitDeadValue(Node* node);
  void VisitBitcastWord32PairToFloat64(node_t node);

  void TryPrepareScheduleFirstProjection(node_t maybe_projection);

  void VisitStackPointerGreaterThan(node_t node, FlagsContinuation* cont);

  void VisitWordCompareZero(node_t user, node_t value, FlagsContinuation* cont);

  void EmitPrepareArguments(ZoneVector<PushParameter>* arguments,
                            const CallDescriptor* call_descriptor, node_t node);
  void EmitPrepareResults(ZoneVector<PushParameter>* results,
                          const CallDescriptor* call_descriptor, node_t node);

  // In LOONG64, calling convention uses free GP param register to pass
  // floating-point arguments when no FP param register is available. But
  // gap does not support moving from FPR to GPR, so we add EmitMoveFPRToParam
  // to complete movement.
  void EmitMoveFPRToParam(InstructionOperand* op, LinkageLocation location);
  // Moving floating-point param from GP param register to FPR to participate in
  // subsequent operations, whether CallCFunction or normal floating-point
  // operations.
  void EmitMoveParamToFPR(node_t node, int index);

  bool CanProduceSignalingNaN(Node* node);

  void AddOutputToSelectContinuation(OperandGenerator* g, int first_input_index,
                                     node_t node);

  void ConsumeEqualZero(turboshaft::OpIndex* user, turboshaft::OpIndex* value,
                        FlagsContinuation* cont);

  // ===========================================================================
  // ============= Vector instruction (SIMD) helper fns. =======================
  // ===========================================================================
  void VisitI8x16RelaxedSwizzle(node_t node);

#if V8_ENABLE_WEBASSEMBLY
  // Canonicalize shuffles to make pattern matching simpler. Returns the shuffle
  // indices, and a boolean indicating if the shuffle is a swizzle (one input).
  template <const int simd_size = kSimd128Size,
            typename = std::enable_if_t<simd_size == kSimd128Size ||
                                        simd_size == kSimd256Size>>
  void CanonicalizeShuffle(typename Adapter::SimdShuffleView& view,
                           uint8_t* shuffle, bool* is_swizzle) {
    // Get raw shuffle indices.
    if constexpr (simd_size == kSimd128Size) {
      DCHECK(view.isSimd128());
      memcpy(shuffle, view.data(), kSimd128Size);
    } else if constexpr (simd_size == kSimd256Size) {
      DCHECK(!view.isSimd128());
      memcpy(shuffle, view.data(), kSimd256Size);
    } else {
      UNREACHABLE();
    }
    bool needs_swap;
    bool inputs_equal =
        GetVirtualRegister(view.input(0)) == GetVirtualRegister(view.input(1));
    wasm::SimdShuffle::CanonicalizeShuffle<simd_size>(inputs_equal, shuffle,
                                                      &needs_swap, is_swizzle);
    if (needs_swap) {
      SwapShuffleInputs(view);
    }
    // Duplicate the first input; for some shuffles on some architectures, it's
    // easiest to implement a swizzle as a shuffle so it might be used.
    if (*is_swizzle) {
      view.DuplicateFirstInput();
    }
  }

  // Swaps the two first input operands of the node, to help match shuffles
  // to specific architectural instructions.
  void SwapShuffleInputs(typename Adapter::SimdShuffleView& node);

#if V8_ENABLE_WASM_SIMD256_REVEC
  void VisitSimd256LoadTransform(node_t node);

#ifdef V8_TARGET_ARCH_X64
  void VisitSimd256Shufd(node_t node);
  void VisitSimd256Shufps(node_t node);
  void VisitSimd256Unpack(node_t node);
  void VisitSimdPack128To256(node_t node);
#endif  // V8_TARGET_ARCH_X64
#endif  // V8_ENABLE_WASM_SIMD256_REVEC

#ifdef V8_TARGET_ARCH_X64
  bool CanOptimizeF64x2PromoteLowF32x4(node_t node);
#endif

#endif  // V8_ENABLE_WEBASSEMBLY

  // ===========================================================================

  schedule_t schedule() const { return schedule_; }
  Linkage* linkage() const { return linkage_; }
  InstructionSequence* sequence() const { return sequence_; }
  base::Vector<const turboshaft::OpIndex> turboshaft_uses(
      turboshaft::OpIndex node) const {
    DCHECK(turboshaft_use_map_.has_value());
    return turboshaft_use_map_->uses(node);
  }
  Zone* instruction_zone() const { return sequence()->zone(); }
  Zone* zone() const { return zone_; }

  void set_instruction_selection_failed() {
    instruction_selection_failed_ = true;
  }
  bool instruction_selection_failed() { return instruction_selection_failed_; }

  FlagsCondition GetComparisonFlagCondition(
      const turboshaft::ComparisonOp& op) const;

  void MarkPairProjectionsAsWord32(node_t node);
  bool IsSourcePositionUsed(node_t node);
  void VisitWord32AtomicBinaryOperation(node_t node, ArchOpcode int8_op,
                                        ArchOpcode uint8_op,
                                        ArchOpcode int16_op,
                                        ArchOpcode uint16_op,
                                        ArchOpcode word32_op);
  void VisitWord64AtomicBinaryOperation(node_t node, ArchOpcode uint8_op,
                                        ArchOpcode uint16_op,
                                        ArchOpcode uint32_op,
                                        ArchOpcode uint64_op);
  void VisitWord64AtomicNarrowBinop(Node* node, ArchOpcode uint8_op,
                                    ArchOpcode uint16_op, ArchOpcode uint32_op);

#if V8_TARGET_ARCH_64_BIT
  bool ZeroExtendsWord32ToWord64(node_t node, int recursion_depth = 0);
  void MarkNodeAsNotZeroExtended(node_t node);
  bool ZeroExtendsWord32ToWord64NoPhis(node_t node);

  enum class Upper32BitsState : uint8_t {
    kNotYetChecked,
    kZero,
    kMayBeNonZero,
  };
#endif  // V8_TARGET_ARCH_64_BIT

  struct FrameStateInput {
    FrameStateInput(node_t node_, FrameStateInputKind kind_)
        : node(node_), kind(kind_) {}

    node_t node;
    FrameStateInputKind kind;

    struct Hash {
      size_t operator()(FrameStateInput const& source) const {
        return base::hash_combine(source.node,
                                  static_cast<size_t>(source.kind));
      }
    };

    struct Equal {
      bool operator()(FrameStateInput const& lhs,
                      FrameStateInput const& rhs) const {
        return lhs.node == rhs.node && lhs.kind == rhs.kind;
      }
    };
  };

  struct CachedStateValues;
  class CachedStateValuesBuilder;

  // ===========================================================================

  Zone* const zone_;
  Linkage* const linkage_;
  InstructionSequence* const sequence_;
  source_position_table_t* const source_positions_;
  InstructionSelector::SourcePositionMode const source_position_mode_;
  Features features_;
  schedule_t const schedule_;
  block_t current_block_;
  ZoneVector<Instruction*> instructions_;
  InstructionOperandVector continuation_inputs_;
  InstructionOperandVector continuation_outputs_;
  InstructionOperandVector continuation_temps_;
  BitVector defined_;
  BitVector used_;
  IntVector effect_level_;
  int current_effect_level_;
  IntVector virtual_registers_;
  IntVector virtual_register_rename_;
  InstructionScheduler* scheduler_;
  InstructionSelector::EnableScheduling enable_scheduling_;
  InstructionSelector::EnableRootsRelativeAddressing
      enable_roots_relative_addressing_;
  InstructionSelector::EnableSwitchJumpTable enable_switch_jump_table_;
  ZoneUnorderedMap<FrameStateInput, CachedStateValues*,
                   typename FrameStateInput::Hash,
                   typename FrameStateInput::Equal>
      state_values_cache_;

  Frame* frame_;
  bool instruction_selection_failed_;
  ZoneVector<std::pair<int, int>> instr_origins_;
  InstructionSelector::EnableTraceTurboJson trace_turbo_;
  TickCounter* const tick_counter_;
  // The broker is only used for unparking the LocalHeap for diagnostic printing
  // for failed StaticAsserts.
  JSHeapBroker* const broker_;

  // Store the maximal unoptimized frame height and an maximal number of pushed
  // arguments (for calls). Later used to apply an offset to stack checks.
  size_t* max_unoptimized_frame_height_;
  size_t* max_pushed_argument_count_;

  // Turboshaft-adapter only.
  std::optional<turboshaft::UseMap> turboshaft_use_map_;
  std::optional<BitVector> protected_loads_to_remove_;
  std::optional<BitVector> additional_protected_instructions_;

#if V8_TARGET_ARCH_64_BIT
  size_t node_count_;

  // Holds lazily-computed results for whether phi nodes guarantee their upper
  // 32 bits to be zero. Indexed by node ID; nobody reads or writes the values
  // for non-phi nodes.
  ZoneVector<Upper32BitsState> phi_states_;
#endif
};

}  // namespace compiler
}  // namespace internal
}  // namespace v8

#endif  // V8_COMPILER_BACKEND_INSTRUCTION_SELECTOR_H_

"""


```