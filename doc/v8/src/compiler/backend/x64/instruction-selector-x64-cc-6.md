Response:
Let's break down the thought process for analyzing this V8 code snippet.

1. **Understanding the Request:** The core request is to analyze a specific V8 source file snippet (`instruction-selector-x64.cc`) and determine its function within the V8 JavaScript engine. The request also has several sub-constraints:
    * Check if it's a Torque file (.tq).
    * Determine its relationship to JavaScript functionality.
    * Provide JavaScript examples if related to JavaScript.
    * Offer code logic reasoning with input/output examples.
    * Identify common programming errors it might help avoid.
    * Summarize its overall function, considering it's part 7 of 10.

2. **Initial Assessment - File Extension:** The filename ends in `.cc`, which signifies a C++ source file, not a Torque file. This immediately answers the Torque question.

3. **Identifying the Core Purpose - "Instruction Selector":** The filename contains "instruction-selector". This is a crucial clue. In compiler terminology, an instruction selector is responsible for choosing the specific machine instructions that will implement higher-level operations. The "x64" part indicates this selector is specifically for the x64 architecture.

4. **Analyzing the Code Snippet - Keywords and Patterns:**  I start scanning the provided code for keywords and recognizable patterns:
    * `case IrOpcode::...`: This suggests a switch statement based on intermediate representation (IR) opcodes. IR is a common way compilers represent code before generating machine code.
    * `kX64Imul32`, `kX64Add`, `kX64Sub`, `kX64Cmp32`, `kX64Test32`, `kX64Lea32`, `kX64Movl`, `kSSEFloat64InsertHighWord32`, `kAtomicExchangeInt8`, etc.: These are clearly x64 assembly instruction mnemonics. This confirms the instruction selector's role.
    * `VisitBinop`, `VisitWordCompare`, `VisitCompareZero`, `Emit`, `EmitTableSwitch`, `EmitBinarySearchSwitch`, `VisitFloat32Compare`, `VisitLoad`, `VisitStoreCommon`, `VisitAtomicExchange`, `VisitAtomicBinop`: These look like helper functions or methods within the `InstructionSelector` class, encapsulating the logic for generating instructions for different operation types.
    * `FlagsContinuation`: This suggests handling of CPU flags that result from comparisons and arithmetic operations, crucial for conditional branching.
    * `SwitchInfo`: Indicates handling of `switch` statements.
    * `AtomicMemoryOrder`: Relates to atomic operations and memory synchronization, important for concurrent programming.
    * `TurbofanAdapter`, `TurboshaftAdapter`: These suggest different compiler pipelines or phases within V8, and the instruction selector might have specialized logic for each.
    * SIMD-related keywords like `F64x2Add`, `I32x4Mul`: Indicate support for Single Instruction Multiple Data operations, used for vector processing.

5. **Connecting to JavaScript Functionality:**  Since this is an instruction selector, its primary job is to translate JavaScript (or rather, its intermediate representation) into executable machine code. Every JavaScript operation that gets compiled down to machine instructions will, at some point, be handled by code like this. Specifically:
    * **Arithmetic Operations:**  The `kInt32MulWithOverflow`, `kInt64AddWithOverflow`, etc., cases directly relate to JavaScript's arithmetic operators (`+`, `-`, `*`).
    * **Comparison Operations:** `kInt32Sub`, `kWord32And`, `kStackPointerGreaterThan`, `kWord32Equal`, `kInt32LessThan`, etc., handle JavaScript's comparison operators (`==`, `!=`, `<`, `>`, `<=`, `>=`). The `VisitSwitch` function deals with JavaScript `switch` statements.
    * **Floating-Point Operations:**  `kFloat32Equal`, `kFloat64LessThan`, `kFloat64InsertLowWord32` relate to JavaScript's number type and floating-point arithmetic.
    * **Atomic Operations:** `VisitWord32AtomicLoad`, `VisitWord32AtomicStore`, `VisitWord32AtomicExchange`, etc., are used for implementing JavaScript's atomic operations (part of shared memory concurrency).

6. **Providing JavaScript Examples:** Based on the identified connections, I create simple JavaScript examples that would exercise the corresponding code paths in the instruction selector (arithmetic, comparisons, `switch`, floating-point, atomic operations).

7. **Code Logic Reasoning and Examples:**  I select a specific code block (e.g., the `VisitBranch` function) and:
    * **Hypothesize Inputs:**  Think about what kind of IR nodes would be passed to this function (e.g., a comparison result used in an `if` statement).
    * **Predict Outputs:**  Describe the assembly instructions that would likely be generated based on the input and the logic within the function. For instance, a comparison followed by a conditional jump.

8. **Identifying Common Programming Errors:** I consider what kinds of errors the instruction selector might implicitly help avoid or handle:
    * **Integer Overflow:** The `...WithOverflow` opcodes and the `cont->OverwriteAndNegateIfEqual(kOverflow)` line directly deal with detecting and potentially handling integer overflow, a common source of bugs.
    * **Incorrect Comparisons:**  The instruction selector ensures that comparisons are translated into the correct assembly instructions, preventing unexpected behavior due to incorrect flag settings.
    * **Data Type Mismatches:**  While not explicitly preventing them, the instruction selector works with typed IR, which is a result of earlier compiler stages that *do* perform type checking.

9. **Summarizing the Function (Part 7 of 10):**  Considering that this is part 7 of 10, I infer that earlier parts likely dealt with parsing and IR generation, while later parts will deal with register allocation, instruction scheduling, and code emission. Therefore, part 7, the instruction selector, is the crucial bridge between the high-level IR and the low-level machine code. It's responsible for making architecture-specific choices about how to implement operations.

10. **Refinement and Clarity:** Finally, I organize the information logically, use clear and concise language, and ensure that the examples are easy to understand. I also double-check that I've addressed all parts of the original request.
好的，我们来分析一下这段 v8 源代码片段 `v8/src/compiler/backend/x64/instruction-selector-x64.cc` 的功能。

**核心功能：X64 架构的指令选择**

这段代码是 V8 编译器后端的一部分，专门负责将中间表示 (Intermediate Representation, IR) 的操作转换成 x64 架构的机器指令。 这就是所谓的“指令选择”过程。

**功能分解：**

1. **处理带有溢出检查的算术运算：**
   - 代码中 `case IrOpcode::kInt32MulWithOverflow:`、`case IrOpcode::kInt64AddWithOverflow:` 等部分处理了可能发生溢出的整数运算。
   - `cont->OverwriteAndNegateIfEqual(kOverflow);` 表明它会设置溢出标志，以便后续的代码可以根据溢出情况进行处理（例如，抛出错误或采取其他措施）。
   - `VisitBinop(this, node, kX64Imul32, cont);` 表示它会调用 `VisitBinop` 函数，并指定了相应的 x64 指令（例如 `kX64Imul32` 用于 32 位整数乘法）。

2. **处理比较运算：**
   - `case IrOpcode::kInt32Sub:` 和 `case IrOpcode::kWord32And:` 处理了整数减法和按位与运算，它们通常用于实现比较操作。
   - `VisitWordCompare(this, value, kX64Cmp32, cont);` 和 `VisitWordCompare(this, value, kX64Test32, cont);` 说明会将这些操作转换为 x64 的比较指令 (`kX64Cmp32`) 或 `TEST` 指令 (`kX64Test32`)，并设置相应的标志。

3. **处理栈指针比较：**
   - `case IrOpcode::kStackPointerGreaterThan:` 检查栈指针是否大于某个值。
   - `cont->OverwriteAndNegateIfEqual(kStackPointerGreaterThanCondition);` 设置了基于栈指针比较结果的条件标志。
   - `VisitStackPointerGreaterThan(value, cont);` 调用特定函数来处理栈指针比较。

4. **处理 `switch` 语句：**
   - `void InstructionSelectorT<Adapter>::VisitSwitch(node_t node, const SwitchInfo& sw)` 函数负责将 IR 中的 `switch` 语句转换成 x64 指令。
   - 它会根据 `case` 的数量和值的范围，选择生成跳转表 (`EmitTableSwitch`) 或二分查找树 (`EmitBinarySearchSwitch`) 来实现 `switch`。
   - `enable_switch_jump_table_` 决定是否启用跳转表优化。

5. **处理相等性比较：**
   - `VisitWord32Equal` 和 `VisitWord64Equal` 函数处理 32 位和 64 位值的相等性比较。
   - 它会尝试优化，例如，如果与零比较，则可能使用更简洁的指令 (`VisitWordCompareZero`)。

6. **处理小于比较：**
   - `VisitInt32LessThan`、`VisitInt32LessThanOrEqual`、`VisitUint32LessThan`、`VisitUint32LessThanOrEqual` 等函数处理不同类型的（有符号/无符号）小于比较。

7. **处理浮点数比较：**
   - `VisitFloat32Equal`, `VisitFloat32LessThan`, `VisitFloat32LessThanOrEqual`, `VisitFloat64Equal`, `VisitFloat64LessThan`, `VisitFloat64LessThanOrEqual` 处理单精度和双精度浮点数的比较。
   - 其中包含针对特定模式的优化，例如，对于 `Float64LessThan(0.0, Float64Abs(x))` 这样的模式，它可以生成更高效的指令。

8. **处理位运算和类型转换：**
   - `VisitBitcastWord32PairToFloat64` 将一对 32 位整数转换为 64 位浮点数。
   - `VisitFloat64InsertLowWord32` 和 `VisitFloat64InsertHighWord32` 用于操作 64 位浮点数的低 32 位和高 32 位。

9. **处理内存屏障：**
   - `VisitMemoryBarrier` 用于确保内存操作的顺序，这在多线程或原子操作中很重要。
   - 对于 x64 架构，只有 `SeqCst` (Sequentially Consistent) 内存顺序需要显式地发出 `MFENCE` 指令。

10. **处理原子操作：**
    - `VisitWord32AtomicLoad`, `VisitWord64AtomicLoad`, `VisitWord32AtomicStore`, `VisitWord64AtomicStore` 处理原子加载和存储操作。
    - `VisitWord32AtomicExchange`, `VisitWord64AtomicExchange`, `VisitWord32AtomicCompareExchange`, `VisitWord64AtomicCompareExchange` 处理原子交换和比较交换操作。
    - `VisitWord32AtomicAdd`, `VisitWord32AtomicSub`, `VisitWord32AtomicAnd`, `VisitWord32AtomicOr`, `VisitWord32AtomicXor` 以及相应的 64 位版本处理原子算术和逻辑运算。

11. **处理 SIMD (Single Instruction, Multiple Data) 操作：**
    - 代码末尾定义了一些宏 (`SIMD_BINOP_SSE_AVX_LIST`, `SIMD_BINOP_SSE_AVX_LANE_SIZE_VECTOR_LENGTH_LIST`)，暗示了对 SIMD 指令的支持，用于并行处理多个数据。

**关于 .tq 结尾：**

`v8/src/compiler/backend/x64/instruction-selector-x64.cc` 以 `.cc` 结尾，这是一个 C++ 源代码文件的标准扩展名。 如果它以 `.tq` 结尾，那它才是一个 V8 Torque 源代码文件。 Torque 是一种 V8 特有的领域特定语言，用于定义类型化的操作和内置函数。

**与 JavaScript 的关系：**

这段代码是 V8 引擎将 JavaScript 代码编译成机器码的关键部分。 当 JavaScript 代码执行时，V8 的编译器（例如 Turbofan 或 Crankshaft）会将 JavaScript 代码转换成 IR。 `instruction-selector-x64.cc` 的功能就是将这些 IR 操作转换成可以在 x64 架构的 CPU 上执行的实际机器指令。

**JavaScript 示例：**

```javascript
// 算术运算，可能会触发溢出检查
let a = 2147483647; // 32位有符号整数的最大值
let b = 1;
let sum = a + b; // 会发生溢出

// 比较运算
let x = 10;
let y = 5;
if (x > y) {
  console.log("x 大于 y");
}

// switch 语句
let day = 2;
switch (day) {
  case 1:
    console.log("星期一");
    break;
  case 2:
    console.log("星期二");
    break;
  default:
    console.log("其他");
}

// 浮点数比较
let f1 = 0.1;
let f2 = 0.2;
if (f1 < f2) {
  console.log("f1 小于 f2");
}

// 原子操作 (需要 SharedArrayBuffer)
const sab = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT);
const view = new Int32Array(sab);
Atomics.add(view, 0, 5);
```

当 V8 编译执行这些 JavaScript 代码时，`instruction-selector-x64.cc` 中的代码会负责为这些操作选择合适的 x64 指令。

**代码逻辑推理和假设输入/输出：**

假设有一个 IR 节点表示 `a + b`，其中 `a` 和 `b` 是 32 位整数，并且需要进行溢出检查 (`IrOpcode::kInt32MulWithOverflow`)。

**假设输入：**

- IR 节点类型：`kInt32MulWithOverflow`
- 输入操作数：表示变量 `a` 和 `b` 的 IR 节点

**预期输出（大致）：**

- x64 指令：`IMUL` (用于乘法)
- 伴随的指令或标志设置，用于检测溢出。例如，可能会使用条件跳转指令来处理溢出的情况。

**用户常见的编程错误：**

这段代码间接帮助处理或暴露一些常见的编程错误：

1. **整数溢出：** `kInt32MulWithOverflow` 等处理了溢出情况，如果 JavaScript 代码中发生了整数溢出，V8 可能会根据这里的指令生成代码来抛出错误或进行特定的处理。程序员常常忘记考虑整数溢出的可能性，导致程序出现意外行为。

   ```javascript
   // 错误示例：未考虑溢出
   let maxInt = 2147483647;
   let result = maxInt + 1; // 结果会变成负数，不是期望的行为
   ```

2. **浮点数比较的精度问题：** 虽然指令选择器本身不直接防止这个问题，但它处理浮点数比较的方式会影响比较的结果。程序员需要注意浮点数比较时可能存在精度误差。

   ```javascript
   // 错误示例：直接比较浮点数是否相等
   let a = 0.1 + 0.2; // a 的值可能略微大于 0.3
   if (a === 0.3) { // 结果可能为 false
     console.log("相等");
   }
   ```

3. **并发编程中的数据竞争：** 原子操作相关的代码（例如 `VisitWord32AtomicAdd`）用于实现 JavaScript 的原子操作。 如果程序员在多线程环境中使用共享内存但不使用原子操作进行同步，就可能发生数据竞争。

   ```javascript
   // 错误示例：未同步的并发访问
   // 假设有两个 worker 同时修改 sharedArrayBuffer 的同一个位置
   // 可能导致数据不一致
   ```

**归纳功能（第 7 部分，共 10 部分）：**

考虑到这是编译器后端指令选择的第 7 部分， 它的主要功能是将**平台无关的中间表示 (IR) 转换成 x64 架构特定的机器指令**。  在这个阶段，编译器已经分析了代码，进行了优化，现在需要将抽象的操作落实到具体的硬件指令上。

前面（1-6 部分）可能涉及：

- 词法分析、语法分析
- 生成抽象语法树 (AST)
- 将 AST 转换为中间表示 (IR)
- 进行一些与平台无关的优化

后面（8-10 部分）可能涉及：

- 寄存器分配：决定哪些变量或临时值存储在 CPU 的寄存器中。
- 指令调度：优化指令的执行顺序以提高性能。
- 代码发射（Code Emission）：将选择好的指令输出为最终的机器码。

因此，`instruction-selector-x64.cc` 作为第 7 部分，是连接高级中间表示和低级机器码的关键桥梁，它决定了如何在 x64 架构上高效地实现 JavaScript 的各种操作。

Prompt: 
```
这是目录为v8/src/compiler/backend/x64/instruction-selector-x64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/x64/instruction-selector-x64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第7部分，共10部分，请归纳一下它的功能

"""
              case IrOpcode::kInt32MulWithOverflow:
                cont->OverwriteAndNegateIfEqual(kOverflow);
                return VisitBinop(this, node, kX64Imul32, cont);
              case IrOpcode::kInt64AddWithOverflow:
                cont->OverwriteAndNegateIfEqual(kOverflow);
                return VisitBinop(this, node, kX64Add, cont);
              case IrOpcode::kInt64SubWithOverflow:
                cont->OverwriteAndNegateIfEqual(kOverflow);
                return VisitBinop(this, node, kX64Sub, cont);
              case IrOpcode::kInt64MulWithOverflow:
                cont->OverwriteAndNegateIfEqual(kOverflow);
                return VisitBinop(this, node, kX64Imul, cont);
              default:
                break;
            }
          }
        }
        break;
      case IrOpcode::kInt32Sub:
        return VisitWordCompare(this, value, kX64Cmp32, cont);
      case IrOpcode::kWord32And:
        return VisitWordCompare(this, value, kX64Test32, cont);
      case IrOpcode::kStackPointerGreaterThan:
        cont->OverwriteAndNegateIfEqual(kStackPointerGreaterThanCondition);
        return VisitStackPointerGreaterThan(value, cont);
      default:
        break;
    }
  }

  // Branch could not be combined with a compare, emit compare against 0.
  VisitCompareZero(this, user, value, kX64Cmp32, cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSwitch(node_t node,
                                                const SwitchInfo& sw) {
  X64OperandGeneratorT<Adapter> g(this);
  DCHECK_EQ(this->value_input_count(node), 1);
  InstructionOperand value_operand = g.UseRegister(this->input_at(node, 0));

  // Emit either ArchTableSwitch or ArchBinarySearchSwitch.
  if (enable_switch_jump_table_ ==
      InstructionSelector::kEnableSwitchJumpTable) {
    static const size_t kMaxTableSwitchValueRange = 2 << 16;
    size_t table_space_cost = 4 + sw.value_range();
    size_t table_time_cost = 3;
    size_t lookup_space_cost = 3 + 2 * sw.case_count();
    size_t lookup_time_cost = sw.case_count();
    if (sw.case_count() > 4 &&
        table_space_cost + 3 * table_time_cost <=
            lookup_space_cost + 3 * lookup_time_cost &&
        sw.min_value() > std::numeric_limits<int32_t>::min() &&
        sw.value_range() <= kMaxTableSwitchValueRange) {
      InstructionOperand index_operand = g.TempRegister();
      if (sw.min_value()) {
        // The leal automatically zero extends, so result is a valid 64-bit
        // index.
        Emit(kX64Lea32 | AddressingModeField::encode(kMode_MRI), index_operand,
             value_operand, g.TempImmediate(-sw.min_value()));
      } else {
        // Zero extend, because we use it as 64-bit index into the jump table.
        if (ZeroExtendsWord32ToWord64(this->input_at(node, 0))) {
          // Input value has already been zero-extended.
          index_operand = value_operand;
        } else {
          Emit(kX64Movl, index_operand, value_operand);
        }
      }
      // Generate a table lookup.
      return EmitTableSwitch(sw, index_operand);
    }
  }

  // Generate a tree of conditional jumps.
  return EmitBinarySearchSwitch(sw, value_operand);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord32Equal(node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  FlagsContinuation cont = FlagsContinuation::ForSet(kEqual, node);
  const ComparisonOp& equal = this->Get(node).Cast<ComparisonOp>();
  DCHECK_EQ(equal.kind, ComparisonOp::Kind::kEqual);
  DCHECK(equal.rep == RegisterRepresentation::Word32() ||
         equal.rep == RegisterRepresentation::Tagged());
  if (MatchIntegralZero(equal.right())) {
    return VisitWordCompareZero(node, equal.left(), &cont);
  }
  VisitWord32EqualImpl(this, node, &cont);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitWord32Equal(node_t node) {
  FlagsContinuation cont = FlagsContinuation::ForSet(kEqual, node);
  Int32BinopMatcher m(node);
  if (m.right().Is(0)) {
    return VisitWordCompareZero(m.node(), m.left().node(), &cont);
  }
  VisitWord32EqualImpl(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32LessThan(node_t node) {
  FlagsContinuation cont = FlagsContinuation::ForSet(kSignedLessThan, node);
  VisitWordCompare(this, node, kX64Cmp32, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32LessThanOrEqual(node_t node) {
  FlagsContinuation cont =
      FlagsContinuation::ForSet(kSignedLessThanOrEqual, node);
  VisitWordCompare(this, node, kX64Cmp32, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint32LessThan(node_t node) {
  FlagsContinuation cont = FlagsContinuation::ForSet(kUnsignedLessThan, node);
  VisitWordCompare(this, node, kX64Cmp32, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint32LessThanOrEqual(node_t node) {
  FlagsContinuation cont =
      FlagsContinuation::ForSet(kUnsignedLessThanOrEqual, node);
  VisitWordCompare(this, node, kX64Cmp32, &cont);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord64Equal(node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  FlagsContinuation cont = FlagsContinuation::ForSet(kEqual, node);
  const ComparisonOp& equal = this->Get(node).Cast<ComparisonOp>();
  DCHECK_EQ(equal.kind, ComparisonOp::Kind::kEqual);
  DCHECK(equal.rep == RegisterRepresentation::Word64() ||
         equal.rep == RegisterRepresentation::Tagged());
  if (MatchIntegralZero(equal.right())) {
    if (CanCover(node, equal.left())) {
      const Operation& left_op = this->Get(equal.left());
      if (left_op.Is<Opmask::kWord64Sub>()) {
        return VisitWordCompare(this, equal.left(), kX64Cmp, &cont);
      } else if (left_op.Is<Opmask::kWord64BitwiseAnd>()) {
        return VisitWordCompare(this, equal.left(), kX64Test, &cont);
      }
    }
  }
  VisitWord64EqualImpl(this, node, &cont);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitWord64Equal(node_t node) {
  FlagsContinuation cont = FlagsContinuation::ForSet(kEqual, node);
  Int64BinopMatcher m(node);
  if (m.right().Is(0)) {
    // Try to combine the equality check with a comparison.
    Node* const user = m.node();
    Node* const value = m.left().node();
    if (CanCover(user, value)) {
      switch (value->opcode()) {
        case IrOpcode::kInt64Sub:
          return VisitWordCompare(this, value, kX64Cmp, &cont);
        case IrOpcode::kWord64And:
          return VisitWordCompare(this, value, kX64Test, &cont);
        default:
          break;
      }
    }
  }
  VisitWord64EqualImpl(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32AddWithOverflow(node_t node) {
  node_t ovf = FindProjection(node, 1);
  if (Adapter::valid(ovf)) {
    FlagsContinuation cont = FlagsContinuation::ForSet(kOverflow, ovf);
    return VisitBinop(this, node, kX64Add32, &cont);
  }
  FlagsContinuation cont;
  VisitBinop(this, node, kX64Add32, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32SubWithOverflow(node_t node) {
  node_t ovf = FindProjection(node, 1);
  if (Adapter::valid(ovf)) {
    FlagsContinuation cont = FlagsContinuation::ForSet(kOverflow, ovf);
    return VisitBinop(this, node, kX64Sub32, &cont);
  }
  FlagsContinuation cont;
  VisitBinop(this, node, kX64Sub32, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64LessThan(node_t node) {
  FlagsContinuation cont = FlagsContinuation::ForSet(kSignedLessThan, node);
  VisitWordCompare(this, node, kX64Cmp, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64LessThanOrEqual(node_t node) {
  FlagsContinuation cont =
      FlagsContinuation::ForSet(kSignedLessThanOrEqual, node);
  VisitWordCompare(this, node, kX64Cmp, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint64LessThan(node_t node) {
  FlagsContinuation cont = FlagsContinuation::ForSet(kUnsignedLessThan, node);
  VisitWordCompare(this, node, kX64Cmp, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint64LessThanOrEqual(node_t node) {
  FlagsContinuation cont =
      FlagsContinuation::ForSet(kUnsignedLessThanOrEqual, node);
  VisitWordCompare(this, node, kX64Cmp, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Equal(node_t node) {
  FlagsContinuation cont = FlagsContinuation::ForSet(kUnorderedEqual, node);
  VisitFloat32Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32LessThan(node_t node) {
  FlagsContinuation cont =
      FlagsContinuation::ForSet(kUnsignedGreaterThan, node);
  VisitFloat32Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32LessThanOrEqual(node_t node) {
  FlagsContinuation cont =
      FlagsContinuation::ForSet(kUnsignedGreaterThanOrEqual, node);
  VisitFloat32Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Equal(node_t node) {
  bool is_self_compare = this->input_at(node, 0) == this->input_at(node, 1);
  FlagsContinuation cont = FlagsContinuation::ForSet(
      is_self_compare ? kIsNotNaN : kUnorderedEqual, node);
  VisitFloat64Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64LessThan(node_t node) {
  // Check for the pattern
  //
  //   Float64LessThan(#0.0, Float64Abs(x))
  //
  // which TurboFan generates for NumberToBoolean in the general case,
  // and which evaluates to false if x is 0, -0 or NaN. We can compile
  // this to a simple (v)ucomisd using not_equal flags condition, which
  // avoids the costly Float64Abs.
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const ComparisonOp& cmp = this->Get(node).template Cast<ComparisonOp>();
    DCHECK_EQ(cmp.rep, RegisterRepresentation::Float64());
    DCHECK_EQ(cmp.kind, ComparisonOp::Kind::kSignedLessThan);
    if (this->MatchZero(cmp.left())) {
      if (const FloatUnaryOp* right_op =
              this->Get(cmp.right()).template TryCast<Opmask::kFloat64Abs>()) {
        FlagsContinuation cont = FlagsContinuation::ForSet(kNotEqual, node);
        InstructionCode const opcode =
            IsSupported(AVX) ? kAVXFloat64Cmp : kSSEFloat64Cmp;
        return VisitCompare(this, opcode, cmp.left(), right_op->input(), &cont,
                            false);
      }
    }
  } else {
    Float64BinopMatcher m(node);
    if (m.left().Is(0.0) && m.right().IsFloat64Abs()) {
      FlagsContinuation cont = FlagsContinuation::ForSet(kNotEqual, node);
      InstructionCode const opcode =
          IsSupported(AVX) ? kAVXFloat64Cmp : kSSEFloat64Cmp;
      return VisitCompare(this, opcode, m.left().node(), m.right().InputAt(0),
                          &cont, false);
    }
  }
  FlagsContinuation cont =
      FlagsContinuation::ForSet(kUnsignedGreaterThan, node);
  VisitFloat64Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64LessThanOrEqual(node_t node) {
  FlagsContinuation cont =
      FlagsContinuation::ForSet(kUnsignedGreaterThanOrEqual, node);
  VisitFloat64Compare(this, node, &cont);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitBitcastWord32PairToFloat64(
    node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  X64OperandGeneratorT<TurboshaftAdapter> g(this);
  const auto& bitcast =
      this->Cast<turboshaft::BitcastWord32PairToFloat64Op>(node);
  node_t hi = bitcast.high_word32();
  node_t lo = bitcast.low_word32();

  // TODO(nicohartmann@): We could try to emit a better sequence here.
  InstructionOperand zero = sequence()->AddImmediate(Constant(0.0));
  InstructionOperand temp = g.TempDoubleRegister();
  Emit(kSSEFloat64InsertHighWord32, temp, zero, g.Use(hi));
  Emit(kSSEFloat64InsertLowWord32, g.DefineSameAsFirst(node), temp, g.Use(lo));
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitFloat64InsertLowWord32(
    node_t node) {
  X64OperandGeneratorT<TurbofanAdapter> g(this);
  DCHECK_EQ(this->value_input_count(node), 2);
  node_t left = this->input_at(node, 0);
  node_t right = this->input_at(node, 1);
  Float64Matcher mleft(left);
  if (mleft.HasResolvedValue() &&
      (base::bit_cast<uint64_t>(mleft.ResolvedValue()) >> 32) == 0u) {
    Emit(kSSEFloat64LoadLowWord32, g.DefineAsRegister(node), g.Use(right));
    return;
  }
  Emit(kSSEFloat64InsertLowWord32, g.DefineSameAsFirst(node),
       g.UseRegister(left), g.Use(right));
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitFloat64InsertHighWord32(
    node_t node) {
  X64OperandGeneratorT<TurbofanAdapter> g(this);
  DCHECK_EQ(this->value_input_count(node), 2);
  node_t left = this->input_at(node, 0);
  node_t right = this->input_at(node, 1);
  Emit(kSSEFloat64InsertHighWord32, g.DefineSameAsFirst(node),
       g.UseRegister(left), g.Use(right));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64SilenceNaN(node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  DCHECK_EQ(this->value_input_count(node), 1);
  Emit(kSSEFloat64SilenceNaN, g.DefineSameAsFirst(node),
       g.UseRegister(this->input_at(node, 0)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitMemoryBarrier(node_t node) {
  AtomicMemoryOrder order;
  if constexpr (Adapter::IsTurboshaft) {
    order = this->Get(node)
                .template Cast<turboshaft::MemoryBarrierOp>()
                .memory_order;
  } else {
    order = OpParameter<AtomicMemoryOrder>(node->op());
  }
  // x64 is no weaker than release-acquire and only needs to emit an
  // instruction for SeqCst memory barriers.
  if (order == AtomicMemoryOrder::kSeqCst) {
    X64OperandGeneratorT<Adapter> g(this);
    Emit(kX64MFence, g.NoOutput());
    return;
  }
  DCHECK_EQ(AtomicMemoryOrder::kAcqRel, order);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicLoad(node_t node) {
  LoadRepresentation load_rep = this->load_view(node).loaded_rep();
  DCHECK(IsIntegral(load_rep.representation()) ||
         IsAnyTagged(load_rep.representation()) ||
         (COMPRESS_POINTERS_BOOL &&
          CanBeCompressedPointer(load_rep.representation())));
  DCHECK_NE(load_rep.representation(), MachineRepresentation::kWord64);
  DCHECK(!load_rep.IsMapWord());
  // The memory order is ignored as both acquire and sequentially consistent
  // loads can emit MOV.
  // https://www.cl.cam.ac.uk/~pes20/cpp/cpp0xmappings.html
  VisitLoad(node, node, GetLoadOpcode(load_rep));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64AtomicLoad(node_t node) {
  LoadRepresentation load_rep = this->load_view(node).loaded_rep();
  DCHECK(!load_rep.IsMapWord());
  // The memory order is ignored as both acquire and sequentially consistent
  // loads can emit MOV.
  // https://www.cl.cam.ac.uk/~pes20/cpp/cpp0xmappings.html
  VisitLoad(node, node, GetLoadOpcode(load_rep));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicStore(node_t node) {
  auto store = this->store_view(node);
  DCHECK_NE(store.stored_rep().representation(),
            MachineRepresentation::kWord64);
  DCHECK_IMPLIES(
      CanBeTaggedOrCompressedPointer(store.stored_rep().representation()),
      kTaggedSize == 4);
  VisitStoreCommon(this, store);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64AtomicStore(node_t node) {
  auto store = this->store_view(node);
  DCHECK_IMPLIES(
      CanBeTaggedOrCompressedPointer(store.stored_rep().representation()),
      kTaggedSize == 8);
  VisitStoreCommon(this, store);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitWord32AtomicExchange(
    Node* node) {
  AtomicOpParameters params = AtomicOpParametersOf(node->op());
  ArchOpcode opcode;
  if (params.type() == MachineType::Int8()) {
    opcode = kAtomicExchangeInt8;
  } else if (params.type() == MachineType::Uint8()) {
    opcode = kAtomicExchangeUint8;
  } else if (params.type() == MachineType::Int16()) {
    opcode = kAtomicExchangeInt16;
  } else if (params.type() == MachineType::Uint16()) {
    opcode = kAtomicExchangeUint16;
  } else if (params.type() == MachineType::Int32()
    || params.type() == MachineType::Uint32()) {
    opcode = kAtomicExchangeWord32;
  } else {
    UNREACHABLE();
  }
  VisitAtomicExchange(this, node, opcode, AtomicWidth::kWord32, params.kind());
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord32AtomicExchange(
    node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const AtomicRMWOp& atomic_op = this->Get(node).template Cast<AtomicRMWOp>();
  ArchOpcode opcode;
  if (atomic_op.memory_rep == MemoryRepresentation::Int8()) {
    opcode = kAtomicExchangeInt8;
  } else if (atomic_op.memory_rep == MemoryRepresentation::Uint8()) {
    opcode = kAtomicExchangeUint8;
  } else if (atomic_op.memory_rep == MemoryRepresentation::Int16()) {
    opcode = kAtomicExchangeInt16;
  } else if (atomic_op.memory_rep == MemoryRepresentation::Uint16()) {
    opcode = kAtomicExchangeUint16;
  } else if (atomic_op.memory_rep == MemoryRepresentation::Int32() ||
             atomic_op.memory_rep == MemoryRepresentation::Uint32()) {
    opcode = kAtomicExchangeWord32;
  } else {
    UNREACHABLE();
  }
  VisitAtomicExchange(this, node, opcode, AtomicWidth::kWord32,
                      atomic_op.memory_access_kind);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitWord64AtomicExchange(
    Node* node) {
  AtomicOpParameters params = AtomicOpParametersOf(node->op());
  ArchOpcode opcode;
  if (params.type() == MachineType::Uint8()) {
    opcode = kAtomicExchangeUint8;
  } else if (params.type() == MachineType::Uint16()) {
    opcode = kAtomicExchangeUint16;
  } else if (params.type() == MachineType::Uint32()) {
    opcode = kAtomicExchangeWord32;
  } else if (params.type() == MachineType::Uint64()) {
    opcode = kX64Word64AtomicExchangeUint64;
  } else {
    UNREACHABLE();
  }
  VisitAtomicExchange(this, node, opcode, AtomicWidth::kWord64, params.kind());
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord64AtomicExchange(
    node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const AtomicRMWOp& atomic_op = this->Get(node).template Cast<AtomicRMWOp>();
  ArchOpcode opcode;
  if (atomic_op.memory_rep == MemoryRepresentation::Uint8()) {
    opcode = kAtomicExchangeUint8;
  } else if (atomic_op.memory_rep == MemoryRepresentation::Uint16()) {
    opcode = kAtomicExchangeUint16;
  } else if (atomic_op.memory_rep == MemoryRepresentation::Uint32()) {
    opcode = kAtomicExchangeWord32;
  } else if (atomic_op.memory_rep == MemoryRepresentation::Uint64()) {
    opcode = kX64Word64AtomicExchangeUint64;
  } else {
    UNREACHABLE();
  }
  VisitAtomicExchange(this, node, opcode, AtomicWidth::kWord64,
                      atomic_op.memory_access_kind);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitWord32AtomicCompareExchange(
    Node* node) {
  AtomicOpParameters params = AtomicOpParametersOf(node->op());
  ArchOpcode opcode;
  if (params.type() == MachineType::Int8()) {
    opcode = kAtomicCompareExchangeInt8;
  } else if (params.type() == MachineType::Uint8()) {
    opcode = kAtomicCompareExchangeUint8;
  } else if (params.type() == MachineType::Int16()) {
    opcode = kAtomicCompareExchangeInt16;
  } else if (params.type() == MachineType::Uint16()) {
    opcode = kAtomicCompareExchangeUint16;
  } else if (params.type() == MachineType::Int32()
    || params.type() == MachineType::Uint32()) {
    opcode = kAtomicCompareExchangeWord32;
  } else {
    UNREACHABLE();
  }
  VisitAtomicCompareExchange(this, node, opcode, AtomicWidth::kWord32,
                             params.kind());
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord32AtomicCompareExchange(
    node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const AtomicRMWOp& atomic_op = this->Get(node).template Cast<AtomicRMWOp>();
  ArchOpcode opcode;
  if (atomic_op.memory_rep == MemoryRepresentation::Int8()) {
    opcode = kAtomicCompareExchangeInt8;
  } else if (atomic_op.memory_rep == MemoryRepresentation::Uint8()) {
    opcode = kAtomicCompareExchangeUint8;
  } else if (atomic_op.memory_rep == MemoryRepresentation::Int16()) {
    opcode = kAtomicCompareExchangeInt16;
  } else if (atomic_op.memory_rep == MemoryRepresentation::Uint16()) {
    opcode = kAtomicCompareExchangeUint16;
  } else if (atomic_op.memory_rep == MemoryRepresentation::Int32() ||
             atomic_op.memory_rep == MemoryRepresentation::Uint32()) {
    opcode = kAtomicCompareExchangeWord32;
  } else {
    UNREACHABLE();
  }
  VisitAtomicCompareExchange(this, node, opcode, AtomicWidth::kWord32,
                             atomic_op.memory_access_kind);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitWord64AtomicCompareExchange(
    Node* node) {
  AtomicOpParameters params = AtomicOpParametersOf(node->op());
  ArchOpcode opcode;
  if (params.type() == MachineType::Uint8()) {
    opcode = kAtomicCompareExchangeUint8;
  } else if (params.type() == MachineType::Uint16()) {
    opcode = kAtomicCompareExchangeUint16;
  } else if (params.type() == MachineType::Uint32()) {
    opcode = kAtomicCompareExchangeWord32;
  } else if (params.type() == MachineType::Uint64()) {
    opcode = kX64Word64AtomicCompareExchangeUint64;
  } else {
    UNREACHABLE();
  }
  VisitAtomicCompareExchange(this, node, opcode, AtomicWidth::kWord64,
                             params.kind());
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord64AtomicCompareExchange(
    node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const AtomicRMWOp& atomic_op = this->Get(node).template Cast<AtomicRMWOp>();
  ArchOpcode opcode;
  if (atomic_op.memory_rep == MemoryRepresentation::Uint8()) {
    opcode = kAtomicCompareExchangeUint8;
  } else if (atomic_op.memory_rep == MemoryRepresentation::Uint16()) {
    opcode = kAtomicCompareExchangeUint16;
  } else if (atomic_op.memory_rep == MemoryRepresentation::Uint32()) {
    opcode = kAtomicCompareExchangeWord32;
  } else if (atomic_op.memory_rep == MemoryRepresentation::Uint64()) {
    opcode = kX64Word64AtomicCompareExchangeUint64;
  } else {
    UNREACHABLE();
  }
  VisitAtomicCompareExchange(this, node, opcode, AtomicWidth::kWord64,
                             atomic_op.memory_access_kind);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord32AtomicBinaryOperation(
    turboshaft::OpIndex node, ArchOpcode int8_op, ArchOpcode uint8_op,
    ArchOpcode int16_op, ArchOpcode uint16_op, ArchOpcode word32_op) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const AtomicRMWOp& atomic_op = this->Get(node).template Cast<AtomicRMWOp>();
  ArchOpcode opcode;
  if (atomic_op.memory_rep == MemoryRepresentation::Int8()) {
    opcode = int8_op;
  } else if (atomic_op.memory_rep == MemoryRepresentation::Uint8()) {
    opcode = uint8_op;
  } else if (atomic_op.memory_rep == MemoryRepresentation::Int16()) {
    opcode = int16_op;
  } else if (atomic_op.memory_rep == MemoryRepresentation::Uint16()) {
    opcode = uint16_op;
  } else if (atomic_op.memory_rep == MemoryRepresentation::Int32() ||
             atomic_op.memory_rep == MemoryRepresentation::Uint32()) {
    opcode = word32_op;
  } else {
    UNREACHABLE();
  }
  VisitAtomicBinop(this, node, opcode, AtomicWidth::kWord32,
                   atomic_op.memory_access_kind);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitWord32AtomicBinaryOperation(
    Node* node, ArchOpcode int8_op, ArchOpcode uint8_op, ArchOpcode int16_op,
    ArchOpcode uint16_op, ArchOpcode word32_op) {
  AtomicOpParameters params = AtomicOpParametersOf(node->op());
  ArchOpcode opcode;
  if (params.type() == MachineType::Int8()) {
    opcode = int8_op;
  } else if (params.type() == MachineType::Uint8()) {
    opcode = uint8_op;
  } else if (params.type() == MachineType::Int16()) {
    opcode = int16_op;
  } else if (params.type() == MachineType::Uint16()) {
    opcode = uint16_op;
  } else if (params.type() == MachineType::Int32()
    || params.type() == MachineType::Uint32()) {
    opcode = word32_op;
  } else {
    UNREACHABLE();
  }
  VisitAtomicBinop(this, node, opcode, AtomicWidth::kWord32, params.kind());
}

#define VISIT_ATOMIC_BINOP(op)                                             \
  template <typename Adapter>                                              \
  void InstructionSelectorT<Adapter>::VisitWord32Atomic##op(node_t node) { \
    VisitWord32AtomicBinaryOperation(                                      \
        node, kAtomic##op##Int8, kAtomic##op##Uint8, kAtomic##op##Int16,   \
        kAtomic##op##Uint16, kAtomic##op##Word32);                         \
  }
VISIT_ATOMIC_BINOP(Add)
VISIT_ATOMIC_BINOP(Sub)
VISIT_ATOMIC_BINOP(And)
VISIT_ATOMIC_BINOP(Or)
VISIT_ATOMIC_BINOP(Xor)
#undef VISIT_ATOMIC_BINOP

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord64AtomicBinaryOperation(
    node_t node, ArchOpcode uint8_op, ArchOpcode uint16_op,
    ArchOpcode uint32_op, ArchOpcode word64_op) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const AtomicRMWOp& atomic_op = this->Get(node).template Cast<AtomicRMWOp>();
  ArchOpcode opcode;
  if (atomic_op.memory_rep == MemoryRepresentation::Uint8()) {
    opcode = uint8_op;
  } else if (atomic_op.memory_rep == MemoryRepresentation::Uint16()) {
    opcode = uint16_op;
  } else if (atomic_op.memory_rep == MemoryRepresentation::Uint32()) {
    opcode = uint32_op;
  } else if (atomic_op.memory_rep == MemoryRepresentation::Uint64()) {
    opcode = word64_op;
  } else {
    UNREACHABLE();
  }
  VisitAtomicBinop(this, node, opcode, AtomicWidth::kWord64,
                   atomic_op.memory_access_kind);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitWord64AtomicBinaryOperation(
    Node* node, ArchOpcode uint8_op, ArchOpcode uint16_op, ArchOpcode uint32_op,
    ArchOpcode word64_op) {
  AtomicOpParameters params = AtomicOpParametersOf(node->op());
  ArchOpcode opcode;
  if (params.type() == MachineType::Uint8()) {
    opcode = uint8_op;
  } else if (params.type() == MachineType::Uint16()) {
    opcode = uint16_op;
  } else if (params.type() == MachineType::Uint32()) {
    opcode = uint32_op;
  } else if (params.type() == MachineType::Uint64()) {
    opcode = word64_op;
  } else {
    UNREACHABLE();
  }
  VisitAtomicBinop(this, node, opcode, AtomicWidth::kWord64, params.kind());
}

#define VISIT_ATOMIC_BINOP(op)                                                 \
  template <typename Adapter>                                                  \
  void InstructionSelectorT<Adapter>::VisitWord64Atomic##op(node_t node) {     \
    VisitWord64AtomicBinaryOperation(node, kAtomic##op##Uint8,                 \
                                     kAtomic##op##Uint16, kAtomic##op##Word32, \
                                     kX64Word64Atomic##op##Uint64);            \
  }
VISIT_ATOMIC_BINOP(Add)
VISIT_ATOMIC_BINOP(Sub)
VISIT_ATOMIC_BINOP(And)
VISIT_ATOMIC_BINOP(Or)
VISIT_ATOMIC_BINOP(Xor)
#undef VISIT_ATOMIC_BINOP

#ifdef V8_ENABLE_WEBASSEMBLY
#define SIMD_BINOP_SSE_AVX_LIST(V) \
  V(I64x2ExtMulLowI32x4S)          \
  V(I64x2ExtMulHighI32x4S)         \
  V(I64x2ExtMulLowI32x4U)          \
  V(I64x2ExtMulHighI32x4U)         \
  V(I32x4DotI16x8S)                \
  V(I32x8DotI16x16S)               \
  V(I32x4ExtMulLowI16x8S)          \
  V(I32x4ExtMulHighI16x8S)         \
  V(I32x4ExtMulLowI16x8U)          \
  V(I32x4ExtMulHighI16x8U)         \
  V(I16x8SConvertI32x4)            \
  V(I16x8UConvertI32x4)            \
  V(I16x8ExtMulLowI8x16S)          \
  V(I16x8ExtMulHighI8x16S)         \
  V(I16x8ExtMulLowI8x16U)          \
  V(I16x8ExtMulHighI8x16U)         \
  V(I16x8Q15MulRSatS)              \
  V(I16x8RelaxedQ15MulRS)          \
  V(I8x16SConvertI16x8)            \
  V(I8x16UConvertI16x8)            \
  V(I16x16SConvertI32x8)           \
  V(I16x16UConvertI32x8)           \
  V(I8x32SConvertI16x16)           \
  V(I8x32UConvertI16x16)           \
  V(I64x4ExtMulI32x4S)             \
  V(I64x4ExtMulI32x4U)             \
  V(I32x8ExtMulI16x8S)             \
  V(I32x8ExtMulI16x8U)             \
  V(I16x16ExtMulI8x16S)            \
  V(I16x16ExtMulI8x16U)

#define SIMD_BINOP_SSE_AVX_LANE_SIZE_VECTOR_LENGTH_LIST(V)  \
  V(F64x2Add, FAdd, kL64, kV128)                            \
  V(F64x4Add, FAdd, kL64, kV256)                            \
  V(F32x4Add, FAdd, kL32, kV128)                            \
  V(F32x8Add, FAdd, kL32, kV256)                            \
  V(I64x2Add, IAdd, kL64, kV128)                            \
  V(I64x4Add, IAdd, kL64, kV256)                            \
  V(I32x8Add, IAdd, kL32, kV256)                            \
  V(I16x16Add, IAdd, kL16, kV256)                           \
  V(I8x32Add, IAdd, kL8, kV256)                             \
  V(I32x4Add, IAdd, kL32, kV128)                            \
  V(I16x8Add, IAdd, kL16, kV128)                            \
  V(I8x16Add, IAdd, kL8, kV128)                             \
  V(F64x4Sub, FSub, kL64, kV256)                            \
  V(F64x2Sub, FSub, kL64, kV128)                            \
  V(F32x4Sub, FSub, kL32, kV128)                            \
  V(F32x8Sub, FSub, kL32, kV256)                            \
  V(I64x2Sub, ISub, kL64, kV128)                            \
  V(I64x4Sub, ISub, kL64, kV256)                            \
  V(I32x8Sub, ISub, kL32, kV256)                            \
  V(I16x16Sub, ISub, kL16, kV256)                           \
  V(I8x32Sub, ISub, kL8, kV256)                             \
  V(I32x4Sub, ISub, kL32, kV128)                            \
  V(I16x8Sub, ISub, kL16, kV128)                            \
  V(I8x16Sub, ISub, kL8, kV128)                             \
  V(F64x2Mul, FMul, kL64, kV128)                            \
  V(F32x4Mul, FMul, kL32, kV128)                            \
  V(F64x4Mul, FMul, kL64, kV256)                            \
  V(F32x8Mul, FMul, kL32, kV256)                            \
  V(I32x8Mul, IMul, kL32, kV256)                            \
  V(I16x16Mul, IMul, kL16, kV256)                           \
  V(I32x4Mul, IMul, kL32, kV128)                            \
  V(I16x8Mul, IMul, kL16, kV128)                            \
  V(F64x2Div, FDiv, kL64, kV128)                            \
  V(F32x4Div, FDiv, kL32, kV128)                            \
  V(F64x4Div, FDiv, kL64, kV256)                            \
  V(F32x8Div, FDiv, kL32, kV256)                            \
  V(I16x8AddSatS, IAddSatS, kL16, kV128)                    \
  V(I16x16AddSatS, IAddSatS, kL16, kV256)                   \
  V(I8x16AddSatS, IAddSatS, kL8, kV128)                     \
  V(I8x32AddSatS, IAddSatS, kL8, kV256)                     \
  V(I16x8SubSatS, ISubSatS, kL16, kV128)                    \
  V(I16x16SubSatS, ISubSatS, kL16, kV256)                   \
  V(I8x16SubSatS, ISubSatS, kL8, kV128)                     \
  V(I8x32SubSatS, ISubSatS, kL8, kV256)                     \
  V(I16x8AddSatU, IAddSatU, kL16, kV128)                    \
  V(I16x16AddSatU, IAddSatU, kL16, kV256)                   \
  V(I8x16AddSatU, IAddSatU, kL8, kV128)                     \
  V(I8x32AddSatU, IAddSatU, kL8, kV256)                     \
  V(I16x8SubSatU, ISubSatU, kL16, kV128)                    \
  V(I16x16SubSatU, ISubSatU, kL16, kV256)                   \
  V(I8x16SubSatU, ISubSatU, kL8, kV128)                     \
  V(I8x32SubSatU, ISubSatU, kL8, kV256)                     \
  V(F64x2Eq, FEq, kL64, kV128)                              \
  V(F32x4Eq, FEq, kL32, kV128)                              \
  V(F32x8Eq, FEq, kL32, kV256)                              \
  V(F64x4Eq, FEq, kL64, kV256)                              \
  V(I8x32Eq, IEq, kL8, kV256)                               \
  V(I16x16Eq, IEq, kL16, kV256)                             \
  V(I32x8Eq, IEq, kL32, kV256)                              \
  V(I64x4Eq, IEq, kL64, kV256)                              \
  V(I64x2Eq, IEq, kL64, kV128)                              \
  V(I32x4Eq, IEq, kL32, kV128)                              \
  V(I16x8Eq, IEq, kL16, kV128)                              \
  V(I8x16Eq, IEq, kL8, kV128)                               \
  V(F64x2Ne, FNe, kL64, kV128)                              \
  V(F32x4Ne
"""


```