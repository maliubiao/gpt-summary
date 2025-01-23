Response:
Let's break down the thought process for analyzing the provided C++ code snippet.

1. **Understanding the Context:** The initial prompt mentions the file `v8/src/compiler/backend/ia32/instruction-selector-ia32.cc`. This immediately tells us we're dealing with a component of the V8 JavaScript engine, specifically the *instruction selector* for the *IA32 (x86 32-bit)* architecture. The instruction selector is responsible for translating high-level intermediate representation (IR) operations into low-level machine instructions.

2. **Identifying the Core Functionality:** The code is a C++ source file. The prompt asks about its *functionality*. The name "instruction-selector" strongly suggests its primary job is to *select machine instructions*. The architecture "ia32" further clarifies that these are x86 instructions.

3. **Analyzing the Code Structure (Scanning for Keywords and Patterns):** I'll scan the provided code snippet for key elements:
    * **`switch` statements:** These often indicate handling different cases or operation types. The presence of `switch (comparison->kind)` and `switch (binop->kind)` suggests the code is dealing with different kinds of comparisons and binary operations.
    * **`case` statements:**  These list the specific types of operations being handled (e.g., `ComparisonOp::Kind::kEqual`, `OverflowCheckedBinopOp::Kind::kSignedAdd`).
    * **Function names like `Visit...`:**  Functions named `VisitWordCompare`, `VisitFloat64Compare`, `VisitBinop`, `VisitSwitch`, etc., strongly imply this code implements a visitor pattern. Each `Visit` function likely handles a specific IR node type.
    * **`FlagsContinuation`:**  This suggests handling of processor flags, which are crucial for implementing conditional branching and comparisons.
    * **`IA32OperandGeneratorT`:**  This class likely assists in generating operands (registers, memory locations, immediates) for IA32 instructions.
    * **Instruction opcodes (e.g., `kIA32Test`, `kIA32Cmp`, `kIA32Add`, `kIA32Imul`):** These are the actual x86 instructions being generated.
    * **Templates (`template <typename Adapter>`)**: This indicates the code is likely designed to be adaptable or reusable across different contexts within the V8 compiler. The `Adapter` probably represents different compilation pipelines (like Turbofan and Turboshaft).
    * **SIMD related names (`I32x4`, `F32x4`, `S128`, etc.):**  This shows support for Single Instruction Multiple Data operations, used for vectorized computations.
    * **Atomic operation related names (`VisitWord32AtomicLoad`, `VisitWord32AtomicStore`, etc.):** This indicates support for atomic operations, essential for concurrent programming.

4. **Inferring Specific Actions:** Based on the identified elements, I can infer specific actions the code performs:
    * **Comparison Handling:** It takes comparison operations (like equality, less than) and might combine them with conditional branches to avoid redundant comparisons. It handles different data types (integers, floats).
    * **Arithmetic Operation Handling:** It processes arithmetic operations (add, subtract, multiply), including checks for overflow.
    * **Switch Statement Optimization:** It chooses between different strategies (jump tables or binary search) for implementing switch statements based on the number of cases and the range of values.
    * **Floating-Point Operations:** It handles comparisons and other operations on single-precision (`float32`) and double-precision (`float64`) floating-point numbers.
    * **Atomic Operations:** It implements atomic load, store, exchange, and compare-and-exchange operations for concurrent data access.
    * **SIMD Instruction Selection:** It maps SIMD IR operations to specific IA32 SIMD instructions (SSE, AVX).

5. **Addressing Specific Questions from the Prompt:**

    * **".tq" extension:** The code is ".cc", not ".tq", so it's C++, not Torque.
    * **Relationship to JavaScript:**  The code is part of the *compiler* that translates JavaScript into machine code. Therefore, it's fundamentally related to how JavaScript code is executed. I can provide JavaScript examples that would trigger these code paths (e.g., `if (a == b)`, `a + b`, `switch (x)`).
    * **Code Logic Inference (Assumptions and Outputs):** I can choose a specific code block (e.g., the `VisitBranch` function) and describe its logic based on the input `value` node and the `cont` (FlagsContinuation). I can provide examples of input IR and the likely output machine instructions.
    * **Common Programming Errors:** Since the code deals with comparisons and arithmetic, common errors like integer overflow, incorrect comparisons (e.g., using `=` instead of `==`), or issues with floating-point comparisons (due to precision) are relevant.
    * **Summarizing Functionality (The Core Task):**  The overarching function is *instruction selection* – translating IR to IA32 machine code, optimizing where possible (like combining comparisons with branches).

6. **Structuring the Answer:**  I'll organize the findings into logical sections, addressing each point in the prompt. I'll start with the core functionality and then elaborate on specific aspects, providing examples and explanations where necessary. I'll use clear and concise language, avoiding overly technical jargon where possible. I'll explicitly address each of the decomposed questions from the prompt to ensure a comprehensive answer.

This methodical approach of understanding context, identifying core functionality, analyzing structure, inferring actions, and then addressing specific questions allows for a thorough and accurate understanding of the C++ code snippet.
这是一个V8 JavaScript引擎源代码文件，位于 `v8/src/compiler/backend/ia32/` 目录下，专门针对 **IA32 (x86 32位)** 架构。它的主要功能是 **指令选择 (Instruction Selection)**。

**具体功能归纳:**

1. **指令选择核心职责:** 该文件的核心功能是将 V8 编译器生成的**中间表示 (Intermediate Representation - IR)** 转换成具体的 **IA32 机器指令**。这是代码生成过程中的关键一步。

2. **针对特定架构 (IA32):**  `instruction-selector-ia32.cc` 中的代码逻辑和生成的指令都严格针对 IA32 架构的特性和指令集。

3. **处理不同 IR 节点 (操作):**  文件中包含大量的 `Visit...` 函数 (例如 `VisitWordCompare`, `VisitFloat64Compare`, `VisitBinop`, `VisitSwitch` 等)。这些函数分别负责处理不同类型的 IR 节点，每个节点代表一个特定的操作 (例如比较、算术运算、内存访问等)。

4. **利用 `FlagsContinuation` 处理条件码:** `FlagsContinuation` 类用于管理和优化基于处理器标志位的条件跳转。代码会尝试将比较操作与后续的条件分支指令合并，以提高效率。

5. **使用 `IA32OperandGeneratorT` 生成操作数:**  `IA32OperandGeneratorT` 模板类用于生成 IA32 指令所需的操作数 (例如寄存器、内存地址、立即数)。

6. **处理比较操作:**  `VisitWordCompare`, `VisitFloat32Compare`, `VisitFloat64Compare` 等函数处理不同数据类型的比较操作，并设置相应的条件码。

7. **处理算术和逻辑运算:** `VisitBinop` 等函数处理二进制算术和逻辑运算 (加、减、乘、与、或、异或等)，并考虑溢出情况。

8. **处理控制流:** `VisitBranch`, `VisitSwitch` 等函数处理条件分支和 `switch` 语句。`VisitSwitch` 还会根据 `switch` 语句的特性选择合适的实现方式 (例如跳转表或二分查找)。

9. **处理浮点数操作:**  包含处理单精度 (`float32`) 和双精度 (`float64`) 浮点数比较和运算的逻辑。

10. **处理原子操作:**  包含对原子加载 (`VisitWord32AtomicLoad`)、原子存储 (`VisitWord32AtomicStore`) 和原子读-修改-写操作 (例如 `VisitWord32AtomicExchange`, `VisitWord32AtomicCompareExchange`, `VisitWord32AtomicAdd` 等) 的支持。这些操作用于多线程环境下的数据同步。

11. **处理 SIMD 指令:**  包含了对 SIMD (Single Instruction, Multiple Data) 指令的支持，例如处理 `I32x4`, `F32x4` 等 SIMD 数据类型的操作，可以并行执行多个数据元素的运算，提高性能。

12. **内存屏障:**  `VisitMemoryBarrier` 函数处理内存屏障指令，用于确保多线程环境下的内存访问顺序。

**如果 v8/src/compiler/backend/ia32/instruction-selector-ia32.cc 以 .tq 结尾:**

那么它将是 **V8 Torque 源代码**。Torque 是一种用于定义 V8 内部实现的领域特定语言。Torque 代码会被编译成 C++ 代码。如果该文件是 `.tq` 文件，那么其中定义的逻辑会以更声明式的方式描述指令选择过程，最终仍然生成 IA32 指令。

**与 Javascript 的功能关系 (举例说明):**

`instruction-selector-ia32.cc` 的工作是直接将 JavaScript 代码编译成 IA32 机器码的一部分。任何 JavaScript 代码的执行最终都会依赖于这个阶段生成的机器指令。

```javascript
// JavaScript 示例

function compare(a, b) {
  if (a > b) {
    return "a is greater";
  } else if (a < b) {
    return "b is greater";
  } else {
    return "equal";
  }
}

let result = compare(10, 5);
console.log(result); // 输出 "a is greater"

let sum = 5 + 3;
console.log(sum); // 输出 8

let arr1 = [1, 2, 3, 4];
let arr2 = [5, 6, 7, 8];
// 假设 V8 内部使用 SIMD 指令优化数组操作
// 这里只是一个概念性的例子，实际实现可能更复杂
let resultArr = arr1.map((val, index) => val + arr2[index]);
console.log(resultArr); // 输出 [6, 8, 10, 12]
```

在编译上述 JavaScript 代码时，`instruction-selector-ia32.cc` 会参与以下过程：

* **`if (a > b)`:**  `VisitInt32LessThan` (经过可能的优化) 会被调用，生成 IA32 的 `cmp` 指令来比较 `a` 和 `b`，并设置相应的标志位，然后根据标志位生成条件跳转指令 (`jg` 或 `jle`)。
* **`5 + 3`:** `VisitBinop` 会被调用，生成 IA32 的 `add` 指令来执行加法运算。
* **数组操作 (SIMD 例子):**  如果 V8 能够将数组的加法操作优化为 SIMD 指令，那么 `instruction-selector-ia32.cc` 中与 SIMD 相关的 `Visit` 函数会被调用，生成例如 `paddd` (SSE2 指令) 或类似的 AVX 指令来并行执行加法。

**代码逻辑推理 (假设输入与输出):**

考虑以下代码片段：

```c++
          switch (comparison->kind) {
            case ComparisonOp::Kind::kEqual:
              cont->OverwriteAndNegateIfEqual(kUnorderedEqual);
              return VisitFloat64Compare(this, value, cont);
            // ... 其他 case ...
          }
```

**假设输入:**

* `comparison->kind` 的值为 `ComparisonOp::Kind::kEqual`。
* `value` 是一个表示需要进行浮点数比较的 IR 节点。
* `cont` 是一个 `FlagsContinuation` 对象。

**输出:**

1. `cont->OverwriteAndNegateIfEqual(kUnorderedEqual);`:  `cont` 对象会被修改，指示如果浮点数比较结果是无序的 (NaN 参与比较)，则条件为真。
2. `VisitFloat64Compare(this, value, cont);`:  会调用 `VisitFloat64Compare` 函数，将 `value` 节点和修改后的 `cont` 对象传递给它，以生成用于执行浮点数比较的 IA32 指令。生成的指令很可能是 `ucomisd` 或类似的指令，它会设置标志位以反映浮点数比较的结果 (包括无序的情况)。

**用户常见的编程错误 (举例说明):**

1. **整数溢出:**

   ```javascript
   let maxInt = 2147483647;
   let result = maxInt + 1;
   console.log(result); // 可能输出一个负数，因为发生了溢出
   ```

   在编译这段代码时，`instruction-selector-ia32.cc` 会生成 `add` 指令。如果启用了溢出检查，并且检测到溢出，可能会抛出异常或执行特定的溢出处理逻辑。用户没有预料到整数溢出，导致程序行为不符合预期。

2. **浮点数比较错误:**

   ```javascript
   let a = 0.1 + 0.2;
   let b = 0.3;
   if (a === b) {
     console.log("相等"); // 实际上不会输出 "相等"
   } else {
     console.log("不相等"); // 会输出 "不相等"
   }
   ```

   由于浮点数的精度问题，`0.1 + 0.2` 的结果可能非常接近但不完全等于 `0.3`。`instruction-selector-ia32.cc` 会生成浮点数比较指令 (`ucomisd` 等)。用户期望浮点数比较是精确的，但由于其内部表示的限制，可能会得到意想不到的结果。

**总结 `instruction-selector-ia32.cc` 的功能 (第 4 部分):**

在提供的代码片段中，`instruction-selector-ia32.cc` 的主要功能集中在 **处理比较操作和基于比较结果的控制流**。具体来说：

* **优化比较和分支:**  代码尝试将比较操作与紧随其后的条件分支指令合并，避免重复的比较操作。
* **处理不同类型的比较:**  能够处理整数、单精度浮点数和双精度浮点数的相等、小于、小于等于等比较。
* **处理 `switch` 语句:**  能够根据 `switch` 语句的特性选择不同的实现策略 (跳转表或二分查找) 来提高效率。
* **处理带溢出检查的运算:**  能够识别并处理带有溢出检查的算术运算，并根据溢出情况生成相应的指令。
* **处理栈指针比较:**  能够处理与栈指针相关的比较操作。

总的来说，这部分代码负责将高级的比较和控制流逻辑转换为底层的 IA32 机器指令，并进行一定的优化。

### 提示词
```
这是目录为v8/src/compiler/backend/ia32/instruction-selector-ia32.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/ia32/instruction-selector-ia32.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
switch (comparison->kind) {
            case ComparisonOp::Kind::kEqual:
              cont->OverwriteAndNegateIfEqual(kUnorderedEqual);
              return VisitFloat64Compare(this, value, cont);
            case ComparisonOp::Kind::kSignedLessThan:
              cont->OverwriteAndNegateIfEqual(kUnsignedGreaterThan);
              return VisitFloat64Compare(this, value, cont);
            case ComparisonOp::Kind::kSignedLessThanOrEqual:
              cont->OverwriteAndNegateIfEqual(kUnsignedGreaterThanOrEqual);
              return VisitFloat64Compare(this, value, cont);
            default:
              UNREACHABLE();
          }
        default:
          break;
      }
    } else if (value_op.Is<Opmask::kWord32Sub>()) {
      return VisitWordCompare(this, value, cont);
    } else if (value_op.Is<Opmask::kWord32BitwiseAnd>()) {
      return VisitWordCompare(this, value, kIA32Test, cont);
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
            DCHECK_EQ(binop->rep, WordRepresentation::Word32());
            cont->OverwriteAndNegateIfEqual(kOverflow);
            switch (binop->kind) {
              case OverflowCheckedBinopOp::Kind::kSignedAdd:
                return VisitBinop(this, node, kIA32Add, cont);
              case OverflowCheckedBinopOp::Kind::kSignedSub:
                return VisitBinop(this, node, kIA32Sub, cont);
              case OverflowCheckedBinopOp::Kind::kSignedMul:
                return VisitBinop(this, node, kIA32Imul, cont);
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
  IA32OperandGeneratorT<TurboshaftAdapter> g(this);
  VisitCompare(this, kIA32Cmp, g.Use(value), g.TempImmediate(0), cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWordCompareZero(
    node_t user, node_t value, FlagsContinuation* cont) {
  if constexpr (Adapter::IsTurboshaft) {
    UNREACHABLE();  // Template-specialized above.
  } else {
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
          return VisitWordCompare(this, value, cont);
        case IrOpcode::kInt32LessThan:
          cont->OverwriteAndNegateIfEqual(kSignedLessThan);
          return VisitWordCompare(this, value, cont);
        case IrOpcode::kInt32LessThanOrEqual:
          cont->OverwriteAndNegateIfEqual(kSignedLessThanOrEqual);
          return VisitWordCompare(this, value, cont);
        case IrOpcode::kUint32LessThan:
          cont->OverwriteAndNegateIfEqual(kUnsignedLessThan);
          return VisitWordCompare(this, value, cont);
        case IrOpcode::kUint32LessThanOrEqual:
          cont->OverwriteAndNegateIfEqual(kUnsignedLessThanOrEqual);
          return VisitWordCompare(this, value, cont);
        case IrOpcode::kFloat32Equal:
          cont->OverwriteAndNegateIfEqual(kUnorderedEqual);
          return VisitFloat32Compare(this, value, cont);
        case IrOpcode::kFloat32LessThan:
          cont->OverwriteAndNegateIfEqual(kUnsignedGreaterThan);
          return VisitFloat32Compare(this, value, cont);
        case IrOpcode::kFloat32LessThanOrEqual:
          cont->OverwriteAndNegateIfEqual(kUnsignedGreaterThanOrEqual);
          return VisitFloat32Compare(this, value, cont);
        case IrOpcode::kFloat64Equal:
          cont->OverwriteAndNegateIfEqual(kUnorderedEqual);
          return VisitFloat64Compare(this, value, cont);
        case IrOpcode::kFloat64LessThan:
          cont->OverwriteAndNegateIfEqual(kUnsignedGreaterThan);
          return VisitFloat64Compare(this, value, cont);
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
                  return VisitBinop(this, node, kIA32Add, cont);
                case IrOpcode::kInt32SubWithOverflow:
                  cont->OverwriteAndNegateIfEqual(kOverflow);
                  return VisitBinop(this, node, kIA32Sub, cont);
                case IrOpcode::kInt32MulWithOverflow:
                  cont->OverwriteAndNegateIfEqual(kOverflow);
                  return VisitBinop(this, node, kIA32Imul, cont);
                default:
                  break;
              }
            }
          }
          break;
        case IrOpcode::kInt32Sub:
          return VisitWordCompare(this, value, cont);
        case IrOpcode::kWord32And:
          return VisitWordCompare(this, value, kIA32Test, cont);
        case IrOpcode::kStackPointerGreaterThan:
          cont->OverwriteAndNegateIfEqual(kStackPointerGreaterThanCondition);
          return VisitStackPointerGreaterThan(value, cont);
        default:
          break;
      }
    }

    // Continuation could not be combined with a compare, emit compare against
    // 0.
    IA32OperandGeneratorT<Adapter> g(this);
    VisitCompare(this, kIA32Cmp, g.Use(value), g.TempImmediate(0), cont);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSwitch(node_t node,
                                                const SwitchInfo& sw) {
  {  // Temporary scope to minimize indentation change churn below.
    IA32OperandGeneratorT<Adapter> g(this);
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
        InstructionOperand index_operand = value_operand;
        if (sw.min_value()) {
          index_operand = g.TempRegister();
          Emit(kIA32Lea | AddressingModeField::encode(kMode_MRI), index_operand,
               value_operand, g.TempImmediate(-sw.min_value()));
        }
        // Generate a table lookup.
        return EmitTableSwitch(sw, index_operand);
      }
    }

    // Generate a tree of conditional jumps.
    return EmitBinarySearchSwitch(sw, value_operand);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Equal(node_t node) {
  FlagsContinuation cont = FlagsContinuation::ForSet(kEqual, node);
  if constexpr (Adapter::IsTurboshaft) {
    const turboshaft::ComparisonOp& comparison =
        this->Get(node).template Cast<turboshaft::ComparisonOp>();
    if (this->MatchIntegralZero(comparison.right())) {
      return VisitWordCompareZero(node, comparison.left(), &cont);
    }
  } else {
    Int32BinopMatcher m(node);
    if (m.right().Is(0)) {
      return VisitWordCompareZero(m.node(), m.left().node(), &cont);
    }
  }
  VisitWordCompare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32LessThan(node_t node) {
  FlagsContinuation cont = FlagsContinuation::ForSet(kSignedLessThan, node);
  VisitWordCompare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32LessThanOrEqual(node_t node) {
  FlagsContinuation cont =
      FlagsContinuation::ForSet(kSignedLessThanOrEqual, node);
  VisitWordCompare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint32LessThan(node_t node) {
  FlagsContinuation cont = FlagsContinuation::ForSet(kUnsignedLessThan, node);
  VisitWordCompare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint32LessThanOrEqual(node_t node) {
  FlagsContinuation cont =
      FlagsContinuation::ForSet(kUnsignedLessThanOrEqual, node);
  VisitWordCompare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32AddWithOverflow(node_t node) {
  node_t ovf = FindProjection(node, 1);
  if (this->valid(ovf)) {
    FlagsContinuation cont = FlagsContinuation::ForSet(kOverflow, ovf);
    return VisitBinop(this, node, kIA32Add, &cont);
  }
  FlagsContinuation cont;
  VisitBinop(this, node, kIA32Add, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32SubWithOverflow(node_t node) {
  node_t ovf = FindProjection(node, 1);
  if (this->valid(ovf)) {
    FlagsContinuation cont = FlagsContinuation::ForSet(kOverflow, ovf);
    return VisitBinop(this, node, kIA32Sub, &cont);
  }
  FlagsContinuation cont;
  VisitBinop(this, node, kIA32Sub, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32MulWithOverflow(node_t node) {
  node_t ovf = FindProjection(node, 1);
  if (this->valid(ovf)) {
    FlagsContinuation cont = FlagsContinuation::ForSet(kOverflow, ovf);
    return VisitBinop(this, node, kIA32Imul, &cont);
  }
  FlagsContinuation cont;
  VisitBinop(this, node, kIA32Imul, &cont);
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
  FlagsContinuation cont = FlagsContinuation::ForSet(kUnorderedEqual, node);
  VisitFloat64Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64LessThan(node_t node) {
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

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64InsertLowWord32(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    // Turboshaft uses {BitcastWord32PairToFloat64}.
    UNREACHABLE();
  } else {
    IA32OperandGeneratorT<Adapter> g(this);
    Node* left = node->InputAt(0);
    Node* right = node->InputAt(1);
    Float64Matcher mleft(left);
    if (mleft.HasResolvedValue() &&
        (base::bit_cast<uint64_t>(mleft.ResolvedValue()) >> 32) == 0u) {
      Emit(kIA32Float64LoadLowWord32, g.DefineAsRegister(node), g.Use(right));
      return;
    }
    Emit(kIA32Float64InsertLowWord32, g.DefineSameAsFirst(node),
         g.UseRegister(left), g.Use(right));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64InsertHighWord32(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    // Turboshaft uses {BitcastWord32PairToFloat64}.
    UNREACHABLE();
  } else {
    IA32OperandGeneratorT<Adapter> g(this);
    Node* left = node->InputAt(0);
    Node* right = node->InputAt(1);
    Emit(kIA32Float64InsertHighWord32, g.DefineSameAsFirst(node),
         g.UseRegister(left), g.Use(right));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitBitcastWord32PairToFloat64(
    node_t node) {
  if constexpr (Adapter::IsTurbofan) {
    // Turbofan uses {Float64Insert{High,Low}Word32}.
    UNREACHABLE();
  } else {
    IA32OperandGeneratorT<Adapter> g(this);
    const turboshaft::BitcastWord32PairToFloat64Op& cast_op =
        this->Get(node)
            .template Cast<turboshaft::BitcastWord32PairToFloat64Op>();
    Emit(kIA32Float64FromWord32Pair, g.DefineAsRegister(node),
         g.Use(cast_op.low_word32()), g.Use(cast_op.high_word32()));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64SilenceNaN(node_t node) {
  IA32OperandGeneratorT<Adapter> g(this);
  Emit(kIA32Float64SilenceNaN, g.DefineSameAsFirst(node),
       g.UseRegister(this->input_at(node, 0)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitMemoryBarrier(node_t node) {
  // ia32 is no weaker than release-acquire and only needs to emit an
  // instruction for SeqCst memory barriers.
  AtomicMemoryOrder order = AtomicOrder(this, node);
  if (order == AtomicMemoryOrder::kSeqCst) {
    IA32OperandGeneratorT<Adapter> g(this);
    Emit(kIA32MFence, g.NoOutput());
    return;
  }
  DCHECK_EQ(AtomicMemoryOrder::kAcqRel, order);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicLoad(node_t node) {
  LoadRepresentation load_rep = this->load_view(node).loaded_rep();
  DCHECK(load_rep.representation() == MachineRepresentation::kWord8 ||
         load_rep.representation() == MachineRepresentation::kWord16 ||
         load_rep.representation() == MachineRepresentation::kWord32 ||
         load_rep.representation() == MachineRepresentation::kTaggedSigned ||
         load_rep.representation() == MachineRepresentation::kTaggedPointer ||
         load_rep.representation() == MachineRepresentation::kTagged);
  // The memory order is ignored as both acquire and sequentially consistent
  // loads can emit MOV.
  // https://www.cl.cam.ac.uk/~pes20/cpp/cpp0xmappings.html
  VisitLoad(node, node, GetLoadOpcode(load_rep));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicStore(node_t node) {
  VisitStoreCommon(this, this->store_view(node));
}

MachineType AtomicOpType(InstructionSelectorT<TurboshaftAdapter>* selector,
                         turboshaft::OpIndex node) {
  const turboshaft::AtomicRMWOp& atomic_op =
      selector->Get(node).template Cast<turboshaft::AtomicRMWOp>();
  return atomic_op.memory_rep.ToMachineType();
}

MachineType AtomicOpType(InstructionSelectorT<TurbofanAdapter>* selector,
                         Node* node) {
  return AtomicOpType(node->op());
}

AtomicMemoryOrder AtomicOrder(InstructionSelectorT<TurboshaftAdapter>* selector,
                              turboshaft::OpIndex node) {
  const turboshaft::Operation& op = selector->Get(node);
  if (op.Is<turboshaft::AtomicWord32PairOp>()) {
    // TODO(nicohartmann): Turboshaft doesn't support configurable memory
    // orders yet; see also {TurboshaftAdapter::StoreView}.
    return AtomicMemoryOrder::kSeqCst;
  }
  if (const turboshaft::MemoryBarrierOp* barrier =
          op.TryCast<turboshaft::MemoryBarrierOp>()) {
    return barrier->memory_order;
  }
  UNREACHABLE();
}

AtomicMemoryOrder AtomicOrder(InstructionSelectorT<TurbofanAdapter>* selector,
                              Node* node) {
  return OpParameter<AtomicMemoryOrder>(node->op());
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicExchange(node_t node) {
  IA32OperandGeneratorT<Adapter> g(this);
  MachineType type = AtomicOpType(this, node);
  ArchOpcode opcode;
  if (type == MachineType::Int8()) {
    opcode = kAtomicExchangeInt8;
  } else if (type == MachineType::Uint8()) {
    opcode = kAtomicExchangeUint8;
  } else if (type == MachineType::Int16()) {
    opcode = kAtomicExchangeInt16;
  } else if (type == MachineType::Uint16()) {
    opcode = kAtomicExchangeUint16;
  } else if (type == MachineType::Int32() || type == MachineType::Uint32()) {
    opcode = kAtomicExchangeWord32;
  } else {
    UNREACHABLE();
  }
  VisitAtomicExchange(this, node, opcode, type.representation());
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicCompareExchange(
    node_t node) {
  IA32OperandGeneratorT<Adapter> g(this);
  auto atomic_op = this->atomic_rmw_view(node);
  node_t base = atomic_op.base();
  node_t index = atomic_op.index();
  node_t old_value = atomic_op.expected();
  node_t new_value = atomic_op.value();

  MachineType type = AtomicOpType(this, node);
  ArchOpcode opcode;
  if (type == MachineType::Int8()) {
    opcode = kAtomicCompareExchangeInt8;
  } else if (type == MachineType::Uint8()) {
    opcode = kAtomicCompareExchangeUint8;
  } else if (type == MachineType::Int16()) {
    opcode = kAtomicCompareExchangeInt16;
  } else if (type == MachineType::Uint16()) {
    opcode = kAtomicCompareExchangeUint16;
  } else if (type == MachineType::Int32() || type == MachineType::Uint32()) {
    opcode = kAtomicCompareExchangeWord32;
  } else {
    UNREACHABLE();
  }
  AddressingMode addressing_mode;
  InstructionOperand new_val_operand =
      (type.representation() == MachineRepresentation::kWord8)
          ? g.UseByteRegister(new_value)
          : g.UseUniqueRegister(new_value);
  InstructionOperand inputs[] = {
      g.UseFixed(old_value, eax), new_val_operand, g.UseUniqueRegister(base),
      g.GetEffectiveIndexOperand(index, &addressing_mode)};
  InstructionOperand outputs[] = {g.DefineAsFixed(node, eax)};
  InstructionCode code = opcode | AddressingModeField::encode(addressing_mode);
  Emit(code, 1, outputs, arraysize(inputs), inputs);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicBinaryOperation(
    node_t node, ArchOpcode int8_op, ArchOpcode uint8_op, ArchOpcode int16_op,
    ArchOpcode uint16_op, ArchOpcode word32_op) {
  {  // Temporary scope to minimize indentation change churn below.
    MachineType type = AtomicOpType(this, node);
    ArchOpcode opcode;
    if (type == MachineType::Int8()) {
      opcode = int8_op;
    } else if (type == MachineType::Uint8()) {
      opcode = uint8_op;
    } else if (type == MachineType::Int16()) {
      opcode = int16_op;
    } else if (type == MachineType::Uint16()) {
      opcode = uint16_op;
    } else if (type == MachineType::Int32() || type == MachineType::Uint32()) {
      opcode = word32_op;
    } else {
      UNREACHABLE();
    }
    VisitAtomicBinOp(this, node, opcode, type.representation());
  }
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

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicPairLoad(node_t node) {
  // Both acquire and sequentially consistent loads can emit MOV.
  // https://www.cl.cam.ac.uk/~pes20/cpp/cpp0xmappings.html
  IA32OperandGeneratorT<Adapter> g(this);
  AddressingMode mode;
  node_t base = this->input_at(node, 0);
  node_t index = this->input_at(node, 1);
  node_t projection0 = FindProjection(node, 0);
  node_t projection1 = FindProjection(node, 1);
  if (this->valid(projection0) && this->valid(projection1)) {
    InstructionOperand inputs[] = {g.UseUniqueRegister(base),
                                   g.GetEffectiveIndexOperand(index, &mode)};
    InstructionCode code =
        kIA32Word32AtomicPairLoad | AddressingModeField::encode(mode);
    InstructionOperand outputs[] = {g.DefineAsRegister(projection0),
                                    g.DefineAsRegister(projection1)};
    Emit(code, 2, outputs, 2, inputs);
  } else if (this->valid(projection0) || this->valid(projection1)) {
    // Only one word is needed, so it's enough to load just that.
    ArchOpcode opcode = kIA32Movl;

    InstructionOperand outputs[] = {g.DefineAsRegister(
        this->valid(projection0) ? projection0 : projection1)};
    InstructionOperand inputs[3];
    size_t input_count = 0;
    // TODO(ahaas): Introduce an enum for {scale} instead of an integer.
    // {scale = 0} means *1 in the generated code.
    int scale = 0;
    AddressingMode mode = g.GenerateMemoryOperandInputs(
        index, scale, base, this->valid(projection0) ? 0 : 4,
        kPositiveDisplacement, inputs, &input_count);
    InstructionCode code = opcode | AddressingModeField::encode(mode);
    Emit(code, 1, outputs, input_count, inputs);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicPairStore(node_t node) {
  // Release pair stores emit a MOVQ via a double register, and sequentially
  // consistent stores emit CMPXCHG8B.
  // https://www.cl.cam.ac.uk/~pes20/cpp/cpp0xmappings.html

  IA32OperandGeneratorT<Adapter> g(this);
  node_t base = this->input_at(node, 0);
  node_t index = this->input_at(node, 1);
  node_t value = this->input_at(node, 2);
  node_t value_high = this->input_at(node, 3);

  AtomicMemoryOrder order = AtomicOrder(this, node);
  if (order == AtomicMemoryOrder::kAcqRel) {
    AddressingMode addressing_mode;
    InstructionOperand inputs[] = {
        g.UseUniqueRegisterOrSlotOrConstant(value),
        g.UseUniqueRegisterOrSlotOrConstant(value_high),
        g.UseUniqueRegister(base),
        g.GetEffectiveIndexOperand(index, &addressing_mode),
    };
    InstructionCode code = kIA32Word32ReleasePairStore |
                           AddressingModeField::encode(addressing_mode);
    Emit(code, 0, nullptr, arraysize(inputs), inputs);
  } else {
    DCHECK_EQ(order, AtomicMemoryOrder::kSeqCst);

    AddressingMode addressing_mode;
    InstructionOperand inputs[] = {
        g.UseUniqueRegisterOrSlotOrConstant(value), g.UseFixed(value_high, ecx),
        g.UseUniqueRegister(base),
        g.GetEffectiveIndexOperand(index, &addressing_mode)};
    // Allocating temp registers here as stores are performed using an atomic
    // exchange, the output of which is stored in edx:eax, which should be saved
    // and restored at the end of the instruction.
    InstructionOperand temps[] = {g.TempRegister(eax), g.TempRegister(edx)};
    const int num_temps = arraysize(temps);
    InstructionCode code = kIA32Word32SeqCstPairStore |
                           AddressingModeField::encode(addressing_mode);
    Emit(code, 0, nullptr, arraysize(inputs), inputs, num_temps, temps);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicPairAdd(node_t node) {
  VisitPairAtomicBinOp(this, node, kIA32Word32AtomicPairAdd);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicPairSub(node_t node) {
  VisitPairAtomicBinOp(this, node, kIA32Word32AtomicPairSub);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicPairAnd(node_t node) {
  VisitPairAtomicBinOp(this, node, kIA32Word32AtomicPairAnd);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicPairOr(node_t node) {
  VisitPairAtomicBinOp(this, node, kIA32Word32AtomicPairOr);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicPairXor(node_t node) {
  VisitPairAtomicBinOp(this, node, kIA32Word32AtomicPairXor);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicPairExchange(node_t node) {
  VisitPairAtomicBinOp(this, node, kIA32Word32AtomicPairExchange);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicPairCompareExchange(
    node_t node) {
  IA32OperandGeneratorT<Adapter> g(this);
  node_t index = this->input_at(node, 1);
  AddressingMode addressing_mode;

  // In the Turbofan and the Turboshaft graph the order of expected and value is
  // swapped.
  const size_t expected_offset = Adapter::IsTurboshaft ? 4 : 2;
  const size_t value_offset = Adapter::IsTurboshaft ? 2 : 4;
  InstructionOperand inputs[] = {
      // High, Low values of old value
      g.UseFixed(this->input_at(node, expected_offset), eax),
      g.UseFixed(this->input_at(node, expected_offset + 1), edx),
      // High, Low values of new value
      g.UseUniqueRegisterOrSlotOrConstant(this->input_at(node, value_offset)),
      g.UseFixed(this->input_at(node, value_offset + 1), ecx),
      // InputAt(0) => base
      g.UseUniqueRegister(this->input_at(node, 0)),
      g.GetEffectiveIndexOperand(index, &addressing_mode)};
  node_t projection0 = FindProjection(node, 0);
  node_t projection1 = FindProjection(node, 1);
  InstructionCode code = kIA32Word32AtomicPairCompareExchange |
                         AddressingModeField::encode(addressing_mode);

  InstructionOperand outputs[2];
  size_t output_count = 0;
  InstructionOperand temps[2];
  size_t temp_count = 0;
  if (this->valid(projection0)) {
    outputs[output_count++] = g.DefineAsFixed(projection0, eax);
  } else {
    temps[temp_count++] = g.TempRegister(eax);
  }
  if (this->valid(projection1)) {
    outputs[output_count++] = g.DefineAsFixed(projection1, edx);
  } else {
    temps[temp_count++] = g.TempRegister(edx);
  }
  Emit(code, output_count, outputs, arraysize(inputs), inputs, temp_count,
       temps);
}

#define SIMD_INT_TYPES(V) \
  V(I32x4)                \
  V(I16x8)                \
  V(I8x16)

#define SIMD_BINOP_LIST(V) \
  V(I32x4GtU)              \
  V(I32x4GeU)              \
  V(I16x8Ne)               \
  V(I16x8GeS)              \
  V(I16x8GtU)              \
  V(I16x8GeU)              \
  V(I8x16Ne)               \
  V(I8x16GeS)              \
  V(I8x16GtU)              \
  V(I8x16GeU)

#define SIMD_BINOP_UNIFIED_SSE_AVX_LIST(V) \
  V(F32x4Add)                              \
  V(F32x4Sub)                              \
  V(F32x4Mul)                              \
  V(F32x4Div)                              \
  V(F32x4Eq)                               \
  V(F32x4Ne)                               \
  V(F32x4Lt)                               \
  V(F32x4Le)                               \
  V(F32x4Min)                              \
  V(F32x4Max)                              \
  V(I64x2Add)                              \
  V(I64x2Sub)                              \
  V(I64x2Eq)                               \
  V(I64x2Ne)                               \
  V(I32x4Add)                              \
  V(I32x4Sub)                              \
  V(I32x4Mul)                              \
  V(I32x4MinS)                             \
  V(I32x4MaxS)                             \
  V(I32x4Eq)                               \
  V(I32x4Ne)                               \
  V(I32x4GtS)                              \
  V(I32x4GeS)                              \
  V(I32x4MinU)                             \
  V(I32x4MaxU)                             \
  V(I32x4DotI16x8S)                        \
  V(I16x8Add)                              \
  V(I16x8AddSatS)                          \
  V(I16x8Sub)                              \
  V(I16x8SubSatS)                          \
  V(I16x8Mul)                              \
  V(I16x8Eq)                               \
  V(I16x8GtS)                              \
  V(I16x8MinS)                             \
  V(I16x8MaxS)                             \
  V(I16x8AddSatU)                          \
  V(I16x8SubSatU)                          \
  V(I16x8MinU)                             \
  V(I16x8MaxU)                             \
  V(I16x8SConvertI32x4)                    \
  V(I16x8UConvertI32x4)                    \
  V(I16x8RoundingAverageU)                 \
  V(I8x16Add)                              \
  V(I8x16AddSatS)                          \
  V(I8x16Sub)                              \
  V(I8x16SubSatS)                          \
  V(I8x16MinS)                             \
  V(I8x16MaxS)                             \
  V(I8x16Eq)                               \
  V(I8x16GtS)                              \
  V(I8x16AddSatU)                          \
  V(I8x16SubSatU)                          \
  V(I8x16MinU)                             \
  V(I8x16MaxU)                             \
  V(I8x16SConvertI16x8)                    \
  V(I8x16UConvertI16x8)                    \
  V(I8x16RoundingAverageU)                 \
  V(S128And)                               \
  V(S128Or)                                \
  V(S128Xor)

// These opcodes require all inputs to be registers because the codegen is
// simpler with all registers.
#define SIMD_BINOP_RRR(V)  \
  V(I64x2ExtMulLowI32x4S)  \
  V(I64x2ExtMulHighI32x4S) \
  V(I64x2ExtMulLowI32x4U)  \
  V(I64x2ExtMulHighI32x4U) \
  V(I32x4ExtMulLowI16x8S)  \
  V(I32x4ExtMulHighI16x8S) \
  V(I32x4ExtMulLowI16x8U)  \
  V(I32x4ExtMulHighI16x8U) \
  V(I16x8ExtMulLowI8x16S)  \
  V(I16x8ExtMulHighI8x16S) \
  V(I16x8ExtMulLowI8x16U)  \
  V(I16x8ExtMulHighI8x16U) \
  V(I16x8Q15MulRSatS)      \
  V(I16x8RelaxedQ15MulRS)

#define SIMD_UNOP_LIST(V)   \
  V(F64x2ConvertLowI32x4S)  \
  V(F32x4DemoteF64x2Zero)   \
  V(F32x4Sqrt)              \
  V(F32x4SConvertI32x4)     \
  V(I64x2BitMask)           \
  V(I64x2SConvertI32x4Low)  \
  V(I64x2SConvertI32x4High) \
  V(I64x2UConvertI32x4Low)  \
  V(I64x2UConvertI32x4High) \
  V(I32x4SConvertI16x8Low)  \
  V(I32x4SConvertI16x8High) \
  V(I32x4Neg)               \
  V(I32x4UConvertI16x8Low)  \
  V(I32x4UConvertI16x8High) \
  V(I32x4Abs)               \
  V(I32x4BitMask)           \
  V(I16x8SConvertI8x16Low)  \
  V(I16x8SConvertI8x16High) \
  V(I16x8Neg)               \
  V(I16x8UConvertI8x16Low)  \
  V(I16x8UConvertI8x16High) \
  V(I16x8Abs)               \
  V(I8x16Neg)               \
  V(I8x16Abs)               \
  V(I8x16BitMask)           \
  V(S128Not)

#define SIMD_ALLTRUE_LIST(V) \
  V(I64x2AllTrue)            \
  V(I32x4AllTrue)            \
  V(I16x8AllTrue)            \
  V(I8x16AllTrue)

#define SIMD_SHIFT_OPCODES_UNIFED_SSE_AVX(V) \
  V(I64x2Shl)                                \
  V(I64x2ShrU)                               \
  V(I32x4Shl)                                \
  V(I32x4ShrS)                               \
  V(I32x4ShrU)                               \
  V(I16x8Shl)                                \
  V(I16x8ShrS)                               \
  V(I16x8ShrU)

#if V8_ENABLE_WEBASSEMBLY

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitS128Const(node_t node) {
```