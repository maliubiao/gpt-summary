Response:
Let's break down the thought process for analyzing this code snippet.

1. **Understanding the Goal:** The request asks for the functionalities of the provided C++ code within the context of V8's instruction selection for the MIPS64 architecture. It also specifies some additional checks (Torque, JavaScript relation, logic, common errors) and the need for a summary.

2. **Initial Scan for Keywords and Patterns:** I started by quickly scanning the code for keywords and patterns that suggest its purpose. I noticed:
    * `Visit...Compare`:  These functions clearly handle comparison operations for different data types (float32, float64, word32, word64).
    * `InstructionSelectorT`: This confirms the code is part of the instruction selection phase.
    * `Mips64OperandGeneratorT`:  This indicates the code generates MIPS64 specific operands.
    * `FlagsContinuationT`: This suggests the code deals with conditional branching and flag setting.
    * `AtomicLoad`, `AtomicStore`, `AtomicExchange`, `AtomicCompareExchange`, `AtomicBinop`:  These functions relate to atomic memory operations.
    * `kMips64...`:  These prefixes indicate MIPS64 specific instruction codes.
    * `Turboshaft`:  This keyword hints at V8's newer Turboshaft compiler pipeline and conditional compilation.
    * `IsNodeUnsigned`:  This function seems to determine if a node represents an unsigned value.
    * Templates (`template <typename Adapter>`) indicate the code is likely used by both the older Crankshaft/Full-codegen and the newer Turboshaft compilers.

3. **Categorizing Functionalities:** Based on the initial scan, I mentally grouped the functionalities:
    * **Comparison Operations:**  Handling comparisons for different data types (float, integer).
    * **Atomic Operations:** Handling atomic loads, stores, exchanges, and compare-and-exchange.
    * **Stack Pointer Check:**  Handling checks related to stack overflow.
    * **Helper Functions:** `IsNodeUnsigned` appears to be a utility.
    * **Adapter-Specific Logic:**  The `if constexpr (Adapter::IsTurboshaft)` blocks show different handling for the two compiler pipelines.

4. **Detailed Analysis of Key Functions:** I then went back and looked at the logic within the important functions:
    * **`VisitFloat32Compare`, `VisitFloat64Compare`:**  These functions take comparison nodes and generate the appropriate MIPS64 compare instructions (`kMips64CmpS`, `kMips64CmpD`). They handle cases where one operand is zero (immediate).
    * **`VisitWordCompare`:** This function is crucial for integer comparisons. It handles immediate operands, commutative operations, and different comparison conditions.
    * **`VisitFullWord32Compare`, `VisitOptimizedWord32Compare`, `VisitWord32Compare`:**  These functions address the specific challenge of 32-bit comparisons on a 64-bit architecture, particularly the sign extension issue. The code shows attempts to optimize and handle cases where full 32-bit comparison is necessary (e.g., comparing signed and unsigned values). The debugging assertion in `VisitOptimizedWord32Compare` is also noteworthy.
    * **Atomic Operation Functions (`VisitAtomicLoad`, `VisitAtomicStore`, etc.):** These functions generate MIPS64 atomic instructions, including handling write barriers for tagged pointers. They also show how addressing modes and atomic widths are configured in the instruction codes.
    * **`VisitStackPointerGreaterThan`:** This function emits an instruction to check if the stack pointer is greater than a limit, used for stack overflow detection.
    * **`VisitWordCompareZero`:** This function optimizes comparisons against zero by potentially combining them with preceding comparison operations. The different handling for Turbofan and Turboshaft is evident here.

5. **Addressing the Specific Questions:**

    * **Function Listing:** I directly listed the identified functionalities based on the function names and their internal logic.
    * **Torque:** I checked the file extension (`.cc`) and confirmed it's not Torque.
    * **JavaScript Relation:** I considered how comparisons are fundamental to JavaScript's control flow and data manipulation. I provided a simple `if` statement as an example, illustrating how the generated assembly code would be used.
    * **Logic/Input-Output:** I selected a representative function (`VisitWordCompare`) and created a simple scenario with concrete inputs and the expected output instruction code. This helps illustrate the code's transformation process.
    * **Common Errors:** I focused on the 32-bit comparison issue as a common source of errors when dealing with signed/unsigned integers. I illustrated this with a JavaScript example.

6. **Summarization:** I synthesized the key functionalities into a concise summary, highlighting the core purpose of instruction selection for comparisons and atomic operations on MIPS64.

7. **Review and Refinement:**  I reviewed my analysis to ensure accuracy, clarity, and completeness, checking against the original code snippet and the specific instructions in the prompt. I ensured the JavaScript example was simple and directly related to the comparison operations. I also made sure the assumptions and outputs for the logic example were clear.

This iterative process of scanning, categorizing, detailed analysis, and addressing specific questions allowed me to understand the code's purpose and generate a comprehensive answer. The key was to connect the C++ code to the underlying concepts of instruction selection and the specific challenges of the MIPS64 architecture.
这是第 4 部分，关于 `v8/src/compiler/backend/mips64/instruction-selector-mips64.cc` 文件的功能归纳：

**总体功能归纳 (基于第4部分代码)：**

这部分代码主要负责 **MIPS64 架构下的指令选择，专注于处理比较操作和原子操作**。它定义了一系列模板函数，用于将中间表示 (IR) 中的比较和原子操作节点转换为具体的 MIPS64 汇编指令。  这些函数考虑了不同的数据类型 (float32, float64, word32, word64)，以及是否使用 Turboshaft 编译器。

**具体功能点：**

1. **浮点数比较指令选择 (`VisitFloat32Compare`, `VisitFloat64Compare`):**
   -  为 `float32` 和 `float64` 类型的比较操作选择合适的 MIPS64 比较指令 (`kMips64CmpS`, `kMips64CmpD`)。
   -  会检查比较的其中一个操作数是否为零，并可能使用立即数进行优化。
   -  Turboshaft 和 Turbofan 编译器的处理逻辑略有不同。

2. **整数比较指令选择 (`VisitWordCompare`):**
   -  为通用整数比较操作选择指令。
   -  能够处理比较操作数中存在立即数的情况，并进行优化，例如将立即数放在右侧，或者在可交换的情况下调整操作数顺序。
   -  支持多种比较条件。

3. **32 位整数全字比较和优化比较 (`VisitFullWord32Compare`, `VisitOptimizedWord32Compare`, `VisitWord32Compare`):**
   -  由于 MIPS64 是 64 位架构，直接比较 32 位整数需要特殊处理。
   -  `VisitFullWord32Compare` 通过将操作数左移 32 位来模拟全 32 位比较。
   -  `VisitOptimizedWord32Compare`  在 Debug 模式下会同时执行优化比较和全字比较，以进行正确性检查。
   -  `VisitWord32Compare`  根据操作数的符号性（是否为 unsigned 类型）以及是否在模拟器中运行等因素，选择执行全字比较或优化比较。  这是一个为了性能而做的权衡，但可能存在遗漏某些需要全字比较的情况的风险（代码中已说明这是一个 hack）。

4. **64 位整数比较指令选择 (`VisitWord64Compare`):**
   -  直接调用 `VisitWordCompare` 处理 64 位整数比较。

5. **与零比较指令选择 (`EmitWordCompareZero`, `VisitWordCompareZero`):**
   -  专门处理与零的比较操作。
   -  `VisitWordCompareZero` 尝试将与零的比较与之前的比较操作合并，例如，如果前面是一个 `Word32Equal` 且右侧是 0，它可以将条件取反并使用之前的比较结果。这是一种常见的优化技巧。
   -  Turbofan 和 Turboshaft 的实现略有不同，Turboshaft 的实现更直接地匹配操作类型。

6. **原子加载指令选择 (`VisitAtomicLoad`):**
   -  为原子加载操作选择合适的 MIPS64 指令 (`kAtomicLoadInt8`, `kAtomicLoadUint8`, `kAtomicLoadInt16`, `kAtomicLoadUint16`, `kAtomicLoadWord32`, `kMips64Word64AtomicLoadUint64`)。
   -  考虑了加载的数据大小和符号性。
   -  支持索引是立即数或寄存器的情况。

7. **原子存储指令选择 (`VisitAtomicStore`):**
   -  为原子存储操作选择合适的 MIPS64 指令 (`kAtomicStoreWord8`, `kAtomicStoreWord16`, `kAtomicStoreWord32`, `kMips64Word64AtomicStoreWord64`, `kMips64StoreCompressTagged`)。
   -  处理写屏障 (write barrier)，这对于垃圾回收至关重要。
   -  支持索引是立即数或寄存器的情况。

8. **原子交换指令选择 (`VisitAtomicExchange`):**
   -  为原子交换操作选择 MIPS64 指令。

9. **原子比较并交换指令选择 (`VisitAtomicCompareExchange`):**
   -  为原子比较并交换操作选择 MIPS64 指令。

10. **原子二元操作指令选择 (`VisitAtomicBinop`):**
    -  为原子二元操作（例如原子加法）选择 MIPS64 指令。

11. **栈指针大于比较指令选择 (`VisitStackPointerGreaterThan`):**
    -  用于检查栈指针是否大于某个限制，常用于栈溢出检测。

**关于其他问题：**

* **`.tq` 结尾：** 代码以 `.cc` 结尾，因此不是 Torque 源代码。
* **与 JavaScript 的关系：** 这段代码是 V8 编译器的后端部分，负责将 JavaScript 代码编译成机器码。JavaScript 中的比较操作（例如 `==`, `!=`, `<`, `>`, `<=`, `>=`) 和原子操作会最终通过指令选择阶段转换成这里对应的 MIPS64 指令。

   ```javascript
   let a = 10;
   let b = 20;

   if (a < b) { // JavaScript 的小于比较
     console.log("a is less than b");
   }

   // 或者使用 Atomics 进行原子操作
   const sab = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT);
   const view = new Int32Array(sab);
   Atomics.add(view, 0, 5); // JavaScript 的原子加法操作
   ```

   当 V8 编译这段 JavaScript 代码时，`a < b` 这个比较操作会被转换成类似于 `VisitWordCompare` 中处理的逻辑，最终生成 MIPS64 的比较指令。 `Atomics.add` 操作则会通过类似于 `VisitAtomicBinop` 的函数生成对应的原子操作指令。

* **代码逻辑推理（假设输入与输出）：**
   假设 `VisitWordCompare` 函数接收到一个表示 `a == 10` 的 IR 节点，其中 `a` 是一个寄存器，`10` 是一个立即数。

   **假设输入:**
   - `node`: 代表 `a == 10` 的 IR 节点。
   - `opcode`: `kMips64Cmp` (假设是相等比较)。
   - `cont`: 一个 `FlagsContinuationT` 对象，表示后续的操作（例如跳转）。
   - `commutative`: `false` (相等比较通常认为是可交换的，但这里假设为了演示)。

   **预期输出:**
   - 调用 `VisitCompare` 函数，生成类似如下的 MIPS64 指令：
     ```assembly
     // 假设 a 寄存器是 t0
     cmp t0, 10
     // 后续根据 cont 的条件进行跳转等操作
     ```
   - 具体生成的指令会受到 `cont` 对象中条件的影响。

* **用户常见的编程错误：**
   涉及到 32 位整数比较时，如果程序员没有意识到 MIPS64 是 64 位架构，并且依赖于简单的比较，可能会遇到符号扩展导致的问题。例如，比较一个有符号的 32 位负数和一个无符号的 32 位正数，简单的 64 位比较可能不会得到预期的结果。

   ```javascript
   // 常见的错误场景
   let signedInt = -1; // 32 位有符号整数
   let unsignedInt = 4294967295; // 32 位无符号整数的最大值

   // 在 JavaScript 中，数值通常是 64 位浮点数，但在底层进行比较时可能会涉及到 32 位整数
   if (signedInt > unsignedInt) {
       console.log("有符号整数大于无符号整数"); // 这行代码可能被错误地执行，取决于底层的比较方式
   }
   ```

   V8 的 `VisitWord32Compare` 尝试解决这个问题，但正如代码注释所说，它可能不是完全完备的，并且是一个为了性能而做的妥协。

**总结：**

这段代码是 V8 编译器中 MIPS64 架构指令选择的关键部分，专注于将高级的比较和原子操作转换为底层的 MIPS64 汇编指令。它针对不同的数据类型和编译器管道进行了适配，并且在 32 位整数比较方面做了一些特殊的处理和优化。理解这部分代码有助于深入了解 V8 如何将 JavaScript 代码高效地编译成机器码。

### 提示词
```
这是目录为v8/src/compiler/backend/mips64/instruction-selector-mips64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/mips64/instruction-selector-mips64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
plate <typename Adapter>
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