Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/compiler/backend/arm64/instruction-selector-arm64.cc`. The user also has several specific questions:

1. **General Functionality:** What does this code do?
2. **Torque Source:**  If the file ended in `.tq`, it would be Torque code. This is not the case here.
3. **JavaScript Relation:** Does this code relate to JavaScript functionality? If so, provide a JavaScript example.
4. **Code Logic Inference:**  Provide examples of input and output based on the code's logic.
5. **Common Programming Errors:**  Are there any common programming errors this code helps avoid or might be related to?
6. **Overall Functionality (Part 8 of 11):** Summarize the specific tasks of this code segment within the broader context of the file.

Let's break down the code to answer these questions:

* **Instruction Selection:** The file name strongly suggests this code is responsible for selecting specific ARM64 instructions based on higher-level operations. This is a key part of the compiler backend.
* **`InstructionSelectorT` Class:** The code defines a template class `InstructionSelectorT`, indicating it's used with different "adapters" (like `TurbofanAdapter` and `TurboshaftAdapter`). This suggests the code handles instruction selection for different compiler pipelines within V8.
* **`Visit...` Methods:** The numerous `Visit...` methods (e.g., `VisitWord32Equal`, `VisitInt32LessThan`, `VisitFloat32Neg`) indicate that the code processes different types of operations or "nodes" in the compiler's intermediate representation.
* **FlagsContinuation:** The `FlagsContinuation` class appears to manage how the results of operations (especially comparisons) affect processor flags, which are crucial for conditional branching.
* **Operand Generation:**  The `Arm64OperandGeneratorT` class is likely responsible for creating the operands (registers, immediates, memory locations) for the selected ARM64 instructions.
* **Instruction Emission:**  The `Emit` and `EmitWithContinuation` functions are used to generate the actual ARM64 instructions.
* **Pattern Matching:**  The code contains logic to identify specific patterns of operations (e.g., comparing against zero, bitwise operations before comparisons) to optimize instruction selection.
* **Overflow Handling:** Several `Visit...WithOverflow` methods deal with operations that can potentially overflow, and they often check for projections (outputs) related to the overflow flag.
* **Switch Statements:** The `VisitSwitch` method handles the compilation of `switch` statements, choosing between table-based and binary search implementations.
* **Floating-Point Operations:** There are dedicated `Visit` methods for various floating-point operations.
* **Turboshaft vs. Turbofan:** The use of template specialization and `if constexpr` indicates different code paths for V8's older Turbofan and newer Turboshaft compilers.

**Answering the User's Questions:**

1. **General Functionality:** This code is responsible for **instruction selection** in V8's ARM64 backend. It takes high-level operations from the compiler's intermediate representation and translates them into concrete ARM64 machine instructions. It includes optimizations for common patterns and handles different data types and operation categories.

2. **Torque Source:** No, this file ends in `.cc`, indicating it's a standard C++ source file. Torque source files end in `.tq`.

3. **JavaScript Relation:** Yes, this code is directly related to how JavaScript code is compiled and executed on ARM64 architectures. For example, the `VisitWord32Equal` function handles the compilation of JavaScript's `===` operator for 32-bit integers.

   ```javascript
   // Example JavaScript code that might involve VisitWord32Equal
   let a = 10;
   let b = 10;
   if (a === b) {
       console.log("a and b are equal");
   }
   ```
   When this JavaScript code is executed, V8 will compile the `a === b` comparison, and this C++ code will be involved in selecting the appropriate ARM64 instructions to perform the comparison.

4. **Code Logic Inference:**

   * **Assumption:** Consider the `VisitWordCompareZero` function with a `Word64Equal` operation comparing a bitwise AND with zero.
   * **Input (Hypothetical Compiler IR):** A `Word64Equal` node where the left input is a `Word64And` operation (e.g., `x & mask`) and the right input is the constant zero. The `FlagsContinuation` is a branch instruction.
   * **Code Logic:** The code checks if the mask in the bitwise AND has only one bit set. If so, it emits a `TBZ` (Test Bit and Branch if Zero) or `TBNZ` (Test Bit and Branch if Not Zero) instruction, which is an optimization for checking a single bit.
   * **Output (Hypothetical ARM64 Assembly):**  If the mask is `0x0000000000000004` (only the 3rd bit set), and the continuation is a branch if equal, the generated instruction might be `tbz register_for_x, #2, label_true`.

5. **Common Programming Errors:** This code helps in the efficient compilation of JavaScript, indirectly mitigating performance issues that could arise from inefficiently compiled code. A common programming error in general programming (not necessarily directly related to *this specific snippet*) is relying on implicit type conversions or bitwise operations without considering potential side effects or unintended consequences. For example:

   ```javascript
   // Potential issue: Implicit type conversion or unexpected bitwise result
   let x = 5; // 0b101
   let y = "1";
   if ((x & y) === 1) { // JavaScript will convert "1" to 1
       console.log("Bitwise AND is 1");
   }
   ```
   While this code snippet doesn't directly prevent such errors in the *JavaScript* code, it ensures that *if* such operations are performed, they are translated into efficient machine code.

6. **Overall Functionality (Part 8 of 11):** This specific part of the `instruction-selector-arm64.cc` file focuses heavily on **handling comparison operations and conditional branching**. It implements the logic for selecting the appropriate ARM64 instructions for:

   * Comparing values (integers, floats, pointers, etc.).
   * Testing for equality, less than, greater than, etc.
   * Handling comparisons against zero.
   * Optimizing comparisons based on the preceding operations (e.g., combining compare and branch, using test-and-branch instructions for bit checks).
   * Generating code for `switch` statements.
   * Dealing with operations that can result in overflow, and branching based on overflow conditions.
   * Handling specific floating-point comparisons.

In essence, this section is a crucial component for implementing control flow and decision-making logic in the generated ARM64 code.
这是v8源代码文件 `v8/src/compiler/backend/arm64/instruction-selector-arm64.cc` 的一个代码片段，主要负责 **为特定的中间表示 (IR) 节点选择合适的 ARM64 汇编指令**。这是编译器后端代码生成阶段的关键部分。

以下是代码片段功能的详细归纳：

1. **处理 Word (32-bit 和 64-bit) 与零的比较 (`VisitWordCompareZero`)：**
   - 尝试将比较操作与之前的操作（例如，位运算）合并，以生成更优化的指令，例如 `TBZ` 和 `TBNZ` (Test Bit and Branch if Zero/Not Zero)。
   - 如果可能，将比较操作与之前的比较操作结合起来，例如，如果正在比较的值本身就是一个比较的结果。
   - 处理溢出检查操作，例如 `Int32AddWithOverflow` 和 `Int32SubWithOverflow` 的溢出投影。
   - 针对不同的 IR 节点类型（例如 `Word32Add`, `Word32Sub`, `Word32BitwiseAnd`）选择相应的比较指令 (`kArm64Cmn32`, `kArm64Tst32` 等)。
   - 如果无法与之前的操作合并，则生成显式的比较指令（例如 `CMP` 或 `TST`）和分支指令。

2. **处理 `switch` 语句 (`VisitSwitch`)：**
   - 根据 `switch` 语句的 case 数量和值的范围，决定使用跳转表 (`ArchTableSwitch`) 还是二分查找 (`ArchBinarySearchSwitch`) 来实现。
   - 如果满足条件（例如，case 数量较多，值范围合理），则生成跳转表查找的代码。
   - 否则，生成一系列条件跳转指令来实现 `switch` 逻辑。

3. **处理 32 位相等比较 (`VisitWord32Equal`)：**
   - 针对与零比较的特殊情况进行优化，例如，如果比较的是一个加法或按位与的结果。
   - 识别并优化 `Word32Equal(Word32Equal(x, y), 0)` 模式，将其转换为 `Word32Compare(x, y, ne)`。
   - 处理与常量根对象的比较，如果常量是只读的，并且可以作为立即数，则直接使用立即数进行比较。
   - 对于 Turboshaft 适配器，代码结构略有不同，但基本逻辑相同，都旨在优化 32 位相等比较。

4. **处理有符号和无符号 32 位比较 (`VisitInt32LessThan`, `VisitInt32LessThanOrEqual`, `VisitUint32LessThan`, `VisitUint32LessThanOrEqual`)：**
   - 设置相应的标志延续 (`FlagsContinuation`)，并调用 `VisitWord32Compare` 来生成比较指令。

5. **处理 64 位相等比较 (`VisitWord64Equal`)：**
   - 类似于 32 位相等比较，针对与零比较的特殊情况进行优化，特别是针对按位与操作。
   - 生成 64 位比较指令 (`kArm64Cmp`)。

6. **处理带溢出的 32 位和 64 位加减乘运算 (`VisitInt32AddWithOverflow`, `VisitInt32SubWithOverflow`, `VisitInt32MulWithOverflow`, `VisitInt64AddWithOverflow`, `VisitInt64SubWithOverflow`, `VisitInt64MulWithOverflow`)：**
   - 检查是否有溢出投影（表示需要检查溢出）。
   - 如果需要检查溢出，则设置相应的标志延续，并生成相应的算术指令 (`kArm64Add32`, `kArm64Sub32`, `kArm64Add`, `kArm64Sub`)。
   - 对于乘法溢出，由于 ARM64 架构的特性，需要生成额外的指令来检查溢出 (例如，使用 `SMULL` 和比较高位)。

7. **处理有符号和无符号 64 位比较 (`VisitInt64LessThan`, `VisitInt64LessThanOrEqual`, `VisitUint64LessThan`, `VisitUint64LessThanOrEqual`)：**
   - 设置相应的标志延续，并调用 `VisitWordCompare` 来生成 64 位比较指令 (`kArm64Cmp`)。

8. **处理单精度浮点数的否定运算 (`VisitFloat32Neg`)：**
   - 识别并优化乘法后跟否定的模式，使用 `FNMUL` 指令。
   - 否则，使用 `FNEG` 指令。

9. **处理单精度浮点数的乘法运算 (`VisitFloat32Mul`)：**
   - 识别并优化操作数包含否定的模式，使用 `FNMUL` 指令。
   - 否则，使用 `FMUL` 指令。

10. **处理单精度和双精度浮点数的绝对值运算 (`VisitFloat32Abs`, `VisitFloat64Abs`)：**
    - 识别并优化减法后跟绝对值的模式，使用 `ABD` 指令。
    - 否则，使用 `FABS` 指令。

11. **处理单精度和双精度浮点数的比较运算 (`VisitFloat32Equal`, `VisitFloat32LessThan`, `VisitFloat32LessThanOrEqual`, `VisitFloat64Equal`, `VisitFloat64LessThan`, `VisitFloat64LessThanOrEqual`)：**
    - 设置相应的标志延续，并调用相应的浮点比较函数 (`VisitFloat32Compare`, `VisitFloat64Compare`)。

12. **处理将 32 位字对转换为双精度浮点数的位转换 (`VisitBitcastWord32PairToFloat64`)：**
    - 使用 `BFI` (Bitfield Insert) 指令将两个 32 位寄存器合并成一个 64 位寄存器，然后使用 `FMOV` 指令将其移动到浮点寄存器。

**如果 `v8/src/compiler/backend/arm64/instruction-selector-arm64.cc` 以 `.tq` 结尾：**

那么它将是一个 **v8 Torque 源代码**。Torque 是一种用于定义 V8 内部函数和操作的领域特定语言。Torque 代码会被编译成 C++ 代码。

**与 Javascript 的功能关系：**

这段代码直接影响 JavaScript 代码在 ARM64 架构上的执行效率。当 JavaScript 代码执行到需要进行比较、算术运算、浮点运算或控制流操作时，V8 的编译器会分析这些操作，并调用 `instruction-selector-arm64.cc` 中的相应函数来选择最佳的 ARM64 指令序列。

**JavaScript 举例：**

```javascript
let x = 10;
let y = 5;

if (x > y) { // VisitInt32LessThan 会被调用
  console.log("x is greater than y");
}

let sum = x + y; // VisitInt32AddWithOverflow 可能会被调用

let f1 = 3.14;
let f2 = -f1; // VisitFloat32Neg 会被调用

switch (x) { // VisitSwitch 会被调用
  case 10:
    console.log("x is 10");
    break;
  default:
    console.log("x is not 10");
}
```

**代码逻辑推理：**

**假设输入：** 一个表示 `x > 0` 的 IR 节点，其中 `x` 是一个 32 位整数。

**`VisitWordCompareZero` 函数的执行流程：**

1. `user` 是表示 `x > 0` 比较结果的节点。
2. `value` 是表示 `x` 的节点。
3. `cont` 是一个 `FlagsContinuation` 对象，表示需要设置 CPU 标志，并且可能需要进行条件跳转。
4. 代码会尝试找到可以与比较操作合并的之前的操作。在这个例子中，假设 `x` 直接来自一个变量加载，没有可以合并的操作。
5. 由于 `cont->IsBranch()` 为真（因为这是一个条件判断），代码会生成一个比较指令和一个条件分支指令。
6. `Emit(cont->Encode(kArm64CompareAndBranch32), g.NoOutput(), g.UseRegister(value), g.Label(cont->true_block()), g.Label(cont->false_block()));` 这行代码会被执行。
7. **输出 (推测的 ARM64 汇编指令):**
   ```assembly
   cmp w[reg_x], #0  // 比较寄存器 reg_x 中的值与 0
   bgt label_true    // 如果大于，跳转到 label_true
   b label_false     // 否则跳转到 label_false
   ```
   其中 `w[reg_x]` 表示存储 `x` 值的 32 位寄存器， `label_true` 和 `label_false` 是代码块的标签。

**涉及用户常见的编程错误：**

虽然这段代码本身是编译器内部的代码，但它间接地帮助处理用户代码中可能出现的错误，例如：

* **整数溢出：** `VisitInt32AddWithOverflow` 和类似函数会生成检查溢出的代码。如果 JavaScript 代码执行加法运算可能导致溢出，V8 可以通过这些生成的代码来检测并采取相应的操作（例如，抛出异常或返回特殊值）。
* **浮点数比较：** 浮点数比较的精度问题是常见的错误。这段代码负责生成正确的浮点数比较指令，但无法完全避免由于浮点数表示的固有特性而产生的一些意外结果。
* **逻辑错误：**  `VisitSwitch` 函数的正确实现确保了 `switch` 语句按照预期的逻辑执行，避免了因错误的跳转而导致的程序行为异常。

**归纳一下它的功能 (第 8 部分，共 11 部分):**

作为指令选择过程的一部分，代码片段所在的第 8 部分主要负责 **处理各种类型的比较运算（整数和浮点数）以及与比较结果相关的控制流操作**。这包括：

* **选择合适的比较指令：** 根据操作数的类型（32 位、64 位、浮点数）和比较的类型（相等、小于、大于等）选择正确的 ARM64 比较指令。
* **优化比较操作：** 尝试将比较操作与之前的算术或逻辑运算合并，以减少指令数量并提高效率。
* **处理条件分支：**  为基于比较结果的条件跳转生成指令。
* **实现 `switch` 语句：**  选择和生成实现 `switch` 语句的指令序列。
* **处理溢出：**  对于可能溢出的算术运算，生成检查溢出的代码。

总而言之，这一部分是代码生成器中至关重要的一环，它确保了 JavaScript 代码中的比较和控制流逻辑能够被正确且高效地翻译成 ARM64 机器码。

### 提示词
```
这是目录为v8/src/compiler/backend/arm64/instruction-selector-arm64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/arm64/instruction-selector-arm64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第8部分，共11部分，请归纳一下它的功能
```

### 源代码
```cpp
cont->OverwriteAndNegateIfEqual(kStackPointerGreaterThanCondition);
          return VisitStackPointerGreaterThan(value, cont);
        default:
          break;
      }
    }

    // Branch could not be combined with a compare, compare against 0 and
    // branch.
    if (cont->IsBranch()) {
      Emit(cont->Encode(kArm64CompareAndBranch32), g.NoOutput(),
           g.UseRegister(value), g.Label(cont->true_block()),
           g.Label(cont->false_block()));
    } else {
      VisitCompare(this, cont->Encode(kArm64Tst32), g.UseRegister(value),
                   g.UseRegister(value), cont);
    }
  }
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWordCompareZero(
    node_t user, node_t value, FlagsContinuation* cont) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  Arm64OperandGeneratorT<TurboshaftAdapter> g(this);
  // Try to combine with comparisons against 0 by simply inverting the branch.
  ConsumeEqualZero(&user, &value, cont);

  // Remove Word64->Word32 truncation.
  if (this->is_truncate_word64_to_word32(value) && CanCover(user, value)) {
    user = value;
    value = this->remove_truncate_word64_to_word32(value);
  }

  // Try to match bit checks to create TBZ/TBNZ instructions.
  // Unlike the switch below, CanCover check is not needed here.
  // If there are several uses of the given operation, we will generate a TBZ
  // instruction for each. This is useful even if there are other uses of the
  // arithmetic result, because it moves dependencies further back.
  const Operation& value_op = Get(value);

  if (cont->IsBranch()) {
    if (value_op.Is<Opmask::kWord64Equal>()) {
      const ComparisonOp& equal = value_op.Cast<ComparisonOp>();
      if (MatchIntegralZero(equal.right())) {
        const WordBinopOp* left_binop =
            Get(equal.left()).TryCast<WordBinopOp>();
        if (left_binop) {
          TestAndBranchMatcherTurboshaft matcher(this, *left_binop);
          if (matcher.Matches()) {
            // If the mask has only one bit set, we can use tbz/tbnz.
            DCHECK((cont->condition() == kEqual) ||
                   (cont->condition() == kNotEqual));
            Arm64OperandGeneratorT<TurboshaftAdapter> gen(this);
            cont->OverwriteAndNegateIfEqual(kEqual);
            EmitWithContinuation(kArm64TestAndBranch,
                                 gen.UseRegister(left_binop->left()),
                                 gen.TempImmediate(matcher.bit()), cont);
            return;
          }
        }
      }
    }

    if (const WordBinopOp* value_binop = value_op.TryCast<WordBinopOp>()) {
      TestAndBranchMatcherTurboshaft matcher(this, *value_binop);
      if (matcher.Matches()) {
        // If the mask has only one bit set, we can use tbz/tbnz.
        DCHECK((cont->condition() == kEqual) ||
               (cont->condition() == kNotEqual));
        InstructionCode opcode = value_binop->rep.MapTaggedToWord() ==
                                         RegisterRepresentation::Word32()
                                     ? kArm64TestAndBranch32
                                     : kArm64TestAndBranch;
        Arm64OperandGeneratorT<TurboshaftAdapter> gen(this);
        EmitWithContinuation(opcode, gen.UseRegister(value_binop->left()),
                             gen.TempImmediate(matcher.bit()), cont);
        return;
      }
    }
  }

  if (CanCover(user, value)) {
    if (const ComparisonOp* comparison = value_op.TryCast<ComparisonOp>()) {
      switch (comparison->rep.MapTaggedToWord().value()) {
        case RegisterRepresentation::Word32():
          cont->OverwriteAndNegateIfEqual(
              GetComparisonFlagCondition(*comparison));
          return VisitWord32Compare(this, value, cont);

        case RegisterRepresentation::Word64():
          cont->OverwriteAndNegateIfEqual(
              GetComparisonFlagCondition(*comparison));

          if (comparison->kind == ComparisonOp::Kind::kEqual) {
            const Operation& left_op = Get(comparison->left());
            if (MatchIntegralZero(comparison->right()) &&
                left_op.Is<Opmask::kWord64BitwiseAnd>() &&
                CanCover(value, comparison->left())) {
              return VisitWordCompare(this, comparison->left(), kArm64Tst, cont,
                                      kLogical64Imm);
            }
          }
          return VisitWordCompare(this, value, kArm64Cmp, cont, kArithmeticImm);

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
                return VisitBinop(this, node, binop->rep,
                                  is64 ? kArm64Add : kArm64Add32,
                                  kArithmeticImm, cont);
              case OverflowCheckedBinopOp::Kind::kSignedSub:
                cont->OverwriteAndNegateIfEqual(kOverflow);
                return VisitBinop(this, node, binop->rep,
                                  is64 ? kArm64Sub : kArm64Sub32,
                                  kArithmeticImm, cont);
              case OverflowCheckedBinopOp::Kind::kSignedMul:
                if (is64) {
                  // ARM64 doesn't set the overflow flag for multiplication, so
                  // we need to test on kNotEqual. Here is the code sequence
                  // used:
                  //   mul result, left, right
                  //   smulh high, left, right
                  //   cmp high, result, asr 63
                  cont->OverwriteAndNegateIfEqual(kNotEqual);
                  return EmitInt64MulWithOverflow(this, node, cont);
                } else {
                  // ARM64 doesn't set the overflow flag for multiplication, so
                  // we need to test on kNotEqual. Here is the code sequence
                  // used:
                  //   smull result, left, right
                  //   cmp result.X(), Operand(result, SXTW)
                  cont->OverwriteAndNegateIfEqual(kNotEqual);
                  return EmitInt32MulWithOverflow(this, node, cont);
                }
            }
          }
        }
      }
    } else if (value_op.Is<Opmask::kWord32Add>()) {
      return VisitWordCompare(this, value, kArm64Cmn32, cont, kArithmeticImm);
    } else if (value_op.Is<Opmask::kWord32Sub>()) {
      return VisitWord32Compare(this, value, cont);
    } else if (value_op.Is<Opmask::kWord32BitwiseAnd>()) {
      if (TryMatchConditionalCompareChainBranch(this, zone(), value, cont)) {
        return;
      }
      return VisitWordCompare(this, value, kArm64Tst32, cont, kLogical32Imm);
    } else if (value_op.Is<Opmask::kWord64BitwiseAnd>()) {
      return VisitWordCompare(this, value, kArm64Tst, cont, kLogical64Imm);
    } else if (value_op.Is<Opmask::kWord32BitwiseOr>()) {
      if (TryMatchConditionalCompareChainBranch(this, zone(), value, cont)) {
        return;
      }
    } else if (value_op.Is<StackPointerGreaterThanOp>()) {
      cont->OverwriteAndNegateIfEqual(kStackPointerGreaterThanCondition);
      return VisitStackPointerGreaterThan(value, cont);
    }
  }

  // Branch could not be combined with a compare, compare against 0 and
  // branch.
  if (cont->IsBranch()) {
    Emit(cont->Encode(kArm64CompareAndBranch32), g.NoOutput(),
         g.UseRegister(value), g.Label(cont->true_block()),
         g.Label(cont->false_block()));
  } else {
    VisitCompare(this, cont->Encode(kArm64Tst32), g.UseRegister(value),
                 g.UseRegister(value), cont);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSwitch(node_t node,
                                                const SwitchInfo& sw) {
  Arm64OperandGeneratorT<Adapter> g(this);
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
        Emit(kArm64Sub32, index_operand, value_operand,
             g.TempImmediate(sw.min_value()));
      } else {
        // Smis top bits are undefined, so zero-extend if not already done so.
        if (!ZeroExtendsWord32ToWord64(this->input_at(node, 0))) {
          index_operand = g.TempRegister();
          Emit(kArm64Mov32, index_operand, value_operand);
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
void InstructionSelectorT<TurbofanAdapter>::VisitWord32Equal(node_t node) {
  {
    Node* const user = node;
    FlagsContinuation cont = FlagsContinuation::ForSet(kEqual, node);
    Int32BinopMatcher m(user);
    if (m.right().Is(0)) {
      Node* const value = m.left().node();
      if (CanCover(user, value)) {
        switch (value->opcode()) {
          case IrOpcode::kInt32Add:
          case IrOpcode::kWord32And:
            return VisitWord32Compare(this, node, &cont);
          case IrOpcode::kInt32Sub:
            return VisitWordCompare(this, value, kArm64Cmp32, &cont,
                                    kArithmeticImm);
          case IrOpcode::kWord32Equal: {
            // Word32Equal(Word32Equal(x, y), 0) => Word32Compare(x, y, ne).
            Int32BinopMatcher mequal(value);
            node->ReplaceInput(0, mequal.left().node());
            node->ReplaceInput(1, mequal.right().node());
            cont.Negate();
            // {node} still does not cover its new operands, because {mequal} is
            // still using them.
            // Since we won't generate any more code for {mequal}, set its
            // operands to zero to make sure {node} can cover them.
            // This improves pattern matching in VisitWord32Compare.
            mequal.node()->ReplaceInput(0, m.right().node());
            mequal.node()->ReplaceInput(1, m.right().node());
            return VisitWord32Compare(this, node, &cont);
          }
          default:
            break;
        }
        return VisitWord32Test(this, value, &cont);
      }
    }

    if (isolate() && (V8_STATIC_ROOTS_BOOL ||
                      (COMPRESS_POINTERS_BOOL && !isolate()->bootstrapper()))) {
      Arm64OperandGeneratorT<TurbofanAdapter> g(this);
      const RootsTable& roots_table = isolate()->roots_table();
      RootIndex root_index;
      Node* left = nullptr;
      Handle<HeapObject> right;
      // HeapConstants and CompressedHeapConstants can be treated the same when
      // using them as an input to a 32-bit comparison. Check whether either is
      // present.
      {
        CompressedHeapObjectBinopMatcher m(node);
        if (m.right().HasResolvedValue()) {
          left = m.left().node();
          right = m.right().ResolvedValue();
        } else {
          HeapObjectBinopMatcher m2(node);
          if (m2.right().HasResolvedValue()) {
            left = m2.left().node();
            right = m2.right().ResolvedValue();
          }
        }
      }
      if (!right.is_null() && roots_table.IsRootHandle(right, &root_index)) {
        DCHECK_NE(left, nullptr);
        if (RootsTable::IsReadOnly(root_index)) {
          Tagged_t ptr =
              MacroAssemblerBase::ReadOnlyRootPtr(root_index, isolate());
          if (g.CanBeImmediate(ptr, ImmediateMode::kArithmeticImm)) {
            return VisitCompare(this, kArm64Cmp32, g.UseRegister(left),
                                g.TempImmediate(ptr), &cont);
          }
        }
      }
    }

    VisitWord32Compare(this, node, &cont);
  }
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord32Equal(node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const Operation& equal = Get(node);
  DCHECK(equal.Is<ComparisonOp>());
  OpIndex left = equal.input(0);
  OpIndex right = equal.input(1);
  OpIndex user = node;
  FlagsContinuation cont = FlagsContinuation::ForSet(kEqual, node);

  if (MatchZero(right)) {
    OpIndex value = left;
    if (CanCover(user, value)) {
      const Operation& value_op = Get(value);
      if (value_op.Is<Opmask::kWord32Add>() ||
          value_op.Is<Opmask::kWord32BitwiseAnd>()) {
        return VisitWord32Compare(this, node, &cont);
      }
      if (value_op.Is<Opmask::kWord32Sub>()) {
        return VisitWordCompare(this, value, kArm64Cmp32, &cont,
                                kArithmeticImm);
      }
      if (value_op.Is<Opmask::kWord32Equal>()) {
        // Word32Equal(Word32Equal(x, y), 0) => Word32Compare(x, y, ne).
        // A new FlagsContinuation is needed as instead of generating the result
        // for {node}, it is generated for {value}.
        FlagsContinuation cont = FlagsContinuation::ForSet(kEqual, value);
        cont.Negate();
        VisitWord32Compare(this, value, &cont);
        EmitIdentity(node);
        return;
      }
      return VisitWord32Test(this, value, &cont);
    }
  }

  if (isolate() && (V8_STATIC_ROOTS_BOOL ||
                    (COMPRESS_POINTERS_BOOL && !isolate()->bootstrapper()))) {
    Arm64OperandGeneratorT<TurboshaftAdapter> g(this);
    const RootsTable& roots_table = isolate()->roots_table();
    RootIndex root_index;
    Handle<HeapObject> right;
    // HeapConstants and CompressedHeapConstants can be treated the same when
    // using them as an input to a 32-bit comparison. Check whether either is
    // present.
    if (MatchHeapConstant(node, &right) && !right.is_null() &&
        roots_table.IsRootHandle(right, &root_index)) {
      if (RootsTable::IsReadOnly(root_index)) {
        Tagged_t ptr =
            MacroAssemblerBase::ReadOnlyRootPtr(root_index, isolate());
        if (g.CanBeImmediate(ptr, ImmediateMode::kArithmeticImm)) {
          return VisitCompare(this, kArm64Cmp32, g.UseRegister(left),
                              g.TempImmediate(ptr), &cont);
        }
      }
    }
  }
  VisitWord32Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32LessThan(node_t node) {
  FlagsContinuation cont = FlagsContinuation::ForSet(kSignedLessThan, node);
  VisitWord32Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32LessThanOrEqual(node_t node) {
  FlagsContinuation cont =
      FlagsContinuation::ForSet(kSignedLessThanOrEqual, node);
  VisitWord32Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint32LessThan(node_t node) {
  FlagsContinuation cont = FlagsContinuation::ForSet(kUnsignedLessThan, node);
  VisitWord32Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint32LessThanOrEqual(node_t node) {
  FlagsContinuation cont =
      FlagsContinuation::ForSet(kUnsignedLessThanOrEqual, node);
  VisitWord32Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Equal(node_t node) {
  FlagsContinuation cont = FlagsContinuation::ForSet(kEqual, node);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const ComparisonOp& equal = this->Get(node).template Cast<ComparisonOp>();
    DCHECK_EQ(equal.kind, ComparisonOp::Kind::kEqual);
    if (this->MatchIntegralZero(equal.right()) &&
        CanCover(node, equal.left())) {
      if (this->Get(equal.left()).template Is<Opmask::kWord64BitwiseAnd>()) {
        return VisitWordCompare(this, equal.left(), kArm64Tst, &cont,
                                kLogical64Imm);
      }
      return VisitWord64Test(this, equal.left(), &cont);
    }
    VisitWordCompare(this, node, kArm64Cmp, &cont, kArithmeticImm);
  } else {
    Node* const user = node;
    Int64BinopMatcher m(user);
    if (m.right().Is(0)) {
      Node* const value = m.left().node();
      if (CanCover(user, value)) {
        switch (value->opcode()) {
          case IrOpcode::kWord64And:
            return VisitWordCompare(this, value, kArm64Tst, &cont,
                                    kLogical64Imm);
          default:
            break;
        }
        return VisitWord64Test(this, value, &cont);
      }
    }
    VisitWordCompare(this, node, kArm64Cmp, &cont, kArithmeticImm);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32AddWithOverflow(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    OpIndex ovf = FindProjection(node, 1);
    if (ovf.valid() && IsUsed(ovf)) {
      FlagsContinuation cont = FlagsContinuation::ForSet(kOverflow, ovf);
      return VisitBinop(this, node, RegisterRepresentation::Word32(),
                        kArm64Add32, kArithmeticImm, &cont);
    }
    FlagsContinuation cont;
    VisitBinop(this, node, RegisterRepresentation::Word32(), kArm64Add32,
               kArithmeticImm, &cont);
  } else {
    if (Node* ovf = NodeProperties::FindProjection(node, 1)) {
      FlagsContinuation cont = FlagsContinuation::ForSet(kOverflow, ovf);
      return VisitBinop<Adapter, Int32BinopMatcher>(this, node, kArm64Add32,
                                                    kArithmeticImm, &cont);
    }
    FlagsContinuation cont;
    VisitBinop<Adapter, Int32BinopMatcher>(this, node, kArm64Add32,
                                           kArithmeticImm, &cont);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32SubWithOverflow(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    OpIndex ovf = FindProjection(node, 1);
    if (ovf.valid()) {
      FlagsContinuation cont = FlagsContinuation::ForSet(kOverflow, ovf);
      return VisitBinop(this, node, RegisterRepresentation::Word32(),
                        kArm64Sub32, kArithmeticImm, &cont);
    }
    FlagsContinuation cont;
    VisitBinop(this, node, RegisterRepresentation::Word32(), kArm64Sub32,
               kArithmeticImm, &cont);
  } else {
    if (Node* ovf = NodeProperties::FindProjection(node, 1)) {
      FlagsContinuation cont = FlagsContinuation::ForSet(kOverflow, ovf);
      return VisitBinop<Adapter, Int32BinopMatcher>(this, node, kArm64Sub32,
                                                    kArithmeticImm, &cont);
    }
    FlagsContinuation cont;
    VisitBinop<Adapter, Int32BinopMatcher>(this, node, kArm64Sub32,
                                           kArithmeticImm, &cont);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32MulWithOverflow(node_t node) {
  node_t ovf = FindProjection(node, 1);
  if (this->valid(ovf)) {
    // ARM64 doesn't set the overflow flag for multiplication, so we need to
    // test on kNotEqual. Here is the code sequence used:
    //   smull result, left, right
    //   cmp result.X(), Operand(result, SXTW)
    FlagsContinuation cont = FlagsContinuation::ForSet(kNotEqual, ovf);
    return EmitInt32MulWithOverflow(this, node, &cont);
  }
  FlagsContinuation cont;
  EmitInt32MulWithOverflow(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64AddWithOverflow(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    OpIndex ovf = FindProjection(node, 1);
    if (ovf.valid()) {
      FlagsContinuation cont = FlagsContinuation::ForSet(kOverflow, ovf);
      return VisitBinop(this, node, RegisterRepresentation::Word64(), kArm64Add,
                        kArithmeticImm, &cont);
    }
    FlagsContinuation cont;
    VisitBinop(this, node, RegisterRepresentation::Word64(), kArm64Add,
               kArithmeticImm, &cont);
  } else {
    if (Node* ovf = NodeProperties::FindProjection(node, 1)) {
      FlagsContinuation cont = FlagsContinuation::ForSet(kOverflow, ovf);
      return VisitBinop<Adapter, Int64BinopMatcher>(this, node, kArm64Add,
                                                    kArithmeticImm, &cont);
    }
    FlagsContinuation cont;
    VisitBinop<Adapter, Int64BinopMatcher>(this, node, kArm64Add,
                                           kArithmeticImm, &cont);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64SubWithOverflow(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    OpIndex ovf = FindProjection(node, 1);
    if (ovf.valid()) {
      FlagsContinuation cont = FlagsContinuation::ForSet(kOverflow, ovf);
      return VisitBinop(this, node, RegisterRepresentation::Word64(), kArm64Sub,
                        kArithmeticImm, &cont);
    }
    FlagsContinuation cont;
    VisitBinop(this, node, RegisterRepresentation::Word64(), kArm64Sub,
               kArithmeticImm, &cont);
  } else {
    if (Node* ovf = NodeProperties::FindProjection(node, 1)) {
      FlagsContinuation cont = FlagsContinuation::ForSet(kOverflow, ovf);
      return VisitBinop<Adapter, Int64BinopMatcher>(this, node, kArm64Sub,
                                                    kArithmeticImm, &cont);
    }
    FlagsContinuation cont;
    VisitBinop<Adapter, Int64BinopMatcher>(this, node, kArm64Sub,
                                           kArithmeticImm, &cont);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64MulWithOverflow(node_t node) {
  node_t ovf = FindProjection(node, 1);
  if (this->valid(ovf)) {
    // ARM64 doesn't set the overflow flag for multiplication, so we need to
    // test on kNotEqual. Here is the code sequence used:
    //   mul result, left, right
    //   smulh high, left, right
    //   cmp high, result, asr 63
    FlagsContinuation cont = FlagsContinuation::ForSet(kNotEqual, ovf);
    return EmitInt64MulWithOverflow(this, node, &cont);
  }
  FlagsContinuation cont;
  EmitInt64MulWithOverflow(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64LessThan(node_t node) {
  FlagsContinuation cont = FlagsContinuation::ForSet(kSignedLessThan, node);
  VisitWordCompare(this, node, kArm64Cmp, &cont, kArithmeticImm);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64LessThanOrEqual(node_t node) {
  FlagsContinuation cont =
      FlagsContinuation::ForSet(kSignedLessThanOrEqual, node);
  VisitWordCompare(this, node, kArm64Cmp, &cont, kArithmeticImm);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint64LessThan(node_t node) {
  FlagsContinuation cont = FlagsContinuation::ForSet(kUnsignedLessThan, node);
  VisitWordCompare(this, node, kArm64Cmp, &cont, kArithmeticImm);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint64LessThanOrEqual(node_t node) {
  FlagsContinuation cont =
      FlagsContinuation::ForSet(kUnsignedLessThanOrEqual, node);
  VisitWordCompare(this, node, kArm64Cmp, &cont, kArithmeticImm);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Neg(node_t node) {
  Arm64OperandGeneratorT<Adapter> g(this);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    OpIndex input = this->Get(node).input(0);
    const Operation& input_op = this->Get(input);
    if (input_op.Is<Opmask::kFloat32Mul>() && CanCover(node, input)) {
      const FloatBinopOp& mul = input_op.Cast<FloatBinopOp>();
      Emit(kArm64Float32Fnmul, g.DefineAsRegister(node),
           g.UseRegister(mul.left()), g.UseRegister(mul.right()));
      return;
    }
    VisitRR(this, kArm64Float32Neg, node);

  } else {
    Node* in = node->InputAt(0);
    if (in->opcode() == IrOpcode::kFloat32Mul && CanCover(node, in)) {
      Float32BinopMatcher m(in);
      Emit(kArm64Float32Fnmul, g.DefineAsRegister(node),
           g.UseRegister(m.left().node()), g.UseRegister(m.right().node()));
      return;
    }
    VisitRR(this, kArm64Float32Neg, node);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Mul(node_t node) {
  Arm64OperandGeneratorT<Adapter> g(this);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const FloatBinopOp& mul = this->Get(node).template Cast<FloatBinopOp>();
    const Operation& lhs = this->Get(mul.left());

    if (lhs.Is<Opmask::kFloat32Negate>() && CanCover(node, mul.left())) {
      Emit(kArm64Float32Fnmul, g.DefineAsRegister(node),
           g.UseRegister(lhs.input(0)), g.UseRegister(mul.right()));
      return;
    }

    const Operation& rhs = this->Get(mul.right());
    if (rhs.Is<Opmask::kFloat32Negate>() && CanCover(node, mul.right())) {
      Emit(kArm64Float32Fnmul, g.DefineAsRegister(node),
           g.UseRegister(rhs.input(0)), g.UseRegister(mul.left()));
      return;
    }
    return VisitRRR(this, kArm64Float32Mul, node);

  } else {
    Arm64OperandGeneratorT<Adapter> g(this);
    Float32BinopMatcher m(node);

    if (m.left().IsFloat32Neg() && CanCover(node, m.left().node())) {
      Emit(kArm64Float32Fnmul, g.DefineAsRegister(node),
           g.UseRegister(m.left().node()->InputAt(0)),
           g.UseRegister(m.right().node()));
      return;
    }

    if (m.right().IsFloat32Neg() && CanCover(node, m.right().node())) {
      Emit(kArm64Float32Fnmul, g.DefineAsRegister(node),
           g.UseRegister(m.right().node()->InputAt(0)),
           g.UseRegister(m.left().node()));
      return;
    }
    return VisitRRR(this, kArm64Float32Mul, node);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Abs(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    Arm64OperandGeneratorT<Adapter> g(this);
    using namespace turboshaft;  // NOLINT(build/namespaces)
    OpIndex in = this->input_at(node, 0);
    const Operation& input_op = this->Get(in);
    if (input_op.Is<Opmask::kFloat32Sub>() && CanCover(node, in)) {
      const FloatBinopOp& sub = input_op.Cast<FloatBinopOp>();
      Emit(kArm64Float32Abd, g.DefineAsRegister(node),
           g.UseRegister(sub.left()), g.UseRegister(sub.right()));
      return;
    }

    return VisitRR(this, kArm64Float32Abs, node);
  } else {
    Arm64OperandGeneratorT<Adapter> g(this);
    Node* in = node->InputAt(0);
    if (in->opcode() == IrOpcode::kFloat32Sub && CanCover(node, in)) {
      Emit(kArm64Float32Abd, g.DefineAsRegister(node),
           g.UseRegister(in->InputAt(0)), g.UseRegister(in->InputAt(1)));
      return;
    }

    return VisitRR(this, kArm64Float32Abs, node);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Abs(node_t node) {
  Arm64OperandGeneratorT<Adapter> g(this);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    OpIndex in = this->input_at(node, 0);
    const Operation& input_op = this->Get(in);
    if (input_op.Is<Opmask::kFloat64Sub>() && CanCover(node, in)) {
      const FloatBinopOp& sub = input_op.Cast<FloatBinopOp>();
      Emit(kArm64Float64Abd, g.DefineAsRegister(node),
           g.UseRegister(sub.left()), g.UseRegister(sub.right()));
      return;
    }

    return VisitRR(this, kArm64Float64Abs, node);
  } else {
    Node* in = node->InputAt(0);
    if (in->opcode() == IrOpcode::kFloat64Sub && CanCover(node, in)) {
      Emit(kArm64Float64Abd, g.DefineAsRegister(node),
           g.UseRegister(in->InputAt(0)), g.UseRegister(in->InputAt(1)));
      return;
    }

    return VisitRR(this, kArm64Float64Abs, node);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Equal(node_t node) {
  FlagsContinuation cont = FlagsContinuation::ForSet(kEqual, node);
  VisitFloat32Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32LessThan(node_t node) {
  FlagsContinuation cont = FlagsContinuation::ForSet(kFloatLessThan, node);
  VisitFloat32Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32LessThanOrEqual(node_t node) {
  FlagsContinuation cont =
      FlagsContinuation::ForSet(kFloatLessThanOrEqual, node);
  VisitFloat32Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Equal(node_t node) {
  FlagsContinuation cont = FlagsContinuation::ForSet(kEqual, node);
  VisitFloat64Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64LessThan(node_t node) {
  FlagsContinuation cont = FlagsContinuation::ForSet(kFloatLessThan, node);
  VisitFloat64Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64LessThanOrEqual(node_t node) {
  FlagsContinuation cont =
      FlagsContinuation::ForSet(kFloatLessThanOrEqual, node);
  VisitFloat64Compare(this, node, &cont);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitBitcastWord32PairToFloat64(
    node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  Arm64OperandGeneratorT<TurboshaftAdapter> g(this);
  const auto& bitcast = this->Cast<BitcastWord32PairToFloat64Op>(node);
  node_t hi = bitcast.high_word32();
  node_t lo = bitcast.low_word32();

  int vreg = g.AllocateVirtualRegister();
  Emit(kArm64Bfi, g.DefineSameAsFirstForVreg(vreg), g.UseRegister(lo),
       g.UseRegister(hi), g.TempImmediate(32), g.TempImmediate(32));
  Emit(kArm64Float64MoveU64, g.DefineAsRegister(node),
       g.UseRegisterForVreg(vreg));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64InsertLowWord32(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    UNIMPLEMENTED();
  } else {
    Arm64OperandGeneratorT<Adapter> g(this);
    Node* left = node->InputAt(0);
    Node* right = node->InputAt(1);
    if (left->opcode() == IrOpcode::kFloat64InsertHighWord32 &&
        CanCover(node, left)) {
```