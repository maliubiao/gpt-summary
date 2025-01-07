Response:
My thought process to answer the request goes like this:

1. **Understand the Goal:** The user wants a summary of the provided C++ code snippet, specifically functions within the `InstructionSelectorT` template class for the ARM64 architecture in V8. The summary should cover functionality, potential JavaScript relations, code logic, user errors, and be part 6 of an 11-part series.

2. **Initial Code Scan (High-Level):** I quickly read through the function names and their basic structures. I see functions like `VisitUint32MulHigh`, `VisitTruncateFloat32ToInt32`, `VisitTryTruncateFloat64ToInt64`, `VisitChangeInt32ToInt64`, `VisitChangeUint32ToUint64`, and comparison/branching related functions. This gives me a general idea that the code is about translating high-level operations into specific ARM64 instructions.

3. **Categorize Functionality:** I start grouping the functions based on the operations they perform:
    * **Multiplication:** `VisitUint32MulHigh`, `VisitUint64MulHigh`
    * **Type Conversion (Truncation):** `VisitTruncateFloat32ToInt32`, `VisitTruncateFloat32ToUint32`, `VisitTryTruncateFloat32ToInt64`, `VisitTruncateFloat64ToInt64`, `VisitTryTruncateFloat64ToInt64`, `VisitTruncateFloat64ToFloat16RawBits`, `VisitTryTruncateFloat32ToUint64`, `VisitTryTruncateFloat64ToUint64`, `VisitTryTruncateFloat64ToInt32`, `VisitTryTruncateFloat64ToUint32`, `VisitTruncateInt64ToInt32`
    * **Type Conversion (Extension/Bitcast):** `VisitBitcastWord32ToWord64`, `VisitChangeInt32ToInt64`, `VisitChangeUint32ToUint64`
    * **Floating-Point Arithmetic:** `VisitFloat64Mod`, `VisitFloat64Ieee754Binop`, `VisitFloat64Ieee754Unop`
    * **Function Call Handling:** `EmitMoveParamToFPR`, `EmitMoveFPRToParam`, `EmitPrepareArguments`, `EmitPrepareResults`, `IsTailCallAddressImmediate`
    * **Comparison and Branching:** `VisitCompare`, `VisitWordCompare`, `TryEmitCbzOrTbz`, `EmitBranchOrDeoptimize`

4. **Detailed Function Analysis:** I go through each function more carefully, noting:
    * **Purpose:** What operation does it perform?
    * **Input/Output:** What kind of data does it take and produce (registers, immediate values)?
    * **ARM64 Instructions:** Which specific ARM64 instructions are being emitted (e.g., `kArm64Smulh`, `kArm64Umull`, `kArm64Lsr`, `kArm64Float32ToInt32`, etc.)?
    * **Turboshaft vs. Turbofan:**  I notice the `if constexpr (Adapter::IsTurboshaft)` blocks, indicating different handling for V8's two compilers. This is an important detail.
    * **Helper Functions:** I see calls to helper functions like `VisitRRR`, `Emit`, `EmitLoad`, `EmitIdentity`, `FindProjection`, `CanCover`, `IsOnlyUserOfNodeInSameBlock`, etc. I don't need to detail these internally, but acknowledge their existence.
    * **FlagsContinuation:** For the comparison functions, I pay attention to the `FlagsContinuationT` and how it's used to handle conditional execution.

5. **JavaScript Relationship (Conceptual):** I consider how these low-level operations relate to JavaScript. For instance:
    * Multiplication in JavaScript corresponds to the `*` operator.
    * Type conversions like `parseInt()` or bitwise operations relate to the truncation and bit manipulation functions.
    * Function calls in JavaScript involve passing arguments and receiving results, which the `EmitPrepareArguments` and `EmitPrepareResults` functions handle.
    * Conditional statements (`if`, `else`) rely on comparisons and branching.

6. **Code Logic and Assumptions:** For functions with more complex logic (like `VisitChangeInt32ToInt64` and the comparison functions), I try to understand the conditions under which specific instructions are chosen. For example, the `VisitChangeInt32ToInt64` function checks for `LoadOp` and `Word32Sar` to optimize instruction selection. The comparison functions have logic to potentially replace a `cmp 0` with a flag-setting arithmetic instruction. I formulate potential inputs and outputs to illustrate this.

7. **Common Programming Errors:** I think about common mistakes JavaScript developers might make that would trigger these operations. For example:
    * Incorrectly assuming integer overflow behavior.
    * Not understanding floating-point truncation.
    * Issues with bitwise operations and sign extension.

8. **Torque Consideration:** I note the beginning of the request about the `.tq` extension and confirm that this file is C++, not Torque.

9. **Part 6 Summary and Context:**  I emphasize that this is part of a larger process of instruction selection for ARM64 within the V8 compiler. The functions convert intermediate representations into machine code.

10. **Structure and Refinement:** I organize the information logically, using headings and bullet points for clarity. I refine the language to be precise and easy to understand. I ensure I address all parts of the user's request.

**Self-Correction/Refinement During the Process:**

* **Initially, I might focus too much on individual instruction details.** I realize I need to provide a higher-level summary of the *functionality* rather than just listing all the ARM64 instructions.
* **I need to make the JavaScript examples more concrete.** Instead of just saying "type conversion," I use `parseInt()` as a more relatable example.
* **The "code logic" section needs to have clear assumptions and examples.**  I ensure I explain *why* a certain instruction might be chosen based on the input.
* **I need to explicitly address the "part 6" aspect and how it fits into the overall instruction selection process.**

By following this iterative process of understanding, categorizing, analyzing, and refining, I can construct a comprehensive and accurate answer to the user's request.
好的，让我们来分析一下这段 C++ 代码的功能。

**核心功能归纳：**

这段代码是 V8 引擎中 ARM64 架构的指令选择器（Instruction Selector）的一部分。它的主要职责是将中间表示（Intermediate Representation - IR）中的节点（node）转换为具体的 ARM64 汇编指令。

**具体功能分解：**

这段代码包含了多个模板化的成员函数，这些函数对应着不同的 IR 节点类型，并负责为这些节点生成相应的 ARM64 指令。以下是每个函数的功能总结：

* **算术运算 (高位乘法)：**
    * `VisitInt32MulHigh`: 生成带符号 32 位整数乘法的高 32 位结果的指令 (`kArm64Smulh`)。
    * `VisitUint32MulHigh`: 生成无符号 32 位整数乘法的高 32 位结果的指令。它使用了 `kArm64Umull` 指令计算完整的 64 位乘积，然后使用 `kArm64Lsr` 指令右移 32 位来获取高 32 位。
    * `VisitUint64MulHigh`: 生成无符号 64 位整数乘法的高 64 位结果的指令 (`kArm64Umulh`)。

* **浮点数到整数的截断：**
    * `VisitTruncateFloat32ToInt32`: 将 32 位浮点数截断为 32 位有符号整数。根据是否需要处理溢出（设置为最小值），生成不同的 `kArm64Float32ToInt32` 指令变体。
    * `VisitTruncateFloat32ToUint32`: 将 32 位浮点数截断为 32 位无符号整数。同样根据溢出处理生成不同的 `kArm64Float32ToUint32` 指令变体。
    * `VisitTryTruncateFloat32ToInt64`: 尝试将 32 位浮点数截断为 64 位有符号整数。如果截断成功，会设置一个标志。使用 `kArm64Float32ToInt64` 指令。
    * `VisitTruncateFloat64ToInt64`: 将 64 位浮点数截断为 64 位有符号整数。根据溢出处理生成不同的 `kArm64Float64ToInt64` 指令变体。
    * `VisitTryTruncateFloat64ToInt64`: 尝试将 64 位浮点数截断为 64 位有符号整数。使用 `kArm64Float64ToInt64` 指令。
    * `VisitTruncateFloat64ToFloat16RawBits`: 将 64 位浮点数截断为 16 位浮点数 (raw bits)。使用 `kArm64Float64ToFloat16RawBits` 指令。
    * `VisitTryTruncateFloat32ToUint64`: 尝试将 32 位浮点数截断为 64 位无符号整数。使用 `kArm64Float32ToUint64` 指令。
    * `VisitTryTruncateFloat64ToUint64`: 尝试将 64 位浮点数截断为 64 位无符号整数。使用 `kArm64Float64ToUint64` 指令。
    * `VisitTryTruncateFloat64ToInt32`: 尝试将 64 位浮点数截断为 32 位有符号整数。使用 `kArm64Float64ToInt32` 指令。
    * `VisitTryTruncateFloat64ToUint32`: 尝试将 64 位浮点数截断为 32 位无符号整数。使用 `kArm64Float64ToUint32` 指令。

* **类型转换和位操作：**
    * `VisitBitcastWord32ToWord64`: 将 32 位字按位转换为 64 位字。在 ARM64 上，如果 `SmiValuesAre31Bits()` 和 `COMPRESS_POINTERS_BOOL` 为真，则可以直接使用原值 (`EmitIdentity`)，因为低 32 位相同。
    * `VisitChangeInt32ToInt64`: 将 32 位有符号整数转换为 64 位有符号整数（符号扩展）。它会尝试优化，如果输入是加载指令，则生成带符号扩展的加载指令（例如 `kArm64Ldrsb`, `kArm64Ldrsh`, `kArm64Ldrsw`）。如果输入是带符号右移指令 (`kWord32Sar`) 且移位量是常量，则生成 `kArm64Sbfx` 指令。否则，使用 `kArm64Sxtw` 指令进行符号扩展。
    * `VisitChangeUint32ToUint64`: 将 32 位无符号整数转换为 64 位无符号整数（零扩展）。如果输入节点的操作本身就会进行零扩展（例如 32 位算术运算的结果），则直接使用原值 (`EmitIdentity`)，否则使用 `kArm64Mov32` 指令。
    * `VisitTruncateInt64ToInt32`: 将 64 位整数截断为 32 位整数。由于 ARM64 的 32 位操作会隐式清除高 32 位，因此可以直接使用原值 (`EmitIdentity`)。

* **浮点数运算：**
    * `VisitFloat64Mod`: 计算 64 位浮点数的模。使用 `kArm64Float64Mod` 指令，并标记为调用 (MarkAsCall)。
    * `VisitFloat64Ieee754Binop`: 处理 IEEE 754 标准的 64 位浮点数二元运算。使用传入的 `opcode` 指令，并标记为调用。
    * `VisitFloat64Ieee754Unop`: 处理 IEEE 754 标准的 64 位浮点数一元运算。使用传入的 `opcode` 指令，并标记为调用。

* **函数调用相关的操作：**
    * `EmitMoveParamToFPR`: 将参数移动到浮点寄存器。这个函数在提供的代码片段中是空的，可能在其他部分有实现。
    * `EmitMoveFPRToParam`: 将浮点寄存器的值移动到参数位置。这个函数在提供的代码片段中是空的，可能在其他部分有实现。
    * `EmitPrepareArguments`:  为函数调用准备参数。它将参数从 IR 节点推送到栈上，并处理对齐。使用了 `kArm64Claim` (分配栈空间) 和 `kArm64Poke`/`kArm64PokePair` (将参数放入栈中) 指令。
    * `EmitPrepareResults`: 为函数调用准备结果。它将函数调用的结果从栈中取出并赋值给相应的 IR 节点。使用了 `kArm64Peek` 指令。
    * `IsTailCallAddressImmediate`:  判断尾调用地址是否为立即数。在这个架构上返回 `false`。

* **比较和条件分支：**
    * `VisitCompare`: 处理比较操作。根据 `FlagsContinuationT` 的类型（选择或分支），生成不同的指令。如果是选择，则生成带有条件选择的指令；如果是分支，则生成设置标志的比较指令。
    * `VisitWordCompare`: 处理字（整数）的比较操作。它会尝试将立即数放在右侧，并根据情况选择不同的比较指令，例如 `kArm64Cmp`。如果比较的是常量 0，则会尝试优化为 `TryEmitCbzOrTbz`。
    * `TryEmitCbzOrTbz`: 尝试为特定的与零比较生成 `TBZ` (Test bit and branch if zero)、`TBNZ` (Test bit and branch if not zero)、`CBZ` (Compare and branch if zero) 或 `CBNZ` (Compare and branch if not zero) 指令。这是一种优化，可以基于单个位的状态进行条件分支。
    * `EmitBranchOrDeoptimize`:  生成条件分支或去优化的指令。

**关于 `.tq` 结尾：**

代码注释中提到，如果文件以 `.tq` 结尾，则它是 V8 Torque 源代码。然而，`v8/src/compiler/backend/arm64/instruction-selector-arm64.cc` 以 `.cc` 结尾，因此它是一个 **C++ 源代码**，而不是 Torque 源代码。Torque 是一种用于编写 V8 内部实现的领域特定语言，可以生成 C++ 代码。

**与 JavaScript 的功能关系：**

这段代码直接参与了 JavaScript 代码的执行过程。当 V8 引擎编译 JavaScript 代码时，它会将 JavaScript 代码转换为中间表示（IR）。指令选择器的作用就是将这些 IR 节点转换为目标架构（在这里是 ARM64）的机器指令。

以下 JavaScript 示例可以说明与部分功能的关系：

```javascript
// 整数运算
let a = 10;
let b = 5;
let high_mul = Math.imul(a, b); //  VisitInt32MulHigh 可能会参与

// 类型转换
let float_num = 3.14;
let int_num = parseInt(float_num); // VisitTruncateFloat32ToInt32 可能参与

// 浮点数运算
let x = 2.0;
let y = 1.0;
let remainder = x % y; // VisitFloat64Mod 参与

// 条件语句
let condition = a > b; // VisitCompare, VisitWordCompare 参与
if (condition) {
  console.log("a is greater than b");
}

// 函数调用
function myFunction(arg1, arg2) {
  return arg1 + arg2;
}
myFunction(1, 2); // EmitPrepareArguments, EmitPrepareResults 参与
```

**代码逻辑推理（假设输入与输出）：**

假设有一个 IR 节点 `node` 代表无符号 32 位整数乘法，其输入分别是两个表示常量 `10` 和 `20` 的 IR 节点。

**假设输入：**

* `node` 的类型为表示无符号 32 位整数乘法的操作。
* `this->input_at(node, 0)` 指向一个表示常量 `10` 的 IR 节点。
* `this->input_at(node, 1)` 指向一个表示常量 `20` 的 IR 节点。

**预期输出：**

`VisitUint32MulHigh` 函数会生成以下 ARM64 指令序列（简化表示）：

```assembly
umull  temp_reg, input_reg_0, input_reg_1  // 计算 10 * 20 的 64 位结果
lsr    output_reg, temp_reg, #32         // 将结果右移 32 位，获取高 32 位
```

其中 `temp_reg` 是一个临时寄存器，`input_reg_0` 和 `input_reg_1` 分别存储 `10` 和 `20`，`output_reg` 是 `node` 对应的输出寄存器。

**用户常见的编程错误举例：**

* **整数溢出：**  在 JavaScript 中，整数运算可能发生溢出，但 JavaScript 的行为与 C++ 不同。理解 V8 如何处理这些溢出（例如，通过 `VisitInt32MulHigh` 获取高位可能用于检测溢出）有助于理解引擎的行为。用户可能错误地假设 JavaScript 的整数运算永远不会溢出或以与 C++ 相同的方式溢出。

   ```javascript
   let maxInt = 2147483647;
   let result = maxInt + 1; // 在 JavaScript 中不会像 C++ 那样直接溢出到负数
   ```

* **浮点数精度问题：** 浮点数的截断和转换可能导致精度损失。用户可能没有意识到将浮点数转换为整数时会发生截断，而不是四舍五入。

   ```javascript
   let floatValue = 3.9;
   let intValue = parseInt(floatValue); // intValue 将是 3，而不是 4
   ```

* **位运算的误用：**  用户可能不理解有符号和无符号整数之间的差异，以及位运算在不同类型上的行为。例如，在进行右移操作时，有符号右移和无符号右移的结果可能不同。

   ```javascript
   let signedInt = -10;
   let unsignedRightShift = signedInt >>> 2; // 无符号右移
   let signedRightShift = signedInt >> 2;  // 有符号右移
   ```

**第 6 部分功能归纳：**

作为第 6 部分，这段代码继续实现了指令选择器的核心功能，专注于：

* **整数和浮点数的算术运算（特别是高位乘法）。**
* **浮点数到整数的各种截断操作，包括尝试截断的情况。**
* **基本的类型转换，例如 32 位到 64 位的转换，并尝试优化这些转换。**
* **处理浮点数的模运算以及一般的 IEEE 754 标准的浮点运算。**
* **函数调用前后的参数准备和结果处理。**
* **针对比较操作和条件分支的指令选择和优化（例如，尝试使用 `TBZ/TBNZ/CBZ/CBNZ`）。**

总的来说，这部分代码负责将一些重要的中间表示操作转换为高效的 ARM64 机器指令，是 V8 代码生成过程中的关键环节。

Prompt: 
```
这是目录为v8/src/compiler/backend/arm64/instruction-selector-arm64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/arm64/instruction-selector-arm64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第6部分，共11部分，请归纳一下它的功能

"""
e_t node) {
  return VisitRRR(this, kArm64Smulh, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint32MulHigh(node_t node) {
  Arm64OperandGeneratorT<Adapter> g(this);
  InstructionOperand const smull_operand = g.TempRegister();
  Emit(kArm64Umull, smull_operand, g.UseRegister(this->input_at(node, 0)),
       g.UseRegister(this->input_at(node, 1)));
  Emit(kArm64Lsr, g.DefineAsRegister(node), smull_operand, g.TempImmediate(32));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint64MulHigh(node_t node) {
  return VisitRRR(this, kArm64Umulh, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTruncateFloat32ToInt32(node_t node) {
  Arm64OperandGeneratorT<Adapter> g(this);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const Operation& op = this->Get(node);
    InstructionCode opcode = kArm64Float32ToInt32;
    opcode |= MiscField::encode(
        op.Is<Opmask::kTruncateFloat32ToInt32OverflowToMin>());
    Emit(opcode, g.DefineAsRegister(node),
         g.UseRegister(this->input_at(node, 0)));
  } else {
    InstructionCode opcode = kArm64Float32ToInt32;
    TruncateKind kind = OpParameter<TruncateKind>(node->op());
    opcode |= MiscField::encode(kind == TruncateKind::kSetOverflowToMin);
    Emit(opcode, g.DefineAsRegister(node), g.UseRegister(node->InputAt(0)));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTruncateFloat32ToUint32(node_t node) {
  Arm64OperandGeneratorT<Adapter> g(this);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const Operation& op = this->Get(node);
    InstructionCode opcode = kArm64Float32ToUint32;
    if (op.Is<Opmask::kTruncateFloat32ToUint32OverflowToMin>()) {
      opcode |= MiscField::encode(true);
    }

    Emit(opcode, g.DefineAsRegister(node),
         g.UseRegister(this->input_at(node, 0)));

  } else {
    InstructionCode opcode = kArm64Float32ToUint32;
    TruncateKind kind = OpParameter<TruncateKind>(node->op());
    if (kind == TruncateKind::kSetOverflowToMin) {
      opcode |= MiscField::encode(true);
    }

    Emit(opcode, g.DefineAsRegister(node), g.UseRegister(node->InputAt(0)));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTryTruncateFloat32ToInt64(
    node_t node) {
    Arm64OperandGeneratorT<Adapter> g(this);

    InstructionOperand inputs[] = {g.UseRegister(this->input_at(node, 0))};
    InstructionOperand outputs[2];
    size_t output_count = 0;
    outputs[output_count++] = g.DefineAsRegister(node);

    node_t success_output = FindProjection(node, 1);
    if (this->valid(success_output)) {
      outputs[output_count++] = g.DefineAsRegister(success_output);
    }

    Emit(kArm64Float32ToInt64, output_count, outputs, 1, inputs);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTruncateFloat64ToInt64(node_t node) {
  Arm64OperandGeneratorT<Adapter> g(this);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    InstructionCode opcode = kArm64Float64ToInt64;
    const Operation& op = this->Get(node);
    if (op.Is<Opmask::kTruncateFloat64ToInt64OverflowToMin>()) {
      opcode |= MiscField::encode(true);
    }

    Emit(opcode, g.DefineAsRegister(node), g.UseRegister(op.input(0)));
  } else {
    InstructionCode opcode = kArm64Float64ToInt64;
    TruncateKind kind = OpParameter<TruncateKind>(node->op());
    if (kind == TruncateKind::kSetOverflowToMin) {
      opcode |= MiscField::encode(true);
    }

    Emit(opcode, g.DefineAsRegister(node), g.UseRegister(node->InputAt(0)));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTryTruncateFloat64ToInt64(
    node_t node) {
  Arm64OperandGeneratorT<Adapter> g(this);

  InstructionOperand inputs[] = {g.UseRegister(this->input_at(node, 0))};
  InstructionOperand outputs[2];
  size_t output_count = 0;
  outputs[output_count++] = g.DefineAsRegister(node);

  node_t success_output = FindProjection(node, 1);
  if (this->valid(success_output)) {
    outputs[output_count++] = g.DefineAsRegister(success_output);
  }

  Emit(kArm64Float64ToInt64, output_count, outputs, 1, inputs);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTruncateFloat64ToFloat16RawBits(
    node_t node) {
  Arm64OperandGeneratorT<Adapter> g(this);
  InstructionOperand inputs[] = {g.UseRegister(this->input_at(node, 0))};
  InstructionOperand outputs[] = {g.DefineAsRegister(node)};
  InstructionOperand temps[] = {g.TempDoubleRegister()};
  Emit(kArm64Float64ToFloat16RawBits, arraysize(outputs), outputs,
       arraysize(inputs), inputs, arraysize(temps), temps);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTryTruncateFloat32ToUint64(
    node_t node) {
  Arm64OperandGeneratorT<Adapter> g(this);

  InstructionOperand inputs[] = {g.UseRegister(this->input_at(node, 0))};
  InstructionOperand outputs[2];
  size_t output_count = 0;
  outputs[output_count++] = g.DefineAsRegister(node);

  node_t success_output = FindProjection(node, 1);
  if (this->valid(success_output)) {
    outputs[output_count++] = g.DefineAsRegister(success_output);
  }

  Emit(kArm64Float32ToUint64, output_count, outputs, 1, inputs);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTryTruncateFloat64ToUint64(
    node_t node) {
  Arm64OperandGeneratorT<Adapter> g(this);

  InstructionOperand inputs[] = {g.UseRegister(this->input_at(node, 0))};
  InstructionOperand outputs[2];
  size_t output_count = 0;
  outputs[output_count++] = g.DefineAsRegister(node);

  node_t success_output = FindProjection(node, 1);
  if (this->valid(success_output)) {
    outputs[output_count++] = g.DefineAsRegister(success_output);
  }

  Emit(kArm64Float64ToUint64, output_count, outputs, 1, inputs);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTryTruncateFloat64ToInt32(
    node_t node) {
  Arm64OperandGeneratorT<Adapter> g(this);
  InstructionOperand inputs[] = {g.UseRegister(this->input_at(node, 0))};
  InstructionOperand outputs[2];
  size_t output_count = 0;
  outputs[output_count++] = g.DefineAsRegister(node);

  node_t success_output = FindProjection(node, 1);
  if (this->valid(success_output)) {
    outputs[output_count++] = g.DefineAsRegister(success_output);
  }

  Emit(kArm64Float64ToInt32, output_count, outputs, 1, inputs);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTryTruncateFloat64ToUint32(
    node_t node) {
  Arm64OperandGeneratorT<Adapter> g(this);
  InstructionOperand inputs[] = {g.UseRegister(this->input_at(node, 0))};
  InstructionOperand outputs[2];
  size_t output_count = 0;
  outputs[output_count++] = g.DefineAsRegister(node);

  node_t success_output = FindProjection(node, 1);
  if (this->valid(success_output)) {
    outputs[output_count++] = g.DefineAsRegister(success_output);
  }

  Emit(kArm64Float64ToUint32, output_count, outputs, 1, inputs);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitBitcastWord32ToWord64(node_t node) {
  DCHECK(SmiValuesAre31Bits());
  DCHECK(COMPRESS_POINTERS_BOOL);
  EmitIdentity(node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitChangeInt32ToInt64(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const ChangeOp& change_op = this->Get(node).template Cast<ChangeOp>();
    const Operation& input_op = this->Get(change_op.input());
    if (input_op.Is<LoadOp>() && CanCover(node, change_op.input())) {
      // Generate sign-extending load.
      LoadRepresentation load_rep =
          this->load_view(change_op.input()).loaded_rep();
      MachineRepresentation rep = load_rep.representation();
      InstructionCode opcode = kArchNop;
      ImmediateMode immediate_mode = kNoImmediate;
      switch (rep) {
        case MachineRepresentation::kBit:  // Fall through.
        case MachineRepresentation::kWord8:
          opcode = load_rep.IsSigned() ? kArm64Ldrsb : kArm64Ldrb;
          immediate_mode = kLoadStoreImm8;
          break;
        case MachineRepresentation::kWord16:
          opcode = load_rep.IsSigned() ? kArm64Ldrsh : kArm64Ldrh;
          immediate_mode = kLoadStoreImm16;
          break;
        case MachineRepresentation::kWord32:
        case MachineRepresentation::kWord64:
          // Since BitcastElider may remove nodes of
          // IrOpcode::kTruncateInt64ToInt32 and directly use the inputs, values
          // with kWord64 can also reach this line.
        case MachineRepresentation::kTaggedSigned:
        case MachineRepresentation::kTagged:
        case MachineRepresentation::kTaggedPointer:
          opcode = kArm64Ldrsw;
          immediate_mode = kLoadStoreImm32;
          break;
        default:
          UNREACHABLE();
      }
      EmitLoad(this, change_op.input(), opcode, immediate_mode, rep, node);
      return;
    }
    if ((input_op.Is<Opmask::kWord32ShiftRightArithmetic>() ||
         input_op.Is<Opmask::kWord32ShiftRightArithmeticShiftOutZeros>()) &&
        CanCover(node, change_op.input())) {
      const ShiftOp& sar = input_op.Cast<ShiftOp>();
      if (this->is_integer_constant(sar.right())) {
        Arm64OperandGeneratorT<Adapter> g(this);
        // Mask the shift amount, to keep the same semantics as Word32Sar.
        int right = this->integer_constant(sar.right()) & 0x1F;
        Emit(kArm64Sbfx, g.DefineAsRegister(node), g.UseRegister(sar.left()),
             g.TempImmediate(right), g.TempImmediate(32 - right));
        return;
      }
    }
    VisitRR(this, kArm64Sxtw, node);
  } else {
    Node* value = node->InputAt(0);
    if ((value->opcode() == IrOpcode::kLoad ||
         value->opcode() == IrOpcode::kLoadImmutable) &&
        CanCover(node, value)) {
      // Generate sign-extending load.
      LoadRepresentation load_rep = LoadRepresentationOf(value->op());
      MachineRepresentation rep = load_rep.representation();
      InstructionCode opcode = kArchNop;
      ImmediateMode immediate_mode = kNoImmediate;
      switch (rep) {
        case MachineRepresentation::kBit:  // Fall through.
        case MachineRepresentation::kWord8:
          opcode = load_rep.IsSigned() ? kArm64Ldrsb : kArm64Ldrb;
          immediate_mode = kLoadStoreImm8;
          break;
        case MachineRepresentation::kWord16:
          opcode = load_rep.IsSigned() ? kArm64Ldrsh : kArm64Ldrh;
          immediate_mode = kLoadStoreImm16;
          break;
        case MachineRepresentation::kWord32:
        case MachineRepresentation::kWord64:
          // Since BitcastElider may remove nodes of
          // IrOpcode::kTruncateInt64ToInt32 and directly use the inputs, values
          // with kWord64 can also reach this line.
        case MachineRepresentation::kTaggedSigned:
        case MachineRepresentation::kTagged:
        case MachineRepresentation::kTaggedPointer:
          opcode = kArm64Ldrsw;
          immediate_mode = kLoadStoreImm32;
          break;
        default:
          UNREACHABLE();
      }
      EmitLoad(this, value, opcode, immediate_mode, rep, node);
      return;
    }

    if (value->opcode() == IrOpcode::kWord32Sar && CanCover(node, value)) {
      Int32BinopMatcher m(value);
      if (m.right().HasResolvedValue()) {
        Arm64OperandGeneratorT<Adapter> g(this);
        // Mask the shift amount, to keep the same semantics as Word32Sar.
        int right = m.right().ResolvedValue() & 0x1F;
        Emit(kArm64Sbfx, g.DefineAsRegister(node),
             g.UseRegister(m.left().node()), g.TempImmediate(right),
             g.TempImmediate(32 - right));
        return;
      }
    }

    VisitRR(this, kArm64Sxtw, node);
  }
}
template <>
bool InstructionSelectorT<TurboshaftAdapter>::ZeroExtendsWord32ToWord64NoPhis(
    node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  DCHECK(!this->Get(node).Is<PhiOp>());
  const Operation& op = this->Get(node);
  // 32-bit operations will write their result in a W register (implicitly
  // clearing the top 32-bit of the corresponding X register) so the
  // zero-extension is a no-op.
  switch (op.opcode) {
    case Opcode::kWordBinop:
      return op.Cast<WordBinopOp>().rep == WordRepresentation::Word32();
    case Opcode::kShift:
      return op.Cast<ShiftOp>().rep == WordRepresentation::Word32();
    case Opcode::kComparison:
      return op.Cast<ComparisonOp>().rep == RegisterRepresentation::Word32();
    case Opcode::kOverflowCheckedBinop:
      return op.Cast<OverflowCheckedBinopOp>().rep ==
             WordRepresentation::Word32();
    case Opcode::kProjection:
      return ZeroExtendsWord32ToWord64NoPhis(op.Cast<ProjectionOp>().input());
    case Opcode::kLoad: {
      RegisterRepresentation rep =
          op.Cast<LoadOp>().loaded_rep.ToRegisterRepresentation();
      return rep == RegisterRepresentation::Word32();
    }
    default:
      return false;
  }
}

template <>
bool InstructionSelectorT<TurbofanAdapter>::ZeroExtendsWord32ToWord64NoPhis(
    Node* node) {
  DCHECK_NE(node->opcode(), IrOpcode::kPhi);
  switch (node->opcode()) {
    case IrOpcode::kWord32And:
    case IrOpcode::kWord32Or:
    case IrOpcode::kWord32Xor:
    case IrOpcode::kWord32Shl:
    case IrOpcode::kWord32Shr:
    case IrOpcode::kWord32Sar:
    case IrOpcode::kWord32Ror:
    case IrOpcode::kWord32Equal:
    case IrOpcode::kInt32Add:
    case IrOpcode::kInt32AddWithOverflow:
    case IrOpcode::kInt32Sub:
    case IrOpcode::kInt32SubWithOverflow:
    case IrOpcode::kInt32Mul:
    case IrOpcode::kInt32MulHigh:
    case IrOpcode::kInt32Div:
    case IrOpcode::kInt32Mod:
    case IrOpcode::kInt32LessThan:
    case IrOpcode::kInt32LessThanOrEqual:
    case IrOpcode::kUint32Div:
    case IrOpcode::kUint32LessThan:
    case IrOpcode::kUint32LessThanOrEqual:
    case IrOpcode::kUint32Mod:
    case IrOpcode::kUint32MulHigh: {
      // 32-bit operations will write their result in a W register (implicitly
      // clearing the top 32-bit of the corresponding X register) so the
      // zero-extension is a no-op.
      return true;
    }
    case IrOpcode::kLoad:
    case IrOpcode::kLoadImmutable: {
      // As for the operations above, a 32-bit load will implicitly clear the
      // top 32 bits of the destination register.
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
    default:
      return false;
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitChangeUint32ToUint64(node_t node) {
  Arm64OperandGeneratorT<Adapter> g(this);
  node_t value = this->input_at(node, 0);
  if (ZeroExtendsWord32ToWord64(value)) {
    return EmitIdentity(node);
  }
  Emit(kArm64Mov32, g.DefineAsRegister(node), g.UseRegister(value));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTruncateInt64ToInt32(node_t node) {
  Arm64OperandGeneratorT<Adapter> g(this);
  // The top 32 bits in the 64-bit register will be undefined, and
  // must not be used by a dependent node.
  EmitIdentity(node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Mod(node_t node) {
  Arm64OperandGeneratorT<Adapter> g(this);
  Emit(kArm64Float64Mod, g.DefineAsFixed(node, d0),
       g.UseFixed(this->input_at(node, 0), d0),
       g.UseFixed(this->input_at(node, 1), d1))
      ->MarkAsCall();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Ieee754Binop(
    node_t node, InstructionCode opcode) {
  Arm64OperandGeneratorT<Adapter> g(this);
  Emit(opcode, g.DefineAsFixed(node, d0),
       g.UseFixed(this->input_at(node, 0), d0),
       g.UseFixed(this->input_at(node, 1), d1))
      ->MarkAsCall();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Ieee754Unop(
    node_t node, InstructionCode opcode) {
  Arm64OperandGeneratorT<Adapter> g(this);
  Emit(opcode, g.DefineAsFixed(node, d0),
       g.UseFixed(this->input_at(node, 0), d0))
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
  Arm64OperandGeneratorT<Adapter> g(this);

  // `arguments` includes alignment "holes". This means that slots bigger than
  // kSystemPointerSize, e.g. Simd128, will span across multiple arguments.
  int claim_count = static_cast<int>(arguments->size());
  bool needs_padding = claim_count % 2 != 0;
  int slot = claim_count - 1;
  claim_count = RoundUp(claim_count, 2);
  // Bump the stack pointer.
  if (claim_count > 0) {
    // TODO(titzer): claim and poke probably take small immediates.
    // TODO(titzer): it would be better to bump the sp here only
    //               and emit paired stores with increment for non c frames.
    Emit(kArm64Claim, g.NoOutput(), g.TempImmediate(claim_count));

    if (needs_padding) {
      Emit(kArm64Poke, g.NoOutput(), g.UseImmediate(0),
           g.TempImmediate(claim_count - 1));
    }
  }

  // Poke the arguments into the stack.
  while (slot >= 0) {
    PushParameter input0 = (*arguments)[slot];
    // Skip holes in the param array. These represent both extra slots for
    // multi-slot values and padding slots for alignment.
    if (!this->valid(input0.node)) {
      slot--;
      continue;
    }
    PushParameter input1 = slot > 0 ? (*arguments)[slot - 1] : PushParameter();
    // Emit a poke-pair if consecutive parameters have the same type.
    // TODO(arm): Support consecutive Simd128 parameters.
    if (this->valid(input1.node) &&
        input0.location.GetType() == input1.location.GetType()) {
      Emit(kArm64PokePair, g.NoOutput(), g.UseRegister(input0.node),
           g.UseRegister(input1.node), g.TempImmediate(slot));
      slot -= 2;
    } else {
      Emit(kArm64Poke, g.NoOutput(), g.UseRegister(input0.node),
           g.TempImmediate(slot));
      slot--;
    }
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::EmitPrepareResults(
    ZoneVector<PushParameter>* results, const CallDescriptor* call_descriptor,
    node_t node) {
  Arm64OperandGeneratorT<Adapter> g(this);

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
      Emit(kArm64Peek, g.DefineAsRegister(output.node),
           g.UseImmediate(reverse_slot));
    }
  }
}

template <typename Adapter>
bool InstructionSelectorT<Adapter>::IsTailCallAddressImmediate() {
  return false;
}

namespace {

// Shared routine for multiple compare operations.
template <typename Adapter>
void VisitCompare(InstructionSelectorT<Adapter>* selector,
                  InstructionCode opcode, InstructionOperand left,
                  InstructionOperand right, FlagsContinuationT<Adapter>* cont) {
  if (cont->IsSelect()) {
    Arm64OperandGeneratorT<Adapter> g(selector);
    InstructionOperand inputs[] = {
        left, right, g.UseRegisterOrImmediateZero(cont->true_value()),
        g.UseRegisterOrImmediateZero(cont->false_value())};
    selector->EmitWithContinuation(opcode, 0, nullptr, 4, inputs, cont);
  } else {
    selector->EmitWithContinuation(opcode, left, right, cont);
  }
}

// This function checks whether we can convert:
// ((a <op> b) cmp 0), b.<cond>
// to:
// (a <ops> b), b.<cond'>
// where <ops> is the flag setting version of <op>.
// We only generate conditions <cond'> that are a combination of the N
// and Z flags. This avoids the need to make this function dependent on
// the flag-setting operation.
bool CanUseFlagSettingBinop(FlagsCondition cond) {
  switch (cond) {
    case kEqual:
    case kNotEqual:
    case kSignedLessThan:
    case kSignedGreaterThanOrEqual:
    case kUnsignedLessThanOrEqual:  // x <= 0 -> x == 0
    case kUnsignedGreaterThan:      // x > 0 -> x != 0
      return true;
    default:
      return false;
  }
}

// Map <cond> to <cond'> so that the following transformation is possible:
// ((a <op> b) cmp 0), b.<cond>
// to:
// (a <ops> b), b.<cond'>
// where <ops> is the flag setting version of <op>.
FlagsCondition MapForFlagSettingBinop(FlagsCondition cond) {
  DCHECK(CanUseFlagSettingBinop(cond));
  switch (cond) {
    case kEqual:
    case kNotEqual:
      return cond;
    case kSignedLessThan:
      return kNegative;
    case kSignedGreaterThanOrEqual:
      return kPositiveOrZero;
    case kUnsignedLessThanOrEqual:  // x <= 0 -> x == 0
      return kEqual;
    case kUnsignedGreaterThan:  // x > 0 -> x != 0
      return kNotEqual;
    default:
      UNREACHABLE();
  }
}

// This function checks if we can perform the transformation:
// ((a <op> b) cmp 0), b.<cond>
// to:
// (a <ops> b), b.<cond'>
// where <ops> is the flag setting version of <op>, and if so,
// updates {node}, {opcode} and {cont} accordingly.
template <typename Adapter>
void MaybeReplaceCmpZeroWithFlagSettingBinop(
    InstructionSelectorT<Adapter>* selector, typename Adapter::node_t* node,
    typename Adapter::node_t binop, ArchOpcode* opcode, FlagsCondition cond,
    FlagsContinuationT<Adapter>* cont, ImmediateMode* immediate_mode) {
  ArchOpcode binop_opcode;
  ArchOpcode no_output_opcode;
  ImmediateMode binop_immediate_mode;
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const Operation& op = selector->Get(binop);
    if (op.Is<Opmask::kWord32Add>()) {
      binop_opcode = kArm64Add32;
      no_output_opcode = kArm64Cmn32;
      binop_immediate_mode = kArithmeticImm;
    } else if (op.Is<Opmask::kWord32BitwiseAnd>()) {
      binop_opcode = kArm64And32;
      no_output_opcode = kArm64Tst32;
      binop_immediate_mode = kLogical32Imm;
    } else {
      UNREACHABLE();
    }
  } else {
    switch (binop->opcode()) {
      case IrOpcode::kInt32Add:
        binop_opcode = kArm64Add32;
        no_output_opcode = kArm64Cmn32;
        binop_immediate_mode = kArithmeticImm;
        break;
      case IrOpcode::kWord32And:
        binop_opcode = kArm64And32;
        no_output_opcode = kArm64Tst32;
        binop_immediate_mode = kLogical32Imm;
        break;
      default:
        UNREACHABLE();
    }
  }
  if (selector->CanCover(*node, binop)) {
    // The comparison is the only user of the add or and, so we can generate
    // a cmn or tst instead.
    cont->Overwrite(MapForFlagSettingBinop(cond));
    *opcode = no_output_opcode;
    *node = binop;
    *immediate_mode = binop_immediate_mode;
  } else if (selector->IsOnlyUserOfNodeInSameBlock(*node, binop)) {
    // We can also handle the case where the add and the compare are in the
    // same basic block, and the compare is the only use of add in this basic
    // block (the add has users in other basic blocks).
    cont->Overwrite(MapForFlagSettingBinop(cond));
    *opcode = binop_opcode;
    *node = binop;
    *immediate_mode = binop_immediate_mode;
  }
}

// Map {cond} to kEqual or kNotEqual, so that we can select
// either TBZ or TBNZ when generating code for:
// (x cmp 0), b.{cond}
FlagsCondition MapForTbz(FlagsCondition cond) {
  switch (cond) {
    case kSignedLessThan:  // generate TBNZ
      return kNotEqual;
    case kSignedGreaterThanOrEqual:  // generate TBZ
      return kEqual;
    default:
      UNREACHABLE();
  }
}

// Map {cond} to kEqual or kNotEqual, so that we can select
// either CBZ or CBNZ when generating code for:
// (x cmp 0), b.{cond}
FlagsCondition MapForCbz(FlagsCondition cond) {
  switch (cond) {
    case kEqual:     // generate CBZ
    case kNotEqual:  // generate CBNZ
      return cond;
    case kUnsignedLessThanOrEqual:  // generate CBZ
      return kEqual;
    case kUnsignedGreaterThan:  // generate CBNZ
      return kNotEqual;
    default:
      UNREACHABLE();
  }
}

template <typename Adapter>
void EmitBranchOrDeoptimize(InstructionSelectorT<Adapter>* selector,
                            InstructionCode opcode, InstructionOperand value,
                            FlagsContinuationT<Adapter>* cont) {
  DCHECK(cont->IsBranch() || cont->IsDeoptimize());
  selector->EmitWithContinuation(opcode, value, cont);
}

template <int N>
struct CbzOrTbzMatchTrait {};

template <>
struct CbzOrTbzMatchTrait<32> {
  using IntegralType = uint32_t;
  using BinopMatcher = Int32BinopMatcher;
  static constexpr IrOpcode::Value kAndOpcode = IrOpcode::kWord32And;
  static constexpr ArchOpcode kTestAndBranchOpcode = kArm64TestAndBranch32;
  static constexpr ArchOpcode kCompareAndBranchOpcode =
      kArm64CompareAndBranch32;
  static constexpr unsigned kSignBit = kWSignBit;
};

template <>
struct CbzOrTbzMatchTrait<64> {
  using IntegralType = uint64_t;
  using BinopMatcher = Int64BinopMatcher;
  static constexpr IrOpcode::Value kAndOpcode = IrOpcode::kWord64And;
  static constexpr ArchOpcode kTestAndBranchOpcode = kArm64TestAndBranch;
  static constexpr ArchOpcode kCompareAndBranchOpcode = kArm64CompareAndBranch;
  static constexpr unsigned kSignBit = kXSignBit;
};

// Try to emit TBZ, TBNZ, CBZ or CBNZ for certain comparisons of {node}
// against {value}, depending on the condition.
template <typename Adapter, int N>
bool TryEmitCbzOrTbz(InstructionSelectorT<Adapter>* selector,
                     typename Adapter::node_t node,
                     typename CbzOrTbzMatchTrait<N>::IntegralType value,
                     typename Adapter::node_t user, FlagsCondition cond,
                     FlagsContinuationT<Adapter>* cont) {
  // Only handle branches and deoptimisations.
  if (!cont->IsBranch() && !cont->IsDeoptimize()) return false;

  switch (cond) {
    case kSignedLessThan:
    case kSignedGreaterThanOrEqual: {
      // Here we handle sign tests, aka. comparisons with zero.
      if (value != 0) return false;
      // We don't generate TBZ/TBNZ for deoptimisations, as they have a
      // shorter range than conditional branches and generating them for
      // deoptimisations results in more veneers.
      if (cont->IsDeoptimize()) return false;
      Arm64OperandGeneratorT<Adapter> g(selector);
      cont->Overwrite(MapForTbz(cond));

      if (N == 32) {
        if constexpr (Adapter::IsTurboshaft) {
          using namespace turboshaft;  // NOLINT(build/namespaces)
          const Operation& op = selector->Get(node);
          if (op.Is<Opmask::kFloat64ExtractHighWord32>() &&
              selector->CanCover(user, node)) {
            // SignedLessThan(Float64ExtractHighWord32(x), 0) and
            // SignedGreaterThanOrEqual(Float64ExtractHighWord32(x), 0)
            // essentially check the sign bit of a 64-bit floating point value.
            InstructionOperand temp = g.TempRegister();
            selector->Emit(kArm64U64MoveFloat64, temp,
                           g.UseRegister(selector->input_at(node, 0)));
            selector->EmitWithContinuation(kArm64TestAndBranch, temp,
                                           g.TempImmediate(kDSignBit), cont);
            return true;
          }
        } else {
          Int32Matcher m(node);
          if (m.IsFloat64ExtractHighWord32() &&
              selector->CanCover(user, node)) {
            // SignedLessThan(Float64ExtractHighWord32(x), 0) and
            // SignedGreaterThanOrEqual(Float64ExtractHighWord32(x), 0)
            // essentially check the sign bit of a 64-bit floating point value.
            InstructionOperand temp = g.TempRegister();
            selector->Emit(kArm64U64MoveFloat64, temp,
                           g.UseRegister(node->InputAt(0)));
            selector->EmitWithContinuation(kArm64TestAndBranch, temp,
                                           g.TempImmediate(kDSignBit), cont);
            return true;
          }
        }
      }

      selector->EmitWithContinuation(
          CbzOrTbzMatchTrait<N>::kTestAndBranchOpcode, g.UseRegister(node),
          g.TempImmediate(CbzOrTbzMatchTrait<N>::kSignBit), cont);
      return true;
    }
    case kEqual:
    case kNotEqual: {
      if constexpr (Adapter::IsTurboshaft) {
        using namespace turboshaft;  // NOLINT(build/namespaces)
        const Operation& op = selector->Get(node);
        if (const WordBinopOp* bitwise_and =
                op.TryCast<Opmask::kBitwiseAnd>()) {
          // Emit a tbz/tbnz if we are comparing with a single-bit mask:
          //   Branch(WordEqual(WordAnd(x, 1 << N), 1 << N), true, false)
          uint64_t actual_value;
          if (cont->IsBranch() && base::bits::IsPowerOfTwo(value) &&
              selector->MatchUnsignedIntegralConstant(bitwise_and->right(),
                                                      &actual_value) &&
              actual_value == value && selector->CanCover(user, node)) {
            Arm64OperandGeneratorT<Adapter> g(selector);
            // In the code generator, Equal refers to a bit being cleared. We
            // want the opposite here so negate the condition.
            cont->Negate();
            selector->EmitWithContinuation(
                CbzOrTbzMatchTrait<N>::kTestAndBranchOpcode,
                g.UseRegister(bitwise_and->left()),
                g.TempImmediate(base::bits::CountTrailingZeros(value)), cont);
            return true;
          }
        }
      } else {
        if (node->opcode() == CbzOrTbzMatchTrait<N>::kAndOpcode) {
          // Emit a tbz/tbnz if we are comparing with a single-bit mask:
          //   Branch(WordEqual(WordAnd(x, 1 << N), 1 << N), true, false)
          typename CbzOrTbzMatchTrait<N>::BinopMatcher m_and(node);
          if (cont->IsBranch() && base::bits::IsPowerOfTwo(value) &&
              m_and.right().Is(value) && selector->CanCover(user, node)) {
            Arm64OperandGeneratorT<Adapter> g(selector);
            // In the code generator, Equal refers to a bit being cleared. We
            // want the opposite here so negate the condition.
            cont->Negate();
            selector->EmitWithContinuation(
                CbzOrTbzMatchTrait<N>::kTestAndBranchOpcode,
                g.UseRegister(m_and.left().node()),
                g.TempImmediate(base::bits::CountTrailingZeros(value)), cont);
            return true;
          }
        }
      }
      [[fallthrough]];
    }
    case kUnsignedLessThanOrEqual:
    case kUnsignedGreaterThan: {
      if (value != 0) return false;
      Arm64OperandGeneratorT<Adapter> g(selector);
      cont->Overwrite(MapForCbz(cond));
      EmitBranchOrDeoptimize(selector,
                             CbzOrTbzMatchTrait<N>::kCompareAndBranchOpcode,
                             g.UseRegister(node), cont);
      return true;
    }
    default:
      return false;
  }
}

// Shared routine for multiple word compare operations.
template <typename Adapter>
void VisitWordCompare(InstructionSelectorT<Adapter>* selector,
                      typename Adapter::node_t node, InstructionCode opcode,
                      FlagsContinuationT<Adapter>* cont,
                      ImmediateMode immediate_mode) {
  Arm64OperandGeneratorT<Adapter> g(selector);
  DCHECK_EQ(selector->value_input_count(node), 2);
  auto left = selector->input_at(node, 0);
  auto right = selector->input_at(node, 1);

  // If one of the two inputs is an immediate, make sure it's on the right.
  if (!g.CanBeImmediate(right, immediate_mode) &&
      g.CanBeImmediate(left, immediate_mode)) {
    cont->Commute();
    std::swap(left, right);
  }

  if (opcode == kArm64Cmp && selector->is_constant(right)) {
    auto constant = selector->constant_view(right);
    if (g.IsIntegerConstant(constant)) {
      if (TryEmitCbzOrTbz<Adapter, 64>(selector, left,
                                       g.GetIntegerConstantValue(constant),
        
"""


```