Response:
Let's break down the thought process for answering the request about the `instruction-selector.cc` file.

**1. Understanding the Core Task:**

The request asks for the functionality of a specific V8 source code file. It also has several sub-constraints related to Torque, JavaScript examples, logical reasoning, common errors, and summarizing the current section.

**2. Initial Analysis of the Code Snippet:**

The provided code is a large `switch` statement. Each `case` corresponds to an `IrOpcode` (likely from the V8 Intermediate Representation). The pattern is:

```c++
case IrOpcode::kSomeOperation:
  return MarkAsSomething(node), VisitSomeOperation(node);
```

This immediately suggests the file's primary function: to *translate* or *select* machine instructions based on higher-level IR operations.

**3. Deconstructing the Pattern:**

* **`IrOpcode::kSomeOperation`:** This is the *input* – a node representing a specific operation in V8's internal representation of code. The sheer number of different `IrOpcode` cases hints at a comprehensive mapping of operations.
* **`MarkAsSomething(node)`:** This suggests type or representation tagging. The arguments to `MarkAs` (`Word32`, `Word64`, `Float32`, `Float64`, `Simd128`, `Tagged`, `Representation`) indicate the data types involved. This is crucial for later stages of compilation where the actual machine instructions need to know the size and format of the data.
* **`VisitSomeOperation(node)`:** This is the core of the instruction selection. The `Visit` functions are likely responsible for generating the low-level machine instructions corresponding to the `IrOpcode`. The specific `Visit` function name usually mirrors the `IrOpcode`.

**4. Inferring Overall Functionality:**

Based on the pattern, the `instruction-selector.cc` file seems to be a crucial component in V8's compiler pipeline. It takes the platform-independent IR and makes platform-specific decisions about which machine instructions to use. This process is called *instruction selection*.

**5. Addressing Specific Constraints:**

* **`.tq` Extension:** The code is C++, not Torque. Torque files have the `.tq` extension. This is a straightforward check.
* **Relationship to JavaScript:**  Every `IrOpcode` here ultimately stems from some JavaScript operation. The task is to provide a clear, simple example. Operations like addition, subtraction, bitwise operations, and comparisons are good candidates. Choosing examples that map directly to some of the listed `IrOpcodes` is ideal.
* **Code Logic Reasoning:**  The `switch` statement itself is the logic. The input is an `IrOpcode`, and the output is the execution of the corresponding `MarkAs` and `Visit` functions. A simple example demonstrating the flow for a particular `IrOpcode` is sufficient. Consider a specific case like `IrOpcode::kWord32Add`.
* **Common Programming Errors:**  This requires thinking about how the operations in the code relate to JavaScript and potential pitfalls. Type mismatches (e.g., adding a number and a string), integer overflow, and floating-point precision issues are all relevant. Choose an example that illustrates one of these concepts.
* **归纳一下它的功能 (Summarize its function):**  This requires consolidating the inferences made so far into a concise summary. Key aspects include IR to machine instruction translation, platform-specific choices, and handling different data types.

**6. Structuring the Answer:**

Organize the answer according to the points raised in the request. Use clear headings and formatting to make it easy to read.

**7. Pre-computation/Pre-analysis (Internal "Sandbox"):**

Before writing the final answer, mentally walk through a few examples:

* **Scenario 1: `a + b` (JavaScript)**
    * This might be represented internally as an `IrOpcode::kNumberAdd` initially.
    * The `instruction-selector.cc` might encounter a `kWord32Add` or `kFloat64Add` depending on the type analysis performed earlier in the pipeline.
    * It would then call `MarkAsWord32/Float64` and `VisitWord32Add/VisitFloat64Add`.

* **Scenario 2: `a & b` (JavaScript, assuming `a` and `b` are integers)**
    * This would likely become `IrOpcode::kWord32And` or `kWord64And`.
    * The process would be similar, leading to the corresponding `Visit` function.

**8. Refinement and Review:**

After drafting the answer, review it for clarity, accuracy, and completeness. Ensure all parts of the request are addressed. Check for any technical inaccuracies. For example, initially, one might think the file directly generates assembly code. However, it likely selects *abstract* machine instructions that are further refined by a later stage.

By following this structured approach, combining code analysis with an understanding of compiler principles, and addressing each constraint systematically, a comprehensive and accurate answer can be constructed.
好的，我们来分析一下提供的 V8 源代码片段 `v8/src/compiler/backend/instruction-selector.cc` 的功能。

**1. 功能概述**

从提供的代码片段来看，`instruction-selector.cc` 文件的主要功能是 **将中间表示 (Intermediate Representation, IR) 的操作 (IrOpcode) 转换为特定架构的机器指令**。  这部分代码是一个巨大的 `switch` 语句，针对不同的 `IrOpcode` 枚举值，调用相应的 `Visit` 函数。

具体来说，这个代码片段负责处理各种算术、逻辑、位运算、类型转换以及 SIMD (单指令多数据流) 操作的指令选择。  对于每个 IR 操作，它可能会执行以下操作：

* **`MarkAsWord32(node)` / `MarkAsWord64(node)` / `MarkAsFloat32(node)` / `MarkAsFloat64(node)` / `MarkAsSimd128(node)` / `MarkAsTagged(node)` / `MarkAsRepresentation(...)`**: 这些函数用于标记节点的表示形式（例如，32位整数、64位整数、单精度浮点数、双精度浮点数、SIMD 向量、标记指针等）。这是为后续的指令生成阶段提供类型信息。
* **`VisitWord32Shr(node)` / `VisitFloat64Add(node)` 等**: 这些 `Visit` 函数是核心，它们负责根据当前的 IR 操作和目标架构，选择合适的机器指令，并将这些指令添加到指令序列中。不同的 `Visit` 函数对应着不同的 IR 操作。

**2. 是否为 Torque 源代码**

根据描述，如果文件以 `.tq` 结尾，则为 Torque 源代码。 `instruction-selector.cc` 以 `.cc` 结尾，因此 **它不是 V8 Torque 源代码，而是 C++ 源代码。**

**3. 与 JavaScript 的关系及举例**

`instruction-selector.cc` 位于编译器的后端，它的工作是将 V8 的中间表示转换为机器码，而中间表示正是 JavaScript 代码经过解析和优化的结果。因此，这个文件与 JavaScript 的执行密切相关。

**JavaScript 示例：**

```javascript
function add(a, b) {
  return a + b;
}

let result = add(5, 10);
```

在这个简单的 JavaScript 函数中，`a + b` 这个加法操作在 V8 的编译过程中会被表示为一个 `IrOpcode::kNumberAdd` 或其他相关的 IR 操作码。  `instruction-selector.cc` 中的代码就负责处理类似 `kInt32Add`、`kFloat64Add` 这样的操作码，并最终选择合适的机器指令（例如，x86-64 架构下的 `ADD` 指令）来执行加法运算。

**4. 代码逻辑推理及假设输入输出**

假设输入是一个代表 32 位整数加法操作的 IR 节点 `node`，其 `IrOpcode` 为 `IrOpcode::kInt32Add`。

**假设输入：**

* `node`:  一个指向 IR 节点的指针，该节点表示 `a + b` 且已知 `a` 和 `b` 为 32 位整数。
* `node->op()` 返回 `IrOpcode::kInt32Add`。

**代码逻辑：**

当执行到 `switch` 语句时，会匹配到 `case IrOpcode::kInt32Add:` 分支。

```c++
case IrOpcode::kInt32Add:
  return MarkAsWord32(node), VisitInt32Add(node);
```

1. `MarkAsWord32(node)`:  该函数会被调用，将 `node` 标记为 32 位整数表示。
2. `VisitInt32Add(node)`:  该函数会被调用，它会根据目标架构生成执行 32 位整数加法的机器指令。具体的指令可能因架构而异。

**假设输出：**

* `MarkAsWord32(node)`:  `node` 内部的某种状态被更新，记录了其 32 位整数的表示形式。
* `VisitInt32Add(node)`:  向当前的机器指令序列中添加了执行 32 位整数加法的指令。

**5. 涉及用户常见的编程错误及举例**

虽然 `instruction-selector.cc` 本身是编译器内部的代码，但它处理的 IR 操作直接来源于用户的 JavaScript 代码。 用户的一些编程错误可能会导致生成特定的 IR 操作，并最终被这个文件处理。

**常见编程错误示例：**

* **类型不匹配的运算:**

```javascript
let a = 5;
let b = "10";
let result = a + b; // JavaScript 允许这种操作，会进行类型转换
```

在这个例子中，JavaScript 允许数字和字符串相加，会进行类型转换（通常将数字转换为字符串）。  在编译过程中，这可能会导致生成一些类型转换相关的 IR 操作，例如将整数转换为字符串的操作，而 `instruction-selector.cc` 会负责为这些转换操作选择合适的机器指令。

* **整数溢出:**

```javascript
let maxInt = 2147483647;
let result = maxInt + 1; // JavaScript 中的数字是双精度浮点数，不会真正溢出成另一个负数，但可能失去精度
```

如果 V8 在某些优化阶段将 `maxInt` 识别为 32 位整数，那么 `maxInt + 1` 可能会被表示为一个 32 位整数加法操作。  `instruction-selector.cc` 会处理 `IrOpcode::kInt32AddWithOverflow` 这样的操作，并生成考虑溢出情况的指令（或者，在 JavaScript 的上下文中，由于使用了浮点数，可能不会直接产生溢出指令，而是处理浮点数加法）。

* **位运算的误用:**

```javascript
let a = 5; // 二进制 0101
let b = 10; // 二进制 1010
let result = a & b; // 位与运算
```

用户可能不理解位运算的原理，导致得到意料之外的结果。 `instruction-selector.cc` 会处理 `IrOpcode::kWord32And` 这样的位运算操作，并生成相应的机器指令。

**6. 功能归纳 (针对提供的代码片段)**

提供的 `instruction-selector.cc` 代码片段（第 5 部分）主要负责 **将各种基本的算术、逻辑、位运算、类型转换以及 SIMD 操作的 IR 节点转换为目标架构的机器指令**。它针对不同的数据类型（32 位整数、64 位整数、单精度浮点数、双精度浮点数、SIMD 向量等）和操作类型，分发到不同的 `Visit` 函数进行处理，并在这个过程中标记节点的表示形式。  这部分是指令选择过程的核心组成部分，确保了 V8 能够有效地将 JavaScript 代码转换为可执行的机器码。

总结来说，`instruction-selector.cc` 是 V8 编译器后端至关重要的一部分，它弥合了平台无关的中间表示和平台相关的机器指令之间的 gap。

### 提示词
```
这是目录为v8/src/compiler/backend/instruction-selector.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/instruction-selector.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
turn MarkAsWord32(node), VisitWord32Shr(node);
    case IrOpcode::kWord32Sar:
      return MarkAsWord32(node), VisitWord32Sar(node);
    case IrOpcode::kWord32Rol:
      return MarkAsWord32(node), VisitWord32Rol(node);
    case IrOpcode::kWord32Ror:
      return MarkAsWord32(node), VisitWord32Ror(node);
    case IrOpcode::kWord32Equal:
      return VisitWord32Equal(node);
    case IrOpcode::kWord32Clz:
      return MarkAsWord32(node), VisitWord32Clz(node);
    case IrOpcode::kWord32Ctz:
      return MarkAsWord32(node), VisitWord32Ctz(node);
    case IrOpcode::kWord32ReverseBits:
      return MarkAsWord32(node), VisitWord32ReverseBits(node);
    case IrOpcode::kWord32ReverseBytes:
      return MarkAsWord32(node), VisitWord32ReverseBytes(node);
    case IrOpcode::kInt32AbsWithOverflow:
      return MarkAsWord32(node), VisitInt32AbsWithOverflow(node);
    case IrOpcode::kWord32Popcnt:
      return MarkAsWord32(node), VisitWord32Popcnt(node);
    case IrOpcode::kWord64Popcnt:
      return MarkAsWord64(node), VisitWord64Popcnt(node);
    case IrOpcode::kWord32Select:
      return MarkAsWord32(node), VisitSelect(node);
    case IrOpcode::kWord64And:
      return MarkAsWord64(node), VisitWord64And(node);
    case IrOpcode::kWord64Or:
      return MarkAsWord64(node), VisitWord64Or(node);
    case IrOpcode::kWord64Xor:
      return MarkAsWord64(node), VisitWord64Xor(node);
    case IrOpcode::kWord64Shl:
      return MarkAsWord64(node), VisitWord64Shl(node);
    case IrOpcode::kWord64Shr:
      return MarkAsWord64(node), VisitWord64Shr(node);
    case IrOpcode::kWord64Sar:
      return MarkAsWord64(node), VisitWord64Sar(node);
    case IrOpcode::kWord64Rol:
      return MarkAsWord64(node), VisitWord64Rol(node);
    case IrOpcode::kWord64Ror:
      return MarkAsWord64(node), VisitWord64Ror(node);
    case IrOpcode::kWord64Clz:
      return MarkAsWord64(node), VisitWord64Clz(node);
    case IrOpcode::kWord64Ctz:
      return MarkAsWord64(node), VisitWord64Ctz(node);
    case IrOpcode::kWord64ReverseBits:
      return MarkAsWord64(node), VisitWord64ReverseBits(node);
    case IrOpcode::kWord64ReverseBytes:
      return MarkAsWord64(node), VisitWord64ReverseBytes(node);
    case IrOpcode::kSimd128ReverseBytes:
      return MarkAsSimd128(node), VisitSimd128ReverseBytes(node);
    case IrOpcode::kInt64AbsWithOverflow:
      return MarkAsWord64(node), VisitInt64AbsWithOverflow(node);
    case IrOpcode::kWord64Equal:
      return VisitWord64Equal(node);
    case IrOpcode::kWord64Select:
      return MarkAsWord64(node), VisitSelect(node);
    case IrOpcode::kInt32Add:
      return MarkAsWord32(node), VisitInt32Add(node);
    case IrOpcode::kInt32AddWithOverflow:
      return MarkAsWord32(node), VisitInt32AddWithOverflow(node);
    case IrOpcode::kInt32Sub:
      return MarkAsWord32(node), VisitInt32Sub(node);
    case IrOpcode::kInt32SubWithOverflow:
      return VisitInt32SubWithOverflow(node);
    case IrOpcode::kInt32Mul:
      return MarkAsWord32(node), VisitInt32Mul(node);
    case IrOpcode::kInt32MulWithOverflow:
      return MarkAsWord32(node), VisitInt32MulWithOverflow(node);
    case IrOpcode::kInt32MulHigh:
      return VisitInt32MulHigh(node);
    case IrOpcode::kInt64MulHigh:
      return VisitInt64MulHigh(node);
    case IrOpcode::kInt32Div:
      return MarkAsWord32(node), VisitInt32Div(node);
    case IrOpcode::kInt32Mod:
      return MarkAsWord32(node), VisitInt32Mod(node);
    case IrOpcode::kInt32LessThan:
      return VisitInt32LessThan(node);
    case IrOpcode::kInt32LessThanOrEqual:
      return VisitInt32LessThanOrEqual(node);
    case IrOpcode::kUint32Div:
      return MarkAsWord32(node), VisitUint32Div(node);
    case IrOpcode::kUint32LessThan:
      return VisitUint32LessThan(node);
    case IrOpcode::kUint32LessThanOrEqual:
      return VisitUint32LessThanOrEqual(node);
    case IrOpcode::kUint32Mod:
      return MarkAsWord32(node), VisitUint32Mod(node);
    case IrOpcode::kUint32MulHigh:
      return VisitUint32MulHigh(node);
    case IrOpcode::kUint64MulHigh:
      return VisitUint64MulHigh(node);
    case IrOpcode::kInt64Add:
      return MarkAsWord64(node), VisitInt64Add(node);
    case IrOpcode::kInt64AddWithOverflow:
      return MarkAsWord64(node), VisitInt64AddWithOverflow(node);
    case IrOpcode::kInt64Sub:
      return MarkAsWord64(node), VisitInt64Sub(node);
    case IrOpcode::kInt64SubWithOverflow:
      return MarkAsWord64(node), VisitInt64SubWithOverflow(node);
    case IrOpcode::kInt64Mul:
      return MarkAsWord64(node), VisitInt64Mul(node);
    case IrOpcode::kInt64MulWithOverflow:
      return MarkAsWord64(node), VisitInt64MulWithOverflow(node);
    case IrOpcode::kInt64Div:
      return MarkAsWord64(node), VisitInt64Div(node);
    case IrOpcode::kInt64Mod:
      return MarkAsWord64(node), VisitInt64Mod(node);
    case IrOpcode::kInt64LessThan:
      return VisitInt64LessThan(node);
    case IrOpcode::kInt64LessThanOrEqual:
      return VisitInt64LessThanOrEqual(node);
    case IrOpcode::kUint64Div:
      return MarkAsWord64(node), VisitUint64Div(node);
    case IrOpcode::kUint64LessThan:
      return VisitUint64LessThan(node);
    case IrOpcode::kUint64LessThanOrEqual:
      return VisitUint64LessThanOrEqual(node);
    case IrOpcode::kUint64Mod:
      return MarkAsWord64(node), VisitUint64Mod(node);
    case IrOpcode::kBitcastTaggedToWord:
    case IrOpcode::kBitcastTaggedToWordForTagAndSmiBits:
      return MarkAsRepresentation(MachineType::PointerRepresentation(), node),
             VisitBitcastTaggedToWord(node);
    case IrOpcode::kBitcastWordToTagged:
      return MarkAsTagged(node), VisitBitcastWordToTagged(node);
    case IrOpcode::kBitcastWordToTaggedSigned:
      return MarkAsRepresentation(MachineRepresentation::kTaggedSigned, node),
             EmitIdentity(node);
    case IrOpcode::kChangeFloat32ToFloat64:
      return MarkAsFloat64(node), VisitChangeFloat32ToFloat64(node);
    case IrOpcode::kChangeInt32ToFloat64:
      return MarkAsFloat64(node), VisitChangeInt32ToFloat64(node);
    case IrOpcode::kChangeInt64ToFloat64:
      return MarkAsFloat64(node), VisitChangeInt64ToFloat64(node);
    case IrOpcode::kChangeUint32ToFloat64:
      return MarkAsFloat64(node), VisitChangeUint32ToFloat64(node);
    case IrOpcode::kChangeFloat64ToInt32:
      return MarkAsWord32(node), VisitChangeFloat64ToInt32(node);
    case IrOpcode::kChangeFloat64ToInt64:
      return MarkAsWord64(node), VisitChangeFloat64ToInt64(node);
    case IrOpcode::kChangeFloat64ToUint32:
      return MarkAsWord32(node), VisitChangeFloat64ToUint32(node);
    case IrOpcode::kChangeFloat64ToUint64:
      return MarkAsWord64(node), VisitChangeFloat64ToUint64(node);
    case IrOpcode::kFloat64SilenceNaN:
      MarkAsFloat64(node);
      if (CanProduceSignalingNaN(node->InputAt(0))) {
        return VisitFloat64SilenceNaN(node);
      } else {
        return EmitIdentity(node);
      }
    case IrOpcode::kTruncateFloat64ToInt64:
      return MarkAsWord64(node), VisitTruncateFloat64ToInt64(node);
    case IrOpcode::kTruncateFloat64ToUint32:
      return MarkAsWord32(node), VisitTruncateFloat64ToUint32(node);
    case IrOpcode::kTruncateFloat32ToInt32:
      return MarkAsWord32(node), VisitTruncateFloat32ToInt32(node);
    case IrOpcode::kTruncateFloat32ToUint32:
      return MarkAsWord32(node), VisitTruncateFloat32ToUint32(node);
    case IrOpcode::kTryTruncateFloat32ToInt64:
      return MarkAsWord64(node), VisitTryTruncateFloat32ToInt64(node);
    case IrOpcode::kTryTruncateFloat64ToInt64:
      return MarkAsWord64(node), VisitTryTruncateFloat64ToInt64(node);
    case IrOpcode::kTryTruncateFloat32ToUint64:
      return MarkAsWord64(node), VisitTryTruncateFloat32ToUint64(node);
    case IrOpcode::kTryTruncateFloat64ToUint64:
      return MarkAsWord64(node), VisitTryTruncateFloat64ToUint64(node);
    case IrOpcode::kTryTruncateFloat64ToInt32:
      return MarkAsWord32(node), VisitTryTruncateFloat64ToInt32(node);
    case IrOpcode::kTryTruncateFloat64ToUint32:
      return MarkAsWord32(node), VisitTryTruncateFloat64ToUint32(node);
    case IrOpcode::kBitcastWord32ToWord64:
      MarkAsWord64(node);
      return VisitBitcastWord32ToWord64(node);
    case IrOpcode::kChangeInt32ToInt64:
      return MarkAsWord64(node), VisitChangeInt32ToInt64(node);
    case IrOpcode::kChangeUint32ToUint64:
      return MarkAsWord64(node), VisitChangeUint32ToUint64(node);
    case IrOpcode::kTruncateFloat64ToFloat32:
      return MarkAsFloat32(node), VisitTruncateFloat64ToFloat32(node);
    case IrOpcode::kTruncateFloat64ToWord32:
      return MarkAsWord32(node), VisitTruncateFloat64ToWord32(node);
    case IrOpcode::kTruncateInt64ToInt32:
      return MarkAsWord32(node), VisitTruncateInt64ToInt32(node);
    case IrOpcode::kRoundFloat64ToInt32:
      return MarkAsWord32(node), VisitRoundFloat64ToInt32(node);
    case IrOpcode::kRoundInt64ToFloat32:
      return MarkAsFloat32(node), VisitRoundInt64ToFloat32(node);
    case IrOpcode::kRoundInt32ToFloat32:
      return MarkAsFloat32(node), VisitRoundInt32ToFloat32(node);
    case IrOpcode::kRoundInt64ToFloat64:
      return MarkAsFloat64(node), VisitRoundInt64ToFloat64(node);
    case IrOpcode::kBitcastFloat32ToInt32:
      return MarkAsWord32(node), VisitBitcastFloat32ToInt32(node);
    case IrOpcode::kRoundUint32ToFloat32:
      return MarkAsFloat32(node), VisitRoundUint32ToFloat32(node);
    case IrOpcode::kRoundUint64ToFloat32:
      return MarkAsFloat32(node), VisitRoundUint64ToFloat32(node);
    case IrOpcode::kRoundUint64ToFloat64:
      return MarkAsFloat64(node), VisitRoundUint64ToFloat64(node);
    case IrOpcode::kBitcastFloat64ToInt64:
      return MarkAsWord64(node), VisitBitcastFloat64ToInt64(node);
    case IrOpcode::kBitcastInt32ToFloat32:
      return MarkAsFloat32(node), VisitBitcastInt32ToFloat32(node);
    case IrOpcode::kBitcastInt64ToFloat64:
      return MarkAsFloat64(node), VisitBitcastInt64ToFloat64(node);
    case IrOpcode::kFloat32Add:
      return MarkAsFloat32(node), VisitFloat32Add(node);
    case IrOpcode::kFloat32Sub:
      return MarkAsFloat32(node), VisitFloat32Sub(node);
    case IrOpcode::kFloat32Neg:
      return MarkAsFloat32(node), VisitFloat32Neg(node);
    case IrOpcode::kFloat32Mul:
      return MarkAsFloat32(node), VisitFloat32Mul(node);
    case IrOpcode::kFloat32Div:
      return MarkAsFloat32(node), VisitFloat32Div(node);
    case IrOpcode::kFloat32Abs:
      return MarkAsFloat32(node), VisitFloat32Abs(node);
    case IrOpcode::kFloat32Sqrt:
      return MarkAsFloat32(node), VisitFloat32Sqrt(node);
    case IrOpcode::kFloat32Equal:
      return VisitFloat32Equal(node);
    case IrOpcode::kFloat32LessThan:
      return VisitFloat32LessThan(node);
    case IrOpcode::kFloat32LessThanOrEqual:
      return VisitFloat32LessThanOrEqual(node);
    case IrOpcode::kFloat32Max:
      return MarkAsFloat32(node), VisitFloat32Max(node);
    case IrOpcode::kFloat32Min:
      return MarkAsFloat32(node), VisitFloat32Min(node);
    case IrOpcode::kFloat32Select:
      return MarkAsFloat32(node), VisitSelect(node);
    case IrOpcode::kFloat64Add:
      return MarkAsFloat64(node), VisitFloat64Add(node);
    case IrOpcode::kFloat64Sub:
      return MarkAsFloat64(node), VisitFloat64Sub(node);
    case IrOpcode::kFloat64Neg:
      return MarkAsFloat64(node), VisitFloat64Neg(node);
    case IrOpcode::kFloat64Mul:
      return MarkAsFloat64(node), VisitFloat64Mul(node);
    case IrOpcode::kFloat64Div:
      return MarkAsFloat64(node), VisitFloat64Div(node);
    case IrOpcode::kFloat64Mod:
      return MarkAsFloat64(node), VisitFloat64Mod(node);
    case IrOpcode::kFloat64Min:
      return MarkAsFloat64(node), VisitFloat64Min(node);
    case IrOpcode::kFloat64Max:
      return MarkAsFloat64(node), VisitFloat64Max(node);
    case IrOpcode::kFloat64Abs:
      return MarkAsFloat64(node), VisitFloat64Abs(node);
    case IrOpcode::kFloat64Acos:
      return MarkAsFloat64(node), VisitFloat64Acos(node);
    case IrOpcode::kFloat64Acosh:
      return MarkAsFloat64(node), VisitFloat64Acosh(node);
    case IrOpcode::kFloat64Asin:
      return MarkAsFloat64(node), VisitFloat64Asin(node);
    case IrOpcode::kFloat64Asinh:
      return MarkAsFloat64(node), VisitFloat64Asinh(node);
    case IrOpcode::kFloat64Atan:
      return MarkAsFloat64(node), VisitFloat64Atan(node);
    case IrOpcode::kFloat64Atanh:
      return MarkAsFloat64(node), VisitFloat64Atanh(node);
    case IrOpcode::kFloat64Atan2:
      return MarkAsFloat64(node), VisitFloat64Atan2(node);
    case IrOpcode::kFloat64Cbrt:
      return MarkAsFloat64(node), VisitFloat64Cbrt(node);
    case IrOpcode::kFloat64Cos:
      return MarkAsFloat64(node), VisitFloat64Cos(node);
    case IrOpcode::kFloat64Cosh:
      return MarkAsFloat64(node), VisitFloat64Cosh(node);
    case IrOpcode::kFloat64Exp:
      return MarkAsFloat64(node), VisitFloat64Exp(node);
    case IrOpcode::kFloat64Expm1:
      return MarkAsFloat64(node), VisitFloat64Expm1(node);
    case IrOpcode::kFloat64Log:
      return MarkAsFloat64(node), VisitFloat64Log(node);
    case IrOpcode::kFloat64Log1p:
      return MarkAsFloat64(node), VisitFloat64Log1p(node);
    case IrOpcode::kFloat64Log10:
      return MarkAsFloat64(node), VisitFloat64Log10(node);
    case IrOpcode::kFloat64Log2:
      return MarkAsFloat64(node), VisitFloat64Log2(node);
    case IrOpcode::kFloat64Pow:
      return MarkAsFloat64(node), VisitFloat64Pow(node);
    case IrOpcode::kFloat64Sin:
      return MarkAsFloat64(node), VisitFloat64Sin(node);
    case IrOpcode::kFloat64Sinh:
      return MarkAsFloat64(node), VisitFloat64Sinh(node);
    case IrOpcode::kFloat64Sqrt:
      return MarkAsFloat64(node), VisitFloat64Sqrt(node);
    case IrOpcode::kFloat64Tan:
      return MarkAsFloat64(node), VisitFloat64Tan(node);
    case IrOpcode::kFloat64Tanh:
      return MarkAsFloat64(node), VisitFloat64Tanh(node);
    case IrOpcode::kFloat64Equal:
      return VisitFloat64Equal(node);
    case IrOpcode::kFloat64LessThan:
      return VisitFloat64LessThan(node);
    case IrOpcode::kFloat64LessThanOrEqual:
      return VisitFloat64LessThanOrEqual(node);
    case IrOpcode::kFloat64Select:
      return MarkAsFloat64(node), VisitSelect(node);
    case IrOpcode::kFloat32RoundDown:
      return MarkAsFloat32(node), VisitFloat32RoundDown(node);
    case IrOpcode::kFloat64RoundDown:
      return MarkAsFloat64(node), VisitFloat64RoundDown(node);
    case IrOpcode::kFloat32RoundUp:
      return MarkAsFloat32(node), VisitFloat32RoundUp(node);
    case IrOpcode::kFloat64RoundUp:
      return MarkAsFloat64(node), VisitFloat64RoundUp(node);
    case IrOpcode::kFloat32RoundTruncate:
      return MarkAsFloat32(node), VisitFloat32RoundTruncate(node);
    case IrOpcode::kFloat64RoundTruncate:
      return MarkAsFloat64(node), VisitFloat64RoundTruncate(node);
    case IrOpcode::kFloat64RoundTiesAway:
      return MarkAsFloat64(node), VisitFloat64RoundTiesAway(node);
    case IrOpcode::kFloat32RoundTiesEven:
      return MarkAsFloat32(node), VisitFloat32RoundTiesEven(node);
    case IrOpcode::kFloat64RoundTiesEven:
      return MarkAsFloat64(node), VisitFloat64RoundTiesEven(node);
    case IrOpcode::kFloat64ExtractLowWord32:
      return MarkAsWord32(node), VisitFloat64ExtractLowWord32(node);
    case IrOpcode::kFloat64ExtractHighWord32:
      return MarkAsWord32(node), VisitFloat64ExtractHighWord32(node);
    case IrOpcode::kFloat64InsertLowWord32:
      return MarkAsFloat64(node), VisitFloat64InsertLowWord32(node);
    case IrOpcode::kFloat64InsertHighWord32:
      return MarkAsFloat64(node), VisitFloat64InsertHighWord32(node);
    case IrOpcode::kStackSlot:
      return VisitStackSlot(node);
    case IrOpcode::kStackPointerGreaterThan:
      return VisitStackPointerGreaterThan(node);
    case IrOpcode::kLoadStackCheckOffset:
      return VisitLoadStackCheckOffset(node);
    case IrOpcode::kLoadFramePointer:
      return VisitLoadFramePointer(node);
#if V8_ENABLE_WEBASSEMBLY
    case IrOpcode::kLoadStackPointer:
      return VisitLoadStackPointer(node);
    case IrOpcode::kSetStackPointer:
      return VisitSetStackPointer(node);
#endif  // V8_ENABLE_WEBASSEMBLY
    case IrOpcode::kLoadParentFramePointer:
      return VisitLoadParentFramePointer(node);
    case IrOpcode::kLoadRootRegister:
      return VisitLoadRootRegister(node);
    case IrOpcode::kUnalignedLoad: {
      LoadRepresentation type = LoadRepresentationOf(node->op());
      MarkAsRepresentation(type.representation(), node);
      return VisitUnalignedLoad(node);
    }
    case IrOpcode::kUnalignedStore:
      return VisitUnalignedStore(node);
    case IrOpcode::kInt32PairAdd:
      MarkAsWord32(node);
      MarkPairProjectionsAsWord32(node);
      return VisitInt32PairAdd(node);
    case IrOpcode::kInt32PairSub:
      MarkAsWord32(node);
      MarkPairProjectionsAsWord32(node);
      return VisitInt32PairSub(node);
    case IrOpcode::kInt32PairMul:
      MarkAsWord32(node);
      MarkPairProjectionsAsWord32(node);
      return VisitInt32PairMul(node);
    case IrOpcode::kWord32PairShl:
      MarkAsWord32(node);
      MarkPairProjectionsAsWord32(node);
      return VisitWord32PairShl(node);
    case IrOpcode::kWord32PairShr:
      MarkAsWord32(node);
      MarkPairProjectionsAsWord32(node);
      return VisitWord32PairShr(node);
    case IrOpcode::kWord32PairSar:
      MarkAsWord32(node);
      MarkPairProjectionsAsWord32(node);
      return VisitWord32PairSar(node);
    case IrOpcode::kMemoryBarrier:
      return VisitMemoryBarrier(node);
    case IrOpcode::kWord32AtomicLoad: {
      AtomicLoadParameters params = AtomicLoadParametersOf(node->op());
      LoadRepresentation type = params.representation();
      MarkAsRepresentation(type.representation(), node);
      return VisitWord32AtomicLoad(node);
    }
    case IrOpcode::kWord64AtomicLoad: {
      AtomicLoadParameters params = AtomicLoadParametersOf(node->op());
      LoadRepresentation type = params.representation();
      MarkAsRepresentation(type.representation(), node);
      return VisitWord64AtomicLoad(node);
    }
    case IrOpcode::kWord32AtomicStore:
      return VisitWord32AtomicStore(node);
    case IrOpcode::kWord64AtomicStore:
      return VisitWord64AtomicStore(node);
    case IrOpcode::kWord32AtomicPairStore:
      return VisitWord32AtomicPairStore(node);
    case IrOpcode::kWord32AtomicPairLoad: {
      MarkAsWord32(node);
      MarkPairProjectionsAsWord32(node);
      return VisitWord32AtomicPairLoad(node);
    }
#define ATOMIC_CASE(name, rep)                         \
  case IrOpcode::k##rep##Atomic##name: {               \
    MachineType type = AtomicOpType(node->op());       \
    MarkAsRepresentation(type.representation(), node); \
    return Visit##rep##Atomic##name(node);             \
  }
      ATOMIC_CASE(Add, Word32)
      ATOMIC_CASE(Add, Word64)
      ATOMIC_CASE(Sub, Word32)
      ATOMIC_CASE(Sub, Word64)
      ATOMIC_CASE(And, Word32)
      ATOMIC_CASE(And, Word64)
      ATOMIC_CASE(Or, Word32)
      ATOMIC_CASE(Or, Word64)
      ATOMIC_CASE(Xor, Word32)
      ATOMIC_CASE(Xor, Word64)
      ATOMIC_CASE(Exchange, Word32)
      ATOMIC_CASE(Exchange, Word64)
      ATOMIC_CASE(CompareExchange, Word32)
      ATOMIC_CASE(CompareExchange, Word64)
#undef ATOMIC_CASE
#define ATOMIC_CASE(name)                     \
  case IrOpcode::kWord32AtomicPair##name: {   \
    MarkAsWord32(node);                       \
    MarkPairProjectionsAsWord32(node);        \
    return VisitWord32AtomicPair##name(node); \
  }
      ATOMIC_CASE(Add)
      ATOMIC_CASE(Sub)
      ATOMIC_CASE(And)
      ATOMIC_CASE(Or)
      ATOMIC_CASE(Xor)
      ATOMIC_CASE(Exchange)
      ATOMIC_CASE(CompareExchange)
#undef ATOMIC_CASE
    case IrOpcode::kProtectedLoad:
    case IrOpcode::kLoadTrapOnNull: {
      LoadRepresentation type = LoadRepresentationOf(node->op());
      MarkAsRepresentation(type.representation(), node);
      return VisitProtectedLoad(node);
    }
    case IrOpcode::kSignExtendWord8ToInt32:
      return MarkAsWord32(node), VisitSignExtendWord8ToInt32(node);
    case IrOpcode::kSignExtendWord16ToInt32:
      return MarkAsWord32(node), VisitSignExtendWord16ToInt32(node);
    case IrOpcode::kSignExtendWord8ToInt64:
      return MarkAsWord64(node), VisitSignExtendWord8ToInt64(node);
    case IrOpcode::kSignExtendWord16ToInt64:
      return MarkAsWord64(node), VisitSignExtendWord16ToInt64(node);
    case IrOpcode::kSignExtendWord32ToInt64:
      return MarkAsWord64(node), VisitSignExtendWord32ToInt64(node);
#if V8_ENABLE_WEBASSEMBLY
    case IrOpcode::kF64x2Splat:
      return MarkAsSimd128(node), VisitF64x2Splat(node);
    case IrOpcode::kF64x2ExtractLane:
      return MarkAsFloat64(node), VisitF64x2ExtractLane(node);
    case IrOpcode::kF64x2ReplaceLane:
      return MarkAsSimd128(node), VisitF64x2ReplaceLane(node);
    case IrOpcode::kF64x2Abs:
      return MarkAsSimd128(node), VisitF64x2Abs(node);
    case IrOpcode::kF64x2Neg:
      return MarkAsSimd128(node), VisitF64x2Neg(node);
    case IrOpcode::kF64x2Sqrt:
      return MarkAsSimd128(node), VisitF64x2Sqrt(node);
    case IrOpcode::kF64x2Add:
      return MarkAsSimd128(node), VisitF64x2Add(node);
    case IrOpcode::kF64x2Sub:
      return MarkAsSimd128(node), VisitF64x2Sub(node);
    case IrOpcode::kF64x2Mul:
      return MarkAsSimd128(node), VisitF64x2Mul(node);
    case IrOpcode::kF64x2Div:
      return MarkAsSimd128(node), VisitF64x2Div(node);
    case IrOpcode::kF64x2Min:
      return MarkAsSimd128(node), VisitF64x2Min(node);
    case IrOpcode::kF64x2Max:
      return MarkAsSimd128(node), VisitF64x2Max(node);
    case IrOpcode::kF64x2Eq:
      return MarkAsSimd128(node), VisitF64x2Eq(node);
    case IrOpcode::kF64x2Ne:
      return MarkAsSimd128(node), VisitF64x2Ne(node);
    case IrOpcode::kF64x2Lt:
      return MarkAsSimd128(node), VisitF64x2Lt(node);
    case IrOpcode::kF64x2Le:
      return MarkAsSimd128(node), VisitF64x2Le(node);
    case IrOpcode::kF64x2Qfma:
      return MarkAsSimd128(node), VisitF64x2Qfma(node);
    case IrOpcode::kF64x2Qfms:
      return MarkAsSimd128(node), VisitF64x2Qfms(node);
    case IrOpcode::kF64x2Pmin:
      return MarkAsSimd128(node), VisitF64x2Pmin(node);
    case IrOpcode::kF64x2Pmax:
      return MarkAsSimd128(node), VisitF64x2Pmax(node);
    case IrOpcode::kF64x2Ceil:
      return MarkAsSimd128(node), VisitF64x2Ceil(node);
    case IrOpcode::kF64x2Floor:
      return MarkAsSimd128(node), VisitF64x2Floor(node);
    case IrOpcode::kF64x2Trunc:
      return MarkAsSimd128(node), VisitF64x2Trunc(node);
    case IrOpcode::kF64x2NearestInt:
      return MarkAsSimd128(node), VisitF64x2NearestInt(node);
    case IrOpcode::kF64x2ConvertLowI32x4S:
      return MarkAsSimd128(node), VisitF64x2ConvertLowI32x4S(node);
    case IrOpcode::kF64x2ConvertLowI32x4U:
      return MarkAsSimd128(node), VisitF64x2ConvertLowI32x4U(node);
    case IrOpcode::kF64x2PromoteLowF32x4:
      return MarkAsSimd128(node), VisitF64x2PromoteLowF32x4(node);
    case IrOpcode::kF32x4Splat:
      return MarkAsSimd128(node), VisitF32x4Splat(node);
    case IrOpcode::kF32x4ExtractLane:
      return MarkAsFloat32(node), VisitF32x4ExtractLane(node);
    case IrOpcode::kF32x4ReplaceLane:
      return MarkAsSimd128(node), VisitF32x4ReplaceLane(node);
    case IrOpcode::kF32x4SConvertI32x4:
      return MarkAsSimd128(node), VisitF32x4SConvertI32x4(node);
    case IrOpcode::kF32x4UConvertI32x4:
      return MarkAsSimd128(node), VisitF32x4UConvertI32x4(node);
    case IrOpcode::kF32x4Abs:
      return MarkAsSimd128(node), VisitF32x4Abs(node);
    case IrOpcode::kF32x4Neg:
      return MarkAsSimd128(node), VisitF32x4Neg(node);
    case IrOpcode::kF32x4Sqrt:
      return MarkAsSimd128(node), VisitF32x4Sqrt(node);
    case IrOpcode::kF32x4Add:
      return MarkAsSimd128(node), VisitF32x4Add(node);
    case IrOpcode::kF32x4Sub:
      return MarkAsSimd128(node), VisitF32x4Sub(node);
    case IrOpcode::kF32x4Mul:
      return MarkAsSimd128(node), VisitF32x4Mul(node);
    case IrOpcode::kF32x4Div:
      return MarkAsSimd128(node), VisitF32x4Div(node);
    case IrOpcode::kF32x4Min:
      return MarkAsSimd128(node), VisitF32x4Min(node);
    case IrOpcode::kF32x4Max:
      return MarkAsSimd128(node), VisitF32x4Max(node);
    case IrOpcode::kF32x4Eq:
      return MarkAsSimd128(node), VisitF32x4Eq(node);
    case IrOpcode::kF32x4Ne:
      return MarkAsSimd128(node), VisitF32x4Ne(node);
    case IrOpcode::kF32x4Lt:
      return MarkAsSimd128(node), VisitF32x4Lt(node);
    case IrOpcode::kF32x4Le:
      return MarkAsSimd128(node), VisitF32x4Le(node);
    case IrOpcode::kF32x4Qfma:
      return MarkAsSimd128(node), VisitF32x4Qfma(node);
    case IrOpcode::kF32x4Qfms:
      return MarkAsSimd128(node), VisitF32x4Qfms(node);
    case IrOpcode::kF32x4Pmin:
      return MarkAsSimd128(node), VisitF32x4Pmin(node);
    case IrOpcode::kF32x4Pmax:
      return MarkAsSimd128(node), VisitF32x4Pmax(node);
    case IrOpcode::kF32x4Ceil:
      return MarkAsSimd128(node), VisitF32x4Ceil(node);
    case IrOpcode::kF32x4Floor:
      return MarkAsSimd128(node), VisitF32x4Floor(node);
    case IrOpcode::kF32x4Trunc:
      return MarkAsSimd128(node), VisitF32x4Trunc(node);
    case IrOpcode::kF32x4NearestInt:
      return MarkAsSimd128(node), VisitF32x4NearestInt(node);
    case IrOpcode::kF32x4DemoteF64x2Zero:
      return MarkAsSimd128(node), VisitF32x4DemoteF64x2Zero(node);
    case IrOpcode::kI64x2Splat:
      return MarkAsSimd128(node), VisitI64x2Splat(node);
    case IrOpcode::kI64x2SplatI32Pair:
      return MarkAsSimd128(node), VisitI64x2SplatI32Pair(node);
    case IrOpcode::kI64x2ExtractLane:
      return MarkAsWord64(node), VisitI64x2ExtractLane(node);
    case IrOpcode::kI64x2ReplaceLane:
      return MarkAsSimd128(node), VisitI64x2ReplaceLane(node);
    case IrOpcode::kI64x2ReplaceLaneI32Pair:
      return MarkAsSimd128(node), VisitI64x2ReplaceLaneI32Pair(node);
    case IrOpcode::kI64x2Abs:
      return MarkAsSimd128(node), VisitI64x2Abs(node);
    case IrOpcode::kI64x2Neg:
      return MarkAsSimd128(node), VisitI64x2Neg(node);
    case IrOpcode::kI64x2SConvertI32x4Low:
      return MarkAsSimd128(node), VisitI64x2SConvertI32x4Low(node);
    case IrOpcode::kI64x2SConvertI32x4High:
      return MarkAsSimd128(node), VisitI64x2SConvertI32x4High(node);
    case IrOpcode::kI64x2UConvertI32x4Low:
      return MarkAsSimd128(node), VisitI64x2UConvertI32x4Low(node);
    case IrOpcode::kI64x2UConvertI32x4High:
      return MarkAsSimd128(node), VisitI64x2UConvertI32x4High(node);
    case IrOpcode::kI64x2BitMask:
      return MarkAsWord32(node), VisitI64x2BitMask(node);
    case IrOpcode::kI64x2Shl:
      return MarkAsSimd128(node), VisitI64x2Shl(node);
    case IrOpcode::kI64x2ShrS:
      return MarkAsSimd128(node), VisitI64x2ShrS(node);
    case IrOpcode::kI64x2Add:
      return MarkAsSimd128(node), VisitI64x2Add(node);
    case IrOpcode::kI64x2Sub:
      return MarkAsSimd128(node), VisitI64x2Sub(node);
    case IrOpcode::kI64x2Mul:
      return MarkAsSimd128(node), VisitI64x2Mul(node);
    case IrOpcode::kI64x2Eq:
      return MarkAsSimd128(node), VisitI64x2Eq(node);
    case IrOpcode::kI64x2Ne:
      return MarkAsSimd128(node), VisitI64x2Ne(node);
    case IrOpcode::kI64x2GtS:
      return MarkAsSimd128(node), VisitI64x2GtS(node);
    case IrOpcode::kI64x2GeS:
      return MarkAsSimd128(node), VisitI64x2GeS(node);
    case IrOpcode::kI64x2ShrU:
      return MarkAsSimd128(node), VisitI64x2ShrU(node);
    case IrOpcode::kI64x2ExtMulLowI32x4S:
      return MarkAsSimd128(node), VisitI64x2ExtMulLowI32x4S(node);
    case IrOpcode::kI64x2ExtMulHighI32x4S:
      return MarkAsSimd128(node), VisitI64x2ExtMulHighI32x4S(node);
    case IrOpcode::kI64x2ExtMulLowI32x4U:
      return MarkAsSimd128(node), VisitI64x2ExtMulLowI32x4U(node);
    case IrOpcode::kI64x2ExtMulHighI32x4U:
      return MarkAsSimd128(node), VisitI64x2ExtMulHighI32x4U(node);
    case IrOpcode::kI32x4Splat:
      return MarkAsSimd128(node), VisitI32x4Splat(node);
    case IrOpcode::kI32x4ExtractLane:
      return MarkAsWord32(node), VisitI32x4ExtractLane(node);
    case IrOpcode::kI32x4ReplaceLane:
      return MarkAsSimd128(node), VisitI32x4ReplaceLane(node);
    case IrOpcode::kI32x4SConvertF32x4:
      return MarkAsSimd128(node), VisitI32x4SConvertF32x4(node);
    case IrOpcode::kI32x4SConvertI16x8Low:
      return MarkAsSimd128(node), VisitI32x4SConvertI16x8Low(node);
    case IrOpcode::kI32x4SConvertI16x8High:
      return MarkAsSimd128(node), VisitI32x4SConvertI16x8High(node);
    case IrOpcode::kI32x4Neg:
      return MarkAsSimd128(node), VisitI32x4Neg(node);
    case IrOpcode::kI32x4Shl:
      return MarkAsSimd128(node), VisitI32x4Shl(node);
    case IrOpcode::kI32x4ShrS:
      return MarkAsSimd128(node), VisitI32x4ShrS(node);
    case IrOpcode::kI32x4Add:
      return MarkAsSimd128(node), VisitI32x4Add(node);
    case IrOpcode::kI32x4Sub:
      return MarkAsSimd128(node), VisitI32x4Sub(node);
    case IrOpcode::kI32x4Mul:
      return MarkAsSimd128(node), VisitI32x4Mul(node);
    case IrOpcode::kI32x4MinS:
      return MarkAsSimd128(node), VisitI32x4MinS(node);
    case IrOpcode::kI32x4MaxS:
      return MarkAsSimd128(node), VisitI32x4MaxS(node);
    case IrOpcode::kI32x4Eq:
      return MarkAsSimd128(node), VisitI32x4Eq(node);
    case IrOpcode::kI32x4Ne:
      return MarkAsSimd128(node), VisitI32x4Ne(node);
    case IrOpcode::kI32x4GtS:
      return MarkAsSimd128(node), VisitI32x4GtS(node);
    case IrOpcode::kI32x4GeS:
      return MarkAsSimd128(node), VisitI32x4GeS(node);
    case IrOpcode::kI32x4UConvertF32x4:
      return MarkAsSimd128(node), VisitI32x4UConvertF32x4(node);
    case IrOpcode::kI32x4UConvertI16x8Low:
      return MarkAsSimd128(node), VisitI32x4UConvertI16x8Low(node);
    case IrOpcode::kI32x4UConvertI16x8High:
      return MarkAsSimd128(node), VisitI32x4UConvertI16x8High(node);
    case IrOpcode::kI32x4ShrU:
      return MarkAsSimd128(node), VisitI32x4ShrU(node);
    case IrOpcode::kI32x4MinU:
      return MarkAsSimd128(node), VisitI32x4MinU(node);
    case IrOpcode::kI32x4MaxU:
      return MarkAsSimd128(node), VisitI32x4MaxU(node);
    case IrOpcode::kI32x4GtU:
      return MarkAsSimd128(node), VisitI32x4GtU(node);
    case IrOpcode::kI32x4GeU:
      return MarkAsSimd128(node), VisitI32x4GeU(node);
    case IrOpcode::kI32x4Abs:
      return MarkAsSimd128(node), VisitI32x4Abs(node);
    case IrOpcode::kI32x4BitMask:
      return MarkAsWord32(node), VisitI32x4BitMask(node);
    case IrOpcode::kI32x4DotI16x8S:
      return MarkAsSimd128(node), VisitI32x4DotI16x8S(node);
    case IrOpcode::kI32x4ExtMulLowI16x8S:
      return MarkAsSimd128(node), VisitI32x4ExtMulLowI16x8S(node);
    case IrOpcode::kI32x4ExtMulHighI16x8S:
      return MarkAsSimd128(node), VisitI32x4ExtMulHighI16x8S(node);
    case IrOpcode::kI32x4ExtMulLowI16x8U:
      return MarkAsSimd128(node), VisitI32x4ExtMulLowI16x8U(node);
    case IrOpcode::kI32x4ExtMulHighI16x8U:
      return MarkAsSimd128(node), VisitI32x4ExtMulHighI16x8U(node);
    case IrOpcode::kI32x4ExtAddPairwiseI16x8S:
      return MarkAsSimd128(node), VisitI32x4ExtAddPairwiseI16x8S(node);
    case IrOpcode::kI32x4ExtAddPairwiseI16x8U:
      return MarkAsSimd128(node), VisitI32x4ExtAddPairwiseI16x8U(node);
    case IrOpcode::kI32x4TruncSatF64x2SZero:
      return MarkAsSimd128(node), VisitI32x4TruncSatF64x2SZero(node);
    case IrOpcode::kI32x4TruncSatF64x2UZero:
      return MarkAsSimd128(node), VisitI32x4TruncSatF64x2UZero(node);
    case IrOpcode::kI16x8Splat:
      return MarkAsSimd128(node), VisitI16x8Splat(node);
    case IrOpcode::kI16x8ExtractLaneU:
      return MarkAsWord32(node), VisitI16x8ExtractLaneU(node);
    case IrOpcode::kI16x8ExtractLaneS:
      return MarkAsWord32(node), VisitI16x8ExtractLaneS(node);
    case IrOpcode::kI16x8ReplaceLane:
      return MarkAsSimd128(node), VisitI16x8ReplaceLane(node);
    case IrOpcode::kI16x8SConvertI8x16Low:
      return MarkAsSimd128(node), VisitI16x8SConvertI8x16Low(node);
    case IrOpcode::kI16x8SConvertI8x16High:
      return MarkAsSimd128(node), VisitI16x8SConvertI8x16High(node);
    case IrOpcode::kI16x8Neg:
      return MarkAsSimd128(node), VisitI16x8Neg(node);
    case IrOpcode::kI16x8Shl:
      return MarkAsSimd128(node), VisitI16x8Shl(node);
    case IrOpcode::kI16x8ShrS:
      return MarkAsSimd128(node), VisitI16x8ShrS(node);
    case IrOpcode::kI16x8SConvertI32x4:
      return MarkAsSimd128(node), VisitI16x8SConvertI32x4(node);
    case IrOpcode::kI16x8Add:
      return MarkAsSimd128(node), VisitI16x8Add(node);
    case IrOpcode::kI16x8AddSatS:
      return MarkAsSimd128(node), VisitI16x8AddSatS(node);
    case IrOpcode::kI16x8Sub:
      return MarkAsSimd128(node), VisitI16x8Sub(node);
    case IrOpcode::kI16x8SubSatS:
      return
```