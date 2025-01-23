Response:
The user wants a summary of the provided C++ code snippet.
The code is part of the V8 JavaScript engine and deals with the interpreter.
It seems to define how different bytecode instructions are handled by the interpreter.

Here's a breakdown of the structure and likely functionality:

1. **`IGNITION_HANDLER` macros:** These likely define handlers for specific bytecode instructions.
2. **Instruction names:**  The names of the handlers (e.g., `LdaModuleVariable`, `StaModuleVariable`, `Add`, `Sub`, `CallAnyReceiver`) suggest the operations they perform.
3. **`InterpreterAssembler` and related classes:** These are likely utility classes for generating the interpreter's code.
4. **Feedback:** Mentions of "feedback" indicate that the interpreter collects information about the types of objects it encounters to optimize future executions.
5. **Context manipulation:** Instructions like `PushContext` and `PopContext` deal with managing the execution context.
6. **Binary and Unary operations:**  Handlers for arithmetic, bitwise, and logical operations are present.
7. **Function calls:**  Handlers for different kinds of function calls (JS calls, runtime calls, intrinsic calls) are included.
8. **Property access:** Instructions for deleting properties are present.
9. **Type conversions:** Instructions for converting values to different types (e.g., `ToName`, `ToNumber`, `ToString`).
10. **Comparisons:** Instructions for performing comparisons.

The request specifically asks for:

*   **Functionality:** A description of what the code does.
*   **Torque source:** Checking if the file name implies it's a Torque file (it's not).
*   **JavaScript relation:**  Examples of how the code relates to JavaScript.
*   **Logic reasoning:**  Hypothetical input and output for some instructions.
*   **Common errors:** Examples of programming errors related to the code.
*   **Summary:** A concise overview of the code's purpose.

Considering this is part 2 of 4, it likely focuses on a specific set of bytecode instructions. Part 1 probably covered foundational aspects, and parts 3 and 4 will likely cover other categories of instructions.

**Plan:**

1. State that the code is C++ for the V8 interpreter.
2. Confirm it's not Torque.
3. Explain that it defines handlers for bytecode instructions.
4. Provide JavaScript examples for some key instruction categories (e.g., variable access, arithmetic, function calls).
5. Give input/output examples for a few instructions like `Add` and `LdaModuleVariable`.
6. Illustrate common errors related to these operations (e.g., type errors in arithmetic, incorrect module imports).
7. Summarize the functionalities covered in this part.
这是 V8 源代码 `v8/src/interpreter/interpreter-generator.cc` 的一部分，它定义了 V8 JavaScript 引擎的解释器如何处理一系列特定的字节码指令。

**功能归纳:**

这部分代码主要定义了以下功能的实现：

1. **模块变量的加载和存储:**  `LdaModuleVariable` 和 `StaModuleVariable` 指令用于从模块作用域中加载和存储变量。这涉及到查找模块的导出和导入列表。
2. **上下文管理:** `PushContext` 和 `PopContext` 指令用于在执行代码时管理执行上下文的堆栈。
3. **二元运算符:**  定义了各种二元算术运算符（加、减、乘、除、模、幂）和位运算符（或、异或、与、左移、右移、无符号右移）的字节码处理逻辑。这些指令可以操作寄存器中的值或者立即数。
4. **一元运算符:**  定义了一元运算符，如取负 (`Negate`) 和按位取反 (虽然被 `#ifndef V8_ENABLE_EXPERIMENTAL_TSA_BUILTINS` 包裹，但仍然存在)。
5. **类型转换:**  实现了将值转换为不同类型的字节码指令，例如 `ToName` (转换为字符串或 Symbol)、`ToNumber`、`ToNumeric`、`ToObject` (转换为对象)、`ToString` (转换为字符串)、`ToBoolean` (转换为布尔值)。
6. **递增/递减运算符:**  实现了 `Inc` (递增) 和 `Dec` (递减) 运算符。
7. **逻辑非运算符:**  实现了逻辑非运算符 `LogicalNot` 和 `ToBooleanLogicalNot`（先转换为布尔值再取反）。
8. **类型判断:**  实现了 `TypeOf` 运算符，用于获取操作数类型的字符串表示。
9. **属性删除:**  实现了 `DeletePropertyStrict` (严格模式) 和 `DeletePropertySloppy` (非严格模式) 运算符，用于删除对象的属性。
10. **获取父类构造函数:** 实现了 `GetSuperConstructor` 运算符。
11. **函数调用:**  定义了多种函数调用相关的指令，包括：
    *   `CallAnyReceiver`:  通用函数调用。
    *   `CallProperty`:  调用属性上的函数。
    *   `CallUndefinedReceiver`:  接收者为 `undefined` 的函数调用。
    *   `CallRuntime`:  调用运行时 (C++) 函数。
    *   `InvokeIntrinsic`:  调用内置的优化过的函数。
    *   `CallRuntimeForPair`:  调用返回两个值的运行时函数。
    *   `CallJSRuntime`:  调用 JavaScript 运行时函数。
    *   `CallWithSpread`:  带有展开运算符的函数调用。
12. **构造函数调用:**  定义了构造函数调用相关的指令：
    *   `ConstructWithSpread`:  带有展开运算符的构造函数调用。
    *   `ConstructForwardAllArgs`:  转发所有参数的构造函数调用。
    *   `Construct`:  标准的构造函数调用。
13. **比较运算符:**  定义了比较运算符（等于、严格等于、小于、大于、小于等于、大于等于）的字节码处理逻辑，并包含了类型反馈机制。

**关于文件类型和 Torque：**

你说的没错，如果 `v8/src/interpreter/interpreter-generator.cc` 以 `.tq` 结尾，那它就是一个 V8 Torque 源代码。但由于它以 `.cc` 结尾，所以它是一个标准的 C++ 源代码文件。 Torque 是一种 V8 自研的类型化的领域特定语言，用于生成高效的 C++ 代码，常用于实现内置函数和运行时功能。

**与 JavaScript 的关系及示例：**

这部分 C++ 代码直接对应于 JavaScript 代码的执行。当 V8 解释执行 JavaScript 代码时，会将代码编译成字节码，然后由这些 C++ 函数来处理这些字节码指令。

以下是一些 JavaScript 示例以及它们可能对应的字节码指令：

*   **模块变量访问:**

    ```javascript
    // module.js
    export const exportedValue = 10;

    // main.js
    import { exportedValue } from './module.js';
    console.log(exportedValue); // 对应 LdaModuleVariable 指令
    ```

*   **加法运算:**

    ```javascript
    let a = 5;
    let b = 3;
    let sum = a + b; // 对应 Add 指令
    ```

*   **函数调用:**

    ```javascript
    function myFunction(x, y) {
      return x * y;
    }
    let result = myFunction(2, 4); // 对应 CallAnyReceiver 或 CallProperty 指令
    ```

*   **类型转换:**

    ```javascript
    let num = 10;
    let str = String(num); // 对应 ToString 指令
    let bool = Boolean(0); // 对应 ToBoolean 指令
    ```

*   **创建对象:**

    ```javascript
    class MyClass {}
    let obj = new MyClass(); // 对应 Construct 指令
    ```

**代码逻辑推理：**

以 `LdaModuleVariable` 指令为例：

**假设输入：**

*   `cell_index`:  一个整数，表示要加载的模块变量在模块的导出或导入列表中的索引。正数表示导出，负数表示导入。
*   `depth`: 一个整数，表示当前上下文相对于模块上下文的深度。

**输出：**

*   将加载的模块变量的值存储到累加器 (Accumulator) 中。

**逻辑流程：**

1. 根据 `depth` 获取模块的上下文。
2. 根据 `cell_index` 的正负判断是导出还是导入。
3. 如果是导出（`cell_index > 0`）：
    *   从模块的 `regular_exports` 数组中获取对应的 Cell 对象。
    *   从 Cell 对象中加载实际的值并设置到累加器。
4. 如果是导入（`cell_index <= 0`）：
    *   从模块的 `regular_imports` 数组中获取对应的 Cell 对象。
    *   从 Cell 对象中加载实际的值并设置到累加器。
5. 执行 `Dispatch()`，跳转到下一条字节码指令的处理。

以 `Add` 指令为例：

**假设输入：**

*   累加器中存储着一个值（右操作数）。
*   索引为 0 的操作数寄存器中存储着另一个值（左操作数）。

**输出：**

*   将两个操作数的和计算出来，并存储到累加器中。

**逻辑流程：**

1. 从索引为 0 的操作数寄存器中加载左操作数。
2. 获取累加器中的右操作数。
3. 调用 `BinaryOpAssembler::Generate_AddWithFeedback` 函数执行加法运算，并可能收集类型反馈信息。
4. 将结果存储到累加器中。
5. 执行 `Dispatch()`，跳转到下一条字节码指令的处理。

**用户常见的编程错误：**

*   **类型错误：**  在进行算术或位运算时，如果操作数的类型不符合预期，会导致运行时错误或意外的结果。例如，尝试将一个字符串与一个数字相加，可能会发生隐式类型转换，导致非预期的行为。

    ```javascript
    let a = 5;
    let b = "3";
    let sum = a + b; // 结果是字符串 "53"，而不是数字 8
    ```

*   **模块导入错误：**  在使用模块时，如果导入的变量名不存在于导出的模块中，或者导入路径错误，会导致 `LdaModuleVariable` 指令找不到对应的变量。

    ```javascript
    // module.js
    export const value = 10;

    // main.js
    import { wrongName } from './module.js'; // 错误：模块中没有导出名为 wrongName 的变量
    console.log(wrongName);
    ```

*   **上下文错误：**  在复杂的代码结构中，如果上下文管理不当，可能会导致变量查找错误。例如，在闭包或嵌套函数中错误地访问了外部作用域的变量。虽然这里的 `PushContext` 和 `PopContext` 是 V8 内部的机制，但理解上下文对于避免 JavaScript 中的作用域问题很重要。

*   **未定义或空值错误：**  对 `undefined` 或 `null` 值执行某些操作（例如，访问属性或调用方法）会导致运行时错误。相关的字节码指令（如属性访问或函数调用）会触发相应的错误处理。

    ```javascript
    let obj = null;
    console.log(obj.property); // TypeError: Cannot read properties of null
    ```

这部分代码是 V8 解释器实现的核心组成部分，它将高级的 JavaScript 语义转换为底层的机器操作。理解这部分代码有助于深入了解 JavaScript 的执行原理。

### 提示词
```
这是目录为v8/src/interpreter/interpreter-generator.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/interpreter/interpreter-generator.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
ontext::EXTENSION_INDEX));

  Label if_export(this), if_import(this), end(this);
  Branch(IntPtrGreaterThan(cell_index, IntPtrConstant(0)), &if_export,
         &if_import);

  BIND(&if_export);
  {
    TNode<FixedArray> regular_exports = LoadObjectField<FixedArray>(
        module, SourceTextModule::kRegularExportsOffset);
    // The actual array index is (cell_index - 1).
    TNode<IntPtrT> export_index = IntPtrSub(cell_index, IntPtrConstant(1));
    TNode<Cell> cell =
        CAST(LoadFixedArrayElement(regular_exports, export_index));
    SetAccumulator(LoadObjectField(cell, Cell::kValueOffset));
    Goto(&end);
  }

  BIND(&if_import);
  {
    TNode<FixedArray> regular_imports = LoadObjectField<FixedArray>(
        module, SourceTextModule::kRegularImportsOffset);
    // The actual array index is (-cell_index - 1).
    TNode<IntPtrT> import_index = IntPtrSub(IntPtrConstant(-1), cell_index);
    TNode<Cell> cell =
        CAST(LoadFixedArrayElement(regular_imports, import_index));
    SetAccumulator(LoadObjectField(cell, Cell::kValueOffset));
    Goto(&end);
  }

  BIND(&end);
  Dispatch();
}

// StaModuleVariable <cell_index> <depth>
//
// Store accumulator to the module variable identified by <cell_index>.
// <depth> is the depth of the current context relative to the module context.
IGNITION_HANDLER(StaModuleVariable, InterpreterAssembler) {
  TNode<Object> value = GetAccumulator();
  TNode<IntPtrT> cell_index = BytecodeOperandImmIntPtr(0);
  TNode<Uint32T> depth = BytecodeOperandUImm(1);

  TNode<Context> module_context = GetContextAtDepth(GetContext(), depth);
  TNode<SourceTextModule> module =
      CAST(LoadContextElement(module_context, Context::EXTENSION_INDEX));

  Label if_export(this), if_import(this), end(this);
  Branch(IntPtrGreaterThan(cell_index, IntPtrConstant(0)), &if_export,
         &if_import);

  BIND(&if_export);
  {
    TNode<FixedArray> regular_exports = LoadObjectField<FixedArray>(
        module, SourceTextModule::kRegularExportsOffset);
    // The actual array index is (cell_index - 1).
    TNode<IntPtrT> export_index = IntPtrSub(cell_index, IntPtrConstant(1));
    TNode<HeapObject> cell =
        CAST(LoadFixedArrayElement(regular_exports, export_index));
    StoreObjectField(cell, Cell::kValueOffset, value);
    Goto(&end);
  }

  BIND(&if_import);
  {
    // Not supported (probably never).
    Abort(AbortReason::kUnsupportedModuleOperation);
    Goto(&end);
  }

  BIND(&end);
  Dispatch();
}

// PushContext <context>
//
// Saves the current context in <context>, and pushes the accumulator as the
// new current context.
IGNITION_HANDLER(PushContext, InterpreterAssembler) {
  TNode<Context> new_context = CAST(GetAccumulator());
  TNode<Context> old_context = GetContext();
  StoreRegisterAtOperandIndex(old_context, 0);
  SetContext(new_context);
  Dispatch();
}

// PopContext <context>
//
// Pops the current context and sets <context> as the new context.
IGNITION_HANDLER(PopContext, InterpreterAssembler) {
  TNode<Context> context = CAST(LoadRegisterAtOperandIndex(0));
  SetContext(context);
  Dispatch();
}

class InterpreterBinaryOpAssembler : public InterpreterAssembler {
 public:
  InterpreterBinaryOpAssembler(CodeAssemblerState* state, Bytecode bytecode,
                               OperandScale operand_scale)
      : InterpreterAssembler(state, bytecode, operand_scale) {}

  using BinaryOpGenerator = TNode<Object> (BinaryOpAssembler::*)(
      const LazyNode<Context>& context, TNode<Object> left, TNode<Object> right,
      TNode<UintPtrT> slot, const LazyNode<HeapObject>& maybe_feedback_vector,
      UpdateFeedbackMode update_feedback_mode, bool rhs_known_smi);

  void BinaryOpWithFeedback(BinaryOpGenerator generator) {
    TNode<Object> lhs = LoadRegisterAtOperandIndex(0);
    TNode<Object> rhs = GetAccumulator();
    TNode<Context> context = GetContext();
    TNode<UintPtrT> slot_index = BytecodeOperandIdx(1);
    TNode<HeapObject> maybe_feedback_vector =
        LoadFeedbackVectorOrUndefinedIfJitless();
    static constexpr UpdateFeedbackMode mode = DefaultUpdateFeedbackMode();

    BinaryOpAssembler binop_asm(state());
    TNode<Object> result = (binop_asm.*generator)(
        [=] { return context; }, lhs, rhs, slot_index,
        [=] { return maybe_feedback_vector; }, mode, false);
    SetAccumulator(result);
    Dispatch();
  }

  void BinaryOpSmiWithFeedback(BinaryOpGenerator generator) {
    TNode<Object> lhs = GetAccumulator();
    TNode<Smi> rhs = BytecodeOperandImmSmi(0);
    TNode<Context> context = GetContext();
    TNode<UintPtrT> slot_index = BytecodeOperandIdx(1);
    TNode<HeapObject> maybe_feedback_vector =
        LoadFeedbackVectorOrUndefinedIfJitless();
    static constexpr UpdateFeedbackMode mode = DefaultUpdateFeedbackMode();

    BinaryOpAssembler binop_asm(state());
    TNode<Object> result = (binop_asm.*generator)(
        [=] { return context; }, lhs, rhs, slot_index,
        [=] { return maybe_feedback_vector; }, mode, true);
    SetAccumulator(result);
    Dispatch();
  }
};

// Add <src>
//
// Add register <src> to accumulator.
IGNITION_HANDLER(Add, InterpreterBinaryOpAssembler) {
  BinaryOpWithFeedback(&BinaryOpAssembler::Generate_AddWithFeedback);
}

// Sub <src>
//
// Subtract register <src> from accumulator.
IGNITION_HANDLER(Sub, InterpreterBinaryOpAssembler) {
  BinaryOpWithFeedback(&BinaryOpAssembler::Generate_SubtractWithFeedback);
}

// Mul <src>
//
// Multiply accumulator by register <src>.
IGNITION_HANDLER(Mul, InterpreterBinaryOpAssembler) {
  BinaryOpWithFeedback(&BinaryOpAssembler::Generate_MultiplyWithFeedback);
}

// Div <src>
//
// Divide register <src> by accumulator.
IGNITION_HANDLER(Div, InterpreterBinaryOpAssembler) {
  BinaryOpWithFeedback(&BinaryOpAssembler::Generate_DivideWithFeedback);
}

// Mod <src>
//
// Modulo register <src> by accumulator.
IGNITION_HANDLER(Mod, InterpreterBinaryOpAssembler) {
  BinaryOpWithFeedback(&BinaryOpAssembler::Generate_ModulusWithFeedback);
}

// Exp <src>
//
// Exponentiate register <src> (base) with accumulator (exponent).
IGNITION_HANDLER(Exp, InterpreterBinaryOpAssembler) {
  BinaryOpWithFeedback(&BinaryOpAssembler::Generate_ExponentiateWithFeedback);
}

// AddSmi <imm>
//
// Adds an immediate value <imm> to the value in the accumulator.
IGNITION_HANDLER(AddSmi, InterpreterBinaryOpAssembler) {
  BinaryOpSmiWithFeedback(&BinaryOpAssembler::Generate_AddWithFeedback);
}

// SubSmi <imm>
//
// Subtracts an immediate value <imm> from the value in the accumulator.
IGNITION_HANDLER(SubSmi, InterpreterBinaryOpAssembler) {
  BinaryOpSmiWithFeedback(&BinaryOpAssembler::Generate_SubtractWithFeedback);
}

// MulSmi <imm>
//
// Multiplies an immediate value <imm> to the value in the accumulator.
IGNITION_HANDLER(MulSmi, InterpreterBinaryOpAssembler) {
  BinaryOpSmiWithFeedback(&BinaryOpAssembler::Generate_MultiplyWithFeedback);
}

// DivSmi <imm>
//
// Divides the value in the accumulator by immediate value <imm>.
IGNITION_HANDLER(DivSmi, InterpreterBinaryOpAssembler) {
  BinaryOpSmiWithFeedback(&BinaryOpAssembler::Generate_DivideWithFeedback);
}

// ModSmi <imm>
//
// Modulo accumulator by immediate value <imm>.
IGNITION_HANDLER(ModSmi, InterpreterBinaryOpAssembler) {
  BinaryOpSmiWithFeedback(&BinaryOpAssembler::Generate_ModulusWithFeedback);
}

// ExpSmi <imm>
//
// Exponentiate accumulator (base) with immediate value <imm> (exponent).
IGNITION_HANDLER(ExpSmi, InterpreterBinaryOpAssembler) {
  BinaryOpSmiWithFeedback(
      &BinaryOpAssembler::Generate_ExponentiateWithFeedback);
}

class InterpreterBitwiseBinaryOpAssembler : public InterpreterAssembler {
 public:
  InterpreterBitwiseBinaryOpAssembler(CodeAssemblerState* state,
                                      Bytecode bytecode,
                                      OperandScale operand_scale)
      : InterpreterAssembler(state, bytecode, operand_scale) {}

  void BitwiseBinaryOpWithFeedback(Operation bitwise_op) {
    TNode<Object> left = LoadRegisterAtOperandIndex(0);
    TNode<Object> right = GetAccumulator();
    TNode<Context> context = GetContext();
    TNode<UintPtrT> slot_index = BytecodeOperandIdx(1);
    TNode<HeapObject> maybe_feedback_vector =
        LoadFeedbackVectorOrUndefinedIfJitless();
    static constexpr UpdateFeedbackMode mode = DefaultUpdateFeedbackMode();

    BinaryOpAssembler binop_asm(state());
    TNode<Object> result = binop_asm.Generate_BitwiseBinaryOpWithFeedback(
        bitwise_op, left, right, [=] { return context; }, slot_index,
        [=] { return maybe_feedback_vector; }, mode, false);

    SetAccumulator(result);
    Dispatch();
  }

  void BitwiseBinaryOpWithSmi(Operation bitwise_op) {
    TNode<Object> left = GetAccumulator();
    TNode<Smi> right = BytecodeOperandImmSmi(0);
    TNode<UintPtrT> slot_index = BytecodeOperandIdx(1);
    TNode<Context> context = GetContext();
    TNode<HeapObject> maybe_feedback_vector =
        LoadFeedbackVectorOrUndefinedIfJitless();
    static constexpr UpdateFeedbackMode mode = DefaultUpdateFeedbackMode();

    BinaryOpAssembler binop_asm(state());
    TNode<Object> result = binop_asm.Generate_BitwiseBinaryOpWithFeedback(
        bitwise_op, left, right, [=] { return context; }, slot_index,
        [=] { return maybe_feedback_vector; }, mode, true);

    SetAccumulator(result);
    Dispatch();
  }
};

// BitwiseOr <src>
//
// BitwiseOr register <src> to accumulator.
IGNITION_HANDLER(BitwiseOr, InterpreterBitwiseBinaryOpAssembler) {
  BitwiseBinaryOpWithFeedback(Operation::kBitwiseOr);
}

// BitwiseXor <src>
//
// BitwiseXor register <src> to accumulator.
IGNITION_HANDLER(BitwiseXor, InterpreterBitwiseBinaryOpAssembler) {
  BitwiseBinaryOpWithFeedback(Operation::kBitwiseXor);
}

// BitwiseAnd <src>
//
// BitwiseAnd register <src> to accumulator.
IGNITION_HANDLER(BitwiseAnd, InterpreterBitwiseBinaryOpAssembler) {
  BitwiseBinaryOpWithFeedback(Operation::kBitwiseAnd);
}

// ShiftLeft <src>
//
// Left shifts register <src> by the count specified in the accumulator.
// Register <src> is converted to an int32 and the accumulator to uint32
// before the operation. 5 lsb bits from the accumulator are used as count
// i.e. <src> << (accumulator & 0x1F).
IGNITION_HANDLER(ShiftLeft, InterpreterBitwiseBinaryOpAssembler) {
  BitwiseBinaryOpWithFeedback(Operation::kShiftLeft);
}

// ShiftRight <src>
//
// Right shifts register <src> by the count specified in the accumulator.
// Result is sign extended. Register <src> is converted to an int32 and the
// accumulator to uint32 before the operation. 5 lsb bits from the accumulator
// are used as count i.e. <src> >> (accumulator & 0x1F).
IGNITION_HANDLER(ShiftRight, InterpreterBitwiseBinaryOpAssembler) {
  BitwiseBinaryOpWithFeedback(Operation::kShiftRight);
}

// ShiftRightLogical <src>
//
// Right Shifts register <src> by the count specified in the accumulator.
// Result is zero-filled. The accumulator and register <src> are converted to
// uint32 before the operation 5 lsb bits from the accumulator are used as
// count i.e. <src> << (accumulator & 0x1F).
IGNITION_HANDLER(ShiftRightLogical, InterpreterBitwiseBinaryOpAssembler) {
  BitwiseBinaryOpWithFeedback(Operation::kShiftRightLogical);
}

// BitwiseOrSmi <imm>
//
// BitwiseOrSmi accumulator with <imm>.
IGNITION_HANDLER(BitwiseOrSmi, InterpreterBitwiseBinaryOpAssembler) {
  BitwiseBinaryOpWithSmi(Operation::kBitwiseOr);
}

// BitwiseXorSmi <imm>
//
// BitwiseXorSmi accumulator with <imm>.
IGNITION_HANDLER(BitwiseXorSmi, InterpreterBitwiseBinaryOpAssembler) {
  BitwiseBinaryOpWithSmi(Operation::kBitwiseXor);
}

// BitwiseAndSmi <imm>
//
// BitwiseAndSmi accumulator with <imm>.
IGNITION_HANDLER(BitwiseAndSmi, InterpreterBitwiseBinaryOpAssembler) {
  BitwiseBinaryOpWithSmi(Operation::kBitwiseAnd);
}

#ifndef V8_ENABLE_EXPERIMENTAL_TSA_BUILTINS

// BitwiseNot <feedback_slot>
//
// Perform bitwise-not on the accumulator.
IGNITION_HANDLER(BitwiseNot, InterpreterAssembler) {
  TNode<Object> value = GetAccumulator();
  TNode<Context> context = GetContext();
  TNode<UintPtrT> slot_index = BytecodeOperandIdx(0);
  TNode<HeapObject> maybe_feedback_vector =
      LoadFeedbackVectorOrUndefinedIfJitless();
  static constexpr UpdateFeedbackMode mode = DefaultUpdateFeedbackMode();

  UnaryOpAssembler unary_op_asm(state());
  TNode<Object> result = unary_op_asm.Generate_BitwiseNotWithFeedback(
      context, value, slot_index, maybe_feedback_vector, mode);

  SetAccumulator(result);
  Dispatch();
}

#endif

// ShiftLeftSmi <imm>
//
// Left shifts accumulator by the count specified in <imm>.
// The accumulator is converted to an int32 before the operation. The 5
// lsb bits from <imm> are used as count i.e. <src> << (<imm> & 0x1F).
IGNITION_HANDLER(ShiftLeftSmi, InterpreterBitwiseBinaryOpAssembler) {
  BitwiseBinaryOpWithSmi(Operation::kShiftLeft);
}

// ShiftRightSmi <imm>
//
// Right shifts accumulator by the count specified in <imm>. Result is sign
// extended. The accumulator is converted to an int32 before the operation. The
// 5 lsb bits from <imm> are used as count i.e. <src> >> (<imm> & 0x1F).
IGNITION_HANDLER(ShiftRightSmi, InterpreterBitwiseBinaryOpAssembler) {
  BitwiseBinaryOpWithSmi(Operation::kShiftRight);
}

// ShiftRightLogicalSmi <imm>
//
// Right shifts accumulator by the count specified in <imm>. Result is zero
// extended. The accumulator is converted to an int32 before the operation. The
// 5 lsb bits from <imm> are used as count i.e. <src> >>> (<imm> & 0x1F).
IGNITION_HANDLER(ShiftRightLogicalSmi, InterpreterBitwiseBinaryOpAssembler) {
  BitwiseBinaryOpWithSmi(Operation::kShiftRightLogical);
}

// Negate <feedback_slot>
//
// Perform arithmetic negation on the accumulator.
IGNITION_HANDLER(Negate, InterpreterAssembler) {
  TNode<Object> value = GetAccumulator();
  TNode<Context> context = GetContext();
  TNode<UintPtrT> slot_index = BytecodeOperandIdx(0);
  TNode<HeapObject> maybe_feedback_vector =
      LoadFeedbackVectorOrUndefinedIfJitless();
  static constexpr UpdateFeedbackMode mode = DefaultUpdateFeedbackMode();

  UnaryOpAssembler unary_op_asm(state());
  TNode<Object> result = unary_op_asm.Generate_NegateWithFeedback(
      context, value, slot_index, maybe_feedback_vector, mode);

  SetAccumulator(result);
  Dispatch();
}

// ToName <dst>
//
// Convert the object referenced by the accumulator to a name.
IGNITION_HANDLER(ToName, InterpreterAssembler) {
  TNode<Object> object = GetAccumulator();
  TNode<Context> context = GetContext();
  TNode<Object> result = CallBuiltin(Builtin::kToName, context, object);
  SetAccumulator(result);
  Dispatch();
}

// ToNumber <slot>
//
// Convert the object referenced by the accumulator to a number.
IGNITION_HANDLER(ToNumber, InterpreterAssembler) {
  ToNumberOrNumeric(Object::Conversion::kToNumber);
}

// ToNumeric <slot>
//
// Convert the object referenced by the accumulator to a numeric.
IGNITION_HANDLER(ToNumeric, InterpreterAssembler) {
  ToNumberOrNumeric(Object::Conversion::kToNumeric);
}

// ToObject <dst>
//
// Convert the object referenced by the accumulator to a JSReceiver.
IGNITION_HANDLER(ToObject, InterpreterAssembler) {
  TNode<Object> accumulator = GetAccumulator();
  TNode<Context> context = GetContext();
  TNode<Object> result = CallBuiltin(Builtin::kToObject, context, accumulator);
  StoreRegisterAtOperandIndex(result, 0);
  Dispatch();
}

// ToString
//
// Convert the accumulator to a String.
IGNITION_HANDLER(ToString, InterpreterAssembler) {
  SetAccumulator(ToString_Inline(GetContext(), GetAccumulator()));
  Dispatch();
}

// ToString
//
// Convert the accumulator to a String.
IGNITION_HANDLER(ToBoolean, InterpreterAssembler) {
  TNode<Object> value = GetAccumulator();
  TVARIABLE(Boolean, result);
  Label if_true(this), if_false(this), end(this);
  BranchIfToBooleanIsTrue(value, &if_true, &if_false);
  BIND(&if_true);
  {
    result = TrueConstant();
    Goto(&end);
  }
  BIND(&if_false);
  {
    result = FalseConstant();
    Goto(&end);
  }
  BIND(&end);
  SetAccumulator(result.value());
  Dispatch();
}

// Inc
//
// Increments value in the accumulator by one.
IGNITION_HANDLER(Inc, InterpreterAssembler) {
  TNode<Object> value = GetAccumulator();
  TNode<Context> context = GetContext();
  TNode<UintPtrT> slot_index = BytecodeOperandIdx(0);
  TNode<HeapObject> maybe_feedback_vector =
      LoadFeedbackVectorOrUndefinedIfJitless();
  static constexpr UpdateFeedbackMode mode = DefaultUpdateFeedbackMode();

  UnaryOpAssembler unary_op_asm(state());
  TNode<Object> result = unary_op_asm.Generate_IncrementWithFeedback(
      context, value, slot_index, maybe_feedback_vector, mode);

  SetAccumulator(result);
  Dispatch();
}

// Dec
//
// Decrements value in the accumulator by one.
IGNITION_HANDLER(Dec, InterpreterAssembler) {
  TNode<Object> value = GetAccumulator();
  TNode<Context> context = GetContext();
  TNode<UintPtrT> slot_index = BytecodeOperandIdx(0);
  TNode<HeapObject> maybe_feedback_vector =
      LoadFeedbackVectorOrUndefinedIfJitless();
  static constexpr UpdateFeedbackMode mode = DefaultUpdateFeedbackMode();

  UnaryOpAssembler unary_op_asm(state());
  TNode<Object> result = unary_op_asm.Generate_DecrementWithFeedback(
      context, value, slot_index, maybe_feedback_vector, mode);

  SetAccumulator(result);
  Dispatch();
}

// ToBooleanLogicalNot
//
// Perform logical-not on the accumulator, first casting the
// accumulator to a boolean value if required.
IGNITION_HANDLER(ToBooleanLogicalNot, InterpreterAssembler) {
  TNode<Object> value = GetAccumulator();
  TVARIABLE(Boolean, result);
  Label if_true(this), if_false(this), end(this);
  BranchIfToBooleanIsTrue(value, &if_true, &if_false);
  BIND(&if_true);
  {
    result = FalseConstant();
    Goto(&end);
  }
  BIND(&if_false);
  {
    result = TrueConstant();
    Goto(&end);
  }
  BIND(&end);
  SetAccumulator(result.value());
  Dispatch();
}

// LogicalNot
//
// Perform logical-not on the accumulator, which must already be a boolean
// value.
IGNITION_HANDLER(LogicalNot, InterpreterAssembler) {
  TNode<Object> value = GetAccumulator();
  TVARIABLE(Boolean, result);
  Label if_true(this), if_false(this), end(this);
  TNode<True> true_value = TrueConstant();
  TNode<False> false_value = FalseConstant();
  Branch(TaggedEqual(value, true_value), &if_true, &if_false);
  BIND(&if_true);
  {
    result = false_value;
    Goto(&end);
  }
  BIND(&if_false);
  {
    CSA_DCHECK(this, TaggedEqual(value, false_value));
    result = true_value;
    Goto(&end);
  }
  BIND(&end);
  SetAccumulator(result.value());
  Dispatch();
}

// TypeOf
//
// Load the accumulator with the string representating type of the
// object in the accumulator.
IGNITION_HANDLER(TypeOf, InterpreterAssembler) {
  TNode<Object> value = GetAccumulator();
  TNode<UintPtrT> slot_id = BytecodeOperandIdx(0);
  TNode<HeapObject> maybe_feedback_vector = LoadFeedbackVector();
  TNode<String> result = Typeof(value, slot_id, maybe_feedback_vector);
  SetAccumulator(result);
  Dispatch();
}

// DeletePropertyStrict
//
// Delete the property specified in the accumulator from the object
// referenced by the register operand following strict mode semantics.
IGNITION_HANDLER(DeletePropertyStrict, InterpreterAssembler) {
  TNode<Object> object = LoadRegisterAtOperandIndex(0);
  TNode<Object> key = GetAccumulator();
  TNode<Context> context = GetContext();
  TNode<Object> result =
      CallBuiltin(Builtin::kDeleteProperty, context, object, key,
                  SmiConstant(Smi::FromEnum(LanguageMode::kStrict)));
  SetAccumulator(result);
  Dispatch();
}

// DeletePropertySloppy
//
// Delete the property specified in the accumulator from the object
// referenced by the register operand following sloppy mode semantics.
IGNITION_HANDLER(DeletePropertySloppy, InterpreterAssembler) {
  TNode<Object> object = LoadRegisterAtOperandIndex(0);
  TNode<Object> key = GetAccumulator();
  TNode<Context> context = GetContext();
  TNode<Object> result =
      CallBuiltin(Builtin::kDeleteProperty, context, object, key,
                  SmiConstant(Smi::FromEnum(LanguageMode::kSloppy)));
  SetAccumulator(result);
  Dispatch();
}

// GetSuperConstructor
//
// Get the super constructor from the object referenced by the accumulator.
// The result is stored in register |reg|.
IGNITION_HANDLER(GetSuperConstructor, InterpreterAssembler) {
  TNode<JSFunction> active_function = CAST(GetAccumulator());
  TNode<Object> result = GetSuperConstructor(active_function);
  StoreRegisterAtOperandIndex(result, 0);
  Dispatch();
}

class InterpreterJSCallAssembler : public InterpreterAssembler {
 public:
  InterpreterJSCallAssembler(CodeAssemblerState* state, Bytecode bytecode,
                             OperandScale operand_scale)
      : InterpreterAssembler(state, bytecode, operand_scale) {}

  // Generates code to perform a JS call that collects type feedback.
  void JSCall(ConvertReceiverMode receiver_mode) {
    TNode<Object> function = LoadRegisterAtOperandIndex(0);
    RegListNodePair args = GetRegisterListAtOperandIndex(1);
    TNode<Context> context = GetContext();

#ifndef V8_JITLESS
    // Collect the {function} feedback.
    LazyNode<Object> receiver = [=, this] {
      return receiver_mode == ConvertReceiverMode::kNullOrUndefined
                 ? UndefinedConstant()
                 : LoadRegisterAtOperandIndex(1);
    };
    TNode<UintPtrT> slot_id = BytecodeOperandIdx(3);
    TNode<HeapObject> maybe_feedback_vector = LoadFeedbackVector();
    CollectCallFeedback(function, receiver, context, maybe_feedback_vector,
                        slot_id);
#endif  // !V8_JITLESS

    // Call the function and dispatch to the next handler.
    CallJSAndDispatch(function, context, args, receiver_mode);
  }

  // Generates code to perform a JS call with a known number of arguments that
  // collects type feedback.
  void JSCallN(int arg_count, ConvertReceiverMode receiver_mode) {
    // Indices and counts of operands on the bytecode.
    const int kFirstArgumentOperandIndex = 1;
    const int kReceiverOperandCount =
        (receiver_mode == ConvertReceiverMode::kNullOrUndefined) ? 0 : 1;
    const int kReceiverAndArgOperandCount = kReceiverOperandCount + arg_count;

    TNode<Object> function = LoadRegisterAtOperandIndex(0);
    TNode<Context> context = GetContext();

#ifndef V8_JITLESS
    // Collect the {function} feedback.
    LazyNode<Object> receiver = [=, this] {
      return receiver_mode == ConvertReceiverMode::kNullOrUndefined
                 ? UndefinedConstant()
                 : LoadRegisterAtOperandIndex(1);
    };
    const int kSlotOperandIndex =
        kFirstArgumentOperandIndex + kReceiverAndArgOperandCount;
    TNode<UintPtrT> slot_id = BytecodeOperandIdx(kSlotOperandIndex);
    TNode<HeapObject> maybe_feedback_vector = LoadFeedbackVector();
    CollectCallFeedback(function, receiver, context, maybe_feedback_vector,
                        slot_id);
#endif  // !V8_JITLESS

    switch (kReceiverAndArgOperandCount) {
      case 0:
        CallJSAndDispatch(function, context, Int32Constant(arg_count),
                          receiver_mode);
        break;
      case 1:
        CallJSAndDispatch(
            function, context, Int32Constant(arg_count), receiver_mode,
            LoadRegisterAtOperandIndex(kFirstArgumentOperandIndex));
        break;
      case 2:
        CallJSAndDispatch(
            function, context, Int32Constant(arg_count), receiver_mode,
            LoadRegisterAtOperandIndex(kFirstArgumentOperandIndex + 1),
            LoadRegisterAtOperandIndex(kFirstArgumentOperandIndex));
        break;
      case 3:
        CallJSAndDispatch(
            function, context, Int32Constant(arg_count), receiver_mode,
            LoadRegisterAtOperandIndex(kFirstArgumentOperandIndex + 2),
            LoadRegisterAtOperandIndex(kFirstArgumentOperandIndex + 1),
            LoadRegisterAtOperandIndex(kFirstArgumentOperandIndex));
        break;
      default:
        UNREACHABLE();
    }
  }
};

// Call <callable> <receiver> <arg_count> <feedback_slot_id>
//
// Call a JSfunction or Callable in |callable| with the |receiver| and
// |arg_count| arguments in subsequent registers. Collect type feedback
// into |feedback_slot_id|
IGNITION_HANDLER(CallAnyReceiver, InterpreterJSCallAssembler) {
  JSCall(ConvertReceiverMode::kAny);
}

IGNITION_HANDLER(CallProperty, InterpreterJSCallAssembler) {
  JSCall(ConvertReceiverMode::kNotNullOrUndefined);
}

IGNITION_HANDLER(CallProperty0, InterpreterJSCallAssembler) {
  JSCallN(0, ConvertReceiverMode::kNotNullOrUndefined);
}

IGNITION_HANDLER(CallProperty1, InterpreterJSCallAssembler) {
  JSCallN(1, ConvertReceiverMode::kNotNullOrUndefined);
}

IGNITION_HANDLER(CallProperty2, InterpreterJSCallAssembler) {
  JSCallN(2, ConvertReceiverMode::kNotNullOrUndefined);
}

IGNITION_HANDLER(CallUndefinedReceiver, InterpreterJSCallAssembler) {
  JSCall(ConvertReceiverMode::kNullOrUndefined);
}

IGNITION_HANDLER(CallUndefinedReceiver0, InterpreterJSCallAssembler) {
  JSCallN(0, ConvertReceiverMode::kNullOrUndefined);
}

IGNITION_HANDLER(CallUndefinedReceiver1, InterpreterJSCallAssembler) {
  JSCallN(1, ConvertReceiverMode::kNullOrUndefined);
}

IGNITION_HANDLER(CallUndefinedReceiver2, InterpreterJSCallAssembler) {
  JSCallN(2, ConvertReceiverMode::kNullOrUndefined);
}

// CallRuntime <function_id> <first_arg> <arg_count>
//
// Call the runtime function |function_id| with the first argument in
// register |first_arg| and |arg_count| arguments in subsequent
// registers.
IGNITION_HANDLER(CallRuntime, InterpreterAssembler) {
  TNode<Uint32T> function_id = BytecodeOperandRuntimeId(0);
  RegListNodePair args = GetRegisterListAtOperandIndex(1);
  TNode<Context> context = GetContext();
  TNode<Object> result = CallRuntimeN(function_id, context, args, 1);
  SetAccumulator(result);
  Dispatch();
}

// InvokeIntrinsic <function_id> <first_arg> <arg_count>
//
// Implements the semantic equivalent of calling the runtime function
// |function_id| with the first argument in |first_arg| and |arg_count|
// arguments in subsequent registers.
IGNITION_HANDLER(InvokeIntrinsic, InterpreterAssembler) {
  TNode<Uint32T> function_id = BytecodeOperandIntrinsicId(0);
  RegListNodePair args = GetRegisterListAtOperandIndex(1);
  TNode<Context> context = GetContext();
  TNode<Object> result =
      GenerateInvokeIntrinsic(this, function_id, context, args);
  SetAccumulator(result);
  Dispatch();
}

// CallRuntimeForPair <function_id> <first_arg> <arg_count> <first_return>
//
// Call the runtime function |function_id| which returns a pair, with the
// first argument in register |first_arg| and |arg_count| arguments in
// subsequent registers. Returns the result in <first_return> and
// <first_return + 1>
IGNITION_HANDLER(CallRuntimeForPair, InterpreterAssembler) {
  // Call the runtime function.
  TNode<Uint32T> function_id = BytecodeOperandRuntimeId(0);
  RegListNodePair args = GetRegisterListAtOperandIndex(1);
  TNode<Context> context = GetContext();
  auto result_pair =
      CallRuntimeN<PairT<Object, Object>>(function_id, context, args, 2);
  // Store the results in <first_return> and <first_return + 1>
  TNode<Object> result0 = Projection<0>(result_pair);
  TNode<Object> result1 = Projection<1>(result_pair);
  StoreRegisterPairAtOperandIndex(result0, result1, 3);
  ClobberAccumulator(result0);
  Dispatch();
}

// CallJSRuntime <context_index> <receiver> <arg_count>
//
// Call the JS runtime function that has the |context_index| with the receiver
// in register |receiver| and |arg_count| arguments in subsequent registers.
IGNITION_HANDLER(CallJSRuntime, InterpreterAssembler) {
  TNode<IntPtrT> context_index = Signed(BytecodeOperandNativeContextIndex(0));
  RegListNodePair args = GetRegisterListAtOperandIndex(1);

  // Get the function to call from the native context.
  TNode<Context> context = GetContext();
  TNode<NativeContext> native_context = LoadNativeContext(context);
  TNode<Object> function = LoadContextElement(native_context, context_index);

  // Call the function.
  CallJSAndDispatch(function, context, args,
                    ConvertReceiverMode::kNullOrUndefined);
}

// CallWithSpread <callable> <first_arg> <arg_count>
//
// Call a JSfunction or Callable in |callable| with the receiver in
// |first_arg| and |arg_count - 1| arguments in subsequent registers. The
// final argument is always a spread.
//
IGNITION_HANDLER(CallWithSpread, InterpreterAssembler) {
  TNode<Object> callable = LoadRegisterAtOperandIndex(0);
  RegListNodePair args = GetRegisterListAtOperandIndex(1);
  TNode<UintPtrT> slot_id = BytecodeOperandIdx(3);
  TNode<Context> context = GetContext();

  // Call into Runtime function CallWithSpread which does everything.
  CallJSWithSpreadAndDispatch(callable, context, args, slot_id);
}

// ConstructWithSpread <constructor> <first_arg> <arg_count>
//
// Call the constructor in |constructor| with the first argument in register
// |first_arg| and |arg_count| arguments in subsequent registers. The final
// argument is always a spread. The new.target is in the accumulator.
//
IGNITION_HANDLER(ConstructWithSpread, InterpreterAssembler) {
  TNode<Object> new_target = GetAccumulator();
  TNode<Object> constructor = LoadRegisterAtOperandIndex(0);
  RegListNodePair args = GetRegisterListAtOperandIndex(1);
  TNode<UintPtrT> slot_id = BytecodeOperandIdx(3);
  TNode<Context> context = GetContext();
  TNode<Object> result =
      ConstructWithSpread(constructor, context, new_target, args, slot_id);
  SetAccumulator(result);
  Dispatch();
}

// ConstructForwardAllArgs <constructor>
//
// Call the constructor in |constructor|, forwarding all arguments in the
// current frame. The new.target is in the accumulator.
//
IGNITION_HANDLER(ConstructForwardAllArgs, InterpreterAssembler) {
  TNode<Object> new_target = GetAccumulator();
  TNode<Object> constructor = LoadRegisterAtOperandIndex(0);
  TNode<TaggedIndex> slot_id = BytecodeOperandIdxTaggedIndex(1);
  TNode<Context> context = GetContext();
  TNode<Object> result =
      ConstructForwardAllArgs(constructor, context, new_target, slot_id);
  SetAccumulator(result);
  Dispatch();
}

// Construct <constructor> <first_arg> <arg_count>
//
// Call operator construct with |constructor| and the first argument in
// register |first_arg| and |arg_count| arguments in subsequent
// registers. The new.target is in the accumulator.
//
IGNITION_HANDLER(Construct, InterpreterAssembler) {
  TNode<Object> new_target = GetAccumulator();
  TNode<Object> constructor = LoadRegisterAtOperandIndex(0);
  RegListNodePair args = GetRegisterListAtOperandIndex(1);
  TNode<UintPtrT> slot_id = BytecodeOperandIdx(3);
  TNode<HeapObject> maybe_feedback_vector = LoadFeedbackVector();
  TNode<Context> context = GetContext();
  TNode<Object> result = Construct(constructor, context, new_target, args,
                                   slot_id, maybe_feedback_vector);
  SetAccumulator(result);
  Dispatch();
}

class InterpreterCompareOpAssembler : public InterpreterAssembler {
 public:
  InterpreterCompareOpAssembler(CodeAssemblerState* state, Bytecode bytecode,
                                OperandScale operand_scale)
      : InterpreterAssembler(state, bytecode, operand_scale) {}

  void CompareOpWithFeedback(Operation compare_op) {
    TNode<Object> lhs = LoadRegisterAtOperandIndex(0);
    TNode<Object> rhs = GetAccumulator();
    TNode<Context> context = GetContext();

    TVARIABLE(Smi, var_type_feedback);
    TVARIABLE(Object, var_exception);
    Label if_exception(this, Label::kDeferred);
    TNode<Boolean> result;
    {
      ScopedExceptionHandler handler(this, &if_exception, &var_exception);
      switch (compare_op) {
        case Operation::kEqual:
          result = Equal(lhs, rhs, context, &var_type_feedback);
          break;
        case Operation::kStrictEqual:
          result = StrictEqual(lhs, rhs, &var_type_feedback);
          break;
        case Operation::kLessThan:
        case Operation::kGreaterThan:
        case Operation::kLessThanOrEqual:
        case Operation::kGreaterThanOrEqual:
          result = RelationalComparison(compare_op, lhs, rhs, context,
                                        &var_type_feedback);
          break;
        default:
          UNREACHABLE();
      }
    }

    TNode<UintPtrT> slot_index = BytecodeOperandIdx(1);
    TNode<HeapObject> maybe_feedback_vector =
        LoadFeedbackVectorOrUndefinedIfJitless();
    static constexpr UpdateFeedbackMode mode = DefaultUpdateFeedbackMode();
    UpdateFeedback(var_type_feedback.value(), maybe_feedback_vector, slot_index,
                   mode);
    SetAccumulator(result);
    Dispatch();

    BIND(&if_exception);
    {
      TNode<UintPtrT> slot_index = BytecodeOperandIdx(1);
      TNode<HeapObject> maybe_feedback_
```