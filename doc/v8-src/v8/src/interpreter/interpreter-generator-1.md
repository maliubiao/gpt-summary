Response: The user wants me to summarize the functionality of the provided C++ code snippet. This is the second part of the file `v8/src/interpreter/interpreter-generator.cc`. I should focus on the bytecode handlers defined in this part. Since this code deals with the interpreter, it directly relates to how Javascript code is executed. I need to identify the Javascript constructs that these bytecode handlers implement and provide illustrative examples.

The provided code defines handlers for various bytecode instructions. These handlers are responsible for performing actions corresponding to those instructions during the execution of Javascript code by the V8 interpreter.

Here's a breakdown of the thought process for summarizing the functionality and providing Javascript examples:

1. **Identify the core concept:** The code defines "IGNITION_HANDLER"s which are essentially implementations of bytecode instructions for the V8 interpreter (Ignition).

2. **Group handlers by functionality:**  The handlers fall into several categories:
    * **Comparison Operations:** `TestEqual`, `TestEqualStrict`, `TestLessThan`, etc.
    * **Membership/Type Checks:** `TestIn`, `TestInstanceOf`, `TestUndetectable`, `TestNull`, `TestUndefined`, `TestTypeOf`.
    * **Control Flow:** `Jump`, `JumpConstant`, `JumpIfTrue`, `JumpIfFalse`, `JumpIfToBooleanTrue`, `JumpIfNull`, `JumpIfUndefined`, `JumpIfJSReceiver`, `JumpIfForInDone`, `JumpLoop`, `SwitchOnSmiNoFeedback`.
    * **Object/Array Creation:** `CreateRegExpLiteral`, `CreateArrayLiteral`, `CreateEmptyArrayLiteral`, `CreateArrayFromIterable`, `CreateObjectLiteral`, `CreateEmptyObjectLiteral`, `CloneObject`, `GetTemplateObject`.
    * **Closure/Context Management:** `CreateClosure`, `CreateBlockContext`, `CreateCatchContext`, `CreateFunctionContext`, `CreateEvalContext`, `CreateWithContext`.
    * **Arguments Handling:** `CreateMappedArguments`, `CreateUnmappedArguments`, `CreateRestParameter`.
    * **Exception Handling:** `SetPendingMessage`, `Throw`, `ReThrow`, `Abort`, `ThrowReferenceErrorIfHole`, `ThrowSuperNotCalledIfHole`, `ThrowSuperAlreadyCalledIfNotHole`, `ThrowIfNotSuperConstructor`.
    * **Debugging:** `Debugger`, `DebugBreak`, `IncBlockCounter`.
    * **Iteration:** `ForInEnumerate`, `ForInPrepare`, `ForInNext`, `ForInStep`, `GetIterator`.
    * **Bytecode Control:** `Wide`, `ExtraWide`, `Illegal`, `SuspendGenerator`, `SwitchOnGeneratorState`, `ResumeGenerator`.
    * **Return:** `Return`.

3. **For each category, understand the underlying Javascript concept:**
    * **Comparisons:**  `==`, `===`, `<`, `>`, `<=`, `>=`.
    * **Membership/Type Checks:** `in` operator, `instanceof` operator, type checking (`typeof`, `null`, `undefined`).
    * **Control Flow:** `if`, `else`, `for`, `while`, `do...while`, `switch` statements.
    * **Object/Array Creation:** Literal notations (`[]`, `{}`), `new RegExp()`, array spreading.
    * **Closure/Context Management:** Scopes created by blocks, `try...catch`, function calls, `eval`, `with` statements.
    * **Arguments Handling:** `arguments` object, rest parameters.
    * **Exception Handling:** `throw`, `try...catch`.
    * **Debugging:** `debugger` statement.
    * **Iteration:** `for...in`, iterators (`Symbol.iterator`).

4. **Select representative handlers and create Javascript examples:**  Focus on handlers that clearly demonstrate the connection between the bytecode and Javascript. It's not necessary to provide an example for every single handler, especially for closely related ones (e.g., different jump conditions).

5. **Explain the connection:** Briefly describe how the bytecode handler is involved in executing the corresponding Javascript code. For instance, the `TestEqual` handler is used when the `==` operator is encountered.

6. **Structure the answer:** Organize the summary by functional category for clarity. Present the Javascript example alongside the description of the handler's functionality.

7. **Review and refine:** Ensure the explanations are accurate and the examples are clear and concise. Check for any ambiguities or potential misunderstandings. For instance, clarifying the role of the "accumulator" might be helpful in some contexts.
这个C++代码文件（`v8/src/interpreter/interpreter-generator.cc` 的第二部分）定义了大量 **Ignition bytecode 的处理函数**。Ignition 是 V8 JavaScript 引擎的解释器。 这些处理函数是用 CodeStubAssembler (CSA) 编写的，用于实现各种 JavaScript 操作。

**总的来说，这个文件的功能是为 V8 解释器 (Ignition) 生成执行特定 JavaScript 操作的低级代码。每个 `IGNITION_HANDLER` 宏定义的函数都对应一个特定的 bytecode 指令，并包含了执行该指令所需的逻辑。**

以下是这个文件中定义的一些主要功能的归纳，并附带相应的 JavaScript 例子：

**1. 比较操作 (Comparison Operations):**

* **`TestEqual`**: 测试寄存器中的值是否等于累加器 (accumulator)。
* **`TestEqualStrict`**: 测试寄存器中的值是否严格等于累加器。
* **`TestLessThan`**, **`TestGreaterThan`**, **`TestLessThanOrEqual`**, **`TestGreaterThanOrEqual`**:  执行小于、大于、小于等于、大于等于比较。
* **`TestReferenceEqual`**:  使用简单的比较方式测试寄存器中的值是否与累加器相等（用于 SMI 和简单的引用比较）。

```javascript
let a = 5;
let b = "5";
if (a == b) { // TestEqual bytecode 会被用于执行这里的相等比较
  console.log("Equal");
}

if (a === Number(b)) { // TestEqualStrict bytecode 用于严格相等比较
  console.log("Strictly Equal");
}

if (a < 10) { // TestLessThan
  console.log("Less than 10");
}
```

**2. 类型和存在性检查 (Type and Existence Checks):**

* **`TestIn`**: 检查寄存器中的值是否是累加器对象的一个属性。
* **`TestInstanceOf`**: 检查寄存器中的对象是否是累加器所引用类型的实例。
* **`TestUndetectable`**: 检查累加器中的值是否不可检测 (null, undefined, 或 document.all)。
* **`TestNull`**: 检查累加器中的值是否严格等于 null。
* **`TestUndefined`**: 检查累加器中的值是否严格等于 undefined。
* **`TestTypeOf`**: 检查累加器中的对象的类型是否与指定的字面量类型匹配。

```javascript
let obj = { key: "value" };
if ("key" in obj) { // TestIn bytecode 用于执行 in 操作符
  console.log("key exists");
}

class MyClass {}
let instance = new MyClass();
if (instance instanceof MyClass) { // TestInstanceOf bytecode
  console.log("Is an instance of MyClass");
}

let und;
if (typeof und === 'undefined') { // TestTypeOf bytecode 用于 typeof 操作符
  console.log("undefined");
}

if (obj === null) { // TestNull bytecode
  console.log("Is null");
}
```

**3. 跳转指令 (Jump Instructions):**

* **`Jump`**, **`JumpConstant`**:  无条件跳转到指定的偏移量。
* **`JumpIfTrue`**, **`JumpIfFalse`**:  如果累加器为 true 或 false 则跳转。
* **`JumpIfToBooleanTrue`**, **`JumpIfToBooleanFalse`**:  如果累加器转换为布尔值后为 true 或 false 则跳转。
* **各种针对 `null`, `undefined`, `JSReceiver` 的条件跳转指令 (`JumpIfNull`, `JumpIfUndefined`, `JumpIfJSReceiver` 等)。**
* **`JumpIfForInDone`**:  在 `for...in` 循环中，如果已遍历完所有属性则跳转。
* **`JumpLoop`**:  用于循环的跳转，会进行栈检查和潜在的 OSR (On-Stack Replacement)。
* **`SwitchOnSmiNoFeedback`**:  根据累加器中的 SMI 值在常量池中的跳转表中跳转。

```javascript
let x = 10;
if (x > 5) { // 可能会用到 JumpIfTrue 或 JumpIfToBooleanTrue
  console.log("x is greater than 5");
}

for (let key in obj) { // JumpIfForInDone 会在循环结束时使用
  console.log(key);
}

let value = 2;
switch (value) { // SwitchOnSmiNoFeedback 用于优化 switch 语句
  case 1:
    console.log("One");
    break;
  case 2:
    console.log("Two");
    break;
}
```

**4. 对象和数组字面量创建 (Object and Array Literal Creation):**

* **`CreateRegExpLiteral`**: 创建正则表达式字面量。
* **`CreateArrayLiteral`**: 创建数组字面量。
* **`CreateEmptyArrayLiteral`**: 创建空数组字面量。
* **`CreateArrayFromIterable`**: 从可迭代对象创建数组 (例如使用 spread 语法)。
* **`CreateObjectLiteral`**: 创建对象字面量。
* **`CreateEmptyObjectLiteral`**: 创建空对象字面量。
* **`CloneObject`**: 克隆一个对象。
* **`GetTemplateObject`**:  创建模板字面量的模板对象。

```javascript
let regex = /pattern/g; // CreateRegExpLiteral
let arr = [1, 2, 3]; // CreateArrayLiteral
let emptyArr = []; // CreateEmptyArrayLiteral
let objLiteral = { a: 1, b: 2 }; // CreateObjectLiteral
let emptyObj = {}; // CreateEmptyObjectLiteral
let newArr = [...arr, 4]; // CreateArrayFromIterable (spread syntax)
let template = `Hello ${name}`; // GetTemplateObject
```

**5. 闭包和上下文管理 (Closure and Context Management):**

* **`CreateClosure`**: 创建一个新的闭包。
* **`CreateBlockContext`**: 创建一个新的块级作用域上下文。
* **`CreateCatchContext`**: 为 `catch` 块创建一个新的上下文。
* **`CreateFunctionContext`**: 为函数闭包创建一个新的上下文。
* **`CreateEvalContext`**: 为 `eval` 创建一个新的上下文。
* **`CreateWithContext`**: 为 `with` 语句创建一个新的上下文。

```javascript
function outer() {
  let outerVar = 10;
  function inner() { // CreateClosure 会在创建 inner 函数时使用
    console.log(outerVar);
  }
  return inner;
}

if (true) { // CreateBlockContext 会在创建块级作用域时使用
  let blockVar = 20;
  console.log(blockVar);
}

try {
  // ...
} catch (e) { // CreateCatchContext
  console.error(e);
}

function myFunc() { // CreateFunctionContext
  console.log("Inside myFunc");
}

// with 语句 (不推荐使用) 可能用到 CreateWithContext
```

**6. 参数处理 (Argument Handling):**

* **`CreateMappedArguments`**: 创建一个映射的 `arguments` 对象 (在非严格模式函数中)。
* **`CreateUnmappedArguments`**: 创建一个非映射的 `arguments` 对象 (在严格模式函数中)。
* **`CreateRestParameter`**: 创建剩余参数数组。

```javascript
function nonStrictFunc() {
  console.log(arguments); // CreateMappedArguments
}

function strictFunc() {
  "use strict";
  console.log(arguments); // CreateUnmappedArguments
}

function restFunc(...args) { // CreateRestParameter
  console.log(args);
}
```

**7. 异常处理 (Exception Handling):**

* **`SetPendingMessage`**: 设置待处理的错误消息。
* **`Throw`**: 抛出一个异常。
* **`ReThrow`**: 重新抛出一个异常。
* **`Abort`**: 中止执行。
* **`ThrowReferenceErrorIfHole`**: 如果累加器是 `TheHole` (表示未初始化的变量) 则抛出 `ReferenceError`。
* **其他用于特定场景的抛出异常的指令 (例如 `ThrowSuperNotCalledIfHole`)。**

```javascript
function mightThrow() {
  throw new Error("Something went wrong"); // Throw bytecode
}

try {
  mightThrow();
} catch (e) { // 捕获异常
  throw e; // ReThrow bytecode
}

let x;
console.log(x); // ThrowReferenceErrorIfHole (如果 x 未初始化)
```

**8. 调试支持 (Debugging Support):**

* **`Debugger`**:  遇到 `debugger` 语句时调用运行时处理函数。
* **`DebugBreak`**:  在特定字节码处设置断点。
* **`IncBlockCounter`**:  用于代码覆盖率，增加代码块的执行计数。

```javascript
function debugMe() {
  debugger; // Debugger bytecode
  console.log("After debugger");
}
```

**9. 迭代器 (Iterators):**

* **`ForInEnumerate`**: 枚举对象的属性，用于 `for...in` 循环。
* **`ForInPrepare`**: 为 `for...in` 循环准备状态。
* **`ForInNext`**: 获取 `for...in` 循环的下一个属性。
* **`ForInStep`**: 递增 `for...in` 循环的计数器。
* **`GetIterator`**: 获取对象的 `Symbol.iterator` 方法并调用它。

```javascript
let iterable = [1, 2, 3];
for (let item of iterable) { // GetIterator 会被用于获取数组的迭代器
  console.log(item);
}

for (let key in obj) { // ForInEnumerate, ForInPrepare, ForInNext, ForInStep
  console.log(key);
}
```

**10. 其他指令 (Other Instructions):**

* **`Wide`**, **`ExtraWide`**:  前缀字节码，指示下一个字节码具有更宽的操作数。
* **`Illegal`**:  一个无效的字节码，如果执行会中止。
* **`SuspendGenerator`**: 暂停生成器函数的执行。
* **`SwitchOnGeneratorState`**: 根据生成器状态跳转。
* **`ResumeGenerator`**: 恢复生成器函数的执行。
* **`Return`**: 从函数返回。

总而言之，这个文件的代码是 V8 JavaScript 引擎解释器 Ignition 的核心组成部分，它将高级的 JavaScript 语法和操作转化为可以执行的低级指令。每个 `IGNITION_HANDLER` 都负责执行一个特定的、细粒度的 JavaScript 语义操作。

Prompt: 
```
这是目录为v8/src/interpreter/interpreter-generator.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
vector =
          LoadFeedbackVectorOrUndefinedIfJitless();
      UpdateFeedback(var_type_feedback.value(), maybe_feedback_vector,
                     slot_index, mode);
      CallRuntime(Runtime::kReThrow, context, var_exception.value());
      Unreachable();
    }
  }
};

// TestEqual <src>
//
// Test if the value in the <src> register equals the accumulator.
IGNITION_HANDLER(TestEqual, InterpreterCompareOpAssembler) {
  CompareOpWithFeedback(Operation::kEqual);
}

// TestEqualStrict <src>
//
// Test if the value in the <src> register is strictly equal to the accumulator.
IGNITION_HANDLER(TestEqualStrict, InterpreterCompareOpAssembler) {
  CompareOpWithFeedback(Operation::kStrictEqual);
}

// TestLessThan <src>
//
// Test if the value in the <src> register is less than the accumulator.
IGNITION_HANDLER(TestLessThan, InterpreterCompareOpAssembler) {
  CompareOpWithFeedback(Operation::kLessThan);
}

// TestGreaterThan <src>
//
// Test if the value in the <src> register is greater than the accumulator.
IGNITION_HANDLER(TestGreaterThan, InterpreterCompareOpAssembler) {
  CompareOpWithFeedback(Operation::kGreaterThan);
}

// TestLessThanOrEqual <src>
//
// Test if the value in the <src> register is less than or equal to the
// accumulator.
IGNITION_HANDLER(TestLessThanOrEqual, InterpreterCompareOpAssembler) {
  CompareOpWithFeedback(Operation::kLessThanOrEqual);
}

// TestGreaterThanOrEqual <src>
//
// Test if the value in the <src> register is greater than or equal to the
// accumulator.
IGNITION_HANDLER(TestGreaterThanOrEqual, InterpreterCompareOpAssembler) {
  CompareOpWithFeedback(Operation::kGreaterThanOrEqual);
}

// TestReferenceEqual <src>
//
// Test if the value in the <src> register is equal to the accumulator
// by means of simple comparison. For SMIs and simple reference comparisons.
IGNITION_HANDLER(TestReferenceEqual, InterpreterAssembler) {
  TNode<Object> lhs = LoadRegisterAtOperandIndex(0);
  TNode<Object> rhs = GetAccumulator();
  TNode<Boolean> result = SelectBooleanConstant(TaggedEqual(lhs, rhs));
  SetAccumulator(result);
  Dispatch();
}

// TestIn <src> <feedback_slot>
//
// Test if the object referenced by the register operand is a property of the
// object referenced by the accumulator.
IGNITION_HANDLER(TestIn, InterpreterAssembler) {
  TNode<Object> name = LoadRegisterAtOperandIndex(0);
  TNode<Object> object = GetAccumulator();
  TNode<TaggedIndex> slot = BytecodeOperandIdxTaggedIndex(1);
  TNode<HeapObject> feedback_vector = LoadFeedbackVector();
  TNode<Context> context = GetContext();

  TVARIABLE(Object, var_result);
  var_result = CallBuiltin(Builtin::kKeyedHasIC, context, object, name, slot,
                           feedback_vector);
  SetAccumulator(var_result.value());
  Dispatch();
}

// TestInstanceOf <src> <feedback_slot>
//
// Test if the object referenced by the <src> register is an an instance of type
// referenced by the accumulator.
IGNITION_HANDLER(TestInstanceOf, InterpreterAssembler) {
  TNode<Object> object = LoadRegisterAtOperandIndex(0);
  TNode<Object> callable = GetAccumulator();
  TNode<Context> context = GetContext();

#ifndef V8_JITLESS
  TNode<HeapObject> maybe_feedback_vector = LoadFeedbackVector();
  TNode<UintPtrT> slot_id = BytecodeOperandIdx(1);
  CollectInstanceOfFeedback(callable, context, maybe_feedback_vector, slot_id);
#endif  // !V8_JITLESS

  SetAccumulator(InstanceOf(object, callable, context));
  Dispatch();
}

// TestUndetectable
//
// Test if the value in the accumulator is undetectable (null, undefined or
// document.all).
IGNITION_HANDLER(TestUndetectable, InterpreterAssembler) {
  Label return_false(this), end(this);
  TNode<Object> object = GetAccumulator();

  // If the object is an Smi then return false.
  SetAccumulator(FalseConstant());
  GotoIf(TaggedIsSmi(object), &end);

  // If it is a HeapObject, load the map and check for undetectable bit.
  TNode<Boolean> result =
      SelectBooleanConstant(IsUndetectableMap(LoadMap(CAST(object))));
  SetAccumulator(result);
  Goto(&end);

  BIND(&end);
  Dispatch();
}

// TestNull
//
// Test if the value in accumulator is strictly equal to null.
IGNITION_HANDLER(TestNull, InterpreterAssembler) {
  TNode<Object> object = GetAccumulator();
  TNode<Boolean> result =
      SelectBooleanConstant(TaggedEqual(object, NullConstant()));
  SetAccumulator(result);
  Dispatch();
}

// TestUndefined
//
// Test if the value in the accumulator is strictly equal to undefined.
IGNITION_HANDLER(TestUndefined, InterpreterAssembler) {
  TNode<Object> object = GetAccumulator();
  TNode<Boolean> result =
      SelectBooleanConstant(TaggedEqual(object, UndefinedConstant()));
  SetAccumulator(result);
  Dispatch();
}

// TestTypeOf <literal_flag>
//
// Tests if the object in the <accumulator> is typeof the literal represented
// by |literal_flag|.
IGNITION_HANDLER(TestTypeOf, InterpreterAssembler) {
  TNode<Object> object = GetAccumulator();
  TNode<Uint32T> literal_flag = BytecodeOperandFlag8(0);

#define MAKE_LABEL(name, lower_case) Label if_##lower_case(this);
  TYPEOF_LITERAL_LIST(MAKE_LABEL)
#undef MAKE_LABEL

#define LABEL_POINTER(name, lower_case) &if_##lower_case,
  Label* labels[] = {TYPEOF_LITERAL_LIST(LABEL_POINTER)};
#undef LABEL_POINTER

#define CASE(name, lower_case) \
  static_cast<int32_t>(TestTypeOfFlags::LiteralFlag::k##name),
  int32_t cases[] = {TYPEOF_LITERAL_LIST(CASE)};
#undef CASE

  Label if_true(this), if_false(this), end(this);

  // We just use the final label as the default and properly CSA_DCHECK
  // that the {literal_flag} is valid here; this significantly improves
  // the generated code (compared to having a default label that aborts).
  unsigned const num_cases = arraysize(cases);
  CSA_DCHECK(this, Uint32LessThan(literal_flag, Int32Constant(num_cases)));
  Switch(literal_flag, labels[num_cases - 1], cases, labels, num_cases - 1);

  BIND(&if_number);
  {
    Comment("IfNumber");
    GotoIfNumber(object, &if_true);
    Goto(&if_false);
  }
  BIND(&if_string);
  {
    Comment("IfString");
    GotoIf(TaggedIsSmi(object), &if_false);
    Branch(IsString(CAST(object)), &if_true, &if_false);
  }
  BIND(&if_symbol);
  {
    Comment("IfSymbol");
    GotoIf(TaggedIsSmi(object), &if_false);
    Branch(IsSymbol(CAST(object)), &if_true, &if_false);
  }
  BIND(&if_boolean);
  {
    Comment("IfBoolean");
    GotoIf(TaggedEqual(object, TrueConstant()), &if_true);
    Branch(TaggedEqual(object, FalseConstant()), &if_true, &if_false);
  }
  BIND(&if_bigint);
  {
    Comment("IfBigInt");
    GotoIf(TaggedIsSmi(object), &if_false);
    Branch(IsBigInt(CAST(object)), &if_true, &if_false);
  }
  BIND(&if_undefined);
  {
    Comment("IfUndefined");
    GotoIf(TaggedIsSmi(object), &if_false);
    // Check it is not null and the map has the undetectable bit set.
    GotoIf(IsNull(object), &if_false);
    Branch(IsUndetectableMap(LoadMap(CAST(object))), &if_true, &if_false);
  }
  BIND(&if_function);
  {
    Comment("IfFunction");
    GotoIf(TaggedIsSmi(object), &if_false);
    // Check if callable bit is set and not undetectable.
    TNode<Int32T> map_bitfield = LoadMapBitField(LoadMap(CAST(object)));
    TNode<Int32T> callable_undetectable = Word32And(
        map_bitfield, Int32Constant(Map::Bits1::IsUndetectableBit::kMask |
                                    Map::Bits1::IsCallableBit::kMask));
    Branch(Word32Equal(callable_undetectable,
                       Int32Constant(Map::Bits1::IsCallableBit::kMask)),
           &if_true, &if_false);
  }
  BIND(&if_object);
  {
    Comment("IfObject");
    GotoIf(TaggedIsSmi(object), &if_false);

    // If the object is null then return true.
    GotoIf(IsNull(object), &if_true);

    // Check if the object is a receiver type and is not undefined or callable.
    TNode<Map> map = LoadMap(CAST(object));
    GotoIfNot(IsJSReceiverMap(map), &if_false);
    TNode<Int32T> map_bitfield = LoadMapBitField(map);
    TNode<Int32T> callable_undetectable = Word32And(
        map_bitfield, Int32Constant(Map::Bits1::IsUndetectableBit::kMask |
                                    Map::Bits1::IsCallableBit::kMask));
    Branch(Word32Equal(callable_undetectable, Int32Constant(0)), &if_true,
           &if_false);
  }
  BIND(&if_other);
  {
    // Typeof doesn't return any other string value.
    Goto(&if_false);
  }

  BIND(&if_false);
  {
    SetAccumulator(FalseConstant());
    Goto(&end);
  }
  BIND(&if_true);
  {
    SetAccumulator(TrueConstant());
    Goto(&end);
  }
  BIND(&end);
  Dispatch();
}

// Jump <imm>
//
// Jump by the number of bytes represented by the immediate operand |imm|.
IGNITION_HANDLER(Jump, InterpreterAssembler) {
  TNode<IntPtrT> relative_jump = Signed(BytecodeOperandUImmWord(0));
  Jump(relative_jump);
}

// JumpConstant <idx>
//
// Jump by the number of bytes in the Smi in the |idx| entry in the constant
// pool.
IGNITION_HANDLER(JumpConstant, InterpreterAssembler) {
  TNode<IntPtrT> relative_jump = LoadAndUntagConstantPoolEntryAtOperandIndex(0);
  Jump(relative_jump);
}

// JumpIfTrue <imm>
//
// Jump by the number of bytes represented by an immediate operand if the
// accumulator contains true. This only works for boolean inputs, and
// will misbehave if passed arbitrary input values.
IGNITION_HANDLER(JumpIfTrue, InterpreterAssembler) {
  TNode<Object> accumulator = GetAccumulator();
  CSA_DCHECK(this, IsBoolean(CAST(accumulator)));
  JumpIfTaggedEqual(accumulator, TrueConstant(), 0);
}

// JumpIfTrueConstant <idx>
//
// Jump by the number of bytes in the Smi in the |idx| entry in the constant
// pool if the accumulator contains true. This only works for boolean inputs,
// and will misbehave if passed arbitrary input values.
IGNITION_HANDLER(JumpIfTrueConstant, InterpreterAssembler) {
  TNode<Object> accumulator = GetAccumulator();
  CSA_DCHECK(this, IsBoolean(CAST(accumulator)));
  JumpIfTaggedEqualConstant(accumulator, TrueConstant(), 0);
}

// JumpIfFalse <imm>
//
// Jump by the number of bytes represented by an immediate operand if the
// accumulator contains false. This only works for boolean inputs, and
// will misbehave if passed arbitrary input values.
IGNITION_HANDLER(JumpIfFalse, InterpreterAssembler) {
  TNode<Object> accumulator = GetAccumulator();
  CSA_DCHECK(this, IsBoolean(CAST(accumulator)));
  JumpIfTaggedEqual(accumulator, FalseConstant(), 0);
}

// JumpIfFalseConstant <idx>
//
// Jump by the number of bytes in the Smi in the |idx| entry in the constant
// pool if the accumulator contains false. This only works for boolean inputs,
// and will misbehave if passed arbitrary input values.
IGNITION_HANDLER(JumpIfFalseConstant, InterpreterAssembler) {
  TNode<Object> accumulator = GetAccumulator();
  CSA_DCHECK(this, IsBoolean(CAST(accumulator)));
  JumpIfTaggedEqualConstant(accumulator, FalseConstant(), 0);
}

// JumpIfToBooleanTrue <imm>
//
// Jump by the number of bytes represented by an immediate operand if the object
// referenced by the accumulator is true when the object is cast to boolean.
IGNITION_HANDLER(JumpIfToBooleanTrue, InterpreterAssembler) {
  TNode<Object> value = GetAccumulator();
  Label if_true(this), if_false(this);
  BranchIfToBooleanIsTrue(value, &if_true, &if_false);
  BIND(&if_true);
  TNode<IntPtrT> relative_jump = Signed(BytecodeOperandUImmWord(0));
  Jump(relative_jump);
  BIND(&if_false);
  Dispatch();
}

// JumpIfToBooleanTrueConstant <idx>
//
// Jump by the number of bytes in the Smi in the |idx| entry in the constant
// pool if the object referenced by the accumulator is true when the object is
// cast to boolean.
IGNITION_HANDLER(JumpIfToBooleanTrueConstant, InterpreterAssembler) {
  TNode<Object> value = GetAccumulator();
  Label if_true(this), if_false(this);
  BranchIfToBooleanIsTrue(value, &if_true, &if_false);
  BIND(&if_true);
  TNode<IntPtrT> relative_jump = LoadAndUntagConstantPoolEntryAtOperandIndex(0);
  Jump(relative_jump);
  BIND(&if_false);
  Dispatch();
}

// JumpIfToBooleanFalse <imm>
//
// Jump by the number of bytes represented by an immediate operand if the object
// referenced by the accumulator is false when the object is cast to boolean.
IGNITION_HANDLER(JumpIfToBooleanFalse, InterpreterAssembler) {
  TNode<Object> value = GetAccumulator();
  Label if_true(this), if_false(this);
  BranchIfToBooleanIsTrue(value, &if_true, &if_false);
  BIND(&if_true);
  Dispatch();
  BIND(&if_false);
  TNode<IntPtrT> relative_jump = Signed(BytecodeOperandUImmWord(0));
  Jump(relative_jump);
}

// JumpIfToBooleanFalseConstant <idx>
//
// Jump by the number of bytes in the Smi in the |idx| entry in the constant
// pool if the object referenced by the accumulator is false when the object is
// cast to boolean.
IGNITION_HANDLER(JumpIfToBooleanFalseConstant, InterpreterAssembler) {
  TNode<Object> value = GetAccumulator();
  Label if_true(this), if_false(this);
  BranchIfToBooleanIsTrue(value, &if_true, &if_false);
  BIND(&if_true);
  Dispatch();
  BIND(&if_false);
  TNode<IntPtrT> relative_jump = LoadAndUntagConstantPoolEntryAtOperandIndex(0);
  Jump(relative_jump);
}

// JumpIfNull <imm>
//
// Jump by the number of bytes represented by an immediate operand if the object
// referenced by the accumulator is the null constant.
IGNITION_HANDLER(JumpIfNull, InterpreterAssembler) {
  TNode<Object> accumulator = GetAccumulator();
  JumpIfTaggedEqual(accumulator, NullConstant(), 0);
}

// JumpIfNullConstant <idx>
//
// Jump by the number of bytes in the Smi in the |idx| entry in the constant
// pool if the object referenced by the accumulator is the null constant.
IGNITION_HANDLER(JumpIfNullConstant, InterpreterAssembler) {
  TNode<Object> accumulator = GetAccumulator();
  JumpIfTaggedEqualConstant(accumulator, NullConstant(), 0);
}

// JumpIfNotNull <imm>
//
// Jump by the number of bytes represented by an immediate operand if the object
// referenced by the accumulator is not the null constant.
IGNITION_HANDLER(JumpIfNotNull, InterpreterAssembler) {
  TNode<Object> accumulator = GetAccumulator();
  JumpIfTaggedNotEqual(accumulator, NullConstant(), 0);
}

// JumpIfNotNullConstant <idx>
//
// Jump by the number of bytes in the Smi in the |idx| entry in the constant
// pool if the object referenced by the accumulator is not the null constant.
IGNITION_HANDLER(JumpIfNotNullConstant, InterpreterAssembler) {
  TNode<Object> accumulator = GetAccumulator();
  JumpIfTaggedNotEqualConstant(accumulator, NullConstant(), 0);
}

// JumpIfUndefined <imm>
//
// Jump by the number of bytes represented by an immediate operand if the object
// referenced by the accumulator is the undefined constant.
IGNITION_HANDLER(JumpIfUndefined, InterpreterAssembler) {
  TNode<Object> accumulator = GetAccumulator();
  JumpIfTaggedEqual(accumulator, UndefinedConstant(), 0);
}

// JumpIfUndefinedConstant <idx>
//
// Jump by the number of bytes in the Smi in the |idx| entry in the constant
// pool if the object referenced by the accumulator is the undefined constant.
IGNITION_HANDLER(JumpIfUndefinedConstant, InterpreterAssembler) {
  TNode<Object> accumulator = GetAccumulator();
  JumpIfTaggedEqualConstant(accumulator, UndefinedConstant(), 0);
}

// JumpIfNotUndefined <imm>
//
// Jump by the number of bytes represented by an immediate operand if the object
// referenced by the accumulator is not the undefined constant.
IGNITION_HANDLER(JumpIfNotUndefined, InterpreterAssembler) {
  TNode<Object> accumulator = GetAccumulator();
  JumpIfTaggedNotEqual(accumulator, UndefinedConstant(), 0);
}

// JumpIfNotUndefinedConstant <idx>
//
// Jump by the number of bytes in the Smi in the |idx| entry in the constant
// pool if the object referenced by the accumulator is not the undefined
// constant.
IGNITION_HANDLER(JumpIfNotUndefinedConstant, InterpreterAssembler) {
  TNode<Object> accumulator = GetAccumulator();
  JumpIfTaggedNotEqualConstant(accumulator, UndefinedConstant(), 0);
}

// JumpIfUndefinedOrNull <imm>
//
// Jump by the number of bytes represented by an immediate operand if the object
// referenced by the accumulator is the undefined constant or the null constant.
IGNITION_HANDLER(JumpIfUndefinedOrNull, InterpreterAssembler) {
  TNode<Object> accumulator = GetAccumulator();

  Label do_jump(this);
  GotoIf(IsUndefined(accumulator), &do_jump);
  GotoIf(IsNull(accumulator), &do_jump);
  Dispatch();

  BIND(&do_jump);
  TNode<IntPtrT> relative_jump = Signed(BytecodeOperandUImmWord(0));
  Jump(relative_jump);
}

// JumpIfUndefinedOrNullConstant <idx>
//
// Jump by the number of bytes in the Smi in the |idx| entry in the constant
// pool if the object referenced by the accumulator is the undefined constant or
// the null constant.
IGNITION_HANDLER(JumpIfUndefinedOrNullConstant, InterpreterAssembler) {
  TNode<Object> accumulator = GetAccumulator();

  Label do_jump(this);
  GotoIf(IsUndefined(accumulator), &do_jump);
  GotoIf(IsNull(accumulator), &do_jump);
  Dispatch();

  BIND(&do_jump);
  TNode<IntPtrT> relative_jump = LoadAndUntagConstantPoolEntryAtOperandIndex(0);
  Jump(relative_jump);
}

// JumpIfJSReceiver <imm>
//
// Jump by the number of bytes represented by an immediate operand if the object
// referenced by the accumulator is a JSReceiver.
IGNITION_HANDLER(JumpIfJSReceiver, InterpreterAssembler) {
  TNode<Object> accumulator = GetAccumulator();

  Label if_object(this), if_notobject(this, Label::kDeferred), if_notsmi(this);
  Branch(TaggedIsSmi(accumulator), &if_notobject, &if_notsmi);

  BIND(&if_notsmi);
  Branch(IsJSReceiver(CAST(accumulator)), &if_object, &if_notobject);
  BIND(&if_object);
  TNode<IntPtrT> relative_jump = Signed(BytecodeOperandUImmWord(0));
  Jump(relative_jump);

  BIND(&if_notobject);
  Dispatch();
}

// JumpIfJSReceiverConstant <idx>
//
// Jump by the number of bytes in the Smi in the |idx| entry in the constant
// pool if the object referenced by the accumulator is a JSReceiver.
IGNITION_HANDLER(JumpIfJSReceiverConstant, InterpreterAssembler) {
  TNode<Object> accumulator = GetAccumulator();

  Label if_object(this), if_notobject(this), if_notsmi(this);
  Branch(TaggedIsSmi(accumulator), &if_notobject, &if_notsmi);

  BIND(&if_notsmi);
  Branch(IsJSReceiver(CAST(accumulator)), &if_object, &if_notobject);

  BIND(&if_object);
  TNode<IntPtrT> relative_jump = LoadAndUntagConstantPoolEntryAtOperandIndex(0);
  Jump(relative_jump);

  BIND(&if_notobject);
  Dispatch();
}

// JumpIfForInDone <imm> <index> <cache_length>
//
// Jump by the number of bytes represented by an immediate operand if the end of
// the enumerable properties has been reached.
IGNITION_HANDLER(JumpIfForInDone, InterpreterAssembler) {
  TNode<Object> index = LoadRegisterAtOperandIndex(1);
  TNode<Object> cache_length = LoadRegisterAtOperandIndex(2);

  // Check if {index} is at {cache_length} already.
  Label if_done(this), if_not_done(this), end(this);
  Branch(TaggedEqual(index, cache_length), &if_done, &if_not_done);

  BIND(&if_done);
  TNode<IntPtrT> relative_jump = Signed(BytecodeOperandUImmWord(0));
  Jump(relative_jump);

  BIND(&if_not_done);
  Dispatch();
}

// JumpIfForInDoneConstant <idx> <index> <cache_length>
//
// Jump by the number of bytes in the Smi in the |idx| entry in the constant
// pool if the end of the enumerable properties has been reached.
IGNITION_HANDLER(JumpIfForInDoneConstant, InterpreterAssembler) {
  TNode<Object> index = LoadRegisterAtOperandIndex(1);
  TNode<Object> cache_length = LoadRegisterAtOperandIndex(2);

  // Check if {index} is at {cache_length} already.
  Label if_done(this), if_not_done(this), end(this);
  Branch(TaggedEqual(index, cache_length), &if_done, &if_not_done);

  BIND(&if_done);
  TNode<IntPtrT> relative_jump = LoadAndUntagConstantPoolEntryAtOperandIndex(0);
  Jump(relative_jump);

  BIND(&if_not_done);
  Dispatch();
}

// JumpLoop <imm> <loop_depth>
//
// Jump by the number of bytes represented by the immediate operand |imm|. Also
// performs a loop nesting check, a stack check, and potentially triggers OSR.
IGNITION_HANDLER(JumpLoop, InterpreterAssembler) {
  TNode<IntPtrT> relative_jump = Signed(BytecodeOperandUImmWord(0));

  ClobberAccumulator(UndefinedConstant());

#ifndef V8_JITLESS
  TVARIABLE(HeapObject, maybe_feedback_vector);
  Label ok(this);
  Label fbv_loaded(this);

  // Load FeedbackVector from Cache.
  maybe_feedback_vector = LoadFeedbackVector();
  // If cache is empty, try to load from function closure.
  GotoIfNot(IsUndefined(maybe_feedback_vector.value()), &fbv_loaded);
  maybe_feedback_vector =
      CodeStubAssembler::LoadFeedbackVector(LoadFunctionClosure(), &ok);
  // Update feedback vector stack cache.
  StoreRegister(maybe_feedback_vector.value(), Register::feedback_vector());
  Goto(&fbv_loaded);

  BIND(&fbv_loaded);

  TNode<FeedbackVector> feedback_vector = CAST(maybe_feedback_vector.value());
  TNode<Int8T> osr_state = LoadOsrState(feedback_vector);
  TNode<Int32T> loop_depth = BytecodeOperandImm(1);

  Label maybe_osr_because_osr_state(this, Label::kDeferred);
  // The quick initial OSR check. If it passes, we proceed on to more expensive
  // OSR logic.
  static_assert(FeedbackVector::MaybeHasMaglevOsrCodeBit::encode(true) >
                FeedbackVector::kMaxOsrUrgency);
  static_assert(FeedbackVector::MaybeHasTurbofanOsrCodeBit::encode(true) >
                FeedbackVector::kMaxOsrUrgency);

  GotoIfNot(Uint32GreaterThanOrEqual(loop_depth, osr_state),
            &maybe_osr_because_osr_state);

  // Perhaps we've got cached baseline code?
  Label maybe_osr_because_baseline(this);
  TNode<SharedFunctionInfo> sfi = LoadObjectField<SharedFunctionInfo>(
      LoadFunctionClosure(), JSFunction::kSharedFunctionInfoOffset);
  Branch(SharedFunctionInfoHasBaselineCode(sfi), &maybe_osr_because_baseline,
         &ok);

  BIND(&ok);
#endif  // !V8_JITLESS

  // The backward jump can trigger a budget interrupt, which can handle stack
  // interrupts, so we don't need to explicitly handle them here.
  JumpBackward(relative_jump);

#ifndef V8_JITLESS
  BIND(&maybe_osr_because_baseline);
  {
    TNode<Context> context = GetContext();
    TNode<IntPtrT> slot_index = Signed(BytecodeOperandIdx(2));
    OnStackReplacement(context, feedback_vector, relative_jump, loop_depth,
                       slot_index, osr_state,
                       OnStackReplacementParams::kBaselineCodeIsCached);
  }

  BIND(&maybe_osr_because_osr_state);
  {
    TNode<Context> context = GetContext();
    TNode<IntPtrT> slot_index = Signed(BytecodeOperandIdx(2));
    OnStackReplacement(context, feedback_vector, relative_jump, loop_depth,
                       slot_index, osr_state,
                       OnStackReplacementParams::kDefault);
  }
#endif  // !V8_JITLESS
}

// SwitchOnSmiNoFeedback <table_start> <table_length> <case_value_base>
//
// Jump by the number of bytes defined by a Smi in a table in the constant pool,
// where the table starts at |table_start| and has |table_length| entries.
// The table is indexed by the accumulator, minus |case_value_base|. If the
// case_value falls outside of the table |table_length|, fall-through to the
// next bytecode.
IGNITION_HANDLER(SwitchOnSmiNoFeedback, InterpreterAssembler) {
  // The accumulator must be a Smi.
  TNode<Object> acc = GetAccumulator();
  TNode<UintPtrT> table_start = BytecodeOperandIdx(0);
  TNode<UintPtrT> table_length = BytecodeOperandUImmWord(1);
  TNode<IntPtrT> case_value_base = BytecodeOperandImmIntPtr(2);

  Label fall_through(this);

  // TODO(leszeks): Use this as an alternative to adding extra bytecodes ahead
  // of a jump-table optimized switch statement, using this code, in lieu of the
  // current case_value line.
  // TNode<IntPtrT> acc_intptr = TryTaggedToInt32AsIntPtr(acc, &fall_through);
  // TNode<IntPtrT> case_value = IntPtrSub(acc_intptr, case_value_base);

  CSA_DCHECK(this, TaggedIsSmi(acc));

  TNode<IntPtrT> case_value = IntPtrSub(SmiUntag(CAST(acc)), case_value_base);

  GotoIf(IntPtrLessThan(case_value, IntPtrConstant(0)), &fall_through);
  GotoIf(IntPtrGreaterThanOrEqual(case_value, table_length), &fall_through);

  TNode<WordT> entry = IntPtrAdd(table_start, case_value);
  TNode<IntPtrT> relative_jump = LoadAndUntagConstantPoolEntry(entry);
  Jump(relative_jump);

  BIND(&fall_through);
  Dispatch();
}

// CreateRegExpLiteral <pattern_idx> <literal_idx> <flags>
//
// Creates a regular expression literal for literal index <literal_idx> with
// <flags> and the pattern in <pattern_idx>.
IGNITION_HANDLER(CreateRegExpLiteral, InterpreterAssembler) {
  TNode<String> pattern = CAST(LoadConstantPoolEntryAtOperandIndex(0));
  TNode<HeapObject> feedback_vector = LoadFeedbackVector();
  TNode<TaggedIndex> slot = BytecodeOperandIdxTaggedIndex(1);
  TNode<Smi> flags =
      SmiFromInt32(UncheckedCast<Int32T>(BytecodeOperandFlag16(2)));
  TNode<Context> context = GetContext();

  TVARIABLE(JSRegExp, result);

  ConstructorBuiltinsAssembler constructor_assembler(state());
  result = constructor_assembler.CreateRegExpLiteral(feedback_vector, slot,
                                                     pattern, flags, context);
  SetAccumulator(result.value());
  Dispatch();
}

// CreateArrayLiteral <element_idx> <literal_idx> <flags>
//
// Creates an array literal for literal index <literal_idx> with
// CreateArrayLiteral flags <flags> and constant elements in <element_idx>.
IGNITION_HANDLER(CreateArrayLiteral, InterpreterAssembler) {
  TNode<HeapObject> feedback_vector = LoadFeedbackVector();
  TNode<TaggedIndex> slot = BytecodeOperandIdxTaggedIndex(1);
  TNode<Context> context = GetContext();
  TNode<Uint32T> bytecode_flags = BytecodeOperandFlag8(2);

  Label fast_shallow_clone(this), slow_clone(this, Label::kDeferred),
      call_runtime(this, Label::kDeferred);

  TNode<UintPtrT> flags_raw =
      DecodeWordFromWord32<CreateArrayLiteralFlags::FlagsBits>(bytecode_flags);
  TNode<Smi> flags = SmiTag(Signed(flags_raw));
  TNode<Object> array_boilerplate_description =
      LoadConstantPoolEntryAtOperandIndex(0);

  //  No feedback, so handle it as a slow case.
  GotoIf(IsUndefined(feedback_vector), &call_runtime);

  Branch(IsSetWord32<CreateArrayLiteralFlags::FastCloneSupportedBit>(
             bytecode_flags),
         &fast_shallow_clone, &slow_clone);

  BIND(&fast_shallow_clone);
  {
    ConstructorBuiltinsAssembler constructor_assembler(state());
    TNode<JSArray> result = constructor_assembler.CreateShallowArrayLiteral(
        CAST(feedback_vector), slot, context, TRACK_ALLOCATION_SITE,
        &call_runtime);
    SetAccumulator(result);
    Dispatch();
  }

  BIND(&slow_clone);
  {
    TNode<JSArray> result = CAST(CallBuiltin(
        Builtin::kCreateArrayFromSlowBoilerplate, context, feedback_vector,
        slot, array_boilerplate_description, flags));

    SetAccumulator(result);
    Dispatch();
  }

  BIND(&call_runtime);
  {
    TNode<Object> result =
        CallRuntime(Runtime::kCreateArrayLiteral, context, feedback_vector,
                    slot, array_boilerplate_description, flags);
    SetAccumulator(result);
    Dispatch();
  }
}

// CreateEmptyArrayLiteral <literal_idx>
//
// Creates an empty JSArray literal for literal index <literal_idx>.
IGNITION_HANDLER(CreateEmptyArrayLiteral, InterpreterAssembler) {
  TNode<HeapObject> maybe_feedback_vector = LoadFeedbackVector();
  TNode<TaggedIndex> slot = BytecodeOperandIdxTaggedIndex(0);
  TNode<Context> context = GetContext();

  Label no_feedback(this, Label::kDeferred), end(this);
  TVARIABLE(JSArray, result);
  GotoIf(IsUndefined(maybe_feedback_vector), &no_feedback);

  ConstructorBuiltinsAssembler constructor_assembler(state());
  result = constructor_assembler.CreateEmptyArrayLiteral(
      CAST(maybe_feedback_vector), slot, context);
  Goto(&end);

  BIND(&no_feedback);
  {
    TNode<Map> array_map = LoadJSArrayElementsMap(GetInitialFastElementsKind(),
                                                  LoadNativeContext(context));
    TNode<Smi> length = SmiConstant(0);
    TNode<IntPtrT> capacity = IntPtrConstant(0);
    result = AllocateJSArray(GetInitialFastElementsKind(), array_map, capacity,
                             length);
    Goto(&end);
  }

  BIND(&end);
  SetAccumulator(result.value());
  Dispatch();
}

// CreateArrayFromIterable
//
// Spread the given iterable from the accumulator into a new JSArray.
// TODO(neis): Turn this into an intrinsic when we're running out of bytecodes.
IGNITION_HANDLER(CreateArrayFromIterable, InterpreterAssembler) {
  TNode<Object> iterable = GetAccumulator();
  TNode<Context> context = GetContext();
  TNode<Object> result =
      CallBuiltin(Builtin::kIterableToListWithSymbolLookup, context, iterable);
  SetAccumulator(result);
  Dispatch();
}

// CreateObjectLiteral <element_idx> <literal_idx> <flags>
//
// Creates an object literal for literal index <literal_idx> with
// CreateObjectLiteralFlags <flags> and constant elements in <element_idx>.
IGNITION_HANDLER(CreateObjectLiteral, InterpreterAssembler) {
  TNode<HeapObject> feedback_vector = LoadFeedbackVector();
  TNode<Context> context = GetContext();
  TNode<TaggedIndex> slot = BytecodeOperandIdxTaggedIndex(1);
  TNode<Uint32T> bytecode_flags = BytecodeOperandFlag8(2);

  TNode<ObjectBoilerplateDescription> object_boilerplate_description =
      CAST(LoadConstantPoolEntryAtOperandIndex(0));
  TNode<UintPtrT> flags_raw =
      DecodeWordFromWord32<CreateObjectLiteralFlags::FlagsBits>(bytecode_flags);
  TNode<Smi> flags = SmiTag(Signed(flags_raw));

  Label fast_shallow_clone(this), Slow_clone(this, Label::kDeferred),
      call_runtime(this, Label::kDeferred);
  // No feedback, so handle it as a slow case.

  GotoIf(IsUndefined(feedback_vector), &call_runtime);

  // Check if we can do a fast clone or have to call the runtime.
  Branch(IsSetWord32<CreateObjectLiteralFlags::FastCloneSupportedBit>(
             bytecode_flags),
         &fast_shallow_clone, &Slow_clone);

  BIND(&fast_shallow_clone);
  {
    // If we can do a fast clone do the fast-path in CreateShallowObjectLiteral.
    ConstructorBuiltinsAssembler constructor_assembler(state());
    TNode<HeapObject> result = constructor_assembler.CreateShallowObjectLiteral(
        CAST(feedback_vector), slot, &call_runtime);
    SetAccumulator(result);
    Dispatch();
  }

  BIND(&Slow_clone);
  {
    TNode<JSObject> result = CAST(CallBuiltin(
        Builtin::kCreateObjectFromSlowBoilerplate, context, feedback_vector,
        slot, object_boilerplate_description, flags));
    SetAccumulator(result);
    Dispatch();
  }

  BIND(&call_runtime);
  {
    TNode<Object> result =
        CallRuntime(Runtime::kCreateObjectLiteral, context, feedback_vector,
                    slot, object_boilerplate_description, flags);
    SetAccumulator(result);
    // TODO(klaasb) build a single dispatch once the call is inlined
    Dispatch();
  }
}

// CreateEmptyObjectLiteral
//
// Creates an empty JSObject literal.
IGNITION_HANDLER(CreateEmptyObjectLiteral, InterpreterAssembler) {
  TNode<Context> context = GetContext();
  ConstructorBuiltinsAssembler constructor_assembler(state());
  TNode<JSObject> result =
      constructor_assembler.CreateEmptyObjectLiteral(context);
  SetAccumulator(result);
  Dispatch();
}

// CloneObject <source_idx> <flags> <feedback_slot>
//
// Allocates a new JSObject with each enumerable own property copied from
// {source}, converting getters into data properties.
IGNITION_HANDLER(CloneObject, InterpreterAssembler) {
  TNode<Object> source = LoadRegisterAtOperandIndex(0);
  TNode<Uint32T> bytecode_flags = BytecodeOperandFlag8(1);
  TNode<UintPtrT> raw_flags =
      DecodeWordFromWord32<CreateObjectLiteralFlags::FlagsBits>(bytecode_flags);
  TNode<Smi> smi_flags = SmiTag(Signed(raw_flags));
  TNode<TaggedIndex> slot = BytecodeOperandIdxTaggedIndex(2);
  TNode<HeapObject> maybe_feedback_vector = LoadFeedbackVector();
  TNode<Context> context = GetContext();

  TNode<Object> result = CallBuiltin(Builtin::kCloneObjectIC, context, source,
                                     smi_flags, slot, maybe_feedback_vector);
  SetAccumulator(result);
  Dispatch();
}

// GetTemplateObject <descriptor_idx> <literal_idx>
//
// Creates the template to pass for tagged templates and returns it in the
// accumulator, creating and caching the site object on-demand as per the
// specification.
IGNITION_HANDLER(GetTemplateObject, InterpreterAssembler) {
  TNode<Context> context = GetContext();
  TNode<JSFunction> closure = LoadFunctionClosure();
  TNode<SharedFunctionInfo> shared_info = LoadObjectField<SharedFunctionInfo>(
      closure, JSFunction::kSharedFunctionInfoOffset);
  TNode<Object> description = LoadConstantPoolEntryAtOperandIndex(0);
  TNode<UintPtrT> slot = BytecodeOperandIdx(1);
  TNode<HeapObject> maybe_feedback_vector = LoadFeedbackVector();
  TNode<Object> result =
      CallBuiltin(Builtin::kGetTemplateObject, context, shared_info,
                  description, slot, maybe_feedback_vector);
  SetAccumulator(result);
  Dispatch();
}

// CreateClosure <index> <slot> <flags>
//
// Creates a new closure for SharedFunctionInfo at position |index| in the
// constant pool and with pretenuring controlled by |flags|.
IGNITION_HANDLER(CreateClosure, InterpreterAssembler) {
  TNode<Object> shared = LoadConstantPoolEntryAtOperandIndex(0);
  TNode<Uint32T> flags = BytecodeOperandFlag8(2);
  TNode<Context> context = GetContext();
  TNode<UintPtrT> slot = BytecodeOperandIdx(1);

  Label if_undefined(this);
  TNode<ClosureFeedbackCellArray> feedback_cell_array =
      LoadClosureFeedbackArray(LoadFunctionClosure());
  TNode<FeedbackCell> feedback_cell =
      LoadArrayElement(feedback_cell_array, slot);

  Label if_fast(this), if_slow(this, Label::kDeferred);
  Branch(IsSetWord32<CreateClosureFlags::FastNewClosureBit>(flags), &if_fast,
         &if_slow);

  BIND(&if_fast);
  {
    TNode<Object> result =
        CallBuiltin(Builtin::kFastNewClosure, context, shared, feedback_cell);
    SetAccumulator(result);
    Dispatch();
  }

  BIND(&if_slow);
  {
    Label if_newspace(this), if_oldspace(this);
    Branch(IsSetWord32<CreateClosureFlags::PretenuredBit>(flags), &if_oldspace,
           &if_newspace);

    BIND(&if_newspace);
    {
      TNode<Object> result =
          CallRuntime(Runtime::kNewClosure, context, shared, feedback_cell);
      SetAccumulator(result);
      Dispatch();
    }

    BIND(&if_oldspace);
    {
      TNode<Object> result = CallRuntime(Runtime::kNewClosure_Tenured, context,
                                         shared, feedback_cell);
      SetAccumulator(result);
      Dispatch();
    }
  }
}

// CreateBlockContext <index>
//
// Creates a new block context with the scope info constant at |index|.
IGNITION_HANDLER(CreateBlockContext, InterpreterAssembler) {
  TNode<ScopeInfo> scope_info = CAST(LoadConstantPoolEntryAtOperandIndex(0));
  TNode<Context> context = GetContext();
  SetAccumulator(CallRuntime(Runtime::kPushBlockContext, context, scope_info));
  Dispatch();
}

// CreateCatchContext <exception> <scope_info_idx>
//
// Creates a new context for a catch block with the |exception| in a register
// and the ScopeInfo at |scope_info_idx|.
IGNITION_HANDLER(CreateCatchContext, InterpreterAssembler) {
  TNode<Object> exception = LoadRegisterAtOperandIndex(0);
  TNode<ScopeInfo> scope_info = CAST(LoadConstantPoolEntryAtOperandIndex(1));
  TNode<Context> context = GetContext();
  SetAccumulator(
      CallRuntime(Runtime::kPushCatchContext, context, exception, scope_info));
  Dispatch();
}

// CreateFunctionContext <scope_info_idx> <slots>
//
// Creates a new context with number of |slots| for the function closure.
IGNITION_HANDLER(CreateFunctionContext, InterpreterAssembler) {
  TNode<UintPtrT> scope_info_idx = BytecodeOperandIdx(0);
  TNode<ScopeInfo> scope_info = CAST(LoadConstantPoolEntry(scope_info_idx));
  TNode<Uint32T> slots = BytecodeOperandUImm(1);
  TNode<Context> context = GetContext();
  ConstructorBuiltinsAssembler constructor_assembler(state());
  SetAccumulator(constructor_assembler.FastNewFunctionContext(
      scope_info, slots, context, FUNCTION_SCOPE));
  Dispatch();
}

// CreateEvalContext <scope_info_idx> <slots>
//
// Creates a new context with number of |slots| for an eval closure.
IGNITION_HANDLER(CreateEvalContext, InterpreterAssembler) {
  TNode<UintPtrT> scope_info_idx = BytecodeOperandIdx(0);
  TNode<ScopeInfo> scope_info = CAST(LoadConstantPoolEntry(scope_info_idx));
  TNode<Uint32T> slots = BytecodeOperandUImm(1);
  TNode<Context> context = GetContext();
  ConstructorBuiltinsAssembler constructor_assembler(state());
  SetAccumulator(constructor_assembler.FastNewFunctionContext(
      scope_info, slots, context, EVAL_SCOPE));
  Dispatch();
}

// CreateWithContext <register> <scope_info_idx>
//
// Creates a new context with the ScopeInfo at |scope_info_idx| for a
// with-statement with the object in |register|.
IGNITION_HANDLER(CreateWithContext, InterpreterAssembler) {
  TNode<Object> object = LoadRegisterAtOperandIndex(0);
  TNode<ScopeInfo> scope_info = CAST(LoadConstantPoolEntryAtOperandIndex(1));
  TNode<Context> context = GetContext();
  SetAccumulator(
      CallRuntime(Runtime::kPushWithContext, context, object, scope_info));
  Dispatch();
}

// CreateMappedArguments
//
// Creates a new mapped arguments object.
IGNITION_HANDLER(CreateMappedArguments, InterpreterAssembler) {
  TNode<JSFunction> closure = LoadFunctionClosure();
  TNode<Context> context = GetContext();

  Label if_duplicate_parameters(this, Label::kDeferred);
  Label if_not_duplicate_parameters(this);

  // Check if function has duplicate parameters.
  // TODO(rmcilroy): Remove this check when FastNewSloppyArgumentsStub supports
  // duplicate parameters.
  TNode<SharedFunctionInfo> shared_info = LoadObjectField<SharedFunctionInfo>(
      closure, JSFunction::kSharedFunctionInfoOffset);
  TNode<Uint32T> flags =
      LoadObjectField<Uint32T>(shared_info, SharedFunctionInfo::kFlagsOffset);
  TNode<BoolT> has_duplicate_parameters =
      IsSetWord32<SharedFunctionInfo::HasDuplicateParametersBit>(flags);
  Branch(has_duplicate_parameters, &if_duplicate_parameters,
         &if_not_duplicate_parameters);

  BIND(&if_not_duplicate_parameters);
  {
    TNode<JSObject> result = EmitFastNewSloppyArguments(context, closure);
    SetAccumulator(result);
    Dispatch();
  }

  BIND(&if_duplicate_parameters);
  {
    TNode<Object> result =
        CallRuntime(Runtime::kNewSloppyArguments, context, closure);
    SetAccumulator(result);
    Dispatch();
  }
}

// CreateUnmappedArguments
//
// Creates a new unmapped arguments object.
IGNITION_HANDLER(CreateUnmappedArguments, InterpreterAssembler) {
  TNode<Context> context = GetContext();
  TNode<JSFunction> closure = LoadFunctionClosure();
  TorqueGeneratedExportedMacrosAssembler builtins_assembler(state());
  TNode<JSObject> result =
      builtins_assembler.EmitFastNewStrictArguments(context, closure);
  SetAccumulator(result);
  Dispatch();
}

// CreateRestParameter
//
// Creates a new rest parameter array.
IGNITION_HANDLER(CreateRestParameter, InterpreterAssembler) {
  TNode<JSFunction> closure = LoadFunctionClosure();
  TNode<Context> context = GetContext();
  TorqueGeneratedExportedMacrosAssembler builtins_assembler(state());
  TNode<JSObject> result =
      builtins_assembler.EmitFastNewRestArguments(context, closure);
  SetAccumulator(result);
  Dispatch();
}

// SetPendingMessage
//
// Sets the pending message to the value in the accumulator, and returns the
// previous pending message in the accumulator.
IGNITION_HANDLER(SetPendingMessage, InterpreterAssembler) {
  TNode<HeapObject> previous_message = GetPendingMessage();
  SetPendingMessage(CAST(GetAccumulator()));
  SetAccumulator(previous_message);
  Dispatch();
}

// Throw
//
// Throws the exception in the accumulator.
IGNITION_HANDLER(Throw, InterpreterAssembler) {
  TNode<Object> exception = GetAccumulator();
  TNode<Context> context = GetContext();
  CallRuntime(Runtime::kThrow, context, exception);
  // We shouldn't ever return from a throw.
  Abort(AbortReason::kUnexpectedReturnFromThrow);
  Unreachable();
}

// ReThrow
//
// Re-throws the exception in the accumulator.
IGNITION_HANDLER(ReThrow, InterpreterAssembler) {
  TNode<Object> exception = GetAccumulator();
  TNode<Context> context = GetContext();
  CallRuntime(Runtime::kReThrow, context, exception);
  // We shouldn't ever return from a throw.
  Abort(AbortReason::kUnexpectedReturnFromThrow);
  Unreachable();
}

// Abort <abort_reason>
//
// Aborts execution (via a call to the runtime function).
IGNITION_HANDLER(Abort, InterpreterAssembler) {
  TNode<UintPtrT> reason = BytecodeOperandIdx(0);
  CallRuntime(Runtime::kAbort, NoContextConstant(), SmiTag(Signed(reason)));
  Unreachable();
}

// Return
//
// Return the value in the accumulator.
IGNITION_HANDLER(Return, InterpreterAssembler) {
  UpdateInterruptBudgetOnReturn();
  TNode<Object> accumulator = GetAccumulator();
  Return(accumulator);
}

// ThrowReferenceErrorIfHole <variable_name>
//
// Throws an exception if the value in the accumulator is TheHole.
IGNITION_HANDLER(ThrowReferenceErrorIfHole, InterpreterAssembler) {
  TNode<Object> value = GetAccumulator();

  Label throw_error(this, Label::kDeferred);
  GotoIf(TaggedEqual(value, TheHoleConstant()), &throw_error);
  Dispatch();

  BIND(&throw_error);
  {
    TNode<Name> name = CAST(LoadConstantPoolEntryAtOperandIndex(0));
    CallRuntime(Runtime::kThrowAccessedUninitializedVariable, GetContext(),
                name);
    // We shouldn't ever return from a throw.
    Abort(AbortReason::kUnexpectedReturnFromThrow);
    Unreachable();
  }
}

// ThrowSuperNotCalledIfHole
//
// Throws an exception if the value in the accumulator is TheHole.
IGNITION_HANDLER(ThrowSuperNotCalledIfHole, InterpreterAssembler) {
  TNode<Object> value = GetAccumulator();

  Label throw_error(this, Label::kDeferred);
  GotoIf(TaggedEqual(value, TheHoleConstant()), &throw_error);
  Dispatch();

  BIND(&throw_error);
  {
    CallRuntime(Runtime::kThrowSuperNotCalled, GetContext());
    // We shouldn't ever return from a throw.
    Abort(AbortReason::kUnexpectedReturnFromThrow);
    Unreachable();
  }
}

// ThrowSuperAlreadyCalledIfNotHole
//
// Throws SuperAlreadyCalled exception if the value in the accumulator is not
// TheHole.
IGNITION_HANDLER(ThrowSuperAlreadyCalledIfNotHole, InterpreterAssembler) {
  TNode<Object> value = GetAccumulator();

  Label throw_error(this, Label::kDeferred);
  GotoIf(TaggedNotEqual(value, TheHoleConstant()), &throw_error);
  Dispatch();

  BIND(&throw_error);
  {
    CallRuntime(Runtime::kThrowSuperAlreadyCalledError, GetContext());
    // We shouldn't ever return from a throw.
    Abort(AbortReason::kUnexpectedReturnFromThrow);
    Unreachable();
  }
}

// ThrowIfNotSuperConstructor <constructor>
//
// Throws an exception if the value in |constructor| is not in fact a
// constructor.
IGNITION_HANDLER(ThrowIfNotSuperConstructor, InterpreterAssembler) {
  TNode<HeapObject> constructor = CAST(LoadRegisterAtOperandIndex(0));
  TNode<Context> context = GetContext();

  Label is_not_constructor(this, Label::kDeferred);
  TNode<Map> constructor_map = LoadMap(constructor);
  GotoIfNot(IsConstructorMap(constructor_map), &is_not_constructor);
  Dispatch();

  BIND(&is_not_constructor);
  {
    TNode<JSFunction> function = LoadFunctionClosure();
    CallRuntime(Runtime::kThrowNotSuperConstructor, context, constructor,
                function);
    // We shouldn't ever return from a throw.
    Abort(AbortReason::kUnexpectedReturnFromThrow);
    Unreachable();
  }
}

// FindNonDefaultConstructorOrConstruct <this_function> <new_target> <output>
//
// Walks the prototype chain from <this_function>'s super ctor until we see a
// non-default ctor. If the walk ends at a default base ctor, creates an
// instance and stores it in <output[1]> and stores true into output[0].
// Otherwise, stores the first non-default ctor into <output[1]> and false into
// <output[0]>.
IGNITION_HANDLER(FindNonDefaultConstructorOrConstruct, InterpreterAssembler) {
  TNode<Context> context = GetContext();
  TVARIABLE(Object, constructor);
  Label found_default_base_ctor(this, &constructor),
      found_something_else(this, &constructor);

  TNode<JSFunction> this_function = CAST(LoadRegisterAtOperandIndex(0));

  FindNonDefaultConstructor(this_function, constructor,
                            &found_default_base_ctor, &found_something_else);

  BIND(&found_default_base_ctor);
  {
    // Create an object directly, without calling the default base ctor.
    TNode<Object> new_target = LoadRegisterAtOperandIndex(1);
    TNode<Object> instance = CallBuiltin(Builtin::kFastNewObject, context,
                                         constructor.value(), new_target);

    StoreRegisterPairAtOperandIndex(TrueConstant(), instance, 2);
    Dispatch();
  }

  BIND(&found_something_else);
  {
    // Not a base ctor (or bailed out).
    StoreRegisterPairAtOperandIndex(FalseConstant(), constructor.value(), 2);
    Dispatch();
  }
}

// Debugger
//
// Call runtime to handle debugger statement.
IGNITION_HANDLER(Debugger, InterpreterAssembler) {
  TNode<Context> context = GetContext();
  TNode<Object> result =
      CallRuntime(Runtime::kHandleDebuggerStatement, context);
  ClobberAccumulator(result);
  Dispatch();
}

// DebugBreak
//
// Call runtime to handle a debug break.
#define DEBUG_BREAK(Name, ...)                                               \
  IGNITION_HANDLER(Name, InterpreterAssembler) {                             \
    TNode<Context> context = GetContext();                                   \
    TNode<Object> accumulator = GetAccumulator();                            \
    TNode<PairT<Object, Smi>> result_pair = CallRuntime<PairT<Object, Smi>>( \
        Runtime::kDebugBreakOnBytecode, context, accumulator);               \
    TNode<Object> return_value = Projection<0>(result_pair);                 \
    TNode<IntPtrT> original_bytecode = SmiUntag(Projection<1>(result_pair)); \
    SetAccumulator(return_value);                                            \
    DispatchToBytecodeWithOptionalStarLookahead(original_bytecode);          \
  }
DEBUG_BREAK_BYTECODE_LIST(DEBUG_BREAK)
#undef DEBUG_BREAK

// IncBlockCounter <slot>
//
// Increment the execution count for the given slot. Used for block code
// coverage.
IGNITION_HANDLER(IncBlockCounter, InterpreterAssembler) {
  TNode<JSFunction> closure = LoadFunctionClosure();
  TNode<Smi> coverage_array_slot = BytecodeOperandIdxSmi(0);
  TNode<Context> context = GetContext();

  CallBuiltin(Builtin::kIncBlockCounter, context, closure, coverage_array_slot);

  Dispatch();
}

// ForInEnumerate <receiver>
//
// Enumerates the enumerable keys of the |receiver| and either returns the
// map of the |receiver| if it has a usable enum cache or a fixed array
// with the keys to enumerate in the accumulator.
IGNITION_HANDLER(ForInEnumerate, InterpreterAssembler) {
  TNode<JSReceiver> receiver = CAST(LoadRegisterAtOperandIndex(0));
  TNode<Context> context = GetContext();

  Label if_empty(this), if_runtime(this, Label::kDeferred);
  TNode<Map> receiver_map = CheckEnumCache(receiver, &if_empty, &if_runtime);
  SetAccumulator(receiver_map);
  Dispatch();

  BIND(&if_empty);
  {
    TNode<FixedArray> result = EmptyFixedArrayConstant();
    SetAccumulator(result);
    Dispatch();
  }

  BIND(&if_runtime);
  {
    TNode<Object> result =
        CallRuntime(Runtime::kForInEnumerate, context, receiver);
    SetAccumulator(result);
    Dispatch();
  }
}

// ForInPrepare <cache_info_triple>
//
// Returns state for for..in loop execution based on the enumerator in
// the accumulator register, which is the result of calling ForInEnumerate
// on a JSReceiver object.
// The result is output in registers |cache_info_triple| to
// |cache_info_triple + 2|, with the registers holding cache_type, cache_array,
// and cache_length respectively.
IGNITION_HANDLER(ForInPrepare, InterpreterAssembler) {
  // The {enumerator} is either a Map or a FixedArray.
  TNode<HeapObject> enumerator = CAST(GetAccumulator());
  TNode<UintPtrT> vector_index = BytecodeOperandIdx(1);
  TNode<HeapObject> maybe_feedback_vector = LoadFeedbackVector();

  TNode<HeapObject> cache_type = enumerator;  // Just to clarify the rename.
  TNode<FixedArray> cache_array;
  TNode<Smi> cache_length;
  ForInPrepare(enumerator, vector_index, maybe_feedback_vector, &cache_array,
               &cache_length, UpdateFeedbackMode::kOptionalFeedback);

  ClobberAccumulator(SmiConstant(0));

  StoreRegisterTripleAtOperandIndex(cache_type, cache_array, cache_length, 0);
  Dispatch();
}

// ForInNext <receiver> <index> <cache_info_pair>
//
// Returns the next enumerable property in the the accumulator.
IGNITION_HANDLER(ForInNext, InterpreterAssembler) {
  TNode<HeapObject> receiver = CAST(LoadRegisterAtOperandIndex(0));
  TNode<Smi> index = CAST(LoadRegisterAtOperandIndex(1));
  TNode<Object> cache_type;
  TNode<Object> cache_array;
  std::tie(cache_type, cache_array) = LoadRegisterPairAtOperandIndex(2);
  TNode<UintPtrT> vector_index = BytecodeOperandIdx(3);
  TNode<HeapObject> maybe_feedback_vector = LoadFeedbackVector();

  // Load the next key from the enumeration array.
  TNode<Object> key = LoadFixedArrayElement(CAST(cache_array), index, 0);

  // Check if we can use the for-in fast path potentially using the enum cache.
  Label if_fast(this), if_slow(this, Label::kDeferred);
  TNode<Map> receiver_map = LoadMap(receiver);
  Branch(TaggedEqual(receiver_map, cache_type), &if_fast, &if_slow);
  BIND(&if_fast);
  {
    // Enum cache in use for {receiver}, the {key} is definitely valid.
    SetAccumulator(key);
    Dispatch();
  }
  BIND(&if_slow);
  {
    TNode<Object> result = ForInNextSlow(GetContext(), vector_index, receiver,
                                         key, cache_type, maybe_feedback_vector,
                                         UpdateFeedbackMode::kOptionalFeedback);
    SetAccumulator(result);
    Dispatch();
  }
}

// ForInStep <index>
//
// Increments the loop counter in register |index| and stores the result
// back into the same register.
IGNITION_HANDLER(ForInStep, InterpreterAssembler) {
  TNode<Smi> index = CAST(LoadRegisterAtOperandIndex(0));
  TNode<Smi> one = SmiConstant(1);
  TNode<Smi> result = SmiAdd(index, one);
  StoreRegisterAtOperandIndex(result, 0);
  Dispatch();
}

// GetIterator <object>
//
// Retrieves the object[Symbol.iterator] method, calls it and stores
// the result in the accumulator. If the result is not JSReceiver,
// throw SymbolIteratorInvalid runtime exception.
IGNITION_HANDLER(GetIterator, InterpreterAssembler) {
  TNode<Object> receiver = LoadRegisterAtOperandIndex(0);
  TNode<Context> context = GetContext();
  TNode<HeapObject> feedback_vector = LoadFeedbackVector();
  TNode<TaggedIndex> load_slot = BytecodeOperandIdxTaggedIndex(1);
  TNode<TaggedIndex> call_slot = BytecodeOperandIdxTaggedIndex(2);

  TNode<Object> iterator =
      CallBuiltin(Builtin::kGetIteratorWithFeedback, context, receiver,
                  load_slot, call_slot, feedback_vector);
  SetAccumulator(iterator);
  Dispatch();
}

// Wide
//
// Prefix bytecode indicating next bytecode has wide (16-bit) operands.
IGNITION_HANDLER(Wide, InterpreterAssembler) {
  DispatchWide(OperandScale::kDouble);
}

// ExtraWide
//
// Prefix bytecode indicating next bytecode has extra-wide (32-bit) operands.
IGNITION_HANDLER(ExtraWide, InterpreterAssembler) {
  DispatchWide(OperandScale::kQuadruple);
}

// Illegal
//
// An invalid bytecode aborting execution if dispatched.
IGNITION_HANDLER(Illegal, InterpreterAssembler) {
  Abort(AbortReason::kInvalidBytecode);
  Unreachable();
}

// SuspendGenerator <generator> <first input register> <register count>
// <suspend_id>
//
// Stores the parameters and the register file in the generator. Also stores
// the current context, |suspend_id|, and the current bytecode offset
// (for debugging purposes) into the generator. Then, returns the value
// in the accumulator.
IGNITION_HANDLER(SuspendGenerator, InterpreterAssembler) {
  TNode<JSGeneratorObject> generator = CAST(LoadRegisterAtOperandIndex(0));
  TNode<FixedArray> array = CAST(LoadObjectField(
      generator, JSGeneratorObject::kParametersAndRegistersOffset));
  TNode<Context> context = GetContext();
  RegListNodePair registers = GetRegisterListAtOperandIndex(1);
  TNode<Smi> suspend_id = BytecodeOperandUImmSmi(3);

  ExportParametersAndRegisterFile(array, registers);
  StoreObjectField(generator, JSGeneratorObject::kContextOffset, context);
  StoreObjectField(generator, JSGeneratorObject::kContinuationOffset,
                   suspend_id);

  // Store the bytecode offset in the [input_or_debug_pos] field, to be used by
  // the inspector.
  TNode<Smi> offset = SmiTag(BytecodeOffset());
  StoreObjectField(generator, JSGeneratorObject::kInputOrDebugPosOffset,
                   offset);

  Return(GetAccumulator());
}

// SwitchOnGeneratorState <generator> <table_start> <table_length>
//
// If |generator| is undefined, falls through. Otherwise, loads the
// generator's state (overwriting it with kGeneratorExecuting), sets the context
// to the generator's resume context, and performs state dispatch on the
// generator's state by looking up the generator state in a jump table in the
// constant pool, starting at |table_start|, and of length |table_length|.
IGNITION_HANDLER(SwitchOnGeneratorState, InterpreterAssembler) {
  TNode<Object> maybe_generator = LoadRegisterAtOperandIndex(0);

  Label fallthrough(this);
  GotoIf(TaggedEqual(maybe_generator, UndefinedConstant()), &fallthrough);

  TNode<JSGeneratorObject> generator = CAST(maybe_generator);

  TNode<Smi> state =
      CAST(LoadObjectField(generator, JSGeneratorObject::kContinuationOffset));
  TNode<Smi> new_state = SmiConstant(JSGeneratorObject::kGeneratorExecuting);
  StoreObjectField(generator, JSGeneratorObject::kContinuationOffset,
                   new_state);

  TNode<Context> context =
      CAST(LoadObjectField(generator, JSGeneratorObject::kContextOffset));
  SetContext(context);

  TNode<UintPtrT> table_start = BytecodeOperandIdx(1);
  TNode<UintPtrT> table_length = BytecodeOperandUImmWord(2);

  // The state must be a Smi.
  CSA_DCHECK(this, TaggedIsSmi(state));

  TNode<IntPtrT> case_value = SmiUntag(state);

  // When the sandbox is enabled, the generator state must be assumed to be
  // untrusted as it is located inside the sandbox, so validate it here.
  CSA_SBXCHECK(this, UintPtrLessThan(case_value, table_length));
  USE(table_length);  // SBXCHECK is a DCHECK when the sandbox is disabled.

  TNode<WordT> entry = IntPtrAdd(table_start, case_value);
  TNode<IntPtrT> relative_jump = LoadAndUntagConstantPoolEntry(entry);
  Jump(relative_jump);

  BIND(&fallthrough);
  Dispatch();
}

// ResumeGenerator <generator> <first output register> <register count>
//
// Imports the register file stored in the generator and marks the generator
// state as executing.
IGNITION_HANDLER(ResumeGenerator, InterpreterAssembler) {
  TNode<JSGeneratorObject> generator = CAST(LoadRegisterAtOperandIndex(0));
  RegListNodePair registers = GetRegisterListAtOperandIndex(1);

  ImportRegisterFile(
      CAST(LoadObjectField(generator,
                           JSGeneratorObject::kParametersAndRegistersOffset)),
      registers);

  // Return the generator's input_or_debug_pos in the accumulator.
  SetAccumulator(
      LoadObjectField(generator, JSGeneratorObject::kInputOrDebugPosOffset));

  Dispatch();
}

#undef IGNITION_HANDLER

}  // namespace

void BitwiseNotAssemblerTS_Generate(compiler::turboshaft::PipelineData* data,
                                    Isolate* isolate,
                                    compiler::turboshaft::Graph& graph,
                                    Zone* zone);

Handle<Code> GenerateBytecodeHandler(Isolate* isolate, const char* debug_name,
                                     Bytecode bytecode,
                                     OperandScale operand_scale,
                                     Builtin builtin,
                                     const AssemblerOptions& options) {
  Zone zone(isolate->allocator(), ZONE_NAME, kCompressGraphZone);
  compiler::CodeAssemblerState state(
      isolate, &zone, InterpreterDispatchDescriptor{},
      CodeKind::BYTECODE_HANDLER, debug_name, builtin);

  const auto descriptor_builder = [](Zone* zone) {
    InterpreterDispatchDescriptor descriptor{};
    return compiler::Linkage::GetStubCallDescriptor(
        zone, descriptor, descriptor.GetStackParameterCount(),
        compiler::CallDescriptor::kNoFlags, compiler::Operator::kNoProperties);
  };
  USE(descriptor_builder);

  Handle<Code> code;
  switch (bytecode) {
#define CALL_GENERATOR(Name, ...)                     \
  case Bytecode::k##Name:                             \
    Name##Assembler::Generate(&state, operand_scale); \
    break;
#define CALL_GENERATOR_TS(Name, ...)                                       \
  case Bytecode::k##Name:                                                  \
    code = compiler::turboshaft::BuildWithTurboshaftAssemblerImpl(         \
        isolate, builtin, &Name##AssemblerTS_Generate, descriptor_builder, \
        debug_name, options, CodeKind::BYTECODE_HANDLER,                   \
        BytecodeHandlerData(bytecode, operand_scale));                     \
    break;
    BYTECODE_LIST_WITH_UNIQUE_HANDLERS(CALL_GENERATOR, CALL_GENERATOR_TS);
#undef CALL_GENERATOR
#undef CALL_GENERATOR_TS
    case Bytecode::kIllegal:
      IllegalAssembler::Generate(&state, operand_scale);
      break;
    case Bytecode::kStar0:
      Star0Assembler::Generate(&state, operand_scale);
      break;
    default:
      // Others (the rest of the short stars, and the rest of the illegal range)
      // must not get their own handler generated. Rather, multiple entries in
      // the jump table point to those handlers.
      UNREACHABLE();
  }

  if (code.is_null()) {
    code = compiler::CodeAssembler::GenerateCode(
        &state, options, ProfileDataFromFile::TryRead(debug_name));
  }

#ifdef ENABLE_DISASSEMBLER
  if (v8_flags.trace_ignition_codegen) {
    StdoutStream os;
    code->Disassemble(Bytecodes::ToString(bytecode), os, isolate);
    os << std::flush;
  }
#endif  // ENABLE_DISASSEMBLER

  return code;
}

#include "src/codegen/undef-code-stub-assembler-macros.inc"

}  // namespace interpreter
}  // namespace internal
}  // namespace v8

"""


```