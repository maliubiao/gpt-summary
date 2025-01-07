Response:
My thinking process to answer the request about the Torque file involved several steps:

1. **Understanding the Request:** I first parsed the request to identify the key pieces of information needed. The user wants to understand the functionality of the provided Torque code, with specific requests for examples related to JavaScript, code logic, and common errors.

2. **Recognizing the File Type and Purpose:** The `.tq` extension immediately signaled that this is a Torque file. The comment at the top confirms it's a V8 Torque source file. Knowing this is V8 code means it's involved in the internal implementation of JavaScript features.

3. **Initial Code Scan for High-Level Functionality:** I quickly scanned the code for keywords and patterns that reveal the general purpose. I noticed:
    * `@export macro`:  This indicates macros intended to be accessible and likely used for testing or as entry points.
    * `check(...)`:  This suggests a testing framework within the code itself.
    * `builtin`:  This denotes calls to built-in functions, often implemented in C++ within V8.
    * `struct`, `class`: These define data structures and internal classes.
    * `try...label...otherwise`: This indicates a control flow mechanism specific to Torque.
    * `typeswitch`:  This suggests type-based dispatch, a common pattern in language implementations.
    * `for` loops, `if` statements: Standard control flow constructs.

4. **Categorizing Functionality by Macro:** I then systematically went through each `@export macro` to understand its specific purpose. I grouped them by the kind of feature they were testing or demonstrating:
    * **Constexpr (Compile-Time Evaluation):** `TestConstexpr1`, `TestConstexprIf`, `TestConstexprReturn`. These test the compile-time evaluation capabilities of Torque.
    * **Labels and `goto`:** `TestGotoLabel`, `TestGotoLabelWithOneParameter`, `TestGotoLabelWithTwoParameters`, `TestPartiallyUnusedLabel`, `CallTestStructInLabel`. These explore Torque's label and `goto` functionality.
    * **Generic Macros and Builtins:** `TestBuiltinSpecialization`, `TestMacroSpecialization`, `TestFunctionPointerToGeneric`. These examine how Torque handles generics (templates) for macros and built-in functions.
    * **Function Pointers:** `TestFunctionPointers`.
    * **Variable Declarations and Operators:** `TestVariableRedeclaration`, `TestTernaryOperator`.
    * **Type System:** `TestTypeAlias`, `TestUnsafeCast`, `TestSubtyping`, `TestTypeswitch`.
    * **Literals and Constants:** `TestHexLiteral`, `TestLargeIntegerLiterals`, `TestModuleConstBindings`, `TestLocalConstBindings`.
    * **Structs:** `TestStruct1` through `TestStruct4`, `TestStructConstructor`, `TestConstInStructs`. These exercise struct definition, usage, and initialization.
    * **Control Flow:** `TestForLoop`, `TestCall`, `TestOtherwiseWithCode1` through `TestOtherwiseWithCode3`, `TestForwardLabel`.
    * **Error Handling:** `TestCatch1`, `TestCatch2`, `TestCatch3`.
    * **Internal V8 Concepts:** `TestIterator`, `TestFrame1`, `TestNew`, `TestParentFrameArguments`, `TestNewFixedArrayFromSpread`.
    * **Internal Classes:** `TestInternalClass`, `TestFullyGeneratedClassFromCpp`.
    * **References and Slices:** `TestReferences`, `TestSlices`, `TestSliceEnumeration`.
    * **Assertions:** `TestMultilineAssert`, `TestStaticAssert`.
    * **Load Elimination:** `TestLoadEliminationFixed`, `TestLoadEliminationVariable`.
    * **Redundant Checks:** `TestRedundantArrayElementCheck`, `TestRedundantSmiCheck`.
    * **Generic Structs:** `TestGenericStruct1`, `TestGenericStruct2`.
    * **Optimization Tests:** `TestBranchOnBoolOptimization`.
    * **Bitfields:** `TestBitFieldLoad` through `TestBitFieldUintptrOps`, `TestBitFieldMultipleFlags`.
    * **Class Inheritance and Casting:** `TestExportedSubClass`, `TestGeneratedCastOperators`.
    * **Memory Management (Pretenuring):** `TestNewPretenured`.
    * **Low-Level Operations:** `TestWord8Phi`, `TestOffHeapSlice`.
    * **Multi-Return Values:** `TestCallMultiReturnBuiltin`.
    * **Lazy Evaluation:** `TestRunLazyTwice`, `TestCreateLazyNodeFromTorque`.
    * **Builtin Calls and Side Effects:** `TestIncrementArraySpeciesModified`.

5. **Connecting Torque to JavaScript:** For each category of functionality, I considered how it relates to JavaScript. This involved thinking about:
    * **What JavaScript feature does this Torque code implement or test?** (e.g., array handling, object creation, function calls, type checking).
    * **How would a JavaScript developer interact with this feature?** (e.g., creating arrays, calling functions, performing type checks).
    * **Could I create a simple JavaScript example that demonstrates the same concept?**

6. **Providing Concrete Examples:** For the JavaScript examples, I aimed for simplicity and clarity, directly illustrating the functionality tested in the corresponding Torque macro.

7. **Inferring Code Logic and Providing Input/Output:** For macros that perform computations or conditional logic, I chose simple input values and traced the execution to determine the expected output. This helps illustrate the control flow and data manipulation.

8. **Identifying Common Programming Errors:**  I leveraged my knowledge of common JavaScript and programming pitfalls to connect the Torque features to potential errors. For instance, type mismatches, incorrect assumptions about data types, and issues with control flow are common.

9. **Structuring the Answer:** I organized the answer logically, starting with a general overview and then providing specific details for each category. I used clear headings and formatting to improve readability.

10. **Review and Refinement:** I reviewed my answer to ensure accuracy, completeness, and clarity. I checked that the JavaScript examples were correct and that the explanations were easy to understand.

Essentially, my process involved understanding the nature of Torque code, systematically analyzing the provided file, connecting the low-level Torque concepts to higher-level JavaScript features, and then providing concrete examples and explanations to illustrate the functionality. The key was to bridge the gap between the V8 internal implementation and the user-facing JavaScript language.
好的，让我们来分析一下 `v8/test/torque/test-torque.tq` 这个 Torque 源代码文件的功能。

**文件类型和用途**

正如你所说，以 `.tq` 结尾的文件是 V8 的 Torque 源代码文件。 Torque 是一种用于编写 V8 内部函数（builtins）的领域特定语言 (DSL)。它的主要目的是提高 V8 代码的可读性、可维护性和安全性。

**功能概览**

`test-torque.tq` 文件，正如其名称所示，是一个 **测试文件**。它的主要功能是 **测试 Torque 语言本身的各种特性和功能**。它不直接对应于某个特定的 JavaScript 功能，而是验证 Torque 编译器的正确性和 Torque 代码的执行逻辑。

**具体功能分解**

这个文件包含了大量的 `@export macro` 定义，每个 macro 都是一个独立的测试用例，用于验证 Torque 的不同方面，包括：

1. **常量表达式 (Constexpr):**
   - `TestConstexpr1`, `TestConstexprIf`, `TestConstexprReturn`: 测试 Torque 是否能正确处理在编译时求值的常量表达式。

2. **标签 (Labels) 和 `goto` 语句:**
   - `TestGotoLabel`, `TestGotoLabelWithOneParameter`, `TestGotoLabelWithTwoParameters`, `TestPartiallyUnusedLabel`, `CallTestStructInLabel`:  测试 Torque 的标签定义和 `goto` 语句的控制流。

3. **泛型 (Generics) 和特化 (Specialization):**
   - `TestBuiltinSpecialization`, `TestMacroSpecialization`: 测试 Torque 如何处理泛型宏和内建函数的特化。

4. **函数指针 (Function Pointers):**
   - `TestFunctionPointers`, `TestFunctionPointerToGeneric`: 测试 Torque 中函数指针的使用。

5. **变量声明和运算符:**
   - `TestVariableRedeclaration`, `TestTernaryOperator`: 测试变量的重复声明和三元运算符。

6. **类型别名 (Type Alias) 和类型转换 (Cast):**
   - `TestTypeAlias`, `TestUnsafeCast`: 测试类型别名和不安全的类型转换。

7. **字面量 (Literals):**
   - `TestHexLiteral`, `TestLargeIntegerLiterals`: 测试十六进制和大型整数的字面量表示。

8. **模块和局部常量绑定:**
   - `TestModuleConstBindings`, `TestLocalConstBindings`: 测试常量在模块和局部作用域中的绑定。

9. **结构体 (Structs):**
   - `TestStruct1` 到 `TestStruct4`, `TestStructConstructor`, `TestConstInStructs`: 测试结构体的定义、使用和初始化。

10. **循环 (Loops):**
    - `TestForLoop`: 测试 `for` 循环的不同形式和 `break`、`continue` 语句。

11. **子类型 (Subtyping) 和类型切换 (Typeswitch):**
    - `TestSubtyping`, `TestTypeswitch`, `TestTypeswitchAsanLsanFailure`: 测试类型之间的关系和 `typeswitch` 语句。

12. **泛型重载 (Generic Overload):**
    - `TestGenericOverload`: 测试泛型宏的重载。

13. **相等性 (Equality) 和逻辑运算符:**
    - `TestEquality`, `TestOrAnd`, `TestAndOr`, `TestLogicalOperators`: 测试相等性比较和逻辑运算符。

14. **函数调用和标签跳转的结合:**
    - `TestCall`, `TestOtherwiseWithCode1` 到 `TestOtherwiseWithCode3`, `TestForwardLabel`: 测试函数调用结合 `otherwise` 语句和标签跳转。

15. **作用域解析 (Qualified Access):**
    - `TestQualifiedAccess`: 测试带限定符的访问。

16. **异常处理 (Exception Handling):**
    - `TestCatch1` 到 `TestCatch3`: 测试 `try...catch` 语句。

17. **内部 V8 概念的模拟和测试:**
    - `TestIterator`, `TestFrame1`, `TestNew`, `TestParentFrameArguments`, `TestNewFixedArrayFromSpread`:  模拟和测试 V8 内部的一些概念，如迭代器、帧、对象创建和参数处理。

18. **内部类 (Internal Class):**
    - `TestInternalClass`, `TestFullyGeneratedClassFromCpp`: 测试内部类的定义和使用。

19. **引用 (References) 和切片 (Slices):**
    - `TestReferences`, `TestSlices`, `TestSliceEnumeration`: 测试引用的使用和数组切片的操作。

20. **静态断言 (Static Assert):**
    - `TestStaticAssert`: 测试在编译时进行断言。

21. **加载消除 (Load Elimination):**
    - `TestLoadEliminationFixed`, `TestLoadEliminationVariable`: 测试编译器是否能优化掉冗余的加载操作。

22. **冗余检查:**
    - `TestRedundantArrayElementCheck`, `TestRedundantSmiCheck`: 测试编译器对冗余类型检查的处理。

23. **泛型结构体:**
    - `TestGenericStruct1`, `TestGenericStruct2`: 测试泛型结构体的定义和使用。

24. **布尔分支优化:**
    - `TestBranchOnBoolOptimization`: 测试编译器对布尔分支的优化。

25. **位域 (Bitfields):**
    - `TestBitFieldLoad` 到 `TestBitFieldUintptrOps`, `TestBitFieldMultipleFlags`: 测试位域结构体的定义和操作。

26. **类的继承和类型转换:**
    - `TestExportedSubClass`, `TestGeneratedCastOperators`: 测试类的继承和自动生成的类型转换操作符。

27. **预先分配的对象:**
    - `TestNewPretenured`: 测试在特定内存区域预先分配对象。

28. **底层操作:**
    - `TestWord8Phi`, `TestOffHeapSlice`: 测试对底层数据类型的操作。

29. **多返回值:**
    - `TestCallMultiReturnBuiltin`: 测试内建函数返回多个值的情况。

30. **惰性求值 (Lazy Evaluation):**
    - `TestRunLazyTwice`, `TestCreateLazyNodeFromTorque`: 测试惰性求值的功能。

31. **内置函数的调用和计数器增加:**
    - `TestIncrementArraySpeciesModified`: 测试调用带有副作用的内置函数，例如增加使用计数器。

**与 JavaScript 的关系及示例**

虽然这个文件主要测试 Torque 语言本身，但它所测试的特性最终都服务于 V8 执行 JavaScript 代码。 让我们举几个例子来说明它们之间的关系：

1. **常量表达式 (Constexpr):**
   - **JavaScript 例子:**  JavaScript 引擎在编译某些 JavaScript 代码时，也会进行常量折叠等优化。
     ```javascript
     const result = 2 + 3; // JavaScript 引擎可能会在编译时直接计算出 result 为 5
     ```
   - **Torque 的测试** 确保 Torque 也能在编译时正确处理常量表达式，这对于生成高效的 V8 代码至关重要。

2. **类型切换 (Typeswitch):**
   - **JavaScript 例子:** JavaScript 是一门动态类型语言，需要在运行时检查变量的类型。
     ```javascript
     function process(input) {
       if (typeof input === 'number') {
         console.log('Input is a number:', input);
       } else if (Array.isArray(input)) {
         console.log('Input is an array:', input);
       } else {
         console.log('Input is something else:', input);
       }
     }
     ```
   - **Torque 的测试**  `TestTypeswitch` 验证 Torque 的 `typeswitch` 语句能否正确处理不同类型的值，这在 V8 内部实现类型相关的操作时非常重要。

3. **结构体 (Structs):**
   - **JavaScript 例子:** JavaScript 中没有像 C++ 或 Torque 那样的显式结构体，但对象可以起到类似的作用。
     ```javascript
     const point = { x: 10, y: 20 };
     console.log(point.x);
     ```
   - **Torque 的测试**  `TestStruct*` 系列测试确保 Torque 能正确定义和操作结构体，这些结构体在 V8 内部用于组织数据。

4. **异常处理 (Exception Handling):**
   - **JavaScript 例子:** JavaScript 使用 `try...catch` 来处理运行时错误。
     ```javascript
     try {
       throw new Error('Something went wrong!');
     } catch (e) {
       console.error('Caught an error:', e.message);
     }
     ```
   - **Torque 的测试** `TestCatch*` 系列测试验证 Torque 的 `try...catch` 机制，这对于 V8 内部处理错误至关重要。

5. **内置函数 (Builtins):**
   - **JavaScript 例子:** JavaScript 的许多全局函数（如 `parseInt`、`Array.isArray`）和对象方法（如 `array.push`）都是由 V8 的内置函数实现的。
   - **Torque 的测试**  虽然 `test-torque.tq` 不直接测试 JavaScript 的内置函数，但它测试了 Torque 编写内置函数的能力，确保这些内置函数可以正确实现 JavaScript 的功能。

**代码逻辑推理和假设输入/输出**

让我们以 `TestTernaryOperator` 这个 macro 为例进行代码逻辑推理：

```torque
@export
macro TestTernaryOperator(x: Smi): Smi {
  const b: bool = x < 0 ? true : false;
  return b ? x - 10 : x + 100;
}
```

**假设输入：**
- `x = 5`

**推理过程：**
1. `const b: bool = x < 0 ? true : false;`  由于 `x` (5) 不小于 0，所以 `b` 被赋值为 `false`。
2. `return b ? x - 10 : x + 100;` 由于 `b` 是 `false`，所以返回 `x + 100`，即 `5 + 100 = 105`。

**假设输出：**
- 如果输入 `x` 为 5，则输出为 105。

**假设输入：**
- `x = -3`

**推理过程：**
1. `const b: bool = x < 0 ? true : false;` 由于 `x` (-3) 小于 0，所以 `b` 被赋值为 `true`。
2. `return b ? x - 10 : x + 100;` 由于 `b` 是 `true`，所以返回 `x - 10`，即 `-3 - 10 = -13`。

**假设输出：**
- 如果输入 `x` 为 -3，则输出为 -13。

**用户常见的编程错误**

在编写 Torque 代码或与 V8 内部机制交互时，可能会遇到一些常见的编程错误：

1. **类型不匹配:** Torque 是一种强类型语言，尝试将一种类型的值赋给不兼容的类型的变量会导致编译错误。
   ```torque
   // 错误示例
   let smi: Smi = 10;
   let obj: Object = smi; // 这是允许的，因为 Smi 是 Object 的子类型
   let number: Number = smi; // 错误！Smi 不是 Number 的子类型
   ```

2. **空指针解引用:** 虽然 Torque 提供了 `Null` 类型，但不小心解引用 `Null` 值仍然可能导致错误。

3. **不正确的类型转换:** 使用 `Cast` 或 `UnsafeCast` 时，如果类型转换不安全，可能会导致运行时错误或未定义的行为。
   ```torque
   // 潜在的错误示例
   let obj: Object = ...;
   let smi: Smi = Cast<Smi>(obj) otherwise Fail; // 如果 obj 不是 Smi，则会跳转到 Fail 标签
   ```

4. **不正确的标签使用:** `goto` 语句必须跳转到当前作用域内的标签，否则会导致编译错误。

5. **在 constexpr 上下文中使用非常量表达式:**  在期望常量表达式的地方使用了运行时才能确定的值会导致编译错误。
   ```torque
   macro MyConstexprMacro(x: constexpr int31): Smi {
     return FromConstexpr<Smi>(x + 1);
   }

   @export
   macro TestConstexprError(y: Smi): void {
     // 错误示例：y 不是 constexpr
     const result: Smi = MyConstexprMacro(y);
   }
   ```

**总结**

`v8/test/torque/test-torque.tq` 是一个至关重要的测试文件，用于确保 V8 的 Torque 语言能够正常工作。它通过大量的测试用例覆盖了 Torque 的各种语法和特性。理解这个文件的内容可以帮助开发者深入了解 Torque 语言以及 V8 内部的实现机制。虽然它不直接对应于用户编写的 JavaScript 代码，但它所测试的特性是 V8 执行 JavaScript 代码的基础。

Prompt: 
```
这是目录为v8/test/torque/test-torque.tq的一个v8源代码， 请列举一下它的功能, 
如果v8/test/torque/test-torque.tq以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2018 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Test line comment
/* Test mulitline
   comment
*/
/*multiline_without_whitespace*/

namespace test {
macro ElementsKindTestHelper1(kind: constexpr ElementsKind): bool {
  if constexpr (
      kind == ElementsKind::UINT8_ELEMENTS ||
      kind == ElementsKind::UINT16_ELEMENTS) {
    return true;
  } else {
    return false;
  }
}

macro ElementsKindTestHelper2(kind: constexpr ElementsKind): constexpr bool {
  return kind == ElementsKind::UINT8_ELEMENTS ||
      kind == ElementsKind::UINT16_ELEMENTS;
}

macro LabelTestHelper1(): never
    labels Label1 {
  goto Label1;
}

macro LabelTestHelper2(): never
    labels Label2(Smi) {
  goto Label2(42);
}

macro LabelTestHelper3(): never
    labels Label3(Oddball, Smi) {
  goto Label3(Null, 7);
}

@export
macro TestConstexpr1(): void {
  check(FromConstexpr<bool>(
      IsFastElementsKind(ElementsKind::PACKED_SMI_ELEMENTS)));
}

@export
macro TestConstexprIf(): void {
  check(ElementsKindTestHelper1(ElementsKind::UINT8_ELEMENTS));
  check(ElementsKindTestHelper1(ElementsKind::UINT16_ELEMENTS));
  check(!ElementsKindTestHelper1(ElementsKind::UINT32_ELEMENTS));
}

@export
macro TestConstexprReturn(): void {
  check(FromConstexpr<bool>(
      ElementsKindTestHelper2(ElementsKind::UINT8_ELEMENTS)));
  check(FromConstexpr<bool>(
      ElementsKindTestHelper2(ElementsKind::UINT16_ELEMENTS)));
  check(!FromConstexpr<bool>(
      ElementsKindTestHelper2(ElementsKind::UINT32_ELEMENTS)));
  check(FromConstexpr<bool>(
      !ElementsKindTestHelper2(ElementsKind::UINT32_ELEMENTS)));
}

@export
macro TestGotoLabel(): Boolean {
  try {
    LabelTestHelper1() otherwise Label1;
  } label Label1 {
    return True;
  }
}

@export
macro TestGotoLabelWithOneParameter(): Boolean {
  try {
    LabelTestHelper2() otherwise Label2;
  } label Label2(smi: Smi) {
    check(smi == 42);
    return True;
  }
}

@export
macro TestGotoLabelWithTwoParameters(): Boolean {
  try {
    LabelTestHelper3() otherwise Label3;
  } label Label3(o: Oddball, smi: Smi) {
    check(o == Null);
    check(smi == 7);
    return True;
  }
}

builtin GenericBuiltinTest<T: type>(_param: T): JSAny {
  return Null;
}

GenericBuiltinTest<JSAny>(param: JSAny): JSAny {
  return param;
}

@export
macro TestBuiltinSpecialization(): void {
  check(GenericBuiltinTest<Smi>(0) == Null);
  check(GenericBuiltinTest<Smi>(1) == Null);
  check(GenericBuiltinTest<JSAny>(Undefined) == Undefined);
  check(GenericBuiltinTest<JSAny>(Undefined) == Undefined);
}

macro LabelTestHelper4(flag: constexpr bool): never
    labels Label4, Label5 {
  if constexpr (flag) {
    goto Label4;
  } else {
    goto Label5;
  }
}

macro CallLabelTestHelper4(flag: constexpr bool): bool {
  try {
    LabelTestHelper4(flag) otherwise Label4, Label5;
  } label Label4 {
    return true;
  } label Label5 {
    return false;
  }
}

@export
macro TestPartiallyUnusedLabel(): Boolean {
  const r1: bool = CallLabelTestHelper4(true);
  const r2: bool = CallLabelTestHelper4(false);

  if (r1 && !r2) {
    return True;
  } else {
    return False;
  }
}

macro GenericMacroTest<T: type>(_param: T): Object {
  return Undefined;
}

GenericMacroTest<Object>(param2: Object): Object {
  return param2;
}

macro GenericMacroTestWithLabels<T: type>(_param: T): Object
labels _X {
  return Undefined;
}

GenericMacroTestWithLabels<Object>(param2: Object): Object
    labels Y {
  return Cast<Smi>(param2) otherwise Y;
}

@export
macro TestMacroSpecialization(): void {
  try {
    const _smi0: Smi = 0;
    check(GenericMacroTest<Smi>(0) == Undefined);
    check(GenericMacroTest<Smi>(1) == Undefined);
    check(GenericMacroTest<Object>(Null) == Null);
    check(GenericMacroTest<Object>(False) == False);
    check(GenericMacroTest<Object>(True) == True);
    check((GenericMacroTestWithLabels<Smi>(0) otherwise Fail) == Undefined);
    check((GenericMacroTestWithLabels<Smi>(0) otherwise Fail) == Undefined);
    try {
      GenericMacroTestWithLabels<Object>(False) otherwise Expected;
    } label Expected {}
  } label Fail {
    unreachable;
  }
}

builtin TestHelperPlus1(x: Smi): Smi {
  return x + 1;
}
builtin TestHelperPlus2(x: Smi): Smi {
  return x + 2;
}

@export
macro TestFunctionPointers(implicit context: Context)(): Boolean {
  let fptr: builtin(Smi) => Smi = TestHelperPlus1;
  check(fptr(42) == 43);
  fptr = TestHelperPlus2;
  check(fptr(42) == 44);
  return True;
}

@export
macro TestVariableRedeclaration(implicit context: Context)(): Boolean {
  let _var1: int31 = FromConstexpr<bool>(42 == 0) ? FromConstexpr<int31>(0) : 1;
  let _var2: int31 = FromConstexpr<bool>(42 == 0) ? FromConstexpr<int31>(1) : 0;
  return True;
}

@export
macro TestTernaryOperator(x: Smi): Smi {
  const b: bool = x < 0 ? true : false;
  return b ? x - 10 : x + 100;
}

@export
macro TestFunctionPointerToGeneric(): void {
  const fptr1: builtin(Smi) => JSAny = GenericBuiltinTest<Smi>;
  const fptr2: builtin(JSAny) => JSAny = GenericBuiltinTest<JSAny>;

  check(fptr1(0) == Null);
  check(fptr1(1) == Null);
  check(fptr2(Undefined) == Undefined);
  check(fptr2(Undefined) == Undefined);
}

type ObjectToObject = builtin(Context, JSAny) => JSAny;
@export
macro TestTypeAlias(x: ObjectToObject): BuiltinPtr {
  return x;
}

@export
macro TestUnsafeCast(implicit context: Context)(n: Number): Boolean {
  if (TaggedIsSmi(n)) {
    const m: Smi = UnsafeCast<Smi>(n);

    check(TestHelperPlus1(m) == 11);
    return True;
  }
  return False;
}

@export
macro TestHexLiteral(): void {
  check(Convert<intptr>(0xffff) + 1 == 0x10000);
  check(Convert<intptr>(-0xffff) == -65535);
}

@export
macro TestLargeIntegerLiterals(implicit c: Context)(): void {
  let _x: int32 = 0x40000000;
  let _y: int32 = 0x7fffffff;
}

@export
macro TestMultilineAssert(): void {
  const someVeryLongVariableNameThatWillCauseLineBreaks: Smi = 5;
  check(
      someVeryLongVariableNameThatWillCauseLineBreaks > 0 &&
      someVeryLongVariableNameThatWillCauseLineBreaks < 10);
}

@export
macro TestNewlineInString(): void {
  Print('Hello, World!\n');
}

const kConstexprConst: constexpr int31 = 5;
const kIntptrConst: intptr = 4;
const kSmiConst: Smi = 3;

@export
macro TestModuleConstBindings(): void {
  check(kConstexprConst == Int32Constant(5));
  check(kIntptrConst == 4);
  check(kSmiConst == 3);
}

@export
macro TestLocalConstBindings(): void {
  const x: constexpr int31 = 3;
  const xSmi: Smi = x;
  {
    const x: Smi = x + FromConstexpr<Smi>(1);
    check(x == xSmi + 1);
    const xSmi: Smi = x;
    check(x == xSmi);
    check(x == 4);
  }
  check(xSmi == 3);
  check(x == xSmi);
}

struct TestStructA {
  indexes: FixedArray;
  i: Smi;
  k: Number;
}

struct TestStructB {
  x: TestStructA;
  y: Smi;
}

@export
macro TestStruct1(i: TestStructA): Smi {
  return i.i;
}

@export
macro TestStruct2(implicit context: Context)(): TestStructA {
  return TestStructA{
    indexes: UnsafeCast<FixedArray>(kEmptyFixedArray),
    i: 27,
    k: 31
  };
}

@export
macro TestStruct3(implicit context: Context)(): TestStructA {
  let a: TestStructA =
  TestStructA{indexes: UnsafeCast<FixedArray>(kEmptyFixedArray), i: 13, k: 5};
  let _b: TestStructA = a;
  const c: TestStructA = TestStruct2();
  a.i = TestStruct1(c);
  a.k = a.i;
  let d: TestStructB;
  d.x = a;
  d = TestStructB{x: a, y: 7};
  let _e: TestStructA = d.x;
  let f: Smi = TestStructA{
    indexes: UnsafeCast<FixedArray>(kEmptyFixedArray),
    i: 27,
    k: 31
  }.i;
  f = TestStruct2().i;
  return a;
}

struct TestStructC {
  x: TestStructA;
  y: TestStructA;
}

@export
macro TestStruct4(implicit context: Context)(): TestStructC {
  return TestStructC{x: TestStruct2(), y: TestStruct2()};
}

macro TestStructInLabel(implicit context: Context)(): never labels
Foo(TestStructA) {
  goto Foo(TestStruct2());
}
@export  // Silence unused warning.
macro CallTestStructInLabel(implicit context: Context)(): void {
  try {
    TestStructInLabel() otherwise Foo;
  } label Foo(_s: TestStructA) {}
}

// This macro tests different versions of the for-loop where some parts
// are (not) present.
@export
macro TestForLoop(): void {
  let sum: Smi = 0;
  for (let i: Smi = 0; i < 5; ++i) sum += i;
  check(sum == 10);

  sum = 0;
  let j: Smi = 0;
  for (; j < 5; ++j) sum += j;
  check(sum == 10);

  sum = 0;
  j = 0;
  for (; j < 5;) sum += j++;
  check(sum == 10);

  // Check that break works. No test expression.
  sum = 0;
  for (let i: Smi = 0;; ++i) {
    if (i == 5) break;
    sum += i;
  }
  check(sum == 10);

  sum = 0;
  j = 0;
  for (;;) {
    if (j == 5) break;
    sum += j;
    j++;
  }
  check(sum == 10);

  // The following tests are the same as above, but use continue to skip
  // index 3.
  sum = 0;
  for (let i: Smi = 0; i < 5; ++i) {
    if (i == 3) continue;
    sum += i;
  }
  check(sum == 7);

  sum = 0;
  j = 0;
  for (; j < 5; ++j) {
    if (j == 3) continue;
    sum += j;
  }
  check(sum == 7);

  sum = 0;
  j = 0;
  for (; j < 5;) {
    if (j == 3) {
      j++;
      continue;
    }
    sum += j;
    j++;
  }
  check(sum == 7);

  sum = 0;
  for (let i: Smi = 0;; ++i) {
    if (i == 3) continue;
    if (i == 5) break;
    sum += i;
  }
  check(sum == 7);

  sum = 0;
  j = 0;
  for (;;) {
    if (j == 3) {
      j++;
      continue;
    }

    if (j == 5) break;
    sum += j;
    j++;
  }
  check(sum == 7);

  j = 0;
  try {
    for (;;) {
      if (++j == 10) goto Exit;
    }
  } label Exit {
    check(j == 10);
  }

  // Test if we can handle uninitialized values on the stack.
  let _i: Smi;
  for (let j: Smi = 0; j < 10; ++j) {
  }
}

@export
macro TestSubtyping(x: Smi): void {
  const _foo: JSAny = x;
}

macro IncrementIfSmi<A: type>(x: A): A {
  typeswitch (x) {
    case (x: Smi): {
      return x + 1;
    }
    case (o: A): {
      return o;
    }
  }
}

type NumberOrFixedArray = Number|FixedArray;
macro TypeswitchExample(implicit context: Context)(x: NumberOrFixedArray):
    int32 {
  let result: int32 = 0;
  typeswitch (IncrementIfSmi(x)) {
    case (_x: FixedArray): {
      result = result + 1;
    }
    case (Number): {
      result = result + 2;
    }
  }

  result = result * 10;

  typeswitch (IncrementIfSmi(x)) {
    case (x: Smi): {
      result = result + Convert<int32>(x);
    }
    case (a: FixedArray): {
      result = result + Convert<int32>(a.length);
    }
    case (_x: HeapNumber): {
      result = result + 7;
    }
  }

  return result;
}

@export
macro TestTypeswitch(implicit context: Context)(): void {
  check(TypeswitchExample(FromConstexpr<Smi>(5)) == 26);
  const a: FixedArray = AllocateZeroedFixedArray(3);
  check(TypeswitchExample(a) == 13);
  check(TypeswitchExample(FromConstexpr<Number>(0.5)) == 27);
}

@export
macro TestTypeswitchAsanLsanFailure(implicit context: Context)(obj: Object):
    void {
  typeswitch (obj) {
    case (_o: Smi): {
    }
    case (_o: JSTypedArray): {
    }
    case (_o: JSReceiver): {
    }
    case (_o: HeapObject): {
    }
  }
}

macro ExampleGenericOverload<A: type>(o: Object): A {
  return o;
}
macro ExampleGenericOverload<A: type>(o: Smi): A {
  return o + 1;
}

@export
macro TestGenericOverload(implicit context: Context)(): void {
  const xSmi: Smi = 5;
  const xObject: Object = xSmi;
  check(ExampleGenericOverload<Smi>(xSmi) == 6);
  check(UnsafeCast<Smi>(ExampleGenericOverload<Object>(xObject)) == 5);
}

@export
macro TestEquality(implicit context: Context)(): void {
  const notEqual: bool =
      AllocateHeapNumberWithValue(0.5) != AllocateHeapNumberWithValue(0.5);
  check(!notEqual);
  const equal: bool =
      AllocateHeapNumberWithValue(0.5) == AllocateHeapNumberWithValue(0.5);
  check(equal);
}

@export
macro TestOrAnd(x: bool, y: bool, z: bool): bool {
  return x || y && z ? true : false;
}

@export
macro TestAndOr(x: bool, y: bool, z: bool): bool {
  return x && y || z ? true : false;
}

@export
macro TestLogicalOperators(): void {
  check(TestAndOr(true, true, true));
  check(TestAndOr(true, true, false));
  check(TestAndOr(true, false, true));
  check(!TestAndOr(true, false, false));
  check(TestAndOr(false, true, true));
  check(!TestAndOr(false, true, false));
  check(TestAndOr(false, false, true));
  check(!TestAndOr(false, false, false));
  check(TestOrAnd(true, true, true));
  check(TestOrAnd(true, true, false));
  check(TestOrAnd(true, false, true));
  check(TestOrAnd(true, false, false));
  check(TestOrAnd(false, true, true));
  check(!TestOrAnd(false, true, false));
  check(!TestOrAnd(false, false, true));
  check(!TestOrAnd(false, false, false));
}

@export
macro TestCall(i: Smi): Smi labels A {
  if (i < 5) return i;
  goto A;
}

@export
macro TestOtherwiseWithCode1(): void {
  let v: Smi = 0;
  let s: Smi = 1;
  try {
    TestCall(10) otherwise goto B(++s);
  } label B(v1: Smi) {
    v = v1;
  }
  dcheck(v == 2);
}

@export
macro TestOtherwiseWithCode2(): void {
  let s: Smi = 0;
  for (let i: Smi = 0; i < 10; ++i) {
    TestCall(i) otherwise break;
    ++s;
  }
  dcheck(s == 5);
}

@export
macro TestOtherwiseWithCode3(): void {
  let s: Smi = 0;
  for (let i: Smi = 0; i < 10; ++i) {
    s += TestCall(i) otherwise break;
  }
  dcheck(s == 10);
}

@export
macro TestForwardLabel(): void {
  try {
    goto A;
  } label A {
    goto B(5);
  } label B(b: Smi) {
    dcheck(b == 5);
  }
}

@export
macro TestQualifiedAccess(implicit context: Context)(): void {
  const s: Smi = 0;
  check(!Is<JSArray>(s));
}

@export
macro TestCatch1(implicit context: Context)(): Smi {
  let r: Smi = 0;
  try {
    ThrowTypeError(MessageTemplate::kInvalidArrayLength);
  } catch (_e, _message) {
    r = 1;
    return r;
  }
}

@export
macro TestCatch2Wrapper(implicit context: Context)(): never {
  ThrowTypeError(MessageTemplate::kInvalidArrayLength);
}

@export
macro TestCatch2(implicit context: Context)(): Smi {
  let r: Smi = 0;
  try {
    TestCatch2Wrapper();
  } catch (_e, _message) {
    r = 2;
    return r;
  }
}

@export
macro TestCatch3WrapperWithLabel(implicit context: Context)():
    never labels _Abort {
  ThrowTypeError(MessageTemplate::kInvalidArrayLength);
}

@export
macro TestCatch3(implicit context: Context)(): Smi {
  let r: Smi = 0;
  try {
    TestCatch3WrapperWithLabel() otherwise Abort;
  } catch (_e, _message) {
    r = 2;
    return r;
  } label Abort {
    return -1;
  }
}

// This test doesn't actually test the functionality of iterators,
// it's only purpose is to make sure tha the CSA macros in the
// IteratorBuiltinsAssembler match the signatures provided in
// iterator.tq.
@export
transitioning macro TestIterator(
    implicit context: Context)(o: JSReceiver, map: Map): void {
  try {
    const t1: JSAny = iterator::GetIteratorMethod(o);
    const t2: iterator::IteratorRecord = iterator::GetIterator(o);

    const _t3: JSAny = iterator::IteratorStep(t2) otherwise Fail;
    const _t4: JSAny = iterator::IteratorStep(t2, map) otherwise Fail;

    const _t5: JSAny = iterator::IteratorValue(o);
    const _t6: JSAny = iterator::IteratorValue(o, map);

    const _t7: JSArray = iterator::IterableToList(t1, t1);

    iterator::IteratorCloseOnException(t2);
  } label Fail {}
}

@export
macro TestFrame1(implicit context: Context)(): void {
  const f: Frame = LoadFramePointer();
  const frameType: FrameType =
      Cast<FrameType>(f.context_or_frame_type) otherwise unreachable;
  dcheck(frameType == STUB_FRAME);
  dcheck(f.caller == LoadParentFramePointer());
  typeswitch (f) {
    case (_f: StandardFrame): {
      unreachable;
    }
    case (_f: StubFrame): {
    }
  }
}

@export
macro TestNew(implicit context: Context)(): void {
  const f: JSArray = NewJSArray();
  check(f.IsEmpty());
  f.length = 0;
}

struct TestInner {
  macro SetX(newValue: int32): void {
    this.x = newValue;
  }
  macro GetX(): int32 {
    return this.x;
  }
  x: int32;
  y: int32;
}

struct TestOuter {
  a: int32;
  b: TestInner;
  c: int32;
}

@export
macro TestStructConstructor(implicit context: Context)(): void {
  // Test default constructor
  let a: TestOuter = TestOuter{a: 5, b: TestInner{x: 6, y: 7}, c: 8};
  check(a.a == 5);
  check(a.b.x == 6);
  check(a.b.y == 7);
  check(a.c == 8);
  a.b.x = 1;
  check(a.b.x == 1);
  a.b.SetX(2);
  check(a.b.x == 2);
  check(a.b.GetX() == 2);
}

class InternalClass extends HeapObject {
  macro Flip(): void labels NotASmi {
    const tmp = Cast<Smi>(this.b) otherwise NotASmi;
    this.b = this.a;
    this.a = tmp;
  }
  a: Smi;
  b: Number;
}

macro NewInternalClass(x: Smi): InternalClass {
  return new InternalClass{a: x, b: x + 1};
}

@export
macro TestInternalClass(implicit context: Context)(): void {
  const o = NewInternalClass(5);
  o.Flip() otherwise unreachable;
  check(o.a == 6);
  check(o.b == 5);
}

struct StructWithConst {
  macro TestMethod1(): int32 {
    return this.b;
  }
  macro TestMethod2(): Object {
    return this.a;
  }
  a: Object;
  const b: int32;
}

@export
macro TestConstInStructs(): void {
  const x = StructWithConst{a: Null, b: 1};
  let y = StructWithConst{a: Null, b: 1};
  y.a = Undefined;
  const _copy = x;

  check(x.TestMethod1() == 1);
  check(x.TestMethod2() == Null);
}

@export
macro TestParentFrameArguments(implicit context: Context)(): void {
  const parentFrame = LoadParentFramePointer();
  const castFrame = Cast<StandardFrame>(parentFrame) otherwise unreachable;
  const arguments = GetFrameArguments(castFrame, 1);
  ArgumentsIterator{arguments, current: 0};
}

struct TestIterator {
  macro Next(): Object labels NoMore {
    if (this.count-- == 0) goto NoMore;
    return TheHole;
  }
  count: Smi;
}

@export
macro TestNewFixedArrayFromSpread(implicit context: Context)(): Object {
  let i = TestIterator{count: 5};
  return new FixedArray{map: kFixedArrayMap, length: 5, objects: ...i};
}

class SmiPair extends HeapObject {
  macro GetA():&Smi {
    return &this.a;
  }
  a: Smi;
  b: Smi;
}

macro Swap<T: type>(a:&T, b:&T): void {
  const tmp = *a;
  *a = *b;
  *b = tmp;
}

@export
macro TestReferences(): void {
  const array = new SmiPair{a: 7, b: 2};
  const ref:&Smi = &array.a;
  *ref = 3 + *ref;
  -- *ref;
  Swap(&array.b, array.GetA());
  check(array.a == 2);
  check(array.b == 9);
}

@export
macro TestSlices(): void {
  const it = TestIterator{count: 3};
  const a = new FixedArray{map: kFixedArrayMap, length: 3, objects: ...it};
  check(a.length == 3);

  const oneTwoThree = Convert<Smi>(123);
  a.objects[0] = oneTwoThree;
  const firstRef:&Object = &a.objects[0];
  check(TaggedEqual(*firstRef, oneTwoThree));

  const slice: MutableSlice<Object> = &a.objects;
  const firstRefAgain:&Object = slice.TryAtIndex(0) otherwise unreachable;
  check(TaggedEqual(*firstRefAgain, oneTwoThree));

  const threeTwoOne = Convert<Smi>(321);
  *firstRefAgain = threeTwoOne;
  check(TaggedEqual(a.objects[0], threeTwoOne));

  // *slice;             // error, not allowed
  // a.objects;          // error, not allowed
  // a.objects = slice;  // error, not allowed

  // TODO(gsps): Currently errors, but should be allowed:
  // const _sameSlice: MutableSlice<Object> = &(*slice);
  // (*slice)[0] : Smi
}

@export
macro TestSliceEnumeration(implicit context: Context)(): Undefined {
  const fixedArray: FixedArray = AllocateZeroedFixedArray(3);
  for (let i: intptr = 0; i < 3; i++) {
    check(UnsafeCast<Smi>(fixedArray.objects[i]) == 0);
    fixedArray.objects[i] = Convert<Smi>(i) + 3;
  }

  let slice = &fixedArray.objects;
  for (let i: intptr = 0; i < slice.length; i++) {
    let ref = slice.TryAtIndex(i) otherwise unreachable;
    const value = UnsafeCast<Smi>(*ref);
    check(value == Convert<Smi>(i) + 3);
    *ref = value + 4;
  }

  let it = slice.Iterator();
  let count: Smi = 0;
  while (true) {
    const value = UnsafeCast<Smi>(it.Next() otherwise break);
    check(value == count + 7);
    count++;
  }
  check(count == 3);
  check(it.Empty());

  return Undefined;
}

@export
macro TestStaticAssert(): void {
  static_assert(1 + 2 == 3);

  static_assert(Convert<uintptr>(5) < Convert<uintptr>(6));
  static_assert(!(Convert<uintptr>(5) < Convert<uintptr>(5)));
  static_assert(!(Convert<uintptr>(6) < Convert<uintptr>(5)));
  static_assert(Convert<uintptr>(5) <= Convert<uintptr>(5));
  static_assert(Convert<uintptr>(5) <= Convert<uintptr>(6));
  static_assert(!(Convert<uintptr>(6) <= Convert<uintptr>(5)));

  static_assert(Convert<intptr>(-6) < Convert<intptr>(-5));
  static_assert(!(Convert<intptr>(-5) < Convert<intptr>(-5)));
  static_assert(!(Convert<intptr>(-5) < Convert<intptr>(-6)));
  static_assert(Convert<intptr>(-5) <= Convert<intptr>(-5));
  static_assert(Convert<intptr>(-6) <= Convert<intptr>(-5));
  static_assert(!(Convert<intptr>(-5) <= Convert<intptr>(-6)));
}

class SmiBox extends HeapObject {
  value: Smi;
  unrelated: Smi;
}

builtin NewSmiBox(implicit context: Context)(value: Smi): SmiBox {
  return new SmiBox{value, unrelated: 0};
}

@export
macro TestLoadEliminationFixed(implicit context: Context)(): void {
  const box = NewSmiBox(123);
  const v1 = box.value;
  box.unrelated = 999;
  const v2 = (box.unrelated == 0) ? box.value : box.value;
  static_assert(TaggedEqual(v1, v2));

  box.value = 11;
  const v3 = box.value;
  const eleven: Smi = 11;
  static_assert(TaggedEqual(v3, eleven));
}

@export
macro TestLoadEliminationVariable(implicit context: Context)(): void {
  const a = UnsafeCast<FixedArray>(kEmptyFixedArray);
  const box = NewSmiBox(1);
  const v1 = a.objects[box.value];
  const u1 = a.objects[box.value + 2];
  const v2 = a.objects[box.value];
  const u2 = a.objects[box.value + 2];
  static_assert(TaggedEqual(v1, v2));
  static_assert(TaggedEqual(u1, u2));
}

@export
macro TestRedundantArrayElementCheck(implicit context: Context)(): Smi {
  const a = kEmptyFixedArray;
  for (let i: Smi = 0; i < a.length; i++) {
    if (a.objects[i] == TheHole) {
      if (a.objects[i] == TheHole) {
        return -1;
      } else {
        static_assert(false);
      }
    }
  }
  return 1;
}

@export
macro TestRedundantSmiCheck(implicit context: Context)(): Smi {
  const a = kEmptyFixedArray;
  const x = a.objects[1];
  typeswitch (x) {
    case (Smi): {
      Cast<Smi>(x) otherwise VerifiedUnreachable();
      return -1;
    }
    case (Object): {
    }
  }
  return 1;
}

struct SBox<T: type> {
  value: T;
}

@export
macro TestGenericStruct1(): intptr {
  const i: intptr = 123;
  let box = SBox{value: i};
  let boxbox: SBox<SBox<intptr>> = SBox{value: box};
  check(box.value == 123);
  boxbox.value.value *= 2;
  check(boxbox.value.value == 246);
  return boxbox.value.value;
}

struct TestTuple<T1: type, T2: type> {
  const fst: T1;
  const snd: T2;
}

macro TupleSwap<T1: type, T2: type>(tuple: TestTuple<T1, T2>):
    TestTuple<T2, T1> {
  return TestTuple{fst: tuple.snd, snd: tuple.fst};
}

@export
macro TestGenericStruct2():
    TestTuple<TestTuple<intptr, Smi>, TestTuple<Smi, intptr>> {
  const intptrAndSmi = TestTuple<intptr, Smi>{fst: 1, snd: 2};
  const smiAndIntptr = TupleSwap(intptrAndSmi);
  check(intptrAndSmi.fst == smiAndIntptr.snd);
  check(intptrAndSmi.snd == smiAndIntptr.fst);
  const tupleTuple =
      TestTuple<TestTuple<intptr, Smi>>{fst: intptrAndSmi, snd: smiAndIntptr};
  return tupleTuple;
}

macro BranchAndWriteResult(x: Smi, box: SmiBox): bool {
  if (x > 5 || x < 0) {
    box.value = 1;
    return true;
  } else {
    box.value = 2;
    return false;
  }
}

@export
macro TestBranchOnBoolOptimization(implicit context: Context)(input: Smi):
    void {
  const box = NewSmiBox(1);
  // If the two branches get combined into one, we should be able to determine
  // the value of {box} statically.
  if (BranchAndWriteResult(input, box)) {
    static_assert(box.value == 1);
  } else {
    static_assert(box.value == 2);
  }
}

bitfield struct TestBitFieldStruct extends uint8 {
  a: bool: 1 bit;
  b: uint16: 3 bit;
  c: uint32: 3 bit;
  d: bool: 1 bit;
}

@export
macro TestBitFieldLoad(
    val: TestBitFieldStruct, expectedA: bool, expectedB: uint16,
    expectedC: uint32, expectedD: bool): void {
  check(val.a == expectedA);
  check(val.b == expectedB);
  check(val.c == expectedC);
  check(val.d == expectedD);
}

@export
macro TestBitFieldStore(val: TestBitFieldStruct): void {
  let val: TestBitFieldStruct = val;  // Get a mutable local copy.
  const a: bool = val.a;
  const b: uint16 = val.b;
  let c: uint32 = val.c;
  const d: bool = val.d;

  val.a = !a;
  TestBitFieldLoad(val, !a, b, c, d);

  c = Unsigned(7 - Signed(val.c));
  val.c = c;
  TestBitFieldLoad(val, !a, b, c, d);

  val.d = val.b == val.c;
  TestBitFieldLoad(val, !a, b, c, b == c);
}

@export
macro TestBitFieldInit(a: bool, b: uint16, c: uint32, d: bool): void {
  const val: TestBitFieldStruct = TestBitFieldStruct{a: a, b: b, c: c, d: d};
  TestBitFieldLoad(val, a, b, c, d);
}

// Some other bitfield structs, to verify getting uintptr values out of word32
// structs and vice versa.
bitfield struct TestBitFieldStruct2 extends uint32 {
  a: uintptr: 5 bit;
  b: uintptr: 6 bit;
}
bitfield struct TestBitFieldStruct3 extends uintptr {
  c: bool: 1 bit;
  d: uint32: 9 bit;
  e: uintptr: 17 bit;
}

@export
macro TestBitFieldUintptrOps(
    val2: TestBitFieldStruct2, val3: TestBitFieldStruct3): void {
  let val2: TestBitFieldStruct2 = val2;  // Get a mutable local copy.
  let val3: TestBitFieldStruct3 = val3;  // Get a mutable local copy.

  // Caller is expected to provide these exact values, so we can verify
  // reading values before starting to write anything.
  check(val2.a == 3);
  check(val2.b == 61);
  check(val3.c);
  check(val3.d == 500);
  check(val3.e == 0x1cc);

  val2.b = 16;
  check(val2.a == 3);
  check(val2.b == 16);

  val2.b++;
  check(val2.a == 3);
  check(val2.b == 17);

  val3.d = 99;
  val3.e = 1234;
  check(val3.c);
  check(val3.d == 99);
  check(val3.e == 1234);
}

bitfield struct TestBitFieldStruct4 extends uint31 {
  a: bool: 1 bit;
  b: int32: 3 bit;
  c: bool: 1 bit;
}

bitfield struct TestBitFieldStruct5 extends uint31 {
  b: int32: 19 bit;
  a: bool: 1 bit;
  c: bool: 1 bit;
}

@export
macro TestBitFieldMultipleFlags(a: bool, b: int32, c: bool): void {
  const f = TestBitFieldStruct4{a: a, b: b, c: c};
  let simpleExpression = f.a & f.b == 3 & !f.c;
  let expectedReduction = (Signed(f) & 0x1f) == Convert<int32>(1 | 3 << 1);
  static_assert(simpleExpression == expectedReduction);
  simpleExpression = !f.a & f.b == 4 & f.c;
  expectedReduction = (Signed(f) & 0x1f) == Convert<int32>(4 << 1 | 1 << 4);
  static_assert(simpleExpression == expectedReduction);
  simpleExpression = f.b == 0 & f.c;
  expectedReduction = (Signed(f) & 0x1e) == Convert<int32>(1 << 4);
  static_assert(simpleExpression == expectedReduction);
  simpleExpression = f.a & f.c;
  expectedReduction = (Signed(f) & 0x11) == Convert<int32>(1 | 1 << 4);
  static_assert(simpleExpression == expectedReduction);
  const f2 = TestBitFieldStruct5{b: b, a: a, c: c};
  simpleExpression = !f2.a & f2.b == 1234 & f2.c;
  expectedReduction = (Signed(f2) & 0x1fffff) == Convert<int32>(1234 | 1 << 20);
  static_assert(simpleExpression == expectedReduction);
  simpleExpression = !f2.a & !f2.c;
  expectedReduction = (Signed(f2) & 0x180000) == Convert<int32>(0);
  static_assert(simpleExpression == expectedReduction);
}

@export
class ExportedSubClass extends ExportedSubClassBase {
  c_field: int32;
  d_field: int32;
  e_field: Smi;
}

@export
class ExportedSubClassBase extends HeapObject {
  a: HeapObject;
  b: HeapObject;
}

@abstract
class AbstractInternalClass extends HeapObject {}

class AbstractInternalClassSubclass1 extends AbstractInternalClass {}

class AbstractInternalClassSubclass2 extends AbstractInternalClass {}

struct InternalClassStructElement {
  a: Smi;
  b: Smi;
}

class InternalClassWithStructElements extends HeapObject {
  dummy1: int32;
  dummy2: int32;
  const count: Smi;
  data: Smi;
  object: Object;
  entries[count]: Smi;
  more_entries[count]: InternalClassStructElement;
}


@export
macro TestFullyGeneratedClassFromCpp(): ExportedSubClass {
  return new
  ExportedSubClass{a: Null, b: Null, c_field: 7, d_field: 8, e_field: 9};
}

@export
class ExportedSubClass2 extends ExportedSubClassBase {
  x_field: int32;
  y_field: int32;
  z_field: Smi;
}

@export
macro TestGeneratedCastOperators(implicit context: Context)(): void {
  const a = new
  ExportedSubClass{a: Null, b: Null, c_field: 3, d_field: 4, e_field: 5};
  const b = new ExportedSubClassBase{a: Undefined, b: Null};
  const c = new
  ExportedSubClass2{a: Null, b: Null, x_field: 3, y_field: 4, z_field: 5};
  const aO: Object = a;
  const bO: Object = b;
  const cO: Object = c;
  dcheck(Is<ExportedSubClassBase>(aO));
  dcheck(Is<ExportedSubClass>(aO));
  dcheck(!Is<ExportedSubClass2>(aO));
  dcheck(Is<ExportedSubClassBase>(bO));
  dcheck(!Is<ExportedSubClass>(bO));
  dcheck(Is<ExportedSubClassBase>(cO));
  dcheck(!Is<ExportedSubClass>(cO));
  dcheck(Is<ExportedSubClass2>(cO));

  const jsf: JSFunction =
      *NativeContextSlot(ContextSlot::REGEXP_FUNCTION_INDEX);
  dcheck(!Is<JSSloppyArgumentsObject>(jsf));

  const parameterValues = NewFixedArray(0, ConstantIterator(TheHole));
  const elements = NewSloppyArgumentsElements(
      0, context, parameterValues, ConstantIterator(TheHole));
  const fastArgs = arguments::NewJSFastAliasedArgumentsObject(
      elements, Convert<Smi>(0), jsf);
  dcheck(Is<JSArgumentsObject>(fastArgs));
}

extern runtime InYoungGeneration(implicit context: Context)(HeapObject):
    Boolean;

@export
macro TestNewPretenured(implicit context: Context)(): void {
  const obj = new (Pretenured) ExportedSubClassBase{a: Undefined, b: Null};
  dcheck(Is<ExportedSubClassBase>(obj));
  dcheck(InYoungGeneration(obj) == False);
}

@export
macro TestWord8Phi(): void {
  for (let i: intptr = -5; i < 5; ++i) {
    let x: int8;
    if (i == -1) {
      x = -1;
    } else {
      x = Convert<int8>(i);
    }
    check(x == Convert<int8>(i));
  }
}

@export
macro TestOffHeapSlice(ptr: RawPtr<char8>, length: intptr): void {
  const string = UnsafeCast<SeqOneByteString>(Convert<String>('Hello World!'));

  check(*torque_internal::unsafe::NewOffHeapReference(ptr) == string.chars[0]);

  let offHeapSlice = torque_internal::unsafe::NewOffHeapConstSlice(ptr, length);
  let onHeapSlice = &string.chars;
  for (let i: intptr = 0; i < onHeapSlice.length; ++i) {
    check(*onHeapSlice.AtIndex(i) == *offHeapSlice.AtIndex(i));
  }
}

struct TwoValues {
  a: Smi;
  b: Map;
}

builtin ReturnTwoValues(
    implicit context: Context)(value: Smi, obj: HeapObject): TwoValues {
  return TwoValues{a: value + 1, b: obj.map};
}

@export
macro TestCallMultiReturnBuiltin(implicit context: Context)(): void {
  const result = ReturnTwoValues(444, FromConstexpr<String>('hi'));
  check(result.a == 445);
  check(result.b == FromConstexpr<String>('hi').map);
}

@export
macro TestRunLazyTwice(lazySmi: Lazy<Smi>): Smi {
  const firstResult = RunLazy(lazySmi);
  const secondResult = RunLazy(lazySmi);
  return firstResult + secondResult;
}

macro GetLazySmi(): Smi {
  return 3;
}

macro AddTwoSmiValues(a: Smi, b: Smi): Smi {
  return a + b;
}

macro AddSmiAndConstexprValues(a: Smi, b: constexpr int31): Smi {
  return a + b;
}

@export
macro TestCreateLazyNodeFromTorque(): void {
  const lazy = %MakeLazy<Smi>('GetLazySmi');
  const result = TestRunLazyTwice(lazy);
  check(result == 6);

  // The macro can also be referred to using namespace qualifications.
  const lazy2 = %MakeLazy<Smi>('test::GetLazySmi');
  const result2 = TestRunLazyTwice(lazy2);
  check(result2 == 6);

  // We can save params to the macro. The most common usage is likely a
  // single-arg macro that just returns the arg, but we can use any number of
  // params.
  const lazy3 = %MakeLazy<Smi>('AddTwoSmiValues', 5, 6);
  const result3 = TestRunLazyTwice(lazy3);
  check(result3 == 22);

  // It's okay if some of the params are constexpr and some aren't.
  const lazy4 = %MakeLazy<Smi>('AddSmiAndConstexprValues', 7, 8);
  const result4 = TestRunLazyTwice(lazy4);
  check(result4 == 30);
}
}

builtin ThrowAsBuiltin(implicit context: Context)(str: String): never {
  Throw(str);
}

builtin TestCallNever(implicit context: Context)(a: Smi): Smi {
  if (a == 1) {
    Throw('a == 1');
  }
  if (a == -1) {
    ThrowAsBuiltin('a == -1');
  }
  return a;
}

@incrementUseCounter('v8::Isolate::kArraySpeciesModified')
builtin TestIncrementArraySpeciesModified(implicit context: Context)(): Smi {
  return 0;
}

"""

```