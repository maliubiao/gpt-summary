Response: The user wants a summary of the provided Torque source code and examples of how its functionality relates to Javascript.

Here's a breakdown of the thought process to achieve the desired output:

1. **Understand Torque's Role:**  Torque is V8's internal language for writing built-in functions. It's a low-level language that interacts directly with V8's internal data structures and mechanisms. Therefore, the code is testing various aspects of Torque itself, and how it can interact with the V8 runtime.

2. **High-Level Overview of the Code:**  Scanning the code, I see a lot of `@export macro` definitions. This immediately suggests that the file is a *test* file. The macros are likely exercising different features of the Torque language. I also see `check()` calls, which confirm this suspicion. The namespace `test` further reinforces this.

3. **Categorize the Tests:**  To provide a structured summary, I need to group the tests by the Torque features they are examining. I'll go through the code and look for patterns and keywords that indicate the feature being tested.

    * **`constexpr`:** Several tests involve `FromConstexpr`, indicating tests for compile-time constant expressions and their evaluation.
    * **`labels` and `goto`:** Tests involving labels and `goto` are about control flow within Torque.
    * **`builtin`:**  The presence of `builtin` functions signifies tests related to calling and specializing built-in functions. The `<T: type>` syntax suggests testing generics.
    * **`try...label`:** This construct tests exception handling and label-based control flow.
    * **`typeswitch`:** Clearly tests the type switching mechanism in Torque.
    * **`struct`:**  Tests involving struct definitions and their usage.
    * **`class`:**  Tests related to class definitions and inheritance.
    * **`for` loop:** Tests different variations of for loops in Torque.
    * **Function Pointers:** Tests assigning and calling function pointers.
    * **Type Aliases:** Tests defining and using type aliases.
    * **Casting (UnsafeCast, Cast):** Tests different casting mechanisms.
    * **Literals (Hex, Large Integers):** Tests parsing of different literal formats.
    * **Assertions:** Tests for compile-time and runtime assertions.
    * **String Printing:** A basic test for string output.
    * **Constants (const):** Tests defining and using constants.
    * **References and Slices:** Tests for memory references and array slices.
    * **`static_assert`:** Tests for compile-time assertions.
    * **Load Elimination:** Tests compiler optimizations related to loading values.
    * **Bitfields:** Tests for bitfield structures.
    * **Generics (Macros and Structs):** Further tests on generic macros and structs.
    * **Multi-Return Builtins:** Tests builtins that return multiple values.
    * **Lazy Evaluation:** Tests the `Lazy` type for deferred computation.
    * **`@incrementUseCounter`:** Tests a specific V8 annotation for incrementing counters.

4. **Explain the Relationship to Javascript:**  This is the crucial part. I need to connect the low-level Torque features to observable Javascript behavior.

    * **`constexpr`:** Relates to compile-time optimizations in V8. Javascript doesn't have explicit compile-time constants, but V8 can perform similar optimizations.
    * **`labels` and `goto`:**  No direct equivalent in Javascript. Explain how Javascript uses other control flow mechanisms (loops, conditional statements, exceptions).
    * **`builtin`:**  These are the *implementations* of Javascript's built-in functions (e.g., `Array.isArray`, `parseInt`).
    * **`try...catch`:** Directly corresponds to Javascript's `try...catch` for exception handling.
    * **`typeswitch`:**  While Javascript is dynamically typed, this relates to how V8 internally handles different object types. The example would demonstrate how Javascript behaves differently based on the type of a variable.
    * **`struct` and `class`:**  Relates to how V8 represents Javascript objects internally. Though Javascript doesn't have explicit structs, Torque's structs are used to manage object layout. Javascript classes are the closest equivalent.
    * **`for` loop:**  Directly maps to Javascript's `for` loops.
    * **Function Pointers:** Relate to how V8 calls built-in functions and how Javascript functions can be passed as arguments.
    * **Type Aliases:**  No direct Javascript equivalent, but it's about type abstraction, which exists in a looser sense in Javascript through conventions.
    * **Casting:** Relates to how V8 handles type conversions internally, which Javascript does implicitly or explicitly.
    * **Literals:**  Directly maps to how Javascript parses numeric literals.
    * **Assertions:**  Javascript has `console.assert` for runtime assertions. Torque's `check` is similar for testing.
    * **Constants:** Javascript has `const`.
    * **References and Slices:** Relates to how V8 manages memory for arrays and objects, though Javascript doesn't have explicit memory management.
    * **`static_assert`:** No direct equivalent in standard Javascript, but build tools or transpilers might have similar concepts.
    * **Load Elimination:** This is a performance optimization that's transparent to Javascript code.
    * **Bitfields:** No direct equivalent in standard Javascript. This is about efficient memory usage at the V8 level.
    * **Generics:**  Relates to how V8 handles operations on different types, and in some ways, to Typescript's generics.
    * **Multi-Return Builtins:**  Javascript functions can return objects or arrays to achieve a similar effect.
    * **Lazy Evaluation:**  Relates to the concept of delaying computation in Javascript, often used in asynchronous programming or for performance optimization.
    * **`@incrementUseCounter`:**  This is an internal V8 mechanism, not directly visible in Javascript.

5. **Provide Concrete Javascript Examples:** For each relevant Torque feature, provide a short, illustrative Javascript code snippet that demonstrates a related concept or behavior. This makes the explanation much clearer.

6. **Structure the Output:** Organize the information logically with clear headings and bullet points for readability. Start with a concise summary, then detail the individual features and their Javascript relationships.

By following these steps, I can generate a comprehensive and informative summary that addresses the user's request. The key is to understand the purpose of Torque and connect its low-level features to the observable behavior of Javascript.
这个 Torque 源代码文件 `v8/test/torque/test-torque.tq` 的主要功能是**测试 Torque 语言的各种特性和语法结构**。

Torque 是 V8 引擎内部使用的一种 DSL (领域特定语言)，用于编写高效的内置函数（builtins）。这个测试文件通过定义各种 Torque 宏（macros）和内建函数（builtins），并使用 `check()` 断言来验证这些功能是否按预期工作。

以下是该文件测试的一些关键 Torque 特性，并附带与 Javascript 功能相关的说明和示例：

**1. 常量表达式 (`constexpr`)：**

   - Torque 允许在编译时计算常量表达式。
   - 文件中 `TestConstexpr1`, `TestConstexprIf`, `TestConstexprReturn` 等宏测试了 `constexpr` 关键字以及在 `if constexpr` 中的使用。

   **与 Javascript 的关系：** 虽然 Javascript 没有显式的编译时常量表达式，但 V8 引擎在编译和优化 Javascript 代码时，也会进行常量折叠等类似的优化。

   ```javascript
   // Javascript 示例：V8 可能在编译时计算简单的常量表达式
   const a = 2 + 3; // V8 可能会直接将 a 的值设为 5
   console.log(a);
   ```

**2. 标签 (`labels`) 和 `goto`：**

   - Torque 提供了 `labels` 关键字定义标签，并使用 `goto` 语句跳转到这些标签。
   - `LabelTestHelper1`, `LabelTestHelper2`, `LabelTestHelper3`, `TestGotoLabel` 等宏测试了标签和 `goto` 的基本用法，包括带参数的跳转。

   **与 Javascript 的关系：** Javascript 没有 `goto` 语句。Javascript 使用控制流语句（如 `if`, `else`, `switch`, `for`, `while`）和异常处理 (`try...catch`) 来实现类似的控制流。

   ```javascript
   // Javascript 示例：使用循环和条件语句模拟控制流
   function example() {
     let i = 0;
     loopStart: // Javascript 中的标签仅用于 break 和 continue
     if (i < 5) {
       console.log(i);
       i++;
       // 无法直接跳转到 loopStart
     }
   }
   example();
   ```

**3. 内建函数 (`builtin`) 和泛型 (`<T: type>`)：**

   - Torque 可以定义内建函数，这些函数直接在 V8 引擎中执行。
   - `GenericBuiltinTest` 和 `TestBuiltinSpecialization` 测试了泛型内建函数的定义和特化。

   **与 Javascript 的关系：** Torque 中的 `builtin` 对应于 Javascript 引擎内部实现的内置函数，例如 `Array.isArray()`, `parseInt()`, `Object.prototype.toString()` 等。 泛型允许编写可以处理多种类型的内建函数。

   ```javascript
   // Javascript 示例：内置函数
   console.log(Array.isArray([])); // 调用内置函数

   // Javascript 中的泛型（通过 Typescript 或 JSDoc 注释模拟）
   /**
    * @template T
    * @param {T[]} arr
    * @returns {T|undefined}
    */
   function getFirstElement(arr) {
     return arr[0];
   }

   console.log(getFirstElement([1, 2, 3]));
   console.log(getFirstElement(['a', 'b', 'c']));
   ```

**4. 异常处理 (`try...label`) 和 `otherwise`：**

   - Torque 使用 `try...label` 结构进行异常处理，`otherwise` 子句定义了在 `try` 块中没有异常发生时执行的标签。
   - `TestGotoLabel`, `TestGotoLabelWithOneParameter`, `TestGotoLabelWithTwoParameters` 等宏展示了 `try...label` 的用法。

   **与 Javascript 的关系：** Torque 的 `try...label` 类似于 Javascript 的 `try...catch` 语句，用于捕获和处理异常。

   ```javascript
   // Javascript 示例：异常处理
   try {
     throw new Error("Something went wrong!");
   } catch (error) {
     console.error("Caught an error:", error.message);
   }
   ```

**5. 宏 (`macro`) 和泛型宏：**

   - Torque 允许定义可复用的代码片段，称为宏。
   - `ElementsKindTestHelper1`, `ElementsKindTestHelper2`, `GenericMacroTest`, `GenericMacroTestWithLabels` 和 `TestMacroSpecialization` 等测试了宏的定义、调用和泛型宏的使用。

   **与 Javascript 的关系：** 虽然 Javascript 没有像 Torque 那样的宏系统，但可以通过函数来实现代码的复用。Typescript 中的泛型类型可以提供类似泛型宏的类型安全。

   ```javascript
   // Javascript 示例：函数实现代码复用
   function add(a, b) {
     return a + b;
   }
   console.log(add(5, 3));

   // Typescript 示例：泛型函数
   function genericAdd<T>(a: T, b: T): any { // 'any' is used for simplicity
     return (a as any) + (b as any);
   }
   console.log(genericAdd<number>(5, 3));
   console.log(genericAdd<string>("hello", " world"));
   ```

**6. 函数指针：**

   - Torque 支持函数指针，可以将内建函数赋值给变量并调用。
   - `TestFunctionPointers` 和 `TestFunctionPointerToGeneric` 测试了函数指针的用法，包括指向泛型内建函数的指针。

   **与 Javascript 的关系：** Javascript 中的函数本身就是“一等公民”，可以作为变量赋值和传递，类似于函数指针。

   ```javascript
   // Javascript 示例：函数作为变量
   function sayHello() {
     console.log("Hello!");
   }
   const greetingFunction = sayHello;
   greetingFunction();
   ```

**7. 类型别名 (`type`)：**

   - Torque 允许使用 `type` 关键字定义类型别名。
   - `TestTypeAlias` 测试了类型别名的定义和使用。

   **与 Javascript 的关系：**  Javascript 本身没有类型别名的概念，但 Typescript 提供了 `type` 关键字来实现类型别名，提高代码的可读性和可维护性。

   ```typescript
   // Typescript 示例：类型别名
   type StringOrNumber = string | number;
   function processInput(input: StringOrNumber) {
     console.log(input);
   }
   processInput("hello");
   processInput(123);
   ```

**8. 结构体 (`struct`) 和类 (`class`)：**

   - Torque 支持定义结构体和类，用于组织数据和方法。
   - `TestStruct1` 到 `TestStruct4`, `TestStructConstructor`, `TestInternalClass`, `TestConstInStructs`, `TestFullyGeneratedClassFromCpp` 等测试了结构体和类的定义、实例化、成员访问和方法调用。

   **与 Javascript 的关系：** Torque 的 `struct` 可以看作是 C 风格的结构体，用于表示内存中的数据布局。 Javascript 中的对象 (objects) 可以用来模拟结构体。 Torque 的 `class` 更接近于 Javascript 的类 (classes)。

   ```javascript
   // Javascript 示例：对象模拟结构体
   const point = {
     x: 10,
     y: 20
   };
   console.log(point.x);

   // Javascript 示例：类
   class Rectangle {
     constructor(width, height) {
       this.width = width;
       this.height = height;
     }
     getArea() {
       return this.width * this.height;
     }
   }
   const rect = new Rectangle(5, 10);
   console.log(rect.getArea());
   ```

**9. 循环 (`for`)：**

   - Torque 提供了 `for` 循环结构。
   - `TestForLoop` 测试了 `for` 循环的各种变体，包括 `break` 和 `continue` 语句的使用。

   **与 Javascript 的关系：** Torque 的 `for` 循环与 Javascript 的 `for` 循环语法类似，功能也相同。

   ```javascript
   // Javascript 示例：for 循环
   for (let i = 0; i < 5; i++) {
     console.log(i);
   }
   ```

**10. 类型转换 (`UnsafeCast`, `Cast`) 和类型判断 (`Is`)：**

    - Torque 提供了 `UnsafeCast` 进行不安全的类型转换，`Cast` 进行安全的类型转换（可能失败并跳转到 `otherwise` 标签），以及 `Is` 进行类型判断。
    - `TestUnsafeCast`, `TestQualifiedAccess`, `TestGeneratedCastOperators` 等测试了这些操作符。

    **与 Javascript 的关系：** Javascript 是动态类型语言，类型转换通常是隐式的，但也有显式的类型转换方法 (如 `Number()`, `String()`). `instanceof` 运算符可以进行类型判断，类似于 Torque 的 `Is`。

    ```javascript
    // Javascript 示例：类型转换和类型判断
    const numStr = "10";
    const num = Number(numStr); // 显式类型转换
    console.log(typeof num); // "number"

    const arr = [];
    console.log(arr instanceof Array); // 类型判断
    ```

**11. 位域 (`bitfield struct`)：**

    - Torque 允许定义位域结构体，用于高效地存储和访问数据的特定位。
    - `TestBitFieldLoad`, `TestBitFieldStore`, `TestBitFieldInit`, `TestBitFieldUintptrOps`, `TestBitFieldMultipleFlags` 等测试了位域的定义和操作。

    **与 Javascript 的关系：** Javascript 没有直接的位域语法。虽然可以使用位运算符进行位操作，但没有结构化的方式来定义位域。这通常是 V8 引擎内部使用的优化技术。

    ```javascript
    // Javascript 示例：位运算符
    const flags = 0b01101;
    const hasFlag1 = flags & 0b00001; // 检查第一个标志位
    console.log(hasFlag1);
    ```

**12. 引用 (`&`) 和切片 (`MutableSlice`)：**

    - Torque 支持引用和切片操作，允许直接访问和修改内存中的数据。
    - `TestReferences`, `TestSlices`, `TestSliceEnumeration`, `TestOffHeapSlice` 等测试了这些特性。

    **与 Javascript 的关系：** Javascript 引擎负责内存管理，Javascript 代码通常不直接操作内存地址。引用和切片是 V8 内部为了性能优化而使用的机制。

**13. 静态断言 (`static_assert`)：**

    - Torque 提供了 `static_assert` 用于在编译时进行断言检查。
    - `TestStaticAssert` 测试了 `static_assert` 的用法。

    **与 Javascript 的关系：** Javascript 没有内置的编译时断言。 断言通常在运行时使用 `console.assert()` 或第三方库。

    ```javascript
    // Javascript 示例：运行时断言
    console.assert(1 + 1 === 2, "数学计算错误");
    ```

**14. 其他特性：**

    - 文件还测试了三元运算符 (`TestTernaryOperator`)、逻辑运算符 (`TestLogicalOperators`)、变量重声明 (`TestVariableRedeclaration`)、字面量（十六进制，大整数）(`TestHexLiteral`, `TestLargeIntegerLiterals`)、多行断言 (`TestMultilineAssert`)、字符串中的换行符 (`TestNewlineInString`)、模块和局部常量绑定 (`TestModuleConstBindings`, `TestLocalConstBindings`)、 `typeswitch` 语句 (`TestTypeswitch`)、泛型重载 (`TestGenericOverload`)、判等 (`TestEquality`)、 `Throw` 和 `Catch` 异常 (`TestCatch1`, `TestCatch2`, `TestCatch3`)、迭代器 (`TestIterator`)、帧操作 (`TestFrame1`)、对象创建 (`TestNew`)、内部类 (`TestInternalClass`)、父帧参数 (`TestParentFrameArguments`)、从展开创建 `FixedArray` (`TestNewFixedArrayFromSpread`)、加载消除优化 (`TestLoadEliminationFixed`, `TestLoadEliminationVariable`)、冗余检查消除 (`TestRedundantArrayElementCheck`, `TestRedundantSmiCheck`)、泛型结构体 (`TestGenericStruct1`, `TestGenericStruct2`)、布尔值分支优化 (`TestBranchOnBoolOptimization`)、导出类 (`ExportedSubClass`, `ExportedSubClassBase`, `ExportedSubClass2`)、预分配对象 (`TestNewPretenured`)、`Word8` 类型的 Phi 节点 (`TestWord8Phi`)、多返回值内建函数 (`TestCallMultiReturnBuiltin`)、惰性求值 (`TestRunLazyTwice`, `TestCreateLazyNodeFromTorque`) 以及调用 `never` 类型的函数 (`TestCallNever`)。

总的来说，这个 Torque 测试文件非常全面地覆盖了 Torque 语言的各种特性，确保 V8 引擎的内置函数能够高效且正确地执行。虽然 Javascript 本身并没有所有这些低级特性，但了解 Torque 的功能有助于理解 V8 引擎内部的工作原理以及如何优化 Javascript 代码的执行。

Prompt: 
```
这是目录为v8/test/torque/test-torque.tq的一个v8 torque源代码， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

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