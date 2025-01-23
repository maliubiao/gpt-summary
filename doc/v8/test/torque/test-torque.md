Response: Let's break down the thought process for analyzing this Torque code.

1. **Understand the Goal:** The fundamental request is to understand the *functionality* of this Torque code and its relationship to JavaScript. This means identifying what the code *does*, not just listing its components.

2. **Initial Scan for Keywords and Structure:**  A quick scan reveals key Torque keywords like `macro`, `builtin`, `namespace`, `struct`, `class`, `export`, `check`, `try`, `label`, `goto`, `typeswitch`, `for`, `if`, `static_assert`, etc. This gives a high-level understanding that it's about defining functions/macros, working with data structures, and performing checks and control flow. The `test` namespace suggests this is part of a testing framework.

3. **Focus on `@export` Macros:** The `@export` annotation is crucial. It indicates the entry points or the parts of the Torque code intended to be visible and callable from the outside (likely the V8 runtime or other Torque code). These are the most important parts to analyze for functionality. I'd list these out:

   * `TestConstexpr1`, `TestConstexprIf`, `TestConstexprReturn`:  Likely related to compile-time evaluation.
   * `TestGotoLabel`, `TestGotoLabelWithOneParameter`, `TestGotoLabelWithTwoParameters`: Testing `goto` and labels.
   * `TestBuiltinSpecialization`:  Related to how built-in functions are specialized based on types.
   * `TestPartiallyUnusedLabel`:  Testing label usage scenarios.
   * `TestMacroSpecialization`:  Similar to builtins, but for Torque macros.
   * `TestFunctionPointers`:  Demonstrates function pointer usage.
   * `TestVariableRedeclaration`: Checks variable redeclaration rules.
   * `TestTernaryOperator`: Tests the ternary operator.
   * `TestFunctionPointerToGeneric`:  Function pointers to generic functions.
   * `TestTypeAlias`:  Testing type aliases.
   * `TestUnsafeCast`:  Demonstrates unsafe type casting.
   * ... and so on.

4. **Analyze Individual `@export` Macros:**  For each exported macro, I'd try to understand its core purpose:

   * **`TestConstexpr...`:** These are clearly about constant expressions. They use `FromConstexpr` and `check` to verify conditions are met at compile time. This has implications for JavaScript performance as these calculations don't happen during runtime.
   * **`TestGotoLabel...`:**  These are straightforward tests for `goto` and labels. While `goto` isn't directly in JavaScript, understanding control flow is important.
   * **`TestBuiltinSpecialization` and `TestMacroSpecialization`:** These highlight the concept of *generics* and *specialization*. Torque allows defining functions/macros that work with different types. The examples show how they behave with specific types like `Smi` and `JSAny`. This is analogous to generics in TypeScript.
   * **`TestFunctionPointers`:** Directly tests function pointers, a concept present in lower-level languages but less explicit in JavaScript (though callbacks and function references serve similar purposes).
   * **`TestTypeswitch`:**  This is very important. It demonstrates how Torque handles different types at runtime, similar to `instanceof` checks or type guards in TypeScript.

5. **Look for Connections to JavaScript Concepts:** After understanding the individual Torque tests, I would actively look for corresponding JavaScript features or concepts. This is where the "If it relates to JavaScript..." part of the prompt comes in.

   * **`Constexpr`:**  Relates to compile-time optimization, which indirectly benefits JavaScript performance. Also, `const` in JavaScript shares the idea of immutability.
   * **`Goto` and `Labels`:**  While `goto` isn't in standard JavaScript, the concept of control flow is fundamental. `break` and `continue` with labels in JavaScript are related.
   * **Generics/Specialization:**  Similar to generics in TypeScript. JavaScript's dynamic nature means this happens at runtime, while Torque does it more statically.
   * **`Typeswitch`:**  Directly relates to type checking in JavaScript using `typeof` or `instanceof`. TypeScript's type guards are even closer.
   * **`Structs` and `Classes`:**  These map to JavaScript objects and classes. Torque's structs are more like C-style structs, while its classes are closer to JavaScript classes.
   * **`Builtins`:** These are fundamental to how JavaScript's core functionalities are implemented. They are the low-level building blocks.

6. **Craft JavaScript Examples:**  For the concepts that have JavaScript parallels, create concise examples to illustrate the connection. The examples should be simple and directly relate to the Torque functionality. For instance, the `TestTypeswitch` example directly leads to demonstrating `typeof` and conditional logic in JavaScript.

7. **Summarize the Functionality:**  Based on the analysis of the individual tests, summarize the overall purpose of the Torque code. Emphasize that it's a testing suite for Torque's features, covering areas like compile-time evaluation, control flow, type handling, data structures, and interaction with built-in functions.

8. **Refine and Organize:**  Organize the findings logically. Start with a general summary, then delve into specific functionalities with JavaScript examples where applicable. Use clear and concise language. Ensure the JavaScript examples are correct and easy to understand. Double-check the connection between the Torque code and the JavaScript examples. For example, initially, I might just say "structs are like objects," but refining it to mention C-style structs vs. JavaScript objects adds more clarity.

9. **Consider Limitations:**  Acknowledge that Torque is a lower-level language for V8 internals, so the relationship with JavaScript is often about *how* JavaScript features are implemented, not necessarily direct equivalents in syntax.

By following these steps, I can systematically analyze the Torque code, understand its functionalities, and effectively explain its relationship to JavaScript with illustrative examples.
这个 Torque 源代码文件 `v8/test/torque/test-torque.tq` 是 V8 引擎中 Torque 语言的**一个测试文件**。它的主要功能是**测试 Torque 语言的各种特性和语法结构是否按预期工作**。

Torque 是一种 V8 使用的**领域特定语言 (DSL)**，用于编写 V8 的内置函数 (builtins)。这些内置函数是 JavaScript 引擎执行 JavaScript 代码时调用的底层操作。

该测试文件涵盖了 Torque 的多种特性，例如：

* **宏 (Macros):** 定义和调用宏，包括带 constexpr 参数、带标签、泛型宏以及宏的特化。
* **常量表达式 (Constexpr):** 测试在编译时求值的表达式。
* **标签 (Labels) 和 `goto` 语句:** 测试控制流跳转。
* **内置函数 (Builtins):** 定义和调用内置函数，包括泛型内置函数和函数指针。
* **类型系统 (Type System):** 测试类型别名、类型转换 (`UnsafeCast`) 和类型判断 (`typeswitch`)。
* **数据结构 (Data Structures):** 测试结构体 (`struct`) 和类 (`class`) 的定义、实例化和成员访问。
* **循环 (Loops):** 测试 `for` 循环的各种形式，包括 `break` 和 `continue`。
* **条件语句 (Conditional Statements):** 测试 `if` 语句和三元运算符。
* **逻辑运算符 (Logical Operators):** 测试 `&&` 和 `||` 运算符的优先级。
* **异常处理 (Exception Handling):** 测试 `try...catch` 语句。
* **迭代器 (Iterators):** 测试与迭代器相关的 CSA (Code Stub Assembler) 宏。
* **帧 (Frames):** 测试帧相关的操作。
* **内存分配 (Memory Allocation):** 测试 `new` 关键字创建对象。
* **函数指针 (Function Pointers):** 测试将内置函数赋值给函数指针并调用。
* **引用 (References):** 测试引用的使用和解引用。
* **切片 (Slices):** 测试数组切片的操作。
* **静态断言 (Static Assertions):** 测试编译时的断言。
* **懒加载 (Lazy Evaluation):** 测试懒加载节点的创建和运行。
* **位域 (Bitfields):** 测试位域结构体的定义和操作。
* **继承 (Inheritance):** 测试 Torque 类的继承。
* **多返回值 (Multi-Return Values):** 测试返回多个值的内置函数调用。

**与 JavaScript 功能的关系 (通过 JavaScript 举例说明):**

虽然 Torque 代码本身不是直接的 JavaScript 代码，但它定义了 JavaScript 引擎在底层执行某些操作的方式。  以下是一些 Torque 特性与 JavaScript 功能的对应关系：

1. **常量表达式 (Constexpr):**

   Torque 中的 `constexpr` 类似于 JavaScript 中使用 `const` 定义的**原始类型常量**。JavaScript 引擎可以对这些常量进行优化，例如在编译时进行计算。

   ```javascript
   const SIZE = 10;
   const arr = new Array(SIZE); // JavaScript 引擎可能在编译时知道数组的大小
   ```

2. **内置函数 (Builtins):**

   Torque 定义的内置函数实现了 JavaScript 的核心功能，例如数组操作、对象创建、类型转换等。

   ```javascript
   const arr = [1, 2, 3];
   arr.push(4); // arr.push() 的底层实现可能就是用 Torque 编写的
   ```

3. **类型系统 (Type System) 和 `typeswitch`:**

   Torque 的类型系统比 JavaScript 更严格。`typeswitch` 类似于 JavaScript 中的 `typeof` 或 `instanceof` 检查，用于根据变量的类型执行不同的代码。

   ```javascript
   function processValue(value) {
     if (typeof value === 'number') {
       console.log('It's a number:', value);
     } else if (typeof value === 'string') {
       console.log('It's a string:', value);
     }
   }
   ```

4. **数据结构 (Structs 和 Classes):**

   Torque 的 `struct` 和 `class` 类似于 JavaScript 的对象 (objects)。Torque 的类支持继承。

   ```javascript
   class MyClass {
     constructor(a, b) {
       this.a = a;
       this.b = b;
     }
     method() {
       console.log(this.a + this.b);
     }
   }

   const obj = new MyClass(1, 2);
   obj.method();
   ```

5. **异常处理 (Exception Handling):**

   Torque 的 `try...catch` 对应于 JavaScript 的 `try...catch` 语句，用于捕获和处理错误。

   ```javascript
   try {
     // 可能抛出错误的代码
     throw new Error('Something went wrong!');
   } catch (error) {
     console.error('Caught an error:', error.message);
   }
   ```

6. **迭代器 (Iterators):**

   Torque 中对迭代器的测试与 JavaScript 中迭代器和 `for...of` 循环的概念相关。

   ```javascript
   const arr = [1, 2, 3];
   for (const item of arr) {
     console.log(item);
   }
   ```

7. **内存分配 (Memory Allocation):**

   Torque 中的 `new` 关键字对应于 JavaScript 中的 `new` 运算符，用于创建对象。

   ```javascript
   const obj = new Object();
   const arr = new Array();
   ```

总而言之，`test-torque.tq` 文件是一个用于确保 V8 引擎的 Torque 实现正确无误的测试套件。它涵盖了 Torque 语言的各种特性，这些特性在底层支撑着 JavaScript 的执行。理解 Torque 可以帮助我们更深入地了解 V8 引擎的工作原理以及 JavaScript 的性能优化。

### 提示词
```
这是目录为v8/test/torque/test-torque.tq的一个v8 torque源代码， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
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
```