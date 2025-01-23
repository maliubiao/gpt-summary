Response:
Let's break down the thought process for analyzing the provided C++ code.

1. **Identify the Core Purpose:** The filename `run-jsops-unittest.cc` immediately suggests this code is for *unit testing*. The `unittest` part is a strong indicator. The `jsops` part hints that it's testing JavaScript *operations*.

2. **Scan for Key Structures:** Look for common C++ testing patterns.
    * `#include`:  This confirms dependencies on other V8 components and a testing framework.
    * `namespace v8`, `namespace internal`, `namespace compiler`:  This shows the code's location within the V8 project's organization.
    * `using RunJSOpsTest = TestWithContext;`: This is a crucial line. It defines a test fixture named `RunJSOpsTest` based on `TestWithContext`. This implies that the tests will need a JavaScript context to operate in.
    * `TEST_F(RunJSOpsTest, ...)`: This is the standard Google Test macro for defining individual test cases within the `RunJSOpsTest` fixture. Each `TEST_F` block represents a separate test.

3. **Analyze Individual Test Cases:**  Examine the name of each `TEST_F` to understand what operation is being tested.
    * `BinopAdd`, `BinopSubtract`, etc.: These clearly indicate tests for binary operators in JavaScript.
    * `UnopNot`, `UnopCountPost`, `UnopCountPre`: These are tests for unary operators.
    * `PropertyNamedLoad`, `PropertyKeyedLoad`, `PropertyNamedStore`, `PropertyKeyedStore`, `PropertyNamedDelete`, `PropertyKeyedDelete`: These tests focus on property access and manipulation.
    * `GlobalLoad`, `GlobalStoreStrict`:  These relate to global variable access.
    * `ContextLoad`, `ContextStore`: These suggest testing how variables in different scopes (contexts) are accessed and modified.
    * `LookupLoad`, `LookupStore`: The name "Lookup" often relates to scope resolution, potentially involving `with` statements.
    * `BlockLoadStore`, `BlockLoadStoreNested`: These likely test block-scoped variables (`let`, `const`).
    * `ObjectLiteralComputed`, `ObjectLiteralNonString`, `ObjectLiteralPrototype`, `ObjectLiteralGetter`: These are tests related to creating JavaScript objects with different kinds of properties.
    * `ArrayLiteral`: Tests creating arrays.
    * `RegExpLiteral`: Tests regular expression literals.
    * `ClassLiteral`: Tests the creation and usage of JavaScript classes.

4. **Examine the Test Logic (Within a `TEST_F`):** Look at the common elements within each test:
    * `FunctionTester T(i_isolate(), "(function(a,b) { return a + b; })");`: This pattern is repeated. It creates a `FunctionTester` object. The second argument is a *string containing JavaScript code*. This is the code being tested. The `i_isolate()` suggests it's running within a V8 isolate.
    * `T.CheckCall(...)`: This is the core assertion. It calls the JavaScript function defined in the `FunctionTester` and checks if the returned value matches the expected value. The arguments to `CheckCall` are the expected result followed by the arguments to the JavaScript function.
    * `T.CheckTrue(...)`, `T.CheckFalse(...)`, `T.CheckThrows(...)`: These are other assertion methods for boolean results and expected exceptions.
    * `T.NewString(...)`, `T.NewNumber(...)`, `T.NewObject(...)`, `T.undefined()`, `T.true_value()`, `T.false_value()`, `T.nan()`: These are helper methods in `FunctionTester` to create V8 objects for testing.
    * `TryRunJS(...)`:  This allows running arbitrary JavaScript code before the main test function is called, likely for setting up global variables or objects.

5. **Infer Functionality:** Based on the test case names and the `CheckCall` assertions, determine what each test is verifying. For example, the `BinopAdd` tests verify the behavior of the `+` operator with different operand types (numbers, strings, objects).

6. **Connect to JavaScript:**  For each test case, translate the C++ test logic into equivalent JavaScript examples to illustrate the functionality being tested. This is essential for making the tests understandable to someone familiar with JavaScript but not necessarily V8 internals.

7. **Identify Potential Programming Errors:** Consider common mistakes developers make when working with the tested JavaScript operations. For example, the string concatenation behavior of `+` or the subtle differences between `==` and `===`.

8. **Consider Edge Cases and Type Coercion:**  Notice how the tests cover different data types and implicit type conversions. This is a key aspect of JavaScript and a likely focus of these tests. For instance, adding a number and a string, or comparing different types with `==`.

9. **Structure the Explanation:** Organize the findings into clear categories: overall functionality, relationship to Torque, JavaScript examples, logic reasoning (input/output), and common programming errors.

10. **Refine and Review:**  Read through the explanation to ensure clarity, accuracy, and completeness. Double-check the JavaScript examples and the input/output scenarios.

By following these steps, one can systematically analyze the C++ code and generate a comprehensive description of its functionality, its relationship to JavaScript, and the potential pitfalls it helps to uncover. The key is to work from the high-level structure down to the specifics of each test case, always keeping the connection to JavaScript behavior in mind.
This C++ code file, `run-jsops-unittest.cc`, is a **unit test suite** for the **V8 JavaScript engine's compiler**. Specifically, it tests the correctness of how the compiler handles various JavaScript *operations* (often shortened to "ops").

Here's a breakdown of its functionality:

**Core Functionality:**

* **Testing JavaScript Operator Implementations:** The primary goal is to verify that the V8 compiler correctly translates JavaScript operators (like `+`, `-`, `*`, `/`, `===`, `<`, `in`, `instanceof`, etc.) into efficient and correct machine code.
* **Using `FunctionTester`:**  The code uses a helper class `FunctionTester` to simplify the process of creating and executing JavaScript functions within the test environment.
* **Checking Expected Results:** For each tested operation, the code defines a JavaScript function that uses that operation. It then uses `T.CheckCall`, `T.CheckTrue`, `T.CheckFalse`, and `T.CheckThrows` methods of the `FunctionTester` to execute the function with various inputs and compare the actual output with the expected output.
* **Testing Different Data Types:** The tests cover various JavaScript data types as inputs, including numbers, strings, booleans, objects, `undefined`, and `NaN`, to ensure the operators work correctly with different types and handle type coercion as expected.
* **Testing Different Scenarios:** The tests cover different scenarios for each operator, including basic cases, edge cases, and cases involving type conversions.
* **Testing Load and Store Operations:** The code also includes tests for loading and storing values in different contexts, such as object properties (named and keyed), global variables, context variables, and block-scoped variables.
* **Testing Literals:**  There are tests for various JavaScript literals like object literals, array literals, regular expression literals, and class literals.

**Relationship to Torque:**

The filename ends with `.cc`, not `.tq`. Therefore, **this is a standard C++ source file, not a Torque source file.** Torque is a V8-specific language used for implementing built-in JavaScript functions and runtime code.

**Relationship to JavaScript and Examples:**

This file directly tests the behavior of JavaScript. Each `TEST_F` function corresponds to a specific JavaScript operation or feature. Here are JavaScript examples illustrating what each test group is verifying:

* **`BinopAdd`:**
   ```javascript
   function testAdd(a, b) {
     return a + b;
   }
   console.log(testAdd(1, 2)); // 3
   console.log(testAdd("A", "B")); // "AB"
   console.log(testAdd("A", 11)); // "A11"
   ```
* **`BinopSubtract`:**
   ```javascript
   function testSubtract(a, b) {
     return a - b;
   }
   console.log(testSubtract(4, 1)); // 3
   console.log(testSubtract("0", 9)); // -9 (string to number conversion)
   console.log(testSubtract("3", "2")); // 1 (string to number conversion)
   console.log(testSubtract("3", "B")); // NaN
   ```
* **`BinopMultiply`, `BinopDivide`, `BinopModulus`, `BinopShiftLeft`, `BinopShiftRight`, `BinopShiftRightLogical`, `BinopAnd`, `BinopOr`, `BinopXor`:** These test the respective arithmetic and bitwise operators in JavaScript, covering type conversions where applicable.
* **`BinopStrictEqual`:**
   ```javascript
   function testStrictEqual(a, b) {
     return a === b;
   }
   console.log(testStrictEqual(7, 7)); // true
   console.log(testStrictEqual(7, "7")); // false (different types)
   console.log(testStrictEqual({}, {})); // false (different object references)
   let obj = {};
   console.log(testStrictEqual(obj, obj)); // true (same object reference)
   ```
* **`BinopEqual`:**
   ```javascript
   function testEqual(a, b) {
     return a == b;
   }
   console.log(testEqual(7, 7)); // true
   console.log(testEqual(7, "7")); // true (type coercion)
   console.log(testEqual({}, {})); // false
   ```
* **`BinopNotEqual`, `BinopLessThan`, `BinopLessThanOrEqual`, `BinopGreaterThan`, `BinopGreaterThanOrEqual`:** These test the respective comparison operators, including type coercion for non-strict equality.
* **`BinopIn`:**
   ```javascript
   function testIn(a, b) {
     return a in b;
   }
   console.log(testIn("x", { x: 23 })); // true
   console.log(testIn(1, [1, 2, 3])); // true (index check)
   ```
* **`BinopInstanceOf`:**
   ```javascript
   function testInstanceOf(a, b) {
     return a instanceof b;
   }
   console.log(testInstanceOf(new Number(23), Number)); // true
   console.log(testInstanceOf(1, Number)); // false
   ```
* **`UnopNot`:**
   ```javascript
   function testNot(a) {
     return !a;
   }
   console.log(testNot(undefined)); // true
   console.log(testNot(123)); // false
   console.log(testNot("x")); // false
   ```
* **`UnopCountPost`, `UnopCountPre`:**
   ```javascript
   function testPostIncrement(a) {
     return a++;
   }
   let x = 0;
   console.log(testPostIncrement(x)); // 0
   console.log(x); // 1

   function testPreIncrement(a) {
     return ++a;
   }
   let y = 0;
   console.log(testPreIncrement(y)); // 1
   console.log(y); // 1
   ```
* **`PropertyNamedLoad`, `PropertyKeyedLoad`:**
   ```javascript
   function testNamedLoad(obj) {
     return obj.x;
   }
   console.log(testNamedLoad({ x: 23 })); // 23

   function testKeyedLoad(obj, key) {
     return obj[key];
   }
   console.log(testKeyedLoad({ x: 23 }, "x")); // 23
   console.log(testKeyedLoad([23, 42], 1)); // 42
   ```
* **`PropertyNamedStore`, `PropertyKeyedStore`:**
   ```javascript
   function testNamedStore(obj) {
     obj.x = 7;
     return obj.x;
   }
   let myObj1 = {};
   console.log(testNamedStore(myObj1)); // 7

   function testKeyedStore(obj, key) {
     obj[key] = 7;
     return obj.x;
   }
   let myObj2 = {};
   console.log(testKeyedStore(myObj2, "x")); // 7
   ```
* **`PropertyNamedDelete`, `PropertyKeyedDelete`:**
   ```javascript
   function testNamedDelete(obj) {
     return delete obj.x;
   }
   let obj1 = { x: 42 };
   console.log(testNamedDelete(obj1)); // true
   console.log(obj1.x); // undefined

   function testKeyedDelete(obj, key) {
     return delete obj[key];
   }
   let obj2 = { x: 42 };
   console.log(testKeyedDelete(obj2, "x")); // true
   console.log(obj2.x); // undefined
   ```
* **`GlobalLoad`, `GlobalStoreStrict`:**
   ```javascript
   // GlobalLoad
   console.log(g); // Throws ReferenceError if g is not defined
   var g = 23;
   console.log(g); // 23

   // GlobalStoreStrict
   "use strict";
   h = 5; // Throws ReferenceError in strict mode
   var h;
   ```
* **`ContextLoad`, `ContextStore`:** These test how variables are accessed and modified within function closures and scopes.
* **`LookupLoad`, `LookupStore`:** These relate to the `with` statement and how variable names are resolved within its scope. The `with` statement is generally discouraged due to performance and readability issues.
* **`BlockLoadStore`, `BlockLoadStoreNested`:** These test the behavior of `let` and `const` within block scopes.
* **`ObjectLiteralComputed`, `ObjectLiteralNonString`, `ObjectLiteralPrototype`, `ObjectLiteralGetter`:** These test different ways to define object literals.
* **`ArrayLiteral`:** Tests the creation of array literals.
* **`RegExpLiteral`:** Tests the creation and usage of regular expression literals.
* **`ClassLiteral`:** Tests the creation and basic functionality of JavaScript classes.

**Code Logic Reasoning (Example: `BinopAdd`)**

* **Assumption:** The `FunctionTester` correctly compiles and executes the provided JavaScript code within a V8 environment.
* **Input (for `T.CheckCall(3, 1, 2);`)**: The JavaScript function `(function(a,b) { return a + b; })` is called with `a = 1` and `b = 2`.
* **Expected Output:** The `+` operator performs addition on numbers, so the expected return value is `3`.
* **Input (for `T.CheckCall(T.NewString("AB"), T.NewString("A"), T.NewString("B"));`)**: The function is called with `a = "A"` and `b = "B"`.
* **Expected Output:** The `+` operator performs string concatenation when operands are strings, so the expected return value is `"AB"`.
* **Input (for `T.CheckCall(T.NewString("A11"), T.NewString("A"), T.NewNumber(11));`)**: The function is called with `a = "A"` and `b = 11`.
* **Expected Output:** JavaScript performs type coercion, converting the number to a string and then concatenating, resulting in `"A11"`.

**Common Programming Errors Illustrated by Tests:**

* **Confusing `==` and `===`:** The `BinopEqual` and `BinopStrictEqual` tests highlight the difference between loose equality (which involves type coercion) and strict equality (which does not). A common error is using `==` when strict equality is intended, leading to unexpected behavior due to implicit type conversions.
* **Incorrectly assuming string concatenation with `+`:** The `BinopAdd` tests show how `+` behaves differently with numbers and strings. Programmers might mistakenly assume it always performs addition.
* **Misunderstanding type coercion in arithmetic operations:** The `BinopSubtract`, `BinopMultiply`, etc., tests involving strings demonstrate how JavaScript attempts to convert strings to numbers for arithmetic operations, which can lead to `NaN` if the conversion fails.
* **Forgetting the distinction between object identity and value:** The `BinopStrictEqual` and `BinopEqual` tests with objects show that two distinct objects with the same properties are not considered equal unless they are the *same object instance*.
* **Errors related to the `with` statement:** The `LookupLoad` and `LookupStore` tests implicitly touch upon the complexities and potential for errors when using the `with` statement due to its impact on scope resolution.
* **Issues with global variable assignment in non-strict mode:** The `GlobalStoreStrict` test demonstrates that assigning to an undeclared variable in non-strict mode creates a global variable, which can be an unintended side effect and a source of bugs. Strict mode prevents this.

In summary, `v8/test/unittests/compiler/run-jsops-unittest.cc` is a crucial part of V8's testing infrastructure, ensuring the compiler correctly implements JavaScript operations across various data types and scenarios, thereby contributing to the overall correctness and reliability of the JavaScript engine.

### 提示词
```
这是目录为v8/test/unittests/compiler/run-jsops-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/compiler/run-jsops-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2022 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/objects/objects-inl.h"
#include "test/unittests/compiler/function-tester.h"
#include "test/unittests/test-utils.h"

namespace v8 {
namespace internal {
namespace compiler {

using RunJSOpsTest = TestWithContext;

TEST_F(RunJSOpsTest, BinopAdd) {
  FunctionTester T(i_isolate(), "(function(a,b) { return a + b; })");

  T.CheckCall(3, 1, 2);
  T.CheckCall(-11, -2, -9);
  T.CheckCall(-11, -1.5, -9.5);
  T.CheckCall(T.NewString("AB"), T.NewString("A"), T.NewString("B"));
  T.CheckCall(T.NewString("A11"), T.NewString("A"), T.NewNumber(11));
  T.CheckCall(T.NewString("12B"), T.NewNumber(12), T.NewString("B"));
  T.CheckCall(T.NewString("38"), T.NewString("3"), T.NewString("8"));
  T.CheckCall(T.NewString("31"), T.NewString("3"), T.NewObject("([1])"));
  T.CheckCall(T.NewString("3[object Object]"), T.NewString("3"),
              T.NewObject("({})"));
}

TEST_F(RunJSOpsTest, BinopSubtract) {
  FunctionTester T(i_isolate(), "(function(a,b) { return a - b; })");

  T.CheckCall(3, 4, 1);
  T.CheckCall(3.0, 4.5, 1.5);
  T.CheckCall(T.NewNumber(-9), T.NewString("0"), T.NewNumber(9));
  T.CheckCall(T.NewNumber(-9), T.NewNumber(0.0), T.NewString("9"));
  T.CheckCall(T.NewNumber(1), T.NewString("3"), T.NewString("2"));
  T.CheckCall(T.nan(), T.NewString("3"), T.NewString("B"));
  T.CheckCall(T.NewNumber(2), T.NewString("3"), T.NewObject("([1])"));
  T.CheckCall(T.nan(), T.NewString("3"), T.NewObject("({})"));
}

TEST_F(RunJSOpsTest, BinopMultiply) {
  FunctionTester T(i_isolate(), "(function(a,b) { return a * b; })");

  T.CheckCall(6, 3, 2);
  T.CheckCall(4.5, 2.0, 2.25);
  T.CheckCall(T.NewNumber(6), T.NewString("3"), T.NewNumber(2));
  T.CheckCall(T.NewNumber(4.5), T.NewNumber(2.0), T.NewString("2.25"));
  T.CheckCall(T.NewNumber(6), T.NewString("3"), T.NewString("2"));
  T.CheckCall(T.nan(), T.NewString("3"), T.NewString("B"));
  T.CheckCall(T.NewNumber(3), T.NewString("3"), T.NewObject("([1])"));
  T.CheckCall(T.nan(), T.NewString("3"), T.NewObject("({})"));
}

TEST_F(RunJSOpsTest, BinopDivide) {
  FunctionTester T(i_isolate(), "(function(a,b) { return a / b; })");

  T.CheckCall(2, 8, 4);
  T.CheckCall(2.1, 8.4, 4);
  T.CheckCall(V8_INFINITY, 8, 0);
  T.CheckCall(-V8_INFINITY, -8, 0);
  T.CheckCall(T.infinity(), T.NewNumber(8), T.NewString("0"));
  T.CheckCall(T.minus_infinity(), T.NewString("-8"), T.NewNumber(0.0));
  T.CheckCall(T.NewNumber(1.5), T.NewString("3"), T.NewString("2"));
  T.CheckCall(T.nan(), T.NewString("3"), T.NewString("B"));
  T.CheckCall(T.NewNumber(1.5), T.NewString("3"), T.NewObject("([2])"));
  T.CheckCall(T.nan(), T.NewString("3"), T.NewObject("({})"));
}

TEST_F(RunJSOpsTest, BinopModulus) {
  FunctionTester T(i_isolate(), "(function(a,b) { return a % b; })");

  T.CheckCall(3, 8, 5);
  T.CheckCall(T.NewNumber(3), T.NewString("8"), T.NewNumber(5));
  T.CheckCall(T.NewNumber(3), T.NewNumber(8), T.NewString("5"));
  T.CheckCall(T.NewNumber(1), T.NewString("3"), T.NewString("2"));
  T.CheckCall(T.nan(), T.NewString("3"), T.NewString("B"));
  T.CheckCall(T.NewNumber(1), T.NewString("3"), T.NewObject("([2])"));
  T.CheckCall(T.nan(), T.NewString("3"), T.NewObject("({})"));
}

TEST_F(RunJSOpsTest, BinopShiftLeft) {
  FunctionTester T(i_isolate(), "(function(a,b) { return a << b; })");

  T.CheckCall(4, 2, 1);
  T.CheckCall(T.NewNumber(4), T.NewString("2"), T.NewNumber(1));
  T.CheckCall(T.NewNumber(4), T.NewNumber(2), T.NewString("1"));
}

TEST_F(RunJSOpsTest, BinopShiftRight) {
  FunctionTester T(i_isolate(), "(function(a,b) { return a >> b; })");

  T.CheckCall(4, 8, 1);
  T.CheckCall(-4, -8, 1);
  T.CheckCall(T.NewNumber(4), T.NewString("8"), T.NewNumber(1));
  T.CheckCall(T.NewNumber(4), T.NewNumber(8), T.NewString("1"));
}

TEST_F(RunJSOpsTest, BinopShiftRightLogical) {
  FunctionTester T(i_isolate(), "(function(a,b) { return a >>> b; })");

  T.CheckCall(4, 8, 1);
  T.CheckCall(0x7FFFFFFC, -8, 1);
  T.CheckCall(T.NewNumber(4), T.NewString("8"), T.NewNumber(1));
  T.CheckCall(T.NewNumber(4), T.NewNumber(8), T.NewString("1"));
}

TEST_F(RunJSOpsTest, BinopAnd) {
  FunctionTester T(i_isolate(), "(function(a,b) { return a & b; })");

  T.CheckCall(7, 7, 15);
  T.CheckCall(7, 15, 7);
  T.CheckCall(T.NewNumber(7), T.NewString("15"), T.NewNumber(7));
  T.CheckCall(T.NewNumber(7), T.NewNumber(15), T.NewString("7"));
}

TEST_F(RunJSOpsTest, BinopOr) {
  FunctionTester T(i_isolate(), "(function(a,b) { return a | b; })");

  T.CheckCall(6, 4, 2);
  T.CheckCall(6, 2, 4);
  T.CheckCall(T.NewNumber(6), T.NewString("2"), T.NewNumber(4));
  T.CheckCall(T.NewNumber(6), T.NewNumber(2), T.NewString("4"));
}

TEST_F(RunJSOpsTest, BinopXor) {
  FunctionTester T(i_isolate(), "(function(a,b) { return a ^ b; })");

  T.CheckCall(7, 15, 8);
  T.CheckCall(7, 8, 15);
  T.CheckCall(T.NewNumber(7), T.NewString("8"), T.NewNumber(15));
  T.CheckCall(T.NewNumber(7), T.NewNumber(8), T.NewString("15"));
}

TEST_F(RunJSOpsTest, BinopStrictEqual) {
  FunctionTester T(i_isolate(), "(function(a,b) { return a === b; })");

  T.CheckTrue(7, 7);
  T.CheckFalse(7, 8);
  T.CheckTrue(7.1, 7.1);
  T.CheckFalse(7.1, 8.1);

  T.CheckTrue(T.NewString("7.1"), T.NewString("7.1"));
  T.CheckFalse(T.NewNumber(7.1), T.NewString("7.1"));
  T.CheckFalse(T.NewNumber(7), T.undefined());
  T.CheckFalse(T.undefined(), T.NewNumber(7));

  TryRunJS("var o = { desc : 'I am a singleton' }");
  T.CheckFalse(T.NewObject("([1])"), T.NewObject("([1])"));
  T.CheckFalse(T.NewObject("({})"), T.NewObject("({})"));
  T.CheckTrue(T.NewObject("(o)"), T.NewObject("(o)"));
}

TEST_F(RunJSOpsTest, BinopEqual) {
  FunctionTester T(i_isolate(), "(function(a,b) { return a == b; })");

  T.CheckTrue(7, 7);
  T.CheckFalse(7, 8);
  T.CheckTrue(7.1, 7.1);
  T.CheckFalse(7.1, 8.1);

  T.CheckTrue(T.NewString("7.1"), T.NewString("7.1"));
  T.CheckTrue(T.NewNumber(7.1), T.NewString("7.1"));

  TryRunJS("var o = { desc : 'I am a singleton' }");
  T.CheckFalse(T.NewObject("([1])"), T.NewObject("([1])"));
  T.CheckFalse(T.NewObject("({})"), T.NewObject("({})"));
  T.CheckTrue(T.NewObject("(o)"), T.NewObject("(o)"));
}

TEST_F(RunJSOpsTest, BinopNotEqual) {
  FunctionTester T(i_isolate(), "(function(a,b) { return a != b; })");

  T.CheckFalse(7, 7);
  T.CheckTrue(7, 8);
  T.CheckFalse(7.1, 7.1);
  T.CheckTrue(7.1, 8.1);

  T.CheckFalse(T.NewString("7.1"), T.NewString("7.1"));
  T.CheckFalse(T.NewNumber(7.1), T.NewString("7.1"));

  TryRunJS("var o = { desc : 'I am a singleton' }");
  T.CheckTrue(T.NewObject("([1])"), T.NewObject("([1])"));
  T.CheckTrue(T.NewObject("({})"), T.NewObject("({})"));
  T.CheckFalse(T.NewObject("(o)"), T.NewObject("(o)"));
}

TEST_F(RunJSOpsTest, BinopLessThan) {
  FunctionTester T(i_isolate(), "(function(a,b) { return a < b; })");

  T.CheckTrue(7, 8);
  T.CheckFalse(8, 7);
  T.CheckTrue(-8.1, -8);
  T.CheckFalse(-8, -8.1);
  T.CheckFalse(0.111, 0.111);

  T.CheckFalse(T.NewString("7.1"), T.NewString("7.1"));
  T.CheckFalse(T.NewNumber(7.1), T.NewString("6.1"));
  T.CheckFalse(T.NewNumber(7.1), T.NewString("7.1"));
  T.CheckTrue(T.NewNumber(7.1), T.NewString("8.1"));
}

TEST_F(RunJSOpsTest, BinopLessThanOrEqual) {
  FunctionTester T(i_isolate(), "(function(a,b) { return a <= b; })");

  T.CheckTrue(7, 8);
  T.CheckFalse(8, 7);
  T.CheckTrue(-8.1, -8);
  T.CheckFalse(-8, -8.1);
  T.CheckTrue(0.111, 0.111);

  T.CheckTrue(T.NewString("7.1"), T.NewString("7.1"));
  T.CheckFalse(T.NewNumber(7.1), T.NewString("6.1"));
  T.CheckTrue(T.NewNumber(7.1), T.NewString("7.1"));
  T.CheckTrue(T.NewNumber(7.1), T.NewString("8.1"));
}

TEST_F(RunJSOpsTest, BinopGreaterThan) {
  FunctionTester T(i_isolate(), "(function(a,b) { return a > b; })");

  T.CheckFalse(7, 8);
  T.CheckTrue(8, 7);
  T.CheckFalse(-8.1, -8);
  T.CheckTrue(-8, -8.1);
  T.CheckFalse(0.111, 0.111);

  T.CheckFalse(T.NewString("7.1"), T.NewString("7.1"));
  T.CheckTrue(T.NewNumber(7.1), T.NewString("6.1"));
  T.CheckFalse(T.NewNumber(7.1), T.NewString("7.1"));
  T.CheckFalse(T.NewNumber(7.1), T.NewString("8.1"));
}

TEST_F(RunJSOpsTest, BinopGreaterThanOrEqual) {
  FunctionTester T(i_isolate(), "(function(a,b) { return a >= b; })");

  T.CheckFalse(7, 8);
  T.CheckTrue(8, 7);
  T.CheckFalse(-8.1, -8);
  T.CheckTrue(-8, -8.1);
  T.CheckTrue(0.111, 0.111);

  T.CheckTrue(T.NewString("7.1"), T.NewString("7.1"));
  T.CheckTrue(T.NewNumber(7.1), T.NewString("6.1"));
  T.CheckTrue(T.NewNumber(7.1), T.NewString("7.1"));
  T.CheckFalse(T.NewNumber(7.1), T.NewString("8.1"));
}

TEST_F(RunJSOpsTest, BinopIn) {
  FunctionTester T(i_isolate(), "(function(a,b) { return a in b; })");

  T.CheckTrue(T.NewString("x"), T.NewObject("({x:23})"));
  T.CheckFalse(T.NewString("y"), T.NewObject("({x:42})"));
  T.CheckFalse(T.NewNumber(123), T.NewObject("({x:65})"));
  T.CheckTrue(T.NewNumber(1), T.NewObject("([1,2,3])"));
}

TEST_F(RunJSOpsTest, BinopInstanceOf) {
  FunctionTester T(i_isolate(), "(function(a,b) { return a instanceof b; })");

  T.CheckTrue(T.NewObject("(new Number(23))"), T.NewObject("Number"));
  T.CheckFalse(T.NewObject("(new Number(23))"), T.NewObject("String"));
  T.CheckFalse(T.NewObject("(new String('a'))"), T.NewObject("Number"));
  T.CheckTrue(T.NewObject("(new String('b'))"), T.NewObject("String"));
  T.CheckFalse(T.NewNumber(1), T.NewObject("Number"));
  T.CheckFalse(T.NewString("abc"), T.NewObject("String"));

  TryRunJS("var bound = (function() {}).bind(undefined)");
  T.CheckTrue(T.NewObject("(new bound())"), T.NewObject("bound"));
  T.CheckTrue(T.NewObject("(new bound())"), T.NewObject("Object"));
  T.CheckFalse(T.NewObject("(new bound())"), T.NewObject("Number"));
}

TEST_F(RunJSOpsTest, UnopNot) {
  FunctionTester T(i_isolate(), "(function(a) { return !a; })");

  T.CheckCall(T.true_value(), T.false_value(), T.undefined());
  T.CheckCall(T.false_value(), T.true_value(), T.undefined());
  T.CheckCall(T.true_value(), T.NewNumber(0.0), T.undefined());
  T.CheckCall(T.false_value(), T.NewNumber(123), T.undefined());
  T.CheckCall(T.false_value(), T.NewString("x"), T.undefined());
  T.CheckCall(T.true_value(), T.undefined(), T.undefined());
  T.CheckCall(T.true_value(), T.nan(), T.undefined());
}

TEST_F(RunJSOpsTest, UnopCountPost) {
  FunctionTester T(i_isolate(), "(function(a) { return a++; })");

  T.CheckCall(T.NewNumber(0.0), T.NewNumber(0.0), T.undefined());
  T.CheckCall(T.NewNumber(2.3), T.NewNumber(2.3), T.undefined());
  T.CheckCall(T.NewNumber(123), T.NewNumber(123), T.undefined());
  T.CheckCall(T.NewNumber(7), T.NewString("7"), T.undefined());
  T.CheckCall(T.nan(), T.NewString("x"), T.undefined());
  T.CheckCall(T.nan(), T.undefined(), T.undefined());
  T.CheckCall(T.NewNumber(1.0), T.true_value(), T.undefined());
  T.CheckCall(T.NewNumber(0.0), T.false_value(), T.undefined());
  T.CheckCall(T.nan(), T.nan(), T.undefined());
}

TEST_F(RunJSOpsTest, UnopCountPre) {
  FunctionTester T(i_isolate(), "(function(a) { return ++a; })");

  T.CheckCall(T.NewNumber(1.0), T.NewNumber(0.0), T.undefined());
  T.CheckCall(T.NewNumber(3.3), T.NewNumber(2.3), T.undefined());
  T.CheckCall(T.NewNumber(124), T.NewNumber(123), T.undefined());
  T.CheckCall(T.NewNumber(8), T.NewString("7"), T.undefined());
  T.CheckCall(T.nan(), T.NewString("x"), T.undefined());
  T.CheckCall(T.nan(), T.undefined(), T.undefined());
  T.CheckCall(T.NewNumber(2.0), T.true_value(), T.undefined());
  T.CheckCall(T.NewNumber(1.0), T.false_value(), T.undefined());
  T.CheckCall(T.nan(), T.nan(), T.undefined());
}

TEST_F(RunJSOpsTest, PropertyNamedLoad) {
  FunctionTester T(i_isolate(), "(function(a,b) { return a.x; })");

  T.CheckCall(T.NewNumber(23), T.NewObject("({x:23})"), T.undefined());
  T.CheckCall(T.undefined(), T.NewObject("({y:23})"), T.undefined());
}

TEST_F(RunJSOpsTest, PropertyKeyedLoad) {
  FunctionTester T(i_isolate(), "(function(a,b) { return a[b]; })");

  T.CheckCall(T.NewNumber(23), T.NewObject("({x:23})"), T.NewString("x"));
  T.CheckCall(T.NewNumber(42), T.NewObject("([23,42,65])"), T.NewNumber(1));
  T.CheckCall(T.undefined(), T.NewObject("({x:23})"), T.NewString("y"));
  T.CheckCall(T.undefined(), T.NewObject("([23,42,65])"), T.NewNumber(4));
}

TEST_F(RunJSOpsTest, PropertyNamedStore) {
  FunctionTester T(i_isolate(), "(function(a) { a.x = 7; return a.x; })");

  T.CheckCall(T.NewNumber(7), T.NewObject("({})"), T.undefined());
  T.CheckCall(T.NewNumber(7), T.NewObject("({x:23})"), T.undefined());
}

TEST_F(RunJSOpsTest, PropertyKeyedStore) {
  FunctionTester T(i_isolate(), "(function(a,b) { a[b] = 7; return a.x; })");

  T.CheckCall(T.NewNumber(7), T.NewObject("({})"), T.NewString("x"));
  T.CheckCall(T.NewNumber(7), T.NewObject("({x:23})"), T.NewString("x"));
  T.CheckCall(T.NewNumber(9), T.NewObject("({x:9})"), T.NewString("y"));
}

TEST_F(RunJSOpsTest, PropertyNamedDelete) {
  FunctionTester T(i_isolate(), "(function(a) { return delete a.x; })");

  TryRunJS("var o = Object.create({}, { x: { value:23 } });");
  T.CheckTrue(T.NewObject("({x:42})"), T.undefined());
  T.CheckTrue(T.NewObject("({})"), T.undefined());
  T.CheckFalse(T.NewObject("(o)"), T.undefined());
}

TEST_F(RunJSOpsTest, PropertyKeyedDelete) {
  FunctionTester T(i_isolate(), "(function(a, b) { return delete a[b]; })");

  TryRunJS("function getX() { return 'x'; }");
  TryRunJS("var o = Object.create({}, { x: { value:23 } });");
  T.CheckTrue(T.NewObject("({x:42})"), T.NewString("x"));
  T.CheckFalse(T.NewObject("(o)"), T.NewString("x"));
  T.CheckFalse(T.NewObject("(o)"), T.NewObject("({toString:getX})"));
}

TEST_F(RunJSOpsTest, GlobalLoad) {
  FunctionTester T(i_isolate(), "(function() { return g; })");

  T.CheckThrows(T.undefined(), T.undefined());
  TryRunJS("var g = 23;");
  T.CheckCall(T.NewNumber(23));
}

TEST_F(RunJSOpsTest, GlobalStoreStrict) {
  FunctionTester T(i_isolate(),
                   "(function(a,b) { 'use strict'; g = a + b; return g; })");

  T.CheckThrows(T.NewNumber(22), T.NewNumber(11));
  TryRunJS("var g = 'a global variable';");
  T.CheckCall(T.NewNumber(33), T.NewNumber(22), T.NewNumber(11));
}

TEST_F(RunJSOpsTest, ContextLoad) {
  FunctionTester T(i_isolate(),
                   "(function(a,b) { (function(){a}); return a + b; })");

  T.CheckCall(T.NewNumber(65), T.NewNumber(23), T.NewNumber(42));
  T.CheckCall(T.NewString("ab"), T.NewString("a"), T.NewString("b"));
}

TEST_F(RunJSOpsTest, ContextStore) {
  FunctionTester T(i_isolate(),
                   "(function(a,b) { (function(){x}); var x = a; return x; })");

  T.CheckCall(T.NewNumber(23), T.NewNumber(23), T.undefined());
  T.CheckCall(T.NewString("a"), T.NewString("a"), T.undefined());
}

TEST_F(RunJSOpsTest, LookupLoad) {
  FunctionTester T(i_isolate(),
                   "(function(a,b) { with(a) { return x + b; } })");

  T.CheckCall(T.NewNumber(24), T.NewObject("({x:23})"), T.NewNumber(1));
  T.CheckCall(T.NewNumber(32), T.NewObject("({x:23, b:9})"), T.NewNumber(2));
  T.CheckCall(T.NewNumber(45), T.NewObject("({__proto__:{x:42}})"),
              T.NewNumber(3));
  T.CheckCall(T.NewNumber(69), T.NewObject("({get x() { return 65; }})"),
              T.NewNumber(4));
}

TEST_F(RunJSOpsTest, LookupStore) {
  FunctionTester T(i_isolate(),
                   "(function(a,b) { var x; with(a) { x = b; } return x; })");

  T.CheckCall(T.undefined(), T.NewObject("({x:23})"), T.NewNumber(1));
  T.CheckCall(T.NewNumber(2), T.NewObject("({y:23})"), T.NewNumber(2));
  T.CheckCall(T.NewNumber(23), T.NewObject("({b:23})"), T.NewNumber(3));
  T.CheckCall(T.undefined(), T.NewObject("({__proto__:{x:42}})"),
              T.NewNumber(4));
}

TEST_F(RunJSOpsTest, BlockLoadStore) {
  FunctionTester T(i_isolate(),
                   "(function(a) { 'use strict'; { let x = a+a; return x; }})");

  T.CheckCall(T.NewNumber(46), T.NewNumber(23));
  T.CheckCall(T.NewString("aa"), T.NewString("a"));
}

TEST_F(RunJSOpsTest, BlockLoadStoreNested) {
  const char* src =
      "(function(a,b) {"
      "'use strict';"
      "{ let x = a, y = a;"
      "  { let y = b;"
      "    return x + y;"
      "  }"
      "}})";
  FunctionTester T(i_isolate(), src);

  T.CheckCall(T.NewNumber(65), T.NewNumber(23), T.NewNumber(42));
  T.CheckCall(T.NewString("ab"), T.NewString("a"), T.NewString("b"));
}

TEST_F(RunJSOpsTest, ObjectLiteralComputed) {
  FunctionTester T(i_isolate(),
                   "(function(a,b) { o = { x:a+b }; return o.x; })");

  T.CheckCall(T.NewNumber(65), T.NewNumber(23), T.NewNumber(42));
  T.CheckCall(T.NewString("ab"), T.NewString("a"), T.NewString("b"));
}

TEST_F(RunJSOpsTest, ObjectLiteralNonString) {
  FunctionTester T(i_isolate(),
                   "(function(a,b) { o = { 7:a+b }; return o[7]; })");

  T.CheckCall(T.NewNumber(65), T.NewNumber(23), T.NewNumber(42));
  T.CheckCall(T.NewString("ab"), T.NewString("a"), T.NewString("b"));
}

TEST_F(RunJSOpsTest, ObjectLiteralPrototype) {
  FunctionTester T(i_isolate(),
                   "(function(a) { o = { __proto__:a }; return o.x; })");

  T.CheckCall(T.NewNumber(23), T.NewObject("({x:23})"), T.undefined());
  T.CheckCall(T.undefined(), T.NewObject("({y:42})"), T.undefined());
}

TEST_F(RunJSOpsTest, ObjectLiteralGetter) {
  FunctionTester T(i_isolate(),
                   "(function(a) { o = { get x() {return a} }; return o.x; })");

  T.CheckCall(T.NewNumber(23), T.NewNumber(23), T.undefined());
  T.CheckCall(T.NewString("x"), T.NewString("x"), T.undefined());
}

TEST_F(RunJSOpsTest, ArrayLiteral) {
  FunctionTester T(i_isolate(),
                   "(function(a,b) { o = [1, a + b, 3]; return o[1]; })");

  T.CheckCall(T.NewNumber(65), T.NewNumber(23), T.NewNumber(42));
  T.CheckCall(T.NewString("ab"), T.NewString("a"), T.NewString("b"));
}

TEST_F(RunJSOpsTest, RegExpLiteral) {
  FunctionTester T(i_isolate(), "(function(a) { o = /b/; return o.test(a); })");

  T.CheckTrue(T.NewString("abc"));
  T.CheckFalse(T.NewString("xyz"));
}

TEST_F(RunJSOpsTest, ClassLiteral) {
  const char* src =
      "(function(a,b) {"
      "  class C {"
      "    x() { return a; }"
      "    static y() { return b; }"
      "    get z() { return 0; }"
      "    constructor() {}"
      "  }"
      "  return new C().x() + C.y();"
      "})";
  FunctionTester T(i_isolate(), src);

  T.CheckCall(T.NewNumber(65), T.NewNumber(23), T.NewNumber(42));
  T.CheckCall(T.NewString("ab"), T.NewString("a"), T.NewString("b"));
}

}  // namespace compiler
}  // namespace internal
}  // namespace v8
```