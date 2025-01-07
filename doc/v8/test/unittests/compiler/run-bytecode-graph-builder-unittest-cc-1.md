Response:
The user wants a summary of the functionality of the provided C++ code snippet. This is the second part of a four-part series. I need to analyze the C++ test cases and infer the functionalities being tested.

The code uses a testing framework (`TEST_F`) and seems to be testing the `BytecodeGraphBuilder` in V8. Each `TEST_F` function tests a specific aspect of bytecode generation.

Here's a breakdown of what each test seems to be doing:

*   **`BytecodeGraphBuilderCountOperation`**: Tests prefix and postfix increment/decrement operators on numbers and object properties.
*   **`BytecodeGraphBuilderDelete`**: Tests the `delete` operator on object properties in both strict and non-strict mode.
*   **`BytecodeGraphBuilderDeleteGlobal`**: Tests the `delete` operator on global variables and object properties in global scope, including scenarios with functions.
*   **`BytecodeGraphBuilderDeleteLookupSlot`**: Tests the `delete` operator on variables in scopes that require lookups (likely due to `eval`).
*   **`BytecodeGraphBuilderLookupSlot`**: Tests accessing variables in scopes requiring lookups.
*   **`BytecodeGraphBuilderLookupContextSlot`**: Tests accessing variables in parent scopes when using `eval`.
*   **`BytecodeGraphBuilderLookupGlobalSlot`**: Tests accessing global variables when using `eval`.
*   **`BytecodeGraphBuilderLookupSlotWide`**: Similar to `BytecodeGraphBuilderLookupSlot`, but likely testing scenarios with many local variables to ensure wide slot indices are handled correctly.
*   **`BytecodeGraphBuilderCallLookupSlot`**: Tests calling functions that involve looking up variables in the scope, particularly with `eval`.
*   **`BytecodeGraphBuilderEval`**: Tests the `eval()` function in various scenarios, including strict mode and variable scope.
*   **`BytecodeGraphBuilderEvalParams`**: Tests how `eval()` interacts with function parameters.
*   **`BytecodeGraphBuilderEvalGlobal`**: Tests how `eval()` creates global variables.
*   **`BytecodeGraphBuilderCompare`**: Tests various comparison operators (`==`, `!=`, `===`, `!==`, `<`, `<=`, `>`, `>=`).
*   **`BytecodeGraphBuilderTestIn`**: Tests the `in` operator for checking property existence.
*   **`BytecodeGraphBuilderTestInstanceOf`**: Tests the `instanceof` operator.
*   **`BytecodeGraphBuilderTryCatch`**: Tests `try...catch` blocks for exception handling.
*   **`BytecodeGraphBuilderTryFinally1`**: Tests `try...finally` blocks where exceptions are not expected.
*   **`BytecodeGraphBuilderTryFinally2`**: Tests `try...finally` blocks where exceptions are expected.
*   **`BytecodeGraphBuilderThrow`**: Tests the `throw` statement.
*   **`BytecodeGraphBuilderContext`**: Tests variable scope and closures with `let` and `var`.
*   **`BytecodeGraphBuilderLoadContext`**: Tests loading variables from parent function contexts.

Now I need to summarize these functionalities concisely.
这是 V8 引擎源代码的一部分，专门用于测试 **字节码图构建器 (Bytecode Graph Builder)** 的功能。这个构建器负责将 JavaScript 代码转换为 V8 内部的字节码表示形式。

根据提供的代码片段，我们可以归纳出以下功能测试点：

1. **自增/自减运算符测试 (`BytecodeGraphBuilderCountOperation`)**:
    *   测试前缀和后缀的自增 (`++`) 和自减 (`--`) 运算符在不同数据类型和对象属性上的行为。
    *   **JavaScript 示例:**
        ```javascript
        let a = 10;
        console.log(++a); // 输出 11
        console.log(a++); // 输出 11，然后 a 变为 12
        ```
    *   **假设输入与输出:**
        *   输入代码片段: `"return ++p1;"`, 输入参数 `p1`: `10`，预期输出: `11`
        *   输入代码片段: `"return p1++;"`, 输入参数 `p1`: `10`，预期输出: `10` (返回自增前的值)

2. **`delete` 运算符测试 (`BytecodeGraphBuilderDelete`, `BytecodeGraphBuilderDeleteGlobal`, `BytecodeGraphBuilderDeleteLookupSlot`)**:
    *   测试 `delete` 运算符删除对象属性的行为，包括在严格模式和非严格模式下的差异。
    *   测试 `delete` 运算符在全局作用域中的行为，以及对全局变量的影响。
    *   测试在需要作用域查找的情况下（例如，通过 `eval` 创建的变量）使用 `delete` 的行为。
    *   **JavaScript 示例:**
        ```javascript
        let obj = { a: 1, b: 2 };
        delete obj.a;
        console.log(obj.a); // 输出 undefined

        var globalVar = 5;
        delete globalVar; // 在非严格模式下返回 false，在严格模式下会报错
        console.log(globalVar); // 如果未删除，则输出 5
        ```
    *   **假设输入与输出:**
        *   输入代码片段: `"return delete p1.val;"`, 输入参数 `p1`: `{val : 10}`，预期输出: `true`
        *   输入代码片段: `"delete p1.val; return p1.val;"`, 输入参数 `p1`: `{val : 10}`，预期输出: `undefined`

3. **变量查找测试 (`BytecodeGraphBuilderLookupSlot`, `BytecodeGraphBuilderLookupContextSlot`, `BytecodeGraphBuilderLookupGlobalSlot`, `BytecodeGraphBuilderLookupSlotWide`, `BytecodeGraphBuilderCallLookupSlot`)**:
    *   测试在不同作用域中查找变量的能力，包括局部变量、全局变量以及通过 `eval` 创建的变量。
    *   测试在嵌套作用域中查找变量，特别是涉及 `eval` 的情况。
    *   测试调用函数时对作用域内变量的访问。
    *   `BytecodeGraphBuilderLookupSlotWide` 可能是测试在存在大量局部变量时，变量查找是否仍然正确。
    *   **JavaScript 示例:**
        ```javascript
        let x = 10;
        function foo() {
          console.log(x); // 查找外部作用域的 x
        }
        foo();

        function bar() {
          let y = 20;
          eval('console.log(y)'); // eval 可以访问当前作用域的 y
        }
        bar();
        ```
    *   **假设输入与输出:**
        *   输入代码片段: `"return x;"`, 上下文中有 `var x = 12;`，预期输出: `12`
        *   输入代码片段: `"return eval('x');"`, 上下文中有 `var x = 0;`，预期输出: `0`

4. **`eval` 函数测试 (`BytecodeGraphBuilderEval`, `BytecodeGraphBuilderEvalParams`, `BytecodeGraphBuilderEvalGlobal`)**:
    *   测试 `eval` 函数执行动态 JavaScript 代码的能力，包括基本表达式、变量声明和作用域影响。
    *   测试 `eval` 函数如何访问和修改外部作用域的变量，以及在严格模式下的行为差异。
    *   测试 `eval` 函数如何处理函数参数。
    *   测试 `eval` 函数在全局作用域中创建变量和函数的能力。
    *   **JavaScript 示例:**
        ```javascript
        let a = 5;
        eval('a = 10;');
        console.log(a); // 输出 10

        function testEval(b) {
          eval('c = b + 1;'); // 在非严格模式下，c 会成为全局变量
          console.log(c);
        }
        testEval(2);
        ```
    *   **假设输入与输出:**
        *   输入代码片段: `"return eval('1;');"`，预期输出: `1`
        *   输入代码片段: `"var x = 10; return eval('x + 20;');"`，预期输出: `30`

5. **比较运算符测试 (`BytecodeGraphBuilderCompare`)**:
    *   测试各种比较运算符 (`==`, `!=`, `===`, `!==`, `<`, `<=`, `>`, `>=`) 在不同数据类型之间的行为。
    *   **JavaScript 示例:**
        ```javascript
        console.log(10 == '10'); // true
        console.log(10 === '10'); // false
        console.log(5 > 3);   // true
        ```
    *   **假设输入与输出:**
        *   输入代码片段: `"return p1 == p2;"`, 输入参数 `p1`: `10`, `p2`: `'10'`，预期输出: `true`
        *   输入代码片段: `"return p1 === p2;"`, 输入参数 `p1`: `10`, `p2`: `'10'`，预期输出: `false`

6. **`in` 运算符测试 (`BytecodeGraphBuilderTestIn`)**:
    *   测试 `in` 运算符用于检查对象是否具有特定属性的能力。
    *   **JavaScript 示例:**
        ```javascript
        let obj = { a: 1 };
        console.log('a' in obj);    // true
        console.log('toString' in obj); // true (继承的属性)
        console.log('b' in obj);    // false
        ```
    *   **假设输入与输出:**
        *   输入代码片段: `"return p2 in p1;"`, 输入参数 `p1`: `{val : 10}`, `p2`: `'val'`，预期输出: `true`

7. **`instanceof` 运算符测试 (`BytecodeGraphBuilderTestInstanceOf`)**:
    *   测试 `instanceof` 运算符用于检查对象是否为特定构造函数的实例。
    *   **JavaScript 示例:**
        ```javascript
        let arr = [];
        console.log(arr instanceof Array);   // true
        console.log(arr instanceof Object);  // true
        ```
    *   **假设输入与输出:**
        *   输入代码片段: `"return p1 instanceof Object;"`, 输入参数 `p1`: `{val : 10}`，预期输出: `true`

8. **`try...catch` 语句测试 (`BytecodeGraphBuilderTryCatch`)**:
    *   测试 `try...catch` 语句捕获和处理异常的能力。
    *   **JavaScript 示例:**
        ```javascript
        try {
          undefined.property; // 抛出一个错误
        } catch (e) {
          console.log('捕获到错误:', e);
        }
        ```
    *   **假设输入与输出:**
        *   输入代码片段: `"var a; try { undef.x } catch(e) { a = 2 }; return a;"`，预期输出: `2`

9. **`try...finally` 语句测试 (`BytecodeGraphBuilderTryFinally1`, `BytecodeGraphBuilderTryFinally2`)**:
    *   测试 `try...finally` 语句中 `finally` 代码块无论是否发生异常都会执行的特性。
    *   测试在 `finally` 代码块中抛出异常的情况。
    *   **JavaScript 示例:**
        ```javascript
        try {
          console.log('try block');
          // throw new Error('Something went wrong');
        } finally {
          console.log('finally block'); // 无论是否抛出异常都会执行
        }
        ```
    *   **假设输入与输出:**
        *   输入代码片段: `"var a = 1; try { a = a + 1; } finally { a = a + 2; }; return a;"`，预期输出: `4`

10. **`throw` 语句测试 (`BytecodeGraphBuilderThrow`)**:
    *   测试 `throw` 语句抛出异常的能力。
    *   **JavaScript 示例:**
        ```javascript
        function testThrow(value) {
          if (value < 0) {
            throw 'Invalid value';
          }
          console.log('Value is valid');
        }
        try {
          testThrow(-1);
        } catch (e) {
          console.log('Caught:', e);
        }
        ```
    *   **假设输入与输出:**
        *   输入代码片段: `"throw undefined;"`，预期抛出一个包含 "Uncaught undefined" 的错误。

11. **作用域上下文测试 (`BytecodeGraphBuilderContext`, `BytecodeGraphBuilderLoadContext`)**:
    *   测试不同作用域的变量访问规则，包括使用 `let` 和 `var` 声明的变量。
    *   测试闭包 (closure) 的能力，即内部函数访问外部函数作用域的能力。
    *   测试从父函数上下文中加载变量的能力。
    *   **JavaScript 示例:**
        ```javascript
        function outer() {
          let outerVar = 10;
          function inner() {
            console.log(outerVar); // inner 函数可以访问 outerVar
          }
          return inner;
        }
        let closureFunc = outer();
        closureFunc(); // 输出 10
        ```
    *   **假设输入与输出:**
        *   输入代码片段涉及到复杂的嵌套作用域和闭包，需要分析具体代码来确定预期输出。

总而言之，这部分代码的功能是全面地测试 V8 引擎中字节码图构建器的正确性，涵盖了 JavaScript 语言中常见的运算符、语句和作用域规则，确保 JavaScript 代码能被准确地转换为高效的字节码执行。

Prompt: 
```
这是目录为v8/test/unittests/compiler/run-bytecode-graph-builder-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/compiler/run-bytecode-graph-builder-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共4部分，请归纳一下它的功能

"""
r<char> script(1024);
    SNPrintF(script, "function %s(p1) { %s }\n%s({});", kFunctionName,
             snippets[i].code_snippet, kFunctionName);

    BytecodeGraphTester tester(isolate, script.begin());
    auto callable = tester.GetCallable<Handle<Object>>();
    DirectHandle<Object> return_value =
        callable(snippets[i].parameter(0)).ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *snippets[i].return_value()));
  }
}

TEST_F(RunBytecodeGraphBuilderTest, BytecodeGraphBuilderCountOperation) {
  Isolate* isolate = i_isolate();
  Factory* factory = isolate->factory();

  ExpectedSnippet<1> snippets[] = {
      {"return ++p1;",
       {factory->NewNumberFromInt(11), factory->NewNumberFromInt(10)}},
      {"return p1++;",
       {factory->NewNumberFromInt(10), factory->NewNumberFromInt(10)}},
      {"return p1++ + 10;",
       {factory->NewHeapNumber(15.23), factory->NewHeapNumber(5.23)}},
      {"return 20 + ++p1;",
       {factory->NewHeapNumber(27.23), factory->NewHeapNumber(6.23)}},
      {"return --p1;",
       {factory->NewHeapNumber(9.8), factory->NewHeapNumber(10.8)}},
      {"return p1--;",
       {factory->NewHeapNumber(10.8), factory->NewHeapNumber(10.8)}},
      {"return p1-- + 10;",
       {factory->NewNumberFromInt(20), factory->NewNumberFromInt(10)}},
      {"return 20 + --p1;",
       {factory->NewNumberFromInt(29), factory->NewNumberFromInt(10)}},
      {"return p1.val--;",
       {factory->NewNumberFromInt(10), RunJS("({val : 10})")}},
      {"return ++p1['val'];",
       {factory->NewNumberFromInt(11), RunJS("({val : 10})")}},
      {"return ++p1[1];", {factory->NewNumberFromInt(11), RunJS("({1 : 10})")}},
      {" function inner() { return p1 } return --p1;",
       {factory->NewNumberFromInt(9), factory->NewNumberFromInt(10)}},
      {" function inner() { return p1 } return p1--;",
       {factory->NewNumberFromInt(10), factory->NewNumberFromInt(10)}},
      {"return ++p1;", {factory->nan_value(), MakeString("String")}},
  };

  for (size_t i = 0; i < arraysize(snippets); i++) {
    base::ScopedVector<char> script(1024);
    SNPrintF(script, "function %s(p1) { %s }\n%s({});", kFunctionName,
             snippets[i].code_snippet, kFunctionName);

    BytecodeGraphTester tester(isolate, script.begin());
    auto callable = tester.GetCallable<Handle<Object>>();
    DirectHandle<Object> return_value =
        callable(snippets[i].parameter(0)).ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *snippets[i].return_value()));
  }
}

TEST_F(RunBytecodeGraphBuilderTest, BytecodeGraphBuilderDelete) {
  Isolate* isolate = i_isolate();
  Factory* factory = isolate->factory();

  ExpectedSnippet<1> snippets[] = {
      {"return delete p1.val;", {factory->true_value(), RunJS("({val : 10})")}},
      {"delete p1.val; return p1.val;",
       {factory->undefined_value(), RunJS("({val : 10})")}},
      {"delete p1.name; return p1.val;",
       {factory->NewNumberFromInt(10), RunJS("({val : 10, name:'abc'})")}},
      {"'use strict'; return delete p1.val;",
       {factory->true_value(), RunJS("({val : 10})")}},
      {"'use strict'; delete p1.val; return p1.val;",
       {factory->undefined_value(), RunJS("({val : 10})")}},
      {"'use strict'; delete p1.name; return p1.val;",
       {factory->NewNumberFromInt(10), RunJS("({val : 10, name:'abc'})")}},
  };

  for (size_t i = 0; i < arraysize(snippets); i++) {
    base::ScopedVector<char> script(1024);
    SNPrintF(script, "function %s(p1) { %s }\n%s({});", kFunctionName,
             snippets[i].code_snippet, kFunctionName);

    BytecodeGraphTester tester(isolate, script.begin());
    auto callable = tester.GetCallable<Handle<Object>>();
    DirectHandle<Object> return_value =
        callable(snippets[i].parameter(0)).ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *snippets[i].return_value()));
  }
}

TEST_F(RunBytecodeGraphBuilderTest, BytecodeGraphBuilderDeleteGlobal) {
  Isolate* isolate = i_isolate();
  Factory* factory = isolate->factory();

  ExpectedSnippet<0> snippets[] = {
      {"var obj = {val : 10, type : 'int'};"
       "function f() {return delete obj;};",
       {factory->false_value()}},
      {"function f() {return delete this;};", {factory->true_value()}},
      {"var obj = {val : 10, type : 'int'};"
       "function f() {return delete obj.val;};",
       {factory->true_value()}},
      {"var obj = {val : 10, type : 'int'};"
       "function f() {'use strict'; return delete obj.val;};",
       {factory->true_value()}},
      {"var obj = {val : 10, type : 'int'};"
       "function f() {delete obj.val; return obj.val;};",
       {factory->undefined_value()}},
      {"var obj = {val : 10, type : 'int'};"
       "function f() {'use strict'; delete obj.val; return obj.val;};",
       {factory->undefined_value()}},
      {"var obj = {1 : 10, 2 : 20};"
       "function f() { return delete obj[1]; };",
       {factory->true_value()}},
      {"var obj = {1 : 10, 2 : 20};"
       "function f() { 'use strict';  return delete obj[1];};",
       {factory->true_value()}},
      {"obj = {1 : 10, 2 : 20};"
       "function f() { delete obj[1]; return obj[2];};",
       {factory->NewNumberFromInt(20)}},
      {"function f() {"
       "  var obj = {1 : 10, 2 : 20};"
       "  function inner() { return obj[1]; };"
       "  return delete obj[1];"
       "}",
       {factory->true_value()}},
  };

  for (size_t i = 0; i < arraysize(snippets); i++) {
    base::ScopedVector<char> script(1024);
    SNPrintF(script, "%s %s({});", snippets[i].code_snippet, kFunctionName);

    BytecodeGraphTester tester(isolate, script.begin());
    auto callable = tester.GetCallable<>();
    DirectHandle<Object> return_value = callable().ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *snippets[i].return_value()));
  }
}

TEST_F(RunBytecodeGraphBuilderTest, BytecodeGraphBuilderDeleteLookupSlot) {
  Isolate* isolate = i_isolate();
  Factory* factory = isolate->factory();

  // TODO(mythria): Add more tests when we have support for LdaLookupSlot.
  const char* function_prologue =
      "var f;"
      "var x = 1;"
      "y = 10;"
      "var obj = {val:10};"
      "var z = 30;"
      "function f1() {"
      "  var z = 20;"
      "  eval(\"function t() {";
  const char* function_epilogue =
      "        }; f = t; t();\");"
      "}"
      "f1();";

  ExpectedSnippet<0> snippets[] = {
      {"return delete y;", {factory->true_value()}},
      {"return delete z;", {factory->false_value()}},
  };

  for (size_t i = 0; i < arraysize(snippets); i++) {
    base::ScopedVector<char> script(1024);
    SNPrintF(script, "%s %s %s", function_prologue, snippets[i].code_snippet,
             function_epilogue);

    BytecodeGraphTester tester(isolate, script.begin(), "t");
    auto callable = tester.GetCallable<>();
    DirectHandle<Object> return_value = callable().ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *snippets[i].return_value()));
  }
}

TEST_F(RunBytecodeGraphBuilderTest, BytecodeGraphBuilderLookupSlot) {
  Isolate* isolate = i_isolate();
  Factory* factory = isolate->factory();

  const char* function_prologue =
      "var f;"
      "var x = 12;"
      "y = 10;"
      "var obj = {val:3.1414};"
      "var z = 30;"
      "function f1() {"
      "  var z = 20;"
      "  eval(\"function t() {";
  const char* function_epilogue =
      "        }; f = t; t();\");"
      "}"
      "f1();";

  ExpectedSnippet<0> snippets[] = {
      {"return x;", {factory->NewNumber(12)}},
      {"return obj.val;", {factory->NewNumber(3.1414)}},
      {"return typeof x;", {MakeString("number")}},
      {"return typeof dummy;", {MakeString("undefined")}},
      {"x = 23; return x;", {factory->NewNumber(23)}},
      {"'use strict'; obj.val = 23.456; return obj.val;",
       {factory->NewNumber(23.456)}}};

  for (size_t i = 0; i < arraysize(snippets); i++) {
    base::ScopedVector<char> script(1024);
    SNPrintF(script, "%s %s %s", function_prologue, snippets[i].code_snippet,
             function_epilogue);

    BytecodeGraphTester tester(isolate, script.begin(), "t");
    auto callable = tester.GetCallable<>();
    DirectHandle<Object> return_value = callable().ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *snippets[i].return_value()));
  }
}

TEST_F(RunBytecodeGraphBuilderTest, BytecodeGraphBuilderLookupContextSlot) {
  Isolate* isolate = i_isolate();
  Factory* factory = isolate->factory();

  // Testing with eval called in the current context.
  const char* inner_eval_prologue = "var x = 0; function inner() {";
  const char* inner_eval_epilogue = "}; return inner();";

  ExpectedSnippet<0> inner_eval_snippets[] = {
      {"eval(''); return x;", {factory->NewNumber(0)}},
      {"eval('var x = 1'); return x;", {factory->NewNumber(1)}},
      {"'use strict'; eval('var x = 1'); return x;", {factory->NewNumber(0)}}};

  for (size_t i = 0; i < arraysize(inner_eval_snippets); i++) {
    base::ScopedVector<char> script(1024);
    SNPrintF(script, "function %s(p1) { %s %s %s } ; %s() ;", kFunctionName,
             inner_eval_prologue, inner_eval_snippets[i].code_snippet,
             inner_eval_epilogue, kFunctionName);

    BytecodeGraphTester tester(isolate, script.begin());
    auto callable = tester.GetCallable<>();
    DirectHandle<Object> return_value = callable().ToHandleChecked();
    CHECK(Object::SameValue(*return_value,
                            *inner_eval_snippets[i].return_value()));
  }

  // Testing with eval called in a parent context.
  const char* outer_eval_prologue = "";
  const char* outer_eval_epilogue =
      "function inner() { return x; }; return inner();";

  ExpectedSnippet<0> outer_eval_snippets[] = {
      {"var x = 0; eval('');", {factory->NewNumber(0)}},
      {"var x = 0; eval('var x = 1');", {factory->NewNumber(1)}},
      {"'use strict'; var x = 0; eval('var x = 1');", {factory->NewNumber(0)}}};

  for (size_t i = 0; i < arraysize(outer_eval_snippets); i++) {
    base::ScopedVector<char> script(1024);
    SNPrintF(script, "function %s() { %s %s %s } ; %s() ;", kFunctionName,
             outer_eval_prologue, outer_eval_snippets[i].code_snippet,
             outer_eval_epilogue, kFunctionName);

    BytecodeGraphTester tester(isolate, script.begin());
    auto callable = tester.GetCallable<>();
    DirectHandle<Object> return_value = callable().ToHandleChecked();
    CHECK(Object::SameValue(*return_value,
                            *outer_eval_snippets[i].return_value()));
  }
}

TEST_F(RunBytecodeGraphBuilderTest, BytecodeGraphBuilderLookupGlobalSlot) {
  Isolate* isolate = i_isolate();
  Factory* factory = isolate->factory();

  // Testing with eval called in the current context.
  const char* inner_eval_prologue = "x = 0; function inner() {";
  const char* inner_eval_epilogue = "}; return inner();";

  ExpectedSnippet<0> inner_eval_snippets[] = {
      {"eval(''); return x;", {factory->NewNumber(0)}},
      {"eval('var x = 1'); return x;", {factory->NewNumber(1)}},
      {"'use strict'; eval('var x = 1'); return x;", {factory->NewNumber(0)}}};

  for (size_t i = 0; i < arraysize(inner_eval_snippets); i++) {
    base::ScopedVector<char> script(1024);
    SNPrintF(script, "function %s(p1) { %s %s %s } ; %s() ;", kFunctionName,
             inner_eval_prologue, inner_eval_snippets[i].code_snippet,
             inner_eval_epilogue, kFunctionName);

    BytecodeGraphTester tester(isolate, script.begin());
    auto callable = tester.GetCallable<>();
    DirectHandle<Object> return_value = callable().ToHandleChecked();
    CHECK(Object::SameValue(*return_value,
                            *inner_eval_snippets[i].return_value()));
  }

  // Testing with eval called in a parent context.
  const char* outer_eval_prologue = "";
  const char* outer_eval_epilogue =
      "function inner() { return x; }; return inner();";

  ExpectedSnippet<0> outer_eval_snippets[] = {
      {"x = 0; eval('');", {factory->NewNumber(0)}},
      {"x = 0; eval('var x = 1');", {factory->NewNumber(1)}},
      {"'use strict'; x = 0; eval('var x = 1');", {factory->NewNumber(0)}}};

  for (size_t i = 0; i < arraysize(outer_eval_snippets); i++) {
    base::ScopedVector<char> script(1024);
    SNPrintF(script, "function %s() { %s %s %s } ; %s() ;", kFunctionName,
             outer_eval_prologue, outer_eval_snippets[i].code_snippet,
             outer_eval_epilogue, kFunctionName);

    BytecodeGraphTester tester(isolate, script.begin());
    auto callable = tester.GetCallable<>();
    DirectHandle<Object> return_value = callable().ToHandleChecked();
    CHECK(Object::SameValue(*return_value,
                            *outer_eval_snippets[i].return_value()));
  }
}

TEST_F(RunBytecodeGraphBuilderTest, BytecodeGraphBuilderLookupSlotWide) {
  Isolate* isolate = i_isolate();
  Factory* factory = isolate->factory();

  const char* function_prologue =
      "var f;"
      "var x = 12;"
      "y = 10;"
      "var obj = {val:3.1414};"
      "var z = 30;"
      "function f1() {"
      "  var z = 20;"
      "  eval(\"function t() {";
  const char* function_epilogue =
      "        }; f = t; t();\");"
      "}"
      "f1();";

  ExpectedSnippet<0> snippets[] = {
      {"var y = 2.3;" REPEAT_256(SPACE, "y = 2.3;") "return x;",
       {factory->NewNumber(12)}},
      {"var y = 2.3;" REPEAT_256(SPACE, "y = 2.3;") "return typeof x;",
       {MakeString("number")}},
      {"var y = 2.3;" REPEAT_256(SPACE, "y = 2.3;") "return x = 23;",
       {factory->NewNumber(23)}},
      {"'use strict';" REPEAT_256(SPACE, "y = 2.3;") "return obj.val = 23.456;",
       {factory->NewNumber(23.456)}}};

  for (size_t i = 0; i < arraysize(snippets); i++) {
    base::ScopedVector<char> script(3072);
    SNPrintF(script, "%s %s %s", function_prologue, snippets[i].code_snippet,
             function_epilogue);

    BytecodeGraphTester tester(isolate, script.begin(), "t");
    auto callable = tester.GetCallable<>();
    DirectHandle<Object> return_value = callable().ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *snippets[i].return_value()));
  }
}

TEST_F(RunBytecodeGraphBuilderTest, BytecodeGraphBuilderCallLookupSlot) {
  Isolate* isolate = i_isolate();

  ExpectedSnippet<0> snippets[] = {
      {"g = function(){ return 2 }; eval(''); return g();",
       {handle(Smi::FromInt(2), isolate)}},
      {"g = function(){ return 2 }; eval('g = function() {return 3}');\n"
       "return g();",
       {handle(Smi::FromInt(3), isolate)}},
      {"g = { x: function(){ return this.y }, y: 20 };\n"
       "eval('g = { x: g.x, y: 30 }');\n"
       "return g.x();",
       {handle(Smi::FromInt(30), isolate)}},
  };

  for (size_t i = 0; i < arraysize(snippets); i++) {
    base::ScopedVector<char> script(1024);
    SNPrintF(script, "function %s() { %s }\n%s();", kFunctionName,
             snippets[i].code_snippet, kFunctionName);
    BytecodeGraphTester tester(isolate, script.begin());
    auto callable = tester.GetCallable<>();
    DirectHandle<Object> return_value = callable().ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *snippets[i].return_value()));
  }
}

TEST_F(RunBytecodeGraphBuilderTest, BytecodeGraphBuilderEval) {
  Isolate* isolate = i_isolate();

  ExpectedSnippet<0> snippets[] = {
      {"return eval('1;');", {handle(Smi::FromInt(1), isolate)}},
      {"return eval('100 * 20;');", {handle(Smi::FromInt(2000), isolate)}},
      {"var x = 10; return eval('x + 20;');",
       {handle(Smi::FromInt(30), isolate)}},
      {"var x = 10; eval('x = 33;'); return x;",
       {handle(Smi::FromInt(33), isolate)}},
      {"'use strict'; var x = 20; var z = 0;\n"
       "eval('var x = 33; z = x;'); return x + z;",
       {handle(Smi::FromInt(53), isolate)}},
      {"eval('var x = 33;'); eval('var y = x + 20'); return x + y;",
       {handle(Smi::FromInt(86), isolate)}},
      {"var x = 1; eval('for(i = 0; i < 10; i++) x = x + 1;'); return x",
       {handle(Smi::FromInt(11), isolate)}},
      {"var x = 10; eval('var x = 20;'); return x;",
       {handle(Smi::FromInt(20), isolate)}},
      {"var x = 1; eval('\"use strict\"; var x = 2;'); return x;",
       {handle(Smi::FromInt(1), isolate)}},
      {"'use strict'; var x = 1; eval('var x = 2;'); return x;",
       {handle(Smi::FromInt(1), isolate)}},
      {"var x = 10; eval('x + 20;'); return typeof x;", {MakeString("number")}},
      {"eval('var y = 10;'); return typeof unallocated;",
       {MakeString("undefined")}},
      {"'use strict'; eval('var y = 10;'); return typeof unallocated;",
       {MakeString("undefined")}},
      {"eval('var x = 10;'); return typeof x;", {MakeString("number")}},
      {"var x = {}; eval('var x = 10;'); return typeof x;",
       {MakeString("number")}},
      {"'use strict'; var x = {}; eval('var x = 10;'); return typeof x;",
       {MakeString("object")}},
  };

  for (size_t i = 0; i < arraysize(snippets); i++) {
    base::ScopedVector<char> script(1024);
    SNPrintF(script, "function %s() { %s }\n%s();", kFunctionName,
             snippets[i].code_snippet, kFunctionName);
    BytecodeGraphTester tester(isolate, script.begin());
    auto callable = tester.GetCallable<>();
    DirectHandle<Object> return_value = callable().ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *snippets[i].return_value()));
  }
}

TEST_F(RunBytecodeGraphBuilderTest, BytecodeGraphBuilderEvalParams) {
  Isolate* isolate = i_isolate();

  ExpectedSnippet<1> snippets[] = {
      {"var x = 10; return eval('x + p1;');",
       {handle(Smi::FromInt(30), isolate), handle(Smi::FromInt(20), isolate)}},
      {"var x = 10; eval('p1 = x;'); return p1;",
       {handle(Smi::FromInt(10), isolate), handle(Smi::FromInt(20), isolate)}},
      {"var a = 10;"
       "function inner() { return eval('a + p1;');}"
       "return inner();",
       {handle(Smi::FromInt(30), isolate), handle(Smi::FromInt(20), isolate)}},
  };

  for (size_t i = 0; i < arraysize(snippets); i++) {
    base::ScopedVector<char> script(1024);
    SNPrintF(script, "function %s(p1) { %s }\n%s(0);", kFunctionName,
             snippets[i].code_snippet, kFunctionName);
    BytecodeGraphTester tester(isolate, script.begin());
    auto callable = tester.GetCallable<Handle<Object>>();
    DirectHandle<Object> return_value =
        callable(snippets[i].parameter(0)).ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *snippets[i].return_value()));
  }
}

TEST_F(RunBytecodeGraphBuilderTest, BytecodeGraphBuilderEvalGlobal) {
  Isolate* isolate = i_isolate();

  ExpectedSnippet<0> snippets[] = {
      {"function add_global() { eval('function f() { z = 33; }; f()'); };"
       "function f() { add_global(); return z; }; f();",
       {handle(Smi::FromInt(33), isolate)}},
      {"function add_global() {\n"
       " eval('\"use strict\"; function f() { y = 33; };"
       "      try { f() } catch(e) {}');\n"
       "}\n"
       "function f() { add_global(); return typeof y; } f();",
       {MakeString("undefined")}},
  };

  for (size_t i = 0; i < arraysize(snippets); i++) {
    BytecodeGraphTester tester(isolate, snippets[i].code_snippet);
    auto callable = tester.GetCallable<>();
    DirectHandle<Object> return_value = callable().ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *snippets[i].return_value()));
  }
}

bool get_compare_result(Isolate* isolate, Token::Value opcode,
                        Handle<Object> lhs_value, Handle<Object> rhs_value) {
  switch (opcode) {
    case Token::kEq:
      return Object::Equals(isolate, lhs_value, rhs_value).FromJust();
    case Token::kNotEq:
      return !Object::Equals(isolate, lhs_value, rhs_value).FromJust();
    case Token::kEqStrict:
      return Object::StrictEquals(*lhs_value, *rhs_value);
    case Token::kNotEqStrict:
      return !Object::StrictEquals(*lhs_value, *rhs_value);
    case Token::kLessThan:
      return Object::LessThan(isolate, lhs_value, rhs_value).FromJust();
    case Token::kLessThanEq:
      return Object::LessThanOrEqual(isolate, lhs_value, rhs_value).FromJust();
    case Token::kGreaterThan:
      return Object::GreaterThan(isolate, lhs_value, rhs_value).FromJust();
    case Token::kGreaterThanEq:
      return Object::GreaterThanOrEqual(isolate, lhs_value, rhs_value)
          .FromJust();
    default:
      UNREACHABLE();
  }
}

const char* get_code_snippet(Token::Value opcode) {
  switch (opcode) {
    case Token::kEq:
      return "return p1 == p2;";
    case Token::kNotEq:
      return "return p1 != p2;";
    case Token::kEqStrict:
      return "return p1 === p2;";
    case Token::kNotEqStrict:
      return "return p1 !== p2;";
    case Token::kLessThan:
      return "return p1 < p2;";
    case Token::kLessThanEq:
      return "return p1 <= p2;";
    case Token::kGreaterThan:
      return "return p1 > p2;";
    case Token::kGreaterThanEq:
      return "return p1 >= p2;";
    default:
      UNREACHABLE();
  }
}

TEST_F(RunBytecodeGraphBuilderTest, BytecodeGraphBuilderCompare) {
  Isolate* isolate = i_isolate();
  Factory* factory = isolate->factory();
  Handle<Object> lhs_values[] = {
      factory->NewNumberFromInt(10), factory->NewHeapNumber(3.45),
      MakeString("abc"), factory->NewNumberFromInt(SMI_MAX),
      factory->NewNumberFromInt(SMI_MIN)};
  Handle<Object> rhs_values[] = {
      factory->NewNumberFromInt(10),     MakeString("10"),
      factory->NewNumberFromInt(20),     MakeString("abc"),
      factory->NewHeapNumber(3.45),      factory->NewNumberFromInt(SMI_MAX),
      factory->NewNumberFromInt(SMI_MIN)};

  for (size_t i = 0; i < arraysize(kCompareOperators); i++) {
    base::ScopedVector<char> script(1024);
    SNPrintF(script, "function %s(p1, p2) { %s }\n%s({}, {});", kFunctionName,
             get_code_snippet(kCompareOperators[i]), kFunctionName);

    BytecodeGraphTester tester(isolate, script.begin());
    auto callable = tester.GetCallable<Handle<Object>, Handle<Object>>();
    for (size_t j = 0; j < arraysize(lhs_values); j++) {
      for (size_t k = 0; k < arraysize(rhs_values); k++) {
        DirectHandle<Object> return_value =
            callable(lhs_values[j], rhs_values[k]).ToHandleChecked();
        bool result = get_compare_result(isolate, kCompareOperators[i],
                                         lhs_values[j], rhs_values[k]);
        CHECK(Object::SameValue(*return_value, *factory->ToBoolean(result)));
      }
    }
  }
}

TEST_F(RunBytecodeGraphBuilderTest, BytecodeGraphBuilderTestIn) {
  Isolate* isolate = i_isolate();
  Factory* factory = isolate->factory();

  ExpectedSnippet<2> snippets[] = {
      {"return p2 in p1;",
       {factory->true_value(), RunJS("({val : 10})"), MakeString("val")}},
      {"return p2 in p1;",
       {factory->true_value(), RunJS("[]"), MakeString("length")}},
      {"return p2 in p1;",
       {factory->true_value(), RunJS("[]"), MakeString("toString")}},
      {"return p2 in p1;",
       {factory->true_value(), RunJS("({val : 10})"), MakeString("toString")}},
      {"return p2 in p1;",
       {factory->false_value(), RunJS("({val : 10})"), MakeString("abc")}},
      {"return p2 in p1;",
       {factory->false_value(), RunJS("({val : 10})"),
        factory->NewNumberFromInt(10)}},
      {"return p2 in p1;",
       {factory->true_value(), RunJS("({10 : 'val'})"),
        factory->NewNumberFromInt(10)}},
      {"return p2 in p1;",
       {factory->false_value(), RunJS("({10 : 'val'})"),
        factory->NewNumberFromInt(1)}},
  };

  for (size_t i = 0; i < arraysize(snippets); i++) {
    base::ScopedVector<char> script(1024);
    SNPrintF(script, "function %s(p1, p2) { %s }\n%s({}, {});", kFunctionName,
             snippets[i].code_snippet, kFunctionName);

    BytecodeGraphTester tester(isolate, script.begin());
    auto callable = tester.GetCallable<Handle<Object>, Handle<Object>>();
    DirectHandle<Object> return_value =
        callable(snippets[i].parameter(0), snippets[i].parameter(1))
            .ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *snippets[i].return_value()));
  }
}

TEST_F(RunBytecodeGraphBuilderTest, BytecodeGraphBuilderTestInstanceOf) {
  Isolate* isolate = i_isolate();
  Factory* factory = isolate->factory();

  ExpectedSnippet<1> snippets[] = {
      {"return p1 instanceof Object;",
       {factory->true_value(), RunJS("({val : 10})")}},
      {"return p1 instanceof String;",
       {factory->false_value(), MakeString("string")}},
      {"var cons = function() {};"
       "var obj = new cons();"
       "return obj instanceof cons;",
       {factory->true_value(), factory->undefined_value()}},
  };

  for (size_t i = 0; i < arraysize(snippets); i++) {
    base::ScopedVector<char> script(1024);
    SNPrintF(script, "function %s(p1) { %s }\n%s({});", kFunctionName,
             snippets[i].code_snippet, kFunctionName);

    BytecodeGraphTester tester(isolate, script.begin());
    auto callable = tester.GetCallable<Handle<Object>>();
    DirectHandle<Object> return_value =
        callable(snippets[i].parameter(0)).ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *snippets[i].return_value()));
  }
}

TEST_F(RunBytecodeGraphBuilderTest, BytecodeGraphBuilderTryCatch) {
  Isolate* isolate = i_isolate();

  ExpectedSnippet<0> snippets[] = {
      {"var a = 1; try { a = 2 } catch(e) { a = 3 }; return a;",
       {handle(Smi::FromInt(2), isolate)}},
      {"var a; try { undef.x } catch(e) { a = 2 }; return a;",
       {handle(Smi::FromInt(2), isolate)}},
      {"var a; try { throw 1 } catch(e) { a = e + 2 }; return a;",
       {handle(Smi::FromInt(3), isolate)}},
      {"var a; try { throw 1 } catch(e) { a = e + 2 };"
       "       try { throw a } catch(e) { a = e + 3 }; return a;",
       {handle(Smi::FromInt(6), isolate)}},
  };

  for (size_t i = 0; i < arraysize(snippets); i++) {
    base::ScopedVector<char> script(1024);
    SNPrintF(script, "function %s() { %s }\n%s();", kFunctionName,
             snippets[i].code_snippet, kFunctionName);

    BytecodeGraphTester tester(isolate, script.begin());
    auto callable = tester.GetCallable<>();
    DirectHandle<Object> return_value = callable().ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *snippets[i].return_value()));
  }
}

TEST_F(RunBytecodeGraphBuilderTest, BytecodeGraphBuilderTryFinally1) {
  Isolate* isolate = i_isolate();

  ExpectedSnippet<0> snippets[] = {
      {"var a = 1; try { a = a + 1; } finally { a = a + 2; }; return a;",
       {handle(Smi::FromInt(4), isolate)}},
      {"var a = 1; try { a = 2; return 23; } finally { a = 3 }; return a;",
       {handle(Smi::FromInt(23), isolate)}},
      {"var a = 1; try { a = 2; throw 23; } finally { return a; };",
       {handle(Smi::FromInt(2), isolate)}},
      {"var a = 1; for (var i = 10; i < 20; i += 5) {"
       "  try { a = 2; break; } finally { a = 3; }"
       "} return a + i;",
       {handle(Smi::FromInt(13), isolate)}},
      {"var a = 1; for (var i = 10; i < 20; i += 5) {"
       "  try { a = 2; continue; } finally { a = 3; }"
       "} return a + i;",
       {handle(Smi::FromInt(23), isolate)}},
      {"var a = 1; try { a = 2;"
       "  try { a = 3; throw 23; } finally { a = 4; }"
       "} catch(e) { a = a + e; } return a;",
       {handle(Smi::FromInt(27), isolate)}},
  };

  for (size_t i = 0; i < arraysize(snippets); i++) {
    base::ScopedVector<char> script(1024);
    SNPrintF(script, "function %s() { %s }\n%s();", kFunctionName,
             snippets[i].code_snippet, kFunctionName);

    BytecodeGraphTester tester(isolate, script.begin());
    auto callable = tester.GetCallable<>();
    DirectHandle<Object> return_value = callable().ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *snippets[i].return_value()));
  }
}

TEST_F(RunBytecodeGraphBuilderTest, BytecodeGraphBuilderTryFinally2) {
  Isolate* isolate = i_isolate();

  ExpectedSnippet<0, const char*> snippets[] = {
      {"var a = 1; try { a = 2; throw 23; } finally { a = 3 }; return a;",
       {"Uncaught 23"}},
      {"var a = 1; try { a = 2; throw 23; } finally { throw 42; };",
       {"Uncaught 42"}},
  };

  for (size_t i = 0; i < arraysize(snippets); i++) {
    base::ScopedVector<char> script(1024);
    SNPrintF(script, "function %s() { %s }\n%s();", kFunctionName,
             snippets[i].code_snippet, kFunctionName);

    BytecodeGraphTester tester(isolate, script.begin());
    v8::Local<v8::String> message = tester.CheckThrowsReturnMessage()->Get();
    v8::Local<v8::String> expected_string =
        NewString(snippets[i].return_value());
    CHECK(message->Equals(v8_isolate()->GetCurrentContext(), expected_string)
              .FromJust());
  }
}

TEST_F(RunBytecodeGraphBuilderTest, BytecodeGraphBuilderThrow) {
  Isolate* isolate = i_isolate();

  // TODO(mythria): Add more tests when real try-catch and deoptimization
  // information are supported.
  ExpectedSnippet<0, const char*> snippets[] = {
      {"throw undefined;", {"Uncaught undefined"}},
      {"throw 1;", {"Uncaught 1"}},
      {"throw 'Error';", {"Uncaught Error"}},
      {"throw 'Error1'; throw 'Error2'", {"Uncaught Error1"}},
      {"var a = true; if (a) { throw 'Error'; }", {"Uncaught Error"}},
  };

  for (size_t i = 0; i < arraysize(snippets); i++) {
    base::ScopedVector<char> script(1024);
    SNPrintF(script, "function %s() { %s }\n%s();", kFunctionName,
             snippets[i].code_snippet, kFunctionName);

    BytecodeGraphTester tester(isolate, script.begin());
    v8::Local<v8::String> message = tester.CheckThrowsReturnMessage()->Get();
    v8::Local<v8::String> expected_string =
        NewString(snippets[i].return_value());
    CHECK(message->Equals(v8_isolate()->GetCurrentContext(), expected_string)
              .FromJust());
  }
}

TEST_F(RunBytecodeGraphBuilderTest, BytecodeGraphBuilderContext) {
  Isolate* isolate = i_isolate();

  ExpectedSnippet<0> snippets[] = {
      {"var x = 'outer';"
       "function f() {"
       " 'use strict';"
       " {"
       "   let x = 'inner';"
       "   (function() {x});"
       " }"
       "return(x);"
       "}"
       "f();",
       {MakeString("outer")}},
      {"var x = 'outer';"
       "function f() {"
       " 'use strict';"
       " {"
       "   let x = 'inner ';"
       "   var innerFunc = function() {return x};"
       " }"
       "return(innerFunc() + x);"
       "}"
       "f();",
       {MakeString("inner outer")}},
      {"var x = 'outer';"
       "function f() {"
       " 'use strict';"
       " {"
       "   let x = 'inner ';"
       "   var innerFunc = function() {return x;};"
       "   {"
       "     let x = 'innermost ';"
       "     var innerMostFunc = function() {return x + innerFunc();};"
       "   }"
       "   x = 'inner_changed ';"
       " }"
       " return(innerMostFunc() + x);"
       "}"
       "f();",
       {MakeString("innermost inner_changed outer")}},
  };

  for (size_t i = 0; i < arraysize(snippets); i++) {
    base::ScopedVector<char> script(1024);
    SNPrintF(script, "%s", snippets[i].code_snippet);

    BytecodeGraphTester tester(isolate, script.begin(), "f");
    auto callable = tester.GetCallable<>("f");
    DirectHandle<Object> return_value = callable().ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *snippets[i].return_value()));
  }
}

TEST_F(RunBytecodeGraphBuilderTest, BytecodeGraphBuilderLoadContext) {
  Isolate* isolate = i_isolate();
  Factory* factory = isolate->factory();

  ExpectedSnippet<1> snippets[] = {
      {"function Outer() {"
       "  var outerVar = 2;"
       "  function Inner(innerArg) {"
       "    this.innerFunc = function () {"
       "     return outerVar * innerArg;"
       "    };"
       "  };"
       "  this.getInnerFunc = function GetInner() {"
       "     return new Inner(3).innerFunc;"
       "   }"
       "}"
       "var f = new Outer().getInnerFunc();"
       "f();",
       {factory->NewNumberFromInt(6), factory->undefined_value()}},
      {"function Outer() {"
       "  var outerVar = 2;"
       "  function Inner(innerArg) {"
       "    this.innerFunc = function () {"
       "     outerVar = innerArg; return outerVar;"
       "    };"
       "  };"
       "  this.getInnerFunc = function GetInner() {"
       "     return new Inner(10).innerFunc;"
       "   }"
       "}"
       "var f = new Outer().getInnerFunc();"
       "f();",
       {factory->NewNumberFromInt(10), factory->undefined_value()}},
      {"function testOuter(outerArg) {"
       " this.testinnerFunc = function testInner(innerArg) {"
       "   return innerArg + outerArg;"
       " }"
       "}"
       "var f = new testOuter(10).testinnerFunc;"
       "f(0);",
       {factory->NewNumberFromInt(14), factory->NewNumberFromInt(4)}},
      {"function testOuter(outerArg) {"
       " var outerVar = outerArg * 2;"
       " this.testi
"""


```