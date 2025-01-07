Response:
My thinking process to analyze the provided C++ code snippet and fulfill the request goes like this:

1. **Understand the Goal:** The core request is to analyze a C++ unit test file for V8's bytecode graph builder. The output should summarize its functionality, relate it to JavaScript concepts, provide examples (if applicable), and discuss potential programming errors. The request explicitly mentions this is part 3 of 4, implying a broader context of testing the bytecode generation process.

2. **Identify the Core Subject:** The filename `run-bytecode-graph-builder-unittest.cc` immediately points to the central theme: testing the `BytecodeGraphBuilder`. This builder is responsible for transforming JavaScript code into bytecode.

3. **Analyze the Structure:** The code uses the Google Test framework (`TEST_F`). Each `TEST_F` function represents a specific test case. The naming convention `BytecodeGraphBuilder*` strongly suggests the tests are focused on different aspects of the `BytecodeGraphBuilder's` behavior.

4. **Examine Individual Test Cases:**  I'll go through each `TEST_F` and try to understand its purpose by looking at the code and the descriptive test name:

    * **`BytecodeGraphBuilderNestedFunctions`:** This test seems to be checking how the builder handles nested function calls and variable scope (closure). The provided JavaScript snippet demonstrates this clearly.
    * **`BytecodeGraphBuilderCreateArgumentsNoParameters`:**  This focuses on how `arguments` behaves when a function has no explicitly defined parameters, including cases with `'use strict'` and rest parameters.
    * **`BytecodeGraphBuilderCreateArguments`:** This test examines the behavior of the `arguments` object with explicitly defined parameters, including how it reflects changes to named parameters and how it works within inline functions.
    * **`BytecodeGraphBuilderCreateRestArguments`:** This specifically targets the creation and behavior of rest parameters (`...restArgs`) and how they interact with the `arguments` object.
    * **`BytecodeGraphBuilderRegExpLiterals`:**  This test is about compiling regular expression literals within JavaScript code.
    * **`BytecodeGraphBuilderArrayLiterals`:**  Focuses on how array literals are processed, including nested arrays and expressions within the literal.
    * **`BytecodeGraphBuilderObjectLiterals`:**  Tests the compilation of object literals, covering various aspects like property access, computed property names, methods, getters/setters, and `__proto__`.
    * **`BytecodeGraphBuilderIf`:**  Checks the generation of bytecode for `if` and `if-else` statements, including nested `if`s.
    * **`BytecodeGraphBuilderConditionalOperator`:**  Specifically tests the ternary conditional operator (`? :`).
    * **`BytecodeGraphBuilderSwitch`:** Examines the bytecode generation for `switch` statements with basic cases, fall-through, and default cases.
    * **`BytecodeGraphBuilderSwitchMerge`:** This test seems to focus on how the builder handles control flow merging at the end of `switch` cases when there's no `break`.
    * **`BytecodeGraphBuilderNestedSwitch`:** Tests the compilation of nested `switch` statements.
    * **`BytecodeGraphBuilderBreakableBlocks`:**  Checks labeled `break` statements within blocks.
    * **`BytecodeGraphBuilderWhile`:** Tests the `while` loop, including `break` and `continue` statements.
    * **`BytecodeGraphBuilderDo`:** Tests the `do-while` loop, also including `break` and `continue`.
    * **`BytecodeGraphBuilderFor`:** Focuses on the standard `for` loop, including different initialization, condition, and increment expressions, and `break`/`continue`.
    * **`BytecodeGraphBuilderForIn`:** Tests the `for...in` loop, specifically how it iterates over object properties (including array indices). It also touches on iterating over `null` and numbers.
    * **`BytecodeGraphBuilderForOf`:** Tests the `for...of` loop, focusing on iterating over iterable objects like arrays and strings, and how `delete` within the loop affects iteration.

5. **Relate to JavaScript Functionality:** For each test case, I consider the corresponding JavaScript language feature being tested. This involves understanding how these features behave in JavaScript. Providing JavaScript examples helps illustrate this connection.

6. **Identify Potential Programming Errors:** Based on the test scenarios, I think about common mistakes developers might make when using these JavaScript features. For example, misunderstanding `arguments` in strict mode, incorrect usage of `break` or `continue`, or issues with variable scope in loops.

7. **Code Logic Inference (Hypothetical Input/Output):**  The `ExpectedSnippet` structure in the C++ code already provides the expected output for given input JavaScript snippets. My task is to understand *why* those are the expected outputs based on JavaScript semantics.

8. **Address Specific Instructions:**  I ensure I cover all the points in the request:

    * **Listing Functionality:** Summarizing the purpose of the file and individual tests.
    * **Torque Source:** Checking the file extension and confirming it's C++.
    * **JavaScript Relation:** Explicitly linking the tests to JavaScript features with examples.
    * **Logic Inference:**  Explaining the expected input and output based on JavaScript rules.
    * **Common Errors:**  Providing relevant examples of programming mistakes.
    * **Part 3 Summary:**  Synthesizing the overall function of this specific part of the test suite.

9. **Structure the Output:** I organize the information clearly, using headings and bullet points for readability. I start with a general summary and then detail the functionality of each test case.

10. **Refine and Review:** I reread my analysis to ensure accuracy, clarity, and completeness, making sure I've addressed all aspects of the request. I check for any inconsistencies or areas that could be explained better. For example, I ensure the JavaScript examples are concise and directly relevant to the tested functionality.
```cpp
nnerFunc = function testInner(innerArg) {"
       "   outerVar = outerVar + innerArg; return outerVar;"
       " }"
       "}"
       "var f = new testOuter(10).testinnerFunc;"
       "f(0);",
       {factory->NewNumberFromInt(24), factory->NewNumberFromInt(4)}}};

  for (size_t i = 0; i < arraysize(snippets); i++) {
    base::ScopedVector<char> script(1024);
    SNPrintF(script, "%s", snippets[i].code_snippet);

    BytecodeGraphTester tester(isolate, script.begin(), "*");
    auto callable = tester.GetCallable<Handle<Object>>("f");
    DirectHandle<Object> return_value =
        callable(snippets[i].parameter(0)).ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *snippets[i].return_value()));
  }
}

TEST_F(RunBytecodeGraphBuilderTest,
       BytecodeGraphBuilderCreateArgumentsNoParameters) {
  Isolate* isolate = i_isolate();
  Factory* factory = isolate->factory();

  ExpectedSnippet<0> snippets[] = {
      {"function f() {return arguments[0];}", {factory->undefined_value()}},
      {"function f(a) {return arguments[0];}", {factory->undefined_value()}},
      {"function f() {'use strict'; return arguments[0];}",
       {factory->undefined_value()}},
      {"function f(a) {'use strict'; return arguments[0];}",
       {factory->undefined_value()}},
      {"function f(...restArgs) {return restArgs[0];}",
       {factory->undefined_value()}},
      {"function f(a, ...restArgs) {return restArgs[0];}",
       {factory->undefined_value()}},
  };

  for (size_t i = 0; i < arraysize(snippets); i++) {
    base::ScopedVector<char> script(1024);
    SNPrintF(script, "%s\n%s();", snippets[i].code_snippet, kFunctionName);

    BytecodeGraphTester tester(isolate, script.begin());
    auto callable = tester.GetCallable<>();
    DirectHandle<Object> return_value = callable().ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *snippets[i].return_value()));
  }
}

TEST_F(RunBytecodeGraphBuilderTest, BytecodeGraphBuilderCreateArguments) {
  Isolate* isolate = i_isolate();
  Factory* factory = isolate->factory();

  ExpectedSnippet<3> snippets[] = {
      {"function f(a, b, c) {return arguments[0];}",
       {factory->NewNumberFromInt(1), factory->NewNumberFromInt(1),
        factory->NewNumberFromInt(2), factory->NewNumberFromInt(3)}},
      {"function f(a, b, c) {return arguments[3];}",
       {factory->undefined_value(), factory->NewNumberFromInt(1),
        factory->NewNumberFromInt(2), factory->NewNumberFromInt(3)}},
      {"function f(a, b, c) { b = c; return arguments[1];}",
       {factory->NewNumberFromInt(3), factory->NewNumberFromInt(1),
        factory->NewNumberFromInt(2), factory->NewNumberFromInt(3)}},
      {"function f(a, b, c) {'use strict'; return arguments[0];}",
       {factory->NewNumberFromInt(1), factory->NewNumberFromInt(1),
        factory->NewNumberFromInt(2), factory->NewNumberFromInt(3)}},
      {"function f(a, b, c) {'use strict'; return arguments[3];}",
       {factory->undefined_value(), factory->NewNumberFromInt(1),
        factory->NewNumberFromInt(2), factory->NewNumberFromInt(3)}},
      {"function f(a, b, c) {'use strict'; b = c; return arguments[1];}",
       {factory->NewNumberFromInt(2), factory->NewNumberFromInt(1),
        factory->NewNumberFromInt(2), factory->NewNumberFromInt(3)}},
      {"function inline_func(a, b) { return arguments[0] }"
       "function f(a, b, c) {return inline_func(b, c) + arguments[0];}",
       {factory->NewNumberFromInt(3), factory->NewNumberFromInt(1),
        factory->NewNumberFromInt(2), factory->NewNumberFromInt(30)}},
  };

  for (size_t i = 0; i < arraysize(snippets); i++) {
    base::ScopedVector<char> script(1024);
    SNPrintF(script, "%s\n%s();", snippets[i].code_snippet, kFunctionName);

    BytecodeGraphTester tester(isolate, script.begin());
    auto callable =
        tester.GetCallable<Handle<Object>, Handle<Object>, Handle<Object>>();
    DirectHandle<Object> return_value =
        callable(snippets[i].parameter(0), snippets[i].parameter(1),
                 snippets[i].parameter(2))
            .ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *snippets[i].return_value()));
  }
}

TEST_F(RunBytecodeGraphBuilderTest, BytecodeGraphBuilderCreateRestArguments) {
  Isolate* isolate = i_isolate();
  Factory* factory = isolate->factory();

  ExpectedSnippet<3> snippets[] = {
      {"function f(...restArgs) {return restArgs[0];}",
       {factory->NewNumberFromInt(1), factory->NewNumberFromInt(1),
        factory->NewNumberFromInt(2), factory->NewNumberFromInt(3)}},
      {"function f(a, b, ...restArgs) {return restArgs[0];}",
       {factory->NewNumberFromInt(3), factory->NewNumberFromInt(1),
        factory->NewNumberFromInt(2), factory->NewNumberFromInt(3)}},
      {"function f(a, b, ...restArgs) {return arguments[2];}",
       {factory->NewNumberFromInt(3), factory->NewNumberFromInt(1),
        factory->NewNumberFromInt(2), factory->NewNumberFromInt(3)}},
      {"function f(a, ...restArgs) { return restArgs[2];}",
       {factory->undefined_value(), factory->NewNumberFromInt(1),
        factory->NewNumberFromInt(2), factory->NewNumberFromInt(3)}},
      {"function f(a, ...restArgs) { return arguments[0] + restArgs[1];}",
       {factory->NewNumberFromInt(4), factory->NewNumberFromInt(1),
        factory->NewNumberFromInt(2), factory->NewNumberFromInt(3)}},
      {"function inline_func(a, ...restArgs) { return restArgs[0] }"
       "function f(a, b, c) {return inline_func(b, c) + arguments[0];}",
       {factory->NewNumberFromInt(31), factory->NewNumberFromInt(1),
        factory->NewNumberFromInt(2), factory->NewNumberFromInt(30)}},
  };

  for (size_t i = 0; i < arraysize(snippets); i++) {
    base::ScopedVector<char> script(1024);
    SNPrintF(script, "%s\n%s();", snippets[i].code_snippet, kFunctionName);

    BytecodeGraphTester tester(isolate, script.begin());
    auto callable =
        tester.GetCallable<Handle<Object>, Handle<Object>, Handle<Object>>();
    DirectHandle<Object> return_value =
        callable(snippets[i].parameter(0), snippets[i].parameter(1),
                 snippets[i].parameter(2))
            .ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *snippets[i].return_value()));
  }
}

TEST_F(RunBytecodeGraphBuilderTest, BytecodeGraphBuilderRegExpLiterals) {
  Isolate* isolate = i_isolate();
  Factory* factory = isolate->factory();

  ExpectedSnippet<0> snippets[] = {
      {"return /abd/.exec('cccabbdd');", {factory->null_value()}},
      {"return /ab+d/.exec('cccabbdd')[0];", {MakeString("abbd")}},
      {"var a = 3.1414;" REPEAT_256(
           SPACE, "a = 3.1414;") "return /ab+d/.exec('cccabbdd')[0];",
       {MakeString("abbd")}},
      {"return /ab+d/.exec('cccabbdd')[1];", {factory->undefined_value()}},
      {"return /AbC/i.exec('ssaBC')[0];", {MakeString("aBC")}},
      {"return 'ssaBC'.match(/AbC/i)[0];", {MakeString("aBC")}},
      {"return 'ssaBCtAbC'.match(/(AbC)/gi)[1];", {MakeString("AbC")}},
  };

  for (size_t i = 0; i < arraysize(snippets); i++) {
    base::ScopedVector<char> script(4096);
    SNPrintF(script, "function %s() { %s }\n%s();", kFunctionName,
             snippets[i].code_snippet, kFunctionName);

    BytecodeGraphTester tester(isolate, script.begin());
    auto callable = tester.GetCallable<>();
    DirectHandle<Object> return_value = callable().ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *snippets[i].return_value()));
  }
}

TEST_F(RunBytecodeGraphBuilderTest, BytecodeGraphBuilderArrayLiterals) {
  Isolate* isolate = i_isolate();
  Factory* factory = isolate->factory();

  ExpectedSnippet<0> snippets[] = {
      {"return [][0];", {factory->undefined_value()}},
      {"return [1, 3, 2][1];", {factory->NewNumberFromInt(3)}},
      {"var a;" REPEAT_256(SPACE, "a = 9.87;") "return [1, 3, 2][1];",
       {factory->NewNumberFromInt(3)}},
      {"return ['a', 'b', 'c'][2];", {MakeString("c")}},
      {"var a = 100; return [a, a++, a + 2, a + 3][2];",
       {factory->NewNumberFromInt(103)}},
      {"var a = 100; return [a, ++a, a + 2, a + 3][1];",
       {factory->NewNumberFromInt(101)}},
      {"var a = 9.2;" REPEAT_256(
           SPACE, "a = 9.34;") "return [a, ++a, a + 2, a + 3][2];",
       {factory->NewHeapNumber(12.34)}},
      {"return [[1, 2, 3], ['a', 'b', 'c']][1][0];", {MakeString("a")}},
      {"var t = 't'; return [[t, t + 'est'], [1 + t]][0][1];",
       {MakeString("test")}},
      {"var t = 't'; return [[t, t + 'est'], [1 + t]][1][0];",
       {MakeString("1t")}}};

  for (size_t i = 0; i < arraysize(snippets); i++) {
    base::ScopedVector<char> script(4096);
    SNPrintF(script, "function %s() { %s }\n%s();", kFunctionName,
             snippets[i].code_snippet, kFunctionName);

    BytecodeGraphTester tester(isolate, script.begin());
    auto callable = tester.GetCallable<>();
    DirectHandle<Object> return_value = callable().ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *snippets[i].return_value()));
  }
}

TEST_F(RunBytecodeGraphBuilderTest, BytecodeGraphBuilderObjectLiterals) {
  Isolate* isolate = i_isolate();
  Factory* factory = isolate->factory();

  ExpectedSnippet<0> snippets[] = {
      {"return { }.name;", {factory->undefined_value()}},
      {"return { name: 'string', val: 9.2 }.name;", {MakeString("string")}},
      {"var a;\n" REPEAT_256(
           SPACE, "a = 1.23;\n") "return { name: 'string', val: 9.2 }.name;",
       {MakeString("string")}},
      {"return { name: 'string', val: 9.2 }['name'];", {MakeString("string")}},
      {"var a = 15; return { name: 'string', val: a }.val;",
       {factory->NewNumberFromInt(15)}},
      {"var a;" REPEAT_256(
           SPACE, "a = 1.23;") "return { name: 'string', val: a }.val;",
       {factory->NewHeapNumber(1.23)}},
      {"var a = 15; var b = 'val'; return { name: 'string', val: a }[b];",
       {factory->NewNumberFromInt(15)}},
      {"var a = 5; return { val: a, val: a + 1 }.val;",
       {factory->NewNumberFromInt(6)}},
      {"return { func: function() { return 'test' } }.func();",
       {MakeString("test")}},
      {"return { func(a) { return a + 'st'; } }.func('te');",
       {MakeString("test")}},
      {"return { get a() { return 22; } }.a;", {factory->NewNumberFromInt(22)}},
      {"var a = { get b() { return this.x + 't'; },\n"
       "          set b(val) { this.x = val + 's' } };\n"
       "a.b = 'te';\n"
       "return a.b;",
       {MakeString("test")}},
      {"var a = 123; return { 1: a }[1];", {factory->NewNumberFromInt(123)}},
      {"return Object.getPrototypeOf({ __proto__: null });",
       {factory->null_value()}},
      {"var a = 'test'; return { [a]: 1 }.test;",
       {factory->NewNumberFromInt(1)}},
      {"var a = 'test'; return { b: a, [a]: a + 'ing' }['test']",
       {MakeString("testing")}},
      {"var a = 'proto_str';\n"
       "var b = { [a]: 1, __proto__: { var : a } };\n"
       "return Object.getPrototypeOf(b).var",
       {MakeString("proto_str")}},
      {"var n = 'name';\n"
       "return { [n]: 'val', get a() { return 987 } }['a'];",
       {factory->NewNumberFromInt(987)}},
  };

  for (size_t i = 0; i < arraysize(snippets); i++) {
    base::ScopedVector<char> script(4096);
    SNPrintF(script, "function %s() { %s }\n%s();", kFunctionName,
             snippets[i].code_snippet, kFunctionName);
    BytecodeGraphTester tester(isolate, script.begin());
    auto callable = tester.GetCallable<>();
    DirectHandle<Object> return_value = callable().ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *snippets[i].return_value()));
  }
}

TEST_F(RunBytecodeGraphBuilderTest, BytecodeGraphBuilderIf) {
  Isolate* isolate = i_isolate();
  Factory* factory = isolate->factory();

  ExpectedSnippet<1> snippets[] = {
      {"if (p1 > 1) return 1;\n"
       "return -1;",
       {factory->NewNumberFromInt(1), factory->NewNumberFromInt(2)}},
      {"if (p1 > 1) return 1;\n"
       "return -1;",
       {factory->NewNumberFromInt(-1), factory->NewNumberFromInt(1)}},
      {"if (p1 > 1) { return 1; } else { return -1; }",
       {factory->NewNumberFromInt(1), factory->NewNumberFromInt(2)}},
      {"if (p1 > 1) { return 1; } else { return -1; }",
       {factory->NewNumberFromInt(-1), factory->NewNumberFromInt(1)}},
      {"if (p1 > 50) {\n"
       "  return 1;\n"
       "} else if (p1 < 10) {\n"
       "   return 10;\n"
       "} else {\n"
       "   return -10;\n"
       "}",
       {factory->NewNumberFromInt(1), factory->NewNumberFromInt(51)}},
      {"if (p1 > 50) {\n"
       "  return 1;\n"
       "} else if (p1 < 10) {\n"
       "   return 10;\n"
       "} else {\n"
       "   return 100;\n"
       "}",
       {factory->NewNumberFromInt(10), factory->NewNumberFromInt(9)}},
      {"if (p1 > 50) {\n"
       "  return 1;\n"
       "} else if (p1 < 10) {\n"
       "   return 10;\n"
       "} else {\n"
       "   return 100;\n"
       "}",
       {factory->NewNumberFromInt(100), factory->NewNumberFromInt(10)}},
      {"if (p1 >= 0) {\n"
       "   if (p1 > 10) { return 2; } else { return 1; }\n"
       "} else {\n"
       "   if (p1 < -10) { return -2; } else { return -1; }\n"
       "}",
       {factory->NewNumberFromInt(2), factory->NewNumberFromInt(100)}},
      {"if (p1 >= 0) {\n"
       "   if (p1 > 10) { return 2; } else { return 1; }\n"
       "} else {\n"
       "   if (p1 < -10) { return -2; } else { return -1; }\n"
       "}",
       {factory->NewNumberFromInt(1), factory->NewNumberFromInt(10)}},
      {"if (p1 >= 0) {\n"
       "   if (p1 > 10) { return 2; } else { return 1; }\n"
       "} else {\n"
       "   if (p1 < -10) { return -2; } else { return -1; }\n"
       "}",
       {factory->NewNumberFromInt(-2), factory->NewNumberFromInt(-11)}},
      {"if (p1 >= 0) {\n"
       "   if (p1 > 10) { return 2; } else { return 1; }\n"
       "} else {\n"
       "   if (p1 < -10) { return -2; } else { return -1; }\n"
       "}",
       {factory->NewNumberFromInt(-1), factory->NewNumberFromInt(-10)}},
      {"var b = 20, c;"
       "if (p1 >= 0) {\n"
       "   if (b > 0) { c = 2; } else { c = 3; }\n"
       "} else {\n"
       "   if (b < -10) { c = -2; } else { c = -1; }\n"
       "}"
       "return c;",
       {factory->NewNumberFromInt(-1), factory->NewNumberFromInt(-1)}},
      {"var b = 20, c = 10;"
       "if (p1 >= 0) {\n"
       "   if (b < 0) { c = 2; }\n"
       "} else {\n"
       "   if (b < -10) { c = -2; } else { c = -1; }\n"
       "}"
       "return c;",
       {factory->NewNumberFromInt(10), factory->NewNumberFromInt(1)}},
      {"var x = 2, a = 10, b = 20, c, d;"
       "x = 0;"
       "if (a) {\n"
       "   b = x;"
       "   if (b > 0) { c = 2; } else { c = 3; }\n"
       "   x = 4; d = 2;"
       "} else {\n"
       "   d = 3;\n"
       "}"
       "x = d;"
       "function f1() {x}"
       "return x + c;",
       {factory->NewNumberFromInt(5), factory->NewNumberFromInt(-1)}},
  };

  for (size_t i = 0; i < arraysize(snippets); i++) {
    base::ScopedVector<char> script(2048);
    SNPrintF(script, "function %s(p1) { %s };\n%s(0);", kFunctionName,
             snippets[i].code_snippet, kFunctionName);

    BytecodeGraphTester tester(isolate, script.begin());
    auto callable = tester.GetCallable<Handle<Object>>();
    DirectHandle<Object> return_value =
        callable(snippets[i].parameter(0)).ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *snippets[i].return_value()));
  }
}

TEST_F(RunBytecodeGraphBuilderTest, BytecodeGraphBuilderConditionalOperator) {
  Isolate* isolate = i_isolate();
  Factory* factory = isolate->factory();

  ExpectedSnippet<1> snippets[] = {
      {"return (p1 > 1) ? 1 : -1;",
       {factory->NewNumberFromInt(1), factory->NewNumberFromInt(2)}},
      {"return (p1 > 1) ? 1 : -1;",
       {factory->NewNumberFromInt(-1), factory->NewNumberFromInt(0)}},
      {"return (p1 > 50) ? 1 : ((p1 < 10) ? 10 : -10);",
       {factory->NewNumberFromInt(10), factory->NewNumberFromInt(2)}},
      {"return (p1 > 50) ? 1 : ((p1 < 10) ? 10 : -10);",
       {factory->NewNumberFromInt(-10), factory->NewNumberFromInt(20)}},
  };

  for (size_t i = 0; i < arraysize(snippets); i++) {
    base::ScopedVector<char> script(2048);
    SNPrintF(script, "function %s(p1) { %s };\n%s(0);", kFunctionName,
             snippets[i].code_snippet, kFunctionName);

    BytecodeGraphTester tester(isolate, script.begin());
    auto callable = tester.GetCallable<Handle<Object>>();
    DirectHandle<Object> return_value =
        callable(snippets[i].parameter(0)).ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *snippets[i].return_value()));
  }
}

TEST_F(RunBytecodeGraphBuilderTest, BytecodeGraphBuilderSwitch) {
  Isolate* isolate = i_isolate();
  Factory* factory = isolate->factory();

  const char* switch_code =
      "switch (p1) {\n"
      "  case 1: return 0;\n"
      "  case 2: return 1;\n"
      "  case 3:\n"
      "  case 4: return 2;\n"
      "  case 9: break;\n"
      "  default: return 3;\n"
      "}\n"
      "return 9;";

  ExpectedSnippet<1> snippets[] = {
      {switch_code,
       {factory->NewNumberFromInt(0), factory->NewNumberFromInt(1)}},
      {switch_code,
       {factory->NewNumberFromInt(1), factory->NewNumberFromInt(2)}},
      {switch_code,
       {factory->NewNumberFromInt(2), factory->NewNumberFromInt(3)}},
      {switch_code,
       {factory->NewNumberFromInt(2), factory->NewNumberFromInt(4)}},
      {switch_code,
       {factory->NewNumberFromInt(9), factory->NewNumberFromInt(9)}},
      {switch_code,
       {factory->NewNumberFromInt(3), factory->NewNumberFromInt(5)}},
      {switch_code,
       {factory->NewNumberFromInt(3), factory->NewNumberFromInt(6)}},
  };

  for (size_t i = 0; i < arraysize(snippets); i++) {
    base::ScopedVector<char> script(2048);
    SNPrintF(script, "function %s(p1) { %s };\n%s(0);", kFunctionName,
             snippets[i].code_snippet, kFunctionName);

    BytecodeGraphTester tester(isolate, script.begin());
    auto callable = tester.GetCallable<Handle<Object>>();
    DirectHandle<Object> return_value =
        callable(snippets[i].parameter(0)).ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *snippets[i].return_value()));
  }
}

TEST_F(RunBytecodeGraphBuilderTest, BytecodeGraphBuilderSwitchMerge) {
  Isolate* isolate = i_isolate();
  Factory* factory = isolate->factory();

  const char* switch_code =
      "var x = 10;"
      "switch (p1) {\n"
      "  case 1: x = 0;\n"
      "  case 2: x = 1;\n"
      "  case 3:\n"
      "  case 4: x = 2; break;\n"
      "  case 5: x = 3;\n"
      "  case 9: break;\n"
      "  default: x = 4;\n"
      "}\n"
      "return x;";

  ExpectedSnippet<1> snippets[] = {
      {switch_code,
       {factory->NewNumberFromInt(2), factory->NewNumberFromInt(1)}},
      {switch_code,
       {factory->NewNumberFromInt(2), factory->NewNumberFromInt(2)}},
      {switch_code,
       {factory->NewNumberFromInt(2), factory->NewNumberFromInt(3)}},
      {switch_code,
       {factory->NewNumberFromInt(2), factory->NewNumberFromInt(4)}},
      {switch_code,
       {factory->NewNumberFromInt(3), factory->NewNumberFromInt(5)}},
      {switch_code,
       {factory->NewNumberFromInt(10), factory->NewNumberFromInt(9)}},
      {switch_code,
       {factory->NewNumberFromInt(4), factory->NewNumberFromInt(6)}},
  };

  for (size_t i = 0; i < arraysize(snippets); i++) {
    base::ScopedVector<char> script(2048);
    SNPrintF(script, "function %s(p1) { %s };\n%s(0);", kFunctionName,
             snippets[i].code_snippet, kFunctionName);

    BytecodeGraphTester tester(isolate, script.begin());
    auto callable = tester.GetCallable<Handle<Object>>();
    DirectHandle<Object> return_value =
        callable(snippets[i].parameter(0)).ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *snippets[i].return_value()));
  }
}

TEST_F(RunBytecodeGraphBuilderTest, BytecodeGraphBuilderNestedSwitch) {
  Isolate* isolate = i_isolate();
  Factory* factory = isolate->factory();

  const char* switch_code =
      "switch (p1) {\n"
      "  case 0: {"
      "    switch (p2) { case 0: return 0; case
Prompt: 
```
这是目录为v8/test/unittests/compiler/run-bytecode-graph-builder-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/compiler/run-bytecode-graph-builder-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共4部分，请归纳一下它的功能

"""
nnerFunc = function testInner(innerArg) {"
       "   outerVar = outerVar + innerArg; return outerVar;"
       " }"
       "}"
       "var f = new testOuter(10).testinnerFunc;"
       "f(0);",
       {factory->NewNumberFromInt(24), factory->NewNumberFromInt(4)}}};

  for (size_t i = 0; i < arraysize(snippets); i++) {
    base::ScopedVector<char> script(1024);
    SNPrintF(script, "%s", snippets[i].code_snippet);

    BytecodeGraphTester tester(isolate, script.begin(), "*");
    auto callable = tester.GetCallable<Handle<Object>>("f");
    DirectHandle<Object> return_value =
        callable(snippets[i].parameter(0)).ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *snippets[i].return_value()));
  }
}

TEST_F(RunBytecodeGraphBuilderTest,
       BytecodeGraphBuilderCreateArgumentsNoParameters) {
  Isolate* isolate = i_isolate();
  Factory* factory = isolate->factory();

  ExpectedSnippet<0> snippets[] = {
      {"function f() {return arguments[0];}", {factory->undefined_value()}},
      {"function f(a) {return arguments[0];}", {factory->undefined_value()}},
      {"function f() {'use strict'; return arguments[0];}",
       {factory->undefined_value()}},
      {"function f(a) {'use strict'; return arguments[0];}",
       {factory->undefined_value()}},
      {"function f(...restArgs) {return restArgs[0];}",
       {factory->undefined_value()}},
      {"function f(a, ...restArgs) {return restArgs[0];}",
       {factory->undefined_value()}},
  };

  for (size_t i = 0; i < arraysize(snippets); i++) {
    base::ScopedVector<char> script(1024);
    SNPrintF(script, "%s\n%s();", snippets[i].code_snippet, kFunctionName);

    BytecodeGraphTester tester(isolate, script.begin());
    auto callable = tester.GetCallable<>();
    DirectHandle<Object> return_value = callable().ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *snippets[i].return_value()));
  }
}

TEST_F(RunBytecodeGraphBuilderTest, BytecodeGraphBuilderCreateArguments) {
  Isolate* isolate = i_isolate();
  Factory* factory = isolate->factory();

  ExpectedSnippet<3> snippets[] = {
      {"function f(a, b, c) {return arguments[0];}",
       {factory->NewNumberFromInt(1), factory->NewNumberFromInt(1),
        factory->NewNumberFromInt(2), factory->NewNumberFromInt(3)}},
      {"function f(a, b, c) {return arguments[3];}",
       {factory->undefined_value(), factory->NewNumberFromInt(1),
        factory->NewNumberFromInt(2), factory->NewNumberFromInt(3)}},
      {"function f(a, b, c) { b = c; return arguments[1];}",
       {factory->NewNumberFromInt(3), factory->NewNumberFromInt(1),
        factory->NewNumberFromInt(2), factory->NewNumberFromInt(3)}},
      {"function f(a, b, c) {'use strict'; return arguments[0];}",
       {factory->NewNumberFromInt(1), factory->NewNumberFromInt(1),
        factory->NewNumberFromInt(2), factory->NewNumberFromInt(3)}},
      {"function f(a, b, c) {'use strict'; return arguments[3];}",
       {factory->undefined_value(), factory->NewNumberFromInt(1),
        factory->NewNumberFromInt(2), factory->NewNumberFromInt(3)}},
      {"function f(a, b, c) {'use strict'; b = c; return arguments[1];}",
       {factory->NewNumberFromInt(2), factory->NewNumberFromInt(1),
        factory->NewNumberFromInt(2), factory->NewNumberFromInt(3)}},
      {"function inline_func(a, b) { return arguments[0] }"
       "function f(a, b, c) {return inline_func(b, c) + arguments[0];}",
       {factory->NewNumberFromInt(3), factory->NewNumberFromInt(1),
        factory->NewNumberFromInt(2), factory->NewNumberFromInt(30)}},
  };

  for (size_t i = 0; i < arraysize(snippets); i++) {
    base::ScopedVector<char> script(1024);
    SNPrintF(script, "%s\n%s();", snippets[i].code_snippet, kFunctionName);

    BytecodeGraphTester tester(isolate, script.begin());
    auto callable =
        tester.GetCallable<Handle<Object>, Handle<Object>, Handle<Object>>();
    DirectHandle<Object> return_value =
        callable(snippets[i].parameter(0), snippets[i].parameter(1),
                 snippets[i].parameter(2))
            .ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *snippets[i].return_value()));
  }
}

TEST_F(RunBytecodeGraphBuilderTest, BytecodeGraphBuilderCreateRestArguments) {
  Isolate* isolate = i_isolate();
  Factory* factory = isolate->factory();

  ExpectedSnippet<3> snippets[] = {
      {"function f(...restArgs) {return restArgs[0];}",
       {factory->NewNumberFromInt(1), factory->NewNumberFromInt(1),
        factory->NewNumberFromInt(2), factory->NewNumberFromInt(3)}},
      {"function f(a, b, ...restArgs) {return restArgs[0];}",
       {factory->NewNumberFromInt(3), factory->NewNumberFromInt(1),
        factory->NewNumberFromInt(2), factory->NewNumberFromInt(3)}},
      {"function f(a, b, ...restArgs) {return arguments[2];}",
       {factory->NewNumberFromInt(3), factory->NewNumberFromInt(1),
        factory->NewNumberFromInt(2), factory->NewNumberFromInt(3)}},
      {"function f(a, ...restArgs) { return restArgs[2];}",
       {factory->undefined_value(), factory->NewNumberFromInt(1),
        factory->NewNumberFromInt(2), factory->NewNumberFromInt(3)}},
      {"function f(a, ...restArgs) { return arguments[0] + restArgs[1];}",
       {factory->NewNumberFromInt(4), factory->NewNumberFromInt(1),
        factory->NewNumberFromInt(2), factory->NewNumberFromInt(3)}},
      {"function inline_func(a, ...restArgs) { return restArgs[0] }"
       "function f(a, b, c) {return inline_func(b, c) + arguments[0];}",
       {factory->NewNumberFromInt(31), factory->NewNumberFromInt(1),
        factory->NewNumberFromInt(2), factory->NewNumberFromInt(30)}},
  };

  for (size_t i = 0; i < arraysize(snippets); i++) {
    base::ScopedVector<char> script(1024);
    SNPrintF(script, "%s\n%s();", snippets[i].code_snippet, kFunctionName);

    BytecodeGraphTester tester(isolate, script.begin());
    auto callable =
        tester.GetCallable<Handle<Object>, Handle<Object>, Handle<Object>>();
    DirectHandle<Object> return_value =
        callable(snippets[i].parameter(0), snippets[i].parameter(1),
                 snippets[i].parameter(2))
            .ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *snippets[i].return_value()));
  }
}

TEST_F(RunBytecodeGraphBuilderTest, BytecodeGraphBuilderRegExpLiterals) {
  Isolate* isolate = i_isolate();
  Factory* factory = isolate->factory();

  ExpectedSnippet<0> snippets[] = {
      {"return /abd/.exec('cccabbdd');", {factory->null_value()}},
      {"return /ab+d/.exec('cccabbdd')[0];", {MakeString("abbd")}},
      {"var a = 3.1414;" REPEAT_256(
           SPACE, "a = 3.1414;") "return /ab+d/.exec('cccabbdd')[0];",
       {MakeString("abbd")}},
      {"return /ab+d/.exec('cccabbdd')[1];", {factory->undefined_value()}},
      {"return /AbC/i.exec('ssaBC')[0];", {MakeString("aBC")}},
      {"return 'ssaBC'.match(/AbC/i)[0];", {MakeString("aBC")}},
      {"return 'ssaBCtAbC'.match(/(AbC)/gi)[1];", {MakeString("AbC")}},
  };

  for (size_t i = 0; i < arraysize(snippets); i++) {
    base::ScopedVector<char> script(4096);
    SNPrintF(script, "function %s() { %s }\n%s();", kFunctionName,
             snippets[i].code_snippet, kFunctionName);

    BytecodeGraphTester tester(isolate, script.begin());
    auto callable = tester.GetCallable<>();
    DirectHandle<Object> return_value = callable().ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *snippets[i].return_value()));
  }
}

TEST_F(RunBytecodeGraphBuilderTest, BytecodeGraphBuilderArrayLiterals) {
  Isolate* isolate = i_isolate();
  Factory* factory = isolate->factory();

  ExpectedSnippet<0> snippets[] = {
      {"return [][0];", {factory->undefined_value()}},
      {"return [1, 3, 2][1];", {factory->NewNumberFromInt(3)}},
      {"var a;" REPEAT_256(SPACE, "a = 9.87;") "return [1, 3, 2][1];",
       {factory->NewNumberFromInt(3)}},
      {"return ['a', 'b', 'c'][2];", {MakeString("c")}},
      {"var a = 100; return [a, a++, a + 2, a + 3][2];",
       {factory->NewNumberFromInt(103)}},
      {"var a = 100; return [a, ++a, a + 2, a + 3][1];",
       {factory->NewNumberFromInt(101)}},
      {"var a = 9.2;" REPEAT_256(
           SPACE, "a = 9.34;") "return [a, ++a, a + 2, a + 3][2];",
       {factory->NewHeapNumber(12.34)}},
      {"return [[1, 2, 3], ['a', 'b', 'c']][1][0];", {MakeString("a")}},
      {"var t = 't'; return [[t, t + 'est'], [1 + t]][0][1];",
       {MakeString("test")}},
      {"var t = 't'; return [[t, t + 'est'], [1 + t]][1][0];",
       {MakeString("1t")}}};

  for (size_t i = 0; i < arraysize(snippets); i++) {
    base::ScopedVector<char> script(4096);
    SNPrintF(script, "function %s() { %s }\n%s();", kFunctionName,
             snippets[i].code_snippet, kFunctionName);

    BytecodeGraphTester tester(isolate, script.begin());
    auto callable = tester.GetCallable<>();
    DirectHandle<Object> return_value = callable().ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *snippets[i].return_value()));
  }
}

TEST_F(RunBytecodeGraphBuilderTest, BytecodeGraphBuilderObjectLiterals) {
  Isolate* isolate = i_isolate();
  Factory* factory = isolate->factory();

  ExpectedSnippet<0> snippets[] = {
      {"return { }.name;", {factory->undefined_value()}},
      {"return { name: 'string', val: 9.2 }.name;", {MakeString("string")}},
      {"var a;\n" REPEAT_256(
           SPACE, "a = 1.23;\n") "return { name: 'string', val: 9.2 }.name;",
       {MakeString("string")}},
      {"return { name: 'string', val: 9.2 }['name'];", {MakeString("string")}},
      {"var a = 15; return { name: 'string', val: a }.val;",
       {factory->NewNumberFromInt(15)}},
      {"var a;" REPEAT_256(
           SPACE, "a = 1.23;") "return { name: 'string', val: a }.val;",
       {factory->NewHeapNumber(1.23)}},
      {"var a = 15; var b = 'val'; return { name: 'string', val: a }[b];",
       {factory->NewNumberFromInt(15)}},
      {"var a = 5; return { val: a, val: a + 1 }.val;",
       {factory->NewNumberFromInt(6)}},
      {"return { func: function() { return 'test' } }.func();",
       {MakeString("test")}},
      {"return { func(a) { return a + 'st'; } }.func('te');",
       {MakeString("test")}},
      {"return { get a() { return 22; } }.a;", {factory->NewNumberFromInt(22)}},
      {"var a = { get b() { return this.x + 't'; },\n"
       "          set b(val) { this.x = val + 's' } };\n"
       "a.b = 'te';\n"
       "return a.b;",
       {MakeString("test")}},
      {"var a = 123; return { 1: a }[1];", {factory->NewNumberFromInt(123)}},
      {"return Object.getPrototypeOf({ __proto__: null });",
       {factory->null_value()}},
      {"var a = 'test'; return { [a]: 1 }.test;",
       {factory->NewNumberFromInt(1)}},
      {"var a = 'test'; return { b: a, [a]: a + 'ing' }['test']",
       {MakeString("testing")}},
      {"var a = 'proto_str';\n"
       "var b = { [a]: 1, __proto__: { var : a } };\n"
       "return Object.getPrototypeOf(b).var",
       {MakeString("proto_str")}},
      {"var n = 'name';\n"
       "return { [n]: 'val', get a() { return 987 } }['a'];",
       {factory->NewNumberFromInt(987)}},
  };

  for (size_t i = 0; i < arraysize(snippets); i++) {
    base::ScopedVector<char> script(4096);
    SNPrintF(script, "function %s() { %s }\n%s();", kFunctionName,
             snippets[i].code_snippet, kFunctionName);
    BytecodeGraphTester tester(isolate, script.begin());
    auto callable = tester.GetCallable<>();
    DirectHandle<Object> return_value = callable().ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *snippets[i].return_value()));
  }
}

TEST_F(RunBytecodeGraphBuilderTest, BytecodeGraphBuilderIf) {
  Isolate* isolate = i_isolate();
  Factory* factory = isolate->factory();

  ExpectedSnippet<1> snippets[] = {
      {"if (p1 > 1) return 1;\n"
       "return -1;",
       {factory->NewNumberFromInt(1), factory->NewNumberFromInt(2)}},
      {"if (p1 > 1) return 1;\n"
       "return -1;",
       {factory->NewNumberFromInt(-1), factory->NewNumberFromInt(1)}},
      {"if (p1 > 1) { return 1; } else { return -1; }",
       {factory->NewNumberFromInt(1), factory->NewNumberFromInt(2)}},
      {"if (p1 > 1) { return 1; } else { return -1; }",
       {factory->NewNumberFromInt(-1), factory->NewNumberFromInt(1)}},
      {"if (p1 > 50) {\n"
       "  return 1;\n"
       "} else if (p1 < 10) {\n"
       "   return 10;\n"
       "} else {\n"
       "   return -10;\n"
       "}",
       {factory->NewNumberFromInt(1), factory->NewNumberFromInt(51)}},
      {"if (p1 > 50) {\n"
       "  return 1;\n"
       "} else if (p1 < 10) {\n"
       "   return 10;\n"
       "} else {\n"
       "   return 100;\n"
       "}",
       {factory->NewNumberFromInt(10), factory->NewNumberFromInt(9)}},
      {"if (p1 > 50) {\n"
       "  return 1;\n"
       "} else if (p1 < 10) {\n"
       "   return 10;\n"
       "} else {\n"
       "   return 100;\n"
       "}",
       {factory->NewNumberFromInt(100), factory->NewNumberFromInt(10)}},
      {"if (p1 >= 0) {\n"
       "   if (p1 > 10) { return 2; } else { return 1; }\n"
       "} else {\n"
       "   if (p1 < -10) { return -2; } else { return -1; }\n"
       "}",
       {factory->NewNumberFromInt(2), factory->NewNumberFromInt(100)}},
      {"if (p1 >= 0) {\n"
       "   if (p1 > 10) { return 2; } else { return 1; }\n"
       "} else {\n"
       "   if (p1 < -10) { return -2; } else { return -1; }\n"
       "}",
       {factory->NewNumberFromInt(1), factory->NewNumberFromInt(10)}},
      {"if (p1 >= 0) {\n"
       "   if (p1 > 10) { return 2; } else { return 1; }\n"
       "} else {\n"
       "   if (p1 < -10) { return -2; } else { return -1; }\n"
       "}",
       {factory->NewNumberFromInt(-2), factory->NewNumberFromInt(-11)}},
      {"if (p1 >= 0) {\n"
       "   if (p1 > 10) { return 2; } else { return 1; }\n"
       "} else {\n"
       "   if (p1 < -10) { return -2; } else { return -1; }\n"
       "}",
       {factory->NewNumberFromInt(-1), factory->NewNumberFromInt(-10)}},
      {"var b = 20, c;"
       "if (p1 >= 0) {\n"
       "   if (b > 0) { c = 2; } else { c = 3; }\n"
       "} else {\n"
       "   if (b < -10) { c = -2; } else { c = -1; }\n"
       "}"
       "return c;",
       {factory->NewNumberFromInt(-1), factory->NewNumberFromInt(-1)}},
      {"var b = 20, c = 10;"
       "if (p1 >= 0) {\n"
       "   if (b < 0) { c = 2; }\n"
       "} else {\n"
       "   if (b < -10) { c = -2; } else { c = -1; }\n"
       "}"
       "return c;",
       {factory->NewNumberFromInt(10), factory->NewNumberFromInt(1)}},
      {"var x = 2, a = 10, b = 20, c, d;"
       "x = 0;"
       "if (a) {\n"
       "   b = x;"
       "   if (b > 0) { c = 2; } else { c = 3; }\n"
       "   x = 4; d = 2;"
       "} else {\n"
       "   d = 3;\n"
       "}"
       "x = d;"
       "function f1() {x}"
       "return x + c;",
       {factory->NewNumberFromInt(5), factory->NewNumberFromInt(-1)}},
  };

  for (size_t i = 0; i < arraysize(snippets); i++) {
    base::ScopedVector<char> script(2048);
    SNPrintF(script, "function %s(p1) { %s };\n%s(0);", kFunctionName,
             snippets[i].code_snippet, kFunctionName);

    BytecodeGraphTester tester(isolate, script.begin());
    auto callable = tester.GetCallable<Handle<Object>>();
    DirectHandle<Object> return_value =
        callable(snippets[i].parameter(0)).ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *snippets[i].return_value()));
  }
}

TEST_F(RunBytecodeGraphBuilderTest, BytecodeGraphBuilderConditionalOperator) {
  Isolate* isolate = i_isolate();
  Factory* factory = isolate->factory();

  ExpectedSnippet<1> snippets[] = {
      {"return (p1 > 1) ? 1 : -1;",
       {factory->NewNumberFromInt(1), factory->NewNumberFromInt(2)}},
      {"return (p1 > 1) ? 1 : -1;",
       {factory->NewNumberFromInt(-1), factory->NewNumberFromInt(0)}},
      {"return (p1 > 50) ? 1 : ((p1 < 10) ? 10 : -10);",
       {factory->NewNumberFromInt(10), factory->NewNumberFromInt(2)}},
      {"return (p1 > 50) ? 1 : ((p1 < 10) ? 10 : -10);",
       {factory->NewNumberFromInt(-10), factory->NewNumberFromInt(20)}},
  };

  for (size_t i = 0; i < arraysize(snippets); i++) {
    base::ScopedVector<char> script(2048);
    SNPrintF(script, "function %s(p1) { %s };\n%s(0);", kFunctionName,
             snippets[i].code_snippet, kFunctionName);

    BytecodeGraphTester tester(isolate, script.begin());
    auto callable = tester.GetCallable<Handle<Object>>();
    DirectHandle<Object> return_value =
        callable(snippets[i].parameter(0)).ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *snippets[i].return_value()));
  }
}

TEST_F(RunBytecodeGraphBuilderTest, BytecodeGraphBuilderSwitch) {
  Isolate* isolate = i_isolate();
  Factory* factory = isolate->factory();

  const char* switch_code =
      "switch (p1) {\n"
      "  case 1: return 0;\n"
      "  case 2: return 1;\n"
      "  case 3:\n"
      "  case 4: return 2;\n"
      "  case 9: break;\n"
      "  default: return 3;\n"
      "}\n"
      "return 9;";

  ExpectedSnippet<1> snippets[] = {
      {switch_code,
       {factory->NewNumberFromInt(0), factory->NewNumberFromInt(1)}},
      {switch_code,
       {factory->NewNumberFromInt(1), factory->NewNumberFromInt(2)}},
      {switch_code,
       {factory->NewNumberFromInt(2), factory->NewNumberFromInt(3)}},
      {switch_code,
       {factory->NewNumberFromInt(2), factory->NewNumberFromInt(4)}},
      {switch_code,
       {factory->NewNumberFromInt(9), factory->NewNumberFromInt(9)}},
      {switch_code,
       {factory->NewNumberFromInt(3), factory->NewNumberFromInt(5)}},
      {switch_code,
       {factory->NewNumberFromInt(3), factory->NewNumberFromInt(6)}},
  };

  for (size_t i = 0; i < arraysize(snippets); i++) {
    base::ScopedVector<char> script(2048);
    SNPrintF(script, "function %s(p1) { %s };\n%s(0);", kFunctionName,
             snippets[i].code_snippet, kFunctionName);

    BytecodeGraphTester tester(isolate, script.begin());
    auto callable = tester.GetCallable<Handle<Object>>();
    DirectHandle<Object> return_value =
        callable(snippets[i].parameter(0)).ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *snippets[i].return_value()));
  }
}

TEST_F(RunBytecodeGraphBuilderTest, BytecodeGraphBuilderSwitchMerge) {
  Isolate* isolate = i_isolate();
  Factory* factory = isolate->factory();

  const char* switch_code =
      "var x = 10;"
      "switch (p1) {\n"
      "  case 1: x = 0;\n"
      "  case 2: x = 1;\n"
      "  case 3:\n"
      "  case 4: x = 2; break;\n"
      "  case 5: x = 3;\n"
      "  case 9: break;\n"
      "  default: x = 4;\n"
      "}\n"
      "return x;";

  ExpectedSnippet<1> snippets[] = {
      {switch_code,
       {factory->NewNumberFromInt(2), factory->NewNumberFromInt(1)}},
      {switch_code,
       {factory->NewNumberFromInt(2), factory->NewNumberFromInt(2)}},
      {switch_code,
       {factory->NewNumberFromInt(2), factory->NewNumberFromInt(3)}},
      {switch_code,
       {factory->NewNumberFromInt(2), factory->NewNumberFromInt(4)}},
      {switch_code,
       {factory->NewNumberFromInt(3), factory->NewNumberFromInt(5)}},
      {switch_code,
       {factory->NewNumberFromInt(10), factory->NewNumberFromInt(9)}},
      {switch_code,
       {factory->NewNumberFromInt(4), factory->NewNumberFromInt(6)}},
  };

  for (size_t i = 0; i < arraysize(snippets); i++) {
    base::ScopedVector<char> script(2048);
    SNPrintF(script, "function %s(p1) { %s };\n%s(0);", kFunctionName,
             snippets[i].code_snippet, kFunctionName);

    BytecodeGraphTester tester(isolate, script.begin());
    auto callable = tester.GetCallable<Handle<Object>>();
    DirectHandle<Object> return_value =
        callable(snippets[i].parameter(0)).ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *snippets[i].return_value()));
  }
}

TEST_F(RunBytecodeGraphBuilderTest, BytecodeGraphBuilderNestedSwitch) {
  Isolate* isolate = i_isolate();
  Factory* factory = isolate->factory();

  const char* switch_code =
      "switch (p1) {\n"
      "  case 0: {"
      "    switch (p2) { case 0: return 0; case 1: return 1; case 2: break; }\n"
      "    return -1;"
      "  }\n"
      "  case 1: {"
      "    switch (p2) { case 0: return 2; case 1: return 3; }\n"
      "  }\n"
      "  case 2: break;"
      "  }\n"
      "return -2;";

  ExpectedSnippet<2> snippets[] = {
      {switch_code,
       {factory->NewNumberFromInt(0), factory->NewNumberFromInt(0),
        factory->NewNumberFromInt(0)}},
      {switch_code,
       {factory->NewNumberFromInt(1), factory->NewNumberFromInt(0),
        factory->NewNumberFromInt(1)}},
      {switch_code,
       {factory->NewNumberFromInt(-1), factory->NewNumberFromInt(0),
        factory->NewNumberFromInt(2)}},
      {switch_code,
       {factory->NewNumberFromInt(-1), factory->NewNumberFromInt(0),
        factory->NewNumberFromInt(3)}},
      {switch_code,
       {factory->NewNumberFromInt(2), factory->NewNumberFromInt(1),
        factory->NewNumberFromInt(0)}},
      {switch_code,
       {factory->NewNumberFromInt(3), factory->NewNumberFromInt(1),
        factory->NewNumberFromInt(1)}},
      {switch_code,
       {factory->NewNumberFromInt(-2), factory->NewNumberFromInt(1),
        factory->NewNumberFromInt(2)}},
      {switch_code,
       {factory->NewNumberFromInt(-2), factory->NewNumberFromInt(2),
        factory->NewNumberFromInt(0)}},
  };

  for (size_t i = 0; i < arraysize(snippets); i++) {
    base::ScopedVector<char> script(2048);
    SNPrintF(script, "function %s(p1, p2) { %s };\n%s(0, 0);", kFunctionName,
             snippets[i].code_snippet, kFunctionName);

    BytecodeGraphTester tester(isolate, script.begin());
    auto callable = tester.GetCallable<Handle<Object>, Handle<Object>>();
    DirectHandle<Object> return_value =
        callable(snippets[i].parameter(0), snippets[i].parameter(1))
            .ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *snippets[i].return_value()));
  }
}

TEST_F(RunBytecodeGraphBuilderTest, BytecodeGraphBuilderBreakableBlocks) {
  Isolate* isolate = i_isolate();
  Factory* factory = isolate->factory();

  ExpectedSnippet<0> snippets[] = {
      {"var x = 0;\n"
       "my_heart: {\n"
       "  x = x + 1;\n"
       "  break my_heart;\n"
       "  x = x + 2;\n"
       "}\n"
       "return x;\n",
       {factory->NewNumberFromInt(1)}},
      {"var sum = 0;\n"
       "outta_here: {\n"
       "  for (var x = 0; x < 10; ++x) {\n"
       "    for (var y = 0; y < 3; ++y) {\n"
       "      ++sum;\n"
       "      if (x + y == 12) { break outta_here; }\n"
       "    }\n"
       "  }\n"
       "}\n"
       "return sum;",
       {factory->NewNumber(30)}},
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

TEST_F(RunBytecodeGraphBuilderTest, BytecodeGraphBuilderWhile) {
  Isolate* isolate = i_isolate();
  Factory* factory = isolate->factory();

  ExpectedSnippet<0> snippets[] = {
      {"var x = 1; while (x < 1) { x *= 100; } return x;",
       {factory->NewNumberFromInt(1)}},
      {"var x = 1, y = 0; while (x < 7) { y += x * x; x += 1; } return y;",
       {factory->NewNumberFromInt(91)}},
      {"var x = 1; while (true) { x += 1; if (x == 10) break; } return x;",
       {factory->NewNumberFromInt(10)}},
      {"var x = 1; while (false) { x += 1; } return x;",
       {factory->NewNumberFromInt(1)}},
      {"var x = 0;\n"
       "while (true) {\n"
       "  while (x < 10) {\n"
       "    x = x * x + 1;\n"
       "  }"
       "  x += 1;\n"
       "  break;\n"
       "}\n"
       "return x;",
       {factory->NewNumberFromInt(27)}},
      {"var x = 1, y = 0;\n"
       "while (x < 7) {\n"
       "  x += 1;\n"
       "  if (x == 2) continue;\n"
       "  if (x == 3) continue;\n"
       "  y += x * x;\n"
       "  if (x == 4) break;\n"
       "}\n"
       "return y;",
       {factory->NewNumberFromInt(16)}}};

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

TEST_F(RunBytecodeGraphBuilderTest, BytecodeGraphBuilderDo) {
  Isolate* isolate = i_isolate();
  Factory* factory = isolate->factory();

  ExpectedSnippet<0> snippets[] = {
      {"var x = 1; do { x *= 100; } while (x < 100); return x;",
       {factory->NewNumberFromInt(100)}},
      {"var x = 1; do { x = x * x + 1; } while (x < 7) return x;",
       {factory->NewNumberFromInt(26)}},
      {"var x = 1; do { x += 1; } while (false); return x;",
       {factory->NewNumberFromInt(2)}},
      {"var x = 1, y = 0;\n"
       "do {\n"
       "  x += 1;\n"
       "  if (x == 2) continue;\n"
       "  if (x == 3) continue;\n"
       "  y += x * x;\n"
       "  if (x == 4) break;\n"
       "} while (x < 7);\n"
       "return y;",
       {factory->NewNumberFromInt(16)}},
      {"var x = 0, sum = 0;\n"
       "do {\n"
       "  do {\n"
       "    ++sum;\n"
       "    ++x;\n"
       "  } while (sum < 1 || x < 2)\n"
       "  do {\n"
       "    ++x;\n"
       "  } while (x < 1)\n"
       "} while (sum < 3)\n"
       "return sum;",
       {factory->NewNumber(3)}}};

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

TEST_F(RunBytecodeGraphBuilderTest, BytecodeGraphBuilderFor) {
  Isolate* isolate = i_isolate();
  Factory* factory = isolate->factory();

  ExpectedSnippet<0> snippets[] = {
      {"for (var x = 0;; x = 2 * x + 1) { if (x > 10) return x; }",
       {factory->NewNumberFromInt(15)}},
      {"for (var x = 0; true; x = 2 * x + 1) { if (x > 100) return x; }",
       {factory->NewNumberFromInt(127)}},
      {"for (var x = 0; false; x = 2 * x + 1) { if (x > 100) return x; } "
       "return 0;",
       {factory->NewNumberFromInt(0)}},
      {"for (var x = 0; x < 200; x = 2 * x + 1) { x = x; } return x;",
       {factory->NewNumberFromInt(255)}},
      {"for (var x = 0; x < 200; x = 2 * x + 1) {} return x;",
       {factory->NewNumberFromInt(255)}},
      {"var sum = 0;\n"
       "for (var x = 0; x < 200; x += 1) {\n"
       "  if (x % 2) continue;\n"
       "  if (sum > 10) break;\n"
       "  sum += x;\n"
       "}\n"
       "return sum;",
       {factory->NewNumberFromInt(12)}},
      {"var sum = 0;\n"
       "for (var w = 0; w < 2; w++) {\n"
       "  for (var x = 0; x < 200; x += 1) {\n"
       "    if (x % 2) continue;\n"
       "    if (x > 4) break;\n"
       "    sum += x + w;\n"
       "  }\n"
       "}\n"
       "return sum;",
       {factory->NewNumberFromInt(15)}},
      {"var sum = 0;\n"
       "for (var w = 0; w < 2; w++) {\n"
       "  if (w == 1) break;\n"
       "  for (var x = 0; x < 200; x += 1) {\n"
       "    if (x % 2) continue;\n"
       "    if (x > 4) break;\n"
       "    sum += x + w;\n"
       "  }\n"
       "}\n"
       "return sum;",
       {factory->NewNumberFromInt(6)}},
      {"var sum = 0;\n"
       "for (var w = 0; w < 3; w++) {\n"
       "  if (w == 1) continue;\n"
       "  for (var x = 0; x < 200; x += 1) {\n"
       "    if (x % 2) continue;\n"
       "    if (x > 4) break;\n"
       "    sum += x + w;\n"
       "  }\n"
       "}\n"
       "return sum;",
       {factory->NewNumberFromInt(18)}},
      {"var sum = 0;\n"
       "for (var x = 1; x < 10; x += 2) {\n"
       "  for (var y = x; y < x + 2; y++) {\n"
       "    sum += y * y;\n"
       "  }\n"
       "}\n"
       "return sum;",
       {factory->NewNumberFromInt(385)}},
      {"var sum = 0;\n"
       "for (var x = 0; x < 5; x++) {\n"
       "  for (var y = 0; y < 5; y++) {\n"
       "    ++sum;\n"
       "  }\n"
       "}\n"
       "for (var x = 0; x < 5; x++) {\n"
       "  for (var y = 0; y < 5; y++) {\n"
       "    ++sum;\n"
       "  }\n"
       "}\n"
       "return sum;",
       {factory->NewNumberFromInt(50)}},
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

TEST_F(RunBytecodeGraphBuilderTest, BytecodeGraphBuilderForIn) {
  Isolate* isolate = i_isolate();
  Factory* factory = isolate->factory();
  ExpectedSnippet<0> snippets[] = {
      {"var sum = 0;\n"
       "var empty = null;\n"
       "for (var x in empty) { sum++; }\n"
       "return sum;",
       {factory->NewNumberFromInt(0)}},
      {"var sum = 100;\n"
       "var empty = 1;\n"
       "for (var x in empty) { sum++; }\n"
       "return sum;",
       {factory->NewNumberFromInt(100)}},
      {"for (var x in [ 10, 20, 30 ]) {}\n"
       "return 2;",
       {factory->NewNumberFromInt(2)}},
      {"var last = 0;\n"
       "for (var x in [ 10, 20, 30 ]) {\n"
       "  last = x;\n"
       "}\n"
       "return +last;",
       {factory->NewNumberFromInt(2)}},
      {"var first = -1;\n"
       "for (var x in [ 10, 20, 30 ]) {\n"
       "  first = +x;\n"
       "  if (first > 0) break;\n"
       "}\n"
       "return first;",
       {factory->NewNumberFromInt(1)}},
      {"var first = -1;\n"
       "for (var x in [ 10, 20, 30 ]) {\n"
       "  if (first >= 0) continue;\n"
       "  first = x;\n"
       "}\n"
       "return +first;",
       {factory->NewNumberFromInt(0)}},
      {"var sum = 0;\n"
       "for (var x in [ 10, 20, 30 ]) {\n"
       "  for (var y in [ 11, 22, 33, 44, 55, 66, 77 ]) {\n"
       "    sum += 1;\n"
       "  }\n"
       "}\n"
       "return sum;",
       {factory->NewNumberFromInt(21)}},
      {"var sum = 0;\n"
       "for (var x in [ 10, 20, 30 ]) {\n"
       "  for (var y in [ 11, 22, 33, 44, 55, 66, 77 ]) {\n"
       "    if (sum == 7) break;\n"
       "    if (sum == 6) continue;\n"
       "    sum += 1;\n"
       "  }\n"
       "}\n"
       "return sum;",
       {factory->NewNumberFromInt(6)}},
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

TEST_F(RunBytecodeGraphBuilderTest, BytecodeGraphBuilderForOf) {
  Isolate* isolate = i_isolate();
  ExpectedSnippet<0> snippets[] = {
      {"  var r = 0;\n"
       "  for (var a of [0,6,7,9]) { r += a; }\n"
       "  return r;\n",
       {handle(Smi::FromInt(22), isolate)}},
      {"  var r = '';\n"
       "  for (var a of 'foobar') { r = a + r; }\n"
       "  return r;\n",
       {MakeString("raboof")}},
      {"  var a = [1, 2, 3];\n"
       "  a.name = 4;\n"
       "  var r = 0;\n"
       "  for (var x of a) { r += x; }\n"
       "  return r;\n",
       {handle(Smi::FromInt(6), isolate)}},
      {"  var r = '';\n"
       "  var data = [1, 2, 3]; \n"
       "  for (a of data) { delete data[0]; r += a; } return r;",
       {MakeString("123")}},
      {"  var r = '';\n"
       "  var data = [1, 2, 3]; \n"
       "  for (a of data) { delete data[2]; r += a; } return r;",
       {MakeString("12undefined")}},
      {"  var r = '';\n"
       "  var data = [1, 2, 3]; \n"
       "  for (a of data) { delete data; r += a; } return r;",
       {MakeString("123")}},
      {"  var r = '';\n"
       "  var input = 'foobar';\n"
       "  for (var a of input) {\n"
       "    if (a == 'b') break;\n"
       " 
"""


```