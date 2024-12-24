Response: The user wants me to summarize the functionality of a C++ source code file for testing the bytecode graph builder in V8. This is the second part of the file.

I need to:
1. Understand the purpose of the code snippets in this part of the file.
2. Identify the JavaScript features being tested.
3. Provide a general description of the file's role.
4. Give an example in JavaScript to illustrate the testing.

Based on the content, it seems this part of the file continues testing various JavaScript language features by compiling them to bytecode and executing them.
这个C++源代码文件（`run-bytecode-graph-builder-unittest.cc`）是V8 JavaScript引擎的一部分，专门用于测试**字节码图构建器**的功能。作为第二部分，它延续了第一部分的工作，通过编写一系列的JavaScript代码片段，然后使用`BytecodeGraphTester`来编译和执行这些代码，并验证其执行结果是否与预期一致。

具体来说，这部分代码测试了以下JavaScript语言特性：

* **`with` 语句**:  测试 `with` 语句创建的作用域以及对变量的访问。
* **`const` 和 `let` 声明**: 测试块级作用域的常量和变量声明，包括声明、赋值和查找。
* **非法 `const` 声明**: 测试在严格和非严格模式下，对 `const` 变量进行非法操作时是否会抛出预期的错误。
* **`debugger` 语句**: 测试 `debugger` 语句是否能够触发断点。

如果这些功能与JavaScript的功能有关系，我们可以用JavaScript举例说明。例如，针对 `const` 和 `let` 声明的测试：

```javascript
function testConstLet() {
  const x = 3;
  console.log(x); // 输出 3

  let y = 10;
  y = y + 20;
  console.log(y); // 输出 30

  // 下面的代码在运行时会抛出错误，因为不能给常量重新赋值
  // x = 4;

  if (true) {
    let blockScoped = 5;
    console.log(blockScoped); // 输出 5
  }
  // console.log(blockScoped); // 这里会报错，因为 blockScoped 是块级作用域

  return x + y;
}

testConstLet();
```

在这个JavaScript例子中，我们使用了 `const` 和 `let` 声明变量，并演示了 `const` 声明的常量不能被重新赋值，以及 `let` 声明的变量具有块级作用域的特性。 `run-bytecode-graph-builder-unittest.cc` 中的相关测试用例就是用来验证V8的字节码图构建器是否能正确处理这些特性，并生成正确的字节码指令。当V8执行这些字节码时，其行为应该与上述JavaScript代码的行为一致。

总而言之，这个文件的主要功能是：**测试V8引擎的字节码图构建器在处理各种JavaScript语法结构（特别是涉及到作用域、声明和调试相关的特性）时是否正确，确保生成的字节码能够按照JavaScript语言规范执行。**

Prompt: 
```
这是目录为v8/test/unittests/compiler/run-bytecode-graph-builder-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共2部分，请归纳一下它的功能

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
       "    r += a;\n"
       "  }\n"
       "  return r;\n",
       {MakeString("foo")}},
      {"  var r = '';\n"
       "  var input = 'foobar';\n"
       "  for (var a of input) {\n"
       "    if (a == 'b') continue;\n"
       "    r += a;\n"
       "  }\n"
       "  return r;\n",
       {MakeString("fooar")}},
      {"  var r = '';\n"
       "  var data = [1, 2, 3, 4]; \n"
       "  for (a of data) { data[2] = 567; r += a; }\n"
       "  return r;\n",
       {MakeString("125674")}},
      {"  var r = '';\n"
       "  var data = [1, 2, 3, 4]; \n"
       "  for (a of data) { data[4] = 567; r += a; }\n"
       "  return r;\n",
       {MakeString("1234567")}},
      {"  var r = '';\n"
       "  var data = [1, 2, 3, 4]; \n"
       "  for (a of data) { data[5] = 567; r += a; }\n"
       "  return r;\n",
       {MakeString("1234undefined567")}},
      {"  var r = '';\n"
       "  var obj = new Object();\n"
       "  obj[Symbol.iterator] = function() { return {\n"
       "    index: 3,\n"
       "    data: ['a', 'b', 'c', 'd'],"
       "    next: function() {"
       "      return {"
       "        done: this.index == -1,\n"
       "        value: this.index < 0 ? undefined : this.data[this.index--]\n"
       "      }\n"
       "    }\n"
       "    }}\n"
       "  for (a of obj) { r += a }\n"
       "  return r;\n",
       {MakeString("dcba")}},
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

SHARD_TEST_BY_4(JumpWithConstantsAndWideConstants)

TEST_F(RunBytecodeGraphBuilderTest, BytecodeGraphBuilderWithStatement) {
  Isolate* isolate = i_isolate();

  ExpectedSnippet<0> snippets[] = {
      {"with({x:42}) return x;", {handle(Smi::FromInt(42), isolate)}},
      {"with({}) { var y = 10; return y;}",
       {handle(Smi::FromInt(10), isolate)}},
      {"var y = {x:42};"
       " function inner() {"
       "   var x = 20;"
       "   with(y) return x;"
       "}"
       "return inner();",
       {handle(Smi::FromInt(42), isolate)}},
      {"var y = {x:42};"
       " function inner(o) {"
       "   var x = 20;"
       "   with(o) return x;"
       "}"
       "return inner(y);",
       {handle(Smi::FromInt(42), isolate)}},
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

TEST_F(RunBytecodeGraphBuilderTest, BytecodeGraphBuilderConstDeclaration) {
  Isolate* isolate = i_isolate();
  Factory* factory = isolate->factory();

  ExpectedSnippet<0> snippets[] = {
      {"const x = 3; return x;", {handle(Smi::FromInt(3), isolate)}},
      {"let x = 10; x = x + 20; return x;",
       {handle(Smi::FromInt(30), isolate)}},
      {"let x = 10; x = 20; return x;", {handle(Smi::FromInt(20), isolate)}},
      {"let x; x = 20; return x;", {handle(Smi::FromInt(20), isolate)}},
      {"let x; return x;", {factory->undefined_value()}},
      {"var x = 10; { let x = 30; } return x;",
       {handle(Smi::FromInt(10), isolate)}},
      {"let x = 10; { let x = 20; } return x;",
       {handle(Smi::FromInt(10), isolate)}},
      {"var x = 10; eval('let x = 20;'); return x;",
       {handle(Smi::FromInt(10), isolate)}},
      {"var x = 10; eval('const x = 20;'); return x;",
       {handle(Smi::FromInt(10), isolate)}},
      {"var x = 10; { const x = 20; } return x;",
       {handle(Smi::FromInt(10), isolate)}},
      {"var x = 10; { const x = 20; return x;} return -1;",
       {handle(Smi::FromInt(20), isolate)}},
      {"var a = 10;\n"
       "for (var i = 0; i < 10; ++i) {\n"
       " const x = i;\n"  // const declarations are block scoped.
       " a = a + x;\n"
       "}\n"
       "return a;\n",
       {handle(Smi::FromInt(55), isolate)}},
  };

  // Tests for sloppy mode.
  for (size_t i = 0; i < arraysize(snippets); i++) {
    base::ScopedVector<char> script(1024);
    SNPrintF(script, "function %s() { %s }\n%s();", kFunctionName,
             snippets[i].code_snippet, kFunctionName);

    BytecodeGraphTester tester(isolate, script.begin());
    auto callable = tester.GetCallable<>();
    DirectHandle<Object> return_value = callable().ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *snippets[i].return_value()));
  }

  // Tests for strict mode.
  for (size_t i = 0; i < arraysize(snippets); i++) {
    base::ScopedVector<char> script(1024);
    SNPrintF(script, "function %s() {'use strict'; %s }\n%s();", kFunctionName,
             snippets[i].code_snippet, kFunctionName);

    BytecodeGraphTester tester(isolate, script.begin());
    auto callable = tester.GetCallable<>();
    DirectHandle<Object> return_value = callable().ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *snippets[i].return_value()));
  }
}

TEST_F(RunBytecodeGraphBuilderTest,
       BytecodeGraphBuilderConstDeclarationLookupSlots) {
  Isolate* isolate = i_isolate();
  Factory* factory = isolate->factory();

  ExpectedSnippet<0> snippets[] = {
      {"const x = 3; function f1() {return x;}; return x;",
       {handle(Smi::FromInt(3), isolate)}},
      {"let x = 10; x = x + 20; function f1() {return x;}; return x;",
       {handle(Smi::FromInt(30), isolate)}},
      {"let x; x = 20; function f1() {return x;}; return x;",
       {handle(Smi::FromInt(20), isolate)}},
      {"let x; function f1() {return x;}; return x;",
       {factory->undefined_value()}},
  };

  // Tests for sloppy mode.
  for (size_t i = 0; i < arraysize(snippets); i++) {
    base::ScopedVector<char> script(1024);
    SNPrintF(script, "function %s() { %s }\n%s();", kFunctionName,
             snippets[i].code_snippet, kFunctionName);

    BytecodeGraphTester tester(isolate, script.begin());
    auto callable = tester.GetCallable<>();
    DirectHandle<Object> return_value = callable().ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *snippets[i].return_value()));
  }

  // Tests for strict mode.
  for (size_t i = 0; i < arraysize(snippets); i++) {
    base::ScopedVector<char> script(1024);
    SNPrintF(script, "function %s() {'use strict'; %s }\n%s();", kFunctionName,
             snippets[i].code_snippet, kFunctionName);

    BytecodeGraphTester tester(isolate, script.begin());
    auto callable = tester.GetCallable<>();
    DirectHandle<Object> return_value = callable().ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *snippets[i].return_value()));
  }
}

TEST_F(RunBytecodeGraphBuilderTest,
       BytecodeGraphBuilderConstInLookupContextChain) {
  Isolate* isolate = i_isolate();

  const char* prologue =
      "function OuterMost() {\n"
      "  const outerConst = 10;\n"
      "  let outerLet = 20;\n"
      "  function Outer() {\n"
      "    function Inner() {\n"
      "      this.innerFunc = function() { ";
  const char* epilogue =
      "      }\n"
      "    }\n"
      "    this.getInnerFunc ="
      "         function() {return new Inner().innerFunc;}\n"
      "  }\n"
      "  this.getOuterFunc ="
      "     function() {return new Outer().getInnerFunc();}"
      "}\n"
      "var f = new OuterMost().getOuterFunc();\n"
      "f();\n";

  // Tests for let / constant.
  ExpectedSnippet<0> const_decl[] = {
      {"return outerConst;", {handle(Smi::FromInt(10), isolate)}},
      {"return outerLet;", {handle(Smi::FromInt(20), isolate)}},
      {"outerLet = 30; return outerLet;", {handle(Smi::FromInt(30), isolate)}},
      {"var outerLet = 40; return outerLet;",
       {handle(Smi::FromInt(40), isolate)}},
      {"var outerConst = 50; return outerConst;",
       {handle(Smi::FromInt(50), isolate)}},
      {"try { outerConst = 30 } catch(e) { return -1; }",
       {handle(Smi::FromInt(-1), isolate)}}};

  for (size_t i = 0; i < arraysize(const_decl); i++) {
    base::ScopedVector<char> script(1024);
    SNPrintF(script, "%s %s %s", prologue, const_decl[i].code_snippet,
             epilogue);

    BytecodeGraphTester tester(isolate, script.begin(), "*");
    auto callable = tester.GetCallable<>();
    DirectHandle<Object> return_value = callable().ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *const_decl[i].return_value()));
  }
}

TEST_F(RunBytecodeGraphBuilderTest,
       BytecodeGraphBuilderIllegalConstDeclaration) {
  Isolate* isolate = i_isolate();

  ExpectedSnippet<0, const char*> illegal_const_decl[] = {
      {"const x = x = 10 + 3; return x;",
       {"Uncaught ReferenceError: Cannot access 'x' before initialization"}},
      {"const x = 10; x = 20; return x;",
       {"Uncaught TypeError: Assignment to constant variable."}},
      {"const x = 10; { x = 20; } return x;",
       {"Uncaught TypeError: Assignment to constant variable."}},
      {"const x = 10; eval('x = 20;'); return x;",
       {"Uncaught TypeError: Assignment to constant variable."}},
      {"let x = x + 10; return x;",
       {"Uncaught ReferenceError: Cannot access 'x' before initialization"}},
      {"'use strict'; (function f1() { f1 = 123; })() ",
       {"Uncaught TypeError: Assignment to constant variable."}},
  };

  // Tests for sloppy mode.
  for (size_t i = 0; i < arraysize(illegal_const_decl); i++) {
    base::ScopedVector<char> script(1024);
    SNPrintF(script, "function %s() { %s }\n%s();", kFunctionName,
             illegal_const_decl[i].code_snippet, kFunctionName);

    BytecodeGraphTester tester(isolate, script.begin());
    v8::Local<v8::String> message = tester.CheckThrowsReturnMessage()->Get();
    v8::Local<v8::String> expected_string =
        NewString(illegal_const_decl[i].return_value());
    CHECK(message->Equals(v8_isolate()->GetCurrentContext(), expected_string)
              .FromJust());
  }

  // Tests for strict mode.
  for (size_t i = 0; i < arraysize(illegal_const_decl); i++) {
    base::ScopedVector<char> script(1024);
    SNPrintF(script, "function %s() {'use strict'; %s }\n%s();", kFunctionName,
             illegal_const_decl[i].code_snippet, kFunctionName);

    BytecodeGraphTester tester(isolate, script.begin());
    v8::Local<v8::String> message = tester.CheckThrowsReturnMessage()->Get();
    v8::Local<v8::String> expected_string =
        NewString(illegal_const_decl[i].return_value());
    CHECK(message->Equals(v8_isolate()->GetCurrentContext(), expected_string)
              .FromJust());
  }
}

class CountBreakDebugDelegate : public v8::debug::DebugDelegate {
 public:
  void BreakProgramRequested(v8::Local<v8::Context> paused_context,
                             const std::vector<int>&,
                             v8::debug::BreakReasons break_reasons) override {
    debug_break_count++;
  }
  int debug_break_count = 0;
};

TEST_F(RunBytecodeGraphBuilderTest, BytecodeGraphBuilderDebuggerStatement) {
  CountBreakDebugDelegate delegate;
  Isolate* isolate = i_isolate();

  v8::debug::SetDebugDelegate(v8_isolate(), &delegate);

  ExpectedSnippet<0> snippet = {
      "function f() {"
      "  debugger;"
      "}"
      "f();",
      {isolate->factory()->undefined_value()}};

  BytecodeGraphTester tester(isolate, snippet.code_snippet);
  auto callable = tester.GetCallable<>();
  Handle<Object> return_value = callable().ToHandleChecked();

  v8::debug::SetDebugDelegate(v8_isolate(), nullptr);
  CHECK(return_value.is_identical_to(snippet.return_value()));
  CHECK_EQ(2, delegate.debug_break_count);
}

#undef SHARD_TEST_BY_2
#undef SHARD_TEST_BY_4
#undef SPACE
#undef REPEAT_2
#undef REPEAT_4
#undef REPEAT_8
#undef REPEAT_16
#undef REPEAT_32
#undef REPEAT_64
#undef REPEAT_128
#undef REPEAT_256
#undef REPEAT_127

}  // namespace compiler
}  // namespace internal
}  // namespace v8

"""


```