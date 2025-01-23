Response:
Let's break down the thought process for analyzing this code snippet and generating the summary.

1. **Understand the Goal:** The request asks for a functional summary of a V8 unit test file, along with specific details like potential Torque usage, JavaScript relevance with examples, logical inference, common errors, and its place within a larger sequence.

2. **Initial Scan for Keywords:**  A quick scan reveals key terms like `TEST_F`, `ParsingTest`, `ParseProgram`, `SuperCall`, `SuperNew`, `MethodDefinition`, `ClassExpression`, `ClassDeclaration`, `ClassBody`, `ClassPropertyName`, `StaticClassFields`, `ClassFields`, `PrivateMethods`, `PrivateAutoAccessorsAndFields`, and `PublicAutoAccessors`. These strongly suggest the file focuses on testing the V8 parser's ability to correctly handle various JavaScript syntax constructs, particularly those related to classes and methods.

3. **Identify Core Testing Areas:** Group the tests by their `TEST_F` names to identify the main features being tested:
    * Parsing general programs (failure cases with modules)
    * `super()` calls in constructors and methods (success and error cases)
    * `new super.x` expressions (success and error cases)
    * Incorrect usage of `super` outside of methods/accessors/constructors.
    * Different forms of method definitions in object literals (names, strict mode parameters, `eval`/`arguments`, duplicate properties).
    * Class expressions and declarations.
    * Various valid class body syntax (methods, getters, setters, static members, async methods, etc.).
    * Valid names for class properties.
    * Static and instance class fields (public).
    * Private methods and their various forms (getters, setters, async, etc.).
    * Combinations of private methods and fields.
    * Public and private auto-accessors (with the `js_decorators` flag).
    * Error cases for private methods.
    * Private members within object literals.

4. **Determine Torque Relevance:** The prompt explicitly asks about `.tq` files. The filename `parsing-unittest.cc` indicates a C++ source file. Therefore, it's *not* a Torque file.

5. **Establish JavaScript Relevance and Provide Examples:**  Since the tests are about *parsing* JavaScript syntax, the connection is direct. For each major testing area, think of a simple JavaScript example demonstrating the feature being tested. For instance:
    * `super()`:  `class A {} class B extends A { constructor() { super(); } }`
    * `new super.x`: `class A { method() { new super.prop; } }`
    * Method definitions: `{ myMethod() {} }`
    * Class declarations: `class MyClass {}`
    * Class fields: `class MyClass { myField = 0; }`
    * Private methods: `class MyClass { #privateMethod() {} }`

6. **Address Logical Inference (Input/Output):** The tests are designed to check if the parser *correctly* identifies valid and invalid syntax. The "input" is the code snippet being tested. The "output" is either success (no parsing error) or failure (a parsing error is detected). For example, an input of `"class C { constructor() { super(); } }"` will result in a parsing error because `super()` is called in a class that doesn't extend another class.

7. **Identify Common Programming Errors:**  The error cases in the tests often highlight common mistakes developers might make:
    * Calling `super()` outside a constructor of a derived class.
    * Calling `super` where it's not allowed (e.g., outside methods/accessors).
    * Using reserved words like `eval` or `arguments` as parameter names in strict mode.
    * Duplicating property names in object literals (in strict mode).
    * Incorrect syntax for class fields or private methods.

8. **Synthesize the Overall Function:** Combine the individual testing areas into a concise summary. Emphasize that this file is part of V8's unit tests, specifically focusing on the parser and its ability to handle various JavaScript syntax features, particularly those related to ES6 classes and later additions (private methods, class fields, auto-accessors).

9. **Address the "Part 7 of 15" Aspect:** Acknowledge that this is a segment of a larger set of tests. Infer that the complete set of files likely covers a broader range of parser functionalities or different aspects of the parsing process.

10. **Refine and Organize:** Review the generated summary for clarity, accuracy, and completeness. Structure the information logically using headings or bullet points to make it easy to read and understand. Ensure all aspects of the prompt are addressed.

**(Self-Correction during the process):**  Initially, I might just list the `TEST_F` names. However, realizing the prompt asks for *functional* summaries, I would then elaborate on *what* each test group is actually testing. Also, initially, I might forget to explicitly connect the tests back to JavaScript examples. Remembering this requirement would lead me to add the illustrative code snippets. Finally, ensuring the language is clear and avoids overly technical jargon is important for broader understanding.
好的，让我们来分析一下 `v8/test/unittests/parser/parsing-unittest.cc` 这个文件的第 7 部分的功能。

**功能归纳:**

这部分 `parsing-unittest.cc` 文件主要集中在测试 V8 的 JavaScript 解析器对于 **`super` 关键字** 和 **类 (class)** 相关的语法结构的支持和错误处理能力。  它涵盖了以下几个关键方面：

1. **`super()` 的调用**: 测试 `super()` 在构造函数中的正确使用，以及在其他场景下的错误使用（例如，在普通方法、getter/setter 中，或者非派生类中调用）。
2. **`new super.x` 的使用**: 测试 `new super.property` 和 `new super.property()` 表达式在特定上下文中的合法性。
3. **方法定义 (Method Definition)**: 测试对象字面量和类中各种合法的和非法的方法定义方式，包括方法名、参数、以及在严格模式下的限制。
4. **类表达式 (Class Expression) 和类声明 (Class Declaration)**: 测试各种合法的类表达式和类声明的语法。
5. **类体 (Class Body)**: 测试类体中各种成员的定义，例如方法、getter、setter、静态成员、异步方法等。
6. **类属性名 (Class Property Name)**: 测试类中各种合法的属性名称。
7. **静态类字段 (Static Class Fields)** 和 **类字段 (Class Fields)**: 测试 V8 对于提出的类字段语法的支持。
8. **私有方法 (Private Methods)**: 测试 V8 对于提出的私有方法语法的支持。
9. **公共和私有自动访问器 (Public and Private Auto Accessors)**: 测试 V8 对于提出的自动访问器语法的支持 (需要 `js_decorators` flag)。

**关于文件类型:**

`v8/test/unittests/parser/parsing-unittest.cc` 以 `.cc` 结尾，所以它是一个 **C++ 源代码文件**，而不是 Torque 文件。Torque 文件通常以 `.tq` 结尾。

**与 JavaScript 的关系及示例:**

这个 C++ 文件中的测试用例直接对应于 JavaScript 的语法结构。每个 `TEST_F` 函数都包含一组 JavaScript 代码片段，用于测试解析器是否能够正确地解析这些代码，或者在遇到错误时是否能够正确地报告错误。

以下是一些 JavaScript 示例，对应于这部分测试用例所涵盖的功能：

* **`super()` 调用:**

```javascript
class Base {}
class Derived extends Base {
  constructor() {
    super(); // 合法使用
  }
}

class NotDerived {
  constructor() {
    // super(); // 错误使用，在非派生类的构造函数中调用
  }
  method() {
    // super(); // 错误使用，在普通方法中调用
  }
}
```

* **`new super.x` 的使用:**

```javascript
class Base {
  constructor() {
    this.prop = 10;
  }
}

class Derived extends Base {
  method() {
    new super.prop; // 合法使用
    new super.prop(); // 合法使用
    () => new super.prop; // 合法使用
  }
  regularMethod() {
    // new super(); // 错误使用
  }
}
```

* **方法定义:**

```javascript
const obj = {
  myMethod() { /* ... */ },
  'string-key'() { /* ... */ },
  [Symbol('sym')]() { /* ... */ },
  get myGetter() { return 1; },
  set mySetter(value) { /* ... */ }
};
```

* **类表达式和类声明:**

```javascript
// 类声明
class MyClass {}

// 类表达式
const MyClassExpr = class NamedClass {};
const AnonymousClassExpr = class {};
```

* **类字段:**

```javascript
class MyClass {
  instanceField = 0;
  static staticField = 1;
}
```

* **私有方法:**

```javascript
class MyClass {
  #privateMethod() {
    console.log("This is private");
  }
  publicMethod() {
    this.#privateMethod(); // 只能在类内部访问
  }
}
```

* **自动访问器 (需要启用装饰器):**

```javascript
// 需要 --harmony-decorators 或类似 flag
class MyClass {
  accessor myAccessor = 0;
  static accessor staticAccessor = 1;
}
```

**代码逻辑推理 (假设输入与输出):**

这些测试用例主要验证解析器的行为，因此其逻辑是：

* **假设输入 (JavaScript 代码片段):**  例如 `"class C extends B { constructor() { super(); } }"`
* **预期输出:**  解析器应该成功解析该代码，不会报错 (对应 `kSuccess`)。

* **假设输入 (错误的 JavaScript 代码片段):** 例如 `"class C { constructor() { super(); } }"`
* **预期输出:** 解析器应该检测到语法错误并报告错误 (对应 `kError`)。

**用户常见的编程错误示例:**

这部分测试覆盖了很多用户常见的关于类和 `super` 关键字的编程错误：

* **在非派生类的构造函数中使用 `super()`:**

```javascript
class MyClass {
  constructor() {
    // super(); // 错误：TypeError: Class constructor MyClass cannot be invoked without 'new'
  }
}
```

* **在普通方法或函数中使用 `super`:**

```javascript
class MyClass extends Base {
  method() {
    // super.someMethod(); // 错误：'super' keyword unexpected here
  }
}

function myFunction() {
  // super(); // 错误：'super' keyword unexpected here
}
```

* **忘记在派生类的构造函数中调用 `super()`:**

```javascript
class Base {
  constructor(name) {
    this.name = name;
  }
}

class Derived extends Base {
  constructor() {
    // 忘记调用 super()，会导致 this 未初始化
    // super('Derived');
  }
}

const derived = new Derived(); // 错误：Must call super constructor in derived class before accessing 'this' or returning from derived constructor
```

* **方法定义中参数名重复 (尤其是在严格模式下使用 `eval` 或 `arguments`):**

```javascript
"use strict";
const obj = {
  method(a, a) {} // 错误：SyntaxError: Duplicate parameter name not allowed in this context
};

const obj2 = {
  method(eval) {} // 错误：SyntaxError: Identifier 'eval' cannot be used as a function parameter name in strict mode
};
```

**总结第 7 部分的功能:**

总而言之，`v8/test/unittests/parser/parsing-unittest.cc` 的第 7 部分是一个关键的测试集，用于验证 V8 的 JavaScript 解析器在处理 `super` 关键字和类相关的各种语法结构时的正确性，包括合法的语法和各种常见的错误用法。这确保了 V8 能够准确地理解和执行符合 JavaScript 规范的代码，并能及时地报告语法错误，帮助开发者避免常见的编程错误。

### 提示词
```
这是目录为v8/test/unittests/parser/parsing-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/parser/parsing-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第7部分，共15部分，请归纳一下它的功能
```

### 源代码
```cpp
ompile_state;
    i::ReusableUnoptimizedCompileState reusable_state(isolate);
    i::UnoptimizedCompileFlags flags =
        i::UnoptimizedCompileFlags::ForScriptCompile(isolate, *script);
    flags.set_is_module(true);
    i::ParseInfo info(isolate, flags, &compile_state, &reusable_state);
    CHECK(!i::parsing::ParseProgram(&info, script, isolate,
                                    parsing::ReportStatisticsMode::kYes));
    CHECK(info.pending_error_handler()->has_pending_error());
  }
}

TEST_F(ParsingTest, SuperCall) {
  const char* context_data[][2] = {{"", ""}, {nullptr, nullptr}};

  const char* success_data[] = {
      "class C extends B { constructor() { super(); } }",
      "class C extends B { constructor() { () => super(); } }", nullptr};

  RunParserSyncTest(context_data, success_data, kSuccess);

  const char* error_data[] = {"class C { constructor() { super(); } }",
                              "class C { method() { super(); } }",
                              "class C { method() { () => super(); } }",
                              "class C { *method() { super(); } }",
                              "class C { get x() { super(); } }",
                              "class C { set x(_) { super(); } }",
                              "({ method() { super(); } })",
                              "({ *method() { super(); } })",
                              "({ get x() { super(); } })",
                              "({ set x(_) { super(); } })",
                              "({ f: function() { super(); } })",
                              "(function() { super(); })",
                              "var f = function() { super(); }",
                              "({ f: function*() { super(); } })",
                              "(function*() { super(); })",
                              "var f = function*() { super(); }",
                              nullptr};

  RunParserSyncTest(context_data, error_data, kError);
}

TEST_F(ParsingTest, SuperNewNoErrors) {
  const char* context_data[][2] = {{"class C { constructor() { ", " } }"},
                                   {"class C { *method() { ", " } }"},
                                   {"class C { get x() { ", " } }"},
                                   {"class C { set x(_) { ", " } }"},
                                   {"({ method() { ", " } })"},
                                   {"({ *method() { ", " } })"},
                                   {"({ get x() { ", " } })"},
                                   {"({ set x(_) { ", " } })"},
                                   {nullptr, nullptr}};

  const char* expression_data[] = {"new super.x;", "new super.x();",
                                   "() => new super.x;", "() => new super.x();",
                                   nullptr};

  RunParserSyncTest(context_data, expression_data, kSuccess);
}

TEST_F(ParsingTest, SuperNewErrors) {
  const char* context_data[][2] = {{"class C { method() { ", " } }"},
                                   {"class C { *method() { ", " } }"},
                                   {"class C { get x() { ", " } }"},
                                   {"class C { set x(_) { ", " } }"},
                                   {"({ method() { ", " } })"},
                                   {"({ *method() { ", " } })"},
                                   {"({ get x() { ", " } })"},
                                   {"({ set x(_) { ", " } })"},
                                   {"({ f: function() { ", " } })"},
                                   {"(function() { ", " })"},
                                   {"var f = function() { ", " }"},
                                   {"({ f: function*() { ", " } })"},
                                   {"(function*() { ", " })"},
                                   {"var f = function*() { ", " }"},
                                   {nullptr, nullptr}};

  const char* statement_data[] = {"new super;", "new super();",
                                  "() => new super;", "() => new super();",
                                  nullptr};

  RunParserSyncTest(context_data, statement_data, kError);
}

TEST_F(ParsingTest, SuperErrorsNonMethods) {
  // super is only allowed in methods, accessors and constructors.
  const char* context_data[][2] = {{"", ";"},
                                   {"k = ", ";"},
                                   {"foo(", ");"},
                                   {"if (", ") {}"},
                                   {"if (true) {", "}"},
                                   {"if (false) {} else {", "}"},
                                   {"while (true) {", "}"},
                                   {"function f() {", "}"},
                                   {"class C extends (", ") {}"},
                                   {"class C { m() { function f() {", "} } }"},
                                   {"({ m() { function f() {", "} } })"},
                                   {nullptr, nullptr}};

  const char* statement_data[] = {
      "super",           "super = x",   "y = super",     "f(super)",
      "super.x",         "super[27]",   "super.x()",     "super[27]()",
      "super()",         "new super.x", "new super.x()", "new super[27]",
      "new super[27]()", nullptr};

  RunParserSyncTest(context_data, statement_data, kError);
}

TEST_F(ParsingTest, NoErrorsMethodDefinition) {
  const char* context_data[][2] = {{"({", "});"},
                                   {"'use strict'; ({", "});"},
                                   {"({*", "});"},
                                   {"'use strict'; ({*", "});"},
                                   {nullptr, nullptr}};

  const char* object_literal_body_data[] = {
      "m() {}",       "m(x) { return x; }", "m(x, y) {}, n() {}",
      "set(x, y) {}", "get(x, y) {}",       nullptr};

  RunParserSyncTest(context_data, object_literal_body_data, kSuccess);
}

TEST_F(ParsingTest, MethodDefinitionNames) {
  const char* context_data[][2] = {{"({", "(x, y) {}});"},
                                   {"'use strict'; ({", "(x, y) {}});"},
                                   {"({*", "(x, y) {}});"},
                                   {"'use strict'; ({*", "(x, y) {}});"},
                                   {nullptr, nullptr}};

  const char* name_data[] = {
      "m", "'m'", "\"m\"", "\"m n\"", "true", "false", "null", "0", "1.2",
      "1e1", "1E1", "1e+1", "1e-1",

      // Keywords
      "async", "await", "break", "case", "catch", "class", "const", "continue",
      "debugger", "default", "delete", "do", "else", "enum", "export",
      "extends", "finally", "for", "function", "if", "implements", "import",
      "in", "instanceof", "interface", "let", "new", "package", "private",
      "protected", "public", "return", "static", "super", "switch", "this",
      "throw", "try", "typeof", "var", "void", "while", "with", "yield",
      nullptr};

  RunParserSyncTest(context_data, name_data, kSuccess);
}

TEST_F(ParsingTest, MethodDefinitionStrictFormalParamereters) {
  const char* context_data[][2] = {{"({method(", "){}});"},
                                   {"'use strict'; ({method(", "){}});"},
                                   {"({*method(", "){}});"},
                                   {"'use strict'; ({*method(", "){}});"},
                                   {nullptr, nullptr}};

  const char* params_data[] = {"x, x", "x, y, x", "var", "const", nullptr};

  RunParserSyncTest(context_data, params_data, kError);
}

TEST_F(ParsingTest, MethodDefinitionEvalArguments) {
  const char* strict_context_data[][2] = {
      {"'use strict'; ({method(", "){}});"},
      {"'use strict'; ({*method(", "){}});"},
      {nullptr, nullptr}};
  const char* sloppy_context_data[][2] = {
      {"({method(", "){}});"}, {"({*method(", "){}});"}, {nullptr, nullptr}};

  const char* data[] = {"eval", "arguments", nullptr};

  // Fail in strict mode
  RunParserSyncTest(strict_context_data, data, kError);

  // OK in sloppy mode
  RunParserSyncTest(sloppy_context_data, data, kSuccess);
}

TEST_F(ParsingTest, MethodDefinitionDuplicateEvalArguments) {
  const char* context_data[][2] = {{"'use strict'; ({method(", "){}});"},
                                   {"'use strict'; ({*method(", "){}});"},
                                   {"({method(", "){}});"},
                                   {"({*method(", "){}});"},
                                   {nullptr, nullptr}};

  const char* data[] = {"eval, eval", "eval, a, eval", "arguments, arguments",
                        "arguments, a, arguments", nullptr};

  // In strict mode, the error is using "eval" or "arguments" as parameter names
  // In sloppy mode, the error is that eval / arguments are duplicated
  RunParserSyncTest(context_data, data, kError);
}

TEST_F(ParsingTest, MethodDefinitionDuplicateProperty) {
  const char* context_data[][2] = {{"'use strict'; ({", "});"},
                                   {nullptr, nullptr}};

  const char* params_data[] = {"x: 1, x() {}",
                               "x() {}, x: 1",
                               "x() {}, get x() {}",
                               "x() {}, set x(_) {}",
                               "x() {}, x() {}",
                               "x() {}, y() {}, x() {}",
                               "x() {}, \"x\"() {}",
                               "x() {}, 'x'() {}",
                               "0() {}, '0'() {}",
                               "1.0() {}, 1: 1",

                               "x: 1, *x() {}",
                               "*x() {}, x: 1",
                               "*x() {}, get x() {}",
                               "*x() {}, set x(_) {}",
                               "*x() {}, *x() {}",
                               "*x() {}, y() {}, *x() {}",
                               "*x() {}, *\"x\"() {}",
                               "*x() {}, *'x'() {}",
                               "*0() {}, *'0'() {}",
                               "*1.0() {}, 1: 1",

                               nullptr};

  RunParserSyncTest(context_data, params_data, kSuccess);
}

TEST_F(ParsingTest, ClassExpressionNoErrors) {
  const char* context_data[][2] = {
      {"(", ");"}, {"var C = ", ";"}, {"bar, ", ";"}, {nullptr, nullptr}};
  const char* class_data[] = {"class {}",
                              "class name {}",
                              "class extends F {}",
                              "class name extends F {}",
                              "class extends (F, G) {}",
                              "class name extends (F, G) {}",
                              "class extends class {} {}",
                              "class name extends class {} {}",
                              "class extends class base {} {}",
                              "class name extends class base {} {}",
                              nullptr};

  RunParserSyncTest(context_data, class_data, kSuccess);
}

TEST_F(ParsingTest, ClassDeclarationNoErrors) {
  const char* context_data[][2] = {{"'use strict'; ", ""},
                                   {"'use strict'; {", "}"},
                                   {"'use strict'; if (true) {", "}"},
                                   {nullptr, nullptr}};
  const char* statement_data[] = {"class name {}",
                                  "class name extends F {}",
                                  "class name extends (F, G) {}",
                                  "class name extends class {} {}",
                                  "class name extends class base {} {}",
                                  nullptr};

  RunParserSyncTest(context_data, statement_data, kSuccess);
}

TEST_F(ParsingTest, ClassBodyNoErrors) {
  // clang-format off
  // Tests that parser and preparser accept valid class syntax.
  const char* context_data[][2] = {{"(class {", "});"},
                                   {"(class extends Base {", "});"},
                                   {"class C {", "}"},
                                   {"class C extends Base {", "}"},
                                   {nullptr, nullptr}};
  const char* class_body_data[] = {
    ";",
    ";;",
    "m() {}",
    "m() {};",
    "; m() {}",
    "m() {}; n(x) {}",
    "get x() {}",
    "set x(v) {}",
    "get() {}",
    "set() {}",
    "*g() {}",
    "*g() {};",
    "; *g() {}",
    "*g() {}; *h(x) {}",
    "async *x(){}",
    "static() {}",
    "get static() {}",
    "set static(v) {}",
    "static m() {}",
    "static get x() {}",
    "static set x(v) {}",
    "static get() {}",
    "static set() {}",
    "static static() {}",
    "static get static() {}",
    "static set static(v) {}",
    "*static() {}",
    "static *static() {}",
    "*get() {}",
    "*set() {}",
    "static *g() {}",
    "async(){}",
    "*async(){}",
    "static async(){}",
    "static *async(){}",
    "static async *x(){}",

    // Escaped 'static' should be allowed anywhere
    // static-as-PropertyName is.
    "st\\u0061tic() {}",
    "get st\\u0061tic() {}",
    "set st\\u0061tic(v) {}",
    "static st\\u0061tic() {}",
    "static get st\\u0061tic() {}",
    "static set st\\u0061tic(v) {}",
    "*st\\u0061tic() {}",
    "static *st\\u0061tic() {}",

    "static async x(){}",
    "static async(){}",
    "static *async(){}",
    "async x(){}",
    "async 0(){}",
    "async get(){}",
    "async set(){}",
    "async static(){}",
    "async async(){}",
    "async(){}",
    "*async(){}",
    nullptr};
  // clang-format on

  RunParserSyncTest(context_data, class_body_data, kSuccess);
}

TEST_F(ParsingTest, ClassPropertyNameNoErrors) {
  const char* context_data[][2] = {{"(class {", "() {}});"},
                                   {"(class { get ", "() {}});"},
                                   {"(class { set ", "(v) {}});"},
                                   {"(class { static ", "() {}});"},
                                   {"(class { static get ", "() {}});"},
                                   {"(class { static set ", "(v) {}});"},
                                   {"(class { *", "() {}});"},
                                   {"(class { static *", "() {}});"},
                                   {"class C {", "() {}}"},
                                   {"class C { get ", "() {}}"},
                                   {"class C { set ", "(v) {}}"},
                                   {"class C { static ", "() {}}"},
                                   {"class C { static get ", "() {}}"},
                                   {"class C { static set ", "(v) {}}"},
                                   {"class C { *", "() {}}"},
                                   {"class C { static *", "() {}}"},
                                   {nullptr, nullptr}};
  const char* name_data[] = {
      "42",       "42.5",  "42e2",  "42e+2",   "42e-2",    "null",
      "false",    "true",  "'str'", "\"str\"", "static",   "get",
      "set",      "var",   "const", "let",     "this",     "class",
      "function", "yield", "if",    "else",    "for",      "while",
      "do",       "try",   "catch", "finally", "accessor", nullptr};

  RunParserSyncTest(context_data, name_data, kSuccess);
}

// TODO(42202709): Remove when the decorators flag is enabled by default.
TEST_F(ParsingTest, ClassPropertyAccessorNameNoErrorsDecoratorsEnabled) {
  FLAG_SCOPE(js_decorators);
  const char* context_data[][2] = {{"(class {", "() {}});"},
                                   {"(class { get ", "() {}});"},
                                   {"(class { set ", "(v) {}});"},
                                   {"(class { static ", "() {}});"},
                                   {"(class { static get ", "() {}});"},
                                   {"(class { static set ", "(v) {}});"},
                                   {"(class { *", "() {}});"},
                                   {"(class { static *", "() {}});"},
                                   {"class C {", "() {}}"},
                                   {"class C { get ", "() {}}"},
                                   {"class C { set ", "(v) {}}"},
                                   {"class C { static ", "() {}}"},
                                   {"class C { static get ", "() {}}"},
                                   {"class C { static set ", "(v) {}}"},
                                   {"class C { *", "() {}}"},
                                   {"class C { static *", "() {}}"},
                                   {nullptr, nullptr}};
  const char* name_data[] = {"accessor", nullptr};

  RunParserSyncTest(context_data, name_data, kSuccess);
}

TEST_F(ParsingTest, StaticClassFieldsNoErrors) {
  // clang-format off
  // Tests proposed class fields syntax.
  const char* context_data[][2] = {{"(class {", "});"},
                                   {"(class extends Base {", "});"},
                                   {"class C {", "}"},
                                   {"class C extends Base {", "}"},
                                   {nullptr, nullptr}};
  const char* class_body_data[] = {
    // Basic syntax
    "static a = 0;",
    "static a = 0; b",
    "static a = 0; b(){}",
    "static a = 0; *b(){}",
    "static a = 0; ['b'](){}",
    "static a;",
    "static a; b;",
    "static a; b(){}",
    "static a; *b(){}",
    "static a; ['b'](){}",
    "static ['a'] = 0;",
    "static ['a'] = 0; b",
    "static ['a'] = 0; b(){}",
    "static ['a'] = 0; *b(){}",
    "static ['a'] = 0; ['b'](){}",
    "static ['a'];",
    "static ['a']; b;",
    "static ['a']; b(){}",
    "static ['a']; *b(){}",
    "static ['a']; ['b'](){}",

    "static 0 = 0;",
    "static 0;",
    "static 'a' = 0;",
    "static 'a';",

    "static c = [c] = c",

    // ASI
    "static a = 0\n",
    "static a = 0\n b",
    "static a = 0\n b(){}",
    "static a\n",
    "static a\n b\n",
    "static a\n b(){}",
    "static a\n *b(){}",
    "static a\n ['b'](){}",
    "static ['a'] = 0\n",
    "static ['a'] = 0\n b",
    "static ['a'] = 0\n b(){}",
    "static ['a']\n",
    "static ['a']\n b\n",
    "static ['a']\n b(){}",
    "static ['a']\n *b(){}",
    "static ['a']\n ['b'](){}",

    "static a = function t() { arguments; }",
    "static a = () => function t() { arguments; }",

    // ASI edge cases
    "static a\n get",
    "static get\n *a(){}",
    "static a\n static",

    // Misc edge cases
    "static yield",
    "static yield = 0",
    "static yield\n a",
    "static async;",
    "static async = 0;",
    "static async",
    "static async = 0",
    "static async\n a(){}",  // a field named async, and a method named a.
    "static async\n a",
    "static await;",
    "static await = 0;",
    "static await\n a",
    "static accessor;",
    "static accessor = 0;"
    "static accessor\n a",
    nullptr
  };
  // clang-format on

  RunParserSyncTest(context_data, class_body_data, kSuccess);
}

TEST_F(ParsingTest, ClassFieldsNoErrors) {
  // clang-format off
  // Tests proposed class fields syntax.
  const char* context_data[][2] = {{"(class {", "});"},
                                   {"(class extends Base {", "});"},
                                   {"class C {", "}"},
                                   {"class C extends Base {", "}"},
                                   {nullptr, nullptr}};
  const char* class_body_data[] = {
    // Basic syntax
    "a = 0;",
    "a = 0; b",
    "a = 0; b(){}",
    "a = 0; *b(){}",
    "a = 0; ['b'](){}",
    "a;",
    "a; b;",
    "a; b(){}",
    "a; *b(){}",
    "a; ['b'](){}",
    "['a'] = 0;",
    "['a'] = 0; b",
    "['a'] = 0; b(){}",
    "['a'] = 0; *b(){}",
    "['a'] = 0; ['b'](){}",
    "['a'];",
    "['a']; b;",
    "['a']; b(){}",
    "['a']; *b(){}",
    "['a']; ['b'](){}",

    "0 = 0;",
    "0;",
    "'a' = 0;",
    "'a';",

    "c = [c] = c",

    // ASI
    "a = 0\n",
    "a = 0\n b",
    "a = 0\n b(){}",
    "a\n",
    "a\n b\n",
    "a\n b(){}",
    "a\n *b(){}",
    "a\n ['b'](){}",
    "['a'] = 0\n",
    "['a'] = 0\n b",
    "['a'] = 0\n b(){}",
    "['a']\n",
    "['a']\n b\n",
    "['a']\n b(){}",
    "['a']\n *b(){}",
    "['a']\n ['b'](){}",

    // ASI edge cases
    "a\n get",
    "get\n *a(){}",
    "a\n static",

    "a = function t() { arguments; }",
    "a = () => function() { arguments; }",

    // Misc edge cases
    "yield",
    "yield = 0",
    "yield\n a",
    "async;",
    "async = 0;",
    "async",
    "async = 0",
    "async\n a(){}",  // a field named async, and a method named a.
    "async\n a",
    "await;",
    "await = 0;",
    "await\n a",
    "accessor;",
    "accessor = 0;",
    "accessor\n a",
    nullptr
  };
  // clang-format on

  RunParserSyncTest(context_data, class_body_data, kSuccess);
}

// TODO(42202709): Remove when the decorators flag is enabled by default.
TEST_F(ParsingTest, ClassFieldsAccessorNameNoErrorsDecoratorsEnabled) {
  FLAG_SCOPE(js_decorators);
  // clang-format off
  // Tests proposed class fields syntax.
  const char* context_data[][2] = {{"(class {", "});"},
                                   {"(class extends Base {", "});"},
                                   {"class C {", "}"},
                                   {"class C extends Base {", "}"},
                                   {nullptr, nullptr}};
  const char* class_body_data[] = {
    "accessor;",
    "accessor = 0;",
    "accessor\n a",
    "static accessor;",
    "static accessor = 0;"
    "static accessor\n a",
    nullptr
  };
  // clang-format on

  RunParserSyncTest(context_data, class_body_data, kSuccess);
}

TEST_F(ParsingTest, PrivateMethodsNoErrors) {
  // clang-format off
  // Tests proposed class methods syntax.
  const char* context_data[][2] = {{"(class {", "});"},
                                   {"(class extends Base {", "});"},
                                   {"class C {", "}"},
                                   {"class C extends Base {", "}"},
                                   {nullptr, nullptr}};
  const char* class_body_data[] = {
    // Basic syntax
    "#a() { }",
    "get #a() { }",
    "set #a(foo) { }",
    "*#a() { }",
    "async #a() { }",
    "async *#a() { }",

    "#a() { } #b() {}",
    "get #a() { } set #a(foo) {}",
    "get #a() { } get #b() {} set #a(foo) {}",
    "get #a() { } get #b() {} set #a(foo) {} set #b(foo) {}",
    "set #a(foo) { } set #b(foo) {}",
    "get #a() { } get #b() {}",

    "#a() { } static a() {}",
    "#a() { } a() {}",
    "#a() { } a() {} static a() {}",
    "get #a() { } get a() {} static get a() {}",
    "set #a(foo) { } set a(foo) {} static set a(foo) {}",

    "#a() { } get #b() {}",
    "#a() { } async #b() {}",
    "#a() { } async *#b() {}",

    // With arguments
    "#a(...args) { }",
    "#a(a = 1) { }",
    "get #a() { }",
    "set #a(a = (...args) => {}) { }",

    // Misc edge cases
    "#get() {}",
    "#set() {}",
    "#yield() {}",
    "#await() {}",
    "#async() {}",
    "#static() {}",
    "#accessor() {}",
    "#arguments() {}",
    "get #yield() {}",
    "get #await() {}",
    "get #async() {}",
    "get #get() {}",
    "get #static() {}",
    "get #arguments() {}",
    "get #accessor() {}",
    "set #yield(test) {}",
    "set #async(test) {}",
    "set #await(test) {}",
    "set #set(test) {}",
    "set #static(test) {}",
    "set #arguments(test) {}",
    "set #accessor(test) {}"
    "async #yield() {}",
    "async #async() {}",
    "async #await() {}",
    "async #get() {}",
    "async #set() {}",
    "async #static() {}",
    "async #arguments() {}",
    "async #accessor() {}",
    "*#async() {}",
    "*#await() {}",
    "*#yield() {}",
    "*#get() {}",
    "*#set() {}",
    "*#static() {}",
    "*#arguments() {}",
    "*#accessor() {}",
    "async *#yield() {}",
    "async *#async() {}",
    "async *#await() {}",
    "async *#get() {}",
    "async *#set() {}",
    "async *#static() {}",
    "async *#arguments() {}",
    "async *#accessor() {}",
    nullptr
  };
  // clang-format on

  RunParserSyncTest(context_data, class_body_data, kSuccess);
}

TEST_F(ParsingTest, PrivateMethodsAccessorNameNoErrorsDecoratorsEnabled) {
  FLAG_SCOPE(js_decorators);
  // clang-format off
  // Tests proposed class methods syntax.
  const char* context_data[][2] = {{"(class {", "});"},
                                   {"(class extends Base {", "});"},
                                   {"class C {", "}"},
                                   {"class C extends Base {", "}"},
                                   {nullptr, nullptr}};
  const char* class_body_data[] = {
    // Accessor edge cases
    "#accessor() {}",
    "set #accessor(test) {}",
    "async #accessor() {}",
    "*#accessor() {}",
    "async *#accessor() {}",
    nullptr
  };
  // clang-format on

  RunParserSyncTest(context_data, class_body_data, kSuccess);
}

TEST_F(ParsingTest, PrivateMethodsAndFieldsNoErrors) {
  // clang-format off
  // Tests proposed class methods syntax in combination with fields
  const char* context_data[][2] = {{"(class {", "});"},
                                   {"(class extends Base {", "});"},
                                   {"class C {", "}"},
                                   {"class C extends Base {", "}"},
                                   {nullptr, nullptr}};
  const char* class_body_data[] = {
    // Basic syntax
    "#b;#a() { }",
    "#b;get #a() { }",
    "#b;set #a(foo) { }",
    "#b;*#a() { }",
    "#b;async #a() { }",
    "#b;async *#a() { }",
    "#b = 1;#a() { }",
    "#b = 1;get #a() { }",
    "#b = 1;set #a(foo) { }",
    "#b = 1;*#a() { }",
    "#b = 1;async #a() { }",
    "#b = 1;async *#a() { }",

    // With public fields
    "a;#a() { }",
    "a;get #a() { }",
    "a;set #a(foo) { }",
    "a;*#a() { }",
    "a;async #a() { }",
    "a;async *#a() { }",
    "a = 1;#a() { }",
    "a = 1;get #a() { }",
    "a = 1;set #a(foo) { }",
    "a = 1;*#a() { }",
    "a = 1;async #a() { }",
    "a = 1;async *#a() { }",

    // ASI
    "#a = 0\n #b(){}",
    "#a\n *#b(){}",
    "#a = 0\n get #b(){}",
    "#a\n *#b(){}",

    "b = 0\n #b(){}",
    "b\n *#b(){}",
    "b = 0\n get #b(){}",
    "b\n *#b(){}",
    nullptr
  };
  // clang-format on

  RunParserSyncTest(context_data, class_body_data, kSuccess);
}

// Test that public auto-accessors do not parse outside class bodies.
TEST_F(ParsingTest, PublicAutoAccessorsInNonClassErrors) {
  FLAG_SCOPE(js_decorators);
  // clang-format off
  const char* context_data[][2] = {{"", ""},
                                   {"({", "})"},
                                   {"'use strict'; ({", "});"},
                                   {"function() {", "}"},
                                   {"() => {", "}"},
                                   {"class C { test() {", "} }"},
                                   {"const {", "} = {}"},
                                   {"({", "} = {})"},
                                   {nullptr, nullptr}};
  const char* class_body_data[] = {
    "accessor a = 1",
    "accessor a = () => {}",
    "accessor a",
    "accessor 0 = 1",
    "accessor 0 = () => {}",
    "accessor 0",
    nullptr
  };
  // clang-format on

  RunParserSyncTest(context_data, class_body_data, kError);
}

// TODO(42202709): Merge with PrivateMethodsAndFieldsNoErrors once the
// decorators flag is enabled by default.
TEST_F(ParsingTest, PrivateAutoAccessorsAndFieldsNoErrors) {
  FLAG_SCOPE(js_decorators);
  // clang-format off
  const char* context_data[][2] = {{"(class {", "});"},
                                   {"(class extends Base {", "});"},
                                   {"class C {", "}"},
                                   {"class C extends Base {", "}"},
                                   {nullptr, nullptr}};
  const char* class_body_data[] = {
    // Basic syntax
    "#b;accessor #a;",
    "#b;accessor #a = 0;",
    "#b = 1;accessor #a;",
    "#b = 1;accessor #a = 0;",

    // With public fields
    "a;accessor #a;",
    "a;accessor #a = 0;",
    "a = 1;accessor #a;",
    "a = 1;accessor #a = 0;",
    nullptr
  };
  // clang-format on

  RunParserSyncTest(context_data, class_body_data, kSuccess);
}

TEST_F(ParsingTest, PublicAutoAccessorsInstanceAndStaticNoErrors) {
  FLAG_SCOPE(js_decorators);
  // clang-format off
  // Tests proposed class auto-accessors syntax.
  const char* context_data[][2] = {{"(class {", "});"},
                                   {"(class extends Base {", "});"},
                                   {"class C {", "}"},
                                   {"class C extends Base {", "}"},
                                   // static declarations
                                   {"(class { static ", "});"},
                                   {"(class extends Base { static ", "});"},
                                   {"class C { static ", "}"},
                                   {"class C extends Base { static ", "}"},
                                   {nullptr, nullptr}};
  const char* class_body_data[] = {
    // Basic syntax
    "accessor a = 0;",
    "accessor a = 0; b",
    "accessor a = 0; b(){}",
    "accessor a = 0; *b(){}",
    "accessor a = 0; ['b'](){}",
    "accessor a;",
    "accessor a; b;",
    "accessor a; b(){}",
    "accessor a; *b(){}",
    "accessor a; ['b'](){}",
    "accessor ['a'] = 0;",
    "accessor ['a'] = 0; b",
    "accessor ['a'] = 0; b(){}",
    "accessor ['a'] = 0; *b(){}",
    "accessor ['a'] = 0; ['b'](){}",
    "accessor ['a'];",
    "accessor ['a']; b;",
    "accessor ['a']; b(){}",
    "accessor ['a']; *b(){}",
    "accessor ['a']; ['b'](){}",

    "accessor 0 = 0;",
    "accessor 0;",
    "accessor 'a' = 0;",
    "accessor 'a';",

    "accessor c = [c] = c",

    // ASI
    "accessor a = 0\n",
    "accessor a = 0\n b",
    "accessor a = 0\n b(){}",
    "accessor a\n",
    "accessor a\n b\n",
    "accessor a\n b(){}",
    "accessor a\n *b(){}",
    "accessor a\n ['b'](){}",
    "accessor ['a'] = 0\n",
    "accessor ['a'] = 0\n b",
    "accessor ['a'] = 0\n b(){}",
    "accessor ['a']\n",
    "accessor ['a']\n b\n",
    "accessor ['a']\n b(){}",
    "accessor ['a']\n *b(){}",
    "accessor ['a']\n ['b'](){}",

    // ASI edge cases
    "accessor a\n get",
    "accessor get\n *a(){}",
    "accessor a\n static",

    "accessor a = function t() { arguments; }",
    "accessor a = () => function() { arguments; }",

    // Misc edge cases
    "accessor yield",
    "accessor yield = 0",
    "accessor yield\n a",
    "accessor async;",
    "accessor async = 0;",
    "accessor async",
    "accessor async = 0",
    "accessor async\n a(){}",  // a field named async, and a method named a.
    "accessor async\n a",
    "accessor await;",
    "accessor await = 0;",
    "accessor await\n a",
    "accessor accessor;",
    "accessor accessor = 0;",
    "accessor accessor\n a",
    nullptr
  };
  // clang-format on

  RunParserSyncTest(context_data, class_body_data, kSuccess);
}

TEST_F(ParsingTest, PrivateMethodsErrors) {
  // clang-format off
  // Tests proposed class methods syntax in combination with fields
  const char* context_data[][2] = {{"(class {", "});"},
                                   {"(class extends Base {", "});"},
                                   {"class C {", "}"},
                                   {"class C extends Base {", "}"},
                                   {nullptr, nullptr}};
  const char* class_body_data[] = {
    "#a() : 0",
    "#a() =",
    "#a() => {}",
    "#a => {}",
    "*#a() = 0",
    "*#a() => 0",
    "*#a() => {}",
    "get #a()[]",
    "yield #a()[]",
    "yield #a => {}",
    "async #a() = 0",
    "async #a => {}",
    "#a(arguments) {}",
    "set #a(arguments) {}",

    "#['a']() { }",
    "get #['a']() { }",
    "set #['a'](foo) { }",
    "*#['a']() { }",
    "async #['a']() { }",
    "async *#['a]() { }",

    "get #a() {} get #a() {}",
    "get #a() {} get #['a']() {}",
    "set #a(val) {} set #a(val) {}",
    "set #a(val) {} set #['a'](val) {}",

    "#a\n#",
    "#a() c",
    "#a() #",
    "#a(arg) c",
    "#a(arg) #",
    "#a(arg) #c",
    "#a#",
    "#a#b",
    "#a#b(){}",
    "#[test](){}",

    "async *#constructor() {}",
    "*#constructor() {}",
    "async #constructor() {}",
    "set #constructor(test) {}",
    "#constructor() {}",
    "get #constructor() {}",

    "static async *#constructor() {}",
    "static *#constructor() {}",
    "static async #constructor() {}",
    "static set #constructor(test) {}",
    "static #constructor() {}",
    "static get #constructor() {}",

    nullptr
  };
  // clang-format on

  RunParserSyncTest(context_data, class_body_data, kError);
}

// Test that private members parse in class bodies nested in object literals
TEST_F(ParsingTest, PrivateMembersNestedInObjectLiteralsNoErrors) {
  // clang-format off
  const char* context_data[][2] = {{"({", "})"},
                                   {"'use strict'; ({", "});"},
```