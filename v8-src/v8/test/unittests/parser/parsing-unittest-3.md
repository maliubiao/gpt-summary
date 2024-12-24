Response: The user wants to understand the functionality of the C++ code provided in the file `v8/test/unittests/parser/parsing-unittest.cc`. This is the 4th part of an 8-part file.

The code consists of several `TEST_F` blocks, which are likely unit tests for the V8 JavaScript engine's parser. Each `TEST_F` block seems to focus on testing a specific grammar rule or feature of JavaScript, checking for both valid (success) and invalid (error) syntax.

Here's a breakdown of the tests in this section:

- **`ParsingTest, InvalidModule`**: Tests parsing of invalid module syntax.
- **`ParsingTest, SuperCall`**: Tests the `super()` call in constructors and methods, ensuring it's only valid in the correct context.
- **`ParsingTest, SuperNewNoErrors`**: Tests the `new super.property` syntax (without actually calling `super`) and verifies it's valid in specific contexts like constructors and accessors.
- **`ParsingTest, SuperNewErrors`**: Tests the invalid use of `new super()` in various contexts.
- **`ParsingTest, SuperErrorsNonMethods`**: Tests that `super` is not allowed outside of methods, accessors, and constructors.
- **`ParsingTest, NoErrorsMethodDefinition`**: Tests valid method definitions within object literals.
- **`ParsingTest, MethodDefinitionNames`**: Tests various valid names for methods in object literals, including keywords.
- **`ParsingTest, MethodDefinitionStrictFormalParamereters`**: Tests errors for duplicate parameter names in strict mode method definitions.
- **`ParsingTest, MethodDefinitionEvalArguments`**: Tests the usage of `eval` and `arguments` as parameter names in strict and sloppy mode.
- **`ParsingTest, MethodDefinitionDuplicateEvalArguments`**: Tests errors for duplicate `eval` or `arguments` parameter names.
- **`ParsingTest, MethodDefinitionDuplicateProperty`**: Tests that duplicate property definitions (methods and data properties) in object literals are allowed.
- **`ParsingTest, ClassExpressionNoErrors`**: Tests valid class expressions.
- **`ParsingTest, ClassDeclarationNoErrors`**: Tests valid class declarations.
- **`ParsingTest, ClassBodyNoErrors`**: Tests various valid syntax within class bodies, including methods, getters, setters, and static members.
- **`ParsingTest, ClassPropertyNameNoErrors`**: Tests valid names for class properties (methods, getters, setters, static members).
- **`ParsingTest, ClassPropertyAccessorNameNoErrorsDecoratorsEnabled`**: Tests the `accessor` keyword as a property name when decorators are enabled.
- **`ParsingTest, StaticClassFieldsNoErrors`**: Tests valid static class field declarations.
- **`ParsingTest, ClassFieldsNoErrors`**: Tests valid instance class field declarations.
- **`ParsingTest, ClassFieldsAccessorNameNoErrorsDecoratorsEnabled`**: Tests the `accessor` keyword as a field name when decorators are enabled.
- **`ParsingTest, PrivateMethodsNoErrors`**: Tests valid private method declarations in classes.
- **`ParsingTest, PrivateMethodsAccessorNameNoErrorsDecoratorsEnabled`**: Tests the `accessor` keyword for private methods when decorators are enabled.
- **`ParsingTest, PrivateMethodsAndFieldsNoErrors`**: Tests the combination of private methods and fields.
- **`ParsingTest, PublicAutoAccessorsInNonClassErrors`**: Tests that public auto-accessors are not valid outside class bodies.
- **`ParsingTest, PrivateAutoAccessorsAndFieldsNoErrors`**: Tests the combination of private auto-accessors and fields.
- **`ParsingTest, PublicAutoAccessorsInstanceAndStaticNoErrors`**: Tests valid public auto-accessor declarations (instance and static).
- **`ParsingTest, PrivateMethodsErrors`**: Tests invalid private method declarations.
- **`ParsingTest, PrivateMembersNestedInObjectLiteralsNoErrors`**: Tests private members in classes nested within object literals.
- **`ParsingTest, PrivateAutoAccessorsNestedInObjectLiteralsNoErrors`**: Tests private auto-accessors in classes nested within object literals.
- **`ParsingTest, PublicAutoAccessorsNestedNoErrors`**: Tests public auto-accessors in nested classes.
- **`ParsingTest, PrivateMembersInNestedClassNoErrors`**: Tests private members in nested classes.
- **`ParsingTest, PrivateAutoAccessorsInNestedClassNoErrors`**: Tests private auto-accessors in nested classes.
- **`ParsingTest, PrivateMembersInNonClassErrors`**: Tests that private members are not valid outside class bodies.
- **`ParsingTest, PrivateAutoAccessorsInNonClassErrors`**: Tests that private auto-accessors are not valid outside class bodies.
- **`ParsingTest, PrivateMembersNestedNoErrors`**: Tests private members in nested class contexts.
- **`ParsingTest, PrivateMembersEarlyErrors`**: Tests for early errors when accessing undeclared private members.
- **`ParsingTest, PrivateMembersWrongAccessNoEarlyErrors`**: Tests that incorrect access to private members doesn't result in early errors (should be runtime errors).
- **`ParsingTest, PrivateStaticClassMethodsAndAccessorsNoErrors`**: Tests valid private static method and accessor declarations.
- **`ParsingTest, PrivateStaticClassMethodsAndAccessorsDuplicateErrors`**: Tests errors for duplicate private static methods and accessors.
- **`ParsingTest, PrivateStaticAutoAccessorsDuplicateErrors`**: Tests errors for duplicate private static auto-accessors.
- **`ParsingTest, PrivateAutoAccessorsDuplicateErrors`**: Tests errors for duplicate private auto-accessors.
- **`ParsingTest, PrivateClassFieldsNoErrors`**: Tests valid private class field declarations.
- **`ParsingTest, PrivateAutoAccessorsNoErrors`**: Tests valid private auto-accessor declarations.
- **`ParsingTest, StaticClassFieldsErrors`**: Tests invalid static class field declarations.
- **`ParsingTest, ClassFieldsErrors`**: Tests invalid instance class field declarations.
- **`ParsingTest, PublicAutoAccessorsInstanceAndStaticErrors`**: Tests invalid public auto-accessor declarations (instance and static).
- **`ParsingTest, PrivateClassFieldsErrors`**: Tests invalid private class field declarations.
- **`ParsingTest, PrivateClassAutoAccessorsErrors`**: Tests invalid private auto-accessor declarations.
- **`ParsingTest, PrivateStaticClassFieldsNoErrors`**: Tests valid private static class field declarations.
- **`ParsingTest, PrivateStaticAutoAccessorsNoErrors`**: Tests valid private static auto-accessor declarations.
- **`ParsingTest, PrivateStaticClassFieldsErrors`**: Tests invalid private static class field declarations.
- **`ParsingTest, PrivateStaticAutoAccessorsErrors`**: Tests invalid private static auto-accessor declarations.

The file systematically tests various aspects of JavaScript syntax related to classes, methods, properties, and the `super` keyword. The tests cover both syntactically correct and incorrect code to ensure the parser behaves as expected.

Since these tests are for a JavaScript engine's parser, there's a strong connection to JavaScript functionality. Here's an example illustrating the `SuperCall` test:

```javascript
// Example related to ParsingTest.SuperCall

// Valid usage of super() in a constructor
class Base {
  constructor() {
    console.log("Base constructor");
  }
}

class Derived extends Base {
  constructor() {
    super(); // Correct: calling super() in the derived class constructor
    console.log("Derived constructor");
  }
}

new Derived(); // Output: Base constructor, then Derived constructor

// Invalid usage of super() outside a constructor or method in a class
class InvalidSuper {
  value = super(); // Error: super() is not allowed here
}

function notAClass() {
  super(); // Error: super() is not allowed here
}
```

This JavaScript example demonstrates the correct and incorrect usage of `super()` as tested in the `ParsingTest.SuperCall` unit test in the C++ code. The C++ test verifies that the parser correctly identifies these cases as either valid or erroneous according to the JavaScript language specification.
这个C++源代码文件 `v8/test/unittests/parser/parsing-unittest.cc` 的第4部分主要功能是**对JavaScript语法中关于类（classes）的定义和使用进行解析的单元测试**。

具体来说，它测试了以下与JavaScript类相关的语法结构：

* **`super()` 调用:**  测试 `super()` 关键字在构造函数和方法中的正确使用，以及在错误上下文中的使用。
* **`new super.x` 表达式:** 测试 `new super.x` 这种形式的表达式在不同上下文中的合法性。
* **`super` 关键字的错误使用:**  测试 `super` 关键字在方法、访问器和构造函数之外的非法使用场景。
* **方法定义 (Method Definition):** 测试对象字面量中定义方法的各种正确语法。
* **方法名 (Method Names):** 测试方法定义中各种合法的名称，包括字符串、数字和关键字。
* **方法参数 (Method Parameters):** 测试方法定义中关于参数的限制，例如严格模式下的重复参数名以及 `eval` 和 `arguments` 作为参数名的情况。
* **重复属性 (Duplicate Property):** 测试对象字面量中重复定义属性（包括方法和数据属性）的情况。
* **类表达式 (Class Expression):** 测试各种有效的类表达式的语法。
* **类声明 (Class Declaration):** 测试各种有效的类声明的语法，特别是在严格模式下。
* **类体 (Class Body):** 测试类体内部各种成员的定义，包括方法、getter、setter、静态成员等。
* **类属性名 (Class Property Names):** 测试类成员定义中各种合法的属性名称。
* **静态类字段 (Static Class Fields):** 测试静态类字段的声明语法。
* **类字段 (Class Fields):** 测试实例类字段的声明语法。
* **私有方法 (Private Methods):** 测试私有方法的声明和各种语法形式。
* **私有字段 (Private Fields):** 测试私有字段的声明和各种语法形式。
* **公共自动访问器 (Public Auto Accessors):** 测试公共自动访问器的声明和在类内外的使用。
* **私有自动访问器 (Private Auto Accessors):** 测试私有自动访问器的声明和使用。

**它与JavaScript的功能有密切关系，因为它测试的是V8引擎中解析JavaScript代码关于类的部分。**  这些测试用例确保V8的解析器能够正确理解和处理符合JavaScript语言规范的类语法，并且能够识别并报错不符合规范的代码。

**JavaScript 示例说明 (与 `ParsingTest.SuperCall` 相关):**

```javascript
class Base {
  constructor() {
    console.log("Base constructor called");
  }
}

class Derived extends Base {
  constructor() {
    super(); // 正确: 在派生类的构造函数中调用 super()
    console.log("Derived constructor called");
  }

  myMethod() {
    // super(); // 错误: 不能在普通方法中直接调用 super() 像函数一样
  }

  myOtherMethod() {
    setTimeout(() => {
      // super(); // 错误: 在箭头函数中直接调用 super() 像函数一样
    }, 100);
  }
}

const derivedInstance = new Derived(); // 输出 "Base constructor called", 然后 "Derived constructor called"

class InvalidSuper {
  constructor() {
    //  super(); // 如果没有继承，在构造函数中调用 super() 会报错
  }
}

function notAClassFunction() {
  // super(); // 错误: 在普通函数中不能使用 super()
}
```

**总结:**  这个C++文件是V8引擎解析器的一个重要测试组件，它专注于验证类相关的JavaScript语法解析是否正确，为V8引擎的健壮性和符合JavaScript标准提供了保障。它通过大量的测试用例覆盖了各种合法的和非法的类语法，确保解析器能够准确地识别和处理这些情况。

Prompt: 
```
这是目录为v8/test/unittests/parser/parsing-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第4部分，共8部分，请归纳一下它的功能

"""
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
                                   {nullptr, nullptr}};
  const char* class_body_data[] = {
    "a: class { #a = 1 }",
    "a: class { #a = () => {} }",
    "a: class { #a }",
    "a: class { #a() { } }",
    "a: class { get #a() { } }",
    "a: class { set #a(foo) { } }",
    "a: class { *#a() { } }",
    "a: class { async #a() { } }",
    "a: class { async *#a() { } }",
    nullptr
  };
  // clang-format on

  RunParserSyncTest(context_data, class_body_data, kSuccess);
}

// TODO(42202709): Merge with PrivateMembersNestedInObjectLiteralsNoErrors once
// the decorators flag is enabled by default.
TEST_F(ParsingTest, PrivateAutoAccessorsNestedInObjectLiteralsNoErrors) {
  FLAG_SCOPE(js_decorators);
  // clang-format off
  const char* context_data[][2] = {{"({", "})"},
                                   {"'use strict'; ({", "});"},
                                   {nullptr, nullptr}};
  const char* class_body_data[] = {
    "a: class { accessor #a = 1 }",
    "a: class { accessor #a = () => {} }",
    "a: class { accessor #a }",
    nullptr
  };
  // clang-format on

  RunParserSyncTest(context_data, class_body_data, kSuccess);
}

TEST_F(ParsingTest, PublicAutoAccessorsNestedNoErrors) {
  FLAG_SCOPE(js_decorators);
  // clang-format off
  const char* context_data[][2] = {{"({a: ", "})"},
                                   {"'use strict'; ({a: ", "});"},
                                   {"(class {a = ", "});"},
                                   {"(class extends Base {a = ", "});"},
                                   {"class C {a = ", "}"},
                                   {"class C extends Base {a = ", "}"},
                                   {nullptr, nullptr}};
  const char* class_body_data[] = {
    "class { accessor a = 1 }",
    "class { accessor a = () => {} }",
    "class { accessor a }",
    "class { accessor 0 = 1 }",
    "class { accessor 0 = () => {} }",
    "class { accessor 0 }",
    "class { accessor ['a'] = 1 }",
    "class { accessor ['a'] = () => {} }",
    "class { accessor ['a'] }",
    nullptr
  };
  // clang-format on

  RunParserSyncTest(context_data, class_body_data, kSuccess);
}

// Test that private members parse in class bodies nested in classes
TEST_F(ParsingTest, PrivateMembersInNestedClassNoErrors) {
  // clang-format off
  const char* context_data[][2] = {{"(class {", "});"},
                                   {"(class extends Base {", "});"},
                                   {"class C {", "}"},
                                   {"class C extends Base {", "}"},
                                   {nullptr, nullptr}};
  const char* class_body_data[] = {
    "a = class { #a = 1 }",
    "a = class { #a = () => {} }",
    "a = class { #a }",
    "a = class { #a() { } }",
    "a = class { get #a() { } }",
    "a = class { set #a(foo) { } }",
    "a = class { *#a() { } }",
    "a = class { async #a() { } }",
    "a = class { async *#a() { } }",
    nullptr
  };
  // clang-format on

  RunParserSyncTest(context_data, class_body_data, kSuccess);
}

// TODO(42202709): Merge with PrivateMembersInNestedClassNoErrors once
// the decorators flag is enabled by default.
TEST_F(ParsingTest, PrivateAutoAccessorsInNestedClassNoErrors) {
  FLAG_SCOPE(js_decorators);
  // clang-format off
  const char* context_data[][2] = {{"(class {", "});"},
                                   {"(class extends Base {", "});"},
                                   {"class C {", "}"},
                                   {"class C extends Base {", "}"},
                                   {nullptr, nullptr}};
  const char* class_body_data[] = {
    "a = class { accessor #a = 1 }",
    "a = class { accessor #a = () => {} }",
    "a = class { accessor #a }",
    nullptr
  };
  // clang-format on

  RunParserSyncTest(context_data, class_body_data, kSuccess);
}

// Test that private members do not parse outside class bodies
TEST_F(ParsingTest, PrivateMembersInNonClassErrors) {
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
    "#a = 1",
    "#a = () => {}",
    "#a",
    "#a() { }",
    "get #a() { }",
    "set #a(foo) { }",
    "*#a() { }",
    "async #a() { }",
    "async *#a() { }",
    nullptr
  };
  // clang-format on

  RunParserSyncTest(context_data, class_body_data, kError);
}

// TODO(42202709): Merge with PrivateMembersInNonClassErrors once
// the decorators flag is enabled by default.
// Test that private auto-accessors do not parse outside class bodies
TEST_F(ParsingTest, PrivateAutoAccessorsInNonClassErrors) {
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
                                   {"class C { static {", "} }"},
                                   {nullptr, nullptr}};
  const char* class_body_data[] = {
    "accessor #a = 1",
    "accessor #a = () => {}",
    "accessor #a",
    nullptr
  };
  // clang-format on

  RunParserSyncTest(context_data, class_body_data, kError);
}

// Test that nested private members parse
TEST_F(ParsingTest, PrivateMembersNestedNoErrors) {
  // clang-format off
  const char* context_data[][2] = {{"(class { get #a() { ", "} });"},
                                   {
                                     "(class { set #a(val) {} get #a() { ",
                                     "} });"
                                    },
                                   {"(class { set #a(val) {", "} });"},
                                   {"(class { #a() { ", "} });"},
                                   {nullptr, nullptr}};
  const char* class_body_data[] = {
    "class C { #a() {} }",
    "class C { get #a() {} }",
    "class C { get #a() {} set #a(val) {} }",
    "class C { set #a(val) {} }",
    nullptr
  };
  // clang-format on

  RunParserSyncTest(context_data, class_body_data, kSuccess);
}

// Test that acessing undeclared private members result in early errors
TEST_F(ParsingTest, PrivateMembersEarlyErrors) {
  // clang-format off
  const char* context_data[][2] = {{"(class {", "});"},
                                   {"(class extends Base {", "});"},
                                   {"class C {", "}"},
                                   {"class C extends Base {", "}"},
                                   {nullptr, nullptr}};
  const char* class_body_data[] = {
    "set #b(val) { this.#a = val; }",
    "get #b() { return this.#a; }",
    "foo() { return this.#a; }",
    "foo() { this.#a = 1; }",
    nullptr
  };
  // clang-format on

  RunParserSyncTest(context_data, class_body_data, kError);
}

// Test that acessing wrong kind private members do not error early.
// Instead these should be runtime errors.
TEST_F(ParsingTest, PrivateMembersWrongAccessNoEarlyErrors) {
  // clang-format off
  const char* context_data[][2] = {{"(class {", "});"},
                                   {"(class extends Base {", "});"},
                                   {"class C {", "}"},
                                   {"class C extends Base {", "}"},
                                   {nullptr, nullptr}};
  const char* class_body_data[] = {
    // Private setter only
    "set #b(val) {} fn() { return this.#b; }",
    "set #b(val) {} fn() { this.#b++; }",
    // Nested private setter only
    R"(get #b() {}
    fn() {
      return new class { set #b(val) {} fn() { this.#b++; } };
    })",
    R"(get #b() {}
    fn() {
      return new class { set #b(val) {} fn() { return this.#b; } };
    })",

    // Private getter only
    "get #b() { } fn() { this.#b = 1; }",
    "get #b() { } fn() { this.#b++; }",
    "get #b() { } fn(obj) { ({ y: this.#b } = obj); }",
    // Nested private getter only
    R"(set #b(val) {}
    fn() {
      return new class { get #b() {} fn() { this.#b++; } };
    })",
    R"(set #b(val) {}
    fn() {
      return new class { get #b() {} fn() { this.#b = 1; } };
    })",
    R"(set #b(val) {}
    fn() {
      return new class { get #b() {} fn() { ({ y: this.#b } = obj); } };
    })",

    // Writing to private methods
    "#b() { } fn() { this.#b = 1; }",
    "#b() { } fn() { this.#b++; }",
    "#b() {} fn(obj) { ({ y: this.#b } = obj); }",
    // Writing to nested private methods
    R"(#b() {}
    fn() {
      return new class { get #b() {} fn() { this.#b++; } };
    })",
    R"(#b() {}
    fn() {
      return new class { get #b() {} fn() { this.#b = 1; } };
    })",
    R"(#b() {}
    fn() {
      return new class { get #b() {} fn() { ({ y: this.#b } = obj); } };
    })",
    nullptr
  };
  // clang-format on

  RunParserSyncTest(context_data, class_body_data, kSuccess);
}

TEST_F(ParsingTest, PrivateStaticClassMethodsAndAccessorsNoErrors) {
  // clang-format off
  // Tests proposed class fields syntax.
  const char* context_data[][2] = {{"(class {", "});"},
                                   {"(class extends Base {", "});"},
                                   {"class C {", "}"},
                                   {"class C extends Base {", "}"},
                                   {nullptr, nullptr}};
  const char* class_body_data[] = {
    "static #a() { }",
    "static get #a() { }",
    "static set #a(val) { }",
    "static get #a() { } static set #a(val) { }",
    "static *#a() { }",
    "static async #a() { }",
    "static async *#a() { }",
    nullptr
  };
  // clang-format on

  RunParserSyncTest(context_data, class_body_data, kSuccess);
}

TEST_F(ParsingTest, PrivateStaticClassMethodsAndAccessorsDuplicateErrors) {
  // clang-format off
  // Tests proposed class fields syntax.
  const char* context_data[][2] = {{"(class {", "});"},
                                   {"(class extends Base {", "});"},
                                   {"class C {", "}"},
                                   {"class C extends Base {", "}"},
                                   {nullptr, nullptr}};
  const char* class_body_data[] = {
    "static get #a() {} static get #a() {}",
    "static get #a() {} static #a() {}",
    "static get #a() {} get #a() {}",
    "static get #a() {} set #a(val) {}",
    "static get #a() {} #a() {}",

    "static set #a(val) {} static set #a(val) {}",
    "static set #a(val) {} static #a() {}",
    "static set #a(val) {} get #a() {}",
    "static set #a(val) {} set #a(val) {}",
    "static set #a(val) {} #a() {}",

    "static #a() {} static #a() {}",
    "static #a() {} #a(val) {}",
    "static #a() {} set #a(val) {}",
    "static #a() {} get #a() {}",

    nullptr
  };
  // clang-format on

  RunParserSyncTest(context_data, class_body_data, kError);
}

// TODO(42202709): Merge with
// PrivateStaticClassMethodsAndAccessorsDuplicateErrors once the decorators flag
// is enabled by default.
TEST_F(ParsingTest, PrivateStaticAutoAccessorsDuplicateErrors) {
  FLAG_SCOPE(js_decorators);
  // clang-format off
  const char* context_data[][2] = {{"(class {", "});"},
                                   {"(class extends Base {", "});"},
                                   {"class C {", "}"},
                                   {"class C extends Base {", "}"},
                                   {nullptr, nullptr}};
  const char* class_body_data[] = {
    "static get #a() {} static accessor #a",
    "static set #a(foo) {} static accessor #a",
    "static #a() {} static accessor #a",
    "static #a; static accessor #a",
    "static accessor #a; static get #a() {}",
    "static accessor #a; static set #a(foo) {}",
    "static accessor #a; static #a",
    "static accessor #a; static #a() {}",
    "static accessor #a; static accessor #a;",
    nullptr
  };
  // clang-format on

  RunParserSyncTest(context_data, class_body_data, kError);
}

TEST_F(ParsingTest, PrivateAutoAccessorsDuplicateErrors) {
  FLAG_SCOPE(js_decorators);
  // clang-format off
  const char* context_data[][2] = {{"(class {", "});"},
                                   {"(class extends Base {", "});"},
                                   {"class C {", "}"},
                                   {"class C extends Base {", "}"},
                                   {nullptr, nullptr}};
  const char* class_body_data[] = {
    "get #a() {} accessor #a",
    "set #a(foo) {} accessor #a",
    "#a() {} accessor #a",
    "#a; accessor #a",
    "accessor #a; get #a() {}",
    "accessor #a; set #a(foo) {}",
    "accessor #a; #a",
    "accessor #a; #a() {}",
    "accessor #a; accessor #a;",
    nullptr
  };
  // clang-format on

  RunParserSyncTest(context_data, class_body_data, kError);
}

TEST_F(ParsingTest, PrivateClassFieldsNoErrors) {
  // clang-format off
  // Tests proposed class fields syntax.
  const char* context_data[][2] = {{"(class {", "});"},
                                   {"(class extends Base {", "});"},
                                   {"class C {", "}"},
                                   {"class C extends Base {", "}"},
                                   {nullptr, nullptr}};
  const char* class_body_data[] = {
    // Basic syntax
    "#a = 0;",
    "#a = 0; #b",
    "#a = 0; b",
    "#a = 0; b(){}",
    "#a = 0; *b(){}",
    "#a = 0; ['b'](){}",
    "#a;",
    "#a; #b;",
    "#a; b;",
    "#a; b(){}",
    "#a; *b(){}",
    "#a; ['b'](){}",

    // ASI
    "#a = 0\n",
    "#a = 0\n #b",
    "#a = 0\n b",
    "#a = 0\n b(){}",
    "#a\n",
    "#a\n #b\n",
    "#a\n b\n",
    "#a\n b(){}",
    "#a\n *b(){}",
    "#a\n ['b'](){}",

    // ASI edge cases
    "#a\n get",
    "#get\n *a(){}",
    "#a\n static",

    "#a = function t() { arguments; }",
    "#a = () => function() { arguments; }",

    // Misc edge cases
    "#yield",
    "#yield = 0",
    "#yield\n a",
    "#async;",
    "#async = 0;",
    "#async",
    "#async = 0",
    "#async\n a(){}",  // a field named async, and a method named a.
    "#async\n a",
    "#await;",
    "#await = 0;",
    "#await\n a",
    nullptr
  };
  // clang-format on

  RunParserSyncTest(context_data, class_body_data, kSuccess);
}

TEST_F(ParsingTest, PrivateAutoAccessorsNoErrors) {
  FLAG_SCOPE(js_decorators);
  // clang-format off
  // Tests proposed class fields syntax.
  const char* context_data[][2] = {{"(class {", "});"},
                                   {"(class extends Base {", "});"},
                                   {"class C {", "}"},
                                   {"class C extends Base {", "}"},
                                   {nullptr, nullptr}};
  const char* class_body_data[] = {
    // Basic syntax
    "accessor #a = 0;",
    "accessor #a = 0; #b",
    "accessor #a = 0; b",
    "accessor #a = 0; b(){}",
    "accessor #a = 0; *b(){}",
    "accessor #a = 0; ['b'](){}",
    "accessor #a;",
    "accessor #a; #b;",
    "accessor #a; b;",
    "accessor #a; b(){}",
    "accessor #a; *b(){}",
    "accessor #a; ['b'](){}",

    // ASI
    "accessor #a = 0\n",
    "accessor #a = 0\n #b",
    "accessor #a = 0\n b",
    "accessor #a = 0\n b(){}",
    "accessor #a\n",
    "accessor #a\n #b\n",
    "accessor #a\n b\n",
    "accessor #a\n b(){}",
    "accessor #a\n *b(){}",
    "accessor #a\n ['b'](){}",

    // ASI edge cases
    "accessor #a\n get",
    "accessor #get\n *a(){}",
    "accessor #a\n static",

    "accessor #a = function t() { arguments; }",
    "accessor #a = () => function() { arguments; }",

    // Misc edge cases
    "accessor #yield",
    "accessor #yield = 0",
    "accessor #yield\n a",
    "accessor #async;",
    "accessor #async = 0;",
    "accessor #async",
    "accessor #async = 0",
    "accessor #async\n a(){}",  // a field named async, and a method named a.
    "accessor #async\n a",
    "accessor #await;",
    "accessor #await = 0;",
    "accessor #await\n a",
    "accessor #accessor;",
    "accessor #accessor = 0;",
    "accessor #accessor\n a",
    nullptr
  };
  // clang-format on

  RunParserSyncTest(context_data, class_body_data, kSuccess);
}

TEST_F(ParsingTest, StaticClassFieldsErrors) {
  // clang-format off
  // Tests proposed class fields syntax.
  const char* context_data[][2] = {{"(class {", "});"},
                                   {"(class extends Base {", "});"},
                                   {"class C {", "}"},
                                   {"class C extends Base {", "}"},
                                   {nullptr, nullptr}};
  const char* class_body_data[] = {
    "static a : 0",
    "static a =",
    "static constructor",
    "static prototype",
    "static *a = 0",
    "static *a",
    "static get a",
    "static get\n a",
    "static yield a",
    "static async a = 0",
    "static async a",

    "static a = arguments",
    "static a = () => arguments",
    "static a = () => { arguments }",
    "static a = arguments[0]",
    "static a = delete arguments[0]",
    "static a = f(arguments)",
    "static a = () => () => arguments",

    // ASI requires a linebreak
    "static a b",
    "static a = 0 b",

    "static c = [1] = [c]",

    // ASI requires that the next token is not part of any legal production
    "static a = 0\n *b(){}",
    "static a = 0\n ['b'](){}",
    nullptr
  };
  // clang-format on

  RunParserSyncTest(context_data, class_body_data, kError);
}

TEST_F(ParsingTest, ClassFieldsErrors) {
  // clang-format off
  // Tests proposed class fields syntax.
  const char* context_data[][2] = {{"(class {", "});"},
                                   {"(class extends Base {", "});"},
                                   {"class C {", "}"},
                                   {"class C extends Base {", "}"},
                                   {nullptr, nullptr}};
  const char* class_body_data[] = {
    "a : 0",
    "a =",
    "constructor",
    "*a = 0",
    "*a",
    "get a",
    "yield a",
    "async a = 0",
    "async a",

    "a = arguments",
    "a = () => arguments",
    "a = () => { arguments }",
    "a = arguments[0]",
    "a = delete arguments[0]",
    "a = f(arguments)",
    "a = () => () => arguments",

    // ASI requires a linebreak
    "a b",
    "a = 0 b",

    "c = [1] = [c]",

    // ASI requires that the next token is not part of any legal production
    "a = 0\n *b(){}",
    "a = 0\n ['b'](){}",
    "get\n a",
    nullptr
  };
  // clang-format on

  RunParserSyncTest(context_data, class_body_data, kError);
}

TEST_F(ParsingTest, PublicAutoAccessorsInstanceAndStaticErrors) {
  FLAG_SCOPE(js_decorators);
  // clang-format off
  // Tests proposed class fields syntax.
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
    "accessor a : 0",
    "accessor a =",
    "accessor constructor",
    "accessor *a = 0",
    "accessor *a",
    "accessor get a",
    "accessor yield a",
    "accessor async a = 0",
    "accessor async a",

    "accessor a = arguments",
    "accessor a = () => arguments",
    "accessor a = () => { arguments }",
    "accessor a = arguments[0]",
    "accessor a = delete arguments[0]",
    "accessor a = f(arguments)",
    "accessor a = () => () => arguments",

    // The accessir keyword can only be applied to fields
    "accessor a() {}",
    "accessor *a() {}",
    "accessor async a() {}",
    "accessor get a() {}",
    "accessor set a(foo) {}",

    // ASI requires a linebreak
    "accessor a b",
    "accessor a = 0 b",

    "accessor c = [1] = [c]",

    // ASI requires that the next token is not part of any legal production
    "accessor a = 0\n *b(){}",
    "accessor a = 0\n ['b'](){}",
    "accessor get\n a",
    nullptr

    // ASI
  };
  // clang-format on

  RunParserSyncTest(context_data, class_body_data, kError);
}

TEST_F(ParsingTest, PrivateClassFieldsErrors) {
  // clang-format off
  // Tests proposed class fields syntax.
  const char* context_data[][2] = {{"(class {", "});"},
                                   {"(class extends Base {", "});"},
                                   {"class C {", "}"},
                                   {"class C extends Base {", "}"},
                                   {nullptr, nullptr}};
  const char* class_body_data[] = {
    "#a : 0",
    "#a =",
    "#*a = 0",
    "#*a",
    "#get a",
    "#yield a",
    "#async a = 0",
    "#async a",

    "#a; #a",
    "#a = 1; #a",
    "#a; #a = 1;",

    "#constructor",
    "#constructor = function() {}",

    "# a = 0",
    "#get a() { }",
    "#set a() { }",
    "#*a() { }",
    "async #*a() { }",

    "#0 = 0;",
    "#0;",
    "#'a' = 0;",
    "#'a';",

    "#['a']",
    "#['a'] = 1",
    "#[a]",
    "#[a] = 1",

    "#a = arguments",
    "#a = () => arguments",
    "#a = () => { arguments }",
    "#a = arguments[0]",
    "#a = delete arguments[0]",
    "#a = f(arguments)",
    "#a = () => () => arguments",

    "foo() { delete this.#a }",
    "foo() { delete this.x.#a }",
    "foo() { delete this.x().#a }",

    "foo() { delete this?.#a }",
    "foo() { delete this.x?.#a }",
    "foo() { delete this?.x.#a }",
    "foo() { delete this.x()?.#a }",
    "foo() { delete this?.x().#a }",

    "foo() { delete f.#a }",
    "foo() { delete f.x.#a }",
    "foo() { delete f.x().#a }",

    "foo() { delete f?.#a }",
    "foo() { delete f.x?.#a }",
    "foo() { delete f?.x.#a }",
    "foo() { delete f.x()?.#a }",
    "foo() { delete f?.x().#a }",

    // ASI requires a linebreak
    "#a b",
    "#a = 0 b",

    // ASI requires that the next token is not part of any legal production
    "#a = 0\n *b(){}",
    "#a = 0\n ['b'](){}",
    nullptr
  };
  // clang-format on

  RunParserSyncTest(context_data, class_body_data, kError);
}

TEST_F(ParsingTest, PrivateClassAutoAccessorsErrors) {
  FLAG_SCOPE(js_decorators);
  // clang-format off
  // Tests proposed class fields syntax.
  const char* context_data[][2] = {{"(class {", "});"},
                                   {"(class extends Base {", "});"},
                                   {"class C {", "}"},
                                   {"class C extends Base {", "}"},
                                   {nullptr, nullptr}};
  const char* class_body_data[] = {
    // The accessor keyword can only be applied to class fields.
    "accessor #a() {}",
    "accessor *#a() {}",
    "accessor async #a() {}",
    "accessor get #a() {}",
    "accessor set #a(foo) {}",
    "accessor async #a() {}",
    "accessor async *#a() {}",

    // Accessors should throw the same errors are regular private fields.
    "accessor #a : 0",
    "accessor #a =",
    "accessor #*a = 0",
    "accessor #*a",
    "accessor #get a",
    "accessor #yield a",
    "accessor #async a = 0",
    "accessor #async a",

    "accessor #a; #a",
    "accessor #a = 1; #a",
    "accessor #a; #a = 1;",

    "accessor #constructor",
    "accessor #constructor = function() {}",

    "accessor # a = 0",
    "accessor #get a() { }",
    "accessor #set a() { }",
    "accessor #*a() { }",
    "accessor async #*a() { }",

    "accessor #0 = 0;",
    "accessor #0;",
    "accessor #'a' = 0;",
    "accessor #'a';",

    "accessor #['a']",
    "accessor #['a'] = 1",
    "accessor #[a]",
    "accessor #[a] = 1",

    "accessor #a = arguments",
    "accessor #a = () => arguments",
    "accessor #a = () => { arguments }",
    "accessor #a = arguments[0]",
    "accessor #a = delete arguments[0]",
    "accessor #a = f(arguments)",
    "accessor #a = () => () => arguments",

    // ASI requires a linebreak
    "accessor #a b",
    "accessor #a = 0 b",

    // ASI requires that the next token is not part of any legal production
    "accessor #a = 0\n *b(){}",
    "accessor #a = 0\n ['b'](){}",
    nullptr
  };
  // clang-format on

  RunParserSyncTest(context_data, class_body_data, kError);
}

TEST_F(ParsingTest, PrivateStaticClassFieldsNoErrors) {
  // clang-format off
  // Tests proposed class fields syntax.
  const char* context_data[][2] = {{"(class {", "});"},
                                   {"(class extends Base {", "});"},
                                   {"class C {", "}"},
                                   {"class C extends Base {", "}"},
                                   {nullptr, nullptr}};
  const char* class_body_data[] = {
    // Basic syntax
    "static #a = 0;",
    "static #a = 0; b",
    "static #a = 0; #b",
    "static #a = 0; b(){}",
    "static #a = 0; *b(){}",
    "static #a = 0; ['b'](){}",
    "static #a;",
    "static #a; b;",
    "static #a; b(){}",
    "static #a; *b(){}",
    "static #a; ['b'](){}",

    "#prototype",
    "#prototype = function() {}",

    // ASI
    "static #a = 0\n",
    "static #a = 0\n b",
    "static #a = 0\n #b",
    "static #a = 0\n b(){}",
    "static #a\n",
    "static #a\n b\n",
    "static #a\n #b\n",
    "static #a\n b(){}",
    "static #a\n *b(){}",
    "static #a\n ['b'](){}",

    "static #a = function t() { arguments; }",
    "static #a = () => function t() { arguments; }",

    // ASI edge cases
    "static #a\n get",
    "static #get\n *a(){}",
    "static #a\n static",

    // Misc edge cases
    "static #yield",
    "static #yield = 0",
    "static #yield\n a",
    "static #async;",
    "static #async = 0;",
    "static #async",
    "static #async = 0",
    "static #async\n a(){}",  // a field named async, and a method named a.
    "static #async\n a",
    "static #await;",
    "static #await = 0;",
    "static #await\n a",
    nullptr
  };
  // clang-format on

  RunParserSyncTest(context_data, class_body_data, kSuccess, nullptr);
}

TEST_F(ParsingTest, PrivateStaticAutoAccessorsNoErrors) {
  FLAG_SCOPE(js_decorators);
  // clang-format off
  // Tests proposed class fields syntax.
  const char* context_data[][2] = {{"(class {", "});"},
                                   {"(class extends Base {", "});"},
                                   {"class C {", "}"},
                                   {"class C extends Base {", "}"},
                                   {nullptr, nullptr}};
  const char* class_body_data[] = {
    // Basic syntax
    "static accessor #a = 0;",
    "static accessor #a = 0; b",
    "static accessor #a = 0; #b",
    "static accessor #a = 0; b(){}",
    "static accessor #a = 0; *b(){}",
    "static accessor #a = 0; ['b'](){}",
    "static accessor #a;",
    "static accessor #a; b;",
    "static accessor #a; b(){}",
    "static accessor #a; *b(){}",
    "static accessor #a; ['b'](){}",

    // ASI
    "static accessor #a = 0\n",
    "static accessor #a = 0\n b",
    "static accessor #a = 0\n #b",
    "static accessor #a = 0\n b(){}",
    "static accessor #a\n",
    "static accessor #a\n b\n",
    "static accessor #a\n #b\n",
    "static accessor #a\n b(){}",
    "static accessor #a\n *b(){}",
    "static accessor #a\n ['b'](){}",

    "static accessor #a = function t() { arguments; }",
    "static accessor #a = () => function t() { arguments; }",

    // ASI edge cases
    "static accessor #a\n get",
    "static accessor #get\n *a(){}",
    "static accessor #a\n static",

    // Misc edge cases
    "static accessor #yield",
    "static accessor #yield = 0",
    "static accessor #yield\n a",
    "static accessor #async;",
    "static accessor #async = 0;",
    "static accessor #async",
    "static accessor #async = 0",
    // A field named async, and a method named a.
    "static accessor #async\n a(){}",
    "static accessor #async\n a",
    "static accessor #await;",
    "static accessor #await = 0;",
    "static accessor #await\n a",
    nullptr
  };
  // clang-format on

  RunParserSyncTest(context_data, class_body_data, kSuccess, nullptr);
}

TEST_F(ParsingTest, PrivateStaticClassFieldsErrors) {
  // clang-format off
  // Tests proposed class fields syntax.
  const char* context_data[][2] = {{"(class {", "});"},
                                   {"(class extends Base {", "});"},
                                   {"class C {", "}"},
                                   {"class C extends Base {", "}"},
                                   {nullptr, nullptr}};
  const char* class_body_data[] = {
    // Basic syntax
    "static #['a'] = 0;",
    "static #['a'] = 0; b",
    "static #['a'] = 0; #b",
    "static #['a'] = 0; b(){}",
    "static #['a'] = 0; *b(){}",
    "static #['a'] = 0; ['b'](){}",
    "static #['a'];",
    "static #['a']; b;",
    "static #['a']; #b;",
    "static #['a']; b(){}",
    "static #['a']; *b(){}",
    "static #['a']; ['b'](){}",

    "static #0 = 0;",
    "static #0;",
    "static #'a' = 0;",
    "static #'a';",

    "static # a = 0",
    "static #get a() { }",
    "static #set a() { }",
    "static #*a() { }",
    "static async #*a() { }",

    "#a = arguments",
    "#a = () => arguments",
    "#a = () => { arguments }",
    "#a = arguments[0]",
    "#a = delete arguments[0]",
    "#a = f(arguments)",
    "#a = () => () => arguments",

    "#a; static #a",
    "static #a; #a",

    // ASI
    "static #['a'] = 0\n",
    "static #['a'] = 0\n b",
    "static #['a'] = 0\n #b",
    "static #['a'] = 0\n b(){}",
    "static #['a']\n",
    "static #['a']\n b\n",
    "static #['a']\n #b\n",
    "static #['a']\n b(){}",
    "static #['a']\n *b(){}",
    "static #['a']\n ['b'](){}",

    // ASI requires a linebreak
    "static #a b",
    "static #a = 0 b",

    // ASI requires that the next token is not part of any legal production
    "static #a = 0\n *b(){}",
    "static #a = 0\n ['b'](){}",

    "static #a : 0",
    "static #a =",
    "static #*a = 0",
    "static #*a",
    "static #get a",
    "static #yield a",
    "static #async a = 0",
    "static #async a",
    "static # a = 0",

    "#constructor",
    "#constructor = function() {}",

    "foo() { delete this.#a }",
    "foo() { delete this.x.#a }",
    "foo() { delete this.x().#a }",

    "foo() { delete f.#a }",
    "foo() { delete f.x.#a }",
    "foo() { delete f.x().#a }",
    nullptr
  };
  // clang-format on

  RunParserSyncTest(context_data, class_body_data, kError);
}

TEST_F(ParsingTest, PrivateStaticAutoAccessorsErrors) {
  FLAG_SCOPE(js_decorators);
  // clang-format off
  // Tests proposed class fields syntax.
  const char* context_data[][2] = {{"(class {", "});"},
                                   {"(class extends Base {", "});"},
                                   {"class C {", "}"},
                                   {"class C extends Base {", "}"},
                                   {nullptr, nullptr}};
  const char* class_body_data[] = {
    // The accessor keyword can only be applied to class fields.
    "static accessor #a() {}",
    "static accessor *#a() {}",
    "static accessor async #a() {}",
    "static accessor get #a() {}",
    "static accessor set #a(foo) {}",
    "static accessor async #a() {}",
    "static accessor async *#a() {}",

    // Accessors should throw the same errors are regular private fields.
    // Basic syntax
    "static accessor #['a'] = 0;",
    "static accessor #['a'] = 0; b",
    "static accessor #['a'] = 0; #b",
    "static accessor #['a'] = 0; b(){}",
    "static accessor #['a'] = 0; *b(){}",
    "static accessor #['a'] = 0; ['b'](){}",
    "static accessor #['a'];",
    "static accessor #['a']; b;",
    "static accessor #['a']; #b;",
    "static accessor #['a']; b(){}",
    "static accessor #['a']; *b(){}",
    "static accessor #['a']; ['b'](){}",

    "static accessor #0 = 0;",
    "static accessor #0;",
    "static accessor #'a' = 0;",
    "static accessor #'a';",

    "static accessor # a = 0",
    "static accessor #get a() { }",
    "static accessor #set a() { }",
    "static accessor #*a() { }",
    "static accessor async #*a() { }",

    "#a; static accessor #a",
    "static accessor #a; #a",

    // ASI
    "static accessor #['a'] = 0\n",
    "static accessor #['a'] = 0\n b",
    
"""


```