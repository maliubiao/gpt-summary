Response: The user wants to understand the functionality of a C++ source code file related to parsing in the V8 JavaScript engine.

Here's a breakdown of the thought process to analyze the provided code:

1. **Identify the core purpose:** The filename `parsing-unittest.cc` and the numerous `TEST_F(ParsingTest, ...)` blocks strongly suggest this file contains unit tests for the V8 JavaScript parser.

2. **Examine the test structure:** Each `TEST_F` block defines a specific test case, usually focusing on a particular parsing scenario (e.g., `PrivateNameResolutionErrors`, `ClassExpressionErrors`, `ObjectLiteralPropertyShorthandKeywordsError`, `BasicImportExportParsing`).

3. **Analyze the test data:**  Within each test, there are usually two arrays of C-style strings: `context_data` and another array (e.g., `statement_data`, `class_data`, `name_data`).
    * `context_data`: Provides surrounding code snippets or execution context for the code being tested. This often includes class definitions, function definitions, or `'use strict'` directives.
    * The second array: Contains the specific code snippets being tested.

4. **Look for keywords and patterns:**  Pay attention to keywords related to JavaScript syntax, such as `class`, `static`, `get`, `set`, `async`, `private`, `import`, `export`, `for...in`, `for...of`, template literals (backticks), etc. These indicate the specific language features being tested.

5. **Interpret `kError` and `kSuccess`:** The `RunParserSyncTest` function takes a `kError` or `kSuccess` argument. This clearly indicates whether the test is designed to verify that the parser correctly identifies invalid syntax (`kError`) or successfully parses valid syntax (`kSuccess`).

6. **Infer functionality from test names and data:** Combine the test names with the code snippets in the data arrays to understand what the test is verifying. For instance:
    * `PrivateNameResolutionErrors`: Tests cases where private names (`#a`) are used incorrectly outside their defining class.
    * `ClassExpressionErrors`: Tests various forms of invalid class expressions.
    * `ObjectLiteralPropertyShorthandKeywordsError`: Checks if using reserved keywords as shorthand property names in object literals results in a parsing error.
    * `BasicImportExportParsing`: Verifies the parser correctly handles valid `import` and `export` statements.

7. **Connect to JavaScript functionality:**  Since this is a JavaScript parser test, the tested scenarios directly correspond to JavaScript language features. The goal is to ensure V8's parser adheres to the ECMAScript specification.

8. **Provide JavaScript examples (if applicable):** For tests related to valid syntax, demonstrate the equivalent JavaScript code that would be successfully parsed and its intended behavior. For error cases, show the invalid JavaScript that the parser should reject.

9. **Address the "part X of 8" instruction:**  Acknowledge that this is a segment of a larger file. The current part likely focuses on a specific set of parsing functionalities, and the complete file covers a broader range.

10. **Structure the answer:** Organize the findings into a clear and concise summary, highlighting the main functionalities and providing illustrative JavaScript examples.

**Self-Correction/Refinement during the thought process:**

* **Initial thought:** This file just tests for errors.
* **Correction:**  While many tests use `kError`, some use `kSuccess`, indicating that the file also verifies correct parsing of valid code.
* **Initial thought:** Focus only on the C++ code.
* **Refinement:** The prompt explicitly asks for the relation to JavaScript, so including JavaScript examples is crucial.
* **Considering the "part X of 8":** Avoid making assumptions about the content of the other parts. Focus solely on the functionality demonstrated in the provided snippet.
这个C++源代码文件 `v8/test/unittests/parser/parsing-unittest.cc` 的第5部分，主要功能是 **测试 V8 JavaScript 引擎的解析器 (parser) 在处理各种错误和一些特定语法时的行为**。

具体来说，这一部分包含了多个独立的测试用例 (由 `TEST_F(ParsingTest, ...)` 定义)，每个测试用例针对不同的 JavaScript 语法结构，并验证解析器是否能够：

1. **正确地识别并报告语法错误 (`kError`)：**  这是大部分测试用例的目标。它们提供了各种不符合 JavaScript 语法规则的代码片段，并断言 V8 的解析器能够检测到这些错误。
2. **正确地解析合法的语法 (`kSuccess`)：** 少数测试用例会验证解析器能够成功解析一些特定的、可能是边界情况的合法 JavaScript 代码。

以下是每个测试用例的具体功能归纳：

* **`ParsingTest.PrivateStaticAccessorErrors`**: 测试类中静态私有访问器 (static private accessor) 的各种非法语法。
* **`ParsingTest.PrivateNameResolutionErrors`**: 测试在不正确的上下文中访问私有名称 (`#a`) 时是否会产生错误。这关系到私有字段的访问权限。
* **`ParsingTest.PrivateNameErrors`**: 测试独立使用或以错误方式使用私有名称 (`#foo`) 时是否会产生错误。
* **`ParsingTest.ClassExpressionErrors`**: 测试各种非法的类表达式语法。
* **`ParsingTest.ClassDeclarationErrors`**: 测试各种非法的类声明语法。
* **`ParsingTest.ClassAsyncErrors`**: 测试类中 `async` 关键字与方法定义结合的各种非法语法。
* **`ParsingTest.ClassNameErrors`**: 测试在类声明和类表达式中使用保留字作为类名时是否会产生错误。
* **`ParsingTest.ClassGetterParamNameErrors`**: 测试类 getter 方法的参数名是否使用了保留字。
* **`ParsingTest.ClassStaticPrototypeErrors`**: 测试在类中定义名为 `prototype` 的静态方法或访问器时是否会产生错误，因为 `prototype` 属性在类中具有特殊意义。
* **`ParsingTest.ClassSpecialConstructorErrors`**: 测试在类中定义特殊的 `constructor` getter 或 setter 方法时是否会产生错误，因为构造函数有其特殊语义。
* **`ParsingTest.ClassConstructorNoErrors`**: 测试类中合法的构造函数定义。
* **`ParsingTest.ClassMultipleConstructorErrors`**: 测试在一个类中定义多个构造函数是否会产生错误。
* **`ParsingTest.ClassMultiplePropertyNamesNoErrors`**: 测试在一个类中定义具有相同名称的多个属性（方法、访问器等）是否被允许。
* **`ParsingTest.ClassesAreStrictErrors`**: 测试在类的方法中使用 `with` 语句是否会产生错误，因为类体总是处于严格模式。
* **`ParsingTest.ObjectLiteralPropertyShorthandKeywordsError`**: 测试在对象字面量中使用 JavaScript 关键字作为属性简写时是否会产生错误。
* **`ParsingTest.ObjectLiteralPropertyShorthandStrictKeywords`**: 测试在对象字面量中使用严格模式下的保留字作为属性简写时的行为。
* **`ParsingTest.ObjectLiteralPropertyShorthandError`**: 测试在对象字面量中使用字面量值作为属性简写时是否会产生错误。
* **`ParsingTest.ObjectLiteralPropertyShorthandYieldInGeneratorError`**: 测试在生成器函数中使用 `yield` 作为对象字面量的属性简写时是否会产生错误。
* **`ParsingTest.ConstParsingInForIn`**: 测试 `const` 关键字在 `for...in` 循环中的合法用法。
* **`ParsingTest.StatementParsingInForIn`**: 测试各种声明语句在 `for...in` 循环中的用法。
* **`ParsingTest.ConstParsingInForInError`**: 测试 `const` 关键字在 `for...in` 循环中的非法用法。
* **`ParsingTest.InitializedDeclarationsInForInOf`**: 测试 `for...in` 和 `for...of` 循环中初始化声明的限制。
* **`ParsingTest.ForInMultipleDeclarationsError`**: 测试 `for...in` 循环中声明多个变量是否会产生错误。
* **`ParsingTest.ForOfMultipleDeclarationsError`**: 测试 `for...of` 循环中声明多个变量是否会产生错误。
* **`ParsingTest.ForInOfLetExpression`**: 测试 `let.x` 表达式在 `for...in` 和 `for...of` 循环中的用法。
* **`ParsingTest.ForInNoDeclarationsError`**: 测试 `for...in` 循环中缺少变量声明是否会产生错误。
* **`ParsingTest.ForOfNoDeclarationsError`**: 测试 `for...of` 循环中缺少变量声明是否会产生错误。
* **`ParsingTest.ForOfInOperator`**: 测试 `for...of` 循环中使用 `in` 运算符的行为。
* **`ParsingTest.ForOfYieldIdentifier`**: 测试 `yield` 关键字在 `for...of` 循环中的用法。
* **`ParsingTest.ForOfYieldExpression`**: 测试 `yield` 表达式在生成器函数的 `for...of` 循环中的用法。
* **`ParsingTest.ForOfExpressionError`**: 测试 `for...of` 循环中表达式的非法用法。
* **`ParsingTest.ForOfAsync`**: 测试 `async` 关键字在 `for...of` 循环中的用法。
* **`ParsingTest.InvalidUnicodeEscapes`**: 测试各种无效的 Unicode 转义序列。
* **`ParsingTest.UnicodeEscapes`**: 测试有效的 Unicode 转义序列。
* **`ParsingTest.OctalEscapes`**: 测试八进制转义序列在严格模式和非严格模式下的行为差异。
* **`ParsingTest.ScanTemplateLiterals`**: 测试模板字面量的扫描。
* **`ParsingTest.ScanTaggedTemplateLiterals`**: 测试带标签的模板字面量的扫描。
* **`ParsingTest.TemplateMaterializedLiterals`**: 测试模板字面量的物化。
* **`ParsingTest.ScanUnterminatedTemplateLiterals`**: 测试未终止的模板字面量是否会产生错误。
* **`ParsingTest.TemplateLiteralsIllegalTokens`**: 测试模板字面量中包含非法 token 是否会产生错误。
* **`ParsingTest.ParseRestParameters`**: 测试函数参数中的剩余参数 (rest parameters) 的合法语法。
* **`ParsingTest.ParseRestParametersErrors`**: 测试函数参数中的剩余参数的非法语法。
* **`ParsingTest.RestParameterInSetterMethodError`**: 测试在 setter 方法中使用剩余参数是否会产生错误。
* **`ParsingTest.RestParametersEvalArguments`**: 测试剩余参数是否可以使用 `eval` 或 `arguments` 作为参数名。
* **`ParsingTest.RestParametersDuplicateEvalArguments`**: 测试剩余参数中是否存在重复的 `eval` 或 `arguments` 参数名。
* **`ParsingTest.SpreadCall`**: 测试函数调用中使用扩展运算符 (spread operator) 的合法语法。
* **`ParsingTest.SpreadCallErrors`**: 测试函数调用中使用扩展运算符的非法语法。
* **`ParsingTest.BadRestSpread`**: 测试在错误的位置使用剩余参数或扩展运算符。
* **`ParsingTest.LexicalScopingSloppyMode`**: 测试在非严格模式下的词法作用域 (`let`)。
* **`ParsingTest.ComputedPropertyName`**: 测试对象字面量和类中计算属性名 (computed property names) 的语法。
* **`ParsingTest.ComputedPropertyNameShorthandError`**: 测试计算属性名与属性简写结合使用时的错误。
* **`ParsingTest.BasicImportExportParsing`**: 测试基本的 `import` 和 `export` 语句的解析。
* **`ParsingTest.NamespaceExportParsing`**: 测试命名空间导出 (`export * as ...`) 的解析。
* **`ParsingTest.ImportExportParsingErrors`**: 测试各种非法的 `import` 和 `export` 语句。
* **`ParsingTest.ModuleTopLevelFunctionDecl`**: 测试模块顶层作用域中重复的函数声明是否会产生错误。
* **`ParsingTest.ModuleAwaitReserved`**: 测试在模块中使用 `await` 作为标识符（变量名、函数名等）是否会产生错误，因为 `await` 在模块中是保留字。
* **`ParsingTest.ModuleAwaitReservedPreParse`**: 测试在模块的函数中使用 `await` 作为变量名是否会产生错误。
* **`ParsingTest.ModuleAwaitPermitted`**: 测试在模块中允许使用 `await` 的场景（例如，作为对象属性名）。
* **`ParsingTest.EnumReserved`**: 测试在模块中使用 `enum` 作为标识符是否会产生错误，因为 `enum` 是保留字。
* **`ParsingTest.ModuleParsingInternals`**:  更深入地测试模块解析的内部结构，例如模块作用域中的声明和导出/导入条目。
* **`ParsingTest.ModuleParsingInternalsWithImportAttributes`**: 测试带有导入属性 (import attributes) 的模块解析内部结构。

**与 JavaScript 功能的关系及示例：**

这些测试用例直接对应于 JavaScript 语言的各种特性。以下举例说明一些测试用例与 JavaScript 功能的关系：

**1. `ParsingTest.PrivateNameResolutionErrors` (私有名称解析错误):**

```javascript
class MyClass {
  #privateField = 0;

  getPrivate() {
    return this.#privateField; // 正确访问
  }
}

const instance = new MyClass();
console.log(instance.getPrivate()); // 输出 0

// 以下代码在 JavaScript 中会报错，测试用例会验证解析器能识别这种错误
// console.log(instance.#privateField); // 外部无法直接访问私有字段
// function foo() {
//   console.log(this.#privateField); // 在非 MyClass 实例的上下文中访问
// }
```

**2. `ParsingTest.ClassExpressionErrors` (类表达式错误):**

```javascript
// 合法的类表达式
const MyClass = class {};
const MyNamedClass = class Named {};

// 以下代码在 JavaScript 中会报错，测试用例会验证解析器能识别这种错误
// class; // 缺少类名
// class extends; // extends 后面缺少基类
// class { // 缺少闭合大括号
```

**3. `ParsingTest.ObjectLiteralPropertyShorthandKeywordsError` (对象字面量属性简写关键字错误):**

```javascript
const myVar = 10;
const myObj = { myVar }; // 合法的属性简写，等价于 { myVar: myVar }

// 以下代码在 JavaScript 中会报错，测试用例会验证解析器能识别这种错误
// const obj = { if }; // 'if' 是关键字，不能作为属性简写
```

**4. `ParsingTest.BasicImportExportParsing` (基本的导入导出解析):**

```javascript
// 假设有一个名为 'module.js' 的文件，内容如下：
// export const myConstant = 42;
// export function myFunction() { console.log('Hello'); }

// 在另一个文件中：
import { myConstant, myFunction } from './module.js';
console.log(myConstant); // 输出 42
myFunction(); // 输出 'Hello'

// 以下代码在 JavaScript 中会报错，测试用例会验证解析器能识别这种错误
// export {; // 导出语法错误
// import { from './module.js'; // 导入语法错误
```

总而言之，这个 C++ 文件是 V8 引擎解析器功能测试的重要组成部分，它通过大量的测试用例确保了解析器能够准确地识别合法的 JavaScript 代码，并有效地捕获各种语法错误，保证了 JavaScript 代码的正确执行。

### 提示词
```
这是目录为v8/test/unittests/parser/parsing-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第5部分，共8部分，请归纳一下它的功能
```

### 源代码
```
"static accessor #['a'] = 0\n #b",
    "static accessor #['a'] = 0\n b(){}",
    "static accessor #['a']\n",
    "static accessor #['a']\n b\n",
    "static accessor #['a']\n #b\n",
    "static accessor #['a']\n b(){}",
    "static accessor #['a']\n *b(){}",
    "static accessor #['a']\n ['b'](){}",

    // ASI requires a linebreak
    "static accessor #a b",
    "static accessor #a = 0 b",

    // ASI requires that the next token is not part of any legal production
    "static accessor #a = 0\n *b(){}",
    "static accessor #a = 0\n ['b'](){}",

    "static accessor #a : 0",
    "static accessor #a =",
    "static accessor #*a = 0",
    "static accessor #*a",
    "static accessor #get a",
    "static accessor #yield a",
    "static accessor #async a = 0",
    "static accessor #async a",
    "static accessor # a = 0",
    nullptr
  };
  // clang-format on

  RunParserSyncTest(context_data, class_body_data, kError);
}

TEST_F(ParsingTest, PrivateNameResolutionErrors) {
  // clang-format off
  const char* context_data[][2] = {
      {"class X { bar() { ", " } }"},
      {"\"use strict\";", ""},
      {nullptr, nullptr}
  };

  const char* statement_data[] = {
    "this.#a",
    "this.#a()",
    "this.#b.#a",
    "this.#b.#a()",

    "foo.#a",
    "foo.#a()",
    "foo.#b.#a",
    "foo.#b.#a()",

    "foo().#a",
    "foo().b.#a",
    "foo().b().#a",
    "foo().b().#a()",
    "foo().b().#a.bar",
    "foo().b().#a.bar()",

    "foo(this.#a)",
    "foo(bar().#a)",

    "new foo.#a",
    "new foo.#b.#a",
    "new foo.#b.#a()",

    "foo.#if;",
    "foo.#yield;",
    "foo.#super;",
    "foo.#interface;",
    "foo.#eval;",
    "foo.#arguments;",

    nullptr
  };

  // clang-format on
  RunParserSyncTest(context_data, statement_data, kError);
}

TEST_F(ParsingTest, PrivateNameErrors) {
  // clang-format off
  const char* context_data[][2] = {
      {"", ""},
      {"function t() { ", " }"},
      {"var t => { ", " }"},
      {"var t = { [ ", " ] }"},
      {"\"use strict\";", ""},
      {nullptr, nullptr}
  };

  const char* statement_data[] = {
    "#foo",
    "#foo = 1",

    "# a;",
    "#\n a;",
    "a, # b",
    "a, #, b;",

    "foo.#[a];",
    "foo.#['a'];",

    "foo()#a",
    "foo()#[a]",
    "foo()#['a']",

    "super.#a;",
    "super.#a = 1;",
    "super.#['a']",
    "super.#[a]",

    "new.#a",
    "new.#[a]",

    "foo.#{;",
    "foo.#};",
    "foo.#=;",
    "foo.#888;",
    "foo.#-;",
    "foo.#--;",
    nullptr
  };

  // clang-format on
  RunParserSyncTest(context_data, statement_data, kError);
}

TEST_F(ParsingTest, ClassExpressionErrors) {
  const char* context_data[][2] = {
      {"(", ");"}, {"var C = ", ";"}, {"bar, ", ";"}, {nullptr, nullptr}};
  const char* class_data[] = {
      "class",
      "class name",
      "class name extends",
      "class extends",
      "class {",
      "class { m: 1 }",
      "class { m(); n() }",
      "class { get m }",
      "class { get m() }",
      "class { get m() { }",
      "class { set m() {} }",      // Missing required parameter.
      "class { m() {}, n() {} }",  // No commas allowed.
      nullptr};

  RunParserSyncTest(context_data, class_data, kError);
}

TEST_F(ParsingTest, ClassDeclarationErrors) {
  const char* context_data[][2] = {
      {"", ""}, {"{", "}"}, {"if (true) {", "}"}, {nullptr, nullptr}};
  const char* class_data[] = {
      "class",
      "class name",
      "class name extends",
      "class extends",
      "class name {",
      "class name { m: 1 }",
      "class name { m(); n() }",
      "class name { get x }",
      "class name { get x() }",
      "class name { set x() {) }",  // missing required param
      "class {}",                   // Name is required for declaration
      "class extends base {}",
      "class name { *",
      "class name { * }",
      "class name { *; }",
      "class name { *get x() {} }",
      "class name { *set x(_) {} }",
      "class name { *static m() {} }",
      nullptr};

  RunParserSyncTest(context_data, class_data, kError);
}

TEST_F(ParsingTest, ClassAsyncErrors) {
  // clang-format off
  const char* context_data[][2] = {{"(class {", "});"},
                                   {"(class extends Base {", "});"},
                                   {"class C {", "}"},
                                   {"class C extends Base {", "}"},
                                   {nullptr, nullptr}};
  const char* async_data[] = {
    "*async x(){}",
    "async *(){}",
    "async get x(){}",
    "async set x(y){}",
    "async x : 0",
    "async : 0",

    "async static x(){}",

    "static *async x(){}",
    "static async *(){}",
    "static async get x(){}",
    "static async set x(y){}",
    "static async x : 0",
    "static async : 0",
    nullptr
  };
  // clang-format on

  RunParserSyncTest(context_data, async_data, kError);
}

TEST_F(ParsingTest, ClassNameErrors) {
  const char* context_data[][2] = {{"class ", "{}"},
                                   {"(class ", "{});"},
                                   {"'use strict'; class ", "{}"},
                                   {"'use strict'; (class ", "{});"},
                                   {nullptr, nullptr}};
  const char* class_name[] = {"arguments", "eval",    "implements", "interface",
                              "let",       "package", "private",    "protected",
                              "public",    "static",  "var",        "yield",
                              nullptr};

  RunParserSyncTest(context_data, class_name, kError);
}

TEST_F(ParsingTest, ClassGetterParamNameErrors) {
  const char* context_data[][2] = {
      {"class C { get name(", ") {} }"},
      {"(class { get name(", ") {} });"},
      {"'use strict'; class C { get name(", ") {} }"},
      {"'use strict'; (class { get name(", ") {} })"},
      {nullptr, nullptr}};

  const char* class_name[] = {"arguments", "eval",    "implements", "interface",
                              "let",       "package", "private",    "protected",
                              "public",    "static",  "var",        "yield",
                              nullptr};

  RunParserSyncTest(context_data, class_name, kError);
}

TEST_F(ParsingTest, ClassStaticPrototypeErrors) {
  const char* context_data[][2] = {
      {"class C {", "}"}, {"(class {", "});"}, {nullptr, nullptr}};

  const char* class_body_data[] = {"static prototype() {}",
                                   "static get prototype() {}",
                                   "static set prototype(_) {}",
                                   "static *prototype() {}",
                                   "static 'prototype'() {}",
                                   "static *'prototype'() {}",
                                   "static prot\\u006ftype() {}",
                                   "static 'prot\\u006ftype'() {}",
                                   "static get 'prot\\u006ftype'() {}",
                                   "static set 'prot\\u006ftype'(_) {}",
                                   "static *'prot\\u006ftype'() {}",
                                   nullptr};

  RunParserSyncTest(context_data, class_body_data, kError);
}

TEST_F(ParsingTest, ClassSpecialConstructorErrors) {
  const char* context_data[][2] = {
      {"class C {", "}"}, {"(class {", "});"}, {nullptr, nullptr}};

  const char* class_body_data[] = {"get constructor() {}",
                                   "get constructor(_) {}",
                                   "*constructor() {}",
                                   "get 'constructor'() {}",
                                   "*'constructor'() {}",
                                   "get c\\u006fnstructor() {}",
                                   "*c\\u006fnstructor() {}",
                                   "get 'c\\u006fnstructor'() {}",
                                   "get 'c\\u006fnstructor'(_) {}",
                                   "*'c\\u006fnstructor'() {}",
                                   nullptr};

  RunParserSyncTest(context_data, class_body_data, kError);
}

TEST_F(ParsingTest, ClassConstructorNoErrors) {
  const char* context_data[][2] = {
      {"class C {", "}"}, {"(class {", "});"}, {nullptr, nullptr}};

  const char* class_body_data[] = {"constructor() {}",
                                   "static constructor() {}",
                                   "static get constructor() {}",
                                   "static set constructor(_) {}",
                                   "static *constructor() {}",
                                   nullptr};

  RunParserSyncTest(context_data, class_body_data, kSuccess);
}

TEST_F(ParsingTest, ClassMultipleConstructorErrors) {
  const char* context_data[][2] = {
      {"class C {", "}"}, {"(class {", "});"}, {nullptr, nullptr}};

  const char* class_body_data[] = {"constructor() {}; constructor() {}",
                                   nullptr};

  RunParserSyncTest(context_data, class_body_data, kError);
}

TEST_F(ParsingTest, ClassMultiplePropertyNamesNoErrors) {
  const char* context_data[][2] = {
      {"class C {", "}"}, {"(class {", "});"}, {nullptr, nullptr}};

  const char* class_body_data[] = {
      "constructor() {}; static constructor() {}",
      "m() {}; static m() {}",
      "m() {}; m() {}",
      "static m() {}; static m() {}",
      "get m() {}; set m(_) {}; get m() {}; set m(_) {};",
      nullptr};

  RunParserSyncTest(context_data, class_body_data, kSuccess);
}

TEST_F(ParsingTest, ClassesAreStrictErrors) {
  const char* context_data[][2] = {{"", ""}, {"(", ");"}, {nullptr, nullptr}};

  const char* class_body_data[] = {
      "class C { method() { with ({}) {} } }",
      "class C extends function() { with ({}) {} } {}",
      "class C { *method() { with ({}) {} } }", nullptr};

  RunParserSyncTest(context_data, class_body_data, kError);
}

TEST_F(ParsingTest, ObjectLiteralPropertyShorthandKeywordsError) {
  const char* context_data[][2] = {
      {"({", "});"}, {"'use strict'; ({", "});"}, {nullptr, nullptr}};

  const char* name_data[] = {
      "break",    "case",    "catch",  "class",      "const", "continue",
      "debugger", "default", "delete", "do",         "else",  "enum",
      "export",   "extends", "false",  "finally",    "for",   "function",
      "if",       "import",  "in",     "instanceof", "new",   "null",
      "return",   "super",   "switch", "this",       "throw", "true",
      "try",      "typeof",  "var",    "void",       "while", "with",
      nullptr};

  RunParserSyncTest(context_data, name_data, kError);
}

TEST_F(ParsingTest, ObjectLiteralPropertyShorthandStrictKeywords) {
  const char* context_data[][2] = {{"({", "});"}, {nullptr, nullptr}};

  const char* name_data[] = {"implements", "interface", "let",    "package",
                             "private",    "protected", "public", "static",
                             "yield",      nullptr};

  RunParserSyncTest(context_data, name_data, kSuccess);

  const char* context_strict_data[][2] = {{"'use strict'; ({", "});"},
                                          {nullptr, nullptr}};
  RunParserSyncTest(context_strict_data, name_data, kError);
}

TEST_F(ParsingTest, ObjectLiteralPropertyShorthandError) {
  const char* context_data[][2] = {
      {"({", "});"}, {"'use strict'; ({", "});"}, {nullptr, nullptr}};

  const char* name_data[] = {"1",   "1.2", "0",     "0.1", "1.0",
                             "1e1", "0x1", "\"s\"", "'s'", nullptr};

  RunParserSyncTest(context_data, name_data, kError);
}

TEST_F(ParsingTest, ObjectLiteralPropertyShorthandYieldInGeneratorError) {
  const char* context_data[][2] = {{"", ""}, {nullptr, nullptr}};

  const char* name_data[] = {"function* g() { ({yield}); }", nullptr};

  RunParserSyncTest(context_data, name_data, kError);
}

TEST_F(ParsingTest, ConstParsingInForIn) {
  const char* context_data[][2] = {{"'use strict';", ""},
                                   {"function foo(){ 'use strict';", "}"},
                                   {nullptr, nullptr}};

  const char* data[] = {
      "for(const x = 1; ; ) {}", "for(const x = 1, y = 2;;){}",
      "for(const x in [1,2,3]) {}", "for(const x of [1,2,3]) {}", nullptr};
  RunParserSyncTest(context_data, data, kSuccess, nullptr, 0, nullptr, 0);
}

TEST_F(ParsingTest, StatementParsingInForIn) {
  const char* context_data[][2] = {{"", ""},
                                   {"'use strict';", ""},
                                   {"function foo(){ 'use strict';", "}"},
                                   {nullptr, nullptr}};

  const char* data[] = {"for(x in {}, {}) {}", "for(var x in {}, {}) {}",
                        "for(let x in {}, {}) {}", "for(const x in {}, {}) {}",
                        nullptr};

  RunParserSyncTest(context_data, data, kSuccess);
}

TEST_F(ParsingTest, ConstParsingInForInError) {
  const char* context_data[][2] = {{"'use strict';", ""},
                                   {"function foo(){ 'use strict';", "}"},
                                   {nullptr, nullptr}};

  const char* data[] = {
      "for(const x,y = 1; ; ) {}",         "for(const x = 4 in [1,2,3]) {}",
      "for(const x = 4, y in [1,2,3]) {}", "for(const x = 4 of [1,2,3]) {}",
      "for(const x = 4, y of [1,2,3]) {}", "for(const x = 1, y = 2 in []) {}",
      "for(const x,y in []) {}",           "for(const x = 1, y = 2 of []) {}",
      "for(const x,y of []) {}",           nullptr};
  RunParserSyncTest(context_data, data, kError, nullptr, 0, nullptr, 0);
}

TEST_F(ParsingTest, InitializedDeclarationsInForInOf) {
  // https://tc39.github.io/ecma262/#sec-initializers-in-forin-statement-heads

  // Initialized declarations only allowed for
  // - sloppy mode (not strict mode)
  // - for-in (not for-of)
  // - var (not let / const)

  // clang-format off
  const char* strict_context[][2] = {{"'use strict';", ""},
                                     {"function foo(){ 'use strict';", "}"},
                                     {"function* foo(){ 'use strict';", "}"},
                                     {nullptr, nullptr}};

  const char* sloppy_context[][2] = {{"", ""},
                                     {"function foo(){ ", "}"},
                                     {"function* foo(){ ", "}"},
                                     {"function foo(){ var yield = 0; ", "}"},
                                     {nullptr, nullptr}};

  const char* let_const_var_for_of[] = {
      "for (let i = 1 of {}) {}",
      "for (let i = void 0 of [1, 2, 3]) {}",
      "for (const i = 1 of {}) {}",
      "for (const i = void 0 of [1, 2, 3]) {}",
      "for (var i = 1 of {}) {}",
      "for (var i = void 0 of [1, 2, 3]) {}",
      nullptr};

  const char* let_const_for_in[] = {
      "for (let i = 1 in {}) {}",
      "for (let i = void 0 in [1, 2, 3]) {}",
      "for (const i = 1 in {}) {}",
      "for (const i = void 0 in [1, 2, 3]) {}",
      nullptr};

  const char* var_for_in[] = {
      "for (var i = 1 in {}) {}",
      "for (var i = void 0 in [1, 2, 3]) {}",
      "for (var i = yield in [1, 2, 3]) {}",
      nullptr};
  // clang-format on

  // The only allowed case is sloppy + var + for-in.
  RunParserSyncTest(sloppy_context, var_for_in, kSuccess);

  // Everything else is disallowed.
  RunParserSyncTest(sloppy_context, let_const_var_for_of, kError);
  RunParserSyncTest(sloppy_context, let_const_for_in, kError);

  RunParserSyncTest(strict_context, let_const_var_for_of, kError);
  RunParserSyncTest(strict_context, let_const_for_in, kError);
  RunParserSyncTest(strict_context, var_for_in, kError);
}

TEST_F(ParsingTest, ForInMultipleDeclarationsError) {
  const char* context_data[][2] = {{"", ""},
                                   {"function foo(){", "}"},
                                   {"'use strict';", ""},
                                   {"function foo(){ 'use strict';", "}"},
                                   {nullptr, nullptr}};

  const char* data[] = {"for (var i, j in {}) {}",
                        "for (var i, j in [1, 2, 3]) {}",
                        "for (var i, j = 1 in {}) {}",
                        "for (var i, j = void 0 in [1, 2, 3]) {}",

                        "for (let i, j in {}) {}",
                        "for (let i, j in [1, 2, 3]) {}",
                        "for (let i, j = 1 in {}) {}",
                        "for (let i, j = void 0 in [1, 2, 3]) {}",

                        "for (const i, j in {}) {}",
                        "for (const i, j in [1, 2, 3]) {}",
                        "for (const i, j = 1 in {}) {}",
                        "for (const i, j = void 0 in [1, 2, 3]) {}",
                        nullptr};
  RunParserSyncTest(context_data, data, kError);
}

TEST_F(ParsingTest, ForOfMultipleDeclarationsError) {
  const char* context_data[][2] = {{"", ""},
                                   {"function foo(){", "}"},
                                   {"'use strict';", ""},
                                   {"function foo(){ 'use strict';", "}"},
                                   {nullptr, nullptr}};

  const char* data[] = {"for (var i, j of {}) {}",
                        "for (var i, j of [1, 2, 3]) {}",
                        "for (var i, j = 1 of {}) {}",
                        "for (var i, j = void 0 of [1, 2, 3]) {}",

                        "for (let i, j of {}) {}",
                        "for (let i, j of [1, 2, 3]) {}",
                        "for (let i, j = 1 of {}) {}",
                        "for (let i, j = void 0 of [1, 2, 3]) {}",

                        "for (const i, j of {}) {}",
                        "for (const i, j of [1, 2, 3]) {}",
                        "for (const i, j = 1 of {}) {}",
                        "for (const i, j = void 0 of [1, 2, 3]) {}",
                        nullptr};
  RunParserSyncTest(context_data, data, kError);
}

TEST_F(ParsingTest, ForInOfLetExpression) {
  const char* sloppy_context_data[][2] = {
      {"", ""}, {"function foo(){", "}"}, {nullptr, nullptr}};

  const char* strict_context_data[][2] = {
      {"'use strict';", ""},
      {"function foo(){ 'use strict';", "}"},
      {nullptr, nullptr}};

  const char* async_context_data[][2] = {
      {"async function foo(){", "}"},
      {"async function foo(){ 'use strict';", "}"},
      {nullptr, nullptr}};

  const char* for_let_in[] = {"for (let.x in {}) {}", nullptr};

  const char* for_let_of[] = {"for (let.x of []) {}", nullptr};

  const char* for_await_let_of[] = {"for await (let.x of []) {}", nullptr};

  // The only place `let.x` is legal as a left-hand side expression
  // is in sloppy mode in a for-in loop.
  RunParserSyncTest(sloppy_context_data, for_let_in, kSuccess);
  RunParserSyncTest(strict_context_data, for_let_in, kError);
  RunParserSyncTest(sloppy_context_data, for_let_of, kError);
  RunParserSyncTest(strict_context_data, for_let_of, kError);
  RunParserSyncTest(async_context_data, for_await_let_of, kError);
}

TEST_F(ParsingTest, ForInNoDeclarationsError) {
  const char* context_data[][2] = {{"", ""},
                                   {"function foo(){", "}"},
                                   {"'use strict';", ""},
                                   {"function foo(){ 'use strict';", "}"},
                                   {nullptr, nullptr}};

  const char* data[] = {"for (var in {}) {}", "for (const in {}) {}", nullptr};
  RunParserSyncTest(context_data, data, kError);
}

TEST_F(ParsingTest, ForOfNoDeclarationsError) {
  const char* context_data[][2] = {{"", ""},
                                   {"function foo(){", "}"},
                                   {"'use strict';", ""},
                                   {"function foo(){ 'use strict';", "}"},
                                   {nullptr, nullptr}};

  const char* data[] = {"for (var of [1, 2, 3]) {}",
                        "for (const of [1, 2, 3]) {}", nullptr};
  RunParserSyncTest(context_data, data, kError);
}

TEST_F(ParsingTest, ForOfInOperator) {
  const char* context_data[][2] = {{"", ""},
                                   {"'use strict';", ""},
                                   {"function foo(){ 'use strict';", "}"},
                                   {nullptr, nullptr}};

  const char* data[] = {"for(x of 'foo' in {}) {}",
                        "for(var x of 'foo' in {}) {}",
                        "for(let x of 'foo' in {}) {}",
                        "for(const x of 'foo' in {}) {}", nullptr};

  RunParserSyncTest(context_data, data, kSuccess);
}

TEST_F(ParsingTest, ForOfYieldIdentifier) {
  const char* context_data[][2] = {{"", ""}, {nullptr, nullptr}};

  const char* data[] = {"for(x of yield) {}", "for(var x of yield) {}",
                        "for(let x of yield) {}", "for(const x of yield) {}",
                        nullptr};

  RunParserSyncTest(context_data, data, kSuccess);
}

TEST_F(ParsingTest, ForOfYieldExpression) {
  const char* context_data[][2] = {{"", ""},
                                   {"'use strict';", ""},
                                   {"function foo(){ 'use strict';", "}"},
                                   {nullptr, nullptr}};

  const char* data[] = {"function* g() { for(x of yield) {} }",
                        "function* g() { for(var x of yield) {} }",
                        "function* g() { for(let x of yield) {} }",
                        "function* g() { for(const x of yield) {} }", nullptr};

  RunParserSyncTest(context_data, data, kSuccess);
}

TEST_F(ParsingTest, ForOfExpressionError) {
  const char* context_data[][2] = {{"", ""},
                                   {"'use strict';", ""},
                                   {"function foo(){ 'use strict';", "}"},
                                   {nullptr, nullptr}};

  const char* data[] = {
      "for(x of [], []) {}", "for(var x of [], []) {}",
      "for(let x of [], []) {}", "for(const x of [], []) {}",

      // AssignmentExpression should be validated statically:
      "for(x of { y = 23 }) {}", "for(var x of { y = 23 }) {}",
      "for(let x of { y = 23 }) {}", "for(const x of { y = 23 }) {}", nullptr};

  RunParserSyncTest(context_data, data, kError);
}

TEST_F(ParsingTest, ForOfAsync) {
  const char* context_data[][2] = {{"", ""},
                                   {"'use strict';", ""},
                                   {"function foo(){ 'use strict';", "}"},
                                   {nullptr, nullptr}};

  const char* data[] = {"for(\\u0061sync of []) {}", nullptr};

  RunParserSyncTest(context_data, data, kSuccess);
}

TEST_F(ParsingTest, InvalidUnicodeEscapes) {
  const char* context_data[][2] = {
      {"", ""}, {"'use strict';", ""}, {nullptr, nullptr}};
  const char* data[] = {
      "var foob\\u123r = 0;", "var \\u123roo = 0;", "\"foob\\u123rr\"",
      // No escapes allowed in regexp flags
      "/regex/\\u0069g", "/regex/\\u006g",
      // Braces gone wrong
      "var foob\\u{c481r = 0;", "var foob\\uc481}r = 0;", "var \\u{0052oo = 0;",
      "var \\u0052}oo = 0;", "\"foob\\u{c481r\"", "var foob\\u{}ar = 0;",
      // Too high value for the Unicode code point escape
      "\"\\u{110000}\"",
      // Not a Unicode code point escape
      "var foob\\v1234r = 0;", "var foob\\U1234r = 0;",
      "var foob\\v{1234}r = 0;", "var foob\\U{1234}r = 0;", nullptr};
  RunParserSyncTest(context_data, data, kError);
}

TEST_F(ParsingTest, UnicodeEscapes) {
  const char* context_data[][2] = {
      {"", ""}, {"'use strict';", ""}, {nullptr, nullptr}};
  const char* data[] = {
      // Identifier starting with escape
      "var \\u0052oo = 0;", "var \\u{0052}oo = 0;", "var \\u{52}oo = 0;",
      "var \\u{00000000052}oo = 0;",
      // Identifier with an escape but not starting with an escape
      "var foob\\uc481r = 0;", "var foob\\u{c481}r = 0;",
      // String with an escape
      "\"foob\\uc481r\"", "\"foob\\{uc481}r\"",
      // This character is a valid Unicode character, representable as a
      // surrogate pair, not representable as 4 hex digits.
      "\"foo\\u{10e6d}\"",
      // Max value for the Unicode code point escape
      "\"\\u{10ffff}\"", nullptr};
  RunParserSyncTest(context_data, data, kSuccess);
}

TEST_F(ParsingTest, OctalEscapes) {
  const char* sloppy_context_data[][2] = {{"", ""},    // as a directive
                                          {"0;", ""},  // as a string literal
                                          {nullptr, nullptr}};

  const char* strict_context_data[][2] = {
      {"'use strict';", ""},     // as a directive before 'use strict'
      {"", ";'use strict';"},    // as a directive after 'use strict'
      {"'use strict'; 0;", ""},  // as a string literal
      {nullptr, nullptr}};

  // clang-format off
  const char* data[] = {
    "'\\1'",
    "'\\01'",
    "'\\001'",
    "'\\08'",
    "'\\09'",
    nullptr};
  // clang-format on

  // Permitted in sloppy mode
  RunParserSyncTest(sloppy_context_data, data, kSuccess);

  // Error in strict mode
  RunParserSyncTest(strict_context_data, data, kError);
}

TEST_F(ParsingTest, ScanTemplateLiterals) {
  const char* context_data[][2] = {{"'use strict';", ""},
                                   {"function foo(){ 'use strict';"
                                    "  var a, b, c; return ",
                                    "}"},
                                   {nullptr, nullptr}};

  const char* data[] = {"``",
                        "`no-subst-template`",
                        "`template-head${a}`",
                        "`${a}`",
                        "`${a}template-tail`",
                        "`template-head${a}template-tail`",
                        "`${a}${b}${c}`",
                        "`a${a}b${b}c${c}`",
                        "`${a}a${b}b${c}c`",
                        "`foo\n\nbar\r\nbaz`",
                        "`foo\n\n${  bar  }\r\nbaz`",
                        "`foo${a /* comment */}`",
                        "`foo${a // comment\n}`",
                        "`foo${a \n}`",
                        "`foo${a \r\n}`",
                        "`foo${a \r}`",
                        "`foo${/* comment */ a}`",
                        "`foo${// comment\na}`",
                        "`foo${\n a}`",
                        "`foo${\r\n a}`",
                        "`foo${\r a}`",
                        "`foo${'a' in a}`",
                        nullptr};
  RunParserSyncTest(context_data, data, kSuccess);
}

TEST_F(ParsingTest, ScanTaggedTemplateLiterals) {
  const char* context_data[][2] = {{"'use strict';", ""},
                                   {"function foo(){ 'use strict';"
                                    "  function tag() {}"
                                    "  var a, b, c; return ",
                                    "}"},
                                   {nullptr, nullptr}};

  const char* data[] = {"tag ``",
                        "tag `no-subst-template`",
                        "tag`template-head${a}`",
                        "tag `${a}`",
                        "tag `${a}template-tail`",
                        "tag   `template-head${a}template-tail`",
                        "tag\n`${a}${b}${c}`",
                        "tag\r\n`a${a}b${b}c${c}`",
                        "tag    `${a}a${b}b${c}c`",
                        "tag\t`foo\n\nbar\r\nbaz`",
                        "tag\r`foo\n\n${  bar  }\r\nbaz`",
                        "tag`foo${a /* comment */}`",
                        "tag`foo${a // comment\n}`",
                        "tag`foo${a \n}`",
                        "tag`foo${a \r\n}`",
                        "tag`foo${a \r}`",
                        "tag`foo${/* comment */ a}`",
                        "tag`foo${// comment\na}`",
                        "tag`foo${\n a}`",
                        "tag`foo${\r\n a}`",
                        "tag`foo${\r a}`",
                        "tag`foo${'a' in a}`",
                        nullptr};
  RunParserSyncTest(context_data, data, kSuccess);
}

TEST_F(ParsingTest, TemplateMaterializedLiterals) {
  const char* context_data[][2] = {{"'use strict';\n"
                                    "function tag() {}\n"
                                    "var a, b, c;\n"
                                    "(",
                                    ")"},
                                   {nullptr, nullptr}};

  const char* data[] = {"tag``", "tag`a`", "tag`a${1}b`", "tag`a${1}b${2}c`",
                        "``",    "`a`",    "`a${1}b`",    "`a${1}b${2}c`",
                        nullptr};

  RunParserSyncTest(context_data, data, kSuccess);
}

TEST_F(ParsingTest, ScanUnterminatedTemplateLiterals) {
  const char* context_data[][2] = {{"'use strict';", ""},
                                   {"function foo(){ 'use strict';"
                                    "  var a, b, c; return ",
                                    "}"},
                                   {nullptr, nullptr}};

  const char* data[] = {"`no-subst-template",
                        "`template-head${a}",
                        "`${a}template-tail",
                        "`template-head${a}template-tail",
                        "`${a}${b}${c}",
                        "`a${a}b${b}c${c}",
                        "`${a}a${b}b${c}c",
                        "`foo\n\nbar\r\nbaz",
                        "`foo\n\n${  bar  }\r\nbaz",
                        "`foo${a /* comment } */`",
                        "`foo${a /* comment } `*/",
                        "`foo${a // comment}`",
                        "`foo${a \n`",
                        "`foo${a \r\n`",
                        "`foo${a \r`",
                        "`foo${/* comment */ a`",
                        "`foo${// commenta}`",
                        "`foo${\n a`",
                        "`foo${\r\n a`",
                        "`foo${\r a`",
                        "`foo${fn(}`",
                        "`foo${1 if}`",
                        nullptr};
  RunParserSyncTest(context_data, data, kError);
}

TEST_F(ParsingTest, TemplateLiteralsIllegalTokens) {
  const char* context_data[][2] = {{"'use strict';", ""},
                                   {"function foo(){ 'use strict';"
                                    "  var a, b, c; return ",
                                    "}"},
                                   {nullptr, nullptr}};
  const char* data[] = {
      "`hello\\x`",         "`hello\\x${1}`",       "`hello${1}\\x`",
      "`hello${1}\\x${2}`", "`hello\\x\n`",         "`hello\\x\n${1}`",
      "`hello${1}\\x\n`",   "`hello${1}\\x\n${2}`", nullptr};

  RunParserSyncTest(context_data, data, kError);
}

TEST_F(ParsingTest, ParseRestParameters) {
  const char* context_data[][2] = {{"'use strict';(function(",
                                    "){ return args;})(1, [], /regexp/, 'str',"
                                    "function(){});"},
                                   {"(function(",
                                    "){ return args;})(1, [],"
                                    "/regexp/, 'str', function(){});"},
                                   {nullptr, nullptr}};

  const char* data[] = {"...args",
                        "a, ...args",
                        "...   args",
                        "a, ...   args",
                        "...\targs",
                        "a, ...\targs",
                        "...\r\nargs",
                        "a, ...\r\nargs",
                        "...\rargs",
                        "a, ...\rargs",
                        "...\t\n\t\t\n  args",
                        "a, ...  \n  \n  args",
                        "...{ length, 0: a, 1: b}",
                        "...{}",
                        "...[a, b]",
                        "...[]",
                        "...[...[a, b, ...c]]",
                        nullptr};
  RunParserSyncTest(context_data, data, kSuccess);
}

TEST_F(ParsingTest, ParseRestParametersErrors) {
  const char* context_data[][2] = {{"'use strict';(function(",
                                    "){ return args;}(1, [], /regexp/, 'str',"
                                    "function(){});"},
                                   {"(function(",
                                    "){ return args;}(1, [],"
                                    "/regexp/, 'str', function(){});"},
                                   {nullptr, nullptr}};

  const char* data[] = {"...args, b",
                        "a, ...args, b",
                        "...args,   b",
                        "a, ...args,   b",
                        "...args,\tb",
                        "a,...args\t,b",
                        "...args\r\n, b",
                        "a, ... args,\r\nb",
                        "...args\r,b",
                        "a, ... args,\rb",
                        "...args\t\n\t\t\n,  b",
                        "a, ... args,  \n  \n  b",
                        "a, a, ...args",
                        "a,\ta, ...args",
                        "a,\ra, ...args",
                        "a,\na, ...args",
                        nullptr};
  RunParserSyncTest(context_data, data, kError);
}

TEST_F(ParsingTest, RestParameterInSetterMethodError) {
  const char* context_data[][2] = {
      {"'use strict';({ set prop(", ") {} }).prop = 1;"},
      {"'use strict';(class { static set prop(", ") {} }).prop = 1;"},
      {"'use strict';(new (class { set prop(", ") {} })).prop = 1;"},
      {"({ set prop(", ") {} }).prop = 1;"},
      {"(class { static set prop(", ") {} }).prop = 1;"},
      {"(new (class { set prop(", ") {} })).prop = 1;"},
      {nullptr, nullptr}};
  const char* data[] = {"...a", "...arguments", "...eval", nullptr};

  RunParserSyncTest(context_data, data, kError);
}

TEST_F(ParsingTest, RestParametersEvalArguments) {
  // clang-format off
  const char* strict_context_data[][2] =
      {{"'use strict';(function(",
        "){ return;})(1, [], /regexp/, 'str',function(){});"},
       {nullptr, nullptr}};
  const char* sloppy_context_data[][2] =
      {{"(function(",
        "){ return;})(1, [],/regexp/, 'str', function(){});"},
       {nullptr, nullptr}};

  const char* data[] = {
      "...eval",
      "eval, ...args",
      "...arguments",
      // See https://bugs.chromium.org/p/v8/issues/detail?id=4577
      // "arguments, ...args",
      nullptr};
  // clang-format on

  // Fail in strict mode
  RunParserSyncTest(strict_context_data, data, kError);

  // OK in sloppy mode
  RunParserSyncTest(sloppy_context_data, data, kSuccess);
}

TEST_F(ParsingTest, RestParametersDuplicateEvalArguments) {
  const char* context_data[][2] = {
      {"'use strict';(function(",
       "){ return;})(1, [], /regexp/, 'str',function(){});"},
      {"(function(", "){ return;})(1, [],/regexp/, 'str', function(){});"},
      {nullptr, nullptr}};

  const char* data[] = {"eval, ...eval", "eval, eval, ...args",
                        "arguments, ...arguments",
                        "arguments, arguments, ...args", nullptr};

  // In strict mode, the error is using "eval" or "arguments" as parameter names
  // In sloppy mode, the error is that eval / arguments are duplicated
  RunParserSyncTest(context_data, data, kError);
}

TEST_F(ParsingTest, SpreadCall) {
  const char* context_data[][2] = {{"function fn() { 'use strict';} fn(", ");"},
                                   {"function fn() {} fn(", ");"},
                                   {nullptr, nullptr}};

  const char* data[] = {"...([1, 2, 3])",
                        "...'123', ...'456'",
                        "...new Set([1, 2, 3]), 4",
                        "1, ...[2, 3], 4",
                        "...Array(...[1,2,3,4])",
                        "...NaN",
                        "0, 1, ...[2, 3, 4], 5, 6, 7, ...'89'",
                        "0, 1, ...[2, 3, 4], 5, 6, 7, ...'89', 10",
                        "...[0, 1, 2], 3, 4, 5, 6, ...'7', 8, 9",
                        "...[0, 1, 2], 3, 4, 5, 6, ...'7', 8, 9, ...[10]",
                        nullptr};

  RunParserSyncTest(context_data, data, kSuccess);
}

TEST_F(ParsingTest, SpreadCallErrors) {
  const char* context_data[][2] = {{"function fn() { 'use strict';} fn(", ");"},
                                   {"function fn() {} fn(", ");"},
                                   {nullptr, nullptr}};

  const char* data[] = {"(...[1, 2, 3])", "......[1,2,3]", nullptr};

  RunParserSyncTest(context_data, data, kError);
}

TEST_F(ParsingTest, BadRestSpread) {
  const char* context_data[][2] = {{"function fn() { 'use strict';", "} fn();"},
                                   {"function fn() { ", "} fn();"},
                                   {nullptr, nullptr}};
  const char* data[] = {
      "return ...[1,2,3];",          "var ...x = [1,2,3];",
      "var [...x,] = [1,2,3];",      "var [...x, y] = [1,2,3];",
      "var { x } = {x: ...[1,2,3]}", nullptr};
  RunParserSyncTest(context_data, data, kError);
}

TEST_F(ParsingTest, LexicalScopingSloppyMode) {
  const char* context_data[][2] = {
      {"", ""}, {"function f() {", "}"}, {"{", "}"}, {nullptr, nullptr}};

  const char* good_data[] = {"let = 1;", "for(let = 1;;){}", nullptr};
  RunParserSyncTest(context_data, good_data, kSuccess);
}

TEST_F(ParsingTest, ComputedPropertyName) {
  const char* context_data[][2] = {{"({[", "]: 1});"},
                                   {"({get [", "]() {}});"},
                                   {"({set [", "](_) {}});"},
                                   {"({[", "]() {}});"},
                                   {"({*[", "]() {}});"},
                                   {"(class {get [", "]() {}});"},
                                   {"(class {set [", "](_) {}});"},
                                   {"(class {[", "]() {}});"},
                                   {"(class {*[", "]() {}});"},
                                   {nullptr, nullptr}};
  const char* error_data[] = {"1, 2", "var name", nullptr};

  RunParserSyncTest(context_data, error_data, kError);

  const char* name_data[] = {"1",  "1 + 2", "'name'", "\"name\"",
                             "[]", "{}",    nullptr};

  RunParserSyncTest(context_data, name_data, kSuccess);
}

TEST_F(ParsingTest, ComputedPropertyNameShorthandError) {
  const char* context_data[][2] = {{"({", "});"}, {nullptr, nullptr}};
  const char* error_data[] = {"a: 1, [2]", "[1], a: 1", nullptr};

  RunParserSyncTest(context_data, error_data, kError);
}

TEST_F(ParsingTest, BasicImportExportParsing) {
  // clang-format off
  const char* kSources[] = {
      "export let x = 0;",
      "export var y = 0;",
      "export const z = 0;",
      "export function func() { };",
      "export class C { };",
      "export { };",
      "function f() {}; f(); export { f };",
      "var a, b, c; export { a, b as baz, c };",
      "var d, e; export { d as dreary, e, };",
      "export default function f() {}",
      "export default function() {}",
      "export default function*() {}",
      "export default class C {}",
      "export default class {}",
      "export default class extends C {}",
      "export default 42",
      "var x; export default x = 7",
      "export { Q } from 'somemodule.js';",
      "export * from 'somemodule.js';",
      "var foo; export { foo as for };",
      "export { arguments } from 'm.js';",
      "export { for } from 'm.js';",
      "export { yield } from 'm.js'",
      "export { static } from 'm.js'",
      "export { let } from 'm.js'",
      "var a; export { a as b, a as c };",
      "var a; export { a as await };",
      "var a; export { a as enum };",

      "import 'somemodule.js';",
      "import { } from 'm.js';",
      "import { a } from 'm.js';",
      "import { a, b as d, c, } from 'm.js';",
      "import * as thing from 'm.js';",
      "import thing from 'm.js';",
      "import thing, * as rest from 'm.js';",
      "import thing, { a, b, c } from 'm.js';",
      "import { arguments as a } from 'm.js';",
      "import { for as f } from 'm.js';",
      "import { yield as y } from 'm.js';",
      "import { static as s } from 'm.js';",
      "import { let as l } from 'm.js';",

      "import thing from 'a.js'; export {thing};",
      "export {thing}; import thing from 'a.js';",
      "import {thing} from 'a.js'; export {thing};",
      "export {thing}; import {thing} from 'a.js';",
      "import * as thing from 'a.js'; export {thing};",
      "export {thing}; import * as thing from 'a.js';",
  };
  // clang-format on

  i::Isolate* isolate = i_isolate();
  i::Factory* factory = isolate->factory();

  isolate->stack_guard()->SetStackLimit(i::GetCurrentStackPosition() -
                                        128 * 1024);

  for (unsigned i = 0; i < arraysize(kSources); ++i) {
    i::DirectHandle<i::String> source =
        factory->NewStringFromAsciiChecked(kSources[i]);

    // Show that parsing as a module works
    {
      i::Handle<i::Script> script = factory->NewScript(source);
      i::UnoptimizedCompileState compile_state;
      i::ReusableUnoptimizedCompileState reusable_state(isolate);
      i::UnoptimizedCompileFlags flags =
          i::UnoptimizedCompileFlags::ForScriptCompile(isolate, *script);
      flags.set_is_module(true);
      i::ParseInfo info(isolate, flags, &compile_state, &reusable_state);
      CHECK_PARSE_PROGRAM(&info, script, isolate);
    }

    // And that parsing a script does not.
    {
      i::UnoptimizedCompileState compile_state;
      i::ReusableUnoptimizedCompileState reusable_state(isolate);
      i::DirectHandle<i::Script> script = factory->NewScript(source);
      i::UnoptimizedCompileFlags flags =
          i::UnoptimizedCompileFlags::ForScriptCompile(isolate, *script);
      i::ParseInfo info(isolate, flags, &compile_state, &reusable_state);
      CHECK(!i::parsing::ParseProgram(&info, script, isolate,
                                      parsing::ReportStatisticsMode::kYes));
      CHECK(info.pending_error_handler()->has_pending_error());
    }
  }
}

TEST_F(ParsingTest, NamespaceExportParsing) {
  // clang-format off
  const char* kSources[] = {
      "export * as arguments from 'bar'",
      "export * as await from 'bar'",
      "export * as default from 'bar'",
      "export * as enum from 'bar'",
      "export * as foo from 'bar'",
      "export * as for from 'bar'",
      "export * as let from 'bar'",
      "export * as static from 'bar'",
      "export * as yield from 'bar'",
  };
  // clang-format on

  i::Isolate* isolate = i_isolate();
  i::Factory* factory = isolate->factory();

  isolate->stack_guard()->SetStackLimit(i::GetCurrentStackPosition() -
                                        128 * 1024);

  for (unsigned i = 0; i < arraysize(kSources); ++i) {
    i::DirectHandle<i::String> source =
        factory->NewStringFromAsciiChecked(kSources[i]);
    i::Handle<i::Script> script = factory->NewScript(source);
    i::UnoptimizedCompileState compile_state;
    i::ReusableUnoptimizedCompileState reusable_state(isolate);
    i::UnoptimizedCompileFlags flags =
        i::UnoptimizedCompileFlags::ForScriptCompile(isolate, *script);
    flags.set_is_module(true);
    i::ParseInfo info(isolate, flags, &compile_state, &reusable_state);
    CHECK_PARSE_PROGRAM(&info, script, isolate);
  }
}

TEST_F(ParsingTest, ImportExportParsingErrors) {
  // clang-format off
  const char* kErrorSources[] = {
      "export {",
      "var a; export { a",
      "var a; export { a,",
      "var a; export { a, ;",
      "var a; export { a as };",
      "var a, b; export { a as , b};",
      "export }",
      "var foo, bar; export { foo bar };",
      "export { foo };",
      "export { , };",
      "export default;",
      "export default var x = 7;",
      "export default let x = 7;",
      "export default const x = 7;",
      "export *;",
      "export * from;",
      "export { Q } from;",
      "export default from 'module.js';",
      "export { for }",
      "export { for as foo }",
      "export { arguments }",
      "export { arguments as foo }",
      "var a; export { a, a };",
      "var a, b; export { a as b, b };",
      "var a, b; export { a as c, b as c };",
      "export default function f(){}; export default class C {};",
      "export default function f(){}; var a; export { a as default };",
      "export function() {}",
      "export function*() {}",
      "export class {}",
      "export class extends C {}",

      "import from;",
      "import from 'm.js';",
      "import { };",
      "import {;",
      "import };",
      "import { , };",
      "import { , } from 'm.js';",
      "import { a } from;",
      "import { a } 'm.js';",
      "import , from 'm.js';",
      "import a , from 'm.js';",
      "import a { b, c } from 'm.js';",
      "import arguments from 'm.js';",
      "import eval from 'm.js';",
      "import { arguments } from 'm.js';",
      "import { eval } from 'm.js';",
      "import { a as arguments } from 'm.js';",
      "import { for } from 'm.js';",
      "import { y as yield } from 'm.js'",
      "import { s as static } from 'm.js'",
      "import { l as let } from 'm.js'",
      "import { a as await } from 'm.js';",
      "import { a as enum } from 'm.js';",
      "import { x }, def from 'm.js';",
      "import def, def2 from 'm.js';",
      "import * as x, def from 'm.js';",
      "import * as x, * as y from 'm.js';",
      "import {x}, {y} from 'm.js';",
      "import * as x, {y} from 'm.js';",

      "export *;",
      "export * as;",
      "export * as foo;",
      "export * as foo from;",
      "export * as foo from ';",
      "export * as ,foo from 'bar'",
  };
  // clang-format on

  i::Isolate* isolate = i_isolate();
  i::Factory* factory = isolate->factory();

  isolate->stack_guard()->SetStackLimit(i::GetCurrentStackPosition() -
                                        128 * 1024);

  for (unsigned i = 0; i < arraysize(kErrorSources); ++i) {
    i::DirectHandle<i::String> source =
        factory->NewStringFromAsciiChecked(kErrorSources[i]);

    i::DirectHandle<i::Script> script = factory->NewScript(source);
    i::UnoptimizedCompileState compile_state;
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

TEST_F(ParsingTest, ModuleTopLevelFunctionDecl) {
  // clang-format off
  const char* kErrorSources[] = {
      "function f() {} function f() {}",
      "var f; function f() {}",
      "function f() {} var f;",
      "function* f() {} function* f() {}",
      "var f; function* f() {}",
      "function* f() {} var f;",
      "function f() {} function* f() {}",
      "function* f() {} function f() {}",
  };
  // clang-format on

  i::Isolate* isolate = i_isolate();
  i::Factory* factory = isolate->factory();

  isolate->stack_guard()->SetStackLimit(i::GetCurrentStackPosition() -
                                        128 * 1024);

  for (unsigned i = 0; i < arraysize(kErrorSources); ++i) {
    i::DirectHandle<i::String> source =
        factory->NewStringFromAsciiChecked(kErrorSources[i]);

    i::DirectHandle<i::Script> script = factory->NewScript(source);
    i::UnoptimizedCompileState compile_state;
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

TEST_F(ParsingTest, ModuleAwaitReserved) {
  // clang-format off
  const char* kErrorSources[] = {
      "await;",
      "await: ;",
      "var await;",
      "var [await] = [];",
      "var { await } = {};",
      "var { x: await } = {};",
      "{ var await; }",
      "let await;",
      "let [await] = [];",
      "let { await } = {};",
      "let { x: await } = {};",
      "{ let await; }",
      "const await = null;",
      "const [await] = [];",
      "const { await } = {};",
      "const { x: await } = {};",
      "{ const await = null; }",
      "function await() {}",
      "function f(await) {}",
      "function* await() {}",
      "function* g(await) {}",
      "(function await() {});",
      "(function (await) {});",
      "(function* await() {});",
      "(function* (await) {});",
      "(await) => {};",
      "await => {};",
      "class await {}",
      "class C { constructor(await) {} }",
      "class C { m(await) {} }",
      "class C { static m(await) {} }",
      "class C { *m(await) {} }",
      "class C { static *m(await) {} }",
      "(class await {})",
      "(class { constructor(await) {} });",
      "(class { m(await) {} });",
      "(class { static m(await) {} });",
      "(class { *m(await) {} });",
      "(class { static *m(await) {} });",
      "({ m(await) {} });",
      "({ *m(await) {} });",
      "({ set p(await) {} });",
      "try {} catch (await) {}",
      "try {} catch (await) {} finally {}",
      nullptr
  };
  // clang-format on
  const char* context_data[][2] = {{"", ""}, {nullptr, nullptr}};

  RunModuleParserSyncTest(context_data, kErrorSources, kError);
}

TEST_F(ParsingTest, ModuleAwaitReservedPreParse) {
  const char* context_data[][2] = {{"", ""}, {nullptr, nullptr}};
  const char* error_data[] = {"function f() { var await = 0; }", nullptr};

  RunModuleParserSyncTest(context_data, error_data, kError);
}

TEST_F(ParsingTest, ModuleAwaitPermitted) {
  // clang-format off
  const char* kValidSources[] = {
    "({}).await;",
    "({ await: null });",
    "({ await() {} });",
    "({ get await() {} });",
    "({ set await(x) {} });",
    "(class { await() {} });",
    "(class { static await() {} });",
    "(class { *await() {} });",
    "(class { static *await() {} });",
    nullptr
  };
  // clang-format on
  const char* context_data[][2] = {{"", ""}, {nullptr, nullptr}};

  RunModuleParserSyncTest(context_data, kValidSources, kSuccess);
}

TEST_F(ParsingTest, EnumReserved) {
  // clang-format off
  const char* kErrorSources[] = {
      "enum;",
      "enum: ;",
      "var enum;",
      "var [enum] = [];",
      "var { enum } = {};",
      "var { x: enum } = {};",
      "{ var enum; }",
      "let enum;",
      "let [enum] = [];",
      "let { enum } = {};",
      "let { x: enum } = {};",
      "{ let enum; }",
      "const enum = null;",
      "const [enum] = [];",
      "const { enum } = {};",
      "const { x: enum } = {};",
      "{ const enum = null; }",
      "function enum() {}",
      "function f(enum) {}",
      "function* enum() {}",
      "function* g(enum) {}",
      "(function enum() {});",
      "(function (enum) {});",
      "(function* enum() {});",
      "(function* (enum) {});",
      "(enum) => {};",
      "enum => {};",
      "class enum {}",
      "class C { constructor(enum) {} }",
      "class C { m(enum) {} }",
      "class C { static m(enum) {} }",
      "class C { *m(enum) {} }",
      "class C { static *m(enum) {} }",
      "(class enum {})",
      "(class { constructor(enum) {} });",
      "(class { m(enum) {} });",
      "(class { static m(enum) {} });",
      "(class { *m(enum) {} });",
      "(class { static *m(enum) {} });",
      "({ m(enum) {} });",
      "({ *m(enum) {} });",
      "({ set p(enum) {} });",
      "try {} catch (enum) {}",
      "try {} catch (enum) {} finally {}",
      nullptr
  };
  // clang-format on
  const char* context_data[][2] = {{"", ""}, {nullptr, nullptr}};

  RunModuleParserSyncTest(context_data, kErrorSources, kError);
}

static void CheckEntry(const i::SourceTextModuleDescriptor::Entry* entry,
                       const char* export_name, const char* local_name,
                       const char* import_name, int module_request) {
  CHECK_NOT_NULL(entry);
  if (export_name == nullptr) {
    CHECK_NULL(entry->export_name);
  } else {
    CHECK(entry->export_name->IsOneByteEqualTo(export_name));
  }
  if (local_name == nullptr) {
    CHECK_NULL(entry->local_name);
  } else {
    CHECK(entry->local_name->IsOneByteEqualTo(local_name));
  }
  if (import_name == nullptr) {
    CHECK_NULL(entry->import_name);
  } else {
    CHECK(entry->import_name->IsOneByteEqualTo(import_name));
  }
  CHECK_EQ(entry->module_request, module_request);
}

TEST_F(ParsingTest, ModuleParsingInternals) {
  i::Isolate* isolate = i_isolate();
  i::Factory* factory = isolate->factory();
  isolate->stack_guard()->SetStackLimit(i::GetCurrentStackPosition() -
                                        128 * 1024);

  static const char kSource[] =
      "let x = 5;"
      "export { x as y };"
      "import { q as z } from 'm.js';"
      "import n from 'n.js';"
      "export { a as b } from 'm.js';"
      "export * from 'p.js';"
      "export var foo;"
      "export function goo() {};"
      "export let hoo;"
      "export const joo = 42;"
      "export default (function koo() {});"
      "import 'q.js';"
      "let nonexport = 42;"
      "import {m as mm} from 'm.js';"
      "import {aa} from 'm.js';"
      "export {aa as bb, x};"
      "import * as loo from 'bar.js';"
      "import * as foob from 'bar.js';"
      "export {foob};";
  i::DirectHandle<i::String> source =
      factory->NewStringFromAsciiChecked(kSource);
  i::Handle<i::Script> script = factory->NewScript(source);
  i::UnoptimizedCompileState compile_state;
  i::ReusableUnoptimizedCompileState reusable_state(isolate);
  i::UnoptimizedCompileFlags flags =
      i::UnoptimizedCompileFlags::ForScriptCompile(isolate, *script);
  flags.set_is_module(true);
  i::ParseInfo info(isolate, flags, &compile_state, &reusable_state);
  CHECK_PARSE_PROGRAM(&info, script, isolate);

  i::FunctionLiteral* func = info.literal();
  i::ModuleScope* module_scope = func->scope()->AsModuleScope();
  i::Scope* outer_scope = module_scope->outer_scope();
  CHECK(outer_scope->is_script_scope());
  CHECK_NULL(outer_scope->outer_scope());
  CHECK(module_scope->is_module_scope());
  const i::SourceTextModuleDescriptor::Entry* entry;
  i::Declaration::List* declarations = module_scope->declarations();
  CHECK_EQ(13, declarations->LengthForTest());

  CHECK(declarations->AtForTest(0)->var()->raw_name()->IsOneByteEqualTo("x"));
  CHECK(declarations->AtForTest(0)->var()->mode() == i::VariableMode::kLet);
  CHECK(declarations->AtForTest(0)->var()->binding_needs_init());
  CHECK(declarations->AtForTest(0)->var()->location() ==
        i::VariableLocation::MODULE);

  CHECK(declarations->AtForTest(1)->var()->raw_name()->IsOneByteEqualTo("z"));
  CHECK(declarations->AtForTest(1)->var()->mode() == i::VariableMode::kConst);
  CHECK(declarations->AtForTest(1)->var()->binding_needs_init());
  CHECK(declarations->AtForTest(1)->var()->location() ==
        i::VariableLocation::MODULE);

  CHECK(declarations->AtForTest(2)->var()->raw_name()->IsOneByteEqualTo("n"));
  CHECK(declarations->AtForTest(2)->var()->mode() == i::VariableMode::kConst);
  CHECK(declarations->AtForTest(2)->var()->binding_needs_init());
  CHECK(declarations->AtForTest(2)->var()->location() ==
        i::VariableLocation::MODULE);

  CHECK(declarations->AtForTest(3)->var()->raw_name()->IsOneByteEqualTo("foo"));
  CHECK(declarations->AtForTest(3)->var()->mode() == i::VariableMode::kVar);
  CHECK(!declarations->AtForTest(3)->var()->binding_needs_init());
  CHECK(declarations->AtForTest(3)->var()->location() ==
        i::VariableLocation::MODULE);

  CHECK(declarations->AtForTest(4)->var()->raw_name()->IsOneByteEqualTo("goo"));
  CHECK(declarations->AtForTest(4)->var()->mode() == i::VariableMode::kLet);
  CHECK(!declarations->AtForTest(4)->var()->binding_needs_init());
  CHECK(declarations->AtForTest(4)->var()->location() ==
        i::VariableLocation::MODULE);

  CHECK(declarations->AtForTest(5)->var()->raw_name()->IsOneByteEqualTo("hoo"));
  CHECK(declarations->AtForTest(5)->var()->mode() == i::VariableMode::kLet);
  CHECK(declarations->AtForTest(5)->var()->binding_needs_init());
  CHECK(declarations->AtForTest(5)->var()->location() ==
        i::VariableLocation::MODULE);

  CHECK(declarations->AtForTest(6)->var()->raw_name()->IsOneByteEqualTo("joo"));
  CHECK(declarations->AtForTest(6)->var()->mode() == i::VariableMode::kConst);
  CHECK(declarations->AtForTest(6)->var()->binding_needs_init());
  CHECK(declarations->AtForTest(6)->var()->location() ==
        i::VariableLocation::MODULE);

  CHECK(declarations->AtForTest(7)->var()->raw_name()->IsOneByteEqualTo(
      ".default"));
  CHECK(declarations->AtForTest(7)->var()->mode() == i::VariableMode::kConst);
  CHECK(declarations->AtForTest(7)->var()->binding_needs_init());
  CHECK(declarations->AtForTest(7)->var()->location() ==
        i::VariableLocation::MODULE);

  CHECK(declarations->AtForTest(8)->var()->raw_name()->IsOneByteEqualTo(
      "nonexport"));
  CHECK(!declarations->AtForTest(8)->var()->binding_needs_init());
  CHECK(declarations->AtForTest(8)->var()->location() ==
        i::VariableLocation::LOCAL);

  CHECK(declarations->AtForTest(9)->var()->raw_name()->IsOneByteEqualTo("mm"));
  CHECK(declarations->AtForTest(9)->var()->mode() == i::VariableMode::kConst);
  CHECK(declarations->AtForTest(9)->var()->binding_needs_init());
  CHECK(declarations->AtForTest(9)->var()->location() ==
        i::VariableLocation::MODULE);

  CHECK(declarations->AtForTest(10)->var()->raw_name()->IsOneByteEqualTo("aa"));
  CHECK(declarations->AtForTest(10)->var()->mode() == i::VariableMode::kConst);
  CHECK(declarations->AtForTest(10)->var()->binding_needs_init());
  CHECK(declarations->AtForTest(10)->var()->location() ==
        i::VariableLocation::MODULE);

  CHECK(
      declarations->AtForTest(11)->var()->raw_name()->IsOneByteEqualTo("loo"));
  CHECK(declarations->AtForTest(11)->var()->mode() == i::VariableMode::kConst);
  CHECK(!declarations->AtForTest(11)->var()->binding_needs_init());
  CHECK(declarations->AtForTest(11)->var()->location() !=
        i::VariableLocation::MODULE);

  CHECK(
      declarations->AtForTest(12)->var()->raw_name()->IsOneByteEqualTo("foob"));
  CHECK(declarations->AtForTest(12)->var()->mode() == i::VariableMode::kConst);
  CHECK(!declarations->AtForTest(12)->var()->binding_needs_init());
  CHECK(declarations->AtForTest(12)->var()->location() ==
        i::VariableLocation::MODULE);

  i::SourceTextModuleDescriptor* descriptor = module_scope->module();
  CHECK_NOT_NULL(descriptor);

  CHECK_EQ(5u, descriptor->module_requests().size());
  for (const auto& elem : descriptor->module_requests()) {
    if (elem->specifier()->IsOneByteEqualTo("m.js")) {
      CHECK_EQ(0, elem->index());
      CHECK_EQ(51, elem->position());
    } else if (elem->specifier()->IsOneByteEqualTo("n.js")) {
      CHECK_EQ(1, elem->index());
      CHECK_EQ(72, elem->position());
    } else if (elem->specifier()->IsOneByteEqualTo("p.js")) {
      CHECK_EQ(2, elem->index());
      CHECK_EQ(123, elem->position());
    } else if (elem->specifier()->IsOneByteEqualTo("q.js")) {
      CHECK_EQ(3, elem->index());
      CHECK_EQ(249, elem->position());
    } else if (elem->specifier()->IsOneByteEqualTo("bar.js")) {
      CHECK_EQ(4, elem->index());
      CHECK_EQ(370, elem->position());
    } else {
      UNREACHABLE();
    }
  }

  CHECK_EQ(3, descriptor->special_exports().size());
  CheckEntry(descriptor->special_exports().at(0), "b", nullptr, "a", 0);
  CheckEntry(descriptor->special_exports().at(1), nullptr, nullptr, nullptr, 2);
  CheckEntry(descriptor->special_exports().at(2), "bb", nullptr, "aa",
             0);  // !!!

  CHECK_EQ(8u, descriptor->regular_exports().size());
  entry = descriptor->regular_exports()
              .find(declarations->AtForTest(3)->var()->raw_name())
              ->second;
  CheckEntry(entry, "foo", "foo", nullptr, -1);
  entry = descriptor->regular_exports()
              .find(declarations->AtForTest(4)->var()->raw_name())
              ->second;
  CheckEntry(entry, "goo", "goo", nullptr, -1);
  entry = descriptor->regular_exports()
              .find(declarations->AtForTest(5)->var()->raw_name())
              ->second;
  CheckEntry(entry, "hoo", "hoo", nullptr, -1);
  entry = descriptor->regular_exports()
              .find(declarations->AtForTest(6)->var()->raw_name())
              ->second;
  CheckEntry(entry, "joo", "joo", nullptr, -1);
  entry = descriptor->regular_exports()
              .find(declarations->AtForTest(7)->var()->raw_name())
              ->second;
  CheckEntry(entry, "default", ".default", nullptr, -1);
  entry = descriptor->regular_exports()
              .find(declarations->AtForTest(12)->var()->raw_name())
              ->second;
  CheckEntry(entry, "foob", "foob", nullptr, -1);
  // TODO(neis): The next lines are terrible. Find a better way.
  auto name_x = declarations->AtForTest(0)->var()->raw_name();
  CHECK_EQ(2u, descriptor->regular_exports().count(name_x));
  auto it = descriptor->regular_exports().equal_range(name_x).first;
  entry = it->second;
  if (entry->export_name->IsOneByteEqualTo("y")) {
    CheckEntry(entry, "y", "x", nullptr, -1);
    entry = (++it)->second;
    CheckEntry(entry, "x", "x", nullptr, -1);
  } else {
    CheckEntry(entry, "x", "x", nullptr, -1);
    entry = (++it)->second;
    CheckEntry(entry, "y", "x", nullptr, -1);
  }

  CHECK_EQ(2, descriptor->namespace_imports().size());
  CheckEntry(descriptor->namespace_imports().at(0), nullptr, "loo", nullptr, 4);
  CheckEntry(descriptor->namespace_imports().at(1), nullptr, "foob", nullptr,
             4);

  CHECK_EQ(4u, descriptor->regular_imports().size());
  entry = descriptor->regular_imports()
              .find(declarations->AtForTest(1)->var()->raw_name())
              ->second;
  CheckEntry(entry, nullptr, "z", "q", 0);
  entry = descriptor->regular_imports()
              .find(declarations->AtForTest(2)->var()->raw_name())
              ->second;
  CheckEntry(entry, nullptr, "n", "default", 1);
  entry = descriptor->regular_imports()
              .find(declarations->AtForTest(9)->var()->raw_name())
              ->second;
  CheckEntry(entry, nullptr, "mm", "m", 0);
  entry = descriptor->regular_imports()
              .find(declarations->AtForTest(10)->var()->raw_name())
              ->second;
  CheckEntry(entry, nullptr, "aa", "aa", 0);
}

TEST_F(ParsingTest, ModuleParsingInternalsWithImportAttributes) {
  i::v8_flags.harmony_import_attributes = true;
  i::Isolate* isolate = i_isolate();
  i::Factory* factory = isolate->factory();
  isolate->stack_guard()->SetStackLimit(base::Stack::GetCurrentStackPosition() -
                                        128 * 1024);

  static const char kSource[] =
      "import { q as z } from 'm.js';"
      "import { q as z2 } from 'm.js' with { foo: 'bar'};"
      "import { q as z3 } from 'm.js' with { foo2: 'bar'};"
      "import { q as z4 } from 'm.js' with { foo: 'bar2'};"
      "import { q as z5 } from 'm.js' with { foo: 'bar', foo2: 'bar'};"
      "import { q as z6 } from 'n.js' with { foo: 'bar'};"
      "import 'm.js' with { foo: 'bar'};"
      "export * from 'm.js' with { foo: 'bar', foo2: 'bar'};";
  i::DirectHandle<i::String> source =
      factory->NewStringFromAsciiChecked(kSource);
  i::Handle<i::Script> script = factory->NewScript(source);
  i::UnoptimizedCompileState compile_state;
  i::ReusableUnoptimizedCompileState reusable_state(isolate);
  i::UnoptimizedCompileFlags flags =
      i::UnoptimizedCompileFlags::ForScriptCompile(isolate, *script);
  flags.set_is_module(true);
  i::ParseInfo info(isolate, flags, &compile_state, &reusable_state);
  CHECK_PARSE_PROGRAM(&info, script, isolate);

  i::FunctionLiteral* func = info.literal();
  i::ModuleScope* module_scope = func->scope()->AsModuleScope();
  CHECK(module_scope->is_module_scope());

  i::SourceTextModuleDescriptor* descriptor = module_scope->module();
  CHECK_NOT_NULL(descriptor);

  const i::AstRawString* foo_string =
      info.ast_value_factory()->GetOneByteString("foo");
  const i::AstRawString* foo2_string =
      info.ast_value_factory()->GetOneByteString("foo2");
  CHECK_EQ(6u, descriptor->module_requests().size());
  for (const auto& elem : descriptor->module_requests()) {
    if (elem->index() == 0) {
      CHECK(elem->specifier()->IsOneByteEqualTo("m.js"));
      CHECK_EQ(0, elem->import_attributes()->size());
      CHECK_EQ(23, elem->position());
    } else if (elem->index() == 1) {
      CHECK(elem->specifier()->IsOneByteEqualTo("m.js"));
      CHECK_EQ(1, elem->import_attributes()->size());
      CHECK_EQ(54, elem->position());
      CHECK(elem->import_attributes()
                ->at(foo_string)
                .first->IsOneByteEqualTo("bar"));
      CHECK_EQ(68, elem->import_attributes()->at(foo_string).second.beg_pos);
    } else if (elem->index() == 2) {
      CHECK(elem->specifier()->IsOneByteEqualTo("m.js"));
      CHECK_EQ(1, elem->import_attributes()->size());
      CHECK_EQ(104, elem->position());
      CHECK(elem->import_attributes()
                ->at(foo2_string)
                .first->IsOneByteEqualTo("bar"));
      CHECK_EQ(118, elem->import_attributes()->at(foo2_string).second.beg_pos);
    } else if (elem->index() == 3) {
      CHECK(elem->specifier()->IsOneByteEqualTo("m.js"));
      CHECK_EQ(1, elem->import_attributes()->size());
```