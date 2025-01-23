Response:
The user wants a summary of the functionality of the C++ code in `v8/test/unittests/parser/parsing-unittest.cc`. They have provided a snippet of the code and have some specific questions about it. I need to:

1. **Identify the purpose of the code:**  Based on the file path and the test structure (using `TEST_F`), it's clear this file contains unit tests for the V8 parser.
2. **List the functionalities demonstrated in the provided snippet:**  The tests cover parsing various JavaScript language features and checking for errors. The snippet focuses on class features (accessors, private names, expressions, declarations, async methods, static prototypes, constructors), object literals, `for...in` and `for...of` loops, unicode escapes, template literals, and rest parameters.
3. **Address the `.tq` file question:**  Explain that `.tq` files are related to Torque, V8's internal type system and compiler, not directly to the parser.
4. **Provide JavaScript examples:** For the relevant features, give concise JavaScript code illustrating them.
5. **Explain code logic inference:** Since the tests primarily check for parsing errors, the "logic inference" involves the parser correctly identifying invalid syntax. I can provide examples of invalid input and the expected error outcome.
6. **Illustrate common programming errors:**  Relate the tested error scenarios to common mistakes developers might make.
7. **Summarize the overall functionality:** Combine the individual functionalities into a concise summary.
8. **Consider the "part 9 of 15" instruction:**  This likely implies the entire file tests various aspects of parsing. The current snippet focuses on a subset of these.
这是文件 `v8/test/unittests/parser/parsing-unittest.cc` 的一部分，它是一个 V8 源代码文件，专门用于测试 V8 JavaScript 引擎的 **解析器** 功能。这个文件包含了大量的单元测试，用于验证解析器在处理各种 JavaScript 代码片段时是否能够正确地识别语法，报告错误，并生成抽象语法树 (AST)。

**功能列举：**

根据您提供的代码片段，这个部分主要测试了以下 JavaScript 语法结构的解析错误处理：

1. **类的静态访问器 (static accessor) 错误：** 测试了各种定义和使用静态访问器时可能出现的语法错误，例如缺少赋值、缺少方法体、不合法的标识符等。
2. **私有名称解析错误 (Private Name Resolution Errors)：** 测试了在不同的上下文中使用私有字段时，解析器是否能够正确地识别出这些私有名称，并在访问不存在的私有字段时报错。
3. **私有名称错误 (Private Name Errors)：** 测试了定义和使用私有字段时可能出现的各种语法错误，例如在类外部使用、不合法的私有名称等。
4. **类表达式错误 (Class Expression Errors)：** 测试了定义类表达式时可能出现的各种语法错误，例如缺少类名、缺少花括号、方法定义错误等。
5. **类声明错误 (Class Declaration Errors)：** 测试了声明类时可能出现的各种语法错误，例如缺少类名（对于声明）、继承错误、方法定义错误等。
6. **类异步方法错误 (Class Async Errors)：** 测试了在类中定义异步方法时可能出现的各种语法错误，例如 `async` 关键字的位置错误、与生成器函数的混用等。
7. **类名错误 (ClassName Errors)：** 测试了在定义类时使用保留字或严格模式下的关键字作为类名时是否会报错。
8. **类 Getter 参数名错误 (Class Getter Param Name Errors)：**  测试了 getter 方法的参数名是否符合规范（getter 不应该有参数）。
9. **类的静态 prototype 属性错误 (Class Static Prototype Errors)：** 测试了在类中定义名为 `prototype` 的静态方法、getter 或 setter 是否会报错。
10. **类的特殊构造函数错误 (Class Special Constructor Errors)：** 测试了以 getter 或生成器函数的形式定义构造函数是否会报错。
11. **类的构造函数无错误 (Class Constructor No Errors)：** 测试了合法的构造函数定义是否能够正确解析。
12. **类的多个构造函数错误 (Class Multiple Constructor Errors)：** 测试了在一个类中定义多个构造函数是否会报错。
13. **类的多个同名属性无错误 (Class Multiple Property Names No Errors)：** 测试了在类中定义多个同名的方法或静态方法是否能够被正确解析（允许重载）。
14. **类是严格模式 (Classes Are Strict Errors)：** 测试了类中的代码是否自动处于严格模式，即使没有显式声明 `'use strict'`。
15. **对象字面量属性简写关键字错误 (Object Literal Property Shorthand Keywords Error)：** 测试了在对象字面量中使用关键字作为简写属性名是否会报错。
16. **对象字面量属性简写严格模式关键字 (Object Literal Property Shorthand Strict Keywords)：** 测试了在对象字面量中使用严格模式下的关键字作为简写属性名在非严格模式和严格模式下的不同表现。
17. **对象字面量属性简写错误 (Object Literal Property Shorthand Error)：** 测试了在对象字面量中使用数字或字符串字面量作为简写属性名是否会报错。
18. **对象字面量属性简写在生成器中的 Yield 错误 (Object Literal Property Shorthand Yield In Generator Error)：** 测试了在生成器函数中使用 `yield` 作为对象字面量的简写属性名是否会报错。
19. **`for...in` 循环中的 `const` 解析 (Const Parsing In ForIn)：** 测试了在 `for...in` 循环中使用 `const` 声明变量是否能够正确解析。
20. **`for...in` 循环中的语句解析 (Statement Parsing In ForIn)：** 测试了在 `for...in` 循环中使用各种声明语句是否能够正确解析。
21. **`for...in` 循环中的 `const` 解析错误 (Const Parsing In ForIn Error)：** 测试了在 `for...in` 循环中使用 `const` 声明变量时可能出现的错误，例如声明多个变量、初始化变量等。
22. **`for...in` 和 `for...of` 循环中的初始化声明 (Initialized Declarations In ForInOf)：**  详细测试了在 `for...in` 和 `for...of` 循环中使用 `var`, `let`, `const` 声明变量并初始化的规则，重点区分严格模式和非严格模式。
23. **`for...in` 循环中的多个声明错误 (ForIn Multiple Declarations Error)：** 测试了在 `for...in` 循环中声明多个变量是否会报错。
24. **`for...of` 循环中的多个声明错误 (ForOf Multiple Declarations Error)：** 测试了在 `for...of` 循环中声明多个变量是否会报错。
25. **`for...in` 和 `for...of` 循环中的 `let` 表达式 (ForInOf Let Expression)：** 测试了在 `for...in` 和 `for...of` 循环中使用 `let.x` 这种表达式作为左侧的情况，以及在异步函数中使用 `for await...of` 的情况。
26. **`for...in` 循环中缺少声明错误 (ForIn No Declarations Error)：** 测试了 `for...in` 循环中没有声明变量是否会报错。
27. **`for...of` 循环中缺少声明错误 (ForOf No Declarations Error)：** 测试了 `for...of` 循环中没有声明变量是否会报错。
28. **`for...of` 循环中的 `in` 运算符 (ForOf In Operator)：** 测试了 `for...of` 循环的迭代对象中使用 `in` 运算符是否能够正确解析。
29. **`for...of` 循环中的 `yield` 标识符 (ForOf Yield Identifier)：** 测试了在非生成器函数中使用 `yield` 作为 `for...of` 循环的迭代对象是否能够正确解析。
30. **`for...of` 循环中的 `yield` 表达式 (ForOf Yield Expression)：** 测试了在生成器函数中使用 `yield` 作为 `for...of` 循环的迭代对象是否能够正确解析。
31. **`for...of` 循环中的表达式错误 (ForOf Expression Error)：** 测试了 `for...of` 循环的迭代对象中使用逗号运算符或赋值表达式是否会报错。
32. **`for...of` 异步迭代 (ForOf Async)：** 测试了在 `for...of` 循环中使用 `async` 关键字（可能指 `async iterable`）的情况。
33. **无效的 Unicode 转义 (Invalid Unicode Escapes)：** 测试了各种不合法的 Unicode 转义序列是否会被解析器正确识别为错误。
34. **合法的 Unicode 转义 (Unicode Escapes)：** 测试了各种合法的 Unicode 转义序列是否能够被解析器正确处理。
35. **八进制转义 (Octal Escapes)：** 测试了八进制转义在严格模式和非严格模式下的不同处理。
36. **扫描模板字面量 (Scan Template Literals)：** 测试了各种合法的模板字面量语法是否能够被扫描器正确识别。
37. **扫描带标签的模板字面量 (Scan Tagged Template Literals)：** 测试了各种合法的带标签的模板字面量语法是否能够被扫描器正确识别。
38. **模板字面量的物化 (Template Materialized Literals)：** 测试了模板字面量作为表达式的情况。
39. **扫描未终止的模板字面量 (Scan Unterminated Template Literals)：** 测试了各种未正确关闭的模板字面量是否会被扫描器识别为错误。
40. **模板字面量的非法 Token (Template Literals Illegal Tokens)：** 测试了模板字面量中包含非法转义序列的情况。
41. **解析剩余参数 (Parse Rest Parameters)：** 测试了函数定义中使用剩余参数语法 ( `...args` ) 是否能够被正确解析。
42. **解析剩余参数错误 (Parse Rest Parameters Errors)：** 测试了函数定义中使用剩余参数语法时可能出现的错误，例如剩余参数后还有其他参数等。

**关于 `.tq` 结尾的文件：**

如果 `v8/test/unittests/parser/parsing-unittest.cc` 以 `.tq` 结尾，那它将是 **V8 Torque** 的源代码文件。Torque 是 V8 用来定义其内部运行时函数和内置对象的类型化中间语言。Torque 代码负责实现 JavaScript 语言的语义，而 C++ 代码（如 `parsing-unittest.cc`）则负责测试这些实现的正确性。在这种情况下，`.tq` 文件会包含用 Torque 编写的运行时函数的实现细节。

**与 JavaScript 功能的关系和 JavaScript 示例：**

所有这些测试都直接关系到 JavaScript 的功能。以下是一些例子：

* **静态访问器错误：**
   ```javascript
   class MyClass {
     static get #a() { return 1; } // 私有静态 getter，这里测试的是解析这种语法的错误
   }
   ```

* **私有名称解析错误：**
   ```javascript
   class MyClass {
     #privateField = 0;
     getPrivate() {
       return this.#privateField; // 正确访问私有字段
     }
   }
   const instance = new MyClass();
   console.log(instance.#privateField); // 错误：无法从类外部访问私有字段
   ```

* **类表达式错误：**
   ```javascript
   const MyClass = class { // 这是一个合法的类表达式
     constructor(value) {
       this.value = value;
     }
   };

   const InvalidClass = class extends { }; // 错误：缺少要继承的表达式
   ```

* **`for...in` 和 `for...of` 循环：**
   ```javascript
   const obj = { a: 1, b: 2 };
   for (let key in obj) {
     console.log(key); // 输出 "a", "b"
   }

   const arr = [1, 2, 3];
   for (const value of arr) {
     console.log(value); // 输出 1, 2, 3
   }
   ```

* **模板字面量：**
   ```javascript
   const name = "World";
   const greeting = `Hello, ${name}!`; // 使用模板字面量
   console.log(greeting); // 输出 "Hello, World!"
   ```

* **剩余参数：**
   ```javascript
   function sum(a, b, ...rest) {
     let total = a + b;
     for (let num of rest) {
       total += num;
     }
     return total;
   }
   console.log(sum(1, 2, 3, 4, 5)); // 输出 15
   ```

**代码逻辑推理的假设输入与输出：**

这些测试主要关注 **错误处理**，所以“代码逻辑推理”指的是解析器如何识别并报告语法错误。

**假设输入：** `static accessor #a b` (缺少赋值或方法体)

**预期输出：** 解析器会抛出一个语法错误，指出静态访问器的定义不完整。

**假设输入：** `this.#unknownPrivate` (访问未定义的私有字段)

**预期输出：** 解析器会抛出一个错误，表明 `#unknownPrivate` 不是当前类或其父类的私有字段。

**用户常见的编程错误举例说明：**

1. **忘记给静态访问器赋值或定义 get/set 方法：**
   ```javascript
   class MyClass {
     static accessor myProperty; // 常见错误，缺少赋值
   }
   ```

2. **在类外部错误地访问私有字段：**
   ```javascript
   class MyClass {
     #privateField = 0;
   }
   const instance = new MyClass();
   console.log(instance.#privateField); // 错误：无法直接访问
   ```

3. **在 `for...in` 或 `for...of` 循环中错误地初始化 `const` 声明的变量：**
   ```javascript
   for (const i = 0 in obj) { // 错误：for-in 循环中 const 不允许初始化
     console.log(i);
   }
   ```

4. **错误地使用模板字面量的语法：**
   ```javascript
   const name = "World";
   const greeting = `Hello, ${ name }!`; // 错误：花括号内不应该有空格
   ```

5. **在剩余参数之后定义其他参数：**
   ```javascript
   function myFunction(...rest, last) { // 错误：剩余参数必须是最后一个参数
     // ...
   }
   ```

**第 9 部分功能归纳：**

这部分 `parsing-unittest.cc` 的主要功能是 **全面测试 V8 JavaScript 解析器在处理各种类相关的语法结构、对象字面量、循环语句（`for...in` 和 `for...of`）、Unicode 转义、模板字面量以及剩余参数时的错误处理能力**。它通过提供各种包含语法错误的 JavaScript 代码片段，验证解析器是否能够正确地识别这些错误并进行报告，从而保证 V8 引擎在解析实际代码时的健壮性和准确性。 这部分测试覆盖了 ES6 及后续版本引入的许多新特性，着重于解析器对不符合语法规则的代码的识别。

### 提示词
```
这是目录为v8/test/unittests/parser/parsing-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/parser/parsing-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第9部分，共15部分，请归纳一下它的功能
```

### 源代码
```cpp
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
```