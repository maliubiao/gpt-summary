Response:
Let's break down the thought process for analyzing this V8 test file.

1. **Identify the Core Purpose:** The filename `parsing-unittest.cc` immediately suggests this file contains unit tests for the V8 JavaScript parser. The `.cc` extension confirms it's C++ source code.

2. **Scan for Key Phrases and Structures:** Look for recurring patterns, keywords, and code structures. In this file, `TEST_F(ParsingTest, ...)` is prominent. This is a common pattern in C++ unit testing frameworks (like Google Test, which V8 uses). It indicates individual test cases.

3. **Analyze Individual Test Cases:**  Examine the names of the `TEST_F` functions. They usually describe what's being tested. For example:
    * `RestParameterSyntax` and `RestParameterSyntaxError`: These clearly relate to the "rest parameter" feature in JavaScript (e.g., `...args`).
    * `RestParameterInSetterMethodError`:  Focuses on the specific context of using rest parameters within setter methods.
    * `RestParametersEvalArguments` and `RestParametersDuplicateEvalArguments`: These check the parser's behavior when rest parameters interact with the `eval` and `arguments` keywords (which have special handling in JavaScript).
    * `SpreadCall` and `SpreadCallErrors`:  These are about the "spread syntax" in function calls (e.g., `...[1, 2, 3]`).
    * `BadRestSpread`: Tests for invalid uses of the rest/spread syntax.
    * `LexicalScopingSloppyMode`:  Examines how lexical scoping works in non-strict mode JavaScript.
    * `ComputedPropertyName` and `ComputedPropertyNameShorthandError`: These relate to object literal property names that are calculated at runtime (e.g., `{[key]: value}`).
    * `BasicImportExportParsing`, `NamespaceExportParsing`, `ImportExportParsingErrors`: These sections are dedicated to testing the `import` and `export` syntax of JavaScript modules.
    * `ModuleTopLevelFunctionDecl`, `ModuleAwaitReserved`, `ModuleAwaitReservedPreParse`, `ModuleAwaitPermitted`, `EnumReserved`: These focus on specific parsing rules and restrictions within JavaScript modules (like top-level function declarations and the reserved keywords `await` and `enum`).
    * `ModuleParsingInternals` and `ModuleParsingInternalsWithImportAttributes`:  These delve into the internal structures created by the parser when processing modules, including the `SourceTextModuleDescriptor`.

4. **Infer Functionality from Test Names and Data:** Based on the test names and the data provided within the tests (the `context_data` and `data` arrays), deduce what specific parsing scenarios are being covered. For example, the `RestParameterSyntax` tests use various spacing and comma arrangements, suggesting they are testing the parser's robustness in handling different formatting. The `RestParameterInSetterMethodError` tests specifically try to use rest parameters in setters, which is disallowed.

5. **Connect to JavaScript Concepts:** Relate the test scenarios to corresponding JavaScript language features. For instance, the rest parameter syntax `...args` allows a function to accept an indefinite number of arguments. The spread syntax `...array` expands an iterable into individual elements. `import` and `export` are fundamental to JavaScript modules.

6. **Identify Potential User Errors:**  Consider what common mistakes a JavaScript programmer might make that these tests are designed to catch. Examples include: using `eval` or `arguments` as rest parameter names in strict mode, incorrectly placing the spread operator, or using invalid syntax for imports and exports.

7. **Check for `.tq` Mention:**  The prompt specifically asks about `.tq` files (Torque). Scan the text to see if `.tq` is mentioned. In this case, it isn't.

8. **Look for Logic/Reasoning:** Identify tests that seem to involve more than just syntax checking. The tests involving `eval` and `arguments` have subtle logic related to strict mode vs. sloppy mode. The module parsing tests involve verifying the internal data structures created by the parser.

9. **Address Specific Instructions:** Go back through the prompt and ensure all instructions are addressed. This includes:
    * Listing functionalities.
    * Checking for `.tq`.
    * Providing JavaScript examples.
    * Describing logic/reasoning.
    * Giving examples of user errors.
    * Summarizing the overall function.

10. **Synthesize a Summary:** Combine the findings from the individual test analysis to create a concise summary of the file's purpose. Emphasize that it's a unit test file focusing on the V8 parser and covering various JavaScript syntax features.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This is just a bunch of syntax tests."  **Correction:** While syntax is a primary focus, some tests delve into semantic aspects (like strict mode behavior) and internal parser structures.
* **Missing details:**  Realize that simply listing test names isn't enough. Need to explain *what* each test is testing and *why* it's important.
* **JavaScript examples:** Ensure the JavaScript examples are clear and directly illustrate the feature being tested.
* **User errors:**  Think about *realistic* mistakes developers make, not just any syntactical error.
* **Clarity and organization:** Structure the answer logically with clear headings and bullet points to make it easy to understand.

By following these steps and refining the analysis along the way, we arrive at a comprehensive understanding of the `parsing-unittest.cc` file.
好的，让我们来分析一下 `v8/test/unittests/parser/parsing-unittest.cc` 这个文件的功能。

**主要功能归纳:**

这个 C++ 文件是 V8 JavaScript 引擎的单元测试文件，专门用于测试 V8 的 JavaScript **解析器 (Parser)** 的功能。它包含了一系列的测试用例，用于验证解析器在处理各种合法的和非法的 JavaScript 代码片段时的行为是否符合预期。

**具体功能拆解:**

1. **测试 Rest 参数 (Rest Parameters):**
   - 验证 Rest 参数的正确语法，例如 `function(...args) {}`。
   - 测试 Rest 参数在不同上下文中的使用，例如普通函数、箭头函数、方法等。
   - 检查 Rest 参数在语法错误情况下的解析，例如在 setter 方法中使用 Rest 参数是非法的。
   - 测试 Rest 参数与 `eval` 和 `arguments` 关键字的交互，特别是在严格模式和非严格模式下的行为差异。

   **JavaScript 例子:**
   ```javascript
   function myFunction(a, b, ...rest) {
     console.log("a:", a);
     console.log("b:", b);
     console.log("rest:", rest);
   }

   myFunction(1, 2, 3, 4, 5); // 输出: a: 1, b: 2, rest: [3, 4, 5]
   ```

2. **测试 Spread 调用 (Spread Call):**
   - 验证 Spread 语法在函数调用中的使用，例如 `myFunction(...[1, 2, 3])`。
   - 测试 Spread 语法处理不同类型可迭代对象的能力，例如数组、字符串、Set 等。
   - 检查 Spread 语法在错误使用情况下的解析。

   **JavaScript 例子:**
   ```javascript
   function myFunction(a, b, c) {
     console.log("a:", a);
     console.log("b:", b);
     console.log("c:", c);
   }

   const arr = [1, 2, 3];
   myFunction(...arr); // 输出: a: 1, b: 2, c: 3
   ```

3. **测试错误的 Rest 和 Spread 语法 (BadRestSpread):**
   - 专门测试一些无效的 Rest 和 Spread 语法，确保解析器能够正确识别并报错。

   **用户常见的编程错误例子:**
   ```javascript
   // 错误的 Rest 语法
   return ...[1, 2, 3]; // 报错：'...' operator must be followed by an identifier

   // 错误的 Spread 语法
   function myFunction(...args,) {} // 报错：Unexpected token ','
   ```

4. **测试词法作用域 (Lexical Scoping) 在非严格模式下的行为:**
   - 验证 `let` 关键字在非严格模式下的作用域规则。

   **JavaScript 例子:**
   ```javascript
   function test() {
     if (true) {
       let x = 10;
       console.log(x); // 输出 10
     }
     // console.log(x); // 报错：x is not defined，因为 let 声明的变量有块级作用域
   }
   test();
   ```

5. **测试计算属性名 (Computed Property Name):**
   - 验证对象字面量中计算属性名的语法，例如 `{[key]: value}`。
   - 测试在不同的上下文中（对象字面量、类定义等）使用计算属性名。
   - 检查计算属性名表达式中可能出现的语法错误。

   **JavaScript 例子:**
   ```javascript
   const key = 'name';
   const obj = {
     [key]: 'Alice',
     ['age' + 1]: 30
   };
   console.log(obj.name); // 输出: Alice
   console.log(obj.age1); // 输出: 30
   ```

6. **测试 Import 和 Export 语法 (BasicImportExportParsing, NamespaceExportParsing, ImportExportParsingErrors):**
   - 验证 ES 模块的 `import` 和 `export` 语句的各种语法形式，包括具名导出、默认导出、命名空间导出、从模块重新导出等。
   - 区分模块解析和脚本解析的不同。
   - 检查各种 `import` 和 `export` 语句的语法错误。

   **JavaScript 例子:**
   ```javascript
   // module.js
   export const message = "Hello";
   export function greet(name) {
     return `Hello, ${name}!`;
   }
   export default class Greeter {
     constructor(greeting) {
       this.greeting = greeting;
     }
     greet(name) {
       return `${this.greeting}, ${name}!`;
     }
   }

   // main.js
   import { message, greet } from './module.js';
   import DefaultGreeter from './module.js';
   import * as Module from './module.js';

   console.log(message); // 输出: Hello
   console.log(greet("Bob")); // 输出: Hello, Bob!
   const greeter = new DefaultGreeter("Greetings");
   console.log(greeter.greet("Charlie")); // 输出: Greetings, Charlie!
   console.log(Module.message); // 输出: Hello
   ```

7. **测试模块顶级函数声明 (ModuleTopLevelFunctionDecl):**
   - 验证在 ES 模块的顶层作用域中，函数声明的行为和限制。例如，不允许重复声明同名函数。

   **用户常见的编程错误例子:**
   ```javascript
   // 在模块顶层重复声明同名函数会导致错误
   function myFunction() {}
   function myFunction() {} // 报错
   ```

8. **测试模块中 `await` 关键字的保留字状态 (ModuleAwaitReserved, ModuleAwaitReservedPreParse, ModuleAwaitPermitted):**
   - 在 ES 模块中，`await` 是一个保留字，不能作为变量名、函数名等。这些测试验证了这种限制。
   - 同时也测试了在模块上下文中允许使用 `await` 的情况，例如作为对象属性名。

   **JavaScript 例子:**
   ```javascript
   // 在模块顶层使用 await 作为变量名是非法的
   // let await = 5; // 报错

   async function myAsyncFunction() {
     return await Promise.resolve(10);
   }
   ```

9. **测试 `enum` 关键字的保留字状态 (EnumReserved):**
   - 验证 `enum` 关键字在严格模式下是保留字，不能作为变量名、函数名等。

   **用户常见的编程错误例子:**
   ```javascript
   // 在严格模式下使用 enum 作为变量名是非法的
   "use strict";
   // let enum = 5; // 报错
   ```

10. **测试模块解析的内部机制 (ModuleParsingInternals, ModuleParsingInternalsWithImportAttributes):**
    - 这些测试深入到解析器内部，检查解析模块时创建的内部数据结构，例如 `SourceTextModuleDescriptor`，它包含了模块的导出、导入信息等。
    - `ModuleParsingInternalsWithImportAttributes` 专门测试带有 import attributes 的模块导入语法。

**关于 `.tq` 文件:**

根据您的描述，如果 `v8/test/unittests/parser/parsing-unittest.cc` 以 `.tq` 结尾，那么它将是一个 V8 Torque 源代码文件。 Torque 是一种用于 V8 内部优化的类型化的中间语言。  然而，这个文件以 `.cc` 结尾，所以它是一个 C++ 文件，用于编写单元测试。

**总结第 10 部分的功能:**

作为第 10 部分，这个代码片段主要集中在 **测试 JavaScript 中 Rest 参数和 Spread 语法的解析**。 它涵盖了这些语法在不同上下文中的正确用法和错误用法，以及与 `eval` 和 `arguments` 等特殊关键字的交互。 这部分旨在确保 V8 的解析器能够准确地理解和处理这些现代 JavaScript 特性。

总而言之，`v8/test/unittests/parser/parsing-unittest.cc` 是一个重要的测试文件，用于确保 V8 的 JavaScript 解析器能够正确地解析各种 JavaScript 代码，为 V8 引擎的稳定性和正确性提供了保障。

Prompt: 
```
这是目录为v8/test/unittests/parser/parsing-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/parser/parsing-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第10部分，共15部分，请归纳一下它的功能

"""
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
"""


```