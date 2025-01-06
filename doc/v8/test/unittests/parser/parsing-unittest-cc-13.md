Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/test/unittests/parser/parsing-unittest.cc`.

Here's a breakdown of the thought process to answer the request:

1. **Identify the core purpose:** The code snippet consists primarily of test cases defined within the `ParsingTest` fixture. These test cases feed strings of JavaScript code to the V8 parser and assert certain behaviors.

2. **Analyze individual test cases:**  Examine the structure of each element in the `inners` array within the `CheckPessimisticAllocation` test. Each element represents a test case with:
    - `params`:  Code snippet potentially defining variables or parameters.
    - `source`:  Code snippet where the variable `my_var` is used.
    - `ctxt_allocate`: A boolean indicating whether the variable `my_var` should be allocated in the context (closure scope) or not.

3. **Understand the `CheckPessimisticAllocation` test:** This test appears to be checking V8's logic for determining if a variable needs to be allocated in the context. This is often related to whether a variable might be accessed by closures or within specific scopes (like `eval` or nested functions).

4. **Relate to JavaScript behavior:** Consider the JavaScript scoping rules that influence context allocation. Variables declared with `var` inside functions are function-scoped. Variables declared with `let` and `const` are block-scoped. Function declarations within blocks in strict mode also have block scope. Accessing variables from outside their scope, or inside nested functions (creating closures), or via `eval` often forces them into the context.

5. **Formulate JavaScript examples:** Based on the test cases, construct corresponding JavaScript examples that illustrate the scenarios being tested. Focus on cases where `my_var` *does* need context allocation and cases where it doesn't.

6. **Address `.tq` files:** Explain that a `.tq` extension signifies Torque code, which is a type system and meta-programming language used within V8. Since the filename is `.cc`, it's C++ and not Torque.

7. **Explain code logic inference:**  Describe how the test asserts the expected context allocation. Explain the input (JavaScript code) and the output (boolean indicating context allocation).

8. **Identify common programming errors:**  Connect the tested scenarios to common mistakes developers might make regarding variable scope and closures, leading to unexpected behavior.

9. **Summarize the functionality:** Provide a concise overview of the purpose of the code, emphasizing its role in testing the parser's context allocation logic. Highlight that it's a unit test for V8's parser.

10. **Address the "part 14 of 15" aspect:** Acknowledge the user's context and reiterate the specific function of *this* part, within the larger context of parser testing.

**Self-Correction/Refinement during thought process:**

- Initially, I might have focused too much on the specific C++ code. It's more important to explain the *JavaScript concepts* being tested.
- I need to clearly differentiate between cases requiring context allocation and those that don't, using JavaScript examples to make it concrete.
-  It's important to explain *why* certain scenarios lead to context allocation (closures, `eval`, strict mode block-level function declarations).
- Ensure the explanation of Torque is accurate and concise.

By following these steps and refining the explanations, a comprehensive and helpful answer can be constructed.
`v8/test/unittests/parser/parsing-unittest.cc` 是 V8 引擎中一个 C++ 源代码文件，它专门用于测试 V8 的 JavaScript **解析器 (parser)** 的功能。这个文件包含了大量的单元测试，用来验证解析器在处理各种 JavaScript 代码片段时的正确性。

**功能归纳:**

总的来说，这个代码片段主要测试了 V8 解析器在处理变量声明和作用域方面的特性，特别是关于 **“悲观上下文分配 (pessimistic context allocation)”** 的逻辑。  “悲观上下文分配”是指当解析器遇到某些可能需要将变量存储在闭包上下文中的情况时，会预先分配上下文。

**具体功能拆解:**

1. **`CheckPessimisticAllocation` 测试:**
   - 这个测试函数旨在验证 V8 解析器是否正确地判断在哪些情况下需要为变量 `my_var` 分配上下文（即，存储在闭包中）。
   - 它通过一系列预定义的 JavaScript 代码片段 (`inners` 数组) 来测试。
   - 每个测试用例包含：
     - `params`: 一段可能包含变量声明的代码。
     - `source`:  使用 `my_var` 的代码片段。
     - `ctxt_allocate`: 一个布尔值，指示解析器是否应该为 `my_var` 分配上下文。`true` 表示应该分配，`false` 表示不应该。
   - 测试逻辑会动态地将 `prefix`、不同的 `inner_function` 结构、`params` 和 `source` 以及 `suffix` 组合成完整的 JavaScript 代码字符串。
   - 然后，它会使用 V8 的解析器来解析这段代码。
   - 接着，它会检查解析后的作用域信息，特别是变量 `my_var` 是否被标记为需要在上下文中分配。

2. **测试用例分析 (`inners` 数组中的示例):**
   - **需要悲观上下文分配的情况 (`ctxt_allocate` 为 `true`):**
     - 当 `my_var` 在严格模式下的块级函数声明中被定义和使用时。这是因为在严格模式下，块级函数声明具有块级作用域。
     - 当 `my_var` 在默认参数中被使用，并且在函数体内部有同名变量声明时。
     - 当 `my_var` 在箭头函数的默认参数中使用，并且函数体内部有同名变量声明时。
     - 当 `my_var` 在嵌套的块级函数声明中使用，并且在外部作用域中也被使用时。
   - **不需要悲观上下文分配的情况 (`ctxt_allocate` 为 `false`):**
     - 当 `my_var` 使用 `var`、`let` 或 `const` 在全局或函数作用域中声明并使用时。
     - 当 `my_var` 作为函数参数被使用时。
     - 当 `my_var` 在非严格模式下的块级函数声明中定义和使用时 (因为非严格模式下的块级函数声明会被提升到函数作用域)。
     - 当 `my_var` 在 `try...catch` 语句的 `catch` 子句中声明时。
     - 当 `my_var` 在 `for` 循环的头部或循环体中使用 `let` 或 `var` 声明时。
     - 当 `my_var` 作为类名或函数名被使用时。

3. **`EscapedStrictReservedWord` 测试:**
   - 这个测试验证了在非严格模式下，可以使用转义字符来创建与严格模式保留字相同的标识符，例如 `l\u0065t` 代表 `let`。

4. **`ForAwaitOf` 和 `ForAwaitOfErrors` 测试:**
   - 这些测试专注于 `for await...of` 循环的解析。
   - `ForAwaitOf` 测试了各种合法的 `for await...of` 循环的语法结构，包括不同的变量声明方式 (`var`, `let`, `const`) 和解构赋值。
   - `ForAwaitOfErrors` 测试了不合法的 `for await...of` 循环语法，例如在循环变量中使用赋值表达式或多个变量声明。

5. **`ForAwaitOfFunctionDeclaration` 测试:**
   - 这个测试验证了在 `for await...of` 循环中不允许直接声明函数。

6. **`AsyncGenerator` 和 `AsyncGeneratorErrors` 测试:**
   - 这些测试关注异步生成器函数的解析。
   - `AsyncGenerator` 测试了异步生成器函数中合法的 `yield` 和 `await` 表达式的使用。
   - `AsyncGeneratorErrors` 测试了异步生成器函数中不合法的 `yield` 和 `await` 表达式的使用，以及与严格模式相关的错误。

7. **`LexicalLoopVariable` 测试:**
   - 这个测试验证了 `let` 声明的循环变量在不同情况下的作用域和生命周期。它检查了当循环变量在循环体内被闭包捕获时，是否会正确地分配到上下文中。

**如果 `v8/test/unittests/parser/parsing-unittest.cc` 以 `.tq` 结尾:**

如果文件名以 `.tq` 结尾，那么它就不是 C++ 代码，而是 **V8 Torque** 源代码。 Torque 是一种 V8 内部使用的类型化的中间语言，用于实现 V8 的内置函数和运行时部分。这个文件将会包含使用 Torque 语法编写的测试代码，可能专注于类型系统的验证或更底层的 V8 功能测试。但由于文件名是 `.cc`，所以当前分析是针对 C++ 代码。

**与 JavaScript 功能的关系和示例:**

`v8/test/unittests/parser/parsing-unittest.cc` 中测试的很多特性都直接对应着 JavaScript 的语法和语义。例如，`CheckPessimisticAllocation` 测试的实际上是 JavaScript 的变量作用域和闭包特性。

**JavaScript 示例 (对应 `CheckPessimisticAllocation` 中的一些用例):**

```javascript
// 需要悲观上下文分配的例子：

'use strict';
function outer() {
  if (true) {
    function my_var() {} // 块级函数声明
  }
  my_var; // 访问块级作用域外的 my_var，需要上下文分配
}

function withDefaultParam(a = my_var) { // 默认参数中使用 my_var
  let my_var; // 函数体内声明同名变量
  console.log(a);
}

// 不需要悲观上下文分配的例子：

var globalVar = 10;
console.log(globalVar); // 全局作用域，不需要上下文分配

function funcParam(my_var) { // my_var 作为函数参数
  console.log(my_var);
}

function nonStrictBlockFunc() {
  if (true) {
    function my_var() {} // 非严格模式下的块级函数声明会被提升
  }
  my_var; // 可以访问，不需要额外的上下文分配
}
```

**代码逻辑推理 (以 `CheckPessimisticAllocation` 为例):**

**假设输入:**

```javascript
prefix = "";
inner_function = "function inner2(%s) { %s my_var; }";
params = "";
source = "if (true) { function my_var() {} }";
suffix = "";
```

**预期输出 (根据测试用例):** `ctxt_allocate` 应该为 `true`，因为在严格模式下（虽然这个例子没有显式声明严格模式，但某些 `inner_function` 可能会引入），块级函数声明会影响作用域，外部访问需要上下文。

**常见编程错误举例:**

```javascript
// 错误示例 1: 意外的全局变量
function myFunction() {
  myVar = 10; // 忘记使用 var, let 或 const，创建了全局变量
  console.log(myVar);
}
myFunction();
console.log(myVar); // 全局变量可以访问

// 错误示例 2: 闭包中的作用域问题
function createCounter() {
  var count = 0;
  return function() {
    count++; // 期望访问外部的 count
    console.log(count);
  };
}
const counter1 = createCounter();
counter1(); // 输出 1
counter1(); // 输出 2

// 错误示例 3:  在块级作用域中使用 var (容易造成变量提升带来的困惑)
function exampleVarScope() {
  if (true) {
    var message = "Hello";
  }
  console.log(message); // 可以访问，因为 var 有函数作用域
}
exampleVarScope();

// 错误示例 4: 在块级作用域中使用 let/const (更符合预期)
function exampleLetScope() {
  if (true) {
    let message = "Hello";
    console.log(message);
  }
  // console.log(message); // 报错，message 在块级作用域外不可访问
}
exampleLetScope();
```

**第 14 部分，共 15 部分的功能归纳:**

作为 `v8/test/unittests/parser/parsing-unittest.cc` 的第 14 部分，这个代码片段的核心功能仍然是 **测试 V8 JavaScript 解析器的正确性**，特别关注以下方面：

- **变量作用域和上下文分配:** 验证解析器是否正确地判断何时需要为变量分配上下文，这对于实现闭包和正确的作用域链至关重要。
- **`for await...of` 循环的解析:** 确保解析器能够正确处理异步迭代的语法结构。
- **异步生成器函数的解析:**  验证解析器对异步生成器函数中 `yield` 和 `await` 表达式的处理。
- **严格模式下的块级作用域:**  测试严格模式下块级函数声明的作用域行为。
- **转义字符和保留字:** 确保解析器能正确处理转义后的严格模式保留字。
- **`let` 声明的循环变量的作用域:** 验证 `let` 声明的循环变量在不同情况下的作用域和生命周期管理。

总而言之，这一部分是 V8 引擎解析器单元测试中的一个重要组成部分，专注于验证解析器在处理复杂的变量声明、作用域以及异步编程相关的语法时的正确性，以确保 V8 引擎能够准确地理解和执行 JavaScript 代码。

Prompt: 
```
这是目录为v8/test/unittests/parser/parsing-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/parser/parsing-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第14部分，共15部分，请归纳一下它的功能

"""
ar() {} } my_var;", true},
      {"",
       "'use strict'; function inner2() { if (true) { function my_var() {} }  "
       "my_var; }",
       true},
      {"",
       "function inner2() { 'use strict'; if (true) { function my_var() {} }  "
       "my_var; }",
       true},
      {"",
       "() => { 'use strict'; if (true) { function my_var() {} }  my_var; }",
       true},
      {"",
       "if (true) { let my_var; if (true) { function my_var() {} } } my_var;",
       true},
      {"", "function inner2(a = my_var) {}", true},
      {"", "function inner2(a = my_var) { let my_var; }", true},
      {"", "(a = my_var) => {}", true},
      {"", "(a = my_var) => { let my_var; }", true},
      // No pessimistic context allocation:
      {"", "var my_var; my_var;", false},
      {"", "var my_var;", false},
      {"", "var my_var = 0;", false},
      {"", "if (true) { var my_var; } my_var;", false},
      {"", "let my_var; my_var;", false},
      {"", "let my_var;", false},
      {"", "let my_var = 0;", false},
      {"", "const my_var = 0; my_var;", false},
      {"", "const my_var = 0;", false},
      {"", "var [a, my_var] = [1, 2]; my_var;", false},
      {"", "let [a, my_var] = [1, 2]; my_var;", false},
      {"", "const [a, my_var] = [1, 2]; my_var;", false},
      {"", "var {a: my_var} = {a: 3}; my_var;", false},
      {"", "let {a: my_var} = {a: 3}; my_var;", false},
      {"", "const {a: my_var} = {a: 3}; my_var;", false},
      {"", "var {my_var} = {my_var: 3}; my_var;", false},
      {"", "let {my_var} = {my_var: 3}; my_var;", false},
      {"", "const {my_var} = {my_var: 3}; my_var;", false},
      {"my_var", "my_var;", false},
      {"my_var", "", false},
      {"my_var = 5", "my_var;", false},
      {"my_var = 5", "", false},
      {"...my_var", "my_var;", false},
      {"...my_var", "", false},
      {"[a, my_var, b]", "my_var;", false},
      {"[a, my_var, b]", "", false},
      {"[a, my_var, b] = [1, 2, 3]", "my_var;", false},
      {"[a, my_var, b] = [1, 2, 3]", "", false},
      {"{x: my_var}", "my_var;", false},
      {"{x: my_var}", "", false},
      {"{x: my_var} = {x: 0}", "my_var;", false},
      {"{x: my_var} = {x: 0}", "", false},
      {"{my_var}", "my_var;", false},
      {"{my_var}", "", false},
      {"{my_var} = {my_var: 0}", "my_var;", false},
      {"{my_var} = {my_var: 0}", "", false},
      {"", "function inner2(my_var) { my_var; }", false},
      {"", "function inner2(my_var) { }", false},
      {"", "function inner2(my_var = 5) { my_var; }", false},
      {"", "function inner2(my_var = 5) { }", false},
      {"", "function inner2(...my_var) { my_var; }", false},
      {"", "function inner2(...my_var) { }", false},
      {"", "function inner2([a, my_var, b]) { my_var; }", false},
      {"", "function inner2([a, my_var, b]) { }", false},
      {"", "function inner2([a, my_var, b] = [1, 2, 3]) { my_var; }", false},
      {"", "function inner2([a, my_var, b] = [1, 2, 3]) { }", false},
      {"", "function inner2({x: my_var}) { my_var; }", false},
      {"", "function inner2({x: my_var}) { }", false},
      {"", "function inner2({x: my_var} = {x: 0}) { my_var; }", false},
      {"", "function inner2({x: my_var} = {x: 0}) { }", false},
      {"", "function inner2({my_var}) { my_var; }", false},
      {"", "function inner2({my_var}) { }", false},
      {"", "function inner2({my_var} = {my_var: 8}) { my_var; } ", false},
      {"", "function inner2({my_var} = {my_var: 8}) { }", false},
      {"", "my_var => my_var;", false},
      {"", "my_var => { }", false},
      {"", "(my_var = 5) => my_var;", false},
      {"", "(my_var = 5) => { }", false},
      {"", "(...my_var) => my_var;", false},
      {"", "(...my_var) => { }", false},
      {"", "([a, my_var, b]) => my_var;", false},
      {"", "([a, my_var, b]) => { }", false},
      {"", "([a, my_var, b] = [1, 2, 3]) => my_var;", false},
      {"", "([a, my_var, b] = [1, 2, 3]) => { }", false},
      {"", "({x: my_var}) => my_var;", false},
      {"", "({x: my_var}) => { }", false},
      {"", "({x: my_var} = {x: 0}) => my_var;", false},
      {"", "({x: my_var} = {x: 0}) => { }", false},
      {"", "({my_var}) => my_var;", false},
      {"", "({my_var}) => { }", false},
      {"", "({my_var} = {my_var: 5}) => my_var;", false},
      {"", "({my_var} = {my_var: 5}) => { }", false},
      {"", "({a, my_var}) => my_var;", false},
      {"", "({a, my_var}) => { }", false},
      {"", "({a, my_var} = {a: 0, my_var: 5}) => my_var;", false},
      {"", "({a, my_var} = {a: 0, my_var: 5}) => { }", false},
      {"", "({y, x: my_var}) => my_var;", false},
      {"", "({y, x: my_var}) => { }", false},
      {"", "({y, x: my_var} = {y: 0, x: 0}) => my_var;", false},
      {"", "({y, x: my_var} = {y: 0, x: 0}) => { }", false},
      {"", "try { } catch (my_var) { my_var; }", false},
      {"", "try { } catch ([a, my_var, b]) { my_var; }", false},
      {"", "try { } catch ({x: my_var}) { my_var; }", false},
      {"", "try { } catch ({y, x: my_var}) { my_var; }", false},
      {"", "try { } catch ({my_var}) { my_var; }", false},
      {"", "for (let my_var in {}) { my_var; }", false},
      {"", "for (let my_var in {}) { }", false},
      {"", "for (let my_var of []) { my_var; }", false},
      {"", "for (let my_var of []) { }", false},
      {"", "for (let [a, my_var, b] in {}) { my_var; }", false},
      {"", "for (let [a, my_var, b] of []) { my_var; }", false},
      {"", "for (let {x: my_var} in {}) { my_var; }", false},
      {"", "for (let {x: my_var} of []) { my_var; }", false},
      {"", "for (let {my_var} in {}) { my_var; }", false},
      {"", "for (let {my_var} of []) { my_var; }", false},
      {"", "for (let {y, x: my_var} in {}) { my_var; }", false},
      {"", "for (let {y, x: my_var} of []) { my_var; }", false},
      {"", "for (let {a, my_var} in {}) { my_var; }", false},
      {"", "for (let {a, my_var} of []) { my_var; }", false},
      {"", "for (var my_var in {}) { my_var; }", false},
      {"", "for (var my_var in {}) { }", false},
      {"", "for (var my_var of []) { my_var; }", false},
      {"", "for (var my_var of []) { }", false},
      {"", "for (var [a, my_var, b] in {}) { my_var; }", false},
      {"", "for (var [a, my_var, b] of []) { my_var; }", false},
      {"", "for (var {x: my_var} in {}) { my_var; }", false},
      {"", "for (var {x: my_var} of []) { my_var; }", false},
      {"", "for (var {my_var} in {}) { my_var; }", false},
      {"", "for (var {my_var} of []) { my_var; }", false},
      {"", "for (var {y, x: my_var} in {}) { my_var; }", false},
      {"", "for (var {y, x: my_var} of []) { my_var; }", false},
      {"", "for (var {a, my_var} in {}) { my_var; }", false},
      {"", "for (var {a, my_var} of []) { my_var; }", false},
      {"", "for (var my_var in {}) { } my_var;", false},
      {"", "for (var my_var of []) { } my_var;", false},
      {"", "for (var [a, my_var, b] in {}) { } my_var;", false},
      {"", "for (var [a, my_var, b] of []) { } my_var;", false},
      {"", "for (var {x: my_var} in {}) { } my_var;", false},
      {"", "for (var {x: my_var} of []) { } my_var;", false},
      {"", "for (var {my_var} in {}) { } my_var;", false},
      {"", "for (var {my_var} of []) { } my_var;", false},
      {"", "for (var {y, x: my_var} in {}) { } my_var;", false},
      {"", "for (var {y, x: my_var} of []) { } my_var;", false},
      {"", "for (var {a, my_var} in {}) { } my_var;", false},
      {"", "for (var {a, my_var} of []) { } my_var;", false},
      {"", "for (let my_var = 0; my_var < 1; ++my_var) { my_var; }", false},
      {"", "for (var my_var = 0; my_var < 1; ++my_var) { my_var; }", false},
      {"", "for (var my_var = 0; my_var < 1; ++my_var) { } my_var; ", false},
      {"", "for (let a = 0, my_var = 0; my_var < 1; ++my_var) { my_var }",
       false},
      {"", "for (var a = 0, my_var = 0; my_var < 1; ++my_var) { my_var }",
       false},
      {"", "class my_var {}; my_var; ", false},
      {"", "function my_var() {} my_var;", false},
      {"", "if (true) { function my_var() {} }  my_var;", false},
      {"", "function inner2() { if (true) { function my_var() {} }  my_var; }",
       false},
      {"", "() => { if (true) { function my_var() {} }  my_var; }", false},
      {"",
       "if (true) { var my_var; if (true) { function my_var() {} } }  my_var;",
       false},
  };

  for (unsigned inner_ix = 0; inner_ix < arraysize(inner_functions);
       ++inner_ix) {
    const char* inner_function = inner_functions[inner_ix];
    int inner_function_len = Utf8LengthHelper(inner_function) - 4;

    for (unsigned i = 0; i < arraysize(inners); ++i) {
      int params_len = Utf8LengthHelper(inners[i].params);
      int source_len = Utf8LengthHelper(inners[i].source);
      int len = prefix_len + inner_function_len + params_len + source_len +
                suffix_len;

      base::ScopedVector<char> program(len + 1);
      base::SNPrintF(program, "%s", prefix);
      base::SNPrintF(program + prefix_len, inner_function, inners[i].params,
                     inners[i].source);
      base::SNPrintF(
          program + prefix_len + inner_function_len + params_len + source_len,
          "%s", suffix);

      i::DirectHandle<i::String> source =
          factory->InternalizeUtf8String(program.begin());
      source->PrintOn(stdout);
      printf("\n");

      i::Handle<i::Script> script = factory->NewScript(source);
      i::UnoptimizedCompileState compile_state;
      i::ReusableUnoptimizedCompileState reusable_state(isolate);
      i::UnoptimizedCompileFlags flags =
          i::UnoptimizedCompileFlags::ForScriptCompile(isolate, *script);
      i::ParseInfo info(isolate, flags, &compile_state, &reusable_state);

      CHECK_PARSE_PROGRAM(&info, script, isolate);

      i::Scope* scope = info.literal()->scope()->inner_scope();
      DCHECK_NOT_NULL(scope);
      DCHECK_NULL(scope->sibling());
      DCHECK(scope->is_function_scope());
      const i::AstRawString* var_name =
          info.ast_value_factory()->GetOneByteString("my_var");
      i::Variable* var = scope->LookupForTesting(var_name);
      CHECK_EQ(inners[i].ctxt_allocate,
               i::ScopeTestHelper::MustAllocateInContext(var));
    }
  }
}

TEST_F(ParsingTest, EscapedStrictReservedWord) {
  // Test that identifiers which are both escaped and only reserved in the
  // strict mode are accepted in non-strict mode.
  const char* context_data[][2] = {{"", ""}, {nullptr, nullptr}};

  const char* statement_data[] = {"if (true) l\\u0065t: ;",
                                  "function l\\u0065t() { }",
                                  "(function l\\u0065t() { })",
                                  "async function l\\u0065t() { }",
                                  "(async function l\\u0065t() { })",
                                  "l\\u0065t => 42",
                                  "async l\\u0065t => 42",
                                  "function packag\\u0065() {}",
                                  "function impl\\u0065ments() {}",
                                  "function privat\\u0065() {}",
                                  nullptr};

  RunParserSyncTest(context_data, statement_data, kSuccess);
}

TEST_F(ParsingTest, ForAwaitOf) {
  // clang-format off
  const char* context_data[][2] = {
    { "async function f() { for await ", " ; }" },
    { "async function f() { for await ", " { } }" },
    { "async function * f() { for await ", " { } }" },
    { "async function f() { 'use strict'; for await ", " ; }" },
    { "async function f() { 'use strict'; for await ", "  { } }" },
    { "async function * f() { 'use strict'; for await ", "  { } }" },
    { "async function f() { for\nawait ", " ; }" },
    { "async function f() { for\nawait ", " { } }" },
    { "async function * f() { for\nawait ", " { } }" },
    { "async function f() { 'use strict'; for\nawait ", " ; }" },
    { "async function f() { 'use strict'; for\nawait ", " { } }" },
    { "async function * f() { 'use strict'; for\nawait ", " { } }" },
    { "async function f() { for await\n", " ; }" },
    { "async function f() { for await\n", " { } }" },
    { "async function * f() { for await\n", " { } }" },
    { "async function f() { 'use strict'; for await\n", " ; }" },
    { "async function f() { 'use strict'; for await\n", " { } }" },
    { "async function * f() { 'use strict'; for await\n", " { } }" },
    { nullptr, nullptr }
  };

  const char* context_data2[][2] = {
    { "async function f() { let a; for await ", " ; }" },
    { "async function f() { let a; for await ", " { } }" },
    { "async function * f() { let a; for await ", " { } }" },
    { "async function f() { 'use strict'; let a; for await ", " ; }" },
    { "async function f() { 'use strict'; let a; for await ", "  { } }" },
    { "async function * f() { 'use strict'; let a; for await ", "  { } }" },
    { "async function f() { let a; for\nawait ", " ; }" },
    { "async function f() { let a; for\nawait ", " { } }" },
    { "async function * f() { let a; for\nawait ", " { } }" },
    { "async function f() { 'use strict'; let a; for\nawait ", " ; }" },
    { "async function f() { 'use strict'; let a; for\nawait ", " { } }" },
    { "async function * f() { 'use strict'; let a; for\nawait ", " { } }" },
    { "async function f() { let a; for await\n", " ; }" },
    { "async function f() { let a; for await\n", " { } }" },
    { "async function * f() { let a; for await\n", " { } }" },
    { "async function f() { 'use strict'; let a; for await\n", " ; }" },
    { "async function f() { 'use strict'; let a; for await\n", " { } }" },
    { "async function * f() { 'use strict'; let a; for await\n", " { } }" },
    { nullptr, nullptr }
  };

  const char* expr_data[] = {
    // Primary Expressions
    "(a of [])",
    "(a.b of [])",
    "([a] of [])",
    "([a = 1] of [])",
    "([a = 1, ...b] of [])",
    "({a} of [])",
    "({a: a} of [])",
    "({'a': a} of [])",
    "({\"a\": a} of [])",
    "({[Symbol.iterator]: a} of [])",
    "({0: a} of [])",
    "({a = 1} of [])",
    "({a: a = 1} of [])",
    "({'a': a = 1} of [])",
    "({\"a\": a = 1} of [])",
    "({[Symbol.iterator]: a = 1} of [])",
    "({0: a = 1} of [])",
    nullptr
  };

  const char* var_data[] = {
    // VarDeclarations
    "(var a of [])",
    "(var [a] of [])",
    "(var [a = 1] of [])",
    "(var [a = 1, ...b] of [])",
    "(var {a} of [])",
    "(var {a: a} of [])",
    "(var {'a': a} of [])",
    "(var {\"a\": a} of [])",
    "(var {[Symbol.iterator]: a} of [])",
    "(var {0: a} of [])",
    "(var {a = 1} of [])",
    "(var {a: a = 1} of [])",
    "(var {'a': a = 1} of [])",
    "(var {\"a\": a = 1} of [])",
    "(var {[Symbol.iterator]: a = 1} of [])",
    "(var {0: a = 1} of [])",
    nullptr
  };

  const char* lexical_data[] = {
    // LexicalDeclartions
    "(let a of [])",
    "(let [a] of [])",
    "(let [a = 1] of [])",
    "(let [a = 1, ...b] of [])",
    "(let {a} of [])",
    "(let {a: a} of [])",
    "(let {'a': a} of [])",
    "(let {\"a\": a} of [])",
    "(let {[Symbol.iterator]: a} of [])",
    "(let {0: a} of [])",
    "(let {a = 1} of [])",
    "(let {a: a = 1} of [])",
    "(let {'a': a = 1} of [])",
    "(let {\"a\": a = 1} of [])",
    "(let {[Symbol.iterator]: a = 1} of [])",
    "(let {0: a = 1} of [])",

    "(const a of [])",
    "(const [a] of [])",
    "(const [a = 1] of [])",
    "(const [a = 1, ...b] of [])",
    "(const {a} of [])",
    "(const {a: a} of [])",
    "(const {'a': a} of [])",
    "(const {\"a\": a} of [])",
    "(const {[Symbol.iterator]: a} of [])",
    "(const {0: a} of [])",
    "(const {a = 1} of [])",
    "(const {a: a = 1} of [])",
    "(const {'a': a = 1} of [])",
    "(const {\"a\": a = 1} of [])",
    "(const {[Symbol.iterator]: a = 1} of [])",
    "(const {0: a = 1} of [])",
    nullptr
  };
  // clang-format on
  RunParserSyncTest(context_data, expr_data, kSuccess);
  RunParserSyncTest(context_data2, expr_data, kSuccess);

  RunParserSyncTest(context_data, var_data, kSuccess);
  // TODO(marja): PreParser doesn't report early errors.
  //              (https://bugs.chromium.org/p/v8/issues/detail?id=2728)
  // RunParserSyncTest(context_data2, var_data, kError, nullptr, 0,
  // always_flags,
  //                   arraysize(always_flags));

  RunParserSyncTest(context_data, lexical_data, kSuccess);
  RunParserSyncTest(context_data2, lexical_data, kSuccess);
}

TEST_F(ParsingTest, ForAwaitOfErrors) {
  // clang-format off
  const char* context_data[][2] = {
    { "async function f() { for await ", " ; }" },
    { "async function f() { for await ", " { } }" },
    { "async function f() { 'use strict'; for await ", " ; }" },
    { "async function f() { 'use strict'; for await ", "  { } }" },
    { "async function * f() { for await ", " ; }" },
    { "async function * f() { for await ", " { } }" },
    { "async function * f() { 'use strict'; for await ", " ; }" },
    { "async function * f() { 'use strict'; for await ", "  { } }" },
    { nullptr, nullptr }
  };

  const char* data[] = {
    // Primary Expressions
    "(a = 1 of [])",
    "(a = 1) of [])",
    "(a.b = 1 of [])",
    "((a.b = 1) of [])",
    "([a] = 1 of [])",
    "(([a] = 1) of [])",
    "([a = 1] = 1 of [])",
    "(([a = 1] = 1) of [])",
    "([a = 1 = 1, ...b] = 1 of [])",
    "(([a = 1 = 1, ...b] = 1) of [])",
    "({a} = 1 of [])",
    "(({a} = 1) of [])",
    "({a: a} = 1 of [])",
    "(({a: a} = 1) of [])",
    "({'a': a} = 1 of [])",
    "(({'a': a} = 1) of [])",
    "({\"a\": a} = 1 of [])",
    "(({\"a\": a} = 1) of [])",
    "({[Symbol.iterator]: a} = 1 of [])",
    "(({[Symbol.iterator]: a} = 1) of [])",
    "({0: a} = 1 of [])",
    "(({0: a} = 1) of [])",
    "({a = 1} = 1 of [])",
    "(({a = 1} = 1) of [])",
    "({a: a = 1} = 1 of [])",
    "(({a: a = 1} = 1) of [])",
    "({'a': a = 1} = 1 of [])",
    "(({'a': a = 1} = 1) of [])",
    "({\"a\": a = 1} = 1 of [])",
    "(({\"a\": a = 1} = 1) of [])",
    "({[Symbol.iterator]: a = 1} = 1 of [])",
    "(({[Symbol.iterator]: a = 1} = 1) of [])",
    "({0: a = 1} = 1 of [])",
    "(({0: a = 1} = 1) of [])",
    "(function a() {} of [])",
    "([1] of [])",
    "({a: 1} of [])"

    // VarDeclarations
    "(var a = 1 of [])",
    "(var a, b of [])",
    "(var [a] = 1 of [])",
    "(var [a], b of [])",
    "(var [a = 1] = 1 of [])",
    "(var [a = 1], b of [])",
    "(var [a = 1 = 1, ...b] of [])",
    "(var [a = 1, ...b], c of [])",
    "(var {a} = 1 of [])",
    "(var {a}, b of [])",
    "(var {a: a} = 1 of [])",
    "(var {a: a}, b of [])",
    "(var {'a': a} = 1 of [])",
    "(var {'a': a}, b of [])",
    "(var {\"a\": a} = 1 of [])",
    "(var {\"a\": a}, b of [])",
    "(var {[Symbol.iterator]: a} = 1 of [])",
    "(var {[Symbol.iterator]: a}, b of [])",
    "(var {0: a} = 1 of [])",
    "(var {0: a}, b of [])",
    "(var {a = 1} = 1 of [])",
    "(var {a = 1}, b of [])",
    "(var {a: a = 1} = 1 of [])",
    "(var {a: a = 1}, b of [])",
    "(var {'a': a = 1} = 1 of [])",
    "(var {'a': a = 1}, b of [])",
    "(var {\"a\": a = 1} = 1 of [])",
    "(var {\"a\": a = 1}, b of [])",
    "(var {[Symbol.iterator]: a = 1} = 1 of [])",
    "(var {[Symbol.iterator]: a = 1}, b of [])",
    "(var {0: a = 1} = 1 of [])",
    "(var {0: a = 1}, b of [])",

    // LexicalDeclartions
    "(let a = 1 of [])",
    "(let a, b of [])",
    "(let [a] = 1 of [])",
    "(let [a], b of [])",
    "(let [a = 1] = 1 of [])",
    "(let [a = 1], b of [])",
    "(let [a = 1, ...b] = 1 of [])",
    "(let [a = 1, ...b], c of [])",
    "(let {a} = 1 of [])",
    "(let {a}, b of [])",
    "(let {a: a} = 1 of [])",
    "(let {a: a}, b of [])",
    "(let {'a': a} = 1 of [])",
    "(let {'a': a}, b of [])",
    "(let {\"a\": a} = 1 of [])",
    "(let {\"a\": a}, b of [])",
    "(let {[Symbol.iterator]: a} = 1 of [])",
    "(let {[Symbol.iterator]: a}, b of [])",
    "(let {0: a} = 1 of [])",
    "(let {0: a}, b of [])",
    "(let {a = 1} = 1 of [])",
    "(let {a = 1}, b of [])",
    "(let {a: a = 1} = 1 of [])",
    "(let {a: a = 1}, b of [])",
    "(let {'a': a = 1} = 1 of [])",
    "(let {'a': a = 1}, b of [])",
    "(let {\"a\": a = 1} = 1 of [])",
    "(let {\"a\": a = 1}, b of [])",
    "(let {[Symbol.iterator]: a = 1} = 1 of [])",
    "(let {[Symbol.iterator]: a = 1}, b of [])",
    "(let {0: a = 1} = 1 of [])",
    "(let {0: a = 1}, b of [])",

    "(const a = 1 of [])",
    "(const a, b of [])",
    "(const [a] = 1 of [])",
    "(const [a], b of [])",
    "(const [a = 1] = 1 of [])",
    "(const [a = 1], b of [])",
    "(const [a = 1, ...b] = 1 of [])",
    "(const [a = 1, ...b], b of [])",
    "(const {a} = 1 of [])",
    "(const {a}, b of [])",
    "(const {a: a} = 1 of [])",
    "(const {a: a}, b of [])",
    "(const {'a': a} = 1 of [])",
    "(const {'a': a}, b of [])",
    "(const {\"a\": a} = 1 of [])",
    "(const {\"a\": a}, b of [])",
    "(const {[Symbol.iterator]: a} = 1 of [])",
    "(const {[Symbol.iterator]: a}, b of [])",
    "(const {0: a} = 1 of [])",
    "(const {0: a}, b of [])",
    "(const {a = 1} = 1 of [])",
    "(const {a = 1}, b of [])",
    "(const {a: a = 1} = 1 of [])",
    "(const {a: a = 1}, b of [])",
    "(const {'a': a = 1} = 1 of [])",
    "(const {'a': a = 1}, b of [])",
    "(const {\"a\": a = 1} = 1 of [])",
    "(const {\"a\": a = 1}, b of [])",
    "(const {[Symbol.iterator]: a = 1} = 1 of [])",
    "(const {[Symbol.iterator]: a = 1}, b of [])",
    "(const {0: a = 1} = 1 of [])",
    "(const {0: a = 1}, b of [])",

    nullptr
  };
  // clang-format on
  RunParserSyncTest(context_data, data, kError);
}

TEST_F(ParsingTest, ForAwaitOfFunctionDeclaration) {
  // clang-format off
  const char* context_data[][2] = {
    { "async function f() {", "}" },
    { "async function f() { 'use strict'; ", "}" },
    { nullptr, nullptr }
  };

  const char* data[] = {
    "for await (x of []) function d() {};",
    "for await (x of []) function d() {}; return d;",
    "for await (x of []) function* g() {};",
    "for await (x of []) function* g() {}; return g;",
    // TODO(caitp): handle async function declarations in ParseScopedStatement.
    // "for await (x of []) async function a() {};",
    // "for await (x of []) async function a() {}; return a;",
    nullptr
  };

  // clang-format on
  RunParserSyncTest(context_data, data, kError);
}

TEST_F(ParsingTest, AsyncGenerator) {
  // clang-format off
  const char* context_data[][2] = {
    { "async function * gen() {", "}" },
    { "(async function * gen() {", "})" },
    { "(async function * () {", "})" },
    { "({ async * gen () {", "} })" },
    { nullptr, nullptr }
  };

  const char* statement_data[] = {
    // An async generator without a body is valid.
    ""
    // Valid yield expressions inside generators.
    "yield 2;",
    "yield * 2;",
    "yield * \n 2;",
    "yield yield 1;",
    "yield * yield * 1;",
    "yield 3 + (yield 4);",
    "yield * 3 + (yield * 4);",
    "(yield * 3) + (yield * 4);",
    "yield 3; yield 4;",
    "yield * 3; yield * 4;",
    "(function (yield) { })",
    "(function yield() { })",
    "(function (await) { })",
    "(function await() { })",
    "yield { yield: 12 }",
    "yield /* comment */ { yield: 12 }",
    "yield * \n { yield: 12 }",
    "yield /* comment */ * \n { yield: 12 }",
    // You can return in an async generator.
    "yield 1; return",
    "yield * 1; return",
    "yield 1; return 37",
    "yield * 1; return 37",
    "yield 1; return 37; yield 'dead';",
    "yield * 1; return 37; yield * 'dead';",
    // Yield/Await are still a valid key in object literals.
    "({ yield: 1 })",
    "({ get yield() { } })",
    "({ await: 1 })",
    "({ get await() { } })",
    // And in assignment pattern computed properties
    "({ [yield]: x } = { })",
    "({ [await 1]: x } = { })",
    // Yield without RHS.
    "yield;",
    "yield",
    "yield\n",
    "yield /* comment */"
    "yield // comment\n"
    "(yield)",
    "[yield]",
    "{yield}",
    "yield, yield",
    "yield; yield",
    "(yield) ? yield : yield",
    "(yield) \n ? yield : yield",
    // If there is a newline before the next token, we don't look for RHS.
    "yield\nfor (;;) {}",
    "x = class extends (yield) {}",
    "x = class extends f(yield) {}",
    "x = class extends (null, yield) { }",
    "x = class extends (a ? null : yield) { }",
    "x = class extends (await 10) {}",
    "x = class extends f(await 10) {}",
    "x = class extends (null, await 10) { }",
    "x = class extends (a ? null : await 10) { }",

    // More tests featuring AwaitExpressions
    "await 10",
    "await 10; return",
    "await 10; return 20",
    "await 10; return 20; yield 'dead'",
    "await (yield 10)",
    "await (yield 10); return",
    "await (yield 10); return 20",
    "await (yield 10); return 20; yield 'dead'",
    "yield await 10",
    "yield await 10; return",
    "yield await 10; return 20",
    "yield await 10; return 20; yield 'dead'",
    "await /* comment */ 10",
    "await // comment\n 10",
    "yield await /* comment\n */ 10",
    "yield await // comment\n 10",
    "await (yield /* comment */)",
    "await (yield // comment\n)",
    nullptr
  };
  // clang-format on

  RunParserSyncTest(context_data, statement_data, kSuccess);
}

TEST_F(ParsingTest, AsyncGeneratorErrors) {
  // clang-format off
  const char* context_data[][2] = {
    { "async function * gen() {", "}" },
    { "\"use strict\"; async function * gen() {", "}" },
    { nullptr, nullptr }
  };

  const char* statement_data[] = {
    // Invalid yield expressions inside generators.
    "var yield;",
    "var await;",
    "var foo, yield;",
    "var foo, await;",
    "try { } catch (yield) { }",
    "try { } catch (await) { }",
    "function yield() { }",
    "function await() { }",
    // The name of the NFE is bound in the generator, which does not permit
    // yield or await to be identifiers.
    "(async function * yield() { })",
    "(async function * await() { })",
    // Yield and Await aren't valid as a formal parameter for generators.
    "async function * foo(yield) { }",
    "(async function * foo(yield) { })",
    "async function * foo(await) { }",
    "(async function * foo(await) { })",
    "yield = 1;",
    "await = 1;",
    "var foo = yield = 1;",
    "var foo = await = 1;",
    "++yield;",
    "++await;",
    "yield++;",
    "await++;",
    "yield *",
    "(yield *)",
    // Yield binds very loosely, so this parses as "yield (3 + yield 4)", which
    // is invalid.
    "yield 3 + yield 4;",
    "yield: 34",
    "yield ? 1 : 2",
    // Parses as yield (/ yield): invalid.
    "yield / yield",
    "+ yield",
    "+ yield 3",
    // Invalid (no newline allowed between yield and *).
    "yield\n*3",
    // Invalid (we see a newline, so we parse {yield:42} as a statement, not an
    // object literal, and yield is not a valid label).
    "yield\n{yield: 42}",
    "yield /* comment */\n {yield: 42}",
    "yield //comment\n {yield: 42}",
    // Destructuring binding and assignment are both disallowed
    "var [yield] = [42];",
    "var [await] = [42];",
    "var {foo: yield} = {a: 42};",
    "var {foo: await} = {a: 42};",
    "[yield] = [42];",
    "[await] = [42];",
    "({a: yield} = {a: 42});",
    "({a: await} = {a: 42});",
    // Also disallow full yield/await expressions on LHS
    "var [yield 24] = [42];",
    "var [await 24] = [42];",
    "var {foo: yield 24} = {a: 42};",
    "var {foo: await 24} = {a: 42};",
    "[yield 24] = [42];",
    "[await 24] = [42];",
    "({a: yield 24} = {a: 42});",
    "({a: await 24} = {a: 42});",
    "for (yield 'x' in {});",
    "for (await 'x' in {});",
    "for (yield 'x' of {});",
    "for (await 'x' of {});",
    "for (yield 'x' in {} in {});",
    "for (await 'x' in {} in {});",
    "for (yield 'x' in {} of {});",
    "for (await 'x' in {} of {});",
    "class C extends yield { }",
    "class C extends await { }",
    nullptr
  };
  // clang-format on

  RunParserSyncTest(context_data, statement_data, kError);
}

TEST_F(ParsingTest, LexicalLoopVariable) {
  i::Isolate* isolate = i_isolate();

  using TestCB =
      std::function<void(const i::ParseInfo& info, i::DeclarationScope*)>;
  auto TestProgram = [isolate](const char* program, TestCB test) {
    i::Factory* const factory = isolate->factory();
    i::DirectHandle<i::String> source =
        factory->NewStringFromUtf8(base::CStrVector(program)).ToHandleChecked();
    i::Handle<i::Script> script = factory->NewScript(source);
    i::UnoptimizedCompileState compile_state;
    i::ReusableUnoptimizedCompileState reusable_state(isolate);
    i::UnoptimizedCompileFlags flags =
        i::UnoptimizedCompileFlags::ForScriptCompile(isolate, *script);
    flags.set_allow_lazy_parsing(false);
    i::ParseInfo info(isolate, flags, &compile_state, &reusable_state);
    CHECK_PARSE_PROGRAM(&info, script, isolate);

    i::DeclarationScope::AllocateScopeInfos(&info, script, isolate);
    CHECK_NOT_NULL(info.literal());

    i::DeclarationScope* script_scope = info.literal()->scope();
    CHECK(script_scope->is_script_scope());

    test(info, script_scope);
  };

  // Check `let` loop variables is a stack local when not captured by
  // an eval or closure within the area of the loop body.
  const char* local_bindings[] = {
      "function loop() {"
      "  for (let loop_var = 0; loop_var < 10; ++loop_var) {"
      "  }"
      "  eval('0');"
      "}",

      "function loop() {"
      "  for (let loop_var = 0; loop_var < 10; ++loop_var) {"
      "  }"
      "  function foo() {}"
      "  foo();"
      "}",
  };
  for (const char* source : local_bindings) {
    TestProgram(source, [=](const i::ParseInfo& info, i::DeclarationScope* s) {
      i::Scope* fn = s->inner_scope();
      CHECK(fn->is_function_scope());

      i::Scope* loop_block = fn->inner_scope();
      if (loop_block->is_function_scope()) loop_block = loop_block->sibling();
      CHECK(loop_block->is_block_scope());

      const i::AstRawString* var_name =
          info.ast_value_factory()->GetOneByteString("loop_var");
      i::Variable* loop_var = loop_block->LookupLocal(var_name);
      CHECK_NOT_NULL(loop_var);
      CHECK(loop_var->IsStackLocal());
      CHECK_EQ(loop_block->ContextLocalCount(), 0);
      CHECK_NULL(loop_block->inner_scope());
    });
  }

  // Check `let` loop variable is not a stack local, and is duplicated in the
  // loop body to ensure capturing can work correctly.
  // In this version of the test, the inner loop block's duplicate `loop_var`
  // binding is not captured, and is a local.
  const char* context_bindings1[] = {
      "function loop() {"
      "  for (let loop_var = eval('0'); loop_var < 10; ++loop_var) {"
      "  }"
      "}",

      "function loop() {"
      "  for (let loop_var = (() => (loop_var, 0))(); loop_var < 10;"
      "       ++loop_var) {"
      "  }"
      "}"};
  for (const char* source : context_bindings1) {
    TestProgram(source, [=](const i::ParseInfo& info, i::DeclarationScope* s) {
      i::Scope* fn = s->inner_scope();
      CHECK(fn->is_function_scope());

      i::Scope* loop_block = fn->inner_scope();
      CHECK(loop_block->is_block_scope());

      const i::AstRawString* var_name =
          info.ast_value_factory()->GetOneByteString("loop_var");
      i::Variable* loop_var = loop_block->LookupLocal(var_name);
      CHECK_NOT_NULL(loop_var);
      CHECK(loop_var->IsContextSlot());
      CHECK_EQ(loop_block->ContextLocalCount(), 1);

      i::Variable* loop_var2 = loop_block->inner_scope()->LookupLocal(var_name);
      CHECK_NE(loop_var, loop_var2);
      CHECK(loop_var2->IsStackLocal());
      CHECK_EQ(loop_block->inner_scope()->ContextLocalCount(), 0);
    });
  }

  // Check `let` loop variable is not a stack local, and is duplicated in the
  // loop body to ensure capturing can work correctly.
  // In this version of the test, the inner loop block's duplicate `loop_var`
  // binding is captured, and must be context allocated.
  const char* context_bindings2[] = {
      "function loop() {"
      "  for (let loop_var = 0; loop_var < 10; ++loop_var) {"
      "    eval('0');"
      "  }"
      "}",

      "function loop() {"
      "  for (let loop_var = 0; loop_var < eval('10'); ++loop_var) {"
      "  }"
      "}",

      "function loop() {"
      "  for (let loop_var = 0; loop_var < 10; eval('++loop_var')) {"
      "  }"
      "}",
  };

  for (const char* source : context_bindings2) {
    TestProgram(source, [=](const i::ParseInfo& info, i::DeclarationScope* s) {
      i::Scope* fn = s->inner_scope();
      CHECK(fn->is_function_scope());

      i::Scope* loop_block = fn->inner_scope();
      CHECK(loop_block->is_block_scope());

      const i::AstRawString* var_name =
          info.ast_value_factory()->GetOneByteString("loop_var"
"""


```