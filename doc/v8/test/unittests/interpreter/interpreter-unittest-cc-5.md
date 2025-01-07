Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/test/unittests/interpreter/interpreter-unittest.cc`.

Here's a breakdown of the code's functionality:

1. **Loop with `continue` and `break`:** The first test case demonstrates the behavior of `continue` and `break` statements within a `for` loop in the interpreter. It dynamically constructs a JavaScript function, executes it with different inputs, and verifies the return value.

2. **`eval()` functionality:**  Several test cases focus on the `eval()` function in JavaScript. These tests cover various scenarios, including:
    - Basic evaluation of expressions.
    - Accessing variables from the surrounding scope.
    - Modifying variables in the surrounding scope.
    - `eval()` in strict mode.
    - `eval()` of variable declarations and their scope.
    - `eval()` and function declarations.
    - `eval()` with parameters.
    - Global `eval()`.

3. **Wide Registers:** Tests named `InterpreterWideRegisterArithmetic` and `InterpreterCallWideRegisters` aim to verify the interpreter's ability to handle a large number of registers, ensuring correct behavior with wide register operands.

4. **Wide Parameters:** Tests named `InterpreterWideParametersPickOne` and `InterpreterWideParametersSummation` check the interpreter's handling of functions with a significant number of parameters.

5. **`with` statement:** The `InterpreterWithStatement` test verifies the functionality of the `with` statement, which changes the scope chain.

6. **Class Literals:** The `InterpreterClassLiterals` test validates the implementation of JavaScript class syntax, including constructors, methods, static methods, getters, and setters.

7. **Class and Superclass (`extends`):** The `InterpreterClassAndSuperClass` test focuses on the inheritance mechanism in JavaScript classes using the `extends` keyword and the `super` keyword.

8. **`const` and `let` declarations:** Several tests (`InterpreterConstDeclaration`, `InterpreterConstDeclarationLookupSlots`, `InterpreterConstInLookupContextChain`, `InterpreterIllegalConstDeclaration`) examine the behavior of `const` and `let` declarations, including:
    - Basic declaration and access.
    - Scoping rules (block scoping).
    - Interaction with `eval()`.
    - Lookup in nested scopes and closures.
    - Errors related to reassignment of `const` and accessing `let` before initialization.

9. **Generators:** The `InterpreterGenerators` test verifies the basic functionality of JavaScript generator functions using the `function*` syntax and the `yield` keyword.

10. **Native Stack with Interpreter:**  The `InterpreterWithNativeStack` test (not on ARM) checks if interpreted frames are correctly included in the native stack, which is important for debugging and profiling.

11. **Bytecode Handler Retrieval:** `InterpreterGetBytecodeHandler` tests the interpreter's mechanism for retrieving the correct bytecode handlers for different bytecodes and operand scales.

12. **Source Position Collection:** Tests related to `InterpreterCollectSourcePositions` verify the mechanism for collecting source code positions for debugging and error reporting, including handling stack overflow scenarios and exceptions during collection.

Based on this, the summary can be generated.
这是 `v8/test/unittests/interpreter/interpreter-unittest.cc` 源代码的第 6 部分，主要功能是测试 **V8 JavaScript 解释器** 的各种特性和边缘情况。它使用 C++ 编写，通过定义一系列的测试用例来验证解释器的正确性。

**核心功能归纳：**

* **控制流语句测试 (Loop with continue and break):**  测试 `for` 循环中 `continue` 和 `break` 语句的执行逻辑。
* **`eval()` 函数测试:**  覆盖了 `eval()` 函数的多种用法，包括：
    * 基本的表达式求值。
    * 访问和修改外部作用域的变量。
    * 在严格模式下的行为。
    * 对变量声明和函数声明的处理。
    * 带参数的 `eval()` 调用。
    * 全局作用域下的 `eval()`。
* **宽寄存器操作测试:** 验证解释器在处理大量局部变量（需要使用宽寄存器）时的算术运算和函数调用的正确性。
* **宽参数传递测试:** 检验解释器在函数接收大量参数时的处理能力。
* **`with` 语句测试:** 测试 `with` 语句改变作用域链的行为。
* **类字面量测试:**  验证 JavaScript 类语法的实现，包括构造函数、方法、静态方法、getter 和 setter。
* **类继承测试:**  测试使用 `extends` 关键字的类继承以及 `super` 关键字的用法。
* **`const` 和 `let` 声明测试:**  详细测试 `const` 和 `let` 声明的各种方面，包括：
    * 基本声明和赋值。
    * 块级作用域。
    * 与 `eval()` 的交互。
    * 在查找上下文链中的行为。
    * 非法声明时的错误处理。
* **生成器函数测试:**  验证生成器函数的基本功能。
* **解释器原生堆栈测试 (非 ARM 架构):**  测试解释器执行的函数调用是否正确地体现在原生堆栈中，这对于调试非常重要。
* **字节码处理器获取测试:**  验证解释器能正确获取各种字节码指令对应的处理器。
* **源代码位置收集测试:**  测试解释器收集源代码位置信息的功能，这用于生成错误堆栈和调试信息。

**如果 `v8/test/unittests/interpreter/interpreter-unittest.cc` 以 `.tq` 结尾：**

那它将是一个 **V8 Torque** 源代码文件。Torque 是一种用于定义 V8 内部运行时函数的领域特定语言。在这种情况下，该文件会包含用 Torque 编写的测试，这些测试直接验证 V8 内部实现的细节，而不是像 `.cc` 文件那样通过 JavaScript 代码进行间接测试。  但根据文件名和内容判断，当前文件是 `.cc` 文件。

**与 JavaScript 功能的关系及示例：**

所有这些测试都直接关系到 JavaScript 的功能，因为它们旨在验证 V8 解释器（执行 JavaScript 代码的引擎）的正确性。

**JavaScript 示例：**

* **Loop with continue and break:**

```javascript
function testLoop(a) {
  let result;
  for (let i = a; i < 2; i++) {
    if (i === 0) {
      i = 10;
      continue;
    } else if (i === a) {
      i = 12;
      break;
    }
  }
  return i;
}

console.log(testLoop(0)); // 输出 11
console.log(testLoop(1)); // 输出 12
console.log(testLoop(2)); // 输出 2
```

* **`eval()` functionality:**

```javascript
let x = 10;
console.log(eval('x + 20;')); // 输出 30
eval('x = 33;');
console.log(x); // 输出 33

function testEvalGlobal() {
  eval('function globalFunc() { globalVar = 33; }');
  globalFunc();
  return globalVar;
}
console.log(testEvalGlobal()); // 输出 33
```

* **Class Literals:**

```javascript
class MyClass {
  constructor(value) {
    this.myValue = value;
  }
  getMethod() {
    return this.myValue;
  }
  static staticMethod(val) {
    return val * 2;
  }
  get myProp() {
    return this.myValue * 2;
  }
  set myProp(newValue) {
    this.myValue = newValue / 2;
  }
}

const instance = new MyClass(5);
console.log(instance.getMethod()); // 输出 5
console.log(MyClass.staticMethod(10)); // 输出 20
console.log(instance.myProp); // 输出 10
instance.myProp = 20;
console.log(instance.myValue); // 输出 10
```

* **`const` and `let` declarations:**

```javascript
const constantValue = 10;
// constantValue = 20; // 报错：Assignment to constant variable.

let letValue = 5;
letValue = 10;
console.log(letValue); // 输出 10

function testScope() {
  var functionScoped = 1;
  if (true) {
    let blockScoped = 2;
    const blockConstant = 3;
    console.log(blockScoped); // 输出 2
    console.log(blockConstant); // 输出 3
  }
  // console.log(blockScoped); // 报错：blockScoped is not defined
  console.log(functionScoped); // 输出 1
}
testScope();
```

* **Generators:**

```javascript
function* myGenerator() {
  yield 1;
  yield 2;
  yield 3;
}

const generator = myGenerator();
console.log(generator.next().value); // 输出 1
console.log(generator.next().value); // 输出 2
console.log(generator.next().value); // 输出 3
console.log(generator.next().value); // 输出 undefined
```

**代码逻辑推理（假设输入与输出）：**

以 `TEST_F(InterpreterTest, InterpreterEval)` 中的一个用例为例：

**假设输入：** JavaScript 代码片段 `"var x = 10; return eval('x + 20;');"`

**代码逻辑：**
1. 定义一个变量 `x` 并赋值为 10。
2. 使用 `eval()` 执行字符串 `'x + 20;'`。
3. 在 `eval()` 的作用域中，访问到外部作用域的变量 `x` 的值（10）。
4. 计算表达式 `10 + 20`，结果为 30。
5. `eval()` 返回 30。
6. 外部函数返回 `eval()` 的返回值。

**预期输出：**  返回值为代表数字 30 的 V8 内部对象。

**用户常见的编程错误示例：**

* **`eval()` 误用导致的安全问题：** 用户可能会使用 `eval()` 执行来自不可信来源的字符串，这可能导致代码注入攻击。

```javascript
let userInput = "alert('Hacked!');";
// 不安全的用法
eval(userInput);
```

* **`const` 变量的重复赋值：** 用户可能会尝试修改 `const` 声明的变量。

```javascript
const PI = 3.14159;
// PI = 3.14; // TypeError: Assignment to constant variable.
```

* **在 `let` 变量声明前访问它：**  用户可能会尝试在 `let` 变量声明之前访问它，导致暂时性死区错误。

```javascript
console.log(myLetVariable); // ReferenceError: Cannot access 'myLetVariable' before initialization
let myLetVariable = 10;
```

* **在 `with` 语句中访问未定义的属性：** 如果 `with` 语句的目标对象上没有对应的属性，并且外部作用域也没有，则会抛出错误。

```javascript
let obj = { a: 1 };
with (obj) {
  console.log(a); // 输出 1
  // console.log(b); // ReferenceError: b is not defined
}
```

总而言之，这段代码是 V8 解释器单元测试套件的一部分，它专注于测试各种核心 JavaScript 语言特性的解释执行是否符合预期。

Prompt: 
```
这是目录为v8/test/unittests/interpreter/interpreter-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/interpreter/interpreter-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第6部分，共7部分，请归纳一下它的功能

"""
ngstream script_os;
    script_os << "function " << InterpreterTester::function_name() << "(a) {\n";
    script_os << "  " << filler;
    script_os << "  for (var i = a; i < 2; i++) {\n";
    script_os << "  " << filler;
    script_os << "    if (i == 0) { " << filler << "i = 10; continue; }\n";
    script_os << "    else if (i == a) { " << filler << "i = 12; break; }\n";
    script_os << "    else { " << filler << " }\n";
    script_os << "  }\n";
    script_os << "  return i;\n";
    script_os << "}\n";
    std::string script(script_os.str());
    for (int a = 0; a < 3; a++) {
      InterpreterTester tester(i_isolate(), script.c_str());
      auto callable = tester.GetCallable<Handle<Object>>();
      Handle<Object> argument = factory->NewNumberFromInt(a);
      DirectHandle<Object> return_val = callable(argument).ToHandleChecked();
      static const int results[] = {11, 12, 2};
      CHECK_EQ(Cast<Smi>(*return_val).value(), results[a]);
    }
  }
}

TEST_F(InterpreterTest, InterpreterEval) {
  Factory* factory = i_isolate()->factory();

  std::pair<const char*, Handle<Object>> eval[] = {
      {"return eval('1;');", handle(Smi::FromInt(1), i_isolate())},
      {"return eval('100 * 20;');", handle(Smi::FromInt(2000), i_isolate())},
      {"var x = 10; return eval('x + 20;');",
       handle(Smi::FromInt(30), i_isolate())},
      {"var x = 10; eval('x = 33;'); return x;",
       handle(Smi::FromInt(33), i_isolate())},
      {"'use strict'; var x = 20; var z = 0;\n"
       "eval('var x = 33; z = x;'); return x + z;",
       handle(Smi::FromInt(53), i_isolate())},
      {"eval('var x = 33;'); eval('var y = x + 20'); return x + y;",
       handle(Smi::FromInt(86), i_isolate())},
      {"var x = 1; eval('for(i = 0; i < 10; i++) x = x + 1;'); return x",
       handle(Smi::FromInt(11), i_isolate())},
      {"var x = 10; eval('var x = 20;'); return x;",
       handle(Smi::FromInt(20), i_isolate())},
      {"var x = 1; eval('\"use strict\"; var x = 2;'); return x;",
       handle(Smi::FromInt(1), i_isolate())},
      {"'use strict'; var x = 1; eval('var x = 2;'); return x;",
       handle(Smi::FromInt(1), i_isolate())},
      {"var x = 10; eval('x + 20;'); return typeof x;",
       factory->NewStringFromStaticChars("number")},
      {"eval('var y = 10;'); return typeof unallocated;",
       factory->NewStringFromStaticChars("undefined")},
      {"'use strict'; eval('var y = 10;'); return typeof unallocated;",
       factory->NewStringFromStaticChars("undefined")},
      {"eval('var x = 10;'); return typeof x;",
       factory->NewStringFromStaticChars("number")},
      {"var x = {}; eval('var x = 10;'); return typeof x;",
       factory->NewStringFromStaticChars("number")},
      {"'use strict'; var x = {}; eval('var x = 10;'); return typeof x;",
       factory->NewStringFromStaticChars("object")},
  };

  for (size_t i = 0; i < arraysize(eval); i++) {
    std::string source(InterpreterTester::SourceForBody(eval[i].first));
    InterpreterTester tester(i_isolate(), source.c_str());
    auto callable = tester.GetCallable<>();
    DirectHandle<i::Object> return_value = callable().ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *eval[i].second));
  }
}

TEST_F(InterpreterTest, InterpreterEvalParams) {
  std::pair<const char*, Handle<Object>> eval_params[] = {
      {"var x = 10; return eval('x + p1;');",
       handle(Smi::FromInt(30), i_isolate())},
      {"var x = 10; eval('p1 = x;'); return p1;",
       handle(Smi::FromInt(10), i_isolate())},
      {"var a = 10;"
       "function inner() { return eval('a + p1;');}"
       "return inner();",
       handle(Smi::FromInt(30), i_isolate())},
  };

  for (size_t i = 0; i < arraysize(eval_params); i++) {
    std::string source = "function " + InterpreterTester::function_name() +
                         "(p1) {" + eval_params[i].first + "}";
    InterpreterTester tester(i_isolate(), source.c_str());
    auto callable = tester.GetCallable<Handle<Object>>();

    DirectHandle<i::Object> return_value =
        callable(handle(Smi::FromInt(20), i_isolate())).ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *eval_params[i].second));
  }
}

TEST_F(InterpreterTest, InterpreterEvalGlobal) {
  Factory* factory = i_isolate()->factory();

  std::pair<const char*, Handle<Object>> eval_global[] = {
      {"function add_global() { eval('function test() { z = 33; }; test()'); };"
       "function f() { add_global(); return z; }; f();",
       handle(Smi::FromInt(33), i_isolate())},
      {"function add_global() {\n"
       " eval('\"use strict\"; function test() { y = 33; };"
       "      try { test() } catch(e) {}');\n"
       "}\n"
       "function f() { add_global(); return typeof y; } f();",
       factory->NewStringFromStaticChars("undefined")},
  };

  for (size_t i = 0; i < arraysize(eval_global); i++) {
    InterpreterTester tester(i_isolate(), eval_global[i].first, "test");
    auto callable = tester.GetCallable<>();

    DirectHandle<i::Object> return_value = callable().ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *eval_global[i].second));
  }
}

TEST_F(InterpreterTest, InterpreterEvalVariableDecl) {
  Factory* factory = i_isolate()->factory();

  std::pair<const char*, Handle<Object>> eval_global[] = {
      {"function f() { eval('var x = 10; x++;'); return x; }",
       handle(Smi::FromInt(11), i_isolate())},
      {"function f() { var x = 20; eval('var x = 10; x++;'); return x; }",
       handle(Smi::FromInt(11), i_isolate())},
      {"function f() {"
       " var x = 20;"
       " eval('\"use strict\"; var x = 10; x++;');"
       " return x; }",
       handle(Smi::FromInt(20), i_isolate())},
      {"function f() {"
       " var y = 30;"
       " eval('var x = {1:20}; x[2]=y;');"
       " return x[2]; }",
       handle(Smi::FromInt(30), i_isolate())},
      {"function f() {"
       " eval('var x = {name:\"test\"};');"
       " return x.name; }",
       factory->NewStringFromStaticChars("test")},
      {"function f() {"
       "  eval('var x = [{name:\"test\"}, {type:\"cc\"}];');"
       "  return x[1].type+x[0].name; }",
       factory->NewStringFromStaticChars("cctest")},
      {"function f() {\n"
       " var x = 3;\n"
       " var get_eval_x;\n"
       " eval('\"use strict\"; "
       "      var x = 20; "
       "      get_eval_x = function func() {return x;};');\n"
       " return get_eval_x() + x;\n"
       "}",
       handle(Smi::FromInt(23), i_isolate())},
      // TODO(mythria): Add tests with const declarations.
  };

  for (size_t i = 0; i < arraysize(eval_global); i++) {
    InterpreterTester tester(i_isolate(), eval_global[i].first, "*");
    auto callable = tester.GetCallable<>();

    DirectHandle<i::Object> return_value = callable().ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *eval_global[i].second));
  }
}

TEST_F(InterpreterTest, InterpreterEvalFunctionDecl) {
  std::pair<const char*, Handle<Object>> eval_func_decl[] = {
      {"function f() {\n"
       " var x = 3;\n"
       " eval('var x = 20;"
       "       function get_x() {return x;};');\n"
       " return get_x() + x;\n"
       "}",
       handle(Smi::FromInt(40), i_isolate())},
  };

  for (size_t i = 0; i < arraysize(eval_func_decl); i++) {
    InterpreterTester tester(i_isolate(), eval_func_decl[i].first, "*");
    auto callable = tester.GetCallable<>();

    DirectHandle<i::Object> return_value = callable().ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *eval_func_decl[i].second));
  }
}

TEST_F(InterpreterTest, InterpreterWideRegisterArithmetic) {
  static const size_t kMaxRegisterForTest = 150;
  std::ostringstream os;
  os << "function " << InterpreterTester::function_name() << "(arg) {\n";
  os << "  var retval = -77;\n";
  for (size_t i = 0; i < kMaxRegisterForTest; i++) {
    os << "  var x" << i << " = " << i << ";\n";
  }
  for (size_t i = 0; i < kMaxRegisterForTest / 2; i++) {
    size_t j = kMaxRegisterForTest - i - 1;
    os << "  var tmp = x" << j << ";\n";
    os << "  var x" << j << " = x" << i << ";\n";
    os << "  var x" << i << " = tmp;\n";
  }
  for (size_t i = 0; i < kMaxRegisterForTest / 2; i++) {
    size_t j = kMaxRegisterForTest - i - 1;
    os << "  var tmp = x" << j << ";\n";
    os << "  var x" << j << " = x" << i << ";\n";
    os << "  var x" << i << " = tmp;\n";
  }
  for (size_t i = 0; i < kMaxRegisterForTest; i++) {
    os << "  if (arg == " << i << ") {\n"  //
       << "    retval = x" << i << ";\n"   //
       << "  }\n";                         //
  }
  os << "  return retval;\n";
  os << "}\n";

  std::string source = os.str();
  InterpreterTester tester(i_isolate(), source.c_str());
  auto callable = tester.GetCallable<Handle<Object>>();
  for (size_t i = 0; i < kMaxRegisterForTest; i++) {
    Handle<Object> arg = handle(Smi::FromInt(static_cast<int>(i)), i_isolate());
    DirectHandle<Object> return_value = callable(arg).ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *arg));
  }
}

TEST_F(InterpreterTest, InterpreterCallWideRegisters) {
  static const int kPeriod = 25;
  static const int kLength = 512;
  static const int kStartChar = 65;

  for (int pass = 0; pass < 3; pass += 1) {
    std::ostringstream os;
    for (int i = 0; i < pass * 97; i += 1) {
      os << "var x" << i << " = " << i << "\n";
    }
    os << "return String.fromCharCode(";
    os << kStartChar;
    for (int i = 1; i < kLength; i += 1) {
      os << "," << kStartChar + (i % kPeriod);
    }
    os << ");";
    std::string source = InterpreterTester::SourceForBody(os.str().c_str());
    InterpreterTester tester(i_isolate(), source.c_str());
    auto callable = tester.GetCallable();
    Handle<Object> return_val = callable().ToHandleChecked();
    DirectHandle<String> return_string = Cast<String>(return_val);
    CHECK_EQ(return_string->length(), kLength);
    for (int i = 0; i < kLength; i += 1) {
      CHECK_EQ(return_string->Get(i), 65 + (i % kPeriod));
    }
  }
}

TEST_F(InterpreterTest, InterpreterWideParametersPickOne) {
  static const int kParameterCount = 130;
  for (int parameter = 0; parameter < 10; parameter++) {
    std::ostringstream os;
    os << "function " << InterpreterTester::function_name() << "(arg) {\n";
    os << "  function selector(i";
    for (int i = 0; i < kParameterCount; i++) {
      os << ","
         << "a" << i;
    }
    os << ") {\n";
    os << "  return a" << parameter << ";\n";
    os << "  };\n";
    os << "  return selector(arg";
    for (int i = 0; i < kParameterCount; i++) {
      os << "," << i;
    }
    os << ");";
    os << "}\n";

    std::string source = os.str();
    InterpreterTester tester(i_isolate(), source.c_str(), "*");
    auto callable = tester.GetCallable<Handle<Object>>();
    Handle<Object> arg = handle(Smi::FromInt(0xAA55), i_isolate());
    DirectHandle<Object> return_value = callable(arg).ToHandleChecked();
    Tagged<Smi> actual = Cast<Smi>(*return_value);
    CHECK_EQ(actual.value(), parameter);
  }
}

TEST_F(InterpreterTest, InterpreterWideParametersSummation) {
  static int kParameterCount = 200;
  static int kBaseValue = 17000;

  std::ostringstream os;
  os << "function " << InterpreterTester::function_name() << "(arg) {\n";
  os << "  function summation(i";
  for (int i = 0; i < kParameterCount; i++) {
    os << ","
       << "a" << i;
  }
  os << ") {\n";
  os << "    var sum = " << kBaseValue << ";\n";
  os << "    switch(i) {\n";
  for (int i = 0; i < kParameterCount; i++) {
    int j = kParameterCount - i - 1;
    os << "      case " << j << ": sum += a" << j << ";\n";
  }
  os << "  }\n";
  os << "    return sum;\n";
  os << "  };\n";
  os << "  return summation(arg";
  for (int i = 0; i < kParameterCount; i++) {
    os << "," << i;
  }
  os << ");";
  os << "}\n";

  std::string source = os.str();
  InterpreterTester tester(i_isolate(), source.c_str(), "*");
  auto callable = tester.GetCallable<Handle<Object>>();
  for (int i = 0; i < kParameterCount; i++) {
    Handle<Object> arg = handle(Smi::FromInt(i), i_isolate());
    DirectHandle<Object> return_value = callable(arg).ToHandleChecked();
    int expected = kBaseValue + i * (i + 1) / 2;
    Tagged<Smi> actual = Cast<Smi>(*return_value);
    CHECK_EQ(actual.value(), expected);
  }
}

TEST_F(InterpreterTest, InterpreterWithStatement) {
  std::pair<const char*, Handle<Object>> with_stmt[] = {
      {"with({x:42}) return x;", handle(Smi::FromInt(42), i_isolate())},
      {"with({}) { var y = 10; return y;}",
       handle(Smi::FromInt(10), i_isolate())},
      {"var y = {x:42};"
       " function inner() {"
       "   var x = 20;"
       "   with(y) return x;"
       "}"
       "return inner();",
       handle(Smi::FromInt(42), i_isolate())},
      {"var y = {x:42};"
       " function inner(o) {"
       "   var x = 20;"
       "   with(o) return x;"
       "}"
       "return inner(y);",
       handle(Smi::FromInt(42), i_isolate())},
  };

  for (size_t i = 0; i < arraysize(with_stmt); i++) {
    std::string source(InterpreterTester::SourceForBody(with_stmt[i].first));
    InterpreterTester tester(i_isolate(), source.c_str());
    auto callable = tester.GetCallable<>();

    DirectHandle<i::Object> return_value = callable().ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *with_stmt[i].second));
  }
}

TEST_F(InterpreterTest, InterpreterClassLiterals) {
  std::pair<const char*, Handle<Object>> examples[] = {
      {"class C {\n"
       "  constructor(x) { this.x_ = x; }\n"
       "  method() { return this.x_; }\n"
       "}\n"
       "return new C(99).method();",
       handle(Smi::FromInt(99), i_isolate())},
      {"class C {\n"
       "  constructor(x) { this.x_ = x; }\n"
       "  static static_method(x) { return x; }\n"
       "}\n"
       "return C.static_method(101);",
       handle(Smi::FromInt(101), i_isolate())},
      {"class C {\n"
       "  get x() { return 102; }\n"
       "}\n"
       "return new C().x",
       handle(Smi::FromInt(102), i_isolate())},
      {"class C {\n"
       "  static get x() { return 103; }\n"
       "}\n"
       "return C.x",
       handle(Smi::FromInt(103), i_isolate())},
      {"class C {\n"
       "  constructor() { this.x_ = 0; }"
       "  set x(value) { this.x_ = value; }\n"
       "  get x() { return this.x_; }\n"
       "}\n"
       "var c = new C();"
       "c.x = 104;"
       "return c.x;",
       handle(Smi::FromInt(104), i_isolate())},
      {"var x = 0;"
       "class C {\n"
       "  static set x(value) { x = value; }\n"
       "  static get x() { return x; }\n"
       "}\n"
       "C.x = 105;"
       "return C.x;",
       handle(Smi::FromInt(105), i_isolate())},
      {"var method = 'f';"
       "class C {\n"
       "  [method]() { return 106; }\n"
       "}\n"
       "return new C().f();",
       handle(Smi::FromInt(106), i_isolate())},
  };

  for (size_t i = 0; i < arraysize(examples); ++i) {
    std::string source(InterpreterTester::SourceForBody(examples[i].first));
    InterpreterTester tester(i_isolate(), source.c_str(), "*");
    auto callable = tester.GetCallable<>();

    DirectHandle<i::Object> return_value = callable().ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *examples[i].second));
  }
}

TEST_F(InterpreterTest, InterpreterClassAndSuperClass) {
  std::pair<const char*, Handle<Object>> examples[] = {
      {"class A {\n"
       "  constructor(x) { this.x_ = x; }\n"
       "  method() { return this.x_; }\n"
       "}\n"
       "class B extends A {\n"
       "   constructor(x, y) { super(x); this.y_ = y; }\n"
       "   method() { return super.method() + 1; }\n"
       "}\n"
       "return new B(998, 0).method();\n",
       handle(Smi::FromInt(999), i_isolate())},
      {"class A {\n"
       "  constructor() { this.x_ = 2; this.y_ = 3; }\n"
       "}\n"
       "class B extends A {\n"
       "  constructor() { super(); }"
       "  method() { this.x_++; this.y_++; return this.x_ + this.y_; }\n"
       "}\n"
       "return new B().method();\n",
       handle(Smi::FromInt(7), i_isolate())},
      {"var calls = 0;\n"
       "class B {}\n"
       "B.prototype.x = 42;\n"
       "class C extends B {\n"
       "  constructor() {\n"
       "    super();\n"
       "    calls++;\n"
       "  }\n"
       "}\n"
       "new C;\n"
       "return calls;\n",
       handle(Smi::FromInt(1), i_isolate())},
      {"class A {\n"
       "  method() { return 1; }\n"
       "  get x() { return 2; }\n"
       "}\n"
       "class B extends A {\n"
       "  method() { return super.x === 2 ? super.method() : -1; }\n"
       "}\n"
       "return new B().method();\n",
       handle(Smi::FromInt(1), i_isolate())},
      {"var object = { setY(v) { super.y = v; }};\n"
       "object.setY(10);\n"
       "return object.y;\n",
       handle(Smi::FromInt(10), i_isolate())},
  };

  for (size_t i = 0; i < arraysize(examples); ++i) {
    std::string source(InterpreterTester::SourceForBody(examples[i].first));
    InterpreterTester tester(i_isolate(), source.c_str(), "*");
    auto callable = tester.GetCallable<>();
    DirectHandle<i::Object> return_value = callable().ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *examples[i].second));
  }
}

TEST_F(InterpreterTest, InterpreterConstDeclaration) {
  Factory* factory = i_isolate()->factory();

  std::pair<const char*, Handle<Object>> const_decl[] = {
      {"const x = 3; return x;", handle(Smi::FromInt(3), i_isolate())},
      {"let x = 10; x = x + 20; return x;",
       handle(Smi::FromInt(30), i_isolate())},
      {"let x = 10; x = 20; return x;", handle(Smi::FromInt(20), i_isolate())},
      {"let x; x = 20; return x;", handle(Smi::FromInt(20), i_isolate())},
      {"let x; return x;", factory->undefined_value()},
      {"var x = 10; { let x = 30; } return x;",
       handle(Smi::FromInt(10), i_isolate())},
      {"let x = 10; { let x = 20; } return x;",
       handle(Smi::FromInt(10), i_isolate())},
      {"var x = 10; eval('let x = 20;'); return x;",
       handle(Smi::FromInt(10), i_isolate())},
      {"var x = 10; eval('const x = 20;'); return x;",
       handle(Smi::FromInt(10), i_isolate())},
      {"var x = 10; { const x = 20; } return x;",
       handle(Smi::FromInt(10), i_isolate())},
      {"var x = 10; { const x = 20; return x;} return -1;",
       handle(Smi::FromInt(20), i_isolate())},
      {"var a = 10;\n"
       "for (var i = 0; i < 10; ++i) {\n"
       " const x = i;\n"  // const declarations are block scoped.
       " a = a + x;\n"
       "}\n"
       "return a;\n",
       handle(Smi::FromInt(55), i_isolate())},
  };

  // Tests for sloppy mode.
  for (size_t i = 0; i < arraysize(const_decl); i++) {
    std::string source(InterpreterTester::SourceForBody(const_decl[i].first));
    InterpreterTester tester(i_isolate(), source.c_str());
    auto callable = tester.GetCallable<>();

    DirectHandle<i::Object> return_value = callable().ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *const_decl[i].second));
  }

  // Tests for strict mode.
  for (size_t i = 0; i < arraysize(const_decl); i++) {
    std::string strict_body =
        "'use strict'; " + std::string(const_decl[i].first);
    std::string source(InterpreterTester::SourceForBody(strict_body.c_str()));
    InterpreterTester tester(i_isolate(), source.c_str());
    auto callable = tester.GetCallable<>();

    DirectHandle<i::Object> return_value = callable().ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *const_decl[i].second));
  }
}

TEST_F(InterpreterTest, InterpreterConstDeclarationLookupSlots) {
  Factory* factory = i_isolate()->factory();

  std::pair<const char*, Handle<Object>> const_decl[] = {
      {"const x = 3; function f1() {return x;}; return x;",
       handle(Smi::FromInt(3), i_isolate())},
      {"let x = 10; x = x + 20; function f1() {return x;}; return x;",
       handle(Smi::FromInt(30), i_isolate())},
      {"let x; x = 20; function f1() {return x;}; return x;",
       handle(Smi::FromInt(20), i_isolate())},
      {"let x; function f1() {return x;}; return x;",
       factory->undefined_value()},
  };

  // Tests for sloppy mode.
  for (size_t i = 0; i < arraysize(const_decl); i++) {
    std::string source(InterpreterTester::SourceForBody(const_decl[i].first));
    InterpreterTester tester(i_isolate(), source.c_str());
    auto callable = tester.GetCallable<>();

    DirectHandle<i::Object> return_value = callable().ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *const_decl[i].second));
  }

  // Tests for strict mode.
  for (size_t i = 0; i < arraysize(const_decl); i++) {
    std::string strict_body =
        "'use strict'; " + std::string(const_decl[i].first);
    std::string source(InterpreterTester::SourceForBody(strict_body.c_str()));
    InterpreterTester tester(i_isolate(), source.c_str());
    auto callable = tester.GetCallable<>();

    DirectHandle<i::Object> return_value = callable().ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *const_decl[i].second));
  }
}

TEST_F(InterpreterTest, InterpreterConstInLookupContextChain) {
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
  std::pair<const char*, Handle<Object>> const_decl[] = {
      {"return outerConst;", handle(Smi::FromInt(10), i_isolate())},
      {"return outerLet;", handle(Smi::FromInt(20), i_isolate())},
      {"outerLet = 30; return outerLet;",
       handle(Smi::FromInt(30), i_isolate())},
      {"var outerLet = 40; return outerLet;",
       handle(Smi::FromInt(40), i_isolate())},
      {"var outerConst = 50; return outerConst;",
       handle(Smi::FromInt(50), i_isolate())},
      {"try { outerConst = 30 } catch(e) { return -1; }",
       handle(Smi::FromInt(-1), i_isolate())}};

  for (size_t i = 0; i < arraysize(const_decl); i++) {
    std::string script = std::string(prologue) +
                         std::string(const_decl[i].first) +
                         std::string(epilogue);
    InterpreterTester tester(i_isolate(), script.c_str(), "*");
    auto callable = tester.GetCallable<>();

    DirectHandle<i::Object> return_value = callable().ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *const_decl[i].second));
  }
}

TEST_F(InterpreterTest, InterpreterIllegalConstDeclaration) {
  std::pair<const char*, const char*> const_decl[] = {
      {"const x = x = 10 + 3; return x;",
       "Uncaught ReferenceError: Cannot access 'x' before initialization"},
      {"const x = 10; x = 20; return x;",
       "Uncaught TypeError: Assignment to constant variable."},
      {"const x = 10; { x = 20; } return x;",
       "Uncaught TypeError: Assignment to constant variable."},
      {"const x = 10; eval('x = 20;'); return x;",
       "Uncaught TypeError: Assignment to constant variable."},
      {"let x = x + 10; return x;",
       "Uncaught ReferenceError: Cannot access 'x' before initialization"},
      {"'use strict'; (function f1() { f1 = 123; })() ",
       "Uncaught TypeError: Assignment to constant variable."},
  };

  // Tests for sloppy mode.
  for (size_t i = 0; i < arraysize(const_decl); i++) {
    std::string source(InterpreterTester::SourceForBody(const_decl[i].first));
    InterpreterTester tester(i_isolate(), source.c_str());
    v8::Local<v8::String> message = tester.CheckThrowsReturnMessage()->Get();
    v8::Local<v8::String> expected_string = NewString(const_decl[i].second);
    CHECK(message->Equals(context(), expected_string).FromJust());
  }

  // Tests for strict mode.
  for (size_t i = 0; i < arraysize(const_decl); i++) {
    std::string strict_body =
        "'use strict'; " + std::string(const_decl[i].first);
    std::string source(InterpreterTester::SourceForBody(strict_body.c_str()));
    InterpreterTester tester(i_isolate(), source.c_str());
    v8::Local<v8::String> message = tester.CheckThrowsReturnMessage()->Get();
    v8::Local<v8::String> expected_string = NewString(const_decl[i].second);
    CHECK(message->Equals(context(), expected_string).FromJust());
  }
}

TEST_F(InterpreterTest, InterpreterGenerators) {
  Factory* factory = i_isolate()->factory();

  std::pair<const char*, Handle<Object>> tests[] = {
      {"function* f() { }; return f().next().value",
       factory->undefined_value()},
      {"function* f() { yield 42 }; return f().next().value",
       factory->NewNumberFromInt(42)},
      {"function* f() { for (let x of [42]) yield x}; return f().next().value",
       factory->NewNumberFromInt(42)},
  };

  for (size_t i = 0; i < arraysize(tests); i++) {
    std::string source(InterpreterTester::SourceForBody(tests[i].first));
    InterpreterTester tester(i_isolate(), source.c_str());
    auto callable = tester.GetCallable<>();

    DirectHandle<i::Object> return_value = callable().ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *tests[i].second));
  }
}

#ifndef V8_TARGET_ARCH_ARM
TEST_F(InterpreterTest, InterpreterWithNativeStack) {
  // "Always sparkplug" messes with this test.
  if (v8_flags.always_sparkplug) return;

  i::FakeCodeEventLogger code_event_logger(i_isolate());
  i::v8_flags.interpreted_frames_native_stack = true;
  CHECK(i_isolate()->logger()->AddListener(&code_event_logger));

  const char* source_text =
      "function testInterpreterWithNativeStack(a,b) { return a + b };";

  i::DirectHandle<i::Object> o = v8::Utils::OpenDirectHandle(
      *v8::Script::Compile(context(), v8::String::NewFromUtf8(
                                          context()->GetIsolate(), source_text)
                                          .ToLocalChecked())
           .ToLocalChecked());

  i::DirectHandle<i::JSFunction> f = i::Cast<i::JSFunction>(o);

  CHECK(f->shared()->HasBytecodeArray());
  i::Tagged<i::Code> code = f->shared()->GetCode(i_isolate());
  i::DirectHandle<i::Code> interpreter_entry_trampoline =
      BUILTIN_CODE(i_isolate(), InterpreterEntryTrampoline);

  CHECK(IsCode(code));
  CHECK(code->is_interpreter_trampoline_builtin());
  CHECK_NE(code.address(), interpreter_entry_trampoline->address());

  CHECK(i_isolate()->logger()->RemoveListener(&code_event_logger));
}
#endif  // V8_TARGET_ARCH_ARM

TEST_F(InterpreterTest, InterpreterGetBytecodeHandler) {
  Interpreter* interpreter = i_isolate()->interpreter();

  // Test that single-width bytecode handlers deserializer correctly.
  Tagged<Code> wide_handler =
      interpreter->GetBytecodeHandler(Bytecode::kWide, OperandScale::kSingle);

  CHECK_EQ(wide_handler->builtin_id(), Builtin::kWideHandler);

  Tagged<Code> add_handler =
      interpreter->GetBytecodeHandler(Bytecode::kAdd, OperandScale::kSingle);

  CHECK_EQ(add_handler->builtin_id(), Builtin::kAddHandler);

  // Test that double-width bytecode handlers deserializer correctly, including
  // an illegal bytecode handler since there is no Wide.Wide handler.
  Tagged<Code> wide_wide_handler =
      interpreter->GetBytecodeHandler(Bytecode::kWide, OperandScale::kDouble);

  CHECK_EQ(wide_wide_handler->builtin_id(), Builtin::kIllegalHandler);

  Tagged<Code> add_wide_handler =
      interpreter->GetBytecodeHandler(Bytecode::kAdd, OperandScale::kDouble);

  CHECK_EQ(add_wide_handler->builtin_id(), Builtin::kAddWideHandler);
}

TEST_F(InterpreterTest, InterpreterCollectSourcePositions) {
  v8_flags.enable_lazy_source_positions = true;
  v8_flags.stress_lazy_source_positions = false;

  const char* source =
      "(function () {\n"
      "  return 1;\n"
      "})";

  DirectHandle<JSFunction> function =
      Cast<JSFunction>(v8::Utils::OpenDirectHandle(
          *v8::Local<v8::Function>::Cast(CompileRun(source))));

  Handle<SharedFunctionInfo> sfi(function->shared(), i_isolate());
  DirectHandle<BytecodeArray> bytecode_array(sfi->GetBytecodeArray(i_isolate()),
                                             i_isolate());
  CHECK(!bytecode_array->HasSourcePositionTable());

  Compiler::CollectSourcePositions(i_isolate(), sfi);

  Tagged<TrustedByteArray> source_position_table =
      bytecode_array->SourcePositionTable();
  CHECK(bytecode_array->HasSourcePositionTable());
  CHECK_GT(source_position_table->length(), 0);
}

TEST_F(InterpreterTest, InterpreterCollectSourcePositions_StackOverflow) {
  v8_flags.enable_lazy_source_positions = true;
  v8_flags.stress_lazy_source_positions = false;

  const char* source =
      "(function () {\n"
      "  return 1;\n"
      "})";

  DirectHandle<JSFunction> function =
      Cast<JSFunction>(v8::Utils::OpenDirectHandle(
          *v8::Local<v8::Function>::Cast(CompileRun(source))));

  Handle<SharedFunctionInfo> sfi(function->shared(), i_isolate());
  DirectHandle<BytecodeArray> bytecode_array(sfi->GetBytecodeArray(i_isolate()),
                                             i_isolate());
  CHECK(!bytecode_array->HasSourcePositionTable());

  // Make the stack limit the same as the current position so recompilation
  // overflows.
  uint64_t previous_limit = i_isolate()->stack_guard()->real_climit();
  i_isolate()->stack_guard()->SetStackLimit(GetCurrentStackPosition());
  Compiler::CollectSourcePositions(i_isolate(), sfi);
  // Stack overflowed so source position table can be returned but is empty.
  Tagged<TrustedByteArray> source_position_table =
      bytecode_array->SourcePositionTable();
  CHECK(!bytecode_array->HasSourcePositionTable());
  CHECK_EQ(source_position_table->length(), 0);

  // Reset the stack limit and try again.
  i_isolate()->stack_guard()->SetStackLimit(previous_limit);
  Compiler::CollectSourcePositions(i_isolate(), sfi);
  source_position_table = bytecode_array->SourcePositionTable();
  CHECK(bytecode_array->HasSourcePositionTable());
  CHECK_GT(source_position_table->length(), 0);
}

TEST_F(InterpreterTest, InterpreterCollectSourcePositions_ThrowFrom1stFrame) {
  v8_flags.enable_lazy_source_positions = true;
  v8_flags.stress_lazy_source_positions = false;

  const char* source =
      R"javascript(
      (function () {
        throw new Error();
      });
      )javascript";

  Handle<JSFunction> function = Cast<JSFunction>(v8::Utils::OpenHandle(
      *v8::Local<v8::Function>::Cast(CompileRun(source))));

  DirectHandle<SharedFunctionInfo> sfi(function->shared(), i_isolate());
  // This is the bytecode for the top-level iife.
  DirectHandle<BytecodeArray> bytecode_array(sfi->GetBytecodeArray(i_isolate()),
                                             i_isolate());
  CHECK(!bytecode_array->HasSourcePositionTable());

  {
    v8::TryCatch try_catch(reinterpret_cast<v8::Isolate*>(i_isolate()));
    MaybeHandle<Object> result = Execution::Call(
        i_isolate(), function,
        ReadOnlyRoots(i_isolate()).undefined_value_handle(), 0, nullptr);
    CHECK(result.is_null());
    CHECK(try_catch.HasCaught());
  }

  // The exception was caught but source positions were not retrieved from it so
  // there should be no source position table.
  CHECK(!bytecode_array->HasSourcePositionTable());
}

TEST_F(InterpreterTest, InterpreterCollectSourcePositions_ThrowFrom2ndFrame) {
  v8_flags.enable_lazy_source_positions = true;
  v8_flags.stress_lazy_source_positions = false;

  const char* source =
      R"javascript(
      (function () {
        (function () {
          throw new Error();
        })();
      });
      )javascript";

  Handle<JSFunction> function = Cast<JSFunction>(v8::Utils::OpenHandle(
      *v8::Local<v8::Function>::Cast(CompileRun(source))));

  DirectHandle<SharedFunctionInfo> sfi(function->shared(), i_isolate());
  // This is the bytecode for the top-level iife.
  DirectHandle<BytecodeArray> bytecode_array(sfi->GetBytecodeArray(i_isolate()),
                                             i_isolate());
  CHECK(!bytecode_array->HasSourcePositionTable());

  {
    v8::TryCatch try_catch(reinterpret_cast<v8::Isolate*>(i_isolate()));
    MaybeHandle<Object> result = Execution::Call(
        i_isolate(), function,
        ReadOnlyRoots(i_isolate()).undefined_value_handle(), 0, nullptr);
    CHECK(result.is_null());
    CHECK(try_catch.HasCaught());
  }

  // The exception was caught but source positions were not retrieved from it so
  // there should be no source position table.
  CHECK(!bytecode_array->HasSourcePositionTable());
}

namespace {

void CheckStringEqual(const char* expected_ptr, const char* actual_ptr) {
  CHECK_NOT_NULL(expected_ptr);
  CHECK_NOT_NULL(actual_ptr);
  std::string expected(ex
"""


```