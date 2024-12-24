Response: The user is asking for a summary of the functionality of the provided C++ code snippet. This is the third part of a four-part file, which suggests the entire file is about testing the V8 interpreter.

Therefore, this specific part likely focuses on testing a particular set of interpreter functionalities. Looking at the code, it contains various `TEST_F` blocks within the `InterpreterTest` class. Each `TEST_F` block seems to test a specific language construct or feature of JavaScript as implemented by the V8 interpreter.

Based on the names of the test cases, it seems this part specifically tests:

- Loop constructs (`while`, `do-while`, `for`)
- `for...in` loops
- `for...of` loops
- `switch` statements
- The `this` keyword in sloppy mode
- The `this` keyword referencing the function itself
- The `new.target` meta-property
- Assignment expressions within other expressions
- Conversion to property names (ToName)
- Temporary register allocation
- Variable lookup in different scopes (local, context, global)
- Function calls involving variable lookup
- Variable lookup with a large number of variables (wide registers)
- Deleting variables in different scopes
- Jumps with different numbers of constants
- The `eval()` function, including different scenarios like strict mode, variable declarations, and function declarations
- `eval()` with parameters
- Global `eval()`
- Variable declarations within `eval()`
- Function declarations within `eval()`
- Arithmetic operations with wide registers
- Function calls with wide registers
- Passing a large number of parameters to functions
- The `with` statement
- Class literals (constructors, methods, static members, getters, setters, computed property names)
- Classes and inheritance (`extends`, `super`)
- `const` and `let` declarations, including scope and immutability
- Looking up `const` and `let` in scopes
- `const` and `let` in the context chain
- Illegal uses of `const` (reassignment, uninitialized access)
- Generators

To illustrate the connection with JavaScript, I can pick a few examples and show the corresponding JavaScript code that the C++ test cases are exercising.
这个C++源代码文件是V8 JavaScript引擎的一部分，专门用于测试**V8解释器**的功能。作为第3部分，它延续了前两个部分的目标，继续测试解释器对各种JavaScript语法和语义的处理是否正确。

具体来说，这部分代码涵盖了以下方面的解释器功能测试：

* **循环语句的执行：**  测试 `while`、`do...while` 和 `for` 循环的不同用法，包括 `break` 和 `continue` 语句的处理。
* **`for...in` 循环的迭代：**  测试 `for...in` 循环遍历对象属性，包括对 `null`、`undefined`、数组、字符串和普通对象的处理，以及在循环中删除或添加属性的情况。
* **`for...of` 循环的迭代：** 测试 `for...of` 循环遍历可迭代对象（如数组和字符串），以及自定义迭代器的处理。
* **`switch` 语句的分支跳转：** 测试 `switch` 语句在不同 `case` 条件下的跳转和 `break` 语句的作用，以及 `default` 分支的处理。
* **`this` 关键字在非严格模式下的行为：** 测试在全局作用域和函数调用中 `this` 关键字的指向。
* **函数内部 `this` 关键字引用自身：** 测试具名函数表达式中 `this` 关键字的行为。
* **`new.target` 元属性：** 测试构造函数中 `new.target` 的值。
* **表达式中的赋值操作：** 测试赋值表达式在其他表达式中执行时的求值顺序和结果。
* **转换为属性名称 (ToName)：** 测试对象字面量中使用计算属性名时的类型转换。
* **临时寄存器分配：** 测试解释器在执行过程中如何有效地分配和使用临时寄存器。
* **变量查找 (LookupSlot)：** 测试解释器在不同作用域（局部、闭包、全局）中查找变量的能力。
* **`eval()` 函数的执行：** 测试 `eval()` 函数执行动态代码，包括对作用域、变量声明、严格模式的影响。
* **`eval()` 函数中的参数访问：** 测试在 `eval()` 中访问外部函数的参数。
* **全局 `eval()` 的行为：** 测试在全局作用域中调用 `eval()` 的效果。
* **`eval()` 中变量声明的影响：** 测试 `eval()` 中声明的变量对外部作用域的影响。
* **`eval()` 中函数声明的影响：** 测试 `eval()` 中声明的函数的作用域和可访问性。
* **使用大量寄存器的算术运算：** 测试解释器在处理大量局部变量时的算术运算能力。
* **使用大量寄存器进行函数调用：** 测试解释器在函数调用中使用大量参数时的处理。
* **选择大量参数中的一个：**  测试解释器如何访问大量的函数参数。
* **对大量参数求和：**  测试解释器如何处理需要访问大量参数的复杂操作。
* **`with` 语句的作用域：** 测试 `with` 语句改变作用域链的行为。
* **类字面量的创建和使用：** 测试类定义、构造函数、方法、静态方法、getter 和 setter 的执行。
* **类和继承的实现：** 测试类的继承关系，包括 `extends` 和 `super` 关键字的使用。
* **`const` 和 `let` 声明的作用域和行为：** 测试 `const` 和 `let` 声明的变量的作用域规则，以及 `const` 变量的不可重新赋值特性。
* **在查找槽中访问 `const` 和 `let` 变量：** 测试在不同作用域中访问 `const` 和 `let` 声明的变量。
* **在上下文链中访问 `const` 变量：** 测试在嵌套作用域中访问 `const` 变量。
* **非法 `const` 声明的错误处理：** 测试对 `const` 变量进行非法操作（如未初始化访问、重复赋值）时解释器的错误处理。
* **生成器函数的执行：** 测试生成器函数的 `yield` 关键字和 `next()` 方法的行为。

**与 JavaScript 功能的关系和示例：**

这个C++文件测试的是V8引擎的解释器，它直接对应了JavaScript代码的执行过程。  每一个 `TEST_F` 对应着一系列的JavaScript代码片段，用于验证解释器是否按照JavaScript的规范正确执行这些代码。

以下是一些示例，说明C++测试用例对应的JavaScript代码功能：

**1. 测试循环语句：**

C++ 代码片段（部分）：

```c++
      std::make_pair("var a = 1; var b = 0;\n"
                     "while (a < 10) {\n"
                     "  b = b + a;\n"
                     "  a++;\n"
                     "}\n"
                     "return b;\n",
                     handle(Smi::FromInt(45), i_isolate())),
```

对应的 JavaScript 代码功能：

```javascript
var a = 1;
var b = 0;
while (a < 10) {
  b = b + a;
  a++;
}
return b; // 结果应该为 45
```

**2. 测试 `for...in` 循环：**

C++ 代码片段（部分）：

```c++
      {"var r = 0;\n"
       "for (var a in [0,6,7,9]) { r = r + (1 << a); }\n"
       "return r;\n",
       0xF},
```

对应的 JavaScript 代码功能：

```javascript
var r = 0;
for (var a in [0, 6, 7, 9]) {
  r = r + (1 << a); // 将 1 左移 a 位，相当于 2 的 a 次方
}
return r; // 结果应该为 0b1111，即 15 (0xF)
```

**3. 测试 `switch` 语句：**

C++ 代码片段（部分）：

```c++
      std::make_pair("var a = 1;\n"
                     "switch(a) {\n"
                     " case 1: return 2;\n"
                     " case 2: return 3;\n"
                     "}\n",
                     handle(Smi::FromInt(2), i_isolate())),
```

对应的 JavaScript 代码功能：

```javascript
var a = 1;
switch (a) {
  case 1:
    return 2;
  case 2:
    return 3;
}
// 如果 a 不是 1 或 2，则不会返回任何值，函数会隐式返回 undefined
```

**4. 测试 `eval()` 函数：**

C++ 代码片段（部分）：

```c++
      {"return eval('1;');", handle(Smi::FromInt(1), i_isolate())},
```

对应的 JavaScript 代码功能：

```javascript
return eval('1;'); // eval 执行字符串 '1' 并返回其结果，即数字 1
```

**5. 测试类字面量：**

C++ 代码片段（部分）：

```c++
      {"class C {\n"
       "  constructor(x) { this.x_ = x; }\n"
       "  method() { return this.x_; }\n"
       "}\n"
       "return new C(99).method();",
       handle(Smi::FromInt(99), i_isolate())},
```

对应的 JavaScript 代码功能：

```javascript
class C {
  constructor(x) {
    this.x_ = x;
  }
  method() {
    return this.x_;
  }
}
return new C(99).method(); // 创建 C 的实例，调用 method 返回构造函数中设置的 x_ 值，即 99
```

总而言之，这个C++文件是V8引擎的测试框架的一部分，它通过构造各种JavaScript代码片段并在解释器中执行，来验证解释器在功能上的正确性，确保V8引擎能够准确地执行JavaScript代码。 每一段C++测试代码背后都对应着具体的JavaScript语法和语义。

Prompt: 
```
这是目录为v8/test/unittests/interpreter/interpreter-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共4部分，请归纳一下它的功能

"""
a;\n"
                     "} while(a);\n"
                     "return b;\n",
                     handle(Smi::FromInt(2), i_isolate())),
      std::make_pair("var b = 1;\n"
                     "for ( var a = 10; a > 0; a--) {\n"
                     "  b *= 2;\n"
                     "}\n"
                     "return b;",
                     factory->NewHeapNumber(1024)),
      std::make_pair("var a = 10; var b = 1;\n"
                     "while (false) {\n"
                     "  b = b * 2;\n"
                     "  a = a - 1;\n"
                     "}\n"
                     "return b;\n",
                     Handle<Object>(Smi::FromInt(1), i_isolate())),
      std::make_pair("var a = 10; var b = 1;\n"
                     "while (true) {\n"
                     "  b = b * 2;\n"
                     "  a = a - 1;\n"
                     "  if (a == 0) break;"
                     "  continue;"
                     "}\n"
                     "return b;\n",
                     factory->NewHeapNumber(1024)),
      std::make_pair("var a = 10; var b = 1;\n"
                     "do {\n"
                     "  b = b * 2;\n"
                     "  a = a - 1;\n"
                     "  if (a == 0) break;"
                     "} while(true);\n"
                     "return b;\n",
                     factory->NewHeapNumber(1024)),
      std::make_pair("var a = 10; var b = 1;\n"
                     "do {\n"
                     "  b = b * 2;\n"
                     "  a = a - 1;\n"
                     "  if (a == 0) break;"
                     "} while(false);\n"
                     "return b;\n",
                     Handle<Object>(Smi::FromInt(2), i_isolate())),
      std::make_pair("var a = 10; var b = 1;\n"
                     "for ( a = 1, b = 30; false; ) {\n"
                     "  b = b * 2;\n"
                     "}\n"
                     "return b;\n",
                     Handle<Object>(Smi::FromInt(30), i_isolate()))};

  for (size_t i = 0; i < arraysize(loops); i++) {
    std::string source(InterpreterTester::SourceForBody(loops[i].first));
    InterpreterTester tester(i_isolate(), source.c_str());
    auto callable = tester.GetCallable<>();

    DirectHandle<i::Object> return_value = callable().ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *loops[i].second));
  }
}

TEST_F(InterpreterTest, InterpreterForIn) {
  std::pair<const char*, int> for_in_samples[] = {
      {"var r = -1;\n"
       "for (var a in null) { r = a; }\n"
       "return r;\n",
       -1},
      {"var r = -1;\n"
       "for (var a in undefined) { r = a; }\n"
       "return r;\n",
       -1},
      {"var r = 0;\n"
       "for (var a in [0,6,7,9]) { r = r + (1 << a); }\n"
       "return r;\n",
       0xF},
      {"var r = 0;\n"
       "for (var a in [0,6,7,9]) { r = r + (1 << a); }\n"
       "var r = 0;\n"
       "for (var a in [0,6,7,9]) { r = r + (1 << a); }\n"
       "return r;\n",
       0xF},
      {"var r = 0;\n"
       "for (var a in 'foobar') { r = r + (1 << a); }\n"
       "return r;\n",
       0x3F},
      {"var r = 0;\n"
       "for (var a in {1:0, 10:1, 100:2, 1000:3}) {\n"
       "  r = r + Number(a);\n"
       " }\n"
       " return r;\n",
       1111},
      {"var r = 0;\n"
       "var data = {1:0, 10:1, 100:2, 1000:3};\n"
       "for (var a in data) {\n"
       "  if (a == 1) delete data[1];\n"
       "  r = r + Number(a);\n"
       " }\n"
       " return r;\n",
       1111},
      {"var r = 0;\n"
       "var data = {1:0, 10:1, 100:2, 1000:3};\n"
       "for (var a in data) {\n"
       "  if (a == 10) delete data[100];\n"
       "  r = r + Number(a);\n"
       " }\n"
       " return r;\n",
       1011},
      {"var r = 0;\n"
       "var data = {1:0, 10:1, 100:2, 1000:3};\n"
       "for (var a in data) {\n"
       "  if (a == 10) data[10000] = 4;\n"
       "  r = r + Number(a);\n"
       " }\n"
       " return r;\n",
       1111},
      {"var r = 0;\n"
       "var input = 'foobar';\n"
       "for (var a in input) {\n"
       "  if (input[a] == 'b') break;\n"
       "  r = r + (1 << a);\n"
       "}\n"
       "return r;\n",
       0x7},
      {"var r = 0;\n"
       "var input = 'foobar';\n"
       "for (var a in input) {\n"
       " if (input[a] == 'b') continue;\n"
       " r = r + (1 << a);\n"
       "}\n"
       "return r;\n",
       0x37},
      {"var r = 0;\n"
       "var data = {1:0, 10:1, 100:2, 1000:3};\n"
       "for (var a in data) {\n"
       "  if (a == 10) {\n"
       "     data[10000] = 4;\n"
       "  }\n"
       "  r = r + Number(a);\n"
       "}\n"
       "return r;\n",
       1111},
      {"var r = [ 3 ];\n"
       "var data = {1:0, 10:1, 100:2, 1000:3};\n"
       "for (r[10] in data) {\n"
       "}\n"
       "return Number(r[10]);\n",
       1000},
      {"var r = [ 3 ];\n"
       "var data = {1:0, 10:1, 100:2, 1000:3};\n"
       "for (r['100'] in data) {\n"
       "}\n"
       "return Number(r['100']);\n",
       1000},
      {"var obj = {}\n"
       "var descObj = new Boolean(false);\n"
       "var accessed = 0;\n"
       "descObj.enumerable = true;\n"
       "Object.defineProperties(obj, { prop:descObj });\n"
       "for (var p in obj) {\n"
       "  if (p === 'prop') { accessed = 1; }\n"
       "}\n"
       "return accessed;",
       1},
      {"var appointment = {};\n"
       "Object.defineProperty(appointment, 'startTime', {\n"
       "    value: 1001,\n"
       "    writable: false,\n"
       "    enumerable: false,\n"
       "    configurable: true\n"
       "});\n"
       "Object.defineProperty(appointment, 'name', {\n"
       "    value: 'NAME',\n"
       "    writable: false,\n"
       "    enumerable: false,\n"
       "    configurable: true\n"
       "});\n"
       "var meeting = Object.create(appointment);\n"
       "Object.defineProperty(meeting, 'conferenceCall', {\n"
       "    value: 'In-person meeting',\n"
       "    writable: false,\n"
       "    enumerable: false,\n"
       "    configurable: true\n"
       "});\n"
       "\n"
       "var teamMeeting = Object.create(meeting);\n"
       "\n"
       "var flags = 0;\n"
       "for (var p in teamMeeting) {\n"
       "    if (p === 'startTime') {\n"
       "        flags |= 1;\n"
       "    }\n"
       "    if (p === 'name') {\n"
       "        flags |= 2;\n"
       "    }\n"
       "    if (p === 'conferenceCall') {\n"
       "        flags |= 4;\n"
       "    }\n"
       "}\n"
       "\n"
       "var hasOwnProperty = !teamMeeting.hasOwnProperty('name') &&\n"
       "    !teamMeeting.hasOwnProperty('startTime') &&\n"
       "    !teamMeeting.hasOwnProperty('conferenceCall');\n"
       "if (!hasOwnProperty) {\n"
       "    flags |= 8;\n"
       "}\n"
       "return flags;\n",
       0},
      {"var data = {x:23, y:34};\n"
       " var result = 0;\n"
       "var o = {};\n"
       "var arr = [o];\n"
       "for (arr[0].p in data)\n"       // This is to test if value is loaded
       "  result += data[arr[0].p];\n"  // back from accumulator before storing
       "return result;\n",              // named properties.
       57},
      {"var data = {x:23, y:34};\n"
       "var result = 0;\n"
       "var o = {};\n"
       "var i = 0;\n"
       "for (o[i++] in data)\n"       // This is to test if value is loaded
       "  result += data[o[i-1]];\n"  // back from accumulator before
       "return result;\n",            // storing keyed properties.
       57}};

  // Two passes are made for this test. On the first, 8-bit register
  // operands are employed, and on the 16-bit register operands are
  // used.
  for (int pass = 0; pass < 2; pass++) {
    std::ostringstream wide_os;
    if (pass == 1) {
      for (int i = 0; i < 200; i++) {
        wide_os << "var local" << i << " = 0;\n";
      }
    }

    for (size_t i = 0; i < arraysize(for_in_samples); i++) {
      std::ostringstream body_os;
      body_os << wide_os.str() << for_in_samples[i].first;
      std::string body(body_os.str());
      std::string function = InterpreterTester::SourceForBody(body.c_str());
      InterpreterTester tester(i_isolate(), function.c_str());
      auto callable = tester.GetCallable<>();
      DirectHandle<Object> return_val = callable().ToHandleChecked();
      CHECK_EQ(Cast<Smi>(*return_val).value(), for_in_samples[i].second);
    }
  }
}

TEST_F(InterpreterTest, InterpreterForOf) {
  Factory* factory = i_isolate()->factory();

  std::pair<const char*, Handle<Object>> for_of[] = {
      {"function f() {\n"
       "  var r = 0;\n"
       "  for (var a of [0,6,7,9]) { r += a; }\n"
       "  return r;\n"
       "}",
       handle(Smi::FromInt(22), i_isolate())},
      {"function f() {\n"
       "  var r = '';\n"
       "  for (var a of 'foobar') { r = a + r; }\n"
       "  return r;\n"
       "}",
       factory->NewStringFromStaticChars("raboof")},
      {"function f() {\n"
       "  var a = [1, 2, 3];\n"
       "  a.name = 4;\n"
       "  var r = 0;\n"
       "  for (var x of a) { r += x; }\n"
       "  return r;\n"
       "}",
       handle(Smi::FromInt(6), i_isolate())},
      {"function f() {\n"
       "  var r = '';\n"
       "  var data = [1, 2, 3]; \n"
       "  for (a of data) { delete data[0]; r += a; } return r; }",
       factory->NewStringFromStaticChars("123")},
      {"function f() {\n"
       "  var r = '';\n"
       "  var data = [1, 2, 3]; \n"
       "  for (a of data) { delete data[2]; r += a; } return r; }",
       factory->NewStringFromStaticChars("12undefined")},
      {"function f() {\n"
       "  var r = '';\n"
       "  var data = [1, 2, 3]; \n"
       "  for (a of data) { delete data; r += a; } return r; }",
       factory->NewStringFromStaticChars("123")},
      {"function f() {\n"
       "  var r = '';\n"
       "  var input = 'foobar';\n"
       "  for (var a of input) {\n"
       "    if (a == 'b') break;\n"
       "    r += a;\n"
       "  }\n"
       "  return r;\n"
       "}",
       factory->NewStringFromStaticChars("foo")},
      {"function f() {\n"
       "  var r = '';\n"
       "  var input = 'foobar';\n"
       "  for (var a of input) {\n"
       "    if (a == 'b') continue;\n"
       "    r += a;\n"
       "  }\n"
       "  return r;\n"
       "}",
       factory->NewStringFromStaticChars("fooar")},
      {"function f() {\n"
       "  var r = '';\n"
       "  var data = [1, 2, 3, 4]; \n"
       "  for (a of data) { data[2] = 567; r += a; }\n"
       "  return r;\n"
       "}",
       factory->NewStringFromStaticChars("125674")},
      {"function f() {\n"
       "  var r = '';\n"
       "  var data = [1, 2, 3, 4]; \n"
       "  for (a of data) { data[4] = 567; r += a; }\n"
       "  return r;\n"
       "}",
       factory->NewStringFromStaticChars("1234567")},
      {"function f() {\n"
       "  var r = '';\n"
       "  var data = [1, 2, 3, 4]; \n"
       "  for (a of data) { data[5] = 567; r += a; }\n"
       "  return r;\n"
       "}",
       factory->NewStringFromStaticChars("1234undefined567")},
      {"function f() {\n"
       "  var r = '';\n"
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
       "  return r;\n"
       "}",
       factory->NewStringFromStaticChars("dcba")},
  };

  for (size_t i = 0; i < arraysize(for_of); i++) {
    InterpreterTester tester(i_isolate(), for_of[i].first);
    auto callable = tester.GetCallable<>();
    DirectHandle<Object> return_val = callable().ToHandleChecked();
    CHECK(Object::SameValue(*return_val, *for_of[i].second));
  }
}

TEST_F(InterpreterTest, InterpreterSwitch) {
  Factory* factory = i_isolate()->factory();

  std::pair<const char*, Handle<Object>> switch_ops[] = {
      std::make_pair("var a = 1;\n"
                     "switch(a) {\n"
                     " case 1: return 2;\n"
                     " case 2: return 3;\n"
                     "}\n",
                     handle(Smi::FromInt(2), i_isolate())),
      std::make_pair("var a = 1;\n"
                     "switch(a) {\n"
                     " case 2: a = 2; break;\n"
                     " case 1: a = 3; break;\n"
                     "}\n"
                     "return a;",
                     handle(Smi::FromInt(3), i_isolate())),
      std::make_pair("var a = 1;\n"
                     "switch(a) {\n"
                     " case 1: a = 2; // fall-through\n"
                     " case 2: a = 3; break;\n"
                     "}\n"
                     "return a;",
                     handle(Smi::FromInt(3), i_isolate())),
      std::make_pair("var a = 100;\n"
                     "switch(a) {\n"
                     " case 1: return 100;\n"
                     " case 2: return 200;\n"
                     "}\n"
                     "return undefined;",
                     factory->undefined_value()),
      std::make_pair("var a = 100;\n"
                     "switch(a) {\n"
                     " case 1: return 100;\n"
                     " case 2: return 200;\n"
                     " default: return 300;\n"
                     "}\n"
                     "return undefined;",
                     handle(Smi::FromInt(300), i_isolate())),
      std::make_pair("var a = 100;\n"
                     "switch(typeof(a)) {\n"
                     " case 'string': return 1;\n"
                     " case 'number': return 2;\n"
                     " default: return 3;\n"
                     "}\n",
                     handle(Smi::FromInt(2), i_isolate())),
      std::make_pair("var a = 100;\n"
                     "switch(a) {\n"
                     " case a += 20: return 1;\n"
                     " case a -= 10: return 2;\n"
                     " case a -= 10: return 3;\n"
                     " default: return 3;\n"
                     "}\n",
                     handle(Smi::FromInt(3), i_isolate())),
      std::make_pair("var a = 1;\n"
                     "switch(a) {\n"
                     " case 1: \n"
                     "   switch(a + 1) {\n"
                     "      case 2 : a += 1; break;\n"
                     "      default : a += 2; break;\n"
                     "   }  // fall-through\n"
                     " case 2: a += 3;\n"
                     "}\n"
                     "return a;",
                     handle(Smi::FromInt(5), i_isolate())),
  };

  for (size_t i = 0; i < arraysize(switch_ops); i++) {
    std::string source(InterpreterTester::SourceForBody(switch_ops[i].first));
    InterpreterTester tester(i_isolate(), source.c_str());
    auto callable = tester.GetCallable<>();

    DirectHandle<i::Object> return_value = callable().ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *switch_ops[i].second));
  }
}

TEST_F(InterpreterTest, InterpreterSloppyThis) {
  Factory* factory = i_isolate()->factory();

  std::pair<const char*, Handle<Object>> sloppy_this[] = {
      std::make_pair("var global_val = 100;\n"
                     "function f() { return this.global_val; }\n",
                     handle(Smi::FromInt(100), i_isolate())),
      std::make_pair("var global_val = 110;\n"
                     "function g() { return this.global_val; };"
                     "function f() { return g(); }\n",
                     handle(Smi::FromInt(110), i_isolate())),
      std::make_pair("var global_val = 110;\n"
                     "function g() { return this.global_val };"
                     "function f() { 'use strict'; return g(); }\n",
                     handle(Smi::FromInt(110), i_isolate())),
      std::make_pair("function f() { 'use strict'; return this; }\n",
                     factory->undefined_value()),
      std::make_pair("function g() { 'use strict'; return this; };"
                     "function f() { return g(); }\n",
                     factory->undefined_value()),
  };

  for (size_t i = 0; i < arraysize(sloppy_this); i++) {
    InterpreterTester tester(i_isolate(), sloppy_this[i].first);
    auto callable = tester.GetCallable<>();

    DirectHandle<i::Object> return_value = callable().ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *sloppy_this[i].second));
  }
}

TEST_F(InterpreterTest, InterpreterThisFunction) {
  Factory* factory = i_isolate()->factory();

  InterpreterTester tester(i_isolate(),
                           "var f;\n f = function f() { return f.name; }");
  auto callable = tester.GetCallable<>();

  DirectHandle<i::Object> return_value = callable().ToHandleChecked();
  CHECK(Object::SameValue(*return_value,
                          *factory->NewStringFromStaticChars("f")));
}

TEST_F(InterpreterTest, InterpreterNewTarget) {
  Factory* factory = i_isolate()->factory();

  // TODO(rmcilroy): Add tests that we get the original constructor for
  // superclass constructors once we have class support.
  InterpreterTester tester(i_isolate(),
                           "function f() { this.a = new.target; }");
  auto callable = tester.GetCallable<>();
  callable().ToHandleChecked();

  DirectHandle<Object> new_target_name = v8::Utils::OpenDirectHandle(
      *CompileRun("(function() { return (new f()).a.name; })();"));
  CHECK(Object::SameValue(*new_target_name,
                          *factory->NewStringFromStaticChars("f")));
}

TEST_F(InterpreterTest, InterpreterAssignmentInExpressions) {
  std::pair<const char*, int> samples[] = {
      {"function f() {\n"
       "  var x = 7;\n"
       "  var y = x + (x = 1) + (x = 2);\n"
       "  return y;\n"
       "}",
       10},
      {"function f() {\n"
       "  var x = 7;\n"
       "  var y = x + (x = 1) + (x = 2);\n"
       "  return x;\n"
       "}",
       2},
      {"function f() {\n"
       "  var x = 55;\n"
       "  x = x + (x = 100) + (x = 101);\n"
       "  return x;\n"
       "}",
       256},
      {"function f() {\n"
       "  var x = 7;\n"
       "  return ++x + x + x++;\n"
       "}",
       24},
      {"function f() {\n"
       "  var x = 7;\n"
       "  var y = 1 + ++x + x + x++;\n"
       "  return x;\n"
       "}",
       9},
      {"function f() {\n"
       "  var x = 7;\n"
       "  var y = ++x + x + x++;\n"
       "  return x;\n"
       "}",
       9},
      {"function f() {\n"
       "  var x = 7, y = 100, z = 1000;\n"
       "  return x + (x += 3) + y + (y *= 10) + (z *= 7) + z;\n"
       "}",
       15117},
      {"function f() {\n"
       "  var inner = function (x) { return x + (x = 2) + (x = 4) + x; };\n"
       "  return inner(1);\n"
       "}",
       11},
      {"function f() {\n"
       "  var x = 1, y = 2;\n"
       "  x = x + (x = 3) + y + (y = 4), y = y + (y = 5) + y + x;\n"
       "  return x + y;\n"
       "}",
       10 + 24},
      {"function f() {\n"
       "  var x = 0;\n"
       "  var y = x | (x = 1) | (x = 2);\n"
       "  return x;\n"
       "}",
       2},
      {"function f() {\n"
       "  var x = 0;\n"
       "  var y = x || (x = 1);\n"
       "  return x;\n"
       "}",
       1},
      {"function f() {\n"
       "  var x = 1;\n"
       "  var y = x && (x = 2) && (x = 3);\n"
       "  return x;\n"
       "}",
       3},
      {"function f() {\n"
       "  var x = 1;\n"
       "  var y = x || (x = 2);\n"
       "  return x;\n"
       "}",
       1},
      {"function f() {\n"
       "  var x = 1;\n"
       "  x = (x << (x = 3)) | (x = 16);\n"
       "  return x;\n"
       "}",
       24},
      {"function f() {\n"
       "  var r = 7;\n"
       "  var s = 11;\n"
       "  var t = 13;\n"
       "  var u = r + s + t + (r = 10) + (s = 20) +"
       "          (t = (r + s)) + r + s + t;\n"
       "  return r + s + t + u;\n"
       "}",
       211},
      {"function f() {\n"
       "  var r = 7;\n"
       "  var s = 11;\n"
       "  var t = 13;\n"
       "  return r > (3 * s * (s = 1)) ? (t + (t += 1)) : (r + (r = 4));\n"
       "}",
       11},
      {"function f() {\n"
       "  var r = 7;\n"
       "  var s = 11;\n"
       "  var t = 13;\n"
       "  return r > (3 * s * (s = 0)) ? (t + (t += 1)) : (r + (r = 4));\n"
       "}",
       27},
      {"function f() {\n"
       "  var r = 7;\n"
       "  var s = 11;\n"
       "  var t = 13;\n"
       "  return (r + (r = 5)) > s ? r : t;\n"
       "}",
       5},
      {"function f(a) {\n"
       "  return a + (arguments[0] = 10);\n"
       "}",
       50},
      {"function f(a) {\n"
       "  return a + (arguments[0] = 10) + a;\n"
       "}",
       60},
      {"function f(a) {\n"
       "  return a + (arguments[0] = 10) + arguments[0];\n"
       "}",
       60},
  };

  const int arg_value = 40;
  for (size_t i = 0; i < arraysize(samples); i++) {
    InterpreterTester tester(i_isolate(), samples[i].first);
    auto callable = tester.GetCallable<Handle<Object>>();
    DirectHandle<Object> return_val =
        callable(handle(Smi::FromInt(arg_value), i_isolate()))
            .ToHandleChecked();
    CHECK_EQ(Cast<Smi>(*return_val).value(), samples[i].second);
  }
}

TEST_F(InterpreterTest, InterpreterToName) {
  Factory* factory = i_isolate()->factory();

  std::pair<const char*, Handle<Object>> to_name_tests[] = {
      {"var a = 'val'; var obj = {[a] : 10}; return obj.val;",
       factory->NewNumberFromInt(10)},
      {"var a = 20; var obj = {[a] : 10}; return obj['20'];",
       factory->NewNumberFromInt(10)},
      {"var a = 20; var obj = {[a] : 10}; return obj[20];",
       factory->NewNumberFromInt(10)},
      {"var a = {val:23}; var obj = {[a] : 10}; return obj[a];",
       factory->NewNumberFromInt(10)},
      {"var a = {val:23}; var obj = {[a] : 10};\n"
       "return obj['[object Object]'];",
       factory->NewNumberFromInt(10)},
      {"var a = {toString : function() { return 'x'}};\n"
       "var obj = {[a] : 10};\n"
       "return obj.x;",
       factory->NewNumberFromInt(10)},
      {"var a = {valueOf : function() { return 'x'}};\n"
       "var obj = {[a] : 10};\n"
       "return obj.x;",
       factory->undefined_value()},
      {"var a = {[Symbol.toPrimitive] : function() { return 'x'}};\n"
       "var obj = {[a] : 10};\n"
       "return obj.x;",
       factory->NewNumberFromInt(10)},
  };

  for (size_t i = 0; i < arraysize(to_name_tests); i++) {
    std::string source(
        InterpreterTester::SourceForBody(to_name_tests[i].first));
    InterpreterTester tester(i_isolate(), source.c_str());
    auto callable = tester.GetCallable<>();

    DirectHandle<i::Object> return_value = callable().ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *to_name_tests[i].second));
  }
}

TEST_F(InterpreterTest, TemporaryRegisterAllocation) {
  Factory* factory = i_isolate()->factory();

  std::pair<const char*, Handle<Object>> reg_tests[] = {
      {"function add(a, b, c) {"
       "   return a + b + c;"
       "}"
       "function f() {"
       "  var a = 10, b = 10;"
       "   return add(a, b++, b);"
       "}",
       factory->NewNumberFromInt(31)},
      {"function add(a, b, c, d) {"
       "  return a + b + c + d;"
       "}"
       "function f() {"
       "  var x = 10, y = 20, z = 30;"
       "  return x + add(x, (y= x++), x, z);"
       "}",
       factory->NewNumberFromInt(71)},
  };

  for (size_t i = 0; i < arraysize(reg_tests); i++) {
    InterpreterTester tester(i_isolate(), reg_tests[i].first);
    auto callable = tester.GetCallable<>();

    DirectHandle<i::Object> return_value = callable().ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *reg_tests[i].second));
  }
}

TEST_F(InterpreterTest, InterpreterLookupSlot) {
  Factory* factory = i_isolate()->factory();

  // TODO(mythria): Add more tests when we have support for eval/with.
  const char* function_prologue =
      "var f;"
      "var x = 1;"
      "function f1() {"
      "  eval(\"function t() {";
  const char* function_epilogue =
      "        }; f = t;\");"
      "}"
      "f1();";

  std::pair<const char*, Handle<Object>> lookup_slot[] = {
      {"return x;", handle(Smi::FromInt(1), i_isolate())},
      {"return typeof x;", factory->NewStringFromStaticChars("number")},
      {"return typeof dummy;", factory->NewStringFromStaticChars("undefined")},
      {"x = 10; return x;", handle(Smi::FromInt(10), i_isolate())},
      {"'use strict'; x = 20; return x;",
       handle(Smi::FromInt(20), i_isolate())},
  };

  for (size_t i = 0; i < arraysize(lookup_slot); i++) {
    std::string script = std::string(function_prologue) +
                         std::string(lookup_slot[i].first) +
                         std::string(function_epilogue);

    InterpreterTester tester(i_isolate(), script.c_str(), "t");
    auto callable = tester.GetCallable<>();

    DirectHandle<i::Object> return_value = callable().ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *lookup_slot[i].second));
  }
}

TEST_F(InterpreterTest, InterpreterLookupContextSlot) {
  const char* inner_function_prologue = "function inner() {";
  const char* inner_function_epilogue = "};";
  const char* outer_function_epilogue = "return inner();";

  std::tuple<const char*, const char*, Handle<Object>> lookup_slot[] = {
      // Eval in inner context.
      std::make_tuple("var x = 0;", "eval(''); return x;",
                      handle(Smi::zero(), i_isolate())),
      std::make_tuple("var x = 0;", "eval('var x = 1'); return x;",
                      handle(Smi::FromInt(1), i_isolate())),
      std::make_tuple("var x = 0;",
                      "'use strict'; eval('var x = 1'); return x;",
                      handle(Smi::zero(), i_isolate())),
      // Eval in outer context.
      std::make_tuple("var x = 0; eval('');", "return x;",
                      handle(Smi::zero(), i_isolate())),
      std::make_tuple("var x = 0; eval('var x = 1');", "return x;",
                      handle(Smi::FromInt(1), i_isolate())),
      std::make_tuple("'use strict'; var x = 0; eval('var x = 1');",
                      "return x;", handle(Smi::zero(), i_isolate())),
  };

  for (size_t i = 0; i < arraysize(lookup_slot); i++) {
    std::string body = std::string(std::get<0>(lookup_slot[i])) +
                       std::string(inner_function_prologue) +
                       std::string(std::get<1>(lookup_slot[i])) +
                       std::string(inner_function_epilogue) +
                       std::string(outer_function_epilogue);
    std::string script = InterpreterTester::SourceForBody(body.c_str());

    InterpreterTester tester(i_isolate(), script.c_str());
    auto callable = tester.GetCallable<>();

    DirectHandle<i::Object> return_value = callable().ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *std::get<2>(lookup_slot[i])));
  }
}

TEST_F(InterpreterTest, InterpreterLookupGlobalSlot) {
  const char* inner_function_prologue = "function inner() {";
  const char* inner_function_epilogue = "};";
  const char* outer_function_epilogue = "return inner();";

  std::tuple<const char*, const char*, Handle<Object>> lookup_slot[] = {
      // Eval in inner context.
      std::make_tuple("x = 0;", "eval(''); return x;",
                      handle(Smi::zero(), i_isolate())),
      std::make_tuple("x = 0;", "eval('var x = 1'); return x;",
                      handle(Smi::FromInt(1), i_isolate())),
      std::make_tuple("x = 0;", "'use strict'; eval('var x = 1'); return x;",
                      handle(Smi::zero(), i_isolate())),
      // Eval in outer context.
      std::make_tuple("x = 0; eval('');", "return x;",
                      handle(Smi::zero(), i_isolate())),
      std::make_tuple("x = 0; eval('var x = 1');", "return x;",
                      handle(Smi::FromInt(1), i_isolate())),
      std::make_tuple("'use strict'; x = 0; eval('var x = 1');", "return x;",
                      handle(Smi::zero(), i_isolate())),
  };

  for (size_t i = 0; i < arraysize(lookup_slot); i++) {
    std::string body = std::string(std::get<0>(lookup_slot[i])) +
                       std::string(inner_function_prologue) +
                       std::string(std::get<1>(lookup_slot[i])) +
                       std::string(inner_function_epilogue) +
                       std::string(outer_function_epilogue);
    std::string script = InterpreterTester::SourceForBody(body.c_str());

    InterpreterTester tester(i_isolate(), script.c_str());
    auto callable = tester.GetCallable<>();

    DirectHandle<i::Object> return_value = callable().ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *std::get<2>(lookup_slot[i])));
  }
}

TEST_F(InterpreterTest, InterpreterCallLookupSlot) {
  std::pair<const char*, Handle<Object>> call_lookup[] = {
      {"g = function(){ return 2 }; eval(''); return g();",
       handle(Smi::FromInt(2), i_isolate())},
      {"g = function(){ return 2 }; eval('g = function() {return 3}');\n"
       "return g();",
       handle(Smi::FromInt(3), i_isolate())},
      {"g = { x: function(){ return this.y }, y: 20 };\n"
       "eval('g = { x: g.x, y: 30 }');\n"
       "return g.x();",
       handle(Smi::FromInt(30), i_isolate())},
  };

  for (size_t i = 0; i < arraysize(call_lookup); i++) {
    std::string source(InterpreterTester::SourceForBody(call_lookup[i].first));
    InterpreterTester tester(i_isolate(), source.c_str());
    auto callable = tester.GetCallable<>();

    DirectHandle<i::Object> return_value = callable().ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *call_lookup[i].second));
  }
}

TEST_F(InterpreterTest, InterpreterLookupSlotWide) {
  Factory* factory = i_isolate()->factory();

  const char* function_prologue =
      "var f;"
      "var x = 1;"
      "function f1() {"
      "  eval(\"function t() {";
  const char* function_epilogue =
      "        }; f = t;\");"
      "}"
      "f1();";
  std::ostringstream str;
  str << "var y = 2.3;";
  for (int i = 1; i < 256; i++) {
    str << "y = " << 2.3 + i << ";";
  }
  std::string init_function_body = str.str();

  std::pair<std::string, Handle<Object>> lookup_slot[] = {
      {init_function_body + "return x;", handle(Smi::FromInt(1), i_isolate())},
      {init_function_body + "return typeof x;",
       factory->NewStringFromStaticChars("number")},
      {init_function_body + "return x = 10;",
       handle(Smi::FromInt(10), i_isolate())},
      {"'use strict';" + init_function_body + "x = 20; return x;",
       handle(Smi::FromInt(20), i_isolate())},
  };

  for (size_t i = 0; i < arraysize(lookup_slot); i++) {
    std::string script = std::string(function_prologue) + lookup_slot[i].first +
                         std::string(function_epilogue);

    InterpreterTester tester(i_isolate(), script.c_str(), "t");
    auto callable = tester.GetCallable<>();

    DirectHandle<i::Object> return_value = callable().ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *lookup_slot[i].second));
  }
}

TEST_F(InterpreterTest, InterpreterDeleteLookupSlot) {
  Factory* factory = i_isolate()->factory();

  // TODO(mythria): Add more tests when we have support for eval/with.
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
      "        }; f = t;\");"
      "}"
      "f1();";

  std::pair<const char*, Handle<Object>> delete_lookup_slot[] = {
      {"return delete x;", factory->false_value()},
      {"return delete y;", factory->true_value()},
      {"return delete z;", factory->false_value()},
      {"return delete obj.val;", factory->true_value()},
      {"'use strict'; return delete obj.val;", factory->true_value()},
  };

  for (size_t i = 0; i < arraysize(delete_lookup_slot); i++) {
    std::string script = std::string(function_prologue) +
                         std::string(delete_lookup_slot[i].first) +
                         std::string(function_epilogue);

    InterpreterTester tester(i_isolate(), script.c_str(), "t");
    auto callable = tester.GetCallable<>();

    DirectHandle<i::Object> return_value = callable().ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *delete_lookup_slot[i].second));
  }
}

TEST_F(InterpreterTest, JumpWithConstantsAndWideConstants) {
  Factory* factory = i_isolate()->factory();
  const int kStep = 13;
  for (int constants = 11; constants < 256 + 3 * kStep; constants += kStep) {
    std::ostringstream filler_os;
    // Generate a string that consumes constant pool entries and
    // spread out branch distances in script below.
    for (int i = 0; i < constants; i++) {
      filler_os << "var x_ = 'x_" << i << "';\n";
    }
    std::string filler(filler_os.str());
    std::ostringstream script_os;
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