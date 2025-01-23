Response:
The user wants a summary of the functionality of the provided C++ code snippet. This code is a unit test file for the bytecode generator of the V8 JavaScript engine.

Here's a breakdown of the thought process to address the user's request:

1. **Identify the core purpose:** The filename `bytecode-generator-unittest.cc` and the `TEST_F` macros immediately suggest that this is a unit test file. It tests the `BytecodeGenerator` component of V8.

2. **Analyze the `TEST_F` structure:** Each `TEST_F` function represents a specific scenario or feature being tested. The name of the test often hints at the functionality being tested (e.g., `ObjectLiterals`, `TryCatch`, `ForIn`).

3. **Infer functionality from test names:**  Go through each `TEST_F` and deduce the JavaScript language feature being tested. For example:
    * `ObjectLiterals`: Tests how object literals are compiled into bytecode.
    * `TryCatch`: Tests the bytecode generation for `try...catch` blocks.
    * `ForIn`: Tests the bytecode generation for `for...in` loops.
    * `ClassDeclarations`: Tests the bytecode generation for class declarations.

4. **Examine the code snippets within each test:**  The `snippets` array within each `TEST_F` contains JavaScript code examples. These snippets represent various ways a specific language feature can be used. Analyzing these snippets provides more detailed insight into the specific aspects being tested. For instance, in `ObjectLiterals`, different ways of defining properties (shorthand, computed properties, getters/setters, `__proto__`) are tested.

5. **Understand the test setup:** The `BuildActual` and `LoadGolden` functions suggest that the tests generate bytecode for the given snippets and compare it against expected "golden" files. This confirms the core purpose of verifying the bytecode generator's output.

6. **Address the specific constraints in the prompt:**
    * **List the functionalities:**  Create a bulleted list of the JavaScript features being tested, based on the `TEST_F` names and code snippets.
    * **`.tq` extension:** Explain that this is a C++ file, not Torque, as it doesn't have a `.tq` extension.
    * **Relationship to JavaScript and examples:** For each functionality, provide a simple JavaScript example to illustrate it.
    * **Code logic and assumptions:** For tests involving control flow (like `TryCatch`, `ForIn`, `Conditional`, `Switch`), describe a possible input and expected output to demonstrate the logic.
    * **Common programming errors:** Identify potential errors related to the tested features, such as accessing undefined variables in `try...catch` or incorrect usage of `for...in`.
    * **Part 2 of 3 and summarization:**  Acknowledge this is part 2 and provide a high-level summary of the overall functionality of the code (testing the bytecode generator).

7. **Structure the answer:** Organize the information clearly, with headings for each functionality, JavaScript examples, input/output scenarios, and common errors.

8. **Review and refine:** Check for accuracy, clarity, and completeness. Ensure all parts of the user's prompt are addressed. For instance, initially, I might just list the test names, but the prompt asks for the *functionality*, which requires explaining what each test verifies.

By following these steps, I can generate a comprehensive and informative answer that addresses all aspects of the user's request about the V8 bytecode generator unit test file.这个C++源代码文件 `v8/test/unittests/interpreter/bytecode-generator-unittest.cc` 是V8 JavaScript引擎的一部分，专门用于测试 **字节码生成器** 的功能。字节码生成器是将JavaScript源代码转换为V8解释器可以执行的字节码的关键组件。

**功能归纳:**

这个文件的主要功能是编写和执行一系列单元测试，以验证 `BytecodeGenerator` 是否能够正确地为各种JavaScript语法结构生成预期的字节码。  它通过以下方式实现：

1. **定义测试用例 (using `TEST_F`)**: 每个 `TEST_F` 宏定义了一个独立的测试用例，针对特定的JavaScript语言特性或语法结构。
2. **提供 JavaScript 代码片段 (using `snippets`)**:  在每个测试用例中，会定义一个包含多个JavaScript代码片段的数组。这些片段涵盖了该测试用例所关注的语言特性的不同用法和边界情况。
3. **构建实际的字节码 (using `BuildActual`)**:  `BuildActual` 函数会将这些 JavaScript 代码片段输入到 `BytecodeGenerator` 中，并生成实际的字节码。
4. **加载期望的字节码 (using `LoadGolden`)**: `LoadGolden` 函数会加载预先定义好的 "golden" 文件，这些文件包含了针对这些 JavaScript 代码片段的期望字节码。
5. **比较实际和期望的字节码 (using `CompareTexts` and `CHECK`)**:  `CompareTexts` 函数会比较 `BuildActual` 生成的实际字节码和 `LoadGolden` 加载的期望字节码。`CHECK` 宏用于断言比较结果是否一致，如果不一致则表示字节码生成器存在错误。

**针对您提供的代码片段的详细功能列表:**

* **`ObjectLiterals`**: 测试对象字面量的字节码生成，包括各种属性定义方式，例如：
    * 简单属性
    * 方法
    * getter 和 setter
    * 数字属性名
    * `__proto__` 属性
    * 计算属性名
    * 混合使用各种属性定义方式

    **JavaScript 示例:**
    ```javascript
    var obj = {
      a: 1,
      b() { return 2; },
      get c() { return this.x; },
      set c(val) { this.x = val; },
      1: 'number key',
      __proto__: null,
      ['computed' + 'Key']: 'computed value'
    };
    ```

* **`TopLevelObjectLiterals`**:  测试顶层作用域中对象字面量的字节码生成。

    **JavaScript 示例:**
    ```javascript
    var globalObj = { func: function() { } };
    ```

* **`TryCatch`**: 测试 `try...catch` 语句的字节码生成，包括嵌套的 `try...catch` 结构。

    **JavaScript 示例:**
    ```javascript
    try {
      // 可能抛出异常的代码
      throw new Error("Something went wrong");
    } catch (e) {
      // 捕获异常并处理
      console.error("Caught an error:", e);
    }
    ```
    **假设输入与输出:**
    假设输入 JavaScript 代码 `try { return 1; } catch(e) { return 2; }`.
    如果 `try` 块中的代码执行成功，则输出字节码会包含返回常量 `1` 的指令。如果 `try` 块中抛出异常，则会跳转到 `catch` 块，输出字节码会包含返回常量 `2` 的指令。

* **`TryFinally`**: 测试 `try...finally` 语句的字节码生成，包括 `try...catch...finally` 结构和嵌套的 `try` 结构。

    **JavaScript 示例:**
    ```javascript
    try {
      // 一些代码
    } finally {
      // 无论 try 块是否抛出异常，都会执行的代码
    }
    ```

* **`Throw`**: 测试 `throw` 语句的字节码生成，包括抛出不同类型的值。

    **JavaScript 示例:**
    ```javascript
    throw "Error message";
    throw 123;
    throw new Error("Custom error");
    ```

* **`CallNew`**: 测试 `new` 关键字调用构造函数的字节码生成，包括调用自定义构造函数和匿名类。

    **JavaScript 示例:**
    ```javascript
    function MyClass(value) {
      this.value = value;
    }
    var instance = new MyClass(5);

    var anonymousInstance = new class {
      constructor() {
        this.data = 10;
      }
    }();
    ```

* **`ContextVariables`**: 测试访问和修改闭包中上下文变量的字节码生成。

    **JavaScript 示例:**
    ```javascript
    function outer() {
      var outerVar = 10;
      return function inner() {
        console.log(outerVar); // 访问外部函数的变量
        outerVar++; // 修改外部函数的变量
      };
    }
    var closure = outer();
    closure();
    ```

* **`ContextParameters`**: 测试在闭包中访问和修改外部函数参数的字节码生成。

    **JavaScript 示例:**
    ```javascript
    function myFunction(arg1) {
      return function() {
        arg1 = 20; // 修改外部函数的参数
        return arg1;
      };
    }
    var innerFunc = myFunction(5);
    console.log(innerFunc()); // 输出 20
    ```

* **`OuterContextVariables`**: 测试多层嵌套闭包中访问和修改外部变量的字节码生成。

    **JavaScript 示例:**
    ```javascript
    function outer() {
      var outerVar = 1;
      function middle() {
        return function inner() {
          return outerVar; // 访问最外层函数的变量
        };
      }
      return middle();
    }
    var innerClosure = outer()();
    console.log(innerClosure()); // 输出 1
    ```

* **`CountOperators`**: 测试递增和递减运算符（`++`, `--`）的字节码生成，包括前缀和后缀形式，以及在对象属性和数组元素上的应用。

    **JavaScript 示例:**
    ```javascript
    var a = 5;
    a++; // 后缀递增
    ++a; // 前缀递增

    var obj = { val: 10 };
    obj.val++;

    var arr = [1, 2];
    arr[0]--;
    ```

* **`GlobalCountOperators`**: 测试全局作用域中的递增和递减运算符的字节码生成。

    **JavaScript 示例:**
    ```javascript
    globalVar = 5;
    globalVar++;

    function f() {
      'use strict';
      globalUndeclaredVar++; // 在严格模式下会报错
    }
    ```
    **用户常见的编程错误:** 在非严格模式下意外地创建全局变量，例如 `unallocated = 1;`。这可能会导致意外的行为和难以调试的问题。

* **`CompoundExpressions`**: 测试复合赋值运算符（例如 `+=`, `-=`, `*=`, `^=`）的字节码生成。

    **JavaScript 示例:**
    ```javascript
    var x = 10;
    x += 5; // x = x + 5;

    var obj = { prop: 2 };
    obj.prop *= 3; // obj.prop = obj.prop * 3;
    ```

* **`GlobalCompoundExpressions`**: 测试全局作用域中的复合赋值运算符的字节码生成。

    **JavaScript 示例:**
    ```javascript
    globalVar = 10;
    globalVar &= 1;
    ```

* **`CreateArguments`**: 测试 `arguments` 对象的创建和访问的字节码生成，包括在严格模式和非严格模式下的情况。

    **JavaScript 示例:**
    ```javascript
    function myFunction(a, b) {
      console.log(arguments[0]);
      console.log(arguments[1]);
      console.log(arguments.length);
    }
    myFunction(1, 2);

    function strictFunction(a) {
      'use strict';
      console.log(arguments); // arguments 对象在严格模式下不会与形参共享
    }
    strictFunction(3);
    ```

* **`CreateRestParameter`**: 测试剩余参数 (`...rest`) 的字节码生成。

    **JavaScript 示例:**
    ```javascript
    function myFunction(first, ...rest) {
      console.log(first);
      console.log(rest); // rest 是一个包含剩余参数的数组
    }
    myFunction(1, 2, 3, 4);
    ```

* **`ForIn`**: 测试 `for...in` 循环的字节码生成，包括遍历 `null`、`undefined`、字符串、数组和对象的情况，以及 `continue` 和 `break` 语句的使用。

    **JavaScript 示例:**
    ```javascript
    const obj = { a: 1, b: 2, c: 3 };
    for (let key in obj) {
      console.log(key, obj[key]);
    }

    const arr = [10, 20, 30];
    for (let index in arr) {
      console.log(index, arr[index]); // 注意 index 是字符串类型的
    }
    ```
    **用户常见的编程错误:** 使用 `for...in` 遍历数组，这通常不是最佳实践，因为它遍历的是属性名（字符串类型的索引），并且会遍历到继承的可枚举属性。

* **`ForOf`**: 测试 `for...of` 循环的字节码生成，包括遍历数组和可迭代对象，以及 `continue` 和 `break` 语句的使用。

    **JavaScript 示例:**
    ```javascript
    const arr = [10, 20, 30];
    for (const value of arr) {
      console.log(value);
    }

    const str = "hello";
    for (const char of str) {
      console.log(char);
    }
    ```

* **`Conditional`**: 测试三元条件运算符 (`? :`) 的字节码生成。

    **JavaScript 示例:**
    ```javascript
    const age = 20;
    const status = age >= 18 ? "Adult" : "Minor";
    console.log(status); // 输出 "Adult"
    ```

* **`Switch`**: 测试 `switch` 语句的字节码生成，包括 `case` 和 `default` 子句，以及 `break` 和 fall-through 的情况。

    **JavaScript 示例:**
    ```javascript
    const fruit = "apple";
    switch (fruit) {
      case "banana":
        console.log("It's a banana.");
        break;
      case "apple":
        console.log("It's an apple.");
        break;
      default:
        console.log("It's some other fruit.");
    }
    ```

* **`BasicBlockToBoolean`**: 测试将基本块的结果转换为布尔值的场景，这通常发生在逻辑运算符 (`||`, `&&`) 和条件语句中。

    **JavaScript 示例:**
    ```javascript
    var a = 1;
    if (a || a < 0) { // a 的值 (1) 会被转换为 true
      console.log("Condition is true");
    }

    var b = 0;
    var result = b && b > 5 ? "yes" : "no"; // b 的值 (0) 会被转换为 false
    console.log(result); // 输出 "no"
    ```

* **`DeadCodeRemoval`**: 测试字节码生成器是否能够移除永远不会执行到的死代码。

    **JavaScript 示例:**
    ```javascript
    function myFunction() {
      return;
      var neverExecuted = 10; // 这行代码永远不会被执行到
    }

    if (false) {
      console.log("This will never be printed");
    }
    ```

* **`ThisFunction`**: 测试在函数内部引用函数自身（通常用于匿名递归）的字节码生成。

    **JavaScript 示例:**
    ```javascript
    var factorial = function fact(n) {
      if (n <= 1) {
        return 1;
      } else {
        return n * fact(n - 1); // 递归调用自身
      }
    };
    console.log(factorial(5));
    ```

* **`NewTarget`**: 测试 `new.target` 元属性的字节码生成，该属性在构造函数中指向 `new` 关键字调用的构造函数。

    **JavaScript 示例:**
    ```javascript
    function MyClass() {
      if (!new.target) {
        throw new Error("MyClass must be called with new");
      }
      console.log("MyClass called with new");
    }
    new MyClass(); // 输出 "MyClass called with new"
    // MyClass(); // 会抛出错误
    ```

* **`RemoveRedundantLdar`**: 测试是否移除了冗余的本地变量加载指令 (Ldar)，优化生成的字节码。

* **`GenerateTestUndetectable`**: 测试对于 `null` 和 `undefined` 的比较操作的字节码生成，特别是针对那些难以直接检测到的对象。

    **JavaScript 示例:**
    ```javascript
    var obj = { val: 1 };
    if (obj == null) {
      console.log("obj is null");
    }
    if (obj === null) {
      console.log("obj is strictly null");
    }
    ```

* **`AssignmentsInBinaryExpression`**: 测试在二元表达式中包含赋值操作的字节码生成，注意赋值操作的副作用和求值顺序。

    **JavaScript 示例:**
    ```javascript
    var x = 0;
    var y = (x = 5) + 10; // x 先被赋值为 5，然后参与加法运算
    console.log(x, y); // 输出 5, 15
    ```

* **`DestructuringAssignment`**: 测试解构赋值的字节码生成，包括数组和对象的解构。

    **JavaScript 示例:**
    ```javascript
    const arr = [1, 2, 3];
    const [a, b, c] = arr;
    console.log(a, b, c); // 输出 1, 2, 3

    const obj = { x: 10, y: 20 };
    const { x: myX, y } = obj;
    console.log(myX, y); // 输出 10, 20
    ```

* **`Eval`**: 测试 `eval()` 函数的字节码生成。

    **JavaScript 示例:**
    ```javascript
    var result = eval("1 + 2");
    console.log(result); // 输出 3
    ```

* **`LookupSlot`**: 测试查找作用域槽位（用于变量存储）的字节码生成，特别是在 `eval()` 函数内部和闭包中的情况。

* **`CallLookupSlot`**: 测试调用通过作用域槽位查找到的函数的字节码生成。

* **`LookupSlotInEval`**: 测试在 `eval()` 函数内部查找作用域槽位的字节码生成。

* **`DeleteLookupSlotInEval`**: 测试在 `eval()` 函数内部删除通过作用域槽位查找到的变量的字节码生成。

* **`WideRegisters`**: 测试当需要使用大量寄存器时，字节码生成器如何处理，可能涉及到使用 "宽" 寄存器。

* **`ConstVariable`**: 测试 `const` 声明的常量变量的字节码生成。

    **JavaScript 示例:**
    ```javascript
    const PI = 3.14159;
    // PI = 3.14; // 会报错，常量不能重新赋值
    ```
    **用户常见的编程错误:** 尝试重新赋值 `const` 声明的变量。

* **`LetVariable`**: 测试 `let` 声明的块级作用域变量的字节码生成。

    **JavaScript 示例:**
    ```javascript
    let message = "Hello";
    if (true) {
      let message = "World"; // 块级作用域，与外部的 message 不同
      console.log(message); // 输出 "World"
    }
    console.log(message); // 输出 "Hello"
    ```
    **用户常见的编程错误:** 在 `let` 声明之前访问该变量，会导致暂时性死区错误 (Temporal Dead Zone error)。

* **`ConstVariableContextSlot`**: 测试在闭包中访问和修改 `const` 声明的上下文变量的字节码生成。

* **`LetVariableContextSlot`**: 测试在闭包中访问和修改 `let` 声明的上下文变量的字节码生成。

* **`WithStatement`**: 测试 `with` 语句的字节码生成。

    **JavaScript 示例:**
    ```javascript
    const obj = { x: 1, y: 2 };
    with (obj) {
      console.log(x + y); // 可以直接访问 obj 的属性
    }
    ```
    **用户常见的编程错误:** 过度使用 `with` 语句，因为它会使代码的作用域变得模糊，降低代码的可读性和性能。

* **`DoDebugger`**: 测试 `debugger` 语句的字节码生成，用于在代码执行时中断并进入调试器。

    **JavaScript 示例:**
    ```javascript
    function myFunction() {
      let x = 10;
      debugger; // 代码执行到这里会暂停，进入调试器
      console.log(x);
    }
    myFunction();
    ```

* **`ClassDeclarations`**: 测试类声明的字节码生成，包括构造函数、方法、静态方法和计算属性名。

    **JavaScript 示例:**
    ```javascript
    class MyClass {
      constructor(name) {
        this.name = name;
      }
      sayHello() {
        console.log(`Hello, my name is ${this.name}`);
      }
      static staticMethod() {
        console.log("This is a static method");
      }
      ['computed' + 'Method']() {
        console.log("This is a computed method name");
      }
    }
    const instance = new MyClass("Alice");
    instance.sayHello();
    MyClass.staticMethod();
    instance.computedMethod();
    ```

* **`ClassAndSuperClass`**: 测试类继承和 `super` 关键字的字节码生成，包括调用父类的方法、getter/setter 和构造函数。

    **JavaScript 示例:**
    ```javascript
    class Parent {
      constructor(name) {
        this.name = name;
      }
      sayHello() {
        console.log(`Hello from Parent, my name is ${this.name}`);
      }
    }

    class Child extends Parent {
      constructor(name, age) {
        super(name); // 调用父类的构造函数
        this.age = age;
      }
      sayHello() {
        super.sayHello(); // 调用父类的方法
        console.log(`Hello from Child, I am ${this.age} years old`);
      }
    }

    const child = new Child("Bob", 10);
    child.sayHello();
    ```

* **`PublicClassFields`**: 测试公有类字段的字节码生成。

    **JavaScript 示例:**
    ```javascript
    class MyClass {
      myField = 10;
      anotherField;
      constructor() {
        this.anotherField = 20;
      }
    }
    const instance = new MyClass();
    console.log(instance.myField); // 输出 10
    console.log(instance.anotherField); // 输出 20
    ```

* **`PrivateClassFields`**: 测试私有类字段的字节码生成。

    **JavaScript 示例:**
    ```javascript
    class MyClass {
      #privateField = 10;
      constructor() {
        console.log(this.#privateField);
      }
    }
    const instance = new MyClass();
    // console.log(instance.#privateField); // 会报错，无法在类外部访问私有字段
    ```

* **`PrivateClassFieldAccess`**: 测试对私有类字段的访问控制的字节码生成。

* **`PrivateMethodDeclaration`**: 测试私有类方法的声明的字节码生成。

    **JavaScript 示例:**
    ```javascript
    class MyClass {
      #privateMethod() {
        console.log("This is a private method");
      }
      publicMethod() {
        this.#privateMethod(); // 只能在类内部访问私有方法
      }
    }
    const instance = new MyClass();
    instance.publicMethod();
    // instance.#privateMethod(); // 会报错，无法在类外部访问私有方法
    ```

* **`PrivateMethodAccess`**: 测试对私有类方法的访问控制的字节码生成。

* **`PrivateAccessorAccess`**: 测试对私有类访问器（getter 和 setter）的访问控制的字节码生成。

    **JavaScript 示例:**
    ```javascript
    class MyClass {
      #value = 0;
      get #privateGetter() {
        return this.#value;
      }
      set #privateSetter(newValue) {
        this.#value = newValue;
      }
      publicMethod() {
        console.log(this.#privateGetter);
        this.#privateSetter = 100;
      }
    }
    const instance = new MyClass();
    instance.publicMethod();
    // console.log(instance.#privateGetter); // 会报错
    // instance.#privateSetter = 200; // 会报错
    ```

* **`StaticPrivateMethodDeclaration`**: 测试静态私有类方法的声明的字节码生成。

    **JavaScript 示例:**
    ```javascript
    class MyClass {
      static #staticPrivateMethod() {
        console.log("This is a static private method");
      }
      static publicStaticMethod() {
        MyClass.#staticPrivateMethod();
      }
    }
    MyClass.publicStaticMethod();
    // MyClass.#staticPrivateMethod(); // 会报错
    ```

* **`StaticPrivateMethodAccess`**: 测试对静态私有类方法的访问控制的字节码生成。

**总结:**

总而言之，`v8/test/unittests/interpreter/bytecode-generator-unittest.cc` 的功能是 **全面测试 V8 JavaScript 引擎的字节码生成器**，确保其能够正确地将各种 JavaScript 代码结构转换为有效的字节码，这是 V8 解释器正确执行 JavaScript 代码的基础。  这个文件通过大量的测试用例覆盖了各种 JavaScript 语法和特性，保证了字节码生成器的健壮性和正确性。

由于 `v8/test/unittests/interpreter/bytecode-generator-unittest.cc` 的文件扩展名是 `.cc`，因此它是一个 **C++ 源代码文件**，而不是 Torque 源代码文件。Torque 文件的扩展名是 `.tq`。

### 提示词
```
这是目录为v8/test/unittests/interpreter/bytecode-generator-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/interpreter/bytecode-generator-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
get a() { return 2; } };\n",

      "return { get a() { return this.x; }, set a(val) { this.x = val } };\n",

      "return { set b(val) { this.y = val } };\n",

      "var a = 1; return { 1: a };\n",

      "return { __proto__: null };\n",

      "var a = 'test'; return { [a]: 1 };\n",

      "var a = 'test'; return { val: a, [a]: 1 };\n",

      "var a = 'test'; return { [a]: 1, __proto__: {} };\n",

      "var n = 'name'; return { [n]: 'val', get a() { }, set a(b) {} };\n",
  };

  CHECK(CompareTexts(BuildActual(printer(), snippets),
                     LoadGolden("ObjectLiterals.golden")));
}

TEST_F(BytecodeGeneratorTest, TopLevelObjectLiterals) {
  printer().set_wrap(false);
  printer().set_test_function_name("f");
  printer().set_top_level(true);

  std::string snippets[] = {
      "var a = { func: function() { } };\n",
  };

  CHECK(CompareTexts(BuildActual(printer(), snippets),
                     LoadGolden("TopLevelObjectLiterals.golden")));
}

TEST_F(BytecodeGeneratorTest, TryCatch) {
  std::string snippets[] = {
      "try { return 1; } catch(e) { return 2; }\n",

      "var a;\n"
      "try { a = 1 } catch(e1) {};\n"
      "try { a = 2 } catch(e2) { a = 3 }\n",
  };

  CHECK(CompareTexts(BuildActual(printer(), snippets),
                     LoadGolden("TryCatch.golden")));
}

TEST_F(BytecodeGeneratorTest, TryFinally) {
  std::string snippets[] = {
      "var a = 1;\n"
      "try { a = 2; } finally { a = 3; }\n",

      "var a = 1;\n"
      "try { a = 2; } catch(e) { a = 20 } finally { a = 3; }\n",

      "var a; try {\n"
      "  try { a = 1 } catch(e) { a = 2 }\n"
      "} catch(e) { a = 20 } finally { a = 3; }\n",
  };

  CHECK(CompareTexts(BuildActual(printer(), snippets),
                     LoadGolden("TryFinally.golden")));
}

TEST_F(BytecodeGeneratorTest, Throw) {
  std::string snippets[] = {
      "throw 1;\n",

      "throw 'Error';\n",

      "var a = 1; if (a) { throw 'Error'; };\n",
  };

  CHECK(CompareTexts(BuildActual(printer(), snippets),
                     LoadGolden("Throw.golden")));
}

TEST_F(BytecodeGeneratorTest, CallNew) {
  printer().set_wrap(false);
  printer().set_test_function_name("f");

  std::string snippets[] = {
      "function bar() { this.value = 0; }\n"
      "function f() { return new bar(); }\n"
      "f();\n",

      "function bar(x) { this.value = 18; this.x = x;}\n"
      "function f() { return new bar(3); }\n"
      "f();\n",

      "function bar(w, x, y, z) {\n"
      "  this.value = 18;\n"
      "  this.x = x;\n"
      "  this.y = y;\n"
      "  this.z = z;\n"
      "}\n"
      "function f() { return new bar(3, 4, 5); }\n"
      "f();\n",

      "function f() { new class {}; }\n"
      "f();\n",
  };

  CHECK(CompareTexts(BuildActual(printer(), snippets),
                     LoadGolden("CallNew.golden")));
}

TEST_F(BytecodeGeneratorTest, ContextVariables) {
  // The wide check below relies on MIN_CONTEXT_SLOTS + 3 + 250 == 256, if this
  // ever changes, the REPEAT_XXX should be changed to output the correct number
  // of unique variables to trigger the wide slot load / store.
  static_assert(Context::MIN_CONTEXT_EXTENDED_SLOTS + 3 + 250 == 256);

  // For historical reasons, this test expects the first unique identifier
  // to be 896.
  global_counter = 896;

  // clang-format off
  std::string snippets[] = {
    "var a; return function() { a = 1; };\n",

    "var a = 1; return function() { a = 2; };\n",

    "var a = 1; var b = 2; return function() { a = 2; b = 3 };\n",

    "var a; (function() { a = 2; })(); return a;\n",

    "'use strict';\n"
    "let a = 1;\n"
    "{ let b = 2; return function() { a + b; }; }\n",

    "'use strict';\n" +
     UniqueVars(252) +
    "eval();\n"
    "var b = 100;\n"
    "return b\n",
  };
  // clang-format on

  CHECK(CompareTexts(BuildActual(printer(), snippets),
                     LoadGolden("ContextVariables.golden")));
}

TEST_F(BytecodeGeneratorTest, ContextParameters) {
  printer().set_wrap(false);
  printer().set_test_function_name("f");

  std::string snippets[] = {
      "function f(arg1) { return function() { arg1 = 2; }; }",

      "function f(arg1) { var a = function() { arg1 = 2; }; return arg1; }",

      "function f(a1, a2, a3, a4) { return function() { a1 = a3; }; }",

      "function f() { var self = this; return function() { self = 2; }; }",
  };

  CHECK(CompareTexts(BuildActual(printer(), snippets, "", "\nf();"),
                     LoadGolden("ContextParameters.golden")));
}

TEST_F(BytecodeGeneratorTest, OuterContextVariables) {
  printer().set_wrap(false);
  printer().set_test_function_name("f");

  std::string snippets[] = {
      "function Outer() {\n"
      "  var outerVar = 1;\n"
      "  function Inner(innerArg) {\n"
      "    this.innerFunc = function() { return outerVar * innerArg; }\n"
      "  }\n"
      "  this.getInnerFunc = function() { return new Inner(1).innerFunc; }\n"
      "}\n"
      "var f = new Outer().getInnerFunc();",

      "function Outer() {\n"
      "  var outerVar = 1;\n"
      "  function Inner(innerArg) {\n"
      "    this.innerFunc = function() { outerVar = innerArg; }\n"
      "  }\n"
      "  this.getInnerFunc = function() { return new Inner(1).innerFunc; }\n"
      "}\n"
      "var f = new Outer().getInnerFunc();",
  };

  CHECK(CompareTexts(BuildActual(printer(), snippets, "", "\nf();"),
                     LoadGolden("OuterContextVariables.golden")));
}

TEST_F(BytecodeGeneratorTest, CountOperators) {
  std::string snippets[] = {
      "var a = 1; return ++a;\n",

      "var a = 1; return a++;\n",

      "var a = 1; return --a;\n",

      "var a = 1; return a--;\n",

      "var a = { val: 1 }; return a.val++;\n",

      "var a = { val: 1 }; return --a.val;\n",

      "var name = 'var'; var a = { val: 1 }; return a[name]--;\n",

      "var name = 'var'; var a = { val: 1 }; return ++a[name];\n",

      "var a = 1; var b = function() { return a }; return ++a;\n",

      "var a = 1; var b = function() { return a }; return a--;\n",

      "var idx = 1; var a = [1, 2]; return a[idx++] = 2;\n",
  };

  CHECK(CompareTexts(BuildActual(printer(), snippets),
                     LoadGolden("CountOperators.golden")));
}

TEST_F(BytecodeGeneratorTest, GlobalCountOperators) {
  printer().set_wrap(false);
  printer().set_test_function_name("f");

  std::string snippets[] = {
      "var global = 1;\n"
      "function f() { return ++global; }\n"
      "f();\n",

      "var global = 1;\n"
      "function f() { return global--; }\n"
      "f();\n",

      "unallocated = 1;\n"
      "function f() { 'use strict'; return --unallocated; }\n"
      "f();\n",

      "unallocated = 1;\n"
      "function f() { return unallocated++; }\n"
      "f();\n",
  };

  CHECK(CompareTexts(BuildActual(printer(), snippets),
                     LoadGolden("GlobalCountOperators.golden")));
}

TEST_F(BytecodeGeneratorTest, CompoundExpressions) {
  std::string snippets[] = {
      "var a = 1; a += 2;\n",

      "var a = 1; a /= 2;\n",

      "var a = { val: 2 }; a.name *= 2;\n",

      "var a = { 1: 2 }; a[1] ^= 2;\n",

      "var a = 1; (function f() { return a; }); a |= 24;\n",
  };

  CHECK(CompareTexts(BuildActual(printer(), snippets),
                     LoadGolden("CompoundExpressions.golden")));
}

TEST_F(BytecodeGeneratorTest, GlobalCompoundExpressions) {
  printer().set_wrap(false);
  printer().set_test_function_name("f");

  std::string snippets[] = {
      "var global = 1;\n"
      "function f() { return global &= 1; }\n"
      "f();\n",

      "unallocated = 1;\n"
      "function f() { return unallocated += 1; }\n"
      "f();\n",
  };

  CHECK(CompareTexts(BuildActual(printer(), snippets),
                     LoadGolden("GlobalCompoundExpressions.golden")));
}

TEST_F(BytecodeGeneratorTest, CreateArguments) {
  printer().set_wrap(false);
  printer().set_test_function_name("f");

  std::string snippets[] = {
      "function f() { return arguments; }",

      "function f() { return arguments[0]; }",

      "function f() { 'use strict'; return arguments; }",

      "function f(a) { return arguments[0]; }",

      "function f(a, b, c) { return arguments; }",

      "function f(a, b, c) { 'use strict'; return arguments; }",
  };

  CHECK(CompareTexts(BuildActual(printer(), snippets, "", "\nf();"),
                     LoadGolden("CreateArguments.golden")));
}

TEST_F(BytecodeGeneratorTest, CreateRestParameter) {
  printer().set_wrap(false);
  printer().set_test_function_name("f");

  std::string snippets[] = {
      "function f(...restArgs) { return restArgs; }",

      "function f(a, ...restArgs) { return restArgs; }",

      "function f(a, ...restArgs) { return restArgs[0]; }",

      "function f(a, ...restArgs) { return restArgs[0] + arguments[0]; }",
  };

  CHECK(CompareTexts(BuildActual(printer(), snippets, "", "\nf();"),
                     LoadGolden("CreateRestParameter.golden")));
}

TEST_F(BytecodeGeneratorTest, ForIn) {
  std::string snippets[] = {
      "for (var p in null) {}\n",

      "for (var p in undefined) {}\n",

      "for (var p in undefined) {}\n",

      "var x = 'potatoes';\n"
      "for (var p in x) { return p; }\n",

      "var x = 0;\n"
      "for (var p in [1,2,3]) { x += p; }\n",

      "var x = { 'a': 1, 'b': 2 };\n"
      "for (x['a'] in [10, 20, 30]) {\n"
      "  if (x['a'] == 10) continue;\n"
      "  if (x['a'] == 20) break;\n"
      "}\n",

      "var x = [ 10, 11, 12 ] ;\n"
      "for (x[0] in [1,2,3]) { return x[3]; }\n",
  };

  CHECK(CompareTexts(BuildActual(printer(), snippets),
                     LoadGolden("ForIn.golden")));
}

TEST_F(BytecodeGeneratorTest, ForOf) {
  std::string snippets[] = {
      "for (var p of [0, 1, 2]) {}\n",

      "var x = 'potatoes';\n"
      "for (var p of x) { return p; }\n",

      "for (var x of [10, 20, 30]) {\n"
      "  if (x == 10) continue;\n"
      "  if (x == 20) break;\n"
      "}\n",

      "var x = { 'a': 1, 'b': 2 };\n"
      "for (x['a'] of [1,2,3]) { return x['a']; }\n",
  };

  CHECK(CompareTexts(BuildActual(printer(), snippets),
                     LoadGolden("ForOf.golden")));
}

TEST_F(BytecodeGeneratorTest, Conditional) {
  std::string snippets[] = {
      "return 1 ? 2 : 3;\n",

      "return 1 ? 2 ? 3 : 4 : 5;\n",

      "return 0 < 1 ? 2 : 3;\n",

      "var x = 0;\n"
      "return x ? 2 : 3;\n",
  };

  CHECK(CompareTexts(BuildActual(printer(), snippets),
                     LoadGolden("Conditional.golden")));
}

TEST_F(BytecodeGeneratorTest, Switch) {
  // clang-format off
  std::string snippets[] = {
    "var a = 1;\n"
    "switch(a) {\n"
    " case 1: return 2;\n"
    " case 2: return 3;\n"
    "}\n",

    "var a = 1;\n"
    "switch(a) {\n"
    " case 1: a = 2; break;\n"
    " case 2: a = 3; break;\n"
    "}\n",

    "var a = 1;\n"
    "switch(a) {\n"
    " case 1: a = 2; // fall-through\n"
    " case 2: a = 3; break;\n"
    "}\n",

    "var a = 1;\n"
    "switch(a) {\n"
    " case 2: break;\n"
    " case 3: break;\n"
    " default: a = 1; break;\n"
    "}\n",

    "var a = 1;\n"
    "switch(typeof(a)) {\n"
    " case 2: a = 1; break;\n"
    " case 3: a = 2; break;\n"
    " default: a = 3; break;\n"
    "}\n",

    "var a = 1;\n"
    "switch(a) {\n"
    " case typeof(a): a = 1; break;\n"
    " default: a = 2; break;\n"
    "}\n",

    "var a = 1;\n"
    "switch(a) {\n"
    " case 1:\n" +
       Repeat("  a = 2;\n", 64) +
    "  break;\n"
    " case 2:\n"
    "  a = 3;\n"
    "  break;\n"
    "}\n",

    "var a = 1;\n"
    "switch(a) {\n"
    " case 1: \n"
    "   switch(a + 1) {\n"
    "      case 2 : a = 1; break;\n"
    "      default : a = 2; break;\n"
    "   }  // fall-through\n"
    " case 2: a = 3;\n"
    "}\n",
  };
  // clang-format on

  CHECK(CompareTexts(BuildActual(printer(), snippets),
                     LoadGolden("Switch.golden")));
}

TEST_F(BytecodeGeneratorTest, BasicBlockToBoolean) {
  std::string snippets[] = {
      "var a = 1; if (a || a < 0) { return 1; }\n",

      "var a = 1; if (a && a < 0) { return 1; }\n",

      "var a = 1; a = (a || a < 0) ? 2 : 3;\n",
  };

  CHECK(CompareTexts(BuildActual(printer(), snippets),
                     LoadGolden("BasicBlockToBoolean.golden")));
}

TEST_F(BytecodeGeneratorTest, DeadCodeRemoval) {
  std::string snippets[] = {
      "return; var a = 1; a();\n",

      "if (false) { return; }; var a = 1;\n",

      "if (true) { return 1; } else { return 2; };\n",

      "var a = 1; if (a) { return 1; }; return 2;\n",
  };

  CHECK(CompareTexts(BuildActual(printer(), snippets),
                     LoadGolden("DeadCodeRemoval.golden")));
}

TEST_F(BytecodeGeneratorTest, ThisFunction) {
  printer().set_wrap(false);
  printer().set_test_function_name("f");

  std::string snippets[] = {
      "var f;\n"
      "f = function f() {};",

      "var f;\n"
      "f = function f() { return f; };",
  };

  CHECK(CompareTexts(BuildActual(printer(), snippets, "", "\nf();"),
                     LoadGolden("ThisFunction.golden")));
}

TEST_F(BytecodeGeneratorTest, NewTarget) {
  std::string snippets[] = {
      "return new.target;\n",

      "new.target;\n",
  };

  CHECK(CompareTexts(BuildActual(printer(), snippets),
                     LoadGolden("NewTarget.golden")));
}

TEST_F(BytecodeGeneratorTest, RemoveRedundantLdar) {
  std::string snippets[] = {
      "var ld_a = 1;\n"          // This test is to check Ldar does not
      "while(true) {\n"          // get removed if the preceding Star is
      "  ld_a = ld_a + ld_a;\n"  // in a different basicblock.
      "  if (ld_a > 10) break;\n"
      "}\n"
      "return ld_a;\n",

      "var ld_a = 1;\n"
      "do {\n"
      "  ld_a = ld_a + ld_a;\n"
      "  if (ld_a > 10) continue;\n"
      "} while(false);\n"
      "return ld_a;\n",

      "var ld_a = 1;\n"
      "  ld_a = ld_a + ld_a;\n"
      "  return ld_a;\n",
  };

  CHECK(CompareTexts(BuildActual(printer(), snippets),
                     LoadGolden("RemoveRedundantLdar.golden")));
}

TEST_F(BytecodeGeneratorTest, GenerateTestUndetectable) {
  std::string snippets[] = {
      "var obj_a = {val:1};\n"
      "var b = 10;\n"
      "if (obj_a == null) { b = 20;}\n"
      "return b;\n",

      "var obj_a = {val:1};\n"
      "var b = 10;\n"
      "if (obj_a == undefined) { b = 20;}\n"
      "return b;\n",

      "var obj_a = {val:1};\n"
      "var b = 10;\n"
      "if (obj_a != null) { b = 20;}\n"
      "return b;\n",

      "var obj_a = {val:1};\n"
      "var b = 10;\n"
      "if (obj_a != undefined) { b = 20;}\n"
      "return b;\n",

      "var obj_a = {val:1};\n"
      "var b = 10;\n"
      "if (obj_a === null) { b = 20;}\n"
      "return b;\n",

      "var obj_a = {val:1};\n"
      "var b = 10;\n"
      "if (obj_a === undefined) { b = 20;}\n"
      "return b;\n",

      "var obj_a = {val:1};\n"
      "var b = 10;\n"
      "if (obj_a !== null) { b = 20;}\n"
      "return b;\n",

      "var obj_a = {val:1};\n"
      "var b = 10;\n"
      "if (obj_a !== undefined) { b = 20;}\n"
      "return b;\n"};

  CHECK(CompareTexts(BuildActual(printer(), snippets),
                     LoadGolden("GenerateTestUndetectable.golden")));
}

TEST_F(BytecodeGeneratorTest, AssignmentsInBinaryExpression) {
  std::string snippets[] = {
      "var x = 0, y = 1;\n"
      "return (x = 2, y = 3, x = 4, y = 5);\n",

      "var x = 55;\n"
      "var y = (x = 100);\n"
      "return y;\n",

      "var x = 55;\n"
      "x = x + (x = 100) + (x = 101);\n"
      "return x;\n",

      "var x = 55;\n"
      "x = (x = 56) - x + (x = 57);\n"
      "x++;\n"
      "return x;\n",

      "var x = 55;\n"
      "var y = x + (x = 1) + (x = 2) + (x = 3);\n"
      "return y;\n",

      "var x = 55;\n"
      "var x = x + (x = 1) + (x = 2) + (x = 3);\n"
      "return x;\n",

      "var x = 10, y = 20;\n"
      "return x + (x = 1) + (x + 1) * (y = 2) + (y = 3) + (x = 4) + (y = 5) + "
      "y;\n",

      "var x = 17;\n"
      "return 1 + x + (x++) + (++x);\n",
  };

  CHECK(CompareTexts(BuildActual(printer(), snippets),
                     LoadGolden("AssignmentsInBinaryExpression.golden")));
}

TEST_F(BytecodeGeneratorTest, DestructuringAssignment) {
  std::string snippets[] = {
      "var x, a = [0,1,2,3];\n"
      "[x] = a;\n",

      "var x, y, a = [0,1,2,3];\n"
      "[,x,...y] = a;\n",

      "var x={}, y, a = [0];\n"
      "[x.foo,y=4] = a;\n",

      "var x, a = {x:1};\n"
      "({x} = a);\n",

      "var x={}, a = {y:1};\n"
      "({y:x.foo} = a);\n",

      "var x, a = {y:1, w:2, v:3};\n"
      "({x=0,...y} = a);\n",
  };

  CHECK(CompareTexts(BuildActual(printer(), snippets),
                     LoadGolden("DestructuringAssignment.golden")));
}

TEST_F(BytecodeGeneratorTest, Eval) {
  std::string snippets[] = {
      "return eval('1;');\n",
  };

  CHECK(CompareTexts(BuildActual(printer(), snippets),
                     LoadGolden("Eval.golden")));
}

TEST_F(BytecodeGeneratorTest, LookupSlot) {
  printer().set_test_function_name("f");

  // clang-format off
  std::string snippets[] = {
      "eval('var x = 10;'); return x;\n",

      "eval('var x = 10;'); return typeof x;\n",

      "x = 20; return eval('');\n",

      "var x = 20;\n"
      "f = function(){\n"
      "  eval('var x = 10');\n"
      "  return x;\n"
      "}\n"
      "f();\n",

      "x = 20;\n"
      "f = function(){\n"
      "  eval('var x = 10');\n"
      "  return x;\n"
      "}\n"
      "f();\n"
  };
  // clang-format on

  CHECK(CompareTexts(BuildActual(printer(), snippets),
                     LoadGolden("LookupSlot.golden")));
}

TEST_F(BytecodeGeneratorTest, CallLookupSlot) {
  std::string snippets[] = {
      "g = function(){}; eval(''); return g();\n",
  };

  CHECK(CompareTexts(BuildActual(printer(), snippets),
                     LoadGolden("CallLookupSlot.golden")));
}

// TODO(mythria): tests for variable/function declaration in lookup slots.

TEST_F(BytecodeGeneratorTest, LookupSlotInEval) {
  printer().set_wrap(false);
  printer().set_test_function_name("f");

  std::string snippets[] = {
      "return x;",

      "x = 10;",

      "'use strict'; x = 10;",

      "return typeof x;",
  };

  std::string actual = BuildActual(printer(), snippets,
                                   "var f;\n"
                                   "var x = 1;\n"
                                   "function f1() {\n"
                                   "  eval(\"function t() { ",

                                   " }; f = t; f();\");\n"
                                   "}\n"
                                   "f1();");

  CHECK(CompareTexts(actual, LoadGolden("LookupSlotInEval.golden")));
}

TEST_F(BytecodeGeneratorTest, DeleteLookupSlotInEval) {
  printer().set_wrap(false);
  printer().set_test_function_name("f");

  std::string snippets[] = {
      "delete x;",

      "return delete y;",

      "return delete z;",
  };

  std::string actual = BuildActual(printer(), snippets,
                                   "var f;\n"
                                   "var x = 1;\n"
                                   "z = 10;\n"
                                   "function f1() {\n"
                                   "  var y;\n"
                                   "  eval(\"function t() { ",

                                   " }; f = t; f();\");\n"
                                   "}\n"
                                   "f1();");

  CHECK(CompareTexts(actual, LoadGolden("DeleteLookupSlotInEval.golden")));
}

TEST_F(BytecodeGeneratorTest, WideRegisters) {
  // Prepare prologue that creates frame for lots of registers.
  std::ostringstream os;
  for (size_t i = 0; i < 157; ++i) {
    os << "var x" << i << " = 0;\n";
  }
  std::string prologue(os.str());

  std::string snippets[] = {
      "x0 = x127;\n"
      "return x0;\n",

      "x127 = x126;\n"
      "return x127;\n",

      "if (x2 > 3) { return x129; }\n"
      "return x128;\n",

      "var x0 = 0;\n"
      "if (x129 == 3) { var x129 = x0; }\n"
      "if (x2 > 3) { return x0; }\n"
      "return x129;\n",

      "var x0 = 0;\n"
      "var x1 = 0;\n"
      "for (x128 = 0; x128 < 64; x128++) {"
      "  x1 += x128;"
      "}"
      "return x128;\n",

      "var x0 = 1234;\n"
      "var x1 = 0;\n"
      "for (x128 in x0) {"
      "  x1 += x128;"
      "}"
      "return x1;\n",

      "x0 = %Add(x64, x63);\n"
      "x1 = %Add(x27, x143);\n"
      "%TheHole();\n"
      "return x1;\n",
  };

  CHECK(CompareTexts(BuildActual(printer(), snippets, prologue.c_str()),
                     LoadGolden("WideRegisters.golden")));
}

TEST_F(BytecodeGeneratorTest, ConstVariable) {
  std::string snippets[] = {
      "const x = 10;\n",

      "const x = 10; return x;\n",

      "const x = ( x = 20);\n",

      "const x = 10; x = 20;\n",
  };

  CHECK(CompareTexts(BuildActual(printer(), snippets),
                     LoadGolden("ConstVariable.golden")));
}

TEST_F(BytecodeGeneratorTest, LetVariable) {
  std::string snippets[] = {
      "let x = 10;\n",

      "let x = 10; return x;\n",

      "let x = (x = 20);\n",

      "let x = 10; x = 20;\n",
  };

  CHECK(CompareTexts(BuildActual(printer(), snippets),
                     LoadGolden("LetVariable.golden")));
}

TEST_F(BytecodeGeneratorTest, ConstVariableContextSlot) {
  // TODO(mythria): Add tests for initialization of this via super calls.
  // TODO(mythria): Add tests that walk the context chain.
  std::string snippets[] = {
      "const x = 10; function f1() {return x;}\n",

      "const x = 10; function f1() {return x;} return x;\n",

      "const x = (x = 20); function f1() {return x;}\n",

      "const x = 10; x = 20; function f1() {return x;}\n",
  };

  CHECK(CompareTexts(BuildActual(printer(), snippets),
                     LoadGolden("ConstVariableContextSlot.golden")));
}

TEST_F(BytecodeGeneratorTest, LetVariableContextSlot) {
  std::string snippets[] = {
      "let x = 10; function f1() {return x;}\n",

      "let x = 10; function f1() {return x;} return x;\n",

      "let x = (x = 20); function f1() {return x;}\n",

      "let x = 10; x = 20; function f1() {return x;}\n",
  };

  CHECK(CompareTexts(BuildActual(printer(), snippets),
                     LoadGolden("LetVariableContextSlot.golden")));
}

TEST_F(BytecodeGeneratorTest, WithStatement) {
  std::string snippets[] = {
      "with ({x:42}) { return x; }\n",
  };

  CHECK(CompareTexts(BuildActual(printer(), snippets),
                     LoadGolden("WithStatement.golden")));
}

TEST_F(BytecodeGeneratorTest, DoDebugger) {
  std::string snippets[] = {
      "debugger;\n",
  };

  CHECK(CompareTexts(BuildActual(printer(), snippets),
                     LoadGolden("DoDebugger.golden")));
}

TEST_F(BytecodeGeneratorTest, ClassDeclarations) {
  std::string snippets[] = {
      "class Person {\n"
      "  constructor(name) { this.name = name; }\n"
      "  speak() { console.log(this.name + ' is speaking.'); }\n"
      "}\n",

      "class person {\n"
      "  constructor(name) { this.name = name; }\n"
      "  speak() { console.log(this.name + ' is speaking.'); }\n"
      "}\n",

      "var n0 = 'a';\n"
      "var n1 = 'b';\n"
      "class N {\n"
      "  [n0]() { return n0; }\n"
      "  static [n1]() { return n1; }\n"
      "}\n",

      "var count = 0;\n"
      "class C { constructor() { count++; }}\n"
      "return new C();\n",

      "(class {})\n"
      "class E { static name () {}}\n",
  };

  CHECK(CompareTexts(BuildActual(printer(), snippets),
                     LoadGolden("ClassDeclarations.golden")));
}

TEST_F(BytecodeGeneratorTest, ClassAndSuperClass) {
  printer().set_wrap(false);
  printer().set_test_function_name("test");
  std::string snippets[] = {
      "var test;\n"
      "(function() {\n"
      "  class A {\n"
      "    method() { return 2; }\n"
      "  }\n"
      "  class B extends A {\n"
      "    method() { return super.method() + 1; }\n"
      "  }\n"
      "  test = new B().method;\n"
      "  test();\n"
      "})();\n",

      "var test;\n"
      "(function() {\n"
      "  class A {\n"
      "    get x() { return 1; }\n"
      "    set x(val) { return; }\n"
      "  }\n"
      "  class B extends A {\n"
      "    method() { super.x = 2; return super.x; }\n"
      "  }\n"
      "  test = new B().method;\n"
      "  test();\n"
      "})();\n",

      "var test;\n"
      "(function() {\n"
      "  class A {\n"
      "    constructor(x) { this.x_ = x; }\n"
      "  }\n"
      "  class B extends A {\n"
      "    constructor() { super(1); this.y_ = 2; }\n"
      "  }\n"
      "  test = new B().constructor;\n"
      "})();\n",

      "var test;\n"
      "(function() {\n"
      "  class A {\n"
      "    constructor() { this.x_ = 1; }\n"
      "  }\n"
      "  class B extends A {\n"
      "    constructor() { super(); this.y_ = 2; }\n"
      "  }\n"
      "  test = new B().constructor;\n"
      "})();\n",
  };

  CHECK(CompareTexts(BuildActual(printer(), snippets),
                     LoadGolden("ClassAndSuperClass.golden")));
}

TEST_F(BytecodeGeneratorTest, PublicClassFields) {
  std::string snippets[] = {
      "{\n"
      "  class A {\n"
      "    a;\n"
      "    ['b'];\n"
      "  }\n"
      "\n"
      "  class B {\n"
      "    a = 1;\n"
      "    ['b'] = this.a;\n"
      "  }\n"
      "  new A;\n"
      "  new B;\n"
      "}\n",

      "{\n"
      "  class A extends class {} {\n"
      "    a;\n"
      "    ['b'];\n"
      "  }\n"
      "\n"
      "  class B extends class {} {\n"
      "    a = 1;\n"
      "    ['b'] = this.a;\n"
      "    foo() { return 1; }\n"
      "    constructor() {\n"
      "      super();\n"
      "    }\n"
      "  }\n"
      "\n"
      "  class C extends B {\n"
      "    a = 1;\n"
      "    ['b'] = this.a;\n"
      "    constructor() {\n"
      "      (() => super())();\n"
      "    }\n"
      "  }\n"
      "\n"
      "  new A;\n"
      "  new B;\n"
      "  new C;\n"
      "}\n"};

  CHECK(CompareTexts(BuildActual(printer(), snippets),
                     LoadGolden("PublicClassFields.golden")));
}

TEST_F(BytecodeGeneratorTest, PrivateClassFields) {
  std::string snippets[] = {
      "{\n"
      "  class A {\n"
      "    #a;\n"
      "    constructor() {\n"
      "      this.#a = 1;\n"
      "    }\n"
      "  }\n"
      "\n"
      "  class B {\n"
      "    #a = 1;\n"
      "  }\n"
      "  new A;\n"
      "  new B;\n"
      "}\n",

      "{\n"
      "  class A extends class {} {\n"
      "    #a;\n"
      "    constructor() {\n"
      "      super();\n"
      "      this.#a = 1;\n"
      "    }\n"
      "  }\n"
      "\n"
      "  class B extends class {} {\n"
      "    #a = 1;\n"
      "    #b = this.#a;\n"
      "    foo() { return this.#a; }\n"
      "    bar(v) { this.#b = v; }\n"
      "    constructor() {\n"
      "      super();\n"
      "      this.foo();\n"
      "      this.bar(3);\n"
      "    }\n"
      "  }\n"
      "\n"
      "  class C extends B {\n"
      "    #a = 2;\n"
      "    constructor() {\n"
      "      (() => super())();\n"
      "    }\n"
      "  }\n"
      "\n"
      "  new A;\n"
      "  new B;\n"
      "  new C;\n"
      "};\n"};

  CHECK(CompareTexts(BuildActual(printer(), snippets),
                     LoadGolden("PrivateClassFields.golden")));
}

TEST_F(BytecodeGeneratorTest, PrivateClassFieldAccess) {
  printer().set_wrap(false);
  printer().set_test_function_name("test");

  std::string snippets[] = {
      "class A {\n"
      "  #a;\n"
      "  #b;\n"
      "  constructor() {\n"
      "    this.#a = this.#b;\n"
      "  }\n"
      "}\n"
      "\n"
      "var test = A;\n"
      "new test;\n",

      "class B {\n"
      "  #a;\n"
      "  #b;\n"
      "  constructor() {\n"
      "    this.#a = this.#b;\n"
      "  }\n"
      "  force(str) {\n"
      "    eval(str);\n"
      "  }\n"
      "}\n"
      "\n"
      "var test = B;\n"
      "new test;\n"};

  CHECK(CompareTexts(BuildActual(printer(), snippets),
                     LoadGolden("PrivateClassFieldAccess.golden")));
}

TEST_F(BytecodeGeneratorTest, PrivateMethodDeclaration) {
  std::string snippets[] = {
      "{\n"
      "  class A {\n"
      "    #a() { return 1; }\n"
      "  }\n"
      "}\n",

      "{\n"
      "  class D {\n"
      "    #d() { return 1; }\n"
      "  }\n"
      "  class E extends D {\n"
      "    #e() { return 2; }\n"
      "  }\n"
      "}\n",

      "{\n"
      "  class A { foo() {} }\n"
      "  class C extends A {\n"
      "    #m() { return super.foo; }\n"
      "  }\n"
      "}\n"};

  CHECK(CompareTexts(BuildActual(printer(), snippets),
                     LoadGolden("PrivateMethodDeclaration.golden")));
}

TEST_F(BytecodeGeneratorTest, PrivateMethodAccess) {
  printer().set_wrap(false);
  printer().set_test_function_name("test");

  std::string snippets[] = {
      "class A {\n"
      "  #a() { return 1; }\n"
      "  constructor() { return this.#a(); }\n"
      "}\n"
      "\n"
      "var test = A;\n"
      "new A;\n",

      "class B {\n"
      "  #b() { return 1; }\n"
      "  constructor() { this.#b = 1; }\n"
      "}\n"
      "\n"
      "var test = B;\n"
      "new test;\n",

      "class C {\n"
      "  #c() { return 1; }\n"
      "  constructor() { this.#c++; }\n"
      "}\n"
      "\n"
      "var test = C;\n"
      "new test;\n",

      "class D {\n"
      "  #d() { return 1; }\n"
      "  constructor() { (() => this)().#d(); }\n"
      "}\n"
      "\n"
      "var test = D;\n"
      "new test;\n",

      "var test;\n"
      "class F extends class {} {\n"
      "  #method() { }\n"
      "  constructor() {\n"
      "    (test = () => super())();\n"
      "    this.#method();\n"
      "  }\n"
      "};\n"
      "new F;\n",

      "var test;\n"
      "class G extends class {} {\n"
      "  #method() { }\n"
      "  constructor() {\n"
      "    test = () => super();\n"
      "    test();\n"
      "    this.#method();\n"
      "  }\n"
      "};\n"
      "new G();\n",

      "var test;\n"
      "class H extends class {} {\n"
      "  #method() { }\n"
      "  constructor(str) {\n"
      "    eval(str);\n"
      "    this.#method();\n"
      "  }\n"
      "};\n"
      "new test('test = () => super(); test()');\n"};

  CHECK(CompareTexts(BuildActual(printer(), snippets),
                     LoadGolden("PrivateMethodAccess.golden")));
}

TEST_F(BytecodeGeneratorTest, PrivateAccessorAccess) {
  printer().set_wrap(false);
  printer().set_test_function_name("test");

  std::string snippets[] = {
      "class A {\n"
      "  get #a() { return 1; }\n"
      "  set #a(val) { }\n"
      "\n"
      "  constructor() {\n"
      "    this.#a++;\n"
      "    this.#a = 1;\n"
      "    return this.#a;\n"
      "  }\n"
      "}\n"
      "var test = A;\n"
      "new test;\n",

      "class B {\n"
      "  get #b() { return 1; }\n"
      "  constructor() { this.#b++; }\n"
      "}\n"
      "var test = B;\n"
      "new test;\n",

      "class C {\n"
      "  set #c(val) { }\n"
      "  constructor() { this.#c++; }\n"
      "}\n"
      "var test = C;\n"
      "new test;\n",

      "class D {\n"
      "  get #d() { return 1; }\n"
      "  constructor() { this.#d = 1; }\n"
      "}\n"
      "var test = D;\n"
      "new test;\n",

      "class E {\n"
      "  set #e(val) { }\n"
      "  constructor() { this.#e; }\n"
      "}\n"
      "var test = E;\n"
      "new test;\n"};

  CHECK(CompareTexts(BuildActual(printer(), snippets),
                     LoadGolden("PrivateAccessorAccess.golden")));
}

TEST_F(BytecodeGeneratorTest, StaticPrivateMethodDeclaration) {
  std::string snippets[] = {
      "{\n"
      "  class A {\n"
      "    static #a() { return 1; }\n"
      "  }\n"
      "}\n",

      "{\n"
      "  class A {\n"
      "    static get #a() { return 1; }\n"
      "  }\n"
      "}\n",

      "{\n"
      "  class A {\n"
      "    static set #a(val) { }\n"
      "  }\n"
      "}\n",

      "{\n"
      "  class A {\n"
      "    static get #a() { return 1; }\n"
      "    static set #a(val) { }\n"
      "  }\n"
      "}\n",

      "{\n"
      "  class A {\n"
      "    static #a() { }\n"
      "    #b() { }\n"
      "  }\n"
      "}\n"};

  CHECK(CompareTexts(BuildActual(printer(), snippets),
                     LoadGolden("StaticPrivateMethodDeclaration.golden")));
}

TEST_F(BytecodeGeneratorTest, StaticPrivateMethodAccess) {
  printer().set_wrap(false);
  printer().set_test_function_name("test");

  std::string snippets[] = {
      "class A {\n"
      "  static #a() { return 1; }\n"
      "  static test() { return this.#a(); }\n"
      "}\n"
      "\n"
      "var test = A.test;\n"
      "test();\n",

      "class B {\n"
      "  static #b() { return 1; }\n"
      "  static test() { this.#b = 1; }\n"
      "}\n"
      "\n"
      "var test = B.test;\n"
      "test();\n",

      "class C {\n"
      "  static #c() { return 1; }\n"
      "  static test() { this.#c++; }\n"
      "}\n"
      "\
```