Response:
The user wants me to analyze a snippet of C++ code from the V8 JavaScript engine. This specific file, `v8/src/compiler/js-typed-lowering.cc`, seems related to optimizing JavaScript code by converting high-level JavaScript operations into lower-level, more efficient operations based on the types of the operands.

Here's a breakdown of the user's requests and how I'll address them:

1. **List the functionalities of the code:** I'll go through each `Reduce...` function and summarize what kind of JavaScript operation it handles and the optimizations it attempts.

2. **Check if it's a Torque file:** The user provides a condition for Torque files. I need to check if the filename ends with `.tq`.

3. **Illustrate with JavaScript if related:**  For each function that relates to a JavaScript feature, I will provide a simple JavaScript example.

4. **Provide code logic reasoning with input/output:** For some functions, especially those dealing with binary operations or comparisons, I can outline the logic with example input types and the resulting optimized output operation.

5. **Illustrate common programming errors:** If a reduction function is designed to handle specific type scenarios and might expose common pitfalls in JavaScript, I'll try to provide an example of such an error.

6. **Summarize the functionality of this part:** After analyzing each function in the snippet, I'll provide a concise summary of the overall purpose of this specific section of the code.

Let's start by analyzing each function individually.
这是 `v8/src/compiler/js-typed-lowering.cc` 源代码的一部分，其主要功能是：**基于类型信息优化 JavaScript 代码中的特定操作，将其转换为更底层的、更高效的表示形式。** 这种优化发生在 V8 的编译管道中，属于类型推断和优化的阶段。

**具体功能归纳：**

* **`ReduceJSAdd(Node* node)`:**
    * 功能：优化 JavaScript 的加法操作 (`+`)。
    * 逻辑：如果加法操作的其中一个输入是字符串，并且另一个输入类型明确，则会尝试将加法转换为字符串连接操作。如果两个输入都是原始类型，则将其转换为数字加法。
    * JavaScript 示例：
        ```javascript
        let a = "hello";
        let b = 123;
        let c = a + b; // 这里会触发字符串连接优化

        let x = 5;
        let y = 10;
        let z = x + y; // 这里会触发数字加法优化
        ```
    * 假设输入与输出：
        * 输入：`JSAdd(string_node, number_node)`
        * 输出：`Call(StringAddStub)` (调用字符串添加的 Stub)
        * 输入：`JSAdd(number_node_1, number_node_2)`
        * 输出：`NumberAdd` (简化后的数字加法操作)

* **`ReduceNumberBinop(Node* node)`:**
    * 功能：处理数字类型的二元运算（例如，减法、乘法等）。
    * 逻辑：如果二元运算符的两个输入都是原始类型，则将它们转换为数字，并将其转换为纯粹的数字运算操作。
    * JavaScript 示例：
        ```javascript
        let a = 5;
        let b = "10";
        let c = a - b; // "10" 会被转换为数字
        ```
    * 假设输入与输出：
        * 输入：`JSSubtract(number_node, string_node)`，且 `string_node` 的类型可以转换为数字
        * 输出：先将 `string_node` 转换为数字，然后输出 `NumberSubtract`

* **`ReduceInt32Binop(Node* node)`:**
    * 功能：处理可以安全地视为 32 位整数的二元运算。
    * 逻辑：如果两个输入都是原始类型，则将其转换为数字，然后转换为无符号 32 位整数，并将其转换为对应的纯粹的整数运算。
    * JavaScript 示例：
        ```javascript
        let a = 5;
        let b = 10;
        let c = a | b; // 位或操作
        ```
    * 假设输入与输出：
        * 输入：`JSBitwiseOr(number_node_1, number_node_2)`，且两者可以安全转换为 32 位整数
        * 输出：先将输入转换为无符号 32 位整数，然后输出 `Word32Or`

* **`ReduceUI32Shift(Node* node, Signedness signedness)`:**
    * 功能：处理无符号 32 位移位操作（左移、右移、无符号右移）。
    * 逻辑：如果两个输入都是原始类型，则将其转换为数字，然后根据 `signedness` 参数将其转换为有符号或无符号 32 位整数，并转换为相应的移位操作。
    * JavaScript 示例：
        ```javascript
        let a = 10;
        let b = 2;
        let c = a >>> b; // 无符号右移
        ```
    * 假设输入与输出：
        * 输入：`JSShiftRightLogical(number_node_1, number_node_2)`
        * 输出：先将输入转换为无符号 32 位整数，然后输出 `Word32ShiftRightLogical`

* **`ReduceJSComparison(Node* node)`:**
    * 功能：优化 JavaScript 的比较操作（`<`、`>`、`<=`、`>=`）。
    * 逻辑：
        * 如果比较的两个输入都是字符串，则将其转换为字符串比较操作。
        * 如果两个输入都是有符号或无符号 32 位整数，则转换为数字比较。
        * 如果可以确定其中一个输入不是字符串或接收器，且两个输入都是原始类型，则转换为数字比较。
        * 如果是字符串比较操作，则检查输入类型并转换为字符串比较。
    * JavaScript 示例：
        ```javascript
        let str1 = "apple";
        let str2 = "banana";
        let result1 = str1 < str2; // 字符串比较

        let num1 = 5;
        let num2 = 10;
        let result2 = num1 < num2; // 数字比较
        ```
    * 假设输入与输出：
        * 输入：`JSLessThan(string_node_1, string_node_2)`
        * 输出：`StringLessThan`
        * 输入：`JSGreaterThan(number_node_1, number_node_2)`
        * 输出：先交换输入，然后输出 `NumberLessThan`

* **`ReduceJSEqual(Node* node)`:**
    * 功能：优化 JavaScript 的相等性比较操作 (`==`)。
    * 逻辑：
        * 如果两个输入都是 `UniqueName`（例如 Symbol），则转换为引用相等性检查。
        * 如果是内部化字符串比较，则转换为引用相等性检查。
        * 如果两个输入都是字符串、布尔值或接收器，则转换为相应的相等性检查操作。
        * 如果其中一个输入是 `null` 或 `undefined`，则转换为检查另一个输入是否不可检测。
        * 如果两个输入都是有符号或无符号 32 位整数或数字，则转换为数字相等性检查。
        * 如果是接收器比较，则转换为引用相等性检查。
        * 如果是与 `null` 或 `undefined` 的比较，则生成相应的逻辑。
    * JavaScript 示例：
        ```javascript
        let sym1 = Symbol();
        let sym2 = Symbol();
        let result1 = sym1 == sym1; // 引用相等

        let str1 = "hello";
        let str2 = "hello";
        let result2 = str1 == str2; // 字符串相等

        let obj1 = {};
        let obj2 = {};
        let result3 = obj1 == obj2; // 引用相等

        let a = null;
        let b = undefined;
        let c = 0;
        let result4 = a == b;
        let result5 = a == c;
        ```
    * 假设输入与输出：
        * 输入：`JSEqual(unique_name_node_1, unique_name_node_2)`
        * 输出：`ReferenceEqual`
        * 输入：`JSEqual(string_node_1, string_node_2)`
        * 输出：`StringEqual`
        * 输入：`JSEqual(null_node, object_node)`
        * 输出：`ObjectIsUndetectable(object_node)`

* **`ReduceJSStrictEqual(Node* node)`:**
    * 功能：优化 JavaScript 的严格相等性比较操作 (`===`)。
    * 逻辑：
        * 如果类型是单例，则交由常量折叠处理。
        * 如果比较的是同一个节点，并且不是 `NaN`，则结果为 `true`。
        * 如果两个输入都是 `Unique` 类型（例如，不会有其他相同实例的值），则进行引用相等性比较。
        * 如果其中一个输入是可进行指针比较的类型，则进行引用相等性比较。
        * 对于内部化字符串、普通字符串，进行相应的相等性比较。
        * 对于数字类型，进行数字相等性比较。
        * 对于接收器，只需要知道其中一个输入是接收器即可进行引用相等性比较。
        * 对于 Symbol，只需要知道其中一个输入是 Symbol 即可进行引用相等性比较。
    * JavaScript 示例：
        ```javascript
        let a = 5;
        let b = "5";
        let result1 = a === b; // false

        let obj1 = {};
        let obj2 = obj1;
        let result2 = obj1 === obj2; // true

        let sym1 = Symbol();
        let sym2 = Symbol();
        let result3 = sym1 === sym1; // true
        ```
    * 假设输入与输出：
        * 输入：`JSStrictEqual(same_node, other_node)`，其中 `other_node` 不是 `NaN`
        * 输出：`BooleanNot(ObjectIsNaN(same_node))`
        * 输入：`JSStrictEqual(unique_node_1, unique_node_2)`
        * 输出：`ReferenceEqual`
        * 输入：`JSStrictEqual(string_node_1, string_node_2)`
        * 输出：`StringEqual`

* **`ReduceJSToName(Node* node)`:**
    * 功能：优化将值转换为名称的操作。
    * 逻辑：如果输入已经是名称类型，则直接返回输入。
    * JavaScript 示例：
        ```javascript
        let sym = Symbol();
        let name = Symbol.toPrimitive;
        let str = "hello";

        String(sym); // JSToName(sym) 会被优化为直接使用 sym
        String(name); // JSToName(name) 会被优化为直接使用 name
        String(str); // 需要转换为字符串
        ```
    * 假设输入与输出：
        * 输入：`JSToName(name_node)`，其中 `name_node` 的类型是 Name
        * 输出：`name_node`

* **`ReduceJSToLength(Node* node)`:**
    * 功能：优化将值转换为长度的操作（通常用于访问数组或字符串的 `length` 属性）。
    * 逻辑：如果输入已经是整数或负零，则根据其范围进行调整，确保结果在安全整数范围内。
    * JavaScript 示例：
        ```javascript
        let arr = [1, 2, 3];
        let str = "hello";
        let len1 = arr.length; // JSToLength(arr)
        let len2 = str.length; // JSToLength(str)

        let hugeNumber = 9007199254740991;
        String(hugeNumber).length; // 16
        ```
    * 假设输入与输出：
        * 输入：`JSToLength(integer_node)`，其中 `integer_node` 的类型是整数
        * 输出：根据整数的值，可能输出 `ZeroConstant`，`ConstantNoHole(kMaxSafeInteger)`，或者 `NumberMax`/`NumberMin` 操作。

* **`ReduceJSToNumberInput(Node* input)`:**
    * 功能：辅助 `ReduceJSToNumber`，尝试对 `JSToNumber` 操作的输入进行常量折叠。
    * 逻辑：
        * 如果输入是字符串常量，则尝试将其解析为数字。
        * 如果输入是堆常量，则尝试将其转换为数字。
        * 如果输入已经是数字、`undefined` 或 `null`，则返回相应的常量。
    * JavaScript 示例：
        ```javascript
        Number("123"); // 常量折叠为 123
        Number(undefined); // 常量折叠为 NaN
        Number(null); // 常量折叠为 0
        ```
    * 假设输入与输出：
        * 输入：`JSToNumber("123")`
        * 输出：`ConstantNoHole(123)`
        * 输入：`JSToNumber(undefined)`
        * 输出：`NaNConstant`

* **`ReduceJSToNumber(Node* node)`:**
    * 功能：优化 JavaScript 的 `Number()` 转换操作。
    * 逻辑：
        * 首先尝试使用 `ReduceJSToNumberInput` 进行常量折叠。
        * 如果输入是原始类型，则将其转换为 `PlainPrimitiveToNumber` 操作。
    * JavaScript 示例：
        ```javascript
        Number("123");
        Number(true);
        Number(null);
        ```
    * 假设输入与输出：
        * 输入：`JSToNumber(string_node)`，无法常量折叠
        * 输出：`PlainPrimitiveToNumber(string_node)`

* **`ReduceJSToBigInt(Node* node)`:**
    * 功能：优化 JavaScript 的 `BigInt()` 转换操作。
    * 逻辑：如果输入已经是 BigInt 类型，则直接返回输入。
    * JavaScript 示例：
        ```javascript
        BigInt(10);
        BigInt(9007199254740991n);
        ```
    * 假设输入与输出：
        * 输入：`JSToBigInt(bigint_node)`，其中 `bigint_node` 的类型是 BigInt
        * 输出：`bigint_node`

* **`ReduceJSToBigIntConvertNumber(Node* node)`:**
    * 功能：优化将数字转换为 BigInt 的操作（例如，使用 `BigInt()` 转换整数）。
    * 逻辑：
        * 如果输入已经是 BigInt 类型，则直接返回输入。
        * 如果输入是 32 位有符号或无符号整数，则将其转换为 `Integral32OrMinusZeroToBigInt` 操作。
    * JavaScript 示例：
        ```javascript
        BigInt(10);
        ```
    * 假设输入与输出：
        * 输入：`JSToBigIntConvertNumber(int32_node)`，其中 `int32_node` 的类型是 Signed32 或 Unsigned32
        * 输出：`Integral32OrMinusZeroToBigInt(int32_node)`

* **`ReduceJSToNumeric(Node* node)`:**
    * 功能：优化将值转换为数字或 BigInt 的操作。
    * 逻辑：如果输入是非 BigInt 的原始类型，则将其转换为 `ToNumber` 操作。
    * JavaScript 示例：
        ```javascript
        let a = "10";
        let b = 10n;
        let num = +a; // JSToNumeric(a) -> JSToNumber(a)
        let big = +b; // JSToNumeric(b) - 不会进行 ToNumber 转换
        ```
    * 假设输入与输出：
        * 输入：`JSToNumeric(string_node)`
        * 输出：`JSToNumber(string_node)`

* **`ReduceJSToStringInput(Node* input)`:**
    * 功能：辅助 `ReduceJSToString`，尝试对 `JSToString` 操作的输入进行优化。
    * 逻辑：
        * 如果输入已经是 `JSToString` 操作，则直接返回输入（避免重复转换）。
        * 如果输入已经是字符串，则直接返回输入。
        * 如果输入是布尔值、`undefined`、`null` 或 `NaN`，则返回相应的字符串常量。
        * 如果输入是数字，则转换为 `NumberToString` 操作。
    * JavaScript 示例：
        ```javascript
        String(true); // 常量折叠为 "true"
        String(undefined); // 常量折叠为 "undefined"
        String(123); // 转换为 NumberToString 操作
        ```
    * 假设输入与输出：
        * 输入：`JSToString(true)`
        * 输出：`HeapConstantNoHole("true")`
        * 输入：`JSToString(number_node)`
        * 输出：`NumberToString(number_node)`

* **`ReduceJSToString(Node* node)`:**
    * 功能：优化 JavaScript 的 `String()` 转换操作。
    * 逻辑：先调用 `ReduceJSToStringInput` 尝试优化输入。
    * JavaScript 示例：
        ```javascript
        String(123);
        String(true);
        ```
    * 假设输入与输出：依赖于 `ReduceJSToStringInput` 的结果。

* **`ReduceJSToObject(Node* node)`:**
    * 功能：优化 JavaScript 的 `Object()` 转换操作。
    * 逻辑：
        * 如果输入已经是接收器类型，则直接返回输入。
        * 否则，检查输入是否是原始值，如果是，则调用 `ToObjectStub` 将其转换为对象。
    * JavaScript 示例：
        ```javascript
        Object({}); // 返回输入对象
        Object(5); // 转换为 Number 对象
        Object("hello"); // 转换为 String 对象
        ```
    * 假设输入与输出：
        * 输入：`JSToObject(receiver_node)`，其中 `receiver_node` 的类型是 Receiver
        * 输出：`receiver_node`
        * 输入：`JSToObject(primitive_node)`，其中 `primitive_node` 是原始类型
        * 输出：`Call(ToObjectStub)`

* **`ReduceJSLoadNamed(Node* node)`:**
    * 功能：优化访问对象属性的操作。
    * 逻辑：对于访问字符串的 `length` 属性，直接生成 `StringLength` 操作。
    * JavaScript 示例：
        ```javascript
        let str = "hello";
        let len = str.length; // 优化为 StringLength 操作
        ```
    * 假设输入与输出：
        * 输入：`JSLoadNamed(string_node, "length")`
        * 输出：`StringLength(string_node)`

* **`ReduceJSHasInPrototypeChain(Node* node)`:**
    * 功能：优化 `in` 运算符在原型链上的查找操作。
    * 逻辑：
        * 如果被查找的值不是接收器，则结果为 `false`。
        * 通过循环遍历原型链，比较原型对象是否与目标原型相同。
        * 对于特殊接收器（例如，Proxy），调用运行时函数 `%HasInPrototypeChain`。
    * JavaScript 示例：
        ```javascript
        function A() {}
        function B() {}
        B.prototype = new A();
        let b = new B();
        let result = b instanceof A; // 内部会使用原型链查找

        let result2 = "toString" in b;
        ```
    * 假设输入与输出：逻辑比较复杂，涉及到循环和条件分支，最终输出 `TrueConstant` 或 `FalseConstant`，或者调用运行时函数。

* **`ReduceJSOrdinaryHasInstance(Node* node)`:**
    * 功能：优化 `instanceof` 运算符的默认行为。
    * 逻辑：
        * 如果构造函数不可调用，则结果为 `false`。
        * 如果构造函数不是 `JSBoundFunction` 且对象不是接收器，则结果为 `false`。
    * JavaScript 示例：
        ```javascript
        function A() {}
        let a = new A();
        a instanceof A; // true

        5 instanceof Number; // false (5 不是对象)
        ```
    * 假设输入与输出：根据构造函数和对象的类型，可能输出 `TrueConstant` 或 `FalseConstant`。

* **`ReduceJSHasContextExtension(Node* node)`:**
    * 功能：优化检查作用域链上是否存在 `with` 语句引入的上下文扩展。
    * 逻辑：向上遍历作用域链，检查指定深度的上下文是否具有扩展槽。
    * JavaScript 示例：
        ```javascript
        function foo() {
          let obj = { a: 1 };
          with (obj) {
            console.log(a); // 这里会引入上下文扩展
          }
        }
        ```
    * 假设输入与输出：根据作用域链的结构，输出表示是否存在上下文扩展的布尔值。

* **`ReduceJSLoadContext(Node* node)`:**
    * 功能：优化从作用域链中加载变量的操作。
    * 逻辑：根据作用域链的深度，向上遍历作用域链，最终加载目标上下文槽中的值。
    * JavaScript 示例：
        ```javascript
        let globalVar = 10;
        function foo() {
          let localVar = 20;
          function bar() {
            console.log(globalVar + localVar); // 加载 globalVar 和 localVar
          }
          bar();
        }
        foo();
        ```
    * 假设输入与输出：输入是上下文和加载槽的索引，输出是加载的值。

* **`ReduceJSLoadScriptContext(Node* node)`:**
    * 功能：优化加载脚本上下文中的变量。
    * 逻辑：类似于 `ReduceJSLoadContext`，但专门用于加载脚本级别的上下文变量。

**关于文件类型：**

`v8/src/compiler/js-typed-lowering.cc` 以 `.cc` 结尾，因此它是 **C++ 源代码**，而不是 Torque 源代码。 Torque 源代码文件通常以 `.tq` 结尾。

**常见的编程错误：**

这些优化器尝试处理 JavaScript 中常见的类型转换和比较，但也可能暴露出一些常见的编程错误，例如：

* **不明确的类型假设：**  例如，在进行加法操作时，如果没有明确知道操作数的类型，可能会导致意想不到的结果（字符串连接或数字相加）。
    ```javascript
    let a = "5";
    let b = 10;
    let c = a + b; // 结果是字符串 "510"，而不是数字 15
    ```
* **错误的相等性比较：** 使用 `==` 进行比较时，可能会发生隐式类型转换，导致与预期不符的结果。
    ```javascript
    console.log(5 == "5");   // true (字符串 "5" 被转换为数字 5)
    console.log(0 == false); // true (false 被转换为数字 0)
    console.log(null == undefined); // true
    ```
    建议在需要严格比较时使用 `===`。
* **对 `null` 或 `undefined` 的不当处理：**  在进行属性访问或方法调用时，如果没有检查对象是否为 `null` 或 `undefined`，可能会导致运行时错误。
    ```javascript
    let obj = null;
    // obj.toString(); // TypeError: Cannot read properties of null (reading 'toString')
    ```

**此部分功能归纳：**

总而言之，这段代码片段是 V8 编译器中类型推断和优化的核心部分，它针对 JavaScript 中常见的操作（如加法、比较、类型转换、属性访问等）进行基于类型的优化，将其转换为更底层的、更高效的中间表示形式，以便后续的编译和执行。这有助于提高 JavaScript 代码的执行效率。

Prompt: 
```
这是目录为v8/src/compiler/js-typed-lowering.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/js-typed-lowering.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共4部分，请归纳一下它的功能

"""
CodeFactory::StringAdd(isolate(), flags);
    auto call_descriptor = Linkage::GetStubCallDescriptor(
        graph()->zone(), callable.descriptor(),
        callable.descriptor().GetStackParameterCount(),
        CallDescriptor::kNeedsFrameState, properties);
    DCHECK_EQ(1, OperatorProperties::GetFrameStateInputCount(node->op()));
    node->RemoveInput(JSAddNode::FeedbackVectorIndex());
    node->InsertInput(graph()->zone(), 0,
                      jsgraph()->HeapConstantNoHole(callable.code()));
    NodeProperties::ChangeOp(node, common()->Call(call_descriptor));
    return Changed(node);
  }
  return NoChange();
}

Reduction JSTypedLowering::ReduceNumberBinop(Node* node) {
  JSBinopReduction r(this, node);
  if (r.BothInputsAre(Type::PlainPrimitive())) {
    r.ConvertInputsToNumber();
    return r.ChangeToPureOperator(r.NumberOp(), Type::Number());
  }
  return NoChange();
}

Reduction JSTypedLowering::ReduceInt32Binop(Node* node) {
  JSBinopReduction r(this, node);
  if (r.BothInputsAre(Type::PlainPrimitive())) {
    r.ConvertInputsToNumber();
    r.ConvertInputsToUI32(kSigned, kSigned);
    return r.ChangeToPureOperator(r.NumberOp(), Type::Signed32());
  }
  return NoChange();
}

Reduction JSTypedLowering::ReduceUI32Shift(Node* node, Signedness signedness) {
  JSBinopReduction r(this, node);
  if (r.BothInputsAre(Type::PlainPrimitive())) {
    r.ConvertInputsToNumber();
    r.ConvertInputsToUI32(signedness, kUnsigned);
    return r.ChangeToPureOperator(r.NumberOp(), signedness == kUnsigned
                                                    ? Type::Unsigned32()
                                                    : Type::Signed32());
  }
  return NoChange();
}

Reduction JSTypedLowering::ReduceJSComparison(Node* node) {
  JSBinopReduction r(this, node);
  if (r.BothInputsAre(Type::String())) {
    // If both inputs are definitely strings, perform a string comparison.
    const Operator* stringOp;
    switch (node->opcode()) {
      case IrOpcode::kJSLessThan:
        stringOp = simplified()->StringLessThan();
        break;
      case IrOpcode::kJSGreaterThan:
        stringOp = simplified()->StringLessThan();
        r.SwapInputs();  // a > b => b < a
        break;
      case IrOpcode::kJSLessThanOrEqual:
        stringOp = simplified()->StringLessThanOrEqual();
        break;
      case IrOpcode::kJSGreaterThanOrEqual:
        stringOp = simplified()->StringLessThanOrEqual();
        r.SwapInputs();  // a >= b => b <= a
        break;
      default:
        return NoChange();
    }
    r.ChangeToPureOperator(stringOp);
    return Changed(node);
  }

  const Operator* less_than;
  const Operator* less_than_or_equal;
  if (r.BothInputsAre(Type::Signed32()) ||
      r.BothInputsAre(Type::Unsigned32())) {
    less_than = simplified()->NumberLessThan();
    less_than_or_equal = simplified()->NumberLessThanOrEqual();
  } else if (r.OneInputCannotBe(Type::StringOrReceiver()) &&
             r.BothInputsAre(Type::PlainPrimitive())) {
    r.ConvertInputsToNumber();
    less_than = simplified()->NumberLessThan();
    less_than_or_equal = simplified()->NumberLessThanOrEqual();
  } else if (r.IsStringCompareOperation()) {
    r.CheckInputsToString();
    less_than = simplified()->StringLessThan();
    less_than_or_equal = simplified()->StringLessThanOrEqual();
  } else {
    return NoChange();
  }
  const Operator* comparison;
  switch (node->opcode()) {
    case IrOpcode::kJSLessThan:
      comparison = less_than;
      break;
    case IrOpcode::kJSGreaterThan:
      comparison = less_than;
      r.SwapInputs();  // a > b => b < a
      break;
    case IrOpcode::kJSLessThanOrEqual:
      comparison = less_than_or_equal;
      break;
    case IrOpcode::kJSGreaterThanOrEqual:
      comparison = less_than_or_equal;
      r.SwapInputs();  // a >= b => b <= a
      break;
    default:
      return NoChange();
  }
  return r.ChangeToPureOperator(comparison);
}

Reduction JSTypedLowering::ReduceJSEqual(Node* node) {
  JSBinopReduction r(this, node);

  if (r.BothInputsAre(Type::UniqueName())) {
    return r.ChangeToPureOperator(simplified()->ReferenceEqual());
  }
  if (r.IsInternalizedStringCompareOperation()) {
    r.CheckInputsToInternalizedString();
    return r.ChangeToPureOperator(simplified()->ReferenceEqual());
  }
  if (r.BothInputsAre(Type::String())) {
    return r.ChangeToPureOperator(simplified()->StringEqual());
  }
  if (r.BothInputsAre(Type::Boolean())) {
    return r.ChangeToPureOperator(simplified()->ReferenceEqual());
  }
  if (r.BothInputsAre(Type::Receiver())) {
    return r.ChangeToPureOperator(simplified()->ReferenceEqual());
  }
  if (r.OneInputIs(Type::NullOrUndefined())) {
    RelaxEffectsAndControls(node);
    node->RemoveInput(r.LeftInputIs(Type::NullOrUndefined()) ? 0 : 1);
    node->TrimInputCount(1);
    NodeProperties::ChangeOp(node, simplified()->ObjectIsUndetectable());
    return Changed(node);
  }

  if (r.BothInputsAre(Type::Signed32()) ||
      r.BothInputsAre(Type::Unsigned32())) {
    return r.ChangeToPureOperator(simplified()->NumberEqual());
  } else if (r.BothInputsAre(Type::Number())) {
    return r.ChangeToPureOperator(simplified()->NumberEqual());
  } else if (r.IsReceiverCompareOperation()) {
    r.CheckInputsToReceiver();
    return r.ChangeToPureOperator(simplified()->ReferenceEqual());
  } else if (r.IsReceiverOrNullOrUndefinedCompareOperation()) {
    // Check that both inputs are Receiver, Null or Undefined.
    r.CheckInputsToReceiverOrNullOrUndefined();

    // If one side is known to be a detectable receiver now, we
    // can simply perform reference equality here, since this
    // known detectable receiver is going to only match itself.
    if (r.OneInputIs(Type::DetectableReceiver())) {
      return r.ChangeToPureOperator(simplified()->ReferenceEqual());
    }

    // Known that both sides are Receiver, Null or Undefined, the
    // abstract equality operation can be performed like this:
    //
    // if left == undefined || left == null
    //    then ObjectIsUndetectable(right)
    // else if right == undefined || right == null
    //    then ObjectIsUndetectable(left)
    // else ReferenceEqual(left, right)
#define __ gasm.
    JSGraphAssembler gasm(broker(), jsgraph(), jsgraph()->zone(),
                          BranchSemantics::kJS);
    gasm.InitializeEffectControl(r.effect(), r.control());

    auto lhs = TNode<Object>::UncheckedCast(r.left());
    auto rhs = TNode<Object>::UncheckedCast(r.right());

    auto done = __ MakeLabel(MachineRepresentation::kTagged);
    auto check_undetectable = __ MakeLabel(MachineRepresentation::kTagged);

    __ GotoIf(__ ReferenceEqual(lhs, __ UndefinedConstant()),
              &check_undetectable, rhs);
    __ GotoIf(__ ReferenceEqual(lhs, __ NullConstant()), &check_undetectable,
              rhs);
    __ GotoIf(__ ReferenceEqual(rhs, __ UndefinedConstant()),
              &check_undetectable, lhs);
    __ GotoIf(__ ReferenceEqual(rhs, __ NullConstant()), &check_undetectable,
              lhs);
    __ Goto(&done, __ ReferenceEqual(lhs, rhs));

    __ Bind(&check_undetectable);
    __ Goto(&done,
            __ ObjectIsUndetectable(check_undetectable.PhiAt<Object>(0)));

    __ Bind(&done);
    Node* value = done.PhiAt(0);
    ReplaceWithValue(node, value, gasm.effect(), gasm.control());
    return Replace(value);
#undef __
  } else if (r.IsStringCompareOperation()) {
    r.CheckInputsToString();
    return r.ChangeToPureOperator(simplified()->StringEqual());
  } else if (r.IsSymbolCompareOperation()) {
    r.CheckInputsToSymbol();
    return r.ChangeToPureOperator(simplified()->ReferenceEqual());
  }
  return NoChange();
}

Reduction JSTypedLowering::ReduceJSStrictEqual(Node* node) {
  JSBinopReduction r(this, node);
  if (r.type().IsSingleton()) {
    // Let ConstantFoldingReducer handle this.
    return NoChange();
  }
  if (r.left() == r.right()) {
    // x === x is always true if x != NaN
    Node* replacement = graph()->NewNode(
        simplified()->BooleanNot(),
        graph()->NewNode(simplified()->ObjectIsNaN(), r.left()));
    DCHECK(NodeProperties::GetType(replacement).Is(r.type()));
    ReplaceWithValue(node, replacement);
    return Replace(replacement);
  }

  if (r.BothInputsAre(Type::Unique())) {
    return r.ChangeToPureOperator(simplified()->ReferenceEqual());
  }
  if (r.OneInputIs(pointer_comparable_type_)) {
    return r.ChangeToPureOperator(simplified()->ReferenceEqual());
  }
  if (r.IsInternalizedStringCompareOperation()) {
    r.CheckInputsToInternalizedString();
    return r.ChangeToPureOperator(simplified()->ReferenceEqual());
  }
  if (r.BothInputsAre(Type::String())) {
    return r.ChangeToPureOperator(simplified()->StringEqual());
  }

  NumberOperationHint hint;
  BigIntOperationHint hint_bigint;
  if (r.BothInputsAre(Type::Signed32()) ||
      r.BothInputsAre(Type::Unsigned32())) {
    return r.ChangeToPureOperator(simplified()->NumberEqual());
  } else if (r.GetCompareNumberOperationHint(&hint) &&
             hint != NumberOperationHint::kNumberOrOddball &&
             hint != NumberOperationHint::kNumberOrBoolean) {
    // SpeculativeNumberEqual performs implicit conversion of oddballs to
    // numbers, so me must not generate it for strict equality with respective
    // hint.
    DCHECK(hint == NumberOperationHint::kNumber ||
           hint == NumberOperationHint::kSignedSmall);
    return r.ChangeToSpeculativeOperator(
        simplified()->SpeculativeNumberEqual(hint), Type::Boolean());
  } else if (r.BothInputsAre(Type::Number())) {
    return r.ChangeToPureOperator(simplified()->NumberEqual());
  } else if (r.GetCompareBigIntOperationHint(&hint_bigint)) {
    DCHECK(hint_bigint == BigIntOperationHint::kBigInt ||
           hint_bigint == BigIntOperationHint::kBigInt64);
    return r.ChangeToSpeculativeOperator(
        simplified()->SpeculativeBigIntEqual(hint_bigint), Type::Boolean());
  } else if (r.IsReceiverCompareOperation()) {
    // For strict equality, it's enough to know that one input is a Receiver,
    // as a strict equality comparison with a Receiver can only yield true if
    // both sides refer to the same Receiver.
    r.CheckLeftInputToReceiver();
    return r.ChangeToPureOperator(simplified()->ReferenceEqual());
  } else if (r.IsReceiverOrNullOrUndefinedCompareOperation()) {
    // For strict equality, it's enough to know that one input is a Receiver,
    // Null or Undefined, as a strict equality comparison with a Receiver,
    // Null or Undefined can only yield true if both sides refer to the same
    // instance.
    r.CheckLeftInputToReceiverOrNullOrUndefined();
    return r.ChangeToPureOperator(simplified()->ReferenceEqual());
  } else if (r.IsStringCompareOperation()) {
    r.CheckInputsToString();
    return r.ChangeToPureOperator(simplified()->StringEqual());
  } else if (r.IsSymbolCompareOperation()) {
    // For strict equality, it's enough to know that one input is a Symbol,
    // as a strict equality comparison with a Symbol can only yield true if
    // both sides refer to the same Symbol.
    r.CheckLeftInputToSymbol();
    return r.ChangeToPureOperator(simplified()->ReferenceEqual());
  }
  return NoChange();
}

Reduction JSTypedLowering::ReduceJSToName(Node* node) {
  Node* const input = NodeProperties::GetValueInput(node, 0);
  Type const input_type = NodeProperties::GetType(input);
  if (input_type.Is(Type::Name())) {
    // JSToName(x:name) => x
    ReplaceWithValue(node, input);
    return Replace(input);
  }
  return NoChange();
}

Reduction JSTypedLowering::ReduceJSToLength(Node* node) {
  Node* input = NodeProperties::GetValueInput(node, 0);
  Type input_type = NodeProperties::GetType(input);
  if (input_type.Is(type_cache_->kIntegerOrMinusZero)) {
    if (input_type.IsNone() || input_type.Max() <= 0.0) {
      input = jsgraph()->ZeroConstant();
    } else if (input_type.Min() >= kMaxSafeInteger) {
      input = jsgraph()->ConstantNoHole(kMaxSafeInteger);
    } else {
      if (input_type.Min() <= 0.0) {
        input = graph()->NewNode(simplified()->NumberMax(),
                                 jsgraph()->ZeroConstant(), input);
      }
      if (input_type.Max() > kMaxSafeInteger) {
        input =
            graph()->NewNode(simplified()->NumberMin(),
                             jsgraph()->ConstantNoHole(kMaxSafeInteger), input);
      }
    }
    ReplaceWithValue(node, input);
    return Replace(input);
  }
  return NoChange();
}

Reduction JSTypedLowering::ReduceJSToNumberInput(Node* input) {
  // Try constant-folding of JSToNumber with constant inputs.
  Type input_type = NodeProperties::GetType(input);

  if (input_type.Is(Type::String())) {
    HeapObjectMatcher m(input);
    if (m.HasResolvedValue() && m.Ref(broker()).IsString()) {
      StringRef input_value = m.Ref(broker()).AsString();
      std::optional<double> number = input_value.ToNumber(broker());
      if (!number.has_value()) return NoChange();
      return Replace(jsgraph()->ConstantNoHole(number.value()));
    }
  }
  if (input_type.IsHeapConstant()) {
    HeapObjectRef input_value = input_type.AsHeapConstant()->Ref();
    double value;
    if (input_value.OddballToNumber(broker()).To(&value)) {
      return Replace(jsgraph()->ConstantNoHole(value));
    }
  }
  if (input_type.Is(Type::Number())) {
    // JSToNumber(x:number) => x
    return Changed(input);
  }
  if (input_type.Is(Type::Undefined())) {
    // JSToNumber(undefined) => #NaN
    return Replace(jsgraph()->NaNConstant());
  }
  if (input_type.Is(Type::Null())) {
    // JSToNumber(null) => #0
    return Replace(jsgraph()->ZeroConstant());
  }
  return NoChange();
}

Reduction JSTypedLowering::ReduceJSToNumber(Node* node) {
  // Try to reduce the input first.
  Node* const input = node->InputAt(0);
  Reduction reduction = ReduceJSToNumberInput(input);
  if (reduction.Changed()) {
    ReplaceWithValue(node, reduction.replacement());
    return reduction;
  }
  Type const input_type = NodeProperties::GetType(input);
  if (input_type.Is(Type::PlainPrimitive())) {
    RelaxEffectsAndControls(node);
    node->TrimInputCount(1);
    // For a PlainPrimitive, ToNumeric is the same as ToNumber.
    Type node_type = NodeProperties::GetType(node);
    NodeProperties::SetType(
        node, Type::Intersect(node_type, Type::Number(), graph()->zone()));
    NodeProperties::ChangeOp(node, simplified()->PlainPrimitiveToNumber());
    return Changed(node);
  }
  return NoChange();
}

Reduction JSTypedLowering::ReduceJSToBigInt(Node* node) {
  // TODO(panq): Reduce constant inputs.
  Node* const input = node->InputAt(0);
  Type const input_type = NodeProperties::GetType(input);
  if (input_type.Is(Type::BigInt())) {
    ReplaceWithValue(node, input);
    return Changed(input);
  }
  return NoChange();
}

Reduction JSTypedLowering::ReduceJSToBigIntConvertNumber(Node* node) {
  // TODO(panq): Reduce constant inputs.
  Node* const input = node->InputAt(0);
  Type const input_type = NodeProperties::GetType(input);
  if (input_type.Is(Type::BigInt())) {
    ReplaceWithValue(node, input);
    return Changed(input);
  } else if (input_type.Is(Type::Signed32OrMinusZero()) ||
             input_type.Is(Type::Unsigned32OrMinusZero())) {
    RelaxEffectsAndControls(node);
    node->TrimInputCount(1);
    Type node_type = NodeProperties::GetType(node);
    NodeProperties::SetType(
        node,
        Type::Intersect(node_type, Type::SignedBigInt64(), graph()->zone()));
    NodeProperties::ChangeOp(node,
                             simplified()->Integral32OrMinusZeroToBigInt());
    return Changed(node);
  }
  return NoChange();
}

Reduction JSTypedLowering::ReduceJSToNumeric(Node* node) {
  Node* const input = NodeProperties::GetValueInput(node, 0);
  Type const input_type = NodeProperties::GetType(input);
  if (input_type.Is(Type::NonBigIntPrimitive())) {
    // ToNumeric(x:primitive\bigint) => ToNumber(x)
    NodeProperties::ChangeOp(node, javascript()->ToNumber());
    Type node_type = NodeProperties::GetType(node);
    NodeProperties::SetType(
        node, Type::Intersect(node_type, Type::Number(), graph()->zone()));
    return Changed(node).FollowedBy(ReduceJSToNumber(node));
  }
  return NoChange();
}

Reduction JSTypedLowering::ReduceJSToStringInput(Node* input) {
  if (input->opcode() == IrOpcode::kJSToString) {
    // Recursively try to reduce the input first.
    Reduction result = ReduceJSToString(input);
    if (result.Changed()) return result;
    return Changed(input);  // JSToString(JSToString(x)) => JSToString(x)
  }
  Type input_type = NodeProperties::GetType(input);
  if (input_type.Is(Type::String())) {
    return Changed(input);  // JSToString(x:string) => x
  }
  if (input_type.Is(Type::Boolean())) {
    return Replace(graph()->NewNode(
        common()->Select(MachineRepresentation::kTagged), input,
        jsgraph()->HeapConstantNoHole(factory()->true_string()),
        jsgraph()->HeapConstantNoHole(factory()->false_string())));
  }
  if (input_type.Is(Type::Undefined())) {
    return Replace(
        jsgraph()->HeapConstantNoHole(factory()->undefined_string()));
  }
  if (input_type.Is(Type::Null())) {
    return Replace(jsgraph()->HeapConstantNoHole(factory()->null_string()));
  }
  if (input_type.Is(Type::NaN())) {
    return Replace(jsgraph()->HeapConstantNoHole(factory()->NaN_string()));
  }
  if (input_type.Is(Type::Number())) {
    return Replace(graph()->NewNode(simplified()->NumberToString(), input));
  }
  return NoChange();
}

Reduction JSTypedLowering::ReduceJSToString(Node* node) {
  DCHECK_EQ(IrOpcode::kJSToString, node->opcode());
  // Try to reduce the input first.
  Node* const input = node->InputAt(0);
  Reduction reduction = ReduceJSToStringInput(input);
  if (reduction.Changed()) {
    ReplaceWithValue(node, reduction.replacement());
    return reduction;
  }
  return NoChange();
}

Reduction JSTypedLowering::ReduceJSToObject(Node* node) {
  DCHECK_EQ(IrOpcode::kJSToObject, node->opcode());
  Node* receiver = NodeProperties::GetValueInput(node, 0);
  Type receiver_type = NodeProperties::GetType(receiver);
  Node* context = NodeProperties::GetContextInput(node);
  Node* frame_state = NodeProperties::GetFrameStateInput(node);
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);
  if (receiver_type.Is(Type::Receiver())) {
    ReplaceWithValue(node, receiver, effect, control);
    return Replace(receiver);
  }

  // Check whether {receiver} is a spec object.
  Node* check = graph()->NewNode(simplified()->ObjectIsReceiver(), receiver);
  Node* branch =
      graph()->NewNode(common()->Branch(BranchHint::kTrue), check, control);

  Node* if_true = graph()->NewNode(common()->IfTrue(), branch);
  Node* etrue = effect;
  Node* rtrue = receiver;

  Node* if_false = graph()->NewNode(common()->IfFalse(), branch);
  Node* efalse = effect;
  Node* rfalse;
  {
    // Convert {receiver} using the ToObjectStub.
    Callable callable = Builtins::CallableFor(isolate(), Builtin::kToObject);
    auto call_descriptor = Linkage::GetStubCallDescriptor(
        graph()->zone(), callable.descriptor(),
        callable.descriptor().GetStackParameterCount(),
        CallDescriptor::kNeedsFrameState, node->op()->properties());
    Node* call = rfalse = efalse = if_false =
        graph()->NewNode(common()->Call(call_descriptor),
                         jsgraph()->HeapConstantNoHole(callable.code()),
                         receiver, context, frame_state, efalse, if_false);

    // We preserve the type of {node}. This is generally useful (to  enable
    // type-based optimizations), and is also required in order to help
    // verification of TypeGuards.
    NodeProperties::SetType(call, NodeProperties::GetType(node));
  }

  // Update potential {IfException} uses of {node} to point to the above
  // ToObject stub call node instead. Note that the stub can only throw on
  // receivers that can be null or undefined.
  Node* on_exception = nullptr;
  if (receiver_type.Maybe(Type::NullOrUndefined()) &&
      NodeProperties::IsExceptionalCall(node, &on_exception)) {
    NodeProperties::ReplaceControlInput(on_exception, if_false);
    NodeProperties::ReplaceEffectInput(on_exception, efalse);
    if_false = graph()->NewNode(common()->IfSuccess(), if_false);
    Revisit(on_exception);
  }

  control = graph()->NewNode(common()->Merge(2), if_true, if_false);
  effect = graph()->NewNode(common()->EffectPhi(2), etrue, efalse, control);

  // Morph the {node} into an appropriate Phi.
  ReplaceWithValue(node, node, effect, control);
  node->ReplaceInput(0, rtrue);
  node->ReplaceInput(1, rfalse);
  node->ReplaceInput(2, control);
  node->TrimInputCount(3);
  NodeProperties::ChangeOp(node,
                           common()->Phi(MachineRepresentation::kTagged, 2));
  return Changed(node);
}

Reduction JSTypedLowering::ReduceJSLoadNamed(Node* node) {
  JSLoadNamedNode n(node);
  Node* receiver = n.object();
  Type receiver_type = NodeProperties::GetType(receiver);
  NameRef name = NamedAccessOf(node->op()).name();
  NameRef length_str = broker()->length_string();
  // Optimize "length" property of strings.
  if (name.equals(length_str) && receiver_type.Is(Type::String())) {
    Node* value = graph()->NewNode(simplified()->StringLength(), receiver);
    ReplaceWithValue(node, value);
    return Replace(value);
  }
  return NoChange();
}

Reduction JSTypedLowering::ReduceJSHasInPrototypeChain(Node* node) {
  DCHECK_EQ(IrOpcode::kJSHasInPrototypeChain, node->opcode());
  Node* value = NodeProperties::GetValueInput(node, 0);
  Type value_type = NodeProperties::GetType(value);
  Node* prototype = NodeProperties::GetValueInput(node, 1);
  Node* context = NodeProperties::GetContextInput(node);
  Node* frame_state = NodeProperties::GetFrameStateInput(node);
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);

  // If {value} cannot be a receiver, then it cannot have {prototype} in
  // it's prototype chain (all Primitive values have a null prototype).
  if (value_type.Is(Type::Primitive())) {
    value = jsgraph()->FalseConstant();
    ReplaceWithValue(node, value, effect, control);
    return Replace(value);
  }

  Node* check0 = graph()->NewNode(simplified()->ObjectIsSmi(), value);
  Node* branch0 =
      graph()->NewNode(common()->Branch(BranchHint::kFalse), check0, control);

  Node* if_true0 = graph()->NewNode(common()->IfTrue(), branch0);
  Node* etrue0 = effect;
  Node* vtrue0 = jsgraph()->FalseConstant();

  control = graph()->NewNode(common()->IfFalse(), branch0);

  // Loop through the {value}s prototype chain looking for the {prototype}.
  Node* loop = control = graph()->NewNode(common()->Loop(2), control, control);
  Node* eloop = effect =
      graph()->NewNode(common()->EffectPhi(2), effect, effect, loop);
  Node* terminate = graph()->NewNode(common()->Terminate(), eloop, loop);
  MergeControlToEnd(graph(), common(), terminate);
  Node* vloop = value = graph()->NewNode(
      common()->Phi(MachineRepresentation::kTagged, 2), value, value, loop);
  NodeProperties::SetType(vloop, Type::NonInternal());

  // Load the {value} map and instance type.
  Node* value_map = effect = graph()->NewNode(
      simplified()->LoadField(AccessBuilder::ForMap()), value, effect, control);
  Node* value_instance_type = effect = graph()->NewNode(
      simplified()->LoadField(AccessBuilder::ForMapInstanceType()), value_map,
      effect, control);

  // Check if the {value} is a special receiver, because for special
  // receivers, i.e. proxies or API values that need access checks,
  // we have to use the %HasInPrototypeChain runtime function instead.
  Node* check1 = graph()->NewNode(
      simplified()->NumberLessThanOrEqual(), value_instance_type,
      jsgraph()->ConstantNoHole(LAST_SPECIAL_RECEIVER_TYPE));
  Node* branch1 =
      graph()->NewNode(common()->Branch(BranchHint::kFalse), check1, control);

  control = graph()->NewNode(common()->IfFalse(), branch1);

  Node* if_true1 = graph()->NewNode(common()->IfTrue(), branch1);
  Node* etrue1 = effect;
  Node* vtrue1;

  // Check if the {value} is not a receiver at all.
  Node* check10 =
      graph()->NewNode(simplified()->NumberLessThan(), value_instance_type,
                       jsgraph()->ConstantNoHole(FIRST_JS_RECEIVER_TYPE));
  Node* branch10 =
      graph()->NewNode(common()->Branch(BranchHint::kTrue), check10, if_true1);

  // A primitive value cannot match the {prototype} we're looking for.
  if_true1 = graph()->NewNode(common()->IfTrue(), branch10);
  vtrue1 = jsgraph()->FalseConstant();

  Node* if_false1 = graph()->NewNode(common()->IfFalse(), branch10);
  Node* efalse1 = etrue1;
  Node* vfalse1;
  {
    // Slow path, need to call the %HasInPrototypeChain runtime function.
    vfalse1 = efalse1 = if_false1 = graph()->NewNode(
        javascript()->CallRuntime(Runtime::kHasInPrototypeChain), value,
        prototype, context, frame_state, efalse1, if_false1);

    // Replace any potential {IfException} uses of {node} to catch
    // exceptions from this %HasInPrototypeChain runtime call instead.
    Node* on_exception = nullptr;
    if (NodeProperties::IsExceptionalCall(node, &on_exception)) {
      NodeProperties::ReplaceControlInput(on_exception, vfalse1);
      NodeProperties::ReplaceEffectInput(on_exception, efalse1);
      if_false1 = graph()->NewNode(common()->IfSuccess(), vfalse1);
      Revisit(on_exception);
    }
  }

  // Load the {value} prototype.
  Node* value_prototype = effect = graph()->NewNode(
      simplified()->LoadField(AccessBuilder::ForMapPrototype()), value_map,
      effect, control);

  // Check if we reached the end of {value}s prototype chain.
  Node* check2 = graph()->NewNode(simplified()->ReferenceEqual(),
                                  value_prototype, jsgraph()->NullConstant());
  Node* branch2 = graph()->NewNode(common()->Branch(), check2, control);

  Node* if_true2 = graph()->NewNode(common()->IfTrue(), branch2);
  Node* etrue2 = effect;
  Node* vtrue2 = jsgraph()->FalseConstant();

  control = graph()->NewNode(common()->IfFalse(), branch2);

  // Check if we reached the {prototype}.
  Node* check3 = graph()->NewNode(simplified()->ReferenceEqual(),
                                  value_prototype, prototype);
  Node* branch3 = graph()->NewNode(common()->Branch(), check3, control);

  Node* if_true3 = graph()->NewNode(common()->IfTrue(), branch3);
  Node* etrue3 = effect;
  Node* vtrue3 = jsgraph()->TrueConstant();

  control = graph()->NewNode(common()->IfFalse(), branch3);

  // Close the loop.
  vloop->ReplaceInput(1, value_prototype);
  eloop->ReplaceInput(1, effect);
  loop->ReplaceInput(1, control);

  control = graph()->NewNode(common()->Merge(5), if_true0, if_true1, if_true2,
                             if_true3, if_false1);
  effect = graph()->NewNode(common()->EffectPhi(5), etrue0, etrue1, etrue2,
                            etrue3, efalse1, control);

  // Morph the {node} into an appropriate Phi.
  ReplaceWithValue(node, node, effect, control);
  node->ReplaceInput(0, vtrue0);
  node->ReplaceInput(1, vtrue1);
  node->ReplaceInput(2, vtrue2);
  node->ReplaceInput(3, vtrue3);
  node->ReplaceInput(4, vfalse1);
  node->ReplaceInput(5, control);
  node->TrimInputCount(6);
  NodeProperties::ChangeOp(node,
                           common()->Phi(MachineRepresentation::kTagged, 5));
  return Changed(node);
}

Reduction JSTypedLowering::ReduceJSOrdinaryHasInstance(Node* node) {
  DCHECK_EQ(IrOpcode::kJSOrdinaryHasInstance, node->opcode());
  Node* constructor = NodeProperties::GetValueInput(node, 0);
  Type constructor_type = NodeProperties::GetType(constructor);
  Node* object = NodeProperties::GetValueInput(node, 1);
  Type object_type = NodeProperties::GetType(object);

  // Check if the {constructor} cannot be callable.
  // See ES6 section 7.3.19 OrdinaryHasInstance ( C, O ) step 1.
  if (!constructor_type.Maybe(Type::Callable())) {
    Node* value = jsgraph()->FalseConstant();
    ReplaceWithValue(node, value);
    return Replace(value);
  }

  // If the {constructor} cannot be a JSBoundFunction and then {object}
  // cannot be a JSReceiver, then this can be constant-folded to false.
  // See ES6 section 7.3.19 OrdinaryHasInstance ( C, O ) step 2 and 3.
  if (!object_type.Maybe(Type::Receiver()) &&
      !constructor_type.Maybe(Type::BoundFunction())) {
    Node* value = jsgraph()->FalseConstant();
    ReplaceWithValue(node, value);
    return Replace(value);
  }

  return NoChange();
}

Reduction JSTypedLowering::ReduceJSHasContextExtension(Node* node) {
  DCHECK_EQ(IrOpcode::kJSHasContextExtension, node->opcode());
  size_t depth = OpParameter<size_t>(node->op());
  Node* effect = NodeProperties::GetEffectInput(node);
  TNode<Context> context =
      TNode<Context>::UncheckedCast(NodeProperties::GetContextInput(node));
  Node* control = graph()->start();

  JSGraphAssembler gasm(broker(), jsgraph_, jsgraph_->zone(),
                        BranchSemantics::kJS);
  gasm.InitializeEffectControl(effect, control);

  for (size_t i = 0; i < depth; ++i) {
#if DEBUG
    // Const tracking let data is stored in the extension slot of a
    // ScriptContext - however, it's unrelated to the sloppy eval variable
    // extension. We should never iterate through a ScriptContext here.

    TNode<ScopeInfo> scope_info = gasm.LoadField<ScopeInfo>(
        AccessBuilder::ForContextSlot(Context::SCOPE_INFO_INDEX), context);
    TNode<Word32T> scope_info_flags = gasm.EnterMachineGraph<Word32T>(
        gasm.LoadField<Word32T>(AccessBuilder::ForScopeInfoFlags(), scope_info),
        UseInfo::TruncatingWord32());
    TNode<Word32T> scope_type = gasm.Word32And(
        scope_info_flags, gasm.Uint32Constant(ScopeInfo::ScopeTypeBits::kMask));
    TNode<Word32T> is_script_scope = gasm.Word32Equal(
        scope_type, gasm.Uint32Constant(ScopeType::SCRIPT_SCOPE));
    TNode<Word32T> is_not_script_scope =
        gasm.Word32Equal(is_script_scope, gasm.Uint32Constant(0));
    gasm.Assert(is_not_script_scope, "we should no see a ScriptContext here",
                __FILE__, __LINE__);
#endif

    context = gasm.LoadField<Context>(
        AccessBuilder::ForContextSlotKnownPointer(Context::PREVIOUS_INDEX),
        context);
  }
  TNode<ScopeInfo> scope_info = gasm.LoadField<ScopeInfo>(
      AccessBuilder::ForContextSlot(Context::SCOPE_INFO_INDEX), context);
  TNode<Word32T> scope_info_flags = gasm.EnterMachineGraph<Word32T>(
      gasm.LoadField<Word32T>(AccessBuilder::ForScopeInfoFlags(), scope_info),
      UseInfo::TruncatingWord32());
  TNode<Word32T> flags_masked = gasm.Word32And(
      scope_info_flags,
      gasm.Uint32Constant(ScopeInfo::HasContextExtensionSlotBit::kMask));
  TNode<Word32T> no_extension =
      gasm.Word32Equal(flags_masked, gasm.Uint32Constant(0));
  TNode<Word32T> has_extension =
      gasm.Word32Equal(no_extension, gasm.Uint32Constant(0));
  TNode<Boolean> has_extension_boolean = gasm.ExitMachineGraph<Boolean>(
      has_extension, MachineRepresentation::kBit, Type::Boolean());

  ReplaceWithValue(node, has_extension_boolean, gasm.effect(), gasm.control());
  return Changed(node);
}

Reduction JSTypedLowering::ReduceJSLoadContext(Node* node) {
  DCHECK_EQ(IrOpcode::kJSLoadContext, node->opcode());
  ContextAccess const& access = ContextAccessOf(node->op());
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* context = NodeProperties::GetContextInput(node);
  Node* control = graph()->start();
  for (size_t i = 0; i < access.depth(); ++i) {
    context = effect = graph()->NewNode(
        simplified()->LoadField(
            AccessBuilder::ForContextSlotKnownPointer(Context::PREVIOUS_INDEX)),
        context, effect, control);
  }
  node->ReplaceInput(0, context);
  node->ReplaceInput(1, effect);
  node->AppendInput(jsgraph()->zone(), control);
  NodeProperties::ChangeOp(
      node,
      simplified()->LoadField(AccessBuilder::ForContextSlot(access.index())));
  return Changed(node);
}

Reduction JSTypedLowering::ReduceJSLoadScriptContext(Node* node) {
  DCHECK_EQ(IrOpcode::kJSLoadScriptContext, node->opcode());
  ContextAccess const& access = ContextAccessOf(node->op());
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);
  JSGraphAssembler gasm(broker(), jsgraph(), jsgraph()->zone(),
                        BranchSemantics::kJS);
  gasm.InitializeEffectControl(effect, control);

  TNode<Context> context =
      TNode<Context>::UncheckedCast(NodeProperties::GetContextInput(node));
  for (size_t i = 0; i < access.depth(); ++i) {
    context = gasm.LoadField<Context>(
        AccessBuilder::ForContextSlotKnownPointer(Context::PREVIOUS_INDEX),
        con
"""


```