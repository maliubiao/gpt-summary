Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/test/cctest/test-api.cc`. I need to go through each `THREADED_TEST` and `TEST` block, understand what it's testing, and then provide a concise summary. I also need to address the specific points raised in the prompt regarding `.tq` files, JavaScript examples, logical inference, common programming errors, and the part number.

Here's a breakdown of the thought process for each test case:

* **`THREADED_TEST(UnsignedInt)`**:  This tests the creation of a `v8::Integer` from an unsigned integer value that exceeds the maximum value of a signed 32-bit integer. It verifies that the conversion works correctly without overflow and that the `Value()` method returns the expected 64-bit integer value.

* **`THREADED_TEST(IsNativeError)`**: This tests the `IsNativeError()` method. It creates a syntax error using `eval()`, a non-error object, and a primitive value, then checks if `IsNativeError()` returns the correct boolean for each.

* **`THREADED_TEST(IsGeneratorFunctionOrObject)`**:  This tests the `IsGeneratorFunction()` and `IsGeneratorObject()` methods. It defines a generator function and a regular function, then checks the results of these methods on the function itself and the result of calling the generator. It also checks a regular object and function.

* **`THREADED_TEST(IsAsyncFunction)`**: This tests the `IsAsyncFunction()` method. It defines an async function and a regular function and checks the return value of `IsAsyncFunction()` and `IsFunction()` for both.

* **`THREADED_TEST(ArgumentsObject)`**: This tests the `IsArgumentsObject()` method. It creates an arguments object within a function, a regular array, and a plain object, then checks if `IsArgumentsObject()` identifies the arguments object correctly.

* **`THREADED_TEST(IsMapOrSet)`**: This tests the `IsMap()`, `IsSet()`, `IsWeakMap()`, and `IsWeakSet()` methods on instances of `Map`, `Set`, `WeakMap`, `WeakSet`, and a plain object. It verifies that each method returns `true` for its corresponding type and `false` for others.

* **`THREADED_TEST(StringObject)`**: This tests the `IsStringObject()` method and the creation and manipulation of `v8::StringObject`. It checks the difference between primitive strings and boxed `String` objects, uses `As<v8::StringObject>()` and `ValueOf()`.

* **`TEST(StringObjectDelete)`**: This tests the behavior of `Delete()` on a `v8::StringObject`. It confirms that deleting indexed properties on a boxed string fails.

* **`THREADED_TEST(NumberObject)`**:  This tests the `IsNumberObject()` method and the creation and manipulation of `v8::NumberObject`. It checks the difference between primitive numbers and boxed `Number` objects, and uses `As<v8::NumberObject>()` and `ValueOf()`.

* **`THREADED_TEST(BigIntObject)`**: This tests `IsBigInt()` and `IsBigIntObject()` and the creation of `v8::BigIntObject`. It also checks some inherited functionality from `v8::Value` like `BooleanValue()` and `ToString()`, and verifies that `IntegerValue()` throws an error.

* **`THREADED_TEST(BooleanObject)`**: This tests the `IsBooleanObject()` method and the creation and manipulation of `v8::BooleanObject`. It checks the difference between primitive booleans and boxed `Boolean` objects, and uses `As<v8::BooleanObject>()` and `ValueOf()`.

* **`THREADED_TEST(PrimitiveAndWrappedBooleans)`**: This test explores the differences between primitive boolean values (created with `Boolean::New`) and boxed boolean objects (created with `BooleanObject::New`). It checks various `Is...` methods and `BooleanValue()`, `ValueOf()` for both.

* **`THREADED_TEST(Number)`**: This tests the creation of a `v8::Number` and verifies that `NumberValue()` returns the correct double value.

* **`THREADED_TEST(ToNumber)`**: This tests the `NumberValue()` method on different primitive types (string and boolean) to verify the correct type coercion to a number.

* **`THREADED_TEST(Date)`**: This tests the creation of a `v8::Date` object and the `NumberValue()` method. It also demonstrates setting and getting properties on a `Date` object.

* **`THREADED_TEST(Boolean)`**: This tests the `BooleanValue()` method on various primitive values (undefined, null, strings, numbers, NaN) to confirm the correct boolean coercion.

* **`THREADED_TEST(GlobalPrototype)`**: This test focuses on setting properties on the global object's prototype using `FunctionTemplate` and `ObjectTemplate`, and then accessing those properties from JavaScript code. It demonstrates the interaction between C++ templates and JavaScript prototypes.

* **`THREADED_TEST(ObjectTemplate)`**: This test explores the functionality of `ObjectTemplate`. It creates instances of templates, sets properties (data and functions), and verifies that these properties are accessible from JavaScript. It also demonstrates prototype inheritance and accessor properties.

* **`THREADED_TEST(IntegerValue)`**:  This tests the `IntegerValue()` method on `undefined`, checking its behavior.

* **`THREADED_TEST(TestObjectTemplateInheritedWithPrototype1/2/3)`**: These tests focus on object template inheritance and how properties are inherited through prototype chains. They cover different ways of instantiating objects (using `NewInstance` directly on the `ObjectTemplate` and via the constructor function).

* **`THREADED_TEST(TestObjectTemplateInheritedWithoutInstanceTemplate1/2)`**: These tests examine inheritance when the derived function template doesn't have its own instance template.

* **`THREADED_TEST(TestDataTypeChecks)`**: This test uses various `Is...` methods to check the type of different V8 data types (Value, Module, Private, ObjectTemplate, FunctionTemplate).

* **`THREADED_TEST(TestObjectTemplateClassInheritance)`**: This test demonstrates how object templates interact with JavaScript class inheritance (`extends`). It verifies that instances of the subclass have the expected properties from the parent class's template.

* **`THREADED_TEST(TestObjectTemplateReflectConstruct)`**: This test uses `Reflect.construct` in JavaScript to create objects based on a constructor defined by a function template and checks if the instances have the expected properties defined by the object template's property handler.

* **`THREADED_TEST(DescriptorInheritance)`**: This test explores the inheritance of properties defined on function templates (on both the prototype and instance templates) when using `Inherit()`. It checks the presence and values of properties accessed through instances.

After analyzing each test, I can now compile the information into a structured summary addressing all the user's requirements.
这是 `v8/test/cctest/test-api.cc` 源代码的第 3 部分，主要功能是 **测试 V8 C++ API 中关于不同 JavaScript 类型的判断和操作功能**。它通过一系列的 `THREADED_TEST` 和 `TEST` 宏定义了多个独立的测试用例，每个用例专注于验证 V8 API 中与特定 JavaScript 类型相关的行为是否符合预期。

**具体功能归纳如下：**

* **数值类型测试:**
    * `UnsignedInt`: 测试使用 `v8::Integer::NewFromUnsigned` 创建表示无符号整数的能力，特别是当数值超出有符号 32 位整数范围时。
    * `NumberObject`: 测试 `IsNumberObject()` 方法，用于判断一个值是否是 `Number` 对象的实例 (例如 `new Number(42)`)。
    * `BigIntObject`: 测试 `IsBigInt()` 和 `IsBigIntObject()` 方法，用于判断值是否是 `BigInt` 类型或 `BigInt` 对象的实例。
    * `Number`: 测试使用 `v8::Number::New` 创建 `Number` 值。
    * `ToNumber`: 测试将其他类型转换为数字的方法 `NumberValue()`。
    * `IntegerValue`: 测试 `IntegerValue()` 方法在 `undefined` 上的行为。

* **布尔类型测试:**
    * `BooleanObject`: 测试 `IsBooleanObject()` 方法，用于判断一个值是否是 `Boolean` 对象的实例 (例如 `new Boolean(true)`)。
    * `PrimitiveAndWrappedBooleans`:  深入测试原始布尔值（`true`, `false`）和包装的布尔对象（`new Boolean(true)`, `new Boolean(false)`) 之间的区别，以及相关的 API 方法如 `IsBoolean()`, `IsBooleanObject()`, `BooleanValue()`, `IsTrue()`, `IsFalse()`, `ValueOf()`。
    * `Boolean`: 测试 `BooleanValue()` 方法将各种 JavaScript 值转换为布尔值的行为 (例如 `undefined`, `null`, 空字符串, 非空字符串, 数字等)。

* **字符串类型测试:**
    * `StringObject`: 测试 `IsStringObject()` 方法，用于判断一个值是否是 `String` 对象的实例 (例如 `new String("test")`)，以及创建和操作 `StringObject` 的方法。
    * `StringObjectDelete`: 测试尝试删除 `StringObject` 的索引属性是否会成功（预期不会成功）。

* **错误类型测试:**
    * `IsNativeError`: 测试 `IsNativeError()` 方法，用于判断一个值是否是原生 JavaScript 错误对象 (例如 `SyntaxError`, `TypeError` 等)。

* **函数类型测试:**
    * `IsGeneratorFunctionOrObject`: 测试 `IsGeneratorFunction()` 和 `IsGeneratorObject()` 方法，用于区分生成器函数和生成器对象。
    * `IsAsyncFunction`: 测试 `IsAsyncFunction()` 方法，用于判断一个函数是否是异步函数。

* **对象类型测试:**
    * `ArgumentsObject`: 测试 `IsArgumentsObject()` 方法，用于判断一个对象是否是 `arguments` 对象。
    * `IsMapOrSet`: 测试 `IsMap()`, `IsSet()`, `IsWeakMap()`, `IsWeakSet()` 方法，用于判断一个对象是否是 `Map`, `Set`, `WeakMap`, `WeakSet` 的实例。

* **日期类型测试:**
    * `Date`: 测试创建 `v8::Date` 对象以及获取其数值表示。

* **模板和原型链测试:**
    * `GlobalPrototype`: 测试使用 `FunctionTemplate` 和 `ObjectTemplate` 设置全局对象的原型属性。
    * `ObjectTemplate`: 测试 `ObjectTemplate` 的基本功能，包括创建实例、设置属性 (数据属性和函数属性)、原型链等。
    * `TestObjectTemplateInheritedWithPrototype*`: 测试对象模板的继承，特别是原型链上的属性继承。
    * `TestObjectTemplateInheritedWithoutInstanceTemplate*`: 测试当子类没有自己的实例模板时，如何继承父类的属性。
    * `TestObjectTemplateClassInheritance`: 测试对象模板与 JavaScript 类继承 (`extends`) 的交互。
    * `TestObjectTemplateReflectConstruct`: 测试 `Reflect.construct` 与对象模板的交互。
    * `DescriptorInheritance`: 测试 `FunctionTemplate` 的继承 (`Inherit`) 如何影响原型链上的属性描述符。

* **数据类型检查:**
    * `TestDataTypeChecks`: 测试各种 `Is...` 方法用于检查不同的 V8 数据类型 (`Value`, `Module`, `Private`, `ObjectTemplate`, `FunctionTemplate`)。

**关于您的提问：**

* **如果 `v8/test/cctest/test-api.cc` 以 `.tq` 结尾，那它是个 v8 torque 源代码。**  这是正确的。如果文件以 `.tq` 结尾，则表示它是使用 V8 的 Torque 语言编写的。但当前的 `v8/test/cctest/test-api.cc` 是一个 C++ 文件。

* **如果它与 javascript 的功能有关系，请用 javascript 举例说明。**

   * **`THREADED_TEST(UnsignedInt)`:**  这个测试在 JavaScript 中没有直接对应的概念，因为它涉及到 C++ 中对超出 JavaScript 安全整数范围的无符号整数的处理。

   * **`THREADED_TEST(IsNativeError)`:**
     ```javascript
     try {
       eval("#"); // 抛出一个 SyntaxError
     } catch (e) {
       console.log(e instanceof SyntaxError); // true
     }
     console.log({a: 42} instanceof Error); // false
     console.log(42 instanceof Error);       // false
     ```

   * **`THREADED_TEST(IsGeneratorFunctionOrObject)`:**
     ```javascript
     function* gen() { yield 1; }
     const genFunc = gen;
     const genObj = gen();
     const obj = { a: 42 };
     function func() {}

     console.log(typeof genFunc === 'function'); // true
     console.log(genFunc.constructor.name === 'GeneratorFunction'); // true

     console.log(typeof genObj === 'object');   // true
     console.log(genObj.constructor.name === 'Generator');       // true

     console.log(typeof obj === 'object');     // true

     console.log(typeof func === 'function');   // true
     ```

   * **`THREADED_TEST(IsAsyncFunction)`:**
     ```javascript
     async function foo() {}
     function bar() {}

     console.log(foo instanceof Function); // true
     console.log(foo.constructor.name === 'AsyncFunction'); // true

     console.log(bar instanceof Function); // true
     console.log(bar.constructor.name === 'Function');      // true
     ```

   * **`THREADED_TEST(ArgumentsObject)`:**
     ```javascript
     function test() {
       console.log(arguments instanceof Object); // true (虽然不是 Array 的实例)
       console.log(Object.prototype.toString.call(arguments)); // "[object Arguments]"
     }
     test(1, 2, 3);
     console.log([1, 2, 3] instanceof Array); // true
     console.log({ a: 42 } instanceof Object);   // true
     ```

   * **`THREADED_TEST(IsMapOrSet)`:**
     ```javascript
     const map = new Map();
     const set = new Set();
     const weakMap = new WeakMap();
     const weakSet = new WeakSet();
     const obj = { a: 42 };

     console.log(map instanceof Map);        // true
     console.log(set instanceof Set);        // true
     console.log(weakMap instanceof WeakMap); // true
     console.log(weakSet instanceof WeakSet); // true
     console.log(obj instanceof Map);        // false
     ```

   * **`THREADED_TEST(StringObject)`:**
     ```javascript
     const boxedString = new String("test");
     const primitiveString = "test";
     const boxedNumber = new Number(42);
     const number = 0;

     console.log(typeof boxedString === 'object'); // true
     console.log(boxedString instanceof String);   // true
     console.log(typeof primitiveString === 'string'); // true

     console.log(typeof boxedNumber === 'object'); // true
     console.log(boxedNumber instanceof String);   // false
     console.log(typeof number === 'number');       // true
     ```

   * **`TEST(StringObjectDelete)`:**
     ```javascript
     const strObj = new String("test");
     delete strObj[0]; // 尝试删除索引属性，但不会成功
     console.log(strObj[0]); // "t"
     ```

   * **`THREADED_TEST(NumberObject)`:**
     ```javascript
     const boxedNumber = new Number(42);
     const primitiveNumber = 42;
     const boxedBoolean = new Boolean(false);

     console.log(typeof boxedNumber === 'object');  // true
     console.log(boxedNumber instanceof Number);    // true
     console.log(typeof primitiveNumber === 'number'); // true
     console.log(typeof boxedBoolean === 'object'); // true
     console.log(boxedBoolean instanceof Number);   // false
     ```

   * **`THREADED_TEST(BigIntObject)`:**
     ```javascript
     const boxedBigInt = Object(42n);
     const primitiveBigInt = 42n;

     console.log(typeof boxedBigInt === 'object');   // true
     console.log(typeof primitiveBigInt === 'bigint'); // true
     console.log(Boolean(primitiveBigInt));         // true
     console.log(String(primitiveBigInt));          // "42"
     // Number(primitiveBigInt); // 会抛出 TypeError
     ```

   * **`THREADED_TEST(BooleanObject)`:**
     ```javascript
     const boxedBoolean = new Boolean(true);
     const primitiveBoolean = true;
     const boxedNumber = new Number(42);

     console.log(typeof boxedBoolean === 'object');    // true
     console.log(boxedBoolean instanceof Boolean);      // true
     console.log(typeof primitiveBoolean === 'boolean'); // true
     console.log(typeof boxedNumber === 'object');     // true
     console.log(boxedNumber instanceof Boolean);       // false
     ```

   * **`THREADED_TEST(PrimitiveAndWrappedBooleans)`:**
     ```javascript
     const primitiveFalse = false;
     const boxedFalse = new Boolean(false);
     const primitiveTrue = true;
     const boxedTrue = new Boolean(true);

     console.log(typeof primitiveFalse === 'boolean'); // true
     console.log(boxedFalse instanceof Boolean);       // true
     console.log(Boolean(boxedFalse));                // true (注意这里的隐式转换)

     console.log(typeof primitiveTrue === 'boolean');  // true
     console.log(boxedTrue instanceof Boolean);        // true
     console.log(Boolean(boxedTrue));                 // true
     ```

   * **`THREADED_TEST(Number)`:**
     ```javascript
     const pi = 3.1415926;
     console.log(typeof pi === 'number'); // true
     ```

   * **`THREADED_TEST(ToNumber)`:**
     ```javascript
     console.log(Number("3.1415926")); // 3.1415926
     console.log(Number(true));        // 1
     console.log(Number(false));       // 0
     ```

   * **`THREADED_TEST(Date)`:**
     ```javascript
     const date = new Date(3.1415926); // 内部表示的时间戳
     console.log(date.getTime());
     date.property = 42;
     console.log(date.property); // 42
     ```

   * **`THREADED_TEST(Boolean)`:**
     ```javascript
     console.log(Boolean(undefined)); // false
     console.log(Boolean(null));      // false
     console.log(Boolean(""));        // false
     console.log(Boolean("x"));       // true
     console.log(Boolean(0));         // false
     console.log(Boolean(-1));        // true
     console.log(Boolean(1));         // true
     console.log(Boolean(42));        // true
     console.log(Boolean(NaN));       // false
     ```

   * **`THREADED_TEST(GlobalPrototype)` 和后续的模板测试:** 这些测试主要验证 V8 的模板机制，这些机制用于在 C++ 中定义 JavaScript 对象的结构和行为，JavaScript 中没有直接对应的简单语法，需要使用构造函数、原型等概念来模拟。

* **如果有代码逻辑推理，请给出假设输入与输出。**

   * **`THREADED_TEST(UnsignedInt)`:**
      * **假设输入:** `value = (1U << 31)` (即 2147483648，超出有符号 32 位整数的最大值)
      * **预期输出:** `value > INT32_MAX_AS_UINT` 为 true，`value_obj->Value()` 等于 2147483648。

   * **`THREADED_TEST(IsNativeError)`:**
      * **假设输入 1:** JavaScript 代码 `"var out = 0; try { eval(\"#\"); } catch(x) { out = x; } out;"`
      * **预期输出 1:** `syntax_error` 是一个 `SyntaxError` 对象，`syntax_error->IsNativeError()` 返回 true。
      * **假设输入 2:** JavaScript 代码 `"{a:42}"`
      * **预期输出 2:** `not_error` 是一个普通对象，`not_error->IsNativeError()` 返回 false。

   * **`THREADED_TEST(IsGeneratorFunctionOrObject)`:**
      * **假设输入 1:** JavaScript 代码 `"gen"` (生成器函数本身)
      * **预期输出 1:** `gen->IsGeneratorFunction()` 为 true，`gen->IsGeneratorObject()` 为 false。
      * **假设输入 2:** JavaScript 代码 `"gen()"` (生成器函数的调用结果)
      * **预期输出 2:** `genObj->IsGeneratorFunction()` 为 false，`genObj->IsGeneratorObject()` 为 true。

   * **`THREADED_TEST(IsAsyncFunction)`:**
      * **假设输入 1:** JavaScript 代码 `"foo"` (异步函数本身)
      * **预期输出 1:** `foo->IsAsyncFunction()` 为 true。
      * **假设输入 2:** JavaScript 代码 `"bar"` (普通函数本身)
      * **预期输出 2:** `bar->IsAsyncFunction()` 为 false。

   * **`THREADED_TEST(ArgumentsObject)`:**
      * **假设输入:** JavaScript 代码 `"var out = 0; (function(){ out = arguments; })(1,2,3); out;"`
      * **预期输出:** `arguments_object->IsArgumentsObject()` 为 true。

   * **`THREADED_TEST(IsMapOrSet)`:**  根据创建的对象类型，`IsMap()`, `IsSet()`, `IsWeakMap()`, `IsWeakSet()` 会返回相应的布尔值。

   * **`THREADED_TEST(StringObject)`:**
      * **假设输入 1:** JavaScript 代码 `"new String(\"test\")"`
      * **预期输出 1:** `boxed_string->IsStringObject()` 为 true。
      * **假设输入 2:** JavaScript 代码 `"\"test\""`
      * **预期输出 2:** `unboxed_string->IsStringObject()` 为 false。

   * **`THREADED_TEST(NumberObject)`:**
      * **假设输入 1:** JavaScript 代码 `"new Number(42)"`
      * **预期输出 1:** `boxed_number->IsNumberObject()` 为 true。
      * **假设输入 2:** JavaScript 代码 `"42"`
      * **预期输出 2:** `unboxed_number->IsNumberObject()` 为 false。

   * **`THREADED_TEST(BigIntObject)`:**
      * **假设输入 1:** JavaScript 代码 `"new Object(42n)"`
      * **预期输出 1:** `boxed_bigint->IsBigIntObject()` 为 true，`boxed_bigint->IsBigInt()` 为 false。
      * **假设输入 2:** JavaScript 代码 `"42n"`
      * **预期输出 2:** `unboxed_bigint->IsBigIntObject()` 为 false，`unboxed_bigint->IsBigInt()` 为 true。

   * **`THREADED_TEST(BooleanObject)`:**
      * **假设输入 1:** JavaScript 代码 `"new Boolean(true)"`
      * **预期输出 1:** `boxed_boolean->IsBooleanObject()` 为 true。
      * **假设输入 2:** JavaScript 代码 `"true"`
      * **预期输出 2:** `unboxed_boolean->IsBooleanObject()` 为 false。

   * **`THREADED_TEST(PrimitiveAndWrappedBooleans)`:**  这个测试直接验证各种布尔值和布尔对象的方法返回值。

   * **`THREADED_TEST(Number)`:**
      * **假设输入:** `PI = 3.1415926`
      * **预期输出:** `pi_obj->NumberValue(env.local()).FromJust()` 等于 3.1415926。

   * **`THREADED_TEST(ToNumber)`:**  根据输入的字符串或布尔值，`NumberValue()` 返回相应的数字。

   * **`THREADED_TEST(Date)`:**
      * **假设输入:** `PI = 3.1415926`
      * **预期输出:** `date->NumberValue(env.local()).FromJust()` 返回与时间戳相关的数值 (这里是 3，因为 Date 构造函数会截断)。

   * **`THREADED_TEST(Boolean)`:**  根据输入的 JavaScript 值，`BooleanValue()` 返回相应的布尔值。

   * **模板相关的测试:** 这些测试设置模板，然后创建实例，并验证实例是否具有预期的属性和行为。具体的输入是模板的定义，输出是实例的属性值。

* **如果涉及用户常见的编程错误，请举例说明。**

   * **混淆原始类型和包装对象:**
     ```javascript
     let str1 = "hello";
     let str2 = new String("hello");

     console.log(typeof str1); // "string"
     console.log(typeof str2); // "object"

     console.log(str1 instanceof String); // false
     console.log(str2 instanceof String); // true

     // 有些方法只存在于包装对象上，或者行为不同
     console.log(str1.valueOf()); // "hello"
     console.log(str2.valueOf()); // "hello"

     // 但是包装对象在某些情况下可能会带来意想不到的结果
     if (new Boolean(false)) {
       console.log("This will be printed!"); // 因为对象总是 truthy
     }
     ```

   * **错误地使用 `instanceof` 运算符:** `instanceof` 检查的是原型链，对于基本类型字面量会返回 `false`。

   * **忘记 `new` 关键字创建包装对象:**
     ```javascript
     let num = Number(42); // 返回原始数值 42
     let numObj = new Number(42); // 返回 Number 对象
     ```

   * **在需要原始值的地方使用了包装对象:**  虽然包装对象在很多情况下会被隐式转换为原始值，但在某些严格比较或者类型检查的场景下可能会出现问题。

   * **对 `arguments` 对象的误解:**  `arguments` 不是真正的数组，缺少数组的一些方法。

* **这是第3部分，共36部分，请归纳一下它的功能。**

总的来说，这部分代码的功能是 **系统地测试 V8 JavaScript 引擎中关于各种 JavaScript 类型的 API 实现是否正确和稳定**。它涵盖了基本类型（数值、布尔、字符串）、对象类型（普通对象、Arguments、Map、Set、WeakMap、WeakSet）、函数类型（普通函数、生成器函数、异步函数）、错误类型以及日期类型。此外，还深入测试了 V8 的模板机制，这是 V8 扩展和嵌入的关键部分。通过这些测试，可以确保 V8 引擎能够正确地识别和操作不同类型的 JavaScript 值，为 JavaScript 代码的执行提供可靠的基础。

Prompt: 
```
这是目录为v8/test/cctest/test-api.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-api.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共36部分，请归纳一下它的功能

"""
pe scope(env->GetIsolate());
  v8::Isolate* isolate = CcTest::isolate();

  uint32_t INT32_MAX_AS_UINT = (1U << 31) - 1;
  uint32_t value = INT32_MAX_AS_UINT + 1;
  CHECK(value > INT32_MAX_AS_UINT);  // No overflow.

  Local<v8::Integer> value_obj = v8::Integer::NewFromUnsigned(isolate, value);
  CHECK_EQ(static_cast<int64_t>(value), value_obj->Value());
}


THREADED_TEST(IsNativeError) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::Local<Value> syntax_error = CompileRun(
      "var out = 0; try { eval(\"#\"); } catch(x) { out = x; } out; ");
  CHECK(syntax_error->IsNativeError());
  v8::Local<Value> not_error = CompileRun("{a:42}");
  CHECK(!not_error->IsNativeError());
  v8::Local<Value> not_object = CompileRun("42");
  CHECK(!not_object->IsNativeError());
}


THREADED_TEST(IsGeneratorFunctionOrObject) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  CompileRun("function *gen() { yield 1; }\nfunction func() {}");
  v8::Local<Value> gen = CompileRun("gen");
  v8::Local<Value> genObj = CompileRun("gen()");
  v8::Local<Value> object = CompileRun("{a:42}");
  v8::Local<Value> func = CompileRun("func");

  CHECK(gen->IsGeneratorFunction());
  CHECK(gen->IsFunction());
  CHECK(!gen->IsGeneratorObject());

  CHECK(!genObj->IsGeneratorFunction());
  CHECK(!genObj->IsFunction());
  CHECK(genObj->IsGeneratorObject());

  CHECK(!object->IsGeneratorFunction());
  CHECK(!object->IsFunction());
  CHECK(!object->IsGeneratorObject());

  CHECK(!func->IsGeneratorFunction());
  CHECK(func->IsFunction());
  CHECK(!func->IsGeneratorObject());
}

THREADED_TEST(IsAsyncFunction) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  CompileRun("async function foo() {}");
  v8::Local<Value> foo = CompileRun("foo");

  CHECK(foo->IsAsyncFunction());
  CHECK(foo->IsFunction());
  CHECK(!foo->IsGeneratorFunction());
  CHECK(!foo->IsGeneratorObject());

  CompileRun("function bar() {}");
  v8::Local<Value> bar = CompileRun("bar");

  CHECK(!bar->IsAsyncFunction());
  CHECK(bar->IsFunction());
}

THREADED_TEST(ArgumentsObject) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::Local<Value> arguments_object =
      CompileRun("var out = 0; (function(){ out = arguments; })(1,2,3); out;");
  CHECK(arguments_object->IsArgumentsObject());
  v8::Local<Value> array = CompileRun("[1,2,3]");
  CHECK(!array->IsArgumentsObject());
  v8::Local<Value> object = CompileRun("{a:42}");
  CHECK(!object->IsArgumentsObject());
}


THREADED_TEST(IsMapOrSet) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::Local<Value> map = CompileRun("new Map()");
  v8::Local<Value> set = CompileRun("new Set()");
  v8::Local<Value> weak_map = CompileRun("new WeakMap()");
  v8::Local<Value> weak_set = CompileRun("new WeakSet()");
  CHECK(map->IsMap());
  CHECK(set->IsSet());
  CHECK(weak_map->IsWeakMap());
  CHECK(weak_set->IsWeakSet());

  CHECK(!map->IsSet());
  CHECK(!map->IsWeakMap());
  CHECK(!map->IsWeakSet());

  CHECK(!set->IsMap());
  CHECK(!set->IsWeakMap());
  CHECK(!set->IsWeakSet());

  CHECK(!weak_map->IsMap());
  CHECK(!weak_map->IsSet());
  CHECK(!weak_map->IsWeakSet());

  CHECK(!weak_set->IsMap());
  CHECK(!weak_set->IsSet());
  CHECK(!weak_set->IsWeakMap());

  v8::Local<Value> object = CompileRun("{a:42}");
  CHECK(!object->IsMap());
  CHECK(!object->IsSet());
  CHECK(!object->IsWeakMap());
  CHECK(!object->IsWeakSet());
}


THREADED_TEST(StringObject) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::Local<Value> boxed_string = CompileRun("new String(\"test\")");
  CHECK(boxed_string->IsStringObject());
  v8::Local<Value> unboxed_string = CompileRun("\"test\"");
  CHECK(!unboxed_string->IsStringObject());
  v8::Local<Value> boxed_not_string = CompileRun("new Number(42)");
  CHECK(!boxed_not_string->IsStringObject());
  v8::Local<Value> not_object = CompileRun("0");
  CHECK(!not_object->IsStringObject());
  v8::Local<v8::StringObject> as_boxed = boxed_string.As<v8::StringObject>();
  CHECK(!as_boxed.IsEmpty());
  Local<v8::String> the_string = as_boxed->ValueOf();
  CHECK(!the_string.IsEmpty());
  ExpectObject("\"test\"", the_string);
  v8::Local<v8::Value> new_boxed_string =
      v8::StringObject::New(CcTest::isolate(), the_string);
  CHECK(new_boxed_string->IsStringObject());
  as_boxed = new_boxed_string.As<v8::StringObject>();
  the_string = as_boxed->ValueOf();
  CHECK(!the_string.IsEmpty());
  ExpectObject("\"test\"", the_string);
}


TEST(StringObjectDelete) {
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());
  v8::Local<Value> boxed_string = CompileRun("new String(\"test\")");
  CHECK(boxed_string->IsStringObject());
  v8::Local<v8::Object> str_obj = boxed_string.As<v8::Object>();
  CHECK(!str_obj->Delete(context.local(), 2).FromJust());
  CHECK(!str_obj->Delete(context.local(), v8_num(2)).FromJust());
}


THREADED_TEST(NumberObject) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::Local<Value> boxed_number = CompileRun("new Number(42)");
  CHECK(boxed_number->IsNumberObject());
  v8::Local<Value> unboxed_number = CompileRun("42");
  CHECK(!unboxed_number->IsNumberObject());
  v8::Local<Value> boxed_not_number = CompileRun("new Boolean(false)");
  CHECK(!boxed_not_number->IsNumberObject());
  v8::Local<v8::NumberObject> as_boxed = boxed_number.As<v8::NumberObject>();
  CHECK(!as_boxed.IsEmpty());
  double the_number = as_boxed->ValueOf();
  CHECK_EQ(42.0, the_number);
  v8::Local<v8::Value> new_boxed_number =
      v8::NumberObject::New(env->GetIsolate(), 43);
  CHECK(new_boxed_number->IsNumberObject());
  as_boxed = new_boxed_number.As<v8::NumberObject>();
  the_number = as_boxed->ValueOf();
  CHECK_EQ(43.0, the_number);
}

THREADED_TEST(BigIntObject) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::Context> context(env.local());
  v8::Local<Value> boxed_bigint = CompileRun("new Object(42n)");
  CHECK(!boxed_bigint->IsBigInt());
  CHECK(boxed_bigint->IsBigIntObject());
  v8::Local<Value> unboxed_bigint = CompileRun("42n");
  CHECK(unboxed_bigint->IsBigInt());
  CHECK(!unboxed_bigint->IsBigIntObject());
  v8::Local<v8::BigIntObject> as_boxed = boxed_bigint.As<v8::BigIntObject>();
  CHECK(!as_boxed.IsEmpty());
  v8::Local<v8::BigInt> unpacked = as_boxed->ValueOf();
  CHECK(!unpacked.IsEmpty());
  v8::Local<v8::Value> new_boxed_bigint = v8::BigIntObject::New(isolate, 43);
  CHECK(new_boxed_bigint->IsBigIntObject());
  v8::Local<v8::Value> new_unboxed_bigint = v8::BigInt::New(isolate, 44);
  CHECK(new_unboxed_bigint->IsBigInt());

  // Test functionality inherited from v8::Value.
  CHECK(unboxed_bigint->BooleanValue(isolate));
  v8::Local<v8::String> string =
      unboxed_bigint->ToString(context).ToLocalChecked();
  CHECK_EQ(0, strcmp("42", *v8::String::Utf8Value(isolate, string)));

  // IntegerValue throws.
  CHECK(unboxed_bigint->IntegerValue(context).IsNothing());
}

THREADED_TEST(BooleanObject) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::Local<Value> boxed_boolean = CompileRun("new Boolean(true)");
  CHECK(boxed_boolean->IsBooleanObject());
  v8::Local<Value> unboxed_boolean = CompileRun("true");
  CHECK(!unboxed_boolean->IsBooleanObject());
  v8::Local<Value> boxed_not_boolean = CompileRun("new Number(42)");
  CHECK(!boxed_not_boolean->IsBooleanObject());
  v8::Local<v8::BooleanObject> as_boxed = boxed_boolean.As<v8::BooleanObject>();
  CHECK(!as_boxed.IsEmpty());
  bool the_boolean = as_boxed->ValueOf();
  CHECK(the_boolean);
  v8::Local<v8::Value> boxed_true =
      v8::BooleanObject::New(env->GetIsolate(), true);
  v8::Local<v8::Value> boxed_false =
      v8::BooleanObject::New(env->GetIsolate(), false);
  CHECK(boxed_true->IsBooleanObject());
  CHECK(boxed_false->IsBooleanObject());
  as_boxed = boxed_true.As<v8::BooleanObject>();
  CHECK(as_boxed->ValueOf());
  as_boxed = boxed_false.As<v8::BooleanObject>();
  CHECK(!as_boxed->ValueOf());
}


THREADED_TEST(PrimitiveAndWrappedBooleans) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  Local<Value> primitive_false = Boolean::New(isolate, false);
  CHECK(primitive_false->IsBoolean());
  CHECK(!primitive_false->IsBooleanObject());
  CHECK(!primitive_false->BooleanValue(isolate));
  CHECK(!primitive_false->IsTrue());
  CHECK(primitive_false->IsFalse());

  Local<Value> false_value = BooleanObject::New(isolate, false);
  CHECK(!false_value->IsBoolean());
  CHECK(false_value->IsBooleanObject());
  CHECK(false_value->BooleanValue(isolate));
  CHECK(!false_value->IsTrue());
  CHECK(!false_value->IsFalse());

  Local<BooleanObject> false_boolean_object = false_value.As<BooleanObject>();
  CHECK(!false_boolean_object->IsBoolean());
  CHECK(false_boolean_object->IsBooleanObject());
  CHECK(false_boolean_object->BooleanValue(isolate));
  CHECK(!false_boolean_object->ValueOf());
  CHECK(!false_boolean_object->IsTrue());
  CHECK(!false_boolean_object->IsFalse());

  Local<Value> primitive_true = Boolean::New(isolate, true);
  CHECK(primitive_true->IsBoolean());
  CHECK(!primitive_true->IsBooleanObject());
  CHECK(primitive_true->BooleanValue(isolate));
  CHECK(primitive_true->IsTrue());
  CHECK(!primitive_true->IsFalse());

  Local<Value> true_value = BooleanObject::New(isolate, true);
  CHECK(!true_value->IsBoolean());
  CHECK(true_value->IsBooleanObject());
  CHECK(true_value->BooleanValue(isolate));
  CHECK(!true_value->IsTrue());
  CHECK(!true_value->IsFalse());

  Local<BooleanObject> true_boolean_object = true_value.As<BooleanObject>();
  CHECK(!true_boolean_object->IsBoolean());
  CHECK(true_boolean_object->IsBooleanObject());
  CHECK(true_boolean_object->BooleanValue(isolate));
  CHECK(true_boolean_object->ValueOf());
  CHECK(!true_boolean_object->IsTrue());
  CHECK(!true_boolean_object->IsFalse());
}


THREADED_TEST(Number) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  double PI = 3.1415926;
  Local<v8::Number> pi_obj = v8::Number::New(env->GetIsolate(), PI);
  CHECK_EQ(PI, pi_obj->NumberValue(env.local()).FromJust());
}


THREADED_TEST(ToNumber) {
  LocalContext env;
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  Local<String> str = v8_str("3.1415926");
  CHECK_EQ(3.1415926, str->NumberValue(env.local()).FromJust());
  v8::Local<v8::Boolean> t = v8::True(isolate);
  CHECK_EQ(1.0, t->NumberValue(env.local()).FromJust());
  v8::Local<v8::Boolean> f = v8::False(isolate);
  CHECK_EQ(0.0, f->NumberValue(env.local()).FromJust());
}


THREADED_TEST(Date) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  double PI = 3.1415926;
  Local<Value> date = v8::Date::New(env.local(), PI).ToLocalChecked();
  CHECK_EQ(3.0, date->NumberValue(env.local()).FromJust());
  CHECK(date.As<v8::Date>()
            ->Set(env.local(), v8_str("property"),
                  v8::Integer::New(env->GetIsolate(), 42))
            .FromJust());
  CHECK_EQ(42, date.As<v8::Date>()
                   ->Get(env.local(), v8_str("property"))
                   .ToLocalChecked()
                   ->Int32Value(env.local())
                   .FromJust());
}


THREADED_TEST(Boolean) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::Boolean> t = v8::True(isolate);
  CHECK(t->Value());
  v8::Local<v8::Boolean> f = v8::False(isolate);
  CHECK(!f->Value());
  v8::Local<v8::Primitive> u = v8::Undefined(isolate);
  CHECK(!u->BooleanValue(isolate));
  v8::Local<v8::Primitive> n = v8::Null(isolate);
  CHECK(!n->BooleanValue(isolate));
  v8::Local<String> str1 = v8_str("");
  CHECK(!str1->BooleanValue(isolate));
  v8::Local<String> str2 = v8_str("x");
  CHECK(str2->BooleanValue(isolate));
  CHECK(!v8::Number::New(isolate, 0)->BooleanValue(isolate));
  CHECK(v8::Number::New(isolate, -1)->BooleanValue(isolate));
  CHECK(v8::Number::New(isolate, 1)->BooleanValue(isolate));
  CHECK(v8::Number::New(isolate, 42)->BooleanValue(isolate));
  CHECK(!v8_compile("NaN")
             ->Run(env.local())
             .ToLocalChecked()
             ->BooleanValue(isolate));
}

static void DummyCallHandler(const v8::FunctionCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  ApiTestFuzzer::Fuzz();
  info.GetReturnValue().Set(v8_num(13.4));
}

static void GetM(Local<Name> name,
                 const v8::PropertyCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  ApiTestFuzzer::Fuzz();
  info.GetReturnValue().Set(v8_num(876));
}

THREADED_TEST(GlobalPrototype) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::FunctionTemplate> func_templ =
      v8::FunctionTemplate::New(isolate);
  func_templ->PrototypeTemplate()->Set(
      isolate, "dummy", v8::FunctionTemplate::New(isolate, DummyCallHandler));
  v8::Local<ObjectTemplate> templ = func_templ->InstanceTemplate();
  templ->Set(isolate, "x", v8_num(200));
  templ->SetNativeDataProperty(v8_str("m"), GetM);
  LocalContext env(nullptr, templ);
  v8::Local<Script> script(v8_compile("dummy()"));
  v8::Local<Value> result(script->Run(env.local()).ToLocalChecked());
  CHECK_EQ(13.4, result->NumberValue(env.local()).FromJust());
  CHECK_EQ(200, v8_run_int32value(v8_compile("x")));
  CHECK_EQ(876, v8_run_int32value(v8_compile("m")));
}


THREADED_TEST(ObjectTemplate) {
  LocalContext env;
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  Local<v8::FunctionTemplate> acc =
      v8::FunctionTemplate::New(isolate, Returns42);
  CHECK(env->Global()
            ->Set(env.local(), v8_str("acc"),
                  acc->GetFunction(env.local()).ToLocalChecked())
            .FromJust());

  Local<v8::FunctionTemplate> fun = v8::FunctionTemplate::New(isolate);
  v8::Local<v8::String> class_name = v8_str("the_class_name");
  fun->SetClassName(class_name);
  Local<ObjectTemplate> templ1 = ObjectTemplate::New(isolate, fun);
  templ1->Set(isolate, "x", v8_num(10));
  templ1->Set(isolate, "y", v8_num(13));
  templ1->Set(isolate, "foo", acc);
  Local<v8::Object> instance1 =
      templ1->NewInstance(env.local()).ToLocalChecked();
  CHECK(class_name->StrictEquals(instance1->GetConstructorName()));
  CHECK(env->Global()->Set(env.local(), v8_str("p"), instance1).FromJust());
  CHECK(CompileRun("(p.x == 10)")->BooleanValue(isolate));
  CHECK(CompileRun("(p.y == 13)")->BooleanValue(isolate));
  CHECK(CompileRun("(p.foo() == 42)")->BooleanValue(isolate));
  CHECK(CompileRun("(p.foo == acc)")->BooleanValue(isolate));
  // Ensure that foo become a data field.
  CompileRun("p.foo = function() {}");
  Local<v8::FunctionTemplate> fun2 = v8::FunctionTemplate::New(isolate);
  fun2->PrototypeTemplate()->Set(isolate, "nirk", v8_num(123));
  Local<ObjectTemplate> templ2 = fun2->InstanceTemplate();
  templ2->Set(isolate, "a", v8_num(12));
  templ2->Set(isolate, "b", templ1);
  templ2->Set(isolate, "bar", acc);
  templ2->SetAccessorProperty(v8_str("acc"), acc);
  Local<v8::Object> instance2 =
      templ2->NewInstance(env.local()).ToLocalChecked();
  CHECK(env->Global()->Set(env.local(), v8_str("q"), instance2).FromJust());
  CHECK(CompileRun("(q.nirk == 123)")->BooleanValue(isolate));
  CHECK(CompileRun("(q.a == 12)")->BooleanValue(isolate));
  CHECK(CompileRun("(q.b.x == 10)")->BooleanValue(isolate));
  CHECK(CompileRun("(q.b.y == 13)")->BooleanValue(isolate));
  CHECK(CompileRun("(q.b.foo() == 42)")->BooleanValue(isolate));
  CHECK(CompileRun("(q.b.foo === acc)")->BooleanValue(isolate));
  CHECK(CompileRun("(q.b !== p)")->BooleanValue(isolate));
  CHECK(CompileRun("(q.acc == 42)")->BooleanValue(isolate));
  CHECK(CompileRun("(q.bar() == 42)")->BooleanValue(isolate));
  CHECK(CompileRun("(q.bar == acc)")->BooleanValue(isolate));

  instance2 = templ2->NewInstance(env.local()).ToLocalChecked();
  CHECK(env->Global()->Set(env.local(), v8_str("q2"), instance2).FromJust());
  CHECK(CompileRun("(q2.nirk == 123)")->BooleanValue(isolate));
  CHECK(CompileRun("(q2.a == 12)")->BooleanValue(isolate));
  CHECK(CompileRun("(q2.b.x == 10)")->BooleanValue(isolate));
  CHECK(CompileRun("(q2.b.y == 13)")->BooleanValue(isolate));
  CHECK(CompileRun("(q2.b.foo() == 42)")->BooleanValue(isolate));
  CHECK(CompileRun("(q2.b.foo === acc)")->BooleanValue(isolate));
  CHECK(CompileRun("(q2.acc == 42)")->BooleanValue(isolate));
  CHECK(CompileRun("(q2.bar() == 42)")->BooleanValue(isolate));
  CHECK(CompileRun("(q2.bar === acc)")->BooleanValue(isolate));

  CHECK(CompileRun("(q.b !== q2.b)")->BooleanValue(isolate));
  CHECK(CompileRun("q.b.x = 17; (q2.b.x == 10)")->BooleanValue(isolate));
  CHECK(CompileRun("desc1 = Object.getOwnPropertyDescriptor(q, 'acc');"
                   "(desc1.get === acc)")
            ->BooleanValue(isolate));
  CHECK(CompileRun("desc2 = Object.getOwnPropertyDescriptor(q2, 'acc');"
                   "(desc2.get === acc)")
            ->BooleanValue(isolate));
}

THREADED_TEST(IntegerValue) {
  LocalContext env;
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);

  CHECK_EQ(0, CompileRun("undefined")->IntegerValue(env.local()).FromJust());
}

static void GetNirk(Local<Name> name,
                    const v8::PropertyCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  ApiTestFuzzer::Fuzz();
  info.GetReturnValue().Set(v8_num(900));
}

static void GetRino(Local<Name> name,
                    const v8::PropertyCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  ApiTestFuzzer::Fuzz();
  info.GetReturnValue().Set(v8_num(560));
}

enum ObjectInstantiationMode {
  // Create object using ObjectTemplate::NewInstance.
  ObjectTemplate_NewInstance,
  // Create object using FunctionTemplate::NewInstance on constructor.
  Constructor_GetFunction_NewInstance,
  // Create object using new operator on constructor.
  Constructor_GetFunction_New
};

// Test object instance creation using a function template with an instance
// template inherited from another function template with accessors and data
// properties in prototype template.
static void TestObjectTemplateInheritedWithPrototype(
    ObjectInstantiationMode mode) {
  LocalContext env;
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);

  Local<v8::FunctionTemplate> fun_A = v8::FunctionTemplate::New(isolate);
  fun_A->SetClassName(v8_str("A"));
  v8::Local<v8::ObjectTemplate> prototype_templ = fun_A->PrototypeTemplate();
  prototype_templ->Set(isolate, "a", v8_num(113));
  prototype_templ->SetNativeDataProperty(v8_str("nirk"), GetNirk);
  prototype_templ->Set(isolate, "b", v8_num(153));

  Local<v8::FunctionTemplate> fun_B = v8::FunctionTemplate::New(isolate);
  v8::Local<v8::String> class_name = v8_str("B");
  fun_B->SetClassName(class_name);
  fun_B->Inherit(fun_A);
  prototype_templ = fun_B->PrototypeTemplate();
  prototype_templ->Set(isolate, "c", v8_num(713));
  prototype_templ->SetNativeDataProperty(v8_str("rino"), GetRino);
  prototype_templ->Set(isolate, "d", v8_num(753));

  Local<ObjectTemplate> templ = fun_B->InstanceTemplate();
  templ->Set(isolate, "x", v8_num(10));
  templ->Set(isolate, "y", v8_num(13));

  // Perform several iterations to trigger creation from cached boilerplate.
  for (int i = 0; i < 3; i++) {
    Local<v8::Object> instance;
    switch (mode) {
      case ObjectTemplate_NewInstance:
        instance = templ->NewInstance(env.local()).ToLocalChecked();
        break;

      case Constructor_GetFunction_NewInstance: {
        Local<v8::Function> function_B =
            fun_B->GetFunction(env.local()).ToLocalChecked();
        instance = function_B->NewInstance(env.local()).ToLocalChecked();
        break;
      }
      case Constructor_GetFunction_New: {
        Local<v8::Function> function_B =
            fun_B->GetFunction(env.local()).ToLocalChecked();
        if (i == 0) {
          CHECK(env->Global()
                    ->Set(env.local(), class_name, function_B)
                    .FromJust());
        }
        instance =
            CompileRun("new B()")->ToObject(env.local()).ToLocalChecked();
        break;
      }
      default:
        UNREACHABLE();
    }

    CHECK(class_name->StrictEquals(instance->GetConstructorName()));
    CHECK(env->Global()->Set(env.local(), v8_str("o"), instance).FromJust());

    CHECK_EQ(10, CompileRun("o.x")->IntegerValue(env.local()).FromJust());
    CHECK_EQ(13, CompileRun("o.y")->IntegerValue(env.local()).FromJust());

    CHECK_EQ(113, CompileRun("o.a")->IntegerValue(env.local()).FromJust());
    CHECK_EQ(900, CompileRun("o.nirk")->IntegerValue(env.local()).FromJust());
    CHECK_EQ(153, CompileRun("o.b")->IntegerValue(env.local()).FromJust());
    CHECK_EQ(713, CompileRun("o.c")->IntegerValue(env.local()).FromJust());
    CHECK_EQ(560, CompileRun("o.rino")->IntegerValue(env.local()).FromJust());
    CHECK_EQ(753, CompileRun("o.d")->IntegerValue(env.local()).FromJust());
  }
}

THREADED_TEST(TestObjectTemplateInheritedWithAccessorsInPrototype1) {
  TestObjectTemplateInheritedWithPrototype(ObjectTemplate_NewInstance);
}

THREADED_TEST(TestObjectTemplateInheritedWithAccessorsInPrototype2) {
  TestObjectTemplateInheritedWithPrototype(Constructor_GetFunction_NewInstance);
}

THREADED_TEST(TestObjectTemplateInheritedWithAccessorsInPrototype3) {
  TestObjectTemplateInheritedWithPrototype(Constructor_GetFunction_New);
}

// Test object instance creation using a function template without an instance
// template inherited from another function template.
static void TestObjectTemplateInheritedWithoutInstanceTemplate(
    ObjectInstantiationMode mode) {
  LocalContext env;
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);

  Local<v8::FunctionTemplate> fun_A = v8::FunctionTemplate::New(isolate);
  fun_A->SetClassName(v8_str("A"));

  Local<ObjectTemplate> templ_A = fun_A->InstanceTemplate();
  templ_A->SetNativeDataProperty(v8_str("nirk"), GetNirk);
  templ_A->SetNativeDataProperty(v8_str("rino"), GetRino);

  Local<v8::FunctionTemplate> fun_B = v8::FunctionTemplate::New(isolate);
  v8::Local<v8::String> class_name = v8_str("B");
  fun_B->SetClassName(class_name);
  fun_B->Inherit(fun_A);

  // Perform several iterations to trigger creation from cached boilerplate.
  for (int i = 0; i < 3; i++) {
    Local<v8::Object> instance;
    switch (mode) {
      case Constructor_GetFunction_NewInstance: {
        Local<v8::Function> function_B =
            fun_B->GetFunction(env.local()).ToLocalChecked();
        instance = function_B->NewInstance(env.local()).ToLocalChecked();
        break;
      }
      case Constructor_GetFunction_New: {
        Local<v8::Function> function_B =
            fun_B->GetFunction(env.local()).ToLocalChecked();
        if (i == 0) {
          CHECK(env->Global()
                    ->Set(env.local(), class_name, function_B)
                    .FromJust());
        }
        instance =
            CompileRun("new B()")->ToObject(env.local()).ToLocalChecked();
        break;
      }
      default:
        UNREACHABLE();
    }

    CHECK(class_name->StrictEquals(instance->GetConstructorName()));
    CHECK(env->Global()->Set(env.local(), v8_str("o"), instance).FromJust());

    CHECK_EQ(900, CompileRun("o.nirk")->IntegerValue(env.local()).FromJust());
    CHECK_EQ(560, CompileRun("o.rino")->IntegerValue(env.local()).FromJust());
  }
}

THREADED_TEST(TestDataTypeChecks) {
  LocalContext env;
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);

  v8::Local<v8::Data> values[] = {
      v8::Undefined(isolate),
      v8::Null(isolate),
      v8::True(isolate),
      v8::Integer::New(isolate, 10),
      v8::Number::New(isolate, 3.14),
      v8::BigInt::NewFromUnsigned(isolate, 10),
      v8::Symbol::New(isolate),
      v8::String::NewFromUtf8Literal(isolate, "hello"),
  };
  for (auto x : values) {
    CHECK(!x->IsModule());
    CHECK(x->IsValue());
    CHECK(!x->IsPrivate());
    CHECK(!x->IsObjectTemplate());
    CHECK(!x->IsFunctionTemplate());
    v8::Local<v8::Value>::Cast(x);
    x.As<v8::Value>();
  }

  v8::ScriptOrigin origin(v8_str(""), 0, 0, false, -1, Local<v8::Value>(),
                          false, false, true);
  v8::ScriptCompiler::Source source(v8::String::NewFromUtf8Literal(isolate, ""),
                                    origin);
  v8::Local<v8::Data> module =
      v8::ScriptCompiler::CompileModule(isolate, &source).ToLocalChecked();
  CHECK(module->IsModule());
  CHECK(!module->IsValue());
  CHECK(!module->IsPrivate());
  CHECK(!module->IsObjectTemplate());
  CHECK(!module->IsFunctionTemplate());
  v8::Local<v8::Module>::Cast(module);
  module.As<v8::Module>();

  v8::Local<v8::Data> p = v8::Private::New(isolate);
  CHECK(!p->IsModule());
  CHECK(!p->IsValue());
  CHECK(p->IsPrivate());
  CHECK(!p->IsObjectTemplate());
  CHECK(!p->IsFunctionTemplate());
  CHECK(!(*reinterpret_cast<Local<Value>*>(&p))->IsSymbol());
  v8::Local<v8::Private>::Cast(p);

  v8::Local<v8::Data> otmpl = v8::ObjectTemplate::New(isolate);
  CHECK(!otmpl->IsModule());
  CHECK(!otmpl->IsValue());
  CHECK(!otmpl->IsPrivate());
  CHECK(otmpl->IsObjectTemplate());
  CHECK(!otmpl->IsFunctionTemplate());

  v8::Local<v8::Data> ftmpl = v8::FunctionTemplate::New(isolate);
  CHECK(!ftmpl->IsModule());
  CHECK(!ftmpl->IsValue());
  CHECK(!ftmpl->IsPrivate());
  CHECK(!ftmpl->IsObjectTemplate());
  CHECK(ftmpl->IsFunctionTemplate());
}

THREADED_TEST(TestObjectTemplateInheritedWithPrototype1) {
  TestObjectTemplateInheritedWithoutInstanceTemplate(
      Constructor_GetFunction_NewInstance);
}

THREADED_TEST(TestObjectTemplateInheritedWithPrototype2) {
  TestObjectTemplateInheritedWithoutInstanceTemplate(
      Constructor_GetFunction_New);
}

THREADED_TEST(TestObjectTemplateClassInheritance) {
  LocalContext env;
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);

  Local<v8::FunctionTemplate> fun_A = v8::FunctionTemplate::New(isolate);
  fun_A->SetClassName(v8_str("A"));

  Local<ObjectTemplate> templ_A = fun_A->InstanceTemplate();
  templ_A->SetNativeDataProperty(v8_str("nirk"), GetNirk);
  templ_A->SetNativeDataProperty(v8_str("rino"), GetRino);

  Local<v8::FunctionTemplate> fun_B = v8::FunctionTemplate::New(isolate);
  v8::Local<v8::String> class_name = v8_str("B");
  fun_B->SetClassName(class_name);
  fun_B->Inherit(fun_A);

  v8::Local<v8::String> subclass_name = v8_str("C");
  v8::Local<v8::Object> b_proto;
  v8::Local<v8::Object> c_proto;
  // Perform several iterations to make sure the cache doesn't break
  // subclassing.
  for (int i = 0; i < 3; i++) {
    Local<v8::Function> function_B =
        fun_B->GetFunction(env.local()).ToLocalChecked();
    if (i == 0) {
      CHECK(env->Global()->Set(env.local(), class_name, function_B).FromJust());
      CompileRun("class C extends B {}");
      b_proto =
          CompileRun("B.prototype")->ToObject(env.local()).ToLocalChecked();
      c_proto =
          CompileRun("C.prototype")->ToObject(env.local()).ToLocalChecked();
      CHECK(b_proto->Equals(env.local(), c_proto->GetPrototypeV2()).FromJust());
    }
    Local<v8::Object> instance =
        CompileRun("new C()")->ToObject(env.local()).ToLocalChecked();
    CHECK(c_proto->Equals(env.local(), instance->GetPrototypeV2()).FromJust());

    CHECK(subclass_name->StrictEquals(instance->GetConstructorName()));
    CHECK(env->Global()->Set(env.local(), v8_str("o"), instance).FromJust());

    CHECK_EQ(900, CompileRun("o.nirk")->IntegerValue(env.local()).FromJust());
    CHECK_EQ(560, CompileRun("o.rino")->IntegerValue(env.local()).FromJust());
  }
}

namespace {
v8::Intercepted NamedPropertyGetterWhichReturns42(
    Local<Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  info.GetReturnValue().Set(v8_num(42));
  return v8::Intercepted::kYes;
}
}  // namespace

THREADED_TEST(TestObjectTemplateReflectConstruct) {
  LocalContext env;
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);

  Local<v8::FunctionTemplate> fun_B = v8::FunctionTemplate::New(isolate);
  fun_B->InstanceTemplate()->SetHandler(
      v8::NamedPropertyHandlerConfiguration(NamedPropertyGetterWhichReturns42));
  v8::Local<v8::String> class_name = v8_str("B");
  fun_B->SetClassName(class_name);

  v8::Local<v8::String> subclass_name = v8_str("C");
  v8::Local<v8::Object> c_proto;
  // Perform several iterations to make sure the cache doesn't break
  // subclassing.
  for (int i = 0; i < 3; i++) {
    Local<v8::Function> function_B =
        fun_B->GetFunction(env.local()).ToLocalChecked();
    if (i == 0) {
      CHECK(env->Global()->Set(env.local(), class_name, function_B).FromJust());
      CompileRun("function C() {}");
      c_proto =
          CompileRun("C.prototype")->ToObject(env.local()).ToLocalChecked();
    }
    Local<v8::Object> instance = CompileRun("Reflect.construct(B, [], C)")
                                     ->ToObject(env.local())
                                     .ToLocalChecked();
    CHECK(c_proto->Equals(env.local(), instance->GetPrototypeV2()).FromJust());

    CHECK(subclass_name->StrictEquals(instance->GetConstructorName()));
    CHECK(env->Global()->Set(env.local(), v8_str("o"), instance).FromJust());

    CHECK_EQ(42, CompileRun("o.nirk")->IntegerValue(env.local()).FromJust());
    CHECK_EQ(42, CompileRun("o.rino")->IntegerValue(env.local()).FromJust());
  }
}

static void GetFlabby(const v8::FunctionCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  ApiTestFuzzer::Fuzz();
  info.GetReturnValue().Set(v8_num(17.2));
}

static void GetKnurd(Local<Name> property,
                     const v8::PropertyCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  ApiTestFuzzer::Fuzz();
  info.GetReturnValue().Set(v8_num(15.2));
}

THREADED_TEST(DescriptorInheritance) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::FunctionTemplate> super = v8::FunctionTemplate::New(isolate);
  super->PrototypeTemplate()->Set(isolate, "flabby",
                                  v8::FunctionTemplate::New(isolate,
                                                            GetFlabby));
  super->PrototypeTemplate()->Set(isolate, "PI", v8_num(3.14));

  super->InstanceTemplate()->SetNativeDataProperty(v8_str("knurd"), GetKnurd);

  v8::Local<v8::FunctionTemplate> base1 = v8::FunctionTemplate::New(isolate);
  base1->Inherit(super);
  base1->PrototypeTemplate()->Set(isolate, "v1", v8_num(20.1));

  v8::Local<v8::FunctionTemplate> base2 = v8::FunctionTemplate::New(isolate);
  base2->Inherit(super);
  base2->PrototypeTemplate()->Set(isolate, "v2", v8_num(10.1));

  LocalContext env;

  CHECK(env->Global()
            ->Set(env.local(), v8_str("s"),
                  super->GetFunction(env.local()).ToLocalChecked())
            .FromJust());
  CHECK(env->Global()
            ->Set(env.local(), v8_str("base1"),
                  base1->GetFunction(env.local()).ToLocalChecked())
            .FromJust());
  CHECK(env->Global()
            ->Set(env.local(), v8_str("base2"),
                  base2->GetFunction(env.local()).ToLocalChecked())
            .FromJust());

  // Checks right __proto__ chain.
  CHECK(CompileRun("base1.prototype.__proto__ == s.prototype")
            ->BooleanValue(isolate));
  CHECK(CompileRun("base2.prototype.__proto__ == s.prototype")
            ->BooleanValue(isolate));

  CHECK(v8_compile("s.prototype.PI == 3.14")
            ->Run(env.local())
            .ToLocalChecked()
            ->BooleanValue(isolate));

  // Instance accessor should not be visible on function object or its prototype
  CHECK(CompileRun("s.knurd == undefined")->BooleanValue(isolate));
  CHECK(CompileRun("s.prototype.knurd == undefined")->BooleanValue(isolate));
  CHECK(
      CompileRun("base1.prototype.knurd == undefined")->BooleanValue(isolate));

  CHECK(env->Global()
            ->Set(env.local(), v8_str("obj"), base1->GetFunction(env.local())
                                                  .ToLocalChecked()
                                                  ->NewInstance(env.local())
                                                  .ToLocalChecked())
            .FromJust());
  CHECK_EQ(17.2,
           CompileRun("obj.flabby()")->NumberValue(env.local()).FromJust());
  CHECK(CompileRun("'flabby' in obj")->BooleanValue(isolate));
  CHECK_EQ(15.2, CompileRun("obj.knurd")->NumberValue(env.local()).FromJust());
  CHECK(CompileRun("'knurd' in obj")->BooleanValue(isolate));
  CHECK_EQ(20.1, CompileRun("obj.v1")->NumberValue(env.local()).FromJust())
"""


```