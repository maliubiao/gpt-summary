Response:
Let's break down the thought process for analyzing this V8 header file.

1. **Understanding the Request:** The core request is to analyze the `v8-value.h` header file, describe its purpose, relate it to JavaScript functionality, and provide examples of usage and common errors. The initial conditional about `.tq` is a red herring since the file ends in `.h`.

2. **Initial Scan and Keyword Identification:** I'd start by quickly scanning the file, looking for keywords and structural elements:
    * `#ifndef`, `#define`, `#include`:  Standard C++ header guard and includes, indicating this is a C++ header file.
    * `namespace v8`:  Confirms it's part of the V8 namespace.
    * `class V8_EXPORT Value : public Data`:  The central class definition. `V8_EXPORT` suggests this is part of V8's public API. Inheritance from `Data` hints at a hierarchy of V8's internal data representation.
    *  A long list of `bool Is...()` methods:  These are the most prominent feature, suggesting type checking.
    * `MaybeLocal<>`, `Local<>`: V8's smart pointer types, indicating handling of potentially failing operations and garbage collection.
    * `To...()` methods:  These strongly suggest type conversion functionalities.
    * Comments with "ECMA-262":  Directly linking V8 concepts to JavaScript specifications.

3. **Core Functionality Identification (The "What"):**  Based on the keywords, the primary function of `v8-value.h` becomes clear: **It defines the `v8::Value` class, which represents all JavaScript values within the V8 engine.**  The `Is...()` methods are for type checking, and the `To...()` methods are for type conversion.

4. **Connecting to JavaScript (The "Why"):** The comments explicitly link the `Is...()` methods to JavaScript's `typeof` operator and equality comparisons (`===`, `==`). The `To...()` methods are linked to JavaScript's built-in conversion functions like `String()`, `Number()`, `Boolean()`, etc. This establishes the connection between the C++ representation and the user-facing JavaScript behavior.

5. **Illustrative JavaScript Examples:**  For each key group of methods (`Is...` and `To...`), concrete JavaScript examples are crucial. I would think:
    * `IsUndefined()`:  `variable === undefined`
    * `IsNull()`: `variable === null`
    * `IsString()`: `typeof variable === 'string'`
    * `ToNumber()`: `Number(variable)`
    * `ToString()`: `String(variable)`
    * `ToBoolean()`: `Boolean(variable)`

6. **Code Logic/Reasoning (The "How"):** The `TypecheckWitness` class is a bit more involved. The comments explain its purpose: optimizing type checks. I'd deduce the following logic:
    * It stores a "baseline" object's internal representation (likely its "map" or hidden class).
    * `Matches()` checks if a candidate object has the *same* internal representation as the baseline.
    * This is an optimization to avoid repeated expensive type checks, especially when dealing with collections of similar objects.
    * **Hypothetical Scenario:** Imagine a loop processing many DOM elements. If the first element is a `<div>`, and `Update()` is called, subsequent `Matches()` calls for other `<div>` elements can quickly return `true` without a full type check.

7. **Common Programming Errors:**  I'd focus on mistakes that arise from the distinctions highlighted in the header file itself:
    * **Confusing `Is...()` with type coercion:**  The difference between `IsTrue()` and `BooleanValue()` is a key point. Demonstrating this with examples like `if ("hello")` vs. checking if a variable is literally `true` is important.
    * **Incorrectly assuming object identity:** Emphasize that `IsArray()` doesn't work for proxies and that object wrappers exist for primitives.
    * **Ignoring the potential for `MaybeLocal` to be empty:** When using `To...()` methods, the result might not always be a valid object. This ties into error handling in the V8 API.

8. **Structure and Refinement:**  Finally, I'd organize the information logically:
    * Start with the basic purpose of the file.
    * Explain the core class `v8::Value` and its role.
    * Detail the functionalities provided by the `Is...()` and `To...()` methods, providing corresponding JavaScript examples.
    * Explain the purpose and logic of `TypecheckWitness`.
    * Provide concrete examples of common programming errors.
    * Add a summary to reinforce the key takeaways.

9. **Review and Accuracy:**  Before submitting the answer, I'd reread the header file and my analysis to ensure accuracy and completeness, double-checking the links between the C++ methods and their JavaScript equivalents. I'd also verify that the code examples are correct and illustrate the points effectively. For instance, I initially might forget to mention the `Local<Context>` parameter in some `To...` methods, but a careful review would catch that.
好的，让我们来分析一下 `v8/include/v8-value.h` 这个 V8 源代码文件。

**文件功能概述**

`v8/include/v8-value.h` 是 V8 JavaScript 引擎中非常核心的头文件。它定义了 `v8::Value` 类，这个类是所有 JavaScript 值和对象的基类。  简单来说，这个文件定义了 V8 如何在 C++ 层面表示和操作 JavaScript 世界中的各种数据类型。

**主要功能点:**

1. **定义 `v8::Value` 类:**  这是最重要的部分。`v8::Value` 是一个抽象基类，代表了 JavaScript 中的所有可能的值，包括：
   - 基本类型 (Primitive Types): `undefined`, `null`, boolean, string, number, symbol, bigint
   - 对象类型 (Object Types): 普通对象, 数组, 函数, 日期, 正则表达式等等。

2. **提供类型检查方法 (`Is...()`):**  `v8::Value` 类提供了大量的 `Is...()` 方法，用于判断一个 `v8::Value` 实例代表的是哪种 JavaScript 类型。例如：
   - `IsUndefined()`: 判断是否是 `undefined`
   - `IsNull()`: 判断是否是 `null`
   - `IsString()`: 判断是否是字符串
   - `IsNumber()`: 判断是否是数字
   - `IsObject()`: 判断是否是对象
   - `IsArray()`: 判断是否是数组
   - ...以及更多针对特定类型的判断方法。

3. **提供类型转换方法 (`To...()`):**  `v8::Value` 类还提供了一系列的 `To...()` 方法，用于将 `v8::Value` 实例转换为特定的 V8 类型。这些转换方法对应了 JavaScript 中的类型转换操作。例如：
   - `ToPrimitive()`:  对应 JavaScript 的 `ToPrimitive()` 抽象操作。
   - `ToNumber()`: 对应 JavaScript 的 `Number()` 转换。
   - `ToString()`: 对应 JavaScript 的 `String()` 转换。
   - `ToObject()`: 对应 JavaScript 的将值转换为对象。
   - `ToBoolean()`: 对应 JavaScript 的 `Boolean()` 转换。
   - `ToInt32()`, `ToUint32()`: 转换为 32 位有符号/无符号整数。

4. **提供比较方法 (`Equals()`, `StrictEquals()`, `SameValue()`):**  这些方法对应了 JavaScript 中的相等性比较操作 (`==`, `===`, `Object.is()`).

5. **提供其他辅助方法:** 例如 `TypeOf()` 用于获取值的类型字符串表示。

6. **`TypecheckWitness` 类:**  这个类用于优化类型检查。它可以缓存一个对象的类型信息，然后快速地检查其他对象是否具有相同的类型结构，避免重复进行昂贵的类型检查。

**关于 `.tq` 后缀**

如果 `v8/include/v8-value.h` 以 `.tq` 结尾，那么它确实是一个 V8 Torque 源代码文件。Torque 是 V8 使用的一种用于定义运行时内置函数和类型的领域特定语言。但是，根据你提供的目录结构和文件名，这个文件是 `.h` 后缀，所以它是一个标准的 C++ 头文件。

**与 JavaScript 功能的关系及 JavaScript 示例**

`v8/include/v8-value.h` 中定义的功能与 JavaScript 的核心概念息息相关。 几乎每一个 JavaScript 操作都涉及到对值的类型的判断和转换。

**1. 类型检查 (`Is...()` 方法)**

```javascript
const value1 = undefined;
const value2 = null;
const value3 = "hello";
const value4 = 123;
const value5 = { name: "John" };
const value6 = [1, 2, 3];
const value7 = true;
const value8 = Symbol("mySymbol");
const value9 = 9007199254740991n; // BigInt

// 在 V8 的 C++ 代码中，会使用类似的方法来判断值的类型
// 例如，当 JavaScript 引擎执行到 `typeof value1` 时，
// 内部可能会调用类似 `value->IsUndefined()` 的方法。

console.log(typeof value1 === 'undefined'); // true (对应 v8::Value::IsUndefined())
console.log(value2 === null);             // true (对应 v8::Value::IsNull())
console.log(typeof value3 === 'string');    // true (对应 v8::Value::IsString())
console.log(typeof value4 === 'number');    // true (对应 v8::Value::IsNumber())
console.log(typeof value5 === 'object');    // true (对应 v8::Value::IsObject())
console.log(Array.isArray(value6));         // true (对应 v8::Value::IsArray())
console.log(typeof value7 === 'boolean');   // true (对应 v8::Value::IsBoolean())
console.log(typeof value8 === 'symbol');    // true (对应 v8::Value::IsSymbol())
console.log(typeof value9 === 'bigint');    // true (对应 v8::Value::IsBigInt())
```

**2. 类型转换 (`To...()` 方法)**

```javascript
const val1 = 10;
const val2 = "20";
const val3 = { valueOf: () => 30 };
const val4 = false;

// 对应 v8::Value::ToNumber()
console.log(Number(val2));   // 20
console.log(Number(val3));   // 30
console.log(Number(val4));   // 0

// 对应 v8::Value::ToString()
console.log(String(val1));   // "10"
console.log(String(val3));   // "[object Object]"
console.log(String(val4));   // "false"

// 对应 v8::Value::ToBoolean()
console.log(Boolean(val1));  // true
console.log(Boolean(val2));  // true
console.log(Boolean(0));     // false

// 对应 v8::Value::ToInt32() 和 v8::Value::ToUint32()
console.log(parseInt("42.9")); // 42 (内部涉及转换为整数)
```

**3. 类型比较 (`Equals()`, `StrictEquals()`, `SameValue()` 方法)**

```javascript
const a = 10;
const b = "10";
const c = 10;
const d = new Number(10);

// 对应 v8::Value::Equals() (JavaScript 的 == 比较)
console.log(a == b); // true (类型转换后值相等)

// 对应 v8::Value::StrictEquals() (JavaScript 的 === 比较)
console.log(a === b); // false (类型不同)
console.log(a === c); // true (类型和值都相等)
console.log(a === d); // false (对象与原始值比较)

// 对应 v8::Value::SameValue() (类似 Object.is())
console.log(Object.is(a, b)); // false
console.log(Object.is(NaN, NaN)); // true (与 === 不同)
console.log(Object.is(+0, -0));   // false (与 === 不同)
```

**代码逻辑推理 (假设输入与输出)**

假设我们有一个 `v8::Value` 类型的变量 `myValue`，它实际上指向一个 JavaScript 字符串 `"test"`。

```c++
// 假设在 V8 引擎内部
v8::Local<v8::Value> myValue = v8::String::NewFromUtf8(isolate, "test").ToLocalChecked();

// 调用类型检查方法
bool isString = myValue->IsString(); // 输入: myValue (指向字符串 "test")， 输出: true
bool isNumber = myValue->IsNumber(); // 输入: myValue， 输出: false

// 调用类型转换方法
v8::MaybeLocal<v8::String> maybeString = myValue->ToString(context);
v8::Local<v8::String> stringValue = maybeString.ToLocalChecked(); // 输入: myValue， 输出: 指向字符串 "test" 的 v8::String

v8::MaybeLocal<v8::Number> maybeNumber = myValue->ToNumber(context);
// maybeNumber 将会是一个空值，因为无法安全地将字符串 "test" 转换为数字
```

**用户常见的编程错误**

1. **混淆 `Is...()` 和类型转换/真值判断:**

   ```javascript
   const value = 0;

   if (value) { // 错误地认为 0 是 truthy
       console.log("This will not be printed");
   }

   // 正确的做法是检查类型或显式比较
   if (typeof value === 'number' && value !== 0) {
       console.log("This is more accurate for checking non-zero numbers");
   }

   // 在 V8 内部，`Value::IsNumber()` 会返回 true，但 `ToBoolean()->Value()` 会返回 false。
   ```

2. **错误地假设对象类型:**

   ```javascript
   function MyObject() {}
   const obj = new MyObject();

   console.log(typeof obj === 'object'); // true
   console.log(obj instanceof MyObject); // true

   // 但在 V8 内部，可能需要更精细的类型检查，例如检查构造函数或内部结构。
   ```

3. **忽略 `MaybeLocal` 的返回值:**

   当使用 `To...()` 方法时，如果转换失败，会返回一个空的 `MaybeLocal`。如果用户不检查返回值，可能会导致程序崩溃或未定义的行为。

   ```c++
   v8::MaybeLocal<v8::Number> maybeNumber = someValue->ToNumber(context);
   v8::Local<v8::Number> numberValue = maybeNumber.ToLocalChecked(); // 如果转换失败，这里会抛出异常
   ```

   正确的做法是：

   ```c++
   v8::MaybeLocal<v8::Number> maybeNumber = someValue->ToNumber(context);
   if (!maybeNumber.IsEmpty()) {
       v8::Local<v8::Number> numberValue = maybeNumber.ToLocalChecked();
       // ... 使用 numberValue
   } else {
       // 处理转换失败的情况
   }
   ```

**总结**

`v8/include/v8-value.h` 是 V8 引擎中定义 JavaScript 值表示和操作的核心头文件。它提供了丰富的 API 用于类型检查、类型转换和比较，是 V8 引擎实现 JavaScript 语义的基础。理解这个文件的内容对于深入了解 V8 的内部工作机制至关重要。

### 提示词
```
这是目录为v8/include/v8-value.h的一个v8源代码， 请列举一下它的功能, 
如果v8/include/v8-value.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef INCLUDE_V8_VALUE_H_
#define INCLUDE_V8_VALUE_H_

#include "v8-data.h"          // NOLINT(build/include_directory)
#include "v8-internal.h"      // NOLINT(build/include_directory)
#include "v8-local-handle.h"  // NOLINT(build/include_directory)
#include "v8-maybe.h"         // NOLINT(build/include_directory)
#include "v8config.h"         // NOLINT(build/include_directory)

/**
 * The v8 JavaScript engine.
 */
namespace v8 {

class Primitive;
class Numeric;
class BigInt;
class Int32;
class Integer;
class Number;
class Object;
class String;
class Uint32;

/**
 * The superclass of all JavaScript values and objects.
 */
class V8_EXPORT Value : public Data {
 public:
  /**
   * Returns true if this value is the undefined value.  See ECMA-262
   * 4.3.10.
   *
   * This is equivalent to `value === undefined` in JS.
   */
  V8_INLINE bool IsUndefined() const;

  /**
   * Returns true if this value is the null value.  See ECMA-262
   * 4.3.11.
   *
   * This is equivalent to `value === null` in JS.
   */
  V8_INLINE bool IsNull() const;

  /**
   * Returns true if this value is either the null or the undefined value.
   * See ECMA-262
   * 4.3.11. and 4.3.12
   *
   * This is equivalent to `value == null` in JS.
   */
  V8_INLINE bool IsNullOrUndefined() const;

  /**
   * Returns true if this value is true.
   *
   * This is not the same as `BooleanValue()`. The latter performs a
   * conversion to boolean, i.e. the result of `Boolean(value)` in JS, whereas
   * this checks `value === true`.
   */
  V8_INLINE bool IsTrue() const;

  /**
   * Returns true if this value is false.
   *
   * This is not the same as `!BooleanValue()`. The latter performs a
   * conversion to boolean, i.e. the result of `!Boolean(value)` in JS, whereas
   * this checks `value === false`.
   */
  V8_INLINE bool IsFalse() const;

  /**
   * Returns true if this value is a symbol or a string.
   *
   * This is equivalent to
   * `typeof value === 'string' || typeof value === 'symbol'` in JS.
   */
  bool IsName() const;

  /**
   * Returns true if this value is an instance of the String type.
   * See ECMA-262 8.4.
   *
   * This is equivalent to `typeof value === 'string'` in JS.
   */
  V8_INLINE bool IsString() const;

  /**
   * Returns true if this value is a symbol.
   *
   * This is equivalent to `typeof value === 'symbol'` in JS.
   */
  bool IsSymbol() const;

  /**
   * Returns true if this value is a function.
   *
   * This is equivalent to `typeof value === 'function'` in JS.
   */
  bool IsFunction() const;

  /**
   * Returns true if this value is an array. Note that it will return false for
   * an Proxy for an array.
   */
  bool IsArray() const;

  /**
   * Returns true if this value is an object.
   */
  bool IsObject() const;

  /**
   * Returns true if this value is a bigint.
   *
   * This is equivalent to `typeof value === 'bigint'` in JS.
   */
  bool IsBigInt() const;

  /**
   * Returns true if this value is boolean.
   *
   * This is equivalent to `typeof value === 'boolean'` in JS.
   */
  bool IsBoolean() const;

  /**
   * Returns true if this value is a number.
   *
   * This is equivalent to `typeof value === 'number'` in JS.
   */
  bool IsNumber() const;

  /**
   * Returns true if this value is an `External` object.
   */
  bool IsExternal() const;

  /**
   * Returns true if this value is a 32-bit signed integer.
   */
  bool IsInt32() const;

  /**
   * Returns true if this value is a 32-bit unsigned integer.
   */
  bool IsUint32() const;

  /**
   * Returns true if this value is a Date.
   */
  bool IsDate() const;

  /**
   * Returns true if this value is an Arguments object.
   */
  bool IsArgumentsObject() const;

  /**
   * Returns true if this value is a BigInt object.
   */
  bool IsBigIntObject() const;

  /**
   * Returns true if this value is a Boolean object.
   */
  bool IsBooleanObject() const;

  /**
   * Returns true if this value is a Number object.
   */
  bool IsNumberObject() const;

  /**
   * Returns true if this value is a String object.
   */
  bool IsStringObject() const;

  /**
   * Returns true if this value is a Symbol object.
   */
  bool IsSymbolObject() const;

  /**
   * Returns true if this value is a NativeError.
   */
  bool IsNativeError() const;

  /**
   * Returns true if this value is a RegExp.
   */
  bool IsRegExp() const;

  /**
   * Returns true if this value is an async function.
   */
  bool IsAsyncFunction() const;

  /**
   * Returns true if this value is a Generator function.
   */
  bool IsGeneratorFunction() const;

  /**
   * Returns true if this value is a Generator object (iterator).
   */
  bool IsGeneratorObject() const;

  /**
   * Returns true if this value is a Promise.
   */
  bool IsPromise() const;

  /**
   * Returns true if this value is a Map.
   */
  bool IsMap() const;

  /**
   * Returns true if this value is a Set.
   */
  bool IsSet() const;

  /**
   * Returns true if this value is a Map Iterator.
   */
  bool IsMapIterator() const;

  /**
   * Returns true if this value is a Set Iterator.
   */
  bool IsSetIterator() const;

  /**
   * Returns true if this value is a WeakMap.
   */
  bool IsWeakMap() const;

  /**
   * Returns true if this value is a WeakSet.
   */
  bool IsWeakSet() const;

  /**
   * Returns true if this value is a WeakRef.
   */
  bool IsWeakRef() const;

  /**
   * Returns true if this value is an ArrayBuffer.
   */
  bool IsArrayBuffer() const;

  /**
   * Returns true if this value is an ArrayBufferView.
   */
  bool IsArrayBufferView() const;

  /**
   * Returns true if this value is one of TypedArrays.
   */
  bool IsTypedArray() const;

  /**
   * Returns true if this value is an Uint8Array.
   */
  bool IsUint8Array() const;

  /**
   * Returns true if this value is an Uint8ClampedArray.
   */
  bool IsUint8ClampedArray() const;

  /**
   * Returns true if this value is an Int8Array.
   */
  bool IsInt8Array() const;

  /**
   * Returns true if this value is an Uint16Array.
   */
  bool IsUint16Array() const;

  /**
   * Returns true if this value is an Int16Array.
   */
  bool IsInt16Array() const;

  /**
   * Returns true if this value is an Uint32Array.
   */
  bool IsUint32Array() const;

  /**
   * Returns true if this value is an Int32Array.
   */
  bool IsInt32Array() const;

  /**
   * Returns true if this value is a Float16Array.
   */
  bool IsFloat16Array() const;

  /**
   * Returns true if this value is a Float32Array.
   */
  bool IsFloat32Array() const;

  /**
   * Returns true if this value is a Float64Array.
   */
  bool IsFloat64Array() const;

  /**
   * Returns true if this value is a BigInt64Array.
   */
  bool IsBigInt64Array() const;

  /**
   * Returns true if this value is a BigUint64Array.
   */
  bool IsBigUint64Array() const;

  /**
   * Returns true if this value is a DataView.
   */
  bool IsDataView() const;

  /**
   * Returns true if this value is a SharedArrayBuffer.
   */
  bool IsSharedArrayBuffer() const;

  /**
   * Returns true if this value is a JavaScript Proxy.
   */
  bool IsProxy() const;

  /**
   * Returns true if this value is a WasmMemoryObject.
   */
  bool IsWasmMemoryObject() const;

  /**
   * Returns true if this value is a WasmModuleObject.
   */
  bool IsWasmModuleObject() const;

  /**
   * Returns true if this value is the WasmNull object.
   */
  bool IsWasmNull() const;

  /**
   * Returns true if the value is a Module Namespace Object.
   */
  bool IsModuleNamespaceObject() const;

  /**
   * Perform `ToPrimitive(value)` as specified in:
   * https://tc39.es/ecma262/#sec-toprimitive.
   */
  V8_WARN_UNUSED_RESULT MaybeLocal<Primitive> ToPrimitive(
      Local<Context> context) const;
  /**
   * Perform `ToNumeric(value)` as specified in:
   * https://tc39.es/ecma262/#sec-tonumeric.
   */
  V8_WARN_UNUSED_RESULT MaybeLocal<Numeric> ToNumeric(
      Local<Context> context) const;
  /**
   * Perform the equivalent of `BigInt(value)` in JS.
   */
  V8_WARN_UNUSED_RESULT MaybeLocal<BigInt> ToBigInt(
      Local<Context> context) const;
  /**
   * Perform the equivalent of `Number(value)` in JS.
   */
  V8_WARN_UNUSED_RESULT MaybeLocal<Number> ToNumber(
      Local<Context> context) const;
  /**
   * Perform the equivalent of `String(value)` in JS.
   */
  V8_WARN_UNUSED_RESULT MaybeLocal<String> ToString(
      Local<Context> context) const;
  /**
   * Provide a string representation of this value usable for debugging.
   * This operation has no observable side effects and will succeed
   * unless e.g. execution is being terminated.
   */
  V8_WARN_UNUSED_RESULT MaybeLocal<String> ToDetailString(
      Local<Context> context) const;
  /**
   * Perform the equivalent of `Tagged<Object>(value)` in JS.
   */
  V8_WARN_UNUSED_RESULT MaybeLocal<Object> ToObject(
      Local<Context> context) const;
  /**
   * Perform the equivalent of `Number(value)` in JS and convert the result
   * to an integer. Negative values are rounded up, positive values are rounded
   * down. NaN is converted to 0. Infinite values yield undefined results.
   */
  V8_WARN_UNUSED_RESULT MaybeLocal<Integer> ToInteger(
      Local<Context> context) const;
  /**
   * Perform the equivalent of `Number(value)` in JS and convert the result
   * to an unsigned 32-bit integer by performing the steps in
   * https://tc39.es/ecma262/#sec-touint32.
   */
  V8_WARN_UNUSED_RESULT MaybeLocal<Uint32> ToUint32(
      Local<Context> context) const;
  /**
   * Perform the equivalent of `Number(value)` in JS and convert the result
   * to a signed 32-bit integer by performing the steps in
   * https://tc39.es/ecma262/#sec-toint32.
   */
  V8_WARN_UNUSED_RESULT MaybeLocal<Int32> ToInt32(Local<Context> context) const;

  /**
   * Perform the equivalent of `Boolean(value)` in JS. This can never fail.
   */
  Local<Boolean> ToBoolean(Isolate* isolate) const;

  /**
   * Attempts to convert a string to an array index.
   * Returns an empty handle if the conversion fails.
   */
  V8_WARN_UNUSED_RESULT MaybeLocal<Uint32> ToArrayIndex(
      Local<Context> context) const;

  /** Returns the equivalent of `ToBoolean()->Value()`. */
  bool BooleanValue(Isolate* isolate) const;

  /** Returns the equivalent of `ToNumber()->Value()`. */
  V8_WARN_UNUSED_RESULT Maybe<double> NumberValue(Local<Context> context) const;
  /** Returns the equivalent of `ToInteger()->Value()`. */
  V8_WARN_UNUSED_RESULT Maybe<int64_t> IntegerValue(
      Local<Context> context) const;
  /** Returns the equivalent of `ToUint32()->Value()`. */
  V8_WARN_UNUSED_RESULT Maybe<uint32_t> Uint32Value(
      Local<Context> context) const;
  /** Returns the equivalent of `ToInt32()->Value()`. */
  V8_WARN_UNUSED_RESULT Maybe<int32_t> Int32Value(Local<Context> context) const;

  /** JS == */
  V8_WARN_UNUSED_RESULT Maybe<bool> Equals(Local<Context> context,
                                           Local<Value> that) const;
  bool StrictEquals(Local<Value> that) const;
  bool SameValue(Local<Value> that) const;

  template <class T>
  V8_INLINE static Value* Cast(T* value) {
    return static_cast<Value*>(value);
  }

  Local<String> TypeOf(Isolate*);

  Maybe<bool> InstanceOf(Local<Context> context, Local<Object> object);

 private:
  V8_INLINE bool QuickIsUndefined() const;
  V8_INLINE bool QuickIsNull() const;
  V8_INLINE bool QuickIsNullOrUndefined() const;
#if V8_STATIC_ROOTS_BOOL
  V8_INLINE bool QuickIsTrue() const;
  V8_INLINE bool QuickIsFalse() const;
#endif  // V8_STATIC_ROOTS_BOOL
  V8_INLINE bool QuickIsString() const;
  bool FullIsUndefined() const;
  bool FullIsNull() const;
  bool FullIsTrue() const;
  bool FullIsFalse() const;
  bool FullIsString() const;

  static void CheckCast(Data* that);
};

/**
 * Can be used to avoid repeated expensive type checks for groups of objects
 * that are expected to be similar (e.g. when Blink converts a bunch of
 * JavaScript objects to "ScriptWrappable" after a "HasInstance" check) by
 * making use of V8-internal "hidden classes". An object that has passed the
 * full check can be remembered via {Update}; further objects can be queried
 * using {Matches}.
 * Note that the answer will be conservative/"best-effort": when {Matches}
 * returns true, then the {candidate} can be relied upon to have the same
 * shape/constructor/prototype/etc. as the {baseline}. Otherwise, no reliable
 * statement can be made (the objects might still have indistinguishable shapes
 * for all intents and purposes, but this mechanism, being optimized for speed,
 * couldn't determine that quickly).
 */
class V8_EXPORT TypecheckWitness {
 public:
  explicit TypecheckWitness(Isolate* isolate);

  /**
   * Checks whether {candidate} can cheaply be identified as being "similar"
   * to the {baseline} that was passed to {Update} earlier.
   * It's safe to call this on an uninitialized {TypecheckWitness} instance:
   * it will then return {false} for any input.
   */
  V8_INLINE bool Matches(Local<Value> candidate) const;

  /**
   * Remembers a new baseline for future {Matches} queries.
   */
  void Update(Local<Value> baseline);

 private:
  Local<Data> cached_map_;
};

template <>
V8_INLINE Value* Value::Cast(Data* value) {
#ifdef V8_ENABLE_CHECKS
  CheckCast(value);
#endif
  return static_cast<Value*>(value);
}

bool Value::IsUndefined() const {
#ifdef V8_ENABLE_CHECKS
  return FullIsUndefined();
#else
  return QuickIsUndefined();
#endif
}

bool Value::QuickIsUndefined() const {
  using A = internal::Address;
  using I = internal::Internals;
  A obj = internal::ValueHelper::ValueAsAddress(this);
#if V8_STATIC_ROOTS_BOOL
  return I::is_identical(obj, I::StaticReadOnlyRoot::kUndefinedValue);
#else
  if (!I::HasHeapObjectTag(obj)) return false;
  if (I::GetInstanceType(obj) != I::kOddballType) return false;
  return (I::GetOddballKind(obj) == I::kUndefinedOddballKind);
#endif  // V8_STATIC_ROOTS_BOOL
}

bool Value::IsNull() const {
#ifdef V8_ENABLE_CHECKS
  return FullIsNull();
#else
  return QuickIsNull();
#endif
}

bool Value::QuickIsNull() const {
  using A = internal::Address;
  using I = internal::Internals;
  A obj = internal::ValueHelper::ValueAsAddress(this);
#if V8_STATIC_ROOTS_BOOL
  return I::is_identical(obj, I::StaticReadOnlyRoot::kNullValue);
#else
  if (!I::HasHeapObjectTag(obj)) return false;
  if (I::GetInstanceType(obj) != I::kOddballType) return false;
  return (I::GetOddballKind(obj) == I::kNullOddballKind);
#endif  // V8_STATIC_ROOTS_BOOL
}

bool Value::IsNullOrUndefined() const {
#ifdef V8_ENABLE_CHECKS
  return FullIsNull() || FullIsUndefined();
#else
  return QuickIsNullOrUndefined();
#endif
}

bool Value::QuickIsNullOrUndefined() const {
#if V8_STATIC_ROOTS_BOOL
  return QuickIsNull() || QuickIsUndefined();
#else
  using A = internal::Address;
  using I = internal::Internals;
  A obj = internal::ValueHelper::ValueAsAddress(this);
  if (!I::HasHeapObjectTag(obj)) return false;
  if (I::GetInstanceType(obj) != I::kOddballType) return false;
  int kind = I::GetOddballKind(obj);
  return kind == I::kNullOddballKind || kind == I::kUndefinedOddballKind;
#endif  // V8_STATIC_ROOTS_BOOL
}

bool Value::IsTrue() const {
#if V8_STATIC_ROOTS_BOOL && !defined(V8_ENABLE_CHECKS)
  return QuickIsTrue();
#else
  return FullIsTrue();
#endif
}

#if V8_STATIC_ROOTS_BOOL
bool Value::QuickIsTrue() const {
  using A = internal::Address;
  using I = internal::Internals;
  A obj = internal::ValueHelper::ValueAsAddress(this);
  return I::is_identical(obj, I::StaticReadOnlyRoot::kTrueValue);
}
#endif  // V8_STATIC_ROOTS_BOOL

bool Value::IsFalse() const {
#if V8_STATIC_ROOTS_BOOL && !defined(V8_ENABLE_CHECKS)
  return QuickIsFalse();
#else
  return FullIsFalse();
#endif
}

#if V8_STATIC_ROOTS_BOOL
bool Value::QuickIsFalse() const {
  using A = internal::Address;
  using I = internal::Internals;
  A obj = internal::ValueHelper::ValueAsAddress(this);
  return I::is_identical(obj, I::StaticReadOnlyRoot::kFalseValue);
}
#endif  // V8_STATIC_ROOTS_BOOL

bool Value::IsString() const {
#ifdef V8_ENABLE_CHECKS
  return FullIsString();
#else
  return QuickIsString();
#endif
}

bool Value::QuickIsString() const {
  using A = internal::Address;
  using I = internal::Internals;
  A obj = internal::ValueHelper::ValueAsAddress(this);
  if (!I::HasHeapObjectTag(obj)) return false;
#if V8_STATIC_ROOTS_BOOL && !V8_MAP_PACKING
  return I::CheckInstanceMapRange(obj,
                                  I::StaticReadOnlyRoot::kStringMapLowerBound,
                                  I::StaticReadOnlyRoot::kStringMapUpperBound);
#else
  return (I::GetInstanceType(obj) < I::kFirstNonstringType);
#endif  // V8_STATIC_ROOTS_BOOL
}

bool TypecheckWitness::Matches(Local<Value> candidate) const {
  internal::Address obj = internal::ValueHelper::ValueAsAddress(*candidate);
  internal::Address obj_map = internal::Internals::LoadMap(obj);
  internal::Address cached =
      internal::ValueHelper::ValueAsAddress(*cached_map_);
  return obj_map == cached;
}

}  // namespace v8

#endif  // INCLUDE_V8_VALUE_H_
```