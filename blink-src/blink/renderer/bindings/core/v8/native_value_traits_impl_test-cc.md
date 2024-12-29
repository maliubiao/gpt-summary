Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Identify the Core Purpose:** The filename `native_value_traits_impl_test.cc` immediately suggests this file tests the implementation of `NativeValueTraits`. The `_test.cc` suffix confirms it's a unit test file. The `blink/renderer/bindings/core/v8/` path points to the V8 (JavaScript engine) binding layer within the Blink rendering engine. Therefore, the primary goal is to test how C++ code interacts with JavaScript values.

2. **Scan for Key Concepts and Data Structures:** Quickly read through the `#include` directives and the code itself to identify the major components being tested:
    * `NativeValueTraits`: This is the central class being tested. It's likely responsible for converting JavaScript values to their corresponding C++ representations.
    * `IDLInterface`, `IDLRecord`, `IDLSequence`, `IDLBigint`, `PassAsSpan`: These are likely IDL (Interface Definition Language) types or related constructs used in the Blink bindings. They represent different ways data can be passed between JavaScript and C++.
    * `V8TestingScope`:  This suggests a testing framework that provides a V8 environment.
    * `DummyExceptionStateForTesting`, `NonThrowableExceptionState`: These indicate mechanisms for handling errors and exceptions during the value conversion process.
    * `TEST(...)`:  This confirms the use of Google Test for writing unit tests.
    * `EXPECT_TRUE`, `EXPECT_EQ`, `EXPECT_THAT`:  These are Google Test assertion macros.

3. **Analyze Individual Tests:** Go through each `TEST` function and understand what it's trying to verify:

    * **`IDLInterface`:** Checks the behavior when attempting to convert a JavaScript number to a C++ object (`Internals`). It expects a failure.
    * **`IDLRecord`:**  Tests the conversion of JavaScript objects to C++ `IDLRecord`s (essentially key-value pairs). It covers different scenarios, including empty objects, objects with different data types, enumerable properties, and handling of proxies and symbols.
    * **`IDLSequence`:**  Tests the conversion of JavaScript arrays and iterable objects to C++ `IDLSequence`s (vectors/lists). It checks various data types and nested sequences.
    * **`IDLBigint`:** Focuses on converting JavaScript `BigInt` values to the Blink `BigInt` C++ representation, also considering strings and objects with `valueOf`. It also tests a legacy behavior flag.
    * **`PassAsSpanBasic`, `PassAsSpanShared`, `PassAsSpanDetached`, `PassAsSpanDataView`, `PassAsSpanInlineStorage`, `PassAsSpanBadType`, `PassAsSpanMissingOpt`, `PassAsSpanCopy`, `TypedPassAsSpanBasic`, `TypedPassAsSpanSubarray`, `TypedPassAsSpanBadType`, `TypedPassAsSpanUint8`, `PassAsSpanAllowSequence`, `PassAsSpanSequenceOfUnrestricted`:** These tests thoroughly examine the `PassAsSpan` mechanism, which allows efficient sharing of memory between JavaScript and C++. They cover different types of buffers (ArrayBuffer, SharedArrayBuffer, DataView, inline storage), different data types within the buffers, handling of detached buffers, and the use of iterables as input.

4. **Identify Relationships with JavaScript, HTML, and CSS:** Based on the tested IDL types and the overall purpose of the file, infer the connections:

    * **JavaScript:** The entire file revolves around the interaction between C++ and JavaScript values. The tests directly manipulate and inspect JavaScript objects and arrays. The `EvaluateScriptForObject` and `EvaluateScriptForArray` functions are key in creating JavaScript values for testing.
    * **HTML:**  While not directly tested *in this file*, the data structures being tested (`IDLRecord`, `IDLSequence`, `PassAsSpan`) are frequently used to represent data passed between JavaScript and HTML elements or APIs. For example, attributes of HTML elements might be represented as records, and collections of elements or data might be represented as sequences. The `Internals` class (tested in a negative case) is a Blink-specific class providing access to internal browser functionality, often exposed to JavaScript.
    * **CSS:**  Similar to HTML, CSS properties and values can be represented using these IDL types when interacting with JavaScript. For instance, the `style` property of an HTML element exposes CSS properties as a JavaScript object (which could be tested with `IDLRecord`), and operations like getting computed styles might return sequences of values.

5. **Infer Logic and Potential Errors:** For each test, consider:

    * **Assumptions:** What is the test setting up? What kind of JavaScript value is being passed? What is the expected C++ type?
    * **Expected Output:** What should the `NativeValueTraits` conversion produce? What are the assertions checking?
    * **Potential Errors:**  What happens if the JavaScript value is of the wrong type? What if it's `null` or `undefined`? What if the conversion logic has bugs? The tests with `DummyExceptionStateForTesting` specifically target error handling.
    * **User/Programming Errors:**  Consider how a developer might misuse the API or encounter issues. For example, passing a regular JavaScript object when an ArrayBuffer is expected for `PassAsSpan`, or providing data of the wrong type for a typed array.

6. **Trace User Operations (Debugging Perspective):** Think about how a user action in a web browser could lead to this code being executed:

    * A JavaScript function is called that expects a specific data structure.
    * The browser needs to pass data from JavaScript back to C++ (e.g., when handling events or calling internal APIs).
    * A web API is used that involves transferring data efficiently (like `ArrayBuffer` manipulation).
    * An error occurs during the data transfer, and the developer needs to understand how the JavaScript value was being converted in C++.

7. **Structure the Explanation:** Organize the findings into logical sections (Functions, Relationships, Logic, Errors, Debugging) for clarity. Use examples to illustrate the connections with JavaScript, HTML, and CSS. Clearly separate assumptions, inputs, and outputs for the logical inferences.

By following these steps, one can effectively analyze the C++ test file, understand its purpose, and explain its relevance within the broader context of a web browser engine.
这个C++源代码文件 `native_value_traits_impl_test.cc` 是 Chromium Blink 渲染引擎的一部分，专门用于测试 `NativeValueTraits` 模板类的实现。 `NativeValueTraits` 的核心功能是在 Blink 引擎中实现 JavaScript 值和 C++ 值之间的相互转换。

**主要功能:**

1. **测试 JavaScript 值到 C++ 值的转换:**  该文件包含了大量的单元测试，验证了 `NativeValueTraits` 能够正确地将各种 JavaScript 类型的值转换为对应的 C++ 类型。 这涵盖了基本类型（如数字、字符串、布尔值）、复杂类型（如对象、数组、BigInt）以及特定的 IDL (Interface Definition Language) 类型（如 Records, Sequences, Spans）。

2. **测试异常处理:**  测试用例也验证了当 JavaScript 值无法成功转换为目标 C++ 类型时，`NativeValueTraits` 是否能够正确地抛出异常或设置错误状态。

3. **验证特定 IDL 类型的转换规则:**  IDL 用于定义 Web API 的接口。 该文件测试了 `NativeValueTraits` 如何处理各种 IDL 定义的类型，例如 `IDLRecord` (表示 JavaScript 对象), `IDLSequence` (表示 JavaScript 数组或可迭代对象), `IDLBigint` (表示 JavaScript BigInt), 以及 `PassAsSpan` (用于高效地在 JavaScript 和 C++ 之间传递内存)。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这个文件直接关系到 **JavaScript** 的功能，因为它测试的是 JavaScript 值在 Blink 引擎内部的表示和转换。

* **JavaScript 对象和 `IDLRecord`:** `IDLRecord` 用于表示 JavaScript 对象。测试用例验证了如何将 JavaScript 对象的属性转换为 C++ 中的 `std::vector<std::pair<String, T>>` 结构。
    * **假设输入:** JavaScript 代码 `({ foo: 42, bar: "hello" })`
    * **预期输出:** C++ 中的 `IDLRecord<IDLString, IDLAny>` 实例，包含两个元素：`{"foo", 42}` 和 `{"bar", "hello"}`。
    * **用户操作:**  JavaScript 代码可能会创建一个对象并将其传递给一个需要 `IDLRecord` 类型参数的 Web API 函数。例如，`fetch()` API 的 `headers` 参数就是一个 `Headers` 对象，其内部实现可能会用到 `IDLRecord` 来表示 HTTP 头部。

* **JavaScript 数组和可迭代对象与 `IDLSequence`:** `IDLSequence` 用于表示 JavaScript 数组或任何可迭代对象。 测试用例验证了如何将 JavaScript 数组转换为 C++ 中的 `Vector<T>` 或 `HeapVector<ScriptValue> `。
    * **假设输入:** JavaScript 代码 `[1, 2, 3]`
    * **预期输出:** C++ 中的 `IDLSequence<IDLLong>` 实例，包含元素 `1`, `2`, `3`。
    * **用户操作:**  JavaScript 代码可能会创建一个数组并将其作为参数传递给 Web API。例如，`URLSearchParams` 构造函数可以接受一个包含键值对的数组。

* **JavaScript BigInt 和 `IDLBigint`:**  `IDLBigint` 用于表示 JavaScript 的 `BigInt` 类型。测试用例验证了 `NativeValueTraits` 能否正确地将 JavaScript `BigInt` 转换为 Blink 的 `BigInt` 类型。
    * **假设输入:** JavaScript 代码 `123n`
    * **预期输出:** C++ 中的 `IDLBigint` 实例，其值为 123。
    * **用户操作:**  JavaScript 代码可能会使用 `BigInt` 来处理大整数，并将其传递给需要 `IDLBigint` 类型参数的 Web API。

* **ArrayBuffer/TypedArrays 和 `PassAsSpan`:** `PassAsSpan` 允许在 JavaScript 的 `ArrayBuffer` 或 TypedArray 和 C++ 之间高效地传递内存，避免不必要的复制。
    * **假设输入:** JavaScript 代码 `new Uint8Array([0, 1, 2, 3])`
    * **预期输出:** C++ 中的 `PassAsSpan<uint8_t>`，它指向底层 `ArrayBuffer` 的内存，包含了字节 `0`, `1`, `2`, `3`。
    * **用户操作:**  JavaScript 代码可能会创建 `ArrayBuffer` 或 TypedArray 来处理二进制数据，例如在 `Canvas API` 或 `WebSockets` 中。这些数据可能需要传递到 C++ 代码中进行处理。

**与 HTML 和 CSS 的间接关系:**

虽然这个测试文件不直接测试 HTML 或 CSS 的解析或渲染逻辑，但它所测试的功能是 Blink 引擎处理 JavaScript 与 HTML 和 CSS 交互的基础。

* 当 JavaScript 操作 DOM (HTML 结构) 或 CSSOM (CSS 规则) 时，可能会涉及到将 JavaScript 值传递给 C++ 代码，例如修改元素的属性或样式。 `NativeValueTraits` 确保这些值能够被正确地转换。

**逻辑推理的假设输入与输出:**

在测试 `IDLRecord` 的例子中，我们看到了这样的逻辑推理：

* **假设输入:**  一个 JavaScript 对象，其属性具有不同的可枚举性。
    ```javascript
    Object.defineProperties({}, {
      foo: {value: 34, enumerable: true},
      bar: {value: -1024, enumerable: false},
      baz: {value: 42, enumerable: true},
    })
    ```
* **预期输出:**  `NativeValueTraits<IDLRecord<IDLByteString, IDLLong>>` 应该只转换可枚举的属性，因此输出的 `IDLRecord` 将包含 `{"foo", 34}` 和 `{"baz", 42}`，而忽略不可枚举的属性 `bar`。

**用户或编程常见的使用错误举例说明:**

1. **类型不匹配:**  如果 JavaScript 代码传递了一个与 C++ 期望类型不符的值，`NativeValueTraits` 可能会抛出异常。
    * **例子:** C++ 函数期望一个 `IDLSequence<IDLLong>` (整数数组)，但 JavaScript 代码传递了一个字符串数组 `["hello", "world"]`。
    * **用户操作:**  JavaScript 开发者错误地传递了类型不兼容的数据给 Web API。

2. **尝试将非对象转换为 `IDLRecord`:**  `IDLRecord` 预期输入是 JavaScript 对象。如果传递了其他类型的值，转换会失败。
    * **例子:** C++ 代码尝试将一个 JavaScript 数字 `42` 转换为 `IDLRecord`。
    * **用户操作:**  JavaScript 开发者可能误解了 API 的参数类型，传递了一个基本类型而不是一个对象。

3. **在需要特定类型的 `PassAsSpan` 时传递错误类型的 ArrayBufferView:**  如果 C++ 代码期望一个 `PassAsSpan<uint8_t>`，但 JavaScript 传递了一个 `Int32Array`，转换会失败。
    * **例子:** C++ 函数需要一个字节数组，但 JavaScript 代码传递了一个整数数组。
    * **用户操作:**  JavaScript 开发者在处理二进制数据时可能使用了错误的 TypedArray 类型。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在浏览器中执行 JavaScript 代码:**  用户与网页交互，触发了 JavaScript 代码的执行。
2. **JavaScript 代码调用 Web API 或内部 Blink 函数:**  JavaScript 代码可能调用了一个需要将 JavaScript 值传递给 C++ 代码的 Web API（例如 `fetch()`, `postMessage()`, Canvas API 的操作等），或者调用了 Blink 引擎内部的某个函数。
3. **参数传递和类型转换:**  当 JavaScript 值作为参数传递给 C++ 函数时，Blink 的绑定机制会使用 `NativeValueTraits` 来尝试将这些 JavaScript 值转换为 C++ 中对应的类型。
4. **`NativeValueTraitsImplTest` 的作用:** 如果在开发或调试过程中，发现 JavaScript 和 C++ 之间的数据传递出现了问题，例如 C++ 代码接收到的值不符合预期，那么开发者可能会查看 `native_value_traits_impl_test.cc` 中的测试用例，以了解 `NativeValueTraits` 是如何处理特定类型的转换的。
5. **调试线索:** 如果问题与特定类型的转换有关，开发者可能会编写新的测试用例来复现该问题，或者修改现有的测试用例来验证修复方案。例如，如果一个 Web API 接收到的对象属性值不正确，开发者可能会检查 `IDLRecord` 相关的测试用例，看看是否存在类型转换错误。如果涉及到二进制数据的传递，则会关注 `PassAsSpan` 的测试。

总而言之，`native_value_traits_impl_test.cc` 是 Blink 引擎中一个非常重要的测试文件，它确保了 JavaScript 和 C++ 之间数据交换的正确性和可靠性，这对于 Web API 的正常工作至关重要。 任何涉及到 JavaScript 与 Blink 内部 C++ 代码交互的功能，都可能间接地依赖于 `NativeValueTraits` 的正确实现。

Prompt: 
```
这是目录为blink/renderer/bindings/core/v8/native_value_traits_impl_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/bindings/core/v8/native_value_traits_impl.h"

#include <numeric>
#include <utility>

#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest-death-test.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/bindings/core/v8/idl_types.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_internals.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_test_sequence_callback.h"
#include "third_party/blink/renderer/core/testing/internals.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink {

namespace {

v8::Local<v8::Object> EvaluateScriptForObject(V8TestingScope& scope,
                                              const char* source) {
  v8::Local<v8::Script> script =
      v8::Script::Compile(scope.GetContext(),
                          V8String(scope.GetIsolate(), source))
          .ToLocalChecked();
  return script->Run(scope.GetContext()).ToLocalChecked().As<v8::Object>();
}

v8::Local<v8::Array> EvaluateScriptForArray(V8TestingScope& scope,
                                            const char* source) {
  return EvaluateScriptForObject(scope, source).As<v8::Array>();
}

TEST(NativeValueTraitsImplTest, IDLInterface) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  DummyExceptionStateForTesting exception_state;
  Internals* internals = NativeValueTraits<Internals>::NativeValue(
      scope.GetIsolate(), v8::Number::New(scope.GetIsolate(), 42),
      exception_state);
  EXPECT_TRUE(exception_state.HadException());
  EXPECT_EQ("Failed to convert value to 'Internals'.",
            exception_state.Message());
  EXPECT_EQ(nullptr, internals);
}

TEST(NativeValueTraitsImplTest, IDLRecord) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  {
    v8::Local<v8::Object> v8_object = v8::Object::New(scope.GetIsolate());
    NonThrowableExceptionState exception_state;
    const auto& record =
        NativeValueTraits<IDLRecord<IDLString, IDLOctet>>::NativeValue(
            scope.GetIsolate(), v8_object, exception_state);
    EXPECT_TRUE(record.empty());
  }
  {
    v8::Local<v8::Object> v8_object =
        EvaluateScriptForObject(scope, "({ foo: 42, bar: -1024 })");

    NonThrowableExceptionState exception_state;
    const auto& record =
        NativeValueTraits<IDLRecord<IDLByteString, IDLLong>>::NativeValue(
            scope.GetIsolate(), v8_object, exception_state);
    EXPECT_EQ(2U, record.size());
    EXPECT_EQ(std::make_pair(String("foo"), int32_t(42)), record[0]);
    EXPECT_EQ(std::make_pair(String("bar"), int32_t(-1024)), record[1]);
  }
  {
    v8::Local<v8::Object> v8_object =
        EvaluateScriptForObject(scope,
                                "Object.defineProperties({}, {"
                                "  foo: {value: 34, enumerable: true},"
                                "  bar: {value: -1024, enumerable: false},"
                                "  baz: {value: 42, enumerable: true},"
                                "})");

    NonThrowableExceptionState exception_state;
    const auto& record =
        NativeValueTraits<IDLRecord<IDLByteString, IDLLong>>::NativeValue(
            scope.GetIsolate(), v8_object, exception_state);
    EXPECT_EQ(2U, record.size());
    EXPECT_EQ(std::make_pair(String("foo"), int32_t(34)), record[0]);
    EXPECT_EQ(std::make_pair(String("baz"), int32_t(42)), record[1]);
  }
  {
    // Exceptions are being thrown in this test, so we need another scope.
    V8TestingScope scope2;
    v8::Local<v8::Object> original_object = EvaluateScriptForObject(
        scope, "(self.originalObject = {foo: 34, bar: 42})");

    NonThrowableExceptionState exception_state;
    const auto& record =
        NativeValueTraits<IDLRecord<IDLString, IDLLong>>::NativeValue(
            scope.GetIsolate(), original_object, exception_state);
    EXPECT_EQ(2U, record.size());

    v8::Local<v8::Proxy> proxy =
        EvaluateScriptForObject(scope,
                                "new Proxy(self.originalObject, {"
                                "  getOwnPropertyDescriptor() {"
                                "    return {"
                                "      configurable: true,"
                                "      get enumerable() { throw 'bogus!'; },"
                                "    };"
                                "  }"
                                "})")
            .As<v8::Proxy>();

    v8::TryCatch try_catch(scope.GetIsolate());
    const auto& record_from_proxy =
        NativeValueTraits<IDLRecord<IDLString, IDLLong>>::NativeValue(
            scope.GetIsolate(), proxy,
            PassThroughException(scope.GetIsolate()));
    EXPECT_EQ(0U, record_from_proxy.size());
    EXPECT_TRUE(try_catch.HasCaught());
    v8::Local<v8::Value> v8_exception = try_catch.Exception();
    EXPECT_TRUE(v8_exception->IsString());
    EXPECT_TRUE(
        V8String(scope.GetIsolate(), "bogus!")
            ->Equals(
                scope.GetContext(),
                v8_exception->ToString(scope.GetContext()).ToLocalChecked())
            .ToChecked());
  }
  {
    v8::Local<v8::Object> v8_object = EvaluateScriptForObject(
        scope, "({foo: 42, bar: 0, xx: true, abcd: false})");

    NonThrowableExceptionState exception_state;
    const auto& record =
        NativeValueTraits<IDLRecord<IDLByteString, IDLBoolean>>::NativeValue(
            scope.GetIsolate(), v8_object, exception_state);
    EXPECT_EQ(4U, record.size());
    EXPECT_EQ(std::make_pair(String("foo"), true), record[0]);
    EXPECT_EQ(std::make_pair(String("bar"), false), record[1]);
    EXPECT_EQ(std::make_pair(String("xx"), true), record[2]);
    EXPECT_EQ(std::make_pair(String("abcd"), false), record[3]);
  }
  {
    v8::Local<v8::Array> v8_string_array = EvaluateScriptForArray(
        scope, "Object.assign(['Hello, World!', 'Hi, Mom!'], {foo: 'Ohai'})");

    NonThrowableExceptionState exception_state;
    const auto& record =
        NativeValueTraits<IDLRecord<IDLUSVString, IDLString>>::NativeValue(
            scope.GetIsolate(), v8_string_array, exception_state);
    EXPECT_EQ(3U, record.size());
    EXPECT_EQ(std::make_pair(String("0"), String("Hello, World!")), record[0]);
    EXPECT_EQ(std::make_pair(String("1"), String("Hi, Mom!")), record[1]);
    EXPECT_EQ(std::make_pair(String("foo"), String("Ohai")), record[2]);
  }
  {
    v8::Local<v8::Object> v8_object =
        EvaluateScriptForObject(scope, "({[Symbol.toStringTag]: 34, foo: 42})");

    // The presence of symbols should throw a TypeError when the conversion to
    // the record's key type is attempted.
    DummyExceptionStateForTesting exception_state;
    const auto& record =
        NativeValueTraits<IDLRecord<IDLString, IDLShort>>::NativeValue(
            scope.GetIsolate(), v8_object, exception_state);
    EXPECT_TRUE(record.empty());
    EXPECT_TRUE(exception_state.HadException());
    EXPECT_TRUE(exception_state.Message().empty());
  }
  {
    v8::Local<v8::Object> v8_object =
        EvaluateScriptForObject(scope, "Object.create({foo: 34, bar: 512})");

    NonThrowableExceptionState exception_state;
    auto record =
        NativeValueTraits<IDLRecord<IDLString, IDLUnsignedLong>>::NativeValue(
            scope.GetIsolate(), v8_object, exception_state);
    EXPECT_TRUE(record.empty());

    v8_object =
        EvaluateScriptForObject(scope,
                                "Object.assign("
                                "    Object.create({foo: 34, bar: 512}),"
                                "    {quux: 42, foo: 1024})");
    record =
        NativeValueTraits<IDLRecord<IDLString, IDLUnsignedLong>>::NativeValue(
            scope.GetIsolate(), v8_object, exception_state);
    EXPECT_EQ(2U, record.size());
    EXPECT_EQ(std::make_pair(String("quux"), uint32_t(42)), record[0]);
    EXPECT_EQ(std::make_pair(String("foo"), uint32_t(1024)), record[1]);
  }
  {
    v8::Local<v8::Object> v8_object = EvaluateScriptForObject(
        scope, "({foo: ['Hello, World!', 'Hi, Mom!']})");

    NonThrowableExceptionState exception_state;
    const auto& record =
        NativeValueTraits<IDLRecord<IDLString, IDLSequence<IDLString>>>::
            NativeValue(scope.GetIsolate(), v8_object, exception_state);
    EXPECT_EQ(1U, record.size());
    EXPECT_EQ("foo", record[0].first);
    EXPECT_EQ("Hello, World!", record[0].second[0]);
    EXPECT_EQ("Hi, Mom!", record[0].second[1]);
  }
}

TEST(NativeValueTraitsImplTest, IDLSequence) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  {
    v8::Local<v8::Array> v8_array = v8::Array::New(scope.GetIsolate());
    NonThrowableExceptionState exception_state;
    const auto& sequence =
        NativeValueTraits<IDLSequence<IDLOctet>>::NativeValue(
            scope.GetIsolate(), v8_array, exception_state);
    EXPECT_TRUE(sequence.empty());
  }
  {
    v8::Local<v8::Array> v8_array =
        EvaluateScriptForArray(scope, "[0, 1, 2, 3, 4]");
    NonThrowableExceptionState exception_state;
    const auto& sequence = NativeValueTraits<IDLSequence<IDLLong>>::NativeValue(
        scope.GetIsolate(), v8_array, exception_state);
    EXPECT_EQ(Vector<int32_t>({0, 1, 2, 3, 4}), sequence);
  }
  {
    const double double_pi = 3.141592653589793238;
    const float float_pi = double_pi;
    v8::Local<v8::Array> v8_real_array =
        EvaluateScriptForArray(scope, "[3.141592653589793238]");

    NonThrowableExceptionState exception_state;
    Vector<double> double_vector =
        NativeValueTraits<IDLSequence<IDLDouble>>::NativeValue(
            scope.GetIsolate(), v8_real_array, exception_state);
    EXPECT_EQ(1U, double_vector.size());
    EXPECT_EQ(double_pi, double_vector[0]);

    Vector<float> float_vector =
        NativeValueTraits<IDLSequence<IDLFloat>>::NativeValue(
            scope.GetIsolate(), v8_real_array, exception_state);
    EXPECT_EQ(1U, float_vector.size());
    EXPECT_EQ(float_pi, float_vector[0]);
  }
  {
    v8::Local<v8::Array> v8_array =
        EvaluateScriptForArray(scope, "['Vini, vidi, vici.', 65535, 0.125]");

    NonThrowableExceptionState exception_state;
    HeapVector<ScriptValue> script_value_vector =
        NativeValueTraits<IDLSequence<IDLAny>>::NativeValue(
            scope.GetIsolate(), v8_array, exception_state);
    EXPECT_EQ(3U, script_value_vector.size());
    String report_on_zela;
    EXPECT_TRUE(script_value_vector[0].ToString(report_on_zela));
    EXPECT_EQ("Vini, vidi, vici.", report_on_zela);
    EXPECT_EQ(65535U,
              ToUInt32(scope.GetIsolate(), script_value_vector[1].V8Value(),
                       kNormalConversion, exception_state));
  }
  {
    v8::Local<v8::Array> v8_string_array_array =
        EvaluateScriptForArray(scope, "[['foo', 'bar'], ['x', 'y', 'z']]");

    NonThrowableExceptionState exception_state;
    Vector<Vector<String>> string_vector_vector =
        NativeValueTraits<IDLSequence<IDLSequence<IDLString>>>::NativeValue(
            scope.GetIsolate(), v8_string_array_array, exception_state);
    EXPECT_EQ(2U, string_vector_vector.size());
    EXPECT_EQ(2U, string_vector_vector[0].size());
    EXPECT_EQ("foo", string_vector_vector[0][0]);
    EXPECT_EQ("bar", string_vector_vector[0][1]);
    EXPECT_EQ(3U, string_vector_vector[1].size());
    EXPECT_EQ("x", string_vector_vector[1][0]);
    EXPECT_EQ("y", string_vector_vector[1][1]);
    EXPECT_EQ("z", string_vector_vector[1][2]);
  }
  {
    v8::Local<v8::Array> v8_array =
        EvaluateScriptForArray(scope,
                               "let arr = [1, 2, 3];"
                               "let iterations = ["
                               "  {done: false, value: 8},"
                               "  {done: false, value: 5},"
                               "  {done: true}"
                               "];"
                               "arr[Symbol.iterator] = function() {"
                               "  let i = 0;"
                               "  return {next: () => iterations[i++]};"
                               "}; arr");

    NonThrowableExceptionState exception_state;
    const auto& sequence = NativeValueTraits<IDLSequence<IDLByte>>::NativeValue(
        scope.GetIsolate(), v8_array, exception_state);
    EXPECT_EQ(Vector<int8_t>({1, 2, 3}), sequence);
  }
  {
    v8::Local<v8::Object> v8_object =
        EvaluateScriptForObject(scope,
                                "let obj = {"
                                "  iterations: ["
                                "    {done: false, value: 55},"
                                "    {done: false, value: 0},"
                                "    {done: true, value: 99}"
                                "  ],"
                                "  [Symbol.iterator]() {"
                                "    let i = 0;"
                                "    return {next: () => this.iterations[i++]};"
                                "  }"
                                "}; obj");

    NonThrowableExceptionState exception_state;
    const auto& byte_sequence =
        NativeValueTraits<IDLSequence<IDLByte>>::NativeValue(
            scope.GetIsolate(), v8_object, exception_state);
    EXPECT_EQ(Vector<int8_t>({55, 0}), byte_sequence);
    const auto& boolean_sequence =
        NativeValueTraits<IDLSequence<IDLBoolean>>::NativeValue(
            scope.GetIsolate(), v8_object, exception_state);
    EXPECT_EQ(Vector<bool>({true, false}), boolean_sequence);
  }
}

TEST(NativeValueTraitsImplTest, IDLBigint) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  {
    v8::Local<v8::BigInt> v8_bigint = v8::BigInt::New(scope.GetIsolate(), 123);
    NonThrowableExceptionState exception_state;
    const blink::BigInt& bigint = NativeValueTraits<IDLBigint>::NativeValue(
        scope.GetIsolate(), v8_bigint, exception_state);
    std::optional<absl::uint128> val = bigint.ToUInt128();
    ASSERT_TRUE(val.has_value());
    EXPECT_EQ(*val, 123u);
  }
  {
    // Numbers don't convert to BigInt.
    v8::Local<v8::Number> v8_number = v8::Number::New(scope.GetIsolate(), 123);
    DummyExceptionStateForTesting exception_state;
    const blink::BigInt& bigint = NativeValueTraits<IDLBigint>::NativeValue(
        scope.GetIsolate(), v8_number, exception_state);
    EXPECT_TRUE(exception_state.HadException());
  }
  {
    // Strings do convert to BigInt.
    v8::Local<v8::String> v8_string =
        v8::String::NewFromUtf8Literal(scope.GetIsolate(), "123");
    NonThrowableExceptionState exception_state;
    const blink::BigInt& bigint = NativeValueTraits<IDLBigint>::NativeValue(
        scope.GetIsolate(), v8_string, exception_state);
    std::optional<absl::uint128> val = bigint.ToUInt128();
    ASSERT_TRUE(val.has_value());
    EXPECT_EQ(*val, 123u);
  }
  {
    // Can also go via valueOf.
    const char kScript[] = R"(
      let obj = {
        valueOf: () => BigInt(123)
      }; obj
    )";
    v8::Local<v8::Object> v8_object = EvaluateScriptForObject(scope, kScript);
    NonThrowableExceptionState exception_state;
    const blink::BigInt& bigint = NativeValueTraits<IDLBigint>::NativeValue(
        scope.GetIsolate(), v8_object, exception_state);
    std::optional<absl::uint128> val = bigint.ToUInt128();
    ASSERT_TRUE(val.has_value());
    EXPECT_EQ(*val, 123u);
  }
  {
    // Test legacy behavior.
    ScopedWebIDLBigIntUsesToBigIntForTest disable_to_bigint(false);
    v8::Local<v8::String> v8_string =
        v8::String::NewFromUtf8Literal(scope.GetIsolate(), "123");
    DummyExceptionStateForTesting exception_state;
    const blink::BigInt& bigint = NativeValueTraits<IDLBigint>::NativeValue(
        scope.GetIsolate(), v8_string, exception_state);
    EXPECT_TRUE(exception_state.HadException());
  }
}

template <typename Arr>
v8::Local<Arr> MakeArray(v8::Isolate* isolate, size_t size) {
  auto arr = Arr::New(isolate, size);
  uint8_t* it = static_cast<uint8_t*>(arr->Data());
  std::iota(it, it + arr->ByteLength(), 0);
  return arr;
}

using PassAsSpanShared = PassAsSpan<PassAsSpanMarkerBase::Flags::kAllowShared>;
using PassAsSpanNoShared = PassAsSpan<PassAsSpanMarkerBase::Flags::kNone>;

TEST(NativeValueTraitsImplTest, PassAsSpanBasic) {
  constexpr size_t kBufferSize = 4;
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  NonThrowableExceptionState exception_state;
  auto v8_arraybuffer =
      MakeArray<v8::ArrayBuffer>(scope.GetIsolate(), kBufferSize);
  EXPECT_THAT(NativeValueTraits<PassAsSpanShared>::ArgumentValue(
                  scope.GetIsolate(), 0, v8_arraybuffer, exception_state)
                  .as_span(),
              testing::ElementsAre(0, 1, 2, 3));
  EXPECT_THAT(NativeValueTraits<PassAsSpanNoShared>::ArgumentValue(
                  scope.GetIsolate(), 0, v8_arraybuffer, exception_state)
                  .as_span(),
              testing::ElementsAre(0, 1, 2, 3));
}

TEST(NativeValueTraitsImplTest, PassAsSpanShared) {
  constexpr size_t kBufferSize = 4;
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto v8_arraybuffer =
      MakeArray<v8::SharedArrayBuffer>(scope.GetIsolate(), kBufferSize);
  {
    NonThrowableExceptionState exception_state;

    auto res = NativeValueTraits<PassAsSpanShared>::ArgumentValue(
        scope.GetIsolate(), 0, v8_arraybuffer, exception_state);
    EXPECT_THAT(res.as_span(), testing::ElementsAre(0, 1, 2, 3));
  }
  {
    DummyExceptionStateForTesting exception_state;
    EXPECT_THAT(NativeValueTraits<PassAsSpanNoShared>::ArgumentValue(
                    scope.GetIsolate(), 0, v8::Undefined(scope.GetIsolate()),
                    exception_state)
                    .as_span(),
                testing::IsEmpty());
    EXPECT_TRUE(exception_state.HadException());
  }
}

TEST(NativeValueTraitsImplTest, PassAsSpanDetached) {
  constexpr size_t kBufferSize = 4;

  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  NonThrowableExceptionState exception_state;

  auto v8_arraybuffer =
      MakeArray<v8::ArrayBuffer>(scope.GetIsolate(), kBufferSize);
  CHECK(v8_arraybuffer->Detach(v8::Local<v8::Value>()).ToChecked());
  auto res = NativeValueTraits<PassAsSpanShared>::ArgumentValue(
      scope.GetIsolate(), 0, v8_arraybuffer, exception_state);
  EXPECT_THAT(res.as_span(), testing::IsEmpty());
}

TEST(NativeValueTraitsImplTest, PassAsSpanDataView) {
  constexpr size_t kBufferSize = 4;

  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  NonThrowableExceptionState exception_state;

  auto v8_arraybuffer =
      MakeArray<v8::ArrayBuffer>(scope.GetIsolate(), kBufferSize);
  auto subarray = v8::DataView::New(v8_arraybuffer, 1, 2);
  EXPECT_THAT(NativeValueTraits<PassAsSpanShared>::ArgumentValue(
                  scope.GetIsolate(), 0, subarray, exception_state)
                  .as_span(),
              testing::ElementsAre(1, 2));

  CHECK(v8_arraybuffer->Detach(v8::Local<v8::Value>()).ToChecked());
  EXPECT_THAT(NativeValueTraits<PassAsSpanShared>::ArgumentValue(
                  scope.GetIsolate(), 0, subarray, exception_state)
                  .as_span(),
              testing::IsEmpty());

  v8::Local<v8::Object> v8_object = EvaluateScriptForObject(scope, R"(
        (function() {
          const arr = new ArrayBuffer(8, {maxByteLength: 8});
          const view = new Uint8Array(arr);

          for (let i = 0; i < 8; ++i) view[i] = i;
          arr.resize(4);
          return view;
        })()
      )");

  EXPECT_THAT(NativeValueTraits<PassAsSpanShared>::ArgumentValue(
                  scope.GetIsolate(), 0, v8_object, exception_state)
                  .as_span(),
              testing::ElementsAre(0, 1, 2, 3));
}

TEST(NativeValueTraitsImplTest, PassAsSpanInlineStorage) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  NonThrowableExceptionState exception_state;

  v8::Local<v8::Object> v8_object =
      EvaluateScriptForObject(scope, "new Uint8Array([0, 1, 2, 3])");
  ASSERT_TRUE(v8_object->IsArrayBufferView());
  v8::Local<v8::ArrayBufferView> v8_array_view =
      v8_object.As<v8::ArrayBufferView>();
  ASSERT_TRUE(!v8_array_view->HasBuffer());
  auto result = NativeValueTraits<PassAsSpanShared>::ArgumentValue(
      scope.GetIsolate(), 0, v8_object, exception_state);
  EXPECT_THAT(result.as_span(), testing::ElementsAre(0, 1, 2, 3));

  // Assure conversion of small data does not force buffer allocation.
  EXPECT_TRUE(!v8_array_view->HasBuffer());
}

TEST(NativeValueTraitsImplTest, PassAsSpanBadType) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  DummyExceptionStateForTesting exception_state;
  auto v8_array = v8::Array::New(scope.GetIsolate(), 10);

  EXPECT_THAT(NativeValueTraits<PassAsSpanShared>::ArgumentValue(
                  scope.GetIsolate(), 0, v8_array, exception_state)
                  .as_span(),
              testing::IsEmpty());
  EXPECT_TRUE(exception_state.HadException());
}

TEST(NativeValueTraitsImplTest, PassAsSpanMissingOpt) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  {
    DummyExceptionStateForTesting exception_state;
    EXPECT_THAT(NativeValueTraits<PassAsSpanShared>::ArgumentValue(
                    scope.GetIsolate(), 0, v8::Undefined(scope.GetIsolate()),
                    exception_state)
                    .as_span(),
                testing::IsEmpty());
    EXPECT_TRUE(exception_state.HadException());
  }
  {
    NonThrowableExceptionState exception_state;
    EXPECT_THAT(NativeValueTraits<IDLOptional<PassAsSpanShared>>::ArgumentValue(
                    scope.GetIsolate(), 0, v8::Undefined(scope.GetIsolate()),
                    exception_state),
                testing::Eq(std::nullopt));
  }
}

TEST(NativeValueTraitsImplTest, PassAsSpanCopy) {
  test::TaskEnvironment task_environment;
  NonThrowableExceptionState exception_state;
  V8TestingScope scope;
  v8::Local<v8::Object> v8_object1 =
      EvaluateScriptForObject(scope, "new Uint8Array([0, 1, 2, 3])");
  v8::Local<v8::Object> v8_object2 =
      EvaluateScriptForObject(scope, "new Uint8Array([5, 6, 7, 8])");

  auto result = NativeValueTraits<PassAsSpanShared>::ArgumentValue(
      scope.GetIsolate(), 0, v8_object1, exception_state);
  EXPECT_THAT(result.as_span(), testing::ElementsAre(0, 1, 2, 3));
  auto result2 = result;
  EXPECT_THAT(result2.as_span(), testing::ElementsAre(0, 1, 2, 3));
  result = NativeValueTraits<PassAsSpanShared>::ArgumentValue(
      scope.GetIsolate(), 0, v8_object2, exception_state);
  EXPECT_THAT(result2.as_span(), testing::ElementsAre(0, 1, 2, 3));
}

template <typename T>
using TypedPassAsSpanShared =
    PassAsSpan<PassAsSpanMarkerBase::Flags::kAllowShared, T>;
template <typename T>
using TypedPassAsSpanNoShared =
    PassAsSpan<PassAsSpanMarkerBase::Flags::kNone, T>;

TEST(NativeValueTraitsImplTest, TypedPassAsSpanBasic) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  NonThrowableExceptionState exception_state;
  v8::Local<v8::Object> v8_object =
      EvaluateScriptForObject(scope, "new Uint16Array([0, 1, 2, 3])");

  EXPECT_THAT(NativeValueTraits<TypedPassAsSpanShared<uint16_t>>::ArgumentValue(
                  scope.GetIsolate(), 0, v8_object, exception_state)
                  .as_span(),
              testing::ElementsAre(0, 1, 2, 3));
}

TEST(NativeValueTraitsImplTest, TypedPassAsSpanSubarray) {
  static const int32_t kRawData[] = {-1, -2, -3, -4};

  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  NonThrowableExceptionState exception_state;

  auto v8_arraybuffer =
      MakeArray<v8::ArrayBuffer>(scope.GetIsolate(), sizeof kRawData);
  memcpy(v8_arraybuffer->Data(), kRawData, sizeof kRawData);
  v8::Local<v8::Int32Array> int32_array = v8::Int32Array::New(
      v8_arraybuffer, /* byte_offset=*/1 * sizeof(int32_t), /* length=*/2);

  EXPECT_THAT(NativeValueTraits<TypedPassAsSpanShared<int32_t>>::ArgumentValue(
                  scope.GetIsolate(), 0, int32_array, exception_state)
                  .as_span(),
              testing::ElementsAre(-2, -3));
}

TEST(NativeValueTraitsImplTest, TypedPassAsSpanBadType) {
  static const int32_t kRawData[] = {-1, -2, -3, -4};

  test::TaskEnvironment task_environment;
  V8TestingScope scope;

  auto v8_arraybuffer =
      MakeArray<v8::ArrayBuffer>(scope.GetIsolate(), sizeof kRawData);
  memcpy(v8_arraybuffer->Data(), kRawData, sizeof kRawData);

  {
    DummyExceptionStateForTesting exception_state;
    EXPECT_THAT(
        NativeValueTraits<TypedPassAsSpanShared<int32_t>>::ArgumentValue(
            scope.GetIsolate(), 0, v8_arraybuffer, exception_state)
            .as_span(),
        testing::IsEmpty());
    EXPECT_TRUE(exception_state.HadException());
  }

  v8::Local<v8::Int32Array> int32_array = v8::Int32Array::New(
      v8_arraybuffer, /* byte_offset=*/0, /* length=*/std::size(kRawData));

  {
    DummyExceptionStateForTesting exception_state;
    EXPECT_THAT(
        NativeValueTraits<TypedPassAsSpanShared<uint32_t>>::ArgumentValue(
            scope.GetIsolate(), 0, int32_array, exception_state)
            .as_span(),
        testing::IsEmpty());
    EXPECT_TRUE(exception_state.HadException());
  }
  {
    DummyExceptionStateForTesting exception_state;
    EXPECT_THAT(NativeValueTraits<TypedPassAsSpanShared<int8_t>>::ArgumentValue(
                    scope.GetIsolate(), 0, int32_array, exception_state)
                    .as_span(),
                testing::IsEmpty());
    EXPECT_TRUE(exception_state.HadException());
  }
}

// Uint8 arrays get their own coverage because of ClampedUint8Array :-/
TEST(NativeValueTraitsImplTest, TypedPassAsSpanUint8) {
  test::TaskEnvironment task_environment;
  NonThrowableExceptionState exception_state;
  V8TestingScope scope;
  {
    v8::Local<v8::Object> v8_object =
        EvaluateScriptForObject(scope, "new Uint8Array([0, 1, 256, 257])");

    EXPECT_THAT(
        NativeValueTraits<TypedPassAsSpanShared<uint8_t>>::ArgumentValue(
            scope.GetIsolate(), 0, v8_object, exception_state)
            .as_span(),
        testing::ElementsAre(0, 1, 0, 1));
  }
  {
    v8::Local<v8::Object> v8_object = EvaluateScriptForObject(
        scope, "new Uint8ClampedArray([0, 1, 256, 257])");
    EXPECT_THAT(
        NativeValueTraits<TypedPassAsSpanShared<uint8_t>>::ArgumentValue(
            scope.GetIsolate(), 0, v8_object, exception_state)
            .as_span(),
        testing::ElementsAre(0, 1, 255, 255));

    DummyExceptionStateForTesting thrown_exception;
    EXPECT_THAT(
        NativeValueTraits<TypedPassAsSpanShared<uint16_t>>::ArgumentValue(
            scope.GetIsolate(), 0, v8_object, thrown_exception)
            .as_span(),
        testing::IsEmpty());
    EXPECT_TRUE(thrown_exception.HadException());
  }
}

template <typename T>
using PassAsSpanSequence =
    PassAsSpan<PassAsSpanMarkerBase::Flags::kAllowSequence, T>;

TEST(NativeValueTraitsImplTest, PassAsSpanAllowSequence) {
  test::TaskEnvironment task_environment;
  NonThrowableExceptionState exception_state;
  V8TestingScope scope;
  {
    v8::Local<v8::Object> v8_object =
        EvaluateScriptForObject(scope, "[1, 2, 3, 4]");

    EXPECT_THAT(NativeValueTraits<PassAsSpanSequence<uint8_t>>::ArgumentValue(
                    scope.GetIsolate(), 0, v8_object, exception_state)
                    .as_span(),
                testing::ElementsAre(1, 2, 3, 4));
    EXPECT_THAT(NativeValueTraits<PassAsSpanSequence<double>>::ArgumentValue(
                    scope.GetIsolate(), 0, v8_object, exception_state)
                    .as_span(),
                testing::ElementsAre(1.0, 2.0, 3.0, 4.0));

    DummyExceptionStateForTesting thrown_exception;
    EXPECT_THAT(
        NativeValueTraits<TypedPassAsSpanShared<uint16_t>>::ArgumentValue(
            scope.GetIsolate(), 0, v8_object, thrown_exception)
            .as_span(),
        testing::IsEmpty());
    EXPECT_TRUE(thrown_exception.HadException());
  }
  {
    v8::Local<v8::Object> v8_iterable = EvaluateScriptForObject(scope, R"(
        (function*() {
            yield 1;
            yield 2;
            yield 3;
        })())");
    EXPECT_THAT(NativeValueTraits<PassAsSpanSequence<uint8_t>>::ArgumentValue(
                    scope.GetIsolate(), 0, v8_iterable, exception_state)
                    .as_span(),
                testing::ElementsAre(1, 2, 3));
  }
}

TEST(NativeValueTraitsImplTest, PassAsSpanSequenceOfUnrestricted) {
  test::TaskEnvironment task_environment;
  NonThrowableExceptionState exception_state;
  V8TestingScope scope;

  v8::Local<v8::Object> v8_object =
      EvaluateScriptForObject(scope, "[1, -Infinity, NaN, Infinity, 42]");

  using testing::Eq;
  using testing::IsNan;
  EXPECT_THAT(
      NativeValueTraits<PassAsSpanSequence<float>>::ArgumentValue(
          scope.GetIsolate(), 0, v8_object, exception_state)
          .as_span(),
      testing::ElementsAre(1, -std::numeric_limits<float>::infinity(), IsNan(),
                           std::numeric_limits<float>::infinity(), 42));
  EXPECT_THAT(
      NativeValueTraits<PassAsSpanSequence<double>>::ArgumentValue(
          scope.GetIsolate(), 0, v8_object, exception_state)
          .as_span(),
      testing::ElementsAre(1, -std::numeric_limits<double>::infinity(), IsNan(),
                           std::numeric_limits<double>::infinity(), 42));
}

}  // namespace
}  // namespace blink

"""

```