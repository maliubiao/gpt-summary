Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Understand the Goal:** The first and most crucial step is to understand *why* this file exists. The filename `to_v8_traits_test.cc` and the directory `blink/renderer/bindings/core/v8` strongly suggest it's testing the conversion of C++ data types to their JavaScript (V8) equivalents within the Blink rendering engine. The `ToV8Traits` part points to a specific mechanism for this conversion.

2. **Identify Key Components:**  Scan the code for important elements:
    * **Includes:** These reveal dependencies and the types being tested. Notice includes like `to_v8_traits.h`, various `v8_...` headers, and core Blink types like `EventTarget`, `DOMPointInit`, `DOMUint8Array`, etc. This reinforces the idea of testing C++ to JS conversion for Blink-specific types.
    * **Namespaces:** `blink` and the anonymous namespace are structural.
    * **Macros/Templates:**  The `TEST_TOV8_TRAITS` macro is central. Understanding its purpose (comparing the V8 representation of a C++ value against an expected string) is key. The `TestToV8Traits` template function does the actual conversion and comparison.
    * **Test Cases:** The `TEST(ToV8TraitsTest, ...)` blocks define individual test scenarios, each focusing on a specific IDL type (like `IDLBoolean`, `IDLBigint`, `IDLString`, etc.).
    * **Setup:** The `test::TaskEnvironment` and `V8TestingScope` indicate a testing environment that simulates V8.
    * **Assertions:** `EXPECT_EQ`, `EXPECT_TRUE`, `ASSERT_TRUE`, `ADD_FAILURE_AT` are standard testing assertions.

3. **Analyze the Core Testing Logic:** Focus on the `TEST_TOV8_TRAITS` macro and the `TestToV8Traits` function. They take an IDL type, an expected string representation, and a C++ value. The function converts the C++ value to a V8 `v8::Value` using `ToV8Traits<IDLType>::ToV8`, then converts that V8 value back to a string for comparison. This confirms the file's purpose.

4. **Relate to Web Technologies (JavaScript, HTML, CSS):**  Think about *how* these C++ types and their V8 representations connect to web development:
    * **IDL Types:** These often correspond directly to JavaScript types or browser APIs exposed to JavaScript. For example, `IDLBoolean` is JavaScript's `boolean`, `IDLString` is `string`, `IDLObject` is `object`, `IDLPromise` is `Promise`, and so on.
    * **Blink Specific Types:**  Types like `EventTarget`, `DOMPointInit`, `DOMUint8Array` are part of the browser's DOM and other web APIs. JavaScript interacts with these through the bindings tested here.
    * **Conversion:** The process being tested is the bridge between the C++ implementation of browser features and the JavaScript interface that web developers use.

5. **Infer Relationships and Provide Examples:** Based on the IDL types, provide concrete examples of how JavaScript, HTML, and CSS interact with the underlying C++ code. For instance:
    * `IDLBoolean`:  `if (someCondition) { ... }` in JavaScript.
    * `IDLString`:  `document.getElementById('foo').textContent = 'Hello';`
    * `IDLObject`:  Passing objects as arguments to JavaScript functions or receiving them from browser APIs.
    * `IDLPromise`:  `fetch('...').then(...);`
    * `EventTarget`:  `document.addEventListener('click', ...);`

6. **Consider Logic and Scenarios:**  Examine individual test cases. What are they testing specifically?
    * **Basic Types:**  Testing true/false for booleans, various integer ranges, different string types.
    * **Collections:** Testing vectors, arrays (frozen vs. non-frozen), records (like JavaScript objects).
    * **Nullability/Optionality:**  Testing how `null`, `undefined`, and optional values are handled in the conversion.
    * **Specific Types:** Testing conversions for `BigInt`, `Float`, `Double`, `Promise`, etc.

7. **Hypothesize Inputs and Outputs:** For some test cases, especially those involving collections or specific types, imagine concrete input values and the expected JavaScript output. This helps solidify understanding. For example, for `IDLSequence<IDLString>`, inputting `["hello", "world"]` should result in a JavaScript array `["hello", "world"]`.

8. **Think About User Errors:**  Consider common mistakes developers might make when interacting with these APIs, which the tests might indirectly cover (by ensuring correct conversions even with potentially problematic inputs). For example, passing `null` where a non-nullable string is expected, or expecting a mutable array when a frozen array is provided.

9. **Trace User Actions (Debugging):**  Imagine how a user's action in a browser could lead to this code being executed. A click event triggers an event listener (involving `EventTarget`), setting the text content of an element involves string conversions, fetching data involves promises, and so on. This connects the low-level C++ to high-level user interactions.

10. **Structure the Answer:** Organize the information logically, starting with the main purpose, then detailing specific functionalities, examples related to web technologies, logical scenarios, potential errors, and debugging clues. Use clear headings and bullet points for readability.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  "This is just testing some conversions."
* **Correction:** "No, it's specifically testing the `ToV8Traits` mechanism, which is crucial for the JavaScript bindings in Blink."
* **Initial thought:** "The examples are obvious."
* **Refinement:** "Provide *specific* JavaScript code snippets that demonstrate the connection to the IDL types being tested."
* **Initial thought:** "Just list the test cases."
* **Refinement:** "Group related test cases (e.g., all the integer types, all the string types) and explain the *purpose* of testing those variations."

By following these steps, the detailed and comprehensive analysis of the C++ test file can be constructed. The key is to connect the low-level code to the higher-level concepts of web development.
这个文件 `to_v8_traits_test.cc` 的功能是 **测试 Blink 渲染引擎中 C++ 数据类型到 JavaScript (V8) 数据类型的转换机制，特别是 `ToV8Traits` 这个模板类的功能。**  `ToV8Traits` 负责将 Blink 内部的 C++ 对象和基本类型转换为 V8 可以理解和使用的 JavaScript 值。

**它与 JavaScript, HTML, CSS 的功能有关系，体现在以下几个方面：**

1. **JavaScript 数据类型映射:**  这个文件测试了各种 C++ 类型如何正确地转换为对应的 JavaScript 类型。
    * **`IDLBoolean` (C++) -> `boolean` (JavaScript):** 测试 C++ 的 `true` 和 `false` 如何转换为 JavaScript 的 `true` 和 `false`。例如，一个 JavaScript 函数接收一个布尔值参数，这个参数可能来源于一个 C++ 的计算结果。
       ```javascript
       function setFlag(flag) {
         if (flag) {
           console.log("Flag is true");
         } else {
           console.log("Flag is false");
         }
       }

       // C++ 代码可能调用 JavaScript 的 setFlag，并传入一个 C++ 的 bool 值。
       ```
    * **`IDLString` (C++) -> `string` (JavaScript):** 测试 C++ 的字符串如何转换为 JavaScript 的字符串。这在处理 DOM 元素的文本内容、属性值等方面非常常见。
       ```javascript
       let element = document.getElementById('myElement');
       element.textContent = 'Hello from C++!'; // C++ 代码设置了元素的 textContent
       ```
    * **各种数值类型 (`IDLLong`, `IDLDouble`, `IDLBigint` 等) (C++) -> `number` 或 `bigint` (JavaScript):**  测试各种 C++ 数值类型到 JavaScript 数值类型的转换，包括整数、浮点数和 BigInt。例如，获取元素的宽度、高度等属性时，C++ 的数值会被转换为 JavaScript 的数值。
       ```javascript
       let width = element.offsetWidth; // C++ 计算的宽度转换为 JavaScript 的 number
       ```
    * **`IDLObject` (C++) -> `object` (JavaScript):** 测试 C++ 的对象如何转换为 JavaScript 的对象。这包括各种 DOM 节点、Blink 内部的对象等。
       ```javascript
       let element = document.createElement('div'); // C++ 创建的 DOM 节点转换为 JavaScript 的对象
       ```
    * **`IDLPromise` (C++) -> `Promise` (JavaScript):** 测试 C++ 的 Promise 对象如何转换为 JavaScript 的 Promise 对象，用于处理异步操作。
       ```javascript
       fetch('/data').then(response => response.json()); // C++ 发起的网络请求返回一个 Promise
       ```
    * **`IDLArray<T>` 和 `IDLSequence<T>` (C++) -> `Array` (JavaScript):** 测试 C++ 的数组和序列如何转换为 JavaScript 的数组。例如，获取元素的子节点列表。
       ```javascript
       let children = element.children; // C++ 维护的子节点列表转换为 JavaScript 的 Array-like 对象
       ```

2. **HTML 元素和属性交互:**  当 JavaScript 操作 HTML 元素时，底层涉及到 C++ 对象的创建、属性的设置和获取。`ToV8Traits` 确保这些操作中 C++ 和 JavaScript 之间的数据类型能够正确转换。例如，通过 JavaScript 获取一个 HTML 元素的 `id` 属性，这个属性值（字符串）的转换就依赖于 `ToV8Traits`。

3. **CSS 样式处理:**  虽然这个文件本身不直接测试 CSS，但当 JavaScript 操作元素的样式时（例如通过 `element.style.width = '100px'`），底层的样式值也需要在 C++ 和 JavaScript 之间进行转换。例如，设置元素的宽度为一个数值，C++ 的数值需要转换为 JavaScript 可以理解的字符串或数值。

**逻辑推理与假设输入输出:**

该文件中的测试用例都遵循类似的模式：

* **假设输入 (C++ 值):**  一个特定的 C++ 数据类型的值，例如 `true` (bool), `"string"` (String), `123` (int),  一个 `DOMPointInit` 对象等。
* **转换过程:**  通过 `ToV8Traits<IDLType>::ToV8(scope.GetScriptState(), value)` 将 C++ 值转换为 V8 的 `v8::Value`。
* **预期输出 (JavaScript 字符串表示):**  期望的 JavaScript 值通过 `ToString()` 方法转换成的字符串表示，例如 `"true"`, `"string"`, `"123"`, `"[object Object]"` 等。
* **断言:** 使用 `EXPECT_EQ` 比较实际转换后的字符串表示和预期的字符串表示是否一致。

**举例说明：**

* **假设输入 (C++):** `true` (类型: `bool`)
* **预期输出 (JavaScript 字符串):** `"true"`
* **测试代码:**
  ```c++
  TEST_TOV8_TRAITS(scope, IDLBoolean, "true", true);
  ```

* **假设输入 (C++):**  `String("hello")` (类型: `blink::String`)
* **预期输出 (JavaScript 字符串):** `"hello"`
* **测试代码:**
  ```c++
  TEST_TOV8_TRAITS(scope, IDLString, "hello", String("hello"));
  ```

* **假设输入 (C++):**  一个包含字符串 "foo" 和 "bar" 的 `Vector<String>`
* **预期输出 (JavaScript 字符串):** `"foo,bar"` (注意这里是将数组元素连接成逗号分隔的字符串用于测试比较)
* **测试代码:**
  ```c++
  Vector<String> string_vector;
  string_vector.push_back("foo");
  string_vector.push_back("bar");
  TEST_TOV8_TRAITS(scope, IDLSequence<IDLString>, "foo,bar", string_vector);
  ```

**用户或编程常见的使用错误:**

虽然这个测试文件本身不直接处理用户输入，但它确保了 Blink 引擎在内部处理数据转换时的正确性，这间接避免了由于类型转换错误导致的问题。一些可能的用户或编程错误，`ToV8Traits` 试图避免（或暴露出来以便修复）包括：

* **类型不匹配:**  JavaScript 期望一个字符串，但 C++ 代码错误地传递了一个数值，或者反之。`ToV8Traits` 确保了即使类型不完全匹配，也能进行合理的转换（例如，数值到字符串）。
* **空值处理不当:**  JavaScript 中有 `null` 和 `undefined`，C++ 中有空指针。`ToV8Traits` 测试了 `Nullable` 和 `Optional` 类型，确保了 C++ 的空值能够正确地映射到 JavaScript 的 `null` 或 `undefined`。如果转换不正确，可能会导致 JavaScript 代码中出现 `TypeError` 或其他错误。
* **精度丢失:**  在数值类型转换时，例如将一个高精度的 C++ 浮点数转换为 JavaScript 的 `number`，可能会发生精度丢失。测试用例会检查这种精度丢失是否在预期范围内。
* **对象生命周期管理错误:**  当 C++ 对象被转换为 JavaScript 对象后，需要正确管理它们的生命周期，避免过早释放导致 JavaScript 代码访问已释放的内存。虽然 `ToV8Traits` 不直接管理生命周期，但它确保了对象能够被正确地包装成 V8 对象，以便 V8 的垃圾回收机制能够处理。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在浏览器中执行 JavaScript 代码:**  用户的任何与网页交互的操作，最终都会触发 JavaScript 代码的执行。例如，点击一个按钮、提交一个表单、滚动页面等。
2. **JavaScript 代码调用了 Blink 提供的 Web API:**  这些 API 往往由 C++ 代码实现。例如，`document.getElementById()`, `element.textContent = ...`, `fetch()` 等。
3. **Web API 的 C++ 实现需要将数据返回给 JavaScript:**  在 C++ 代码执行完毕后，需要将结果返回给 JavaScript 环境。这时，`ToV8Traits` 就发挥作用，将 C++ 的数据类型转换为 V8 可以理解的 JavaScript 类型。
4. **如果在转换过程中出现问题，可能会触发 `to_v8_traits_test.cc` 中的断言失败:**  开发者在修改或新增 Blink 代码时，会运行这些测试用例来确保他们的修改没有破坏 C++ 到 JavaScript 的数据类型转换机制。如果测试失败，就表明转换逻辑存在问题。

**调试线索:**

如果 `to_v8_traits_test.cc` 中的测试失败，可以提供以下调试线索：

* **失败的测试用例名称:**  指明了哪个特定的类型转换出现了问题，例如 `TEST(ToV8TraitsTest, String)` 表示字符串类型的转换有问题。
* **预期的输出和实际的输出:**  对比预期的 JavaScript 字符串表示和实际转换出来的字符串表示，可以帮助定位转换逻辑的错误。例如，预期是 `"true"`，但实际是 `"1"`，就说明布尔类型的转换可能存在问题。
* **相关的 C++ 代码:**  查看 `third_party/blink/renderer/bindings/core/v8/to_v8_traits.h` 中的 `ToV8Traits` 模板类的实现，找到负责特定类型转换的代码。
* **V8 的调试工具:**  可以使用 V8 的调试工具来查看转换过程中 V8 对象的具体状态。

总而言之，`to_v8_traits_test.cc` 是 Blink 引擎中非常重要的一个测试文件，它确保了 C++ 和 JavaScript 之间数据交互的正确性，是保证浏览器功能稳定性和可靠性的基石之一。

### 提示词
```
这是目录为blink/renderer/bindings/core/v8/to_v8_traits_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/bindings/core/v8/to_v8_traits.h"

#include "base/time/time.h"
#include "third_party/blink/renderer/bindings/core/v8/frozen_array.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_align_setting.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_create_html_callback.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_dom_point_init.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_event_listener.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_file_formdata_usvstring.h"
#include "third_party/blink/renderer/core/dom/events/event_target.h"
#include "third_party/blink/renderer/core/testing/garbage_collected_script_wrappable.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer.h"
#include "third_party/blink/renderer/platform/bindings/dictionary_base.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"

namespace blink {

namespace {

#define TEST_TOV8_TRAITS(scope, IDLType, expected, value) \
  TestToV8Traits<IDLType>(scope, expected, value, __FILE__, __LINE__)

template <typename IDLType, typename T>
void TestToV8Traits(const V8TestingScope& scope,
                    const String& expected,
                    T value,
                    const char* path,
                    int line_number) {
  v8::Local<v8::Value> actual =
      ToV8Traits<IDLType>::ToV8(scope.GetScriptState(), value);
  String actual_string =
      ToCoreString(scope.GetIsolate(),
                   actual->ToString(scope.GetContext()).ToLocalChecked());
  if (expected != actual_string) {
    ADD_FAILURE_AT(path, line_number)
        << "ToV8 returns an incorrect value.\n  Actual: "
        << actual_string.Utf8() << "\nExpected: " << expected;
    return;
  }
}

TEST(ToV8TraitsTest, Any) {
  test::TaskEnvironment task_environment;
  const V8TestingScope scope;
  ScriptValue value(scope.GetIsolate(),
                    v8::Number::New(scope.GetIsolate(), 1234.0));
  v8::Local<v8::Value> actual1 =
      ToV8Traits<IDLAny>::ToV8(scope.GetScriptState(), value);
  double actual_as_number1 = actual1.As<v8::Number>()->Value();
  EXPECT_EQ(1234.0, actual_as_number1);

  v8::Local<v8::Value> actual2 =
      ToV8Traits<IDLAny>::ToV8(scope.GetScriptState(), actual1);
  EXPECT_EQ(actual1, actual2);
}

TEST(ToV8TraitsTest, Boolean) {
  test::TaskEnvironment task_environment;
  const V8TestingScope scope;
  TEST_TOV8_TRAITS(scope, IDLBoolean, "true", true);
  TEST_TOV8_TRAITS(scope, IDLBoolean, "false", false);
}

TEST(ToV8TraitsTest, BigInt) {
  test::TaskEnvironment task_environment;
  const V8TestingScope scope;
  uint64_t words[5];

  // 0
  TEST_TOV8_TRAITS(
      scope, IDLBigint, "0",
      BigInt(v8::BigInt::NewFromWords(scope.GetContext(), 0, 0, words)
                 .ToLocalChecked()));
  // +/- 1
  words[0] = 1;
  TEST_TOV8_TRAITS(
      scope, IDLBigint, "1",
      BigInt(v8::BigInt::NewFromWords(scope.GetContext(), 0, 1, words)
                 .ToLocalChecked()));
  TEST_TOV8_TRAITS(
      scope, IDLBigint, "-1",
      BigInt(v8::BigInt::NewFromWords(scope.GetContext(), 1, 1, words)
                 .ToLocalChecked()));

  // +/- 2^64
  words[0] = 0;
  words[1] = 1;
  TEST_TOV8_TRAITS(
      scope, IDLBigint, "18446744073709551616",
      BigInt(v8::BigInt::NewFromWords(scope.GetContext(), 0, 2, words)
                 .ToLocalChecked()));
  TEST_TOV8_TRAITS(
      scope, IDLBigint, "-18446744073709551616",
      BigInt(v8::BigInt::NewFromWords(scope.GetContext(), 1, 2, words)
                 .ToLocalChecked()));

  // +/- 2^128
  words[0] = 0;
  words[1] = 0;
  words[2] = 1;
  TEST_TOV8_TRAITS(
      scope, IDLBigint, "340282366920938463463374607431768211456",
      BigInt(v8::BigInt::NewFromWords(scope.GetContext(), 0, 3, words)
                 .ToLocalChecked()));
  TEST_TOV8_TRAITS(
      scope, IDLBigint, "-340282366920938463463374607431768211456",
      BigInt(v8::BigInt::NewFromWords(scope.GetContext(), 1, 3, words)
                 .ToLocalChecked()));

  // +/- 2^320 - 1
  uint64_t max = std::numeric_limits<uint64_t>::max();
  for (int i = 0; i < 5; i++) {
    words[i] = max;
  }
  TEST_TOV8_TRAITS(
      scope, IDLBigint,
      "213598703592091008239502170616955211460270452235665276994704160782221972"
      "5780640550022962086936575",
      BigInt(v8::BigInt::NewFromWords(scope.GetContext(), 0, 5, words)
                 .ToLocalChecked()));
  TEST_TOV8_TRAITS(
      scope, IDLBigint,
      "-21359870359209100823950217061695521146027045223566527699470416078222197"
      "25780640550022962086936575",
      BigInt(v8::BigInt::NewFromWords(scope.GetContext(), 1, 5, words)
                 .ToLocalChecked()));
}

TEST(ToV8TraitsTest, Integer) {
  test::TaskEnvironment task_environment;
  const V8TestingScope scope;
  // Test type matching
  // Integer
  TEST_TOV8_TRAITS(scope, IDLByte, "0", static_cast<int8_t>(0));
  TEST_TOV8_TRAITS(scope, IDLByte, "1", static_cast<int8_t>(1));
  TEST_TOV8_TRAITS(scope, IDLByte, "-2", static_cast<int8_t>(-2));
  TEST_TOV8_TRAITS(scope, IDLShort, "0", static_cast<int16_t>(0));
  TEST_TOV8_TRAITS(scope, IDLLong, "0", static_cast<int32_t>(0));
  TEST_TOV8_TRAITS(scope, IDLLongLong, "0", static_cast<int64_t>(0));
  TEST_TOV8_TRAITS(scope, IDLOctet, "0", static_cast<uint8_t>(0));
  TEST_TOV8_TRAITS(scope, IDLUnsignedShort, "0", static_cast<uint16_t>(0));
  TEST_TOV8_TRAITS(scope, IDLUnsignedLong, "0", static_cast<uint32_t>(0));
  TEST_TOV8_TRAITS(scope, IDLUnsignedLongLong, "0", static_cast<uint64_t>(0));
  // [Clamp] Integer
  TEST_TOV8_TRAITS(scope, IDLByteClamp, "0", static_cast<int8_t>(0));
  TEST_TOV8_TRAITS(scope, IDLShortClamp, "0", static_cast<int16_t>(0));
  TEST_TOV8_TRAITS(scope, IDLLongClamp, "0", static_cast<int32_t>(0));
  TEST_TOV8_TRAITS(scope, IDLLongLongClamp, "0", static_cast<int64_t>(0));
  TEST_TOV8_TRAITS(scope, IDLOctetClamp, "0", static_cast<uint8_t>(0));
  TEST_TOV8_TRAITS(scope, IDLUnsignedShortClamp, "0", static_cast<uint16_t>(0));
  TEST_TOV8_TRAITS(scope, IDLUnsignedLongClamp, "0", static_cast<uint32_t>(0));
  TEST_TOV8_TRAITS(scope, IDLUnsignedLongLongClamp, "0",
                   static_cast<uint64_t>(0));
  // [EnforceRange] Integer
  TEST_TOV8_TRAITS(scope, IDLByteEnforceRange, "0", static_cast<int8_t>(0));
  TEST_TOV8_TRAITS(scope, IDLShortEnforceRange, "0", static_cast<int16_t>(0));
  TEST_TOV8_TRAITS(scope, IDLLongEnforceRange, "0", static_cast<int32_t>(0));
  TEST_TOV8_TRAITS(scope, IDLLongLongEnforceRange, "0",
                   static_cast<int64_t>(0));
  TEST_TOV8_TRAITS(scope, IDLOctetEnforceRange, "0", static_cast<uint8_t>(0));
  TEST_TOV8_TRAITS(scope, IDLUnsignedShortEnforceRange, "0",
                   static_cast<uint16_t>(0));
  TEST_TOV8_TRAITS(scope, IDLUnsignedLongEnforceRange, "0",
                   static_cast<uint32_t>(0));
  TEST_TOV8_TRAITS(scope, IDLUnsignedLongLongEnforceRange, "0",
                   static_cast<uint64_t>(0));

  // Test the maximum and the minimum integer in the range
  TEST_TOV8_TRAITS(scope, IDLLong, "-2147483648",
                   std::numeric_limits<int32_t>::min());
  TEST_TOV8_TRAITS(scope, IDLLong, "2147483647",
                   std::numeric_limits<int32_t>::max());
  TEST_TOV8_TRAITS(scope, IDLUnsignedLong, "4294967295",
                   std::numeric_limits<uint32_t>::max());

  // v8::Number can represent exact numbers in [-(2^53-1), 2^53-1].
  TEST_TOV8_TRAITS(scope, IDLLongLong, "-9007199254740991",
                   static_cast<int64_t>(-9007199254740991));  // -(2^53-1)
  TEST_TOV8_TRAITS(scope, IDLLongLong, "9007199254740991",
                   static_cast<int64_t>(9007199254740991));  // 2^53-1
  TEST_TOV8_TRAITS(scope, IDLUnsignedLongLong, "9007199254740991",
                   static_cast<uint64_t>(9007199254740991));  // 2^53-1
}

TEST(ToV8TraitsTest, FloatAndDouble) {
  test::TaskEnvironment task_environment;
  const V8TestingScope scope;
  TEST_TOV8_TRAITS(scope, IDLFloat, "0.5", static_cast<float>(0.5));
  TEST_TOV8_TRAITS(scope, IDLUnrestrictedFloat, "-0.5",
                   static_cast<float>(-0.5));
  TEST_TOV8_TRAITS(scope, IDLDouble, "0.5", static_cast<double>(0.5));
  TEST_TOV8_TRAITS(scope, IDLUnrestrictedDouble, "-0.5",
                   static_cast<double>(-0.5));
  TEST_TOV8_TRAITS(scope, IDLUnrestrictedDouble, "NaN",
                   std::numeric_limits<double>::quiet_NaN());
  TEST_TOV8_TRAITS(scope, IDLUnrestrictedDouble, "Infinity",
                   std::numeric_limits<double>::infinity());
  TEST_TOV8_TRAITS(scope, IDLUnrestrictedDouble, "-Infinity",
                   -std::numeric_limits<double>::infinity());
}

TEST(ToV8TraitsTest, String) {
  test::TaskEnvironment task_environment;
  const V8TestingScope scope;
  const String string("string");
  const char* const charptr_string = "charptrString";
  // ByteString
  TEST_TOV8_TRAITS(scope, IDLByteString, "string", string);
  TEST_TOV8_TRAITS(scope, IDLByteString, "charptrString", charptr_string);
  // DOMString
  TEST_TOV8_TRAITS(scope, IDLString, "string", string);
  TEST_TOV8_TRAITS(scope, IDLString, "charptrString", charptr_string);
  TEST_TOV8_TRAITS(scope, IDLStringLegacyNullToEmptyString, "string", string);
  TEST_TOV8_TRAITS(scope, IDLStringLegacyNullToEmptyString, "charptrString",
                   charptr_string);
  // USVString
  TEST_TOV8_TRAITS(scope, IDLUSVString, "string", string);
  TEST_TOV8_TRAITS(scope, IDLUSVString, "charptrString", charptr_string);
  // [StringContext=TrustedHTML] DOMString
  TEST_TOV8_TRAITS(scope, IDLStringStringContextTrustedHTML, "string", string);
  TEST_TOV8_TRAITS(scope, IDLStringStringContextTrustedHTML, "charptrString",
                   charptr_string);
  TEST_TOV8_TRAITS(scope,
                   IDLStringLegacyNullToEmptyStringStringContextTrustedHTML,
                   "string", string);
  TEST_TOV8_TRAITS(scope,
                   IDLStringLegacyNullToEmptyStringStringContextTrustedHTML,
                   "charptrString", charptr_string);
  // [StringContext=TrustedScript] DOMString
  TEST_TOV8_TRAITS(scope, IDLStringStringContextTrustedScript, "string",
                   string);
  TEST_TOV8_TRAITS(scope, IDLStringStringContextTrustedScript, "charptrString",
                   charptr_string);
  TEST_TOV8_TRAITS(scope,
                   IDLStringLegacyNullToEmptyStringStringContextTrustedScript,
                   "string", string);
  TEST_TOV8_TRAITS(scope,
                   IDLStringLegacyNullToEmptyStringStringContextTrustedScript,
                   "charptrString", charptr_string);
  // [StringContext=TrustedScriptURL] USVString
  TEST_TOV8_TRAITS(scope, IDLUSVStringStringContextTrustedScriptURL, "string",
                   string);
  TEST_TOV8_TRAITS(scope, IDLUSVStringStringContextTrustedScriptURL,
                   "charptrString", charptr_string);
}

TEST(ToV8TraitsTest, EmptyString) {
  test::TaskEnvironment task_environment;
  const V8TestingScope scope;
  const String empty_string("");
  TEST_TOV8_TRAITS(scope, IDLString, "", empty_string);
  const char* const empty = "";
  TEST_TOV8_TRAITS(scope, IDLString, "", empty);
}

TEST(ToV8TraitsTest, Object) {
  test::TaskEnvironment task_environment;
  const V8TestingScope scope;
  Vector<String> string_vector;
  string_vector.push_back("hello");
  string_vector.push_back("world");
  ScriptValue value(scope.GetIsolate(),
                    ToV8Traits<IDLSequence<IDLString>>::ToV8(
                        scope.GetScriptState(), string_vector));
  TEST_TOV8_TRAITS(scope, IDLObject, "hello,world", value);
  v8::Local<v8::Value> actual =
      ToV8Traits<IDLObject>::ToV8(scope.GetScriptState(), value);
  EXPECT_TRUE(actual->IsObject());
}

TEST(ToV8TraitsTest, Promise) {
  test::TaskEnvironment task_environment;
  const V8TestingScope scope;
  auto promise = ToResolvedUndefinedPromise(scope.GetScriptState());
  TEST_TOV8_TRAITS(scope, IDLPromise<IDLUndefined>, "[object Promise]",
                   promise);
}

TEST(ToV8TraitsTest, NotShared) {
  test::TaskEnvironment task_environment;
  const V8TestingScope scope;
  auto not_shared = NotShared<DOMUint8Array>(DOMUint8Array::Create(2));
  not_shared->Data()[0] = static_cast<uint8_t>(0);
  not_shared->Data()[1] = static_cast<uint8_t>(255);
  TEST_TOV8_TRAITS(scope, NotShared<DOMUint8Array>, "0,255", not_shared);
}

TEST(ToV8TraitsTest, MaybeShared) {
  test::TaskEnvironment task_environment;
  const V8TestingScope scope;
  auto maybe_shared = MaybeShared<DOMInt8Array>(DOMInt8Array::Create(3));
  maybe_shared->Data()[0] = static_cast<int8_t>(-128);
  maybe_shared->Data()[1] = static_cast<int8_t>(0);
  maybe_shared->Data()[2] = static_cast<int8_t>(127);
  TEST_TOV8_TRAITS(scope, MaybeShared<DOMInt8Array>, "-128,0,127",
                   maybe_shared);
}

TEST(ToV8TraitsTest, Vector) {
  test::TaskEnvironment task_environment;
  const V8TestingScope scope;
  Vector<String> string_vector;
  string_vector.push_back("foo");
  string_vector.push_back("bar");
  TEST_TOV8_TRAITS(scope, IDLSequence<IDLString>, "foo,bar", string_vector);
}

TEST(ToV8TraitsTest, HeapVector) {
  test::TaskEnvironment task_environment;
  const V8TestingScope scope;
  HeapVector<Member<GarbageCollectedScriptWrappable>> heap_vector;
  heap_vector.push_back(
      MakeGarbageCollected<GarbageCollectedScriptWrappable>("hoge"));
  heap_vector.push_back(
      MakeGarbageCollected<GarbageCollectedScriptWrappable>("fuga"));
  TEST_TOV8_TRAITS(scope, IDLSequence<GarbageCollectedScriptWrappable>,
                   "hoge,fuga", heap_vector);

  const HeapVector<Member<GarbageCollectedScriptWrappable>>*
      const_garbage_collected_heap_vector = &heap_vector;
  TEST_TOV8_TRAITS(scope, IDLSequence<GarbageCollectedScriptWrappable>,
                   "hoge,fuga", *const_garbage_collected_heap_vector);
}

TEST(ToV8TraitsTest, BasicIDLTypeVectors) {
  test::TaskEnvironment task_environment;
  const V8TestingScope scope;

  Vector<int32_t> int32_vector;
  int32_vector.push_back(42);
  int32_vector.push_back(23);
  TEST_TOV8_TRAITS(scope, IDLSequence<IDLLong>, "42,23", int32_vector);

  Vector<int64_t> int64_vector;
  int64_vector.push_back(31773);
  int64_vector.push_back(404);
  TEST_TOV8_TRAITS(scope, IDLSequence<IDLLongLong>, "31773,404", int64_vector);

  Vector<uint32_t> uint32_vector;
  uint32_vector.push_back(1);
  uint32_vector.push_back(2);
  TEST_TOV8_TRAITS(scope, IDLSequence<IDLUnsignedLong>, "1,2", uint32_vector);

  Vector<uint64_t> uint64_vector;
  uint64_vector.push_back(1001);
  uint64_vector.push_back(2002);
  TEST_TOV8_TRAITS(scope, IDLSequence<IDLUnsignedLongLong>, "1001,2002",
                   uint64_vector);

  Vector<float> float_vector;
  float_vector.push_back(0.125);
  float_vector.push_back(1.);
  TEST_TOV8_TRAITS(scope, IDLSequence<IDLFloat>, "0.125,1", float_vector);

  Vector<double> double_vector;
  double_vector.push_back(2.3);
  double_vector.push_back(4.2);
  TEST_TOV8_TRAITS(scope, IDLSequence<IDLDouble>, "2.3,4.2", double_vector);

  Vector<bool> bool_vector;
  bool_vector.push_back(true);
  bool_vector.push_back(true);
  bool_vector.push_back(false);
  TEST_TOV8_TRAITS(scope, IDLSequence<IDLBoolean>, "true,true,false",
                   bool_vector);
}

TEST(ToV8TraitsTest, StringVectorVector) {
  test::TaskEnvironment task_environment;
  const V8TestingScope scope;

  Vector<String> string_vector1;
  string_vector1.push_back("foo");
  string_vector1.push_back("bar");
  Vector<String> string_vector2;
  string_vector2.push_back("quux");

  Vector<Vector<String>> compound_vector;
  compound_vector.push_back(string_vector1);
  compound_vector.push_back(string_vector2);

  EXPECT_EQ(2U, compound_vector.size());
  TEST_TOV8_TRAITS(scope, IDLSequence<IDLSequence<IDLString>>, "foo,bar,quux",
                   compound_vector);

  v8::Local<v8::Value> actual =
      ToV8Traits<IDLSequence<IDLSequence<IDLString>>>::ToV8(
          scope.GetScriptState(), compound_vector);
  v8::Local<v8::Object> result =
      actual->ToObject(scope.GetContext()).ToLocalChecked();
  v8::Local<v8::Value> vector1 =
      result->Get(scope.GetContext(), 0).ToLocalChecked();
  EXPECT_TRUE(vector1->IsArray());
  EXPECT_EQ(2U, vector1.As<v8::Array>()->Length());
  v8::Local<v8::Value> vector2 =
      result->Get(scope.GetContext(), 1).ToLocalChecked();
  EXPECT_TRUE(vector2->IsArray());
  EXPECT_EQ(1U, vector2.As<v8::Array>()->Length());
}

TEST(ToV8TraitsTest, ArrayAndSequence) {
  test::TaskEnvironment task_environment;
  const V8TestingScope scope;
  DOMPointInit* dom_point_init1 = DOMPointInit::Create();
  dom_point_init1->setW(1.0);
  DOMPointInit* dom_point_init2 = DOMPointInit::Create();
  dom_point_init2->setW(2.0);
  DOMPointInit* dom_point_init3 = DOMPointInit::Create();
  dom_point_init3->setW(3.0);
  HeapVector<Member<DOMPointInit>> dom_point_init_vector;
  dom_point_init_vector.push_back(dom_point_init1);
  dom_point_init_vector.push_back(dom_point_init2);
  v8::Local<v8::Value> v8_dom_point_init3 =
      ToV8Traits<DOMPointInit>::ToV8(scope.GetScriptState(), dom_point_init3);

  // Frozen array
  TEST_TOV8_TRAITS(scope, IDLArray<DOMPointInit>,
                   "[object Object],[object Object]", dom_point_init_vector);
  v8::Local<v8::Value> v8_frozen_array =
      ToV8Traits<IDLArray<DOMPointInit>>::ToV8(scope.GetScriptState(),
                                               dom_point_init_vector);

  bool is_value_set;
  ASSERT_TRUE(v8_frozen_array.As<v8::Object>()
                  ->Set(scope.GetContext(), 0, v8_dom_point_init3)
                  .To(&is_value_set));
  ASSERT_TRUE(is_value_set);
  v8::Local<v8::Value> element_of_frozen_array =
      v8_frozen_array.As<v8::Object>()
          ->Get(scope.GetContext(), 0)
          .ToLocalChecked();
  // An element of a frozen array cannot be changed.
  EXPECT_NE(element_of_frozen_array, v8_dom_point_init3);

  // Sequence
  TEST_TOV8_TRAITS(scope, IDLSequence<DOMPointInit>,
                   "[object Object],[object Object]", dom_point_init_vector);
  v8::Local<v8::Value> v8_sequence =
      ToV8Traits<IDLSequence<DOMPointInit>>::ToV8(scope.GetScriptState(),
                                                  dom_point_init_vector);
  ASSERT_TRUE(v8_sequence.As<v8::Object>()
                  ->Set(scope.GetContext(), 0, v8_dom_point_init3)
                  .To(&is_value_set));
  ASSERT_TRUE(is_value_set);
  v8::Local<v8::Value> element_of_sequence =
      v8_sequence.As<v8::Object>()->Get(scope.GetContext(), 0).ToLocalChecked();
  // An element of a sequence can be changed.
  EXPECT_EQ(element_of_sequence, v8_dom_point_init3);
}

TEST(ToV8TraitsTest, PairVector) {
  test::TaskEnvironment task_environment;
  const V8TestingScope scope;
  Vector<std::pair<String, int8_t>> pair_vector;
  pair_vector.push_back(std::make_pair("one", 1));
  pair_vector.push_back(std::make_pair("two", 2));
  using ByteRecord = IDLRecord<IDLString, IDLByte>;
  TEST_TOV8_TRAITS(scope, ByteRecord, "[object Object]", pair_vector);
  v8::Local<v8::Value> actual =
      ToV8Traits<ByteRecord>::ToV8(scope.GetScriptState(), pair_vector);
  v8::Local<v8::Object> result =
      actual->ToObject(scope.GetContext()).ToLocalChecked();
  v8::Local<v8::Value> one =
      result->Get(scope.GetContext(), V8String(scope.GetIsolate(), "one"))
          .ToLocalChecked();
  EXPECT_EQ(1, one->NumberValue(scope.GetContext()).FromJust());
  v8::Local<v8::Value> two =
      result->Get(scope.GetContext(), V8String(scope.GetIsolate(), "two"))
          .ToLocalChecked();
  EXPECT_EQ(2, two->NumberValue(scope.GetContext()).FromJust());
}

TEST(ToV8TraitsTest, PairHeapVector) {
  test::TaskEnvironment task_environment;
  const V8TestingScope scope;
  HeapVector<std::pair<String, Member<GarbageCollectedScriptWrappable>>>
      pair_heap_vector;
  pair_heap_vector.push_back(std::make_pair(
      "one", MakeGarbageCollected<GarbageCollectedScriptWrappable>("foo")));
  pair_heap_vector.push_back(std::make_pair(
      "two", MakeGarbageCollected<GarbageCollectedScriptWrappable>("bar")));
  using HeapRecord = IDLRecord<IDLString, GarbageCollectedScriptWrappable>;
  TEST_TOV8_TRAITS(scope, HeapRecord, "[object Object]", pair_heap_vector);
  v8::Local<v8::Value> actual =
      ToV8Traits<HeapRecord>::ToV8(scope.GetScriptState(), pair_heap_vector);
  v8::Local<v8::Object> result =
      actual->ToObject(scope.GetContext()).ToLocalChecked();
  v8::Local<v8::Value> one =
      result->Get(scope.GetContext(), V8String(scope.GetIsolate(), "one"))
          .ToLocalChecked();
  EXPECT_TRUE(one->IsObject());
  EXPECT_EQ(String("foo"),
            ToCoreString(scope.GetIsolate(),
                         one->ToString(scope.GetContext()).ToLocalChecked()));
  v8::Local<v8::Value> two =
      result->Get(scope.GetContext(), V8String(scope.GetIsolate(), "two"))
          .ToLocalChecked();
  EXPECT_TRUE(two->IsObject());
  EXPECT_EQ(String("bar"),
            ToCoreString(scope.GetIsolate(),
                         two->ToString(scope.GetContext()).ToLocalChecked()));
}

TEST(ToV8TraitsTest, NullStringInputForNoneNullableType) {
  test::TaskEnvironment task_environment;
  const V8TestingScope scope;
  const String null_string;
  TEST_TOV8_TRAITS(scope, IDLString, "", null_string);
  const char* const null = nullptr;
  TEST_TOV8_TRAITS(scope, IDLString, "", null);
}

TEST(ToV8TraitsTest, Nullable) {
  test::TaskEnvironment task_environment;
  const V8TestingScope scope;
  // Nullable Boolean
  TEST_TOV8_TRAITS(scope, IDLNullable<IDLBoolean>, "null", std::nullopt);
  TEST_TOV8_TRAITS(scope, IDLNullable<IDLBoolean>, "true", true);
  // Nullable Integer
  TEST_TOV8_TRAITS(scope, IDLNullable<IDLByte>, "null", std::nullopt);
  TEST_TOV8_TRAITS(scope, IDLNullable<IDLUnsignedLong>, "0",
                   std::optional<uint32_t>(0));
  // Nullable Float
  TEST_TOV8_TRAITS(scope, IDLNullable<IDLFloat>, "null",
                   std::optional<float>());
  TEST_TOV8_TRAITS(scope, IDLNullable<IDLFloat>, "0.5",
                   std::optional<float>(0.5));
  // Nullable Double
  TEST_TOV8_TRAITS(scope, IDLNullable<IDLDouble>, "null",
                   std::optional<double>());
  TEST_TOV8_TRAITS(scope, IDLNullable<IDLDouble>, "3.14",
                   std::optional<double>(3.14));
  // Nullable DOMHighResTimeStamp
  TEST_TOV8_TRAITS(scope, IDLNullable<IDLDOMHighResTimeStamp>, "null",
                   std::optional<base::Time>());
  TEST_TOV8_TRAITS(scope, IDLNullable<IDLDOMHighResTimeStamp>, "123.456",
                   std::optional<base::Time>(
                       base::Time::FromMillisecondsSinceUnixEpoch(123.456)));
}

TEST(ToV8TraitsTest, NullableString) {
  test::TaskEnvironment task_environment;
  const V8TestingScope scope;
  TEST_TOV8_TRAITS(scope, IDLNullable<IDLString>, "null", String());
  TEST_TOV8_TRAITS(scope, IDLNullable<IDLString>, "string", String("string"));
  TEST_TOV8_TRAITS(scope, IDLNullable<IDLString>, "", String(""));
  const char* const null = nullptr;
  TEST_TOV8_TRAITS(scope, IDLNullable<IDLString>, "null", null);
  const char* const charptr_string = "charptrString";
  TEST_TOV8_TRAITS(scope, IDLNullable<IDLString>, "charptrString",
                   charptr_string);
  const char* const charptr_empty_string = "";
  TEST_TOV8_TRAITS(scope, IDLNullable<IDLString>, "", charptr_empty_string);
}

TEST(ToV8TraitsTest, NullableObject) {
  test::TaskEnvironment task_environment;
  const V8TestingScope scope;
  TEST_TOV8_TRAITS(
      scope, IDLNullable<IDLObject>, "null",
      ScriptValue(scope.GetIsolate(), v8::Null(scope.GetIsolate())));

  Vector<uint8_t> uint8_vector;
  uint8_vector.push_back(static_cast<uint8_t>(0));
  uint8_vector.push_back(static_cast<uint8_t>(255));
  ScriptValue value(scope.GetIsolate(),
                    ToV8Traits<IDLNullable<IDLSequence<IDLOctet>>>::ToV8(
                        scope.GetScriptState(), uint8_vector));
  TEST_TOV8_TRAITS(scope, IDLNullable<IDLObject>, "0,255", value);
  v8::Local<v8::Value> actual =
      ToV8Traits<IDLNullable<IDLObject>>::ToV8(scope.GetScriptState(), value);
  EXPECT_TRUE(actual->IsObject());
}

TEST(ToV8TraitsTest, NullableScriptWrappable) {
  test::TaskEnvironment task_environment;
  const V8TestingScope scope;
  TEST_TOV8_TRAITS(scope, IDLNullable<EventTarget>, "null", nullptr);
  EventTarget* event_target = EventTarget::Create(scope.GetScriptState());
  TEST_TOV8_TRAITS(scope, IDLNullable<EventTarget>, "[object EventTarget]",
                   event_target);
}

TEST(ToV8TraitsTest, NullableDictionary) {
  test::TaskEnvironment task_environment;
  const V8TestingScope scope;
  // bindings::DictionaryBase
  TEST_TOV8_TRAITS(scope, IDLNullable<bindings::DictionaryBase>, "null",
                   nullptr);
  DOMPointInit* dom_point_init = DOMPointInit::Create();
  TEST_TOV8_TRAITS(scope, IDLNullable<DOMPointInit>, "null", nullptr);
  TEST_TOV8_TRAITS(scope, IDLNullable<DOMPointInit>, "[object Object]",
                   dom_point_init);
}

TEST(ToV8TraitsTest, NullableCallbackFunction) {
  test::TaskEnvironment task_environment;
  const V8TestingScope scope;
  TEST_TOV8_TRAITS(scope, IDLNullable<V8CreateHTMLCallback>, "null", nullptr);
  V8CreateHTMLCallback* v8_create_html_callback =
      V8CreateHTMLCallback::Create(scope.GetContext()->Global());
  TEST_TOV8_TRAITS(scope, IDLNullable<V8CreateHTMLCallback>, "[object Window]",
                   v8_create_html_callback);
}

TEST(ToV8TraitsTest, NullableCallbackInterface) {
  test::TaskEnvironment task_environment;
  const V8TestingScope scope;
  TEST_TOV8_TRAITS(scope, IDLNullable<V8CreateHTMLCallback>, "null", nullptr);
  V8EventListener* v8_event_listener =
      V8EventListener::Create(scope.GetContext()->Global());
  TEST_TOV8_TRAITS(scope, IDLNullable<V8EventListener>, "[object Window]",
                   v8_event_listener);
}

TEST(ToV8TraitsTest, NullableEnumeration) {
  test::TaskEnvironment task_environment;
  const V8TestingScope scope;
  TEST_TOV8_TRAITS(scope, IDLNullable<V8AlignSetting>, "null", std::nullopt);
  const std::optional<V8AlignSetting> v8_align_setting =
      V8AlignSetting::Create("start");
  TEST_TOV8_TRAITS(scope, IDLNullable<V8AlignSetting>, "start",
                   v8_align_setting);
}

TEST(ToV8TraitsTest, NullableArray) {
  test::TaskEnvironment task_environment;
  const V8TestingScope scope;
  TEST_TOV8_TRAITS(scope, IDLNullable<IDLArray<DOMPointInit>>, "null",
                   std::nullopt);

  DOMPointInit* dom_point_init1 = DOMPointInit::Create();
  DOMPointInit* dom_point_init2 = DOMPointInit::Create();
  HeapVector<Member<DOMPointInit>> dom_point_init_vector;
  dom_point_init_vector.push_back(dom_point_init1);
  dom_point_init_vector.push_back(dom_point_init2);
  TEST_TOV8_TRAITS(scope, IDLNullable<IDLArray<DOMPointInit>>,
                   "[object Object],[object Object]", dom_point_init_vector);
}

TEST(ToV8TraitsTest, NullableDate) {
  test::TaskEnvironment task_environment;
  const V8TestingScope scope;
  TEST_TOV8_TRAITS(scope, IDLNullable<IDLDate>, "null", std::nullopt);

  base::Time expected_date;
  EXPECT_TRUE(
      base::Time::FromString("Fri, 01 Jan 2021 00:00:00 GMT", &expected_date));
  v8::Local<v8::Value> result = ToV8Traits<IDLNullable<IDLDate>>::ToV8(
      scope.GetScriptState(), std::optional<base::Time>(expected_date));
  String actual_string =
      ToCoreString(scope.GetIsolate(),
                   result->ToString(scope.GetContext()).ToLocalChecked());
  base::Time actual_date;
  EXPECT_TRUE(
      base::Time::FromString(actual_string.Ascii().c_str(), &actual_date));
  EXPECT_EQ(expected_date, actual_date);
}

TEST(ToV8TraitsTest, Union) {
  test::TaskEnvironment task_environment;
  const V8TestingScope scope;
  const auto* usv_string =
      MakeGarbageCollected<V8UnionFileOrFormDataOrUSVString>(
          "https://example.com/");
  TEST_TOV8_TRAITS(scope, V8UnionFileOrFormDataOrUSVString,
                   "https://example.com/", usv_string);
}

TEST(ToV8TraitsTest, NullableUnion) {
  test::TaskEnvironment task_environment;
  const V8TestingScope scope;
  TEST_TOV8_TRAITS(scope, IDLNullable<V8UnionFileOrFormDataOrUSVString>, "null",
                   nullptr);
  const auto* usv_string =
      MakeGarbageCollected<V8UnionFileOrFormDataOrUSVString>(
          "http://example.com/");
  TEST_TOV8_TRAITS(scope, IDLNullable<V8UnionFileOrFormDataOrUSVString>,
                   "http://example.com/", usv_string);
}

TEST(ToV8TraitsTest, Optional) {
  test::TaskEnvironment task_environment;
  const V8TestingScope scope;
  TEST_TOV8_TRAITS(scope, IDLOptional<DOMPointInit>, "undefined", nullptr);
  DOMPointInit* dom_point_init = DOMPointInit::Create();
  TEST_TOV8_TRAITS(scope, IDLOptional<DOMPointInit>, "[object Object]",
                   dom_point_init);

  TEST_TOV8_TRAITS(scope, IDLOptional<IDLAny>, "undefined", ScriptValue());
  ScriptValue value(scope.GetIsolate(),
                    v8::Number::New(scope.GetIsolate(), 3.14));
  TEST_TOV8_TRAITS(scope, IDLOptional<IDLAny>, "3.14", value);
}

}  // namespace

}  // namespace blink
```