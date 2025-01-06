Response: Let's break down the thought process for analyzing this C++ code and explaining its functionality with JavaScript examples.

1. **Understand the Goal:** The request asks for a summary of the C++ code's functionality and how it relates to JavaScript, using JavaScript examples. This means we need to identify what the C++ code *does* and how those actions manifest in JavaScript's behavior.

2. **Initial Scan for Keywords:**  Look for immediately recognizable terms. In this code, "TypedArray," "ArrayBuffer," "DataView," and specific typed array names like "Uint8Array," "Int32Array," etc., jump out. These strongly suggest the code is testing the implementation of JavaScript's TypedArray and DataView objects within the V8 engine.

3. **Identify the Testing Framework:**  The presence of `TEST()`, `THREADED_TEST()`, `CHECK()`, and the inclusion of headers like `"test/cctest/test-api.h"` indicate this is part of a unit testing framework (likely `cctest` within the V8 project). This tells us the primary goal is *verification* of expected behavior.

4. **Analyze Individual Test Cases:**  The code is organized into numerous test cases. It's crucial to examine what each test case is doing:
    * **`ObjectWithExternalArrayTestHelper`:** This looks like a core helper function. It takes a TypedArray object and performs various JavaScript operations on it (setting properties, accessing elements, loops, assignments, handling different data types). The name suggests it's dealing with TypedArrays backed by *external* memory (not just V8's internal heap).
    * **`TypedArrayTestHelper`:** This function creates different types of TypedArrays (Uint8Array, Int32Array, etc.) using `ArrayBuffer` and calls `ObjectWithExternalArrayTestHelper` to test them. This confirms that the code is specifically testing the behavior of each TypedArray type. The different integer ranges passed (`0xFF`, `-0x80`, etc.) hint at testing boundary conditions and data type constraints.
    * **`DataView` tests:** These tests focus on the `DataView` object, checking its creation, byte offset, and byte length.
    * **`Shared*Array` tests:** These are similar to the regular TypedArray tests but use `SharedArrayBuffer`, indicating testing for concurrency and shared memory scenarios.
    * **`Is*` tests:** These tests verify that the `IsUint8Array()`, `IsDataView()`, etc., JavaScript methods correctly identify the type of an object.
    * **`InternalFieldsOnTypedArray` and `InternalFieldsOnDataView`:**  These likely test the internal structure of these objects within V8, ensuring certain internal pointers are initialized correctly.
    * **`TestOnHeapHasBuffer` and `TestOffHeapHasBuffer`:** These tests focus on how and when TypedArrays acquire their underlying `ArrayBuffer`. The "on-heap" and "off-heap" distinction suggests testing different allocation strategies based on the size of the TypedArray.

5. **Connect C++ to JavaScript:**  As you analyze each test, think about the corresponding JavaScript functionality being tested. For example:
    * The loops and assignments in `ObjectWithExternalArrayTestHelper` directly correspond to JavaScript code that interacts with TypedArrays.
    * The boundary checks with `low` and `high` values relate to the valid range of values for each TypedArray type in JavaScript.
    * The "out-of-range loads/stores" tests verify JavaScript's behavior when accessing indices outside the bounds of a TypedArray.
    * The tests involving `__proto__` and `concat` examine how TypedArrays interact with standard JavaScript array methods.

6. **Formulate JavaScript Examples:** Based on the C++ test logic, create concise JavaScript examples that demonstrate the same behavior being tested. Focus on clarity and direct correspondence to the C++ actions. For instance, the C++ sets values and then reads them back; a JavaScript example should do the same. The C++ tests for out-of-bounds access; the JavaScript example should attempt that and observe the lack of error.

7. **Structure the Explanation:** Organize the findings logically:
    * Start with a high-level summary of the file's purpose.
    * Explain the core functionality being tested (TypedArrays, DataView).
    * Detail the specific aspects covered by the tests (creation, access, boundaries, type checking, shared memory, internal structure).
    * Provide the JavaScript examples alongside the corresponding C++ functionality.
    * Conclude with a summary of the relationship between the C++ code and JavaScript.

8. **Refine and Review:**  Read through the explanation to ensure it's clear, accurate, and easy to understand. Check that the JavaScript examples are correct and illustrate the intended points. Make sure the connection between the C++ and JavaScript is explicitly stated. For instance, if the C++ tests how NaNs are handled, the JavaScript example should demonstrate that NaN assignment results in a specific behavior for that TypedArray type.

Self-Correction Example During the Process:

* **Initial Thought:** "This code just creates and manipulates TypedArrays."
* **Correction:**  "No, it's *testing* the creation and manipulation. The `CHECK()` calls are assertions that verify expected outcomes. The different test cases focus on specific aspects like boundary conditions, different data types, and shared memory."

By following these steps, you can effectively analyze C++ source code like this and explain its relevance to JavaScript functionality using illustrative examples.
这个 C++ 源代码文件 `v8/test/cctest/test-api-typed-array.cc` 是 V8 JavaScript 引擎的测试代码，专门用于测试 **JavaScript 中 `TypedArray` 和 `DataView` 相关的 API 功能**。

**主要功能归纳:**

1. **创建和基本操作测试:** 测试各种类型的 `TypedArray` (如 `Uint8Array`, `Int32Array`, `Float64Array` 等) 和 `DataView` 的创建、长度、字节偏移、字节长度等基本属性。它验证了通过 C++ API 创建的这些对象与 JavaScript 中创建的行为是否一致。

2. **元素访问和赋值测试:**  测试通过索引访问和设置 `TypedArray` 元素的行为。这包括了对不同数据类型的赋值，以及超出边界访问时的行为（不应该抛出异常）。

3. **类型转换和边界值测试:** 测试在 `TypedArray` 中赋值不同类型的值（例如，将字符串赋值给整型数组）时的类型转换行为。同时也测试了边界值（最大值、最小值）和特殊值（`NaN`, `Infinity`）的处理。

4. **性能相关的测试 (通过 `%PrepareFunctionForOptimization` 等):** 代码中使用了 V8 内部的函数，如 `%PrepareFunctionForOptimization` 和 `%OptimizeFunctionOnNextCall`，这意味着它还测试了 `TypedArray` 操作的性能，例如在经过 JIT 优化后的执行效率。

5. **与其他 JavaScript 特性的交互测试:**  测试 `TypedArray` 如何与其他的 JavaScript 特性进行交互，例如设置属性、作为原型链的一部分、与普通数组进行 `concat` 操作等。

6. **`SharedArrayBuffer` 相关测试:**  测试基于 `SharedArrayBuffer` 创建的 `TypedArray` 和 `DataView` 的功能，这涉及到多线程环境下的数据共享和同步。

7. **类型判断测试:** 测试 JavaScript 中用于判断对象类型的函数，如 `isUint8Array()`, `isDataView()` 等是否能正确识别通过 C++ API 创建的 `TypedArray` 和 `DataView` 对象。

8. **内部字段测试:**  测试 `TypedArray` 和 `DataView` 对象的内部字段是否正确初始化。

9. **`HasBuffer` 测试:**  测试 `TypedArray` 对象是否正确管理其底层的 `ArrayBuffer`，包括何时分配和是否持有 `Buffer`。

**与 JavaScript 功能的关联及举例:**

这个 C++ 文件直接测试了 JavaScript 中 `TypedArray` 和 `DataView` 对象的行为。以下是一些 JavaScript 例子，展示了该 C++ 文件正在测试的功能：

**1. 创建和基本操作:**

```javascript
// 对应 C++ 中的 TypedArrayTestHelper 和 DataView 测试

// 创建一个 Uint8Array
const uint8Array = new Uint8Array(10);
console.log(uint8Array.length); // 输出 10
console.log(uint8Array.byteLength); // 输出 10
console.log(uint8Array.byteOffset); // 输出 0

// 创建一个指定偏移和长度的 Int16Array
const buffer = new ArrayBuffer(20);
const int16Array = new Int16Array(buffer, 4, 5);
console.log(int16Array.length); // 输出 5
console.log(int16Array.byteLength); // 输出 10 (5 * 2)
console.log(int16Array.byteOffset); // 输出 4

// 创建一个 DataView
const dataView = new DataView(buffer, 2, 8);
console.log(dataView.byteLength); // 输出 8
console.log(dataView.byteOffset); // 输出 2
```

**2. 元素访问和赋值:**

```javascript
// 对应 C++ 中的 ObjectWithExternalArrayTestHelper 中的元素访问和赋值部分

const float32Array = new Float32Array(5);
float32Array[0] = 1.5;
float32Array[1] = -2.7;
console.log(float32Array[0]); // 输出 1.5
console.log(float32Array[1]); // 输出 -2.7

// 超出边界访问不会抛出错误，但会返回 undefined (或者赋值不会生效)
console.log(float32Array[10]); // 输出 undefined
float32Array[10] = 5;
console.log(float32Array[10]); // 仍然输出 undefined
```

**3. 类型转换和边界值:**

```javascript
// 对应 C++ 中关于类型转换和边界值的测试

const int8Array = new Int8Array(3);
int8Array[0] = 100;
int8Array[1] = "120"; // 字符串会被转换为数字
int8Array[2] = 200;  // 超出 Int8 的最大值 127，会发生截断（按补码计算）
console.log(int8Array[0]); // 输出 100
console.log(int8Array[1]); // 输出 120
console.log(int8Array[2]); // 输出 -56 (200 的 8 位补码)

const uint8ClampedArray = new Uint8ClampedArray(2);
uint8ClampedArray[0] = 300; // 会被限制到最大值 255
uint8ClampedArray[1] = -50;  // 会被限制到最小值 0
console.log(uint8ClampedArray[0]); // 输出 255
console.log(uint8ClampedArray[1]); // 输出 0
```

**4. 与其他 JavaScript 特性的交互:**

```javascript
// 对应 C++ 中测试与属性、原型链交互的部分

const uint16Array = new Uint16Array(2);
uint16Array.myProperty = "hello";
console.log(uint16Array.myProperty); // 输出 "hello"

const arr = [1, 2, 3];
const combined = arr.concat(uint16Array);
console.log(combined); // 输出 [1, 2, 3, 0, 0] (Uint16Array 初始值为 0)
```

**总结:**

`v8/test/cctest/test-api-typed-array.cc` 文件是 V8 引擎中用于验证 JavaScript `TypedArray` 和 `DataView` 功能实现正确性的关键测试代码。它通过 C++ API 操作这些对象，并编写断言来确保其行为与 JavaScript 规范一致。理解这个文件有助于深入了解 V8 引擎如何实现和测试 JavaScript 的二进制数据处理能力。

Prompt: 
```
这是目录为v8/test/cctest/test-api-typed-array.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2019 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/api/api-inl.h"
#include "src/base/strings.h"
#include "src/objects/js-array-buffer-inl.h"
#include "src/objects/js-array-buffer.h"
#include "test/cctest/heap/heap-utils.h"
#include "test/cctest/test-api.h"

using ::v8::Array;
using ::v8::Context;
using ::v8::Local;
using ::v8::Value;

namespace {

void CheckElementValue(i::Isolate* isolate, int expected,
                       i::Handle<i::JSAny> obj, int offset) {
  i::Tagged<i::Object> element =
      *i::Object::GetElement(isolate, obj, offset).ToHandleChecked();
  CHECK_EQ(expected, i::Smi::ToInt(element));
}

template <class ElementType>
void ObjectWithExternalArrayTestHelper(Local<Context> context,
                                       v8::Local<v8::TypedArray> obj,
                                       int element_count,
                                       i::ExternalArrayType array_type,
                                       int64_t low, int64_t high) {
  i::Handle<i::JSTypedArray> jsobj = v8::Utils::OpenHandle(*obj);
  v8::Isolate* v8_isolate = context->GetIsolate();
  i::Isolate* isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  obj->Set(context, v8_str("field"), v8::Int32::New(v8_isolate, 1503))
      .FromJust();
  CHECK(context->Global()->Set(context, v8_str("ext_array"), obj).FromJust());
  v8::Local<v8::Value> result = CompileRun("ext_array.field");
  CHECK_EQ(1503, result->Int32Value(context).FromJust());
  result = CompileRun("ext_array[1]");
  CHECK_EQ(1, result->Int32Value(context).FromJust());

  // Check assigned smis
  result = CompileRun(
      "for (var i = 0; i < 8; i++) {"
      "  ext_array[i] = i;"
      "}"
      "var sum = 0;"
      "for (var i = 0; i < 8; i++) {"
      "  sum += ext_array[i];"
      "}"
      "sum;");

  CHECK_EQ(28, result->Int32Value(context).FromJust());
  // Check pass through of assigned smis
  result = CompileRun(
      "var sum = 0;"
      "for (var i = 0; i < 8; i++) {"
      "  sum += ext_array[i] = ext_array[i] = -i;"
      "}"
      "sum;");
  CHECK_EQ(-28, result->Int32Value(context).FromJust());

  // Check assigned smis in reverse order
  result = CompileRun(
      "for (var i = 8; --i >= 0; ) {"
      "  ext_array[i] = i;"
      "}"
      "var sum = 0;"
      "for (var i = 0; i < 8; i++) {"
      "  sum += ext_array[i];"
      "}"
      "sum;");
  CHECK_EQ(28, result->Int32Value(context).FromJust());

  // Check pass through of assigned HeapNumbers
  result = CompileRun(
      "var sum = 0;"
      "for (var i = 0; i < 16; i+=2) {"
      "  sum += ext_array[i] = ext_array[i] = (-i * 0.5);"
      "}"
      "sum;");
  CHECK_EQ(-28, result->Int32Value(context).FromJust());

  // Check assigned HeapNumbers
  result = CompileRun(
      "for (var i = 0; i < 16; i+=2) {"
      "  ext_array[i] = (i * 0.5);"
      "}"
      "var sum = 0;"
      "for (var i = 0; i < 16; i+=2) {"
      "  sum += ext_array[i];"
      "}"
      "sum;");
  CHECK_EQ(28, result->Int32Value(context).FromJust());

  // Check assigned HeapNumbers in reverse order
  result = CompileRun(
      "for (var i = 14; i >= 0; i-=2) {"
      "  ext_array[i] = (i * 0.5);"
      "}"
      "var sum = 0;"
      "for (var i = 0; i < 16; i+=2) {"
      "  sum += ext_array[i];"
      "}"
      "sum;");
  CHECK_EQ(28, result->Int32Value(context).FromJust());

  v8::base::ScopedVector<char> test_buf(1024);

  // Check legal boundary conditions.
  // The repeated loads and stores ensure the ICs are exercised.
  const char* boundary_program =
      "var res = 0;"
      "for (var i = 0; i < 16; i++) {"
      "  ext_array[i] = %lld;"
      "  if (i > 8) {"
      "    res = ext_array[i];"
      "  }"
      "}"
      "res;";
  v8::base::SNPrintF(test_buf, boundary_program, low);
  result = CompileRun(test_buf.begin());
  CHECK_EQ(low, result->IntegerValue(context).FromJust());

  v8::base::SNPrintF(test_buf, boundary_program, high);
  result = CompileRun(test_buf.begin());
  CHECK_EQ(high, result->IntegerValue(context).FromJust());

  // Check misprediction of type in IC.
  result = CompileRun(
      "var tmp_array = ext_array;"
      "var sum = 0;"
      "for (var i = 0; i < 8; i++) {"
      "  tmp_array[i] = i;"
      "  sum += tmp_array[i];"
      "  if (i == 4) {"
      "    tmp_array = {};"
      "  }"
      "}"
      "sum;");
  // Force GC to trigger verification.
  i::heap::InvokeMajorGC(CcTest::heap());
  CHECK_EQ(28, result->Int32Value(context).FromJust());

  // Make sure out-of-range loads do not throw.
  v8::base::SNPrintF(test_buf,
                     "var caught_exception = false;"
                     "try {"
                     "  ext_array[%d];"
                     "} catch (e) {"
                     "  caught_exception = true;"
                     "}"
                     "caught_exception;",
                     element_count);
  result = CompileRun(test_buf.begin());
  CHECK(!result->BooleanValue(v8_isolate));

  // Make sure out-of-range stores do not throw.
  v8::base::SNPrintF(test_buf,
                     "var caught_exception = false;"
                     "try {"
                     "  ext_array[%d] = 1;"
                     "} catch (e) {"
                     "  caught_exception = true;"
                     "}"
                     "caught_exception;",
                     element_count);
  result = CompileRun(test_buf.begin());
  CHECK(!result->BooleanValue(v8_isolate));

  // Check other boundary conditions, values and operations.
  result = CompileRun(
      "for (var i = 0; i < 8; i++) {"
      "  ext_array[7] = undefined;"
      "}"
      "ext_array[7];");
  CHECK_EQ(0, result->Int32Value(context).FromJust());
  if (array_type == i::kExternalFloat64Array ||
      array_type == i::kExternalFloat32Array) {
    CHECK(std::isnan(i::Object::NumberValue(Cast<i::Number>(
        *i::Object::GetElement(isolate, jsobj, 7).ToHandleChecked()))));
  } else {
    CheckElementValue(isolate, 0, jsobj, 7);
  }

  result = CompileRun(
      "for (var i = 0; i < 8; i++) {"
      "  ext_array[6] = '2.3';"
      "}"
      "ext_array[6];");
  CHECK_EQ(2, result->Int32Value(context).FromJust());
  CHECK_EQ(2,
           static_cast<int>(i::Object::NumberValue(Cast<i::Number>(
               *i::Object::GetElement(isolate, jsobj, 6).ToHandleChecked()))));

  if (array_type != i::kExternalFloat32Array &&
      array_type != i::kExternalFloat64Array) {
    // Though the specification doesn't state it, be explicit about
    // converting NaNs and +/-Infinity to zero.
    result = CompileRun(
        "for (var i = 0; i < 8; i++) {"
        "  ext_array[i] = 5;"
        "}"
        "for (var i = 0; i < 8; i++) {"
        "  ext_array[i] = NaN;"
        "}"
        "ext_array[5];");
    CHECK_EQ(0, result->Int32Value(context).FromJust());
    CheckElementValue(isolate, 0, jsobj, 5);

    result = CompileRun(
        "for (var i = 0; i < 8; i++) {"
        "  ext_array[i] = 5;"
        "}"
        "for (var i = 0; i < 8; i++) {"
        "  ext_array[i] = Infinity;"
        "}"
        "ext_array[5];");
    int expected_value =
        (array_type == i::kExternalUint8ClampedArray) ? 255 : 0;
    CHECK_EQ(expected_value, result->Int32Value(context).FromJust());
    CheckElementValue(isolate, expected_value, jsobj, 5);

    result = CompileRun(
        "for (var i = 0; i < 8; i++) {"
        "  ext_array[i] = 5;"
        "}"
        "for (var i = 0; i < 8; i++) {"
        "  ext_array[i] = -Infinity;"
        "}"
        "ext_array[5];");
    CHECK_EQ(0, result->Int32Value(context).FromJust());
    CheckElementValue(isolate, 0, jsobj, 5);

    // Check truncation behavior of integral arrays.
    const char* unsigned_data =
        "var source_data = [0.6, 10.6];"
        "var expected_results = [0, 10];";
    const char* signed_data =
        "var source_data = [0.6, 10.6, -0.6, -10.6];"
        "var expected_results = [0, 10, 0, -10];";
    const char* pixel_data =
        "var source_data = [0.6, 10.6];"
        "var expected_results = [1, 11];";
    bool is_unsigned = (array_type == i::kExternalUint8Array ||
                        array_type == i::kExternalUint16Array ||
                        array_type == i::kExternalUint32Array);
    bool is_pixel_data = array_type == i::kExternalUint8ClampedArray;

    v8::base::SNPrintF(
        test_buf,
        "%s"
        "var all_passed = true;"
        "for (var i = 0; i < source_data.length; i++) {"
        "  for (var j = 0; j < 8; j++) {"
        "    ext_array[j] = source_data[i];"
        "  }"
        "  all_passed = all_passed &&"
        "               (ext_array[5] == expected_results[i]);"
        "}"
        "all_passed;",
        (is_unsigned ? unsigned_data
                     : (is_pixel_data ? pixel_data : signed_data)));
    result = CompileRun(test_buf.begin());
    CHECK(result->BooleanValue(v8_isolate));
  }

  {
    ElementType* data_ptr = static_cast<ElementType*>(jsobj->DataPtr());
    for (int i = 0; i < element_count; i++) {
      data_ptr[i] = static_cast<ElementType>(i);
    }
  }

  bool old_natives_flag_sentry = i::v8_flags.allow_natives_syntax;
  i::v8_flags.allow_natives_syntax = true;

  // Test complex assignments
  result = CompileRun(
      "function ee_op_test_complex_func(sum) {"
      " for (var i = 0; i < 40; ++i) {"
      "   sum += (ext_array[i] += 1);"
      "   sum += (ext_array[i] -= 1);"
      " } "
      " return sum;"
      "};"
      "%PrepareFunctionForOptimization(ee_op_test_complex_func);"
      "sum=0;"
      "sum=ee_op_test_complex_func(sum);"
      "sum=ee_op_test_complex_func(sum);"
      "%OptimizeFunctionOnNextCall(ee_op_test_complex_func);"
      "sum=ee_op_test_complex_func(sum);"
      "sum;");
  CHECK_EQ(4800, result->Int32Value(context).FromJust());

  // Test count operations
  result = CompileRun(
      "function ee_op_test_count_func(sum) {"
      " for (var i = 0; i < 40; ++i) {"
      "   sum += (++ext_array[i]);"
      "   sum += (--ext_array[i]);"
      " } "
      " return sum;"
      "};"
      "%PrepareFunctionForOptimization(ee_op_test_count_func);"
      "sum=0;"
      "sum=ee_op_test_count_func(sum);"
      "sum=ee_op_test_count_func(sum);"
      "%OptimizeFunctionOnNextCall(ee_op_test_count_func);"
      "sum=ee_op_test_count_func(sum);"
      "sum;");
  CHECK_EQ(4800, result->Int32Value(context).FromJust());

  i::v8_flags.allow_natives_syntax = old_natives_flag_sentry;

  result = CompileRun(
      "ext_array[3] = 33;"
      "delete ext_array[3];"
      "ext_array[3];");
  CHECK_EQ(33, result->Int32Value(context).FromJust());

  result = CompileRun(
      "ext_array[0] = 10; ext_array[1] = 11;"
      "ext_array[2] = 12; ext_array[3] = 13;"
      "try { ext_array.__defineGetter__('2', function() { return 120; }); }"
      "catch (e) { }"
      "ext_array[2];");
  CHECK_EQ(12, result->Int32Value(context).FromJust());

  result = CompileRun(
      "var js_array = new Array(40);"
      "js_array[0] = 77;"
      "js_array;");
  CHECK_EQ(77, v8::Object::Cast(*result)
                   ->Get(context, v8_str("0"))
                   .ToLocalChecked()
                   ->Int32Value(context)
                   .FromJust());

  result = CompileRun(
      "ext_array[1] = 23;"
      "ext_array.__proto__ = [];"
      "js_array.__proto__ = ext_array;"
      "js_array.concat(ext_array);");
  CHECK_EQ(77, v8::Object::Cast(*result)
                   ->Get(context, v8_str("0"))
                   .ToLocalChecked()
                   ->Int32Value(context)
                   .FromJust());
  CHECK_EQ(23, v8::Object::Cast(*result)
                   ->Get(context, v8_str("1"))
                   .ToLocalChecked()
                   ->Int32Value(context)
                   .FromJust());

  result = CompileRun("ext_array[1] = 23;");
  CHECK_EQ(23, result->Int32Value(context).FromJust());
}

template <typename ElementType, typename TypedArray, class ArrayBufferType>
void TypedArrayTestHelper(i::ExternalArrayType array_type, int64_t low,
                          int64_t high) {
  const int kElementCount = 50;

  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope handle_scope(isolate);

  Local<ArrayBufferType> ab =
      ArrayBufferType::New(isolate, (kElementCount + 2) * sizeof(ElementType));
  Local<TypedArray> ta =
      TypedArray::New(ab, 2 * sizeof(ElementType), kElementCount);
  CheckInternalFieldsAreZero<v8::ArrayBufferView>(ta);
  CHECK_EQ(kElementCount, static_cast<int>(ta->Length()));
  CHECK_EQ(2 * sizeof(ElementType), ta->ByteOffset());
  CHECK_EQ(kElementCount * sizeof(ElementType), ta->ByteLength());
  CHECK(ab->Equals(env.local(), ta->Buffer()).FromJust());

  ElementType* data =
      reinterpret_cast<ElementType*>(ab->GetBackingStore()->Data()) + 2;
  for (int i = 0; i < kElementCount; i++) {
    data[i] = static_cast<ElementType>(i);
  }

  ObjectWithExternalArrayTestHelper<ElementType>(env.local(), ta, kElementCount,
                                                 array_type, low, high);

  // TODO(v8:11111): Use API functions for testing these, once they're exposed
  // via the API.
  i::DirectHandle<i::JSTypedArray> i_ta = v8::Utils::OpenDirectHandle(*ta);
  CHECK(!i_ta->is_length_tracking());
  CHECK(!i_ta->is_backed_by_rab());
}

}  // namespace

THREADED_TEST(Uint8Array) {
  TypedArrayTestHelper<uint8_t, v8::Uint8Array, v8::ArrayBuffer>(
      i::kExternalUint8Array, 0, 0xFF);
}

THREADED_TEST(Int8Array) {
  TypedArrayTestHelper<int8_t, v8::Int8Array, v8::ArrayBuffer>(
      i::kExternalInt8Array, -0x80, 0x7F);
}

THREADED_TEST(Uint16Array) {
  TypedArrayTestHelper<uint16_t, v8::Uint16Array, v8::ArrayBuffer>(
      i::kExternalUint16Array, 0, 0xFFFF);
}

THREADED_TEST(Int16Array) {
  TypedArrayTestHelper<int16_t, v8::Int16Array, v8::ArrayBuffer>(
      i::kExternalInt16Array, -0x8000, 0x7FFF);
}

THREADED_TEST(Uint32Array) {
  TypedArrayTestHelper<uint32_t, v8::Uint32Array, v8::ArrayBuffer>(
      i::kExternalUint32Array, 0, UINT_MAX);
}

THREADED_TEST(Int32Array) {
  TypedArrayTestHelper<int32_t, v8::Int32Array, v8::ArrayBuffer>(
      i::kExternalInt32Array, INT_MIN, INT_MAX);
}

THREADED_TEST(Float32Array) {
  TypedArrayTestHelper<float, v8::Float32Array, v8::ArrayBuffer>(
      i::kExternalFloat32Array, -500, 500);
}

THREADED_TEST(Float64Array) {
  TypedArrayTestHelper<double, v8::Float64Array, v8::ArrayBuffer>(
      i::kExternalFloat64Array, -500, 500);
}

THREADED_TEST(Uint8ClampedArray) {
  TypedArrayTestHelper<uint8_t, v8::Uint8ClampedArray, v8::ArrayBuffer>(
      i::kExternalUint8ClampedArray, 0, 0xFF);
}

THREADED_TEST(DataView) {
  const int kSize = 50;

  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope handle_scope(isolate);

  Local<v8::ArrayBuffer> ab = v8::ArrayBuffer::New(isolate, 2 + kSize);
  Local<v8::DataView> dv = v8::DataView::New(ab, 2, kSize);
  CheckInternalFieldsAreZero<v8::ArrayBufferView>(dv);
  CHECK_EQ(2u, dv->ByteOffset());
  CHECK_EQ(kSize, static_cast<int>(dv->ByteLength()));
  CHECK(ab->Equals(env.local(), dv->Buffer()).FromJust());

  // TODO(v8:11111): Use API functions for testing these, once they're exposed
  // via the API.
  i::DirectHandle<i::JSDataViewOrRabGsabDataView> i_dv =
      v8::Utils::OpenDirectHandle(*dv);
  CHECK(!i_dv->is_length_tracking());
  CHECK(!i_dv->is_backed_by_rab());
}

THREADED_TEST(SharedUint8Array) {
  TypedArrayTestHelper<uint8_t, v8::Uint8Array, v8::SharedArrayBuffer>(
      i::kExternalUint8Array, 0, 0xFF);
}

THREADED_TEST(SharedInt8Array) {
  TypedArrayTestHelper<int8_t, v8::Int8Array, v8::SharedArrayBuffer>(
      i::kExternalInt8Array, -0x80, 0x7F);
}

THREADED_TEST(SharedUint16Array) {
  TypedArrayTestHelper<uint16_t, v8::Uint16Array, v8::SharedArrayBuffer>(
      i::kExternalUint16Array, 0, 0xFFFF);
}

THREADED_TEST(SharedInt16Array) {
  TypedArrayTestHelper<int16_t, v8::Int16Array, v8::SharedArrayBuffer>(
      i::kExternalInt16Array, -0x8000, 0x7FFF);
}

THREADED_TEST(SharedUint32Array) {
  TypedArrayTestHelper<uint32_t, v8::Uint32Array, v8::SharedArrayBuffer>(
      i::kExternalUint32Array, 0, UINT_MAX);
}

THREADED_TEST(SharedInt32Array) {
  TypedArrayTestHelper<int32_t, v8::Int32Array, v8::SharedArrayBuffer>(
      i::kExternalInt32Array, INT_MIN, INT_MAX);
}

THREADED_TEST(SharedFloat32Array) {
  TypedArrayTestHelper<float, v8::Float32Array, v8::SharedArrayBuffer>(
      i::kExternalFloat32Array, -500, 500);
}

THREADED_TEST(SharedFloat64Array) {
  TypedArrayTestHelper<double, v8::Float64Array, v8::SharedArrayBuffer>(
      i::kExternalFloat64Array, -500, 500);
}

THREADED_TEST(SharedUint8ClampedArray) {
  TypedArrayTestHelper<uint8_t, v8::Uint8ClampedArray, v8::SharedArrayBuffer>(
      i::kExternalUint8ClampedArray, 0, 0xFF);
}

THREADED_TEST(SharedDataView) {
  const int kSize = 50;

  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope handle_scope(isolate);

  Local<v8::SharedArrayBuffer> ab =
      v8::SharedArrayBuffer::New(isolate, 2 + kSize);
  Local<v8::DataView> dv = v8::DataView::New(ab, 2, kSize);
  CheckInternalFieldsAreZero<v8::ArrayBufferView>(dv);
  CHECK_EQ(2u, dv->ByteOffset());
  CHECK_EQ(kSize, static_cast<int>(dv->ByteLength()));
  CHECK(ab->Equals(env.local(), dv->Buffer()).FromJust());

  // TODO(v8:11111): Use API functions for testing these, once they're exposed
  // via the API.
  i::DirectHandle<i::JSDataViewOrRabGsabDataView> i_dv =
      v8::Utils::OpenDirectHandle(*dv);
  CHECK(!i_dv->is_length_tracking());
  CHECK(!i_dv->is_backed_by_rab());
}

#define IS_ARRAY_BUFFER_VIEW_TEST(View)                                     \
  THREADED_TEST(Is##View) {                                                 \
    LocalContext env;                                                       \
    v8::Isolate* isolate = env->GetIsolate();                               \
    v8::HandleScope handle_scope(isolate);                                  \
                                                                            \
    Local<Value> result = CompileRun(                                       \
        "var ab = new ArrayBuffer(128);"                                    \
        "new " #View "(ab)");                                               \
    CHECK(result->IsArrayBufferView());                                     \
    CHECK(result->Is##View());                                              \
    CheckInternalFieldsAreZero<v8::ArrayBufferView>(result.As<v8::View>()); \
  }

IS_ARRAY_BUFFER_VIEW_TEST(Uint8Array)
IS_ARRAY_BUFFER_VIEW_TEST(Int8Array)
IS_ARRAY_BUFFER_VIEW_TEST(Uint16Array)
IS_ARRAY_BUFFER_VIEW_TEST(Int16Array)
IS_ARRAY_BUFFER_VIEW_TEST(Uint32Array)
IS_ARRAY_BUFFER_VIEW_TEST(Int32Array)
IS_ARRAY_BUFFER_VIEW_TEST(Float32Array)
IS_ARRAY_BUFFER_VIEW_TEST(Float64Array)
IS_ARRAY_BUFFER_VIEW_TEST(Uint8ClampedArray)
IS_ARRAY_BUFFER_VIEW_TEST(DataView)

#undef IS_ARRAY_BUFFER_VIEW_TEST

TEST(InternalFieldsOnTypedArray) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::Context> context = env.local();
  Context::Scope context_scope(context);
  v8::Local<v8::ArrayBuffer> buffer = v8::ArrayBuffer::New(isolate, 1);
  v8::Local<v8::Uint8Array> array = v8::Uint8Array::New(buffer, 0, 1);
  for (int i = 0; i < v8::ArrayBufferView::kInternalFieldCount; i++) {
    CHECK_EQ(static_cast<void*>(nullptr),
             array->GetAlignedPointerFromInternalField(i));
  }
}

TEST(InternalFieldsOnDataView) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::Context> context = env.local();
  Context::Scope context_scope(context);
  v8::Local<v8::ArrayBuffer> buffer = v8::ArrayBuffer::New(isolate, 1);
  v8::Local<v8::DataView> array = v8::DataView::New(buffer, 0, 1);
  for (int i = 0; i < v8::ArrayBufferView::kInternalFieldCount; i++) {
    CHECK_EQ(static_cast<void*>(nullptr),
             array->GetAlignedPointerFromInternalField(i));
  }
}

namespace {
void TestOnHeapHasBuffer(const char* array_name, size_t elem_size) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope handle_scope(isolate);

  v8::base::ScopedVector<char> source(128);
  // Test on-heap sizes.
  for (size_t size = 0; size <= i::JSTypedArray::kMaxSizeInHeap;
       size += elem_size) {
    size_t length = size / elem_size;
    v8::base::SNPrintF(source, "new %sArray(%zu)", array_name, length);
    auto typed_array =
        v8::Local<v8::TypedArray>::Cast(CompileRun(source.begin()));

    CHECK_EQ(length, typed_array->Length());

    // Should not (yet) have a buffer.
    CHECK(!typed_array->HasBuffer());

    // Get the buffer and check its length.
    i::DirectHandle<i::JSTypedArray> i_typed_array =
        v8::Utils::OpenDirectHandle(*typed_array);
    auto i_array_buffer1 = i_typed_array->GetBuffer();
    CHECK_EQ(size, i_array_buffer1->byte_length());
    CHECK(typed_array->HasBuffer());

    // Should have the same buffer each time.
    auto i_array_buffer2 = i_typed_array->GetBuffer();
    CHECK(i_array_buffer1.is_identical_to(i_array_buffer2));
  }
}

void TestOffHeapHasBuffer(const char* array_name, size_t elem_size) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope handle_scope(isolate);

  v8::base::ScopedVector<char> source(128);
  // Test off-heap sizes.
  size_t size = i::JSTypedArray::kMaxSizeInHeap;
  for (int i = 0; i < 3; i++) {
    size_t length = 1 + (size / elem_size);
    v8::base::SNPrintF(source, "new %sArray(%zu)", array_name, length);
    auto typed_array =
        v8::Local<v8::TypedArray>::Cast(CompileRun(source.begin()));
    CHECK_EQ(length, typed_array->Length());

    // Should already have a buffer.
    CHECK(typed_array->HasBuffer());

    // Get the buffer and check its length.
    i::DirectHandle<i::JSTypedArray> i_typed_array =
        v8::Utils::OpenDirectHandle(*typed_array);
    auto i_array_buffer1 = i_typed_array->GetBuffer();
    CHECK_EQ(length * elem_size, i_array_buffer1->byte_length());

    size *= 2;
  }
}

}  // namespace

#define TEST_HAS_BUFFER(array_name, elem_size)    \
  TEST(OnHeap_##array_name##Array_HasBuffer) {    \
    TestOnHeapHasBuffer(#array_name, elem_size);  \
  }                                               \
  TEST(OffHeap_##array_name##_HasBuffer) {        \
    TestOffHeapHasBuffer(#array_name, elem_size); \
  }

TEST_HAS_BUFFER(Uint8, 1)
TEST_HAS_BUFFER(Int8, 1)
TEST_HAS_BUFFER(Uint16, 2)
TEST_HAS_BUFFER(Int16, 2)
TEST_HAS_BUFFER(Uint32, 4)
TEST_HAS_BUFFER(Int32, 4)
TEST_HAS_BUFFER(Float32, 4)
TEST_HAS_BUFFER(Float64, 8)

#undef TEST_HAS_BUFFER

"""

```