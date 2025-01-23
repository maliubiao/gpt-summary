Response:
Let's break down the thought process for analyzing the C++ code and generating the explanation.

1. **Understanding the Goal:** The request asks for a functional description of the C++ code, connections to JavaScript, potential errors, and examples. The core task is to bridge the gap between low-level C++ testing and high-level JavaScript concepts.

2. **Initial Scan for Keywords:**  A quick scan reveals keywords like "TypedArray", "ArrayBuffer", "DataView", "Uint8Array", "Int32Array", etc. These immediately suggest the code is about testing JavaScript's typed array functionality within the V8 engine.

3. **Identifying the Testing Framework:** The `#include "test/cctest/test-api.h"` strongly indicates this is part of V8's internal testing framework (`cctest`). The `THREADED_TEST` and `TEST` macros confirm this. This means the primary function is to verify the correctness of typed array implementations.

4. **Analyzing the Test Structure:**  The code is organized into various `THREADED_TEST` and `TEST` blocks. Each block appears to focus on a specific aspect of typed arrays or a particular typed array type. This modular structure makes analysis easier.

5. **Focusing on Key Functions and Helpers:**
    * `CheckElementValue`: A helper function to verify the value of an element at a specific offset. This signals direct memory manipulation.
    * `ObjectWithExternalArrayTestHelper`:  This function seems central. It takes a `TypedArray` object and performs a series of operations on it, including setting properties, accessing elements via indexing, and running JavaScript code that interacts with the typed array. The name suggests it's testing typed arrays backed by external memory.
    * `TypedArrayTestHelper`: This function creates various typed arrays (`Uint8Array`, `Int32Array`, etc.) using `ArrayBuffer` and calls `ObjectWithExternalArrayTestHelper`. This reinforces the idea that it's testing different typed array types.

6. **Connecting C++ to JavaScript:** The `CompileRun` function is a crucial link. It takes a C++ string, interprets it as JavaScript code within a V8 context, and executes it. This explains how the C++ tests interact with and verify JavaScript behavior related to typed arrays.

7. **Inferring Functionality from Test Cases:** By examining the JavaScript code snippets within `CompileRun`, we can understand what aspects of typed arrays are being tested:
    * Basic access and assignment (`ext_array[1] = 1`).
    * Iteration and summation.
    * Handling of different data types (integers, floats, `NaN`, `Infinity`).
    * Boundary conditions and out-of-bounds access (checking that errors *aren't* thrown for out-of-bounds).
    * Interactions with regular JavaScript arrays (`js_array.concat(ext_array)`).
    * `delete` operator behavior on typed arrays (although it doesn't truly delete).
    * Performance optimization hints (`%PrepareFunctionForOptimization`, `%OptimizeFunctionOnNextCall`).
    * Internal properties and methods (`HasBuffer`).

8. **Identifying Potential Programming Errors:** The tests often demonstrate how JavaScript engines handle certain scenarios, which implicitly points to common errors developers might make:
    * Assuming `delete` works the same way on typed arrays as on regular objects.
    * Incorrectly assuming out-of-bounds access throws errors.
    * Not understanding the type coercion rules when assigning different data types to typed arrays.
    * Overlooking the clamped behavior of `Uint8ClampedArray`.

9. **Generating JavaScript Examples:** Based on the `CompileRun` code, it's straightforward to create equivalent, standalone JavaScript examples that illustrate the tested features.

10. **Reasoning About Inputs and Outputs:**  For specific test cases (especially within `ObjectWithExternalArrayTestHelper`), it's possible to infer input values and predict expected outputs. For instance, the loops assigning and summing elements have predictable results.

11. **Addressing the `.tq` Question:** The prompt specifically asks about `.tq` files. Knowing that Torque is V8's internal language for implementing built-in functions, the answer is that if the file *were* `.tq`, it would contain the implementation of typed array methods, not just tests.

12. **Structuring the Output:**  The final step is to organize the findings into a clear and comprehensive answer, addressing each point in the original request. Using headings and bullet points improves readability. Providing both general descriptions and specific examples is crucial.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe this file defines the typed array API.
* **Correction:**  The `#include "src/api/api-inl.h"` suggests it *uses* the API, and the test structure points to testing, not definition.
* **Initial thought:** The numerical checks are arbitrary.
* **Refinement:** The numerical ranges in the `TypedArrayTestHelper` calls (e.g., `0, 0xFF` for `Uint8Array`) correspond to the minimum and maximum values for those data types, indicating boundary testing.
* **Initial thought:**  The `%PrepareFunctionForOptimization` calls are just boilerplate.
* **Refinement:** While part of testing, they specifically target the performance of typed array operations within optimized code, which is an important aspect of V8.

By following this systematic approach, combining code analysis with knowledge of V8 internals and JavaScript concepts, a detailed and accurate explanation can be generated.
`v8/test/cctest/test-api-typed-array.cc` 是一个 V8 JavaScript 引擎的 C++ 源代码文件，其主要功能是**测试 V8 引擎提供的 JavaScript Typed Array API 的正确性和功能性**。

具体来说，该文件包含了针对各种 Typed Array 类型（例如 `Uint8Array`, `Int32Array`, `Float64Array` 等）以及 `DataView` 对象的单元测试。 这些测试用例旨在验证以下方面：

1. **创建和初始化 Typed Arrays 和 DataViews:** 测试使用不同的构造函数和参数创建这些对象是否按预期工作。
2. **读写元素:** 验证通过索引访问和修改 Typed Array 中的元素，以及使用 `DataView` 的特定方法（如 `getInt8`, `setFloat64` 等）读写不同数据类型的能力。
3. **边界条件:** 测试在 Typed Array 的边界附近进行读写操作的行为，例如访问第一个和最后一个元素，以及尝试访问超出范围的索引。
4. **数据类型转换:** 检查在将不同类型的值赋给 Typed Array 元素时，V8 是否按照规范进行类型转换。例如，将浮点数赋值给整型 Typed Array 时的截断行为。
5. **与 ArrayBuffer 的关联:** 验证 Typed Array 和 DataView 对象与其底层的 `ArrayBuffer` 之间的正确关联，包括 `byteOffset` 和 `byteLength` 属性。
6. **SharedArrayBuffer 的支持:** 测试 Typed Array 和 DataView 是否能正确地与 `SharedArrayBuffer` 一起工作，这是用于在多个 JavaScript 线程之间共享内存的机制。
7. **Internal Fields:**  检查 TypedArray 和 DataView 对象的内部字段是否被正确地初始化和管理。
8. **性能优化:**  使用 `%PrepareFunctionForOptimization` 和 `%OptimizeFunctionOnNextCall` 等内置函数来测试在优化代码路径下 Typed Array 操作的正确性。
9. **与普通 JavaScript 对象的交互:** 测试 Typed Array 在与普通 JavaScript 对象（例如设置属性、作为原型链的一部分）交互时的行为。
10. **`HasBuffer` 方法:**  验证 TypedArray 对象在不同大小的情况下是否正确报告其是否拥有内部缓冲区。

**关于文件扩展名 `.tq`：**

如果 `v8/test/cctest/test-api-typed-array.cc` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码文件**。 Torque 是 V8 内部使用的一种领域特定语言，用于实现 JavaScript 的内置函数和运行时库。然而，根据你提供的文件内容，它的扩展名是 `.cc`，这意味着它是一个 C++ 文件。

**与 JavaScript 的功能关系及示例：**

`v8/test/cctest/test-api-typed-array.cc` 测试的功能直接对应于 JavaScript 中提供的 Typed Array 和 DataView API。以下是一些 JavaScript 示例，展示了这些 API 的用法以及 `test-api-typed-array.cc` 中可能测试的场景：

```javascript
// 创建不同类型的 Typed Arrays
const uint8 = new Uint8Array(10);
const int32 = new Int32Array(new ArrayBuffer(16), 4, 3); // 从 ArrayBuffer 的偏移量 4 开始，长度为 3

// 创建 DataView
const buffer = new ArrayBuffer(16);
const dataView = new DataView(buffer, 2, 8); // 从偏移量 2 开始，长度为 8

// 读写 Typed Array 元素
uint8[0] = 255;
console.log(uint8[0]); // 输出 255

int32[0] = -100;
console.log(int32[0]); // 输出 -100

// 读写 DataView 中的数据
dataView.setInt16(0, 1024); // 从偏移量 0 开始写入一个 16 位整数
console.log(dataView.getInt16(0)); // 输出 1024

dataView.setFloat64(2, 3.14159); // 从偏移量 2 开始写入一个 64 位浮点数
console.log(dataView.getFloat64(2)); // 输出 3.14159

// 边界条件
console.log(uint8[9]); // 访问最后一个元素
// console.log(uint8[10]); // 访问超出范围的索引，不会抛出错误，返回 undefined (在 C++ 测试中会验证不会抛出异常)

// 类型转换
uint8[1] = 300; // 会被截断为 44 (300 % 256)
console.log(uint8[1]);

int32[1] = 3.9; // 会被截断为 3
console.log(int32[1]);

// 与普通 JavaScript 对象的交互 (测试中会验证)
const obj = {};
obj.typedArray = uint8;
console.log(obj.typedArray[0]);

Array.prototype.push.call(uint8, 10); // 尝试调用 Array 的方法，可能会导致错误或意外行为，测试会覆盖这些情况
```

**代码逻辑推理的假设输入与输出：**

让我们以 `ObjectWithExternalArrayTestHelper` 函数中的一个代码片段为例进行推理：

**假设输入：**

* `ElementType` 为 `int32_t`
* `obj` 是一个长度为 8 的 `Int32Array`，底层 buffer 初始化为 `[0, 1, 2, 3, 4, 5, 6, 7]`

**JavaScript 代码片段：**

```javascript
  result = CompileRun(
      "for (var i = 0; i < 8; i++) {"
      "  ext_array[i] = i;"
      "}"
      "var sum = 0;"
      "for (var i = 0; i < 8; i++) {"
      "  sum += ext_array[i];"
      "}"
      "sum;");
```

**推理过程：**

1. 第一个循环将 `ext_array` 的每个元素设置为其索引值。因此，`ext_array` 的值变为 `[0, 1, 2, 3, 4, 5, 6, 7]`。
2. 第二个循环遍历 `ext_array` 并将每个元素的值加到 `sum` 变量上。
3. `sum` 的计算过程是 `0 + 1 + 2 + 3 + 4 + 5 + 6 + 7`。

**预期输出：**

`result` 应该包含整数值 `28`。

**用户常见的编程错误示例：**

1. **假设 `delete` 操作会减小 Typed Array 的长度：**

   ```javascript
   const arr = new Uint8Array([1, 2, 3]);
   delete arr[1];
   console.log(arr.length); // 输出 3，长度不变
   console.log(arr[1]);    // 输出 undefined，但数组长度没有改变
   ```

   用户可能错误地认为 `delete` 会像操作普通对象一样删除元素并缩小数组长度。实际上，`delete` 只是将 Typed Array 中相应索引的值设置为 "empty"，但不会改变数组的长度。

2. **忽略不同 Typed Array 类型的溢出和截断行为：**

   ```javascript
   const uint8 = new Uint8Array(1);
   uint8[0] = 300; // 期望抛出错误，但实际会截断
   console.log(uint8[0]); // 输出 44 (300 % 256)

   const int8 = new Int8Array(1);
   int8[0] = 150; // 期望抛出错误，但实际会处理为 -106 (150 - 256)
   console.log(int8[0]);
   ```

   用户可能没有意识到不同类型的 Typed Array 在赋值超出其范围的值时会发生溢出或截断，而不是抛出错误。`Uint8Array` 会进行模运算，而有符号类型则会根据其二进制表示进行处理。

3. **错误地假设 Typed Array 的方法与普通数组完全相同：**

   ```javascript
   const typedArray = new Uint8Array([1, 2, 3]);
   const result = typedArray.map(x => x * 2);
   console.log(result); // 输出一个新的 Uint8Array [2, 4, 6]

   typedArray.push(4); // 报错：typedArray.push is not a function
   ```

   用户可能认为所有适用于普通数组的方法都可以在 Typed Array 上使用。虽然像 `map`、`filter` 等迭代方法可用，但像 `push`、`pop` 这样修改长度的方法在 Typed Array 上是不存在的。

`v8/test/cctest/test-api-typed-array.cc` 中编写的测试用例会覆盖这些常见的编程错误场景，确保 V8 引擎能够按照 JavaScript 规范正确地处理这些情况，或者在不符合规范的行为时能够给出合理的处理方式。

### 提示词
```
这是目录为v8/test/cctest/test-api-typed-array.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-api-typed-array.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
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
```