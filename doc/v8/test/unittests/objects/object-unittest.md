Response:
Let's break down the thought process for analyzing this C++ unittest file for V8.

1. **Identify the core purpose:** The filename `object-unittest.cc` within the `v8/test/unittests/objects/` directory immediately suggests that this file contains unit tests specifically for the `Object` functionality in V8. This is a strong starting point.

2. **Scan the includes:**  The `#include` directives provide valuable clues about the areas being tested:
    * `<cmath>`, `<iostream>`, `<limits>`: Standard C++ libraries, likely used for basic operations and assertions.
    * `"src/api/api-inl.h"`:  Indicates interaction with the V8 public API, though the `-inl.h` suggests internal usage.
    * `"src/codegen/compiler.h"`: Implies testing of interactions or assumptions made by the compiler regarding objects.
    * `"src/objects/hash-table-inl.h"`, `"src/objects/objects-inl.h"`, `"src/objects/objects.h"`, `"src/objects/string-set.h"`: These are core V8 object system headers. We can expect tests related to object creation, manipulation, properties, and specific object types like hash tables and strings.
    * `"test/unittests/test-utils.h"`:  V8's internal testing utilities are used.
    * `"testing/gtest/include/gtest/gtest.h"`:  Confirms that Google Test is the testing framework used.

3. **Examine the namespaces:** `namespace v8 { namespace internal { namespace { ... }}}`  shows the code is within V8's internal implementation, and the anonymous namespace suggests helper functions used only within this test file.

4. **Analyze the helper functions:** The anonymous namespace contains `IsInStringInstanceTypeList` and `CheckOneInstanceType`. These functions deal with `InstanceType`, which strongly hints at testing the internal type system of V8 objects, specifically string types.

5. **Focus on the `TEST` macros:**  These are Google Test macros indicating individual test cases. Go through each one and summarize its intent:
    * `TEST(Object, InstanceTypeList)`: Checks if all defined `InstanceType` values are correctly classified as string or non-string.
    * `TEST(Object, InstanceTypeListOrder)`: Verifies the numerical order of `InstanceType` enums.
    * `TEST(Object, StructListOrder)`:  Similar to the above, but for `STRUCT_LIST_GENERATOR`. This likely tests the ordering of internal struct representations.
    * `TEST_F(ObjectWithIsolate, DictionaryGrowth)`: Tests the growth behavior of `NumberDictionary` (a V8 internal hash map) as elements are added. The name "DictionaryGrowth" is very descriptive.
    * `TEST_F(TestWithNativeContext, EmptyFunctionScopeInfo)`: Checks if the `ScopeInfo` (related to variable scope) of an empty function is correctly set up.
    * `TEST_F(ObjectTest, NoSideEffectsToString)`: Examines the behavior of `Object::NoSideEffectsToString`, likely a function to get a string representation of an object without invoking potentially observable side effects. It tests various object types.
    * `TEST_F(ObjectTest, EnumCache)`:  Focuses on the `EnumCache`, an optimization for iterating over object properties. It tests how the cache is shared and updated across different object maps (hidden classes).
    * `TEST_F(ObjectTest, ObjectMethodsThatTruncateMinusZero)`: Tests specific object conversion methods (`ToInteger`, `ToLength`, `ToIndex`) and their handling of negative zero.
    * `TEST_F(ObjectTest, ...)` for various `FunctionKind` tests:  These test helper functions related to classifying different kinds of JavaScript functions (arrow functions, async functions, generators, etc.).
    * `TEST_F(ObjectTest, ConstructorInstanceTypes)`: Checks the `InstanceType` assigned to built-in JavaScript constructor functions (like `Array`, `RegExp`).
    * `TEST_F(ObjectTest, AddDataPropertyNameCollision)` and `TEST_F(ObjectTest, AddDataPropertyNameCollisionDeprecatedMap)`:  These test scenarios where attempts are made to add properties with the same name, potentially under different map states (including deprecated maps). The "DEATH_IF_SUPPORTED" macro strongly indicates testing for expected crashes or assertions in debug builds.

6. **Connect the tests to JavaScript functionality:** For tests that seem related to observable JavaScript behavior, provide illustrative examples. For instance, the `EnumCache` test directly relates to how `for...in` loops work. The `NoSideEffectsToString` test is about the string conversion of objects.

7. **Infer code logic and provide examples:** When a test case involves specific logic (like the dictionary growth), provide a step-by-step explanation of the expected behavior, including input and output (capacity in the dictionary example).

8. **Identify potential programming errors:**  Look for tests that highlight common pitfalls. The property name collision tests demonstrate a scenario that would lead to unexpected behavior if not handled correctly by the engine.

9. **Consider the `.tq` check:** Since the prompt specifically asks about `.tq` files (Torque), it's important to explicitly state that this file is C++ and not Torque.

10. **Structure the answer:**  Organize the findings logically. Start with a high-level summary, then detail the functionalities of each test case, connect them to JavaScript where relevant, and provide code examples and explanations. Address all points raised in the prompt.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe some tests directly manipulate object memory layouts.
* **Correction:** While the tests interact with internal object structures, they primarily go through public or internal APIs for object manipulation, which is the correct way to test V8's behavior. Direct memory manipulation would be too brittle and might not reflect real-world usage.
* **Initial thought:** Focus heavily on the C++ details of the test setup.
* **Correction:** While the C++ is important, the prompt also asks about the *functionality* being tested and its relation to JavaScript. Balance the C++ analysis with explanations of the JavaScript concepts involved.
* **Realization:** The `DEATH_IF_SUPPORTED` macro is a key indicator of testing for error conditions and internal assertions. Emphasize this when discussing those test cases.

By following these steps, we can systematically analyze the C++ unittest file and provide a comprehensive answer addressing all aspects of the prompt.
`v8/test/unittests/objects/object-unittest.cc` 是一个 V8 源代码文件，它包含了针对 V8 中 `Object` 对象的单元测试。它的主要功能是 **验证 V8 引擎中 `Object` 相关的各种功能的正确性**。

以下是该文件中的测试用例所涵盖的一些具体功能：

**1. Instance 类型列表 (Instance Type List):**

* **功能:** 验证 V8 内部定义的各种对象实例类型 (InstanceType) 的正确性。特别是检查字符串类型的实例类型是否正确地设置了 `kStringTag` 标志。
* **代码逻辑推理:**  该部分代码遍历 `INSTANCE_TYPE_LIST` 和 `STRING_TYPE_LIST` 宏定义中的所有实例类型。它断言所有字符串类型的 `InstanceType` 都满足 `(instance_type & kIsNotStringMask) == kStringTag`，而所有非字符串类型的则不满足。
* **假设输入与输出:**
    * **假设输入:**  V8 定义了一系列 `InstanceType` 枚举值，例如 `JS_OBJECT_TYPE`, `STRING_TYPE`, `ARRAY_TYPE` 等。
    * **预期输出:**  对于 `STRING_TYPE`，断言 `(STRING_TYPE & kIsNotStringMask) == kStringTag` 为真。对于 `JS_OBJECT_TYPE`，断言 `(JS_OBJECT_TYPE & kIsNotStringMask) == kStringTag` 为假。

**2. Instance 类型列表顺序 (Instance Type List Order):**

* **功能:**  验证 `INSTANCE_TYPE_LIST` 宏定义中实例类型的定义顺序是否正确（通常是按照数值递增的顺序）。
* **代码逻辑推理:** 代码遍历 `INSTANCE_TYPE_LIST_BASE` 中定义的实例类型，并断言当前类型的数值大于前一个类型的数值。
* **假设输入与输出:**
    * **假设输入:**  `INSTANCE_TYPE_LIST_BASE` 中定义了例如 `INTERNALIZED_STRING_TYPE`, `EXTERNAL_STRING_TYPE` 等，并且 `INTERNALIZED_STRING_TYPE` 的数值小于 `EXTERNAL_STRING_TYPE` 的数值。
    * **预期输出:**  断言 `static_cast<int>(InstanceType::INTERNALIZED_STRING_TYPE) < static_cast<int>(InstanceType::EXTERNAL_STRING_TYPE)` 为真。

**3. 结构体列表顺序 (Struct List Order):**

* **功能:** 验证 `STRUCT_LIST_GENERATOR` 宏定义中结构体类型的定义顺序是否正确。
* **代码逻辑推理:** 类似于 Instance 类型列表顺序的测试，但针对的是结构体类型。
* **假设输入与输出:** 类似 Instance 类型列表顺序的假设和输出，只是针对不同的类型列表。

**4. 字典增长 (Dictionary Growth):**

* **功能:** 测试 `NumberDictionary` (V8 内部用于存储数字索引属性的哈希表) 的增长行为。它验证了当添加元素超过当前容量时，字典如何重新分配内存。
* **代码逻辑推理:**  测试用例逐步向 `NumberDictionary` 添加元素，并断言在添加特定数量的元素后，字典的容量会增加到预期的值（通常是 2 的幂次方）。
* **假设输入与输出:**
    * **假设输入:**  创建一个初始容量为 1 的 `NumberDictionary`，并依次添加数字键值对。
    * **预期输出:**  添加 4 个元素后，容量变为 8；添加 6 个元素后，容量变为 16，以此类推。

**5. 空函数作用域信息 (Empty Function Scope Info):**

* **功能:**  验证 V8 中空函数 (例如 `(function(){})`) 的作用域信息 (`ScopeInfo`) 是否已正确设置，并与预定义的空函数的作用域信息一致。
* **代码逻辑推理:**  获取一个空函数和一个预定义的空函数的 `ScopeInfo`，并比较它们的标志、参数数量和上下文局部变量数量是否相等。
* **与 Javascript 的关系:** 这与 JavaScript 中函数的作用域和闭包的概念相关。即使是一个空函数，V8 也需要为其维护必要的作用域信息。
* **Javascript 示例:**
  ```javascript
  function emptyFunction() {}
  // V8 内部会为 emptyFunction 创建 ScopeInfo
  ```

**6. 无副作用的字符串转换 (NoSideEffectsToString):**

* **功能:**  测试 `Object::NoSideEffectsToString` 函数，该函数用于获取对象的字符串表示，但保证不会触发对象的副作用（例如调用 `toString` 方法）。
* **代码逻辑推理:**  针对各种不同的 V8 对象类型（数字、字符串、布尔值、`undefined`、`null`、错误对象、Symbol、普通对象等）调用 `Object::NoSideEffectsToString`，并断言返回的字符串与预期一致。
* **与 Javascript 的关系:**  这与 JavaScript 中将各种类型转换为字符串的操作相关，但 V8 内部需要一种安全的方式来获取字符串表示，而不会意外执行用户代码。
* **Javascript 示例:**
  ```javascript
  const num = 42.3;
  const str = "fisk hest";
  const obj = {};
  const err = new Error("some error");

  // Object::NoSideEffectsToString 类似于在不调用对象的 toString 方法的情况下获取字符串
  // 例如，对于普通对象，可能会返回 "#<Object>"
  ```

**7. 枚举缓存 (EnumCache):**

* **功能:**  测试 V8 中用于优化对象属性枚举的 `EnumCache` 的行为。它验证了 `EnumCache` 的创建、共享和更新机制。
* **代码逻辑推理:**  创建具有不同属性的对象，形成一个原型链或转换树。然后，通过执行 `for...in` 循环来触发 `EnumCache` 的创建和使用，并断言 `EnumCache` 的状态（例如长度、键和索引）以及在不同对象之间的共享情况是否符合预期。
* **与 Javascript 的关系:**  直接关联到 JavaScript 中的 `for...in` 循环，它用于枚举对象的可枚举属性。`EnumCache` 的目的是提高 `for...in` 循环的性能。
* **Javascript 示例:**
  ```javascript
  const obj1 = { a: 1 };
  const obj2 = { a: 1, b: 2 };
  const obj3 = { a: 1, b: 2, c: 3 };

  for (let key in obj2) {
    console.log(key, obj2[key]);
  }
  // V8 可能会利用 EnumCache 来加速这个循环
  ```

**8. 截断负零的对象方法 (ObjectMethodsThatTruncateMinusZero):**

* **功能:**  测试 `Object::ToInteger`, `Object::ToLength`, 和 `Object::ToIndex` 等方法在处理 `-0` 时的行为。这些方法应该将 `-0` 截断为 `+0`。
* **代码逻辑推理:**  创建一个表示 `-0` 的 `Number` 对象，然后将其传递给上述方法，并断言返回的结果是 `+0`。
* **与 Javascript 的关系:**  与 JavaScript 中数字类型的转换和处理有关。在某些情况下，需要将值转换为整数或长度，并且需要正确处理 `-0`。
* **Javascript 示例:**
  ```javascript
  const minusZero = -0;
  console.log(parseInt(minusZero)); // 输出 0
  console.log(Math.floor(minusZero)); // 输出 -0 (JavaScript 的 Math.floor 不截断)
  // V8 内部的 Object::ToInteger 应该类似于将 -0 转换为 0
  ```

**9. FunctionKind 相关测试:**

* **功能:**  测试各种辅助函数，用于判断 `FunctionKind` 枚举值的类型，例如是否是箭头函数、异步函数、生成器函数、构造函数等。
* **代码逻辑推理:**  遍历所有可能的 `FunctionKind` 枚举值，并断言相应的判断函数返回的值与预期一致。
* **与 Javascript 的关系:**  `FunctionKind` 用于区分不同类型的 JavaScript 函数，这对于 V8 的编译、优化和执行至关重要。
* **Javascript 示例:**
  ```javascript
  const arrowFunc = () => {};
  async function asyncFunc() {}
  function* generatorFunc() {}
  class MyClass {}
  const method = MyClass.prototype.myMethod = function() {};

  // V8 内部会为这些不同的函数赋予不同的 FunctionKind
  ```

**10. 构造函数实例类型 (ConstructorInstanceTypes):**

* **功能:**  验证内置的 JavaScript 构造函数（例如 `Array`, `RegExp`, `Promise`）是否具有预期的 `InstanceType`。
* **代码逻辑推理:**  获取内置构造函数，检查它们的 map 属性中的 `instance_type` 是否与预定义的类型一致。
* **与 Javascript 的关系:**  这与 JavaScript 的对象创建和内置类型有关。每个内置构造函数创建的对象都应该具有特定的内部类型。
* **Javascript 示例:**
  ```javascript
  const arr = new Array();
  const regex = new RegExp('');
  const promise = new Promise(() => {});

  // V8 内部会为 arr, regex, promise 等对象赋予不同的 InstanceType
  ```

**11. 添加数据属性名称冲突 (AddDataPropertyNameCollision 和 AddDataPropertyNameCollisionDeprecatedMap):**

* **功能:**  测试在尝试向对象添加已存在的同名数据属性时，V8 的行为。特别是当对象的 map 被标记为 deprecated 时的情况。
* **代码逻辑推理:**  尝试使用 `Object::AddDataProperty` 向对象添加已存在的属性，并期望抛出异常（使用 `EXPECT_DEATH_IF_SUPPORTED` 宏）。`AddDataPropertyNameCollisionDeprecatedMap` 测试了在 map 被 deprecated 后的类似场景。
* **与 Javascript 的关系:**  与 JavaScript 中对象属性的添加和修改规则有关。在严格模式下，尝试定义已存在的属性会抛出错误。
* **Javascript 示例:**
  ```javascript
  const obj = { key: 0 };
  // 尝试再次定义 key 属性，在某些情况下会出错
  Object.defineProperty(obj, 'key', { value: 'corrupt' }); // 在严格模式下会抛出 TypeError
  ```

**如果 `v8/test/unittests/objects/object-unittest.cc` 以 `.tq` 结尾:**

那么它将是一个 **V8 Torque 源代码文件**。Torque 是 V8 使用的一种领域特定语言，用于生成高效的 C++ 代码，特别是用于实现内置函数和运行时函数。如果文件是 `.tq`，其功能仍然是定义针对 `Object` 相关的单元测试，但测试的编写方式和目标可能更侧重于 Torque 代码的正确性，而不是直接测试 C++ 接口。

**用户常见的编程错误:**

该文件中的测试用例间接涉及了一些用户常见的编程错误，例如：

* **意外的类型转换:**  `ObjectMethodsThatTruncateMinusZero` 测试了 `-0` 的处理，用户可能没有意识到 JavaScript 中 `-0` 的存在及其特殊性。
* **对对象属性枚举的误解:** `EnumCache` 测试与 `for...in` 循环有关，用户可能不清楚 `for...in` 遍历的属性范围以及 V8 的优化机制。
* **属性覆盖和冲突:** `AddDataPropertyNameCollision` 测试了属性冲突的情况，用户在动态添加属性时可能会遇到意外的覆盖或错误。
* **对 JavaScript 函数类型的理解不足:** `FunctionKind` 测试涵盖了多种 JavaScript 函数类型，用户可能不清楚不同类型函数的特性和限制。

总而言之，`v8/test/unittests/objects/object-unittest.cc` 是一个至关重要的文件，用于确保 V8 引擎中 `Object` 相关的核心功能按照预期工作，并且能够处理各种边界情况和潜在的编程错误。它通过大量的单元测试覆盖了 `Object` 及其相关概念的各个方面。

### 提示词
```
这是目录为v8/test/unittests/objects/object-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/objects/object-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cmath>
#include <iostream>
#include <limits>

#include "src/api/api-inl.h"
#include "src/codegen/compiler.h"
#include "src/objects/hash-table-inl.h"
#include "src/objects/objects-inl.h"
#include "src/objects/objects.h"
#include "src/objects/string-set.h"
#include "test/unittests/test-utils.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace v8 {
namespace internal {

namespace {

bool IsInStringInstanceTypeList(InstanceType instance_type) {
  switch (instance_type) {
#define ASSERT_INSTANCE_TYPE(type, ...) \
  static_assert(InstanceType::type < InstanceType::FIRST_NONSTRING_TYPE);
    STRING_TYPE_LIST(ASSERT_INSTANCE_TYPE)
#undef ASSERT_INSTANCE_TYPE
#define TEST_INSTANCE_TYPE(type, ...) case InstanceType::type:
    STRING_TYPE_LIST(TEST_INSTANCE_TYPE)
#undef TEST_INSTANCE_TYPE
    return true;
    default:
      EXPECT_LE(InstanceType::FIRST_NONSTRING_TYPE, instance_type);
      return false;
  }
}

void CheckOneInstanceType(InstanceType instance_type) {
  if (IsInStringInstanceTypeList(instance_type)) {
    EXPECT_TRUE((instance_type & kIsNotStringMask) == kStringTag)
        << "Failing IsString mask check for " << instance_type;
  } else {
    EXPECT_FALSE((instance_type & kIsNotStringMask) == kStringTag)
        << "Failing !IsString mask check for " << instance_type;
  }
}

}  // namespace

TEST(Object, InstanceTypeList) {
#define TEST_INSTANCE_TYPE(type) CheckOneInstanceType(InstanceType::type);

  INSTANCE_TYPE_LIST(TEST_INSTANCE_TYPE)
#undef TEST_INSTANCE_TYPE
}

TEST(Object, InstanceTypeListOrder) {
  int current = 0;
  int prev = -1;
  InstanceType current_type = static_cast<InstanceType>(current);
  EXPECT_EQ(current_type, InstanceType::FIRST_TYPE);
  EXPECT_EQ(current_type, InstanceType::INTERNALIZED_TWO_BYTE_STRING_TYPE);
#define TEST_INSTANCE_TYPE(type)                                           \
  current_type = InstanceType::type;                                       \
  current = static_cast<int>(current_type);                                \
  if (current > static_cast<int>(LAST_NAME_TYPE)) {                        \
    EXPECT_LE(prev + 1, current);                                          \
  }                                                                        \
  EXPECT_LT(prev, current) << " INSTANCE_TYPE_LIST is not ordered: "       \
                           << "last = " << static_cast<InstanceType>(prev) \
                           << " vs. current = " << current_type;           \
  prev = current;

  // Only test hand-written portion of instance type list. The generated portion
  // doesn't run the same risk of getting out of order, and it does emit type
  // names out of numerical order in one case: JS_OBJECT_TYPE is emitted before
  // its subclass types, because types are emitted in depth-first pre-order
  // traversal order, and some of its subclass types are numerically earlier.
  INSTANCE_TYPE_LIST_BASE(TEST_INSTANCE_TYPE)
#undef TEST_INSTANCE_TYPE
}

TEST(Object, StructListOrder) {
  int current = static_cast<int>(InstanceType::FIRST_STRUCT_TYPE);
  int prev = current - 1;
  ASSERT_LT(0, prev);
  InstanceType current_type = static_cast<InstanceType>(current);
#define TEST_STRUCT(TYPE, class, name)                 \
  current_type = InstanceType::TYPE;                   \
  current = static_cast<int>(current_type);            \
  EXPECT_LE(prev + 1, current)                         \
      << " STRUCT_LIST is not ordered: "               \
      << " last = " << static_cast<InstanceType>(prev) \
      << " vs. current = " << current_type;            \
  prev = current;

  STRUCT_LIST_GENERATOR(STRUCT_LIST_ADAPTER, TEST_STRUCT)
#undef TEST_STRUCT
}

using ObjectWithIsolate = TestWithIsolate;

TEST_F(ObjectWithIsolate, DictionaryGrowth) {
  Handle<NumberDictionary> dict = NumberDictionary::New(isolate(), 1);
  DirectHandle<Object> value = isolate()->factory()->null_value();
  PropertyDetails details = PropertyDetails::Empty();

  // This test documents the expected growth behavior of a dictionary getting
  // elements added to it one by one.
  static_assert(HashTableBase::kMinCapacity == 4);
  uint32_t i = 1;
  // 3 elements fit into the initial capacity.
  for (; i <= 3; i++) {
    dict = NumberDictionary::Add(isolate(), dict, i, value, details);
    CHECK_EQ(4, dict->Capacity());
  }
  // 4th element triggers growth.
  DCHECK_EQ(4, i);
  for (; i <= 5; i++) {
    dict = NumberDictionary::Add(isolate(), dict, i, value, details);
    CHECK_EQ(8, dict->Capacity());
  }
  // 6th element triggers growth.
  DCHECK_EQ(6, i);
  for (; i <= 11; i++) {
    dict = NumberDictionary::Add(isolate(), dict, i, value, details);
    CHECK_EQ(16, dict->Capacity());
  }
  // 12th element triggers growth.
  DCHECK_EQ(12, i);
  for (; i <= 21; i++) {
    dict = NumberDictionary::Add(isolate(), dict, i, value, details);
    CHECK_EQ(32, dict->Capacity());
  }
  // 22nd element triggers growth.
  DCHECK_EQ(22, i);
  for (; i <= 43; i++) {
    dict = NumberDictionary::Add(isolate(), dict, i, value, details);
    CHECK_EQ(64, dict->Capacity());
  }
  // 44th element triggers growth.
  DCHECK_EQ(44, i);
  for (; i <= 50; i++) {
    dict = NumberDictionary::Add(isolate(), dict, i, value, details);
    CHECK_EQ(128, dict->Capacity());
  }

  // If we grow by larger chunks, the next (sufficiently big) power of 2 is
  // chosen as the capacity.
  dict = NumberDictionary::New(isolate(), 1);
  dict = NumberDictionary::EnsureCapacity(isolate(), dict, 65);
  CHECK_EQ(128, dict->Capacity());

  dict = NumberDictionary::New(isolate(), 1);
  dict = NumberDictionary::EnsureCapacity(isolate(), dict, 30);
  CHECK_EQ(64, dict->Capacity());
}

TEST_F(TestWithNativeContext, EmptyFunctionScopeInfo) {
  // Check that the empty_function has a properly set up ScopeInfo.
  DirectHandle<JSFunction> function = RunJS<JSFunction>("(function(){})");

  DirectHandle<ScopeInfo> scope_info(function->shared()->scope_info(),
                                     function->GetIsolate());
  DirectHandle<ScopeInfo> empty_function_scope_info(
      isolate()->empty_function()->shared()->scope_info(),
      function->GetIsolate());

  EXPECT_EQ(scope_info->Flags(), empty_function_scope_info->Flags());
  EXPECT_EQ(scope_info->ParameterCount(),
            empty_function_scope_info->ParameterCount());
  EXPECT_EQ(scope_info->ContextLocalCount(),
            empty_function_scope_info->ContextLocalCount());
}

using ObjectTest = TestWithContext;

static void CheckObject(Isolate* isolate, DirectHandle<Object> obj,
                        const char* string) {
  DirectHandle<String> print_string = String::Flatten(
      isolate,
      indirect_handle(Object::NoSideEffectsToString(isolate, obj), isolate));
  CHECK(print_string->IsOneByteEqualTo(base::CStrVector(string)));
}

static void CheckSmi(Isolate* isolate, int value, const char* string) {
  DirectHandle<Object> handle(Smi::FromInt(value), isolate);
  CheckObject(isolate, handle, string);
}

static void CheckString(Isolate* isolate, const char* value,
                        const char* string) {
  DirectHandle<String> handle(
      isolate->factory()->NewStringFromAsciiChecked(value));
  CheckObject(isolate, handle, string);
}

static void CheckNumber(Isolate* isolate, double value, const char* string) {
  DirectHandle<Object> number = isolate->factory()->NewNumber(value);
  CHECK(IsNumber(*number));
  CheckObject(isolate, number, string);
}

static void CheckBoolean(Isolate* isolate, bool value, const char* string) {
  CheckObject(isolate, isolate->factory()->ToBoolean(value), string);
}

TEST_F(ObjectTest, NoSideEffectsToString) {
  Factory* factory = i_isolate()->factory();

  HandleScope scope(i_isolate());

  CheckString(i_isolate(), "fisk hest", "fisk hest");
  CheckNumber(i_isolate(), 42.3, "42.3");
  CheckSmi(i_isolate(), 42, "42");
  CheckBoolean(i_isolate(), true, "true");
  CheckBoolean(i_isolate(), false, "false");
  CheckBoolean(i_isolate(), false, "false");
  Handle<Object> smi_42 = handle(Smi::FromInt(42), i_isolate());
  CheckObject(i_isolate(),
              BigInt::FromNumber(i_isolate(), smi_42).ToHandleChecked(), "42");
  CheckObject(i_isolate(), factory->undefined_value(), "undefined");
  CheckObject(i_isolate(), factory->null_value(), "null");

  CheckObject(i_isolate(), factory->error_to_string(), "[object Error]");
  CheckObject(i_isolate(), factory->unscopables_symbol(),
              "Symbol(Symbol.unscopables)");
  CheckObject(
      i_isolate(),
      factory->NewError(i_isolate()->error_function(), factory->empty_string()),
      "Error");
  CheckObject(
      i_isolate(),
      factory->NewError(i_isolate()->error_function(),
                        factory->NewStringFromAsciiChecked("fisk hest")),
      "Error: fisk hest");
  CheckObject(i_isolate(), factory->NewJSObject(i_isolate()->object_function()),
              "#<Object>");
  CheckObject(
      i_isolate(),
      factory->NewJSProxy(factory->NewJSObject(i_isolate()->object_function()),
                          factory->NewJSObject(i_isolate()->object_function())),
      "#<Object>");
}

TEST_F(ObjectTest, EnumCache) {
  i::Factory* factory = i_isolate()->factory();
  v8::HandleScope scope(isolate());

  // Create a nice transition tree:
  // (a) --> (b) --> (c)   shared DescriptorArray 1
  //          |
  //          +---> (cc)   shared DescriptorArray 2
  RunJS(
      "function O(a) { this.a = 1 };"

      "a = new O();"

      "b = new O();"
      "b.b = 2;"

      "c = new O();"
      "c.b = 2;"
      "c.c = 3;"

      "cc = new O();"
      "cc.b = 2;"
      "cc.cc = 4;");

  DirectHandle<JSObject> a = Cast<JSObject>(v8::Utils::OpenDirectHandle(
      *context()->Global()->Get(context(), NewString("a")).ToLocalChecked()));
  DirectHandle<JSObject> b = Cast<JSObject>(v8::Utils::OpenDirectHandle(
      *context()->Global()->Get(context(), NewString("b")).ToLocalChecked()));
  DirectHandle<JSObject> c = Cast<JSObject>(v8::Utils::OpenDirectHandle(
      *context()->Global()->Get(context(), NewString("c")).ToLocalChecked()));
  DirectHandle<JSObject> cc = Cast<JSObject>(v8::Utils::OpenDirectHandle(
      *context()->Global()->Get(context(), NewString("cc")).ToLocalChecked()));

  // Check the transition tree.
  CHECK_EQ(a->map()->instance_descriptors(), b->map()->instance_descriptors());
  CHECK_EQ(b->map()->instance_descriptors(), c->map()->instance_descriptors());
  CHECK_NE(c->map()->instance_descriptors(), cc->map()->instance_descriptors());
  CHECK_NE(b->map()->instance_descriptors(), cc->map()->instance_descriptors());

  // Check that the EnumLength is unset.
  CHECK_EQ(a->map()->EnumLength(), kInvalidEnumCacheSentinel);
  CHECK_EQ(b->map()->EnumLength(), kInvalidEnumCacheSentinel);
  CHECK_EQ(c->map()->EnumLength(), kInvalidEnumCacheSentinel);
  CHECK_EQ(cc->map()->EnumLength(), kInvalidEnumCacheSentinel);

  // Check that the EnumCache is empty.
  CHECK_EQ(a->map()->instance_descriptors()->enum_cache(),
           *factory->empty_enum_cache());
  CHECK_EQ(b->map()->instance_descriptors()->enum_cache(),
           *factory->empty_enum_cache());
  CHECK_EQ(c->map()->instance_descriptors()->enum_cache(),
           *factory->empty_enum_cache());
  CHECK_EQ(cc->map()->instance_descriptors()->enum_cache(),
           *factory->empty_enum_cache());

  // The EnumCache is shared on the DescriptorArray, creating it on {cc} has no
  // effect on the other maps.
  RunJS("var s = 0; for (let key in cc) { s += cc[key] };");
  {
    CHECK_EQ(a->map()->EnumLength(), kInvalidEnumCacheSentinel);
    CHECK_EQ(b->map()->EnumLength(), kInvalidEnumCacheSentinel);
    CHECK_EQ(c->map()->EnumLength(), kInvalidEnumCacheSentinel);
    CHECK_EQ(cc->map()->EnumLength(), 3);

    CHECK_EQ(a->map()->instance_descriptors()->enum_cache(),
             *factory->empty_enum_cache());
    CHECK_EQ(b->map()->instance_descriptors()->enum_cache(),
             *factory->empty_enum_cache());
    CHECK_EQ(c->map()->instance_descriptors()->enum_cache(),
             *factory->empty_enum_cache());

    Tagged<EnumCache> enum_cache =
        cc->map()->instance_descriptors()->enum_cache();
    CHECK_NE(enum_cache, *factory->empty_enum_cache());
    CHECK_EQ(enum_cache->keys()->length(), 3);
    CHECK_EQ(enum_cache->indices()->length(), 3);
  }

  // Initializing the EnumCache for the the topmost map {a} will not create the
  // cache for the other maps.
  RunJS("var s = 0; for (let key in a) { s += a[key] };");
  {
    CHECK_EQ(a->map()->EnumLength(), 1);
    CHECK_EQ(b->map()->EnumLength(), kInvalidEnumCacheSentinel);
    CHECK_EQ(c->map()->EnumLength(), kInvalidEnumCacheSentinel);
    CHECK_EQ(cc->map()->EnumLength(), 3);

    // The enum cache is shared on the descriptor array of maps {a}, {b} and
    // {c} only.
    Tagged<EnumCache> enum_cache =
        a->map()->instance_descriptors()->enum_cache();
    CHECK_NE(enum_cache, *factory->empty_enum_cache());
    CHECK_NE(cc->map()->instance_descriptors()->enum_cache(),
             *factory->empty_enum_cache());
    CHECK_NE(cc->map()->instance_descriptors()->enum_cache(), enum_cache);
    CHECK_EQ(a->map()->instance_descriptors()->enum_cache(), enum_cache);
    CHECK_EQ(b->map()->instance_descriptors()->enum_cache(), enum_cache);
    CHECK_EQ(c->map()->instance_descriptors()->enum_cache(), enum_cache);

    CHECK_EQ(enum_cache->keys()->length(), 1);
    CHECK_EQ(enum_cache->indices()->length(), 1);
  }

  // Creating the EnumCache for {c} will create a new EnumCache on the shared
  // DescriptorArray.
  DirectHandle<EnumCache> previous_enum_cache(
      a->map()->instance_descriptors()->enum_cache(), a->GetIsolate());
  DirectHandle<FixedArray> previous_keys(previous_enum_cache->keys(),
                                         a->GetIsolate());
  DirectHandle<FixedArray> previous_indices(previous_enum_cache->indices(),
                                            a->GetIsolate());
  RunJS("var s = 0; for (let key in c) { s += c[key] };");
  {
    CHECK_EQ(a->map()->EnumLength(), 1);
    CHECK_EQ(b->map()->EnumLength(), kInvalidEnumCacheSentinel);
    CHECK_EQ(c->map()->EnumLength(), 3);
    CHECK_EQ(cc->map()->EnumLength(), 3);

    Tagged<EnumCache> enum_cache =
        c->map()->instance_descriptors()->enum_cache();
    CHECK_NE(enum_cache, *factory->empty_enum_cache());
    // The keys and indices caches are updated.
    CHECK_EQ(enum_cache, *previous_enum_cache);
    CHECK_NE(enum_cache->keys(), *previous_keys);
    CHECK_NE(enum_cache->indices(), *previous_indices);
    CHECK_EQ(previous_keys->length(), 1);
    CHECK_EQ(previous_indices->length(), 1);
    CHECK_EQ(enum_cache->keys()->length(), 3);
    CHECK_EQ(enum_cache->indices()->length(), 3);

    // The enum cache is shared on the descriptor array of maps {a}, {b} and
    // {c} only.
    CHECK_NE(cc->map()->instance_descriptors()->enum_cache(),
             *factory->empty_enum_cache());
    CHECK_NE(cc->map()->instance_descriptors()->enum_cache(), enum_cache);
    CHECK_NE(cc->map()->instance_descriptors()->enum_cache(),
             *previous_enum_cache);
    CHECK_EQ(a->map()->instance_descriptors()->enum_cache(), enum_cache);
    CHECK_EQ(b->map()->instance_descriptors()->enum_cache(), enum_cache);
    CHECK_EQ(c->map()->instance_descriptors()->enum_cache(), enum_cache);
  }

  // {b} can reuse the existing EnumCache, hence we only need to set the correct
  // EnumLength on the map without modifying the cache itself.
  previous_enum_cache =
      handle(a->map()->instance_descriptors()->enum_cache(), a->GetIsolate());
  previous_keys = handle(previous_enum_cache->keys(), a->GetIsolate());
  previous_indices = handle(previous_enum_cache->indices(), a->GetIsolate());
  RunJS("var s = 0; for (let key in b) { s += b[key] };");
  {
    CHECK_EQ(a->map()->EnumLength(), 1);
    CHECK_EQ(b->map()->EnumLength(), 2);
    CHECK_EQ(c->map()->EnumLength(), 3);
    CHECK_EQ(cc->map()->EnumLength(), 3);

    Tagged<EnumCache> enum_cache =
        c->map()->instance_descriptors()->enum_cache();
    CHECK_NE(enum_cache, *factory->empty_enum_cache());
    // The keys and indices caches are not updated.
    CHECK_EQ(enum_cache, *previous_enum_cache);
    CHECK_EQ(enum_cache->keys(), *previous_keys);
    CHECK_EQ(enum_cache->indices(), *previous_indices);
    CHECK_EQ(enum_cache->keys()->length(), 3);
    CHECK_EQ(enum_cache->indices()->length(), 3);

    // The enum cache is shared on the descriptor array of maps {a}, {b} and
    // {c} only.
    CHECK_NE(cc->map()->instance_descriptors()->enum_cache(),
             *factory->empty_enum_cache());
    CHECK_NE(cc->map()->instance_descriptors()->enum_cache(), enum_cache);
    CHECK_NE(cc->map()->instance_descriptors()->enum_cache(),
             *previous_enum_cache);
    CHECK_EQ(a->map()->instance_descriptors()->enum_cache(), enum_cache);
    CHECK_EQ(b->map()->instance_descriptors()->enum_cache(), enum_cache);
    CHECK_EQ(c->map()->instance_descriptors()->enum_cache(), enum_cache);
  }
}

TEST_F(ObjectTest, ObjectMethodsThatTruncateMinusZero) {
  Factory* factory = i_isolate()->factory();

  Handle<Object> minus_zero = factory->NewNumber(-1.0 * 0.0);
  CHECK(IsMinusZero(*minus_zero));

  DirectHandle<Object> result =
      Object::ToInteger(i_isolate(), minus_zero).ToHandleChecked();
  CHECK(IsZero(*result));

  result = Object::ToLength(i_isolate(), minus_zero).ToHandleChecked();
  CHECK(IsZero(*result));

  // Choose an error message template, doesn't matter which.
  result = Object::ToIndex(i_isolate(), minus_zero,
                           MessageTemplate::kInvalidAtomicAccessIndex)
               .ToHandleChecked();
  CHECK(IsZero(*result));
}

#define TEST_FUNCTION_KIND(Name)                                            \
  TEST_F(ObjectTest, Name) {                                                \
    for (uint32_t i = 0;                                                    \
         i < static_cast<uint32_t>(FunctionKind::kLastFunctionKind); i++) { \
      FunctionKind kind = static_cast<FunctionKind>(i);                     \
      CHECK_EQ(FunctionKind##Name(kind), Name(kind));                       \
    }                                                                       \
  }

bool FunctionKindIsArrowFunction(FunctionKind kind) {
  switch (kind) {
    case FunctionKind::kArrowFunction:
    case FunctionKind::kAsyncArrowFunction:
      return true;
    default:
      return false;
  }
}
TEST_FUNCTION_KIND(IsArrowFunction)

bool FunctionKindIsAsyncGeneratorFunction(FunctionKind kind) {
  switch (kind) {
    case FunctionKind::kAsyncConciseGeneratorMethod:
    case FunctionKind::kStaticAsyncConciseGeneratorMethod:
    case FunctionKind::kAsyncGeneratorFunction:
      return true;
    default:
      return false;
  }
}
TEST_FUNCTION_KIND(IsAsyncGeneratorFunction)

bool FunctionKindIsGeneratorFunction(FunctionKind kind) {
  switch (kind) {
    case FunctionKind::kConciseGeneratorMethod:
    case FunctionKind::kStaticConciseGeneratorMethod:
    case FunctionKind::kAsyncConciseGeneratorMethod:
    case FunctionKind::kStaticAsyncConciseGeneratorMethod:
    case FunctionKind::kGeneratorFunction:
    case FunctionKind::kAsyncGeneratorFunction:
      return true;
    default:
      return false;
  }
}
TEST_FUNCTION_KIND(IsGeneratorFunction)

bool FunctionKindIsAsyncFunction(FunctionKind kind) {
  switch (kind) {
    case FunctionKind::kAsyncFunction:
    case FunctionKind::kAsyncArrowFunction:
    case FunctionKind::kAsyncConciseMethod:
    case FunctionKind::kStaticAsyncConciseMethod:
    case FunctionKind::kAsyncConciseGeneratorMethod:
    case FunctionKind::kStaticAsyncConciseGeneratorMethod:
    case FunctionKind::kAsyncGeneratorFunction:
      return true;
    default:
      return false;
  }
}
TEST_FUNCTION_KIND(IsAsyncFunction)

bool FunctionKindIsConciseMethod(FunctionKind kind) {
  switch (kind) {
    case FunctionKind::kConciseMethod:
    case FunctionKind::kStaticConciseMethod:
    case FunctionKind::kConciseGeneratorMethod:
    case FunctionKind::kStaticConciseGeneratorMethod:
    case FunctionKind::kAsyncConciseMethod:
    case FunctionKind::kStaticAsyncConciseMethod:
    case FunctionKind::kAsyncConciseGeneratorMethod:
    case FunctionKind::kStaticAsyncConciseGeneratorMethod:
    case FunctionKind::kClassMembersInitializerFunction:
      return true;
    default:
      return false;
  }
}
TEST_FUNCTION_KIND(IsConciseMethod)

bool FunctionKindIsAccessorFunction(FunctionKind kind) {
  switch (kind) {
    case FunctionKind::kGetterFunction:
    case FunctionKind::kStaticGetterFunction:
    case FunctionKind::kSetterFunction:
    case FunctionKind::kStaticSetterFunction:
      return true;
    default:
      return false;
  }
}
TEST_FUNCTION_KIND(IsAccessorFunction)

bool FunctionKindIsDefaultConstructor(FunctionKind kind) {
  switch (kind) {
    case FunctionKind::kDefaultBaseConstructor:
    case FunctionKind::kDefaultDerivedConstructor:
      return true;
    default:
      return false;
  }
}
TEST_FUNCTION_KIND(IsDefaultConstructor)

bool FunctionKindIsBaseConstructor(FunctionKind kind) {
  switch (kind) {
    case FunctionKind::kBaseConstructor:
    case FunctionKind::kDefaultBaseConstructor:
      return true;
    default:
      return false;
  }
}
TEST_FUNCTION_KIND(IsBaseConstructor)

bool FunctionKindIsDerivedConstructor(FunctionKind kind) {
  switch (kind) {
    case FunctionKind::kDefaultDerivedConstructor:
    case FunctionKind::kDerivedConstructor:
      return true;
    default:
      return false;
  }
}
TEST_FUNCTION_KIND(IsDerivedConstructor)

bool FunctionKindIsClassConstructor(FunctionKind kind) {
  switch (kind) {
    case FunctionKind::kBaseConstructor:
    case FunctionKind::kDefaultBaseConstructor:
    case FunctionKind::kDefaultDerivedConstructor:
    case FunctionKind::kDerivedConstructor:
      return true;
    default:
      return false;
  }
}
TEST_FUNCTION_KIND(IsClassConstructor)

bool FunctionKindIsConstructable(FunctionKind kind) {
  switch (kind) {
    case FunctionKind::kGetterFunction:
    case FunctionKind::kStaticGetterFunction:
    case FunctionKind::kSetterFunction:
    case FunctionKind::kStaticSetterFunction:
    case FunctionKind::kArrowFunction:
    case FunctionKind::kAsyncArrowFunction:
    case FunctionKind::kAsyncFunction:
    case FunctionKind::kAsyncConciseMethod:
    case FunctionKind::kStaticAsyncConciseMethod:
    case FunctionKind::kAsyncConciseGeneratorMethod:
    case FunctionKind::kStaticAsyncConciseGeneratorMethod:
    case FunctionKind::kAsyncGeneratorFunction:
    case FunctionKind::kGeneratorFunction:
    case FunctionKind::kConciseGeneratorMethod:
    case FunctionKind::kStaticConciseGeneratorMethod:
    case FunctionKind::kConciseMethod:
    case FunctionKind::kStaticConciseMethod:
    case FunctionKind::kClassMembersInitializerFunction:
      return false;
    default:
      return true;
  }
}
TEST_FUNCTION_KIND(IsConstructable)

bool FunctionKindIsStrictFunctionWithoutPrototype(FunctionKind kind) {
  return IsArrowFunction(kind) || IsConciseMethod(kind) ||
         IsAccessorFunction(kind);
}
TEST_FUNCTION_KIND(IsStrictFunctionWithoutPrototype)

#undef TEST_FUNCTION_KIND

TEST_F(ObjectTest, ConstructorInstanceTypes) {
  bool flag_was_enabled = i::v8_flags.js_float16array;
  i::v8_flags.js_float16array = true;
  v8::HandleScope scope(isolate());

  DirectHandle<NativeContext> context = i_isolate()->native_context();

  DisallowGarbageCollection no_gc;
  for (int i = 0; i < Context::NATIVE_CONTEXT_SLOTS; i++) {
    Tagged<Object> value = context->get(i);
    if (!IsJSFunction(value)) continue;
    InstanceType instance_type =
        Cast<JSFunction>(value)->map()->instance_type();

    switch (i) {
      case Context::ARRAY_FUNCTION_INDEX:
        CHECK_EQ(instance_type, JS_ARRAY_CONSTRUCTOR_TYPE);
        break;
      case Context::REGEXP_FUNCTION_INDEX:
        CHECK_EQ(instance_type, JS_REG_EXP_CONSTRUCTOR_TYPE);
        break;
      case Context::PROMISE_FUNCTION_INDEX:
        CHECK_EQ(instance_type, JS_PROMISE_CONSTRUCTOR_TYPE);
        break;

#define TYPED_ARRAY_CASE(Type, type, TYPE, ctype)                 \
  case Context::TYPE##_ARRAY_FUN_INDEX:                           \
    CHECK_EQ(instance_type, TYPE##_TYPED_ARRAY_CONSTRUCTOR_TYPE); \
    break;
        TYPED_ARRAYS(TYPED_ARRAY_CASE)
#undef TYPED_ARRAY_CASE

      default:
        // All the other functions must have the default instance type.
        CHECK_EQ(instance_type, JS_FUNCTION_TYPE);
        break;
    }
  }
  i::v8_flags.js_float16array = flag_was_enabled;
}

TEST_F(ObjectTest, AddDataPropertyNameCollision) {
  v8::HandleScope scope(isolate());
  Factory* factory = i_isolate()->factory();

  Handle<JSObject> object =
      factory->NewJSObject(i_isolate()->object_function());

  Handle<String> key = factory->NewStringFromStaticChars("key_string");
  DirectHandle<Object> value1(Smi::FromInt(0), i_isolate());
  DirectHandle<Object> value2 = factory->NewStringFromAsciiChecked("corrupt");

  LookupIterator outer_it(i_isolate(), object, key, object,
                          LookupIterator::OWN_SKIP_INTERCEPTOR);
  {
    LookupIterator inner_it(i_isolate(), object, key, object,
                            LookupIterator::OWN_SKIP_INTERCEPTOR);

    CHECK(Object::AddDataProperty(&inner_it, value1, NONE,
                                  Just(ShouldThrow::kThrowOnError),
                                  StoreOrigin::kNamed)
              .IsJust());
  }
  EXPECT_DEATH_IF_SUPPORTED(
      Object::AddDataProperty(&outer_it, value2, NONE,
                              Just(ShouldThrow::kThrowOnError),
                              StoreOrigin::kNamed)
          .IsJust(),
      "");
}

TEST_F(ObjectTest, AddDataPropertyNameCollisionDeprecatedMap) {
  v8::HandleScope scope(isolate());
  Factory* factory = i_isolate()->factory();

  // Create two identical maps
  RunJS(
      "a = {'regular_prop':5};"
      "b = {'regular_prop':5};");

  Handle<JSObject> a = Cast<JSObject>(v8::Utils::OpenHandle(
      *context()->Global()->Get(context(), NewString("a")).ToLocalChecked()));
  DirectHandle<JSObject> b = Cast<JSObject>(v8::Utils::OpenHandle(
      *context()->Global()->Get(context(), NewString("b")).ToLocalChecked()));

  CHECK(a->map() == b->map());

  Handle<String> key = factory->NewStringFromStaticChars("corrupted_prop");
  DirectHandle<Object> value = factory->NewStringFromAsciiChecked("corrupt");
  LookupIterator it(i_isolate(), a, key, a,
                    LookupIterator::OWN_SKIP_INTERCEPTOR);

  // Transition `a`'s map to deprecated
  RunJS(
      "a.corrupted_prop = 1;"
      "b.regular_prop = 5.5;");

  CHECK(a->map()->is_deprecated());

  EXPECT_DEATH_IF_SUPPORTED(
      Object::AddDataProperty(&it, value, NONE,
                              Just(ShouldThrow::kThrowOnError),
                              StoreOrigin::kNamed)
          .IsJust(),
      "");
}

}  // namespace internal
}  // namespace v8
```