Response: My thinking process to analyze the C++ code and explain its functionality and relation to JavaScript involved these steps:

1. **Understand the Goal:** The request asks for a summary of the C++ file's functionality and to illustrate its connection to JavaScript with examples. This means I need to identify the core purpose of the code and how it relates to V8's JavaScript execution.

2. **Initial Scan for Keywords and Concepts:** I quickly scanned the code for familiar terms related to JavaScript and V8's internal workings. Keywords like "Object," "String," "Number," "Boolean," "Function," "Array," "Promise," "Map," "Scope," "Context," and "Symbol" immediately jumped out. The presence of "TEST" macros also indicated that this is a unit test file.

3. **Identify the Main Focus:** The file name "object-unittest.cc" strongly suggests the tests are focused on the `Object` class and related object system within V8. The included headers like `src/objects/objects-inl.h` and `src/objects/objects.h` confirm this.

4. **Analyze Individual Test Cases:** I started examining each `TEST` macro to understand what specific aspects of the object system are being tested.

    * **`InstanceTypeList` and `InstanceTypeListOrder`:**  These tests are clearly verifying the structure and order of the `InstanceType` enum, which is crucial for V8's internal representation and type checking of JavaScript objects. The `STRING_TYPE_LIST` and `INSTANCE_TYPE_LIST` macros are key here.

    * **`StructListOrder`:**  Similar to `InstanceTypeListOrder`, this focuses on the order of structures defined in the `STRUCT_LIST_GENERATOR`. These structures likely represent the internal layout of various V8 objects.

    * **`DictionaryGrowth`:**  This test specifically checks the dynamic resizing behavior of `NumberDictionary`, a hash table implementation used in V8 for storing object properties.

    * **`EmptyFunctionScopeInfo`:** This test verifies that the scope information for empty functions is correctly initialized, which is important for function execution and scope management in JavaScript.

    * **`NoSideEffectsToString`:** This tests the `NoSideEffectsToString` function, which is responsible for generating string representations of JavaScript values without triggering side effects. This is crucial for debugging and introspection.

    * **`EnumCache`:** This test delves into the implementation and sharing behavior of the enum cache, which optimizes property enumeration in JavaScript objects. The different scenarios of creating and sharing the cache based on the transition tree are particularly interesting.

    * **`ObjectMethodsThatTruncateMinusZero`:**  This tests how V8's internal conversion methods handle the `-0` value, ensuring it's correctly converted to `0` in certain contexts.

    * **`FunctionKind...` tests:** These tests exhaustively check the helper functions related to `FunctionKind`, an enum that categorizes different types of JavaScript functions.

    * **`ConstructorInstanceTypes`:** This test verifies that the correct `InstanceType` is assigned to the constructor functions of built-in JavaScript objects like `Array`, `RegExp`, and `Promise`.

    * **`AddDataPropertyNameCollision` and `AddDataPropertyNameCollisionDeprecatedMap`:** These tests focus on how V8 handles adding properties with the same name to objects, particularly when maps are involved and when a map is deprecated (meaning it's no longer optimized).

5. **Identify Connections to JavaScript:** As I analyzed the tests, I started connecting the underlying C++ functionality to corresponding JavaScript concepts.

    * **`InstanceType`:** Relates to JavaScript's dynamic typing and how V8 internally categorizes different kinds of objects.
    * **`NumberDictionary`:**  Directly underlies the implementation of JavaScript objects as hash maps.
    * **`ScopeInfo`:**  Essential for implementing JavaScript's lexical scoping rules.
    * **`NoSideEffectsToString`:** Corresponds to the `Object.prototype.toString()` method and implicit string conversions in JavaScript.
    * **`EnumCache`:**  Optimizes the behavior of `for...in` loops and `Object.keys()` in JavaScript.
    * **`ToInteger`, `ToLength`, `ToIndex`:**  Internal implementations of JavaScript's type coercion rules when converting values to numbers for specific purposes.
    * **`FunctionKind`:**  Reflects the different ways functions can be defined and behave in JavaScript (regular functions, arrow functions, async functions, generators, etc.).
    * **Constructor Instance Types:** Guarantees that built-in constructors have the correct internal type for efficient handling.
    * **Property Addition and Map Deprecation:**  Demonstrates V8's internal mechanisms for managing object properties and the consequences of map deprecation on property access and modification.

6. **Craft JavaScript Examples:**  For each key concept, I devised simple JavaScript code snippets that illustrate the corresponding behavior being tested in the C++ code. The goal was to make the connection clear and understandable to someone familiar with JavaScript.

7. **Structure the Explanation:**  I organized the explanation by first providing a general summary of the file's purpose. Then, I went through each category of tests, explaining the C++ functionality and providing the corresponding JavaScript examples. I also included an overall conclusion to summarize the key takeaways.

8. **Refine and Clarify:** I reviewed the explanation to ensure clarity, accuracy, and conciseness. I used precise language and avoided overly technical jargon where possible. I made sure the JavaScript examples were easy to understand and directly related to the C++ functionality.

By following this systematic approach, I could effectively dissect the C++ code, understand its purpose within the V8 engine, and bridge the gap between the internal implementation and the observable behavior of JavaScript.
这个C++源代码文件 `object-unittest.cc` 是 V8 JavaScript 引擎的一部分，它包含了针对 V8 中 **对象 (Object)** 相关功能的 **单元测试 (Unit Tests)**。

**主要功能归纳：**

这个文件旨在测试 V8 引擎中 `Object` 类的各种内部实现细节和行为，确保其正确性和稳定性。 具体来说，它测试了以下几个方面：

1. **实例类型 (Instance Types) 的管理:**
   - 验证 `InstanceType` 枚举的定义和顺序，确保所有定义的类型都被正确标记为字符串类型或非字符串类型。
   - 检查实例类型列表的顺序是否正确，这对于 V8 内部的对象处理至关重要。

2. **结构体列表 (Struct List) 的管理:**
   - 验证 V8 内部用于表示不同对象结构的结构体列表的顺序。

3. **字典 (Dictionary) 的增长策略:**
   - 测试 `NumberDictionary` (V8 中用于存储对象属性的哈希表) 在添加元素时的动态增长行为，验证其容量扩展逻辑是否符合预期。

4. **函数作用域信息 (Function Scope Info):**
   - 检查空函数的 `ScopeInfo` 是否已正确设置，这关系到 JavaScript 的作用域链和闭包的实现。

5. **`NoSideEffectsToString` 方法:**
   - 测试 `Object::NoSideEffectsToString` 方法，该方法用于在不触发任何副作用的情况下获取对象的字符串表示。这对于调试和错误报告非常重要。它测试了不同类型的 JavaScript 值（字符串、数字、布尔值、null、undefined、Error 对象、Symbol 对象、普通对象等）的输出。

6. **枚举缓存 (Enum Cache):**
   - 详细测试了 V8 中用于优化对象属性枚举的缓存机制。
   - 测试了在不同的对象和属性添加顺序下，枚举缓存的创建、共享和更新行为。
   - 验证了枚举缓存如何与对象的 Map (描述对象结构的信息) 关联。

7. **处理负零 (-0):**
   - 测试了 V8 中将负零转换为整数、长度和索引的几种方法，确保负零被正确地转换为正零。

8. **函数类型 (Function Kind) 的判断:**
   - 测试了各种用于判断函数类型的辅助函数（例如 `IsArrowFunction`、`IsAsyncFunction`、`IsGeneratorFunction` 等），确保这些函数能够正确识别不同类型的 JavaScript 函数。

9. **构造函数 (Constructor) 的实例类型:**
   - 验证内置构造函数（如 `Array`、`RegExp`、`Promise` 等）是否具有预期的实例类型。

10. **添加数据属性时的名称冲突:**
    - 测试了在尝试添加已存在的属性时，V8 的行为，特别是在 Map 被标记为 deprecated 的情况下，防止出现数据不一致的情况。

**与 JavaScript 功能的关系及 JavaScript 示例：**

这个 C++ 文件测试的是 V8 引擎的底层实现，这些实现直接支撑着 JavaScript 的各种对象特性和行为。 以下是一些功能的 JavaScript 示例：

1. **实例类型:**  JavaScript 自身没有直接暴露实例类型的概念，但 V8 内部使用它来区分不同类型的对象，例如数组、函数、普通对象等，这影响着对象的内存布局和操作效率。

2. **字典增长:**  当你向 JavaScript 对象动态添加属性时，V8 内部可能会使用 `NumberDictionary` 来存储这些属性。字典的增长策略直接影响了对象属性访问的性能。
   ```javascript
   const obj = {};
   for (let i = 0; i < 100; i++) {
     obj[i] = i * 2;
   }
   // V8 内部的 NumberDictionary 会根据添加的属性数量动态增长。
   ```

3. **`NoSideEffectsToString`:**  JavaScript 中的 `Object.prototype.toString()` 方法，以及将对象转换为字符串时的隐式类型转换，都与 V8 的 `NoSideEffectsToString` 方法有关。
   ```javascript
   const num = 42.3;
   console.log(num.toString()); // 输出 "42.3"

   const err = new Error("Something went wrong");
   console.log(err.toString()); // 输出 "Error: Something went wrong"

   const obj = {};
   console.log(obj.toString()); // 输出 "[object Object]" (或类似格式)
   ```

4. **枚举缓存:**  JavaScript 的 `for...in` 循环和 `Object.keys()` 方法受益于 V8 的枚举缓存优化，可以更快地遍历对象的属性。
   ```javascript
   const obj = { a: 1, b: 2, c: 3 };
   for (let key in obj) {
     console.log(key, obj[key]);
   }
   console.log(Object.keys(obj)); // 输出 ["a", "b", "c"]
   ```

5. **处理负零:**  JavaScript 中存在 `-0` 和 `0` 两个概念，但在某些运算中它们会被视为相等。 V8 的这些测试确保了在特定类型转换中 `-0` 被正确处理。
   ```javascript
   console.log(-0 === 0); // true
   console.log(parseInt('-0')); // 0
   console.log(Math.round(-0.1)); // 0
   ```

6. **函数类型:**  JavaScript 中有多种函数定义方式（普通函数、箭头函数、async 函数、生成器函数等），V8 内部需要区分这些类型以执行不同的操作和进行优化。
   ```javascript
   function regularFunction() {}
   const arrowFunction = () => {};
   async function asyncFunction() {}
   function* generatorFunction() {}

   console.log(typeof regularFunction); // "function"
   console.log(typeof arrowFunction);   // "function"
   console.log(typeof asyncFunction);  // "function"
   console.log(typeof generatorFunction); // "function"
   ```

7. **构造函数的实例类型:**  当你使用 `new` 关键字创建对象时，V8 会根据构造函数的类型创建具有特定内部结构的实例。
   ```javascript
   const arr = new Array(); // 创建一个 JS_ARRAY_TYPE 的对象
   const regex = new RegExp("abc"); // 创建一个 JS_REG_EXP_TYPE 的对象
   const promise = new Promise(() => {}); // 创建一个 JS_PROMISE_TYPE 的对象
   ```

8. **添加数据属性时的名称冲突:**  JavaScript 中对象不允许直接在原型链上拥有同名的访问器属性和数据属性，V8 的测试确保了这种行为的一致性。
   ```javascript
   const obj = {};
   Object.defineProperty(obj, 'prop', {
       get: function() { return 1; }
   });
   obj.prop = 2; // 在严格模式下会报错，非严格模式下赋值无效
   console.log(obj.prop); // 输出 1
   ```

总而言之，`object-unittest.cc` 文件通过各种单元测试，深入验证了 V8 引擎中对象系统的核心功能，确保了 JavaScript 在 V8 上的正确、高效运行。 这些测试涵盖了对象创建、属性管理、类型转换、函数处理等多个关键方面。

Prompt: ```这是目录为v8/test/unittests/objects/object-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
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

"""
```