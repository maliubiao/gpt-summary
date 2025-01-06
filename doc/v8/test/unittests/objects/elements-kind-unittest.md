Response: Let's break down the thought process for analyzing this C++ code and relating it to JavaScript.

1. **Understand the Goal:** The request asks for a summary of the C++ code's functionality and, importantly, its connection to JavaScript, illustrated with examples. This means I need to understand what the C++ code *does* in the V8 engine and how that behavior is reflected in JavaScript.

2. **Initial Scan for Keywords:**  I'll quickly scan the code for relevant terms:
    * `ElementsKind`: This appears frequently, suggesting it's central to the code's purpose.
    * `JSObject`, `JSArray`: These clearly relate to JavaScript objects and arrays.
    * `Property`, `Element`: These are fundamental concepts in JavaScript object models.
    * `Map`: In V8 context, this refers to the hidden class or structure of an object.
    * `Factory`: This suggests object creation within the V8 engine.
    * `TEST_F`:  This indicates it's a unit test file.
    * `Smi`, `Double`, `String`: These are V8's internal representations of JavaScript primitive types.
    * `HOLEY`, `PACKED`, `DICTIONARY`: These are likely states or types related to how array elements are stored.
    * `DefinePropertyOrElementIgnoreAttributes`, `DeletePropertyOrElement`: These are operations on objects/arrays.

3. **Focus on `ElementsKind`:** The repeated use of `ElementsKind` strongly suggests this is the core subject. The tests seem to be about how different actions cause the `ElementsKind` of `JSObject` and `JSArray` to change.

4. **Analyze the Tests:**  I'll examine the individual tests to understand what scenarios they are covering:
    * `SystemPointerElementsKind`:  Confirms the size of system pointers. This is more of an internal V8 detail but shows `ElementsKind` has associated size information.
    * `JSObjectAddingProperties`: Tests adding properties to a plain JavaScript object. It checks how this affects the internal representation (property array).
    * `JSObjectInObjectAddingProperties`:  Focuses on how adding properties interacts with "in-object" properties (properties stored directly within the object's memory).
    * `JSObjectAddingElements`: Explores adding *indexed* elements to a plain object and how it can lead to a transition to `DICTIONARY_ELEMENTS` for very large indices.
    * `JSArrayAddingProperties`: Similar to the `JSObject` test, but for JavaScript arrays.
    * `JSArrayAddingElements`: Examines how adding indexed elements to an array affects its internal storage.
    * `JSArrayAddingElementsGeneralizingiFastSmiElements`, `JSArrayAddingElementsGeneralizingFastElements`, `JSArrayAddingElementsGeneralizingiFastDoubleElements`: These are crucial. They explicitly test how adding different types of elements (smis, strings, doubles) and deleting elements cause the `ElementsKind` of an array to transition between states like `PACKED_SMI_ELEMENTS`, `HOLEY_SMI_ELEMENTS`, `HOLEY_ELEMENTS`, `PACKED_DOUBLE_ELEMENTS`, `HOLEY_DOUBLE_ELEMENTS`.

5. **Identify Key Concepts:** From analyzing the tests, the key concepts emerge:
    * **Elements Kind:**  An internal optimization in V8 that determines how the elements of an array or object are stored. Different kinds offer different performance characteristics.
    * **Packed vs. Holey:** `PACKED` indicates contiguous storage, while `HOLEY` allows for "gaps" or deleted elements.
    * **Smi, Double, Generic:** These refer to the types of elements primarily stored in the array. `SMI` (Small Integer) is a special optimization for integers. `Double` is for floating-point numbers. "Generic" means it can hold any JavaScript value.
    * **Transitions:** The `ElementsKind` can change dynamically based on operations performed on the array. These transitions are crucial for performance.
    * **Dictionary Elements:** A less optimized storage mode used for sparse arrays or objects with many gaps.

6. **Relate to JavaScript:**  Now the crucial step: how does this internal C++ behavior manifest in JavaScript?
    * **Initial Array State:** When you create an array with only integers, V8 might initially use a `PACKED_SMI_ELEMENTS` kind for efficiency.
    * **Adding Different Types:**  If you add a string or a floating-point number, V8 needs to generalize the storage, causing a transition to a less specialized `ElementsKind`.
    * **Deleting Elements:** Deleting elements creates "holes," leading to a transition from `PACKED` to `HOLEY`.
    * **Sparse Arrays:** Assigning to a very large index creates a sparse array, which V8 internally handles with `DICTIONARY_ELEMENTS`.

7. **Construct JavaScript Examples:**  Based on the identified relationships, I can create JavaScript code snippets that demonstrate these internal transitions:
    * Start with an array of integers.
    * Show how adding a non-integer changes its behavior (though the internal `ElementsKind` is hidden).
    * Demonstrate how `delete` makes an array "holey."
    * Illustrate the creation of a sparse array.

8. **Structure the Summary:** Organize the findings into a clear and concise summary, covering the main purpose of the C++ file and explaining the connection to JavaScript with concrete examples. Emphasize that the C++ code is *testing* these internal mechanisms.

9. **Refine and Review:**  Read through the summary and examples to ensure accuracy and clarity. Make sure the connection between the C++ tests and the JavaScript behavior is well-explained. For example, initially, I might just say "adding a string changes the ElementsKind."  I should refine this to explain *why* – the need to accommodate different types.

This detailed process, moving from low-level code analysis to high-level JavaScript behavior and then back to concrete examples, is essential for understanding the connection between V8's internals and the JavaScript we write.
这个C++源代码文件 `elements-kind-unittest.cc` 是 V8 JavaScript 引擎的一部分，它的主要功能是**测试 V8 引擎中关于 `ElementsKind`（元素种类）的机制和行为**。

具体来说，这个文件包含了一系列的单元测试，用来验证以下几个方面：

1. **`ElementsKind` 的基本属性：** 例如，测试 `SYSTEM_POINTER_ELEMENTS` 这种元素种类的字节大小和偏移量。
2. **`JSObject` 和 `JSArray` 在添加属性和元素时 `ElementsKind` 的变化：**  测试在向 JavaScript 对象或数组添加不同类型的属性或元素时，V8 引擎如何动态地改变其内部的元素存储方式 (`ElementsKind`) 以优化性能。
3. **`ElementsKind` 之间的转换和泛化：**  测试当数组元素类型发生变化时，`ElementsKind` 如何从更具体的类型（例如，只包含小整数的 `PACKED_SMI_ELEMENTS`）转换为更通用的类型（例如，可以包含任意类型值的 `HOLEY_ELEMENTS`）。
4. **辅助函数的正确性：** 测试像 `IsHoleyElementsKindForRead`、`IsHoleyElementsKind` 和 `IsFastPackedElementsKind` 这样的辅助函数是否能够正确地判断给定的 `ElementsKind` 属于哪种特性。

**`ElementsKind` 与 JavaScript 功能的关系：**

`ElementsKind` 是 V8 引擎内部用于优化 JavaScript 数组和对象元素存储和访问的关键机制。 JavaScript 是一种动态类型语言，数组可以包含不同类型的值。为了提高性能，V8 会尝试根据数组中元素的类型选择最合适的存储方式。

以下是一些主要的 `ElementsKind` 及其含义：

* **`PACKED_SMI_ELEMENTS`**: 数组只包含小整数 (Smi)。这是最紧凑和高效的存储方式。
* **`HOLEY_SMI_ELEMENTS`**: 数组可能包含小整数或 "洞" (holes, 指未定义的索引)。
* **`PACKED_DOUBLE_ELEMENTS`**: 数组只包含浮点数。
* **`HOLEY_DOUBLE_ELEMENTS`**: 数组可能包含浮点数或 "洞"。
* **`PACKED_ELEMENTS`**: 数组包含各种类型的对象（包括原始类型）。
* **`HOLEY_ELEMENTS`**: 数组可能包含各种类型的对象或 "洞"。
* **`DICTIONARY_ELEMENTS`**:  当数组变得非常稀疏或键不是连续的整数时使用，性能相对较差。

**JavaScript 举例说明：**

```javascript
// 初始状态，数组只包含小整数
let arr1 = [1, 2, 3];
// V8 内部可能会使用 PACKED_SMI_ELEMENTS

// 添加一个字符串
arr1.push("hello");
// V8 内部可能会将 ElementsKind 转换为 HOLEY_ELEMENTS 或 PACKED_ELEMENTS，
// 因为数组现在包含了不同类型的元素

// 创建一个包含 "洞" 的数组
let arr2 = [1, , 3]; // 中间有一个未定义的元素
// V8 内部可能会使用 HOLEY_SMI_ELEMENTS

// 创建一个只包含浮点数的数组
let arr3 = [1.1, 2.2, 3.3];
// V8 内部可能会使用 PACKED_DOUBLE_ELEMENTS

// 删除数组元素
delete arr3[1];
// V8 内部可能会将 ElementsKind 转换为 HOLEY_DOUBLE_ELEMENTS

// 创建一个非常稀疏的数组
let arr4 = [];
arr4[1000000] = 1;
// V8 内部很可能会使用 DICTIONARY_ELEMENTS
```

**总结：**

`elements-kind-unittest.cc` 文件通过大量的单元测试，验证了 V8 引擎在处理 JavaScript 数组和对象时，如何根据元素的类型和操作动态地管理和转换 `ElementsKind`，从而优化内存使用和访问性能。这些测试确保了 V8 引擎在面对各种 JavaScript 代码模式时，能够正确且高效地工作。虽然开发者通常不需要直接关心 `ElementsKind` 的具体状态，但理解其背后的原理有助于理解 JavaScript 引擎的性能优化策略。

Prompt: ```这是目录为v8/test/unittests/objects/elements-kind-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdlib.h>

#include <utility>

#include "src/codegen/compilation-cache.h"
#include "src/execution/execution.h"
#include "src/handles/global-handles.h"
#include "src/heap/factory.h"
#include "src/ic/stub-cache.h"
#include "src/init/v8.h"
#include "src/objects/js-array-inl.h"
#include "src/objects/objects-inl.h"
#include "test/unittests/test-utils.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace v8 {
namespace internal {

using ElementsKindTest = TestWithContext;

//
// Helper functions.
//

namespace {

template <typename T, typename M>
bool EQUALS(Isolate* isolate, Handle<T> left, Handle<M> right) {
  if (*left == *right) return true;
  return Object::Equals(isolate, Cast<Object>(left), Cast<Object>(right))
      .FromJust();
}

template <typename T, typename M>
bool EQUALS(Isolate* isolate, Handle<T> left, M right) {
  return EQUALS(isolate, left, handle(right, isolate));
}

template <typename T, typename M>
bool EQUALS(Isolate* isolate, T left, Handle<M> right) {
  return EQUALS(isolate, handle(left, isolate), right);
}

bool ElementsKindIsHoleyElementsKindForRead(ElementsKind kind) {
  switch (kind) {
    case ElementsKind::HOLEY_SMI_ELEMENTS:
    case ElementsKind::HOLEY_ELEMENTS:
    case ElementsKind::HOLEY_DOUBLE_ELEMENTS:
    case ElementsKind::HOLEY_NONEXTENSIBLE_ELEMENTS:
    case ElementsKind::HOLEY_SEALED_ELEMENTS:
    case ElementsKind::HOLEY_FROZEN_ELEMENTS:
      return true;
    default:
      return false;
  }
}

bool ElementsKindIsHoleyElementsKind(ElementsKind kind) {
  switch (kind) {
    case ElementsKind::HOLEY_SMI_ELEMENTS:
    case ElementsKind::HOLEY_ELEMENTS:
    case ElementsKind::HOLEY_DOUBLE_ELEMENTS:
      return true;
    default:
      return false;
  }
}

bool ElementsKindIsFastPackedElementsKind(ElementsKind kind) {
  switch (kind) {
    case ElementsKind::PACKED_SMI_ELEMENTS:
    case ElementsKind::PACKED_ELEMENTS:
    case ElementsKind::PACKED_DOUBLE_ELEMENTS:
      return true;
    default:
      return false;
  }
}

}  // namespace

//
// Tests
//

TEST_F(ElementsKindTest, SystemPointerElementsKind) {
  CHECK_EQ(ElementsKindToShiftSize(SYSTEM_POINTER_ELEMENTS),
           kSystemPointerSizeLog2);
  CHECK_EQ(ElementsKindToByteSize(SYSTEM_POINTER_ELEMENTS), kSystemPointerSize);
}

TEST_F(ElementsKindTest, JSObjectAddingProperties) {
  Factory* factory = i_isolate()->factory();
  v8::HandleScope scope(isolate());

  Handle<FixedArray> empty_fixed_array(factory->empty_fixed_array());
  Handle<PropertyArray> empty_property_array(factory->empty_property_array());
  Handle<JSFunction> function =
      factory->NewFunctionForTesting(factory->empty_string());
  Handle<Object> value(Smi::FromInt(42), i_isolate());

  Handle<JSObject> object = factory->NewJSObject(function);
  DirectHandle<Map> previous_map(object->map(), i_isolate());
  CHECK_EQ(HOLEY_ELEMENTS, previous_map->elements_kind());
  CHECK(EQUALS(i_isolate(), object->property_array(), empty_property_array));
  CHECK(EQUALS(i_isolate(), object->elements(), empty_fixed_array));

  // for the default constructor function no in-object properties are reserved
  // hence adding a single property will initialize the property-array
  Handle<String> name = MakeName("property", 0);
  JSObject::DefinePropertyOrElementIgnoreAttributes(object, name, value, NONE)
      .Check();
  CHECK_NE(object->map(), *previous_map);
  CHECK_EQ(HOLEY_ELEMENTS, object->map()->elements_kind());
  CHECK_LE(1, object->property_array()->length());
  CHECK(EQUALS(i_isolate(), object->elements(), empty_fixed_array));
}

TEST_F(ElementsKindTest, JSObjectInObjectAddingProperties) {
  Factory* factory = i_isolate()->factory();
  v8::HandleScope scope(isolate());

  Handle<FixedArray> empty_fixed_array(factory->empty_fixed_array());
  Handle<PropertyArray> empty_property_array(factory->empty_property_array());
  Handle<JSFunction> function =
      factory->NewFunctionForTesting(factory->empty_string());
  int nof_inobject_properties = 10;
  // force in object properties by changing the expected_nof_properties
  // (we always reserve 8 inobject properties slack on top).
  function->shared()->set_expected_nof_properties(nof_inobject_properties - 8);
  Handle<Object> value(Smi::FromInt(42), i_isolate());

  Handle<JSObject> object = factory->NewJSObject(function);
  DirectHandle<Map> previous_map(object->map(), i_isolate());
  CHECK_EQ(HOLEY_ELEMENTS, previous_map->elements_kind());
  CHECK(EQUALS(i_isolate(), object->property_array(), empty_property_array));
  CHECK(EQUALS(i_isolate(), object->elements(), empty_fixed_array));

  // we have reserved space for in-object properties, hence adding up to
  // |nof_inobject_properties| will not create a property store
  for (int i = 0; i < nof_inobject_properties; i++) {
    Handle<String> name = MakeName("property", i);
    JSObject::DefinePropertyOrElementIgnoreAttributes(object, name, value, NONE)
        .Check();
  }
  CHECK_NE(object->map(), *previous_map);
  CHECK_EQ(HOLEY_ELEMENTS, object->map()->elements_kind());
  CHECK(EQUALS(i_isolate(), object->property_array(), empty_property_array));
  CHECK(EQUALS(i_isolate(), object->elements(), empty_fixed_array));

  // adding one more property will not fit in the in-object properties, thus
  // creating a property store
  int index = nof_inobject_properties + 1;
  Handle<String> name = MakeName("property", index);
  JSObject::DefinePropertyOrElementIgnoreAttributes(object, name, value, NONE)
      .Check();
  CHECK_NE(object->map(), *previous_map);
  CHECK_EQ(HOLEY_ELEMENTS, object->map()->elements_kind());
  // there must be at least 1 element in the properies store
  CHECK_LE(1, object->property_array()->length());
  CHECK(EQUALS(i_isolate(), object->elements(), empty_fixed_array));
}

TEST_F(ElementsKindTest, JSObjectAddingElements) {
  Factory* factory = i_isolate()->factory();
  v8::HandleScope scope(isolate());

  Handle<String> name;
  Handle<FixedArray> empty_fixed_array(factory->empty_fixed_array());
  Handle<PropertyArray> empty_property_array(factory->empty_property_array());
  Handle<JSFunction> function =
      factory->NewFunctionForTesting(factory->empty_string());
  Handle<Object> value(Smi::FromInt(42), i_isolate());

  Handle<JSObject> object = factory->NewJSObject(function);
  DirectHandle<Map> previous_map(object->map(), i_isolate());
  CHECK_EQ(HOLEY_ELEMENTS, previous_map->elements_kind());
  CHECK(EQUALS(i_isolate(), object->property_array(), empty_property_array));
  CHECK(EQUALS(i_isolate(), object->elements(), empty_fixed_array));

  // Adding an indexed element initializes the elements array
  name = MakeString("0");
  JSObject::DefinePropertyOrElementIgnoreAttributes(object, name, value, NONE)
      .Check();
  // no change in elements_kind => no map transition
  CHECK_EQ(object->map(), *previous_map);
  CHECK_EQ(HOLEY_ELEMENTS, object->map()->elements_kind());
  CHECK(EQUALS(i_isolate(), object->property_array(), empty_property_array));
  CHECK_LE(1, object->elements()->length());

  // Adding more consecutive elements without a change in the backing store
  int non_dict_backing_store_limit = 100;
  for (int i = 1; i < non_dict_backing_store_limit; i++) {
    name = MakeName("", i);
    JSObject::DefinePropertyOrElementIgnoreAttributes(object, name, value, NONE)
        .Check();
  }
  // no change in elements_kind => no map transition
  CHECK_EQ(object->map(), *previous_map);
  CHECK_EQ(HOLEY_ELEMENTS, object->map()->elements_kind());
  CHECK(EQUALS(i_isolate(), object->property_array(), empty_property_array));
  CHECK_LE(non_dict_backing_store_limit, object->elements()->length());

  // Adding an element at an very large index causes a change to
  // DICTIONARY_ELEMENTS
  name = MakeString("100000000");
  JSObject::DefinePropertyOrElementIgnoreAttributes(object, name, value, NONE)
      .Check();
  // change in elements_kind => map transition
  CHECK_NE(object->map(), *previous_map);
  CHECK_EQ(DICTIONARY_ELEMENTS, object->map()->elements_kind());
  CHECK(EQUALS(i_isolate(), object->property_array(), empty_property_array));
  CHECK_LE(non_dict_backing_store_limit, object->elements()->length());
}

TEST_F(ElementsKindTest, JSArrayAddingProperties) {
  Factory* factory = i_isolate()->factory();
  v8::HandleScope scope(isolate());

  Handle<FixedArray> empty_fixed_array(factory->empty_fixed_array());
  Handle<PropertyArray> empty_property_array(factory->empty_property_array());
  Handle<Object> value(Smi::FromInt(42), i_isolate());

  Handle<JSArray> array =
      factory->NewJSArray(ElementsKind::PACKED_SMI_ELEMENTS, 0, 0);
  DirectHandle<Map> previous_map(array->map(), i_isolate());
  CHECK_EQ(PACKED_SMI_ELEMENTS, previous_map->elements_kind());
  CHECK(EQUALS(i_isolate(), array->property_array(), empty_property_array));
  CHECK(EQUALS(i_isolate(), array->elements(), empty_fixed_array));
  CHECK_EQ(0, Smi::ToInt(array->length()));

  // for the default constructor function no in-object properties are reserved
  // hence adding a single property will initialize the property-array
  Handle<String> name = MakeName("property", 0);
  JSObject::DefinePropertyOrElementIgnoreAttributes(array, name, value, NONE)
      .Check();
  // No change in elements_kind but added property => new map
  CHECK_NE(array->map(), *previous_map);
  CHECK_EQ(PACKED_SMI_ELEMENTS, array->map()->elements_kind());
  CHECK_LE(1, array->property_array()->length());
  CHECK(EQUALS(i_isolate(), array->elements(), empty_fixed_array));
  CHECK_EQ(0, Smi::ToInt(array->length()));
}

TEST_F(ElementsKindTest, JSArrayAddingElements) {
  Factory* factory = i_isolate()->factory();
  v8::HandleScope scope(isolate());

  Handle<String> name;
  Handle<FixedArray> empty_fixed_array(factory->empty_fixed_array());
  Handle<PropertyArray> empty_property_array(factory->empty_property_array());
  Handle<Object> value(Smi::FromInt(42), i_isolate());

  Handle<JSArray> array =
      factory->NewJSArray(ElementsKind::PACKED_SMI_ELEMENTS, 0, 0);
  DirectHandle<Map> previous_map(array->map(), i_isolate());
  CHECK_EQ(PACKED_SMI_ELEMENTS, previous_map->elements_kind());
  CHECK(EQUALS(i_isolate(), array->property_array(), empty_property_array));
  CHECK(EQUALS(i_isolate(), array->elements(), empty_fixed_array));
  CHECK_EQ(0, Smi::ToInt(array->length()));

  // Adding an indexed element initializes the elements array
  name = MakeString("0");
  JSObject::DefinePropertyOrElementIgnoreAttributes(array, name, value, NONE)
      .Check();
  // no change in elements_kind => no map transition
  CHECK_EQ(array->map(), *previous_map);
  CHECK_EQ(PACKED_SMI_ELEMENTS, array->map()->elements_kind());
  CHECK(EQUALS(i_isolate(), array->property_array(), empty_property_array));
  CHECK_LE(1, array->elements()->length());
  CHECK_EQ(1, Smi::ToInt(array->length()));

  // Adding more consecutive elements without a change in the backing store
  int non_dict_backing_store_limit = 100;
  for (int i = 1; i < non_dict_backing_store_limit; i++) {
    name = MakeName("", i);
    JSObject::DefinePropertyOrElementIgnoreAttributes(array, name, value, NONE)
        .Check();
  }
  // no change in elements_kind => no map transition
  CHECK_EQ(array->map(), *previous_map);
  CHECK_EQ(PACKED_SMI_ELEMENTS, array->map()->elements_kind());
  CHECK(EQUALS(i_isolate(), array->property_array(), empty_property_array));
  CHECK_LE(non_dict_backing_store_limit, array->elements()->length());
  CHECK_EQ(non_dict_backing_store_limit, Smi::ToInt(array->length()));

  // Adding an element at an very large index causes a change to
  // DICTIONARY_ELEMENTS
  int index = 100000000;
  name = MakeName("", index);
  JSObject::DefinePropertyOrElementIgnoreAttributes(array, name, value, NONE)
      .Check();
  // change in elements_kind => map transition
  CHECK_NE(array->map(), *previous_map);
  CHECK_EQ(DICTIONARY_ELEMENTS, array->map()->elements_kind());
  CHECK(EQUALS(i_isolate(), array->property_array(), empty_property_array));
  CHECK_LE(non_dict_backing_store_limit, array->elements()->length());
  CHECK_LE(array->elements()->length(), index);
  CHECK_EQ(index + 1, Smi::ToInt(array->length()));
}

TEST_F(ElementsKindTest, JSArrayAddingElementsGeneralizingiFastSmiElements) {
  Factory* factory = i_isolate()->factory();
  v8::HandleScope scope(isolate());

  Handle<String> name;
  Handle<Object> value_smi(Smi::FromInt(42), i_isolate());
  Handle<Object> value_string(MakeString("value"));
  Handle<Object> value_double = factory->NewNumber(3.1415);

  Handle<JSArray> array =
      factory->NewJSArray(ElementsKind::PACKED_SMI_ELEMENTS, 0, 0);
  DirectHandle<Map> previous_map(array->map(), i_isolate());
  CHECK_EQ(PACKED_SMI_ELEMENTS, previous_map->elements_kind());
  CHECK_EQ(0, Smi::ToInt(array->length()));

  // `array[0] = smi_value` doesn't change the elements_kind
  name = MakeString("0");
  JSObject::DefinePropertyOrElementIgnoreAttributes(array, name, value_smi,
                                                    NONE)
      .Check();
  // no change in elements_kind => no map transition
  CHECK_EQ(array->map(), *previous_map);
  CHECK_EQ(PACKED_SMI_ELEMENTS, array->map()->elements_kind());
  CHECK_EQ(1, Smi::ToInt(array->length()));

  // `delete array[0]` does not alter length, but changes the elments_kind
  name = MakeString("0");
  CHECK(JSReceiver::DeletePropertyOrElement(i_isolate(), array, name)
            .FromMaybe(false));
  CHECK_NE(array->map(), *previous_map);
  CHECK_EQ(HOLEY_SMI_ELEMENTS, array->map()->elements_kind());
  CHECK_EQ(1, Smi::ToInt(array->length()));
  previous_map = handle(array->map(), i_isolate());

  // add a couple of elements again
  name = MakeString("0");
  JSObject::DefinePropertyOrElementIgnoreAttributes(array, name, value_smi,
                                                    NONE)
      .Check();
  name = MakeString("1");
  JSObject::DefinePropertyOrElementIgnoreAttributes(array, name, value_smi,
                                                    NONE)
      .Check();
  CHECK_EQ(array->map(), *previous_map);
  CHECK_EQ(HOLEY_SMI_ELEMENTS, array->map()->elements_kind());
  CHECK_EQ(2, Smi::ToInt(array->length()));

  // Adding a string to the array changes from FAST_HOLEY_SMI to FAST_HOLEY
  name = MakeString("0");
  JSObject::DefinePropertyOrElementIgnoreAttributes(array, name, value_string,
                                                    NONE)
      .Check();
  CHECK_NE(array->map(), *previous_map);
  CHECK_EQ(HOLEY_ELEMENTS, array->map()->elements_kind());
  CHECK_EQ(2, Smi::ToInt(array->length()));
  previous_map = handle(array->map(), i_isolate());

  // We don't transition back to FAST_SMI even if we remove the string
  name = MakeString("0");
  JSObject::DefinePropertyOrElementIgnoreAttributes(array, name, value_smi,
                                                    NONE)
      .Check();
  CHECK_EQ(array->map(), *previous_map);

  // Adding a double doesn't change the map either
  name = MakeString("0");
  JSObject::DefinePropertyOrElementIgnoreAttributes(array, name, value_double,
                                                    NONE)
      .Check();
  CHECK_EQ(array->map(), *previous_map);
}

TEST_F(ElementsKindTest, JSArrayAddingElementsGeneralizingFastElements) {
  Factory* factory = i_isolate()->factory();
  v8::HandleScope scope(isolate());

  Handle<String> name;
  Handle<Object> value_smi(Smi::FromInt(42), i_isolate());
  Handle<Object> value_string(MakeString("value"));

  Handle<JSArray> array =
      factory->NewJSArray(ElementsKind::PACKED_ELEMENTS, 0, 0);
  DirectHandle<Map> previous_map(array->map(), i_isolate());
  CHECK_EQ(PACKED_ELEMENTS, previous_map->elements_kind());
  CHECK_EQ(0, Smi::ToInt(array->length()));

  // `array[0] = smi_value` doesn't change the elements_kind
  name = MakeString("0");
  JSObject::DefinePropertyOrElementIgnoreAttributes(array, name, value_smi,
                                                    NONE)
      .Check();
  // no change in elements_kind => no map transition
  CHECK_EQ(array->map(), *previous_map);
  CHECK_EQ(PACKED_ELEMENTS, array->map()->elements_kind());
  CHECK_EQ(1, Smi::ToInt(array->length()));

  // `delete array[0]` does not alter length, but changes the elments_kind
  name = MakeString("0");
  CHECK(JSReceiver::DeletePropertyOrElement(i_isolate(), array, name)
            .FromMaybe(false));
  CHECK_NE(array->map(), *previous_map);
  CHECK_EQ(HOLEY_ELEMENTS, array->map()->elements_kind());
  CHECK_EQ(1, Smi::ToInt(array->length()));
  previous_map = handle(array->map(), i_isolate());

  // add a couple of elements, elements_kind stays HOLEY
  name = MakeString("0");
  JSObject::DefinePropertyOrElementIgnoreAttributes(array, name, value_string,
                                                    NONE)
      .Check();
  name = MakeString("1");
  JSObject::DefinePropertyOrElementIgnoreAttributes(array, name, value_smi,
                                                    NONE)
      .Check();
  CHECK_EQ(array->map(), *previous_map);
  CHECK_EQ(HOLEY_ELEMENTS, array->map()->elements_kind());
  CHECK_EQ(2, Smi::ToInt(array->length()));
}

TEST_F(ElementsKindTest, JSArrayAddingElementsGeneralizingiFastDoubleElements) {
  Factory* factory = i_isolate()->factory();
  v8::HandleScope scope(isolate());

  Handle<String> name;
  Handle<Object> value_smi(Smi::FromInt(42), i_isolate());
  Handle<Object> value_string(MakeString("value"));
  Handle<Object> value_double = factory->NewNumber(3.1415);

  Handle<JSArray> array =
      factory->NewJSArray(ElementsKind::PACKED_SMI_ELEMENTS, 0, 0);
  DirectHandle<Map> previous_map(array->map(), i_isolate());

  // `array[0] = value_double` changes |elements_kind| to PACKED_DOUBLE_ELEMENTS
  name = MakeString("0");
  JSObject::DefinePropertyOrElementIgnoreAttributes(array, name, value_double,
                                                    NONE)
      .Check();
  CHECK_NE(array->map(), *previous_map);
  CHECK_EQ(PACKED_DOUBLE_ELEMENTS, array->map()->elements_kind());
  CHECK_EQ(1, Smi::ToInt(array->length()));
  previous_map = handle(array->map(), i_isolate());

  // `array[1] = value_smi` doesn't alter the |elements_kind|
  name = MakeString("1");
  JSObject::DefinePropertyOrElementIgnoreAttributes(array, name, value_smi,
                                                    NONE)
      .Check();
  CHECK_EQ(array->map(), *previous_map);
  CHECK_EQ(PACKED_DOUBLE_ELEMENTS, array->map()->elements_kind());
  CHECK_EQ(2, Smi::ToInt(array->length()));

  // `delete array[0]` does not alter length, but changes the elments_kind
  name = MakeString("0");
  CHECK(JSReceiver::DeletePropertyOrElement(i_isolate(), array, name)
            .FromMaybe(false));
  CHECK_NE(array->map(), *previous_map);
  CHECK_EQ(HOLEY_DOUBLE_ELEMENTS, array->map()->elements_kind());
  CHECK_EQ(2, Smi::ToInt(array->length()));
  previous_map = handle(array->map(), i_isolate());

  // filling the hole `array[0] = value_smi` again doesn't transition back
  name = MakeString("0");
  JSObject::DefinePropertyOrElementIgnoreAttributes(array, name, value_double,
                                                    NONE)
      .Check();
  CHECK_EQ(array->map(), *previous_map);
  CHECK_EQ(HOLEY_DOUBLE_ELEMENTS, array->map()->elements_kind());
  CHECK_EQ(2, Smi::ToInt(array->length()));

  // Adding a string to the array changes to elements_kind PACKED_ELEMENTS
  name = MakeString("1");
  JSObject::DefinePropertyOrElementIgnoreAttributes(array, name, value_string,
                                                    NONE)
      .Check();
  CHECK_NE(array->map(), *previous_map);
  CHECK_EQ(HOLEY_ELEMENTS, array->map()->elements_kind());
  CHECK_EQ(2, Smi::ToInt(array->length()));
  previous_map = handle(array->map(), i_isolate());

  // Adding a double doesn't change the map
  name = MakeString("0");
  JSObject::DefinePropertyOrElementIgnoreAttributes(array, name, value_double,
                                                    NONE)
      .Check();
  CHECK_EQ(array->map(), *previous_map);
}

TEST_F(ElementsKindTest, IsHoleyElementsKindForRead) {
  for (int i = 0; i <= ElementsKind::LAST_ELEMENTS_KIND; i++) {
    ElementsKind kind = static_cast<ElementsKind>(i);
    CHECK_EQ(ElementsKindIsHoleyElementsKindForRead(kind),
             IsHoleyElementsKindForRead(kind));
  }
}

TEST_F(ElementsKindTest, IsHoleyElementsKind) {
  for (int i = 0; i <= ElementsKind::LAST_ELEMENTS_KIND; i++) {
    ElementsKind kind = static_cast<ElementsKind>(i);
    CHECK_EQ(ElementsKindIsHoleyElementsKind(kind), IsHoleyElementsKind(kind));
  }
}

TEST_F(ElementsKindTest, IsFastPackedElementsKind) {
  for (int i = 0; i <= ElementsKind::LAST_ELEMENTS_KIND; i++) {
    ElementsKind kind = static_cast<ElementsKind>(i);
    CHECK_EQ(ElementsKindIsFastPackedElementsKind(kind),
             IsFastPackedElementsKind(kind));
  }
}

}  // namespace internal
}  // namespace v8

"""
```