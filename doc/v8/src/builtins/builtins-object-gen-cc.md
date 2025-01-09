Response:
The user wants a summary of the provided V8 C++ source code file `v8/src/builtins/builtins-object-gen.cc`.

Here's a breakdown of the request and a plan to address it:

1. **Identify the file's purpose:** The file is located in the `builtins` directory and named `builtins-object-gen.cc`. This strongly suggests it contains implementations of built-in functions related to the `Object` constructor in JavaScript.

2. **Analyze the included headers:** The `#include` directives reveal dependencies on other V8 components, such as code generation (`codegen`), heap management (`heap`), inline caches (`ic`), and object representations (`objects`). This confirms the file deals with low-level implementation details.

3. **Examine the class `ObjectEntriesValuesBuiltinsAssembler`:** This class seems to be responsible for implementing `Object.entries()` and `Object.values()`. The `CollectType` enum and the methods `GetOwnValuesOrEntries` and `FastGetOwnValuesOrEntries` support this hypothesis.

4. **Examine the `ObjectBuiltinsAssembler` methods:**  Methods like `ReturnToStringFormat`, `ConstructAccessorDescriptor`, and `ConstructDataDescriptor` indicate the file handles the creation and manipulation of object property descriptors.

5. **Analyze the `TF_BUILTIN` macros:** These macros define the entry points for specific JavaScript built-in functions. The names of the built-ins (`ObjectPrototypeHasOwnProperty`, `ObjectAssign`, `ObjectKeys`, `ObjectHasOwn`, `ObjectGetOwnPropertyNames`) directly correspond to standard JavaScript `Object` methods.

6. **Infer the overall functionality:** Based on the above points, the file likely implements several core `Object` methods, potentially with optimized "fast-path" implementations for common scenarios and fallback to slower runtime functions for more complex cases.

7. **Address the `.tq` question:** The prompt explicitly asks about the `.tq` extension. Since the provided file has a `.cc` extension, it's C++, not Torque.

8. **Provide JavaScript examples:** For the implemented built-ins, concrete JavaScript examples demonstrating their usage should be provided.

9. **Consider code logic and reasoning:**  The `FastGetOwnValuesOrEntries` method appears to have specific logic for handling objects with an "enum cache."  A hypothetical scenario with input and output for this logic would be useful.

10. **Identify common programming errors:**  Relate the built-in implementations to common mistakes developers make when using these `Object` methods.

11. **Summarize the functionality:**  Provide a concise overview of the file's purpose.

**Constraint Checklist & Confidence Score:**

* 列举一下它的功能: Yes
* 如果v8/src/builtins/builtins-object-gen.cc以.tq结尾，那它是个v8 torque源代码: Yes
* 如果它与javascript的功能有关系，请用javascript举例说明: Yes
* 如果有代码逻辑推理，请给出假设输入与输出: Yes (focusing on the fast path for `Object.entries`/`Object.values`)
* 如果涉及用户常见的编程错误，请举例说明: Yes
* 这是第1部分，共3部分，请归纳一下它的功能: Yes

Confidence Score: 5/5

**Mental Sandbox Simulation:**

I mentally walked through the provided code snippets, focusing on the `TF_BUILTIN` macros and their corresponding JavaScript methods. I also looked at the fast-path logic in `FastGetOwnValuesOrEntries`. The structure of the code suggests a pattern of checking for fast-path conditions and falling back to runtime calls.

Strategizing complete. I will now generate the response based on the analysis above.

这是 V8 JavaScript 引擎的 C++ 源代码文件，它实现了 `Object` 构造函数的一些内置方法。 由于文件以 `.cc` 结尾，它不是 Torque 源代码。

**功能归纳:**

此文件主要负责实现以下 JavaScript `Object` 的内置方法：

* **`Object.prototype.hasOwnProperty()`:**  检查对象自身（不包括原型链）是否具有指定的属性。
* **`Object.assign()`:** 将一个或多个源对象的所有可枚举的自有属性复制到目标对象。它返回修改后的目标对象。
* **`Object.keys()`:** 返回一个由给定对象自身可枚举的属性名称组成的数组，数组中属性名的排列顺序和使用 `for...in` 循环遍历该对象属性所得到的顺序一致。
* **`Object.hasOwn()` (提案):**  类似于 `Object.prototype.hasOwnProperty()`，但设计为更易于访问。
* **`Object.getOwnPropertyNames()`:**  返回一个由指定对象的所有自身属性的名称（包括不可枚举属性，但不包括 Symbol 属性）组成的数组。

**JavaScript 举例说明:**

```javascript
const obj = { a: 1, b: 2 };
const protoObj = { c: 3 };
Object.setPrototypeOf(obj, protoObj);

// Object.prototype.hasOwnProperty()
console.log(obj.hasOwnProperty('a'));   // 输出: true
console.log(obj.hasOwnProperty('c'));   // 输出: false

// Object.assign()
const target = { x: 0 };
const source1 = { y: 1 };
const source2 = { z: 2 };
const returnedTarget = Object.assign(target, source1, source2);
console.log(target);                     // 输出: { x: 0, y: 1, z: 2 }
console.log(returnedTarget === target); // 输出: true

// Object.keys()
console.log(Object.keys(obj));          // 输出: [ 'a', 'b' ]

// Object.hasOwn()
console.log(Object.hasOwn(obj, 'a'));    // 输出: true
console.log(Object.hasOwn(obj, 'c'));    // 输出: false

// Object.getOwnPropertyNames()
const nonEnumObj = Object.defineProperty({}, 'nonEnum', {
  value: 4,
  enumerable: false
});
console.log(Object.getOwnPropertyNames(nonEnumObj)); // 输出: [ 'nonEnum' ]
```

**代码逻辑推理 (以 `Object.entries` / `Object.values` 的快速路径为例):**

虽然这段代码本身没有直接实现 `Object.entries` 或 `Object.values` 的 `TF_BUILTIN`，但它包含了一个名为 `ObjectEntriesValuesBuiltinsAssembler` 的类，暗示了它们的部分实现。`FastGetOwnValuesOrEntries` 方法尝试为这些方法提供一个优化的快速路径。

**假设输入与输出 (针对 `FastGetOwnValuesOrEntries` 中的循环):**

假设我们有一个简单的对象 `obj = { a: 1, b: 2 }`，并且调用 `Object.entries(obj)`。

1. **输入:**
   * `context`: 当前的执行上下文。
   * `object`:  表示 `{ a: 1, b: 2 }` 的 `JSObject`。
   * `if_call_runtime_with_fast_path`: 一个标签，如果需要调用运行时函数则跳转到此处。
   * `if_no_properties`: 一个标签，如果对象没有属性则跳转到此处。
   * `collect_type`: `kEntries` (表示我们正在收集键值对)。
   * `map`:  `obj` 对象的 Map，包含对象的结构信息。
   * `descriptors`: `obj` 对象的 DescriptorArray，包含属性的描述信息。

2. **循环过程 (简化):**
   * **第一次循环:**
     * `next_key` 将是字符串 "a"。
     * `details` 将包含关于属性 "a" 的信息 (例如，是否可枚举，是否是数据属性)。
     * 假设 "a" 是可枚举的数据属性。
     * `value` 将被获取为 `obj.a`，即数字 `1`。
     * 由于 `collect_type` 是 `kEntries`，将创建一个新的数组 `["a", 1]`。
     * 这个数组将被存储在 `values_or_entries` 数组的第一个位置。
     * `var_result_index` 递增。
   * **第二次循环:**
     * `next_key` 将是字符串 "b"。
     * `details` 将包含关于属性 "b" 的信息。
     * 假设 "b" 是可枚举的数据属性。
     * `value` 将被获取为 `obj.b`，即数字 `2`。
     * 创建一个新的数组 `["b", 2]`。
     * 这个数组将被存储在 `values_or_entries` 数组的第二个位置。
     * `var_result_index` 递增。

3. **输出:**
   * 如果所有属性都成功处理且没有触发慢路径，`FinalizeValuesOrEntriesJSArray` 将被调用，返回一个新的 `JSArray`，其内容为 `[["a", 1], ["b", 2]]`。

**用户常见的编程错误:**

* **误解 `Object.assign()` 的行为:**  `Object.assign()` 执行的是浅拷贝，如果源对象的属性值是对象，则只会复制对象的引用。

   ```javascript
   const obj1 = { a: { b: 1 } };
   const obj2 = Object.assign({}, obj1);
   obj2.a.b = 2;
   console.log(obj1.a.b); // 输出: 2 (obj1 也被修改了)
   ```

* **期望 `Object.keys()` 返回所有属性:** `Object.keys()` 只返回可枚举的自有属性的名称。开发者可能会忘记某些属性是不可枚举的。

   ```javascript
   const obj = Object.defineProperty({}, 'hidden', {
     value: 5,
     enumerable: false
   });
   console.log(Object.keys(obj)); // 输出: []
   ```

* **在 `Object.assign()` 中修改目标对象的原型链:** `Object.assign()` 只复制自有属性，不会复制或修改原型链。

   ```javascript
   const proto = { c: 3 };
   const target = Object.create(proto);
   const source = { a: 1 };
   Object.assign(target, source);
   console.log(target.a); // 输出: 1
   console.log(target.c); // 输出: 3 (仍然从原型链继承)
   ```

**总结:**

`v8/src/builtins/builtins-object-gen.cc` 文件的第 1 部分主要实现了 `Object.prototype.hasOwnProperty`、`Object.assign`、`Object.keys`、`Object.hasOwn` 和 `Object.getOwnPropertyNames` 这些核心的 JavaScript `Object` 内置方法。它还包含用于实现 `Object.entries` 和 `Object.values` 的辅助类和方法，特别是针对这些方法的性能优化（快速路径）。该文件展示了 V8 引擎如何用 C++ 高效地实现 JavaScript 的基本对象操作。

Prompt: 
```
这是目录为v8/src/builtins/builtins-object-gen.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/builtins-object-gen.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/builtins/builtins-object-gen.h"

#include <optional>

#include "src/builtins/builtins-constructor-gen.h"
#include "src/builtins/builtins-inl.h"
#include "src/builtins/builtins-utils-gen.h"
#include "src/codegen/code-stub-assembler-inl.h"
#include "src/common/globals.h"
#include "src/heap/factory-inl.h"
#include "src/ic/accessor-assembler.h"
#include "src/ic/keyed-store-generic.h"
#include "src/objects/js-generator.h"
#include "src/objects/js-objects.h"
#include "src/objects/property-descriptor-object.h"
#include "src/objects/property-details.h"
#include "src/objects/shared-function-info.h"
#include "src/objects/transitions.h"

namespace v8 {
namespace internal {

#include "src/codegen/define-code-stub-assembler-macros.inc"

class ObjectEntriesValuesBuiltinsAssembler : public ObjectBuiltinsAssembler {
 public:
  explicit ObjectEntriesValuesBuiltinsAssembler(
      compiler::CodeAssemblerState* state)
      : ObjectBuiltinsAssembler(state) {}

 protected:
  enum CollectType { kEntries, kValues };

  TNode<BoolT> IsPropertyEnumerable(TNode<Uint32T> details);

  TNode<BoolT> IsPropertyKindAccessor(TNode<Uint32T> kind);

  TNode<BoolT> IsPropertyKindData(TNode<Uint32T> kind);

  TNode<Uint32T> LoadPropertyKind(TNode<Uint32T> details) {
    return DecodeWord32<PropertyDetails::KindField>(details);
  }

  void GetOwnValuesOrEntries(TNode<Context> context, TNode<Object> maybe_object,
                             CollectType collect_type);

  TNode<JSArray> FastGetOwnValuesOrEntries(
      TNode<Context> context, TNode<JSObject> object,
      Label* if_call_runtime_with_fast_path, Label* if_no_properties,
      CollectType collect_type);

  TNode<JSArray> FinalizeValuesOrEntriesJSArray(
      TNode<Context> context, TNode<FixedArray> values_or_entries,
      TNode<IntPtrT> size, TNode<Map> array_map, Label* if_empty);
};

void ObjectBuiltinsAssembler::ReturnToStringFormat(TNode<Context> context,
                                                   TNode<String> string) {
  TNode<String> lhs = StringConstant("[object ");
  TNode<String> rhs = StringConstant("]");

  Builtin builtin = Builtins::StringAdd(STRING_ADD_CHECK_NONE);

  Return(CallBuiltin(builtin, context,
                     CallBuiltin(builtin, context, lhs, string), rhs));
}

TNode<JSObject> ObjectBuiltinsAssembler::ConstructAccessorDescriptor(
    TNode<Context> context, TNode<Object> getter, TNode<Object> setter,
    TNode<BoolT> enumerable, TNode<BoolT> configurable) {
  TNode<NativeContext> native_context = LoadNativeContext(context);
  TNode<Map> map = CAST(LoadContextElement(
      native_context, Context::ACCESSOR_PROPERTY_DESCRIPTOR_MAP_INDEX));
  TNode<JSObject> js_desc = AllocateJSObjectFromMap(map);

  StoreObjectFieldNoWriteBarrier(
      js_desc, JSAccessorPropertyDescriptor::kGetOffset, getter);
  StoreObjectFieldNoWriteBarrier(
      js_desc, JSAccessorPropertyDescriptor::kSetOffset, setter);
  StoreObjectFieldNoWriteBarrier(
      js_desc, JSAccessorPropertyDescriptor::kEnumerableOffset,
      SelectBooleanConstant(enumerable));
  StoreObjectFieldNoWriteBarrier(
      js_desc, JSAccessorPropertyDescriptor::kConfigurableOffset,
      SelectBooleanConstant(configurable));

  return js_desc;
}

TNode<JSObject> ObjectBuiltinsAssembler::ConstructDataDescriptor(
    TNode<Context> context, TNode<Object> value, TNode<BoolT> writable,
    TNode<BoolT> enumerable, TNode<BoolT> configurable) {
  TNode<NativeContext> native_context = LoadNativeContext(context);
  TNode<Map> map = CAST(LoadContextElement(
      native_context, Context::DATA_PROPERTY_DESCRIPTOR_MAP_INDEX));
  TNode<JSObject> js_desc = AllocateJSObjectFromMap(map);

  StoreObjectFieldNoWriteBarrier(js_desc,
                                 JSDataPropertyDescriptor::kValueOffset, value);
  StoreObjectFieldNoWriteBarrier(js_desc,
                                 JSDataPropertyDescriptor::kWritableOffset,
                                 SelectBooleanConstant(writable));
  StoreObjectFieldNoWriteBarrier(js_desc,
                                 JSDataPropertyDescriptor::kEnumerableOffset,
                                 SelectBooleanConstant(enumerable));
  StoreObjectFieldNoWriteBarrier(js_desc,
                                 JSDataPropertyDescriptor::kConfigurableOffset,
                                 SelectBooleanConstant(configurable));

  return js_desc;
}

TNode<BoolT> ObjectEntriesValuesBuiltinsAssembler::IsPropertyEnumerable(
    TNode<Uint32T> details) {
  TNode<Uint32T> attributes =
      DecodeWord32<PropertyDetails::AttributesField>(details);
  return IsNotSetWord32(attributes, PropertyAttributes::DONT_ENUM);
}

TNode<BoolT> ObjectEntriesValuesBuiltinsAssembler::IsPropertyKindAccessor(
    TNode<Uint32T> kind) {
  return Word32Equal(kind,
                     Int32Constant(static_cast<int>(PropertyKind::kAccessor)));
}

TNode<BoolT> ObjectEntriesValuesBuiltinsAssembler::IsPropertyKindData(
    TNode<Uint32T> kind) {
  return Word32Equal(kind,
                     Int32Constant(static_cast<int>(PropertyKind::kData)));
}

void ObjectEntriesValuesBuiltinsAssembler::GetOwnValuesOrEntries(
    TNode<Context> context, TNode<Object> maybe_object,
    CollectType collect_type) {
  TNode<JSReceiver> receiver = ToObject_Inline(context, maybe_object);

  Label if_call_runtime_with_fast_path(this, Label::kDeferred),
      if_call_runtime(this, Label::kDeferred),
      if_no_properties(this, Label::kDeferred);

  TNode<Map> map = LoadMap(receiver);
  GotoIfNot(IsJSObjectMap(map), &if_call_runtime);
  GotoIfMapHasSlowProperties(map, &if_call_runtime);

  TNode<JSObject> object = CAST(receiver);
  TNode<FixedArrayBase> elements = LoadElements(object);
  // If the object has elements, we treat it as slow case.
  // So, we go to runtime call.
  GotoIfNot(IsEmptyFixedArray(elements), &if_call_runtime_with_fast_path);

  TNode<JSArray> result = FastGetOwnValuesOrEntries(
      context, object, &if_call_runtime_with_fast_path, &if_no_properties,
      collect_type);
  Return(result);

  BIND(&if_no_properties);
  {
    TNode<NativeContext> native_context = LoadNativeContext(context);
    TNode<Map> array_map =
        LoadJSArrayElementsMap(PACKED_ELEMENTS, native_context);
    TNode<JSArray> empty_array = AllocateJSArray(
        PACKED_ELEMENTS, array_map, IntPtrConstant(0), SmiConstant(0));
    Return(empty_array);
  }

  BIND(&if_call_runtime_with_fast_path);
  {
    // In slow case, we simply call runtime.
    if (collect_type == CollectType::kEntries) {
      Return(CallRuntime(Runtime::kObjectEntries, context, object));
    } else {
      DCHECK(collect_type == CollectType::kValues);
      Return(CallRuntime(Runtime::kObjectValues, context, object));
    }
  }

  BIND(&if_call_runtime);
  {
    // In slow case, we simply call runtime.
    if (collect_type == CollectType::kEntries) {
      Return(
          CallRuntime(Runtime::kObjectEntriesSkipFastPath, context, receiver));
    } else {
      DCHECK(collect_type == CollectType::kValues);
      Return(
          CallRuntime(Runtime::kObjectValuesSkipFastPath, context, receiver));
    }
  }
}

TNode<JSArray> ObjectEntriesValuesBuiltinsAssembler::FastGetOwnValuesOrEntries(
    TNode<Context> context, TNode<JSObject> object,
    Label* if_call_runtime_with_fast_path, Label* if_no_properties,
    CollectType collect_type) {
  TNode<NativeContext> native_context = LoadNativeContext(context);
  TNode<Map> array_map =
      LoadJSArrayElementsMap(PACKED_ELEMENTS, native_context);
  TNode<Map> map = LoadMap(object);
  TNode<Uint32T> bit_field3 = LoadMapBitField3(map);

  Label if_has_enum_cache(this), if_not_has_enum_cache(this),
      collect_entries(this);
  TNode<IntPtrT> object_enum_length =
      Signed(DecodeWordFromWord32<Map::Bits3::EnumLengthBits>(bit_field3));
  TNode<BoolT> has_enum_cache = WordNotEqual(
      object_enum_length, IntPtrConstant(kInvalidEnumCacheSentinel));

  // In case, we found enum_cache in object,
  // we use it as array_length because it has same size for
  // Object.(entries/values) result array object length.
  // So object_enum_length use less memory space than
  // NumberOfOwnDescriptorsBits value.
  // And in case, if enum_cache_not_found,
  // we call runtime and initialize enum_cache for subsequent call of
  // CSA fast path.
  Branch(has_enum_cache, &if_has_enum_cache, if_call_runtime_with_fast_path);

  BIND(&if_has_enum_cache);
  {
    GotoIf(WordEqual(object_enum_length, IntPtrConstant(0)), if_no_properties);
    TNode<FixedArray> values_or_entries =
        CAST(AllocateFixedArray(PACKED_ELEMENTS, object_enum_length));

    // If in case we have enum_cache,
    // we can't detect accessor of object until loop through descriptors.
    // So if object might have accessor,
    // we will remain invalid addresses of FixedArray.
    // Because in that case, we need to jump to runtime call.
    // So the array filled by the-hole even if enum_cache exists.
    FillFixedArrayWithValue(PACKED_ELEMENTS, values_or_entries,
                            IntPtrConstant(0), object_enum_length,
                            RootIndex::kTheHoleValue);

    TVARIABLE(IntPtrT, var_result_index, IntPtrConstant(0));
    TVARIABLE(IntPtrT, var_descriptor_number, IntPtrConstant(0));
    // Let desc be ? O.[[GetOwnProperty]](key).
    TNode<DescriptorArray> descriptors = LoadMapDescriptors(map);
    Label loop(this, {&var_descriptor_number, &var_result_index}),
        after_loop(this), next_descriptor(this);
    Branch(IntPtrEqual(var_descriptor_number.value(), object_enum_length),
           &after_loop, &loop);

    // We dont use BuildFastLoop.
    // Instead, we use hand-written loop
    // because of we need to use 'continue' functionality.
    BIND(&loop);
    {
      // Currently, we will not invoke getters,
      // so, map will not be changed.
      CSA_DCHECK(this, TaggedEqual(map, LoadMap(object)));
      TNode<IntPtrT> descriptor_entry = var_descriptor_number.value();
      TNode<Name> next_key =
          LoadKeyByDescriptorEntry(descriptors, descriptor_entry);

      // Skip Symbols.
      GotoIf(IsSymbol(next_key), &next_descriptor);

      TNode<Uint32T> details =
          LoadDetailsByDescriptorEntry(descriptors, descriptor_entry);

      TNode<Uint32T> kind = LoadPropertyKind(details);

      // If property is accessor, we escape fast path and call runtime.
      GotoIf(IsPropertyKindAccessor(kind), if_call_runtime_with_fast_path);
      CSA_DCHECK(this, IsPropertyKindData(kind));

      // If desc is not undefined and desc.[[Enumerable]] is true, then skip to
      // the next descriptor.
      GotoIfNot(IsPropertyEnumerable(details), &next_descriptor);

      TVARIABLE(Object, var_property_value, UndefinedConstant());
      TNode<IntPtrT> descriptor_name_index = ToKeyIndex<DescriptorArray>(
          Unsigned(TruncateIntPtrToInt32(var_descriptor_number.value())));

      // Let value be ? Get(O, key).
      LoadPropertyFromFastObject(object, map, descriptors,
                                 descriptor_name_index, details,
                                 &var_property_value);

      // If kind is "value", append value to properties.
      TNode<Object> value = var_property_value.value();

      if (collect_type == CollectType::kEntries) {
        // Let entry be CreateArrayFromList(« key, value »).
        TNode<JSArray> array;
        TNode<FixedArrayBase> elements;
        std::tie(array, elements) = AllocateUninitializedJSArrayWithElements(
            PACKED_ELEMENTS, array_map, SmiConstant(2), std::nullopt,
            IntPtrConstant(2));
        StoreFixedArrayElement(CAST(elements), 0, next_key, SKIP_WRITE_BARRIER);
        StoreFixedArrayElement(CAST(elements), 1, value, SKIP_WRITE_BARRIER);
        value = array;
      }

      StoreFixedArrayElement(values_or_entries, var_result_index.value(),
                             value);
      Increment(&var_result_index);
      Goto(&next_descriptor);

      BIND(&next_descriptor);
      {
        Increment(&var_descriptor_number);
        Branch(IntPtrEqual(var_result_index.value(), object_enum_length),
               &after_loop, &loop);
      }
    }
    BIND(&after_loop);
    return FinalizeValuesOrEntriesJSArray(context, values_or_entries,
                                          var_result_index.value(), array_map,
                                          if_no_properties);
  }
}

TNode<JSArray>
ObjectEntriesValuesBuiltinsAssembler::FinalizeValuesOrEntriesJSArray(
    TNode<Context> context, TNode<FixedArray> result, TNode<IntPtrT> size,
    TNode<Map> array_map, Label* if_empty) {
  CSA_DCHECK(this, IsJSArrayMap(array_map));

  GotoIf(IntPtrEqual(size, IntPtrConstant(0)), if_empty);
  TNode<JSArray> array = AllocateJSArray(array_map, result, SmiTag(size));
  return array;
}

TF_BUILTIN(ObjectPrototypeHasOwnProperty, ObjectBuiltinsAssembler) {
  auto object = Parameter<Object>(Descriptor::kReceiver);
  auto key = Parameter<Object>(Descriptor::kKey);
  auto context = Parameter<Context>(Descriptor::kContext);

  Label call_runtime(this), return_true(this), return_false(this),
      to_primitive(this);

  // Smi receivers do not have own properties, just perform ToPrimitive on the
  // key.
  Label if_objectisnotsmi(this);
  Branch(TaggedIsSmi(object), &to_primitive, &if_objectisnotsmi);
  BIND(&if_objectisnotsmi);

  TNode<HeapObject> heap_object = CAST(object);

  TNode<Map> map = LoadMap(heap_object);
  TNode<Uint16T> instance_type = LoadMapInstanceType(map);

  {
    TVARIABLE(IntPtrT, var_index);
    TVARIABLE(Name, var_unique);

    Label if_index(this, &var_index), if_unique_name(this),
        if_notunique_name(this);
    TryToName(key, &if_index, &var_index, &if_unique_name, &var_unique,
              &call_runtime, &if_notunique_name);

    BIND(&if_unique_name);
    TryHasOwnProperty(heap_object, map, instance_type, var_unique.value(),
                      &return_true, &return_false, &call_runtime);

    BIND(&if_index);
    {
      TryLookupElement(heap_object, map, instance_type, var_index.value(),
                       &return_true, &return_false, &return_false,
                       &call_runtime);
    }

    BIND(&if_notunique_name);
    {
      Label not_in_string_table(this);
      TryInternalizeString(CAST(key), &if_index, &var_index, &if_unique_name,
                           &var_unique, &not_in_string_table, &call_runtime);

      BIND(&not_in_string_table);
      {
        // If the string was not found in the string table, then no regular
        // object can have a property with that name, so return |false|.
        // "Special API objects" with interceptors must take the slow path.
        Branch(IsSpecialReceiverInstanceType(instance_type), &call_runtime,
               &return_false);
      }
    }
  }
  BIND(&to_primitive);
  GotoIf(IsNumber(key), &return_false);
  Branch(IsName(CAST(key)), &return_false, &call_runtime);

  BIND(&return_true);
  Return(TrueConstant());

  BIND(&return_false);
  Return(FalseConstant());

  BIND(&call_runtime);
  Return(CallRuntime(Runtime::kObjectHasOwnProperty, context, object, key));
}

// ES #sec-object.assign
TF_BUILTIN(ObjectAssign, ObjectBuiltinsAssembler) {
  TNode<IntPtrT> argc = ChangeInt32ToIntPtr(
      UncheckedParameter<Int32T>(Descriptor::kJSActualArgumentsCount));
  CodeStubArguments args(this, argc);

  auto context = Parameter<Context>(Descriptor::kContext);
  TNode<Object> target = args.GetOptionalArgumentValue(0);

  TVARIABLE(IntPtrT, slow_path_index, IntPtrConstant(1));

  // 1. Let to be ? ToObject(target).
  TNode<JSReceiver> to = ToObject_Inline(context, target);

  Label done(this);
  // 2. If only one argument was passed, return to.
  TNode<IntPtrT> args_length = args.GetLengthWithoutReceiver();
  GotoIf(UintPtrLessThanOrEqual(args_length, IntPtrConstant(1)), &done);

  // First let's try a fastpath specifically for when the target objects is an
  // empty object literal.
  // TODO(olivf): For the cases where we could detect that the object literal
  // does not escape in the parser already, we should have a variant of this
  // builtin where the target is not yet allocated at all.
  Label done_fast_path(this), slow_path(this);
  GotoIfForceSlowPath(&slow_path);
  {
    Label fall_through_slow_path(this);

    // First, evaluate the first source object.
    TNode<Object> source = args.GetOptionalArgumentValue(1);
    GotoIf(IsNullOrUndefined(source), &done_fast_path);

    TVARIABLE(IntPtrT, var_result_index, IntPtrConstant(0));
    TNode<JSReceiver> from = ToObject_Inline(context, source);

    TNode<Map> from_map = LoadMap(from);
    // For the fast case we want the source to be a JSObject.
    GotoIfNot(IsJSObjectMap(from_map), &slow_path);

    TNode<Map> to_map = LoadMap(to);

    // Chances that the fast cloning is possible is very low in case source
    // and target maps belong to different native contexts (the only case
    // it'd work is if the |from| object doesn't have enumerable properties)
    // or if one of them is a remote JS object.
    // TODO(olivf): Re-Evaluate this once we have a representation for "no
    // enumerable properties" state in an Object.assign sidestep transition.
    {
      TNode<Map> to_meta_map = LoadMap(to_map);
      GotoIfNot(TaggedEqual(LoadMap(from_map), to_meta_map), &slow_path);

      // For the fast case we want the target to be a fresh empty object
      // literal from current context.
      // TODO(olivf): consider extending the fast path to a case when source
      // and target objects are from the same context but not necessarily from
      // current one.
      TNode<NativeContext> native_context = LoadNativeContext(context);
      TNode<Map> empty_object_literal_map =
          LoadObjectFunctionInitialMap(native_context);
      GotoIfNot(TaggedEqual(to_map, empty_object_literal_map), &slow_path);
      // Double-check that the meta map is not contextless.
      CSA_DCHECK(this,
                 TaggedEqual(native_context,
                             LoadMapConstructorOrBackPointerOrNativeContext(
                                 to_meta_map)));
    }

    // Chances are very slim that cloning is possible if we have different
    // instance sizes.
    // TODO(olivf): Re-Evaluate this once we have a faster target map lookup
    // that does not need to go through the runtime.
    TNode<IntPtrT> from_inst_size = LoadMapInstanceSizeInWords(from_map);
    TNode<IntPtrT> to_inst_size = LoadMapInstanceSizeInWords(to_map);
    GotoIfNot(IntPtrEqual(from_inst_size, to_inst_size), &slow_path);

    // Both source and target should be in fastmode, not a prototype and not
    // deprecated.
    constexpr uint32_t field3_exclusion_mask =
        Map::Bits3::IsDictionaryMapBit::kMask |
        Map::Bits3::IsDeprecatedBit::kMask |
        Map::Bits3::IsPrototypeMapBit::kMask;

    // Ensure the target is empty and extensible and has none of the exclusion
    // bits set.
    TNode<Uint32T> target_field3 = LoadMapBitField3(to_map);
    TNode<Uint32T> field3_descriptors_and_extensible_mask = Uint32Constant(
        Map::Bits3::NumberOfOwnDescriptorsBits::kMask |
        Map::Bits3::IsExtensibleBit::kMask | field3_exclusion_mask);
    // If the masked field3 equals the extensible bit, then the number of
    // descriptors was 0 -- which is what we need here.
    GotoIfNot(
        Word32Equal(
            Uint32Constant(Map::Bits3::IsExtensibleBit::encode(true)),
            Word32And(target_field3, field3_descriptors_and_extensible_mask)),
        &slow_path);

    // Check that the source is in fastmode, not a prototype and not deprecated.
    TNode<Uint32T> source_field3 = LoadMapBitField3(from_map);
    TNode<Uint32T> field3_exclusion_mask_const =
        Uint32Constant(field3_exclusion_mask);
    GotoIfNot(
        Word32Equal(Uint32Constant(0),
                    Word32And(source_field3, field3_exclusion_mask_const)),
        &slow_path);
    CSA_DCHECK(this, Word32BinaryNot(IsElementsKindInRange(
                         LoadElementsKind(to_map),
                         FIRST_ANY_NONEXTENSIBLE_ELEMENTS_KIND,
                         LAST_ANY_NONEXTENSIBLE_ELEMENTS_KIND)));

    // TODO(olivf): We could support the case when the `to` has elements, but
    // the source doesn't. But there is a danger of then caching an invalid
    // transition when the converse happens later.
    GotoIfNot(TaggedEqual(LoadElements(CAST(to)), EmptyFixedArrayConstant()),
              &slow_path);

    Label continue_fast_path(this), runtime_map_lookup(this, Label::kDeferred);

    // Check if our particular source->target combination is fast clonable.
    // E.g., this ensures that we only have fast properties and in general that
    // the binary layout is compatible for `FastCloneJSObject`.
    // If such a clone map exists then it can be found in the transition array
    // with object_assign_clone_transition_symbol as a key. If this transition
    // slot is cleared, then the map is not clonable. If the key is missing
    // from the transitions we rely on the runtime function
    // ObjectAssignTryFastcase that does the actual computation.
    TVARIABLE(Map, clone_map);
    {
      // First check if we have a transition array.
      TNode<MaybeObject> maybe_transitions = LoadMaybeWeakObjectField(
          from_map, Map::kTransitionsOrPrototypeInfoOffset);
      TNode<HeapObject> maybe_transitions2 =
          GetHeapObjectIfStrong(maybe_transitions, &runtime_map_lookup);
      GotoIfNot(IsTransitionArrayMap(LoadMap(maybe_transitions2)),
                &runtime_map_lookup);
      TNode<WeakFixedArray> transitions = CAST(maybe_transitions2);
      TNode<Object> side_step_transitions = CAST(LoadWeakFixedArrayElement(
          transitions,
          IntPtrConstant(TransitionArray::kSideStepTransitionsIndex)));
      GotoIf(TaggedIsSmi(side_step_transitions), &runtime_map_lookup);
      TNode<MaybeObject> maybe_target_map = LoadWeakFixedArrayElement(
          CAST(side_step_transitions),
          IntPtrConstant(SideStepTransition::index_of(
              SideStepTransition::Kind::kObjectAssign)));
      GotoIf(TaggedEqual(maybe_target_map,
                         SmiConstant(SideStepTransition::Unreachable)),
             &slow_path);
      GotoIf(
          TaggedEqual(maybe_target_map, SmiConstant(SideStepTransition::Empty)),
          &runtime_map_lookup);
      TNode<Map> target_map =
          CAST(GetHeapObjectAssumeWeak(maybe_target_map, &runtime_map_lookup));
      GotoIf(IsDeprecatedMap(target_map), &runtime_map_lookup);
      TNode<MaybeObject> maybe_validity_cell = LoadWeakFixedArrayElement(
          CAST(side_step_transitions),
          IntPtrConstant(SideStepTransition::index_of(
              SideStepTransition::Kind::kObjectAssignValidityCell)));
      TNode<Cell> validity_cell = CAST(
          GetHeapObjectAssumeWeak(maybe_validity_cell, &runtime_map_lookup));
      GotoIfNot(TaggedEqual(LoadCellValue(validity_cell),
                            SmiConstant(Map::kPrototypeChainValid)),
                &runtime_map_lookup);
      clone_map = target_map;
    }
    Goto(&continue_fast_path);

    BIND(&runtime_map_lookup);
    TNode<HeapObject> maybe_clone_map =
        CAST(CallRuntime(Runtime::kObjectAssignTryFastcase, context, from, to));
    GotoIf(TaggedEqual(maybe_clone_map, UndefinedConstant()), &slow_path);
    GotoIf(TaggedEqual(maybe_clone_map, TrueConstant()), &done_fast_path);
    CSA_DCHECK(this, IsMap(maybe_clone_map));
    clone_map = CAST(maybe_clone_map);
    Goto(&continue_fast_path);

    BIND(&continue_fast_path);
    CSA_DCHECK(this,
               IntPtrEqual(LoadMapInstanceSizeInWords(to_map),
                           LoadMapInstanceSizeInWords(clone_map.value())));
    CSA_DCHECK(
        this,
        IntPtrEqual(LoadMapInobjectPropertiesStartInWords(to_map),
                    LoadMapInobjectPropertiesStartInWords(clone_map.value())));
    FastCloneJSObject(
        from, from_map, clone_map.value(),
        [&](TNode<Map> map, TNode<HeapObject> properties,
            TNode<FixedArray> elements) {
          StoreMap(to, clone_map.value());
          StoreJSReceiverPropertiesOrHash(to, properties);
          StoreJSObjectElements(CAST(to), elements);
          return to;
        },
        false /* target_is_new */);

    Goto(&done_fast_path);
    BIND(&done_fast_path);

    // If the fast path above succeeded we must skip assigning the first source
    // object in the generic implementation below.
    slow_path_index = IntPtrConstant(2);
    Branch(IntPtrGreaterThan(args_length, IntPtrConstant(2)), &slow_path,
           &done);
  }
  BIND(&slow_path);

  // 3. Let sources be the List of argument values starting with the
  //    second argument.
  // 4. For each element nextSource of sources, in ascending index order,
  {
    args.ForEach(
        [=, this](TNode<Object> next_source) {
          CallBuiltin(Builtin::kSetDataProperties, context, to, next_source);
        },
        slow_path_index.value());
    Goto(&done);
  }

  // 5. Return to.
  BIND(&done);
  args.PopAndReturn(to);
}

// ES #sec-object.keys
TF_BUILTIN(ObjectKeys, ObjectBuiltinsAssembler) {
  auto object = Parameter<Object>(Descriptor::kObject);
  auto context = Parameter<Context>(Descriptor::kContext);

  TVARIABLE(Smi, var_length);
  TVARIABLE(FixedArrayBase, var_elements);
  Label if_empty(this, Label::kDeferred), if_empty_elements(this),
      if_fast(this), if_slow(this, Label::kDeferred), if_join(this);

  // Check if the {object} has a usable enum cache.
  GotoIf(TaggedIsSmi(object), &if_slow);

  TNode<Map> object_map = LoadMap(CAST(object));
  TNode<Uint32T> object_bit_field3 = LoadMapBitField3(object_map);
  TNode<UintPtrT> object_enum_length =
      DecodeWordFromWord32<Map::Bits3::EnumLengthBits>(object_bit_field3);
  GotoIf(
      WordEqual(object_enum_length, IntPtrConstant(kInvalidEnumCacheSentinel)),
      &if_slow);

  // Ensure that the {object} doesn't have any elements.
  CSA_DCHECK(this, IsJSObjectMap(object_map));
  TNode<FixedArrayBase> object_elements = LoadElements(CAST(object));
  GotoIf(IsEmptyFixedArray(object_elements), &if_empty_elements);
  Branch(IsEmptySlowElementDictionary(object_elements), &if_empty_elements,
         &if_slow);

  // Check whether there are enumerable properties.
  BIND(&if_empty_elements);
  Branch(WordEqual(object_enum_length, IntPtrConstant(0)), &if_empty, &if_fast);

  // TODO(solanes): These if_xxx here and below seem to be quite similar for
  // ObjectKeys and for ObjectGetOwnPropertyNames. In particular, if_fast seem
  // to be the exact same.
  BIND(&if_fast);
  {
    // The {object} has a usable enum cache, use that.
    TNode<DescriptorArray> object_descriptors = LoadMapDescriptors(object_map);
    TNode<EnumCache> object_enum_cache = LoadObjectField<EnumCache>(
        object_descriptors, DescriptorArray::kEnumCacheOffset);
    auto object_enum_keys = LoadObjectField<FixedArrayBase>(
        object_enum_cache, EnumCache::kKeysOffset);

    // Allocate a JSArray and copy the elements from the {object_enum_keys}.
    TNode<JSArray> array;
    TNode<FixedArrayBase> elements;
    TNode<NativeContext> native_context = LoadNativeContext(context);
    TNode<Map> array_map =
        LoadJSArrayElementsMap(PACKED_ELEMENTS, native_context);
    TNode<IntPtrT> object_enum_length_intptr = Signed(object_enum_length);
    TNode<Smi> array_length = SmiTag(object_enum_length_intptr);
    std::tie(array, elements) = AllocateUninitializedJSArrayWithElements(
        PACKED_ELEMENTS, array_map, array_length, std::nullopt,
        object_enum_length_intptr);
    CopyFixedArrayElements(PACKED_ELEMENTS, object_enum_keys, elements,
                           object_enum_length_intptr, SKIP_WRITE_BARRIER);
    Return(array);
  }

  BIND(&if_empty);
  {
    // The {object} doesn't have any enumerable keys.
    var_length = SmiConstant(0);
    var_elements = EmptyFixedArrayConstant();
    Goto(&if_join);
  }

  BIND(&if_slow);
  {
    // Let the runtime compute the elements.
    TNode<FixedArray> elements =
        CAST(CallRuntime(Runtime::kObjectKeys, context, object));
    var_length = LoadObjectField<Smi>(elements, offsetof(FixedArray, length_));
    var_elements = elements;
    Goto(&if_join);
  }

  BIND(&if_join);
  {
    // Wrap the elements into a proper JSArray and return that.
    TNode<NativeContext> native_context = LoadNativeContext(context);
    TNode<Map> array_map =
        LoadJSArrayElementsMap(PACKED_ELEMENTS, native_context);
    TNode<JSArray> array =
        AllocateJSArray(array_map, var_elements.value(), var_length.value());
    Return(array);
  }
}

// https://github.com/tc39/proposal-accessible-object-hasownproperty
TF_BUILTIN(ObjectHasOwn, ObjectBuiltinsAssembler) {
  // Object.prototype.hasOwnProperty()
  // 1. Let obj be ? ToObject(O).
  // 2. Let key be ? ToPropertyKey(P).
  // 3. Return ? HasOwnProperty(obj, key).
  //
  // ObjectPrototypeHasOwnProperty has similar semantics with steps 1 and 2
  // swapped. We check if ToObject can fail and delegate the rest of the
  // execution to ObjectPrototypeHasOwnProperty.

  auto target = Parameter<Object>(Descriptor::kJSTarget);
  auto new_target = Parameter<Object>(Descriptor::kJSNewTarget);
  auto object = Parameter<Object>(Descriptor::kObject);
  auto key = Parameter<Object>(Descriptor::kKey);
  auto context = Parameter<Context>(Descriptor::kContext);

  // ToObject can only fail when object is undefined or null.
  Label undefined_or_null(this), not_undefined_nor_null(this);
  Branch(IsNullOrUndefined(object), &undefined_or_null,
         &not_undefined_nor_null);

  BIND(&undefined_or_null);
  ThrowTypeError(context, MessageTemplate::kUndefinedOrNullToObject);

  BIND(&not_undefined_nor_null);
  Return(CallJSBuiltin(Builtin::kObjectPrototypeHasOwnProperty, context, target,
                       new_target, object, key));
}

// ES #sec-object.getOwnPropertyNames
TF_BUILTIN(ObjectGetOwnPropertyNames, ObjectBuiltinsAssembler) {
  auto object = Parameter<Object>(Descriptor::kObject);
  auto context = Parameter<Context>(Descriptor::kContext);

  TVARIABLE(Smi, var_length);
  TVARIABLE(FixedArrayBase, var_elements);
  Label if_empty(this, Label::kDeferred), if_empty_elements(this),
      if_fast(this), try_fast(this, Label::kDeferred),
      if_slow(this, Label::kDeferred), if_join(this);

  // Take the slow path if the {object} IsCustomElementsReceiverInstanceType or
  // has any elements.
  GotoIf(TaggedIsSmi(object), &if_slow);

  TNode<Map> object_map = LoadMap(CAST(object));
  TNode<Uint16T> instance_type = LoadMapInstanceType(object_map);
  GotoIf(IsCustomElementsReceiverInstanceType(instance_type), &if_slow);
  TNode<FixedArrayBase> object_elements = LoadElements(CAST(object));
  GotoIf(IsEmptyFixedArray(object_elements), &if_empty_elements);
  Branch(IsEmptySlowElementDictionary(object_elements), &if_empty_elements,
         &if_slow);

  // Check if the {object} has a usable enum cache.
  BIND(&if_empty_elements);
  TNode<Uint32T> object_bit_field3 = LoadMapBitField3(object_map);
  TNode<UintPtrT> object_enum_length =
      DecodeWordFromWord32<Map::Bits3::EnumLengthBits>(object_bit_field3);
  GotoIf(
      WordEqual(object_enum_length, IntPtrConstant(kInvalidEnumCacheSentinel)),
      &try_fast);

  // Check whether all own properties are enumerable.
  TNode<UintPtrT> number_descriptors =
      DecodeWordFromWord32<Map::Bits3::NumberOfOwnDescriptorsBits>(
          object_bit_field3);
  GotoIfNot(WordEqual(object_enum_length, number_descriptors), &if_slow);

  // Check whether there are enumerable properties.
  Branch(WordEqual(object_enum_length, IntPtrConstant(0)), &if_empty, &if_fast);

  // TODO(solanes): These if_xxx here and below seem to be quite similar for
  // ObjectKeys and for ObjectGetOwnPropertyNames. In particular, if_fast seem
  // to be the exact same.
  BIND(&if_fast);
  {
    // The {object} has a usable enum cache and all own properties are
    // enumerable, use that.
    TNode<DescriptorArray> object_descriptors = LoadMapDescriptors(object_map);
    TNode<EnumCache> object_enum_cache = LoadObjectField<EnumCache>(
        object_descriptors, DescriptorArray::kEnumCacheOffset);
    auto object_enum_keys = LoadObjectField<FixedArrayBase>(
        object_enum_cache, EnumCache::kKeysOffset);

    // Allocate a JSArray and copy the elements from the {object_enum_keys}.
    TNode<JSArray> array;
    TNode<FixedArrayBase> elements;
    TNode<NativeContext> native_context = LoadNativeContext(context);
    TNode<
"""


```