Response:
The user wants a summary of the functionalities provided by the given C++ code snippet from `v8/src/runtime/runtime-object.cc`.

Here's a breakdown of how to approach this:

1. **Identify the file type:** The prompt explicitly states that if the file ended with `.tq`, it would be a Torque file. Since it ends with `.cc`, it's a regular C++ source file. This means it contains implementations of runtime functions.

2. **Recognize the purpose of `v8/src/runtime`:** Files in this directory implement the core functionalities that are exposed to JavaScript. These are often the "guts" behind built-in JavaScript features.

3. **Iterate through the `RUNTIME_FUNCTION` definitions:** Each `RUNTIME_FUNCTION` likely corresponds to a specific JavaScript operation or a lower-level utility function used by the engine. We need to understand what each of these functions does.

4. **Look for relationships to JavaScript:** For each function, determine if it directly corresponds to a JavaScript API or a concept used in JavaScript.

5. **Identify potential programming errors:** Based on the function's behavior, think about common mistakes developers might make that would lead to these runtime functions being called.

6. **Infer code logic (if applicable):** Some functions might perform simple logical operations (e.g., checking for property existence). If so, consider basic input/output scenarios.

7. **Group functionalities:**  Organize the identified functions into logical groups based on the types of operations they perform (e.g., property access, object creation, etc.).

8. **Formulate a summary:**  Combine the identified functionalities into a concise summary.

Let's go through the code and apply these steps:

*   **`GetObjectProperty`**: Gets a property of an object. Relates to JavaScript property access.
*   **`HasProperty`**: Checks if an object has a property. Relates to the `in` operator and `hasOwnProperty`.
*   **`DeleteObjectProperty`**: Deletes a property from an object. Relates to the `delete` operator.
*   **`Runtime_ObjectKeys`**: Implements `Object.keys()`.
*   **`Runtime_ObjectGetOwnPropertyNames`**: Implements `Object.getOwnPropertyNames()`.
*   **`Runtime_ObjectGetOwnPropertyNamesTryFast`**: Seems like an optimized version of `Object.getOwnPropertyNames()`.
*   **`Runtime_ObjectHasOwnProperty`**: Implements `Object.hasOwnProperty()`.
*   **`Runtime_HasOwnConstDataProperty`**: Checks if an object has a constant own data property. More internal, but relates to property characteristics.
*   **`Runtime_IsDictPropertyConstTrackingEnabled`**: Likely a debug/internal setting.
*   **`Runtime_AddDictionaryProperty`**: Adds a property to an object's dictionary (internal representation).
*   **`Runtime_AddPrivateBrand`**: Manages private class fields/methods.
*   **`Runtime_ObjectCreate`**: Implements `Object.create()`.
*   **`SetObjectProperty`**: Sets a property on an object. Relates to assignment.
*   **`DefineObjectOwnProperty`**: Implements `Object.defineProperty()`.
*   **`Runtime_InternalSetPrototype`**: Sets the internal prototype of an object. Relates to `Object.setPrototypeOf()` and `__proto__`.
*   **`Runtime_OptimizeObjectForAddingMultipleProperties`**: An optimization hint.
*   **`Runtime_ObjectValues`**: Implements `Object.values()`.
*   **`Runtime_ObjectValuesSkipFastPath`**:  Likely a non-optimized version for testing or specific scenarios.
*   **`Runtime_ObjectEntries`**: Implements `Object.entries()`.
*   **`Runtime_ObjectEntriesSkipFastPath`**: Likely a non-optimized version.
*   **`Runtime_ObjectIsExtensible`**: Implements `Object.isExtensible()`.
*   **`Runtime_JSReceiverPreventExtensionsThrow`**: Implements `Object.preventExtensions()`, throwing on failure.
*   **`Runtime_JSReceiverPreventExtensionsDontThrow`**: Implements `Object.preventExtensions()`, not throwing on failure.
*   **`Runtime_JSReceiverGetPrototypeOf`**: Implements `Object.getPrototypeOf()`.
*   **`Runtime_JSReceiverSetPrototypeOfThrow`**: Implements `Object.setPrototypeOf()`, throwing on failure.
*   **`Runtime_JSReceiverSetPrototypeOfDontThrow`**: Implements `Object.setPrototypeOf()`, not throwing on failure.
*   **`Runtime_GetProperty`**: Another entry point for getting properties, possibly optimized.
*   **`Runtime_SetKeyedProperty`**: Sets a property using bracket notation (e.g., `obj[key] = value`).
*   **`Runtime_DefineObjectOwnProperty`**:  Another entry point for defining own properties.
*   **`Runtime_SetNamedProperty`**: Sets a property using dot notation (e.g., `obj.key = value`).
*   **`DeleteProperty` (internal function):**  Core logic for deleting properties.
*   **`Runtime_DeleteProperty`**:  Exposes the `DeleteProperty` logic to the runtime.
*   **`Runtime_ShrinkNameDictionary`**: Internal function for optimizing object property storage.
*   **`Runtime_ShrinkSwissNameDictionary`**:  Similar optimization, likely for a different dictionary implementation.
*   **`Runtime_HasProperty`**: Another entry point for checking property existence.
*   **`Runtime_GetOwnPropertyKeys`**: More general version of getting own property keys with filtering.
*   **`Runtime_ToFastProperties`**: Forces an object to use a faster property storage mechanism.
*   **`Runtime_AllocateHeapNumber`**:  Allocates a `HeapNumber` object (V8's representation of numbers).
*   **`Runtime_NewObject`**: Creates a new object using a constructor.
*   **`Runtime_GetDerivedMap`**:  Used in class inheritance to get the appropriate map for derived classes.

Now, let's synthesize the summary.
```cpp
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/base/macros.h"
#include "src/builtins/builtins.h"
#include "src/common/globals.h"
#include "src/common/message-template.h"
#include "src/execution/arguments-inl.h"
#include "src/execution/frames.h"
#include "src/execution/isolate-inl.h"
#include "src/execution/messages.h"
#include "src/handles/maybe-handles.h"
#include "src/heap/heap-inl.h"  // For ToBoolean. TODO(jkummerow): Drop.
#include "src/objects/map-updater.h"
#include "src/objects/property-descriptor-object.h"
#include "src/objects/property-descriptor.h"
#include "src/objects/property-details.h"
#include "src/objects/swiss-name-dictionary-inl.h"
#include "src/runtime/runtime.h"

namespace v8 {
namespace internal {

MaybeHandle<Object> Runtime::GetObjectProperty(
    Isolate* isolate, Handle<JSAny> lookup_start_object, Handle<Object> key,
    Handle<JSAny> receiver, bool* is_found) {
  // ... implementation ...
}

MaybeHandle<Object> Runtime::HasProperty(Isolate* isolate,
                                         Handle<Object> object,
                                         Handle<Object> key) {
  // ... implementation ...
}

Maybe<bool> Runtime::DeleteObjectProperty(Isolate* isolate,
                                          Handle<JSReceiver> receiver,
                                          Handle<Object> key,
                                          LanguageMode language_mode) {
  // ... implementation ...
}

// ES #sec-object.keys
RUNTIME_FUNCTION(Runtime_ObjectKeys) {
  // ... implementation ...
}

// ES #sec-object.getOwnPropertyNames
RUNTIME_FUNCTION(Runtime_ObjectGetOwnPropertyNames) {
  // ... implementation ...
}

RUNTIME_FUNCTION(Runtime_ObjectGetOwnPropertyNamesTryFast) {
  // ... implementation ...
}

// ES6 19.1.3.2
RUNTIME_FUNCTION(Runtime_ObjectHasOwnProperty) {
  // ... implementation ...
}

RUNTIME_FUNCTION(Runtime_HasOwnConstDataProperty) {
  // ... implementation ...
}

RUNTIME_FUNCTION(Runtime_IsDictPropertyConstTrackingEnabled) {
  // ... implementation ...
}

RUNTIME_FUNCTION(Runtime_AddDictionaryProperty) {
  // ... implementation ...
}

RUNTIME_FUNCTION(Runtime_AddPrivateBrand) {
  // ... implementation ...
}

// ES6 section 19.1.2.2 Object.create ( O [ , Properties ] )
// TODO(verwaest): Support the common cases with precached map directly in
// an Object.create stub.
RUNTIME_FUNCTION(Runtime_ObjectCreate) {
  // ... implementation ...
}

MaybeHandle<Object> Runtime::SetObjectProperty(
    Isolate* isolate, Handle<JSAny> lookup_start_obj, Handle<Object> key,
    Handle<Object> value, MaybeHandle<JSAny> maybe_receiver,
    StoreOrigin store_origin, Maybe<ShouldThrow> should_throw) {
  // ... implementation ...
}

MaybeHandle<Object> Runtime::SetObjectProperty(
    Isolate* isolate, Handle<JSAny> object, Handle<Object> key,
    Handle<Object> value, StoreOrigin store_origin,
    Maybe<ShouldThrow> should_throw) {
  return SetObjectProperty(isolate, object, key, value, object, store_origin,
                           should_throw);
}

MaybeHandle<Object> Runtime::DefineObjectOwnProperty(Isolate* isolate,
                                                     Handle<JSAny> object,
                                                     Handle<Object> key,
                                                     Handle<Object> value,
                                                     StoreOrigin store_origin) {
  // ... implementation ...
}

RUNTIME_FUNCTION(Runtime_InternalSetPrototype) {
  // ... implementation ...
}

RUNTIME_FUNCTION(Runtime_OptimizeObjectForAddingMultipleProperties) {
  // ... implementation ...
}

RUNTIME_FUNCTION(Runtime_ObjectValues) {
  // ... implementation ...
}

RUNTIME_FUNCTION(Runtime_ObjectValuesSkipFastPath) {
  // ... implementation ...
}

RUNTIME_FUNCTION(Runtime_ObjectEntries) {
  // ... implementation ...
}

RUNTIME_FUNCTION(Runtime_ObjectEntriesSkipFastPath) {
  // ... implementation ...
}

RUNTIME_FUNCTION(Runtime_ObjectIsExtensible) {
  // ... implementation ...
}

RUNTIME_FUNCTION(Runtime_JSReceiverPreventExtensionsThrow) {
  // ... implementation ...
}

RUNTIME_FUNCTION(Runtime_JSReceiverPreventExtensionsDontThrow) {
  // ... implementation ...
}

RUNTIME_FUNCTION(Runtime_JSReceiverGetPrototypeOf) {
  // ... implementation ...
}

RUNTIME_FUNCTION(Runtime_JSReceiverSetPrototypeOfThrow) {
  // ... implementation ...
}

RUNTIME_FUNCTION(Runtime_JSReceiverSetPrototypeOfDontThrow) {
  // ... implementation ...
}

RUNTIME_FUNCTION(Runtime_GetProperty) {
  // ... implementation ...
}

RUNTIME_FUNCTION(Runtime_SetKeyedProperty) {
  // ... implementation ...
}

RUNTIME_FUNCTION(Runtime_DefineObjectOwnProperty) {
  // ... implementation ...
}

RUNTIME_FUNCTION(Runtime_SetNamedProperty) {
  // ... implementation ...
}

namespace {

// ES6 section 12.5.4.
Tagged<Object> DeleteProperty(Isolate* isolate, Handle<Object> object,
                              Handle<Object> key, LanguageMode language_mode) {
  // ... implementation ...
}

}  // namespace

RUNTIME_FUNCTION(Runtime_DeleteProperty) {
  // ... implementation ...
}

RUNTIME_FUNCTION(Runtime_ShrinkNameDictionary) {
  // ... implementation ...
}

RUNTIME_FUNCTION(Runtime_ShrinkSwissNameDictionary) {
  // ... implementation ...
}

// ES6 section 12.9.3, operator in.
RUNTIME_FUNCTION(Runtime_HasProperty) {
  // ... implementation ...
}

RUNTIME_FUNCTION(Runtime_GetOwnPropertyKeys) {
  // ... implementation ...
}

RUNTIME_FUNCTION(Runtime_ToFastProperties) {
  // ... implementation ...
}

RUNTIME_FUNCTION(Runtime_AllocateHeapNumber) {
  // ... implementation ...
}

RUNTIME_FUNCTION(Runtime_NewObject) {
  // ... implementation ...
}

RUNTIME_FUNCTION(Runtime_GetDerivedMap) {
  // ... implementation ...
}

}  // namespace internal
}  // namespace v8
```

## 功能归纳：

`v8/src/runtime/runtime-object.cc` 是 V8 JavaScript 引擎中的一个 C++ 源代码文件。它定义了**运行时 (Runtime)** 中与 **对象 (Object)** 操作相关的各种函数。这些运行时函数是 V8 引擎内部使用的，用于实现 JavaScript 语言中与对象相关的 built-in 功能和操作。

**具体功能可以归纳为以下几个方面：**

1. **属性访问和操作:**
    *   获取对象属性 (`GetObjectProperty`, `Runtime_GetProperty`).
    *   检查对象是否拥有某个属性 (`HasProperty`, `Runtime_HasProperty`, `Runtime_ObjectHasOwnProperty`, `Runtime_HasOwnConstDataProperty`).
    *   设置对象属性 (`SetObjectProperty`, `Runtime_SetKeyedProperty`, `Runtime_SetNamedProperty`).
    *   定义对象自身的属性 (`DefineObjectOwnProperty`, `Runtime_DefineObjectOwnProperty`).
    *   删除对象属性 (`DeleteObjectProperty`, `Runtime_DeleteProperty`).

2. **对象属性枚举:**
    *   获取对象的可枚举属性键 (`Runtime_ObjectKeys`).
    *   获取对象自身的所有属性键（包括不可枚举的） (`Runtime_ObjectGetOwnPropertyNames`, `Runtime_ObjectGetOwnPropertyNamesTryFast`, `Runtime_GetOwnPropertyKeys`).
    *   获取对象自身的可枚举属性值 (`Runtime_ObjectValues`, `Runtime_ObjectValuesSkipFastPath`).
    *   获取对象自身的可枚举属性的键值对 (`Runtime_ObjectEntries`, `Runtime_ObjectEntriesSkipFastPath`).

3. **对象创建和原型操作:**
    *   创建新对象 (`Runtime_ObjectCreate`, `Runtime_NewObject`).
    *   获取对象的原型 (`Runtime_JSReceiverGetPrototypeOf`).
    *   设置对象的原型 (`Runtime_InternalSetPrototype`, `Runtime_JSReceiverSetPrototypeOfThrow`, `Runtime_JSReceiverSetPrototypeOfDontThrow`).

4. **对象扩展性控制:**
    *   检查对象是否可扩展 (`Runtime_ObjectIsExtensible`).
    *   阻止对象的扩展 (`Runtime_JSReceiverPreventExtensionsThrow`, `Runtime_JSReceiverPreventExtensionsDontThrow`).

5. **内部优化和管理:**
    *   优化对象以添加多个属性 (`Runtime_OptimizeObjectForAddingMultipleProperties`).
    *   将对象的属性存储转换为快速模式 (`Runtime_ToFastProperties`).
    *   收缩对象的属性字典以节省内存 (`Runtime_ShrinkNameDictionary`, `Runtime_ShrinkSwissNameDictionary`).
    *   添加私有品牌（用于 private class members） (`Runtime_AddPrivateBrand`).
    *   添加字典属性 (`Runtime_AddDictionaryProperty`).

6. **其他:**
    *   分配堆数字 (`Runtime_AllocateHeapNumber`).
    *   获取派生类的 Map (`Runtime_GetDerivedMap`).
    *   检查是否启用了字典属性的常量跟踪 (`Runtime_IsDictPropertyConstTrackingEnabled`).

**关于源代码类型和 JavaScript 关系：**

*   该文件 `v8/src/runtime/runtime-object.cc` 以 `.cc` 结尾，因此它是一个 **V8 C++ 源代码文件**，而不是 Torque 源代码。
*   该文件中的函数与 JavaScript 的功能有密切关系，因为它实现了 JavaScript 中与对象相关的核心操作。

**JavaScript 示例：**

以下是一些 JavaScript 例子，展示了 `v8/src/runtime/runtime-object.cc` 中实现的运行时函数背后的 JavaScript 功能：

```javascript
const obj = { a: 1, b: 2 };

// Runtime_ObjectKeys
console.log(Object.keys(obj)); // 输出: ['a', 'b']

// Runtime_ObjectGetOwnPropertyNames
console.log(Object.getOwnPropertyNames(obj)); // 输出: ['a', 'b']

// Runtime_ObjectHasOwnProperty
console.log(obj.hasOwnProperty('a')); // 输出: true

// Runtime_ObjectCreate
const newObj = Object.create(obj);
console.log(newObj.__proto__ === obj); // 输出: true

// SetObjectProperty (例如通过赋值)
obj.c = 3;
console.log(obj.c); // 输出: 3

// DefineObjectOwnProperty
Object.defineProperty(obj, 'd', { value: 4, enumerable: false });
console.log(obj.d); // 输出: 4
console.log(Object.keys(obj)); // 输出: ['a', 'b', 'c'] (因为 'd' 不可枚举)

// Runtime_ObjectValues
console.log(Object.values(obj)); // 输出: [1, 2, 3]

// Runtime_ObjectEntries
console.log(Object.entries(obj)); // 输出: [['a', 1], ['b', 2], ['c', 3]]

// Runtime_ObjectIsExtensible
console.log(Object.isExtensible(obj)); // 输出: true

// Runtime_JSReceiverPreventExtensionsThrow
Object.preventExtensions(obj);
console.log(Object.isExtensible(obj)); // 输出: false

// Runtime_JSReceiverGetPrototypeOf
console.log(Object.getPrototypeOf(newObj) === obj); // 输出: true

// Runtime_JSReceiverSetPrototypeOfThrow
const anotherObj = {};
Object.setPrototypeOf(anotherObj, obj);
console.log(Object.getPrototypeOf(anotherObj) === obj); // 输出: true

// GetObjectProperty (例如通过属性访问)
console.log(obj.a); // 输出: 1

// HasProperty (例如通过 in 操作符)
console.log('a' in obj); // 输出: true

// DeleteProperty
delete obj.a;
console.log(obj.a); // 输出: undefined
```

**假设输入与输出 (代码逻辑推理):**

以 `GetObjectProperty` 为例：

**假设输入：**

*   `isolate`: 当前 V8 隔离区
*   `lookup_start_object`: 一个 JavaScript 对象，例如 `{ x: 10 }`
*   `key`:  一个表示属性名的字符串或 Symbol，例如 `"x"`
*   `receiver`:  接收者对象，通常与 `lookup_start_object` 相同，例如 `{ x: 10 }`
*   `is_found`: 一个指向布尔变量的指针

**可能输出：**

*   如果找到属性，则返回一个 `MaybeHandle<Object>`，其中包含属性的值（在这个例子中是 `10`）。`is_found` 指向的布尔变量会被设置为 `true`。
*   如果未找到属性，则返回一个空的 `MaybeHandle<Object>()`。`is_found` 指向的布尔变量会被设置为 `false`。
*   如果发生错误（例如，在 `null` 或 `undefined` 上查找属性），则会抛出异常，并返回一个空的 `MaybeHandle<Object>()`。

**用户常见的编程错误举例：**

1. **在 `null` 或 `undefined` 上访问属性:**

    ```javascript
    let obj = null;
    console.log(obj.a); // TypeError: Cannot read properties of null (reading 'a')
    ```

    `GetObjectProperty` 函数会处理这种情况并抛出 `TypeError`。

2. **使用 `delete` 操作符删除不可删除的属性：**

    ```javascript
    const obj = {};
    Object.defineProperty(obj, 'prop', { value: 1, configurable: false });
    delete obj.prop; // 在严格模式下会抛出 TypeError，非严格模式下删除失败但不会报错
    console.log(obj.prop); // 输出: 1
    ```

    `DeleteObjectProperty` 函数会根据语言模式 (严格模式或非严格模式) 返回不同的结果或抛出错误。

3. **错误地使用 `Object.setPrototypeOf` 更改对象的原型：**

    ```javascript
    const obj1 = {};
    const obj2 = {};
    Object.setPrototypeOf(obj1, obj2);
    Object.setPrototypeOf(obj1, null); // 可能导致意外行为或错误
    ```

    `Runtime_JSReceiverSetPrototypeOfThrow` 和 `Runtime_JSReceiverSetPrototypeOfDontThrow` 函数实现了 `Object.setPrototypeOf` 的逻辑，并处理诸如循环原型链等错误情况。

这是对 `v8/src/runtime/runtime-object.cc` 文件功能的初步归纳。更深入的理解需要分析每个函数的具体实现细节。

### 提示词
```
这是目录为v8/src/runtime/runtime-object.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/runtime/runtime-object.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/base/macros.h"
#include "src/builtins/builtins.h"
#include "src/common/globals.h"
#include "src/common/message-template.h"
#include "src/execution/arguments-inl.h"
#include "src/execution/frames.h"
#include "src/execution/isolate-inl.h"
#include "src/execution/messages.h"
#include "src/handles/maybe-handles.h"
#include "src/heap/heap-inl.h"  // For ToBoolean. TODO(jkummerow): Drop.
#include "src/objects/map-updater.h"
#include "src/objects/property-descriptor-object.h"
#include "src/objects/property-descriptor.h"
#include "src/objects/property-details.h"
#include "src/objects/swiss-name-dictionary-inl.h"
#include "src/runtime/runtime.h"

namespace v8 {
namespace internal {

MaybeHandle<Object> Runtime::GetObjectProperty(
    Isolate* isolate, Handle<JSAny> lookup_start_object, Handle<Object> key,
    Handle<JSAny> receiver, bool* is_found) {
  if (receiver.is_null()) {
    receiver = lookup_start_object;
  }
  if (IsNullOrUndefined(*lookup_start_object, isolate)) {
    ErrorUtils::ThrowLoadFromNullOrUndefined(isolate, lookup_start_object, key);
    return MaybeHandle<Object>();
  }

  bool success = false;
  PropertyKey lookup_key(isolate, key, &success);
  if (!success) return MaybeHandle<Object>();
  LookupIterator it =
      LookupIterator(isolate, receiver, lookup_key, lookup_start_object);

  MaybeHandle<Object> result = Object::GetProperty(&it);
  if (result.is_null()) {
    return result;
  }
  if (is_found) {
    *is_found = it.state() != LookupIterator::TYPED_ARRAY_INDEX_NOT_FOUND &&
                it.state() != LookupIterator::NOT_FOUND;
  }

  return result;
}

MaybeHandle<Object> Runtime::HasProperty(Isolate* isolate,
                                         Handle<Object> object,
                                         Handle<Object> key) {
  // Check that {object} is actually a receiver.
  if (!IsJSReceiver(*object)) {
    THROW_NEW_ERROR(
        isolate,
        NewTypeError(MessageTemplate::kInvalidInOperatorUse, key, object));
  }
  Handle<JSReceiver> receiver = Cast<JSReceiver>(object);

  // Convert the {key} to a name.
  Handle<Name> name;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, name, Object::ToName(isolate, key));

  // Lookup the {name} on {receiver}.
  Maybe<bool> maybe = JSReceiver::HasProperty(isolate, receiver, name);
  if (maybe.IsNothing()) return MaybeHandle<Object>();
  return ReadOnlyRoots(isolate).boolean_value_handle(maybe.FromJust());
}

Maybe<bool> Runtime::DeleteObjectProperty(Isolate* isolate,
                                          Handle<JSReceiver> receiver,
                                          Handle<Object> key,
                                          LanguageMode language_mode) {
  bool success = false;
  PropertyKey lookup_key(isolate, key, &success);
  if (!success) return Nothing<bool>();
  LookupIterator it(isolate, receiver, lookup_key, LookupIterator::OWN);

  return JSReceiver::DeleteProperty(&it, language_mode);
}

// ES #sec-object.keys
RUNTIME_FUNCTION(Runtime_ObjectKeys) {
  HandleScope scope(isolate);
  Handle<Object> object = args.at(0);

  // Convert the {object} to a proper {receiver}.
  Handle<JSReceiver> receiver;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, receiver,
                                     Object::ToObject(isolate, object));

  // Collect the own keys for the {receiver}.
  Handle<FixedArray> keys;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, keys,
      KeyAccumulator::GetKeys(isolate, receiver, KeyCollectionMode::kOwnOnly,
                              ENUMERABLE_STRINGS,
                              GetKeysConversion::kConvertToString));
  return *keys;
}

// ES #sec-object.getOwnPropertyNames
RUNTIME_FUNCTION(Runtime_ObjectGetOwnPropertyNames) {
  HandleScope scope(isolate);
  Handle<Object> object = args.at(0);

  // Convert the {object} to a proper {receiver}.
  Handle<JSReceiver> receiver;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, receiver,
                                     Object::ToObject(isolate, object));

  // Collect the own keys for the {receiver}.
  // TODO(v8:9401): We should extend the fast path of KeyAccumulator::GetKeys to
  // also use fast path even when filter = SKIP_SYMBOLS.
  Handle<FixedArray> keys;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, keys,
      KeyAccumulator::GetKeys(isolate, receiver, KeyCollectionMode::kOwnOnly,
                              SKIP_SYMBOLS,
                              GetKeysConversion::kConvertToString));
  return *keys;
}

RUNTIME_FUNCTION(Runtime_ObjectGetOwnPropertyNamesTryFast) {
  HandleScope scope(isolate);
  Handle<Object> object = args.at(0);

  // Convert the {object} to a proper {receiver}.
  Handle<JSReceiver> receiver;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, receiver,
                                     Object::ToObject(isolate, object));

  DirectHandle<Map> map(receiver->map(), isolate);

  int nod = map->NumberOfOwnDescriptors();
  Handle<FixedArray> keys;
  if (nod != 0 && map->NumberOfEnumerableProperties() == nod) {
    ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
        isolate, keys,
        KeyAccumulator::GetKeys(isolate, receiver, KeyCollectionMode::kOwnOnly,
                                ENUMERABLE_STRINGS,
                                GetKeysConversion::kConvertToString));
  } else {
    ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
        isolate, keys,
        KeyAccumulator::GetKeys(isolate, receiver, KeyCollectionMode::kOwnOnly,
                                SKIP_SYMBOLS,
                                GetKeysConversion::kConvertToString));
  }

  return *keys;
}

// ES6 19.1.3.2
RUNTIME_FUNCTION(Runtime_ObjectHasOwnProperty) {
  HandleScope scope(isolate);
  Handle<Object> property = args.at(1);

  // TODO(ishell): To improve performance, consider performing the to-string
  // conversion of {property} before calling into the runtime.
  bool success;
  PropertyKey key(isolate, property, &success);
  if (!success) return ReadOnlyRoots(isolate).exception();

  Handle<JSAny> object = args.at<JSAny>(0);

  if (IsJSModuleNamespace(*object)) {
    LookupIterator it(isolate, object, key, LookupIterator::OWN);
    PropertyDescriptor desc;
    Maybe<bool> result = JSReceiver::GetOwnPropertyDescriptor(&it, &desc);
    if (!result.IsJust()) return ReadOnlyRoots(isolate).exception();
    return isolate->heap()->ToBoolean(result.FromJust());

  } else if (IsJSObject(*object)) {
    Handle<JSObject> js_obj = Cast<JSObject>(object);
    // Fast case: either the key is a real named property or it is not
    // an array index and there are no interceptors or hidden
    // prototypes.
    // TODO(jkummerow): Make JSReceiver::HasOwnProperty fast enough to
    // handle all cases directly (without this custom fast path).
    {
      LookupIterator::Configuration c = LookupIterator::OWN_SKIP_INTERCEPTOR;
      LookupIterator it(isolate, js_obj, key, js_obj, c);
      Maybe<bool> maybe = JSReceiver::HasProperty(&it);
      if (maybe.IsNothing()) return ReadOnlyRoots(isolate).exception();
      DCHECK(!isolate->has_exception());
      if (maybe.FromJust()) return ReadOnlyRoots(isolate).true_value();
    }

    Tagged<Map> map = js_obj->map();
    if (!IsJSGlobalProxyMap(map) &&
        (key.is_element() && key.index() <= JSObject::kMaxElementIndex
             ? !map->has_indexed_interceptor()
             : !map->has_named_interceptor())) {
      return ReadOnlyRoots(isolate).false_value();
    }

    // Slow case.
    LookupIterator it(isolate, js_obj, key, js_obj, LookupIterator::OWN);
    Maybe<bool> maybe = JSReceiver::HasProperty(&it);
    if (maybe.IsNothing()) return ReadOnlyRoots(isolate).exception();
    DCHECK(!isolate->has_exception());
    return isolate->heap()->ToBoolean(maybe.FromJust());

  } else if (IsJSProxy(*object)) {
    LookupIterator it(isolate, object, key, Cast<JSProxy>(object),
                      LookupIterator::OWN);
    Maybe<PropertyAttributes> attributes =
        JSReceiver::GetPropertyAttributes(&it);
    if (attributes.IsNothing()) return ReadOnlyRoots(isolate).exception();
    return isolate->heap()->ToBoolean(attributes.FromJust() != ABSENT);

  } else if (IsString(*object)) {
    return isolate->heap()->ToBoolean(
        key.is_element()
            ? key.index() < static_cast<size_t>(Cast<String>(*object)->length())
            : key.name()->Equals(ReadOnlyRoots(isolate).length_string()));
  } else if (IsNullOrUndefined(*object, isolate)) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewTypeError(MessageTemplate::kUndefinedOrNullToObject));
  }

  return ReadOnlyRoots(isolate).false_value();
}

RUNTIME_FUNCTION(Runtime_HasOwnConstDataProperty) {
  HandleScope scope(isolate);
  DCHECK_EQ(2, args.length());
  Handle<Object> object = args.at(0);
  Handle<Object> property = args.at(1);

  bool success;
  PropertyKey key(isolate, property, &success);
  if (!success) return ReadOnlyRoots(isolate).undefined_value();

  if (IsJSObject(*object)) {
    Handle<JSObject> js_obj = Cast<JSObject>(object);
    LookupIterator it(isolate, js_obj, key, js_obj, LookupIterator::OWN);

    switch (it.state()) {
      case LookupIterator::NOT_FOUND:
        return isolate->heap()->ToBoolean(false);
      case LookupIterator::DATA:
        return isolate->heap()->ToBoolean(it.constness() ==
                                          PropertyConstness::kConst);
      default:
        return ReadOnlyRoots(isolate).undefined_value();
    }
  }

  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_IsDictPropertyConstTrackingEnabled) {
  return isolate->heap()->ToBoolean(V8_DICT_PROPERTY_CONST_TRACKING_BOOL);
}

RUNTIME_FUNCTION(Runtime_AddDictionaryProperty) {
  HandleScope scope(isolate);
  DirectHandle<JSObject> receiver = args.at<JSObject>(0);
  Handle<Name> name = args.at<Name>(1);
  Handle<Object> value = args.at(2);

  DCHECK(IsUniqueName(*name));

  PropertyDetails property_details(
      PropertyKind::kData, NONE,
      PropertyDetails::kConstIfDictConstnessTracking);
  if (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
    Handle<SwissNameDictionary> dictionary(
        receiver->property_dictionary_swiss(), isolate);
    dictionary = SwissNameDictionary::Add(isolate, dictionary, name, value,
                                          property_details);
    // TODO(pthier): Add flags to swiss dictionaries and track interesting
    // symbols.
    receiver->SetProperties(*dictionary);
  } else {
    Handle<NameDictionary> dictionary(receiver->property_dictionary(), isolate);
    dictionary =
        NameDictionary::Add(isolate, dictionary, name, value, property_details);
    if (name->IsInteresting(isolate)) {
      dictionary->set_may_have_interesting_properties(true);
    }
    receiver->SetProperties(*dictionary);
  }

  return *value;
}

RUNTIME_FUNCTION(Runtime_AddPrivateBrand) {
  HandleScope scope(isolate);
  DCHECK_EQ(args.length(), 4);
  Handle<JSReceiver> receiver = args.at<JSReceiver>(0);
  Handle<Symbol> brand = args.at<Symbol>(1);
  DirectHandle<Context> context = args.at<Context>(2);
  int depth = args.smi_value_at(3);
  DCHECK(brand->is_private_name());

  LookupIterator it(isolate, receiver, brand, LookupIterator::OWN);

  if (it.IsFound()) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate,
        NewTypeError(MessageTemplate::kInvalidPrivateBrandReinitialization,
                     brand));
  }

  PropertyAttributes attributes =
      static_cast<PropertyAttributes>(DONT_ENUM | DONT_DELETE | READ_ONLY);

  // Look for the context in |depth| in the context chain to store it
  // in the instance with the brand variable as key, which is needed by
  // the debugger for retrieving names of private methods.
  DCHECK_GE(depth, 0);
  for (; depth > 0; depth--) {
    context =
        handle(Cast<Context>(context->get(Context::PREVIOUS_INDEX)), isolate);
  }
  DCHECK_EQ(context->scope_info()->scope_type(), ScopeType::CLASS_SCOPE);
  Maybe<bool> added_brand = Object::AddDataProperty(
      &it, context, attributes, Just(kThrowOnError), StoreOrigin::kMaybeKeyed);
  // Objects in shared space are fixed shape, so private symbols cannot be
  // added.
  if (V8_UNLIKELY(IsAlwaysSharedSpaceJSObject(*receiver))) {
    CHECK(added_brand.IsNothing());
    return ReadOnlyRoots(isolate).exception();
  }
  CHECK(added_brand.IsJust());
  return *receiver;
}

// ES6 section 19.1.2.2 Object.create ( O [ , Properties ] )
// TODO(verwaest): Support the common cases with precached map directly in
// an Object.create stub.
RUNTIME_FUNCTION(Runtime_ObjectCreate) {
  HandleScope scope(isolate);
  Handle<Object> maybe_prototype = args.at(0);
  Handle<Object> properties = args.at(1);
  Handle<JSObject> obj;
  // 1. If Type(O) is neither Object nor Null, throw a TypeError exception.
  Handle<JSPrototype> prototype;
  if (!TryCast(maybe_prototype, &prototype)) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate,
        NewTypeError(MessageTemplate::kProtoObjectOrNull, maybe_prototype));
  }

  // 2. Let obj be ObjectCreate(O).
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, obj, JSObject::ObjectCreate(isolate, prototype));

  // 3. If Properties is not undefined, then
  if (!IsUndefined(*properties, isolate)) {
    // a. Return ? ObjectDefineProperties(obj, Properties).
    // Define the properties if properties was specified and is not undefined.
    RETURN_RESULT_OR_FAILURE(
        isolate, JSReceiver::DefineProperties(isolate, obj, properties));
  }
  // 4. Return obj.
  return *obj;
}

MaybeHandle<Object> Runtime::SetObjectProperty(
    Isolate* isolate, Handle<JSAny> lookup_start_obj, Handle<Object> key,
    Handle<Object> value, MaybeHandle<JSAny> maybe_receiver,
    StoreOrigin store_origin, Maybe<ShouldThrow> should_throw) {
  Handle<JSAny> receiver;
  if (!maybe_receiver.ToHandle(&receiver)) {
    receiver = lookup_start_obj;
  }
  if (IsNullOrUndefined(*lookup_start_obj, isolate)) {
    MaybeDirectHandle<String> maybe_property =
        Object::NoSideEffectsToMaybeString(isolate, key);
    DirectHandle<String> property_name;
    if (maybe_property.ToHandle(&property_name)) {
      THROW_NEW_ERROR(
          isolate,
          NewTypeError(MessageTemplate::kNonObjectPropertyStoreWithProperty,
                       lookup_start_obj, property_name));
    } else {
      THROW_NEW_ERROR(isolate,
                      NewTypeError(MessageTemplate::kNonObjectPropertyStore,
                                   lookup_start_obj));
    }
  }

  // Check if the given key is an array index.
  bool success = false;
  PropertyKey lookup_key(isolate, key, &success);
  if (!success) return MaybeHandle<Object>();
  LookupIterator it(isolate, receiver, lookup_key, lookup_start_obj);
  if (IsSymbol(*key) && Cast<Symbol>(*key)->is_private_name()) {
    Maybe<bool> can_store = JSReceiver::CheckPrivateNameStore(&it, false);
    MAYBE_RETURN_NULL(can_store);
    if (!can_store.FromJust()) {
      return isolate->factory()->undefined_value();
    }
  }

  MAYBE_RETURN_NULL(
      Object::SetProperty(&it, value, store_origin, should_throw));

  return value;
}

MaybeHandle<Object> Runtime::SetObjectProperty(
    Isolate* isolate, Handle<JSAny> object, Handle<Object> key,
    Handle<Object> value, StoreOrigin store_origin,
    Maybe<ShouldThrow> should_throw) {
  return SetObjectProperty(isolate, object, key, value, object, store_origin,
                           should_throw);
}

MaybeHandle<Object> Runtime::DefineObjectOwnProperty(Isolate* isolate,
                                                     Handle<JSAny> object,
                                                     Handle<Object> key,
                                                     Handle<Object> value,
                                                     StoreOrigin store_origin) {
  if (IsNullOrUndefined(*object, isolate)) {
    MaybeDirectHandle<String> maybe_property =
        Object::NoSideEffectsToMaybeString(isolate, key);
    DirectHandle<String> property_name;
    if (maybe_property.ToHandle(&property_name)) {
      THROW_NEW_ERROR(
          isolate,
          NewTypeError(MessageTemplate::kNonObjectPropertyStoreWithProperty,
                       object, property_name));
    } else {
      THROW_NEW_ERROR(
          isolate,
          NewTypeError(MessageTemplate::kNonObjectPropertyStore, object));
    }
  }
  // Check if the given key is an array index.
  bool success = false;
  PropertyKey lookup_key(isolate, key, &success);
  if (!success) return MaybeHandle<Object>();

  if (IsSymbol(*key) && Cast<Symbol>(*key)->is_private_name()) {
    LookupIterator it(isolate, object, lookup_key, LookupIterator::OWN);
    Maybe<bool> can_store = JSReceiver::CheckPrivateNameStore(&it, true);
    MAYBE_RETURN_NULL(can_store);
    // If the state is ACCESS_CHECK, the faliled access check callback
    // is configured but it did't throw.
    DCHECK_IMPLIES(it.IsFound(), it.state() == LookupIterator::ACCESS_CHECK &&
                                     !can_store.FromJust());
    if (!can_store.FromJust()) {
      return isolate->factory()->undefined_value();
    }
    MAYBE_RETURN_NULL(
        JSReceiver::AddPrivateField(&it, value, Nothing<ShouldThrow>()));
  } else {
    MAYBE_RETURN_NULL(JSReceiver::CreateDataProperty(
        isolate, object, lookup_key, value, Nothing<ShouldThrow>()));
  }

  return value;
}

RUNTIME_FUNCTION(Runtime_InternalSetPrototype) {
  HandleScope scope(isolate);
  DCHECK_EQ(2, args.length());
  Handle<JSReceiver> obj = args.at<JSReceiver>(0);
  Handle<Object> prototype = args.at(1);
  MAYBE_RETURN(
      JSReceiver::SetPrototype(isolate, obj, prototype, false, kThrowOnError),
      ReadOnlyRoots(isolate).exception());
  return *obj;
}

RUNTIME_FUNCTION(Runtime_OptimizeObjectForAddingMultipleProperties) {
  HandleScope scope(isolate);
  DCHECK_EQ(2, args.length());
  DirectHandle<JSObject> object = args.at<JSObject>(0);
  int properties = args.smi_value_at(1);
  // Conservative upper limit to prevent fuzz tests from going OOM.
  if (properties > 100000) return isolate->ThrowIllegalOperation();
  if (object->HasFastProperties() && !IsJSGlobalProxy(*object)) {
    JSObject::NormalizeProperties(isolate, object, KEEP_INOBJECT_PROPERTIES,
                                  properties, "OptimizeForAdding");
  }
  return *object;
}

RUNTIME_FUNCTION(Runtime_ObjectValues) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());

  Handle<JSReceiver> receiver = args.at<JSReceiver>(0);

  Handle<FixedArray> values;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, values,
      JSReceiver::GetOwnValues(isolate, receiver,
                               PropertyFilter::ENUMERABLE_STRINGS, true));
  return *isolate->factory()->NewJSArrayWithElements(values);
}

RUNTIME_FUNCTION(Runtime_ObjectValuesSkipFastPath) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());

  Handle<JSReceiver> receiver = args.at<JSReceiver>(0);

  Handle<FixedArray> value;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, value,
      JSReceiver::GetOwnValues(isolate, receiver,
                               PropertyFilter::ENUMERABLE_STRINGS, false));
  return *isolate->factory()->NewJSArrayWithElements(value);
}

RUNTIME_FUNCTION(Runtime_ObjectEntries) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());

  Handle<JSReceiver> receiver = args.at<JSReceiver>(0);

  Handle<FixedArray> entries;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, entries,
      JSReceiver::GetOwnEntries(isolate, receiver,
                                PropertyFilter::ENUMERABLE_STRINGS, true));
  return *isolate->factory()->NewJSArrayWithElements(entries);
}

RUNTIME_FUNCTION(Runtime_ObjectEntriesSkipFastPath) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());

  Handle<JSReceiver> receiver = args.at<JSReceiver>(0);

  Handle<FixedArray> entries;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, entries,
      JSReceiver::GetOwnEntries(isolate, receiver,
                                PropertyFilter::ENUMERABLE_STRINGS, false));
  return *isolate->factory()->NewJSArrayWithElements(entries);
}

RUNTIME_FUNCTION(Runtime_ObjectIsExtensible) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  Handle<Object> object = args.at(0);

  Maybe<bool> result =
      IsJSReceiver(*object)
          ? JSReceiver::IsExtensible(isolate, Cast<JSReceiver>(object))
          : Just(false);
  MAYBE_RETURN(result, ReadOnlyRoots(isolate).exception());
  return isolate->heap()->ToBoolean(result.FromJust());
}

RUNTIME_FUNCTION(Runtime_JSReceiverPreventExtensionsThrow) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  Handle<JSReceiver> object = args.at<JSReceiver>(0);

  MAYBE_RETURN(JSReceiver::PreventExtensions(isolate, Cast<JSReceiver>(object),
                                             kThrowOnError),
               ReadOnlyRoots(isolate).exception());
  return *object;
}

RUNTIME_FUNCTION(Runtime_JSReceiverPreventExtensionsDontThrow) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  Handle<JSReceiver> object = args.at<JSReceiver>(0);

  Maybe<bool> result = JSReceiver::PreventExtensions(
      isolate, Cast<JSReceiver>(object), kDontThrow);
  MAYBE_RETURN(result, ReadOnlyRoots(isolate).exception());
  return *isolate->factory()->ToBoolean(result.FromJust());
}

RUNTIME_FUNCTION(Runtime_JSReceiverGetPrototypeOf) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  Handle<JSReceiver> receiver = args.at<JSReceiver>(0);

  RETURN_RESULT_OR_FAILURE(isolate,
                           JSReceiver::GetPrototype(isolate, receiver));
}

RUNTIME_FUNCTION(Runtime_JSReceiverSetPrototypeOfThrow) {
  HandleScope scope(isolate);

  DCHECK_EQ(2, args.length());
  Handle<JSReceiver> object = args.at<JSReceiver>(0);
  Handle<Object> proto = args.at(1);

  MAYBE_RETURN(
      JSReceiver::SetPrototype(isolate, object, proto, true, kThrowOnError),
      ReadOnlyRoots(isolate).exception());

  return *object;
}

RUNTIME_FUNCTION(Runtime_JSReceiverSetPrototypeOfDontThrow) {
  HandleScope scope(isolate);

  DCHECK_EQ(2, args.length());
  Handle<JSReceiver> object = args.at<JSReceiver>(0);
  Handle<Object> proto = args.at(1);

  Maybe<bool> result =
      JSReceiver::SetPrototype(isolate, object, proto, true, kDontThrow);
  MAYBE_RETURN(result, ReadOnlyRoots(isolate).exception());
  return *isolate->factory()->ToBoolean(result.FromJust());
}

RUNTIME_FUNCTION(Runtime_GetProperty) {
  HandleScope scope(isolate);
  DCHECK(args.length() == 3 || args.length() == 2);
  Handle<JSAny> lookup_start_obj = args.at<JSAny>(0);
  Handle<Object> key_obj = args.at(1);
  Handle<JSAny> receiver_obj = lookup_start_obj;
  if (args.length() == 3) {
    receiver_obj = args.at<JSAny>(2);
  }

  // Fast cases for getting named properties of the lookup_start_obj JSObject
  // itself.
  //
  // The global proxy objects has to be excluded since LookupOwn on
  // the global proxy object can return a valid result even though the
  // global proxy object never has properties.  This is the case
  // because the global proxy object forwards everything to its hidden
  // prototype including own lookups.
  //
  // Additionally, we need to make sure that we do not cache results
  // for objects that require access checks.

  // Convert string-index keys to their number variant to avoid internalization
  // below; and speed up subsequent conversion to index.
  uint32_t index;
  if (IsString(*key_obj) && Cast<String>(*key_obj)->AsArrayIndex(&index)) {
    key_obj = isolate->factory()->NewNumberFromUint(index);
  }
  if (IsJSObject(*lookup_start_obj)) {
    Handle<JSObject> lookup_start_object = Cast<JSObject>(lookup_start_obj);
    if (!IsJSGlobalProxy(*lookup_start_object) &&
        !IsAccessCheckNeeded(*lookup_start_object) && IsName(*key_obj)) {
      Handle<Name> key = Cast<Name>(key_obj);
      key_obj = key = isolate->factory()->InternalizeName(key);

      DisallowGarbageCollection no_gc;
      if (IsJSGlobalObject(*lookup_start_object)) {
        // Attempt dictionary lookup.
        Tagged<GlobalDictionary> dictionary =
            Cast<JSGlobalObject>(*lookup_start_object)
                ->global_dictionary(kAcquireLoad);
        InternalIndex entry = dictionary->FindEntry(isolate, key);
        if (entry.is_found()) {
          Tagged<PropertyCell> cell = dictionary->CellAt(entry);
          if (cell->property_details().kind() == PropertyKind::kData) {
            Tagged<Object> value = cell->value();
            if (!IsPropertyCellHole(value, isolate)) return value;
            // If value is the hole (meaning, absent) do the general lookup.
          }
        }
      } else if (!lookup_start_object->HasFastProperties()) {
        // Attempt dictionary lookup.
        if (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
          Tagged<SwissNameDictionary> dictionary =
              lookup_start_object->property_dictionary_swiss();
          InternalIndex entry = dictionary->FindEntry(isolate, *key);
          if (entry.is_found() &&
              (dictionary->DetailsAt(entry).kind() == PropertyKind::kData)) {
            return dictionary->ValueAt(entry);
          }
        } else {
          Tagged<NameDictionary> dictionary =
              lookup_start_object->property_dictionary();
          InternalIndex entry = dictionary->FindEntry(isolate, key);
          if ((entry.is_found()) &&
              (dictionary->DetailsAt(entry).kind() == PropertyKind::kData)) {
            return dictionary->ValueAt(entry);
          }
        }
      }
    } else if (IsSmi(*key_obj)) {
      // JSObject without a name key. If the key is a Smi, check for a
      // definite out-of-bounds access to elements, which is a strong indicator
      // that subsequent accesses will also call the runtime. Proactively
      // transition elements to FAST_*_ELEMENTS to avoid excessive boxing of
      // doubles for those future calls in the case that the elements would
      // become PACKED_DOUBLE_ELEMENTS.
      ElementsKind elements_kind = lookup_start_object->GetElementsKind();
      if (IsDoubleElementsKind(elements_kind)) {
        if (Smi::ToInt(*key_obj) >= lookup_start_object->elements()->length()) {
          elements_kind = IsHoleyElementsKind(elements_kind) ? HOLEY_ELEMENTS
                                                             : PACKED_ELEMENTS;
          JSObject::TransitionElementsKind(lookup_start_object, elements_kind);
        }
      } else {
        DCHECK(IsSmiOrObjectElementsKind(elements_kind) ||
               !IsFastElementsKind(elements_kind));
      }
    }
  } else if (IsString(*lookup_start_obj) && IsSmi(*key_obj)) {
    // Fast case for string indexing using [] with a smi index.
    Handle<String> str = Cast<String>(lookup_start_obj);
    uint32_t smi_index = Cast<Smi>(*key_obj).value();
    if (smi_index < str->length()) {
      Factory* factory = isolate->factory();
      return *factory->LookupSingleCharacterStringFromCode(
          String::Flatten(isolate, str)->Get(smi_index));
    }
  }

  // Fall back to GetObjectProperty.
  RETURN_RESULT_OR_FAILURE(
      isolate, Runtime::GetObjectProperty(isolate, lookup_start_obj, key_obj,
                                          receiver_obj));
}

RUNTIME_FUNCTION(Runtime_SetKeyedProperty) {
  HandleScope scope(isolate);
  DCHECK_EQ(3, args.length());

  Handle<JSAny> object = args.at<JSAny>(0);
  Handle<Object> key = args.at(1);
  Handle<Object> value = args.at(2);

  RETURN_RESULT_OR_FAILURE(
      isolate, Runtime::SetObjectProperty(isolate, object, key, value,
                                          StoreOrigin::kMaybeKeyed));
}

RUNTIME_FUNCTION(Runtime_DefineObjectOwnProperty) {
  HandleScope scope(isolate);
  DCHECK_EQ(3, args.length());

  Handle<JSAny> object = args.at<JSAny>(0);
  Handle<Object> key = args.at(1);
  Handle<Object> value = args.at(2);

  RETURN_RESULT_OR_FAILURE(
      isolate, Runtime::DefineObjectOwnProperty(isolate, object, key, value,
                                                StoreOrigin::kMaybeKeyed));
}

RUNTIME_FUNCTION(Runtime_SetNamedProperty) {
  HandleScope scope(isolate);
  DCHECK_EQ(3, args.length());

  Handle<JSAny> object = args.at<JSAny>(0);
  Handle<Object> key = args.at(1);
  Handle<Object> value = args.at(2);

  RETURN_RESULT_OR_FAILURE(
      isolate, Runtime::SetObjectProperty(isolate, object, key, value,
                                          StoreOrigin::kNamed));
}

namespace {

// ES6 section 12.5.4.
Tagged<Object> DeleteProperty(Isolate* isolate, Handle<Object> object,
                              Handle<Object> key, LanguageMode language_mode) {
  Handle<JSReceiver> receiver;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, receiver,
                                     Object::ToObject(isolate, object));
  Maybe<bool> result =
      Runtime::DeleteObjectProperty(isolate, receiver, key, language_mode);
  MAYBE_RETURN(result, ReadOnlyRoots(isolate).exception());
  return isolate->heap()->ToBoolean(result.FromJust());
}

}  // namespace

RUNTIME_FUNCTION(Runtime_DeleteProperty) {
  HandleScope scope(isolate);
  DCHECK_EQ(3, args.length());
  Handle<Object> object = args.at(0);
  Handle<Object> key = args.at(1);
  int language_mode = args.smi_value_at(2);
  return DeleteProperty(isolate, object, key,
                        static_cast<LanguageMode>(language_mode));
}

RUNTIME_FUNCTION(Runtime_ShrinkNameDictionary) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  Handle<NameDictionary> dictionary = args.at<NameDictionary>(0);

  return *NameDictionary::Shrink(isolate, dictionary);
}

RUNTIME_FUNCTION(Runtime_ShrinkSwissNameDictionary) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  Handle<SwissNameDictionary> dictionary = args.at<SwissNameDictionary>(0);

  return *SwissNameDictionary::Shrink(isolate, dictionary);
}

// ES6 section 12.9.3, operator in.
RUNTIME_FUNCTION(Runtime_HasProperty) {
  HandleScope scope(isolate);
  DCHECK_EQ(2, args.length());
  Handle<Object> object = args.at(0);
  Handle<Object> key = args.at(1);

  // Check that {object} is actually a receiver.
  if (!IsJSReceiver(*object)) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate,
        NewTypeError(MessageTemplate::kInvalidInOperatorUse, key, object));
  }
  Handle<JSReceiver> receiver = Cast<JSReceiver>(object);

  // Convert the {key} to a name.
  Handle<Name> name;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, name,
                                     Object::ToName(isolate, key));

  // Lookup the {name} on {receiver}.
  Maybe<bool> maybe = JSReceiver::HasProperty(isolate, receiver, name);
  if (maybe.IsNothing()) return ReadOnlyRoots(isolate).exception();
  return isolate->heap()->ToBoolean(maybe.FromJust());
}

RUNTIME_FUNCTION(Runtime_GetOwnPropertyKeys) {
  HandleScope scope(isolate);
  DCHECK_EQ(2, args.length());
  Handle<JSReceiver> object = args.at<JSReceiver>(0);
  int filter_value = args.smi_value_at(1);
  PropertyFilter filter = static_cast<PropertyFilter>(filter_value);

  Handle<FixedArray> keys;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, keys,
      KeyAccumulator::GetKeys(isolate, object, KeyCollectionMode::kOwnOnly,
                              filter, GetKeysConversion::kConvertToString));

  return *isolate->factory()->NewJSArrayWithElements(keys);
}

RUNTIME_FUNCTION(Runtime_ToFastProperties) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  Handle<Object> object = args.at(0);
  if (IsJSObject(*object) && !IsJSGlobalObject(*object)) {
    JSObject::MigrateSlowToFast(Cast<JSObject>(object), 0,
                                "RuntimeToFastProperties");
  }
  return *object;
}

RUNTIME_FUNCTION(Runtime_AllocateHeapNumber) {
  HandleScope scope(isolate);
  DCHECK_EQ(0, args.length());
  return *isolate->factory()->NewHeapNumber(0);
}

RUNTIME_FUNCTION(Runtime_NewObject) {
  HandleScope scope(isolate);
  DCHECK_EQ(2, args.length());
  Handle<JSFunction> target = args.at<JSFunction>(0);
  Handle<JSReceiver> new_target = args.at<JSReceiver>(1);
  RETURN_RESULT_OR_FAILURE(
      isolate,
      JSObject::New(target, new_target, Handle<AllocationSite>::null()));
}

RUNTIME_FUNCTION(Runtime_GetDerivedMap) {
  HandleScope scope(isolate);
  DCHECK_EQ(3, args.length());
  Handle<JSFunction> target = args.at<JSFunction>(0);
  Handle<JSReceiver> new_target = args.at<JSReceiver>(1);
  DirectHandle<Object> rab_gsab = args.at(2);
  if (IsTrue(*rab_gsab)) {
    RETURN_RESULT_OR_FAILURE(
        isolate, JSFunction::GetDerivedRabGsabTypedArrayMap(isolate, target,
                                                            new_targ
```