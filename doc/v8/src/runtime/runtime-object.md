Response: The user wants a summary of the C++ source code file `v8/src/runtime/runtime-object.cc`.
This file seems to implement runtime functions related to JavaScript objects in the V8 engine.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the core purpose:** The filename and the `Runtime::` namespace strongly suggest that this file implements runtime functions for object manipulation in V8. These functions are likely called from generated code or the interpreter when performing object-related operations in JavaScript.

2. **Scan for function definitions:** Look for the `RUNTIME_FUNCTION` macro. Each of these functions represents a specific operation that can be invoked at runtime. List these functions and their basic signatures.

3. **Group related functions:** Notice patterns in the function names and their functionalities. For example, many functions start with `Runtime_Object`, `Runtime_Has`, `Runtime_Get`, `Runtime_Set`, etc. Group these functions logically by the kind of operation they perform (e.g., getting properties, setting properties, deleting properties, etc.).

4. **Analyze function implementations:**  For each group, examine the implementation details briefly. Look for key V8 concepts being used, such as `LookupIterator`, `PropertyKey`, `JSReceiver`, `JSObject`, `NameDictionary`, `SwissNameDictionary`, `Map`, etc. These concepts reveal the underlying mechanisms for object manipulation.

5. **Connect to JavaScript concepts:** For each group of functions, try to relate them back to corresponding JavaScript operations or built-in methods. For instance:
    * `Runtime_GetObjectProperty` corresponds to accessing properties using `object.property` or `object['property']`.
    * `Runtime_HasProperty` corresponds to the `in` operator.
    * `Runtime_ObjectKeys` corresponds to `Object.keys()`.
    * `Runtime_DefineObjectOwnProperty` corresponds to `Object.defineProperty()`.
    * And so on.

6. **Choose representative examples:** Select a few of the most common or illustrative functions and demonstrate their connection to JavaScript with simple examples. Focus on basic object operations like getting, setting, and checking for properties.

7. **Summarize the overall functionality:** Based on the analysis, provide a concise summary of the file's purpose. Emphasize its role in implementing the core object model of JavaScript within the V8 engine.

8. **Structure the output:** Organize the information logically with clear headings and bullet points for readability. Start with a general summary, then provide more specific details about the different categories of functions, and finally offer illustrative JavaScript examples.

**(Self-Correction during the process):**

* Initially, I might just list all the `RUNTIME_FUNCTION` names without grouping them. Realizing that this is not very informative, I would then go back and group them based on their functionality.
*  I might focus too much on the C++ implementation details initially. The prompt asks for a connection to JavaScript, so I need to shift the focus towards how these C++ functions relate to JavaScript features.
*  When providing examples, I need to ensure they are simple and directly illustrate the function's purpose. Avoid overly complex or edge-case scenarios.
* For the SwissNameDictionary functions, I need to mention their temporary nature as indicated by the comments.
这个C++源代码文件 `v8/src/runtime/runtime-object.cc` 实现了 V8 JavaScript 引擎中与 **JavaScript 对象操作相关的运行时 (runtime) 函数**。这些运行时函数是 V8 引擎在执行 JavaScript 代码时，处理各种对象操作（例如属性访问、修改、删除、创建等）的基础。

**主要功能归纳:**

该文件包含了大量用于实现 JavaScript 对象行为的底层函数，主要涉及以下方面：

* **属性访问 (Property Access):**
    * `Runtime::GetObjectProperty`: 获取对象的属性值，对应 JavaScript 中的 `object.property` 或 `object['property']`。
    * `Runtime::SetObjectProperty`: 设置对象的属性值，对应 JavaScript 中的 `object.property = value` 或 `object['property'] = value`。
    * `Runtime::GetProperty`:  优化的属性获取，包含一些快速路径处理。
* **属性存在性检查 (Property Existence Check):**
    * `Runtime::HasProperty`: 检查对象是否拥有某个属性（包括原型链上的属性），对应 JavaScript 中的 `in` 运算符。
    * `Runtime_ObjectHasOwnProperty`: 检查对象是否拥有自身的属性，对应 JavaScript 中的 `object.hasOwnProperty(property)`。
* **属性定义和修改 (Property Definition and Modification):**
    * `Runtime::DefineObjectOwnProperty`: 定义或修改对象自身的属性，对应 JavaScript 中的 `Object.defineProperty()`。
    * `Runtime_DefineAccessorPropertyUnchecked`, `Runtime_DefineGetterPropertyUnchecked`, `Runtime_DefineSetterPropertyUnchecked`: 定义访问器属性（getter/setter）。
    * `Runtime_SetOwnPropertyIgnoreAttributes`: 设置对象自身属性的值，忽略属性的特性。
* **属性删除 (Property Deletion):**
    * `Runtime::DeleteObjectProperty`: 删除对象的属性，对应 JavaScript 中的 `delete object.property`。
    * `Runtime_DeleteProperty`:  提供语言模式 (strict/non-strict) 的属性删除。
* **属性枚举 (Property Enumeration):**
    * `Runtime_ObjectKeys`: 获取对象自身可枚举的属性名，对应 JavaScript 中的 `Object.keys()`。
    * `Runtime_ObjectGetOwnPropertyNames`: 获取对象自身的所有属性名（包括不可枚举的），对应 JavaScript 中的 `Object.getOwnPropertyNames()`。
    * `Runtime_ObjectValues`: 获取对象自身可枚举的属性值，对应 JavaScript 中的 `Object.values()`。
    * `Runtime_ObjectEntries`: 获取对象自身可枚举的属性名值对，对应 JavaScript 中的 `Object.entries()`。
    * `Runtime_GetOwnPropertyKeys`:  根据过滤器获取对象自身的属性键。
* **原型 (Prototype) 操作:**
    * `Runtime_InternalSetPrototype`: 设置对象的原型，对应 JavaScript 中的 `Object.setPrototypeOf()`。
    * `Runtime_JSReceiverGetPrototypeOf`: 获取对象的原型，对应 JavaScript 中的 `Object.getPrototypeOf()`。
    * `Runtime_JSReceiverSetPrototypeOfThrow`, `Runtime_JSReceiverSetPrototypeOfDontThrow`: 设置对象的原型。
    * `Runtime_HasInPrototypeChain`: 检查一个对象是否在另一个对象的原型链上。
* **对象创建 (Object Creation):**
    * `Runtime_ObjectCreate`: 创建一个新对象，可以指定原型，对应 JavaScript 中的 `Object.create()`。
    * `Runtime_NewObject`:  使用构造函数创建一个新对象。
* **对象特性 (Object Attributes):**
    * `Runtime_ObjectIsExtensible`: 检查对象是否可扩展，对应 JavaScript 中的 `Object.isExtensible()`。
    * `Runtime_JSReceiverPreventExtensionsThrow`, `Runtime_JSReceiverPreventExtensionsDontThrow`:  阻止对象扩展，对应 JavaScript 中的 `Object.preventExtensions()`。
* **私有属性 (Private Properties):**
    * `Runtime_AddPrivateBrand`: 添加私有 brand。
    * `Runtime_GetPrivateMember`: 获取私有成员。
    * `Runtime_SetPrivateMember`: 设置私有成员。
    * `Runtime_LoadPrivateGetter`, `Runtime_LoadPrivateSetter`, `Runtime_CreatePrivateAccessors`:  与私有访问器相关的操作。
* **类型转换 (Type Conversion):**
    * `Runtime_ToObject`: 将值转换为对象。
    * `Runtime_ToNumber`: 将值转换为数字。
    * `Runtime_ToString`: 将值转换为字符串。
    * `Runtime_ToName`: 将值转换为 Name 类型。
    * `Runtime_ToLength`: 将值转换为合法的数组长度。
    * `Runtime_ToNumeric`: 将值转换为数字或 BigInt。
* **优化 (Optimization):**
    * `Runtime_OptimizeObjectForAddingMultipleProperties`:  为添加多个属性优化对象。
    * `Runtime_ToFastProperties`: 将对象的属性存储方式转换为快速模式。
    * `Runtime_TryMigrateInstance`: 尝试迁移对象的实例。
* **字典 (Dictionary) 相关:**
    * `Runtime_AddDictionaryProperty`: 向字典类型的对象添加属性。
    * `Runtime_ShrinkNameDictionary`, `Runtime_ShrinkSwissNameDictionary`: 收缩字典。
* **其他:**
    * `Runtime_SetFunctionName`: 设置函数的名字。
    * `Runtime_DefineKeyedOwnPropertyInLiteral`: 在对象字面量中定义键控属性。
    * `Runtime_CopyDataProperties`, `Runtime_SetDataProperties`: 复制或设置数据属性。
    * `Runtime_AllocateHeapNumber`: 分配一个堆上的数字。
    * `Runtime_GetDerivedMap`: 获取派生类的 Map。
    * `Runtime_CompleteInobjectSlackTrackingForMap`: 完成 Map 的内联属性空闲跟踪。
    * `Runtime_CreateIterResultObject`: 创建迭代器结果对象。
    * `Runtime_SetOwnPropertyIgnoreAttributes`: 设置对象自身属性，忽略属性特性。
    * `Runtime_GetOwnPropertyDescriptorObject`: 获取属性的描述符对象。
    * 与 `SwissNameDictionary` 相关的函数（例如 `Runtime_SwissTableAllocate`, `Runtime_SwissTableAdd` 等），这是一种用于存储对象属性的更现代的字典实现。

**与 JavaScript 功能的关系及 JavaScript 示例:**

这个文件中的运行时函数是 JavaScript 语言内置对象和操作的基础。当你在 JavaScript 中执行对象相关的代码时，V8 引擎会在底层调用这些 C++ 函数来完成相应的操作。

以下是一些 JavaScript 示例，展示了该文件中运行时函数可能被调用的场景：

**1. 获取属性:**

```javascript
const obj = { a: 1 };
const value = obj.a; // 底层可能会调用 Runtime::GetObjectProperty 或 Runtime::GetProperty
console.log(value); // 输出 1
```

**2. 设置属性:**

```javascript
const obj = {};
obj.b = 2; // 底层可能会调用 Runtime::SetObjectProperty
console.log(obj.b); // 输出 2
```

**3. 检查属性是否存在:**

```javascript
const obj = { c: 3 };
const hasProperty = 'c' in obj; // 底层可能会调用 Runtime::HasProperty
console.log(hasProperty); // 输出 true
```

**4. 获取自身属性名:**

```javascript
const obj = { d: 4, e: 5 };
const keys = Object.keys(obj); // 底层会调用 Runtime_ObjectKeys
console.log(keys); // 输出 ["d", "e"]
```

**5. 定义属性特性:**

```javascript
const obj = {};
Object.defineProperty(obj, 'f', {
  value: 6,
  enumerable: false,
  writable: false,
  configurable: false
}); // 底层会调用 Runtime::DefineObjectOwnProperty
console.log(obj.f); // 输出 6
```

**6. 删除属性:**

```javascript
const obj = { g: 7 };
delete obj.g; // 底层可能会调用 Runtime::DeleteObjectProperty 或 Runtime_DeleteProperty
console.log(obj.g); // 输出 undefined
```

**总结:**

`v8/src/runtime/runtime-object.cc` 是 V8 引擎中一个至关重要的文件，它实现了 JavaScript 对象模型的底层操作。JavaScript 代码中对对象的各种操作最终都会映射到这个文件中定义的 C++ 运行时函数，从而保证了 JavaScript 语法的正确执行和高效运行。理解这个文件中的代码有助于深入理解 V8 引擎的工作原理以及 JavaScript 对象的内部结构和行为。

### 提示词
```
这是目录为v8/src/runtime/runtime-object.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
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
                                                            new_target));
  } else {
    RETURN_RESULT_OR_FAILURE(
        isolate, JSFunction::GetDerivedMap(isolate, target, new_target));
  }
}

RUNTIME_FUNCTION(Runtime_CompleteInobjectSlackTrackingForMap) {
  DisallowGarbageCollection no_gc;
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());

  DirectHandle<Map> initial_map = args.at<Map>(0);
  MapUpdater::CompleteInobjectSlackTracking(isolate, *initial_map);

  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_TryMigrateInstance) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  DirectHandle<JSObject> js_object = args.at<JSObject>(0);
  // It could have been a DCHECK but we call this function directly from tests.
  if (!js_object->map()->is_deprecated()) return Smi::zero();
  // This call must not cause lazy deopts, because it's called from deferred
  // code where we can't handle lazy deopts for lack of a suitable bailout
  // ID. So we just try migration and signal failure if necessary,
  // which will also trigger a deopt.
  if (!JSObject::TryMigrateInstance(isolate, js_object)) return Smi::zero();
  return *js_object;
}

static bool IsValidAccessor(Isolate* isolate, DirectHandle<Object> obj) {
  return IsNullOrUndefined(*obj, isolate) || IsCallable(*obj);
}

// Implements part of 8.12.9 DefineOwnProperty.
// There are 3 cases that lead here:
// Step 4b - define a new accessor property.
// Steps 9c & 12 - replace an existing data property with an accessor property.
// Step 12 - update an existing accessor property with an accessor or generic
//           descriptor.
RUNTIME_FUNCTION(Runtime_DefineAccessorPropertyUnchecked) {
  HandleScope scope(isolate);
  DCHECK_EQ(5, args.length());
  Handle<JSObject> obj = args.at<JSObject>(0);
  CHECK(!IsNull(*obj, isolate));
  Handle<Name> name = args.at<Name>(1);
  DirectHandle<Object> getter = args.at(2);
  CHECK(IsValidAccessor(isolate, getter));
  DirectHandle<Object> setter = args.at(3);
  CHECK(IsValidAccessor(isolate, setter));
  auto attrs = PropertyAttributesFromInt(args.smi_value_at(4));

  RETURN_FAILURE_ON_EXCEPTION(
      isolate, JSObject::DefineOwnAccessorIgnoreAttributes(obj, name, getter,
                                                           setter, attrs));
  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_SetFunctionName) {
  HandleScope scope(isolate);
  DCHECK_EQ(2, args.length());
  Handle<Object> value = args.at(0);
  Handle<Name> name = args.at<Name>(1);
  DCHECK(IsJSFunction(*value));
  auto function = Cast<JSFunction>(value);
  DCHECK(!function->shared()->HasSharedName());
  DirectHandle<Map> function_map(function->map(), isolate);
  if (!JSFunction::SetName(function, name,
                           isolate->factory()->empty_string())) {
    return ReadOnlyRoots(isolate).exception();
  }
  // Class constructors do not reserve in-object space for name field.
  DCHECK_IMPLIES(!IsClassConstructor(function->shared()->kind()),
                 *function_map == function->map());
  return *value;
}

RUNTIME_FUNCTION(Runtime_DefineKeyedOwnPropertyInLiteral) {
  HandleScope scope(isolate);
  DCHECK_EQ(6, args.length());
  Handle<JSReceiver> object = args.at<JSReceiver>(0);
  Handle<Object> name = args.at(1);
  Handle<Object> value = args.at(2);
  int flag = args.smi_value_at(3);
  Handle<HeapObject> maybe_vector = args.at<HeapObject>(4);

  if (!IsUndefined(*maybe_vector)) {
    int index = args.tagged_index_value_at(5);
    DCHECK(IsName(*name));
    DCHECK(IsFeedbackVector(*maybe_vector));
    Handle<FeedbackVector> vector = Cast<FeedbackVector>(maybe_vector);
    FeedbackNexus nexus(isolate, vector, FeedbackVector::ToSlot(index));
    if (nexus.ic_state() == InlineCacheState::UNINITIALIZED) {
      if (IsUniqueName(*name)) {
        nexus.ConfigureMonomorphic(Cast<Name>(name),
                                   handle(object->map(), isolate),
                                   MaybeObjectHandle());
      } else {
        nexus.ConfigureMegamorphic(IcCheckType::kProperty);
      }
    } else if (nexus.ic_state() == InlineCacheState::MONOMORPHIC) {
      if (nexus.GetFirstMap() != object->map() || nexus.GetName() != *name) {
        nexus.ConfigureMegamorphic(IcCheckType::kProperty);
      }
    }
  }

  DefineKeyedOwnPropertyInLiteralFlags flags(flag);

  if (flags & DefineKeyedOwnPropertyInLiteralFlag::kSetFunctionName) {
    DCHECK(IsName(*name));
    DCHECK(IsJSFunction(*value));
    auto function = Cast<JSFunction>(value);
    DCHECK(!function->shared()->HasSharedName());
    DirectHandle<Map> function_map(function->map(), isolate);
    if (!JSFunction::SetName(function, Cast<Name>(name),
                             isolate->factory()->empty_string())) {
      return ReadOnlyRoots(isolate).exception();
    }
    // Class constructors do not reserve in-object space for name field.
    DCHECK_IMPLIES(!IsClassConstructor(function->shared()->kind()),
                   *function_map == function->map());
  }

  PropertyKey key(isolate, name);
  LookupIterator it(isolate, object, key, object, LookupIterator::OWN);

  Maybe<bool> result = JSObject::DefineOwnPropertyIgnoreAttributes(
      &it, value, PropertyAttributes::NONE, Just(kDontThrow));
  // Cannot fail since this should only be called when
  // creating an object literal.
  RETURN_FAILURE_IF_EXCEPTION(isolate);
  DCHECK(result.IsJust());
  USE(result);

  // Return the value so that
  // BaselineCompiler::VisitDefineKeyedOwnPropertyInLiteral doesn't have to
  // save the accumulator.
  return *value;
}

RUNTIME_FUNCTION(Runtime_HasFastPackedElements) {
  SealHandleScope shs(isolate);
  DCHECK_EQ(1, args.length());
  auto obj = Cast<HeapObject>(args[0]);
  return isolate->heap()->ToBoolean(
      IsFastPackedElementsKind(obj->map()->elements_kind()));
}

RUNTIME_FUNCTION(Runtime_IsJSReceiver) {
  SealHandleScope shs(isolate);
  DCHECK_EQ(1, args.length());
  Tagged<Object> obj = args[0];
  return isolate->heap()->ToBoolean(IsJSReceiver(obj));
}

RUNTIME_FUNCTION(Runtime_GetFunctionName) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  DirectHandle<JSFunction> function = args.at<JSFunction>(0);
  return *JSFunction::GetName(isolate, function);
}

RUNTIME_FUNCTION(Runtime_DefineGetterPropertyUnchecked) {
  HandleScope scope(isolate);
  DCHECK_EQ(4, args.length());
  Handle<JSObject> object = args.at<JSObject>(0);
  Handle<Name> name = args.at<Name>(1);
  Handle<JSFunction> getter = args.at<JSFunction>(2);
  auto attrs = PropertyAttributesFromInt(args.smi_value_at(3));

  if (Cast<String>(getter->shared()->Name())->length() == 0) {
    DirectHandle<Map> getter_map(getter->map(), isolate);
    if (!JSFunction::SetName(getter, name, isolate->factory()->get_string())) {
      return ReadOnlyRoots(isolate).exception();
    }
    CHECK_EQ(*getter_map, getter->map());
  }

  RETURN_FAILURE_ON_EXCEPTION(
      isolate,
      JSObject::DefineOwnAccessorIgnoreAttributes(
          object, name, getter, isolate->factory()->null_value(), attrs));
  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_SetDataProperties) {
  HandleScope scope(isolate);
  DCHECK_EQ(2, args.length());
  Handle<JSReceiver> target = args.at<JSReceiver>(0);
  Handle<Object> source = args.at(1);

  // 2. If source is undefined or null, let keys be an empty List.
  if (IsUndefined(*source, isolate) || IsNull(*source, isolate)) {
    return ReadOnlyRoots(isolate).undefined_value();
  }

  MAYBE_RETURN(JSReceiver::SetOrCopyDataProperties(
                   isolate, target, source,
                   PropertiesEnumerationMode::kEnumerationOrder),
               ReadOnlyRoots(isolate).exception());
  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_CopyDataProperties) {
  HandleScope scope(isolate);
  DCHECK_EQ(2, args.length());
  Handle<JSObject> target = args.at<JSObject>(0);
  Handle<Object> source = args.at(1);

  // 2. If source is undefined or null, let keys be an empty List.
  if (IsUndefined(*source, isolate) || IsNull(*source, isolate)) {
    return ReadOnlyRoots(isolate).undefined_value();
  }

  MAYBE_RETURN(
      JSReceiver::SetOrCopyDataProperties(
          isolate, target, source,
          PropertiesEnumerationMode::kPropertyAdditionOrder, {}, false),
      ReadOnlyRoots(isolate).exception());
  return ReadOnlyRoots(isolate).undefined_value();
}

namespace {

// Check that the excluded properties are within the stack range of the top of
// the stack, and the start of the JS frame.
void CheckExcludedPropertiesAreOnCallerStack(Isolate* isolate, Address base,
                                             int count) {
#ifdef DEBUG
  StackFrameIterator it(isolate);

  // Don't need to check when there's no excluded properties.
  if (count == 0) return;

  DCHECK(!it.done());

  // Properties are pass in order on the stack, which means that their addresses
  // are in reverse order in memory (because stacks grow backwards). So, we
  // need to check if the _last_ property address is before the stack end...
  Address last_property = base - (count - 1) * kSystemPointerSize;
  DCHECK_GE(last_property, it.frame()->sp());

  // ... and for the first JS frame, make sure the _first_ property address is
  // after that stack frame's start.
  for (; !it.done(); it.Advance()) {
    if (it.frame()->is_javascript()) {
      DCHECK_LT(base, it.frame()->fp());
      return;
    }
  }

  // We should always find a JS frame.
  UNREACHABLE();
#endif
}

}  // namespace

RUNTIME_FUNCTION(Runtime_CopyDataPropertiesWithExcludedPropertiesOnStack) {
  HandleScope scope(isolate);
  DCHECK_EQ(3, args.length());
  Handle<Object> source = args.at(0);
  int excluded_property_count = args.smi_value_at(1);
  // The excluded_property_base is passed as a raw stack pointer. This is safe
  // because the stack pointer is aligned, so it looks like a Smi to the GC.
  Address* excluded_property_base = reinterpret_cast<Address*>(args[2].ptr());
  DCHECK(HAS_SMI_TAG(reinterpret_cast<intptr_t>(excluded_property_base)));
  // Also make sure that the given base pointer points to to on-stack values.
  CheckExcludedPropertiesAreOnCallerStack(
      isolate, reinterpret_cast<Address>(excluded_property_base),
      excluded_property_count);

  // If source is undefined or null, throw a non-coercible error.
  if (IsNullOrUndefined(*source, isolate)) {
    return ErrorUtils::ThrowLoadFromNullOrUndefined(isolate, source,
                                                    MaybeHandle<Object>());
  }

  DirectHandleVector<Object> excluded_properties(isolate,
                                                 excluded_property_count);
  for (int i = 0; i < excluded_property_count; i++) {
    // Because the excluded properties on stack is from high address
    // to low address, so we need to use sub
    Handle<Object> property(excluded_property_base - i);
    uint32_t property_num;
    // We convert string to number if possible, in cases of computed
    // properties resolving to numbers, which would've been strings
    // instead because of our call to %ToName() in the desugaring for
    // computed properties.
    if (IsString(*property) &&
        Cast<String>(*property)->AsArrayIndex(&property_num)) {
      property = isolate->factory()->NewNumberFromUint(property_num);
    }

    excluded_properties[i] = property;
  }

  Handle<JSObject> target =
      isolate->factory()->NewJSObject(isolate->object_function());
  MAYBE_RETURN(
      JSReceiver::SetOrCopyDataProperties(
          isolate, target, source,
          PropertiesEnumerationMode::kPropertyAdditionOrder,
          {excluded_properties.data(), excluded_properties.size()}, false),
      ReadOnlyRoots(isolate).exception());
  return *target;
}

RUNTIME_FUNCTION(Runtime_DefineSetterPropertyUnchecked) {
  HandleScope scope(isolate);
  DCHECK_EQ(4, args.length());
  Handle<JSObject> object = args.at<JSObject>(0);
  Handle<Name> name = args.at<Name>(1);
  Handle<JSFunction> setter = args.at<JSFunction>(2);
  auto attrs = PropertyAttributesFromInt(args.smi_value_at(3));

  if (Cast<String>(setter->shared()->Name())->length() == 0) {
    DirectHandle<Map> setter_map(setter->map(), isolate);
    if (!JSFunction::SetName(setter, name, isolate->factory()->set_string())) {
      return ReadOnlyRoots(isolate).exception();
    }
    CHECK_EQ(*setter_map, setter->map());
  }

  RETURN_FAILURE_ON_EXCEPTION(
      isolate,
      JSObject::DefineOwnAccessorIgnoreAttributes(
          object, name, isolate->factory()->null_value(), setter, attrs));
  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_ToObject) {
  // Runtime call is implemented in InterpreterIntrinsics and lowered in
  // JSIntrinsicLowering.
  UNREACHABLE();
}

RUNTIME_FUNCTION(Runtime_ToNumber) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  Handle<Object> input = args.at(0);
  RETURN_RESULT_OR_FAILURE(isolate, Object::ToNumber(isolate, input));
}

RUNTIME_FUNCTION(Runtime_ToNumeric) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  Handle<Object> input = args.at(0);
  RETURN_RESULT_OR_FAILURE(isolate, Object::ToNumeric(isolate, input));
}

RUNTIME_FUNCTION(Runtime_ToLength) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  Handle<Object> input = args.at(0);
  RETURN_RESULT_OR_FAILURE(isolate, Object::ToLength(isolate, input));
}

RUNTIME_FUNCTION(Runtime_ToString) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  Handle<Object> input = args.at(0);
  RETURN_RESULT_OR_FAILURE(isolate, Object::ToString(isolate, input));
}

RUNTIME_FUNCTION(Runtime_ToName) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  Handle<Object> input = args.at(0);
  RETURN_RESULT_OR_FAILURE(isolate, Object::ToName(isolate, input));
}

RUNTIME_FUNCTION(Runtime_HasInPrototypeChain) {
  HandleScope scope(isolate);
  DCHECK_EQ(2, args.length());
  Handle<Object> object = args.at(0);
  Handle<Object> prototype = args.at(1);
  if (!IsJSReceiver(*object)) return ReadOnlyRoots(isolate).false_value();
  Maybe<bool> result = JSReceiver::HasInPrototypeChain(
      isolate, Cast<JSReceiver>(object), prototype);
  MAYBE_RETURN(result, ReadOnlyRoots(isolate).exception());
  return isolate->heap()->ToBoolean(result.FromJust());
}

// ES6 section 7.4.7 CreateIterResultObject ( value, done )
RUNTIME_FUNCTION(Runtime_CreateIterResultObject) {
  HandleScope scope(isolate);
  DCHECK_EQ(2, args.length());
  DirectHandle<Object> value = args.at(0);
  DirectHandle<Object> done = args.at(1);
  return *isolate->factory()->NewJSIteratorResult(
      value, Object::BooleanValue(*done, isolate));
}

RUNTIME_FUNCTION(Runtime_CreateDataProperty) {
  HandleScope scope(isolate);
  DCHECK_EQ(3, args.length());
  Handle<JSReceiver> o = args.at<JSReceiver>(0);
  Handle<Object> key = args.at(1);
  Handle<Object> value = args.at(2);
  bool success;
  PropertyKey lookup_key(isolate, key, &success);
  if (!success) return ReadOnlyRoots(isolate).exception();
  MAYBE_RETURN(JSReceiver::CreateDataProperty(isolate, o, lookup_key, value,
                                              Just(kThrowOnError)),
               ReadOnlyRoots(isolate).exception());
  return *value;
}

RUNTIME_FUNCTION(Runtime_SetOwnPropertyIgnoreAttributes) {
  HandleScope scope(isolate);
  DCHECK_EQ(4, args.length());
  Handle<JSObject> o = args.at<JSObject>(0);
  Handle<String> key = args.at<String>(1);
  Handle<Object> value = args.at(2);
  int attributes = args.smi_value_at(3);

  RETURN_RESULT_OR_FAILURE(isolate,
                           JSObject::SetOwnPropertyIgnoreAttributes(
                               o, key, value, PropertyAttributes(attributes)));
}

// Returns a PropertyDescriptorObject (property-descriptor-object.h)
RUNTIME_FUNCTION(Runtime_GetOwnPropertyDescriptorObject) {
  HandleScope scope(isolate);

  DCHECK_EQ(2, args.length());
  Handle<JSReceiver> object = args.at<JSReceiver>(0);
  Handle<Name> name = args.at<Name>(1);

  PropertyDescriptor desc;
  Maybe<bool> found =
      JSReceiver::GetOwnPropertyDescriptor(isolate, object, name, &desc);
  MAYBE_RETURN(found, ReadOnlyRoots(isolate).exception());

  if (!found.FromJust()) return ReadOnlyRoots(isolate).undefined_value();
  return *desc.ToPropertyDescriptorObject(isolate);
}

enum class PrivateMemberType {
  kPrivateField,
  kPrivateAccessor,
  kPrivateMethod,
};

struct PrivateMember {
  PrivateMemberType type;
  // It's the class constructor for static methods/accessors,
  // the brand symbol for instance methods/accessors,
  // and the private name symbol for fields.
  Handle<Object> brand_or_field_symbol;
  Handle<Object> value;
};

namespace {
void CollectPrivateMethodsAndAccessorsFromContext(
    Isolate* isolate, DirectHandle<Context> context, Handle<String> desc,
    Handle<Object> brand, IsStaticFlag is_static_flag,
    std::vector<PrivateMember>* results) {
  DirectHandle<ScopeInfo> scope_info(context->scope_info(), isolate);
  VariableLookupResult lookup_result;
  int context_index = scope_info->ContextSlotIndex(desc, &lookup_result);
  if (context_index == -1 ||
      !IsPrivateMethodOrAccessorVariableMode(lookup_result.mode) ||
      lookup_result.is_static_flag != is_static_flag) {
    return;
  }

  Handle<Object> slot_value(context->get(context_index), isolate);
  DCHECK_IMPLIES(lookup_result.mode == VariableMode::kPrivateMethod,
                 IsJSFunction(*slot_value));
  DCHECK_IMPLIES(lookup_result.mode != VariableMode::kPrivateMethod,
                 IsAccessorPair(*slot_value));
  results->push_back({
      lookup_result.mode == VariableMode::kPrivateMethod
          ? PrivateMemberType::kPrivateMethod
          : PrivateMemberType::kPrivateAccessor,
      brand,
      slot_value,
  });
}

Maybe<bool> CollectPrivateMembersFromReceiver(
    Isolate* isolate, Handle<JSReceiver> receiver, Handle<String> desc,
    std::vector<PrivateMember>* results) {
  PropertyFilter key_filter =
      static_cast<PropertyFilter>(PropertyFilter::PRIVATE_NAMES_ONLY);
  Handle<FixedArray> keys;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, keys,
      KeyAccumulator::GetKeys(isolate, receiver, KeyCollectionMode::kOwnOnly,
                              key_filter, GetKeysConversion::kConvertToString),
      Nothing<bool>());

  if (IsJSFunction(*receiver)) {
    Handle<JSFunction> func(Cast<JSFunction>(*receiver), isolate);
    DirectHandle<SharedFunctionInfo> shared(func->shared(), isolate);
    if (shared->is_class_constructor() &&
        shared->has_static_private_methods_or_accessors()) {
      DirectHandle<Context> receiver_context(
          Cast<JSFunction>(*receiver)->context(), isolate);
      CollectPrivateMethodsAndAccessorsFromContext(
          isolate, receiver_context, desc, func, IsStaticFlag::kStatic,
          results);
    }
  }

  for (int i = 0; i < keys->length(); ++i) {
    DirectHandle<Object> obj_key(keys->get(i), isolate);
    Handle<Symbol> symbol(Cast<Symbol>(*obj_key), isolate);
    CHECK(symbol->is_private_name());
    Handle<Object> value;
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, value, Object::GetProperty(isolate, receiver, symbol),
        Nothing<bool>());

    if (symbol->is_private_brand()) {
      DirectHandle<Context> value_context(Cast<Context>(*value), isolate);
      CollectPrivateMethodsAndAccessorsFromContext(
          isolate, value_context, desc, symbol, IsStaticFlag::kNotStatic,
          results);
    } else {
      DirectHandle<String> symbol_desc(Cast<String>(symbol->description()),
                                       isolate);
      if (symbol_desc->Equals(*desc)) {
        results->push_back({
            PrivateMemberType::kPrivateField,
            symbol,
            value,
        });
      }
    }
  }

  return Just(true);
}

Maybe<bool> FindPrivateMembersFromReceiver(Isolate* isolate,
                                           Handle<JSReceiver> receiver,
                                           Handle<String> desc,
                                           MessageTemplate not_found_message,
                                           PrivateMember* result) {
  std::vector<PrivateMember> results;
  MAYBE_RETURN(
      CollectPrivateMembersFromReceiver(isolate, receiver, desc, &results),
      Nothing<bool>());

  if (results.empty()) {
    THROW_NEW_ERROR_RETURN_VALUE(isolate, NewError(not_found_message, desc),
                                 Nothing<bool>());
  } else if (results.size() > 1) {
    THROW_NEW_ERROR_RETURN_VALUE(
        isolate, NewError(MessageTemplate::kConflictingPrivateName, desc),
        Nothing<bool>());
  }

  *result = results[0];
  return Just(true);
}
}  // namespace

MaybeHandle<Object> Runtime::GetPrivateMember(Isolate* isolate,
                                              Handle<JSReceiver> receiver,
                                              Handle<String> desc) {
  PrivateMember result;
  MAYBE_RETURN_NULL(FindPrivateMembersFromReceiver(
      isolate, receiver, desc, MessageTemplate::kInvalidPrivateMemberRead,
      &result));

  switch (result.type) {
    case PrivateMemberType::kPrivateField:
    case PrivateMemberType::kPrivateMethod: {
      return result.value;
    }
    case PrivateMemberType::kPrivateAccessor: {
      // The accessors are collected from the contexts, so there is no need to
      // perform brand checks.
      auto pair = Cast<AccessorPair>(result.value);
      if (IsNull(pair->getter())) {
        THROW_NEW_ERROR(
            isolate,
            NewError(MessageTemplate::kInvalidPrivateGetterAccess, desc));
      }
      DCHECK(IsJSFunction(pair->getter()));
      Handle<JSFunction> getter(Cast<JSFunction>(pair->getter()), isolate);
      return Execution::Call(isolate, getter, receiver, 0, nullptr);
    }
  }
}

MaybeHandle<Object> Runtime::SetPrivateMember(Isolate* isolate,
                                              Handle<JSReceiver> receiver,
                                              Handle<String> desc,
                                              Handle<Object> value) {
  PrivateMember result;
  MAYBE_RETURN_NULL(FindPrivateMembersFromReceiver(
      isolate, receiver, desc, MessageTemplate::kInvalidPrivateMemberRead,
      &result));

  switch (result.type) {
    case PrivateMemberType::kPrivateField: {
      auto symbol = Cast<Symbol>(result.brand_or_field_symbol);
      return Object::SetProperty(isolate, receiver, symbol, value,
                                 StoreOrigin::kMaybeKeyed);
    }
    case PrivateMemberType::kPrivateMethod: {
      THROW_NEW_ERROR(
          isolate, NewError(MessageTemplate::kInvalidPrivateMethodWrite, desc));
    }
    case PrivateMemberType::kPrivateAccessor: {
      // The accessors are collected from the contexts, so there is no need to
      // perform brand checks.
      auto pair = Cast<AccessorPair>(result.value);
      if (IsNull(pair->setter())) {
        THROW_NEW_ERROR(
            isolate,
            NewError(MessageTemplate::kInvalidPrivateSetterAccess, desc));
      }
      DCHECK(IsJSFunction(pair->setter()));
      Handle<Object> argv[] = {value};
      Handle<JSFunction> setter(Cast<JSFunction>(pair->setter()), isolate);
      return Execution::Call(isolate, setter, receiver, arraysize(argv), argv);
    }
  }
}

RUNTIME_FUNCTION(Runtime_GetPrivateMember) {
  HandleScope scope(isolate);
  // TODO(chromium:1381806) support specifying scopes, or selecting the right
  // one from the conflicting names.
  DCHECK_EQ(args.length(), 2);
  Handle<Object> receiver = args.at<Object>(0);
  Handle<String> desc = args.at<String>(1);
  if (IsNullOrUndefined(*receiver, isolate)) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewTypeError(MessageTemplate::kNonObjectPrivateNameAccess,
                              desc, receiver));
  }
  RETURN_RESULT_OR_FAILURE(
      isolate,
      Runtime::GetPrivateMember(isolate, Cast<JSReceiver>(receiver), desc));
}

RUNTIME_FUNCTION(Runtime_SetPrivateMember) {
  HandleScope scope(isolate);
  // TODO(chromium:1381806) support specifying scopes, or selecting the right
  // one from the conflicting names.
  DCHECK_EQ(args.length(), 3);
  Handle<Object> receiver = args.at<Object>(0);
  Handle<String> desc = args.at<String>(1);
  if (IsNullOrUndefined(*receiver, isolate)) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewTypeError(MessageTemplate::kNonObjectPrivateNameAccess,
                              desc, receiver));
  }
  Handle<Object> value = args.at<Object>(2);
  RETURN_RESULT_OR_FAILURE(
      isolate, Runtime::SetPrivateMember(isolate, Cast<JSReceiver>(receiver),
                                         desc, value));
}

RUNTIME_FUNCTION(Runtime_LoadPrivateSetter) {
  HandleScope scope(isolate);
  DCHECK_EQ(args.length(), 1);
  DirectHandle<AccessorPair> pair = args.at<AccessorPair>(0);
  DCHECK(IsJSFunction(pair->setter()));
  return pair->setter();
}

RUNTIME_FUNCTION(Runtime_LoadPrivateGetter) {
  HandleScope scope(isolate);
  DCHECK_EQ(args.length(), 1);
  DirectHandle<AccessorPair> pair = args.at<AccessorPair>(0);
  DCHECK(IsJSFunction(pair->getter()));
  return pair->getter();
}

RUNTIME_FUNCTION(Runtime_CreatePrivateAccessors) {
  HandleScope scope(isolate);
  DCHECK_EQ(args.length(), 2);
  DCHECK(IsNull(args[0]) || IsJSFunction(args[0]));
  DCHECK(IsNull(args[1]) || IsJSFunction(args[1]));
  DirectHandle<AccessorPair> pair = isolate->factory()->NewAccessorPair();
  pair->SetComponents(args[0], args[1]);
  return *pair;
}

// TODO(v8:11330) This is only here while the CSA/Torque implementaton of
// SwissNameDictionary is work in progress.
RUNTIME_FUNCTION(Runtime_SwissTableAllocate) {
  HandleScope scope(isolate);
  int at_least_space_for = args.smi_value_at(0);

  return *isolate->factory()->NewSwissNameDictionary(at_least_space_for,
                                                     AllocationType::kYoung);
}

// TODO(v8:11330) This is only here while the CSA/Torque implementaton of
// SwissNameDictionary is work in progress.
RUNTIME_FUNCTION(Runtime_SwissTableAdd) {
  HandleScope scope(isolate);
  Handle<SwissNameDictionary> table = args.at<SwissNameDictionary>(0);
  DirectHandle<Name> key = args.at<Name>(1);
  DirectHandle<Object> value = args.at(2);
  PropertyDetails details(Cast<Smi>(args[3]));

  DCHECK(IsUniqueName(*key));

  return *SwissNameDictionary::Add(isolate, table, key, value, details);
}

// TODO(v8:11330) This is only here while the CSA/Torque implementaton of
// SwissNameDictionary is work in progress.
RUNTIME_FUNCTION(Runtime_SwissTableFindEntry) {
  HandleScope scope(isolate);
  DisallowGarbageCollection no_gc;
  auto table = Cast<SwissNameDictionary>(args[0]);
  Tagged<Name> key = Cast<Name>(args[1]);
  InternalIndex index = table->FindEntry(isolate, key);
  return Smi::FromInt(index.is_found()
                          ? index.as_int()
                          : SwissNameDictionary::kNotFoundSentinel);
}

// TODO(v8:11330) This is only here while the CSA/Torque implementaton of
// SwissNameDictionary is work in progress.
RUNTIME_FUNCTION(Runtime_SwissTableUpdate) {
  HandleScope scope(isolate);
  DisallowGarbageCollection no_gc;
  auto table = Cast<SwissNameDictionary>(args[0]);
  InternalIndex index(args.smi_value_at(1));
  Tagged<Object> value = args[2];
  table->ValueAtPut(index, value);

  PropertyDetails details(Cast<Smi>(args[3]));
  table->DetailsAtPut(index, details);

  return ReadOnlyRoots(isolate).undefined_value();
}

// TODO(v8:11330) This is only here while the CSA/Torque implementaton of
// SwissNameDictionary is work in progress.
RUNTIME_FUNCTION(Runtime_SwissTableDelete) {
  HandleScope scope(isolate);
  Handle<SwissNameDictionary> table = args.at<SwissNameDictionary>(0);
  InternalIndex index(args.smi_value_at(1));

  return *SwissNameDictionary::DeleteEntry(isolate, table, index);
}

// TODO(v8:11330) This is only here while the CSA/Torque implementaton of
// SwissNameDictionary is work in progress.
RUNTIME_FUNCTION(Runtime_SwissTableEquals) {
  HandleScope scope(isolate);
  DisallowGarbageCollection no_gc;
  auto table = Cast<SwissNameDictionary>(args[0]);
  auto other = Cast<SwissNameDictionary>(args[0]);
  return Smi::FromInt(table->EqualsForTesting(other));
}

// TODO(v8:11330) This is only here while the CSA/Torque implementaton of
// SwissNameDictionary is work in progress.
RUNTIME_FUNCTION(Runtime_SwissTableElementsCount) {
  HandleScope scope(isolate);
  DisallowGarbageCollection no_gc;
  auto table = Cast<SwissNameDictionary>(args[0]);
  return Smi::FromInt(table->NumberOfElements());
}

// TODO(v8:11330) This is only here while the CSA/Torque implementaton of
// SwissNameDictionary is work in progress.
RUNTIME_FUNCTION(Runtime_SwissTableKeyAt) {
  HandleScope scope(isolate);
  DisallowGarbageCollection no_gc;
  auto table = Cast<SwissNameDictionary>(args[0]);
  InternalIndex index(args.smi_value_at(1));
  return table->KeyAt(index);
}

// TODO(v8:11330) This is only here while the CSA/Torque implementaton of
// SwissNameDictionary is work in progress.
RUNTIME_FUNCTION(Runtime_SwissTableValueAt) {
  HandleScope scope(isolate);
  DisallowGarbageCollection no_gc;
  auto table = Cast<SwissNameDictionary>(args[0]);
  InternalIndex index(args.smi_value_at(1));
  return table->ValueAt(index);
}

// TODO(v8:11330) This is only here while the CSA/Torque implementaton of
// SwissNameDictionary is work in progress.
RUNTIME_FUNCTION(Runtime_SwissTableDetailsAt) {
  HandleScope scope(isolate);
  DisallowGarbageCollection no_gc;
  auto table = Cast<SwissNameDictionary>(args[0]);
  InternalIndex index(args.smi_value_at(1));
  PropertyDetails d = table->DetailsAt(index);
  return d.AsSmi();
}

}  // namespace internal
}  // namespace v8
```