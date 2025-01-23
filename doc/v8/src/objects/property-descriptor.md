Response: Let's break down the thought process for analyzing the C++ code and generating the summary and JavaScript examples.

**1. Understanding the Goal:**

The request asks for the functionality of the C++ file `property-descriptor.cc` within the V8 engine and its relationship to JavaScript, with examples. This means I need to understand *what* this code does and *how* that relates to something a JavaScript developer would recognize.

**2. Initial Scan and Keyword Spotting:**

I'd start by quickly scanning the code for key terms and patterns. I see things like:

* `PropertyDescriptor`: This is the central concept, so I'd focus on how it's used.
* `enumerable`, `configurable`, `writable`, `value`, `get`, `set`: These are the familiar attributes of JavaScript properties.
* `ToPropertyDescriptor`, `ToObject`, `CompletePropertyDescriptor`: These look like functions related to converting to and from the `PropertyDescriptor` representation.
* `JSObject`, `Handle`, `Isolate`: These are V8-specific types, indicating this code is deeply embedded in the engine.
* `CreateDataProperty`: Suggests a mechanism for creating properties.
* `FastPath`, `SlowPath`:  Hints at optimization strategies.

**3. Focusing on Key Functions:**

The function names `ToPropertyDescriptor` and `ToObject` immediately stand out as important.

* **`ToPropertyDescriptor`:** This function takes a JavaScript object and converts it into a `PropertyDescriptor` C++ object. The code clearly follows the steps of the ECMAScript specification for this operation (e.g., steps 4-23 are explicitly numbered). It checks for the presence of "enumerable", "configurable", "value", "writable", "get", and "set" properties on the input JavaScript object and extracts their values. The "fast path" optimization is interesting, suggesting efficiency considerations.

* **`ToObject`:**  This function does the reverse – it takes a `PropertyDescriptor` C++ object and converts it back into a JavaScript object. The logic here shows how the internal representation maps back to standard JavaScript objects with the appropriate property attributes.

* **`CompletePropertyDescriptor`:** This function takes an *incomplete* `PropertyDescriptor` and fills in any missing default values according to the ECMAScript specification. This is important for ensuring that property descriptors are well-defined.

**4. Connecting to JavaScript Concepts:**

At this point, I can start making the connection to JavaScript. The attributes `enumerable`, `configurable`, `writable`, `value`, `get`, and `set` directly correspond to the attributes you can set when defining or modifying properties in JavaScript using `Object.defineProperty` or the shorter object literal syntax.

**5. Developing JavaScript Examples:**

Now the goal is to illustrate the C++ code's functionality with understandable JavaScript.

* **`ToObject` Example:**  The C++ code creates a JavaScript object from a `PropertyDescriptor`. The JavaScript equivalent is to define an object literal with the same properties and their values. I'd create examples for both data and accessor properties.

* **`ToPropertyDescriptor` Example:** The C++ code takes a JavaScript object and converts it *to* a `PropertyDescriptor`. The JavaScript equivalent is using `Object.getOwnPropertyDescriptor()` to retrieve the descriptor of a property. I'd demonstrate how a regular object and an object mimicking a property descriptor are handled.

* **`CompletePropertyDescriptor` Example:** This function fills in missing defaults. The JavaScript equivalent isn't a direct function call, but the *behavior* is reflected in how JavaScript treats partially defined descriptors. When you define a property with `Object.defineProperty` and omit some attributes, JavaScript provides the default values. I'd illustrate this by showing how omitting attributes results in the default values being applied.

**6. Explaining the "Why":**

It's crucial to explain *why* this C++ code exists. It's a fundamental part of the V8 engine's implementation of JavaScript's property model. It's used internally when JavaScript code interacts with properties, whether during object creation, property access, or modification.

**7. Refinement and Clarity:**

Finally, I'd review the summary and examples for clarity and accuracy. I'd make sure the language is easy to understand, even for someone not deeply familiar with V8 internals. I would also ensure the examples are correct and effectively demonstrate the connection between the C++ code and JavaScript behavior. For example, explicitly mentioning the ECMAScript specification helps solidify the purpose of the code. Highlighting the "fast path" optimization also adds a layer of understanding about V8's performance considerations.

This systematic approach, starting with understanding the core concept, dissecting the key functions, connecting to JavaScript, and then illustrating with examples, allows for a comprehensive and informative explanation of the given C++ code.
这个 C++ 代码文件 `property-descriptor.cc` 的主要功能是**管理和操作 JavaScript 中属性描述符 (Property Descriptors)**。它是 V8 引擎（JavaScript 引擎）内部实现 JavaScript 对象属性行为的关键部分。

**具体功能归纳如下:**

1. **表示属性描述符:**  该文件定义了 `PropertyDescriptor` 类，用于在 C++ 层面表示 JavaScript 属性的各种特性，例如：
    * `value`: 属性的值。
    * `writable`:  属性是否可写。
    * `enumerable`: 属性是否可枚举（是否会出现在 `for...in` 循环中）。
    * `configurable`: 属性是否可配置（是否可以删除或修改属性描述符）。
    * `get`:  属性的 getter 函数。
    * `set`:  属性的 setter 函数。

2. **与 JavaScript 对象之间的转换:**  提供了以下关键函数进行 C++ 的 `PropertyDescriptor` 和 JavaScript 对象之间的转换：
    * **`ToObject(Isolate* isolate)`:**  将 C++ 的 `PropertyDescriptor` 对象转换成一个 JavaScript 对象。这个 JavaScript 对象会包含 `value`, `writable`, `enumerable`, `configurable`, `get`, `set` 等属性，其值对应 `PropertyDescriptor` 中的设置。
    * **`ToPropertyDescriptor(Isolate* isolate, Handle<JSAny> obj, PropertyDescriptor* desc)`:** 将一个 JavaScript 对象转换成 C++ 的 `PropertyDescriptor` 对象。它会检查 JavaScript 对象上的特定属性（"enumerable", "configurable", "value", "writable", "get", "set"）来填充 `PropertyDescriptor` 对象。这个过程严格遵循 ECMAScript 规范中定义的 "ToPropertyDescriptor" 抽象操作。

3. **处理属性描述符的默认值:**  `CompletePropertyDescriptor(Isolate* isolate, PropertyDescriptor* desc)` 函数用于补全一个属性描述符的缺失字段。例如，如果一个属性描述符没有显式设置 `enumerable`，该函数会将其设置为 `false`。这对应了 ECMAScript 规范中描述的属性描述符的默认值。

4. **优化转换过程:**  代码中包含 `ToPropertyDescriptorFastPath` 函数，这是一个优化的路径，用于处理具有简单结构的 JavaScript 对象到属性描述符的转换。这避免了在原型链上进行查找，提高了性能。

5. **创建数据属性的辅助函数:**  `CreateDataProperty` 函数用于在 JavaScript 对象上创建数据属性。

**与 JavaScript 的关系及示例:**

这个文件直接关系到 JavaScript 中如何定义和操作对象属性。  `PropertyDescriptor` 在 JavaScript 中可以通过 `Object.getOwnPropertyDescriptor()` 和 `Object.defineProperty()` 等方法进行访问和修改。

**JavaScript 示例:**

**1. `ToObject` 的对应 (将 Property Descriptor 转换为 JavaScript 对象):**

```javascript
// 在 V8 引擎内部，当需要将一个 PropertyDescriptor 传递给 JavaScript 时，
// 会调用 PropertyDescriptor::ToObject。

// 假设在 C++ 层面创建了一个 PropertyDescriptor：
// PropertyDescriptor desc;
// desc.set_value(Handle<String>("hello"));
// desc.set_writable(true);
// desc.set_enumerable(true);
// desc.set_configurable(false);
// Handle<JSObject> jsObject = desc.ToObject(isolate);

// 在 JavaScript 中，这相当于创建了以下对象：
const jsObjectEquivalent = {
  value: "hello",
  writable: true,
  enumerable: true,
  configurable: false
};
```

**2. `ToPropertyDescriptor` 的对应 (将 JavaScript 对象转换为 Property Descriptor):**

```javascript
// 在 V8 引擎内部，当 JavaScript 代码调用 Object.getOwnPropertyDescriptor() 时，
// 会调用 PropertyDescriptor::ToPropertyDescriptor。

const myObject = {
  a: 10,
  get b() { return 20; }
};

// JavaScript 代码：
const descriptorA = Object.getOwnPropertyDescriptor(myObject, 'a');
const descriptorB = Object.getOwnPropertyDescriptor(myObject, 'b');

console.log(descriptorA);
// 输出: { value: 10, writable: true, enumerable: true, configurable: true }

console.log(descriptorB);
// 输出: { get: [Function: b], set: undefined, enumerable: true, configurable: true }

// 在 V8 引擎内部，当调用 Object.getOwnPropertyDescriptor(myObject, 'a') 时，
// V8 会遍历 myObject 的属性，并根据属性的特性填充一个 PropertyDescriptor 对象。
// 对于属性 'a'，V8 内部的 PropertyDescriptor 可能会有类似以下的设置：
// desc_a.set_value(Handle<Smi>(10));
// desc_a.set_writable(true);
// desc_a.set_enumerable(true);
// desc_a.set_configurable(true);

// 当调用 Object.getOwnPropertyDescriptor(myObject, 'b') 时，
// V8 内部的 PropertyDescriptor 可能会有类似以下的设置：
// desc_b.set_get(Handle<JSFunction>(myObject.b));
// desc_b.set_enumerable(true);
// desc_b.set_configurable(true);
```

**3. `CompletePropertyDescriptor` 的对应 (属性描述符的默认值):**

```javascript
// 在 V8 引擎内部，当使用 Object.defineProperty() 创建或修改属性时，
// 如果没有提供某些属性描述符，V8 会调用 CompletePropertyDescriptor 来设置默认值。

const emptyObject = {};

// JavaScript 代码：
Object.defineProperty(emptyObject, 'c', { value: 30 });

// 相当于在 V8 内部，创建了一个 PropertyDescriptor 并设置了 value，
// 然后调用 CompletePropertyDescriptor 来填充缺失的字段：
// PropertyDescriptor desc_c;
// desc_c.set_value(Handle<Smi>(30));
// PropertyDescriptor::CompletePropertyDescriptor(isolate, &desc_c);

// 完成后，desc_c 的 writable, enumerable, configurable 都会是默认值 false。

const descriptorC = Object.getOwnPropertyDescriptor(emptyObject, 'c');
console.log(descriptorC);
// 输出: { value: 30, writable: false, enumerable: false, configurable: false }
```

**总结:**

`v8/src/objects/property-descriptor.cc` 文件是 V8 引擎中处理 JavaScript 属性描述符的核心组件。它负责在 C++ 层面表示和操作属性的各种特性，并提供了与 JavaScript 对象之间相互转换的功能。这使得 V8 能够正确地实现 JavaScript 的属性行为，例如属性的读写、枚举、配置以及 getter/setter 的工作方式。 理解这个文件有助于深入理解 JavaScript 引擎的内部工作原理。

### 提示词
```
这是目录为v8/src/objects/property-descriptor.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
// Copyright 2011 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/objects/property-descriptor.h"

#include "src/common/assert-scope.h"
#include "src/execution/isolate-inl.h"
#include "src/heap/factory.h"
#include "src/heap/heap-inl.h"  // For ToBoolean. TODO(jkummerow): Drop.
#include "src/init/bootstrapper.h"
#include "src/objects/lookup.h"
#include "src/objects/objects-inl.h"
#include "src/objects/property-descriptor-object-inl.h"

namespace v8 {
namespace internal {

namespace {

// Helper function for ToPropertyDescriptor. Comments describe steps for
// "enumerable", other properties are handled the same way.
// Returns false if an exception was thrown.
bool GetPropertyIfPresent(Isolate* isolate, Handle<JSReceiver> receiver,
                          Handle<String> name, Handle<JSAny>* value) {
  LookupIterator it(isolate, receiver, name, receiver);
  // 4. Let hasEnumerable be HasProperty(Obj, "enumerable").
  Maybe<bool> has_property = JSReceiver::HasProperty(&it);
  // 5. ReturnIfAbrupt(hasEnumerable).
  if (has_property.IsNothing()) return false;
  // 6. If hasEnumerable is true, then
  if (has_property.FromJust() == true) {
    // 6a. Let enum be ToBoolean(Get(Obj, "enumerable")).
    // 6b. ReturnIfAbrupt(enum).
    if (!Cast<JSAny>(Object::GetProperty(&it)).ToHandle(value)) return false;
  }
  return true;
}

// Helper function for ToPropertyDescriptor. Handles the case of "simple"
// objects: nothing on the prototype chain, just own fast data properties.
// Must not have observable side effects, because the slow path will restart
// the entire conversion!
bool ToPropertyDescriptorFastPath(Isolate* isolate, Handle<JSReceiver> obj,
                                  PropertyDescriptor* desc) {
  {
    DisallowGarbageCollection no_gc;
    Tagged<JSReceiver> raw_obj = *obj;
    if (!IsJSObject(*raw_obj)) return false;
    Tagged<Map> raw_map = raw_obj->map(isolate);
    if (raw_map->instance_type() != JS_OBJECT_TYPE) return false;
    if (raw_map->is_access_check_needed()) return false;
    if (raw_map->prototype() != *isolate->initial_object_prototype())
      return false;
    // During bootstrapping, the object_function_prototype_map hasn't been
    // set up yet.
    if (isolate->bootstrapper()->IsActive()) return false;
    if (Cast<JSObject>(raw_map->prototype())->map() !=
        isolate->raw_native_context()->object_function_prototype_map()) {
      return false;
    }
    // TODO(jkummerow): support dictionary properties?
    if (raw_map->is_dictionary_map()) return false;
  }

  DirectHandle<Map> map(obj->map(isolate), isolate);

  DirectHandle<DescriptorArray> descs(map->instance_descriptors(isolate),
                                      isolate);
  ReadOnlyRoots roots(isolate);
  for (InternalIndex i : map->IterateOwnDescriptors()) {
    PropertyDetails details = descs->GetDetails(i);
    Handle<Object> value;
    if (details.location() == PropertyLocation::kField) {
      if (details.kind() == PropertyKind::kData) {
        value = JSObject::FastPropertyAt(isolate, Cast<JSObject>(obj),
                                         details.representation(),
                                         FieldIndex::ForDetails(*map, details));
      } else {
        DCHECK_EQ(PropertyKind::kAccessor, details.kind());
        // Bail out to slow path.
        return false;
      }

    } else {
      DCHECK_EQ(PropertyLocation::kDescriptor, details.location());
      if (details.kind() == PropertyKind::kData) {
        value = handle(descs->GetStrongValue(i), isolate);
      } else {
        DCHECK_EQ(PropertyKind::kAccessor, details.kind());
        // Bail out to slow path.
        return false;
      }
    }
    Tagged<Name> key = descs->GetKey(i);
    if (key == roots.enumerable_string()) {
      desc->set_enumerable(Object::BooleanValue(*value, isolate));
    } else if (key == roots.configurable_string()) {
      desc->set_configurable(Object::BooleanValue(*value, isolate));
    } else if (key == roots.value_string()) {
      desc->set_value(Cast<JSAny>(value));
    } else if (key == roots.writable_string()) {
      desc->set_writable(Object::BooleanValue(*value, isolate));
    } else if (key == roots.get_string()) {
      // Bail out to slow path to throw an exception if necessary.
      if (!IsCallable(*value)) return false;
      desc->set_get(Cast<JSAny>(value));
    } else if (key == roots.set_string()) {
      // Bail out to slow path to throw an exception if necessary.
      if (!IsCallable(*value)) return false;
      desc->set_set(Cast<JSAny>(value));
    }
  }
  if ((desc->has_get() || desc->has_set()) &&
      (desc->has_value() || desc->has_writable())) {
    // Bail out to slow path to throw an exception.
    return false;
  }
  return true;
}

void CreateDataProperty(Isolate* isolate, Handle<JSObject> object,
                        Handle<String> name, Handle<Object> value) {
  Maybe<bool> result = JSObject::CreateDataProperty(
      isolate, object, PropertyKey(isolate, Cast<Name>(name)), value);
  CHECK(result.IsJust() && result.FromJust());
}

}  // namespace

// ES6 6.2.4.4 "FromPropertyDescriptor"
Handle<JSObject> PropertyDescriptor::ToObject(Isolate* isolate) {
  DCHECK(!(PropertyDescriptor::IsAccessorDescriptor(this) &&
           PropertyDescriptor::IsDataDescriptor(this)));
  Factory* factory = isolate->factory();
  if (IsRegularAccessorProperty()) {
    // Fast case for regular accessor properties.
    Handle<JSObject> result = factory->NewJSObjectFromMap(
        isolate->accessor_property_descriptor_map());
    result->InObjectPropertyAtPut(JSAccessorPropertyDescriptor::kGetIndex,
                                  *get());
    result->InObjectPropertyAtPut(JSAccessorPropertyDescriptor::kSetIndex,
                                  *set());
    result->InObjectPropertyAtPut(
        JSAccessorPropertyDescriptor::kEnumerableIndex,
        isolate->heap()->ToBoolean(enumerable()));
    result->InObjectPropertyAtPut(
        JSAccessorPropertyDescriptor::kConfigurableIndex,
        isolate->heap()->ToBoolean(configurable()));
    return result;
  }
  if (IsRegularDataProperty()) {
    // Fast case for regular data properties.
    Handle<JSObject> result =
        factory->NewJSObjectFromMap(isolate->data_property_descriptor_map());
    result->InObjectPropertyAtPut(JSDataPropertyDescriptor::kValueIndex,
                                  *value());
    result->InObjectPropertyAtPut(JSDataPropertyDescriptor::kWritableIndex,
                                  isolate->heap()->ToBoolean(writable()));
    result->InObjectPropertyAtPut(JSDataPropertyDescriptor::kEnumerableIndex,
                                  isolate->heap()->ToBoolean(enumerable()));
    result->InObjectPropertyAtPut(JSDataPropertyDescriptor::kConfigurableIndex,
                                  isolate->heap()->ToBoolean(configurable()));
    return result;
  }
  Handle<JSObject> result = factory->NewJSObject(isolate->object_function());
  if (has_value()) {
    CreateDataProperty(isolate, result, factory->value_string(), value());
  }
  if (has_writable()) {
    CreateDataProperty(isolate, result, factory->writable_string(),
                       factory->ToBoolean(writable()));
  }
  if (has_get()) {
    CreateDataProperty(isolate, result, factory->get_string(), get());
  }
  if (has_set()) {
    CreateDataProperty(isolate, result, factory->set_string(), set());
  }
  if (has_enumerable()) {
    CreateDataProperty(isolate, result, factory->enumerable_string(),
                       factory->ToBoolean(enumerable()));
  }
  if (has_configurable()) {
    CreateDataProperty(isolate, result, factory->configurable_string(),
                       factory->ToBoolean(configurable()));
  }
  return result;
}

// ES6 6.2.4.5
// Returns false in case of exception.
// static
bool PropertyDescriptor::ToPropertyDescriptor(Isolate* isolate,
                                              Handle<JSAny> obj,
                                              PropertyDescriptor* desc) {
  // 1. ReturnIfAbrupt(Obj).
  // 2. If Type(Obj) is not Object, throw a TypeError exception.
  if (!IsJSReceiver(*obj)) {
    isolate->Throw(*isolate->factory()->NewTypeError(
        MessageTemplate::kPropertyDescObject, obj));
    return false;
  }
  // 3. Let desc be a new Property Descriptor that initially has no fields.
  DCHECK(desc->is_empty());

  Handle<JSReceiver> receiver = Cast<JSReceiver>(obj);
  if (ToPropertyDescriptorFastPath(isolate, receiver, desc)) {
    return true;
  }

  // enumerable?
  Handle<JSAny> enumerable;
  // 4 through 6b.
  if (!GetPropertyIfPresent(isolate, receiver,
                            isolate->factory()->enumerable_string(),
                            &enumerable)) {
    return false;
  }
  // 6c. Set the [[Enumerable]] field of desc to enum.
  if (!enumerable.is_null()) {
    desc->set_enumerable(Object::BooleanValue(*enumerable, isolate));
  }

  // configurable?
  Handle<JSAny> configurable;
  // 7 through 9b.
  if (!GetPropertyIfPresent(isolate, receiver,
                            isolate->factory()->configurable_string(),
                            &configurable)) {
    return false;
  }
  // 9c. Set the [[Configurable]] field of desc to conf.
  if (!configurable.is_null()) {
    desc->set_configurable(Object::BooleanValue(*configurable, isolate));
  }

  // value?
  Handle<JSAny> value;
  // 10 through 12b.
  if (!GetPropertyIfPresent(isolate, receiver,
                            isolate->factory()->value_string(), &value)) {
    return false;
  }
  // 12c. Set the [[Value]] field of desc to value.
  if (!value.is_null()) desc->set_value(value);

  // writable?
  Handle<JSAny> writable;
  // 13 through 15b.
  if (!GetPropertyIfPresent(isolate, receiver,
                            isolate->factory()->writable_string(), &writable)) {
    return false;
  }
  // 15c. Set the [[Writable]] field of desc to writable.
  if (!writable.is_null())
    desc->set_writable(Object::BooleanValue(*writable, isolate));

  // getter?
  Handle<JSAny> getter;
  // 16 through 18b.
  if (!GetPropertyIfPresent(isolate, receiver, isolate->factory()->get_string(),
                            &getter)) {
    return false;
  }
  if (!getter.is_null()) {
    // 18c. If IsCallable(getter) is false and getter is not undefined,
    // throw a TypeError exception.
    if (!IsCallable(*getter) && !IsUndefined(*getter, isolate)) {
      isolate->Throw(*isolate->factory()->NewTypeError(
          MessageTemplate::kObjectGetterCallable, getter));
      return false;
    }
    // 18d. Set the [[Get]] field of desc to getter.
    desc->set_get(getter);
  }
  // setter?
  Handle<JSAny> setter;
  // 19 through 21b.
  if (!GetPropertyIfPresent(isolate, receiver, isolate->factory()->set_string(),
                            &setter)) {
    return false;
  }
  if (!setter.is_null()) {
    // 21c. If IsCallable(setter) is false and setter is not undefined,
    // throw a TypeError exception.
    if (!IsCallable(*setter) && !IsUndefined(*setter, isolate)) {
      isolate->Throw(*isolate->factory()->NewTypeError(
          MessageTemplate::kObjectSetterCallable, setter));
      return false;
    }
    // 21d. Set the [[Set]] field of desc to setter.
    desc->set_set(setter);
  }

  // 22. If either desc.[[Get]] or desc.[[Set]] is present, then
  // 22a. If either desc.[[Value]] or desc.[[Writable]] is present,
  // throw a TypeError exception.
  if ((desc->has_get() || desc->has_set()) &&
      (desc->has_value() || desc->has_writable())) {
    isolate->Throw(*isolate->factory()->NewTypeError(
        MessageTemplate::kValueAndAccessor, obj));
    return false;
  }

  // 23. Return desc.
  return true;
}

// ES6 6.2.4.6
// static
void PropertyDescriptor::CompletePropertyDescriptor(Isolate* isolate,
                                                    PropertyDescriptor* desc) {
  // 1. ReturnIfAbrupt(Desc).
  // 2. Assert: Desc is a Property Descriptor.
  // 3. Let like be Record{
  //        [[Value]]: undefined, [[Writable]]: false,
  //        [[Get]]: undefined, [[Set]]: undefined,
  //        [[Enumerable]]: false, [[Configurable]]: false}.
  // 4. If either IsGenericDescriptor(Desc) or IsDataDescriptor(Desc) is true,
  // then:
  if (!IsAccessorDescriptor(desc)) {
    // 4a. If Desc does not have a [[Value]] field, set Desc.[[Value]] to
    //     like.[[Value]].
    if (!desc->has_value()) {
      desc->set_value(isolate->factory()->undefined_value());
    }
    // 4b. If Desc does not have a [[Writable]] field, set Desc.[[Writable]]
    //     to like.[[Writable]].
    if (!desc->has_writable()) desc->set_writable(false);
  } else {
    // 5. Else,
    // 5a. If Desc does not have a [[Get]] field, set Desc.[[Get]] to
    //     like.[[Get]].
    if (!desc->has_get()) {
      desc->set_get(isolate->factory()->undefined_value());
    }
    // 5b. If Desc does not have a [[Set]] field, set Desc.[[Set]] to
    //     like.[[Set]].
    if (!desc->has_set()) {
      desc->set_set(isolate->factory()->undefined_value());
    }
  }
  // 6. If Desc does not have an [[Enumerable]] field, set
  //    Desc.[[Enumerable]] to like.[[Enumerable]].
  if (!desc->has_enumerable()) desc->set_enumerable(false);
  // 7. If Desc does not have a [[Configurable]] field, set
  //    Desc.[[Configurable]] to like.[[Configurable]].
  if (!desc->has_configurable()) desc->set_configurable(false);
  // 8. Return Desc.
}

Handle<PropertyDescriptorObject> PropertyDescriptor::ToPropertyDescriptorObject(
    Isolate* isolate) {
  Handle<PropertyDescriptorObject> obj =
      isolate->factory()->NewPropertyDescriptorObject();

  int flags =
      PropertyDescriptorObject::IsEnumerableBit::encode(enumerable_) |
      PropertyDescriptorObject::HasEnumerableBit::encode(has_enumerable_) |
      PropertyDescriptorObject::IsConfigurableBit::encode(configurable_) |
      PropertyDescriptorObject::HasConfigurableBit::encode(has_configurable_) |
      PropertyDescriptorObject::IsWritableBit::encode(writable_) |
      PropertyDescriptorObject::HasWritableBit::encode(has_writable_) |
      PropertyDescriptorObject::HasValueBit::encode(has_value()) |
      PropertyDescriptorObject::HasGetBit::encode(has_get()) |
      PropertyDescriptorObject::HasSetBit::encode(has_set());

  obj->set_flags(flags);

  if (has_value()) obj->set_value(*value_);
  if (has_get()) obj->set_get(*get_);
  if (has_set()) obj->set_set(*set_);

  return obj;
}

}  // namespace internal
}  // namespace v8
```