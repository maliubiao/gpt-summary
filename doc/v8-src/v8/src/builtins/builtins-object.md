Response: Let's break down the thought process for analyzing this C++ code and relating it to JavaScript functionality.

1. **Identify the Core Purpose:** The first lines of the file give a big clue: `v8/src/builtins/builtins-object.cc`. The directory `builtins` strongly suggests that this code implements built-in JavaScript functionalities. The filename `builtins-object.cc` further narrows it down to built-in functions related to the `Object` constructor in JavaScript.

2. **Scan for Keywords and Patterns:**  Quickly scan the code for recognizable patterns. The `BUILTIN(...)` macro is prominent. This immediately tells us these are the C++ implementations of JavaScript built-in functions. Look for names within the `BUILTIN` macro calls. We see things like:
    * `ObjectPrototypePropertyIsEnumerable`
    * `ObjectDefineProperties`
    * `ObjectDefineProperty`
    * `ObjectDefineGetter`
    * `ObjectDefineSetter`
    * `ObjectLookupGetter`
    * `ObjectLookupSetter`
    * `ObjectFreeze`
    * `ObjectPrototypeGetProto`
    * `ObjectPrototypeSetProto`
    * `ObjectGetOwnPropertySymbols`
    * `ObjectIsFrozen`
    * `ObjectIsSealed`
    * `ObjectGetOwnPropertyDescriptors`
    * `ObjectSeal`

3. **Relate Builtin Names to JavaScript:** The names within the `BUILTIN` macros are very close to their JavaScript equivalents. `Object.prototype.propertyIsEnumerable` maps directly to `ObjectPrototypePropertyIsEnumerable`, and so on. This is the crucial step in linking the C++ code to the JavaScript world.

4. **Understand Individual Builtin Functions:**  For each `BUILTIN`, look at the code within its block. Try to understand the logic:
    * **`ObjectPrototypePropertyIsEnumerable`**: It takes an object and a property name, checks if the property exists and if its `enumerable` attribute is set. This directly corresponds to the JavaScript `propertyIsEnumerable()` method.
    * **`ObjectDefineProperties`**: It takes a target object and an object containing property descriptors, and defines multiple properties on the target. This maps to `Object.defineProperties()`.
    * **`ObjectDefineProperty`**:  Similar to `ObjectDefineProperties` but for a single property. Maps to `Object.defineProperty()`.
    * **`ObjectDefineGetter` / `ObjectDefineSetter`**: These define getter and setter functions for a property. Maps to `Object.defineProperty(obj, prop, { get: function() { ... } })` and `Object.defineProperty(obj, prop, { set: function(value) { ... } })`. The older `__defineGetter__` and `__defineSetter__` are also mentioned in the comments.
    * **`ObjectLookupGetter` / `ObjectLookupSetter`**: These traverse the prototype chain to find a getter or setter. Maps to the older `__lookupGetter__` and `__lookupSetter__`.
    * **`ObjectFreeze`**:  Makes an object immutable. Maps to `Object.freeze()`.
    * **`ObjectPrototypeGetProto` / `ObjectPrototypeSetProto`**: Get and set the prototype of an object. Maps to `Object.getPrototypeOf()` and `Object.setPrototypeOf()` or the older `__proto__`.
    * **`ObjectGetOwnPropertySymbols`**: Returns an array of symbol properties directly on an object. Maps to `Object.getOwnPropertySymbols()`.
    * **`ObjectIsFrozen` / `ObjectIsSealed`**: Check if an object is frozen or sealed. Maps to `Object.isFrozen()` and `Object.isSealed()`.
    * **`ObjectGetOwnPropertyDescriptors`**: Returns an object containing property descriptors for all own properties. Maps to `Object.getOwnPropertyDescriptors()`.
    * **`ObjectSeal`**: Prevents adding/removing properties and makes existing ones non-configurable. Maps to `Object.seal()`.

5. **Identify Supporting Code:** Notice the helper functions and namespaces:
    * `namespace v8 { namespace internal { ... } }`: This is the V8 engine's internal implementation.
    * `#include ...`: These are header files providing necessary data structures and functions for V8's internal workings (like `HandleScope`, `Isolate`, `JSReceiver`, etc.). You don't need to understand the details of these unless you're working on V8 itself, but recognizing they are part of V8's internal machinery is helpful.
    * Template functions like `ObjectDefineAccessor`:  These are code reuse mechanisms to handle similar logic for getters and setters.
    * Helper functions like `GetOwnPropertyKeys`:  These encapsulate common operations.

6. **Construct JavaScript Examples:**  For each identified built-in function, create simple JavaScript code snippets that demonstrate its usage. This makes the connection between the C++ implementation and the JavaScript API clear. Focus on the core functionality of each method.

7. **Summarize the Functionality:**  Finally, write a concise summary of the file's purpose. Emphasize that it implements the core `Object` built-in methods in JavaScript and is a part of the V8 engine.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This looks complicated."  **Correction:** Focus on the `BUILTIN` macros and their names. That's the entry point.
* **Misunderstanding a specific function:**  Read the comments and the code carefully. If the logic isn't immediately obvious, try to break it down step-by-step. Look for standard ECMAScript references in the comments (like "ES6 section 19.1.3.4").
* **Overlooking connections:**  Constantly ask yourself, "What JavaScript function does this correspond to?"  If you're unsure, try searching the web for the `BUILTIN` name or related keywords.
* **Too much detail:** The goal isn't to understand every line of C++ code. Focus on the *functionality* being implemented and its JavaScript equivalent.

By following these steps, you can effectively analyze C++ code like this and relate it to higher-level concepts like JavaScript built-in functions.

这个C++源代码文件 `builtins-object.cc` 实现了 **JavaScript 中 `Object` 构造函数及其原型对象上的一些内置方法 (built-in methods)**。 换句话说，它定义了 V8 引擎如何执行诸如 `Object.defineProperty`, `Object.freeze`, `Object.prototype.propertyIsEnumerable` 等等这些 JavaScript 的核心功能。

**主要功能归纳:**

该文件包含了以下 JavaScript `Object` 相关功能的 C++ 实现：

* **属性操作:**
    * `Object.defineProperty`:  定义或修改对象上的属性。
    * `Object.defineProperties`: 定义或修改对象上的多个属性。
    * `Object.prototype.propertyIsEnumerable`:  检查对象自身属性是否可枚举。
    * `Object.getOwnPropertyDescriptors`: 获取对象自身属性的描述符。
* **Getter/Setter:**
    * `Object.prototype.__defineGetter__`: (已废弃，但仍有实现) 为对象属性定义 getter 方法。
    * `Object.prototype.__defineSetter__`: (已废弃，但仍有实现) 为对象属性定义 setter 方法。
    * `Object.prototype.__lookupGetter__`: (已废弃，但仍有实现) 在原型链上查找属性的 getter 方法。
    * `Object.prototype.__lookupSetter__`: (已废弃，但仍有实现) 在原型链上查找属性的 setter 方法。
* **对象状态:**
    * `Object.freeze`: 冻结对象，使其属性不可添加、删除或修改。
    * `Object.isFrozen`: 检查对象是否被冻结。
    * `Object.seal`: 封闭对象，使其属性不可添加或删除，但属性值可以修改（如果可写）。
    * `Object.isSealed`: 检查对象是否被封闭。
* **原型链:**
    * `Object.prototype.__proto__` (getter 和 setter):  获取或设置对象的原型。
    * `Object.getPrototypeOf`:  获取对象的原型。
    * `Object.setPrototypeOf`: 设置对象的原型。
* **属性枚举:**
    * `Object.getOwnPropertySymbols`: 获取对象自身的所有 Symbol 类型的属性名。

**与 JavaScript 功能的关联及举例说明:**

该文件中的每一个 `BUILTIN` 宏定义的函数都直接对应一个 JavaScript 的内置方法。以下是一些例子：

**1. `Object.prototype.propertyIsEnumerable(v)`:**

* **C++ 实现 (部分):**
  ```c++
  BUILTIN(ObjectPrototypePropertyIsEnumerable) {
    HandleScope scope(isolate);
    Handle<JSReceiver> object;
    Handle<Name> name;
    ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
        isolate, name, Object::ToName(isolate, args.atOrUndefined(isolate, 1)));
    ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
        isolate, object, Object::ToObject(isolate, args.receiver()));
    Maybe<PropertyAttributes> maybe =
        JSReceiver::GetOwnPropertyAttributes(object, name);
    // ... (省略部分逻辑)
    return isolate->heap()->ToBoolean((maybe.FromJust() & DONT_ENUM) == 0);
  }
  ```

* **JavaScript 示例:**
  ```javascript
  const obj = { a: 1 };
  console.log(obj.propertyIsEnumerable('a')); // 输出: true

  Object.defineProperty(obj, 'b', {
    value: 2,
    enumerable: false
  });
  console.log(obj.propertyIsEnumerable('b')); // 输出: false
  ```
  C++ 代码中的 `ObjectPrototypePropertyIsEnumerable` 函数接收 JavaScript 传递的对象和属性名，然后检查该属性是否是对象自身的属性，并且其内部的 `DONT_ENUM` 标志是否被设置 (即不可枚举)。最终返回一个布尔值，对应 JavaScript 中 `propertyIsEnumerable` 的行为。

**2. `Object.defineProperty(o, p, attributes)`:**

* **C++ 实现 (部分):**
  ```c++
  BUILTIN(ObjectDefineProperty) {
    HandleScope scope(isolate);
    DCHECK_LE(4, args.length());
    Handle<Object> target = args.at(1);
    Handle<Object> key = args.at(2);
    Handle<Object> attributes = args.at(3);

    return JSReceiver::DefineProperty(isolate, target, key, attributes);
  }
  ```

* **JavaScript 示例:**
  ```javascript
  const obj = {};
  Object.defineProperty(obj, 'c', {
    value: 3,
    writable: false,
    enumerable: true,
    configurable: false
  });
  console.log(obj.c); // 输出: 3
  obj.c = 4; // 严格模式下会报错，非严格模式下赋值无效
  console.log(obj.c); // 输出: 3
  ```
  C++ 代码中的 `ObjectDefineProperty` 函数接收 JavaScript 传递的目标对象、属性名和属性描述符对象，然后调用 `JSReceiver::DefineProperty` 在 V8 内部完成属性的定义或修改。

**3. `Object.freeze(obj)`:**

* **C++ 实现 (部分):**
  ```c++
  BUILTIN(ObjectFreeze) {
    HandleScope scope(isolate);
    Handle<Object> object = args.atOrUndefined(isolate, 1);
    if (IsJSReceiver(*object)) {
      MAYBE_RETURN(JSReceiver::SetIntegrityLevel(
                       isolate, Cast<JSReceiver>(object), FROZEN, kThrowOnError),
                   ReadOnlyRoots(isolate).exception());
    }
    return *object;
  }
  ```

* **JavaScript 示例:**
  ```javascript
  const obj = { d: 5 };
  Object.freeze(obj);
  obj.d = 6; // 严格模式下会报错，非严格模式下赋值无效
  console.log(obj.d); // 输出: 5
  delete obj.d; // 严格模式下会报错，非严格模式下删除无效
  console.log(obj.d); // 输出: 5
  ```
  C++ 代码中的 `ObjectFreeze` 函数接收 JavaScript 传递的对象，然后调用 `JSReceiver::SetIntegrityLevel` 设置对象的完整性级别为 `FROZEN`，从而阻止对该对象属性的修改。

总而言之，`v8/src/builtins/builtins-object.cc` 文件是 V8 引擎中至关重要的一个组成部分，它桥接了 JavaScript 的 `Object` 相关操作和 V8 引擎底层的 C++ 实现。理解这个文件有助于深入理解 JavaScript 语言的运行机制。

Prompt: 
```
这是目录为v8/src/builtins/builtins-object.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/builtins/builtins-utils-inl.h"
#include "src/builtins/builtins.h"
#include "src/common/message-template.h"
#include "src/execution/isolate.h"
#include "src/heap/heap-inl.h"  // For ToBoolean. TODO(jkummerow): Drop.
#include "src/objects/keys.h"
#include "src/objects/lookup.h"
#include "src/objects/objects-inl.h"
#include "src/objects/property-descriptor.h"

namespace v8 {
namespace internal {

// -----------------------------------------------------------------------------
// ES6 section 19.1 Object Objects

// ES6 section 19.1.3.4 Object.prototype.propertyIsEnumerable ( V )
BUILTIN(ObjectPrototypePropertyIsEnumerable) {
  HandleScope scope(isolate);
  Handle<JSReceiver> object;
  Handle<Name> name;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, name, Object::ToName(isolate, args.atOrUndefined(isolate, 1)));
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, object, Object::ToObject(isolate, args.receiver()));
  Maybe<PropertyAttributes> maybe =
      JSReceiver::GetOwnPropertyAttributes(object, name);
  if (maybe.IsNothing()) return ReadOnlyRoots(isolate).exception();
  if (maybe.FromJust() == ABSENT) return ReadOnlyRoots(isolate).false_value();
  return isolate->heap()->ToBoolean((maybe.FromJust() & DONT_ENUM) == 0);
}

// ES6 section 19.1.2.3 Object.defineProperties
BUILTIN(ObjectDefineProperties) {
  HandleScope scope(isolate);
  DCHECK_LE(3, args.length());
  Handle<Object> target = args.at(1);
  Handle<Object> properties = args.at(2);

  RETURN_RESULT_OR_FAILURE(
      isolate, JSReceiver::DefineProperties(isolate, target, properties));
}

// ES6 section 19.1.2.4 Object.defineProperty
BUILTIN(ObjectDefineProperty) {
  HandleScope scope(isolate);
  DCHECK_LE(4, args.length());
  Handle<Object> target = args.at(1);
  Handle<Object> key = args.at(2);
  Handle<Object> attributes = args.at(3);

  return JSReceiver::DefineProperty(isolate, target, key, attributes);
}

namespace {

template <AccessorComponent which_accessor>
Tagged<Object> ObjectDefineAccessor(Isolate* isolate, Handle<JSAny> object,
                                    Handle<Object> name,
                                    Handle<Object> accessor) {
  // 1. Let O be ? ToObject(this value).
  Handle<JSReceiver> receiver;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, receiver,
                                     Object::ToObject(isolate, object));
  // 2. If IsCallable(getter) is false, throw a TypeError exception.
  if (!IsCallable(*accessor)) {
    MessageTemplate message =
        which_accessor == ACCESSOR_GETTER
            ? MessageTemplate::kObjectGetterExpectingFunction
            : MessageTemplate::kObjectSetterExpectingFunction;
    THROW_NEW_ERROR_RETURN_FAILURE(isolate, NewTypeError(message));
  }
  // 3. Let desc be PropertyDescriptor{[[Get]]: getter, [[Enumerable]]: true,
  //                                   [[Configurable]]: true}.
  PropertyDescriptor desc;
  if (which_accessor == ACCESSOR_GETTER) {
    desc.set_get(Cast<JSAny>(accessor));
  } else {
    DCHECK(which_accessor == ACCESSOR_SETTER);
    desc.set_set(Cast<JSAny>(accessor));
  }
  desc.set_enumerable(true);
  desc.set_configurable(true);
  // 4. Let key be ? ToPropertyKey(P).
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, name,
                                     Object::ToPropertyKey(isolate, name));
  // 5. Perform ? DefinePropertyOrThrow(O, key, desc).
  // To preserve legacy behavior, we ignore errors silently rather than
  // throwing an exception.
  Maybe<bool> success = JSReceiver::DefineOwnProperty(
      isolate, receiver, name, &desc, Just(kThrowOnError));
  MAYBE_RETURN(success, ReadOnlyRoots(isolate).exception());
  if (!success.FromJust()) {
    isolate->CountUsage(v8::Isolate::kDefineGetterOrSetterWouldThrow);
  }
  // 6. Return undefined.
  return ReadOnlyRoots(isolate).undefined_value();
}

Tagged<Object> ObjectLookupAccessor(Isolate* isolate, Handle<JSAny> object,
                                    Handle<Object> key,
                                    AccessorComponent component) {
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, object,
                                     Object::ToObject(isolate, object));
  // TODO(jkummerow/verwaest): PropertyKey(..., bool*) performs a
  // functionally equivalent conversion, but handles element indices slightly
  // differently. Does one of the approaches have a performance advantage?
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, key,
                                     Object::ToPropertyKey(isolate, key));
  PropertyKey lookup_key(isolate, key);
  LookupIterator it(isolate, object, lookup_key,
                    LookupIterator::PROTOTYPE_CHAIN_SKIP_INTERCEPTOR);

  for (;; it.Next()) {
    switch (it.state()) {
      case LookupIterator::INTERCEPTOR:
      case LookupIterator::TRANSITION:
        UNREACHABLE();

      case LookupIterator::ACCESS_CHECK:
        if (it.HasAccess()) continue;
        RETURN_FAILURE_ON_EXCEPTION(isolate, isolate->ReportFailedAccessCheck(
                                                 it.GetHolder<JSObject>()));
        UNREACHABLE();

      case LookupIterator::JSPROXY: {
        PropertyDescriptor desc;
        Maybe<bool> found = JSProxy::GetOwnPropertyDescriptor(
            isolate, it.GetHolder<JSProxy>(), it.GetName(), &desc);
        MAYBE_RETURN(found, ReadOnlyRoots(isolate).exception());
        if (found.FromJust()) {
          if (component == ACCESSOR_GETTER && desc.has_get()) {
            return *desc.get();
          }
          if (component == ACCESSOR_SETTER && desc.has_set()) {
            return *desc.set();
          }
          return ReadOnlyRoots(isolate).undefined_value();
        }
        Handle<JSPrototype> prototype;
        ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
            isolate, prototype, JSProxy::GetPrototype(it.GetHolder<JSProxy>()));
        if (IsNull(*prototype, isolate)) {
          return ReadOnlyRoots(isolate).undefined_value();
        }
        return ObjectLookupAccessor(isolate, prototype, key, component);
      }
      case LookupIterator::WASM_OBJECT:
      case LookupIterator::TYPED_ARRAY_INDEX_NOT_FOUND:
      case LookupIterator::DATA:
      case LookupIterator::NOT_FOUND:
        return ReadOnlyRoots(isolate).undefined_value();

      case LookupIterator::ACCESSOR: {
        Handle<Object> maybe_pair = it.GetAccessors();
        if (IsAccessorPair(*maybe_pair)) {
          Handle<NativeContext> holder_realm(
              it.GetHolder<JSReceiver>()->GetCreationContext().value(),
              isolate);
          return *AccessorPair::GetComponent(
              isolate, holder_realm, Cast<AccessorPair>(maybe_pair), component);
        }
        continue;
      }
    }
    UNREACHABLE();
  }
}

}  // namespace

// ES6 B.2.2.2 a.k.a.
// https://tc39.github.io/ecma262/#sec-object.prototype.__defineGetter__
BUILTIN(ObjectDefineGetter) {
  HandleScope scope(isolate);
  Handle<JSAny> object = args.at<JSAny>(0);  // Receiver.
  Handle<Object> name = args.at(1);
  Handle<Object> getter = args.at(2);
  return ObjectDefineAccessor<ACCESSOR_GETTER>(isolate, object, name, getter);
}

// ES6 B.2.2.3 a.k.a.
// https://tc39.github.io/ecma262/#sec-object.prototype.__defineSetter__
BUILTIN(ObjectDefineSetter) {
  HandleScope scope(isolate);
  Handle<JSAny> object = args.at<JSAny>(0);  // Receiver.
  Handle<Object> name = args.at(1);
  Handle<Object> setter = args.at(2);
  return ObjectDefineAccessor<ACCESSOR_SETTER>(isolate, object, name, setter);
}

// ES6 B.2.2.4 a.k.a.
// https://tc39.github.io/ecma262/#sec-object.prototype.__lookupGetter__
BUILTIN(ObjectLookupGetter) {
  HandleScope scope(isolate);
  Handle<JSAny> object = args.at<JSAny>(0);
  Handle<Object> name = args.at(1);
  return ObjectLookupAccessor(isolate, object, name, ACCESSOR_GETTER);
}

// ES6 B.2.2.5 a.k.a.
// https://tc39.github.io/ecma262/#sec-object.prototype.__lookupSetter__
BUILTIN(ObjectLookupSetter) {
  HandleScope scope(isolate);
  Handle<JSAny> object = args.at<JSAny>(0);
  Handle<Object> name = args.at(1);
  return ObjectLookupAccessor(isolate, object, name, ACCESSOR_SETTER);
}

// ES6 section 19.1.2.5 Object.freeze ( O )
BUILTIN(ObjectFreeze) {
  HandleScope scope(isolate);
  Handle<Object> object = args.atOrUndefined(isolate, 1);
  if (IsJSReceiver(*object)) {
    MAYBE_RETURN(JSReceiver::SetIntegrityLevel(
                     isolate, Cast<JSReceiver>(object), FROZEN, kThrowOnError),
                 ReadOnlyRoots(isolate).exception());
  }
  return *object;
}

// ES6 section B.2.2.1.1 get Object.prototype.__proto__
BUILTIN(ObjectPrototypeGetProto) {
  HandleScope scope(isolate);
  // 1. Let O be ? ToObject(this value).
  Handle<JSReceiver> receiver;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, receiver, Object::ToObject(isolate, args.receiver()));

  // 2. Return ? O.[[GetPrototypeOf]]().
  RETURN_RESULT_OR_FAILURE(isolate,
                           JSReceiver::GetPrototype(isolate, receiver));
}

// ES6 section B.2.2.1.2 set Object.prototype.__proto__
BUILTIN(ObjectPrototypeSetProto) {
  HandleScope scope(isolate);
  // 1. Let O be ? RequireObjectCoercible(this value).
  Handle<Object> object = args.receiver();
  if (IsNullOrUndefined(*object, isolate)) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewTypeError(MessageTemplate::kCalledOnNullOrUndefined,
                              isolate->factory()->NewStringFromAsciiChecked(
                                  "set Object.prototype.__proto__")));
  }

  // 2. If Type(proto) is neither Object nor Null, return undefined.
  Handle<Object> proto = args.at(1);
  if (!IsNull(*proto, isolate) && !IsJSReceiver(*proto)) {
    return ReadOnlyRoots(isolate).undefined_value();
  }

  // 3. If Type(O) is not Object, return undefined.
  if (!IsJSReceiver(*object)) return ReadOnlyRoots(isolate).undefined_value();
  Handle<JSReceiver> receiver = Cast<JSReceiver>(object);

  // 4. Let status be ? O.[[SetPrototypeOf]](proto).
  // 5. If status is false, throw a TypeError exception.
  MAYBE_RETURN(
      JSReceiver::SetPrototype(isolate, receiver, proto, true, kThrowOnError),
      ReadOnlyRoots(isolate).exception());

  // Return undefined.
  return ReadOnlyRoots(isolate).undefined_value();
}

namespace {

Tagged<Object> GetOwnPropertyKeys(Isolate* isolate, BuiltinArguments args,
                                  PropertyFilter filter) {
  HandleScope scope(isolate);
  Handle<Object> object = args.atOrUndefined(isolate, 1);
  Handle<JSReceiver> receiver;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, receiver,
                                     Object::ToObject(isolate, object));
  Handle<FixedArray> keys;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, keys,
      KeyAccumulator::GetKeys(isolate, receiver, KeyCollectionMode::kOwnOnly,
                              filter, GetKeysConversion::kConvertToString));
  return *isolate->factory()->NewJSArrayWithElements(keys);
}

}  // namespace

// ES6 section 19.1.2.8 Object.getOwnPropertySymbols ( O )
BUILTIN(ObjectGetOwnPropertySymbols) {
  return GetOwnPropertyKeys(isolate, args, SKIP_STRINGS);
}

// ES6 section 19.1.2.12 Object.isFrozen ( O )
BUILTIN(ObjectIsFrozen) {
  HandleScope scope(isolate);
  Handle<Object> object = args.atOrUndefined(isolate, 1);
  Maybe<bool> result = IsJSReceiver(*object)
                           ? JSReceiver::TestIntegrityLevel(
                                 isolate, Cast<JSReceiver>(object), FROZEN)
                           : Just(true);
  MAYBE_RETURN(result, ReadOnlyRoots(isolate).exception());
  return isolate->heap()->ToBoolean(result.FromJust());
}

// ES6 section 19.1.2.13 Object.isSealed ( O )
BUILTIN(ObjectIsSealed) {
  HandleScope scope(isolate);
  Handle<Object> object = args.atOrUndefined(isolate, 1);
  Maybe<bool> result = IsJSReceiver(*object)
                           ? JSReceiver::TestIntegrityLevel(
                                 isolate, Cast<JSReceiver>(object), SEALED)
                           : Just(true);
  MAYBE_RETURN(result, ReadOnlyRoots(isolate).exception());
  return isolate->heap()->ToBoolean(result.FromJust());
}

BUILTIN(ObjectGetOwnPropertyDescriptors) {
  HandleScope scope(isolate);
  Handle<Object> object = args.atOrUndefined(isolate, 1);

  Handle<JSReceiver> receiver;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, receiver,
                                     Object::ToObject(isolate, object));

  Handle<FixedArray> keys;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, keys,
      KeyAccumulator::GetKeys(isolate, receiver, KeyCollectionMode::kOwnOnly,
                              ALL_PROPERTIES,
                              GetKeysConversion::kConvertToString));

  Handle<JSObject> descriptors =
      isolate->factory()->NewJSObject(isolate->object_function());

  for (int i = 0; i < keys->length(); ++i) {
    Handle<Name> key(Cast<Name>(keys->get(i)), isolate);
    PropertyDescriptor descriptor;
    Maybe<bool> did_get_descriptor = JSReceiver::GetOwnPropertyDescriptor(
        isolate, receiver, key, &descriptor);
    MAYBE_RETURN(did_get_descriptor, ReadOnlyRoots(isolate).exception());

    if (!did_get_descriptor.FromJust()) continue;
    Handle<Object> from_descriptor = descriptor.ToObject(isolate);

    Maybe<bool> success = JSReceiver::CreateDataProperty(
        isolate, descriptors, key, from_descriptor, Just(kDontThrow));
    CHECK(success.FromJust());
  }

  return *descriptors;
}

// ES6 section 19.1.2.17 Object.seal ( O )
BUILTIN(ObjectSeal) {
  HandleScope scope(isolate);
  Handle<Object> object = args.atOrUndefined(isolate, 1);
  if (IsJSReceiver(*object)) {
    MAYBE_RETURN(JSReceiver::SetIntegrityLevel(
                     isolate, Cast<JSReceiver>(object), SEALED, kThrowOnError),
                 ReadOnlyRoots(isolate).exception());
  }
  return *object;
}

}  // namespace internal
}  // namespace v8

"""

```