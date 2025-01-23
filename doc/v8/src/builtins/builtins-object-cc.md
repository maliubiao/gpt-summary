Response:
Let's break down the thought process for analyzing this C++ code snippet.

**1. Initial Understanding of the Request:**

The user wants to understand the functionality of a specific V8 source code file, `v8/src/builtins/builtins-object.cc`. The request also has specific instructions about how to present the information, including handling `.tq` files, relating it to JavaScript, providing examples, and discussing potential errors.

**2. Identifying the Core Purpose of the File:**

The filename `builtins-object.cc` and the inclusion of headers like `src/builtins/builtins.h` strongly suggest that this file contains implementations of built-in JavaScript `Object` methods. The comment "// ES6 section 19.1 Object Objects" further confirms this.

**3. Analyzing Individual Built-in Functions:**

The code is structured as a series of `BUILTIN` macros. Each `BUILTIN` corresponds to a specific JavaScript `Object` method. The key is to identify these methods and understand their ECMA-262 specification.

* **`ObjectPrototypePropertyIsEnumerable`:** The name and the comment "// ES6 section 19.1.3.4 Object.prototype.propertyIsEnumerable ( V )" clearly indicate this implements `Object.prototype.propertyIsEnumerable`. I need to recall what this method does (checks if a property is enumerable).

* **`ObjectDefineProperties`:** Similarly, the name and comment point to `Object.defineProperties`. This method defines multiple properties on an object.

* **`ObjectDefineProperty`:**  This corresponds to `Object.defineProperty`, used for defining a single property.

* **`ObjectDefineGetter` and `ObjectDefineSetter`:** The comments mention ES6 B.2.2.2 and B.2.2.3 and the names themselves are self-explanatory: they implement the non-standard `__defineGetter__` and `__defineSetter__` methods.

* **`ObjectLookupGetter` and `ObjectLookupSetter`:**  Again, the comments (ES6 B.2.2.4 and B.2.2.5) and names indicate these are for the non-standard `__lookupGetter__` and `__lookupSetter__` methods.

* **`ObjectFreeze`:**  The comment points to `Object.freeze`, which makes an object immutable.

* **`ObjectPrototypeGetProto` and `ObjectPrototypeSetProto`:**  These implement the getter and setter for the `__proto__` property on `Object.prototype`.

* **`ObjectGetOwnPropertySymbols`:**  This corresponds to `Object.getOwnPropertySymbols`, retrieving an array of symbol properties.

* **`ObjectIsFrozen` and `ObjectIsSealed`:**  These implement `Object.isFrozen` and `Object.isSealed`, checking the immutability status of an object.

* **`ObjectGetOwnPropertyDescriptors`:**  This corresponds to `Object.getOwnPropertyDescriptors`, returning descriptors for all own properties.

* **`ObjectSeal`:**  This implements `Object.seal`, preventing adding or removing properties.

**4. Relating to JavaScript and Providing Examples:**

For each built-in function identified, I need to provide a corresponding JavaScript example to illustrate its usage. This involves translating the C++ functionality (however abstractly) into concrete JavaScript code.

**5. Handling `.tq` Files:**

The prompt specifically asks about `.tq` files. I need to check if the filename ends with `.tq`. In this case, it doesn't, so I can state that it's C++ and not Torque.

**6. Code Logic Inference (Input/Output):**

For some functions, like `propertyIsEnumerable`, `isFrozen`, and `isSealed`, I can define hypothetical inputs and expected outputs to demonstrate their logic.

**7. Identifying Common Programming Errors:**

For methods like `defineProperty`, `defineProperties`, `defineGetter`, and `defineSetter`, there are common errors related to the descriptor properties (e.g., providing invalid values, conflicting attributes). For `setPrototypeOf`, attempting to set the prototype of a non-extensible object is a common error.

**8. Structuring the Output:**

The request asks for a list of functionalities. I'll structure the output by listing each built-in function and then providing the requested information (description, JavaScript example, input/output if applicable, common errors).

**9. Refinement and Review:**

After the initial pass, I'll review the information for accuracy, clarity, and completeness. I'll ensure the JavaScript examples are correct and the error scenarios are realistic. I'll also double-check that I've addressed all aspects of the user's request. For example, ensuring the explanations are tailored to someone who might be familiar with JavaScript but not necessarily with V8 internals.

**Self-Correction/Refinement Example During the Process:**

Initially, I might just list the ES6 section numbers. However, I realize that providing a brief description of what each method *does* in plain English is more helpful to the user. So, I'll add a concise explanation before the JavaScript example. Similarly, I might initially forget to mention the non-standard nature of `__defineGetter__`, `__defineSetter__`, `__lookupGetter__`, and `__lookupSetter__`, but during review, I'll remember to include this important detail. Also, I need to ensure the JavaScript examples are simple and directly illustrate the function's purpose. Avoid overly complex examples that might obscure the core functionality.
Based on the provided V8 source code for `v8/src/builtins/builtins-object.cc`, here's a breakdown of its functionalities:

**Core Functionality:**

This file implements the built-in functions of the JavaScript `Object` constructor and `Object.prototype` as defined in the ECMAScript specification (primarily ES6). These built-in functions are fundamental for working with objects in JavaScript.

**Specific Functions Implemented:**

Here's a breakdown of each `BUILTIN` function in the code:

1. **`ObjectPrototypePropertyIsEnumerable(V)`:**
   - **Functionality:** Implements `Object.prototype.propertyIsEnumerable()`. This method checks if a specified property of an object is enumerable (i.e., will be included in a `for...in` loop).
   - **JavaScript Example:**
     ```javascript
     const obj = { a: 1, b: 2 };
     Object.defineProperty(obj, 'c', { value: 3, enumerable: false });

     console.log(obj.propertyIsEnumerable('a')); // Output: true
     console.log(obj.propertyIsEnumerable('c')); // Output: false
     console.log(obj.propertyIsEnumerable('toString')); // Output: false (inherited, non-enumerable)
     console.log(obj.propertyIsEnumerable('d')); // Output: false (doesn't exist)
     ```
   - **Code Logic Inference:**
     - **Input:** A JavaScript object and a property name (string or symbol).
     - **Output:** A boolean value (`true` if the property exists directly on the object and is enumerable, `false` otherwise). It checks the `DONT_ENUM` attribute of the property descriptor.
   - **Common Programming Errors:**
     - Confusing `propertyIsEnumerable` with checking if a property simply *exists* on an object. Use the `in` operator or `hasOwnProperty` for existence checks.

2. **`ObjectDefineProperties(target, properties)`:**
   - **Functionality:** Implements `Object.defineProperties()`. This method defines new or modifies existing properties directly on an object, using provided property descriptors.
   - **JavaScript Example:**
     ```javascript
     const obj = {};
     Object.defineProperties(obj, {
       'a': { value: 1, writable: true, enumerable: true, configurable: true },
       'b': { get: function() { return 2; } }
     });
     console.log(obj.a); // Output: 1
     console.log(obj.b); // Output: 2
     ```
   - **Code Logic Inference:**
     - **Input:** A target JavaScript object and an object whose properties represent the properties to define or modify on the target.
     - **Output:** The target object after defining or modifying the properties. It iterates through the `properties` object and calls `DefineProperty` for each.
   - **Common Programming Errors:**
     - Providing invalid property descriptors (e.g., missing `value` for data properties without getters/setters).
     - Expecting `defineProperties` to work on primitive values (it will attempt to coerce them to objects, which might not be the intended behavior).

3. **`ObjectDefineProperty(target, key, attributes)`:**
   - **Functionality:** Implements `Object.defineProperty()`. This method defines a new property directly on an object or modifies an existing property on an object, and returns the object.
   - **JavaScript Example:**
     ```javascript
     const obj = {};
     Object.defineProperty(obj, 'a', {
       value: 42,
       writable: false,
       enumerable: true,
       configurable: false
     });
     console.log(obj.a); // Output: 42
     obj.a = 100; // Strict mode would throw a TypeError here
     console.log(obj.a); // Output: 42 (writable: false)
     ```
   - **Code Logic Inference:**
     - **Input:** A target JavaScript object, a property key (string or symbol), and a property descriptor object.
     - **Output:** The target object after defining or modifying the property.
   - **Common Programming Errors:**
     - Trying to redefine a non-configurable property in a way that violates its current configuration (e.g., changing `configurable: false` to `true`).
     - Not understanding the different attributes of a property descriptor (`value`, `writable`, `enumerable`, `configurable`, `get`, `set`).

4. **`ObjectDefineGetter(object, name, getter)`:**
   - **Functionality:** Implements the non-standard `Object.prototype.__defineGetter__()`. Defines a getter function for a specific property on an object.
   - **JavaScript Example:**
     ```javascript
     const obj = {};
     obj.__defineGetter__('fullName', function() {
       return this.firstName + ' ' + this.lastName;
     });
     obj.firstName = 'John';
     obj.lastName = 'Doe';
     console.log(obj.fullName); // Output: John Doe
     ```
   - **Code Logic Inference:**
     - **Input:** A JavaScript object, a property name, and a function to be used as the getter.
     - **Output:** `undefined`. It sets the `get` attribute of the property descriptor.
   - **Common Programming Errors:**
     - Providing a non-callable value as the `getter`.
     - Confusing this with standard `Object.defineProperty` syntax for defining getters.

5. **`ObjectDefineSetter(object, name, setter)`:**
   - **Functionality:** Implements the non-standard `Object.prototype.__defineSetter__()`. Defines a setter function for a specific property on an object.
   - **JavaScript Example:**
     ```javascript
     const obj = {};
     obj.__defineSetter__('age', function(value) {
       if (value < 0) {
         console.error("Age cannot be negative");
       } else {
         this._age = value;
       }
     });
     obj.age = 30;
     obj.age = -5; // Output: Age cannot be negative
     console.log(obj._age); // Output: 30
     ```
   - **Code Logic Inference:**
     - **Input:** A JavaScript object, a property name, and a function to be used as the setter.
     - **Output:** `undefined`. It sets the `set` attribute of the property descriptor.
   - **Common Programming Errors:**
     - Providing a non-callable value as the `setter`.
     - Confusing this with standard `Object.defineProperty` syntax for defining setters.

6. **`ObjectLookupGetter(object, name)`:**
   - **Functionality:** Implements the non-standard `Object.prototype.__lookupGetter__()`. Returns the getter function defined for a property on an object (traversing the prototype chain).
   - **JavaScript Example:**
     ```javascript
     const proto = { get foo() { return 'proto-foo'; } };
     const obj = Object.create(proto);
     obj.__defineGetter__('bar', function() { return 'obj-bar'; });

     console.log(obj.__lookupGetter__('bar')); // Output: function() { return 'obj-bar'; }
     console.log(obj.__lookupGetter__('foo')); // Output: function() { return 'proto-foo'; }
     console.log(obj.__lookupGetter__('baz')); // Output: undefined
     ```
   - **Code Logic Inference:**
     - **Input:** A JavaScript object and a property name.
     - **Output:** The getter function if found, otherwise `undefined`. It traverses the prototype chain to find the getter.
   - **Common Programming Errors:**
     - Expecting this to return the *value* of the property, not the getter function itself.

7. **`ObjectLookupSetter(object, name)`:**
   - **Functionality:** Implements the non-standard `Object.prototype.__lookupSetter__()`. Returns the setter function defined for a property on an object (traversing the prototype chain).
   - **JavaScript Example:**
     ```javascript
     const proto = { set qux(value) { this._qux = 'proto-' + value; } };
     const obj = Object.create(proto);
     obj.__defineSetter__('baz', function(value) { this._baz = 'obj-' + value; });

     console.log(obj.__lookupSetter__('baz')); // Output: function(value) { this._baz = 'obj-' + value; }
     console.log(obj.__lookupSetter__('qux')); // Output: function(value) { this._qux = 'proto-' + value; }
     console.log(obj.__lookupSetter__('norf')); // Output: undefined
     ```
   - **Code Logic Inference:**
     - **Input:** A JavaScript object and a property name.
     - **Output:** The setter function if found, otherwise `undefined`. It traverses the prototype chain to find the setter.
   - **Common Programming Errors:**
     - Expecting this to set the *value* of the property, not return the setter function.

8. **`ObjectFreeze(O)`:**
   - **Functionality:** Implements `Object.freeze()`. Freezes an object, preventing new properties from being added, existing properties from being removed, and making existing data properties non-writable and non-configurable. Returns the frozen object.
   - **JavaScript Example:**
     ```javascript
     const obj = { a: 1 };
     Object.freeze(obj);
     obj.b = 2; // Strict mode would throw a TypeError
     delete obj.a; // Strict mode would throw a TypeError
     obj.a = 3; // Strict mode would throw a TypeError
     console.log(obj); // Output: { a: 1 }
     console.log(Object.isFrozen(obj)); // Output: true
     ```
   - **Code Logic Inference:**
     - **Input:** A JavaScript object.
     - **Output:** The input object (after attempting to freeze it). It sets the `configurable` and `writable` attributes of all own properties to `false` and prevents adding new properties.
   - **Common Programming Errors:**
     - Thinking `Object.freeze()` makes an object completely immutable in all scenarios (e.g., it doesn't deeply freeze nested objects).

9. **`ObjectPrototypeGetProto()`:**
   - **Functionality:** Implements the getter for `Object.prototype.__proto__`. Returns the prototype of an object.
   - **JavaScript Example:**
     ```javascript
     const obj = {};
     const proto = { x: 10 };
     Object.setPrototypeOf(obj, proto);
     console.log(obj.__proto__); // Output: { x: 10, constructor: ... }
     ```
   - **Code Logic Inference:**
     - **Input:** A JavaScript object (obtained as the receiver).
     - **Output:** The prototype object of the receiver.
   - **Common Programming Errors:**
     - Using `__proto__` in performance-critical code, as it can be slower than `Object.getPrototypeOf()`.

10. **`ObjectPrototypeSetProto(proto)`:**
    - **Functionality:** Implements the setter for `Object.prototype.__proto__`. Sets the prototype of an object.
    - **JavaScript Example:**
      ```javascript
      const obj = {};
      const proto = { x: 10 };
      obj.__proto__ = proto;
      console.log(obj.x); // Output: 10
      ```
    - **Code Logic Inference:**
      - **Input:** A JavaScript object (as the receiver) and a potential new prototype (an object or `null`).
      - **Output:** `undefined`. It attempts to set the internal `[[Prototype]]` of the receiver.
    - **Common Programming Errors:**
      - Trying to set the prototype of a non-extensible object.
      - Setting `__proto__` to a primitive value (which is ignored).
      - Creating prototype cycles (which will throw an error in strict mode and some engines).

11. **`ObjectGetOwnPropertySymbols(O)`:**
    - **Functionality:** Implements `Object.getOwnPropertySymbols()`. Returns an array of all own symbol properties found directly upon a given object.
    - **JavaScript Example:**
      ```javascript
      const sym1 = Symbol('foo');
      const sym2 = Symbol('bar');
      const obj = { [sym1]: 'baz', a: 1, [sym2]: 'qux' };
      const symbols = Object.getOwnPropertySymbols(obj);
      console.log(symbols); // Output: [Symbol(foo), Symbol(bar)]
      ```
    - **Code Logic Inference:**
      - **Input:** A JavaScript object.
      - **Output:** An array containing the Symbol objects representing the own symbol properties of the input object.
    - **Common Programming Errors:**
      - Expecting this to return string keys as well (use `Object.keys()` or `Object.getOwnPropertyNames()` for that).

12. **`ObjectIsFrozen(O)`:**
    - **Functionality:** Implements `Object.isFrozen()`. Determines if an object is frozen.
    - **JavaScript Example:**
      ```javascript
      const obj1 = { a: 1 };
      console.log(Object.isFrozen(obj1)); // Output: false
      Object.freeze(obj1);
      console.log(Object.isFrozen(obj1)); // Output: true

      const obj2 = 123;
      console.log(Object.isFrozen(obj2)); // Output: true (primitives are considered frozen)
      ```
    - **Code Logic Inference:**
      - **Input:** A JavaScript object.
      - **Output:** `true` if the object is frozen, `false` otherwise. For non-object types, it returns `true`.
    - **Common Programming Errors:**
      - Not realizing that primitive values are considered frozen.

13. **`ObjectIsSealed(O)`:**
    - **Functionality:** Implements `Object.isSealed()`. Determines if an object is sealed.
    - **JavaScript Example:**
      ```javascript
      const obj1 = { a: 1 };
      console.log(Object.isSealed(obj1)); // Output: false
      Object.seal(obj1);
      console.log(Object.isSealed(obj1)); // Output: true

      const obj2 = 123;
      console.log(Object.isSealed(obj2)); // Output: true (primitives are considered sealed)
      ```
    - **Code Logic Inference:**
      - **Input:** A JavaScript object.
      - **Output:** `true` if the object is sealed, `false` otherwise. For non-object types, it returns `true`.
    - **Common Programming Errors:**
      - Confusing `isSealed` with `isFrozen`. A sealed object prevents adding/removing properties, while a frozen object also makes existing data properties non-writable.

14. **`ObjectGetOwnPropertyDescriptors(O)`:**
    - **Functionality:** Implements `Object.getOwnPropertyDescriptors()`. Returns an object containing all own property descriptors of an object.
    - **JavaScript Example:**
      ```javascript
      const obj = { a: 1, get b() { return 2; } };
      const descriptors = Object.getOwnPropertyDescriptors(obj);
      console.log(descriptors);
      /* Output:
      {
        a: { value: 1, writable: true, enumerable: true, configurable: true },
        b: { get: [Function: b], set: undefined, enumerable: true, configurable: true }
      }
      */
      ```
    - **Code Logic Inference:**
      - **Input:** A JavaScript object.
      - **Output:** An object where keys are the own property names of the input object, and values are their corresponding property descriptor objects.
    - **Common Programming Errors:**
      - Expecting inherited properties to be included (it only returns own properties).

15. **`ObjectSeal(O)`:**
    - **Functionality:** Implements `Object.seal()`. Seals an object, preventing new properties from being added and marking all existing properties as non-configurable. Returns the sealed object.
    - **JavaScript Example:**
      ```javascript
      const obj = { a: 1 };
      Object.seal(obj);
      obj.b = 2; // Strict mode would throw a TypeError
      delete obj.a; // Strict mode would throw a TypeError
      Object.defineProperty(obj, 'a', { configurable: true }); // TypeError
      console.log(obj); // Output: { a: 1 }
      console.log(Object.isSealed(obj)); // Output: true
      ```
    - **Code Logic Inference:**
      - **Input:** A JavaScript object.
      - **Output:** The input object (after attempting to seal it). It sets the `configurable` attribute of all own properties to `false` and prevents adding new properties.
    - **Common Programming Errors:**
      - Thinking `Object.seal()` makes properties non-writable (it only affects configurability).

**Regarding `.tq` files:**

The prompt states: "如果v8/src/builtins/builtins-object.cc以.tq结尾，那它是个v8 torque源代码".

Since the filename is `builtins-object.cc`, it **does not** end with `.tq`. Therefore, this file is a **standard C++ source file** within the V8 project, not a Torque source file. Torque is a domain-specific language used within V8 for defining built-in functions in a more type-safe and higher-level way than raw C++.

In summary, `v8/src/builtins/builtins-object.cc` is a crucial part of the V8 engine responsible for implementing the fundamental behaviors of JavaScript objects as defined by the ECMAScript specification. It provides the underlying C++ implementation for many of the core `Object` methods that JavaScript developers use daily.

### 提示词
```
这是目录为v8/src/builtins/builtins-object.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/builtins-object.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
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
```