Response:
Let's break down the thought process for analyzing the C++ code and generating the response.

**1. Understanding the Goal:**

The core request is to understand the functionality of `v8/src/objects/property-descriptor.cc`. Specifically, the request asks for:

* A summary of its functions.
* Checking if it's a Torque file (it's not).
* Demonstrating the connection to JavaScript with examples.
* Providing code logic examples with inputs and outputs.
* Identifying common programming errors related to this code.

**2. Initial Code Scan and Keyword Identification:**

The first step is to quickly skim the code and identify key terms and structures. I'm looking for things like:

* **Class/struct names:** `PropertyDescriptor`, `PropertyDescriptorObject`.
* **Function names:** `ToObject`, `ToPropertyDescriptor`, `CompletePropertyDescriptor`, `CreateDataProperty`, `GetPropertyIfPresent`, `ToPropertyDescriptorFastPath`.
* **V8-specific types/namespaces:** `Isolate`, `Handle`, `Factory`, `JSObject`, `String`, `JSAny`, `Map`, `LookupIterator`, `PropertyDetails`.
* **Keywords related to property attributes:** `enumerable`, `configurable`, `writable`, `value`, `get`, `set`.
* **Error handling:** `Throw`, `TypeError`.
* **Comments:**  Pay attention to comments explaining specific steps or logic, especially those referencing ECMAScript specifications (like "ES6 6.2.4.4").

**3. Dissecting Key Functions:**

Now, I'll focus on the main functions and try to understand their purpose:

* **`PropertyDescriptor::ToObject(Isolate* isolate)`:** The name suggests converting a `PropertyDescriptor` (an internal C++ representation) into a JavaScript object. The code creates `JSObject` instances with specific maps (`accessor_property_descriptor_map`, `data_property_descriptor_map`) and sets properties like `value`, `writable`, `get`, `set`, etc. This strongly links it to how JavaScript property descriptors are represented.

* **`PropertyDescriptor::ToPropertyDescriptor(Isolate* isolate, Handle<JSAny> obj, PropertyDescriptor* desc)`:** This function takes a JavaScript object (`JSAny`) and tries to convert it *into* a C++ `PropertyDescriptor`. The code checks for the presence of properties like "enumerable", "configurable", "value", etc., and populates the `desc` object accordingly. The "fast path" logic is interesting – it optimizes the conversion for simple objects. The error handling for non-object inputs and invalid getter/setter types is also important.

* **`PropertyDescriptor::CompletePropertyDescriptor(Isolate* isolate, PropertyDescriptor* desc)`:** This function seems to fill in default values for a `PropertyDescriptor` if they are missing. The comments mention default values for `value`, `writable`, `get`, `set`, `enumerable`, and `configurable`. This relates to the default behavior of properties in JavaScript.

* **Helper functions (`GetPropertyIfPresent`, `ToPropertyDescriptorFastPath`, `CreateDataProperty`):** These break down the logic of the main functions into smaller, more manageable units. `GetPropertyIfPresent` is about checking for the existence of a property and retrieving its value. `ToPropertyDescriptorFastPath` is an optimization. `CreateDataProperty` is a utility for setting properties on a JS object.

**4. Connecting to JavaScript:**

Based on the understanding of the functions, I can now draw parallels to JavaScript concepts:

* The `PropertyDescriptor` class directly corresponds to the concept of a *property descriptor* in JavaScript. The attributes like `enumerable`, `configurable`, `writable`, `value`, `get`, and `set` are fundamental to how properties behave.
* The `ToObject` function is used when JavaScript code needs to get the descriptor of a property as an object (e.g., using `Object.getOwnPropertyDescriptor`).
* The `ToPropertyDescriptor` function is used when JavaScript operations need to interpret an object as a property descriptor (e.g., in `Object.defineProperty`).

**5. Crafting JavaScript Examples:**

Now, it's time to create concrete JavaScript examples that demonstrate the functionality of the C++ code:

* **`Object.getOwnPropertyDescriptor()`:**  Directly relates to `PropertyDescriptor::ToObject`.
* **`Object.defineProperty()`:** Directly relates to `PropertyDescriptor::ToPropertyDescriptor` and the validation it performs.
* Demonstrating the default values when properties are not explicitly defined connects to `CompletePropertyDescriptor`.

**6. Developing Code Logic Examples:**

For code logic examples, I'll choose scenarios that exercise the different parts of the `ToPropertyDescriptor` function:

* **Basic data descriptor:**  Demonstrates the handling of `value` and `writable`.
* **Accessor descriptor:**  Demonstrates the handling of `get` and `set`.
* **Invalid descriptor:** Shows the error handling for conflicting `value`/`writable` with `get`/`set`.

For each example, I'll define a clear *input* (the JavaScript object) and the expected *output* (the resulting `PropertyDescriptor` attributes).

**7. Identifying Common Programming Errors:**

This involves thinking about how developers might misuse or misunderstand property descriptors in JavaScript, which are directly related to the logic in the C++ code:

* **Conflicting data and accessor properties:**  The C++ code explicitly checks for this and throws an error, so it's a good example.
* **Non-callable getter/setter:** The C++ code validates this.
* **Incorrect types for descriptor properties:** Although not explicitly shown in the C++ code *at this level*, it's a common error, so it's worth mentioning.

**8. Structuring the Response:**

Finally, I'll organize the information in a clear and logical way, following the structure requested in the prompt:

* Start with the overall functionality.
* Address the Torque file question.
* Provide JavaScript examples with explanations.
* Present the code logic examples with inputs and outputs.
* List the common programming errors.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe the `.cc` file directly implements the JavaScript functions.
* **Correction:** Realized that the `.cc` file is a lower-level implementation within the V8 engine. It provides the *mechanism* for property descriptors, but the actual JavaScript API is exposed through other parts of V8.

* **Initial thought:** Focus only on the success cases.
* **Correction:** Added examples of error conditions and how the C++ code handles them (throwing `TypeError`).

* **Initial thought:** Keep the JavaScript examples very simple.
* **Refinement:** Added more detailed explanations of how the JavaScript code relates to the C++ functionality.

By following these steps, I can systematically analyze the C++ code, understand its purpose, and generate a comprehensive and accurate response that addresses all aspects of the user's request.
This C++ source file, `v8/src/objects/property-descriptor.cc`, is a core part of the V8 JavaScript engine responsible for **managing and manipulating property descriptors**. Property descriptors define the characteristics of object properties in JavaScript, such as whether they are writable, enumerable, or configurable, and their associated value or getter/setter functions.

Here's a breakdown of its functionalities:

**1. Representation of Property Descriptors:**

* It defines the `PropertyDescriptor` class, which is a C++ structure used to represent the attributes of a JavaScript property. These attributes include:
    * `value`: The value associated with the property (for data properties).
    * `writable`: A boolean indicating if the property's value can be changed (for data properties).
    * `get`: A function to be called when the property is accessed (for accessor properties).
    * `set`: A function to be called when the property is assigned a value (for accessor properties).
    * `enumerable`: A boolean indicating if the property will be included in `for...in` loops and `Object.keys()`.
    * `configurable`: A boolean indicating if the property can be deleted or its attributes can be changed.

**2. Conversion to JavaScript Objects:**

* The `ToObject(Isolate* isolate)` method converts a `PropertyDescriptor` C++ object into a regular JavaScript object. This JavaScript object represents the property descriptor and can be used in JavaScript code (e.g., as the return value of `Object.getOwnPropertyDescriptor`).

**3. Conversion from JavaScript Objects:**

* The static method `ToPropertyDescriptor(Isolate* isolate, Handle<JSAny> obj, PropertyDescriptor* desc)` takes a JavaScript object as input and attempts to convert it into a C++ `PropertyDescriptor`. This is crucial for operations like `Object.defineProperty` where a JavaScript object specifies the attributes of a property.
    * It performs validation to ensure the input JavaScript object is a valid property descriptor object.
    * It extracts the `enumerable`, `configurable`, `value`, `writable`, `get`, and `set` properties from the input object.
    * It throws `TypeError` exceptions if the input object is not valid (e.g., if it's not an object, or if it has both `value`/`writable` and `get`/`set`).

**4. Completing Property Descriptors:**

* The static method `CompletePropertyDescriptor(Isolate* isolate, PropertyDescriptor* desc)` fills in any missing attributes of a `PropertyDescriptor` with their default values according to the ECMAScript specification. For instance, if `writable` is not specified, it defaults to `false`.

**5. Optimized Fast Path:**

* The `ToPropertyDescriptorFastPath` function provides an optimized path for converting simple JavaScript objects (with no prototype chain and only own, fast data properties) into `PropertyDescriptor` objects. This avoids the overhead of a full property lookup.

**6. Creation of Data Properties:**

* The `CreateDataProperty` helper function is used within `ToObject` to efficiently create data properties on the resulting JavaScript descriptor object.

**Is `v8/src/objects/property-descriptor.cc` a Torque file?**

No, `v8/src/objects/property-descriptor.cc` ends with `.cc`, which indicates it's a standard C++ source file. Torque source files end with `.tq`.

**Relationship with JavaScript and Examples:**

This file directly implements the underlying mechanisms for how JavaScript handles property descriptors. Here are some JavaScript examples that relate to the functionality in `property-descriptor.cc`:

**Example 1: `Object.getOwnPropertyDescriptor()`**

```javascript
const obj = { x: 10 };
const descriptor = Object.getOwnPropertyDescriptor(obj, 'x');
console.log(descriptor);
// Output (something like): { value: 10, writable: true, enumerable: true, configurable: true }
```

Internally, V8 uses the logic in `property-descriptor.cc`'s `ToObject` method to create the JavaScript object representing this descriptor.

**Example 2: `Object.defineProperty()`**

```javascript
const obj = {};
Object.defineProperty(obj, 'y', {
  value: 20,
  writable: false,
  enumerable: false,
  configurable: false
});

console.log(obj.y); // Output: 20
obj.y = 30;
console.log(obj.y); // Output: 20 (because writable is false)
console.log(Object.keys(obj)); // Output: [] (because enumerable is false)
delete obj.y; // Will fail silently because configurable is false
console.log(obj.y); // Output: 20
```

When `Object.defineProperty` is called, V8 uses the logic in `property-descriptor.cc`'s `ToPropertyDescriptor` method to parse the descriptor object provided as the third argument and create an internal `PropertyDescriptor` representation. It also performs the validation checks.

**Example 3: Default Descriptor Attributes**

```javascript
const obj = {};
Object.defineProperty(obj, 'z', { value: 40 });
const descriptorZ = Object.getOwnPropertyDescriptor(obj, 'z');
console.log(descriptorZ);
// Output (something like): { value: 40, writable: false, enumerable: false, configurable: false }
```

Notice that `writable`, `enumerable`, and `configurable` are `false` even though they weren't explicitly specified in `defineProperty`. This is because the `CompletePropertyDescriptor` method in `property-descriptor.cc` fills in these defaults.

**Code Logic Inference with Assumptions:**

Let's consider the `ToPropertyDescriptor` function and assume the following input:

**Assumption:**

* `isolate`: A valid `v8::internal::Isolate` object representing the current V8 isolate.
* `obj`: A `Handle<JSAny>` pointing to the following JavaScript object:
  ```javascript
  {
    enumerable: 'true',  // String "true"
    configurable: 1,      // Number 1 (coerces to true)
    value: 100
  }
  ```
* `desc`: An initially empty `PropertyDescriptor` C++ object.

**Expected Output:**

After calling `PropertyDescriptor::ToPropertyDescriptor(isolate, obj, desc)`, the `desc` object should have the following attributes set:

* `enumerable`: `true` (because the string "true" coerces to true in JavaScript's ToBoolean).
* `configurable`: `true` (because the number 1 coerces to true).
* `value`: A `Handle<JSAny>` pointing to the JavaScript number `100`.
* `writable`: `false` (not present in the input object, so it will remain in its default uninitialized state or be filled later by `CompletePropertyDescriptor`).
* `get`: Not set.
* `set`: Not set.

**Reasoning:**

The `ToPropertyDescriptor` function retrieves the values of "enumerable", "configurable", and "value" properties from the input JavaScript object. It uses JavaScript's `ToBoolean` conversion for "enumerable" and "configurable". Since "writable", "get", and "set" are not present, those attributes of `desc` will remain unset at this stage.

**User-Common Programming Errors:**

Here are some common programming errors related to property descriptors that the code in `property-descriptor.cc` helps to prevent or handle:

1. **Providing a non-object as a descriptor to `Object.defineProperty`:**

   ```javascript
   const obj = {};
   try {
     Object.defineProperty(obj, 'myProp', 'not an object'); // Error!
   } catch (e) {
     console.error(e); // TypeError: Property description must be an object
   }
   ```

   The `ToPropertyDescriptor` function checks if the input is a `JSReceiver` (an object). If not, it throws a `TypeError`.

2. **Defining both data and accessor properties in the same descriptor:**

   ```javascript
   const obj = {};
   try {
     Object.defineProperty(obj, 'badProp', {
       value: 123,
       get: function() { return 456; }
     });
   } catch (e) {
     console.error(e); // TypeError: Invalid property descriptor. Cannot both specify accessors and a value or writable attribute
   }
   ```

   The `ToPropertyDescriptor` function explicitly checks for this condition (`(desc->has_get() || desc->has_set()) && (desc->has_value() || desc->has_writable())`) and throws a `TypeError`.

3. **Providing a non-callable getter or setter:**

   ```javascript
   const obj = {};
   try {
     Object.defineProperty(obj, 'badAccessor', {
       get: 'not a function'
     });
   } catch (e) {
     console.error(e); // TypeError: Getter must be a function: not a function
   }
   ```

   The `ToPropertyDescriptor` function verifies that the provided `get` and `set` properties are either callable or `undefined`.

4. **Misunderstanding default values:** Developers might assume that if they don't specify `writable`, `enumerable`, or `configurable`, they will default to `true`. However, the defaults are `false`. This file's `CompletePropertyDescriptor` method enforces these defaults.

In summary, `v8/src/objects/property-descriptor.cc` is a fundamental piece of V8 that underpins how JavaScript defines and manipulates object properties. It handles the internal representation, conversion between C++ and JavaScript objects, validation, and the application of default values for property descriptors, ensuring the correct behavior of JavaScript's property mechanisms.

Prompt: 
```
这是目录为v8/src/objects/property-descriptor.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/property-descriptor.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
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

"""

```