Response: My goal is to analyze the provided C++ code snippet and summarize its functionality, explaining its connection to JavaScript with examples. Since this is part 1 of 4, I'll focus on the core object manipulation aspects and avoid diving too deep into specific object types that might be covered later.

**Thinking Process:**

1. **Initial Scan for Keywords and Includes:**  I'll look for recurring terms and the included header files to get a high-level understanding of the domain. "objects", "JS", "property", "lookup", "define", "delete", "has", "get", "set" stand out. The includes point towards various object types within V8 (arrays, functions, promises, etc.) and core V8 infrastructure (handles, isolate, heap).

2. **Focus on `JSReceiver`:** The code heavily features `JSReceiver`. This suggests the file deals with the fundamental operations on JavaScript objects. I'll pay close attention to the methods within the `JSReceiver` namespace.

3. **Analyze Key Methods:** I'll go through the prominent methods like `HasProperty`, `HasOwnProperty`, `GetDataProperty`, `DefineOwnProperty`, `DeleteProperty`, `SetOrCopyDataProperties`, and `GetConstructorName`. I'll try to understand what each method does at a basic level.

4. **Identify Core Functionality:**  The methods seem to implement the fundamental operations you can perform on JavaScript objects: checking for property existence, retrieving property values, defining new properties, deleting properties, and copying properties.

5. **Connect to JavaScript Concepts:** For each key method, I'll try to think of the corresponding JavaScript syntax or built-in methods. For example:
    * `HasProperty` relates to the `in` operator.
    * `HasOwnProperty` relates to `hasOwnProperty()`.
    * `GetDataProperty` relates to accessing properties (e.g., `obj.prop` or `obj['prop']`).
    * `DefineOwnProperty` relates to `Object.defineProperty()`.
    * `DeleteProperty` relates to the `delete` operator.
    * `SetOrCopyDataProperties` relates to `Object.assign()`.
    * `GetConstructorName` relates to accessing the `constructor.name` property.

6. **Formulate a Concise Summary:** I'll synthesize my findings into a clear and concise summary of the file's purpose. I'll emphasize its role in implementing the core behaviors of JavaScript objects.

7. **Provide JavaScript Examples:** For key functionalities, I'll create simple JavaScript code snippets that demonstrate the corresponding actions. These examples will help illustrate the connection between the C++ code and JavaScript behavior.

8. **Address "Part 1 of 4":**  Since this is the first part, I'll focus on the foundational aspects and avoid speculating too much about what might be in the subsequent parts. I'll keep the summary relatively general and emphasize the basic object operations.

**Self-Correction/Refinement during the process:**

* **Initial thought:** This file might be responsible for *creating* JavaScript objects.
* **Correction:** While it might be involved in the creation process indirectly (through property definitions, etc.), the core focus seems to be on *manipulating* existing objects. The presence of methods like `HasProperty` and `DeleteProperty` points to this.
* **Initial thought:** I should explain the intricate details of how V8's heap works.
* **Correction:** Given the "Part 1 of 4" constraint, I'll keep the explanation at a higher level and avoid getting bogged down in low-level details unless absolutely necessary for explaining the core functionality. I'll prioritize the *what* over the *how* for now.
* **Initial thought:**  I should explain each included header file.
* **Correction:**  That would be too granular for a functional summary. I'll mention the general categories of includes (API, execution, heap, objects) without going into detail about each individual file.

By following this process, I arrived at the summary and examples provided in the initial prompt's example answer. The key was to identify the core operations on JavaScript objects and then link those operations to their corresponding JavaScript syntax.
Based on the included header files and the function names within the provided C++ code snippet (`v8/src/objects/js-objects.cc`, part 1), its primary function is to **define and implement the core behavior and properties of various JavaScript objects within the V8 engine.**

Here's a breakdown of its functionalities:

* **Fundamental JavaScript Object Operations:**  The code implements essential operations that can be performed on JavaScript objects, including:
    * **Property Access and Existence:**  Functions like `HasProperty`, `HasOwnProperty`, and `GetDataProperty` handle checking if an object has a certain property and retrieving its value.
    * **Property Definition and Modification:**  Functions like `DefineProperty`, `DefineProperties`, and `OrdinaryDefineOwnProperty` deal with defining new properties on objects, including their attributes (writable, enumerable, configurable).
    * **Property Deletion:** The `DeleteProperty` function handles the removal of properties from objects.
    * **Prototype Chain Traversal:** `HasInPrototypeChain` is used to check if an object inherits from a specific prototype.
    * **Object Identity and Hashing:**  Functions related to identity hash (`SetIdentityHash`, `GetIdentityHash`, `CreateIdentityHash`) are used for efficient object comparison and storage in hash tables.
    * **Constructor Retrieval:** `GetConstructor` and `GetConstructorName` are used to determine the constructor function of an object.
    * **Realm (Context) Retrieval:** Functions like `GetFunctionRealm` and `GetContextForMicrotask` are involved in managing the execution context of functions and microtasks associated with objects.
    * **Property Enumeration and Copying:** `SetOrCopyDataProperties` handles copying properties from one object to another, similar to `Object.assign()`.

* **Handling Different JavaScript Object Types:** The code includes headers for various specific JavaScript object types like `JSArray`, `JSFunction`, `JSProxy`, `JSTypedArray`, `JSMap`, `JSSet`, `JSError`, `JSPromise`, etc. This suggests that this file provides a base implementation for common object operations that can be further specialized by these specific object types.

* **Interaction with Interceptors and Proxies:**  The code handles interaction with interceptors (custom C++ code that can intercept property access) and proxies (objects that virtualize property access).

* **Support for Native Code and Callbacks:** The code includes elements related to API callbacks and interaction with native code, indicating its role in bridging the gap between JavaScript and C++.

**Relationship to JavaScript Functionality (with examples):**

This C++ code directly implements the underlying mechanisms that make JavaScript object behavior possible. Here are some JavaScript examples illustrating the connection:

**1. `HasProperty` and the `in` operator:**

```javascript
const obj = { x: 10 };
console.log('x' in obj); // Output: true (internally uses a mechanism similar to HasProperty)
console.log('y' in obj); // Output: false
```

**2. `HasOwnProperty` and the `hasOwnProperty()` method:**

```javascript
const obj = { x: 10 };
console.log(obj.hasOwnProperty('x')); // Output: true (directly relates to HasOwnProperty)
console.log(obj.hasOwnProperty('toString')); // Output: false (inherited property)
```

**3. `GetDataProperty` and property access:**

```javascript
const obj = { name: 'Alice' };
console.log(obj.name); // Output: Alice (internally uses something like GetDataProperty)
console.log(obj['name']); // Output: Alice
```

**4. `DefineProperty` and `Object.defineProperty()`:**

```javascript
const obj = {};
Object.defineProperty(obj, 'y', {
  value: 20,
  writable: false,
  enumerable: true,
  configurable: false
});
console.log(obj.y); // Output: 20
obj.y = 30; // Does nothing because writable is false
console.log(obj.y); // Output: 20
```

**5. `DeleteProperty` and the `delete` operator:**

```javascript
const obj = { z: 30 };
console.log(obj.z); // Output: 30
delete obj.z; // Uses a mechanism similar to DeleteProperty
console.log(obj.z); // Output: undefined
```

**6. `SetOrCopyDataProperties` and `Object.assign()`:**

```javascript
const target = { a: 1 };
const source = { b: 2, c: 3 };
Object.assign(target, source); // Internally leverages functions like SetOrCopyDataProperties
console.log(target); // Output: { a: 1, b: 2, c: 3 }
```

**In summary, this part of the `js-objects.cc` file provides the fundamental C++ implementation for how JavaScript objects behave in V8. It lays the groundwork for more specific object types and their interactions within the engine.**

### 提示词
```
这是目录为v8/src/objects/js-objects.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共4部分，请归纳一下它的功能
```

### 源代码
```
// Copyright 2019 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/objects/js-objects.h"

#include <limits>
#include <optional>

#include "src/api/api-arguments-inl.h"
#include "src/api/api-natives.h"
#include "src/common/assert-scope.h"
#include "src/common/globals.h"
#include "src/date/date.h"
#include "src/execution/arguments.h"
#include "src/execution/frames.h"
#include "src/execution/isolate-utils.h"
#include "src/execution/isolate.h"
#include "src/handles/handles-inl.h"
#include "src/handles/maybe-handles.h"
#include "src/heap/factory-inl.h"
#include "src/heap/heap-inl.h"
#include "src/heap/heap-layout-inl.h"
#include "src/heap/mutable-page-metadata.h"
#include "src/heap/pretenuring-handler-inl.h"
#include "src/init/bootstrapper.h"
#include "src/logging/counters.h"
#include "src/logging/log.h"
#include "src/objects/allocation-site-inl.h"
#include "src/objects/api-callbacks.h"
#include "src/objects/arguments-inl.h"
#include "src/objects/dictionary.h"
#include "src/objects/elements.h"
#include "src/objects/field-type.h"
#include "src/objects/fixed-array.h"
#include "src/objects/heap-number.h"
#include "src/objects/heap-object.h"
#include "src/objects/js-array-buffer-inl.h"
#include "src/objects/js-array-inl.h"
#include "src/objects/js-atomics-synchronization.h"
#include "src/objects/js-collection.h"
#include "src/objects/js-disposable-stack.h"
#include "src/objects/js-generator-inl.h"
#include "src/objects/js-iterator-helpers-inl.h"
#include "src/objects/js-promise.h"
#include "src/objects/js-raw-json-inl.h"
#include "src/objects/js-regexp-inl.h"
#include "src/objects/js-regexp-string-iterator.h"
#include "src/objects/js-shadow-realm.h"
#include "src/objects/js-shared-array-inl.h"
#include "src/objects/js-struct-inl.h"
#include "src/objects/js-temporal-objects-inl.h"
#include "src/objects/js-weak-refs.h"
#include "src/objects/lookup.h"
#include "src/objects/map-inl.h"
#include "src/objects/map-updater.h"
#include "src/objects/module.h"
#include "src/objects/objects-body-descriptors-inl.h"
#include "src/objects/objects-inl.h"
#include "src/objects/oddball.h"
#include "src/objects/property-cell.h"
#include "src/objects/property-descriptor.h"
#include "src/objects/property.h"
#include "src/objects/prototype-info.h"
#include "src/objects/prototype.h"
#include "src/objects/shared-function-info.h"
#include "src/objects/swiss-name-dictionary-inl.h"
#include "src/objects/tagged.h"
#include "src/objects/transitions.h"
#include "src/strings/string-builder-inl.h"
#include "src/strings/string-stream.h"
#include "src/utils/ostreams.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/debug/debug-wasm-objects.h"
#include "src/wasm/wasm-objects.h"
#endif  // V8_ENABLE_WEBASSEMBLY

#ifdef V8_INTL_SUPPORT
#include "src/objects/js-break-iterator.h"
#include "src/objects/js-collator.h"
#include "src/objects/js-date-time-format.h"
#include "src/objects/js-display-names.h"
#include "src/objects/js-duration-format.h"
#include "src/objects/js-list-format.h"
#include "src/objects/js-locale.h"
#include "src/objects/js-number-format.h"
#include "src/objects/js-plural-rules.h"
#include "src/objects/js-relative-time-format.h"
#include "src/objects/js-segment-iterator.h"
#include "src/objects/js-segmenter.h"
#include "src/objects/js-segments.h"
#endif  // V8_INTL_SUPPORT

namespace v8::internal {

// static
Maybe<bool> JSReceiver::HasProperty(LookupIterator* it) {
  for (;; it->Next()) {
    switch (it->state()) {
      case LookupIterator::TRANSITION:
        UNREACHABLE();
      case LookupIterator::JSPROXY:
        return JSProxy::HasProperty(it->isolate(), it->GetHolder<JSProxy>(),
                                    it->GetName());
      case LookupIterator::WASM_OBJECT:
        return Just(false);
      case LookupIterator::INTERCEPTOR: {
        Maybe<PropertyAttributes> result =
            JSObject::GetPropertyAttributesWithInterceptor(it);
        if (result.IsNothing()) return Nothing<bool>();
        if (result.FromJust() != ABSENT) return Just(true);
        continue;
      }
      case LookupIterator::ACCESS_CHECK: {
        if (it->HasAccess()) continue;
        Maybe<PropertyAttributes> result =
            JSObject::GetPropertyAttributesWithFailedAccessCheck(it);
        if (result.IsNothing()) return Nothing<bool>();
        return Just(result.FromJust() != ABSENT);
      }
      case LookupIterator::TYPED_ARRAY_INDEX_NOT_FOUND:
        // TypedArray out-of-bounds access.
        return Just(false);
      case LookupIterator::ACCESSOR:
      case LookupIterator::DATA:
        return Just(true);
      case LookupIterator::NOT_FOUND:
        return Just(false);
    }
    UNREACHABLE();
  }
}

// static
Maybe<bool> JSReceiver::HasOwnProperty(Isolate* isolate,
                                       Handle<JSReceiver> object,
                                       Handle<Name> name) {
  if (IsJSModuleNamespace(*object)) {
    PropertyDescriptor desc;
    return JSReceiver::GetOwnPropertyDescriptor(isolate, object, name, &desc);
  }

  if (IsJSObject(*object)) {  // Shortcut.
    PropertyKey key(isolate, name);
    LookupIterator it(isolate, object, key, LookupIterator::OWN);
    return HasProperty(&it);
  }

  Maybe<PropertyAttributes> attributes =
      JSReceiver::GetOwnPropertyAttributes(object, name);
  MAYBE_RETURN(attributes, Nothing<bool>());
  return Just(attributes.FromJust() != ABSENT);
}

Handle<Object> JSReceiver::GetDataProperty(LookupIterator* it,
                                           AllocationPolicy allocation_policy) {
  for (;; it->Next()) {
    switch (it->state()) {
      case LookupIterator::INTERCEPTOR:
      case LookupIterator::TRANSITION:
        UNREACHABLE();
      case LookupIterator::ACCESS_CHECK:
        // Support calling this method without an active context, but refuse
        // access to access-checked objects in that case.
        if (!it->isolate()->context().is_null() && it->HasAccess()) continue;
        [[fallthrough]];
      case LookupIterator::JSPROXY:
      case LookupIterator::WASM_OBJECT:
        it->NotFound();
        return it->isolate()->factory()->undefined_value();
      case LookupIterator::ACCESSOR:
        // TODO(verwaest): For now this doesn't call into AccessorInfo, since
        // clients don't need it. Update once relevant.
        it->NotFound();
        return it->isolate()->factory()->undefined_value();
      case LookupIterator::TYPED_ARRAY_INDEX_NOT_FOUND:
        return it->isolate()->factory()->undefined_value();
      case LookupIterator::DATA:
        return it->GetDataValue(allocation_policy);
      case LookupIterator::NOT_FOUND:
        return it->isolate()->factory()->undefined_value();
    }
    UNREACHABLE();
  }
}

// static
Maybe<bool> JSReceiver::HasInPrototypeChain(Isolate* isolate,
                                            Handle<JSReceiver> object,
                                            Handle<Object> proto) {
  PrototypeIterator iter(isolate, object, kStartAtReceiver);
  while (true) {
    if (!iter.AdvanceFollowingProxies()) return Nothing<bool>();
    if (iter.IsAtEnd()) return Just(false);
    if (PrototypeIterator::GetCurrent(iter).is_identical_to(proto)) {
      return Just(true);
    }
  }
}

// static
Maybe<bool> JSReceiver::CheckPrivateNameStore(LookupIterator* it,
                                              bool is_define) {
  DCHECK(it->GetName()->IsPrivateName());
  Isolate* isolate = it->isolate();
  Handle<String> name_string(
      Cast<String>(Cast<Symbol>(it->GetName())->description()), isolate);
  for (;; it->Next()) {
    switch (it->state()) {
      case LookupIterator::TRANSITION:
      case LookupIterator::INTERCEPTOR:
      case LookupIterator::JSPROXY:
      case LookupIterator::TYPED_ARRAY_INDEX_NOT_FOUND:
      case LookupIterator::ACCESSOR:
        UNREACHABLE();
      case LookupIterator::ACCESS_CHECK:
        if (!it->HasAccess()) {
          RETURN_ON_EXCEPTION_VALUE(isolate,
                                    isolate->ReportFailedAccessCheck(
                                        Cast<JSObject>(it->GetReceiver())),
                                    Nothing<bool>());
          UNREACHABLE();
        }
        continue;
      case LookupIterator::DATA:
        if (is_define) {
          MessageTemplate message =
              it->GetName()->IsPrivateBrand()
                  ? MessageTemplate::kInvalidPrivateBrandReinitialization
                  : MessageTemplate::kInvalidPrivateFieldReinitialization;
          RETURN_FAILURE(isolate,
                         GetShouldThrow(isolate, Nothing<ShouldThrow>()),
                         NewTypeError(message, name_string, it->GetReceiver()));
        }
        return Just(true);
      case LookupIterator::WASM_OBJECT:
        RETURN_FAILURE(isolate, kThrowOnError,
                       NewTypeError(MessageTemplate::kWasmObjectsAreOpaque));
      case LookupIterator::NOT_FOUND:
        if (!is_define) {
          RETURN_FAILURE(
              isolate, GetShouldThrow(isolate, Nothing<ShouldThrow>()),
              NewTypeError(MessageTemplate::kInvalidPrivateMemberWrite,
                           name_string, it->GetReceiver()));
        } else if (IsAlwaysSharedSpaceJSObject(*it->GetReceiver())) {
          RETURN_FAILURE(
              isolate, kThrowOnError,
              NewTypeError(MessageTemplate::kDefineDisallowed, name_string));
        }
        return Just(true);
    }
    UNREACHABLE();
  }
}

namespace {

bool HasExcludedProperty(base::Vector<DirectHandle<Object>> excluded_properties,
                         DirectHandle<Object> search_element) {
  // TODO(gsathya): Change this to be a hashtable.
  for (DirectHandle<Object> object : excluded_properties) {
    if (Object::SameValue(*search_element, *object)) {
      return true;
    }
  }

  return false;
}

// If direct handles are enabled, it is the responsibility of the caller to
// ensure that the memory pointed to by `excluded_properties` is scanned
// during CSS, e.g., it comes from a `DirectHandleVector<Object>`.
V8_WARN_UNUSED_RESULT Maybe<bool> FastAssign(
    Isolate* isolate, Handle<JSReceiver> target, Handle<Object> source,
    PropertiesEnumerationMode mode,
    base::Vector<DirectHandle<Object>> excluded_properties, bool use_set) {
  // Non-empty strings are the only non-JSReceivers that need to be handled
  // explicitly by Object.assign.
  if (!IsJSReceiver(*source)) {
    return Just(!IsString(*source) || Cast<String>(*source)->length() == 0);
  }

  // If the target is deprecated, the object will be updated on first store. If
  // the source for that store equals the target, this will invalidate the
  // cached representation of the source. Preventively upgrade the target.
  // Do this on each iteration since any property load could cause deprecation.
  if (target->map()->is_deprecated()) {
    JSObject::MigrateInstance(isolate, Cast<JSObject>(target));
  }

  DirectHandle<Map> map(Cast<JSReceiver>(*source)->map(), isolate);

  if (!IsJSObjectMap(*map)) return Just(false);
  if (!map->OnlyHasSimpleProperties()) return Just(false);

  Handle<JSObject> from = Cast<JSObject>(source);
  if (from->elements() != ReadOnlyRoots(isolate).empty_fixed_array()) {
    return Just(false);
  }

  // We should never try to copy properties from an object itself.
  CHECK_IMPLIES(!use_set, !target.is_identical_to(from));

  Handle<DescriptorArray> descriptors(map->instance_descriptors(isolate),
                                      isolate);

  bool stable = true;

  // Process symbols last and only do that if we found symbols.
  bool has_symbol = false;
  bool process_symbol_only = false;
  while (true) {
    for (InternalIndex i : map->IterateOwnDescriptors()) {
      HandleScope inner_scope(isolate);

      Handle<Name> next_key(descriptors->GetKey(i), isolate);
      if (mode == PropertiesEnumerationMode::kEnumerationOrder) {
        if (IsSymbol(*next_key)) {
          has_symbol = true;
          if (!process_symbol_only) continue;
        } else {
          if (process_symbol_only) continue;
        }
      }
      Handle<Object> prop_value;
      // Directly decode from the descriptor array if |from| did not change
      // shape.
      if (stable) {
        DCHECK_EQ(from->map(), *map);
        DCHECK_EQ(*descriptors, map->instance_descriptors(isolate));

        PropertyDetails details = descriptors->GetDetails(i);
        if (!details.IsEnumerable()) continue;
        if (details.kind() == PropertyKind::kData) {
          if (details.location() == PropertyLocation::kDescriptor) {
            prop_value = handle(descriptors->GetStrongValue(i), isolate);
          } else {
            Representation representation = details.representation();
            FieldIndex index = FieldIndex::ForPropertyIndex(
                *map, details.field_index(), representation);
            prop_value =
                JSObject::FastPropertyAt(isolate, from, representation, index);
          }
        } else {
          LookupIterator it(isolate, from, next_key,
                            LookupIterator::OWN_SKIP_INTERCEPTOR);
          ASSIGN_RETURN_ON_EXCEPTION_VALUE(
              isolate, prop_value, Object::GetProperty(&it), Nothing<bool>());
          stable = from->map() == *map;
          descriptors.PatchValue(map->instance_descriptors(isolate));
        }
      } else {
        // If the map did change, do a slower lookup. We are still guaranteed
        // that the object has a simple shape, and that the key is a name.
        LookupIterator it(isolate, from, next_key, from,
                          LookupIterator::OWN_SKIP_INTERCEPTOR);
        if (!it.IsFound()) continue;
        DCHECK(it.state() == LookupIterator::DATA ||
               it.state() == LookupIterator::ACCESSOR);
        if (!it.IsEnumerable()) continue;
        ASSIGN_RETURN_ON_EXCEPTION_VALUE(
            isolate, prop_value, Object::GetProperty(&it), Nothing<bool>());
      }

      if (use_set) {
        // The lookup will walk the prototype chain, so we have to be careful
        // to treat any key correctly for any receiver/holder.
        PropertyKey key(isolate, next_key);
        LookupIterator it(isolate, target, key);
        Maybe<bool> result =
            Object::SetProperty(&it, prop_value, StoreOrigin::kNamed,
                                Just(ShouldThrow::kThrowOnError));
        if (result.IsNothing()) return result;
        if (stable) {
          stable = from->map() == *map;
          descriptors.PatchValue(map->instance_descriptors(isolate));
        }
      } else {
        // No element indexes should get here or the exclusion check may
        // yield false negatives for type mismatch.
        if (!excluded_properties.empty() &&
            HasExcludedProperty(excluded_properties, next_key)) {
          continue;
        }

        // 4a ii 2. Perform ? CreateDataProperty(target, nextKey, propValue).
        // This is an OWN lookup, so constructing a named-mode LookupIterator
        // from {next_key} is safe.
        CHECK(JSReceiver::CreateDataProperty(isolate, target, next_key,
                                             prop_value, Just(kThrowOnError))
                  .FromJust());
      }
    }
    if (mode == PropertiesEnumerationMode::kEnumerationOrder) {
      if (process_symbol_only || !has_symbol) {
        return Just(true);
      }
      if (has_symbol) {
        process_symbol_only = true;
      }
    } else {
      DCHECK_EQ(mode, PropertiesEnumerationMode::kPropertyAdditionOrder);
      return Just(true);
    }
  }
  UNREACHABLE();
}
}  // namespace

// static
Maybe<bool> JSReceiver::SetOrCopyDataProperties(
    Isolate* isolate, Handle<JSReceiver> target, Handle<Object> source,
    PropertiesEnumerationMode mode,
    base::Vector<DirectHandle<Object>> excluded_properties, bool use_set) {
  Maybe<bool> fast_assign =
      FastAssign(isolate, target, source, mode, excluded_properties, use_set);
  if (fast_assign.IsNothing()) return Nothing<bool>();
  if (fast_assign.FromJust()) return Just(true);

  Handle<JSReceiver> from = Object::ToObject(isolate, source).ToHandleChecked();

  // 3b. Let keys be ? from.[[OwnPropertyKeys]]().
  Handle<FixedArray> keys;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, keys,
      KeyAccumulator::GetKeys(isolate, from, KeyCollectionMode::kOwnOnly,
                              ALL_PROPERTIES, GetKeysConversion::kKeepNumbers),
      Nothing<bool>());

  if (!from->HasFastProperties() && target->HasFastProperties() &&
      IsJSObject(*target) && !IsJSGlobalProxy(*target)) {
    // Convert to slow properties if we're guaranteed to overflow the number of
    // descriptors.
    int source_length;
    if (IsJSGlobalObject(*from)) {
      source_length = Cast<JSGlobalObject>(*from)
                          ->global_dictionary(kAcquireLoad)
                          ->NumberOfEnumerableProperties();
    } else if constexpr (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
      source_length =
          from->property_dictionary_swiss()->NumberOfEnumerableProperties();
    } else {
      source_length =
          from->property_dictionary()->NumberOfEnumerableProperties();
    }
    if (source_length > kMaxNumberOfDescriptors) {
      JSObject::NormalizeProperties(isolate, Cast<JSObject>(target),
                                    CLEAR_INOBJECT_PROPERTIES, source_length,
                                    "Copying data properties");
    }
  }

  // 4. Repeat for each element nextKey of keys in List order,
  for (int i = 0; i < keys->length(); ++i) {
    Handle<Object> next_key(keys->get(i), isolate);
    if (!excluded_properties.empty() &&
        HasExcludedProperty(excluded_properties, next_key)) {
      continue;
    }

    // 4a i. Let desc be ? from.[[GetOwnProperty]](nextKey).
    PropertyDescriptor desc;
    Maybe<bool> found =
        JSReceiver::GetOwnPropertyDescriptor(isolate, from, next_key, &desc);
    if (found.IsNothing()) return Nothing<bool>();
    // 4a ii. If desc is not undefined and desc.[[Enumerable]] is true, then
    if (found.FromJust() && desc.enumerable()) {
      // 4a ii 1. Let propValue be ? Get(from, nextKey).
      Handle<Object> prop_value;
      ASSIGN_RETURN_ON_EXCEPTION_VALUE(
          isolate, prop_value,
          Runtime::GetObjectProperty(isolate, from, next_key), Nothing<bool>());

      if (use_set) {
        // 4c ii 2. Let status be ? Set(to, nextKey, propValue, true).
        Handle<Object> status;
        ASSIGN_RETURN_ON_EXCEPTION_VALUE(
            isolate, status,
            Runtime::SetObjectProperty(isolate, target, next_key, prop_value,
                                       StoreOrigin::kMaybeKeyed,
                                       Just(ShouldThrow::kThrowOnError)),
            Nothing<bool>());
      } else {
        // 4a ii 2. Perform ! CreateDataProperty(target, nextKey, propValue).
        PropertyKey key(isolate, next_key);
        CHECK(JSReceiver::CreateDataProperty(isolate, target, key, prop_value,
                                             Just(kThrowOnError))
                  .FromJust());
      }
    }
  }

  return Just(true);
}

Tagged<String> JSReceiver::class_name() {
  ReadOnlyRoots roots = GetReadOnlyRoots();
  if (IsJSFunctionOrBoundFunctionOrWrappedFunction(*this)) {
    return roots.Function_string();
  }
  if (IsJSArgumentsObject(*this)) return roots.Arguments_string();
  if (IsJSArray(*this)) return roots.Array_string();
  if (IsJSArrayBuffer(*this)) {
    if (Cast<JSArrayBuffer>(*this)->is_shared()) {
      return roots.SharedArrayBuffer_string();
    }
    return roots.ArrayBuffer_string();
  }
  if (IsJSArrayIterator(*this)) return roots.ArrayIterator_string();
  if (IsJSDate(*this)) return roots.Date_string();
  if (IsJSError(*this)) return roots.Error_string();
  if (IsJSGeneratorObject(*this)) return roots.Generator_string();
  if (IsJSMap(*this)) return roots.Map_string();
  if (IsJSMapIterator(*this)) return roots.MapIterator_string();
  if (IsJSProxy(*this)) {
    return map()->is_callable() ? roots.Function_string()
                                : roots.Object_string();
  }
  if (IsJSRegExp(*this)) return roots.RegExp_string();
  if (IsJSSet(*this)) return roots.Set_string();
  if (IsJSSetIterator(*this)) return roots.SetIterator_string();
  if (IsJSTypedArray(*this)) {
#define SWITCH_KIND(Type, type, TYPE, ctype)       \
  if (map()->elements_kind() == TYPE##_ELEMENTS) { \
    return roots.Type##Array_string();             \
  }
    TYPED_ARRAYS(SWITCH_KIND)
#undef SWITCH_KIND
  }
  if (IsJSPrimitiveWrapper(*this)) {
    Tagged<Object> value = Cast<JSPrimitiveWrapper>(*this)->value();
    if (IsBoolean(value)) return roots.Boolean_string();
    if (IsString(value)) return roots.String_string();
    if (IsNumber(value)) return roots.Number_string();
    if (IsBigInt(value)) return roots.BigInt_string();
    if (IsSymbol(value)) return roots.Symbol_string();
    if (IsScript(value)) return roots.Script_string();
    UNREACHABLE();
  }
  if (IsJSWeakMap(*this)) return roots.WeakMap_string();
  if (IsJSWeakSet(*this)) return roots.WeakSet_string();
  if (IsJSGlobalProxy(*this)) return roots.global_string();
  if (IsShared(*this)) {
    if (IsJSSharedStruct(*this)) return roots.SharedStruct_string();
    if (IsJSSharedArray(*this)) return roots.SharedArray_string();
    if (IsJSAtomicsMutex(*this)) return roots.AtomicsMutex_string();
    if (IsJSAtomicsCondition(*this)) return roots.AtomicsCondition_string();
    // Other shared values are primitives.
    UNREACHABLE();
  }

  return roots.Object_string();
}

namespace {
std::pair<MaybeHandle<JSFunction>, Handle<String>> GetConstructorHelper(
    Isolate* isolate, Handle<JSReceiver> receiver) {
  // If the object was instantiated simply with base == new.target, the
  // constructor on the map provides the most accurate name.
  // Don't provide the info for prototypes, since their constructors are
  // reclaimed and replaced by Object in OptimizeAsPrototype.
  if (!IsJSProxy(*receiver) && receiver->map()->new_target_is_base() &&
      !receiver->map()->is_prototype_map()) {
    Handle<Object> maybe_constructor(receiver->map()->GetConstructor(),
                                     isolate);
    if (IsJSFunction(*maybe_constructor)) {
      Handle<JSFunction> constructor = Cast<JSFunction>(maybe_constructor);
      Handle<String> name = SharedFunctionInfo::DebugName(
          isolate, handle(constructor->shared(), isolate));
      if (name->length() != 0 &&
          !name->Equals(ReadOnlyRoots(isolate).Object_string())) {
        return std::make_pair(constructor, name);
      }
    } else if (IsFunctionTemplateInfo(*maybe_constructor)) {
      DirectHandle<FunctionTemplateInfo> function_template =
          Cast<FunctionTemplateInfo>(maybe_constructor);
      if (!IsUndefined(function_template->class_name(), isolate)) {
        return std::make_pair(
            MaybeHandle<JSFunction>(),
            handle(Cast<String>(function_template->class_name()), isolate));
      }
    }
  }

  for (PrototypeIterator it(isolate, receiver, kStartAtReceiver); !it.IsAtEnd();
       it.AdvanceIgnoringProxies()) {
    auto current = PrototypeIterator::GetCurrent<JSReceiver>(it);

    LookupIterator it_to_string_tag(
        isolate, receiver, isolate->factory()->to_string_tag_symbol(), current,
        LookupIterator::OWN_SKIP_INTERCEPTOR);
    auto maybe_to_string_tag = JSReceiver::GetDataProperty(
        &it_to_string_tag, AllocationPolicy::kAllocationDisallowed);
    if (IsString(*maybe_to_string_tag)) {
      return std::make_pair(MaybeHandle<JSFunction>(),
                            Cast<String>(maybe_to_string_tag));
    }

    // Consider the following example:
    //
    //   function A() {}
    //   function B() {}
    //   B.prototype = new A();
    //   B.prototype.constructor = B;
    //
    // The constructor name for `B.prototype` must yield "A", so we don't take
    // "constructor" into account for the receiver itself, but only starting
    // on the prototype chain.
    if (!receiver.is_identical_to(current)) {
      LookupIterator it_constructor(
          isolate, receiver, isolate->factory()->constructor_string(), current,
          LookupIterator::OWN_SKIP_INTERCEPTOR);
      auto maybe_constructor = JSReceiver::GetDataProperty(
          &it_constructor, AllocationPolicy::kAllocationDisallowed);
      if (IsJSFunction(*maybe_constructor)) {
        auto constructor = Cast<JSFunction>(maybe_constructor);
        auto name = SharedFunctionInfo::DebugName(
            isolate, handle(constructor->shared(), isolate));

        if (name->length() != 0 &&
            !name->Equals(ReadOnlyRoots(isolate).Object_string())) {
          return std::make_pair(constructor, name);
        }
      }
    }
  }

  return std::make_pair(MaybeHandle<JSFunction>(),
                        handle(receiver->class_name(), isolate));
}
}  // anonymous namespace

// static
MaybeHandle<JSFunction> JSReceiver::GetConstructor(
    Isolate* isolate, Handle<JSReceiver> receiver) {
  return GetConstructorHelper(isolate, receiver).first;
}

// static
Handle<String> JSReceiver::GetConstructorName(Isolate* isolate,
                                              Handle<JSReceiver> receiver) {
  return GetConstructorHelper(isolate, receiver).second;
}

// static
MaybeHandle<NativeContext> JSReceiver::GetFunctionRealm(
    DirectHandle<JSReceiver> receiver) {
  Isolate* isolate = receiver->GetIsolate();
  // This is implemented as a loop because it's possible to construct very
  // long chains of bound functions or proxies where a recursive implementation
  // would run out of stack space.
  DisallowGarbageCollection no_gc;
  Tagged<JSReceiver> current = *receiver;
  do {
    DCHECK(current->map()->is_constructor());
    InstanceType instance_type = current->map()->instance_type();
    if (InstanceTypeChecker::IsJSProxy(instance_type)) {
      Tagged<JSProxy> proxy = Cast<JSProxy>(current);
      if (proxy->IsRevoked()) {
        AllowGarbageCollection allow_allocating_errors;
        THROW_NEW_ERROR(isolate, NewTypeError(MessageTemplate::kProxyRevoked));
      }
      current = Cast<JSReceiver>(proxy->target());
      continue;
    }
    if (InstanceTypeChecker::IsJSFunction(instance_type)) {
      Tagged<JSFunction> function = Cast<JSFunction>(current);
      return handle(function->native_context(), isolate);
    }
    if (InstanceTypeChecker::IsJSBoundFunction(instance_type)) {
      Tagged<JSBoundFunction> function = Cast<JSBoundFunction>(current);
      current = function->bound_target_function();
      continue;
    }
    if (InstanceTypeChecker::IsJSWrappedFunction(instance_type)) {
      Tagged<JSWrappedFunction> function = Cast<JSWrappedFunction>(current);
      current = function->wrapped_target_function();
      continue;
    }
    Tagged<JSObject> object = Cast<JSObject>(current);
    DCHECK(!IsJSFunction(object));
    return object->GetCreationContext(isolate);
  } while (true);
}

// static
MaybeHandle<NativeContext> JSReceiver::GetContextForMicrotask(
    DirectHandle<JSReceiver> receiver) {
  Isolate* isolate = receiver->GetIsolate();
  while (IsJSBoundFunction(*receiver) || IsJSProxy(*receiver)) {
    if (IsJSBoundFunction(*receiver)) {
      receiver = direct_handle(
          Cast<JSBoundFunction>(receiver)->bound_target_function(), isolate);
    } else {
      DCHECK(IsJSProxy(*receiver));
      DirectHandle<Object> target(Cast<JSProxy>(receiver)->target(), isolate);
      if (!IsJSReceiver(*target)) return MaybeHandle<NativeContext>();
      receiver = Cast<JSReceiver>(target);
    }
  }

  if (!IsJSFunction(*receiver)) return MaybeHandle<NativeContext>();
  return handle(Cast<JSFunction>(receiver)->native_context(), isolate);
}

Maybe<PropertyAttributes> JSReceiver::GetPropertyAttributes(
    LookupIterator* it) {
  for (;; it->Next()) {
    switch (it->state()) {
      case LookupIterator::TRANSITION:
        UNREACHABLE();
      case LookupIterator::JSPROXY:
        return JSProxy::GetPropertyAttributes(it);
      case LookupIterator::WASM_OBJECT:
        return Just(ABSENT);
      case LookupIterator::INTERCEPTOR: {
        Maybe<PropertyAttributes> result =
            JSObject::GetPropertyAttributesWithInterceptor(it);
        if (result.IsNothing()) return result;
        if (result.FromJust() != ABSENT) return result;
        continue;
      }
      case LookupIterator::ACCESS_CHECK:
        if (it->HasAccess()) continue;
        return JSObject::GetPropertyAttributesWithFailedAccessCheck(it);
      case LookupIterator::TYPED_ARRAY_INDEX_NOT_FOUND:
        return Just(ABSENT);
      case LookupIterator::ACCESSOR:
        if (IsJSModuleNamespace(*it->GetHolder<Object>())) {
          return JSModuleNamespace::GetPropertyAttributes(it);
        } else {
          return Just(it->property_attributes());
        }
      case LookupIterator::DATA:
        return Just(it->property_attributes());
      case LookupIterator::NOT_FOUND:
        return Just(ABSENT);
    }
    UNREACHABLE();
  }
}

namespace {

Tagged<Object> SetHashAndUpdateProperties(Tagged<HeapObject> properties,
                                          int hash) {
  DCHECK_NE(PropertyArray::kNoHashSentinel, hash);
  DCHECK(PropertyArray::HashField::is_valid(hash));

  ReadOnlyRoots roots = properties->GetReadOnlyRoots();
  if (properties == roots.empty_fixed_array() ||
      properties == roots.empty_property_array() ||
      properties == roots.empty_property_dictionary() ||
      properties == roots.empty_swiss_property_dictionary()) {
    return Smi::FromInt(hash);
  }

  if (IsPropertyArray(properties)) {
    Cast<PropertyArray>(properties)->SetHash(hash);
    DCHECK_LT(0, Cast<PropertyArray>(properties)->length());
    return properties;
  }

  if (IsGlobalDictionary(properties)) {
    Cast<GlobalDictionary>(properties)->SetHash(hash);
    return properties;
  }

  DCHECK(IsPropertyDictionary(properties));
  Cast<PropertyDictionary>(properties)->SetHash(hash);

  return properties;
}

int GetIdentityHashHelper(Tagged<JSReceiver> object) {
  DisallowGarbageCollection no_gc;
  Tagged<Object> properties = object->raw_properties_or_hash();
  if (IsSmi(properties)) {
    return Smi::ToInt(properties);
  }

  if (IsPropertyArray(properties)) {
    return Cast<PropertyArray>(properties)->Hash();
  }

  if (IsPropertyDictionary(properties)) {
    return Cast<PropertyDictionary>(properties)->Hash();
  }

  if (IsGlobalDictionary(properties)) {
    return Cast<GlobalDictionary>(properties)->Hash();
  }

#ifdef DEBUG
  ReadOnlyRoots roots = object->GetReadOnlyRoots();
  DCHECK(properties == roots.empty_fixed_array() ||
         properties == roots.empty_property_dictionary() ||
         properties == roots.empty_swiss_property_dictionary());
#endif

  return PropertyArray::kNoHashSentinel;
}
}  // namespace

void JSReceiver::SetIdentityHash(int hash) {
  DisallowGarbageCollection no_gc;
  DCHECK_NE(PropertyArray::kNoHashSentinel, hash);
  DCHECK(PropertyArray::HashField::is_valid(hash));

  Tagged<HeapObject> existing_properties =
      Cast<HeapObject>(raw_properties_or_hash());
  Tagged<Object> new_properties =
      SetHashAndUpdateProperties(existing_properties, hash);
  set_raw_properties_or_hash(new_properties, kRelaxedStore);
}

void JSReceiver::SetProperties(Tagged<HeapObject> properties) {
  DCHECK_IMPLIES(IsPropertyArray(properties) &&
                     Cast<PropertyArray>(properties)->length() == 0,
                 properties == GetReadOnlyRoots().empty_property_array());
  DisallowGarbageCollection no_gc;
  int hash = GetIdentityHashHelper(*this);
  Tagged<Object> new_properties = properties;

  // TODO(cbruni): Make GetIdentityHashHelper return a bool so that we
  // don't have to manually compare against kNoHashSentinel.
  if (hash != PropertyArray::kNoHashSentinel) {
    new_properties = SetHashAndUpdateProperties(properties, hash);
  }

  set_raw_properties_or_hash(new_properties, kRelaxedStore);
}

Tagged<Object> JSReceiver::GetIdentityHash() {
  DisallowGarbageCollection no_gc;

  int hash = GetIdentityHashHelper(*this);
  if (hash == PropertyArray::kNoHashSentinel) {
    return GetReadOnlyRoots().undefined_value();
  }

  return Smi::FromInt(hash);
}

// static
Tagged<Smi> JSReceiver::CreateIdentityHash(Isolate* isolate,
                                           Tagged<JSReceiver> key) {
  DisallowGarbageCollection no_gc;
  int hash = isolate->GenerateIdentityHash(PropertyArray::HashField::kMax);
  DCHECK_NE(PropertyArray::kNoHashSentinel, hash);

  key->SetIdentityHash(hash);
  return Smi::FromInt(hash);
}

Tagged<Smi> JSReceiver::GetOrCreateIdentityHash(Isolate* isolate) {
  DisallowGarbageCollection no_gc;

  int hash = GetIdentityHashHelper(*this);
  if (hash != PropertyArray::kNoHashSentinel) {
    return Smi::FromInt(hash);
  }

  return JSReceiver::CreateIdentityHash(isolate, *this);
}

void JSReceiver::DeleteNormalizedProperty(DirectHandle<JSReceiver> object,
                                          InternalIndex entry) {
  DCHECK(!object->HasFastProperties());
  Isolate* isolate = object->GetIsolate();
  DCHECK(entry.is_found());

  if (IsJSGlobalObject(*object)) {
    // If we have a global object, invalidate the cell and remove it from the
    // global object's dictionary.
    Handle<GlobalDictionary> dictionary(
        Cast<JSGlobalObject>(*object)->global_dictionary(kAcquireLoad),
        isolate);

    DirectHandle<PropertyCell> cell(dictionary->CellAt(entry), isolate);

    DirectHandle<GlobalDictionary> new_dictionary =
        GlobalDictionary::DeleteEntry(isolate, dictionary, entry);
    Cast<JSGlobalObject>(*object)->set_global_dictionary(*new_dictionary,
                                                         kReleaseStore);

    cell->ClearAndInvalidate(ReadOnlyRoots(isolate));
  } else {
    if constexpr (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
      Handle<SwissNameDictionary> dictionary(
          object->property_dictionary_swiss(), isolate);

      dictionary = SwissNameDictionary::DeleteEntry(isolate, dictionary, entry);
      object->SetProperties(*dictionary);
    } else {
      Handle<NameDictionary> dictionary(object->property_dictionary(), isolate);

      dictionary = NameDictionary::DeleteEntry(isolate, dictionary, entry);
      object->SetProperties(*dictionary);
    }
  }
  if (object->map()->is_prototype_map()) {
    // Invalidate prototype validity cell as this may invalidate transitioning
    // store IC handlers.
    JSObject::InvalidatePrototypeChains(object->map());
  }
}

Maybe<bool> JSReceiver::DeleteProperty(LookupIterator* it,
                                       LanguageMode language_mode) {
  it->UpdateProtector();

  Isolate* isolate = it->isolate();

  if (it->state() == LookupIterator::JSPROXY) {
    return JSProxy::DeletePropertyOrElement(it->GetHolder<JSProxy>(),
                                            it->GetName(), language_mode);
  }

  if (IsJSProxy(*it->GetReceiver())) {
    if (it->state() != LookupIterator::NOT_FOUND) {
      DCHECK_EQ(LookupIterator::DATA, it->state());
      DCHECK(it->name()->IsPrivate());
      it->Delete();
    }
    return Just(true);
  }

  for (;; it->Next()) {
    switch (it->state()) {
      case LookupIterator::JSPROXY:
      case LookupIterator::TRANSITION:
        UNREACHABLE();
      case LookupIterator::WASM_OBJECT:
        RETURN_FAILURE(isolate, kThrowOnError,
                       NewTypeError(MessageTemplate::kWasmObjectsAreOpaque));
      case LookupIterator::ACCESS_CHECK:
        if (it->HasAccess()) continue;
        RETURN_ON_EXCEPTION_VALUE(
            isolate,
            isolate->ReportFailedAccessCheck(it->GetHolder<JSObject>()),
            Nothing<bool>());
        UNREACHABLE();
      case LookupIterator::INTERCEPTOR: {
        ShouldThrow should_throw =
            is_sloppy(language_mode) ? kDontThrow : kThrowOnError;
        InterceptorResult result;
        if (!JSObject::DeletePropertyWithInterceptor(it, should_throw)
                 .To(&result)) {
          // An exception was thrown in the interceptor. Propagate.
          return Nothing<bool>();
        }
        switch (result) {
          case InterceptorResult::kFalse:
            return Just(false);
          case InterceptorResult::kTrue:
            return Just(true);
          case InterceptorResult::kNotIntercepted:
            // Proceed lookup.
            continue;
        }
        UNREACHABLE();
      }
      case LookupIterator::TYPED_ARRAY_INDEX_NOT_FOUND:
        return Just(true);
      case LookupIterator::DATA:
      case LookupIterator::ACCESSOR: {
        DirectHandle<JSObject> holder = it->GetHolder<JSObject>();
        if (!it->IsConfigurable() ||
            (IsJSTypedArray(*holder) && it->IsElement(*holder))) {
          // Fail if the property is not configurable if the property is a
          // TypedArray element.
          if (is_strict(language_mode)) {
            isolate->Throw(*isolate->factory()->NewTypeError(
                MessageTemplate::kStrictDeleteProperty, it->GetName(),
                it->GetReceiver()));
            return Nothing<bool>();
          }
          return Just(false);
        }

        it->Delete();

        return Just(true);
      }
      case LookupIterator::NOT_FOUND:
        return Just(true);
    }
    UNREACHABLE();
  }
}

Maybe<bool> JSReceiver::DeleteElement(Isolate* isolate,
                                      Handle<JSReceiver> object, uint32_t index,
                                      LanguageMode language_mode) {
  LookupIterator it(isolate, object, index, object, LookupIterator::OWN);
  return DeleteProperty(&it, language_mode);
}

Maybe<bool> JSReceiver::DeleteProperty(Isolate* isolate,
                                       Handle<JSReceiver> object,
                                       Handle<Name> name,
                                       LanguageMode language_mode) {
  LookupIterator it(isolate, object, name, object, LookupIterator::OWN);
  return DeleteProperty(&it, language_mode);
}

Maybe<bool> JSReceiver::DeletePropertyOrElement(Isolate* isolate,
                                                Handle<JSReceiver> object,
                                                Handle<Name> name,
                                                LanguageMode language_mode) {
  PropertyKey key(isolate, name);
  LookupIterator it(isolate, object, key, object, LookupIterator::OWN);
  return DeleteProperty(&it, language_mode);
}

// ES6 19.1.2.4
// static
Tagged<Object> JSReceiver::DefineProperty(Isolate* isolate,
                                          Handle<Object> object,
                                          Handle<Object> key,
                                          Handle<Object> attributes) {
  // 1. If Type(O) is not Object, throw a TypeError exception.
  if (!IsJSReceiver(*object)) {
    Handle<String> fun_name =
        isolate->factory()->InternalizeUtf8String("Object.defineProperty");
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewTypeError(MessageTemplate::kCalledOnNonObject, fun_name));
  }
  // 2. Let key be ToPropertyKey(P).
  // 3. ReturnIfAbrupt(key).
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, key,
                                     Object::ToPropertyKey(isolate, key));
  // 4. Let desc be ToPropertyDescriptor(Attributes).
  // 5. ReturnIfAbrupt(desc).
  PropertyDescriptor desc;
  if (!PropertyDescriptor::ToPropertyDescriptor(
          isolate, Cast<JSAny>(attributes), &desc)) {
    return ReadOnlyRoots(isolate).exception();
  }
  // 6. Let success be DefinePropertyOrThrow(O,key, desc).
  Maybe<bool> success = DefineOwnProperty(isolate, Cast<JSReceiver>(object),
                                          key, &desc, Just(kThrowOnError));
  // 7. ReturnIfAbrupt(success).
  MAYBE_RETURN(success, ReadOnlyRoots(isolate).exception());
  CHECK(success.FromJust());
  // 8. Return O.
  return *object;
}

// ES6 19.1.2.3.1
// static
MaybeHandle<Object> JSReceiver::DefineProperties(Isolate* isolate,
                                                 Handle<Object> object,
                                                 Handle<Object> properties) {
  // 1. If Type(O) is not Object, throw a TypeError exception.
  if (!IsJSReceiver(*object)) {
    Handle<String> fun_name =
        isolate->factory()->InternalizeUtf8String("Object.defineProperties");
    THROW_NEW_ERROR(
        isolate, NewTypeError(MessageTemplate::kCalledOnNonObject, fun_name));
  }
  // 2. Let props be ToObject(Properties).
  // 3. ReturnIfAbrupt(props).
  Handle<JSReceiver> props;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, props,
                             Object::ToObject(isolate, properties));

  // 4. Let keys be props.[[OwnPropertyKeys]]().
  // 5. ReturnIfAbrupt(keys).
  Handle<FixedArray> keys;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, keys,
      KeyAccumulator::GetKeys(isolate, props, KeyCollectionMode::kOwnOnly,
                              ALL_PROPERTIES));
  // 6. Let descriptors be an empty List.s
  int capacity = keys->length();
  std::vector<PropertyDescriptor> descriptors(capacity);
  size_t descriptors_index = 0;
  // 7. Repeat for each element nextKey of keys in List order,
  for (int i = 0; i < keys->length(); ++i) {
    Handle<JSAny> next_key(Cast<JSAny>(keys->get(i)), isolate);
    // 7a. Let propDesc be props.[[GetOwnProperty]](nextKey).
    // 7b. ReturnIfAbrupt(propDesc).
    PropertyKey key(isolate, next_key);
    LookupIterator it(isolate, props, key, LookupIterator::OWN);
    Maybe<PropertyAttributes> maybe = JSReceiver::GetPropertyAttributes(&it);
    if (maybe.IsNothing()) return MaybeHandle<Object>();
    PropertyAttributes attrs = maybe.FromJust();
    // 7c. If propDesc is not undefined and propDesc.[[Enumerable]] is true:
    if (attrs == ABSENT) continue;
    if (attrs & DONT_ENUM) continue;
    // 7c i. Let descObj be Get(props, nextKey).
    // 7c ii. ReturnIfAbrupt(descObj).
    Handle<JSAny> desc_obj;
    ASSIGN_RETURN_ON_EXCEPTION(isolate, desc_obj,
                               Cast<JSAny>(Object::GetProperty(&it)));
    // 7c iii. Let desc be ToPropertyDescriptor(descObj).
    bool success = PropertyDescriptor::ToPropertyDescriptor(
        isolate, desc_obj, &descriptors[descriptors_index]);
    // 7c iv. ReturnIfAbrupt(desc).
    if (!success) return MaybeHandle<Object>();
    // 7c v. Append the pair (a two element List) consisting of nextKey and
    //       desc to the end of descriptors.
    descriptors[descriptors_index].set_name(next_key);
    descriptors_index++;
  }
  // 8. For each pair from descriptors in list order,
  for (size_t i = 0; i < descriptors_index; ++i) {
    PropertyDescriptor* desc = &descriptors[i];
    // 8a. Let P be the first element of pair.
    // 8b. Let desc be the second element of pair.
    // 8c. Let status be DefinePropertyOrThrow(O, P, desc).
    Maybe<bool> status =
        DefineOwnProperty(isolate, Cast<JSReceiver>(object), desc->name(), desc,
                          Just(kThrowOnError));
    // 8d. ReturnIfAbrupt(status).
    if (status.IsNothing()) return MaybeHandle<Object>();
    CHECK(status.FromJust());
  }
  // 9. Return o.
  return object;
}

// static
Maybe<bool> JSReceiver::DefineOwnProperty(Isolate* isolate,
                                          Handle<JSReceiver> object,
                                          Handle<Object> key,
                                          PropertyDescriptor* desc,
                                          Maybe<ShouldThrow> should_throw) {
  if (IsJSArray(*object)) {
    return JSArray::DefineOwnProperty(isolate, Cast<JSArray>(object), key, desc,
                                      should_throw);
  }
  if (IsJSProxy(*object)) {
    return JSProxy::DefineOwnProperty(isolate, Cast<JSProxy>(object), key, desc,
                                      should_throw);
  }
  if (IsJSTypedArray(*object)) {
    return JSTypedArray::DefineOwnProperty(isolate, Cast<JSTypedArray>(object),
                                           key, desc, should_throw);
  }
  if (IsJSModuleNamespace(*object)) {
    return JSModuleNamespace::DefineOwnProperty(
        isolate, Cast<JSModuleNamespace>(object), key, desc, should_throw);
  }
  if (IsWasmObject(*object)) {
    RETURN_FAILURE(isolate, kThrowOnError,
                   NewTypeError(MessageTemplate::kWasmObjectsAreOpaque));
  }
  if (IsAlwaysSharedSpaceJSObject(*object)) {
    return AlwaysSharedSpaceJSObject::DefineOwnProperty(
        isolate, Cast<AlwaysSharedSpaceJSObject>(object), key, desc,
        should_throw);
  }

  // OrdinaryDefineOwnProperty, by virtue of calling
  // DefineOwnPropertyIgnoreAttributes, can handle arguments
  // (ES#sec-arguments-exotic-objects-defineownproperty-p-desc).
  return OrdinaryDefineOwnProperty(isolate, Cast<JSObject>(object), key, desc,
                                   should_throw);
}

// static
Maybe<bool> JSReceiver::OrdinaryDefineOwnProperty(
    Isolate* isolate, Handle<JSObject> object, Handle<Object> key,
    PropertyDescriptor* desc, Maybe<ShouldThrow> should_throw) {
  DCHECK(IsName(*key) || IsNumber(*key));  // |key| is a PropertyKey.
  PropertyKey lookup_key(isolate, key);
  return OrdinaryDefineOwnProperty(isolate, object, lookup_key, desc,
                                   should_throw);
}

namespace {

MaybeHandle<JSAny> GetPropertyWithInterceptorInternal(
    LookupIterator* it, Handle<InterceptorInfo> interceptor, bool* done) {
  *done = false;
  Isolate* isolate = it->isolate();
  // Make sure that the top context does not change when doing callbacks or
  // interceptor calls.
  AssertNoContextChange ncc(isolate);

  if (IsUndefined(interceptor->getter(), isolate)) {
    return isolate->factory()->undefined_value();
  }

  DirectHandle<JSObject> holder = it->GetHolder<JSObject>();
  Handle<JSAny> result;
  Handle<Object> receiver = it->GetReceiver();
  if (!IsJSReceiver(*receiver)) {
    ASSIGN_RETURN_ON_EXCEPTION(isolate, receiver,
                               Object::ConvertReceiver(isolate, receiver));
  }
  PropertyCallbackArguments args(isolate, interceptor->data(), *receiver,
                                 *holder, Just(kDontThrow));

  if (it->IsElement(*holder)) {
    result = args.CallIndexedGetter(interceptor, it->array_index());
  } else {
    result = args.CallNamedGetter(interceptor, it->name());
  }
  // An exception was thrown in the interceptor. Propagate.
  RETURN_VALUE_IF_EXCEPTION_DETECTOR(isolate, args, kNullMaybeHandle);
  if (result.is_null()) return isolate->factory()->undefined_value();
  *done = true;
  args.AcceptSideEffects();
  // Rebox handle before return
  return handle(*result, isolate);
}

Maybe<PropertyAttributes> GetPropertyAttributesWithInterceptorInternal(
    LookupIterator* it, Handle<InterceptorInfo> interceptor) {
  Isolate* isolate = it->isolate();
  // Make sure that the top context does not change when doing
  // callbacks or interceptor calls.
  AssertNoContextChange ncc(isolate);
  HandleScope scope(isolate);

  DirectHandle<JSObject> holder = it->GetHolder<JSObject>();
  DCHECK_IMPLIES(!it->IsElement(*holder) && IsSymbol(*it->name()),
                 interceptor->can_intercept_symbols());
  Handle<Object> receiver = it->GetReceiver();
  if (!IsJSReceiver(*receiver)) {
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(isolate, receiver,
                                     Object::ConvertReceiver(isolate, receiver),
                                     Nothing<PropertyAttributes>());
  }
  PropertyCallbackArguments args(isolate, interceptor->data(), *receiver,
                                 *holder, Just(kDontThrow));
  if (!IsUndefined(interceptor->query(), isolate)) {
    Handle<Object> result;
    if (it->IsElement(*holder)) {
      result = args.CallIndexedQuery(interceptor, it->array_index());
    } else {
      result = args.CallNamedQuery(interceptor, it->name());
    }
    // An exception was thrown in the interceptor. Propagate.
    RETURN_VALUE_IF_EXCEPTION_DETECTOR(isolate, args,
                                       Nothing<PropertyAttributes>());

    if (!result.is_null()) {
      int32_t value;
      CHECK(Object::ToInt32(*result, &value));
      DCHECK_IMPLIES((value & ~PropertyAttributes::ALL_ATTRIBUTES_MASK) != 0,
                     value == PropertyAttributes::ABSENT);
      // In case of absent property side effects are not allowed.
      // TODO(ishell): PropertyAttributes::ABSENT is not exposed in the Api,
      // so it can't be officially returned. We should fix the tests instead.
      if (value != PropertyAttributes::ABSENT) {
        args.AcceptSideEffects();
      }
      return Just(static_cast<PropertyAttributes>(value));
    }
  } else if (!IsUndefined(interceptor->getter(), isolate)) {
    // TODO(verwaest): Use GetPropertyWithInterceptor?
    Handle<Object> result;
    if (it->IsElement(*holder)) {
      result = args.CallIndexedGetter(interceptor, it->array_index());
    } else {
      result = args.CallNamedGetter(interceptor, it->name());
    }
    // An exception was thrown in the interceptor. Propagate.
    RETURN_VALUE_IF_EXCEPTION_DETECTOR(isolate, args,
                                       Nothing<PropertyAttributes>());

    if (!result.is_null()) {
      args.AcceptSideEffects();
      return Just(DONT_ENUM);
    }
  }
  return Just(ABSENT);
}

Maybe<InterceptorResult> SetPropertyWithInterceptorInternal(
    LookupIterator* it, DirectHandle<InterceptorInfo> interceptor,
    Maybe<ShouldThrow> should_throw, Handle<Object> value) {
  Isolate* isolate = it->isolate();
  // Make sure that the top context does not change when doing callbacks or
  // interceptor calls.
  AssertNoContextChange ncc(isolate);

  if (IsUndefined(interceptor->setter(), isolate)) {
    return Just(InterceptorResult::kNotIntercepted);
  }

  DirectHandle<JSObject> holder = it->GetHolder<JSObject>();
  Handle<Object> receiver = it->GetReceiver();
  if (!IsJSReceiver(*receiver)) {
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(isolate, receiver,
                                     Object::ConvertReceiver(isolate, receiver),
                                     Nothing<InterceptorResult>());
  }
  PropertyCallbackArguments args(isolate, interceptor->data(), *receiver,
                                 *holder, should_throw);

  v8::Intercepted intercepted =
      it->IsElement(*holder)
          ? args.CallIndexedSetter(interceptor, it->array_index(), value)
          : args.CallNamedSetter(interceptor, it->name(), value);

  return args.GetBooleanReturnValue(intercepted, "Setter");
}

Maybe<InterceptorResult> DefinePropertyWithInterceptorInternal(
    LookupIterator* it, DirectHandle<InterceptorInfo> interceptor,
    Maybe<ShouldThrow> should_throw, PropertyDescriptor* desc) {
  Isolate* isolate = it->isolate();
  // Make sure that the top context does not change when doing callbacks or
  // interceptor calls.
  AssertNoContextChange ncc(isolate);

  if (IsUndefined(interceptor->definer(), isolate)) {
    return Just(InterceptorResult::kNotIntercepted);
  }

  DirectHandle<JSObject> holder = it->GetHolder<JSObject>();
  Handle<Object> receiver = it->GetReceiver();
  if (!IsJSReceiver(*receiver)) {
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(isolate, receiver,
                                     Object::ConvertReceiver(isolate, receiver),
                                     Nothing<InterceptorResult>());
  }

  std::unique_ptr<v8::PropertyDescriptor> descriptor(
      new v8::PropertyDescriptor());
  if (PropertyDescriptor::IsAccessorDescriptor(desc)) {
    Handle<Object> getter = desc->get();
    if (!getter.is_null() && IsFunctionTemplateInfo(*getter)) {
      ASSIGN_RETURN_ON_EXCEPTION_VALUE(
          isolate, getter,
          ApiNatives::InstantiateFunction(
              isolate, Cast<FunctionTemplateInfo>(getter), MaybeHandle<Name>()),
          Nothing<InterceptorResult>());
    }
    Handle<Object> setter = desc->set();
    if (!setter.is_null() && IsFunctionTemplateInfo(*setter)) {
      ASSIGN_RETURN_ON_EXCEPTION_VALUE(
          isolate, setter,
          ApiNatives::InstantiateFunction(
              isolate, Cast<FunctionTemplateInfo>(setter), MaybeHandle<Name>()),
          Nothing<InterceptorResult>());
    }
    descriptor.reset(new v8::PropertyDescriptor(v8::Utils::ToLocal(getter),
                                                v8::Utils::ToLocal(setter)));
  } else if (PropertyDescriptor::IsDataDescriptor(desc)) {
    if (desc->has_writable()) {
      descriptor.reset(new v8::PropertyDescriptor(
          v8::Utils::ToLocal(desc->value()), desc->writable()));
    } else {
      descriptor.reset(
          new v8::PropertyDescriptor(v8::Utils::ToLocal(desc->value())));
    }
  }
  if (desc->has_enumerable()) {
    descriptor->set_enumerable(desc->enumerable());
  }
  if (desc->has_configurable()) {
    descriptor->set_configurable(desc->configurable());
  }

  PropertyCallbackArguments args(isolate, interceptor->data(), *receiver,
                                 *holder, should_throw);

  v8::Intercepted intercepted =
      it->IsElement(*holder)
          ? args.CallIndexedDefiner(interceptor, it->array_index(), *descriptor)
          : args.CallNamedDefiner(interceptor, it->name(), *descriptor);

  return args.GetBooleanReturnValue(intercepted, "Definer");
}

}  // namespace

// ES6 9.1.6.1
// static
Maybe<bool> JSReceiver::OrdinaryDefineOwnProperty(
    Isolate* isolate, Handle<JSObject> object, const PropertyKey& key,
    PropertyDescriptor* desc, Maybe<ShouldThrow> should_throw) {
  LookupIterator it(isolate, object, key, LookupIterator::OWN);

  // Deal with access checks first.
  while (it.state() == LookupIterator::ACCESS_CHECK) {
    if (!it.HasAccess()) {
      RETURN_ON_EXCEPTION_VALUE(
          isolate, isolate->ReportFailedAccessCheck(it.GetHolder<JSObject>()),
          Nothing<bool>());
      UNREACHABLE();
    }
    it.Next();
  }

  // 1. Let current be O.[[GetOwnProperty]](P).
  // 2. ReturnIfAbrupt(current).
  PropertyDescriptor current;
  MAYBE_RETURN(GetOwnPropertyDescriptor(&it, &current), Nothing<bool>());

  // TODO(jkummerow/verwaest): It would be nice if we didn't have to reset
  // the iterator every time. Currently, the reasons why we need it are because
  // GetOwnPropertyDescriptor can have side effects, namely:
  // - Interceptors
  // - Accessors (which might change the holder's map)
  it.Restart();

  // Skip over the access check after restarting -- we've already checked it.
  while (it.state() == LookupIterator::ACCESS_CHECK) {
    DCHECK(it.HasAccess());
    it.Next();
  }

  // Handle interceptor.
  if (it.state() == LookupIterator::INTERCEPTOR) {
    if (it.HolderIsReceiverOrHiddenPrototype()) {
      InterceptorResult result;
      if (!DefinePropertyWithInterceptorInternal(&it, it.GetInterceptor(),
                                                 should_throw, desc)
               .To(&result)) {
        // An exception was thrown in the interceptor. Propagate.
        return Nothing<bool>();
      }
      switch (result) {
        case InterceptorResult::kFalse:
          return Just(false);
        case InterceptorResult::kTrue:
          return Just(true);

        case InterceptorResult::kNotIntercepted:
          // Proceed lookup.
          break;
      }
      // We need to restart the lookup in case the interceptor ran with side
      // effects.
      it.Restart();
    }
  }

  // 3. Let extensible be the value of the [[Extensible]] internal slot of O.
  bool extensible = JSObject::IsExtensible(isolate, object);

  return ValidateAndApplyPropertyDescriptor(
      isolate, &it, extensible, desc, &current, should_throw, Handle<Name>());
}

// ES6 9.1.6.2
// static
Maybe<bool> JSReceiver::IsCompatiblePropertyDescriptor(
    Isolate* isolate, bool extensible, PropertyDescriptor* desc,
    PropertyDescriptor* current, Handle<Name> property_name,
    Maybe<ShouldThrow> should_throw) {
  // 1. Return ValidateAndApplyPropertyDescriptor(undefined, undefined,
  //    Extensible, Desc, Current).
  return ValidateAndApplyPropertyDescriptor(
      isolate, nullptr, extensible, desc, current, should_throw, property_name);
}

// https://tc39.es/ecma262/#sec-validateandapplypropertydescriptor
// static
Maybe<bool> JSReceiver::ValidateAndApplyPropertyDescriptor(
    Isolate* isolate, LookupIterator* it, bool extensible,
    PropertyDescriptor* desc, PropertyDescriptor* current,
    Maybe<ShouldThrow> should_throw, Handle<Name> property_name) {
  // We either need a LookupIterator, or a property name.
  DCHECK((it == nullptr) != property_name.is_null());
  bool desc_is_data_descriptor = PropertyDescriptor::IsDataDescriptor(desc);
  bool desc_is_accessor_descriptor =
      PropertyDescriptor::IsAccessorDescriptor(desc);
  bool desc_is_generic_descriptor =
      PropertyDescriptor::IsGenericDescriptor(desc);
  // 1. (Assert)
  // 2. If current is undefined, then
  if (current->is_empty()) {
    // 2a. If extensible is false, return false.
    if (!extensible) {
      RETURN_FAILURE(
          isolate, GetShouldThrow(isolate, should_throw),
          NewTypeError(MessageTemplate::kDefineDisallowed,
                       it != nullptr ? it->GetName() : property_name));
    }
    // 2c. If IsGenericDescriptor(Desc) or IsDataDescriptor(Desc) is true, then:
    // (This is equivalent to !IsAccessorDescriptor(desc).)
    DCHECK_EQ(desc_is_generic_descriptor || desc_is_data_descriptor,
              !desc_is_accessor_descriptor);
    if (!desc_is_accessor_descriptor) {
      // 2c i. If O is not undefined, create an own data property named P of
      // object O whose [[Value]], [[Writable]], [[Enumerable]] and
      // [[Configurable]] attribute values are described by Desc. If the value
      // of an attribute field of Desc is absent, the attribute of the newly
      // created property is set to its default value.
      if (it != nullptr) {
        if (!desc->has_writable()) desc->set_writable(false);
        if (!desc->has_enumerable()) desc->set_enumerable(false);
        if (!desc->has_configurable()) desc->set_configurable(false);
        Handle<Object> value(
            desc->has_value()
                ? desc->value()
                : Cast<Object>(isolate->factory()->undefined_value()));
        MaybeHandle<Object> result =
            JSObject::DefineOwnPropertyIgnoreAttributes(it, value,
                                                        desc->ToAttributes());
        if (result.is_null()) return Nothing<bool>();
      }
    } else {
      // 2d. Else Desc must be an accessor Property Descriptor,
      DCHECK(desc_is_accessor_descriptor);
      // 2d i. If O is not undefined, create an own accessor property named P
      // of object O whose [[Get]], [[Set]], [[Enumerable]] and
      // [[Configurable]] attribute values are described by Desc. If the value
      // of an attribute field of Desc is absent, the attribute of the newly
      // created property is set to its default value.
      if (it != nullptr) {
        if (!desc->has_enumerable()) desc->set_enumerable(false);
        if (!desc->has_configurable()) desc->set_configurable(false);
        DirectHandle<Object> getter(
            desc->has_get() ? desc->get()
                            : Cast<Object>(isolate->factory()->null_value()));
        DirectHandle<Object> setter(
            desc->has_set() ? desc->set()
                            : Cast<Object>(isolate->factory()->null_value()));
        MaybeHandle<Object> result =
            JSObject::DefineOwnAccessorIgnoreAttributes(it, getter, setter,
                                                        desc->ToAttributes());
        if (result.is_null()) return Nothing<bool>();
      }
    }
    // 2e. Return true.
    return Just(true);
  }
  // 3. If every field in Desc is absent, return true. (This also has a shortcut
  // not in the spec: if every field value matches the current value, return.)
  if ((!desc->has_enumerable() ||
       desc->enumerable() == current->enumerable()) &&
      (!desc->has_configurable() ||
       desc->configurable() == current->configurable()) &&
      !desc->has_value() &&
      (!desc->has_writable() ||
       (current->has_writable() && current->writable() == desc->writable())) &&
      (!desc->has_get() ||
       (current->has_get() &&
        Object::SameValue(*current->get(), *desc->get()))) &&
      (!desc->has_set() ||
       (current->has_set() &&
        Object::SameValue(*current->set(), *desc->set())))) {
    return Just(true);
  }
  // 4. If current.[[Configurable]] is false, then
  if (!current->configurable()) {
    // 4a. If Desc.[[Configurable]] is present and its value is true, return
    // false.
    if (desc->has_configurable() && desc->configurable()) {
      RETURN_FAILURE(
          isolate, GetShouldThrow(isolate, should_throw),
          NewTypeError(MessageTemplate::kRedefineDisallowed,
                       it != nullptr ? it->GetName() : property_name));
    }
    // 4b. If Desc.[[Enumerable]] is present and
    // ! SameValue(Desc.[[Enumerable]], current.[[Enumerable]]) is false, return
    // false.
    if (desc->has_enumerable() && desc->enumerable() != current->enumerable()) {
      RETURN_FAILURE(
          isolate, GetShouldThrow(isolate, should_throw),
          NewTypeError(MessageTemplate::kRedefineDisallowed,
                       it != nullptr ? it->GetName() : property_name));
    }
  }

  bool current_is_data_descriptor =
      PropertyDescriptor::IsDataDescriptor(current);
  // 5. If ! IsGenericDescriptor(Desc) is true, no further validation is
  // required.
  if (desc_is_generic_descriptor) {
    // Nothing to see here.

    // 6. Else if ! SameValue(!IsDataDescriptor(current),
    // !IsDataDescriptor(Desc)) is false, the
  } else if (current_is_data_descriptor != desc_is_data_descriptor) {
    // 6a. If current.[[Configurable]] is false, return false.
    if (!current->configurable()) {
      RETURN_FAILURE(
          isolate, GetShouldThrow(isolate, should_throw),
          NewTypeError(MessageTemplate::kRedefineDisallowed,
                       it != nullptr ? it->GetName() : property_name));
    }
    // 6b. If IsDataDescriptor(current) is true, then:
    if (current_is_data_descriptor) {
      // 6b i. If O is not undefined, convert the property named P of object O
      // from a data property to an accessor property. Preserve the existing
      // values of the converted property's [[Configurable]] and [[Enumerable]]
      // attributes and set the rest of the property's attributes to their
      // default values.
      // --> Folded into step 9
    } else {
      // 6c i. If O is not undefined, convert the property named P of object O
      // from an accessor property to a data property. Preserve the existing
      // values of the converted property’s [[Configurable]] and [[Enumerable]]
      // attributes and set the rest of the property’s attributes to their
      // default values.
      // --> Folded into step 9
    }

    // 7. Else if IsDataDescriptor(current) and IsDataDescriptor(Desc) are both
    // true, then:
  } else if (current_is_data_descriptor && desc_is_data_descriptor) {
    // 7a. If current.[[Configurable]] is false and current.[[Writable]] is
    // false, then
    if (!current->configurable() && !current->writable()) {
      // 7a i. If Desc.[[Writable]] is present and Desc.[[Writable]] is true,
      // return false.
      if (desc->has_writable() && desc->writable()) {
        RETURN_FAILURE(
            isolate, GetShouldThrow(isolate, should_throw),
            NewTypeError(MessageTemplate::kRedefineDisallowed,
                         it != nullptr ? it->GetName() : property_name));
      }
      // 7a ii. If Desc.[[Value]] is present and SameValue(Desc.[[Value]],
      // current.[[Value]]) is false, return false.
      if (desc->has_value()) {
        // We'll succeed applying the property, but the value is already the
        // same and the property is read-only, so skip actually writing the
        // property. Otherwise we may try to e.g., write to frozen elements.
        if (Object::SameValue(*desc->value(), *current->value()))
          return Just(true);
        RETURN_FAILURE(
            isolate, GetShouldThrow(isolate, should_throw),
            NewTypeError(MessageTemplate::kRedefineDisallowed,
                         it != nullptr ? it->GetName() : property_name));
      }
    }
  } else {
    // 8. Else,
    // 8a. Assert: ! IsAccessorDescriptor(current) and
    // ! IsAccessorDescriptor(Desc) are both true.
    DCHECK(PropertyDescriptor::IsAccessorDescriptor(current) &&
           desc_is_accessor_descriptor);
    // 8b. If current.[[Configurable]] is false, then:
    if (!current->configurable()) {
      // 8a i. If Desc.[[Set]] is present and SameValue(Desc.[[Set]],
      // current.[[Set]]) is false, return false.
      if (desc->has_set() &&
          !Object::SameValue(*desc->set(), *current->set())) {
        RETURN_FAILURE(
            isolate, GetShouldThrow(isolate, should_throw),
            NewTypeError(MessageTemplate::kRedefineDisallowed,
                         it != nullptr ? it->GetName() : property_name));
      }
      // 8a ii. If Desc.[[Get]] is present and SameValue(Desc.[[Get]],
      // current.[[Get]]) is false, return false.
      if (desc->has_get() &&
          !Object::SameValue(*desc->get(), *current-
```