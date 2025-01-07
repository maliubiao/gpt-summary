Response:
The user wants a summary of the provided C++ code for `v8/src/objects/js-objects.cc`. The summary should cover the file's functionality, mention if it were a Torque file (it's not), illustrate its connection to JavaScript with examples, explain code logic with hypothetical inputs/outputs, highlight common programming errors related to the content, and finally, provide an overall summarization of its role.

Here's a breakdown of the code's content and how to address each requirement:

1. **Functionality:** The file seems to define methods for various operations on JavaScript objects within the V8 engine. This includes property access (hasProperty, hasOwnProperty, getDataProperty), prototype chain traversal (hasInPrototypeChain), handling private names, copying properties (setOrCopyDataProperties, fastAssign), determining class and constructor names, retrieving the realm of a function, and managing object identity hashes. It also includes logic for handling special object types like proxies, modules, and WebAssembly objects.

2. **Torque:** The prompt explicitly asks about `.tq` files. Since the file ends with `.cc`, it's a C++ file and not a Torque file.

3. **JavaScript Connection:**  Most of the functions directly relate to JavaScript operations. Examples can be provided for property access, prototype inheritance, private fields, and object assignment.

4. **Code Logic Inference:**  Functions like `HasProperty`, `HasOwnProperty`, and `GetDataProperty` involve iterating through the object's property structure. Hypothetical scenarios can be constructed to trace how these functions would behave with different object structures and property states. `FastAssign` and `SetOrCopyDataProperties` are good candidates for illustrating property copying logic.

5. **Common Programming Errors:**  Issues like trying to access non-existent properties, incorrectly handling private fields, misunderstanding prototype inheritance, and potential problems with object assignment can be discussed.

6. **Overall Summary:**  The file provides core functionalities for manipulating and inspecting JavaScript objects within the V8 engine. It's a fundamental part of how JavaScript code interacts with the underlying engine.

**Mental Sandbox Simulation:**

* **Functionality:**  Yes, the code clearly deals with object operations.
* **Torque:** Easy check, it's `.cc`.
* **JavaScript Connection:** Straightforward, many direct equivalents in JS.
* **Code Logic:** The `LookupIterator` pattern is key here. Need to simulate its steps.
* **Common Errors:** Standard JS pitfalls related to objects.
* **Overall Summary:** Can be synthesized after understanding the individual functionalities.

**Plan of Action:**

1. State that the file is a C++ file for handling JavaScript objects.
2. Confirm it's not a Torque file.
3. Provide JavaScript examples for functions like `HasProperty`, `GetOwnPropertyDescriptor`, and object assignment related to `SetOrCopyDataProperties`.
4. Create a simple object and demonstrate how `HasProperty` would work, showcasing different lookup scenarios (own property, prototype property, non-existent property). Similarly, illustrate the property copying logic with a source and target object. For private names, show how attempting to access or redefine them without proper context leads to errors.
5. Give examples of common errors, like `TypeError` when accessing private members incorrectly or when trying to redefine non-configurable properties.
6. Conclude with a concise summary of the file's importance in V8's object handling.
```cpp
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
    Tagged<JS
Prompt: 
```
这是目录为v8/src/objects/js-objects.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/js-objects.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共8部分，请归纳一下它的功能

"""
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

Tagged<Smi> JSReceiver::Ge
"""


```